//! Blocklist fetch → parse → compile → atomic swap pipeline.
//!
//! Implements `specs/wp2-daemon.md` §4 and `docs/architecture.md` §6.
//! Snapshot cold-start seam implements `specs/wp12-packaging.md` §1.
//!
//! Boot sequence (executed by [`ListsPipeline::start`]):
//! 1. Try `CompiledRules::load(state/compiled)` → swap in, log counts.
//! 2. Corrupt/missing → try compiling from cached raw sources in
//!    `state/lists/`.
//! 3. Nothing cached + snapshot_dir configured + dir exists → compile from
//!    the packaged snapshot immediately so blocking works before any fetch.
//! 4. Nothing cached, no snapshot → `CompiledRules::empty()` + immediate
//!    fetch (10s delay for readiness, then fetch).
//!
//! **Never blocks listener startup on a fetch.**  The compiled rules are
//! always either loaded from disk or set to empty before this function
//! returns.
//!
//! Refresh task: jittered daily interval; per-source `If-None-Match` /
//! `If-Modified-Since`; 304 keeps cached; 200 atomic-replaces raw file.
//! Any source failing → uses cached copy; ALL failing → keep current compile
//! with exponential backoff (30 s → 1 h cap) and a `warn!`.
//!
//! Compile is on `tokio::task::spawn_blocking` (fst build of 1 M domains is
//! CPU-bound).  Source responses > 256 MB are rejected (poisoned-source guard).

use hush_core::{
    config::ListsConfig,
    parse::parse_list,
    rules::{CompiledRules, RulesBuilder},
    DecisionEngine,
};
use reqwest::header::{HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Maximum raw source response size (256 MB).
const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;

/// Initial delay before the very first fetch attempt when starting cold.
const COLD_START_FETCH_DELAY: Duration = Duration::from_secs(10);

/// Initial retry backoff after all sources fail.
const BACKOFF_INITIAL: Duration = Duration::from_secs(30);

/// Maximum retry backoff cap.
const BACKOFF_CAP: Duration = Duration::from_secs(3600);

/// Status of a single source.
// WP3-seam: exposed via the control API `GET /lists/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceStatus {
    /// Source name from config.
    pub name: String,
    /// URL.
    pub url: String,
    /// Last successful fetch time (Unix ms), `None` if never fetched.
    pub last_ok_unix_ms: Option<u64>,
    /// Last fetch error, `None` if last fetch succeeded.
    pub last_error: Option<String>,
    /// Number of rules contributed by this source, `None` if never compiled.
    pub last_rule_count: Option<u64>,
}

/// Aggregate pipeline status exposed to WP3's API.
// WP3-seam: exposed via the control API `GET /lists/status`.
#[derive(Debug, Clone)]
pub struct ListsStatus {
    /// Per-source status.
    pub per_source: Vec<SourceStatus>,
    /// Metadata of the currently active compiled rule set.
    pub compiled_meta: Option<hush_core::rules::RulesMeta>,
    /// Unix ms when the last successful swap occurred.
    pub last_swap_unix_ms: Option<u64>,
}

/// Per-source fetch outcome tracked in memory.
///
/// Updated on every fetch attempt; read by `status()` to populate
/// `SourceStatus`.  Guarded by a `std::sync::Mutex` — critical sections are
/// short (map insert/lookup only; no `.await` held across the lock).
#[derive(Debug, Clone, Default)]
struct SourceTrack {
    /// Unix ms of the last successful fetch (200 or 304).
    last_ok_unix_ms: Option<u64>,
    /// Error string from the last fetch, cleared on success.
    last_error: Option<String>,
    /// Number of rules contributed by this source from the last compile.
    last_rule_count: Option<u64>,
}

/// Errors from the lists pipeline.
#[derive(Debug, Error)]
pub enum ListsError {
    /// An I/O error on the state directory.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Reqwest HTTP error.
    #[error("HTTP error fetching {url}: {source}")]
    Http {
        /// Source URL.
        url: String,
        /// Underlying error.
        #[source]
        source: reqwest::Error,
    },
    /// Source response exceeded the size limit.
    #[error("source {url} response exceeded {MAX_SOURCE_BYTES} bytes (poisoned-source guard)")]
    SourceTooLarge {
        /// Source URL.
        url: String,
    },
    /// Rule compilation failed.
    #[error("compile error: {0}")]
    Compile(String),
}

/// Per-source HTTP validator state (ETag / Last-Modified), persisted to disk.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Validators {
    /// Map from source URL to `(etag, last_modified)`.
    #[serde(default)]
    entries: HashMap<String, (Option<String>, Option<String>)>,
}

impl Validators {
    fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &Path) {
        if let Ok(data) = serde_json::to_vec(self) {
            if let Err(e) = std::fs::write(path, data) {
                warn!(path = %path.display(), error = %e, "failed to save validators");
            }
        }
    }

    fn get(&self, url: &str) -> (Option<&str>, Option<&str>) {
        match self.entries.get(url) {
            Some((etag, lm)) => (etag.as_deref(), lm.as_deref()),
            None => (None, None),
        }
    }

    fn set(&mut self, url: &str, etag: Option<String>, last_modified: Option<String>) {
        self.entries.insert(url.to_string(), (etag, last_modified));
    }
}

/// Handles the full list pipeline: boot load + background refresh task.
pub struct ListsPipeline {
    /// Pipeline configuration (preset, sources, refresh interval).
    ///
    /// Protected by a `Mutex` so `POST /v0/config/reload` can swap it before
    /// triggering `force_refresh`.  The hot path (refresh loop) re-reads this
    /// at the start of each refresh cycle, so the new config takes effect on
    /// the next fetch without a restart.
    config: Mutex<ListsConfig>,
    state_dir: PathBuf,
    engine: Arc<DecisionEngine>,
    http: reqwest::Client,
    /// Per-source fetch outcome tracking.
    ///
    /// Keyed by source URL.  The `Mutex` is `std::sync::Mutex` (not tokio) because
    /// no `.await` is held across any critical section.
    source_track: Mutex<HashMap<String, SourceTrack>>,
    /// Unix ms of the last successful `engine.swap_rules` call.
    ///
    /// Set both after a successful HTTP fetch+compile and when boot loads rules
    /// from disk or raw cache.
    last_swap_unix_ms: Mutex<Option<u64>>,
}

impl ListsPipeline {
    /// The effective source list: preset ∪ extra_categories ∪ explicit sources.
    ///
    /// This is the canonical merge rule from `specs/wp4-privacy.md` §1.
    /// All pipeline methods iterate this instead of `config.sources` directly
    /// so that preset-based configs fetch and compile the right lists.
    fn sources(&self) -> Vec<hush_core::config::ListSource> {
        self.config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .effective_sources()
    }

    /// Return the configured preset name (`"minimal"`, `"balanced"`, etc.).
    ///
    /// Used by `GET /v0/lists` (WP4 §4) to include the `preset` field in the response.
    pub fn preset(&self) -> String {
        self.config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .preset
            .clone()
    }

    /// Hot-swap the pipeline configuration.
    ///
    /// After calling this, the next `force_refresh()` / `fetch_and_compile_if_changed()`
    /// will use the new preset, categories, and source list.  The background refresh
    /// loop also picks up the change on its next iteration (it reads `sources()` at
    /// the start of each cycle).
    pub fn update_config(&self, new_cfg: ListsConfig) {
        let mut guard = self.config.lock().unwrap_or_else(|e| e.into_inner());
        *guard = new_cfg;
    }

    /// Return a snapshot of the current pipeline status.
    ///
    /// Merges the config-defined sources with the in-memory fetch tracking map
    /// so callers see real `last_ok_unix_ms`, `last_error`, and `last_rule_count`
    /// values after the first fetch.
    // WP3-seam: called by `GET /v0/lists`.
    pub fn status(&self) -> ListsStatus {
        let track_snap = {
            // Short critical section — clone the map and release the lock.
            let guard = self.source_track.lock().unwrap_or_else(|e| e.into_inner());
            guard.clone()
        };

        let per_source = self
            .sources()
            .iter()
            .map(|s| {
                let t = track_snap.get(&s.url).cloned().unwrap_or_default();
                SourceStatus {
                    name: s.name.clone(),
                    url: s.url.clone(),
                    last_ok_unix_ms: t.last_ok_unix_ms,
                    last_error: t.last_error,
                    last_rule_count: t.last_rule_count,
                }
            })
            .collect();

        let rules = self.engine.current_rules();
        let compiled_meta = Some(rules.meta.clone());
        drop(rules);

        let last_swap_unix_ms = {
            let guard = self
                .last_swap_unix_ms
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *guard
        };

        ListsStatus {
            per_source,
            compiled_meta,
            last_swap_unix_ms,
        }
    }
}

impl ListsPipeline {
    /// Create a new pipeline.  Caller must call [`start`] to begin operation.
    pub fn new(config: ListsConfig, state_dir: PathBuf, engine: Arc<DecisionEngine>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .gzip(true)
            .build()
            .unwrap_or_default();
        Self {
            config: Mutex::new(config),
            state_dir,
            engine,
            http,
            source_track: Mutex::new(HashMap::new()),
            last_swap_unix_ms: Mutex::new(None),
        }
    }

    /// Boot the pipeline: load or compile rules, then spawn the background
    /// refresh task.
    ///
    /// Returns immediately after swapping in the initial rules.  The
    /// background refresh task runs for the lifetime of the daemon.
    pub async fn start(self: Arc<Self>) {
        // Step 1: try loading compiled artifact.
        let compiled_dir = self.state_dir.join("compiled");
        match CompiledRules::load(&compiled_dir) {
            Ok(rules) => {
                info!(
                    block_count = rules.meta.block_count,
                    allow_count = rules.meta.allow_count,
                    "loaded compiled rules from disk"
                );
                self.engine.swap_rules(Arc::new(rules));
                self.record_swap();
            }
            Err(e) => {
                debug!(error = %e, "compiled artifact not loadable; trying raw sources");

                // Step 2: try compiling from cached raw sources.
                match self.compile_from_raw_cache().await {
                    Ok(rules) => {
                        info!(
                            block_count = rules.meta.block_count,
                            "compiled rules from cached raw sources"
                        );
                        self.engine.swap_rules(Arc::new(rules));
                        self.record_swap();
                    }
                    Err(e2) => {
                        debug!(error = %e2, "no cached raw sources; checking for packaged snapshot");

                        // Step 3 (WP12 §1): compile from packaged snapshot when present.
                        // This allows blocking on first boot with no network.
                        let swapped_from_snapshot = self.try_load_snapshot().await;

                        if !swapped_from_snapshot {
                            // Step 4: start empty + schedule immediate fetch.
                            warn!("no cached sources and no snapshot; starting with empty rules");
                            self.engine.swap_rules(Arc::new(CompiledRules::empty()));
                        }
                    }
                }
            }
        }

        // Spawn background refresh.
        let pipeline = Arc::clone(&self);
        tokio::spawn(async move {
            pipeline.run_refresh_loop().await;
        });
    }

    /// Attempt to load and compile the packaged snapshot (WP12 §1).
    ///
    /// Consults `config.lists.snapshot_dir`.  Returns `true` if rules were
    /// swapped from the snapshot, `false` if the snapshot is absent or fails.
    /// Logs loudly on failure so operators see it in the daemon log.
    async fn try_load_snapshot(&self) -> bool {
        let cfg_snap = self
            .config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let snapshot_dir = match cfg_snap.snapshot_dir.as_deref() {
            Some(d) if !d.is_empty() => std::path::PathBuf::from(d),
            _ => return false,
        };

        if !snapshot_dir.exists() {
            debug!(
                path = %snapshot_dir.display(),
                "snapshot dir does not exist — skipping"
            );
            return false;
        }

        info!(
            path = %snapshot_dir.display(),
            "cold start: compiling from packaged snapshot (no cached lists)"
        );
        match self.compile_from_snapshot(&snapshot_dir).await {
            Ok(rules) => {
                info!(
                    block_count = rules.meta.block_count,
                    path = %snapshot_dir.display(),
                    "snapshot rules compiled and active; network refresh will follow"
                );
                self.engine.swap_rules(Arc::new(rules));
                self.record_swap();
                true
            }
            Err(e) => {
                error!(
                    error = %e,
                    path = %snapshot_dir.display(),
                    "snapshot compile failed — starting with empty rules"
                );
                false
            }
        }
    }

    /// Recompile rules from raw source files in `state/lists/` and swap them
    /// into the engine.
    ///
    /// Does NOT perform any HTTP fetch — uses whatever raw files are currently
    /// on disk.  Intended for integration tests that write list files directly.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no cached raw files are found or compilation fails.
    // WP3-seam + test: called by `POST /lists/reload` and by integration tests.
    #[allow(dead_code)]
    pub async fn reload_from_cache(&self) -> Result<(), ListsError> {
        let rules = self.compile_from_raw_cache().await?;
        self.engine.swap_rules(Arc::new(rules));
        Ok(())
    }

    /// Attempt to compile rules from cached raw source files in
    /// `state/lists/`.
    ///
    /// Captures per-source rule-count deltas and records them in the tracking
    /// map so `status()` can report accurate counts after a compile.
    async fn compile_from_raw_cache(&self) -> Result<CompiledRules, ListsError> {
        let lists_dir = self.state_dir.join("lists");
        let mut builder = RulesBuilder::new();
        let mut found_any = false;
        // Collect (url, rule_count) pairs to update the tracking map after
        // compile — we cannot borrow `self.source_track` across the blocking
        // task boundary.
        let mut source_counts: Vec<(String, u64)> = Vec::new();

        for source in &self.sources() {
            let file_path = source_file_path(&lists_dir, &source.url);
            if let Ok(data) = std::fs::read(&file_path) {
                let before = builder.block_len();
                let text = String::from_utf8_lossy(&data);
                parse_list(&text, &mut builder);
                let delta = (builder.block_len() - before) as u64;
                builder.add_source_name(source.name.clone());
                source_counts.push((source.url.clone(), delta));
                found_any = true;
            }
        }

        if !found_any {
            return Err(ListsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no cached raw source files found",
            )));
        }

        let rules = spawn_blocking_compile(builder).await?;

        // Record per-source rule counts now that compile succeeded.
        {
            let mut guard = self.source_track.lock().unwrap_or_else(|e| e.into_inner());
            for (url, count) in source_counts {
                guard.entry(url).or_default().last_rule_count = Some(count);
            }
        }

        Ok(rules)
    }

    /// Compile rules from the packaged snapshot directory (WP12 §1).
    ///
    /// The snapshot directory contains one `.txt` file per Hagezi source, named
    /// as `<source-name>.txt`.  All files in the directory are parsed and
    /// compiled into a single rule set.  This is a one-time cold-start path —
    /// the snapshot exists only when no cached state is present.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the snapshot directory does not exist, is empty, or
    /// compilation fails.
    async fn compile_from_snapshot(
        &self,
        snapshot_dir: &Path,
    ) -> Result<CompiledRules, ListsError> {
        let mut builder = RulesBuilder::new();
        let mut found_any = false;

        let read_dir = std::fs::read_dir(snapshot_dir).map_err(|e| {
            ListsError::Io(std::io::Error::new(
                e.kind(),
                format!("snapshot dir {}: {e}", snapshot_dir.display()),
            ))
        })?;

        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            // Only process .txt files; ignore manifest.json and other metadata.
            if path.extension().and_then(|e| e.to_str()) != Some("txt") {
                continue;
            }
            if let Ok(data) = std::fs::read(&path) {
                let text = String::from_utf8_lossy(&data);
                let source_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("snapshot");
                builder.add_source_name(source_name.to_string());
                parse_list(&text, &mut builder);
                found_any = true;
            } else {
                warn!(path = %path.display(), "snapshot: failed to read file — skipping");
            }
        }

        if !found_any {
            return Err(ListsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "snapshot dir {} contained no .txt files",
                    snapshot_dir.display()
                ),
            )));
        }

        spawn_blocking_compile(builder).await
    }

    /// Main refresh loop.  Runs until the task is cancelled.
    async fn run_refresh_loop(&self) {
        // If rules are empty (cold start), do a first fetch after a short delay.
        {
            // Guard<Arc<CompiledRules>> derefs through Arc → CompiledRules.
            let rules_guard = self.engine.current_rules();
            let is_empty = rules_guard.meta.block_count == 0;
            drop(rules_guard);
            if is_empty {
                sleep(COLD_START_FETCH_DELAY).await;
            }
        }

        let mut backoff = BACKOFF_INITIAL;

        loop {
            let changed = self.fetch_and_compile_if_changed().await;
            match changed {
                Ok(true) => {
                    info!("lists refreshed and swapped");
                    backoff = BACKOFF_INITIAL; // reset backoff
                }
                Ok(false) => {
                    debug!("lists unchanged (304 or no-op)");
                    backoff = BACKOFF_INITIAL;
                }
                Err(e) => {
                    warn!(error = %e, "list refresh failed; keeping current rules");
                    // Exponential backoff capped at BACKOFF_CAP.
                    sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, BACKOFF_CAP);
                    continue;
                }
            }

            // Normal interval: refresh_hours ± jitter.
            // Re-read config under lock so a hot-reload of refresh_hours takes effect.
            let (refresh_hours, jitter_minutes) = {
                let cfg = self.config.lock().unwrap_or_else(|e| e.into_inner());
                (cfg.refresh_hours, cfg.jitter_minutes)
            };
            let interval = compute_next_interval(refresh_hours, jitter_minutes);
            debug!(interval_secs = interval.as_secs(), "next list refresh");
            sleep(interval).await;
        }
    }

    /// Fetch all sources (conditional GET), compile if any changed.
    ///
    /// Returns `Ok(true)` if rules were swapped, `Ok(false)` if no changes,
    /// `Err` if all sources failed.
    pub async fn fetch_and_compile_if_changed(&self) -> Result<bool, ListsError> {
        let lists_dir = self.state_dir.join("lists");
        let validators_path = self.state_dir.join("validators.json");
        let mut validators = Validators::load(&validators_path);

        let mut any_changed = false;
        let mut all_failed = true;

        for source in &self.sources() {
            let (etag, last_mod) = validators.get(&source.url);
            let result = fetch_source(&self.http, &source.url, etag, last_mod).await;
            match result {
                Ok(FetchResult::NotModified) => {
                    all_failed = false;
                    // 304 = content validated as current; counts as a successful fetch.
                    self.record_source_ok(&source.url);
                    debug!(url = %source.url, "source not modified (304)");
                }
                Ok(FetchResult::Content {
                    data,
                    etag: new_etag,
                    last_modified,
                }) => {
                    all_failed = false;
                    any_changed = true;
                    let file_path = source_file_path(&lists_dir, &source.url);
                    std::fs::create_dir_all(&lists_dir)?;
                    std::fs::write(&file_path, &data)?;
                    validators.set(&source.url, new_etag, last_modified);
                    self.record_source_ok(&source.url);
                    info!(url = %source.url, bytes = data.len(), "source updated");
                }
                Err(e) => {
                    warn!(url = %source.url, error = %e, "source fetch failed; using cached");
                    self.record_source_error(&source.url, e.to_string());
                    // Any fetch failure = use cached (do not flip all_failed if others ok).
                    // But we keep all_failed tracking for the "ALL fail" case.
                }
            }
        }

        validators.save(&validators_path);

        if all_failed {
            return Err(ListsError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "all list sources failed",
            )));
        }

        if !any_changed {
            return Ok(false);
        }

        // Recompile from all cached raw sources (also updates per-source rule counts).
        let rules = self.compile_from_raw_cache().await?;
        let compiled_dir = self.state_dir.join("compiled");
        if let Err(e) = rules.save(&compiled_dir) {
            warn!(error = %e, "failed to save compiled rules to disk");
        }
        self.engine.swap_rules(Arc::new(rules));
        self.record_swap();
        Ok(true)
    }

    /// Force a full refresh (used by WP3's `POST /lists/refresh`).
    // WP3-seam: called by the control API endpoint.
    #[allow(dead_code)]
    pub async fn force_refresh(&self) -> Result<bool, ListsError> {
        // Remove validators to force fresh 200 on all sources.
        let validators_path = self.state_dir.join("validators.json");
        let _ = std::fs::remove_file(&validators_path);
        self.fetch_and_compile_if_changed().await
    }
}

// ── Tracking helpers ──────────────────────────────────────────────────────────

impl ListsPipeline {
    /// Record a successful fetch for `url` (200 or 304).
    ///
    /// Sets `last_ok_unix_ms` to now and clears any previous `last_error`.
    fn record_source_ok(&self, url: &str) {
        let now = unix_ms_now();
        let mut guard = self.source_track.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(url.to_owned()).or_default();
        entry.last_ok_unix_ms = Some(now);
        entry.last_error = None;
    }

    /// Record a fetch failure for `url`.
    ///
    /// Stores the error string; `last_ok_unix_ms` is preserved so the previous
    /// good time remains visible.
    fn record_source_error(&self, url: &str, error: String) {
        let mut guard = self.source_track.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(url.to_owned()).or_default();
        entry.last_error = Some(error);
    }

    /// Record a successful rule swap (called after `engine.swap_rules`).
    fn record_swap(&self) {
        let now = unix_ms_now();
        let mut guard = self
            .last_swap_unix_ms
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(now);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Current Unix time in milliseconds, best-effort.
///
/// Falls back to 0 on platforms where `SystemTime` is unavailable; this is
/// cosmetic metadata and never affects correctness.
fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Outcome of a single source fetch.
enum FetchResult {
    /// HTTP 304 — content unchanged.
    NotModified,
    /// HTTP 200 — new content.
    Content {
        data: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// Fetch a single source with conditional GET headers.
async fn fetch_source(
    client: &reqwest::Client,
    url: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Result<FetchResult, ListsError> {
    let mut headers = HeaderMap::new();
    if let Some(e) = etag {
        if let Ok(v) = e.parse() {
            headers.insert(IF_NONE_MATCH, v);
        }
    }
    if let Some(lm) = last_modified {
        if let Ok(v) = lm.parse() {
            headers.insert(IF_MODIFIED_SINCE, v);
        }
    }

    let resp = client
        .get(url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| ListsError::Http {
            url: url.to_string(),
            source: e,
        })?;

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(FetchResult::NotModified);
    }

    if !resp.status().is_success() {
        // error_for_status() is Err on non-2xx; we checked above — the
        // match here makes the error extraction explicit without unwrap_err.
        return match resp.error_for_status() {
            Ok(_) => {
                // PANIC-OK: we just verified !is_success() above; this arm
                // is unreachable by construction.
                unreachable!("error_for_status returned Ok on non-success status")
            }
            Err(source) => Err(ListsError::Http {
                url: url.to_string(),
                source,
            }),
        };
    }

    // Guard against poisoned sources.
    if let Some(content_length) = resp.content_length() {
        if content_length > MAX_SOURCE_BYTES {
            return Err(ListsError::SourceTooLarge {
                url: url.to_string(),
            });
        }
    }

    let new_etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let new_lm = resp
        .headers()
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Read body with size limit.
    let bytes = resp.bytes().await.map_err(|e| ListsError::Http {
        url: url.to_string(),
        source: e,
    })?;

    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(ListsError::SourceTooLarge {
            url: url.to_string(),
        });
    }

    Ok(FetchResult::Content {
        data: bytes.to_vec(),
        etag: new_etag,
        last_modified: new_lm,
    })
}

/// Compute the next refresh interval: `refresh_hours` ± jitter.
fn compute_next_interval(refresh_hours: u32, jitter_minutes: u32) -> Duration {
    let base_ms = (refresh_hours as u64) * 3600 * 1000;
    let jitter_ms = if jitter_minutes > 0 {
        let max = (jitter_minutes as u64) * 60 * 1000;
        // Use sub-second time as a cheap non-crypto random source.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        (seed as u64) % max
    } else {
        0
    };
    Duration::from_millis(base_ms + jitter_ms)
}

/// Build a deterministic raw-file path for a given source URL.
fn source_file_path(lists_dir: &Path, url: &str) -> PathBuf {
    // Replace all non-alphanumeric characters with '_' to get a safe filename.
    let safe: String = url
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    lists_dir.join(format!("{safe}.txt"))
}

/// Compile rules off the tokio thread pool.
async fn spawn_blocking_compile(builder: RulesBuilder) -> Result<CompiledRules, ListsError> {
    tokio::task::spawn_blocking(move || {
        builder
            .build()
            .map_err(|e| ListsError::Compile(e.to_string()))
    })
    .await
    .map_err(|e| ListsError::Compile(e.to_string()))?
}

// Note: `DecisionEngine::current_rules()` was added as a minimal core
// extension in WP2 to allow the list pipeline to inspect the active rule-set
// metadata (e.g. detect empty rules on cold start) without duplicating the
// arc_swap field.  Flagged in run summary per specs/standards.md §7.

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // ── compute_next_interval ─────────────────────────────────────────────────

    #[test]
    fn interval_at_least_refresh_hours() {
        let dur = compute_next_interval(24, 60);
        let base = Duration::from_secs(24 * 3600);
        assert!(dur >= base, "interval must be at least refresh_hours");
        let max = Duration::from_secs(24 * 3600 + 60 * 60);
        assert!(
            dur <= max,
            "interval must not exceed refresh_hours + jitter"
        );
    }

    #[test]
    fn interval_zero_jitter_exact() {
        let dur = compute_next_interval(12, 0);
        assert_eq!(dur, Duration::from_secs(12 * 3600));
    }

    // ── source_file_path ─────────────────────────────────────────────────────

    #[test]
    fn source_file_path_is_safe() {
        let dir = PathBuf::from("/tmp/lists");
        let p = source_file_path(&dir, "https://small.oisd.nl/domainswild2");
        let name = p.file_name().unwrap().to_str().unwrap();
        // Must not contain / : etc.
        assert!(!name.contains('/'));
        assert!(!name.contains(':'));
    }

    // ── compile_from_raw_cache (via spawn_blocking_compile) ───────────────────

    #[tokio::test]
    async fn blocking_compile_empty_builder() {
        let builder = RulesBuilder::new();
        let rules = spawn_blocking_compile(builder).await.unwrap();
        assert_eq!(rules.meta.block_count, 0);
    }

    #[tokio::test]
    async fn blocking_compile_with_domains() {
        use hush_core::rules::RuleSink;
        let mut builder = RulesBuilder::new();
        builder.block(hush_core::Domain::parse("ads.example.com").unwrap());
        let rules = spawn_blocking_compile(builder).await.unwrap();
        assert_eq!(rules.meta.block_count, 1);
    }

    // ── status() merge — unit tests ──────────────────────────────────────────

    /// Build a minimal ListsPipeline pointing at `state_dir` with one source.
    fn make_pipeline(state_dir: &std::path::Path, url: &str) -> Arc<ListsPipeline> {
        use hush_core::config::ListSource;
        let config = ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: vec![ListSource {
                name: "test".to_string(),
                url: url.to_string(),
            }],
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: None,
        };
        Arc::new(ListsPipeline::new(
            config,
            state_dir.to_path_buf(),
            Arc::new(hush_core::DecisionEngine::new()),
        ))
    }

    /// Build a ListsPipeline with a snapshot_dir configured.
    fn make_pipeline_with_snapshot(
        state_dir: &std::path::Path,
        snapshot_dir: &std::path::Path,
    ) -> Arc<ListsPipeline> {
        let config = ListsConfig {
            preset: "custom".to_string(),
            extra_categories: Vec::new(),
            sources: Vec::new(),
            refresh_hours: 24,
            jitter_minutes: 0,
            snapshot_dir: Some(snapshot_dir.to_string_lossy().into_owned()),
        };
        Arc::new(ListsPipeline::new(
            config,
            state_dir.to_path_buf(),
            Arc::new(hush_core::DecisionEngine::new()),
        ))
    }

    #[test]
    fn status_initially_all_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_pipeline(tmp.path(), "http://example.com/list");
        let s = p.status();
        assert_eq!(s.per_source.len(), 1);
        assert!(s.per_source[0].last_ok_unix_ms.is_none(), "no fetch yet");
        assert!(s.per_source[0].last_error.is_none());
        assert!(s.per_source[0].last_rule_count.is_none());
        assert!(s.last_swap_unix_ms.is_none());
    }

    #[test]
    fn status_after_record_source_ok_shows_timestamp() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_pipeline(tmp.path(), "http://example.com/list");
        p.record_source_ok("http://example.com/list");
        let s = p.status();
        assert!(
            s.per_source[0].last_ok_unix_ms.is_some(),
            "last_ok must be set after record_source_ok"
        );
        assert!(s.per_source[0].last_error.is_none());
    }

    #[test]
    fn status_after_record_source_error_shows_error_keeps_previous_ok() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_pipeline(tmp.path(), "http://example.com/list");
        // First a successful fetch.
        p.record_source_ok("http://example.com/list");
        let ok_ts = p.status().per_source[0].last_ok_unix_ms;
        assert!(ok_ts.is_some());
        // Now an error.
        p.record_source_error("http://example.com/list", "connection refused".to_string());
        let s = p.status();
        assert_eq!(
            s.per_source[0].last_ok_unix_ms, ok_ts,
            "previous last_ok must be preserved after error"
        );
        assert_eq!(
            s.per_source[0].last_error.as_deref(),
            Some("connection refused"),
        );
    }

    #[test]
    fn status_record_ok_clears_previous_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_pipeline(tmp.path(), "http://example.com/list");
        p.record_source_error("http://example.com/list", "timeout".to_string());
        p.record_source_ok("http://example.com/list");
        let s = p.status();
        assert!(
            s.per_source[0].last_error.is_none(),
            "error must be cleared after ok"
        );
    }

    #[test]
    fn status_after_record_swap_shows_timestamp() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_pipeline(tmp.path(), "http://example.com/list");
        assert!(p.status().last_swap_unix_ms.is_none());
        p.record_swap();
        assert!(
            p.status().last_swap_unix_ms.is_some(),
            "last_swap must be set after record_swap"
        );
    }

    #[tokio::test]
    async fn compile_from_raw_cache_records_rule_counts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lists_dir = tmp.path().join("lists");
        std::fs::create_dir_all(&lists_dir).unwrap();
        // Write two domains into the list file.
        let file_name = source_file_path(&lists_dir, "http://example.com/list");
        std::fs::write(&file_name, "ads.example.com\ntracker.bad.com\n").unwrap();

        let p = make_pipeline(tmp.path(), "http://example.com/list");
        p.compile_from_raw_cache().await.unwrap();

        let s = p.status();
        let rule_count = s.per_source[0].last_rule_count;
        assert_eq!(
            rule_count,
            Some(2),
            "must record 2 rules from the source file"
        );
    }

    // ── WP12 §1: snapshot cold-start ─────────────────────────────────────────

    /// Snapshot dir empty → compile_from_snapshot returns Err (no .txt files).
    #[tokio::test]
    async fn compile_from_snapshot_empty_dir_returns_err() {
        let tmp = tempfile::TempDir::new().unwrap();
        let snap_dir = tmp.path().join("snapshot");
        std::fs::create_dir_all(&snap_dir).unwrap();

        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let p = make_pipeline_with_snapshot(&state_dir, &snap_dir);
        let result = p.compile_from_snapshot(&snap_dir).await;
        assert!(result.is_err(), "empty snapshot dir must return Err");
    }

    /// Snapshot dir does not exist → try_load_snapshot returns false.
    #[tokio::test]
    async fn try_load_snapshot_missing_dir_returns_false() {
        let tmp = tempfile::TempDir::new().unwrap();
        let snap_dir = tmp.path().join("nonexistent_snapshot");
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let p = make_pipeline_with_snapshot(&state_dir, &snap_dir);
        let swapped = p.try_load_snapshot().await;
        assert!(!swapped, "missing snapshot dir must return false");
    }

    /// snapshot_dir not configured → try_load_snapshot returns false.
    #[tokio::test]
    async fn try_load_snapshot_no_config_returns_false() {
        let tmp = tempfile::TempDir::new().unwrap();
        // make_pipeline has snapshot_dir = None.
        let p = make_pipeline(tmp.path(), "http://example.com/list");
        let swapped = p.try_load_snapshot().await;
        assert!(!swapped, "unconfigured snapshot_dir must return false");
    }

    /// Cold start with populated snapshot: rules compiled, queries blocked,
    /// engine block_count > 0 before any network fetch.
    #[tokio::test]
    async fn cold_start_with_snapshot_loads_rules() {
        let tmp = tempfile::TempDir::new().unwrap();
        let snap_dir = tmp.path().join("snapshot");
        std::fs::create_dir_all(&snap_dir).unwrap();

        // Write a small snapshot list (two blocked domains).
        std::fs::write(
            snap_dir.join("hagezi-light.txt"),
            "ads.example.com\ntracker.bad.org\n",
        )
        .unwrap();
        // manifest.json should be ignored (not a .txt file).
        std::fs::write(
            snap_dir.join("manifest.json"),
            r#"{"source":"hagezi-light"}"#,
        )
        .unwrap();

        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let p = make_pipeline_with_snapshot(&state_dir, &snap_dir);
        // Confirm engine starts empty.
        assert_eq!(p.engine.current_rules().meta.block_count, 0);

        // Trigger snapshot load.
        let swapped = p.try_load_snapshot().await;
        assert!(swapped, "snapshot load must return true when files present");

        // Engine must now have rules (2 domains).
        let block_count = p.engine.current_rules().meta.block_count;
        assert_eq!(
            block_count, 2,
            "engine must have 2 blocked domains from snapshot; got {block_count}"
        );
    }

    /// Full start() cold-start path: no compiled artifact, no raw cache,
    /// snapshot present → engine has rules after start().
    #[tokio::test]
    async fn start_cold_with_snapshot_swaps_rules_before_fetch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let snap_dir = tmp.path().join("snapshot");
        std::fs::create_dir_all(&snap_dir).unwrap();
        std::fs::write(
            snap_dir.join("hagezi-multi.txt"),
            "spam.example.com\nmalware.bad.com\nphishing.test.net\n",
        )
        .unwrap();

        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let pipeline = make_pipeline_with_snapshot(&state_dir, &snap_dir);
        // start() must return with rules swapped — no network fetch happens
        // in this test (the refresh loop runs async in the background and
        // fails immediately on a tempdir URL, which is fine for this test).
        Arc::clone(&pipeline).start().await;

        let block_count = pipeline.engine.current_rules().meta.block_count;
        assert_eq!(
            block_count, 3,
            "start() must compile snapshot and swap rules; got block_count={block_count}"
        );
    }

    /// manifest.json and non-.txt files in snapshot dir are ignored.
    #[tokio::test]
    async fn compile_from_snapshot_ignores_non_txt() {
        let tmp = tempfile::TempDir::new().unwrap();
        let snap_dir = tmp.path().join("snapshot");
        std::fs::create_dir_all(&snap_dir).unwrap();
        std::fs::write(snap_dir.join("manifest.json"), r#"{"url":"test"}"#).unwrap();
        std::fs::write(snap_dir.join("hagezi-light.txt"), "ads.example.com\n").unwrap();

        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let p = make_pipeline_with_snapshot(&state_dir, &snap_dir);
        let rules = p.compile_from_snapshot(&snap_dir).await.unwrap();
        assert_eq!(
            rules.meta.block_count, 1,
            "only .txt files must be parsed; manifest.json must be ignored"
        );
    }
}
