//! SQLite query-log rollup writer.
//!
//! Implements `specs/wp9-dashboard-rollup.md` §2–§3 and
//! `specs/wp13-network-guard.md` §3.
//!
//! ## Architecture
//!
//! A bounded tokio channel carries [`RollupRecord`]s from the DNS hot path
//! (tee'd after the ring push in `dns.rs`).  A single background task drains
//! the channel, batches rows, and flushes every 2 s or 256 rows — whichever
//! comes first.
//!
//! SQLite is opened in WAL mode so readers never block the writer.  Writes are
//! always synchronous (single-writer invariant).
//!
//! ## Schema history
//!
//! ### v1 (WP9)
//!
//! ```sql
//! CREATE TABLE queries(ts_ms INTEGER, qname TEXT, qtype INTEGER,
//!                      verdict TEXT, reason TEXT, detail TEXT);
//! CREATE INDEX queries_ts ON queries(ts_ms);
//! CREATE TABLE meta(schema_version INTEGER);
//! ```
//!
//! ### v2 (WP13)
//!
//! Adds a nullable `client` TEXT column for the Network Guard per-client IP.
//! Existing v1 rows are preserved; migration updates `meta.schema_version` to 2.
//!
//! ```sql
//! ALTER TABLE queries ADD COLUMN client TEXT;  -- NULL for loopback / log_clients=false
//! UPDATE meta SET schema_version = 2;
//! ```
//!
//! ## Mode interplay
//!
//! - `query_log = "off"` → the DB file is never opened; the channel sender is
//!   dropped immediately so the writer task exits after its first drain.
//! - `query_log = "anonymous"` → rows carry `qname = "<redacted>"`.
//! - `query_log = "full"` → rows carry the actual qname.
//!
//! ## Corruption recovery
//!
//! If `rusqlite::Connection::open` or the schema setup fails, the corrupt file
//! is renamed to `<name>.corrupt.<timestamp>` and a fresh DB is created.  The
//! daemon never crashes on DB errors; DNS resolution continues unaffected.

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use rusqlite::Connection;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use hush_core::config::QueryLogMode;

// ── Constants ──────────────────────────────────────────────────────────────────

/// Bounded channel capacity.  When full, the hot path drops rather than blocks.
const CHANNEL_CAP: usize = 4096;
/// Maximum rows to accumulate before forcing a flush.
const BATCH_SIZE: usize = 256;
/// Flush interval.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
/// Current schema version stored in `meta`.
///
/// v1 = WP9 baseline; v2 = WP13 adds nullable `client` column.
const SCHEMA_VERSION: i64 = 2;
/// Maximum SQLite file size in bytes (100 MB).
const SIZE_CAP_BYTES: u64 = 100 * 1024 * 1024;

// ── Public types ──────────────────────────────────────────────────────────────

/// A single query record to be persisted to SQLite.
///
/// This mirrors [`hush_core::querylog::QueryRecord`] but carries pre-serialised
/// `verdict` and `reason` strings, which are the canonical form for storage.
#[derive(Debug, Clone)]
pub struct RollupRecord {
    /// Unix timestamp in milliseconds.
    pub ts_ms: u64,
    /// Queried domain name (or `"<redacted>"` in anonymous mode).
    pub qname: String,
    /// DNS query type code.
    pub qtype: u16,
    /// Verdict string (`"block"`, `"forward"`, `"forward_local"`).
    pub verdict: String,
    /// Reason string.
    pub reason: String,
    /// WP13: source client IP (as text) when `network_guard.log_clients = true`
    /// and the query arrived on a guard listener.  `None` for loopback queries
    /// and when `log_clients = false`.
    pub client: Option<std::net::IpAddr>,
}

/// Atomic drop counter — incremented when the channel is full and a record
/// is dropped.  Exposed via [`RollupHandle::drops`] for the Metrics system.
#[derive(Debug, Default)]
pub struct RollupDrops(AtomicU64);

impl RollupDrops {
    /// Increment the drop counter by 1.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Return the current drop count.
    pub fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ── Public handle ─────────────────────────────────────────────────────────────

/// Handle to the rollup writer task.
///
/// Clone this and call [`RollupHandle::try_send`] from the DNS hot path.
/// When all senders are dropped the writer task drains and exits cleanly.
#[derive(Clone)]
pub struct RollupHandle {
    /// Channel sender (None when query_log="off").
    tx: Option<mpsc::Sender<RollupRecord>>,
    /// Shared drop counter.
    drops: Arc<RollupDrops>,
}

impl RollupHandle {
    /// Try to send a record to the rollup writer.
    ///
    /// On full channel: increments the drop counter and returns without
    /// blocking.  This is the hot-path contract.
    pub fn try_send(&self, rec: RollupRecord) {
        let Some(tx) = &self.tx else { return };
        if tx.try_send(rec).is_err() {
            self.drops.inc();
        }
    }

    /// Return the current drop count.
    pub fn drops(&self) -> u64 {
        self.drops.load()
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Start the rollup writer task and return a [`RollupHandle`] for the hot path.
///
/// When `mode` is [`QueryLogMode::Off`] the DB file is never opened and the
/// returned handle silently discards all records.
///
/// The writer task runs until all senders are dropped (daemon shutdown) or
/// until the cancellation token fires.
pub fn start_rollup(
    state_dir: PathBuf,
    mode: QueryLogMode,
    retain_days: u32,
    cancel: tokio_util::sync::CancellationToken,
) -> RollupHandle {
    let drops = Arc::new(RollupDrops::default());

    if mode == QueryLogMode::Off {
        // Never open the DB.
        return RollupHandle { tx: None, drops };
    }

    let (tx, rx) = mpsc::channel::<RollupRecord>(CHANNEL_CAP);
    let drops2 = Arc::clone(&drops);
    tokio::spawn(writer_task(state_dir, rx, retain_days, drops2, cancel));

    RollupHandle {
        tx: Some(tx),
        drops,
    }
}

// ── Writer task ───────────────────────────────────────────────────────────────

/// Core writer loop: drains the channel, batches inserts, handles retention.
async fn writer_task(
    state_dir: PathBuf,
    mut rx: mpsc::Receiver<RollupRecord>,
    retain_days: u32,
    _drops: Arc<RollupDrops>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let db_path = state_dir.join("querylog.sqlite");
    let conn = match open_db(&db_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "rollup: could not open DB; rollup disabled for this run");
            return;
        }
    };

    let mut batch: Vec<RollupRecord> = Vec::with_capacity(BATCH_SIZE);
    let flush_interval = tokio::time::interval(FLUSH_INTERVAL);
    tokio::pin!(flush_interval);

    // Hourly retention ticker.
    let retention_interval = tokio::time::interval(Duration::from_secs(3600));
    tokio::pin!(retention_interval);
    // Consume the first immediate tick so retention doesn't run on startup.
    retention_interval.as_mut().tick().await;

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                // Drain remaining records before exiting.
                while let Ok(rec) = rx.try_recv() {
                    batch.push(rec);
                }
                flush_batch(&conn, &batch);
                debug!("rollup: writer task cancelled; flushed {} rows", batch.len());
                break;
            }
            Some(rec) = rx.recv() => {
                batch.push(rec);
                if batch.len() >= BATCH_SIZE {
                    flush_batch(&conn, &batch);
                    batch.clear();
                }
            }
            _ = flush_interval.tick() => {
                if !batch.is_empty() {
                    flush_batch(&conn, &batch);
                    batch.clear();
                }
            }
            _ = retention_interval.tick() => {
                run_retention(&conn, retain_days);
            }
            else => {
                // Channel closed — flush and exit.
                flush_batch(&conn, &batch);
                debug!("rollup: channel closed; writer task exiting");
                break;
            }
        }
    }
}

// ── DB helpers ────────────────────────────────────────────────────────────────

/// Open or create the SQLite database at `path`.
///
/// Enables WAL mode and creates the v1 schema if it doesn't exist.
/// On corruption: renames the file aside and recreates.
fn open_db(path: &Path) -> Result<Connection, DbError> {
    match try_open_db(path) {
        Ok(c) => Ok(c),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "rollup: DB open/schema error; renaming aside and recreating");
            rename_corrupt(path);
            try_open_db(path)
        }
    }
}

fn try_open_db(path: &Path) -> Result<Connection, DbError> {
    // Set permissions to 0600 on creation (Unix).
    // rusqlite creates the file before we can set perms on the path; we use
    // the OpenFlags to open read/write + create, then set perms immediately.
    let conn = Connection::open(path).map_err(DbError::Open)?;

    // PRAGMA auto_vacuum=INCREMENTAL must be set BEFORE any schema creation so
    // SQLite activates the auto-vacuum mechanism on page allocation.  For a
    // pre-existing DB that was created without it, we detect and migrate below.
    //
    // Enable WAL mode FIRST — must precede auto_vacuum for correct interaction.
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(DbError::Schema)?;

    // Check if auto_vacuum is already enabled (2 = INCREMENTAL).
    // For a brand-new DB (size=0) or a DB that doesn't yet have the pragma set,
    // we can simply set it.  For an existing DB with auto_vacuum=0 (NONE), we
    // must set it AND run a full VACUUM to rebuild the freelist tracking pages.
    let auto_vacuum_mode: i64 = conn
        .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
        .unwrap_or(0);

    if auto_vacuum_mode != 2 {
        // Set INCREMENTAL auto_vacuum.  On an existing DB this is a no-op
        // unless followed by a full VACUUM (which rebuilds the B-tree).
        conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")
            .map_err(DbError::Schema)?;
        // Only run the full VACUUM when the DB already has data (page_count > 1).
        // For a fresh DB the subsequent CREATE TABLE calls handle it correctly.
        let page_count: i64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap_or(0);
        if page_count > 1 {
            // Full VACUUM re-applies auto_vacuum to the existing pages.
            // This is a one-time migration cost.
            conn.execute_batch("VACUUM;").map_err(DbError::Schema)?;
        }
    }

    // Create schema if needed (v2 includes the `client` column).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS queries (
             ts_ms   INTEGER NOT NULL,
             qname   TEXT    NOT NULL,
             qtype   INTEGER NOT NULL,
             verdict TEXT    NOT NULL,
             reason  TEXT    NOT NULL,
             detail  TEXT,
             client  TEXT
         );
         CREATE INDEX IF NOT EXISTS queries_ts ON queries(ts_ms);
         CREATE TABLE IF NOT EXISTS meta (schema_version INTEGER NOT NULL);",
    )
    .map_err(DbError::Schema)?;

    // Insert schema version if not already present.
    let version: Option<i64> = conn
        .query_row("SELECT schema_version FROM meta LIMIT 1", [], |row| {
            row.get(0)
        })
        .ok();

    if let Some(v) = version {
        // Migrate existing database if at an older schema version.
        if v < 2 {
            migrate_v1_to_v2(&conn)?;
        }
    } else {
        // Fresh database: insert current schema version.
        conn.execute(
            "INSERT INTO meta(schema_version) VALUES(?1)",
            [SCHEMA_VERSION],
        )
        .map_err(DbError::Schema)?;
    }

    // Set file permissions to 0600 (owner r/w only) on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    Ok(conn)
}

/// Migrate a v1 database to v2.
///
/// Adds the nullable `client` TEXT column and bumps `meta.schema_version` to 2.
/// Existing rows are preserved with `client = NULL`.
fn migrate_v1_to_v2(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "ALTER TABLE queries ADD COLUMN client TEXT;
         UPDATE meta SET schema_version = 2;",
    )
    .map_err(DbError::Schema)?;
    info!("rollup: migrated schema v1 → v2 (added client column)");
    Ok(())
}

/// Rename a potentially corrupt DB aside.
fn rename_corrupt(path: &Path) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let corrupt_path = path.with_extension(format!("corrupt.{ts}"));
    if let Err(e) = std::fs::rename(path, &corrupt_path) {
        warn!(
            from = %path.display(),
            to = %corrupt_path.display(),
            error = %e,
            "rollup: could not rename corrupt DB aside"
        );
    } else {
        warn!(
            original = %path.display(),
            renamed_to = %corrupt_path.display(),
            "rollup: corrupt DB renamed aside; a fresh DB will be created"
        );
    }
}

/// Flush a batch of records into SQLite using a single transaction.
///
/// Errors are logged and the batch is silently dropped — DNS must never block.
fn flush_batch(conn: &Connection, batch: &[RollupRecord]) {
    if batch.is_empty() {
        return;
    }
    let result = (|| -> Result<(), DbError> {
        let tx = conn.unchecked_transaction().map_err(DbError::Insert)?;
        for rec in batch {
            // WP13: client is stored as a text IP string (or NULL).
            let client_str: Option<String> = rec.client.map(|ip| ip.to_string());
            tx.execute(
                "INSERT INTO queries(ts_ms, qname, qtype, verdict, reason, detail, client)
                 VALUES(?1, ?2, ?3, ?4, ?5, NULL, ?6)",
                rusqlite::params![
                    rec.ts_ms as i64,
                    rec.qname,
                    rec.qtype as i64,
                    rec.verdict,
                    rec.reason,
                    client_str,
                ],
            )
            .map_err(DbError::Insert)?;
        }
        tx.commit().map_err(DbError::Insert)?;
        Ok(())
    })();
    if let Err(e) = result {
        warn!(error = %e, count = batch.len(), "rollup: batch flush failed; rows dropped");
    } else {
        debug!(count = batch.len(), "rollup: flushed batch to sqlite");
    }
}

// ── Retention ─────────────────────────────────────────────────────────────────

/// Delete rows older than `retain_days` and enforce the 100 MB size cap.
///
/// Uses `PRAGMA incremental_vacuum` after deleting to reclaim space.
/// Errors are logged and ignored — retention failure is not fatal.
pub(crate) fn run_retention(conn: &Connection, retain_days: u32) {
    let cutoff_ms = cutoff_ms_for_days(retain_days);
    match conn.execute("DELETE FROM queries WHERE ts_ms < ?1", [cutoff_ms]) {
        Ok(n) => {
            if n > 0 {
                info!(
                    deleted = n,
                    retain_days, "rollup: retention deleted old rows"
                );
            }
        }
        Err(e) => {
            warn!(error = %e, "rollup: retention delete failed");
            return;
        }
    }

    // Size cap: if the DB is over SIZE_CAP_BYTES, delete oldest rows in batches.
    // `enforce_size_cap` runs incremental_vacuum after each delete batch.
    enforce_size_cap(conn);

    // Final incremental vacuum pass to reclaim any remaining free pages after
    // the retention delete (size-cap already vacuums per-batch above).
    let _ = conn.execute_batch("PRAGMA incremental_vacuum(500);");
}

fn cutoff_ms_for_days(retain_days: u32) -> i64 {
    let retain_ms = retain_days as u64 * 24 * 3600 * 1000;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    now_ms.saturating_sub(retain_ms) as i64
}

fn enforce_size_cap(conn: &Connection) {
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .unwrap_or(4096);

    /// Helper: return freelist-adjusted occupied bytes.
    ///
    /// `page_count` includes free (recycled) pages that still occupy disk space
    /// until vacuumed.  Subtracting `freelist_count` gives the number of pages
    /// actually used by live data — this is the correct input to the size-cap
    /// decision so we don't delete more rows than necessary.
    fn occupied_bytes(conn: &Connection, page_size: i64) -> u64 {
        let page_count: i64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap_or(0);
        let freelist_count: i64 = conn
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))
            .unwrap_or(0);
        let live_pages = page_count.saturating_sub(freelist_count).max(0);
        (live_pages * page_size) as u64
    }

    if occupied_bytes(conn, page_size) <= SIZE_CAP_BYTES {
        return;
    }

    // Delete 1000 oldest rows at a time until under the cap.
    // Cap at 100 iterations per retention run to bound worst-case latency.
    let mut iterations = 0;
    while iterations < 100 {
        iterations += 1;
        match conn.execute(
            "DELETE FROM queries WHERE rowid IN (SELECT rowid FROM queries ORDER BY ts_ms ASC LIMIT 1000)",
            [],
        ) {
            Ok(0) => break, // Nothing left to delete.
            Ok(n) => {
                debug!(deleted = n, "rollup: size cap trimmed rows");
                // Run incremental vacuum after each batch so freed pages are
                // reclaimed and `freelist_count` reflects the deletion.
                let _ = conn.execute_batch("PRAGMA incremental_vacuum(200);");
            }
            Err(e) => {
                warn!(error = %e, "rollup: size cap delete failed");
                break;
            }
        }
        // Re-check freelist-adjusted size.
        if occupied_bytes(conn, page_size) <= SIZE_CAP_BYTES {
            break;
        }
    }
}

// ── Stats queries ─────────────────────────────────────────────────────────────

/// A single time-bucket for the history API.
#[derive(Debug, Clone)]
pub struct HistoryBucket {
    /// Bucket start time (Unix ms, aligned to `bucket_secs`).
    pub ts: u64,
    /// Total queries in the bucket.
    pub total: u64,
    /// Blocked queries in the bucket.
    pub blocked: u64,
}

/// Query time-bucketed history from the rollup DB.
///
/// Returns empty vec when the DB doesn't exist (log_mode=off).
pub fn query_history(
    db_path: &Path,
    hours: u32,
    bucket_secs: u32,
) -> Result<Vec<HistoryBucket>, DbError> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open(db_path).map_err(DbError::Open)?;
    let now_ms = now_ms();
    let since_ms = now_ms.saturating_sub(hours as u64 * 3600 * 1000) as i64;
    let bucket_ms = bucket_secs as i64 * 1000;

    let mut stmt = conn
        .prepare(
            "SELECT (ts_ms / ?1) * ?1 AS bucket,
                    COUNT(*) AS total,
                    SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) AS blocked
             FROM queries
             WHERE ts_ms >= ?2
             GROUP BY bucket
             ORDER BY bucket ASC",
        )
        .map_err(DbError::Query)?;

    let rows = stmt
        .query_map([bucket_ms, since_ms], |row| {
            Ok(HistoryBucket {
                ts: row.get::<_, i64>(0)? as u64,
                total: row.get::<_, i64>(1)? as u64,
                blocked: row.get::<_, i64>(2)? as u64,
            })
        })
        .map_err(DbError::Query)?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(DbError::Query)?);
    }
    Ok(result)
}

/// Per-client statistics row returned by [`query_clients`].
#[derive(Debug, Clone)]
pub struct ClientEntry {
    /// Client IP address as a string.
    pub client: String,
    /// Total queries from this client in the window.
    pub total: u64,
    /// Blocked queries from this client in the window.
    pub blocked: u64,
}

/// Query per-client totals from the rollup DB (WP13 `GET /v0/clients`).
///
/// Returns empty vec when:
/// - The DB doesn't exist (log_mode=off).
/// - No rows with a non-NULL client exist.
pub fn query_clients(db_path: &Path, hours: u32) -> Result<Vec<ClientEntry>, DbError> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open(db_path).map_err(DbError::Open)?;
    let now_ms = now_ms();
    let since_ms = now_ms.saturating_sub(hours as u64 * 3600 * 1000) as i64;

    let mut stmt = conn
        .prepare(
            "SELECT client,
                    COUNT(*) AS total,
                    SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) AS blocked
             FROM queries
             WHERE ts_ms >= ?1 AND client IS NOT NULL
             GROUP BY client
             ORDER BY total DESC",
        )
        .map_err(DbError::Query)?;

    let rows = stmt
        .query_map([since_ms], |row| {
            Ok(ClientEntry {
                client: row.get::<_, String>(0)?,
                total: row.get::<_, i64>(1)? as u64,
                blocked: row.get::<_, i64>(2)? as u64,
            })
        })
        .map_err(DbError::Query)?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(DbError::Query)?);
    }
    Ok(result)
}

/// A single top-domain entry.
#[derive(Debug, Clone)]
pub struct TopEntry {
    /// Domain name.
    pub qname: String,
    /// Count of queries matching the filter.
    pub count: u64,
}

/// Query top blocked and top allowed domains from the rollup DB.
///
/// Returns empty vecs when the DB doesn't exist or mode is anonymous/off.
pub fn query_top(
    db_path: &Path,
    n: u32,
    hours: u32,
    mode: QueryLogMode,
) -> Result<(Vec<TopEntry>, Vec<TopEntry>), DbError> {
    // Anonymous mode: qnames are "<redacted>" — top-N is meaningless.
    if mode != QueryLogMode::Full || !db_path.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    let conn = Connection::open(db_path).map_err(DbError::Open)?;
    let now_ms = now_ms();
    let since_ms = now_ms.saturating_sub(hours as u64 * 3600 * 1000) as i64;
    let n = n as i64;

    let blocked = top_query(&conn, since_ms, n, "block")?;
    let allowed = top_query(&conn, since_ms, n, "forward")?;
    Ok((blocked, allowed))
}

fn top_query(
    conn: &Connection,
    since_ms: i64,
    n: i64,
    verdict: &str,
) -> Result<Vec<TopEntry>, DbError> {
    let mut stmt = conn
        .prepare(
            "SELECT qname, COUNT(*) AS cnt
             FROM queries
             WHERE ts_ms >= ?1 AND verdict = ?2 AND qname != '<redacted>'
             GROUP BY qname
             ORDER BY cnt DESC
             LIMIT ?3",
        )
        .map_err(DbError::Query)?;

    let rows = stmt
        .query_map(rusqlite::params![since_ms, verdict, n], |row| {
            Ok(TopEntry {
                qname: row.get(0)?,
                count: row.get::<_, i64>(1)? as u64,
            })
        })
        .map_err(DbError::Query)?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(DbError::Query)?);
    }
    Ok(result)
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors from the rollup module.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Failed to open the SQLite connection.
    #[error("sqlite open: {0}")]
    Open(rusqlite::Error),
    /// Schema creation or PRAGMA failed.
    #[error("sqlite schema: {0}")]
    Schema(rusqlite::Error),
    /// Insert / transaction failed.
    #[error("sqlite insert: {0}")]
    Insert(rusqlite::Error),
    /// Query failed.
    #[error("sqlite query: {0}")]
    Query(rusqlite::Error),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use tempfile::TempDir;

    fn make_conn(dir: &Path) -> Connection {
        let path = dir.join("querylog.sqlite");
        open_db(&path).unwrap()
    }

    fn insert_row(conn: &Connection, ts_ms: i64, qname: &str, verdict: &str) {
        conn.execute(
            "INSERT INTO queries(ts_ms, qname, qtype, verdict, reason, detail, client)
             VALUES(?1, ?2, 1, ?3, 'no_match', NULL, NULL)",
            rusqlite::params![ts_ms, qname, verdict],
        )
        .unwrap();
    }

    fn insert_row_with_client(
        conn: &Connection,
        ts_ms: i64,
        qname: &str,
        verdict: &str,
        client: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO queries(ts_ms, qname, qtype, verdict, reason, detail, client)
             VALUES(?1, ?2, 1, ?3, 'no_match', NULL, ?4)",
            rusqlite::params![ts_ms, qname, verdict, client],
        )
        .unwrap();
    }

    // ── Schema created correctly ──────────────────────────────────────────────

    #[test]
    fn schema_created_on_open() {
        let tmp = TempDir::new().unwrap();
        let conn = make_conn(tmp.path());
        // meta must have schema_version = 2 (current).
        let v: i64 = conn
            .query_row("SELECT schema_version FROM meta LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn schema_idempotent_second_open() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("querylog.sqlite");
        let _ = open_db(&path).unwrap();
        // Second open must succeed without duplicate schema_version row.
        let conn2 = open_db(&path).unwrap();
        let count: i64 = conn2
            .query_row("SELECT COUNT(*) FROM meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "meta must have exactly one row");
    }

    // ── Batch flush ───────────────────────────────────────────────────────────

    #[test]
    fn flush_inserts_rows() {
        let tmp = TempDir::new().unwrap();
        let conn = make_conn(tmp.path());
        let batch = vec![
            RollupRecord {
                ts_ms: 1000,
                qname: "a.test".into(),
                qtype: 1,
                verdict: "block".into(),
                reason: "list_blocked".into(),
                client: None,
            },
            RollupRecord {
                ts_ms: 2000,
                qname: "b.test".into(),
                qtype: 28,
                verdict: "forward".into(),
                reason: "no_match".into(),
                client: None,
            },
        ];
        flush_batch(&conn, &batch);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn flush_empty_batch_is_noop() {
        let tmp = TempDir::new().unwrap();
        let conn = make_conn(tmp.path());
        flush_batch(&conn, &[]);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    // ── Retention ─────────────────────────────────────────────────────────────

    #[test]
    fn retention_deletes_old_rows() {
        let tmp = TempDir::new().unwrap();
        let conn = make_conn(tmp.path());
        // Old row: 10 days ago.
        let old_ms = now_ms() as i64 - 10 * 24 * 3600 * 1000;
        // Recent row: now.
        let recent_ms = now_ms() as i64;
        insert_row(&conn, old_ms, "old.example", "forward");
        insert_row(&conn, recent_ms, "new.example", "forward");

        run_retention(&conn, 7);

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "old row must be deleted; recent row kept");
        let qname: String = conn
            .query_row("SELECT qname FROM queries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(qname, "new.example");
    }

    #[test]
    fn retention_keeps_rows_within_window() {
        let tmp = TempDir::new().unwrap();
        let conn = make_conn(tmp.path());
        // All rows within 7 days.
        for i in 0..5i64 {
            let ts = now_ms() as i64 - i * 24 * 3600 * 1000;
            insert_row(&conn, ts, "keep.example", "forward");
        }
        run_retention(&conn, 7);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 5, "all within-window rows must be kept");
    }

    // ── Corruption recovery ───────────────────────────────────────────────────

    #[test]
    fn corrupt_file_renamed_and_db_recreated() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("querylog.sqlite");
        // Write garbage content to simulate a corrupt DB.
        std::fs::write(&path, b"not a sqlite database at all!!").unwrap();
        // open_db must recover: rename aside + recreate.
        let conn = open_db(&path).unwrap();
        // New DB must be valid (schema v2).
        let v: i64 = conn
            .query_row("SELECT schema_version FROM meta LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        // A corrupt file must have been renamed aside.
        let corrupt_files: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .collect();
        assert!(
            !corrupt_files.is_empty(),
            "corrupt file must be renamed aside"
        );
    }

    // ── Mode interplay ────────────────────────────────────────────────────────

    #[test]
    fn anonymous_mode_rows_have_redacted_qname() {
        let tmp = TempDir::new().unwrap();
        let conn = make_conn(tmp.path());
        // In anonymous mode the caller already sends "<redacted>".
        flush_batch(
            &conn,
            &[RollupRecord {
                ts_ms: 1000,
                qname: "<redacted>".into(),
                qtype: 1,
                verdict: "block".into(),
                reason: "list_blocked".into(),
                client: None,
            }],
        );
        let qname: String = conn
            .query_row("SELECT qname FROM queries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(qname, "<redacted>");
    }

    // ── history and top queries ───────────────────────────────────────────────

    #[test]
    fn query_history_returns_buckets() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("querylog.sqlite");
        let conn = open_db(&path).unwrap();
        let now = now_ms() as i64;
        // Two rows in the same bucket (1-hour buckets).
        insert_row(&conn, now - 60_000, "a.test", "block");
        insert_row(&conn, now - 30_000, "b.test", "forward");
        drop(conn);

        let buckets = query_history(&path, 1, 3600).unwrap();
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].total, 2);
        assert_eq!(buckets[0].blocked, 1);
    }

    #[test]
    fn query_history_missing_db_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nonexistent.sqlite");
        let buckets = query_history(&path, 24, 3600).unwrap();
        assert!(buckets.is_empty());
    }

    #[test]
    fn query_top_returns_top_blocked() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("querylog.sqlite");
        let conn = open_db(&path).unwrap();
        let now = now_ms() as i64;
        // Insert 3 rows for "evil.com" and 1 for "other.com".
        for _ in 0..3 {
            insert_row(&conn, now - 1000, "evil.com", "block");
        }
        insert_row(&conn, now - 1000, "other.com", "block");
        drop(conn);

        let (blocked, _allowed) = query_top(&path, 10, 1, QueryLogMode::Full).unwrap();
        assert_eq!(blocked[0].qname, "evil.com");
        assert_eq!(blocked[0].count, 3);
    }

    #[test]
    fn query_top_anonymous_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("querylog.sqlite");
        let _conn = open_db(&path).unwrap();
        let (blocked, allowed) = query_top(&path, 10, 24, QueryLogMode::Anonymous).unwrap();
        assert!(blocked.is_empty());
        assert!(allowed.is_empty());
    }

    // ── cutoff_ms_for_days math ───────────────────────────────────────────────

    #[test]
    fn cutoff_ms_is_approximately_correct() {
        let now = now_ms();
        let cutoff = cutoff_ms_for_days(7) as u64;
        let expected_diff = 7u64 * 24 * 3600 * 1000;
        // Allow 5-second slack for test execution time.
        let slack = 5000u64;
        assert!(
            now.saturating_sub(cutoff).abs_diff(expected_diff) < slack,
            "cutoff_ms_for_days(7) must be approximately now - 7 days"
        );
    }

    // ── WP13: schema v1→v2 migration ─────────────────────────────────────────

    /// Create a v1-style database (no `client` column, schema_version=1).
    fn create_v1_db(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        conn.execute_batch(
            "CREATE TABLE queries (
                 ts_ms   INTEGER NOT NULL,
                 qname   TEXT    NOT NULL,
                 qtype   INTEGER NOT NULL,
                 verdict TEXT    NOT NULL,
                 reason  TEXT    NOT NULL,
                 detail  TEXT
             );
             CREATE INDEX queries_ts ON queries(ts_ms);
             CREATE TABLE meta (schema_version INTEGER NOT NULL);
             INSERT INTO meta(schema_version) VALUES(1);",
        )
        .unwrap();
        conn
    }

    #[test]
    fn migration_v1_to_v2_preserves_rows() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("querylog.sqlite");

        // Build a v1 database with some rows.
        {
            let conn = create_v1_db(&path);
            let now = now_ms() as i64;
            conn.execute(
                "INSERT INTO queries(ts_ms, qname, qtype, verdict, reason, detail)
                 VALUES(?1, 'old.example', 1, 'block', 'list_blocked', NULL)",
                [now - 1000],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO queries(ts_ms, qname, qtype, verdict, reason, detail)
                 VALUES(?1, 'another.example', 1, 'forward', 'no_match', NULL)",
                [now - 500],
            )
            .unwrap();
        } // conn dropped / file closed

        // Re-open via open_db — must migrate to v2.
        let conn = open_db(&path).unwrap();

        // Version must be 2.
        let v: i64 = conn
            .query_row("SELECT schema_version FROM meta LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 2, "schema must be v2 after migration");

        // Original rows must be preserved.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2, "existing rows must be preserved after migration");

        // Existing rows must have client = NULL.
        let null_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM queries WHERE client IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(null_count, 2, "migrated rows must have client = NULL");
    }

    #[test]
    fn migration_idempotent_already_v2() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("querylog.sqlite");
        // First open creates v2.
        let _ = open_db(&path).unwrap();
        // Second open must not fail or double-migrate.
        let conn = open_db(&path).unwrap();
        let v: i64 = conn
            .query_row("SELECT schema_version FROM meta LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 2);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "meta must have exactly one row after second open");
    }

    // ── WP13: query_clients ───────────────────────────────────────────────────

    #[test]
    fn query_clients_returns_per_client_totals() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("querylog.sqlite");
        let conn = open_db(&path).unwrap();
        let now = now_ms() as i64;

        // Client A: 3 queries, 2 blocked.
        insert_row_with_client(&conn, now - 1000, "a.test", "block", Some("192.168.1.10"));
        insert_row_with_client(&conn, now - 900, "b.test", "block", Some("192.168.1.10"));
        insert_row_with_client(&conn, now - 800, "c.test", "forward", Some("192.168.1.10"));

        // Client B: 1 query, 0 blocked.
        insert_row_with_client(&conn, now - 700, "d.test", "forward", Some("192.168.1.20"));

        // Loopback (no client).
        insert_row_with_client(&conn, now - 600, "e.test", "forward", None);

        drop(conn);

        let clients = query_clients(&path, 1).unwrap();
        // Only 2 distinct clients (loopback not counted).
        assert_eq!(
            clients.len(),
            2,
            "must return 2 client entries; got {clients:?}"
        );

        // Find client A.
        let a = clients.iter().find(|c| c.client == "192.168.1.10").unwrap();
        assert_eq!(a.total, 3);
        assert_eq!(a.blocked, 2);

        // Find client B.
        let b = clients.iter().find(|c| c.client == "192.168.1.20").unwrap();
        assert_eq!(b.total, 1);
        assert_eq!(b.blocked, 0);
    }

    #[test]
    fn query_clients_missing_db_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nonexistent.sqlite");
        let clients = query_clients(&path, 24).unwrap();
        assert!(clients.is_empty());
    }

    #[test]
    fn flush_batch_stores_client_ip() {
        let tmp = TempDir::new().unwrap();
        let conn = make_conn(tmp.path());
        let lan_ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        flush_batch(
            &conn,
            &[RollupRecord {
                ts_ms: 1000,
                qname: "test.example".into(),
                qtype: 1,
                verdict: "block".into(),
                reason: "list_blocked".into(),
                client: Some(lan_ip),
            }],
        );
        let client_str: Option<String> = conn
            .query_row("SELECT client FROM queries LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            client_str,
            Some("10.0.0.5".to_string()),
            "client IP must be stored as text"
        );
    }

    #[test]
    fn flush_batch_stores_null_client_for_loopback() {
        let tmp = TempDir::new().unwrap();
        let conn = make_conn(tmp.path());
        flush_batch(
            &conn,
            &[RollupRecord {
                ts_ms: 1000,
                qname: "test.example".into(),
                qtype: 1,
                verdict: "block".into(),
                reason: "list_blocked".into(),
                client: None,
            }],
        );
        let client_str: Option<String> = conn
            .query_row("SELECT client FROM queries LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(
            client_str.is_none(),
            "loopback query must store NULL client"
        );
    }

    // ── RollupHandle off-mode ─────────────────────────────────────────────────

    #[test]
    fn off_mode_handle_never_creates_db() {
        let tmp = TempDir::new().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = start_rollup(tmp.path().to_path_buf(), QueryLogMode::Off, 7, cancel);
        // try_send on an off-mode handle must be a no-op.
        handle.try_send(RollupRecord {
            ts_ms: 1000,
            qname: "test.example".into(),
            qtype: 1,
            verdict: "block".into(),
            reason: "list_blocked".into(),
            client: None,
        });
        // DB must NOT be created.
        let db_path = tmp.path().join("querylog.sqlite");
        assert!(!db_path.exists(), "off mode must never create the DB file");
    }
}
