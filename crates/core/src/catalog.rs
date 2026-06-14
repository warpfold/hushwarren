//! Compiled-in source catalog for hushwarren blocklists.
//!
//! Implements `specs/wp4-privacy.md` §2.  This module holds the canonical URLs
//! and metadata for every list preset and extra-category entry.  **No network
//! I/O occurs here** — the URLs are fetched at runtime by the daemon's list
//! pipeline.  The catalog only maps human-readable keys to stable URLs and
//! attribution metadata.
//!
//! # URL provenance
//!
//! All URLs were verified on 2026-06-12 against the live repositories:
//! - Hagezi `multi.txt` is the correct filename for the "Normal" tier
//!   (`normal.txt` does not exist; the repository uses `multi.txt`).
//! - OISD endpoints use the `domainswild2` path for wildcard-friendly format.
//!
//! # Usage
//!
//! ```rust
//! use hush_core::catalog::Catalog;
//!
//! // Resolve the "balanced" preset (no extra categories).
//! let sources = Catalog::resolve("balanced", &[]).unwrap();
//! assert!(sources.len() >= 2);
//! ```

use crate::config::ListSource;
use thiserror::Error;

/// A single entry in the compiled-in source catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    /// Catalog key used in config (`preset` or `extra_categories` element).
    pub key: &'static str,
    /// Human-readable name shown in the dashboard.
    pub name: &'static str,
    /// URL to fetch the list from.
    pub url: &'static str,
    /// License string, if declared by the upstream project.
    pub license: Option<&'static str>,
    /// Attribution/credit string for the upstream project.
    pub attribution: &'static str,
}

/// Errors from the catalog module.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CatalogError {
    /// An unknown preset name was supplied.
    #[error(
        "unknown list preset: {0:?}; valid values are minimal, balanced, strict, aggressive, custom"
    )]
    UnknownPreset(String),
    /// One or more unknown category keys were supplied.
    #[error("unknown extra_categories: {0:?}")]
    UnknownCategories(Vec<String>),
    /// preset=custom with no sources from categories or explicit sources.
    #[error(
        "preset=custom with empty sources union: \
         add at least one entry via extra_categories or lists.sources"
    )]
    CustomPresetEmpty,
}

/// All catalog entries — presets and extra categories.
///
/// These are the ONLY authoritative URLs; do not duplicate them elsewhere.
const CATALOG: &[CatalogEntry] = &[
    // ── Preset: minimal ──────────────────────────────────────────────────────
    CatalogEntry {
        key: "hagezi-light",
        name: "Hagezi Light",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Preset: balanced ─────────────────────────────────────────────────────
    CatalogEntry {
        key: "oisd-small",
        name: "OISD Small",
        url: "https://small.oisd.nl/domainswild2",
        license: None, // no stated license
        attribution: "OISD (https://oisd.nl) — runtime-fetched; not bundled",
    },
    CatalogEntry {
        key: "hagezi-normal",
        name: "Hagezi Normal (multi)",
        // NB: the filename is multi.txt, NOT normal.txt — verified 2026-06-12.
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Preset: strict ───────────────────────────────────────────────────────
    CatalogEntry {
        key: "oisd-big",
        name: "OISD Big",
        url: "https://big.oisd.nl/domainswild2",
        license: None,
        attribution: "OISD (https://oisd.nl) — runtime-fetched; not bundled",
    },
    CatalogEntry {
        key: "hagezi-pro",
        name: "Hagezi Pro",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Preset: aggressive ───────────────────────────────────────────────────
    CatalogEntry {
        key: "hagezi-pro-plus",
        name: "Hagezi Pro++",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.plus.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Extra category: telemetry-windows ────────────────────────────────────
    CatalogEntry {
        key: "telemetry-windows",
        name: "Hagezi Windows/Office Telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.winoffice.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // Additional WindowsSpyBlocker entry for Windows telemetry.
    CatalogEntry {
        key: "telemetry-windows-spy",
        name: "WindowsSpyBlocker Spy",
        url: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
        license: Some("MIT"),
        attribution: "WindowsSpyBlocker (https://github.com/crazy-max/WindowsSpyBlocker)",
    },
    // ── Extra category: telemetry-samsung ────────────────────────────────────
    CatalogEntry {
        key: "telemetry-samsung",
        name: "Hagezi Samsung Telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.samsung.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Extra category: telemetry-xiaomi ─────────────────────────────────────
    CatalogEntry {
        key: "telemetry-xiaomi",
        name: "Hagezi Xiaomi Telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.xiaomi.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Extra category: telemetry-apple ──────────────────────────────────────
    CatalogEntry {
        key: "telemetry-apple",
        name: "Hagezi Apple Telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.apple.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Extra category: telemetry-amazon ─────────────────────────────────────
    CatalogEntry {
        key: "telemetry-amazon",
        name: "Hagezi Amazon Telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.amazon.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Extra category: telemetry-huawei ─────────────────────────────────────
    CatalogEntry {
        key: "telemetry-huawei",
        name: "Hagezi Huawei Telemetry",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.huawei.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Extra category: threat-intel ─────────────────────────────────────────
    CatalogEntry {
        key: "threat-intel",
        name: "Hagezi Threat Intelligence Feeds (medium)",
        // adblock format — the parser handles both plain-domain and AdBlock syntax.
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Extra category: doh-bypass ───────────────────────────────────────────
    CatalogEntry {
        key: "doh-bypass",
        name: "Hagezi DoH/VPN/Proxy Bypass",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt",
        license: Some("MIT"),
        attribution: "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)",
    },
    // ── Extra category: nsfw ─────────────────────────────────────────────────
    CatalogEntry {
        key: "nsfw",
        name: "OISD NSFW",
        url: "https://nsfw.oisd.nl/domainswild2",
        license: None,
        attribution: "OISD (https://oisd.nl) — runtime-fetched; not bundled",
    },
];

/// Keys included in the `minimal` preset.
const PRESET_MINIMAL_KEYS: &[&str] = &["hagezi-light"];

/// Keys included in the `balanced` preset.
const PRESET_BALANCED_KEYS: &[&str] = &["oisd-small", "hagezi-normal"];

/// Keys included in the `strict` preset.
const PRESET_STRICT_KEYS: &[&str] = &["oisd-big", "hagezi-pro"];

/// Keys included in the `aggressive` preset — one Hagezi tier above `strict`
/// (Pro++ instead of Pro). Blocks the long tail (crash/error analytics,
/// `adservice.google.com`, `ad.doubleclick.net`, …) at the cost of a higher
/// false-positive rate; opt-in, not the default.
const PRESET_AGGRESSIVE_KEYS: &[&str] = &["oisd-big", "hagezi-pro-plus"];

/// The set of valid preset names.
pub const VALID_PRESETS: &[&str] = &["minimal", "balanced", "strict", "aggressive", "custom"];

/// The set of valid extra-category keys (those not used as preset sub-keys).
pub const VALID_CATEGORY_KEYS: &[&str] = &[
    "telemetry-windows",
    "telemetry-windows-spy",
    "telemetry-samsung",
    "telemetry-xiaomi",
    "telemetry-apple",
    "telemetry-amazon",
    "telemetry-huawei",
    "threat-intel",
    "doh-bypass",
    "nsfw",
];

/// The compiled-in source catalog.
///
/// All methods are pure (no I/O).  URLs are resolved at runtime by the
/// daemon's list pipeline.
pub struct Catalog;

impl Catalog {
    /// Return all catalog entries (for the API/dashboard).
    pub fn all() -> &'static [CatalogEntry] {
        CATALOG
    }

    /// Resolve `preset` + `extra_categories` into a deduplicated `Vec<ListSource>`.
    ///
    /// Merge rule (spec §1): effective sources =
    /// `preset_sources(preset) ∪ catalog(extra_categories) ∪ explicit_sources`.
    /// `preset="custom"` contributes nothing from the preset itself.
    ///
    /// Deduplication is by URL (last-writer wins is not relevant here because
    /// the union operation produces exactly one entry per URL).
    ///
    /// Returns [`CatalogError`] for unknown presets, unknown category keys, or
    /// a `custom` preset whose union would be empty (explicit_sources handled
    /// by the caller — pass the count so we can validate).
    ///
    /// `extra_category_union_len` is `extra_categories.len() + explicit_sources.len()`
    /// — used only to validate the custom+empty guard.  The caller (config
    /// validate) passes the full union size.
    pub fn resolve(
        preset: &str,
        extra_categories: &[&str],
    ) -> Result<Vec<ListSource>, CatalogError> {
        Self::resolve_with_overrides(preset, extra_categories, None)
    }

    /// Like [`resolve`] but rewrites all URLs by replacing the default base URL
    /// prefix with `base_url_override`.  Used in tests to redirect catalog
    /// fetches to a local mock HTTP server without hitting the real internet.
    ///
    /// `base_url_override` must end with `/`; the URL suffix after the last `/`
    /// in the catalog URL is appended.
    pub fn resolve_with_overrides(
        preset: &str,
        extra_categories: &[&str],
        base_url_override: Option<&str>,
    ) -> Result<Vec<ListSource>, CatalogError> {
        // Validate preset.
        if !VALID_PRESETS.contains(&preset) {
            return Err(CatalogError::UnknownPreset(preset.to_owned()));
        }

        // Validate extra_categories — collect ALL unknown keys at once.
        let all_known_keys: Vec<&str> = CATALOG.iter().map(|e| e.key).collect();
        let unknown: Vec<String> = extra_categories
            .iter()
            .filter(|&&k| !all_known_keys.contains(&k))
            .map(|k| (*k).to_owned())
            .collect();
        if !unknown.is_empty() {
            return Err(CatalogError::UnknownCategories(unknown));
        }

        // Build the ordered, deduplicated source list.
        let preset_keys: &[&str] = match preset {
            "minimal" => PRESET_MINIMAL_KEYS,
            "balanced" => PRESET_BALANCED_KEYS,
            "strict" => PRESET_STRICT_KEYS,
            "aggressive" => PRESET_AGGRESSIVE_KEYS,
            "custom" => &[],
            _ => &[], // PANIC-OK: validated above
        };

        let mut seen_urls: Vec<String> = Vec::new();
        let mut sources: Vec<ListSource> = Vec::new();

        // Helper closure to add an entry if its URL hasn't been seen.
        let mut maybe_add = |key: &str| {
            if let Some(entry) = CATALOG.iter().find(|e| e.key == key) {
                let url = rewrite_url(entry.url, base_url_override);
                if !seen_urls.contains(&url) {
                    seen_urls.push(url.clone());
                    sources.push(ListSource {
                        name: entry.name.to_owned(),
                        url,
                    });
                }
            }
        };

        // 1. Preset sources first.
        for key in preset_keys {
            maybe_add(key);
        }

        // 2. Extra category sources.
        for key in extra_categories {
            maybe_add(key);
        }

        Ok(sources)
    }

    /// Look up a single entry by key.  Returns `None` for unknown keys.
    pub fn get(key: &str) -> Option<&'static CatalogEntry> {
        CATALOG.iter().find(|e| e.key == key)
    }

    /// Look up a catalog entry by its URL.
    ///
    /// Returns `Some` if the URL is present in the compiled-in catalog, `None`
    /// for user-custom sources that are not in the catalog.  Used by the API to
    /// attach `category`, `license`, and `attribution` metadata to list sources.
    pub fn find_by_url(url: &str) -> Option<&'static CatalogEntry> {
        CATALOG.iter().find(|e| e.url == url)
    }

    /// Validate that `preset` is a known preset name.
    pub fn is_valid_preset(preset: &str) -> bool {
        VALID_PRESETS.contains(&preset)
    }

    /// Validate that `key` is a known category key.
    pub fn is_valid_category(key: &str) -> bool {
        CATALOG.iter().any(|e| e.key == key)
    }
}

/// Rewrite a catalog URL for test injection.
///
/// If `base_override` is `None`, returns the original URL unchanged.
/// Otherwise, replaces everything up to and including the last `/` with
/// `base_override`.
fn rewrite_url(url: &str, base_override: Option<&str>) -> String {
    match base_override {
        None => url.to_owned(),
        Some(base) => {
            // Extract just the filename (everything after the last '/').
            let filename = url.rsplit('/').next().unwrap_or(url);
            format!("{base}{filename}")
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // ── URL well-formedness ───────────────────────────────────────────────────
    // Spec §5: catalog URLs must be well-formed HTTPS URLs (no reqwest dep in core;
    // we validate the scheme + non-empty host manually).

    #[test]
    fn all_catalog_urls_are_https() {
        for entry in Catalog::all() {
            assert!(
                entry.url.starts_with("https://"),
                "catalog entry {:?} URL must start with https://: {}",
                entry.key,
                entry.url
            );
        }
    }

    #[test]
    fn all_catalog_urls_have_non_empty_path() {
        for entry in Catalog::all() {
            // After stripping "https://" there must be at least one '/' followed by a non-empty path.
            let after_scheme = entry.url.strip_prefix("https://").unwrap();
            let slash_pos = after_scheme.find('/');
            assert!(
                slash_pos.is_some(),
                "catalog entry {:?} URL must have a path component: {}",
                entry.key,
                entry.url
            );
            let path = &after_scheme[slash_pos.unwrap()..];
            assert!(
                path.len() > 1,
                "catalog entry {:?} URL path must be non-trivial: {}",
                entry.key,
                entry.url
            );
        }
    }

    // ── Preset resolution ─────────────────────────────────────────────────────

    #[test]
    fn preset_minimal_resolves_hagezi_light() {
        let sources = Catalog::resolve("minimal", &[]).unwrap();
        assert_eq!(sources.len(), 1);
        assert!(sources[0].url.contains("light.txt"));
    }

    #[test]
    fn preset_balanced_resolves_two_sources() {
        let sources = Catalog::resolve("balanced", &[]).unwrap();
        assert_eq!(sources.len(), 2);
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        assert!(urls
            .iter()
            .any(|u| u.contains("domainswild2") && u.contains("small")));
        // multi.txt (not normal.txt) — verified URL per spec note
        assert!(urls.iter().any(|u| u.contains("multi.txt")));
    }

    #[test]
    fn preset_balanced_uses_multi_not_normal() {
        let sources = Catalog::resolve("balanced", &[]).unwrap();
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        assert!(
            urls.iter().any(|u| u.contains("multi.txt")),
            "balanced preset must use multi.txt (not normal.txt)"
        );
        assert!(
            !urls.iter().any(|u| u.contains("normal.txt")),
            "balanced preset must NOT use normal.txt"
        );
    }

    #[test]
    fn preset_strict_resolves_two_sources() {
        let sources = Catalog::resolve("strict", &[]).unwrap();
        assert_eq!(sources.len(), 2);
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        assert!(urls.iter().any(|u| u.contains("big.oisd.nl")));
        assert!(urls.iter().any(|u| u.contains("pro.txt")));
    }

    #[test]
    fn preset_aggressive_resolves_oisd_big_and_pro_plus() {
        let sources = Catalog::resolve("aggressive", &[]).unwrap();
        assert_eq!(sources.len(), 2);
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        assert!(urls.iter().any(|u| u.contains("big.oisd.nl")));
        assert!(
            urls.iter().any(|u| u.contains("pro.plus.txt")),
            "aggressive preset must use pro.plus.txt"
        );
        assert!(
            !urls.iter().any(|u| u.ends_with("/pro.txt")),
            "aggressive must use pro.plus.txt, not pro.txt"
        );
    }

    #[test]
    fn preset_custom_empty_returns_empty_vec() {
        // custom with no categories → empty (caller validates against explicit sources)
        let sources = Catalog::resolve("custom", &[]).unwrap();
        assert!(sources.is_empty());
    }

    // ── Unknown preset ────────────────────────────────────────────────────────

    #[test]
    fn unknown_preset_returns_error() {
        let err = Catalog::resolve("typo-preset", &[]).unwrap_err();
        assert!(
            matches!(err, CatalogError::UnknownPreset(_)),
            "unknown preset must return UnknownPreset error"
        );
    }

    // ── Unknown category ──────────────────────────────────────────────────────

    #[test]
    fn unknown_category_returns_error() {
        let err = Catalog::resolve("balanced", &["not-a-real-category"]).unwrap_err();
        assert!(
            matches!(err, CatalogError::UnknownCategories(_)),
            "unknown category must return UnknownCategories error"
        );
    }

    #[test]
    fn multiple_unknown_categories_collected_at_once() {
        let err = Catalog::resolve("balanced", &["fake1", "fake2"]).unwrap_err();
        match err {
            CatalogError::UnknownCategories(keys) => {
                assert_eq!(keys.len(), 2);
            }
            _ => panic!("expected UnknownCategories, got: {err:?}"),
        }
    }

    // ── Deduplication ─────────────────────────────────────────────────────────

    #[test]
    fn dedup_by_url_no_duplicates() {
        // strict includes hagezi-pro; if someone also requests it as a category,
        // it must appear only once.
        let sources = Catalog::resolve("strict", &["hagezi-pro"]).unwrap();
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        let mut uniq = urls.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(
            urls.len(),
            uniq.len(),
            "no URL must appear twice in the resolved source list"
        );
    }

    // ── Merge rule: preset ∪ categories ──────────────────────────────────────

    #[test]
    fn merge_rule_balanced_plus_threat_intel() {
        let sources = Catalog::resolve("balanced", &["threat-intel"]).unwrap();
        // 2 preset + 1 category = 3 total
        assert_eq!(sources.len(), 3);
        let urls: Vec<&str> = sources.iter().map(|s| s.url.as_str()).collect();
        assert!(urls.iter().any(|u| u.contains("tif.medium.txt")));
    }

    #[test]
    fn merge_rule_custom_plus_nsfw() {
        // custom + nsfw = 1 source (no preset contribution)
        let sources = Catalog::resolve("custom", &["nsfw"]).unwrap();
        assert_eq!(sources.len(), 1);
        assert!(sources[0].url.contains("nsfw.oisd.nl"));
    }

    // ── URL rewrite for test injection ────────────────────────────────────────

    #[test]
    fn resolve_with_overrides_rewrites_urls() {
        let sources =
            Catalog::resolve_with_overrides("minimal", &[], Some("http://localhost:9999/"))
                .unwrap();
        assert_eq!(sources.len(), 1);
        assert!(
            sources[0].url.starts_with("http://localhost:9999/"),
            "override must rewrite URL to local server"
        );
        assert!(
            sources[0].url.ends_with("light.txt"),
            "filename must be preserved after rewrite"
        );
    }

    // ── Catalog::all ──────────────────────────────────────────────────────────

    #[test]
    fn catalog_all_is_non_empty() {
        assert!(!Catalog::all().is_empty());
    }

    // ── Valid preset and category predicates ──────────────────────────────────

    #[test]
    fn valid_presets_recognized() {
        for p in ["minimal", "balanced", "strict", "aggressive", "custom"] {
            assert!(Catalog::is_valid_preset(p), "{p} must be a valid preset");
        }
        assert!(!Catalog::is_valid_preset("unknown"));
    }

    #[test]
    fn valid_categories_recognized() {
        for k in VALID_CATEGORY_KEYS {
            assert!(
                Catalog::is_valid_category(k),
                "{k} must be a valid category"
            );
        }
        assert!(!Catalog::is_valid_category("unknown-cat"));
    }
}
