//! Live catalog URL-rot canary — gated by `#[ignore]` (real network).
//!
//! `specs/wp4-privacy.md` §5 (Live): fetch the real catalog endpoints and assert
//! they respond with non-trivial bodies. Catches URL rot (e.g. Hagezi renaming
//! `multi.txt`); deliberately does NOT assert entry counts (lists change daily).
//!
//! Run manually: `cargo test -p hush-daemon --test live_lists -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hush_core::catalog::{Catalog, VALID_CATEGORY_KEYS};

#[tokio::test]
#[ignore]
async fn live_privacy_lists_fetch() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    // Every URL the shipped catalog can ever instruct the daemon to fetch.
    let mut urls: Vec<String> = Vec::new();
    for preset in ["minimal", "balanced", "strict"] {
        for src in Catalog::resolve(preset, &[]).unwrap() {
            urls.push(src.url.clone());
        }
    }
    for cat in VALID_CATEGORY_KEYS {
        for src in Catalog::resolve("custom", &[cat]).unwrap() {
            urls.push(src.url.clone());
        }
    }
    urls.sort();
    urls.dedup();
    assert!(!urls.is_empty(), "catalog produced no URLs");

    let mut failures = Vec::new();
    for url in &urls {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let len = resp.bytes().await.map(|b| b.len()).unwrap_or(0);
                // "Non-trivial" = bigger than an error page / empty stub.
                if len < 1024 {
                    failures.push(format!("{url}: suspiciously small body ({len} B)"));
                } else {
                    eprintln!("OK  {url} ({len} B)");
                }
            }
            Ok(resp) => failures.push(format!("{url}: HTTP {}", resp.status())),
            Err(e) => failures.push(format!("{url}: {e}")),
        }
    }

    assert!(
        failures.is_empty(),
        "catalog URL rot detected:\n{}",
        failures.join("\n")
    );
}
