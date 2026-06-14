# Engineering Standards — binding for all work packages

Every implementation PR/agent-run must satisfy this document **in addition to** its
work-package spec. Deviations require a written note in the run summary; silent
deviations are rejected at verification.

## 1. Quality gate (run before declaring done)

```bash
cd /path/to/hushwarren
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check licenses 2>/dev/null || true   # report result; failures are findings, not auto-fix
```

All four run from the workspace root. Tests must pass deterministically — run the
test suite twice; flaky = failing.

## 2. Error & panic policy (a DNS daemon that panics takes the user offline)

- Workspace lints already `deny` `clippy::unwrap_used` / `clippy::expect_used`.
  Production code: return `Result`, use `thiserror` enums per crate. No
  `panic!`, `todo!`, `unimplemented!`, `unreachable!` in non-test code (the last
  only with a `// PANIC-OK:` comment proving unreachability).
- Test code MAY unwrap: put `#![allow(clippy::unwrap_used, clippy::expect_used)]`
  at the top of test modules / `tests/*.rs` files. Do not weaken the workspace lint.
- The DNS request path must be **infallible at the boundary**: any internal error
  maps to SERVFAIL (or pass-through where specified), never a crash, never a hang.
  Malformed input is a counted, debug-logged event — not an error return.
- No `.clone()`-to-silence-borrowck on the hot path; no locks held across `.await`.

## 3. Logging & observability

- `tracing` only — no `println!`/`eprintln!` outside `main()` startup failures and
  CLI user output.
- Levels: `error` = user-impacting + actionable; `warn` = degraded (upstream down,
  list fetch failed); `info` = lifecycle (started, list swapped, N rules); `debug`
  = per-query. Per-query logging must be compiled-in but cheap (no formatting
  unless enabled).
- Never log full query streams at info — privacy is a product principle (P3).

## 4. Dependencies

- Permissive licenses only; the root `deny.toml` allowlist is authoritative.
  Adding a dep that fails `cargo deny check licenses` requires stopping and
  reporting, not editing deny.toml.
- Prefer: tokio, hickory-*, rustls (+ rustls-native-certs / platform verifier —
  **avoid webpki-roots**, it is MPL-2.0), axum, reqwest (default-features off,
  `rustls-tls-native-roots`), serde, toml, thiserror, fst, arc-swap, clap, tracing.
- Pin via `Cargo.lock` (committed). Use current stable versions from crates.io —
  verify API against docs.rs of the version you actually resolved; do not code
  against from-memory APIs without checking.
- Workspace-level `[workspace.dependencies]` for anything used by ≥2 crates.

## 5. Test pyramid (definitions used by every WP spec)

| Layer | Lives in | Rules |
|---|---|---|
| **Unit** | `#[cfg(test)] mod tests` next to the code | No I/O, no sleeps, no network, no filesystem (except `tempfile`). Table-driven where natural. |
| **Integration** | `crates/<x>/tests/*.rs` | In-process components on ephemeral ports (`127.0.0.1:0`), mock upstreams also in-process. **No external network. No fixed ports. No `sleep`-based synchronization** — use readiness signals/retry-with-deadline helpers. |
| **E2E** | `crates/cli/tests/e2e_*.rs` | Spawn the real compiled binaries (`assert_cmd`/`CARGO_BIN_EXE_*`), temp state dirs, ephemeral ports. Still no external network. |
| **Live** | `#[ignore]`-gated | The only layer allowed to touch the real internet (real DoH endpoints). Run manually: `cargo test -- --ignored`. |

Every public function with branching logic gets unit tests including the failure
branches. Every WP spec enumerates mandatory cases — those are a floor, not a
ceiling.

## 6. Code shape

- rustdoc (`///`) on every public item; module-level `//!` explaining the module's
  role and linking the design doc section it implements.
- Comments state constraints/invariants, not narration of the code.
- OS-specific code ONLY in `hush-daemon/src/platform/` behind `cfg` — everything
  else compiles on all three OSes (CI will enforce later; until then assume it).
- Public API surface minimal: `pub(crate)` by default, `pub` only what the
  consuming crate needs.
- Config structs: `#[serde(deny_unknown_fields, default)]`, every field documented,
  `Default` impls produce a fully-working config.

## 7. Run summary (what the implementing agent must return)

1. What was implemented vs the spec, with any deviations + reasons.
2. Gate output: the final fmt/clippy/test/deny results (paste the tail).
3. Test inventory: count per pyramid layer + the spec's mandatory-case checklist
   with each item marked done/deviated.
4. Anything discovered that the spec got wrong (API drift in deps, design gaps) —
   flag loudly, do not silently work around.
