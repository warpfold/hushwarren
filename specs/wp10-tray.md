# WP10 — Tray app (the ambient UI)

P2 deliverable (architecture §4 hush-tray row; zero-touch-ux.md §8). Binding:
`specs/standards.md`. Architecture §11 question resolved: **lean stack**
(`tray-icon` + `muda`), no Tauri. Quitting/crashing the tray never affects
filtering (the daemon is the product).

## 1. Scope & deps

- Crate `hush-tray` (exists as a stub). Deps (tray crate only, NOT workspace):
  `tray-icon`, `muda`, the matching event-loop crate tray-icon's docs require
  on macOS (verify on docs.rs — likely `tao` or `winit`), and nothing else.
  All through `cargo deny`. Target all three OSes in code (tray-icon supports
  them) but ONLY macOS is build-verified in this environment — Linux needs
  gtk system libs, Windows needs a Windows box; cfg-document both, do not
  break `cargo test --workspace` on macOS.
- Icons: build the four state dots **programmatically** (`Icon::from_rgba`
  with a circle rasterized in code — a tiny pure function, unit-testable).
  No binary assets in the repo. macOS: template-style monochrome + colored
  dot variants; keep it simple.

## 2. Behavior (zero-touch-ux.md §8)

- Discovery: read `api.addr` + `api.token` from the state dir (mirror
  `hush-cli`'s discovery — duplicate the ~30 lines rather than inventing a
  shared crate; comment the duplication and why). State dir resolution must
  match the daemon's (`HUSH_*` env override included).
- Poll `GET /v0/status` every 5 s (tokio or thread — pick what the event
  loop tolerates; tray-icon on macOS wants the main thread for UI).
- Dot states: green = filtering; amber = snoozed; grey = standing by
  (VPN / portal / user-DNS / daemon unreachable); red = attention (breaker
  fired). Map from the status response's existing guard-state field —
  read routes.rs to get the exact enum strings; unreachable API ⇒ grey with
  "starting / not running" tooltip.
- Menu: blocked counter line (disabled item, live), `Snooze 5 min` /
  `Snooze 1 hour` (POST /v0/snooze {secs}), `Resume` (POST /v0/snooze
  {secs:0} — verify the API's unsnooze contract in routes.rs first),
  `Open dashboard` (build the `#token=` URL exactly like `hush dashboard`,
  shell out to `open`), `Quit hush-tray` (with the §8 wording that protection
  keeps running).
- Tooltip: "hushwarren — N blocked today" / state description.

## 3. Structure for testability

main.rs = event loop + wiring ONLY. All logic in lib-style modules:
`state.rs` (status JSON → DotState pure mapping), `client.rs` (blocking HTTP
with token — `reqwest` blocking or `std` + existing pattern; pick the
lightest already-vetted dep), `icon.rs` (rgba circle renderer). Unit tests on
all three (mock status JSONs incl. snoozed/attention/unreachable; icon
buffer: correct dimensions, center pixel colored, corner transparent).
NO GUI e2e (document why: headless CI). A `--once` CLI flag prints the
resolved state string and exits 0 (gives the e2e layer something real:
spawn daemon → `hush-tray --once` → expect "filtering").

## 4. macOS login item

Ship `dist/macos/io.hushwarren.tray.plist` (LaunchAgent, RunAtLoad, user
session) + install/uninstall.sh additions guarded so a missing tray binary
is not fatal. WP12 packages it; here just the plist + script lines.

## 5. Mandatory tests

Unit per §3. E2E: `--once` against a running daemon (extend the cli e2e
harness pattern; skip gracefully if the tray binary can't init headless —
`--once` must not require the event loop). Gate per standards §1 on macOS.

## 6. Deliverable

Working menu-bar app on macOS; compile-clean cross-platform code paths;
run summary per standards §7 incl. a manual-verification note (the agent
cannot click a menu bar: state exactly what was and wasn't verified).
