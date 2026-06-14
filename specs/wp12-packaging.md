# WP12 — Packaging: installers, uninstallers, first-run snapshot

P2 deliverable (architecture §10 P2 "signed installers, uninstallers,
pre-fetched list snapshot"; os-integration.md §4). Binding:
`specs/standards.md`. Honesty rule: SIGNING NEEDS CERTS the repo does not
have — every artifact builds unsigned with documented signing hooks
(env-var driven), and the run summary states exactly which artifacts were
actually built and inspected in this environment (macOS) vs recipe-only.

## 1. First-run snapshot (the only daemon code change)

- Roadmap §1.1 license constraint: snapshot is built from **Hagezi only**
  (MIT, bundleable). OISD is runtime-fetch only — never in a package.
- `dist/build-snapshot.sh`: fetches hagezi light + multi at package-build
  time into `dist/_snapshot/` (raw list files + a manifest.json with URL,
  fetch date, license, attribution).
- Daemon: at cold start, when the state dir has NO cached lists AND a
  packaged snapshot exists at a well-known path (`/usr/local/share/hushwarren/
  snapshot` on unix; config override `lists.snapshot_dir` for tests), the
  lists pipeline compiles from the snapshot immediately, then refreshes from
  the network as usual. Seam: `ListsPipeline` cold-start only — do NOT touch
  app.rs beyond passing the configured path. Blocking works on first boot
  with no network (architecture §6).

## 2. macOS `.pkg` (BUILDABLE HERE — build and inspect it)

- `dist/macos/build-pkg.sh`: release build → `pkgbuild` component(s)
  (binaries to /usr/local/bin, LaunchDaemon plist, tray LaunchAgent plist,
  snapshot to /usr/local/share/hushwarren/snapshot) → `productbuild`
  distribution pkg. Postinstall script = the existing install.sh takeover
  flow (load daemon, takeover); preserve the proven transactional behavior —
  reuse install.sh logic, don't fork it (extract shared steps into
  `dist/macos/lib.sh` if needed).
- Uninstall: `.pkg` has no uninstaller — keep/extend `uninstall.sh` (restore
  DNS, unload, remove files, forget receipts via `pkgutil --forget`).
- Signing hooks: `HUSH_SIGN_IDENTITY` (codesign), `HUSH_INSTALLER_IDENTITY`
  (productsign), `HUSH_NOTARY_PROFILE` (notarytool) — all optional; absent ⇒
  unsigned with a loud build-log note.
- VERIFY: actually run build-pkg.sh; `pkgutil --expand` the result and
  assert payload contents + scripts in a repo test script
  (`dist/macos/test-pkg.sh`, runnable without sudo — no install).

## 3. Linux packages (recipe + local structural check)

- `dist/linux/`: systemd unit (Restart=always, dedicated user,
  CAP_NET_BIND_SERVICE per os-integration §3), postinst (create user,
  enable+start, `hushd takeover`), prerm (restore + disable), nfpm.yaml (or
  cargo-deb config — pick ONE, justify) producing .deb + .rpm in CI.
- This mac cannot run dpkg/rpm builds: provide the config + a CI job recipe
  (`dist/linux/README.md` + a Gitea workflow snippet consistent with the
  existing CI) and a shellcheck-style sanity script for the scripts. State
  "built in CI, not here" in the summary.

## 4. Windows installer (recipe only)

`dist/windows/`: WiX v4 `.wxs` (binaries, service install via `hushd
service install`, Start-menu shortcut for tray, uninstall custom action =
restore DNS first), README with the exact build command for a Windows CI
runner + `HUSH_SIGN_PFX` hook. Recipe-only — no Windows here; say so.

## 5. Mandatory tests / verification

- `dist/macos/test-pkg.sh` (structural assertions on the built pkg) runs
  green locally — wire it as an `#[ignore]`-style manual script, NOT into
  cargo test (packaging ≠ unit tests; document in dist/README.md).
- Daemon unit/integration: snapshot cold-start (state dir empty + snapshot
  dir populated ⇒ rules compiled, queries blocked before any fetch; then a
  fetch refresh swaps normally — extend the existing lists tests with a
  tempdir snapshot).
- `cargo test --workspace` untouched-green; shellcheck the new scripts if
  shellcheck is available locally (report if not).

## 6. Deliverable

dist/ tree per above + the snapshot cold-start seam + built-and-inspected
unsigned .pkg. Run summary per standards §7 with the built-vs-recipe table
and the signing-hook documentation.
