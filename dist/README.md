# dist/ — packaging artifacts, scripts, and CI recipes

WP12 packaging deliverables.  See `specs/wp12-packaging.md` for the binding spec.

## Built-vs-recipe matrix

| Artifact | Status | Notes |
|---|---|---|
| `dist/_snapshot/` | **Built here (macOS)** | `dist/build-snapshot.sh` fetches Hagezi light + multi at package-build time; real network OK |
| `dist/_pkg/hushwarren-installer.pkg` | **Built here (macOS)** | `pkgbuild` + `productbuild`; unsigned (no `HUSH_SIGN_IDENTITY`); inspected by `test-pkg.sh` |
| Linux `.deb` | **Recipe only** (built in CI on Linux) | `nfpm package --packager deb`; see `dist/linux/README.md` |
| Linux `.rpm` | **Recipe only** (built in CI on Linux) | `nfpm package --packager rpm`; see `dist/linux/README.md` |
| Windows `.msi` | **Recipe only** (built in CI on Windows) | `wix build hushwarren.wxs`; see `dist/windows/README.md` |

## Signing hooks (all optional; absent = unsigned with loud log note)

| Variable | Scope | Effect |
|---|---|---|
| `HUSH_SIGN_IDENTITY` | macOS | `codesign` identity for binaries in the pkg |
| `HUSH_INSTALLER_IDENTITY` | macOS | `productsign` identity for the `.pkg` |
| `HUSH_NOTARY_PROFILE` | macOS | `notarytool` credential-store profile (requires `HUSH_INSTALLER_IDENTITY`) |
| `HUSH_SIGN_PFX` | Windows | Path to the `.pfx` code-signing certificate |
| `HUSH_SIGN_PFX_PASSWORD` | Windows | Password for the `.pfx` |

## Directory structure

```
dist/
├── build-snapshot.sh          # Fetch Hagezi light+multi → dist/_snapshot/
├── _snapshot/                 # Generated: hagezi-light.txt, hagezi-multi.txt, manifest.json
├── _pkg/                      # Generated: hushwarren.pkg, hushwarren-installer.pkg
├── macos/
│   ├── build-pkg.sh           # Build the macOS .pkg (runs here)
│   ├── test-pkg.sh            # Structural assertions on the .pkg (no sudo, no install)
│   ├── lib.sh                 # Shared install helpers (sourced by install.sh + postinstall)
│   ├── postinstall            # pkg postinstall script (load daemon, takeover)
│   ├── install.sh             # One-command installer (zero-touch contract)
│   ├── uninstall.sh           # Uninstaller (restore DNS, pkgutil --forget)
│   └── io.hushwarren.tray.plist
├── linux/
│   ├── hushd.service          # systemd unit (Restart=always, CAP_NET_BIND_SERVICE)
│   ├── postinst               # Debian/RPM post-install (create user, takeover)
│   ├── prerm                  # Debian/RPM pre-remove (restore, disable)
│   ├── nfpm.yaml              # nfpm config for .deb + .rpm
│   └── README.md              # CI recipe
└── windows/
    ├── hushwarren.wxs         # WiX v4 installer definition
    └── README.md              # Build command + HUSH_SIGN_PFX hook
```

## Verification

The macOS `.pkg` is verified without installing:

```sh
./dist/macos/test-pkg.sh            # structural assertions via pkgutil --expand
```

Shell scripts are sanity-checked with shellcheck when available:

```sh
command -v shellcheck && shellcheck dist/macos/install.sh dist/macos/uninstall.sh \
  dist/macos/lib.sh dist/macos/postinstall dist/linux/postinst dist/linux/prerm \
  || echo "shellcheck not available"
```

## First-run snapshot seam (WP12 §1)

The bundled Hagezi light + multi snapshot (`/usr/local/share/hushwarren/snapshot`
on macOS/Linux; `%ProgramFiles%\hushwarren\snapshot` on Windows) allows the
daemon to compile blocking rules on cold start with no network access.

- Only Hagezi (MIT) is bundled.  OISD is runtime-fetch only — never in the pkg.
- The `lists.snapshot_dir` config field is the test-override knob.  Production
  installers set `HUSH_SNAPSHOT_DIR` in the LaunchDaemon plist.
- After cold-start compile from snapshot, the normal refresh loop runs and will
  overwrite the snapshot-derived rules with the latest network-fetched rules.
