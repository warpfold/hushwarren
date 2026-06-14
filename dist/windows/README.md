# Windows installer — recipe + WiX v4

**Status: recipe-only.** No Windows build environment here.
Artifacts are built on a Windows CI runner.

## Requirements (Windows CI runner)

- Rust + `cross` or native Windows toolchain (`x86_64-pc-windows-msvc`)
- [WiX Toolset v4](https://wixtoolset.org/docs/intro/) (`wix` CLI or MSBuild)
- `signtool.exe` (Windows SDK) for signing

## Build command

```cmd
:: 1. Build snapshot (requires curl, available on Windows 10+)
bash dist/build-snapshot.sh

:: 2. Cargo release build
cargo build --release --target x86_64-pc-windows-msvc

:: 3. Harvest snapshot files into WiX (generates snapshot_files.wxs)
heat.exe dir dist\_snapshot ^
  -o dist\windows\snapshot_files.wxs ^
  -srd -dr INSTALLDIR ^
  -cg SnapshotFilesGroup ^
  -gg -sfrag -sreg

:: 4. Build the .msi
wix build dist\windows\hushwarren.wxs dist\windows\snapshot_files.wxs ^
  -o dist\_windows\hushwarren-installer.msi

:: 5. Sign the .msi (HUSH_SIGN_PFX hook)
if defined HUSH_SIGN_PFX (
  signtool.exe sign ^
    /f "%HUSH_SIGN_PFX%" /p "%HUSH_SIGN_PFX_PASSWORD%" ^
    /fd sha256 /tr http://timestamp.digicert.com /td sha256 ^
    dist\_windows\hushwarren-installer.msi
) else (
  echo NOTE: HUSH_SIGN_PFX not set -- installer is unsigned.
)
```

## Signing hook

| Environment variable | Purpose |
|---|---|
| `HUSH_SIGN_PFX` | Path to the `.pfx` code-signing certificate |
| `HUSH_SIGN_PFX_PASSWORD` | Password for the `.pfx` file |

When `HUSH_SIGN_PFX` is absent the `.msi` is built unsigned with a loud log
note.  For public distribution, EV/OV code-signing is mandatory — unsigned new
binaries that rewrite DNS are flagged by Smart-App-Control and Defender
(docs/os-integration.md §4).

## Gitea CI recipe

Add to `.gitea/workflows/ci.yaml`:

```yaml
  package-windows:
    runs-on: self-hosted-windows-amd64
    needs: gate
    if: startsWith(github.ref, 'refs/tags/')
    steps:
      - uses: actions/checkout@v4

      - name: Build snapshot
        run: bash dist/build-snapshot.sh

      - name: Cargo build --release
        run: cargo build --release --target x86_64-pc-windows-msvc

      - name: Harvest snapshot
        run: |
          heat.exe dir dist\_snapshot -o dist\windows\snapshot_files.wxs `
            -srd -dr INSTALLDIR -cg SnapshotFilesGroup -gg -sfrag -sreg

      - name: Build .msi
        run: |
          wix build dist\windows\hushwarren.wxs dist\windows\snapshot_files.wxs `
            -o dist\_windows\hushwarren-installer.msi

      - name: Sign (if cert available)
        run: |
          if ($env:HUSH_SIGN_PFX) {
            signtool.exe sign /f $env:HUSH_SIGN_PFX /p $env:HUSH_SIGN_PFX_PASSWORD `
              /fd sha256 /tr http://timestamp.digicert.com /td sha256 `
              dist\_windows\hushwarren-installer.msi
          } else {
            Write-Host "NOTE: HUSH_SIGN_PFX not set -- installer is unsigned."
          }
        env:
          HUSH_SIGN_PFX: ${{ secrets.HUSH_SIGN_PFX }}
          HUSH_SIGN_PFX_PASSWORD: ${{ secrets.HUSH_SIGN_PFX_PASSWORD }}
```

## WiX v4 design notes

- `hushd.exe service install` custom action: hushd already implements the
  Windows Service Manager protocol via the `windows-service` crate — no
  `ServiceControl` element needed. It registers the service as **LocalSystem**
  with restart-on-crash recovery (1 s/2 s/5 s); LocalSystem is required because
  the Sentinel rewrites the protected `Tcpip\…\NameServer` registry keys. See
  `proof/zero-touch-evidence-windows.md`.
- Uninstall custom action: `DnsRestore` runs BEFORE `RemoveFiles` so
  `dns-snapshot.json` is still on disk when the restore command reads it.
- Start-menu shortcut + Run-key for hush-tray (per os-integration §4).
- Snapshot files are harvested at CI build time via `heat.exe dir` because
  WiX v4 requires explicit `<File>` elements; the `SnapshotFilesGroup`
  component group is generated, not hand-authored.
