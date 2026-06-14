# Linux packaging — recipe + CI

**Status: recipe-only.** This Mac cannot run `dpkg`/`rpm` builds.
Artifacts are built in CI on a Linux runner.

## Tooling choice

`nfpm` (Go binary, MIT) over `cargo-deb` (Rust crate) because:

1. Single config produces both `.deb` and `.rpm`.
2. No Rust workspace dependency — keeps the package step independent.
3. Consistent with `docs/os-integration.md §5` "nfpm-style deb+rpm".

## CI recipe (Gitea — matches `.gitea/workflows/ci.yaml` pattern)

Add to `.gitea/workflows/ci.yaml` as a separate job triggered on tag pushes:

```yaml
  package-linux:
    runs-on: self-hosted-linux-amd64   # or ubuntu-latest on GitHub Actions
    needs: gate
    if: startsWith(github.ref, 'refs/tags/')
    env:
      WS: workspace-hushwarren
    steps:
      - name: Checkout
        run: |
          if [ -d "$WS/.git" ]; then
            cd "$WS"
            git fetch origin "$GITHUB_SHA"
            git reset --hard "$GITHUB_SHA"
          else
            git clone "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY.git" "$WS"
            cd "$WS" && git checkout "$GITHUB_SHA"
          fi

      - name: Install nfpm
        run: |
          if ! command -v nfpm >/dev/null 2>&1; then
            curl -sSfL \
              https://github.com/goreleaser/nfpm/releases/latest/download/nfpm_linux_amd64.tar.gz \
              | tar -xz -C /usr/local/bin nfpm
          fi

      - name: Build snapshot (Hagezi MIT lists)
        run: cd "$WS" && bash dist/build-snapshot.sh

      - name: Cargo build --release
        run: cd "$WS" && cargo build --release

      - name: Build .deb
        run: |
          cd "$WS"
          nfpm package --config dist/linux/nfpm.yaml --packager deb

      - name: Build .rpm
        run: |
          cd "$WS"
          nfpm package --config dist/linux/nfpm.yaml --packager rpm

      - name: Upload artifacts
        run: |
          # Upload hushwarren_*.deb and hushwarren-*.rpm to the Gitea release.
          echo "upload artifacts here (gitea release API or artifact store)"
```

## Files

| File | Purpose |
|---|---|
| `hushd.service` | systemd unit (Restart=always, CAP_NET_BIND_SERVICE, dedicated user) |
| `postinst` | create user, enable+start, `hushd takeover` |
| `prerm` | `hushd restore`, disable+stop |
| `nfpm.yaml` | nfpm config for .deb + .rpm |

## Shell sanity

Run `shellcheck` on the scripts when available locally:

```sh
command -v shellcheck && shellcheck dist/linux/postinst dist/linux/prerm || echo "shellcheck not available"
```

**Note:** `shellcheck` was not available in the build environment when WP12 was
implemented. Scripts follow `set -euo pipefail` and standard Debian postinst
conventions; review manually if shellcheck is unavailable.

## Signing

Linux packages are not signed at the binary level in P2 (rpm and dpkg signing
requires GPG key infrastructure). Add GPG signing in CI via:

```sh
# nfpm does not sign; sign the .deb separately:
dpkg-sig --sign builder hushwarren_*.deb
# or via reprepro / aptly repository signing.
```
