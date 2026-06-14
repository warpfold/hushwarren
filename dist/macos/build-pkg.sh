#!/bin/bash
# dist/macos/build-pkg.sh — build the hushwarren macOS .pkg installer.
#
# WP12 §2.  Requires: cargo build --release already completed (or pass
# --build to trigger it).  Signing is env-var driven; absent = unsigned (loud
# log line per spec).
#
# Usage:
#   cd /path/to/hushwarren
#   ./dist/macos/build-pkg.sh [--build] [--out <dir>]
#
# Environment (all optional — absent = unsigned):
#   HUSH_SIGN_IDENTITY      codesign identity (e.g. "Developer ID Application: ...")
#   HUSH_INSTALLER_IDENTITY productsign identity (e.g. "Developer ID Installer: ...")
#   HUSH_NOTARY_PROFILE     notarytool credential-store profile name
#
# Output:
#   <out-dir>/hushwarren.pkg            (component pkg, intermediate)
#   <out-dir>/hushwarren-installer.pkg  (distribution pkg, the final artifact)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
OUT_DIR="${REPO_ROOT}/dist/_pkg"
DO_BUILD=0

while [ $# -gt 0 ]; do
    case "$1" in
        --build) DO_BUILD=1; shift ;;
        --out)   OUT_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# ── 1. Optional cargo release build ──────────────────────────────────────────
if [ "${DO_BUILD}" -eq 1 ]; then
    echo "==> cargo build --release"
    cd "${REPO_ROOT}"
    cargo build --release
fi

RELEASE_DIR="${REPO_ROOT}/target/release"
for bin in hushd hush; do
    [ -x "${RELEASE_DIR}/${bin}" ] || {
        echo "ERROR: ${bin} not found in ${RELEASE_DIR}. Run: cargo build --release" >&2
        exit 1
    }
done

# ── 2. Snapshot: run dist/build-snapshot.sh if not already present ────────────
SNAPSHOT_SRC="${DIST_DIR}/_snapshot"
if [ ! -f "${SNAPSHOT_SRC}/manifest.json" ]; then
    echo "==> building snapshot (no dist/_snapshot/manifest.json found)"
    "${DIST_DIR}/build-snapshot.sh"
else
    echo "==> using existing snapshot at ${SNAPSHOT_SRC}"
fi

# ── 3. Stage a payload tree ──────────────────────────────────────────────────
echo "==> staging payload"
STAGE="${OUT_DIR}/stage"
rm -rf "${STAGE}"

# Binaries → /usr/local/bin/
mkdir -p "${STAGE}/usr/local/bin"
install -m 0755 "${RELEASE_DIR}/hushd" "${STAGE}/usr/local/bin/hushd"
install -m 0755 "${RELEASE_DIR}/hush"  "${STAGE}/usr/local/bin/hush"
if [ -x "${RELEASE_DIR}/hush-tray" ]; then
    install -m 0755 "${RELEASE_DIR}/hush-tray" "${STAGE}/usr/local/bin/hush-tray"
else
    echo "    (hush-tray not found — omitting from pkg)"
fi

# Snapshot → /usr/local/share/hushwarren/snapshot/
mkdir -p "${STAGE}/usr/local/share/hushwarren/snapshot"
cp "${SNAPSHOT_SRC}"/*.txt  "${STAGE}/usr/local/share/hushwarren/snapshot/"
cp "${SNAPSHOT_SRC}/manifest.json" "${STAGE}/usr/local/share/hushwarren/snapshot/"

# Tray plist → /usr/local/share/hushwarren/ (postinstall copies to ~/Library/LaunchAgents)
cp "${SCRIPT_DIR}/io.hushwarren.tray.plist" "${STAGE}/usr/local/share/hushwarren/"

# Uninstall script → /usr/local/share/hushwarren/
cp "${SCRIPT_DIR}/uninstall.sh" "${STAGE}/usr/local/share/hushwarren/"
chmod 0755 "${STAGE}/usr/local/share/hushwarren/uninstall.sh"

# LaunchDaemon placeholder dir (postinstall writes the actual plist)
mkdir -p "${STAGE}/Library/LaunchDaemons"
mkdir -p "${STAGE}/Library/Logs/hushwarren"
mkdir -p "${STAGE}/Library/Application Support/hushwarren"

# ── 4. Optional codesign ─────────────────────────────────────────────────────
if [ -n "${HUSH_SIGN_IDENTITY:-}" ]; then
    echo "==> codesigning binaries with identity: ${HUSH_SIGN_IDENTITY}"
    for bin in hushd hush hush-tray; do
        bin_path="${STAGE}/usr/local/bin/${bin}"
        [ -x "${bin_path}" ] || continue
        codesign --force --options runtime \
            --sign "${HUSH_SIGN_IDENTITY}" \
            "${bin_path}"
    done
else
    echo "NOTE: HUSH_SIGN_IDENTITY not set — binaries will be unsigned."
    echo "      Set HUSH_SIGN_IDENTITY to codesign for distribution."
fi

# ── 5. Scripts directory (postinstall + lib.sh) ───────────────────────────────
SCRIPTS_DIR="${OUT_DIR}/scripts"
mkdir -p "${SCRIPTS_DIR}"
cp "${SCRIPT_DIR}/postinstall" "${SCRIPTS_DIR}/postinstall"
cp "${SCRIPT_DIR}/lib.sh"     "${SCRIPTS_DIR}/lib.sh"
chmod 0755 "${SCRIPTS_DIR}/postinstall"

# ── 6. pkgbuild component ────────────────────────────────────────────────────
mkdir -p "${OUT_DIR}"
COMPONENT_PKG="${OUT_DIR}/hushwarren.pkg"
echo "==> pkgbuild component: ${COMPONENT_PKG}"
pkgbuild \
    --root "${STAGE}" \
    --identifier "io.hushwarren.pkg" \
    --version "0.0.1" \
    --scripts "${SCRIPTS_DIR}" \
    --install-location "/" \
    "${COMPONENT_PKG}"

# ── 7. Distribution XML ──────────────────────────────────────────────────────
DIST_XML="${OUT_DIR}/distribution.xml"
cat > "${DIST_XML}" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>hushwarren</title>
    <options require-scripts="true" customize="never" rootVolumeOnly="true"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <background file="background.png" alignment="bottomleft" scaling="none" mime-type="image/png"/>
    <welcome file="welcome.html" mime-type="text/html"/>
    <license file="LICENSE" mime-type="text/plain"/>
    <pkg-ref id="io.hushwarren.pkg">
        <bundle-version/>
    </pkg-ref>
    <choices-outline>
        <line choice="default">
            <line choice="io.hushwarren.pkg"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="io.hushwarren.pkg" visible="false">
        <pkg-ref id="io.hushwarren.pkg"/>
    </choice>
    <pkg-ref id="io.hushwarren.pkg" version="0.0.1" onConclusion="none">hushwarren.pkg</pkg-ref>
</installer-gui-script>
EOF

# ── 8. productbuild distribution pkg ─────────────────────────────────────────
DIST_PKG="${OUT_DIR}/hushwarren-installer.pkg"
echo "==> productbuild distribution: ${DIST_PKG}"
# productbuild --resources requires a resources dir; create a minimal one.
RESOURCES="${OUT_DIR}/resources"
mkdir -p "${RESOURCES}"
# Stub out optional resources so productbuild doesn't complain.
[ -f "${RESOURCES}/welcome.html" ] || echo "<html><body><h1>hushwarren</h1></body></html>" > "${RESOURCES}/welcome.html"
[ -f "${RESOURCES}/LICENSE" ] || cp "${REPO_ROOT}/LICENSE" "${RESOURCES}/LICENSE" 2>/dev/null || echo "GPL-3.0" > "${RESOURCES}/LICENSE"

productbuild \
    --distribution "${DIST_XML}" \
    --resources "${RESOURCES}" \
    --package-path "${OUT_DIR}" \
    "${DIST_PKG}"

# ── 9. Optional productsign ──────────────────────────────────────────────────
if [ -n "${HUSH_INSTALLER_IDENTITY:-}" ]; then
    echo "==> productsign with identity: ${HUSH_INSTALLER_IDENTITY}"
    SIGNED_PKG="${OUT_DIR}/hushwarren-installer-signed.pkg"
    productsign \
        --sign "${HUSH_INSTALLER_IDENTITY}" \
        "${DIST_PKG}" \
        "${SIGNED_PKG}"
    mv "${SIGNED_PKG}" "${DIST_PKG}"
else
    echo "NOTE: HUSH_INSTALLER_IDENTITY not set — installer will be unsigned."
    echo "      Set HUSH_INSTALLER_IDENTITY to productsign for distribution."
fi

# ── 10. Optional notarization ────────────────────────────────────────────────
if [ -n "${HUSH_NOTARY_PROFILE:-}" ] && [ -n "${HUSH_INSTALLER_IDENTITY:-}" ]; then
    echo "==> notarizing with profile: ${HUSH_NOTARY_PROFILE}"
    xcrun notarytool submit "${DIST_PKG}" \
        --keychain-profile "${HUSH_NOTARY_PROFILE}" \
        --wait
    xcrun stapler staple "${DIST_PKG}"
else
    echo "NOTE: HUSH_NOTARY_PROFILE/HUSH_INSTALLER_IDENTITY not set — skipping notarization."
fi

echo
echo "==> done."
echo "    installer: ${DIST_PKG}"
echo "    component: ${COMPONENT_PKG}"
echo ""
echo "Signing hooks (set env vars before running this script):"
echo "  HUSH_SIGN_IDENTITY      — codesign identity for binaries"
echo "  HUSH_INSTALLER_IDENTITY — productsign identity for the .pkg"
echo "  HUSH_NOTARY_PROFILE     — notarytool credential-store profile for notarization"
