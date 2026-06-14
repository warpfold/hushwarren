#!/bin/bash
# dist/macos/test-pkg.sh — structural assertions on the built .pkg (no sudo, no install).
#
# WP12 §2.  Expands the distribution pkg with pkgutil --expand and checks that
# the expected payload files and scripts are present.  Does NOT install the pkg.
#
# Usage:
#   ./dist/macos/test-pkg.sh [<pkg-path>]
#
# Default pkg path: dist/_pkg/hushwarren-installer.pkg
#
# Exit codes:
#   0 — all assertions passed
#   1 — one or more assertions failed
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PKG="${1:-${REPO_ROOT}/dist/_pkg/hushwarren-installer.pkg}"

PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*" >&2; FAIL=$((FAIL+1)); }

assert_file() {
    local f="$1"
    if [ -f "$f" ]; then
        pass "file exists: $f"
    else
        fail "missing file: $f"
    fi
}

assert_dir() {
    local d="$1"
    if [ -d "$d" ]; then
        pass "dir exists: $d"
    else
        fail "missing dir: $d"
    fi
}

assert_nonempty() {
    local f="$1"
    if [ -s "$f" ]; then
        pass "non-empty: $f"
    else
        fail "empty or missing: $f"
    fi
}

echo "==> test-pkg.sh: structural assertions"
echo "    pkg: ${PKG}"
echo ""

# Check the pkg file itself exists.
[ -f "${PKG}" ] || { echo "ERROR: pkg not found: ${PKG}" >&2; echo "Run ./dist/macos/build-pkg.sh first." >&2; exit 1; }

# Expand into a temp directory.
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "==> expanding ${PKG} -> ${TMP}/expanded"
pkgutil --expand "${PKG}" "${TMP}/expanded"

echo ""
echo "── Distribution XML ─────────────────────────────────────────────────────"
assert_file "${TMP}/expanded/Distribution"
if grep -q "io.hushwarren.pkg" "${TMP}/expanded/Distribution" 2>/dev/null; then
    pass "Distribution references io.hushwarren.pkg"
else
    fail "Distribution must reference io.hushwarren.pkg"
fi

echo ""
echo "── Component package ────────────────────────────────────────────────────"
COMP_PKG="${TMP}/expanded/hushwarren.pkg"
assert_dir "${COMP_PKG}"

echo ""
echo "── Payload (Payload or Payload.gz) ──────────────────────────────────────"
# pkgutil --expand may produce Payload or Payload.gz depending on compression.
PAYLOAD=""
if [ -f "${COMP_PKG}/Payload" ]; then
    PAYLOAD="${COMP_PKG}/Payload"
elif [ -f "${COMP_PKG}/Payload.gz" ]; then
    PAYLOAD="${COMP_PKG}/Payload.gz"
fi
if [ -n "${PAYLOAD}" ]; then
    pass "Payload file present: ${PAYLOAD}"
else
    fail "No Payload or Payload.gz in ${COMP_PKG}"
fi

# Extract the cpio payload into a further subdirectory for file assertions.
PAYLOAD_DIR="${TMP}/payload_contents"
mkdir -p "${PAYLOAD_DIR}"
if [ -n "${PAYLOAD}" ]; then
    # Decompress if needed, then extract via cpio.
    (
        cd "${PAYLOAD_DIR}"
        if [[ "${PAYLOAD}" == *.gz ]]; then
            gunzip -c "${PAYLOAD}" | cpio -i --quiet 2>/dev/null || true
        else
            # Try as gzip first (pkgbuild often gzip-compresses Payload without .gz ext).
            if gunzip -c "${PAYLOAD}" > /dev/null 2>&1; then
                gunzip -c "${PAYLOAD}" | cpio -i --quiet 2>/dev/null || true
            else
                cpio -i --quiet < "${PAYLOAD}" 2>/dev/null || true
            fi
        fi
    )
fi

echo ""
echo "── Payload binary contents ──────────────────────────────────────────────"
assert_file "${PAYLOAD_DIR}/usr/local/bin/hushd"
assert_file "${PAYLOAD_DIR}/usr/local/bin/hush"

echo ""
echo "── Payload snapshot contents ────────────────────────────────────────────"
SNAP="${PAYLOAD_DIR}/usr/local/share/hushwarren/snapshot"
assert_dir "${SNAP}"
assert_file "${SNAP}/manifest.json"
assert_file "${SNAP}/hagezi-light.txt"
assert_file "${SNAP}/hagezi-multi.txt"
assert_nonempty "${SNAP}/hagezi-light.txt"
assert_nonempty "${SNAP}/hagezi-multi.txt"
assert_nonempty "${SNAP}/manifest.json"

if grep -q '"license": "MIT"' "${SNAP}/manifest.json" 2>/dev/null; then
    pass "manifest.json contains MIT license entry"
else
    fail "manifest.json must contain MIT license entry"
fi

if grep -q '"fetch_date"' "${SNAP}/manifest.json" 2>/dev/null; then
    pass "manifest.json contains fetch_date"
else
    fail "manifest.json must contain fetch_date"
fi

echo ""
echo "── Payload share dir contents ───────────────────────────────────────────"
SHARE="${PAYLOAD_DIR}/usr/local/share/hushwarren"
assert_file "${SHARE}/io.hushwarren.tray.plist"
assert_file "${SHARE}/uninstall.sh"

echo ""
echo "── Scripts (postinstall + lib.sh) ───────────────────────────────────────"
SCRIPTS="${COMP_PKG}/Scripts"
assert_dir "${SCRIPTS}"
assert_file "${SCRIPTS}/postinstall"
assert_file "${SCRIPTS}/lib.sh"

if grep -q "run_takeover\|takeover" "${SCRIPTS}/postinstall" 2>/dev/null; then
    pass "postinstall references the takeover flow"
else
    fail "postinstall must call the takeover flow"
fi

if grep -q "write_launch_daemon\|LaunchDaemon" "${SCRIPTS}/lib.sh" 2>/dev/null; then
    pass "lib.sh contains LaunchDaemon logic"
else
    fail "lib.sh must contain LaunchDaemon logic"
fi

echo ""
echo "── PackageInfo ──────────────────────────────────────────────────────────"
assert_file "${COMP_PKG}/PackageInfo"
if grep -q "io.hushwarren.pkg" "${COMP_PKG}/PackageInfo" 2>/dev/null; then
    pass "PackageInfo has correct identifier"
else
    fail "PackageInfo identifier must be io.hushwarren.pkg"
fi

echo ""
echo "────────────────────────────────────────────────────────────────────────"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo ""
if [ "${FAIL}" -gt 0 ]; then
    echo "FAIL: ${FAIL} assertion(s) failed." >&2
    exit 1
else
    echo "PASS: all assertions passed."
fi
