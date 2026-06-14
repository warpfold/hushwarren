#!/bin/bash
# hushwarren macOS installer — the "one command" of the zero-touch contract.
#
#   sudo ./dist/macos/install.sh [--bin-dir <dir-with-hushd+hush>]
#
# Installs the LaunchDaemon, starts the resolver, and runs the transactional
# DNS takeover (docs/zero-touch-ux.md §1). Idempotent: safe to re-run.
# Rollback guarantee: takeover failure leaves DNS exactly as found.
#
# Implementation note: all LaunchDaemon write / daemon-start / takeover /
# tray-agent steps are delegated to dist/macos/lib.sh so that the manual
# install path and the .pkg postinstall share ONE implementation.
set -euo pipefail

# ── Source shared helpers ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

# ── Argument parsing ───────────────────────────────────────────────────────────
SRC_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)/target/release"

while [ $# -gt 0 ]; do
  case "$1" in
    --bin-dir) SRC_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run with sudo (installs a system service + rewrites DNS)" >&2; exit 1; }
[ -x "${SRC_DIR}/hushd" ] || { echo "hushd not found in ${SRC_DIR} (build with: cargo build --release)" >&2; exit 1; }
[ -x "${SRC_DIR}/hush" ]  || { echo "hush not found in ${SRC_DIR}" >&2; exit 1; }

echo "==> installing binaries to ${BIN_DST}"
mkdir -p "${BIN_DST}" "${APP_SUPPORT}" "${LOG_DIR}"
install -m 0755 "${SRC_DIR}/hushd" "${BIN_DST}/hushd"
install -m 0755 "${SRC_DIR}/hush"  "${BIN_DST}/hush"
# hush-tray is optional — missing binary is not fatal (WP10 §4).
if [ -x "${SRC_DIR}/hush-tray" ]; then
  install -m 0755 "${SRC_DIR}/hush-tray" "${BIN_DST}/hush-tray"
else
  echo "    (hush-tray binary not found in ${SRC_DIR} — skipping tray install)"
fi

# ── Snapshot directory (manual install) ──────────────────────────────────────
# On .pkg installs the snapshot is laid down by the pkg payload at SNAPSHOT_DIR
# (/usr/local/share/hushwarren/snapshot).  On manual installs the directory may
# not exist; guard so HUSH_SNAPSHOT_DIR is only wired when the snapshot is
# actually present — the daemon will fetch lists from the network otherwise.
if [ ! -d "${SNAPSHOT_DIR}" ]; then
  echo "    (snapshot dir ${SNAPSHOT_DIR} not found — daemon will fetch lists from network on first start)"
fi
# HUSH_SNAPSHOT_DIR is injected into the LaunchDaemon plist by write_launch_daemon
# (from lib.sh), which always includes the EnvironmentVariables block pointing
# at SNAPSHOT_DIR.  The daemon's apply_env_overrides() ignores the env var when
# lists.snapshot_dir is set in config, and skips loading if the path does not
# exist — so it is safe to set unconditionally.

# ── Write LaunchDaemon + start daemon + takeover ───────────────────────────────
write_launch_daemon
start_daemon_and_wait
run_takeover

echo "==> done. status:"
HUSH_STATE_DIR="${APP_SUPPORT}" "${BIN_DST}/hush" status || true

# ── Register hush-tray as a per-user login item (LaunchAgent) ──────────────
# Must run after the daemon is ready so the tray finds api.addr on first poll.
# The tray plist source is in the same directory as this script.
TRAY_PLIST_SRC="${SCRIPT_DIR}/io.hushwarren.tray.plist"
install_tray_agent "${TRAY_PLIST_SRC}"

echo
echo "hushwarren is protecting this machine. Nothing else to do."
echo "Uninstall any time with: sudo ./dist/macos/uninstall.sh"
