#!/bin/bash
# hushwarren macOS uninstaller — leaves DNS bit-identical to pre-install.
#   sudo ./dist/macos/uninstall.sh [--purge]   (--purge also removes state/logs)
set -euo pipefail

LABEL="io.hushwarren.daemon"
TRAY_LABEL="io.hushwarren.tray"
APP_SUPPORT="/Library/Application Support/hushwarren"
BIN_DST="/usr/local/bin"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
LOG_DIR="/Library/Logs/hushwarren"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

echo "==> restoring DNS from snapshot (dependency-light path; works without the daemon)"
if [ -x "$BIN_DST/hushd" ] && [ -f "$APP_SUPPORT/dns-snapshot.json" ]; then
  "$BIN_DST/hushd" --state-dir "$APP_SUPPORT" restore
else
  echo "    no snapshot/binary found — skipping (DNS was never taken over?)"
fi

# ── Stop and remove tray login item (not fatal if absent) ──────────────────
echo "==> stopping tray login item"
TRAY_AGENT_PLIST="$HOME/Library/LaunchAgents/${TRAY_LABEL}.plist"
launchctl bootout "gui/$(id -u)" "$TRAY_AGENT_PLIST" 2>/dev/null || true
rm -f "$TRAY_AGENT_PLIST"

echo "==> stopping + removing service"
launchctl bootout system "$PLIST" 2>/dev/null || true
rm -f "$PLIST"

echo "==> removing binaries"
rm -f "$BIN_DST/hushd" "$BIN_DST/hush" "$BIN_DST/hush-tray"

if [ "$PURGE" -eq 1 ]; then
  echo "==> purging state + logs"
  rm -rf "$APP_SUPPORT" "$LOG_DIR"
  # Remove the per-user tray log directory created by install_tray_agent.
  # $HOME is available even when run with sudo (sudo preserves HOME by default
  # on macOS, or the invoking user's home is available via logname).
  USER_TRAY_LOG="${HOME}/Library/Logs/hushwarren"
  if [ -d "${USER_TRAY_LOG}" ]; then
    rm -rf "${USER_TRAY_LOG}"
    echo "==> removed user tray log dir: ${USER_TRAY_LOG}"
  fi
else
  echo "==> keeping state at '$APP_SUPPORT' (allowlist survives reinstall; --purge to remove)"
fi

# Remove shared resources installed by the .pkg.
echo "==> removing shared resources"
rm -rf "/usr/local/share/hushwarren"

# Forget the pkg receipt so macOS does not think hushwarren is still installed.
# pkgutil --forget is idempotent (silently no-ops if the receipt doesn't exist).
echo "==> forgetting pkg receipt"
pkgutil --forget io.hushwarren.pkg 2>/dev/null || true

echo "==> uninstalled. DNS restored to its pre-install configuration."
