#!/bin/bash
# dist/macos/lib.sh — shared helpers for install.sh and the .pkg postinstall script.
#
# Source this file; do not execute directly.
# WP12 §2: extracted from install.sh so postinstall can reuse the proven flow
# without forking it.

LABEL="io.hushwarren.daemon"
TRAY_LABEL="io.hushwarren.tray"
APP_SUPPORT="/Library/Application Support/hushwarren"
BIN_DST="/usr/local/bin"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
LOG_DIR="/Library/Logs/hushwarren"
SHARE_DIR="/usr/local/share/hushwarren"
SNAPSHOT_DIR="${SHARE_DIR}/snapshot"

# ── write_launch_daemon ───────────────────────────────────────────────────────
# Write the LaunchDaemon plist, reload, and wait for readiness.
# Binaries are expected at BIN_DST already.
write_launch_daemon() {
    echo "==> writing LaunchDaemon ${PLIST}"
    launchctl bootout system "${PLIST}" 2>/dev/null || true
    cat > "${PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BIN_DST}/hushd</string>
    <string>--state-dir</string><string>${APP_SUPPORT}</string>
    <string>run</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HUSH_SNAPSHOT_DIR</key>
    <string>${SNAPSHOT_DIR}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${LOG_DIR}/hushd.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/hushd.log</string>
</dict></plist>
EOF
    chown root:wheel "${PLIST}" && chmod 0644 "${PLIST}"
}

# ── start_daemon_and_wait ─────────────────────────────────────────────────────
# Bootstrap the daemon and wait up to 30 s for api.addr to appear.
start_daemon_and_wait() {
    # Clear stale readiness marker so the wait tracks THIS daemon instance.
    rm -f "${APP_SUPPORT}/api.addr"

    echo "==> starting service"
    launchctl bootstrap system "${PLIST}"

    echo "==> waiting for resolver readiness"
    for i in $(seq 1 30); do
        [ -s "${APP_SUPPORT}/api.addr" ] && break
        sleep 1
    done
    [ -s "${APP_SUPPORT}/api.addr" ] || {
        echo "daemon did not become ready; see ${LOG_DIR}/hushd.log" >&2
        exit 1
    }
}

# ── run_takeover ──────────────────────────────────────────────────────────────
# Run the transactional DNS takeover.
run_takeover() {
    echo "==> transactional DNS takeover (self-test -> snapshot -> commit -> verify)"
    "${BIN_DST}/hushd" --state-dir "${APP_SUPPORT}" takeover
}

# ── install_tray_agent ────────────────────────────────────────────────────────
# Register the tray LaunchAgent for the current user (optional; not fatal).
#
# LaunchAgent plists do NOT expand '~' at runtime — we substitute the actual
# $HOME path for the __HUSH_TRAY_LOG__ placeholder so the user-session tray
# process can write its log without needing access to the root-owned
# /Library/Logs/hushwarren directory.
install_tray_agent() {
    local tray_plist_src="${1:-}"
    if [ -x "${BIN_DST}/hush-tray" ] && [ -f "${tray_plist_src}" ]; then
        echo "==> registering tray login item for current user"
        local TRAY_AGENT_DIR="${HOME}/Library/LaunchAgents"
        local TRAY_AGENT_PLIST="${TRAY_AGENT_DIR}/${TRAY_LABEL}.plist"
        local TRAY_USER_LOG_DIR="${HOME}/Library/Logs/hushwarren"
        local TRAY_LOG_PATH="${TRAY_USER_LOG_DIR}/hush-tray.log"
        mkdir -p "${TRAY_AGENT_DIR}" "${TRAY_USER_LOG_DIR}"
        # Copy the template plist and substitute the log path placeholder.
        sed "s|__HUSH_TRAY_LOG__|${TRAY_LOG_PATH}|g" \
            "${tray_plist_src}" > "${TRAY_AGENT_PLIST}"
        chmod 0644 "${TRAY_AGENT_PLIST}"
        launchctl bootout "gui/$(id -u)" "${TRAY_AGENT_PLIST}" 2>/dev/null || true
        launchctl bootstrap "gui/$(id -u)" "${TRAY_AGENT_PLIST}" || \
            echo "    (tray login item registration failed — you can start hush-tray manually)"
    else
        echo "    (hush-tray not installed — skipping login item)"
    fi
}
