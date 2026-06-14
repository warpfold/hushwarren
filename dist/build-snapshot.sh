#!/bin/bash
# dist/build-snapshot.sh — fetch Hagezi blocklist snapshot for installer bundling.
#
# WP12 §1: Hagezi light + multi (MIT, bundleable) only. OISD is runtime-fetch
# only and must NOT be included in any package.
#
# Output: dist/_snapshot/
#   hagezi-light.txt
#   hagezi-multi.txt
#   manifest.json  (url, fetch_date, license, attribution per each source)
#
# Usage:
#   ./dist/build-snapshot.sh            # write to dist/_snapshot/
#   OUT_DIR=/tmp/snap ./dist/build-snapshot.sh
#
# Network access is required (called at package-build time, not at test time).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/_snapshot}"

LIGHT_URL="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt"
MULTI_URL="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"

echo "==> building snapshot in ${OUT_DIR}"
mkdir -p "${OUT_DIR}"

fetch_one() {
    local url="$1"
    local name="$2"
    local dest="${OUT_DIR}/${name}.txt"

    echo "  fetching ${url}"
    if ! curl -fsSL --connect-timeout 30 --max-time 300 -o "${dest}" "${url}"; then
        echo "ERROR: failed to fetch ${url}" >&2
        return 1
    fi
    local lines
    lines="$(wc -l < "${dest}" | tr -d ' ')"
    echo "  ${name}: ${lines} lines -> ${dest}"
}

fetch_one "${LIGHT_URL}" "hagezi-light"
fetch_one "${MULTI_URL}" "hagezi-multi"

FETCH_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Write manifest.json.
cat > "${OUT_DIR}/manifest.json" <<EOF
{
  "fetch_date": "${FETCH_DATE}",
  "sources": [
    {
      "name": "hagezi-light",
      "url": "${LIGHT_URL}",
      "file": "hagezi-light.txt",
      "license": "MIT",
      "attribution": "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)"
    },
    {
      "name": "hagezi-multi",
      "url": "${MULTI_URL}",
      "file": "hagezi-multi.txt",
      "license": "MIT",
      "attribution": "Hagezi DNS Blocklists (https://github.com/hagezi/dns-blocklists)"
    }
  ],
  "note": "OISD lists are runtime-fetch only; never bundled (WP12 §1 license constraint)"
}
EOF

echo "==> snapshot written to ${OUT_DIR}"
echo "    manifest.json, hagezi-light.txt, hagezi-multi.txt"
echo "    fetch_date: ${FETCH_DATE}"
