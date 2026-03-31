#!/bin/sh
set -eu

LOG_FILE="${BRUCE_HOOK_LOG_FILE:-/data/state/hook-events.log}"
mkdir -p "$(dirname "$LOG_FILE")"

printf '%s old=%s new=%s iaco=%s sha=%s path=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "${BRUCE_OLD_CLASSIFICATION:-UNKNOWN}" \
  "${BRUCE_NEW_CLASSIFICATION:-UNKNOWN}" \
  "${BRUCE_IACO_SCORE:-0}" \
  "${BRUCE_CAPTURE_SHA256:-}" \
  "${BRUCE_CAPTURE_PATH:-}" >> "$LOG_FILE"
