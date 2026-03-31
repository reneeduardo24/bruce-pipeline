#!/bin/sh
set -eu

LOG_FILE="${BRUCE_HOOK_LOG_FILE:-/data/state/hook-events.log}"
mkdir -p "$(dirname "$LOG_FILE")"

timestamp() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

sanitize_for_log() {
  printf '%s' "$1" | tr '\r\n' '  '
}

log_line() {
  printf '%s %s\n' "$(timestamp)" "$1" >> "$LOG_FILE"
}

is_enabled() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

OLD_CLASSIFICATION="${BRUCE_OLD_CLASSIFICATION:-NONE}"
NEW_CLASSIFICATION="${BRUCE_NEW_CLASSIFICATION:-UNKNOWN}"
IACO_SCORE="${BRUCE_IACO_SCORE:-0}"
CAPTURE_NAME="${BRUCE_CAPTURE_NAME:-$(basename "${BRUCE_CAPTURE_PATH:-capture}")}"
CAPTURE_SHA256="${BRUCE_CAPTURE_SHA256:-}"
CAPTURE_PATH="${BRUCE_CAPTURE_PATH:-}"
PROCESSED_AT="${BRUCE_PROCESSED_AT:-$(timestamp)}"

log_line "evento=clasificacion old=${OLD_CLASSIFICATION} new=${NEW_CLASSIFICATION} iaco=${IACO_SCORE} archivo=${CAPTURE_NAME} sha=${CAPTURE_SHA256} procesado=${PROCESSED_AT} ruta=${CAPTURE_PATH}"

if ! is_enabled "${TELEGRAM_ENABLED:-false}"; then
  log_line "telegram=deshabilitado motivo=TELEGRAM_ENABLED archivo=${CAPTURE_NAME}"
  exit 0
fi

if [ -z "${TELEGRAM_BOT_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
  log_line "telegram=deshabilitado motivo=config_incompleta archivo=${CAPTURE_NAME}"
  exit 0
fi

TELEGRAM_MESSAGE="Bruce Pipeline - cambio de clasificación
Clasificación anterior: ${OLD_CLASSIFICATION}
Nueva clasificación: ${NEW_CLASSIFICATION}
Score IACO: ${IACO_SCORE}
Archivo procesado: ${CAPTURE_NAME}
SHA256: ${CAPTURE_SHA256}
Procesado: ${PROCESSED_AT}"

TELEGRAM_OUTPUT="$(
  TELEGRAM_API_BASE_URL="${TELEGRAM_API_BASE_URL:-https://api.telegram.org}" \
  TELEGRAM_MESSAGE="$TELEGRAM_MESSAGE" \
  python - <<'PY' 2>&1
import json
import os
import sys
import urllib.error
import urllib.request

api_base = os.environ["TELEGRAM_API_BASE_URL"].rstrip("/")
token = os.environ["TELEGRAM_BOT_TOKEN"]
chat_id = os.environ["TELEGRAM_CHAT_ID"]
message = os.environ["TELEGRAM_MESSAGE"]
url = f"{api_base}/bot{token}/sendMessage"
payload = json.dumps({"chat_id": chat_id, "text": message}).encode("utf-8")
request = urllib.request.Request(
    url,
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=15) as response:
        body = response.read().decode("utf-8", errors="replace")
except urllib.error.HTTPError as error:
    detail = error.read().decode("utf-8", errors="replace")
    print(f"HTTP {error.code}: {detail}", file=sys.stderr)
    raise SystemExit(1)
except Exception as error:  # pragma: no cover - shell-level integration
    print(str(error), file=sys.stderr)
    raise SystemExit(1)

try:
    parsed = json.loads(body)
except json.JSONDecodeError:
    print(f"Respuesta no valida: {body}", file=sys.stderr)
    raise SystemExit(1)

if not parsed.get("ok"):
    print(json.dumps(parsed, ensure_ascii=True), file=sys.stderr)
    raise SystemExit(1)

print("ok")
PY
)" || {
  log_line "telegram=error archivo=${CAPTURE_NAME} detalle=$(sanitize_for_log "$TELEGRAM_OUTPUT")"
  exit 0
}

log_line "telegram=enviado chat_id=${TELEGRAM_CHAT_ID} archivo=${CAPTURE_NAME} detalle=$(sanitize_for_log "$TELEGRAM_OUTPUT")"
