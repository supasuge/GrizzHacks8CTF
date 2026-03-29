#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${APP_DIR}"

# Make PATH explicit (covers weird supervisor env edge cases)
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

: "${PORT:=8080}"
: "${WEB_BIND:=0.0.0.0:${PORT}}"
: "${WEB_WORKERS:=1}"
: "${BOT_BASE_URL:=http://127.0.0.1:${PORT}}"
: "${BOT_VISIT_TIMEOUT_MS:=6000}"
: "${BOT_POLL_INTERVAL:=0.75}"
: "${BOT_MAX_PER_LOOP:=2}"
: "${SUBMISSION_TTL_SECONDS:=1800}"
: "${DB_PATH:=${APP_DIR}/state.db}"
: "${FLAG_PATH:=${APP_DIR}/flag.txt}"

export BOT_BASE_URL BOT_VISIT_TIMEOUT_MS BOT_POLL_INTERVAL BOT_MAX_PER_LOOP SUBMISSION_TTL_SECONDS DB_PATH FLAG_PATH

echo "[start] web: python -m gunicorn -w ${WEB_WORKERS} -b ${WEB_BIND} app:app"
python -m gunicorn -w "${WEB_WORKERS}" -b "${WEB_BIND}" app:app &
WEB_PID=$!

echo "[start] bot: python ${APP_DIR}/bot_worker.py (BASE_URL=${BOT_BASE_URL})"
python "${APP_DIR}/bot_worker.py" &
BOT_PID=$!

cleanup() {
  echo "[start] stopping..."
  kill -TERM "$BOT_PID" "$WEB_PID" 2>/dev/null || true
  wait "$BOT_PID" 2>/dev/null || true
  wait "$WEB_PID" 2>/dev/null || true
  echo "[start] stopped."
}
trap cleanup INT TERM
wait -n "$WEB_PID" "$BOT_PID" || true
cleanup
exit 1
