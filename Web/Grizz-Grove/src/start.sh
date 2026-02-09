#!/usr/bin/env bash
set -euo pipefail

# Make PATH explicit (covers weird supervisor env edge cases)
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

: "${PORT:=1338}"
: "${WEB_BIND:=0.0.0.0:${PORT}}"
: "${WEB_WORKERS:=1}"
: "${BOT_BASE_URL:=http://127.0.0.1:${PORT}}"
: "${BOT_VISIT_TIMEOUT_MS:=6000}"
: "${BOT_POLL_INTERVAL:=0.75}"
: "${BOT_MAX_PER_LOOP:=2}"
: "${SUBMISSION_TTL_SECONDS:=1800}"

export BOT_BASE_URL BOT_VISIT_TIMEOUT_MS BOT_POLL_INTERVAL BOT_MAX_PER_LOOP SUBMISSION_TTL_SECONDS

echo "[start] web: python -m gunicorn -w ${WEB_WORKERS} -b ${WEB_BIND} app:app"
python -m gunicorn -w "${WEB_WORKERS}" -b "${WEB_BIND}" app:app &
WEB_PID=$!

echo "[start] bot: python /app/bot_worker.py (BASE_URL=${BOT_BASE_URL})"
python /app/bot_worker.py &
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
