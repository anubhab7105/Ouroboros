#!/usr/bin/env bash
#
# Block until the backend is ready, or give up and say why.
#
#   scripts/wait_for_backend.sh
#   scripts/wait_for_backend.sh --timeout 120 --url http://localhost:8000
#
# Polls /api/v1/health/ready, which reports the database check as well as the
# process being up. That distinction is the reason this script exists: a
# container that is listening is not a backend that can serve a request, and a
# seed script run one second too early fails with a connection error that looks
# like a bug in the seed script.
#
# Exit codes
#   0  ready
#   1  reachable but not ready before the timeout
#   2  never reachable
set -euo pipefail

URL="${MULEGUARD_BASE_URL:-http://localhost:8000}"
TIMEOUT=60
INTERVAL=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

READY_URL="${URL%/}/api/v1/health/ready"
DEADLINE=$(( $(date +%s) + TIMEOUT ))
EVER_REACHED=0
LAST_BODY=""

printf 'waiting for %s (timeout %ss)' "$READY_URL" "$TIMEOUT"

while [[ $(date +%s) -lt $DEADLINE ]]; do
  if LAST_BODY=$(curl -fsS --max-time 5 "$READY_URL" 2>/dev/null); then
    EVER_REACHED=1

    # The endpoint answers 200 with `ready: false` while the database check is
    # still failing, so the status code alone is not the signal.
    if printf '%s' "$LAST_BODY" | grep -q '"ready"[[:space:]]*:[[:space:]]*true'; then
      printf '\nready\n'
      exit 0
    fi
  fi

  printf '.'
  sleep "$INTERVAL"
done

printf '\n'

if [[ $EVER_REACHED -eq 0 ]]; then
  echo "never reached $READY_URL in ${TIMEOUT}s." >&2
  echo "Is the backend running?  scripts/run_backend_dev.sh" >&2
  echo "In Docker?               docker compose logs -f backend" >&2
  exit 2
fi

echo "reachable but not ready after ${TIMEOUT}s." >&2
echo "The process is up and a dependency check is failing. Last response:" >&2
printf '%s\n' "$LAST_BODY" | head -c 2000 >&2
echo >&2
echo "Most often this is the database: check DATABASE_URL, and that migrations" >&2
echo "have run (make migrate, or alembic upgrade head)." >&2
exit 1
