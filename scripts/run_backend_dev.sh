#!/usr/bin/env bash
#
# Run the backend for development: migrate, then serve with reload.
#
#   scripts/run_backend_dev.sh
#   scripts/run_backend_dev.sh --port 8080 --no-migrate
#
# Migrations run first, every time. A backend started against a database one
# revision behind fails on the first query that touches the changed table,
# which is somewhere in the middle of a request rather than at startup, and the
# error names a column instead of naming the cause.
set -euo pipefail

cd "$(dirname "$0")/.."

HOST="127.0.0.1"
PORT="8000"
MIGRATE=1
RELOAD="--reload"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --no-migrate) MIGRATE=0; shift ;;
    --no-reload) RELOAD=""; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

if [[ ! -f backend/.env ]]; then
  echo "backend/.env not found." >&2
  echo "Start from the example:  cp backend/.env.example backend/.env" >&2
  echo "Then set BACKEND_SECRET_KEY, which has no default by design." >&2
  exit 1
fi

if ! python3 -c 'import fastapi' 2>/dev/null; then
  echo "FastAPI is not importable. Install the requirements:" >&2
  echo "  python3 -m venv .venv && . .venv/bin/activate" >&2
  echo "  pip install -r backend/requirements.txt -r backend/requirements-dev.txt" >&2
  exit 1
fi

# 127.0.0.1 rather than 0.0.0.0 by default. A development server bound to every
# interface is reachable from the network it is on, and this one ships with
# known development usernames.
if [[ "$HOST" == "0.0.0.0" ]]; then
  echo "warning: binding to 0.0.0.0 exposes a development server with known" >&2
  echo "         usernames to your whole network." >&2
fi

cd backend

if [[ $MIGRATE -eq 1 ]]; then
  echo "running migrations"
  alembic upgrade head
fi

echo "serving on http://${HOST}:${PORT}  (docs at /docs)"
exec uvicorn app.main:app --host "$HOST" --port "$PORT" ${RELOAD}
