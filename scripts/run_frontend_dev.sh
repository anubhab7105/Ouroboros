#!/usr/bin/env bash
#
# Run the frontend development server.
#
#   scripts/run_frontend_dev.sh
#   scripts/run_frontend_dev.sh --port 5174
#
# Checks that the backend is reachable first and warns rather than refusing: a
# frontend with no backend still renders, every panel shows its error state,
# and that is occasionally what you want to look at.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="5173"
SKIP_BACKEND_CHECK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --skip-backend-check) SKIP_BACKEND_CHECK=1; shift ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

if [[ ! -d frontend/node_modules ]]; then
  echo "frontend/node_modules not found. Install first:" >&2
  echo "  cd frontend && npm ci" >&2
  exit 1
fi

if [[ ! -f frontend/.env ]]; then
  echo "frontend/.env not found; copying the example"
  cp frontend/.env.example frontend/.env
fi

API_BASE="${VITE_API_BASE_URL:-http://localhost:8000}"

if [[ $SKIP_BACKEND_CHECK -eq 0 ]]; then
  if ! curl -fsS --max-time 3 "${API_BASE%/}/health" >/dev/null 2>&1; then
    echo "warning: no backend at ${API_BASE}." >&2
    echo "         The app will render with every panel in its error state." >&2
    echo "         Start one:  scripts/run_backend_dev.sh" >&2
  fi
fi

cd frontend
echo "serving on http://localhost:${PORT}  (API at ${API_BASE})"
# Passed through the environment so this matches run_frontend_dev.ps1,
# where the `--` form does not survive PowerShell argument parsing.
export VITE_DEV_PORT="$PORT"
exec npm run dev
