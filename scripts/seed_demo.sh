#!/usr/bin/env bash
#
# Load a dataset into a running backend, in dependency order.
#
#   scripts/seed_demo.sh                              # the checked-in samples
#   scripts/seed_demo.sh --from data/generated/run-42 # a generated dataset
#   scripts/seed_demo.sh --generate 500               # generate, then load
#
# A thin wrapper over scripts/import_json.py, which does the ordering, the
# login and the count arithmetic. This script adds the two things a demo needs:
# generating a dataset first, and running an analysis pass afterwards so the
# dashboard has something on it.
#
# Needs MULEGUARD_ADMIN_PASSWORD in the environment. Ingestion is admin-only.
set -euo pipefail

cd "$(dirname "$0")/.."

FROM="data/samples"
GENERATE=""
BASE_URL="${MULEGUARD_BASE_URL:-http://localhost:8000}"
ANALYSE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM="$2"; shift 2 ;;
    --generate) GENERATE="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --no-analyse|--no-analyze) ANALYSE=0; shift ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

if [[ -z "${MULEGUARD_ADMIN_PASSWORD:-}" ]]; then
  echo "MULEGUARD_ADMIN_PASSWORD is not set." >&2
  echo "Ingestion is admin-only. Set it in your shell:" >&2
  echo "  export MULEGUARD_ADMIN_PASSWORD='...'" >&2
  exit 1
fi

scripts/wait_for_backend.sh --url "$BASE_URL"

if [[ -n "$GENERATE" ]]; then
  FROM="data/generated/demo-${GENERATE}"
  echo
  python3 scripts/generate_data.py \
    --accounts "$GENERATE" \
    --transactions "$(( GENERATE * 40 ))" \
    --complaints "$(( GENERATE / 4 ))" \
    --out "$FROM"
fi

echo
python3 scripts/import_json.py --dir "$FROM" --base-url "$BASE_URL"

if [[ $ANALYSE -eq 0 ]]; then
  echo
  echo "skipped the analysis pass. Nothing is scored, so the dashboard and the"
  echo "alert queue will be empty -- which is correct, not broken."
  exit 0
fi

echo
echo "running an analysis pass so there is something to look at"

TOKEN=$(curl -fsS -X POST "${BASE_URL%/}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"identifier\":\"${MULEGUARD_ADMIN_USER:-admin}\",\"password\":\"${MULEGUARD_ADMIN_PASSWORD}\"}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

# The run has to name the accounts it covers.
#
# An empty body asks for all-account selection, which the API refuses unless
# ANALYSIS_ALLOW_ALL_ACCOUNTS=true. That refusal is the product working as
# designed -- analysis is bounded on purpose, the same way graph traversal
# requires a root and refuses whole-bank queries. A demo script is the wrong
# place to switch a safety bound off, so it enumerates the accounts instead and
# asks for a scope it can state.
ACCOUNT_IDS_JSON=$(
  curl -fsS -H "Authorization: Bearer ${TOKEN}" \
    "${BASE_URL%/}/api/v1/accounts?page=1&page_size=200" \
  | python3 -c '
import json, sys
listing = json.load(sys.stdin)
ids = [item["id"] for item in listing.get("items", [])][:1000]
if not ids:
    sys.stderr.write("No accounts to analyse. Load data first.\n")
    raise SystemExit(1)
total = listing.get("total", len(ids))
if total > len(ids):
    sys.stderr.write(f"  scoring the first {len(ids)} of {total} accounts (bounded run)\n")
else:
    sys.stderr.write(f"  scoring {len(ids)} accounts\n")
print(json.dumps({"account_ids": ids}))
'
)

# Synchronous, so when this returns the dashboard is populated.
curl -fsS -X POST "${BASE_URL%/}/api/v1/analysis/runs" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "${ACCOUNT_IDS_JSON}" \
  | python3 -c '
import json, sys
run = json.load(sys.stdin)
print(f"  run {run[\"id\"]}: {run[\"status\"]}")
print(f"  {run.get(\"account_count\", 0)} accounts, {run.get(\"assessment_count\", 0)} assessments")
for caveat in (run.get("caveats") or [])[:3]:
    print(f"  - {caveat}")
'

echo
echo "done. Open the dashboard, or:"
echo "  curl -H \"Authorization: Bearer \$TOKEN\" ${BASE_URL%/}/api/v1/alerts | jq"
