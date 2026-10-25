#!/usr/bin/env bash
#
# Check that a deployed backend actually works, not just that it answers.
#
#   scripts/smoke_test.sh
#   scripts/smoke_test.sh --base-url https://muleguard.example.internal
#
# Eleven checks, in the order a problem is most likely to be found. Each prints
# pass or fail and the whole script exits non-zero if any failed, so it works
# as a deployment gate.
#
# Authenticated checks need MULEGUARD_ADMIN_PASSWORD. Without it the public
# checks still run and the rest are reported as skipped rather than passed --
# a smoke test that silently skips most of itself is worse than no smoke test.
set -uo pipefail

cd "$(dirname "$0")/.."

BASE_URL="${MULEGUARD_BASE_URL:-http://localhost:8000}"
BASE_URL="${BASE_URL%/}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE_URL="${2%/}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

PASSED=0
FAILED=0
SKIPPED=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASSED=$((PASSED + 1)); }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [[ -n "${2:-}" ]] && printf '        %s\n' "$2"; FAILED=$((FAILED + 1)); }
skip() { printf '  \033[33mSKIP\033[0m  %s\n' "$1"; [[ -n "${2:-}" ]] && printf '        %s\n' "$2"; SKIPPED=$((SKIPPED + 1)); }

json_field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)" 2>/dev/null; }

echo "smoke test: ${BASE_URL}"
echo

# 1. The process is up.
if BODY=$(curl -fsS --max-time 10 "${BASE_URL}/health" 2>&1); then
  pass "liveness"
else
  fail "liveness" "$BODY"
  echo
  echo "Nothing else can pass. Stopping."
  exit 1
fi

# 2. Dependencies are up. A process that is listening is not a backend that
#    can serve a request, and this is the check that tells them apart.
if BODY=$(curl -fsS --max-time 15 "${BASE_URL}/api/v1/health/ready" 2>&1); then
  if [[ "$(printf '%s' "$BODY" | json_field '["ready"]')" == "True" ]]; then
    pass "readiness (database reachable)"
  else
    fail "readiness" "$(printf '%s' "$BODY" | head -c 400)"
  fi
else
  fail "readiness" "$BODY"
fi

# 3. The synthetic banner. If this is missing, something has been configured to
#    look like a production system, which is the one claim this prototype must
#    never make.
if BODY=$(curl -fsS --max-time 10 "${BASE_URL}/api/v1/health" 2>&1); then
  CLASSIFICATION=$(printf '%s' "$BODY" | json_field '["data_classification"]')
  PRODUCTION=$(printf '%s' "$BODY" | json_field '["production_ready"]')

  if [[ "$CLASSIFICATION" == "synthetic" && "$PRODUCTION" == "False" ]]; then
    pass "declares itself synthetic and not production-ready"
  else
    fail "synthetic banner" "classification=${CLASSIFICATION} production_ready=${PRODUCTION}"
  fi
else
  fail "synthetic banner" "$BODY"
fi

# 4. The schema generates. Catches a duplicated operation_id or an unresolved
#    forward reference, which otherwise surface as a 500 the first time
#    somebody opens the docs.
if curl -fsS --max-time 20 "${BASE_URL}/api/v1/openapi.json" >/dev/null 2>&1; then
  pass "OpenAPI schema generates"
else
  fail "OpenAPI schema generates"
fi

# 5. Protected endpoints are protected.
STATUS=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${BASE_URL}/api/v1/accounts")
if [[ "$STATUS" == "401" ]]; then
  pass "unauthenticated request is refused (401)"
else
  fail "unauthenticated request is refused" "got HTTP ${STATUS}, expected 401"
fi

# 6. The error envelope. A client writes one reader for it.
if BODY=$(curl -s --max-time 10 "${BASE_URL}/api/v1/accounts" 2>&1); then
  CODE=$(printf '%s' "$BODY" | json_field '["code"]')
  if [[ "$CODE" == MULEGUARD_* ]]; then
    pass "error envelope is flat and namespaced (${CODE})"
  else
    fail "error envelope" "$(printf '%s' "$BODY" | head -c 300)"
  fi
else
  fail "error envelope" "$BODY"
fi

# 7. Request ids come back. This is the thread between a screenshot, a log
#    line and an audit row.
RID="smoke-$(date +%s)"
RETURNED=$(curl -s -o /dev/null -D - --max-time 10 -H "X-Request-ID: ${RID}" \
  "${BASE_URL}/api/v1/accounts" 2>/dev/null | tr -d '\r' \
  | awk 'tolower($1) == "x-request-id:" { print $2 }')
if [[ "$RETURNED" == "$RID" ]]; then
  pass "X-Request-ID is echoed"
else
  fail "X-Request-ID is echoed" "sent ${RID}, got ${RETURNED:-nothing}"
fi

if [[ -z "${MULEGUARD_ADMIN_PASSWORD:-}" ]]; then
  echo
  skip "authenticated checks" "MULEGUARD_ADMIN_PASSWORD is not set"
  skip "login"
  skip "a list endpoint returns the pagination envelope"
  skip "a scored response carries its caveats"
  skip "the model endpoint states its limitations"
else
  echo

  # 8. Login.
  LOGIN=$(curl -s --max-time 15 -X POST "${BASE_URL}/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"identifier\":\"${MULEGUARD_ADMIN_USER:-admin}\",\"password\":\"${MULEGUARD_ADMIN_PASSWORD}\"}")
  TOKEN=$(printf '%s' "$LOGIN" | json_field '["access_token"]')

  if [[ -n "$TOKEN" ]]; then
    pass "login"
  else
    fail "login" "$(printf '%s' "$LOGIN" | json_field '["message"]')"
    TOKEN=""
  fi

  if [[ -n "$TOKEN" ]]; then
    AUTH=(-H "Authorization: Bearer ${TOKEN}")

    # 9. The pagination envelope, on a real list endpoint.
    if BODY=$(curl -fsS --max-time 20 "${AUTH[@]}" "${BASE_URL}/api/v1/accounts?page_size=1" 2>&1); then
      TOTAL=$(printf '%s' "$BODY" | json_field '["total"]')
      if [[ -n "$TOTAL" ]]; then
        pass "a list endpoint returns the pagination envelope (total=${TOTAL})"
      else
        fail "pagination envelope" "$(printf '%s' "$BODY" | head -c 300)"
      fi
    else
      fail "pagination envelope" "$BODY"
    fi

    # 10. Caveats travel with the data. The platform's position is that its
    #     output is a lead rather than a finding, and the caveat list is how
    #     that travels.
    if BODY=$(curl -fsS --max-time 20 "${AUTH[@]}" "${BASE_URL}/api/v1/dashboard/overview" 2>&1); then
      COUNT=$(printf '%s' "$BODY" | json_field '["caveats"].__len__()')
      if [[ -n "$COUNT" && "$COUNT" -gt 0 ]]; then
        pass "a scored response carries its caveats (${COUNT})"
      else
        fail "caveats" "the dashboard published none"
      fi
    else
      fail "caveats" "$BODY"
    fi

    # 11. The model says what it cannot do.
    if BODY=$(curl -fsS --max-time 20 "${AUTH[@]}" "${BASE_URL}/api/v1/model/limitations" 2>&1); then
      if printf '%s' "$BODY" | grep -qi 'synthetic'; then
        pass "the model endpoint states its limitations"
      else
        fail "model limitations" "no mention of synthetic data"
      fi
    else
      fail "model limitations" "$BODY"
    fi
  fi
fi

echo
echo "${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped"

if [[ $FAILED -gt 0 ]]; then
  exit 1
fi

if [[ $SKIPPED -gt 0 ]]; then
  echo
  echo "Some checks were skipped. Set MULEGUARD_ADMIN_PASSWORD to run them."
fi
