#!/usr/bin/env bash
#
# Drop the demo data and start again.
#
#   scripts/reset_demo.sh                 # asks first
#   scripts/reset_demo.sh --yes           # does not ask
#   scripts/reset_demo.sh --yes --reseed   # drop, migrate, seed
#
# Destroys every row in the database the backend is configured to use. There is
# no selective version: a half-reset database is worse than either state,
# because the accounts that survive are referenced by transactions that did
# not.
#
# Refuses to run when BACKEND_ENV looks deployed. The check is on the
# environment name rather than a flag, because a flag is the thing somebody
# passes by accident.
set -euo pipefail

cd "$(dirname "$0")/.."

CONFIRMED=0
RESEED=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) CONFIRMED=1; shift ;;
    --reseed) RESEED=1; shift ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

ENVIRONMENT=$(cd backend && python3 -c '
from app.core.config import get_settings
print(str(getattr(get_settings(), "BACKEND_ENV", "local") or "local").lower())
' 2>/dev/null || echo "unknown")

case "$ENVIRONMENT" in
  production|prod|staging|stage|uat|preprod)
    echo "Refusing to run: BACKEND_ENV is '${ENVIRONMENT}'." >&2
    echo "This drops every row. If you really mean it, do it deliberately with" >&2
    echo "your database tooling rather than with a script called reset_demo." >&2
    exit 1
    ;;
esac

TARGET=$(cd backend && python3 -c '
from app.core.config import get_settings
url = str(get_settings().DATABASE_URL)
# Print the host and database only. A URL with a password in it should not be
# echoed to a terminal, let alone into a CI log.
import re
match = re.search(r"@([^/]+)/([^?]+)", url)
print(f"{match.group(1)}/{match.group(2)}" if match else "(local file)")
' 2>/dev/null || echo "(unknown)")

echo "environment: ${ENVIRONMENT}"
echo "target:      ${TARGET}"

if [[ $CONFIRMED -eq 0 ]]; then
  printf 'Drop every row? Type the environment name to confirm: '
  read -r REPLY
  if [[ "$REPLY" != "$ENVIRONMENT" ]]; then
    echo "not confirmed; nothing was changed"
    exit 1
  fi
fi

cd backend

echo "downgrading to base"
alembic downgrade base

echo "upgrading to head"
alembic upgrade head

cd ..

if [[ $RESEED -eq 1 ]]; then
  echo
  if [[ -z "${MULEGUARD_DEV_PASSWORD:-}${MULEGUARD_ADMIN_PASSWORD:-}" ]]; then
    echo "skipping users and seed: no password in the environment." >&2
    echo "Set MULEGUARD_DEV_PASSWORD, then:" >&2
    echo "  python3 scripts/create_dev_users.py && scripts/seed_demo.sh" >&2
    exit 1
  fi

  python3 scripts/create_dev_users.py
  echo
  scripts/seed_demo.sh
else
  echo
  echo "database is empty. Next:"
  echo "  python3 scripts/create_dev_users.py"
  echo "  scripts/seed_demo.sh"
fi
