#!/usr/bin/env bash
# =============================================================================
# MULEGUARD backend Docker entrypoint
# -----------------------------------------------------------------------------
# Purpose:
#   Safe, production-aware container startup for the MULEGUARD FastAPI backend.
#
# Responsibilities:
#   - Validate runtime safety before starting the application
#   - Block synthetic/demo/development behaviour in production-like environments
#   - Detect placeholder secrets and fail closed when required
#   - Create required writable runtime directories
#   - Optionally wait for the database
#   - Optionally run Alembic migrations with retry and advisory locking
#   - Optionally seed local development users
#   - Optionally seed deterministic synthetic demo data
#   - Warn or fail based on ML artifact availability
#   - Start Uvicorn with safe defaults
#
# Product safety rules enforced here:
#   - MULEGUARD is synthetic-first by default
#   - Demo seeding and development users are local-only
#   - Production-like environments must not use placeholder secrets
#   - Production-like environments must not enable demo seeding
#   - Production-like environments must not enable remote debugging
#   - Missing ML artifacts must produce explicit fallback expectations,
#     not fabricated model claims
#
# Usage:
#   This script is intended to be used as the container ENTRYPOINT.
#
#   Example Dockerfile fragment:
#
#     COPY --chown=root:root docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
#     RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
#     ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
#
#   Default command:
#     Starts Uvicorn using BACKEND_APP_MODULE, BACKEND_HOST, BACKEND_PORT, etc.
#
#   Custom command:
#     docker run muleguard/backend python -m alembic current
#
# =============================================================================

set -Eeuo pipefail

# Improve error propagation in subshells when supported.
if [ -n "${BASH_VERSINFO:-}" ] && [ "${BASH_VERSINFO[0]}" -ge 4 ]; then
  shopt -s inherit_errexit 2>/dev/null || true
fi

readonly SCRIPT_NAME="${0##*/}"

# Restrictive default file creation mask.
# Runtime directories should still be writable by the application user.
umask 027


# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------

log() {
  local level="$1"
  shift
  printf '[%s] [%-6s] [%s] %s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    "$level" \
    "$SCRIPT_NAME" \
    "$*" >&2
}

log_info() {
  log INFO "$@"
}

log_warn() {
  log WARN "$@"
}

log_error() {
  log ERROR "$@"
}

log_fatal() {
  log FATAL "$@"
  exit 1
}


# -----------------------------------------------------------------------------
# Traps
# -----------------------------------------------------------------------------

trap '
  exit_code=$?
  if [ "$exit_code" -ne 0 ]; then
    log_error "MULEGUARD backend entrypoint failed (exit=${exit_code})"
  fi
' EXIT

trap '
  log_warn "Received SIGTERM during startup; exiting"
  exit 143
' TERM

trap '
  log_warn "Received SIGINT during startup; exiting"
  exit 130
' INT


# -----------------------------------------------------------------------------
# Boolean helpers
# -----------------------------------------------------------------------------

to_bool() {
  case "${1:-}" in
    true|TRUE|True|1|yes|YES|Yes|on|ON|On)
      printf 'true'
      ;;
    *)
      printf 'false'
      ;;
  esac
}

is_true() {
  [ "$(to_bool "${1:-}")" = "true" ]
}

is_false() {
  [ "$(to_bool "${1:-}")" = "false" ]
}


# -----------------------------------------------------------------------------
# Placeholder / weak secret detection
# -----------------------------------------------------------------------------
# This is intentionally conservative. It is not a replacement for a real secret
# scanner, but it prevents obvious template values from being used in
# non-local environments.
# -----------------------------------------------------------------------------

contains_placeholder() {
  local value="${1:-}"

  case "$value" in
    ""|\
    *CHANGE_ME*|\
    *change_me*|\
    *CHANGEME*|\
    *changeme*|\
    *PLACEHOLDER*|\
    *placeholder*|\
    *REPLACE_ME*|\
    *replace_me*|\
    *REPLACE-ME*|\
    *replace-me*|\
    *YOUR_*|\
    *your_*|\
    *EXAMPLE*|\
    *example*)
      return 0
      ;;
  esac

  return 1
}


# -----------------------------------------------------------------------------
# Environment classification
# -----------------------------------------------------------------------------

is_production_like() {
  local current="${BACKEND_ENV:-local}"
  local list="${BACKEND_PRODUCTION_LIKE_ENVS:-production,staging,prod,stage}"
  local env_name

  # Temporarily split on commas.
  local old_ifs="$IFS"
  IFS=','
  for env_name in $list; do
    IFS="$old_ifs"
    env_name="$(printf '%s' "$env_name" | tr -d '[:space:]')"
    if [ "$current" = "$env_name" ]; then
      return 0
    fi
    IFS=','
  done
  IFS="$old_ifs"

  return 1
}


# -----------------------------------------------------------------------------
# Required command checks
# -----------------------------------------------------------------------------

validate_required_commands() {
  local cmd

  for cmd in python date mkdir; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      log_fatal "Required command not found: ${cmd}"
    fi
  done

  if ! command -v flock >/dev/null 2>&1; then
    log_warn "flock not available; Alembic migration locking will be best-effort only"
  fi
}


# -----------------------------------------------------------------------------
# Runtime safety validation
# -----------------------------------------------------------------------------

validate_environment_safety() {
  local env_name="${BACKEND_ENV:-local}"

  # -------------------------------------------------------------------------
  # Production-like hard blocks
  # -------------------------------------------------------------------------
  if is_production_like; then
    log_info "Production-like environment detected: BACKEND_ENV=${env_name}"

    if is_true "${BACKEND_DEBUG:-false}"; then
      log_fatal "BACKEND_DEBUG=true is not allowed in production-like environments"
    fi

    if is_true "${SEED_DEV_USERS:-false}" && \
       is_true "${BACKEND_BLOCK_DEV_USERS_IN_PRODUCTION:-true}"; then
      log_fatal "SEED_DEV_USERS=true is not allowed in production-like environments"
    fi

    if is_true "${SEED_DEMO_DATA:-false}" && \
       is_true "${BACKEND_BLOCK_SEEDING_IN_PRODUCTION:-true}"; then
      log_fatal "SEED_DEMO_DATA=true is not allowed in production-like environments"
    fi

    if is_true "${AUTH_DEMO_MODE:-false}" && \
       is_true "${BACKEND_BLOCK_DEMO_FEATURES_IN_PRODUCTION:-true}"; then
      log_fatal "AUTH_DEMO_MODE=true is not allowed in production-like environments"
    fi

    if is_true "${BACKEND_OPENAPI_ENABLED:-true}" && \
       is_true "${BACKEND_BLOCK_OPENAPI_IN_PRODUCTION:-true}"; then
      log_fatal "BACKEND_OPENAPI_ENABLED=true is not allowed in production-like environments unless explicitly overridden"
    fi

    if is_true "${BACKEND_DOCS_ENABLED:-true}" && \
       is_true "${BACKEND_BLOCK_OPENAPI_IN_PRODUCTION:-true}"; then
      log_fatal "BACKEND_DOCS_ENABLED=true is not allowed in production-like environments unless explicitly overridden"
    fi

    if is_true "${REMOTE_DEBUGGING_ENABLED:-false}" || \
       is_true "${DEBUGPY_ENABLED:-false}"; then
      log_fatal "Remote debugging is not allowed in production-like environments"
    fi
  fi

  # -------------------------------------------------------------------------
  # Non-local secret strength requirements
  # -------------------------------------------------------------------------
  if [ "$env_name" != "local" ] && \
     is_true "${BACKEND_REQUIRE_STRONG_SECRET_IN_NON_LOCAL:-true}"; then

    if contains_placeholder "${BACKEND_SECRET_KEY:-}"; then
      log_fatal "BACKEND_SECRET_KEY must be set to a strong non-placeholder value in non-local environments"
    fi

    if [ -n "${DATABASE_URL:-}" ] && contains_placeholder "${DATABASE_URL:-}"; then
      log_fatal "DATABASE_URL contains a placeholder value and must be replaced in non-local environments"
    fi

    if [ -n "${POSTGRES_PASSWORD:-}" ] && contains_placeholder "${POSTGRES_PASSWORD:-}"; then
      log_fatal "POSTGRES_PASSWORD contains a placeholder value and must be replaced in non-local environments"
    fi
  fi

  # -------------------------------------------------------------------------
  # Local-only warnings
  # -------------------------------------------------------------------------
  if [ "$env_name" = "local" ]; then
    if contains_placeholder "${BACKEND_SECRET_KEY:-}"; then
      log_warn "BACKEND_SECRET_KEY is missing or uses a placeholder value. This is allowed only for local synthetic development."
    fi

    if is_true "${SEED_DEMO_DATA:-false}" || is_true "${SEED_DEV_USERS:-false}"; then
      log_warn "Local synthetic/demo mode is enabled. Do not expose this container publicly."
    fi
  fi

  # -------------------------------------------------------------------------
  # Defensive check: accidental .env file inside image
  # -------------------------------------------------------------------------
  if [ -f ".env" ]; then
    if is_true "${BACKEND_FAIL_ON_ENV_FILE_IN_IMAGE:-false}"; then
      log_fatal "A .env file was found inside the container filesystem. Secrets must be provided through runtime environment variables or a secret manager."
    else
      log_warn "A .env file was found inside the container filesystem. This is discouraged; prefer runtime environment variables or Docker secrets."
    fi
  fi
}


# -----------------------------------------------------------------------------
# Development password validation
# -----------------------------------------------------------------------------
# If development user seeding is enabled, passwords must come from environment
# configuration. This prevents accidental use of template passwords.
# -----------------------------------------------------------------------------

validate_dev_passwords_if_seeding() {
  if ! is_true "${SEED_DEV_USERS:-false}"; then
    return 0
  fi

  local var
  local value
  local found_any=false

  for var in \
    DEV_ADMIN_PASSWORD \
    DEV_ANALYST_PASSWORD \
    DEV_SENIOR_INVESTIGATOR_PASSWORD \
    DEV_AUDITOR_PASSWORD
  do
    value="${!var:-}"

    if [ -n "$value" ]; then
      found_any=true

      if contains_placeholder "$value"; then
        log_fatal "${var} contains a placeholder value. Development user passwords must be supplied through environment configuration."
      fi
    fi
  done

  if [ "$found_any" != "true" ]; then
    log_fatal "SEED_DEV_USERS=true requires at least one DEV_*_PASSWORD environment variable to be set. Do not use hardcoded development passwords."
  fi
}


# -----------------------------------------------------------------------------
# Runtime directory preparation
# -----------------------------------------------------------------------------

prepare_runtime_directories() {
  local var_dir="${VAR_DIR:-var}"
  local report_dir="${REPORT_OUTPUT_DIR:-${var_dir}/reports}"
  local ml_dir="${ML_ARTIFACT_DIR:-app/ml/artifacts}"

  local dirs=(
    "${var_dir}"
    "${var_dir}/logs"
    "${var_dir}/tmp"
    "${var_dir}/cache"
    "${var_dir}/runs"
    "${var_dir}/exports"
    "${report_dir}"
    "${ml_dir}"
  )

  local dir
  for dir in "${dirs[@]}"; do
    if ! mkdir -p "$dir"; then
      log_fatal "Unable to create runtime directory: ${dir}"
    fi
  done

  # Optional ownership correction when the entrypoint is run as root before
  # privilege dropping. In the recommended Dockerfile, the container already
  # runs as a non-root user, so this is usually a no-op.
  if [ "$(id -u)" = "0" ] && [ -n "${RUNTIME_USER:-}" ]; then
    local owner="${RUNTIME_USER}:${RUNTIME_GROUP:-${RUNTIME_USER}}"
    for dir in "${dirs[@]}"; do
      chown -R "$owner" "$dir" 2>/dev/null || log_warn "Unable to chown ${dir} to ${owner}"
    done
  fi

  if [ "$(id -u)" = "0" ]; then
    log_warn "Entrypoint is running as root. Production images should drop privileges to a non-root user."
  fi
}


# -----------------------------------------------------------------------------
# Python module existence check
# -----------------------------------------------------------------------------

module_exists() {
  local module_name="$1"

  python - "$module_name" <<'PY' >/dev/null 2>&1
import importlib.util
import sys

module_name = sys.argv[1]
sys.exit(0 if importlib.util.find_spec(module_name) else 1)
PY
}


# -----------------------------------------------------------------------------
# Database readiness wait
# -----------------------------------------------------------------------------
# This performs a lightweight TCP reachability check. It does not execute SQL.
# Actual authentication and schema correctness are validated by Alembic or the
# application during startup.
# -----------------------------------------------------------------------------

wait_for_database() {
  if is_true "${SKIP_DB_WAIT:-false}"; then
    log_warn "SKIP_DB_WAIT=true; skipping database readiness wait"
    return 0
  fi

  python <<'PY'
import os
import socket
import sys
import time
import urllib.parse


def log(level: str, message: str) -> None:
    print(f"[{level}] [docker-entrypoint] {message}", file=sys.stderr)


def parse_target() -> tuple[str, int] | None:
    url = os.getenv("DATABASE_URL", "").strip()

    if url:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.split("+", 1)[0].lower()

        if scheme in {"sqlite", "aiosqlite"}:
            return None

        host = parsed.hostname
        if not host:
            return None

        default_port = 5432 if scheme in {"postgresql", "postgres"} else 5432
        port = parsed.port or default_port
        return host, port

    # Fallback to explicit POSTGRES_* variables.
    host = os.getenv("POSTGRES_HOST", "").strip()
    if not host:
        return None

    try:
        port = int(os.getenv("POSTGRES_PORT", "5432"))
    except ValueError:
        port = 5432

    return host, port


def main() -> int:
    target = parse_target()
    if target is None:
        log("INFO", "No TCP database target detected; skipping database wait")
        return 0

    host, port = target

    try:
        retries = int(os.getenv("DB_CONNECTION_RETRIES", "10"))
    except ValueError:
        retries = 10

    try:
        backoff = float(os.getenv("DB_RETRY_BACKOFF_SECONDS", "2"))
    except ValueError:
        backoff = 2.0

    try:
        timeout = float(os.getenv("DB_CONNECT_TIMEOUT_SECONDS", "5"))
    except ValueError:
        timeout = 5.0

    retries = max(1, retries)
    backoff = max(0.1, backoff)
    timeout = max(0.1, timeout)

    for attempt in range(1, retries + 1):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                log("INFO", f"Database TCP endpoint reachable: host={host} port={port}")
                return 0
        except OSError as exc:
            if attempt >= retries:
                log("ERROR", f"Database unreachable after {attempt} attempts: {exc}")
                return 1

            delay = min(backoff * attempt, 30.0)
            log(
                "WARN",
                f"Database not ready attempt={attempt}/{retries} host={host} port={port}; retrying in {delay:.1f}s"
            )
            time.sleep(delay)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
PY
}


# -----------------------------------------------------------------------------
# Alembic migration helpers
# -----------------------------------------------------------------------------

perform_migrations_with_retry() {
  local config="${ALEMBIC_CONFIG_PATH:-alembic.ini}"
  local attempts="${DB_CONNECTION_RETRIES:-5}"
  local backoff="${DB_RETRY_BACKOFF_SECONDS:-2}"
  local attempt

  # Ensure numeric values are sane.
  attempts="${attempts%%.*}"
  backoff="${backoff%%.*}"

  if ! [[ "$attempts" =~ ^[0-9]+$ ]] || [ "$attempts" -lt 1 ]; then
    attempts=5
  fi

  if ! [[ "$backoff" =~ ^[0-9]+$ ]] || [ "$backoff" -lt 1 ]; then
    backoff=2
  fi

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    log_info "Running Alembic migrations attempt=${attempt}/${attempts} config=${config}"

    if python -m alembic -c "$config" upgrade head; then
      log_info "Alembic migrations completed successfully"
      return 0
    fi

    if [ "$attempt" -lt "$attempts" ]; then
      log_warn "Alembic migration attempt ${attempt} failed; retrying in ${backoff}s"
      sleep "$backoff"
    fi
  done

  log_fatal "Alembic migrations failed after ${attempts} attempts"
}

run_alembic_migrations() {
  if ! is_true "${ALEMBIC_UPGRADE_ON_START:-false}"; then
    log_info "ALEMBIC_UPGRADE_ON_START=false; skipping migrations"
    return 0
  fi

  local config="${ALEMBIC_CONFIG_PATH:-alembic.ini}"

  if [ ! -f "$config" ]; then
    log_fatal "Alembic configuration file not found: ${config}"
  fi

  wait_for_database

  if command -v flock >/dev/null 2>&1 && is_true "${DB_MIGRATION_LOCK_ENABLED:-true}"; then
    local lock_file="${VAR_DIR:-var}/alembic.lock"
    local lock_timeout="${DB_MIGRATION_LOCK_TIMEOUT_SECONDS:-60}"

    mkdir -p "$(dirname "$lock_file")"

    log_info "Acquiring Alembic migration lock: ${lock_file}"

    (
      exec 9>"$lock_file"

      if ! flock -w "$lock_timeout" 9; then
        exit 99
      fi

      perform_migrations_with_retry
    )

    local status=$?

    case "$status" in
      0)
        log_info "Alembic migration lock released"
        ;;
      99)
        log_fatal "Unable to acquire Alembic migration lock within ${lock_timeout}s"
        ;;
      *)
        log_fatal "Alembic migrations failed while holding migration lock"
        ;;
    esac
  else
    log_warn "Running Alembic migrations without advisory locking. Ensure only one instance performs migrations concurrently."
    perform_migrations_with_retry
  fi
}


# -----------------------------------------------------------------------------
# Reference data bootstrap
# -----------------------------------------------------------------------------
# This is optional. The preferred path is for reference data to be seeded by
# Alembic migration 0002_seed_roles_and_reference_data.py. This hook exists for
# projects that expose an idempotent bootstrap module.
# -----------------------------------------------------------------------------

seed_reference_data_if_enabled() {
  if ! is_true "${ALEMBIC_SEED_REFERENCE_DATA:-false}"; then
    return 0
  fi

  if module_exists app.bootstrap; then
    log_info "Running idempotent reference-data bootstrap module: app.bootstrap"
    python -m app.bootstrap
  else
    log_warn "ALEMBIC_SEED_REFERENCE_DATA=true but app.bootstrap module was not found. Ensure reference data is seeded by migration instead."
  fi
}


# -----------------------------------------------------------------------------
# Development user seeding
# -----------------------------------------------------------------------------

seed_dev_users_if_enabled() {
  if ! is_true "${SEED_DEV_USERS:-false}"; then
    return 0
  fi

  if is_production_like; then
    log_fatal "SEED_DEV_USERS=true is not allowed in production-like environments"
  fi

  validate_dev_passwords_if_seeding

  if module_exists app.auth.dev_users; then
    log_info "Seeding local development users"
    python -m app.auth.dev_users
  else
    log_warn "SEED_DEV_USERS=true but app.auth.dev_users module was not found"
  fi
}


# -----------------------------------------------------------------------------
# Synthetic demo data seeding
# -----------------------------------------------------------------------------

seed_demo_data_if_enabled() {
  if ! is_true "${SEED_DEMO_DATA:-false}"; then
    return 0
  fi

  if is_production_like; then
    log_fatal "SEED_DEMO_DATA=true is not allowed in production-like environments"
  fi

  if module_exists app.ingestion.seed; then
    log_info "Seeding deterministic synthetic demo data"
    python -m app.ingestion.seed
  else
    log_warn "SEED_DEMO_DATA=true but app.ingestion.seed module was not found"
  fi
}


# -----------------------------------------------------------------------------
# ML artifact preflight
# -----------------------------------------------------------------------------
# This does not load model binaries. It only checks whether a controlled local
# artifact appears to exist so that the startup logs can accurately describe
# expected fallback behaviour.
# -----------------------------------------------------------------------------

preflight_ml_artifact() {
  local artifact_dir="${ML_ARTIFACT_DIR:-app/ml/artifacts}"
  local artifact_format="${ML_ARTIFACT_FORMAT:-joblib}"
  local has_artifact=false

  if [ -d "$artifact_dir" ]; then
    if find "$artifact_dir" -maxdepth 1 -type f -name "*.${artifact_format}" -print -quit 2>/dev/null | grep -q .; then
      has_artifact=true
    fi
  fi

  if is_true "${ML_REQUIRE_TRAINED_MODEL:-false}"; then
    if [ "$has_artifact" != "true" ]; then
      log_fatal "ML_REQUIRE_TRAINED_MODEL=true but no .${artifact_format} artifact was found under ${artifact_dir}"
    fi

    log_info "Trained ML artifact detected under ${artifact_dir}"
  else
    if [ "$has_artifact" != "true" ] && is_true "${ML_WARN_ON_MISSING_ML_ARTIFACT:-true}"; then
      log_warn "No trained ML artifact detected under ${artifact_dir}. The application is expected to run in explicit fallback mode, such as scoring_mode=heuristic_fallback, if supported."
    elif [ "$has_artifact" = "true" ]; then
      log_info "Trained ML artifact detected under ${artifact_dir}"
    fi
  fi
}


# -----------------------------------------------------------------------------
# Startup banner
# -----------------------------------------------------------------------------

print_startup_banner() {
  log_info "MULEGUARD backend entrypoint starting"
  log_info "BACKEND_ENV=${BACKEND_ENV:-local}"
  log_info "BACKEND_DEBUG=${BACKEND_DEBUG:-false}"
  log_info "BACKEND_APP_MODULE=${BACKEND_APP_MODULE:-app.main:app}"
  log_info "BACKEND_HOST=${BACKEND_HOST:-0.0.0.0}"
  log_info "BACKEND_PORT=${BACKEND_PORT:-8000}"
  log_info "ALEMBIC_UPGRADE_ON_START=${ALEMBIC_UPGRADE_ON_START:-false}"
  log_info "SEED_DEV_USERS=${SEED_DEV_USERS:-false}"
  log_info "SEED_DEMO_DATA=${SEED_DEMO_DATA:-false}"
  log_info "ML_REQUIRE_TRAINED_MODEL=${ML_REQUIRE_TRAINED_MODEL:-false}"

  if is_production_like; then
    log_warn "Production-like mode is active. Synthetic demo seeding, development users, placeholder secrets, and remote debugging are blocked."
  else
    log_warn "SYNTHETIC DEMO MODE: This prototype is not production-ready. Alerts, risk scores, graph relationships, candidate money trails, and complaint correlations are investigative leads only."
  fi
}


# -----------------------------------------------------------------------------
# Final command construction
# -----------------------------------------------------------------------------

exec_default_command() {
  local app_module="${BACKEND_APP_MODULE:-app.main:app}"
  local host="${BACKEND_HOST:-0.0.0.0}"
  local port="${BACKEND_PORT:-8000}"
  local workers="${BACKEND_WORKERS:-1}"
  local keep_alive="${BACKEND_KEEP_ALIVE_TIMEOUT_SECONDS:-5}"
  local graceful_timeout="${BACKEND_GRACEFUL_TIMEOUT_SECONDS:-20}"
  local log_level
  local -a uvicorn_args

  log_level="${BACKEND_UVICORN_LOG_LEVEL:-${BACKEND_LOG_LEVEL:-info}}"
  log_level="$(printf '%s' "$log_level" | tr '[:upper:]' '[:lower:]')"

  uvicorn_args=(
    "--host" "$host"
    "--port" "$port"
    "--workers" "$workers"
    "--timeout-keep-alive" "$keep_alive"
    "--graceful-timeout" "$graceful_timeout"
    "--log-level" "$log_level"
  )

  if is_true "${BACKEND_TRUST_PROXY_HEADERS:-false}"; then
    uvicorn_args+=("--proxy-headers")
  fi

  if [ -n "${BACKEND_FORWARDED_ALLOW_IPS:-}" ]; then
    uvicorn_args+=("--forwarded-allow-ips" "$BACKEND_FORWARDED_ALLOW_IPS")
  fi

  if [ -n "${BACKEND_ROOT_PATH:-}" ]; then
    uvicorn_args+=("--root-path" "$BACKEND_ROOT_PATH")
  fi

  if is_false "${ACCESS_LOG_ENABLED:-true}"; then
    uvicorn_args+=("--no-access-log")
  fi

  if [ -n "${UVICORN_LIMIT_CONCURRENCY:-}" ] && [ "${UVICORN_LIMIT_CONCURRENCY:-0}" != "0" ]; then
    uvicorn_args+=("--limit-concurrency" "$UVICORN_LIMIT_CONCURRENCY")
  fi

  log_info "Starting Uvicorn: module=${app_module} host=${host} port=${port} workers=${workers}"

  exec python -m uvicorn "$app_module" "${uvicorn_args[@]}"
}


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
  validate_required_commands
  validate_environment_safety
  prepare_runtime_directories
  print_startup_banner

  if is_true "${SKIP_STARTUP_TASKS:-false}"; then
    log_warn "SKIP_STARTUP_TASKS=true; skipping migrations, seeding, and ML preflight"
  else
    preflight_ml_artifact
    run_alembic_migrations
    seed_reference_data_if_enabled
    seed_dev_users_if_enabled
    seed_demo_data_if_enabled
  fi

  if [ "$#" -gt 0 ]; then
    log_info "Executing custom container command: $*"
    exec "$@"
  fi

  exec_default_command
}

main "$@"