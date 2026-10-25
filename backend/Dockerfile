# syntax=docker/dockerfile:1

# =============================================================================
# MULEGUARD backend Dockerfile
# -----------------------------------------------------------------------------
# Build context expected:
#   muleguard/backend
#
# Example build:
#   DOCKER_BUILDKIT=1 docker build -f backend/Dockerfile -t muleguard/backend:latest backend
#
# Example development build with test/lint tools:
#   DOCKER_BUILDKIT=1 docker build \
#     -f backend/Dockerfile \
#     --build-arg INSTALL_DEV=true \
#     -t muleguard/backend:dev \
#     backend
#
# Design goals:
#   - Python 3.11 slim base
#   - Multi-stage build
#   - Non-root runtime user
#   - No secrets copied into image
#   - Deterministic runtime defaults
#   - Optional startup migrations
#   - Optional local synthetic/demo seeding with production safeguards
#   - Healthcheck without curl
#   - Safe fallback behaviour when optional modules are not present
#   - Minimal runtime OS packages
#   - BuildKit cache mounts for faster repeated builds
#
# Security notes:
#   - This image does not bake in .env files.
#   - Provide runtime configuration through environment variables or Docker secrets.
#   - For production-like deployments, disable demo seeding and development users.
#   - Pin the base image digest in regulated environments.
# =============================================================================


# -----------------------------------------------------------------------------
# Global build arguments
# -----------------------------------------------------------------------------
ARG PYTHON_VERSION=3.11


# -----------------------------------------------------------------------------
# Base image
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1


# -----------------------------------------------------------------------------
# Builder stage
# -----------------------------------------------------------------------------
FROM base AS builder

ARG INSTALL_DEV=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    gcc \
    g++ \
    libpq-dev \
    libssl-dev \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv

ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /build

# Copy dependency manifests first for better layer caching.
COPY requirements*.txt ./

RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --upgrade pip setuptools wheel \
    && if [ "${INSTALL_DEV}" = "true" ] && [ -f requirements-dev.txt ]; then \
    echo "Installing development dependencies..."; \
    python -m pip install -r requirements-dev.txt; \
    else \
    echo "Installing production dependencies..."; \
    python -m pip install -r requirements.txt; \
    fi


# -----------------------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------------------
FROM base AS runtime

ARG BUILD_DATE
ARG VCS_REF
ARG BUILD_VERSION=0.1.0
ARG UID=10001
ARG GID=10001

LABEL org.opencontainers.image.title="MULEGUARD Backend" \
    org.opencontainers.image.description="Synthetic-first financial fraud investigation prototype backend" \
    org.opencontainers.image.version="${BUILD_VERSION}" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.vendor="MULEGUARD Contributors" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.source="https://github.com/YOUR_ORG/muleguard" \
    org.opencontainers.image.documentation="https://github.com/YOUR_ORG/muleguard/blob/main/README.md" \
    ai.muleguard.data.classification="synthetic" \
    ai.muleguard.safety.production_ready="false" \
    ai.muleguard.safety.automatic_adverse_action="false"

# Runtime OS dependencies:
#   - ca-certificates: TLS trust store
#   - tzdata: timezone data
#   - libpq5: PostgreSQL client runtime
#   - libgomp1: OpenMP runtime used by some scientific wheels
#   - libssl3: TLS runtime used by Python/C extensions
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgomp1 \
    libpq5 \
    libssl3 \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Create non-root runtime user.
RUN groupadd --gid "${GID}" appgroup \
    && useradd \
    --uid "${UID}" \
    --gid appgroup \
    --shell /usr/sbin/nologin \
    --create-home \
    appuser

# Python and application runtime environment.
#
# These are safe local defaults. Override them at runtime through:
#   - docker compose environment
#   - --env-file
#   - Kubernetes ConfigMap/Secret
#   - platform secret manager
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH="/app" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=42 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    HOME=/home/appuser \
    TMPDIR=/app/var/tmp \
    XDG_CACHE_HOME=/app/var/cache \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 \
    BACKEND_HOST=0.0.0.0 \
    BACKEND_PORT=8000 \
    BACKEND_WORKERS=1 \
    BACKEND_APP_MODULE=app.main:app \
    BACKEND_HEALTHCHECK_URL=http://127.0.0.1:8000/health \
    BACKEND_ENV=local \
    BACKEND_DEBUG=false \
    BACKEND_SAFE_MODE=true \
    BACKEND_LOG_LEVEL=INFO \
    BACKEND_LOG_JSON=false \
    BACKEND_OPENAPI_ENABLED=true \
    BACKEND_DOCS_ENABLED=true \
    ALEMBIC_UPGRADE_ON_START=false \
    SEED_DEV_USERS=false \
    SEED_DEMO_DATA=false \
    ML_ARTIFACT_DIR=/app/app/ml/artifacts \
    REPORT_OUTPUT_DIR=/app/var/reports

WORKDIR /app

# Copy installed Python virtual environment from builder.
COPY --from=builder --chown=appuser:appgroup /opt/venv /opt/venv

# Copy backend application source.
#
# The backend/.dockerignore file should prevent local secrets, caches, tests,
# generated data, model binaries, and other non-runtime files from entering
# the build context.
COPY --chown=appuser:appgroup . .

# Create writable runtime directories for the non-root user.
RUN mkdir -p \
    /app/var/logs \
    /app/var/tmp \
    /app/var/cache \
    /app/var/reports \
    /app/var/runs \
    /app/var/exports \
    /app/app/ml/artifacts \
    && chown -R appuser:appgroup /app/var /app/app/ml/artifacts

# Remove files that should not normally be present in the runtime image.
# This is defensive and does not replace .dockerignore.
RUN rm -f \
    /app/Dockerfile \
    /app/.dockerignore \
    /app/docker-compose.yml \
    /app/docker-compose.override.yml

# -----------------------------------------------------------------------------
# Embedded entrypoint
# -----------------------------------------------------------------------------
# This entrypoint:
#   - refuses unsafe demo seeding in production-like environments
#   - refuses placeholder secrets in production-like environments
#   - creates writable runtime directories
#   - optionally runs Alembic migrations with retry
#   - optionally seeds development users and synthetic demo data locally
#   - execs the final container command
#
# If you prefer an external script, replace this COPY heredoc with:
#   COPY --chown=root:root docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# and keep the chmod line below.
COPY <<'EOF' /usr/local/bin/docker-entrypoint.sh
#!/bin/sh
set -eu

umask 027

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

is_production_like() {
    case "${BACKEND_ENV:-local}" in
        production|staging|prod|stage)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Production-like safety checks
# -----------------------------------------------------------------------------
if is_production_like; then
    if [ "${SEED_DEV_USERS:-false}" = "true" ]; then
        log "ERROR: SEED_DEV_USERS=true is not allowed in BACKEND_ENV=${BACKEND_ENV}."
        exit 1
    fi

    if [ "${SEED_DEMO_DATA:-false}" = "true" ]; then
        log "ERROR: SEED_DEMO_DATA=true is not allowed in BACKEND_ENV=${BACKEND_ENV}."
        exit 1
    fi

    if [ "${BACKEND_REQUIRE_STRONG_SECRET_IN_NON_LOCAL:-true}" = "true" ]; then
        secret=${BACKEND_SECRET_KEY:-}
        case "${secret}" in
            ""|*CHANGE_ME*|*change_me*|*placeholder*|*replace-me*|*replace_me*)
                log "ERROR: BACKEND_SECRET_KEY must be set to a strong non-placeholder value in BACKEND_ENV=${BACKEND_ENV}."
                exit 1
                ;;
        esac
    fi
fi

# -----------------------------------------------------------------------------
# Runtime directories
# -----------------------------------------------------------------------------
mkdir -p \
    /app/var/logs \
    /app/var/tmp \
    /app/var/cache \
    /app/var/reports \
    /app/var/runs \
    /app/var/exports \
    /app/app/ml/artifacts

# -----------------------------------------------------------------------------
# Optional database migrations
# -----------------------------------------------------------------------------
if [ "${ALEMBIC_UPGRADE_ON_START:-false}" = "true" ]; then
    log "Running Alembic migrations..."

    attempts=0
    max_attempts="${DB_CONNECTION_RETRIES:-5}"
    backoff="${DB_RETRY_BACKOFF_SECONDS:-2}"

    until python -m alembic upgrade head; do
        attempts=$((attempts + 1))

        if [ "${attempts}" -ge "${max_attempts}" ]; then
            log "ERROR: database migration failed after ${attempts} attempts."
            exit 1
        fi

        log "Migration attempt ${attempts} failed; retrying in ${backoff}s..."
        sleep "${backoff}"
    done

    log "Database migrations completed."
fi

# -----------------------------------------------------------------------------
# Optional development user seeding
# -----------------------------------------------------------------------------
if [ "${SEED_DEV_USERS:-false}" = "true" ]; then
    if python -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('app.auth.dev_users') else 1)"; then
        log "Seeding local development users..."
        python -m app.auth.dev_users
    else
        log "WARNING: app.auth.dev_users not found; skipping development user seeding."
    fi
fi

# -----------------------------------------------------------------------------
# Optional synthetic demo data seeding
# -----------------------------------------------------------------------------
if [ "${SEED_DEMO_DATA:-false}" = "true" ]; then
    if python -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('app.ingestion.seed') else 1)"; then
        log "Seeding synthetic demo data..."
        python -m app.ingestion.seed
    else
        log "WARNING: app.ingestion.seed not found; skipping synthetic demo seeding."
    fi
fi

log "Starting MULEGUARD backend..."
exec "$@"
EOF

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

# Drop root privileges.
USER appuser

# Application port.
EXPOSE 8000

# Graceful shutdown signal.
STOPSIGNAL SIGTERM

# Container healthcheck without curl.
# The start period allows migrations and optional local seeding to complete.
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=5 \
    CMD ["python", "-c", "import os, sys, urllib.request; url=os.environ.get('BACKEND_HEALTHCHECK_URL', 'http://127.0.0.1:8000/health'); r=urllib.request.urlopen(url, timeout=3); sys.exit(0 if r.status == 200 else 1)"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command.
#
# Uses python -m uvicorn so the command works even if the uvicorn console script
# is not directly on PATH.
CMD ["sh", "-c", "exec python -m uvicorn \"${BACKEND_APP_MODULE:-app.main:app}\" --host \"${BACKEND_HOST:-0.0.0.0}\" --port \"${BACKEND_PORT:-8000}\" --workers \"${BACKEND_WORKERS:-1}\""]