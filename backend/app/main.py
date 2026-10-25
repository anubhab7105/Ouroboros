"""
MULEGUARD backend FastAPI application entrypoint.

This module is responsible for:

- creating the FastAPI application instance;
- loading typed runtime configuration;
- configuring structured logging;
- enforcing local/production safety boundaries;
- registering middleware for request IDs, security headers, CORS, compression,
  trusted hosts, and performance instrumentation;
- registering the versioned `/api/v1` router;
- exposing a safe root liveness endpoint;
- performing optional startup checks for database connectivity and ML artifact
  availability;
- ensuring graceful degradation when optional ML artifacts are unavailable;
- shutting down database resources cleanly.

Important product-safety rules:

- MULEGUARD is a synthetic-first academic / hackathon-grade prototype.
- It is not production-ready.
- It must not process real customer data by default.
- It must not implement automatic adverse customer action.
- Alerts, risk scores, graph relationships, candidate money trails, and
  complaint correlations are investigative leads only.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import API_PREFIX, APP_NAME, DATA_CLASSIFICATION, __version__
from app.api.error_handlers import register_exception_handlers
from app.api.middleware.performance import PerformanceMiddleware
from app.api.middleware.request_id import RequestIdMiddleware
from app.api.middleware.security_headers import SecurityHeadersMiddleware
from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.db import engine

_LOGGER_NAME: Final[str] = "muleguard.backend"

_STARTUP_BANNER: Final[str] = (
    "MULEGUARD backend starting. "
    "Synthetic-first prototype only. "
    "Alerts, scores, graph relationships, candidate money trails, and "
    "complaint correlations are investigative leads, not proof of wrongdoing."
)

_PLACEHOLDER_MARKERS: Final[tuple[str, ...]] = (
    "change_me",
    "changeme",
    "placeholder",
    "replace_me",
    "replace-me",
    "your_",
    "example_",
    "todo",
    "fixme",
)

__all__ = ["app", "create_app"]


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _bool_setting(value: object, default: bool = False) -> bool:
    """
    Convert common environment/config representations to boolean.
    """
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, int):
        return bool(value)

    return str(value).strip().lower() in {"1", "true", "yes", "on", "y", "t"}


def _int_setting(value: object, default: int) -> int:
    """
    Safely convert a setting to int.
    """
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _float_setting(value: object, default: float) -> float:
    """
    Safely convert a setting to float.
    """
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _csv(value: object) -> list[str]:
    """
    Parse comma-separated settings into a clean list.
    """
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return [part.strip() for part in str(value).split(",") if part.strip()]


def _contains_placeholder(value: str | None) -> bool:
    """
    Detect obvious template/placeholder secret values.

    This is intentionally conservative and is not a replacement for a real
    secret scanner.
    """
    if not value:
        return True

    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _read_signal(obj: Any, name: str, default: Any = None) -> Any:
    """
    Read a field from either a mapping or an object.
    """
    if isinstance(obj, dict):
        return obj.get(name, default)

    return getattr(obj, name, default)


# -----------------------------------------------------------------------------
# Safety validation
# -----------------------------------------------------------------------------


def _validate_runtime_safety(settings: Settings, logger: logging.Logger) -> None:
    """
    Enforce MULEGUARD safety boundaries at application startup.

    Production-like environments must not enable:

    - debug mode;
    - synthetic demo seeding;
    - development user seeding;
    - demo authentication mode;
    - remote debugging;
    - public OpenAPI/docs unless explicitly overridden;
    - placeholder secrets.
    """
    env = str(getattr(settings, "BACKEND_ENV", "local")).strip().lower()

    production_like_values = {
        value.lower()
        for value in _csv(
            getattr(
                settings,
                "BACKEND_PRODUCTION_LIKE_ENVS",
                "production,staging,prod,stage",
            )
        )
    }

    is_production_like = env in production_like_values

    debug_enabled = _bool_setting(getattr(settings, "BACKEND_DEBUG", False))
    seed_dev_users = _bool_setting(getattr(settings, "SEED_DEV_USERS", False))
    seed_demo_data = _bool_setting(getattr(settings, "SEED_DEMO_DATA", False))
    auth_demo_mode = _bool_setting(getattr(settings, "AUTH_DEMO_MODE", False))

    remote_debugging_enabled = _bool_setting(
        getattr(settings, "REMOTE_DEBUGGING_ENABLED", False)
    ) or _bool_setting(getattr(settings, "DEBUGPY_ENABLED", False))

    openapi_enabled = _bool_setting(
        getattr(settings, "BACKEND_OPENAPI_ENABLED", True)
    )
    docs_enabled = _bool_setting(getattr(settings, "BACKEND_DOCS_ENABLED", True))

    block_dev_users_in_production = _bool_setting(
        getattr(settings, "BACKEND_BLOCK_DEV_USERS_IN_PRODUCTION", True)
    )
    block_seeding_in_production = _bool_setting(
        getattr(settings, "BACKEND_BLOCK_SEEDING_IN_PRODUCTION", True)
    )
    block_demo_features_in_production = _bool_setting(
        getattr(settings, "BACKEND_BLOCK_DEMO_FEATURES_IN_PRODUCTION", True)
    )
    block_openapi_in_production = _bool_setting(
        getattr(settings, "BACKEND_BLOCK_OPENAPI_IN_PRODUCTION", True)
    )

    require_strong_secret = _bool_setting(
        getattr(settings, "BACKEND_REQUIRE_STRONG_SECRET_IN_NON_LOCAL", True)
    )
    secret_key = str(getattr(settings, "BACKEND_SECRET_KEY", "") or "")

    if is_production_like:
        if debug_enabled:
            raise RuntimeError(
                "BACKEND_DEBUG=true is not allowed in production-like environments."
            )

        if seed_dev_users and block_dev_users_in_production:
            raise RuntimeError(
                "SEED_DEV_USERS=true is not allowed in production-like environments."
            )

        if seed_demo_data and block_seeding_in_production:
            raise RuntimeError(
                "SEED_DEMO_DATA=true is not allowed in production-like environments."
            )

        if auth_demo_mode and block_demo_features_in_production:
            raise RuntimeError(
                "AUTH_DEMO_MODE=true is not allowed in production-like environments."
            )

        if remote_debugging_enabled:
            raise RuntimeError(
                "Remote debugging is not allowed in production-like environments."
            )

        if block_openapi_in_production and (openapi_enabled or docs_enabled):
            raise RuntimeError(
                "BACKEND_OPENAPI_ENABLED and BACKEND_DOCS_ENABLED must be false "
                "in production-like environments unless explicitly overridden."
            )

    if env != "local" and require_strong_secret:
        if _contains_placeholder(secret_key):
            raise RuntimeError(
                "BACKEND_SECRET_KEY must be set to a strong non-placeholder value "
                "in non-local environments."
            )

    if env == "local" and _contains_placeholder(secret_key):
        logger.warning(
            "BACKEND_SECRET_KEY is missing or uses a placeholder value. "
            "This is allowed only for local synthetic development."
        )

    if env == "local":
        logger.warning(
            "Local synthetic/demo mode is active. Do not expose this instance "
            "publicly without hardening authentication, TLS, rate limits, "
            "audit retention, and deployment controls."
        )


# -----------------------------------------------------------------------------
# Logging/banner
# -----------------------------------------------------------------------------


def _log_startup_banner(settings: Settings, logger: logging.Logger) -> None:
    """
    Emit a clear startup banner describing prototype status and environment.
    """
    env = str(getattr(settings, "BACKEND_ENV", "local")).strip().lower()
    debug_enabled = _bool_setting(getattr(settings, "BACKEND_DEBUG", False))

    logger.info("=" * 78)
    logger.info("MULEGUARD backend version=%s", __version__)
    logger.info("Application name: %s", APP_NAME)
    logger.info("API prefix: %s", getattr(settings, "API_PREFIX", API_PREFIX))
    logger.info("Environment: %s", env)
    logger.info("Debug mode: %s", debug_enabled)
    logger.info("Data classification: %s", DATA_CLASSIFICATION)
    logger.info("Production ready: False")
    logger.info("Automatic adverse customer action: False")
    logger.info(_STARTUP_BANNER)
    logger.info("=" * 78)


# -----------------------------------------------------------------------------
# Startup/shutdown tasks
# -----------------------------------------------------------------------------


async def _startup_database_check(
    settings: Settings,
    logger: logging.Logger,
) -> None:
    """
    Optionally verify database connectivity during startup.

    This does not run migrations. Migrations remain the documented schema
    management path and are handled by Alembic or the container entrypoint.
    """
    if not _bool_setting(getattr(settings, "STARTUP_CHECK_DB", True)):
        logger.info("Database startup connectivity check disabled by configuration.")
        return

    timeout = max(0.1, _float_setting(getattr(settings, "DB_CONNECT_TIMEOUT_SECONDS", 10.0), 10.0))

    def _ping() -> None:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    try:
        await asyncio.wait_for(asyncio.to_thread(_ping), timeout=timeout)
        logger.info("Database connectivity check passed.")
    except Exception as exc:
        fail_on_db_unavailable = _bool_setting(
            getattr(settings, "HEALTH_FAIL_ON_DB_UNAVAILABLE", True)
        ) or _bool_setting(getattr(settings, "STARTUP_FAIL_DB", True))

        if fail_on_db_unavailable:
            raise RuntimeError("Database connectivity check failed.") from exc

        logger.warning(
            "Database connectivity check failed; continuing with degraded readiness: %s",
            exc,
        )


async def _startup_ml_preflight(
    app: FastAPI,
    settings: Settings,
    logger: logging.Logger,
) -> None:
    """
    Optionally preflight the ML model service.

    The application must gracefully degrade when no trained artifact exists.
    It must not fabricate model probabilities or crash solely because optional
    ML artifacts are unavailable, unless ML_REQUIRE_TRAINED_MODEL is true.
    """
    if not _bool_setting(getattr(settings, "ML_ENABLED", True)):
        logger.info("ML subsystem disabled by configuration.")
        app.state.active_scoring_mode = "ml_disabled"
        return

    module_name = "app.ml.model_service"

    if importlib.util.find_spec(module_name) is None:
        message = (
            "ML model service module not found. "
            "The application will continue only if fallback scoring is supported."
        )

        if _bool_setting(getattr(settings, "ML_REQUIRE_TRAINED_MODEL", False)):
            raise RuntimeError(message)

        logger.warning(message)
        app.state.active_scoring_mode = str(
            getattr(settings, "ML_FALLBACK_MODE_LABEL", "heuristic_fallback")
        )
        return

    try:
        module = importlib.import_module(module_name)
        factory = getattr(module, "get_model_service", None)

        if factory is None:
            raise AttributeError("app.ml.model_service.get_model_service is missing.")

        service = factory()
        preflight = getattr(service, "preflight", None)

        result: Any = None
        if callable(preflight):
            result = await asyncio.to_thread(preflight)

        scoring_mode = (
            _read_signal(result, "scoring_mode")
            or _read_signal(service, "scoring_mode")
            or getattr(settings, "ML_ACTIVE_SCORING_MODE", "auto")
        )

        model_version = (
            _read_signal(result, "model_version")
            or _read_signal(service, "model_version")
            or getattr(settings, "ML_ACTIVE_MODEL_VERSION", None)
        )

        app.state.active_scoring_mode = str(scoring_mode)
        app.state.active_model_version = str(model_version) if model_version else None

        logger.info(
            "ML preflight completed: scoring_mode=%s model_version=%s",
            app.state.active_scoring_mode,
            app.state.active_model_version,
        )

    except Exception as exc:
        if _bool_setting(getattr(settings, "ML_REQUIRE_TRAINED_MODEL", False)):
            raise RuntimeError("ML preflight failed and trained model is required.") from exc

        logger.warning(
            "ML preflight failed; expected fallback mode: %s",
            exc,
        )

        app.state.active_scoring_mode = str(
            getattr(settings, "ML_FALLBACK_MODE_LABEL", "heuristic_fallback")
        )
        app.state.active_model_version = None


async def _shutdown_database(logger: logging.Logger) -> None:
    """
    Dispose SQLAlchemy engine resources during shutdown.
    """
    try:
        await asyncio.to_thread(engine.dispose)
        logger.info("Database engine disposed.")
    except Exception as exc:
        logger.warning("Error while disposing database engine: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    FastAPI lifespan context manager.

    Performs safe startup checks and clean shutdown.
    """
    settings: Settings = app.state.settings
    logger = logging.getLogger(_LOGGER_NAME)

    startup_started_at = time.perf_counter()

    logger.info("MULEGUARD backend lifespan startup begins.")

    await _startup_database_check(settings, logger)
    await _startup_ml_preflight(app, settings, logger)

    app.state.start_time = time.time()

    logger.info(
        "MULEGUARD backend ready in %.3f seconds.",
        time.perf_counter() - startup_started_at,
    )

    try:
        yield
    finally:
        logger.info("MULEGUARD backend lifespan shutdown begins.")
        await _shutdown_database(logger)
        logger.info("MULEGUARD backend shutdown complete.")


# -----------------------------------------------------------------------------
# OpenAPI hardening/helper
# -----------------------------------------------------------------------------


def _install_openapi_bearer_security(app: FastAPI, api_prefix: str) -> None:
    """
    Add a bearer-auth security scheme to the generated OpenAPI document.

    Public endpoints such as health, login, docs, and OpenAPI itself should not
    require authentication in the generated schema.
    """
    original_openapi = app.openapi

    public_paths = {
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/api/v1/openapi.json",
        f"{api_prefix}/openapi.json",
        f"{api_prefix}/health/ready",
        f"{api_prefix}/auth/login",
    }

    http_methods = {"get", "post", "put", "patch", "delete", "options", "head"}

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema

        schema = original_openapi()

        components = schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})

        security_schemes["bearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "MULEGUARD local development/demo bearer token. "
                "Obtain a token from POST /api/v1/auth/login when authentication is enabled."
            ),
        }

        schema.setdefault("security", [{"bearerAuth": []}])

        paths = schema.get("paths", {})

        if isinstance(paths, dict):
            for path, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue

                if path not in public_paths:
                    continue

                for method in http_methods:
                    operation = path_item.get(method)

                    if isinstance(operation, dict):
                        operation.pop("security", None)

        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]


# -----------------------------------------------------------------------------
# Application factory
# -----------------------------------------------------------------------------


def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Create and configure the MULEGUARD FastAPI application.

    This factory is intentionally explicit and defensive. It is suitable for:

    - normal application startup;
    - test fixtures;
    - Docker entrypoints;
    - future managed deployment pipelines.
    """
    settings = settings or get_settings()

    configure_logging(settings)

    logger = logging.getLogger(_LOGGER_NAME)

    _log_startup_banner(settings, logger)
    _validate_runtime_safety(settings, logger)

    docs_enabled = _bool_setting(getattr(settings, "BACKEND_DOCS_ENABLED", True))
    openapi_enabled = _bool_setting(getattr(settings, "BACKEND_OPENAPI_ENABLED", True))

    docs_url = "/docs" if docs_enabled else None
    redoc_url = "/redoc" if docs_enabled else None
    openapi_url = str(getattr(settings, "OPENAPI_PATH", "/api/v1/openapi.json")) if openapi_enabled else None

    api_prefix = str(getattr(settings, "API_PREFIX", API_PREFIX))

    app = FastAPI(
        title=str(getattr(settings, "OPENAPI_TITLE", "MULEGUARD API")),
        version=str(getattr(settings, "OPENAPI_VERSION", "v1")),
        description=(
            "Backend API for MULEGUARD, a synthetic-first mule account detection "
            "and financial fraud investigation prototype. "
            "All alerts, scores, graph relationships, candidate money trails, and "
            "complaint correlations are investigative leads only."
        ),
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
        swagger_ui_parameters={
            "persistAuthorization": True,
            "displayRequestDuration": True,
            "tryItOutEnabled": docs_enabled,
        },
        openapi_tags=[
            {
                "name": "health",
                "description": "Liveness, readiness, and service status endpoints.",
            },
            {
                "name": "auth",
                "description": "Authentication and current-user endpoints.",
            },
            {
                "name": "dashboard",
                "description": "Executive dashboard aggregates derived from persisted data.",
            },
            {
                "name": "accounts",
                "description": "Account search, profiles, risk assessments, and explanations.",
            },
            {
                "name": "transactions",
                "description": "Transaction monitoring and evidence context.",
            },
            {
                "name": "analysis",
                "description": "Batch analysis runs, scoring mode, and run status.",
            },
            {
                "name": "alerts",
                "description": "Ranked investigative alerts and triage actions.",
            },
            {
                "name": "graph",
                "description": "Bounded graph analytics and candidate money-trail search.",
            },
            {
                "name": "complaints",
                "description": "Complaint records and transparent correlation tiers.",
            },
            {
                "name": "ingestion",
                "description": "Validated bulk ingestion endpoints.",
            },
            {
                "name": "cases",
                "description": "Investigation case management, evidence, notes, and events.",
            },
            {
                "name": "audit",
                "description": "Read-only audit history for permitted roles.",
            },
            {
                "name": "reports",
                "description": "PDF investigation report generation and download.",
            },
            {
                "name": "model",
                "description": "Model monitoring, evaluation metrics, and limitations.",
            },
        ],
    )

    app.state.settings = settings
    app.state.start_time = None
    app.state.active_scoring_mode = str(getattr(settings, "ML_ACTIVE_SCORING_MODE", "auto"))
    app.state.active_model_version = getattr(settings, "ML_ACTIVE_MODEL_VERSION", None)

    # -------------------------------------------------------------------------
    # Middleware
    # -------------------------------------------------------------------------
    # Order matters conceptually:
    #   - trusted host validation should happen early;
    #   - CORS should wrap API responses;
    #   - request ID should be available to logs/errors;
    #   - security headers should apply broadly;
    #   - performance instrumentation should measure inner handlers.
    # -------------------------------------------------------------------------

    allowed_hosts = _csv(getattr(settings, "BACKEND_ALLOWED_HOSTS", "localhost,127.0.0.1"))
    if not allowed_hosts:
        allowed_hosts = ["localhost", "127.0.0.1"]

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    if _bool_setting(getattr(settings, "CORS_ENABLED", True)):
        cors_origins = _csv(getattr(settings, "BACKEND_CORS_ORIGINS", ""))
        cors_allow_credentials = _bool_setting(
            getattr(settings, "CORS_ALLOW_CREDENTIALS", True)
        )

        if cors_origins == ["*"] and cors_allow_credentials:
            logger.warning(
                "CORS wildcard origin with credentials is unsafe. "
                "Disabling credentials for wildcard CORS in this startup."
            )
            cors_allow_credentials = False

        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=cors_allow_credentials,
            allow_methods=_csv(
                getattr(
                    settings,
                    "CORS_ALLOW_METHODS",
                    "GET,POST,PATCH,DELETE,OPTIONS,HEAD",
                )
            ),
            allow_headers=_csv(
                getattr(
                    settings,
                    "CORS_ALLOW_HEADERS",
                    "Authorization,Content-Type,X-Request-ID,X-Correlation-ID,Idempotency-Key,X-CSRF-Token",
                )
            ),
            expose_headers=_csv(
                getattr(
                    settings,
                    "CORS_EXPOSE_HEADERS",
                    "X-Request-ID,X-Correlation-ID,X-Response-Time",
                )
            ),
            allow_origin_regex=getattr(settings, "CORS_ALLOW_ORIGIN_REGEX", None) or None,
            max_age=_int_setting(getattr(settings, "CORS_MAX_AGE_SECONDS", 600), 600),
        )

    if _bool_setting(getattr(settings, "API_COMPRESSION_ENABLED", True)):
        app.add_middleware(
            GZipMiddleware,
            minimum_size=_int_setting(
                getattr(settings, "API_COMPRESSION_MIN_SIZE_BYTES", 1024),
                1024,
            ),
        )

    app.add_middleware(RequestIdMiddleware)

    try:
        app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    except TypeError:
        app.add_middleware(SecurityHeadersMiddleware)

    try:
        app.add_middleware(
            PerformanceMiddleware,
            slow_request_threshold_ms=_int_setting(
                getattr(settings, "PERFORMANCE_SLOW_REQUEST_THRESHOLD_MS", 2000),
                2000,
            ),
        )
    except TypeError:
        app.add_middleware(PerformanceMiddleware)

    register_exception_handlers(app)

    app.include_router(api_router, prefix=api_prefix)

    if _bool_setting(getattr(settings, "AUTH_ENABLED", True)):
        _install_openapi_bearer_security(app, api_prefix)

    # -------------------------------------------------------------------------
    # Root and liveness endpoints
    # -------------------------------------------------------------------------

    @app.get(
        "/",
        include_in_schema=False,
        summary="Service root",
    )
    async def root(request: Request) -> dict[str, Any]:
        """
        Minimal safe service root.

        Does not expose secrets, environment files, database URLs, tokens, or
        real customer data.
        """
        app_settings: Settings = request.app.state.settings
        docs_enabled_root = _bool_setting(
            getattr(app_settings, "BACKEND_DOCS_ENABLED", True)
        )

        return {
            "name": APP_NAME,
            "version": __version__,
            "status": "ok",
            "data_classification": DATA_CLASSIFICATION,
            "production_ready": False,
            "docs_url": "/docs" if docs_enabled_root else None,
            "health_url": "/health",
            "api_prefix": getattr(app_settings, "API_PREFIX", API_PREFIX),
        }

    @app.get(
        "/health",
        tags=["health"],
        summary="Liveness health check",
        description=(
            "Returns a safe liveness payload. This endpoint must not expose "
            "secrets, database URLs, tokens, real customer data, or internal "
            "configuration values."
        ),
    )
    async def health(request: Request) -> dict[str, Any]:
        """
        Safe liveness endpoint.
        """
        app_settings: Settings = request.app.state.settings
        started_at = getattr(request.app.state, "start_time", None)

        uptime_seconds = None
        if isinstance(started_at, (int, float)):
            uptime_seconds = round(time.time() - float(started_at), 3)

        return {
            "status": "ok",
            "app": APP_NAME,
            "version": __version__,
            "environment": str(getattr(app_settings, "BACKEND_ENV", "local")),
            "data_classification": DATA_CLASSIFICATION,
            "synthetic_demo": str(getattr(app_settings, "BACKEND_DATASET_MODE", "synthetic")) == "synthetic",
            "production_ready": False,
            "uptime_seconds": uptime_seconds,
            "request_id": getattr(request.state, "request_id", None),
            "active_scoring_mode": getattr(
                request.app.state,
                "active_scoring_mode",
                getattr(app_settings, "ML_ACTIVE_SCORING_MODE", "auto"),
            ),
            "active_model_version": getattr(request.app.state, "active_model_version", None),
        }

    return app


# -----------------------------------------------------------------------------
# Module-level ASGI app
# -----------------------------------------------------------------------------

app = create_app()


if __name__ == "__main__":
    """
    Convenience local runner.

    Preferred development command remains:

        uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

    This block is useful for IDE run configurations.
    """
    import uvicorn

    runtime_settings = get_settings()

    uvicorn.run(
        "app.main:app",
        host=str(getattr(runtime_settings, "BACKEND_HOST", "0.0.0.0")),
        port=_int_setting(getattr(runtime_settings, "BACKEND_PORT", 8000), 8000),
        reload=_bool_setting(getattr(runtime_settings, "BACKEND_DEBUG", False), False),
        log_level=str(getattr(runtime_settings, "BACKEND_UVICORN_LOG_LEVEL", "info")).lower(),
    )