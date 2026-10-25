"""
MULEGUARD backend API package.

This module is the public entry point for the FastAPI API layer.

Its responsibilities are intentionally narrow:

- expose stable API-layer constants;
- define public/protected path conventions;
- provide OpenAPI tag metadata;
- expose safe request-header constants;
- declare API-layer safety expectations;
- provide lazy access to API submodules and symbols;
- avoid eager imports of FastAPI, SQLAlchemy, Pydantic, ML, graph, or report
  dependencies during package initialization.

This package must not become a place where heavy runtime logic is executed at
import time.

Product-safety expectations for the API layer:

- All protected actions must be enforced server-side.
- Frontend hiding is not a security boundary.
- List endpoints must be paginated and stably ordered.
- Graph endpoints must remain bounded.
- Error responses must not expose secrets, stack traces, database URLs,
  tokens, passwords, or raw sensitive narratives.
- Alerts, scores, graph relationships, candidate money trails, and complaint
  correlations are investigative leads only.
- The API must not expose automatic adverse customer action.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from importlib import import_module
from types import MappingProxyType
from typing import Any, Final

# -----------------------------------------------------------------------------
# Execution guard
# -----------------------------------------------------------------------------
# This package is intended to be imported as part of the backend application.
# Direct execution is not a supported entrypoint.
if __package__ in {None, ""}:
    raise RuntimeError(
        "Do not execute app/api/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Stable API metadata
# -----------------------------------------------------------------------------

API_PACKAGE_NAME: Final[str] = "muleguard.backend.api"
API_LAYER: Final[str] = "api"
API_VERSION: Final[str] = "v1"
API_PREFIX: Final[str] = "/api/v1"

OPENAPI_TITLE: Final[str] = "MULEGUARD API"
OPENAPI_VERSION: Final[str] = "v1"
OPENAPI_PATH: Final[str] = f"{API_PREFIX}/openapi.json"

DOCS_PATH: Final[str] = "/docs"
REDOC_PATH: Final[str] = "/redoc"

HEALTH_PATH: Final[str] = "/health"
READY_PATH: Final[str] = f"{API_PREFIX}/health/ready"
METRICS_PATH: Final[str] = "/metrics"

LOGIN_PATH: Final[str] = f"{API_PREFIX}/auth/login"


# -----------------------------------------------------------------------------
# Public and protected path conventions
# -----------------------------------------------------------------------------
# These constants provide a single source of truth for route-classification
# helpers. Actual authentication and authorization enforcement must still be
# implemented in dependencies, middleware, services, and tests.

PUBLIC_PATHS: Final[tuple[str, ...]] = (
    "/",
    HEALTH_PATH,
    DOCS_PATH,
    REDOC_PATH,
    OPENAPI_PATH,
    READY_PATH,
    METRICS_PATH,
    LOGIN_PATH,
)

PUBLIC_PATH_PREFIXES: Final[tuple[str, ...]] = (
    "/docs/",
    "/redoc/",
    "/health/",
)

PROTECTED_PREFIXES: Final[tuple[str, ...]] = (
    API_PREFIX,
)


# -----------------------------------------------------------------------------
# HTTP conventions
# -----------------------------------------------------------------------------

SUPPORTED_METHODS: Final[tuple[str, ...]] = (
    "GET",
    "POST",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
)

ERROR_CODE_PREFIX: Final[str] = "MULEGUARD_"

REQUEST_ID_HEADER: Final[str] = "X-Request-ID"
CORRELATION_ID_HEADER: Final[str] = "X-Correlation-ID"
IDEMPOTENCY_KEY_HEADER: Final[str] = "Idempotency-Key"

TRACE_HEADERS: Final[tuple[str, ...]] = (
    REQUEST_ID_HEADER,
    CORRELATION_ID_HEADER,
)

CORS_EXPOSED_HEADERS: Final[tuple[str, ...]] = (
    REQUEST_ID_HEADER,
    CORRELATION_ID_HEADER,
    "X-Response-Time",
    "Deprecation",
    "Sunset",
)


# -----------------------------------------------------------------------------
# API-layer safety flags
# -----------------------------------------------------------------------------
# These are declarative policy markers. Runtime enforcement must still exist in
# configuration validation, dependencies, services, middleware, tests, and
# deployment controls.

_API_SAFETY_FLAGS_RAW: Final[dict[str, bool]] = {
    "server_side_authorization_required": True,
    "frontend_hiding_is_not_security_boundary": True,
    "pagination_required_for_list_endpoints": True,
    "stable_ordering_required_for_list_endpoints": True,
    "bounded_graph_queries_required": True,
    "evidence_backed_alerts_required": True,
    "explainable_scores_required": True,
    "audit_material_actions_required": True,
    "no_real_customer_data_by_default": True,
    "no_automatic_adverse_action": True,
    "no_unbounded_whole_bank_graph_access": True,
    "no_stack_trace_leakage": True,
    "no_secret_logging": True,
    "no_fake_functionality": True,
    "scores_are_investigative_priority_only": True,
    "graph_proximity_is_not_proof": True,
    "complaint_correlations_require_provenance": True,
    "money_trails_are_candidate_flow_paths_only": True,
}

API_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(_API_SAFETY_FLAGS_RAW)


# -----------------------------------------------------------------------------
# OpenAPI tags
# -----------------------------------------------------------------------------
# Centralizing tags here helps keep routers, docs, and tests aligned.

OPENAPI_TAGS: Final[tuple[dict[str, str], ...]] = (
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
)


# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------

__all__: Final[tuple[str, ...]] = (
    "API_PACKAGE_NAME",
    "API_LAYER",
    "API_VERSION",
    "API_PREFIX",
    "OPENAPI_TITLE",
    "OPENAPI_VERSION",
    "OPENAPI_PATH",
    "DOCS_PATH",
    "REDOC_PATH",
    "HEALTH_PATH",
    "READY_PATH",
    "METRICS_PATH",
    "LOGIN_PATH",
    "PUBLIC_PATHS",
    "PUBLIC_PATH_PREFIXES",
    "PROTECTED_PREFIXES",
    "SUPPORTED_METHODS",
    "ERROR_CODE_PREFIX",
    "REQUEST_ID_HEADER",
    "CORRELATION_ID_HEADER",
    "IDEMPOTENCY_KEY_HEADER",
    "TRACE_HEADERS",
    "CORS_EXPOSED_HEADERS",
    "API_SAFETY_FLAGS",
    "OPENAPI_TAGS",
    "get_api_router",
    "register_api_exception_handlers",
    "is_public_path",
    "is_protected_api_path",
    "get_api_metadata",
    "api_router",
    "register_exception_handlers",
)


# -----------------------------------------------------------------------------
# Lazy module and symbol access
# -----------------------------------------------------------------------------
# This keeps `import app.api` cheap and avoids circular-import pressure during
# package initialization.
#
# Supported patterns:
#
#   from app.api import v1
#   from app.api import deps
#   from app.api import api_router
#   from app.api import register_exception_handlers
#
# Missing modules or symbols raise normal ImportError/AttributeError at the
# point of use rather than failing the entire package import.

_LAZY_MODULES: Final[dict[str, str]] = {
    "deps": ".deps",
    "error_handlers": ".error_handlers",
    "middleware": ".middleware",
    "router": ".router",
    "v1": ".v1",
}

_LAZY_ATTRS: Final[dict[str, tuple[str, str]]] = {
    "api_router": (".v1.router", "api_router"),
    "register_exception_handlers": (".error_handlers", "register_exception_handlers"),
}


def __getattr__(name: str) -> Any:
    """
    Lazily import API submodules or selected public symbols.
    """
    module_name = _LAZY_MODULES.get(name)

    if module_name is not None:
        module = import_module(module_name, __name__)
        globals()[name] = module
        return module

    attr_spec = _LAZY_ATTRS.get(name)

    if attr_spec is not None:
        lazy_module_name, attr_name = attr_spec
        module = import_module(lazy_module_name, __name__)
        value = getattr(module, attr_name)
        globals()[name] = value
        return value

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )


def __dir__() -> list[str]:
    """
    Return a deterministic directory listing including lazily available modules
    and symbols.
    """
    return sorted(
        {
            *globals().keys(),
            *_LAZY_MODULES.keys(),
            *_LAZY_ATTRS.keys(),
        }
    )


# -----------------------------------------------------------------------------
# Convenience helpers
# -----------------------------------------------------------------------------


def get_api_router() -> Any:
    """
    Lazily import and return the versioned API router.

    This is a convenience wrapper for code that prefers not to import
    `app.api.v1.router` directly.
    """
    module = import_module(".v1.router", __name__)
    return getattr(module, "api_router")


def register_api_exception_handlers(app: Any) -> None:
    """
    Lazily import and invoke the API exception-handler registrar.

    The target function is expected to have the signature:

        register_exception_handlers(app: FastAPI) -> None

    This helper intentionally does not swallow missing implementations. If the
    API layer is expected to register handlers, the implementation must exist.
    """
    module = import_module(".error_handlers", __name__)
    handler = getattr(module, "register_exception_handlers", None)

    if not callable(handler):
        raise AttributeError(
            "app.api.error_handlers.register_exception_handlers is missing "
            "or not callable."
        )

    handler(app)


def _normalize_path(path: str | None) -> str:
    """
    Normalize a request path for safe prefix comparisons.

    This helper is intentionally conservative:

    - treats empty/None as root;
    - ensures leading slash;
    - collapses duplicate slashes;
    - removes trailing slash except for root.
    """
    if path is None:
        return "/"

    value = str(path).strip()

    if not value:
        return "/"

    if not value.startswith("/"):
        value = f"/{value}"

    while "//" in value:
        value = value.replace("//", "/")

    if len(value) > 1 and value.endswith("/"):
        value = value.rstrip("/")

    return value or "/"


def is_public_path(path: str | None) -> bool:
    """
    Return True when a path is considered public by API-layer convention.

    This helper does not replace authentication middleware or dependencies.
    It is intended for logging, documentation, tests, and route-classification
    consistency.
    """
    normalized = _normalize_path(path)

    if normalized in PUBLIC_PATHS:
        return True

    return any(normalized.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES)


def is_protected_api_path(path: str | None) -> bool:
    """
    Return True when a path is under the API prefix and is not public.

    Again, this is a convention helper, not the enforcement boundary.
    """
    normalized = _normalize_path(path)

    if not normalized.startswith(API_PREFIX):
        return False

    return not is_public_path(normalized)


def get_api_metadata() -> dict[str, Any]:
    """
    Return safe, serializable API-layer metadata.

    This is useful for:

    - OpenAPI metadata;
    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, or real customer data.
    """
    return {
        "package": API_PACKAGE_NAME,
        "layer": API_LAYER,
        "version": API_VERSION,
        "prefix": API_PREFIX,
        "openapi": {
            "title": OPENAPI_TITLE,
            "version": OPENAPI_VERSION,
            "path": OPENAPI_PATH,
        },
        "docs": {
            "path": DOCS_PATH,
            "redoc_path": REDOC_PATH,
        },
        "health": {
            "path": HEALTH_PATH,
            "ready_path": READY_PATH,
            "metrics_path": METRICS_PATH,
        },
        "auth": {
            "login_path": LOGIN_PATH,
        },
        "public_paths": PUBLIC_PATHS,
        "public_path_prefixes": PUBLIC_PATH_PREFIXES,
        "protected_prefixes": PROTECTED_PREFIXES,
        "supported_methods": SUPPORTED_METHODS,
        "error_code_prefix": ERROR_CODE_PREFIX,
        "headers": {
            "request_id": REQUEST_ID_HEADER,
            "correlation_id": CORRELATION_ID_HEADER,
            "idempotency_key": IDEMPOTENCY_KEY_HEADER,
            "trace_headers": TRACE_HEADERS,
            "cors_exposed_headers": CORS_EXPOSED_HEADERS,
        },
        "safety_flags": dict(API_SAFETY_FLAGS),
        "openapi_tags": [dict(tag) for tag in OPENAPI_TAGS],
        "lazy_modules": tuple(sorted(_LAZY_MODULES)),
        "lazy_attributes": tuple(sorted(_LAZY_ATTRS)),
    }