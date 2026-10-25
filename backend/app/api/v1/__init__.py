"""
MULEGUARD backend API v1 package.

This module is the public entry point for the versioned MULEGUARD API layer.

Its responsibilities are intentionally narrow:

- expose stable API v1 metadata;
- declare the `/api/v1` prefix and OpenAPI path;
- define public, protected, health, docs, auth, and system path conventions;
- declare OpenAPI tags for v1 endpoint groups;
- provide a registry of known v1 endpoint modules;
- provide lazy imports for v1 modules, routers, and endpoint packages;
- provide safe helpers for route installation and diagnostics;
- avoid eager imports of FastAPI, SQLAlchemy, Pydantic, ML, graph, reporting,
  audit, ingestion, or case dependencies during package initialization.

This package must not become a place where heavy runtime logic is executed at
import time.

Product-safety expectations for the v1 API layer:

- The backend is the security boundary.
- Authentication and authorization must be enforced by dependencies/services,
  not by frontend hiding or route naming alone.
- List endpoints must be paginated and stably ordered.
- Graph endpoints must remain bounded.
- Candidate money trails are flow hypotheses, not exact currency tracing.
- Complaint correlations must preserve exact-vs-inferred provenance.
- ML outputs must expose scoring mode and model version honestly.
- Heuristic fallback must not be presented as calibrated model probability.
- Alerts, scores, graph relationships, and complaint correlations are
  investigative leads only.
- The API must not expose automatic adverse customer action.
- Error responses must not expose secrets, stack traces, database URLs, tokens,
  passwords, raw complaint narratives, or real customer data.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib import import_module
from types import MappingProxyType
from typing import Any, Final, Optional

# -----------------------------------------------------------------------------
# Execution guard
# -----------------------------------------------------------------------------
# This package is intended to be imported as part of the backend application.
# Direct execution is not a supported entrypoint.
if __package__ in {None, ""}:
    raise RuntimeError(
        "Do not execute app/api/v1/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Stable API v1 metadata
# -----------------------------------------------------------------------------

API_PACKAGE_NAME: Final[str] = "muleguard.backend.api.v1"
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
CURRENT_USER_PATH: Final[str] = f"{API_PREFIX}/auth/me"
RUNTIME_CONFIG_PATH: Final[str] = f"{API_PREFIX}/config/runtime"


# -----------------------------------------------------------------------------
# Path conventions
# -----------------------------------------------------------------------------
# These constants provide a single source of truth for route classification,
# middleware, tests, diagnostics, and documentation. They do not replace
# authentication or authorization enforcement.

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
    "/api/v1/health/",
    "/api/v1/auth/login",
)

PROTECTED_PREFIXES: Final[tuple[str, ...]] = (
    API_PREFIX,
)

HEALTH_PATHS: Final[tuple[str, ...]] = (
    HEALTH_PATH,
    READY_PATH,
)

METRICS_PATHS: Final[tuple[str, ...]] = (
    METRICS_PATH,
)

DOCS_PATHS: Final[tuple[str, ...]] = (
    DOCS_PATH,
    REDOC_PATH,
    OPENAPI_PATH,
)

AUTH_PATHS: Final[tuple[str, ...]] = (
    LOGIN_PATH,
    CURRENT_USER_PATH,
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
RESPONSE_TIME_HEADER: Final[str] = "X-Response-Time"

TRACE_HEADERS: Final[tuple[str, ...]] = (
    REQUEST_ID_HEADER,
    CORRELATION_ID_HEADER,
)

CORS_EXPOSED_HEADERS: Final[tuple[str, ...]] = (
    REQUEST_ID_HEADER,
    CORRELATION_ID_HEADER,
    RESPONSE_TIME_HEADER,
    "RateLimit-Limit",
    "RateLimit-Remaining",
    "RateLimit-Reset",
    "Retry-After",
    "Deprecation",
    "Sunset",
)


# -----------------------------------------------------------------------------
# API v1 safety flags
# -----------------------------------------------------------------------------
# These are declarative policy markers. Runtime enforcement must still exist in
# dependencies, services, middleware, tests, and deployment controls.

_API_V1_SAFETY_FLAGS_RAW: Final[dict[str, bool]] = {
    "versioned_contract": True,
    "server_side_authorization_required": True,
    "frontend_hiding_is_not_security_boundary": True,
    "pagination_required_for_list_endpoints": True,
    "stable_ordering_required_for_list_endpoints": True,
    "bounded_graph_queries_required": True,
    "evidence_backed_alerts_required": True,
    "explainable_scores_required": True,
    "scoring_mode_visible_required": True,
    "model_version_visible_required": True,
    "fallback_not_model_probability": True,
    "exact_complaint_matches_distinct_from_inferred": True,
    "money_trails_are_candidate_flow_paths_only": True,
    "graph_proximity_is_not_proof": True,
    "audit_material_actions_required": True,
    "no_real_customer_data_by_default": True,
    "no_automatic_adverse_action": True,
    "no_unbounded_whole_bank_graph_access": True,
    "no_stack_trace_leakage": True,
    "no_secret_logging": True,
    "no_fake_functionality": True,
    "scores_are_investigative_priority_only": True,
}

API_V1_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    _API_V1_SAFETY_FLAGS_RAW
)


# -----------------------------------------------------------------------------
# OpenAPI tags
# -----------------------------------------------------------------------------
# Centralizing tags here helps keep routers, docs, tests, and clients aligned.

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
    {
        "name": "system",
        "description": "Safe system diagnostics, runtime configuration, and metadata.",
    },
)


# -----------------------------------------------------------------------------
# Endpoint registry model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EndpointSpec:
    """
    Safe metadata describing a known API v1 endpoint module.

    This registry does not instantiate routers by itself. It allows tests,
    startup diagnostics, application factories, and documentation tooling to
    reason about the v1 API surface without importing heavy modules prematurely.
    """

    name: str
    module: str
    prefix: str
    tags: tuple[str, ...]
    order: int
    router_attr: str = "router"
    required: bool = True
    default_enabled: bool = True
    enabled_setting: Optional[str] = None
    notes: tuple[str, ...] = field(default_factory=tuple)


# -----------------------------------------------------------------------------
# Known endpoint modules
# -----------------------------------------------------------------------------
# These correspond to expected modules under app/api/v1/endpoints/.
#
# Recommended layout:
#
#   app/api/v1/endpoints/
#       __init__.py
#       health.py
#       auth.py
#       dashboard.py
#       accounts.py
#       transactions.py
#       analysis.py
#       alerts.py
#       graph.py
#       complaints.py
#       ingestion.py
#       cases.py
#       audit.py
#       reports.py
#       model.py
#       system.py
#
# Each endpoint module should expose a FastAPI APIRouter named `router`, or
# another name declared in `router_attr`.

_ENDPOINT_REGISTRY_RAW: Final[dict[str, EndpointSpec]] = {
    "health": EndpointSpec(
        name="health",
        module=".endpoints.health",
        prefix="/health",
        tags=("health",),
        order=10,
        required=True,
        default_enabled=True,
        enabled_setting=None,
        notes=(
            "Liveness and readiness endpoints must remain safe and non-sensitive.",
            "Health payloads must not expose secrets, database URLs, tokens, or real customer data.",
        ),
    ),
    "auth": EndpointSpec(
        name="auth",
        module=".endpoints.auth",
        prefix="/auth",
        tags=("auth",),
        order=20,
        required=True,
        default_enabled=True,
        enabled_setting="AUTH_ENABLED",
        notes=(
            "Login may be public depending on configuration, but protected auth endpoints must enforce authentication.",
            "Invalid credentials must not reveal whether username or password failed.",
        ),
    ),
    "dashboard": EndpointSpec(
        name="dashboard",
        module=".endpoints.dashboard",
        prefix="/dashboard",
        tags=("dashboard",),
        order=40,
        required=False,
        default_enabled=True,
        enabled_setting="DASHBOARD_ENABLED",
        notes=(
            "Dashboard metrics must derive from persisted data.",
            "Empty states must be explicit; no fake chart series or hardcoded metrics.",
        ),
    ),
    "accounts": EndpointSpec(
        name="accounts",
        module=".endpoints.accounts",
        prefix="/accounts",
        tags=("accounts",),
        order=50,
        required=True,
        default_enabled=True,
        enabled_setting=None,
        notes=(
            "Account risk scores are investigative priority scores, not probabilities of guilt.",
            "Account explanations must cite real persisted evidence.",
        ),
    ),
    "transactions": EndpointSpec(
        name="transactions",
        module=".endpoints.transactions",
        prefix="/transactions",
        tags=("transactions",),
        order=60,
        required=True,
        default_enabled=True,
        enabled_setting=None,
        notes=(
            "Failed and reversed transactions must not be treated as completed fund movement.",
            "Transaction evidence references must point to persisted records.",
        ),
    ),
    "analysis": EndpointSpec(
        name="analysis",
        module=".endpoints.analysis",
        prefix="/analysis",
        tags=("analysis",),
        order=70,
        required=True,
        default_enabled=True,
        enabled_setting="ANALYSIS_ENABLED",
        notes=(
            "Analysis runs must expose scoring mode, model version where applicable, and safe run state.",
            "Missing ML artifacts must produce explicit fallback, not fabricated model claims.",
        ),
    ),
    "alerts": EndpointSpec(
        name="alerts",
        module=".endpoints.alerts",
        prefix="/alerts",
        tags=("alerts",),
        order=80,
        required=True,
        default_enabled=True,
        enabled_setting="ALERT_ENGINE_ENABLED",
        notes=(
            "Alerts are investigative leads, not proof of wrongdoing.",
            "Alert triage actions must be permission-checked and audited where material.",
        ),
    ),
    "graph": EndpointSpec(
        name="graph",
        module=".endpoints.graph",
        prefix="/graph",
        tags=("graph",),
        order=90,
        required=True,
        default_enabled=True,
        enabled_setting="GRAPH_ENABLED",
        notes=(
            "Graph queries must be bounded by root/constrained source, hops, nodes, edges, paths, and date span.",
            "Candidate money trails are flow hypotheses, not exact currency tracing.",
            "Graph proximity is not proof of common control or wrongdoing.",
        ),
    ),
    "complaints": EndpointSpec(
        name="complaints",
        module=".endpoints.complaints",
        prefix="/complaints",
        tags=("complaints",),
        order=100,
        required=True,
        default_enabled=True,
        enabled_setting="COMPLAINT_ENGINE_ENABLED",
        notes=(
            "Exact matches must be separated from inferred associations.",
            "Raw complaint facts must be preserved separately from normalized values.",
            "Narrative access and extraction must be role-gated and redacted where appropriate.",
        ),
    ),
    "ingestion": EndpointSpec(
        name="ingestion",
        module=".endpoints.ingestion",
        prefix="/ingestion",
        tags=("ingestion",),
        order=110,
        required=False,
        default_enabled=True,
        enabled_setting="INGESTION_ENABLED",
        notes=(
            "Ingestion is synthetic-first by default.",
            "Batch responses must report accepted/rejected/duplicated/skipped counts.",
            "Row-level errors must not leak secrets or unnecessary sensitive narrative content.",
        ),
    ),
    "cases": EndpointSpec(
        name="cases",
        module=".endpoints.cases",
        prefix="/cases",
        tags=("cases",),
        order=120,
        required=True,
        default_enabled=True,
        enabled_setting="CASE_ENGINE_ENABLED",
        notes=(
            "Case state transitions must be centrally validated.",
            "Evidence must reference validated persisted records.",
            "Case history must remain append-only.",
            "Dispositions are investigator-entered assessments, not automatic conclusions.",
        ),
    ),
    "entities": EndpointSpec(
        name="entities",
        module=".endpoints.entities",
        prefix="/entities",
        tags=("entities",),
        order=115,
        required=False,
        default_enabled=True,
        enabled_setting="ENTITIES_ENABLED",
        notes=(
            "Entities are pseudonymous. Raw device, phone, email, and address values are never exposed.",
            "Shared-entity associations are investigative leads, not proof of shared control.",
        ),
    ),
    "users": EndpointSpec(
        name="users",
        module=".endpoints.users",
        prefix="/users",
        tags=("users",),
        order=125,
        required=False,
        default_enabled=True,
        enabled_setting="USER_MANAGEMENT_ENABLED",
        notes=(
            "User administration must be restricted to the admin role.",
            "Password hashes and lockout internals must never appear in a response.",
        ),
    ),
    "audit": EndpointSpec(
        name="audit",
        module=".endpoints.audit",
        prefix="/audit",
        tags=("audit",),
        order=130,
        required=False,
        default_enabled=True,
        enabled_setting="AUDIT_ENABLED",
        notes=(
            "Audit reads must be restricted to permitted roles.",
            "Audit payloads must not expose passwords, tokens, secrets, or unnecessary sensitive narratives.",
        ),
    ),
    "reports": EndpointSpec(
        name="reports",
        module=".endpoints.reports",
        prefix="/reports",
        tags=("reports",),
        order=140,
        required=False,
        default_enabled=True,
        enabled_setting="REPORT_ENABLED",
        notes=(
            "PDF reports must be generated from persisted data.",
            "Reports must include synthetic-data disclaimer and limitations.",
            "Report downloads must check authorization and sanitize filenames.",
        ),
    ),
    "model": EndpointSpec(
        name="model",
        # The module is `model_metrics`, not `model`: the prefix and the file
        # name differ, and pointing at `.endpoints.model` silently left every
        # /model route unmounted.
        module=".endpoints.model_metrics",
        prefix="/model",
        tags=("model",),
        order=150,
        required=False,
        default_enabled=True,
        enabled_setting="ML_ENABLED",
        notes=(
            "Model metrics must be real computed outputs.",
            "Undefined metrics must be reported honestly as unavailable.",
            "Heuristic fallback must not be presented as calibrated model probability.",
        ),
    ),
}

ENDPOINT_REGISTRY: Final[Mapping[str, EndpointSpec]] = MappingProxyType(
    _ENDPOINT_REGISTRY_RAW
)


def _sorted_endpoint_specs() -> tuple[EndpointSpec, ...]:
    return tuple(
        sorted(
            ENDPOINT_REGISTRY.values(),
            key=lambda spec: (spec.order, spec.name),
        )
    )


ENDPOINT_ORDER: Final[tuple[str, ...]] = tuple(
    spec.name for spec in _sorted_endpoint_specs()
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
    "CURRENT_USER_PATH",
    "RUNTIME_CONFIG_PATH",
    "PUBLIC_PATHS",
    "PUBLIC_PATH_PREFIXES",
    "PROTECTED_PREFIXES",
    "HEALTH_PATHS",
    "METRICS_PATHS",
    "DOCS_PATHS",
    "AUTH_PATHS",
    "SUPPORTED_METHODS",
    "ERROR_CODE_PREFIX",
    "REQUEST_ID_HEADER",
    "CORRELATION_ID_HEADER",
    "IDEMPOTENCY_KEY_HEADER",
    "RESPONSE_TIME_HEADER",
    "TRACE_HEADERS",
    "CORS_EXPOSED_HEADERS",
    "API_V1_SAFETY_FLAGS",
    "OPENAPI_TAGS",
    "EndpointSpec",
    "ENDPOINT_REGISTRY",
    "ENDPOINT_ORDER",
    "api_router",
    "get_api_router",
    "get_endpoint_spec",
    "get_endpoint_router",
    "iter_endpoint_specs",
    "install_default_routers",
    "normalize_path",
    "is_public_path",
    "is_protected_api_path",
    "get_api_v1_metadata",
)


# -----------------------------------------------------------------------------
# Lazy module and symbol access
# -----------------------------------------------------------------------------
# Keeps `import app.api.v1` cheap and avoids circular-import pressure during
# package initialization.
#
# Supported patterns:
#
#   from app.api.v1 import router
#   from app.api.v1 import endpoints
#   from app.api.v1 import api_router
#   from app.api.v1 import health
#   from app.api.v1 import graph
#   from app.api.v1 import cases
#
# Missing modules or symbols raise normal ImportError/AttributeError at the
# point of use rather than failing the entire package import.

_LAZY_MODULES: Final[dict[str, str]] = {
    "router": ".router",
    "endpoints": ".endpoints",
}

_LAZY_ATTRS: Final[dict[str, tuple[str, str]]] = {
    "api_router": (".router", "api_router"),
}


def __getattr__(name: str) -> Any:
    """
    Lazily import v1 submodules, endpoint modules, or selected public symbols.
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

    endpoint_spec = ENDPOINT_REGISTRY.get(name)

    if endpoint_spec is not None:
        module = import_module(endpoint_spec.module, __name__)
        globals()[name] = module
        return module

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )


def __dir__() -> list[str]:
    """
    Return a deterministic directory listing including lazily available modules,
    endpoint modules, and symbols.
    """
    return sorted(
        {
            *globals().keys(),
            *_LAZY_MODULES.keys(),
            *_LAZY_ATTRS.keys(),
            *ENDPOINT_REGISTRY.keys(),
        }
    )


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}


def _read_setting(settings: Any, name: str, default: Any = None) -> Any:
    """
    Read a setting from either a Pydantic settings object or mapping.
    """
    if settings is None:
        return default

    if isinstance(settings, Mapping):
        return settings.get(name, default)

    return getattr(settings, name, default)


def _as_bool(value: object, default: bool = False) -> bool:
    """
    Convert common configuration representations to boolean.
    """
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, int):
        return bool(value)

    text_value = str(value).strip().lower()

    if text_value in _TRUE_VALUES:
        return True

    if text_value in _FALSE_VALUES:
        return False

    return default


def _resolve_settings(app: Any, settings: Any | None) -> Any:
    """
    Resolve runtime settings for router installation.

    Preference order:

    1. explicitly supplied settings;
    2. `app.state.settings`, when available;
    3. `app.core.config.get_settings()`;
    4. empty mapping fallback.
    """
    if settings is not None:
        return settings

    state = getattr(app, "state", None)
    state_settings = getattr(state, "settings", None)

    if state_settings is not None:
        return state_settings

    try:
        from app.core.config import get_settings

        return get_settings()
    except Exception:
        return {}


# -----------------------------------------------------------------------------
# Path helpers
# -----------------------------------------------------------------------------


def normalize_path(path: str | None) -> str:
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
    Return True when a path is considered public by v1 API convention.

    This helper does not replace authentication middleware or dependencies.
    It is intended for logging, documentation, tests, diagnostics, and
    route-classification consistency.
    """
    normalized = normalize_path(path)

    if normalized in PUBLIC_PATHS:
        return True

    return any(normalized.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES)


def is_protected_api_path(path: str | None) -> bool:
    """
    Return True when a path is under the v1 API prefix and is not public.

    Again, this is a convention helper, not the enforcement boundary.
    """
    normalized = normalize_path(path)

    if not normalized.startswith(API_PREFIX):
        return False

    return not is_public_path(normalized)


# -----------------------------------------------------------------------------
# Registry helpers
# -----------------------------------------------------------------------------


def iter_endpoint_specs() -> tuple[EndpointSpec, ...]:
    """
    Return known v1 endpoint specs in logical installation order.
    """
    return _sorted_endpoint_specs()


def get_endpoint_spec(name: str) -> EndpointSpec:
    """
    Return an endpoint spec by name.

    Raises KeyError when the endpoint name is unknown.
    """
    normalized = str(name).strip().lower()

    try:
        return ENDPOINT_REGISTRY[normalized]
    except KeyError as exc:
        raise KeyError(f"Unknown API v1 endpoint: {name}") from exc


def get_endpoint_router(name: str) -> Any:
    """
    Lazily import and return a FastAPI router for a named endpoint module.

    The endpoint module is expected to expose a router object under the
    registry-defined `router_attr`, usually `router`.
    """
    spec = get_endpoint_spec(name)
    module = import_module(spec.module, __name__)
    router = getattr(module, spec.router_attr, None)

    if router is None:
        raise AttributeError(
            f"{spec.module} does not expose router attribute {spec.router_attr!r}"
        )

    return router


def get_api_router() -> Any:
    """
    Lazily import and return the aggregated v1 API router.

    This is the preferred integration point for `app/main.py`:

        from app.api.v1 import get_api_router

        app.include_router(get_api_router(), prefix=API_PREFIX)

    or directly:

        from app.api.v1.router import api_router

        app.include_router(api_router, prefix="/api/v1")
    """
    module = import_module(".router", __name__)
    router = getattr(module, "api_router", None)

    if router is None:
        raise AttributeError(
            "app.api.v1.router does not expose `api_router`."
        )

    return router


# -----------------------------------------------------------------------------
# Router installation helper
# -----------------------------------------------------------------------------


def install_default_routers(
    app: Any,
    settings: Any | None = None,
    *,
    force: bool = False,
    include_prefix: bool = True,
) -> list[str]:
    """
    Install known default v1 endpoint routers onto a FastAPI application.

    This helper is intentionally defensive:

    - skips endpoint modules disabled by configuration;
    - skips optional modules that cannot be imported;
    - raises for required modules that cannot be imported;
    - marks `app.state` to avoid double installation unless `force=True`;
    - includes routers under `/api/v1` by default;
    - does not install middleware, exception handlers, CORS, trusted hosts,
      compression, or authentication dependencies, because those are owned by
      the application factory and dependency layers.

    Important:

    If `app/api/v1/router.py` already aggregates endpoint routers into
    `api_router`, prefer using:

        app.include_router(get_api_router(), prefix="/api/v1")

    and do not call `install_default_routers()` unless you intentionally want
    direct endpoint-module installation.

    Returns the list of installed endpoint names.
    """
    installed: list[str] = []
    state = getattr(app, "state", None)

    if state is not None and not force:
        if getattr(state, "_muleguard_api_v1_routers_installed", False):
            return installed

    resolved_settings = _resolve_settings(app, settings)

    for spec in iter_endpoint_specs():
        if spec.enabled_setting is not None:
            enabled = _as_bool(
                _read_setting(
                    resolved_settings,
                    spec.enabled_setting,
                    spec.default_enabled,
                ),
                spec.default_enabled,
            )

            if not enabled:
                continue

        try:
            router = get_endpoint_router(spec.name)
        except Exception:
            if spec.required:
                raise
            continue

        prefix = spec.prefix or ""

        if include_prefix and not prefix.startswith(API_PREFIX):
            prefix = f"{API_PREFIX}{prefix}"

        try:
            app.include_router(
                router,
                prefix=prefix,
                tags=list(spec.tags),
            )
        except TypeError:
            # Older or alternate router implementations may not accept tags in
            # include_router. Fall back to prefix-only installation.
            app.include_router(
                router,
                prefix=prefix,
            )

        installed.append(spec.name)

    if state is not None:
        setattr(state, "_muleguard_api_v1_routers_installed", True)

    return installed


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_api_v1_metadata() -> dict[str, Any]:
    """
    Return safe, serializable API v1 metadata.

    This is useful for:

    - OpenAPI metadata;
    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, or real customer data.
    """
    specs: list[dict[str, Any]] = []

    for spec in iter_endpoint_specs():
        specs.append(
            {
                "name": spec.name,
                "module": spec.module,
                "prefix": spec.prefix,
                "tags": list(spec.tags),
                "order": spec.order,
                "router_attr": spec.router_attr,
                "required": spec.required,
                "default_enabled": spec.default_enabled,
                "enabled_setting": spec.enabled_setting,
                "notes": list(spec.notes),
            }
        )

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
            "current_user_path": CURRENT_USER_PATH,
        },
        "system": {
            "runtime_config_path": RUNTIME_CONFIG_PATH,
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
            "response_time": RESPONSE_TIME_HEADER,
            "trace_headers": TRACE_HEADERS,
            "cors_exposed_headers": CORS_EXPOSED_HEADERS,
        },
        "safety_flags": dict(API_V1_SAFETY_FLAGS),
        "openapi_tags": [dict(tag) for tag in OPENAPI_TAGS],
        "endpoint_order": ENDPOINT_ORDER,
        "endpoints": specs,
        "lazy_modules": tuple(sorted(_LAZY_MODULES)),
        "lazy_attributes": tuple(sorted(_LAZY_ATTRS)),
    }