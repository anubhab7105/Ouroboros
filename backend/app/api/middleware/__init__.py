"""
MULEGUARD backend API middleware package.

This module is the public entry point for the MULEGUARD FastAPI/Starlette
middleware layer.

Its responsibilities are intentionally narrow:

- expose stable middleware-layer constants;
- declare safe header conventions;
- declare public/non-business path conventions;
- provide a registry of known middleware components;
- provide lazy imports for middleware modules and classes;
- provide safe helpers for path/method skipping;
- provide optional installation helpers for default middleware;
- avoid eager imports of FastAPI, Starlette, SQLAlchemy, Pydantic, ML, graph,
  reporting, or audit dependencies during package initialization.

Middleware is not the security boundary.

Authentication and authorization are enforced by the API dependency layer and
services. Middleware may add request context, security headers, performance
instrumentation, maintenance behaviour, rate-limit headers, or safe audit
metadata, but it must not make investigative decisions, enforce business
authorization alone, or fabricate functionality.

Product-safety expectations for this layer:

- Request IDs and correlation IDs must be safe, bounded, and non-sensitive.
- Security headers must not leak server internals.
- Performance middleware must not log request/response bodies by default.
- Audit middleware, when present, must record only safe metadata.
- Rate-limit middleware must not expose internal limiter state.
- Public paths may skip some instrumentation, but must not bypass authentication
  for protected operations.
- Error responses must not expose secrets, stack traces, database URLs, tokens,
  passwords, raw complaint narratives, or real customer data.
- Alerts, scores, graph relationships, candidate money trails, and complaint
  correlations remain investigative leads only.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from importlib import import_module
from types import MappingProxyType
from typing import Any, Final, Literal, Optional

# -----------------------------------------------------------------------------
# Execution guard
# -----------------------------------------------------------------------------
# This package is intended to be imported as part of the backend application.
# Direct execution is not a supported entrypoint.
if __package__ in {None, ""}:
    raise RuntimeError(
        "Do not execute app/api/middleware/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Stable middleware metadata
# -----------------------------------------------------------------------------

MIDDLEWARE_PACKAGE_NAME: Final[str] = "muleguard.backend.api.middleware"
MIDDLEWARE_LAYER: Final[str] = "middleware"
MIDDLEWARE_API_PREFIX: Final[str] = "/api/v1"


# -----------------------------------------------------------------------------
# Header conventions
# -----------------------------------------------------------------------------
# These constants provide a single source of truth for middleware, routers,
# exception handlers, tests, and frontend/client conventions.

REQUEST_ID_HEADER: Final[str] = "X-Request-ID"
CORRELATION_ID_HEADER: Final[str] = "X-Correlation-ID"
RESPONSE_TIME_HEADER: Final[str] = "X-Response-Time"

RATELIMIT_LIMIT_HEADER: Final[str] = "RateLimit-Limit"
RATELIMIT_REMAINING_HEADER: Final[str] = "RateLimit-Remaining"
RATELIMIT_RESET_HEADER: Final[str] = "RateLimit-Reset"
RETRY_AFTER_HEADER: Final[str] = "Retry-After"
WWW_AUTHENTICATE_HEADER: Final[str] = "WWW-Authenticate"

TRACE_HEADERS: Final[tuple[str, ...]] = (
    REQUEST_ID_HEADER,
    CORRELATION_ID_HEADER,
)

CORS_EXPOSED_HEADERS: Final[tuple[str, ...]] = (
    REQUEST_ID_HEADER,
    CORRELATION_ID_HEADER,
    RESPONSE_TIME_HEADER,
    RATELIMIT_LIMIT_HEADER,
    RATELIMIT_REMAINING_HEADER,
    RATELIMIT_RESET_HEADER,
    RETRY_AFTER_HEADER,
)

# Headers that middleware/error handlers may safely copy into responses.
# This is intentionally small. Do not add cookies, authorization, tokens,
# internal debug headers, or sensitive diagnostics here.
SAFE_RESPONSE_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "allow",
        "content-type",
        "location",
        "retry-after",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "www-authenticate",
        "x-request-id",
        "x-correlation-id",
        "x-response-time",
    }
)


# -----------------------------------------------------------------------------
# Path conventions
# -----------------------------------------------------------------------------
# These paths are considered non-business or infrastructure paths for purposes
# of safe instrumentation. They do not define authentication policy.

PUBLIC_PATHS: Final[tuple[str, ...]] = (
    "/",
    "/health",
    "/docs",
    "/redoc",
    "/metrics",
    "/api/v1/openapi.json",
    "/api/v1/health/ready",
    "/api/v1/auth/login",
)

PUBLIC_PATH_PREFIXES: Final[tuple[str, ...]] = (
    "/docs/",
    "/redoc/",
    "/health/",
    "/api/v1/health/",
    "/static/",
)

HEALTH_PATHS: Final[tuple[str, ...]] = (
    "/health",
    "/api/v1/health/ready",
)

METRICS_PATHS: Final[tuple[str, ...]] = (
    "/metrics",
)

DOCS_PATHS: Final[tuple[str, ...]] = (
    "/docs",
    "/redoc",
    "/api/v1/openapi.json",
)

# Methods that are usually safe to exclude from audit/performance noise.
SKIP_METHODS_FOR_AUDIT: Final[frozenset[str]] = frozenset({"OPTIONS"})
SKIP_METHODS_FOR_PERFORMANCE: Final[frozenset[str]] = frozenset()


# -----------------------------------------------------------------------------
# Middleware-layer safety flags
# -----------------------------------------------------------------------------
# These are declarative policy markers. Runtime enforcement must still exist in
# middleware implementations, dependencies, services, tests, and deployment
# controls.

_MIDDLEWARE_SAFETY_FLAGS_RAW: Final[dict[str, bool]] = {
    "middleware_is_not_security_boundary": True,
    "middleware_is_not_authorization_boundary": True,
    "middleware_must_not_make_investigative_decisions": True,
    "request_ids_are_safe_and_bounded": True,
    "no_secrets_in_middleware_headers": True,
    "no_request_body_logging_by_default": True,
    "no_response_body_logging_by_default": True,
    "no_query_string_logging_by_default": True,
    "security_headers_do_not_replace_tls": True,
    "security_headers_do_not_leak_server_internals": True,
    "performance_logging_is_bounded": True,
    "audit_metadata_is_safe_and_redacted": True,
    "rate_limit_headers_do_not_leak_internals": True,
    "public_paths_may_skip_instrumentation": True,
    "public_paths_must_not_bypass_authentication_for_protected_actions": True,
    "graceful_degradation_for_optional_middleware": True,
    "no_fake_functionality": True,
}

MIDDLEWARE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    _MIDDLEWARE_SAFETY_FLAGS_RAW
)


# -----------------------------------------------------------------------------
# Middleware registry model
# -----------------------------------------------------------------------------

MiddlewareKind = Literal["asgi", "http", "factory"]


@dataclass(frozen=True, slots=True)
class MiddlewareSpec:
    """
    Safe metadata describing a known middleware component.

    This registry does not instantiate middleware by itself. It allows tests,
    startup diagnostics, and application factories to reason about middleware
    without importing heavy modules prematurely.
    """

    name: str
    module: str
    class_name: str
    order: int
    required: bool = True
    default_enabled: bool = True
    enabled_setting: Optional[str] = None
    kind: MiddlewareKind = "asgi"
    safe_defaults: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({})
    )
    skip_paths: tuple[str, ...] = ()
    skip_prefixes: tuple[str, ...] = ()
    skip_methods: frozenset[str] = field(default_factory=frozenset)
    notes: tuple[str, ...] = ()


# -----------------------------------------------------------------------------
# Known middleware defaults
# -----------------------------------------------------------------------------

_SECURITY_HEADERS_DEFAULTS: Final[Mapping[str, Any]] = MappingProxyType(
    {
        "x_content_type_options": "nosniff",
        "x_frame_options": "DENY",
        "referrer_policy": "no-referrer",
        "apply_to_errors": True,
        "remove_server": True,
        "remove_x_powered_by": True,
    }
)

_PERFORMANCE_DEFAULTS: Final[Mapping[str, Any]] = MappingProxyType(
    {
        "slow_request_threshold_ms": 2000,
        "include_response_time_header": True,
        "log_request_body": False,
        "log_response_body": False,
        "log_query_string": False,
    }
)

_REQUEST_ID_DEFAULTS: Final[Mapping[str, Any]] = MappingProxyType(
    {
        "header_name": REQUEST_ID_HEADER,
        "correlation_header_name": CORRELATION_ID_HEADER,
        "max_length": 128,
        "validate_inbound": True,
        "generate_if_missing": True,
    }
)


# -----------------------------------------------------------------------------
# Middleware registry
# -----------------------------------------------------------------------------
# Only include middleware modules that are expected to exist in this package.
# Optional future middleware should be added here only when implemented,
# tested, and documented.

_MIDDLEWARE_REGISTRY_RAW: Final[dict[str, MiddlewareSpec]] = {
    "request_id": MiddlewareSpec(
        name="request_id",
        module=".request_id",
        class_name="RequestIdMiddleware",
        order=10,
        required=True,
        default_enabled=True,
        enabled_setting=None,
        kind="asgi",
        safe_defaults=_REQUEST_ID_DEFAULTS,
        skip_paths=(),
        skip_prefixes=(),
        skip_methods=frozenset(),
        notes=(
            "Assigns or preserves safe request/correlation IDs.",
            "Must not accept unbounded or control-character header values.",
            "Request IDs are for diagnostics and audit correlation, not identity.",
        ),
    ),
    "security_headers": MiddlewareSpec(
        name="security_headers",
        module=".security_headers",
        class_name="SecurityHeadersMiddleware",
        order=20,
        required=True,
        default_enabled=True,
        enabled_setting="SECURE_HEADERS_ENABLED",
        kind="asgi",
        safe_defaults=_SECURITY_HEADERS_DEFAULTS,
        skip_paths=(),
        skip_prefixes=(),
        skip_methods=frozenset(),
        notes=(
            "Adds conservative security headers to API responses.",
            "Must not leak server version, framework internals, or secrets.",
            "Does not replace TLS, authentication, authorization, or CSP review.",
        ),
    ),
    "performance": MiddlewareSpec(
        name="performance",
        module=".performance",
        class_name="PerformanceMiddleware",
        order=30,
        required=False,
        default_enabled=True,
        enabled_setting="PERFORMANCE_MIDDLEWARE_ENABLED",
        kind="asgi",
        safe_defaults=_PERFORMANCE_DEFAULTS,
        skip_paths=HEALTH_PATHS + METRICS_PATHS,
        skip_prefixes=("/health/", "/metrics/"),
        skip_methods=frozenset({"OPTIONS"}),
        notes=(
            "Measures request latency and logs slow requests safely.",
            "Must not log request/response bodies or query strings by default.",
            "Performance telemetry is not investigative evidence.",
        ),
    ),
}

MIDDLEWARE_REGISTRY: Final[Mapping[str, MiddlewareSpec]] = MappingProxyType(
    _MIDDLEWARE_REGISTRY_RAW
)


def _sorted_middleware_specs() -> tuple[MiddlewareSpec, ...]:
    return tuple(
        sorted(
            MIDDLEWARE_REGISTRY.values(),
            key=lambda spec: (spec.order, spec.name),
        )
    )


MIDDLEWARE_ORDER: Final[tuple[str, ...]] = tuple(
    spec.name for spec in _sorted_middleware_specs()
)


# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------

__all__: Final[tuple[str, ...]] = (
    "MIDDLEWARE_PACKAGE_NAME",
    "MIDDLEWARE_LAYER",
    "MIDDLEWARE_API_PREFIX",
    "REQUEST_ID_HEADER",
    "CORRELATION_ID_HEADER",
    "RESPONSE_TIME_HEADER",
    "RATELIMIT_LIMIT_HEADER",
    "RATELIMIT_REMAINING_HEADER",
    "RATELIMIT_RESET_HEADER",
    "RETRY_AFTER_HEADER",
    "WWW_AUTHENTICATE_HEADER",
    "TRACE_HEADERS",
    "CORS_EXPOSED_HEADERS",
    "SAFE_RESPONSE_HEADERS",
    "PUBLIC_PATHS",
    "PUBLIC_PATH_PREFIXES",
    "HEALTH_PATHS",
    "METRICS_PATHS",
    "DOCS_PATHS",
    "SKIP_METHODS_FOR_AUDIT",
    "SKIP_METHODS_FOR_PERFORMANCE",
    "MIDDLEWARE_SAFETY_FLAGS",
    "MiddlewareKind",
    "MiddlewareSpec",
    "MIDDLEWARE_REGISTRY",
    "MIDDLEWARE_ORDER",
    "RequestIdMiddleware",
    "SecurityHeadersMiddleware",
    "PerformanceMiddleware",
    "get_middleware_spec",
    "get_middleware_class",
    "iter_middleware_specs",
    "install_default_middleware",
    "normalize_path",
    "is_public_path",
    "should_skip_middleware",
    "get_middleware_metadata",
)


# -----------------------------------------------------------------------------
# Lazy module and symbol access
# -----------------------------------------------------------------------------
# Keeps `import app.api.middleware` cheap and avoids circular-import pressure.
#
# Supported patterns:
#
#   from app.api.middleware import request_id
#   from app.api.middleware import RequestIdMiddleware
#   from app.api.middleware import security_headers
#   from app.api.middleware import SecurityHeadersMiddleware
#   from app.api.middleware import performance
#   from app.api.middleware import PerformanceMiddleware

_LAZY_MODULES: Final[dict[str, str]] = {
    "request_id": ".request_id",
    "security_headers": ".security_headers",
    "performance": ".performance",
}

_LAZY_ATTRS: Final[dict[str, tuple[str, str]]] = {
    "RequestIdMiddleware": (".request_id", "RequestIdMiddleware"),
    "SecurityHeadersMiddleware": (".security_headers", "SecurityHeadersMiddleware"),
    "PerformanceMiddleware": (".performance", "PerformanceMiddleware"),
}


def __getattr__(name: str) -> Any:
    """
    Lazily import middleware submodules or selected public middleware classes.
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
            *MIDDLEWARE_REGISTRY.keys(),
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


def _as_int(value: object, default: int) -> int:
    """
    Safely convert a setting to int.
    """
    try:
        return int(value)  # type: ignore[arg-type]
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


def _normalize_string_sequence(values: Any) -> tuple[str, ...]:
    """
    Normalize an iterable, string, or single value into a tuple of strings.
    """
    if values is None:
        return ()

    if isinstance(values, str):
        return (values.strip(),) if values.strip() else ()

    if isinstance(values, Sequence) and not isinstance(values, (bytes, bytearray)):
        return tuple(str(value).strip() for value in values if str(value).strip())

    text_value = str(values).strip()
    return (text_value,) if text_value else ()


def _normalize_frozenset(values: Any) -> frozenset[str]:
    """
    Normalize values into an uppercase frozenset.
    """
    return frozenset(value.upper() for value in _normalize_string_sequence(values))


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
    Return True when a path is considered public by middleware convention.

    This helper does not replace authentication middleware or dependencies.
    It is intended for logging, instrumentation skipping, diagnostics, tests,
    and route-classification consistency.
    """
    normalized = normalize_path(path)

    if normalized in PUBLIC_PATHS:
        return True

    return any(normalized.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES)


def should_skip_middleware(
    path: str | None,
    method: str | None = None,
    *,
    skip_paths: Any = (),
    skip_prefixes: Any = (),
    skip_methods: Any = (),
) -> bool:
    """
    Return True when middleware should skip instrumentation for a request.

    This is a safe convention helper. It must not be used to bypass
    authentication or authorization.
    """
    normalized = normalize_path(path)
    upper_method = str(method or "").strip().upper()

    configured_skip_methods = _normalize_frozenset(skip_methods)

    if upper_method and upper_method in configured_skip_methods:
        return True

    configured_skip_paths = {
        normalize_path(candidate)
        for candidate in _normalize_string_sequence(skip_paths)
    }

    if normalized in configured_skip_paths:
        return True

    configured_skip_prefixes = _normalize_string_sequence(skip_prefixes)

    return any(
        normalized.startswith(prefix)
        for prefix in configured_skip_prefixes
        if prefix
    )


# -----------------------------------------------------------------------------
# Registry helpers
# -----------------------------------------------------------------------------


def iter_middleware_specs() -> tuple[MiddlewareSpec, ...]:
    """
    Return known middleware specs in logical installation order.
    """
    return _sorted_middleware_specs()


def get_middleware_spec(name: str) -> MiddlewareSpec:
    """
    Return a middleware spec by name.

    Raises KeyError when the middleware name is unknown.
    """
    normalized = str(name).strip().lower()

    try:
        return MIDDLEWARE_REGISTRY[normalized]
    except KeyError as exc:
        raise KeyError(f"Unknown middleware: {name}") from exc


def get_middleware_class(name: str) -> Any:
    """
    Lazily import and return a middleware class by registry name.
    """
    spec = get_middleware_spec(name)
    module = import_module(spec.module, __name__)
    middleware_class = getattr(module, spec.class_name, None)

    if middleware_class is None or not callable(middleware_class):
        raise AttributeError(
            f"{spec.module} does not expose callable {spec.class_name}"
        )

    return middleware_class


# -----------------------------------------------------------------------------
# Installation helper
# -----------------------------------------------------------------------------


def install_default_middleware(
    app: Any,
    settings: Any | None = None,
    *,
    force: bool = False,
) -> list[str]:
    """
    Install known default middleware onto a FastAPI/Starlette application.

    This helper is intentionally defensive:

    - skips middleware disabled by configuration;
    - retries without unsupported keyword arguments;
    - raises for required middleware that cannot be imported;
    - marks app.state to avoid double installation unless force=True;
    - does not install CORS, trusted-host, compression, exception handlers, or
      authentication dependencies, because those are owned by application
      factory and dependency layers.

    Returns the list of installed middleware names.
    """
    installed: list[str] = []
    state = getattr(app, "state", None)

    if state is not None and not force:
        if getattr(state, "_muleguard_middleware_installed", False):
            return installed

    for spec in iter_middleware_specs():
        if spec.enabled_setting is not None:
            enabled = _as_bool(
                _read_setting(
                    settings,
                    spec.enabled_setting,
                    spec.default_enabled,
                ),
                spec.default_enabled,
            )

            if not enabled:
                continue

        try:
            middleware_class = get_middleware_class(spec.name)
        except Exception:
            if spec.required:
                raise
            continue

        defaults = dict(spec.safe_defaults)
        added = False

        if settings is not None:
            try:
                app.add_middleware(middleware_class, settings=settings, **defaults)
                added = True
            except TypeError:
                added = False

        if not added:
            try:
                app.add_middleware(middleware_class, **defaults)
                added = True
            except TypeError:
                app.add_middleware(middleware_class)
                added = True

        if added:
            installed.append(spec.name)

    if state is not None:
        setattr(state, "_muleguard_middleware_installed", True)

    return installed


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_middleware_metadata() -> dict[str, Any]:
    """
    Return safe, serializable middleware-layer metadata.

    This is useful for:

    - startup diagnostics;
    - health/readiness payloads;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, or real customer data.
    """
    specs: list[dict[str, Any]] = []

    for spec in iter_middleware_specs():
        specs.append(
            {
                "name": spec.name,
                "module": spec.module,
                "class_name": spec.class_name,
                "order": spec.order,
                "required": spec.required,
                "default_enabled": spec.default_enabled,
                "enabled_setting": spec.enabled_setting,
                "kind": spec.kind,
                "safe_defaults": dict(spec.safe_defaults),
                "skip_paths": list(spec.skip_paths),
                "skip_prefixes": list(spec.skip_prefixes),
                "skip_methods": sorted(spec.skip_methods),
                "notes": list(spec.notes),
            }
        )

    return {
        "package": MIDDLEWARE_PACKAGE_NAME,
        "layer": MIDDLEWARE_LAYER,
        "api_prefix": MIDDLEWARE_API_PREFIX,
        "order": MIDDLEWARE_ORDER,
        "headers": {
            "request_id": REQUEST_ID_HEADER,
            "correlation_id": CORRELATION_ID_HEADER,
            "response_time": RESPONSE_TIME_HEADER,
            "ratelimit_limit": RATELIMIT_LIMIT_HEADER,
            "ratelimit_remaining": RATELIMIT_REMAINING_HEADER,
            "ratelimit_reset": RATELIMIT_RESET_HEADER,
            "retry_after": RETRY_AFTER_HEADER,
            "www_authenticate": WWW_AUTHENTICATE_HEADER,
            "trace_headers": TRACE_HEADERS,
            "cors_exposed_headers": CORS_EXPOSED_HEADERS,
            "safe_response_headers": sorted(SAFE_RESPONSE_HEADERS),
        },
        "paths": {
            "public_paths": PUBLIC_PATHS,
            "public_path_prefixes": PUBLIC_PATH_PREFIXES,
            "health_paths": HEALTH_PATHS,
            "metrics_paths": METRICS_PATHS,
            "docs_paths": DOCS_PATHS,
        },
        "methods": {
            "skip_for_audit": sorted(SKIP_METHODS_FOR_AUDIT),
            "skip_for_performance": sorted(SKIP_METHODS_FOR_PERFORMANCE),
        },
        "safety_flags": dict(MIDDLEWARE_SAFETY_FLAGS),
        "specs": specs,
        "lazy_modules": tuple(sorted(_LAZY_MODULES)),
        "lazy_attributes": tuple(sorted(_LAZY_ATTRS)),
    }