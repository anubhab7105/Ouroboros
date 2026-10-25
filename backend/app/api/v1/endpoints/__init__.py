"""
MULEGUARD backend API v1 endpoints package.

This module is the public entry point for the concrete `/api/v1` endpoint
modules used by the MULEGUARD FastAPI backend.

Its responsibilities are intentionally narrow:

- expose stable endpoint-package metadata;
- provide lazy access to individual endpoint modules;
- provide safe helpers for resolving endpoint routers;
- provide machine-readable endpoint metadata for diagnostics and tests;
- avoid eager imports of FastAPI routers, SQLAlchemy models, Pydantic schemas,
  ML services, graph services, report generators, ingestion pipelines, case
  workflows, audit systems, or complaint correlation engines during package
  initialization.

This package must not become a place where heavy runtime logic is executed at
import time.

Canonical endpoint installation order and feature-flag metadata are defined in:

    app.api.v1.ENDPOINT_REGISTRY

This package mirrors only the minimum information required for lazy imports and
safe diagnostics.

Product-safety expectations for endpoint modules:

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

import importlib
import importlib.util
import sys
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final

# -----------------------------------------------------------------------------
# Execution guard
# -----------------------------------------------------------------------------
# This package is intended to be imported as part of the backend application.
# Direct execution is not a supported entrypoint.
if __package__ in {None, ""}:
    raise RuntimeError(
        "Do not execute app/api/v1/endpoints/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Canonical parent metadata, with defensive fallback for isolated imports
# -----------------------------------------------------------------------------
# The canonical endpoint registry lives in app.api.v1. Importing it here keeps
# this package aligned with the router installation contract while still
# allowing isolated diagnostic imports if the parent package is unavailable.

try:
    from app.api.v1 import (
        API_PREFIX as _PARENT_API_PREFIX,
        API_VERSION as _PARENT_API_VERSION,
        ENDPOINT_REGISTRY as _PARENT_ENDPOINT_REGISTRY,
        OPENAPI_TAGS as _PARENT_OPENAPI_TAGS,
    )

    _HAS_PARENT_REGISTRY: Final[bool] = True

except Exception:  # pragma: no cover - fallback for isolated module import
    _PARENT_API_PREFIX = "/api/v1"
    _PARENT_API_VERSION = "v1"
    _PARENT_ENDPOINT_REGISTRY = None
    _PARENT_OPENAPI_TAGS = ()
    _HAS_PARENT_REGISTRY = False


PACKAGE_NAME: Final[str] = "muleguard.backend.api.v1.endpoints"
API_PREFIX: Final[str] = str(_PARENT_API_PREFIX or "/api/v1")
API_VERSION: Final[str] = str(_PARENT_API_VERSION or "v1")


# -----------------------------------------------------------------------------
# Fallback endpoint order
# -----------------------------------------------------------------------------
# Used only when the canonical parent registry cannot be imported. In normal
# application use, app.api.v1.ENDPOINT_REGISTRY is the source of truth.

_FALLBACK_ENDPOINT_NAMES: Final[tuple[str, ...]] = (
    "health",
    "auth",
    "dashboard",
    "accounts",
    "transactions",
    "analysis",
    "alerts",
    "graph",
    "complaints",
    "entities",
    "ingestion",
    "cases",
    "users",
    "audit",
    "reports",
    "model_metrics",
)

_FALLBACK_REQUIRED_ENDPOINTS: Final[frozenset[str]] = frozenset(
    {
        "health",
        "auth",
        "accounts",
        "transactions",
        "analysis",
        "alerts",
        "graph",
        "complaints",
        "cases",
    }
)


def _computed_endpoint_names() -> tuple[str, ...]:
    """
    Return endpoint names in deterministic installation order.

    Preference order:

    1. canonical app.api.v1.ENDPOINT_REGISTRY, when available;
    2. local fallback order.
    """
    if _HAS_PARENT_REGISTRY and _PARENT_ENDPOINT_REGISTRY:
        return tuple(
            sorted(
                _PARENT_ENDPOINT_REGISTRY.keys(),
                key=lambda name: (
                    int(getattr(_PARENT_ENDPOINT_REGISTRY[name], "order", 1000)),
                    str(name),
                ),
            )
        )

    return _FALLBACK_ENDPOINT_NAMES


ENDPOINT_NAMES: Final[tuple[str, ...]] = _computed_endpoint_names()


# -----------------------------------------------------------------------------
# Lazy module map
# -----------------------------------------------------------------------------
# Keeps `import app.api.v1.endpoints` cheap and avoids circular-import pressure.
#
# Supported patterns:
#
#   from app.api.v1.endpoints import health
#   from app.api.v1.endpoints import graph
#   from app.api.v1.endpoints import cases
#
# Missing endpoint modules raise normal ImportError/ModuleNotFoundError at the
# point of use rather than failing the entire package import.

_LAZY_MODULES: Final[dict[str, str]] = {
    name: f".{name}" for name in ENDPOINT_NAMES
}

_MODULE_CACHE: dict[str, Any] = {}


# -----------------------------------------------------------------------------
# Endpoint-package safety flags
# -----------------------------------------------------------------------------
# These are declarative policy markers. Runtime enforcement must still exist in
# endpoint modules, dependencies, services, middleware, tests, and deployment
# controls.

_ENDPOINT_PACKAGE_SAFETY_FLAGS_RAW: Final[dict[str, bool]] = {
    "endpoint_modules_are_not_business_logic_containers": True,
    "endpoint_modules_must_use_typed_dependencies": True,
    "endpoint_modules_must_enforce_server_side_authorization": True,
    "endpoint_modules_must_not_bypass_services_for_critical_workflows": True,
    "list_endpoints_must_be_paginated_and_stably_ordered": True,
    "graph_endpoints_must_remain_bounded": True,
    "money_trails_are_candidate_flow_paths_only": True,
    "complaint_correlations_must_preserve_exact_vs_inferred_provenance": True,
    "ml_outputs_must_expose_scoring_mode_and_model_version": True,
    "fallback_must_not_be_presented_as_calibrated_probability": True,
    "alerts_scores_and_graph_relationships_are_investigative_leads_only": True,
    "no_automatic_adverse_customer_action": True,
    "no_real_customer_data_by_default": True,
    "no_fake_functionality": True,
    "no_secret_logging": True,
    "no_stack_trace_leakage": True,
}

ENDPOINT_PACKAGE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    _ENDPOINT_PACKAGE_SAFETY_FLAGS_RAW
)


# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------

__all__: Final[tuple[str, ...]] = (
    "PACKAGE_NAME",
    "API_PREFIX",
    "API_VERSION",
    "ENDPOINT_NAMES",
    "ENDPOINT_PACKAGE_SAFETY_FLAGS",
    "endpoint_module_available",
    "get_endpoint_metadata",
    "get_endpoint_module",
    "get_endpoint_router",
    "get_endpoints_metadata",
    "iter_endpoint_names",
)


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------


def _normalize_endpoint_name(name: Any) -> str:
    """
    Normalize an endpoint name to a lowercase string.
    """
    return str(name).strip().lower()


def _known_endpoint_name(name: Any) -> bool:
    """
    Return True when the endpoint name is known by this package.
    """
    return _normalize_endpoint_name(name) in ENDPOINT_NAMES


def _spec_for(name: Any) -> Any | None:
    """
    Return the canonical endpoint spec from app.api.v1, when available.
    """
    normalized = _normalize_endpoint_name(name)

    if _HAS_PARENT_REGISTRY and _PARENT_ENDPOINT_REGISTRY is not None:
        return _PARENT_ENDPOINT_REGISTRY.get(normalized)

    return None


def _spec_value(spec: Any | None, attr: str, default: Any) -> Any:
    """
    Read an attribute from an endpoint spec with a safe default.
    """
    if spec is None:
        return default

    return getattr(spec, attr, default)


def _full_prefix(prefix: str | None) -> str:
    """
    Return the full API prefix for an endpoint module.

    Endpoint registry prefixes are usually relative, for example `/graph`.
    This helper converts them to `/api/v1/graph`.
    """
    normalized = str(prefix or "").strip()

    if not normalized:
        return API_PREFIX

    if normalized.startswith(API_PREFIX):
        return normalized

    if not normalized.startswith("/"):
        normalized = f"/{normalized}"

    return f"{API_PREFIX}{normalized}"


# -----------------------------------------------------------------------------
# Endpoint introspection
# -----------------------------------------------------------------------------


def iter_endpoint_names() -> tuple[str, ...]:
    """
    Return known endpoint names in deterministic order.
    """
    return ENDPOINT_NAMES


def endpoint_module_available(name: str) -> bool:
    """
    Return True when the endpoint module can be found without importing it.

    This is a lightweight diagnostic helper. It does not guarantee that the
    module imports successfully or exposes a valid router.
    """
    normalized = _normalize_endpoint_name(name)

    if not _known_endpoint_name(normalized):
        return False

    if normalized in _MODULE_CACHE:
        return True

    try:
        spec = importlib.util.find_spec(f".{normalized}", __name__)
        return spec is not None
    except Exception:
        return False


def get_endpoint_module(name: str) -> Any:
    """
    Lazily import and return an endpoint module by name.

    Example:

        health_module = get_endpoint_module("health")
        graph_module = get_endpoint_module("graph")

    Raises:
        KeyError: when the endpoint name is unknown.
        ModuleNotFoundError: when the endpoint module does not exist.
        ImportError: when the endpoint module exists but fails to import.
    """
    normalized = _normalize_endpoint_name(name)

    if not _known_endpoint_name(normalized):
        raise KeyError(f"Unknown API v1 endpoint: {name}")

    cached = _MODULE_CACHE.get(normalized)

    if cached is not None:
        return cached

    module = importlib.import_module(f".{normalized}", __name__)
    _MODULE_CACHE[normalized] = module
    return module


def get_endpoint_router(name: str) -> Any:
    """
    Lazily import an endpoint module and return its FastAPI router.

    The expected router attribute is usually `router`, but the canonical
    endpoint spec may override it through `router_attr`.

    Raises:
        KeyError: when the endpoint name is unknown.
        ModuleNotFoundError: when the endpoint module does not exist.
        ImportError: when the endpoint module exists but fails to import.
        AttributeError: when the module does not expose the expected router.
    """
    module = get_endpoint_module(name)
    spec = _spec_for(name)
    router_attr = str(_spec_value(spec, "router_attr", "router") or "router").strip()

    router = getattr(module, router_attr, None)

    if router is None:
        raise AttributeError(
            f"API v1 endpoint module {module.__name__!r} does not expose "
            f"router attribute {router_attr!r}."
        )

    return router


def get_endpoint_metadata(name: str) -> dict[str, Any]:
    """
    Return safe metadata for one endpoint module.

    This metadata is intended for diagnostics, tests, and documentation checks.
    It must not expose secrets, database URLs, tokens, passwords, raw complaint
    narratives, or real customer data.
    """
    normalized = _normalize_endpoint_name(name)

    if not _known_endpoint_name(normalized):
        raise KeyError(f"Unknown API v1 endpoint: {name}")

    spec = _spec_for(name)

    if spec is None:
        # Fallback metadata for isolated imports.
        try:
            order = (_FALLBACK_ENDPOINT_NAMES.index(normalized) + 1) * 10
        except ValueError:
            order = 1000

        prefix = f"/{normalized}"
        tags: tuple[str, ...] = (normalized,)
        required = normalized in _FALLBACK_REQUIRED_ENDPOINTS
        default_enabled = True
        enabled_setting = None
        router_attr = "router"
        notes: tuple[str, ...] = ()
    else:
        prefix = str(_spec_value(spec, "prefix", f"/{normalized}") or f"/{normalized}")

        raw_tags = _spec_value(spec, "tags", (normalized,))

        if isinstance(raw_tags, str):
            tags = (raw_tags,)
        else:
            tags = tuple(
                str(tag).strip()
                for tag in raw_tags
                if str(tag).strip()
            ) or (normalized,)

        order = int(_spec_value(spec, "order", 1000))
        required = bool(_spec_value(spec, "required", False))
        default_enabled = bool(_spec_value(spec, "default_enabled", True))

        raw_enabled_setting = _spec_value(spec, "enabled_setting", None)

        if raw_enabled_setting is None:
            enabled_setting = None
        else:
            enabled_setting = str(raw_enabled_setting).strip() or None

        router_attr = str(_spec_value(spec, "router_attr", "router") or "router")

        raw_notes = _spec_value(spec, "notes", ())

        if isinstance(raw_notes, str):
            notes = (raw_notes,)
        else:
            notes = tuple(
                str(note).strip()
                for note in raw_notes
                if str(note).strip()
            )

    return {
        "name": normalized,
        "module": f".{normalized}",
        "absolute_module": f"{__name__}.{normalized}",
        "prefix": prefix,
        "full_prefix": _full_prefix(prefix),
        "tags": list(tags),
        "order": order,
        "router_attr": router_attr,
        "required": required,
        "default_enabled": default_enabled,
        "enabled_setting": enabled_setting,
        "notes": list(notes),
    }


def get_endpoints_metadata(
    *,
    include_availability: bool = False,
    include_installation_state: bool = False,
) -> dict[str, Any]:
    """
    Return safe metadata for all known API v1 endpoint modules.

    Parameters
    ----------
    include_availability:
        When True, include a lightweight `available` flag for each endpoint
        module. This uses importlib.util.find_spec and does not import endpoint
        modules.

    include_installation_state:
        When True, attempt to import app.api.v1.router and include the router
        installation state. This may import endpoint modules and should only be
        used for diagnostics or tests.

    The returned payload is intentionally non-sensitive.
    """
    endpoints: list[dict[str, Any]] = []

    for name in ENDPOINT_NAMES:
        metadata = get_endpoint_metadata(name)

        if include_availability:
            metadata["available"] = endpoint_module_available(name)

        endpoints.append(metadata)

    payload: dict[str, Any] = {
        "package": PACKAGE_NAME,
        "api_version": API_VERSION,
        "api_prefix": API_PREFIX,
        "endpoint_count": len(ENDPOINT_NAMES),
        "endpoint_names": list(ENDPOINT_NAMES),
        "endpoints": endpoints,
        "safety_flags": dict(ENDPOINT_PACKAGE_SAFETY_FLAGS),
        "openapi_tags": [
            dict(tag)
            for tag in _PARENT_OPENAPI_TAGS
            if isinstance(tag, Mapping)
        ],
        "canonical_registry_available": _HAS_PARENT_REGISTRY,
    }

    if include_installation_state:
        try:
            from app.api.v1.router import get_api_v1_inclusion_state

            payload["installation_state"] = get_api_v1_inclusion_state()
        except Exception as exc:
            payload["installation_state_error_type"] = type(exc).__name__

    return payload


# -----------------------------------------------------------------------------
# Lazy module access
# -----------------------------------------------------------------------------


def __getattr__(name: str) -> Any:
    """
    Lazily import endpoint modules by attribute access.

    Example:

        from app.api.v1.endpoints import graph

    This keeps package import cheap and avoids loading all endpoint routers
    during application startup.
    """
    if name in _LAZY_MODULES:
        module = get_endpoint_module(name)
        globals()[name] = module
        return module

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )


def __dir__() -> list[str]:
    """
    Return a deterministic directory listing including lazily available endpoint
    modules.
    """
    return sorted(
        {
            *globals().keys(),
            *_LAZY_MODULES.keys(),
        }
    )