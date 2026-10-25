"""
MULEGUARD backend API v1 router.

This module is the central aggregation point for the versioned `/api/v1`
FastAPI API surface.

Primary responsibilities:

- expose a stable `api_router` object for inclusion in `app.main`;
- lazily import and mount known v1 endpoint routers;
- preserve deterministic endpoint installation order;
- honour feature-flag / module-enablement settings;
- distinguish required versus optional endpoint modules;
- fail closed in production-like environments when required endpoint modules
  are missing;
- allow incremental local development when optional or required endpoint
  modules are not yet implemented, while honestly reporting degraded state;
- expose a safe API v1 metadata endpoint for diagnostics and contract
  visibility;
- avoid importing heavy endpoint dependencies at package-initialisation time
  unless the endpoint module is actually being mounted.

Important boundaries:

- This router is an aggregation layer, not a business-logic layer.
- Endpoint modules remain responsible for request validation, authentication,
  authorization, pagination, bounded graph constraints, evidence integrity,
  audit emission, report safety, and domain service orchestration.
- This router must not fabricate placeholder business endpoints.
- Missing required endpoints must be reported honestly and must not be masked
  by fake responses.
- MULEGUARD remains a synthetic-first investigative prototype. Alerts, scores,
  graph relationships, candidate money trails, and complaint correlations are
  investigative leads only.
"""

from __future__ import annotations

import importlib
import logging
import threading
from collections.abc import Mapping
from typing import Any, Final

from fastapi import APIRouter, HTTPException, Request

from app.api.v1 import (
    API_PREFIX,
    API_VERSION,
    ENDPOINT_REGISTRY,
    OPENAPI_TAGS,
)

logger = logging.getLogger("muleguard.backend.api.v1.router")


# -----------------------------------------------------------------------------
# Boolean parsing helpers
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}


# -----------------------------------------------------------------------------
# Inclusion state
# -----------------------------------------------------------------------------
# This state is intentionally conservative and contains only non-sensitive
# module names, endpoint names, error types, and configuration outcomes.
#
# It must not contain:
#   - secrets;
#   - tokens;
#   - passwords;
#   - database URLs;
#   - raw complaint narratives;
#   - real customer data;
#   - stack traces;
#   - exception messages that may leak internal state.

_STATE_LOCK = threading.Lock()

_INCLUSION_STATE: dict[str, list[dict[str, Any] | str]] = {
    "included": [],
    "disabled": [],
    "missing_required": [],
    "missing_optional": [],
    "errors": [],
}


def _record_event(
    bucket: str,
    payload: dict[str, Any] | str,
) -> None:
    """
    Record a safe router-installation event.
    """
    with _STATE_LOCK:
        _INCLUSION_STATE.setdefault(bucket, []).append(payload)


def get_api_v1_inclusion_state() -> dict[str, Any]:
    """
    Return a safe copy of the API v1 router installation state.

    This is useful for:

    - diagnostics;
    - tests;
    - startup validation;
    - deployment readiness checks;
    - developer tooling.
    """
    with _STATE_LOCK:
        return {
            "included": list(_INCLUSION_STATE.get("included", [])),
            "disabled": list(_INCLUSION_STATE.get("disabled", [])),
            "missing_required": list(_INCLUSION_STATE.get("missing_required", [])),
            "missing_optional": list(_INCLUSION_STATE.get("missing_optional", [])),
            "errors": list(_INCLUSION_STATE.get("errors", [])),
        }


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _setting(settings: Any, name: str, default: Any = None) -> Any:
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


def _csv(value: object) -> list[str]:
    """
    Parse comma-separated settings into a clean list.
    """
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return [part.strip() for part in str(value).split(",") if part.strip()]


def _is_production_like(settings: Any) -> bool:
    """
    Return True when the runtime environment is production-like.
    """
    env = str(_setting(settings, "BACKEND_ENV", "local")).strip().lower()

    configured_values = _csv(
        _setting(
            settings,
            "BACKEND_PRODUCTION_LIKE_ENVS",
            "production,staging,prod,stage",
        )
    )

    production_like_values = {value.lower() for value in configured_values}

    if not production_like_values:
        production_like_values = {"production", "staging", "prod", "stage"}

    return env in production_like_values


def _resolve_settings(request: Request | None = None) -> Any:
    """
    Resolve runtime settings.

    Preference order:

    1. `request.app.state.settings`, when available;
    2. `app.core.config.get_settings()`;
    3. empty mapping fallback.
    """
    if request is not None:
        app = getattr(request, "app", None)
        state = getattr(app, "state", None)
        state_settings = getattr(state, "settings", None)

        if state_settings is not None:
            return state_settings

    try:
        from app.core.config import get_settings

        return get_settings()
    except Exception:
        logger.debug(
            "API v1 router could not resolve application settings; "
            "using empty settings fallback.",
            exc_info=True,
        )
        return {}


def _sorted_endpoint_specs() -> tuple[Any, ...]:
    """
    Return endpoint specs in deterministic installation order.
    """
    return tuple(
        sorted(
            ENDPOINT_REGISTRY.values(),
            key=lambda spec: (
                int(getattr(spec, "order", 1000)),
                str(getattr(spec, "name", "")),
            ),
        )
    )


def _spec_name(spec: Any) -> str:
    return str(getattr(spec, "name", "<unknown>")).strip() or "<unknown>"


def _spec_module(spec: Any) -> str:
    return str(getattr(spec, "module", "<unknown>")).strip() or "<unknown>"


def _spec_prefix(spec: Any) -> str:
    return str(getattr(spec, "prefix", "") or "").strip()


def _spec_tags(spec: Any) -> list[str]:
    tags = getattr(spec, "tags", ()) or ()

    if isinstance(tags, str):
        return [tags]

    return [str(tag).strip() for tag in tags if str(tag).strip()]


def _spec_router_attr(spec: Any) -> str:
    return str(getattr(spec, "router_attr", "router") or "router").strip()


def _spec_required(spec: Any) -> bool:
    return bool(getattr(spec, "required", False))


def _spec_default_enabled(spec: Any) -> bool:
    return bool(getattr(spec, "default_enabled", True))


def _spec_enabled_setting(spec: Any) -> str | None:
    value = getattr(spec, "enabled_setting", None)

    if value is None:
        return None

    normalized = str(value).strip()
    return normalized or None


# -----------------------------------------------------------------------------
# Router construction
# -----------------------------------------------------------------------------

_router_tags = [tag["name"] for tag in OPENAPI_TAGS if isinstance(tag, Mapping) and "name" in tag]

api_router = APIRouter(
    tags=_router_tags,
    redirect_slashes=True,
)


# -----------------------------------------------------------------------------
# Endpoint installation
# -----------------------------------------------------------------------------


def _include_endpoint_router(
    spec: Any,
    settings: Any,
    *,
    strict_required: bool,
) -> bool:
    """
    Attempt to import and include one endpoint router.

    Returns True when the endpoint router was included successfully.

    Behaviour:

    - respects optional enablement settings;
    - skips disabled endpoints safely;
    - records missing optional endpoints;
    - records missing required endpoints;
    - raises RuntimeError for missing required endpoints when strict mode is
      enabled, especially in production-like environments;
    - never fabricates placeholder business routes.
    """
    name = _spec_name(spec)
    module_name = _spec_module(spec)
    prefix = _spec_prefix(spec)
    tags = _spec_tags(spec)
    router_attr = _spec_router_attr(spec)
    required = _spec_required(spec)
    enabled_setting = _spec_enabled_setting(spec)

    # ---------------------------------------------------------------------
    # Feature-flag / module-enablement check
    # ---------------------------------------------------------------------
    if enabled_setting is not None:
        enabled = _as_bool(
            _setting(
                settings,
                enabled_setting,
                _spec_default_enabled(spec),
            ),
            _spec_default_enabled(spec),
        )

        if not enabled:
            _record_event(
                "disabled",
                {
                    "endpoint": name,
                    "module": module_name,
                    "setting": enabled_setting,
                    "required": required,
                },
            )
            logger.info(
                "API v1 endpoint disabled by setting: endpoint=%s setting=%s",
                name,
                enabled_setting,
            )
            return False

    # ---------------------------------------------------------------------
    # Lazy import
    # ---------------------------------------------------------------------
    try:
        module = importlib.import_module(module_name, __package__)
    except ImportError as exc:
        payload = {
            "endpoint": name,
            "module": module_name,
            "required": required,
            "error_type": type(exc).__name__,
        }

        if required:
            _record_event("missing_required", payload)

            if strict_required:
                raise RuntimeError(
                    f"Required API v1 endpoint module is missing: {module_name}"
                ) from exc

            logger.warning(
                "Required API v1 endpoint module is missing; continuing in degraded local mode: "
                "endpoint=%s module=%s error_type=%s",
                name,
                module_name,
                type(exc).__name__,
            )
        else:
            _record_event("missing_optional", payload)

            logger.info(
                "Optional API v1 endpoint module is missing; skipping: "
                "endpoint=%s module=%s error_type=%s",
                name,
                module_name,
                type(exc).__name__,
            )

        return False

    except Exception as exc:
        payload = {
            "endpoint": name,
            "module": module_name,
            "required": required,
            "error_type": type(exc).__name__,
        }

        if required:
            _record_event("errors", payload)

            if strict_required:
                raise RuntimeError(
                    f"Required API v1 endpoint module failed to import: {module_name}"
                ) from exc

            logger.warning(
                "Required API v1 endpoint module failed to import; continuing in degraded local mode: "
                "endpoint=%s module=%s error_type=%s",
                name,
                module_name,
                type(exc).__name__,
            )
        else:
            _record_event("errors", payload)

            logger.warning(
                "Optional API v1 endpoint module failed to import; skipping: "
                "endpoint=%s module=%s error_type=%s",
                name,
                module_name,
                type(exc).__name__,
            )

        return False

    # ---------------------------------------------------------------------
    # Router object resolution
    # ---------------------------------------------------------------------
    endpoint_router = getattr(module, router_attr, None)

    if endpoint_router is None:
        payload = {
            "endpoint": name,
            "module": module_name,
            "required": required,
            "error_type": "MissingRouterAttribute",
            "router_attr": router_attr,
        }

        if required:
            _record_event("missing_required", payload)

            if strict_required:
                raise RuntimeError(
                    f"Required API v1 endpoint module does not expose router attribute "
                    f"{router_attr!r}: {module_name}"
                )

            logger.warning(
                "Required API v1 endpoint module does not expose router attribute; "
                "continuing in degraded local mode: endpoint=%s module=%s router_attr=%s",
                name,
                module_name,
                router_attr,
            )
        else:
            _record_event("missing_optional", payload)

            logger.info(
                "Optional API v1 endpoint module does not expose router attribute; skipping: "
                "endpoint=%s module=%s router_attr=%s",
                name,
                module_name,
                router_attr,
            )

        return False

    # ---------------------------------------------------------------------
    # Mount router
    # ---------------------------------------------------------------------
    try:
        api_router.include_router(
            endpoint_router,
            prefix=prefix,
            tags=tags,
        )
    except TypeError:
        # Some router implementations or older FastAPI versions may not accept
        # tags during include_router. Fall back to prefix-only mounting.
        api_router.include_router(
            endpoint_router,
            prefix=prefix,
        )
    except Exception as exc:
        payload = {
            "endpoint": name,
            "module": module_name,
            "required": required,
            "error_type": type(exc).__name__,
        }

        if required:
            _record_event("errors", payload)

            if strict_required:
                raise RuntimeError(
                    f"Required API v1 endpoint router could not be mounted: {module_name}"
                ) from exc

            logger.warning(
                "Required API v1 endpoint router could not be mounted; "
                "continuing in degraded local mode: endpoint=%s module=%s error_type=%s",
                name,
                module_name,
                type(exc).__name__,
            )
        else:
            _record_event("errors", payload)

            logger.warning(
                "Optional API v1 endpoint router could not be mounted; skipping: "
                "endpoint=%s module=%s error_type=%s",
                name,
                module_name,
                type(exc).__name__,
            )

        return False

    _record_event(
        "included",
        {
            "endpoint": name,
            "module": module_name,
            "prefix": prefix,
            "tags": tags,
            "required": required,
        },
    )

    logger.info(
        "API v1 endpoint mounted: endpoint=%s module=%s prefix=%s",
        name,
        module_name,
        prefix or "/",
    )

    return True


def install_api_v1_endpoint_routers(settings: Any | None = None) -> dict[str, Any]:
    """
    Install all known API v1 endpoint routers.

    This function is idempotent enough for application-factory use, but the
    normal path is to call it once at module import time.

    Returns the inclusion state snapshot.
    """
    resolved_settings = settings if settings is not None else _resolve_settings()

    production_like = _is_production_like(resolved_settings)

    strict_required = _as_bool(
        _setting(
            resolved_settings,
            "API_V1_STRICT_REQUIRED_ENDPOINTS",
            production_like,
        ),
        production_like,
    )

    logger.info(
        "Installing API v1 endpoint routers: environment=%s production_like=%s strict_required=%s",
        str(_setting(resolved_settings, "BACKEND_ENV", "local")),
        production_like,
        strict_required,
    )

    for spec in _sorted_endpoint_specs():
        _include_endpoint_router(
            spec,
            resolved_settings,
            strict_required=strict_required,
        )

    state = get_api_v1_inclusion_state()

    if state["missing_required"] or state["errors"]:
        logger.warning(
            "API v1 router installed with degraded state: missing_required=%s errors=%s",
            len(state["missing_required"]),
            len(state["errors"]),
        )
    else:
        logger.info(
            "API v1 router installed successfully: included=%s disabled=%s",
            len(state["included"]),
            len(state["disabled"]),
        )

    return state


# Install endpoint routers at import time.
#
# In production-like environments, missing required endpoint modules will cause
# startup failure. In local development, missing required modules are recorded
# as degraded state so the application can still be inspected and incrementally
# completed without pretending that unavailable features exist.
install_api_v1_endpoint_routers()


# -----------------------------------------------------------------------------
# Safe API v1 metadata endpoint
# -----------------------------------------------------------------------------


@api_router.get(
    "",
    include_in_schema=True,
    summary="API v1 metadata",
    description=(
        "Returns safe, non-sensitive metadata about the MULEGUARD API v1 "
        "contract and endpoint installation state. "
        "This endpoint does not expose secrets, database URLs, tokens, "
        "passwords, raw complaint narratives, or real customer data."
    ),
    tags=["system"],
)
async def api_v1_metadata(request: Request) -> dict[str, Any]:
    """
    Return safe API v1 metadata and installation state.

    This endpoint is intended for:

    - local development visibility;
    - contract diagnostics;
    - deployment smoke tests;
    - demonstrating that the API surface is real and not fabricated.

    It is disabled by default in production-like environments unless explicitly
    enabled through `API_V1_METADATA_ENDPOINT_ENABLED=true`.
    """
    settings = _resolve_settings(request)
    production_like = _is_production_like(settings)

    enabled = _as_bool(
        _setting(
            settings,
            "API_V1_METADATA_ENDPOINT_ENABLED",
            not production_like,
        ),
        not production_like,
    )

    if not enabled:
        raise HTTPException(status_code=404, detail="Not Found")

    state = get_api_v1_inclusion_state()

    degraded = bool(state["missing_required"] or state["errors"])

    return {
        "name": "MULEGUARD API",
        "version": API_VERSION,
        "prefix": API_PREFIX,
        "status": "degraded" if degraded else "ok",
        "data_classification": "synthetic",
        "production_ready": False,
        "automatic_adverse_action_allowed": False,
        "real_customer_data_allowed": False,
        "safety_notice": (
            "MULEGUARD is a synthetic-first investigative prototype. "
            "Alerts, risk scores, graph relationships, candidate money trails, "
            "and complaint correlations are investigative leads only. "
            "They are not proof of wrongdoing and must not trigger automatic "
            "adverse customer action."
        ),
        "openapi": {
            "title": "MULEGUARD API",
            "version": API_VERSION,
            "path": f"{API_PREFIX}/openapi.json",
        },
        "endpoint_summary": {
            "included": len(state["included"]),
            "disabled": len(state["disabled"]),
            "missing_required": len(state["missing_required"]),
            "missing_optional": len(state["missing_optional"]),
            "errors": len(state["errors"]),
        },
        "endpoints": {
            "included": state["included"],
            "disabled": state["disabled"],
            "missing_required": state["missing_required"],
            "missing_optional": state["missing_optional"],
            "errors": state["errors"],
        },
        "tags": [
            tag["name"]
            for tag in OPENAPI_TAGS
            if isinstance(tag, Mapping) and isinstance(tag.get("name"), str)
        ],
    }


# -----------------------------------------------------------------------------
# Compatibility alias
# -----------------------------------------------------------------------------
# Some application factories may import `router` instead of `api_router`.
router = api_router


__all__ = [
    "api_router",
    "get_api_v1_inclusion_state",
    "install_api_v1_endpoint_routers",
    "router",
]