"""
MULEGUARD backend API v1 health endpoints.

This module implements the versioned `/api/v1/health` surface for safe runtime
diagnostics, liveness, readiness, and detailed synthetic-prototype status.

Implemented endpoints:

- GET /api/v1/health
- GET /api/v1/health/live
- GET /api/v1/health/ready
- GET /api/v1/health/status

Design goals:

- provide honest operational status without exposing secrets or sensitive data;
- keep health endpoints public and dependency-light where practical;
- distinguish liveness, readiness, and detailed diagnostic status;
- report database connectivity safely;
- report ML scoring mode honestly, including explicit fallback;
- report bounded graph policy posture;
- report ingestion, audit, reporting, and auth configuration safety signals;
- preserve MULEGUARD synthetic-first and human-review-only product boundaries;
- avoid fabricating functionality or hiding degraded states.

Explicit non-goals:

- This module does not expose database URLs, credentials, tokens, secrets,
  stack traces, raw complaint narratives, model artifact paths, or real customer
  data.
- This module does not make investigative decisions.
- This module does not implement automatic adverse customer action.
- This module does not claim production readiness.
- This module does not claim real-world fraud-detection accuracy.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, and complaint correlations are
investigative leads only. They are not proof of wrongdoing and must not trigger
automatic adverse customer action.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any, Final, Literal, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from app import APP_NAME, DATA_CLASSIFICATION, __version__
from app.api.deps import RequestIDDep
from app.core.config import get_settings
from app.db import check_database_health

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.health")


# -----------------------------------------------------------------------------
# Optional lifecycle integration
# -----------------------------------------------------------------------------
# The lifecycle manager is preferred when available, but health endpoints must
# remain usable even if lifecycle wiring is incomplete during early bootstrap or
# isolated tests.

try:  # pragma: no cover - exercised indirectly through application startup
    from app.lifecycle import get_lifecycle_manager as _get_lifecycle_manager
except Exception:  # pragma: no cover - fallback for isolated import
    _get_lifecycle_manager = None


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["health"])


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

StatusValue = Literal["ok", "degraded", "not_ready", "failed"]
CheckStatusValue = Literal["ok", "skipped", "degraded", "failed", "unavailable"]

ML_FALLBACK_MODES: Final[frozenset[str]] = frozenset(
    {
        "heuristic_fallback",
        "rules_only",
        "ml_disabled",
        "unknown",
        "auto",
    }
)

ML_TRAINED_MODES: Final[frozenset[str]] = frozenset(
    {
        "trained_model",
    }
)

SAFETY_NOTICE: Final[str] = (
    "MULEGUARD is a synthetic-first investigative prototype. "
    "Alerts, risk scores, graph relationships, candidate money trails, and "
    "complaint correlations are investigative leads only. "
    "They are not proof of wrongdoing and must not trigger automatic adverse "
    "customer action."
)

DEFAULT_SYNTHETIC_BANNER: Final[str] = "SYNTHETIC DEMO DATA"


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


def _as_int(value: object, default: int) -> int:
    """
    Safely convert a setting to int.
    """
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float) -> float:
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


def _now_utc() -> datetime:
    """
    Return timezone-aware UTC current time.
    """
    return datetime.now(timezone.utc)


def _environment(settings: Any) -> str:
    """
    Return normalized runtime environment label.
    """
    return str(_setting(settings, "BACKEND_ENV", "local")).strip().lower() or "local"


def _is_production_like(settings: Any) -> bool:
    """
    Return True when the runtime environment is production-like.
    """
    env = _environment(settings)

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


def _resolve_settings(request: Request) -> Any:
    """
    Resolve runtime settings safely.

    Preference order:

    1. `request.app.state.settings`;
    2. `app.core.config.get_settings()`;
    3. empty mapping fallback.

    Health endpoints must not crash simply because settings resolution fails.
    """
    state = getattr(request.app, "state", None)
    state_settings = getattr(state, "settings", None)

    if state_settings is not None:
        return state_settings

    try:
        return get_settings()
    except Exception:
        logger.debug(
            "Health endpoint could not resolve application settings; "
            "using empty settings fallback.",
            exc_info=True,
        )
        return {}


def _get_lifecycle(request: Request) -> Any | None:
    """
    Return the lifecycle manager when available.
    """
    state = getattr(request.app, "state", None)
    manager = getattr(state, "lifecycle", None)

    if manager is not None:
        return manager

    if _get_lifecycle_manager is not None:
        try:
            return _get_lifecycle_manager()
        except Exception:
            logger.debug(
                "Health endpoint could not resolve lifecycle manager.",
                exc_info=True,
            )

    return None


def _lifecycle_phase(request: Request, manager: Any | None = None) -> str:
    """
    Return a safe lifecycle phase label.
    """
    state = getattr(request.app, "state", None)
    phase = getattr(state, "lifecycle_phase", None)

    if phase:
        return str(phase)

    if manager is None:
        manager = _get_lifecycle(request)

    if manager is not None:
        phase = getattr(manager, "phase", None)
        value = getattr(phase, "value", phase)

        if value:
            return str(value)

    return "unknown"


def _uptime_seconds(request: Request) -> Optional[float]:
    """
    Return safe uptime in seconds when available.
    """
    state = getattr(request.app, "state", None)
    started_at = getattr(state, "start_time", None)

    if isinstance(started_at, (int, float)):
        return round(max(0.0, time.time() - float(started_at)), 3)

    manager = _get_lifecycle(request)

    if manager is not None:
        manager_started_at = getattr(manager, "started_at", None)

        if isinstance(manager_started_at, datetime):
            if manager_started_at.tzinfo is None:
                manager_started_at = manager_started_at.replace(tzinfo=timezone.utc)

            return round(max(0.0, (_now_utc() - manager_started_at).total_seconds()), 3)

    return None


def _unique(values: Iterable[Any]) -> list[str]:
    """
    Return unique stringified values while preserving order.
    """
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        text = str(value).strip()

        if not text or text in seen:
            continue

        seen.add(text)
        result.append(text)

    return result


def _check(
    name: str,
    status: CheckStatusValue,
    message: str,
    *,
    duration_ms: Optional[float] = None,
    details: Optional[dict[str, Any]] = None,
) -> "CheckDetail":
    """
    Build a safe check detail payload.
    """
    return CheckDetail(
        name=str(name),
        status=status,
        message=str(message),
        duration_ms=duration_ms,
        details=details or {},
    )


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class CheckDetail(BaseModel):
    """
    Safe structured result from one health check.
    """

    model_config = ConfigDict(extra="ignore")

    name: str
    status: CheckStatusValue
    message: str
    duration_ms: Optional[float] = None
    details: dict[str, Any] = Field(default_factory=dict)


class BaseStatusResponse(BaseModel):
    """
    Common safe status fields shared by health responses.
    """

    model_config = ConfigDict(extra="ignore")

    app: str
    version: str
    environment: str
    data_classification: str
    synthetic_demo: bool
    production_ready: Literal[False] = False
    timestamp: datetime
    uptime_seconds: Optional[float] = None
    request_id: Optional[str] = None
    banner: str
    safety_notice: str


class LivenessResponse(BaseStatusResponse):
    """
    Minimal liveness payload.

    This endpoint should succeed whenever the process can handle HTTP requests.
    It must not depend on database availability.
    """

    status: Literal["ok"] = "ok"


class ReadinessResponse(BaseStatusResponse):
    """
    Readiness payload.

    The application is ready when required runtime dependencies are available
    and no blocking policy/configuration failures are detected.
    """

    ready: bool
    status: StatusValue
    checks: list[CheckDetail] = Field(default_factory=list)
    database: dict[str, Any] = Field(default_factory=dict)
    ml: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class HealthResponse(BaseStatusResponse):
    """
    Detailed safe health payload.

    This payload is intended for local diagnostics, deployment smoke tests, and
    operational visibility. It must not expose secrets or sensitive data.
    """

    status: StatusValue
    lifecycle_phase: str = "unknown"
    checks: list[CheckDetail] = Field(default_factory=list)
    database: dict[str, Any] = Field(default_factory=dict)
    ml: dict[str, Any] = Field(default_factory=dict)
    auth: dict[str, Any] = Field(default_factory=dict)
    graph: dict[str, Any] = Field(default_factory=dict)
    ingestion: dict[str, Any] = Field(default_factory=dict)
    audit: dict[str, Any] = Field(default_factory=dict)
    reports: dict[str, Any] = Field(default_factory=dict)
    subsystems: dict[str, Any] = Field(default_factory=dict)
    build: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Common payload helper
# -----------------------------------------------------------------------------


def _common_payload(
    request: Request,
    settings: Any,
    request_id: Optional[str],
) -> dict[str, Any]:
    """
    Build common safe response fields.
    """
    dataset_mode = str(
        _setting(settings, "BACKEND_DATASET_MODE", "synthetic")
    ).strip().lower()

    return {
        "app": APP_NAME,
        "version": __version__,
        "environment": _environment(settings),
        "data_classification": DATA_CLASSIFICATION,
        "synthetic_demo": dataset_mode == "synthetic",
        "production_ready": False,
        "timestamp": _now_utc(),
        "uptime_seconds": _uptime_seconds(request),
        "request_id": request_id,
        "banner": str(
            _setting(
                settings,
                "BACKEND_SYNTHETIC_BANNER_TEXT",
                DEFAULT_SYNTHETIC_BANNER,
            )
            or DEFAULT_SYNTHETIC_BANNER
        ),
        "safety_notice": SAFETY_NOTICE,
    }


# -----------------------------------------------------------------------------
# Individual checks
# -----------------------------------------------------------------------------


def _run_lifecycle_check(
    request: Request,
    manager: Any | None,
) -> CheckDetail:
    """
    Report lifecycle phase safely.
    """
    phase = _lifecycle_phase(request, manager)
    details = {"phase": phase}

    if manager is None:
        return _check(
            "lifecycle",
            "skipped",
            "Lifecycle manager not available; basic runtime status only.",
            details=details,
        )

    if phase == "started":
        return _check(
            "lifecycle",
            "ok",
            "Lifecycle startup completed.",
            details=details,
        )

    if phase == "degraded":
        return _check(
            "lifecycle",
            "degraded",
            "Lifecycle startup completed with degraded dependencies or warnings.",
            details=details,
        )

    if phase in {"failed", "stopped", "stopping"}:
        return _check(
            "lifecycle",
            "failed",
            f"Lifecycle phase is not healthy: {phase}.",
            details=details,
        )

    return _check(
        "lifecycle",
        "degraded",
        f"Lifecycle phase is not fully started: {phase}.",
        details=details,
    )


def _run_database_check(settings: Any) -> tuple[CheckDetail, dict[str, Any]]:
    """
    Run a safe database connectivity check.

    This must not expose connection strings, credentials, hostnames, or raw
    driver errors.
    """
    timeout_seconds = max(
        0.1,
        _as_float(_setting(settings, "DB_CONNECT_TIMEOUT_SECONDS", 3.0), 3.0),
    )

    started_at = time.perf_counter()

    try:
        health = check_database_health(timeout_seconds=timeout_seconds)
    except Exception as exc:
        duration_ms = round((time.perf_counter() - started_at) * 1000, 3)
        details = {
            "ok": False,
            "timeout_seconds": timeout_seconds,
            "error_code": "DATABASE_HEALTH_CHECK_ERROR",
            "error_type": type(exc).__name__,
        }

        return (
            _check(
                "database",
                "failed",
                "Database health check raised an unexpected error.",
                duration_ms=duration_ms,
                details=details,
            ),
            details,
        )

    duration_ms = round((time.perf_counter() - started_at) * 1000, 3)

    safe_details = {
        key: health.get(key)
        for key in (
            "ok",
            "dialect",
            "driver",
            "latency_ms",
            "error_code",
        )
        if key in health
    }

    safe_details["timeout_seconds"] = timeout_seconds
    safe_details["check_duration_ms"] = duration_ms

    ok = bool(health.get("ok"))

    if ok:
        return (
            _check(
                "database",
                "ok",
                "Database connectivity check passed.",
                duration_ms=duration_ms,
                details=safe_details,
            ),
            safe_details,
        )

    error_code = str(health.get("error_code") or "")
    status: CheckStatusValue = (
        "unavailable" if error_code == "DATABASE_UNAVAILABLE" else "failed"
    )

    return (
        _check(
            "database",
            status,
            "Database connectivity check failed.",
            duration_ms=duration_ms,
            details=safe_details,
        ),
        safe_details,
    )


def _run_ml_check(
    request: Request,
    settings: Any,
    manager: Any | None,
) -> tuple[CheckDetail, dict[str, Any]]:
    """
    Report ML scoring mode honestly.

    Missing or optional trained artifacts must surface as explicit fallback,
    not as fabricated model confidence.
    """
    enabled = _as_bool(_setting(settings, "ML_ENABLED", True), True)
    require_trained = _as_bool(
        _setting(settings, "ML_REQUIRE_TRAINED_MODEL", False),
        False,
    )
    fallback_label = str(
        _setting(settings, "ML_FALLBACK_MODE_LABEL", "heuristic_fallback")
        or "heuristic_fallback"
    ).strip().lower()

    scoring_mode = getattr(request.app.state, "active_scoring_mode", None)
    model_version = getattr(request.app.state, "active_model_version", None)

    if scoring_mode is None and manager is not None:
        scoring_mode = getattr(manager, "ml_scoring_mode", None)

    if model_version is None and manager is not None:
        model_version = getattr(manager, "model_version", None)

    if scoring_mode is None:
        scoring_mode = _setting(settings, "ML_ACTIVE_SCORING_MODE", "auto")

    scoring_mode = str(scoring_mode or "unknown").strip().lower() or "unknown"
    model_version = str(model_version) if model_version not in (None, "") else None

    details = {
        "enabled": enabled,
        "scoring_mode": scoring_mode,
        "model_version": model_version,
        "require_trained_model": require_trained,
        "fallback_label": fallback_label,
        "trained_model_modes": sorted(ML_TRAINED_MODES),
        "fallback_modes": sorted(ML_FALLBACK_MODES),
    }

    if not enabled:
        if require_trained:
            return (
                _check(
                    "ml",
                    "failed",
                    "ML is disabled but ML_REQUIRE_TRAINED_MODEL=true.",
                    details=details,
                ),
                details,
            )

        return (
            _check(
                "ml",
                "skipped",
                "ML subsystem disabled by configuration.",
                details=details,
            ),
            details,
        )

    if scoring_mode in ML_TRAINED_MODES:
        return (
            _check(
                "ml",
                "ok",
                "ML trained model mode is active.",
                details=details,
            ),
            details,
        )

    if scoring_mode in ML_FALLBACK_MODES:
        if require_trained:
            return (
                _check(
                    "ml",
                    "failed",
                    "ML requires a trained model, but fallback mode is active.",
                    details=details,
                ),
                details,
            )

        return (
            _check(
                "ml",
                "degraded",
                "ML is operating in explicit fallback mode. "
                "Fallback scores are not calibrated model probabilities.",
                details=details,
            ),
            details,
        )

    return (
        _check(
            "ml",
            "degraded",
            "ML scoring mode is unresolved; treating as fallback until preflight completes.",
            details=details,
        ),
        details,
    )


def _run_auth_check(settings: Any) -> tuple[CheckDetail, dict[str, Any]]:
    """
    Report authentication posture safely.

    This does not expose secrets or token material.
    """
    enabled = _as_bool(_setting(settings, "AUTH_ENABLED", True), True)
    mode = str(_setting(settings, "AUTH_MODE", "jwt_bearer") or "jwt_bearer").strip().lower()
    demo_mode = _as_bool(_setting(settings, "AUTH_DEMO_MODE", False), False)
    production_like = _is_production_like(settings)

    details = {
        "enabled": enabled,
        "mode": mode,
        "demo_mode": demo_mode,
        "production_like": production_like,
        "reveal_locked_account": _as_bool(
            _setting(settings, "AUTH_REVEAL_LOCKED_ACCOUNT", False),
            False,
        ),
        "reveal_inactive_account": _as_bool(
            _setting(settings, "AUTH_REVEAL_INACTIVE_ACCOUNT", False),
            False,
        ),
        "access_token_expire_minutes": _as_int(
            _setting(settings, "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES", 30),
            30,
        ),
    }

    if not enabled:
        return (
            _check(
                "auth",
                "degraded",
                "Authentication is disabled. Protected endpoints must fail closed "
                "unless an explicit local unsafe bypass is enabled.",
                details=details,
            ),
            details,
        )

    if production_like and demo_mode:
        return (
            _check(
                "auth",
                "failed",
                "AUTH_DEMO_MODE=true is not allowed in production-like environments.",
                details=details,
            ),
            details,
        )

    if mode != "jwt_bearer":
        return (
            _check(
                "auth",
                "degraded",
                "Only AUTH_MODE=jwt_bearer is implemented by the bundled auth endpoints.",
                details=details,
            ),
            details,
        )

    return (
        _check(
            "auth",
            "ok",
            "Authentication is enabled in supported local JWT bearer mode.",
            details=details,
        ),
        details,
    )


def _run_graph_check(settings: Any) -> tuple[CheckDetail, dict[str, Any]]:
    """
    Report bounded graph policy posture.

    Unbounded whole-bank graph access is prohibited by MULEGUARD safety policy.
    """
    enabled = _as_bool(_setting(settings, "GRAPH_ENABLED", True), True)
    allow_whole_bank = _as_bool(
        _setting(settings, "GRAPH_ALLOW_WHOLE_BANK_QUERY", False),
        False,
    )
    require_root = _as_bool(_setting(settings, "GRAPH_REQUIRE_ROOT", True), True)

    details = {
        "enabled": enabled,
        "allow_whole_bank_query": allow_whole_bank,
        "require_root": require_root,
        "max_hops": _as_int(_setting(settings, "GRAPH_MAX_HOPS", 3), 3),
        "max_nodes": _as_int(_setting(settings, "GRAPH_MAX_NODES", 500), 500),
        "max_edges": _as_int(_setting(settings, "GRAPH_MAX_EDGES", 1500), 1500),
        "max_paths": _as_int(_setting(settings, "GRAPH_MAX_PATHS", 20), 20),
        "max_date_span_days": _as_int(
            _setting(settings, "GRAPH_MAX_DATE_SPAN_DAYS", 90),
            90,
        ),
        "timeout_seconds": _as_int(
            _setting(settings, "GRAPH_TIMEOUT_SECONDS", 15),
            15,
        ),
    }

    if not enabled:
        return (
            _check(
                "graph",
                "skipped",
                "Graph analytics disabled by configuration.",
                details=details,
            ),
            details,
        )

    if allow_whole_bank:
        return (
            _check(
                "graph",
                "failed",
                "GRAPH_ALLOW_WHOLE_BANK_QUERY=true violates MULEGUARD bounded-graph policy.",
                details=details,
            ),
            details,
        )

    if not require_root:
        return (
            _check(
                "graph",
                "failed",
                "GRAPH_REQUIRE_ROOT=false violates MULEGUARD bounded-graph policy.",
                details=details,
            ),
            details,
        )

    return (
        _check(
            "graph",
            "ok",
            "Graph analytics enabled with bounded query policy.",
            details=details,
        ),
        details,
    )


def _run_ingestion_check(settings: Any) -> tuple[CheckDetail, dict[str, Any]]:
    """
    Report ingestion posture and synthetic-first protections.
    """
    enabled = _as_bool(_setting(settings, "INGESTION_ENABLED", True), True)
    max_batch_size = _as_int(
        _setting(settings, "INGESTION_MAX_BATCH_SIZE", 1000),
        1000,
    )
    transactional_batch = _as_bool(
        _setting(settings, "INGESTION_TRANSACTIONAL_BATCH", True),
        True,
    )
    block_real_data = _as_bool(
        _setting(settings, "BACKEND_BLOCK_REAL_DATA_IF_SYNTHETIC_ONLY", True),
        True,
    )
    dataset_mode = str(
        _setting(settings, "BACKEND_DATASET_MODE", "synthetic")
    ).strip().lower()

    details = {
        "enabled": enabled,
        "max_batch_size": max_batch_size,
        "transactional_batch": transactional_batch,
        "block_real_data_if_synthetic_only": block_real_data,
        "dataset_mode": dataset_mode,
    }

    if not enabled:
        return (
            _check(
                "ingestion",
                "skipped",
                "Bulk ingestion disabled by configuration.",
                details=details,
            ),
            details,
        )

    if max_batch_size <= 0:
        return (
            _check(
                "ingestion",
                "failed",
                "INGESTION_MAX_BATCH_SIZE must be positive when ingestion is enabled.",
                details=details,
            ),
            details,
        )

    if dataset_mode == "synthetic" and not block_real_data:
        return (
            _check(
                "ingestion",
                "degraded",
                "Synthetic dataset mode is active but real-data blocking is disabled.",
                details=details,
            ),
            details,
        )

    return (
        _check(
            "ingestion",
            "ok",
            "Ingestion enabled with bounded batch configuration.",
            details=details,
        ),
        details,
    )


def _run_audit_check(settings: Any) -> tuple[CheckDetail, dict[str, Any]]:
    """
    Report audit posture.

    Material case, evidence, analysis, authentication, and report actions should
    leave durable audit records.
    """
    enabled = _as_bool(_setting(settings, "AUDIT_ENABLED", True), True)
    redaction_enabled = _as_bool(
        _setting(settings, "PRIVACY_AUDIT_REDACTION_ENABLED", True),
        True,
    )
    log_denied = _as_bool(_setting(settings, "AUDIT_LOG_DENIED", True), True)

    details = {
        "enabled": enabled,
        "redaction_enabled": redaction_enabled,
        "log_denied": log_denied,
        "retention_days": _as_int(
            _setting(settings, "RETENTION_AUDIT_DAYS", 3650),
            3650,
        ),
    }

    if not enabled:
        return (
            _check(
                "audit",
                "degraded",
                "Audit logging is disabled. Material actions cannot be durably audited.",
                details=details,
            ),
            details,
        )

    if not redaction_enabled:
        return (
            _check(
                "audit",
                "degraded",
                "Audit redaction is disabled. Ensure no secrets or sensitive narratives are logged.",
                details=details,
            ),
            details,
        )

    return (
        _check(
            "audit",
            "ok",
            "Audit logging enabled with redaction posture.",
            details=details,
        ),
        details,
    )


def _run_report_check(settings: Any) -> tuple[CheckDetail, dict[str, Any]]:
    """
    Report PDF investigation report posture.
    """
    enabled = _as_bool(_setting(settings, "REPORT_ENABLED", True), True)
    max_pages = _as_int(_setting(settings, "REPORT_MAX_PAGES", 100), 100)
    max_generation_seconds = _as_int(
        _setting(settings, "REPORT_MAX_GENERATION_SECONDS", 30),
        30,
    )
    include_disclaimer = _as_bool(
        _setting(settings, "REPORT_INCLUDE_SYNTHETIC_DISCLAIMER", True),
        True,
    )
    include_limitations = _as_bool(
        _setting(settings, "REPORT_INCLUDE_LIMITATIONS", True),
        True,
    )

    details = {
        "enabled": enabled,
        "max_pages": max_pages,
        "max_generation_seconds": max_generation_seconds,
        "include_synthetic_disclaimer": include_disclaimer,
        "include_limitations": include_limitations,
        "filename_prefix": str(
            _setting(settings, "REPORT_FILENAME_PREFIX", "muleguard-case-report")
        ),
    }

    if not enabled:
        return (
            _check(
                "reports",
                "skipped",
                "PDF report generation disabled by configuration.",
                details=details,
            ),
            details,
        )

    if max_pages <= 0 or max_generation_seconds <= 0:
        return (
            _check(
                "reports",
                "failed",
                "Report limits must be positive when report generation is enabled.",
                details=details,
            ),
            details,
        )

    if not include_disclaimer or not include_limitations:
        return (
            _check(
                "reports",
                "degraded",
                "Reports should include synthetic disclaimer and limitations text.",
                details=details,
            ),
            details,
        )

    return (
        _check(
            "reports",
            "ok",
            "PDF report generation enabled with safety text configured.",
            details=details,
        ),
        details,
    )


# -----------------------------------------------------------------------------
# Aggregate status collection
# -----------------------------------------------------------------------------


async def _collect_status(
    request: Request,
    settings: Any,
    request_id: Optional[str],
    *,
    include_database: bool = True,
) -> tuple[list[CheckDetail], dict[str, Any]]:
    """
    Collect safe health checks and subsystem status.
    """
    manager = _get_lifecycle(request)
    checks: list[CheckDetail] = []

    lifecycle_check = _run_lifecycle_check(request, manager)
    checks.append(lifecycle_check)

    if include_database:
        database_check, database_details = await asyncio.to_thread(
            _run_database_check,
            settings,
        )
    else:
        database_check = _check(
            "database",
            "skipped",
            "Database check skipped for liveness-style status.",
            details={"ok": None, "skipped": True},
        )
        database_details = {"ok": None, "skipped": True}

    checks.append(database_check)

    ml_check, ml_details = _run_ml_check(request, settings, manager)
    checks.append(ml_check)

    auth_check, auth_details = _run_auth_check(settings)
    checks.append(auth_check)

    graph_check, graph_details = _run_graph_check(settings)
    checks.append(graph_check)

    ingestion_check, ingestion_details = _run_ingestion_check(settings)
    checks.append(ingestion_check)

    audit_check, audit_details = _run_audit_check(settings)
    checks.append(audit_check)

    report_check, report_details = _run_report_check(settings)
    checks.append(report_check)

    warnings: list[Any] = []
    errors: list[Any] = []

    for check in checks:
        if check.status == "degraded":
            warnings.append(check.message)
        elif check.status in {"failed", "unavailable"}:
            errors.append(check.message)

    if manager is not None:
        warnings.extend(getattr(manager, "warnings", []) or [])
        errors.extend(getattr(manager, "errors", []) or [])

    subsystems = {
        "auth": auth_details,
        "database": database_details,
        "ml": ml_details,
        "graph": graph_details,
        "ingestion": ingestion_details,
        "audit": audit_details,
        "reports": report_details,
        "dashboard": {
            "enabled": _as_bool(_setting(settings, "DASHBOARD_ENABLED", True), True),
        },
        "docs": {
            "enabled": _as_bool(_setting(settings, "BACKEND_DOCS_ENABLED", True), True),
            "openapi_enabled": _as_bool(
                _setting(settings, "BACKEND_OPENAPI_ENABLED", True),
                True,
            ),
        },
    }

    build = {
        "service_name": str(
            _setting(settings, "SERVICE_NAME", "muleguard-backend")
            or "muleguard-backend"
        ),
        "build_version": str(_setting(settings, "BUILD_VERSION", __version__) or __version__),
        "build_commit": str(_setting(settings, "BUILD_COMMIT", "unknown") or "unknown"),
        "build_time": str(_setting(settings, "BUILD_TIME", "unknown") or "unknown"),
        "build_branch": str(_setting(settings, "BUILD_BRANCH", "unknown") or "unknown"),
        "build_source": str(_setting(settings, "BUILD_SOURCE", "local") or "local"),
    }

    bits = {
        "lifecycle_phase": _lifecycle_phase(request, manager),
        "database": database_details,
        "ml": ml_details,
        "auth": auth_details,
        "graph": graph_details,
        "ingestion": ingestion_details,
        "audit": audit_details,
        "reports": report_details,
        "subsystems": subsystems,
        "build": {key: value for key, value in build.items() if value},
        "warnings": _unique(warnings),
        "errors": _unique(errors),
        "database_check": database_check,
    }

    return checks, bits


def _health_status(
    checks: list[CheckDetail],
    database_check: CheckDetail,
) -> StatusValue:
    """
    Compute overall detailed health status.
    """
    if database_check.status != "ok":
        return "not_ready"

    if any(check.status in {"failed", "unavailable"} for check in checks):
        return "degraded"

    if any(check.status == "degraded" for check in checks):
        return "degraded"

    return "ok"


def _readiness_status(
    checks: list[CheckDetail],
    database_check: CheckDetail,
) -> tuple[bool, StatusValue]:
    """
    Compute readiness boolean and status.

    Readiness is false when required dependencies are unavailable or when
    blocking policy/configuration failures are detected.
    """
    if database_check.status != "ok":
        return False, "not_ready"

    if any(check.status in {"failed", "unavailable"} for check in checks):
        return False, "not_ready"

    if any(check.status == "degraded" for check in checks):
        return True, "degraded"

    return True, "ok"


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "/live",
    response_model=LivenessResponse,
    summary="Liveness probe",
    description=(
        "Returns a minimal safe liveness payload. "
        "This endpoint should succeed whenever the process can handle HTTP "
        "requests and must not depend on database availability."
    ),
)
async def liveness(
    request: Request,
    request_id: RequestIDDep,
) -> LivenessResponse:
    """
    Minimal liveness endpoint.
    """
    settings = _resolve_settings(request)

    return LivenessResponse(
        status="ok",
        **_common_payload(
            request=request,
            settings=settings,
            request_id=request_id,
        ),
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    description=(
        "Returns a safe readiness payload. "
        "The application is considered ready when required runtime dependencies "
        "are available and no blocking policy/configuration failures are detected. "
        "ML fallback mode is allowed and surfaced explicitly; it is not treated "
        "as a calibrated model probability."
    ),
)
async def readiness(
    request: Request,
    request_id: RequestIDDep,
) -> ReadinessResponse:
    """
    Readiness endpoint.
    """
    settings = _resolve_settings(request)

    checks, bits = await _collect_status(
        request=request,
        settings=settings,
        request_id=request_id,
        include_database=True,
    )

    database_check: CheckDetail = bits["database_check"]
    ready, status = _readiness_status(checks, database_check)

    return ReadinessResponse(
        ready=ready,
        status=status,
        checks=checks,
        database=bits["database"],
        ml=bits["ml"],
        warnings=bits["warnings"],
        errors=bits["errors"],
        **_common_payload(
            request=request,
            settings=settings,
            request_id=request_id,
        ),
    )


@router.get(
    "",
    response_model=HealthResponse,
    summary="Detailed API v1 health",
    description=(
        "Returns a detailed but safe health payload for the MULEGUARD backend. "
        "This endpoint is intended for local diagnostics, deployment smoke tests, "
        "and operational visibility. It must not expose secrets, database URLs, "
        "tokens, passwords, raw complaint narratives, model artifact paths, or "
        "real customer data."
    ),
)
async def health(
    request: Request,
    request_id: RequestIDDep,
) -> HealthResponse:
    """
    Detailed health endpoint.
    """
    settings = _resolve_settings(request)

    checks, bits = await _collect_status(
        request=request,
        settings=settings,
        request_id=request_id,
        include_database=True,
    )

    database_check: CheckDetail = bits["database_check"]
    status = _health_status(checks, database_check)

    return HealthResponse(
        status=status,
        lifecycle_phase=bits["lifecycle_phase"],
        checks=checks,
        database=bits["database"],
        ml=bits["ml"],
        auth=bits["auth"],
        graph=bits["graph"],
        ingestion=bits["ingestion"],
        audit=bits["audit"],
        reports=bits["reports"],
        subsystems=bits["subsystems"],
        build=bits["build"],
        warnings=bits["warnings"],
        errors=bits["errors"],
        **_common_payload(
            request=request,
            settings=settings,
            request_id=request_id,
        ),
    )


@router.get(
    "/status",
    response_model=HealthResponse,
    summary="Detailed API v1 status alias",
    description=(
        "Alias for GET /api/v1/health. "
        "Provided for operational tooling that expects a status path."
    ),
)
async def health_status(
    request: Request,
    request_id: RequestIDDep,
) -> HealthResponse:
    """
    Alias for the detailed health endpoint.
    """
    return await health(request=request, request_id=request_id)


__all__ = [
    "router",
]