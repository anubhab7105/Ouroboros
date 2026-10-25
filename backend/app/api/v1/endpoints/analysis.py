"""
MULEGUARD backend API v1 analysis endpoints.

This module implements the versioned `/api/v1/analysis` surface for triggering,
inspecting, and auditing synthetic batch analysis runs.

Implemented endpoints:

- GET  /api/v1/analysis/status
- GET  /api/v1/analysis/runs
- POST /api/v1/analysis/runs
- GET  /api/v1/analysis/runs/{run_id}
- GET  /api/v1/analysis/runs/{run_id}/results
- GET  /api/v1/analysis/runs/{run_id}/history
- POST /api/v1/analysis/runs/{run_id}/cancel

Design goals:

- provide real, persisted, auditable analysis-run orchestration;
- enforce server-side RBAC through dependency permissions;
- keep list endpoints paginated, filtered, searched, and stably ordered;
- require bounded account selection unless explicitly enabled by configuration;
- preserve point-in-time correctness through `as_of`;
- expose scoring mode and model version honestly;
- distinguish trained-model mode from heuristic/rules-only fallback;
- avoid exposing synthetic ground-truth labels, scenario IDs, ring IDs,
  passwords, tokens, secrets, database URLs, raw complaint narratives, or real
  customer data;
- make clear that alerts, scores, graph relationships, candidate money trails,
  entity links, and complaint correlations are investigative leads only.

Explicit non-goals:

- This module does not freeze, block, blacklist, close, restrict, or otherwise
  take adverse action against accounts or customers.
- This module does not connect to real banking systems.
- This module does not compute ML scores inline. It orchestrates a persisted
  analysis service.
- This module does not fabricate placeholder analysis results.
- This module does not claim production readiness or real-world fraud-detection
  accuracy.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, and complaint
correlations are investigative leads only. They are not proof of wrongdoing and
must not trigger automatic adverse customer action.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import logging
import threading
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Final, Optional

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    IdempotencyKeyDep,
    PageParams,
    Permission,
    RequestIDDep,
    SearchParams,
    SessionDep,
    SettingsDep,
    apply_pagination,
    pagination_dependency,
    rate_limited,
    require_permission,
    search_dependency,
)
from app.exceptions import (
    ConflictError,
    FeatureFlagDisabledError,
    IdempotencyConflictError,
    InternalError,
    MuleGuardError,
    NotFoundError,
    PermissionDeniedError,
    ServiceUnavailableError,
    SyntheticDataRequiredError,
    ValidationError as MuleGuardValidationError,
)
from app.models import (
    Account,
    AccountStatus,
    AccountType,
    Alert,
    AlertState,
    AnalysisRun,
    AnalysisRunStatus,
    AuditEvent,
    AuditOutcome,
    ModelAssessment,
    Priority,
    RiskBand,
    ScoringMode,
    User,
    UserRole,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.analysis")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["analysis"])


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_REASON_LENGTH: Final[int] = 1000
_MAX_NOTE_LENGTH: Final[int] = 1000
_MAX_RESPONSE_LIST_LENGTH: Final[int] = 100
_MAX_PARAM_LIST_LENGTH: Final[int] = 5000
_MAX_MAPPING_KEYS: Final[int] = 100
_MAX_JSON_DEPTH: Final[int] = 6
_MAX_BUNDLE_ITEMS: Final[int] = 100
_MAX_ACCOUNT_IDS_IN_ERROR: Final[int] = 10

_IDEMPOTENCY_CACHE_MAX_ENTRIES: Final[int] = 10_000

_SERVICE_UNAVAILABLE_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "ANALYSIS_SERVICE_UNAVAILABLE",
        "ANALYSIS_SERVICE_INCOMPLETE",
        "ANALYSIS_SERVICE_IMPORT_FAILED",
    }
)

_ANALYSIS_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Analysis runs are investigative prioritisation workflows, not enforcement actions.",
    "Alerts and risk scores are investigative leads only and are not proof of wrongdoing.",
    "Risk scores are investigative priority scores, not probabilities of guilt.",
    "Scoring mode and model version must be interpreted honestly.",
    "Heuristic fallback scores are not calibrated model probabilities.",
    "Entity links, graph relationships, candidate money trails, and complaint correlations are investigative leads only.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    "This API does not freeze, block, blacklist, close, or otherwise take adverse action against accounts or customers.",
    "Analysis uses point-in-time data only when the configured analysis service enforces temporal correctness.",
)

_RESULTS_CAVEATS: Final[tuple[str, ...]] = (
    *_ANALYSIS_CAVEATS,
    "Run results are bounded and may be truncated.",
    "Raw complaint narratives are intentionally not returned.",
    "Assessment explanations are investigative context only.",
)

_HISTORY_CAVEATS: Final[tuple[str, ...]] = (
    *_ANALYSIS_CAVEATS,
    "Analysis history contains safe audit metadata only.",
    "Passwords, tokens, secrets, raw narratives, and unnecessary sensitive payloads are not stored in audit metadata.",
)

_CANCEL_CAVEATS: Final[tuple[str, ...]] = (
    *_ANALYSIS_CAVEATS,
    "Cancellation only affects the MULEGUARD analysis-run workflow.",
    "Cancellation does not close, freeze, block, blacklist, or restrict any account.",
)

_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "apikey",
        "auth_header",
        "authorization",
        "bearer",
        "body",
        "card_number",
        "cookie",
        "credential",
        "credentials",
        "cvv",
        "id_token",
        "identifier_hash",
        "narrative",
        "narrative_raw",
        "narrative_normalized",
        "otp",
        "pan",
        "pass",
        "passwd",
        "password",
        "password_hash",
        "payload_hash",
        "pin",
        "private_key",
        "raw_payload",
        "refresh_token",
        "secret",
        "secret_key",
        "session",
        "source_payload_hash",
        "token",
    }
)

_SENSITIVE_KEY_TOKENS: Final[tuple[str, ...]] = (
    "access_key",
    "account_number",
    "api_key",
    "apikey",
    "authorization",
    "card_number",
    "credential",
    "customer_data",
    "customer_id",
    "device_id",
    "email_address",
    "fraud",
    "ground_truth",
    "hash",
    "ifsc",
    "identifier_hash",
    "ip_address",
    "label",
    "narrative",
    "passphrase",
    "password",
    "passwd",
    "payload_hash",
    "phone_number",
    "private_key",
    "raw_",
    "real_data",
    "refresh_token",
    "ring",
    "scenario",
    "secret",
    "secret_key",
    "token",
    "upi_id",
)


# -----------------------------------------------------------------------------
# Idempotency cache
# -----------------------------------------------------------------------------
# This is intentionally process-local and non-durable. It reduces accidental
# duplicate submissions in local/demo use. Distributed idempotency requires a
# shared store and is not claimed here.

_IDEMPOTENCY_LOCK = threading.Lock()
_IDEMPOTENCY_CACHE: dict[str, tuple[str, str]] = {}


# -----------------------------------------------------------------------------
# Dynamic column helpers
# -----------------------------------------------------------------------------


def _model_column(model: Any, name: str) -> Any | None:
    """
    Return a SQLAlchemy column attribute when present.

    This keeps the endpoint module resilient to incremental schema evolution
    while still allowing typed queries against the expected MULEGUARD models.
    """
    return getattr(model, name, None)


def _build_column_map(model: Any, names: Sequence[str]) -> dict[str, Any]:
    """
    Build a safe column map containing only attributes that exist.
    """
    column_map: dict[str, Any] = {}

    for name in names:
        column = _model_column(model, name)

        if column is not None:
            column_map[name] = column

    return column_map


_ANALYSIS_RUN_COLUMN_MAP: Final[dict[str, Any]] = _build_column_map(
    AnalysisRun,
    (
        "id",
        "created_at",
        "updated_at",
        "started_at",
        "finished_at",
        "status",
        "scoring_mode",
        "account_count",
        "assessment_count",
        "alert_count",
        "requested_by",
    ),
)

_ASSESSMENT_COLUMN_MAP: Final[dict[str, Any]] = _build_column_map(
    ModelAssessment,
    (
        "id",
        "scored_at",
        "as_of",
        "score",
        "risk_band",
        "scoring_mode",
    ),
)

_ALERT_COLUMN_MAP: Final[dict[str, Any]] = _build_column_map(
    Alert,
    (
        "id",
        "created_at",
        "priority",
        "state",
        "score",
        "first_seen_at",
        "last_seen_at",
    ),
)

_HISTORY_COLUMN_MAP: Final[dict[str, Any]] = _build_column_map(
    AuditEvent,
    (
        "id",
        "created_at",
        "action",
        "outcome",
        "actor_username",
    ),
)

_RUN_TIEBREAKER = _model_column(AnalysisRun, "id")
_ASSESSMENT_TIEBREAKER = _model_column(ModelAssessment, "id")
_ALERT_TIEBREAKER = _model_column(Alert, "id")
_HISTORY_TIEBREAKER = _model_column(AuditEvent, "id")

_RUN_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _ANALYSIS_RUN_COLUMN_MAP
    else ("id" if "id" in _ANALYSIS_RUN_COLUMN_MAP else "created_at")
)

_ASSESSMENT_DEFAULT_SORT: Final[str] = (
    "scored_at"
    if "scored_at" in _ASSESSMENT_COLUMN_MAP
    else ("id" if "id" in _ASSESSMENT_COLUMN_MAP else "scored_at")
)

_HISTORY_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _HISTORY_COLUMN_MAP
    else ("id" if "id" in _HISTORY_COLUMN_MAP else "created_at")
)


# -----------------------------------------------------------------------------
# Reusable bounded dependencies
# -----------------------------------------------------------------------------

run_pagination = pagination_dependency(
    sortable_fields=tuple(_ANALYSIS_RUN_COLUMN_MAP.keys()),
    default_sort_by=_RUN_DEFAULT_SORT,
    default_sort_order="desc",
)

result_pagination = pagination_dependency(
    sortable_fields=tuple(_ASSESSMENT_COLUMN_MAP.keys()),
    default_sort_by=_ASSESSMENT_DEFAULT_SORT,
    default_sort_order="desc",
    max_page_size=100,
    hard_max_page_size=100,
)

history_pagination = pagination_dependency(
    sortable_fields=tuple(_HISTORY_COLUMN_MAP.keys()),
    default_sort_by=_HISTORY_DEFAULT_SORT,
    default_sort_order="desc",
)

run_search = search_dependency(max_length=200, alias="q")


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


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    """
    Normalize datetimes to timezone-aware UTC.

    Naive datetimes are assumed to already be UTC.
    """
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _enum_str(value: Any) -> Optional[str]:
    """
    Return a stable string for enum-like values.
    """
    if value is None:
        return None

    return str(getattr(value, "value", value))


def _normalize_role(value: Any) -> str:
    """
    Normalize a role-like value to an uppercase role string.
    """
    if isinstance(value, UserRole):
        return value.value

    return str(value).strip().upper().replace(" ", "_").replace("-", "_")


def _coerce_enum(enum_cls: Any, value: Any, default: Any = None) -> Any:
    """
    Coerce a value to an enum member when possible.
    """
    if value is None:
        return default

    if isinstance(value, enum_cls):
        return value

    normalized = str(value).strip().upper().replace(" ", "_").replace("-", "_")

    try:
        return enum_cls(normalized)
    except ValueError:
        return default


def _clean_text(value: Any, limit: int = _MAX_STRING_LENGTH) -> str:
    """
    Return a safe single-line text value.
    """
    text = str(value or "")
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if len(text) > limit:
        return text[:limit]

    return text


def _safe_string_list(
    value: Any,
    *,
    max_items: int = _MAX_RESPONSE_LIST_LENGTH,
) -> list[str]:
    """
    Return a bounded list of safe strings.
    """
    if value is None:
        return []

    if isinstance(value, str):
        candidates: Sequence[Any] = [value]
    elif isinstance(value, Mapping):
        return []
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        candidates = value
    else:
        candidates = [value]

    seen: set[str] = set()
    result: list[str] = []

    for item in candidates:
        text = _clean_text(item, _MAX_STRING_LENGTH)

        if not text:
            continue

        if text in seen:
            continue

        seen.add(text)
        result.append(text)

        if len(result) >= max_items:
            break

    return result


def _is_sensitive_key(key: str) -> bool:
    """
    Return True when a metadata key appears sensitive or leakage-prone.
    """
    lowered = key.strip().lower()

    if lowered in _SENSITIVE_KEYS:
        return True

    return any(token in lowered for token in _SENSITIVE_KEY_TOKENS)


def _sanitize_json_value(
    value: Any,
    depth: int = 0,
    *,
    max_sequence_length: int = _MAX_RESPONSE_LIST_LENGTH,
    max_mapping_keys: int = _MAX_MAPPING_KEYS,
) -> Any:
    """
    Convert an arbitrary JSON-like value into a safe response value.
    """
    if depth > _MAX_JSON_DEPTH:
        return "[truncated-depth]"

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return value

    if isinstance(value, str):
        return _clean_text(value, _MAX_STRING_LENGTH)

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Enum):
        return _sanitize_json_value(
            value.value,
            depth + 1,
            max_sequence_length=max_sequence_length,
            max_mapping_keys=max_mapping_keys,
        )

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        return _sanitize_json_object(
            value,
            depth + 1,
            max_sequence_length=max_sequence_length,
            max_mapping_keys=max_mapping_keys,
        )

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        original_length = len(value)
        limited = list(value)[:max_sequence_length]
        items = [
            _sanitize_json_value(
                item,
                depth + 1,
                max_sequence_length=max_sequence_length,
                max_mapping_keys=max_mapping_keys,
            )
            for item in limited
        ]

        if original_length > max_sequence_length:
            items.append({"_truncated": True})

        return items

    return f"<{type(value).__name__}>"


def _sanitize_json_object(
    value: Mapping[Any, Any],
    depth: int = 0,
    *,
    max_sequence_length: int = _MAX_RESPONSE_LIST_LENGTH,
    max_mapping_keys: int = _MAX_MAPPING_KEYS,
) -> dict[str, Any]:
    """
    Return a sanitized JSON object suitable for API responses.
    """
    if depth > _MAX_JSON_DEPTH:
        return {"_truncated": True}

    sanitized: dict[str, Any] = {}

    for raw_key, raw_value in list(value.items())[:max_mapping_keys]:
        key = str(raw_key)

        if _is_sensitive_key(key):
            continue

        sanitized[key] = _sanitize_json_value(
            raw_value,
            depth + 1,
            max_sequence_length=max_sequence_length,
            max_mapping_keys=max_mapping_keys,
        )

        if len(sanitized) >= max_mapping_keys:
            sanitized["_truncated_keys"] = True
            break

    return sanitized


def _response_metadata(value: Any) -> Any:
    """
    Sanitize metadata_json-like values before returning them in API responses.
    """
    if isinstance(value, Mapping):
        return _sanitize_json_object(value)

    if value is None:
        return None

    return _sanitize_json_value(value)


def _param_metadata(value: Any) -> Any:
    """
    Sanitize parameter-like values for persisted analysis-run parameters.

    Parameter payloads may legitimately contain larger bounded lists, such as
    explicit account IDs, than general response metadata.
    """
    if isinstance(value, Mapping):
        return _sanitize_json_object(
            value,
            max_sequence_length=_MAX_PARAM_LIST_LENGTH,
            max_mapping_keys=200,
        )

    if value is None:
        return None

    return _sanitize_json_value(
        value,
        max_sequence_length=_MAX_PARAM_LIST_LENGTH,
        max_mapping_keys=200,
    )


def _total_pages(total: int, page_size: int) -> int:
    """
    Compute bounded total page count.
    """
    if total <= 0 or page_size <= 0:
        return 0

    return (total + page_size - 1) // page_size


def _apply_conditions(stmt: Any, conditions: list[Any]) -> Any:
    """
    Apply a list of SQLAlchemy conditions to a statement.
    """
    if conditions:
        stmt = stmt.where(and_(*conditions))

    return stmt


def _scalar_count(db: Session, stmt: Any) -> int:
    """
    Execute a count statement and return an int.
    """
    return int(db.scalar(stmt) or 0)


def _set_if_exists(obj: Any, name: str, value: Any) -> None:
    """
    Set an attribute only when it exists on the object.
    """
    if hasattr(obj, name):
        setattr(obj, name, value)


def _get_if_exists(obj: Any, name: str, default: Any = None) -> Any:
    """
    Get an attribute only when it exists on the object.
    """
    return getattr(obj, name, default)


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


def _validate_not_future(value: Optional[datetime], field_name: str) -> None:
    """
    Reject future point-in-time parameters.
    """
    if value is not None and value > _now_utc():
        raise MuleGuardValidationError(
            f"{field_name} must not be in the future.",
            details={field_name: value.isoformat()},
        )


def _validate_date_range(
    start: Optional[datetime],
    end: Optional[datetime],
    start_name: str,
    end_name: str,
) -> None:
    """
    Validate optional date-range ordering.
    """
    if start is not None and end is not None and start > end:
        raise MuleGuardValidationError(
            f"{start_name} must be earlier than or equal to {end_name}.",
            details={
                start_name: start.isoformat(),
                end_name: end.isoformat(),
            },
        )


def _validate_span(
    start: Optional[datetime],
    end: Optional[datetime],
    field_prefix: str,
    settings: Any,
) -> None:
    """
    Enforce optional maximum date span for analysis scans.
    """
    if start is None or end is None:
        return

    max_days = max(
        1,
        _as_int(_setting(settings, "ANALYSIS_MAX_DATE_SPAN_DAYS", 3650), 3650),
    )

    span = end - start
    max_delta = timedelta(days=max_days)

    if span > max_delta:
        raise MuleGuardValidationError(
            "Analysis date span exceeds configured maximum.",
            details={
                f"{field_prefix}_max_span_days": max_days,
                f"{field_prefix}_requested_span_days": round(
                    span.total_seconds() / 86400.0,
                    3,
                ),
            },
        )


def _client_ip(request: Request, settings: Any) -> str:
    """
    Return a best-effort client IP.

    Proxy headers are trusted only when BACKEND_TRUST_PROXY_HEADERS=true.
    """
    trust_proxy = _as_bool(
        _setting(settings, "BACKEND_TRUST_PROXY_HEADERS", False),
        False,
    )

    if trust_proxy:
        forwarded_for = request.headers.get("X-Forwarded-For")

        if forwarded_for:
            first = forwarded_for.split(",", 1)[0].strip()

            if first:
                return first

        real_ip = request.headers.get("X-Real-IP")

        if real_ip:
            return real_ip.strip()

    if request.client and request.client.host:
        return request.client.host

    return ""


def _hash_salt(settings: Any) -> str:
    """
    Return a salt for non-secret hashing such as IP hashes.
    """
    return str(
        _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
        or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
        or _setting(settings, "BACKEND_SECRET_KEY", None)
        or "muleguard-analysis"
    )


def _hash_value(value: str, salt: str) -> str:
    """
    Return a stable SHA-256 hash for safe audit storage.
    """
    payload = f"{salt}:{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ip_hash(request: Request, settings: Any) -> Optional[str]:
    """
    Return a hashed client IP for audit storage, or None when disabled.
    """
    mode = str(_setting(settings, "PRIVACY_IP_LOG_MODE", "hashed")).strip().lower()

    if mode in {"none", "off", "disabled"}:
        return None

    ip = _client_ip(request, settings)

    if not ip:
        return None

    return _hash_value(ip, _hash_salt(settings))


def _safe_metadata(metadata: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return sanitized audit metadata.
    """
    if not metadata:
        return {}

    safe: dict[str, Any] = {}

    for raw_key, raw_value in list(metadata.items())[:50]:
        key = str(raw_key).strip()

        if not key or _is_sensitive_key(key):
            continue

        if raw_value is None:
            safe[key] = None
            continue

        if isinstance(raw_value, bool):
            safe[key] = raw_value
            continue

        if isinstance(raw_value, int):
            safe[key] = raw_value
            continue

        if isinstance(raw_value, float):
            safe[key] = raw_value
            continue

        if isinstance(raw_value, str):
            safe[key] = _clean_text(raw_value, _MAX_STRING_LENGTH)
            continue

        safe[key] = _clean_text(raw_value, _MAX_STRING_LENGTH)

    return safe


def _note_metadata(note: Optional[str], *, limit: int = 200) -> dict[str, Any]:
    """
    Return safe audit metadata for an optional note.
    """
    if not note:
        return {}

    cleaned = _clean_text(note, limit)

    return {
        "note_length": len(note),
        "note_excerpt": cleaned,
    }


def _add_audit_event(
    db: Session,
    *,
    action: str,
    outcome: AuditOutcome,
    request_id: Optional[str] = None,
    actor: Optional[User] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_hash: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Add a safe audit event to the current session.

    The caller is responsible for committing the transaction.
    """
    event = AuditEvent(
        actor_id=str(actor.id) if actor is not None else None,
        actor_username=str(actor.username) if actor is not None else None,
        actor_role=_enum_str(actor.role) if actor is not None else None,
        action=str(action)[:100],
        resource_type=str(resource_type)[:100] if resource_type is not None else None,
        resource_id=str(resource_id)[:128] if resource_id is not None else None,
        outcome=outcome,
        request_id=str(request_id)[:64] if request_id is not None else None,
        ip_hash=ip_hash,
        metadata_json=_safe_metadata(metadata),
    )

    db.add(event)


# -----------------------------------------------------------------------------
# Analysis policy helpers
# -----------------------------------------------------------------------------


def _ensure_analysis_enabled(settings: Any) -> None:
    """
    Fail closed when the analysis API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "ANALYSIS_ENABLED", True), True):
        raise FeatureFlagDisabledError("Analysis endpoints are disabled by configuration.")

    if _as_bool(_setting(settings, "ANALYSIS_REQUIRE_SYNTHETIC_DATA", True), True):
        mode = str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower()

        if mode != "synthetic":
            raise SyntheticDataRequiredError(
                "Analysis requires BACKEND_DATASET_MODE=synthetic unless explicitly overridden."
            )


def _analysis_max_accounts(settings: Any) -> int:
    """
    Return bounded maximum account selection size for one analysis run.
    """
    configured = max(
        1,
        _as_int(_setting(settings, "ANALYSIS_MAX_ACCOUNTS", 1000), 1000),
    )
    hard_cap = max(
        configured,
        _as_int(_setting(settings, "ANALYSIS_HARD_MAX_ACCOUNTS", 50_000), 50_000),
    )

    return min(configured, hard_cap)


def _analysis_allow_all_accounts(settings: Any) -> bool:
    """
    Return True when analysis may select all accounts without explicit IDs.

    Default is False to avoid accidental whole-bank scans.
    """
    return _as_bool(_setting(settings, "ANALYSIS_ALLOW_ALL_ACCOUNTS", False), False)


def _analysis_service_module_candidates(settings: Any) -> list[tuple[str, list[str]]]:
    """
    Return candidate analysis service modules and function names.
    """
    default_functions = [
        "execute_analysis_run",
        "run_analysis",
        "run",
        "analyze",
    ]

    candidates: list[tuple[str, list[str]]] = []

    configured = _setting(settings, "ANALYSIS_SERVICE_MODULE", None)

    if configured:
        configured_text = str(configured).strip()

        if ":" in configured_text:
            module_name, function_name = configured_text.split(":", 1)
            module_name = module_name.strip()
            function_name = function_name.strip()

            if module_name and function_name:
                candidates.append((module_name, [function_name]))
        elif configured_text:
            candidates.append((configured_text, default_functions))

    candidates.extend(
        [
            ("app.services.analysis", default_functions),
            ("app.analysis.service", default_functions),
            ("app.ml.analysis", default_functions),
        ]
    )

    return candidates


def _load_analysis_service(settings: Any) -> tuple[Any | None, str | None]:
    """
    Load the configured or default analysis service callable.

    Returns `(callable, label)` or `(None, None)` when unavailable.
    """
    for module_name, function_names in _analysis_service_module_candidates(settings):
        try:
            module = importlib.import_module(module_name)
        except Exception:
            logger.debug(
                "Analysis service module unavailable: %s",
                module_name,
                exc_info=True,
            )
            continue

        for function_name in function_names:
            candidate = getattr(module, function_name, None)

            if callable(candidate):
                return candidate, f"{module_name}.{function_name}"

    return None, None


def _call_analysis_service_with_known_kwargs(
    fn: Any,
    *,
    db: Session,
    run: AnalysisRun,
    settings: Any,
) -> Any:
    """
    Invoke an analysis service using compatible keyword or positional arguments.

    Supported common signatures include:

    - execute_analysis_run(db, run, settings)
    - run_analysis(session, analysis_run, config)
    - run(db, run)
    - analyze(run)
    """
    available = {
        "db": db,
        "run": run,
        "settings": settings,
        "run_id": str(run.id),
    }

    aliases = {
        "session": "db",
        "analysis_run": "run",
        "run_obj": "run",
        "config": "settings",
    }

    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):
        signature = None

    if signature is not None:
        kwargs: dict[str, Any] = {}
        missing_required = False

        for parameter_name, parameter in signature.parameters.items():
            resolved_name = parameter_name

            if resolved_name not in available and resolved_name in aliases:
                resolved_name = aliases[resolved_name]

            if resolved_name in available:
                kwargs[parameter_name] = available[resolved_name]
            elif parameter.default is inspect.Parameter.empty:
                missing_required = True
                break

        if not missing_required:
            return fn(**kwargs)

    positional_attempts = (
        (db, run, settings),
        (db, run),
        (run, settings),
        (run,),
    )

    last_error: Exception | None = None

    for args in positional_attempts:
        try:
            return fn(*args)
        except TypeError as exc:
            last_error = exc
            continue

    if last_error is not None:
        raise last_error

    raise TypeError("Analysis service signature is not compatible.")


def _invoke_analysis_service(
    fn: Any,
    *,
    db: Session,
    run: AnalysisRun,
    settings: Any,
) -> Any:
    """
    Invoke the analysis service and reject async services in this sync endpoint.
    """
    result = _call_analysis_service_with_known_kwargs(fn, db=db, run=run, settings=settings)

    if inspect.isawaitable(result):
        close = getattr(result, "close", None)

        if callable(close):
            try:
                close()
            except Exception:
                logger.debug("Failed to close async analysis service result.", exc_info=True)

        raise TypeError(
            "Async analysis service is not supported by the synchronous analysis endpoint."
        )

    return result


def _apply_service_result(run: AnalysisRun, result: Any) -> None:
    """
    Apply service result fields to the run object when present.
    """
    if result is None:
        return

    mutable_keys = (
        "status",
        "scoring_mode",
        "model_version_id",
        "model_version",
        "started_at",
        "finished_at",
        "account_count",
        "assessment_count",
        "alert_count",
        "error_code",
        "error_message",
        "summary_json",
        "parameters_json",
    )

    if isinstance(result, Mapping):
        for key in mutable_keys:
            if key not in result:
                continue

            value = result[key]

            if key == "status":
                value = _coerce_enum(AnalysisRunStatus, value, run.status)
            elif key == "scoring_mode":
                value = _coerce_enum(ScoringMode, value, run.scoring_mode)

            _set_if_exists(run, key, value)

        return

    if hasattr(result, "id") and str(_get_if_exists(result, "id", "")) == str(run.id):
        for key in mutable_keys:
            if not hasattr(result, key):
                continue

            value = getattr(result, key)

            if key == "status":
                value = _coerce_enum(AnalysisRunStatus, value, run.status)
            elif key == "scoring_mode":
                value = _coerce_enum(ScoringMode, value, run.scoring_mode)

            _set_if_exists(run, key, value)


_TERMINAL_STATUSES: Final[set[AnalysisRunStatus]] = {
    AnalysisRunStatus.SUCCEEDED,
    AnalysisRunStatus.FAILED,
    AnalysisRunStatus.CANCELLED,
    AnalysisRunStatus.PARTIAL,
}

_TERMINAL_STATUS_VALUES: Final[set[str]] = {
    status.value for status in _TERMINAL_STATUSES
}


def _is_terminal_status(status: Any) -> bool:
    """
    Return True when a run status is terminal.
    """
    status_value = _enum_str(status)

    if status_value is None:
        return False

    return status_value in _TERMINAL_STATUS_VALUES


def _safe_error_code(exc: Exception) -> str:
    """
    Return a safe error code from an exception.
    """
    if isinstance(exc, MuleGuardError):
        return _clean_text(exc.code, 100)

    return "ANALYSIS_EXECUTION_FAILED"


def _safe_error_message(exc: Exception) -> str:
    """
    Return a safe error message from an exception.
    """
    if isinstance(exc, MuleGuardError):
        return _clean_text(exc.message, _MAX_STRING_LENGTH)

    return "Analysis execution failed."


def _mark_run_failed(
    db: Session,
    run: AnalysisRun,
    *,
    actor: User,
    request: Request,
    settings: Any,
    request_id: str,
    error_code: str,
    error_message: str,
) -> None:
    """
    Mark a run failed, audit the failure, and commit.
    """
    now = _now_utc()

    _set_if_exists(run, "status", AnalysisRunStatus.FAILED)
    _set_if_exists(run, "finished_at", now)
    _set_if_exists(run, "error_code", _clean_text(error_code, 100))
    _set_if_exists(run, "error_message", _clean_text(error_message, _MAX_STRING_LENGTH))

    _add_audit_event(
        db,
        action="analysis_run_failed",
        outcome=AuditOutcome.FAILURE,
        request_id=request_id,
        actor=actor,
        resource_type="analysis_run",
        resource_id=str(run.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "error_code": _clean_text(error_code, 100),
            "error_message": _clean_text(error_message, 256),
            "account_count": int(_get_if_exists(run, "account_count", 0) or 0),
            "scoring_mode": _enum_str(_get_if_exists(run, "scoring_mode", None)),
        },
    )

    db.commit()


def _raise_for_failed_run(run: AnalysisRun) -> None:
    """
    Raise a safe API error for a failed run.
    """
    error_code = str(_get_if_exists(run, "error_code", "") or "ANALYSIS_EXECUTION_FAILED")
    error_message = str(_get_if_exists(run, "error_message", "") or "Analysis run failed.")

    details = {
        "run_id": str(run.id),
        "error_code": error_code,
        "error_message": _clean_text(error_message, 256),
    }

    if error_code in _SERVICE_UNAVAILABLE_ERROR_CODES:
        raise ServiceUnavailableError(
            message="Analysis service is unavailable.",
            details=details,
        )

    raise InternalError(
        message="Analysis run failed.",
        details=details,
    )


# -----------------------------------------------------------------------------
# Account selection helpers
# -----------------------------------------------------------------------------


class AccountFilterRequest(BaseModel):
    """
    Optional bounded filters used when selecting all accounts.
    """

    model_config = ConfigDict(extra="forbid")

    account_type: Optional[AccountType] = Field(
        default=None,
        description="Filter by synthetic account type.",
    )
    status: Optional[AccountStatus] = Field(
        default=None,
        description="Filter by synthetic account status.",
    )
    created_from: Optional[datetime] = Field(
        default=None,
        description="Filter accounts created at or after this UTC timestamp.",
    )
    created_to: Optional[datetime] = Field(
        default=None,
        description="Filter accounts created at or before this UTC timestamp.",
    )


class AnalysisRunRequest(BaseModel):
    """
    Request to trigger a bounded synthetic analysis run.
    """

    model_config = ConfigDict(extra="forbid")

    account_ids: Optional[list[str]] = Field(
        default=None,
        description=(
            "Explicit synthetic account IDs to analyse. When omitted, all-account "
            "selection is used only if ANALYSIS_ALLOW_ALL_ACCOUNTS=true."
        ),
    )
    account_filters: Optional[AccountFilterRequest] = Field(
        default=None,
        description="Optional filters used only for all-account selection.",
    )
    as_of: Optional[datetime] = Field(
        default=None,
        description=(
            "Point-in-time cutoff for analysis. Defaults to current UTC time. "
            "Future values are rejected."
        ),
    )
    options: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "Optional non-sensitive analysis options. Sensitive or leakage-prone "
            "keys are removed."
        ),
    )

    @field_validator("account_ids")
    @classmethod
    def _validate_account_ids(cls, value: Optional[list[str]]) -> Optional[list[str]]:
        if value is None:
            return None

        normalized: list[str] = []
        seen: set[str] = set()

        for item in value:
            text = str(item).strip()

            if not text:
                raise ValueError("account_ids must not contain empty values")

            if len(text) > 128:
                raise ValueError("account_id is too long")

            if text in seen:
                continue

            seen.add(text)
            normalized.append(text)

        return normalized


def _account_filter_conditions(
    filters: Optional[AccountFilterRequest],
    settings: Any,
) -> list[Any]:
    """
    Build SQLAlchemy conditions for optional all-account filters.
    """
    if filters is None:
        return []

    conditions: list[Any] = []

    account_type_column = _model_column(Account, "account_type")
    status_column = _model_column(Account, "status")
    created_at_column = _model_column(Account, "created_at")

    if filters.account_type is not None and account_type_column is not None:
        conditions.append(account_type_column == filters.account_type)

    if filters.status is not None and status_column is not None:
        conditions.append(status_column == filters.status)

    created_from = _ensure_utc(filters.created_from)
    created_to = _ensure_utc(filters.created_to)

    _validate_date_range(created_from, created_to, "created_from", "created_to")
    _validate_span(created_from, created_to, "account_created", settings)

    if created_from is not None and created_at_column is not None:
        conditions.append(created_at_column >= created_from)

    if created_to is not None and created_at_column is not None:
        conditions.append(created_at_column <= created_to)

    return conditions


def _validate_account_selection(
    db: Session,
    settings: Any,
    payload: AnalysisRunRequest,
) -> tuple[Optional[list[str]], int, Optional[dict[str, Any]]]:
    """
    Validate and bound the account selection for an analysis run.

    Returns:

        (account_ids, account_count, filter_payload)

    `account_ids` is None for all-account selection.
    """
    max_accounts = _analysis_max_accounts(settings)

    if payload.account_ids is not None:
        account_ids = list(payload.account_ids)

        if len(account_ids) > max_accounts:
            raise MuleGuardValidationError(
                "Account selection exceeds configured maximum.",
                details={
                    "max_accounts": max_accounts,
                    "requested_accounts": len(account_ids),
                },
            )

        if not account_ids:
            return [], 0, None

        rows = db.scalars(
            select(Account.id).where(Account.id.in_(account_ids))
        ).all()

        existing_ids = {str(row) for row in rows}
        missing_ids = [account_id for account_id in account_ids if account_id not in existing_ids]

        if missing_ids:
            raise MuleGuardValidationError(
                "One or more account IDs were not found.",
                details={
                    "missing_count": len(missing_ids),
                    "missing_sample": missing_ids[:_MAX_ACCOUNT_IDS_IN_ERROR],
                },
            )

        return account_ids, len(account_ids), None

    if not _analysis_allow_all_accounts(settings):
        raise MuleGuardValidationError(
            "account_ids is required unless ANALYSIS_ALLOW_ALL_ACCOUNTS=true.",
            details={
                "setting": "ANALYSIS_ALLOW_ALL_ACCOUNTS",
                "max_accounts": max_accounts,
            },
        )

    conditions = _account_filter_conditions(payload.account_filters, settings)

    count_stmt = select(func.count()).select_from(Account)
    count_stmt = _apply_conditions(count_stmt, conditions)
    account_count = _scalar_count(db, count_stmt)

    if account_count > max_accounts:
        raise MuleGuardValidationError(
            "All-account selection exceeds configured maximum.",
            details={
                "max_accounts": max_accounts,
                "matched_accounts": account_count,
                "hint": "Provide explicit account_ids or narrow account_filters.",
            },
        )

    filter_payload = None

    if payload.account_filters is not None:
        filter_payload = _param_metadata(
            payload.account_filters.model_dump(mode="json", exclude_none=True)
        )

    return None, account_count, filter_payload


def _sanitize_options(options: Optional[dict[str, Any]]) -> dict[str, Any]:
    """
    Sanitize non-sensitive analysis options.
    """
    if not options:
        return {}

    if not isinstance(options, Mapping):
        return {}

    return _param_metadata(options) or {}


def _build_parameters(
    *,
    payload: AnalysisRunRequest,
    actor: User,
    request_id: str,
    idempotency_key: Optional[str],
    account_ids: Optional[list[str]],
    account_count: int,
    filter_payload: Optional[dict[str, Any]],
    as_of: datetime,
    settings: Any,
) -> dict[str, Any]:
    """
    Build sanitized persisted analysis-run parameters.
    """
    options = _sanitize_options(payload.options)

    parameters: dict[str, Any] = {
        "schema_version": "analysis-run-v1",
        "selection": {
            "mode": "explicit" if account_ids is not None else "all",
            "account_count": int(account_count),
        },
        "as_of": as_of.isoformat(),
        "options": options,
        "requested_by": str(actor.id),
        "request_id": request_id,
        "dataset_mode": str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")),
        "environment": str(_setting(settings, "BACKEND_ENV", "local")),
    }

    if account_ids is not None:
        parameters["account_ids"] = list(account_ids)

    if filter_payload:
        parameters["account_filters"] = filter_payload

    if idempotency_key:
        parameters["idempotency_key_hash"] = hashlib.sha256(
            idempotency_key.encode("utf-8")
        ).hexdigest()

    return _param_metadata(parameters) or {}


def _payload_hash(parameters: Mapping[str, Any]) -> str:
    """
    Return a stable hash for idempotency conflict detection.
    """
    canonical = json.dumps(
        parameters,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _idempotency_cache_key(actor_id: str, key: str) -> str:
    """
    Return a process-local idempotency cache key.
    """
    raw = f"{actor_id}\x00{key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _remember_idempotency(cache_key: str, payload_hash: str, run_id: str) -> None:
    """
    Store an idempotency mapping in the process-local cache.
    """
    with _IDEMPOTENCY_LOCK:
        if len(_IDEMPOTENCY_CACHE) >= _IDEMPOTENCY_CACHE_MAX_ENTRIES:
            try:
                oldest_key = next(iter(_IDEMPOTENCY_CACHE))
            except StopIteration:
                oldest_key = None

            if oldest_key is not None:
                _IDEMPOTENCY_CACHE.pop(oldest_key, None)

        _IDEMPOTENCY_CACHE[cache_key] = (payload_hash, run_id)


def _lookup_idempotency(cache_key: str) -> tuple[str, str] | None:
    """
    Return `(payload_hash, run_id)` from the process-local cache.
    """
    with _IDEMPOTENCY_LOCK:
        return _IDEMPOTENCY_CACHE.get(cache_key)


def _forget_idempotency(cache_key: str) -> None:
    """
    Remove an idempotency mapping from the process-local cache.
    """
    with _IDEMPOTENCY_LOCK:
        _IDEMPOTENCY_CACHE.pop(cache_key, None)


# -----------------------------------------------------------------------------
# User helpers
# -----------------------------------------------------------------------------


def _username_for_user_id(db: Session, user_id: Optional[str]) -> Optional[str]:
    """
    Return a username for a user ID, or None when unavailable.
    """
    if not user_id:
        return None

    row = db.execute(
        select(User.username).where(User.id == str(user_id)).limit(1)
    ).first()

    if row is None:
        return None

    return str(row[0])


def _username_map_for_user_ids(
    db: Session,
    user_ids: Sequence[Optional[str]],
) -> dict[str, str]:
    """
    Return a bounded username map for a set of user IDs.
    """
    ids = {str(user_id) for user_id in user_ids if user_id}

    if not ids:
        return {}

    rows = db.execute(
        select(User.id, User.username).where(User.id.in_(list(ids)))
    ).all()

    return {str(row[0]): str(row[1]) for row in rows}


# -----------------------------------------------------------------------------
# Run lookup helpers
# -----------------------------------------------------------------------------


def _get_run_or_404(db: Session, run_id: str) -> AnalysisRun:
    """
    Load an analysis run or raise a safe not-found error.
    """
    run = db.get(AnalysisRun, run_id)

    if run is None:
        raise NotFoundError.resource("analysis_run", run_id)

    return run


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class AnalysisRunResponse(BaseModel):
    """
    Safe analysis-run response.
    """

    model_config = ConfigDict(from_attributes=False, populate_by_name=True)

    id: str
    status: str
    scoring_mode: str
    version_id: Optional[str] = Field(default=None, alias="model_version_id")
    version_label: Optional[str] = Field(default=None, alias="model_version")
    requested_by: Optional[str] = None
    requested_by_username: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    account_count: int = 0
    assessment_count: int = 0
    alert_count: int = 0
    parameters_json: Optional[Any] = None
    summary_json: Optional[Any] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    caveats: list[str] = Field(default_factory=list)


class AnalysisRunListResponse(BaseModel):
    """
    Paginated analysis-run list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[AnalysisRunResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class AnalysisAssessmentResponse(BaseModel):
    """
    Safe assessment row produced by an analysis run.
    """

    model_config = ConfigDict(from_attributes=False, populate_by_name=True)

    id: str
    account_id: str
    as_of: datetime
    scored_at: datetime
    scoring_mode: str
    score: Optional[Decimal] = None
    score_type: Optional[str] = None
    risk_band: str
    version_id: Optional[str] = Field(default=None, alias="model_version_id")
    feature_snapshot_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    explanation_available: bool = False


class AnalysisAlertResponse(BaseModel):
    """
    Safe alert row produced by an analysis run.
    """

    model_config = ConfigDict(from_attributes=False, populate_by_name=True)

    id: str
    account_id: str
    assessment_id: Optional[str] = None
    title: str
    summary: Optional[str] = None
    priority: str
    state: str
    score: Optional[Decimal] = None
    score_version: Optional[str] = None
    scoring_mode: str
    version_label: Optional[str] = Field(default=None, alias="model_version")
    rule_codes: list[str] = Field(default_factory=list)
    first_seen_at: datetime
    last_seen_at: datetime


class AnalysisRunResultsResponse(BaseModel):
    """
    Bounded results produced by one analysis run.
    """

    model_config = ConfigDict(from_attributes=False)

    run: AnalysisRunResponse
    assessments: list[AnalysisAssessmentResponse] = Field(default_factory=list)
    assessment_total: int = 0
    assessment_truncated: bool = False
    alerts: list[AnalysisAlertResponse] = Field(default_factory=list)
    alert_total: int = 0
    alert_truncated: bool = False
    alerts_available: bool = True
    page: int = 1
    page_size: int = 50
    caveats: list[str] = Field(default_factory=list)


class AnalysisRunHistoryEventResponse(BaseModel):
    """
    Safe audit history event for an analysis run.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    action: str
    outcome: str
    actor_id: Optional[str] = None
    actor_username: Optional[str] = None
    actor_role: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    request_id: Optional[str] = None
    metadata_json: Optional[Any] = None
    created_at: datetime


class AnalysisRunHistoryListResponse(BaseModel):
    """
    Paginated analysis-run history response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[AnalysisRunHistoryEventResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class AnalysisStatusResponse(BaseModel):
    """
    Safe analysis subsystem status.
    """

    model_config = ConfigDict(from_attributes=False, populate_by_name=True)

    enabled: bool
    service_available: bool
    scoring_mode: str
    version_id: Optional[str] = Field(default=None, alias="model_version_id")
    version_label: Optional[str] = Field(default=None, alias="model_version")
    require_trained_model: bool
    dataset_mode: str
    allow_all_accounts: bool
    max_accounts: int
    max_date_span_days: int
    default_as_of_policy: str = "now_utc"
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Response builders
# -----------------------------------------------------------------------------


def _duration_seconds(run: AnalysisRun) -> Optional[float]:
    """
    Return safe run duration in seconds when start and finish timestamps exist.
    """
    started_at = _ensure_utc(_get_if_exists(run, "started_at", None))
    finished_at = _ensure_utc(_get_if_exists(run, "finished_at", None))

    if started_at is None or finished_at is None:
        return None

    return round(max(0.0, (finished_at - started_at).total_seconds()), 3)


def _run_response(
    db: Session,
    run: AnalysisRun,
    *,
    requested_by_username: Optional[str] = None,
) -> AnalysisRunResponse:
    """
    Build a safe analysis-run response.
    """
    requested_by = _get_if_exists(run, "requested_by", None)
    requested_by_text = str(requested_by) if requested_by is not None else None

    if requested_by_username is None and requested_by_text:
        requested_by_username = _username_for_user_id(db, requested_by_text)

    model_version_id = _get_if_exists(run, "model_version_id", None)
    model_version = _get_if_exists(run, "model_version", None)

    return AnalysisRunResponse(
        id=str(run.id),
        status=_enum_str(_get_if_exists(run, "status", None)) or "unknown",
        scoring_mode=_enum_str(_get_if_exists(run, "scoring_mode", None)) or "unknown",
        model_version_id=str(model_version_id) if model_version_id is not None else None,
        model_version=str(model_version) if model_version is not None else None,
        requested_by=requested_by_text,
        requested_by_username=requested_by_username,
        started_at=_get_if_exists(run, "started_at", None),
        finished_at=_get_if_exists(run, "finished_at", None),
        created_at=_get_if_exists(run, "record_created_at", None),
        updated_at=_get_if_exists(run, "record_updated_at", None),
        duration_seconds=_duration_seconds(run),
        account_count=int(_get_if_exists(run, "account_count", 0) or 0),
        assessment_count=int(_get_if_exists(run, "assessment_count", 0) or 0),
        alert_count=int(_get_if_exists(run, "alert_count", 0) or 0),
        parameters_json=_response_metadata(_get_if_exists(run, "parameters_json", None)),
        summary_json=_response_metadata(_get_if_exists(run, "summary_json", None)),
        error_code=(
            _clean_text(_get_if_exists(run, "error_code", None), 100)
            if _get_if_exists(run, "error_code", None)
            else None
        ),
        error_message=(
            _clean_text(_get_if_exists(run, "error_message", None), _MAX_STRING_LENGTH)
            if _get_if_exists(run, "error_message", None)
            else None
        ),
        caveats=list(_ANALYSIS_CAVEATS),
    )


def _assessment_response(assessment: ModelAssessment) -> AnalysisAssessmentResponse:
    """
    Build a safe assessment response.
    """
    return AnalysisAssessmentResponse(
        id=str(assessment.id),
        account_id=str(_get_if_exists(assessment, "account_id", "")),
        as_of=_get_if_exists(assessment, "as_of", _now_utc()),
        scored_at=_get_if_exists(assessment, "scored_at", _now_utc()),
        scoring_mode=_enum_str(_get_if_exists(assessment, "scoring_mode", None)) or "unknown",
        score=_get_if_exists(assessment, "score", None),
        score_type=(
            str(_get_if_exists(assessment, "score_type", None))
            if _get_if_exists(assessment, "score_type", None) is not None
            else None
        ),
        risk_band=_enum_str(_get_if_exists(assessment, "risk_band", None)) or "LOW",
        model_version_id=(
            str(_get_if_exists(assessment, "model_version_id", None))
            if _get_if_exists(assessment, "model_version_id", None) is not None
            else None
        ),
        feature_snapshot_id=(
            str(_get_if_exists(assessment, "feature_snapshot_id", None))
            if _get_if_exists(assessment, "feature_snapshot_id", None) is not None
            else None
        ),
        analysis_run_id=(
            str(_get_if_exists(assessment, "analysis_run_id", None))
            if _get_if_exists(assessment, "analysis_run_id", None) is not None
            else None
        ),
        explanation_available=bool(_get_if_exists(assessment, "explanation_json", None)),
    )


def _alert_response(alert: Alert) -> AnalysisAlertResponse:
    """
    Build a safe alert response.
    """
    return AnalysisAlertResponse(
        id=str(alert.id),
        account_id=str(_get_if_exists(alert, "account_id", "")),
        assessment_id=(
            str(_get_if_exists(alert, "assessment_id", None))
            if _get_if_exists(alert, "assessment_id", None) is not None
            else None
        ),
        title=str(_get_if_exists(alert, "title", "") or ""),
        summary=(
            str(_get_if_exists(alert, "summary", None))
            if _get_if_exists(alert, "summary", None) is not None
            else None
        ),
        priority=_enum_str(_get_if_exists(alert, "priority", None)) or "MEDIUM",
        state=_enum_str(_get_if_exists(alert, "state", None)) or "NEW",
        score=_get_if_exists(alert, "score", None),
        score_version=(
            str(_get_if_exists(alert, "score_version", None))
            if _get_if_exists(alert, "score_version", None) is not None
            else None
        ),
        scoring_mode=_enum_str(_get_if_exists(alert, "scoring_mode", None)) or "unknown",
        model_version=(
            str(_get_if_exists(alert, "model_version", None))
            if _get_if_exists(alert, "model_version", None) is not None
            else None
        ),
        rule_codes=_safe_string_list(_get_if_exists(alert, "rule_codes_json", None)),
        first_seen_at=_get_if_exists(alert, "first_seen_at", _now_utc()),
        last_seen_at=_get_if_exists(alert, "last_seen_at", _now_utc()),
    )


def _audit_event_response(event: AuditEvent) -> AnalysisRunHistoryEventResponse:
    """
    Build a safe audit history response.
    """
    return AnalysisRunHistoryEventResponse(
        id=str(event.id),
        action=str(_get_if_exists(event, "action", "") or ""),
        outcome=_enum_str(_get_if_exists(event, "outcome", None)) or "SUCCESS",
        actor_id=(
            str(_get_if_exists(event, "actor_id", None))
            if _get_if_exists(event, "actor_id", None) is not None
            else None
        ),
        actor_username=(
            str(_get_if_exists(event, "actor_username", None))
            if _get_if_exists(event, "actor_username", None) is not None
            else None
        ),
        actor_role=(
            str(_get_if_exists(event, "actor_role", None))
            if _get_if_exists(event, "actor_role", None) is not None
            else None
        ),
        resource_type=(
            str(_get_if_exists(event, "resource_type", None))
            if _get_if_exists(event, "resource_type", None) is not None
            else None
        ),
        resource_id=(
            str(_get_if_exists(event, "resource_id", None))
            if _get_if_exists(event, "resource_id", None) is not None
            else None
        ),
        request_id=(
            str(_get_if_exists(event, "request_id", None))
            if _get_if_exists(event, "request_id", None) is not None
            else None
        ),
        metadata_json=_response_metadata(_get_if_exists(event, "metadata_json", None)),
        created_at=_get_if_exists(event, "created_at", _now_utc()),
    )


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=AnalysisStatusResponse,
    summary="Get analysis subsystem status",
    description=(
        "Returns safe status for the MULEGUARD analysis subsystem, including "
        "whether an analysis service is available, the active scoring mode, and "
        "bounded-selection policy. This endpoint does not expose secrets, "
        "database URLs, model artifact paths, ground-truth labels, or real "
        "customer data."
    ),
)
def analysis_status(
    request: Request,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.ANALYSIS_RUN)),
) -> AnalysisStatusResponse:
    """
    Return safe analysis subsystem status.
    """
    _ensure_analysis_enabled(settings)

    service_fn, _ = _load_analysis_service(settings)

    scoring_mode = getattr(request.app.state, "active_scoring_mode", None)

    if scoring_mode is None:
        scoring_mode = _setting(settings, "ML_ACTIVE_SCORING_MODE", "auto")

    model_version = getattr(request.app.state, "active_model_version", None)

    if model_version is None:
        model_version = _setting(settings, "ML_ACTIVE_MODEL_VERSION", None)

    return AnalysisStatusResponse(
        enabled=True,
        service_available=service_fn is not None,
        scoring_mode=str(scoring_mode or "unknown").strip().lower() or "unknown",
        model_version_id=str(model_version) if model_version is not None else None,
        model_version=str(model_version) if model_version is not None else None,
        require_trained_model=_as_bool(
            _setting(settings, "ML_REQUIRE_TRAINED_MODEL", False),
            False,
        ),
        dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")),
        allow_all_accounts=_analysis_allow_all_accounts(settings),
        max_accounts=_analysis_max_accounts(settings),
        max_date_span_days=max(
            1,
            _as_int(_setting(settings, "ANALYSIS_MAX_DATE_SPAN_DAYS", 3650), 3650),
        ),
        default_as_of_policy="now_utc",
        caveats=list(_ANALYSIS_CAVEATS),
    )


@router.get(
    "/runs",
    response_model=AnalysisRunListResponse,
    summary="List analysis runs",
    description=(
        "Returns a paginated, filtered, and stably ordered list of synthetic "
        "MULEGUARD analysis runs. Runs are investigative workflow records only."
    ),
)
def list_analysis_runs(
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(run_pagination),
    search: SearchParams = Depends(run_search),
    _: User = Depends(require_permission(Permission.ANALYSIS_RUN)),
    status: Annotated[
        Optional[AnalysisRunStatus],
        Query(description="Filter by run status."),
    ] = None,
    scoring_mode: Annotated[
        Optional[ScoringMode],
        Query(description="Filter by scoring mode."),
    ] = None,
    requested_by: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by requesting local user."),
    ] = None,
    created_from: Annotated[
        Optional[datetime],
        Query(description="Filter runs created at or after this UTC timestamp."),
    ] = None,
    created_to: Annotated[
        Optional[datetime],
        Query(description="Filter runs created at or before this UTC timestamp."),
    ] = None,
    started_from: Annotated[
        Optional[datetime],
        Query(description="Filter runs started at or after this UTC timestamp."),
    ] = None,
    started_to: Annotated[
        Optional[datetime],
        Query(description="Filter runs started at or before this UTC timestamp."),
    ] = None,
    finished_from: Annotated[
        Optional[datetime],
        Query(description="Filter runs finished at or after this UTC timestamp."),
    ] = None,
    finished_to: Annotated[
        Optional[datetime],
        Query(description="Filter runs finished at or before this UTC timestamp."),
    ] = None,
) -> AnalysisRunListResponse:
    """
    List analysis runs with bounded pagination and safe filters.
    """
    _ensure_analysis_enabled(settings)

    normalized_created_from = _ensure_utc(created_from)
    normalized_created_to = _ensure_utc(created_to)
    normalized_started_from = _ensure_utc(started_from)
    normalized_started_to = _ensure_utc(started_to)
    normalized_finished_from = _ensure_utc(finished_from)
    normalized_finished_to = _ensure_utc(finished_to)

    _validate_not_future(normalized_created_to, "created_to")
    _validate_not_future(normalized_started_to, "started_to")
    _validate_not_future(normalized_finished_to, "finished_to")

    _validate_date_range(
        normalized_created_from,
        normalized_created_to,
        "created_from",
        "created_to",
    )
    _validate_date_range(
        normalized_started_from,
        normalized_started_to,
        "started_from",
        "started_to",
    )
    _validate_date_range(
        normalized_finished_from,
        normalized_finished_to,
        "finished_from",
        "finished_to",
    )

    _validate_span(
        normalized_created_from,
        normalized_created_to,
        "created",
        settings,
    )
    _validate_span(
        normalized_started_from,
        normalized_started_to,
        "started",
        settings,
    )
    _validate_span(
        normalized_finished_from,
        normalized_finished_to,
        "finished",
        settings,
    )

    conditions: list[Any] = []

    status_column = _model_column(AnalysisRun, "status")
    scoring_mode_column = _model_column(AnalysisRun, "scoring_mode")
    requested_by_column = _model_column(AnalysisRun, "requested_by")
    created_at_column = _model_column(AnalysisRun, "record_created_at")
    started_at_column = _model_column(AnalysisRun, "started_at")
    finished_at_column = _model_column(AnalysisRun, "finished_at")
    id_column = _model_column(AnalysisRun, "id")

    if status is not None and status_column is not None:
        conditions.append(status_column == status)

    if scoring_mode is not None and scoring_mode_column is not None:
        conditions.append(scoring_mode_column == scoring_mode)

    if requested_by is not None and requested_by_column is not None:
        conditions.append(requested_by_column == requested_by.strip())

    if normalized_created_from is not None and created_at_column is not None:
        conditions.append(created_at_column >= normalized_created_from)

    if normalized_created_to is not None and created_at_column is not None:
        conditions.append(created_at_column <= normalized_created_to)

    if normalized_started_from is not None and started_at_column is not None:
        conditions.append(started_at_column >= normalized_started_from)

    if normalized_started_to is not None and started_at_column is not None:
        conditions.append(started_at_column <= normalized_started_to)

    if normalized_finished_from is not None and finished_at_column is not None:
        conditions.append(finished_at_column >= normalized_finished_from)

    if normalized_finished_to is not None and finished_at_column is not None:
        conditions.append(finished_at_column <= normalized_finished_to)

    if search.q and id_column is not None:
        pattern = f"%{search.q.lower()}%"
        search_conditions = [func.lower(id_column).like(pattern)]

        if requested_by_column is not None:
            search_conditions.append(func.lower(requested_by_column).like(pattern))

        conditions.append(or_(*search_conditions))

    count_stmt = select(func.count()).select_from(AnalysisRun)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(AnalysisRun)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_ANALYSIS_RUN_COLUMN_MAP,
        tiebreaker=_RUN_TIEBREAKER,
        default_sort_by=_RUN_DEFAULT_SORT,
        default_sort_order="desc",
    )

    runs = db.scalars(stmt).all()

    usernames = _username_map_for_user_ids(
        db,
        [_get_if_exists(run, "requested_by", None) for run in runs],
    )

    items = [
        _run_response(
            db,
            run,
            requested_by_username=usernames.get(
                str(_get_if_exists(run, "requested_by", ""))
            )
            if _get_if_exists(run, "requested_by", None)
            else None,
        )
        for run in runs
    ]

    return AnalysisRunListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_ANALYSIS_CAVEATS),
    )


@router.post(
    "/runs",
    response_model=AnalysisRunResponse,
    status_code=201,
    summary="Trigger a bounded synthetic analysis run",
    description=(
        "Creates and executes a bounded MULEGUARD analysis run through the "
        "configured analysis service. This endpoint is honest about missing "
        "services and fallback modes. It does not take adverse action against "
        "accounts or customers."
    ),
)
def create_analysis_run(
    payload: AnalysisRunRequest,
    request: Request,
    response: Response,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.ANALYSIS_RUN)),
    idempotency_key: IdempotencyKeyDep = None,
    _: None = Depends(rate_limited(key_prefix="analysis", by="ip")),
) -> AnalysisRunResponse:
    """
    Trigger one bounded analysis run.
    """
    _ensure_analysis_enabled(settings)

    service_fn, service_label = _load_analysis_service(settings)

    if service_fn is None:
        raise ServiceUnavailableError(
            "Analysis service is not available.",
            details={
                "setting": "ANALYSIS_SERVICE_MODULE",
                "expected_modules": [
                    module for module, _ in _analysis_service_module_candidates(settings)
                ],
            },
        )

    as_of = _ensure_utc(payload.as_of) or _now_utc()
    _validate_not_future(as_of, "as_of")

    account_ids, account_count, filter_payload = _validate_account_selection(
        db=db,
        settings=settings,
        payload=payload,
    )

    parameters = _build_parameters(
        payload=payload,
        actor=actor,
        request_id=request_id,
        idempotency_key=idempotency_key,
        account_ids=account_ids,
        account_count=account_count,
        filter_payload=filter_payload,
        as_of=as_of,
        settings=settings,
    )

    # Hash only the canonical caller payload. Generated metadata such as request_id
    # and the default as_of timestamp changes on every retry and must not break
    # idempotent replay of the same request.
    payload_digest = _payload_hash(payload.model_dump(mode="json", exclude_none=True))
    cache_key: Optional[str] = None

    if idempotency_key:
        cache_key = _idempotency_cache_key(str(actor.id), idempotency_key)
        cached = _lookup_idempotency(cache_key)

        if cached is not None:
            cached_payload_hash, cached_run_id = cached

            if cached_payload_hash != payload_digest:
                raise IdempotencyConflictError(
                    "Idempotency-Key was already used with a different analysis payload.",
                    details={"run_id": cached_run_id},
                )

            existing_run = db.get(AnalysisRun, cached_run_id)

            if existing_run is not None:
                response.status_code = 200
                return _run_response(db, existing_run)

            _forget_idempotency(cache_key)

    run_kwargs: dict[str, Any] = {
        "status": AnalysisRunStatus.QUEUED,
        "scoring_mode": ScoringMode.UNKNOWN,
        "requested_by": str(actor.id),
        "parameters_json": parameters,
        "account_count": int(account_count),
        "assessment_count": 0,
        "alert_count": 0,
    }

    optional_none_fields = (
        "started_at",
        "finished_at",
        "model_version_id",
        "model_version",
        "error_code",
        "error_message",
        "summary_json",
    )

    for field_name in optional_none_fields:
        if hasattr(AnalysisRun, field_name):
            run_kwargs[field_name] = None

    run = AnalysisRun(**run_kwargs)

    db.add(run)
    db.flush()

    _add_audit_event(
        db,
        action="analysis_run_start",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="analysis_run",
        resource_id=str(run.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "account_count": int(account_count),
            "selection_mode": "explicit" if account_ids is not None else "all",
            "as_of": as_of.isoformat(),
            "service_label": service_label,
            "idempotency": bool(idempotency_key),
        },
    )

    db.commit()

    if cache_key:
        _remember_idempotency(cache_key, payload_digest, str(run.id))

    try:
        result = _invoke_analysis_service(
            service_fn,
            db=db,
            run=run,
            settings=settings,
        )

        _apply_service_result(run, result)
        db.flush()

        current_status = _get_if_exists(run, "status", None)

        if not _is_terminal_status(current_status):
            _mark_run_failed(
                db,
                run,
                actor=actor,
                request=request,
                settings=settings,
                request_id=request_id,
                error_code="ANALYSIS_SERVICE_INCOMPLETE",
                error_message="Analysis service did not finalize run status.",
            )
            raise ServiceUnavailableError(
                "Analysis service did not finalize run status.",
                details={"run_id": str(run.id)},
            )

        if _enum_str(current_status) == AnalysisRunStatus.FAILED.value:
            db.commit()
            _raise_for_failed_run(run)

        db.commit()
        db.refresh(run)

        return _run_response(db, run)

    except MuleGuardError as exc:
        current_status = _get_if_exists(run, "status", None)

        if not _is_terminal_status(current_status):
            _mark_run_failed(
                db,
                run,
                actor=actor,
                request=request,
                settings=settings,
                request_id=request_id,
                error_code=_safe_error_code(exc),
                error_message=_safe_error_message(exc),
            )

        raise

    except Exception as exc:
        current_status = _get_if_exists(run, "status", None)

        if not _is_terminal_status(current_status):
            _mark_run_failed(
                db,
                run,
                actor=actor,
                request=request,
                settings=settings,
                request_id=request_id,
                error_code="ANALYSIS_EXECUTION_FAILED",
                error_message="Analysis execution failed.",
            )

        logger.exception("Analysis run failed unexpectedly.")

        raise InternalError(
            "Analysis run failed.",
            details={"run_id": str(run.id)},
        ) from exc


@router.get(
    "/runs/{run_id}",
    response_model=AnalysisRunResponse,
    summary="Get an analysis run",
    description=(
        "Returns safe metadata for one synthetic MULEGUARD analysis run. "
        "This endpoint does not expose secrets, ground-truth labels, scenario "
        "IDs, ring IDs, or real customer data."
    ),
)
def get_analysis_run(
    run_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Analysis run identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.ANALYSIS_RUN)),
) -> AnalysisRunResponse:
    """
    Retrieve one analysis run.
    """
    _ensure_analysis_enabled(settings)

    run = _get_run_or_404(db, run_id)
    return _run_response(db, run)


@router.get(
    "/runs/{run_id}/results",
    response_model=AnalysisRunResultsResponse,
    summary="Get bounded results for an analysis run",
    description=(
        "Returns bounded persisted assessments and alerts produced by one "
        "analysis run. Results are investigative leads only and may be "
        "truncated."
    ),
)
def get_analysis_run_results(
    run_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Analysis run identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(result_pagination),
    _: User = Depends(require_permission(Permission.ANALYSIS_RUN)),
    account_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter results by synthetic account."),
    ] = None,
    scoring_mode: Annotated[
        Optional[ScoringMode],
        Query(description="Filter assessments by scoring mode."),
    ] = None,
    risk_band: Annotated[
        Optional[RiskBand],
        Query(description="Filter assessments by risk band."),
    ] = None,
    alert_state: Annotated[
        Optional[AlertState],
        Query(description="Filter alerts by triage state."),
    ] = None,
    alert_priority: Annotated[
        Optional[Priority],
        Query(description="Filter alerts by priority."),
    ] = None,
) -> AnalysisRunResultsResponse:
    """
    Return bounded results for one analysis run.
    """
    _ensure_analysis_enabled(settings)

    run = _get_run_or_404(db, run_id)
    run_response = _run_response(db, run)

    assessment_run_column = _model_column(ModelAssessment, "analysis_run_id")
    assessment_id_column = _model_column(ModelAssessment, "id")
    assessment_account_column = _model_column(ModelAssessment, "account_id")
    assessment_scoring_column = _model_column(ModelAssessment, "scoring_mode")
    assessment_risk_column = _model_column(ModelAssessment, "risk_band")

    if assessment_run_column is None or assessment_id_column is None:
        return AnalysisRunResultsResponse(
            run=run_response,
            assessments=[],
            assessment_total=0,
            assessment_truncated=False,
            alerts=[],
            alert_total=0,
            alert_truncated=False,
            alerts_available=False,
            page=params.page,
            page_size=params.page_size,
            caveats=[
                *_RESULTS_CAVEATS,
                "Persisted analysis-run linkage is not available in this schema.",
            ],
        )

    assessment_conditions: list[Any] = [assessment_run_column == str(run.id)]

    if account_id is not None and assessment_account_column is not None:
        assessment_conditions.append(assessment_account_column == account_id.strip())

    if scoring_mode is not None and assessment_scoring_column is not None:
        assessment_conditions.append(assessment_scoring_column == scoring_mode)

    if risk_band is not None and assessment_risk_column is not None:
        assessment_conditions.append(assessment_risk_column == risk_band)

    assessment_count_stmt = select(func.count()).select_from(ModelAssessment)
    assessment_count_stmt = _apply_conditions(assessment_count_stmt, assessment_conditions)
    assessment_total = _scalar_count(db, assessment_count_stmt)

    assessment_stmt = select(ModelAssessment)
    assessment_stmt = _apply_conditions(assessment_stmt, assessment_conditions)
    assessment_stmt = apply_pagination(
        assessment_stmt,
        params,
        column_map=_ASSESSMENT_COLUMN_MAP,
        tiebreaker=_ASSESSMENT_TIEBREAKER,
        default_sort_by=_ASSESSMENT_DEFAULT_SORT,
        default_sort_order="desc",
    )

    assessments = db.scalars(assessment_stmt).all()

    alert_assessment_column = _model_column(Alert, "assessment_id")
    alert_state_column = _model_column(Alert, "state")
    alert_priority_column = _model_column(Alert, "priority")

    alerts_available = alert_assessment_column is not None

    alert_items: list[Alert] = []
    alert_total = 0

    if alerts_available:
        assessment_ids_subquery = (
            select(assessment_id_column)
            .where(and_(*assessment_conditions))
            .subquery()
        )

        alert_conditions: list[Any] = [
            alert_assessment_column.in_(select(assessment_ids_subquery.c.id))
        ]

        if alert_state is not None and alert_state_column is not None:
            alert_conditions.append(alert_state_column == alert_state)

        if alert_priority is not None and alert_priority_column is not None:
            alert_conditions.append(alert_priority_column == alert_priority)

        alert_count_stmt = select(func.count()).select_from(Alert)
        alert_count_stmt = _apply_conditions(alert_count_stmt, alert_conditions)
        alert_total = _scalar_count(db, alert_count_stmt)

        alert_stmt = select(Alert)
        alert_stmt = _apply_conditions(alert_stmt, alert_conditions)

        alert_created_column = _model_column(Alert, "record_created_at")
        alert_id_column = _model_column(Alert, "id")

        if alert_created_column is not None:
            alert_stmt = alert_stmt.order_by(desc(alert_created_column))

        if alert_id_column is not None:
            alert_stmt = alert_stmt.order_by(desc(alert_id_column))

        alert_stmt = alert_stmt.offset(params.offset).limit(params.limit)

        alert_items = list(db.scalars(alert_stmt).all())

    return AnalysisRunResultsResponse(
        run=run_response,
        assessments=[_assessment_response(assessment) for assessment in assessments],
        assessment_total=assessment_total,
        assessment_truncated=assessment_total > len(assessments),
        alerts=[_alert_response(alert) for alert in alert_items],
        alert_total=alert_total,
        alert_truncated=alert_total > len(alert_items),
        alerts_available=alerts_available,
        page=params.page,
        page_size=params.page_size,
        caveats=list(_RESULTS_CAVEATS),
    )


@router.get(
    "/runs/{run_id}/history",
    response_model=AnalysisRunHistoryListResponse,
    summary="Get safe audit history for an analysis run",
    description=(
        "Returns paginated safe audit history for one analysis run. History "
        "contains run lifecycle actions with sanitized metadata only."
    ),
)
def get_analysis_run_history(
    run_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Analysis run identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(history_pagination),
    _: User = Depends(require_permission(Permission.ANALYSIS_RUN)),
    action: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audit action name."),
    ] = None,
    outcome: Annotated[
        Optional[AuditOutcome],
        Query(description="Filter by audit outcome."),
    ] = None,
) -> AnalysisRunHistoryListResponse:
    """
    Return audit history for one analysis run.
    """
    _ensure_analysis_enabled(settings)

    run = _get_run_or_404(db, run_id)

    resource_type_column = _model_column(AuditEvent, "resource_type")
    resource_id_column = _model_column(AuditEvent, "resource_id")
    action_column = _model_column(AuditEvent, "action")
    outcome_column = _model_column(AuditEvent, "outcome")
    actor_username_column = _model_column(AuditEvent, "actor_username")

    if resource_type_column is None or resource_id_column is None:
        return AnalysisRunHistoryListResponse(
            items=[],
            page=params.page,
            page_size=params.page_size,
            total=0,
            total_pages=0,
            sort_by=params.sort_by,
            sort_order=params.sort_order,
            caveats=[
                *_HISTORY_CAVEATS,
                "Audit resource linkage is not available in this schema.",
            ],
        )

    conditions: list[Any] = [
        resource_type_column == "analysis_run",
        resource_id_column == str(run.id),
    ]

    if action is not None and action_column is not None:
        conditions.append(action_column == action.strip())

    if outcome is not None and outcome_column is not None:
        conditions.append(outcome_column == outcome)

    if search := None:  # placeholder to keep structure explicit
        _ = search

    count_stmt = select(func.count()).select_from(AuditEvent)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(AuditEvent)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_HISTORY_COLUMN_MAP,
        tiebreaker=_HISTORY_TIEBREAKER,
        default_sort_by=_HISTORY_DEFAULT_SORT,
        default_sort_order="desc",
    )

    events = db.scalars(stmt).all()

    return AnalysisRunHistoryListResponse(
        items=[_audit_event_response(event) for event in events],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_HISTORY_CAVEATS),
    )


@router.post(
    "/runs/{run_id}/cancel",
    response_model=AnalysisRunResponse,
    summary="Cancel a queued analysis run",
    description=(
        "Cancels a queued MULEGUARD analysis run. Running synchronous prototype "
        "runs cannot be interrupted mid-execution. Cancellation affects only "
        "the analysis workflow and does not take adverse action against accounts."
    ),
)
def cancel_analysis_run(
    run_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Analysis run identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.ANALYSIS_RUN)),
) -> AnalysisRunResponse:
    """
    Cancel one queued analysis run.
    """
    _ensure_analysis_enabled(settings)

    run = _get_run_or_404(db, run_id)

    requested_by = _get_if_exists(run, "requested_by", None)
    actor_role = _normalize_role(actor.role)

    if str(requested_by or "") != str(actor.id) and actor_role != UserRole.ADMIN.value:
        raise PermissionDeniedError(
            "Only the requesting user or an administrator may cancel this run.",
            details={"run_id": str(run.id)},
        )

    current_status = _get_if_exists(run, "status", None)
    current_status_value = _enum_str(current_status)

    if current_status_value != AnalysisRunStatus.QUEUED.value:
        raise ConflictError(
            "Only queued analysis runs can be cancelled in the synchronous prototype.",
            details={
                "run_id": str(run.id),
                "status": current_status_value or "unknown",
            },
        )

    now = _now_utc()

    _set_if_exists(run, "status", AnalysisRunStatus.CANCELLED)
    _set_if_exists(run, "finished_at", now)
    _set_if_exists(run, "error_code", "ANALYSIS_CANCELLED")
    _set_if_exists(run, "error_message", "Analysis run cancelled by user.")

    _add_audit_event(
        db,
        action="analysis_run_cancel",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="analysis_run",
        resource_id=str(run.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "previous_status": current_status_value or "unknown",
            "new_status": AnalysisRunStatus.CANCELLED.value,
            "account_count": int(_get_if_exists(run, "account_count", 0) or 0),
        },
    )

    db.commit()
    db.refresh(run)

    return _run_response(db, run)


__all__ = [
    "router",
]