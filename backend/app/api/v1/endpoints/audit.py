"""
MULEGUARD backend API v1 audit endpoints.

This module implements the versioned `/api/v1/audit` read-only audit surface for
synthetic MULEGUARD operational and investigative actions.

Implemented endpoints:

- GET /api/v1/audit/status
- GET /api/v1/audit
- GET /api/v1/audit/stats
- GET /api/v1/audit/export
- GET /api/v1/audit/{event_id}

Design goals:

- provide durable, read-only visibility into material MULEGUARD actions;
- enforce server-side RBAC through dependency permissions;
- keep list endpoints paginated, filtered, searched, and stably ordered;
- expose safe aggregate statistics for oversight and operations reviews;
- support bounded JSON and CSV audit exports for authorised auditors/admins;
- sanitise all metadata before storage or response serialisation;
- avoid exposing passwords, tokens, secrets, database URLs, raw complaint
  narratives, synthetic ground-truth labels, scenario IDs, ring IDs, or real
  customer data;
- preserve audit integrity by never modifying, deleting, or redacting existing
  audit events through this API.

Explicit non-goals:

- This module does not write arbitrary audit events through the public API.
- This module does not delete or mutate audit history.
- This module does not expose raw IP addresses; only hashed IP values are
  stored and returned when configured.
- This module does not expose raw complaint narratives.
- This module does not claim production readiness.
- This module does not make investigative decisions.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Audit history records
operator and system actions for accountability. It is not proof of wrongdoing
and must not trigger automatic adverse customer action.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import secrets
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Final, Literal, Optional

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, asc, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    DateRangeParams,
    PageParams,
    Permission,
    RequestIDDep,
    SearchParams,
    SessionDep,
    SettingsDep,
    apply_pagination,
    date_range_dependency,
    pagination_dependency,
    rate_limited,
    require_permission,
    search_dependency,
)
from app.exceptions import (
    FeatureFlagDisabledError,
    InternalError,
    NotFoundError,
    ValidationError as MuleGuardValidationError,
)
from app.models import AuditEvent, AuditOutcome, User, UserRole

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.audit")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["audit"])


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_CSV_CELL_LENGTH: Final[int] = 20_000
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_MAPPING_KEYS: Final[int] = 100
_MAX_JSON_DEPTH: Final[int] = 6

_TOP_LIMIT_DEFAULT: Final[int] = 10
_TOP_LIMIT_MAX: Final[int] = 50

_EXPORT_DEFAULT_MAX_ROWS: Final[int] = 10_000
_EXPORT_HARD_MAX_ROWS: Final[int] = 100_000

_STATS_DEFAULT_DAYS: Final[int] = 30

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

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

_AUDIT_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Audit history is read-only through this API.",
    "Audit metadata is sanitised before storage and response serialisation.",
    "Passwords, tokens, secrets, database URLs, raw complaint narratives, ground-truth labels, scenario IDs, and ring IDs are not returned.",
    "Audit records are accountability artefacts, not proof of wrongdoing.",
    "This endpoint does not modify, delete, or redact existing audit events.",
    "MULEGUARD does not permit automatic adverse customer action.",
)

_EXPORT_CAVEATS: Final[tuple[str, ...]] = (
    *_AUDIT_CAVEATS,
    "Exports are bounded and may be truncated.",
    "CSV cells are sanitised to reduce spreadsheet formula-injection risk.",
    "Export requests are themselves audited.",
)

_STATS_CAVEATS: Final[tuple[str, ...]] = (
    *_AUDIT_CAVEATS,
    "Aggregate statistics are operational oversight signals only.",
    "Low-count categories may be privacy-sensitive and should be interpreted cautiously.",
)


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


_AUDIT_EVENT_COLUMN_MAP: Final[dict[str, Any]] = _build_column_map(
    AuditEvent,
    (
        "id",
        "created_at",
        "action",
        "resource_type",
        "resource_id",
        "actor_id",
        "actor_username",
        "actor_role",
        "outcome",
        "request_id",
        "ip_hash",
    ),
)

_EVENT_TIEBREAKER = _model_column(AuditEvent, "id")

_EVENT_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _AUDIT_EVENT_COLUMN_MAP
    else ("id" if "id" in _AUDIT_EVENT_COLUMN_MAP else "created_at")
)


# -----------------------------------------------------------------------------
# Reusable bounded dependencies
# -----------------------------------------------------------------------------

audit_pagination = pagination_dependency(
    sortable_fields=tuple(_AUDIT_EVENT_COLUMN_MAP.keys()),
    default_sort_by=_EVENT_DEFAULT_SORT,
    default_sort_order="desc",
)

audit_date_range = date_range_dependency(max_span_days=0)
audit_search = search_dependency(max_length=200, alias="q")


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
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if len(text) > limit:
        return text[:limit]

    return text


def _get_if_exists(obj: Any, name: str, default: Any = None) -> Any:
    """
    Get an attribute only when it exists on the object.
    """
    return getattr(obj, name, default)


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
    max_sequence_length: int = _MAX_LIST_LENGTH,
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
    max_sequence_length: int = _MAX_LIST_LENGTH,
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


def _safe_metadata(metadata: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return sanitized audit metadata suitable for persistence.
    """
    if not metadata:
        return {}

    return _sanitize_json_object(
        metadata,
        max_sequence_length=50,
        max_mapping_keys=50,
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


def _max_date_span_days(settings: Any) -> int:
    """
    Return bounded maximum audit query date span in days.
    """
    return max(
        1,
        _as_int(_setting(settings, "AUDIT_MAX_DATE_SPAN_DAYS", 365), 365),
    )


def _validate_span(
    start: Optional[datetime],
    end: Optional[datetime],
    settings: Any,
) -> None:
    """
    Enforce optional maximum date span for audit scans.
    """
    if start is None or end is None:
        return

    max_days = _max_date_span_days(settings)
    span = end - start
    max_delta = timedelta(days=max_days)

    if span > max_delta:
        raise MuleGuardValidationError(
            "Audit date span exceeds configured maximum.",
            details={
                "max_span_days": max_days,
                "requested_span_days": round(span.total_seconds() / 86400.0, 3),
            },
        )


def _ensure_audit_enabled(settings: Any) -> None:
    """
    Fail closed when the audit API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "AUDIT_API_ENABLED", True), True):
        raise FeatureFlagDisabledError("Audit endpoints are disabled by configuration.")


def _audit_subsystem_enabled(settings: Any) -> bool:
    """
    Return True when the audit subsystem is enabled.

    This is distinct from API exposure. If the subsystem is disabled, existing
    audit rows may still be readable, but new material actions may not be
    captured by other layers.
    """
    return _as_bool(_setting(settings, "AUDIT_ENABLED", True), True)


def _audit_export_enabled(settings: Any) -> bool:
    """
    Return True when audit export is enabled.
    """
    return (
        _as_bool(_setting(settings, "AUDIT_API_ENABLED", True), True)
        and _as_bool(_setting(settings, "AUDIT_EXPORT_ENABLED", True), True)
    )


def _export_max_rows(settings: Any) -> tuple[int, int]:
    """
    Return `(configured_max_rows, hard_max_rows)` for audit exports.
    """
    configured = max(
        1,
        _as_int(_setting(settings, "AUDIT_EXPORT_MAX_ROWS", _EXPORT_DEFAULT_MAX_ROWS), _EXPORT_DEFAULT_MAX_ROWS),
    )
    hard = max(
        configured,
        _as_int(_setting(settings, "AUDIT_EXPORT_HARD_MAX_ROWS", _EXPORT_HARD_MAX_ROWS), _EXPORT_HARD_MAX_ROWS),
    )

    return min(configured, hard), hard


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
        or "muleguard-audit"
    )


def _hash_value(value: str, salt: str) -> str:
    """
    Return a stable SHA-256 hash for safe audit storage.
    """
    import hashlib

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


def _safe_filename(export_format: str, generated_at: datetime, export_id: str) -> str:
    """
    Return a safe, non-sensitive export filename.
    """
    timestamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    extension = "csv" if export_format == "csv" else "json"
    safe_export_id = _clean_text(export_id, 64).replace("/", "-").replace("\\", "-")

    return f"muleguard-audit-export-{timestamp}-{safe_export_id}.{extension}"


def _json_default(value: Any) -> Any:
    """
    JSON serializer fallback for safe payload construction.
    """
    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, Enum):
        return _enum_str(value)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    return _clean_text(value, _MAX_STRING_LENGTH)


def _csv_cell(value: Any, limit: int = _MAX_CSV_CELL_LENGTH) -> str:
    """
    Return a CSV-safe cell value.

    This reduces spreadsheet formula-injection risk and removes control
    characters. It intentionally does not attempt to preserve rich formatting.
    """
    if value is None:
        return ""

    text = _clean_text(value, limit)

    if text and text[0] in {"=", "+", "-", "@", "\t", "\r"}:
        text = f"'{text}"

    return text


def _filters_summary(
    *,
    action: Optional[str],
    resource_type: Optional[str],
    resource_id: Optional[str],
    actor_id: Optional[str],
    actor_username: Optional[str],
    actor_role: Optional[str],
    outcome: Optional[AuditOutcome],
    request_id: Optional[str],
    ip_hash: Optional[str],
    date_range: DateRangeParams,
    search: Optional[SearchParams],
) -> dict[str, Any]:
    """
    Return a safe summary of audit filters for export metadata.

    Search text is intentionally not included; only its length is recorded to
    avoid persisting potentially sensitive operator search terms.
    """
    summary: dict[str, Any] = {}

    if action:
        summary["action"] = _clean_text(action, 100)

    if resource_type:
        summary["resource_type"] = _clean_text(resource_type, 100)

    if resource_id:
        summary["resource_id"] = _clean_text(resource_id, 128)

    if actor_id:
        summary["actor_id"] = _clean_text(actor_id, 128)

    if actor_username:
        summary["actor_username"] = _clean_text(actor_username, 100)

    if actor_role:
        summary["actor_role"] = _clean_text(actor_role, 50).upper()

    if outcome is not None:
        summary["outcome"] = _enum_str(outcome)

    if request_id:
        summary["request_id"] = _clean_text(request_id, 128)

    if ip_hash:
        summary["ip_hash"] = _clean_text(ip_hash, 128)

    if date_range.date_from is not None:
        summary["created_from"] = date_range.date_from.isoformat()

    if date_range.date_to is not None:
        summary["created_to"] = date_range.date_to.isoformat()

    if search is not None and search.q:
        summary["search_length"] = len(search.q)

    return summary


# -----------------------------------------------------------------------------
# Query condition builder
# -----------------------------------------------------------------------------


def _build_conditions(
    *,
    action: Optional[str],
    resource_type: Optional[str],
    resource_id: Optional[str],
    actor_id: Optional[str],
    actor_username: Optional[str],
    actor_role: Optional[str],
    outcome: Optional[AuditOutcome],
    request_id: Optional[str],
    ip_hash: Optional[str],
    date_range: DateRangeParams,
    search: Optional[SearchParams],
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for audit queries.
    """
    conditions: list[Any] = []

    action_column = _model_column(AuditEvent, "action")
    resource_type_column = _model_column(AuditEvent, "resource_type")
    resource_id_column = _model_column(AuditEvent, "resource_id")
    actor_id_column = _model_column(AuditEvent, "actor_id")
    actor_username_column = _model_column(AuditEvent, "actor_username")
    actor_role_column = _model_column(AuditEvent, "actor_role")
    outcome_column = _model_column(AuditEvent, "outcome")
    request_id_column = _model_column(AuditEvent, "request_id")
    ip_hash_column = _model_column(AuditEvent, "ip_hash")
    created_at_column = _model_column(AuditEvent, "created_at")

    if action and action_column is not None:
        conditions.append(action_column == _clean_text(action, 100))

    if resource_type and resource_type_column is not None:
        conditions.append(resource_type_column == _clean_text(resource_type, 100))

    if resource_id and resource_id_column is not None:
        conditions.append(resource_id_column == _clean_text(resource_id, 128))

    if actor_id and actor_id_column is not None:
        conditions.append(actor_id_column == _clean_text(actor_id, 128))

    if actor_username and actor_username_column is not None:
        conditions.append(actor_username_column == _clean_text(actor_username, 100))

    if actor_role and actor_role_column is not None:
        conditions.append(actor_role_column == _clean_text(actor_role, 50).upper())

    if outcome is not None and outcome_column is not None:
        conditions.append(outcome_column == outcome)

    if request_id and request_id_column is not None:
        conditions.append(request_id_column == _clean_text(request_id, 128))

    if ip_hash and ip_hash_column is not None:
        conditions.append(ip_hash_column == _clean_text(ip_hash, 128))

    if date_range.date_from is not None and created_at_column is not None:
        conditions.append(created_at_column >= date_range.date_from)

    if date_range.date_to is not None and created_at_column is not None:
        conditions.append(created_at_column <= date_range.date_to)

    if search is not None and search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column_name in (
            "action",
            "resource_type",
            "resource_id",
            "actor_username",
            "request_id",
        ):
            column = _model_column(AuditEvent, column_name)

            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class AuditEventResponse(BaseModel):
    """
    Safe audit event response.
    """

    model_config = ConfigDict(from_attributes=False, extra="ignore")

    id: str
    created_at: Optional[datetime] = None
    action: str
    outcome: str
    actor_id: Optional[str] = None
    actor_username: Optional[str] = None
    actor_role: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    request_id: Optional[str] = None
    ip_hash: Optional[str] = None
    metadata_json: Optional[Any] = None


class AuditEventListResponse(BaseModel):
    """
    Paginated audit event list response.
    """

    model_config = ConfigDict(from_attributes=False, extra="ignore")

    items: list[AuditEventResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class AuditEventDetailResponse(BaseModel):
    """
    Detailed audit event response.
    """

    model_config = ConfigDict(from_attributes=False, extra="ignore")

    event: AuditEventResponse
    caveats: list[str] = Field(default_factory=list)


class AuditTopItem(BaseModel):
    """
    Safe aggregate top-N item.
    """

    model_config = ConfigDict(from_attributes=False, extra="ignore")

    value: Optional[str] = None
    count: int


class AuditStatsResponse(BaseModel):
    """
    Safe aggregate audit statistics response.
    """

    model_config = ConfigDict(from_attributes=False, extra="ignore")

    period: dict[str, Any] = Field(default_factory=dict)
    total_events: int = 0
    outcome_counts: dict[str, int] = Field(default_factory=dict)
    distinct_actor_count: int = 0
    top_actions: list[AuditTopItem] = Field(default_factory=list)
    top_resource_types: list[AuditTopItem] = Field(default_factory=list)
    top_actors: list[AuditTopItem] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)


class AuditStatusResponse(BaseModel):
    """
    Safe audit subsystem status response.
    """

    model_config = ConfigDict(from_attributes=False, extra="ignore")

    enabled: bool
    audit_subsystem_enabled: bool
    export_enabled: bool
    retention_days: int
    max_date_span_days: int
    export_max_rows: int
    export_hard_max_rows: int
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Response builders
# -----------------------------------------------------------------------------


def _event_response(
    event: AuditEvent,
    *,
    include_metadata: bool = True,
) -> AuditEventResponse:
    """
    Build a safe audit event response.
    """
    return AuditEventResponse(
        id=str(_get_if_exists(event, "id", "")),
        created_at=_get_if_exists(event, "created_at", None),
        action=_clean_text(_get_if_exists(event, "action", ""), 100),
        outcome=_enum_str(_get_if_exists(event, "outcome", None)) or "UNKNOWN",
        actor_id=(
            _clean_text(_get_if_exists(event, "actor_id", None), 128)
            if _get_if_exists(event, "actor_id", None) is not None
            else None
        ),
        actor_username=(
            _clean_text(_get_if_exists(event, "actor_username", None), 100)
            if _get_if_exists(event, "actor_username", None) is not None
            else None
        ),
        actor_role=(
            _clean_text(_get_if_exists(event, "actor_role", None), 50)
            if _get_if_exists(event, "actor_role", None) is not None
            else None
        ),
        resource_type=(
            _clean_text(_get_if_exists(event, "resource_type", None), 100)
            if _get_if_exists(event, "resource_type", None) is not None
            else None
        ),
        resource_id=(
            _clean_text(_get_if_exists(event, "resource_id", None), 128)
            if _get_if_exists(event, "resource_id", None) is not None
            else None
        ),
        request_id=(
            _clean_text(_get_if_exists(event, "request_id", None), 128)
            if _get_if_exists(event, "request_id", None) is not None
            else None
        ),
        ip_hash=(
            _clean_text(_get_if_exists(event, "ip_hash", None), 128)
            if _get_if_exists(event, "ip_hash", None) is not None
            else None
        ),
        metadata_json=(
            _response_metadata(_get_if_exists(event, "metadata_json", None))
            if include_metadata
            else None
        ),
    )


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
        action=_clean_text(action, 100),
        resource_type=_clean_text(resource_type, 100) if resource_type is not None else None,
        resource_id=_clean_text(resource_id, 128) if resource_id is not None else None,
        outcome=outcome,
        request_id=_clean_text(request_id, 64) if request_id is not None else None,
        ip_hash=ip_hash,
        metadata_json=_safe_metadata(metadata),
    )

    db.add(event)


def _top_group(
    db: Session,
    column: Any | None,
    conditions: list[Any],
    limit: int,
) -> list[AuditTopItem]:
    """
    Return a bounded top-N grouping for a nullable string-like column.
    """
    if column is None:
        return []

    stmt = select(column, func.count().label("count"))
    stmt = _apply_conditions(stmt, conditions)
    stmt = stmt.group_by(column).order_by(desc(func.count()), column).limit(limit)

    rows = db.execute(stmt).all()

    return [
        AuditTopItem(
            value=_clean_text(row[0], 200) if row[0] is not None else None,
            count=int(row[1] or 0),
        )
        for row in rows
    ]


def _resolve_stats_range(
    date_range: DateRangeParams,
    settings: Any,
) -> tuple[DateRangeParams, bool]:
    """
    Resolve a bounded default window for audit statistics.
    """
    start = date_range.date_from
    end = date_range.date_to
    defaulted = False

    max_span = _max_date_span_days(settings)
    default_days = max(
        1,
        min(
            _as_int(_setting(settings, "AUDIT_STATS_DEFAULT_DAYS", _STATS_DEFAULT_DAYS), _STATS_DEFAULT_DAYS),
            max_span,
        ),
    )

    if end is None:
        end = _now_utc()
        defaulted = True

    if start is None:
        start = end - timedelta(days=default_days)
        defaulted = True

    _validate_date_range(start, end, "created_from", "created_to")
    _validate_span(start, end, settings)

    return DateRangeParams(date_from=start, date_to=end), defaulted


# -----------------------------------------------------------------------------
# Export builders
# -----------------------------------------------------------------------------


def _build_csv_content(
    events: Sequence[AuditEventResponse],
    *,
    include_metadata: bool,
) -> str:
    """
    Build bounded CSV content from sanitized audit event responses.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")

    header = [
        "id",
        "created_at",
        "action",
        "outcome",
        "actor_id",
        "actor_username",
        "actor_role",
        "resource_type",
        "resource_id",
        "request_id",
        "ip_hash",
    ]

    if include_metadata:
        header.append("metadata_json")

    writer.writerow(header)

    for event in events:
        row = [
            _csv_cell(event.id, 128),
            _csv_cell(event.created_at.isoformat() if event.created_at else "", 64),
            _csv_cell(event.action, 100),
            _csv_cell(event.outcome, 50),
            _csv_cell(event.actor_id, 128),
            _csv_cell(event.actor_username, 100),
            _csv_cell(event.actor_role, 50),
            _csv_cell(event.resource_type, 100),
            _csv_cell(event.resource_id, 128),
            _csv_cell(event.request_id, 128),
            _csv_cell(event.ip_hash, 128),
        ]

        if include_metadata:
            metadata_text = ""

            if event.metadata_json is not None:
                metadata_text = json.dumps(
                    event.metadata_json,
                    ensure_ascii=False,
                    default=_json_default,
                )

            row.append(_csv_cell(metadata_text, _MAX_CSV_CELL_LENGTH))

        writer.writerow(row)

    return output.getvalue()


def _build_json_content(
    *,
    export_id: str,
    generated_at: datetime,
    events: Sequence[AuditEventResponse],
    total_matching: int,
    truncated: bool,
    max_rows: int,
    include_metadata: bool,
    filters: Mapping[str, Any],
) -> str:
    """
    Build bounded JSON content from sanitized audit event responses.
    """
    caveats = list(_EXPORT_CAVEATS)

    if truncated:
        caveats.append("Export truncated because matching rows exceeded max_rows.")

    payload = {
        "export_id": export_id,
        "generated_at": generated_at.isoformat(),
        "format": "json",
        "row_count": len(events),
        "total_matching": int(total_matching),
        "truncated": bool(truncated),
        "max_rows": int(max_rows),
        "include_metadata": bool(include_metadata),
        "filters": dict(filters),
        "caveats": caveats,
        "events": [json.loads(event.model_dump_json()) for event in events],
    }

    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        default=_json_default,
    )


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=AuditStatusResponse,
    summary="Get audit subsystem status",
    description=(
        "Returns safe status for the MULEGUARD audit subsystem, including API "
        "exposure, export posture, retention configuration, and bounded query "
        "limits. This endpoint does not expose secrets, database URLs, tokens, "
        "passwords, raw complaint narratives, or real customer data."
    ),
)
def audit_status(
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
) -> AuditStatusResponse:
    """
    Return safe audit subsystem status.
    """
    _ensure_audit_enabled(settings)

    configured_max, hard_max = _export_max_rows(settings)

    return AuditStatusResponse(
        enabled=True,
        audit_subsystem_enabled=_audit_subsystem_enabled(settings),
        export_enabled=_audit_export_enabled(settings),
        retention_days=max(
            0,
            _as_int(_setting(settings, "RETENTION_AUDIT_DAYS", 3650), 3650),
        ),
        max_date_span_days=_max_date_span_days(settings),
        export_max_rows=configured_max,
        export_hard_max_rows=hard_max,
        caveats=list(_AUDIT_CAVEATS),
    )


@router.get(
    "",
    response_model=AuditEventListResponse,
    summary="List audit events",
    description=(
        "Returns a paginated, filtered, and stably ordered list of synthetic "
        "MULEGUARD audit events. Audit history is read-only and sanitised. "
        "This endpoint does not modify or delete audit records."
    ),
)
def list_audit_events(
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(audit_pagination),
    date_range: DateRangeParams = Depends(audit_date_range),
    search: SearchParams = Depends(audit_search),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
    action: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audit action name."),
    ] = None,
    resource_type: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audited resource type."),
    ] = None,
    resource_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by audited resource identifier."),
    ] = None,
    actor_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by actor user identifier."),
    ] = None,
    actor_username: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by actor username."),
    ] = None,
    actor_role: Annotated[
        Optional[str],
        Query(max_length=50, description="Filter by actor role."),
    ] = None,
    outcome: Annotated[
        Optional[AuditOutcome],
        Query(description="Filter by audit outcome."),
    ] = None,
    request_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by request/correlation ID."),
    ] = None,
    ip_hash: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by hashed client IP."),
    ] = None,
) -> AuditEventListResponse:
    """
    List audit events with bounded pagination and safe filters.
    """
    _ensure_audit_enabled(settings)

    _validate_date_range(date_range.date_from, date_range.date_to, "created_from", "created_to")
    _validate_span(date_range.date_from, date_range.date_to, settings)

    conditions = _build_conditions(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=actor_id,
        actor_username=actor_username,
        actor_role=actor_role,
        outcome=outcome,
        request_id=request_id,
        ip_hash=ip_hash,
        date_range=date_range,
        search=search,
    )

    count_stmt = select(func.count()).select_from(AuditEvent)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(AuditEvent)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_AUDIT_EVENT_COLUMN_MAP,
        tiebreaker=_EVENT_TIEBREAKER,
        default_sort_by=_EVENT_DEFAULT_SORT,
        default_sort_order="desc",
    )

    events = db.scalars(stmt).all()

    return AuditEventListResponse(
        items=[_event_response(event) for event in events],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_AUDIT_CAVEATS),
    )


@router.get(
    "/stats",
    response_model=AuditStatsResponse,
    summary="Get aggregate audit statistics",
    description=(
        "Returns bounded aggregate audit statistics for oversight and "
        "operational review. Statistics are derived from persisted audit events "
        "and are investigative/accountability signals only."
    ),
)
def audit_stats(
    db: SessionDep,
    settings: SettingsDep,
    date_range: DateRangeParams = Depends(audit_date_range),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
    action: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audit action name."),
    ] = None,
    resource_type: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audited resource type."),
    ] = None,
    outcome: Annotated[
        Optional[AuditOutcome],
        Query(description="Filter by audit outcome."),
    ] = None,
    top_limit: Annotated[
        int,
        Query(ge=1, le=_TOP_LIMIT_MAX, description="Maximum top-N categories to return."),
    ] = _TOP_LIMIT_DEFAULT,
) -> AuditStatsResponse:
    """
    Return bounded aggregate audit statistics.
    """
    _ensure_audit_enabled(settings)

    resolved_range, defaulted = _resolve_stats_range(date_range, settings)

    conditions = _build_conditions(
        action=action,
        resource_type=resource_type,
        resource_id=None,
        actor_id=None,
        actor_username=None,
        actor_role=None,
        outcome=outcome,
        request_id=None,
        ip_hash=None,
        date_range=resolved_range,
        search=None,
    )

    total_events = _scalar_count(
        db,
        _apply_conditions(select(func.count()).select_from(AuditEvent), conditions),
    )

    outcome_counts = {
        "SUCCESS": 0,
        "FAILURE": 0,
        "DENIED": 0,
        "OTHER": 0,
    }

    outcome_column = _model_column(AuditEvent, "outcome")

    if outcome_column is not None:
        outcome_stmt = select(outcome_column, func.count().label("count"))
        outcome_stmt = _apply_conditions(outcome_stmt, conditions)
        outcome_stmt = outcome_stmt.group_by(outcome_column)

        for row in db.execute(outcome_stmt).all():
            key = _enum_str(row[0]) or "OTHER"

            if key not in outcome_counts:
                key = "OTHER"

            outcome_counts[key] += int(row[1] or 0)
    else:
        outcome_counts["OTHER"] = total_events

    distinct_actor_count = 0
    actor_id_column = _model_column(AuditEvent, "actor_id")

    if actor_id_column is not None:
        distinct_stmt = select(func.count(func.distinct(actor_id_column)))
        distinct_stmt = _apply_conditions(distinct_stmt, conditions)
        distinct_actor_count = int(db.scalar(distinct_stmt) or 0)

    action_column = _model_column(AuditEvent, "action")
    resource_type_column = _model_column(AuditEvent, "resource_type")
    actor_username_column = _model_column(AuditEvent, "actor_username")

    effective_top_limit = max(1, min(int(top_limit), _TOP_LIMIT_MAX))

    return AuditStatsResponse(
        period={
            "date_from": resolved_range.date_from.isoformat() if resolved_range.date_from else None,
            "date_to": resolved_range.date_to.isoformat() if resolved_range.date_to else None,
            "defaulted": defaulted,
            "max_span_days": _max_date_span_days(settings),
        },
        total_events=total_events,
        outcome_counts=outcome_counts,
        distinct_actor_count=distinct_actor_count,
        top_actions=_top_group(db, action_column, conditions, effective_top_limit),
        top_resource_types=_top_group(db, resource_type_column, conditions, effective_top_limit),
        top_actors=_top_group(db, actor_username_column, conditions, effective_top_limit),
        caveats=list(_STATS_CAVEATS),
    )


@router.get(
    "/export",
    response_model=None,
    summary="Export bounded audit events",
    description=(
        "Exports a bounded set of sanitised audit events as JSON or CSV. "
        "This endpoint is restricted to authorised auditors/administrators and "
        "records its own audit event. Exports may be truncated according to "
        "configured limits."
    ),
)
def export_audit_events(
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.AUDIT_EXPORT)),
    date_range: DateRangeParams = Depends(audit_date_range),
    search: SearchParams = Depends(audit_search),
    export_format: Annotated[
        Literal["json", "csv"],
        Query(alias="format", description="Export serialisation format."),
    ] = "json",
    max_rows: Annotated[
        Optional[int],
        Query(ge=1, description="Maximum rows to export. Clamped to configured limits."),
    ] = None,
    include_metadata: Annotated[
        bool,
        Query(description="Include sanitised metadata_json in exported rows."),
    ] = True,
    action: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audit action name."),
    ] = None,
    resource_type: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audited resource type."),
    ] = None,
    resource_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by audited resource identifier."),
    ] = None,
    actor_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by actor user identifier."),
    ] = None,
    actor_username: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by actor username."),
    ] = None,
    actor_role: Annotated[
        Optional[str],
        Query(max_length=50, description="Filter by actor role."),
    ] = None,
    outcome: Annotated[
        Optional[AuditOutcome],
        Query(description="Filter by audit outcome."),
    ] = None,
    export_request_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by request/correlation ID."),
    ] = None,
    ip_hash: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by hashed client IP."),
    ] = None,
    _: None = Depends(rate_limited(key_prefix="audit_export", by="user_and_ip")),
) -> Response:
    """
    Export bounded audit events as JSON or CSV.
    """
    _ensure_audit_enabled(settings)

    if not _audit_export_enabled(settings):
        raise FeatureFlagDisabledError("Audit export is disabled by configuration.")

    _validate_date_range(date_range.date_from, date_range.date_to, "created_from", "created_to")
    _validate_span(date_range.date_from, date_range.date_to, settings)

    conditions = _build_conditions(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=actor_id,
        actor_username=actor_username,
        actor_role=actor_role,
        outcome=outcome,
        request_id=export_request_id,
        ip_hash=ip_hash,
        date_range=date_range,
        search=search,
    )

    total_matching = _scalar_count(
        db,
        _apply_conditions(select(func.count()).select_from(AuditEvent), conditions),
    )

    configured_max, hard_max = _export_max_rows(settings)
    requested_max = max_rows if max_rows is not None else configured_max
    effective_max = max(1, min(int(requested_max), int(configured_max), int(hard_max)))

    stmt = select(AuditEvent)
    stmt = _apply_conditions(stmt, conditions)

    created_at_column = _model_column(AuditEvent, "created_at")
    id_column = _model_column(AuditEvent, "id")

    if created_at_column is not None:
        stmt = stmt.order_by(asc(created_at_column))

    if id_column is not None:
        stmt = stmt.order_by(asc(id_column))

    stmt = stmt.limit(effective_max)

    rows = db.scalars(stmt).all()
    events = [_event_response(row, include_metadata=include_metadata) for row in rows]

    truncated = total_matching > len(events)
    export_id = secrets.token_hex(16)
    generated_at = _now_utc()

    filters = _filters_summary(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=actor_id,
        actor_username=actor_username,
        actor_role=actor_role,
        outcome=outcome,
        request_id=export_request_id,
        ip_hash=ip_hash,
        date_range=date_range,
        search=search,
    )

    if export_format == "csv":
        content = _build_csv_content(events, include_metadata=include_metadata)
        media_type = "text/csv; charset=utf-8"
    else:
        content = _build_json_content(
            export_id=export_id,
            generated_at=generated_at,
            events=events,
            total_matching=total_matching,
            truncated=truncated,
            max_rows=effective_max,
            include_metadata=include_metadata,
            filters=filters,
        )
        media_type = "application/json"

    filename = _safe_filename(export_format, generated_at, export_id)

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Export-ID": export_id,
        "X-Export-Rows": str(len(events)),
        "X-Export-Truncated": str(truncated).lower(),
        "X-Export-Max-Rows": str(effective_max),
        "Cache-Control": "no-store",
    }

    if request_id:
        headers["X-Request-ID"] = request_id

    _add_audit_event(
        db,
        action="audit_export",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="audit_export",
        resource_id=export_id,
        ip_hash=_ip_hash(request, settings),
        metadata={
            "format": export_format,
            "row_count": len(events),
            "total_matching": total_matching,
            "truncated": truncated,
            "max_rows": effective_max,
            "include_metadata": include_metadata,
            "filters": filters,
            "requested_by": str(actor.id),
            "request_id": request_id,
        },
    )

    try:
        db.commit()
    except Exception as exc:
        logger.exception("Failed to persist audit export event.")
        raise InternalError(
            "Audit export could not be completed.",
            details={"error_type": type(exc).__name__},
        ) from exc

    return Response(
        content=content,
        media_type=media_type,
        headers=headers,
    )


@router.get(
    "/{event_id}",
    response_model=AuditEventDetailResponse,
    summary="Get one audit event",
    description=(
        "Returns a safe detail view for one synthetic MULEGUARD audit event. "
        "Audit history is read-only and sanitised."
    ),
)
def get_audit_event(
    event_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Audit event identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
) -> AuditEventDetailResponse:
    """
    Retrieve one audit event.
    """
    _ensure_audit_enabled(settings)

    event = db.get(AuditEvent, event_id)

    if event is None:
        raise NotFoundError.resource("audit_event", event_id)

    return AuditEventDetailResponse(
        event=_event_response(event, include_metadata=True),
        caveats=list(_AUDIT_CAVEATS),
    )


__all__ = [
    "router",
]