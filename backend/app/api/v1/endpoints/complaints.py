"""
MULEGUARD backend API v1 complaint endpoints.

This module implements the versioned `/api/v1/complaints` read-mostly
investigation surface for synthetic MULEGUARD complaints and complaint
correlations.

Implemented endpoints:

- GET  /api/v1/complaints
- GET  /api/v1/complaints/stats
- GET  /api/v1/complaints/{complaint_id}
- GET  /api/v1/complaints/{complaint_id}/correlations
- POST /api/v1/complaints/{complaint_id}/correlations/{correlation_id}/review-state
- GET  /api/v1/complaints/{complaint_id}/accounts
- GET  /api/v1/complaints/{complaint_id}/transactions
- GET  /api/v1/complaints/{complaint_id}/entities
- GET  /api/v1/complaints/{complaint_id}/alerts
- GET  /api/v1/complaints/{complaint_id}/history
- GET  /api/v1/complaints/{complaint_id}/export

Design goals:

- provide real, persisted, evidence-backed complaint investigation views;
- enforce server-side RBAC through dependency permissions;
- keep list endpoints paginated, filtered, searched, and stably ordered;
- preserve exact-vs-inferred provenance for complaint correlations through
  match tier, match method, determinism, confidence, and review state;
- allow authorised senior investigators/administrators to update correlation
  review state with durable audit records;
- never return raw or normalized complaint narratives;
- never expose synthetic ground-truth labels, scenario IDs, ring IDs,
  passwords, tokens, secrets, database URLs, or real customer data;
- make clear that complaints, correlations, alerts, scores, graph relationships,
  candidate money trails, and entity links are investigative leads only.

Explicit non-goals:

- This module does not create, edit, delete, or ingest complaints.
- This module does not connect to real complaint systems, banks, payment rails,
  or customer support platforms.
- This module does not take adverse action against accounts or customers.
- This module does not compute ML scores inline.
- This module does not return complaint narrative text.
- This module does not claim production readiness or real-world fraud-detection
  accuracy.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, and review states are investigative leads or human workflow
artefacts only. They are not proof of wrongdoing and must not trigger automatic
adverse customer action.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Final, Optional

from fastapi import APIRouter, Depends, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    AmountRangeParams,
    DateRangeParams,
    PageParams,
    Permission,
    RequestIDDep,
    SearchParams,
    SessionDep,
    SettingsDep,
    amount_range_dependency,
    apply_pagination,
    date_range_dependency,
    pagination_dependency,
    require_permission,
    require_roles,
    search_dependency,
)
from app.exceptions import (
    ConflictError,
    FeatureFlagDisabledError,
    NotFoundError,
    ValidationError as MuleGuardValidationError,
)
from app.models import (
    Account,
    AccountStatus,
    AccountType,
    Alert,
    AlertEvidence,
    AlertState,
    AuditEvent,
    AuditOutcome,
    Channel,
    Complaint,
    ComplaintCorrelation,
    ComplaintReviewState,
    Entity,
    EntityType,
    EvidenceType,
    MatchMethod,
    Priority,
    Transaction,
    TransactionStatus,
    User,
    UserRole,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.complaints")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["complaints"])


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_NOTE_LENGTH: Final[int] = 1000
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_MAPPING_KEYS: Final[int] = 100
_MAX_JSON_DEPTH: Final[int] = 6

_EXPORT_DEFAULT_MAX_ITEMS: Final[int] = 200
_EXPORT_HARD_MAX_ITEMS: Final[int] = 1000

_STATS_TOP_LIMIT_DEFAULT: Final[int] = 10
_STATS_TOP_LIMIT_MAX: Final[int] = 50
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

_COMPLAINT_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Complaints are investigative inputs only and are not proof of wrongdoing.",
    "Raw and normalized complaint narratives are intentionally not returned.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    "This API does not freeze, block, blacklist, close, restrict, or otherwise take adverse action against accounts or customers.",
)

_CORRELATION_CAVEATS: Final[tuple[str, ...]] = (
    *_COMPLAINT_CAVEATS,
    "Complaint correlations are investigative leads only.",
    "Exact matches are distinguished from inferred associations through match tier, method, determinism, and confidence.",
    "Inferred correlations are not verified facts.",
)

_LINKED_ACCOUNT_CAVEATS: Final[tuple[str, ...]] = (
    *_CORRELATION_CAVEATS,
    "Linked accounts are associated through complaint correlations only.",
    "Account links are investigative associations, not proof of common control or wrongdoing.",
)

_LINKED_TRANSACTION_CAVEATS: Final[tuple[str, ...]] = (
    *_CORRELATION_CAVEATS,
    "Linked transactions are associated through complaint correlations only.",
    "Completed transfers are treated as fund movement; pending, failed, and reversed records are not treated as completed transfers.",
)

_LINKED_ENTITY_CAVEATS: Final[tuple[str, ...]] = (
    *_CORRELATION_CAVEATS,
    "Linked entities are pseudonymous synthetic associations such as devices, hashed phones, UPI IDs, emails, addresses, or IPs.",
    "Raw identifier hashes are intentionally not returned.",
)

_ALERT_CAVEATS: Final[tuple[str, ...]] = (
    *_COMPLAINT_CAVEATS,
    "Alerts are investigative leads only.",
    "Alert evidence references must be reviewed by an authorised investigator.",
)

_HISTORY_CAVEATS: Final[tuple[str, ...]] = (
    *_COMPLAINT_CAVEATS,
    "Complaint history contains safe audit metadata only.",
    "Passwords, tokens, secrets, raw narratives, and unnecessary sensitive payloads are not stored in audit metadata.",
)

_EXPORT_CAVEATS: Final[tuple[str, ...]] = (
    *_COMPLAINT_CAVEATS,
    "Export bundles are bounded and may be truncated.",
    "Export bundles do not include raw complaint narratives.",
    "Export bundles do not include ground-truth labels, scenario IDs, or fraud-ring IDs.",
)

_REVIEW_CAVEATS: Final[tuple[str, ...]] = (
    *_CORRELATION_CAVEATS,
    "Review-state updates are investigator judgements, not automatic enforcement actions.",
    "This endpoint does not freeze, block, blacklist, close, or otherwise take adverse action against any account.",
)

_STATS_CAVEATS: Final[tuple[str, ...]] = (
    *_COMPLAINT_CAVEATS,
    "Aggregate statistics are operational oversight signals only.",
    "Low-count categories may be privacy-sensitive and should be interpreted cautiously.",
)


# -----------------------------------------------------------------------------
# Dynamic column helpers
# -----------------------------------------------------------------------------


def _model_column(model: Any, name: str) -> Any | None:
    """
    Return a SQLAlchemy column attribute when present.
    """
    return getattr(model, name, None)


def _first_column(model: Any, *names: str) -> Any | None:
    """
    Return the first existing column attribute among names.
    """
    for name in names:
        column = _model_column(model, name)

        if column is not None:
            return column

    return None


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


def _default_sort_name(column_map: Mapping[str, Any], preferred: Sequence[str]) -> str:
    """
    Return the first preferred sortable field present in the column map.
    """
    for name in preferred:
        if name in column_map:
            return name

    return next(iter(column_map), "id")


_COMPLAINT_CREATED_AT = _first_column(Complaint, "record_created_at", "created_at")
_COMPLAINT_UPDATED_AT = _first_column(Complaint, "record_updated_at", "updated_at")

_COMPLAINT_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(Complaint, "id"),
        "created_at": _COMPLAINT_CREATED_AT,
        "updated_at": _COMPLAINT_UPDATED_AT,
        "reference": _model_column(Complaint, "reference"),
        "category": _model_column(Complaint, "category"),
        "reported_at": _model_column(Complaint, "reported_at"),
        "amount": _model_column(Complaint, "amount"),
        "currency": _model_column(Complaint, "currency"),
        "source": _model_column(Complaint, "source"),
    }.items()
    if column is not None
}

_COMPLAINT_TIEBREAKER = _model_column(Complaint, "id")
_COMPLAINT_DEFAULT_SORT = _default_sort_name(
    _COMPLAINT_COLUMN_MAP,
    ("created_at", "reported_at", "id"),
)

_CORRELATION_CREATED_AT = _first_column(
    ComplaintCorrelation,
    "record_created_at",
    "created_at",
)

_CORRELATION_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(ComplaintCorrelation, "id"),
        "created_at": _CORRELATION_CREATED_AT,
        "match_tier": _model_column(ComplaintCorrelation, "match_tier"),
        "confidence": _model_column(ComplaintCorrelation, "confidence"),
        "review_state": _model_column(ComplaintCorrelation, "review_state"),
        "match_method": _model_column(ComplaintCorrelation, "match_method"),
        "deterministic": _model_column(ComplaintCorrelation, "deterministic"),
        "account_id": _model_column(ComplaintCorrelation, "account_id"),
        "transaction_id": _model_column(ComplaintCorrelation, "transaction_id"),
        "entity_id": _model_column(ComplaintCorrelation, "entity_id"),
    }.items()
    if column is not None
}

_CORRELATION_TIEBREAKER = _model_column(ComplaintCorrelation, "id")
_CORRELATION_DEFAULT_SORT = _default_sort_name(
    _CORRELATION_COLUMN_MAP,
    ("created_at", "id"),
)

_ACCOUNT_CREATED_AT = _first_column(Account, "record_created_at", "created_at")
_ACCOUNT_UPDATED_AT = _first_column(Account, "record_updated_at", "updated_at")

_ACCOUNT_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(Account, "id"),
        "created_at": _ACCOUNT_CREATED_AT,
        "updated_at": _ACCOUNT_UPDATED_AT,
        "account_type": _model_column(Account, "account_type"),
        "status": _model_column(Account, "status"),
    }.items()
    if column is not None
}

_ACCOUNT_TIEBREAKER = _model_column(Account, "id")
_ACCOUNT_DEFAULT_SORT = _default_sort_name(
    _ACCOUNT_COLUMN_MAP,
    ("created_at", "id"),
)

_TRANSACTION_CREATED_AT = _first_column(Transaction, "record_created_at", "created_at")

_TRANSACTION_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(Transaction, "id"),
        "created_at": _TRANSACTION_CREATED_AT,
        "occurred_at": _model_column(Transaction, "occurred_at"),
        "amount": _model_column(Transaction, "amount"),
        "status": _model_column(Transaction, "status"),
        "channel": _model_column(Transaction, "channel"),
        "reference": _model_column(Transaction, "reference"),
    }.items()
    if column is not None
}

_TRANSACTION_TIEBREAKER = _model_column(Transaction, "id")
_TRANSACTION_DEFAULT_SORT = _default_sort_name(
    _TRANSACTION_COLUMN_MAP,
    ("occurred_at", "created_at", "id"),
)

_ENTITY_CREATED_AT = _first_column(Entity, "record_created_at", "created_at")

_ENTITY_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(Entity, "id"),
        "created_at": _ENTITY_CREATED_AT,
        "entity_type": _model_column(Entity, "entity_type"),
        "source": _model_column(Entity, "source"),
        "first_seen_at": _model_column(Entity, "first_seen_at"),
        "last_seen_at": _model_column(Entity, "last_seen_at"),
    }.items()
    if column is not None
}

_ENTITY_TIEBREAKER = _model_column(Entity, "id")
_ENTITY_DEFAULT_SORT = _default_sort_name(
    _ENTITY_COLUMN_MAP,
    ("created_at", "id"),
)

_ALERT_CREATED_AT = _first_column(Alert, "record_created_at", "created_at")

_ALERT_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(Alert, "id"),
        "created_at": _ALERT_CREATED_AT,
        "priority": _model_column(Alert, "priority"),
        "state": _model_column(Alert, "state"),
        "score": _model_column(Alert, "score"),
        "first_seen_at": _model_column(Alert, "first_seen_at"),
        "last_seen_at": _model_column(Alert, "last_seen_at"),
    }.items()
    if column is not None
}

_ALERT_TIEBREAKER = _model_column(Alert, "id")
_ALERT_DEFAULT_SORT = _default_sort_name(
    _ALERT_COLUMN_MAP,
    ("created_at", "id"),
)

_AUDIT_CREATED_AT = _first_column(AuditEvent, "created_at", "record_created_at")

_AUDIT_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(AuditEvent, "id"),
        "created_at": _AUDIT_CREATED_AT,
        "action": _model_column(AuditEvent, "action"),
        "outcome": _model_column(AuditEvent, "outcome"),
        "actor_username": _model_column(AuditEvent, "actor_username"),
    }.items()
    if column is not None
}

_AUDIT_TIEBREAKER = _model_column(AuditEvent, "id")
_AUDIT_DEFAULT_SORT = _default_sort_name(
    _AUDIT_COLUMN_MAP,
    ("created_at", "id"),
)


# -----------------------------------------------------------------------------
# Reusable bounded dependencies
# -----------------------------------------------------------------------------

complaint_pagination = pagination_dependency(
    sortable_fields=tuple(_COMPLAINT_COLUMN_MAP.keys()),
    default_sort_by=_COMPLAINT_DEFAULT_SORT,
    default_sort_order="desc",
)

correlation_pagination = pagination_dependency(
    sortable_fields=tuple(_CORRELATION_COLUMN_MAP.keys()),
    default_sort_by=_CORRELATION_DEFAULT_SORT,
    default_sort_order="desc",
)

account_pagination = pagination_dependency(
    sortable_fields=tuple(_ACCOUNT_COLUMN_MAP.keys()),
    default_sort_by=_ACCOUNT_DEFAULT_SORT,
    default_sort_order="desc",
)

transaction_pagination = pagination_dependency(
    sortable_fields=tuple(_TRANSACTION_COLUMN_MAP.keys()),
    default_sort_by=_TRANSACTION_DEFAULT_SORT,
    default_sort_order="desc",
)

entity_pagination = pagination_dependency(
    sortable_fields=tuple(_ENTITY_COLUMN_MAP.keys()),
    default_sort_by=_ENTITY_DEFAULT_SORT,
    default_sort_order="desc",
)

alert_pagination = pagination_dependency(
    sortable_fields=tuple(_ALERT_COLUMN_MAP.keys()),
    default_sort_by=_ALERT_DEFAULT_SORT,
    default_sort_order="desc",
)

audit_pagination = pagination_dependency(
    sortable_fields=tuple(_AUDIT_COLUMN_MAP.keys()),
    default_sort_by=_AUDIT_DEFAULT_SORT,
    default_sort_order="desc",
)

complaint_date_range = date_range_dependency(max_span_days=0)
transaction_date_range = date_range_dependency(max_span_days=0)

complaint_amount_range = amount_range_dependency(allow_negative=False)
transaction_amount_range = amount_range_dependency(allow_negative=False)

complaint_search = search_dependency(max_length=200, alias="q")
correlation_search = search_dependency(max_length=200, alias="q")
account_search = search_dependency(max_length=200, alias="q")
transaction_search = search_dependency(max_length=200, alias="q")
entity_search = search_dependency(max_length=200, alias="q")
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


def _set_if_exists(obj: Any, name: str, value: Any) -> None:
    """
    Set an attribute only when it exists on the object.
    """
    if hasattr(obj, name):
        setattr(obj, name, value)


def _str_or_none(value: Any) -> Optional[str]:
    """
    Return a stripped string or None.
    """
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _timestamp_value(obj: Any, *names: str) -> Optional[datetime]:
    """
    Return the first non-null timestamp-like attribute.
    """
    for name in names:
        value = _get_if_exists(obj, name, None)

        if value is not None:
            return value

    return None


def _sha256_text(value: str) -> str:
    """
    Return a SHA-256 hex digest for integrity/reference purposes.

    This is not used for secrets or passwords.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text_audit_metadata(value: Optional[str], *, field_name: str) -> dict[str, Any]:
    """
    Return safe audit metadata for an optional note.

    The full text is not duplicated into audit metadata.
    """
    if not value:
        return {}

    return {
        f"{field_name}_length": len(value),
        f"{field_name}_sha256": _sha256_text(value),
    }


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
    Return sanitized audit metadata.
    """
    if not metadata:
        return {}

    return _sanitize_json_object(
        metadata,
        max_sequence_length=50,
        max_mapping_keys=50,
    )


def _safe_string_list(value: Any, *, max_items: int = _MAX_LIST_LENGTH) -> list[str]:
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


# -----------------------------------------------------------------------------
# Client IP / audit helpers
# -----------------------------------------------------------------------------


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
        or "muleguard-complaints"
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


# -----------------------------------------------------------------------------
# Policy helpers
# -----------------------------------------------------------------------------


def _ensure_complaints_enabled(settings: Any) -> None:
    """
    Fail closed when the complaint API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "COMPLAINTS_API_ENABLED", True), True):
        raise FeatureFlagDisabledError("Complaint endpoints are disabled by configuration.")

    if not _as_bool(_setting(settings, "COMPLAINT_ENGINE_ENABLED", True), True):
        raise FeatureFlagDisabledError("Complaint engine is disabled by configuration.")


def _ensure_complaint_stats_enabled(settings: Any) -> None:
    """
    Fail closed when complaint statistics are disabled.
    """
    _ensure_complaints_enabled(settings)

    if not _as_bool(_setting(settings, "COMPLAINT_STATS_ENABLED", True), True):
        raise FeatureFlagDisabledError("Complaint statistics are disabled by configuration.")


def _ensure_complaint_review_enabled(settings: Any) -> None:
    """
    Fail closed when complaint correlation review updates are disabled.
    """
    _ensure_complaints_enabled(settings)

    if not _as_bool(_setting(settings, "COMPLAINT_REVIEW_ENABLED", True), True):
        raise FeatureFlagDisabledError(
            "Complaint correlation review updates are disabled by configuration."
        )


def _max_complaint_date_span_days(settings: Any) -> int:
    """
    Return bounded maximum complaint query date span in days.
    """
    return max(
        1,
        _as_int(_setting(settings, "COMPLAINT_MAX_DATE_SPAN_DAYS", 3650), 3650),
    )


def _complaint_export_max_items(settings: Any) -> int:
    """
    Return bounded maximum items embedded in complaint export bundles.
    """
    configured = max(
        1,
        _as_int(
            _setting(settings, "COMPLAINT_EXPORT_MAX_ITEMS", _EXPORT_DEFAULT_MAX_ITEMS),
            _EXPORT_DEFAULT_MAX_ITEMS,
        ),
    )
    hard = max(
        configured,
        _as_int(
            _setting(settings, "COMPLAINT_EXPORT_HARD_MAX_ITEMS", _EXPORT_HARD_MAX_ITEMS),
            _EXPORT_HARD_MAX_ITEMS,
        ),
    )

    return min(configured, hard)


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


def _validate_complaint_span(
    start: Optional[datetime],
    end: Optional[datetime],
    settings: Any,
) -> None:
    """
    Enforce optional maximum date span for complaint scans.
    """
    if start is None or end is None:
        return

    max_days = _max_complaint_date_span_days(settings)
    span = end - start
    max_delta = timedelta(days=max_days)

    if span > max_delta:
        raise MuleGuardValidationError(
            "Complaint date span exceeds configured maximum.",
            details={
                "max_span_days": max_days,
                "requested_span_days": round(span.total_seconds() / 86400.0, 3),
            },
        )


def _validate_not_future(value: Optional[datetime], field_name: str) -> None:
    """
    Reject future point-in-time parameters.
    """
    if value is not None and value > _now_utc():
        raise MuleGuardValidationError(
            f"{field_name} must not be in the future.",
            details={field_name: value.isoformat()},
        )


def _resolve_stats_range(
    date_range: DateRangeParams,
    settings: Any,
) -> tuple[DateRangeParams, bool]:
    """
    Resolve a bounded default window for complaint statistics.
    """
    start = date_range.date_from
    end = date_range.date_to
    defaulted = False

    max_span = _max_complaint_date_span_days(settings)
    default_days = max(
        1,
        min(
            _as_int(
                _setting(settings, "COMPLAINT_STATS_DEFAULT_DAYS", _STATS_DEFAULT_DAYS),
                _STATS_DEFAULT_DAYS,
            ),
            max_span,
        ),
    )

    if end is None:
        end = _now_utc()
        defaulted = True

    if start is None:
        start = end - timedelta(days=default_days)
        defaulted = True

    _validate_date_range(start, end, "date_from", "date_to")
    _validate_complaint_span(start, end, settings)

    return DateRangeParams(date_from=start, date_to=end), defaulted


def _normalize_text(value: Optional[str], *, max_length: int = 100, field_name: str) -> Optional[str]:
    """
    Normalize and bound an optional text filter.
    """
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    if len(text) > max_length:
        raise MuleGuardValidationError(
            f"{field_name} is too long.",
            details={field_name: text[:max_length]},
        )

    return text


# -----------------------------------------------------------------------------
# Lookup helpers
# -----------------------------------------------------------------------------


def _get_complaint_or_404(db: Session, complaint_id: str) -> Complaint:
    """
    Load a synthetic complaint or raise a safe not-found error.
    """
    complaint = db.get(Complaint, complaint_id)

    if complaint is None:
        raise NotFoundError.resource("complaint", complaint_id)

    return complaint


def _get_correlation_or_404(
    db: Session,
    complaint_id: str,
    correlation_id: str,
) -> ComplaintCorrelation:
    """
    Load a complaint correlation belonging to the given complaint or raise 404.
    """
    correlation = db.get(ComplaintCorrelation, correlation_id)

    if (
        correlation is None
        or str(_get_if_exists(correlation, "complaint_id", "")) != str(complaint_id)
    ):
        raise NotFoundError.resource("complaint_correlation", correlation_id)

    return correlation


# -----------------------------------------------------------------------------
# Count helpers
# -----------------------------------------------------------------------------


def _correlation_counts_for_complaint_ids(
    db: Session,
    complaint_ids: Sequence[str],
) -> dict[str, int]:
    """
    Return bounded complaint-correlation counts for a set of complaint IDs.
    """
    ids = [str(complaint_id) for complaint_id in complaint_ids if complaint_id]

    if not ids:
        return {}

    complaint_id_column = _model_column(ComplaintCorrelation, "complaint_id")

    if complaint_id_column is None:
        return {}

    rows = db.execute(
        select(complaint_id_column, func.count())
        .where(complaint_id_column.in_(ids))
        .group_by(complaint_id_column)
    ).all()

    return {str(row[0]): int(row[1] or 0) for row in rows}


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class ComplaintResponse(BaseModel):
    """
    Safe synthetic complaint response.

    Raw and normalized narratives are intentionally not returned.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    reference: str
    category: str
    reported_at: datetime
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    source: Optional[str] = None
    victim_account_id: Optional[str] = None
    suspected_account_id: Optional[str] = None
    transaction_reference: Optional[str] = None
    narrative_available: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    correlation_count: Optional[int] = None


class ComplaintListResponse(BaseModel):
    """
    Paginated complaint list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[ComplaintResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ComplaintCorrelationResponse(BaseModel):
    """
    Complaint correlation view.

    Raw and normalized complaint narratives are intentionally not returned.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    complaint_id: str
    complaint_reference: Optional[str] = None
    complaint_category: Optional[str] = None
    complaint_reported_at: Optional[datetime] = None
    complaint_amount: Optional[Decimal] = None
    complaint_currency: Optional[str] = None
    complaint_source: Optional[str] = None
    complaint_narrative_available: bool = False

    account_id: Optional[str] = None
    transaction_id: Optional[str] = None
    entity_id: Optional[str] = None

    match_tier: int
    match_method: str
    confidence: Optional[Decimal] = None
    deterministic: bool
    review_state: str
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None


class ComplaintCorrelationListResponse(BaseModel):
    """
    Paginated complaint-correlation list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[ComplaintCorrelationResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ComplaintLinkedAccountResponse(BaseModel):
    """
    Account linked to a complaint through a persisted correlation.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_type: str
    status: str
    created_at: Optional[datetime] = None

    correlation_id: str
    match_tier: int
    match_method: str
    confidence: Optional[Decimal] = None
    deterministic: bool
    review_state: str


class ComplaintLinkedAccountListResponse(BaseModel):
    """
    Paginated linked-account list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[ComplaintLinkedAccountResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ComplaintLinkedTransactionResponse(BaseModel):
    """
    Transaction linked to a complaint through a persisted correlation.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    sender_account_id: str
    receiver_account_id: str
    amount: Decimal
    currency: str
    occurred_at: datetime
    status: str
    channel: str
    reference: str

    correlation_id: str
    match_tier: int
    match_method: str
    confidence: Optional[Decimal] = None
    deterministic: bool
    review_state: str


class ComplaintLinkedTransactionListResponse(BaseModel):
    """
    Paginated linked-transaction list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[ComplaintLinkedTransactionResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ComplaintLinkedEntityResponse(BaseModel):
    """
    Pseudonymous entity linked to a complaint through a persisted correlation.

    Raw identifier hashes are intentionally not returned.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    entity_type: str
    identifier_display: Optional[str] = None
    source: str

    correlation_id: str
    match_tier: int
    match_method: str
    confidence: Optional[Decimal] = None
    deterministic: bool
    review_state: str


class ComplaintLinkedEntityListResponse(BaseModel):
    """
    Paginated linked-entity list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[ComplaintLinkedEntityResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ComplaintAlertResponse(BaseModel):
    """
    Safe investigative alert summary referencing a complaint.
    """

    model_config = ConfigDict(from_attributes=False)

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
    model_version: Optional[str] = None
    rule_codes: list[str] = Field(default_factory=list)
    signal_summary_json: Optional[Any] = None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: Optional[datetime] = None


class ComplaintAlertListResponse(BaseModel):
    """
    Paginated alert list response referencing a complaint.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[ComplaintAlertResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ComplaintHistoryEventResponse(BaseModel):
    """
    Safe audit history event for a complaint or complaint correlation.
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
    created_at: Optional[datetime] = None


class ComplaintHistoryListResponse(BaseModel):
    """
    Paginated complaint history response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[ComplaintHistoryEventResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ComplaintExportBundleResponse(BaseModel):
    """
    Bounded JSON export bundle for one synthetic complaint.
    """

    model_config = ConfigDict(from_attributes=False)

    complaint: ComplaintResponse
    correlations: list[ComplaintCorrelationResponse] = Field(default_factory=list)
    correlation_total: int = 0
    correlation_truncated: bool = False
    max_items: int = 0
    caveats: list[str] = Field(default_factory=list)


class ComplaintStatsResponse(BaseModel):
    """
    Safe aggregate complaint statistics response.
    """

    model_config = ConfigDict(from_attributes=False)

    period: dict[str, Any] = Field(default_factory=dict)
    total_complaints: int = 0
    total_correlations: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    by_match_tier: dict[str, int] = Field(default_factory=dict)
    by_review_state: dict[str, int] = Field(default_factory=dict)
    deterministic_count: int = 0
    inferred_count: int = 0
    caveats: list[str] = Field(default_factory=list)


class ComplaintCorrelationReviewUpdateRequest(BaseModel):
    """
    Authorised investigator request to update a complaint-correlation review state.
    """

    model_config = ConfigDict(extra="forbid")

    review_state: ComplaintReviewState = Field(
        description="New review state for the complaint correlation.",
    )
    note: Optional[str] = Field(
        default=None,
        max_length=_MAX_NOTE_LENGTH,
        description=(
            "Optional investigator note. Do not include secrets, tokens, "
            "passwords, raw complaint narratives, or unnecessary sensitive text."
        ),
    )

    @field_validator("note")
    @classmethod
    def _validate_note(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > _MAX_NOTE_LENGTH:
            raise ValueError("note is too long")

        return normalized


class ComplaintCorrelationReviewUpdateResponse(BaseModel):
    """
    Response from updating a complaint-correlation review state.
    """

    model_config = ConfigDict(from_attributes=False)

    correlation: ComplaintCorrelationResponse
    complaint: ComplaintResponse
    changed: bool
    previous_state: str
    new_state: str
    audited: bool
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Response builders
# -----------------------------------------------------------------------------


def _complaint_response(
    complaint: Complaint,
    correlation_count: Optional[int] = None,
) -> ComplaintResponse:
    """
    Build a safe complaint response.
    """
    return ComplaintResponse(
        id=str(_get_if_exists(complaint, "id", "")),
        reference=str(_get_if_exists(complaint, "reference", "") or ""),
        category=str(_get_if_exists(complaint, "category", "") or ""),
        reported_at=_get_if_exists(complaint, "reported_at", _now_utc()),
        amount=_get_if_exists(complaint, "amount", None),
        currency=_str_or_none(_get_if_exists(complaint, "currency", None)),
        source=_str_or_none(_get_if_exists(complaint, "source", None)),
        victim_account_id=_str_or_none(_get_if_exists(complaint, "victim_account_id", None)),
        suspected_account_id=_str_or_none(_get_if_exists(complaint, "suspected_account_id", None)),
        transaction_reference=_str_or_none(_get_if_exists(complaint, "transaction_reference", None)),
        narrative_available=bool(_get_if_exists(complaint, "narrative_raw", None)),
        created_at=_timestamp_value(complaint, "record_created_at", "created_at"),
        updated_at=_timestamp_value(complaint, "record_updated_at", "updated_at"),
        correlation_count=correlation_count,
    )


def _correlation_response(
    correlation: ComplaintCorrelation,
    complaint: Optional[Complaint] = None,
) -> ComplaintCorrelationResponse:
    """
    Build a safe complaint-correlation response.

    Raw and normalized narratives are intentionally omitted.
    """
    return ComplaintCorrelationResponse(
        id=str(_get_if_exists(correlation, "id", "")),
        complaint_id=str(_get_if_exists(correlation, "complaint_id", "")),
        complaint_reference=(
            str(_get_if_exists(complaint, "reference", "") or "")
            if complaint is not None
            else None
        ),
        complaint_category=(
            str(_get_if_exists(complaint, "category", "") or "")
            if complaint is not None
            else None
        ),
        complaint_reported_at=(
            _get_if_exists(complaint, "reported_at", None)
            if complaint is not None
            else None
        ),
        complaint_amount=(
            _get_if_exists(complaint, "amount", None)
            if complaint is not None
            else None
        ),
        complaint_currency=(
            _str_or_none(_get_if_exists(complaint, "currency", None))
            if complaint is not None
            else None
        ),
        complaint_source=(
            _str_or_none(_get_if_exists(complaint, "source", None))
            if complaint is not None
            else None
        ),
        complaint_narrative_available=(
            bool(_get_if_exists(complaint, "narrative_raw", None))
            if complaint is not None
            else False
        ),
        account_id=_str_or_none(_get_if_exists(correlation, "account_id", None)),
        transaction_id=_str_or_none(_get_if_exists(correlation, "transaction_id", None)),
        entity_id=_str_or_none(_get_if_exists(correlation, "entity_id", None)),
        match_tier=int(_get_if_exists(correlation, "match_tier", 0) or 0),
        match_method=_enum_str(_get_if_exists(correlation, "match_method", None)) or "UNKNOWN",
        confidence=_get_if_exists(correlation, "confidence", None),
        deterministic=bool(_get_if_exists(correlation, "deterministic", False)),
        review_state=_enum_str(_get_if_exists(correlation, "review_state", None)) or "UNREVIEWED",
        evidence_refs=_safe_string_list(_get_if_exists(correlation, "evidence_refs_json", None)),
        created_at=_timestamp_value(correlation, "record_created_at", "created_at"),
    )


def _linked_account_response(
    account: Account,
    correlation: ComplaintCorrelation,
) -> ComplaintLinkedAccountResponse:
    """
    Build a safe linked-account response.
    """
    return ComplaintLinkedAccountResponse(
        id=str(_get_if_exists(account, "id", "")),
        account_type=_enum_str(_get_if_exists(account, "account_type", None)) or "OTHER",
        status=_enum_str(_get_if_exists(account, "status", None)) or "ACTIVE",
        created_at=_timestamp_value(account, "record_created_at", "created_at"),
        correlation_id=str(_get_if_exists(correlation, "id", "")),
        match_tier=int(_get_if_exists(correlation, "match_tier", 0) or 0),
        match_method=_enum_str(_get_if_exists(correlation, "match_method", None)) or "UNKNOWN",
        confidence=_get_if_exists(correlation, "confidence", None),
        deterministic=bool(_get_if_exists(correlation, "deterministic", False)),
        review_state=_enum_str(_get_if_exists(correlation, "review_state", None)) or "UNREVIEWED",
    )


def _linked_transaction_response(
    transaction: Transaction,
    correlation: ComplaintCorrelation,
) -> ComplaintLinkedTransactionResponse:
    """
    Build a safe linked-transaction response.
    """
    return ComplaintLinkedTransactionResponse(
        id=str(_get_if_exists(transaction, "id", "")),
        sender_account_id=str(_get_if_exists(transaction, "sender_account_id", "")),
        receiver_account_id=str(_get_if_exists(transaction, "receiver_account_id", "")),
        amount=_get_if_exists(transaction, "amount", Decimal("0")),
        currency=str(_get_if_exists(transaction, "currency", "") or ""),
        occurred_at=_get_if_exists(transaction, "occurred_at", _now_utc()),
        status=_enum_str(_get_if_exists(transaction, "status", None)) or "UNKNOWN",
        channel=_enum_str(_get_if_exists(transaction, "channel", None)) or "UNKNOWN",
        reference=str(_get_if_exists(transaction, "reference", "") or ""),
        correlation_id=str(_get_if_exists(correlation, "id", "")),
        match_tier=int(_get_if_exists(correlation, "match_tier", 0) or 0),
        match_method=_enum_str(_get_if_exists(correlation, "match_method", None)) or "UNKNOWN",
        confidence=_get_if_exists(correlation, "confidence", None),
        deterministic=bool(_get_if_exists(correlation, "deterministic", False)),
        review_state=_enum_str(_get_if_exists(correlation, "review_state", None)) or "UNREVIEWED",
    )


def _linked_entity_response(
    entity: Entity,
    correlation: ComplaintCorrelation,
) -> ComplaintLinkedEntityResponse:
    """
    Build a safe linked-entity response.

    Raw identifier hashes are intentionally omitted.
    """
    return ComplaintLinkedEntityResponse(
        id=str(_get_if_exists(entity, "id", "")),
        entity_type=_enum_str(_get_if_exists(entity, "entity_type", None)) or "OTHER",
        identifier_display=(
            _clean_text(_get_if_exists(entity, "identifier_display", None), 200)
            if _get_if_exists(entity, "identifier_display", None)
            else None
        ),
        source=str(_get_if_exists(entity, "source", None) or "synthetic"),
        correlation_id=str(_get_if_exists(correlation, "id", "")),
        match_tier=int(_get_if_exists(correlation, "match_tier", 0) or 0),
        match_method=_enum_str(_get_if_exists(correlation, "match_method", None)) or "UNKNOWN",
        confidence=_get_if_exists(correlation, "confidence", None),
        deterministic=bool(_get_if_exists(correlation, "deterministic", False)),
        review_state=_enum_str(_get_if_exists(correlation, "review_state", None)) or "UNREVIEWED",
    )


def _alert_response(alert: Alert) -> ComplaintAlertResponse:
    """
    Build a safe alert response.
    """
    return ComplaintAlertResponse(
        id=str(_get_if_exists(alert, "id", "")),
        account_id=str(_get_if_exists(alert, "account_id", "")),
        assessment_id=_str_or_none(_get_if_exists(alert, "assessment_id", None)),
        title=str(_get_if_exists(alert, "title", "") or ""),
        summary=_str_or_none(_get_if_exists(alert, "summary", None)),
        priority=_enum_str(_get_if_exists(alert, "priority", None)) or "MEDIUM",
        state=_enum_str(_get_if_exists(alert, "state", None)) or "NEW",
        score=_get_if_exists(alert, "score", None),
        score_version=_str_or_none(_get_if_exists(alert, "score_version", None)),
        scoring_mode=_enum_str(_get_if_exists(alert, "scoring_mode", None)) or "unknown",
        model_version=_str_or_none(_get_if_exists(alert, "model_version", None)),
        rule_codes=_safe_string_list(_get_if_exists(alert, "rule_codes_json", None)),
        signal_summary_json=_response_metadata(_get_if_exists(alert, "signal_summary_json", None)),
        first_seen_at=_get_if_exists(alert, "first_seen_at", _now_utc()),
        last_seen_at=_get_if_exists(alert, "last_seen_at", _now_utc()),
        created_at=_timestamp_value(alert, "record_created_at", "created_at"),
    )


def _audit_event_response(event: AuditEvent) -> ComplaintHistoryEventResponse:
    """
    Build a safe audit history response.
    """
    return ComplaintHistoryEventResponse(
        id=str(_get_if_exists(event, "id", "")),
        action=str(_get_if_exists(event, "action", "") or ""),
        outcome=_enum_str(_get_if_exists(event, "outcome", None)) or "UNKNOWN",
        actor_id=_str_or_none(_get_if_exists(event, "actor_id", None)),
        actor_username=_str_or_none(_get_if_exists(event, "actor_username", None)),
        actor_role=_str_or_none(_get_if_exists(event, "actor_role", None)),
        resource_type=_str_or_none(_get_if_exists(event, "resource_type", None)),
        resource_id=_str_or_none(_get_if_exists(event, "resource_id", None)),
        request_id=_str_or_none(_get_if_exists(event, "request_id", None)),
        metadata_json=_response_metadata(_get_if_exists(event, "metadata_json", None)),
        created_at=_get_if_exists(event, "created_at", None),
    )


# -----------------------------------------------------------------------------
# Query condition builders
# -----------------------------------------------------------------------------


def _build_complaint_conditions(
    *,
    category: Optional[str],
    source: Optional[str],
    victim_account_id: Optional[str],
    suspected_account_id: Optional[str],
    transaction_reference: Optional[str],
    date_range: DateRangeParams,
    amount_range: AmountRangeParams,
    search: SearchParams,
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for complaint list queries.
    """
    conditions: list[Any] = []

    category_column = _model_column(Complaint, "category")
    source_column = _model_column(Complaint, "source")
    victim_column = _model_column(Complaint, "victim_account_id")
    suspected_column = _model_column(Complaint, "suspected_account_id")
    transaction_reference_column = _model_column(Complaint, "transaction_reference")
    reported_at_column = _model_column(Complaint, "reported_at")
    amount_column = _model_column(Complaint, "amount")

    if category and category_column is not None:
        conditions.append(category_column == category)

    if source and source_column is not None:
        conditions.append(source_column == source)

    if victim_account_id and victim_column is not None:
        conditions.append(victim_column == victim_account_id.strip())

    if suspected_account_id and suspected_column is not None:
        conditions.append(suspected_column == suspected_account_id.strip())

    if transaction_reference and transaction_reference_column is not None:
        conditions.append(transaction_reference_column == transaction_reference.strip())

    time_column = reported_at_column or _COMPLAINT_CREATED_AT

    if date_range.date_from is not None and time_column is not None:
        conditions.append(time_column >= date_range.date_from)

    if date_range.date_to is not None and time_column is not None:
        conditions.append(time_column <= date_range.date_to)

    if amount_range.amount_min is not None and amount_column is not None:
        conditions.append(amount_column >= amount_range.amount_min)

    if amount_range.amount_max is not None and amount_column is not None:
        conditions.append(amount_column <= amount_range.amount_max)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (
            _model_column(Complaint, "reference"),
            category_column,
            source_column,
        ):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


def _build_correlation_conditions(
    *,
    complaint_id: str,
    match_tier: Optional[int],
    review_state: Optional[ComplaintReviewState],
    deterministic: Optional[bool],
    match_method: Optional[MatchMethod],
    account_id: Optional[str],
    transaction_id: Optional[str],
    entity_id: Optional[str],
    search: SearchParams,
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for complaint-correlation queries.
    """
    conditions: list[Any] = [ComplaintCorrelation.complaint_id == complaint_id]

    if match_tier is not None:
        conditions.append(ComplaintCorrelation.match_tier == match_tier)

    if review_state is not None:
        conditions.append(ComplaintCorrelation.review_state == review_state)

    if deterministic is not None:
        conditions.append(ComplaintCorrelation.deterministic.is_(deterministic))

    if match_method is not None:
        conditions.append(ComplaintCorrelation.match_method == match_method)

    if account_id:
        conditions.append(ComplaintCorrelation.account_id == account_id.strip())

    if transaction_id:
        conditions.append(ComplaintCorrelation.transaction_id == transaction_id.strip())

    if entity_id:
        conditions.append(ComplaintCorrelation.entity_id == entity_id.strip())

    if search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (
            _model_column(Complaint, "reference"),
            _model_column(Complaint, "category"),
            _model_column(Complaint, "source"),
        ):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


def _build_linked_account_conditions(
    *,
    complaint_id: str,
    account_type: Optional[AccountType],
    account_status: Optional[AccountStatus],
    match_tier: Optional[int],
    review_state: Optional[ComplaintReviewState],
    deterministic: Optional[bool],
    match_method: Optional[MatchMethod],
    search: SearchParams,
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for complaint-linked account queries.
    """
    conditions: list[Any] = [
        ComplaintCorrelation.complaint_id == complaint_id,
        ComplaintCorrelation.account_id.isnot(None),
    ]

    if account_type is not None:
        conditions.append(Account.account_type == account_type)

    if account_status is not None:
        conditions.append(Account.status == account_status)

    if match_tier is not None:
        conditions.append(ComplaintCorrelation.match_tier == match_tier)

    if review_state is not None:
        conditions.append(ComplaintCorrelation.review_state == review_state)

    if deterministic is not None:
        conditions.append(ComplaintCorrelation.deterministic.is_(deterministic))

    if match_method is not None:
        conditions.append(ComplaintCorrelation.match_method == match_method)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (
            _model_column(Account, "id"),
            _model_column(ComplaintCorrelation, "account_id"),
        ):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


def _build_linked_transaction_conditions(
    *,
    complaint_id: str,
    status: Optional[TransactionStatus],
    channel: Optional[Channel],
    currency: Optional[str],
    reference: Optional[str],
    date_range: DateRangeParams,
    amount_range: AmountRangeParams,
    match_tier: Optional[int],
    review_state: Optional[ComplaintReviewState],
    deterministic: Optional[bool],
    match_method: Optional[MatchMethod],
    search: SearchParams,
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for complaint-linked transaction queries.
    """
    conditions: list[Any] = [
        ComplaintCorrelation.complaint_id == complaint_id,
        ComplaintCorrelation.transaction_id.isnot(None),
    ]

    if status is not None:
        conditions.append(Transaction.status == status)

    if channel is not None:
        conditions.append(Transaction.channel == channel)

    if currency is not None:
        conditions.append(Transaction.currency == currency.strip().upper())

    if reference is not None:
        conditions.append(Transaction.reference == reference.strip())

    if date_range.date_from is not None:
        conditions.append(Transaction.occurred_at >= date_range.date_from)

    if date_range.date_to is not None:
        conditions.append(Transaction.occurred_at <= date_range.date_to)

    if amount_range.amount_min is not None:
        conditions.append(Transaction.amount >= amount_range.amount_min)

    if amount_range.amount_max is not None:
        conditions.append(Transaction.amount <= amount_range.amount_max)

    if match_tier is not None:
        conditions.append(ComplaintCorrelation.match_tier == match_tier)

    if review_state is not None:
        conditions.append(ComplaintCorrelation.review_state == review_state)

    if deterministic is not None:
        conditions.append(ComplaintCorrelation.deterministic.is_(deterministic))

    if match_method is not None:
        conditions.append(ComplaintCorrelation.match_method == match_method)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (
            _model_column(Transaction, "id"),
            _model_column(Transaction, "reference"),
        ):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


def _build_linked_entity_conditions(
    *,
    complaint_id: str,
    entity_type: Optional[EntityType],
    match_tier: Optional[int],
    review_state: Optional[ComplaintReviewState],
    deterministic: Optional[bool],
    match_method: Optional[MatchMethod],
    search: SearchParams,
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for complaint-linked entity queries.
    """
    conditions: list[Any] = [
        ComplaintCorrelation.complaint_id == complaint_id,
        ComplaintCorrelation.entity_id.isnot(None),
    ]

    if entity_type is not None:
        conditions.append(Entity.entity_type == entity_type)

    if match_tier is not None:
        conditions.append(ComplaintCorrelation.match_tier == match_tier)

    if review_state is not None:
        conditions.append(ComplaintCorrelation.review_state == review_state)

    if deterministic is not None:
        conditions.append(ComplaintCorrelation.deterministic.is_(deterministic))

    if match_method is not None:
        conditions.append(ComplaintCorrelation.match_method == match_method)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (
            _model_column(Entity, "id"),
            _model_column(Entity, "identifier_display"),
            _model_column(Entity, "source"),
        ):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


def _build_complaint_alert_conditions(
    *,
    complaint_id: str,
    state: Optional[AlertState],
    priority: Optional[Priority],
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for complaint-referencing alert queries.
    """
    conditions: list[Any] = [
        AlertEvidence.evidence_type == EvidenceType.COMPLAINT,
        AlertEvidence.evidence_id == complaint_id,
    ]

    if state is not None:
        conditions.append(Alert.state == state)

    if priority is not None:
        conditions.append(Alert.priority == priority)

    return conditions


def _build_complaint_history_conditions(
    *,
    complaint_id: str,
    action: Optional[str],
    outcome: Optional[AuditOutcome],
    search: SearchParams,
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for complaint history queries.
    """
    resource_type_column = _model_column(AuditEvent, "resource_type")
    resource_id_column = _model_column(AuditEvent, "resource_id")

    if resource_type_column is None or resource_id_column is None:
        return []

    correlation_id_column = _model_column(ComplaintCorrelation, "id")
    correlation_complaint_id_column = _model_column(ComplaintCorrelation, "complaint_id")

    complaint_condition = and_(
        resource_type_column == "complaint",
        resource_id_column == complaint_id,
    )

    if correlation_id_column is not None and correlation_complaint_id_column is not None:
        correlation_subquery = (
            select(correlation_id_column)
            .where(correlation_complaint_id_column == complaint_id)
            .subquery()
        )

        correlation_condition = and_(
            resource_type_column == "complaint_correlation",
            resource_id_column.in_(select(correlation_subquery.c.id)),
        )

        conditions: list[Any] = [or_(complaint_condition, correlation_condition)]
    else:
        conditions = [complaint_condition]

    if action:
        action_column = _model_column(AuditEvent, "action")

        if action_column is not None:
            conditions.append(action_column == action.strip())

    if outcome is not None:
        outcome_column = _model_column(AuditEvent, "outcome")

        if outcome_column is not None:
            conditions.append(outcome_column == outcome)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (
            _model_column(AuditEvent, "action"),
            _model_column(AuditEvent, "actor_username"),
            _model_column(AuditEvent, "resource_id"),
        ):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


# -----------------------------------------------------------------------------
# Internal loaders
# -----------------------------------------------------------------------------


def _load_complaint_correlations(
    db: Session,
    complaint_id: str,
    *,
    limit: int,
) -> tuple[list[ComplaintCorrelationResponse], int]:
    """
    Load bounded complaint correlations and total count.
    """
    total = _scalar_count(
        db,
        select(func.count())
        .select_from(ComplaintCorrelation)
        .join(Complaint, Complaint.id == ComplaintCorrelation.complaint_id)
        .where(ComplaintCorrelation.complaint_id == complaint_id),
    )

    stmt = (
        select(ComplaintCorrelation, Complaint)
        .join(Complaint, Complaint.id == ComplaintCorrelation.complaint_id)
        .where(ComplaintCorrelation.complaint_id == complaint_id)
    )

    if _CORRELATION_CREATED_AT is not None:
        stmt = stmt.order_by(desc(_CORRELATION_CREATED_AT))

    if _CORRELATION_TIEBREAKER is not None:
        stmt = stmt.order_by(desc(_CORRELATION_TIEBREAKER))

    stmt = stmt.limit(max(1, int(limit)))

    rows = db.execute(stmt).all()

    return [
        _correlation_response(correlation, complaint)
        for correlation, complaint in rows
    ], total


def _group_complaint_counts(
    db: Session,
    column: Any | None,
    conditions: list[Any],
    limit: int,
) -> dict[str, int]:
    """
    Return bounded complaint grouping counts.
    """
    if column is None:
        return {}

    stmt = select(column, func.count()).select_from(Complaint)
    stmt = _apply_conditions(stmt, conditions)
    stmt = stmt.group_by(column).order_by(desc(func.count()), column).limit(limit)

    rows = db.execute(stmt).all()

    return {
        (_clean_text(row[0], 100) or "UNKNOWN"): int(row[1] or 0)
        for row in rows
    }


def _group_correlation_counts(
    db: Session,
    column: Any | None,
    conditions: list[Any],
    limit: int,
) -> dict[str, int]:
    """
    Return bounded complaint-correlation grouping counts.
    """
    complaint_id_column = _model_column(ComplaintCorrelation, "complaint_id")
    complaint_id_join = _model_column(Complaint, "id")

    if column is None or complaint_id_column is None or complaint_id_join is None:
        return {}

    stmt = (
        select(column, func.count())
        .select_from(ComplaintCorrelation)
        .join(Complaint, complaint_id_join == complaint_id_column)
    )
    stmt = _apply_conditions(stmt, conditions)
    stmt = stmt.group_by(column).order_by(desc(func.count()), column).limit(limit)

    rows = db.execute(stmt).all()

    return {
        (_enum_str(row[0]) or _clean_text(row[0], 100) or "UNKNOWN"): int(row[1] or 0)
        for row in rows
    }


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "",
    response_model=ComplaintListResponse,
    summary="List synthetic complaints",
    description=(
        "Returns a paginated, filtered, and stably ordered list of synthetic "
        "MULEGUARD complaints. This endpoint is read-only and does not take "
        "adverse action. Raw and normalized complaint narratives are "
        "intentionally not returned."
    ),
)
def list_complaints(
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(complaint_pagination),
    date_range: DateRangeParams = Depends(complaint_date_range),
    amount_range: AmountRangeParams = Depends(complaint_amount_range),
    search: SearchParams = Depends(complaint_search),
    _: User = Depends(require_permission(Permission.COMPLAINT_READ)),
    category: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by complaint category."),
    ] = None,
    source: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by complaint source."),
    ] = None,
    victim_account_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by victim synthetic account."),
    ] = None,
    suspected_account_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by suspected synthetic account."),
    ] = None,
    transaction_reference: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by complaint transaction reference."),
    ] = None,
    include_correlation_count: Annotated[
        bool,
        Query(description="Include bounded correlation counts for returned complaints."),
    ] = False,
) -> ComplaintListResponse:
    """
    List synthetic complaints with bounded pagination and safe filters.
    """
    _ensure_complaints_enabled(settings)

    normalized_category = _normalize_text(category, field_name="category")
    normalized_source = _normalize_text(source, field_name="source")

    _validate_date_range(date_range.date_from, date_range.date_to, "date_from", "date_to")
    _validate_complaint_span(date_range.date_from, date_range.date_to, settings)

    conditions = _build_complaint_conditions(
        category=normalized_category,
        source=normalized_source,
        victim_account_id=victim_account_id,
        suspected_account_id=suspected_account_id,
        transaction_reference=transaction_reference,
        date_range=date_range,
        amount_range=amount_range,
        search=search,
    )

    count_stmt = select(func.count()).select_from(Complaint)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(Complaint)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_COMPLAINT_COLUMN_MAP,
        tiebreaker=_COMPLAINT_TIEBREAKER,
        default_sort_by=_COMPLAINT_DEFAULT_SORT,
        default_sort_order="desc",
    )

    complaints = db.scalars(stmt).all()

    counts: dict[str, int] = {}

    if include_correlation_count and complaints:
        counts = _correlation_counts_for_complaint_ids(
            db,
            [str(complaint.id) for complaint in complaints],
        )

    items = [
        _complaint_response(
            complaint,
            counts.get(str(complaint.id)),
        )
        for complaint in complaints
    ]

    return ComplaintListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_COMPLAINT_CAVEATS),
    )


@router.get(
    "/stats",
    response_model=ComplaintStatsResponse,
    summary="Get aggregate complaint statistics",
    description=(
        "Returns bounded aggregate complaint and correlation statistics for "
        "oversight and operational review. Statistics are investigative and "
        "accountability signals only."
    ),
)
def complaint_stats(
    db: SessionDep,
    settings: SettingsDep,
    date_range: DateRangeParams = Depends(complaint_date_range),
    _: User = Depends(require_permission(Permission.COMPLAINT_READ)),
    category: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by complaint category."),
    ] = None,
    source: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by complaint source."),
    ] = None,
    top_limit: Annotated[
        int,
        Query(ge=1, le=_STATS_TOP_LIMIT_MAX, description="Maximum top-N categories to return."),
    ] = _STATS_TOP_LIMIT_DEFAULT,
) -> ComplaintStatsResponse:
    """
    Return bounded aggregate complaint statistics.
    """
    _ensure_complaint_stats_enabled(settings)

    normalized_category = _normalize_text(category, field_name="category")
    normalized_source = _normalize_text(source, field_name="source")

    resolved_range, defaulted = _resolve_stats_range(date_range, settings)

    time_column = _model_column(Complaint, "reported_at") or _COMPLAINT_CREATED_AT

    conditions: list[Any] = []

    if time_column is not None:
        if resolved_range.date_from is not None:
            conditions.append(time_column >= resolved_range.date_from)

        if resolved_range.date_to is not None:
            conditions.append(time_column <= resolved_range.date_to)

    category_column = _model_column(Complaint, "category")
    source_column = _model_column(Complaint, "source")

    if normalized_category and category_column is not None:
        conditions.append(category_column == normalized_category)

    if normalized_source and source_column is not None:
        conditions.append(source_column == normalized_source)

    total_complaints = _scalar_count(
        db,
        _apply_conditions(select(func.count()).select_from(Complaint), conditions),
    )

    complaint_id_column = _model_column(Complaint, "id")
    correlation_complaint_id_column = _model_column(ComplaintCorrelation, "complaint_id")

    total_correlations = 0
    deterministic_count = 0
    inferred_count = 0

    correlation_conditions = list(conditions)

    if complaint_id_column is not None and correlation_complaint_id_column is not None:
        correlation_count_stmt = (
            select(func.count())
            .select_from(ComplaintCorrelation)
            .join(Complaint, complaint_id_column == correlation_complaint_id_column)
        )
        correlation_count_stmt = _apply_conditions(
            correlation_count_stmt,
            correlation_conditions,
        )
        total_correlations = _scalar_count(db, correlation_count_stmt)

        deterministic_column = _model_column(ComplaintCorrelation, "deterministic")

        if deterministic_column is not None:
            deterministic_stmt = (
                select(func.count())
                .select_from(ComplaintCorrelation)
                .join(Complaint, complaint_id_column == correlation_complaint_id_column)
                .where(deterministic_column.is_(True))
            )
            deterministic_stmt = _apply_conditions(deterministic_stmt, correlation_conditions)
            deterministic_count = _scalar_count(db, deterministic_stmt)

            inferred_stmt = (
                select(func.count())
                .select_from(ComplaintCorrelation)
                .join(Complaint, complaint_id_column == correlation_complaint_id_column)
                .where(deterministic_column.is_(False))
            )
            inferred_stmt = _apply_conditions(inferred_stmt, correlation_conditions)
            inferred_count = _scalar_count(db, inferred_stmt)

    effective_top_limit = max(1, min(int(top_limit), _STATS_TOP_LIMIT_MAX))

    caveats = list(_STATS_CAVEATS)

    if time_column is None:
        caveats.append("Complaint time column is unavailable; statistics are constrained to zero.")

    return ComplaintStatsResponse(
        period={
            "date_from": resolved_range.date_from.isoformat() if resolved_range.date_from else None,
            "date_to": resolved_range.date_to.isoformat() if resolved_range.date_to else None,
            "defaulted": defaulted,
            "max_span_days": _max_complaint_date_span_days(settings),
        },
        total_complaints=total_complaints,
        total_correlations=total_correlations,
        by_category=_group_complaint_counts(
            db,
            category_column,
            conditions,
            effective_top_limit,
        ),
        by_source=_group_complaint_counts(
            db,
            source_column,
            conditions,
            effective_top_limit,
        ),
        by_match_tier=_group_correlation_counts(
            db,
            _model_column(ComplaintCorrelation, "match_tier"),
            correlation_conditions,
            effective_top_limit,
        ),
        by_review_state=_group_correlation_counts(
            db,
            _model_column(ComplaintCorrelation, "review_state"),
            correlation_conditions,
            effective_top_limit,
        ),
        deterministic_count=deterministic_count,
        inferred_count=inferred_count,
        caveats=caveats,
    )


@router.get(
    "/{complaint_id}",
    response_model=ComplaintResponse,
    summary="Get a synthetic complaint",
    description=(
        "Returns a safe view for one synthetic MULEGUARD complaint. Raw and "
        "normalized narratives are intentionally not returned."
    ),
)
def get_complaint(
    complaint_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic complaint identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.COMPLAINT_READ)),
) -> ComplaintResponse:
    """
    Retrieve one synthetic complaint.
    """
    _ensure_complaints_enabled(settings)

    complaint = _get_complaint_or_404(db, complaint_id)
    counts = _correlation_counts_for_complaint_ids(db, [str(complaint.id)])

    return _complaint_response(
        complaint,
        counts.get(str(complaint.id)),
    )


@router.get(
    "/{complaint_id}/correlations",
    response_model=ComplaintCorrelationListResponse,
    summary="List correlations for a synthetic complaint",
    description=(
        "Returns paginated complaint correlations for one synthetic complaint. "
        "Exact matches are distinguished from inferred associations through "
        "match tier, method, determinism, and confidence. Raw and normalized "
        "complaint narratives are intentionally not returned."
    ),
)
def list_complaint_correlations(
    complaint_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic complaint identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(correlation_pagination),
    search: SearchParams = Depends(correlation_search),
    _: User = Depends(require_permission(Permission.COMPLAINT_READ)),
    match_tier: Annotated[
        Optional[int],
        Query(ge=1, le=5, description="Filter by correlation tier."),
    ] = None,
    review_state: Annotated[
        Optional[ComplaintReviewState],
        Query(description="Filter by reviewer state."),
    ] = None,
    deterministic: Annotated[
        Optional[bool],
        Query(description="Filter deterministic versus inferred correlations."),
    ] = None,
    match_method: Annotated[
        Optional[MatchMethod],
        Query(description="Filter by match method."),
    ] = None,
    account_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by correlated synthetic account."),
    ] = None,
    transaction_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by correlated synthetic transaction."),
    ] = None,
    entity_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by correlated synthetic entity."),
    ] = None,
) -> ComplaintCorrelationListResponse:
    """
    List correlations for one complaint.
    """
    _ensure_complaints_enabled(settings)

    complaint = _get_complaint_or_404(db, complaint_id)
    complaint_id = str(complaint.id)

    conditions = _build_correlation_conditions(
        complaint_id=complaint_id,
        match_tier=match_tier,
        review_state=review_state,
        deterministic=deterministic,
        match_method=match_method,
        account_id=account_id,
        transaction_id=transaction_id,
        entity_id=entity_id,
        search=search,
    )

    count_stmt = (
        select(func.count())
        .select_from(ComplaintCorrelation)
        .join(Complaint, Complaint.id == ComplaintCorrelation.complaint_id)
    )
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = (
        select(ComplaintCorrelation, Complaint)
        .join(Complaint, Complaint.id == ComplaintCorrelation.complaint_id)
    )
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_CORRELATION_COLUMN_MAP,
        tiebreaker=_CORRELATION_TIEBREAKER,
        default_sort_by=_CORRELATION_DEFAULT_SORT,
        default_sort_order="desc",
    )

    rows = db.execute(stmt).all()

    items = [
        _correlation_response(correlation, complaint_record)
        for correlation, complaint_record in rows
    ]

    return ComplaintCorrelationListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_CORRELATION_CAVEATS),
    )


@router.post(
    "/{complaint_id}/correlations/{correlation_id}/review-state",
    response_model=ComplaintCorrelationReviewUpdateResponse,
    summary="Update complaint-correlation review state",
    description=(
        "Allows an authorised senior investigator or administrator to update "
        "the review state of one complaint correlation. This is an investigative "
        "metadata action, not an enforcement action. The change is audited."
    ),
)
def update_complaint_correlation_review_state(
    complaint_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic complaint identifier."),
    ],
    correlation_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Complaint correlation identifier."),
    ],
    payload: ComplaintCorrelationReviewUpdateRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    reviewer: User = Depends(
        require_roles(UserRole.SENIOR_INVESTIGATOR, UserRole.ADMIN)
    ),
) -> ComplaintCorrelationReviewUpdateResponse:
    """
    Update the review state for one complaint correlation.
    """
    _ensure_complaint_review_enabled(settings)

    complaint = _get_complaint_or_404(db, complaint_id)
    complaint_id = str(complaint.id)

    correlation = _get_correlation_or_404(db, complaint_id, correlation_id)

    previous_state = _enum_str(_get_if_exists(correlation, "review_state", None)) or "UNREVIEWED"
    new_state = _enum_str(payload.review_state) or "UNREVIEWED"

    if previous_state == new_state:
        return ComplaintCorrelationReviewUpdateResponse(
            correlation=_correlation_response(correlation, complaint),
            complaint=_complaint_response(complaint),
            changed=False,
            previous_state=previous_state,
            new_state=new_state,
            audited=False,
            caveats=list(_REVIEW_CAVEATS),
        )

    _set_if_exists(correlation, "review_state", payload.review_state)
    _set_if_exists(correlation, "reviewed_by", str(reviewer.id))
    _set_if_exists(correlation, "reviewed_at", _now_utc())

    _add_audit_event(
        db,
        action="complaint_correlation_review_state_update",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=reviewer,
        resource_type="complaint_correlation",
        resource_id=str(correlation.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "complaint_id": complaint_id,
            "previous_state": previous_state,
            "new_state": new_state,
            "match_tier": int(_get_if_exists(correlation, "match_tier", 0) or 0),
            "match_method": _enum_str(_get_if_exists(correlation, "match_method", None)),
            "deterministic": bool(_get_if_exists(correlation, "deterministic", False)),
            "confidence": (
                str(_get_if_exists(correlation, "confidence", None))
                if _get_if_exists(correlation, "confidence", None) is not None
                else None
            ),
            **_text_audit_metadata(payload.note, field_name="note"),
        },
    )

    db.commit()
    db.refresh(correlation)
    db.refresh(complaint)

    return ComplaintCorrelationReviewUpdateResponse(
        correlation=_correlation_response(correlation, complaint),
        complaint=_complaint_response(complaint),
        changed=True,
        previous_state=previous_state,
        new_state=new_state,
        audited=True,
        caveats=list(_REVIEW_CAVEATS),
    )


@router.get(
    "/{complaint_id}/accounts",
    response_model=ComplaintLinkedAccountListResponse,
    summary="List accounts correlated with a synthetic complaint",
    description=(
        "Returns paginated synthetic accounts linked to one complaint through "
        "persisted correlations. Account links are investigative associations "
        "only and are not proof of common control or wrongdoing."
    ),
)
def list_complaint_accounts(
    complaint_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic complaint identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(account_pagination),
    search: SearchParams = Depends(account_search),
    _: User = Depends(require_permission(Permission.COMPLAINT_READ)),
    account_type: Annotated[
        Optional[AccountType],
        Query(description="Filter linked accounts by synthetic account type."),
    ] = None,
    account_status: Annotated[
        Optional[AccountStatus],
        Query(description="Filter linked accounts by synthetic account status."),
    ] = None,
    match_tier: Annotated[
        Optional[int],
        Query(ge=1, le=5, description="Filter correlations by tier."),
    ] = None,
    review_state: Annotated[
        Optional[ComplaintReviewState],
        Query(description="Filter correlations by reviewer state."),
    ] = None,
    deterministic: Annotated[
        Optional[bool],
        Query(description="Filter deterministic versus inferred correlations."),
    ] = None,
    match_method: Annotated[
        Optional[MatchMethod],
        Query(description="Filter correlations by match method."),
    ] = None,
) -> ComplaintLinkedAccountListResponse:
    """
    List accounts linked to one complaint.
    """
    _ensure_complaints_enabled(settings)

    complaint = _get_complaint_or_404(db, complaint_id)
    complaint_id = str(complaint.id)

    account_id_column = _model_column(ComplaintCorrelation, "account_id")

    if account_id_column is None:
        return ComplaintLinkedAccountListResponse(
            items=[],
            page=params.page,
            page_size=params.page_size,
            total=0,
            total_pages=0,
            sort_by=params.sort_by,
            sort_order=params.sort_order,
            caveats=[
                *_LINKED_ACCOUNT_CAVEATS,
                "Complaint-to-account correlation linkage is not available in this schema.",
            ],
        )

    conditions = _build_linked_account_conditions(
        complaint_id=complaint_id,
        account_type=account_type,
        account_status=account_status,
        match_tier=match_tier,
        review_state=review_state,
        deterministic=deterministic,
        match_method=match_method,
        search=search,
    )

    count_stmt = (
        select(func.count())
        .select_from(ComplaintCorrelation)
        .join(Account, Account.id == account_id_column)
    )
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = (
        select(ComplaintCorrelation, Account)
        .join(Account, Account.id == account_id_column)
    )
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_ACCOUNT_COLUMN_MAP,
        tiebreaker=_ACCOUNT_TIEBREAKER,
        default_sort_by=_ACCOUNT_DEFAULT_SORT,
        default_sort_order="desc",
    )

    rows = db.execute(stmt).all()

    items = [
        _linked_account_response(account, correlation)
        for correlation, account in rows
    ]

    return ComplaintLinkedAccountListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_LINKED_ACCOUNT_CAVEATS),
    )


@router.get(
    "/{complaint_id}/transactions",
    response_model=ComplaintLinkedTransactionListResponse,
    summary="List transactions correlated with a synthetic complaint",
    description=(
        "Returns paginated synthetic transactions linked to one complaint "
        "through persisted correlations. Transaction links are investigative "
        "evidence only and must not be interpreted as proof of wrongdoing."
    ),
)
def list_complaint_transactions(
    complaint_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic complaint identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(transaction_pagination),
    date_range: DateRangeParams = Depends(transaction_date_range),
    amount_range: AmountRangeParams = Depends(transaction_amount_range),
    search: SearchParams = Depends(transaction_search),
    _: User = Depends(require_permission(Permission.TRANSACTION_READ)),
    status: Annotated[
        Optional[TransactionStatus],
        Query(description="Filter by transaction status."),
    ] = None,
    channel: Annotated[
        Optional[Channel],
        Query(description="Filter by synthetic payment channel."),
    ] = None,
    currency: Annotated[
        Optional[str],
        Query(max_length=3, description="Filter by currency code."),
    ] = None,
    reference: Annotated[
        Optional[str],
        Query(max_length=128, description="Exact transaction reference filter."),
    ] = None,
    match_tier: Annotated[
        Optional[int],
        Query(ge=1, le=5, description="Filter correlations by tier."),
    ] = None,
    review_state: Annotated[
        Optional[ComplaintReviewState],
        Query(description="Filter correlations by reviewer state."),
    ] = None,
    deterministic: Annotated[
        Optional[bool],
        Query(description="Filter deterministic versus inferred correlations."),
    ] = None,
    match_method: Annotated[
        Optional[MatchMethod],
        Query(description="Filter correlations by match method."),
    ] = None,
) -> ComplaintLinkedTransactionListResponse:
    """
    List transactions linked to one complaint.
    """
    _ensure_complaints_enabled(settings)

    complaint = _get_complaint_or_404(db, complaint_id)
    complaint_id = str(complaint.id)

    transaction_id_column = _model_column(ComplaintCorrelation, "transaction_id")

    if transaction_id_column is None:
        return ComplaintLinkedTransactionListResponse(
            items=[],
            page=params.page,
            page_size=params.page_size,
            total=0,
            total_pages=0,
            sort_by=params.sort_by,
            sort_order=params.sort_order,
            caveats=[
                *_LINKED_TRANSACTION_CAVEATS,
                "Complaint-to-transaction correlation linkage is not available in this schema.",
            ],
        )

    conditions = _build_linked_transaction_conditions(
        complaint_id=complaint_id,
        status=status,
        channel=channel,
        currency=currency,
        reference=reference,
        date_range=date_range,
        amount_range=amount_range,
        match_tier=match_tier,
        review_state=review_state,
        deterministic=deterministic,
        match_method=match_method,
        search=search,
    )

    count_stmt = (
        select(func.count())
        .select_from(ComplaintCorrelation)
        .join(Transaction, Transaction.id == transaction_id_column)
    )
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = (
        select(ComplaintCorrelation, Transaction)
        .join(Transaction, Transaction.id == transaction_id_column)
    )
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_TRANSACTION_COLUMN_MAP,
        tiebreaker=_TRANSACTION_TIEBREAKER,
        default_sort_by=_TRANSACTION_DEFAULT_SORT,
        default_sort_order="desc",
    )

    rows = db.execute(stmt).all()

    items = [
        _linked_transaction_response(transaction, correlation)
        for correlation, transaction in rows
    ]

    return ComplaintLinkedTransactionListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_LINKED_TRANSACTION_CAVEATS),
    )


@router.get(
    "/{complaint_id}/entities",
    response_model=ComplaintLinkedEntityListResponse,
    summary="List entities correlated with a synthetic complaint",
    description=(
        "Returns paginated pseudonymous entities linked to one complaint "
        "through persisted correlations. Entity links are investigative "
        "associations only and are not proof of common control or wrongdoing. "
        "Raw identifier hashes are not returned."
    ),
)
def list_complaint_entities(
    complaint_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic complaint identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(entity_pagination),
    search: SearchParams = Depends(entity_search),
    _: User = Depends(require_permission(Permission.COMPLAINT_READ)),
    entity_type: Annotated[
        Optional[EntityType],
        Query(description="Filter by entity type."),
    ] = None,
    match_tier: Annotated[
        Optional[int],
        Query(ge=1, le=5, description="Filter correlations by tier."),
    ] = None,
    review_state: Annotated[
        Optional[ComplaintReviewState],
        Query(description="Filter correlations by reviewer state."),
    ] = None,
    deterministic: Annotated[
        Optional[bool],
        Query(description="Filter deterministic versus inferred correlations."),
    ] = None,
    match_method: Annotated[
        Optional[MatchMethod],
        Query(description="Filter correlations by match method."),
    ] = None,
) -> ComplaintLinkedEntityListResponse:
    """
    List entities linked to one complaint.
    """
    _ensure_complaints_enabled(settings)

    complaint = _get_complaint_or_404(db, complaint_id)
    complaint_id = str(complaint.id)

    entity_id_column = _model_column(ComplaintCorrelation, "entity_id")

    if entity_id_column is None:
        return ComplaintLinkedEntityListResponse(
            items=[],
            page=params.page,
            page_size=params.page_size,
            total=0,
            total_pages=0,
            sort_by=params.sort_by,
            sort_order=params.sort_order,
            caveats=[
                *_LINKED_ENTITY_CAVEATS,
                "Complaint-to-entity correlation linkage is not available in this schema.",
            ],
        )

    conditions = _build_linked_entity_conditions(
        complaint_id=complaint_id,
        entity_type=entity_type,
        match_tier=match_tier,
        review_state=review_state,
        deterministic=deterministic,
        match_method=match_method,
        search=search,
    )

    count_stmt = (
        select(func.count())
        .select_from(ComplaintCorrelation)
        .join(Entity, Entity.id == entity_id_column)
    )
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = (
        select(ComplaintCorrelation, Entity)
        .join(Entity, Entity.id == entity_id_column)
    )
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_ENTITY_COLUMN_MAP,
        tiebreaker=_ENTITY_TIEBREAKER,
        default_sort_by=_ENTITY_DEFAULT_SORT,
        default_sort_order="desc",
    )

    rows = db.execute(stmt).all()

    items = [
        _linked_entity_response(entity, correlation)
        for correlation, entity in rows
    ]

    return ComplaintLinkedEntityListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_LINKED_ENTITY_CAVEATS),
    )


@router.get(
    "/{complaint_id}/alerts",
    response_model=ComplaintAlertListResponse,
    summary="List alerts referencing a synthetic complaint",
    description=(
        "Returns paginated investigative alerts whose evidence references one "
        "synthetic complaint. Alerts are investigative leads only and must not "
        "be treated as proof of wrongdoing or used for automatic adverse action."
    ),
)
def list_complaint_alerts(
    complaint_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic complaint identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(alert_pagination),
    _: User = Depends(require_permission(Permission.ALERT_READ)),
    state: Annotated[
        Optional[AlertState],
        Query(description="Filter by alert triage state."),
    ] = None,
    priority: Annotated[
        Optional[Priority],
        Query(description="Filter by alert priority."),
    ] = None,
) -> ComplaintAlertListResponse:
    """
    List alerts referencing one complaint.
    """
    _ensure_complaints_enabled(settings)

    complaint = _get_complaint_or_404(db, complaint_id)
    complaint_id = str(complaint.id)

    conditions = _build_complaint_alert_conditions(
        complaint_id=complaint_id,
        state=state,
        priority=priority,
    )

    count_stmt = (
        select(func.count())
        .select_from(Alert)
        .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
    )
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = (
        select(Alert)
        .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
    )
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_ALERT_COLUMN_MAP,
        tiebreaker=_ALERT_TIEBREAKER,
        default_sort_by=_ALERT_DEFAULT_SORT,
        default_sort_order="desc",
    )

    alerts = db.scalars(stmt).all()

    return ComplaintAlertListResponse(
        items=[_alert_response(alert) for alert in alerts],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_ALERT_CAVEATS),
    )


@router.get(
    "/{complaint_id}/history",
    response_model=ComplaintHistoryListResponse,
    summary="List safe audit history for a synthetic complaint",
    description=(
        "Returns paginated safe audit history for one synthetic complaint and "
        "its correlations. History contains sanitized metadata only."
    ),
)
def list_complaint_history(
    complaint_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic complaint identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(audit_pagination),
    search: SearchParams = Depends(audit_search),
    _: User = Depends(require_permission(Permission.COMPLAINT_READ)),
    action: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audit action name."),
    ] = None,
    outcome: Annotated[
        Optional[AuditOutcome],
        Query(description="Filter by audit outcome."),
    ] = None,
) -> ComplaintHistoryListResponse:
    """
    List audit history for one complaint and its correlations.
    """
    _ensure_complaints_enabled(settings)

    complaint = _get_complaint_or_404(db, complaint_id)
    complaint_id = str(complaint.id)

    resource_type_column = _model_column(AuditEvent, "resource_type")
    resource_id_column = _model_column(AuditEvent, "resource_id")

    if resource_type_column is None or resource_id_column is None:
        return ComplaintHistoryListResponse(
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

    conditions = _build_complaint_history_conditions(
        complaint_id=complaint_id,
        action=action,
        outcome=outcome,
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
        column_map=_AUDIT_COLUMN_MAP,
        tiebreaker=_AUDIT_TIEBREAKER,
        default_sort_by=_AUDIT_DEFAULT_SORT,
        default_sort_order="desc",
    )

    events = db.scalars(stmt).all()

    return ComplaintHistoryListResponse(
        items=[_audit_event_response(event) for event in events],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_HISTORY_CAVEATS),
    )


@router.get(
    "/{complaint_id}/export",
    response_model=ComplaintExportBundleResponse,
    summary="Export a bounded complaint bundle",
    description=(
        "Returns a bounded JSON export bundle for one synthetic complaint, "
        "including sanitized correlation views. Raw complaint narratives are "
        "intentionally not returned."
    ),
)
def export_complaint_bundle(
    complaint_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic complaint identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.COMPLAINT_READ)),
) -> ComplaintExportBundleResponse:
    """
    Export one complaint bundle.
    """
    _ensure_complaints_enabled(settings)

    complaint = _get_complaint_or_404(db, complaint_id)
    complaint_id = str(complaint.id)

    limit = _complaint_export_max_items(settings)

    correlations, correlation_total = _load_complaint_correlations(
        db,
        complaint_id,
        limit=limit,
    )

    return ComplaintExportBundleResponse(
        complaint=_complaint_response(
            complaint,
            correlation_count=correlation_total,
        ),
        correlations=correlations,
        correlation_total=correlation_total,
        correlation_truncated=correlation_total > len(correlations),
        max_items=limit,
        caveats=list(_EXPORT_CAVEATS),
    )


__all__ = [
    "router",
]