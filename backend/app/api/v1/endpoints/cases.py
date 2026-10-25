"""
MULEGUARD backend API v1 case endpoints.

This module implements the versioned `/api/v1/cases` investigation workflow
surface for synthetic MULEGUARD cases.

Implemented endpoints:

- GET    /api/v1/cases
- POST   /api/v1/cases
- GET    /api/v1/cases/{case_id}
- PATCH  /api/v1/cases/{case_id}
- POST   /api/v1/cases/{case_id}/assign
- POST   /api/v1/cases/{case_id}/start
- POST   /api/v1/cases/{case_id}/escalate
- POST   /api/v1/cases/{case_id}/close
- POST   /api/v1/cases/{case_id}/reopen
- GET    /api/v1/cases/{case_id}/notes
- POST   /api/v1/cases/{case_id}/notes
- GET    /api/v1/cases/{case_id}/evidence
- POST   /api/v1/cases/{case_id}/evidence
- POST   /api/v1/cases/{case_id}/evidence/{evidence_id}/remove
- GET    /api/v1/cases/{case_id}/events
- GET    /api/v1/cases/{case_id}/audit
- GET    /api/v1/cases/{case_id}/export

Design goals:

- provide real, persisted, auditable investigation-case workflows;
- enforce server-side RBAC through dependency permissions;
- centralise case state-transition validation;
- keep case history append-only;
- require evidence references to point to validated persisted records;
- keep list endpoints paginated, filtered, searched, and stably ordered;
- avoid exposing synthetic ground-truth labels, scenario IDs, ring IDs,
  passwords, tokens, secrets, database URLs, raw complaint narratives, or real
  customer data;
- make clear that case dispositions are investigator-entered assessments, not
  automatic conclusions or enforcement actions.

Explicit non-goals:

- This module does not freeze, block, blacklist, close, restrict, or otherwise
  take adverse action against accounts or customers.
- This module does not connect to real banking systems.
- This module does not compute ML scores inline.
- This module does not delete or mutate case history.
- This module does not allow manual attachment of graph-path evidence; graph
  evidence must be produced by the bounded graph service.
- This module does not claim production readiness or real-world fraud-detection
  accuracy.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, and case dispositions are investigative leads or human workflow
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
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
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
    require_permission,
    search_dependency,
)
from app.exceptions import (
    ConflictError,
    EvidenceNotFoundError,
    EvidenceValidationError,
    FeatureFlagDisabledError,
    NotFoundError,
    PermissionDeniedError,
    UnsupportedActionError,
    ValidationError as MuleGuardValidationError,
)
from app.models import (
    Account,
    AccountEntityLink,
    Alert,
    AuditEvent,
    AuditOutcome,
    CaseEvent,
    CaseEvidence,
    CaseStatus,
    Complaint,
    ComplaintCorrelation,
    Disposition,
    EvidenceType,
    InvestigationCase,
    ModelAssessment,
    Priority,
    Transaction,
    User,
    UserRole,
)
from app.services.case_state_machine import (
    allowed_transitions,
    validate_transition,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.cases")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["cases"])


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_TITLE_LENGTH: Final[int] = 200
_MAX_DESCRIPTION_LENGTH: Final[int] = 2000
_MAX_REASON_LENGTH: Final[int] = 2000
_MAX_NOTE_LENGTH: Final[int] = 2000
_MAX_SUMMARY_LENGTH: Final[int] = 2000
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_MAPPING_KEYS: Final[int] = 100
_MAX_JSON_DEPTH: Final[int] = 6

_DETAIL_DEFAULT_MAX_ITEMS: Final[int] = 50
_DETAIL_HARD_MAX_ITEMS: Final[int] = 200

_EXPORT_DEFAULT_MAX_ITEMS: Final[int] = 200
_EXPORT_HARD_MAX_ITEMS: Final[int] = 1000

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

_NOTE_ACTION: Final[str] = "case_note_add"
_EVIDENCE_ADD_ACTION: Final[str] = "case_evidence_add"
_EVIDENCE_REMOVE_ACTION: Final[str] = "case_evidence_remove"

# The disposition vocabulary is the `Disposition` enum, because that is what
# the column stores.
#
# This module previously carried its own list of labels — "no_further_action",
# "monitoring", "referred_for_further_review" and so on — which it normalized
# to lower snake_case and wrote into a column declared as
# `enum_column(Disposition)`. Only one label even overlapped, and in the wrong
# case. Every close therefore attempted to store a value the column does not
# accept.
_DEFAULT_CASE_DISPOSITIONS: Final[tuple[str, ...]] = tuple(
    item.value for item in Disposition
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

_CASE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Cases are human investigative workflow artefacts, not enforcement actions.",
    "Case dispositions are investigator-entered assessments, not automatic conclusions.",
    "Alerts, risk scores, graph relationships, candidate money trails, entity links, and complaint correlations are investigative leads only.",
    "Risk scores are investigative priority scores, not probabilities of guilt.",
    "Evidence references must point to validated persisted records.",
    "Case history is append-only through this API.",
    "Raw complaint narratives are intentionally not returned.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    "This API does not freeze, block, blacklist, close, restrict, or otherwise take adverse action against accounts or customers.",
)

_EVIDENCE_CAVEATS: Final[tuple[str, ...]] = (
    *_CASE_CAVEATS,
    "Graph path evidence must be generated by the bounded graph service and cannot be manually attached through this endpoint.",
    "Removing case evidence deactivates the reference; it does not delete the underlying record or audit history.",
)

_EVENT_CAVEATS: Final[tuple[str, ...]] = (
    *_CASE_CAVEATS,
    "Case events are append-only investigator/system workflow records.",
    "Case event metadata is sanitised before storage and response serialisation.",
)

_AUDIT_CAVEATS: Final[tuple[str, ...]] = (
    *_CASE_CAVEATS,
    "Audit history contains safe operational metadata only.",
    "Passwords, tokens, secrets, raw narratives, and unnecessary sensitive payloads are not stored in audit metadata.",
)

_EXPORT_CAVEATS: Final[tuple[str, ...]] = (
    *_CASE_CAVEATS,
    "Export bundles are bounded and may be truncated.",
    "Export bundles do not include raw complaint narratives.",
    "Export bundles do not include ground-truth labels, scenario IDs, or fraud-ring IDs.",
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


_CASE_COLUMN_MAP: Final[dict[str, Any]] = _build_column_map(
    InvestigationCase,
    (
        "id",
        "created_at",
        "updated_at",
        "title",
        "status",
        "priority",
        "assignee_id",
        "creator_id",
        "account_id",
        "alert_id",
        "closed_at",
        "disposition",
    ),
)

_EVENT_COLUMN_MAP: Final[dict[str, Any]] = _build_column_map(
    CaseEvent,
    (
        "id",
        "created_at",
        "action",
        "actor_id",
        "actor_username",
        "resource_type",
        "resource_id",
    ),
)

_EVIDENCE_COLUMN_MAP: Final[dict[str, Any]] = _build_column_map(
    CaseEvidence,
    (
        "id",
        "created_at",
        "updated_at",
        "evidence_type",
        "evidence_id",
        "is_active",
        "added_by",
    ),
)

_AUDIT_COLUMN_MAP: Final[dict[str, Any]] = _build_column_map(
    AuditEvent,
    (
        "id",
        "created_at",
        "action",
        "outcome",
        "actor_username",
    ),
)

_CASE_TIEBREAKER = _model_column(InvestigationCase, "id")
_EVENT_TIEBREAKER = _model_column(CaseEvent, "id")
_EVIDENCE_TIEBREAKER = _model_column(CaseEvidence, "id")
_AUDIT_TIEBREAKER = _model_column(AuditEvent, "id")

_CASE_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _CASE_COLUMN_MAP
    else ("id" if "id" in _CASE_COLUMN_MAP else "created_at")
)

_EVENT_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _EVENT_COLUMN_MAP
    else ("id" if "id" in _EVENT_COLUMN_MAP else "created_at")
)

_EVIDENCE_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _EVIDENCE_COLUMN_MAP
    else ("id" if "id" in _EVIDENCE_COLUMN_MAP else "created_at")
)

_AUDIT_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _AUDIT_COLUMN_MAP
    else ("id" if "id" in _AUDIT_COLUMN_MAP else "created_at")
)


# -----------------------------------------------------------------------------
# Reusable bounded dependencies
# -----------------------------------------------------------------------------

case_pagination = pagination_dependency(
    sortable_fields=tuple(_CASE_COLUMN_MAP.keys()),
    default_sort_by=_CASE_DEFAULT_SORT,
    default_sort_order="desc",
)

event_pagination = pagination_dependency(
    sortable_fields=tuple(_EVENT_COLUMN_MAP.keys()),
    default_sort_by=_EVENT_DEFAULT_SORT,
    default_sort_order="desc",
)

evidence_pagination = pagination_dependency(
    sortable_fields=tuple(_EVIDENCE_COLUMN_MAP.keys()),
    default_sort_by=_EVIDENCE_DEFAULT_SORT,
    default_sort_order="desc",
)

audit_pagination = pagination_dependency(
    sortable_fields=tuple(_AUDIT_COLUMN_MAP.keys()),
    default_sort_by=_AUDIT_DEFAULT_SORT,
    default_sort_order="desc",
)

case_date_range = date_range_dependency(max_span_days=0)
case_search = search_dependency(max_length=200, alias="q")
event_search = search_dependency(max_length=200, alias="q")
evidence_search = search_dependency(max_length=200, alias="q")


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


def _normalize_token(value: Any) -> str:
    """
    Normalize a label-like value to lowercase snake_case.
    """
    text = str(value or "").strip().lower()
    text = text.replace(" ", "_").replace("-", "_")
    text = re.sub(r"[^a-z0-9_]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_")


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


def _sha256_text(value: str) -> str:
    """
    Return a SHA-256 hex digest for integrity/reference purposes.

    This is not used for secrets or passwords.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text_audit_metadata(value: Optional[str], *, field_name: str) -> dict[str, Any]:
    """
    Return safe audit metadata for a free-text note/reason.

    The full text is not duplicated into audit metadata. Case events may store
    the sanitised workflow text; audit metadata stores length and digest only.
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
    Return sanitized audit/case-event metadata.
    """
    if not metadata:
        return {}

    return _sanitize_json_object(
        metadata,
        max_sequence_length=50,
        max_mapping_keys=50,
    )


def _sanitize_input_mapping(value: Any) -> dict[str, Any]:
    """
    Sanitize caller-supplied mapping input.
    """
    if not isinstance(value, Mapping):
        return {}

    return _sanitize_json_object(
        value,
        max_sequence_length=100,
        max_mapping_keys=100,
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


def _construct_model(model: Any, values: Mapping[str, Any]) -> Any:
    """
    Construct a SQLAlchemy model using only attributes that appear to exist.

    This keeps the endpoint module tolerant of incremental schema differences
    while still persisting real records.
    """
    kwargs: dict[str, Any] = {}

    for key, value in values.items():
        if _model_column(model, key) is not None or hasattr(model, key):
            kwargs[key] = value

    return model(**kwargs)


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
        or "muleguard-cases"
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


def _add_case_event(
    db: Session,
    *,
    case_id: str,
    actor: Optional[User],
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    summary: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> CaseEvent:
    """
    Add an append-only case event to the current session.

    The caller is responsible for committing the transaction.
    """
    event = _construct_model(
        CaseEvent,
        {
            "case_id": _clean_text(case_id, 128),
            "actor_id": str(actor.id) if actor is not None else None,
            "actor_username": str(actor.username) if actor is not None else None,
            "action": _clean_text(action, 100),
            "resource_type": _clean_text(resource_type, 100) if resource_type is not None else None,
            "resource_id": _clean_text(resource_id, 128) if resource_id is not None else None,
            "summary": _clean_text(summary, _MAX_SUMMARY_LENGTH) if summary is not None else None,
            "metadata_json": _safe_metadata(metadata),
        },
    )

    db.add(event)
    return event


def _record_case_action(
    db: Session,
    *,
    case: InvestigationCase,
    actor: User,
    action: str,
    summary: Optional[str],
    metadata: Optional[Mapping[str, Any]],
    request: Request,
    settings: Any,
    request_id: str,
    audit_action: Optional[str] = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
) -> CaseEvent:
    """
    Persist a case event and corresponding audit event for a material action.
    """
    case_id = str(case.id)
    safe_metadata = _safe_metadata(metadata)

    event = _add_case_event(
        db,
        case_id=case_id,
        actor=actor,
        action=action,
        resource_type="investigation_case",
        resource_id=case_id,
        summary=summary,
        metadata=safe_metadata,
    )

    _add_audit_event(
        db,
        action=audit_action or action,
        outcome=outcome,
        request_id=request_id,
        actor=actor,
        resource_type="investigation_case",
        resource_id=case_id,
        ip_hash=_ip_hash(request, settings),
        metadata=safe_metadata,
    )

    return event


# -----------------------------------------------------------------------------
# Case status helpers
# -----------------------------------------------------------------------------


# The statuses are the `CaseStatus` members themselves, not names looked up by
# string.
#
# These were previously resolved through a helper that fell back to the bare
# name when the member did not exist, and one of the names it was asked for —
# `UNDER_REVIEW` — is an *alert* state, not a case status. The case column is
# `enum_column(CaseStatus)`, so starting an investigation wrote the string
# "UNDER_REVIEW" into a column that only accepts NEW, TRIAGED,
# UNDER_INVESTIGATION, ESCALATED or CLOSED. The fallback turned a name error
# into a database error one layer further down, and the workflow's central
# action could not complete.
STATUS_NEW: Final[CaseStatus] = CaseStatus.NEW
STATUS_TRIAGED: Final[CaseStatus] = CaseStatus.TRIAGED
STATUS_UNDER_INVESTIGATION: Final[CaseStatus] = CaseStatus.UNDER_INVESTIGATION
STATUS_ESCALATED: Final[CaseStatus] = CaseStatus.ESCALATED
STATUS_CLOSED: Final[CaseStatus] = CaseStatus.CLOSED

_STATUS_NEW: Final[str] = STATUS_NEW.value
_STATUS_TRIAGED: Final[str] = STATUS_TRIAGED.value
_STATUS_UNDER_INVESTIGATION: Final[str] = STATUS_UNDER_INVESTIGATION.value
_STATUS_ESCALATED: Final[str] = STATUS_ESCALATED.value
_STATUS_CLOSED: Final[str] = STATUS_CLOSED.value


def _status_str(status: Any) -> str:
    """
    Return a normalized status string.
    """
    text = _enum_str(status) or str(status or "UNKNOWN")
    return text.strip().upper().replace(" ", "_").replace("-", "_")


def _case_current_status(case: InvestigationCase) -> str:
    """
    Return the current case status as a normalized string.
    """
    return _status_str(_get_if_exists(case, "status", None))


def _assert_case_open(case: InvestigationCase, action: str) -> None:
    """
    Prevent material workflow mutations on closed cases.
    """
    if _case_current_status(case) == _STATUS_CLOSED:
        raise ConflictError(
            f"Cannot {action} a closed case. Reopen the case first.",
            details={
                "case_id": str(case.id),
                "status": _case_current_status(case),
            },
        )


def _assert_transition(
    case: InvestigationCase,
    target_status: CaseStatus,
    action: str,
    *,
    disposition: Any = None,
    assignee_id: Optional[str] = None,
    reason: Optional[str] = None,
) -> str:
    """
    Validate a case state transition and return the previous status string.

    The transition table lives in `app/services/case_state_machine.py`, which
    is what `describe_state_machine()` publishes and what the service layer
    enforces. This endpoint module used to carry a second copy of it, and the
    two had drifted: the copy had no TRIAGED row at all, so a triaged case
    could not move anywhere, and it enforced reachability only. The
    obligations the published machine declares — a disposition to close, an
    assignee to start, a reason to escalate, de-escalate or reopen — went
    unchecked, so the API accepted closures with no stated outcome while
    advertising that it would not.
    """
    current = _case_current_status(case)
    target = target_status.value

    if current == target:
        return current

    try:
        validate_transition(
            current=current,
            target=target_status,
            disposition=disposition,
            assignee_id=assignee_id,
            reason=reason,
        )
    except ValueError as exc:
        raise ConflictError(
            f"Cannot {action} case: {exc}",
            details={
                "case_id": str(case.id),
                "previous_status": current,
                "requested_status": target,
                "allowed_statuses": sorted(
                    rule.target.value for rule in allowed_transitions(current)
                ),
            },
        ) from exc

    return current


def _set_case_status(
    case: InvestigationCase,
    target_status: Any,
    actor: User,
) -> None:
    """
    Set case status and updated_by when available.
    """
    _set_if_exists(case, "status", target_status)
    _set_if_exists(case, "updated_by", str(actor.id))


# -----------------------------------------------------------------------------
# Policy helpers
# -----------------------------------------------------------------------------


def _ensure_cases_enabled(settings: Any) -> None:
    """
    Fail closed when the case API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "CASES_API_ENABLED", True), True):
        raise FeatureFlagDisabledError("Case endpoints are disabled by configuration.")

    if not _as_bool(_setting(settings, "CASE_ENGINE_ENABLED", True), True):
        raise FeatureFlagDisabledError("Case engine is disabled by configuration.")


def _case_detail_max_items(settings: Any) -> int:
    """
    Return bounded maximum items embedded in case detail responses.
    """
    configured = max(
        1,
        _as_int(
            _setting(settings, "CASE_DETAIL_MAX_ITEMS", _DETAIL_DEFAULT_MAX_ITEMS),
            _DETAIL_DEFAULT_MAX_ITEMS,
        ),
    )
    hard = max(
        configured,
        _as_int(
            _setting(settings, "CASE_DETAIL_HARD_MAX_ITEMS", _DETAIL_HARD_MAX_ITEMS),
            _DETAIL_HARD_MAX_ITEMS,
        ),
    )

    return min(configured, hard)


def _case_export_max_items(settings: Any) -> int:
    """
    Return bounded maximum items embedded in case export bundles.
    """
    configured = max(
        1,
        _as_int(
            _setting(settings, "CASE_EXPORT_MAX_ITEMS", _EXPORT_DEFAULT_MAX_ITEMS),
            _EXPORT_DEFAULT_MAX_ITEMS,
        ),
    )
    hard = max(
        configured,
        _as_int(
            _setting(settings, "CASE_EXPORT_HARD_MAX_ITEMS", _EXPORT_HARD_MAX_ITEMS),
            _EXPORT_HARD_MAX_ITEMS,
        ),
    )

    return min(configured, hard)


def _max_case_date_span_days(settings: Any) -> int:
    """
    Return bounded maximum case query date span in days.
    """
    return max(
        1,
        _as_int(_setting(settings, "CASE_MAX_DATE_SPAN_DAYS", 3650), 3650),
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


def _validate_case_span(
    start: Optional[datetime],
    end: Optional[datetime],
    settings: Any,
) -> None:
    """
    Enforce optional maximum date span for case scans.
    """
    if start is None or end is None:
        return

    max_days = _max_case_date_span_days(settings)
    span = end - start
    max_delta = timedelta(days=max_days)

    if span > max_delta:
        raise MuleGuardValidationError(
            "Case date span exceeds configured maximum.",
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


def _role_allowed(
    setting_name: str,
    role: Any,
    default_roles: Sequence[str],
    settings: Any,
) -> bool:
    """
    Return True when a role is allowed by setting or default policy.
    """
    raw = _setting(settings, setting_name, None)
    normalized_role = _normalize_role(role)

    if raw is None:
        allowed = {_normalize_role(item) for item in default_roles if str(item).strip()}
    else:
        allowed = {_normalize_role(item) for item in _csv(raw) if str(item).strip()}

    return normalized_role in allowed


_DEFAULT_CASE_ASSIGNABLE_ROLES: Final[tuple[str, ...]] = (
    UserRole.ANALYST.value,
    UserRole.SENIOR_INVESTIGATOR.value,
    UserRole.ADMIN.value,
)


def _case_dispositions(settings: Any) -> tuple[str, ...]:
    """
    Return configured or default case disposition labels.
    """
    configured = _csv(_setting(settings, "CASE_DISPOSITIONS", ""))

    if configured:
        return tuple(configured)

    return _DEFAULT_CASE_DISPOSITIONS


def _validate_disposition(value: Optional[str], settings: Any) -> Optional[Disposition]:
    """
    Resolve an investigator-entered disposition label to its enum member.

    Matching is case-insensitive and tolerates separators, so "confirmed
    fraud" and "confirmed-fraud" both resolve, but the result is always a
    `Disposition` member: the column is declared over the enum, and a label
    that merely looks plausible has nowhere to be stored.

    Dispositions are workflow assessments only. They are not automatic
    conclusions and must not trigger adverse action.
    """
    if value is None:
        return None

    normalized = _normalize_token(value)

    if not normalized:
        return None

    configured = {
        _normalize_token(item) for item in _case_dispositions(settings) if item
    }
    by_token = {_normalize_token(item.value): item for item in Disposition}
    resolved = by_token.get(normalized)

    if resolved is None or (configured and normalized not in configured):
        raise MuleGuardValidationError(
            "Disposition is not allowed by configuration.",
            details={
                "disposition": normalized,
                "allowed_dispositions": sorted(
                    item for item in _case_dispositions(settings)
                ),
            },
        )

    return resolved


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


def _validate_assignee(
    db: Session,
    settings: Any,
    assignee_id: str,
    *,
    field_name: str,
) -> User:
    """
    Validate that an assignee exists, is active, and has an allowed role.
    """
    assignee = db.get(User, assignee_id)

    if assignee is None:
        raise NotFoundError.resource("user", assignee_id)

    if not assignee.is_active:
        raise MuleGuardValidationError(
            "Assignee is inactive.",
            details={field_name: assignee_id},
        )

    if not _role_allowed(
        "CASE_ASSIGNABLE_ROLES",
        assignee.role,
        _DEFAULT_CASE_ASSIGNABLE_ROLES,
        settings,
    ):
        raise MuleGuardValidationError(
            "Assignee role is not permitted for case assignment.",
            details={
                field_name: assignee_id,
                "role": _enum_str(assignee.role),
                "setting": "CASE_ASSIGNABLE_ROLES",
            },
        )

    return assignee


# -----------------------------------------------------------------------------
# Account / alert lookup helpers
# -----------------------------------------------------------------------------


def _load_accounts_by_ids(
    db: Session,
    account_ids: Sequence[Optional[str]],
) -> dict[str, Account]:
    """
    Load a bounded map of synthetic accounts by ID.
    """
    ids = {str(account_id) for account_id in account_ids if account_id}

    if not ids:
        return {}

    rows = db.scalars(select(Account).where(Account.id.in_(list(ids)))).all()
    return {str(account.id): account for account in rows}


def _load_alerts_by_ids(
    db: Session,
    alert_ids: Sequence[Optional[str]],
) -> dict[str, Alert]:
    """
    Load a bounded map of synthetic alerts by ID.
    """
    ids = {str(alert_id) for alert_id in alert_ids if alert_id}

    if not ids:
        return {}

    rows = db.scalars(select(Alert).where(Alert.id.in_(list(ids)))).all()
    return {str(alert.id): alert for alert in rows}


def _get_case_or_404(db: Session, case_id: str) -> InvestigationCase:
    """
    Load a case or raise a safe not-found error.
    """
    case = db.get(InvestigationCase, case_id)

    if case is None:
        raise NotFoundError.resource("case", case_id)

    return case


# -----------------------------------------------------------------------------
# Evidence validation helpers
# -----------------------------------------------------------------------------


def _case_account_id(case: InvestigationCase) -> str:
    """
    Return the case account ID or raise a safe validation error.
    """
    account_id = _str_or_none(_get_if_exists(case, "account_id", None))

    if not account_id:
        raise MuleGuardValidationError(
            "Case must have an account_id before evidence can be attached.",
            details={"case_id": str(case.id)},
        )

    return account_id


def _build_evidence_snapshot(
    evidence_type: EvidenceType,
    obj: Any,
) -> dict[str, Any]:
    """
    Build a safe, minimal evidence snapshot from a validated persisted record.

    Raw complaint narratives and identifier hashes are intentionally omitted.
    """
    if evidence_type == EvidenceType.ACCOUNT:
        payload = {
            "id": str(_get_if_exists(obj, "id", "")),
            "account_type": _enum_str(_get_if_exists(obj, "account_type", None)),
            "status": _enum_str(_get_if_exists(obj, "status", None)),
            "created_at": _get_if_exists(obj, "created_at", None),
        }

    elif evidence_type == EvidenceType.TRANSACTION:
        payload = {
            "id": str(_get_if_exists(obj, "id", "")),
            "sender_account_id": str(_get_if_exists(obj, "sender_account_id", "")),
            "receiver_account_id": str(_get_if_exists(obj, "receiver_account_id", "")),
            "amount": _get_if_exists(obj, "amount", None),
            "currency": str(_get_if_exists(obj, "currency", "") or ""),
            "occurred_at": _get_if_exists(obj, "occurred_at", None),
            "status": _enum_str(_get_if_exists(obj, "status", None)),
            "channel": _enum_str(_get_if_exists(obj, "channel", None)),
            "reference": str(_get_if_exists(obj, "reference", "") or ""),
        }

    elif evidence_type == EvidenceType.COMPLAINT:
        payload = {
            "id": str(_get_if_exists(obj, "id", "")),
            "reference": str(_get_if_exists(obj, "reference", "") or ""),
            "category": str(_get_if_exists(obj, "category", "") or ""),
            "reported_at": _get_if_exists(obj, "reported_at", None),
            "amount": _get_if_exists(obj, "amount", None),
            "currency": _str_or_none(_get_if_exists(obj, "currency", None)),
            "source": _str_or_none(_get_if_exists(obj, "source", None)),
            "victim_account_id": _str_or_none(_get_if_exists(obj, "victim_account_id", None)),
            "suspected_account_id": _str_or_none(_get_if_exists(obj, "suspected_account_id", None)),
            "transaction_reference": _str_or_none(_get_if_exists(obj, "transaction_reference", None)),
            "narrative_available": bool(_get_if_exists(obj, "narrative_raw", None)),
        }

    elif evidence_type == EvidenceType.MODEL_ASSESSMENT:
        payload = {
            "id": str(_get_if_exists(obj, "id", "")),
            "account_id": str(_get_if_exists(obj, "account_id", "")),
            "as_of": _get_if_exists(obj, "as_of", None),
            "scored_at": _get_if_exists(obj, "scored_at", None),
            "scoring_mode": _enum_str(_get_if_exists(obj, "scoring_mode", None)),
            "score": _get_if_exists(obj, "score", None),
            "score_type": _str_or_none(_get_if_exists(obj, "score_type", None)),
            "risk_band": _enum_str(_get_if_exists(obj, "risk_band", None)),
            "model_version_id": _str_or_none(_get_if_exists(obj, "model_version_id", None)),
            "feature_snapshot_id": _str_or_none(_get_if_exists(obj, "feature_snapshot_id", None)),
            "analysis_run_id": _str_or_none(_get_if_exists(obj, "analysis_run_id", None)),
        }

    elif evidence_type == EvidenceType.ENTITY_LINK:
        payload = {
            "id": str(_get_if_exists(obj, "id", "")),
            "account_id": str(_get_if_exists(obj, "account_id", "")),
            "entity_id": str(_get_if_exists(obj, "entity_id", "")),
            "match_method": _enum_str(_get_if_exists(obj, "match_method", None)),
            "confidence": _get_if_exists(obj, "confidence", None),
            "verification_state": _enum_str(_get_if_exists(obj, "verification_state", None)),
            "valid_from": _get_if_exists(obj, "valid_from", None),
            "valid_to": _get_if_exists(obj, "valid_to", None),
            "source": str(_get_if_exists(obj, "source", "") or "synthetic"),
        }

    elif evidence_type == EvidenceType.ALERT:
        payload = {
            "id": str(_get_if_exists(obj, "id", "")),
            "account_id": str(_get_if_exists(obj, "account_id", "")),
            "title": str(_get_if_exists(obj, "title", "") or ""),
            "priority": _enum_str(_get_if_exists(obj, "priority", None)),
            "state": _enum_str(_get_if_exists(obj, "state", None)),
            "score": _get_if_exists(obj, "score", None),
            "scoring_mode": _enum_str(_get_if_exists(obj, "scoring_mode", None)),
            "first_seen_at": _get_if_exists(obj, "first_seen_at", None),
            "last_seen_at": _get_if_exists(obj, "last_seen_at", None),
        }

    else:
        payload = {
            "evidence_type": _enum_str(evidence_type),
            "evidence_id": str(_get_if_exists(obj, "id", "")),
        }

    return _sanitize_json_object(payload)


def _validate_evidence_reference(
    db: Session,
    case: InvestigationCase,
    evidence_type: EvidenceType,
    evidence_id: str,
) -> dict[str, Any]:
    """
    Validate that an evidence reference points to a relevant persisted record.

    Returns a safe snapshot for the referenced record.
    """
    case_account = _case_account_id(case)

    if evidence_type == EvidenceType.ACCOUNT:
        obj = db.get(Account, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced account evidence was not found.")

        if str(obj.id) != case_account:
            raise EvidenceValidationError(
                "Referenced account is not the case account."
            )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.TRANSACTION:
        obj = db.get(Transaction, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced transaction evidence was not found.")

        sender = str(_get_if_exists(obj, "sender_account_id", ""))
        receiver = str(_get_if_exists(obj, "receiver_account_id", ""))

        if case_account not in {sender, receiver}:
            raise EvidenceValidationError(
                "Referenced transaction does not involve the case account."
            )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.COMPLAINT:
        obj = db.get(Complaint, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced complaint evidence was not found.")

        victim = _str_or_none(_get_if_exists(obj, "victim_account_id", None))
        suspected = _str_or_none(_get_if_exists(obj, "suspected_account_id", None))

        related = case_account in {victim, suspected}

        if not related:
            correlation_exists = db.scalar(
                select(ComplaintCorrelation.id)
                .where(
                    ComplaintCorrelation.complaint_id == obj.id,
                    ComplaintCorrelation.account_id == case_account,
                )
                .limit(1)
            )

            if correlation_exists is None:
                raise EvidenceValidationError(
                    "Referenced complaint is not related to the case account."
                )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.MODEL_ASSESSMENT:
        obj = db.get(ModelAssessment, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError(
                "Referenced model assessment evidence was not found."
            )

        if str(_get_if_exists(obj, "account_id", "")) != case_account:
            raise EvidenceValidationError(
                "Referenced assessment does not belong to the case account."
            )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.ENTITY_LINK:
        obj = db.get(AccountEntityLink, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced entity link evidence was not found.")

        if str(_get_if_exists(obj, "account_id", "")) != case_account:
            raise EvidenceValidationError(
                "Referenced entity link does not belong to the case account."
            )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.ALERT:
        obj = db.get(Alert, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced alert evidence was not found.")

        if str(_get_if_exists(obj, "account_id", "")) != case_account:
            raise EvidenceValidationError(
                "Referenced alert does not belong to the case account."
            )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.GRAPH_PATH:
        raise EvidenceValidationError(
            "Graph path evidence must be generated by the bounded graph service "
            "and cannot be manually attached through this endpoint."
        )

    raise EvidenceValidationError("Unsupported evidence type.")


def _existing_active_case_evidence(
    db: Session,
    case_id: str,
    evidence_type: EvidenceType,
    evidence_id: str,
) -> Optional[str]:
    """
    Return an existing active case-evidence ID when duplicate attachment is
    attempted.
    """
    active_column = _model_column(CaseEvidence, "is_active")
    case_id_column = _model_column(CaseEvidence, "case_id")
    evidence_type_column = _model_column(CaseEvidence, "evidence_type")
    evidence_id_column = _model_column(CaseEvidence, "evidence_id")
    id_column = _model_column(CaseEvidence, "id")

    if (
        case_id_column is None
        or evidence_type_column is None
        or evidence_id_column is None
        or id_column is None
    ):
        return None

    stmt = select(id_column).where(
        and_(
            case_id_column == case_id,
            evidence_type_column == evidence_type,
            evidence_id_column == evidence_id,
        )
    )

    if active_column is not None:
        stmt = stmt.where(active_column.is_(True))

    row = db.scalar(stmt.limit(1))

    if row is None:
        return None

    return str(row)


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class CaseAccountSummaryResponse(BaseModel):
    """
    Safe synthetic account summary embedded in case views.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_type: str
    status: str
    created_at: datetime
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None


class CaseAlertSummaryResponse(BaseModel):
    """
    Safe synthetic alert summary embedded in case views.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_id: str
    title: str
    priority: str
    state: str
    score: Optional[Decimal] = None
    scoring_mode: str
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


class CaseResponse(BaseModel):
    """
    Safe investigation-case response.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    assignee_id: Optional[str] = None
    assignee_username: Optional[str] = None
    creator_id: Optional[str] = None
    creator_username: Optional[str] = None
    alert_id: Optional[str] = None
    account_id: Optional[str] = None
    disposition: Optional[str] = None
    closed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    metadata_json: Optional[Any] = None
    account: Optional[CaseAccountSummaryResponse] = None
    alert: Optional[CaseAlertSummaryResponse] = None


class CaseListResponse(BaseModel):
    """
    Paginated case list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[CaseResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class CaseEventResponse(BaseModel):
    """
    Safe append-only case event response.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    case_id: str
    action: str
    actor_id: Optional[str] = None
    actor_username: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    summary: Optional[str] = None
    metadata_json: Optional[Any] = None
    created_at: Optional[datetime] = None


class CaseEventListResponse(BaseModel):
    """
    Paginated case event list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[CaseEventResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class CaseEvidenceResponse(BaseModel):
    """
    Safe case evidence reference response.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    case_id: str
    evidence_type: str
    evidence_id: str
    evidence_snapshot_json: Optional[Any] = None
    provenance_json: Optional[Any] = None
    added_by: Optional[str] = None
    added_by_username: Optional[str] = None
    is_active: Optional[bool] = None
    # Withdrawal is recorded, not hidden. Evidence is deactivated rather than
    # deleted, so a reader has to be able to see that an item was attached and
    # then taken out, by whom and why — otherwise the case is a tidied version
    # of the investigation rather than a record of it.
    removed_by: Optional[str] = None
    removed_by_username: Optional[str] = None
    removed_at: Optional[datetime] = None
    removal_reason: Optional[str] = None
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None


class CaseEvidenceRemoveRequest(BaseModel):
    """
    Request to withdraw a case evidence reference.

    The reason is required. Evidence is deactivated rather than deleted, so
    the row survives and the reason travels with it; "evidence withdrawn" with
    nothing saying why tells a reviewer that something was taken out and
    nothing about whether that was right.
    """

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        min_length=1,
        max_length=_MAX_REASON_LENGTH,
        description="Why the evidence is being withdrawn. Recorded on the evidence row.",
    )

    @field_validator("reason")
    @classmethod
    def _validate_reason(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("reason must not be empty")

        return normalized


class CaseEvidenceListResponse(BaseModel):
    """
    Paginated case evidence list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[CaseEvidenceResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class CaseDetailResponse(BaseModel):
    """
    Detailed case response with bounded evidence, events, and notes.
    """

    model_config = ConfigDict(from_attributes=False)

    case: CaseResponse
    evidences: list[CaseEvidenceResponse] = Field(default_factory=list)
    events: list[CaseEventResponse] = Field(default_factory=list)
    notes: list[CaseEventResponse] = Field(default_factory=list)
    evidence_total: int = 0
    evidence_truncated: bool = False
    event_total: int = 0
    event_truncated: bool = False
    note_total: int = 0
    note_truncated: bool = False
    caveats: list[str] = Field(default_factory=list)


class CaseActionResponse(BaseModel):
    """
    Generic response for idempotent case workflow actions.
    """

    model_config = ConfigDict(from_attributes=False)

    case: CaseResponse
    changed: bool
    previous_status: str
    new_status: str
    audited: bool
    caveats: list[str] = Field(default_factory=list)


class CaseAssignResponse(BaseModel):
    """
    Response from assigning a case.
    """

    model_config = ConfigDict(from_attributes=False)

    case: CaseResponse
    changed: bool
    previous_assignee_id: Optional[str] = None
    new_assignee_id: Optional[str] = None
    previous_status: str
    new_status: str
    audited: bool
    caveats: list[str] = Field(default_factory=list)


class CaseNoteResponse(BaseModel):
    """
    Response from adding a case note.
    """

    model_config = ConfigDict(from_attributes=False)

    note: CaseEventResponse
    case: CaseResponse
    audited: bool
    caveats: list[str] = Field(default_factory=list)


class CaseEvidenceActionResponse(BaseModel):
    """
    Response from attaching evidence to a case.
    """

    model_config = ConfigDict(from_attributes=False)

    evidence: CaseEvidenceResponse
    case: CaseResponse
    changed: bool
    audited: bool
    caveats: list[str] = Field(default_factory=list)


class CaseEvidenceRemoveResponse(BaseModel):
    """
    Response from deactivating a case evidence reference.
    """

    model_config = ConfigDict(from_attributes=False)

    evidence: CaseEvidenceResponse
    case: CaseResponse
    changed: bool
    audited: bool
    caveats: list[str] = Field(default_factory=list)


class CaseAuditEventResponse(BaseModel):
    """
    Safe audit event response for a case.
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


class CaseAuditListResponse(BaseModel):
    """
    Paginated case audit history response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[CaseAuditEventResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class CaseExportBundleResponse(BaseModel):
    """
    Bounded JSON export bundle for one investigation case.
    """

    model_config = ConfigDict(from_attributes=False)

    case: CaseResponse
    evidences: list[CaseEvidenceResponse] = Field(default_factory=list)
    events: list[CaseEventResponse] = Field(default_factory=list)
    notes: list[CaseEventResponse] = Field(default_factory=list)
    evidence_total: int = 0
    evidence_truncated: bool = False
    event_total: int = 0
    event_truncated: bool = False
    note_total: int = 0
    note_truncated: bool = False
    max_items: int = 0
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Request models
# -----------------------------------------------------------------------------


class CaseCreateRequest(BaseModel):
    """
    Request to create a synthetic investigation case.
    """

    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(
        default=None,
        max_length=_MAX_TITLE_LENGTH,
        description="Case title. Defaults to alert title or account-based label.",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=_MAX_DESCRIPTION_LENGTH,
        description="Optional case description.",
    )
    account_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Synthetic account identifier. Required unless alert_id is supplied.",
    )
    alert_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Synthetic alert identifier. Account is derived from the alert.",
    )
    assignee_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Optional local user identifier to assign.",
    )
    priority: Optional[Priority] = Field(
        default=None,
        description="Optional case priority. Defaults to MEDIUM or alert priority when available.",
    )
    metadata_json: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional safe case metadata.",
    )

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            raise ValueError("title must not be empty")

        if len(normalized) > _MAX_TITLE_LENGTH:
            raise ValueError("title is too long")

        return normalized

    @field_validator("description")
    @classmethod
    def _validate_description(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > _MAX_DESCRIPTION_LENGTH:
            raise ValueError("description is too long")

        return normalized

    @field_validator("account_id", "alert_id", "assignee_id")
    @classmethod
    def _validate_ids(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > 128:
            raise ValueError("identifier is too long")

        return normalized

    @model_validator(mode="after")
    def _validate_target(self) -> "CaseCreateRequest":
        if not self.account_id and not self.alert_id:
            raise ValueError("account_id or alert_id is required")

        return self


class CaseUpdateRequest(BaseModel):
    """
    Request to update non-material case attributes.

    Status and assignee changes must use dedicated workflow endpoints.
    """

    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(
        default=None,
        max_length=_MAX_TITLE_LENGTH,
        description="Updated case title.",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=_MAX_DESCRIPTION_LENGTH,
        description="Updated case description. Use null to clear.",
    )
    priority: Optional[Priority] = Field(
        default=None,
        description="Updated case priority.",
    )
    metadata_json: Optional[dict[str, Any]] = Field(
        default=None,
        description="Replacement safe case metadata. Use null to clear.",
    )

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            raise ValueError("title must not be empty")

        if len(normalized) > _MAX_TITLE_LENGTH:
            raise ValueError("title is too long")

        return normalized

    @field_validator("description")
    @classmethod
    def _validate_description(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > _MAX_DESCRIPTION_LENGTH:
            raise ValueError("description is too long")

        return normalized

    @model_validator(mode="after")
    def _validate_update_payload(self) -> "CaseUpdateRequest":
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")

        if "title" in self.model_fields_set and self.title is None:
            raise ValueError("title must not be null.")

        if "priority" in self.model_fields_set and self.priority is None:
            raise ValueError("priority must not be null.")

        return self


class CaseAssignRequest(BaseModel):
    """
    Request to assign a case to an active, permitted local user.
    """

    model_config = ConfigDict(extra="forbid")

    assignee_id: str = Field(
        min_length=1,
        max_length=128,
        description="Local prototype user identifier to assign.",
    )
    note: Optional[str] = Field(
        default=None,
        max_length=_MAX_NOTE_LENGTH,
        description=(
            "Optional assignment note. Do not include secrets, tokens, "
            "passwords, or unnecessary sensitive narrative text."
        ),
    )

    @field_validator("assignee_id")
    @classmethod
    def _validate_assignee_id(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("assignee_id must not be empty")

        return normalized

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


class CaseCloseRequest(BaseModel):
    """
    Request to close a case as a human investigative decision.
    """

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        min_length=3,
        max_length=_MAX_REASON_LENGTH,
        description=(
            "Investigator closure reason. This is recorded in case history and "
            "sanitised audit metadata. Do not include secrets, tokens, passwords, "
            "or unnecessary sensitive narrative text."
        ),
    )
    # Required, because the state machine requires it.
    #
    # `close` carries `requires_disposition=True`, and the disposition is the
    # one field every later quality measurement depends on: confirmed fraud,
    # false positive, inconclusive, referred. It cannot be reconstructed
    # afterwards from the reason text, and a closed case recorded as
    # "unspecified" is indistinguishable from one nobody concluded.
    #
    # Accepting a close without it let the API record exactly that, while
    # `describe_state_machine()` published the opposite.
    disposition: str = Field(
        min_length=1,
        max_length=100,
        description=(
            "Investigator-entered disposition label. This is a workflow "
            "assessment, not an automatic conclusion or enforcement action."
        ),
    )

    @field_validator("reason")
    @classmethod
    def _validate_reason(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("reason must not be empty")

        if len(normalized) > _MAX_REASON_LENGTH:
            raise ValueError("reason is too long")

        return normalized

    @field_validator("disposition")
    @classmethod
    def _validate_disposition(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("disposition must not be empty")

        if len(normalized) > 100:
            raise ValueError("disposition is too long")

        return normalized


class CaseEscalateRequest(BaseModel):
    """
    Request to escalate a case for senior review.
    """

    model_config = ConfigDict(extra="forbid")

    # Required, because the state machine requires it.
    #
    # `escalate` carries `requires_reason=True`. An escalation with no stated
    # reason arrives at a senior reviewer as a case with a changed status and
    # nothing to act on, and the reviewer's first task becomes reconstructing
    # why it was sent.
    reason: str = Field(
        min_length=3,
        max_length=_MAX_REASON_LENGTH,
        description=(
            "Why the case is being escalated. This is recorded in case history "
            "and sanitised audit metadata. Do not include secrets, tokens, "
            "passwords, or unnecessary sensitive narrative text."
        ),
    )

    @field_validator("reason")
    @classmethod
    def _validate_reason(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("reason must not be empty")

        if len(normalized) > _MAX_REASON_LENGTH:
            raise ValueError("reason is too long")

        return normalized


class CaseReopenRequest(BaseModel):
    """
    Request to reopen a closed case.
    """

    model_config = ConfigDict(extra="forbid")

    # Required, because the state machine requires it.
    #
    # The `reopen` transition carries `requires_reason=True`, so
    # `validate_transition` refuses a reopen without one. Declaring the field
    # optional here promised callers something the workflow then rejected: the
    # request passed validation and failed deep inside with a 409, which reads
    # as "the case cannot be reopened" rather than "say why".
    #
    # A reason is also the point. A case is reopened because new information
    # arrived, and the previous disposition is preserved in history rather than
    # erased — so the reason is what explains the discrepancy to whoever reads
    # the timeline later.
    reason: str = Field(
        min_length=1,
        max_length=_MAX_REASON_LENGTH,
        description="Why the case is being reopened. Recorded in case history.",
    )

    @field_validator("reason")
    @classmethod
    def _validate_reason(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > _MAX_REASON_LENGTH:
            raise ValueError("reason is too long")

        return normalized


class CaseNoteRequest(BaseModel):
    """
    Request to append a note to a case.
    """

    model_config = ConfigDict(extra="forbid")

    note: str = Field(
        min_length=1,
        max_length=_MAX_NOTE_LENGTH,
        description=(
            "Investigator note. Notes are append-only. Do not include secrets, "
            "tokens, passwords, raw complaint narratives, or unnecessary "
            "sensitive text."
        ),
    )

    @field_validator("note")
    @classmethod
    def _validate_note(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("note must not be empty")

        if len(normalized) > _MAX_NOTE_LENGTH:
            raise ValueError("note is too long")

        return normalized


class CaseEvidenceCreateRequest(BaseModel):
    """
    Request to attach a validated persisted record as case evidence.
    """

    model_config = ConfigDict(extra="forbid")

    evidence_type: EvidenceType = Field(
        description="Validated evidence type.",
    )
    evidence_id: str = Field(
        min_length=1,
        max_length=128,
        description="Identifier of the referenced persisted record.",
    )
    evidence_snapshot_json: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "Optional safe structured snapshot. If omitted, MULEGUARD generates "
            "a minimal snapshot from the referenced record."
        ),
    )
    provenance_json: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional safe provenance metadata.",
    )

    @field_validator("evidence_id")
    @classmethod
    def _validate_evidence_id(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("evidence_id must not be empty")

        return normalized


# -----------------------------------------------------------------------------
# Response builders
# -----------------------------------------------------------------------------


def _account_summary_response(account: Account) -> CaseAccountSummaryResponse:
    """
    Build a safe account summary.
    """
    return CaseAccountSummaryResponse(
        id=str(account.id),
        account_type=_enum_str(_get_if_exists(account, "account_type", None)) or "OTHER",
        status=_enum_str(_get_if_exists(account, "status", None)) or "ACTIVE",
        created_at=_get_if_exists(account, "created_at", _now_utc()),
        record_created_at=_get_if_exists(account, "record_created_at", None),
        record_updated_at=_get_if_exists(account, "record_updated_at", None),
    )


def _alert_summary_response(alert: Alert) -> CaseAlertSummaryResponse:
    """
    Build a safe alert summary.
    """
    return CaseAlertSummaryResponse(
        id=str(alert.id),
        account_id=str(_get_if_exists(alert, "account_id", "")),
        title=str(_get_if_exists(alert, "title", "") or ""),
        priority=_enum_str(_get_if_exists(alert, "priority", None)) or "MEDIUM",
        state=_enum_str(_get_if_exists(alert, "state", None)) or "NEW",
        score=_get_if_exists(alert, "score", None),
        scoring_mode=_enum_str(_get_if_exists(alert, "scoring_mode", None)) or "unknown",
        first_seen_at=_get_if_exists(alert, "first_seen_at", None),
        last_seen_at=_get_if_exists(alert, "last_seen_at", None),
    )


def _event_response(event: CaseEvent) -> CaseEventResponse:
    """
    Build a safe case event response.
    """
    return CaseEventResponse(
        id=str(_get_if_exists(event, "id", "")),
        case_id=str(_get_if_exists(event, "case_id", "")),
        action=str(_get_if_exists(event, "action", "") or ""),
        actor_id=_str_or_none(_get_if_exists(event, "actor_id", None)),
        actor_username=_str_or_none(_get_if_exists(event, "actor_username", None)),
        resource_type=_str_or_none(_get_if_exists(event, "resource_type", None)),
        resource_id=_str_or_none(_get_if_exists(event, "resource_id", None)),
        summary=_str_or_none(_get_if_exists(event, "summary", None)),
        metadata_json=_response_metadata(_get_if_exists(event, "metadata_json", None)),
        created_at=_get_if_exists(event, "created_at", None),
    )


def _evidence_response(
    evidence: CaseEvidence,
    added_by_username: Optional[str] = None,
    removed_by_username: Optional[str] = None,
) -> CaseEvidenceResponse:
    """
    Build a safe case evidence response.
    """
    return CaseEvidenceResponse(
        id=str(_get_if_exists(evidence, "id", "")),
        case_id=str(_get_if_exists(evidence, "case_id", "")),
        evidence_type=_enum_str(_get_if_exists(evidence, "evidence_type", None)) or "UNKNOWN",
        evidence_id=str(_get_if_exists(evidence, "evidence_id", "")),
        evidence_snapshot_json=_response_metadata(
            _get_if_exists(evidence, "evidence_snapshot_json", None)
        ),
        provenance_json=_response_metadata(
            _get_if_exists(evidence, "provenance_json", None)
        ),
        added_by=_str_or_none(_get_if_exists(evidence, "added_by", None)),
        added_by_username=added_by_username,
        is_active=_get_if_exists(evidence, "is_active", None),
        removed_by=_str_or_none(_get_if_exists(evidence, "removed_by", None)),
        removed_by_username=removed_by_username,
        removed_at=_get_if_exists(evidence, "removed_at", None),
        removal_reason=_str_or_none(_get_if_exists(evidence, "removal_reason", None)),
        record_created_at=_get_if_exists(evidence, "record_created_at", None),
        record_updated_at=_get_if_exists(evidence, "record_updated_at", None),
    )


def _audit_event_response(event: AuditEvent) -> CaseAuditEventResponse:
    """
    Build a safe audit event response.
    """
    return CaseAuditEventResponse(
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


def _case_response(
    case: InvestigationCase,
    *,
    account: Optional[Account] = None,
    alert: Optional[Alert] = None,
    assignee_username: Optional[str] = None,
    creator_username: Optional[str] = None,
) -> CaseResponse:
    """
    Build a safe case response.
    """
    disposition = _get_if_exists(case, "disposition", None)

    return CaseResponse(
        id=str(case.id),
        title=str(_get_if_exists(case, "title", "") or ""),
        description=_str_or_none(_get_if_exists(case, "description", None)),
        status=_case_current_status(case),
        priority=_enum_str(_get_if_exists(case, "priority", None)) or "MEDIUM",
        assignee_id=_str_or_none(_get_if_exists(case, "assignee_id", None)),
        assignee_username=assignee_username,
        creator_id=_str_or_none(_get_if_exists(case, "creator_id", None)),
        creator_username=creator_username,
        alert_id=_str_or_none(_get_if_exists(case, "alert_id", None)),
        account_id=_str_or_none(_get_if_exists(case, "account_id", None)),
        disposition=_enum_str(disposition) if isinstance(disposition, Enum) else _str_or_none(disposition),
        closed_at=_get_if_exists(case, "closed_at", None),
        created_at=_get_if_exists(case, "record_created_at", None),
        updated_at=_get_if_exists(case, "record_updated_at", None),
        metadata_json=_response_metadata(_get_if_exists(case, "metadata_json", None)),
        account=_account_summary_response(account) if account is not None else None,
        alert=_alert_summary_response(alert) if alert is not None else None,
    )


def _hydrate_case_response(
    db: Session,
    case: InvestigationCase,
) -> CaseResponse:
    """
    Build a case response with bounded account, alert, and username context.
    """
    account_id = _str_or_none(_get_if_exists(case, "account_id", None))
    alert_id = _str_or_none(_get_if_exists(case, "alert_id", None))
    assignee_id = _str_or_none(_get_if_exists(case, "assignee_id", None))
    creator_id = _str_or_none(_get_if_exists(case, "creator_id", None))

    account = db.get(Account, account_id) if account_id else None
    alert = db.get(Alert, alert_id) if alert_id else None

    usernames = _username_map_for_user_ids(db, [assignee_id, creator_id])

    return _case_response(
        case,
        account=account,
        alert=alert,
        assignee_username=usernames.get(assignee_id) if assignee_id else None,
        creator_username=usernames.get(creator_id) if creator_id else None,
    )


# -----------------------------------------------------------------------------
# Internal loaders for detail/export
# -----------------------------------------------------------------------------


def _load_case_events(
    db: Session,
    case_id: str,
    *,
    limit: int,
    action: Optional[str] = None,
) -> tuple[list[CaseEventResponse], int]:
    """
    Load bounded case events and total count.
    """
    conditions: list[Any] = [_model_column(CaseEvent, "case_id") == case_id]

    if action is not None:
        action_column = _model_column(CaseEvent, "action")

        if action_column is not None:
            conditions.append(action_column == action)

    total = _scalar_count(
        db,
        _apply_conditions(select(func.count()).select_from(CaseEvent), conditions),
    )

    stmt = select(CaseEvent)
    stmt = _apply_conditions(stmt, conditions)

    created_at_column = _model_column(CaseEvent, "created_at")
    id_column = _model_column(CaseEvent, "id")

    if created_at_column is not None:
        stmt = stmt.order_by(desc(created_at_column))

    if id_column is not None:
        stmt = stmt.order_by(desc(id_column))

    stmt = stmt.limit(max(1, int(limit)))

    rows = db.scalars(stmt).all()

    return [_event_response(event) for event in rows], total


def _load_case_evidence(
    db: Session,
    case_id: str,
    *,
    limit: int,
    include_inactive: bool = False,
) -> tuple[list[CaseEvidenceResponse], int]:
    """
    Load bounded case evidence and total count.
    """
    conditions: list[Any] = [_model_column(CaseEvidence, "case_id") == case_id]

    active_column = _model_column(CaseEvidence, "is_active")

    if active_column is not None and not include_inactive:
        conditions.append(active_column.is_(True))

    total = _scalar_count(
        db,
        _apply_conditions(select(func.count()).select_from(CaseEvidence), conditions),
    )

    stmt = select(CaseEvidence)
    stmt = _apply_conditions(stmt, conditions)

    created_at_column = _model_column(CaseEvidence, "record_created_at")
    id_column = _model_column(CaseEvidence, "id")

    if created_at_column is not None:
        stmt = stmt.order_by(desc(created_at_column))

    if id_column is not None:
        stmt = stmt.order_by(desc(id_column))

    stmt = stmt.limit(max(1, int(limit)))

    rows = db.scalars(stmt).all()

    usernames = _username_map_for_user_ids(
        db,
        [
            *(_str_or_none(_get_if_exists(row, "added_by", None)) for row in rows),
            *(_str_or_none(_get_if_exists(row, "removed_by", None)) for row in rows),
        ],
    )

    items = [
        _evidence_response(
            row,
            added_by_username=usernames.get(
                str(_get_if_exists(row, "added_by", ""))
            )
            if _get_if_exists(row, "added_by", None)
            else None,
            removed_by_username=usernames.get(
                str(_get_if_exists(row, "removed_by", ""))
            )
            if _get_if_exists(row, "removed_by", None)
            else None,
        )
        for row in rows
    ]

    return items, total


def _load_case_notes(
    db: Session,
    case_id: str,
    *,
    limit: int,
) -> tuple[list[CaseEventResponse], int]:
    """
    Load bounded case notes and total count.
    """
    return _load_case_events(db, case_id, limit=limit, action=_NOTE_ACTION)


def _case_detail_response(
    db: Session,
    case: InvestigationCase,
    settings: Any,
) -> CaseDetailResponse:
    """
    Build a detailed case response with bounded evidence, events, and notes.
    """
    limit = _case_detail_max_items(settings)
    case_id = str(case.id)

    evidences, evidence_total = _load_case_evidence(db, case_id, limit=limit)
    events, event_total = _load_case_events(db, case_id, limit=limit)
    notes, note_total = _load_case_notes(db, case_id, limit=limit)

    return CaseDetailResponse(
        case=_hydrate_case_response(db, case),
        evidences=evidences,
        events=events,
        notes=notes,
        evidence_total=evidence_total,
        evidence_truncated=evidence_total > len(evidences),
        event_total=event_total,
        event_truncated=event_total > len(events),
        note_total=note_total,
        note_truncated=note_total > len(notes),
        caveats=[*_CASE_CAVEATS, *_EVIDENCE_CAVEATS, *_EVENT_CAVEATS],
    )


# -----------------------------------------------------------------------------
# Query condition builders
# -----------------------------------------------------------------------------


def _build_case_conditions(
    *,
    status: Optional[CaseStatus],
    priority: Optional[Priority],
    assignee_id: Optional[str],
    creator_id: Optional[str],
    account_id: Optional[str],
    alert_id: Optional[str],
    disposition: Optional[str],
    date_range: DateRangeParams,
    closed_from: Optional[datetime],
    closed_to: Optional[datetime],
    search: Optional[SearchParams],
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for case list queries.
    """
    conditions: list[Any] = []

    status_column = _model_column(InvestigationCase, "status")
    priority_column = _model_column(InvestigationCase, "priority")
    assignee_column = _model_column(InvestigationCase, "assignee_id")
    creator_column = _model_column(InvestigationCase, "creator_id")
    account_column = _model_column(InvestigationCase, "account_id")
    alert_column = _model_column(InvestigationCase, "alert_id")
    disposition_column = _model_column(InvestigationCase, "disposition")
    created_at_column = _model_column(InvestigationCase, "record_created_at")
    closed_at_column = _model_column(InvestigationCase, "closed_at")
    id_column = _model_column(InvestigationCase, "id")
    title_column = _model_column(InvestigationCase, "title")
    description_column = _model_column(InvestigationCase, "description")

    if status is not None and status_column is not None:
        conditions.append(status_column == status)

    if priority is not None and priority_column is not None:
        conditions.append(priority_column == priority)

    if assignee_id and assignee_column is not None:
        conditions.append(assignee_column == assignee_id.strip())

    if creator_id and creator_column is not None:
        conditions.append(creator_column == creator_id.strip())

    if account_id and account_column is not None:
        conditions.append(account_column == account_id.strip())

    if alert_id and alert_column is not None:
        conditions.append(alert_column == alert_id.strip())

    if disposition and disposition_column is not None:
        conditions.append(disposition_column == disposition.strip())

    if date_range.date_from is not None and created_at_column is not None:
        conditions.append(created_at_column >= date_range.date_from)

    if date_range.date_to is not None and created_at_column is not None:
        conditions.append(created_at_column <= date_range.date_to)

    if closed_from is not None and closed_at_column is not None:
        conditions.append(closed_at_column >= closed_from)

    if closed_to is not None and closed_at_column is not None:
        conditions.append(closed_at_column <= closed_to)

    if search is not None and search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (id_column, title_column, description_column, account_column, alert_column):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


def _build_case_event_conditions(
    *,
    case_id: str,
    action: Optional[str],
    actor_id: Optional[str],
    actor_username: Optional[str],
    resource_type: Optional[str],
    resource_id: Optional[str],
    date_range: DateRangeParams,
    search: Optional[SearchParams],
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for case event queries.
    """
    conditions: list[Any] = [_model_column(CaseEvent, "case_id") == case_id]

    action_column = _model_column(CaseEvent, "action")
    actor_id_column = _model_column(CaseEvent, "actor_id")
    actor_username_column = _model_column(CaseEvent, "actor_username")
    resource_type_column = _model_column(CaseEvent, "resource_type")
    resource_id_column = _model_column(CaseEvent, "resource_id")
    created_at_column = _model_column(CaseEvent, "created_at")
    summary_column = _model_column(CaseEvent, "summary")
    id_column = _model_column(CaseEvent, "id")

    if action and action_column is not None:
        conditions.append(action_column == action.strip())

    if actor_id and actor_id_column is not None:
        conditions.append(actor_id_column == actor_id.strip())

    if actor_username and actor_username_column is not None:
        conditions.append(actor_username_column == actor_username.strip())

    if resource_type and resource_type_column is not None:
        conditions.append(resource_type_column == resource_type.strip())

    if resource_id and resource_id_column is not None:
        conditions.append(resource_id_column == resource_id.strip())

    if date_range.date_from is not None and created_at_column is not None:
        conditions.append(created_at_column >= date_range.date_from)

    if date_range.date_to is not None and created_at_column is not None:
        conditions.append(created_at_column <= date_range.date_to)

    if search is not None and search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (id_column, action_column, actor_username_column, summary_column, resource_id_column):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


def _build_case_evidence_conditions(
    *,
    case_id: str,
    evidence_type: Optional[EvidenceType],
    include_inactive: bool,
    search: Optional[SearchParams],
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for case evidence queries.
    """
    conditions: list[Any] = [_model_column(CaseEvidence, "case_id") == case_id]

    evidence_type_column = _model_column(CaseEvidence, "evidence_type")
    evidence_id_column = _model_column(CaseEvidence, "evidence_id")
    active_column = _model_column(CaseEvidence, "is_active")
    id_column = _model_column(CaseEvidence, "id")

    if evidence_type is not None and evidence_type_column is not None:
        conditions.append(evidence_type_column == evidence_type)

    if active_column is not None and not include_inactive:
        conditions.append(active_column.is_(True))

    if search is not None and search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (id_column, evidence_id_column, evidence_type_column):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


def _build_case_audit_conditions(
    *,
    case_id: str,
    action: Optional[str],
    outcome: Optional[AuditOutcome],
    actor_username: Optional[str],
    date_range: DateRangeParams,
    search: Optional[SearchParams],
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for case audit queries.
    """
    resource_type_column = _model_column(AuditEvent, "resource_type")
    resource_id_column = _model_column(AuditEvent, "resource_id")
    action_column = _model_column(AuditEvent, "action")
    outcome_column = _model_column(AuditEvent, "outcome")
    actor_username_column = _model_column(AuditEvent, "actor_username")
    created_at_column = _model_column(AuditEvent, "created_at")
    id_column = _model_column(AuditEvent, "id")

    conditions: list[Any] = []

    if resource_type_column is not None:
        conditions.append(resource_type_column == "investigation_case")

    if resource_id_column is not None:
        conditions.append(resource_id_column == case_id)

    if action and action_column is not None:
        conditions.append(action_column == action.strip())

    if outcome is not None and outcome_column is not None:
        conditions.append(outcome_column == outcome)

    if actor_username and actor_username_column is not None:
        conditions.append(actor_username_column == actor_username.strip())

    if date_range.date_from is not None and created_at_column is not None:
        conditions.append(created_at_column >= date_range.date_from)

    if date_range.date_to is not None and created_at_column is not None:
        conditions.append(created_at_column <= date_range.date_to)

    if search is not None and search.q:
        pattern = f"%{search.q.lower()}%"
        search_columns: list[Any] = []

        for column in (id_column, action_column, actor_username_column, resource_id_column):
            if column is not None:
                search_columns.append(column)

        if search_columns:
            conditions.append(
                or_(*[func.lower(column).like(pattern) for column in search_columns])
            )

    return conditions


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List investigation cases",
    description=(
        "Returns a paginated, filtered, and stably ordered list of synthetic "
        "MULEGUARD investigation cases. Cases are human investigative workflow "
        "artefacts only and do not represent automatic enforcement."
    ),
)
def list_cases(
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(case_pagination),
    date_range: DateRangeParams = Depends(case_date_range),
    search: SearchParams = Depends(case_search),
    _: User = Depends(require_permission(Permission.CASE_READ)),
    status: Annotated[
        Optional[CaseStatus],
        Query(description="Filter by case status."),
    ] = None,
    priority: Annotated[
        Optional[Priority],
        Query(description="Filter by case priority."),
    ] = None,
    assignee_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by assigned local user."),
    ] = None,
    creator_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by creating local user."),
    ] = None,
    account_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by synthetic account."),
    ] = None,
    alert_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by originating synthetic alert."),
    ] = None,
    disposition: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by investigator-entered disposition."),
    ] = None,
    closed_from: Annotated[
        Optional[datetime],
        Query(description="Filter cases closed at or after this UTC timestamp."),
    ] = None,
    closed_to: Annotated[
        Optional[datetime],
        Query(description="Filter cases closed at or before this UTC timestamp."),
    ] = None,
    include_account: Annotated[
        bool,
        Query(description="Include bounded account summaries for returned cases."),
    ] = False,
    include_alert: Annotated[
        bool,
        Query(description="Include bounded alert summaries for returned cases."),
    ] = False,
) -> CaseListResponse:
    """
    List investigation cases with bounded pagination and safe filters.
    """
    _ensure_cases_enabled(settings)

    normalized_closed_from = _ensure_utc(closed_from)
    normalized_closed_to = _ensure_utc(closed_to)

    _validate_not_future(normalized_closed_to, "closed_to")
    _validate_date_range(
        normalized_closed_from,
        normalized_closed_to,
        "closed_from",
        "closed_to",
    )
    _validate_case_span(date_range.date_from, date_range.date_to, settings)
    _validate_case_span(normalized_closed_from, normalized_closed_to, settings)

    conditions = _build_case_conditions(
        status=status,
        priority=priority,
        assignee_id=assignee_id,
        creator_id=creator_id,
        account_id=account_id,
        alert_id=alert_id,
        disposition=disposition,
        date_range=date_range,
        closed_from=normalized_closed_from,
        closed_to=normalized_closed_to,
        search=search,
    )

    count_stmt = select(func.count()).select_from(InvestigationCase)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(InvestigationCase)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_CASE_COLUMN_MAP,
        tiebreaker=_CASE_TIEBREAKER,
        default_sort_by=_CASE_DEFAULT_SORT,
        default_sort_order="desc",
    )

    cases = db.scalars(stmt).all()

    account_map = (
        _load_accounts_by_ids(
            db,
            [_str_or_none(_get_if_exists(case, "account_id", None)) for case in cases],
        )
        if include_account
        else {}
    )

    alert_map = (
        _load_alerts_by_ids(
            db,
            [_str_or_none(_get_if_exists(case, "alert_id", None)) for case in cases],
        )
        if include_alert
        else {}
    )

    usernames = _username_map_for_user_ids(
        db,
        [
            _str_or_none(_get_if_exists(case, "assignee_id", None))
            for case in cases
        ]
        + [
            _str_or_none(_get_if_exists(case, "creator_id", None))
            for case in cases
        ],
    )

    items = [
        _case_response(
            case,
            account=account_map.get(str(_get_if_exists(case, "account_id", "")))
            if _get_if_exists(case, "account_id", None)
            else None,
            alert=alert_map.get(str(_get_if_exists(case, "alert_id", "")))
            if _get_if_exists(case, "alert_id", None)
            else None,
            assignee_username=usernames.get(
                str(_get_if_exists(case, "assignee_id", ""))
            )
            if _get_if_exists(case, "assignee_id", None)
            else None,
            creator_username=usernames.get(
                str(_get_if_exists(case, "creator_id", ""))
            )
            if _get_if_exists(case, "creator_id", None)
            else None,
        )
        for case in cases
    ]

    return CaseListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_CASE_CAVEATS),
    )


@router.post(
    "",
    response_model=CaseResponse,
    status_code=201,
    summary="Create an investigation case",
    description=(
        "Creates a synthetic MULEGUARD investigation case linked to a synthetic "
        "account and optionally an alert. This starts a human investigative "
        "workflow and does not take adverse action against accounts or customers."
    ),
)
def create_case(
    payload: CaseCreateRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_CREATE)),
) -> CaseResponse:
    """
    Create one investigation case.
    """
    _ensure_cases_enabled(settings)

    account: Optional[Account] = None
    alert: Optional[Alert] = None
    account_id = _str_or_none(payload.account_id)
    alert_id = _str_or_none(payload.alert_id)

    if alert_id:
        alert = db.get(Alert, alert_id)

        if alert is None:
            raise NotFoundError.resource("alert", alert_id)

        alert_account_id = _str_or_none(_get_if_exists(alert, "account_id", None))

        if not alert_account_id:
            raise ConflictError(
                "Referenced alert does not have an account_id.",
                details={"alert_id": alert_id},
            )

        if account_id and account_id != alert_account_id:
            raise ConflictError(
                "account_id does not match the referenced alert account.",
                details={
                    "account_id": account_id,
                    "alert_id": alert_id,
                    "alert_account_id": alert_account_id,
                },
            )

        account_id = alert_account_id

    if account_id:
        account = db.get(Account, account_id)

        if account is None:
            raise NotFoundError.resource("account", account_id)
    else:
        raise MuleGuardValidationError(
            "account_id or alert_id is required.",
            details={"fields": [{"field": "account_id", "type": "missing"}]},
        )

    assignee: Optional[User] = None
    assignee_id = _str_or_none(payload.assignee_id)

    if assignee_id:
        assignee = _validate_assignee(
            db,
            settings,
            assignee_id,
            field_name="assignee_id",
        )

    priority = payload.priority or _get_if_exists(alert, "priority", None) or Priority.MEDIUM

    title = payload.title or (
        str(_get_if_exists(alert, "title", "") or "")
        if alert is not None
        else f"Case for account {account_id}"
    )

    description = payload.description or (
        f"Investigation case created for synthetic account {account_id}."
        if alert is None
        else f"Investigation case created from alert {alert.id}."
    )

    metadata = _sanitize_input_mapping(payload.metadata_json)
    metadata.update(
        {
            "source": "alert" if alert_id else "manual",
            "account_id": account_id,
            "alert_id": alert_id,
            "created_by": str(actor.id),
            "request_id": request_id,
            "dataset_mode": str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")),
            "environment": str(_setting(settings, "BACKEND_ENV", "local")),
        }
    )

    case = _construct_model(
        InvestigationCase,
        {
            "title": _clean_text(title, _MAX_TITLE_LENGTH),
            "description": _clean_text(description, _MAX_DESCRIPTION_LENGTH),
            "status": STATUS_NEW,
            "priority": priority,
            "assignee_id": str(assignee.id) if assignee is not None else None,
            "creator_id": str(actor.id),
            "alert_id": alert_id,
            "account_id": account_id,
            "metadata_json": _safe_metadata(metadata),
        },
    )

    db.add(case)
    db.flush()

    _record_case_action(
        db,
        case=case,
        actor=actor,
        action="case_create",
        summary=f"Case created for account {account_id}.",
        metadata={
            "account_id": account_id,
            "alert_id": alert_id,
            "status": _case_current_status(case),
            "priority": _enum_str(_get_if_exists(case, "priority", None)),
            "assignee_id": str(assignee.id) if assignee is not None else None,
        },
        request=request,
        settings=settings,
        request_id=request_id,
        audit_action="case_create",
    )

    db.commit()
    db.refresh(case)

    return _hydrate_case_response(db, case)


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
    summary="Get an investigation case",
    description=(
        "Returns a safe detailed view for one synthetic MULEGUARD investigation "
        "case, including bounded evidence, events, and notes."
    ),
)
def get_case(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.CASE_READ)),
) -> CaseDetailResponse:
    """
    Retrieve one investigation case detail.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    return _case_detail_response(db, case, settings)


@router.patch(
    "/{case_id}",
    response_model=CaseResponse,
    summary="Update non-material case attributes",
    description=(
        "Updates title, description, priority, or safe metadata for one "
        "investigation case. Status and assignee changes must use dedicated "
        "workflow endpoints. Closed cases must be reopened before mutation."
    ),
)
def update_case(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    payload: CaseUpdateRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_UPDATE)),
) -> CaseResponse:
    """
    Update one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    _assert_case_open(case, "update")

    changes = payload.model_dump(exclude_unset=True)
    changed_fields: list[str] = []

    previous_priority = _enum_str(_get_if_exists(case, "priority", None))

    if "title" in changes:
        new_title = _clean_text(changes["title"], _MAX_TITLE_LENGTH)

        if str(_get_if_exists(case, "title", "")) != new_title:
            _set_if_exists(case, "title", new_title)
            changed_fields.append("title")

    if "description" in changes:
        raw_description = changes["description"]
        new_description = (
            _clean_text(raw_description, _MAX_DESCRIPTION_LENGTH)
            if raw_description is not None
            else None
        )

        if _get_if_exists(case, "description", None) != new_description:
            _set_if_exists(case, "description", new_description)
            changed_fields.append("description")

    if "priority" in changes:
        new_priority = changes["priority"]

        if _get_if_exists(case, "priority", None) != new_priority:
            _set_if_exists(case, "priority", new_priority)
            changed_fields.append("priority")

    if "metadata_json" in changes:
        new_metadata = _sanitize_input_mapping(changes["metadata_json"])

        if _get_if_exists(case, "metadata_json", None) != new_metadata:
            _set_if_exists(case, "metadata_json", new_metadata)
            changed_fields.append("metadata_json")

    if changed_fields:
        _set_if_exists(case, "updated_by", str(actor.id))

        _record_case_action(
            db,
            case=case,
            actor=actor,
            action="case_update",
            summary=f"Case updated: {', '.join(sorted(changed_fields))}.",
            metadata={
                "changed_fields": sorted(changed_fields),
                "previous_priority": previous_priority,
                "new_priority": _enum_str(_get_if_exists(case, "priority", None)),
            },
            request=request,
            settings=settings,
            request_id=request_id,
            audit_action="case_update",
        )

        db.commit()
        db.refresh(case)

    return _hydrate_case_response(db, case)


@router.post(
    "/{case_id}/assign",
    response_model=CaseAssignResponse,
    summary="Assign an investigation case",
    description=(
        "Assigns a synthetic investigation case to an active, permitted local "
        "prototype user. Assignment is a human workflow action, not an "
        "enforcement action."
    ),
)
def assign_case(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    payload: CaseAssignRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_ASSIGN)),
) -> CaseAssignResponse:
    """
    Assign one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    _assert_case_open(case, "assign")

    assignee = _validate_assignee(
        db,
        settings,
        payload.assignee_id,
        field_name="assignee_id",
    )

    previous_status = _case_current_status(case)
    previous_assignee = _str_or_none(_get_if_exists(case, "assignee_id", None))
    new_assignee = str(assignee.id)

    changed = False

    if previous_assignee != new_assignee:
        _set_if_exists(case, "assignee_id", new_assignee)
        changed = True

    if previous_status == _STATUS_NEW:
        # Assignment triages a new case; it does not start the investigation.
        # `triage` is the machine's NEW → TRIAGED transition, and the
        # distinction is the point of having TRIAGED: a case with an owner who
        # has not begun is not the same as one being worked.
        _assert_transition(
            case,
            STATUS_TRIAGED,
            "assign",
            assignee_id=new_assignee,
        )
        _set_case_status(case, STATUS_TRIAGED, actor)
        changed = True

    new_status = _case_current_status(case)

    if changed:
        _record_case_action(
            db,
            case=case,
            actor=actor,
            action="case_assign",
            summary=f"Case assigned to {assignee.username}.",
            metadata={
                "previous_assignee_id": previous_assignee,
                "new_assignee_id": new_assignee,
                "assignee_role": _enum_str(assignee.role),
                "previous_status": previous_status,
                "new_status": new_status,
                **_text_audit_metadata(payload.note, field_name="note"),
            },
            request=request,
            settings=settings,
            request_id=request_id,
            audit_action="case_assign",
        )

        db.commit()
        db.refresh(case)

    return CaseAssignResponse(
        case=_hydrate_case_response(db, case),
        changed=changed,
        previous_assignee_id=previous_assignee,
        new_assignee_id=new_assignee if changed else previous_assignee,
        previous_status=previous_status,
        new_status=new_status,
        audited=changed,
        caveats=list(_CASE_CAVEATS),
    )


@router.post(
    "/{case_id}/start",
    response_model=CaseActionResponse,
    summary="Start reviewing an investigation case",
    description=(
        "Moves a new or escalated case into under-review state. This is a human "
        "workflow action, not an enforcement action."
    ),
)
def start_case(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_UPDATE)),
) -> CaseActionResponse:
    """
    Start one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    previous_status = _case_current_status(case)

    if previous_status == _STATUS_UNDER_INVESTIGATION:
        return CaseActionResponse(
            case=_hydrate_case_response(db, case),
            changed=False,
            previous_status=previous_status,
            new_status=previous_status,
            audited=False,
            caveats=list(_CASE_CAVEATS),
        )

    if previous_status not in {_STATUS_NEW, _STATUS_TRIAGED}:
        raise ConflictError(
            "Only new or triaged cases can be started.",
            details={
                "case_id": str(case.id),
                "status": previous_status,
                "hint": (
                    "An escalated case returns to investigation through "
                    "de-escalation, which records a reason."
                    if previous_status == _STATUS_ESCALATED
                    else None
                ),
            },
        )

    # `start` carries `requires_assignee=True`. A case in
    # UNDER_INVESTIGATION that nobody owns is the state a case goes to die
    # in: it counts as active everywhere and nobody is looking at it.
    assignee_id = _str_or_none(_get_if_exists(case, "assignee_id", None))

    _assert_transition(
        case,
        STATUS_UNDER_INVESTIGATION,
        "start",
        assignee_id=assignee_id,
    )
    _set_case_status(case, STATUS_UNDER_INVESTIGATION, actor)
    new_status = _case_current_status(case)

    _record_case_action(
        db,
        case=case,
        actor=actor,
        action="case_start",
        summary="Case moved to under investigation.",
        metadata={
            "previous_status": previous_status,
            "new_status": new_status,
        },
        request=request,
        settings=settings,
        request_id=request_id,
        audit_action="case_start",
    )

    db.commit()
    db.refresh(case)

    return CaseActionResponse(
        case=_hydrate_case_response(db, case),
        changed=True,
        previous_status=previous_status,
        new_status=new_status,
        audited=True,
        caveats=list(_CASE_CAVEATS),
    )


@router.post(
    "/{case_id}/escalate",
    response_model=CaseActionResponse,
    summary="Escalate an investigation case",
    description=(
        "Escalates a synthetic investigation case for senior review. This is a "
        "human workflow action, not an enforcement action."
    ),
)
def escalate_case(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    payload: CaseEscalateRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_UPDATE)),
) -> CaseActionResponse:
    """
    Escalate one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    previous_status = _case_current_status(case)

    if previous_status == _STATUS_ESCALATED:
        return CaseActionResponse(
            case=_hydrate_case_response(db, case),
            changed=False,
            previous_status=previous_status,
            new_status=previous_status,
            audited=False,
            caveats=list(_CASE_CAVEATS),
        )

    _assert_case_open(case, "escalate")
    _assert_transition(case, STATUS_ESCALATED, "escalate", reason=payload.reason)
    _set_case_status(case, STATUS_ESCALATED, actor)
    new_status = _case_current_status(case)

    _record_case_action(
        db,
        case=case,
        actor=actor,
        action="case_escalate",
        summary="Case escalated for senior review.",
        metadata={
            "previous_status": previous_status,
            "new_status": new_status,
            **_text_audit_metadata(payload.reason, field_name="reason"),
        },
        request=request,
        settings=settings,
        request_id=request_id,
        audit_action="case_escalate",
    )

    db.commit()
    db.refresh(case)

    return CaseActionResponse(
        case=_hydrate_case_response(db, case),
        changed=True,
        previous_status=previous_status,
        new_status=new_status,
        audited=True,
        caveats=list(_CASE_CAVEATS),
    )


@router.post(
    "/{case_id}/close",
    response_model=CaseActionResponse,
    summary="Close an investigation case",
    description=(
        "Closes a synthetic investigation case as a human investigative decision. "
        "This does not close, freeze, block, blacklist, or restrict any account. "
        "Dispositions are investigator-entered assessments, not automatic "
        "conclusions."
    ),
)
def close_case(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    payload: CaseCloseRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_CLOSE)),
) -> CaseActionResponse:
    """
    Close one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    previous_status = _case_current_status(case)
    disposition = _validate_disposition(payload.disposition, settings)

    if disposition is None:
        # The field is required and non-empty, so this is a label that
        # canonicalized to nothing — punctuation only, say.
        raise MuleGuardValidationError(
            "Disposition could not be interpreted.",
            details={
                "disposition": payload.disposition,
                "allowed_dispositions": sorted(_case_dispositions(settings)),
            },
        )

    if previous_status == _STATUS_CLOSED:
        return CaseActionResponse(
            case=_hydrate_case_response(db, case),
            changed=False,
            previous_status=previous_status,
            new_status=previous_status,
            audited=False,
            caveats=[
                *_CASE_CAVEATS,
                "Closure reason is recorded in case history only when a change occurs.",
            ],
        )

    _assert_transition(
        case,
        STATUS_CLOSED,
        "close",
        disposition=disposition,
        reason=payload.reason,
    )

    now = _now_utc()
    previous_disposition = _enum_str(_get_if_exists(case, "disposition", None)) or _str_or_none(
        _get_if_exists(case, "disposition", None)
    )

    _set_case_status(case, STATUS_CLOSED, actor)
    _set_if_exists(case, "closed_at", now)

    _set_if_exists(case, "disposition", disposition)

    new_status = _case_current_status(case)

    _record_case_action(
        db,
        case=case,
        actor=actor,
        action="case_close",
        summary=f"Case closed. Disposition: {disposition}.",
        metadata={
            "previous_status": previous_status,
            "new_status": new_status,
            "previous_disposition": previous_disposition,
            "new_disposition": disposition,
            "closed_at": now.isoformat(),
            **_text_audit_metadata(payload.reason, field_name="reason"),
        },
        request=request,
        settings=settings,
        request_id=request_id,
        audit_action="case_close",
    )

    db.commit()
    db.refresh(case)

    return CaseActionResponse(
        case=_hydrate_case_response(db, case),
        changed=True,
        previous_status=previous_status,
        new_status=new_status,
        audited=True,
        caveats=[
            *_CASE_CAVEATS,
            "Closing a case does not close, freeze, block, blacklist, or restrict any account.",
            "Dispositions are investigator-entered assessments, not automatic conclusions.",
        ],
    )


@router.post(
    "/{case_id}/reopen",
    response_model=CaseActionResponse,
    summary="Reopen a closed investigation case",
    description=(
        "Reopens a closed synthetic investigation case for further human review. "
        "This does not take adverse action against any account."
    ),
)
def reopen_case(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    payload: CaseReopenRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_REOPEN)),
) -> CaseActionResponse:
    """
    Reopen one closed investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    previous_status = _case_current_status(case)

    if previous_status != _STATUS_CLOSED:
        raise ConflictError(
            "Only closed cases can be reopened.",
            details={
                "case_id": str(case.id),
                "status": previous_status,
            },
        )

    _assert_transition(
        case,
        STATUS_UNDER_INVESTIGATION,
        "reopen",
        reason=payload.reason,
    )
    _set_case_status(case, STATUS_UNDER_INVESTIGATION, actor)
    
    # Clear closed_at and disposition upon reopening to indicate active work
    _set_if_exists(case, "closed_at", None)
    _set_if_exists(case, "disposition", None)

    new_status = _case_current_status(case)

    _record_case_action(
        db,
        case=case,
        actor=actor,
        action="case_reopen",
        summary="Case reopened for further review.",
        metadata={
            "previous_status": previous_status,
            "new_status": new_status,
            **_text_audit_metadata(payload.reason, field_name="reason"),
        },
        request=request,
        settings=settings,
        request_id=request_id,
        audit_action="case_reopen",
    )

    db.commit()
    db.refresh(case)

    return CaseActionResponse(
        case=_hydrate_case_response(db, case),
        changed=True,
        previous_status=previous_status,
        new_status=new_status,
        audited=True,
        caveats=list(_CASE_CAVEATS),
    )


@router.get(
    "/{case_id}/notes",
    response_model=CaseEventListResponse,
    summary="List notes for an investigation case",
    description=(
        "Returns paginated append-only investigator notes for one synthetic "
        "MULEGUARD investigation case."
    ),
)
def list_case_notes(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(event_pagination),
    search: SearchParams = Depends(event_search),
    _: User = Depends(require_permission(Permission.CASE_READ)),
    actor_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter notes by author user ID."),
    ] = None,
) -> CaseEventListResponse:
    """
    List notes for one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    case_id = str(case.id)

    conditions = _build_case_event_conditions(
        case_id=case_id,
        action=_NOTE_ACTION,
        actor_id=actor_id,
        actor_username=None,
        resource_type=None,
        resource_id=None,
        date_range=DateRangeParams(date_from=None, date_to=None),
        search=search,
    )

    count_stmt = select(func.count()).select_from(CaseEvent)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(CaseEvent)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_EVENT_COLUMN_MAP,
        tiebreaker=_EVENT_TIEBREAKER,
        default_sort_by=_EVENT_DEFAULT_SORT,
        default_sort_order="desc",
    )

    events = db.scalars(stmt).all()

    return CaseEventListResponse(
        items=[_event_response(event) for event in events],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_EVENT_CAVEATS),
    )


@router.post(
    "/{case_id}/notes",
    response_model=CaseNoteResponse,
    status_code=201,
    summary="Add a note to an investigation case",
    description=(
        "Appends a safe investigator note to one synthetic MULEGUARD investigation "
        "case. Notes are append-only and do not modify case state directly."
    ),
)
def add_case_note(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    payload: CaseNoteRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_NOTE_ADD)),
) -> CaseNoteResponse:
    """
    Add one note to an investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    _assert_case_open(case, "add a note to")

    note_text = _clean_text(payload.note, _MAX_NOTE_LENGTH)
    
    event = _record_case_action(
        db,
        case=case,
        actor=actor,
        action=_NOTE_ACTION,
        summary=note_text,
        metadata={
            "note_length": len(note_text),
            "note_sha256": _sha256_text(note_text),
        },
        request=request,
        settings=settings,
        request_id=request_id,
        audit_action="case_note_add",
    )

    db.commit()
    db.refresh(event)

    return CaseNoteResponse(
        note=_event_response(event),
        case=_hydrate_case_response(db, case),
        audited=True,
        caveats=list(_EVENT_CAVEATS),
    )


@router.get(
    "/{case_id}/evidence",
    response_model=CaseEvidenceListResponse,
    summary="List evidence for an investigation case",
    description=(
        "Returns paginated evidence references attached to one synthetic "
        "MULEGUARD investigation case. Evidence must point to validated "
        "persisted records."
    ),
)
def list_case_evidence(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(evidence_pagination),
    search: SearchParams = Depends(evidence_search),
    _: User = Depends(require_permission(Permission.CASE_READ)),
    evidence_type: Annotated[
        Optional[EvidenceType],
        Query(description="Filter by evidence type."),
    ] = None,
    include_inactive: Annotated[
        bool,
        Query(description="Include deactivated evidence references."),
    ] = False,
) -> CaseEvidenceListResponse:
    """
    List evidence for one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    case_id = str(case.id)

    conditions = _build_case_evidence_conditions(
        case_id=case_id,
        evidence_type=evidence_type,
        include_inactive=include_inactive,
        search=search,
    )

    count_stmt = select(func.count()).select_from(CaseEvidence)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(CaseEvidence)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_EVIDENCE_COLUMN_MAP,
        tiebreaker=_EVIDENCE_TIEBREAKER,
        default_sort_by=_EVIDENCE_DEFAULT_SORT,
        default_sort_order="desc",
    )

    evidences = db.scalars(stmt).all()

    usernames = _username_map_for_user_ids(
        db,
        [
            *(_str_or_none(_get_if_exists(ev, "added_by", None)) for ev in evidences),
            *(_str_or_none(_get_if_exists(ev, "removed_by", None)) for ev in evidences),
        ],
    )

    items = [
        _evidence_response(
            ev,
            added_by_username=usernames.get(str(_get_if_exists(ev, "added_by", "")))
            if _get_if_exists(ev, "added_by", None)
            else None,
            removed_by_username=usernames.get(
                str(_get_if_exists(ev, "removed_by", ""))
            )
            if _get_if_exists(ev, "removed_by", None)
            else None,
        )
        for ev in evidences
    ]

    return CaseEvidenceListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_EVIDENCE_CAVEATS),
    )


@router.post(
    "/{case_id}/evidence",
    response_model=CaseEvidenceActionResponse,
    status_code=201,
    summary="Attach evidence to an investigation case",
    description=(
        "Attaches a validated persisted record as evidence to one synthetic "
        "MULEGUARD investigation case. Graph path evidence must be generated "
        "by the bounded graph service and cannot be manually attached here."
    ),
)
def add_case_evidence(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    payload: CaseEvidenceCreateRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_EVIDENCE_ADD)),
) -> CaseEvidenceActionResponse:
    """
    Attach evidence to one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    _assert_case_open(case, "attach evidence to")

    evidence_id = payload.evidence_id.strip()
    evidence_type = payload.evidence_type

    snapshot = _validate_evidence_reference(
        db=db,
        case=case,
        evidence_type=evidence_type,
        evidence_id=evidence_id,
    )

    existing_id = _existing_active_case_evidence(
        db,
        str(case.id),
        evidence_type,
        evidence_id,
    )

    if existing_id is not None:
        raise ConflictError(
            "This evidence reference is already attached to the case.",
            details={
                "case_id": str(case.id),
                "evidence_type": _enum_str(evidence_type),
                "evidence_id": evidence_id,
                "existing_evidence_id": existing_id,
            },
        )

    provided_snapshot = (
        _sanitize_json_object(payload.evidence_snapshot_json)
        if isinstance(payload.evidence_snapshot_json, Mapping)
        else None
    )

    final_snapshot = provided_snapshot or snapshot

    provenance = {
        "source": "manual_api",
        "actor_id": str(actor.id),
        "actor_role": _enum_str(actor.role),
        "request_id": request_id,
    }

    if isinstance(payload.provenance_json, Mapping):
        provenance.update(_sanitize_json_object(payload.provenance_json))

    evidence = _construct_model(
        CaseEvidence,
        {
            "case_id": str(case.id),
            "evidence_type": evidence_type,
            "evidence_id": evidence_id,
            "evidence_snapshot_json": final_snapshot,
            "provenance_json": _sanitize_json_object(provenance),
            "added_by": str(actor.id),
            "is_active": True,
        },
    )

    db.add(evidence)
    db.flush()

    _record_case_action(
        db,
        case=case,
        actor=actor,
        action=_EVIDENCE_ADD_ACTION,
        summary=f"Evidence attached: {_enum_str(evidence_type)} {evidence_id}",
        metadata={
            "evidence_type": _enum_str(evidence_type),
            "evidence_id": evidence_id,
            "case_id": str(case.id),
        },
        request=request,
        settings=settings,
        request_id=request_id,
        audit_action="case_evidence_add",
    )

    db.commit()
    db.refresh(evidence)

    usernames = _username_map_for_user_ids(db, [evidence.added_by])

    return CaseEvidenceActionResponse(
        evidence=_evidence_response(
            evidence,
            added_by_username=usernames.get(str(evidence.added_by))
            if evidence.added_by
            else None,
        ),
        case=_hydrate_case_response(db, case),
        changed=True,
        audited=True,
        caveats=list(_EVIDENCE_CAVEATS),
    )


@router.post(
    "/{case_id}/evidence/{evidence_id}/remove",
    response_model=CaseEvidenceRemoveResponse,
    summary="Deactivate a case evidence reference",
    description=(
        "Marks a case evidence reference as inactive. This does not delete the "
        "underlying record or remove it from audit history."
    ),
)
def remove_case_evidence(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    evidence_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Case evidence identifier."),
    ],
    payload: CaseEvidenceRemoveRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.CASE_EVIDENCE_REMOVE)),
) -> CaseEvidenceRemoveResponse:
    """
    Deactivate one case evidence reference.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    _assert_case_open(case, "remove evidence from")

    evidence = db.get(CaseEvidence, evidence_id)

    if evidence is None or str(_get_if_exists(evidence, "case_id", "")) != str(case.id):
        raise NotFoundError.resource("case_evidence", evidence_id)

    if not _get_if_exists(evidence, "is_active", True):
        return CaseEvidenceRemoveResponse(
            evidence=_evidence_response(evidence),
            case=_hydrate_case_response(db, case),
            changed=False,
            audited=False,
            caveats=list(_EVIDENCE_CAVEATS),
        )

    reason = _clean_text(payload.reason, _MAX_REASON_LENGTH)

    _set_if_exists(evidence, "is_active", False)
    _set_if_exists(evidence, "removed_by", str(actor.id))
    _set_if_exists(evidence, "removed_at", _now_utc())
    # The reason is the point of recording the removal. "Evidence withdrawn"
    # with nothing saying why tells a reviewer that something was taken out
    # and nothing about whether that was right. The column existed and was
    # never written, because the endpoint accepted no body at all.
    _set_if_exists(evidence, "removal_reason", reason)

    _record_case_action(
        db,
        case=case,
        actor=actor,
        action=_EVIDENCE_REMOVE_ACTION,
        summary=f"Evidence deactivated: {_enum_str(_get_if_exists(evidence, 'evidence_type', None))} {_get_if_exists(evidence, 'evidence_id', '')}",
        metadata={
            "evidence_type": _enum_str(_get_if_exists(evidence, "evidence_type", None)),
            "evidence_id": _str_or_none(_get_if_exists(evidence, "evidence_id", None)),
            "case_id": str(case.id),
            "case_evidence_id": str(evidence.id),
            "removal_reason": reason,
        },
        request=request,
        settings=settings,
        request_id=request_id,
        audit_action="case_evidence_remove",
    )

    db.commit()
    db.refresh(evidence)

    usernames = _username_map_for_user_ids(
        db,
        [
            _str_or_none(_get_if_exists(evidence, "added_by", None)),
            _str_or_none(_get_if_exists(evidence, "removed_by", None)),
        ],
    )

    return CaseEvidenceRemoveResponse(
        evidence=_evidence_response(
            evidence,
            added_by_username=usernames.get(
                str(_get_if_exists(evidence, "added_by", ""))
            )
            if _get_if_exists(evidence, "added_by", None)
            else None,
            removed_by_username=usernames.get(
                str(_get_if_exists(evidence, "removed_by", ""))
            )
            if _get_if_exists(evidence, "removed_by", None)
            else None,
        ),
        case=_hydrate_case_response(db, case),
        changed=True,
        audited=True,
        caveats=list(_EVIDENCE_CAVEATS),
    )


@router.get(
    "/{case_id}/events",
    response_model=CaseEventListResponse,
    summary="List events for an investigation case",
    description=(
        "Returns paginated append-only workflow events for one synthetic "
        "MULEGUARD investigation case."
    ),
)
def list_case_events(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(event_pagination),
    search: SearchParams = Depends(event_search),
    _: User = Depends(require_permission(Permission.CASE_READ)),
    action: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by event action."),
    ] = None,
    actor_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by actor user ID."),
    ] = None,
) -> CaseEventListResponse:
    """
    List events for one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    case_id = str(case.id)

    conditions = _build_case_event_conditions(
        case_id=case_id,
        action=action,
        actor_id=actor_id,
        actor_username=None,
        resource_type=None,
        resource_id=None,
        date_range=DateRangeParams(date_from=None, date_to=None),
        search=search,
    )

    count_stmt = select(func.count()).select_from(CaseEvent)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(CaseEvent)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_EVENT_COLUMN_MAP,
        tiebreaker=_EVENT_TIEBREAKER,
        default_sort_by=_EVENT_DEFAULT_SORT,
        default_sort_order="desc",
    )

    events = db.scalars(stmt).all()

    return CaseEventListResponse(
        items=[_event_response(event) for event in events],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_EVENT_CAVEATS),
    )


@router.get(
    "/{case_id}/audit",
    response_model=CaseAuditListResponse,
    summary="List audit history for an investigation case",
    description=(
        "Returns paginated safe audit history for one synthetic MULEGUARD "
        "investigation case."
    ),
)
def list_case_audit(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(audit_pagination),
    search: SearchParams = Depends(case_search),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
    action: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audit action."),
    ] = None,
    outcome: Annotated[
        Optional[AuditOutcome],
        Query(description="Filter by audit outcome."),
    ] = None,
) -> CaseAuditListResponse:
    """
    List audit history for one investigation case.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    case_id = str(case.id)

    conditions = _build_case_audit_conditions(
        case_id=case_id,
        action=action,
        outcome=outcome,
        actor_username=None,
        date_range=DateRangeParams(date_from=None, date_to=None),
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

    return CaseAuditListResponse(
        items=[_audit_event_response(event) for event in events],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_AUDIT_CAVEATS),
    )


@router.get(
    "/{case_id}/export",
    response_model=CaseExportBundleResponse,
    summary="Export a bounded case bundle",
    description=(
        "Returns a bounded JSON export bundle for one synthetic MULEGUARD "
        "investigation case, including sanitized evidence, events, and notes."
    ),
)
def export_case_bundle(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.CASE_READ)),
    include_inactive_evidence: Annotated[
        bool,
        Query(description="Include deactivated evidence references in the bundle."),
    ] = False,
) -> CaseExportBundleResponse:
    """
    Export one case bundle.
    """
    _ensure_cases_enabled(settings)

    case = _get_case_or_404(db, case_id)
    case_id = str(case.id)

    limit = _case_export_max_items(settings)

    evidences, evidence_total = _load_case_evidence(
        db,
        case_id,
        limit=limit,
        include_inactive=include_inactive_evidence,
    )
    events, event_total = _load_case_events(db, case_id, limit=limit)
    notes, note_total = _load_case_notes(db, case_id, limit=limit)

    return CaseExportBundleResponse(
        case=_hydrate_case_response(db, case),
        evidences=evidences,
        events=events,
        notes=notes,
        evidence_total=evidence_total,
        evidence_truncated=evidence_total > len(evidences),
        event_total=event_total,
        event_truncated=event_total > len(events),
        note_total=note_total,
        note_truncated=note_total > len(notes),
        max_items=limit,
        caveats=list(_EXPORT_CAVEATS),
    )


__all__ = [
    "router",
]