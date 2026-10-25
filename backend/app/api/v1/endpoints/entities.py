"""
MULEGUARD backend API v1 entity endpoints.

This module implements the versioned `/api/v1/entities` read-mostly
investigation surface for synthetic MULEGUARD pseudonymous entities and
time-bound account-entity links.

Implemented endpoints:

- GET   /api/v1/entities
- GET   /api/v1/entities/{entity_id}
- GET   /api/v1/entities/{entity_id}/accounts
- PATCH /api/v1/entities/{entity_id}/links/{link_id}/verification-state
- GET   /api/v1/entities/{entity_id}/complaint-correlations
- GET   /api/v1/entities/{entity_id}/alerts

Design goals:

- provide real, persisted, evidence-backed entity and link views;
- enforce server-side RBAC through dependency permissions;
- keep list endpoints paginated, filtered, searched, and stably ordered;
- expose only safe pseudonymous entity metadata;
- never return raw identifier hashes, secrets, tokens, passwords, database
  URLs, raw complaint narratives, synthetic ground-truth labels, scenario IDs,
  ring IDs, or real customer data;
- preserve match-method, confidence, verification-state, and temporal validity
  provenance for account-entity links;
- allow authorised investigators to update link verification state with durable
  audit records;
- make clear that shared entities and graph-derived associations are
  investigative leads only.

Explicit non-goals:

- This module does not create, delete, freeze, block, blacklist, close, or
  otherwise take adverse action against accounts or entities.
- This module does not expose real bank customer data.
- This module does not compute new ML scores inline.
- This module does not treat shared devices, phones, UPI IDs, emails, addresses,
  or IPs as proof of common control or wrongdoing.
- This module does not return raw complaint narratives.
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
import logging
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Final, Optional

from fastapi import APIRouter, Depends, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, case, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    PageParams,
    Permission,
    RequestIDDep,
    SearchParams,
    SessionDep,
    SettingsDep,
    apply_pagination,
    pagination_dependency,
    require_permission,
    require_roles,
    search_dependency,
)
from app.exceptions import (
    FeatureFlagDisabledError,
    NotFoundError,
    ValidationError as MuleGuardValidationError,
)
from app.models import (
    Account,
    AccountEntityLink,
    AccountStatus,
    AccountType,
    Alert,
    AlertEvidence,
    AlertState,
    Complaint,
    ComplaintCorrelation,
    ComplaintReviewState,
    Entity,
    EntityType,
    EvidenceType,
    MatchMethod,
    Priority,
    User,
    UserRole,
    VerificationState,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.entities")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["entities"])


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_NOTE_LENGTH: Final[int] = 1000
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_EVIDENCE_REFS: Final[int] = 200
_MAX_JSON_DEPTH: Final[int] = 6

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

_ENTITY_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Entities are pseudonymous synthetic associations such as devices, hashed phones, UPI IDs, emails, addresses, or IPs.",
    "Shared entities are investigative associations only and are not proof of common control or wrongdoing.",
    "Raw identifier hashes are intentionally not returned.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    "Entity links and graph-derived signals must not trigger automatic adverse customer action.",
)

_LINK_CAVEATS: Final[tuple[str, ...]] = (
    *_ENTITY_CAVEATS,
    "Account-entity links are time-bound and must be interpreted using match method, confidence, verification state, and validity window.",
    "Inferred links are not verified facts.",
)

_COMPLAINT_CAVEATS: Final[tuple[str, ...]] = (
    *_ENTITY_CAVEATS,
    "Complaint correlations are investigative leads only.",
    "Raw and normalized complaint narratives are intentionally not returned.",
    "Exact matches are distinguished from inferred associations through match tier, method, determinism, and confidence.",
)

_ALERT_CAVEATS: Final[tuple[str, ...]] = (
    *_ENTITY_CAVEATS,
    "Alerts are investigative leads only.",
    "Alert evidence references must be reviewed by an authorised investigator.",
)

_UPDATE_CAVEATS: Final[tuple[str, ...]] = (
    *_LINK_CAVEATS,
    "Verification-state updates are investigator judgements, not automatic enforcement actions.",
    "This endpoint does not freeze, block, blacklist, close, or otherwise take adverse action against any account.",
)


# -----------------------------------------------------------------------------
# Column maps for stable pagination
# -----------------------------------------------------------------------------

_ENTITY_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": Entity.id,
    "created_at": Entity.record_created_at,
    "updated_at": Entity.record_updated_at,
    "first_seen_at": Entity.first_seen_at,
    "last_seen_at": Entity.last_seen_at,
    "entity_type": Entity.entity_type,
    "source": Entity.source,
}

_LINK_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": AccountEntityLink.id,
    "account_id": AccountEntityLink.account_id,
    "entity_id": AccountEntityLink.entity_id,
    "valid_from": AccountEntityLink.valid_from,
    "valid_to": AccountEntityLink.valid_to,
    "created_at": AccountEntityLink.record_created_at,
    "updated_at": AccountEntityLink.record_updated_at,
    "confidence": AccountEntityLink.confidence,
    "match_method": AccountEntityLink.match_method,
    "verification_state": AccountEntityLink.verification_state,
}

_CORRELATION_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": ComplaintCorrelation.id,
    "created_at": ComplaintCorrelation.record_created_at,
    "match_tier": ComplaintCorrelation.match_tier,
    "confidence": ComplaintCorrelation.confidence,
    "review_state": ComplaintCorrelation.review_state,
}

_ALERT_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": Alert.id,
    "created_at": Alert.record_created_at,
    "priority": Alert.priority,
    "score": Alert.score,
    "state": Alert.state,
    "first_seen_at": Alert.first_seen_at,
    "last_seen_at": Alert.last_seen_at,
}


# -----------------------------------------------------------------------------
# Reusable bounded dependencies
# -----------------------------------------------------------------------------

entity_pagination = pagination_dependency(
    sortable_fields=tuple(_ENTITY_COLUMN_MAP.keys()),
    default_sort_by="created_at",
    default_sort_order="desc",
)

link_pagination = pagination_dependency(
    sortable_fields=tuple(_LINK_COLUMN_MAP.keys()),
    default_sort_by="valid_from",
    default_sort_order="desc",
)

correlation_pagination = pagination_dependency(
    sortable_fields=tuple(_CORRELATION_COLUMN_MAP.keys()),
    default_sort_by="created_at",
    default_sort_order="desc",
)

alert_pagination = pagination_dependency(
    sortable_fields=tuple(_ALERT_COLUMN_MAP.keys()),
    default_sort_by="created_at",
    default_sort_order="desc",
)

entity_search = search_dependency(max_length=200, alias="q")
link_search = search_dependency(max_length=200, alias="q")
correlation_search = search_dependency(max_length=200, alias="q")


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


def _safe_string_list(value: Any, *, max_items: int = _MAX_EVIDENCE_REFS) -> list[str]:
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


def _sanitize_json_value(value: Any, depth: int = 0) -> Any:
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
        return _sanitize_json_value(value.value, depth + 1)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        return _sanitize_json_object(value, depth + 1)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = [_sanitize_json_value(item, depth + 1) for item in list(value)[:_MAX_LIST_LENGTH]]

        if len(value) > _MAX_LIST_LENGTH:
            items.append({"_truncated": True})

        return items

    return f"<{type(value).__name__}>"


def _sanitize_json_object(value: Mapping[Any, Any], depth: int = 0) -> dict[str, Any]:
    """
    Return a sanitized JSON object suitable for API responses.
    """
    if depth > _MAX_JSON_DEPTH:
        return {"_truncated": True}

    sanitized: dict[str, Any] = {}

    for raw_key, raw_value in list(value.items())[:_MAX_LIST_LENGTH]:
        key = str(raw_key)

        if _is_sensitive_key(key):
            continue

        sanitized[key] = _sanitize_json_value(raw_value, depth + 1)

        if len(sanitized) >= _MAX_LIST_LENGTH:
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


def _ensure_entities_enabled(settings: Any) -> None:
    """
    Fail closed when the entity API surface is disabled by configuration.
    """
    graph_enabled = _as_bool(_setting(settings, "GRAPH_ENABLED", True), True)
    entities_enabled = _as_bool(
        _setting(settings, "ENTITIES_API_ENABLED", graph_enabled),
        graph_enabled,
    )

    if not entities_enabled:
        raise FeatureFlagDisabledError(
            "Entity endpoints are disabled by configuration."
        )


def _normalize_source(value: Optional[str]) -> Optional[str]:
    """
    Normalize an optional source filter.
    """
    if value is None:
        return None

    normalized = str(value).strip()

    if not normalized:
        return None

    if len(normalized) > 100:
        raise MuleGuardValidationError(
            "Source filter is too long.",
            details={"source": normalized[:100]},
        )

    return normalized


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
        or "muleguard-entities"
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
    mode = str(
        _setting(settings, "PRIVACY_IP_LOG_MODE", "hashed")
    ).strip().lower()

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


def _audit_note_metadata(note: Optional[str]) -> dict[str, Any]:
    """
    Return safe audit metadata for an optional investigator note.

    The note is truncated and flattened. Deployments should instruct
    investigators not to place secrets, tokens, passwords, or unnecessary
    sensitive narrative text in notes.
    """
    if not note:
        return {}

    cleaned = _clean_text(note, 200)

    return {
        "note_length": len(note),
        "note_excerpt": cleaned,
    }


def _add_audit_event(
    db: Session,
    *,
    action: str,
    outcome: str,
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
    from app.models import AuditEvent, AuditOutcome

    event = AuditEvent(
        actor_id=str(actor.id) if actor is not None else None,
        actor_username=str(actor.username) if actor is not None else None,
        actor_role=_enum_str(actor.role) if actor is not None else None,
        action=str(action)[:100],
        resource_type=str(resource_type)[:100] if resource_type is not None else None,
        resource_id=str(resource_id)[:128] if resource_id is not None else None,
        outcome=AuditOutcome(outcome),
        request_id=str(request_id)[:64] if request_id is not None else None,
        ip_hash=ip_hash,
        metadata_json=_safe_metadata(metadata),
    )

    db.add(event)


# -----------------------------------------------------------------------------
# Entity display helpers
# -----------------------------------------------------------------------------


def _entity_display_label(entity: Entity) -> str:
    """
    Return a safe display label for an entity.

    Raw identifier hashes are never returned.
    """
    raw_display = getattr(entity, "identifier_display", None)

    if raw_display:
        return _clean_text(raw_display, 200)

    entity_type = (_enum_str(entity.entity_type) or "ENTITY").lower()
    short_id = str(entity.id)[:8]

    return f"{entity_type}-entity-{short_id}"


# -----------------------------------------------------------------------------
# Link count helpers
# -----------------------------------------------------------------------------


def _link_counts_for_entity_ids(
    db: Session,
    entity_ids: Sequence[str],
    *,
    as_of: Optional[datetime] = None,
) -> dict[str, dict[str, int]]:
    """
    Return bounded account-entity link counts for a set of entity IDs.
    """
    ids = [str(entity_id) for entity_id in entity_ids if entity_id]

    if not ids:
        return {}

    normalized_as_of = _ensure_utc(as_of)

    if normalized_as_of is None:
        active_condition = AccountEntityLink.valid_to.is_(None)
    else:
        active_condition = and_(
            AccountEntityLink.valid_from <= normalized_as_of,
            or_(
                AccountEntityLink.valid_to.is_(None),
                AccountEntityLink.valid_to >= normalized_as_of,
            ),
        )

    verified_condition = AccountEntityLink.verification_state == VerificationState.VERIFIED
    inferred_condition = AccountEntityLink.match_method != MatchMethod.EXACT

    stmt = (
        select(
            AccountEntityLink.entity_id,
            func.count().label("total"),
            func.count(case((active_condition, 1), else_=None)).label("active"),
            func.count(case((verified_condition, 1), else_=None)).label("verified"),
            func.count(case((inferred_condition, 1), else_=None)).label("inferred"),
        )
        .where(AccountEntityLink.entity_id.in_(ids))
        .group_by(AccountEntityLink.entity_id)
    )

    rows = db.execute(stmt).all()

    return {
        str(row.entity_id): {
            "total": int(row.total or 0),
            "active": int(row.active or 0),
            "verified": int(row.verified or 0),
            "inferred": int(row.inferred or 0),
        }
        for row in rows
    }


def _entity_alert_id_subquery(entity_id: str) -> Any:
    """
    Return a subquery of distinct alert IDs whose evidence references any link
    belonging to the given entity.
    """
    link_id_subq = (
        select(AccountEntityLink.id)
        .where(AccountEntityLink.entity_id == entity_id)
        .subquery()
    )

    return (
        select(AlertEvidence.alert_id)
        .where(
            AlertEvidence.evidence_type == EvidenceType.ENTITY_LINK,
            AlertEvidence.evidence_id.in_(select(link_id_subq.c.id)),
        )
        .distinct()
        .subquery()
    )


# -----------------------------------------------------------------------------
# Lookup helpers
# -----------------------------------------------------------------------------


def _get_entity_or_404(db: Session, entity_id: str) -> Entity:
    """
    Load a synthetic entity or raise a safe not-found error.
    """
    entity = db.get(Entity, entity_id)

    if entity is None:
        raise NotFoundError.resource("entity", entity_id)

    return entity


def _get_link_or_404(
    db: Session,
    entity_id: str,
    link_id: str,
) -> AccountEntityLink:
    """
    Load an account-entity link belonging to the given entity or raise 404.
    """
    link = db.get(AccountEntityLink, link_id)

    if link is None or str(link.entity_id) != str(entity_id):
        raise NotFoundError.resource("entity_link", link_id)

    return link


def _load_accounts_by_ids(
    db: Session,
    account_ids: Sequence[str],
) -> dict[str, Account]:
    """
    Load a bounded map of synthetic accounts by ID.
    """
    ids = [str(account_id) for account_id in account_ids if account_id]

    if not ids:
        return {}

    rows = db.scalars(select(Account).where(Account.id.in_(ids))).all()
    return {str(account.id): account for account in rows}


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class AccountSummaryResponse(BaseModel):
    """
    Safe synthetic account summary embedded in entity-link views.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_type: str
    status: str
    created_at: datetime
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None


class EntityResponse(BaseModel):
    """
    Safe synthetic entity response.

    Raw identifier hashes are intentionally not returned.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    entity_type: str
    identifier_display: str
    source: str
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    metadata_json: Optional[Any] = None
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None
    source_system: Optional[str] = None
    source_batch_id: Optional[str] = None
    ingestion_run_id: Optional[str] = None

    account_link_count: Optional[int] = None
    active_account_link_count: Optional[int] = None
    verified_account_link_count: Optional[int] = None
    inferred_account_link_count: Optional[int] = None


class EntityListResponse(BaseModel):
    """
    Paginated entity list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[EntityResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class EntityDetailResponse(BaseModel):
    """
    Detailed synthetic entity response with bounded counts.
    """

    model_config = ConfigDict(from_attributes=False)

    entity: EntityResponse
    account_link_count: int
    active_account_link_count: int
    verified_account_link_count: int
    inferred_account_link_count: int
    complaint_correlation_count: int
    alert_evidence_count: int
    caveats: list[str] = Field(default_factory=list)


class EntityAccountLinkResponse(BaseModel):
    """
    Time-bound account-entity link response.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_id: str
    entity_id: str
    account: Optional[AccountSummaryResponse] = None
    match_method: str
    confidence: Optional[Decimal] = None
    verification_state: str
    valid_from: datetime
    valid_to: Optional[datetime] = None
    source: str
    metadata_json: Optional[Any] = None
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None
    source_system: Optional[str] = None
    source_batch_id: Optional[str] = None
    ingestion_run_id: Optional[str] = None


class EntityAccountLinkListResponse(BaseModel):
    """
    Paginated account-entity link list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[EntityAccountLinkResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class EntityComplaintCorrelationResponse(BaseModel):
    """
    Complaint correlation view for an entity.

    Raw and normalized complaint narratives are intentionally not returned.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    complaint_id: str
    complaint_reference: str
    complaint_category: str
    reported_at: datetime
    complaint_amount: Optional[Decimal] = None
    complaint_currency: Optional[str] = None
    complaint_source: Optional[str] = None
    complaint_narrative_available: bool = False

    entity_id: Optional[str] = None
    account_id: Optional[str] = None
    transaction_id: Optional[str] = None

    match_tier: int
    match_method: str
    confidence: Optional[Decimal] = None
    deterministic: bool
    review_state: str
    evidence_refs: list[str] = Field(default_factory=list)
    record_created_at: Optional[datetime] = None


class EntityComplaintCorrelationListResponse(BaseModel):
    """
    Paginated complaint-correlation list response for an entity.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[EntityComplaintCorrelationResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class EntityAlertResponse(BaseModel):
    """
    Safe investigative alert summary referencing an entity link.
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
    record_created_at: Optional[datetime] = None


class EntityAlertListResponse(BaseModel):
    """
    Paginated alert list response referencing an entity.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[EntityAlertResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class EntityLinkVerificationUpdateRequest(BaseModel):
    """
    Authorised investigator request to update an account-entity link
    verification state.
    """

    model_config = ConfigDict(extra="forbid")

    verification_state: VerificationState = Field(
        description="New verification state for the account-entity link.",
    )
    note: Optional[str] = Field(
        default=None,
        max_length=_MAX_NOTE_LENGTH,
        description=(
            "Optional investigator note. Do not include secrets, tokens, "
            "passwords, or unnecessary sensitive narrative text."
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


class EntityLinkVerificationUpdateResponse(BaseModel):
    """
    Response from an account-entity link verification-state update.
    """

    model_config = ConfigDict(from_attributes=False)

    link: EntityAccountLinkResponse
    changed: bool
    previous_state: str
    new_state: str
    audited: bool
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Response builders
# -----------------------------------------------------------------------------


def _account_summary_response(account: Account) -> AccountSummaryResponse:
    """
    Build a safe account summary.
    """
    return AccountSummaryResponse(
        id=str(account.id),
        account_type=_enum_str(account.account_type) or "OTHER",
        status=_enum_str(account.status) or "ACTIVE",
        created_at=account.created_at,
        record_created_at=getattr(account, "record_created_at", None),
        record_updated_at=getattr(account, "record_updated_at", None),
    )


def _entity_response(
    entity: Entity,
    counts: Optional[dict[str, int]] = None,
) -> EntityResponse:
    """
    Build a safe entity response.
    """
    counts = counts or {}

    return EntityResponse(
        id=str(entity.id),
        entity_type=_enum_str(entity.entity_type) or "OTHER",
        identifier_display=_entity_display_label(entity),
        source=str(entity.source or "synthetic"),
        first_seen_at=getattr(entity, "first_seen_at", None),
        last_seen_at=getattr(entity, "last_seen_at", None),
        metadata_json=_response_metadata(entity.metadata_json),
        record_created_at=getattr(entity, "record_created_at", None),
        record_updated_at=getattr(entity, "record_updated_at", None),
        source_system=(
            str(entity.source_system)
            if getattr(entity, "source_system", None)
            else None
        ),
        source_batch_id=(
            str(entity.source_batch_id)
            if getattr(entity, "source_batch_id", None)
            else None
        ),
        ingestion_run_id=(
            str(entity.ingestion_run_id)
            if getattr(entity, "ingestion_run_id", None)
            else None
        ),
        account_link_count=counts.get("total"),
        active_account_link_count=counts.get("active"),
        verified_account_link_count=counts.get("verified"),
        inferred_account_link_count=counts.get("inferred"),
    )


def _link_response(
    link: AccountEntityLink,
    account: Optional[Account] = None,
) -> EntityAccountLinkResponse:
    """
    Build a safe account-entity link response.
    """
    return EntityAccountLinkResponse(
        id=str(link.id),
        account_id=str(link.account_id),
        entity_id=str(link.entity_id),
        account=(
            _account_summary_response(account)
            if account is not None
            else None
        ),
        match_method=_enum_str(link.match_method) or "UNKNOWN",
        confidence=link.confidence,
        verification_state=_enum_str(link.verification_state) or "UNVERIFIED",
        valid_from=link.valid_from,
        valid_to=link.valid_to,
        source=str(link.source or "synthetic"),
        metadata_json=_response_metadata(link.metadata_json),
        record_created_at=getattr(link, "record_created_at", None),
        record_updated_at=getattr(link, "record_updated_at", None),
        source_system=(
            str(link.source_system)
            if getattr(link, "source_system", None)
            else None
        ),
        source_batch_id=(
            str(link.source_batch_id)
            if getattr(link, "source_batch_id", None)
            else None
        ),
        ingestion_run_id=(
            str(link.ingestion_run_id)
            if getattr(link, "ingestion_run_id", None)
            else None
        ),
    )


def _correlation_response(
    correlation: ComplaintCorrelation,
    complaint: Complaint,
) -> EntityComplaintCorrelationResponse:
    """
    Build a safe complaint-correlation response.

    Raw and normalized narratives are intentionally omitted.
    """
    return EntityComplaintCorrelationResponse(
        id=str(correlation.id),
        complaint_id=str(complaint.id),
        complaint_reference=str(complaint.reference),
        complaint_category=str(complaint.category),
        reported_at=complaint.reported_at,
        complaint_amount=complaint.amount,
        complaint_currency=str(complaint.currency) if complaint.currency else None,
        complaint_source=str(complaint.source) if complaint.source else None,
        complaint_narrative_available=bool(complaint.narrative_raw),
        entity_id=str(correlation.entity_id) if correlation.entity_id else None,
        account_id=str(correlation.account_id) if correlation.account_id else None,
        transaction_id=str(correlation.transaction_id) if correlation.transaction_id else None,
        match_tier=int(correlation.match_tier),
        match_method=_enum_str(correlation.match_method) or "UNKNOWN",
        confidence=correlation.confidence,
        deterministic=bool(correlation.deterministic),
        review_state=_enum_str(correlation.review_state) or "UNREVIEWED",
        evidence_refs=_safe_string_list(correlation.evidence_refs_json),
        record_created_at=getattr(correlation, "record_created_at", None),
    )


def _alert_response(alert: Alert) -> EntityAlertResponse:
    """
    Build a safe alert response.
    """
    return EntityAlertResponse(
        id=str(alert.id),
        account_id=str(alert.account_id),
        assessment_id=str(alert.assessment_id) if alert.assessment_id else None,
        title=str(alert.title),
        summary=str(alert.summary) if alert.summary else None,
        priority=_enum_str(alert.priority) or "MEDIUM",
        state=_enum_str(alert.state) or "NEW",
        score=alert.score,
        score_version=str(alert.score_version) if alert.score_version else None,
        scoring_mode=_enum_str(alert.scoring_mode) or "unknown",
        model_version=str(alert.model_version) if alert.model_version else None,
        rule_codes=_safe_string_list(alert.rule_codes_json),
        signal_summary_json=_response_metadata(alert.signal_summary_json),
        first_seen_at=alert.first_seen_at,
        last_seen_at=alert.last_seen_at,
        record_created_at=getattr(alert, "record_created_at", None),
    )


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "",
    response_model=EntityListResponse,
    summary="List synthetic entities",
    description=(
        "Returns a paginated, filtered, and stably ordered list of synthetic "
        "MULEGUARD pseudonymous entities. This endpoint is read-only and does "
        "not take adverse action. Shared entities are investigative "
        "associations only and are not proof of common control or wrongdoing."
    ),
)
def list_entities(
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(entity_pagination),
    search: SearchParams = Depends(entity_search),
    _: User = Depends(require_permission(Permission.GRAPH_READ)),
    entity_type: Annotated[
        Optional[EntityType],
        Query(description="Filter by synthetic entity type."),
    ] = None,
    source: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by entity provenance source."),
    ] = None,
    first_seen_from: Annotated[
        Optional[datetime],
        Query(description="Filter entities first seen at or after this UTC timestamp."),
    ] = None,
    first_seen_to: Annotated[
        Optional[datetime],
        Query(description="Filter entities first seen at or before this UTC timestamp."),
    ] = None,
    last_seen_from: Annotated[
        Optional[datetime],
        Query(description="Filter entities last seen at or after this UTC timestamp."),
    ] = None,
    last_seen_to: Annotated[
        Optional[datetime],
        Query(description="Filter entities last seen at or before this UTC timestamp."),
    ] = None,
    as_of: Annotated[
        Optional[datetime],
        Query(description="Point-in-time cutoff used for optional active link counts."),
    ] = None,
    include_link_counts: Annotated[
        bool,
        Query(description="Include bounded account-entity link counts for returned entities."),
    ] = False,
) -> EntityListResponse:
    """
    List synthetic entities with bounded pagination and safe filters.
    """
    _ensure_entities_enabled(settings)

    normalized_first_from = _ensure_utc(first_seen_from)
    normalized_first_to = _ensure_utc(first_seen_to)
    normalized_last_from = _ensure_utc(last_seen_from)
    normalized_last_to = _ensure_utc(last_seen_to)
    normalized_as_of = _ensure_utc(as_of)

    _validate_not_future(normalized_as_of, "as_of")
    _validate_date_range(
        normalized_first_from,
        normalized_first_to,
        "first_seen_from",
        "first_seen_to",
    )
    _validate_date_range(
        normalized_last_from,
        normalized_last_to,
        "last_seen_from",
        "last_seen_to",
    )

    source_norm = _normalize_source(source)

    conditions: list[Any] = []

    if entity_type is not None:
        conditions.append(Entity.entity_type == entity_type)

    if source_norm is not None:
        conditions.append(func.lower(Entity.source) == source_norm.lower())

    if normalized_first_from is not None:
        conditions.append(Entity.first_seen_at >= normalized_first_from)

    if normalized_first_to is not None:
        conditions.append(Entity.first_seen_at <= normalized_first_to)

    if normalized_last_from is not None:
        conditions.append(Entity.last_seen_at >= normalized_last_from)

    if normalized_last_to is not None:
        conditions.append(Entity.last_seen_at <= normalized_last_to)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(
            or_(
                func.lower(Entity.id).like(pattern),
                func.lower(Entity.identifier_display).like(pattern),
                func.lower(Entity.source).like(pattern),
            )
        )

    count_stmt = select(func.count()).select_from(Entity)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(Entity)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_ENTITY_COLUMN_MAP,
        tiebreaker=Entity.id,
        default_sort_by="created_at",
        default_sort_order="desc",
    )

    entities = db.scalars(stmt).all()

    counts_by_entity: dict[str, dict[str, int]] = {}

    if include_link_counts and entities:
        counts_by_entity = _link_counts_for_entity_ids(
            db,
            [str(entity.id) for entity in entities],
            as_of=normalized_as_of,
        )

    items = [
        _entity_response(
            entity,
            counts_by_entity.get(str(entity.id)),
        )
        for entity in entities
    ]

    return EntityListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_ENTITY_CAVEATS),
    )


@router.get(
    "/{entity_id}",
    response_model=EntityDetailResponse,
    summary="Get a synthetic entity",
    description=(
        "Returns a safe detail view for one synthetic MULEGUARD entity, "
        "including bounded account-entity link, complaint-correlation, and "
        "alert-evidence counts. Raw identifier hashes are not returned."
    ),
)
def get_entity(
    entity_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic entity identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.GRAPH_READ)),
    as_of: Annotated[
        Optional[datetime],
        Query(description="Point-in-time cutoff used for active link counts."),
    ] = None,
) -> EntityDetailResponse:
    """
    Retrieve one synthetic entity detail.
    """
    _ensure_entities_enabled(settings)

    entity = _get_entity_or_404(db, entity_id)
    entity_id = str(entity.id)

    normalized_as_of = _ensure_utc(as_of)
    _validate_not_future(normalized_as_of, "as_of")

    counts = _link_counts_for_entity_ids(
        db,
        [entity_id],
        as_of=normalized_as_of,
    ).get(entity_id, {})

    complaint_count = _scalar_count(
        db,
        select(func.count())
        .select_from(ComplaintCorrelation)
        .where(ComplaintCorrelation.entity_id == entity_id),
    )

    alert_id_subq = _entity_alert_id_subquery(entity_id)
    alert_count = _scalar_count(
        db,
        select(func.count()).select_from(alert_id_subq),
    )

    return EntityDetailResponse(
        entity=_entity_response(entity, counts),
        account_link_count=int(counts.get("total", 0)),
        active_account_link_count=int(counts.get("active", 0)),
        verified_account_link_count=int(counts.get("verified", 0)),
        inferred_account_link_count=int(counts.get("inferred", 0)),
        complaint_correlation_count=complaint_count,
        alert_evidence_count=alert_count,
        caveats=list(_ENTITY_CAVEATS),
    )


@router.get(
    "/{entity_id}/accounts",
    response_model=EntityAccountLinkListResponse,
    summary="List accounts linked to a synthetic entity",
    description=(
        "Returns paginated time-bound account-entity links for one synthetic "
        "entity. Shared accounts are investigative associations only and are "
        "not proof of common control or wrongdoing."
    ),
)
def list_entity_accounts(
    entity_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic entity identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(link_pagination),
    search: SearchParams = Depends(link_search),
    _: User = Depends(require_permission(Permission.GRAPH_READ)),
    account_type: Annotated[
        Optional[AccountType],
        Query(description="Filter linked accounts by synthetic account type."),
    ] = None,
    account_status: Annotated[
        Optional[AccountStatus],
        Query(description="Filter linked accounts by synthetic account status."),
    ] = None,
    match_method: Annotated[
        Optional[MatchMethod],
        Query(description="Filter links by match method."),
    ] = None,
    verification_state: Annotated[
        Optional[VerificationState],
        Query(description="Filter links by verification state."),
    ] = None,
    as_of: Annotated[
        Optional[datetime],
        Query(description="Return links valid at this UTC point in time."),
    ] = None,
    active_only: Annotated[
        bool,
        Query(description="Return only links active at as_of, or currently open-ended when as_of is omitted."),
    ] = False,
) -> EntityAccountLinkListResponse:
    """
    List account-entity links for one entity.
    """
    _ensure_entities_enabled(settings)

    entity = _get_entity_or_404(db, entity_id)
    entity_id = str(entity.id)

    normalized_as_of = _ensure_utc(as_of)
    _validate_not_future(normalized_as_of, "as_of")

    conditions: list[Any] = [AccountEntityLink.entity_id == entity_id]

    if account_type is not None:
        conditions.append(Account.account_type == account_type)

    if account_status is not None:
        conditions.append(Account.status == account_status)

    if match_method is not None:
        conditions.append(AccountEntityLink.match_method == match_method)

    if verification_state is not None:
        conditions.append(AccountEntityLink.verification_state == verification_state)

    if active_only:
        if normalized_as_of is not None:
            conditions.append(AccountEntityLink.valid_from <= normalized_as_of)
            conditions.append(
                or_(
                    AccountEntityLink.valid_to.is_(None),
                    AccountEntityLink.valid_to >= normalized_as_of,
                )
            )
        else:
            conditions.append(AccountEntityLink.valid_to.is_(None))
    elif normalized_as_of is not None:
        conditions.append(AccountEntityLink.valid_from <= normalized_as_of)
        conditions.append(
            or_(
                AccountEntityLink.valid_to.is_(None),
                AccountEntityLink.valid_to >= normalized_as_of,
            )
        )

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(
            or_(
                func.lower(Account.id).like(pattern),
                func.lower(AccountEntityLink.source).like(pattern),
            )
        )

    count_stmt = (
        select(func.count())
        .select_from(AccountEntityLink)
        .join(Account, Account.id == AccountEntityLink.account_id)
    )
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = (
        select(AccountEntityLink, Account)
        .join(Account, Account.id == AccountEntityLink.account_id)
    )
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_LINK_COLUMN_MAP,
        tiebreaker=AccountEntityLink.id,
        default_sort_by="valid_from",
        default_sort_order="desc",
    )

    rows = db.execute(stmt).all()

    items = [
        _link_response(link, account)
        for link, account in rows
    ]

    return EntityAccountLinkListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_LINK_CAVEATS),
    )


@router.patch(
    "/{entity_id}/links/{link_id}/verification-state",
    response_model=EntityLinkVerificationUpdateResponse,
    summary="Update account-entity link verification state",
    description=(
        "Allows an authorised senior investigator or administrator to update "
        "the verification state of a time-bound account-entity link. This is "
        "an investigative metadata action, not an enforcement action. The "
        "change is audited."
    ),
)
def update_entity_link_verification_state(
    entity_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic entity identifier."),
    ],
    link_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Account-entity link identifier."),
    ],
    payload: EntityLinkVerificationUpdateRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    reviewer: User = Depends(
        require_roles(UserRole.SENIOR_INVESTIGATOR, UserRole.ADMIN)
    ),
) -> EntityLinkVerificationUpdateResponse:
    """
    Update the verification state for one account-entity link.
    """
    _ensure_entities_enabled(settings)

    entity = _get_entity_or_404(db, entity_id)
    entity_id = str(entity.id)

    link = _get_link_or_404(db, entity_id, link_id)

    previous_state = _enum_str(link.verification_state) or "UNVERIFIED"
    new_state = _enum_str(payload.verification_state) or "UNVERIFIED"

    if previous_state == new_state:
        account = db.get(Account, str(link.account_id))

        return EntityLinkVerificationUpdateResponse(
            link=_link_response(link, account),
            changed=False,
            previous_state=previous_state,
            new_state=new_state,
            audited=False,
            caveats=list(_UPDATE_CAVEATS),
        )

    link.verification_state = payload.verification_state

    _add_audit_event(
        db,
        action="entity_link_verification_state_update",
        outcome="SUCCESS",
        request_id=request_id,
        actor=reviewer,
        resource_type="account_entity_link",
        resource_id=str(link.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "entity_id": entity_id,
            "account_id": str(link.account_id),
            "previous_state": previous_state,
            "new_state": new_state,
            "match_method": _enum_str(link.match_method),
            "confidence": str(link.confidence) if link.confidence is not None else None,
            **_audit_note_metadata(payload.note),
        },
    )

    db.commit()
    db.refresh(link)

    account = db.get(Account, str(link.account_id))

    return EntityLinkVerificationUpdateResponse(
        link=_link_response(link, account),
        changed=True,
        previous_state=previous_state,
        new_state=new_state,
        audited=True,
        caveats=list(_UPDATE_CAVEATS),
    )


@router.get(
    "/{entity_id}/complaint-correlations",
    response_model=EntityComplaintCorrelationListResponse,
    summary="List complaint correlations for a synthetic entity",
    description=(
        "Returns paginated complaint correlations associated with one synthetic "
        "entity. Exact matches are distinguished from inferred associations "
        "through match tier, method, determinism, and confidence. Raw and "
        "normalized complaint narratives are intentionally not returned."
    ),
)
def list_entity_complaint_correlations(
    entity_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic entity identifier."),
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
) -> EntityComplaintCorrelationListResponse:
    """
    List complaint correlations for one entity.
    """
    _ensure_entities_enabled(settings)

    entity = _get_entity_or_404(db, entity_id)
    entity_id = str(entity.id)

    conditions: list[Any] = [ComplaintCorrelation.entity_id == entity_id]

    if match_tier is not None:
        conditions.append(ComplaintCorrelation.match_tier == match_tier)

    if review_state is not None:
        conditions.append(ComplaintCorrelation.review_state == review_state)

    if deterministic is not None:
        conditions.append(ComplaintCorrelation.deterministic.is_(deterministic))

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(
            or_(
                func.lower(Complaint.reference).like(pattern),
                func.lower(Complaint.category).like(pattern),
            )
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
        tiebreaker=ComplaintCorrelation.id,
        default_sort_by="created_at",
        default_sort_order="desc",
    )

    rows = db.execute(stmt).all()

    items = [
        _correlation_response(correlation, complaint)
        for correlation, complaint in rows
    ]

    return EntityComplaintCorrelationListResponse(
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
    "/{entity_id}/alerts",
    response_model=EntityAlertListResponse,
    summary="List alerts referencing a synthetic entity",
    description=(
        "Returns paginated investigative alerts whose evidence references one "
        "or more account-entity links belonging to the given synthetic entity. "
        "Alerts are investigative leads only and must not be treated as proof "
        "of wrongdoing or used for automatic adverse action."
    ),
)
def list_entity_alerts(
    entity_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic entity identifier."),
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
) -> EntityAlertListResponse:
    """
    List alerts referencing links belonging to one entity.
    """
    _ensure_entities_enabled(settings)

    entity = _get_entity_or_404(db, entity_id)
    entity_id = str(entity.id)

    alert_id_subq = _entity_alert_id_subquery(entity_id)

    conditions: list[Any] = [
        Alert.id.in_(select(alert_id_subq.c.alert_id))
    ]

    if state is not None:
        conditions.append(Alert.state == state)

    if priority is not None:
        conditions.append(Alert.priority == priority)

    count_stmt = select(func.count()).select_from(Alert)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(Alert)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_ALERT_COLUMN_MAP,
        tiebreaker=Alert.id,
        default_sort_by="created_at",
        default_sort_order="desc",
    )

    alerts = db.scalars(stmt).all()

    return EntityAlertListResponse(
        items=[_alert_response(alert) for alert in alerts],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_ALERT_CAVEATS),
    )


__all__ = [
    "router",
]