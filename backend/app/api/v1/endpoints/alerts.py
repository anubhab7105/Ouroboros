"""
MULEGUARD backend API v1 alert endpoints.

This module implements the versioned `/api/v1/alerts` investigation and triage
surface for synthetic MULEGUARD alerts.

Implemented endpoints:

- GET    /api/v1/alerts
- GET    /api/v1/alerts/{alert_id}
- GET    /api/v1/alerts/{alert_id}/evidence
- POST   /api/v1/alerts/{alert_id}/evidence
- GET    /api/v1/alerts/{alert_id}/history
- POST   /api/v1/alerts/{alert_id}/acknowledge
- POST   /api/v1/alerts/{alert_id}/assign
- POST   /api/v1/alerts/{alert_id}/escalate
- POST   /api/v1/alerts/{alert_id}/close
- POST   /api/v1/alerts/{alert_id}/reopen
- POST   /api/v1/alerts/{alert_id}/case

Design goals:

- provide real, persisted, evidence-backed alert triage workflows;
- enforce server-side RBAC through dependency permissions;
- keep list endpoints paginated, filtered, searched, and stably ordered;
- preserve scoring mode, model version, rule codes, signal summary, and
  evidence provenance;
- make all material triage actions durable and auditable;
- prevent automatic adverse customer action;
- avoid exposing synthetic ground-truth labels, scenario IDs, ring IDs,
  passwords, tokens, secrets, database URLs, raw complaint narratives, or real
  customer data;
- make clear that alerts, scores, graph relationships, candidate money trails,
  entity links, and complaint correlations are investigative leads only.

Explicit non-goals:

- This module does not freeze, block, blacklist, close, restrict, or otherwise
  take adverse action against accounts or customers.
- This module does not connect to real banking systems.
- This module does not compute new ML scores inline.
- This module does not fabricate alert history or evidence.
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
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Final, Optional

from fastapi import APIRouter, Depends, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, desc, func, or_, select
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
    search_dependency,
)
from app.exceptions import (
    ConflictError,
    EvidenceNotFoundError,
    EvidenceValidationError,
    FeatureFlagDisabledError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError as MuleGuardValidationError,
)
from app.models import (
    Account,
    AccountEntityLink,
    Alert,
    AlertEvidence,
    AlertState,
    AuditEvent,
    AuditOutcome,
    CaseEvent,
    CaseEvidence,
    CaseStatus,
    Complaint,
    ComplaintCorrelation,
    EvidenceType,
    InvestigationCase,
    ModelAssessment,
    Priority,
    ScoringMode,
    Transaction,
    User,
    UserRole,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.alerts")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["alerts"])


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_REASON_LENGTH: Final[int] = 1000
_MAX_NOTE_LENGTH: Final[int] = 1000
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_EVIDENCE_REFS: Final[int] = 200
_MAX_BUNDLE_ITEMS: Final[int] = 100
_MAX_JSON_DEPTH: Final[int] = 6

_OPEN_ALERT_STATES: Final[frozenset[AlertState]] = frozenset(
    {
        AlertState.NEW,
        AlertState.ACKNOWLEDGED,
        AlertState.UNDER_REVIEW,
        AlertState.ESCALATED,
    }
)

_ALL_ROLES: Final[tuple[str, ...]] = tuple(role.value for role in UserRole)

_ANALYST_AND_ABOVE: Final[tuple[str, ...]] = (
    UserRole.ANALYST.value,
    UserRole.SENIOR_INVESTIGATOR.value,
    UserRole.ADMIN.value,
)

_SENIOR_AND_ADMIN: Final[tuple[str, ...]] = (
    UserRole.SENIOR_INVESTIGATOR.value,
    UserRole.ADMIN.value,
)

_DEFAULT_ALERT_ASSIGNABLE_ROLES: Final[tuple[str, ...]] = _ANALYST_AND_ABOVE
_DEFAULT_CASE_ASSIGNABLE_ROLES: Final[tuple[str, ...]] = _ANALYST_AND_ABOVE

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

_ALERT_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Alerts are investigative leads only and are not proof of wrongdoing.",
    "Risk scores are investigative priority scores, not probabilities of guilt.",
    "Scoring mode and model version must be interpreted honestly.",
    "Heuristic fallback scores are not calibrated model probabilities.",
    "Entity links, graph relationships, candidate money trails, and complaint correlations are investigative leads only.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    "This API does not freeze, block, blacklist, close, or otherwise take adverse action against accounts or customers.",
)

_EVIDENCE_CAVEATS: Final[tuple[str, ...]] = (
    *_ALERT_CAVEATS,
    "Evidence references must point to validated persisted records.",
    "Raw complaint narratives are intentionally not returned.",
    "Graph path evidence must be generated by the bounded graph service, not manually attached through this endpoint.",
)

_HISTORY_CAVEATS: Final[tuple[str, ...]] = (
    *_ALERT_CAVEATS,
    "Alert history contains safe audit metadata only.",
    "Passwords, tokens, secrets, raw narratives, and unnecessary sensitive payloads are not stored in audit metadata.",
)

_ACTION_CAVEATS: Final[tuple[str, ...]] = (
    *_ALERT_CAVEATS,
    "Triage actions are human investigative workflow states, not automatic enforcement actions.",
    "Closing an alert does not close, freeze, block, or restrict any account.",
)

_CASE_CAVEATS: Final[tuple[str, ...]] = (
    *_ALERT_CAVEATS,
    "Creating a case from an alert starts a human investigation workflow.",
    "Case dispositions are investigator-entered assessments, not automatic conclusions.",
    "This endpoint does not take adverse action against accounts or customers.",
)


# -----------------------------------------------------------------------------
# Column maps for stable pagination
# -----------------------------------------------------------------------------

_ALERT_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": Alert.id,
    "account_id": Alert.account_id,
    "created_at": Alert.record_created_at,
    "updated_at": Alert.record_updated_at,
    "priority": Alert.priority,
    "state": Alert.state,
    "score": Alert.score,
    "scoring_mode": Alert.scoring_mode,
    "first_seen_at": Alert.first_seen_at,
    "last_seen_at": Alert.last_seen_at,
    "acknowledged_at": Alert.acknowledged_at,
    "acknowledged_by": Alert.acknowledged_by,
    "assigned_to": Alert.assigned_to,
    "closed_at": Alert.closed_at,
}

_EVIDENCE_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": AlertEvidence.id,
    "created_at": AlertEvidence.record_created_at,
    "updated_at": AlertEvidence.record_updated_at,
    "evidence_type": AlertEvidence.evidence_type,
    "evidence_id": AlertEvidence.evidence_id,
}

_HISTORY_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": AuditEvent.id,
    "created_at": AuditEvent.created_at,
    "action": AuditEvent.action,
    "outcome": AuditEvent.outcome,
    "actor_username": AuditEvent.actor_username,
}


# -----------------------------------------------------------------------------
# Reusable bounded dependencies
# -----------------------------------------------------------------------------

alert_pagination = pagination_dependency(
    sortable_fields=tuple(_ALERT_COLUMN_MAP.keys()),
    default_sort_by="created_at",
    default_sort_order="desc",
)

evidence_pagination = pagination_dependency(
    sortable_fields=tuple(_EVIDENCE_COLUMN_MAP.keys()),
    default_sort_by="created_at",
    default_sort_order="desc",
)

history_pagination = pagination_dependency(
    sortable_fields=tuple(_HISTORY_COLUMN_MAP.keys()),
    default_sort_by="created_at",
    default_sort_order="desc",
)

alert_search = search_dependency(max_length=200, alias="q")
evidence_search = search_dependency(max_length=200, alias="q")
history_search = search_dependency(max_length=200, alias="q")


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


def _ensure_alerts_enabled(settings: Any) -> None:
    """
    Fail closed when the alert API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "ALERTS_API_ENABLED", True), True):
        raise FeatureFlagDisabledError("Alert endpoints are disabled by configuration.")


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
    Enforce optional maximum date span for alert scans.
    """
    if start is None or end is None:
        return

    max_days = max(
        1,
        _as_int(_setting(settings, "ALERT_MAX_DATE_SPAN_DAYS", 3650), 3650),
    )

    span = end - start
    max_delta = timedelta(days=max_days)

    if span > max_delta:
        raise MuleGuardValidationError(
            "Alert date span exceeds configured maximum.",
            details={
                f"{field_prefix}_max_span_days": max_days,
                f"{field_prefix}_requested_span_days": round(span.total_seconds() / 86400.0, 3),
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
        or "muleguard-alerts"
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
    Return safe audit metadata for an optional note/reason.
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
# Alert lookup and state helpers
# -----------------------------------------------------------------------------


def _get_alert_or_404(db: Session, alert_id: str) -> Alert:
    """
    Load a synthetic alert or raise a safe not-found error.
    """
    alert = db.get(Alert, alert_id)

    if alert is None:
        raise NotFoundError.resource("alert", alert_id)

    return alert


def _assert_alert_not_closed(alert: Alert, action: str) -> None:
    """
    Prevent triage actions on closed alerts unless explicitly reopened first.
    """
    if alert.state == AlertState.CLOSED:
        raise ConflictError(
            f"Cannot {action} a closed alert. Reopen the alert first.",
            details={
                "alert_id": str(alert.id),
                "state": _enum_str(alert.state),
            },
        )


def _state_str(state: Any) -> str:
    return _enum_str(state) or "UNKNOWN"


# -----------------------------------------------------------------------------
# Assignee validation
# -----------------------------------------------------------------------------


def _validate_assignee(
    db: Session,
    settings: Any,
    assignee_id: str,
    *,
    setting_name: str,
    default_roles: Sequence[str],
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

    if not _role_allowed(setting_name, assignee.role, default_roles, settings):
        raise MuleGuardValidationError(
            "Assignee role is not permitted for this workflow.",
            details={
                field_name: assignee_id,
                "role": _enum_str(assignee.role),
                "setting": setting_name,
            },
        )

    return assignee


# -----------------------------------------------------------------------------
# Count helpers
# -----------------------------------------------------------------------------


def _evidence_counts_for_alert_ids(
    db: Session,
    alert_ids: Sequence[str],
) -> dict[str, int]:
    """
    Return bounded alert-evidence counts for a set of alert IDs.
    """
    ids = [str(alert_id) for alert_id in alert_ids if alert_id]

    if not ids:
        return {}

    rows = db.execute(
        select(AlertEvidence.alert_id, func.count())
        .where(AlertEvidence.alert_id.in_(ids))
        .group_by(AlertEvidence.alert_id)
    ).all()

    return {str(row[0]): int(row[1] or 0) for row in rows}


def _case_info_for_alert_ids(
    db: Session,
    alert_ids: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """
    Return bounded case counts and active case IDs for a set of alert IDs.
    """
    ids = [str(alert_id) for alert_id in alert_ids if alert_id]

    if not ids:
        return {}

    rows = db.execute(
        select(
            InvestigationCase.alert_id,
            InvestigationCase.id,
            InvestigationCase.status,
        )
        .where(InvestigationCase.alert_id.in_(ids))
        .order_by(
            desc(InvestigationCase.record_created_at),
            desc(InvestigationCase.id),
        )
    ).all()

    info: dict[str, dict[str, Any]] = {
        alert_id: {
            "total": 0,
            "active": 0,
            "active_case_id": None,
        }
        for alert_id in ids
    }

    for row in rows:
        alert_id = str(row.alert_id)
        bucket = info.setdefault(
            alert_id,
            {
                "total": 0,
                "active": 0,
                "active_case_id": None,
            },
        )

        bucket["total"] += 1

        if row.status != CaseStatus.CLOSED:
            bucket["active"] += 1

            if bucket["active_case_id"] is None:
                bucket["active_case_id"] = str(row.id)

    return info


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

    rows = db.scalars(select(User).where(User.id.in_(list(ids)))).all()
    return {str(user.id): str(user.username) for user in rows}


# -----------------------------------------------------------------------------
# Evidence validation and snapshot helpers
# -----------------------------------------------------------------------------


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
            "id": str(obj.id),
            "account_type": _enum_str(obj.account_type),
            "status": _enum_str(obj.status),
            "created_at": obj.created_at,
        }

    elif evidence_type == EvidenceType.TRANSACTION:
        payload = {
            "id": str(obj.id),
            "sender_account_id": str(obj.sender_account_id),
            "receiver_account_id": str(obj.receiver_account_id),
            "amount": obj.amount,
            "currency": str(obj.currency),
            "occurred_at": obj.occurred_at,
            "status": _enum_str(obj.status),
            "channel": _enum_str(obj.channel),
            "reference": str(obj.reference),
        }

    elif evidence_type == EvidenceType.COMPLAINT:
        payload = {
            "id": str(obj.id),
            "reference": str(obj.reference),
            "category": str(obj.category),
            "reported_at": obj.reported_at,
            "amount": obj.amount,
            "currency": str(obj.currency) if obj.currency else None,
            "source": str(obj.source) if obj.source else None,
            "victim_account_id": str(obj.victim_account_id) if obj.victim_account_id else None,
            "suspected_account_id": (
                str(obj.suspected_account_id) if obj.suspected_account_id else None
            ),
            "transaction_reference": (
                str(obj.transaction_reference) if obj.transaction_reference else None
            ),
            "narrative_available": bool(obj.narrative_raw),
        }

    elif evidence_type == EvidenceType.MODEL_ASSESSMENT:
        payload = {
            "id": str(obj.id),
            "account_id": str(obj.account_id),
            "as_of": obj.as_of,
            "scored_at": obj.scored_at,
            "scoring_mode": _enum_str(obj.scoring_mode),
            "score": obj.score,
            "score_type": str(obj.score_type),
            "risk_band": _enum_str(obj.risk_band),
            "model_version_id": str(obj.model_version_id) if obj.model_version_id else None,
            "feature_snapshot_id": (
                str(obj.feature_snapshot_id) if obj.feature_snapshot_id else None
            ),
            "analysis_run_id": str(obj.analysis_run_id) if obj.analysis_run_id else None,
        }

    elif evidence_type == EvidenceType.ENTITY_LINK:
        payload = {
            "id": str(obj.id),
            "account_id": str(obj.account_id),
            "entity_id": str(obj.entity_id),
            "match_method": _enum_str(obj.match_method),
            "confidence": obj.confidence,
            "verification_state": _enum_str(obj.verification_state),
            "valid_from": obj.valid_from,
            "valid_to": obj.valid_to,
            "source": str(obj.source),
        }

    elif evidence_type == EvidenceType.ALERT:
        payload = {
            "id": str(obj.id),
            "account_id": str(obj.account_id),
            "title": str(obj.title),
            "priority": _enum_str(obj.priority),
            "state": _enum_str(obj.state),
            "score": obj.score,
            "scoring_mode": _enum_str(obj.scoring_mode),
            "first_seen_at": obj.first_seen_at,
            "last_seen_at": obj.last_seen_at,
        }

    else:
        payload = {
            "evidence_type": _enum_str(evidence_type),
            "evidence_id": str(getattr(obj, "id", "")),
        }

    return _sanitize_json_object(payload)


def _validate_evidence_reference(
    db: Session,
    alert: Alert,
    evidence_type: EvidenceType,
    evidence_id: str,
) -> dict[str, Any]:
    """
    Validate that an evidence reference points to a relevant persisted record.

    Returns a safe snapshot for the referenced record.
    """
    alert_account_id = str(alert.account_id)

    if evidence_type == EvidenceType.ACCOUNT:
        obj = db.get(Account, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced account evidence was not found.")

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.TRANSACTION:
        obj = db.get(Transaction, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced transaction evidence was not found.")

        if (
            str(obj.sender_account_id) != alert_account_id
            and str(obj.receiver_account_id) != alert_account_id
        ):
            raise EvidenceValidationError(
                "Referenced transaction does not involve the alerted account."
            )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.COMPLAINT:
        obj = db.get(Complaint, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced complaint evidence was not found.")

        related = (
            str(obj.victim_account_id or "") == alert_account_id
            or str(obj.suspected_account_id or "") == alert_account_id
        )

        if not related:
            correlation_exists = db.scalar(
                select(ComplaintCorrelation.id)
                .where(
                    ComplaintCorrelation.complaint_id == obj.id,
                    ComplaintCorrelation.account_id == alert_account_id,
                )
                .limit(1)
            )

            if correlation_exists is None:
                raise EvidenceValidationError(
                    "Referenced complaint is not related to the alerted account."
                )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.MODEL_ASSESSMENT:
        obj = db.get(ModelAssessment, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError(
                "Referenced model assessment evidence was not found."
            )

        if str(obj.account_id) != alert_account_id:
            raise EvidenceValidationError(
                "Referenced assessment does not belong to the alerted account."
            )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.ENTITY_LINK:
        obj = db.get(AccountEntityLink, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced entity link evidence was not found.")

        if str(obj.account_id) != alert_account_id:
            raise EvidenceValidationError(
                "Referenced entity link does not belong to the alerted account."
            )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.ALERT:
        if evidence_id == str(alert.id):
            raise EvidenceValidationError(
                "An alert cannot reference itself as evidence."
            )

        obj = db.get(Alert, evidence_id)

        if obj is None:
            raise EvidenceNotFoundError("Referenced alert evidence was not found.")

        if str(obj.account_id) != alert_account_id:
            raise EvidenceValidationError(
                "Referenced alert does not belong to the same alerted account."
            )

        return _build_evidence_snapshot(evidence_type, obj)

    if evidence_type == EvidenceType.GRAPH_PATH:
        raise EvidenceValidationError(
            "Graph path evidence must be generated by the bounded graph service "
            "and cannot be manually attached through this endpoint."
        )

    raise EvidenceValidationError("Unsupported evidence type.")


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class AlertAccountSummaryResponse(BaseModel):
    """
    Safe synthetic account summary embedded in alert views.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_type: str
    status: str
    created_at: datetime
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None


class AlertCaseSummaryResponse(BaseModel):
    """
    Safe investigation case summary linked to an alert.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    title: str
    status: str
    priority: str
    assignee_id: Optional[str] = None
    creator_id: Optional[str] = None
    alert_id: Optional[str] = None
    account_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    metadata_json: Optional[Any] = None


class AlertEvidenceResponse(BaseModel):
    """
    Safe alert evidence reference.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    alert_id: str
    evidence_type: str
    evidence_id: str
    evidence_snapshot_json: Optional[Any] = None
    provenance_json: Optional[Any] = None
    created_by: Optional[str] = None
    created_by_username: Optional[str] = None
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None


class AlertEvidenceListResponse(BaseModel):
    """
    Paginated alert evidence list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[AlertEvidenceResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class AlertEvidenceCreateRequest(BaseModel):
    """
    Request to attach a validated persisted record as alert evidence.
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


class AlertEvidenceActionResponse(BaseModel):
    """
    Response from attaching evidence to an alert.
    """

    model_config = ConfigDict(from_attributes=False)

    evidence: AlertEvidenceResponse
    alert: "AlertResponse"
    changed: bool
    audited: bool
    caveats: list[str] = Field(default_factory=list)


class AlertHistoryEventResponse(BaseModel):
    """
    Safe audit history event for an alert.
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


class AlertHistoryListResponse(BaseModel):
    """
    Paginated alert history response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[AlertHistoryEventResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class AlertResponse(BaseModel):
    """
    Safe synthetic alert response.
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
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    assigned_to: Optional[str] = None
    closed_at: Optional[datetime] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None
    account: Optional[AlertAccountSummaryResponse] = None
    evidence_count: Optional[int] = None
    case_count: Optional[int] = None
    active_case_count: Optional[int] = None
    active_case_id: Optional[str] = None


class AlertListResponse(BaseModel):
    """
    Paginated alert list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[AlertResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class AlertDetailResponse(BaseModel):
    """
    Detailed alert response with bounded evidence and case summaries.
    """

    model_config = ConfigDict(from_attributes=False)

    alert: AlertResponse
    evidences: list[AlertEvidenceResponse] = Field(default_factory=list)
    cases: list[AlertCaseSummaryResponse] = Field(default_factory=list)
    evidence_truncated: bool = False
    case_truncated: bool = False
    caveats: list[str] = Field(default_factory=list)


class AlertActionResponse(BaseModel):
    """
    Generic response for idempotent alert triage actions.
    """

    model_config = ConfigDict(from_attributes=False)

    alert: AlertResponse
    changed: bool
    previous_state: str
    new_state: str
    audited: bool
    caveats: list[str] = Field(default_factory=list)


class AlertAssignRequest(BaseModel):
    """
    Request to assign an alert to an active, permitted local user.
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


class AlertAssignResponse(BaseModel):
    """
    Response from assigning an alert.
    """

    model_config = ConfigDict(from_attributes=False)

    alert: AlertResponse
    changed: bool
    previous_assignee_id: Optional[str] = None
    new_assignee_id: Optional[str] = None
    previous_state: str
    new_state: str
    audited: bool
    caveats: list[str] = Field(default_factory=list)


class AlertCloseRequest(BaseModel):
    """
    Request to close an alert as a human triage decision.
    """

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        min_length=3,
        max_length=_MAX_REASON_LENGTH,
        description=(
            "Investigator closure reason. This is recorded in audit history only. "
            "Do not include secrets, tokens, passwords, or unnecessary sensitive "
            "narrative text."
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


class AlertCreateCaseRequest(BaseModel):
    """
    Request to create an investigation case from an alert.
    """

    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Optional case title. Defaults to the alert title.",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Optional case description.",
    )
    assignee_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Optional local user identifier to assign the case.",
    )
    priority: Optional[Priority] = Field(
        default=None,
        description="Optional case priority. Defaults to the alert priority.",
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
            return None

        if len(normalized) > 200:
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

        if len(normalized) > 2000:
            raise ValueError("description is too long")

        return normalized

    @field_validator("assignee_id")
    @classmethod
    def _validate_assignee_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        return normalized


class AlertCreateCaseResponse(BaseModel):
    """
    Response from creating an investigation case from an alert.
    """

    model_config = ConfigDict(from_attributes=False)

    case: AlertCaseSummaryResponse
    alert: AlertResponse
    copied_evidence_count: int
    total_evidence_count: int
    evidence_truncated: bool
    audited: bool
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Response builders
# -----------------------------------------------------------------------------


def _account_summary_response(account: Account) -> AlertAccountSummaryResponse:
    """
    Build a safe account summary.
    """
    return AlertAccountSummaryResponse(
        id=str(account.id),
        account_type=_enum_str(account.account_type) or "OTHER",
        status=_enum_str(account.status) or "ACTIVE",
        created_at=account.created_at,
        record_created_at=getattr(account, "record_created_at", None),
        record_updated_at=getattr(account, "record_updated_at", None),
    )


def _case_summary_response(case_obj: InvestigationCase) -> AlertCaseSummaryResponse:
    """
    Build a safe case summary.
    """
    return AlertCaseSummaryResponse(
        id=str(case_obj.id),
        title=str(case_obj.title),
        status=_enum_str(case_obj.status) or "NEW",
        priority=_enum_str(case_obj.priority) or "MEDIUM",
        assignee_id=str(case_obj.assignee_id) if case_obj.assignee_id else None,
        creator_id=str(case_obj.creator_id) if case_obj.creator_id else None,
        alert_id=str(case_obj.alert_id) if case_obj.alert_id else None,
        account_id=str(case_obj.account_id) if case_obj.account_id else None,
        created_at=getattr(case_obj, "record_created_at", None),
        updated_at=getattr(case_obj, "record_updated_at", None),
        metadata_json=_response_metadata(case_obj.metadata_json),
    )


def _evidence_response(
    evidence: AlertEvidence,
    created_by_username: Optional[str] = None,
) -> AlertEvidenceResponse:
    """
    Build a safe alert evidence response.
    """
    return AlertEvidenceResponse(
        id=str(evidence.id),
        alert_id=str(evidence.alert_id),
        evidence_type=_enum_str(evidence.evidence_type) or "UNKNOWN",
        evidence_id=str(evidence.evidence_id),
        evidence_snapshot_json=_response_metadata(evidence.evidence_snapshot_json),
        provenance_json=_response_metadata(evidence.provenance_json),
        created_by=str(evidence.created_by) if evidence.created_by else None,
        created_by_username=created_by_username,
        record_created_at=getattr(evidence, "record_created_at", None),
        record_updated_at=getattr(evidence, "record_updated_at", None),
    )


def _audit_event_response(event: AuditEvent) -> AlertHistoryEventResponse:
    """
    Build a safe audit history response.
    """
    return AlertHistoryEventResponse(
        id=str(event.id),
        action=str(event.action),
        outcome=_enum_str(event.outcome) or "SUCCESS",
        actor_id=str(event.actor_id) if event.actor_id else None,
        actor_username=str(event.actor_username) if event.actor_username else None,
        actor_role=str(event.actor_role) if event.actor_role else None,
        resource_type=str(event.resource_type) if event.resource_type else None,
        resource_id=str(event.resource_id) if event.resource_id else None,
        request_id=str(event.request_id) if event.request_id else None,
        metadata_json=_response_metadata(event.metadata_json),
        created_at=event.created_at,
    )


def _alert_response(
    alert: Alert,
    *,
    account: Optional[Account] = None,
    evidence_count: Optional[int] = None,
    case_count: Optional[int] = None,
    active_case_count: Optional[int] = None,
    active_case_id: Optional[str] = None,
) -> AlertResponse:
    """
    Build a safe alert response.
    """
    return AlertResponse(
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
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by=str(alert.acknowledged_by) if alert.acknowledged_by else None,
        assigned_to=str(alert.assigned_to) if alert.assigned_to else None,
        closed_at=alert.closed_at,
        created_by=str(alert.created_by) if alert.created_by else None,
        updated_by=str(alert.updated_by) if alert.updated_by else None,
        record_created_at=getattr(alert, "record_created_at", None),
        record_updated_at=getattr(alert, "record_updated_at", None),
        account=_account_summary_response(account) if account is not None else None,
        evidence_count=evidence_count,
        case_count=case_count,
        active_case_count=active_case_count,
        active_case_id=active_case_id,
    )


def _load_alert_evidences(
    db: Session,
    alert_id: str,
    *,
    limit: int = _MAX_BUNDLE_ITEMS,
) -> tuple[list[AlertEvidence], int]:
    """
    Load bounded alert evidences and total count.
    """
    total = _scalar_count(
        db,
        select(func.count())
        .select_from(AlertEvidence)
        .where(AlertEvidence.alert_id == alert_id),
    )

    rows = db.scalars(
        select(AlertEvidence)
        .where(AlertEvidence.alert_id == alert_id)
        .order_by(
            desc(AlertEvidence.record_created_at),
            desc(AlertEvidence.id),
        )
        .limit(limit)
    ).all()

    return list(rows), total


def _load_alert_cases(
    db: Session,
    alert_id: str,
    *,
    limit: int = _MAX_BUNDLE_ITEMS,
) -> tuple[list[InvestigationCase], int]:
    """
    Load bounded linked cases and total count.
    """
    total = _scalar_count(
        db,
        select(func.count())
        .select_from(InvestigationCase)
        .where(InvestigationCase.alert_id == alert_id),
    )

    rows = db.scalars(
        select(InvestigationCase)
        .where(InvestigationCase.alert_id == alert_id)
        .order_by(
            desc(InvestigationCase.record_created_at),
            desc(InvestigationCase.id),
        )
        .limit(limit)
    ).all()

    return list(rows), total


def _hydrate_alert_response(
    db: Session,
    alert: Alert,
    settings: Any,
) -> AlertResponse:
    """
    Build an alert response with bounded account, evidence, and case metadata.
    """
    _ = settings

    account = db.get(Account, str(alert.account_id))
    evidence_counts = _evidence_counts_for_alert_ids(db, [str(alert.id)])
    case_info = _case_info_for_alert_ids(db, [str(alert.id)]).get(str(alert.id), {})

    return _alert_response(
        alert,
        account=account,
        evidence_count=evidence_counts.get(str(alert.id), 0),
        case_count=int(case_info.get("total", 0)),
        active_case_count=int(case_info.get("active", 0)),
        active_case_id=case_info.get("active_case_id"),
    )


def _hydrate_alert_detail(
    db: Session,
    alert: Alert,
    settings: Any,
) -> AlertDetailResponse:
    """
    Build a detailed alert response with bounded evidence and case summaries.
    """
    alert_response = _hydrate_alert_response(db, alert, settings)

    evidences, evidence_total = _load_alert_evidences(db, str(alert.id))
    cases, case_total = _load_alert_cases(db, str(alert.id))

    usernames = _username_map_for_user_ids(
        db,
        [evidence.created_by for evidence in evidences],
    )

    evidence_items = [
        _evidence_response(
            evidence,
            created_by_username=usernames.get(str(evidence.created_by))
            if evidence.created_by
            else None,
        )
        for evidence in evidences
    ]

    case_items = [_case_summary_response(case_obj) for case_obj in cases]

    return AlertDetailResponse(
        alert=alert_response,
        evidences=evidence_items,
        cases=case_items,
        evidence_truncated=evidence_total > len(evidence_items),
        case_truncated=case_total > len(case_items),
        caveats=[*_ALERT_CAVEATS, *_EVIDENCE_CAVEATS],
    )


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "",
    response_model=AlertListResponse,
    summary="List synthetic investigative alerts",
    description=(
        "Returns a paginated, filtered, and stably ordered list of synthetic "
        "MULEGUARD alerts. Alerts are investigative leads only and must not be "
        "treated as proof of wrongdoing or used for automatic adverse action."
    ),
)
def list_alerts(
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(alert_pagination),
    search: SearchParams = Depends(alert_search),
    _: User = Depends(require_permission(Permission.ALERT_READ)),
    account_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by alerted synthetic account."),
    ] = None,
    states: Annotated[
        Optional[list[AlertState]],
        Query(description="Filter by one or more alert states."),
    ] = None,
    priorities: Annotated[
        Optional[list[Priority]],
        Query(description="Filter by one or more alert priorities."),
    ] = None,
    scoring_mode: Annotated[
        Optional[ScoringMode],
        Query(description="Filter by scoring mode."),
    ] = None,
    assigned_to: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by assigned local user."),
    ] = None,
    acknowledged_by: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by acknowledging local user."),
    ] = None,
    min_score: Annotated[
        Optional[Decimal],
        Query(ge=0, le=100, description="Minimum alert score."),
    ] = None,
    max_score: Annotated[
        Optional[Decimal],
        Query(ge=0, le=100, description="Maximum alert score."),
    ] = None,
    created_from: Annotated[
        Optional[datetime],
        Query(description="Filter alerts created at or after this UTC timestamp."),
    ] = None,
    created_to: Annotated[
        Optional[datetime],
        Query(description="Filter alerts created at or before this UTC timestamp."),
    ] = None,
    first_seen_from: Annotated[
        Optional[datetime],
        Query(description="Filter alerts first seen at or after this UTC timestamp."),
    ] = None,
    first_seen_to: Annotated[
        Optional[datetime],
        Query(description="Filter alerts first seen at or before this UTC timestamp."),
    ] = None,
    last_seen_from: Annotated[
        Optional[datetime],
        Query(description="Filter alerts last seen at or after this UTC timestamp."),
    ] = None,
    last_seen_to: Annotated[
        Optional[datetime],
        Query(description="Filter alerts last seen at or before this UTC timestamp."),
    ] = None,
    include_account: Annotated[
        bool,
        Query(description="Include bounded account summaries for returned alerts."),
    ] = False,
) -> AlertListResponse:
    """
    List synthetic alerts with bounded pagination and safe filters.
    """
    _ensure_alerts_enabled(settings)

    normalized_created_from = _ensure_utc(created_from)
    normalized_created_to = _ensure_utc(created_to)
    normalized_first_from = _ensure_utc(first_seen_from)
    normalized_first_to = _ensure_utc(first_seen_to)
    normalized_last_from = _ensure_utc(last_seen_from)
    normalized_last_to = _ensure_utc(last_seen_to)

    _validate_not_future(normalized_created_to, "created_to")
    _validate_not_future(normalized_first_to, "first_seen_to")
    _validate_not_future(normalized_last_to, "last_seen_to")

    _validate_date_range(
        normalized_created_from,
        normalized_created_to,
        "created_from",
        "created_to",
    )
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

    _validate_span(
        normalized_created_from,
        normalized_created_to,
        "created",
        settings,
    )
    _validate_span(
        normalized_first_from,
        normalized_first_to,
        "first_seen",
        settings,
    )
    _validate_span(
        normalized_last_from,
        normalized_last_to,
        "last_seen",
        settings,
    )

    if min_score is not None and max_score is not None and min_score > max_score:
        raise MuleGuardValidationError(
            "min_score must be less than or equal to max_score.",
            details={
                "min_score": str(min_score),
                "max_score": str(max_score),
            },
        )

    conditions: list[Any] = []

    if account_id is not None:
        conditions.append(Alert.account_id == account_id.strip())

    if states:
        conditions.append(Alert.state.in_(states))

    if priorities:
        conditions.append(Alert.priority.in_(priorities))

    if scoring_mode is not None:
        conditions.append(Alert.scoring_mode == scoring_mode)

    if assigned_to is not None:
        conditions.append(Alert.assigned_to == assigned_to.strip())

    if acknowledged_by is not None:
        conditions.append(Alert.acknowledged_by == acknowledged_by.strip())

    if min_score is not None:
        conditions.append(Alert.score >= min_score)

    if max_score is not None:
        conditions.append(Alert.score <= max_score)

    if normalized_created_from is not None:
        conditions.append(Alert.record_created_at >= normalized_created_from)

    if normalized_created_to is not None:
        conditions.append(Alert.record_created_at <= normalized_created_to)

    if normalized_first_from is not None:
        conditions.append(Alert.first_seen_at >= normalized_first_from)

    if normalized_first_to is not None:
        conditions.append(Alert.first_seen_at <= normalized_first_to)

    if normalized_last_from is not None:
        conditions.append(Alert.last_seen_at >= normalized_last_from)

    if normalized_last_to is not None:
        conditions.append(Alert.last_seen_at <= normalized_last_to)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(
            or_(
                func.lower(Alert.id).like(pattern),
                func.lower(Alert.account_id).like(pattern),
                func.lower(Alert.title).like(pattern),
                func.lower(Alert.summary).like(pattern),
            )
        )

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
    alert_ids = [str(alert.id) for alert in alerts]

    evidence_counts = _evidence_counts_for_alert_ids(db, alert_ids)
    case_info = _case_info_for_alert_ids(db, alert_ids)

    accounts: dict[str, Account] = {}

    if include_account and alerts:
        account_ids = {str(alert.account_id) for alert in alerts}
        rows = db.scalars(select(Account).where(Account.id.in_(list(account_ids)))).all()
        accounts = {str(account.id): account for account in rows}

    items = [
        _alert_response(
            alert,
            account=accounts.get(str(alert.account_id)),
            evidence_count=evidence_counts.get(str(alert.id), 0),
            case_count=int(case_info.get(str(alert.id), {}).get("total", 0)),
            active_case_count=int(case_info.get(str(alert.id), {}).get("active", 0)),
            active_case_id=case_info.get(str(alert.id), {}).get("active_case_id"),
        )
        for alert in alerts
    ]

    return AlertListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_ALERT_CAVEATS),
    )


@router.get(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    summary="Get a synthetic investigative alert",
    description=(
        "Returns a safe detailed view for one synthetic MULEGUARD alert, "
        "including bounded evidence references and linked case summaries. "
        "Alerts are investigative leads only."
    ),
)
def get_alert(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.ALERT_READ)),
) -> AlertDetailResponse:
    """
    Retrieve one synthetic alert detail.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    return _hydrate_alert_detail(db, alert, settings)


@router.get(
    "/{alert_id}/evidence",
    response_model=AlertEvidenceListResponse,
    summary="List evidence references for a synthetic alert",
    description=(
        "Returns paginated evidence references attached to one synthetic alert. "
        "Evidence must point to validated persisted records. Raw complaint "
        "narratives are intentionally not returned."
    ),
)
def list_alert_evidence(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(evidence_pagination),
    search: SearchParams = Depends(evidence_search),
    _: User = Depends(require_permission(Permission.ALERT_READ)),
    evidence_type: Annotated[
        Optional[EvidenceType],
        Query(description="Filter by evidence type."),
    ] = None,
) -> AlertEvidenceListResponse:
    """
    List evidence references for one alert.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    alert_id = str(alert.id)

    conditions: list[Any] = [AlertEvidence.alert_id == alert_id]

    if evidence_type is not None:
        conditions.append(AlertEvidence.evidence_type == evidence_type)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(
            or_(
                func.lower(AlertEvidence.evidence_id).like(pattern),
                func.lower(AlertEvidence.evidence_type).like(pattern),
            )
        )

    count_stmt = select(func.count()).select_from(AlertEvidence)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(AlertEvidence)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_EVIDENCE_COLUMN_MAP,
        tiebreaker=AlertEvidence.id,
        default_sort_by="created_at",
        default_sort_order="desc",
    )

    evidences = db.scalars(stmt).all()

    usernames = _username_map_for_user_ids(
        db,
        [evidence.created_by for evidence in evidences],
    )

    items = [
        _evidence_response(
            evidence,
            created_by_username=usernames.get(str(evidence.created_by))
            if evidence.created_by
            else None,
        )
        for evidence in evidences
    ]

    return AlertEvidenceListResponse(
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
    "/{alert_id}/evidence",
    response_model=AlertEvidenceActionResponse,
    status_code=201,
    summary="Attach validated evidence to a synthetic alert",
    description=(
        "Allows an authorised triage user to attach a validated persisted record "
        "as evidence to one synthetic alert. Graph path evidence must be generated "
        "by the bounded graph service and cannot be manually attached here. "
        "The action is audited."
    ),
)
def add_alert_evidence(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    payload: AlertEvidenceCreateRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.ALERT_TRIAGE)),
) -> AlertEvidenceActionResponse:
    """
    Attach validated evidence to one alert.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    alert_id = str(alert.id)

    evidence_id = payload.evidence_id.strip()
    evidence_type = payload.evidence_type

    snapshot = _validate_evidence_reference(
        db=db,
        alert=alert,
        evidence_type=evidence_type,
        evidence_id=evidence_id,
    )

    existing = db.scalar(
        select(AlertEvidence.id)
        .where(
            AlertEvidence.alert_id == alert_id,
            AlertEvidence.evidence_type == evidence_type,
            AlertEvidence.evidence_id == evidence_id,
        )
        .limit(1)
    )

    if existing is not None:
        raise ConflictError(
            "This evidence reference is already attached to the alert.",
            details={
                "alert_id": alert_id,
                "evidence_type": _enum_str(evidence_type),
                "evidence_id": evidence_id,
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

    evidence = AlertEvidence(
        alert_id=alert_id,
        evidence_type=evidence_type,
        evidence_id=evidence_id,
        evidence_snapshot_json=final_snapshot,
        provenance_json=_sanitize_json_object(provenance),
        created_by=str(actor.id),
    )

    db.add(evidence)
    db.flush()

    _add_audit_event(
        db,
        action="alert_evidence_add",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="alert",
        resource_id=alert_id,
        ip_hash=_ip_hash(request, settings),
        metadata={
            "evidence_type": _enum_str(evidence_type),
            "evidence_id": evidence_id,
            "alert_state": _enum_str(alert.state),
            "alert_priority": _enum_str(alert.priority),
        },
    )

    db.commit()
    db.refresh(evidence)

    usernames = _username_map_for_user_ids(db, [evidence.created_by])

    return AlertEvidenceActionResponse(
        evidence=_evidence_response(
            evidence,
            created_by_username=usernames.get(str(evidence.created_by))
            if evidence.created_by
            else None,
        ),
        alert=_hydrate_alert_response(db, alert, settings),
        changed=True,
        audited=True,
        caveats=list(_EVIDENCE_CAVEATS),
    )


@router.get(
    "/{alert_id}/history",
    response_model=AlertHistoryListResponse,
    summary="List safe audit history for a synthetic alert",
    description=(
        "Returns paginated safe audit history for one synthetic alert. "
        "History contains triage actions, evidence attachments, and case creation "
        "events with sanitized metadata only."
    ),
)
def list_alert_history(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(history_pagination),
    search: SearchParams = Depends(history_search),
    _: User = Depends(require_permission(Permission.ALERT_READ)),
    action: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by audit action name."),
    ] = None,
    outcome: Annotated[
        Optional[AuditOutcome],
        Query(description="Filter by audit outcome."),
    ] = None,
) -> AlertHistoryListResponse:
    """
    List audit history for one alert.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    alert_id = str(alert.id)

    conditions: list[Any] = [
        AuditEvent.resource_type == "alert",
        AuditEvent.resource_id == alert_id,
    ]

    if action is not None:
        conditions.append(AuditEvent.action == action.strip())

    if outcome is not None:
        conditions.append(AuditEvent.outcome == outcome)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(
            or_(
                func.lower(AuditEvent.action).like(pattern),
                func.lower(AuditEvent.resource_type).like(pattern),
                func.lower(AuditEvent.actor_username).like(pattern),
            )
        )

    count_stmt = select(func.count()).select_from(AuditEvent)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(AuditEvent)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_HISTORY_COLUMN_MAP,
        tiebreaker=AuditEvent.id,
        default_sort_by="created_at",
        default_sort_order="desc",
    )

    events = db.scalars(stmt).all()

    return AlertHistoryListResponse(
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
    "/{alert_id}/acknowledge",
    response_model=AlertActionResponse,
    summary="Acknowledge a synthetic alert",
    description=(
        "Marks a synthetic alert as acknowledged by the current local user. "
        "This is a human triage action, not an enforcement action."
    ),
)
def acknowledge_alert(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.ALERT_TRIAGE)),
) -> AlertActionResponse:
    """
    Acknowledge one alert.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    previous_state = _state_str(alert.state)

    if alert.state == AlertState.CLOSED:
        raise ConflictError(
            "Cannot acknowledge a closed alert. Reopen the alert first.",
            details={"alert_id": str(alert.id), "state": previous_state},
        )

    if alert.state == AlertState.ACKNOWLEDGED:
        return AlertActionResponse(
            alert=_hydrate_alert_response(db, alert, settings),
            changed=False,
            previous_state=previous_state,
            new_state=previous_state,
            audited=False,
            caveats=list(_ACTION_CAVEATS),
        )

    now = _now_utc()

    alert.state = AlertState.ACKNOWLEDGED
    alert.acknowledged_at = now
    alert.acknowledged_by = str(actor.id)
    alert.updated_by = str(actor.id)

    _add_audit_event(
        db,
        action="alert_acknowledge",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="alert",
        resource_id=str(alert.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "previous_state": previous_state,
            "new_state": _state_str(alert.state),
            "alert_priority": _enum_str(alert.priority),
            "alert_score": str(alert.score) if alert.score is not None else None,
            "scoring_mode": _enum_str(alert.scoring_mode),
        },
    )

    db.commit()
    db.refresh(alert)

    return AlertActionResponse(
        alert=_hydrate_alert_response(db, alert, settings),
        changed=True,
        previous_state=previous_state,
        new_state=_state_str(alert.state),
        audited=True,
        caveats=list(_ACTION_CAVEATS),
    )


@router.post(
    "/{alert_id}/assign",
    response_model=AlertAssignResponse,
    summary="Assign a synthetic alert",
    description=(
        "Assigns a synthetic alert to an active, permitted local prototype user. "
        "This is a human triage workflow action, not an enforcement action."
    ),
)
def assign_alert(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    payload: AlertAssignRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.ALERT_ASSIGN)),
) -> AlertAssignResponse:
    """
    Assign one alert.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    _assert_alert_not_closed(alert, "assign")

    assignee = _validate_assignee(
        db,
        settings,
        payload.assignee_id,
        setting_name="ALERT_ASSIGNABLE_ROLES",
        default_roles=_DEFAULT_ALERT_ASSIGNABLE_ROLES,
        field_name="assignee_id",
    )

    previous_state = _state_str(alert.state)
    previous_assignee = str(alert.assigned_to) if alert.assigned_to else None
    new_assignee = str(assignee.id)

    changed = False

    if alert.assigned_to != assignee.id:
        alert.assigned_to = new_assignee
        changed = True

    if alert.state in {AlertState.NEW, AlertState.ACKNOWLEDGED}:
        alert.state = AlertState.UNDER_REVIEW
        changed = True

    if changed:
        alert.updated_by = str(actor.id)

        _add_audit_event(
            db,
            action="alert_assign",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            actor=actor,
            resource_type="alert",
            resource_id=str(alert.id),
            ip_hash=_ip_hash(request, settings),
            metadata={
                "previous_assignee_id": previous_assignee,
                "new_assignee_id": new_assignee,
                "assignee_role": _enum_str(assignee.role),
                "previous_state": previous_state,
                "new_state": _state_str(alert.state),
                **_note_metadata(payload.note),
            },
        )

        db.commit()
        db.refresh(alert)

    return AlertAssignResponse(
        alert=_hydrate_alert_response(db, alert, settings),
        changed=changed,
        previous_assignee_id=previous_assignee,
        new_assignee_id=new_assignee if changed else previous_assignee,
        previous_state=previous_state,
        new_state=_state_str(alert.state),
        audited=changed,
        caveats=list(_ACTION_CAVEATS),
    )


@router.post(
    "/{alert_id}/escalate",
    response_model=AlertActionResponse,
    summary="Escalate a synthetic alert",
    description=(
        "Escalates a synthetic alert for senior review. This is a human triage "
        "workflow action, not an enforcement action."
    ),
)
def escalate_alert(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.ALERT_ESCALATE)),
) -> AlertActionResponse:
    """
    Escalate one alert.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    _assert_alert_not_closed(alert, "escalate")

    previous_state = _state_str(alert.state)

    if alert.state == AlertState.ESCALATED:
        return AlertActionResponse(
            alert=_hydrate_alert_response(db, alert, settings),
            changed=False,
            previous_state=previous_state,
            new_state=previous_state,
            audited=False,
            caveats=list(_ACTION_CAVEATS),
        )

    alert.state = AlertState.ESCALATED
    alert.updated_by = str(actor.id)

    _add_audit_event(
        db,
        action="alert_escalate",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="alert",
        resource_id=str(alert.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "previous_state": previous_state,
            "new_state": _state_str(alert.state),
            "alert_priority": _enum_str(alert.priority),
            "alert_score": str(alert.score) if alert.score is not None else None,
            "scoring_mode": _enum_str(alert.scoring_mode),
        },
    )

    db.commit()
    db.refresh(alert)

    return AlertActionResponse(
        alert=_hydrate_alert_response(db, alert, settings),
        changed=True,
        previous_state=previous_state,
        new_state=_state_str(alert.state),
        audited=True,
        caveats=list(_ACTION_CAVEATS),
    )


@router.post(
    "/{alert_id}/close",
    response_model=AlertActionResponse,
    summary="Close a synthetic alert as a triage decision",
    description=(
        "Closes a synthetic alert as a human triage decision. This does not "
        "close, freeze, block, blacklist, or restrict any account. The closure "
        "reason is recorded in audit history only."
    ),
)
def close_alert(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    payload: AlertCloseRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.ALERT_TRIAGE)),
) -> AlertActionResponse:
    """
    Close one alert.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    previous_state = _state_str(alert.state)

    if alert.state == AlertState.CLOSED:
        return AlertActionResponse(
            alert=_hydrate_alert_response(db, alert, settings),
            changed=False,
            previous_state=previous_state,
            new_state=previous_state,
            audited=False,
            caveats=[
                *_ACTION_CAVEATS,
                "Closure reason is recorded in audit history only.",
            ],
        )

    now = _now_utc()

    alert.state = AlertState.CLOSED
    alert.closed_at = now
    alert.updated_by = str(actor.id)

    _add_audit_event(
        db,
        action="alert_close",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="alert",
        resource_id=str(alert.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "previous_state": previous_state,
            "new_state": _state_str(alert.state),
            "alert_priority": _enum_str(alert.priority),
            "alert_score": str(alert.score) if alert.score is not None else None,
            "scoring_mode": _enum_str(alert.scoring_mode),
            **_note_metadata(payload.reason),
        },
    )

    db.commit()
    db.refresh(alert)

    return AlertActionResponse(
        alert=_hydrate_alert_response(db, alert, settings),
        changed=True,
        previous_state=previous_state,
        new_state=_state_str(alert.state),
        audited=True,
        caveats=[
            *_ACTION_CAVEATS,
            "Closure reason is recorded in audit history only.",
        ],
    )


@router.post(
    "/{alert_id}/reopen",
    response_model=AlertActionResponse,
    summary="Reopen a closed synthetic alert",
    description=(
        "Reopens a closed synthetic alert for further human review. This does "
        "not take adverse action against any account."
    ),
)
def reopen_alert(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.ALERT_TRIAGE)),
) -> AlertActionResponse:
    """
    Reopen one closed alert.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    previous_state = _state_str(alert.state)

    if alert.state != AlertState.CLOSED:
        raise ConflictError(
            "Only closed alerts can be reopened.",
            details={"alert_id": str(alert.id), "state": previous_state},
        )

    alert.state = AlertState.UNDER_REVIEW
    alert.closed_at = None
    alert.updated_by = str(actor.id)

    _add_audit_event(
        db,
        action="alert_reopen",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="alert",
        resource_id=str(alert.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "previous_state": previous_state,
            "new_state": _state_str(alert.state),
            "alert_priority": _enum_str(alert.priority),
            "alert_score": str(alert.score) if alert.score is not None else None,
            "scoring_mode": _enum_str(alert.scoring_mode),
        },
    )

    db.commit()
    db.refresh(alert)

    return AlertActionResponse(
        alert=_hydrate_alert_response(db, alert, settings),
        changed=True,
        previous_state=previous_state,
        new_state=_state_str(alert.state),
        audited=True,
        caveats=list(_ACTION_CAVEATS),
    )


@router.post(
    "/{alert_id}/case",
    response_model=AlertCreateCaseResponse,
    status_code=201,
    summary="Create an investigation case from a synthetic alert",
    description=(
        "Creates a human investigation case from one synthetic alert and copies "
        "bounded alert evidence into the case. This starts an investigative "
        "workflow and does not take adverse action against any account."
    ),
)
def create_case_from_alert(
    alert_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic alert identifier."),
    ],
    payload: AlertCreateCaseRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(Permission.ALERT_CASE_CREATE)),
) -> AlertCreateCaseResponse:
    """
    Create an investigation case from one alert.
    """
    _ensure_alerts_enabled(settings)

    alert = _get_alert_or_404(db, alert_id)
    _assert_alert_not_closed(alert, "create a case from")

    allow_multiple_active_cases = _as_bool(
        _setting(settings, "ALERT_ALLOW_MULTIPLE_ACTIVE_CASES", False),
        False,
    )

    if not allow_multiple_active_cases:
        existing_active_case = db.scalar(
            select(InvestigationCase.id)
            .where(
                InvestigationCase.alert_id == str(alert.id),
                InvestigationCase.status.notin_([CaseStatus.CLOSED]),
            )
            .limit(1)
        )

        if existing_active_case is not None:
            raise ConflictError(
                "An active investigation case already exists for this alert.",
                details={
                    "alert_id": str(alert.id),
                    "existing_case_id": str(existing_active_case),
                },
            )

    assignee: Optional[User] = None

    if payload.assignee_id:
        assignee = _validate_assignee(
            db,
            settings,
            payload.assignee_id,
            setting_name="CASE_ASSIGNABLE_ROLES",
            default_roles=_DEFAULT_CASE_ASSIGNABLE_ROLES,
            field_name="assignee_id",
        )

    title = payload.title or str(alert.title)
    description = payload.description or (
        f"Investigation case created from alert {alert.id}. "
        f"Alert state: {_enum_str(alert.state)}. "
        f"Alert priority: {_enum_str(alert.priority)}. "
        f"Alert score: {alert.score if alert.score is not None else 'unavailable'}. "
        f"Scoring mode: {_enum_str(alert.scoring_mode)}."
    )

    case_metadata = {
        "source": "alert",
        "alert_id": str(alert.id),
        "alert_state": _enum_str(alert.state),
        "alert_priority": _enum_str(alert.priority),
        "alert_score": str(alert.score) if alert.score is not None else None,
        "alert_scoring_mode": _enum_str(alert.scoring_mode),
        "alert_model_version": str(alert.model_version) if alert.model_version else None,
    }

    if isinstance(payload.metadata_json, Mapping):
        case_metadata.update(_sanitize_json_object(payload.metadata_json))

    case_obj = InvestigationCase(
        title=_clean_text(title, 200),
        description=_clean_text(description, 2000),
        status=CaseStatus.NEW,
        priority=payload.priority or alert.priority,
        assignee_id=str(assignee.id) if assignee is not None else None,
        creator_id=str(actor.id),
        alert_id=str(alert.id),
        account_id=str(alert.account_id),
        metadata_json=_sanitize_json_object(case_metadata),
    )

    db.add(case_obj)
    db.flush()

    evidences, total_evidence_count = _load_alert_evidences(
        db,
        str(alert.id),
        limit=_MAX_BUNDLE_ITEMS,
    )

    copied_evidence_count = 0

    for evidence in evidences:
        case_evidence = CaseEvidence(
            case_id=str(case_obj.id),
            evidence_type=evidence.evidence_type,
            evidence_id=evidence.evidence_id,
            evidence_snapshot_json=_response_metadata(evidence.evidence_snapshot_json),
            provenance_json=_response_metadata(evidence.provenance_json),
            added_by=str(actor.id),
            is_active=True,
        )

        db.add(case_evidence)
        copied_evidence_count += 1

    case_event = CaseEvent(
        case_id=str(case_obj.id),
        actor_id=str(actor.id),
        actor_username=str(actor.username),
        action="created_from_alert",
        resource_type="alert",
        resource_id=str(alert.id),
        summary=f"Case created from alert {alert.id}.",
        metadata_json=_safe_metadata(
            {
                "alert_state": _enum_str(alert.state),
                "alert_priority": _enum_str(alert.priority),
                "alert_score": str(alert.score) if alert.score is not None else None,
                "scoring_mode": _enum_str(alert.scoring_mode),
                "copied_evidence_count": copied_evidence_count,
                "total_evidence_count": total_evidence_count,
                "evidence_truncated": total_evidence_count > copied_evidence_count,
            }
        ),
    )

    db.add(case_event)

    previous_alert_state = _state_str(alert.state)

    if alert.state in {AlertState.NEW, AlertState.ACKNOWLEDGED}:
        alert.state = AlertState.UNDER_REVIEW

    alert.updated_by = str(actor.id)

    _add_audit_event(
        db,
        action="alert_case_create",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="alert",
        resource_id=str(alert.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "case_id": str(case_obj.id),
            "previous_alert_state": previous_alert_state,
            "new_alert_state": _state_str(alert.state),
            "copied_evidence_count": copied_evidence_count,
            "total_evidence_count": total_evidence_count,
            "evidence_truncated": total_evidence_count > copied_evidence_count,
            "assignee_id": str(assignee.id) if assignee is not None else None,
        },
    )

    _add_audit_event(
        db,
        action="case_create",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=actor,
        resource_type="investigation_case",
        resource_id=str(case_obj.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "alert_id": str(alert.id),
            "account_id": str(alert.account_id),
            "case_status": _enum_str(case_obj.status),
            "case_priority": _enum_str(case_obj.priority),
            "assignee_id": str(assignee.id) if assignee is not None else None,
        },
    )

    db.commit()
    db.refresh(case_obj)
    db.refresh(alert)

    return AlertCreateCaseResponse(
        case=_case_summary_response(case_obj),
        alert=_hydrate_alert_response(db, alert, settings),
        copied_evidence_count=copied_evidence_count,
        total_evidence_count=total_evidence_count,
        evidence_truncated=total_evidence_count > copied_evidence_count,
        audited=True,
        caveats=list(_CASE_CAVEATS),
    )


# Rebuild forward reference after models are defined.
AlertEvidenceActionResponse.model_rebuild()


__all__ = [
    "router",
]