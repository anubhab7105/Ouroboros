"""
MULEGUARD backend API v1 account endpoints.

This module implements the versioned `/api/v1/accounts` read-only investigation
surface for synthetic MULEGUARD accounts.

Implemented endpoints:

- GET /api/v1/accounts
- GET /api/v1/accounts/{account_id}
- GET /api/v1/accounts/{account_id}/summary
- GET /api/v1/accounts/{account_id}/transactions
- GET /api/v1/accounts/{account_id}/assessment
- GET /api/v1/accounts/{account_id}/assessments
- GET /api/v1/accounts/{account_id}/alerts
- GET /api/v1/accounts/{account_id}/entities
- GET /api/v1/accounts/{account_id}/complaint-correlations

Design goals:

- provide real, persisted, evidence-backed account investigation views;
- enforce server-side RBAC through dependency permissions;
- keep list endpoints paginated, filtered, searched, and stably ordered;
- expose latest persisted risk assessments and explanations without recomputing
  or fabricating model output;
- keep transaction, alert, entity-link, and complaint-correlation views bounded;
- preserve exact-vs-inferred provenance for complaint correlations;
- avoid exposing synthetic ground-truth labels, scenario IDs, ring IDs,
  passwords, tokens, secrets, database URLs, raw complaint narratives, or real
  customer data;
- make clear that scores, alerts, graph/entity relationships, candidate money
  trails, and complaint correlations are investigative leads only.

Explicit non-goals:

- This module does not create, freeze, block, blacklist, close, or otherwise
  take adverse action on accounts.
- This module does not expose real bank customer data.
- This module does not compute new ML scores inline. It reads persisted
  assessments produced by the analysis pipeline.
- This module does not return ground-truth labels or injected scenario metadata.
- This module does not claim production readiness or real-world fraud-detection
  accuracy.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, and complaint correlations are
investigative leads only. They are not proof of wrongdoing and must not trigger
automatic adverse customer action.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Annotated, Any, Final, Literal, Optional

from fastapi import APIRouter, Depends, Path, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, case, desc, distinct, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    AmountRangeParams,
    DateRangeParams,
    PageParams,
    Permission,
    SearchParams,
    SessionDep,
    SettingsDep,
    amount_range_dependency,
    apply_pagination,
    date_range_dependency,
    pagination_dependency,
    require_permission,
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
    AlertState,
    Channel,
    Complaint,
    ComplaintCorrelation,
    ComplaintReviewState,
    Entity,
    EntityType,
    MatchMethod,
    ModelAssessment,
    Priority,
    RiskBand,
    RiskIndicator,
    RuleHit,
    ScoringMode,
    Transaction,
    TransactionStatus,
    User,
    VerificationState,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.accounts")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["accounts"])


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_EVIDENCE_REFS: Final[int] = 200
_MAX_JSON_DEPTH: Final[int] = 6

TransactionDirection = Literal["incoming", "outgoing", "both", "self"]

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
        "narrative",
        "narrative_raw",
        "narrative_normalized",
        "otp",
        "pan",
        "pass",
        "passwd",
        "password",
        "password_hash",
        "pin",
        "private_key",
        "raw_payload",
        "refresh_token",
        "secret",
        "secret_key",
        "session",
        "token",
    }
)

_SENSITIVE_KEY_TOKENS: Final[tuple[str, ...]] = (
    "access_key",
    "api_key",
    "apikey",
    "authorization",
    "card_number",
    "credential",
    "customer_data",
    "fraud",
    "ground_truth",
    "label",
    "narrative",
    "passphrase",
    "password",
    "passwd",
    "private_key",
    "raw_payload",
    "real_data",
    "refresh_token",
    "ring",
    "scenario",
    "secret",
    "secret_key",
    "token",
)


#: Interpretation limits published with the account collection.
#:
#: Each row carries a risk band and a score, so the limits travel with the
#: list and not only with the single-account view somebody may never open.
_ACCOUNT_LIST_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Latest assessment score is an investigative priority score, not a probability of guilt.",
    "A risk band is a triage ordering, not a finding about an account holder.",
    "An account with no assessment is unscored, which is not the same as low risk.",
    "Entity links, complaint correlations, and graph-derived signals are investigative leads only.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    "Nothing in this response restricts, freezes, blocks, or blacklists any account.",
)


# -----------------------------------------------------------------------------
# Column maps for stable pagination
# -----------------------------------------------------------------------------

_ACCOUNT_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": Account.id,
    "created_at": Account.created_at,
    "updated_at": Account.record_updated_at,
    "status": Account.status,
    "account_type": Account.account_type,
}

_TRANSACTION_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": Transaction.id,
    "occurred_at": Transaction.occurred_at,
    "amount": Transaction.amount,
    "status": Transaction.status,
    "channel": Transaction.channel,
    "reference": Transaction.reference,
}

_ASSESSMENT_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": ModelAssessment.id,
    "scored_at": ModelAssessment.scored_at,
    "as_of": ModelAssessment.as_of,
    "score": ModelAssessment.score,
    "risk_band": ModelAssessment.risk_band,
    "scoring_mode": ModelAssessment.scoring_mode,
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

_ENTITY_LINK_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": AccountEntityLink.id,
    "valid_from": AccountEntityLink.valid_from,
    "created_at": AccountEntityLink.record_created_at,
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


# -----------------------------------------------------------------------------
# Reusable bounded dependencies
# -----------------------------------------------------------------------------

account_pagination = pagination_dependency(
    sortable_fields=tuple(_ACCOUNT_COLUMN_MAP.keys()),
    default_sort_by="created_at",
    default_sort_order="desc",
)

transaction_pagination = pagination_dependency(
    sortable_fields=tuple(_TRANSACTION_COLUMN_MAP.keys()),
    default_sort_by="occurred_at",
    default_sort_order="desc",
)

assessment_pagination = pagination_dependency(
    sortable_fields=tuple(_ASSESSMENT_COLUMN_MAP.keys()),
    default_sort_by="scored_at",
    default_sort_order="desc",
)

alert_pagination = pagination_dependency(
    sortable_fields=tuple(_ALERT_COLUMN_MAP.keys()),
    default_sort_by="created_at",
    default_sort_order="desc",
)

entity_link_pagination = pagination_dependency(
    sortable_fields=tuple(_ENTITY_LINK_COLUMN_MAP.keys()),
    default_sort_by="valid_from",
    default_sort_order="desc",
)

correlation_pagination = pagination_dependency(
    sortable_fields=tuple(_CORRELATION_COLUMN_MAP.keys()),
    default_sort_by="created_at",
    default_sort_order="desc",
)

# These date-range dependencies validate ordering. Endpoint-specific maximum
# span checks are applied where aggregation or expensive scanning occurs.
transaction_date_range = date_range_dependency(max_span_days=0)
summary_date_range = date_range_dependency(max_span_days=0)

transaction_amount_range = amount_range_dependency(allow_negative=False)

account_search = search_dependency(max_length=200, alias="q")
transaction_search = search_dependency(max_length=200, alias="q")
entity_link_search = search_dependency(max_length=200, alias="q")
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


def _to_decimal(value: Any) -> Optional[Decimal]:
    """
    Convert a database/Python value to Decimal without raising.
    """
    if value is None:
        return None

    if isinstance(value, Decimal):
        return value

    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None


def _safe_string_list(value: Any, *, max_items: int = _MAX_EVIDENCE_REFS) -> list[str]:
    """
    Return a bounded list of safe strings.

    This is used for evidence references and rule-code lists. It intentionally
    avoids returning nested objects or unbounded text.
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
        text = str(item).strip()

        if not text:
            continue

        if len(text) > _MAX_STRING_LENGTH:
            text = text[:_MAX_STRING_LENGTH]

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

    This intentionally avoids returning secrets, raw narratives, ground-truth
    labels, scenario metadata, binary blobs, or unbounded object graphs.
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
        if len(value) <= _MAX_STRING_LENGTH:
            return value
        return value[:_MAX_STRING_LENGTH] + "...[truncated]"

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


def _ensure_accounts_enabled(settings: Any) -> None:
    """
    Fail closed when the account API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "ACCOUNTS_API_ENABLED", True), True):
        raise FeatureFlagDisabledError("Account endpoints are disabled by configuration.")


def _normalize_currency(value: Optional[str], settings: Any) -> str:
    """
    Normalize and validate a currency filter/default.
    """
    currency = str(value or _setting(settings, "BACKEND_DEFAULT_CURRENCY", "INR") or "INR").strip().upper()

    if not currency:
        currency = "INR"

    if len(currency) != 3:
        raise MuleGuardValidationError(
            "Currency must be a three-letter code.",
            details={"currency": currency[:16]},
        )

    return currency


def _validate_not_future(value: Optional[datetime], field_name: str) -> None:
    """
    Reject future point-in-time parameters.
    """
    if value is not None and value > _now_utc():
        raise MuleGuardValidationError(
            f"{field_name} must not be in the future.",
            details={field_name: value.isoformat()},
        )


# -----------------------------------------------------------------------------
# Account lookup helpers
# -----------------------------------------------------------------------------


def _get_account_or_404(db: Session, account_id: str) -> Account:
    """
    Load a synthetic account or raise a safe not-found error.
    """
    account = db.get(Account, account_id)

    if account is None:
        raise NotFoundError.resource("account", account_id)

    return account


# -----------------------------------------------------------------------------
# Assessment helpers
# -----------------------------------------------------------------------------


def _latest_assessment_for_account(
    db: Session,
    account_id: str,
    *,
    as_of: Optional[datetime] = None,
) -> Optional[ModelAssessment]:
    """
    Return the latest persisted assessment for an account.

    When `as_of` is supplied, only assessments whose point-in-time `as_of`
    timestamp is less than or equal to the requested time are considered.
    """
    stmt = select(ModelAssessment).where(ModelAssessment.account_id == account_id)

    if as_of is not None:
        stmt = stmt.where(ModelAssessment.as_of <= as_of)
        stmt = stmt.order_by(
            desc(ModelAssessment.as_of),
            desc(ModelAssessment.scored_at),
            desc(ModelAssessment.id),
        )
    else:
        stmt = stmt.order_by(
            desc(ModelAssessment.scored_at),
            desc(ModelAssessment.as_of),
            desc(ModelAssessment.id),
        )

    return db.scalar(stmt.limit(1))


def _latest_assessments_for_account_ids(
    db: Session,
    account_ids: Sequence[str],
) -> dict[str, ModelAssessment]:
    """
    Return latest persisted assessments for a bounded set of account IDs.

    This avoids N+1 queries in account list responses while remaining portable
    across SQLite and PostgreSQL.
    """
    ids = [str(account_id) for account_id in account_ids if account_id]

    if not ids:
        return {}

    stmt = (
        select(ModelAssessment)
        .where(ModelAssessment.account_id.in_(ids))
        .order_by(
            ModelAssessment.account_id.asc(),
            desc(ModelAssessment.scored_at),
            desc(ModelAssessment.as_of),
            desc(ModelAssessment.id),
        )
    )

    latest: dict[str, ModelAssessment] = {}

    for assessment in db.scalars(stmt).all():
        if assessment.account_id not in latest:
            latest[assessment.account_id] = assessment

    return latest


def _collect_evidence_refs(*values: Any) -> list[str]:
    """
    Collect and deduplicate evidence references from indicator/rule payloads.
    """
    combined: list[Any] = []

    for value in values:
        if value is None:
            continue

        if isinstance(value, Mapping):
            continue

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            combined.extend(value)
        else:
            combined.append(value)

    return _safe_string_list(combined, max_items=_MAX_EVIDENCE_REFS)


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class LatestAssessmentSummary(BaseModel):
    """
    Safe summary of a persisted account assessment.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_id: str
    as_of: datetime
    scored_at: datetime
    scoring_mode: str
    score: Decimal
    score_type: str
    score_version: Optional[str] = None
    risk_band: str
    model_version_id: Optional[str] = None
    feature_snapshot_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    dataset_fingerprint: Optional[str] = None
    explanation_available: bool = False
    indicator_count: Optional[int] = None


class AccountResponse(BaseModel):
    """
    Safe synthetic account profile.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_type: str
    status: str
    created_at: datetime
    metadata_json: Optional[Any] = None
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None
    latest_assessment: Optional[LatestAssessmentSummary] = None


class AccountListResponse(BaseModel):
    """
    Paginated account list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[AccountResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    # Every other collection in the API carries its interpretation limits, and
    # this one needs them most: each row holds a risk band and a score, which
    # is the number most likely to be read as a verdict and quoted without
    # qualification. The field was the only list envelope in the API without
    # it, so a client built one reader for the others and silently dropped the
    # caveats here.
    caveats: list[str] = Field(default_factory=list)


class TransactionResponse(BaseModel):
    """
    Safe transaction evidence row relative to an account.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    direction: str
    counterparty_account_id: Optional[str] = None
    amount: Decimal
    currency: str
    occurred_at: datetime
    status: str
    channel: str
    reference: str
    metadata_json: Optional[Any] = None
    record_created_at: Optional[datetime] = None


class TransactionListResponse(BaseModel):
    """
    Paginated transaction list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[TransactionResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"


class AccountSummaryResponse(BaseModel):
    """
    Bounded persisted aggregate summary for one synthetic account.

    Monetary aggregates are calculated only for completed transfers in the
    selected currency. Failed, pending, and reversed records are counted
    separately and are not treated as completed fund movement.
    """

    model_config = ConfigDict(from_attributes=False)

    account_id: str
    window: dict[str, Any]
    currency: str

    incoming_completed_count: int
    incoming_completed_amount: Decimal
    outgoing_completed_count: int
    outgoing_completed_amount: Decimal
    net_completed_amount: Decimal

    distinct_incoming_counterparties: int
    distinct_outgoing_recipients: int
    self_transfer_count: int

    pending_count: int
    failed_count: int
    reversed_count: int

    latest_assessment: Optional[LatestAssessmentSummary] = None
    open_alert_count: int = 0
    complaint_correlation_count: int = 0
    active_entity_link_count: int = 0

    caveats: list[str] = Field(default_factory=list)


class IndicatorResponse(BaseModel):
    """
    Evidence-backed risk indicator attached to an assessment.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    indicator_type: str
    code: str
    title: str
    severity: str
    measured_value: Optional[Decimal] = None
    threshold: Optional[Decimal] = None
    explanation: Optional[str] = None
    evidence_refs: list[str] = Field(default_factory=list)
    rule_hit_id: Optional[str] = None


class RuleHitResponse(BaseModel):
    """
    Persisted triggered rule result.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    rule_code: str
    rule_version: str
    triggered: bool
    measured_value: Optional[Decimal] = None
    threshold: Optional[Decimal] = None
    severity: str
    explanation: Optional[str] = None
    evidence_refs: list[str] = Field(default_factory=list)
    evaluated_at: datetime


class AssessmentDetail(BaseModel):
    """
    Full persisted assessment detail for analyst review.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_id: str
    as_of: datetime
    scored_at: datetime
    scoring_mode: str
    score: Decimal
    score_type: str
    score_version: Optional[str] = None
    risk_band: str
    model_version_id: Optional[str] = None
    feature_snapshot_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    dataset_fingerprint: Optional[str] = None
    components_json: Optional[Any] = None
    explanation_json: Optional[Any] = None
    caveats_json: Optional[Any] = None
    evidence_refs: list[str] = Field(default_factory=list)


class AccountAssessmentResponse(BaseModel):
    """
    Assessment response that honestly reports missing persisted assessments.
    """

    model_config = ConfigDict(from_attributes=False)

    available: bool
    status: Literal["available", "no_assessment"]
    message: Optional[str] = None
    assessment: Optional[AssessmentDetail] = None
    indicators: list[IndicatorResponse] = Field(default_factory=list)
    rule_hits: list[RuleHitResponse] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class AssessmentHistoryResponse(BaseModel):
    """
    Paginated assessment history response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[LatestAssessmentSummary]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"


class AlertResponse(BaseModel):
    """
    Safe investigative alert summary for an account.
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


class EntityLinkResponse(BaseModel):
    """
    Time-bound account-entity relationship.

    Raw identifier hashes are intentionally not returned. Only synthetic display
    labels and provenance-safe metadata are exposed.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_id: str
    entity_id: str
    entity_type: str
    identifier_display: Optional[str] = None
    source: str
    match_method: str
    confidence: Optional[Decimal] = None
    verification_state: str
    valid_from: datetime
    valid_to: Optional[datetime] = None
    metadata_json: Optional[Any] = None


class EntityLinkListResponse(BaseModel):
    """
    Paginated entity-link list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[EntityLinkResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"


class ComplaintCorrelationResponse(BaseModel):
    """
    Complaint correlation view for an account.

    Raw and normalized complaint narratives are intentionally not returned.
    Exact matches are distinguished from inferred associations through
    `match_tier`, `match_method`, `deterministic`, and `confidence`.
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

    account_id: Optional[str] = None
    transaction_id: Optional[str] = None
    entity_id: Optional[str] = None

    match_tier: int
    match_method: str
    confidence: Optional[Decimal] = None
    deterministic: bool
    review_state: str
    evidence_refs: list[str] = Field(default_factory=list)
    record_created_at: Optional[datetime] = None


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


# -----------------------------------------------------------------------------
# Response builders
# -----------------------------------------------------------------------------


def _latest_assessment_summary(assessment: ModelAssessment) -> LatestAssessmentSummary:
    """
    Build a safe summary from a persisted assessment.
    """
    return LatestAssessmentSummary(
        id=str(assessment.id),
        account_id=str(assessment.account_id),
        as_of=assessment.as_of,
        scored_at=assessment.scored_at,
        scoring_mode=_enum_str(assessment.scoring_mode) or "unknown",
        score=assessment.score,
        score_type=str(assessment.score_type),
        score_version=str(assessment.score_version) if assessment.score_version else None,
        risk_band=_enum_str(assessment.risk_band) or "LOW",
        model_version_id=str(assessment.model_version_id) if assessment.model_version_id else None,
        feature_snapshot_id=(
            str(assessment.feature_snapshot_id) if assessment.feature_snapshot_id else None
        ),
        analysis_run_id=str(assessment.analysis_run_id) if assessment.analysis_run_id else None,
        dataset_fingerprint=(
            str(assessment.dataset_fingerprint) if assessment.dataset_fingerprint else None
        ),
        explanation_available=bool(assessment.explanation_json),
        indicator_count=None,
    )


def _account_response(
    account: Account,
    latest_assessment: Optional[ModelAssessment] = None,
    settings: Any | None = None,
) -> AccountResponse:
    """
    Build a safe account response.

    Ground-truth labels, scenario IDs, and ring IDs are never queried or
    returned by this endpoint module.
    """
    _ = settings

    return AccountResponse(
        id=str(account.id),
        account_type=_enum_str(account.account_type) or "OTHER",
        status=_enum_str(account.status) or "ACTIVE",
        created_at=account.created_at,
        metadata_json=_response_metadata(account.metadata_json),
        record_created_at=getattr(account, "record_created_at", None),
        record_updated_at=getattr(account, "record_updated_at", None),
        latest_assessment=(
            _latest_assessment_summary(latest_assessment)
            if latest_assessment is not None
            else None
        ),
    )


def _transaction_response(transaction: Transaction, account_id: str) -> TransactionResponse:
    """
    Build a transaction response relative to the requested account.
    """
    sender = str(transaction.sender_account_id)
    receiver = str(transaction.receiver_account_id)

    if sender == account_id and receiver == account_id:
        direction = "self"
        counterparty = account_id
    elif sender == account_id:
        direction = "outgoing"
        counterparty = receiver
    elif receiver == account_id:
        direction = "incoming"
        counterparty = sender
    else:
        direction = "related"
        counterparty = None

    return TransactionResponse(
        id=str(transaction.id),
        direction=direction,
        counterparty_account_id=counterparty,
        amount=transaction.amount,
        currency=str(transaction.currency),
        occurred_at=transaction.occurred_at,
        status=_enum_str(transaction.status) or "UNKNOWN",
        channel=_enum_str(transaction.channel) or "UNKNOWN",
        reference=str(transaction.reference),
        metadata_json=_response_metadata(transaction.metadata_json),
        record_created_at=getattr(transaction, "record_created_at", None),
    )


def _indicator_response(indicator: RiskIndicator) -> IndicatorResponse:
    """
    Build a safe indicator response.
    """
    return IndicatorResponse(
        id=str(indicator.id),
        indicator_type=_enum_str(indicator.indicator_type) or "UNKNOWN",
        code=str(indicator.code),
        title=str(indicator.title),
        severity=_enum_str(indicator.severity) or "LOW",
        measured_value=indicator.measured_value,
        threshold=indicator.threshold,
        explanation=str(indicator.explanation) if indicator.explanation else None,
        evidence_refs=_safe_string_list(indicator.evidence_refs_json),
        rule_hit_id=str(indicator.rule_hit_id) if indicator.rule_hit_id else None,
    )


def _rule_hit_response(rule_hit: RuleHit) -> RuleHitResponse:
    """
    Build a safe rule-hit response.
    """
    return RuleHitResponse(
        id=str(rule_hit.id),
        rule_code=str(rule_hit.rule_code),
        rule_version=str(rule_hit.rule_version),
        triggered=bool(rule_hit.triggered),
        measured_value=rule_hit.measured_value,
        threshold=rule_hit.threshold,
        severity=_enum_str(rule_hit.severity) or "LOW",
        explanation=str(rule_hit.explanation) if rule_hit.explanation else None,
        evidence_refs=_safe_string_list(rule_hit.evidence_refs_json),
        evaluated_at=rule_hit.evaluated_at,
    )


def _assessment_detail_response(
    assessment: ModelAssessment,
    indicators: Sequence[RiskIndicator],
    rule_hits: Sequence[RuleHit],
) -> AssessmentDetail:
    """
    Build a full persisted assessment detail response.
    """
    evidence_refs = _collect_evidence_refs(
        *[indicator.evidence_refs_json for indicator in indicators],
        *[rule_hit.evidence_refs_json for rule_hit in rule_hits],
    )

    return AssessmentDetail(
        id=str(assessment.id),
        account_id=str(assessment.account_id),
        as_of=assessment.as_of,
        scored_at=assessment.scored_at,
        scoring_mode=_enum_str(assessment.scoring_mode) or "unknown",
        score=assessment.score,
        score_type=str(assessment.score_type),
        score_version=str(assessment.score_version) if assessment.score_version else None,
        risk_band=_enum_str(assessment.risk_band) or "LOW",
        model_version_id=str(assessment.model_version_id) if assessment.model_version_id else None,
        feature_snapshot_id=(
            str(assessment.feature_snapshot_id) if assessment.feature_snapshot_id else None
        ),
        analysis_run_id=str(assessment.analysis_run_id) if assessment.analysis_run_id else None,
        dataset_fingerprint=(
            str(assessment.dataset_fingerprint) if assessment.dataset_fingerprint else None
        ),
        components_json=_response_metadata(assessment.components_json),
        explanation_json=_response_metadata(assessment.explanation_json),
        caveats_json=_response_metadata(assessment.caveats_json),
        evidence_refs=evidence_refs,
    )


def _alert_response(alert: Alert) -> AlertResponse:
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
        record_created_at=getattr(alert, "record_created_at", None),
    )


def _entity_link_response(link: AccountEntityLink, entity: Entity) -> EntityLinkResponse:
    """
    Build a safe entity-link response.

    Raw identifier hashes are intentionally omitted.
    """
    return EntityLinkResponse(
        id=str(link.id),
        account_id=str(link.account_id),
        entity_id=str(entity.id),
        entity_type=_enum_str(entity.entity_type) or "OTHER",
        identifier_display=str(entity.identifier_display) if entity.identifier_display else None,
        source=str(entity.source or link.source or "synthetic"),
        match_method=_enum_str(link.match_method) or "UNKNOWN",
        confidence=link.confidence,
        verification_state=_enum_str(link.verification_state) or "UNVERIFIED",
        valid_from=link.valid_from,
        valid_to=link.valid_to,
        metadata_json=_response_metadata(link.metadata_json),
    )


def _correlation_response(
    correlation: ComplaintCorrelation,
    complaint: Complaint,
) -> ComplaintCorrelationResponse:
    """
    Build a safe complaint-correlation response.

    Raw and normalized narratives are intentionally omitted.
    """
    return ComplaintCorrelationResponse(
        id=str(correlation.id),
        complaint_id=str(complaint.id),
        complaint_reference=str(complaint.reference),
        complaint_category=str(complaint.category),
        reported_at=complaint.reported_at,
        complaint_amount=complaint.amount,
        complaint_currency=str(complaint.currency) if complaint.currency else None,
        complaint_source=str(complaint.source) if complaint.source else None,
        complaint_narrative_available=bool(_str_or_none(complaint.narrative_raw)),
        account_id=str(correlation.account_id) if correlation.account_id else None,
        transaction_id=str(correlation.transaction_id) if correlation.transaction_id else None,
        entity_id=str(correlation.entity_id) if correlation.entity_id else None,
        match_tier=int(correlation.match_tier),
        match_method=_enum_str(correlation.match_method) or "UNKNOWN",
        confidence=correlation.confidence,
        deterministic=bool(correlation.deterministic),
        review_state=_enum_str(correlation.review_state) or "UNREVIEWED",
        evidence_refs=_safe_string_list(correlation.evidence_refs_json),
        record_created_at=getattr(correlation, "record_created_at", None),
    )


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "",
    response_model=AccountListResponse,
    summary="List synthetic accounts",
    description=(
        "Returns a paginated, filtered, and stably ordered list of synthetic "
        "MULEGUARD accounts. This endpoint is read-only and does not take any "
        "adverse action. Account risk scores, when included, are investigative "
        "priority scores derived from persisted assessments, not probabilities "
        "of guilt."
    ),
)
def list_accounts(
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(account_pagination),
    search: SearchParams = Depends(account_search),
    _: User = Depends(require_permission(Permission.ACCOUNT_READ)),
    account_type: Annotated[
        Optional[AccountType],
        Query(description="Filter by synthetic account type."),
    ] = None,
    status: Annotated[
        Optional[AccountStatus],
        Query(description="Filter by synthetic account lifecycle status."),
    ] = None,
    created_from: Annotated[
        Optional[datetime],
        Query(description="Filter accounts created at or after this UTC timestamp."),
    ] = None,
    created_to: Annotated[
        Optional[datetime],
        Query(description="Filter accounts created at or before this UTC timestamp."),
    ] = None,
    include_latest_assessment: Annotated[
        bool,
        Query(description="Include latest persisted assessment summary for each returned account."),
    ] = False,
) -> AccountListResponse:
    """
    List synthetic accounts with bounded pagination and safe filters.
    """
    _ensure_accounts_enabled(settings)

    start = _ensure_utc(created_from)
    end = _ensure_utc(created_to)

    if start is not None and end is not None and start > end:
        raise MuleGuardValidationError(
            "created_from must be earlier than or equal to created_to.",
            details={
                "created_from": start.isoformat(),
                "created_to": end.isoformat(),
            },
        )

    conditions: list[Any] = []

    if account_type is not None:
        conditions.append(Account.account_type == account_type)

    if status is not None:
        conditions.append(Account.status == status)

    if start is not None:
        conditions.append(Account.created_at >= start)

    if end is not None:
        conditions.append(Account.created_at <= end)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(func.lower(Account.id).like(pattern))

    count_stmt = select(func.count()).select_from(Account)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(Account)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_ACCOUNT_COLUMN_MAP,
        tiebreaker=Account.id,
        default_sort_by="created_at",
        default_sort_order="desc",
    )

    accounts = db.scalars(stmt).all()

    latest_map: dict[str, ModelAssessment] = {}

    if include_latest_assessment and accounts:
        latest_map = _latest_assessments_for_account_ids(
            db,
            [str(account.id) for account in accounts],
        )

    items = [
        _account_response(
            account,
            latest_map.get(str(account.id)),
            settings,
        )
        for account in accounts
    ]

    return AccountListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_ACCOUNT_LIST_CAVEATS),
    )


@router.get(
    "/{account_id}",
    response_model=AccountResponse,
    summary="Get a synthetic account profile",
    description=(
        "Returns a safe profile for one synthetic MULEGUARD account, including "
        "the latest persisted assessment summary when available. This endpoint "
        "does not expose ground-truth labels, scenario IDs, ring IDs, secrets, "
        "tokens, or real customer data."
    ),
)
def get_account(
    account_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic account identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.ACCOUNT_READ)),
) -> AccountResponse:
    """
    Retrieve one synthetic account profile.
    """
    _ensure_accounts_enabled(settings)

    account = _get_account_or_404(db, account_id)
    latest = _latest_assessment_for_account(db, str(account.id))

    return _account_response(account, latest, settings)


@router.get(
    "/{account_id}/summary",
    response_model=AccountSummaryResponse,
    summary="Get a bounded synthetic account activity summary",
    description=(
        "Returns bounded persisted aggregate activity metrics for one synthetic "
        "account within a date window and currency. Completed transfers are "
        "treated as fund movement. Pending, failed, and reversed records are "
        "counted separately and are not treated as completed transfers. "
        "Monetary aggregates are not mixed across currencies."
    ),
)
def get_account_summary(
    account_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic account identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    date_range: DateRangeParams = Depends(summary_date_range),
    _: User = Depends(require_permission(Permission.ACCOUNT_READ)),
    currency: Annotated[
        Optional[str],
        Query(max_length=3, description="Currency for monetary aggregates. Defaults to configured currency."),
    ] = None,
) -> AccountSummaryResponse:
    """
    Build a bounded account summary from persisted transaction and assessment
    records.
    """
    _ensure_accounts_enabled(settings)

    account = _get_account_or_404(db, account_id)
    account_id = str(account.id)

    max_span_days = max(
        1,
        min(
            _as_int(
                _setting(
                    settings,
                    "ACCOUNT_SUMMARY_MAX_DATE_SPAN_DAYS",
                    _setting(settings, "GRAPH_MAX_DATE_SPAN_DAYS", 90),
                ),
                90,
            ),
            3650,
        ),
    )

    now = _now_utc()
    date_from = date_range.date_from
    date_to = date_range.date_to
    defaulted = False

    if date_to is None:
        date_to = now
        defaulted = True

    if date_from is None:
        date_from = date_to - timedelta(days=max_span_days)
        defaulted = True

    if date_from > date_to:
        raise MuleGuardValidationError(
            "date_from must be earlier than or equal to date_to.",
            details={
                "date_from": date_from.isoformat(),
                "date_to": date_to.isoformat(),
            },
        )

    span_days = (date_to - date_from).total_seconds() / 86400.0

    if span_days > max_span_days + 1e-9:
        raise MuleGuardValidationError(
            "Summary date span exceeds configured maximum.",
            details={
                "max_span_days": max_span_days,
                "requested_span_days": round(span_days, 3),
            },
        )

    effective_currency = _normalize_currency(currency, settings)

    completed = TransactionStatus.COMPLETED
    pending = TransactionStatus.PENDING
    failed = TransactionStatus.FAILED
    reversed_status = TransactionStatus.REVERSED

    time_currency_conditions = [
        Transaction.occurred_at >= date_from,
        Transaction.occurred_at <= date_to,
        Transaction.currency == effective_currency,
    ]

    account_involved = or_(
        Transaction.sender_account_id == account_id,
        Transaction.receiver_account_id == account_id,
    )

    incoming_cond = and_(
        Transaction.receiver_account_id == account_id,
        Transaction.status == completed,
        *time_currency_conditions,
    )

    outgoing_cond = and_(
        Transaction.sender_account_id == account_id,
        Transaction.status == completed,
        *time_currency_conditions,
    )

    self_cond = and_(
        Transaction.sender_account_id == account_id,
        Transaction.receiver_account_id == account_id,
        Transaction.status == completed,
        *time_currency_conditions,
    )

    pending_cond = and_(
        account_involved,
        Transaction.status == pending,
        *time_currency_conditions,
    )

    failed_cond = and_(
        account_involved,
        Transaction.status == failed,
        *time_currency_conditions,
    )

    reversed_cond = and_(
        account_involved,
        Transaction.status == reversed_status,
        *time_currency_conditions,
    )

    base_cond = and_(
        account_involved,
        *time_currency_conditions,
    )

    stmt = select(
        func.count(case((incoming_cond, 1), else_=None)).label("incoming_count"),
        func.coalesce(
            func.sum(case((incoming_cond, Transaction.amount), else_=0)),
            0,
        ).label("incoming_amount"),
        func.count(case((outgoing_cond, 1), else_=None)).label("outgoing_count"),
        func.coalesce(
            func.sum(case((outgoing_cond, Transaction.amount), else_=0)),
            0,
        ).label("outgoing_amount"),
        func.count(distinct(case((incoming_cond, Transaction.sender_account_id), else_=None))).label(
            "distinct_incoming_counterparties"
        ),
        func.count(distinct(case((outgoing_cond, Transaction.receiver_account_id), else_=None))).label(
            "distinct_outgoing_recipients"
        ),
        func.count(case((self_cond, 1), else_=None)).label("self_transfer_count"),
        func.count(case((pending_cond, 1), else_=None)).label("pending_count"),
        func.count(case((failed_cond, 1), else_=None)).label("failed_count"),
        func.count(case((reversed_cond, 1), else_=None)).label("reversed_count"),
    ).where(base_cond)

    row = db.execute(stmt).one()

    incoming_amount = _to_decimal(row.incoming_amount) or Decimal("0")
    outgoing_amount = _to_decimal(row.outgoing_amount) or Decimal("0")
    net_amount = incoming_amount - outgoing_amount

    latest = _latest_assessment_for_account(db, account_id, as_of=date_to)

    open_alert_count = _scalar_count(
        db,
        select(func.count())
        .select_from(Alert)
        .where(
            Alert.account_id == account_id,
            Alert.first_seen_at <= date_to,
            or_(Alert.closed_at.is_(None), Alert.closed_at > date_to),
            Alert.state != AlertState.CLOSED,
        ),
    )

    complaint_correlation_count = _scalar_count(
        db,
        select(func.count())
        .select_from(ComplaintCorrelation)
        .join(Complaint, Complaint.id == ComplaintCorrelation.complaint_id)
        .where(
            ComplaintCorrelation.account_id == account_id,
            Complaint.reported_at <= date_to,
        ),
    )

    active_entity_link_count = _scalar_count(
        db,
        select(func.count())
        .select_from(AccountEntityLink)
        .where(
            AccountEntityLink.account_id == account_id,
            AccountEntityLink.valid_from <= date_to,
            or_(
                AccountEntityLink.valid_to.is_(None),
                AccountEntityLink.valid_to >= date_to,
            ),
        ),
    )

    caveats = [
        "Synthetic prototype data only. Not real customer or bank data.",
        "Monetary aggregates include only completed transfers in the selected currency.",
        "Pending, failed, and reversed records are counted separately and are not treated as completed fund movement.",
        "Latest assessment score is an investigative priority score, not a probability of guilt.",
        "Entity links, complaint correlations, and graph-derived signals are investigative leads only.",
        "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    ]

    if defaulted:
        caveats.insert(0, "Date window was defaulted because one or both bounds were omitted.")

    return AccountSummaryResponse(
        account_id=account_id,
        window={
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
            "max_span_days": max_span_days,
            "defaulted": defaulted,
            "currency": effective_currency,
        },
        currency=effective_currency,
        incoming_completed_count=int(row.incoming_count or 0),
        incoming_completed_amount=incoming_amount,
        outgoing_completed_count=int(row.outgoing_count or 0),
        outgoing_completed_amount=outgoing_amount,
        net_completed_amount=net_amount,
        distinct_incoming_counterparties=int(row.distinct_incoming_counterparties or 0),
        distinct_outgoing_recipients=int(row.distinct_outgoing_recipients or 0),
        self_transfer_count=int(row.self_transfer_count or 0),
        pending_count=int(row.pending_count or 0),
        failed_count=int(row.failed_count or 0),
        reversed_count=int(row.reversed_count or 0),
        latest_assessment=_latest_assessment_summary(latest) if latest is not None else None,
        open_alert_count=open_alert_count,
        complaint_correlation_count=complaint_correlation_count,
        active_entity_link_count=active_entity_link_count,
        caveats=caveats,
    )


@router.get(
    "/{account_id}/transactions",
    response_model=TransactionListResponse,
    summary="List transactions involving a synthetic account",
    description=(
        "Returns paginated transaction evidence rows involving one synthetic "
        "account. Direction is expressed relative to the requested account. "
        "Failed, pending, and reversed transactions are preserved and must not "
        "be interpreted as completed fund movement."
    ),
)
def list_account_transactions(
    account_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic account identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(transaction_pagination),
    date_range: DateRangeParams = Depends(transaction_date_range),
    amount_range: AmountRangeParams = Depends(transaction_amount_range),
    search: SearchParams = Depends(transaction_search),
    _: User = Depends(require_permission(Permission.TRANSACTION_READ)),
    direction: Annotated[
        TransactionDirection,
        Query(description="Transaction direction relative to the requested account."),
    ] = "both",
    counterparty_account_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by counterparty account identifier."),
    ] = None,
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
) -> TransactionListResponse:
    """
    List transactions involving one synthetic account.
    """
    _ensure_accounts_enabled(settings)

    account = _get_account_or_404(db, account_id)
    account_id = str(account.id)

    conditions: list[Any] = []

    if direction == "incoming":
        conditions.append(Transaction.receiver_account_id == account_id)

        if counterparty_account_id:
            conditions.append(Transaction.sender_account_id == counterparty_account_id)

    elif direction == "outgoing":
        conditions.append(Transaction.sender_account_id == account_id)

        if counterparty_account_id:
            conditions.append(Transaction.receiver_account_id == counterparty_account_id)

    elif direction == "self":
        conditions.append(Transaction.sender_account_id == account_id)
        conditions.append(Transaction.receiver_account_id == account_id)

        if counterparty_account_id:
            conditions.append(Transaction.sender_account_id == counterparty_account_id)

    else:
        conditions.append(
            or_(
                Transaction.sender_account_id == account_id,
                Transaction.receiver_account_id == account_id,
            )
        )

        if counterparty_account_id:
            conditions.append(
                or_(
                    and_(
                        Transaction.receiver_account_id == account_id,
                        Transaction.sender_account_id == counterparty_account_id,
                    ),
                    and_(
                        Transaction.sender_account_id == account_id,
                        Transaction.receiver_account_id == counterparty_account_id,
                    ),
                )
            )

    if status is not None:
        conditions.append(Transaction.status == status)

    if channel is not None:
        conditions.append(Transaction.channel == channel)

    if currency is not None:
        conditions.append(Transaction.currency == _normalize_currency(currency, settings))

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

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(
            or_(
                func.lower(Transaction.reference).like(pattern),
                func.lower(Transaction.id).like(pattern),
            )
        )

    count_stmt = select(func.count()).select_from(Transaction)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(Transaction)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_TRANSACTION_COLUMN_MAP,
        tiebreaker=Transaction.id,
        default_sort_by="occurred_at",
        default_sort_order="desc",
    )

    transactions = db.scalars(stmt).all()

    items = [_transaction_response(transaction, account_id) for transaction in transactions]

    return TransactionListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
    )


@router.get(
    "/{account_id}/assessment",
    response_model=AccountAssessmentResponse,
    summary="Get latest or point-in-time persisted account assessment",
    description=(
        "Returns the latest persisted assessment for a synthetic account, or "
        "the latest assessment available at a requested point in time. This "
        "endpoint does not recompute ML scores. If no persisted assessment is "
        "available, it honestly reports `no_assessment` instead of fabricating "
        "a result."
    ),
)
def get_account_assessment(
    account_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic account identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.ACCOUNT_READ)),
    as_of: Annotated[
        Optional[datetime],
        Query(description="Point-in-time assessment cutoff in UTC. Defaults to latest."),
    ] = None,
) -> AccountAssessmentResponse:
    """
    Return latest or point-in-time persisted assessment detail.
    """
    _ensure_accounts_enabled(settings)

    account = _get_account_or_404(db, account_id)
    account_id = str(account.id)

    requested_as_of = _ensure_utc(as_of)
    _validate_not_future(requested_as_of, "as_of")

    assessment = _latest_assessment_for_account(db, account_id, as_of=requested_as_of)

    if assessment is None:
        return AccountAssessmentResponse(
            available=False,
            status="no_assessment",
            message=(
                "No persisted assessment is available for this account at the "
                "requested point in time. Run analysis or ingest assessment "
                "data before requesting an explanation."
            ),
            assessment=None,
            indicators=[],
            rule_hits=[],
            evidence_refs=[],
        )

    indicators = db.scalars(
        select(RiskIndicator)
        .where(RiskIndicator.assessment_id == assessment.id)
        .order_by(
            desc(RiskIndicator.record_created_at),
            RiskIndicator.code.asc(),
        )
    ).all()

    rule_hits = db.scalars(
        select(RuleHit)
        .where(
            RuleHit.assessment_id == assessment.id,
            RuleHit.triggered.is_(True),
        )
        .order_by(
            desc(RuleHit.evaluated_at),
            RuleHit.rule_code.asc(),
        )
    ).all()

    detail = _assessment_detail_response(assessment, indicators, rule_hits)

    return AccountAssessmentResponse(
        available=True,
        status="available",
        message=None,
        assessment=detail,
        indicators=[_indicator_response(indicator) for indicator in indicators],
        rule_hits=[_rule_hit_response(rule_hit) for rule_hit in rule_hits],
        evidence_refs=detail.evidence_refs,
    )


@router.get(
    "/{account_id}/assessments",
    response_model=AssessmentHistoryResponse,
    summary="List persisted assessment history for a synthetic account",
    description=(
        "Returns paginated persisted assessment history for one synthetic "
        "account. History is read from persisted ModelAssessment records and "
        "does not recompute scores."
    ),
)
def list_account_assessments(
    account_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic account identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(assessment_pagination),
    _: User = Depends(require_permission(Permission.ACCOUNT_READ)),
    scoring_mode: Annotated[
        Optional[ScoringMode],
        Query(description="Filter by scoring mode."),
    ] = None,
    risk_band: Annotated[
        Optional[RiskBand],
        Query(description="Filter by risk band."),
    ] = None,
) -> AssessmentHistoryResponse:
    """
    List assessment history for one account.
    """
    _ensure_accounts_enabled(settings)

    account = _get_account_or_404(db, account_id)
    account_id = str(account.id)

    conditions: list[Any] = [ModelAssessment.account_id == account_id]

    if scoring_mode is not None:
        conditions.append(ModelAssessment.scoring_mode == scoring_mode)

    if risk_band is not None:
        conditions.append(ModelAssessment.risk_band == risk_band)

    count_stmt = select(func.count()).select_from(ModelAssessment)
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = select(ModelAssessment)
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_ASSESSMENT_COLUMN_MAP,
        tiebreaker=ModelAssessment.id,
        default_sort_by="scored_at",
        default_sort_order="desc",
    )

    assessments = db.scalars(stmt).all()

    return AssessmentHistoryResponse(
        items=[_latest_assessment_summary(assessment) for assessment in assessments],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
    )


@router.get(
    "/{account_id}/alerts",
    response_model=AlertListResponse,
    summary="List investigative alerts for a synthetic account",
    description=(
        "Returns paginated investigative alerts associated with one synthetic "
        "account. Alerts are investigative leads only and must not be treated "
        "as proof of wrongdoing or used for automatic adverse action."
    ),
)
def list_account_alerts(
    account_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic account identifier."),
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
) -> AlertListResponse:
    """
    List alerts for one account.
    """
    _ensure_accounts_enabled(settings)

    account = _get_account_or_404(db, account_id)
    account_id = str(account.id)

    conditions: list[Any] = [Alert.account_id == account_id]

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

    return AlertListResponse(
        items=[_alert_response(alert) for alert in alerts],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
    )


@router.get(
    "/{account_id}/entities",
    response_model=EntityLinkListResponse,
    summary="List time-bound entity links for a synthetic account",
    description=(
        "Returns paginated time-bound relationships between one synthetic "
        "account and pseudonymous synthetic entities such as devices, hashed "
        "phones, UPI IDs, or other identifiers. Shared entities are "
        "investigative associations only and are not proof of common control "
        "or wrongdoing. Raw identifier hashes are not returned."
    ),
)
def list_account_entities(
    account_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic account identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(entity_link_pagination),
    search: SearchParams = Depends(entity_link_search),
    _: User = Depends(require_permission(Permission.ACCOUNT_READ)),
    entity_type: Annotated[
        Optional[EntityType],
        Query(description="Filter by entity type."),
    ] = None,
    verification_state: Annotated[
        Optional[VerificationState],
        Query(description="Filter by link verification state."),
    ] = None,
    match_method: Annotated[
        Optional[MatchMethod],
        Query(description="Filter by link match method."),
    ] = None,
    as_of: Annotated[
        Optional[datetime],
        Query(description="Return links valid at this UTC point in time."),
    ] = None,
) -> EntityLinkListResponse:
    """
    List entity links for one account.
    """
    _ensure_accounts_enabled(settings)

    account = _get_account_or_404(db, account_id)
    account_id = str(account.id)

    requested_as_of = _ensure_utc(as_of)
    _validate_not_future(requested_as_of, "as_of")

    conditions: list[Any] = [AccountEntityLink.account_id == account_id]

    if entity_type is not None:
        conditions.append(Entity.entity_type == entity_type)

    if verification_state is not None:
        conditions.append(AccountEntityLink.verification_state == verification_state)

    if match_method is not None:
        conditions.append(AccountEntityLink.match_method == match_method)

    if requested_as_of is not None:
        conditions.append(AccountEntityLink.valid_from <= requested_as_of)
        conditions.append(
            or_(
                AccountEntityLink.valid_to.is_(None),
                AccountEntityLink.valid_to >= requested_as_of,
            )
        )

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(
            or_(
                func.lower(Entity.identifier_display).like(pattern),
                func.lower(AccountEntityLink.source).like(pattern),
            )
        )

    count_stmt = (
        select(func.count())
        .select_from(AccountEntityLink)
        .join(Entity, Entity.id == AccountEntityLink.entity_id)
    )
    count_stmt = _apply_conditions(count_stmt, conditions)
    total = _scalar_count(db, count_stmt)

    stmt = (
        select(AccountEntityLink, Entity)
        .join(Entity, Entity.id == AccountEntityLink.entity_id)
    )
    stmt = _apply_conditions(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_ENTITY_LINK_COLUMN_MAP,
        tiebreaker=AccountEntityLink.id,
        default_sort_by="valid_from",
        default_sort_order="desc",
    )

    rows = db.execute(stmt).all()

    items = [
        _entity_link_response(link, entity)
        for link, entity in rows
    ]

    return EntityLinkListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
    )


@router.get(
    "/{account_id}/complaint-correlations",
    response_model=ComplaintCorrelationListResponse,
    summary="List complaint correlations for a synthetic account",
    description=(
        "Returns paginated complaint correlations associated with one synthetic "
        "account. Exact matches are distinguished from inferred associations "
        "through match tier, method, determinism, and confidence. Raw and "
        "normalized complaint narratives are intentionally not returned."
    ),
)
def list_account_complaint_correlations(
    account_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic account identifier."),
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
) -> ComplaintCorrelationListResponse:
    """
    List complaint correlations for one account.
    """
    _ensure_accounts_enabled(settings)

    account = _get_account_or_404(db, account_id)
    account_id = str(account.id)

    conditions: list[Any] = [ComplaintCorrelation.account_id == account_id]

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

    return ComplaintCorrelationListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
    )


__all__ = [
    "router",
]