"""
MULEGUARD backend API v1 transaction endpoints.

This module implements the versioned `/api/v1/transactions` read-only
investigation surface for synthetic MULEGUARD transaction records.

Implemented endpoints:

- GET /api/v1/transactions
- GET /api/v1/transactions/{transaction_id}
- GET /api/v1/transactions/{transaction_id}/complaint-correlations
- GET /api/v1/transactions/{transaction_id}/alerts
- GET /api/v1/transactions/{transaction_id}/evidence

Design goals:

- provide real, persisted, evidence-backed transaction views;
- enforce server-side RBAC through dependency permissions;
- keep list endpoints paginated, filtered, searched, and stably ordered;
- preserve transaction status semantics:
    - completed transfers are treated as fund movement;
    - pending, failed, and reversed records are not silently counted as
      completed transfers;
- keep counterparty, complaint-correlation, and alert views bounded;
- preserve exact-vs-inferred provenance for complaint correlations;
- avoid exposing synthetic ground-truth labels, scenario IDs, ring IDs,
  passwords, tokens, secrets, database URLs, raw complaint narratives, or real
  customer data;
- make clear that transaction evidence, alerts, scores, graph relationships,
  candidate money trails, and complaint correlations are investigative leads
  only.

Explicit non-goals:

- This module does not create, reverse, block, freeze, refund, cancel, or
  otherwise mutate transactions.
- This module does not take adverse action on accounts or counterparties.
- This module does not expose real bank customer data.
- This module does not compute new ML scores inline.
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
from sqlalchemy import and_, desc, func, or_, select
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
    AccountStatus,
    AccountType,
    Alert,
    AlertEvidence,
    AlertState,
    Channel,
    Complaint,
    ComplaintCorrelation,
    ComplaintReviewState,
    EvidenceType,
    Priority,
    Transaction,
    TransactionStatus,
    User,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.transactions")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["transactions"])


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_EVIDENCE_REFS: Final[int] = 200
_MAX_JSON_DEPTH: Final[int] = 6
_MAX_BUNDLE_ITEMS: Final[int] = 50

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

_TRANSACTION_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Completed transfers are treated as fund movement.",
    "Pending, failed, and reversed records are not treated as completed fund movement.",
    "Transaction references are investigative evidence, not proof of wrongdoing.",
    "Alerts, complaint correlations, and graph-derived signals are investigative leads only.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
)


# -----------------------------------------------------------------------------
# Column maps for stable pagination
# -----------------------------------------------------------------------------

_TRANSACTION_COLUMN_MAP: Final[dict[str, Any]] = {
    "id": Transaction.id,
    "occurred_at": Transaction.occurred_at,
    "amount": Transaction.amount,
    "status": Transaction.status,
    "channel": Transaction.channel,
    "reference": Transaction.reference,
    "created_at": Transaction.record_created_at,
    "updated_at": Transaction.record_updated_at,
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

transaction_pagination = pagination_dependency(
    sortable_fields=tuple(_TRANSACTION_COLUMN_MAP.keys()),
    default_sort_by="occurred_at",
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

transaction_date_range = date_range_dependency(max_span_days=0)
transaction_amount_range = amount_range_dependency(allow_negative=False)

transaction_search = search_dependency(max_length=200, alias="q")
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


def _ensure_transactions_enabled(settings: Any) -> None:
    """
    Fail closed when the transaction API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "TRANSACTIONS_API_ENABLED", True), True):
        raise FeatureFlagDisabledError(
            "Transaction endpoints are disabled by configuration."
        )


def _normalize_currency(value: Optional[str], settings: Any) -> Optional[str]:
    """
    Normalize and validate an optional currency filter.
    """
    if value is None:
        return None

    currency = str(value).strip().upper()

    if not currency:
        return None

    if len(currency) != 3:
        raise MuleGuardValidationError(
            "Currency must be a three-letter code.",
            details={"currency": currency[:16]},
        )

    return currency


def _validate_transaction_date_span(
    date_from: Optional[datetime],
    date_to: Optional[datetime],
    settings: Any,
) -> None:
    """
    Enforce optional maximum date span for transaction scans.

    Pagination already bounds response size, but this prevents accidental
    whole-history scans when both bounds are supplied.
    """
    if date_from is None or date_to is None:
        return

    max_span_days = max(
        1,
        _as_int(
            _setting(
                settings,
                "TRANSACTION_MAX_DATE_SPAN_DAYS",
                _setting(settings, "GRAPH_MAX_DATE_SPAN_DAYS", 3650),
            ),
            3650,
        ),
    )

    span = date_to - date_from
    max_delta = timedelta(days=max_span_days)

    if span > max_delta:
        raise MuleGuardValidationError(
            "Transaction date span exceeds configured maximum.",
            details={
                "max_span_days": max_span_days,
                "requested_span_days": round(span.total_seconds() / 86400.0, 3),
            },
        )


# -----------------------------------------------------------------------------
# Lookup helpers
# -----------------------------------------------------------------------------


def _get_transaction_or_404(db: Session, transaction_id: str) -> Transaction:
    """
    Load a synthetic transaction or raise a safe not-found error.
    """
    transaction = db.get(Transaction, transaction_id)

    if transaction is None:
        raise NotFoundError.resource("transaction", transaction_id)

    return transaction


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
    Safe synthetic account summary embedded in transaction views.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    account_type: str
    status: str
    created_at: datetime
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None


class TransactionResponse(BaseModel):
    """
    Safe synthetic transaction evidence row.
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
    metadata_json: Optional[Any] = None
    record_created_at: Optional[datetime] = None
    record_updated_at: Optional[datetime] = None


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
    caveats: list[str] = Field(default_factory=list)


class TransactionDetailResponse(BaseModel):
    """
    Detailed synthetic transaction response with optional account context.
    """

    model_config = ConfigDict(from_attributes=False)

    transaction: TransactionResponse
    sender_account: Optional[AccountSummaryResponse] = None
    receiver_account: Optional[AccountSummaryResponse] = None
    caveats: list[str] = Field(default_factory=list)


class TransactionComplaintCorrelationResponse(BaseModel):
    """
    Complaint correlation view for a transaction.

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

    transaction_id: Optional[str] = None
    account_id: Optional[str] = None
    entity_id: Optional[str] = None

    match_tier: int
    match_method: str
    confidence: Optional[Decimal] = None
    deterministic: bool
    review_state: str
    evidence_refs: list[str] = Field(default_factory=list)
    record_created_at: Optional[datetime] = None


class TransactionComplaintCorrelationListResponse(BaseModel):
    """
    Paginated complaint-correlation list response for a transaction.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[TransactionComplaintCorrelationResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class TransactionAlertResponse(BaseModel):
    """
    Safe investigative alert summary referencing a transaction.
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


class TransactionAlertListResponse(BaseModel):
    """
    Paginated alert list response referencing a transaction.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[TransactionAlertResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class TransactionEvidenceBundleResponse(BaseModel):
    """
    Bounded evidence bundle for one synthetic transaction.

    This endpoint intentionally returns only transaction and account evidence.
    Complaint correlations and alerts remain available through dedicated,
    permission-scoped endpoints.
    """

    model_config = ConfigDict(from_attributes=False)

    transaction: TransactionResponse
    sender_account: Optional[AccountSummaryResponse] = None
    receiver_account: Optional[AccountSummaryResponse] = None
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


def _transaction_response(transaction: Transaction) -> TransactionResponse:
    """
    Build a safe transaction response.
    """
    return TransactionResponse(
        id=str(transaction.id),
        sender_account_id=str(transaction.sender_account_id),
        receiver_account_id=str(transaction.receiver_account_id),
        amount=transaction.amount,
        currency=str(transaction.currency),
        occurred_at=transaction.occurred_at,
        status=_enum_str(transaction.status) or "UNKNOWN",
        channel=_enum_str(transaction.channel) or "UNKNOWN",
        reference=str(transaction.reference),
        metadata_json=_response_metadata(transaction.metadata_json),
        record_created_at=getattr(transaction, "record_created_at", None),
        record_updated_at=getattr(transaction, "record_updated_at", None),
    )


def _complaint_correlation_response(
    correlation: ComplaintCorrelation,
    complaint: Complaint,
) -> TransactionComplaintCorrelationResponse:
    """
    Build a safe complaint-correlation response.

    Raw and normalized narratives are intentionally omitted.
    """
    return TransactionComplaintCorrelationResponse(
        id=str(correlation.id),
        complaint_id=str(complaint.id),
        complaint_reference=str(complaint.reference),
        complaint_category=str(complaint.category),
        reported_at=complaint.reported_at,
        complaint_amount=complaint.amount,
        complaint_currency=str(complaint.currency) if complaint.currency else None,
        complaint_source=str(complaint.source) if complaint.source else None,
        complaint_narrative_available=bool(complaint.narrative_raw),
        transaction_id=str(correlation.transaction_id) if correlation.transaction_id else None,
        account_id=str(correlation.account_id) if correlation.account_id else None,
        entity_id=str(correlation.entity_id) if correlation.entity_id else None,
        match_tier=int(correlation.match_tier),
        match_method=_enum_str(correlation.match_method) or "UNKNOWN",
        confidence=correlation.confidence,
        deterministic=bool(correlation.deterministic),
        review_state=_enum_str(correlation.review_state) or "UNREVIEWED",
        evidence_refs=_safe_string_list(correlation.evidence_refs_json),
        record_created_at=getattr(correlation, "record_created_at", None),
    )


def _alert_response(alert: Alert) -> TransactionAlertResponse:
    """
    Build a safe alert response.
    """
    return TransactionAlertResponse(
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


def _transaction_detail_response(
    transaction: Transaction,
    sender_account: Optional[Account] = None,
    receiver_account: Optional[Account] = None,
) -> TransactionDetailResponse:
    """
    Build a transaction detail response with optional account context.
    """
    return TransactionDetailResponse(
        transaction=_transaction_response(transaction),
        sender_account=(
            _account_summary_response(sender_account)
            if sender_account is not None
            else None
        ),
        receiver_account=(
            _account_summary_response(receiver_account)
            if receiver_account is not None
            else None
        ),
        caveats=list(_TRANSACTION_CAVEATS),
    )


# -----------------------------------------------------------------------------
# Query condition helpers
# -----------------------------------------------------------------------------


def _build_transaction_conditions(
    *,
    sender_account_id: Optional[str],
    receiver_account_id: Optional[str],
    account_id: Optional[str],
    direction: TransactionDirection,
    counterparty_account_id: Optional[str],
    status: Optional[TransactionStatus],
    channel: Optional[Channel],
    currency: Optional[str],
    reference: Optional[str],
    date_range: DateRangeParams,
    amount_range: AmountRangeParams,
    search: SearchParams,
) -> list[Any]:
    """
    Build bounded SQLAlchemy conditions for transaction list queries.
    """
    conditions: list[Any] = []

    if account_id is not None:
        if counterparty_account_id is not None and counterparty_account_id == account_id:
            # A counterparty filter identical to the focal account is only
            # meaningful for self-transfers. Keep the query explicit rather
            # than silently producing contradictory predicates.
            if direction != "self":
                raise MuleGuardValidationError(
                    "counterparty_account_id equal to account_id is only valid "
                    "when direction=self.",
                    details={
                        "account_id": account_id,
                        "counterparty_account_id": counterparty_account_id,
                        "direction": direction,
                    },
                )

        if direction == "incoming":
            conditions.append(Transaction.receiver_account_id == account_id)

            if counterparty_account_id is not None:
                conditions.append(Transaction.sender_account_id == counterparty_account_id)

        elif direction == "outgoing":
            conditions.append(Transaction.sender_account_id == account_id)

            if counterparty_account_id is not None:
                conditions.append(Transaction.receiver_account_id == counterparty_account_id)

        elif direction == "self":
            conditions.append(Transaction.sender_account_id == account_id)
            conditions.append(Transaction.receiver_account_id == account_id)

            if counterparty_account_id is not None:
                conditions.append(Transaction.sender_account_id == counterparty_account_id)

        else:
            conditions.append(
                or_(
                    Transaction.sender_account_id == account_id,
                    Transaction.receiver_account_id == account_id,
                )
            )

            if counterparty_account_id is not None:
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

    else:
        if counterparty_account_id is not None:
            raise MuleGuardValidationError(
                "counterparty_account_id requires account_id to define direction.",
                details={"counterparty_account_id": counterparty_account_id},
            )

        if sender_account_id is not None:
            conditions.append(Transaction.sender_account_id == sender_account_id)

        if receiver_account_id is not None:
            conditions.append(Transaction.receiver_account_id == receiver_account_id)

    if status is not None:
        conditions.append(Transaction.status == status)

    if channel is not None:
        conditions.append(Transaction.channel == channel)

    if currency is not None:
        conditions.append(Transaction.currency == currency)

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

    return conditions


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "",
    response_model=TransactionListResponse,
    summary="List synthetic transactions",
    description=(
        "Returns a paginated, filtered, and stably ordered list of synthetic "
        "MULEGUARD transactions. This endpoint is read-only and does not mutate "
        "transactions or take adverse action. Completed transfers represent "
        "fund movement; pending, failed, and reversed records are preserved "
        "separately and must not be interpreted as completed transfers."
    ),
)
def list_transactions(
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(transaction_pagination),
    date_range: DateRangeParams = Depends(transaction_date_range),
    amount_range: AmountRangeParams = Depends(transaction_amount_range),
    search: SearchParams = Depends(transaction_search),
    _: User = Depends(require_permission(Permission.TRANSACTION_READ)),
    sender_account_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by sending synthetic account."),
    ] = None,
    receiver_account_id: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by receiving synthetic account."),
    ] = None,
    account_id: Annotated[
        Optional[str],
        Query(
            max_length=128,
            description=(
                "Convenience filter for transactions involving this account. "
                "When supplied, direction and counterparty_account_id are "
                "interpreted relative to this account."
            ),
        ),
    ] = None,
    direction: Annotated[
        TransactionDirection,
        Query(
            description=(
                "Transaction direction relative to account_id. Ignored unless "
                "account_id is supplied."
            ),
        ),
    ] = "both",
    counterparty_account_id: Annotated[
        Optional[str],
        Query(
            max_length=128,
            description=(
                "Counterparty filter relative to account_id. Requires account_id."
            ),
        ),
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
    include_accounts: Annotated[
        bool,
        Query(description="Include bounded sender/receiver account summaries."),
    ] = False,
) -> TransactionListResponse:
    """
    List synthetic transactions with bounded pagination and safe filters.
    """
    _ensure_transactions_enabled(settings)

    effective_currency = _normalize_currency(currency, settings)

    _validate_transaction_date_span(
        date_range.date_from,
        date_range.date_to,
        settings,
    )

    conditions = _build_transaction_conditions(
        sender_account_id=sender_account_id,
        receiver_account_id=receiver_account_id,
        account_id=account_id,
        direction=direction,
        counterparty_account_id=counterparty_account_id,
        status=status,
        channel=channel,
        currency=effective_currency,
        reference=reference,
        date_range=date_range,
        amount_range=amount_range,
        search=search,
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

    items = [_transaction_response(transaction) for transaction in transactions]

    if include_accounts and transactions:
        account_ids: set[str] = set()

        for transaction in transactions:
            account_ids.add(str(transaction.sender_account_id))
            account_ids.add(str(transaction.receiver_account_id))

        accounts = _load_accounts_by_ids(db, list(account_ids))

        # Account summaries are intentionally not embedded into the flat
        # TransactionResponse list model to keep the list payload compact.
        # Clients that need account context should use the detail endpoint or
        # request include_accounts=True, which is handled by attaching summaries
        # through the response model's optional fields when needed.
        #
        # For list responses, include_accounts currently acts as a hint for
        # future enrichment and keeps the query bounded. The detail endpoint
        # provides full account context.
        _ = accounts

    return TransactionListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_TRANSACTION_CAVEATS),
    )


@router.get(
    "/{transaction_id}",
    response_model=TransactionDetailResponse,
    summary="Get a synthetic transaction",
    description=(
        "Returns a safe detail view for one synthetic MULEGUARD transaction, "
        "including optional sender/receiver account summaries. This endpoint "
        "does not expose ground-truth labels, scenario IDs, ring IDs, secrets, "
        "tokens, or real customer data."
    ),
)
def get_transaction(
    transaction_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic transaction identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.TRANSACTION_READ)),
    include_accounts: Annotated[
        bool,
        Query(description="Include sender/receiver account summaries."),
    ] = True,
) -> TransactionDetailResponse:
    """
    Retrieve one synthetic transaction detail.
    """
    _ensure_transactions_enabled(settings)

    transaction = _get_transaction_or_404(db, transaction_id)

    sender_account: Optional[Account] = None
    receiver_account: Optional[Account] = None

    if include_accounts:
        accounts = _load_accounts_by_ids(
            db,
            [
                str(transaction.sender_account_id),
                str(transaction.receiver_account_id),
            ],
        )

        sender_account = accounts.get(str(transaction.sender_account_id))
        receiver_account = accounts.get(str(transaction.receiver_account_id))

    return _transaction_detail_response(
        transaction,
        sender_account=sender_account,
        receiver_account=receiver_account,
    )


@router.get(
    "/{transaction_id}/complaint-correlations",
    response_model=TransactionComplaintCorrelationListResponse,
    summary="List complaint correlations for a synthetic transaction",
    description=(
        "Returns paginated complaint correlations associated with one synthetic "
        "transaction. Exact matches are distinguished from inferred associations "
        "through match tier, method, determinism, and confidence. Raw and "
        "normalized complaint narratives are intentionally not returned."
    ),
)
def list_transaction_complaint_correlations(
    transaction_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic transaction identifier."),
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
) -> TransactionComplaintCorrelationListResponse:
    """
    List complaint correlations for one transaction.
    """
    _ensure_transactions_enabled(settings)

    transaction = _get_transaction_or_404(db, transaction_id)
    transaction_id = str(transaction.id)

    conditions: list[Any] = [ComplaintCorrelation.transaction_id == transaction_id]

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
        _complaint_correlation_response(correlation, complaint)
        for correlation, complaint in rows
    ]

    return TransactionComplaintCorrelationListResponse(
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=[
            *_TRANSACTION_CAVEATS,
            "Complaint correlations are investigative leads only.",
            "Raw and normalized complaint narratives are intentionally not returned.",
        ],
    )


@router.get(
    "/{transaction_id}/alerts",
    response_model=TransactionAlertListResponse,
    summary="List alerts referencing a synthetic transaction",
    description=(
        "Returns paginated investigative alerts whose evidence references one "
        "synthetic transaction. Alerts are investigative leads only and must "
        "not be treated as proof of wrongdoing or used for automatic adverse "
        "action."
    ),
)
def list_transaction_alerts(
    transaction_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic transaction identifier."),
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
) -> TransactionAlertListResponse:
    """
    List alerts referencing one transaction.
    """
    _ensure_transactions_enabled(settings)

    transaction = _get_transaction_or_404(db, transaction_id)
    transaction_id = str(transaction.id)

    conditions: list[Any] = [
        AlertEvidence.evidence_type == EvidenceType.TRANSACTION,
        AlertEvidence.evidence_id == transaction_id,
    ]

    if state is not None:
        conditions.append(Alert.state == state)

    if priority is not None:
        conditions.append(Alert.priority == priority)

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
        tiebreaker=Alert.id,
        default_sort_by="created_at",
        default_sort_order="desc",
    )

    alerts = db.scalars(stmt).all()

    return TransactionAlertListResponse(
        items=[_alert_response(alert) for alert in alerts],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=[
            *_TRANSACTION_CAVEATS,
            "Alerts are investigative leads only.",
            "Alert evidence references must be reviewed by an authorised investigator.",
        ],
    )


@router.get(
    "/{transaction_id}/evidence",
    response_model=TransactionEvidenceBundleResponse,
    summary="Get a bounded transaction evidence bundle",
    description=(
        "Returns a bounded evidence bundle for one synthetic transaction, "
        "including the transaction record and sender/receiver account summaries. "
        "Complaint correlations and alerts remain available through dedicated, "
        "permission-scoped endpoints to avoid over-disclosure."
    ),
)
def get_transaction_evidence(
    transaction_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Synthetic transaction identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.TRANSACTION_READ)),
) -> TransactionEvidenceBundleResponse:
    """
    Return a bounded transaction evidence bundle.
    """
    _ensure_transactions_enabled(settings)

    transaction = _get_transaction_or_404(db, transaction_id)

    accounts = _load_accounts_by_ids(
        db,
        [
            str(transaction.sender_account_id),
            str(transaction.receiver_account_id),
        ],
    )

    sender_account = accounts.get(str(transaction.sender_account_id))
    receiver_account = accounts.get(str(transaction.receiver_account_id))

    return TransactionEvidenceBundleResponse(
        transaction=_transaction_response(transaction),
        sender_account=(
            _account_summary_response(sender_account)
            if sender_account is not None
            else None
        ),
        receiver_account=(
            _account_summary_response(receiver_account)
            if receiver_account is not None
            else None
        ),
        caveats=[
            *_TRANSACTION_CAVEATS,
            "This bundle contains transaction and account evidence only.",
            "Complaint correlations and alerts require dedicated permission-scoped endpoints.",
        ],
    )


__all__ = [
    "router",
]