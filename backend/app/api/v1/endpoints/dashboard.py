"""
MULEGUARD backend API v1 dashboard endpoints.

This module implements the versioned `/api/v1/dashboard` read-only operational
and investigative dashboard surface for synthetic MULEGUARD data.

Implemented endpoints:

- GET /api/v1/dashboard/status
- GET /api/v1/dashboard/overview
- GET /api/v1/dashboard/metrics
- GET /api/v1/dashboard/queues
- GET /api/v1/dashboard/trends

Design goals:

- provide bounded, safe, aggregated operational visibility for synthetic
  MULEGUARD investigations;
- enforce server-side RBAC through dependency permissions;
- avoid exposing raw complaint narratives, secrets, tokens, passwords,
  database URLs, synthetic ground-truth labels, scenario IDs, ring IDs, model
  artifact paths, or real customer data;
- keep all dashboard queries bounded by configured date spans and top-N limits;
- distinguish all-time backlog state from windowed activity;
- surface honest operational signals without implying production readiness;
- preserve the product boundary that alerts, scores, cases, correlations, and
  graph/entity signals are investigative leads only;
- avoid any automatic adverse customer action.

Explicit non-goals:

- This module does not create, update, delete, freeze, block, blacklist, close,
  restrict, or otherwise take adverse action against accounts or customers.
- This module does not compute ML scores inline.
- This module does not expose raw complaint narratives.
- This module does not expose ground-truth labels or injected scenario metadata.
- This module does not claim real-world fraud-detection accuracy.
- This module does not replace detailed investigation endpoints.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Dashboard metrics,
queues, trends, alerts, risk scores, graph relationships, candidate money
trails, entity links, complaint correlations, and case dispositions are
investigative leads or human workflow artefacts only. They are not proof of
wrongdoing and must not trigger automatic adverse customer action.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Final, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import JSON, and_, desc, func, select
from sqlalchemy.orm import Session

from app.api.deps import (
    DateRangeParams,
    Permission,
    SessionDep,
    SettingsDep,
    date_range_dependency,
    require_permission,
)
from app.exceptions import (
    FeatureFlagDisabledError,
    ValidationError as MuleGuardValidationError,
)
from app.models import (
    Account,
    AccountStatus,
    Alert,
    AlertState,
    CaseStatus,
    Complaint,
    ComplaintCorrelation,
    ComplaintReviewState,
    InvestigationCase,
    ModelAssessment,
    Transaction,
    TransactionStatus,
    User,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.dashboard")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["dashboard"])


# -----------------------------------------------------------------------------
# Permission resolution
# -----------------------------------------------------------------------------
# Prefer a dedicated dashboard permission when the project defines one. Fall
# back to an investigative read permission so the module remains usable across
# incremental RBAC evolutions.

_DASHBOARD_PERMISSION_NAMES: Final[tuple[str, ...]] = (
    "DASHBOARD_READ",
    "ALERT_READ",
    "ACCOUNT_READ",
    "CASE_READ",
    "COMPLAINT_READ",
)

def _first_permission(names: tuple[str, ...]) -> Any:
    """
    Return the first available permission attribute from the supplied names.

    This deliberately avoids `iter(Permission)`. There are two `Permission`
    classes in this codebase: `app.core.permissions.Permission` is a
    `str, Enum` and is iterable, while `app.api.deps.Permission` -- the one
    this module imports -- is a plain class of `Final[str]` constants and is
    NOT. `iter()` on it raises `TypeError: 'type' object is not iterable`.

    The previous form put that call in the `default` argument of `next()`,
    where it was evaluated EAGERLY: the fallback ran even though
    `Permission.DASHBOARD_READ` exists and the generator would have yielded on
    its first item. Importing this module therefore always raised TypeError,
    the router caught it and skipped the endpoint, and /api/v1/dashboard/*
    silently did not exist.
    """
    for name in names:
        permission = getattr(Permission, name, None)

        if permission is not None:
            return permission

    for attribute, value in vars(Permission).items():
        if not attribute.startswith("_") and isinstance(value, str):
            return value

    return None


DASHBOARD_READ_PERMISSION: Final[Any] = _first_permission(_DASHBOARD_PERMISSION_NAMES)


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

_DEFAULT_WINDOW_DAYS: Final[int] = 30
_MAX_WINDOW_DAYS: Final[int] = 3650

_DEFAULT_TREND_BUCKETS: Final[int] = 90
_HARD_TREND_BUCKETS: Final[int] = 366

_DEFAULT_TOP_LIMIT: Final[int] = 10
_HARD_TOP_LIMIT: Final[int] = 50

_DASHBOARD_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Dashboard aggregates are operational and investigative signals only.",
    "Alerts, risk scores, cases, complaint correlations, entity links, and graph-derived signals are investigative leads only.",
    "Risk scores are investigative priority scores, not probabilities of guilt.",
    "Heuristic fallback scores are not calibrated model probabilities.",
    "Raw complaint narratives are intentionally not returned.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    "This API does not freeze, block, blacklist, close, restrict, or otherwise take adverse action against accounts or customers.",
    "Windowed metrics depend on configured date ranges and may be bounded or defaulted.",
)

_QUEUE_CAVEATS: Final[tuple[str, ...]] = (
    *_DASHBOARD_CAVEATS,
    "Work queues are bounded triage views, not exhaustive case management.",
    "Queue ordering is heuristic and must not be interpreted as legal or evidentiary priority.",
)

_TREND_CAVEATS: Final[tuple[str, ...]] = (
    *_DASHBOARD_CAVEATS,
    "Trend buckets are calendar-date based in UTC and may be affected by ingestion timing.",
    "Low-volume daily buckets should be interpreted cautiously.",
)

_METRICS_CAVEATS: Final[tuple[str, ...]] = (
    *_DASHBOARD_CAVEATS,
    "Rates are simple windowed counts divided by elapsed days and are not statistically calibrated.",
    "Backlog counts are current-state counts and are not scoped to the activity window unless stated.",
)


# -----------------------------------------------------------------------------
# Dynamic enum helpers
# -----------------------------------------------------------------------------


def _enum_member(enum_cls: Any, name: str, fallback: Optional[str] = None) -> Any:
    """
    Return an enum member when present, otherwise a safe string fallback.
    """
    member = getattr(enum_cls, name, None)

    if member is not None:
        return member

    return fallback if fallback is not None else name


def _enum_members(enum_cls: Any, names: tuple[str, ...]) -> list[Any]:
    """
    Return available enum members for the supplied names.

    If none are available, return the raw names as string fallbacks.
    """
    members = [
        member
        for member in (getattr(enum_cls, name, None) for name in names)
        if member is not None
    ]

    if members:
        return members

    return list(names)


_ALERT_OPEN_STATES: Final[list[Any]] = _enum_members(
    AlertState,
    (
        "NEW",
        "ACKNOWLEDGED",
        "UNDER_REVIEW",
        "ESCALATED",
    ),
)

# A case's open states are NEW, TRIAGED, UNDER_INVESTIGATION and ESCALATED.
#
# `UNDER_REVIEW` is an *alert* state. Asking `CaseStatus` for it returned None,
# which `_enum_members` drops and `_eq_condition` treats as no condition, so
# the dashboard's in-progress case count matched nothing and the open-case
# total silently excluded every case being worked. TRIAGED was missing for the
# same reason — it was never listed.
_CASE_OPEN_STATES: Final[list[Any]] = _enum_members(
    CaseStatus,
    (
        "NEW",
        "TRIAGED",
        "UNDER_INVESTIGATION",
        "ESCALATED",
    ),
)

_CASE_NEW: Final[Any] = _enum_member(CaseStatus, "NEW")
_CASE_TRIAGED: Final[Any] = _enum_member(CaseStatus, "TRIAGED")
_CASE_UNDER_INVESTIGATION: Final[Any] = _enum_member(
    CaseStatus,
    "UNDER_INVESTIGATION",
)
_CASE_ESCALATED: Final[Any] = _enum_member(CaseStatus, "ESCALATED")

_TX_COMPLETED: Final[Any] = _enum_member(TransactionStatus, "COMPLETED")
_TX_PENDING: Final[Any] = _enum_member(TransactionStatus, "PENDING")
_TX_FAILED: Final[Any] = _enum_member(TransactionStatus, "FAILED")
_TX_REVERSED: Final[Any] = _enum_member(TransactionStatus, "REVERSED")

_UNREVIEWED: Final[Any] = _enum_member(ComplaintReviewState, "UNREVIEWED")
_ACTIVE_ACCOUNT_STATUS: Final[Any] = _enum_member(AccountStatus, "ACTIVE")


# -----------------------------------------------------------------------------
# Dynamic column helpers
# -----------------------------------------------------------------------------


def _column(model: Any, name: str) -> Any | None:
    """
    Return a SQLAlchemy column attribute when present.
    """
    return getattr(model, name, None)


def _first_column(model: Any, *names: str) -> Any | None:
    """
    Return the first existing column attribute among names.
    """
    for name in names:
        column = _column(model, name)

        if column is not None:
            return column

    return None


_ALERT_TIME = _first_column(Alert, "record_created_at", "created_at", "first_seen_at")
_ALERT_SORT = _first_column(Alert, "record_created_at", "created_at", "last_seen_at")

_CASE_TIME = _first_column(InvestigationCase, "record_created_at", "created_at")
_CASE_SORT = _first_column(InvestigationCase, "record_created_at", "created_at")

_COMPLAINT_RECORD_TIME = _first_column(Complaint, "record_created_at", "created_at")
_COMPLAINT_REPORTED_TIME = _first_column(Complaint, "reported_at", "record_created_at", "created_at")

_TXN_TIME = _first_column(Transaction, "occurred_at", "record_created_at", "created_at")

_ASSESS_TIME = _first_column(ModelAssessment, "scored_at", "as_of")

_CORR_TIME = _first_column(ComplaintCorrelation, "record_created_at", "created_at")


# -----------------------------------------------------------------------------
# Reusable bounded dependencies
# -----------------------------------------------------------------------------

dashboard_date_range = date_range_dependency(max_span_days=0)


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _setting(settings: Any, name: str, default: Any = None) -> Any:
    """
    Read a setting from either a Pydantic settings object or mapping.
    """
    if settings is None:
        return default

    if hasattr(settings, "model_dump"):
        return getattr(settings, name, default)

    if isinstance(settings, dict):
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


def _age_seconds(value: Optional[datetime], now: datetime) -> Optional[float]:
    """
    Return safe age in seconds from a timestamp to now.
    """
    normalized = _ensure_utc(value)

    if normalized is None:
        return None

    delta = now - normalized
    return round(max(0.0, delta.total_seconds()), 3)


def _group_key(value: Any) -> str:
    """
    Return a safe grouping key for enum-like or scalar values.
    """
    if value is None:
        return "UNKNOWN"

    text = _enum_str(value)

    if text:
        return text

    return _clean_text(value, 100) or "UNKNOWN"


def _date_bucket(value: Any) -> Optional[str]:
    """
    Return a stable YYYY-MM-DD bucket key from a date-like value.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)

        if normalized is None:
            return None

        return normalized.date().isoformat()

    if hasattr(value, "isoformat"):
        try:
            return str(value.isoformat())[:10]
        except Exception:
            return _clean_text(value, 10) or None

    text = _clean_text(value, 10)
    return text or None


# -----------------------------------------------------------------------------
# Query helpers
# -----------------------------------------------------------------------------


def _apply(stmt: Any, conditions: list[Any]) -> Any:
    """
    Apply a list of SQLAlchemy conditions to a statement.
    """
    if conditions:
        stmt = stmt.where(and_(*conditions))

    return stmt


def _count(db: Session, model: Any, conditions: list[Any]) -> int:
    """
    Return a bounded count for a model under conditions.
    """
    stmt = select(func.count()).select_from(model)
    stmt = _apply(stmt, conditions)
    return int(db.scalar(stmt) or 0)


def _group_counts(
    db: Session,
    model: Any,
    column: Any | None,
    conditions: list[Any],
    limit: Optional[int] = None,
) -> dict[str, int]:
    """
    Return bounded grouping counts for a nullable column.
    """
    if column is None:
        return {}

    stmt = select(column, func.count()).select_from(model)
    stmt = _apply(stmt, conditions)
    stmt = stmt.group_by(column).order_by(desc(func.count()))

    if limit is not None and limit > 0:
        stmt = stmt.limit(int(limit))

    rows = db.execute(stmt).all()

    return {
        _group_key(row[0]): int(row[1] or 0)
        for row in rows
    }


def _time_conditions(
    time_column: Any | None,
    date_from: datetime,
    date_to: datetime,
) -> list[Any]:
    """
    Build time-range conditions when a time column exists.
    """
    if time_column is None:
        return []

    return [
        time_column >= date_from,
        time_column <= date_to,
    ]


def _in_condition(column: Any | None, values: list[Any]) -> list[Any]:
    """
    Build an IN condition when both column and values exist.
    """
    if column is None or not values:
        return []

    return [column.in_(values)]


def _eq_condition(column: Any | None, value: Any) -> list[Any]:
    """
    Build an equality condition when column and value exist.
    """
    if column is None or value is None:
        return []

    return [column == value]


def _bool_condition(column: Any | None, value: bool) -> list[Any]:
    """
    Build a boolean IS condition when column exists.
    """
    if column is None:
        return []

    return [column.is_(value)]


def _is_null_condition(column: Any | None) -> list[Any]:
    """
    Build an IS NULL condition when column exists.
    """
    if column is None:
        return []

    return [column.is_(None)]


def _not_null_condition(column: Any | None) -> list[Any]:
    """
    Build an IS NOT NULL condition when column exists.
    """
    if column is None:
        return []

    return [column.isnot(None)]


def _daily_counts(
    db: Session,
    model: Any,
    time_column: Any | None,
    date_from: datetime,
    date_to: datetime,
) -> dict[str, int]:
    """
    Return bounded daily counts for a model using UTC calendar buckets.
    """
    if time_column is None:
        return {}

    date_expr = func.date(time_column)

    stmt = (
        select(date_expr, func.count())
        .select_from(model)
        .where(
            time_column >= date_from,
            time_column <= date_to,
        )
        .group_by(date_expr)
        .order_by(date_expr)
    )

    rows = db.execute(stmt).all()
    result: dict[str, int] = {}

    for row in rows:
        key = _date_bucket(row[0])

        if key is None:
            continue

        result[key] = int(row[1] or 0)

    return result


# -----------------------------------------------------------------------------
# Policy helpers
# -----------------------------------------------------------------------------


def _ensure_dashboard_enabled(settings: Any) -> None:
    """
    Fail closed when the dashboard API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "DASHBOARD_API_ENABLED", True), True):
        raise FeatureFlagDisabledError("Dashboard endpoints are disabled by configuration.")

    if not _as_bool(_setting(settings, "DASHBOARD_ENABLED", True), True):
        raise FeatureFlagDisabledError("Dashboard subsystem is disabled by configuration.")


def _max_dashboard_date_span_days(settings: Any) -> int:
    """
    Return bounded maximum dashboard query date span in days.
    """
    configured = max(
        1,
        _as_int(
            _setting(settings, "DASHBOARD_MAX_DATE_SPAN_DAYS", 365),
            365,
        ),
    )
    hard = max(
        configured,
        _as_int(
            _setting(settings, "DASHBOARD_HARD_MAX_DATE_SPAN_DAYS", _MAX_WINDOW_DAYS),
            _MAX_WINDOW_DAYS,
        ),
    )

    return min(configured, hard)


def _default_dashboard_window_days(settings: Any, max_span_days: int) -> int:
    """
    Return bounded default dashboard window in days.
    """
    configured = max(
        1,
        _as_int(
            _setting(settings, "DASHBOARD_DEFAULT_WINDOW_DAYS", _DEFAULT_WINDOW_DAYS),
            _DEFAULT_WINDOW_DAYS,
        ),
    )

    return min(configured, max_span_days)


def _max_trend_buckets(settings: Any) -> int:
    """
    Return bounded maximum trend buckets.
    """
    configured = max(
        1,
        _as_int(
            _setting(settings, "DASHBOARD_MAX_TREND_BUCKETS", _DEFAULT_TREND_BUCKETS),
            _DEFAULT_TREND_BUCKETS,
        ),
    )
    hard = max(
        configured,
        _as_int(
            _setting(settings, "DASHBOARD_HARD_MAX_TREND_BUCKETS", _HARD_TREND_BUCKETS),
            _HARD_TREND_BUCKETS,
        ),
    )

    return min(configured, hard)


def _bounded_top_limit(value: Optional[int], settings: Any) -> int:
    """
    Return bounded top-N limit for dashboard breakdowns and queues.
    """
    default_limit = max(
        1,
        _as_int(
            _setting(settings, "DASHBOARD_TOP_LIMIT_DEFAULT", _DEFAULT_TOP_LIMIT),
            _DEFAULT_TOP_LIMIT,
        ),
    )
    hard_limit = max(
        default_limit,
        _as_int(
            _setting(settings, "DASHBOARD_TOP_LIMIT_MAX", _HARD_TOP_LIMIT),
            _HARD_TOP_LIMIT,
        ),
    )

    if value is None:
        return min(default_limit, hard_limit)

    return max(1, min(int(value), hard_limit))


def _validate_date_range(
    start: datetime,
    end: datetime,
) -> None:
    """
    Validate date-range ordering.
    """
    if start > end:
        raise MuleGuardValidationError(
            "date_from must be earlier than or equal to date_to.",
            details={
                "date_from": start.isoformat(),
                "date_to": end.isoformat(),
            },
        )


def _validate_not_future(value: datetime, field_name: str) -> None:
    """
    Reject future dashboard window endpoints.
    """
    if value > _now_utc():
        raise MuleGuardValidationError(
            f"{field_name} must not be in the future.",
            details={field_name: value.isoformat()},
        )


def _validate_span(
    start: datetime,
    end: datetime,
    max_span_days: int,
) -> None:
    """
    Enforce maximum date span for dashboard scans.
    """
    span = end - start
    max_delta = timedelta(days=max_span_days)

    if span > max_delta:
        raise MuleGuardValidationError(
            "Dashboard date span exceeds configured maximum.",
            details={
                "max_span_days": max_span_days,
                "requested_span_days": round(span.total_seconds() / 86400.0, 3),
            },
        )


def _resolve_window(
    date_range: DateRangeParams,
    settings: Any,
) -> tuple[datetime, datetime, bool, int, int]:
    """
    Resolve a bounded default or supplied dashboard window.
    """
    max_span = _max_dashboard_date_span_days(settings)
    default_days = _default_dashboard_window_days(settings, max_span)

    date_to = _ensure_utc(date_range.date_to) or _now_utc()
    date_from = _ensure_utc(date_range.date_from)
    defaulted = False

    if date_from is None:
        date_from = date_to - timedelta(days=default_days)
        defaulted = True

    _validate_not_future(date_to, "date_to")
    _validate_date_range(date_from, date_to)
    _validate_span(date_from, date_to, max_span)

    return date_from, date_to, defaulted, default_days, max_span


def _validate_trend_buckets(
    date_from: datetime,
    date_to: datetime,
    settings: Any,
) -> tuple[int, int]:
    """
    Validate and return trend bucket count and configured maximum.
    """
    max_buckets = _max_trend_buckets(settings)
    days = (date_to.date() - date_from.date()).days + 1

    if days > max_buckets:
        raise MuleGuardValidationError(
            "Dashboard trend range exceeds configured maximum bucket count.",
            details={
                "max_buckets": max_buckets,
                "requested_buckets": days,
            },
        )

    return days, max_buckets


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class DashboardWindow(BaseModel):
    """
    Safe dashboard window metadata.
    """

    model_config = ConfigDict(from_attributes=False)

    date_from: datetime
    date_to: datetime
    defaulted: bool = False
    default_window_days: int = _DEFAULT_WINDOW_DAYS
    max_span_days: int = 365


class DashboardAccountBreakdown(BaseModel):
    """
    Safe account dashboard breakdown.
    """

    model_config = ConfigDict(from_attributes=False)

    total: int = 0
    active: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)


class DashboardAlertBreakdown(BaseModel):
    """
    Safe alert dashboard breakdown.
    """

    model_config = ConfigDict(from_attributes=False)

    total_all_time: int = 0
    open_all_time: int = 0
    created_in_window: int = 0
    open_by_state: dict[str, int] = Field(default_factory=dict)
    created_by_state: dict[str, int] = Field(default_factory=dict)
    created_by_priority: dict[str, int] = Field(default_factory=dict)


class DashboardCaseBreakdown(BaseModel):
    """
    Safe case dashboard breakdown.
    """

    model_config = ConfigDict(from_attributes=False)

    total_all_time: int = 0
    open_all_time: int = 0
    created_in_window: int = 0
    open_by_status: dict[str, int] = Field(default_factory=dict)
    created_by_status: dict[str, int] = Field(default_factory=dict)
    created_by_priority: dict[str, int] = Field(default_factory=dict)


class DashboardComplaintBreakdown(BaseModel):
    """
    Safe complaint dashboard breakdown.

    Raw and normalized narratives are intentionally not represented.
    """

    model_config = ConfigDict(from_attributes=False)

    total_all_time: int = 0
    reported_in_window: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    correlations_total: int = 0
    correlations_deterministic: int = 0
    correlations_inferred: int = 0
    correlations_unreviewed: int = 0


class DashboardTransactionBreakdown(BaseModel):
    """
    Safe transaction dashboard breakdown.
    """

    model_config = ConfigDict(from_attributes=False)

    total_in_window: int = 0
    completed: int = 0
    pending: int = 0
    failed: int = 0
    reversed: int = 0


class DashboardAssessmentBreakdown(BaseModel):
    """
    Safe persisted-assessment dashboard breakdown.
    """

    model_config = ConfigDict(from_attributes=False)

    total_in_window: int = 0
    by_scoring_mode: dict[str, int] = Field(default_factory=dict)
    by_risk_band: dict[str, int] = Field(default_factory=dict)
    explanation_available: int = 0


class DashboardOverviewResponse(BaseModel):
    """
    Safe bounded dashboard overview response.
    """

    model_config = ConfigDict(from_attributes=False)

    generated_at: datetime
    window: DashboardWindow
    accounts: DashboardAccountBreakdown
    alerts: DashboardAlertBreakdown
    cases: DashboardCaseBreakdown
    complaints: DashboardComplaintBreakdown
    transactions: DashboardTransactionBreakdown
    assessments: DashboardAssessmentBreakdown
    caveats: list[str] = Field(default_factory=list)


class DashboardMetricsResponse(BaseModel):
    """
    Safe bounded dashboard metrics response.
    """

    model_config = ConfigDict(from_attributes=False)

    generated_at: datetime
    window: DashboardWindow
    days: float
    totals: dict[str, int] = Field(default_factory=dict)
    rates_per_day: dict[str, float] = Field(default_factory=dict)
    caveats: list[str] = Field(default_factory=list)


class DashboardQueueItem(BaseModel):
    """
    Safe bounded work-queue item.
    """

    model_config = ConfigDict(from_attributes=False)

    kind: str
    id: str
    title: Optional[str] = None
    account_id: Optional[str] = None
    priority: Optional[str] = None
    state: Optional[str] = None
    score: Optional[Decimal] = None
    assignee_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    age_seconds: Optional[float] = None


class DashboardQueueSection(BaseModel):
    """
    Safe bounded work-queue section.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[DashboardQueueItem] = Field(default_factory=list)
    total: int = 0
    truncated: bool = False


class DashboardQueuesResponse(BaseModel):
    """
    Safe bounded dashboard work-queue response.
    """

    model_config = ConfigDict(from_attributes=False)

    generated_at: datetime
    unassigned_alerts: DashboardQueueSection
    my_alerts: DashboardQueueSection
    new_cases: DashboardQueueSection
    triaged_cases: DashboardQueueSection
    under_investigation_cases: DashboardQueueSection
    escalated_cases: DashboardQueueSection
    unreviewed_complaint_correlations: DashboardQueueSection
    caveats: list[str] = Field(default_factory=list)


class DashboardTrendPoint(BaseModel):
    """
    Safe daily trend point.
    """

    model_config = ConfigDict(from_attributes=False)

    date: str
    alerts: int = 0
    cases: int = 0
    complaints: int = 0
    transactions: int = 0
    assessments: int = 0


class DashboardTrendsResponse(BaseModel):
    """
    Safe bounded dashboard trends response.
    """

    model_config = ConfigDict(from_attributes=False)

    generated_at: datetime
    period: DashboardWindow
    bucket_size: str = "day"
    points: list[DashboardTrendPoint] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)


class DashboardStatusResponse(BaseModel):
    """
    Safe dashboard subsystem status response.
    """

    model_config = ConfigDict(from_attributes=False)

    enabled: bool
    default_window_days: int
    max_date_span_days: int
    max_trend_buckets: int
    top_limit_default: int
    top_limit_max: int
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Internal builders
# -----------------------------------------------------------------------------


def _window_response(
    date_from: datetime,
    date_to: datetime,
    defaulted: bool,
    default_window_days: int,
    max_span_days: int,
) -> DashboardWindow:
    """
    Build safe window metadata.
    """
    return DashboardWindow(
        date_from=date_from,
        date_to=date_to,
        defaulted=defaulted,
        default_window_days=default_window_days,
        max_span_days=max_span_days,
    )


def _build_overview(
    db: Session,
    settings: Any,
    date_from: datetime,
    date_to: datetime,
    defaulted: bool,
    default_window_days: int,
    max_span_days: int,
    top_limit: int,
) -> DashboardOverviewResponse:
    """
    Build a bounded dashboard overview from persisted synthetic records.
    """
    now = _now_utc()

    account_status_col = _column(Account, "status")
    account_type_col = _column(Account, "account_type")

    accounts = DashboardAccountBreakdown(
        total=_count(db, Account, []),
        active=_count(
            db,
            Account,
            _eq_condition(account_status_col, _ACTIVE_ACCOUNT_STATUS),
        ),
        by_status=_group_counts(
            db,
            Account,
            account_status_col,
            [],
            top_limit,
        ),
        by_type=_group_counts(
            db,
            Account,
            account_type_col,
            [],
            top_limit,
        ),
    )

    alert_state_col = _column(Alert, "state")
    alert_priority_col = _column(Alert, "priority")

    alert_open_conditions = _in_condition(alert_state_col, _ALERT_OPEN_STATES)
    alert_window_conditions = _time_conditions(_ALERT_TIME, date_from, date_to)

    alerts = DashboardAlertBreakdown(
        total_all_time=_count(db, Alert, []),
        open_all_time=_count(db, Alert, alert_open_conditions),
        created_in_window=_count(db, Alert, alert_window_conditions),
        open_by_state=_group_counts(
            db,
            Alert,
            alert_state_col,
            alert_open_conditions,
            top_limit,
        ),
        created_by_state=_group_counts(
            db,
            Alert,
            alert_state_col,
            alert_window_conditions,
            top_limit,
        ),
        created_by_priority=_group_counts(
            db,
            Alert,
            alert_priority_col,
            alert_window_conditions,
            top_limit,
        ),
    )

    case_status_col = _column(InvestigationCase, "status")
    case_priority_col = _column(InvestigationCase, "priority")

    case_open_conditions = _in_condition(case_status_col, _CASE_OPEN_STATES)
    case_window_conditions = _time_conditions(_CASE_TIME, date_from, date_to)

    cases = DashboardCaseBreakdown(
        total_all_time=_count(db, InvestigationCase, []),
        open_all_time=_count(db, InvestigationCase, case_open_conditions),
        created_in_window=_count(db, InvestigationCase, case_window_conditions),
        open_by_status=_group_counts(
            db,
            InvestigationCase,
            case_status_col,
            case_open_conditions,
            top_limit,
        ),
        created_by_status=_group_counts(
            db,
            InvestigationCase,
            case_status_col,
            case_window_conditions,
            top_limit,
        ),
        created_by_priority=_group_counts(
            db,
            InvestigationCase,
            case_priority_col,
            case_window_conditions,
            top_limit,
        ),
    )

    complaint_category_col = _column(Complaint, "category")
    complaint_source_col = _column(Complaint, "source")

    complaint_window_conditions = _time_conditions(
        _COMPLAINT_REPORTED_TIME,
        date_from,
        date_to,
    )

    correlation_deterministic_col = _column(ComplaintCorrelation, "deterministic")
    correlation_review_col = _column(ComplaintCorrelation, "review_state")

    complaints = DashboardComplaintBreakdown(
        total_all_time=_count(db, Complaint, []),
        reported_in_window=_count(db, Complaint, complaint_window_conditions),
        by_category=_group_counts(
            db,
            Complaint,
            complaint_category_col,
            complaint_window_conditions,
            top_limit,
        ),
        by_source=_group_counts(
            db,
            Complaint,
            complaint_source_col,
            complaint_window_conditions,
            top_limit,
        ),
        correlations_total=_count(db, ComplaintCorrelation, []),
        correlations_deterministic=_count(
            db,
            ComplaintCorrelation,
            _bool_condition(correlation_deterministic_col, True),
        ),
        correlations_inferred=_count(
            db,
            ComplaintCorrelation,
            _bool_condition(correlation_deterministic_col, False),
        ),
        correlations_unreviewed=_count(
            db,
            ComplaintCorrelation,
            _eq_condition(correlation_review_col, _UNREVIEWED),
        ),
    )

    txn_status_col = _column(Transaction, "status")
    txn_window_conditions = _time_conditions(_TXN_TIME, date_from, date_to)

    transactions = DashboardTransactionBreakdown(
        total_in_window=_count(db, Transaction, txn_window_conditions),
        completed=_count(
            db,
            Transaction,
            txn_window_conditions + _eq_condition(txn_status_col, _TX_COMPLETED),
        ),
        pending=_count(
            db,
            Transaction,
            txn_window_conditions + _eq_condition(txn_status_col, _TX_PENDING),
        ),
        failed=_count(
            db,
            Transaction,
            txn_window_conditions + _eq_condition(txn_status_col, _TX_FAILED),
        ),
        reversed=_count(
            db,
            Transaction,
            txn_window_conditions + _eq_condition(txn_status_col, _TX_REVERSED),
        ),
    )

    assessment_scoring_col = _column(ModelAssessment, "scoring_mode")
    assessment_risk_col = _column(ModelAssessment, "risk_band")
    assessment_explanation_col = _column(ModelAssessment, "explanation_json")

    assessment_window_conditions = _time_conditions(_ASSESS_TIME, date_from, date_to)

    assessments = DashboardAssessmentBreakdown(
        total_in_window=_count(db, ModelAssessment, assessment_window_conditions),
        by_scoring_mode=_group_counts(
            db,
            ModelAssessment,
            assessment_scoring_col,
            assessment_window_conditions,
            top_limit,
        ),
        by_risk_band=_group_counts(
            db,
            ModelAssessment,
            assessment_risk_col,
            assessment_window_conditions,
            top_limit,
        ),
        explanation_available=_count(
            db,
            ModelAssessment,
            assessment_window_conditions
            + _not_null_condition(assessment_explanation_col)
            + [assessment_explanation_col != JSON.NULL],
        ),
    )

    return DashboardOverviewResponse(
        generated_at=now,
        window=_window_response(
            date_from=date_from,
            date_to=date_to,
            defaulted=defaulted,
            default_window_days=default_window_days,
            max_span_days=max_span_days,
        ),
        accounts=accounts,
        alerts=alerts,
        cases=cases,
        complaints=complaints,
        transactions=transactions,
        assessments=assessments,
        caveats=list(_DASHBOARD_CAVEATS),
    )


def _build_metrics(
    db: Session,
    settings: Any,
    date_from: datetime,
    date_to: datetime,
    defaulted: bool,
    default_window_days: int,
    max_span_days: int,
) -> DashboardMetricsResponse:
    """
    Build bounded dashboard metrics from persisted synthetic records.
    """
    now = _now_utc()

    account_status_col = _column(Account, "status")
    alert_state_col = _column(Alert, "state")
    case_status_col = _column(InvestigationCase, "status")
    correlation_review_col = _column(ComplaintCorrelation, "review_state")
    txn_status_col = _column(Transaction, "status")

    alert_window_conditions = _time_conditions(_ALERT_TIME, date_from, date_to)
    case_window_conditions = _time_conditions(_CASE_TIME, date_from, date_to)
    complaint_window_conditions = _time_conditions(
        _COMPLAINT_REPORTED_TIME,
        date_from,
        date_to,
    )
    txn_window_conditions = _time_conditions(_TXN_TIME, date_from, date_to)
    assessment_window_conditions = _time_conditions(_ASSESS_TIME, date_from, date_to)

    alerts_created = _count(db, Alert, alert_window_conditions)
    cases_created = _count(db, InvestigationCase, case_window_conditions)
    complaints_reported = _count(db, Complaint, complaint_window_conditions)
    transactions_completed = _count(
        db,
        Transaction,
        txn_window_conditions + _eq_condition(txn_status_col, _TX_COMPLETED),
    )
    assessments_scored = _count(db, ModelAssessment, assessment_window_conditions)

    days = max(1.0, (date_to - date_from).total_seconds() / 86400.0)

    totals = {
        "active_accounts": _count(
            db,
            Account,
            _eq_condition(account_status_col, _ACTIVE_ACCOUNT_STATUS),
        ),
        "open_alerts": _count(
            db,
            Alert,
            _in_condition(alert_state_col, _ALERT_OPEN_STATES),
        ),
        "open_cases": _count(
            db,
            InvestigationCase,
            _in_condition(case_status_col, _CASE_OPEN_STATES),
        ),
        "unreviewed_complaint_correlations": _count(
            db,
            ComplaintCorrelation,
            _eq_condition(correlation_review_col, _UNREVIEWED),
        ),
        "alerts_created_in_window": alerts_created,
        "cases_created_in_window": cases_created,
        "complaints_reported_in_window": complaints_reported,
        "transactions_completed_in_window": transactions_completed,
        "assessments_scored_in_window": assessments_scored,
    }

    rates_per_day = {
        "alerts_created_per_day": round(alerts_created / days, 3),
        "cases_created_per_day": round(cases_created / days, 3),
        "complaints_reported_per_day": round(complaints_reported / days, 3),
        "transactions_completed_per_day": round(transactions_completed / days, 3),
        "assessments_scored_per_day": round(assessments_scored / days, 3),
    }

    return DashboardMetricsResponse(
        generated_at=now,
        window=_window_response(
            date_from=date_from,
            date_to=date_to,
            defaulted=defaulted,
            default_window_days=default_window_days,
            max_span_days=max_span_days,
        ),
        days=round(days, 3),
        totals=totals,
        rates_per_day=rates_per_day,
        caveats=list(_METRICS_CAVEATS),
    )


def _empty_queue_section() -> DashboardQueueSection:
    """
    Return an empty queue section.
    """
    return DashboardQueueSection(items=[], total=0, truncated=False)


def _alert_queue_item(alert: Alert, now: datetime) -> DashboardQueueItem:
    """
    Build a safe alert queue item.
    """
    created_at = _timestamp_value(alert, "record_created_at", "created_at", "first_seen_at")
    updated_at = _timestamp_value(alert, "record_updated_at", "updated_at", "last_seen_at")

    return DashboardQueueItem(
        kind="alert",
        id=str(_get_if_exists(alert, "id", "")),
        title=_str_or_none(_get_if_exists(alert, "title", None)),
        account_id=_str_or_none(_get_if_exists(alert, "account_id", None)),
        priority=_enum_str(_get_if_exists(alert, "priority", None)),
        state=_enum_str(_get_if_exists(alert, "state", None)),
        score=_get_if_exists(alert, "score", None),
        assignee_id=_str_or_none(_get_if_exists(alert, "assigned_to", None)),
        created_at=created_at,
        updated_at=updated_at,
        age_seconds=_age_seconds(created_at, now),
    )


def _case_queue_item(case: InvestigationCase, now: datetime) -> DashboardQueueItem:
    """
    Build a safe case queue item.
    """
    created_at = _timestamp_value(case, "record_created_at", "created_at")
    updated_at = _timestamp_value(case, "record_updated_at", "updated_at")

    return DashboardQueueItem(
        kind="case",
        id=str(_get_if_exists(case, "id", "")),
        title=_str_or_none(_get_if_exists(case, "title", None)),
        account_id=_str_or_none(_get_if_exists(case, "account_id", None)),
        priority=_enum_str(_get_if_exists(case, "priority", None)),
        state=_enum_str(_get_if_exists(case, "status", None)),
        score=None,
        assignee_id=_str_or_none(_get_if_exists(case, "assignee_id", None)),
        created_at=created_at,
        updated_at=updated_at,
        age_seconds=_age_seconds(created_at, now),
    )


def _correlation_queue_item(
    correlation: ComplaintCorrelation,
    now: datetime,
) -> DashboardQueueItem:
    """
    Build a safe complaint-correlation queue item.
    """
    created_at = _timestamp_value(correlation, "record_created_at", "created_at")
    updated_at = _timestamp_value(correlation, "record_updated_at", "updated_at")
    correlation_id = str(_get_if_exists(correlation, "id", ""))
    complaint_id = _str_or_none(_get_if_exists(correlation, "complaint_id", None))

    title = f"Complaint correlation {correlation_id}"

    if complaint_id:
        title = f"{title} for complaint {complaint_id}"

    return DashboardQueueItem(
        kind="complaint_correlation",
        id=correlation_id,
        title=title,
        account_id=_str_or_none(_get_if_exists(correlation, "account_id", None)),
        priority=None,
        state=_enum_str(_get_if_exists(correlation, "review_state", None)),
        score=_get_if_exists(correlation, "confidence", None),
        assignee_id=_str_or_none(_get_if_exists(correlation, "reviewed_by", None)),
        created_at=created_at,
        updated_at=updated_at,
        age_seconds=_age_seconds(created_at, now),
    )


def _alert_queue_section(
    db: Session,
    conditions: list[Any],
    limit: int,
    now: datetime,
) -> DashboardQueueSection:
    """
    Build a bounded alert queue section.
    """
    id_col = _column(Alert, "id")

    if id_col is None:
        return _empty_queue_section()

    total = _count(db, Alert, conditions)

    stmt = select(Alert)
    stmt = _apply(stmt, conditions)

    score_col = _column(Alert, "score")

    if score_col is not None:
        stmt = stmt.order_by(desc(score_col))

    if _ALERT_SORT is not None:
        stmt = stmt.order_by(desc(_ALERT_SORT))

    stmt = stmt.order_by(desc(id_col)).limit(max(1, int(limit)))

    rows = db.scalars(stmt).all()
    items = [_alert_queue_item(row, now) for row in rows]

    return DashboardQueueSection(
        items=items,
        total=total,
        truncated=total > len(items),
    )


def _case_queue_section(
    db: Session,
    conditions: list[Any],
    limit: int,
    now: datetime,
) -> DashboardQueueSection:
    """
    Build a bounded case queue section.
    """
    id_col = _column(InvestigationCase, "id")

    if id_col is None:
        return _empty_queue_section()

    total = _count(db, InvestigationCase, conditions)

    stmt = select(InvestigationCase)
    stmt = _apply(stmt, conditions)

    if _CASE_SORT is not None:
        stmt = stmt.order_by(desc(_CASE_SORT))

    stmt = stmt.order_by(desc(id_col)).limit(max(1, int(limit)))

    rows = db.scalars(stmt).all()
    items = [_case_queue_item(row, now) for row in rows]

    return DashboardQueueSection(
        items=items,
        total=total,
        truncated=total > len(items),
    )


def _correlation_queue_section(
    db: Session,
    conditions: list[Any],
    limit: int,
    now: datetime,
) -> DashboardQueueSection:
    """
    Build a bounded complaint-correlation queue section.
    """
    id_col = _column(ComplaintCorrelation, "id")

    if id_col is None:
        return _empty_queue_section()

    total = _count(db, ComplaintCorrelation, conditions)

    stmt = select(ComplaintCorrelation)
    stmt = _apply(stmt, conditions)

    confidence_col = _column(ComplaintCorrelation, "confidence")

    if confidence_col is not None:
        stmt = stmt.order_by(desc(confidence_col))

    if _CORR_TIME is not None:
        stmt = stmt.order_by(desc(_CORR_TIME))

    stmt = stmt.order_by(desc(id_col)).limit(max(1, int(limit)))

    rows = db.scalars(stmt).all()
    items = [_correlation_queue_item(row, now) for row in rows]

    return DashboardQueueSection(
        items=items,
        total=total,
        truncated=total > len(items),
    )


def _build_queues(
    db: Session,
    actor: User,
    limit: int,
) -> DashboardQueuesResponse:
    """
    Build bounded dashboard work queues.
    """
    now = _now_utc()

    alert_state_col = _column(Alert, "state")
    alert_assigned_col = _column(Alert, "assigned_to")
    case_status_col = _column(InvestigationCase, "status")
    correlation_review_col = _column(ComplaintCorrelation, "review_state")

    open_alert_conditions = _in_condition(alert_state_col, _ALERT_OPEN_STATES)

    if alert_assigned_col is None:
        unassigned_alerts = _empty_queue_section()
        my_alerts = _empty_queue_section()
    else:
        unassigned_alerts = _alert_queue_section(
            db,
            open_alert_conditions + _is_null_condition(alert_assigned_col),
            limit,
            now,
        )
        my_alerts = _alert_queue_section(
            db,
            open_alert_conditions + _eq_condition(alert_assigned_col, str(actor.id)),
            limit,
            now,
        )

    if case_status_col is None:
        new_cases = _empty_queue_section()
        triaged_cases = _empty_queue_section()
        under_investigation_cases = _empty_queue_section()
        escalated_cases = _empty_queue_section()
    else:
        new_cases = _case_queue_section(
            db,
            _eq_condition(case_status_col, _CASE_NEW),
            limit,
            now,
        )
        triaged_cases = _case_queue_section(
            db,
            _eq_condition(case_status_col, _CASE_TRIAGED),
            limit,
            now,
        )
        under_investigation_cases = _case_queue_section(
            db,
            _eq_condition(case_status_col, _CASE_UNDER_INVESTIGATION),
            limit,
            now,
        )
        escalated_cases = _case_queue_section(
            db,
            _eq_condition(case_status_col, _CASE_ESCALATED),
            limit,
            now,
        )

    if correlation_review_col is None:
        unreviewed_complaint_correlations = _empty_queue_section()
    else:
        unreviewed_complaint_correlations = _correlation_queue_section(
            db,
            _eq_condition(correlation_review_col, _UNREVIEWED),
            limit,
            now,
        )

    return DashboardQueuesResponse(
        generated_at=now,
        unassigned_alerts=unassigned_alerts,
        my_alerts=my_alerts,
        new_cases=new_cases,
        triaged_cases=triaged_cases,
        under_investigation_cases=under_investigation_cases,
        escalated_cases=escalated_cases,
        unreviewed_complaint_correlations=unreviewed_complaint_correlations,
        caveats=list(_QUEUE_CAVEATS),
    )


def _build_trends(
    db: Session,
    date_from: datetime,
    date_to: datetime,
    defaulted: bool,
    default_window_days: int,
    max_span_days: int,
) -> DashboardTrendsResponse:
    """
    Build bounded daily dashboard trends.
    """
    now = _now_utc()

    alert_counts = _daily_counts(db, Alert, _ALERT_TIME, date_from, date_to)
    case_counts = _daily_counts(db, InvestigationCase, _CASE_TIME, date_from, date_to)
    complaint_counts = _daily_counts(
        db,
        Complaint,
        _COMPLAINT_REPORTED_TIME,
        date_from,
        date_to,
    )
    transaction_counts = _daily_counts(db, Transaction, _TXN_TIME, date_from, date_to)
    assessment_counts = _daily_counts(db, ModelAssessment, _ASSESS_TIME, date_from, date_to)

    points: list[DashboardTrendPoint] = []

    current = date_from.date()
    end = date_to.date()

    while current <= end:
        key = current.isoformat()

        points.append(
            DashboardTrendPoint(
                date=key,
                alerts=alert_counts.get(key, 0),
                cases=case_counts.get(key, 0),
                complaints=complaint_counts.get(key, 0),
                transactions=transaction_counts.get(key, 0),
                assessments=assessment_counts.get(key, 0),
            )
        )

        current += timedelta(days=1)

    return DashboardTrendsResponse(
        generated_at=now,
        period=_window_response(
            date_from=date_from,
            date_to=date_to,
            defaulted=defaulted,
            default_window_days=default_window_days,
            max_span_days=max_span_days,
        ),
        bucket_size="day",
        points=points,
        caveats=list(_TREND_CAVEATS),
    )


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=DashboardStatusResponse,
    summary="Get dashboard subsystem status",
    description=(
        "Returns safe status for the MULEGUARD dashboard subsystem, including "
        "bounded window, trend, and top-limit configuration. This endpoint does "
        "not expose secrets, database URLs, tokens, passwords, raw complaint "
        "narratives, ground-truth labels, or real customer data."
    ),
)
def dashboard_status(
    settings: SettingsDep,
    _: User = Depends(require_permission(DASHBOARD_READ_PERMISSION)),
) -> DashboardStatusResponse:
    """
    Return safe dashboard subsystem status.
    """
    _ensure_dashboard_enabled(settings)

    max_span = _max_dashboard_date_span_days(settings)
    default_days = _default_dashboard_window_days(settings, max_span)
    max_buckets = _max_trend_buckets(settings)

    default_top = max(
        1,
        _as_int(
            _setting(settings, "DASHBOARD_TOP_LIMIT_DEFAULT", _DEFAULT_TOP_LIMIT),
            _DEFAULT_TOP_LIMIT,
        ),
    )
    hard_top = max(
        default_top,
        _as_int(
            _setting(settings, "DASHBOARD_TOP_LIMIT_MAX", _HARD_TOP_LIMIT),
            _HARD_TOP_LIMIT,
        ),
    )

    return DashboardStatusResponse(
        enabled=True,
        default_window_days=default_days,
        max_date_span_days=max_span,
        max_trend_buckets=max_buckets,
        top_limit_default=min(default_top, hard_top),
        top_limit_max=hard_top,
        caveats=list(_DASHBOARD_CAVEATS),
    )


@router.get(
    "/overview",
    response_model=DashboardOverviewResponse,
    summary="Get bounded dashboard overview",
    description=(
        "Returns a bounded, safe, aggregated overview of synthetic MULEGUARD "
        "accounts, alerts, cases, complaints, transactions, and persisted "
        "assessments. This endpoint is read-only and does not take adverse "
        "action."
    ),
)
def dashboard_overview(
    db: SessionDep,
    settings: SettingsDep,
    date_range: DateRangeParams = Depends(dashboard_date_range),
    _: User = Depends(require_permission(DASHBOARD_READ_PERMISSION)),
    top_limit: Annotated[
        Optional[int],
        Query(
            ge=1,
            le=100,
            description="Bounded top-N limit for breakdown categories.",
        ),
    ] = None,
) -> DashboardOverviewResponse:
    """
    Return bounded dashboard overview.
    """
    _ensure_dashboard_enabled(settings)

    date_from, date_to, defaulted, default_days, max_span = _resolve_window(
        date_range,
        settings,
    )
    limit = _bounded_top_limit(top_limit, settings)

    return _build_overview(
        db=db,
        settings=settings,
        date_from=date_from,
        date_to=date_to,
        defaulted=defaulted,
        default_window_days=default_days,
        max_span_days=max_span,
        top_limit=limit,
    )


@router.get(
    "/metrics",
    response_model=DashboardMetricsResponse,
    summary="Get bounded dashboard metrics",
    description=(
        "Returns bounded aggregate metrics and simple windowed rates for "
        "synthetic MULEGUARD operations. Rates are operational signals only and "
        "are not statistically calibrated."
    ),
)
def dashboard_metrics(
    db: SessionDep,
    settings: SettingsDep,
    date_range: DateRangeParams = Depends(dashboard_date_range),
    _: User = Depends(require_permission(DASHBOARD_READ_PERMISSION)),
) -> DashboardMetricsResponse:
    """
    Return bounded dashboard metrics.
    """
    _ensure_dashboard_enabled(settings)

    date_from, date_to, defaulted, default_days, max_span = _resolve_window(
        date_range,
        settings,
    )

    return _build_metrics(
        db=db,
        settings=settings,
        date_from=date_from,
        date_to=date_to,
        defaulted=defaulted,
        default_window_days=default_days,
        max_span_days=max_span,
    )


@router.get(
    "/queues",
    response_model=DashboardQueuesResponse,
    summary="Get bounded dashboard work queues",
    description=(
        "Returns bounded triage queues for unassigned alerts, assigned alerts, "
        "new cases, under-review cases, escalated cases, and unreviewed "
        "complaint correlations. Queue items are investigative leads only."
    ),
)
def dashboard_queues(
    db: SessionDep,
    settings: SettingsDep,
    actor: User = Depends(require_permission(DASHBOARD_READ_PERMISSION)),
    top_limit: Annotated[
        Optional[int],
        Query(
            ge=1,
            le=100,
            description="Bounded top-N limit for each queue section.",
        ),
    ] = None,
) -> DashboardQueuesResponse:
    """
    Return bounded dashboard work queues.
    """
    _ensure_dashboard_enabled(settings)

    limit = _bounded_top_limit(top_limit, settings)

    return _build_queues(
        db=db,
        actor=actor,
        limit=limit,
    )


@router.get(
    "/trends",
    response_model=DashboardTrendsResponse,
    summary="Get bounded dashboard trends",
    description=(
        "Returns bounded daily trend counts for synthetic MULEGUARD alerts, "
        "cases, complaints, transactions, and persisted assessments. Trend "
        "buckets are UTC calendar dates and are operational signals only."
    ),
)
def dashboard_trends(
    db: SessionDep,
    settings: SettingsDep,
    date_range: DateRangeParams = Depends(dashboard_date_range),
    _: User = Depends(require_permission(DASHBOARD_READ_PERMISSION)),
) -> DashboardTrendsResponse:
    """
    Return bounded dashboard trends.
    """
    _ensure_dashboard_enabled(settings)

    date_from, date_to, defaulted, default_days, max_span = _resolve_window(
        date_range,
        settings,
    )

    _validate_trend_buckets(
        date_from,
        date_to,
        settings,
    )

    return _build_trends(
        db=db,
        date_from=date_from,
        date_to=date_to,
        defaulted=defaulted,
        default_window_days=default_days,
        max_span_days=max_span,
    )


__all__ = [
    "router",
]