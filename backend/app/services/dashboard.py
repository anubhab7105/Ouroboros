"""
MULEGUARD dashboard aggregation service.

Computes the counts, trends, and prioritised queues the investigation dashboard
shows.

Every query here is bounded by a window and a row cap. Dashboard endpoints are
the ones hit on every page load, so an unbounded aggregate over the whole
transaction table is the easiest way to make the product feel broken.

Trend granularity is chosen from the requested span (`windows.default.json`),
so a one-year request returns weekly buckets rather than 365 points. The
response states which granularity it used; a caller that silently receives
fewer points than it asked for would mis-plot them.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any, Final, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    Account,
    Alert,
    AlertState,
    CaseStatus,
    Complaint,
    ComplaintCorrelation,
    ComplaintReviewState,
    InvestigationCase,
    ModelAssessment,
    Priority,
    RiskBand,
    Transaction,
    TransactionStatus,
)
from app.services.policy import get_windows_policy
from app.utils.dates import ensure_utc, floor_to_granularity, utcnow
from app.utils.decimals import to_float
from app.utils.json import sanitize_json

logger = logging.getLogger("muleguard.backend.services.dashboard")

__all__ = [
    "DASHBOARD_SERVICE_VERSION",
    "alert_trend",
    "complaint_category_counts",
    "dashboard_overview",
    "get_dashboard_service_metadata",
    "granularity_for_span",
    "prioritised_queues",
    "risk_distribution",
]

DASHBOARD_SERVICE_VERSION: Final[str] = "v1"

_DEFAULT_WINDOW_DAYS: Final[int] = 30
_MAX_WINDOW_DAYS: Final[int] = 365
_MAX_BUCKETS: Final[int] = 180
_MAX_QUEUE_ITEMS: Final[int] = 25

_OPEN_ALERT_STATES: Final[tuple[AlertState, ...]] = (
    AlertState.NEW,
    AlertState.ACKNOWLEDGED,
    AlertState.UNDER_REVIEW,
    AlertState.ESCALATED,
)

_OPEN_CASE_STATES: Final[tuple[CaseStatus, ...]] = (
    CaseStatus.NEW,
    CaseStatus.TRIAGED,
    CaseStatus.UNDER_INVESTIGATION,
    CaseStatus.ESCALATED,
)


def granularity_for_span(days: int) -> str:
    """
    Choose a trend granularity for a span, from the windows policy.
    """
    try:
        rules = (get_windows_policy().get("trend_granularity") or {}).get("rules") or []
    except Exception:
        rules = []

    for rule in rules:
        if not isinstance(rule, Mapping):
            continue

        cap = rule.get("max_span_days")

        if cap is None:
            return str(rule.get("granularity") or "month")

        try:
            if days <= int(cap):
                return str(rule.get("granularity") or "day")
        except (TypeError, ValueError):
            continue

    if days <= 2:
        return "hour"

    if days <= 90:
        return "day"

    if days <= 365:
        return "week"

    return "month"


def _window(days: Optional[int], as_of: Optional[datetime]) -> tuple[datetime, datetime, int]:
    """
    Resolve a bounded dashboard window.
    """
    end = ensure_utc(as_of) or utcnow()
    span = max(1, min(int(days or _DEFAULT_WINDOW_DAYS), _MAX_WINDOW_DAYS))
    return end - timedelta(days=span), end, span


def dashboard_overview(
    db: Session,
    *,
    window_days: Optional[int] = None,
    as_of: Optional[datetime] = None,
) -> dict[str, Any]:
    """
    Return the headline counts for the dashboard.
    """
    start, end, span = _window(window_days, as_of)

    def _count(model: Any, *conditions: Any) -> int:
        stmt = select(func.count()).select_from(model)

        for condition in conditions:
            stmt = stmt.where(condition)

        return int(db.execute(stmt).scalar() or 0)

    open_alerts = _count(Alert, Alert.state.in_(_OPEN_ALERT_STATES))
    new_alerts = _count(
        Alert,
        Alert.state == AlertState.NEW,
        Alert.record_created_at >= start,
    )
    critical_alerts = _count(
        Alert,
        Alert.state.in_(_OPEN_ALERT_STATES),
        Alert.priority == Priority.CRITICAL,
    )
    unassigned_alerts = _count(
        Alert,
        Alert.state.in_(_OPEN_ALERT_STATES),
        Alert.assigned_to.is_(None),
    )

    open_cases = _count(InvestigationCase, InvestigationCase.status.in_(_OPEN_CASE_STATES))
    escalated_cases = _count(
        InvestigationCase, InvestigationCase.status == CaseStatus.ESCALATED
    )

    high_risk_accounts = _count(
        ModelAssessment,
        ModelAssessment.risk_band.in_([RiskBand.HIGH, RiskBand.CRITICAL]),
        ModelAssessment.as_of >= start,
    )

    complaints_in_window = _count(Complaint, Complaint.reported_at >= start)
    unreviewed_correlations = _count(
        ComplaintCorrelation,
        ComplaintCorrelation.review_state == ComplaintReviewState.UNREVIEWED,
    )

    completed_value = db.execute(
        select(func.coalesce(func.sum(Transaction.amount), 0))
        .where(Transaction.status == TransactionStatus.COMPLETED)
        .where(Transaction.occurred_at >= start)
        .where(Transaction.occurred_at <= end)
    ).scalar()

    return {
        "window": {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "days": span,
        },
        "alerts": {
            "open": open_alerts,
            "new_in_window": new_alerts,
            "critical_open": critical_alerts,
            "unassigned_open": unassigned_alerts,
        },
        "cases": {
            "open": open_cases,
            "escalated": escalated_cases,
        },
        "accounts": {
            "total": _count(Account),
            "high_risk_assessed_in_window": high_risk_accounts,
        },
        "complaints": {
            "reported_in_window": complaints_in_window,
            "unreviewed_correlations": unreviewed_correlations,
        },
        "transactions": {
            "completed_value_in_window": to_float(completed_value) or 0.0,
            "completed_count_in_window": _count(
                Transaction,
                Transaction.status == TransactionStatus.COMPLETED,
                Transaction.occurred_at >= start,
                Transaction.occurred_at <= end,
            ),
        },
        "caveats": [
            "Counts describe investigative leads, not confirmed fraud.",
            "High-risk account counts reflect the latest assessment inside the "
            "window, not a cumulative total.",
        ],
    }


def risk_distribution(
    db: Session,
    *,
    window_days: Optional[int] = None,
    as_of: Optional[datetime] = None,
) -> dict[str, int]:
    """
    Return assessment counts by risk band within the window.
    """
    start, end, _ = _window(window_days, as_of)

    rows = db.execute(
        select(ModelAssessment.risk_band, func.count())
        .where(ModelAssessment.as_of >= start)
        .where(ModelAssessment.as_of <= end)
        .group_by(ModelAssessment.risk_band)
    ).all()

    counts = {band.value: 0 for band in RiskBand}

    for band, count in rows:
        counts[str(getattr(band, "value", band))] = int(count)

    return counts


def alert_trend(
    db: Session,
    *,
    window_days: Optional[int] = None,
    as_of: Optional[datetime] = None,
) -> dict[str, Any]:
    """
    Return alert counts bucketed over the window.

    Bucketing happens in Python rather than SQL: date truncation syntax differs
    between PostgreSQL and SQLite, and the project supports both.
    """
    start, end, span = _window(window_days, as_of)
    granularity = granularity_for_span(span)

    rows = db.execute(
        select(Alert.record_created_at, Alert.priority)
        .where(Alert.record_created_at >= start)
        .where(Alert.record_created_at <= end)
        .order_by(Alert.record_created_at)
        .limit(50_000)
    ).all()

    buckets: dict[str, dict[str, int]] = {}

    for created_at, priority in rows:
        moment = ensure_utc(created_at)

        if moment is None:
            continue

        key = floor_to_granularity(moment, granularity).isoformat()
        entry = buckets.setdefault(
            key, {"total": 0, **{p.value: 0 for p in Priority}}
        )
        entry["total"] += 1
        entry[str(getattr(priority, "value", priority))] += 1

    ordered = sorted(buckets.items())[-_MAX_BUCKETS:]

    return {
        "granularity": granularity,
        "window": {"start": start.isoformat(), "end": end.isoformat(), "days": span},
        "buckets": [{"bucket": key, **values} for key, values in ordered],
        "truncated": len(buckets) > _MAX_BUCKETS,
    }


def complaint_category_counts(
    db: Session,
    *,
    window_days: Optional[int] = None,
    as_of: Optional[datetime] = None,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """
    Return complaint counts by category within the window.
    """
    start, end, _ = _window(window_days, as_of)

    rows = db.execute(
        select(Complaint.category, func.count())
        .where(Complaint.reported_at >= start)
        .where(Complaint.reported_at <= end)
        .group_by(Complaint.category)
        .order_by(func.count().desc())
        .limit(max(1, min(int(limit), 50)))
    ).all()

    return [{"category": str(category or "other"), "count": int(count)} for category, count in rows]


def prioritised_queues(
    db: Session,
    *,
    limit: int = _MAX_QUEUE_ITEMS,
    assignee_id: Optional[str] = None,
) -> dict[str, list[dict[str, Any]]]:
    """
    Return the prioritised investigative leads.

    Ordered by priority then score, which is the order an analyst should work
    the queue in.
    """
    capped = max(1, min(int(limit), _MAX_QUEUE_ITEMS))

    alert_stmt = (
        select(Alert)
        .where(Alert.state.in_(_OPEN_ALERT_STATES))
        .order_by(Alert.priority.desc(), Alert.score.desc().nullslast())
        .limit(capped)
    )

    if assignee_id:
        alert_stmt = alert_stmt.where(Alert.assigned_to == str(assignee_id))

    alerts = [
        {
            "alert_id": str(alert.id),
            "account_id": str(alert.account_id),
            "title": str(alert.title),
            "priority": alert.priority.value,
            "state": alert.state.value,
            "score": to_float(alert.score),
            "scoring_mode": alert.scoring_mode.value,
            "rule_codes": list(alert.rule_codes_json or [])[:8],
            "first_seen_at": (ensure_utc(alert.first_seen_at) or utcnow()).isoformat(),
            "assigned_to": alert.assigned_to,
        }
        for alert in db.execute(alert_stmt).scalars()
    ]

    case_stmt = (
        select(InvestigationCase)
        .where(InvestigationCase.status.in_(_OPEN_CASE_STATES))
        .order_by(
            InvestigationCase.priority.desc(),
            InvestigationCase.record_updated_at.desc(),
        )
        .limit(capped)
    )

    if assignee_id:
        case_stmt = case_stmt.where(InvestigationCase.assignee_id == str(assignee_id))

    cases = [
        {
            "case_id": str(case.id),
            "title": str(case.title),
            "status": case.status.value,
            "priority": case.priority.value,
            "account_id": case.account_id,
            "assignee_id": case.assignee_id,
            "updated_at": (
                ensure_utc(case.record_updated_at) or utcnow()
            ).isoformat(),
        }
        for case in db.execute(case_stmt).scalars()
    ]

    correlations = [
        {
            "correlation_id": str(row.id),
            "complaint_id": str(row.complaint_id),
            "account_id": row.account_id,
            "transaction_id": row.transaction_id,
            "match_tier": int(row.match_tier),
            "match_method": row.match_method.value,
            "deterministic": bool(row.deterministic),
            "confidence": to_float(row.confidence),
        }
        for row in db.execute(
            select(ComplaintCorrelation)
            .where(
                ComplaintCorrelation.review_state == ComplaintReviewState.UNREVIEWED
            )
            # Strongest tier first: tier 1 is an identity, tier 5 is a guess.
            .order_by(
                ComplaintCorrelation.match_tier.asc(),
                ComplaintCorrelation.record_created_at.desc(),
            )
            .limit(capped)
        ).scalars()
    ]

    return {
        "alerts": alerts,
        "cases": cases,
        "unreviewed_correlations": correlations,
    }


def get_dashboard_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the dashboard service.
    """
    return {
        "service": "muleguard.backend.services.dashboard",
        "version": DASHBOARD_SERVICE_VERSION,
        "limits": {
            "default_window_days": _DEFAULT_WINDOW_DAYS,
            "max_window_days": _MAX_WINDOW_DAYS,
            "max_trend_buckets": _MAX_BUCKETS,
            "max_queue_items": _MAX_QUEUE_ITEMS,
        },
        "open_alert_states": [state.value for state in _OPEN_ALERT_STATES],
        "open_case_states": [state.value for state in _OPEN_CASE_STATES],
        "notes": [
            "Trend granularity is chosen from the requested span and stated in "
            "the response.",
            "Bucketing happens in Python because date truncation syntax differs "
            "between PostgreSQL and SQLite.",
            "Every aggregate is bounded by a window and a row cap.",
        ],
    }
