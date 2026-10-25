"""
MULEGUARD dashboard schemas.

Trend responses always state the `granularity` the server chose. A client that
asked for a year and silently received weekly buckets instead of daily ones
would mis-plot them, so the choice is part of the payload rather than an
implementation detail.

`WindowInfo` appears on every aggregate because the same count means different
things over 7 days and over a year.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Optional

from pydantic import Field

from app.schemas.common import IdentifierField, MuleGuardModel, ResponseModel

__all__ = [
    "AlertQueueItem",
    "CaseQueueItem",
    "CorrelationQueueItem",
    "DashboardOverviewResponse",
    "DashboardQueuesResponse",
    "DashboardWindowParams",
    "RiskDistributionResponse",
    "TrendBucket",
    "TrendResponse",
    "WindowInfo",
]

_GRANULARITIES = ("hour", "day", "week", "month")

GranularityField = Annotated[str, Field(pattern=f"^({'|'.join(_GRANULARITIES)})$")]


class WindowInfo(ResponseModel):
    """
    The time window an aggregate covers.
    """

    start: datetime = Field(description="Inclusive start, UTC.")
    end: datetime = Field(description="Exclusive end, UTC.")
    days: int = Field(description="Window length in days.")


class DashboardWindowParams(MuleGuardModel):
    """
    Dashboard window selection.
    """

    window_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Window length. Capped server-side at 365.",
    )
    as_of: Optional[datetime] = Field(
        default=None, description="Window end. Defaults to now."
    )


class DashboardOverviewResponse(ResponseModel):
    """
    Headline dashboard counts.
    """

    window: WindowInfo

    open_alerts: int = Field(default=0)
    new_alerts_in_window: int = Field(default=0)
    critical_open_alerts: int = Field(default=0)
    unassigned_open_alerts: int = Field(
        default=0,
        description="Open alerts with no owner: the queue nobody is working.",
    )

    open_cases: int = Field(default=0)
    escalated_cases: int = Field(default=0)

    total_accounts: int = Field(default=0)
    high_risk_accounts_in_window: int = Field(
        default=0,
        description=(
            "Accounts whose latest assessment in the window is HIGH or "
            "CRITICAL. Not a cumulative all-time total."
        ),
    )

    complaints_in_window: int = Field(default=0)
    unreviewed_correlations: int = Field(
        default=0,
        description="Correlations awaiting analyst review.",
    )

    completed_transaction_count: int = Field(default=0)
    completed_transaction_value: Optional[Decimal] = Field(
        default=None,
        description="COMPLETED transfers only; other statuses are excluded.",
    )

    caveats: list[str] = Field(
        default_factory=lambda: [
            "Counts describe investigative leads, not confirmed fraud.",
            "High-risk counts reflect the latest assessment inside the window.",
        ]
    )


class RiskDistributionResponse(ResponseModel):
    """
    Assessment counts by risk band.
    """

    window: WindowInfo
    counts: dict[str, int] = Field(
        default_factory=dict, description="Band name to assessment count."
    )
    total: int = Field(default=0)
    caveats: list[str] = Field(
        default_factory=lambda: [
            "A LOW band is not a clearance. It means the account was not "
            "prioritised, not that it was cleared.",
        ]
    )


class TrendBucket(ResponseModel):
    """
    One point on a trend series.
    """

    bucket: str = Field(description="ISO timestamp of the bucket start.")
    total: int = Field(default=0)
    LOW: int = Field(default=0)
    MEDIUM: int = Field(default=0)
    HIGH: int = Field(default=0)
    CRITICAL: int = Field(default=0)


class TrendResponse(ResponseModel):
    """
    A bucketed trend series.
    """

    window: WindowInfo
    granularity: str = Field(
        description=(
            "The bucket size the server chose for this span. Stated because a "
            "client that assumed daily buckets would mis-plot weekly ones."
        )
    )
    buckets: list[TrendBucket] = Field(default_factory=list)
    truncated: bool = Field(
        default=False,
        description="True when the bucket cap shortened the series.",
    )


class AlertQueueItem(ResponseModel):
    """
    One prioritised alert lead.
    """

    alert_id: str
    account_id: str
    title: str
    priority: str
    state: str
    score: Optional[Decimal] = Field(default=None)
    scoring_mode: Optional[str] = Field(default=None)
    rule_codes: list[str] = Field(default_factory=list)
    first_seen_at: Optional[datetime] = Field(
        default=None, description="Queue age is measured from here."
    )
    assigned_to: Optional[str] = Field(default=None)


class CaseQueueItem(ResponseModel):
    """
    One open case lead.
    """

    case_id: str
    title: str
    status: str
    priority: str
    account_id: Optional[str] = Field(default=None)
    assignee_id: Optional[str] = Field(default=None)
    updated_at: Optional[datetime] = Field(default=None)


class CorrelationQueueItem(ResponseModel):
    """
    One unreviewed complaint correlation.
    """

    correlation_id: str
    complaint_id: str
    account_id: Optional[str] = Field(default=None)
    transaction_id: Optional[str] = Field(default=None)
    match_tier: int = Field(ge=1, le=5, description="1 strongest, 5 weakest.")
    match_method: str
    deterministic: bool
    confidence: Optional[Decimal] = Field(default=None)


class DashboardQueuesResponse(ResponseModel):
    """
    The prioritised investigative queues.
    """

    alerts: list[AlertQueueItem] = Field(default_factory=list)
    cases: list[CaseQueueItem] = Field(default_factory=list)
    unreviewed_correlations: list[CorrelationQueueItem] = Field(default_factory=list)
    generated_at: Optional[datetime] = Field(default=None)
    caveats: list[str] = Field(
        default_factory=lambda: [
            "Queues are ordered by priority then score, which is the order to "
            "work them in. Ordering shifts as new analysis results land.",
        ]
    )
