"""
MULEGUARD account schemas.

Account status is **observational**, not an enforcement state. A `REVIEW_REQUIRED`
account has not been restricted by MULEGUARD; the field records what the source
system reported. Every response that carries a risk judgement therefore also
carries `caveats`, so the distinction travels with the data.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Optional

from pydantic import Field

from app.schemas.common import (
    IdentifierField,
    MuleGuardModel,
    ResponseModel,
    ScoreField,
)
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "AccountDetailResponse",
    "AccountFilterParams",
    "AccountListResponse",
    "AccountResponse",
    "AccountSummaryResponse",
    "LatestAssessmentSummary",
]

_ACCOUNT_TYPES = ("INDIVIDUAL", "BUSINESS", "MERCHANT", "OTHER")
_ACCOUNT_STATUSES = ("ACTIVE", "DORMANT", "CLOSED", "REVIEW_REQUIRED")
_RISK_BANDS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

AccountTypeField = Annotated[str, Field(pattern=f"^({'|'.join(_ACCOUNT_TYPES)})$")]
AccountStatusField = Annotated[str, Field(pattern=f"^({'|'.join(_ACCOUNT_STATUSES)})$")]
RiskBandField = Annotated[str, Field(pattern=f"^({'|'.join(_RISK_BANDS)})$")]


class LatestAssessmentSummary(ResponseModel):
    """
    The most recent risk assessment for an account, in brief.
    """

    assessment_id: str = Field(description="Assessment identifier.")
    score: Optional[Decimal] = Field(
        default=None,
        description=(
            "Investigative priority score, 0-100. Not a probability of guilt."
        ),
    )
    risk_band: Optional[str] = Field(default=None)
    scoring_mode: Optional[str] = Field(
        default=None,
        description=(
            "How the score was produced: TRAINED_MODEL, HEURISTIC_FALLBACK, "
            "RULES_ONLY, or ML_DISABLED. A reader needs this to weigh it."
        ),
    )
    as_of: Optional[datetime] = Field(
        default=None, description="Point-in-time instant the score describes."
    )
    scored_at: Optional[datetime] = Field(
        default=None, description="When scoring actually ran."
    )
    triggered_rule_count: int = Field(default=0)


class AccountResponse(ResponseModel):
    """
    An account row.
    """

    id: str = Field(description="Account identifier.")
    account_type: str = Field(description="Synthetic account type.")
    status: str = Field(
        description=(
            "Lifecycle status as reported by the source system. Observational "
            "only; MULEGUARD never sets it as an enforcement action."
        )
    )
    created_at: datetime = Field(description="Account opening timestamp.")
    latest_assessment: Optional[LatestAssessmentSummary] = Field(default=None)
    open_alert_count: int = Field(default=0)
    open_case_count: int = Field(default=0)


class AccountListResponse(PaginatedResponse[AccountResponse]):
    """
    A page of accounts.
    """


class AccountSummaryResponse(ResponseModel):
    """
    Aggregated behaviour for one account over a window.
    """

    account_id: str = Field(description="Account identifier.")
    window_days: int = Field(description="Window length in days.")
    window_start: datetime = Field(description="Inclusive window start, UTC.")
    window_end: datetime = Field(description="Exclusive window end, UTC.")

    completed_transaction_count: int = Field(
        default=0,
        description=(
            "COMPLETED transfers only. Failed and reversed transactions are "
            "excluded because they are not fund movement."
        ),
    )
    inbound_amount: Optional[Decimal] = Field(default=None)
    outbound_amount: Optional[Decimal] = Field(default=None)
    distinct_counterparties: int = Field(default=0)
    distinct_channels: int = Field(default=0)
    first_transaction_at: Optional[datetime] = Field(default=None)
    last_transaction_at: Optional[datetime] = Field(default=None)

    linked_entity_count: int = Field(default=0)
    shared_entity_account_count: int = Field(
        default=0,
        description=(
            "Accounts sharing at least one entity within the window. An "
            "association, not evidence of shared control."
        ),
    )
    complaint_count: int = Field(default=0)
    correlation_count: int = Field(default=0)

    caveats: list[str] = Field(
        default_factory=list,
        description="Interpretation limits for the figures above.",
    )


class AccountDetailResponse(ResponseModel):
    """
    Full account detail for the account page.
    """

    account: AccountResponse
    summary: Optional[AccountSummaryResponse] = Field(default=None)
    feature_snapshot_available: bool = Field(
        default=False,
        description="Whether a point-in-time feature snapshot exists.",
    )
    last_analysed_at: Optional[datetime] = Field(default=None)
    caveats: list[str] = Field(default_factory=list)


class AccountFilterParams(MuleGuardModel):
    """
    Account list filters.
    """

    account_type: Optional[AccountTypeField] = Field(default=None)
    status: Optional[AccountStatusField] = Field(default=None)
    risk_band: Optional[RiskBandField] = Field(
        default=None,
        description="Filter by the band of the account's latest assessment.",
    )
    min_score: Optional[ScoreField] = Field(default=None)
    max_score: Optional[ScoreField] = Field(default=None)
    created_after: Optional[datetime] = Field(default=None)
    created_before: Optional[datetime] = Field(default=None)
    has_open_alerts: Optional[bool] = Field(default=None)
    q: Optional[str] = Field(
        default=None, max_length=100, description="Free-text search on identifier."
    )
