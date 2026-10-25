"""
MULEGUARD complaint and correlation schemas.

Two things these schemas are careful about:

- **Raw narratives are source facts.** `narrative_raw` is returned verbatim;
  `narrative_normalized` is the derived form. They are separate fields because
  overwriting the original would destroy evidence.
- **Correlation tier is always present.** Tier 1 and 2 are deterministic
  reference matches; tiers 3 to 5 are inferred and carry a confidence. A
  deterministic match deliberately has `confidence: null` rather than 1.0, so a
  client cannot average an identity together with an estimate.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Optional

from pydantic import Field

from app.schemas.common import ConfidenceField, IdentifierField, MuleGuardModel, ResponseModel
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "ComplaintCorrelationResponse",
    "ComplaintCorrelationListResponse",
    "ComplaintDetailResponse",
    "ComplaintFilterParams",
    "ComplaintListResponse",
    "ComplaintResponse",
    "CorrelationReviewRequest",
]

_REVIEW_STATES = ("UNREVIEWED", "REVIEWED", "ACCEPTED", "REJECTED", "NEEDS_MORE_INFO")
_MATCH_METHODS = (
    "EXACT",
    "NORMALIZED",
    "ENTITY_TEMPORAL",
    "GRAPH_TEMPORAL",
    "NARRATIVE_EXTRACTION",
    "MANUAL",
    "UNKNOWN",
)

ReviewStateField = Annotated[str, Field(pattern=f"^({'|'.join(_REVIEW_STATES)})$")]
MatchMethodField = Annotated[str, Field(pattern=f"^({'|'.join(_MATCH_METHODS)})$")]

TIER_LEGEND: dict[str, str] = {
    "1": "exact reference match (deterministic)",
    "2": "normalised reference match (deterministic)",
    "3": "shared entity within the complaint window (inferred)",
    "4": "amount and time proximity (inferred)",
    "5": "reference extracted from narrative text (inferred)",
}


class ComplaintResponse(ResponseModel):
    """
    A complaint row.
    """

    id: str = Field(description="Complaint identifier.")
    reference: str = Field(description="Source complaint reference.")
    reported_at: datetime = Field(description="When the complaint was filed, UTC.")
    category: str = Field(description="Complaint category.")
    transaction_reference: Optional[str] = Field(
        default=None, description="Transaction reference the complainant supplied."
    )
    victim_account_id: Optional[str] = Field(default=None)
    suspected_account_id: Optional[str] = Field(default=None)
    amount: Optional[Decimal] = Field(default=None, description="Reported amount.")
    currency: Optional[str] = Field(default=None)
    source: Optional[str] = Field(default=None, description="Reporting channel.")
    correlation_count: int = Field(default=0)
    narrative_excerpt: Optional[str] = Field(
        default=None,
        description="Short preview of the narrative, for list views.",
    )


class ComplaintDetailResponse(ComplaintResponse):
    """
    A complaint with its full narrative.
    """

    narrative_raw: str = Field(
        description=(
            "The original narrative, verbatim. A source fact; never rewritten."
        )
    )
    narrative_normalized: Optional[str] = Field(
        default=None,
        description=(
            "Derived normalised form, stored separately so the original "
            "survives intact."
        ),
    )
    ingested_at: Optional[datetime] = Field(default=None)
    caveats: list[str] = Field(
        default_factory=lambda: [
            "A complaint is an allegation by a complainant. It is not an "
            "adjudicated finding.",
        ]
    )


class ComplaintListResponse(PaginatedResponse[ComplaintResponse]):
    """
    A page of complaints.
    """


class ComplaintCorrelationResponse(ResponseModel):
    """
    One complaint-to-record correlation.
    """

    id: str = Field(description="Correlation identifier.")
    complaint_id: str = Field(description="The complaint.")
    complaint_reference: Optional[str] = Field(default=None)
    account_id: Optional[str] = Field(default=None)
    transaction_id: Optional[str] = Field(default=None)
    entity_id: Optional[str] = Field(default=None)

    match_tier: int = Field(ge=1, le=5, description="1 strongest, 5 weakest.")
    match_tier_label: Optional[str] = Field(
        default=None, description="Human-readable description of the tier."
    )
    match_method: str = Field(description="How the correlation was established.")
    deterministic: bool = Field(
        description="True for tiers 1 and 2, where the match is an identity."
    )
    confidence: Optional[Decimal] = Field(
        default=None,
        description=(
            "Confidence for inferred correlations only. Null for a "
            "deterministic match, so an identity is never averaged with an "
            "estimate."
        ),
    )
    review_state: str = Field(description="Analyst review state.")
    reviewed_by: Optional[str] = Field(default=None)
    reviewed_at: Optional[datetime] = Field(default=None)
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: Optional[datetime] = Field(default=None)


class ComplaintCorrelationListResponse(PaginatedResponse[ComplaintCorrelationResponse]):
    """
    A page of correlations, with the tier legend attached.
    """

    tier_legend: dict[str, str] = Field(default_factory=lambda: dict(TIER_LEGEND))


class CorrelationReviewRequest(MuleGuardModel):
    """
    An analyst's review decision on a correlation.
    """

    review_state: ReviewStateField = Field(description="The decision.")
    notes: Optional[str] = Field(
        default=None,
        max_length=2_000,
        description="Reasoning, recorded with the decision.",
    )


class ComplaintFilterParams(MuleGuardModel):
    """
    Complaint list filters.
    """

    category: Optional[str] = Field(default=None, max_length=100)
    source: Optional[str] = Field(default=None, max_length=100)
    account_id: Optional[IdentifierField] = Field(
        default=None, description="Matches victim or suspected account."
    )
    reported_after: Optional[datetime] = Field(default=None)
    reported_before: Optional[datetime] = Field(default=None)
    has_correlations: Optional[bool] = Field(default=None)
    min_match_tier: Optional[int] = Field(default=None, ge=1, le=5)
    review_state: Optional[ReviewStateField] = Field(default=None)
    q: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Free-text search over reference and narrative.",
    )
