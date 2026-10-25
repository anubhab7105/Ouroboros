"""
MULEGUARD analysis run and assessment schemas.

`AnalysisRunResponse` mirrors the fields the analysis endpoint already returns,
so this module is the documented contract for them rather than a second,
divergent shape.

`PARTIAL` is a first-class status, not an error. A 5,000-account run where
three accounts failed produced usable output and should say so, rather than
claiming success or throwing the rest away.

Assessment responses always carry `components`, `caveats` and `scoring_mode`.
A score without the knowledge that the model was unavailable and the weights
were renormalised is a number a reader will over-trust.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Optional

from pydantic import Field, field_validator

from app.schemas.common import IdentifierField, MuleGuardModel, ResponseModel, ScoreField
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "AnalysisRunRequest",
    "AnalysisRunResponse",
    "AnalysisRunListResponse",
    "AnalysisRunResultsResponse",
    "AssessmentResponse",
    "ComponentBreakdown",
    "RiskIndicatorResponse",
    "RuleHitResponse",
]

_RUN_STATUSES = ("QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "PARTIAL")
_SCORING_MODES = (
    "TRAINED_MODEL",
    "HEURISTIC_FALLBACK",
    "RULES_ONLY",
    "ML_DISABLED",
    "UNKNOWN",
)
_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_RISK_BANDS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_INDICATOR_TYPES = (
    "RULE",
    "MODEL",
    "ANOMALY",
    "GRAPH",
    "COMPLAINT",
    "FEATURE",
    "FUSED_RISK",
)

RunStatusField = Annotated[str, Field(pattern=f"^({'|'.join(_RUN_STATUSES)})$")]
ScoringModeField = Annotated[str, Field(pattern=f"^({'|'.join(_SCORING_MODES)})$")]
SeverityField = Annotated[str, Field(pattern=f"^({'|'.join(_SEVERITIES)})$")]
RiskBandField = Annotated[str, Field(pattern=f"^({'|'.join(_RISK_BANDS)})$")]
IndicatorTypeField = Annotated[str, Field(pattern=f"^({'|'.join(_INDICATOR_TYPES)})$")]


class AnalysisRunRequest(MuleGuardModel):
    """
    A request to run analysis.

    With no `account_ids`, every account created before `as_of` is scored up to
    the configured cap.
    """

    account_ids: Optional[list[IdentifierField]] = Field(
        default=None,
        max_length=10_000,
        description="Explicit account selection. Omit to score all accounts.",
    )
    as_of: Optional[datetime] = Field(
        default=None,
        description=(
            "Point-in-time instant. Features see only what was knowable "
            "before it. Defaults to now; a future value is rejected."
        ),
    )
    max_accounts: Optional[int] = Field(
        default=None,
        ge=1,
        le=10_000,
        description="Cap on accounts scored when no explicit selection is given.",
    )
    run_type: str = Field(
        default="batch",
        max_length=50,
        description="batch, targeted, or replay.",
    )
    notes: Optional[str] = Field(default=None, max_length=1_000)

    @field_validator("as_of")
    @classmethod
    def _not_future(cls, value: Optional[datetime]) -> Optional[datetime]:
        """
        Reject a future observation instant.

        Scoring "as of" the future would silently include nothing, producing an
        empty result that looks like a clean run.
        """
        from app.utils.dates import ensure_utc, utcnow

        normalised = ensure_utc(value)

        if normalised is not None and normalised > utcnow():
            raise ValueError("as_of must not be in the future")

        return normalised


class AnalysisRunResponse(ResponseModel):
    """
    An analysis run.
    """

    id: str = Field(description="Run identifier.")
    status: str = Field(
        description=(
            "QUEUED, RUNNING, SUCCEEDED, PARTIAL, FAILED or CANCELLED. "
            "PARTIAL means usable output with some per-account failures."
        )
    )
    scoring_mode: str = Field(description="Dominant scoring mode across the run.")
    run_type: Optional[str] = Field(default=None)
    model_version_id: Optional[str] = Field(default=None)
    model_version: Optional[str] = Field(default=None)
    requested_by: Optional[str] = Field(default=None)
    requested_by_username: Optional[str] = Field(default=None)
    started_at: Optional[datetime] = Field(default=None)
    finished_at: Optional[datetime] = Field(default=None)
    duration_seconds: Optional[float] = Field(default=None)

    account_count: int = Field(default=0, description="Accounts selected.")
    processed_count: int = Field(default=0, description="Accounts successfully scored.")
    assessment_count: int = Field(default=0)
    alert_count: int = Field(default=0, description="New alerts raised.")
    error_count: int = Field(default=0, description="Per-account failures.")

    feature_version: Optional[str] = Field(default=None)
    rules_version: Optional[str] = Field(default=None)
    score_version: Optional[str] = Field(default=None)
    dataset_fingerprint: Optional[str] = Field(
        default=None, description="Dataset shape digest, for reproducibility."
    )
    summary: Optional[dict[str, Any]] = Field(default=None)
    error_code: Optional[str] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    caveats: list[str] = Field(default_factory=list)


class AnalysisRunListResponse(PaginatedResponse[AnalysisRunResponse]):
    """
    A page of analysis runs.
    """


class ComponentBreakdown(ResponseModel):
    """
    One component's contribution to a fused score.
    """

    name: str = Field(description="rules, model, anomaly, graph or complaint.")
    normalised_value: Optional[float] = Field(
        default=None, ge=0, le=1, description="The component's 0-1 value."
    )
    effective_weight: Optional[float] = Field(
        default=None,
        description=(
            "Weight after renormalisation. Differs from the configured weight "
            "when another component was unavailable."
        ),
    )
    contribution_points: Optional[float] = Field(
        default=None, description="Points of the 0-100 score from this component."
    )
    available: bool = Field(default=True)
    source: Optional[str] = Field(default=None)


class RuleHitResponse(ResponseModel):
    """
    One triggered detection rule.
    """

    id: str = Field(description="Rule hit identifier.")
    rule_code: str = Field(description="Stable rule code.")
    rule_version: str = Field(default="v1")
    severity: str = Field(description="Rule severity.")
    triggered: bool = Field(default=True)
    measured_value: Optional[Decimal] = Field(default=None)
    threshold: Optional[Decimal] = Field(default=None)
    explanation: Optional[str] = Field(
        default=None, description="Analyst-facing reason the rule fired."
    )
    evidence_refs: list[str] = Field(default_factory=list)
    evaluated_at: Optional[datetime] = Field(default=None)


class RiskIndicatorResponse(ResponseModel):
    """
    One evidence-backed risk indicator.
    """

    id: str = Field(description="Indicator identifier.")
    indicator_type: str = Field(description="Where the indicator came from.")
    code: str = Field(description="Stable indicator code.")
    title: str = Field(description="Short label.")
    severity: str = Field(description="Indicator severity.")
    measured_value: Optional[Decimal] = Field(default=None)
    threshold: Optional[Decimal] = Field(default=None)
    explanation: Optional[str] = Field(default=None)
    evidence_refs: list[str] = Field(
        default_factory=list,
        description=(
            "Records supporting the indicator. An indicator with no resolvable "
            "evidence is omitted rather than shown unsupported."
        ),
    )
    rule_hit_id: Optional[str] = Field(default=None)


class AssessmentResponse(ResponseModel):
    """
    One account's risk assessment.
    """

    id: str = Field(description="Assessment identifier.")
    account_id: str = Field(description="Assessed account.")
    analysis_run_id: Optional[str] = Field(default=None)
    feature_snapshot_id: Optional[str] = Field(default=None)
    model_version_id: Optional[str] = Field(default=None)

    as_of: datetime = Field(description="Point-in-time instant assessed.")
    scored_at: datetime = Field(description="When scoring ran.")
    score: Decimal = Field(
        description=(
            "Investigative priority score, 0-100. Ranks attention; it is not a "
            "probability of guilt."
        )
    )
    score_type: str = Field(default="investigative_priority_score")
    score_version: Optional[str] = Field(default=None)
    risk_band: str = Field(description="Configured band for the score.")
    scoring_mode: str = Field(description="How the score was produced.")

    components: list[ComponentBreakdown] = Field(
        default_factory=list, description="Per-component contributions."
    )
    unavailable_components: list[str] = Field(
        default_factory=list,
        description=(
            "Components that had no data. Their weight was redistributed, "
            "which lowers confidence in the score but not the underlying risk."
        ),
    )
    indicators: list[RiskIndicatorResponse] = Field(default_factory=list)
    rule_hits: list[RuleHitResponse] = Field(default_factory=list)
    explanation_summary: Optional[str] = Field(default=None)
    caveats: list[str] = Field(default_factory=list)


class AnalysisRunResultsResponse(ResponseModel):
    """
    A run's assessments, ranked.
    """

    run: AnalysisRunResponse
    assessments: list[AssessmentResponse] = Field(default_factory=list)
    total_assessments: int = Field(default=0)
    total_alerts: int = Field(default=0)
    caveats: list[str] = Field(default_factory=list)
