"""
MULEGUARD alert schemas.

An alert is a triage-queue entry, not a decision. Nothing a client can send
here restricts an account; the available actions are acknowledge, assign,
escalate, close and open a case.

`first_seen_at` and `last_seen_at` are both exposed because alert
deduplication updates an existing entry rather than raising a new one each run.
Queue age comes from `first_seen_at`, which tells an analyst how long a pattern
has persisted — the single most useful column when working a backlog.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Optional

from pydantic import Field

from app.schemas.common import IdentifierField, MuleGuardModel, ResponseModel, ScoreField
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "AlertActionRequest",
    "AlertDetailResponse",
    "AlertEvidenceResponse",
    "AlertFilterParams",
    "AlertListResponse",
    "AlertResponse",
    "CreateCaseFromAlertRequest",
]

_STATES = ("NEW", "ACKNOWLEDGED", "UNDER_REVIEW", "ESCALATED", "CLOSED")
_PRIORITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_EVIDENCE_TYPES = (
    "ACCOUNT",
    "TRANSACTION",
    "COMPLAINT",
    "ALERT",
    "GRAPH_PATH",
    "MODEL_ASSESSMENT",
    "ENTITY_LINK",
)

AlertStateField = Annotated[str, Field(pattern=f"^({'|'.join(_STATES)})$")]
PriorityField = Annotated[str, Field(pattern=f"^({'|'.join(_PRIORITIES)})$")]
EvidenceTypeField = Annotated[str, Field(pattern=f"^({'|'.join(_EVIDENCE_TYPES)})$")]


class AlertEvidenceResponse(ResponseModel):
    """
    One evidence reference attached to an alert.
    """

    id: str = Field(description="Attachment identifier.")
    evidence_type: str = Field(description="Validated evidence type.")
    evidence_id: str = Field(description="Referenced record identifier.")
    resolves: Optional[bool] = Field(
        default=None,
        description=(
            "Whether the reference still resolves to an existing record. "
            "Reported rather than hidden, because a reader who cannot find a "
            "cited record should know the system cannot either."
        ),
    )
    created_at: Optional[datetime] = Field(default=None)


class AlertResponse(ResponseModel):
    """
    An alert row.
    """

    id: str = Field(description="Alert identifier.")
    account_id: str = Field(description="Alerted account.")
    assessment_id: Optional[str] = Field(default=None)
    title: str = Field(description="Alert title.")
    summary: Optional[str] = Field(default=None)
    priority: str = Field(description="Triage priority band.")
    state: str = Field(description="Triage state.")
    score: Optional[Decimal] = Field(
        default=None,
        description="Investigative priority score, 0-100. Not a probability of guilt.",
    )
    scoring_mode: str = Field(description="How the score was produced.")
    rule_codes: list[str] = Field(
        default_factory=list, description="Rule codes that contributed."
    )
    first_seen_at: datetime = Field(
        description=(
            "When this alert signature was first seen. Queue age is measured "
            "from here, not from the last run."
        )
    )
    last_seen_at: datetime = Field(
        description="Most recent run in which the signature recurred."
    )
    assigned_to: Optional[str] = Field(default=None)
    acknowledged_by: Optional[str] = Field(default=None)
    acknowledged_at: Optional[datetime] = Field(default=None)
    evidence_count: int = Field(default=0)
    case_count: int = Field(default=0)


class AlertDetailResponse(AlertResponse):
    """
    An alert with its evidence and signal breakdown.
    """

    signal_summary: dict[str, Any] = Field(
        default_factory=dict,
        description="Which components and typologies contributed.",
    )
    evidence: list[AlertEvidenceResponse] = Field(default_factory=list)
    dedup_window_start: Optional[datetime] = Field(default=None)
    dedup_window_end: Optional[datetime] = Field(default=None)
    available_actions: list[str] = Field(
        default_factory=list,
        description=(
            "Actions legal in the current state. None of them restricts an "
            "account."
        ),
    )
    caveats: list[str] = Field(
        default_factory=lambda: [
            "An alert is an investigative lead. It does not establish that an "
            "account holder participated in wrongdoing.",
            "Raising an alert triggers no automatic action against the account.",
        ]
    )


class AlertListResponse(PaginatedResponse[AlertResponse]):
    """
    A page of alerts.
    """


class AlertActionRequest(MuleGuardModel):
    """
    A triage action on an alert.
    """

    reason: Optional[str] = Field(
        default=None,
        max_length=1_000,
        description="Reasoning, recorded in the audit trail.",
    )
    assignee_id: Optional[IdentifierField] = Field(
        default=None, description="Required when assigning."
    )


class CreateCaseFromAlertRequest(MuleGuardModel):
    """
    Open an investigation case from an alert.
    """

    title: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Case title. Derived from the alert when omitted.",
    )
    assignee_id: Optional[IdentifierField] = Field(default=None)
    priority: Optional[PriorityField] = Field(
        default=None, description="Defaults to the alert's priority."
    )
    notes: Optional[str] = Field(default=None, max_length=4_000)


class AlertFilterParams(MuleGuardModel):
    """
    Alert queue filters.
    """

    state: Optional[AlertStateField] = Field(default=None)
    priority: Optional[PriorityField] = Field(default=None)
    account_id: Optional[IdentifierField] = Field(default=None)
    assigned_to: Optional[IdentifierField] = Field(default=None)
    unassigned_only: bool = Field(
        default=False, description="Only alerts with no owner."
    )
    open_only: bool = Field(
        default=False, description="Exclude CLOSED alerts."
    )
    min_score: Optional[ScoreField] = Field(default=None)
    rule_code: Optional[str] = Field(
        default=None, max_length=100, description="Alerts citing this rule."
    )
    first_seen_after: Optional[datetime] = Field(default=None)
    q: Optional[str] = Field(default=None, max_length=200)
