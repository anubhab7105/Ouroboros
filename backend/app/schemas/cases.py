"""
MULEGUARD investigation case schemas.

Transitions are not a free-form status field. `CaseTransitionRequest` carries
the target status plus whatever that transition requires — a disposition to
close, an assignee to start, a reason to escalate or reopen — and the state
machine rejects anything illegal with the list of what was allowed instead.

`available_transitions` is returned on every case detail response so the
frontend renders exactly the legal actions rather than keeping its own copy of
the workflow and drifting from the backend.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Optional

from pydantic import Field, field_validator

from app.schemas.common import IdentifierField, MuleGuardModel, ResponseModel
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "CaseCreateRequest",
    "CaseDetailResponse",
    "CaseEventResponse",
    "CaseEvidenceResponse",
    "CaseFilterParams",
    "CaseListResponse",
    "CaseNoteCreateRequest",
    "CaseNoteResponse",
    "CaseResponse",
    "CaseTransitionRequest",
    "CaseUpdateRequest",
    "EvidenceAttachRequest",
    "TransitionOption",
]

_STATUSES = ("NEW", "TRIAGED", "UNDER_INVESTIGATION", "ESCALATED", "CLOSED")
_PRIORITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_DISPOSITIONS = ("CONFIRMED_FRAUD", "FALSE_POSITIVE", "INCONCLUSIVE", "REFERRED")
_EVIDENCE_TYPES = (
    "ACCOUNT",
    "TRANSACTION",
    "COMPLAINT",
    "ALERT",
    "GRAPH_PATH",
    "MODEL_ASSESSMENT",
    "ENTITY_LINK",
)

CaseStatusField = Annotated[str, Field(pattern=f"^({'|'.join(_STATUSES)})$")]
PriorityField = Annotated[str, Field(pattern=f"^({'|'.join(_PRIORITIES)})$")]
DispositionField = Annotated[str, Field(pattern=f"^({'|'.join(_DISPOSITIONS)})$")]
EvidenceTypeField = Annotated[str, Field(pattern=f"^({'|'.join(_EVIDENCE_TYPES)})$")]


class TransitionOption(ResponseModel):
    """
    One legal transition from a case's current status.
    """

    action: str = Field(description="Action name, e.g. triage, escalate, close.")
    to_status: str = Field(alias="to", description="Resulting status.")
    description: str = Field(description="What the transition means.")
    requires_disposition: bool = Field(default=False)
    requires_assignee: bool = Field(default=False)
    requires_reason: bool = Field(default=False)


class CaseResponse(ResponseModel):
    """
    A case row.
    """

    id: str = Field(description="Case identifier.")
    title: str = Field(description="Case title.")
    status: str = Field(description="Workflow status.")
    priority: str = Field(description="Case priority.")
    disposition: Optional[str] = Field(
        default=None,
        description="Closure disposition. Always present on a CLOSED case.",
    )
    assignee_id: Optional[str] = Field(default=None)
    assignee_username: Optional[str] = Field(default=None)
    account_id: Optional[str] = Field(default=None)
    alert_id: Optional[str] = Field(default=None)
    created_at: Optional[datetime] = Field(default=None)
    updated_at: Optional[datetime] = Field(default=None)
    closed_at: Optional[datetime] = Field(default=None)
    evidence_count: int = Field(default=0)
    note_count: int = Field(default=0)


class CaseEvidenceResponse(ResponseModel):
    """
    One evidence attachment.
    """

    id: str = Field(description="Attachment identifier.")
    evidence_type: str = Field(description="Validated evidence type.")
    evidence_id: str = Field(description="Referenced record.")
    is_active: bool = Field(
        default=True,
        description=(
            "False when soft-removed. Removed items are kept so an earlier "
            "report stays reconstructible."
        ),
    )
    added_by: Optional[str] = Field(default=None)
    added_at: Optional[datetime] = Field(default=None)
    removed_at: Optional[datetime] = Field(default=None)
    removal_reason: Optional[str] = Field(default=None)


class CaseNoteResponse(ResponseModel):
    """
    One investigator note.
    """

    id: str = Field(description="Note identifier.")
    author_id: Optional[str] = Field(default=None)
    author_username: Optional[str] = Field(default=None)
    body: str = Field(description="Note text, redacted before storage.")
    is_internal: bool = Field(
        default=True,
        description="Internal notes are excluded from exported reports.",
    )
    created_at: Optional[datetime] = Field(default=None)
    revision_count: int = Field(
        default=0,
        description=(
            "Edits made. An edit appends a revision rather than overwriting, "
            "so the reasoning recorded at decision time survives."
        ),
    )


class CaseEventResponse(ResponseModel):
    """
    One append-only history entry.
    """

    id: str = Field(description="Event identifier.")
    action: str = Field(description="What happened.")
    actor_username: Optional[str] = Field(
        default=None,
        description=(
            "Denormalised, so history still reads correctly after a user "
            "record is removed."
        ),
    )
    resource_type: Optional[str] = Field(default=None)
    resource_id: Optional[str] = Field(default=None)
    summary: Optional[str] = Field(default=None)
    created_at: datetime = Field(description="When it happened, UTC.")


class CaseDetailResponse(CaseResponse):
    """
    Full case detail.
    """

    description: Optional[str] = Field(default=None)
    creator_username: Optional[str] = Field(default=None)
    evidence: list[CaseEvidenceResponse] = Field(default_factory=list)
    notes: list[CaseNoteResponse] = Field(default_factory=list)
    recent_events: list[CaseEventResponse] = Field(default_factory=list)
    available_transitions: list[TransitionOption] = Field(
        default_factory=list,
        description=(
            "Transitions legal right now. The frontend renders exactly these."
        ),
    )
    disposition_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Prior dispositions from earlier closures. Reopening preserves "
            "them rather than erasing the earlier decision."
        ),
    )


class CaseListResponse(PaginatedResponse[CaseResponse]):
    """
    A page of cases.
    """


class CaseCreateRequest(MuleGuardModel):
    """
    A new case.
    """

    title: str = Field(min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=10_000)
    priority: PriorityField = Field(default="MEDIUM")
    assignee_id: Optional[IdentifierField] = Field(default=None)
    account_id: Optional[IdentifierField] = Field(default=None)
    alert_id: Optional[IdentifierField] = Field(default=None)


class CaseUpdateRequest(MuleGuardModel):
    """
    Editable case fields.

    Status is absent on purpose: it changes only through a validated
    transition, never through a general edit.
    """

    title: Optional[str] = Field(default=None, min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=10_000)
    priority: Optional[PriorityField] = Field(default=None)
    assignee_id: Optional[IdentifierField] = Field(default=None)


class CaseTransitionRequest(MuleGuardModel):
    """
    A workflow transition.
    """

    target_status: CaseStatusField = Field(description="The status to move to.")
    disposition: Optional[DispositionField] = Field(
        default=None, description="Required when closing."
    )
    reason: Optional[str] = Field(
        default=None,
        max_length=2_000,
        description="Required when escalating, de-escalating or reopening.",
    )
    assignee_id: Optional[IdentifierField] = Field(
        default=None, description="Required when starting an investigation."
    )

    @field_validator("disposition")
    @classmethod
    def _closing_needs_disposition(cls, value: Optional[str], info) -> Optional[str]:
        """
        Catch a missing disposition before the request reaches the database.
        """
        target = (info.data or {}).get("target_status")

        if target == "CLOSED" and not value:
            raise ValueError(
                "closing a case requires a disposition "
                f"({', '.join(_DISPOSITIONS)})"
            )

        return value


class CaseNoteCreateRequest(MuleGuardModel):
    """
    A new note.
    """

    body: str = Field(min_length=1, max_length=10_000)
    is_internal: bool = Field(
        default=True,
        description="Internal notes are excluded from exported reports.",
    )


class EvidenceAttachRequest(MuleGuardModel):
    """
    Attach evidence to a case.

    Only a validated type and an existing record identifier are accepted.
    Arbitrary URLs and free-text locations are not, so evidence cannot point
    outside the system.
    """

    evidence_type: EvidenceTypeField = Field(description="Validated evidence type.")
    evidence_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        description="Identifier of an existing record.",
    )
    note: Optional[str] = Field(default=None, max_length=1_000)


class CaseFilterParams(MuleGuardModel):
    """
    Case list filters.
    """

    status: Optional[CaseStatusField] = Field(default=None)
    priority: Optional[PriorityField] = Field(default=None)
    disposition: Optional[DispositionField] = Field(default=None)
    assignee_id: Optional[IdentifierField] = Field(default=None)
    account_id: Optional[IdentifierField] = Field(default=None)
    open_only: bool = Field(default=False, description="Exclude CLOSED cases.")
    unassigned_only: bool = Field(default=False)
    created_after: Optional[datetime] = Field(default=None)
    q: Optional[str] = Field(default=None, max_length=200)
