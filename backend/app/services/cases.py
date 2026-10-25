"""
MULEGUARD investigation case service.

Creates cases, moves them through the workflow defined in
`app.services.case_state_machine`, and keeps the append-only history in step.

Every transition does three things atomically: validate against the state
machine, update the case, and append a `CaseEvent`. They belong together — a
status change with no history entry is an unexplained change, and history
without the change is a lie.

Nothing here is automatic. The detection pipeline raises alerts; a human
creates and advances cases. `create_case_from_alert` is called by an analyst
acting on an alert, never by the analysis run.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.exceptions import CaseClosedError, InvalidCaseTransitionError, NotFoundError
from app.models import (
    Alert,
    AlertState,
    CaseStatus,
    Disposition,
    EvidenceType,
    InvestigationCase,
    ModelAssessment,
    Priority,
    User,
)
from app.services.case_events import record_case_event
from app.services.case_state_machine import (
    allowed_transitions,
    is_terminal,
    validate_transition,
)
from app.services.evidence import add_case_evidence
from app.utils.dates import ensure_utc, utcnow
from app.utils.json import sanitize_json
from app.utils.text import clean_text, truncate

logger = logging.getLogger("muleguard.backend.services.cases")

__all__ = [
    "CASES_SERVICE_VERSION",
    "assign_case",
    "available_transitions",
    "close_case",
    "create_case",
    "create_case_from_alert",
    "get_cases_service_metadata",
    "list_cases",
    "reopen_case",
    "transition_case",
]

CASES_SERVICE_VERSION: Final[str] = "v1"

_MAX_TITLE_LENGTH: Final[int] = 200
_MAX_DESCRIPTION_LENGTH: Final[int] = 10_000


def _require_case(db: Session, case_id: str) -> InvestigationCase:
    """
    Load a case or raise NotFoundError.
    """
    case = db.get(InvestigationCase, str(case_id))

    if case is None:
        raise NotFoundError(
            "Case not found.",
            details={"case_id": str(case_id)[:64]},
        )

    return case


def create_case(
    db: Session,
    *,
    title: str,
    description: Optional[str] = None,
    priority: Priority = Priority.MEDIUM,
    creator: Optional[User] = None,
    creator_id: Optional[str] = None,
    assignee_id: Optional[str] = None,
    account_id: Optional[str] = None,
    alert_id: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> InvestigationCase:
    """
    Create a case in the NEW state and record its creation event.
    """
    cleaned_title = truncate(clean_text(title, _MAX_TITLE_LENGTH), _MAX_TITLE_LENGTH)

    if not cleaned_title:
        raise ValueError("A case requires a title.")

    resolved_creator = creator_id or (
        str(getattr(creator, "id", "") or "") or None if creator is not None else None
    )

    case = InvestigationCase(
        title=cleaned_title,
        description=clean_text(description or "", _MAX_DESCRIPTION_LENGTH) or None,
        status=CaseStatus.NEW,
        priority=priority if isinstance(priority, Priority) else Priority.MEDIUM,
        assignee_id=assignee_id,
        creator_id=resolved_creator,
        alert_id=alert_id,
        account_id=account_id,
        disposition=None,
        metadata_json=sanitize_json(
            {"service_version": CASES_SERVICE_VERSION, **dict(metadata or {})},
            max_items=30,
        ),
    )
    db.add(case)
    db.flush()

    record_case_event(
        db,
        case_id=str(case.id),
        action="created",
        actor=creator,
        actor_id=resolved_creator,
        resource_type="investigation_case",
        resource_id=str(case.id),
        summary=f"Case created: {cleaned_title}",
        metadata={
            "priority": case.priority.value,
            "account_id": account_id,
            "alert_id": alert_id,
        },
    )

    if assignee_id:
        record_case_event(
            db,
            case_id=str(case.id),
            action="assigned",
            actor=creator,
            actor_id=resolved_creator,
            resource_type="user",
            resource_id=assignee_id,
            summary="Case assigned at creation.",
        )

    return case


def create_case_from_alert(
    db: Session,
    *,
    alert_id: str,
    creator: Optional[User] = None,
    creator_id: Optional[str] = None,
    assignee_id: Optional[str] = None,
    title: Optional[str] = None,
    priority: Optional[Priority] = None,
) -> InvestigationCase:
    """
    Open a case from an alert, carrying the alert's evidence across.

    The alert moves to UNDER_REVIEW: a queue entry someone has opened a case on
    is no longer waiting for triage.
    """
    alert = db.get(Alert, str(alert_id))

    if alert is None:
        raise NotFoundError("Alert not found.", details={"alert_id": str(alert_id)[:64]})

    case = create_case(
        db,
        title=title
        or f"Investigation of account {alert.account_id} ({alert.priority.value} priority)",
        description=clean_text(alert.summary or "", _MAX_DESCRIPTION_LENGTH) or None,
        priority=priority or alert.priority,
        creator=creator,
        creator_id=creator_id,
        assignee_id=assignee_id,
        account_id=str(alert.account_id),
        alert_id=str(alert.id),
        metadata={
            "origin": "alert",
            "alert_score": float(alert.score) if alert.score is not None else None,
            "alert_dedup_key": alert.dedup_key,
        },
    )

    # Carry the alert's own evidence onto the case so the investigator starts
    # with what the detection pipeline actually cited.
    references: list[tuple[EvidenceType, str]] = [
        (EvidenceType.ALERT, str(alert.id)),
        (EvidenceType.ACCOUNT, str(alert.account_id)),
    ]

    if alert.assessment_id:
        references.append((EvidenceType.MODEL_ASSESSMENT, str(alert.assessment_id)))

    for evidence_type, evidence_id in references:
        try:
            add_case_evidence(
                db,
                case_id=str(case.id),
                evidence_type=evidence_type,
                evidence_id=evidence_id,
                added_by=creator_id or (str(getattr(creator, "id", "") or "") or None),
                provenance={"carried_from_alert": str(alert.id)},
            )
        except Exception:
            # A single unresolvable reference must not block case creation.
            logger.warning(
                "Could not carry %s:%s onto case %s",
                evidence_type.value,
                evidence_id,
                case.id,
                exc_info=True,
            )

    if alert.state in {AlertState.NEW, AlertState.ACKNOWLEDGED}:
        alert.state = AlertState.UNDER_REVIEW
        alert.updated_by = creator_id or (
            str(getattr(creator, "id", "") or "") or None
        )

    db.flush()
    return case


def transition_case(
    db: Session,
    *,
    case_id: str,
    target_status: Any,
    actor: Optional[User] = None,
    actor_id: Optional[str] = None,
    disposition: Any = None,
    reason: Optional[str] = None,
    assignee_id: Optional[str] = None,
) -> InvestigationCase:
    """
    Move a case to a new status.

    Validates against the state machine, applies the change, and appends a
    history event. Raises InvalidCaseTransitionError when the move is illegal
    or its preconditions are unmet.
    """
    case = _require_case(db, case_id)
    effective_assignee = assignee_id or case.assignee_id

    try:
        rule = validate_transition(
            current=case.status,
            target=target_status,
            disposition=disposition,
            assignee_id=effective_assignee,
            reason=reason,
        )
    except ValueError as exc:
        raise InvalidCaseTransitionError(
            str(exc),
            details={
                "case_id": str(case.id),
                "current_status": case.status.value,
                "requested_status": str(
                    getattr(target_status, "value", target_status)
                ),
                "allowed": [r.target.value for r in allowed_transitions(case.status)],
            },
        ) from exc

    previous_status = case.status
    resolved_actor = actor_id or (
        str(getattr(actor, "id", "") or "") or None if actor is not None else None
    )

    case.status = rule.target

    if assignee_id and assignee_id != case.assignee_id:
        case.assignee_id = assignee_id

    if rule.target is CaseStatus.CLOSED:
        resolved_disposition = (
            disposition
            if isinstance(disposition, Disposition)
            else Disposition[str(disposition).strip().upper()]
        )
        case.disposition = resolved_disposition
        case.closed_at = utcnow()
        case.closed_by = resolved_actor

    if rule.clears_disposition:
        # Reopening: the previous decision moves into history rather than
        # being erased, so the audit trail survives.
        metadata = dict(case.metadata_json or {})
        history = list(metadata.get("disposition_history") or [])

        if case.disposition is not None:
            history.append(
                {
                    "disposition": case.disposition.value,
                    "closed_at": case.closed_at.isoformat() if case.closed_at else None,
                    "closed_by": case.closed_by,
                    "reopened_at": utcnow().isoformat(),
                    "reopened_by": resolved_actor,
                    "reason": clean_text(reason or "", 500) or None,
                }
            )

        metadata["disposition_history"] = history[-20:]
        case.metadata_json = sanitize_json(metadata, max_items=40)
        case.disposition = None
        case.closed_at = None
        case.closed_by = None
        case.reopened_at = utcnow()
        case.reopened_by = resolved_actor

    db.flush()

    record_case_event(
        db,
        case_id=str(case.id),
        action=rule.action,
        actor=actor,
        actor_id=resolved_actor,
        resource_type="investigation_case",
        resource_id=str(case.id),
        summary=(
            f"Status changed from {previous_status.value} to {rule.target.value}."
            + (f" Reason: {clean_text(reason, 300)}" if reason else "")
        ),
        metadata={
            "from_status": previous_status.value,
            "to_status": rule.target.value,
            "disposition": case.disposition.value if case.disposition else None,
            "reason": clean_text(reason or "", 500) or None,
        },
    )

    logger.info(
        "Case %s moved %s -> %s by %s",
        case.id,
        previous_status.value,
        rule.target.value,
        resolved_actor or "system",
    )
    return case


def assign_case(
    db: Session,
    *,
    case_id: str,
    assignee_id: Optional[str],
    actor: Optional[User] = None,
    actor_id: Optional[str] = None,
) -> InvestigationCase:
    """
    Assign or unassign a case owner.
    """
    case = _require_case(db, case_id)

    if is_terminal(case.status):
        raise CaseClosedError(
            "A closed case cannot be reassigned. Reopen it first.",
            details={"case_id": str(case.id), "status": case.status.value},
        )

    previous = case.assignee_id
    case.assignee_id = assignee_id or None
    db.flush()

    resolved_actor = actor_id or (
        str(getattr(actor, "id", "") or "") or None if actor is not None else None
    )
    record_case_event(
        db,
        case_id=str(case.id),
        action="assigned" if assignee_id else "unassigned",
        actor=actor,
        actor_id=resolved_actor,
        resource_type="user",
        resource_id=assignee_id,
        summary=(
            f"Case assigned to {assignee_id}." if assignee_id else "Case unassigned."
        ),
        metadata={"previous_assignee_id": previous},
    )
    return case


def close_case(
    db: Session,
    *,
    case_id: str,
    disposition: Any,
    actor: Optional[User] = None,
    actor_id: Optional[str] = None,
    reason: Optional[str] = None,
) -> InvestigationCase:
    """
    Close a case with a disposition.
    """
    return transition_case(
        db,
        case_id=case_id,
        target_status=CaseStatus.CLOSED,
        actor=actor,
        actor_id=actor_id,
        disposition=disposition,
        reason=reason,
    )


def reopen_case(
    db: Session,
    *,
    case_id: str,
    reason: str,
    actor: Optional[User] = None,
    actor_id: Optional[str] = None,
) -> InvestigationCase:
    """
    Reopen a closed case, preserving the prior disposition in history.
    """
    return transition_case(
        db,
        case_id=case_id,
        target_status=CaseStatus.UNDER_INVESTIGATION,
        actor=actor,
        actor_id=actor_id,
        reason=reason,
    )


def available_transitions(case: InvestigationCase) -> list[dict[str, Any]]:
    """
    Return the transitions legal for a case right now.

    The frontend renders exactly these, rather than keeping its own copy of the
    workflow and drifting from the backend.
    """
    return [rule.to_dict() for rule in allowed_transitions(case.status)]


def list_cases(
    db: Session,
    *,
    statuses: Optional[Sequence[CaseStatus]] = None,
    priorities: Optional[Sequence[Priority]] = None,
    assignee_id: Optional[str] = None,
    account_id: Optional[str] = None,
    search: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[InvestigationCase], int]:
    """
    Return a page of cases and the total matching count.
    """
    conditions: list[Any] = []

    if statuses:
        conditions.append(InvestigationCase.status.in_(list(statuses)))

    if priorities:
        conditions.append(InvestigationCase.priority.in_(list(priorities)))

    if assignee_id:
        conditions.append(InvestigationCase.assignee_id == str(assignee_id))

    if account_id:
        conditions.append(InvestigationCase.account_id == str(account_id))

    lower = ensure_utc(since)

    if lower is not None:
        conditions.append(InvestigationCase.record_created_at >= lower)

    if search:
        pattern = f"%{clean_text(search, 100).lower()}%"
        conditions.append(
            or_(
                func.lower(InvestigationCase.title).like(pattern),
                func.lower(InvestigationCase.description).like(pattern),
            )
        )

    count_stmt = select(func.count()).select_from(InvestigationCase)
    page_stmt = select(InvestigationCase)

    for condition in conditions:
        count_stmt = count_stmt.where(condition)
        page_stmt = page_stmt.where(condition)

    total = int(db.execute(count_stmt).scalar() or 0)
    page_stmt = (
        page_stmt.order_by(InvestigationCase.record_updated_at.desc())
        .offset(max(0, int(offset)))
        .limit(max(1, min(int(limit), 200)))
    )
    return list(db.execute(page_stmt).scalars()), total


def get_cases_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the case service.
    """
    return {
        "service": "muleguard.backend.services.cases",
        "version": CASES_SERVICE_VERSION,
        "statuses": [item.value for item in CaseStatus],
        "dispositions": [item.value for item in Disposition],
        "priorities": [item.value for item in Priority],
        "guarantees": [
            "Every transition is validated against the state machine.",
            "Every transition appends an append-only CaseEvent.",
            "Closing requires a disposition, enforced here and by a CHECK constraint.",
            "Reopening preserves the prior disposition in case history.",
            "No transition is ever performed by the detection pipeline.",
        ],
    }
