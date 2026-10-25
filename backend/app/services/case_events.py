"""
MULEGUARD case event service.

`CaseEvent` is the append-only history of an investigation. Nothing in this
module updates or deletes an event, and that is the point: a case is only
defensible if its history cannot be rewritten after the fact.

`CaseEvent` deliberately has no `RecordTimestampMixin` — there is no
`record_updated_at`, because an event is never updated.

The actor username is denormalised onto each event so the history still reads
correctly after a user row is removed (`actor_id` is `ON DELETE SET NULL`).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import CaseEvent, User
from app.utils.dates import ensure_utc, utcnow
from app.utils.json import sanitize_json
from app.utils.text import clean_text, truncate

logger = logging.getLogger("muleguard.backend.services.case_events")

__all__ = [
    "CASE_EVENTS_SERVICE_VERSION",
    "KNOWN_ACTIONS",
    "count_case_events",
    "get_case_events_service_metadata",
    "list_case_events",
    "record_case_event",
]

CASE_EVENTS_SERVICE_VERSION: Final[str] = "v1"

# Canonical action vocabulary. Free-form actions are accepted but normalised,
# so the timeline filter has a stable set to offer.
KNOWN_ACTIONS: Final[tuple[str, ...]] = (
    "created",
    "assigned",
    "unassigned",
    "status_change",
    "triaged",
    "started",
    "escalated",
    "de_escalated",
    "closed",
    "reopened",
    "priority_change",
    "note_added",
    "evidence_added",
    "evidence_removed",
    "report_generated",
    "bundle_exported",
)

_MAX_SUMMARY_LENGTH: Final[int] = 1_000
_MAX_EVENTS: Final[int] = 500


def record_case_event(
    db: Session,
    *,
    case_id: str,
    action: str,
    actor: Optional[User] = None,
    actor_id: Optional[str] = None,
    actor_username: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    summary: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    created_at: Optional[datetime] = None,
) -> Optional[CaseEvent]:
    """
    Append one event to a case's history.

    Returns the event, or None when it could not be written. Never raises: an
    event-logging failure must not roll back the case action it describes.
    """
    cleaned_action = clean_text(action, 100).lower().replace(" ", "_")

    if not cleaned_action:
        logger.warning("Refusing to record a case event with an empty action.")
        return None

    resolved_id = actor_id
    resolved_username = actor_username

    if actor is not None:
        resolved_id = resolved_id or str(getattr(actor, "id", "") or "") or None
        resolved_username = resolved_username or clean_text(
            getattr(actor, "username", "") or "", 64
        ) or None

    try:
        event = CaseEvent(
            case_id=str(case_id),
            actor_id=resolved_id,
            actor_username=resolved_username or "system",
            action=cleaned_action,
            resource_type=clean_text(resource_type or "", 100) or None,
            resource_id=clean_text(resource_id or "", 128) or None,
            summary=truncate(clean_text(summary or "", _MAX_SUMMARY_LENGTH), _MAX_SUMMARY_LENGTH)
            or None,
            metadata_json=sanitize_json(dict(metadata or {}), max_items=40),
            created_at=ensure_utc(created_at) or utcnow(),
        )
        db.add(event)
        db.flush()
        return event
    except Exception:
        logger.exception(
            "Failed to record case event case=%s action=%s", case_id, cleaned_action
        )
        return None


def list_case_events(
    db: Session,
    case_id: str,
    *,
    actions: Optional[Sequence[str]] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    ascending: bool = True,
    limit: int = 200,
    offset: int = 0,
) -> list[CaseEvent]:
    """
    Return a case's events.

    Ascending by default: a timeline reads forward in time.
    """
    stmt = select(CaseEvent).where(CaseEvent.case_id == str(case_id))

    if actions:
        normalised = [
            clean_text(a, 100).lower().replace(" ", "_")
            for a in actions
            if str(a).strip()
        ]

        if normalised:
            stmt = stmt.where(CaseEvent.action.in_(normalised))

    lower = ensure_utc(since)
    upper = ensure_utc(until)

    if lower is not None:
        stmt = stmt.where(CaseEvent.created_at >= lower)

    if upper is not None:
        stmt = stmt.where(CaseEvent.created_at <= upper)

    order = CaseEvent.created_at.asc() if ascending else CaseEvent.created_at.desc()
    stmt = (
        stmt.order_by(order, CaseEvent.id.asc() if ascending else CaseEvent.id.desc())
        .offset(max(0, int(offset)))
        .limit(max(1, min(int(limit), _MAX_EVENTS)))
    )
    return list(db.execute(stmt).scalars())


def count_case_events(
    db: Session,
    case_id: str,
    *,
    action: Optional[str] = None,
) -> int:
    """
    Count a case's events, optionally for one action.
    """
    stmt = select(func.count()).select_from(CaseEvent).where(
        CaseEvent.case_id == str(case_id)
    )

    if action:
        stmt = stmt.where(
            CaseEvent.action == clean_text(action, 100).lower().replace(" ", "_")
        )

    return int(db.execute(stmt).scalar() or 0)


def get_case_events_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the case event service.
    """
    return {
        "service": "muleguard.backend.services.case_events",
        "version": CASE_EVENTS_SERVICE_VERSION,
        "known_actions": list(KNOWN_ACTIONS),
        "guarantees": [
            "Case history is append-only: no update or delete path exists.",
            "Event writes never raise into the caller.",
            "The actor username is denormalised so history survives user deletion.",
            "Metadata is sanitised; credential-like keys are dropped.",
        ],
    }
