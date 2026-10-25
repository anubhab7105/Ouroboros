"""
MULEGUARD audit service.

Writes `AuditEvent` rows for material actions and reads them back for the
auditor views.

Design rules:

- Audit writing never raises into the caller. An audit failure must not roll
  back the action it describes, and it must not turn a successful investigation
  step into a 500. Failures are logged loudly instead.
- Metadata is sanitised through `app.utils.json.sanitize_json`, which drops
  credential-like keys and bounds depth and size. Audit rows are durable and
  analyst-visible, so a raw request payload must never land in one.
- IP addresses and user agents are stored hashed, never raw.
- The actor username is denormalised onto the row so the trail still reads
  correctly after a user record is removed (`actor_id` is `ON DELETE SET NULL`).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, AuditOutcome, User
from app.utils.dates import ensure_utc, utcnow
from app.utils.hashing import hash_identifier
from app.utils.json import sanitize_json
from app.utils.text import clean_text

logger = logging.getLogger("muleguard.backend.services.audit")

__all__ = [
    "AUDIT_SERVICE_VERSION",
    "SYSTEM_ACTOR",
    "count_audit_events",
    "get_audit_service_metadata",
    "list_audit_events",
    "record_audit_event",
    "record_system_event",
]

AUDIT_SERVICE_VERSION: Final[str] = "v1"

# Used when an action has no authenticated actor: scheduled analysis runs,
# migrations, seeding.
SYSTEM_ACTOR: Final[str] = "system"

_MAX_ACTION_LENGTH: Final[int] = 100
_MAX_RESOURCE_TYPE_LENGTH: Final[int] = 100
_MAX_RESOURCE_ID_LENGTH: Final[int] = 128
_MAX_METADATA_ITEMS: Final[int] = 60


def record_audit_event(
    db: Session,
    *,
    action: str,
    actor: Optional[User] = None,
    actor_id: Optional[str] = None,
    actor_username: Optional[str] = None,
    actor_role: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    ip_hash: Optional[str] = None,
    user_agent_hash: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    created_at: Optional[datetime] = None,
    salt: Optional[str] = None,
) -> Optional[AuditEvent]:
    """
    Record one audit event.

    Returns the event, or None when it could not be written. Never raises:
    callers treat audit as best-effort so that a logging problem cannot undo
    the action being logged.

    Pass either the raw `ip_address` / `user_agent` (hashed here) or a
    pre-computed `ip_hash` / `user_agent_hash`. Raw values are never stored.
    """
    cleaned_action = clean_text(action, _MAX_ACTION_LENGTH)

    if not cleaned_action:
        logger.warning("Refusing to record an audit event with an empty action.")
        return None

    resolved_actor_id = actor_id
    resolved_username = actor_username
    resolved_role = actor_role

    if actor is not None:
        resolved_actor_id = resolved_actor_id or str(getattr(actor, "id", "") or "") or None
        resolved_username = resolved_username or clean_text(
            getattr(actor, "username", "") or "", 64
        ) or None
        role_value = getattr(actor, "role", None)
        resolved_role = resolved_role or (
            str(getattr(role_value, "value", role_value) or "") or None
        )

    if not resolved_username:
        resolved_username = SYSTEM_ACTOR

    try:
        event = AuditEvent(
            actor_id=resolved_actor_id,
            actor_username=clean_text(resolved_username, 64) or SYSTEM_ACTOR,
            actor_role=clean_text(resolved_role or "", 50) or None,
            action=cleaned_action,
            resource_type=clean_text(resource_type or "", _MAX_RESOURCE_TYPE_LENGTH) or None,
            resource_id=clean_text(resource_id or "", _MAX_RESOURCE_ID_LENGTH) or None,
            outcome=outcome if isinstance(outcome, AuditOutcome) else AuditOutcome.SUCCESS,
            request_id=clean_text(request_id or "", 64) or None,
            correlation_id=clean_text(correlation_id or "", 64) or None,
            ip_hash=(
                ip_hash
                or (
                    hash_identifier(ip_address, salt=salt, kind="ip")
                    if ip_address
                    else None
                )
            ),
            user_agent_hash=(
                user_agent_hash
                or (
                    hash_identifier(user_agent, salt=salt, kind="user_agent")
                    if user_agent
                    else None
                )
            ),
            metadata_json=sanitize_json(
                dict(metadata or {}), max_items=_MAX_METADATA_ITEMS
            ),
            created_at=ensure_utc(created_at) or utcnow(),
        )
        db.add(event)
        db.flush()
        return event
    except Exception:
        # Deliberately broad: an audit write must never propagate.
        logger.exception(
            "Failed to record audit event action=%s resource=%s/%s",
            cleaned_action,
            resource_type,
            resource_id,
        )
        return None


def record_system_event(
    db: Session,
    *,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Optional[AuditEvent]:
    """
    Record an audit event for an action with no authenticated actor.
    """
    return record_audit_event(
        db,
        action=action,
        actor_username=SYSTEM_ACTOR,
        actor_role=SYSTEM_ACTOR,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        metadata=metadata,
    )


def list_audit_events(
    db: Session,
    *,
    actor_id: Optional[str] = None,
    actor_username: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    outcome: Optional[AuditOutcome] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditEvent]:
    """
    Return audit events matching the given filters, newest first.
    """
    stmt = select(AuditEvent)

    for column, value in (
        (AuditEvent.actor_id, actor_id),
        (AuditEvent.actor_username, actor_username),
        (AuditEvent.action, action),
        (AuditEvent.resource_type, resource_type),
        (AuditEvent.resource_id, resource_id),
    ):
        if value:
            stmt = stmt.where(column == str(value))

    if outcome is not None:
        stmt = stmt.where(AuditEvent.outcome == outcome)

    lower = ensure_utc(since)
    upper = ensure_utc(until)

    if lower is not None:
        stmt = stmt.where(AuditEvent.created_at >= lower)

    if upper is not None:
        stmt = stmt.where(AuditEvent.created_at <= upper)

    stmt = (
        stmt.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .offset(max(0, int(offset)))
        .limit(max(1, min(int(limit), 1_000)))
    )
    return list(db.execute(stmt).scalars())


def count_audit_events(
    db: Session,
    *,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    since: Optional[datetime] = None,
) -> int:
    """
    Count audit events matching the given filters.
    """
    stmt = select(func.count()).select_from(AuditEvent)

    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == str(resource_type))

    if resource_id:
        stmt = stmt.where(AuditEvent.resource_id == str(resource_id))

    lower = ensure_utc(since)

    if lower is not None:
        stmt = stmt.where(AuditEvent.created_at >= lower)

    return int(db.execute(stmt).scalar() or 0)


def get_audit_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the audit service.
    """
    return {
        "service": "muleguard.backend.services.audit",
        "version": AUDIT_SERVICE_VERSION,
        "outcomes": [item.value for item in AuditOutcome],
        "guarantees": [
            "Audit writes never raise into the caller.",
            "IP addresses and user agents are stored hashed, never raw.",
            "Metadata is sanitised; credential-like keys are dropped.",
            "The actor username is denormalised so the trail survives user deletion.",
        ],
    }
