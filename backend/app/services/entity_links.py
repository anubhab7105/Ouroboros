"""
MULEGUARD account-entity link service.

Manages the time-bound relationships between accounts and pseudonymous
entities (devices, phones, UPI handles, emails, addresses, IPs), and answers
the shared-entity questions the investigation UI asks.

Two things make this more than a join table:

- **Links are time-bound.** `valid_from` / `valid_to` exist because a device
  changes hands and a phone number is reassigned. A query that ignores the
  validity window will claim two accounts shared a device when in fact one used
  it in January and the other in June. Every read here takes an `as_of` or an
  explicit window.

- **Links carry a match method and a verification state.** An `EXACT` verified
  link and a `GRAPH_TEMPORAL` unverified link are both rows in this table, and
  presenting them identically would misrepresent inferred association as
  established fact. Callers get both fields and the UI shows them.

The file was previously empty, so nothing depended on a prior shape.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import (
    AccountEntityLink,
    Entity,
    EntityType,
    MatchMethod,
    VerificationState,
)
from app.utils.dates import ensure_utc, utcnow
from app.utils.decimals import quantize_confidence, to_float
from app.utils.json import sanitize_json

logger = logging.getLogger("muleguard.backend.services.entity_links")

__all__ = [
    "ENTITY_LINKS_SERVICE_VERSION",
    "SharedEntityCluster",
    "active_links_for_account",
    "count_links_for_account",
    "create_link",
    "entity_type_counts",
    "get_entity_links_service_metadata",
    "linked_accounts_for_entity",
    "set_verification_state",
    "shared_entity_clusters",
]

ENTITY_LINKS_SERVICE_VERSION: Final[str] = "v1"

_MAX_LINKS: Final[int] = 500
_MAX_CLUSTER_ACCOUNTS: Final[int] = 200

# Entity kinds ordered by how strongly a shared value suggests shared control.
# A device is close to dispositive; an IP is weak because of carrier NAT.
_STRENGTH_ORDER: Final[dict[str, int]] = {
    EntityType.DEVICE.value: 5,
    EntityType.UPI_ID.value: 4,
    EntityType.PHONE_HASH.value: 3,
    EntityType.EMAIL_HASH.value: 3,
    EntityType.ADDRESS_HASH.value: 2,
    EntityType.IP_HASH.value: 1,
    EntityType.OTHER.value: 1,
}


def _valid_at(as_of: datetime) -> Any:
    """
    Build the SQL predicate for a link being valid at an instant.
    """
    return (AccountEntityLink.valid_from <= as_of) & (
        or_(
            AccountEntityLink.valid_to.is_(None),
            AccountEntityLink.valid_to > as_of,
        )
    )


def _overlaps(window_start: datetime, window_end: datetime) -> Any:
    """
    Build the SQL predicate for a link's validity overlapping a window.

    Two half-open intervals overlap when each starts before the other ends.
    """
    return (AccountEntityLink.valid_from < window_end) & (
        or_(
            AccountEntityLink.valid_to.is_(None),
            AccountEntityLink.valid_to > window_start,
        )
    )


class SharedEntityCluster:
    """
    A set of accounts associated through one entity.
    """

    __slots__ = (
        "account_ids",
        "entity_id",
        "entity_type",
        "max_confidence",
        "unverified_count",
        "verified_count",
    )

    def __init__(
        self,
        *,
        entity_id: str,
        entity_type: str,
        account_ids: Sequence[str],
        verified_count: int = 0,
        unverified_count: int = 0,
        max_confidence: Optional[float] = None,
    ) -> None:
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.account_ids = list(account_ids)
        self.verified_count = verified_count
        self.unverified_count = unverified_count
        self.max_confidence = max_confidence

    @property
    def size(self) -> int:
        """
        Number of accounts in the cluster.
        """
        return len(self.account_ids)

    @property
    def strength(self) -> int:
        """
        How strongly this entity kind suggests shared control (1-5).
        """
        return _STRENGTH_ORDER.get(self.entity_type, 1)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation.
        """
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "account_ids": self.account_ids[:_MAX_CLUSTER_ACCOUNTS],
            "size": self.size,
            "verified_links": self.verified_count,
            "unverified_links": self.unverified_count,
            "max_confidence": self.max_confidence,
            "association_strength": self.strength,
            "limits": [
                "A shared entity is an association, not proof of shared "
                "control. Families and small businesses share devices, "
                "addresses, and handles legitimately.",
                "IP associations are weak: carrier NAT and public Wi-Fi put "
                "unrelated accounts behind one address.",
            ],
        }


def create_link(
    db: Session,
    *,
    account_id: str,
    entity_id: str,
    match_method: MatchMethod = MatchMethod.EXACT,
    confidence: Optional[float] = None,
    verification_state: VerificationState = VerificationState.UNVERIFIED,
    valid_from: Optional[datetime] = None,
    valid_to: Optional[datetime] = None,
    source: str = "synthetic",
    metadata: Optional[Mapping[str, Any]] = None,
) -> AccountEntityLink:
    """
    Create an account-entity link.

    `(account_id, entity_id, valid_from, source)` is unique, so re-creating the
    same link returns the existing row instead of raising.
    """
    start = ensure_utc(valid_from) or utcnow()
    end = ensure_utc(valid_to)

    if end is not None and end <= start:
        raise ValueError("valid_to must be after valid_from")

    existing = db.execute(
        select(AccountEntityLink)
        .where(AccountEntityLink.account_id == str(account_id))
        .where(AccountEntityLink.entity_id == str(entity_id))
        .where(AccountEntityLink.valid_from == start)
        .where(AccountEntityLink.source == str(source))
        .limit(1)
    ).scalars().first()

    if existing is not None:
        return existing

    link = AccountEntityLink(
        account_id=str(account_id),
        entity_id=str(entity_id),
        match_method=match_method,
        # A deterministic EXACT match carries no confidence: 1.0 would invite
        # averaging an identity with an estimate.
        confidence=(
            None
            if match_method is MatchMethod.EXACT and confidence is None
            else quantize_confidence(confidence)
        ),
        verification_state=verification_state,
        valid_from=start,
        valid_to=end,
        source=str(source)[:100],
        metadata_json=sanitize_json(dict(metadata or {}), max_items=20),
    )
    db.add(link)
    db.flush()
    return link


def active_links_for_account(
    db: Session,
    account_id: str,
    *,
    as_of: Optional[datetime] = None,
    entity_types: Optional[Sequence[EntityType]] = None,
    verification_states: Optional[Sequence[VerificationState]] = None,
    limit: int = _MAX_LINKS,
) -> list[tuple[AccountEntityLink, Entity]]:
    """
    Return the links valid for an account at an instant, with their entities.
    """
    moment = ensure_utc(as_of) or utcnow()

    stmt = (
        select(AccountEntityLink, Entity)
        .join(Entity, Entity.id == AccountEntityLink.entity_id)
        .where(AccountEntityLink.account_id == str(account_id))
        .where(_valid_at(moment))
    )

    if entity_types:
        stmt = stmt.where(Entity.entity_type.in_(list(entity_types)))

    if verification_states:
        stmt = stmt.where(
            AccountEntityLink.verification_state.in_(list(verification_states))
        )

    stmt = stmt.order_by(AccountEntityLink.valid_from.desc()).limit(
        max(1, min(int(limit), _MAX_LINKS))
    )
    return [(link, entity) for link, entity in db.execute(stmt).all()]


def count_links_for_account(
    db: Session,
    account_id: str,
    *,
    as_of: Optional[datetime] = None,
) -> int:
    """
    Count the links valid for an account at an instant.
    """
    moment = ensure_utc(as_of) or utcnow()
    stmt = (
        select(func.count())
        .select_from(AccountEntityLink)
        .where(AccountEntityLink.account_id == str(account_id))
        .where(_valid_at(moment))
    )
    return int(db.execute(stmt).scalar() or 0)


def linked_accounts_for_entity(
    db: Session,
    entity_id: str,
    *,
    as_of: Optional[datetime] = None,
    exclude_account_ids: Optional[Sequence[str]] = None,
    limit: int = _MAX_CLUSTER_ACCOUNTS,
) -> list[str]:
    """
    Return the accounts associated with an entity at an instant.
    """
    moment = ensure_utc(as_of) or utcnow()

    stmt = (
        select(AccountEntityLink.account_id)
        .where(AccountEntityLink.entity_id == str(entity_id))
        .where(_valid_at(moment))
    )

    if exclude_account_ids:
        stmt = stmt.where(
            AccountEntityLink.account_id.notin_([str(a) for a in exclude_account_ids])
        )

    stmt = stmt.distinct().limit(max(1, min(int(limit), _MAX_CLUSTER_ACCOUNTS)))
    return [str(item) for item in db.execute(stmt).scalars()]


def shared_entity_clusters(
    db: Session,
    account_id: str,
    *,
    as_of: Optional[datetime] = None,
    window_start: Optional[datetime] = None,
    min_cluster_size: int = 2,
    limit: int = 50,
) -> list[SharedEntityCluster]:
    """
    Return the entity clusters an account participates in.

    Only clusters whose link validity overlaps the window are returned, so two
    accounts that used the same device months apart are not reported as
    sharing it.
    """
    moment = ensure_utc(as_of) or utcnow()
    start = ensure_utc(window_start) or moment.replace(
        year=moment.year - 1 if moment.year > 1 else moment.year
    )

    own_links = db.execute(
        select(AccountEntityLink, Entity)
        .join(Entity, Entity.id == AccountEntityLink.entity_id)
        .where(AccountEntityLink.account_id == str(account_id))
        .where(_overlaps(start, moment))
        .limit(_MAX_LINKS)
    ).all()

    clusters: list[SharedEntityCluster] = []

    for link, entity in own_links:
        sibling_rows = db.execute(
            select(AccountEntityLink)
            .where(AccountEntityLink.entity_id == str(link.entity_id))
            .where(_overlaps(start, moment))
            .limit(_MAX_CLUSTER_ACCOUNTS)
        ).scalars().all()

        account_ids = sorted({str(row.account_id) for row in sibling_rows})

        if len(account_ids) < max(2, int(min_cluster_size)):
            continue

        verified = sum(
            1
            for row in sibling_rows
            if row.verification_state is VerificationState.VERIFIED
        )
        unverified = sum(
            1
            for row in sibling_rows
            if row.verification_state is VerificationState.UNVERIFIED
        )
        confidences = [
            value
            for value in (to_float(row.confidence) for row in sibling_rows)
            if value is not None
        ]

        clusters.append(
            SharedEntityCluster(
                entity_id=str(link.entity_id),
                entity_type=str(
                    getattr(entity.entity_type, "value", entity.entity_type)
                ),
                account_ids=account_ids,
                verified_count=verified,
                unverified_count=unverified,
                max_confidence=max(confidences) if confidences else None,
            )
        )

    # Strongest association kind first, then largest cluster: a shared device
    # across three accounts matters more than a shared IP across thirty.
    clusters.sort(key=lambda c: (-c.strength, -c.size))
    return clusters[: max(1, int(limit))]


def entity_type_counts(
    db: Session,
    account_id: str,
    *,
    as_of: Optional[datetime] = None,
) -> dict[str, int]:
    """
    Return distinct linked-entity counts per entity type for an account.
    """
    moment = ensure_utc(as_of) or utcnow()

    rows = db.execute(
        select(Entity.entity_type, func.count(func.distinct(Entity.id)))
        .join(AccountEntityLink, AccountEntityLink.entity_id == Entity.id)
        .where(AccountEntityLink.account_id == str(account_id))
        .where(_valid_at(moment))
        .group_by(Entity.entity_type)
    ).all()

    return {
        str(getattr(entity_type, "value", entity_type)): int(count)
        for entity_type, count in rows
    }


def set_verification_state(
    db: Session,
    link_id: str,
    *,
    state: VerificationState,
    reviewer_id: Optional[str] = None,
    note: Optional[str] = None,
) -> Optional[AccountEntityLink]:
    """
    Record an analyst's verification decision on a link.

    The decision is appended to the link's metadata rather than overwriting it,
    so the review history survives a later change.
    """
    link = db.get(AccountEntityLink, str(link_id))

    if link is None:
        return None

    link.verification_state = state
    metadata = dict(link.metadata_json or {})
    history = list(metadata.get("verification_history") or [])
    history.append(
        {
            "state": state.value,
            "reviewer_id": reviewer_id,
            "note": str(note or "")[:500] or None,
            "at": utcnow().isoformat(),
        }
    )
    metadata["verification_history"] = history[-20:]
    link.metadata_json = sanitize_json(metadata, max_items=30)
    db.flush()
    return link


def get_entity_links_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the entity-link service.
    """
    return {
        "service": "muleguard.backend.services.entity_links",
        "version": ENTITY_LINKS_SERVICE_VERSION,
        "entity_types": [item.value for item in EntityType],
        "match_methods": [item.value for item in MatchMethod],
        "verification_states": [item.value for item in VerificationState],
        "association_strength": dict(_STRENGTH_ORDER),
        "limits": {
            "max_links": _MAX_LINKS,
            "max_cluster_accounts": _MAX_CLUSTER_ACCOUNTS,
        },
        "guarantees": [
            "Every read respects the link validity window, so accounts that "
            "used an entity at different times are not reported as sharing it.",
            "Match method and verification state are always returned, so an "
            "inferred link is never presented as established fact.",
            "EXACT links carry no confidence value by default.",
        ],
    }
