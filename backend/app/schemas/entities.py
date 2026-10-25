"""
MULEGUARD entity and entity-link schemas.

Entities are pseudonymous. `identifier_hash` is a salted one-way hash and
`identifier_display` is a masked label; a raw device id, phone number, or email
address never appears in a request or a response.

Every link response carries `match_method`, `verification_state` and the
validity window, because an `EXACT` verified link and an inferred unverified
one must never render identically. `association_strength` says how much weight
the entity kind deserves: a shared device is close to dispositive, a shared IP
is weak because of carrier NAT.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Optional

from pydantic import Field

from app.schemas.common import ConfidenceField, IdentifierField, MuleGuardModel, ResponseModel
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "EntityFilterParams",
    "EntityLinkResponse",
    "EntityLinkListResponse",
    "EntityListResponse",
    "EntityResponse",
    "SharedEntityClusterResponse",
    "VerificationUpdateRequest",
]

_ENTITY_TYPES = (
    "DEVICE",
    "PHONE_HASH",
    "UPI_ID",
    "EMAIL_HASH",
    "ADDRESS_HASH",
    "IP_HASH",
    "OTHER",
)
_VERIFICATION_STATES = ("UNVERIFIED", "VERIFIED", "REJECTED", "NEEDS_REVIEW")
_MATCH_METHODS = (
    "EXACT",
    "NORMALIZED",
    "ENTITY_TEMPORAL",
    "GRAPH_TEMPORAL",
    "NARRATIVE_EXTRACTION",
    "MANUAL",
    "UNKNOWN",
)

EntityTypeField = Annotated[str, Field(pattern=f"^({'|'.join(_ENTITY_TYPES)})$")]
VerificationStateField = Annotated[str, Field(pattern=f"^({'|'.join(_VERIFICATION_STATES)})$")]
MatchMethodField = Annotated[str, Field(pattern=f"^({'|'.join(_MATCH_METHODS)})$")]


class EntityResponse(ResponseModel):
    """
    A pseudonymous entity.
    """

    id: str = Field(description="Entity identifier.")
    entity_type: str = Field(description="Entity kind.")
    identifier_display: Optional[str] = Field(
        default=None,
        description=(
            "Masked display label. Never the raw identifier; the underlying "
            "value is stored only as a salted hash."
        ),
    )
    source: str = Field(description="Provenance source.")
    first_seen_at: Optional[datetime] = Field(default=None)
    last_seen_at: Optional[datetime] = Field(default=None)
    linked_account_count: int = Field(default=0)
    association_strength: int = Field(
        default=1,
        ge=1,
        le=5,
        description=(
            "How strongly a shared value of this kind suggests shared control: "
            "5 device, 4 UPI handle, 3 phone or email, 2 address, 1 IP."
        ),
    )


class EntityListResponse(PaginatedResponse[EntityResponse]):
    """
    A page of entities.
    """


class EntityLinkResponse(ResponseModel):
    """
    A time-bound account-entity association.
    """

    id: str = Field(description="Link identifier.")
    account_id: str = Field(description="Linked account.")
    entity_id: str = Field(description="Linked entity.")
    entity_type: Optional[str] = Field(default=None)
    identifier_display: Optional[str] = Field(default=None)

    match_method: str = Field(
        description=(
            "How the association was established. An inferred method must not "
            "be presented as established fact."
        )
    )
    verification_state: str = Field(description="Analyst verification state.")
    confidence: Optional[Decimal] = Field(
        default=None,
        description=(
            "Confidence for inferred links. Null for a deterministic EXACT "
            "match."
        ),
    )
    valid_from: datetime = Field(description="Association start, UTC.")
    valid_to: Optional[datetime] = Field(
        default=None,
        description=(
            "Association end, UTC, when known. Null means still current. "
            "Shared-entity queries respect this window: two accounts that used "
            "a device months apart did not share it."
        ),
    )
    source: str = Field(description="Provenance source.")
    is_current: bool = Field(
        default=True, description="Whether the link is valid right now."
    )


class EntityLinkListResponse(PaginatedResponse[EntityLinkResponse]):
    """
    A page of entity links.
    """


class SharedEntityClusterResponse(ResponseModel):
    """
    A set of accounts associated through one entity.
    """

    entity_id: str = Field(description="The shared entity.")
    entity_type: str = Field(description="Entity kind.")
    identifier_display: Optional[str] = Field(default=None)
    account_ids: list[str] = Field(default_factory=list)
    size: int = Field(default=0, description="Accounts in the cluster.")
    verified_links: int = Field(default=0)
    unverified_links: int = Field(default=0)
    max_confidence: Optional[Decimal] = Field(default=None)
    association_strength: int = Field(default=1, ge=1, le=5)
    caveats: list[str] = Field(
        default_factory=lambda: [
            "A shared entity is an association, not proof of shared control. "
            "Families and small businesses legitimately share devices, "
            "addresses and handles.",
            "Network address associations are especially weak: carrier NAT and "
            "public Wi-Fi place unrelated accounts behind one address.",
        ]
    )


class VerificationUpdateRequest(MuleGuardModel):
    """
    An analyst's verification decision on a link.
    """

    verification_state: VerificationStateField = Field(description="The decision.")
    note: Optional[str] = Field(
        default=None,
        max_length=1_000,
        description="Reasoning, appended to the link's review history.",
    )


class EntityFilterParams(MuleGuardModel):
    """
    Entity list filters.
    """

    entity_type: Optional[EntityTypeField] = Field(default=None)
    source: Optional[str] = Field(default=None, max_length=100)
    account_id: Optional[IdentifierField] = Field(
        default=None, description="Only entities linked to this account."
    )
    verification_state: Optional[VerificationStateField] = Field(default=None)
    min_linked_accounts: Optional[int] = Field(
        default=None,
        ge=1,
        description="Only entities shared by at least this many accounts.",
    )
    valid_at: Optional[datetime] = Field(
        default=None,
        description="Only links valid at this instant. Defaults to now.",
    )
