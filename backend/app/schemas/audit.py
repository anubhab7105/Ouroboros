"""
MULEGUARD audit schemas.

Audit responses expose `ip_hash` and `user_agent_hash` and never a raw IP or
user agent. The hash is enough to establish that two actions came from the same
source, which is what an auditor needs, without storing the source itself.

`metadata` is sanitised before it is ever written, so no response model here
needs to filter it again.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Optional

from pydantic import Field

from app.schemas.common import IdentifierField, MuleGuardModel, ResponseModel
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "AuditEventResponse",
    "AuditFilterParams",
    "AuditListResponse",
]

_OUTCOMES = ("SUCCESS", "FAILURE", "DENIED", "WARNING")

AuditOutcomeField = Annotated[str, Field(pattern=f"^({'|'.join(_OUTCOMES)})$")]


class AuditEventResponse(ResponseModel):
    """
    One audit record.
    """

    id: str = Field(description="Audit event identifier.")
    action: str = Field(description="What was attempted.")
    outcome: str = Field(
        description=(
            "SUCCESS, FAILURE, DENIED or WARNING. DENIED records an "
            "authorisation refusal, which is as important to retain as a "
            "success."
        )
    )
    actor_id: Optional[str] = Field(default=None)
    actor_username: Optional[str] = Field(
        default=None,
        description=(
            "Denormalised, so the trail stays attributed after a user record "
            "is removed."
        ),
    )
    actor_role: Optional[str] = Field(
        default=None, description="Role held at the time of the action."
    )
    resource_type: Optional[str] = Field(default=None)
    resource_id: Optional[str] = Field(default=None)
    request_id: Optional[str] = Field(default=None)
    correlation_id: Optional[str] = Field(default=None)
    ip_hash: Optional[str] = Field(
        default=None,
        description=(
            "Hashed source address. Enough to correlate two actions from one "
            "source without storing the address."
        ),
    )
    user_agent_hash: Optional[str] = Field(default=None)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitised context. Credential-like keys are dropped at write time.",
    )
    created_at: datetime = Field(description="When it happened, UTC.")


class AuditListResponse(PaginatedResponse[AuditEventResponse]):
    """
    A page of audit events.
    """

    caveats: list[str] = Field(
        default_factory=lambda: [
            "Audit records are append-only. They are never edited or deleted.",
            "Source addresses and user agents are stored hashed, never raw.",
        ]
    )


class AuditFilterParams(MuleGuardModel):
    """
    Audit search filters.
    """

    actor_id: Optional[IdentifierField] = Field(default=None)
    actor_username: Optional[str] = Field(default=None, max_length=64)
    action: Optional[str] = Field(default=None, max_length=100)
    outcome: Optional[AuditOutcomeField] = Field(default=None)
    resource_type: Optional[str] = Field(default=None, max_length=100)
    resource_id: Optional[str] = Field(default=None, max_length=128)
    since: Optional[datetime] = Field(default=None)
    until: Optional[datetime] = Field(default=None)
    q: Optional[str] = Field(default=None, max_length=200)
