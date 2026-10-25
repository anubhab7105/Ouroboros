"""
MULEGUARD transaction schemas.

`status` matters more than it looks. Only `COMPLETED` transfers count as fund
movement in features, graph edges, and money trails. A `FAILED` or `REVERSED`
transaction is returned by the API — an investigator needs to see an attempted
transfer — but it is excluded from every aggregate. Responses state the
distinction so a client does not sum amounts across all statuses and get a
figure that disagrees with the dashboard.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Optional

from pydantic import Field, field_validator

from app.schemas.common import (
    AmountField,
    IdentifierField,
    MuleGuardModel,
    ResponseModel,
)
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "TransactionFilterParams",
    "TransactionListResponse",
    "TransactionResponse",
    "TransactionTimelineResponse",
]

_STATUSES = ("PENDING", "COMPLETED", "FAILED", "REVERSED")
_CHANNELS = ("UPI", "IMPS", "NEFT", "RTGS", "CARD", "INTERNAL")

TransactionStatusField = Annotated[str, Field(pattern=f"^({'|'.join(_STATUSES)})$")]
ChannelField = Annotated[str, Field(pattern=f"^({'|'.join(_CHANNELS)})$")]
CurrencyField = Annotated[str, Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")]


class TransactionResponse(ResponseModel):
    """
    A transaction row.
    """

    id: str = Field(description="Transaction identifier.")
    reference: str = Field(
        description=(
            "Unique source reference. This is what complaint correlation "
            "matches on at tiers 1 and 2."
        )
    )
    sender_account_id: str = Field(description="Sending account.")
    receiver_account_id: str = Field(description="Receiving account.")
    amount: Decimal = Field(description="Transfer amount.")
    currency: str = Field(description="ISO-style 3-letter currency code.")
    occurred_at: datetime = Field(description="When the transfer occurred, UTC.")
    status: str = Field(
        description=(
            "Lifecycle status. Only COMPLETED counts as fund movement in "
            "features, graph edges and money trails."
        )
    )
    channel: str = Field(description="Payment channel.")
    direction: Optional[str] = Field(
        default=None,
        description=(
            "'inbound' or 'outbound' relative to the account being viewed. "
            "Absent on a global list, where there is no reference account."
        ),
    )
    counterparty_account_id: Optional[str] = Field(
        default=None,
        description="The other endpoint relative to the account being viewed.",
    )
    is_fund_movement: bool = Field(
        default=True,
        description=(
            "True only for COMPLETED transfers. Clients should exclude rows "
            "where this is false from any total."
        ),
    )


class TransactionListResponse(PaginatedResponse[TransactionResponse]):
    """
    A page of transactions.
    """


class TransactionTimelineResponse(ResponseModel):
    """
    An account's transactions with window totals.

    Totals cover COMPLETED transfers only, while `items` may include other
    statuses. `excluded_non_completed_count` makes the difference explicit so a
    client summing `items` can see why its figure differs.
    """

    account_id: str = Field(description="Account the timeline belongs to.")
    window_start: datetime
    window_end: datetime
    items: list[TransactionResponse] = Field(default_factory=list)

    completed_count: int = Field(default=0)
    completed_inbound_amount: Optional[Decimal] = Field(default=None)
    completed_outbound_amount: Optional[Decimal] = Field(default=None)
    excluded_non_completed_count: int = Field(
        default=0,
        description=(
            "Rows present in `items` but excluded from the totals because "
            "they are not COMPLETED."
        ),
    )
    truncated: bool = Field(
        default=False,
        description="True when the row limit cut the timeline short.",
    )
    caveats: list[str] = Field(default_factory=list)


class TransactionFilterParams(MuleGuardModel):
    """
    Transaction list filters.
    """

    account_id: Optional[IdentifierField] = Field(
        default=None, description="Either endpoint matches."
    )
    sender_account_id: Optional[IdentifierField] = Field(default=None)
    receiver_account_id: Optional[IdentifierField] = Field(default=None)
    status: Optional[TransactionStatusField] = Field(default=None)
    channel: Optional[ChannelField] = Field(default=None)
    currency: Optional[CurrencyField] = Field(default=None)
    min_amount: Optional[Decimal] = Field(default=None, ge=0)
    max_amount: Optional[Decimal] = Field(default=None, ge=0)
    occurred_after: Optional[datetime] = Field(default=None)
    occurred_before: Optional[datetime] = Field(default=None)
    reference: Optional[str] = Field(default=None, max_length=128)
    completed_only: bool = Field(
        default=False,
        description="Restrict results to COMPLETED fund movement.",
    )

    @field_validator("max_amount")
    @classmethod
    def _range_ordered(cls, value: Optional[Decimal], info) -> Optional[Decimal]:
        """
        Reject an inverted amount range.
        """
        minimum = (info.data or {}).get("min_amount")

        if value is not None and minimum is not None and value < minimum:
            raise ValueError("max_amount must not be below min_amount")

        return value

    @field_validator("occurred_before")
    @classmethod
    def _dates_ordered(cls, value: Optional[datetime], info) -> Optional[datetime]:
        """
        Reject an inverted date range.
        """
        after = (info.data or {}).get("occurred_after")

        if value is not None and after is not None and value < after:
            raise ValueError("occurred_before must not precede occurred_after")

        return value
