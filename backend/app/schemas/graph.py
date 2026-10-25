"""
MULEGUARD graph schemas.

Every graph response carries `limits` and `capped`. A truncated traversal is
not a complete answer, and a client that renders one without saying so lets a
reader conclude "no path exists" when the real answer is "we stopped looking".

A money trail is a *candidate*. Money is fungible, so a path shows that value
could have moved along it — not that specific funds did. `TrailResponse` names
the field `throughput_ratio` rather than anything implying traced funds, and
the caveats say so explicitly.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Optional

from pydantic import Field, field_validator

from app.schemas.common import IdentifierField, MuleGuardModel, ResponseModel

__all__ = [
    "CycleResponse",
    "GraphEdgeResponse",
    "GraphLimitsResponse",
    "GraphNodeResponse",
    "GraphQueryParams",
    "MoneyTrailQueryParams",
    "NeighbourhoodResponse",
    "SharedEntityQueryParams",
    "TrailResponse",
]

GRAPH_CAVEATS: tuple[str, ...] = (
    "A candidate money trail shows that value could have moved along a path. "
    "Money is fungible, so it does not establish that specific funds did.",
    "Only COMPLETED transfers are edges. Failed and reversed transactions are "
    "excluded because they are not fund movement.",
    "Traversal is bounded. Where a result was capped, the absence of a path "
    "does not mean no path exists.",
    "Graph position is an investigative lead, not proof of involvement.",
)


class GraphLimitsResponse(ResponseModel):
    """
    The bounds applied to a traversal.
    """

    max_hops: int = Field(description="Maximum expansion depth.")
    max_nodes: int = Field(description="Maximum nodes returned.")
    max_edges: int = Field(description="Maximum edges returned.")
    max_paths: int = Field(description="Maximum paths enumerated.")
    max_path_length: int = Field(description="Maximum path length.")
    span_days: int = Field(description="Date span considered.")


class GraphNodeResponse(ResponseModel):
    """
    One account node.
    """

    id: str = Field(description="Account identifier.")
    hop: int = Field(default=0, description="Distance from the root, in hops.")
    inbound_amount: Optional[Decimal] = Field(default=None)
    outbound_amount: Optional[Decimal] = Field(default=None)
    risk_band: Optional[str] = Field(
        default=None, description="Latest band, when the account has been assessed."
    )
    score: Optional[Decimal] = Field(default=None)
    is_root: bool = Field(default=False)


class GraphEdgeResponse(ResponseModel):
    """
    One aggregated transfer edge.

    An edge collapses every completed transfer between the same ordered pair,
    so `amount` is the total and `count` the number of transfers. One edge per
    transaction would make a busy pair unreadable.
    """

    from_account_id: str = Field(alias="from", description="Sending account.")
    to_account_id: str = Field(alias="to", description="Receiving account.")
    amount: Decimal = Field(description="Total value across the aggregated transfers.")
    currency: Optional[str] = Field(default=None)
    count: int = Field(default=1, description="Transfers aggregated into this edge.")
    first_at: Optional[datetime] = Field(default=None)
    last_at: Optional[datetime] = Field(default=None)
    channel: Optional[str] = Field(default=None)
    transaction_ids: list[str] = Field(
        default_factory=list,
        description="A bounded sample of the underlying transactions.",
    )


class TrailResponse(ResponseModel):
    """
    One candidate money trail.
    """

    path: list[str] = Field(description="Ordered account identifiers.")
    hops: int = Field(description="Number of transfers in the path.")
    min_hop_amount: Optional[Decimal] = Field(default=None)
    max_hop_amount: Optional[Decimal] = Field(default=None)
    throughput_ratio: Optional[float] = Field(
        default=None,
        ge=0,
        le=1,
        description=(
            "Smallest hop value divided by the largest. A high ratio across "
            "several hops is the shape of layering. It does not mean the same "
            "funds traversed the path."
        ),
    )


class CycleResponse(ResponseModel):
    """
    One cycle returning to the root account.
    """

    path: list[str] = Field(description="Ordered accounts, ending at the root.")
    length: int = Field(description="Number of transfers in the cycle.")


class NeighbourhoodResponse(ResponseModel):
    """
    A bounded fund-flow neighbourhood.
    """

    root_account_id: str = Field(description="The account at the centre.")
    window_start: datetime
    window_end: datetime

    nodes: list[GraphNodeResponse] = Field(default_factory=list)
    edges: list[GraphEdgeResponse] = Field(default_factory=list)
    trails: list[TrailResponse] = Field(default_factory=list)
    cycles: list[CycleResponse] = Field(default_factory=list)

    metrics: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Position metrics. `intermediary_score` distinguishes a layering "
            "hop from an endpoint: it is high only when inbound and outbound "
            "flow are both present and roughly balanced."
        ),
    )
    limits: GraphLimitsResponse = Field(description="Bounds applied.")
    capped: dict[str, bool] = Field(
        default_factory=dict,
        description="Which limits truncated the result, if any.",
    )
    is_complete: bool = Field(
        default=True,
        description=(
            "False when any limit was hit. A client must surface this: an "
            "incomplete traversal is not evidence of absence."
        ),
    )
    caveats: list[str] = Field(default_factory=lambda: list(GRAPH_CAVEATS))


class GraphQueryParams(MuleGuardModel):
    """
    Neighbourhood query parameters.

    `root_account_id` is required. An unrooted graph query is unbounded by
    construction, so the API does not offer one.
    """

    root_account_id: IdentifierField = Field(
        description="Account at the centre of the traversal. Required."
    )
    max_hops: int = Field(default=2, ge=1, le=6)
    max_nodes: int = Field(default=200, ge=2, le=2_000)
    max_edges: int = Field(default=800, ge=1, le=10_000)
    span_days: int = Field(default=90, ge=1, le=365)
    min_amount: Optional[Decimal] = Field(
        default=None, ge=0, description="Exclude transfers below this value."
    )
    include_trails: bool = Field(default=True)
    include_cycles: bool = Field(default=True)


class MoneyTrailQueryParams(MuleGuardModel):
    """
    Money-trail search parameters.

    At least one endpoint is required for the same reason as above.
    """

    source_account_id: Optional[IdentifierField] = Field(default=None)
    destination_account_id: Optional[IdentifierField] = Field(default=None)
    max_hops: int = Field(default=4, ge=2, le=6)
    max_paths: int = Field(default=25, ge=1, le=200)
    span_days: int = Field(default=90, ge=1, le=365)
    min_amount: Optional[Decimal] = Field(default=None, ge=0)

    @field_validator("destination_account_id")
    @classmethod
    def _needs_an_endpoint(cls, value: Optional[str], info) -> Optional[str]:
        """
        Require at least one endpoint.
        """
        source = (info.data or {}).get("source_account_id")

        if not value and not source:
            raise ValueError(
                "a source or destination account is required; an unrooted "
                "trail search would be unbounded"
            )

        return value


class SharedEntityQueryParams(MuleGuardModel):
    """
    Shared-entity cluster query parameters.
    """

    account_id: IdentifierField = Field(description="Account to expand from.")
    min_cluster_size: int = Field(
        default=2, ge=2, le=100, description="Minimum accounts per cluster."
    )
    entity_types: Optional[list[str]] = Field(
        default=None, max_length=10, description="Restrict to these entity kinds."
    )
    valid_at: Optional[datetime] = Field(
        default=None,
        description=(
            "Only associations valid at this instant. Defaults to now, so two "
            "accounts that used an entity at different times are not reported "
            "as sharing it."
        ),
    )
