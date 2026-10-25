"""
MULEGUARD pagination schemas.

Page-based pagination with a hard server-side ceiling.

Two decisions worth stating:

- **`page_size` is capped server-side at 200.** A client asking for 100,000
  rows gets 200. Honouring it would turn one request into a table scan and a
  response too large to render.
- **`total` is returned, but `total_pages` is derived.** Clients that compute
  it themselves disagree with the server about the final page when `total`
  changes between requests.

Investigative lists are ordered by recency or by score, both of which shift as
analysis runs land. A row can therefore move between pages during paging. The
response says so via `ordering_is_volatile` rather than pretending otherwise;
`sort_by` with a stable tiebreaker is the mitigation the endpoints apply.
"""

from __future__ import annotations

from typing import Annotated, Any, Final, Generic, Optional, TypeVar

from pydantic import Field, computed_field

from app.schemas.common import MuleGuardModel, ResponseModel

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "PageMeta",
    "PaginatedResponse",
    "PaginationParams",
    "SortOrder",
    "SortParams",
]

T = TypeVar("T")

DEFAULT_PAGE_SIZE: Final[int] = 25
MAX_PAGE_SIZE: Final[int] = 200

SortOrder = Annotated[str, Field(pattern="^(asc|desc)$")]


class PaginationParams(MuleGuardModel):
    """
    Requested page.
    """

    page: int = Field(default=1, ge=1, le=10_000, description="1-based page number.")
    page_size: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description=(
            f"Rows per page. Capped server-side at {MAX_PAGE_SIZE} regardless "
            "of what is requested."
        ),
    )

    @property
    def offset(self) -> int:
        """
        Zero-based row offset for the requested page.
        """
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """
        Row limit for the requested page.
        """
        return self.page_size


class SortParams(MuleGuardModel):
    """
    Requested ordering.
    """

    sort_by: Optional[str] = Field(
        default=None,
        max_length=64,
        description=(
            "Field to sort by. Only fields the endpoint allows are accepted; "
            "an unknown field is rejected rather than ignored."
        ),
    )
    sort_order: SortOrder = Field(default="desc", description="asc or desc.")


class PageMeta(ResponseModel):
    """
    Pagination metadata for a page of results.
    """

    page: int = Field(description="1-based page number returned.")
    page_size: int = Field(description="Rows per page actually applied.")
    total: int = Field(ge=0, description="Total matching rows.")
    sort_by: Optional[str] = Field(default=None)
    sort_order: str = Field(default="desc")
    requested_page_size: Optional[int] = Field(
        default=None,
        description=(
            "What the client asked for, when it differed from what was "
            "applied because of the server cap."
        ),
    )
    ordering_is_volatile: bool = Field(
        default=False,
        description=(
            "True when the ordering can shift between requests because new "
            "analysis results change scores or recency. Rows may move between "
            "pages while paging."
        ),
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_pages(self) -> int:
        """
        Total page count, derived server-side.
        """
        if self.page_size <= 0:
            return 0

        return max(1, -(-self.total // self.page_size))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_next(self) -> bool:
        """
        True when a further page exists.
        """
        return self.page < self.total_pages

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_previous(self) -> bool:
        """
        True when an earlier page exists.
        """
        return self.page > 1


class PaginatedResponse(ResponseModel, Generic[T]):
    """
    A page of results with its metadata.
    """

    items: list[T] = Field(default_factory=list, description="Rows on this page.")
    meta: PageMeta = Field(description="Pagination metadata.")
    caveats: list[str] = Field(
        default_factory=list,
        description="Interpretation limits that travel with the data.",
    )

    @classmethod
    def build(
        cls,
        *,
        items: list[T],
        page: int,
        page_size: int,
        total: int,
        sort_by: Optional[str] = None,
        sort_order: str = "desc",
        requested_page_size: Optional[int] = None,
        volatile_ordering: bool = False,
        caveats: Optional[list[str]] = None,
    ) -> "PaginatedResponse[T]":
        """
        Build a paginated response with consistent metadata.
        """
        return cls(
            items=items,
            meta=PageMeta(
                page=page,
                page_size=page_size,
                total=total,
                sort_by=sort_by,
                sort_order=sort_order,
                requested_page_size=(
                    requested_page_size
                    if requested_page_size and requested_page_size != page_size
                    else None
                ),
                ordering_is_volatile=volatile_ordering,
            ),
            caveats=list(caveats or []),
        )
