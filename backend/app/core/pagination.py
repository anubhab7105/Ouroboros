"""
MULEGUARD backend core pagination primitives.

This module provides reusable, bounded, safe pagination and sorting helpers for
the MULEGUARD backend.

Primary responsibilities:

- parse and clamp page/page-size inputs;
- parse stable, allowlisted sort selections;
- support offset pagination and signed keyset/cursor pagination;
- provide safe in-memory sorting and pagination helpers;
- provide SQLAlchemy-friendly pagination helpers without requiring SQLAlchemy at
  import time;
- provide page metadata, link-header generation, and cursor encoding/decoding;
- prevent unbounded queries, unstable ordering, sort-field injection, and
  cursor tampering.

Relationship to other modules:

- API dependencies may use these primitives to build FastAPI pagination
  dependencies.
- Endpoint modules may use `apply_sqlalchemy_pagination` for ORM queries.
- Services may use `safe_sort` and `paginate_in_memory` for bounded in-process
  collections.

Security and product-safety rules enforced here:

- Pagination is always bounded by configured limits.
- Sort fields must match a conservative identifier pattern and, when configured,
  an explicit allowlist.
- Cursors are versioned and optionally HMAC-signed.
- Cursor payloads are strict JSON with duplicate-key and non-finite-constant
  rejection.
- Link headers never include secrets, tokens, passwords, raw complaint
  narratives, database URLs, or real customer data.
- Pagination helpers never trigger automatic adverse customer action.

Explicit non-goals:

- This module does not authenticate or authorize users.
- This module does not fetch data by itself.
- This module does not implement full-text relevance ranking.
- This module does not claim production readiness.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Final, Generic, Optional, TypeVar
from urllib.parse import urlencode

from app.exceptions import ValidationError


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

DEFAULT_PAGE_NUMBER: Final[int] = 1
DEFAULT_PAGE_SIZE: Final[int] = 50
DEFAULT_MAX_PAGE_SIZE: Final[int] = 200
DEFAULT_HARD_MAX_PAGE_SIZE: Final[int] = 500
DEFAULT_MAX_OFFSET: Final[int] = 1_000_000
DEFAULT_MAX_SORT_FIELDS: Final[int] = 8

CURSOR_VERSION: Final[str] = "v1"

_FIELD_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

T = TypeVar("T")


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class SortOrder(str, Enum):
    """
    Stable sort direction identifiers.
    """

    ASC = "asc"
    DESC = "desc"


class PaginationStrategy(str, Enum):
    """
    Supported pagination strategies.
    """

    OFFSET = "offset"
    CURSOR = "cursor"


# -----------------------------------------------------------------------------
# Dataclasses
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SortSpec:
    """
    One validated sort selection.
    """

    field: str
    order: SortOrder


@dataclass(frozen=True, slots=True)
class PaginationConfig:
    """
    Bounded pagination policy.

    Callers should construct this from trusted settings or constants, not from
    raw user input.
    """

    default_page_size: int = DEFAULT_PAGE_SIZE
    max_page_size: int = DEFAULT_MAX_PAGE_SIZE
    hard_max_page_size: int = DEFAULT_HARD_MAX_PAGE_SIZE
    max_offset: int = DEFAULT_MAX_OFFSET
    max_sort_fields: int = DEFAULT_MAX_SORT_FIELDS
    default_sort_by: Optional[str] = None
    default_sort_order: SortOrder = SortOrder.DESC
    sortable_fields: frozenset[str] = field(default_factory=frozenset)
    tiebreaker_field: Optional[str] = "id"
    tiebreaker_order: SortOrder = SortOrder.DESC

    def __post_init__(self) -> None:
        """
        Normalize and clamp configuration values.
        """
        hard_max = max(1, int(self.hard_max_page_size))
        max_page_size = max(1, min(int(self.max_page_size), hard_max))
        default_page_size = max(1, min(int(self.default_page_size), max_page_size))

        object.__setattr__(self, "hard_max_page_size", hard_max)
        object.__setattr__(self, "max_page_size", max_page_size)
        object.__setattr__(self, "default_page_size", default_page_size)
        object.__setattr__(self, "max_offset", max(0, int(self.max_offset)))
        object.__setattr__(self, "max_sort_fields", max(1, int(self.max_sort_fields)))

        if not isinstance(self.sortable_fields, frozenset):
            object.__setattr__(
                self,
                "sortable_fields",
                frozenset(str(item) for item in (self.sortable_fields or ())),
            )

        object.__setattr__(
            self,
            "default_sort_order",
            _normalize_order(self.default_sort_order, SortOrder.DESC),
        )
        object.__setattr__(
            self,
            "tiebreaker_order",
            _normalize_order(self.tiebreaker_order, SortOrder.DESC),
        )

        if self.default_sort_by is not None:
            default_sort_by = str(self.default_sort_by).strip()

            if not default_sort_by:
                object.__setattr__(self, "default_sort_by", None)
            elif not _FIELD_RE.match(default_sort_by):
                raise ValueError("default_sort_by is not a safe field name.")
            else:
                object.__setattr__(self, "default_sort_by", default_sort_by)

        if self.tiebreaker_field is not None:
            tiebreaker_field = str(self.tiebreaker_field).strip()

            if not tiebreaker_field:
                object.__setattr__(self, "tiebreaker_field", None)
            elif not _FIELD_RE.match(tiebreaker_field):
                raise ValueError("tiebreaker_field is not a safe field name.")
            else:
                object.__setattr__(self, "tiebreaker_field", tiebreaker_field)

    @property
    def effective_max_page_size(self) -> int:
        """
        Return the effective maximum page size.
        """
        return min(self.max_page_size, self.hard_max_page_size)


@dataclass(frozen=True, slots=True)
class PaginationParams:
    """
    Validated pagination request parameters.
    """

    page: int
    page_size: int
    sort_specs: tuple[SortSpec, ...]
    strategy: PaginationStrategy = PaginationStrategy.OFFSET
    cursor: Optional[str] = None
    tiebreaker_field: Optional[str] = None

    @property
    def offset(self) -> int:
        """
        Return the offset for offset pagination.
        """
        if self.strategy != PaginationStrategy.OFFSET:
            return 0

        return max(0, (self.page - 1) * self.page_size)

    @property
    def limit(self) -> int:
        """
        Return the bounded page limit.
        """
        return self.page_size

    @property
    def sort_by(self) -> Optional[str]:
        """
        Return the primary sort field, if any.
        """
        if not self.sort_specs:
            return None

        return self.sort_specs[0].field

    @property
    def sort_order(self) -> SortOrder:
        """
        Return the primary sort order.
        """
        if not self.sort_specs:
            return SortOrder.DESC

        return self.sort_specs[0].order


@dataclass(frozen=True, slots=True)
class PageMeta:
    """
    Safe pagination metadata.
    """

    page: int
    page_size: int
    total: int
    total_pages: int
    has_next: bool
    has_previous: bool
    next_page: Optional[int]
    previous_page: Optional[int]
    strategy: PaginationStrategy = PaginationStrategy.OFFSET

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable metadata mapping.
        """
        payload = asdict(self)
        payload["strategy"] = self.strategy.value
        return payload


@dataclass
class Page(Generic[T]):
    """
    Safe paginated result envelope.
    """

    items: list[T]
    meta: PageMeta
    next_cursor: Optional[str] = None
    previous_cursor: Optional[str] = None

    def to_dict(
        self,
        *,
        item_serializer: Optional[Callable[[T], Any]] = None,
    ) -> dict[str, Any]:
        """
        Return a JSON-serializable payload.
        """
        if item_serializer is not None:
            items = [item_serializer(item) for item in self.items]
        else:
            items = list(self.items)

        return {
            "items": items,
            "meta": self.meta.to_dict(),
            "next_cursor": self.next_cursor,
            "previous_cursor": self.previous_cursor,
        }


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _normalize_order(value: Any, default: SortOrder) -> SortOrder:
    """
    Normalize a sort-direction-like value.
    """
    if isinstance(value, SortOrder):
        return value

    text = str(value or "").strip().lower()

    if text in {"asc", "ascending", "a", "up"}:
        return SortOrder.ASC

    if text in {"desc", "descending", "d", "down"}:
        return SortOrder.DESC

    return default


def _normalize_strategy(value: Any) -> PaginationStrategy:
    """
    Normalize a pagination strategy value.
    """
    if isinstance(value, PaginationStrategy):
        return value

    text = str(value or PaginationStrategy.OFFSET.value).strip().lower()

    try:
        return PaginationStrategy(text)
    except ValueError as exc:
        raise ValidationError(
            "Pagination strategy is not supported.",
            details={
                "allowed_strategies": [item.value for item in PaginationStrategy],
            },
        ) from exc


def _clean_text(value: Any, limit: int = 512) -> str:
    """
    Return a safe single-line text value.
    """
    text = str(value if value is not None else "")
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if len(text) > limit:
        return text[:limit]

    return text


def _as_sort_items(sort_by: Any) -> list[str]:
    """
    Convert sort_by input into a bounded list of raw sort tokens.
    """
    if sort_by is None:
        return []

    if isinstance(sort_by, str):
        parts = [part.strip() for part in sort_by.split(",") if part.strip()]
    elif isinstance(sort_by, Sequence):
        parts = [str(item).strip() for item in sort_by if str(item).strip()]
    else:
        parts = [str(sort_by).strip()]

    return [part for part in parts if part]


def _parse_sort_token(token: str, default_order: SortOrder) -> tuple[str, SortOrder]:
    """
    Parse one sort token.

    Supported forms:

    - `field`
    - `+field`
    - `-field`
    - `field:asc`
    - `field:desc`
    """
    text = str(token).strip()

    if not text:
        raise ValidationError(
            "Sort field must not be empty.",
            details={"reason": "empty_sort_field"},
        )

    if text.startswith("+"):
        return text[1:].strip(), SortOrder.ASC

    if text.startswith("-"):
        return text[1:].strip(), SortOrder.DESC

    if ":" in text:
        field_name, _, order_text = text.partition(":")
        return field_name.strip(), _normalize_order(order_text, default_order)

    return text, default_order


def _default_field_accessor(item: Any, field_name: str) -> Any:
    """
    Read a field from a mapping/object using dotted path notation.
    """
    obj = item

    for part in field_name.split("."):
        if obj is None:
            return None

        if isinstance(obj, Mapping):
            obj = obj.get(part)
        else:
            obj = getattr(obj, part, None)

    return obj


def _type_rank(value: Any) -> int:
    """
    Return a stable type rank for safe cross-type sorting.
    """
    if value is None:
        return 0

    if isinstance(value, bool):
        return 1

    if isinstance(value, (int, float, Decimal)):
        return 2

    if isinstance(value, (datetime, date)):
        return 3

    if isinstance(value, str):
        return 4

    if isinstance(value, (bytes, bytearray, memoryview)):
        return 5

    return 6


class _SortableValue:
    """
    Comparable wrapper that makes heterogeneous values safely sortable.

    This is intentionally conservative. Values of different types are ordered
    by type rank first, then by value when possible, then by stable string
    fallback.
    """

    __slots__ = ("value", "rank")

    def __init__(self, value: Any) -> None:
        self.value = value
        self.rank = _type_rank(value)

    def __lt__(self, other: "_SortableValue") -> bool:
        if self.rank != other.rank:
            return self.rank < other.rank

        if self.value is None or other.value is None:
            return False

        try:
            return bool(self.value < other.value)
        except Exception:
            try:
                return str(self.value) < str(other.value)
            except Exception:
                return False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _SortableValue):
            return NotImplemented

        if self.rank != other.rank:
            return False

        try:
            return bool(self.value == other.value)
        except Exception:
            return str(self.value) == str(other.value)


def _compare_values(left: Any, right: Any) -> int:
    """
    Return -1 when left < right, 1 when left > right, else 0.
    """
    left_key = _SortableValue(left)
    right_key = _SortableValue(right)

    if left_key < right_key:
        return -1

    if right_key < left_key:
        return 1

    return 0


def _coerce_cursor_value(value: Any) -> Any:
    """
    Best-effort coercion of cursor JSON values.

    Callers can supply explicit transforms for exact column types.
    """
    if not isinstance(value, str):
        return value

    text = value.strip()

    if not text:
        return value

    if text.endswith("Z"):
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            pass

    if "T" in text:
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass

    return value


def _coerce_cursor_to_item_type(item_value: Any, cursor_value: Any) -> Any:
    """
    Coerce a cursor value to the observed item value type for in-memory
    comparison.
    """
    if item_value is None or cursor_value is None:
        return cursor_value

    if isinstance(item_value, datetime) and isinstance(cursor_value, str):
        text = cursor_value.strip()

        try:
            if text.endswith("Z"):
                return datetime.fromisoformat(text.replace("Z", "+00:00"))

            return datetime.fromisoformat(text)
        except ValueError:
            return cursor_value

    if isinstance(item_value, date) and isinstance(cursor_value, str):
        try:
            return date.fromisoformat(cursor_value.strip())
        except ValueError:
            return cursor_value

    if isinstance(item_value, Decimal) and isinstance(cursor_value, str):
        try:
            return Decimal(cursor_value)
        except InvalidOperation:
            return cursor_value

    if isinstance(item_value, bool):
        if isinstance(cursor_value, bool):
            return cursor_value

        text = str(cursor_value).strip().lower()

        if text in {"1", "true", "yes", "y", "on", "t"}:
            return True

        if text in {"0", "false", "no", "n", "off", "f"}:
            return False

        return cursor_value

    if isinstance(item_value, int) and isinstance(cursor_value, str):
        try:
            return int(cursor_value)
        except ValueError:
            return cursor_value

    if isinstance(item_value, float) and isinstance(cursor_value, str):
        try:
            return float(cursor_value)
        except ValueError:
            return cursor_value

    return cursor_value


def _json_default(value: Any) -> Any:
    """
    JSON serializer for cursor payloads.
    """
    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, date):
        return value.isoformat()

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.urlsafe_b64encode(bytes(value)).decode("ascii")

    return str(value)


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    """
    Reject duplicate JSON object keys.
    """
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")

        result[key] = value

    return result


def _reject_non_finite_constant(value: str) -> Any:
    """
    Reject NaN/Infinity JSON constants.
    """
    raise ValueError(f"non_finite_constant:{value}")


def _b64url_encode(raw: bytes) -> str:
    """
    URL-safe base64 encode without padding.
    """
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    """
    URL-safe base64 decode with padding restoration.
    """
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _secret_bytes(secret: str | bytes) -> bytes:
    """
    Normalize a secret to bytes.
    """
    if isinstance(secret, bytes):
        return secret

    return str(secret).encode("utf-8", errors="replace")


# -----------------------------------------------------------------------------
# Sort parsing
# -----------------------------------------------------------------------------


def parse_sort_selection(
    sort_by: Any,
    sort_order: Any,
    config: PaginationConfig,
) -> tuple[SortSpec, ...]:
    """
    Parse and validate sort selection.

    Supports comma-separated fields, explicit `+`/`-` prefixes, and
    `field:direction` syntax. Unknown or unsafe fields are rejected.
    """
    global_order = _normalize_order(sort_order, config.default_sort_order)
    raw_tokens = _as_sort_items(sort_by)

    if not raw_tokens and config.default_sort_by:
        raw_tokens = [config.default_sort_by]

    if len(raw_tokens) > config.max_sort_fields:
        raise ValidationError(
            "Too many sort fields.",
            details={
                "max_sort_fields": config.max_sort_fields,
                "requested_sort_fields": len(raw_tokens),
            },
        )

    specs: list[SortSpec] = []
    seen: set[str] = set()

    for token in raw_tokens:
        field_name, order = _parse_sort_token(token, global_order)
        field_name = field_name.strip()

        if not field_name:
            raise ValidationError(
                "Sort field must not be empty.",
                details={"reason": "empty_sort_field"},
            )

        if not _FIELD_RE.match(field_name):
            raise ValidationError(
                "Sort field is not allowed.",
                details={"reason": "unsafe_sort_field"},
            )

        if config.sortable_fields and field_name not in config.sortable_fields:
            raise ValidationError(
                "Sort field is not allowed.",
                details={
                    "reason": "sort_field_not_in_allowlist",
                    "field": field_name,
                },
            )

        if field_name in seen:
            continue

        seen.add(field_name)
        specs.append(SortSpec(field=field_name, order=order))

    if (
        config.tiebreaker_field
        and config.tiebreaker_field not in seen
        and _FIELD_RE.match(config.tiebreaker_field)
    ):
        specs.append(
            SortSpec(
                field=config.tiebreaker_field,
                order=config.tiebreaker_order,
            )
        )

    return tuple(specs)


# -----------------------------------------------------------------------------
# Request parsing
# -----------------------------------------------------------------------------


def clamp_page_size(value: Any, config: PaginationConfig) -> int:
    """
    Clamp a requested page size to configured bounds.
    """
    if value is None:
        return config.default_page_size

    try:
        page_size = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            "page_size must be an integer.",
            details={"reason": "invalid_page_size"},
        ) from exc

    if page_size <= 0:
        raise ValidationError(
            "page_size must be greater than zero.",
            details={"reason": "non_positive_page_size"},
        )

    return min(page_size, config.effective_max_page_size)


def clamp_page_number(value: Any) -> int:
    """
    Validate and clamp a page number.
    """
    if value is None:
        return DEFAULT_PAGE_NUMBER

    try:
        page = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            "page must be an integer.",
            details={"reason": "invalid_page"},
        ) from exc

    if page < DEFAULT_PAGE_NUMBER:
        raise ValidationError(
            "page must be greater than or equal to 1.",
            details={"reason": "non_positive_page"},
        )

    return page


def parse_pagination(
    *,
    page: Any = None,
    page_size: Any = None,
    sort_by: Any = None,
    sort_order: Any = None,
    cursor: Optional[str] = None,
    strategy: Any = PaginationStrategy.OFFSET,
    config: Optional[PaginationConfig] = None,
) -> PaginationParams:
    """
    Parse bounded pagination parameters.

    For cursor pagination, `page` is ignored and callers should supply a cursor
    for subsequent pages. For offset pagination, `cursor` must not be supplied.
    """
    cfg = config or PaginationConfig()
    resolved_strategy = _normalize_strategy(strategy)

    if resolved_strategy == PaginationStrategy.CURSOR:
        page_number = DEFAULT_PAGE_NUMBER
    else:
        page_number = clamp_page_number(page)

    resolved_page_size = clamp_page_size(page_size, cfg)
    sort_specs = parse_sort_selection(sort_by, sort_order, cfg)

    if resolved_strategy == PaginationStrategy.OFFSET and cursor:
        raise ValidationError(
            "Cursor is only supported when strategy=cursor.",
            details={"reason": "cursor_with_offset_strategy"},
        )

    if resolved_strategy == PaginationStrategy.OFFSET:
        offset = (page_number - 1) * resolved_page_size

        if offset > cfg.max_offset:
            raise ValidationError(
                "Requested page is too deep.",
                details={
                    "reason": "offset_too_large",
                    "max_offset": cfg.max_offset,
                },
            )

    return PaginationParams(
        page=page_number,
        page_size=resolved_page_size,
        sort_specs=sort_specs,
        strategy=resolved_strategy,
        cursor=_clean_text(cursor, 2048) if cursor else None,
        tiebreaker_field=cfg.tiebreaker_field,
    )


# -----------------------------------------------------------------------------
# Page metadata
# -----------------------------------------------------------------------------


def compute_page_meta(
    total: int,
    page: int,
    page_size: int,
    *,
    strategy: PaginationStrategy = PaginationStrategy.OFFSET,
) -> PageMeta:
    """
    Compute safe page metadata.
    """
    safe_total = max(0, int(total))
    safe_page_size = max(1, int(page_size))
    safe_page = max(1, int(page))

    total_pages = (
        (safe_total + safe_page_size - 1) // safe_page_size
        if safe_total > 0
        else 0
    )

    has_next = safe_page < total_pages
    has_previous = safe_page > 1 and total_pages > 0

    return PageMeta(
        page=safe_page,
        page_size=safe_page_size,
        total=safe_total,
        total_pages=total_pages,
        has_next=has_next,
        has_previous=has_previous,
        next_page=safe_page + 1 if has_next else None,
        previous_page=safe_page - 1 if has_previous else None,
        strategy=strategy,
    )


def build_link_header(
    path: str,
    meta: PageMeta,
    extra_query: Optional[Mapping[str, Any]] = None,
    *,
    page_param: str = "page",
    page_size_param: str = "page_size",
) -> Optional[str]:
    """
    Build a safe RFC8288-style Link header for offset pagination.

    This helper never includes secrets. Callers must not place sensitive values
    in `extra_query`.
    """
    if meta.strategy != PaginationStrategy.OFFSET:
        return None

    if not meta.has_next and not meta.has_previous:
        return None

    safe_path = _clean_text(path, 2048)

    if not safe_path.startswith("/"):
        safe_path = f"/{safe_path}"

    base_params: dict[str, Any] = {}

    if extra_query:
        for key, value in extra_query.items():
            if value is None:
                continue

            text_key = _clean_text(key, 128)

            if not text_key:
                continue

            if text_key in {page_param, page_size_param}:
                continue

            base_params[text_key] = _clean_text(value, 512)

    links: list[str] = []

    def link_url(page: int) -> str:
        params = dict(base_params)
        params[page_param] = page
        params[page_size_param] = meta.page_size
        return f"<{safe_path}?{urlencode(params)}>; rel=\"{rel}\""

    if meta.next_page is not None:
        rel = "next"
        links.append(link_url(meta.next_page))

    if meta.previous_page is not None:
        rel = "prev"
        links.append(link_url(meta.previous_page))

    if not links:
        return None

    return ", ".join(links)


# -----------------------------------------------------------------------------
# In-memory sorting and pagination
# -----------------------------------------------------------------------------


def safe_sort(
    items: Sequence[T],
    sort_specs: Sequence[SortSpec],
    *,
    accessor: Optional[Callable[[Any, str], Any]] = None,
) -> list[T]:
    """
    Sort items safely using bounded sort specs.

    Sorting is stable and supports mixed directions by applying least-significant
    keys first.
    """
    if not sort_specs:
        return list(items)

    field_accessor = accessor or _default_field_accessor
    result = list(items)

    for spec in reversed(list(sort_specs)):
        result.sort(
            key=lambda item, spec=spec: _SortableValue(
                field_accessor(item, spec.field)
            ),
            reverse=spec.order == SortOrder.DESC,
        )

    return result


def build_cursor_from_item(
    item: Any,
    params: PaginationParams,
    *,
    accessor: Optional[Callable[[Any, str], Any]] = None,
    secret: Optional[str | bytes] = None,
) -> Optional[str]:
    """
    Build a signed cursor from the last item on a page.

    Returns None when no sort specs are present.
    """
    if not params.sort_specs:
        return None

    field_accessor = accessor or _default_field_accessor

    payload: dict[str, Any] = {
        "__version": CURSOR_VERSION,
        "__strategy": PaginationStrategy.CURSOR.value,
        "__sort": [[spec.field, spec.order.value] for spec in params.sort_specs],
    }

    for spec in params.sort_specs:
        value = field_accessor(item, spec.field)

        if value is None:
            raise ValidationError(
                "Cursor pagination requires non-null sort fields.",
                details={
                    "reason": "cursor_null_sort_value",
                    "field": spec.field,
                },
            )

        payload[spec.field] = value

    return encode_cursor(payload, secret=secret)


def paginate_in_memory(
    items: Sequence[T],
    params: PaginationParams,
    *,
    total: Optional[int] = None,
    accessor: Optional[Callable[[Any, str], Any]] = None,
    cursor_secret: Optional[str | bytes] = None,
) -> Page[T]:
    """
    Sort, filter, and paginate an in-memory sequence safely.

    For cursor pagination, the supplied cursor must match the current sort
    selection. This helper filters to rows after the cursor position according
    to the sort order.
    """
    field_accessor = accessor or _default_field_accessor
    sorted_items = safe_sort(items, params.sort_specs, accessor=field_accessor)

    if total is None:
        total = len(sorted_items)

    if params.strategy == PaginationStrategy.OFFSET:
        start = params.offset
        end = start + params.limit
        page_items = list(sorted_items[start:end])

        meta = compute_page_meta(
            total=total,
            page=params.page,
            page_size=params.page_size,
            strategy=PaginationStrategy.OFFSET,
        )

        return Page(items=page_items, meta=meta)

    cursor_values: Optional[dict[str, Any]] = None

    if params.cursor:
        payload = decode_cursor_for_params(params.cursor, params, secret=cursor_secret)

        cursor_values = {}

        for spec in params.sort_specs:
            if spec.field not in payload:
                raise ValidationError(
                    "Cursor is missing required sort values.",
                    details={
                        "reason": "cursor_missing_field",
                        "field": spec.field,
                    },
                )

            cursor_values[spec.field] = _coerce_cursor_value(payload[spec.field])

    filtered_items: list[T] = []

    for item in sorted_items:
        if cursor_values is None or _item_is_after_cursor(
            item,
            cursor_values,
            params.sort_specs,
            accessor=field_accessor,
        ):
            filtered_items.append(item)

    page_items = filtered_items[: params.limit]

    next_cursor: Optional[str] = None

    if page_items and len(page_items) == params.limit:
        next_cursor = build_cursor_from_item(
            page_items[-1],
            params,
            accessor=field_accessor,
            secret=cursor_secret,
        )

    meta = compute_page_meta(
        total=total if total is not None else len(filtered_items),
        page=DEFAULT_PAGE_NUMBER,
        page_size=params.page_size,
        strategy=PaginationStrategy.CURSOR,
    )

    return Page(items=page_items, meta=meta, next_cursor=next_cursor)


def _item_is_after_cursor(
    item: Any,
    cursor_values: Mapping[str, Any],
    sort_specs: Sequence[SortSpec],
    *,
    accessor: Callable[[Any, str], Any],
) -> bool:
    """
    Return True when an item sorts after the cursor position.
    """
    for spec in sort_specs:
        item_value = accessor(item, spec.field)
        cursor_value = cursor_values.get(spec.field)

        cursor_value = _coerce_cursor_to_item_type(item_value, cursor_value)

        comparison = _compare_values(item_value, cursor_value)

        if comparison == 0:
            continue

        if spec.order == SortOrder.ASC:
            return comparison > 0

        return comparison < 0

    return False


# -----------------------------------------------------------------------------
# Cursor encoding / decoding
# -----------------------------------------------------------------------------


def encode_cursor(
    payload: Mapping[str, Any],
    *,
    secret: Optional[str | bytes] = None,
) -> str:
    """
    Encode a cursor payload.

    When a secret is supplied, the cursor is HMAC-SHA256 signed. Unsigned cursors
    are still versioned and strictly parsed, but should only be used in trusted
    local contexts.
    """
    clean_payload = {
        str(key): value
        for key, value in payload.items()
        if not _CONTROL_CHAR_RE.search(str(key))
    }

    canonical = json.dumps(
        clean_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    )

    encoded_payload = _b64url_encode(canonical.encode("utf-8"))

    if secret is None:
        return f"{CURSOR_VERSION}.{encoded_payload}"

    signature = hmac.new(
        _secret_bytes(secret),
        f"{CURSOR_VERSION}.{encoded_payload}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"{CURSOR_VERSION}.{encoded_payload}.{signature}"


def decode_cursor(
    token: str,
    *,
    secret: Optional[str | bytes] = None,
) -> dict[str, Any]:
    """
    Decode and validate a cursor token.

    Raises ValidationError for malformed, unsigned-when-signed-required,
    tampered, expired-format, or non-strict JSON cursors.
    """
    text = _clean_text(token, 4096)

    if not text:
        raise ValidationError(
            "Cursor is required.",
            details={"reason": "missing_cursor"},
        )

    parts = text.split(".")

    if len(parts) not in {2, 3}:
        raise ValidationError(
            "Cursor is malformed.",
            details={"reason": "malformed_cursor"},
        )

    version, encoded_payload = parts[0], parts[1]

    if version != CURSOR_VERSION:
        raise ValidationError(
            "Cursor version is not supported.",
            details={"reason": "unsupported_cursor_version"},
        )

    if len(parts) == 3:
        if secret is None:
            raise ValidationError(
                "Signed cursor cannot be verified without a secret.",
                details={"reason": "cursor_signature_key_missing"},
            )

        supplied_signature = parts[2]

        expected_signature = hmac.new(
            _secret_bytes(secret),
            f"{version}.{encoded_payload}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(
            supplied_signature.encode("utf-8", errors="replace"),
            expected_signature.encode("utf-8"),
        ):
            raise ValidationError(
                "Cursor signature is invalid.",
                details={"reason": "cursor_signature_invalid"},
            )
    elif secret is not None:
        raise ValidationError(
            "Cursor signature is required.",
            details={"reason": "cursor_signature_missing"},
        )

    try:
        raw = _b64url_decode(encoded_payload)
    except Exception as exc:
        raise ValidationError(
            "Cursor payload is malformed.",
            details={"reason": "cursor_payload_decode_failed"},
        ) from exc

    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except Exception as exc:
        raise ValidationError(
            "Cursor payload is invalid JSON.",
            details={"reason": "cursor_payload_invalid_json"},
        ) from exc

    if not isinstance(payload, dict):
        raise ValidationError(
            "Cursor payload must be a JSON object.",
            details={"reason": "cursor_payload_not_object"},
        )

    return payload


def decode_cursor_for_params(
    token: str,
    params: PaginationParams,
    *,
    secret: Optional[str | bytes] = None,
) -> dict[str, Any]:
    """
    Decode a cursor and verify that it matches the current sort selection.
    """
    payload = decode_cursor(token, secret=secret)

    expected_sort = [[spec.field, spec.order.value] for spec in params.sort_specs]

    if payload.get("__sort") != expected_sort:
        raise ValidationError(
            "Cursor does not match the current sort selection.",
            details={"reason": "cursor_sort_mismatch"},
        )

    if payload.get("__strategy") != PaginationStrategy.CURSOR.value:
        raise ValidationError(
            "Cursor strategy is not supported.",
            details={"reason": "cursor_strategy_mismatch"},
        )

    return payload


# -----------------------------------------------------------------------------
# SQLAlchemy helpers
# -----------------------------------------------------------------------------


def apply_sqlalchemy_pagination(
    query: Any,
    params: PaginationParams,
    column_map: Mapping[str, Any],
    *,
    tiebreaker: Any = None,
    tiebreaker_order: SortOrder = SortOrder.DESC,
) -> Any:
    """
    Apply stable ordering and bounded pagination to a SQLAlchemy selectable.

    This helper does not import SQLAlchemy. It relies on column objects exposing
    `.asc()` and `.desc()` and query objects exposing `.offset()` and `.limit()`.

    For cursor pagination, apply cursor filters with
    `apply_sqlalchemy_cursor_pagination` instead of this helper.
    """
    order_clauses: list[Any] = []
    tiebreaker_applied = False

    for spec in params.sort_specs:
        column = column_map.get(spec.field)

        if column is None and spec.field == params.tiebreaker_field and tiebreaker is not None:
            column = tiebreaker

        if column is None:
            raise ValidationError(
                "Sort field is not available for this query.",
                details={
                    "reason": "sort_field_unavailable",
                    "field": spec.field,
                },
            )

        order_clauses.append(column.asc() if spec.order == SortOrder.ASC else column.desc())

        if tiebreaker is not None and spec.field == params.tiebreaker_field:
            tiebreaker_applied = True

    if tiebreaker is not None and not tiebreaker_applied:
        order_clauses.append(
            tiebreaker.asc() if tiebreaker_order == SortOrder.ASC else tiebreaker.desc()
        )

    query = query.order_by(*order_clauses)

    if params.strategy == PaginationStrategy.OFFSET:
        return query.offset(params.offset).limit(params.limit)

    return query.limit(params.limit)


def build_sqlalchemy_cursor_condition(
    params: PaginationParams,
    column_map: Mapping[str, Any],
    *,
    cursor_secret: Optional[str | bytes] = None,
    value_transforms: Optional[Mapping[str, Callable[[Any], Any]]] = None,
) -> Any:
    """
    Build a SQLAlchemy keyset condition for cursor pagination.

    This supports composite sort selections. Cursor values must be non-null.
    Null-aware keyset pagination requires custom query logic.
    """
    if not params.cursor:
        return None

    if params.strategy != PaginationStrategy.CURSOR:
        raise ValidationError(
            "Cursor conditions require strategy=cursor.",
            details={"reason": "cursor_strategy_mismatch"},
        )

    payload = decode_cursor_for_params(params.cursor, params, secret=cursor_secret)

    try:
        from sqlalchemy import and_, or_
    except Exception as exc:
        raise ValidationError(
            "SQLAlchemy is required for cursor condition building.",
            details={"reason": "sqlalchemy_unavailable"},
        ) from exc

    branches: list[Any] = []
    equality_prefix: list[Any] = []

    for spec in params.sort_specs:
        column = column_map.get(spec.field)

        if column is None:
            raise ValidationError(
                "Cursor sort field is not available for this query.",
                details={
                    "reason": "cursor_sort_field_unavailable",
                    "field": spec.field,
                },
            )

        if spec.field not in payload:
            raise ValidationError(
                "Cursor is missing required sort values.",
                details={
                    "reason": "cursor_missing_field",
                    "field": spec.field,
                },
            )

        raw_value = payload[spec.field]

        if raw_value is None:
            raise ValidationError(
                "Cursor pagination requires non-null sort values.",
                details={
                    "reason": "cursor_null_sort_value",
                    "field": spec.field,
                },
            )

        if value_transforms is not None and spec.field in value_transforms:
            value = value_transforms[spec.field](raw_value)
        else:
            value = _coerce_cursor_value(raw_value)

        inequality = column > value if spec.order == SortOrder.ASC else column < value

        if equality_prefix:
            branches.append(and_(*equality_prefix, inequality))
        else:
            branches.append(inequality)

        equality_prefix.append(column == value)

    if not branches:
        return None

    return or_(*branches)


def apply_sqlalchemy_cursor_pagination(
    query: Any,
    params: PaginationParams,
    column_map: Mapping[str, Any],
    *,
    tiebreaker: Any = None,
    tiebreaker_order: SortOrder = SortOrder.DESC,
    cursor_secret: Optional[str | bytes] = None,
    value_transforms: Optional[Mapping[str, Callable[[Any], Any]]] = None,
) -> Any:
    """
    Apply cursor filtering, stable ordering, and bounded limit to a SQLAlchemy
    selectable.
    """
    condition = build_sqlalchemy_cursor_condition(
        params,
        column_map,
        cursor_secret=cursor_secret,
        value_transforms=value_transforms,
    )

    if condition is not None:
        query = query.where(condition)

    return apply_sqlalchemy_pagination(
        query,
        params,
        column_map,
        tiebreaker=tiebreaker,
        tiebreaker_order=tiebreaker_order,
    )


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "DEFAULT_HARD_MAX_PAGE_SIZE",
    "DEFAULT_MAX_OFFSET",
    "DEFAULT_MAX_PAGE_SIZE",
    "DEFAULT_MAX_SORT_FIELDS",
    "DEFAULT_PAGE_NUMBER",
    "DEFAULT_PAGE_SIZE",
    "CURSOR_VERSION",
    "Page",
    "PageMeta",
    "PaginationConfig",
    "PaginationParams",
    "PaginationStrategy",
    "SortOrder",
    "SortSpec",
    "apply_sqlalchemy_cursor_pagination",
    "apply_sqlalchemy_pagination",
    "build_cursor_from_item",
    "build_link_header",
    "build_sqlalchemy_cursor_condition",
    "clamp_page_number",
    "clamp_page_size",
    "compute_page_meta",
    "decode_cursor",
    "decode_cursor_for_params",
    "encode_cursor",
    "paginate_in_memory",
    "parse_pagination",
    "parse_sort_selection",
    "safe_sort",
]