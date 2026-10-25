"""
MULEGUARD date and time utilities.

All timestamps crossing a MULEGUARD boundary are timezone-aware UTC. This
module is the single place that decides what "now" means, how a naive value is
interpreted, and how analysis windows are derived.

Design rules:

- Naive datetimes are treated as UTC rather than local time, because the
  deployment timezone must never change analysis results.
- Window helpers are inclusive of the lower bound and exclusive of the upper
  bound, so adjacent windows never double-count a transaction.
- Nothing here raises on unparseable input; callers that need strictness use
  `require_utc`.
- Point-in-time correctness: `as_of` is always an upper bound. Helpers never
  return a window whose end is in the future relative to `as_of`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import date, datetime, timedelta, timezone
from typing import Any, Final, Optional

__all__ = [
    "DAY",
    "HOUR",
    "MINUTE",
    "WEEK",
    "Window",
    "age_in_days",
    "clamp_to_range",
    "coerce_utc",
    "day_bucket",
    "end_of_day",
    "ensure_utc",
    "floor_to_granularity",
    "format_iso",
    "hour_bucket",
    "is_future",
    "iter_buckets",
    "parse_datetime",
    "parse_duration",
    "require_utc",
    "seconds_between",
    "start_of_day",
    "utcnow",
    "window_for",
    "window_days",
]

MINUTE: Final[timedelta] = timedelta(minutes=1)
HOUR: Final[timedelta] = timedelta(hours=1)
DAY: Final[timedelta] = timedelta(days=1)
WEEK: Final[timedelta] = timedelta(days=7)

# Window label -> duration. Mirrors the feature catalog window vocabulary.
_WINDOW_DURATIONS: Final[dict[str, timedelta]] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "12h": timedelta(hours=12),
    "24h": timedelta(hours=24),
    "1d": timedelta(days=1),
    "7d": timedelta(days=7),
    "14d": timedelta(days=14),
    "30d": timedelta(days=30),
    "60d": timedelta(days=60),
    "90d": timedelta(days=90),
    "180d": timedelta(days=180),
    "365d": timedelta(days=365),
}

_DURATION_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>ms|s|m|h|d|w)\s*$",
    re.IGNORECASE,
)

_UNIT_SECONDS: Final[dict[str, float]] = {
    "ms": 0.001,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86_400.0,
    "w": 604_800.0,
}

_GRANULARITIES: Final[frozenset[str]] = frozenset({"hour", "day", "week", "month"})


def utcnow() -> datetime:
    """
    Return the current timezone-aware UTC timestamp.
    """
    return datetime.now(timezone.utc)


def ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    """
    Normalise a datetime to UTC, treating naive values as UTC.

    Returns None for None so callers can pass optional columns straight
    through.
    """
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def require_utc(value: Any, field_name: str = "timestamp") -> datetime:
    """
    Coerce a value to a UTC datetime or raise ValueError.

    Used on ingestion boundaries where a missing timestamp is a data error
    rather than something to silently default.
    """
    parsed = coerce_utc(value)

    if parsed is None:
        raise ValueError(f"{field_name} is not a valid timestamp: {value!r}")

    return parsed


def coerce_utc(value: Any) -> Optional[datetime]:
    """
    Best-effort conversion of any supported value into a UTC datetime.

    Accepts datetime, date, ISO-8601 text, and epoch seconds/milliseconds.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        return ensure_utc(value)

    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)

    if isinstance(value, bool):
        # bool is an int subclass; an epoch of 0/1 is never meaningful here.
        return None

    if isinstance(value, (int, float)):
        seconds = float(value)

        # Values above ~1e11 are almost certainly milliseconds.
        if abs(seconds) > 1e11:
            seconds /= 1000.0

        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    if isinstance(value, str):
        return parse_datetime(value)

    return None


def parse_datetime(text: Any) -> Optional[datetime]:
    """
    Parse ISO-8601 text into a UTC datetime, or return None.

    Tolerates a trailing `Z`, a space instead of `T`, and date-only values.
    """
    if not isinstance(text, str):
        return coerce_utc(text)

    cleaned = text.strip()

    if not cleaned:
        return None

    if cleaned.endswith(("Z", "z")):
        cleaned = f"{cleaned[:-1]}+00:00"

    # Allow "2026-01-01 10:00:00" as well as the ISO "T" separator.
    if " " in cleaned and "T" not in cleaned:
        cleaned = cleaned.replace(" ", "T", 1)

    try:
        return ensure_utc(datetime.fromisoformat(cleaned))
    except ValueError:
        pass

    try:
        return ensure_utc(datetime.strptime(cleaned, "%Y-%m-%d"))
    except ValueError:
        return None


def format_iso(value: Optional[datetime]) -> Optional[str]:
    """
    Format a datetime as an ISO-8601 UTC string with a `+00:00` offset.
    """
    normalised = ensure_utc(value)

    if normalised is None:
        return None

    return normalised.isoformat()


def is_future(value: Optional[datetime], *, reference: Optional[datetime] = None) -> bool:
    """
    Return True when a timestamp lies strictly after the reference instant.
    """
    normalised = ensure_utc(value)

    if normalised is None:
        return False

    return normalised > (ensure_utc(reference) or utcnow())


def seconds_between(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    """
    Return the signed number of seconds from `start` to `end`.
    """
    first = ensure_utc(start)
    second = ensure_utc(end)

    if first is None or second is None:
        return None

    return (second - first).total_seconds()


def age_in_days(
    value: Optional[datetime],
    *,
    as_of: Optional[datetime] = None,
) -> Optional[float]:
    """
    Return the age of a timestamp in fractional days at `as_of`.

    Never returns a negative age: a timestamp after `as_of` yields 0.0, because
    a negative age is meaningless as a behavioural feature.
    """
    elapsed = seconds_between(value, ensure_utc(as_of) or utcnow())

    if elapsed is None:
        return None

    return max(0.0, elapsed / 86_400.0)


def start_of_day(value: Optional[datetime] = None) -> datetime:
    """
    Return midnight UTC on the day of the given timestamp.
    """
    normalised = ensure_utc(value) or utcnow()
    return normalised.replace(hour=0, minute=0, second=0, microsecond=0)


def end_of_day(value: Optional[datetime] = None) -> datetime:
    """
    Return the exclusive end of the UTC day (next midnight).
    """
    return start_of_day(value) + DAY


def floor_to_granularity(value: datetime, granularity: str) -> datetime:
    """
    Floor a timestamp to the start of its hour, day, week, or month.

    Weeks start on Monday, matching ISO-8601.
    """
    normalised = ensure_utc(value) or utcnow()
    token = str(granularity).strip().lower()

    if token not in _GRANULARITIES:
        raise ValueError(
            f"unsupported granularity {granularity!r}; "
            f"expected one of {sorted(_GRANULARITIES)}"
        )

    if token == "hour":
        return normalised.replace(minute=0, second=0, microsecond=0)

    midnight = normalised.replace(hour=0, minute=0, second=0, microsecond=0)

    if token == "day":
        return midnight

    if token == "week":
        return midnight - timedelta(days=midnight.weekday())

    return midnight.replace(day=1)


def hour_bucket(value: datetime) -> str:
    """
    Return a stable `YYYY-MM-DDTHH` bucket label.
    """
    return floor_to_granularity(value, "hour").strftime("%Y-%m-%dT%H")


def day_bucket(value: datetime) -> str:
    """
    Return a stable `YYYY-MM-DD` bucket label.
    """
    return floor_to_granularity(value, "day").strftime("%Y-%m-%d")


def parse_duration(text: Any, default: Optional[timedelta] = None) -> Optional[timedelta]:
    """
    Parse a short duration such as `30s`, `15m`, `24h`, `7d`, or `2w`.
    """
    if isinstance(text, timedelta):
        return text

    if isinstance(text, (int, float)) and not isinstance(text, bool):
        return timedelta(seconds=float(text))

    if not isinstance(text, str):
        return default

    match = _DURATION_RE.match(text)

    if match is None:
        return default

    unit = match.group("unit").lower()
    value = float(match.group("value"))
    return timedelta(seconds=value * _UNIT_SECONDS[unit])


def window_days(label: Any, default: Optional[timedelta] = None) -> Optional[timedelta]:
    """
    Resolve a feature window label such as `24h` or `30d` to a duration.
    """
    if isinstance(label, timedelta):
        return label

    token = str(label or "").strip().lower()

    if token in _WINDOW_DURATIONS:
        return _WINDOW_DURATIONS[token]

    return parse_duration(token, default)


class Window:
    """
    A half-open analysis window `[start, end)`.

    Half-open bounds are deliberate: adjacent windows tile the timeline without
    counting a transaction twice.
    """

    __slots__ = ("end", "label", "start")

    def __init__(self, start: datetime, end: datetime, label: str = "") -> None:
        normalised_start = ensure_utc(start)
        normalised_end = ensure_utc(end)

        if normalised_start is None or normalised_end is None:
            raise ValueError("window bounds must be valid timestamps")

        if normalised_end < normalised_start:
            raise ValueError("window end must not precede window start")

        self.start = normalised_start
        self.end = normalised_end
        self.label = str(label or "")

    @property
    def duration(self) -> timedelta:
        """
        Return the window length.
        """
        return self.end - self.start

    def contains(self, value: Optional[datetime]) -> bool:
        """
        Return True when a timestamp falls inside `[start, end)`.
        """
        normalised = ensure_utc(value)

        if normalised is None:
            return False

        return self.start <= normalised < self.end

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation.
        """
        return {
            "label": self.label,
            "start": format_iso(self.start),
            "end": format_iso(self.end),
            "duration_seconds": self.duration.total_seconds(),
        }

    def __repr__(self) -> str:
        return f"Window(label={self.label!r}, start={self.start!r}, end={self.end!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Window):
            return NotImplemented

        return (self.start, self.end, self.label) == (other.start, other.end, other.label)

    def __hash__(self) -> int:
        return hash((self.start, self.end, self.label))


def window_for(
    label: Any,
    *,
    as_of: Optional[datetime] = None,
    default: Optional[timedelta] = None,
) -> Optional[Window]:
    """
    Build the window of the given label ending at `as_of`.

    `as_of` is the exclusive upper bound, which keeps feature computation
    point-in-time correct: nothing at or after `as_of` is ever included.
    """
    duration = window_days(label, default)

    if duration is None:
        return None

    end = ensure_utc(as_of) or utcnow()
    return Window(end - duration, end, str(label or ""))


def clamp_to_range(
    value: Optional[datetime],
    *,
    earliest: Optional[datetime] = None,
    latest: Optional[datetime] = None,
) -> Optional[datetime]:
    """
    Clamp a timestamp into an inclusive range.
    """
    normalised = ensure_utc(value)

    if normalised is None:
        return None

    low = ensure_utc(earliest)
    high = ensure_utc(latest)

    if low is not None and normalised < low:
        normalised = low

    if high is not None and normalised > high:
        normalised = high

    return normalised


def iter_buckets(
    start: datetime,
    end: datetime,
    granularity: str = "day",
    *,
    max_buckets: int = 1_000,
) -> Iterable[Window]:
    """
    Yield consecutive half-open windows covering `[start, end)`.

    Used by dashboard trend endpoints. `max_buckets` is a hard stop so a wide
    date range cannot produce an unbounded response.
    """
    cursor = floor_to_granularity(start, granularity)
    limit = ensure_utc(end) or utcnow()
    produced = 0

    while cursor < limit and produced < max_buckets:
        if granularity == "hour":
            nxt = cursor + HOUR
        elif granularity == "day":
            nxt = cursor + DAY
        elif granularity == "week":
            nxt = cursor + WEEK
        else:
            nxt = (cursor.replace(day=28) + timedelta(days=4)).replace(day=1)

        yield Window(cursor, min(nxt, limit), day_bucket(cursor))
        cursor = nxt
        produced += 1
