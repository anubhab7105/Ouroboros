"""
MULEGUARD decimal and money utilities.

Monetary values are `Decimal` end to end and are stored as SQL NUMERIC. Floats
are only ever used for derived statistics and model scores, never for amounts.

Design rules:

- Money quantizes to 2 decimal places with ROUND_HALF_UP, which is what a
  financial reader expects; bankers' rounding would surprise them.
- Confidence values quantize to 4 places to match the `Numeric(5, 4)` columns.
- Scores quantize to 2 places to match the `Numeric(7, 2)` columns.
- Nothing here raises on bad input; `to_decimal` returns None and the caller
  decides whether that is a validation error.
- `safe_div` never raises on a zero denominator, because ratio features are
  computed over windows that can legitimately be empty.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from decimal import (
    Decimal,
    InvalidOperation,
    ROUND_HALF_UP,
    localcontext,
)
from typing import Any, Final, Optional

__all__ = [
    "CONFIDENCE_QUANTUM",
    "MONEY_QUANTUM",
    "SCORE_QUANTUM",
    "clamp",
    "clamp_confidence",
    "clamp_score",
    "decimal_to_float",
    "is_finite_number",
    "mean",
    "median",
    "percentile",
    "quantize_confidence",
    "quantize_money",
    "quantize_score",
    "safe_div",
    "stddev",
    "sum_money",
    "to_decimal",
    "to_float",
]

MONEY_QUANTUM: Final[Decimal] = Decimal("0.01")
CONFIDENCE_QUANTUM: Final[Decimal] = Decimal("0.0001")
SCORE_QUANTUM: Final[Decimal] = Decimal("0.01")

# Numeric(18, 2) in models.py; keep a headroom guard so a corrupt input cannot
# overflow the column at flush time.
_MAX_MONEY: Final[Decimal] = Decimal("9" * 16 + ".99")
_MIN_MONEY: Final[Decimal] = -_MAX_MONEY


def to_decimal(value: Any, default: Optional[Decimal] = None) -> Optional[Decimal]:
    """
    Convert a value to Decimal, or return `default`.

    Floats are routed through `str()` so that 0.1 becomes Decimal("0.1")
    rather than the binary expansion.
    """
    if value is None:
        return default

    if isinstance(value, Decimal):
        return value if value.is_finite() else default

    if isinstance(value, bool):
        return default

    if isinstance(value, int):
        return Decimal(value)

    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return default
        try:
            return Decimal(str(value))
        except InvalidOperation:
            return default

    if isinstance(value, str):
        text = value.strip().replace(",", "")

        if not text:
            return default

        try:
            parsed = Decimal(text)
        except InvalidOperation:
            return default

        return parsed if parsed.is_finite() else default

    return default


def to_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    """
    Convert a value to a finite float, or return `default`.
    """
    if value is None:
        return default

    if isinstance(value, bool):
        return default

    if isinstance(value, (int, float)):
        numeric = float(value)
        return numeric if _finite(numeric) else default

    if isinstance(value, Decimal):
        if not value.is_finite():
            return default
        return float(value)

    if isinstance(value, str):
        try:
            numeric = float(value.strip().replace(",", ""))
        except ValueError:
            return default
        return numeric if _finite(numeric) else default

    return default


def _finite(value: float) -> bool:
    return value == value and value not in (float("inf"), float("-inf"))


def is_finite_number(value: Any) -> bool:
    """
    Return True when a value is a usable finite number.
    """
    return to_float(value) is not None


def decimal_to_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    """
    Convert a Decimal column value into a JSON-safe float.
    """
    return to_float(value, default)


def quantize_money(value: Any, default: Optional[Decimal] = None) -> Optional[Decimal]:
    """
    Quantize to 2 decimal places with ROUND_HALF_UP and clamp to NUMERIC(18,2).
    """
    parsed = to_decimal(value)

    if parsed is None:
        return default

    if parsed > _MAX_MONEY:
        parsed = _MAX_MONEY
    elif parsed < _MIN_MONEY:
        parsed = _MIN_MONEY

    with localcontext() as ctx:
        ctx.prec = 32
        try:
            return parsed.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
        except InvalidOperation:
            return default


def quantize_confidence(value: Any, default: Optional[Decimal] = None) -> Optional[Decimal]:
    """
    Quantize a 0..1 confidence to 4 places, matching `Numeric(5, 4)`.

    Values outside 0..1 are clamped rather than rejected, so an engine that
    returns 1.0000000002 does not fail a CHECK constraint.
    """
    parsed = to_decimal(value)

    if parsed is None:
        return default

    if parsed < 0:
        parsed = Decimal(0)
    elif parsed > 1:
        parsed = Decimal(1)

    try:
        return parsed.quantize(CONFIDENCE_QUANTUM, rounding=ROUND_HALF_UP)
    except InvalidOperation:
        return default


def quantize_score(value: Any, default: Optional[Decimal] = None) -> Optional[Decimal]:
    """
    Quantize a 0..100 priority score to 2 places, matching `Numeric(7, 2)`.

    Clamped to the `ck_model_assessments_score_range` CHECK constraint.
    """
    parsed = to_decimal(value)

    if parsed is None:
        return default

    if parsed < 0:
        parsed = Decimal(0)
    elif parsed > 100:
        parsed = Decimal(100)

    try:
        return parsed.quantize(SCORE_QUANTUM, rounding=ROUND_HALF_UP)
    except InvalidOperation:
        return default


def clamp(value: float, low: float, high: float) -> float:
    """
    Clamp a float into an inclusive range.
    """
    if value < low:
        return low

    if value > high:
        return high

    return value


def clamp_score(value: Any, default: float = 0.0) -> float:
    """
    Clamp any value into the 0..100 investigative priority score range.
    """
    numeric = to_float(value)

    if numeric is None:
        return clamp(default, 0.0, 100.0)

    return clamp(numeric, 0.0, 100.0)


def clamp_confidence(value: Any, default: float = 0.0) -> float:
    """
    Clamp any value into the 0..1 confidence range.
    """
    numeric = to_float(value)

    if numeric is None:
        return clamp(default, 0.0, 1.0)

    return clamp(numeric, 0.0, 1.0)


def safe_div(
    numerator: Any,
    denominator: Any,
    default: Optional[float] = None,
) -> Optional[float]:
    """
    Divide without raising on a zero or missing denominator.

    Ratio features are computed over windows that may be empty, so "no data"
    must be representable rather than an exception.
    """
    top = to_float(numerator)
    bottom = to_float(denominator)

    if top is None or bottom is None or bottom == 0.0:
        return default

    result = top / bottom
    return result if _finite(result) else default


def sum_money(values: Iterable[Any]) -> Decimal:
    """
    Sum an iterable of amounts as Decimal, ignoring unusable entries.
    """
    total = Decimal(0)

    for value in values:
        parsed = to_decimal(value)

        if parsed is not None:
            total += parsed

    return quantize_money(total) or Decimal("0.00")


def mean(values: Sequence[Any]) -> Optional[float]:
    """
    Return the arithmetic mean of the usable values, or None.
    """
    numbers = [n for n in (to_float(v) for v in values) if n is not None]

    if not numbers:
        return None

    return sum(numbers) / len(numbers)


def median(values: Sequence[Any]) -> Optional[float]:
    """
    Return the median of the usable values, or None.
    """
    numbers = sorted(n for n in (to_float(v) for v in values) if n is not None)

    if not numbers:
        return None

    midpoint = len(numbers) // 2

    if len(numbers) % 2 == 1:
        return numbers[midpoint]

    return (numbers[midpoint - 1] + numbers[midpoint]) / 2.0


def stddev(values: Sequence[Any], *, sample: bool = True) -> Optional[float]:
    """
    Return the standard deviation of the usable values, or None.

    Uses the sample standard deviation (n-1) by default, which is the right
    choice when a window is a sample of an account's behaviour.
    """
    numbers = [n for n in (to_float(v) for v in values) if n is not None]
    count = len(numbers)

    if count < 2:
        return 0.0 if count == 1 else None

    average = sum(numbers) / count
    divisor = count - 1 if sample else count
    variance = sum((n - average) ** 2 for n in numbers) / divisor
    return variance ** 0.5


def percentile(values: Sequence[Any], fraction: float) -> Optional[float]:
    """
    Return a linear-interpolated percentile, with `fraction` in 0..1.
    """
    numbers = sorted(n for n in (to_float(v) for v in values) if n is not None)

    if not numbers:
        return None

    if len(numbers) == 1:
        return numbers[0]

    position = clamp(fraction, 0.0, 1.0) * (len(numbers) - 1)
    lower = int(position)
    upper = min(lower + 1, len(numbers) - 1)
    weight = position - lower
    return numbers[lower] * (1.0 - weight) + numbers[upper] * weight
