"""
MULEGUARD JSON serialisation utilities.

Every JSON column, API response, report payload, and audit metadata blob is
produced through this module, so one set of rules governs all of them.

Design rules:

- `Decimal` serialises to a JSON number via `float`, never to a string, so the
  frontend can do arithmetic without parsing.
- `datetime` serialises to ISO-8601 UTC.
- Enums serialise to `.value`, which is what the database stores.
- Unknown objects degrade to `str()` rather than raising, because a response
  must not 500 because a new type appeared in a metadata dict.
- `sanitize_json` bounds depth, breadth, and string length and drops
  credential-like keys. JSON columns are analyst-visible and must not become a
  dumping ground for raw payloads.
- `canonical_json` is byte-stable for hashing: sorted keys, no spaces.
"""

from __future__ import annotations

import json as _json
from collections.abc import Mapping, Sequence, Set
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import Any, Final, Optional
from uuid import UUID

__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_ITEMS",
    "DEFAULT_MAX_STRING",
    "canonical_json",
    "dumps",
    "is_json_safe",
    "json_default",
    "loads",
    "merge_json",
    "sanitize_json",
    "to_json_value",
]

DEFAULT_MAX_DEPTH: Final[int] = 8
DEFAULT_MAX_ITEMS: Final[int] = 200
DEFAULT_MAX_STRING: Final[int] = 2_000

# Key fragments whose values are never persisted or returned.
_FORBIDDEN_KEY_PARTS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "api_key",
        "apikey",
        "authorization",
        "card_number",
        "client_secret",
        "cookie",
        "credential",
        "cvv",
        "database_url",
        "ground_truth",
        "jwt",
        "otp",
        "passphrase",
        "password",
        "passwd",
        "pin",
        "private_key",
        "pwd",
        "refresh_token",
        "secret",
        "secret_key",
        "session_id",
        "set_cookie",
        "token",
    }
)

# Keys that are legitimate despite containing a forbidden fragment.
_ALLOWED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "token_count",
        "tokens_used",
        "has_token",
        "token_type",
        "secret_configured",
        "password_policy",
        "must_change_password",
        "pin_required",
    }
)

_TRUNCATION_MARK: Final[str] = "...[truncated]"


def _is_forbidden_key(key: Any) -> bool:
    """
    Return True when a mapping key must be dropped from JSON output.
    """
    text = str(key).strip().lower().replace("-", "_").replace(" ", "_")

    if not text:
        return False

    if text in _ALLOWED_KEYS:
        return False

    return any(part in text for part in _FORBIDDEN_KEY_PARTS)


def json_default(value: Any) -> Any:
    """
    `json.dumps` fallback for types the stdlib encoder does not handle.
    """
    if isinstance(value, Decimal):
        return float(value) if value.is_finite() else None

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, (date, time)):
        return value.isoformat()

    if isinstance(value, timedelta):
        return value.total_seconds()

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, PurePath):
        return str(value)

    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)

    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace")

    return str(value)


def to_json_value(value: Any) -> Any:
    """
    Convert a value into JSON-native types, recursively.

    Unlike `sanitize_json`, this applies no bounds and drops no keys. Use it
    for small, already-trusted structures.
    """
    # Enum must be tested before str/int: a `class X(str, Enum)` member is a
    # str subclass, so a str check first would return the enum member itself
    # instead of its `.value`.
    if isinstance(value, Enum):
        return to_json_value(value.value)

    if value is None or isinstance(value, (bool, int, str)):
        return value

    if isinstance(value, float):
        # NaN and infinities are not valid JSON.
        return value if value == value and value not in (float("inf"), float("-inf")) else None

    if isinstance(value, Mapping):
        return {str(k): to_json_value(v) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [to_json_value(item) for item in value]

    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)

    return json_default(value)


def sanitize_json(
    value: Any,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_items: int = DEFAULT_MAX_ITEMS,
    max_string: int = DEFAULT_MAX_STRING,
    _depth: int = 0,
) -> Any:
    """
    Convert a value into a bounded, credential-free JSON structure.

    Nesting deeper than `max_depth` is replaced with a marker, collections are
    capped at `max_items`, strings are truncated at `max_string`, and
    credential-like keys are removed entirely.
    """
    if _depth >= max_depth:
        return "[max depth reached]"

    # Enum first: a `class X(str, Enum)` / `class X(int, Enum)` member is a
    # str/int subclass, so a primitive check first would leak the enum member
    # into a JSON column instead of its `.value`.
    if isinstance(value, Enum):
        return sanitize_json(
            value.value,
            max_depth=max_depth,
            max_items=max_items,
            max_string=max_string,
            _depth=_depth + 1,
        )

    if value is None or isinstance(value, bool):
        return value

    if isinstance(value, int) and not isinstance(value, bool):
        return value

    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else None

    if isinstance(value, Decimal):
        return float(value) if value.is_finite() else None

    if isinstance(value, str):
        if len(value) > max_string:
            return value[:max_string] + _TRUNCATION_MARK
        return value

    if isinstance(value, (datetime, date, time, timedelta, UUID, PurePath)):
        return json_default(value)

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}

        for index, (raw_key, raw_value) in enumerate(value.items()):
            if index >= max_items:
                out["__truncated__"] = True
                break

            if _is_forbidden_key(raw_key):
                continue

            out[str(raw_key)[:200]] = sanitize_json(
                raw_value,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
                _depth=_depth + 1,
            )

        return out

    if isinstance(value, (Sequence, Set)) and not isinstance(value, (str, bytes, bytearray)):
        items = list(value)
        truncated = len(items) > max_items
        rendered = [
            sanitize_json(
                item,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
                _depth=_depth + 1,
            )
            for item in items[:max_items]
        ]

        if truncated:
            rendered.append("...[truncated]")

        return rendered

    if isinstance(value, (bytes, bytearray)):
        return f"[{len(value)} bytes]"

    return str(value)[:max_string]


def dumps(
    value: Any,
    *,
    sort_keys: bool = False,
    indent: Optional[int] = None,
    ensure_ascii: bool = False,
) -> str:
    """
    Serialise a value to JSON text using the MULEGUARD encoder.
    """
    return _json.dumps(
        value,
        default=json_default,
        sort_keys=sort_keys,
        indent=indent,
        ensure_ascii=ensure_ascii,
        allow_nan=False,
        separators=(",", ": ") if indent is not None else (",", ":"),
    )


def canonical_json(value: Any) -> str:
    """
    Serialise to a byte-stable canonical form for fingerprinting.

    Keys are sorted and separators carry no whitespace, so the same logical
    payload always hashes to the same digest.
    """
    return _json.dumps(
        to_json_value(value),
        default=json_default,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def loads(text: Any, default: Any = None) -> Any:
    """
    Parse JSON text, returning `default` on any failure.
    """
    if text is None:
        return default

    if isinstance(text, (dict, list)):
        return text

    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8", errors="replace")

    if not isinstance(text, str) or not text.strip():
        return default

    try:
        return _json.loads(text)
    except (ValueError, TypeError):
        return default


def is_json_safe(value: Any) -> bool:
    """
    Return True when a value can be serialised without the fallback encoder.
    """
    try:
        _json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return False

    return True


def merge_json(
    base: Optional[Mapping[str, Any]],
    overlay: Optional[Mapping[str, Any]],
    *,
    deep: bool = True,
) -> dict[str, Any]:
    """
    Merge two JSON objects, with `overlay` winning.

    With `deep=True`, nested objects merge recursively; lists are replaced
    wholesale rather than concatenated, because appending would make repeated
    runs grow unboundedly.
    """
    result: dict[str, Any] = dict(base or {})

    for key, value in (overlay or {}).items():
        existing = result.get(key)

        if (
            deep
            and isinstance(existing, Mapping)
            and isinstance(value, Mapping)
        ):
            result[key] = merge_json(existing, value, deep=True)
        else:
            result[key] = value

    return result
