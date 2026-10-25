"""
MULEGUARD text normalisation and redaction utilities.

Text reaches MULEGUARD from synthetic complaint narratives, analyst notes, and
import payloads. This module makes that text safe to log, store, and render.

Design rules:

- Raw complaint narratives are source facts and must never be silently
  rewritten; normalisation results are stored in separate columns.
- Anything that may reach a log or an audit record passes through `redact`
  first, so a pasted token or password does not become durable.
- Control characters are stripped rather than escaped, which keeps single-line
  log records single-line.
- Truncation is explicit and marked, so a reader can tell a value was cut.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from typing import Any, Final, Optional

__all__ = [
    "REDACTED",
    "clean_text",
    "collapse_whitespace",
    "jaccard_similarity",
    "mask_middle",
    "normalize_reference",
    "normalize_token",
    "normalize_whitespace_text",
    "redact",
    "shannon_entropy",
    "slugify",
    "snippet",
    "split_terms",
    "strip_control_chars",
    "title_case",
    "token_set",
    "truncate",
]

REDACTED: Final[str] = "[REDACTED]"

_CONTROL_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE: Final[re.Pattern[str]] = re.compile(r"\s+")
_NON_SLUG: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")
_NON_TOKEN: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_TERM_SPLIT: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")

# Patterns whose *values* must never be logged or persisted in metadata.
# Ordered most specific first so that a longer match wins.
_SECRET_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "bearer",
        re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{8,}=*", re.IGNORECASE),
    ),
    (
        "jwt",
        re.compile(r"\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),
    ),
    (
        "dsn",
        re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:@/]+:[^\s@/]+@[^\s]+", re.IGNORECASE),
    ),
    (
        "assignment",
        re.compile(
            r"\b(?P<key>password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
            r"|private[_-]?key|authorization|auth[_-]?token|session[_-]?id|otp|pin"
            r"|cvv|card[_-]?number)\b\s*[:=]\s*(?P<value>\"[^\"]*\"|'[^']*'|\S+)",
            re.IGNORECASE,
        ),
    ),
    (
        "long_digits",
        # 12+ consecutive digits: card-like / account-like numbers.
        re.compile(r"\b\d{12,}\b"),
    ),
)

_MAX_DEFAULT_LENGTH: Final[int] = 4_000


def strip_control_chars(value: Any) -> str:
    """
    Remove control characters, normalising Unicode to NFKC first.
    """
    if value is None:
        return ""

    text = unicodedata.normalize("NFKC", str(value))
    return _CONTROL_CHARS.sub(" ", text)


def collapse_whitespace(value: Any) -> str:
    """
    Collapse all whitespace runs into single spaces and trim.
    """
    return _WHITESPACE.sub(" ", strip_control_chars(value)).strip()


def clean_text(value: Any, limit: int = _MAX_DEFAULT_LENGTH) -> str:
    """
    Return safe single-line text, truncated to `limit` characters.
    """
    text = collapse_whitespace(value)

    if limit <= 0:
        return ""

    return text[:limit]


def normalize_whitespace_text(value: Any, limit: int = _MAX_DEFAULT_LENGTH) -> str:
    """
    Normalise a multi-line body while preserving paragraph breaks.

    Used for analyst notes and complaint narratives, where losing paragraph
    structure would change how a human reads the record.
    """
    text = strip_control_chars(value).replace("\r\n", "\n").replace("\r", "\n")
    paragraphs = [
        _WHITESPACE.sub(" ", block).strip()
        for block in text.split("\n\n")
    ]
    joined = "\n\n".join(block for block in paragraphs if block)

    if limit > 0 and len(joined) > limit:
        return joined[:limit]

    return joined


def truncate(value: Any, limit: int, suffix: str = "...") -> str:
    """
    Truncate text and append a marker so the cut is visible.
    """
    text = collapse_whitespace(value)

    if limit <= 0:
        return ""

    if len(text) <= limit:
        return text

    if limit <= len(suffix):
        return text[:limit]

    return text[: limit - len(suffix)] + suffix


def snippet(value: Any, limit: int = 160) -> str:
    """
    Return a short, redacted preview suitable for a list view or a log line.
    """
    return truncate(redact(value), limit)


def redact(value: Any, limit: int = _MAX_DEFAULT_LENGTH) -> str:
    """
    Replace credential-like substrings with `[REDACTED]`.

    This is defence in depth for logs and audit metadata. It is deliberately
    conservative: it would rather redact a harmless string than persist a
    secret.
    """
    text = clean_text(value, limit)

    if not text:
        return ""

    for name, pattern in _SECRET_PATTERNS:
        if name == "assignment":
            text = pattern.sub(
                lambda m: f"{m.group('key')}={REDACTED}",
                text,
            )
        else:
            text = pattern.sub(REDACTED, text)

    return text


def mask_middle(value: Any, *, keep_start: int = 2, keep_end: int = 2) -> str:
    """
    Mask the middle of an identifier, e.g. `AC****89`.

    Used for display labels. It is not a security control: the hashed
    identifier columns exist for that.
    """
    text = collapse_whitespace(value)

    if not text:
        return ""

    if len(text) <= keep_start + keep_end:
        return "*" * len(text)

    return f"{text[:keep_start]}{'*' * (len(text) - keep_start - keep_end)}{text[-keep_end:]}"


def normalize_token(value: Any) -> str:
    """
    Normalise a token-like value to lower snake_case.

    Mirrors the normalisation used by the feature and rule engines, so a key
    written one way in configuration matches a key produced elsewhere.
    """
    text = strip_control_chars(value).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = _NON_TOKEN.sub("_", text)
    text = re.sub(r"_{2,}", "_", text)
    return text.strip("_").lower()


def normalize_reference(value: Any, limit: int = 128) -> str:
    """
    Normalise a transaction or complaint reference for matching.

    Upper-cases and removes separators so that `txn-001`, `TXN_001`, and
    `TXN 001` all compare equal. The raw reference is kept in its own column;
    this value is only ever used for correlation.
    """
    text = strip_control_chars(value).strip()

    if not text:
        return ""

    return _NON_TOKEN.sub("", text).upper()[:limit]


def slugify(value: Any, limit: int = 80, default: str = "item") -> str:
    """
    Produce a filesystem- and URL-safe slug.
    """
    text = unicodedata.normalize("NFKD", strip_control_chars(value))
    text = text.encode("ascii", "ignore").decode("ascii").lower()
    text = _NON_SLUG.sub("-", text).strip("-")
    text = re.sub(r"-{2,}", "-", text)

    if not text:
        return default

    return text[:limit].strip("-") or default


def title_case(value: Any) -> str:
    """
    Convert a snake_case or kebab-case token into a human-readable label.
    """
    text = collapse_whitespace(value).replace("_", " ").replace("-", " ")

    if not text:
        return ""

    return " ".join(word[:1].upper() + word[1:] for word in text.split(" ") if word)


def split_terms(value: Any, *, min_length: int = 2, limit: int = 256) -> list[str]:
    """
    Split text into lower-case search terms.
    """
    text = strip_control_chars(value).lower()
    terms = [term for term in _TERM_SPLIT.split(text) if len(term) >= min_length]
    return terms[:limit]


def token_set(value: Any, *, min_length: int = 2) -> set[str]:
    """
    Return the distinct search terms in a piece of text.
    """
    return set(split_terms(value, min_length=min_length))


def jaccard_similarity(left: Any, right: Any) -> float:
    """
    Return the Jaccard similarity of two texts' term sets, in 0..1.

    Used by narrative correlation as a transparent, explainable similarity
    measure. It is intentionally simple: an analyst can reproduce it by hand.
    """
    first = token_set(left)
    second = token_set(right)

    if not first or not second:
        return 0.0

    intersection = len(first & second)

    if intersection == 0:
        return 0.0

    return intersection / len(first | second)


def shannon_entropy(values: Iterable[Any]) -> float:
    """
    Return the Shannon entropy (in bits) of a categorical sequence.

    Entropy features describe how evenly an account spreads its activity
    across channels, hours, or counterparties.
    """
    counts: dict[str, int] = {}
    total = 0

    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
        total += 1

    if total <= 1 or len(counts) <= 1:
        return 0.0

    import math

    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy
