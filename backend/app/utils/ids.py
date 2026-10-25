"""
MULEGUARD identifier utilities.

Primary keys are `String(64)` across the schema. Runtime records get UUID4
values; synthetic seed data gets deterministic identifiers so that a demo reset
reproduces the same dataset.

Design rules:

- `new_id` is random (UUID4) and is what API-created records use.
- `deterministic_id` is derived from a namespace plus parts, so re-running the
  generator with the same seed produces the same IDs. That is what makes
  `make demo-reset` reproducible.
- Prefixed IDs (`acc_`, `txn_`, ...) make a stray identifier in a log or an
  evidence reference self-describing.
- `is_safe_identifier` is a validation guard for anything that arrives from a
  request path or an import payload.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Final, Optional

__all__ = [
    "ID_MAX_LENGTH",
    "PREFIXES",
    "coerce_id",
    "deterministic_id",
    "dedup_key",
    "evidence_ref",
    "is_safe_identifier",
    "is_uuid",
    "new_id",
    "parse_evidence_ref",
    "prefixed_id",
    "strip_prefix",
]

ID_MAX_LENGTH: Final[int] = 64

# Conventional prefixes per record kind.
PREFIXES: Final[dict[str, str]] = {
    "account": "acc",
    "transaction": "txn",
    "complaint": "cmp",
    "entity": "ent",
    "entity_link": "lnk",
    "alert": "alt",
    "case": "cas",
    "evidence": "evd",
    "assessment": "asm",
    "feature_snapshot": "fts",
    "analysis_run": "run",
    "graph_run": "grp",
    "correlation": "cor",
    "rule_hit": "rhl",
    "indicator": "ind",
    "model_version": "mdl",
    "audit": "aud",
    "note": "nte",
    "user": "usr",
}

# Conservative: letters, digits, dot, dash, underscore, colon. No whitespace,
# no quotes, no SQL metacharacters, no path separators.
_SAFE_ID: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")

_UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_NAMESPACE: Final[uuid.UUID] = uuid.UUID("6f9b1c2e-4a73-4c21-9f0b-2d6a51e3c7d4")


def new_id() -> str:
    """
    Return a fresh random identifier for a runtime-created record.
    """
    return str(uuid.uuid4())


def prefixed_id(kind: str, *, value: Optional[str] = None) -> str:
    """
    Return a prefixed identifier such as `acc_1f2e3d...`.
    """
    prefix = PREFIXES.get(str(kind).strip().lower(), str(kind).strip().lower()[:6] or "rec")
    suffix = (value or uuid.uuid4().hex)[: ID_MAX_LENGTH - len(prefix) - 1]
    return f"{prefix}_{suffix}"


def deterministic_id(namespace: str, *parts: Any, prefix: Optional[str] = None) -> str:
    """
    Derive a stable identifier from a namespace and parts.

    The same inputs always produce the same identifier, which is what makes the
    synthetic generator reproducible across runs and machines.
    """
    seed = "|".join([str(namespace), *(str(part) for part in parts)])
    derived = uuid.uuid5(_NAMESPACE, seed)

    if prefix:
        return prefixed_id(prefix, value=derived.hex)

    return str(derived)


def is_uuid(value: Any) -> bool:
    """
    Return True when a value is a canonical UUID string.
    """
    return isinstance(value, str) and _UUID_RE.match(value.strip()) is not None


def is_safe_identifier(value: Any, *, max_length: int = ID_MAX_LENGTH) -> bool:
    """
    Return True when a value is safe to use as a record identifier.

    Rejects whitespace, quoting, path separators, and anything longer than the
    column width. Evidence references and path parameters are validated with
    this before they are stored or queried.
    """
    if not isinstance(value, str):
        return False

    text = value.strip()

    if not text or len(text) > max_length:
        return False

    return _SAFE_ID.match(text) is not None


def coerce_id(value: Any, *, max_length: int = ID_MAX_LENGTH) -> Optional[str]:
    """
    Return a cleaned identifier, or None when it is not usable.
    """
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    if not is_safe_identifier(text, max_length=max_length):
        return None

    return text


def strip_prefix(value: Any) -> str:
    """
    Remove a known `kind_` prefix from an identifier.
    """
    text = str(value or "").strip()

    if "_" not in text:
        return text

    head, _, tail = text.partition("_")

    if head in PREFIXES.values() and tail:
        return tail

    return text


def evidence_ref(evidence_type: Any, evidence_id: Any) -> str:
    """
    Build a canonical `TYPE:id` evidence reference.

    Rule hits, indicators, and correlations store evidence references in this
    form so a reader can resolve them without extra context.
    """
    kind = str(getattr(evidence_type, "value", evidence_type) or "").strip().upper()
    identifier = str(evidence_id or "").strip()

    if not kind or not identifier:
        return ""

    return f"{kind}:{identifier}"


def parse_evidence_ref(value: Any) -> tuple[Optional[str], Optional[str]]:
    """
    Split a `TYPE:id` evidence reference into its parts.

    Returns `(None, None)` when the reference is malformed or the identifier
    fails `is_safe_identifier`, so a caller cannot be tricked into querying an
    attacker-supplied string.
    """
    text = str(value or "").strip()

    if ":" not in text:
        return None, None

    kind, _, identifier = text.partition(":")
    kind = kind.strip().upper()
    identifier = identifier.strip()

    if not kind or not identifier:
        return None, None

    if not is_safe_identifier(identifier, max_length=128):
        return None, None

    return kind, identifier


def dedup_key(*parts: Any, max_length: int = 255) -> str:
    """
    Build an alert deduplication key from its parts.

    Matches the `String(255)` unique `Alert.dedup_key` column. Parts are joined
    with `|`; blanks become `-` so positional meaning is preserved.
    """
    rendered = "|".join(str(part).strip() if part is not None and str(part).strip() else "-" for part in parts)
    return rendered[:max_length]
