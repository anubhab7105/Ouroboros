"""
MULEGUARD backend ingestion deduplication.

This module provides the canonical deduplication layer for synthetic MULEGUARD
ingestion workflows.

Primary responsibilities:

- detect exact, natural-key, and optional near-duplicate ingestion records
  within bounded batches and across a bounded process-local sliding window;
- produce deterministic, salted, one-way fingerprints so raw identifiers,
  complaint narratives, secrets, tokens, passwords, database URLs, model
  artifact paths, ground-truth labels, scenario IDs, and fraud-ring IDs are not
  stored in duplicate indexes;
- provide bounded, thread-safe, in-memory duplicate indexes suitable for local
  prototype, demo, test, and CI use;
- provide optional MinHash/LSH near-duplicate detection for synthetic complaint
  narratives without retaining raw narrative text;
- return safe, structured duplicate groups, issues, counts, and bounded index
  samples without exposing sensitive record content;
- remain import-safe, dependency-light, and usable by loaders, normalizers,
  validators, seeders, services, tests, and offline fixtures.

This module detects duplicates only. It does not persist data, call external
systems, authenticate users, authorize actions, train models, generate reports,
or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be ingested.
- Ground-truth labels, injected scenario IDs, and fraud-ring IDs must not be
  accepted, persisted, returned, logged, or exported.
- Raw complaint narratives are never stored, logged, or returned.
- Near-duplicate narrative detection is optional and disabled by default. When
  enabled, only transient token shingles and one-way hashed MinHash signatures
  are used.
- Duplicate indexes store salted HMAC fingerprints and bounded MinHash
  signatures only.
- Near-duplicate matches are operational ingestion hygiene signals only. They
  are not investigative correlations, not proof of duplication, and not proof of
  wrongdoing.
- Duplicate handling affects ingestion record processing only. It never freezes,
  blocks, blacklists, closes, restricts, or otherwise takes adverse action
  against accounts or customers.
- All indexes are bounded by hard caps and sliding-window pruning.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not write to the database.
- This module does not call real banking systems.
- This module does not authenticate or authorize users.
- This module does not generate synthetic data.
- This module does not perform final business-rule validation; use
  `app.ingestion.normalizers` and `app.ingestion.validators` for that.
- This module does not train or evaluate models.
- This module is not a distributed deduplication service. Production
  multi-instance deployments should replace the local memory store with a
  reviewed shared store such as Redis or a database-backed uniqueness control.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, and case dispositions are investigative leads or human workflow
artefacts only. They are not proof of wrongdoing and must not trigger automatic
adverse customer action.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
import threading
import time
import unicodedata
from collections import OrderedDict, defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from functools import lru_cache
from typing import Any, Final, Optional, Protocol, runtime_checkable

logger = logging.getLogger("muleguard.backend.ingestion.dedupe")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

DEDUPE_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_MAX_ENTRIES: Final[int] = 50_000
_HARD_MAX_ENTRIES: Final[int] = 1_000_000

_DEFAULT_MAX_NEAR_ENTRIES: Final[int] = 10_000
_HARD_MAX_NEAR_ENTRIES: Final[int] = 200_000

_DEFAULT_MAX_RECORDS_PER_BATCH: Final[int] = 10_000
_HARD_MAX_RECORDS_PER_BATCH: Final[int] = 100_000

_DEFAULT_MAX_CANDIDATES_PER_RECORD: Final[int] = 200
_HARD_MAX_CANDIDATES_PER_RECORD: Final[int] = 5_000

_DEFAULT_MAX_DUPLICATE_GROUP_SIZE: Final[int] = 1_000
_HARD_MAX_DUPLICATE_GROUP_SIZE: Final[int] = 10_000

_DEFAULT_MAX_INDICES_RETURNED: Final[int] = 1_000
_HARD_MAX_INDICES_RETURNED: Final[int] = 10_000

_DEFAULT_MAX_ISSUES_RETURNED: Final[int] = 100
_HARD_MAX_ISSUES_RETURNED: Final[int] = 500

_DEFAULT_MAX_GROUPS_RETURNED: Final[int] = 100
_HARD_MAX_GROUPS_RETURNED: Final[int] = 1_000

_DEFAULT_WINDOW_SECONDS: Final[float] = 3_600.0
_DEFAULT_PRUNE_INTERVAL_SECONDS: Final[float] = 60.0

_DEFAULT_NEAR_NUM_PERM: Final[int] = 64
_HARD_MAX_NEAR_NUM_PERM: Final[int] = 128
_DEFAULT_NEAR_BANDS: Final[int] = 8
_HARD_MAX_NEAR_BANDS: Final[int] = 32
_DEFAULT_NEAR_THRESHOLD: Final[float] = 0.75
_DEFAULT_NEAR_MAX_SHINGLES: Final[int] = 512
_HARD_MAX_NEAR_SHINGLES: Final[int] = 4_096
_DEFAULT_NEAR_MIN_TOKENS: Final[int] = 8
_HARD_MAX_NEAR_TOKENS: Final[int] = 5_000

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_NARRATIVE_TOKENS: Final[int] = 5_000
_SHINGLE_SIZE: Final[int] = 3

_MASK_64: Final[int] = (1 << 64) - 1

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9]{3,}")

_DEFAULT_SALT: Final[str] = "muleguard-ingestion-dedupe-default-salt"

_SUPPORTED_ENTITY_TYPES: Final[tuple[str, ...]] = (
    "accounts",
    "transactions",
    "complaints",
    "entities",
    "entity_links",
)

_NATURAL_KEY_SPECS: Final[Mapping[str, tuple[tuple[str, ...], ...]]] = {
    "accounts": (
        ("id",),
    ),
    "transactions": (
        ("id",),
        ("reference",),
        (
            "sender_account_id",
            "receiver_account_id",
            "occurred_at",
            "amount",
            "currency",
            "channel",
        ),
    ),
    "complaints": (
        ("id",),
        ("reference",),
        (
            "reported_at",
            "category",
            "victim_account_id",
            "suspected_account_id",
            "amount",
            "currency",
            "transaction_reference",
        ),
    ),
    "entities": (
        ("id",),
        ("entity_type", "identifier_hash"),
    ),
    "entity_links": (
        ("id",),
        ("account_id", "entity_id", "valid_from", "source"),
    ),
}

# Business keys are intentionally conservative. They are disabled by default
# because they can create operational false positives in synthetic workflows.
_BUSINESS_KEY_SPECS: Final[Mapping[str, tuple[tuple[str, ...], ...]]] = {
    "transactions": (
        (
            "sender_account_id",
            "receiver_account_id",
            "occurred_at",
            "amount",
            "currency",
        ),
    ),
    "complaints": (
        (
            "reported_at",
            "category",
            "victim_account_id",
            "suspected_account_id",
            "amount",
            "currency",
        ),
    ),
}

_DUPE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype ingestion deduplication only. Do not use with real customer data.",
    "Duplicate detection is operational ingestion hygiene only.",
    "Duplicate detection must not trigger automatic adverse customer action.",
    "Raw complaint narratives are never stored, logged, or returned.",
    "Near-duplicate narrative detection is optional and disabled by default.",
    "Near-duplicate matches are not investigative correlations and are not proof of duplication.",
    "Duplicate indexes store salted one-way fingerprints and bounded MinHash signatures only.",
    "All indexes are bounded by hard caps and sliding-window pruning.",
    "This module does not persist data or call external systems.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class DedupeScope(str, Enum):
    """
    Duplicate detection scope.

    Lower priority values are checked first.
    """

    EXACT_ID = "exact_id"
    NATURAL = "natural"
    BUSINESS = "business"
    NEAR = "near"

    @property
    def priority(self) -> int:
        """
        Return deterministic checking priority.
        """
        return {
            DedupeScope.EXACT_ID: 0,
            DedupeScope.NATURAL: 1,
            DedupeScope.BUSINESS: 2,
            DedupeScope.NEAR: 3,
        }[self]


class DedupeAction(str, Enum):
    """
    Action taken when a duplicate is detected.

    This action affects ingestion record handling only. It never takes adverse
    action against accounts or customers.
    """

    SKIP = "skip"
    REJECT = "reject"
    FLAG = "flag"


class DedupeSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _setting(settings: Any, name: str, default: Any = None) -> Any:
    """
    Read a setting from either a typed settings object or mapping.
    """
    if settings is None:
        return default

    if isinstance(settings, Mapping):
        return settings.get(name, default)

    return getattr(settings, name, default)


def _as_bool(value: object, default: bool = False) -> bool:
    """
    Convert common configuration representations to boolean.
    """
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, int):
        return bool(value)

    text_value = str(value).strip().lower()

    if text_value in _TRUE_VALUES:
        return True

    if text_value in _FALSE_VALUES:
        return False

    return default


def _as_int(value: object, default: int) -> int:
    """
    Safely convert a setting to int.
    """
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float) -> float:
    """
    Safely convert a setting to float.
    """
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default

    if math.isnan(result) or math.isinf(result):
        return default

    return result


def _clamp_int(value: object, minimum: int, maximum: int, default: int) -> int:
    """
    Clamp an integer-like value into bounds.
    """
    parsed = _as_int(value, default)
    return max(minimum, min(parsed, maximum))


def _clamp_float(value: object, minimum: float, maximum: float, default: float) -> float:
    """
    Clamp a float-like value into bounds.
    """
    parsed = _as_float(value, default)
    return max(minimum, min(parsed, maximum))


def _normalize_unicode(value: Any) -> str:
    """
    Normalize Unicode text deterministically.

    Enum members are unwrapped to their value first: for a `str`-mixin enum
    `str(Member)` is "ClassName.MEMBER", not "member", so an enum reaching
    here would normalise to a token nothing recognises.
    """
    if isinstance(value, Enum):
        value = value.value

    return unicodedata.normalize("NFKC", str(value if value is not None else ""))


def _clean_text(value: Any, limit: int = _MAX_TEXT_LENGTH) -> str:
    """
    Return a safe single-line text value.
    """
    text = _normalize_unicode(value)
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if limit <= 0:
        return ""

    if len(text) > limit:
        return text[:limit]

    return text


def _canonical_field_name(key: Any) -> str:
    """
    Convert a field name to a conservative canonical snake_case form.
    """
    text = _normalize_unicode(key).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = _SEPARATOR_RE.sub("_", text)
    text = _MULTI_UNDERSCORE_RE.sub("_", text)
    return text.strip("_").lower()


def _normalize_entity_type(value: Any) -> str:
    """
    Normalize an ingestion entity type.
    """
    text = _canonical_field_name(value)

    aliases = {
        "account": "accounts",
        "txn": "transactions",
        "transaction": "transactions",
        "complaint": "complaints",
        "entity": "entities",
        "entity_link": "entity_links",
        "account_entity_link": "entity_links",
        "account_entity_links": "entity_links",
    }

    return aliases.get(text, text)


def _normalize_action(value: Any, default: DedupeAction = DedupeAction.SKIP) -> DedupeAction:
    """
    Normalize a duplicate action value.
    """
    if isinstance(value, DedupeAction):
        return value

    text = _canonical_field_name(value)

    aliases = {
        "ignore": DedupeAction.SKIP,
        "drop": DedupeAction.SKIP,
        "skip": DedupeAction.SKIP,
        "fail": DedupeAction.REJECT,
        "error": DedupeAction.REJECT,
        "reject": DedupeAction.REJECT,
        "deny": DedupeAction.REJECT,
        "review": DedupeAction.FLAG,
        "flag": DedupeAction.FLAG,
        "mark": DedupeAction.FLAG,
    }

    return aliases.get(text, default)


def _ensure_salt(salt: Any) -> str:
    """
    Ensure the dedupe salt is non-empty and sufficiently long.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _now_utc() -> datetime:
    """
    Return timezone-aware UTC current time.
    """
    return datetime.now(timezone.utc)


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    """
    Normalize datetimes to timezone-aware UTC.

    Naive datetimes are assumed to already be UTC.
    """
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _parse_datetime(value: Any) -> Optional[datetime]:
    """
    Parse a datetime-like value into timezone-aware UTC.
    """
    if isinstance(value, datetime):
        return _ensure_utc(value)

    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return None

        if not math.isfinite(numeric):
            return None

        if abs(numeric) > 1_000_000_000_000:
            numeric = numeric / 1000.0

        try:
            return datetime.fromtimestamp(numeric, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    text = _normalize_unicode(value).strip()

    if not text:
        return None

    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(text)
        return _ensure_utc(parsed)
    except Exception:
        pass

    try:
        numeric = float(text)
    except (TypeError, ValueError):
        return None

    if not math.isfinite(numeric):
        return None

    if abs(numeric) > 1_000_000_000_000:
        numeric = numeric / 1000.0

    try:
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _decimal_to_canonical(value: Decimal) -> str:
    """
    Return a stable canonical decimal string.
    """
    if not value.is_finite():
        return "non_finite"

    text = format(value, "f")

    if "." in text:
        text = text.rstrip("0").rstrip(".")

    return text or "0"


def _parse_decimal(value: Any) -> Optional[Decimal]:
    """
    Parse a decimal-like value.
    """
    if isinstance(value, Decimal):
        return value if value.is_finite() else None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return Decimal(value)

    if isinstance(value, float):
        if not math.isfinite(value):
            return None

        try:
            return Decimal(str(value))
        except (InvalidOperation, ValueError):
            return None

    text = _normalize_unicode(value).strip().replace(",", "")

    if not text:
        return None

    try:
        parsed = Decimal(text)
    except (InvalidOperation, ValueError, TypeError):
        return None

    return parsed if parsed.is_finite() else None


def _canonical_scalar(value: Any) -> str:
    """
    Convert a field value into a stable canonical string for hashing.

    This never returns raw sensitive values to callers. It is used only as
    input to one-way HMAC hashing.
    """
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, int):
        return str(value)

    if isinstance(value, float):
        if not math.isfinite(value):
            return "non_finite"

        return _decimal_to_canonical(Decimal(str(value)))

    if isinstance(value, Decimal):
        return _decimal_to_canonical(value)

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else "invalid_datetime"

    if isinstance(value, str):
        return _clean_text(value, _MAX_TEXT_LENGTH)

    if isinstance(value, Enum):
        return _canonical_scalar(value.value)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()

    if isinstance(value, Mapping):
        try:
            canonical = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            )
        except Exception:
            canonical = str(value)

        return _clean_text(canonical, _MAX_TEXT_LENGTH)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        try:
            canonical = json.dumps(
                list(value),
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            )
        except Exception:
            canonical = str(value)

        return _clean_text(canonical, _MAX_TEXT_LENGTH)

    return _clean_text(str(value), _MAX_TEXT_LENGTH)


def _is_missing(record: Mapping[str, Any], field_name: str) -> bool:
    """
    Return True when a field is absent, None, or blank text.
    """
    if field_name not in record:
        return True

    value = record[field_name]

    if value is None:
        return True

    if isinstance(value, str) and not value.strip():
        return True

    return False


def _hash_parts(parts: Sequence[str], salt: str, domain: str) -> str:
    """
    Return a domain-separated HMAC-SHA256 hex digest.
    """
    material = "\x00".join(str(part) for part in parts)
    key = salt.encode("utf-8", errors="replace")
    message = f"{domain}\x00{material}".encode("utf-8", errors="replace")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _composite_hash(
    entity_type: str,
    scope: DedupeScope,
    fields: Sequence[str],
    record: Mapping[str, Any],
    salt: str,
) -> Optional[str]:
    """
    Build a salted composite fingerprint hash.

    Returns None when any required field is missing.
    """
    parts: list[str] = [entity_type, scope.value]

    for field_name in fields:
        if _is_missing(record, field_name):
            return None

        parts.append(_canonical_scalar(record[field_name]))

    return _hash_parts(parts, salt, f"muleguard.dedupe.{scope.value}")


def _mix64(value: int, seed: int) -> int:
    """
    Deterministic 64-bit mixer used by MinHash.
    """
    x = (value ^ seed) & _MASK_64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & _MASK_64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & _MASK_64
    x = x ^ (x >> 31)
    return x & _MASK_64


@lru_cache(maxsize=8)
def _minhash_seeds(num_perm: int) -> tuple[int, ...]:
    """
    Return deterministic MinHash seed constants.
    """
    return tuple(_mix64(0x123456789ABCDEF0, index + 1) for index in range(num_perm))


def _jaccard_estimate(left: Sequence[int], right: Sequence[int]) -> float:
    """
    Return MinHash Jaccard estimate between two signatures.
    """
    if not left or not right or len(left) != len(right):
        return 0.0

    matches = sum(1 for a, b in zip(left, right) if a == b)
    return float(matches) / float(len(left))


def _safe_detail_value(value: Any, depth: int = 0) -> Any:
    """
    Convert arbitrary detail values into bounded, safe representations.
    """
    if depth > 4:
        return "[truncated-depth]"

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, str):
        return _clean_text(value, 300)

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, datetime):
        return _ensure_utc(value).isoformat() if _ensure_utc(value) else None

    if isinstance(value, Enum):
        return _safe_detail_value(value.value, depth + 1)

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:20]:
            key = _clean_text(raw_key, 100)

            if not key:
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:20]]

    return f"<{type(value).__name__}>"


def _safe_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return safe issue details.

    Details must never contain raw narratives, secrets, tokens, passwords,
    database URLs, model artifact paths, or sensitive identifiers.
    """
    if not details:
        return {}

    sanitized = _safe_detail_value(details)

    if isinstance(sanitized, dict):
        return sanitized

    if sanitized is None:
        return {}

    return {"value": sanitized}


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DedupeOptions:
    """
    Bounded ingestion deduplication policy.

    Hard caps prevent client-controlled or configuration-controlled unbounded
    duplicate indexes.
    """

    enabled: bool = True
    action: DedupeAction = DedupeAction.SKIP

    include_exact_id: bool = True
    include_natural_keys: bool = True
    include_business_keys: bool = False

    include_near_duplicates: bool = False
    near_threshold: float = _DEFAULT_NEAR_THRESHOLD
    near_num_perm: int = _DEFAULT_NEAR_NUM_PERM
    near_bands: int = _DEFAULT_NEAR_BANDS
    near_max_shingles: int = _DEFAULT_NEAR_MAX_SHINGLES
    near_min_tokens: int = _DEFAULT_NEAR_MIN_TOKENS

    max_entries: int = _DEFAULT_MAX_ENTRIES
    max_near_entries: int = _DEFAULT_MAX_NEAR_ENTRIES
    max_records_per_batch: int = _DEFAULT_MAX_RECORDS_PER_BATCH
    max_candidates_per_record: int = _DEFAULT_MAX_CANDIDATES_PER_RECORD
    max_duplicate_group_size: int = _DEFAULT_MAX_DUPLICATE_GROUP_SIZE
    max_indices_returned: int = _DEFAULT_MAX_INDICES_RETURNED
    max_issues_returned: int = _DEFAULT_MAX_ISSUES_RETURNED
    max_groups_returned: int = _DEFAULT_MAX_GROUPS_RETURNED

    window_seconds: float = _DEFAULT_WINDOW_SECONDS
    prune_interval_seconds: float = _DEFAULT_PRUNE_INTERVAL_SECONDS

    treat_missing_as_unique: bool = True
    salt: str = ""

    def __post_init__(self) -> None:
        """
        Normalize and clamp option values.
        """
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "action", _normalize_action(self.action))

        object.__setattr__(
            self,
            "include_exact_id",
            _as_bool(self.include_exact_id, True),
        )
        object.__setattr__(
            self,
            "include_natural_keys",
            _as_bool(self.include_natural_keys, True),
        )
        object.__setattr__(
            self,
            "include_business_keys",
            _as_bool(self.include_business_keys, False),
        )
        object.__setattr__(
            self,
            "include_near_duplicates",
            _as_bool(self.include_near_duplicates, False),
        )

        bands = _clamp_int(
            self.near_bands,
            1,
            _HARD_MAX_NEAR_BANDS,
            _DEFAULT_NEAR_BANDS,
        )

        num_perm = _clamp_int(
            self.near_num_perm,
            bands,
            _HARD_MAX_NEAR_NUM_PERM,
            _DEFAULT_NEAR_NUM_PERM,
        )

        num_perm = (num_perm // bands) * bands

        if num_perm < bands:
            num_perm = bands

        object.__setattr__(self, "near_bands", bands)
        object.__setattr__(self, "near_num_perm", num_perm)

        object.__setattr__(
            self,
            "near_threshold",
            _clamp_float(
                self.near_threshold,
                0.01,
                0.999,
                _DEFAULT_NEAR_THRESHOLD,
            ),
        )

        object.__setattr__(
            self,
            "near_max_shingles",
            _clamp_int(
                self.near_max_shingles,
                1,
                _HARD_MAX_NEAR_SHINGLES,
                _DEFAULT_NEAR_MAX_SHINGLES,
            ),
        )

        object.__setattr__(
            self,
            "near_min_tokens",
            _clamp_int(
                self.near_min_tokens,
                1,
                _HARD_MAX_NEAR_TOKENS,
                _DEFAULT_NEAR_MIN_TOKENS,
            ),
        )

        object.__setattr__(
            self,
            "max_entries",
            _clamp_int(
                self.max_entries,
                1,
                _HARD_MAX_ENTRIES,
                _DEFAULT_MAX_ENTRIES,
            ),
        )

        object.__setattr__(
            self,
            "max_near_entries",
            _clamp_int(
                self.max_near_entries,
                1,
                _HARD_MAX_NEAR_ENTRIES,
                _DEFAULT_MAX_NEAR_ENTRIES,
            ),
        )

        object.__setattr__(
            self,
            "max_records_per_batch",
            _clamp_int(
                self.max_records_per_batch,
                1,
                _HARD_MAX_RECORDS_PER_BATCH,
                _DEFAULT_MAX_RECORDS_PER_BATCH,
            ),
        )

        object.__setattr__(
            self,
            "max_candidates_per_record",
            _clamp_int(
                self.max_candidates_per_record,
                1,
                _HARD_MAX_CANDIDATES_PER_RECORD,
                _DEFAULT_MAX_CANDIDATES_PER_RECORD,
            ),
        )

        object.__setattr__(
            self,
            "max_duplicate_group_size",
            _clamp_int(
                self.max_duplicate_group_size,
                1,
                _HARD_MAX_DUPLICATE_GROUP_SIZE,
                _DEFAULT_MAX_DUPLICATE_GROUP_SIZE,
            ),
        )

        object.__setattr__(
            self,
            "max_indices_returned",
            _clamp_int(
                self.max_indices_returned,
                1,
                _HARD_MAX_INDICES_RETURNED,
                _DEFAULT_MAX_INDICES_RETURNED,
            ),
        )

        object.__setattr__(
            self,
            "max_issues_returned",
            _clamp_int(
                self.max_issues_returned,
                1,
                _HARD_MAX_ISSUES_RETURNED,
                _DEFAULT_MAX_ISSUES_RETURNED,
            ),
        )

        object.__setattr__(
            self,
            "max_groups_returned",
            _clamp_int(
                self.max_groups_returned,
                1,
                _HARD_MAX_GROUPS_RETURNED,
                _DEFAULT_MAX_GROUPS_RETURNED,
            ),
        )

        object.__setattr__(
            self,
            "window_seconds",
            max(0.0, _as_float(self.window_seconds, _DEFAULT_WINDOW_SECONDS)),
        )

        object.__setattr__(
            self,
            "prune_interval_seconds",
            max(1.0, _as_float(self.prune_interval_seconds, _DEFAULT_PRUNE_INTERVAL_SECONDS)),
        )

        object.__setattr__(
            self,
            "treat_missing_as_unique",
            _as_bool(self.treat_missing_as_unique, True),
        )

        object.__setattr__(self, "salt", _ensure_salt(self.salt))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "DedupeOptions":
        """
        Build dedupe options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "DEDUPE_SALT", None)
            or _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
            or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
            or _setting(settings, "BACKEND_SECRET_KEY", None)
            or ""
        )

        return cls(
            enabled=_as_bool(_setting(settings, "DEDUPE_ENABLED", True), True),
            action=_normalize_action(_setting(settings, "DEDUPE_ACTION", DedupeAction.SKIP.value)),
            include_exact_id=_as_bool(_setting(settings, "DEDUPE_INCLUDE_EXACT_ID", True), True),
            include_natural_keys=_as_bool(
                _setting(settings, "DEDUPE_INCLUDE_NATURAL_KEYS", True),
                True,
            ),
            include_business_keys=_as_bool(
                _setting(settings, "DEDUPE_INCLUDE_BUSINESS_KEYS", False),
                False,
            ),
            include_near_duplicates=_as_bool(
                _setting(settings, "DEDUPE_INCLUDE_NEAR_DUPLICATES", False),
                False,
            ),
            near_threshold=_as_float(
                _setting(settings, "DEDUPE_NEAR_THRESHOLD", _DEFAULT_NEAR_THRESHOLD),
                _DEFAULT_NEAR_THRESHOLD,
            ),
            near_num_perm=_as_int(
                _setting(settings, "DEDUPE_NEAR_NUM_PERM", _DEFAULT_NEAR_NUM_PERM),
                _DEFAULT_NEAR_NUM_PERM,
            ),
            near_bands=_as_int(
                _setting(settings, "DEDUPE_NEAR_BANDS", _DEFAULT_NEAR_BANDS),
                _DEFAULT_NEAR_BANDS,
            ),
            near_max_shingles=_as_int(
                _setting(settings, "DEDUPE_NEAR_MAX_SHINGLES", _DEFAULT_NEAR_MAX_SHINGLES),
                _DEFAULT_NEAR_MAX_SHINGLES,
            ),
            near_min_tokens=_as_int(
                _setting(settings, "DEDUPE_NEAR_MIN_TOKENS", _DEFAULT_NEAR_MIN_TOKENS),
                _DEFAULT_NEAR_MIN_TOKENS,
            ),
            max_entries=_as_int(
                _setting(settings, "DEDUPE_MAX_ENTRIES", _DEFAULT_MAX_ENTRIES),
                _DEFAULT_MAX_ENTRIES,
            ),
            max_near_entries=_as_int(
                _setting(settings, "DEDUPE_MAX_NEAR_ENTRIES", _DEFAULT_MAX_NEAR_ENTRIES),
                _DEFAULT_MAX_NEAR_ENTRIES,
            ),
            max_records_per_batch=_as_int(
                _setting(settings, "DEDUPE_MAX_RECORDS_PER_BATCH", _DEFAULT_MAX_RECORDS_PER_BATCH),
                _DEFAULT_MAX_RECORDS_PER_BATCH,
            ),
            max_candidates_per_record=_as_int(
                _setting(
                    settings,
                    "DEDUPE_MAX_CANDIDATES_PER_RECORD",
                    _DEFAULT_MAX_CANDIDATES_PER_RECORD,
                ),
                _DEFAULT_MAX_CANDIDATES_PER_RECORD,
            ),
            max_duplicate_group_size=_as_int(
                _setting(
                    settings,
                    "DEDUPE_MAX_DUPLICATE_GROUP_SIZE",
                    _DEFAULT_MAX_DUPLICATE_GROUP_SIZE,
                ),
                _DEFAULT_MAX_DUPLICATE_GROUP_SIZE,
            ),
            max_indices_returned=_as_int(
                _setting(settings, "DEDUPE_MAX_INDICES_RETURNED", _DEFAULT_MAX_INDICES_RETURNED),
                _DEFAULT_MAX_INDICES_RETURNED,
            ),
            max_issues_returned=_as_int(
                _setting(settings, "DEDUPE_MAX_ISSUES_RETURNED", _DEFAULT_MAX_ISSUES_RETURNED),
                _DEFAULT_MAX_ISSUES_RETURNED,
            ),
            max_groups_returned=_as_int(
                _setting(settings, "DEDUPE_MAX_GROUPS_RETURNED", _DEFAULT_MAX_GROUPS_RETURNED),
                _DEFAULT_MAX_GROUPS_RETURNED,
            ),
            window_seconds=_as_float(
                _setting(settings, "DEDUPE_WINDOW_SECONDS", _DEFAULT_WINDOW_SECONDS),
                _DEFAULT_WINDOW_SECONDS,
            ),
            prune_interval_seconds=_as_float(
                _setting(settings, "DEDUPE_PRUNE_INTERVAL_SECONDS", _DEFAULT_PRUNE_INTERVAL_SECONDS),
                _DEFAULT_PRUNE_INTERVAL_SECONDS,
            ),
            treat_missing_as_unique=_as_bool(
                _setting(settings, "DEDUPE_TREAT_MISSING_AS_UNIQUE", True),
                True,
            ),
            salt=salt,
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable summary of dedupe options.

        The salt is never included.
        """
        return {
            "enabled": self.enabled,
            "action": self.action.value,
            "include_exact_id": self.include_exact_id,
            "include_natural_keys": self.include_natural_keys,
            "include_business_keys": self.include_business_keys,
            "include_near_duplicates": self.include_near_duplicates,
            "near_threshold": round(self.near_threshold, 4),
            "near_num_perm": self.near_num_perm,
            "near_bands": self.near_bands,
            "near_max_shingles": self.near_max_shingles,
            "near_min_tokens": self.near_min_tokens,
            "max_entries": self.max_entries,
            "max_near_entries": self.max_near_entries,
            "max_records_per_batch": self.max_records_per_batch,
            "max_candidates_per_record": self.max_candidates_per_record,
            "max_duplicate_group_size": self.max_duplicate_group_size,
            "max_indices_returned": self.max_indices_returned,
            "max_issues_returned": self.max_issues_returned,
            "max_groups_returned": self.max_groups_returned,
            "window_seconds": round(self.window_seconds, 3),
            "prune_interval_seconds": round(self.prune_interval_seconds, 3),
            "treat_missing_as_unique": self.treat_missing_as_unique,
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
        }


# -----------------------------------------------------------------------------
# Fingerprints, matches, signatures
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """
    One safe duplicate fingerprint for a record.
    """

    scope: DedupeScope
    key: str
    hash: str
    fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DedupeMatch:
    """
    Safe duplicate match metadata.

    This never contains raw record values.
    """

    scope: DedupeScope
    representative_uid: int
    representative_batch_id: str
    representative_index: int
    similarity: Optional[float] = None
    key_hash: Optional[str] = None


@dataclass(frozen=True, slots=True)
class NearSignature:
    """
    Bounded MinHash signature for optional near-duplicate detection.

    This contains one-way hashed MinHash values only. It never contains raw
    narrative text.
    """

    values: tuple[int, ...]
    band_keys: tuple[str, ...]
    num_perm: int
    bands: int


# -----------------------------------------------------------------------------
# Internal store models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _Representative:
    """
    Internal representative record for a duplicate group.
    """

    uid: int
    batch_id: str
    index: int
    entity_type: str
    keys: tuple[str, ...]
    created_at: float
    last_seen: float
    hit_count: int = 1


@dataclass(slots=True)
class _NearEntry:
    """
    Internal near-duplicate index entry.
    """

    uid: int
    batch_id: str
    index: int
    entity_type: str
    signature: tuple[int, ...]
    band_keys: tuple[str, ...]
    created_at: float
    last_seen: float


# -----------------------------------------------------------------------------
# Store protocol
# -----------------------------------------------------------------------------


@runtime_checkable
class DedupeStore(Protocol):
    """
    Protocol for duplicate stores.

    A production deployment may implement this protocol with Redis, a database
    uniqueness control, or another shared store. The bundled implementation is
    process-local.
    """

    def find_duplicate(self, keys: Sequence[str]) -> Optional[DedupeMatch]:
        """
        Return a duplicate match for one or more fingerprint keys.
        """
        raise NotImplementedError

    def add(
        self,
        keys: Sequence[str],
        batch_id: str,
        index: int,
        entity_type: str,
    ) -> int:
        """
        Add a representative and return its stable UID.
        """
        raise NotImplementedError

    def add_near(self, uid: int, signature: NearSignature) -> None:
        """
        Add a near-duplicate signature for a representative UID.
        """
        raise NotImplementedError

    def find_near(
        self,
        signature: NearSignature,
        threshold: float,
        max_candidates: int,
    ) -> Optional[DedupeMatch]:
        """
        Return a near-duplicate match above threshold.
        """
        raise NotImplementedError

    def touch(self, uid: int) -> None:
        """
        Mark a representative as recently seen.
        """
        raise NotImplementedError

    def clear(self) -> None:
        """
        Clear all stored indexes.
        """
        raise NotImplementedError

    def stats(self) -> dict[str, Any]:
        """
        Return safe store statistics.
        """
        raise NotImplementedError


# -----------------------------------------------------------------------------
# Memory store
# -----------------------------------------------------------------------------


class MemoryDedupeStore:
    """
    Bounded, thread-safe, process-local duplicate store.

    This store is intended for local prototype, demo, test, and CI use. It is
    not durable and is not shared across processes or hosts.
    """

    def __init__(self, options: DedupeOptions | None = None) -> None:
        self.options = options or DedupeOptions()

        self._lock = threading.RLock()
        self._reprs: OrderedDict[int, _Representative] = OrderedDict()
        self._key_index: dict[str, int] = {}

        self._near_entries: OrderedDict[int, _NearEntry] = OrderedDict()
        self._near_buckets: dict[str, deque[int]] = defaultdict(deque)
        self._near_bucket_refs = 0

        self._uid_counter = 0
        self._last_prune = time.monotonic()

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------

    def _now(self) -> float:
        return time.monotonic()

    def _is_expired(self, created_at: float, now: float) -> bool:
        window = float(self.options.window_seconds)
        return window > 0 and (now - created_at) > window

    def _remove_repr(self, uid: int) -> None:
        rep = self._reprs.pop(uid, None)

        if rep is None:
            return

        for key in rep.keys:
            if self._key_index.get(key) == uid:
                self._key_index.pop(key, None)

    def _rebuild_near_buckets(self) -> None:
        self._near_buckets.clear()
        refs = 0

        for uid, entry in self._near_entries.items():
            for band_key in entry.band_keys:
                self._near_buckets[band_key].append(uid)
                refs += 1

        self._near_bucket_refs = refs

    def _prune(self, force: bool = False) -> None:
        now = self._now()

        if not force and (now - self._last_prune) < float(self.options.prune_interval_seconds):
            return

        self._last_prune = now

        expired_reprs = [
            uid
            for uid, rep in self._reprs.items()
            if self._is_expired(rep.created_at, now)
        ]

        for uid in expired_reprs:
            self._remove_repr(uid)

        while len(self._reprs) > int(self.options.max_entries):
            oldest_uid = next(iter(self._reprs), None)

            if oldest_uid is None:
                break

            self._remove_repr(oldest_uid)

        expired_near = [
            uid
            for uid, entry in self._near_entries.items()
            if self._is_expired(entry.created_at, now)
        ]

        for uid in expired_near:
            self._near_entries.pop(uid, None)

        while len(self._near_entries) > int(self.options.max_near_entries):
            oldest_near_uid = next(iter(self._near_entries), None)

            if oldest_near_uid is None:
                break

            self._near_entries.pop(oldest_near_uid, None)

        rebuild_threshold = max(1_000, int(self.options.max_near_entries) * 3)

        if self._near_bucket_refs > rebuild_threshold:
            self._rebuild_near_buckets()

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def find_duplicate(self, keys: Sequence[str]) -> Optional[DedupeMatch]:
        """
        Return a duplicate match for one or more fingerprint keys.
        """
        if not keys:
            return None

        now = self._now()

        with self._lock:
            self._prune()

            for key in keys:
                uid = self._key_index.get(key)

                if uid is None:
                    continue

                rep = self._reprs.get(uid)

                if rep is None or self._is_expired(rep.created_at, now):
                    continue

                self._reprs.move_to_end(uid)
                rep.last_seen = now
                rep.hit_count += 1

                return DedupeMatch(
                    scope=DedupeScope.NATURAL,
                    representative_uid=rep.uid,
                    representative_batch_id=rep.batch_id,
                    representative_index=rep.index,
                    key_hash=key.rsplit(":", 1)[-1] if ":" in key else key,
                )

        return None

    def add(
        self,
        keys: Sequence[str],
        batch_id: str,
        index: int,
        entity_type: str,
    ) -> int:
        """
        Add a representative and return its stable UID.
        """
        now = self._now()
        safe_keys = tuple(str(key) for key in keys if str(key))

        with self._lock:
            self._prune()

            self._uid_counter += 1
            uid = self._uid_counter

            rep = _Representative(
                uid=uid,
                batch_id=str(batch_id),
                index=int(index),
                entity_type=str(entity_type),
                keys=safe_keys,
                created_at=now,
                last_seen=now,
                hit_count=1,
            )

            self._reprs[uid] = rep

            for key in safe_keys:
                self._key_index[key] = uid

            while len(self._reprs) > int(self.options.max_entries):
                oldest_uid = next(iter(self._reprs), None)

                if oldest_uid is None:
                    break

                self._remove_repr(oldest_uid)

            return uid

    def add_near(self, uid: int, signature: NearSignature) -> None:
        """
        Add a near-duplicate signature for a representative UID.
        """
        now = self._now()

        with self._lock:
            rep = self._reprs.get(uid)

            if rep is None:
                return

            if uid in self._near_entries:
                entry = self._near_entries[uid]
                entry.last_seen = now
                entry.signature = signature.values
                entry.band_keys = signature.band_keys
                self._near_entries.move_to_end(uid)
                return

            entry = _NearEntry(
                uid=uid,
                batch_id=rep.batch_id,
                index=rep.index,
                entity_type=rep.entity_type,
                signature=signature.values,
                band_keys=signature.band_keys,
                created_at=now,
                last_seen=now,
            )

            self._near_entries[uid] = entry

            for band_key in signature.band_keys:
                self._near_buckets[band_key].append(uid)
                self._near_bucket_refs += 1

            while len(self._near_entries) > int(self.options.max_near_entries):
                oldest_near_uid = next(iter(self._near_entries), None)

                if oldest_near_uid is None:
                    break

                self._near_entries.pop(oldest_near_uid, None)

            rebuild_threshold = max(1_000, int(self.options.max_near_entries) * 3)

            if self._near_bucket_refs > rebuild_threshold:
                self._rebuild_near_buckets()

    def find_near(
        self,
        signature: NearSignature,
        threshold: float,
        max_candidates: int,
    ) -> Optional[DedupeMatch]:
        """
        Return a near-duplicate match above threshold.
        """
        if not signature.values or not signature.band_keys:
            return None

        now = self._now()
        candidates: set[int] = set()
        scanned = 0
        max_scan = max(1_000, int(max_candidates) * 20)

        with self._lock:
            self._prune()

            for band_key in signature.band_keys:
                bucket = self._near_buckets.get(band_key)

                if not bucket:
                    continue

                for uid in bucket:
                    scanned += 1

                    if uid in self._near_entries:
                        candidates.add(uid)

                    if len(candidates) >= int(max_candidates) or scanned >= max_scan:
                        break

                if len(candidates) >= int(max_candidates) or scanned >= max_scan:
                    break

            best_entry: Optional[_NearEntry] = None
            best_score = 0.0

            for uid in candidates:
                entry = self._near_entries.get(uid)

                if entry is None or self._is_expired(entry.created_at, now):
                    continue

                score = _jaccard_estimate(signature.values, entry.signature)

                if score >= float(threshold) and score > best_score:
                    best_entry = entry
                    best_score = score

            if best_entry is None:
                return None

            rep = self._reprs.get(best_entry.uid)

            if rep is not None:
                self._reprs.move_to_end(rep.uid)
                rep.last_seen = now
                rep.hit_count += 1

            return DedupeMatch(
                scope=DedupeScope.NEAR,
                representative_uid=best_entry.uid,
                representative_batch_id=best_entry.batch_id,
                representative_index=best_entry.index,
                similarity=round(best_score, 4),
            )

    def touch(self, uid: int) -> None:
        """
        Mark a representative as recently seen.
        """
        now = self._now()

        with self._lock:
            rep = self._reprs.get(uid)

            if rep is None:
                return

            self._reprs.move_to_end(uid)
            rep.last_seen = now
            rep.hit_count += 1

    def clear(self) -> None:
        """
        Clear all stored indexes.
        """
        with self._lock:
            self._reprs.clear()
            self._key_index.clear()
            self._near_entries.clear()
            self._near_buckets.clear()
            self._near_bucket_refs = 0
            self._uid_counter = 0
            self._last_prune = time.monotonic()

    def stats(self) -> dict[str, Any]:
        """
        Return safe store statistics.
        """
        with self._lock:
            self._prune()

            return {
                "backend": "memory",
                "distributed": False,
                "durable": False,
                "max_entries": self.options.max_entries,
                "max_near_entries": self.options.max_near_entries,
                "active_representatives": len(self._reprs),
                "active_keys": len(self._key_index),
                "active_near_entries": len(self._near_entries),
                "near_bucket_refs": self._near_bucket_refs,
                "window_seconds": round(self.options.window_seconds, 3),
            }


# -----------------------------------------------------------------------------
# Result models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class DedupeIssue:
    """
    Safe dedupe issue.

    Issues never contain raw narratives, secrets, tokens, passwords, database
    URLs, model artifact paths, or sensitive identifiers.
    """

    severity: DedupeSeverity
    code: str
    message: str
    entity_type: str = ""
    index: Optional[int] = None
    field: Optional[str] = None
    details: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable issue mapping.
        """
        payload: dict[str, Any] = {
            "severity": self.severity.value,
            "code": _clean_text(self.code, 100),
            "message": _clean_text(self.message, 300),
        }

        if self.entity_type:
            payload["entity_type"] = _clean_text(self.entity_type, 100)

        if self.index is not None:
            payload["index"] = int(self.index)

        if self.field:
            payload["field"] = _clean_text(self.field, 200)

        if self.details:
            payload["details"] = self.details

        return payload


@dataclass(slots=True)
class DedupeGroup:
    """
    Safe duplicate group.

    This contains indices and one-way fingerprint prefixes only. It never
    contains raw record values.
    """

    scope: DedupeScope
    representative_uid: int
    representative_batch_id: str
    representative_index: Optional[int]
    duplicate_indices: list[int] = dataclass_field(default_factory=list)
    similarity: Optional[float] = None
    key_hash_prefix: Optional[str] = None
    truncated: bool = False

    @property
    def count(self) -> int:
        """
        Return total records represented by this group.
        """
        return 1 + len(self.duplicate_indices)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable group mapping.
        """
        return {
            "scope": self.scope.value,
            "representative_uid": int(self.representative_uid),
            "representative_batch_id": _clean_text(self.representative_batch_id, 128),
            "representative_index": self.representative_index,
            "duplicate_indices": list(self.duplicate_indices),
            "count": self.count,
            "similarity": self.similarity,
            "key_hash_prefix": self.key_hash_prefix,
            "truncated": bool(self.truncated),
        }


@dataclass(slots=True)
class DedupeResult:
    """
    Safe ingestion deduplication result.

    The full index lists are retained on the result object for downstream
    processing. Public summaries deliberately truncate index samples and never
    include record content.
    """

    ok: bool = True
    entity_type: str = ""
    batch_id: str = ""
    submitted: int = 0

    accepted_indices: list[int] = dataclass_field(default_factory=list)
    duplicate_indices: list[int] = dataclass_field(default_factory=list)
    rejected_indices: list[int] = dataclass_field(default_factory=list)
    review_indices: list[int] = dataclass_field(default_factory=list)

    issues: list[DedupeIssue] = dataclass_field(default_factory=list)
    groups: list[DedupeGroup] = dataclass_field(default_factory=list)
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)

    max_issues: int = _DEFAULT_MAX_ISSUES_RETURNED
    max_groups: int = _DEFAULT_MAX_GROUPS_RETURNED
    max_indices_returned: int = _DEFAULT_MAX_INDICES_RETURNED

    _groups_by_uid: dict[int, DedupeGroup] = dataclass_field(default_factory=dict, repr=False)
    _issue_count: int = dataclass_field(default=0, repr=False)
    _issue_truncated: bool = dataclass_field(default=False, repr=False)

    def add_issue(
        self,
        *,
        severity: DedupeSeverity,
        code: str,
        message: str,
        index: Optional[int] = None,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe issue entry.

        Returns False when the bounded issue list is already truncated.
        """
        if self._issue_truncated:
            if severity == DedupeSeverity.ERROR:
                self.ok = False
            return False

        if self._issue_count >= max(1, int(self.max_issues)):
            self._issue_truncated = True
            self.issues.append(
                DedupeIssue(
                    severity=DedupeSeverity.WARNING,
                    code="issue_list_truncated",
                    message="Issue list truncated by configured limit.",
                    entity_type=self.entity_type,
                )
            )

            if severity == DedupeSeverity.ERROR:
                self.ok = False

            return False

        self.issues.append(
            DedupeIssue(
                severity=severity,
                code=_clean_text(code, 100),
                message=_clean_text(message, 300),
                entity_type=_clean_text(self.entity_type, 100),
                index=int(index) if index is not None else None,
                field=_clean_text(field, 200) if field else None,
                details=_safe_details(details),
            )
        )

        self._issue_count += 1

        if severity == DedupeSeverity.ERROR:
            self.ok = False

        return True

    def finalize(self, options: DedupeOptions) -> None:
        """
        Finalize safe metadata and bounded group output.
        """
        sorted_groups = sorted(
            self._groups_by_uid.values(),
            key=lambda group: group.representative_uid,
        )

        groups_truncated = False

        if len(sorted_groups) > max(1, int(self.max_groups)):
            sorted_groups = sorted_groups[: max(1, int(self.max_groups))]
            groups_truncated = True

        self.groups = sorted_groups

        self.metadata.update(
            {
                "dedupe_version": DEDUPE_VERSION,
                "entity_type": self.entity_type,
                "batch_id": self.batch_id,
                "submitted": self.submitted,
                "accepted_count": len(self.accepted_indices),
                "duplicate_count": len(self.duplicate_indices),
                "rejected_count": len(self.rejected_indices),
                "review_count": len(self.review_indices),
                "group_count": len(self._groups_by_uid),
                "groups_returned": len(self.groups),
                "groups_truncated": groups_truncated,
                "issue_count": self._issue_count,
                "issue_truncated": self._issue_truncated,
                "action": options.action.value,
                "exact_id_enabled": options.include_exact_id,
                "natural_keys_enabled": options.include_natural_keys,
                "business_keys_enabled": options.include_business_keys,
                "near_duplicates_enabled": options.include_near_duplicates,
                "near_threshold": round(options.near_threshold, 4),
                "window_seconds": round(options.window_seconds, 3),
                "treat_missing_as_unique": options.treat_missing_as_unique,
                "caveats": list(_DUPE_CAVEATS),
            }
        )

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately truncates index samples and does not include record
        content, raw narratives, identifier hashes, or sensitive values.
        """
        limit = max(1, int(self.max_indices_returned))

        def sample(indices: Sequence[int]) -> dict[str, Any]:
            values = list(indices)
            return {
                "count": len(values),
                "sample": values[:limit],
                "truncated": len(values) > limit,
            }

        return {
            "ok": self.ok,
            "entity_type": self.entity_type,
            "batch_id": self.batch_id,
            "submitted": self.submitted,
            "counts": {
                "accepted": len(self.accepted_indices),
                "duplicates": len(self.duplicate_indices),
                "rejected": len(self.rejected_indices),
                "review": len(self.review_indices),
                "groups": len(self._groups_by_uid),
                "issues": self._issue_count,
            },
            "indices": {
                "accepted": sample(self.accepted_indices),
                "duplicates": sample(self.duplicate_indices),
                "rejected": sample(self.rejected_indices),
                "review": sample(self.review_indices),
            },
            "groups": [group.to_dict() for group in self.groups],
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
            "caveats": list(_DUPE_CAVEATS),
        }


# -----------------------------------------------------------------------------
# Fingerprint construction
# -----------------------------------------------------------------------------


def _record_fingerprints(
    entity_type: str,
    record: Mapping[str, Any],
    options: DedupeOptions,
    salt: str,
) -> list[Fingerprint]:
    """
    Build deterministic safe fingerprints for one record.
    """
    fingerprints: list[Fingerprint] = []

    if options.include_exact_id and not _is_missing(record, "id"):
        digest = _composite_hash(
            entity_type,
            DedupeScope.EXACT_ID,
            ("id",),
            record,
            salt,
        )

        if digest:
            fingerprints.append(
                Fingerprint(
                    scope=DedupeScope.EXACT_ID,
                    key=f"{entity_type}:{DedupeScope.EXACT_ID.value}:{digest}",
                    hash=digest,
                    fields=("id",),
                )
            )

    if options.include_natural_keys:
        for fields in _NATURAL_KEY_SPECS.get(entity_type, ()):
            if fields == ("id",) and options.include_exact_id:
                continue

            digest = _composite_hash(
                entity_type,
                DedupeScope.NATURAL,
                fields,
                record,
                salt,
            )

            if digest:
                fingerprints.append(
                    Fingerprint(
                        scope=DedupeScope.NATURAL,
                        key=f"{entity_type}:{DedupeScope.NATURAL.value}:{digest}",
                        hash=digest,
                        fields=tuple(fields),
                    )
                )

    if options.include_business_keys:
        for fields in _BUSINESS_KEY_SPECS.get(entity_type, ()):
            digest = _composite_hash(
                entity_type,
                DedupeScope.BUSINESS,
                fields,
                record,
                salt,
            )

            if digest:
                fingerprints.append(
                    Fingerprint(
                        scope=DedupeScope.BUSINESS,
                        key=f"{entity_type}:{DedupeScope.BUSINESS.value}:{digest}",
                        hash=digest,
                        fields=tuple(fields),
                    )
                )

    fingerprints.sort(key=lambda fp: (fp.scope.priority, fp.key))
    return fingerprints


# -----------------------------------------------------------------------------
# Near-duplicate signature construction
# -----------------------------------------------------------------------------


def _compute_near_signature(
    entity_type: str,
    record: Mapping[str, Any],
    options: DedupeOptions,
    salt: str,
) -> Optional[NearSignature]:
    """
    Compute an optional MinHash near-duplicate signature.

    Currently supported only for synthetic complaint narratives. Raw narrative
    text is transient and is never stored, logged, or returned.
    """
    if not options.include_near_duplicates:
        return None

    if entity_type != "complaints":
        return None

    narrative = record.get("narrative_raw")

    if narrative is None:
        return None

    text = _normalize_unicode(narrative).lower()
    text = _CONTROL_CHAR_RE.sub(" ", text)

    tokens = _TOKEN_RE.findall(text)

    if len(tokens) < int(options.near_min_tokens):
        return None

    tokens = tokens[:_MAX_NARRATIVE_TOKENS]

    if len(tokens) < _SHINGLE_SIZE:
        shingles: list[tuple[str, ...]] = [(token,) for token in tokens]
    else:
        shingles = [
            tuple(tokens[index : index + _SHINGLE_SIZE])
            for index in range(len(tokens) - _SHINGLE_SIZE + 1)
        ]

    unique_shingles = list(dict.fromkeys(shingles))[: int(options.near_max_shingles)]

    if not unique_shingles:
        return None

    shingle_hashes: list[int] = []
    key = salt.encode("utf-8", errors="replace")

    for shingle in unique_shingles:
        raw = "\x00".join(shingle)
        message = f"muleguard.dedupe.shingle\x00{raw}".encode("utf-8", errors="replace")
        digest = hmac.new(key, message, hashlib.sha256).digest()
        shingle_hashes.append(int.from_bytes(digest[:8], "big"))

    num_perm = int(options.near_num_perm)
    bands = int(options.near_bands)
    rows = num_perm // bands
    seeds = _minhash_seeds(num_perm)

    signature = [_MASK_64] * num_perm

    for shingle_hash in shingle_hashes:
        for index, seed in enumerate(seeds):
            value = _mix64(shingle_hash, seed)

            if value < signature[index]:
                signature[index] = value

    band_keys: list[str] = []

    for band_index in range(bands):
        start = band_index * rows
        end = start + rows
        parts = [
            str(num_perm),
            str(bands),
            str(rows),
            str(band_index),
            *[str(value) for value in signature[start:end]],
        ]
        band_keys.append(_hash_parts(parts, salt, domain="muleguard.dedupe.band"))

    return NearSignature(
        values=tuple(signature),
        band_keys=tuple(band_keys),
        num_perm=num_perm,
        bands=bands,
    )


# -----------------------------------------------------------------------------
# Duplicate group helpers
# -----------------------------------------------------------------------------


def _get_or_create_group(
    result: DedupeResult,
    match: DedupeMatch,
    current_batch_id: str,
) -> DedupeGroup:
    """
    Return an existing duplicate group or create a new one.
    """
    group = result._groups_by_uid.get(match.representative_uid)

    if group is not None:
        return group

    representative_index = (
        match.representative_index
        if match.representative_batch_id == current_batch_id
        else None
    )

    key_hash_prefix = None

    if match.key_hash:
        key_hash_prefix = match.key_hash[:16]

    group = DedupeGroup(
        scope=match.scope,
        representative_uid=match.representative_uid,
        representative_batch_id=match.representative_batch_id,
        representative_index=representative_index,
        similarity=match.similarity,
        key_hash_prefix=key_hash_prefix,
    )

    result._groups_by_uid[match.representative_uid] = group
    return group


def _add_duplicate_to_group(
    result: DedupeResult,
    group: DedupeGroup,
    index: int,
    options: DedupeOptions,
) -> None:
    """
    Add one duplicate index to a bounded group.
    """
    if len(group.duplicate_indices) < int(options.max_duplicate_group_size):
        group.duplicate_indices.append(int(index))
        return

    if not group.truncated:
        group.truncated = True
        result.add_issue(
            severity=DedupeSeverity.WARNING,
            code="group_truncated",
            message="Duplicate group index list truncated by configured limit.",
            details={
                "representative_uid": group.representative_uid,
                "max_duplicate_group_size": options.max_duplicate_group_size,
            },
        )


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------


class DedupeEngine:
    """
    High-level ingestion deduplication engine.

    This engine resolves options, builds salted fingerprints, delegates to a
    bounded store, and produces safe duplicate results.
    """

    def __init__(
        self,
        options: DedupeOptions | None = None,
        store: DedupeStore | None = None,
    ) -> None:
        if options is None:
            options = DedupeOptions.from_settings()

        self.options = options
        self.store: DedupeStore = store or MemoryDedupeStore(options)
        self._salt = _ensure_salt(options.salt)
        self._batch_counter = 0
        self._batch_lock = threading.Lock()

    # ---------------------------------------------------------------------
    # Batch identity
    # ---------------------------------------------------------------------

    def _next_batch_id(self) -> str:
        with self._batch_lock:
            self._batch_counter += 1
            return f"dedupe-batch-{self._batch_counter}"

    # ---------------------------------------------------------------------
    # Core processing
    # ---------------------------------------------------------------------

    def process_batch(
        self,
        entity_type: str,
        records: Sequence[Mapping[str, Any]] | Mapping[str, Any] | Any,
        batch_id: Optional[str] = None,
    ) -> DedupeResult:
        """
        Process one bounded ingestion batch for duplicates.

        Args:
            entity_type: One of accounts, transactions, complaints, entities,
                entity_links.
            records: Sequence of record mappings, or a single mapping.
            batch_id: Optional stable batch identifier. Generated when omitted.

        Returns:
            DedupeResult with safe duplicate groups and bounded index samples.
        """
        normalized_type = _normalize_entity_type(entity_type)
        resolved_batch_id = str(batch_id or self._next_batch_id())

        result = DedupeResult(
            entity_type=normalized_type,
            batch_id=resolved_batch_id,
            max_issues=self.options.max_issues_returned,
            max_groups=self.options.max_groups_returned,
            max_indices_returned=self.options.max_indices_returned,
        )

        if not self.options.enabled:
            record_list = self._as_record_list(records)
            result.submitted = len(record_list)
            result.accepted_indices = list(range(result.submitted))
            result.add_issue(
                severity=DedupeSeverity.INFO,
                code="dedupe_disabled",
                message="Deduplication is disabled. All records were accepted without duplicate checks.",
            )
            result.finalize(self.options)
            result.metadata["store"] = self.store.stats()
            return result

        if normalized_type not in _SUPPORTED_ENTITY_TYPES:
            result.add_issue(
                severity=DedupeSeverity.ERROR,
                code="unsupported_entity_type",
                message="Unsupported ingestion entity type for deduplication.",
                details={"allowed_entity_types": list(_SUPPORTED_ENTITY_TYPES)},
            )
            result.finalize(self.options)
            result.metadata["store"] = self.store.stats()
            return result

        record_list = self._as_record_list(records)
        result.submitted = len(record_list)

        if result.submitted > int(self.options.max_records_per_batch):
            result.add_issue(
                severity=DedupeSeverity.ERROR,
                code="batch_too_large",
                message="Batch exceeds configured deduplication limit.",
                details={
                    "submitted": result.submitted,
                    "max_records_per_batch": self.options.max_records_per_batch,
                },
            )
            result.rejected_indices = list(range(result.submitted))
            result.finalize(self.options)
            result.metadata["store"] = self.store.stats()
            return result

        for index, record in enumerate(record_list):
            if result._issue_truncated and result.ok is False:
                # Continue counting but avoid unbounded issue growth.
                pass

            if not isinstance(record, Mapping):
                result.add_issue(
                    severity=DedupeSeverity.ERROR,
                    code="invalid_record",
                    message="Record must be a mapping.",
                    index=index,
                )
                result.rejected_indices.append(index)
                continue

            fingerprints = _record_fingerprints(
                normalized_type,
                record,
                self.options,
                self._salt,
            )

            keys = [fp.key for fp in fingerprints]

            near_signature = _compute_near_signature(
                normalized_type,
                record,
                self.options,
                self._salt,
            )

            match = self.store.find_duplicate(keys) if keys else None

            if match is None and near_signature is not None:
                match = self.store.find_near(
                    near_signature,
                    threshold=self.options.near_threshold,
                    max_candidates=self.options.max_candidates_per_record,
                )

            if match is not None:
                self._handle_duplicate(
                    result=result,
                    index=index,
                    match=match,
                    batch_id=resolved_batch_id,
                )
                continue

            if keys or near_signature is not None:
                uid = self.store.add(
                    keys=keys,
                    batch_id=resolved_batch_id,
                    index=index,
                    entity_type=normalized_type,
                )

                if near_signature is not None:
                    self.store.add_near(uid, near_signature)

                result.accepted_indices.append(index)
                continue

            if self.options.treat_missing_as_unique:
                result.accepted_indices.append(index)
                result.add_issue(
                    severity=DedupeSeverity.WARNING,
                    code="missing_dedupe_key",
                    message="Record has no usable deduplication key and was accepted without duplicate detection.",
                    index=index,
                )
            else:
                result.rejected_indices.append(index)
                result.add_issue(
                    severity=DedupeSeverity.ERROR,
                    code="missing_dedupe_key",
                    message="Record has no usable deduplication key and was rejected.",
                    index=index,
                )

        result.finalize(self.options)
        result.metadata["store"] = self.store.stats()
        return result

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------

    @staticmethod
    def _as_record_list(records: Any) -> list[Any]:
        """
        Normalize record input into a list.
        """
        if records is None:
            return []

        if isinstance(records, Mapping):
            return [records]

        if isinstance(records, Sequence) and not isinstance(records, (str, bytes, bytearray)):
            return list(records)

        return [records]

    def _handle_duplicate(
        self,
        result: DedupeResult,
        index: int,
        match: DedupeMatch,
        batch_id: str,
    ) -> None:
        """
        Handle one detected duplicate according to policy.
        """
        group = _get_or_create_group(result, match, batch_id)
        _add_duplicate_to_group(result, group, index, self.options)

        if self.options.action == DedupeAction.SKIP:
            result.duplicate_indices.append(index)
            return

        if self.options.action == DedupeAction.REJECT:
            result.duplicate_indices.append(index)
            result.rejected_indices.append(index)
            result.add_issue(
                severity=DedupeSeverity.ERROR,
                code="duplicate_rejected",
                message="Duplicate record rejected by deduplication policy.",
                index=index,
                details={
                    "scope": match.scope.value,
                    "representative_uid": match.representative_uid,
                    "similarity": match.similarity,
                    "key_hash_prefix": (match.key_hash or "")[:16] or None,
                },
            )
            return

        # FLAG
        result.duplicate_indices.append(index)
        result.review_indices.append(index)
        result.add_issue(
            severity=DedupeSeverity.WARNING,
            code="duplicate_flagged_for_review",
            message="Duplicate record flagged for operational review.",
            index=index,
            details={
                "scope": match.scope.value,
                "representative_uid": match.representative_uid,
                "similarity": match.similarity,
                "key_hash_prefix": (match.key_hash or "")[:16] or None,
            },
        )

    # ---------------------------------------------------------------------
    # Maintenance
    # ---------------------------------------------------------------------

    def clear(self) -> None:
        """
        Clear the underlying store. Intended for tests.
        """
        self.store.clear()

    def stats(self) -> dict[str, Any]:
        """
        Return safe engine and store statistics.
        """
        return {
            "version": DEDUPE_VERSION,
            "options": self.options.safe_summary(),
            "store": self.store.stats(),
        }


# -----------------------------------------------------------------------------
# Convenience helpers
# -----------------------------------------------------------------------------


_default_engine: Optional[DedupeEngine] = None
_default_engine_lock = threading.Lock()


def get_dedupe_engine(options: DedupeOptions | None = None) -> DedupeEngine:
    """
    Return a process-wide dedupe engine.

    If options are provided, a new engine is created and becomes the default.
    This is useful for tests or applications that construct options explicitly.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or options is not None:
            _default_engine = DedupeEngine(options=options)

        return _default_engine


def dedupe_ingestion_batch(
    entity_type: str,
    records: Sequence[Mapping[str, Any]] | Mapping[str, Any] | Any,
    options: DedupeOptions | None = None,
    batch_id: Optional[str] = None,
) -> DedupeResult:
    """
    Convenience wrapper around the default dedupe engine.
    """
    engine = get_dedupe_engine(options)
    return engine.process_batch(entity_type, records, batch_id=batch_id)


def get_dedupe_metadata() -> dict[str, Any]:
    """
    Return safe, serializable dedupe-layer metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, or real customer data.
    """
    default_options = DedupeOptions()

    return {
        "package": "muleguard.backend.ingestion.dedupe",
        "version": DEDUPE_VERSION,
        "supported_entity_types": list(_SUPPORTED_ENTITY_TYPES),
        "scopes": [scope.value for scope in DedupeScope],
        "actions": [action.value for action in DedupeAction],
        "default_options": default_options.safe_summary(),
        "hard_limits": {
            "max_entries": _HARD_MAX_ENTRIES,
            "max_near_entries": _HARD_MAX_NEAR_ENTRIES,
            "max_records_per_batch": _HARD_MAX_RECORDS_PER_BATCH,
            "max_candidates_per_record": _HARD_MAX_CANDIDATES_PER_RECORD,
            "max_duplicate_group_size": _HARD_MAX_DUPLICATE_GROUP_SIZE,
            "max_indices_returned": _HARD_MAX_INDICES_RETURNED,
            "max_issues_returned": _HARD_MAX_ISSUES_RETURNED,
            "max_groups_returned": _HARD_MAX_GROUPS_RETURNED,
            "near_num_perm": _HARD_MAX_NEAR_NUM_PERM,
            "near_bands": _HARD_MAX_NEAR_BANDS,
            "near_max_shingles": _HARD_MAX_NEAR_SHINGLES,
            "near_min_tokens": _HARD_MAX_NEAR_TOKENS,
        },
        "caveats": list(_DUPE_CAVEATS),
        "safety_flags": {
            "synthetic_only_by_default": True,
            "no_real_customer_data_by_default": True,
            "no_raw_narrative_storage": True,
            "no_raw_narrative_logging": True,
            "no_raw_narrative_in_summaries": True,
            "no_ground_truth_labels_accepted": True,
            "no_scenario_ids_accepted": True,
            "no_fraud_ring_ids_accepted": True,
            "no_secrets_in_summaries": True,
            "salted_one_way_fingerprints": True,
            "bounded_indexes_required": True,
            "sliding_window_pruning": True,
            "near_duplicates_disabled_by_default": True,
            "near_duplicates_are_operational_hygiene_only": True,
            "no_automatic_adverse_customer_action": True,
            "not_production_ready": True,
        },
    }


__all__ = [
    "DedupeAction",
    "DedupeEngine",
    "DedupeGroup",
    "DedupeIssue",
    "DedupeMatch",
    "DedupeOptions",
    "DedupeResult",
    "DedupeScope",
    "DedupeSeverity",
    "DedupeStore",
    "Fingerprint",
    "MemoryDedupeStore",
    "NearSignature",
    "dedupe_ingestion_batch",
    "get_dedupe_engine",
    "get_dedupe_metadata",
]