"""
MULEGUARD backend ML labels.

This module provides the canonical synthetic label management layer for the
MULEGUARD machine-learning subsystem.

Primary responsibilities:

- define a bounded, versioned, non-adjudicative synthetic label taxonomy for
  offline ML evaluation and controlled training fixtures;
- validate and normalize synthetic label inputs from fixtures, generators,
  tests, and offline evaluation harnesses;
- protect label linkage using salted, domain-separated, one-way pseudonymous
  subject hashes;
- enforce strict label isolation so labels are never treated as features,
  never returned in public summaries, never logged, and never persisted by this
  module;
- build deterministic internal label sets aligned to synthetic feature vectors;
- provide bounded train/validation/test splitting, stratification, class
  balancing, optional synthetic label noise, and label quality diagnostics;
- reject leakage-prone inputs such as real ground-truth fields, fraud labels,
  injected scenario IDs, fraud-ring IDs, raw complaint narratives, raw
  identifiers, secrets, tokens, passwords, database URLs, filesystem paths, and
  model artifact paths;
- remain import-safe, dependency-light, and usable by ML services, evaluation
  harnesses, tests, seeders, offline fixtures, and developer tooling.

This module manages labels only. It does not train models, score accounts,
evaluate models, persist data, call external systems, authenticate users,
authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for label construction.
- Synthetic labels are evaluation fixtures only. They are not proof of
  wrongdoing.
- Labels must never be used as model features.
- Labels must never be returned in public API summaries, logs, diagnostics,
  exports, or artifacts.
- Fields named like real supervision signals, such as `ground_truth`,
  `is_fraud`, `fraud_label`, `scenario_id`, or `ring_id`, are rejected as
  leakage-prone inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden outputs. Subject linkage uses salted one-way
  pseudonymous hashes only.
- Risk labels, review labels, escalation labels, and priority labels are
  investigative workflow fixtures only. They are not adjudications.
- Label handling never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable labels are reported honestly as unavailable rather
  than invented.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call model runtimes.
- This module does not train, promote, retire, upload, replace, or execute
  models.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable label store. Production deployments should use a
  reviewed, access-controlled, audited label store if persistent labels are
  required.

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
import random
import re
import threading
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum, IntEnum
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError

logger = logging.getLogger("muleguard.backend.ml.labels")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

LABELS_VERSION: Final[str] = "v1"
LABEL_TAXONOMY_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.labels.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_LABELS: Final[int] = 100_000
_HARD_MAX_LABELS: Final[int] = 1_000_000

_DEFAULT_MAX_SUBJECTS: Final[int] = 100_000
_HARD_MAX_SUBJECTS: Final[int] = 1_000_000

_DEFAULT_MAX_CLASSES: Final[int] = 32
_HARD_MAX_CLASSES: Final[int] = 128

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_SPLIT_TRAIN: Final[float] = 0.70
_DEFAULT_SPLIT_VALIDATION: Final[float] = 0.15
_DEFAULT_SPLIT_TEST: Final[float] = 0.15

_DEFAULT_NOISE_RATE: Final[float] = 0.0
_HARD_MAX_NOISE_RATE: Final[float] = 0.49

_DEFAULT_MIN_CLASS_COUNT: Final[int] = 1
_DEFAULT_MAX_CLASS_SHARE: Final[float] = 0.95

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_ID_LENGTH: Final[int] = 128
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256
_MAX_WEIGHT: Final[float] = 100.0

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

_MISSING: Final[object] = object()

_LABEL_ALLOWED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "subject_ref_hash",
        "subject_hash",
        "subject",
        "account_id",
        "account",
        "id",
        "label",
        "label_code",
        "target",
        "y",
        "synthetic_label",
        "weight",
        "split",
        "metadata_json",
        "metadata",
    }
)

_LABEL_FORBIDDEN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "apikey",
        "artifact_path",
        "auth_header",
        "authorization",
        "bearer",
        "card_number",
        "connection_string",
        "cookie",
        "credential",
        "credentials",
        "cvv",
        "database_url",
        "dsn",
        "email_address",
        "file_path",
        "fraud_label",
        "fraud_ring_id",
        "ground_truth",
        "ground_truth_label",
        "identifier_raw",
        "ifsc",
        "ip_address",
        "is_fraud",
        "model_artifact_path",
        "model_path",
        "narrative",
        "narrative_normalized",
        "narrative_raw",
        "otp",
        "pan",
        "pass",
        "passwd",
        "password",
        "password_hash",
        "phone_number",
        "pickle",
        "pin",
        "private_key",
        "raw_identifier",
        "raw_payload",
        "refresh_token",
        "ring_id",
        "scenario_id",
        "secret",
        "secret_key",
        "session",
        "source_payload_hash",
        "token",
        "truth_label",
        "upi_id",
    }
)

_LABEL_FORBIDDEN_TOKENS: Final[tuple[str, ...]] = (
    "ground_truth",
    "truth_label",
    "fraud_label",
    "is_fraud",
    "scenario_id",
    "ring_id",
    "fraud_ring",
    "identifier_raw",
    "raw_identifier",
    "raw_payload",
    "narrative",
    "model_artifact",
    "artifact_path",
    "database_url",
    "connection_string",
    "private_key",
    "password",
    "passwd",
    "secret",
    "authorization",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "cookie",
    "session",
    "csrf",
    "xsrf",
    "pickle",
    "card_number",
    "pan",
    "cvv",
    "upi_id",
    "phone_number",
    "email_address",
    "ip_address",
    "device_id",
    "account_number",
    "ifsc",
    "customer_id",
    "customer_data",
    "real_data",
)

_LABEL_LEAKAGE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "fraud_label",
        "ground_truth",
        "ground_truth_label",
        "is_fraud",
        "label",
        "label_code",
        "ring_id",
        "scenario_id",
        "synthetic_label",
        "target",
        "truth_label",
        "y",
    }
)

_LABEL_LEAKAGE_TOKENS: Final[tuple[str, ...]] = (
    "ground_truth",
    "truth_label",
    "fraud_label",
    "is_fraud",
    "scenario_id",
    "ring_id",
    "fraud_ring",
    "synthetic_label",
)

_SENSITIVE_DETAIL_TOKENS: Final[tuple[str, ...]] = (
    "access_key",
    "account_number",
    "api_key",
    "apikey",
    "artifact_path",
    "authorization",
    "card_number",
    "connection_string",
    "credential",
    "customer_data",
    "customer_id",
    "database_url",
    "device_id",
    "dsn",
    "email_address",
    "file_path",
    "filesystem",
    "fraud_label",
    "ground_truth",
    "ifsc",
    "ip_address",
    "is_fraud",
    "model_artifact_path",
    "model_path",
    "narrative",
    "passphrase",
    "password",
    "passwd",
    "payload_hash",
    "phone_number",
    "pickle",
    "private_key",
    "raw_",
    "real_data",
    "refresh_token",
    "ring_id",
    "scenario_id",
    "secret",
    "secret_key",
    "token",
    "truth_label",
    "upi_id",
)

_LABEL_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML label management only. Do not use with real customer data.",
    "Synthetic labels are evaluation fixtures only and are not proof of wrongdoing.",
    "Labels must never be used as model features.",
    "Labels must never be returned in public summaries, logs, diagnostics, exports, or artifacts.",
    "Real ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Subject linkage uses salted one-way pseudonymous hashes only.",
    "Risk, review, escalation, and priority labels are investigative workflow fixtures only.",
    "Label handling must not trigger automatic adverse customer action.",
    "Unavailable labels are reported honestly as unavailable rather than invented.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_LABEL_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_labels_as_features": True,
        "no_raw_labels_in_public_summaries": True,
        "no_ground_truth_fields_accepted": True,
        "no_fraud_label_fields_accepted": True,
        "no_scenario_ids_accepted": True,
        "no_fraud_ring_ids_accepted": True,
        "no_raw_narratives_accepted": True,
        "no_raw_identifiers_accepted": True,
        "no_secrets_accepted": True,
        "no_tokens_accepted": True,
        "no_passwords_accepted": True,
        "no_database_urls_accepted": True,
        "no_model_artifact_paths_accepted": True,
        "salted_pseudonymous_subject_hashes": True,
        "bounded_label_sets_required": True,
        "deterministic_label_construction": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Label codes
# -----------------------------------------------------------------------------


class LabelCode(IntEnum):
    """
    Built-in synthetic label codes.

    These codes are non-adjudicative workflow fixtures only.
    """

    UNKNOWN = 0
    NO_ACTION = 1
    REVIEW = 2
    ESCALATE = 3
    UNCERTAIN = 4


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


def _csv(value: object) -> list[str]:
    """
    Parse comma-separated settings into a clean list.
    """
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return [part.strip() for part in str(value).split(",") if part.strip()]


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


def _normalize_token(value: Any) -> str:
    """
    Normalize a token-like value into lower snake_case.
    """
    text = _normalize_unicode(value).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = _SEPARATOR_RE.sub("_", text)
    text = _MULTI_UNDERSCORE_RE.sub("_", text)
    return text.strip("_").lower()


def _canonical_field_name(key: Any) -> str:
    """
    Convert a field name to a conservative canonical snake_case form.
    """
    return _normalize_token(key)


def _is_safe_hash(value: Any) -> bool:
    """
    Return True when a value looks like a pseudonymous hash.
    """
    text = str(value or "").strip()
    return bool(text and _HASH_RE.match(text))


def _is_forbidden_label_input_key(key: Any) -> bool:
    """
    Return True when a label input key is forbidden.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _LABEL_FORBIDDEN_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _LABEL_FORBIDDEN_TOKENS)


def _is_label_leakage_key(key: Any) -> bool:
    """
    Return True when a feature-vector key looks like a label.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _LABEL_LEAKAGE_FIELDS:
        return True

    return any(token in canonical for token in _LABEL_LEAKAGE_TOKENS)


def _is_sensitive_detail_key(key: Any) -> bool:
    """
    Return True when a detail key appears sensitive or leakage-prone.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    return any(token in canonical for token in _SENSITIVE_DETAIL_TOKENS)


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
        return str(value) if value.is_finite() else None

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, IntEnum):
        return int(value)

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:100]:
            key = _clean_text(raw_key, 128)

            if not key or _is_sensitive_detail_key(key):
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            _safe_detail_value(item, depth + 1)
            for item in list(value)[:100]
        ]

    return f"<{type(value).__name__}>"


def _safe_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return safe issue details.
    """
    if not details:
        return {}

    sanitized = _safe_detail_value(details)

    if isinstance(sanitized, dict):
        return sanitized

    if sanitized is None:
        return {}

    return {"value": sanitized}


def _clip_float(
    value: Optional[float],
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
    default: float = 0.0,
) -> float:
    """
    Clip a float into bounds.
    """
    if value is None:
        return default

    if math.isnan(value) or math.isinf(value):
        return default

    result = float(value)

    if minimum is not None:
        result = max(minimum, result)

    if maximum is not None:
        result = min(maximum, result)

    if math.isnan(result) or math.isinf(result):
        return default

    return result


def _decimal_to_float(value: Any, default: float = 0.0) -> float:
    """
    Convert a decimal-like value to finite float.
    """
    if isinstance(value, Decimal):
        if not value.is_finite():
            return default

        try:
            result = float(value)
        except (OverflowError, ValueError):
            return default

        return result if math.isfinite(result) else default

    if isinstance(value, bool):
        return default

    if isinstance(value, (int, float)):
        try:
            result = float(value)
        except (TypeError, ValueError):
            return default

        return result if math.isfinite(result) else default

    text = _normalize_unicode(value).strip().replace(",", "")

    if not text:
        return default

    try:
        result = float(text)
    except (TypeError, ValueError):
        return default

    return result if math.isfinite(result) else default


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
        if math.isnan(value) or math.isinf(value):
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


def _json_default(value: Any) -> Any:
    """
    JSON serializer fallback for canonicalization.
    """
    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, Decimal):
        return str(value) if value.is_finite() else None

    if isinstance(value, IntEnum):
        return int(value)

    if isinstance(value, Mapping):
        return {str(k): v for k, v in value.items()}

    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)

    if isinstance(value, tuple):
        return list(value)

    return str(value)


def _canonical_json(value: Any) -> str:
    """
    Return deterministic canonical JSON.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    )


def _sha256_hex(value: str) -> str:
    """
    Return SHA-256 hex digest for a string.
    """
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _hmac_hex(salt: str, domain: str, message: str) -> str:
    """
    Return a domain-separated HMAC-SHA256 hex digest.
    """
    key = salt.encode("utf-8", errors="replace")
    payload = f"{domain}\x00{message}".encode("utf-8", errors="replace")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _stable_seed(*parts: Any) -> int:
    """
    Return a deterministic 64-bit seed from stable parts.
    """
    digest = hashlib.sha256(
        _canonical_json(list(parts)).encode("utf-8", errors="replace")
    ).digest()
    return int.from_bytes(digest[:8], "big")


def _ensure_salt(salt: Any) -> str:
    """
    Ensure the label salt is non-empty and sufficiently long.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _subject_hash(identifier: str, salt: str, namespace: str) -> str:
    """
    Return a salted, domain-separated pseudonymous subject hash.
    """
    safe_namespace = _normalize_token(namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.labels.subject.{safe_namespace}"
    return _hmac_hex(salt, domain, _clean_text(identifier, _MAX_TEXT_LENGTH))


def _normalized_entropy(weights: Mapping[Any, Any]) -> float:
    """
    Return normalized Shannon entropy in [0, 1].
    """
    numeric: list[float] = []

    for value in weights.values():
        float_value = _decimal_to_float(value, 0.0)

        if float_value > 0:
            numeric.append(float_value)

    total = sum(numeric)

    if total <= 0 or len(numeric) <= 1:
        return 0.0

    entropy = 0.0

    for value in numeric:
        p = value / total

        if p > 0:
            entropy -= p * math.log(p)

    norm = math.log(len(numeric))

    if norm <= 0:
        return 0.0

    return _clip_float(entropy / norm, 0.0, 1.0, 0.0)


def _as_sequence(value: Any) -> list[Any]:
    """
    Convert a flexible source into a list.
    """
    if value is None:
        return []

    if isinstance(value, Mapping):
        return [value]

    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return [value]

    if isinstance(value, Sequence):
        return list(value)

    if isinstance(value, Iterable):
        try:
            return list(value)
        except Exception:
            return [value]

    return [value]


def _get_source_collection(source: Any, names: Sequence[str]) -> Any:
    """
    Retrieve a collection from a dataset-like source.
    """
    for name in names:
        if isinstance(source, Mapping):
            if name in source:
                return source[name]
        else:
            value = getattr(source, name, None)

            if value is not None:
                return value

    return None


def _extract_account_id(record: Any) -> Optional[str]:
    """
    Extract a safe account identifier from a record-like object.
    """
    if isinstance(record, Mapping):
        for key in ("id", "account_id", "acct_id"):
            text = _clean_text(record.get(key), _MAX_ID_LENGTH)

            if text:
                return text

        return None

    for attr in ("id", "account_id", "acct_id"):
        text = _clean_text(getattr(record, attr, None), _MAX_ID_LENGTH)

        if text:
            return text

    return None


def _normalize_split(value: Any) -> Optional[str]:
    """
    Normalize a split-like value.
    """
    token = _normalize_token(value)

    aliases = {
        "train": "train",
        "training": "train",
        "val": "validation",
        "valid": "validation",
        "validation": "validation",
        "test": "test",
        "holdout": "test",
    }

    return aliases.get(token)


def _parse_rate_mapping(value: Any) -> dict[Any, float]:
    """
    Parse a rate-like setting into a mapping.

    Supported forms:

    - mapping;
    - comma-separated `name=weight` pairs.
    """
    if value is None:
        return {}

    if isinstance(value, Mapping):
        out: dict[Any, float] = {}

        for raw_key, raw_value in value.items():
            weight = _decimal_to_float(raw_value, 0.0)

            if weight > 0:
                out[raw_key] = weight

        return out

    out = {}

    for part in _csv(value):
        if "=" not in part:
            continue

        raw_key, raw_value = part.split("=", 1)
        key = raw_key.strip()
        weight = _decimal_to_float(raw_value, 0.0)

        if key and weight > 0:
            out[key] = weight

    return out


# -----------------------------------------------------------------------------
# Label taxonomy models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LabelDefinition:
    """
    One bounded synthetic label definition.
    """

    code: int
    name: str
    description: str
    aliases: tuple[str, ...] = ()
    enabled: bool = True
    positive: bool = False
    priority: float = 0.0

    def __post_init__(self) -> None:
        """
        Normalize label definition metadata.
        """
        object.__setattr__(self, "code", int(self.code))
        object.__setattr__(self, "name", _normalize_token(self.name) or f"label_{self.code}")
        object.__setattr__(self, "description", _clean_text(self.description, 1000))
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "positive", _as_bool(self.positive, False))
        object.__setattr__(
            self,
            "priority",
            _clip_float(self.priority, 0.0, 100.0, 0.0),
        )

        aliases: list[str] = []

        for raw_alias in self.aliases or ():
            alias = _normalize_token(raw_alias)

            if alias and alias != self.name:
                aliases.append(alias)

        object.__setattr__(self, "aliases", tuple(dict.fromkeys(aliases)))

    def safe_dict(self) -> dict[str, Any]:
        """
        Return a safe serializable label definition summary.
        """
        return {
            "code": int(self.code),
            "name": self.name,
            "description": self.description,
            "aliases": list(self.aliases),
            "enabled": bool(self.enabled),
            "positive": bool(self.positive),
            "priority": round(float(self.priority), 4),
        }


@dataclass(frozen=True, slots=True)
class LabelTaxonomy:
    """
    Bounded, versioned synthetic label taxonomy.
    """

    version: str
    definitions: tuple[LabelDefinition, ...]
    default_code: int = int(LabelCode.UNKNOWN)
    positive_codes: frozenset[int] = frozenset()
    negative_codes: frozenset[int] = frozenset()
    uncertain_codes: frozenset[int] = frozenset()

    _by_code: Mapping[int, LabelDefinition] = dataclass_field(
        init=False,
        default_factory=dict,
        repr=False,
        compare=False,
    )
    _by_name: Mapping[str, LabelDefinition] = dataclass_field(
        init=False,
        default_factory=dict,
        repr=False,
        compare=False,
    )
    _alias_map: Mapping[str, int] = dataclass_field(
        init=False,
        default_factory=dict,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """
        Normalize taxonomy metadata and build lookup maps.
        """
        definitions = tuple(self.definitions or ())

        if not definitions:
            raise ConfigurationError("Label taxonomy must contain at least one definition.")

        by_code: dict[int, LabelDefinition] = {}
        by_name: dict[str, LabelDefinition] = {}
        alias_map: dict[str, int] = {}

        for definition in definitions:
            if definition.code in by_code:
                raise ConfigurationError(
                    "Duplicate label code in taxonomy.",
                    details={"code": definition.code},
                )

            if definition.name in by_name:
                raise ConfigurationError(
                    "Duplicate label name in taxonomy.",
                    details={"name": definition.name},
                )

            by_code[definition.code] = definition
            by_name[definition.name] = definition

            for alias in definition.aliases:
                if alias in alias_map and alias_map[alias] != definition.code:
                    raise ConfigurationError(
                        "Duplicate label alias in taxonomy.",
                        details={"alias": alias},
                    )

                alias_map[alias] = definition.code

        if len(by_code) > _HARD_MAX_CLASSES:
            raise ConfigurationError(
                "Label taxonomy exceeds hard class limit.",
                details={"max_classes": _HARD_MAX_CLASSES},
            )

        positive_codes = self.positive_codes

        if not positive_codes:
            positive_codes = frozenset(
                definition.code
                for definition in definitions
                if definition.positive
            )

        uncertain_codes = self.uncertain_codes

        if not uncertain_codes:
            uncertain_codes = frozenset(
                definition.code
                for definition in definitions
                if definition.name == "uncertain" or "uncertain" in definition.aliases
            )

        negative_codes = self.negative_codes

        if not negative_codes:
            negative_codes = frozenset(
                definition.code
                for definition in definitions
                if (
                    definition.enabled
                    and definition.code not in positive_codes
                    and definition.code not in uncertain_codes
                    and definition.code != int(LabelCode.UNKNOWN)
                )
            )

        if self.default_code not in by_code:
            default_code = int(LabelCode.UNKNOWN)

            if default_code not in by_code:
                default_code = definitions[0].code
        else:
            default_code = int(self.default_code)

        object.__setattr__(self, "version", _clean_text(self.version, 32) or LABEL_TAXONOMY_VERSION)
        object.__setattr__(self, "definitions", definitions)
        object.__setattr__(self, "default_code", default_code)
        object.__setattr__(self, "positive_codes", frozenset(int(code) for code in positive_codes))
        object.__setattr__(self, "negative_codes", frozenset(int(code) for code in negative_codes))
        object.__setattr__(self, "uncertain_codes", frozenset(int(code) for code in uncertain_codes))
        object.__setattr__(self, "_by_code", MappingProxyType(by_code))
        object.__setattr__(self, "_by_name", MappingProxyType(by_name))
        object.__setattr__(self, "_alias_map", MappingProxyType(alias_map))

    def try_normalize(self, value: Any) -> Optional[int]:
        """
        Normalize a label-like value to a known code, or return None.
        """
        if isinstance(value, LabelCode):
            code = int(value)
        elif isinstance(value, int) and not isinstance(value, bool):
            code = int(value)
        elif isinstance(value, str):
            token = _normalize_token(value)
            code = self._alias_map.get(token)

            if code is None:
                definition = self._by_name.get(token)
                code = definition.code if definition is not None else None
        else:
            code = None

        if code is None:
            return None

        if code not in self._by_code:
            return None

        return int(code)

    def normalize(self, value: Any) -> int:
        """
        Normalize a label-like value to a known code.

        Unknown values fall back to the taxonomy default code.
        """
        code = self.try_normalize(value)
        return code if code is not None else int(self.default_code)

    def decode(self, code: Any) -> str:
        """
        Return a safe label name for a code.
        """
        try:
            resolved = int(code)
        except (TypeError, ValueError):
            return "unknown"

        definition = self._by_code.get(resolved)

        if definition is None:
            return f"unknown_{resolved}"

        return definition.name

    def get(self, code: Any) -> Optional[LabelDefinition]:
        """
        Return one label definition by code.
        """
        try:
            resolved = int(code)
        except (TypeError, ValueError):
            return None

        return self._by_code.get(resolved)

    @property
    def enabled_codes(self) -> tuple[int, ...]:
        """
        Return enabled label codes in deterministic order.
        """
        return tuple(
            definition.code
            for definition in self.definitions
            if definition.enabled
        )

    @property
    def trainable_codes(self) -> tuple[int, ...]:
        """
        Return enabled non-unknown label codes.
        """
        return tuple(
            code
            for code in self.enabled_codes
            if code != int(LabelCode.UNKNOWN)
        )

    def is_positive(self, code: Any) -> bool:
        """
        Return True when a code is a synthetic positive/investigate fixture.
        """
        try:
            return int(code) in self.positive_codes
        except (TypeError, ValueError):
            return False

    def is_negative(self, code: Any) -> bool:
        """
        Return True when a code is a synthetic negative/no-action fixture.
        """
        try:
            return int(code) in self.negative_codes
        except (TypeError, ValueError):
            return False

    def is_uncertain(self, code: Any) -> bool:
        """
        Return True when a code is a synthetic uncertain/human-review fixture.
        """
        try:
            return int(code) in self.uncertain_codes
        except (TypeError, ValueError):
            return False

    def summary(self) -> dict[str, Any]:
        """
        Return a safe serializable taxonomy summary.
        """
        return {
            "version": self.version,
            "default_code": int(self.default_code),
            "default_label": self.decode(self.default_code),
            "positive_codes": sorted(int(code) for code in self.positive_codes),
            "negative_codes": sorted(int(code) for code in self.negative_codes),
            "uncertain_codes": sorted(int(code) for code in self.uncertain_codes),
            "labels": [definition.safe_dict() for definition in self.definitions],
        }

    def fingerprint(self) -> str:
        """
        Return a deterministic taxonomy fingerprint.
        """
        try:
            return _sha256_hex(_canonical_json(self.summary()))
        except Exception:
            return _sha256_hex(str(len(self.definitions)))


def build_default_label_taxonomy() -> LabelTaxonomy:
    """
    Build the canonical bounded synthetic MULEGUARD label taxonomy.

    These labels are non-adjudicative workflow fixtures only.
    """
    definitions = (
        LabelDefinition(
            code=int(LabelCode.UNKNOWN),
            name="unknown",
            description="Unlabeled or unavailable synthetic label.",
            aliases=("unknown", "none", "null", "missing", "unlabeled"),
            enabled=True,
            positive=False,
            priority=0.0,
        ),
        LabelDefinition(
            code=int(LabelCode.NO_ACTION),
            name="no_action",
            description="Synthetic no-investigation fixture label.",
            aliases=(
                "negative",
                "no_action",
                "benign",
                "clean",
                "not_investigate",
                "low",
            ),
            enabled=True,
            positive=False,
            priority=0.0,
        ),
        LabelDefinition(
            code=int(LabelCode.REVIEW),
            name="review",
            description="Synthetic investigate fixture label.",
            aliases=(
                "positive",
                "review",
                "investigate",
                "flagged_for_review",
                "medium",
            ),
            enabled=True,
            positive=True,
            priority=1.0,
        ),
        LabelDefinition(
            code=int(LabelCode.ESCALATE),
            name="escalate",
            description="Synthetic high-priority investigate fixture label.",
            aliases=("escalate", "high_priority", "critical", "urgent"),
            enabled=True,
            positive=True,
            priority=2.0,
        ),
        LabelDefinition(
            code=int(LabelCode.UNCERTAIN),
            name="uncertain",
            description="Synthetic ambiguous label requiring human review.",
            aliases=("uncertain", "ambiguous", "needs_human", "unknown_label"),
            enabled=True,
            positive=False,
            priority=0.5,
        ),
    )

    return LabelTaxonomy(
        version=LABEL_TAXONOMY_VERSION,
        definitions=definitions,
        default_code=int(LabelCode.UNKNOWN),
        positive_codes=frozenset({int(LabelCode.REVIEW), int(LabelCode.ESCALATE)}),
        negative_codes=frozenset({int(LabelCode.NO_ACTION)}),
        uncertain_codes=frozenset({int(LabelCode.UNCERTAIN)}),
    )


_default_taxonomy: Optional[LabelTaxonomy] = None
_default_taxonomy_lock = threading.Lock()


def get_label_taxonomy(version: str = LABEL_TAXONOMY_VERSION) -> LabelTaxonomy:
    """
    Return a process-wide label taxonomy.

    Currently only the default synthetic taxonomy is bundled. Unknown versions
    fall back to the default taxonomy and should be treated as unavailable by
    callers that require strict versioning.
    """
    global _default_taxonomy

    _ = version

    with _default_taxonomy_lock:
        if _default_taxonomy is None:
            _default_taxonomy = build_default_label_taxonomy()

        return _default_taxonomy


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LabelOptions:
    """
    Bounded synthetic label construction policy.

    Hard caps prevent accidental unbounded label surfaces.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED
    taxonomy_version: str = LABEL_TAXONOMY_VERSION

    max_labels: int = _DEFAULT_MAX_LABELS
    max_subjects: int = _DEFAULT_MAX_SUBJECTS
    max_classes: int = _DEFAULT_MAX_CLASSES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS

    default_label_code: int = int(LabelCode.UNKNOWN)
    label_rates: Mapping[Any, float] = dataclass_field(default_factory=dict)

    noise_rate: float = _DEFAULT_NOISE_RATE

    split_train: float = _DEFAULT_SPLIT_TRAIN
    split_validation: float = _DEFAULT_SPLIT_VALIDATION
    split_test: float = _DEFAULT_SPLIT_TEST
    split_salt: str = "split"
    stratify: bool = True
    balance_classes: bool = True
    min_class_count: int = _DEFAULT_MIN_CLASS_COUNT
    max_class_share: float = _DEFAULT_MAX_CLASS_SHARE

    include_uncertain: bool = True
    drop_uncertain: bool = False
    collapse_binary: bool = False

    allow_external_labels: bool = True
    reject_real_data: bool = True
    emit_internal_labels: bool = True

    def __post_init__(self) -> None:
        """
        Normalize and clamp option values.
        """
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(
            self,
            "dataset_mode",
            _normalize_token(self.dataset_mode) or "synthetic",
        )
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(self, "salt", _ensure_salt(self.salt))
        object.__setattr__(
            self,
            "namespace",
            _normalize_token(self.namespace) or _DEFAULT_NAMESPACE,
        )
        object.__setattr__(self, "seed", int(self.seed))
        object.__setattr__(
            self,
            "taxonomy_version",
            _clean_text(self.taxonomy_version, 32) or LABEL_TAXONOMY_VERSION,
        )

        object.__setattr__(
            self,
            "max_labels",
            _clamp_int(self.max_labels, 1, _HARD_MAX_LABELS, _DEFAULT_MAX_LABELS),
        )
        object.__setattr__(
            self,
            "max_subjects",
            _clamp_int(self.max_subjects, 1, _HARD_MAX_SUBJECTS, _DEFAULT_MAX_SUBJECTS),
        )
        object.__setattr__(
            self,
            "max_classes",
            _clamp_int(self.max_classes, 1, _HARD_MAX_CLASSES, _DEFAULT_MAX_CLASSES),
        )
        object.__setattr__(
            self,
            "max_issues",
            _clamp_int(self.max_issues, 1, _HARD_MAX_ISSUES, _DEFAULT_MAX_ISSUES),
        )
        object.__setattr__(
            self,
            "max_summary_items",
            _clamp_int(
                self.max_summary_items,
                1,
                _HARD_MAX_SUMMARY_ITEMS,
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
        )

        object.__setattr__(self, "default_label_code", int(self.default_label_code))

        rates: dict[Any, float] = {}

        for raw_key, raw_value in (self.label_rates or {}).items():
            weight = _decimal_to_float(raw_value, 0.0)

            if weight > 0:
                rates[raw_key] = weight

        object.__setattr__(self, "label_rates", MappingProxyType(rates))

        object.__setattr__(
            self,
            "noise_rate",
            _clamp_float(self.noise_rate, 0.0, _HARD_MAX_NOISE_RATE, _DEFAULT_NOISE_RATE),
        )

        train = max(0.0, _as_float(self.split_train, _DEFAULT_SPLIT_TRAIN))
        validation = max(0.0, _as_float(self.split_validation, _DEFAULT_SPLIT_VALIDATION))
        test = max(0.0, _as_float(self.split_test, _DEFAULT_SPLIT_TEST))
        total = train + validation + test

        if total <= 0:
            train = _DEFAULT_SPLIT_TRAIN
            validation = _DEFAULT_SPLIT_VALIDATION
            test = _DEFAULT_SPLIT_TEST
            total = train + validation + test

        object.__setattr__(self, "split_train", train / total)
        object.__setattr__(self, "split_validation", validation / total)
        object.__setattr__(self, "split_test", test / total)

        object.__setattr__(
            self,
            "split_salt",
            _normalize_token(self.split_salt) or "split",
        )
        object.__setattr__(self, "stratify", _as_bool(self.stratify, True))
        object.__setattr__(self, "balance_classes", _as_bool(self.balance_classes, True))
        object.__setattr__(
            self,
            "min_class_count",
            max(0, _as_int(self.min_class_count, _DEFAULT_MIN_CLASS_COUNT)),
        )
        object.__setattr__(
            self,
            "max_class_share",
            _clamp_float(self.max_class_share, 0.5, 1.0, _DEFAULT_MAX_CLASS_SHARE),
        )

        object.__setattr__(self, "include_uncertain", _as_bool(self.include_uncertain, True))
        object.__setattr__(self, "drop_uncertain", _as_bool(self.drop_uncertain, False))
        object.__setattr__(self, "collapse_binary", _as_bool(self.collapse_binary, False))
        object.__setattr__(self, "allow_external_labels", _as_bool(self.allow_external_labels, True))
        object.__setattr__(self, "reject_real_data", _as_bool(self.reject_real_data, True))
        object.__setattr__(self, "emit_internal_labels", _as_bool(self.emit_internal_labels, True))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "LabelOptions":
        """
        Build label options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_LABEL_SALT", None)
            or _setting(settings, "PROVENANCE_SALT", None)
            or _setting(settings, "DEDUPE_SALT", None)
            or _setting(settings, "ML_FEATURE_SALT", None)
            or _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
            or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
            or _setting(settings, "BACKEND_SECRET_KEY", None)
            or _DEFAULT_SALT
        )

        env = str(_setting(settings, "BACKEND_ENV", "local")).strip().lower()
        production_values = {
            value.lower()
            for value in _csv(
                _setting(
                    settings,
                    "BACKEND_PRODUCTION_LIKE_ENVS",
                    "production,staging,prod,stage",
                )
            )
        }

        if not production_values:
            production_values = {"production", "staging", "prod", "stage"}

        return cls(
            enabled=_as_bool(_setting(settings, "ML_LABELS_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_LABELS_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_LABELS_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_LABELS_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_LABELS_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            taxonomy_version=str(
                _setting(settings, "ML_LABELS_TAXONOMY_VERSION", LABEL_TAXONOMY_VERSION)
            ),
            max_labels=_as_int(
                _setting(settings, "ML_LABELS_MAX_LABELS", _DEFAULT_MAX_LABELS),
                _DEFAULT_MAX_LABELS,
            ),
            max_subjects=_as_int(
                _setting(settings, "ML_LABELS_MAX_SUBJECTS", _DEFAULT_MAX_SUBJECTS),
                _DEFAULT_MAX_SUBJECTS,
            ),
            max_classes=_as_int(
                _setting(settings, "ML_LABELS_MAX_CLASSES", _DEFAULT_MAX_CLASSES),
                _DEFAULT_MAX_CLASSES,
            ),
            max_issues=_as_int(
                _setting(settings, "ML_LABELS_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "ML_LABELS_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            default_label_code=_as_int(
                _setting(settings, "ML_LABELS_DEFAULT_CODE", int(LabelCode.UNKNOWN)),
                int(LabelCode.UNKNOWN),
            ),
            label_rates=_parse_rate_mapping(_setting(settings, "ML_LABELS_RATES", None)),
            noise_rate=_as_float(
                _setting(settings, "ML_LABELS_NOISE_RATE", _DEFAULT_NOISE_RATE),
                _DEFAULT_NOISE_RATE,
            ),
            split_train=_as_float(
                _setting(settings, "ML_LABELS_SPLIT_TRAIN", _DEFAULT_SPLIT_TRAIN),
                _DEFAULT_SPLIT_TRAIN,
            ),
            split_validation=_as_float(
                _setting(settings, "ML_LABELS_SPLIT_VALIDATION", _DEFAULT_SPLIT_VALIDATION),
                _DEFAULT_SPLIT_VALIDATION,
            ),
            split_test=_as_float(
                _setting(settings, "ML_LABELS_SPLIT_TEST", _DEFAULT_SPLIT_TEST),
                _DEFAULT_SPLIT_TEST,
            ),
            split_salt=str(_setting(settings, "ML_LABELS_SPLIT_SALT", "split")),
            stratify=_as_bool(_setting(settings, "ML_LABELS_STRATIFY", True), True),
            balance_classes=_as_bool(_setting(settings, "ML_LABELS_BALANCE_CLASSES", True), True),
            min_class_count=_as_int(
                _setting(settings, "ML_LABELS_MIN_CLASS_COUNT", _DEFAULT_MIN_CLASS_COUNT),
                _DEFAULT_MIN_CLASS_COUNT,
            ),
            max_class_share=_as_float(
                _setting(settings, "ML_LABELS_MAX_CLASS_SHARE", _DEFAULT_MAX_CLASS_SHARE),
                _DEFAULT_MAX_CLASS_SHARE,
            ),
            include_uncertain=_as_bool(
                _setting(settings, "ML_LABELS_INCLUDE_UNCERTAIN", True),
                True,
            ),
            drop_uncertain=_as_bool(_setting(settings, "ML_LABELS_DROP_UNCERTAIN", False), False),
            collapse_binary=_as_bool(_setting(settings, "ML_LABELS_COLLAPSE_BINARY", False), False),
            allow_external_labels=_as_bool(
                _setting(settings, "ML_LABELS_ALLOW_EXTERNAL", True),
                True,
            ),
            reject_real_data=_as_bool(_setting(settings, "ML_LABELS_REJECT_REAL_DATA", True), True),
            emit_internal_labels=_as_bool(
                _setting(settings, "ML_LABELS_EMIT_INTERNAL", True),
                True,
            ),
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable options summary.

        The salt is never included.
        """
        return {
            "enabled": self.enabled,
            "synthetic_required": self.synthetic_required,
            "dataset_mode": self.dataset_mode,
            "production_like": self.production_like,
            "allow_in_production": self.allow_in_production,
            "namespace": self.namespace,
            "seed": self.seed,
            "taxonomy_version": self.taxonomy_version,
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
            "limits": {
                "max_labels": self.max_labels,
                "max_subjects": self.max_subjects,
                "max_classes": self.max_classes,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
            },
            "default_label_code": self.default_label_code,
            "label_rates_configured": bool(self.label_rates),
            "noise_rate": round(self.noise_rate, 6),
            "split": {
                "train": round(self.split_train, 6),
                "validation": round(self.split_validation, 6),
                "test": round(self.split_test, 6),
                "stratify": self.stratify,
                "balance_classes": self.balance_classes,
                "min_class_count": self.min_class_count,
                "max_class_share": round(self.max_class_share, 6),
            },
            "behaviour": {
                "include_uncertain": self.include_uncertain,
                "drop_uncertain": self.drop_uncertain,
                "collapse_binary": self.collapse_binary,
                "allow_external_labels": self.allow_external_labels,
                "reject_real_data": self.reject_real_data,
                "emit_internal_labels": self.emit_internal_labels,
            },
        }


# -----------------------------------------------------------------------------
# Issue and validation models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LabelIssue:
    """
    Safe label validation or construction issue.

    Issues never contain raw labels, raw narratives, raw identifiers, secrets,
    tokens, passwords, database URLs, filesystem paths, or model artifact paths.
    """

    severity: str
    code: str
    message: str
    field: Optional[str] = None
    details: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable issue mapping.
        """
        payload: dict[str, Any] = {
            "severity": _clean_text(self.severity, 20),
            "code": _clean_text(self.code, 100),
            "message": _clean_text(self.message, 300),
        }

        if self.field:
            payload["field"] = _clean_text(self.field, 200)

        if self.details:
            payload["details"] = self.details

        return payload


def _issue(
    *,
    severity: str,
    code: str,
    message: str,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> LabelIssue:
    """
    Build one safe label issue.
    """
    return LabelIssue(
        severity=_clean_text(severity, 20),
        code=_clean_text(code, 100),
        message=_clean_text(message, 300),
        field=_clean_text(field, 200) if field else None,
        details=_safe_details(details),
    )


@dataclass(frozen=True, slots=True)
class NormalizedLabel:
    """
    One normalized synthetic label record.

    This is internal-facing. Public summaries must not expose subject-label
    pairs.
    """

    subject_ref_hash: str
    label_code: int
    weight: float = 1.0
    split: Optional[str] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize label record values.
        """
        object.__setattr__(
            self,
            "subject_ref_hash",
            _clean_text(self.subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower(),
        )
        object.__setattr__(self, "label_code", int(self.label_code))
        object.__setattr__(
            self,
            "weight",
            _clip_float(self.weight, 0.0, _MAX_WEIGHT, 1.0),
        )
        object.__setattr__(self, "split", _normalize_split(self.split))
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(_safe_detail_value(self.metadata) or {}),
        )


@dataclass(slots=True)
class LabelValidationResult:
    """
    Safe label validation result.

    The `accepted` list is internal-facing. Public summaries deliberately
    exclude accepted records.
    """

    ok: bool = True
    submitted: int = 0

    accepted: list[NormalizedLabel] = dataclass_field(default_factory=list)
    rejected: list[int] = dataclass_field(default_factory=list)
    issues: list[LabelIssue] = dataclass_field(default_factory=list)
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)

    max_issues: int = _DEFAULT_MAX_ISSUES

    _error_count: int = dataclass_field(default=0, repr=False, compare=False)
    _warning_count: int = dataclass_field(default=0, repr=False, compare=False)
    _issue_truncated: bool = dataclass_field(default=False, repr=False, compare=False)

    def add_issue(self, issue: LabelIssue) -> bool:
        """
        Add one safe issue entry.

        Returns False when the bounded issue list is already truncated.
        """
        if self._issue_truncated:
            if issue.severity == "error":
                self.ok = False
            return False

        if len(self.issues) >= max(1, int(self.max_issues)):
            self._issue_truncated = True
            self.issues.append(
                _issue(
                    severity="warning",
                    code="issue_list_truncated",
                    message="Issue list truncated by configured limit.",
                )
            )

            if issue.severity == "error":
                self.ok = False

            return False

        self.issues.append(issue)

        if issue.severity == "error":
            self._error_count += 1
            self.ok = False
        elif issue.severity == "warning":
            self._warning_count += 1

        return True

    def add_error(
        self,
        *,
        code: str,
        message: str,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe error entry.
        """
        return self.add_issue(
            _issue(
                severity="error",
                code=code,
                message=message,
                field=field,
                details=details,
            )
        )

    def add_warning(
        self,
        *,
        code: str,
        message: str,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe warning entry.
        """
        return self.add_issue(
            _issue(
                severity="warning",
                code=code,
                message=message,
                field=field,
                details=details,
            )
        )

    def add_info(
        self,
        *,
        code: str,
        message: str,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe info entry.
        """
        return self.add_issue(
            _issue(
                severity="info",
                code=code,
                message=message,
                field=field,
                details=details,
            )
        )

    def finalize(self, options: Optional[LabelOptions] = None) -> None:
        """
        Finalize safe metadata for the result.
        """
        self.metadata.update(
            {
                "labels_version": LABELS_VERSION,
                "submitted": self.submitted,
                "accepted_count": len(self.accepted),
                "rejected_count": len(self.rejected),
                "error_count": self._error_count,
                "warning_count": self._warning_count,
                "issue_truncated": self._issue_truncated,
                "caveats": list(_LABEL_CAVEATS),
                "safety_flags": dict(_LABEL_SAFETY_FLAGS),
            }
        )

        if options is not None:
            self.metadata["options"] = options.safe_summary()

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include accepted subject-label pairs.
        """
        return {
            "ok": self.ok,
            "counts": {
                "submitted": self.submitted,
                "accepted": len(self.accepted),
                "rejected": len(self.rejected),
                "errors": self._error_count,
                "warnings": self._warning_count,
            },
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_LABEL_CAVEATS),
            "safety_flags": dict(_LABEL_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Label record validation
# -----------------------------------------------------------------------------


def _extract_subject_ref(
    record: Mapping[str, Any],
    options: LabelOptions,
) -> Optional[str]:
    """
    Extract or derive a pseudonymous subject reference.

    Raw identifiers are never retained. Non-hash values are hashed.
    """
    candidates: tuple[tuple[str, bool], ...] = (
        ("subject_ref_hash", True),
        ("subject_hash", True),
        ("subject", False),
        ("account_id", False),
        ("account", False),
        ("id", False),
    )

    for field_name, is_hash_field in candidates:
        value = record.get(field_name)
        text = _clean_text(value, _MAX_TEXT_LENGTH)

        if not text:
            continue

        if is_hash_field and _is_safe_hash(text):
            return text.lower()

        return _subject_hash(text, options.salt, options.namespace)

    return None


def _extract_label_value(record: Mapping[str, Any]) -> Any:
    """
    Extract a label-like value from controlled label fields only.
    """
    for field_name in ("label_code", "label", "target", "y", "synthetic_label"):
        if field_name not in record:
            continue

        value = record[field_name]

        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        return value

    return _MISSING


def validate_label_record(
    record: Any,
    taxonomy: LabelTaxonomy | None = None,
    options: LabelOptions | None = None,
) -> tuple[Optional[NormalizedLabel], list[LabelIssue]]:
    """
    Validate and normalize one synthetic label record.

    Returns `(normalized_label, issues)`.
    """
    active_taxonomy = taxonomy or get_label_taxonomy()
    opts = options or LabelOptions.from_settings()
    issues: list[LabelIssue] = []

    if not isinstance(record, Mapping):
        issues.append(
            _issue(
                severity="error",
                code="label_record_not_object",
                message="Label record must be a mapping.",
                details={"type": type(record).__name__},
            )
        )
        return None, issues

    for raw_key in record.keys():
        key = _clean_text(raw_key, 200)

        if _is_forbidden_label_input_key(key):
            issues.append(
                _issue(
                    severity="error",
                    code="forbidden_label_field",
                    message="Forbidden label field omitted.",
                    field=key,
                )
            )

    if any(issue.severity == "error" for issue in issues):
        return None, issues

    subject_ref_hash = _extract_subject_ref(record, opts)

    if not subject_ref_hash:
        issues.append(
            _issue(
                severity="error",
                code="missing_subject_reference",
                message="Label record is missing a subject reference.",
            )
        )
        return None, issues

    raw_label = _extract_label_value(record)

    if raw_label is _MISSING:
        label_code = int(opts.default_label_code)
        issues.append(
            _issue(
                severity="warning",
                code="missing_label_value",
                message="Label value was missing and defaulted.",
                details={"default_code": label_code},
            )
        )
    else:
        resolved = active_taxonomy.try_normalize(raw_label)

        if resolved is None:
            label_code = int(opts.default_label_code)
            issues.append(
                _issue(
                    severity="warning",
                    code="unknown_label_value",
                    message="Label value was unknown and defaulted.",
                    field="label",
                    details={"default_code": label_code},
                )
            )
        else:
            label_code = int(resolved)

    definition = active_taxonomy.get(label_code)

    if definition is None:
        label_code = int(active_taxonomy.default_code)
        issues.append(
            _issue(
                severity="warning",
                code="invalid_label_code",
                message="Label code was invalid and defaulted.",
                details={"default_code": label_code},
            )
        )
    elif not definition.enabled:
        issues.append(
            _issue(
                severity="warning",
                code="disabled_label_code",
                message="Label code is disabled in the active taxonomy.",
                details={"code": label_code},
            )
        )

    weight = _decimal_to_float(record.get("weight"), 1.0)
    weight = _clip_float(weight, 0.0, _MAX_WEIGHT, 1.0)

    split = _normalize_split(record.get("split"))

    metadata_value = record.get("metadata_json")
    if metadata_value is None:
        metadata_value = record.get("metadata")

    metadata = _safe_detail_value(metadata_value) or {}

    for raw_key, raw_value in record.items():
        key = _canonical_field_name(raw_key)

        if not key:
            continue

        if key in _LABEL_ALLOWED_FIELDS:
            continue

        issues.append(
            _issue(
                severity="warning",
                code="unknown_label_field_dropped",
                message="Unknown label field omitted.",
                field=_clean_text(raw_key, 200),
            )
        )

    normalized = NormalizedLabel(
        subject_ref_hash=subject_ref_hash,
        label_code=label_code,
        weight=weight,
        split=split,
        metadata=metadata,
    )

    return normalized, issues


def validate_label_records(
    records: Any,
    options: LabelOptions | None = None,
    taxonomy: LabelTaxonomy | None = None,
) -> LabelValidationResult:
    """
    Validate bounded synthetic label records.
    """
    opts = options or LabelOptions.from_settings()
    active_taxonomy = taxonomy or get_label_taxonomy()
    result = LabelValidationResult(max_issues=opts.max_issues)

    record_list = _as_sequence(records)
    result.submitted = len(record_list)

    if result.submitted > opts.max_labels:
        result.add_error(
            code="label_batch_too_large",
            message="Label batch exceeds configured maximum size.",
            details={
                "submitted": result.submitted,
                "max_labels": opts.max_labels,
            },
        )
        result.rejected.extend(range(result.submitted))
        result.finalize(opts)
        return result

    for index, record in enumerate(record_list):
        normalized, issues = validate_label_record(record, active_taxonomy, opts)

        for issue in issues:
            result.add_issue(issue)

        if normalized is None:
            result.rejected.append(index)
            continue

        result.accepted.append(normalized)

    result.finalize(opts)
    return result


# -----------------------------------------------------------------------------
# Label set model
# -----------------------------------------------------------------------------


def _compute_label_set_fingerprint(
    taxonomy_version: str,
    subject_hashes: Sequence[str],
    label_codes: Sequence[int],
    splits: Sequence[str],
    weights: Sequence[float],
) -> str:
    """
    Compute a streaming deterministic fingerprint for a label set.
    """
    digest = hashlib.sha256()
    digest.update(
        f"muleguard.ml.labels.{LABELS_VERSION}|{taxonomy_version}|{len(subject_hashes)}".encode(
            "utf-8",
            errors="replace",
        )
    )

    for subject, code, split, weight in zip(
        subject_hashes,
        label_codes,
        splits,
        weights,
    ):
        digest.update(
            f"{subject}\x00{int(code)}\x00{split}\x00{float(weight):.6f}\n".encode(
                "utf-8",
                errors="replace",
            )
        )

    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class LabelSet:
    """
    Internal-facing bounded synthetic label set.

    Public summaries deliberately exclude subject-label pairs.
    """

    label_set_id: str
    taxonomy_version: str
    generated_at: datetime
    subject_hashes: tuple[str, ...] = ()
    label_codes: tuple[int, ...] = ()
    splits: tuple[str, ...] = ()
    weights: tuple[float, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize label set values and compute missing identity fields.
        """
        subject_hashes = tuple(
            _clean_text(item, _MAX_SUBJECT_HASH_LENGTH).lower()
            for item in (self.subject_hashes or ())
        )
        label_codes = tuple(int(item) for item in (self.label_codes or ()))
        splits = tuple(
            _normalize_split(item) or "train"
            for item in (self.splits or ())
        )
        weights = tuple(
            round(_clip_float(item, 0.0, _MAX_WEIGHT, 1.0), 6)
            for item in (self.weights or ())
        )

        length = min(len(subject_hashes), len(label_codes), len(splits), len(weights))
        subject_hashes = subject_hashes[:length]
        label_codes = label_codes[:length]
        splits = splits[:length]
        weights = weights[:length]

        generated_at = _ensure_utc(self.generated_at) or _now_utc()
        taxonomy_version = _clean_text(self.taxonomy_version, 32) or LABEL_TAXONOMY_VERSION

        if not self.fingerprint:
            fingerprint = _compute_label_set_fingerprint(
                taxonomy_version,
                subject_hashes,
                label_codes,
                splits,
                weights,
            )
        else:
            fingerprint = _clean_text(self.fingerprint, 128)

        label_set_id = _clean_text(self.label_set_id, 128) or fingerprint[:32]

        object.__setattr__(self, "subject_hashes", subject_hashes)
        object.__setattr__(self, "label_codes", label_codes)
        object.__setattr__(self, "splits", splits)
        object.__setattr__(self, "weights", weights)
        object.__setattr__(self, "generated_at", generated_at)
        object.__setattr__(self, "taxonomy_version", taxonomy_version)
        object.__setattr__(self, "fingerprint", fingerprint)
        object.__setattr__(self, "label_set_id", label_set_id)
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata or {})))
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts or {})))

    def __len__(self) -> int:
        """
        Return the number of labeled subjects.
        """
        return len(self.subject_hashes)

    def __iter__(self):
        """
        Iterate internal subject-label tuples.

        This is internal-facing and must not be exposed publicly.
        """
        return zip(
            self.subject_hashes,
            self.label_codes,
            self.splits,
            self.weights,
        )

    def label_for(self, subject_ref_hash: Any) -> Optional[int]:
        """
        Return the internal label code for one subject hash.
        """
        target = _clean_text(subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower()

        for subject, code in zip(self.subject_hashes, self.label_codes):
            if subject == target:
                return int(code)

        return None

    def indices_for_split(self, split: str) -> tuple[int, ...]:
        """
        Return indices belonging to one split.
        """
        normalized = _normalize_split(split) or "train"
        return tuple(
            index
            for index, item in enumerate(self.splits)
            if item == normalized
        )

    def subset(self, split: str) -> "LabelSet":
        """
        Return a new label set containing one split.
        """
        indices = self.indices_for_split(split)
        normalized = _normalize_split(split) or "train"

        metadata = dict(self.metadata)
        metadata["subset_of"] = self.label_set_id
        metadata["subset_split"] = normalized

        counts = Counter(self.splits[index] for index in indices)

        return LabelSet(
            label_set_id="",
            taxonomy_version=self.taxonomy_version,
            generated_at=_now_utc(),
            subject_hashes=tuple(self.subject_hashes[index] for index in indices),
            label_codes=tuple(self.label_codes[index] for index in indices),
            splits=tuple(self.splits[index] for index in indices),
            weights=tuple(self.weights[index] for index in indices),
            metadata=metadata,
            counts={f"split_{key}": int(value) for key, value in counts.items()},
            fingerprint="",
        )

    def binary_labels(self, positive_codes: Optional[Iterable[int]] = None) -> tuple[int, ...]:
        """
        Return binary synthetic evaluation labels.

        Mapping:

        - positive codes -> 1
        - negative codes -> 0
        - uncertain or unknown -> -1
        """
        taxonomy = get_label_taxonomy(self.taxonomy_version)
        positives = {int(code) for code in (positive_codes or taxonomy.positive_codes)}
        negatives = {int(code) for code in taxonomy.negative_codes}

        out: list[int] = []

        for code in self.label_codes:
            if int(code) in positives:
                out.append(1)
            elif int(code) in negatives:
                out.append(0)
            else:
                out.append(-1)

        return tuple(out)

    def class_distribution(self) -> dict[str, float]:
        """
        Return safe label class distribution.
        """
        total = len(self.label_codes)

        if total <= 0:
            return {}

        taxonomy = get_label_taxonomy(self.taxonomy_version)
        counter = Counter(self.label_codes)

        return {
            taxonomy.decode(code): float(count) / float(total)
            for code, count in sorted(counter.items())
        }

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include subject-label pairs.
        """
        return {
            "label_set_id": self.label_set_id,
            "taxonomy_version": self.taxonomy_version,
            "generated_at": self.generated_at.isoformat(),
            "subject_count": len(self.subject_hashes),
            "fingerprint": self.fingerprint,
            "counts": dict(self.counts),
            "class_distribution": self.class_distribution(),
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_LABEL_CAVEATS),
            "safety_flags": dict(_LABEL_SAFETY_FLAGS),
        }

    def to_internal_dict(self) -> dict[str, Any]:
        """
        Return a fuller internal representation.

        This contains subject-label pairs and must not be exposed publicly.
        """
        payload = self.to_public_dict()
        payload["records"] = [
            {
                "subject_ref_hash": subject,
                "label_code": int(code),
                "split": split,
                "weight": float(weight),
            }
            for subject, code, split, weight in self
        ]
        return payload


# -----------------------------------------------------------------------------
# Label construction helpers
# -----------------------------------------------------------------------------


def _fallback_label_code(options: LabelOptions, taxonomy: LabelTaxonomy) -> int:
    """
    Return a safe fallback label code.
    """
    default = int(options.default_label_code)

    definition = taxonomy.get(default)

    if definition is not None and definition.enabled and default != int(LabelCode.UNKNOWN):
        return default

    no_action = taxonomy.get(int(LabelCode.NO_ACTION))

    if no_action is not None and no_action.enabled:
        return int(LabelCode.NO_ACTION)

    trainable = taxonomy.trainable_codes

    if trainable:
        return int(trainable[0])

    return int(taxonomy.default_code)


def _resolve_rates(
    options: LabelOptions,
    taxonomy: LabelTaxonomy,
) -> dict[int, float]:
    """
    Resolve deterministic synthetic label sampling rates.
    """
    resolved: dict[int, float] = {}

    for raw_key, raw_value in (options.label_rates or {}).items():
        code = taxonomy.try_normalize(raw_key)

        if code is None:
            continue

        definition = taxonomy.get(code)

        if definition is None or not definition.enabled:
            continue

        if code == int(LabelCode.UNKNOWN):
            continue

        weight = _decimal_to_float(raw_value, 0.0)

        if weight > 0:
            resolved[int(code)] = weight

    if resolved:
        total = sum(resolved.values())

        if total > 0:
            return {code: weight / total for code, weight in resolved.items()}

    default_rates = {
        int(LabelCode.NO_ACTION): 0.70,
        int(LabelCode.REVIEW): 0.18,
        int(LabelCode.ESCALATE): 0.07,
        int(LabelCode.UNCERTAIN): 0.05,
    }

    out: dict[int, float] = {}

    for code, weight in default_rates.items():
        definition = taxonomy.get(code)

        if definition is not None and definition.enabled:
            out[code] = weight

    if out:
        total = sum(out.values())
        return {code: weight / total for code, weight in out.items()}

    trainable = taxonomy.trainable_codes

    if trainable:
        uniform = 1.0 / float(len(trainable))
        return {int(code): uniform for code in trainable}

    return {}


def _sample_label(
    rng: random.Random,
    rates: Mapping[int, float],
    fallback: int,
) -> int:
    """
    Sample one synthetic label code from resolved rates.
    """
    if not rates:
        return int(fallback)

    items = sorted(rates.items(), key=lambda item: item[0])
    total = sum(max(0.0, float(weight)) for _, weight in items)

    if total <= 0:
        return int(fallback)

    threshold = rng.random() * total
    cumulative = 0.0

    for code, weight in items:
        cumulative += max(0.0, float(weight))

        if threshold <= cumulative:
            return int(code)

    return int(items[-1][0]) if items else int(fallback)


def _choose_alternate_label(
    rng: random.Random,
    current_code: int,
    taxonomy: LabelTaxonomy,
) -> Optional[int]:
    """
    Choose an alternate enabled label code for synthetic noise injection.
    """
    candidates = [
        code
        for code in taxonomy.trainable_codes
        if int(code) != int(current_code)
    ]

    if not candidates:
        return None

    return int(rng.choice(candidates))


def _split_counts(
    n: int,
    train_ratio: float,
    validation_ratio: float,
    test_ratio: float,
) -> tuple[int, int, int]:
    """
    Return deterministic split counts for one group.
    """
    if n <= 0:
        return 0, 0, 0

    train_n = int(math.floor(n * max(0.0, train_ratio) + 0.5))
    train_n = max(0, min(train_n, n))

    remaining = n - train_n

    if validation_ratio + test_ratio <= 0:
        validation_n = 0
        test_n = remaining
    else:
        validation_share = validation_ratio / (validation_ratio + test_ratio)
        validation_n = int(math.floor(remaining * validation_share + 0.5))
        validation_n = max(0, min(validation_n, remaining))
        test_n = remaining - validation_n

    return train_n, validation_n, test_n


def _assign_splits(
    label_codes: Sequence[int],
    existing_splits: Sequence[Optional[str]],
    options: LabelOptions,
    taxonomy: LabelTaxonomy,
) -> tuple[str, ...]:
    """
    Assign deterministic splits while preserving valid external splits.
    """
    n = len(label_codes)
    result: list[str] = [
        _normalize_split(split) or ""
        for split in existing_splits
    ]

    missing = [index for index, split in enumerate(result) if not split]

    if not missing:
        return tuple(item or "train" for item in result)

    if options.stratify:
        groups: dict[int, list[int]] = defaultdict(list)

        for index in missing:
            groups[int(label_codes[index])].append(index)

        for code, indices in sorted(groups.items()):
            order = list(indices)
            rng = random.Random(
                _stable_seed(
                    options.seed,
                    options.namespace,
                    options.split_salt,
                    taxonomy.version,
                    "stratified",
                    int(code),
                    len(order),
                )
            )
            rng.shuffle(order)

            train_n, validation_n, test_n = _split_counts(
                len(order),
                options.split_train,
                options.split_validation,
                options.split_test,
            )

            for position, index in enumerate(order):
                if position < train_n:
                    result[index] = "train"
                elif position < train_n + validation_n:
                    result[index] = "validation"
                else:
                    result[index] = "test"
    else:
        order = list(missing)
        rng = random.Random(
            _stable_seed(
                options.seed,
                options.namespace,
                options.split_salt,
                taxonomy.version,
                "global",
                len(order),
            )
        )
        rng.shuffle(order)

        train_n, validation_n, test_n = _split_counts(
            len(order),
            options.split_train,
            options.split_validation,
            options.split_test,
        )

        for position, index in enumerate(order):
            if position < train_n:
                result[index] = "train"
            elif position < train_n + validation_n:
                result[index] = "validation"
            else:
                result[index] = "test"

    for index, split in enumerate(result):
        if not split:
            result[index] = "train"

    return tuple(result)


def _balance_weights(
    label_codes: Sequence[int],
    base_weights: Sequence[float],
    options: LabelOptions,
) -> tuple[float, ...]:
    """
    Return bounded class-balanced weights.
    """
    weights = [
        _clip_float(weight, 0.0, _MAX_WEIGHT, 1.0)
        for weight in base_weights
    ]

    if not options.balance_classes:
        return tuple(round(weight, 6) for weight in weights)

    counts = Counter(
        int(code)
        for code in label_codes
        if int(code) != int(LabelCode.UNKNOWN)
    )

    total = len(label_codes)
    class_count = len(counts)

    if total <= 0 or class_count <= 0:
        return tuple(round(weight, 6) for weight in weights)

    out: list[float] = []

    for code, weight in zip(label_codes, weights):
        resolved_code = int(code)

        if resolved_code == int(LabelCode.UNKNOWN):
            out.append(0.0)
            continue

        class_total = counts.get(resolved_code, 0)

        if class_total <= 0:
            out.append(0.0)
            continue

        base = float(total) / (float(class_count) * float(class_total))
        balanced = float(weight) * base
        out.append(_clip_float(balanced, 0.0, _MAX_WEIGHT, 0.0))

    return tuple(round(value, 6) for value in out)


# -----------------------------------------------------------------------------
# Label builder
# -----------------------------------------------------------------------------


class LabelBuilder:
    """
    Bounded synthetic ML label builder.

    This builder constructs internal label sets from synthetic accounts and/or
    controlled synthetic label fixtures.
    """

    def __init__(
        self,
        options: LabelOptions | None = None,
        taxonomy: LabelTaxonomy | None = None,
    ) -> None:
        self.options = options or LabelOptions.from_settings()
        self.taxonomy = taxonomy or get_label_taxonomy(self.options.taxonomy_version)
        self._lock = threading.RLock()

    def build(
        self,
        dataset: Any = None,
        account_ids: Optional[Iterable[str]] = None,
        label_records: Any = None,
        observation_time: Optional[datetime] = None,
    ) -> LabelSet:
        """
        Build one bounded synthetic label set.

        Args:
            dataset: Optional dataset-like object containing accounts and/or
                labels.
            account_ids: Optional explicit account identifiers to label.
            label_records: Optional controlled synthetic label records.
            observation_time: Optional timestamp for metadata.

        Returns:
            Internal-facing LabelSet. Public summaries must use
            `LabelSet.to_public_dict()`.
        """
        opts = self.options
        taxonomy = self.taxonomy
        generated_at = _ensure_utc(observation_time) or _now_utc()
        validation = LabelValidationResult(max_issues=opts.max_issues)

        if not opts.enabled:
            validation.add_info(
                code="labels_disabled",
                message="Synthetic label construction is disabled.",
            )
            validation.finalize(opts)
            return _empty_label_set(taxonomy, generated_at, validation)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            validation.add_error(
                code="non_synthetic_dataset",
                message="Synthetic label construction requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            validation.finalize(opts)
            return _empty_label_set(taxonomy, generated_at, validation)

        if opts.production_like and not opts.allow_in_production:
            validation.add_error(
                code="production_like_blocked",
                message="Synthetic label construction is blocked in production-like environments.",
            )
            validation.finalize(opts)
            return _empty_label_set(taxonomy, generated_at, validation)

        if opts.taxonomy_version and opts.taxonomy_version != taxonomy.version:
            validation.add_warning(
                code="taxonomy_version_fallback",
                message="Requested taxonomy version is unavailable; using bundled taxonomy.",
                details={
                    "requested": opts.taxonomy_version,
                    "active": taxonomy.version,
                },
            )

        with self._lock:
            subjects, external, truncated_subjects = self._collect_subjects(
                dataset=dataset,
                account_ids=account_ids,
                label_records=label_records,
                validation=validation,
            )

            if not subjects:
                validation.add_warning(
                    code="no_label_subjects",
                    message="No synthetic subjects were available for label construction.",
                )
                validation.finalize(opts)
                return _empty_label_set(taxonomy, generated_at, validation, truncated_subjects=truncated_subjects)

            records = self._assign_labels(
                subjects=subjects,
                external=external,
                validation=validation,
            )

            if not records:
                validation.add_warning(
                    code="no_labels_after_filtering",
                    message="All synthetic subjects were dropped during label construction.",
                )
                validation.finalize(opts)
                return _empty_label_set(taxonomy, generated_at, validation, truncated_subjects=truncated_subjects)

            subject_hashes = tuple(item.subject_ref_hash for item in records)
            label_codes = tuple(int(item.label_code) for item in records)
            base_weights = tuple(float(item.weight) for item in records)
            existing_splits = tuple(item.split for item in records)

            splits = _assign_splits(label_codes, existing_splits, opts, taxonomy)
            weights = _balance_weights(label_codes, base_weights, opts)

            counts = self._build_counts(
                records=records,
                splits=splits,
                taxonomy=taxonomy,
                truncated_subjects=truncated_subjects,
            )

            quality = self._build_quality(
                label_codes=label_codes,
                splits=splits,
                taxonomy=taxonomy,
                options=opts,
            )

            fingerprint = _compute_label_set_fingerprint(
                taxonomy.version,
                subject_hashes,
                label_codes,
                splits,
                weights,
            )

            metadata: dict[str, Any] = {
                "labels_version": LABELS_VERSION,
                "taxonomy_version": taxonomy.version,
                "taxonomy_fingerprint": taxonomy.fingerprint(),
                "generated_at": generated_at.isoformat(),
                "observation_time": generated_at.isoformat(),
                "options": opts.safe_summary(),
                "quality": quality,
                "validation": validation.to_response_dict(),
                "caveats": list(_LABEL_CAVEATS),
                "safety_flags": dict(_LABEL_SAFETY_FLAGS),
            }

            if not opts.emit_internal_labels:
                metadata["internal_labels_emitted"] = False
                subject_hashes = ()
                label_codes = ()
                splits = ()
                weights = ()
                fingerprint = _compute_label_set_fingerprint(
                    taxonomy.version,
                    (),
                    (),
                    (),
                    (),
                )
            else:
                metadata["internal_labels_emitted"] = True

            return LabelSet(
                label_set_id=fingerprint[:32],
                taxonomy_version=taxonomy.version,
                generated_at=generated_at,
                subject_hashes=subject_hashes,
                label_codes=label_codes,
                splits=splits,
                weights=weights,
                metadata=metadata,
                counts=counts,
                fingerprint=fingerprint,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_subjects(
        self,
        dataset: Any,
        account_ids: Optional[Iterable[str]],
        label_records: Any,
        validation: LabelValidationResult,
    ) -> tuple[tuple[str, ...], dict[str, NormalizedLabel], int]:
        """
        Collect bounded pseudonymous subjects and controlled external labels.
        """
        opts = self.options
        subjects: list[str] = []
        seen: set[str] = set()
        external: dict[str, NormalizedLabel] = {}

        def add_hash(subject_hash: str) -> None:
            cleaned = _clean_text(subject_hash, _MAX_SUBJECT_HASH_LENGTH).lower()

            if not cleaned or cleaned in seen:
                return

            seen.add(cleaned)
            subjects.append(cleaned)

        def add_identifier(identifier: Any) -> None:
            text = _clean_text(identifier, _MAX_TEXT_LENGTH)

            if not text:
                return

            if _is_safe_hash(text):
                add_hash(text)
                return

            add_hash(_subject_hash(text, opts.salt, opts.namespace))

        raw_accounts = _as_sequence(
            _get_source_collection(dataset, ("accounts", "account_records"))
        )

        for record in raw_accounts:
            if len(subjects) >= opts.max_subjects * 2:
                break

            account_id = _extract_account_id(record)

            if account_id:
                add_identifier(account_id)

        if account_ids is not None:
            for account_id in account_ids:
                if len(subjects) >= opts.max_subjects * 2:
                    break

                add_identifier(account_id)

        raw_labels = label_records

        if raw_labels is None:
            raw_labels = _get_source_collection(
                dataset,
                ("labels", "label_records", "targets"),
            )

        if opts.allow_external_labels and raw_labels is not None:
            label_list = _as_sequence(raw_labels)

            if len(label_list) > opts.max_labels:
                validation.add_warning(
                    code="external_labels_truncated",
                    message="External label input exceeded configured limit and was truncated.",
                    details={
                        "submitted": len(label_list),
                        "max_labels": opts.max_labels,
                    },
                )
                label_list = label_list[: opts.max_labels]

            for record in label_list:
                normalized, issues = validate_label_record(record, self.taxonomy, opts)

                for issue in issues:
                    validation.add_issue(issue)

                if normalized is None:
                    continue

                external[normalized.subject_ref_hash] = normalized
                add_hash(normalized.subject_ref_hash)

        subjects.sort()

        truncated_subjects = 0

        if len(subjects) > opts.max_subjects:
            truncated_subjects = len(subjects) - opts.max_subjects
            validation.add_warning(
                code="subjects_truncated",
                message="Subject list exceeded configured limit and was truncated.",
                details={
                    "submitted": len(subjects),
                    "max_subjects": opts.max_subjects,
                },
            )
            subjects = subjects[: opts.max_subjects]

        return tuple(subjects), external, truncated_subjects

    def _assign_labels(
        self,
        subjects: Sequence[str],
        external: Mapping[str, NormalizedLabel],
        validation: LabelValidationResult,
    ) -> list[NormalizedLabel]:
        """
        Assign deterministic synthetic labels to subjects.
        """
        opts = self.options
        taxonomy = self.taxonomy
        fallback = _fallback_label_code(opts, taxonomy)
        rates = _resolve_rates(opts, taxonomy)

        rng = random.Random(
            _stable_seed(
                opts.seed,
                opts.namespace,
                taxonomy.version,
                "labels",
                len(subjects),
            )
        )

        records: list[NormalizedLabel] = []
        dropped_uncertain = 0
        noisy_flips = 0

        for subject in subjects:
            ext = external.get(subject)

            if ext is not None:
                label_code = int(ext.label_code)
                weight = float(ext.weight)
                split = ext.split
                metadata = dict(ext.metadata)
            else:
                label_code = _sample_label(rng, rates, fallback)
                weight = 1.0
                split = None
                metadata = {}

            if not opts.include_uncertain and taxonomy.is_uncertain(label_code):
                if opts.drop_uncertain:
                    dropped_uncertain += 1
                    continue

                label_code = fallback

            if opts.noise_rate > 0 and rng.random() < opts.noise_rate:
                alternate = _choose_alternate_label(rng, label_code, taxonomy)

                if alternate is not None:
                    label_code = alternate
                    noisy_flips += 1

            records.append(
                NormalizedLabel(
                    subject_ref_hash=subject,
                    label_code=label_code,
                    weight=weight,
                    split=split,
                    metadata=metadata,
                )
            )

        if dropped_uncertain:
            validation.add_info(
                code="uncertain_labels_dropped",
                message="Uncertain synthetic labels were dropped by policy.",
                details={"dropped_count": dropped_uncertain},
            )

        if noisy_flips:
            validation.add_info(
                code="synthetic_label_noise_applied",
                message="Deterministic synthetic label noise was applied.",
                details={
                    "noise_rate": round(opts.noise_rate, 6),
                    "flipped_count": noisy_flips,
                },
            )

        return records

    def _build_counts(
        self,
        records: Sequence[NormalizedLabel],
        splits: Sequence[str],
        taxonomy: LabelTaxonomy,
        truncated_subjects: int,
    ) -> dict[str, int]:
        """
        Build safe count metadata.
        """
        label_counter = Counter(int(record.label_code) for record in records)
        split_counter = Counter(splits)
        external_count = sum(
            1
            for record in records
            if record.metadata.get("source") == "external"
        )

        counts: dict[str, int] = {
            "subjects": len(records),
            "external": external_count,
            "synthesized": len(records) - external_count,
            "unlabeled": int(label_counter.get(int(LabelCode.UNKNOWN), 0)),
            "truncated_subjects": int(truncated_subjects),
        }

        for split in ("train", "validation", "test"):
            counts[f"split_{split}"] = int(split_counter.get(split, 0))

        for code, count in sorted(label_counter.items()):
            name = taxonomy.decode(code)
            counts[f"label_{name}"] = int(count)

        return counts

    def _build_quality(
        self,
        label_codes: Sequence[int],
        splits: Sequence[str],
        taxonomy: LabelTaxonomy,
        options: LabelOptions,
    ) -> dict[str, Any]:
        """
        Build safe label quality diagnostics.
        """
        total = len(label_codes)

        if total <= 0:
            return {
                "class_count": 0,
                "entropy": 0.0,
                "imbalance_ratio": 0.0,
                "max_class_share": 0.0,
                "min_class_count": 0,
                "split_overlap": 0,
                "warnings": ["empty_label_set"],
            }

        counter = Counter(int(code) for code in label_codes)
        distribution = {
            taxonomy.decode(code): float(count) / float(total)
            for code, count in sorted(counter.items())
        }

        labeled_counts = [
            count
            for code, count in counter.items()
            if int(code) != int(LabelCode.UNKNOWN)
        ]

        entropy = _normalized_entropy(counter)
        max_class_share = max(distribution.values(), default=0.0)
        min_class_count = min(labeled_counts, default=0)
        max_class_count = max(labeled_counts, default=0)
        imbalance_ratio = (
            float(max_class_count) / float(min_class_count)
            if min_class_count > 0
            else 0.0
        )

        split_sets = {
            split: {
                index
                for index, item in enumerate(splits)
                if item == split
            }
            for split in ("train", "validation", "test")
        }

        split_overlap = 0

        for left in ("train", "validation", "test"):
            for right in ("train", "validation", "test"):
                if left >= right:
                    continue

                split_overlap += len(split_sets[left] & split_sets[right])

        warnings: list[str] = []

        if max_class_share > options.max_class_share:
            warnings.append("class_share_above_target")

        if min_class_count < options.min_class_count:
            warnings.append("class_count_below_minimum")

        if split_overlap:
            warnings.append("split_overlap_detected")

        return {
            "class_count": len(counter),
            "distribution": {
                key: round(float(value), 6)
                for key, value in distribution.items()
            },
            "entropy": round(float(entropy), 6),
            "imbalance_ratio": round(float(imbalance_ratio), 6),
            "max_class_share": round(float(max_class_share), 6),
            "min_class_count": int(min_class_count),
            "max_class_count": int(max_class_count),
            "split_overlap": int(split_overlap),
            "warnings": warnings,
        }


def _empty_label_set(
    taxonomy: LabelTaxonomy,
    generated_at: datetime,
    validation: LabelValidationResult,
    truncated_subjects: int = 0,
) -> LabelSet:
    """
    Return a safe empty label set.
    """
    fingerprint = _compute_label_set_fingerprint(
        taxonomy.version,
        (),
        (),
        (),
        (),
    )

    metadata: dict[str, Any] = {
        "labels_version": LABELS_VERSION,
        "taxonomy_version": taxonomy.version,
        "taxonomy_fingerprint": taxonomy.fingerprint(),
        "generated_at": generated_at.isoformat(),
        "observation_time": generated_at.isoformat(),
        "quality": {
            "class_count": 0,
            "entropy": 0.0,
            "imbalance_ratio": 0.0,
            "max_class_share": 0.0,
            "min_class_count": 0,
            "split_overlap": 0,
            "warnings": ["empty_label_set"],
        },
        "validation": validation.to_response_dict(),
        "caveats": list(_LABEL_CAVEATS),
        "safety_flags": dict(_LABEL_SAFETY_FLAGS),
    }

    counts = {
        "subjects": 0,
        "external": 0,
        "synthesized": 0,
        "unlabeled": 0,
        "truncated_subjects": int(truncated_subjects),
        "split_train": 0,
        "split_validation": 0,
        "split_test": 0,
    }

    return LabelSet(
        label_set_id=fingerprint[:32],
        taxonomy_version=taxonomy.version,
        generated_at=generated_at,
        subject_hashes=(),
        label_codes=(),
        splits=(),
        weights=(),
        metadata=metadata,
        counts=counts,
        fingerprint=fingerprint,
    )


# -----------------------------------------------------------------------------
# Feature-label leakage guards
# -----------------------------------------------------------------------------


def scan_feature_vector_for_label_leakage(
    features: Mapping[str, Any],
    taxonomy: LabelTaxonomy | None = None,
) -> list[LabelIssue]:
    """
    Scan a feature mapping for label-like leakage fields.

    This is a defensive helper. Feature schema validation remains authoritative.
    """
    _ = taxonomy
    issues: list[LabelIssue] = []

    if not isinstance(features, Mapping):
        issues.append(
            _issue(
                severity="error",
                code="feature_vector_not_object",
                message="Feature vector must be a mapping.",
                details={"type": type(features).__name__},
            )
        )
        return issues

    for raw_key in features.keys():
        key = _clean_text(raw_key, 200)

        if _is_label_leakage_key(key):
            issues.append(
                _issue(
                    severity="error",
                    code="label_leakage_field",
                    message="Feature vector contains a label-like field.",
                    field=key,
                )
            )

    return issues


def assert_no_label_leakage(
    features: Mapping[str, Any],
    taxonomy: LabelTaxonomy | None = None,
) -> None:
    """
    Raise a safe validation error when label leakage fields are detected.
    """
    issues = scan_feature_vector_for_label_leakage(features, taxonomy=taxonomy)
    errors = [issue for issue in issues if issue.severity == "error"]

    if errors:
        raise MuleGuardValidationError(
            "Feature vector contains label-like leakage fields.",
            details={
                "issue_count": len(errors),
                "fields": [issue.field for issue in errors[:50] if issue.field],
            },
        )


# -----------------------------------------------------------------------------
# Default builder and public API
# -----------------------------------------------------------------------------


_default_builder: Optional[LabelBuilder] = None
_default_builder_lock = threading.Lock()


def get_label_builder(
    options: LabelOptions | None = None,
    taxonomy: LabelTaxonomy | None = None,
    *,
    rebuild: bool = False,
) -> LabelBuilder:
    """
    Return a process-wide label builder.

    If options or taxonomy are supplied, or rebuild is True, a new builder is
    constructed and becomes the default.
    """
    global _default_builder

    with _default_builder_lock:
        if (
            _default_builder is None
            or rebuild
            or options is not None
            or taxonomy is not None
        ):
            _default_builder = LabelBuilder(options=options, taxonomy=taxonomy)

        return _default_builder


def build_synthetic_labels(
    dataset: Any = None,
    account_ids: Optional[Iterable[str]] = None,
    label_records: Any = None,
    *,
    options: LabelOptions | None = None,
    taxonomy: LabelTaxonomy | None = None,
    observation_time: Optional[datetime] = None,
) -> LabelSet:
    """
    Build one bounded synthetic ML label set.

    This is the primary public helper for label construction.

    Args:
        dataset: Optional dataset-like object containing accounts and/or labels.
        account_ids: Optional explicit account identifiers to label.
        label_records: Optional controlled synthetic label records.
        options: Optional label policy. Resolved from settings when absent.
        taxonomy: Optional label taxonomy. Resolved from options when absent.
        observation_time: Optional timestamp for metadata.

    Returns:
        Internal-facing LabelSet. Public consumers should use
        `LabelSet.to_public_dict()` or `summarize_label_set()`.
    """
    builder = get_label_builder(options=options, taxonomy=taxonomy)

    return builder.build(
        dataset=dataset,
        account_ids=account_ids,
        label_records=label_records,
        observation_time=observation_time,
    )


def build_synthetic_label_set(
    dataset: Any = None,
    account_ids: Optional[Iterable[str]] = None,
    label_records: Any = None,
    *,
    options: LabelOptions | None = None,
    taxonomy: LabelTaxonomy | None = None,
    observation_time: Optional[datetime] = None,
) -> LabelSet:
    """
    Alias for `build_synthetic_labels`.
    """
    return build_synthetic_labels(
        dataset=dataset,
        account_ids=account_ids,
        label_records=label_records,
        options=options,
        taxonomy=taxonomy,
        observation_time=observation_time,
    )


def label_set_from_records(
    records: Any,
    *,
    options: LabelOptions | None = None,
    taxonomy: LabelTaxonomy | None = None,
    observation_time: Optional[datetime] = None,
) -> LabelSet:
    """
    Build a label set directly from controlled synthetic label records.

    This helper validates records first, then assigns deterministic splits and
    bounded class-balancing weights.
    """
    opts = options or LabelOptions.from_settings()
    tax = taxonomy or get_label_taxonomy(opts.taxonomy_version)
    generated_at = _ensure_utc(observation_time) or _now_utc()

    validation = validate_label_records(records, opts, tax)
    accepted = validation.accepted

    if not accepted:
        return _empty_label_set(tax, generated_at, validation)

    subject_hashes = tuple(item.subject_ref_hash for item in accepted)
    label_codes = tuple(int(item.label_code) for item in accepted)
    base_weights = tuple(float(item.weight) for item in accepted)
    existing_splits = tuple(item.split for item in accepted)

    splits = _assign_splits(label_codes, existing_splits, opts, tax)
    weights = _balance_weights(label_codes, base_weights, opts)

    builder = LabelBuilder(options=opts, taxonomy=tax)
    counts = builder._build_counts(accepted, splits, tax, 0)

    counts["external"] = len(accepted)
    counts["synthesized"] = 0

    quality = builder._build_quality(label_codes, splits, tax, opts)

    if opts.emit_internal_labels:
        stored_subject_hashes = subject_hashes
        stored_label_codes = label_codes
        stored_splits = splits
        stored_weights = weights
        internal_labels_emitted = True
    else:
        stored_subject_hashes = ()
        stored_label_codes = ()
        stored_splits = ()
        stored_weights = ()
        internal_labels_emitted = False

    fingerprint = _compute_label_set_fingerprint(
        tax.version,
        stored_subject_hashes,
        stored_label_codes,
        stored_splits,
        stored_weights,
    )

    metadata: dict[str, Any] = {
        "labels_version": LABELS_VERSION,
        "taxonomy_version": tax.version,
        "taxonomy_fingerprint": tax.fingerprint(),
        "generated_at": generated_at.isoformat(),
        "observation_time": generated_at.isoformat(),
        "options": opts.safe_summary(),
        "quality": quality,
        "validation": validation.to_response_dict(),
        "internal_labels_emitted": internal_labels_emitted,
        "caveats": list(_LABEL_CAVEATS),
        "safety_flags": dict(_LABEL_SAFETY_FLAGS),
    }

    return LabelSet(
        label_set_id=fingerprint[:32],
        taxonomy_version=tax.version,
        generated_at=generated_at,
        subject_hashes=stored_subject_hashes,
        label_codes=stored_label_codes,
        splits=stored_splits,
        weights=stored_weights,
        metadata=metadata,
        counts=counts,
        fingerprint=fingerprint,
    )


@dataclass(frozen=True, slots=True)
class AlignedLabelVectors:
    """
    Internal-facing alignment between synthetic feature vectors and labels.

    Public summaries deliberately exclude vectors and subject-label pairs.
    """

    vectors: tuple[Any, ...] = ()
    y: tuple[int, ...] = ()
    weights: tuple[float, ...] = ()
    subject_hashes: tuple[str, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize alignment lengths and metadata.
        """
        length = min(
            len(self.vectors or ()),
            len(self.y or ()),
            len(self.weights or ()),
            len(self.subject_hashes or ()),
        )

        object.__setattr__(self, "vectors", tuple(self.vectors[:length]))
        object.__setattr__(self, "y", tuple(int(item) for item in self.y[:length]))
        object.__setattr__(
            self,
            "weights",
            tuple(
                round(_clip_float(item, 0.0, _MAX_WEIGHT, 1.0), 6)
                for item in self.weights[:length]
            ),
        )
        object.__setattr__(
            self,
            "subject_hashes",
            tuple(
                _clean_text(item, _MAX_SUBJECT_HASH_LENGTH).lower()
                for item in self.subject_hashes[:length]
            ),
        )
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts or {})))
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(_safe_detail_value(self.metadata) or {}),
        )

    def __len__(self) -> int:
        """
        Return the number of aligned examples.
        """
        return len(self.y)

    def __iter__(self):
        """
        Iterate aligned subject-label-weight tuples.

        This is internal-facing and must not be exposed publicly.
        """
        return zip(self.subject_hashes, self.y, self.weights)

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include vectors, subject hashes, labels, or
        weights.
        """
        return {
            "aligned_count": len(self),
            "counts": dict(self.counts),
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_LABEL_CAVEATS),
            "safety_flags": dict(_LABEL_SAFETY_FLAGS),
        }

    def to_internal_dict(self) -> dict[str, Any]:
        """
        Return a fuller internal representation.

        This contains subject-label pairs and must not be exposed publicly.
        """
        payload = self.to_public_dict()
        payload["records"] = [
            {
                "subject_ref_hash": subject,
                "label_code": int(code),
                "weight": float(weight),
            }
            for subject, code, weight in self
        ]
        payload["vector_count"] = len(self.vectors)
        return payload


def _split_for_subject(
    label_set: LabelSet,
    subject_ref_hash: Any,
) -> Optional[str]:
    """
    Return the split assigned to one subject hash.
    """
    target = _clean_text(subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower()

    for subject, _code, split, _weight in label_set:
        if subject == target:
            return split

    return None


def _weight_for_subject(
    label_set: LabelSet,
    subject_ref_hash: Any,
) -> float:
    """
    Return the weight assigned to one subject hash.
    """
    target = _clean_text(subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower()

    for subject, _code, _split, weight in label_set:
        if subject == target:
            return _clip_float(weight, 0.0, _MAX_WEIGHT, 1.0)

    return 1.0


def align_labels_to_feature_vectors(
    label_set: LabelSet,
    feature_vectors: Any,
    *,
    split: Optional[str] = None,
    require_validation_ok: bool = False,
    scan_for_leakage: bool = True,
) -> AlignedLabelVectors:
    """
    Align synthetic feature vectors to internal labels by pseudonymous subject
    hash.

    This helper is internal-facing. It must not be exposed directly through
    public APIs.

    Args:
        label_set: Internal label set.
        feature_vectors: Sequence of feature vectors or feature mappings.
        split: Optional split filter.
        require_validation_ok: Skip vectors whose embedded validation failed.
        scan_for_leakage: Defensively skip vectors containing label-like fields.

    Returns:
        AlignedLabelVectors containing vectors, labels, weights, and safe counts.
    """
    vectors = _as_sequence(feature_vectors)
    normalized_split = _normalize_split(split) if split is not None else None

    aligned_vectors: list[Any] = []
    aligned_y: list[int] = []
    aligned_weights: list[float] = []
    aligned_subjects: list[str] = []

    counts: dict[str, int] = {
        "submitted": len(vectors),
        "aligned": 0,
        "skipped": 0,
        "missing_subject": 0,
        "unlabeled": 0,
        "split_mismatch": 0,
        "validation_failed": 0,
        "label_leakage": 0,
    }

    for index, vector in enumerate(vectors):
        subject: Any = None
        features: Any = None
        validation: Any = None

        if isinstance(vector, Mapping):
            subject = vector.get("subject_ref_hash") or vector.get("subject_hash")
            features = vector.get("features") if "features" in vector else vector
            validation = vector.get("validation")
        else:
            subject = getattr(vector, "subject_ref_hash", None)
            features = getattr(vector, "features", None)
            validation = getattr(vector, "validation", None)

        subject_text = _clean_text(subject, _MAX_SUBJECT_HASH_LENGTH).lower()

        if not subject_text:
            counts["skipped"] += 1
            counts["missing_subject"] += 1
            continue

        code = label_set.label_for(subject_text)

        if code is None or int(code) == int(LabelCode.UNKNOWN):
            counts["skipped"] += 1
            counts["unlabeled"] += 1
            continue

        if normalized_split is not None:
            actual_split = _normalize_split(_split_for_subject(label_set, subject_text))

            if actual_split != normalized_split:
                counts["skipped"] += 1
                counts["split_mismatch"] += 1
                continue

        if require_validation_ok and validation is not None:
            ok = getattr(validation, "ok", None)

            if ok is False:
                counts["skipped"] += 1
                counts["validation_failed"] += 1
                continue

        if scan_for_leakage and isinstance(features, Mapping):
            issues = scan_feature_vector_for_label_leakage(features)

            if any(issue.severity == "error" for issue in issues):
                counts["skipped"] += 1
                counts["label_leakage"] += 1
                continue

        weight = _weight_for_subject(label_set, subject_text)

        aligned_vectors.append(vector)
        aligned_y.append(int(code))
        aligned_weights.append(float(weight))
        aligned_subjects.append(subject_text)
        counts["aligned"] += 1

    counts["built"] = len(aligned_y)

    metadata: dict[str, Any] = {
        "labels_version": LABELS_VERSION,
        "label_set_id": label_set.label_set_id,
        "taxonomy_version": label_set.taxonomy_version,
        "label_set_fingerprint": label_set.fingerprint,
        "split_filter": normalized_split,
        "require_validation_ok": bool(require_validation_ok),
        "scan_for_leakage": bool(scan_for_leakage),
        "caveats": list(_LABEL_CAVEATS),
        "safety_flags": dict(_LABEL_SAFETY_FLAGS),
    }

    return AlignedLabelVectors(
        vectors=tuple(aligned_vectors),
        y=tuple(aligned_y),
        weights=tuple(round(weight, 6) for weight in aligned_weights),
        subject_hashes=tuple(aligned_subjects),
        counts=counts,
        metadata=metadata,
    )


def internal_supervised_arrays(
    aligned: AlignedLabelVectors,
) -> tuple[list[str], list[int], list[float]]:
    """
    Return internal subject hashes, labels, and weights.

    This is internal-facing and must not be exposed publicly.
    """
    return (
        list(aligned.subject_hashes),
        list(aligned.y),
        list(aligned.weights),
    )


def supervised_arrays_for_split(
    label_set: LabelSet,
    feature_vectors: Any,
    split: str,
    *,
    require_validation_ok: bool = False,
    scan_for_leakage: bool = True,
) -> tuple[list[str], list[int], list[float]]:
    """
    Return internal supervised arrays for one split.

    This is internal-facing and must not be exposed publicly.
    """
    aligned = align_labels_to_feature_vectors(
        label_set,
        feature_vectors,
        split=split,
        require_validation_ok=require_validation_ok,
        scan_for_leakage=scan_for_leakage,
    )

    return internal_supervised_arrays(aligned)


def binary_label_array(
    label_set: LabelSet,
    positive_codes: Optional[Iterable[int]] = None,
) -> tuple[int, ...]:
    """
    Return binary synthetic evaluation labels.

    Mapping:

    - positive codes -> 1
    - negative codes -> 0
    - uncertain or unknown -> -1
    """
    return label_set.binary_labels(positive_codes=positive_codes)


def iter_label_splits(label_set: LabelSet):
    """
    Iterate train, validation, and test label subsets.
    """
    for split in ("train", "validation", "test"):
        yield split, label_set.subset(split)


def label_set_split_summary(label_set: LabelSet) -> dict[str, Any]:
    """
    Return a safe per-split summary.

    This does not include subject-label pairs.
    """
    summary: dict[str, Any] = {}

    for split in ("train", "validation", "test"):
        subset = label_set.subset(split)

        summary[split] = {
            "count": len(subset),
            "fingerprint": subset.fingerprint,
            "class_distribution": subset.class_distribution(),
            "counts": dict(subset.counts),
        }

    summary["overall"] = {
        "count": len(label_set),
        "fingerprint": label_set.fingerprint,
        "class_distribution": label_set.class_distribution(),
        "counts": dict(label_set.counts),
    }

    return summary


def summarize_label_set(label_set: LabelSet) -> dict[str, Any]:
    """
    Return a safe API-facing label-set summary.
    """
    return label_set.to_public_dict()


def label_quality_report(label_set: LabelSet) -> dict[str, Any]:
    """
    Return a safe label-quality report.

    This does not include subject-label pairs.
    """
    metadata = dict(label_set.metadata or {})
    quality = metadata.get("quality") or {}
    validation = metadata.get("validation") or {}

    return {
        "label_set_id": label_set.label_set_id,
        "taxonomy_version": label_set.taxonomy_version,
        "generated_at": label_set.generated_at.isoformat(),
        "subject_count": len(label_set),
        "fingerprint": label_set.fingerprint,
        "counts": dict(label_set.counts),
        "class_distribution": label_set.class_distribution(),
        "split_summary": label_set_split_summary(label_set),
        "quality": _safe_detail_value(quality),
        "validation": _safe_detail_value(validation),
        "caveats": list(_LABEL_CAVEATS),
        "safety_flags": dict(_LABEL_SAFETY_FLAGS),
    }


def get_label_metadata() -> dict[str, Any]:
    """
    Return safe, serializable ML label-layer metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose raw labels, subject-label pairs, secrets, environment
    files, database URLs, tokens, passwords, raw complaint narratives,
    ground-truth labels, scenario IDs, fraud-ring IDs, model artifact paths, or
    real customer data.
    """
    taxonomy = get_label_taxonomy()
    options = LabelOptions.from_settings()
    builder = get_label_builder()

    return {
        "package": "muleguard.backend.ml.labels",
        "version": LABELS_VERSION,
        "taxonomy_version": taxonomy.version,
        "taxonomy_fingerprint": taxonomy.fingerprint(),
        "label_codes": [int(code) for code in taxonomy.enabled_codes],
        "trainable_codes": [int(code) for code in taxonomy.trainable_codes],
        "positive_codes": sorted(int(code) for code in taxonomy.positive_codes),
        "negative_codes": sorted(int(code) for code in taxonomy.negative_codes),
        "uncertain_codes": sorted(int(code) for code in taxonomy.uncertain_codes),
        "default_options": options.safe_summary(),
        "builder_backend": "in_memory_deterministic",
        "distributed": False,
        "durable": False,
        "hard_limits": {
            "max_labels": _HARD_MAX_LABELS,
            "max_subjects": _HARD_MAX_SUBJECTS,
            "max_classes": _HARD_MAX_CLASSES,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_noise_rate": _HARD_MAX_NOISE_RATE,
        },
        "forbidden_label_field_count": len(_LABEL_FORBIDDEN_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "taxonomy": taxonomy.summary(),
        "caveats": list(_LABEL_CAVEATS),
        "safety_flags": dict(_LABEL_SAFETY_FLAGS),
        "builder_stats": {
            "taxonomy_version": builder.taxonomy.version,
            "options": builder.options.safe_summary(),
        },
    }


__all__ = [
    "AlignedLabelVectors",
    "LabelBuilder",
    "LabelCode",
    "LabelDefinition",
    "LabelIssue",
    "LabelOptions",
    "LabelSet",
    "LabelTaxonomy",
    "LabelValidationResult",
    "NormalizedLabel",
    "align_labels_to_feature_vectors",
    "assert_no_label_leakage",
    "binary_label_array",
    "build_default_label_taxonomy",
    "build_synthetic_label_set",
    "build_synthetic_labels",
    "get_label_builder",
    "get_label_metadata",
    "get_label_taxonomy",
    "internal_supervised_arrays",
    "iter_label_splits",
    "label_quality_report",
    "label_set_from_records",
    "label_set_split_summary",
    "scan_feature_vector_for_label_leakage",
    "summarize_label_set",
    "supervised_arrays_for_split",
    "validate_label_record",
    "validate_label_records",
]