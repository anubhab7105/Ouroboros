"""
MULEGUARD backend ML splits.

This module provides the canonical train/validation/test split management layer
for the synthetic MULEGUARD machine-learning subsystem.

Primary responsibilities:

- create deterministic, bounded, reproducible ML splits for synthetic feature
  vectors, synthetic label sets, and controlled split inputs;
- support random, stratified, grouped, temporal, hybrid, and preserve-existing
  split strategies;
- prevent subject or group leakage across splits where the selected strategy
  requires isolation;
- preserve pseudonymous subject linkage using salted, domain-separated, one-way
  hashes;
- reject or omit leakage-prone fields such as ground-truth labels, injected
  scenario IDs, fraud-ring IDs, raw complaint narratives, raw identifiers,
  secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths;
- produce safe split plans whose public summaries do not expose subject-label
  pairs, raw identifiers, raw narratives, feature values, secrets, or sensitive
  metadata;
- provide split quality diagnostics, overlap detection, temporal sanity checks,
  class distribution summaries, bounded issue reporting, and deterministic
  fingerprints;
- remain import-safe, dependency-light, and usable by ML services, training
  harnesses, evaluation harnesses, tests, seeders, offline fixtures, and
  developer tooling.

This module manages splits only. It does not train models, score accounts,
evaluate models, persist data, call external systems, authenticate users,
authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for split construction.
- Synthetic labels are evaluation fixtures only. They are not proof of
  wrongdoing.
- Labels must never be returned in public split summaries, logs, diagnostics,
  exports, or artifacts.
- Subject linkage is pseudonymous. Raw identifiers are never retained in split
  plans.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone inputs.
- Split plans are operational ML hygiene artefacts only. They are not
  investigative conclusions and are not proof of wrongdoing.
- Split handling never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable split capabilities are reported honestly rather than
  invented.
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
- This module is not a durable split store. Production deployments should use a
  reviewed, access-controlled, audited experiment tracking or data versioning
  system if persistent split lineage is required.

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
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError

logger = logging.getLogger("muleguard.backend.ml.splits")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

SPLITS_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.splits.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_TRAIN_RATIO: Final[float] = 0.70
_DEFAULT_VALIDATION_RATIO: Final[float] = 0.15
_DEFAULT_TEST_RATIO: Final[float] = 0.15

_DEFAULT_MAX_ITEMS: Final[int] = 100_000
_HARD_MAX_ITEMS: Final[int] = 1_000_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MIN_ITEMS_PER_SPLIT: Final[int] = 0
_DEFAULT_MAX_CLASS_SHARE: Final[float] = 0.95
_DEFAULT_MAX_WEIGHT: Final[float] = 100.0

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_ID_LENGTH: Final[int] = 128
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

_MISSING: Final[object] = object()

_DATETIME_MIN: Final[datetime] = datetime(1970, 1, 1, tzinfo=timezone.utc)
_DATETIME_MAX: Final[datetime] = datetime.max.replace(tzinfo=timezone.utc)

_FORBIDDEN_SPLIT_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_SPLIT_TOKENS: Final[tuple[str, ...]] = (
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

_ACCEPTED_SPLIT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "subject_ref_hash",
        "group_key_hash",
        "label_code",
        "split",
        "weight",
        "timestamp",
        "metadata",
    }
)

_INPUT_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "subject_ref_hash": "subject_ref_hash",
        "subject_hash": "subject_ref_hash",
        "subject": "subject_ref_hash",
        "account_id": "subject_ref_hash",
        "acct_id": "subject_ref_hash",
        "id": "subject_ref_hash",
        "group_key_hash": "group_key_hash",
        "group_hash": "group_key_hash",
        "entity_hash": "group_key_hash",
        "entity_id": "group_key_hash",
        "label_code": "label_code",
        "label": "label_code",
        "target": "label_code",
        "y": "label_code",
        "synthetic_label": "label_code",
        "split": "split",
        "fold": "split",
        "weight": "weight",
        "sample_weight": "weight",
        "timestamp": "timestamp",
        "occurred_at": "timestamp",
        "valid_from": "timestamp",
        "reported_at": "timestamp",
        "created_at": "timestamp",
        "time": "timestamp",
        "date": "timestamp",
        "metadata_json": "metadata",
        "metadata": "metadata",
    }
)

_OBJECT_FIELD_NAMES: Final[tuple[str, ...]] = (
    "subject_ref_hash",
    "subject_hash",
    "subject",
    "account_id",
    "acct_id",
    "id",
    "group_key_hash",
    "group_hash",
    "entity_hash",
    "entity_id",
    "label_code",
    "label",
    "target",
    "y",
    "synthetic_label",
    "split",
    "fold",
    "weight",
    "sample_weight",
    "timestamp",
    "occurred_at",
    "valid_from",
    "reported_at",
    "created_at",
    "time",
    "date",
    "metadata_json",
    "metadata",
)

_SPLIT_ORDER: Final[tuple["SplitName", ...]] = ()

_LOCAL_LABEL_NAMES: Final[Mapping[int, str]] = MappingProxyType(
    {
        0: "unknown",
        1: "no_action",
        2: "review",
        3: "escalate",
        4: "uncertain",
    }
)

_SPLIT_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML split management only. Do not use with real customer data.",
    "Split plans are operational ML hygiene artefacts only and are not proof of wrongdoing.",
    "Split handling must not trigger automatic adverse customer action.",
    "Labels must never be returned in public split summaries, logs, diagnostics, exports, or artifacts.",
    "Subject linkage uses salted one-way pseudonymous hashes only.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Grouped and hybrid strategies aim to prevent subject or group leakage across splits.",
    "Temporal strategies aim to preserve chronological train/validation/test ordering.",
    "Unavailable or unsafe split capabilities are reported honestly rather than invented.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_SPLIT_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
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
        "bounded_split_plans_required": True,
        "deterministic_split_construction": True,
        "leakage_aware_group_splitting": True,
        "temporal_leakage_checks": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class SplitName(str, Enum):
    """
    Canonical split names.
    """

    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


_SPLIT_ORDER = (SplitName.TRAIN, SplitName.VALIDATION, SplitName.TEST)


class SplitStrategy(str, Enum):
    """
    Supported split strategies.
    """

    RANDOM = "random"
    STRATIFIED = "stratified"
    GROUPED = "grouped"
    TEMPORAL = "temporal"
    HYBRID = "hybrid"
    PRESERVE = "preserve"


class SplitGroupBy(str, Enum):
    """
    Grouping basis for leakage-aware splits.
    """

    NONE = "none"
    SUBJECT = "subject"
    ENTITY = "entity"
    CUSTOM = "custom"


class IssueSeverity(str, Enum):
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
    return max(minimum, min(parsed, default))


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


def _is_forbidden_split_key(key: Any) -> bool:
    """
    Return True when an input key is forbidden for split construction.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_SPLIT_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_SPLIT_TOKENS)


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

    if isinstance(value, Enum):
        return _safe_detail_value(value.value, depth + 1)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

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

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

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


def _stable_rank(salt: str, domain: str, *parts: Any) -> int:
    """
    Return a deterministic 64-bit rank for stable ordering.
    """
    message = "\x00".join(str(part) for part in parts)
    digest = hmac.new(
        salt.encode("utf-8", errors="replace"),
        f"{domain}\x00{message}".encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).digest()
    return int.from_bytes(digest[:8], "big")


def _ensure_salt(salt: Any) -> str:
    """
    Ensure the split salt is non-empty and sufficiently long.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _hash_identifier(value: Any, salt: str, namespace: str, domain: str) -> str:
    """
    Return a salted, domain-separated pseudonymous hash for an identifier.
    """
    safe_namespace = _normalize_token(namespace) or _DEFAULT_NAMESPACE
    full_domain = f"muleguard.ml.splits.{domain}.{safe_namespace}"
    return _hmac_hex(salt, full_domain, _clean_text(value, _MAX_TEXT_LENGTH))


def _normalize_split_name(value: Any) -> Optional[SplitName]:
    """
    Normalize a split-like value.
    """
    if isinstance(value, SplitName):
        return value

    token = _normalize_token(value)

    aliases = {
        "train": SplitName.TRAIN,
        "training": SplitName.TRAIN,
        "validation": SplitName.VALIDATION,
        "valid": SplitName.VALIDATION,
        "val": SplitName.VALIDATION,
        "test": SplitName.TEST,
        "holdout": SplitName.TEST,
    }

    return aliases.get(token)


def _split_value(split: Any) -> str:
    """
    Return a safe split string value.
    """
    normalized = _normalize_split_name(split)
    return normalized.value if normalized is not None else ""


def _normalize_strategy(value: Any, default: SplitStrategy = SplitStrategy.STRATIFIED) -> SplitStrategy:
    """
    Normalize a split strategy value.
    """
    if isinstance(value, SplitStrategy):
        return value

    token = _normalize_token(value)

    aliases = {
        "rand": SplitStrategy.RANDOM,
        "random": SplitStrategy.RANDOM,
        "shuffle": SplitStrategy.RANDOM,
        "strat": SplitStrategy.STRATIFIED,
        "stratified": SplitStrategy.STRATIFIED,
        "group": SplitStrategy.GROUPED,
        "grouped": SplitStrategy.GROUPED,
        "time": SplitStrategy.TEMPORAL,
        "temporal": SplitStrategy.TEMPORAL,
        "chronological": SplitStrategy.TEMPORAL,
        "mixed": SplitStrategy.HYBRID,
        "hybrid": SplitStrategy.HYBRID,
        "existing": SplitStrategy.PRESERVE,
        "preserve": SplitStrategy.PRESERVE,
    }

    resolved = aliases.get(token, token)

    try:
        return SplitStrategy(resolved)
    except ValueError:
        return default


def _normalize_group_by(value: Any, default: SplitGroupBy = SplitGroupBy.SUBJECT) -> SplitGroupBy:
    """
    Normalize a group-by value.
    """
    if isinstance(value, SplitGroupBy):
        return value

    token = _normalize_token(value)

    aliases = {
        "none": SplitGroupBy.NONE,
        "subject": SplitGroupBy.SUBJECT,
        "account": SplitGroupBy.SUBJECT,
        "entity": SplitGroupBy.ENTITY,
        "custom": SplitGroupBy.CUSTOM,
        "group": SplitGroupBy.CUSTOM,
    }

    resolved = aliases.get(token, token)

    try:
        return SplitGroupBy(resolved)
    except ValueError:
        return default


def _normalize_weight_mode(value: Any, default: str = "none") -> str:
    """
    Normalize a class balancing weight mode.
    """
    token = _normalize_token(value)

    aliases = {
        "none": "none",
        "off": "none",
        "inverse": "inverse_frequency",
        "inverse_frequency": "inverse_frequency",
        "class_weight": "inverse_frequency",
        "capped": "capped_inverse_frequency",
        "capped_inverse_frequency": "capped_inverse_frequency",
    }

    resolved = aliases.get(token, token)

    if resolved in {"none", "inverse_frequency", "capped_inverse_frequency"}:
        return resolved

    return default


def _normalize_missing_policy(value: Any, default: str = "end") -> str:
    """
    Normalize a temporal missing timestamp policy.
    """
    token = _normalize_token(value)

    if token in {"start", "begin", "earliest"}:
        return "start"

    if token in {"error", "reject"}:
        return "error"

    return "end"


def _parse_datetime(value: Any) -> Optional[datetime]:
    """
    Parse a datetime-like value into timezone-aware UTC.
    """
    if isinstance(value, bool):
        return None

    if isinstance(value, datetime):
        return _ensure_utc(value)

    if isinstance(value, (int, float, Decimal)):
        numeric = _as_float(value, math.nan)

        if math.isnan(numeric) or math.isinf(numeric):
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

    if math.isnan(numeric) or math.isinf(numeric):
        return None

    if abs(numeric) > 1_000_000_000_000:
        numeric = numeric / 1000.0

    try:
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


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


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SplitIssue:
    """
    Safe split issue.

    Issues never contain raw labels, raw narratives, raw identifiers, secrets,
    tokens, passwords, database URLs, filesystem paths, or model artifact paths.
    """

    severity: IssueSeverity
    code: str
    message: str
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

        if self.field:
            payload["field"] = _clean_text(self.field, 200)

        if self.details:
            payload["details"] = self.details

        return payload


def _add_issue(
    issues: list[SplitIssue],
    *,
    severity: IssueSeverity,
    code: str,
    message: str,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Append one safe issue.
    """
    issues.append(
        SplitIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SplitOptions:
    """
    Bounded ML split construction policy.

    Hard caps prevent accidental unbounded split surfaces.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    strategy: SplitStrategy | str = SplitStrategy.STRATIFIED
    group_by: SplitGroupBy | str = SplitGroupBy.SUBJECT

    train_ratio: float = _DEFAULT_TRAIN_RATIO
    validation_ratio: float = _DEFAULT_VALIDATION_RATIO
    test_ratio: float = _DEFAULT_TEST_RATIO

    min_items_per_split: int = _DEFAULT_MIN_ITEMS_PER_SPLIT
    allow_empty_splits: bool = False
    preserve_existing_splits: bool = False

    temporal_field: Optional[str] = None
    temporal_boundary_train_validation: Optional[datetime] = None
    temporal_boundary_validation_test: Optional[datetime] = None
    temporal_missing_policy: str = "end"

    group_field: Optional[str] = None
    allow_split_large_groups: bool = False

    balance_classes: bool = False
    weight_mode: str = "none"
    max_weight: float = _DEFAULT_MAX_WEIGHT
    max_class_share: float = _DEFAULT_MAX_CLASS_SHARE

    leakage_guard: bool = True
    drop_forbidden_fields: bool = False

    max_items: int = _DEFAULT_MAX_ITEMS
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS

    deterministic_order: bool = True
    validate_input: bool = True

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

        strategy = _normalize_strategy(self.strategy)
        object.__setattr__(self, "strategy", strategy)

        group_by = _normalize_group_by(self.group_by)
        object.__setattr__(self, "group_by", group_by)

        train = max(0.0, _as_float(self.train_ratio, _DEFAULT_TRAIN_RATIO))
        validation = max(0.0, _as_float(self.validation_ratio, _DEFAULT_VALIDATION_RATIO))
        test = max(0.0, _as_float(self.test_ratio, _DEFAULT_TEST_RATIO))
        total = train + validation + test

        if total <= 0:
            train = _DEFAULT_TRAIN_RATIO
            validation = _DEFAULT_VALIDATION_RATIO
            test = _DEFAULT_TEST_RATIO
            total = train + validation + test

        object.__setattr__(self, "train_ratio", train / total)
        object.__setattr__(self, "validation_ratio", validation / total)
        object.__setattr__(self, "test_ratio", test / total)

        object.__setattr__(
            self,
            "min_items_per_split",
            max(0, _as_int(self.min_items_per_split, _DEFAULT_MIN_ITEMS_PER_SPLIT)),
        )
        object.__setattr__(self, "allow_empty_splits", _as_bool(self.allow_empty_splits, False))

        if strategy == SplitStrategy.PRESERVE:
            object.__setattr__(self, "preserve_existing_splits", True)
        else:
            object.__setattr__(self, "preserve_existing_splits", _as_bool(self.preserve_existing_splits, False))

        object.__setattr__(
            self,
            "temporal_field",
            _canonical_field_name(self.temporal_field) if self.temporal_field else None,
        )
        object.__setattr__(
            self,
            "temporal_boundary_train_validation",
            _parse_datetime(self.temporal_boundary_train_validation),
        )
        object.__setattr__(
            self,
            "temporal_boundary_validation_test",
            _parse_datetime(self.temporal_boundary_validation_test),
        )
        object.__setattr__(
            self,
            "temporal_missing_policy",
            _normalize_missing_policy(self.temporal_missing_policy, "end"),
        )

        object.__setattr__(
            self,
            "group_field",
            _canonical_field_name(self.group_field) if self.group_field else None,
        )
        object.__setattr__(self, "allow_split_large_groups", _as_bool(self.allow_split_large_groups, False))

        object.__setattr__(self, "balance_classes", _as_bool(self.balance_classes, False))
        object.__setattr__(
            self,
            "weight_mode",
            _normalize_weight_mode(self.weight_mode, "none" if not self.balance_classes else "capped_inverse_frequency"),
        )
        object.__setattr__(
            self,
            "max_weight",
            _clamp_float(self.max_weight, 0.0, 1000.0, _DEFAULT_MAX_WEIGHT),
        )
        object.__setattr__(
            self,
            "max_class_share",
            _clamp_float(self.max_class_share, 0.5, 1.0, _DEFAULT_MAX_CLASS_SHARE),
        )

        object.__setattr__(self, "leakage_guard", _as_bool(self.leakage_guard, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))

        object.__setattr__(
            self,
            "max_items",
            _clamp_int(self.max_items, 1, _HARD_MAX_ITEMS, _DEFAULT_MAX_ITEMS),
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

        object.__setattr__(self, "deterministic_order", _as_bool(self.deterministic_order, True))
        object.__setattr__(self, "validate_input", _as_bool(self.validate_input, True))

        if self.temporal_boundary_train_validation is not None and self.temporal_boundary_validation_test is not None:
            if self.temporal_boundary_validation_test < self.temporal_boundary_train_validation:
                raise ConfigurationError(
                    "Temporal validation/test boundary must be after train/validation boundary.",
                )

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "SplitOptions":
        """
        Build split options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_SPLIT_SALT", None)
            or _setting(settings, "ML_LABEL_SALT", None)
            or _setting(settings, "ML_FEATURE_SALT", None)
            or _setting(settings, "PROVENANCE_SALT", None)
            or _setting(settings, "DEDUPE_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_SPLITS_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_SPLITS_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_SPLITS_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_SPLITS_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_SPLITS_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            strategy=_normalize_strategy(_setting(settings, "ML_SPLIT_STRATEGY", SplitStrategy.STRATIFIED.value)),
            group_by=_normalize_group_by(_setting(settings, "ML_SPLIT_GROUP_BY", SplitGroupBy.SUBJECT.value)),
            train_ratio=_as_float(_setting(settings, "ML_SPLIT_TRAIN_RATIO", _DEFAULT_TRAIN_RATIO), _DEFAULT_TRAIN_RATIO),
            validation_ratio=_as_float(
                _setting(settings, "ML_SPLIT_VALIDATION_RATIO", _DEFAULT_VALIDATION_RATIO),
                _DEFAULT_VALIDATION_RATIO,
            ),
            test_ratio=_as_float(_setting(settings, "ML_SPLIT_TEST_RATIO", _DEFAULT_TEST_RATIO), _DEFAULT_TEST_RATIO),
            min_items_per_split=_as_int(
                _setting(settings, "ML_SPLIT_MIN_ITEMS_PER_SPLIT", _DEFAULT_MIN_ITEMS_PER_SPLIT),
                _DEFAULT_MIN_ITEMS_PER_SPLIT,
            ),
            allow_empty_splits=_as_bool(_setting(settings, "ML_SPLIT_ALLOW_EMPTY", False), False),
            preserve_existing_splits=_as_bool(
                _setting(settings, "ML_SPLIT_PRESERVE_EXISTING", False),
                False,
            ),
            temporal_field=_setting(settings, "ML_SPLIT_TEMPORAL_FIELD", None),
            temporal_boundary_train_validation=_parse_datetime(
                _setting(settings, "ML_SPLIT_TEMPORAL_BOUNDARY_TRAIN_VALIDATION", None)
            ),
            temporal_boundary_validation_test=_parse_datetime(
                _setting(settings, "ML_SPLIT_TEMPORAL_BOUNDARY_VALIDATION_TEST", None)
            ),
            temporal_missing_policy=_normalize_missing_policy(
                _setting(settings, "ML_SPLIT_TEMPORAL_MISSING_POLICY", "end"),
                "end",
            ),
            group_field=_setting(settings, "ML_SPLIT_GROUP_FIELD", None),
            allow_split_large_groups=_as_bool(
                _setting(settings, "ML_SPLIT_ALLOW_SPLIT_LARGE_GROUPS", False),
                False,
            ),
            balance_classes=_as_bool(_setting(settings, "ML_SPLIT_BALANCE_CLASSES", False), False),
            weight_mode=_normalize_weight_mode(
                _setting(settings, "ML_SPLIT_WEIGHT_MODE", "capped_inverse_frequency"),
                "none",
            ),
            max_weight=_as_float(_setting(settings, "ML_SPLIT_MAX_WEIGHT", _DEFAULT_MAX_WEIGHT), _DEFAULT_MAX_WEIGHT),
            max_class_share=_as_float(
                _setting(settings, "ML_SPLIT_MAX_CLASS_SHARE", _DEFAULT_MAX_CLASS_SHARE),
                _DEFAULT_MAX_CLASS_SHARE,
            ),
            leakage_guard=_as_bool(_setting(settings, "ML_SPLIT_LEAKAGE_GUARD", True), True),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ML_SPLIT_DROP_FORBIDDEN_FIELDS", False),
                False,
            ),
            max_items=_as_int(_setting(settings, "ML_SPLIT_MAX_ITEMS", _DEFAULT_MAX_ITEMS), _DEFAULT_MAX_ITEMS),
            max_issues=_as_int(_setting(settings, "ML_SPLIT_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(
                _setting(settings, "ML_SPLIT_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            deterministic_order=_as_bool(_setting(settings, "ML_SPLIT_DETERMINISTIC_ORDER", True), True),
            validate_input=_as_bool(_setting(settings, "ML_SPLIT_VALIDATE_INPUT", True), True),
        )

    def ratios(self) -> dict[SplitName, float]:
        """
        Return normalized split ratios.
        """
        return {
            SplitName.TRAIN: float(self.train_ratio),
            SplitName.VALIDATION: float(self.validation_ratio),
            SplitName.TEST: float(self.test_ratio),
        }

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
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
            "strategy": self.strategy.value,
            "group_by": self.group_by.value,
            "ratios": {
                "train": round(self.train_ratio, 6),
                "validation": round(self.validation_ratio, 6),
                "test": round(self.test_ratio, 6),
            },
            "min_items_per_split": self.min_items_per_split,
            "allow_empty_splits": self.allow_empty_splits,
            "preserve_existing_splits": self.preserve_existing_splits,
            "temporal": {
                "field": self.temporal_field,
                "boundary_train_validation": (
                    self.temporal_boundary_train_validation.isoformat()
                    if self.temporal_boundary_train_validation
                    else None
                ),
                "boundary_validation_test": (
                    self.temporal_boundary_validation_test.isoformat()
                    if self.temporal_boundary_validation_test
                    else None
                ),
                "missing_policy": self.temporal_missing_policy,
            },
            "grouping": {
                "group_field": self.group_field,
                "allow_split_large_groups": self.allow_split_large_groups,
            },
            "balancing": {
                "balance_classes": self.balance_classes,
                "weight_mode": self.weight_mode,
                "max_weight": round(self.max_weight, 6),
                "max_class_share": round(self.max_class_share, 6),
            },
            "guards": {
                "leakage_guard": self.leakage_guard,
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "validate_input": self.validate_input,
                "deterministic_order": self.deterministic_order,
            },
            "limits": {
                "max_items": self.max_items,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
            },
        }


# -----------------------------------------------------------------------------
# Split item model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SplitItem:
    """
    One normalized split item.

    This is internal-facing. Public summaries must not expose subject-label
    pairs.
    """

    subject_ref_hash: str
    split: Optional[SplitName] = None
    group_key_hash: str = ""
    label_code: Optional[int] = None
    weight: float = 1.0
    timestamp: Optional[datetime] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    source_index: Optional[int] = None

    def __post_init__(self) -> None:
        """
        Normalize split item values.
        """
        subject = _clean_text(self.subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower()

        if not subject:
            raise ConfigurationError("Split item subject reference is required.")

        if not _is_safe_hash(subject):
            raise ConfigurationError(
                "Split item subject reference must be a pseudonymous hash.",
            )

        object.__setattr__(self, "subject_ref_hash", subject)

        group = _clean_text(self.group_key_hash, _MAX_SUBJECT_HASH_LENGTH).lower() or subject

        if not _is_safe_hash(group):
            raise ConfigurationError(
                "Split item group key must be a pseudonymous hash.",
            )

        object.__setattr__(self, "group_key_hash", group)

        object.__setattr__(self, "split", _normalize_split_name(self.split))

        if self.label_code is not None:
            object.__setattr__(self, "label_code", int(self.label_code))

        object.__setattr__(
            self,
            "weight",
            round(_clip_float(self.weight, 0.0, _DEFAULT_MAX_WEIGHT, 1.0), 6),
        )
        object.__setattr__(self, "timestamp", _ensure_utc(self.timestamp))
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(_safe_detail_value(self.metadata) or {}),
        )

        if self.source_index is not None:
            object.__setattr__(self, "source_index", int(self.source_index))

    @property
    def split_name(self) -> str:
        """
        Return the canonical split name or empty string.
        """
        return self.split.value if self.split is not None else ""


# -----------------------------------------------------------------------------
# Input normalization
# -----------------------------------------------------------------------------


def _record_to_safe_mapping(
    record: Any,
    options: SplitOptions,
    issues: list[SplitIssue],
    index: int,
) -> Optional[dict[str, Any]]:
    """
    Convert a record-like object into a safe accepted-field mapping.

    Forbidden fields are rejected or omitted. Unknown fields are omitted.
    Aliases are resolved deterministically.
    """
    if isinstance(record, Mapping):
        raw_items = record.items()
    else:
        raw_items = [
            (name, getattr(record, name, None))
            for name in _OBJECT_FIELD_NAMES
            if hasattr(record, name)
        ]

    safe: dict[str, Any] = {}

    for raw_key, raw_value in raw_items:
        key_text = _clean_text(raw_key, 200)

        if not key_text:
            continue

        canonical = _canonical_field_name(key_text)

        if not canonical:
            _add_issue(
                issues,
                severity=IssueSeverity.WARNING,
                code="invalid_field_name",
                message="Field name could not be canonicalized and was omitted.",
                field=key_text,
                details={"index": index},
            )
            continue

        if _is_forbidden_split_key(canonical):
            if options.leakage_guard and not options.drop_forbidden_fields:
                _add_issue(
                    issues,
                    severity=IssueSeverity.ERROR,
                    code="forbidden_split_field",
                    message="Forbidden field rejected.",
                    field=key_text,
                    details={"index": index},
                )
                return None

            _add_issue(
                issues,
                severity=IssueSeverity.WARNING,
                code="forbidden_split_field_dropped",
                message="Forbidden field omitted.",
                field=key_text,
                details={"index": index},
            )
            continue

        target = _INPUT_ALIASES.get(canonical, canonical)

        if target not in _ACCEPTED_SPLIT_FIELDS:
            _add_issue(
                issues,
                severity=IssueSeverity.WARNING,
                code="unknown_split_field_dropped",
                message="Unknown field omitted.",
                field=key_text,
                details={"index": index},
            )
            continue

        if target in safe:
            _add_issue(
                issues,
                severity=IssueSeverity.WARNING,
                code="duplicate_field_alias",
                message="Duplicate field alias omitted.",
                field=key_text,
                details={"index": index},
            )
            continue

        safe[target] = raw_value

    return safe


def _normalize_label_code(value: Any, taxonomy: Any | None = None) -> Optional[int]:
    """
    Normalize a label-like value to an integer code.

    Unknown values return None. This helper does not validate taxonomy
    membership; downstream metrics only use codes for distribution summaries.
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return int(value)

    if isinstance(value, Decimal):
        if not value.is_finite():
            return None

        if value != value.to_integral_value():
            return None

        return int(value)

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None

        if not float(value).is_integer():
            return None

        return int(value)

    if taxonomy is not None and hasattr(taxonomy, "try_normalize"):
        try:
            code = taxonomy.try_normalize(value)
        except Exception:
            code = None

        if code is not None:
            try:
                return int(code)
            except (TypeError, ValueError):
                pass

    text = _normalize_token(value)

    if not text:
        return None

    aliases = {
        "unknown": 0,
        "none": 0,
        "null": 0,
        "missing": 0,
        "unlabeled": 0,
        "no_action": 1,
        "negative": 1,
        "benign": 1,
        "clean": 1,
        "not_investigate": 1,
        "low": 1,
        "review": 2,
        "positive": 2,
        "investigate": 2,
        "flagged_for_review": 2,
        "medium": 2,
        "escalate": 3,
        "high_priority": 3,
        "critical": 3,
        "urgent": 3,
        "uncertain": 4,
        "ambiguous": 4,
        "needs_human": 4,
    }

    return aliases.get(text)


def _as_subject_hash(value: Any, options: SplitOptions, domain: str) -> Optional[str]:
    """
    Return a pseudonymous hash for a subject-like value.

    Already-safe hashes are preserved in lowercase. Raw values are hashed and
    never retained.
    """
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    return _hash_identifier(text, options.salt, options.namespace, domain)


def _normalize_input_record(
    record: Any,
    index: int,
    options: SplitOptions,
    taxonomy: Any | None,
    issues: list[SplitIssue],
) -> Optional[SplitItem]:
    """
    Normalize one split input record.
    """
    safe = _record_to_safe_mapping(record, options, issues, index)

    if safe is None:
        return None

    subject_ref_hash = _as_subject_hash(safe.get("subject_ref_hash"), options, "subject")

    if not subject_ref_hash:
        _add_issue(
            issues,
            severity=IssueSeverity.ERROR,
            code="missing_subject_reference",
            message="Split record is missing a subject reference.",
            details={"index": index},
        )
        return None

    if options.group_by == SplitGroupBy.NONE:
        group_key_hash = subject_ref_hash
    else:
        raw_group = safe.get("group_key_hash")

        if options.group_field:
            raw_group = raw_group or safe.get(options.group_field)

        group_key_hash = _as_subject_hash(raw_group, options, "group") or subject_ref_hash

        if not raw_group and options.group_by in {SplitGroupBy.ENTITY, SplitGroupBy.CUSTOM}:
            _add_issue(
                issues,
                severity=IssueSeverity.WARNING,
                code="group_key_missing_using_subject",
                message="Group key was missing and subject hash was used as fallback.",
                details={"index": index},
            )

    label_code = _normalize_label_code(safe.get("label_code"), taxonomy=taxonomy)
    split = _normalize_split_name(safe.get("split"))
    weight = _clip_float(_decimal_to_float(safe.get("weight"), 1.0), 0.0, options.max_weight, 1.0)
    timestamp = _parse_datetime(safe.get("timestamp"))
    metadata = _safe_detail_value(safe.get("metadata")) or {}

    return SplitItem(
        subject_ref_hash=subject_ref_hash,
        split=split,
        group_key_hash=group_key_hash,
        label_code=label_code,
        weight=weight,
        timestamp=timestamp,
        metadata=metadata,
        source_index=index,
    )


def _normalize_items(
    records: Any,
    options: SplitOptions,
    taxonomy: Any | None,
    issues: list[SplitIssue],
) -> list[SplitItem]:
    """
    Normalize bounded split inputs.
    """
    items: list[SplitItem] = []
    record_list = _as_sequence(records)

    if len(record_list) > options.max_items:
        _add_issue(
            issues,
            severity=IssueSeverity.WARNING,
            code="split_input_truncated",
            message="Split input exceeded configured item limit and was truncated.",
            details={
                "submitted": len(record_list),
                "max_items": options.max_items,
            },
        )
        record_list = record_list[: options.max_items]

    for index, record in enumerate(record_list):
        item = _normalize_input_record(record, index, options, taxonomy, issues)

        if item is not None:
            items.append(item)

    return items


# -----------------------------------------------------------------------------
# Allocation helpers
# -----------------------------------------------------------------------------


def _largest_remainder(total: int, ratios: Mapping[SplitName, float]) -> dict[SplitName, int]:
    """
    Allocate an integer total across splits using largest remainder method.
    """
    if total <= 0:
        return {split: 0 for split in _SPLIT_ORDER}

    raw = {
        split: float(total) * max(0.0, float(ratios.get(split, 0.0)))
        for split in _SPLIT_ORDER
    }
    floors = {split: int(math.floor(value)) for split, value in raw.items()}
    remainder = total - sum(floors.values())

    if remainder <= 0:
        return floors

    ordered = sorted(
        _SPLIT_ORDER,
        key=lambda split: (
            -(raw[split] - floors[split]),
            -float(ratios.get(split, 0.0)),
            split.value,
        ),
    )

    for split in ordered[:remainder]:
        floors[split] += 1

    return floors


def _adjust_allocation_sum(
    allocation: Mapping[SplitName, int],
    free_count: int,
    ratios: Mapping[SplitName, float],
) -> dict[SplitName, int]:
    """
    Adjust an allocation so its sum exactly equals free_count.
    """
    alloc = {split: max(0, int(allocation.get(split, 0))) for split in _SPLIT_ORDER}
    diff = int(free_count) - sum(alloc.values())

    if diff > 0:
        ordered = sorted(
            _SPLIT_ORDER,
            key=lambda split: (-float(ratios.get(split, 0.0)), split.value),
        )
        position = 0

        while diff > 0:
            split = ordered[position % len(ordered)]
            alloc[split] += 1
            diff -= 1
            position += 1

    elif diff < 0:
        ordered = sorted(
            _SPLIT_ORDER,
            key=lambda split: (-alloc[split], split.value),
        )
        position = 0

        while diff < 0:
            split = ordered[position % len(ordered)]

            if alloc[split] > 0:
                alloc[split] -= 1
                diff += 1

            position += 1

    return alloc


def _compute_free_allocation(
    total_count: int,
    locked_counts: Mapping[SplitName, int],
    free_count: int,
    ratios: Mapping[SplitName, float],
    min_items_per_split: int,
    allow_empty_splits: bool,
    issues: list[SplitIssue] | None = None,
) -> dict[SplitName, int]:
    """
    Compute free-item allocation while respecting locked counts and minima.
    """
    base = _largest_remainder(max(0, int(total_count)), ratios)
    alloc = {
        split: max(0, int(base.get(split, 0)) - int(locked_counts.get(split, 0)))
        for split in _SPLIT_ORDER
    }
    alloc = _adjust_allocation_sum(alloc, max(0, int(free_count)), ratios)

    if min_items_per_split > 0 and total_count >= min_items_per_split * len(_SPLIT_ORDER):
        for split in _SPLIT_ORDER:
            current_total = int(locked_counts.get(split, 0)) + int(alloc.get(split, 0))
            need = int(min_items_per_split) - current_total

            if need <= 0:
                continue

            donors = sorted(
                _SPLIT_ORDER,
                key=lambda donor: (
                    -(int(locked_counts.get(donor, 0)) + int(alloc.get(donor, 0)) - int(min_items_per_split)),
                    donor.value,
                ),
            )

            for donor in donors:
                if donor == split:
                    continue

                available = int(locked_counts.get(donor, 0)) + int(alloc.get(donor, 0)) - int(min_items_per_split)

                if available <= 0 or alloc.get(donor, 0) <= 0:
                    continue

                take = min(available, int(alloc[donor]), need)
                alloc[donor] -= take
                alloc[split] += take
                need -= take

                if need <= 0:
                    break

    elif min_items_per_split > 0 and not allow_empty_splits and issues is not None:
        _add_issue(
            issues,
            severity=IssueSeverity.WARNING,
            code="min_items_per_split_not_met",
            message="Not enough items were available to satisfy minimum items per split.",
            details={
                "total_count": total_count,
                "min_items_per_split": min_items_per_split,
            },
        )

    return alloc


def _split_counter(items: Sequence[SplitItem]) -> Counter[SplitName]:
    """
    Count locked items by split.
    """
    return Counter(item.split for item in items if item.split is not None)


def _item_sort_key(item: SplitItem, options: SplitOptions) -> tuple[int, int, str]:
    """
    Return deterministic stable sort key for one item.
    """
    # Ordering is a stable hash of the configuration and the subject, not a
    # seeded shuffle. That is deliberate and worth keeping: a given account
    # always lands in the same split, so adding new data does not reshuffle
    # the existing assignment — which would silently invalidate every
    # evaluation taken before it.
    #
    # `options.seed` is mixed in so that it actually governs the assignment.
    # It was previously recorded in the configuration fingerprint but unused
    # here, which made it a decoy: changing the seed produced a different
    # fingerprint and an identical split, so anyone re-splitting by changing
    # the seed got the same split and a plan that claimed to be new.
    rank = _stable_rank(
        options.salt,
        "muleguard.ml.splits.item_order",
        options.seed,
        item.subject_ref_hash,
        item.group_key_hash,
        item.label_code if item.label_code is not None else -1,
        item.source_index if item.source_index is not None else -1,
    )
    source_index = item.source_index if item.source_index is not None else 0
    return (rank, source_index, item.subject_ref_hash)


def _assign_by_allocation(
    free: Sequence[SplitItem],
    allocation: Mapping[SplitName, int],
    options: SplitOptions,
    issues: list[SplitIssue],
    sort_key: Any | None = None,
) -> list[SplitItem]:
    """
    Assign free items according to an allocation map.
    """
    alloc = _adjust_allocation_sum(allocation, len(free), options.ratios())
    key_fn = sort_key or (lambda item: _item_sort_key(item, options))
    ordered = sorted(free, key=key_fn)

    assigned: list[SplitItem] = []
    position = 0

    for split in _SPLIT_ORDER:
        count = int(alloc.get(split, 0))

        for item in ordered[position : position + count]:
            assigned.append(replace(item, split=split))

        position += count

    if position < len(ordered):
        fallback_split = max(
            _SPLIT_ORDER,
            key=lambda split: (options.ratios().get(split, 0.0), split.value),
        )

        for item in ordered[position:]:
            assigned.append(replace(item, split=fallback_split))

    return assigned


# -----------------------------------------------------------------------------
# Split strategies
# -----------------------------------------------------------------------------


def _assign_random(
    free: Sequence[SplitItem],
    locked: Sequence[SplitItem],
    options: SplitOptions,
    issues: list[SplitIssue],
) -> list[SplitItem]:
    """
    Random deterministic split assignment.
    """
    locked_counts = _split_counter(locked)
    allocation = _compute_free_allocation(
        total_count=len(free) + len(locked),
        locked_counts=locked_counts,
        free_count=len(free),
        ratios=options.ratios(),
        min_items_per_split=options.min_items_per_split,
        allow_empty_splits=options.allow_empty_splits,
        issues=issues,
    )
    return _assign_by_allocation(free, allocation, options, issues)


def _assign_stratified(
    free: Sequence[SplitItem],
    locked: Sequence[SplitItem],
    options: SplitOptions,
    issues: list[SplitIssue],
) -> list[SplitItem]:
    """
    Stratified split assignment by label code.
    """
    free_by_label: dict[int, list[SplitItem]] = defaultdict(list)

    for item in free:
        label = item.label_code if item.label_code is not None else -1
        free_by_label[label].append(item)

    locked_by_label: dict[int, Counter[SplitName]] = defaultdict(Counter)

    for item in locked:
        label = item.label_code if item.label_code is not None else -1
        if item.split is not None:
            locked_by_label[label][item.split] += 1

    assigned: list[SplitItem] = []
    ratios = options.ratios()

    for label, group in sorted(
        free_by_label.items(),
        key=lambda kv: (kv[0] == -1, kv[0]),
    ):
        locked_counter = locked_by_label.get(label, Counter())
        total_label = len(group) + sum(locked_counter.values())
        base = _largest_remainder(total_label, ratios)
        allocation = {
            split: max(0, int(base.get(split, 0)) - int(locked_counter.get(split, 0)))
            for split in _SPLIT_ORDER
        }
        allocation = _adjust_allocation_sum(allocation, len(group), ratios)
        assigned.extend(_assign_by_allocation(group, allocation, options, issues))

    return assigned


def _choose_split_for_group(
    group_label_counts: Mapping[int, int],
    size: int,
    remaining: Mapping[SplitName, int],
    current_counts: Mapping[SplitName, Counter[int]],
    current_totals: Mapping[SplitName, int],
    global_distribution: Mapping[int, float],
    options: SplitOptions,
    group_key_hash: str,
) -> SplitName:
    """
    Choose the best split for one group.

    For grouped strategy, capacity dominates. For hybrid strategy, label
    distribution fit is also considered.
    """
    candidates = [split for split in _SPLIT_ORDER if int(remaining.get(split, 0)) > 0] or list(_SPLIT_ORDER)
    best_split = candidates[0]
    best_score = -math.inf
    best_tie = math.inf

    hybrid = options.strategy == SplitStrategy.HYBRID

    for split in candidates:
        capacity = int(remaining.get(split, 0))
        capacity_score = float(capacity) / float(max(1, size))

        divergence = 0.0

        if hybrid:
            projected_total = int(current_totals.get(split, 0)) + int(size)
            union_labels = set(global_distribution) | set(current_counts.get(split, {})) | set(group_label_counts)

            for label in union_labels:
                projected_count = int(current_counts.get(split, {}).get(label, 0)) + int(
                    group_label_counts.get(label, 0)
                )
                projected_share = float(projected_count) / float(projected_total) if projected_total > 0 else 0.0
                expected_share = float(global_distribution.get(label, 0.0))
                divergence += abs(projected_share - expected_share)

        score = capacity_score - (0.5 * divergence if hybrid else 0.05 * divergence)
        tie = _stable_rank(
            options.salt,
            "muleguard.ml.splits.group_choice",
            split.value,
            group_key_hash,
            size,
        )

        if score > best_score + 1e-12 or (abs(score - best_score) <= 1e-12 and tie < best_tie):
            best_split = split
            best_score = score
            best_tie = tie

    return best_split


def _assign_grouped(
    free: Sequence[SplitItem],
    locked: Sequence[SplitItem],
    options: SplitOptions,
    issues: list[SplitIssue],
    hybrid: bool = False,
) -> list[SplitItem]:
    """
    Group-aware split assignment.

    Whole groups are assigned to a single split whenever possible to reduce
    subject or entity leakage across splits.
    """
    locked_counts = _split_counter(locked)
    remaining = _compute_free_allocation(
        total_count=len(free) + len(locked),
        locked_counts=locked_counts,
        free_count=len(free),
        ratios=options.ratios(),
        min_items_per_split=options.min_items_per_split,
        allow_empty_splits=options.allow_empty_splits,
        issues=issues,
    )

    groups: dict[str, list[SplitItem]] = defaultdict(list)

    for item in free:
        groups[item.group_key_hash].append(item)

    all_items = list(free) + list(locked)
    global_counter = Counter(
        item.label_code if item.label_code is not None else -1
        for item in all_items
    )
    global_total = sum(global_counter.values())
    global_distribution = {
        label: float(count) / float(global_total)
        for label, count in global_counter.items()
    } if global_total > 0 else {}

    current_counts: dict[SplitName, Counter[int]] = {split: Counter() for split in _SPLIT_ORDER}
    current_totals: Counter[SplitName] = Counter()

    for item in locked:
        if item.split is None:
            continue

        label = item.label_code if item.label_code is not None else -1
        current_counts[item.split][label] += 1
        current_totals[item.split] += 1

    group_infos: list[tuple[int, int, str, list[SplitItem], Counter[int]]] = []

    for group_key, items in groups.items():
        label_counts = Counter(
            item.label_code if item.label_code is not None else -1
            for item in items
        )
        rank = _stable_rank(
            options.salt,
            "muleguard.ml.splits.group_order",
            group_key,
            len(items),
            min((item.source_index if item.source_index is not None else 0) for item in items),
        )
        group_infos.append((-len(items), rank, group_key, items, label_counts))

    group_infos.sort(key=lambda info: (info[0], info[1]))

    assigned: list[SplitItem] = []
    effective_strategy = SplitStrategy.HYBRID if hybrid else SplitStrategy.GROUPED

    for _, _, group_key, items, label_counts in group_infos:
        size = len(items)
        max_remaining = max((int(value) for value in remaining.values()), default=0)

        if options.allow_split_large_groups and size > max_remaining and max_remaining > 0:
            ordered_items = sorted(items, key=lambda item: _item_sort_key(item, options))

            for item in ordered_items:
                split = _choose_split_for_group(
                    group_label_counts={
                        item.label_code if item.label_code is not None else -1: 1
                    },
                    size=1,
                    remaining=remaining,
                    current_counts=current_counts,
                    current_totals=current_totals,
                    global_distribution=global_distribution,
                    options=replace(options, strategy=effective_strategy),
                    group_key_hash=group_key,
                )

                label = item.label_code if item.label_code is not None else -1
                assigned.append(replace(item, split=split))
                current_counts[split][label] += 1
                current_totals[split] += 1
                remaining[split] = int(remaining.get(split, 0)) - 1

            continue

        split = _choose_split_for_group(
            group_label_counts=label_counts,
            size=size,
            remaining=remaining,
            current_counts=current_counts,
            current_totals=current_totals,
            global_distribution=global_distribution,
            options=replace(options, strategy=effective_strategy),
            group_key_hash=group_key,
        )

        for item in items:
            label = item.label_code if item.label_code is not None else -1
            assigned.append(replace(item, split=split))
            current_counts[split][label] += 1
            current_totals[split] += 1

        remaining[split] = int(remaining.get(split, 0)) - size

        if remaining[split] < 0:
            _add_issue(
                issues,
                severity=IssueSeverity.WARNING,
                code="group_capacity_overflow",
                message="A group exceeded the remaining capacity of its assigned split.",
                details={
                    "group_size": size,
                    "split": split.value,
                },
            )

    if any(int(value) > 0 for value in remaining.values()):
        _add_issue(
            issues,
            severity=IssueSeverity.WARNING,
            code="group_allocation_underfilled",
            message="Group allocation did not fully consume target split capacities.",
            details={
                "remaining": {
                    split.value: int(remaining.get(split, 0))
                    for split in _SPLIT_ORDER
                }
            },
        )

    return assigned


def _assign_temporal(
    free: Sequence[SplitItem],
    locked: Sequence[SplitItem],
    options: SplitOptions,
    issues: list[SplitIssue],
) -> list[SplitItem]:
    """
    Temporal split assignment.

    Uses explicit boundaries when configured. Otherwise, allocates by sorted
    timestamp and target ratios.
    """
    if locked:
        _add_issue(
            issues,
            severity=IssueSeverity.WARNING,
            code="temporal_with_locked_splits",
            message="Temporal splitting with preserved existing splits may violate chronological ordering.",
            details={"locked_count": len(locked)},
        )

    boundary_tv = options.temporal_boundary_train_validation
    boundary_vt = options.temporal_boundary_validation_test

    if boundary_tv is not None or boundary_vt is not None:
        assigned: list[SplitItem] = []

        for item in free:
            timestamp = item.timestamp

            if timestamp is None:
                if options.temporal_missing_policy == "start":
                    split = SplitName.TRAIN
                elif options.temporal_missing_policy == "error":
                    _add_issue(
                        issues,
                        severity=IssueSeverity.ERROR,
                        code="temporal_missing_timestamp",
                        message="Temporal split record is missing timestamp.",
                        details={"subject_omitted": True},
                    )
                    split = SplitName.TEST
                else:
                    split = SplitName.TEST
            elif boundary_tv is not None and timestamp < boundary_tv:
                split = SplitName.TRAIN
            elif boundary_vt is not None and timestamp >= boundary_vt:
                split = SplitName.TEST
            else:
                split = SplitName.VALIDATION

            assigned.append(replace(item, split=split))

        return assigned

    locked_counts = _split_counter(locked)
    allocation = _compute_free_allocation(
        total_count=len(free) + len(locked),
        locked_counts=locked_counts,
        free_count=len(free),
        ratios=options.ratios(),
        min_items_per_split=options.min_items_per_split,
        allow_empty_splits=options.allow_empty_splits,
        issues=issues,
    )
    allocation = _adjust_allocation_sum(allocation, len(free), options.ratios())

    def temporal_sort_key(item: SplitItem) -> tuple[int, datetime, int, int, str]:
        timestamp = item.timestamp

        if timestamp is None:
            if options.temporal_missing_policy == "start":
                return (0, _DATETIME_MIN, 0, 0, item.subject_ref_hash)

            return (1, _DATETIME_MAX, 0, 0, item.subject_ref_hash)

        rank = _stable_rank(
            options.salt,
            "muleguard.ml.splits.temporal_order",
            item.subject_ref_hash,
            item.group_key_hash,
            item.label_code if item.label_code is not None else -1,
            item.source_index if item.source_index is not None else -1,
        )
        source_index = item.source_index if item.source_index is not None else 0
        return (0, timestamp, rank, source_index, item.subject_ref_hash)

    ordered = sorted(free, key=temporal_sort_key)
    assigned = []
    position = 0

    for split in _SPLIT_ORDER:
        count = int(allocation.get(split, 0))

        for item in ordered[position : position + count]:
            assigned.append(replace(item, split=split))

        position += count

    if position < len(ordered):
        for item in ordered[position:]:
            assigned.append(replace(item, split=SplitName.TEST))

    return assigned


def _assign_preserve(
    free: Sequence[SplitItem],
    locked: Sequence[SplitItem],
    options: SplitOptions,
    issues: list[SplitIssue],
) -> list[SplitItem]:
    """
    Preserve existing splits where available and randomly assign the rest.
    """
    return _assign_random(free, locked, options, issues)


# -----------------------------------------------------------------------------
# Weight balancing
# -----------------------------------------------------------------------------


def _apply_balance_weights(
    items: Sequence[SplitItem],
    options: SplitOptions,
) -> list[SplitItem]:
    """
    Apply bounded class-balancing weights when configured.
    """
    if not options.balance_classes or options.weight_mode == "none":
        return list(items)

    counts = Counter(item.label_code for item in items if item.label_code is not None)
    total = sum(counts.values())
    class_count = len(counts)

    if total <= 0 or class_count <= 0:
        return list(items)

    out: list[SplitItem] = []

    for item in items:
        base_weight = float(item.weight)

        if item.label_code is None:
            factor = 1.0
        else:
            class_total = int(counts.get(item.label_code, 0))

            if class_total <= 0:
                factor = 0.0
            else:
                factor = float(total) / (float(class_count) * float(class_total))

        weighted = base_weight * factor
        weighted = _clip_float(weighted, 0.0, options.max_weight, base_weight)
        out.append(replace(item, weight=round(weighted, 6)))

    return out


# -----------------------------------------------------------------------------
# Metrics and fingerprints
# -----------------------------------------------------------------------------


def _label_name(code: Optional[int], taxonomy: Any | None = None) -> str:
    """
    Return a safe label name for a code.
    """
    if code is None:
        return "unlabeled"

    if taxonomy is not None and hasattr(taxonomy, "decode"):
        try:
            return str(taxonomy.decode(code))
        except Exception:
            pass

    try:
        resolved = int(code)
    except (TypeError, ValueError):
        return "unknown"

    return _LOCAL_LABEL_NAMES.get(resolved, f"label_{resolved}")


def _compute_counts(items: Sequence[SplitItem]) -> dict[str, int]:
    """
    Compute safe split counts.
    """
    counts = {"total": len(items)}

    for split in _SPLIT_ORDER:
        counts[split.value] = sum(1 for item in items if item.split == split)

    labeled = sum(1 for item in items if item.label_code is not None)
    counts["labeled"] = labeled
    counts["unlabeled"] = len(items) - labeled
    return counts


def _compute_metrics(
    items: Sequence[SplitItem],
    options: SplitOptions,
    taxonomy: Any | None,
    issues: list[SplitIssue],
) -> dict[str, Any]:
    """
    Compute safe split quality metrics and append warnings when needed.
    """
    counts = _compute_counts(items)
    total = int(counts.get("total", 0))
    labeled = int(counts.get("labeled", 0))

    class_counter = Counter(item.label_code for item in items if item.label_code is not None)
    class_distribution = {
        _label_name(code, taxonomy): float(count) / float(labeled)
        for code, count in sorted(class_counter.items())
    } if labeled > 0 else {}

    per_split: dict[str, Any] = {}
    group_splits: dict[str, set[str]] = defaultdict(set)
    temporal_bounds: dict[str, dict[str, Optional[str]]] = {}

    for split in _SPLIT_ORDER:
        split_items = [item for item in items if item.split == split]
        split_class_counter = Counter(
            item.label_code
            for item in split_items
            if item.label_code is not None
        )
        split_labeled = sum(split_class_counter.values())

        per_split[split.value] = {
            "count": len(split_items),
            "labeled": split_labeled,
            "class_distribution": {
                _label_name(code, taxonomy): float(count) / float(split_labeled)
                for code, count in sorted(split_class_counter.items())
            } if split_labeled > 0 else {},
        }

        timestamps = [item.timestamp for item in split_items if item.timestamp is not None]

        temporal_bounds[split.value] = {
            "min": min(timestamps).isoformat() if timestamps else None,
            "max": max(timestamps).isoformat() if timestamps else None,
        }

        for item in split_items:
            group_splits[item.group_key_hash].add(split.value)

    group_overlap_count = sum(1 for split_set in group_splits.values() if len(split_set) > 1)

    temporal_overlap = False

    train_bounds = temporal_bounds.get(SplitName.TRAIN.value, {})
    validation_bounds = temporal_bounds.get(SplitName.VALIDATION.value, {})
    test_bounds = temporal_bounds.get(SplitName.TEST.value, {})

    train_max = _parse_datetime(train_bounds.get("max"))
    validation_min = _parse_datetime(validation_bounds.get("min"))
    validation_max = _parse_datetime(validation_bounds.get("max"))
    test_min = _parse_datetime(test_bounds.get("min"))

    if train_max is not None and validation_min is not None and train_max >= validation_min:
        temporal_overlap = True

    if validation_max is not None and test_min is not None and validation_max >= test_min:
        temporal_overlap = True

    entropy = _normalized_entropy(class_counter)
    class_counts = list(class_counter.values())
    max_class_count = max(class_counts, default=0)
    min_class_count = min(class_counts, default=0)
    imbalance_ratio = float(max_class_count) / float(min_class_count) if min_class_count > 0 else 0.0
    max_class_share = max(class_distribution.values(), default=0.0)

    actual_ratios = {
        split.value: float(counts.get(split.value, 0)) / float(total)
        if total > 0
        else 0.0
        for split in _SPLIT_ORDER
    }

    if group_overlap_count > 0 and options.strategy in {SplitStrategy.GROUPED, SplitStrategy.HYBRID}:
        _add_issue(
            issues,
            severity=IssueSeverity.WARNING,
            code="group_split_overlap",
            message="Groups appear in more than one split.",
            details={"overlap_group_count": group_overlap_count},
        )

    if temporal_overlap and options.strategy == SplitStrategy.TEMPORAL:
        _add_issue(
            issues,
            severity=IssueSeverity.WARNING,
            code="temporal_split_overlap",
            message="Temporal splits overlap.",
        )

    if not options.allow_empty_splits:
        empty_splits = [
            split.value
            for split in _SPLIT_ORDER
            if int(counts.get(split.value, 0)) == 0
        ]

        if empty_splits:
            _add_issue(
                issues,
                severity=IssueSeverity.WARNING,
                code="empty_split",
                message="One or more splits are empty.",
                details={"empty_splits": empty_splits},
            )

    if labeled > 0 and max_class_share > options.max_class_share:
        _add_issue(
            issues,
            severity=IssueSeverity.WARNING,
            code="class_share_above_target",
            message="Maximum class share exceeds configured target.",
            details={
                "max_class_share": round(max_class_share, 6),
                "target_max_class_share": round(options.max_class_share, 6),
            },
        )

    return {
        "counts": counts,
        "actual_ratios": {
            key: round(float(value), 6)
            for key, value in actual_ratios.items()
        },
        "class_distribution": {
            key: round(float(value), 6)
            for key, value in class_distribution.items()
        },
        "per_split": per_split,
        "group_overlap_count": group_overlap_count,
        "temporal_bounds": temporal_bounds,
        "temporal_overlap": temporal_overlap,
        "entropy": round(float(entropy), 6),
        "imbalance_ratio": round(float(imbalance_ratio), 6),
        "max_class_share": round(float(max_class_share), 6),
        "min_class_count": int(min_class_count),
        "max_class_count": int(max_class_count),
    }


def _config_fingerprint(options: SplitOptions) -> str:
    """
    Return deterministic config fingerprint.
    """
    try:
        return _sha256_hex(_canonical_json(options.safe_summary()))
    except Exception:
        return _sha256_hex(str(options.safe_summary()))


def _data_fingerprint(items: Sequence[SplitItem]) -> str:
    """
    Return deterministic dataset fingerprint independent of split assignment.
    """
    digest = hashlib.sha256()
    digest.update(f"muleguard.ml.splits.data.{SPLITS_VERSION}|{len(items)}".encode("utf-8", errors="replace"))

    rows = sorted(
        (
            item.subject_ref_hash,
            item.group_key_hash,
            str(item.label_code if item.label_code is not None else -1),
            item.timestamp.isoformat() if item.timestamp is not None else "",
        )
        for item in items
    )

    for row in rows:
        digest.update("\x00".join(row).encode("utf-8", errors="replace"))
        digest.update(b"\n")

    return digest.hexdigest()


def _plan_fingerprint(items: Sequence[SplitItem]) -> str:
    """
    Return deterministic split plan fingerprint.
    """
    digest = hashlib.sha256()
    digest.update(f"muleguard.ml.splits.plan.{SPLITS_VERSION}|{len(items)}".encode("utf-8", errors="replace"))

    rows = sorted(
        (
            item.subject_ref_hash,
            item.split_name,
            item.group_key_hash,
            str(item.label_code if item.label_code is not None else -1),
            f"{float(item.weight):.6f}",
            str(item.source_index if item.source_index is not None else -1),
        )
        for item in items
    )

    for row in rows:
        digest.update("\x00".join(row).encode("utf-8", errors="replace"))
        digest.update(b"\n")

    return digest.hexdigest()


# -----------------------------------------------------------------------------
# Split plan model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SplitPlan:
    """
    Internal-facing bounded ML split plan.

    Public summaries deliberately exclude subject-label pairs.
    """

    plan_id: str
    strategy: SplitStrategy
    generated_at: datetime
    config_fingerprint: str
    data_fingerprint: str
    fingerprint: str
    items: tuple[SplitItem, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    issues: tuple[SplitIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize plan values.
        """
        object.__setattr__(self, "strategy", _normalize_strategy(self.strategy))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "items", tuple(self.items or ()))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts or {})))
        object.__setattr__(self, "metrics", MappingProxyType(_safe_detail_value(self.metrics) or {}))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

    def __len__(self) -> int:
        """
        Return number of split items.
        """
        return len(self.items)

    def __iter__(self):
        """
        Iterate split items.

        This is internal-facing and must not be exposed publicly.
        """
        return iter(self.items)

    def items_for_split(self, split: Any) -> tuple[SplitItem, ...]:
        """
        Return items assigned to one split.
        """
        target = _normalize_split_name(split)

        if target is None:
            return ()

        return tuple(item for item in self.items if item.split == target)

    def subject_to_split(self) -> dict[str, str]:
        """
        Return internal subject-to-split mapping.

        This is internal-facing and must not be exposed publicly.
        """
        return {
            item.subject_ref_hash: item.split_name
            for item in self.items
            if item.split is not None
        }

    def partitions(self) -> dict[str, tuple[SplitItem, ...]]:
        """
        Return internal split partitions.

        This is internal-facing and must not be exposed publicly.
        """
        return {
            split.value: self.items_for_split(split)
            for split in _SPLIT_ORDER
        }

    def validate(self) -> list[SplitIssue]:
        """
        Return safe validation issues for this plan.
        """
        issues: list[SplitIssue] = []
        subject_splits: dict[str, set[str]] = defaultdict(set)

        for item in self.items:
            if item.split is not None:
                subject_splits[item.subject_ref_hash].add(item.split.value)

        overlapping = sum(1 for split_set in subject_splits.values() if len(split_set) > 1)

        if overlapping:
            _add_issue(
                issues,
                severity=IssueSeverity.ERROR,
                code="subject_split_overlap",
                message="One or more subjects appear in multiple splits.",
                details={"overlap_subject_count": overlapping},
            )

        counts = dict(self.counts or {})
        total = int(counts.get("total", len(self.items)))

        if total != len(self.items):
            _add_issue(
                issues,
                severity=IssueSeverity.ERROR,
                code="split_count_mismatch",
                message="Split plan count metadata does not match items.",
                details={"metadata_total": total, "item_count": len(self.items)},
            )

        return issues

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include subject-label pairs, subject hashes,
        group hashes, timestamps, weights, or item-level assignments.
        """
        return {
            "plan_id": self.plan_id,
            "strategy": self.strategy.value,
            "generated_at": self.generated_at.isoformat(),
            "config_fingerprint": self.config_fingerprint,
            "data_fingerprint": self.data_fingerprint,
            "fingerprint": self.fingerprint,
            "counts": dict(self.counts),
            "metrics": _safe_detail_value(self.metrics),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "items_omitted": True,
            "caveats": list(_SPLIT_CAVEATS),
            "safety_flags": dict(_SPLIT_SAFETY_FLAGS),
        }

    def to_internal_dict(self) -> dict[str, Any]:
        """
        Return a fuller internal representation.

        This contains subject-label pairs and must not be exposed publicly.
        """
        payload = self.to_public_dict()
        payload.pop("items_omitted", None)
        payload["internal_only"] = True
        payload["items"] = [
            {
                "subject_ref_hash": item.subject_ref_hash,
                "split": item.split_name,
                "group_key_hash": item.group_key_hash,
                "label_code": item.label_code,
                "weight": float(item.weight),
                "timestamp": item.timestamp.isoformat() if item.timestamp else None,
                "source_index": item.source_index,
                "metadata": _safe_detail_value(item.metadata),
            }
            for item in self.items
        ]
        return payload


def _empty_split_plan(
    options: SplitOptions,
    issues: Sequence[SplitIssue],
    generated_at: Optional[datetime] = None,
) -> SplitPlan:
    """
    Return a safe empty split plan.
    """
    stamp = _ensure_utc(generated_at) or _now_utc()
    config_fp = _config_fingerprint(options)
    data_fp = _data_fingerprint(())
    plan_fp = _plan_fingerprint(())

    counts = _compute_counts(())
    metrics: dict[str, Any] = {
        "counts": counts,
        "actual_ratios": {
            split.value: 0.0
            for split in _SPLIT_ORDER
        },
        "class_distribution": {},
        "per_split": {
            split.value: {
                "count": 0,
                "labeled": 0,
                "class_distribution": {},
            }
            for split in _SPLIT_ORDER
        },
        "group_overlap_count": 0,
        "temporal_bounds": {
            split.value: {"min": None, "max": None}
            for split in _SPLIT_ORDER
        },
        "temporal_overlap": False,
        "entropy": 0.0,
        "imbalance_ratio": 0.0,
        "max_class_share": 0.0,
        "min_class_count": 0,
        "max_class_count": 0,
    }

    metadata = {
        "splits_version": SPLITS_VERSION,
        "options": options.safe_summary(),
        "empty_plan": True,
        "caveats": list(_SPLIT_CAVEATS),
        "safety_flags": dict(_SPLIT_SAFETY_FLAGS),
    }

    return SplitPlan(
        plan_id=plan_fp[:32],
        strategy=options.strategy,
        generated_at=stamp,
        config_fingerprint=config_fp,
        data_fingerprint=data_fp,
        fingerprint=plan_fp,
        items=(),
        counts=counts,
        metrics=metrics,
        issues=tuple(issues),
        metadata=metadata,
    )


# -----------------------------------------------------------------------------
# Core builder
# -----------------------------------------------------------------------------


def _add_issue(
    issues: list[SplitIssue],
    *,
    severity: IssueSeverity,
    code: str,
    message: str,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Append one safe issue with a hard cap.

    This is a hardened replacement for the earlier unbounded helper. It keeps
    issue reporting bounded even when malformed input produces many warnings or
    errors.
    """
    if len(issues) >= _HARD_MAX_ISSUES:
        if issues and issues[-1].code != "issue_list_truncated":
            issues.append(
                SplitIssue(
                    severity=IssueSeverity.WARNING,
                    code="issue_list_truncated",
                    message="Issue list truncated by hard limit.",
                )
            )
        return

    issues.append(
        SplitIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _truncate_issues(
    issues: Sequence[SplitIssue],
    max_issues: int,
) -> tuple[SplitIssue, ...]:
    """
    Return a bounded issue tuple.
    """
    limit = max(1, int(max_issues))

    if len(issues) <= limit:
        return tuple(issues)

    out = list(issues[: max(0, limit - 1)])

    out.append(
        SplitIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
    )

    return tuple(out)


def _taxonomy_metadata(taxonomy: Any | None) -> dict[str, Any]:
    """
    Return safe metadata from an optional taxonomy-like object.

    This avoids a hard dependency on `app.ml.labels` while still allowing
    taxonomy version and fingerprint propagation when available.
    """
    if taxonomy is None:
        return {}

    out: dict[str, Any] = {}

    version = getattr(taxonomy, "version", None)

    if version is not None:
        out["version"] = _clean_text(version, 32)

    fingerprint = getattr(taxonomy, "fingerprint", None)

    if callable(fingerprint):
        try:
            value = fingerprint()
        except Exception:
            value = None

        if value is not None:
            out["fingerprint"] = _clean_text(value, 128)

    summary = getattr(taxonomy, "summary", None)

    if callable(summary):
        try:
            value = summary()
        except Exception:
            value = None

        if value is not None:
            out["summary"] = _safe_detail_value(value)

    return out


def _build_split_plan(
    records: Any,
    options: SplitOptions | None = None,
    taxonomy: Any | None = None,
) -> SplitPlan:
    """
    Core bounded split builder.

    Args:
        records: Split input records. May be a mapping, sequence of mappings,
            iterable of mappings, or object-like records with accepted fields.
        options: Optional split policy. Resolved from settings when absent.
        taxonomy: Optional taxonomy-like object used only for label-code
            normalization and safe distribution labels.

    Returns:
        SplitPlan containing internal split assignments and safe public
        metadata.
    """
    opts = options or SplitOptions.from_settings()
    generated_at = _now_utc()
    issues: list[SplitIssue] = []

    record_list = _as_sequence(records)
    submitted = len(record_list)

    if not opts.enabled:
        _add_issue(
            issues,
            severity=IssueSeverity.INFO,
            code="splits_disabled",
            message="ML split construction is disabled.",
        )
        return _empty_split_plan(opts, issues, generated_at)

    if opts.synthetic_required and opts.dataset_mode != "synthetic":
        _add_issue(
            issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="ML split construction requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
        return _empty_split_plan(opts, issues, generated_at)

    if opts.production_like and not opts.allow_in_production:
        _add_issue(
            issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="ML split construction is blocked in production-like environments.",
        )
        return _empty_split_plan(opts, issues, generated_at)

    items = _normalize_items(record_list, opts, taxonomy, issues)

    if not items:
        _add_issue(
            issues,
            severity=IssueSeverity.WARNING,
            code="no_split_items",
            message="No valid split items were available.",
            details={"submitted": submitted},
        )
        return _empty_split_plan(opts, issues, generated_at)

    subject_counts = Counter(item.subject_ref_hash for item in items)
    duplicate_subject_count = sum(1 for count in subject_counts.values() if count > 1)

    if duplicate_subject_count:
        _add_issue(
            issues,
            severity=IssueSeverity.WARNING,
            code="duplicate_subject_references",
            message="Duplicate subject references were detected in split input.",
            details={"duplicate_subject_count": duplicate_subject_count},
        )

    group_counts = Counter(item.group_key_hash for item in items)
    duplicate_group_count = sum(1 for count in group_counts.values() if count > 1)

    if duplicate_group_count and opts.strategy in {SplitStrategy.GROUPED, SplitStrategy.HYBRID}:
        _add_issue(
            issues,
            severity=IssueSeverity.INFO,
            code="grouped_split_multiple_items_per_group",
            message="Grouped splitting detected multiple items for some groups.",
            details={"duplicate_group_count": duplicate_group_count},
        )

    locked: list[SplitItem] = []
    free: list[SplitItem] = []

    for item in items:
        if opts.preserve_existing_splits and item.split is not None:
            locked.append(item)
        else:
            free.append(replace(item, split=None))

    if opts.strategy == SplitStrategy.TEMPORAL:
        assigned = _assign_temporal(free, locked, opts, issues)
    elif opts.strategy == SplitStrategy.GROUPED:
        assigned = _assign_grouped(free, locked, opts, issues, hybrid=False)
    elif opts.strategy == SplitStrategy.HYBRID:
        assigned = _assign_grouped(free, locked, opts, issues, hybrid=True)
    elif opts.strategy == SplitStrategy.STRATIFIED:
        assigned = _assign_stratified(free, locked, opts, issues)
    elif opts.strategy == SplitStrategy.PRESERVE:
        assigned = _assign_preserve(free, locked, opts, issues)
    else:
        assigned = _assign_random(free, locked, opts, issues)

    final_items = locked + assigned
    final_items = _apply_balance_weights(final_items, opts)

    final_items.sort(
        key=lambda item: (
            item.source_index if item.source_index is not None else 10**12,
            item.subject_ref_hash,
        )
    )

    counts = _compute_counts(final_items)
    metrics = _compute_metrics(final_items, opts, taxonomy, issues)

    issue_count = len(issues)
    error_count = sum(1 for issue in issues if issue.severity == IssueSeverity.ERROR)
    warning_count = sum(1 for issue in issues if issue.severity == IssueSeverity.WARNING)
    info_count = sum(1 for issue in issues if issue.severity == IssueSeverity.INFO)

    bounded_issues = _truncate_issues(issues, opts.max_issues)

    config_fp = _config_fingerprint(opts)
    data_fp = _data_fingerprint(items)
    plan_fp = _plan_fingerprint(final_items)

    metadata: dict[str, Any] = {
        "splits_version": SPLITS_VERSION,
        "submitted": submitted,
        "normalized_count": len(items),
        "locked_count": len(locked),
        "free_count": len(free),
        "assigned_count": len(assigned),
        "final_count": len(final_items),
        "strategy": opts.strategy.value,
        "group_by": opts.group_by.value,
        "generated_at": generated_at.isoformat(),
        "config_fingerprint": config_fp,
        "data_fingerprint": data_fp,
        "plan_fingerprint": plan_fp,
        "issue_count": issue_count,
        "error_count": error_count,
        "warning_count": warning_count,
        "info_count": info_count,
        "issue_truncated": len(bounded_issues) < issue_count,
        "taxonomy": _taxonomy_metadata(taxonomy),
        "options": opts.safe_summary(),
        "caveats": list(_SPLIT_CAVEATS),
        "safety_flags": dict(_SPLIT_SAFETY_FLAGS),
    }

    return SplitPlan(
        plan_id=plan_fp[:32],
        strategy=opts.strategy,
        generated_at=generated_at,
        config_fingerprint=config_fp,
        data_fingerprint=data_fp,
        fingerprint=plan_fp,
        items=tuple(final_items),
        counts=counts,
        metrics=metrics,
        issues=bounded_issues,
        metadata=metadata,
    )


# -----------------------------------------------------------------------------
# Public split-plan builders
# -----------------------------------------------------------------------------


def build_split_plan(
    records: Any,
    options: SplitOptions | None = None,
    taxonomy: Any | None = None,
) -> SplitPlan:
    """
    Build one bounded ML split plan from split records.

    This is the primary public helper for split construction.

    Args:
        records: Split input records. Each record should contain at least a
            subject reference. Accepted fields include subject-like identifiers,
            optional group keys, optional labels, optional existing splits,
            optional weights, optional timestamps, and optional metadata.
        options: Optional split policy. Resolved from settings when absent.
        taxonomy: Optional taxonomy-like object for safer label normalization
            and label distribution naming.

    Returns:
        SplitPlan containing internal assignments and safe public metadata.
    """
    return _build_split_plan(records, options=options, taxonomy=taxonomy)


def build_split_plan_from_label_set(
    label_set: Any,
    options: SplitOptions | None = None,
    taxonomy: Any | None = None,
) -> SplitPlan:
    """
    Build one bounded ML split plan from a label-set-like object.

    Supported shapes:

    - object with `subject_hashes`, `label_codes`, `splits`, and `weights`;
    - mapping with the same keys;
    - mapping with `records` or `items`;
    - bare mapping treated as one record;
    - iterable of records.

    This helper is internal-facing. It does not expose subject-label pairs in
    public summaries.
    """
    records: list[Any] = []

    if label_set is None:
        records = []
    elif isinstance(label_set, Mapping):
        if "subject_hashes" in label_set:
            subject_hashes = _as_sequence(label_set.get("subject_hashes") or ())
            label_codes = _as_sequence(label_set.get("label_codes") or ())
            splits = _as_sequence(label_set.get("splits") or ())
            weights = _as_sequence(label_set.get("weights") or ())

            for index, subject in enumerate(subject_hashes):
                record: dict[str, Any] = {"subject_ref_hash": subject}

                if index < len(label_codes):
                    record["label_code"] = label_codes[index]

                if index < len(splits):
                    record["split"] = splits[index]

                if index < len(weights):
                    record["weight"] = weights[index]

                records.append(record)
        elif "records" in label_set:
            records = _as_sequence(label_set.get("records") or ())
        elif "items" in label_set:
            records = _as_sequence(label_set.get("items") or ())
        else:
            records = [label_set]
    else:
        subject_hashes = getattr(label_set, "subject_hashes", None)

        if subject_hashes is None:
            records = _as_sequence(label_set)
        else:
            subject_hashes = _as_sequence(subject_hashes)
            label_codes = _as_sequence(getattr(label_set, "label_codes", ()) or ())
            splits = _as_sequence(getattr(label_set, "splits", ()) or ())
            weights = _as_sequence(getattr(label_set, "weights", ()) or ())

            for index, subject in enumerate(subject_hashes):
                record = {"subject_ref_hash": subject}

                if index < len(label_codes):
                    record["label_code"] = label_codes[index]

                if index < len(splits):
                    record["split"] = splits[index]

                if index < len(weights):
                    record["weight"] = weights[index]

                records.append(record)

    return _build_split_plan(records, options=options, taxonomy=taxonomy)


def build_split_plan_from_aligned_examples(
    aligned: Any,
    options: SplitOptions | None = None,
    taxonomy: Any | None = None,
) -> SplitPlan:
    """
    Build one bounded ML split plan from aligned feature-label examples.

    Supported shapes:

    - object with `subject_hashes`, `y`, and `weights`;
    - mapping with the same keys;
    - mapping with `records` or `items`;
    - iterable of records.

    This helper is internal-facing. It does not expose subject-label pairs in
    public summaries.
    """
    records: list[Any] = []

    if aligned is None:
        records = []
    elif isinstance(aligned, Mapping):
        if "subject_hashes" in aligned:
            subject_hashes = _as_sequence(aligned.get("subject_hashes") or ())
            y = _as_sequence(aligned.get("y") or aligned.get("label_codes") or ())
            weights = _as_sequence(aligned.get("weights") or ())

            for index, subject in enumerate(subject_hashes):
                record: dict[str, Any] = {"subject_ref_hash": subject}

                if index < len(y):
                    record["label_code"] = y[index]

                if index < len(weights):
                    record["weight"] = weights[index]

                records.append(record)
        elif "records" in aligned:
            records = _as_sequence(aligned.get("records") or ())
        elif "items" in aligned:
            records = _as_sequence(aligned.get("items") or ())
        else:
            records = [aligned]
    else:
        subject_hashes = getattr(aligned, "subject_hashes", None)

        if subject_hashes is None:
            records = _as_sequence(aligned)
        else:
            subject_hashes = _as_sequence(subject_hashes)
            y = _as_sequence(getattr(aligned, "y", None) or getattr(aligned, "label_codes", ()) or ())
            weights = _as_sequence(getattr(aligned, "weights", ()) or ())

            for index, subject in enumerate(subject_hashes):
                record = {"subject_ref_hash": subject}

                if index < len(y):
                    record["label_code"] = y[index]

                if index < len(weights):
                    record["weight"] = weights[index]

                records.append(record)

    return _build_split_plan(records, options=options, taxonomy=taxonomy)


def build_split_plan_from_feature_vectors(
    feature_vectors: Any,
    options: SplitOptions | None = None,
    taxonomy: Any | None = None,
    *,
    include_metadata: bool = True,
) -> SplitPlan:
    """
    Build one bounded ML split plan from feature-vector-like objects.

    This helper extracts only pseudonymous subject references and safe metadata.
    It does not copy feature values into the split plan.

    Supported shapes:

    - object or mapping with `subject_ref_hash`;
    - sequence of such objects or mappings;
    - payload wrapper with `records` or `items`.
    """
    vectors = _as_sequence(feature_vectors)
    records: list[Any] = []

    for index, vector in enumerate(vectors):
        subject: Any = None
        metadata: Any = None

        if isinstance(vector, Mapping):
            subject = (
                vector.get("subject_ref_hash")
                or vector.get("subject_hash")
                or vector.get("subject")
                or vector.get("account_id")
                or vector.get("acct_id")
                or vector.get("id")
            )

            if include_metadata:
                metadata = vector.get("metadata") or vector.get("metadata_json")
        else:
            subject = (
                getattr(vector, "subject_ref_hash", None)
                or getattr(vector, "subject_hash", None)
                or getattr(vector, "subject", None)
                or getattr(vector, "account_id", None)
                or getattr(vector, "acct_id", None)
                or getattr(vector, "id", None)
            )

            if include_metadata:
                metadata = getattr(vector, "metadata", None)

        if not subject:
            continue

        record: dict[str, Any] = {
            "subject_ref_hash": subject,
            "source_index": index,
        }

        if include_metadata and metadata is not None:
            record["metadata"] = metadata

        records.append(record)

    return _build_split_plan(records, options=options, taxonomy=taxonomy)


# -----------------------------------------------------------------------------
# Split-plan accessors
# -----------------------------------------------------------------------------


def split_plan_partitions(plan: SplitPlan) -> dict[str, tuple[SplitItem, ...]]:
    """
    Return internal split partitions.

    This is internal-facing and must not be exposed publicly.
    """
    return plan.partitions()


def training_items(plan: SplitPlan) -> tuple[SplitItem, ...]:
    """
    Return internal training split items.
    """
    return plan.items_for_split(SplitName.TRAIN)


def validation_items(plan: SplitPlan) -> tuple[SplitItem, ...]:
    """
    Return internal validation split items.
    """
    return plan.items_for_split(SplitName.VALIDATION)


def test_items(plan: SplitPlan) -> tuple[SplitItem, ...]:
    """
    Return internal test split items.
    """
    return plan.items_for_split(SplitName.TEST)


def subject_split_map(plan: SplitPlan) -> dict[str, str]:
    """
    Return internal subject-to-split mapping.

    This is internal-facing and must not be exposed publicly.
    """
    return plan.subject_to_split()


def split_plan_fingerprint(plan: SplitPlan) -> str:
    """
    Return the deterministic split-plan fingerprint.
    """
    return plan.fingerprint


def split_plan_has_errors(plan: SplitPlan) -> bool:
    """
    Return True when the plan contains error issues or validation errors.
    """
    if any(issue.severity == IssueSeverity.ERROR for issue in plan.issues):
        return True

    return any(issue.severity == IssueSeverity.ERROR for issue in plan.validate())


def assert_no_split_leakage(plan: SplitPlan) -> None:
    """
    Raise a safe validation error when split leakage is detected.

    Leakage checks include subject overlap across splits and count metadata
    mismatches.
    """
    issues = plan.validate()
    errors = [issue for issue in issues if issue.severity == IssueSeverity.ERROR]

    if errors:
        raise MuleGuardValidationError(
            "Split plan failed leakage validation.",
            details={
                "issue_count": len(errors),
                "codes": [issue.code for issue in errors[:50]],
            },
        )


def apply_split_plan_to_items(
    items: Sequence[SplitItem],
    plan: SplitPlan,
    *,
    missing_policy: str = "unassigned",
) -> list[SplitItem]:
    """
    Apply split assignments from a plan to existing split items.

    Args:
        items: Items to update.
        plan: Source split plan.
        missing_policy: One of `unassigned`, `train`, `validation`, `test`,
            `error`, or `drop`.

    Returns:
        Updated items with split assignments from the plan where available.
    """
    mapping = plan.subject_to_split()
    out: list[SplitItem] = []
    policy = _normalize_token(missing_policy) or "unassigned"

    for item in items:
        split_name = mapping.get(item.subject_ref_hash)

        if split_name:
            out.append(replace(item, split=_normalize_split_name(split_name)))
            continue

        if policy == "drop":
            continue

        if policy == "error":
            raise MuleGuardValidationError(
                "Split item missing from plan.",
                details={"subject_omitted": True},
            )

        if policy in {"train", "training"}:
            out.append(replace(item, split=SplitName.TRAIN))
        elif policy in {"validation", "valid", "val"}:
            out.append(replace(item, split=SplitName.VALIDATION))
        elif policy in {"test", "holdout"}:
            out.append(replace(item, split=SplitName.TEST))
        else:
            out.append(replace(item, split=None))

    return out


def filter_items_by_split(
    items: Sequence[SplitItem],
    split: Any,
) -> tuple[SplitItem, ...]:
    """
    Return items assigned to one split.
    """
    target = _normalize_split_name(split)

    if target is None:
        return ()

    return tuple(item for item in items if item.split == target)


def split_item_labels(
    items: Sequence[SplitItem],
) -> tuple[int, ...]:
    """
    Return internal label codes for split items.

    Unlabeled items are represented as `-1`.
    """
    return tuple(
        int(item.label_code) if item.label_code is not None else -1
        for item in items
    )


def split_item_weights(
    items: Sequence[SplitItem],
) -> tuple[float, ...]:
    """
    Return internal weights for split items.
    """
    return tuple(
        round(_clip_float(item.weight, 0.0, _DEFAULT_MAX_WEIGHT, 1.0), 6)
        for item in items
    )


def split_item_subjects(
    items: Sequence[SplitItem],
) -> tuple[str, ...]:
    """
    Return internal subject hashes for split items.
    """
    return tuple(item.subject_ref_hash for item in items)


# -----------------------------------------------------------------------------
# Reporting helpers
# -----------------------------------------------------------------------------


def summarize_split_plan(plan: SplitPlan) -> dict[str, Any]:
    """
    Return a safe API-facing split-plan summary.
    """
    return plan.to_public_dict()


def split_quality_report(plan: SplitPlan) -> dict[str, Any]:
    """
    Return a safe split-quality report.

    This does not include subject-label pairs.
    """
    validation_issues = plan.validate()
    metrics = dict(plan.metrics or {})
    counts = dict(plan.counts or {})

    return {
        "plan_id": plan.plan_id,
        "strategy": plan.strategy.value,
        "generated_at": plan.generated_at.isoformat(),
        "config_fingerprint": plan.config_fingerprint,
        "data_fingerprint": plan.data_fingerprint,
        "fingerprint": plan.fingerprint,
        "counts": counts,
        "metrics": _safe_detail_value(metrics),
        "issues": [issue.to_dict() for issue in plan.issues],
        "validation_issues": [issue.to_dict() for issue in validation_issues],
        "metadata": _safe_detail_value(plan.metadata),
        "caveats": list(_SPLIT_CAVEATS),
        "safety_flags": dict(_SPLIT_SAFETY_FLAGS),
    }


def split_plan_diff(
    left: SplitPlan,
    right: SplitPlan,
) -> dict[str, Any]:
    """
    Return a safe comparison between two split plans.

    This compares fingerprints, counts, strategies, and issue codes. It does not
    expose subject-label pairs.
    """
    left_counts = dict(left.counts or {})
    right_counts = dict(right.counts or {})

    count_diff = {
        key: int(right_counts.get(key, 0)) - int(left_counts.get(key, 0))
        for key in sorted(set(left_counts) | set(right_counts))
    }

    left_issue_codes = Counter(issue.code for issue in left.issues)
    right_issue_codes = Counter(issue.code for issue in right.issues)

    issue_diff = {
        code: int(right_issue_codes.get(code, 0)) - int(left_issue_codes.get(code, 0))
        for code in sorted(set(left_issue_codes) | set(right_issue_codes))
    }

    return {
        "same_fingerprint": left.fingerprint == right.fingerprint,
        "same_config": left.config_fingerprint == right.config_fingerprint,
        "same_data": left.data_fingerprint == right.data_fingerprint,
        "left_plan_id": left.plan_id,
        "right_plan_id": right.plan_id,
        "left_strategy": left.strategy.value,
        "right_strategy": right.strategy.value,
        "count_diff": count_diff,
        "issue_diff": issue_diff,
        "caveats": list(_SPLIT_CAVEATS),
        "safety_flags": dict(_SPLIT_SAFETY_FLAGS),
    }


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_splits_metadata() -> dict[str, Any]:
    """
    Return safe, serializable ML split-layer metadata.

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
    options = SplitOptions.from_settings()

    return {
        "package": "muleguard.backend.ml.splits",
        "version": SPLITS_VERSION,
        "split_names": [split.value for split in _SPLIT_ORDER],
        "strategies": [strategy.value for strategy in SplitStrategy],
        "group_by_options": [group.value for group in SplitGroupBy],
        "default_options": options.safe_summary(),
        "builder_backend": "in_memory_deterministic",
        "distributed": False,
        "durable": False,
        "hard_limits": {
            "max_items": _HARD_MAX_ITEMS,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_weight": _DEFAULT_MAX_WEIGHT,
        },
        "forbidden_split_field_count": len(_FORBIDDEN_SPLIT_FIELDS),
        "accepted_split_fields": sorted(_ACCEPTED_SPLIT_FIELDS),
        "caveats": list(_SPLIT_CAVEATS),
        "safety_flags": dict(_SPLIT_SAFETY_FLAGS),
    }


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "IssueSeverity",
    "SplitOptions",
    "SplitGroupBy",
    "SplitItem",
    "SplitIssue",
    "SplitName",
    "SplitPlan",
    "SplitStrategy",
    "apply_split_plan_to_items",
    "assert_no_split_leakage",
    "build_split_plan",
    "build_split_plan_from_aligned_examples",
    "build_split_plan_from_feature_vectors",
    "build_split_plan_from_label_set",
    "filter_items_by_split",
    "get_splits_metadata",
    "split_item_labels",
    "split_item_subjects",
    "split_item_weights",
    "split_plan_diff",
    "split_plan_fingerprint",
    "split_plan_has_errors",
    "split_plan_partitions",
    "split_quality_report",
    "subject_split_map",
    "summarize_split_plan",
    "test_items",
    "training_items",
    "validation_items",
]