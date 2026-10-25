"""
MULEGUARD backend ML fallback.

This module provides the canonical bounded heuristic fallback scoring layer for
the synthetic MULEGUARD machine-learning subsystem.

Primary responsibilities:

- produce deterministic, explainable, bounded investigative prioritization
  scores from synthetic feature vectors when trained ML models are unavailable,
  disabled, unhealthy, or intentionally bypassed for controlled testing;
- combine known synthetic risk signals using transparent weighted evidence
  aggregation rather than hidden model inference;
- reject leakage-prone inputs such as ground-truth labels, injected scenario
  IDs, fraud-ring IDs, raw complaint narratives, raw identifiers, secrets,
  tokens, passwords, database URLs, filesystem paths, and model artifact paths;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values from public summaries;
- provide bounded contribution reporting, honest unavailable-score handling,
  safe fingerprints, issue reporting, and API-facing summaries;
- remain import-safe, dependency-light, and usable by ML services, APIs,
  evaluation harnesses, tests, seeders, offline fixtures, and developer tooling.

This module scores fallback heuristics only. It does not train models, deploy
models, evaluate supervised models, persist data, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for fallback scoring.
- Fallback scores are investigative prioritization signals only. They are not
  probabilities of guilt.
- Fallback flags are operational review prompts only. They are not proof of
  wrongdoing.
- Feature contributions are operational attributions only. They are not causal
  proof.
- Labels must never be used as features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden. Subject linkage is pseudonymous and salted.
- Fallback handling never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable scores are reported honestly as unavailable rather
  than invented.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call model runtimes.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable score store.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, and case dispositions are
investigative leads or human workflow artefacts only. They are not proof of
wrongdoing and must not trigger automatic adverse customer action.
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

logger = logging.getLogger("muleguard.backend.ml.fallback")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

FALLBACK_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.fallback.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_RECORDS: Final[int] = 10_000
_HARD_MAX_RECORDS: Final[int] = 100_000

_DEFAULT_MAX_FEATURES: Final[int] = 512
_HARD_MAX_FEATURES: Final[int] = 4_096

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_CONTRIBUTIONS: Final[int] = 20
_HARD_MAX_CONTRIBUTIONS: Final[int] = 200

_DEFAULT_MAX_WEIGHT: Final[float] = 100.0
_DEFAULT_THRESHOLD: Final[float] = 0.60

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

_MISSING: Final[object] = object()

_SUBJECT_KEYS: Final[tuple[str, ...]] = (
    "subject_ref_hash",
    "subject_hash",
    "subject",
    "account_id",
    "acct_id",
    "id",
)

_NON_FEATURE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "features",
        "values",
        "metadata",
        "metadata_json",
        "validation",
        "issues",
        "counts",
        "caveats",
        "safety_flags",
        "subject_ref_hash",
        "subject_hash",
        "subject",
        "account_id",
        "acct_id",
        "id",
    }
)

_FORBIDDEN_FALLBACK_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_FALLBACK_TOKENS: Final[tuple[str, ...]] = (
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

_SIGNAL_DIRECT: Final[str] = "direct"
_SIGNAL_INVERSE_DIRECT: Final[str] = "inverse_direct"
_SIGNAL_FLAG: Final[str] = "flag"
_SIGNAL_LOG: Final[str] = "log"
_SIGNAL_RATIO: Final[str] = "ratio"
_SIGNAL_ABS_Z: Final[str] = "abs_z"
_SIGNAL_POSITIVE_DELTA: Final[str] = "positive_delta"
_SIGNAL_POSITIVE_LOG_DELTA: Final[str] = "positive_log_delta"
_SIGNAL_RECENCY: Final[str] = "recency"
_SIGNAL_NEW_ACCOUNT: Final[str] = "new_account"

_FALLBACK_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic heuristic fallback scoring only. Do not use with real customer data.",
    "Fallback scores are investigative prioritization signals, not probabilities of guilt.",
    "Fallback flags are operational review prompts only and are not proof of wrongdoing.",
    "Feature contributions are operational attributions only and are not causal proof.",
    "Fallback scoring must not trigger automatic adverse customer action.",
    "Labels must never be used as features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Unavailable fallback scores are reported honestly as unavailable rather than invented.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_FALLBACK_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_labels_as_features": True,
        "no_raw_values_in_public_summaries": True,
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
        "deterministic_fallback_scoring": True,
        "bounded_fallback_required": True,
        "scores_are_investigative_priority_only": True,
        "contributions_are_not_causal_proof": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class RiskBand(str, Enum):
    """
    Investigative risk band.

    Bands are prioritization labels only. They are not adjudications.
    """

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AggregationMethod(str, Enum):
    """
    Fallback evidence aggregation method.
    """

    WEIGHTED_MEAN = "weighted_mean"
    MAX = "max"
    MEDIAN = "median"


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

    if parsed < minimum:
        return minimum

    if parsed > maximum:
        return maximum

    return parsed


def _clamp_float(value: object, minimum: float, maximum: float, default: float) -> float:
    """
    Clamp a float-like value into bounds.
    """
    parsed = _as_float(value, default)

    if parsed < minimum:
        return minimum

    if parsed > maximum:
        return maximum

    return parsed


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


def _is_forbidden_key(key: Any) -> bool:
    """
    Return True when a key is forbidden for fallback inputs.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_FALLBACK_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_FALLBACK_TOKENS)


def _is_label_leakage_key(key: Any) -> bool:
    """
    Return True when a key looks like a label or supervision signal.
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


def _round6(value: float) -> float:
    """
    Round a float to six decimal places when finite.
    """
    if math.isnan(value) or math.isinf(value):
        return 0.0

    return round(float(value), 6)


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


def _coerce_optional_float(value: Any, *, allow_bool: bool = False) -> Optional[float]:
    """
    Coerce a feature value to finite float or None.
    """
    if value is None:
        return None

    if isinstance(value, bool):
        if not allow_bool:
            return None
        return 1.0 if value else 0.0

    if isinstance(value, int):
        return float(value)

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, Decimal):
        if not value.is_finite():
            return None

        try:
            result = float(value)
        except (OverflowError, ValueError):
            return None

        return result if math.isfinite(result) else None

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.timestamp() if normalized else None

    if isinstance(value, Enum):
        return _coerce_optional_float(value.value, allow_bool=allow_bool)

    if isinstance(value, str):
        text = value.strip().replace(",", "")

        if not text:
            return None

        lowered = text.lower()

        if allow_bool:
            if lowered in _TRUE_VALUES:
                return 1.0

            if lowered in _FALSE_VALUES:
                return 0.0

        try:
            result = float(text)
        except (TypeError, ValueError):
            return None

        return result if math.isfinite(result) else None

    return None


def _coerce_bool(value: Any) -> Optional[bool]:
    """
    Coerce a value to bool when unambiguous.
    """
    if isinstance(value, bool):
        return value

    if value is None:
        return None

    if isinstance(value, int):
        if value == 0:
            return False
        if value == 1:
            return True
        return None

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        if value == 0.0:
            return False
        if value == 1.0:
            return True
        return None

    if isinstance(value, Decimal):
        if not value.is_finite():
            return None
        if value == Decimal(0):
            return False
        if value == Decimal(1):
            return True
        return None

    if isinstance(value, Enum):
        return _coerce_bool(value.value)

    text = _normalize_unicode(value).strip().lower()

    if text in _TRUE_VALUES:
        return True

    if text in _FALSE_VALUES:
        return False

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


def _normalize_enum_option(
    enum_cls: type[Enum],
    value: Any,
    default: Any,
) -> Any:
    """
    Normalize an enum-like option with a safe fallback.
    """
    if value is None:
        return default

    if isinstance(value, enum_cls):
        return value

    token = _normalize_token(value)

    for member in enum_cls:
        if token == _normalize_token(member.value) or token == member.name.lower():
            return member

    return default


def _parse_weight_mapping(value: Any) -> dict[str, float]:
    """
    Parse feature weight settings into a clean mapping.
    """
    if value is None:
        return {}

    out: dict[str, float] = {}

    if isinstance(value, Mapping):
        for raw_key, raw_value in value.items():
            key = _normalize_token(raw_key)
            weight = _decimal_to_float(raw_value, 0.0)

            if key and weight > 0:
                out[key] = weight

        return out

    for part in _csv(value):
        if "=" not in part:
            continue

        raw_key, raw_value = part.split("=", 1)
        key = _normalize_token(raw_key)
        weight = _decimal_to_float(raw_value, 0.0)

        if key and weight > 0:
            out[key] = weight

    return out


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


def _ensure_salt(salt: Any) -> str:
    """
    Ensure the fallback salt is non-empty and sufficiently long.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _subject_hash(value: Any, options: "FallbackOptions") -> Optional[str]:
    """
    Return a salted, domain-separated pseudonymous subject hash.
    """
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.fallback.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _append_issue(
    issues: list["FallbackIssue"],
    max_issues: int,
    *,
    severity: IssueSeverity,
    code: str,
    message: str,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Append one bounded safe issue.
    """
    limit = max(1, int(max_issues))

    if len(issues) >= limit:
        if issues and issues[-1].code == "issue_list_truncated":
            return

        issues[-1] = FallbackIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        FallbackIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _risk_band(score: Optional[float], thresholds: Mapping[str, float]) -> RiskBand:
    """
    Map a bounded score to an investigative risk band.
    """
    if score is None:
        return RiskBand.UNKNOWN

    value = _clip_float(score, 0.0, 1.0, 0.0)
    critical = _clip_float(thresholds.get("critical", 0.90), 0.0, 1.0, 0.90)
    high = _clip_float(thresholds.get("high", 0.75), 0.0, 1.0, 0.75)
    medium = _clip_float(thresholds.get("medium", 0.55), 0.0, 1.0, 0.55)
    low = _clip_float(thresholds.get("low", 0.35), 0.0, 1.0, 0.35)

    if value >= critical:
        return RiskBand.CRITICAL

    if value >= high:
        return RiskBand.HIGH

    if value >= medium:
        return RiskBand.MEDIUM

    if value >= low:
        return RiskBand.LOW

    return RiskBand.LOW


# -----------------------------------------------------------------------------
# Signal specs
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SignalSpec:
    """
    One bounded fallback signal specification.
    """

    feature: str
    weight: float
    method: str
    params: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize signal spec values.
        """
        object.__setattr__(self, "feature", _canonical_field_name(self.feature))
        object.__setattr__(self, "method", _normalize_token(self.method) or _SIGNAL_DIRECT)
        object.__setattr__(
            self,
            "weight",
            _round6(_clip_float(self.weight, 0.0, _DEFAULT_MAX_WEIGHT, 0.0)),
        )
        object.__setattr__(self, "params", MappingProxyType(_safe_detail_value(self.params) or {}))


def _spec(name: str, weight: float, method: str, **params: Any) -> SignalSpec:
    """
    Build one signal spec.
    """
    return SignalSpec(feature=name, weight=weight, method=method, params=params)


def _default_signal_specs() -> tuple[SignalSpec, ...]:
    """
    Return the canonical bounded fallback signal specifications.

    These specs are transparent heuristic evidence rules only. They are not
    learned model weights and are not proof of wrongdoing.
    """
    specs = (
        # Profile
        _spec("account_age_days", 0.01, _SIGNAL_NEW_ACCOUNT, cap=30.0),
        _spec("is_dormant_flag", 0.01, _SIGNAL_FLAG),
        _spec("is_wallet_flag", 0.01, _SIGNAL_FLAG),

        # Balance
        _spec("balance_cv_30d", 0.03, _SIGNAL_RATIO, cap=5.0),
        _spec("balance_drop_ratio_7d", 0.05, _SIGNAL_DIRECT),

        # Transaction volume
        _spec("txn_count_1h", 0.03, _SIGNAL_LOG, cap=100.0),
        _spec("txn_count_24h", 0.04, _SIGNAL_LOG, cap=1_000.0),
        _spec("txn_count_7d", 0.03, _SIGNAL_LOG, cap=5_000.0),
        _spec("txn_count_30d", 0.02, _SIGNAL_LOG, cap=20_000.0),
        _spec("txn_amount_sum_24h", 0.03, _SIGNAL_LOG, cap=1e8),
        _spec("txn_amount_sum_7d", 0.02, _SIGNAL_LOG, cap=5e8),
        _spec("txn_amount_sum_30d", 0.01, _SIGNAL_LOG, cap=2e9),
        _spec("txn_amount_max_24h", 0.03, _SIGNAL_LOG, cap=1e8),
        _spec("txn_amount_max_30d", 0.02, _SIGNAL_LOG, cap=1e9),
        _spec("txn_amount_zscore_30d", 0.07, _SIGNAL_ABS_Z, cap=5.0),
        _spec("txn_amount_anomaly_score_30d", 0.06, _SIGNAL_DIRECT),

        # Velocity and temporal
        _spec("txn_count_velocity_ratio_7d_30d", 0.05, _SIGNAL_DIRECT),
        _spec("txn_count_burstiness_24h", 0.03, _SIGNAL_RATIO, cap=10.0),
        _spec("txn_night_ratio_30d", 0.02, _SIGNAL_DIRECT),
        _spec("txn_weekend_ratio_30d", 0.01, _SIGNAL_DIRECT),
        _spec("txn_hour_entropy_30d", 0.02, _SIGNAL_INVERSE_DIRECT),
        _spec("txn_day_entropy_30d", 0.01, _SIGNAL_INVERSE_DIRECT),
        _spec("txn_count_delta_7d_vs_prior_7d", 0.03, _SIGNAL_POSITIVE_DELTA, cap=1_000.0),
        _spec("txn_amount_delta_7d_vs_prior_7d", 0.02, _SIGNAL_POSITIVE_LOG_DELTA, cap=1e8),
        _spec("txn_count_pct_change_7d", 0.03, _SIGNAL_POSITIVE_DELTA, cap=1_000.0),

        # Counterparty
        _spec("counterparty_distinct_count_30d", 0.02, _SIGNAL_LOG, cap=1_000.0),
        _spec("counterparty_new_ratio_30d", 0.05, _SIGNAL_DIRECT),
        _spec("counterparty_repeat_ratio_30d", 0.01, _SIGNAL_DIRECT),
        _spec("counterparty_top1_share_30d", 0.04, _SIGNAL_DIRECT),
        _spec("counterparty_top5_share_30d", 0.02, _SIGNAL_DIRECT),
        _spec("counterparty_hhi_30d", 0.03, _SIGNAL_DIRECT),
        _spec("counterparty_entropy_30d", 0.02, _SIGNAL_INVERSE_DIRECT),
        _spec("outbound_amount_share_30d", 0.03, _SIGNAL_DIRECT),

        # Channel
        _spec("channel_upi_share_30d", 0.02, _SIGNAL_DIRECT),
        _spec("channel_wallet_share_30d", 0.01, _SIGNAL_DIRECT),
        _spec("channel_external_share_30d", 0.02, _SIGNAL_DIRECT),
        _spec("channel_entropy_30d", 0.01, _SIGNAL_INVERSE_DIRECT),
        _spec("channel_switch_count_7d", 0.03, _SIGNAL_LOG, cap=100.0),

        # Entity and link
        _spec("entity_link_count_30d", 0.02, _SIGNAL_LOG, cap=100.0),
        _spec("device_distinct_count_30d", 0.02, _SIGNAL_LOG, cap=20.0),
        _spec("ip_distinct_count_30d", 0.02, _SIGNAL_LOG, cap=50.0),
        _spec("phone_distinct_count_30d", 0.01, _SIGNAL_LOG, cap=20.0),
        _spec("email_distinct_count_30d", 0.01, _SIGNAL_LOG, cap=20.0),
        _spec("upi_distinct_count_30d", 0.02, _SIGNAL_LOG, cap=20.0),
        _spec("shared_device_account_count_30d", 0.04, _SIGNAL_LOG, cap=20.0),
        _spec("shared_ip_account_count_30d", 0.04, _SIGNAL_LOG, cap=50.0),
        _spec("shared_upi_account_count_30d", 0.04, _SIGNAL_LOG, cap=20.0),
        _spec("entity_link_heuristic_ratio_30d", 0.04, _SIGNAL_DIRECT),
        _spec("entity_link_unverified_ratio_30d", 0.04, _SIGNAL_DIRECT),
        _spec("entity_link_confidence_mean_30d", 0.02, _SIGNAL_INVERSE_DIRECT),

        # Complaint
        _spec("complaint_count_30d", 0.05, _SIGNAL_LOG, cap=20.0),
        _spec("complaint_rate_30d", 0.03, _SIGNAL_RATIO, cap=1.0),
        _spec("complaint_category_entropy_30d", 0.01, _SIGNAL_INVERSE_DIRECT),
        _spec("complaint_victim_count_30d", 0.05, _SIGNAL_LOG, cap=20.0),
        _spec("complaint_suspect_count_30d", 0.04, _SIGNAL_LOG, cap=20.0),
        _spec("complaint_recency_days", 0.05, _SIGNAL_RECENCY, cap=30.0),
        _spec("complaint_linked_txn_ratio_30d", 0.04, _SIGNAL_DIRECT),

        # Graph and network
        _spec("graph_degree_30d", 0.02, _SIGNAL_LOG, cap=200.0),
        _spec("graph_in_degree_30d", 0.02, _SIGNAL_LOG, cap=100.0),
        _spec("graph_out_degree_30d", 0.03, _SIGNAL_LOG, cap=100.0),
        _spec("graph_page_rank_norm_30d", 0.04, _SIGNAL_DIRECT),
        _spec("graph_betweenness_norm_30d", 0.04, _SIGNAL_DIRECT),
        _spec("graph_cycle_indicator_30d", 0.05, _SIGNAL_FLAG),
        _spec("graph_path_count_30d", 0.03, _SIGNAL_LOG, cap=10_000.0),
        _spec("graph_intermediary_score_30d", 0.04, _SIGNAL_DIRECT),
        _spec("graph_source_concentration_30d", 0.03, _SIGNAL_DIRECT),
        _spec("graph_beneficiary_concentration_30d", 0.03, _SIGNAL_DIRECT),
        _spec("graph_shared_entity_cluster_size_30d", 0.04, _SIGNAL_LOG, cap=100.0),
        _spec("graph_neighbor_complaint_ratio_30d", 0.05, _SIGNAL_DIRECT),

        # Composite anomaly
        _spec("velocity_anomaly_score_30d", 0.08, _SIGNAL_DIRECT),
        _spec("network_anomaly_score_30d", 0.08, _SIGNAL_DIRECT),
        _spec("composite_anomaly_score_30d", 0.12, _SIGNAL_DIRECT),
    )

    return tuple(sorted(specs, key=lambda item: item.feature))


_SIGNAL_SPECS: Final[tuple[SignalSpec, ...]] = _default_signal_specs()
_SIGNAL_INDEX: Final[Mapping[str, SignalSpec]] = MappingProxyType(
    {spec.feature: spec for spec in _SIGNAL_SPECS}
)


# -----------------------------------------------------------------------------
# Signal computation
# -----------------------------------------------------------------------------


def _param_float(spec: SignalSpec, name: str, default: float) -> float:
    """
    Read a bounded float parameter from a signal spec.
    """
    return _clamp_float(spec.params.get(name, default), 0.0, 1e18, default)


def _compute_signal(spec: SignalSpec, value: Any) -> Optional[float]:
    """
    Compute one bounded fallback signal in [0, 1].

    Returns None when the signal is unavailable.
    """
    method = spec.method

    if value is _MISSING:
        return None

    if method == _SIGNAL_RECENCY and value is None:
        return 0.0

    if value is None:
        return None

    if method == _SIGNAL_FLAG:
        parsed = _coerce_bool(value)

        if parsed is None:
            numeric = _coerce_optional_float(value, allow_bool=True)

            if numeric is None:
                return None

            parsed = numeric >= 0.5

        return 1.0 if parsed else 0.0

    if method in {_SIGNAL_DIRECT, _SIGNAL_INVERSE_DIRECT}:
        numeric = _coerce_optional_float(value, allow_bool=True)

        if numeric is None:
            return None

        clipped = _clip_float(numeric, 0.0, 1.0, 0.0)
        return _round6(1.0 - clipped if method == _SIGNAL_INVERSE_DIRECT else clipped)

    numeric = _coerce_optional_float(value, allow_bool=False)

    if numeric is None:
        return None

    if method == _SIGNAL_LOG:
        cap = _param_float(spec, "cap", 1_000.0)

        if cap <= 0:
            return 0.0

        x = max(0.0, numeric)

        if x <= 0:
            return 0.0

        return _round6(_clip_float(math.log1p(x) / math.log1p(cap), 0.0, 1.0, 0.0))

    if method == _SIGNAL_RATIO:
        cap = _param_float(spec, "cap", 1.0)

        if cap <= 0:
            return 0.0

        return _round6(_clip_float(max(0.0, numeric) / cap, 0.0, 1.0, 0.0))

    if method == _SIGNAL_ABS_Z:
        cap = _param_float(spec, "cap", 5.0)

        if cap <= 0:
            return 0.0

        return _round6(_clip_float(abs(numeric) / cap, 0.0, 1.0, 0.0))

    if method == _SIGNAL_POSITIVE_DELTA:
        cap = _param_float(spec, "cap", 1.0)

        if cap <= 0:
            return 0.0

        return _round6(_clip_float(max(0.0, numeric) / cap, 0.0, 1.0, 0.0))

    if method == _SIGNAL_POSITIVE_LOG_DELTA:
        cap = _param_float(spec, "cap", 1.0)

        if cap <= 0:
            return 0.0

        x = max(0.0, numeric)

        if x <= 0:
            return 0.0

        return _round6(_clip_float(math.log1p(x) / math.log1p(cap), 0.0, 1.0, 0.0))

    if method == _SIGNAL_RECENCY:
        cap = _param_float(spec, "cap", 30.0)

        if cap <= 0:
            return 0.0

        days = max(0.0, numeric)
        return _round6(_clip_float(1.0 - days / cap, 0.0, 1.0, 0.0))

    if method == _SIGNAL_NEW_ACCOUNT:
        cap = _param_float(spec, "cap", 30.0)

        if cap <= 0:
            return 0.0

        age = max(0.0, numeric)
        return _round6(_clip_float(1.0 - age / cap, 0.0, 1.0, 0.0))

    return None


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FallbackOptions:
    """
    Bounded heuristic fallback scoring policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    aggregation_method: AggregationMethod | str = AggregationMethod.WEIGHTED_MEAN
    threshold: float = _DEFAULT_THRESHOLD
    risk_thresholds: Mapping[str, float] = dataclass_field(
        default_factory=lambda: {
            "low": 0.35,
            "medium": 0.55,
            "high": 0.75,
            "critical": 0.90,
        }
    )

    feature_weights: Mapping[str, float] = dataclass_field(default_factory=dict)

    max_records: int = _DEFAULT_MAX_RECORDS
    max_features: int = _DEFAULT_MAX_FEATURES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_contributions: int = _DEFAULT_MAX_CONTRIBUTIONS

    include_contributions: bool = True
    drop_forbidden_fields: bool = False

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
            "aggregation_method",
            _normalize_enum_option(
                AggregationMethod,
                self.aggregation_method,
                AggregationMethod.WEIGHTED_MEAN,
            ),
        )
        object.__setattr__(
            self,
            "threshold",
            _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD),
        )

        thresholds = dict(self.risk_thresholds or {})
        low = _clamp_float(thresholds.get("low", 0.35), 0.0, 1.0, 0.35)
        medium = max(low, _clamp_float(thresholds.get("medium", 0.55), 0.0, 1.0, 0.55))
        high = max(medium, _clamp_float(thresholds.get("high", 0.75), 0.0, 1.0, 0.75))
        critical = max(high, _clamp_float(thresholds.get("critical", 0.90), 0.0, 1.0, 0.90))

        object.__setattr__(
            self,
            "risk_thresholds",
            MappingProxyType(
                {
                    "low": round(low, 6),
                    "medium": round(medium, 6),
                    "high": round(high, 6),
                    "critical": round(critical, 6),
                }
            ),
        )

        object.__setattr__(
            self,
            "feature_weights",
            MappingProxyType(_parse_weight_mapping(self.feature_weights)),
        )

        object.__setattr__(
            self,
            "max_records",
            _clamp_int(self.max_records, 1, _HARD_MAX_RECORDS, _DEFAULT_MAX_RECORDS),
        )
        object.__setattr__(
            self,
            "max_features",
            _clamp_int(self.max_features, 1, _HARD_MAX_FEATURES, _DEFAULT_MAX_FEATURES),
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
        object.__setattr__(
            self,
            "max_contributions",
            _clamp_int(
                self.max_contributions,
                1,
                _HARD_MAX_CONTRIBUTIONS,
                _DEFAULT_MAX_CONTRIBUTIONS,
            ),
        )

        object.__setattr__(self, "include_contributions", _as_bool(self.include_contributions, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "FallbackOptions":
        """
        Build fallback options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_FALLBACK_SALT", None)
            or _setting(settings, "ML_ANOMALY_SALT", None)
            or _setting(settings, "ML_SUPERVISED_SALT", None)
            or _setting(settings, "ML_PREPROCESS_SALT", None)
            or _setting(settings, "ML_SPLIT_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_FALLBACK_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_FALLBACK_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_FALLBACK_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_FALLBACK_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_FALLBACK_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            aggregation_method=str(
                _setting(settings, "ML_FALLBACK_AGGREGATION_METHOD", AggregationMethod.WEIGHTED_MEAN.value)
            ),
            threshold=_as_float(
                _setting(settings, "ML_FALLBACK_THRESHOLD", _DEFAULT_THRESHOLD),
                _DEFAULT_THRESHOLD,
            ),
            risk_thresholds={
                "low": _as_float(_setting(settings, "ML_FALLBACK_RISK_LOW", 0.35), 0.35),
                "medium": _as_float(_setting(settings, "ML_FALLBACK_RISK_MEDIUM", 0.55), 0.55),
                "high": _as_float(_setting(settings, "ML_FALLBACK_RISK_HIGH", 0.75), 0.75),
                "critical": _as_float(_setting(settings, "ML_FALLBACK_RISK_CRITICAL", 0.90), 0.90),
            },
            feature_weights=_parse_weight_mapping(_setting(settings, "ML_FALLBACK_FEATURE_WEIGHTS", None)),
            max_records=_as_int(
                _setting(settings, "ML_FALLBACK_MAX_RECORDS", _DEFAULT_MAX_RECORDS),
                _DEFAULT_MAX_RECORDS,
            ),
            max_features=_as_int(
                _setting(settings, "ML_FALLBACK_MAX_FEATURES", _DEFAULT_MAX_FEATURES),
                _DEFAULT_MAX_FEATURES,
            ),
            max_issues=_as_int(
                _setting(settings, "ML_FALLBACK_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "ML_FALLBACK_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_contributions=_as_int(
                _setting(settings, "ML_FALLBACK_MAX_CONTRIBUTIONS", _DEFAULT_MAX_CONTRIBUTIONS),
                _DEFAULT_MAX_CONTRIBUTIONS,
            ),
            include_contributions=_as_bool(
                _setting(settings, "ML_FALLBACK_INCLUDE_CONTRIBUTIONS", True),
                True,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ML_FALLBACK_DROP_FORBIDDEN_FIELDS", False),
                False,
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
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
            "aggregation_method": self.aggregation_method.value,
            "threshold": round(self.threshold, 6),
            "risk_thresholds": dict(self.risk_thresholds),
            "configured_feature_weight_count": len(self.feature_weights),
            "signal_spec_count": len(_SIGNAL_SPECS),
            "limits": {
                "max_records": self.max_records,
                "max_features": self.max_features,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_contributions": self.max_contributions,
            },
            "flags": {
                "include_contributions": self.include_contributions,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
        }


# -----------------------------------------------------------------------------
# Issue and result models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FallbackIssue:
    """
    Safe fallback issue.

    Issues never contain raw feature values, raw labels, raw narratives, raw
    identifiers, secrets, tokens, passwords, database URLs, filesystem paths, or
    model artifact paths.
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


@dataclass(frozen=True, slots=True)
class FallbackScoreRecord:
    """
    One fallback score record.

    Scores are investigative prioritization outputs only.
    """

    subject_ref_hash: Optional[str] = None
    score: Optional[float] = None
    risk_band: RiskBand | str = RiskBand.UNKNOWN
    review_recommended: bool = False
    signals_evaluated: int = 0
    signals_unavailable: int = 0
    contributions: tuple[dict[str, Any], ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize score record values.
        """
        object.__setattr__(
            self,
            "subject_ref_hash",
            _clean_text(self.subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower()
            if self.subject_ref_hash
            else None,
        )

        if self.score is not None:
            object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))

        object.__setattr__(
            self,
            "risk_band",
            _normalize_enum_option(RiskBand, self.risk_band, RiskBand.UNKNOWN),
        )
        object.__setattr__(self, "review_recommended", _as_bool(self.review_recommended, False))
        object.__setattr__(self, "signals_evaluated", max(0, _as_int(self.signals_evaluated, 0)))
        object.__setattr__(self, "signals_unavailable", max(0, _as_int(self.signals_unavailable, 0)))

        clean_contributions: list[dict[str, Any]] = []

        for item in self.contributions or ():
            if not isinstance(item, Mapping):
                continue

            clean_contributions.append(
                {
                    "feature": _clean_text(item.get("feature"), 200),
                    "weight": _round6(_coerce_optional_float(item.get("weight"), allow_bool=True) or 0.0),
                    "contribution": _round6(_coerce_optional_float(item.get("contribution"), allow_bool=True) or 0.0),
                    "magnitude": _round6(_coerce_optional_float(item.get("magnitude"), allow_bool=True) or 0.0),
                    "direction": _clean_text(item.get("direction"), 32) or "increase",
                    "method": _clean_text(item.get("method"), 100),
                    "interpretation": _clean_text(item.get("interpretation"), 300)
                    or "operational attribution only, not causal proof",
                }
            )

        object.__setattr__(self, "contributions", tuple(clean_contributions))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable score record mapping.
        """
        return {
            "subject_ref_hash": self.subject_ref_hash,
            "score": float(self.score) if self.score is not None else None,
            "risk_band": self.risk_band.value if isinstance(self.risk_band, RiskBand) else str(self.risk_band),
            "review_recommended": bool(self.review_recommended),
            "signals_evaluated": int(self.signals_evaluated),
            "signals_unavailable": int(self.signals_unavailable),
            "contributions": [dict(item) for item in self.contributions],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_FALLBACK_CAVEATS),
            "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
        }


@dataclass(slots=True)
class FallbackBatchResult:
    """
    Safe fallback batch result.
    """

    ok: bool = True
    records: tuple[FallbackScoreRecord, ...] = ()
    counts: dict[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[FallbackIssue, ...] = ()
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize batch result values.
        """
        object.__setattr__(self, "records", tuple(self.records or ()))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "counts", dict(self.counts or {}))
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})

        if not self.fingerprint:
            payload = {
                "version": FALLBACK_VERSION,
                "counts": self.counts,
                "records": [
                    {
                        "score": record.score,
                        "risk_band": (
                            record.risk_band.value
                            if isinstance(record.risk_band, RiskBand)
                            else str(record.risk_band)
                        ),
                        "review_recommended": bool(record.review_recommended),
                    }
                    for record in self.records
                ],
            }

            try:
                object.__setattr__(self, "fingerprint", _sha256_hex(_canonical_json(payload)))
            except Exception:
                object.__setattr__(self, "fingerprint", "")

    def __len__(self) -> int:
        """
        Return number of records.
        """
        return len(self.records)

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing batch summary.
        """
        return {
            "ok": self.ok,
            "counts": dict(self.counts),
            "records": [record.to_dict() for record in self.records],
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_FALLBACK_CAVEATS),
            "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Input extraction
# -----------------------------------------------------------------------------


def _iter_fallback_records(data: Any) -> list[Any]:
    """
    Convert flexible fallback input into a list of record-like objects.
    """
    if data is None:
        return []

    if isinstance(data, FallbackBatchResult):
        return list(data.records)

    if isinstance(data, Mapping):
        for key in ("records", "items", "rows", "examples", "vectors"):
            if key in data:
                return _as_sequence(data[key])

        return [data]

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray, memoryview)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _extract_raw_features(record: Any) -> Mapping[str, Any]:
    """
    Extract a raw feature mapping from a record-like object.
    """
    if isinstance(record, Mapping):
        return record

    candidate = getattr(record, "features", None)

    if isinstance(candidate, Mapping):
        return candidate

    candidate = getattr(record, "values", None)

    if isinstance(candidate, Mapping):
        return candidate

    out: dict[str, Any] = {}

    for name in _SIGNAL_INDEX:
        if hasattr(record, name):
            out[name] = getattr(record, name)

    return out


def _extract_subject(record: Any, options: FallbackOptions) -> Optional[str]:
    """
    Extract and pseudonymize a subject reference.
    """
    value: Any = None

    if isinstance(record, Mapping):
        for key in _SUBJECT_KEYS:
            if key in record:
                value = record[key]
                break
    else:
        for attr in _SUBJECT_KEYS:
            candidate = getattr(record, attr, None)

            if candidate is not None:
                value = candidate
                break

    return _subject_hash(value, options) if value is not None else None


def _extract_features(
    record: Any,
    options: FallbackOptions,
    issues: list[FallbackIssue],
    index: int,
) -> Optional[dict[str, Any]]:
    """
    Extract safe known features from one record.

    Returns None when the record must be rejected.
    """
    raw = _extract_raw_features(record)
    candidates: dict[str, Any] = {}

    for raw_key, raw_value in raw.items():
        key_text = _clean_text(raw_key, 200)
        canonical = _canonical_field_name(key_text)

        if not canonical:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="invalid_feature_name",
                message="Feature name could not be canonicalized and was omitted.",
                field=key_text or None,
                details={"index": index},
            )
            continue

        if canonical in _SUBJECT_KEYS or canonical in _NON_FEATURE_KEYS:
            continue

        if _is_forbidden_key(canonical) or _is_label_leakage_key(canonical):
            if options.drop_forbidden_fields:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="forbidden_feature_dropped",
                    message="Forbidden or label-like feature field omitted.",
                    field=key_text,
                    details={"index": index},
                )
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_feature",
                message="Forbidden or label-like feature field rejected.",
                field=key_text,
                details={"index": index},
            )
            return None

        if canonical not in _SIGNAL_INDEX:
            continue

        if canonical in candidates:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="duplicate_feature_alias",
                message="Duplicate feature alias omitted.",
                field=key_text,
                details={"index": index},
            )
            continue

        candidates[canonical] = raw_value

    if len(candidates) > options.max_features:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="feature_limit_applied",
            message="Known feature count exceeded configured limit and was truncated.",
            details={
                "submitted": len(candidates),
                "max_features": options.max_features,
            },
        )
        candidates = dict(sorted(candidates.items())[: options.max_features])

    return candidates


# -----------------------------------------------------------------------------
# Leakage guard helpers
# -----------------------------------------------------------------------------


def scan_features_for_label_leakage(features: Mapping[str, Any]) -> list[FallbackIssue]:
    """
    Scan a feature mapping for label-like leakage fields.
    """
    issues: list[FallbackIssue] = []

    if not isinstance(features, Mapping):
        issues.append(
            FallbackIssue(
                severity=IssueSeverity.ERROR,
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
                FallbackIssue(
                    severity=IssueSeverity.ERROR,
                    code="label_leakage_field",
                    message="Feature vector contains a label-like field.",
                    field=key,
                )
            )

    return issues


def assert_no_fallback_label_leakage(features: Mapping[str, Any]) -> None:
    """
    Raise a safe validation error when label leakage fields are detected.
    """
    issues = scan_features_for_label_leakage(features)
    errors = [issue for issue in issues if issue.severity == IssueSeverity.ERROR]

    if errors:
        raise MuleGuardValidationError(
            "Feature vector contains label-like leakage fields.",
            details={
                "issue_count": len(errors),
                "fields": [issue.field for issue in errors[:50] if issue.field],
            },
        )


# -----------------------------------------------------------------------------
# Scorer
# -----------------------------------------------------------------------------


class FallbackScorer:
    """
    Bounded deterministic heuristic fallback scorer.
    """

    def __init__(self, options: FallbackOptions | None = None) -> None:
        self.options = options or FallbackOptions.from_settings()
        self.specs = self._build_specs(self.options)
        self._lock = threading.RLock()

    @staticmethod
    def _build_specs(options: FallbackOptions) -> tuple[SignalSpec, ...]:
        """
        Apply configured weight overrides and remove disabled specs.
        """
        overrides = options.feature_weights or {}
        out: list[SignalSpec] = []

        for spec in _SIGNAL_SPECS:
            weight = overrides.get(spec.feature, spec.weight)
            weight = _clip_float(weight, 0.0, _DEFAULT_MAX_WEIGHT, spec.weight)

            if weight <= 0:
                continue

            out.append(replace(spec, weight=_round6(weight)))

        return tuple(sorted(out, key=lambda item: item.feature))

    def score_record(
        self,
        record: Any,
        *,
        index: int = 0,
        issues: Optional[list[FallbackIssue]] = None,
    ) -> FallbackScoreRecord:
        """
        Score one record.
        """
        opts = self.options
        local_issues = issues if issues is not None else []
        subject = _extract_subject(record, opts)
        features = _extract_features(record, opts, local_issues, index)

        if features is None:
            return FallbackScoreRecord(
                subject_ref_hash=subject,
                score=None,
                risk_band=RiskBand.UNKNOWN,
                review_recommended=False,
                signals_evaluated=0,
                signals_unavailable=len(self.specs),
                contributions=(),
                metadata={
                    "rejected": True,
                    "reason": "forbidden_or_invalid_feature_input",
                    "fallback_version": FALLBACK_VERSION,
                    "caveats": list(_FALLBACK_CAVEATS),
                    "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
                },
            )

        signals: list[tuple[float, float]] = []
        contributions: list[dict[str, Any]] = []
        unavailable = 0

        for spec in self.specs:
            value = features.get(spec.feature, _MISSING)
            signal = _compute_signal(spec, value)

            if signal is None:
                unavailable += 1
                continue

            signal = _round6(_clip_float(signal, 0.0, 1.0, 0.0))
            weighted = _round6(float(spec.weight) * signal)
            signals.append((signal, float(spec.weight)))
            contributions.append(
                {
                    "feature": spec.feature,
                    "weight": _round6(spec.weight),
                    "contribution": weighted,
                    "magnitude": 0.0,
                    "direction": "increase",
                    "method": spec.method,
                    "interpretation": "operational attribution only, not causal proof",
                }
            )

        evaluated = len(signals)

        if not signals:
            return FallbackScoreRecord(
                subject_ref_hash=subject,
                score=None,
                risk_band=RiskBand.UNKNOWN,
                review_recommended=False,
                signals_evaluated=0,
                signals_unavailable=unavailable,
                contributions=(),
                metadata={
                    "rejected": False,
                    "unavailable": True,
                    "reason": "no_available_signals",
                    "fallback_version": FALLBACK_VERSION,
                    "spec_count": len(self.specs),
                    "caveats": list(_FALLBACK_CAVEATS),
                    "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
                },
            )

        method = opts.aggregation_method

        if method == AggregationMethod.MAX:
            score = max(signal for signal, _weight in signals)
        elif method == AggregationMethod.MEDIAN:
            ordered = sorted(signal for signal, _weight in signals)
            mid = len(ordered) // 2

            if len(ordered) % 2 == 1:
                score = ordered[mid]
            else:
                score = (ordered[mid - 1] + ordered[mid]) / 2.0
        else:
            total_weight = sum(weight for _signal, weight in signals)
            total_weighted = sum(signal * weight for signal, weight in signals)
            score = total_weighted / total_weight if total_weight > 0 else 0.0

        score = _round6(_clip_float(score, 0.0, 1.0, 0.0))
        band = _risk_band(score, opts.risk_thresholds)
        review = score >= float(opts.threshold)

        total_contribution = sum(abs(float(item["contribution"])) for item in contributions)

        if total_contribution > 0:
            for item in contributions:
                item["magnitude"] = _round6(abs(float(item["contribution"])) / total_contribution)
        else:
            for item in contributions:
                item["magnitude"] = 0.0

        if opts.include_contributions:
            contributions.sort(key=lambda item: (-float(item["magnitude"]), str(item["feature"])))
            contributions = contributions[: opts.max_contributions]
        else:
            contributions = []

        return FallbackScoreRecord(
            subject_ref_hash=subject,
            score=score,
            risk_band=band,
            review_recommended=review,
            signals_evaluated=evaluated,
            signals_unavailable=unavailable,
            contributions=tuple(contributions),
            metadata={
                "rejected": False,
                "unavailable": False,
                "fallback_version": FALLBACK_VERSION,
                "spec_count": len(self.specs),
                "aggregation_method": method.value,
                "threshold": _round6(opts.threshold),
                "risk_thresholds": dict(opts.risk_thresholds),
                "caveats": list(_FALLBACK_CAVEATS),
                "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
            },
        )

    def score_batch(self, data: Any) -> FallbackBatchResult:
        """
        Score a bounded batch of records.
        """
        opts = self.options
        issues: list[FallbackIssue] = []
        records_raw = _iter_fallback_records(data)
        submitted = len(records_raw)

        if submitted > opts.max_records:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="batch_truncated",
                message="Fallback batch exceeded configured record limit and was truncated.",
                details={
                    "submitted": submitted,
                    "max_records": opts.max_records,
                },
            )
            records_raw = records_raw[: opts.max_records]

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="fallback_disabled",
                message="Heuristic fallback scoring is disabled.",
            )
            return FallbackBatchResult(
                ok=True,
                records=(),
                counts={
                    "submitted": submitted,
                    "processed": 0,
                    "scored": 0,
                    "unavailable": 0,
                    "rejected": 0,
                    "review_recommended": 0,
                },
                issues=tuple(issues),
                metadata={
                    "fallback_version": FALLBACK_VERSION,
                    "options": opts.safe_summary(),
                    "disabled": True,
                    "caveats": list(_FALLBACK_CAVEATS),
                    "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
                },
                fingerprint="",
            )

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Fallback scoring requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return FallbackBatchResult(
                ok=False,
                records=(),
                counts={
                    "submitted": submitted,
                    "processed": 0,
                    "scored": 0,
                    "unavailable": 0,
                    "rejected": 0,
                    "review_recommended": 0,
                },
                issues=tuple(issues),
                metadata={
                    "fallback_version": FALLBACK_VERSION,
                    "options": opts.safe_summary(),
                    "invalid": True,
                    "caveats": list(_FALLBACK_CAVEATS),
                    "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
                },
                fingerprint="",
            )

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Fallback scoring is blocked in production-like environments.",
            )
            return FallbackBatchResult(
                ok=False,
                records=(),
                counts={
                    "submitted": submitted,
                    "processed": 0,
                    "scored": 0,
                    "unavailable": 0,
                    "rejected": 0,
                    "review_recommended": 0,
                },
                issues=tuple(issues),
                metadata={
                    "fallback_version": FALLBACK_VERSION,
                    "options": opts.safe_summary(),
                    "invalid": True,
                    "caveats": list(_FALLBACK_CAVEATS),
                    "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
                },
                fingerprint="",
            )

        records: list[FallbackScoreRecord] = []

        with self._lock:
            for index, record in enumerate(records_raw):
                records.append(self.score_record(record, index=index, issues=issues))

        scored = sum(1 for record in records if record.score is not None)
        unavailable = sum(
            1
            for record in records
            if record.score is None and not bool(record.metadata.get("rejected"))
        )
        rejected = sum(1 for record in records if bool(record.metadata.get("rejected")))
        review_recommended = sum(1 for record in records if record.review_recommended)

        band_counter = Counter(
            record.risk_band.value if isinstance(record.risk_band, RiskBand) else str(record.risk_band)
            for record in records
        )

        counts = {
            "submitted": submitted,
            "processed": len(records),
            "scored": scored,
            "unavailable": unavailable,
            "rejected": rejected,
            "review_recommended": review_recommended,
            "band_unknown": int(band_counter.get(RiskBand.UNKNOWN.value, 0)),
            "band_low": int(band_counter.get(RiskBand.LOW.value, 0)),
            "band_medium": int(band_counter.get(RiskBand.MEDIUM.value, 0)),
            "band_high": int(band_counter.get(RiskBand.HIGH.value, 0)),
            "band_critical": int(band_counter.get(RiskBand.CRITICAL.value, 0)),
        }

        ok = not any(issue.severity == IssueSeverity.ERROR for issue in issues)

        metadata = {
            "fallback_version": FALLBACK_VERSION,
            "options": opts.safe_summary(),
            "signal_spec_count": len(self.specs),
            "counts": counts,
            "caveats": list(_FALLBACK_CAVEATS),
            "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
        }

        return FallbackBatchResult(
            ok=ok,
            records=tuple(records),
            counts=counts,
            issues=tuple(issues),
            metadata=metadata,
            fingerprint="",
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe scorer summary.
        """
        return {
            "options": self.options.safe_summary(),
            "spec_count": len(self.specs),
            "specs_sample": [
                {
                    "feature": spec.feature,
                    "weight": _round6(spec.weight),
                    "method": spec.method,
                }
                for spec in self.specs[: self.options.max_summary_items]
            ],
            "specs_truncated": len(self.specs) > self.options.max_summary_items,
            "caveats": list(_FALLBACK_CAVEATS),
            "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default scorer and public API
# -----------------------------------------------------------------------------


_default_scorer: Optional[FallbackScorer] = None
_default_scorer_lock = threading.Lock()


def get_fallback_scorer(
    options: FallbackOptions | None = None,
    *,
    rebuild: bool = False,
) -> FallbackScorer:
    """
    Return a process-wide fallback scorer.

    If options are supplied or rebuild is True, a new scorer is created and
    becomes the default.
    """
    global _default_scorer

    with _default_scorer_lock:
        if _default_scorer is None or rebuild or options is not None:
            _default_scorer = FallbackScorer(options=options)

        return _default_scorer


def score_fallback_record(
    record: Any,
    options: FallbackOptions | None = None,
    *,
    scorer: FallbackScorer | None = None,
) -> FallbackScoreRecord:
    """
    Score one fallback record.
    """
    active_scorer = scorer or get_fallback_scorer(options)
    return active_scorer.score_record(record)


def score_fallback_batch(
    data: Any,
    options: FallbackOptions | None = None,
    *,
    scorer: FallbackScorer | None = None,
) -> FallbackBatchResult:
    """
    Score a bounded fallback batch.
    """
    active_scorer = scorer or get_fallback_scorer(options)
    return active_scorer.score_batch(data)


def fallback_score(
    data: Any,
    options: FallbackOptions | None = None,
    *,
    scorer: FallbackScorer | None = None,
) -> FallbackBatchResult:
    """
    Convenience alias for `score_fallback_batch`.
    """
    return score_fallback_batch(data, options=options, scorer=scorer)


def fallback_score_one(
    record: Any,
    options: FallbackOptions | None = None,
    *,
    scorer: FallbackScorer | None = None,
) -> FallbackScoreRecord:
    """
    Convenience alias for `score_fallback_record`.
    """
    return score_fallback_record(record, options=options, scorer=scorer)


def get_fallback_metadata() -> dict[str, Any]:
    """
    Return safe, serializable fallback ML metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, raw feature values, subject-label
    pairs, or real customer data.
    """
    options = FallbackOptions.from_settings()
    scorer = get_fallback_scorer()

    return {
        "package": "muleguard.backend.ml.fallback",
        "version": FALLBACK_VERSION,
        "risk_bands": [band.value for band in RiskBand],
        "aggregation_methods": [method.value for method in AggregationMethod],
        "signal_methods": sorted(
            {
                _SIGNAL_DIRECT,
                _SIGNAL_INVERSE_DIRECT,
                _SIGNAL_FLAG,
                _SIGNAL_LOG,
                _SIGNAL_RATIO,
                _SIGNAL_ABS_Z,
                _SIGNAL_POSITIVE_DELTA,
                _SIGNAL_POSITIVE_LOG_DELTA,
                _SIGNAL_RECENCY,
                _SIGNAL_NEW_ACCOUNT,
            }
        ),
        "default_options": options.safe_summary(),
        "scorer": scorer.safe_summary(),
        "builder_backend": "in_memory_deterministic",
        "distributed": False,
        "durable": False,
        "hard_limits": {
            "max_records": _HARD_MAX_RECORDS,
            "max_features": _HARD_MAX_FEATURES,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_contributions": _HARD_MAX_CONTRIBUTIONS,
        },
        "forbidden_fallback_field_count": len(_FORBIDDEN_FALLBACK_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_FALLBACK_CAVEATS),
        "safety_flags": dict(_FALLBACK_SAFETY_FLAGS),
    }


__all__ = [
    "AggregationMethod",
    "FallbackBatchResult",
    "FallbackIssue",
    "FallbackOptions",
    "FallbackScoreRecord",
    "FallbackScorer",
    "IssueSeverity",
    "RiskBand",
    "SignalSpec",
    "assert_no_fallback_label_leakage",
    "fallback_score",
    "fallback_score_one",
    "get_fallback_metadata",
    "get_fallback_scorer",
    "scan_features_for_label_leakage",
    "score_fallback_batch",
    "score_fallback_record",
]