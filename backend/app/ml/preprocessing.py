"""
MULEGUARD backend ML preprocessing.

This module provides the canonical preprocessing layer for the synthetic
MULEGUARD machine-learning subsystem.

Primary responsibilities:

- transform bounded synthetic feature vectors into model-ready numeric matrices
  for training, evaluation, and inference;
- enforce deterministic fit/transform separation so preprocessing parameters are
  learned only from approved training data and never leak target information;
- support numeric, boolean, categorical, set, vector, datetime, and composite
  feature roles;
- provide bounded missing-value handling, outlier handling, scaling, encoding,
  feature hashing, feature selection, and safe pipeline fingerprinting;
- reject or omit leakage-prone fields such as ground-truth labels, injected
  scenario IDs, fraud-ring IDs, raw complaint narratives, raw identifiers,
  secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths;
- preserve privacy by storing only salted one-way category/set element hashes
  in fitted state and by excluding feature values from public summaries;
- remain import-safe, dependency-light, and usable by ML services, training
  harnesses, evaluation harnesses, tests, seeders, offline fixtures, and
  developer tooling.

This module preprocesses features only. It does not train models, score
accounts, evaluate models, persist data, call external systems, authenticate
users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for preprocessing.
- Labels must never be used as features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden feature inputs. Subject linkage is pseudonymous
  and excluded from feature matrices.
- Fitted categorical and set-element state stores salted one-way hashes only.
- Public preprocessing summaries never include feature values, subject-label
  pairs, raw identifiers, raw narratives, secrets, tokens, passwords, database
  URLs, filesystem paths, or model artifact paths.
- Risk and anomaly features remain investigative prioritization signals only.
  They are not probabilities of guilt.
- Preprocessing outputs are operational ML artefacts only. They are not
  investigative conclusions and are not proof of wrongdoing.
- Preprocessing never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable capabilities are reported honestly rather than
  invented.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call model runtimes.
- This module does not train, promote, retire, upload, replace, or execute
  models.
- This module does not generate synthetic data.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable preprocessing state store. Production deployments
  should persist fitted state only through reviewed, access-controlled, audited
  experiment-tracking or model-registry systems.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, and case dispositions are investigative leads or human workflow
artefacts only. They are not proof of wrongdoing and must not trigger automatic
adverse customer action.
"""

from __future__ import annotations

import bisect
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

logger = logging.getLogger("muleguard.backend.ml.preprocessing")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

PREPROCESSING_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.preprocessing.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_SAMPLES: Final[int] = 10_000
_HARD_MAX_SAMPLES: Final[int] = 100_000

_DEFAULT_MAX_FEATURES: Final[int] = 512
_HARD_MAX_FEATURES: Final[int] = 4_096

_DEFAULT_MAX_CATEGORIES: Final[int] = 1_000
_HARD_MAX_CATEGORIES: Final[int] = 10_000

_DEFAULT_MAX_SET_ITEMS: Final[int] = 100
_HARD_MAX_SET_ITEMS: Final[int] = 1_000

_DEFAULT_MAX_VECTOR_DIM: Final[int] = 128
_HARD_MAX_VECTOR_DIM: Final[int] = 4_096

_DEFAULT_HASH_DIM: Final[int] = 16
_HARD_MAX_HASH_DIM: Final[int] = 256

_DEFAULT_MAX_RANK_SAMPLES: Final[int] = 10_000
_HARD_MAX_RANK_SAMPLES: Final[int] = 100_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_WEIGHT: Final[float] = 100.0
_DEFAULT_CLIP_STD_DEVS: Final[float] = 5.0

_DEFAULT_WINSOR_LOWER: Final[float] = 0.01
_DEFAULT_WINSOR_UPPER: Final[float] = 0.99

_DEFAULT_VARIANCE_THRESHOLD: Final[float] = 0.0
_DEFAULT_COVERAGE_THRESHOLD: Final[float] = 0.0

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

_FORBIDDEN_PREPROCESS_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_PREPROCESS_TOKENS: Final[tuple[str, ...]] = (
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

_PREPROCESSING_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML preprocessing only. Do not use with real customer data.",
    "Preprocessed matrices are operational ML artefacts only and are not proof of wrongdoing.",
    "Preprocessing must not trigger automatic adverse customer action.",
    "Labels must never be used as features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Fitted categorical and set-element state stores salted one-way hashes only.",
    "Public preprocessing summaries never include feature values or subject-label pairs.",
    "Risk and anomaly features remain investigative prioritization signals only.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_PREPROCESSING_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "salted_one_way_category_hashes": True,
        "salted_one_way_set_element_hashes": True,
        "deterministic_fit_transform": True,
        "bounded_preprocessing_required": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class PreprocessingStage(str, Enum):
    """
    Preprocessing invocation stage.
    """

    FIT = "fit"
    TRANSFORM = "transform"
    FIT_TRANSFORM = "fit_transform"


class MissingPolicy(str, Enum):
    """
    Missing-value policy.
    """

    ERROR = "error"
    DROP_ROW = "drop_row"
    DROP_COLUMN = "drop_column"
    ZERO = "zero"
    NONE = "none"
    MEDIAN = "median"
    MODE = "mode"
    CONSTANT = "constant"


class OutlierPolicy(str, Enum):
    """
    Outlier-handling policy.
    """

    KEEP = "keep"
    CLIP = "clip"
    WINSORIZE = "winsorize"


class ScalingMethod(str, Enum):
    """
    Numeric scaling method.
    """

    NONE = "none"
    LOG1P = "log1p"
    SQRT = "sqrt"
    STANDARD = "standard"
    ROBUST_STANDARD = "robust_standard"
    MINMAX = "minmax"
    MAXABS = "maxabs"
    RANK = "rank"


class EncodingMethod(str, Enum):
    """
    Categorical encoding method.
    """

    NONE = "none"
    ORDINAL = "ordinal"
    ONE_HOT = "one_hot"
    HASH = "hash"
    FREQUENCY = "frequency"
    BINARY = "binary"


class SetEncodingMethod(str, Enum):
    """
    Set-feature encoding method.
    """

    NONE = "none"
    CARDINALITY = "cardinality"
    ONE_HOT = "one_hot"
    HASH = "hash"
    FREQUENCY = "frequency"
    SUMMARY = "summary"


class VectorScalingMethod(str, Enum):
    """
    Vector-feature scaling method.
    """

    NONE = "none"
    STANDARD = "standard"
    MINMAX = "minmax"
    L2 = "l2"


class DatetimeFeatureMode(str, Enum):
    """
    Datetime feature conversion mode.
    """

    NONE = "none"
    EPOCH = "epoch"
    CYCLICAL = "cyclical"
    BOTH = "both"


class FeatureRole(str, Enum):
    """
    Feature role.
    """

    AUTO = "auto"
    NUMERIC = "numeric"
    BOOLEAN = "boolean"
    CATEGORICAL = "categorical"
    SET = "set"
    VECTOR = "vector"
    DATETIME = "datetime"
    COMPOSITE = "composite"


class FeatureSelectionMethod(str, Enum):
    """
    Unsupervised feature-selection method.

    Supervised selection is intentionally not supported because it can leak
    target information into preprocessing.
    """

    NONE = "none"
    VARIANCE = "variance"
    COVERAGE = "coverage"
    COMBINED = "combined"


class UnknownFieldPolicy(str, Enum):
    """
    Policy for feature names not present in fitted state.
    """

    DROP = "drop"
    WARN = "warn"
    ERROR = "error"


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


def _is_forbidden_key(key: Any) -> bool:
    """
    Return True when a key is forbidden for preprocessing.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_PREPROCESS_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_PREPROCESS_TOKENS)


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


def _to_decimal(value: Any) -> Optional[Decimal]:
    """
    Convert a value to finite Decimal when possible.
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


def _coerce_float(value: Any, *, allow_bool: bool = False) -> Optional[float]:
    """
    Coerce a value to finite float.
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
        return _coerce_float(value.value, allow_bool=allow_bool)

    text = _normalize_unicode(value).strip().replace(",", "")

    if not text:
        return None

    try:
        result = float(text)
    except (TypeError, ValueError):
        return None

    return result if math.isfinite(result) else None


def _coerce_bool(value: Any) -> Optional[bool]:
    """
    Coerce a value to bool.
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

    text = _normalize_unicode(value).strip().lower()

    if text in _TRUE_VALUES:
        return True

    if text in _FALSE_VALUES:
        return False

    return None


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


def _mean(values: Sequence[float]) -> float:
    """
    Return arithmetic mean.
    """
    if not values:
        return 0.0

    return sum(values) / float(len(values))


def _variance(values: Sequence[float], mean_value: Optional[float] = None) -> float:
    """
    Return population variance.
    """
    if len(values) < 2:
        return 0.0

    mu = _mean(values) if mean_value is None else float(mean_value)
    total = sum((float(value) - mu) ** 2 for value in values)
    result = total / float(len(values))

    return result if math.isfinite(result) and result > 0 else 0.0


def _stddev(values: Sequence[float], mean_value: Optional[float] = None) -> float:
    """
    Return population standard deviation.
    """
    var = _variance(values, mean_value)

    if var <= 0:
        return 0.0

    result = math.sqrt(var)
    return result if math.isfinite(result) else 0.0


def _quantile(sorted_values: Sequence[float], q: float) -> float:
    """
    Return linear-interpolated quantile from sorted values.
    """
    if not sorted_values:
        return 0.0

    q = _clamp_float(q, 0.0, 1.0, 0.0)
    idx = (len(sorted_values) - 1) * q
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))

    if lo == hi:
        return float(sorted_values[lo])

    return float(sorted_values[lo]) * (hi - idx) + float(sorted_values[hi]) * (idx - lo)


def _mad(sorted_values: Sequence[float], median_value: float) -> float:
    """
    Return median absolute deviation.
    """
    if not sorted_values:
        return 0.0

    deviations = sorted(abs(float(value) - median_value) for value in sorted_values)
    return _quantile(deviations, 0.5)


def _rank_percentile(sorted_values: Sequence[float], value: float) -> float:
    """
    Return empirical CDF percentile for value.
    """
    if not sorted_values:
        return 0.0

    position = bisect.bisect_right(list(sorted_values), float(value))
    result = float(position) / float(len(sorted_values))

    return _clip_float(result, 0.0, 1.0, 0.0)


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


def _signed_log1p(value: float) -> float:
    """
    Return signed log1p transform.
    """
    if value >= 0:
        return math.log1p(value)

    return -math.log1p(abs(value))


def _signed_sqrt(value: float) -> float:
    """
    Return signed square-root transform.
    """
    if value >= 0:
        return math.sqrt(value)

    return -math.sqrt(abs(value))


def _l2_norm(values: Sequence[float]) -> float:
    """
    Return L2 norm.
    """
    total = sum(float(value) * float(value) for value in values)

    if total <= 0 or not math.isfinite(total):
        return 0.0

    result = math.sqrt(total)
    return result if math.isfinite(result) else 0.0


def _cyclical(value: float, period: float) -> tuple[float, float]:
    """
    Return sine/cosine cyclical encoding.
    """
    if period <= 0 or not math.isfinite(period):
        return 0.0, 0.0

    angle = 2.0 * math.pi * (float(value) / float(period))
    sin_value = math.sin(angle)
    cos_value = math.cos(angle)

    return (
        _clip_float(sin_value, -1.0, 1.0, 0.0),
        _clip_float(cos_value, -1.0, 1.0, 0.0),
    )


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
    Ensure the preprocessing salt is non-empty and sufficiently long.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _hash_token(token: str, options: "PreprocessOptions", domain: str) -> str:
    """
    Return a salted, domain-separated one-way hash for a transient token.
    """
    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    full_domain = f"muleguard.ml.preprocessing.{domain}.{safe_namespace}"
    return _hmac_hex(options.salt, full_domain, token)


def _feature_hash_vector(
    token: str,
    options: "PreprocessOptions",
    domain: str,
    dim: int,
) -> tuple[float, ...]:
    """
    Return a deterministic feature-hashing vector in [-1, 1].
    """
    if dim <= 0:
        return ()

    out: list[float] = []
    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE

    for index in range(int(dim)):
        full_domain = f"muleguard.ml.preprocessing.{domain}.{safe_namespace}.{index}"
        digest = _hmac_hex(options.salt, full_domain, token)
        numeric = int(digest[:16], 16)
        value = (float(numeric) / float(1 << 64)) * 2.0 - 1.0
        out.append(_round6(_clip_float(value, -1.0, 1.0, 0.0)))

    return tuple(out)


def _categorical_token(value: Any) -> str:
    """
    Convert a value into a transient canonical categorical token.

    The token is never stored raw in fitted state.
    """
    if value is None:
        return ""

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else ""

    if isinstance(value, Decimal):
        return str(value) if value.is_finite() else ""

    if isinstance(value, Enum):
        return _categorical_token(value.value)

    return _clean_text(value, _MAX_TEXT_LENGTH).lower()


def _coerce_set_tokens(value: Any, max_items: int) -> Optional[list[str]]:
    """
    Coerce a value into transient set tokens.

    Returns None when the value is missing. Returns an empty list when the set
    is present but empty.
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return [_categorical_token(value)]

    if isinstance(value, (str, bytes, bytearray, memoryview)):
        token = _categorical_token(value)
        return [token] if token else []

    if isinstance(value, Mapping):
        items: Sequence[Any] = list(value.keys())
    elif isinstance(value, Sequence):
        items = list(value)
    elif isinstance(value, (set, frozenset)):
        items = list(value)
    else:
        items = [value]

    limit = max(1, int(max_items))
    out: list[str] = []
    seen: set[str] = set()

    for item in items[: limit + 1]:
        token = _categorical_token(item)

        if not token or token in seen:
            continue

        seen.add(token)
        out.append(token)

    return out[:limit]


def _coerce_vector(value: Any, max_items: int) -> Optional[tuple[float, ...]]:
    """
    Coerce a value into a bounded numeric vector.
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return None

    if isinstance(value, Mapping):
        items: Sequence[Any] = list(value.values())
    elif isinstance(value, Sequence):
        items = list(value)
    elif isinstance(value, (set, frozenset)):
        items = list(value)
    else:
        return None

    limit = max(1, int(max_items))
    out: list[float] = []

    for item in items[:limit]:
        numeric = _coerce_float(item)

        if numeric is None:
            return None

        out.append(numeric)

    return tuple(out)


def _enum_from_value(
    enum_cls: type[Enum],
    value: Any,
    *,
    field_name: str,
    default: Any = None,
) -> Enum:
    """
    Convert a value to an enum member or raise ConfigurationError.
    """
    if value is None:
        if default is not None:
            return default if isinstance(default, enum_cls) else enum_cls(default)  # type: ignore[call-arg]
        raise ConfigurationError(
            f"Invalid {field_name}.",
            details={
                "field": field_name,
                "allowed_values": [str(member.value) for member in enum_cls],
            },
        )

    if isinstance(value, enum_cls):
        return value

    token = _normalize_token(value)

    for member in enum_cls:
        if token == _normalize_token(member.value) or token == member.name.lower():
            return member

    if default is not None:
        return default if isinstance(default, enum_cls) else enum_cls(default)  # type: ignore[call-arg]

    raise ConfigurationError(
        f"Invalid {field_name}.",
        details={
            "field": field_name,
            "allowed_values": [str(member.value) for member in enum_cls],
        },
    )


def _optional_enum_from_value(
    enum_cls: type[Enum],
    value: Any,
    *,
    field_name: str,
) -> Optional[Enum]:
    """
    Convert an optional value to an enum member.

    Returns None when value is None.
    """
    if value is None:
        return None

    return _enum_from_value(enum_cls, value, field_name=field_name)


def _normalize_enum_option(value: Any, enum_cls: type[Enum], default: Enum) -> Enum:
    """
    Normalize an option enum value with a default.
    """
    if value is None:
        return default

    return _enum_from_value(enum_cls, value, field_name=enum_cls.__name__)


def _first(*values: Any) -> Any:
    """
    Return first non-None value.
    """
    for value in values:
        if value is not None:
            return value

    return None


def _append_issue(
    issues: list["PreprocessingIssue"],
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

        issues[-1] = PreprocessingIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        PreprocessingIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


# -----------------------------------------------------------------------------
# Config and options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeatureTransformConfig:
    """
    Per-feature preprocessing configuration.

    All fields are optional. Unset values inherit from default config or global
    preprocessing options.
    """

    role: FeatureRole | str | None = None
    missing_policy: MissingPolicy | str | None = None
    outlier_policy: OutlierPolicy | str | None = None
    scaling_method: ScalingMethod | str | None = None
    encoding_method: EncodingMethod | str | None = None
    set_encoding_method: SetEncodingMethod | str | None = None
    vector_scaling_method: VectorScalingMethod | str | None = None
    datetime_mode: DatetimeFeatureMode | str | None = None

    log1p: bool | None = None
    clip_min: float | None = None
    clip_max: float | None = None
    constant_fill: float | None = None

    max_categories: int | None = None
    hash_dim: int | None = None

    selected: bool | None = None
    weight: float = 1.0

    def __post_init__(self) -> None:
        """
        Normalize optional config values.
        """
        object.__setattr__(
            self,
            "role",
            _optional_enum_from_value(FeatureRole, self.role, field_name="role"),
        )
        object.__setattr__(
            self,
            "missing_policy",
            _optional_enum_from_value(
                MissingPolicy,
                self.missing_policy,
                field_name="missing_policy",
            ),
        )
        object.__setattr__(
            self,
            "outlier_policy",
            _optional_enum_from_value(
                OutlierPolicy,
                self.outlier_policy,
                field_name="outlier_policy",
            ),
        )
        object.__setattr__(
            self,
            "scaling_method",
            _optional_enum_from_value(
                ScalingMethod,
                self.scaling_method,
                field_name="scaling_method",
            ),
        )
        object.__setattr__(
            self,
            "encoding_method",
            _optional_enum_from_value(
                EncodingMethod,
                self.encoding_method,
                field_name="encoding_method",
            ),
        )
        object.__setattr__(
            self,
            "set_encoding_method",
            _optional_enum_from_value(
                SetEncodingMethod,
                self.set_encoding_method,
                field_name="set_encoding_method",
            ),
        )
        object.__setattr__(
            self,
            "vector_scaling_method",
            _optional_enum_from_value(
                VectorScalingMethod,
                self.vector_scaling_method,
                field_name="vector_scaling_method",
            ),
        )
        object.__setattr__(
            self,
            "datetime_mode",
            _optional_enum_from_value(
                DatetimeFeatureMode,
                self.datetime_mode,
                field_name="datetime_mode",
            ),
        )

        if self.log1p is not None:
            object.__setattr__(self, "log1p", _as_bool(self.log1p, False))

        if self.clip_min is not None:
            object.__setattr__(
                self,
                "clip_min",
                _as_float(self.clip_min, math.nan)
                if math.isfinite(_as_float(self.clip_min, math.nan))
                else None,
            )

        if self.clip_max is not None:
            object.__setattr__(
                self,
                "clip_max",
                _as_float(self.clip_max, math.nan)
                if math.isfinite(_as_float(self.clip_max, math.nan))
                else None,
            )

        if self.constant_fill is not None:
            object.__setattr__(
                self,
                "constant_fill",
                _as_float(self.constant_fill, 0.0),
            )

        if self.max_categories is not None:
            object.__setattr__(
                self,
                "max_categories",
                _clamp_int(self.max_categories, 1, _HARD_MAX_CATEGORIES, _DEFAULT_MAX_CATEGORIES),
            )

        if self.hash_dim is not None:
            object.__setattr__(
                self,
                "hash_dim",
                _clamp_int(self.hash_dim, 1, _HARD_MAX_HASH_DIM, _DEFAULT_HASH_DIM),
            )

        object.__setattr__(
            self,
            "weight",
            _round6(_clamp_float(self.weight, 0.0, _DEFAULT_MAX_WEIGHT, 1.0)),
        )


@dataclass(frozen=True, slots=True)
class PreprocessOptions:
    """
    Bounded ML preprocessing policy.

    Hard caps prevent accidental unbounded preprocessing surfaces.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    max_samples: int = _DEFAULT_MAX_SAMPLES
    max_features: int = _DEFAULT_MAX_FEATURES
    max_categories: int = _DEFAULT_MAX_CATEGORIES
    max_set_items: int = _DEFAULT_MAX_SET_ITEMS
    max_vector_dim: int = _DEFAULT_MAX_VECTOR_DIM
    hash_dim: int = _DEFAULT_HASH_DIM
    max_rank_samples: int = _DEFAULT_MAX_RANK_SAMPLES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS

    missing_policy: MissingPolicy | str = MissingPolicy.ZERO
    outlier_policy: OutlierPolicy | str = OutlierPolicy.CLIP
    scaling_method: ScalingMethod | str = ScalingMethod.STANDARD
    encoding_method: EncodingMethod | str = EncodingMethod.ORDINAL
    set_encoding_method: SetEncodingMethod | str = SetEncodingMethod.HASH
    vector_scaling_method: VectorScalingMethod | str = VectorScalingMethod.NONE
    datetime_mode: DatetimeFeatureMode | str = DatetimeFeatureMode.BOTH

    feature_selection_method: FeatureSelectionMethod | str = FeatureSelectionMethod.NONE
    variance_threshold: float = _DEFAULT_VARIANCE_THRESHOLD
    coverage_threshold: float = _DEFAULT_COVERAGE_THRESHOLD
    max_selected_features: int = 0

    one_hot_max_categories: int = 50
    add_missing_indicators: bool = False
    preserve_original_feature_names: bool = True

    winsor_lower_quantile: float = _DEFAULT_WINSOR_LOWER
    winsor_upper_quantile: float = _DEFAULT_WINSOR_UPPER
    clip_standard_devs: float = _DEFAULT_CLIP_STD_DEVS

    unknown_field_policy: UnknownFieldPolicy | str = UnknownFieldPolicy.DROP
    drop_forbidden_fields: bool = False
    allow_label_leakage_scan: bool = True

    default_config: FeatureTransformConfig = dataclass_field(default_factory=FeatureTransformConfig)
    feature_configs: Mapping[str, FeatureTransformConfig | Mapping[str, Any]] = dataclass_field(
        default_factory=dict
    )

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
            "max_samples",
            _clamp_int(self.max_samples, 1, _HARD_MAX_SAMPLES, _DEFAULT_MAX_SAMPLES),
        )
        object.__setattr__(
            self,
            "max_features",
            _clamp_int(self.max_features, 1, _HARD_MAX_FEATURES, _DEFAULT_MAX_FEATURES),
        )
        object.__setattr__(
            self,
            "max_categories",
            _clamp_int(self.max_categories, 1, _HARD_MAX_CATEGORIES, _DEFAULT_MAX_CATEGORIES),
        )
        object.__setattr__(
            self,
            "max_set_items",
            _clamp_int(self.max_set_items, 1, _HARD_MAX_SET_ITEMS, _DEFAULT_MAX_SET_ITEMS),
        )
        object.__setattr__(
            self,
            "max_vector_dim",
            _clamp_int(self.max_vector_dim, 1, _HARD_MAX_VECTOR_DIM, _DEFAULT_MAX_VECTOR_DIM),
        )
        object.__setattr__(
            self,
            "hash_dim",
            _clamp_int(self.hash_dim, 1, _HARD_MAX_HASH_DIM, _DEFAULT_HASH_DIM),
        )
        object.__setattr__(
            self,
            "max_rank_samples",
            _clamp_int(
                self.max_rank_samples,
                10,
                _HARD_MAX_RANK_SAMPLES,
                _DEFAULT_MAX_RANK_SAMPLES,
            ),
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
            "missing_policy",
            _normalize_enum_option(self.missing_policy, MissingPolicy, MissingPolicy.ZERO),
        )
        object.__setattr__(
            self,
            "outlier_policy",
            _normalize_enum_option(self.outlier_policy, OutlierPolicy, OutlierPolicy.CLIP),
        )
        object.__setattr__(
            self,
            "scaling_method",
            _normalize_enum_option(self.scaling_method, ScalingMethod, ScalingMethod.STANDARD),
        )
        object.__setattr__(
            self,
            "encoding_method",
            _normalize_enum_option(self.encoding_method, EncodingMethod, EncodingMethod.ORDINAL),
        )
        object.__setattr__(
            self,
            "set_encoding_method",
            _normalize_enum_option(
                self.set_encoding_method,
                SetEncodingMethod,
                SetEncodingMethod.HASH,
            ),
        )
        object.__setattr__(
            self,
            "vector_scaling_method",
            _normalize_enum_option(
                self.vector_scaling_method,
                VectorScalingMethod,
                VectorScalingMethod.NONE,
            ),
        )
        object.__setattr__(
            self,
            "datetime_mode",
            _normalize_enum_option(
                self.datetime_mode,
                DatetimeFeatureMode,
                DatetimeFeatureMode.BOTH,
            ),
        )
        object.__setattr__(
            self,
            "feature_selection_method",
            _normalize_enum_option(
                self.feature_selection_method,
                FeatureSelectionMethod,
                FeatureSelectionMethod.NONE,
            ),
        )
        object.__setattr__(
            self,
            "unknown_field_policy",
            _normalize_enum_option(
                self.unknown_field_policy,
                UnknownFieldPolicy,
                UnknownFieldPolicy.DROP,
            ),
        )

        object.__setattr__(
            self,
            "variance_threshold",
            _clamp_float(self.variance_threshold, 0.0, 1.0, _DEFAULT_VARIANCE_THRESHOLD),
        )
        object.__setattr__(
            self,
            "coverage_threshold",
            _clamp_float(self.coverage_threshold, 0.0, 1.0, _DEFAULT_COVERAGE_THRESHOLD),
        )
        object.__setattr__(
            self,
            "max_selected_features",
            max(0, _as_int(self.max_selected_features, 0)),
        )
        object.__setattr__(
            self,
            "one_hot_max_categories",
            _clamp_int(self.one_hot_max_categories, 1, _HARD_MAX_CATEGORIES, 50),
        )

        object.__setattr__(self, "add_missing_indicators", _as_bool(self.add_missing_indicators, False))
        object.__setattr__(
            self,
            "preserve_original_feature_names",
            _as_bool(self.preserve_original_feature_names, True),
        )
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))
        object.__setattr__(self, "allow_label_leakage_scan", _as_bool(self.allow_label_leakage_scan, True))

        object.__setattr__(
            self,
            "winsor_lower_quantile",
            _clamp_float(self.winsor_lower_quantile, 0.0, 0.49, _DEFAULT_WINSOR_LOWER),
        )
        object.__setattr__(
            self,
            "winsor_upper_quantile",
            _clamp_float(self.winsor_upper_quantile, 0.51, 1.0, _DEFAULT_WINSOR_UPPER),
        )
        object.__setattr__(
            self,
            "clip_standard_devs",
            max(0.0, _as_float(self.clip_standard_devs, _DEFAULT_CLIP_STD_DEVS)),
        )

        if isinstance(self.default_config, Mapping):
            try:
                default_config = FeatureTransformConfig(**self.default_config)
            except Exception as exc:
                raise ConfigurationError(
                    "Invalid default preprocessing feature config.",
                    details={"reason": type(exc).__name__},
                ) from exc
        elif isinstance(self.default_config, FeatureTransformConfig):
            default_config = self.default_config
        else:
            raise ConfigurationError("Default preprocessing feature config must be a mapping or FeatureTransformConfig.")

        configs: dict[str, FeatureTransformConfig] = {}

        for raw_key, raw_value in (self.feature_configs or {}).items():
            name = _canonical_field_name(raw_key)

            if not name:
                continue

            if isinstance(raw_value, Mapping):
                try:
                    config = FeatureTransformConfig(**raw_value)
                except Exception as exc:
                    raise ConfigurationError(
                        "Invalid preprocessing feature config.",
                        details={"feature": name, "reason": type(exc).__name__},
                    ) from exc
            elif isinstance(raw_value, FeatureTransformConfig):
                config = raw_value
            else:
                raise ConfigurationError(
                    "Preprocessing feature config must be a mapping or FeatureTransformConfig.",
                    details={"feature": name},
                )

            configs[name] = config

        object.__setattr__(self, "default_config", default_config)
        object.__setattr__(self, "feature_configs", MappingProxyType(configs))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "PreprocessOptions":
        """
        Build preprocessing options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_PREPROCESS_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_PREPROCESS_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_PREPROCESS_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_PREPROCESS_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_PREPROCESS_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_PREPROCESS_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_samples=_as_int(
                _setting(settings, "ML_PREPROCESS_MAX_SAMPLES", _DEFAULT_MAX_SAMPLES),
                _DEFAULT_MAX_SAMPLES,
            ),
            max_features=_as_int(
                _setting(settings, "ML_PREPROCESS_MAX_FEATURES", _DEFAULT_MAX_FEATURES),
                _DEFAULT_MAX_FEATURES,
            ),
            max_categories=_as_int(
                _setting(settings, "ML_PREPROCESS_MAX_CATEGORIES", _DEFAULT_MAX_CATEGORIES),
                _DEFAULT_MAX_CATEGORIES,
            ),
            max_set_items=_as_int(
                _setting(settings, "ML_PREPROCESS_MAX_SET_ITEMS", _DEFAULT_MAX_SET_ITEMS),
                _DEFAULT_MAX_SET_ITEMS,
            ),
            max_vector_dim=_as_int(
                _setting(settings, "ML_PREPROCESS_MAX_VECTOR_DIM", _DEFAULT_MAX_VECTOR_DIM),
                _DEFAULT_MAX_VECTOR_DIM,
            ),
            hash_dim=_as_int(
                _setting(settings, "ML_PREPROCESS_HASH_DIM", _DEFAULT_HASH_DIM),
                _DEFAULT_HASH_DIM,
            ),
            max_rank_samples=_as_int(
                _setting(settings, "ML_PREPROCESS_MAX_RANK_SAMPLES", _DEFAULT_MAX_RANK_SAMPLES),
                _DEFAULT_MAX_RANK_SAMPLES,
            ),
            max_issues=_as_int(
                _setting(settings, "ML_PREPROCESS_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "ML_PREPROCESS_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            missing_policy=str(_setting(settings, "ML_PREPROCESS_MISSING_POLICY", MissingPolicy.ZERO.value)),
            outlier_policy=str(_setting(settings, "ML_PREPROCESS_OUTLIER_POLICY", OutlierPolicy.CLIP.value)),
            scaling_method=str(_setting(settings, "ML_PREPROCESS_SCALING_METHOD", ScalingMethod.STANDARD.value)),
            encoding_method=str(_setting(settings, "ML_PREPROCESS_ENCODING_METHOD", EncodingMethod.ORDINAL.value)),
            set_encoding_method=str(
                _setting(settings, "ML_PREPROCESS_SET_ENCODING_METHOD", SetEncodingMethod.HASH.value)
            ),
            vector_scaling_method=str(
                _setting(settings, "ML_PREPROCESS_VECTOR_SCALING_METHOD", VectorScalingMethod.NONE.value)
            ),
            datetime_mode=str(
                _setting(settings, "ML_PREPROCESS_DATETIME_MODE", DatetimeFeatureMode.BOTH.value)
            ),
            feature_selection_method=str(
                _setting(settings, "ML_PREPROCESS_FEATURE_SELECTION_METHOD", FeatureSelectionMethod.NONE.value)
            ),
            variance_threshold=_as_float(
                _setting(settings, "ML_PREPROCESS_VARIANCE_THRESHOLD", _DEFAULT_VARIANCE_THRESHOLD),
                _DEFAULT_VARIANCE_THRESHOLD,
            ),
            coverage_threshold=_as_float(
                _setting(settings, "ML_PREPROCESS_COVERAGE_THRESHOLD", _DEFAULT_COVERAGE_THRESHOLD),
                _DEFAULT_COVERAGE_THRESHOLD,
            ),
            max_selected_features=_as_int(
                _setting(settings, "ML_PREPROCESS_MAX_SELECTED_FEATURES", 0),
                0,
            ),
            one_hot_max_categories=_as_int(
                _setting(settings, "ML_PREPROCESS_ONE_HOT_MAX_CATEGORIES", 50),
                50,
            ),
            add_missing_indicators=_as_bool(
                _setting(settings, "ML_PREPROCESS_ADD_MISSING_INDICATORS", False),
                False,
            ),
            preserve_original_feature_names=_as_bool(
                _setting(settings, "ML_PREPROCESS_PRESERVE_ORIGINAL_NAMES", True),
                True,
            ),
            winsor_lower_quantile=_as_float(
                _setting(settings, "ML_PREPROCESS_WINSOR_LOWER_QUANTILE", _DEFAULT_WINSOR_LOWER),
                _DEFAULT_WINSOR_LOWER,
            ),
            winsor_upper_quantile=_as_float(
                _setting(settings, "ML_PREPROCESS_WINSOR_UPPER_QUANTILE", _DEFAULT_WINSOR_UPPER),
                _DEFAULT_WINSOR_UPPER,
            ),
            clip_standard_devs=_as_float(
                _setting(settings, "ML_PREPROCESS_CLIP_STANDARD_DEVS", _DEFAULT_CLIP_STD_DEVS),
                _DEFAULT_CLIP_STD_DEVS,
            ),
            unknown_field_policy=str(
                _setting(settings, "ML_PREPROCESS_UNKNOWN_FIELD_POLICY", UnknownFieldPolicy.DROP.value)
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ML_PREPROCESS_DROP_FORBIDDEN_FIELDS", False),
                False,
            ),
            allow_label_leakage_scan=_as_bool(
                _setting(settings, "ML_PREPROCESS_ALLOW_LABEL_LEAKAGE_SCAN", True),
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
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
            "limits": {
                "max_samples": self.max_samples,
                "max_features": self.max_features,
                "max_categories": self.max_categories,
                "max_set_items": self.max_set_items,
                "max_vector_dim": self.max_vector_dim,
                "hash_dim": self.hash_dim,
                "max_rank_samples": self.max_rank_samples,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_selected_features": self.max_selected_features,
            },
            "policies": {
                "missing_policy": self.missing_policy.value,
                "outlier_policy": self.outlier_policy.value,
                "scaling_method": self.scaling_method.value,
                "encoding_method": self.encoding_method.value,
                "set_encoding_method": self.set_encoding_method.value,
                "vector_scaling_method": self.vector_scaling_method.value,
                "datetime_mode": self.datetime_mode.value,
                "feature_selection_method": self.feature_selection_method.value,
                "unknown_field_policy": self.unknown_field_policy.value,
            },
            "thresholds": {
                "variance_threshold": round(self.variance_threshold, 6),
                "coverage_threshold": round(self.coverage_threshold, 6),
                "winsor_lower_quantile": round(self.winsor_lower_quantile, 6),
                "winsor_upper_quantile": round(self.winsor_upper_quantile, 6),
                "clip_standard_devs": round(self.clip_standard_devs, 6),
            },
            "flags": {
                "one_hot_max_categories": self.one_hot_max_categories,
                "add_missing_indicators": self.add_missing_indicators,
                "preserve_original_feature_names": self.preserve_original_feature_names,
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "allow_label_leakage_scan": self.allow_label_leakage_scan,
            },
            "configured_feature_count": len(self.feature_configs),
        }


# -----------------------------------------------------------------------------
# Issue and result models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PreprocessingIssue:
    """
    Safe preprocessing issue.

    Issues never contain raw feature values, raw narratives, raw identifiers,
    secrets, tokens, passwords, database URLs, filesystem paths, or model
    artifact paths.
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


@dataclass(slots=True)
class PreprocessedRow:
    """
    One preprocessed internal row.

    This is internal-facing. Public summaries must not expose values.
    """

    subject_ref_hash: Optional[str] = None
    values: dict[str, float] = dataclass_field(default_factory=dict)
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize row values.
        """
        if self.subject_ref_hash is not None:
            cleaned = _clean_text(self.subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower()
            self.subject_ref_hash = cleaned if cleaned and _is_safe_hash(cleaned) else cleaned or None

        normalized: dict[str, float] = {}

        for raw_key, raw_value in (self.values or {}).items():
            key = _canonical_field_name(raw_key)

            if not key:
                continue

            numeric = _coerce_float(raw_value, allow_bool=True)
            normalized[key] = _round6(numeric if numeric is not None else 0.0)

        self.values = normalized
        self.metadata = _safe_detail_value(self.metadata) or {}

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return a safe row summary without values.
        """
        return {
            "feature_count": len(self.values),
            "metadata": _safe_detail_value(self.metadata),
        }

    def to_internal_dict(self) -> dict[str, Any]:
        """
        Return a fuller internal row representation.

        This contains feature values and must not be exposed publicly.
        """
        return {
            "subject_ref_hash": self.subject_ref_hash,
            "values": {key: float(value) for key, value in sorted(self.values.items())},
            "metadata": _safe_detail_value(self.metadata),
        }


@dataclass(slots=True)
class PreprocessedMatrix:
    """
    Safe preprocessing result.

    The `rows` list is internal-facing. Public summaries deliberately exclude
    feature values and subject-label pairs.
    """

    ok: bool = True
    stage: PreprocessingStage = PreprocessingStage.TRANSFORM
    feature_names: tuple[str, ...] = ()
    rows: tuple[PreprocessedRow, ...] = ()
    counts: dict[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[PreprocessingIssue, ...] = ()
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize matrix values.
        """
        object.__setattr__(self, "stage", _normalize_enum_option(self.stage, PreprocessingStage, PreprocessingStage.TRANSFORM))
        object.__setattr__(self, "feature_names", tuple(_canonical_field_name(name) for name in (self.feature_names or ()) if _canonical_field_name(name)))
        object.__setattr__(self, "rows", tuple(self.rows or ()))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "counts", dict(self.counts or {}))
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})

    def __len__(self) -> int:
        """
        Return number of preprocessed rows.
        """
        return len(self.rows)

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include feature values or subject hashes.
        """
        feature_sample = list(self.feature_names[: max(1, int(self.metadata.get("max_summary_items", _DEFAULT_MAX_SUMMARY_ITEMS)))])

        return {
            "ok": self.ok,
            "stage": self.stage.value,
            "feature_count": len(self.feature_names),
            "feature_names_sample": feature_sample,
            "feature_names_truncated": len(self.feature_names) > len(feature_sample),
            "row_count": len(self.rows),
            "counts": dict(self.counts),
            "fingerprint": self.fingerprint,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_PREPROCESSING_CAVEATS),
            "safety_flags": dict(_PREPROCESSING_SAFETY_FLAGS),
        }

    def to_internal_dict(self) -> dict[str, Any]:
        """
        Return a fuller internal representation.

        This contains feature values and must not be exposed publicly.
        """
        payload = self.to_response_dict()
        payload.pop("feature_names_sample", None)
        payload.pop("feature_names_truncated", None)
        payload["feature_names"] = list(self.feature_names)
        payload["rows"] = [row.to_internal_dict() for row in self.rows]
        payload["internal_only"] = True
        return payload


# -----------------------------------------------------------------------------
# Column state
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class ColumnState:
    """
    Fitted state for one input feature column.
    """

    name: str
    role: FeatureRole
    config: FeatureTransformConfig

    fitted: bool = False
    selected: bool = True
    total_count: int = 0
    missing_count: int = 0
    nonmissing_count: int = 0
    coverage: float = 0.0
    selection_score: float = 0.0

    output_columns: tuple[str, ...] = ()
    missing_indicator_column: Optional[str] = None

    # Numeric state
    mean: float = 0.0
    std: float = 0.0
    median: float = 0.0
    mad: float = 0.0
    min_value: float = 0.0
    max_value: float = 0.0
    q_low: float = 0.0
    q_high: float = 0.0
    max_abs: float = 0.0
    variance: float = 0.0
    fill_value: float = 0.0
    sorted_values: tuple[float, ...] = ()

    # Categorical state
    category_map: dict[str, int] = dataclass_field(default_factory=dict)
    category_freq: dict[str, int] = dataclass_field(default_factory=dict)
    category_total: int = 0
    unknown_code: int = 0
    binary_two: bool = False
    one_hot_columns: tuple[str, ...] = ()
    one_hot_map: dict[str, str] = dataclass_field(default_factory=dict)
    one_hot_other: Optional[str] = None
    hash_columns: tuple[str, ...] = ()

    # Set state
    element_freq: dict[str, int] = dataclass_field(default_factory=dict)
    element_total: int = 0
    max_set_size: int = 0
    set_size_variance: float = 0.0
    top_elements: tuple[str, ...] = ()
    set_one_hot_columns: tuple[str, ...] = ()
    set_one_hot_map: dict[str, str] = dataclass_field(default_factory=dict)
    set_hash_columns: tuple[str, ...] = ()
    set_summary_columns: tuple[str, ...] = ()

    # Vector state
    vector_dim: int = 0
    vector_columns: tuple[str, ...] = ()
    dim_means: tuple[float, ...] = ()
    dim_stds: tuple[float, ...] = ()
    dim_mins: tuple[float, ...] = ()
    dim_maxs: tuple[float, ...] = ()
    vector_norm_variance: float = 0.0

    # Datetime state
    reference_epoch: float = 0.0
    epoch_scale: float = 1.0
    epoch_variance: float = 0.0
    datetime_columns: tuple[str, ...] = ()


# -----------------------------------------------------------------------------
# Input extraction and normalization
# -----------------------------------------------------------------------------


def _iter_input_records(data: Any) -> list[Any]:
    """
    Convert flexible preprocessing input into a list of row-like records.
    """
    if data is None:
        return []

    if isinstance(data, Mapping):
        if "feature_names" in data and ("rows" in data or "matrix" in data):
            names = _as_sequence(data.get("feature_names") or ())
            raw_rows = _as_sequence(data.get("rows") if "rows" in data else data.get("matrix"))
            out: list[Any] = []

            for raw_row in raw_rows:
                if isinstance(raw_row, Mapping):
                    out.append(raw_row)
                elif isinstance(raw_row, Sequence) and not isinstance(raw_row, (str, bytes, bytearray)):
                    out.append(dict(zip([str(name) for name in names], raw_row)))

            return out

        for key in ("rows", "records", "items", "examples", "vectors"):
            if key in data:
                return _as_sequence(data[key])

        return [data]

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _extract_row(record: Any) -> tuple[Optional[str], dict[str, Any]]:
    """
    Extract pseudonymous subject reference and feature mapping from a row.
    """
    subject: Any = None
    features: Any = None

    if isinstance(record, Mapping):
        for key in _SUBJECT_KEYS:
            if key in record:
                subject = record[key]
                break

        if "features" in record and isinstance(record["features"], Mapping):
            features = record["features"]
        elif "values" in record and isinstance(record["values"], Mapping):
            features = record["values"]
        else:
            features = {
                key: value
                for key, value in record.items()
                if key not in _SUBJECT_KEYS and key not in _NON_FEATURE_KEYS
            }
    else:
        for attr in _SUBJECT_KEYS:
            value = getattr(record, attr, None)

            if value is not None:
                subject = value
                break

        candidate = getattr(record, "features", None)

        if isinstance(candidate, Mapping):
            features = candidate
        else:
            candidate = getattr(record, "values", None)
            features = candidate if isinstance(candidate, Mapping) else {}

    if not isinstance(features, Mapping):
        features = {}

    subject_text = _clean_text(subject, _MAX_SUBJECT_HASH_LENGTH)

    if subject_text and not _is_safe_hash(subject_text):
        # Preprocessing never hashes raw identifiers here. Raw identifiers are
        # treated as non-feature metadata and omitted from the matrix.
        subject_text = None

    return subject_text or None, dict(features)


def _normalize_feature_keys(
    features: Mapping[str, Any],
    options: PreprocessOptions,
    issues: list[PreprocessingIssue],
    index: int,
    known_names: Optional[set[str]] = None,
) -> Optional[dict[str, Any]]:
    """
    Normalize and validate feature keys for one row.

    Returns None when the row must be skipped.
    """
    out: dict[str, Any] = {}

    for raw_key, raw_value in features.items():
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

        if _is_forbidden_key(canonical) or (
            options.allow_label_leakage_scan and _is_label_leakage_key(canonical)
        ):
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

        if known_names is not None and canonical not in known_names:
            if options.unknown_field_policy == UnknownFieldPolicy.ERROR:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="unknown_feature",
                    message="Unknown feature field rejected.",
                    field=key_text,
                    details={"index": index},
                )
                return None

            if options.unknown_field_policy == UnknownFieldPolicy.WARN:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="unknown_feature_dropped",
                    message="Unknown feature field omitted.",
                    field=key_text,
                    details={"index": index},
                )

            continue

        if canonical in out:
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

        out[canonical] = raw_value

    return out


def _infer_role(values: Sequence[Any]) -> FeatureRole:
    """
    Infer a conservative feature role from sampled values.
    """
    if not values:
        return FeatureRole.NUMERIC

    saw_bool = False
    saw_numeric = False
    saw_string = False
    saw_datetime = False
    saw_set = False
    vector_like = 0
    set_like = 0
    sample_count = 0

    for value in values[: min(len(values), 1_000)]:
        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        sample_count += 1

        if isinstance(value, bool):
            saw_bool = True
        elif isinstance(value, datetime):
            saw_datetime = True
        elif isinstance(value, (int, float, Decimal)):
            saw_numeric = True
        elif isinstance(value, (set, frozenset)):
            saw_set = True
        elif isinstance(value, Mapping):
            saw_string = True
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            items = list(value)

            if not items:
                set_like += 1
                continue

            if all(isinstance(item, (int, float, Decimal)) and not isinstance(item, bool) for item in items):
                vector_like += 1
            else:
                set_like += 1
        else:
            saw_string = True

    if sample_count == 0:
        return FeatureRole.NUMERIC

    if saw_datetime and not (saw_numeric or saw_string or saw_set or vector_like or set_like):
        return FeatureRole.DATETIME

    if saw_bool and not (saw_numeric or saw_string or saw_datetime or saw_set or vector_like or set_like):
        return FeatureRole.BOOLEAN

    if saw_set or set_like > vector_like:
        return FeatureRole.SET

    if vector_like:
        return FeatureRole.VECTOR

    if saw_numeric and not (saw_string or saw_datetime or saw_set):
        return FeatureRole.NUMERIC

    if saw_string:
        return FeatureRole.CATEGORICAL

    return FeatureRole.COMPOSITE


def _resolve_config(
    options: PreprocessOptions,
    name: str,
    inferred_role: FeatureRole,
) -> FeatureTransformConfig:
    """
    Resolve effective per-feature configuration.
    """
    default_config = options.default_config
    override = options.feature_configs.get(name)

    role_value = _first(
        override.role if override is not None else None,
        default_config.role,
        inferred_role,
    )

    if role_value is None or role_value == FeatureRole.AUTO:
        role = inferred_role
    else:
        role = role_value if isinstance(role_value, FeatureRole) else FeatureRole(str(role_value))

    return FeatureTransformConfig(
        role=role,
        missing_policy=_first(
            override.missing_policy if override is not None else None,
            default_config.missing_policy,
            options.missing_policy,
        ),
        outlier_policy=_first(
            override.outlier_policy if override is not None else None,
            default_config.outlier_policy,
            options.outlier_policy,
        ),
        scaling_method=_first(
            override.scaling_method if override is not None else None,
            default_config.scaling_method,
            options.scaling_method,
        ),
        encoding_method=_first(
            override.encoding_method if override is not None else None,
            default_config.encoding_method,
            options.encoding_method,
        ),
        set_encoding_method=_first(
            override.set_encoding_method if override is not None else None,
            default_config.set_encoding_method,
            options.set_encoding_method,
        ),
        vector_scaling_method=_first(
            override.vector_scaling_method if override is not None else None,
            default_config.vector_scaling_method,
            options.vector_scaling_method,
        ),
        datetime_mode=_first(
            override.datetime_mode if override is not None else None,
            default_config.datetime_mode,
            options.datetime_mode,
        ),
        log1p=_first(
            override.log1p if override is not None else None,
            default_config.log1p,
        ),
        clip_min=_first(
            override.clip_min if override is not None else None,
            default_config.clip_min,
        ),
        clip_max=_first(
            override.clip_max if override is not None else None,
            default_config.clip_max,
        ),
        constant_fill=_first(
            override.constant_fill if override is not None else None,
            default_config.constant_fill,
        ),
        max_categories=_first(
            override.max_categories if override is not None else None,
            default_config.max_categories,
            options.one_hot_max_categories,
        ),
        hash_dim=_first(
            override.hash_dim if override is not None else None,
            default_config.hash_dim,
            options.hash_dim,
        ),
        selected=_first(
            override.selected if override is not None else None,
            default_config.selected,
        ),
        weight=_first(
            override.weight if override is not None else None,
            default_config.weight,
            1.0,
        ),
    )


def _missing_indicator_column(name: str) -> str:
    """
    Return safe missing-indicator column name.
    """
    return f"{name}__missing"


def _add_missing_indicator(state: ColumnState, options: PreprocessOptions) -> None:
    """
    Append missing-indicator column when configured.
    """
    if not options.add_missing_indicators:
        return

    column = _missing_indicator_column(state.name)
    state.missing_indicator_column = column

    if column not in state.output_columns:
        state.output_columns = tuple(sorted(set(state.output_columns) | {column}))


# -----------------------------------------------------------------------------
# Fitting helpers
# -----------------------------------------------------------------------------


def _fit_numeric_state(
    state: ColumnState,
    values: Sequence[Any],
    options: PreprocessOptions,
) -> None:
    """
    Fit numeric or boolean state.
    """
    allow_bool = state.role == FeatureRole.BOOLEAN
    floats: list[float] = []
    missing = 0

    for value in values:
        numeric = _coerce_float(value, allow_bool=allow_bool)

        if numeric is None:
            missing += 1
        else:
            floats.append(numeric)

    state.total_count = len(values)
    state.missing_count = missing
    state.nonmissing_count = len(floats)
    state.coverage = float(len(floats)) / float(len(values)) if values else 0.0

    if floats:
        sorted_values = sorted(floats)
        state.sorted_values = tuple(sorted_values[: options.max_rank_samples])
        state.min_value = _round6(sorted_values[0])
        state.max_value = _round6(sorted_values[-1])
        state.mean = _round6(_mean(floats))
        state.std = _round6(_stddev(floats, state.mean))
        state.median = _round6(_quantile(sorted_values, 0.5))
        state.mad = _round6(_mad(sorted_values, state.median))
        state.q_low = _round6(_quantile(sorted_values, options.winsor_lower_quantile))
        state.q_high = _round6(_quantile(sorted_values, options.winsor_upper_quantile))
        state.max_abs = _round6(max(abs(value) for value in floats))
        state.variance = _round6(state.std * state.std)
    else:
        state.sorted_values = ()
        state.min_value = 0.0
        state.max_value = 0.0
        state.mean = 0.0
        state.std = 0.0
        state.median = 0.0
        state.mad = 0.0
        state.q_low = 0.0
        state.q_high = 0.0
        state.max_abs = 0.0
        state.variance = 0.0

    missing_policy = state.config.missing_policy or options.missing_policy

    if missing_policy in {MissingPolicy.MEDIAN, MissingPolicy.MODE}:
        state.fill_value = state.median
    elif missing_policy == MissingPolicy.CONSTANT:
        state.fill_value = _round6(
            state.config.constant_fill if state.config.constant_fill is not None else 0.0
        )
    else:
        state.fill_value = 0.0

    state.output_columns = (state.name,)
    _add_missing_indicator(state, options)
    state.fitted = True


def _fit_categorical_state(
    state: ColumnState,
    values: Sequence[Any],
    options: PreprocessOptions,
) -> None:
    """
    Fit categorical state using salted one-way hashes only.
    """
    freq: dict[str, int] = {}
    missing = 0
    total = 0

    for value in values:
        token = _categorical_token(value)

        if not token:
            missing += 1
            continue

        hashed = _hash_token(token, options, "category")
        freq[hashed] = freq.get(hashed, 0) + 1
        total += 1

    state.total_count = len(values)
    state.missing_count = missing
    state.nonmissing_count = total
    state.coverage = float(total) / float(len(values)) if values else 0.0
    state.category_freq = freq
    state.category_total = total

    sorted_hashes = sorted(freq)
    encoding = state.config.encoding_method or options.encoding_method

    if encoding == EncodingMethod.NONE:
        encoding = EncodingMethod.ORDINAL

    if encoding == EncodingMethod.BINARY and len(sorted_hashes) == 2:
        state.category_map = {hashed: index for index, hashed in enumerate(sorted_hashes)}
        state.binary_two = True
        state.unknown_code = 0
    else:
        if encoding == EncodingMethod.BINARY:
            encoding = EncodingMethod.ORDINAL

        state.category_map = {hashed: index + 1 for index, hashed in enumerate(sorted_hashes)}
        state.binary_two = False
        state.unknown_code = 0

    output_columns: list[str] = []

    if encoding == EncodingMethod.ONE_HOT:
        max_categories = int(state.config.max_categories or options.one_hot_max_categories)
        top = sorted(freq.items(), key=lambda item: (-item[1], item[0]))[:max_categories]
        state.one_hot_map = {
            hashed: f"{state.name}__cat_{hashed[:12]}"
            for hashed, _ in top
        }
        output_columns.extend(state.one_hot_map.values())

        if len(freq) > len(top):
            state.one_hot_other = f"{state.name}__cat_other"
            output_columns.append(state.one_hot_other)
        else:
            state.one_hot_other = None

        state.one_hot_columns = tuple(output_columns)

    elif encoding == EncodingMethod.HASH:
        dim = int(state.config.hash_dim or options.hash_dim)
        state.hash_columns = tuple(f"{state.name}__hash_{index:03d}" for index in range(dim))
        output_columns.extend(state.hash_columns)

    else:
        output_columns.append(state.name)

    state.output_columns = tuple(sorted(set(output_columns)))
    _add_missing_indicator(state, options)
    state.fitted = True


def _fit_set_state(
    state: ColumnState,
    values: Sequence[Any],
    options: PreprocessOptions,
) -> None:
    """
    Fit set state using salted one-way element hashes only.
    """
    element_freq: dict[str, int] = {}
    sizes: list[int] = []
    missing = 0
    total_elements = 0

    for value in values:
        tokens = _coerce_set_tokens(value, options.max_set_items)

        if tokens is None:
            missing += 1
            continue

        hashed_items: list[str] = []
        seen: set[str] = set()

        for token in tokens:
            hashed = _hash_token(token, options, "set_element")

            if hashed in seen:
                continue

            seen.add(hashed)
            hashed_items.append(hashed)
            element_freq[hashed] = element_freq.get(hashed, 0) + 1
            total_elements += 1

        sizes.append(len(hashed_items))

    state.total_count = len(values)
    state.missing_count = missing
    state.nonmissing_count = len(sizes)
    state.coverage = float(len(sizes)) / float(len(values)) if values else 0.0
    state.element_freq = element_freq
    state.element_total = total_elements
    state.max_set_size = max(sizes, default=0)
    state.set_size_variance = _round6(_variance([float(size) for size in sizes]))

    max_categories = int(state.config.max_categories or options.one_hot_max_categories)
    top = sorted(element_freq.items(), key=lambda item: (-item[1], item[0]))[:max_categories]
    state.top_elements = tuple(hashed for hashed, _ in top)

    encoding = state.config.set_encoding_method or options.set_encoding_method

    if encoding == SetEncodingMethod.NONE:
        encoding = SetEncodingMethod.HASH

    output_columns: list[str] = []

    if encoding == SetEncodingMethod.ONE_HOT:
        state.set_one_hot_map = {
            hashed: f"{state.name}__elem_{hashed[:12]}"
            for hashed in state.top_elements
        }
        output_columns.extend(state.set_one_hot_map.values())
        state.set_one_hot_columns = tuple(output_columns)

    elif encoding == SetEncodingMethod.HASH:
        dim = int(state.config.hash_dim or options.hash_dim)
        state.set_hash_columns = tuple(f"{state.name}__hash_{index:03d}" for index in range(dim))
        output_columns.extend(state.set_hash_columns)

    elif encoding == SetEncodingMethod.SUMMARY:
        state.set_summary_columns = (
            f"{state.name}__cardinality",
            f"{state.name}__entropy",
            f"{state.name}__top_share",
            f"{state.name}__mean_frequency",
        )
        output_columns.extend(state.set_summary_columns)

    elif encoding == SetEncodingMethod.FREQUENCY:
        output_columns.append(f"{state.name}__mean_frequency")

    else:
        output_columns.append(f"{state.name}__cardinality")

    state.output_columns = tuple(sorted(set(output_columns)))
    _add_missing_indicator(state, options)
    state.fitted = True


def _fit_vector_state(
    state: ColumnState,
    values: Sequence[Any],
    options: PreprocessOptions,
) -> None:
    """
    Fit vector state.
    """
    vectors: list[tuple[float, ...]] = []
    missing = 0
    dim = 0

    for value in values:
        vector = _coerce_vector(value, options.max_vector_dim)

        if vector is None:
            missing += 1
            continue

        dim = max(dim, len(vector))
        vectors.append(vector)

    state.total_count = len(values)
    state.missing_count = missing
    state.nonmissing_count = len(vectors)
    state.coverage = float(len(vectors)) / float(len(values)) if values else 0.0
    state.vector_dim = min(dim, options.max_vector_dim)

    if vectors and state.vector_dim > 0:
        per_dim: list[list[float]] = [[] for _ in range(state.vector_dim)]
        norms: list[float] = []

        for vector in vectors:
            padded = list(vector[: state.vector_dim])
            padded.extend([0.0] * (state.vector_dim - len(padded)))

            for index, value in enumerate(padded):
                per_dim[index].append(value)

            norms.append(_l2_norm(padded))

        state.dim_means = tuple(_round6(_mean(column)) for column in per_dim)
        state.dim_stds = tuple(_round6(_stddev(column)) for column in per_dim)
        state.dim_mins = tuple(_round6(min(column)) for column in per_dim)
        state.dim_maxs = tuple(_round6(max(column)) for column in per_dim)
        state.vector_norm_variance = _round6(_variance(norms))
        state.vector_columns = tuple(f"{state.name}__{index:03d}" for index in range(state.vector_dim))
    else:
        state.dim_means = ()
        state.dim_stds = ()
        state.dim_mins = ()
        state.dim_maxs = ()
        state.vector_norm_variance = 0.0
        state.vector_columns = ()

    state.output_columns = state.vector_columns
    _add_missing_indicator(state, options)
    state.fitted = True


def _fit_datetime_state(
    state: ColumnState,
    values: Sequence[Any],
    options: PreprocessOptions,
) -> None:
    """
    Fit datetime state.
    """
    epochs: list[float] = []
    missing = 0

    for value in values:
        parsed = _parse_datetime(value)

        if parsed is None:
            missing += 1
            continue

        epochs.append(parsed.timestamp())

    state.total_count = len(values)
    state.missing_count = missing
    state.nonmissing_count = len(epochs)
    state.coverage = float(len(epochs)) / float(len(values)) if values else 0.0

    if epochs:
        state.reference_epoch = _round6(min(epochs))
        scale = max(abs(value - state.reference_epoch) for value in epochs)
        state.epoch_scale = _round6(scale if scale > 0 else 1.0)
        state.epoch_variance = _round6(_variance(epochs))
    else:
        state.reference_epoch = 0.0
        state.epoch_scale = 1.0
        state.epoch_variance = 0.0

    mode = state.config.datetime_mode or options.datetime_mode

    if mode == DatetimeFeatureMode.NONE:
        mode = DatetimeFeatureMode.BOTH

    columns: list[str] = []

    if mode in {DatetimeFeatureMode.EPOCH, DatetimeFeatureMode.BOTH}:
        columns.append(f"{state.name}__epoch")

    if mode in {DatetimeFeatureMode.CYCLICAL, DatetimeFeatureMode.BOTH}:
        columns.extend(
            [
                f"{state.name}__hour_sin",
                f"{state.name}__hour_cos",
                f"{state.name}__weekday_sin",
                f"{state.name}__weekday_cos",
                f"{state.name}__is_weekend",
            ]
        )

    state.datetime_columns = tuple(columns)
    state.output_columns = tuple(columns)
    _add_missing_indicator(state, options)
    state.fitted = True


def _fit_state(
    state: ColumnState,
    values: Sequence[Any],
    options: PreprocessOptions,
) -> None:
    """
    Fit one column state by role.
    """
    if state.role in {FeatureRole.NUMERIC, FeatureRole.BOOLEAN}:
        _fit_numeric_state(state, values, options)
    elif state.role == FeatureRole.CATEGORICAL:
        _fit_categorical_state(state, values, options)
    elif state.role == FeatureRole.SET:
        _fit_set_state(state, values, options)
    elif state.role == FeatureRole.VECTOR:
        _fit_vector_state(state, values, options)
    elif state.role == FeatureRole.DATETIME:
        _fit_datetime_state(state, values, options)
    else:
        _fit_categorical_state(state, values, options)


def _selection_score(state: ColumnState) -> float:
    """
    Return unsupervised selection score for one fitted state.
    """
    coverage = _clip_float(state.coverage, 0.0, 1.0, 0.0)

    if state.role in {FeatureRole.NUMERIC, FeatureRole.BOOLEAN}:
        variance = state.variance
    elif state.role == FeatureRole.CATEGORICAL:
        variance = _normalized_entropy(state.category_freq)
    elif state.role == FeatureRole.SET:
        denominator = float(state.max_set_size * state.max_set_size + 1)
        variance = state.set_size_variance / denominator if denominator > 0 else 0.0
    elif state.role == FeatureRole.VECTOR:
        variance = state.vector_norm_variance
    elif state.role == FeatureRole.DATETIME:
        denominator = float(state.epoch_scale * state.epoch_scale + 1)
        variance = state.epoch_variance / denominator if denominator > 0 else 0.0
    else:
        variance = 0.0

    normalized_variance = variance / (1.0 + variance) if variance > 0 else 0.0
    return _round6(coverage * normalized_variance)


def _select_features(
    states: Sequence[ColumnState],
    options: PreprocessOptions,
    issues: list[PreprocessingIssue],
) -> tuple[ColumnState, ...]:
    """
    Select features using bounded unsupervised policy.

    Supervised selection is intentionally not supported because it can leak
    target information into preprocessing.
    """
    forced: list[ColumnState] = []
    optional: list[ColumnState] = []
    dropped: list[ColumnState] = []

    for state in states:
        state.selection_score = _selection_score(state)

        if state.config.selected is False:
            state.selected = False
            dropped.append(state)
        elif state.config.selected is True:
            state.selected = True
            forced.append(state)
        else:
            optional.append(state)

    if options.feature_selection_method != FeatureSelectionMethod.NONE:
        filtered: list[ColumnState] = []

        for state in optional:
            if state.coverage < options.coverage_threshold:
                state.selected = False
                dropped.append(state)
                continue

            if options.feature_selection_method in {
                FeatureSelectionMethod.VARIANCE,
                FeatureSelectionMethod.COMBINED,
            } and state.selection_score < options.variance_threshold:
                state.selected = False
                dropped.append(state)
                continue

            state.selected = True
            filtered.append(state)

        optional = filtered

    optional.sort(key=lambda state: (-state.selection_score, state.name))

    max_selected = int(options.max_selected_features)

    if max_selected > 0:
        remaining = max(0, max_selected - len(forced))
        selected_optional = optional[:remaining]
        unselected_optional = optional[remaining:]

        for state in unselected_optional:
            state.selected = False
            dropped.append(state)
    else:
        selected_optional = optional

    if len(forced) > max_selected > 0:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="forced_features_exceed_max_selected",
            message="Forced feature selections exceed configured maximum selected features.",
            details={
                "forced_count": len(forced),
                "max_selected_features": max_selected,
            },
        )

    selected = forced + selected_optional

    if dropped:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="features_dropped_by_selection",
            message="Some features were dropped by preprocessing selection policy.",
            details={"dropped_count": len(dropped)},
        )

    selected.sort(key=lambda state: state.name)
    return tuple(selected)


def _build_output_columns(states: Sequence[ColumnState]) -> tuple[str, ...]:
    """
    Build deterministic global output column order.
    """
    columns: list[str] = []

    for state in states:
        if not state.selected:
            continue

        columns.extend(state.output_columns)

    return tuple(dict.fromkeys(columns))


def _zero_output_columns(
    state: ColumnState,
    row_values: dict[str, float],
) -> None:
    """
    Zero all non-indicator output columns for one state.
    """
    for column in state.output_columns:
        if column == state.missing_indicator_column:
            continue

        row_values[column] = 0.0


def _apply_state_weight(
    state: ColumnState,
    row_values: dict[str, float],
) -> None:
    """
    Apply bounded per-feature weight to non-indicator output columns.
    """
    weight = _round6(state.config.weight)

    if weight == 1.0:
        return

    for column in state.output_columns:
        if column == state.missing_indicator_column:
            continue

        if column in row_values:
            row_values[column] = _round6(float(row_values[column]) * weight)


def _finalize_state_output(
    state: ColumnState,
    row_values: dict[str, float],
) -> None:
    """
    Ensure all expected output columns exist and apply weights.
    """
    for column in state.output_columns:
        if column == state.missing_indicator_column:
            continue

        row_values.setdefault(column, 0.0)

    _apply_state_weight(state, row_values)


# -----------------------------------------------------------------------------
# Transform helpers
# -----------------------------------------------------------------------------


def _transform_numeric_state(
    state: ColumnState,
    value: Any,
    row_values: dict[str, float],
    options: PreprocessOptions,
    issues: list[PreprocessingIssue],
    index: int,
    missing: bool,
) -> bool:
    """
    Transform one numeric or boolean feature value.
    """
    policy = state.config.missing_policy or options.missing_policy

    if missing:
        if policy in {MissingPolicy.ERROR, MissingPolicy.DROP_ROW}:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="missing_numeric_feature",
                message="Required numeric feature is missing.",
                field=state.name,
                details={"index": index, "policy": policy.value},
            )
            return False

        numeric = state.fill_value
    else:
        numeric = _coerce_float(value, allow_bool=state.role == FeatureRole.BOOLEAN)

        if numeric is None:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="invalid_numeric_feature",
                message="Numeric feature value could not be coerced and was filled.",
                field=state.name,
                details={"index": index},
            )
            numeric = state.fill_value

    if state.config.log1p:
        numeric = _signed_log1p(numeric)

    outlier_policy = state.config.outlier_policy or options.outlier_policy

    if outlier_policy == OutlierPolicy.CLIP:
        low = state.config.clip_min
        high = state.config.clip_max

        if low is None and high is None and state.std > 0:
            low = state.mean - options.clip_standard_devs * state.std
            high = state.mean + options.clip_standard_devs * state.std

        if low is None:
            low = state.min_value

        if high is None:
            high = state.max_value

        numeric = _clip_float(numeric, low, high, numeric)

    elif outlier_policy == OutlierPolicy.WINSORIZE:
        numeric = _clip_float(numeric, state.q_low, state.q_high, numeric)

    scaling = state.config.scaling_method or options.scaling_method

    if scaling == ScalingMethod.LOG1P:
        numeric = _signed_log1p(numeric)
    elif scaling == ScalingMethod.SQRT:
        numeric = _signed_sqrt(numeric)
    elif scaling == ScalingMethod.STANDARD:
        numeric = (numeric - state.mean) / state.std if state.std > 0 else 0.0
    elif scaling == ScalingMethod.ROBUST_STANDARD:
        numeric = (numeric - state.median) / state.mad if state.mad > 0 else 0.0
    elif scaling == ScalingMethod.MINMAX:
        span = state.max_value - state.min_value
        numeric = (numeric - state.min_value) / span if span > 0 else 0.0
    elif scaling == ScalingMethod.MAXABS:
        numeric = numeric / state.max_abs if state.max_abs > 0 else 0.0
    elif scaling == ScalingMethod.RANK:
        numeric = _rank_percentile(state.sorted_values, numeric)

    row_values[state.name] = _round6(numeric)
    return True


def _transform_categorical_state(
    state: ColumnState,
    value: Any,
    row_values: dict[str, float],
    options: PreprocessOptions,
    issues: list[PreprocessingIssue],
    index: int,
    missing: bool,
) -> bool:
    """
    Transform one categorical feature value.
    """
    _ = issues, index

    encoding = state.config.encoding_method or options.encoding_method

    if encoding == EncodingMethod.NONE:
        encoding = EncodingMethod.ORDINAL

    if missing:
        _zero_output_columns(state, row_values)

        if encoding in {EncodingMethod.ORDINAL, EncodingMethod.BINARY}:
            row_values[state.name] = float(state.unknown_code)

        return True

    token = _categorical_token(value)

    if not token:
        _zero_output_columns(state, row_values)

        if encoding in {EncodingMethod.ORDINAL, EncodingMethod.BINARY}:
            row_values[state.name] = float(state.unknown_code)

        return True

    hashed = _hash_token(token, options, "category")

    if encoding in {EncodingMethod.ORDINAL, EncodingMethod.BINARY}:
        row_values[state.name] = float(state.category_map.get(hashed, state.unknown_code))
        return True

    if encoding == EncodingMethod.ONE_HOT:
        _zero_output_columns(state, row_values)

        column = state.one_hot_map.get(hashed)

        if column is not None:
            row_values[column] = 1.0
        elif state.one_hot_other is not None:
            row_values[state.one_hot_other] = 1.0

        return True

    if encoding == EncodingMethod.HASH:
        dim = len(state.hash_columns)

        if dim <= 0:
            return True

        vector = _feature_hash_vector(hashed, options, "category_hash", dim)

        for column, component in zip(state.hash_columns, vector):
            row_values[column] = _round6(component)

        return True

    # Frequency encoding.
    frequency = (
        float(state.category_freq.get(hashed, 0)) / float(state.category_total)
        if state.category_total > 0
        else 0.0
    )

    row_values[state.name] = _round6(frequency)
    return True


def _transform_set_state(
    state: ColumnState,
    value: Any,
    row_values: dict[str, float],
    options: PreprocessOptions,
    issues: list[PreprocessingIssue],
    index: int,
    missing: bool,
) -> bool:
    """
    Transform one set feature value.
    """
    _ = issues, index

    encoding = state.config.set_encoding_method or options.set_encoding_method

    if encoding == SetEncodingMethod.NONE:
        encoding = SetEncodingMethod.HASH

    if missing:
        _zero_output_columns(state, row_values)
        return True

    tokens = _coerce_set_tokens(value, options.max_set_items)

    if tokens is None:
        _zero_output_columns(state, row_values)
        return True

    hashed_items: list[str] = []
    seen: set[str] = set()

    for token in tokens:
        hashed = _hash_token(token, options, "set_element")

        if hashed in seen:
            continue

        seen.add(hashed)
        hashed_items.append(hashed)

    if encoding == SetEncodingMethod.CARDINALITY:
        row_values[f"{state.name}__cardinality"] = float(len(hashed_items))
        return True

    if encoding == SetEncodingMethod.ONE_HOT:
        _zero_output_columns(state, row_values)

        for hashed in hashed_items:
            column = state.set_one_hot_map.get(hashed)

            if column is not None:
                row_values[column] = 1.0

        return True

    if encoding == SetEncodingMethod.HASH:
        dim = len(state.set_hash_columns)

        if dim <= 0:
            return True

        sums = [0.0] * dim

        for hashed in hashed_items:
            vector = _feature_hash_vector(hashed, options, "set_element_hash", dim)

            for position, component in enumerate(vector):
                sums[position] += component

        count = float(len(hashed_items)) if hashed_items else 1.0

        for column, total in zip(state.set_hash_columns, sums):
            row_values[column] = _round6(total / count)

        return True

    if encoding == SetEncodingMethod.FREQUENCY:
        if not hashed_items or state.element_total <= 0:
            mean_frequency = 0.0
        else:
            total_frequency = sum(
                float(state.element_freq.get(hashed, 0))
                for hashed in hashed_items
            )
            mean_frequency = total_frequency / (
                float(len(hashed_items)) * float(state.element_total)
            )

        row_values[f"{state.name}__mean_frequency"] = _round6(mean_frequency)
        return True

    # Summary encoding.
    cardinality = float(len(hashed_items))

    if hashed_items:
        entropy = _normalized_entropy(
            {
                hashed: float(state.element_freq.get(hashed, 0))
                for hashed in hashed_items
            }
        )
    else:
        entropy = 0.0

    top_set = set(state.top_elements)

    if hashed_items and top_set:
        top_share = float(
            sum(1 for hashed in hashed_items if hashed in top_set)
        ) / float(len(hashed_items))
    else:
        top_share = 0.0

    if hashed_items and state.element_total > 0:
        total_frequency = sum(
            float(state.element_freq.get(hashed, 0))
            for hashed in hashed_items
        )
        mean_frequency = total_frequency / (
            float(len(hashed_items)) * float(state.element_total)
        )
    else:
        mean_frequency = 0.0

    columns = state.set_summary_columns or (f"{state.name}__cardinality",)
    values = (cardinality, entropy, top_share, mean_frequency)

    for column, component in zip(columns, values):
        row_values[column] = _round6(component)

    return True


def _transform_vector_state(
    state: ColumnState,
    value: Any,
    row_values: dict[str, float],
    options: PreprocessOptions,
    issues: list[PreprocessingIssue],
    index: int,
    missing: bool,
) -> bool:
    """
    Transform one vector feature value.
    """
    _ = issues, index

    if missing:
        _zero_output_columns(state, row_values)
        return True

    vector = _coerce_vector(value, max(state.vector_dim, options.max_vector_dim))

    if vector is None or state.vector_dim <= 0:
        _zero_output_columns(state, row_values)
        return True

    padded = list(vector[: state.vector_dim])
    padded.extend([0.0] * (state.vector_dim - len(padded)))

    scaling = state.config.vector_scaling_method or options.vector_scaling_method

    if scaling == VectorScalingMethod.L2:
        norm = _l2_norm(padded)

        if norm > 0:
            padded = [component / norm for component in padded]
        else:
            padded = [0.0 for _ in padded]

    for position, column in enumerate(state.vector_columns):
        component = padded[position] if position < len(padded) else 0.0

        if scaling == VectorScalingMethod.STANDARD:
            std = state.dim_stds[position] if position < len(state.dim_stds) else 0.0
            mean = state.dim_means[position] if position < len(state.dim_means) else 0.0
            component = (component - mean) / std if std > 0 else 0.0

        elif scaling == VectorScalingMethod.MINMAX:
            low = state.dim_mins[position] if position < len(state.dim_mins) else 0.0
            high = state.dim_maxs[position] if position < len(state.dim_maxs) else 0.0
            span = high - low
            component = (component - low) / span if span > 0 else 0.0

        row_values[column] = _round6(component)

    return True


def _transform_datetime_state(
    state: ColumnState,
    value: Any,
    row_values: dict[str, float],
    options: PreprocessOptions,
    issues: list[PreprocessingIssue],
    index: int,
    missing: bool,
) -> bool:
    """
    Transform one datetime feature value.
    """
    _ = issues, index

    mode = state.config.datetime_mode or options.datetime_mode

    if mode == DatetimeFeatureMode.NONE:
        mode = DatetimeFeatureMode.BOTH

    if missing:
        _zero_output_columns(state, row_values)
        return True

    parsed = _parse_datetime(value)

    if parsed is None:
        _zero_output_columns(state, row_values)
        return True

    epoch_column = f"{state.name}__epoch"

    if mode in {DatetimeFeatureMode.EPOCH, DatetimeFeatureMode.BOTH}:
        epoch = parsed.timestamp()
        scaled = (epoch - state.reference_epoch) / state.epoch_scale if state.epoch_scale > 0 else 0.0
        row_values[epoch_column] = _round6(scaled)

    if mode in {DatetimeFeatureMode.CYCLICAL, DatetimeFeatureMode.BOTH}:
        hour = (
            float(parsed.hour)
            + float(parsed.minute) / 60.0
            + float(parsed.second) / 3600.0
            + float(parsed.microsecond) / 3_600_000_000.0
        )

        hour_sin, hour_cos = _cyclical(hour, 24.0)
        row_values[f"{state.name}__hour_sin"] = _round6(hour_sin)
        row_values[f"{state.name}__hour_cos"] = _round6(hour_cos)

        weekday = float(parsed.weekday()) + hour / 24.0
        weekday_sin, weekday_cos = _cyclical(weekday, 7.0)
        row_values[f"{state.name}__weekday_sin"] = _round6(weekday_sin)
        row_values[f"{state.name}__weekday_cos"] = _round6(weekday_cos)
        row_values[f"{state.name}__is_weekend"] = 1.0 if parsed.weekday() >= 5 else 0.0

    return True


def _transform_state(
    state: ColumnState,
    value: Any,
    row_values: dict[str, float],
    options: PreprocessOptions,
    issues: list[PreprocessingIssue],
    index: int,
) -> bool:
    """
    Transform one feature value into one or more output columns.

    Returns False when the row must be rejected.
    """
    missing = (
        value is _MISSING
        or value is None
        or (isinstance(value, str) and not value.strip())
    )

    if state.missing_indicator_column:
        row_values[state.missing_indicator_column] = 1.0 if missing else 0.0

    if missing:
        policy = state.config.missing_policy or options.missing_policy

        if policy in {MissingPolicy.ERROR, MissingPolicy.DROP_ROW}:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="missing_required_feature",
                message="Required feature is missing.",
                field=state.name,
                details={"index": index, "policy": policy.value},
            )
            return False

        if policy == MissingPolicy.DROP_COLUMN:
            _zero_output_columns(state, row_values)
            _finalize_state_output(state, row_values)
            return True

    if state.role in {FeatureRole.NUMERIC, FeatureRole.BOOLEAN}:
        ok = _transform_numeric_state(
            state,
            value,
            row_values,
            options,
            issues,
            index,
            missing,
        )
    elif state.role == FeatureRole.CATEGORICAL:
        ok = _transform_categorical_state(
            state,
            value,
            row_values,
            options,
            issues,
            index,
            missing,
        )
    elif state.role == FeatureRole.SET:
        ok = _transform_set_state(
            state,
            value,
            row_values,
            options,
            issues,
            index,
            missing,
        )
    elif state.role == FeatureRole.VECTOR:
        ok = _transform_vector_state(
            state,
            value,
            row_values,
            options,
            issues,
            index,
            missing,
        )
    elif state.role == FeatureRole.DATETIME:
        ok = _transform_datetime_state(
            state,
            value,
            row_values,
            options,
            issues,
            index,
            missing,
        )
    else:
        ok = _transform_categorical_state(
            state,
            value,
            row_values,
            options,
            issues,
            index,
            missing,
        )

    if ok:
        _finalize_state_output(state, row_values)

    return ok


# -----------------------------------------------------------------------------
# State summaries and fingerprints
# -----------------------------------------------------------------------------


def _enum_or_none(value: Any) -> Optional[str]:
    """
    Return safe enum value or None.
    """
    if value is None:
        return None

    if isinstance(value, Enum):
        return str(value.value)

    return _clean_text(value, 100)


def _config_safe_summary(config: FeatureTransformConfig) -> dict[str, Any]:
    """
    Return safe per-feature config summary.
    """
    return {
        "role": _enum_or_none(config.role),
        "missing_policy": _enum_or_none(config.missing_policy),
        "outlier_policy": _enum_or_none(config.outlier_policy),
        "scaling_method": _enum_or_none(config.scaling_method),
        "encoding_method": _enum_or_none(config.encoding_method),
        "set_encoding_method": _enum_or_none(config.set_encoding_method),
        "vector_scaling_method": _enum_or_none(config.vector_scaling_method),
        "datetime_mode": _enum_or_none(config.datetime_mode),
        "log1p": config.log1p,
        "clip_min": _round6(config.clip_min) if config.clip_min is not None else None,
        "clip_max": _round6(config.clip_max) if config.clip_max is not None else None,
        "constant_fill": (
            _round6(config.constant_fill) if config.constant_fill is not None else None
        ),
        "max_categories": config.max_categories,
        "hash_dim": config.hash_dim,
        "selected": config.selected,
        "weight": _round6(config.weight),
    }


def _state_safe_summary(state: ColumnState) -> dict[str, Any]:
    """
    Return safe fitted-state summary.

    This never exposes raw category values, raw set elements, feature values,
    subject hashes, or salt.
    """
    cardinality: Optional[int] = None

    if state.role == FeatureRole.CATEGORICAL:
        cardinality = len(state.category_freq)
    elif state.role == FeatureRole.SET:
        cardinality = len(state.element_freq)
    elif state.role == FeatureRole.VECTOR:
        cardinality = state.vector_dim

    return {
        "name": state.name,
        "role": state.role.value,
        "selected": bool(state.selected),
        "fitted": bool(state.fitted),
        "coverage": _round6(state.coverage),
        "total_count": int(state.total_count),
        "missing_count": int(state.missing_count),
        "nonmissing_count": int(state.nonmissing_count),
        "selection_score": _round6(state.selection_score),
        "output_column_count": len(state.output_columns),
        "missing_indicator_column": state.missing_indicator_column,
        "cardinality": cardinality,
        "config": _config_safe_summary(state.config),
    }


def _matrix_fingerprint(
    feature_names: Sequence[str],
    rows: Sequence[PreprocessedRow],
    options: PreprocessOptions,
) -> str:
    """
    Return deterministic matrix fingerprint.

    The fingerprint commits to output column order and rounded row values. It
    does not expose values directly.
    """
    digest = hashlib.sha256()

    digest.update(
        f"muleguard.ml.preprocessing.matrix.{PREPROCESSING_VERSION}|{options.namespace}|{len(feature_names)}|{len(rows)}".encode(
            "utf-8",
            errors="replace",
        )
    )

    columns = list(feature_names)

    for column in columns:
        digest.update(_clean_text(column, 300).encode("utf-8", errors="replace"))
        digest.update(b"\x00")

    digest.update(b"\n")

    for row in rows:
        for column in columns:
            value = row.values.get(column, 0.0)
            digest.update(f"{float(value):.6f}\x00".encode("utf-8", errors="replace"))

        digest.update(b"\n")

    return digest.hexdigest()


def _empty_preprocessed_matrix(
    options: PreprocessOptions,
    stage: PreprocessingStage,
    issues: Sequence[PreprocessingIssue],
    feature_names: Sequence[str] = (),
    metadata: Optional[Mapping[str, Any]] = None,
) -> PreprocessedMatrix:
    """
    Return a safe empty preprocessing matrix.
    """
    payload: dict[str, Any] = {
        "preprocessing_version": PREPROCESSING_VERSION,
        "options": options.safe_summary(),
        "max_summary_items": options.max_summary_items,
        "empty_matrix": True,
        "caveats": list(_PREPROCESSING_CAVEATS),
        "safety_flags": dict(_PREPROCESSING_SAFETY_FLAGS),
    }

    if metadata:
        payload.update(_safe_detail_value(metadata) or {})

    ok = not any(issue.severity == IssueSeverity.ERROR for issue in issues)

    return PreprocessedMatrix(
        ok=ok,
        stage=stage,
        feature_names=tuple(feature_names),
        rows=(),
        counts={
            "submitted": 0,
            "processed": 0,
            "accepted": 0,
            "rejected": 0,
            "rows": 0,
            "output_features": len(feature_names),
        },
        issues=tuple(issues),
        metadata=payload,
        fingerprint=_matrix_fingerprint(tuple(feature_names), (), options),
    )


# -----------------------------------------------------------------------------
# Preprocessor
# -----------------------------------------------------------------------------


class Preprocessor:
    """
    Bounded, deterministic, leakage-aware ML preprocessor.

    The preprocessor learns fitted state from training-like data and applies the
    same transformation to validation, test, or inference data. Fitted state is
    internal-facing and must not be exposed through public APIs without review.
    """

    def __init__(
        self,
        options: PreprocessOptions | None = None,
        *,
        all_states: Sequence[ColumnState] | None = None,
        selected_states: Sequence[ColumnState] | None = None,
        feature_names: Sequence[str] | None = None,
        fitted: bool = False,
        issues: Sequence[PreprocessingIssue] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.options = options or PreprocessOptions.from_settings()
        self.all_states: tuple[ColumnState, ...] = tuple(all_states or ())
        self.selected_states: tuple[ColumnState, ...] = tuple(selected_states or ())
        self.feature_names: tuple[str, ...] = tuple(feature_names or ())
        self.fitted: bool = bool(fitted)
        self.issues: tuple[PreprocessingIssue, ...] = tuple(issues or ())
        self.metadata: dict[str, Any] = dict(metadata or {})

    # ------------------------------------------------------------------
    # Fit
    # ------------------------------------------------------------------

    def fit(self, data: Any) -> "Preprocessor":
        """
        Fit preprocessing state from bounded synthetic feature data.
        """
        opts = self.options
        issues: list[PreprocessingIssue] = []

        all_records = _iter_input_records(data)
        submitted = len(all_records)

        if submitted > opts.max_samples:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="fit_sample_truncated",
                message="Fit input exceeded configured sample limit and was truncated.",
                details={
                    "submitted": submitted,
                    "max_samples": opts.max_samples,
                },
            )
            records = all_records[: opts.max_samples]
        else:
            records = all_records

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="preprocessing_disabled",
                message="Preprocessing is disabled.",
            )
            self.all_states = ()
            self.selected_states = ()
            self.feature_names = ()
            self.fitted = True
            self.issues = tuple(issues)
            self.metadata = {
                "preprocessing_version": PREPROCESSING_VERSION,
                "options": opts.safe_summary(),
                "fitted": True,
                "disabled": True,
                "submitted": submitted,
                "processed": len(records),
                "input_feature_count": 0,
                "selected_feature_count": 0,
                "output_feature_count": 0,
                "caveats": list(_PREPROCESSING_CAVEATS),
                "safety_flags": dict(_PREPROCESSING_SAFETY_FLAGS),
            }
            return self

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Preprocessing requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            self.all_states = ()
            self.selected_states = ()
            self.feature_names = ()
            self.fitted = True
            self.issues = tuple(issues)
            self.metadata = {
                "preprocessing_version": PREPROCESSING_VERSION,
                "options": opts.safe_summary(),
                "fitted": True,
                "invalid": True,
                "submitted": submitted,
                "processed": len(records),
                "input_feature_count": 0,
                "selected_feature_count": 0,
                "output_feature_count": 0,
                "caveats": list(_PREPROCESSING_CAVEATS),
                "safety_flags": dict(_PREPROCESSING_SAFETY_FLAGS),
            }
            return self

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Preprocessing is blocked in production-like environments.",
            )
            self.all_states = ()
            self.selected_states = ()
            self.feature_names = ()
            self.fitted = True
            self.issues = tuple(issues)
            self.metadata = {
                "preprocessing_version": PREPROCESSING_VERSION,
                "options": opts.safe_summary(),
                "fitted": True,
                "invalid": True,
                "submitted": submitted,
                "processed": len(records),
                "input_feature_count": 0,
                "selected_feature_count": 0,
                "output_feature_count": 0,
                "caveats": list(_PREPROCESSING_CAVEATS),
                "safety_flags": dict(_PREPROCESSING_SAFETY_FLAGS),
            }
            return self

        sample_cap = max(
            10,
            min(
                opts.max_samples,
                opts.max_rank_samples,
                1_000,
            ),
        )

        samples: dict[str, list[Any]] = {}
        counts: dict[str, int] = {}

        for index, record in enumerate(records):
            _subject, features = _extract_row(record)
            normalized = _normalize_feature_keys(
                features,
                opts,
                issues,
                index,
                known_names=None,
            )

            if normalized is None:
                continue

            for name, value in normalized.items():
                counts[name] = counts.get(name, 0) + 1
                bucket = samples.setdefault(name, [])

                if len(bucket) < sample_cap:
                    bucket.append(value)

        states: list[ColumnState] = []

        for name in sorted(samples):
            sampled_values = samples[name]
            inferred_role = _infer_role(sampled_values)
            config = _resolve_config(opts, name, inferred_role)
            role = config.role or inferred_role

            state = ColumnState(
                name=name,
                role=role,
                config=config,
            )

            _fit_state(state, sampled_values, opts)
            states.append(state)

        if not states:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="no_fit_features",
                message="No valid feature columns were available for fitting.",
                details={"submitted": submitted, "processed": len(records)},
            )

        selected = _select_features(states, opts, issues)
        feature_names = _build_output_columns(selected)

        self.all_states = tuple(states)
        self.selected_states = tuple(selected)
        self.feature_names = tuple(feature_names)
        self.fitted = True
        self.issues = tuple(issues)

        state_summaries = [
            _state_safe_summary(state)
            for state in selected[: opts.max_summary_items]
        ]

        self.metadata = {
            "preprocessing_version": PREPROCESSING_VERSION,
            "options": opts.safe_summary(),
            "fitted": True,
            "submitted": submitted,
            "processed": len(records),
            "input_feature_count": len(states),
            "selected_feature_count": len(selected),
            "output_feature_count": len(feature_names),
            "sample_cap": sample_cap,
            "state_summaries": state_summaries,
            "state_summary_truncated": len(selected) > opts.max_summary_items,
            "column_counts": {
                name: int(count)
                for name, count in sorted(counts.items())[: opts.max_summary_items]
            },
            "column_counts_truncated": len(counts) > opts.max_summary_items,
            "caveats": list(_PREPROCESSING_CAVEATS),
            "safety_flags": dict(_PREPROCESSING_SAFETY_FLAGS),
        }

        return self

    # ------------------------------------------------------------------
    # Transform
    # ------------------------------------------------------------------

    def transform(
        self,
        data: Any,
        stage: PreprocessingStage | str = PreprocessingStage.TRANSFORM,
    ) -> PreprocessedMatrix:
        """
        Transform bounded synthetic feature data into a preprocessed matrix.
        """
        opts = self.options
        resolved_stage = _normalize_enum_option(stage, PreprocessingStage, PreprocessingStage.TRANSFORM)
        issues: list[PreprocessingIssue] = []

        if not self.fitted:
            raise ConfigurationError(
                "Preprocessor must be fitted before transform.",
                details={"hint": "Use fit_transform_features() or call fit() first."},
            )

        all_records = _iter_input_records(data)
        submitted = len(all_records)

        if submitted > opts.max_samples:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="transform_sample_truncated",
                message="Transform input exceeded configured sample limit and was truncated.",
                details={
                    "submitted": submitted,
                    "max_samples": opts.max_samples,
                },
            )
            records = all_records[: opts.max_samples]
        else:
            records = all_records

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="preprocessing_disabled",
                message="Preprocessing is disabled.",
            )
            return _empty_preprocessed_matrix(
                opts,
                resolved_stage,
                issues,
                self.feature_names,
                self.metadata,
            )

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Preprocessing requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return _empty_preprocessed_matrix(
                opts,
                resolved_stage,
                issues,
                self.feature_names,
                self.metadata,
            )

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Preprocessing is blocked in production-like environments.",
            )
            return _empty_preprocessed_matrix(
                opts,
                resolved_stage,
                issues,
                self.feature_names,
                self.metadata,
            )

        known_names = {state.name for state in self.all_states}
        rows: list[PreprocessedRow] = []
        accepted = 0
        rejected = 0

        for index, record in enumerate(records):
            subject, features = _extract_row(record)
            normalized = _normalize_feature_keys(
                features,
                opts,
                issues,
                index,
                known_names=known_names,
            )

            if normalized is None:
                rejected += 1
                continue

            row_values: dict[str, float] = {}
            row_invalid = False

            try:
                for state in self.selected_states:
                    value = normalized.get(state.name, _MISSING)
                    ok = _transform_state(
                        state,
                        value,
                        row_values,
                        opts,
                        issues,
                        index,
                    )

                    if not ok:
                        row_invalid = True
                        break
            except Exception as exc:
                row_invalid = True
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="transform_failed",
                    message="Feature transformation failed for row.",
                    details={
                        "index": index,
                        "exception_type": type(exc).__name__,
                    },
                )

            if row_invalid:
                rejected += 1
                continue

            for column in self.feature_names:
                row_values.setdefault(column, 0.0)

            row_values = {
                column: _round6(float(row_values.get(column, 0.0)))
                for column in self.feature_names
            }

            rows.append(
                PreprocessedRow(
                    subject_ref_hash=subject,
                    values=row_values,
                    metadata={
                        "index": index,
                        "feature_count": len(row_values),
                    },
                )
            )

            accepted += 1

        counts = {
            "submitted": submitted,
            "processed": len(records),
            "accepted": accepted,
            "rejected": rejected,
            "rows": len(rows),
            "output_features": len(self.feature_names),
        }

        ok = not any(issue.severity == IssueSeverity.ERROR for issue in issues)

        metadata = dict(self.metadata)
        metadata.update(
            {
                "stage": resolved_stage.value,
                "counts": counts,
                "transform_issues": [issue.to_dict() for issue in issues[: opts.max_issues]],
                "transform_issue_count": len(issues),
                "caveats": list(_PREPROCESSING_CAVEATS),
                "safety_flags": dict(_PREPROCESSING_SAFETY_FLAGS),
            }
        )

        return PreprocessedMatrix(
            ok=ok,
            stage=resolved_stage,
            feature_names=self.feature_names,
            rows=tuple(rows),
            counts=counts,
            issues=tuple(issues),
            metadata=metadata,
            fingerprint=_matrix_fingerprint(self.feature_names, rows, opts),
        )

    # ------------------------------------------------------------------
    # Fit + transform
    # ------------------------------------------------------------------

    def fit_transform(self, data: Any) -> PreprocessedMatrix:
        """
        Fit and transform in one pass over materialized records.
        """
        records = _iter_input_records(data)
        self.fit(records)
        return self.transform(
            records,
            stage=PreprocessingStage.FIT_TRANSFORM,
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe preprocessor summary.

        This does not include feature values, subject hashes, raw categories,
        raw set elements, or salt.
        """
        return {
            "fitted": self.fitted,
            "options": self.options.safe_summary(),
            "input_feature_count": len(self.all_states),
            "selected_feature_count": len(self.selected_states),
            "output_feature_count": len(self.feature_names),
            "feature_names_sample": list(self.feature_names[: self.options.max_summary_items]),
            "feature_names_truncated": len(self.feature_names) > self.options.max_summary_items,
            "state_summaries": [
                _state_safe_summary(state)
                for state in self.selected_states[: self.options.max_summary_items]
            ],
            "state_summary_truncated": len(self.selected_states) > self.options.max_summary_items,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_PREPROCESSING_CAVEATS),
            "safety_flags": dict(_PREPROCESSING_SAFETY_FLAGS),
        }

    def output_columns(self) -> tuple[str, ...]:
        """
        Return fitted output column names.
        """
        return self.feature_names

    def fingerprint(self) -> str:
        """
        Return deterministic preprocessor fingerprint.
        """
        payload = {
            "version": PREPROCESSING_VERSION,
            "options": self.options.safe_summary(),
            "feature_names": list(self.feature_names),
            "states": [
                {
                    "name": state.name,
                    "role": state.role.value,
                    "selected": state.selected,
                    "output_columns": list(state.output_columns),
                    "config": _config_safe_summary(state.config),
                    "coverage": _round6(state.coverage),
                    "cardinality": (
                        len(state.category_freq)
                        if state.role == FeatureRole.CATEGORICAL
                        else len(state.element_freq)
                        if state.role == FeatureRole.SET
                        else state.vector_dim
                        if state.role == FeatureRole.VECTOR
                        else None
                    ),
                }
                for state in self.selected_states
            ],
        }

        try:
            return _sha256_hex(_canonical_json(payload))
        except Exception:
            return _sha256_hex(str(len(self.feature_names)))


# -----------------------------------------------------------------------------
# Default preprocessor and public API
# -----------------------------------------------------------------------------


_default_preprocessor: Optional[Preprocessor] = None
_default_preprocessor_lock = threading.Lock()


def get_preprocessor(
    options: PreprocessOptions | None = None,
    *,
    rebuild: bool = False,
) -> Preprocessor:
    """
    Return a process-wide preprocessor.

    If options are supplied or rebuild is True, a new preprocessor is created
    and becomes the default.
    """
    global _default_preprocessor

    with _default_preprocessor_lock:
        if _default_preprocessor is None or rebuild or options is not None:
            _default_preprocessor = Preprocessor(options=options)

        return _default_preprocessor


def fit_preprocessor(
    data: Any,
    options: PreprocessOptions | None = None,
    *,
    preprocessor: Preprocessor | None = None,
) -> Preprocessor:
    """
    Fit a preprocessor from bounded synthetic feature data.
    """
    proc = preprocessor or get_preprocessor(options)
    records = _iter_input_records(data)
    return proc.fit(records)


def transform_features(
    data: Any,
    preprocessor: Preprocessor | None = None,
    options: PreprocessOptions | None = None,
    *,
    stage: PreprocessingStage | str = PreprocessingStage.TRANSFORM,
) -> PreprocessedMatrix:
    """
    Transform bounded synthetic feature data using a fitted preprocessor.

    If the selected preprocessor is not fitted, this helper fits it first using
    the supplied data. For strict train/test separation, callers should fit on
    training data only and then call transform on validation/test data.
    """
    proc = preprocessor or get_preprocessor(options)
    records = _iter_input_records(data)

    if not proc.fitted:
        proc.fit(records)

    return proc.transform(records, stage=stage)


def fit_transform_features(
    data: Any,
    options: PreprocessOptions | None = None,
    *,
    preprocessor: Preprocessor | None = None,
) -> PreprocessedMatrix:
    """
    Fit and transform bounded synthetic feature data in one call.

    This is convenient for tests, prototypes, and offline fixtures. For real
    model development, fit on training data only and transform validation/test
    data separately.
    """
    proc = preprocessor or get_preprocessor(options)
    records = _iter_input_records(data)
    return proc.fit_transform(records)


def preprocess_features(
    data: Any,
    options: PreprocessOptions | None = None,
    *,
    preprocessor: Preprocessor | None = None,
) -> PreprocessedMatrix:
    """
    Convenience alias for fit_transform_features.
    """
    return fit_transform_features(
        data,
        options=options,
        preprocessor=preprocessor,
    )


def preprocess_feature_vectors(
    feature_vectors: Any,
    options: PreprocessOptions | None = None,
    *,
    preprocessor: Preprocessor | None = None,
) -> PreprocessedMatrix:
    """
    Preprocess feature-vector-like objects.

    This accepts FeatureVector objects, mappings with `features`, or sequences
    of such objects.
    """
    records: list[Any] = []

    for vector in _iter_input_records(feature_vectors):
        if isinstance(vector, Mapping):
            if "features" in vector and isinstance(vector["features"], Mapping):
                record = dict(vector["features"])

                for key in _SUBJECT_KEYS:
                    if key in vector:
                        record[key] = vector[key]
                        break

                records.append(record)
            else:
                records.append(vector)
        else:
            features = getattr(vector, "features", None)

            if isinstance(features, Mapping):
                record = dict(features)

                for key in _SUBJECT_KEYS:
                    value = getattr(vector, key, None)

                    if value is not None:
                        record[key] = value
                        break

                records.append(record)
            else:
                records.append(vector)

    return fit_transform_features(
        records,
        options=options,
        preprocessor=preprocessor,
    )


def matrix_to_numeric_rows(
    matrix: PreprocessedMatrix,
) -> list[list[float]]:
    """
    Return internal numeric rows from a preprocessed matrix.

    This is internal-facing and must not be exposed publicly without review.
    """
    columns = list(matrix.feature_names)

    return [
        [float(row.values.get(column, 0.0)) for column in columns]
        for row in matrix.rows
    ]


def matrix_subjects(
    matrix: PreprocessedMatrix,
) -> list[Optional[str]]:
    """
    Return internal subject references from a preprocessed matrix.

    This is internal-facing and must not be exposed publicly without review.
    """
    return [row.subject_ref_hash for row in matrix.rows]


def matrix_feature_names(
    matrix: PreprocessedMatrix,
) -> tuple[str, ...]:
    """
    Return preprocessed output feature names.
    """
    return matrix.feature_names


def summarize_preprocessed_matrix(
    matrix: PreprocessedMatrix,
) -> dict[str, Any]:
    """
    Return a safe API-facing matrix summary.
    """
    return matrix.to_response_dict()


def get_preprocessing_metadata() -> dict[str, Any]:
    """
    Return safe, serializable ML preprocessing metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, feature values, subject-label pairs,
    or real customer data.
    """
    options = PreprocessOptions.from_settings()

    return {
        "package": "muleguard.backend.ml.preprocessing",
        "version": PREPROCESSING_VERSION,
        "stages": [stage.value for stage in PreprocessingStage],
        "missing_policies": [policy.value for policy in MissingPolicy],
        "outlier_policies": [policy.value for policy in OutlierPolicy],
        "scaling_methods": [method.value for method in ScalingMethod],
        "encoding_methods": [method.value for method in EncodingMethod],
        "set_encoding_methods": [method.value for method in SetEncodingMethod],
        "vector_scaling_methods": [method.value for method in VectorScalingMethod],
        "datetime_feature_modes": [mode.value for mode in DatetimeFeatureMode],
        "feature_roles": [role.value for role in FeatureRole],
        "feature_selection_methods": [method.value for method in FeatureSelectionMethod],
        "unknown_field_policies": [policy.value for policy in UnknownFieldPolicy],
        "default_options": options.safe_summary(),
        "builder_backend": "in_memory_deterministic",
        "distributed": False,
        "durable": False,
        "hard_limits": {
            "max_samples": _HARD_MAX_SAMPLES,
            "max_features": _HARD_MAX_FEATURES,
            "max_categories": _HARD_MAX_CATEGORIES,
            "max_set_items": _HARD_MAX_SET_ITEMS,
            "max_vector_dim": _HARD_MAX_VECTOR_DIM,
            "hash_dim": _HARD_MAX_HASH_DIM,
            "max_rank_samples": _HARD_MAX_RANK_SAMPLES,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
        },
        "forbidden_preprocess_field_count": len(_FORBIDDEN_PREPROCESS_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_PREPROCESSING_CAVEATS),
        "safety_flags": dict(_PREPROCESSING_SAFETY_FLAGS),
    }


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "ColumnState",
    "DatetimeFeatureMode",
    "EncodingMethod",
    "FeatureRole",
    "FeatureSelectionMethod",
    "FeatureTransformConfig",
    "MissingPolicy",
    "OutlierPolicy",
    "PreprocessOptions",
    "PreprocessedMatrix",
    "PreprocessedRow",
    "PreprocessingIssue",
    "PreprocessingStage",
    "Preprocessor",
    "ScalingMethod",
    "SetEncodingMethod",
    "UnknownFieldPolicy",
    "VectorScalingMethod",
    "fit_preprocessor",
    "fit_transform_features",
    "get_preprocessing_metadata",
    "get_preprocessor",
    "matrix_feature_names",
    "matrix_subjects",
    "matrix_to_numeric_rows",
    "preprocess_feature_vectors",
    "preprocess_features",
    "summarize_preprocessed_matrix",
    "transform_features",
]