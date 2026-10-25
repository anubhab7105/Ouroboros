"""
MULEGUARD backend supervised ML.

This module provides the canonical bounded supervised learning layer for the
synthetic MULEGUARD machine-learning subsystem.

Primary responsibilities:

- train deterministic synthetic supervised models from preprocessed numeric
  feature matrices and internal synthetic label fixtures;
- support binary and multiclass classification using logistic regression and
  softmax regression, with bounded baseline priors;
- enforce strict train/validation/test isolation and leakage-aware calibration;
- provide bounded regularization, class weighting, early stopping, time
  budgets, deterministic optimization, and safe model fingerprints;
- evaluate models with honest, bounded metrics including accuracy, precision,
  recall, F1, ROC AUC, PR AUC, log loss, Brier score, expected calibration
  error, and confusion matrices;
- produce investigative prediction records with bounded feature contributions;
- reject leakage-prone inputs such as ground-truth labels, injected scenario
  IDs, fraud-ring IDs, raw complaint narratives, raw identifiers, secrets,
  tokens, passwords, database URLs, filesystem paths, and model artifact paths;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values, subject-label pairs, and sensitive metadata from
  public summaries;
- remain import-safe, dependency-light, and usable by ML services, training
  harnesses, evaluation harnesses, tests, seeders, offline fixtures, and
  developer tooling.

This module trains and evaluates synthetic supervised models only. It does not
persist data, call external systems, authenticate users, authorize actions,
deploy models, promote models, retire models, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for training, evaluation, or inference.
- Synthetic labels are evaluation fixtures only. They are not proof of
  wrongdoing.
- Labels must never be used as features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden. Subject linkage is pseudonymous and salted.
- Model probabilities are investigative prioritization scores only. They are
  not probabilities of guilt.
- Heuristic or calibrated scores are not adjudications.
- Feature contributions are operational attributions only. They are not causal
  proof.
- Supervised outputs are investigative leads only.
- Supervised handling never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable metrics are reported honestly as unavailable rather
  than invented.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external model runtimes.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable model registry. The bundled registry is
  process-local, non-durable, and bounded for local prototype use only.

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
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError

logger = logging.getLogger("muleguard.backend.ml.supervised")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

SUPERVISED_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.supervised.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_SAMPLES: Final[int] = 5_000
_HARD_MAX_SAMPLES: Final[int] = 100_000

_DEFAULT_MAX_FEATURES: Final[int] = 256
_HARD_MAX_FEATURES: Final[int] = 4_096

_DEFAULT_MAX_CELLS: Final[int] = 2_000_000
_HARD_MAX_CELLS: Final[int] = 50_000_000

_DEFAULT_MAX_CLASSES: Final[int] = 8
_HARD_MAX_CLASSES: Final[int] = 128

_DEFAULT_MAX_ITERATIONS: Final[int] = 80
_HARD_MAX_ITERATIONS: Final[int] = 5_000

_DEFAULT_BATCH_SIZE: Final[int] = 128
_HARD_MAX_BATCH_SIZE: Final[int] = 4_096

_DEFAULT_MAX_MINIBATCH_STEPS: Final[int] = 10_000
_HARD_MAX_MINIBATCH_STEPS: Final[int] = 1_000_000

_DEFAULT_LEARNING_RATE: Final[float] = 0.05
_DEFAULT_MIN_LEARNING_RATE: Final[float] = 1e-6

_DEFAULT_REG_STRENGTH: Final[float] = 1e-4
_DEFAULT_L1_RATIO: Final[float] = 0.0

_DEFAULT_EARLY_STOPPING_PATIENCE: Final[int] = 8
_DEFAULT_MIN_DELTA: Final[float] = 1e-5

_DEFAULT_MAX_TIME_MS: Final[int] = 15_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_DEFAULT_THRESHOLD: Final[float] = 0.5
_DEFAULT_ECE_BINS: Final[int] = 10
_DEFAULT_MAX_HISTORY: Final[int] = 250
_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500
_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500
_DEFAULT_MAX_EXPLANATIONS: Final[int] = 20
_HARD_MAX_EXPLANATIONS: Final[int] = 500
_DEFAULT_MAX_CLASS_WEIGHT: Final[float] = 100.0
_DEFAULT_INTERNAL_VALIDATION_FRACTION: Final[float] = 0.15

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256
_MAX_WEIGHT: Final[float] = 100.0

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

_FORBIDDEN_SUPERVISED_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_SUPERVISED_TOKENS: Final[tuple[str, ...]] = (
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

_LOCAL_LABEL_CODES: Final[Mapping[str, int]] = MappingProxyType(
    {
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
)

_LOCAL_LABEL_NAMES: Final[Mapping[int, str]] = MappingProxyType(
    {
        0: "unknown",
        1: "no_action",
        2: "review",
        3: "escalate",
        4: "uncertain",
    }
)

_SUPERVISED_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic supervised ML only. Do not use with real customer data.",
    "Model probabilities are investigative prioritization scores, not probabilities of guilt.",
    "Feature contributions are operational attributions only and are not causal proof.",
    "Supervised outputs are investigative leads only and must not trigger automatic adverse customer action.",
    "Labels must never be used as features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Calibration is bounded and uses validation data only when available.",
    "Unavailable metrics are reported honestly as unavailable rather than invented.",
    "The bundled model registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_SUPERVISED_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_training": True,
        "bounded_supervised_required": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class TaskType(str, Enum):
    """
    Supervised task type.
    """

    BINARY = "binary"
    MULTICLASS = "multiclass"


class ModelFamily(str, Enum):
    """
    Supported bounded model families.
    """

    BASELINE_PRIOR = "baseline_prior"
    LOGISTIC_REGRESSION = "logistic_regression"
    SOFTMAX_REGRESSION = "softmax_regression"


class Optimizer(str, Enum):
    """
    Supported optimizers.
    """

    SGD = "sgd"
    ADAM = "adam"


class Regularization(str, Enum):
    """
    Supported regularization modes.
    """

    NONE = "none"
    L1 = "l1"
    L2 = "l2"
    ELASTIC_NET = "elastic_net"


class CalibrationMethod(str, Enum):
    """
    Supported calibration methods.
    """

    NONE = "none"
    PLATT = "platt"
    TEMPERATURE = "temperature"


class SplitName(str, Enum):
    """
    Canonical split names.
    """

    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


class ModelStatus(str, Enum):
    """
    Model lifecycle status.

    Status changes are operational metadata only. This module does not promote,
    deploy, or retire models.
    """

    DRAFT = "DRAFT"
    TRAINED = "TRAINED"
    EVALUATED = "EVALUATED"
    CANDIDATE = "CANDIDATE"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


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
    Return True when a key is forbidden for supervised inputs.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_SUPERVISED_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_SUPERVISED_TOKENS)


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


def _coerce_float(value: Any, *, allow_bool: bool = True) -> Optional[float]:
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


def _coerce_int_label(value: Any) -> Optional[int]:
    """
    Coerce a label-like value to an integer code.
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return int(value)

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        if not float(value).is_integer():
            return None
        return int(value)

    if isinstance(value, Decimal):
        if not value.is_finite():
            return None
        if value != value.to_integral_value():
            return None
        return int(value)

    token = _normalize_token(value)

    if not token:
        return None

    if token in _LOCAL_LABEL_CODES:
        return int(_LOCAL_LABEL_CODES[token])

    try:
        return int(token)
    except (TypeError, ValueError):
        return None


def _label_name(code: Any) -> str:
    """
    Return a safe label name for a code.
    """
    try:
        resolved = int(code)
    except (TypeError, ValueError):
        return "unknown"

    return _LOCAL_LABEL_NAMES.get(resolved, f"label_{resolved}")


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


def _normalize_split_name(value: Any) -> str:
    """
    Normalize a split-like value.
    """
    token = _normalize_token(value)

    aliases = {
        "train": SplitName.TRAIN.value,
        "training": SplitName.TRAIN.value,
        "validation": SplitName.VALIDATION.value,
        "valid": SplitName.VALIDATION.value,
        "val": SplitName.VALIDATION.value,
        "test": SplitName.TEST.value,
        "holdout": SplitName.TEST.value,
    }

    return aliases.get(token, SplitName.TRAIN.value)


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
    Ensure the supervised salt is non-empty and sufficiently long.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _subject_hash(value: Any, options: "SupervisedOptions") -> Optional[str]:
    """
    Return a salted, domain-separated pseudonymous subject hash.
    """
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.supervised.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _sigmoid(value: float) -> float:
    """
    Numerically stable sigmoid.
    """
    if value >= 0:
        z = math.exp(-value)
        result = 1.0 / (1.0 + z)
    else:
        z = math.exp(value)
        result = z / (1.0 + z)

    return _clip_float(result, 1e-12, 1.0 - 1e-12, 0.5)


def _softmax(values: Sequence[float]) -> tuple[float, ...]:
    """
    Numerically stable softmax.
    """
    if not values:
        return ()

    max_value = max(float(value) for value in values)

    if math.isnan(max_value) or math.isinf(max_value):
        return tuple(1.0 / float(len(values)) for _ in values)

    exps = []

    for value in values:
        numeric = float(value)

        if math.isnan(numeric) or math.isinf(numeric):
            numeric = max_value

        exps.append(math.exp(numeric - max_value))

    total = sum(exps)

    if total <= 0 or not math.isfinite(total):
        return tuple(1.0 / float(len(values)) for _ in values)

    return tuple(_clip_float(value / total, 0.0, 1.0, 0.0) for value in exps)


def _logit(probability: float) -> float:
    """
    Return logit for a clipped probability.
    """
    p = _clip_float(probability, 1e-12, 1.0 - 1e-12, 0.5)
    return math.log(p / (1.0 - p))


def _dot(weights: Sequence[float], x: Sequence[float]) -> float:
    """
    Return dot product with bounded safety.
    """
    total = 0.0

    for left, right in zip(weights, x):
        try:
            total += float(left) * float(right)
        except (TypeError, ValueError):
            continue

    if math.isnan(total) or math.isinf(total):
        return 0.0

    return total


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


def _append_issue(
    issues: list["SupervisedIssue"],
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

        issues[-1] = SupervisedIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        SupervisedIssue(
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
class SupervisedOptions:
    """
    Bounded supervised learning policy.

    Hard caps prevent accidental unbounded training, evaluation, or inference
    surfaces.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    task: TaskType | str | None = None
    model_family: ModelFamily | str | None = None

    optimizer: Optimizer | str = Optimizer.ADAM
    regularization: Regularization | str = Regularization.L2
    reg_strength: float = _DEFAULT_REG_STRENGTH
    l1_ratio: float = _DEFAULT_L1_RATIO

    learning_rate: float = _DEFAULT_LEARNING_RATE
    min_learning_rate: float = _DEFAULT_MIN_LEARNING_RATE
    max_iterations: int = _DEFAULT_MAX_ITERATIONS
    batch_size: int = _DEFAULT_BATCH_SIZE
    max_minibatch_steps: int = _DEFAULT_MAX_MINIBATCH_STEPS

    momentum: float = 0.9
    beta1: float = 0.9
    beta2: float = 0.999
    epsilon: float = 1e-8

    balance_classes: bool = True
    max_class_weight: float = _DEFAULT_MAX_CLASS_WEIGHT
    threshold: float = _DEFAULT_THRESHOLD

    calibration_method: CalibrationMethod | str | None = None
    calibrate_on_validation: bool = True
    calibration_iterations: int = 50
    ece_bins: int = _DEFAULT_ECE_BINS

    early_stopping: bool = True
    patience: int = _DEFAULT_EARLY_STOPPING_PATIENCE
    min_delta: float = _DEFAULT_MIN_DELTA
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    internal_validation_fraction: float = _DEFAULT_INTERNAL_VALIDATION_FRACTION

    max_samples: int = _DEFAULT_MAX_SAMPLES
    max_features: int = _DEFAULT_MAX_FEATURES
    max_cells: int = _DEFAULT_MAX_CELLS
    max_classes: int = _DEFAULT_MAX_CLASSES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_history: int = _DEFAULT_MAX_HISTORY
    max_explanations: int = _DEFAULT_MAX_EXPLANATIONS

    drop_forbidden_fields: bool = False
    expose_coefficients: bool = False
    register_model: bool = True
    audit_material_actions: bool = True

    risk_thresholds: Mapping[str, float] = dataclass_field(
        default_factory=lambda: {
            "critical": 0.90,
            "high": 0.75,
            "medium": 0.50,
            "low": 0.25,
        }
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
            "task",
            _normalize_enum_option(TaskType, self.task, None),
        )
        object.__setattr__(
            self,
            "model_family",
            _normalize_enum_option(ModelFamily, self.model_family, None),
        )
        object.__setattr__(
            self,
            "optimizer",
            _normalize_enum_option(Optimizer, self.optimizer, Optimizer.ADAM),
        )
        object.__setattr__(
            self,
            "regularization",
            _normalize_enum_option(Regularization, self.regularization, Regularization.L2),
        )
        object.__setattr__(
            self,
            "calibration_method",
            _normalize_enum_option(CalibrationMethod, self.calibration_method, None),
        )

        object.__setattr__(
            self,
            "reg_strength",
            _clamp_float(self.reg_strength, 0.0, 10.0, _DEFAULT_REG_STRENGTH),
        )
        object.__setattr__(
            self,
            "l1_ratio",
            _clamp_float(self.l1_ratio, 0.0, 1.0, _DEFAULT_L1_RATIO),
        )
        object.__setattr__(
            self,
            "learning_rate",
            _clamp_float(self.learning_rate, 1e-8, 10.0, _DEFAULT_LEARNING_RATE),
        )
        object.__setattr__(
            self,
            "min_learning_rate",
            _clamp_float(self.min_learning_rate, 0.0, 1.0, _DEFAULT_MIN_LEARNING_RATE),
        )
        object.__setattr__(
            self,
            "max_iterations",
            _clamp_int(self.max_iterations, 0, _HARD_MAX_ITERATIONS, _DEFAULT_MAX_ITERATIONS),
        )
        object.__setattr__(
            self,
            "batch_size",
            _clamp_int(self.batch_size, 1, _HARD_MAX_BATCH_SIZE, _DEFAULT_BATCH_SIZE),
        )
        object.__setattr__(
            self,
            "max_minibatch_steps",
            _clamp_int(
                self.max_minibatch_steps,
                1,
                _HARD_MAX_MINIBATCH_STEPS,
                _DEFAULT_MAX_MINIBATCH_STEPS,
            ),
        )

        object.__setattr__(
            self,
            "momentum",
            _clamp_float(self.momentum, 0.0, 0.999, 0.9),
        )
        object.__setattr__(
            self,
            "beta1",
            _clamp_float(self.beta1, 0.0, 0.999, 0.9),
        )
        object.__setattr__(
            self,
            "beta2",
            _clamp_float(self.beta2, 0.0, 0.9999, 0.999),
        )
        object.__setattr__(
            self,
            "epsilon",
            max(1e-12, _as_float(self.epsilon, 1e-8)),
        )

        object.__setattr__(self, "balance_classes", _as_bool(self.balance_classes, True))
        object.__setattr__(
            self,
            "max_class_weight",
            _clamp_float(self.max_class_weight, 1.0, 1000.0, _DEFAULT_MAX_CLASS_WEIGHT),
        )
        object.__setattr__(
            self,
            "threshold",
            _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD),
        )

        object.__setattr__(self, "calibrate_on_validation", _as_bool(self.calibrate_on_validation, True))
        object.__setattr__(
            self,
            "calibration_iterations",
            _clamp_int(self.calibration_iterations, 1, 1_000, 50),
        )
        object.__setattr__(
            self,
            "ece_bins",
            _clamp_int(self.ece_bins, 2, 100, _DEFAULT_ECE_BINS),
        )

        object.__setattr__(self, "early_stopping", _as_bool(self.early_stopping, True))
        object.__setattr__(
            self,
            "patience",
            max(1, _as_int(self.patience, _DEFAULT_EARLY_STOPPING_PATIENCE)),
        )
        object.__setattr__(
            self,
            "min_delta",
            max(0.0, _as_float(self.min_delta, _DEFAULT_MIN_DELTA)),
        )
        object.__setattr__(
            self,
            "max_time_ms",
            _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS),
        )
        object.__setattr__(
            self,
            "internal_validation_fraction",
            _clamp_float(
                self.internal_validation_fraction,
                0.01,
                0.50,
                _DEFAULT_INTERNAL_VALIDATION_FRACTION,
            ),
        )

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
            "max_cells",
            _clamp_int(self.max_cells, 1_000, _HARD_MAX_CELLS, _DEFAULT_MAX_CELLS),
        )
        object.__setattr__(
            self,
            "max_classes",
            _clamp_int(self.max_classes, 2, _HARD_MAX_CLASSES, _DEFAULT_MAX_CLASSES),
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
            "max_history",
            _clamp_int(self.max_history, 1, 10_000, _DEFAULT_MAX_HISTORY),
        )
        object.__setattr__(
            self,
            "max_explanations",
            _clamp_int(
                self.max_explanations,
                1,
                _HARD_MAX_EXPLANATIONS,
                _DEFAULT_MAX_EXPLANATIONS,
            ),
        )

        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))
        object.__setattr__(self, "expose_coefficients", _as_bool(self.expose_coefficients, False))
        object.__setattr__(self, "register_model", _as_bool(self.register_model, True))
        object.__setattr__(self, "audit_material_actions", _as_bool(self.audit_material_actions, True))

        thresholds = dict(self.risk_thresholds or {})
        low = _clamp_float(thresholds.get("low", 0.25), 0.0, 1.0, 0.25)
        medium = max(low, _clamp_float(thresholds.get("medium", 0.50), 0.0, 1.0, 0.50))
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

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "SupervisedOptions":
        """
        Build supervised options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_SUPERVISED_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_SUPERVISED_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_SUPERVISED_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_SUPERVISED_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_SUPERVISED_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_SUPERVISED_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            task=_setting(settings, "ML_SUPERVISED_TASK", None),
            model_family=_setting(settings, "ML_SUPERVISED_MODEL_FAMILY", None),
            optimizer=str(_setting(settings, "ML_SUPERVISED_OPTIMIZER", Optimizer.ADAM.value)),
            regularization=str(
                _setting(settings, "ML_SUPERVISED_REGULARIZATION", Regularization.L2.value)
            ),
            reg_strength=_as_float(
                _setting(settings, "ML_SUPERVISED_REG_STRENGTH", _DEFAULT_REG_STRENGTH),
                _DEFAULT_REG_STRENGTH,
            ),
            l1_ratio=_as_float(
                _setting(settings, "ML_SUPERVISED_L1_RATIO", _DEFAULT_L1_RATIO),
                _DEFAULT_L1_RATIO,
            ),
            learning_rate=_as_float(
                _setting(settings, "ML_SUPERVISED_LEARNING_RATE", _DEFAULT_LEARNING_RATE),
                _DEFAULT_LEARNING_RATE,
            ),
            min_learning_rate=_as_float(
                _setting(settings, "ML_SUPERVISED_MIN_LEARNING_RATE", _DEFAULT_MIN_LEARNING_RATE),
                _DEFAULT_MIN_LEARNING_RATE,
            ),
            max_iterations=_as_int(
                _setting(settings, "ML_SUPERVISED_MAX_ITERATIONS", _DEFAULT_MAX_ITERATIONS),
                _DEFAULT_MAX_ITERATIONS,
            ),
            batch_size=_as_int(
                _setting(settings, "ML_SUPERVISED_BATCH_SIZE", _DEFAULT_BATCH_SIZE),
                _DEFAULT_BATCH_SIZE,
            ),
            max_minibatch_steps=_as_int(
                _setting(
                    settings,
                    "ML_SUPERVISED_MAX_MINIBATCH_STEPS",
                    _DEFAULT_MAX_MINIBATCH_STEPS,
                ),
                _DEFAULT_MAX_MINIBATCH_STEPS,
            ),
            balance_classes=_as_bool(
                _setting(settings, "ML_SUPERVISED_BALANCE_CLASSES", True),
                True,
            ),
            threshold=_as_float(
                _setting(settings, "ML_SUPERVISED_THRESHOLD", _DEFAULT_THRESHOLD),
                _DEFAULT_THRESHOLD,
            ),
            calibration_method=_setting(settings, "ML_SUPERVISED_CALIBRATION_METHOD", None),
            calibrate_on_validation=_as_bool(
                _setting(settings, "ML_SUPERVISED_CALIBRATE_ON_VALIDATION", True),
                True,
            ),
            early_stopping=_as_bool(
                _setting(settings, "ML_SUPERVISED_EARLY_STOPPING", True),
                True,
            ),
            patience=_as_int(
                _setting(settings, "ML_SUPERVISED_PATIENCE", _DEFAULT_EARLY_STOPPING_PATIENCE),
                _DEFAULT_EARLY_STOPPING_PATIENCE,
            ),
            max_time_ms=_as_int(
                _setting(settings, "ML_SUPERVISED_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS),
                _DEFAULT_MAX_TIME_MS,
            ),
            max_samples=_as_int(
                _setting(settings, "ML_SUPERVISED_MAX_SAMPLES", _DEFAULT_MAX_SAMPLES),
                _DEFAULT_MAX_SAMPLES,
            ),
            max_features=_as_int(
                _setting(settings, "ML_SUPERVISED_MAX_FEATURES", _DEFAULT_MAX_FEATURES),
                _DEFAULT_MAX_FEATURES,
            ),
            max_cells=_as_int(
                _setting(settings, "ML_SUPERVISED_MAX_CELLS", _DEFAULT_MAX_CELLS),
                _DEFAULT_MAX_CELLS,
            ),
            max_classes=_as_int(
                _setting(settings, "ML_SUPERVISED_MAX_CLASSES", _DEFAULT_MAX_CLASSES),
                _DEFAULT_MAX_CLASSES,
            ),
            max_issues=_as_int(
                _setting(settings, "ML_SUPERVISED_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_explanations=_as_int(
                _setting(settings, "ML_SUPERVISED_MAX_EXPLANATIONS", _DEFAULT_MAX_EXPLANATIONS),
                _DEFAULT_MAX_EXPLANATIONS,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ML_SUPERVISED_DROP_FORBIDDEN_FIELDS", False),
                False,
            ),
            expose_coefficients=_as_bool(
                _setting(settings, "ML_SUPERVISED_EXPOSE_COEFFICIENTS", False),
                False,
            ),
            register_model=_as_bool(
                _setting(settings, "ML_SUPERVISED_REGISTER_MODEL", True),
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
            "task": self.task.value if isinstance(self.task, TaskType) else "auto",
            "model_family": (
                self.model_family.value
                if isinstance(self.model_family, ModelFamily)
                else "auto"
            ),
            "optimizer": self.optimizer.value,
            "regularization": self.regularization.value,
            "reg_strength": round(self.reg_strength, 8),
            "l1_ratio": round(self.l1_ratio, 8),
            "learning_rate": round(self.learning_rate, 8),
            "max_iterations": self.max_iterations,
            "batch_size": self.batch_size,
            "max_minibatch_steps": self.max_minibatch_steps,
            "balance_classes": self.balance_classes,
            "threshold": round(self.threshold, 6),
            "calibration_method": (
                self.calibration_method.value
                if isinstance(self.calibration_method, CalibrationMethod)
                else "auto"
            ),
            "calibrate_on_validation": self.calibrate_on_validation,
            "early_stopping": self.early_stopping,
            "patience": self.patience,
            "max_time_ms": self.max_time_ms,
            "limits": {
                "max_samples": self.max_samples,
                "max_features": self.max_features,
                "max_cells": self.max_cells,
                "max_classes": self.max_classes,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_history": self.max_history,
                "max_explanations": self.max_explanations,
            },
            "risk_thresholds": dict(self.risk_thresholds),
            "flags": {
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "expose_coefficients": self.expose_coefficients,
                "register_model": self.register_model,
                "audit_material_actions": self.audit_material_actions,
            },
        }


# -----------------------------------------------------------------------------
# Issue and data models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SupervisedIssue:
    """
    Safe supervised issue.

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
class TrainingDataset:
    """
    Internal-facing bounded supervised training dataset.

    Public summaries must not expose X, y, subjects, or subject-label pairs.
    """

    feature_names: tuple[str, ...] = ()
    classes: tuple[int, ...] = ()
    class_names: tuple[str, ...] = ()
    x: tuple[tuple[float, ...], ...] = ()
    y: tuple[int, ...] = ()
    weights: tuple[float, ...] = ()
    splits: tuple[str, ...] = ()
    subjects: tuple[Optional[str], ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize dataset values.
        """
        feature_names = tuple(
            _canonical_field_name(name)
            for name in (self.feature_names or ())
            if _canonical_field_name(name)
        )
        classes = tuple(sorted({int(code) for code in (self.classes or ())}))
        class_names = tuple(_label_name(code) for code in classes)

        length = min(
            len(self.x or ()),
            len(self.y or ()),
            len(self.weights or ()),
            len(self.splits or ()),
            len(self.subjects or ()),
        )

        x = tuple(
            tuple(_round6(_coerce_float(value, allow_bool=True) or 0.0) for value in row[: len(feature_names)])
            for row in list(self.x or ())[:length]
        )
        y = tuple(int(code) for code in list(self.y or ())[:length])
        weights = tuple(
            _round6(_clip_float(weight, 0.0, _MAX_WEIGHT, 1.0))
            for weight in list(self.weights or ())[:length]
        )
        splits = tuple(
            _normalize_split_name(split)
            for split in list(self.splits or ())[:length]
        )
        subjects = tuple(
            _clean_text(subject, _MAX_SUBJECT_HASH_LENGTH).lower() if subject else None
            for subject in list(self.subjects or ())[:length]
        )

        counts = dict(self.counts or {})
        counts.update(
            {
                "samples": len(x),
                "features": len(feature_names),
                "classes": len(classes),
                "labeled": sum(1 for code in y if code is not None),
                "train": sum(1 for split in splits if split == SplitName.TRAIN.value),
                "validation": sum(1 for split in splits if split == SplitName.VALIDATION.value),
                "test": sum(1 for split in splits if split == SplitName.TEST.value),
            }
        )

        metadata = _safe_detail_value(self.metadata) or {}

        if not self.fingerprint:
            payload = {
                "version": SUPERVISED_VERSION,
                "feature_names": list(feature_names),
                "classes": list(classes),
                "counts": counts,
                "rows": [
                    [
                        subject or "",
                        list(row),
                        int(label),
                        float(weight),
                        split,
                    ]
                    for subject, row, label, weight, split in zip(
                        subjects,
                        x,
                        y,
                        weights,
                        splits,
                    )
                ],
            }

            try:
                fingerprint = _sha256_hex(_canonical_json(payload))
            except Exception:
                fingerprint = _sha256_hex(str(len(x)))
        else:
            fingerprint = _clean_text(self.fingerprint, 128)

        object.__setattr__(self, "feature_names", feature_names)
        object.__setattr__(self, "classes", classes)
        object.__setattr__(self, "class_names", class_names)
        object.__setattr__(self, "x", x)
        object.__setattr__(self, "y", y)
        object.__setattr__(self, "weights", weights)
        object.__setattr__(self, "splits", splits)
        object.__setattr__(self, "subjects", subjects)
        object.__setattr__(self, "counts", MappingProxyType(counts))
        object.__setattr__(self, "metadata", MappingProxyType(metadata))
        object.__setattr__(self, "fingerprint", fingerprint)

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing dataset summary.
        """
        return {
            "feature_count": len(self.feature_names),
            "feature_names_sample": list(self.feature_names[: _DEFAULT_MAX_SUMMARY_ITEMS]),
            "feature_names_truncated": len(self.feature_names) > _DEFAULT_MAX_SUMMARY_ITEMS,
            "class_count": len(self.classes),
            "classes": list(self.classes),
            "class_names": list(self.class_names),
            "counts": dict(self.counts),
            "fingerprint": self.fingerprint,
            "metadata": _safe_detail_value(self.metadata),
            "records_omitted": True,
            "caveats": list(_SUPERVISED_CAVEATS),
            "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
        }


@dataclass(slots=True)
class ModelParameters:
    """
    Internal-facing fitted model parameters.
    """

    feature_names: tuple[str, ...] = ()
    classes: tuple[int, ...] = ()
    class_names: tuple[str, ...] = ()
    task: TaskType = TaskType.BINARY
    weights: tuple[tuple[float, ...], ...] = ()
    intercept: tuple[float, ...] = ()
    calibration: dict[str, Any] = dataclass_field(default_factory=dict)
    threshold: float = _DEFAULT_THRESHOLD
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize parameter values.
        """
        object.__setattr__(self, "feature_names", tuple(_canonical_field_name(name) for name in self.feature_names if _canonical_field_name(name)))
        object.__setattr__(self, "classes", tuple(sorted({int(code) for code in self.classes})))
        object.__setattr__(self, "class_names", tuple(_label_name(code) for code in self.classes))
        object.__setattr__(self, "task", _normalize_enum_option(TaskType, self.task, TaskType.BINARY))
        object.__setattr__(
            self,
            "weights",
            tuple(
                tuple(_round6(_coerce_float(value, allow_bool=True) or 0.0) for value in row)
                for row in (self.weights or ())
            ),
        )
        object.__setattr__(
            self,
            "intercept",
            tuple(_round6(_coerce_float(value, allow_bool=True) or 0.0) for value in (self.intercept or ())),
        )
        object.__setattr__(self, "threshold", _round6(_clip_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)))
        object.__setattr__(self, "calibration", _safe_detail_value(self.calibration) or {})
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})

    def output_count(self) -> int:
        """
        Return number of model outputs.
        """
        if self.task == TaskType.BINARY:
            return 1

        return max(1, len(self.classes))

    def raw_logits(self, x: Sequence[float]) -> tuple[float, ...]:
        """
        Return raw model logits for one feature row.
        """
        if self.task == TaskType.BINARY:
            row = self.weights[0] if self.weights else ()
            bias = self.intercept[0] if self.intercept else 0.0
            return (_round6(bias + _dot(row, x)),)

        logits: list[float] = []

        for index, row in enumerate(self.weights):
            bias = self.intercept[index] if index < len(self.intercept) else 0.0
            logits.append(_round6(bias + _dot(row, x)))

        if not logits:
            logits = [0.0]

        return tuple(logits)

    def raw_probs(self, x: Sequence[float]) -> tuple[tuple[float, ...], tuple[float, ...]]:
        """
        Return raw probabilities and logits for one feature row.
        """
        logits = self.raw_logits(x)

        if self.task == TaskType.BINARY:
            p = _sigmoid(logits[0] if logits else 0.0)
            return ((1.0 - p, p), logits)

        return (_softmax(logits), logits)

    def calibrated_probs(self, x: Sequence[float]) -> tuple[tuple[float, ...], tuple[float, ...]]:
        """
        Return calibrated probabilities and raw logits.
        """
        probs, logits = self.raw_probs(x)
        method = str(self.calibration.get("method") or CalibrationMethod.NONE.value)

        if method == CalibrationMethod.PLATT.value and self.task == TaskType.BINARY:
            logit_value = logits[0] if logits else _logit(probs[1])
            a = _clip_float(_coerce_float(self.calibration.get("A")), 0.01, 100.0, 1.0)
            b = _clip_float(_coerce_float(self.calibration.get("B")), -100.0, 100.0, 0.0)
            p = _sigmoid(a * logit_value + b)
            return ((1.0 - p, p), logits)

        if method == CalibrationMethod.TEMPERATURE.value:
            temperature = _clip_float(_coerce_float(self.calibration.get("temperature")), 0.01, 100.0, 1.0)
            return (_softmax([value / temperature for value in logits]), logits)

        return (probs, logits)

    def predict_index(self, probs: Sequence[float]) -> int:
        """
        Return predicted internal class index.
        """
        if not probs:
            return 0

        if self.task == TaskType.BINARY:
            positive = _clip_float(_coerce_float(probs[-1]), 0.0, 1.0, 0.0)
            return 1 if positive >= self.threshold else 0

        best_index = 0
        best_value = -1.0

        for index, value in enumerate(probs):
            numeric = _clip_float(_coerce_float(value), 0.0, 1.0, 0.0)

            if numeric > best_value:
                best_value = numeric
                best_index = index

        return best_index

    def to_internal_dict(self) -> dict[str, Any]:
        """
        Return internal parameter representation.

        This contains coefficients and must not be exposed publicly without
        review.
        """
        return {
            "feature_names": list(self.feature_names),
            "classes": list(self.classes),
            "class_names": list(self.class_names),
            "task": self.task.value,
            "weights": [list(row) for row in self.weights],
            "intercept": list(self.intercept),
            "calibration": dict(self.calibration),
            "threshold": float(self.threshold),
            "metadata": _safe_detail_value(self.metadata),
        }

    def to_public_dict(self, *, expose_coefficients: bool = False) -> dict[str, Any]:
        """
        Return safe parameter summary.
        """
        payload: dict[str, Any] = {
            "feature_count": len(self.feature_names),
            "class_count": len(self.classes),
            "classes": list(self.classes),
            "class_names": list(self.class_names),
            "task": self.task.value,
            "threshold": float(self.threshold),
            "calibration_method": str(self.calibration.get("method") or "none"),
            "metadata": _safe_detail_value(self.metadata),
        }

        if expose_coefficients:
            payload["weights"] = [list(row) for row in self.weights]
            payload["intercept"] = list(self.intercept)
        else:
            payload["coefficients_omitted"] = True

        return payload


# Wall-clock and run-identity values are reported but never hashed: training is
# deterministic by design, so retraining the same dataset with the same options
# must produce the same fingerprint and therefore the same model id. Hashing a
# duration would make every identical model look like a different one.
_VOLATILE_FINGERPRINT_KEYS: tuple[str, ...] = (
    "training_elapsed_ms",
    "evaluation_elapsed_ms",
    "elapsed_ms",
    "duration_ms",
    "created_at",
    "trained_at",
    "evaluated_at",
    "generated_at",
    "request_id",
)


def _drop_volatile_keys(value: Any) -> Any:
    """
    Return a copy of a nested structure with wall-clock keys removed.
    """
    if isinstance(value, Mapping):
        return {
            key: _drop_volatile_keys(item)
            for key, item in value.items()
            if str(key) not in _VOLATILE_FINGERPRINT_KEYS
        }

    if isinstance(value, (list, tuple)):
        return [_drop_volatile_keys(item) for item in value]

    return value


def _fingerprintable_parameters(parameters: "ModelParameters") -> dict[str, Any]:
    """
    Return the fitted parameters in the stable form used for fingerprinting.
    """
    payload = parameters.to_internal_dict()
    payload["metadata"] = _drop_volatile_keys(payload.get("metadata"))
    return payload


@dataclass(slots=True)
class SupervisedModel:
    """
    Internal-facing bounded supervised model.
    """

    model_id: str = ""
    family: ModelFamily = ModelFamily.BASELINE_PRIOR
    task: TaskType = TaskType.BINARY
    status: ModelStatus = ModelStatus.DRAFT
    created_at: datetime = dataclass_field(default_factory=_now_utc)
    options: SupervisedOptions = dataclass_field(default_factory=SupervisedOptions)
    parameters: ModelParameters = dataclass_field(default_factory=ModelParameters)
    training_history: tuple[dict[str, Any], ...] = ()
    metrics: dict[str, Any] = dataclass_field(default_factory=dict)
    issues: tuple[SupervisedIssue, ...] = ()
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize model values.
        """
        object.__setattr__(self, "family", _normalize_enum_option(ModelFamily, self.family, ModelFamily.BASELINE_PRIOR))
        object.__setattr__(self, "task", _normalize_enum_option(TaskType, self.task, TaskType.BINARY))
        object.__setattr__(self, "status", _normalize_enum_option(ModelStatus, self.status, ModelStatus.DRAFT))
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())
        object.__setattr__(self, "training_history", tuple(self.training_history or ()))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metrics", _safe_detail_value(self.metrics) or {})
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})

        if not self.fingerprint:
            payload = {
                "version": SUPERVISED_VERSION,
                "family": self.family.value,
                "task": self.task.value,
                "options": self.options.safe_summary(),
                "parameters": _fingerprintable_parameters(self.parameters),
                "metrics": _drop_volatile_keys(self.metrics),
            }

            try:
                object.__setattr__(self, "fingerprint", _sha256_hex(_canonical_json(payload)))
            except Exception:
                object.__setattr__(self, "fingerprint", _sha256_hex(self.model_id or "model"))

        if not self.model_id:
            object.__setattr__(self, "model_id", self.fingerprint[:32])

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return safe API-facing model summary.
        """
        return {
            "model_id": self.model_id,
            "family": self.family.value,
            "task": self.task.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "fingerprint": self.fingerprint,
            "feature_count": len(self.parameters.feature_names),
            "feature_names_sample": list(
                self.parameters.feature_names[: self.options.max_summary_items]
            ),
            "feature_names_truncated": len(self.parameters.feature_names) > self.options.max_summary_items,
            "class_count": len(self.parameters.classes),
            "classes": list(self.parameters.classes),
            "class_names": list(self.parameters.class_names),
            "threshold": float(self.parameters.threshold),
            "calibration_method": str(self.parameters.calibration.get("method") or "none"),
            "metrics": _safe_detail_value(self.metrics),
            "training_history": list(self.training_history[: self.options.max_history]),
            "training_history_truncated": len(self.training_history) > self.options.max_history,
            "issues": [issue.to_dict() for issue in self.issues],
            "parameters": self.parameters.to_public_dict(
                expose_coefficients=self.options.expose_coefficients
            ),
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_SUPERVISED_CAVEATS),
            "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
        }

    def to_internal_dict(self) -> dict[str, Any]:
        """
        Return fuller internal model representation.

        This may include coefficients and must not be exposed publicly without
        review.
        """
        payload = self.to_public_dict()
        payload["parameters"] = self.parameters.to_internal_dict()
        payload["internal_only"] = True
        return payload


@dataclass(frozen=True, slots=True)
class Prediction:
    """
    One supervised prediction record.

    Predictions are investigative prioritization outputs only.
    """

    subject_ref_hash: Optional[str] = None
    label_code: int = 0
    label_name: str = "unknown"
    score: float = 0.0
    probabilities: Mapping[str, float] = dataclass_field(default_factory=dict)
    risk_band: str = "UNKNOWN"
    contributions: tuple[dict[str, Any], ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize prediction values.
        """
        object.__setattr__(self, "label_code", int(self.label_code))
        object.__setattr__(self, "label_name", _clean_text(self.label_name, 100) or _label_name(self.label_code))
        object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))
        object.__setattr__(
            self,
            "probabilities",
            MappingProxyType(
                {
                    _clean_text(key, 100): _round6(_clip_float(_coerce_float(value, allow_bool=True), 0.0, 1.0, 0.0))
                    for key, value in (self.probabilities or {}).items()
                }
            ),
        )
        object.__setattr__(self, "risk_band", _clean_text(self.risk_band, 32) or "UNKNOWN")
        object.__setattr__(self, "contributions", tuple(self.contributions or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable prediction mapping.
        """
        return {
            "subject_ref_hash": self.subject_ref_hash,
            "label_code": self.label_code,
            "label_name": self.label_name,
            "score": float(self.score),
            "probabilities": dict(self.probabilities),
            "risk_band": self.risk_band,
            "contributions": [dict(item) for item in self.contributions],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_SUPERVISED_CAVEATS),
            "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
        }


@dataclass(slots=True)
class EvaluationReport:
    """
    Safe supervised evaluation report.
    """

    ok: bool = True
    model_id: str = ""
    split_used: str = "none"
    counts: dict[str, int] = dataclass_field(default_factory=dict)
    metrics: dict[str, Any] = dataclass_field(default_factory=dict)
    class_metrics: tuple[dict[str, Any], ...] = ()
    confusion: dict[str, Any] = dataclass_field(default_factory=dict)
    calibration: dict[str, Any] = dataclass_field(default_factory=dict)
    issues: tuple[SupervisedIssue, ...] = ()
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize report values.
        """
        object.__setattr__(self, "counts", dict(self.counts or {}))
        object.__setattr__(self, "metrics", _safe_detail_value(self.metrics) or {})
        object.__setattr__(self, "class_metrics", tuple(self.class_metrics or ()))
        object.__setattr__(self, "confusion", _safe_detail_value(self.confusion) or {})
        object.__setattr__(self, "calibration", _safe_detail_value(self.calibration) or {})
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})

        if not self.fingerprint:
            payload = {
                "model_id": self.model_id,
                "split_used": self.split_used,
                "counts": self.counts,
                "metrics": self.metrics,
                "class_metrics": list(self.class_metrics),
                "confusion": self.confusion,
                "calibration": self.calibration,
            }

            try:
                object.__setattr__(self, "fingerprint", _sha256_hex(_canonical_json(payload)))
            except Exception:
                object.__setattr__(self, "fingerprint", "")

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable report mapping.
        """
        return {
            "ok": self.ok,
            "model_id": self.model_id,
            "split_used": self.split_used,
            "counts": dict(self.counts),
            "metrics": _safe_detail_value(self.metrics),
            "class_metrics": list(self.class_metrics),
            "confusion": _safe_detail_value(self.confusion),
            "calibration": _safe_detail_value(self.calibration),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_SUPERVISED_CAVEATS),
            "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Input normalization
# -----------------------------------------------------------------------------


def _positional_feature_name(position: int) -> str:
    """
    Build one canonical, sort-stable positional feature name.

    Zero padding matters: column order is recovered later by sorting the
    resolved names, and "feature_10" sorts before "feature_2".
    """
    return f"feature_{int(position):04d}"


def _is_positional_row(record: Any) -> bool:
    """
    Return True when a record is a bare ordered vector rather than a mapping.
    """
    if isinstance(record, Mapping):
        return False

    if isinstance(record, (str, bytes, bytearray)):
        return False

    if isinstance(getattr(record, "features", None), Mapping):
        return False

    if isinstance(getattr(record, "values", None), Mapping):
        return False

    return hasattr(record, "__len__") and hasattr(record, "__getitem__")


def _normalize_positional_records(
    records: Sequence[Any],
    feature_names: Optional[Sequence[str]],
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
) -> list[Any]:
    """
    Convert bare vector rows into named feature mappings.

    A caller may hand in a plain numeric matrix with the column names supplied
    separately, which is the ordinary shape for a feature matrix. Such rows
    carry no field names of their own, so they are paired with the declared
    names positionally here. Without this step they reach the extractor as
    non-mappings, yield an empty feature mapping, and produce an all-zero
    design matrix that trains without error and scores at chance.
    """
    rows = list(records)

    if not any(_is_positional_row(record) for record in rows):
        return rows

    declared: tuple[str, ...] = ()

    if feature_names is not None:
        declared = tuple(
            dict.fromkeys(
                _canonical_field_name(name)
                for name in feature_names
                if _canonical_field_name(name)
            )
        )

    widest = 0

    for record in rows:
        if _is_positional_row(record):
            widest = max(widest, len(record))

    if declared:
        names = declared
    else:
        names = tuple(_positional_feature_name(position) for position in range(widest))

    ragged = 0
    out: list[Any] = []

    for record in rows:
        if not _is_positional_row(record):
            out.append(record)
            continue

        values = tuple(record)

        if len(values) != widest:
            ragged += 1

        out.append(dict(zip(names, values)))

    if declared and widest > len(declared):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="vector_columns_undeclared",
            message="Vector rows carried more columns than declared feature names; the undeclared trailing columns were dropped.",
            details={"declared": len(declared), "columns": widest},
        )

    if ragged:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="ragged_vector_rows",
            message="Vector rows had differing lengths; positions absent from a row were left unset for that row.",
            details={"rows": ragged, "columns": widest},
        )

    return out


def _iter_records(data: Any) -> list[Any]:
    """
    Convert flexible supervised input into a list of row-like records.
    """
    if data is None:
        return []

    feature_names = getattr(data, "feature_names", None)
    rows = getattr(data, "rows", None)

    if feature_names is not None and rows is not None:
        out: list[Any] = []

        for row in _as_sequence(rows):
            values = getattr(row, "values", None)

            if isinstance(values, Mapping):
                record = dict(values)
            elif isinstance(row, Mapping):
                record = dict(row.get("values") if isinstance(row.get("values"), Mapping) else row)
            else:
                continue

            subject = getattr(row, "subject_ref_hash", None)

            if subject is None and isinstance(row, Mapping):
                subject = row.get("subject_ref_hash")

            if subject is not None:
                record["subject_ref_hash"] = subject

            out.append(record)

        return out

    if isinstance(data, Mapping):
        for key in ("rows", "records", "items", "examples", "vectors"):
            if key in data:
                return _as_sequence(data[key])

        if "feature_names" in data and "values" in data:
            names = _as_sequence(data.get("feature_names") or ())
            values = _as_sequence(data.get("values") or ())
            return [dict(zip([str(name) for name in names], values))]

        return [data]

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _extract_subject_and_features(
    record: Any,
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
    index: int,
) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    """
    Extract pseudonymous subject and safe feature mapping from one record.
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

    subject_hash = _subject_hash(subject, options) if subject is not None else None

    safe_features: dict[str, Any] = {}

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
            return subject_hash, None

        if canonical in safe_features:
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

        safe_features[canonical] = raw_value

    return subject_hash, safe_features


def _row_to_vector(
    features: Mapping[str, Any],
    feature_names: Sequence[str],
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
    index: int,
) -> Optional[tuple[float, ...]]:
    """
    Convert one feature mapping to a bounded numeric vector.
    """
    out: list[float] = []

    for name in feature_names:
        value = features.get(name, 0.0)
        numeric = _coerce_float(value, allow_bool=True)

        if numeric is None:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="non_numeric_feature",
                message="Non-numeric feature value was zero-filled.",
                field=name,
                details={"index": index},
            )
            numeric = 0.0

        out.append(_round6(_clip_float(numeric, -1e12, 1e12, 0.0)))

    return tuple(out)


def _labels_to_arrays(
    labels: Any,
    subjects: Sequence[Optional[str]],
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
) -> tuple[list[Optional[int]], list[float], list[str]]:
    """
    Extract aligned label, weight, and split arrays from flexible label input.
    """
    n = len(subjects)
    y: list[Optional[int]] = [None] * n
    weights: list[float] = [1.0] * n
    splits: list[str] = [SplitName.TRAIN.value] * n

    if labels is None:
        return y, weights, splits

    subject_hashes: Any = None
    label_codes: Any = None
    label_weights: Any = None
    label_splits: Any = None
    records: Any = None

    if isinstance(labels, Mapping):
        subject_hashes = labels.get("subject_hashes") or labels.get("subjects")
        label_codes = labels.get("label_codes") or labels.get("labels") or labels.get("y")
        label_weights = labels.get("weights")
        label_splits = labels.get("splits")
        records = labels.get("records") or labels.get("items")
    else:
        subject_hashes = getattr(labels, "subject_hashes", None)
        label_codes = getattr(labels, "label_codes", None) or getattr(labels, "labels", None)
        label_weights = getattr(labels, "weights", None)
        label_splits = getattr(labels, "splits", None)
        records = getattr(labels, "records", None) or getattr(labels, "items", None)

    if label_codes is not None:
        label_seq = _as_sequence(label_codes)
        subject_seq = _as_sequence(subject_hashes or ())
        weight_seq = _as_sequence(label_weights or ())
        split_seq = _as_sequence(label_splits or ())

        if subject_seq and len(subject_seq) == len(label_seq) and any(subjects):
            mapping: dict[str, tuple[Optional[int], float, str]] = {}

            for index, subject in enumerate(subject_seq):
                subject_text = _clean_text(subject, _MAX_SUBJECT_HASH_LENGTH).lower()

                if not subject_text:
                    continue

                weight = _clip_float(
                    _coerce_float(weight_seq[index] if index < len(weight_seq) else 1.0),
                    0.0,
                    _MAX_WEIGHT,
                    1.0,
                )
                split = _normalize_split_name(split_seq[index] if index < len(split_seq) else SplitName.TRAIN.value)
                mapping[subject_text] = (_coerce_int_label(label_seq[index]), weight, split)

            for index, subject in enumerate(subjects):
                if subject is None:
                    continue

                item = mapping.get(subject)

                if item is None:
                    continue

                y[index], weights[index], splits[index] = item

            return y, weights, splits

        for index in range(min(n, len(label_seq))):
            y[index] = _coerce_int_label(label_seq[index])

            if index < len(weight_seq):
                weights[index] = _clip_float(
                    _coerce_float(weight_seq[index]),
                    0.0,
                    _MAX_WEIGHT,
                    1.0,
                )

            if index < len(split_seq):
                splits[index] = _normalize_split_name(split_seq[index])

        return y, weights, splits

    if records is not None:
        record_seq = _as_sequence(records)
        mapping = {}
        positional: list[tuple[Optional[int], float, str]] = []

        for record in record_seq:
            if not isinstance(record, Mapping):
                continue

            subject = None

            for key in _SUBJECT_KEYS:
                if key in record:
                    subject = record[key]
                    break

            subject_text = _clean_text(subject, _MAX_SUBJECT_HASH_LENGTH).lower() if subject is not None else ""
            label_value = (
                record.get("label_code")
                or record.get("label")
                or record.get("target")
                or record.get("y")
                or record.get("synthetic_label")
            )
            weight_value = _clip_float(
                _coerce_float(record.get("weight"), 1.0),
                0.0,
                _MAX_WEIGHT,
                1.0,
            )
            split_value = _normalize_split_name(record.get("split", SplitName.TRAIN.value))
            item = (_coerce_int_label(label_value), weight_value, split_value)

            positional.append(item)

            if subject_text:
                mapping[subject_text] = item

        if mapping and any(subjects):
            for index, subject in enumerate(subjects):
                if subject is None:
                    continue

                item = mapping.get(subject)

                if item is not None:
                    y[index], weights[index], splits[index] = item
        else:
            for index, item in enumerate(positional[:n]):
                y[index], weights[index], splits[index] = item

        return y, weights, splits

    label_seq = _as_sequence(labels)

    for index in range(min(n, len(label_seq))):
        item = label_seq[index]

        if isinstance(item, Mapping):
            label_value = (
                item.get("label_code")
                or item.get("label")
                or item.get("target")
                or item.get("y")
                or item.get("synthetic_label")
            )
            y[index] = _coerce_int_label(label_value)
            weights[index] = _clip_float(
                _coerce_float(item.get("weight"), 1.0),
                0.0,
                _MAX_WEIGHT,
                1.0,
            )
            splits[index] = _normalize_split_name(item.get("split", SplitName.TRAIN.value))
        else:
            y[index] = _coerce_int_label(item)

    return y, weights, splits


def _override_sequence(
    values: Any,
    current: list[Any],
    default: Any,
    parser: Any,
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
    code: str,
) -> list[Any]:
    """
    Override an array with a supplied sequence when compatible.
    """
    if values is None:
        return current

    seq = _as_sequence(values)

    if not seq:
        return current

    if len(seq) < len(current):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code=f"{code}_short",
            message="Supplied array was shorter than dataset and was padded with defaults.",
            details={"supplied": len(seq), "expected": len(current)},
        )

    out = list(current)

    for index in range(min(len(out), len(seq))):
        parsed = parser(seq[index])

        if parsed is None:
            parsed = default

        out[index] = parsed

    return out


def build_training_dataset(
    features: Any,
    labels: Any = None,
    *,
    weights: Any = None,
    splits: Any = None,
    feature_names: Optional[Sequence[str]] = None,
    options: SupervisedOptions | None = None,
) -> TrainingDataset:
    """
    Build one bounded internal supervised training dataset.

    This is internal-facing. Public consumers must use safe summaries only.
    """
    opts = options or SupervisedOptions.from_settings()
    issues: list[SupervisedIssue] = []

    records = _normalize_positional_records(
        _iter_records(features),
        feature_names,
        opts,
        issues,
    )
    submitted = len(records)

    if submitted > opts.max_samples:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="dataset_sample_truncated",
            message="Dataset input exceeded configured sample limit and was truncated.",
            details={"submitted": submitted, "max_samples": opts.max_samples},
        )
        records = records[: opts.max_samples]

    subjects: list[Optional[str]] = []
    feature_rows: list[dict[str, Any]] = []
    name_counts: Counter[str] = Counter()

    for index, record in enumerate(records):
        subject, safe_features = _extract_subject_and_features(record, opts, issues, index)

        if safe_features is None:
            continue

        subjects.append(subject)
        feature_rows.append(safe_features)

        for name in safe_features:
            name_counts[name] += 1

    if feature_names is not None:
        resolved_names = tuple(
            dict.fromkeys(
                _canonical_field_name(name)
                for name in feature_names
                if _canonical_field_name(name)
            )
        )
    else:
        ordered_names = sorted(
            name_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
        if len(ordered_names) > opts.max_features:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="feature_limit_applied",
                message="Feature count exceeded configured limit and was truncated.",
                details={
                    "submitted": len(ordered_names),
                    "max_features": opts.max_features,
                },
            )
        resolved_names = tuple(sorted(name for name, _ in ordered_names[: opts.max_features]))

    if not resolved_names:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="no_features",
            message="No valid numeric feature columns were available.",
        )

    max_rows_by_cells = max(1, opts.max_cells // max(1, len(resolved_names)))

    if len(feature_rows) > max_rows_by_cells:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="dataset_cells_truncated",
            message="Dataset was truncated to satisfy maximum cell budget.",
            details={
                "submitted": len(feature_rows),
                "max_rows_by_cells": max_rows_by_cells,
                "max_cells": opts.max_cells,
            },
        )
        feature_rows = feature_rows[:max_rows_by_cells]
        subjects = subjects[:max_rows_by_cells]

    # A row that shares no column with the resolved names vectorizes to zeros.
    # That is indistinguishable from genuinely zero-valued features downstream,
    # so it is reported here rather than left to look like trained signal.
    unmatched_rows = sum(
        1
        for row in feature_rows
        if resolved_names and not any(name in row for name in resolved_names)
    )

    if unmatched_rows:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING if unmatched_rows < len(feature_rows) else IssueSeverity.ERROR,
            code="rows_without_resolved_features",
            message="Some rows carried none of the resolved feature columns and vectorized to zeros.",
            details={
                "rows": unmatched_rows,
                "total_rows": len(feature_rows),
                "resolved_features": len(resolved_names),
            },
        )

    x: list[tuple[float, ...]] = []
    kept_subjects: list[Optional[str]] = []

    for index, row in enumerate(feature_rows):
        vector = _row_to_vector(row, resolved_names, opts, issues, index)

        if vector is None:
            continue

        x.append(vector)
        kept_subjects.append(subjects[index] if index < len(subjects) else None)

    y, dataset_weights, dataset_splits = _labels_to_arrays(
        labels,
        kept_subjects,
        opts,
        issues,
    )

    dataset_weights = _override_sequence(
        weights,
        dataset_weights,
        1.0,
        lambda value: _clip_float(_coerce_float(value, allow_bool=True), 0.0, _MAX_WEIGHT, 1.0),
        opts,
        issues,
        "weights",
    )
    dataset_splits = _override_sequence(
        splits,
        dataset_splits,
        SplitName.TRAIN.value,
        lambda value: _normalize_split_name(value),
        opts,
        issues,
        "splits",
    )

    labeled_pairs = [
        (index, int(code))
        for index, code in enumerate(y)
        if code is not None
    ]
    classes = tuple(sorted({code for _, code in labeled_pairs}))

    if len(classes) > opts.max_classes:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="too_many_classes",
            message="Dataset class count exceeds configured maximum.",
            details={"classes": len(classes), "max_classes": opts.max_classes},
        )
        classes = ()
        labeled_pairs = []

    final_x: list[tuple[float, ...]] = []
    final_y: list[int] = []
    final_weights: list[float] = []
    final_splits: list[str] = []
    final_subjects: list[Optional[str]] = []

    for index, code in labeled_pairs:
        final_x.append(x[index])
        final_y.append(code)
        final_weights.append(dataset_weights[index])
        final_splits.append(dataset_splits[index])
        final_subjects.append(kept_subjects[index])

    counts = {
        "submitted": submitted,
        "processed": len(x),
        "labeled": len(final_y),
        "unlabeled": max(0, len(x) - len(final_y)),
        "features": len(resolved_names),
        "classes": len(classes),
        "train": sum(1 for split in final_splits if split == SplitName.TRAIN.value),
        "validation": sum(1 for split in final_splits if split == SplitName.VALIDATION.value),
        "test": sum(1 for split in final_splits if split == SplitName.TEST.value),
    }

    metadata: dict[str, Any] = {
        "supervised_version": SUPERVISED_VERSION,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues[: opts.max_issues]],
        "issue_count": len(issues),
        "caveats": list(_SUPERVISED_CAVEATS),
        "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
    }

    return TrainingDataset(
        feature_names=resolved_names,
        classes=classes,
        x=tuple(final_x),
        y=tuple(final_y),
        weights=tuple(final_weights),
        splits=tuple(final_splits),
        subjects=tuple(final_subjects),
        counts=counts,
        metadata=metadata,
    )


# -----------------------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------------------


def _binary_roc_auc(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    """
    Compute binary ROC AUC.
    """
    pairs = sorted(
        (float(score), int(label))
        for score, label in zip(scores, y_true)
        if label in (0, 1)
    )

    positives = sum(1 for _, label in pairs if label == 1)
    negatives = len(pairs) - positives

    if positives <= 0 or negatives <= 0:
        return None

    rank_sum = 0.0
    index = 0

    while index < len(pairs):
        j = index

        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[index][0]:
            j += 1

        average_rank = (float(index + 1) + float(j + 1)) / 2.0
        rank_sum += sum(average_rank for k in range(index, j + 1) if pairs[k][1] == 1)
        index = j + 1

    auc = (rank_sum - (positives * (positives + 1)) / 2.0) / float(positives * negatives)
    return _round6(_clip_float(auc, 0.0, 1.0, 0.5))


def _binary_pr_auc(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    """
    Compute binary precision-recall AUC using step interpolation.
    """
    pairs = sorted(
        (float(score), int(label))
        for score, label in zip(scores, y_true)
        if label in (0, 1)
    )

    positives = sum(1 for _, label in pairs if label == 1)

    if positives <= 0 or len(pairs) <= positives:
        return None

    pairs.sort(key=lambda item: -item[0])

    tp = 0
    fp = 0
    ap = 0.0
    previous_recall = 0.0

    for _, label in pairs:
        if label == 1:
            tp += 1
        else:
            fp += 1

        precision = float(tp) / float(tp + fp) if (tp + fp) > 0 else 0.0
        recall = float(tp) / float(positives)

        ap += precision * (recall - previous_recall)
        previous_recall = recall

    return _round6(_clip_float(ap, 0.0, 1.0, 0.0))


def _log_loss_binary(y_true: Sequence[int], probs: Sequence[float]) -> Optional[float]:
    """
    Compute binary log loss.
    """
    total = 0.0
    count = 0

    for label, probability in zip(y_true, probs):
        if label not in (0, 1):
            continue

        p = _clip_float(probability, 1e-12, 1.0 - 1e-12, 0.5)
        total -= float(label) * math.log(p) + (1.0 - float(label)) * math.log(1.0 - p)
        count += 1

    if count <= 0:
        return None

    return _round6(total / float(count))


def _log_loss_multiclass(y_true: Sequence[int], probs: Sequence[Sequence[float]]) -> Optional[float]:
    """
    Compute multiclass cross-entropy log loss.
    """
    total = 0.0
    count = 0

    for label, row in zip(y_true, probs):
        if label < 0 or label >= len(row):
            continue

        p = _clip_float(float(row[label]), 1e-12, 1.0, 1e-12)
        total -= math.log(p)
        count += 1

    if count <= 0:
        return None

    return _round6(total / float(count))


def _brier_binary(y_true: Sequence[int], probs: Sequence[float]) -> Optional[float]:
    """
    Compute binary Brier score.
    """
    total = 0.0
    count = 0

    for label, probability in zip(y_true, probs):
        if label not in (0, 1):
            continue

        p = _clip_float(probability, 0.0, 1.0, 0.0)
        total += (p - float(label)) ** 2
        count += 1

    if count <= 0:
        return None

    return _round6(total / float(count))


def _brier_multiclass(y_true: Sequence[int], probs: Sequence[Sequence[float]]) -> Optional[float]:
    """
    Compute multiclass Brier score.
    """
    total = 0.0
    count = 0

    for label, row in zip(y_true, probs):
        if label < 0 or label >= len(row):
            continue

        for index, probability in enumerate(row):
            p = _clip_float(float(probability), 0.0, 1.0, 0.0)
            target = 1.0 if index == label else 0.0
            total += (p - target) ** 2

        count += 1

    if count <= 0:
        return None

    return _round6(total / float(count))


def _ece_binary(
    y_true: Sequence[int],
    probs: Sequence[float],
    bins: int,
) -> Optional[float]:
    """
    Compute binary expected calibration error.
    """
    pairs = [
        (int(label), _clip_float(float(probability), 0.0, 1.0, 0.0))
        for label, probability in zip(y_true, probs)
        if label in (0, 1)
    ]

    if not pairs:
        return None

    bin_count = max(2, int(bins))
    totals = [0.0 for _ in range(bin_count)]
    confidences = [0.0 for _ in range(bin_count)]
    accuracies = [0.0 for _ in range(bin_count)]

    for label, probability in pairs:
        confidence = max(probability, 1.0 - probability)
        correct = 1.0 if (probability >= 0.5 and label == 1) or (probability < 0.5 and label == 0) else 0.0
        index = min(bin_count - 1, int(confidence * bin_count))
        totals[index] += 1.0
        confidences[index] += confidence
        accuracies[index] += correct

    total = float(len(pairs))
    ece = 0.0

    for index in range(bin_count):
        if totals[index] <= 0:
            continue

        avg_confidence = confidences[index] / totals[index]
        avg_accuracy = accuracies[index] / totals[index]
        ece += (totals[index] / total) * abs(avg_accuracy - avg_confidence)

    return _round6(_clip_float(ece, 0.0, 1.0, 0.0))


def _ece_multiclass(
    y_true: Sequence[int],
    probs: Sequence[Sequence[float]],
    bins: int,
) -> Optional[float]:
    """
    Compute multiclass expected calibration error.
    """
    pairs: list[tuple[int, float, int]] = []

    for label, row in zip(y_true, probs):
        if label < 0 or label >= len(row):
            continue

        predicted = max(range(len(row)), key=lambda index: float(row[index]))
        confidence = _clip_float(float(row[predicted]), 0.0, 1.0, 0.0)
        pairs.append((int(label), confidence, int(predicted)))

    if not pairs:
        return None

    bin_count = max(2, int(bins))
    totals = [0.0 for _ in range(bin_count)]
    confidences = [0.0 for _ in range(bin_count)]
    accuracies = [0.0 for _ in range(bin_count)]

    for label, confidence, predicted in pairs:
        index = min(bin_count - 1, int(confidence * bin_count))
        totals[index] += 1.0
        confidences[index] += confidence
        accuracies[index] += 1.0 if predicted == label else 0.0

    total = float(len(pairs))
    ece = 0.0

    for index in range(bin_count):
        if totals[index] <= 0:
            continue

        avg_confidence = confidences[index] / totals[index]
        avg_accuracy = accuracies[index] / totals[index]
        ece += (totals[index] / total) * abs(avg_accuracy - avg_confidence)

    return _round6(_clip_float(ece, 0.0, 1.0, 0.0))


def _classification_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    num_classes: int,
) -> dict[str, Any]:
    """
    Compute bounded classification metrics.
    """
    if num_classes <= 0 or not y_true:
        return {}

    confusion = [[0 for _ in range(num_classes)] for _ in range(num_classes)]
    correct = 0

    for true_label, predicted_label in zip(y_true, y_pred):
        if true_label < 0 or true_label >= num_classes:
            continue

        if predicted_label < 0 or predicted_label >= num_classes:
            continue

        confusion[int(true_label)][int(predicted_label)] += 1

        if true_label == predicted_label:
            correct += 1

    total = sum(sum(row) for row in confusion)

    if total <= 0:
        return {}

    accuracy = float(correct) / float(total)

    per_class: list[dict[str, Any]] = []
    macro_precision = 0.0
    macro_recall = 0.0
    macro_f1 = 0.0
    weighted_precision = 0.0
    weighted_recall = 0.0
    weighted_f1 = 0.0

    for class_index in range(num_classes):
        tp = confusion[class_index][class_index]
        fp = sum(confusion[row][class_index] for row in range(num_classes)) - tp
        fn = sum(confusion[class_index]) - tp
        support = tp + fn

        precision = float(tp) / float(tp + fp) if (tp + fp) > 0 else 0.0
        recall = float(tp) / float(tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2.0 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        per_class.append(
            {
                "class_index": class_index,
                "support": int(support),
                "precision": _round6(precision),
                "recall": _round6(recall),
                "f1": _round6(f1),
                "tp": int(tp),
                "fp": int(fp),
                "fn": int(fn),
            }
        )

        macro_precision += precision
        macro_recall += recall
        macro_f1 += f1

        if support > 0:
            weight = float(support) / float(total)
            weighted_precision += weight * precision
            weighted_recall += weight * recall
            weighted_f1 += weight * f1

    micro_precision = accuracy
    micro_recall = accuracy
    micro_f1 = accuracy

    return {
        "accuracy": _round6(accuracy),
        "micro_precision": _round6(micro_precision),
        "micro_recall": _round6(micro_recall),
        "micro_f1": _round6(micro_f1),
        "macro_precision": _round6(macro_precision / float(num_classes)),
        "macro_recall": _round6(macro_recall / float(num_classes)),
        "macro_f1": _round6(macro_f1 / float(num_classes)),
        "weighted_precision": _round6(weighted_precision),
        "weighted_recall": _round6(weighted_recall),
        "weighted_f1": _round6(weighted_f1),
        "per_class": per_class,
        "confusion": confusion,
        "total": int(total),
    }


# -----------------------------------------------------------------------------
# Training internals
# -----------------------------------------------------------------------------


def _compute_class_weights(
    y_train: Sequence[int],
    weights_train: Sequence[float],
    num_classes: int,
    options: SupervisedOptions,
) -> tuple[float, ...]:
    """
    Compute bounded class weights from training labels only.
    """
    if not options.balance_classes or num_classes <= 0:
        return tuple(1.0 for _ in range(num_classes))

    counts = [0.0 for _ in range(num_classes)]

    for label, weight in zip(y_train, weights_train):
        if 0 <= int(label) < num_classes:
            counts[int(label)] += max(0.0, float(weight))

    total = sum(counts)

    if total <= 0:
        return tuple(1.0 for _ in range(num_classes))

    out: list[float] = []

    for count in counts:
        if count <= 0:
            out.append(0.0)
        else:
            value = total / (float(num_classes) * count)
            out.append(_round6(_clip_float(value, 0.0, options.max_class_weight, 1.0)))

    return tuple(out)


def _effective_weight(
    label: int,
    sample_weight: float,
    class_weights: Sequence[float],
) -> float:
    """
    Return bounded effective sample weight.
    """
    if label < 0 or label >= len(class_weights):
        class_weight = 1.0
    else:
        class_weight = float(class_weights[label])

    return _round6(max(0.0, float(sample_weight)) * max(0.0, class_weight))


def _stable_epoch_order(
    indices: Sequence[int],
    options: SupervisedOptions,
    epoch: int,
) -> list[int]:
    """
    Return deterministic shuffled local order for one epoch.
    """
    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.supervised.order.{safe_namespace}"

    return sorted(
        range(len(indices)),
        key=lambda local_index: (
            _stable_rank(
                options.salt,
                domain,
                options.seed,
                epoch,
                indices[local_index],
            ),
            local_index,
        ),
    )


def _evaluate_loss_binary(
    x: Sequence[Sequence[float]],
    y: Sequence[int],
    weights: Sequence[float],
    class_weights: Sequence[float],
    model_weights: Sequence[float],
    bias: float,
) -> Optional[float]:
    """
    Evaluate binary weighted log loss.
    """
    total_loss = 0.0
    total_weight = 0.0

    for row, label, sample_weight in zip(x, y, weights):
        effective = _effective_weight(int(label), float(sample_weight), class_weights)

        if effective <= 0:
            continue

        p = _sigmoid(bias + _dot(model_weights, row))
        target = float(label)
        total_loss -= effective * (
            target * math.log(max(p, 1e-12))
            + (1.0 - target) * math.log(max(1.0 - p, 1e-12))
        )
        total_weight += effective

    if total_weight <= 0:
        return None

    return _round6(total_loss / total_weight)


def _evaluate_loss_multiclass(
    x: Sequence[Sequence[float]],
    y: Sequence[int],
    weights: Sequence[float],
    class_weights: Sequence[float],
    model_weights: Sequence[Sequence[float]],
    biases: Sequence[float],
) -> Optional[float]:
    """
    Evaluate multiclass weighted cross-entropy loss.
    """
    total_loss = 0.0
    total_weight = 0.0
    num_classes = len(model_weights)

    for row, label, sample_weight in zip(x, y, weights):
        true_label = int(label)

        if true_label < 0 or true_label >= num_classes:
            continue

        effective = _effective_weight(true_label, float(sample_weight), class_weights)

        if effective <= 0:
            continue

        logits = [
            float(biases[index] if index < len(biases) else 0.0)
            + _dot(model_weights[index], row)
            for index in range(num_classes)
        ]
        probs = _softmax(logits)
        p = _clip_float(float(probs[true_label]), 1e-12, 1.0, 1e-12)
        total_loss -= effective * math.log(p)
        total_weight += effective

    if total_weight <= 0:
        return None

    return _round6(total_loss / total_weight)


def _prox_l1(values: list[float], shrink: float) -> None:
    """
    Apply in-place soft-thresholding for L1 regularization.
    """
    if shrink <= 0:
        return

    for index, value in enumerate(values):
        if abs(value) <= shrink:
            values[index] = 0.0
        else:
            values[index] = math.copysign(abs(value) - shrink, value)


def _train_binary(
    x_train: Sequence[Sequence[float]],
    y_train: Sequence[int],
    w_train: Sequence[float],
    class_weights: Sequence[float],
    x_val: Sequence[Sequence[float]],
    y_val: Sequence[int],
    w_val: Sequence[float],
    feature_count: int,
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
    start_time: float,
) -> tuple[tuple[tuple[float, ...], ...], tuple[float, ...], tuple[dict[str, Any], ...]]:
    """
    Train bounded binary logistic regression.
    """
    n_features = max(1, int(feature_count))
    weights = [0.0 for _ in range(n_features)]
    bias = 0.0

    m_w = [0.0 for _ in range(n_features)]
    v_w = [0.0 for _ in range(n_features)]
    m_b = 0.0
    v_b = 0.0

    n_train = len(x_train)

    if n_train <= 0:
        return ((tuple(weights),), (bias,), ())

    batch_size = max(1, min(int(options.batch_size), n_train))
    steps_per_epoch = max(1, math.ceil(n_train / batch_size))
    max_steps = min(int(options.max_minibatch_steps), int(options.max_iterations) * steps_per_epoch)

    best_weights = tuple(weights)
    best_bias = bias
    best_val_loss = math.inf
    patience_counter = 0
    history: list[dict[str, Any]] = []

    l2_strength = 0.0
    l1_strength = 0.0

    if options.regularization in {Regularization.L2, Regularization.ELASTIC_NET}:
        l2_strength = float(options.reg_strength) * (1.0 - float(options.l1_ratio))

    if options.regularization in {Regularization.L1, Regularization.ELASTIC_NET}:
        l1_strength = float(options.reg_strength) * float(options.l1_ratio)

    step = 0

    for epoch in range(int(options.max_iterations)):
        if step >= max_steps:
            break

        if (time.monotonic() - start_time) * 1000.0 > float(options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="training_time_budget_exhausted",
                message="Training stopped after reaching configured time budget.",
                details={"epoch": epoch, "step": step},
            )
            break

        order = _stable_epoch_order(list(range(n_train)), options, epoch)

        for batch_start in range(0, n_train, batch_size):
            if step >= max_steps:
                break

            step += 1
            batch = order[batch_start : batch_start + batch_size]

            grad_w = [0.0 for _ in range(n_features)]
            grad_b = 0.0
            denom = 0.0

            for local_index in batch:
                index = int(local_index)
                row = x_train[index]
                label = int(y_train[index])
                effective = _effective_weight(label, float(w_train[index]), class_weights)

                if effective <= 0:
                    continue

                p = _sigmoid(bias + _dot(weights, row))
                error = (p - float(label)) * effective
                denom += effective

                for feature_index, value in enumerate(row[:n_features]):
                    grad_w[feature_index] += error * float(value)

                grad_b += error

            if denom <= 0:
                continue

            for feature_index in range(n_features):
                grad_w[feature_index] = (
                    grad_w[feature_index] / denom
                    + l2_strength * weights[feature_index]
                )

            grad_b = grad_b / denom

            if options.optimizer == Optimizer.ADAM:
                beta1 = float(options.beta1)
                beta2 = float(options.beta2)
                epsilon = float(options.epsilon)

                for feature_index in range(n_features):
                    m_w[feature_index] = (
                        beta1 * m_w[feature_index]
                        + (1.0 - beta1) * grad_w[feature_index]
                    )
                    v_w[feature_index] = (
                        beta2 * v_w[feature_index]
                        + (1.0 - beta2) * grad_w[feature_index] ** 2
                    )
                    m_hat = m_w[feature_index] / (1.0 - beta1**step)
                    v_hat = v_w[feature_index] / (1.0 - beta2**step)
                    weights[feature_index] -= (
                        float(options.learning_rate)
                        * m_hat
                        / (math.sqrt(v_hat) + epsilon)
                    )

                m_b = beta1 * m_b + (1.0 - beta1) * grad_b
                v_b = beta2 * v_b + (1.0 - beta2) * grad_b**2
                m_hat_b = m_b / (1.0 - beta1**step)
                v_hat_b = v_b / (1.0 - beta2**step)
                bias -= float(options.learning_rate) * m_hat_b / (math.sqrt(v_hat_b) + epsilon)
            else:
                momentum = float(options.momentum)

                for feature_index in range(n_features):
                    m_w[feature_index] = momentum * m_w[feature_index] + grad_w[feature_index]
                    weights[feature_index] -= float(options.learning_rate) * m_w[feature_index]

                m_b = momentum * m_b + grad_b
                bias -= float(options.learning_rate) * m_b

            if l1_strength > 0:
                shrink = float(options.learning_rate) * l1_strength
                _prox_l1(weights, shrink)

            weights = [_round6(_clip_float(value, -1e6, 1e6, 0.0)) for value in weights]
            bias = _round6(_clip_float(bias, -1e6, 1e6, 0.0))

        train_loss = _evaluate_loss_binary(x_train, y_train, w_train, class_weights, weights, bias)
        val_loss = None

        if x_val:
            val_loss = _evaluate_loss_binary(x_val, y_val, w_val, class_weights, weights, bias)

        history.append(
            {
                "epoch": epoch + 1,
                "step": step,
                "train_loss": train_loss,
                "val_loss": val_loss,
            }
        )

        if len(history) > options.max_history:
            history = history[-options.max_history :]

        if val_loss is not None:
            if val_loss < best_val_loss - float(options.min_delta):
                best_val_loss = val_loss
                best_weights = tuple(weights)
                best_bias = bias
                patience_counter = 0
            else:
                patience_counter += 1

                if options.early_stopping and patience_counter >= int(options.patience):
                    _append_issue(
                        issues,
                        options.max_issues,
                        severity=IssueSeverity.INFO,
                        code="early_stopping_triggered",
                        message="Training stopped early based on validation loss.",
                        details={"epoch": epoch + 1, "val_loss": val_loss},
                    )
                    break

    if best_val_loss == math.inf:
        best_weights = tuple(weights)
        best_bias = bias

    return ((best_weights,), (best_bias,), tuple(history))


def _train_multiclass(
    x_train: Sequence[Sequence[float]],
    y_train: Sequence[int],
    w_train: Sequence[float],
    class_weights: Sequence[float],
    x_val: Sequence[Sequence[float]],
    y_val: Sequence[int],
    w_val: Sequence[float],
    feature_count: int,
    num_classes: int,
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
    start_time: float,
) -> tuple[tuple[tuple[float, ...], ...], tuple[float, ...], tuple[dict[str, Any], ...]]:
    """
    Train bounded softmax regression.
    """
    n_features = max(1, int(feature_count))
    k = max(2, int(num_classes))

    weights = [[0.0 for _ in range(n_features)] for _ in range(k)]
    biases = [0.0 for _ in range(k)]

    m_w = [[0.0 for _ in range(n_features)] for _ in range(k)]
    v_w = [[0.0 for _ in range(n_features)] for _ in range(k)]
    m_b = [0.0 for _ in range(k)]
    v_b = [0.0 for _ in range(k)]

    n_train = len(x_train)

    if n_train <= 0:
        return (tuple(tuple(row) for row in weights), tuple(biases), ())

    batch_size = max(1, min(int(options.batch_size), n_train))
    steps_per_epoch = max(1, math.ceil(n_train / batch_size))
    max_steps = min(int(options.max_minibatch_steps), int(options.max_iterations) * steps_per_epoch)

    best_weights = [list(row) for row in weights]
    best_biases = list(biases)
    best_val_loss = math.inf
    patience_counter = 0
    history: list[dict[str, Any]] = []

    l2_strength = 0.0
    l1_strength = 0.0

    if options.regularization in {Regularization.L2, Regularization.ELASTIC_NET}:
        l2_strength = float(options.reg_strength) * (1.0 - float(options.l1_ratio))

    if options.regularization in {Regularization.L1, Regularization.ELASTIC_NET}:
        l1_strength = float(options.reg_strength) * float(options.l1_ratio)

    step = 0

    for epoch in range(int(options.max_iterations)):
        if step >= max_steps:
            break

        if (time.monotonic() - start_time) * 1000.0 > float(options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="training_time_budget_exhausted",
                message="Training stopped after reaching configured time budget.",
                details={"epoch": epoch, "step": step},
            )
            break

        order = _stable_epoch_order(list(range(n_train)), options, epoch)

        for batch_start in range(0, n_train, batch_size):
            if step >= max_steps:
                break

            step += 1
            batch = order[batch_start : batch_start + batch_size]

            grad_w = [[0.0 for _ in range(n_features)] for _ in range(k)]
            grad_b = [0.0 for _ in range(k)]
            denom = 0.0

            for local_index in batch:
                index = int(local_index)
                row = x_train[index]
                label = int(y_train[index])
                effective = _effective_weight(label, float(w_train[index]), class_weights)

                if effective <= 0 or label < 0 or label >= k:
                    continue

                logits = [
                    biases[class_index] + _dot(weights[class_index], row)
                    for class_index in range(k)
                ]
                probs = _softmax(logits)
                denom += effective

                for class_index in range(k):
                    target = 1.0 if class_index == label else 0.0
                    error = (float(probs[class_index]) - target) * effective
                    grad_b[class_index] += error

                    if error == 0.0:
                        continue

                    class_grad = grad_w[class_index]

                    for feature_index, value in enumerate(row[:n_features]):
                        class_grad[feature_index] += error * float(value)

            if denom <= 0:
                continue

            for class_index in range(k):
                class_weights_row = grad_w[class_index]
                model_weights_row = weights[class_index]

                for feature_index in range(n_features):
                    class_weights_row[feature_index] = (
                        class_weights_row[feature_index] / denom
                        + l2_strength * model_weights_row[feature_index]
                    )

                grad_b[class_index] = grad_b[class_index] / denom

            if options.optimizer == Optimizer.ADAM:
                beta1 = float(options.beta1)
                beta2 = float(options.beta2)
                epsilon = float(options.epsilon)

                for class_index in range(k):
                    for feature_index in range(n_features):
                        m_w[class_index][feature_index] = (
                            beta1 * m_w[class_index][feature_index]
                            + (1.0 - beta1) * grad_w[class_index][feature_index]
                        )
                        v_w[class_index][feature_index] = (
                            beta2 * v_w[class_index][feature_index]
                            + (1.0 - beta2) * grad_w[class_index][feature_index] ** 2
                        )
                        m_hat = m_w[class_index][feature_index] / (1.0 - beta1**step)
                        v_hat = v_w[class_index][feature_index] / (1.0 - beta2**step)
                        weights[class_index][feature_index] -= (
                            float(options.learning_rate)
                            * m_hat
                            / (math.sqrt(v_hat) + epsilon)
                        )

                    m_b[class_index] = beta1 * m_b[class_index] + (1.0 - beta1) * grad_b[class_index]
                    v_b[class_index] = beta2 * v_b[class_index] + (1.0 - beta2) * grad_b[class_index] ** 2
                    m_hat_b = m_b[class_index] / (1.0 - beta1**step)
                    v_hat_b = v_b[class_index] / (1.0 - beta2**step)
                    biases[class_index] -= (
                        float(options.learning_rate)
                        * m_hat_b
                        / (math.sqrt(v_hat_b) + epsilon)
                    )
            else:
                momentum = float(options.momentum)

                for class_index in range(k):
                    for feature_index in range(n_features):
                        m_w[class_index][feature_index] = (
                            momentum * m_w[class_index][feature_index]
                            + grad_w[class_index][feature_index]
                        )
                        weights[class_index][feature_index] -= (
                            float(options.learning_rate)
                            * m_w[class_index][feature_index]
                        )

                    m_b[class_index] = momentum * m_b[class_index] + grad_b[class_index]
                    biases[class_index] -= float(options.learning_rate) * m_b[class_index]

            if l1_strength > 0:
                shrink = float(options.learning_rate) * l1_strength

                for class_index in range(k):
                    _prox_l1(weights[class_index], shrink)

            for class_index in range(k):
                weights[class_index] = [
                    _round6(_clip_float(value, -1e6, 1e6, 0.0))
                    for value in weights[class_index]
                ]

            biases = [_round6(_clip_float(value, -1e6, 1e6, 0.0)) for value in biases]

        train_loss = _evaluate_loss_multiclass(
            x_train,
            y_train,
            w_train,
            class_weights,
            weights,
            biases,
        )
        val_loss = None

        if x_val:
            val_loss = _evaluate_loss_multiclass(
                x_val,
                y_val,
                w_val,
                class_weights,
                weights,
                biases,
            )

        history.append(
            {
                "epoch": epoch + 1,
                "step": step,
                "train_loss": train_loss,
                "val_loss": val_loss,
            }
        )

        if len(history) > options.max_history:
            history = history[-options.max_history :]

        if val_loss is not None:
            if val_loss < best_val_loss - float(options.min_delta):
                best_val_loss = val_loss
                best_weights = [list(row) for row in weights]
                best_biases = list(biases)
                patience_counter = 0
            else:
                patience_counter += 1

                if options.early_stopping and patience_counter >= int(options.patience):
                    _append_issue(
                        issues,
                        options.max_issues,
                        severity=IssueSeverity.INFO,
                        code="early_stopping_triggered",
                        message="Training stopped early based on validation loss.",
                        details={"epoch": epoch + 1, "val_loss": val_loss},
                    )
                    break

    if best_val_loss == math.inf:
        best_weights = [list(row) for row in weights]
        best_biases = list(biases)

    return (
        tuple(tuple(row) for row in best_weights),
        tuple(best_biases),
        tuple(history),
    )


# -----------------------------------------------------------------------------
# Calibration internals
# -----------------------------------------------------------------------------


def _weighted_binary_ce(
    labels: Sequence[int],
    probs: Sequence[float],
    weights: Sequence[float],
) -> Optional[float]:
    """
    Return bounded weighted binary cross-entropy.
    """
    total = 0.0
    denom = 0.0

    for label, probability, weight in zip(labels, probs, weights):
        effective = max(0.0, float(weight))

        if effective <= 0 or int(label) not in (0, 1):
            continue

        p = _clip_float(float(probability), 1e-12, 1.0 - 1e-12, 0.5)
        target = float(int(label))
        total -= effective * (target * math.log(p) + (1.0 - target) * math.log(1.0 - p))
        denom += effective

    if denom <= 0:
        return None

    return _round6(total / denom)


def _weighted_multiclass_ce_from_logits(
    logits_rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    weights: Sequence[float],
    temperature: float = 1.0,
) -> Optional[float]:
    """
    Return bounded weighted multiclass cross-entropy from logits.
    """
    total = 0.0
    denom = 0.0
    temp = _clip_float(temperature, 0.01, 100.0, 1.0)

    for logits, label, weight in zip(logits_rows, labels, weights):
        effective = max(0.0, float(weight))
        true_label = int(label)

        if effective <= 0 or true_label < 0 or true_label >= len(logits):
            continue

        probs = _softmax([float(value) / temp for value in logits])
        p = _clip_float(float(probs[true_label]), 1e-12, 1.0, 1e-12)
        total -= effective * math.log(p)
        denom += effective

    if denom <= 0:
        return None

    return _round6(total / denom)


def _fit_platt_binary(
    logits: Sequence[float],
    labels: Sequence[int],
    weights: Sequence[float],
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
) -> dict[str, Any]:
    """
    Fit bounded Platt scaling for binary models.
    """
    if not logits:
        return {"method": CalibrationMethod.NONE.value, "fitted_on_validation": False}

    positives = sum(1 for label in labels if int(label) == 1)
    negatives = sum(1 for label in labels if int(label) == 0)

    if positives <= 0 or negatives <= 0:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="platt_calibration_skipped_single_class",
            message="Platt calibration skipped because validation labels contain only one class.",
        )
        return {"method": CalibrationMethod.NONE.value, "fitted_on_validation": False}

    raw_probs = [_sigmoid(float(value)) for value in logits]
    loss_before = _weighted_binary_ce(labels, raw_probs, weights)

    a = 1.0
    b = 0.0
    learning_rate = 0.1
    iterations = max(1, int(options.calibration_iterations))

    for _ in range(iterations):
        grad_a = 0.0
        grad_b = 0.0
        denom = 0.0

        for logit, label, weight in zip(logits, labels, weights):
            effective = max(0.0, float(weight))

            if effective <= 0:
                continue

            p = _sigmoid(a * float(logit) + b)
            error = (p - float(int(label))) * effective
            denom += effective
            grad_a += error * float(logit)
            grad_b += error

        if denom <= 0:
            break

        grad_a /= denom
        grad_b /= denom

        a = _clip_float(a - learning_rate * grad_a, 0.01, 10.0, a)
        b = _clip_float(b - learning_rate * grad_b, -10.0, 10.0, b)

    calibrated_probs = [_sigmoid(a * float(logit) + b) for logit in logits]
    loss_after = _weighted_binary_ce(labels, calibrated_probs, weights)

    if (
        loss_before is None
        or loss_after is None
        or loss_after > loss_before + 1e-6
    ):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="platt_calibration_not_improving",
            message="Platt calibration did not improve validation loss and was disabled.",
            details={"loss_before": loss_before, "loss_after": loss_after},
        )
        return {"method": CalibrationMethod.NONE.value, "fitted_on_validation": True}

    return {
        "method": CalibrationMethod.PLATT.value,
        "A": _round6(a),
        "B": _round6(b),
        "loss_before": loss_before,
        "loss_after": loss_after,
        "sample_count": len(logits),
        "fitted_on_validation": True,
    }


def _temperature_grid(options: SupervisedOptions) -> tuple[float, ...]:
    """
    Return deterministic bounded temperature grid.
    """
    steps = max(5, min(50, int(options.calibration_iterations)))
    low = math.log(0.1)
    high = math.log(10.0)

    if steps == 1:
        values = [1.0]
    else:
        values = [
            _round6(math.exp(low + (high - low) * float(index) / float(steps - 1)))
            for index in range(steps)
        ]

    values.append(1.0)
    return tuple(sorted(dict.fromkeys(max(0.01, min(100.0, value)) for value in values)))


def _fit_temperature_multiclass(
    logits_rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    weights: Sequence[float],
    num_classes: int,
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
) -> dict[str, Any]:
    """
    Fit bounded temperature scaling for multiclass models.
    """
    if not logits_rows or num_classes < 2:
        return {"method": CalibrationMethod.NONE.value, "fitted_on_validation": False}

    loss_before = _weighted_multiclass_ce_from_logits(logits_rows, labels, weights, 1.0)
    best_temperature = 1.0
    best_loss = loss_before if loss_before is not None else math.inf

    for temperature in _temperature_grid(options):
        loss = _weighted_multiclass_ce_from_logits(logits_rows, labels, weights, temperature)

        if loss is None:
            continue

        if loss < best_loss - 1e-9:
            best_loss = loss
            best_temperature = temperature

    if loss_before is None or best_loss >= loss_before - 1e-6:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="temperature_calibration_not_improving",
            message="Temperature calibration did not improve validation loss and was disabled.",
            details={"loss_before": loss_before, "loss_after": best_loss},
        )
        return {"method": CalibrationMethod.NONE.value, "fitted_on_validation": True}

    return {
        "method": CalibrationMethod.TEMPERATURE.value,
        "temperature": _round6(best_temperature),
        "loss_before": loss_before,
        "loss_after": _round6(best_loss),
        "sample_count": len(logits_rows),
        "fitted_on_validation": True,
    }


def _calibrate_parameters(
    parameters: ModelParameters,
    x_val: Sequence[Sequence[float]],
    y_val_original: Sequence[int],
    w_val: Sequence[float],
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
) -> None:
    """
    Calibrate model parameters using validation data only.
    """
    parameters.calibration = {
        "method": CalibrationMethod.NONE.value,
        "fitted_on_validation": False,
    }

    if not x_val or not y_val_original:
        return

    requested_method = _normalize_enum_option(CalibrationMethod, options.calibration_method, None)

    if requested_method == CalibrationMethod.NONE:
        return

    if parameters.task == TaskType.BINARY:
        method = requested_method or CalibrationMethod.PLATT

        if method == CalibrationMethod.TEMPERATURE:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.INFO,
                code="binary_temperature_fallback",
                message="Binary temperature calibration is not supported by this bounded implementation; using Platt scaling.",
            )
            method = CalibrationMethod.PLATT

        if method != CalibrationMethod.PLATT:
            return

        positive_index = int(parameters.metadata.get("positive_class_index", 1))

        if positive_index < 0 or positive_index >= len(parameters.classes):
            positive_index = max(0, len(parameters.classes) - 1)

        positive_class = parameters.classes[positive_index]
        labels = [1 if int(code) == int(positive_class) else 0 for code in y_val_original]
        logits = [float(parameters.raw_logits(row)[0]) for row in x_val]
        parameters.calibration = _fit_platt_binary(logits, labels, w_val, options, issues)
        return

    method = requested_method or CalibrationMethod.TEMPERATURE

    if method == CalibrationMethod.PLATT:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="multiclass_platt_fallback",
            message="Multiclass Platt calibration is not supported by this bounded implementation; using temperature scaling.",
        )
        method = CalibrationMethod.TEMPERATURE

    if method != CalibrationMethod.TEMPERATURE:
        return

    class_mapping = _class_index_mapping(parameters)

    filtered_logits: list[tuple[float, ...]] = []
    filtered_labels: list[int] = []
    filtered_weights: list[float] = []

    for row, code, weight in zip(x_val, y_val_original, w_val):
        label_index = class_mapping.get(int(code))

        if label_index is None:
            continue

        filtered_logits.append(parameters.raw_logits(row))
        filtered_labels.append(int(label_index))
        filtered_weights.append(max(0.0, float(weight)))

    if not filtered_logits:
        return

    parameters.calibration = _fit_temperature_multiclass(
        filtered_logits,
        filtered_labels,
        filtered_weights,
        len(parameters.classes),
        options,
        issues,
    )


# -----------------------------------------------------------------------------
# Split resolution
# -----------------------------------------------------------------------------


def _resolve_split_indices(
    dataset: TrainingDataset,
    options: SupervisedOptions,
    issues: list[SupervisedIssue],
) -> tuple[list[int], list[int], list[int]]:
    """
    Resolve train/validation/test indices, carving internal validation if needed.
    """
    train_idx = [
        index
        for index, split in enumerate(dataset.splits)
        if split == SplitName.TRAIN.value
    ]
    val_idx = [
        index
        for index, split in enumerate(dataset.splits)
        if split == SplitName.VALIDATION.value
    ]
    test_idx = [
        index
        for index, split in enumerate(dataset.splits)
        if split == SplitName.TEST.value
    ]

    if not train_idx and dataset.y:
        train_idx = list(range(len(dataset.y)))
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="missing_train_split",
            message="No explicit training split was present; all labeled rows were used for training.",
        )

    if not val_idx and float(options.internal_validation_fraction) > 0 and len(train_idx) >= 10:
        take = max(1, int(math.floor(len(train_idx) * float(options.internal_validation_fraction))))
        order = _stable_epoch_order(train_idx, options, 10**9)
        selected_positions = set(order[:take])
        val_idx = [train_idx[position] for position in sorted(selected_positions)]
        train_idx = [
            train_idx[position]
            for position in range(len(train_idx))
            if position not in selected_positions
        ]

        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="internal_validation_carved",
            message="Internal validation split was carved deterministically from training data.",
            details={"validation_count": len(val_idx), "train_count": len(train_idx)},
        )

    return train_idx, val_idx, test_idx


def _class_index_mapping(parameters: "ModelParameters") -> dict[int, int]:
    """
    Read the model's class-code to output-index mapping as integer keys.

    Model metadata is normalized into a JSON-safe form when the model is
    built, which turns the integer class codes into strings. Every consumer
    looks the mapping up by integer code, so the coercion happens here once
    rather than being re-derived, or silently missed, at each call site.
    """
    raw = parameters.metadata.get("class_mapping")
    out: dict[int, int] = {}

    if isinstance(raw, Mapping):
        for code, index in raw.items():
            try:
                out[int(code)] = int(index)
            except (TypeError, ValueError):
                continue

    if out:
        return out

    return {int(code): index for index, code in enumerate(parameters.classes)}


def _choose_positive_class_index(
    classes: Sequence[int],
    class_names: Sequence[str],
    task: TaskType,
) -> int:
    """
    Choose the synthetic positive/investigate class index for binary tasks.
    """
    if task != TaskType.BINARY or len(classes) < 2:
        return min(1, max(0, len(classes) - 1))

    positive_aliases = {
        "review",
        "escalate",
        "positive",
        "investigate",
        "flagged_for_review",
        "high_priority",
        "critical",
        "urgent",
    }

    negative_aliases = {
        "unknown",
        "no_action",
        "negative",
        "benign",
        "clean",
        "not_investigate",
        "low",
    }

    priority = {
        "escalate": 3,
        "high_priority": 3,
        "critical": 3,
        "urgent": 3,
        "review": 2,
        "positive": 2,
        "investigate": 2,
        "flagged_for_review": 2,
        "uncertain": 1,
        "ambiguous": 1,
        "needs_human": 1,
    }

    best_index = len(classes) - 1
    best_score = -1

    for index, name in enumerate(class_names):
        token = _normalize_token(name)

        if token in negative_aliases:
            score = -1
        elif token in priority:
            score = priority[token]
        elif token in positive_aliases:
            score = 2
        else:
            score = 0

        if score > best_score:
            best_score = score
            best_index = index

    return best_index


def _class_is_positive_name(name: str) -> bool:
    """
    Return True when a class name is treated as an investigative positive class.
    """
    token = _normalize_token(name)

    return token in {
        "review",
        "escalate",
        "positive",
        "investigate",
        "flagged_for_review",
        "high_priority",
        "critical",
        "urgent",
    }


# -----------------------------------------------------------------------------
# Evaluation internals
# -----------------------------------------------------------------------------


def _predicted_class_code(
    parameters: ModelParameters,
    probs: Sequence[float],
) -> int:
    """
    Return predicted original class code.
    """
    if not parameters.classes:
        # app.ml.labels.LabelCode.UNKNOWN is 0. The guarded form here
        # referenced a name this module never imports, so the guard was
        # always False and this already returned 0 -- the reference was
        # dead weight that read like a dependency. Importing labels just
        # for a zero would couple the trainer to the label vocabulary.
        return 0

    if parameters.task == TaskType.BINARY:
        positive_index = int(parameters.metadata.get("positive_class_index", 1))

        if positive_index < 0 or positive_index >= len(parameters.classes):
            positive_index = max(0, len(parameters.classes) - 1)

        positive_class = int(parameters.classes[positive_index])
        negative_index = 0 if positive_index != 0 else 1

        if negative_index >= len(parameters.classes):
            negative_class = positive_class
        else:
            negative_class = int(parameters.classes[negative_index])

        positive_probability = _clip_float(
            _coerce_float(probs[1] if len(probs) > 1 else 0.0),
            0.0,
            1.0,
            0.0,
        )

        return positive_class if positive_probability >= float(parameters.threshold) else negative_class

    predicted_index = parameters.predict_index(probs)

    if predicted_index < 0 or predicted_index >= len(parameters.classes):
        predicted_index = 0

    return int(parameters.classes[predicted_index])


def _probability_mapping(
    parameters: ModelParameters,
    probs: Sequence[float],
) -> dict[str, float]:
    """
    Return safe probability mapping keyed by class name.
    """
    if parameters.task == TaskType.BINARY:
        positive_index = int(parameters.metadata.get("positive_class_index", 1))

        if positive_index < 0 or positive_index >= len(parameters.classes):
            positive_index = max(0, len(parameters.classes) - 1)

        positive_name = (
            parameters.class_names[positive_index]
            if positive_index < len(parameters.class_names)
            else "positive"
        )
        negative_index = 0 if positive_index != 0 else 1
        negative_name = (
            parameters.class_names[negative_index]
            if negative_index < len(parameters.class_names)
            else "negative"
        )

        positive_probability = _clip_float(
            _coerce_float(probs[1] if len(probs) > 1 else 0.0),
            0.0,
            1.0,
            0.0,
        )

        return {
            negative_name: _round6(1.0 - positive_probability),
            positive_name: _round6(positive_probability),
        }

    return {
        (
            parameters.class_names[index]
            if index < len(parameters.class_names)
            else f"class_{index}"
        ): _round6(_clip_float(_coerce_float(value), 0.0, 1.0, 0.0))
        for index, value in enumerate(probs)
    }


def _prediction_score(
    parameters: ModelParameters,
    probs: Sequence[float],
) -> float:
    """
    Return investigative priority score for one prediction.

    For binary models this is the positive-class probability.

    For multiclass models this is the summed probability of positive/investigate
    classes when available, otherwise the maximum class probability.
    """
    if not probs:
        return 0.0

    if parameters.task == TaskType.BINARY:
        return _round6(
            _clip_float(
                _coerce_float(probs[1] if len(probs) > 1 else 0.0),
                0.0,
                1.0,
                0.0,
            )
        )

    positive_total = 0.0
    max_probability = 0.0

    for index, value in enumerate(probs):
        probability = _clip_float(_coerce_float(value), 0.0, 1.0, 0.0)
        max_probability = max(max_probability, probability)

        class_name = (
            parameters.class_names[index]
            if index < len(parameters.class_names)
            else ""
        )

        if _class_is_positive_name(class_name):
            positive_total += probability

    if positive_total > 0:
        return _round6(_clip_float(positive_total, 0.0, 1.0, 0.0))

    return _round6(max_probability)


def _risk_band(score: float, thresholds: Mapping[str, float]) -> str:
    """
    Map a bounded score to an investigative risk band.
    """
    value = _clip_float(score, 0.0, 1.0, 0.0)
    critical = _clip_float(thresholds.get("critical", 0.90), 0.0, 1.0, 0.90)
    high = _clip_float(thresholds.get("high", 0.75), 0.0, 1.0, 0.75)
    medium = _clip_float(thresholds.get("medium", 0.50), 0.0, 1.0, 0.50)
    low = _clip_float(thresholds.get("low", 0.25), 0.0, 1.0, 0.25)

    if value >= critical:
        return "CRITICAL"

    if value >= high:
        return "HIGH"

    if value >= medium:
        return "MEDIUM"

    if value >= low:
        return "LOW"

    return "LOW"


def _macro_ovr_auc(
    y_idx: Sequence[int],
    probs: Sequence[Sequence[float]],
    num_classes: int,
    kind: str,
) -> Optional[float]:
    """
    Return macro one-vs-rest AUC.
    """
    values: list[float] = []

    for class_index in range(num_classes):
        labels = [1 if int(label) == class_index else 0 for label in y_idx]
        scores = [
            _clip_float(_coerce_float(row[class_index]), 0.0, 1.0, 0.0)
            for row in probs
            if class_index < len(row)
        ]

        if len(labels) != len(scores):
            continue

        value = (
            _binary_roc_auc(labels, scores)
            if kind == "roc"
            else _binary_pr_auc(labels, scores)
        )

        if value is not None:
            values.append(float(value))

    if not values:
        return None

    return _round6(sum(values) / float(len(values)))


def _reliability_binary(
    labels: Sequence[int],
    probs: Sequence[float],
    bins: int,
) -> list[dict[str, Any]]:
    """
    Return bounded binary reliability bins.
    """
    bin_count = max(2, int(bins))
    totals = [0.0 for _ in range(bin_count)]
    confidences = [0.0 for _ in range(bin_count)]
    outcomes = [0.0 for _ in range(bin_count)]

    for label, probability in zip(labels, probs):
        if int(label) not in (0, 1):
            continue

        p = _clip_float(float(probability), 0.0, 1.0, 0.0)
        index = min(bin_count - 1, int(p * bin_count))
        totals[index] += 1.0
        confidences[index] += p
        outcomes[index] += float(int(label))

    out: list[dict[str, Any]] = []

    for index in range(bin_count):
        if totals[index] <= 0:
            continue

        out.append(
            {
                "bin": index,
                "count": int(totals[index]),
                "avg_predicted": _round6(confidences[index] / totals[index]),
                "avg_observed": _round6(outcomes[index] / totals[index]),
            }
        )

    return out


def _reliability_multiclass(
    labels: Sequence[int],
    probs: Sequence[Sequence[float]],
    bins: int,
) -> list[dict[str, Any]]:
    """
    Return bounded multiclass confidence reliability bins.
    """
    bin_count = max(2, int(bins))
    totals = [0.0 for _ in range(bin_count)]
    confidences = [0.0 for _ in range(bin_count)]
    accuracies = [0.0 for _ in range(bin_count)]

    for label, row in zip(labels, probs):
        true_label = int(label)

        if true_label < 0 or true_label >= len(row):
            continue

        predicted = max(range(len(row)), key=lambda index: float(row[index]))
        confidence = _clip_float(float(row[predicted]), 0.0, 1.0, 0.0)
        index = min(bin_count - 1, int(confidence * bin_count))
        totals[index] += 1.0
        confidences[index] += confidence
        accuracies[index] += 1.0 if predicted == true_label else 0.0

    out: list[dict[str, Any]] = []

    for index in range(bin_count):
        if totals[index] <= 0:
            continue

        out.append(
            {
                "bin": index,
                "count": int(totals[index]),
                "avg_confidence": _round6(confidences[index] / totals[index]),
                "avg_accuracy": _round6(accuracies[index] / totals[index]),
            }
        )

    return out


def evaluate_model(
    model: SupervisedModel,
    dataset: TrainingDataset,
    *,
    split: str = SplitName.TEST.value,
    max_samples: Optional[int] = None,
) -> EvaluationReport:
    """
    Evaluate a supervised model on one split of a training dataset.

    This is internal-facing when used with raw datasets. Public APIs should
    expose only safe report summaries.
    """
    opts = model.options
    issues: list[SupervisedIssue] = []
    resolved_split = _normalize_split_name(split)

    indices = [
        index
        for index, item in enumerate(dataset.splits)
        if item == resolved_split
    ]

    if not indices:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="evaluation_split_unavailable",
            message="Requested evaluation split is unavailable.",
            details={"split": resolved_split},
        )
        return EvaluationReport(
            ok=False,
            model_id=model.model_id,
            split_used=resolved_split,
            counts={"samples": 0, "evaluated": 0, "skipped": 0},
            metrics={},
            class_metrics=(),
            confusion={},
            calibration={"method": str(model.parameters.calibration.get("method") or "none")},
            issues=tuple(issues),
            metadata={
                "supervised_version": SUPERVISED_VERSION,
                "caveats": list(_SUPERVISED_CAVEATS),
                "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
            },
            fingerprint="",
        )

    limit = max_samples or opts.max_samples

    if len(indices) > limit:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="evaluation_sample_truncated",
            message="Evaluation input exceeded configured sample limit and was truncated.",
            details={"submitted": len(indices), "max_samples": limit},
        )
        indices = indices[:limit]

    x_eval = [dataset.x[index] for index in indices]
    y_original = [int(dataset.y[index]) for index in indices]
    weights_eval = [float(dataset.weights[index]) for index in indices]

    probs_list: list[tuple[float, ...]] = []
    pred_codes: list[int] = []

    for row in x_eval:
        probs, _logits = model.parameters.calibrated_probs(row)
        probs_list.append(probs)
        pred_codes.append(_predicted_class_code(model.parameters, probs))

    counts = {
        "samples": len(indices),
        "evaluated": len(probs_list),
        "skipped": 0,
        "classes": len(model.parameters.classes),
    }

    if not probs_list or not model.parameters.classes:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="evaluation_no_samples",
            message="Evaluation produced no usable samples.",
        )
        return EvaluationReport(
            ok=False,
            model_id=model.model_id,
            split_used=resolved_split,
            counts=counts,
            metrics={},
            class_metrics=(),
            confusion={},
            calibration={"method": str(model.parameters.calibration.get("method") or "none")},
            issues=tuple(issues),
            metadata={
                "supervised_version": SUPERVISED_VERSION,
                "caveats": list(_SUPERVISED_CAVEATS),
                "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
            },
            fingerprint="",
        )

    metrics: dict[str, Any] = {}
    class_metrics: list[dict[str, Any]] = []
    confusion: dict[str, Any] = {}
    calibration_report: dict[str, Any] = {
        "method": str(model.parameters.calibration.get("method") or "none"),
        "fitted_on_validation": bool(model.parameters.calibration.get("fitted_on_validation", False)),
        "loss_before": model.parameters.calibration.get("loss_before"),
        "loss_after": model.parameters.calibration.get("loss_after"),
        "bins": int(opts.ece_bins),
    }

    if model.parameters.task == TaskType.BINARY:
        positive_index = int(model.parameters.metadata.get("positive_class_index", 1))

        if positive_index < 0 or positive_index >= len(model.parameters.classes):
            positive_index = max(0, len(model.parameters.classes) - 1)

        positive_class = int(model.parameters.classes[positive_index])
        negative_index = 0 if positive_index != 0 else 1
        negative_class = (
            int(model.parameters.classes[negative_index])
            if negative_index < len(model.parameters.classes)
            else positive_class
        )

        y_bin = [1 if code == positive_class else 0 for code in y_original]
        p_pos = [
            _clip_float(_coerce_float(probs[1] if len(probs) > 1 else 0.0), 0.0, 1.0, 0.0)
            for probs in probs_list
        ]
        pred_bin = [1 if probability >= float(model.parameters.threshold) else 0 for probability in p_pos]

        base = _classification_metrics(y_bin, pred_bin, 2)
        confusion_matrix = base.get("confusion", [[0, 0], [0, 0]])
        per_class = base.get("per_class", [])

        class_names_for_matrix = [
            _label_name(negative_class),
            _label_name(positive_class),
        ]
        class_codes_for_matrix = [negative_class, positive_class]

        for item in per_class:
            index = int(item.get("class_index", 0))
            enriched = dict(item)
            enriched["class_code"] = class_codes_for_matrix[index] if index < len(class_codes_for_matrix) else 0
            enriched["class_name"] = class_names_for_matrix[index] if index < len(class_names_for_matrix) else "unknown"
            class_metrics.append(enriched)

        metrics.update(
            {
                "accuracy": base.get("accuracy"),
                "precision": base.get("macro_precision"),
                "recall": base.get("macro_recall"),
                "f1": base.get("macro_f1"),
                "weighted_precision": base.get("weighted_precision"),
                "weighted_recall": base.get("weighted_recall"),
                "weighted_f1": base.get("weighted_f1"),
                "roc_auc": _binary_roc_auc(y_bin, p_pos),
                "pr_auc": _binary_pr_auc(y_bin, p_pos),
                "log_loss": _log_loss_binary(y_bin, p_pos),
                "brier_score": _brier_binary(y_bin, p_pos),
                "expected_calibration_error": _ece_binary(y_bin, p_pos, opts.ece_bins),
                "positive_class_code": positive_class,
                "negative_class_code": negative_class,
                "threshold": float(model.parameters.threshold),
            }
        )

        confusion = {
            "matrix": confusion_matrix,
            "classes": class_codes_for_matrix,
            "class_names": class_names_for_matrix,
            "normalization": "counts",
        }
        calibration_report["reliability"] = _reliability_binary(y_bin, p_pos, opts.ece_bins)
    else:
        class_mapping = _class_index_mapping(model.parameters)
        y_idx: list[int] = []
        filtered_probs: list[tuple[float, ...]] = []
        filtered_weights: list[float] = []
        skipped = 0

        for code, probs, weight in zip(y_original, probs_list, weights_eval):
            index = class_mapping.get(int(code))

            if index is None:
                skipped += 1
                continue

            y_idx.append(int(index))
            filtered_probs.append(probs)
            filtered_weights.append(max(0.0, float(weight)))

        counts["skipped"] = skipped

        if not y_idx:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="evaluation_no_mapped_classes",
                message="Evaluation samples could not be mapped to model classes.",
            )
            return EvaluationReport(
                ok=False,
                model_id=model.model_id,
                split_used=resolved_split,
                counts=counts,
                metrics={},
                class_metrics=(),
                confusion={},
                calibration=calibration_report,
                issues=tuple(issues),
                metadata={
                    "supervised_version": SUPERVISED_VERSION,
                    "caveats": list(_SUPERVISED_CAVEATS),
                    "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
                },
                fingerprint="",
            )

        pred_idx = [model.parameters.predict_index(probs) for probs in filtered_probs]
        base = _classification_metrics(y_idx, pred_idx, len(model.parameters.classes))
        confusion_matrix = base.get("confusion", [])
        per_class = base.get("per_class", [])

        for item in per_class:
            index = int(item.get("class_index", 0))
            enriched = dict(item)
            enriched["class_code"] = (
                int(model.parameters.classes[index])
                if index < len(model.parameters.classes)
                else 0
            )
            enriched["class_name"] = (
                model.parameters.class_names[index]
                if index < len(model.parameters.class_names)
                else "unknown"
            )
            class_metrics.append(enriched)

        metrics.update(
            {
                "accuracy": base.get("accuracy"),
                "micro_precision": base.get("micro_precision"),
                "micro_recall": base.get("micro_recall"),
                "micro_f1": base.get("micro_f1"),
                "macro_precision": base.get("macro_precision"),
                "macro_recall": base.get("macro_recall"),
                "macro_f1": base.get("macro_f1"),
                "weighted_precision": base.get("weighted_precision"),
                "weighted_recall": base.get("weighted_recall"),
                "weighted_f1": base.get("weighted_f1"),
                "roc_auc": _macro_ovr_auc(y_idx, filtered_probs, len(model.parameters.classes), "roc"),
                "pr_auc": _macro_ovr_auc(y_idx, filtered_probs, len(model.parameters.classes), "pr"),
                "log_loss": _log_loss_multiclass(y_idx, filtered_probs),
                "brier_score": _brier_multiclass(y_idx, filtered_probs),
                "expected_calibration_error": _ece_multiclass(y_idx, filtered_probs, opts.ece_bins),
                "threshold": float(model.parameters.threshold),
            }
        )

        confusion = {
            "matrix": confusion_matrix,
            "classes": [int(code) for code in model.parameters.classes],
            "class_names": list(model.parameters.class_names),
            "normalization": "counts",
        }
        calibration_report["reliability"] = _reliability_multiclass(
            y_idx,
            filtered_probs,
            opts.ece_bins,
        )

    unavailable = [
        key
        for key, value in metrics.items()
        if value is None
    ]

    if unavailable:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="metrics_unavailable",
            message="Some metrics are unavailable and are reported honestly as null.",
            details={"unavailable_metrics": unavailable[: opts.max_summary_items]},
        )

    ok = not any(issue.severity == IssueSeverity.ERROR for issue in issues)

    metadata = {
        "supervised_version": SUPERVISED_VERSION,
        "model_fingerprint": model.fingerprint,
        "dataset_fingerprint": dataset.fingerprint,
        "split": resolved_split,
        "calibration_method": str(model.parameters.calibration.get("method") or "none"),
        "caveats": list(_SUPERVISED_CAVEATS),
        "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
    }

    report = EvaluationReport(
        ok=ok,
        model_id=model.model_id,
        split_used=resolved_split,
        counts=counts,
        metrics=metrics,
        class_metrics=tuple(class_metrics),
        confusion=confusion,
        calibration=calibration_report,
        issues=tuple(issues),
        metadata=metadata,
        fingerprint="",
    )

    return report


# -----------------------------------------------------------------------------
# Trainer
# -----------------------------------------------------------------------------


def _empty_supervised_model(
    options: SupervisedOptions,
    issues: Sequence[SupervisedIssue],
    metadata: Optional[Mapping[str, Any]] = None,
) -> SupervisedModel:
    """
    Return a safe empty supervised model.
    """
    parameters = ModelParameters(
        feature_names=(),
        classes=(),
        class_names=(),
        task=TaskType.BINARY,
        weights=(),
        intercept=(),
        calibration={"method": CalibrationMethod.NONE.value, "fitted_on_validation": False},
        threshold=float(options.threshold),
        metadata={},
    )

    payload = {
        "supervised_version": SUPERVISED_VERSION,
        "empty_model": True,
        "options": options.safe_summary(),
        "caveats": list(_SUPERVISED_CAVEATS),
        "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
    }

    if metadata:
        payload.update(_safe_detail_value(metadata) or {})

    return SupervisedModel(
        model_id="",
        family=ModelFamily.BASELINE_PRIOR,
        task=TaskType.BINARY,
        status=ModelStatus.DRAFT,
        created_at=_now_utc(),
        options=options,
        parameters=parameters,
        training_history=(),
        metrics={},
        issues=tuple(issues),
        metadata=payload,
        fingerprint="",
    )


class SupervisedTrainer:
    """
    Bounded deterministic supervised trainer for synthetic MULEGUARD data.
    """

    def __init__(self, options: SupervisedOptions | None = None) -> None:
        self.options = options or SupervisedOptions.from_settings()

    def train(
        self,
        dataset: TrainingDataset,
        *,
        model_family: ModelFamily | str | None = None,
        task: TaskType | str | None = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> SupervisedModel:
        """
        Train one bounded supervised model from one internal training dataset.
        """
        opts = self.options
        issues: list[SupervisedIssue] = []
        start_time = time.monotonic()

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="supervised_disabled",
                message="Supervised training is disabled.",
            )
            return _empty_supervised_model(opts, issues, metadata)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Supervised training requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return _empty_supervised_model(opts, issues, metadata)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Supervised training is blocked in production-like environments.",
            )
            return _empty_supervised_model(opts, issues, metadata)

        if dataset is None or not dataset.x or not dataset.y:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="empty_training_dataset",
                message="Training dataset is empty.",
            )
            return _empty_supervised_model(opts, issues, metadata)

        feature_count = len(dataset.feature_names)
        classes = tuple(dataset.classes)

        if feature_count <= 0:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_features",
                message="Training dataset has no feature columns.",
            )
            return _empty_supervised_model(opts, issues, metadata)

        if feature_count > opts.max_features:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="too_many_features",
                message="Training dataset feature count exceeds configured maximum.",
                details={"features": feature_count, "max_features": opts.max_features},
            )
            return _empty_supervised_model(opts, issues, metadata)

        if len(classes) > opts.max_classes:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="too_many_classes",
                message="Training dataset class count exceeds configured maximum.",
                details={"classes": len(classes), "max_classes": opts.max_classes},
            )
            return _empty_supervised_model(opts, issues, metadata)

        if not classes:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_classes",
                message="Training dataset has no classes.",
            )
            return _empty_supervised_model(opts, issues, metadata)

        resolved_task = _normalize_enum_option(TaskType, task or opts.task, None)

        if resolved_task is None:
            resolved_task = TaskType.BINARY if len(classes) == 2 else TaskType.MULTICLASS

        resolved_family = _normalize_enum_option(ModelFamily, model_family or opts.model_family, None)

        if resolved_family is None:
            if len(classes) <= 1:
                resolved_family = ModelFamily.BASELINE_PRIOR
            elif resolved_task == TaskType.BINARY:
                resolved_family = ModelFamily.LOGISTIC_REGRESSION
            else:
                resolved_family = ModelFamily.SOFTMAX_REGRESSION

        train_idx, val_idx, test_idx = _resolve_split_indices(dataset, opts, issues)

        if not train_idx:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_training_samples",
                message="No training samples were available.",
            )
            return _empty_supervised_model(opts, issues, metadata)

        x_train = tuple(dataset.x[index] for index in train_idx)
        y_train_original = tuple(int(dataset.y[index]) for index in train_idx)
        w_train = tuple(float(dataset.weights[index]) for index in train_idx)

        x_val = tuple(dataset.x[index] for index in val_idx)
        y_val_original = tuple(int(dataset.y[index]) for index in val_idx)
        w_val = tuple(float(dataset.weights[index]) for index in val_idx)

        class_mapping = {int(code): index for index, code in enumerate(classes)}
        positive_index = _choose_positive_class_index(classes, dataset.class_names, resolved_task)

        if resolved_task == TaskType.BINARY:
            positive_class = int(classes[positive_index])
            y_train = tuple(1 if int(code) == positive_class else 0 for code in y_train_original)
            y_val = tuple(1 if int(code) == positive_class else 0 for code in y_val_original)
            num_outputs = 2
        else:
            y_train = tuple(int(class_mapping[int(code)]) for code in y_train_original)
            y_val = tuple(int(class_mapping[int(code)]) for code in y_val_original)
            num_outputs = len(classes)

        class_weights = _compute_class_weights(y_train, w_train, num_outputs, opts)

        if resolved_family == ModelFamily.BASELINE_PRIOR:
            if resolved_task == TaskType.BINARY:
                total = sum(max(0.0, float(weight)) for weight in w_train)
                positive_mass = sum(
                    max(0.0, float(weight))
                    for label, weight in zip(y_train, w_train)
                    if int(label) == 1
                )
                p = _clip_float(positive_mass / total if total > 0 else 0.5, 1e-6, 1.0 - 1e-6, 0.5)
                intercept = _round6(math.log(p / (1.0 - p)))
                weights = (tuple(0.0 for _ in range(feature_count)),)
                intercepts = (intercept,)
            else:
                counts = [0.0 for _ in range(num_outputs)]
                total = 0.0

                for label, weight in zip(y_train, w_train):
                    effective = max(0.0, float(weight))

                    if 0 <= int(label) < num_outputs:
                        counts[int(label)] += effective
                        total += effective

                intercepts = tuple(
                    _round6(math.log(max(count / total, 1e-6) if total > 0 else 1.0 / max(1, num_outputs)))
                    for count in counts
                )
                weights = tuple(tuple(0.0 for _ in range(feature_count)) for _ in range(num_outputs))

            history: tuple[dict[str, Any], ...] = ()
        elif resolved_task == TaskType.BINARY:
            weights, intercepts, history = _train_binary(
                x_train,
                y_train,
                w_train,
                class_weights,
                x_val,
                y_val,
                w_val,
                feature_count,
                opts,
                issues,
                start_time,
            )
        else:
            weights, intercepts, history = _train_multiclass(
                x_train,
                y_train,
                w_train,
                class_weights,
                x_val,
                y_val,
                w_val,
                feature_count,
                num_outputs,
                opts,
                issues,
                start_time,
            )

        elapsed_ms = int((time.monotonic() - start_time) * 1000.0)

        parameters = ModelParameters(
            feature_names=dataset.feature_names,
            classes=classes,
            class_names=dataset.class_names,
            task=resolved_task,
            weights=weights,
            intercept=intercepts,
            calibration={"method": CalibrationMethod.NONE.value, "fitted_on_validation": False},
            threshold=float(opts.threshold),
            metadata={
                "class_mapping": class_mapping,
                "positive_class_index": positive_index,
                "dataset_fingerprint": dataset.fingerprint,
                "feature_count": feature_count,
                "class_count": len(classes),
                "train_count": len(train_idx),
                "validation_count": len(val_idx),
                "test_count": len(test_idx),
                "training_elapsed_ms": elapsed_ms,
                "model_family": resolved_family.value,
                "task": resolved_task.value,
                "options": opts.safe_summary(),
            },
        )

        _calibrate_parameters(parameters, x_val, y_val_original, w_val, opts, issues)

        model_metadata: dict[str, Any] = {
            "supervised_version": SUPERVISED_VERSION,
            "dataset_fingerprint": dataset.fingerprint,
            "training_counts": dict(dataset.counts),
            "split_counts": {
                "train": len(train_idx),
                "validation": len(val_idx),
                "test": len(test_idx),
            },
            "training_elapsed_ms": elapsed_ms,
            "history": list(history[: opts.max_history]),
            "history_truncated": len(history) > opts.max_history,
            "options": opts.safe_summary(),
            "caller_metadata": _safe_detail_value(metadata),
            "caveats": list(_SUPERVISED_CAVEATS),
            "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
        }

        model = SupervisedModel(
            model_id="",
            family=resolved_family,
            task=resolved_task,
            status=ModelStatus.TRAINED,
            created_at=_now_utc(),
            options=opts,
            parameters=parameters,
            training_history=history,
            metrics={},
            issues=tuple(issues),
            metadata=model_metadata,
            fingerprint="",
        )

        metrics: dict[str, Any] = {}

        if val_idx:
            validation_report = evaluate_model(model, dataset, split=SplitName.VALIDATION.value)
            metrics["validation"] = validation_report.to_dict()

        if test_idx:
            test_report = evaluate_model(model, dataset, split=SplitName.TEST.value)
            metrics["test"] = test_report.to_dict()

        if metrics:
            model.status = ModelStatus.EVALUATED

        model.metrics = metrics
        model.metadata["metrics_available"] = sorted(metrics)

        if opts.register_model:
            get_model_registry().register(model)

        return model


# -----------------------------------------------------------------------------
# Prediction
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class PredictionBatch:
    """
    Safe supervised prediction batch.
    """

    ok: bool = True
    model_id: str = ""
    predictions: tuple[Prediction, ...] = ()
    counts: dict[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[SupervisedIssue, ...] = ()
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize batch values.
        """
        object.__setattr__(self, "predictions", tuple(self.predictions or ()))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "counts", dict(self.counts or {}))
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})

        if not self.fingerprint:
            payload = {
                "model_id": self.model_id,
                "count": len(self.predictions),
                "labels": [prediction.label_code for prediction in self.predictions],
                "scores": [prediction.score for prediction in self.predictions],
                "risk_bands": [prediction.risk_band for prediction in self.predictions],
            }

            try:
                object.__setattr__(self, "fingerprint", _sha256_hex(_canonical_json(payload)))
            except Exception:
                object.__setattr__(self, "fingerprint", "")

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing prediction batch summary.
        """
        return {
            "ok": self.ok,
            "model_id": self.model_id,
            "counts": dict(self.counts),
            "predictions": [prediction.to_dict() for prediction in self.predictions],
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_SUPERVISED_CAVEATS),
            "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
        }


def _feature_contributions(
    parameters: ModelParameters,
    x: Sequence[float],
    predicted_code: int,
    options: SupervisedOptions,
    enabled: bool,
) -> tuple[dict[str, Any], ...]:
    """
    Return bounded operational feature contributions for one prediction.

    These contributions are not causal proof.
    """
    if not enabled or not parameters.feature_names:
        return ()

    if parameters.task == TaskType.BINARY:
        weight_row = parameters.weights[0] if parameters.weights else ()
    else:
        class_mapping = _class_index_mapping(parameters)
        class_index = class_mapping.get(int(predicted_code))

        if class_index is None or class_index >= len(parameters.weights):
            return ()

        weight_row = parameters.weights[class_index]

    raw: list[tuple[str, float]] = []

    for name, weight, value in zip(parameters.feature_names, weight_row, x):
        try:
            contribution = float(weight) * float(value)
        except (TypeError, ValueError):
            continue

        if math.isnan(contribution) or math.isinf(contribution):
            continue

        if abs(contribution) <= 1e-12:
            continue

        raw.append((name, _round6(contribution)))

    if not raw:
        return ()

    total_abs = sum(abs(value) for _, value in raw)

    if total_abs <= 0:
        return ()

    raw.sort(key=lambda item: (-abs(item[1]), item[0]))
    limited = raw[: max(1, int(options.max_explanations))]

    out: list[dict[str, Any]] = []

    for name, contribution in limited:
        magnitude = abs(contribution) / total_abs
        signed = contribution / total_abs

        out.append(
            {
                "feature": name,
                "effect": _round6(contribution),
                "normalized_effect": _round6(signed),
                "magnitude": _round6(magnitude),
                "direction": "increase" if contribution > 0 else "decrease",
                "interpretation": "operational attribution only, not causal proof",
            }
        )

    return tuple(out)


def predict_model(
    model: SupervisedModel,
    features: Any,
    *,
    include_contributions: bool = True,
    max_predictions: Optional[int] = None,
) -> PredictionBatch:
    """
    Produce bounded investigative predictions from one supervised model.

    Predictions are investigative prioritization outputs only. They are not
    probabilities of guilt and must not trigger automatic adverse customer
    action.
    """
    opts = model.options
    issues: list[SupervisedIssue] = []
    records = _normalize_positional_records(
        _iter_records(features),
        model.parameters.feature_names,
        opts,
        issues,
    )
    submitted = len(records)
    limit = max_predictions or opts.max_samples

    if submitted > limit:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="prediction_sample_truncated",
            message="Prediction input exceeded configured sample limit and was truncated.",
            details={"submitted": submitted, "max_predictions": limit},
        )
        records = records[:limit]

    predictions: list[Prediction] = []
    rejected = 0
    feature_names = model.parameters.feature_names

    for index, record in enumerate(records):
        subject, safe_features = _extract_subject_and_features(record, opts, issues, index)

        if safe_features is None:
            rejected += 1
            continue

        row = _row_to_vector(safe_features, feature_names, opts, issues, index)

        if row is None:
            rejected += 1
            continue

        probs, logits = model.parameters.calibrated_probs(row)
        predicted_code = _predicted_class_code(model.parameters, probs)
        score = _prediction_score(model.parameters, probs)
        risk = _risk_band(score, opts.risk_thresholds)
        contributions = _feature_contributions(
            model.parameters,
            row,
            predicted_code,
            opts,
            include_contributions,
        )

        predictions.append(
            Prediction(
                subject_ref_hash=subject,
                label_code=int(predicted_code),
                label_name=_label_name(predicted_code),
                score=score,
                probabilities=_probability_mapping(model.parameters, probs),
                risk_band=risk,
                contributions=contributions,
                metadata={
                    "model_id": model.model_id,
                    "model_fingerprint": model.fingerprint,
                    "threshold": float(model.parameters.threshold),
                    "calibration_method": str(model.parameters.calibration.get("method") or "none"),
                    "raw_logit_count": len(logits),
                    "index": index,
                    "caveats": list(_SUPERVISED_CAVEATS),
                    "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
                },
            )
        )

    counts = {
        "submitted": submitted,
        "processed": len(records),
        "predicted": len(predictions),
        "rejected": rejected,
    }

    ok = not any(issue.severity == IssueSeverity.ERROR for issue in issues)

    metadata = {
        "supervised_version": SUPERVISED_VERSION,
        "model_family": model.family.value,
        "model_task": model.task.value,
        "model_status": model.status.value,
        "feature_count": len(feature_names),
        "class_count": len(model.parameters.classes),
        "options": opts.safe_summary(),
        "caveats": list(_SUPERVISED_CAVEATS),
        "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
    }

    return PredictionBatch(
        ok=ok,
        model_id=model.model_id,
        predictions=tuple(predictions),
        counts=counts,
        issues=tuple(issues),
        metadata=metadata,
        fingerprint="",
    )


# -----------------------------------------------------------------------------
# Process-local model registry
# -----------------------------------------------------------------------------


class ModelRegistry:
    """
    Bounded process-local supervised model registry.

    This registry is not durable, not distributed, and not production-ready.
    It exists only to support local prototype workflows, tests, and developer
    tooling.
    """

    def __init__(self, max_models: int = 1_000) -> None:
        self.max_models = max(1, int(max_models))
        self._models: dict[str, SupervisedModel] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, model: SupervisedModel) -> str:
        """
        Register one model and return its model id.
        """
        with self._lock:
            model_id = _clean_text(model.model_id, 128) or model.fingerprint[:32]

            if not model_id:
                model_id = _sha256_hex(str(len(self._models) + 1))[:32]

            model.model_id = model_id

            if model_id in self._models:
                self._models[model_id] = model
                return model_id

            if len(self._models) >= self.max_models:
                evict_id = self._order.pop(0) if self._order else None

                if evict_id is not None:
                    self._models.pop(evict_id, None)

            self._models[model_id] = model
            self._order.append(model_id)
            return model_id

    def get(self, model_id: Any) -> Optional[SupervisedModel]:
        """
        Return one registered model by id.
        """
        key = _clean_text(model_id, 128)

        with self._lock:
            return self._models.get(key)

    def list_ids(self) -> tuple[str, ...]:
        """
        Return registered model ids in insertion order.
        """
        with self._lock:
            return tuple(self._order)

    def summarize(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """
        Return safe registry summaries.
        """
        with self._lock:
            out: list[dict[str, Any]] = []

            for model_id in self._order[: max(1, int(limit))]:
                model = self._models.get(model_id)

                if model is None:
                    continue

                out.append(
                    {
                        "model_id": model.model_id,
                        "family": model.family.value,
                        "task": model.task.value,
                        "status": model.status.value,
                        "created_at": model.created_at.isoformat(),
                        "fingerprint": model.fingerprint,
                        "feature_count": len(model.parameters.feature_names),
                        "class_count": len(model.parameters.classes),
                        "metrics_available": sorted(model.metrics),
                    }
                )

            return out

    def clear(self) -> None:
        """
        Clear the process-local registry.
        """
        with self._lock:
            self._models.clear()
            self._order.clear()


_default_registry: Optional[ModelRegistry] = None
_default_registry_lock = threading.Lock()


def get_model_registry() -> ModelRegistry:
    """
    Return the process-wide model registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None:
            _default_registry = ModelRegistry()

        return _default_registry


def register_model(model: SupervisedModel) -> str:
    """
    Register one model in the process-local registry.
    """
    return get_model_registry().register(model)


def get_registered_model(model_id: Any) -> Optional[SupervisedModel]:
    """
    Return one registered model.
    """
    return get_model_registry().get(model_id)


def list_registered_models(*, limit: int = 50) -> list[dict[str, Any]]:
    """
    Return safe registered-model summaries.
    """
    return get_model_registry().summarize(limit=limit)


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


_default_trainer: Optional[SupervisedTrainer] = None
_default_trainer_lock = threading.Lock()


def get_supervised_trainer(
    options: SupervisedOptions | None = None,
    *,
    rebuild: bool = False,
) -> SupervisedTrainer:
    """
    Return a process-wide supervised trainer.
    """
    global _default_trainer

    with _default_trainer_lock:
        if _default_trainer is None or rebuild or options is not None:
            _default_trainer = SupervisedTrainer(options=options)

        return _default_trainer


def train_supervised_model(
    features: Any,
    labels: Any = None,
    *,
    weights: Any = None,
    splits: Any = None,
    feature_names: Optional[Sequence[str]] = None,
    options: SupervisedOptions | None = None,
    trainer: SupervisedTrainer | None = None,
    model_family: ModelFamily | str | None = None,
    task: TaskType | str | None = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> SupervisedModel:
    """
    Build a training dataset and train one bounded supervised model.
    """
    dataset = build_training_dataset(
        features,
        labels,
        weights=weights,
        splits=splits,
        feature_names=feature_names,
        options=options,
    )

    active_trainer = trainer or get_supervised_trainer(options)
    return active_trainer.train(
        dataset,
        model_family=model_family,
        task=task,
        metadata=metadata,
    )


def evaluate_supervised_model(
    model: SupervisedModel,
    dataset: TrainingDataset,
    *,
    split: str = SplitName.TEST.value,
    max_samples: Optional[int] = None,
) -> EvaluationReport:
    """
    Evaluate one supervised model on one dataset split.
    """
    return evaluate_model(model, dataset, split=split, max_samples=max_samples)


def predict_supervised_model(
    model: SupervisedModel,
    features: Any,
    *,
    include_contributions: bool = True,
    max_predictions: Optional[int] = None,
) -> PredictionBatch:
    """
    Predict with one supervised model.
    """
    return predict_model(
        model,
        features,
        include_contributions=include_contributions,
        max_predictions=max_predictions,
    )


def get_supervised_metadata() -> dict[str, Any]:
    """
    Return safe, serializable supervised ML metadata.

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
    options = SupervisedOptions.from_settings()
    registry = get_model_registry()

    return {
        "package": "muleguard.backend.ml.supervised",
        "version": SUPERVISED_VERSION,
        "tasks": [task.value for task in TaskType],
        "model_families": [family.value for family in ModelFamily],
        "optimizers": [optimizer.value for optimizer in Optimizer],
        "regularization_modes": [mode.value for mode in Regularization],
        "calibration_methods": [method.value for method in CalibrationMethod],
        "model_statuses": [status.value for status in ModelStatus],
        "default_options": options.safe_summary(),
        "registry": {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_models": registry.max_models,
            "registered_models": len(registry.list_ids()),
            "summaries": registry.summarize(limit=options.max_summary_items),
        },
        "hard_limits": {
            "max_samples": _HARD_MAX_SAMPLES,
            "max_features": _HARD_MAX_FEATURES,
            "max_cells": _HARD_MAX_CELLS,
            "max_classes": _HARD_MAX_CLASSES,
            "max_iterations": _HARD_MAX_ITERATIONS,
            "max_batch_size": _HARD_MAX_BATCH_SIZE,
            "max_minibatch_steps": _HARD_MAX_MINIBATCH_STEPS,
            "max_time_ms": _HARD_MAX_TIME_MS,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_explanations": _HARD_MAX_EXPLANATIONS,
        },
        "forbidden_supervised_field_count": len(_FORBIDDEN_SUPERVISED_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_SUPERVISED_CAVEATS),
        "safety_flags": dict(_SUPERVISED_SAFETY_FLAGS),
    }


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "CalibrationMethod",
    "EvaluationReport",
    "IssueSeverity",
    "ModelFamily",
    "ModelParameters",
    "ModelRegistry",
    "ModelStatus",
    "Optimizer",
    "Prediction",
    "PredictionBatch",
    "Regularization",
    "SplitName",
    "SupervisedIssue",
    "SupervisedModel",
    "SupervisedOptions",
    "SupervisedTrainer",
    "TaskType",
    "build_training_dataset",
    "evaluate_model",
    "evaluate_supervised_model",
    "get_model_registry",
    "get_registered_model",
    "get_supervised_metadata",
    "get_supervised_trainer",
    "list_registered_models",
    "predict_model",
    "predict_supervised_model",
    "register_model",
    "train_supervised_model",
]