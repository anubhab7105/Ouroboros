"""
MULEGUARD backend ML anomaly detection.

This module provides the canonical bounded unsupervised anomaly detection layer
for the synthetic MULEGUARD machine-learning subsystem.

Primary responsibilities:

- fit deterministic, bounded anomaly detectors from synthetic numeric feature
  matrices;
- score synthetic feature vectors using robust statistical, distance-based,
  tree-based, density-based, and subspace-residual methods;
- combine multiple detectors into a bounded ensemble with honest normalization
  and safe contribution reporting;
- enforce strict leakage resistance by rejecting ground-truth labels, injected
  scenario IDs, fraud-ring IDs, raw complaint narratives, raw identifiers,
  secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values from public summaries;
- provide bounded diagnostics, calibration, fingerprints, issue reporting, and
  safe API-facing result summaries;
- remain import-safe, dependency-light, and usable by ML services, evaluation
  harnesses, tests, seeders, offline fixtures, and developer tooling.

This module detects anomalies only. It does not train supervised models, score
accounts for adjudication, evaluate supervised models, persist data, call
external systems, authenticate users, authorize actions, deploy models, promote
models, retire models, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for anomaly fitting or scoring.
- Anomaly scores are investigative prioritization signals only. They are not
  probabilities of guilt.
- Anomaly flags are operational review prompts only. They are not proof of
  wrongdoing.
- Feature contributions are operational attributions only. They are not causal
  proof.
- Labels must never be used as anomaly features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden. Subject linkage is pseudonymous and salted.
- Anomaly handling never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable metrics are reported honestly as unavailable rather
  than invented.
- The bundled detector registry is process-local, non-durable, and bounded for
  local prototype use only.
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
- This module is not a durable model registry.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, and case dispositions are investigative leads or
human workflow artefacts only. They are not proof of wrongdoing and must not
trigger automatic adverse customer action.
"""

from __future__ import annotations

import bisect
import hashlib
import hmac
import json
import logging
import math
import random
import re
import threading
import time
import unicodedata
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError

logger = logging.getLogger("muleguard.backend.ml.anomaly")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

ANOMALY_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.anomaly.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_SAMPLES: Final[int] = 10_000
_HARD_MAX_SAMPLES: Final[int] = 100_000

_DEFAULT_MAX_FEATURES: Final[int] = 256
_HARD_MAX_FEATURES: Final[int] = 4_096

_DEFAULT_MAX_CELLS: Final[int] = 2_000_000
_HARD_MAX_CELLS: Final[int] = 50_000_000

_DEFAULT_MAX_K: Final[int] = 20
_HARD_MAX_K: Final[int] = 200

_DEFAULT_MAX_TREES: Final[int] = 100
_HARD_MAX_TREES: Final[int] = 1_000

_DEFAULT_MAX_TREE_DEPTH: Final[int] = 20
_HARD_MAX_TREE_DEPTH: Final[int] = 100

_DEFAULT_SUBSAMPLE_SIZE: Final[int] = 256
_HARD_MAX_SUBSAMPLE_SIZE: Final[int] = 4_096

_DEFAULT_MAX_STORED_ROWS: Final[int] = 2_000
_HARD_MAX_STORED_ROWS: Final[int] = 20_000

_DEFAULT_MAX_COVARIANCE_FEATURES: Final[int] = 32
_HARD_MAX_COVARIANCE_FEATURES: Final[int] = 128

_DEFAULT_MAX_PCA_FEATURES: Final[int] = 64
_HARD_MAX_PCA_FEATURES: Final[int] = 256

_DEFAULT_MAX_PCA_COMPONENTS: Final[int] = 8
_HARD_MAX_PCA_COMPONENTS: Final[int] = 64

_DEFAULT_MAX_POWER_ITERATIONS: Final[int] = 50
_HARD_MAX_POWER_ITERATIONS: Final[int] = 1_000

_DEFAULT_MAX_CALIBRATION_ROWS: Final[int] = 2_000
_HARD_MAX_CALIBRATION_ROWS: Final[int] = 20_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_TOP_CONTRIBUTIONS: Final[int] = 10
_HARD_MAX_TOP_CONTRIBUTIONS: Final[int] = 200

_DEFAULT_THRESHOLD: Final[float] = 0.80
_DEFAULT_SCORE_CLIP: Final[float] = 6.0
_DEFAULT_MIN_DELTA: Final[float] = 1e-9
_DEFAULT_RIDGE: Final[float] = 1e-4

_DEFAULT_MAX_TIME_MS: Final[int] = 15_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

_MISSING: Final[object] = object()
_EPS: Final[float] = 1e-12
_EULER_GAMMA: Final[float] = 0.5772156649015329

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

_FORBIDDEN_ANOMALY_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_ANOMALY_TOKENS: Final[tuple[str, ...]] = (
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

_ANOMALY_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic unsupervised anomaly detection only. Do not use with real customer data.",
    "Anomaly scores are investigative prioritization signals, not probabilities of guilt.",
    "Anomaly flags are operational review prompts only and are not proof of wrongdoing.",
    "Feature contributions are operational attributions only and are not causal proof.",
    "Anomaly detection must not trigger automatic adverse customer action.",
    "Labels must never be used as anomaly features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Unavailable detector scores are reported honestly as unavailable rather than invented.",
    "The bundled detector registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_ANOMALY_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_anomaly_detection": True,
        "bounded_anomaly_required": True,
        "scores_are_investigative_priority_only": True,
        "contributions_are_not_causal_proof": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class AnomalyMethod(str, Enum):
    """
    Supported bounded anomaly detector methods.
    """

    ROBUST_Z = "robust_z"
    MAHALANOBIS = "mahalanobis"
    ISOLATION_FOREST = "isolation_forest"
    LOCAL_OUTLIER_FACTOR = "local_outlier_factor"
    PCA_RESIDUAL = "pca_residual"


class EnsembleMethod(str, Enum):
    """
    Ensemble combination method.
    """

    MEAN = "mean"
    WEIGHTED_MEAN = "weighted_mean"
    MAX = "max"
    MEDIAN = "median"


class NormalizationMethod(str, Enum):
    """
    Detector score normalization method.
    """

    NONE = "none"
    QUANTILE = "quantile"
    MINMAX = "minmax"


class MissingPolicy(str, Enum):
    """
    Missing-value policy for anomaly input rows.
    """

    ERROR = "error"
    DROP_ROW = "drop_row"
    ZERO = "zero"
    MEDIAN = "median"
    MEAN = "mean"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


_ALL_ANOMALY_METHODS: Final[tuple[AnomalyMethod, ...]] = (
    AnomalyMethod.ROBUST_Z,
    AnomalyMethod.MAHALANOBIS,
    AnomalyMethod.ISOLATION_FOREST,
    AnomalyMethod.LOCAL_OUTLIER_FACTOR,
    AnomalyMethod.PCA_RESIDUAL,
)


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
    Return True when a key is forbidden for anomaly inputs.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_ANOMALY_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_ANOMALY_TOKENS)


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


def _coerce_optional_float(value: Any) -> Optional[float]:
    """
    Coerce a feature value to finite float or None.
    """
    if value is None:
        return None

    if isinstance(value, bool):
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
        return _coerce_optional_float(value.value)

    if isinstance(value, str):
        text = value.strip().replace(",", "")

        if not text:
            return None

        lowered = text.lower()

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


def _is_missing_value(value: Any) -> bool:
    """
    Return True when a raw feature value should be treated as missing.
    """
    if value is None:
        return True

    if isinstance(value, str) and not value.strip():
        return True

    numeric = _coerce_optional_float(value)
    return numeric is None


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


def _normalize_anomaly_methods(value: Any) -> tuple[AnomalyMethod, ...]:
    """
    Normalize configured anomaly methods.
    """
    if value is None:
        return _ALL_ANOMALY_METHODS

    raw_items = value if isinstance(value, (list, tuple, set)) else _csv(value)
    out: list[AnomalyMethod] = []

    for item in raw_items:
        member = _normalize_enum_option(AnomalyMethod, item, None)

        if isinstance(member, AnomalyMethod):
            out.append(member)

    if not out:
        return _ALL_ANOMALY_METHODS

    return tuple(dict.fromkeys(out))


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
    Ensure the anomaly salt is non-empty and sufficiently long.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _subject_hash(value: Any, options: "AnomalyOptions") -> Optional[str]:
    """
    Return a salted, domain-separated pseudonymous subject hash.
    """
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.anomaly.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _stable_rng(options: "AnomalyOptions", domain: str, *parts: Any) -> random.Random:
    """
    Return a deterministic random generator for one bounded operation.
    """
    seed = _stable_rank(
        options.salt,
        f"muleguard.ml.anomaly.rng.{_normalize_token(domain)}",
        options.seed,
        options.namespace,
        *parts,
    )
    return random.Random(seed)


def _deterministic_sample_indices(
    n: int,
    count: int,
    options: "AnomalyOptions",
    domain: str,
    *parts: Any,
) -> list[int]:
    """
    Return a deterministic sampled index list.
    """
    if n <= 0:
        return []

    count = max(0, min(int(count), n))

    if count >= n:
        return list(range(n))

    rng = _stable_rng(options, domain, n, count, *parts)
    return sorted(rng.sample(range(n), count))


def _mean(values: Sequence[float]) -> float:
    """
    Return arithmetic mean.
    """
    if not values:
        return 0.0

    return sum(float(value) for value in values) / float(len(values))


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


def _quantile_sorted(sorted_values: Sequence[float], q: float) -> float:
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


def _median_abs_deviation_sorted(sorted_values: Sequence[float], median_value: float) -> float:
    """
    Return median absolute deviation from sorted values.
    """
    if not sorted_values:
        return 0.0

    deviations = sorted(abs(float(value) - median_value) for value in sorted_values)
    return _quantile_sorted(deviations, 0.5)


def _euclidean_distance(left: Sequence[float], right: Sequence[float]) -> float:
    """
    Return bounded Euclidean distance.
    """
    total = 0.0

    for a, b in zip(left, right):
        try:
            delta = float(a) - float(b)
        except (TypeError, ValueError):
            delta = 0.0

        total += delta * delta

    if total <= 0 or not math.isfinite(total):
        return 0.0

    result = math.sqrt(total)
    return result if math.isfinite(result) else 0.0


def _harmonic_number(n: int) -> float:
    """
    Return approximate harmonic number.
    """
    if n <= 0:
        return 0.0

    if n < 20:
        return sum(1.0 / float(i) for i in range(1, n + 1))

    return math.log(float(n)) + _EULER_GAMMA + 1.0 / (2.0 * float(n)) - 1.0 / (12.0 * float(n) * float(n))


def _average_path_length(n: int) -> float:
    """
    Return expected unsuccessful search path length for isolation trees.
    """
    if n <= 1:
        return 0.0

    if n == 2:
        return 1.0

    return 2.0 * _harmonic_number(n - 1) - (2.0 * float(n - 1) / float(n))


def _mat_vec(mat: Sequence[Sequence[float]], vec: Sequence[float]) -> list[float]:
    """
    Return matrix-vector product.
    """
    out: list[float] = []

    for row in mat:
        total = 0.0

        for a, b in zip(row, vec):
            try:
                total += float(a) * float(b)
            except (TypeError, ValueError):
                continue

        out.append(total if math.isfinite(total) else 0.0)

    return out


def _normalize_vector(vec: Sequence[float]) -> list[float]:
    """
    Return L2-normalized vector.
    """
    norm = _l2_norm(vec)

    if norm <= 0:
        return [0.0 for _ in vec]

    return [float(value) / norm for value in vec]


def _l2_norm(vec: Sequence[float]) -> float:
    """
    Return L2 norm.
    """
    total = 0.0

    for value in vec:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = 0.0

        total += numeric * numeric

    if total <= 0 or not math.isfinite(total):
        return 0.0

    result = math.sqrt(total)
    return result if math.isfinite(result) else 0.0


def _invert_matrix(matrix: Sequence[Sequence[float]]) -> Optional[list[list[float]]]:
    """
    Invert a small square matrix using Gauss-Jordan elimination.

    Returns None when inversion fails.
    """
    n = len(matrix)

    if n <= 0:
        return None

    aug: list[list[float]] = []

    for i, row in enumerate(matrix):
        if len(row) != n:
            return None

        identity = [1.0 if i == j else 0.0 for j in range(n)]
        augmented = [float(value) if math.isfinite(float(value)) else 0.0 for value in row] + identity
        aug.append(augmented)

    for col in range(n):
        pivot_row = max(range(col, n), key=lambda r: abs(aug[r][col]))
        pivot_value = aug[pivot_row][col]

        if abs(pivot_value) < 1e-12:
            return None

        if pivot_row != col:
            aug[col], aug[pivot_row] = aug[pivot_row], aug[col]
            pivot_value = aug[col][col]

        for j in range(2 * n):
            aug[col][j] /= pivot_value

        for row in range(n):
            if row == col:
                continue

            factor = aug[row][col]

            if abs(factor) < 1e-15:
                continue

            for j in range(2 * n):
                aug[row][j] -= factor * aug[col][j]

    out: list[list[float]] = []

    for row in aug:
        inv_row = row[n:]

        if any(not math.isfinite(value) for value in inv_row):
            return None

        out.append([_round6(value) for value in inv_row])

    return out


def _append_issue(
    issues: list["AnomalyIssue"],
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

        issues[-1] = AnomalyIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        AnomalyIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _make_contribution(
    feature: str,
    effect: float,
    magnitude: float,
    method: str,
) -> dict[str, Any]:
    """
    Return one bounded operational contribution record.

    Contributions are not causal proof.
    """
    signed = _round6(effect)
    mag = _round6(max(0.0, magnitude))

    if signed > 0:
        direction = "increase"
    elif signed < 0:
        direction = "decrease"
    else:
        direction = "neutral"

    return {
        "feature": _clean_text(feature, 200),
        "effect": signed,
        "magnitude": mag,
        "direction": direction,
        "method": _clean_text(method, 100),
        "interpretation": "operational attribution only, not causal proof",
    }


def _top_contributions(
    contributions: Sequence[dict[str, Any]],
    limit: int,
) -> tuple[dict[str, Any], ...]:
    """
    Return bounded top contributions sorted by magnitude.
    """
    if not contributions:
        return ()

    ordered = sorted(
        contributions,
        key=lambda item: (
            -float(item.get("magnitude", 0.0)),
            str(item.get("feature", "")),
        ),
    )

    return tuple(ordered[: max(1, int(limit))])


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AnomalyOptions:
    """
    Bounded unsupervised anomaly detection policy.

    Hard caps prevent accidental unbounded fitting or scoring surfaces.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    methods: tuple[AnomalyMethod, ...] = _ALL_ANOMALY_METHODS
    ensemble_method: EnsembleMethod | str = EnsembleMethod.WEIGHTED_MEAN
    normalization_method: NormalizationMethod | str = NormalizationMethod.QUANTILE
    weights: Mapping[str, float] = dataclass_field(default_factory=dict)

    threshold: float = _DEFAULT_THRESHOLD
    score_clip: float = _DEFAULT_SCORE_CLIP
    missing_policy: MissingPolicy | str = MissingPolicy.MEDIAN

    max_samples: int = _DEFAULT_MAX_SAMPLES
    max_features: int = _DEFAULT_MAX_FEATURES
    max_cells: int = _DEFAULT_MAX_CELLS
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    max_k: int = _DEFAULT_MAX_K
    max_trees: int = _DEFAULT_MAX_TREES
    max_tree_depth: int = _DEFAULT_MAX_TREE_DEPTH
    subsample_size: int = _DEFAULT_SUBSAMPLE_SIZE
    max_stored_rows: int = _DEFAULT_MAX_STORED_ROWS
    max_calibration_rows: int = _DEFAULT_MAX_CALIBRATION_ROWS

    max_covariance_features: int = _DEFAULT_MAX_COVARIANCE_FEATURES
    max_pca_features: int = _DEFAULT_MAX_PCA_FEATURES
    max_pca_components: int = _DEFAULT_MAX_PCA_COMPONENTS
    max_power_iterations: int = _DEFAULT_MAX_POWER_ITERATIONS

    ridge: float = _DEFAULT_RIDGE
    top_contributions: int = _DEFAULT_TOP_CONTRIBUTIONS
    include_contributions: bool = True

    drop_forbidden_fields: bool = False
    register_model: bool = True

    risk_thresholds: Mapping[str, float] = dataclass_field(
        default_factory=lambda: {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.50,
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

        object.__setattr__(self, "methods", _normalize_anomaly_methods(self.methods))
        object.__setattr__(
            self,
            "ensemble_method",
            _normalize_enum_option(EnsembleMethod, self.ensemble_method, EnsembleMethod.WEIGHTED_MEAN),
        )
        object.__setattr__(
            self,
            "normalization_method",
            _normalize_enum_option(
                NormalizationMethod,
                self.normalization_method,
                NormalizationMethod.QUANTILE,
            ),
        )
        object.__setattr__(
            self,
            "missing_policy",
            _normalize_enum_option(MissingPolicy, self.missing_policy, MissingPolicy.MEDIAN),
        )

        weights: dict[str, float] = {}

        for raw_key, raw_value in (self.weights or {}).items():
            key = _normalize_token(raw_key)

            if not key:
                continue

            weight = _clip_float(_decimal_to_float(raw_value, 0.0), 0.0, 1000.0, 0.0)

            if weight > 0:
                weights[key] = _round6(weight)

        object.__setattr__(self, "weights", MappingProxyType(weights))

        object.__setattr__(
            self,
            "threshold",
            _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD),
        )
        object.__setattr__(
            self,
            "score_clip",
            max(0.0, _as_float(self.score_clip, _DEFAULT_SCORE_CLIP)),
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
            "max_time_ms",
            _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS),
        )

        object.__setattr__(
            self,
            "max_k",
            _clamp_int(self.max_k, 1, _HARD_MAX_K, _DEFAULT_MAX_K),
        )
        object.__setattr__(
            self,
            "max_trees",
            _clamp_int(self.max_trees, 1, _HARD_MAX_TREES, _DEFAULT_MAX_TREES),
        )
        object.__setattr__(
            self,
            "max_tree_depth",
            _clamp_int(self.max_tree_depth, 1, _HARD_MAX_TREE_DEPTH, _DEFAULT_MAX_TREE_DEPTH),
        )
        object.__setattr__(
            self,
            "subsample_size",
            _clamp_int(self.subsample_size, 2, _HARD_MAX_SUBSAMPLE_SIZE, _DEFAULT_SUBSAMPLE_SIZE),
        )
        object.__setattr__(
            self,
            "max_stored_rows",
            _clamp_int(self.max_stored_rows, 2, _HARD_MAX_STORED_ROWS, _DEFAULT_MAX_STORED_ROWS),
        )
        object.__setattr__(
            self,
            "max_calibration_rows",
            _clamp_int(
                self.max_calibration_rows,
                10,
                _HARD_MAX_CALIBRATION_ROWS,
                _DEFAULT_MAX_CALIBRATION_ROWS,
            ),
        )

        object.__setattr__(
            self,
            "max_covariance_features",
            _clamp_int(
                self.max_covariance_features,
                2,
                _HARD_MAX_COVARIANCE_FEATURES,
                _DEFAULT_MAX_COVARIANCE_FEATURES,
            ),
        )
        object.__setattr__(
            self,
            "max_pca_features",
            _clamp_int(self.max_pca_features, 2, _HARD_MAX_PCA_FEATURES, _DEFAULT_MAX_PCA_FEATURES),
        )
        object.__setattr__(
            self,
            "max_pca_components",
            _clamp_int(
                self.max_pca_components,
                1,
                _HARD_MAX_PCA_COMPONENTS,
                _DEFAULT_MAX_PCA_COMPONENTS,
            ),
        )
        object.__setattr__(
            self,
            "max_power_iterations",
            _clamp_int(
                self.max_power_iterations,
                1,
                _HARD_MAX_POWER_ITERATIONS,
                _DEFAULT_MAX_POWER_ITERATIONS,
            ),
        )

        object.__setattr__(
            self,
            "ridge",
            max(0.0, _as_float(self.ridge, _DEFAULT_RIDGE)),
        )
        object.__setattr__(
            self,
            "top_contributions",
            _clamp_int(
                self.top_contributions,
                1,
                _HARD_MAX_TOP_CONTRIBUTIONS,
                _DEFAULT_TOP_CONTRIBUTIONS,
            ),
        )
        object.__setattr__(self, "include_contributions", _as_bool(self.include_contributions, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))
        object.__setattr__(self, "register_model", _as_bool(self.register_model, True))

        thresholds = dict(self.risk_thresholds or {})
        low = _clamp_float(thresholds.get("low", 0.50), 0.0, 1.0, 0.50)
        medium = max(low, _clamp_float(thresholds.get("medium", 0.70), 0.0, 1.0, 0.70))
        high = max(medium, _clamp_float(thresholds.get("high", 0.85), 0.0, 1.0, 0.85))
        critical = max(high, _clamp_float(thresholds.get("critical", 0.95), 0.0, 1.0, 0.95))

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
    def from_settings(cls, settings: Any | None = None) -> "AnomalyOptions":
        """
        Build anomaly options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_ANOMALY_SALT", None)
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

        weights_raw = _setting(settings, "ML_ANOMALY_WEIGHTS", None)
        weights: dict[str, float] = {}

        if isinstance(weights_raw, Mapping):
            for raw_key, raw_value in weights_raw.items():
                key = _normalize_token(raw_key)
                weight = _decimal_to_float(raw_value, 0.0)

                if key and weight > 0:
                    weights[key] = weight
        else:
            for part in _csv(weights_raw):
                if "=" not in part:
                    continue

                raw_key, raw_value = part.split("=", 1)
                key = _normalize_token(raw_key)
                weight = _decimal_to_float(raw_value, 0.0)

                if key and weight > 0:
                    weights[key] = weight

        return cls(
            enabled=_as_bool(_setting(settings, "ML_ANOMALY_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_ANOMALY_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_ANOMALY_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_ANOMALY_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_ANOMALY_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            methods=_normalize_anomaly_methods(_setting(settings, "ML_ANOMALY_METHODS", None)),
            ensemble_method=str(
                _setting(settings, "ML_ANOMALY_ENSEMBLE_METHOD", EnsembleMethod.WEIGHTED_MEAN.value)
            ),
            normalization_method=str(
                _setting(settings, "ML_ANOMALY_NORMALIZATION_METHOD", NormalizationMethod.QUANTILE.value)
            ),
            weights=weights,
            threshold=_as_float(_setting(settings, "ML_ANOMALY_THRESHOLD", _DEFAULT_THRESHOLD), _DEFAULT_THRESHOLD),
            score_clip=_as_float(_setting(settings, "ML_ANOMALY_SCORE_CLIP", _DEFAULT_SCORE_CLIP), _DEFAULT_SCORE_CLIP),
            missing_policy=str(_setting(settings, "ML_ANOMALY_MISSING_POLICY", MissingPolicy.MEDIAN.value)),
            max_samples=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_SAMPLES", _DEFAULT_MAX_SAMPLES),
                _DEFAULT_MAX_SAMPLES,
            ),
            max_features=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_FEATURES", _DEFAULT_MAX_FEATURES),
                _DEFAULT_MAX_FEATURES,
            ),
            max_cells=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_CELLS", _DEFAULT_MAX_CELLS),
                _DEFAULT_MAX_CELLS,
            ),
            max_issues=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS),
                _DEFAULT_MAX_TIME_MS,
            ),
            max_k=_as_int(_setting(settings, "ML_ANOMALY_MAX_K", _DEFAULT_MAX_K), _DEFAULT_MAX_K),
            max_trees=_as_int(_setting(settings, "ML_ANOMALY_MAX_TREES", _DEFAULT_MAX_TREES), _DEFAULT_MAX_TREES),
            max_tree_depth=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_TREE_DEPTH", _DEFAULT_MAX_TREE_DEPTH),
                _DEFAULT_MAX_TREE_DEPTH,
            ),
            subsample_size=_as_int(
                _setting(settings, "ML_ANOMALY_SUBSAMPLE_SIZE", _DEFAULT_SUBSAMPLE_SIZE),
                _DEFAULT_SUBSAMPLE_SIZE,
            ),
            max_stored_rows=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_STORED_ROWS", _DEFAULT_MAX_STORED_ROWS),
                _DEFAULT_MAX_STORED_ROWS,
            ),
            max_calibration_rows=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_CALIBRATION_ROWS", _DEFAULT_MAX_CALIBRATION_ROWS),
                _DEFAULT_MAX_CALIBRATION_ROWS,
            ),
            max_covariance_features=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_COVARIANCE_FEATURES", _DEFAULT_MAX_COVARIANCE_FEATURES),
                _DEFAULT_MAX_COVARIANCE_FEATURES,
            ),
            max_pca_features=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_PCA_FEATURES", _DEFAULT_MAX_PCA_FEATURES),
                _DEFAULT_MAX_PCA_FEATURES,
            ),
            max_pca_components=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_PCA_COMPONENTS", _DEFAULT_MAX_PCA_COMPONENTS),
                _DEFAULT_MAX_PCA_COMPONENTS,
            ),
            max_power_iterations=_as_int(
                _setting(settings, "ML_ANOMALY_MAX_POWER_ITERATIONS", _DEFAULT_MAX_POWER_ITERATIONS),
                _DEFAULT_MAX_POWER_ITERATIONS,
            ),
            ridge=_as_float(_setting(settings, "ML_ANOMALY_RIDGE", _DEFAULT_RIDGE), _DEFAULT_RIDGE),
            top_contributions=_as_int(
                _setting(settings, "ML_ANOMALY_TOP_CONTRIBUTIONS", _DEFAULT_TOP_CONTRIBUTIONS),
                _DEFAULT_TOP_CONTRIBUTIONS,
            ),
            include_contributions=_as_bool(
                _setting(settings, "ML_ANOMALY_INCLUDE_CONTRIBUTIONS", True),
                True,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ML_ANOMALY_DROP_FORBIDDEN_FIELDS", False),
                False,
            ),
            register_model=_as_bool(_setting(settings, "ML_ANOMALY_REGISTER_MODEL", True), True),
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
            "methods": [method.value for method in self.methods],
            "ensemble_method": self.ensemble_method.value,
            "normalization_method": self.normalization_method.value,
            "weights": dict(self.weights),
            "threshold": round(self.threshold, 6),
            "score_clip": round(self.score_clip, 6),
            "missing_policy": self.missing_policy.value,
            "limits": {
                "max_samples": self.max_samples,
                "max_features": self.max_features,
                "max_cells": self.max_cells,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
                "max_k": self.max_k,
                "max_trees": self.max_trees,
                "max_tree_depth": self.max_tree_depth,
                "subsample_size": self.subsample_size,
                "max_stored_rows": self.max_stored_rows,
                "max_calibration_rows": self.max_calibration_rows,
                "max_covariance_features": self.max_covariance_features,
                "max_pca_features": self.max_pca_features,
                "max_pca_components": self.max_pca_components,
                "max_power_iterations": self.max_power_iterations,
                "top_contributions": self.top_contributions,
            },
            "risk_thresholds": dict(self.risk_thresholds),
            "flags": {
                "include_contributions": self.include_contributions,
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "register_model": self.register_model,
            },
        }


# -----------------------------------------------------------------------------
# Issue and score models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AnomalyIssue:
    """
    Safe anomaly issue.

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
class DetectorScore:
    """
    One detector score.
    """

    method: AnomalyMethod
    raw_score: float
    normalized_score: Optional[float] = None
    contributions: tuple[dict[str, Any], ...] = ()
    details: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize detector score values.
        """
        object.__setattr__(self, "method", _normalize_enum_option(AnomalyMethod, self.method, AnomalyMethod.ROBUST_Z))
        object.__setattr__(self, "raw_score", _round6(_clip_float(self.raw_score, 0.0, None, 0.0)))

        if self.normalized_score is not None:
            object.__setattr__(
                self,
                "normalized_score",
                _round6(_clip_float(self.normalized_score, 0.0, 1.0, 0.0)),
            )

        object.__setattr__(self, "contributions", tuple(self.contributions or ()))
        object.__setattr__(self, "details", MappingProxyType(_safe_detail_value(self.details) or {}))

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable detector score mapping.
        """
        return {
            "method": self.method.value,
            "raw_score": float(self.raw_score),
            "normalized_score": (
                float(self.normalized_score)
                if self.normalized_score is not None
                else None
            ),
            "contributions": [dict(item) for item in self.contributions],
            "details": _safe_detail_value(self.details),
        }


@dataclass(frozen=True, slots=True)
class AnomalyRecord:
    """
    One anomaly detection record.

    Records are investigative prioritization outputs only.
    """

    subject_ref_hash: Optional[str] = None
    score: float = 0.0
    risk_band: str = "LOW"
    is_anomalous: bool = False
    detector_scores: Mapping[str, float] = dataclass_field(default_factory=dict)
    contributions: tuple[dict[str, Any], ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Normalize record values.
        """
        object.__setattr__(
            self,
            "subject_ref_hash",
            _clean_text(self.subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower()
            if self.subject_ref_hash
            else None,
        )
        object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "risk_band", _clean_text(self.risk_band, 32) or "LOW")
        object.__setattr__(self, "is_anomalous", _as_bool(self.is_anomalous, False))
        object.__setattr__(
            self,
            "detector_scores",
            MappingProxyType(
                {
                    _clean_text(key, 100): _round6(_clip_float(_coerce_optional_float(value), 0.0, 1.0, 0.0))
                    for key, value in (self.detector_scores or {}).items()
                }
            ),
        )
        object.__setattr__(self, "contributions", tuple(self.contributions or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable record mapping.
        """
        return {
            "subject_ref_hash": self.subject_ref_hash,
            "score": float(self.score),
            "risk_band": self.risk_band,
            "is_anomalous": bool(self.is_anomalous),
            "detector_scores": dict(self.detector_scores),
            "contributions": [dict(item) for item in self.contributions],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_ANOMALY_CAVEATS),
            "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
        }


@dataclass(slots=True)
class AnomalyResult:
    """
    Safe anomaly detection result.
    """

    ok: bool = True
    model_id: str = ""
    records: tuple[AnomalyRecord, ...] = ()
    counts: dict[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[AnomalyIssue, ...] = ()
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize result values.
        """
        object.__setattr__(self, "records", tuple(self.records or ()))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "counts", dict(self.counts or {}))
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})

        if not self.fingerprint:
            payload = {
                "model_id": self.model_id,
                "count": len(self.records),
                "scores": [record.score for record in self.records],
                "risk_bands": [record.risk_band for record in self.records],
                "anomalous": [record.is_anomalous for record in self.records],
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
        Return a safe API-facing result summary.
        """
        return {
            "ok": self.ok,
            "model_id": self.model_id,
            "counts": dict(self.counts),
            "records": [record.to_dict() for record in self.records],
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_ANOMALY_CAVEATS),
            "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Input model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AnomalyInput:
    """
    Internal-facing bounded anomaly input.

    Public summaries must not expose rows.
    """

    feature_names: tuple[str, ...] = ()
    subjects: tuple[Optional[str], ...] = ()
    rows: tuple[tuple[Optional[float], ...], ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize input values.
        """
        feature_names = tuple(
            dict.fromkeys(
                _canonical_field_name(name)
                for name in (self.feature_names or ())
                if _canonical_field_name(name)
            )
        )

        d = len(feature_names)
        length = min(len(self.subjects or ()), len(self.rows or ()))

        subjects = tuple(
            _clean_text(subject, _MAX_SUBJECT_HASH_LENGTH).lower() if subject else None
            for subject in list(self.subjects or ())[:length]
        )

        rows: list[tuple[Optional[float], ...]] = []

        for raw_row in list(self.rows or ())[:length]:
            values = list(raw_row)[:d]
            values.extend([None] * (d - len(values)))
            rows.append(tuple(values))

        counts = dict(self.counts or {})
        counts.update(
            {
                "rows": len(rows),
                "features": d,
                "cells": len(rows) * d,
                "subjects": sum(1 for subject in subjects if subject),
            }
        )

        metadata = _safe_detail_value(self.metadata) or {}

        if not self.fingerprint:
            payload = {
                "version": ANOMALY_VERSION,
                "feature_names": list(feature_names),
                "rows": [
                    [
                        subject or "",
                        [
                            "" if value is None else f"{float(value):.6f}"
                            for value in row
                        ],
                    ]
                    for subject, row in zip(subjects, rows)
                ],
            }

            try:
                fingerprint = _sha256_hex(_canonical_json(payload))
            except Exception:
                fingerprint = _sha256_hex(str(len(rows)))
        else:
            fingerprint = _clean_text(self.fingerprint, 128)

        object.__setattr__(self, "feature_names", feature_names)
        object.__setattr__(self, "subjects", subjects)
        object.__setattr__(self, "rows", tuple(rows))
        object.__setattr__(self, "counts", MappingProxyType(counts))
        object.__setattr__(self, "metadata", MappingProxyType(metadata))
        object.__setattr__(self, "fingerprint", fingerprint)

    def __len__(self) -> int:
        """
        Return number of rows.
        """
        return len(self.rows)

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing input summary.
        """
        return {
            "feature_count": len(self.feature_names),
            "feature_names_sample": list(self.feature_names[: _DEFAULT_MAX_SUMMARY_ITEMS]),
            "feature_names_truncated": len(self.feature_names) > _DEFAULT_MAX_SUMMARY_ITEMS,
            "counts": dict(self.counts),
            "fingerprint": self.fingerprint,
            "metadata": _safe_detail_value(self.metadata),
            "rows_omitted": True,
            "caveats": list(_ANOMALY_CAVEATS),
            "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Input extraction
# -----------------------------------------------------------------------------


def _iter_anomaly_records(data: Any) -> list[Any]:
    """
    Convert flexible anomaly input into a list of row-like records.
    """
    if data is None:
        return []

    if isinstance(data, AnomalyInput):
        out: list[Any] = []

        for subject, row in zip(data.subjects, data.rows):
            record = {
                name: value
                for name, value in zip(data.feature_names, row)
            }

            if subject:
                record["subject_ref_hash"] = subject

            out.append(record)

        return out

    feature_names = getattr(data, "feature_names", None)
    rows = getattr(data, "rows", None)

    if feature_names is not None and rows is not None:
        out = []

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
    options: AnomalyOptions,
    issues: list[AnomalyIssue],
    index: int,
    allowed_names: Optional[set[str]] = None,
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

        if allowed_names is not None and canonical not in allowed_names:
            continue

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


def build_anomaly_input(
    data: Any,
    *,
    feature_names: Optional[Sequence[str]] = None,
    options: AnomalyOptions | None = None,
) -> AnomalyInput:
    """
    Build one bounded internal anomaly input from flexible data.

    This is internal-facing. Public consumers must use safe summaries only.
    """
    opts = options or AnomalyOptions.from_settings()
    issues: list[AnomalyIssue] = []

    if isinstance(data, AnomalyInput):
        if feature_names is None:
            return data

        allowed = tuple(
            dict.fromkeys(
                _canonical_field_name(name)
                for name in feature_names
                if _canonical_field_name(name)
            )
        )
        rows = [
            {
                name: row[index]
                for index, name in enumerate(data.feature_names)
                if name in set(allowed)
            }
            for row in data.rows
        ]
        data = rows
        feature_names = allowed

    records = _iter_anomaly_records(data)
    submitted = len(records)

    if submitted > opts.max_samples:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="anomaly_input_truncated",
            message="Anomaly input exceeded configured sample limit and was truncated.",
            details={"submitted": submitted, "max_samples": opts.max_samples},
        )
        records = records[: opts.max_samples]

    name_counts: dict[str, int] = defaultdict(int)
    parsed_rows: list[tuple[Optional[str], dict[str, Any]]] = []

    for index, record in enumerate(records):
        subject, safe_features = _extract_subject_and_features(
            record,
            opts,
            issues,
            index,
            allowed_names=None if feature_names is None else set(
                _canonical_field_name(name) for name in feature_names if _canonical_field_name(name)
            ),
        )

        if safe_features is None:
            continue

        parsed_rows.append((subject, safe_features))

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

    if len(parsed_rows) > max_rows_by_cells:
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="anomaly_cells_truncated",
            message="Anomaly input was truncated to satisfy maximum cell budget.",
            details={
                "submitted": len(parsed_rows),
                "max_rows_by_cells": max_rows_by_cells,
                "max_cells": opts.max_cells,
            },
        )
        parsed_rows = parsed_rows[:max_rows_by_cells]

    subjects: list[Optional[str]] = []
    rows: list[tuple[Optional[float], ...]] = []
    skipped_missing_rows = 0

    for subject, features in parsed_rows:
        row: list[Optional[float]] = []
        missing = 0

        for name in resolved_names:
            value = _coerce_optional_float(features.get(name))

            if value is None:
                missing += 1

            row.append(value)

        if missing:
            if opts.missing_policy == MissingPolicy.ERROR:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="missing_feature_value",
                    message="Row contains missing feature values under error policy.",
                    details={"missing_count": missing},
                )
                continue

            if opts.missing_policy == MissingPolicy.DROP_ROW:
                skipped_missing_rows += 1
                continue

        subjects.append(subject)
        rows.append(tuple(row))

    counts = {
        "submitted": submitted,
        "processed": len(parsed_rows),
        "rows": len(rows),
        "skipped_missing_rows": skipped_missing_rows,
        "features": len(resolved_names),
        "cells": len(rows) * len(resolved_names),
    }

    metadata: dict[str, Any] = {
        "anomaly_version": ANOMALY_VERSION,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues[: opts.max_issues]],
        "issue_count": len(issues),
        "caveats": list(_ANOMALY_CAVEATS),
        "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
    }

    return AnomalyInput(
        feature_names=resolved_names,
        subjects=tuple(subjects),
        rows=tuple(rows),
        counts=counts,
        metadata=metadata,
        fingerprint="",
    )


# -----------------------------------------------------------------------------
# Score calibration
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScoreCalibrator:
    """
    Bounded detector score calibrator.
    """

    method: NormalizationMethod
    sorted_scores: tuple[float, ...] = ()
    min_score: float = 0.0
    max_score: float = 1.0
    sample_count: int = 0
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize calibrator values.
        """
        object.__setattr__(
            self,
            "method",
            _normalize_enum_option(NormalizationMethod, self.method, NormalizationMethod.QUANTILE),
        )

        scores = tuple(
            sorted(
                _round6(_clip_float(_coerce_optional_float(value), 0.0, None, 0.0))
                for value in (self.sorted_scores or ())
                if _coerce_optional_float(value) is not None
            )
        )

        object.__setattr__(self, "sorted_scores", scores)
        object.__setattr__(self, "sample_count", len(scores))

        if scores:
            object.__setattr__(self, "min_score", float(scores[0]))
            object.__setattr__(self, "max_score", float(scores[-1]))
        else:
            object.__setattr__(self, "min_score", 0.0)
            object.__setattr__(self, "max_score", 1.0)

        if not self.fingerprint:
            payload = {
                "method": self.method.value,
                "min_score": self.min_score,
                "max_score": self.max_score,
                "sample_count": self.sample_count,
                "quantiles": [
                    _quantile_sorted(scores, q)
                    for q in (0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1.0)
                ]
                if scores
                else [],
            }

            try:
                object.__setattr__(self, "fingerprint", _sha256_hex(_canonical_json(payload)))
            except Exception:
                object.__setattr__(self, "fingerprint", "")

    @classmethod
    def fit(
        cls,
        scores: Sequence[float],
        method: NormalizationMethod | str = NormalizationMethod.QUANTILE,
    ) -> "ScoreCalibrator":
        """
        Fit one calibrator from raw detector scores.
        """
        resolved = _normalize_enum_option(NormalizationMethod, method, NormalizationMethod.QUANTILE)
        clean = [
            _round6(_clip_float(_coerce_optional_float(value), 0.0, None, 0.0))
            for value in scores
            if _coerce_optional_float(value) is not None
        ]

        return cls(
            method=resolved,
            sorted_scores=tuple(sorted(clean)),
            fingerprint="",
        )

    def transform(self, score: float) -> float:
        """
        Normalize one raw score into [0, 1].
        """
        raw = _clip_float(_coerce_optional_float(score), 0.0, None, 0.0)

        if self.method == NormalizationMethod.NONE:
            return _round6(_clip_float(raw, 0.0, 1.0, 0.0))

        if not self.sorted_scores:
            return 0.0

        if self.method == NormalizationMethod.MINMAX:
            span = self.max_score - self.min_score

            if span <= 0:
                return 0.5

            return _round6(_clip_float((raw - self.min_score) / span, 0.0, 1.0, 0.0))

        position = bisect.bisect_right(list(self.sorted_scores), raw)
        return _round6(float(position) / float(len(self.sorted_scores)))

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe calibrator summary.
        """
        return {
            "method": self.method.value,
            "sample_count": self.sample_count,
            "min_score": _round6(self.min_score),
            "max_score": _round6(self.max_score),
            "fingerprint": self.fingerprint,
        }


# -----------------------------------------------------------------------------
# Detector base protocol helpers
# -----------------------------------------------------------------------------


def _filled_row(
    row: Sequence[Optional[float]],
    fill_values: Sequence[float],
) -> tuple[float, ...]:
    """
    Return one row with missing values replaced by fitted fill values.
    """
    out: list[float] = []

    for index, value in enumerate(row):
        numeric = _coerce_optional_float(value)

        if numeric is None:
            numeric = float(fill_values[index]) if index < len(fill_values) else 0.0

        out.append(_round6(_clip_float(numeric, -1e12, 1e12, 0.0)))

    return tuple(out)


def _column_stats(
    rows: Sequence[Sequence[Optional[float]]],
    feature_count: int,
) -> tuple[tuple[float, ...], tuple[float, ...], tuple[float, ...], tuple[float, ...], tuple[int, ...]]:
    """
    Compute per-column median, MAD, mean, stddev, and missing counts.
    """
    values: list[list[float]] = [[] for _ in range(feature_count)]
    missing = [0 for _ in range(feature_count)]

    for row in rows:
        for index in range(feature_count):
            value = row[index] if index < len(row) else None
            numeric = _coerce_optional_float(value)

            if numeric is None:
                missing[index] += 1
            else:
                values[index].append(numeric)

    medians: list[float] = []
    mads: list[float] = []
    means: list[float] = []
    stds: list[float] = []

    for column in values:
        if column:
            sorted_values = sorted(column)
            median = _quantile_sorted(sorted_values, 0.5)
            mad = _median_abs_deviation_sorted(sorted_values, median)
            mean = _mean(column)
            std = _stddev(column, mean)
        else:
            median = 0.0
            mad = 0.0
            mean = 0.0
            std = 0.0

        medians.append(_round6(median))
        mads.append(_round6(mad))
        means.append(_round6(mean))
        stds.append(_round6(std))

    return (
        tuple(medians),
        tuple(mads),
        tuple(means),
        tuple(stds),
        tuple(missing),
    )


# -----------------------------------------------------------------------------
# Detectors
# -----------------------------------------------------------------------------


class BaseAnomalyDetector:
    """
    Base bounded anomaly detector.
    """

    method: AnomalyMethod = AnomalyMethod.ROBUST_Z

    def __init__(self, options: AnomalyOptions) -> None:
        self.options = options
        self.fitted = False
        self.feature_names: tuple[str, ...] = ()
        self.fill_values: tuple[float, ...] = ()

    def fit(self, feature_names: Sequence[str], rows: Sequence[Sequence[Optional[float]]]) -> None:
        """
        Fit detector state.
        """
        raise NotImplementedError

    def score(self, row: Sequence[Optional[float]]) -> DetectorScore:
        """
        Score one row.
        """
        raise NotImplementedError

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe detector summary.
        """
        return {
            "method": self.method.value,
            "fitted": bool(self.fitted),
            "feature_count": len(self.feature_names),
        }

    def fingerprint(self) -> str:
        """
        Return deterministic detector fingerprint.
        """
        payload = {
            "method": self.method.value,
            "feature_names": list(self.feature_names),
            "summary": self.safe_summary(),
        }

        try:
            return _sha256_hex(_canonical_json(payload))
        except Exception:
            return _sha256_hex(self.method.value)


class RobustZDetector(BaseAnomalyDetector):
    """
    Robust per-feature z-score anomaly detector.
    """

    method = AnomalyMethod.ROBUST_Z

    def __init__(self, options: AnomalyOptions) -> None:
        super().__init__(options)
        self.medians: tuple[float, ...] = ()
        self.mads: tuple[float, ...] = ()
        self.means: tuple[float, ...] = ()
        self.stds: tuple[float, ...] = ()
        self.missing_counts: tuple[int, ...] = ()

    def fit(self, feature_names: Sequence[str], rows: Sequence[Sequence[Optional[float]]]) -> None:
        """
        Fit robust column statistics.
        """
        names = tuple(_canonical_field_name(name) for name in feature_names if _canonical_field_name(name))
        d = len(names)

        medians, mads, means, stds, missing = _column_stats(rows, d)

        self.feature_names = names
        self.medians = medians
        self.mads = mads
        self.means = means
        self.stds = stds
        self.missing_counts = missing
        self.fill_values = medians
        self.fitted = True

    def score(self, row: Sequence[Optional[float]]) -> DetectorScore:
        """
        Score one row using robust z statistics.
        """
        if not self.fitted:
            return DetectorScore(
                method=self.method,
                raw_score=0.0,
                contributions=(),
                details={"unfitted": True},
            )

        filled = _filled_row(row, self.fill_values)
        terms: list[float] = []
        contributions: list[dict[str, Any]] = []

        for index, name in enumerate(self.feature_names):
            x = filled[index] if index < len(filled) else 0.0
            median = self.medians[index] if index < len(self.medians) else 0.0
            mad = self.mads[index] if index < len(self.mads) else 0.0
            std = self.stds[index] if index < len(self.stds) else 0.0

            scale = 1.4826 * mad if mad > 0 else std
            z = (x - median) / scale if scale > 0 else 0.0
            z = _clip_float(z, -self.options.score_clip, self.options.score_clip, 0.0)

            terms.append(z * z)
            contributions.append(
                _make_contribution(
                    feature=name,
                    effect=z,
                    magnitude=abs(z),
                    method=self.method.value,
                )
            )

        raw = math.sqrt(_mean(terms)) if terms else 0.0
        total_abs = sum(abs(float(item["effect"])) for item in contributions)

        if total_abs > 0:
            for item in contributions:
                item["magnitude"] = _round6(abs(float(item["effect"])) / total_abs)

        return DetectorScore(
            method=self.method,
            raw_score=_round6(raw),
            contributions=_top_contributions(contributions, self.options.top_contributions),
            details={
                "feature_count": len(self.feature_names),
                "score_clip": _round6(self.options.score_clip),
            },
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe detector summary.
        """
        payload = super().safe_summary()
        payload.update(
            {
                "missing_counts_sample": list(self.missing_counts[: self.options.max_summary_items]),
                "missing_counts_truncated": len(self.missing_counts) > self.options.max_summary_items,
            }
        )
        return payload


class MahalanobisDetector(BaseAnomalyDetector):
    """
    Bounded Mahalanobis-style anomaly detector.

    Uses full covariance when feasible and falls back to diagonal variance.
    """

    method = AnomalyMethod.MAHALANOBIS

    def __init__(self, options: AnomalyOptions) -> None:
        super().__init__(options)
        self.mode = "diagonal"
        self.means: tuple[float, ...] = ()
        self.variances: tuple[float, ...] = ()
        self.cov_inv: tuple[tuple[float, ...], ...] = ()

    def fit(self, feature_names: Sequence[str], rows: Sequence[Sequence[Optional[float]]]) -> None:
        """
        Fit mean and covariance or diagonal variance.
        """
        names = tuple(_canonical_field_name(name) for name in feature_names if _canonical_field_name(name))
        d = len(names)

        _, _, means, stds, _ = _column_stats(rows, d)
        variances = tuple(_round6(std * std) for std in stds)

        self.feature_names = names
        self.means = means
        self.variances = variances
        self.fill_values = means
        self.mode = "diagonal"
        self.cov_inv = ()

        if d <= 0:
            self.fitted = True
            return

        if d > self.options.max_covariance_features:
            self.fitted = True
            return

        max_rows = max(
            d + 2,
            min(
                len(rows),
                max(10, int(self.options.max_cells / max(1, d * d))),
            ),
        )

        sample_indices = _deterministic_sample_indices(
            len(rows),
            max_rows,
            self.options,
            "mahalanobis_fit",
            d,
            len(rows),
        )

        filled_rows = [_filled_row(rows[index], means) for index in sample_indices]
        n = len(filled_rows)

        if n < d + 2:
            self.fitted = True
            return

        cov = [[0.0 for _ in range(d)] for _ in range(d)]

        for row in filled_rows:
            delta = [row[i] - means[i] for i in range(d)]

            for i in range(d):
                di = delta[i]

                if di == 0.0:
                    continue

                for j in range(i, d):
                    cov[i][j] += di * delta[j]

        denom = float(max(1, n - 1))

        for i in range(d):
            for j in range(i, d):
                value = _round6(cov[i][j] / denom)
                cov[i][j] = value
                cov[j][i] = value

        trace = sum(cov[i][i] for i in range(d)) / float(d)
        ridge = max(self.options.ridge, _round6(trace * 1e-4 if trace > 0 else self.options.ridge))

        for i in range(d):
            cov[i][i] = _round6(cov[i][i] + ridge)

        inv = _invert_matrix(cov)

        if inv is not None:
            self.mode = "full"
            self.cov_inv = tuple(tuple(row) for row in inv)

        self.fitted = True

    def score(self, row: Sequence[Optional[float]]) -> DetectorScore:
        """
        Score one row using Mahalanobis distance.
        """
        if not self.fitted:
            return DetectorScore(
                method=self.method,
                raw_score=0.0,
                contributions=(),
                details={"unfitted": True},
            )

        filled = _filled_row(row, self.fill_values)
        d = len(self.feature_names)

        if d <= 0:
            return DetectorScore(method=self.method, raw_score=0.0, contributions=(), details={})

        delta = [
            (filled[i] if i < len(filled) else 0.0) - (self.means[i] if i < len(self.means) else 0.0)
            for i in range(d)
        ]

        contributions: list[dict[str, Any]] = []

        if self.mode == "full" and self.cov_inv:
            grad = [0.0 for _ in range(d)]

            for i in range(d):
                row_inv = self.cov_inv[i]
                total = 0.0

                for j in range(d):
                    total += float(row_inv[j]) * delta[j]

                grad[i] = 2.0 * total

            q = 0.5 * sum(delta[i] * grad[i] for i in range(d))

            for i, name in enumerate(self.feature_names):
                effect = delta[i] * grad[i]
                contributions.append(
                    _make_contribution(
                        feature=name,
                        effect=effect,
                        magnitude=abs(effect),
                        method=self.method.value,
                    )
                )
        else:
            q = 0.0

            for i, name in enumerate(self.feature_names):
                var = self.variances[i] if i < len(self.variances) else 0.0
                effect = (delta[i] * delta[i]) / var if var > 0 else 0.0
                q += effect
                contributions.append(
                    _make_contribution(
                        feature=name,
                        effect=effect,
                        magnitude=abs(effect),
                        method=self.method.value,
                    )
                )

        raw = math.sqrt(max(0.0, q / float(d)))
        total_abs = sum(float(item["magnitude"]) for item in contributions)

        if total_abs > 0:
            for item in contributions:
                item["magnitude"] = _round6(float(item["magnitude"]) / total_abs)

        return DetectorScore(
            method=self.method,
            raw_score=_round6(raw),
            contributions=_top_contributions(contributions, self.options.top_contributions),
            details={
                "mode": self.mode,
                "feature_count": d,
            },
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe detector summary.
        """
        payload = super().safe_summary()
        payload["mode"] = self.mode
        return payload


class IsolationForestDetector(BaseAnomalyDetector):
    """
    Bounded isolation-forest-style anomaly detector.
    """

    method = AnomalyMethod.ISOLATION_FOREST

    def __init__(self, options: AnomalyOptions) -> None:
        super().__init__(options)
        self.trees: tuple[Any, ...] = ()
        self.subsample_size = 0
        self.normalizer = 1.0

    def fit(self, feature_names: Sequence[str], rows: Sequence[Sequence[Optional[float]]]) -> None:
        """
        Fit isolation trees.
        """
        names = tuple(_canonical_field_name(name) for name in feature_names if _canonical_field_name(name))
        d = len(names)

        _, medians, _, _, _ = _column_stats(rows, d)
        fill = medians

        self.feature_names = names
        self.fill_values = fill

        n = len(rows)

        if n <= 1 or d <= 0:
            self.trees = ()
            self.subsample_size = max(2, n)
            self.normalizer = max(1.0, _average_path_length(self.subsample_size))
            self.fitted = True
            return

        subsample = max(2, min(self.options.subsample_size, n))
        self.subsample_size = subsample
        self.normalizer = max(1.0, _average_path_length(subsample))

        filled_rows = [_filled_row(row, fill) for row in rows]
        trees: list[Any] = []

        for tree_index in range(self.options.max_trees):
            indices = _deterministic_sample_indices(
                n,
                subsample,
                self.options,
                "isolation_tree_sample",
                tree_index,
                n,
                subsample,
            )

            if not indices:
                continue

            tree = self._build_tree(
                indices=indices,
                filled_rows=filled_rows,
                depth=0,
                tree_index=tree_index,
            )
            trees.append(tree)

        self.trees = tuple(trees)
        self.fitted = True

    def _build_tree(
        self,
        indices: Sequence[int],
        filled_rows: Sequence[Sequence[float]],
        depth: int,
        tree_index: int,
    ) -> Any:
        """
        Recursively build one isolation tree.
        """
        size = len(indices)

        if depth >= self.options.max_tree_depth or size <= 1:
            return ("leaf", -1, 0.0, 0.0, 0.0, None, None, size)

        d = len(self.feature_names)
        ranges: list[tuple[int, float, float]] = []

        for feature_index in range(d):
            min_value = math.inf
            max_value = -math.inf

            for row_index in indices:
                value = float(filled_rows[row_index][feature_index])

                if value < min_value:
                    min_value = value

                if value > max_value:
                    max_value = value

            if max_value > min_value:
                ranges.append((feature_index, min_value, max_value))

        if not ranges:
            return ("leaf", -1, 0.0, 0.0, 0.0, None, None, size)

        rng = _stable_rng(
            self.options,
            "isolation_tree_split",
            tree_index,
            depth,
            size,
            tuple(indices[: min(16, len(indices))]),
        )

        feature_index, min_value, max_value = rng.choice(ranges)
        split = rng.uniform(min_value, max_value)

        left = [row_index for row_index in indices if filled_rows[row_index][feature_index] < split]
        right = [row_index for row_index in indices if filled_rows[row_index][feature_index] >= split]

        if not left or not right:
            return ("leaf", -1, 0.0, min_value, max_value, None, None, size)

        return (
            "node",
            feature_index,
            _round6(split),
            _round6(min_value),
            _round6(max_value),
            self._build_tree(left, filled_rows, depth + 1, tree_index),
            self._build_tree(right, filled_rows, depth + 1, tree_index),
            size,
        )

    def score(self, row: Sequence[Optional[float]]) -> DetectorScore:
        """
        Score one row using average isolation path length.
        """
        if not self.fitted or not self.trees:
            return DetectorScore(
                method=self.method,
                raw_score=0.0,
                contributions=(),
                details={"unfitted": not self.fitted, "no_trees": not self.trees},
            )

        filled = _filled_row(row, self.fill_values)
        total_path = 0.0
        aggregated: dict[str, float] = defaultdict(float)

        for tree in self.trees:
            node = tree
            depth = 0

            while node and node[0] == "node":
                _kind, feature_index, split, low, high, left, right, _size = node
                value = filled[feature_index] if feature_index < len(filled) else 0.0

                span = max(_EPS, float(high) - float(low))
                deviation = abs(float(value) - float(split)) / span
                name = self.feature_names[feature_index] if feature_index < len(self.feature_names) else f"feature_{feature_index}"
                aggregated[name] += deviation

                if value < split:
                    node = left
                else:
                    node = right

                depth += 1

            leaf_size = node[7] if node else 1
            total_path += float(depth) + _average_path_length(int(leaf_size))

        avg_path = total_path / float(max(1, len(self.trees)))
        raw = 2.0 ** (-avg_path / self.normalizer) if self.normalizer > 0 else 0.0
        raw = _clip_float(raw, 0.0, 1.0, 0.0)

        contributions = [
            _make_contribution(
                feature=name,
                effect=value,
                magnitude=value,
                method=self.method.value,
            )
            for name, value in aggregated.items()
        ]

        total_abs = sum(float(item["magnitude"]) for item in contributions)

        if total_abs > 0:
            for item in contributions:
                item["magnitude"] = _round6(float(item["magnitude"]) / total_abs)

        return DetectorScore(
            method=self.method,
            raw_score=_round6(raw),
            contributions=_top_contributions(contributions, self.options.top_contributions),
            details={
                "tree_count": len(self.trees),
                "subsample_size": self.subsample_size,
                "normalizer": _round6(self.normalizer),
            },
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe detector summary.
        """
        payload = super().safe_summary()
        payload.update(
            {
                "tree_count": len(self.trees),
                "subsample_size": self.subsample_size,
                "normalizer": _round6(self.normalizer),
            }
        )
        return payload


class LocalOutlierFactorDetector(BaseAnomalyDetector):
    """
    Bounded local-outlier-factor-style anomaly detector.
    """

    method = AnomalyMethod.LOCAL_OUTLIER_FACTOR

    def __init__(self, options: AnomalyOptions) -> None:
        super().__init__(options)
        self.stored_rows: tuple[tuple[float, ...], ...] = ()
        self.k_distances: tuple[float, ...] = ()
        self.k = 0
        self.medians: tuple[float, ...] = ()
        self.scales: tuple[float, ...] = ()

    def fit(self, feature_names: Sequence[str], rows: Sequence[Sequence[Optional[float]]]) -> None:
        """
        Fit stored normalized rows and k-distances.
        """
        names = tuple(_canonical_field_name(name) for name in feature_names if _canonical_field_name(name))
        d = len(names)

        medians, mads, means, stds, _ = _column_stats(rows, d)
        scales = tuple(
            _round6(1.4826 * mad if mad > 0 else std if std > 0 else 1.0)
            for mad, std in zip(mads, stds)
        )

        self.feature_names = names
        self.medians = medians
        self.scales = scales
        self.fill_values = medians

        if d <= 0 or not rows:
            self.stored_rows = ()
            self.k_distances = ()
            self.k = 0
            self.fitted = True
            return

        max_by_cells = max(
            10,
            int(math.sqrt(max(1, self.options.max_cells) / float(max(1, d)))),
        )
        stored_limit = max(10, min(self.options.max_stored_rows, max_by_cells, len(rows)))

        sample_indices = _deterministic_sample_indices(
            len(rows),
            stored_limit,
            self.options,
            "lof_store",
            d,
            len(rows),
            stored_limit,
        )

        stored: list[tuple[float, ...]] = []

        for index in sample_indices:
            raw = rows[index]
            normalized: list[float] = []

            for feature_index in range(d):
                value = _coerce_optional_float(raw[feature_index] if feature_index < len(raw) else None)

                if value is None:
                    value = medians[feature_index]

                scale = scales[feature_index] if feature_index < len(scales) else 1.0
                normalized.append(_round6((float(value) - medians[feature_index]) / scale if scale > 0 else 0.0))

            stored.append(tuple(normalized))

        n = len(stored)
        k = max(1, min(self.options.max_k, n - 1)) if n > 1 else 0

        k_distances = [0.0 for _ in range(n)]

        if k > 0:
            for i in range(n):
                distances: list[float] = []

                for j in range(n):
                    if i == j:
                        continue

                    distances.append(_euclidean_distance(stored[i], stored[j]))

                distances.sort()
                k_distances[i] = _round6(distances[k - 1] if k - 1 < len(distances) else 0.0)

        self.stored_rows = tuple(stored)
        self.k_distances = tuple(k_distances)
        self.k = k
        self.fitted = True

    def _normalize_row(self, row: Sequence[Optional[float]]) -> tuple[float, ...]:
        """
        Normalize one row using fitted robust scale.
        """
        d = len(self.feature_names)
        out: list[float] = []

        for index in range(d):
            value = _coerce_optional_float(row[index] if index < len(row) else None)

            if value is None:
                value = self.medians[index] if index < len(self.medians) else 0.0

            scale = self.scales[index] if index < len(self.scales) else 1.0
            median = self.medians[index] if index < len(self.medians) else 0.0
            out.append(_round6((float(value) - median) / scale if scale > 0 else 0.0))

        return tuple(out)

    def score(self, row: Sequence[Optional[float]]) -> DetectorScore:
        """
        Score one row using approximate LOF.
        """
        if not self.fitted or not self.stored_rows or self.k <= 0:
            return DetectorScore(
                method=self.method,
                raw_score=0.0,
                contributions=(),
                details={"unfitted": not self.fitted, "no_stored_rows": not self.stored_rows},
            )

        normalized = self._normalize_row(row)
        distances: list[tuple[float, int]] = []

        for index, stored in enumerate(self.stored_rows):
            distances.append((_euclidean_distance(normalized, stored), index))

        distances.sort(key=lambda item: (item[0], item[1]))
        neighbors = distances[: self.k]

        if not neighbors:
            return DetectorScore(method=self.method, raw_score=0.0, contributions=(), details={})

        reachabilities: list[float] = []
        neighbor_densities: list[float] = []

        for distance, neighbor_index in neighbors:
            kdist = self.k_distances[neighbor_index] if neighbor_index < len(self.k_distances) else 0.0
            reach = max(float(kdist), float(distance))
            reachabilities.append(reach)
            neighbor_densities.append(1.0 / (float(kdist) + _EPS))

        own_reach = _mean(reachabilities)
        own_density = 1.0 / (own_reach + _EPS)
        avg_neighbor_density = _mean(neighbor_densities)

        lof = avg_neighbor_density / own_density if own_density > 0 else 0.0
        raw = _clip_float(lof, 0.0, None, 0.0)

        centroid = [0.0 for _ in range(len(normalized))]

        for distance, neighbor_index in neighbors:
            stored = self.stored_rows[neighbor_index]

            for feature_index, value in enumerate(stored):
                centroid[feature_index] += float(value)

        count = float(len(neighbors))

        if count > 0:
            centroid = [value / count for value in centroid]

        contributions: list[dict[str, Any]] = []

        for feature_index, name in enumerate(self.feature_names):
            own = float(normalized[feature_index]) if feature_index < len(normalized) else 0.0
            center = float(centroid[feature_index]) if feature_index < len(centroid) else 0.0
            diff = own - center
            contributions.append(
                _make_contribution(
                    feature=name,
                    effect=diff,
                    magnitude=abs(diff),
                    method=self.method.value,
                )
            )

        total_abs = sum(float(item["magnitude"]) for item in contributions)

        if total_abs > 0:
            for item in contributions:
                item["magnitude"] = _round6(float(item["magnitude"]) / total_abs)

        return DetectorScore(
            method=self.method,
            raw_score=_round6(raw),
            contributions=_top_contributions(contributions, self.options.top_contributions),
            details={
                "stored_rows": len(self.stored_rows),
                "k": self.k,
            },
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe detector summary.
        """
        payload = super().safe_summary()
        payload.update(
            {
                "stored_rows": len(self.stored_rows),
                "k": self.k,
            }
        )
        return payload


class PCAResidualDetector(BaseAnomalyDetector):
    """
    Bounded PCA-residual anomaly detector using power iteration.
    """

    method = AnomalyMethod.PCA_RESIDUAL

    def __init__(self, options: AnomalyOptions) -> None:
        super().__init__(options)
        self.means: tuple[float, ...] = ()
        self.components: tuple[tuple[float, ...], ...] = ()
        self.explained_variance: tuple[float, ...] = ()

    def fit(self, feature_names: Sequence[str], rows: Sequence[Sequence[Optional[float]]]) -> None:
        """
        Fit PCA components when bounded dimensions permit.
        """
        names = tuple(_canonical_field_name(name) for name in feature_names if _canonical_field_name(name))
        d = len(names)

        _, medians, means, _, _ = _column_stats(rows, d)

        self.feature_names = names
        self.means = means
        self.fill_values = medians
        self.components = ()
        self.explained_variance = ()

        if d <= 0 or d > self.options.max_pca_features or len(rows) < 3:
            self.fitted = True
            return

        max_rows = max(
            3,
            min(
                len(rows),
                max(10, int(self.options.max_cells / max(1, d * d))),
            ),
        )

        sample_indices = _deterministic_sample_indices(
            len(rows),
            max_rows,
            self.options,
            "pca_fit",
            d,
            len(rows),
            max_rows,
        )

        centered: list[list[float]] = []

        for index in sample_indices:
            filled = _filled_row(rows[index], medians)
            centered.append([filled[i] - means[i] for i in range(d)])

        if len(centered) < 3:
            self.fitted = True
            return

        cov = [[0.0 for _ in range(d)] for _ in range(d)]

        for row in centered:
            for i in range(d):
                di = row[i]

                if di == 0.0:
                    continue

                for j in range(i, d):
                    cov[i][j] += di * row[j]

        denom = float(len(centered) - 1)

        for i in range(d):
            for j in range(i, d):
                value = _round6(cov[i][j] / denom)
                cov[i][j] = value
                cov[j][i] = value

        trace = sum(cov[i][i] for i in range(d)) / float(d)
        ridge = max(self.options.ridge, _round6(trace * 1e-4 if trace > 0 else self.options.ridge))

        for i in range(d):
            cov[i][i] = _round6(cov[i][i] + ridge)

        components: list[tuple[float, ...]] = []
        explained: list[float] = []
        rng = _stable_rng(self.options, "pca_init", d, len(centered))

        work = [list(row) for row in cov]

        for _ in range(min(self.options.max_pca_components, d)):
            vector = [rng.gauss(0.0, 1.0) for _ in range(d)]
            vector = _normalize_vector(vector)

            eigenvalue = 0.0

            for _iteration in range(self.options.max_power_iterations):
                multiplied = _mat_vec(work, vector)
                new_vector = _normalize_vector(multiplied)
                eigenvalue = _dot_product(multiplied, vector)

                if _vector_distance(vector, new_vector) < 1e-7:
                    vector = new_vector
                    break

                vector = new_vector

            if eigenvalue <= 0 or not math.isfinite(eigenvalue):
                break

            components.append(tuple(_round6(value) for value in vector))
            explained.append(_round6(eigenvalue))

            for i in range(d):
                vi = vector[i]

                if vi == 0.0:
                    continue

                for j in range(d):
                    work[i][j] = _round6(work[i][j] - eigenvalue * vi * vector[j])

        self.components = tuple(components)
        self.explained_variance = tuple(explained)
        self.fitted = True

    def score(self, row: Sequence[Optional[float]]) -> DetectorScore:
        """
        Score one row using PCA reconstruction residual.
        """
        if not self.fitted:
            return DetectorScore(
                method=self.method,
                raw_score=0.0,
                contributions=(),
                details={"unfitted": True},
            )

        d = len(self.feature_names)

        if d <= 0:
            return DetectorScore(method=self.method, raw_score=0.0, contributions=(), details={})

        filled = _filled_row(row, self.fill_values)
        delta = [
            (filled[i] if i < len(filled) else 0.0) - (self.means[i] if i < len(self.means) else 0.0)
            for i in range(d)
        ]

        if not self.components:
            raw = 0.0
            contributions = [
                _make_contribution(
                    feature=name,
                    effect=value,
                    magnitude=abs(value),
                    method=self.method.value,
                )
                for name, value in zip(self.feature_names, delta)
            ]
        else:
            projection = [0.0 for _ in range(d)]

            for component in self.components:
                coeff = _dot_product(component, delta)

                for i in range(d):
                    projection[i] += coeff * component[i]

            residual = [delta[i] - projection[i] for i in range(d)]
            delta_norm = _l2_norm(delta)
            residual_norm = _l2_norm(residual)
            raw = residual_norm / delta_norm if delta_norm > 0 else 0.0

            contributions = [
                _make_contribution(
                    feature=name,
                    effect=value,
                    magnitude=abs(value),
                    method=self.method.value,
                )
                for name, value in zip(self.feature_names, residual)
            ]

        total_abs = sum(float(item["magnitude"]) for item in contributions)

        if total_abs > 0:
            for item in contributions:
                item["magnitude"] = _round6(float(item["magnitude"]) / total_abs)

        return DetectorScore(
            method=self.method,
            raw_score=_round6(_clip_float(raw, 0.0, 1.0, 0.0)),
            contributions=_top_contributions(contributions, self.options.top_contributions),
            details={
                "component_count": len(self.components),
                "explained_variance_sample": list(self.explained_variance[: self.options.max_summary_items]),
            },
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe detector summary.
        """
        payload = super().safe_summary()
        payload.update(
            {
                "component_count": len(self.components),
                "explained_variance_sample": list(self.explained_variance[: self.options.max_summary_items]),
                "explained_variance_truncated": len(self.explained_variance) > self.options.max_summary_items,
            }
        )
        return payload


def _dot_product(left: Sequence[float], right: Sequence[float]) -> float:
    """
    Return dot product.
    """
    total = 0.0

    for a, b in zip(left, right):
        try:
            total += float(a) * float(b)
        except (TypeError, ValueError):
            continue

    return total if math.isfinite(total) else 0.0


def _vector_distance(left: Sequence[float], right: Sequence[float]) -> float:
    """
    Return L2 distance between vectors.
    """
    return _euclidean_distance(left, right)


_DETECTOR_CLASSES: Final[Mapping[AnomalyMethod, type[BaseAnomalyDetector]]] = MappingProxyType(
    {
        AnomalyMethod.ROBUST_Z: RobustZDetector,
        AnomalyMethod.MAHALANOBIS: MahalanobisDetector,
        AnomalyMethod.ISOLATION_FOREST: IsolationForestDetector,
        AnomalyMethod.LOCAL_OUTLIER_FACTOR: LocalOutlierFactorDetector,
        AnomalyMethod.PCA_RESIDUAL: PCAResidualDetector,
    }
)


# -----------------------------------------------------------------------------
# Anomaly model
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class AnomalyModel:
    """
    Bounded deterministic unsupervised anomaly model.

    This model is internal-facing. Public summaries must not expose raw feature
    values, subject-label pairs, raw identifiers, raw narratives, secrets,
    tokens, passwords, database URLs, filesystem paths, or model artifact paths.
    """

    model_id: str = ""
    options: AnomalyOptions = dataclass_field(default_factory=AnomalyOptions)
    feature_names: tuple[str, ...] = ()
    detectors: tuple[BaseAnomalyDetector, ...] = ()
    calibrators: Mapping[str, ScoreCalibrator] = dataclass_field(default_factory=dict)
    fitted: bool = False
    fitted_at: datetime = dataclass_field(default_factory=_now_utc)
    issues: tuple[AnomalyIssue, ...] = ()
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """
        Normalize model values and compute missing identity fields.
        """
        object.__setattr__(
            self,
            "options",
            self.options if isinstance(self.options, AnomalyOptions) else AnomalyOptions.from_settings(),
        )
        object.__setattr__(
            self,
            "feature_names",
            tuple(
                _canonical_field_name(name)
                for name in (self.feature_names or ())
                if _canonical_field_name(name)
            ),
        )
        object.__setattr__(self, "detectors", tuple(self.detectors or ()))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "fitted_at", _ensure_utc(self.fitted_at) or _now_utc())
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})

        calibrators: dict[str, ScoreCalibrator] = {}

        for raw_key, raw_value in (self.calibrators or {}).items():
            key = _normalize_token(raw_key)

            if not key:
                continue

            if isinstance(raw_value, ScoreCalibrator):
                calibrators[key] = raw_value

        object.__setattr__(self, "calibrators", MappingProxyType(calibrators))

        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", self._compute_fingerprint())

        if not self.model_id:
            object.__setattr__(self, "model_id", self.fingerprint[:32])

    def _compute_fingerprint(self) -> str:
        """
        Return deterministic model fingerprint.

        The fingerprint commits to options, feature names, detector identities,
        calibrator identities, and safe metadata. It does not expose raw feature
        values or subject hashes.
        """
        payload = {
            "version": ANOMALY_VERSION,
            "options": self.options.safe_summary(),
            "feature_names": list(self.feature_names),
            "fitted": bool(self.fitted),
            "detectors": [
                {
                    "method": detector.method.value,
                    "fingerprint": detector.fingerprint(),
                    "summary": detector.safe_summary(),
                }
                for detector in self.detectors
            ],
            "calibrators": {
                key: calibrator.safe_summary()
                for key, calibrator in sorted(self.calibrators.items())
            },
            "metadata": _safe_detail_value(self.metadata),
        }

        try:
            return _sha256_hex(_canonical_json(payload))
        except Exception:
            return _sha256_hex(f"{ANOMALY_VERSION}|{len(self.feature_names)}|{len(self.detectors)}")

    def _risk_band(self, score: float) -> str:
        """
        Map a bounded ensemble score to an investigative risk band.
        """
        value = _clip_float(score, 0.0, 1.0, 0.0)
        thresholds = self.options.risk_thresholds

        critical = _clip_float(thresholds.get("critical", 0.95), 0.0, 1.0, 0.95)
        high = _clip_float(thresholds.get("high", 0.85), 0.0, 1.0, 0.85)
        medium = _clip_float(thresholds.get("medium", 0.70), 0.0, 1.0, 0.70)
        low = _clip_float(thresholds.get("low", 0.50), 0.0, 1.0, 0.50)

        if value >= critical:
            return "CRITICAL"

        if value >= high:
            return "HIGH"

        if value >= medium:
            return "MEDIUM"

        if value >= low:
            return "LOW"

        return "LOW"

    def _combine_detector_scores(self, scores: Mapping[str, float]) -> float:
        """
        Combine normalized detector scores into one bounded ensemble score.
        """
        if not scores:
            return 0.0

        values = [
            _clip_float(_coerce_optional_float(value), 0.0, 1.0, 0.0)
            for value in scores.values()
        ]

        if not values:
            return 0.0

        method = self.options.ensemble_method

        if method == EnsembleMethod.MAX:
            return _round6(max(values))

        if method == EnsembleMethod.MEDIAN:
            ordered = sorted(values)
            mid = len(ordered) // 2

            if len(ordered) % 2 == 1:
                return _round6(ordered[mid])

            return _round6((ordered[mid - 1] + ordered[mid]) / 2.0)

        if method == EnsembleMethod.WEIGHTED_MEAN:
            total_weight = 0.0
            total = 0.0

            for key, value in scores.items():
                weight = max(0.0, float(self.options.weights.get(key, 1.0)))
                numeric = _clip_float(_coerce_optional_float(value), 0.0, 1.0, 0.0)
                total += numeric * weight
                total_weight += weight

            if total_weight <= 0:
                return _round6(_mean(values))

            return _round6(total / total_weight)

        return _round6(_mean(values))

    def fit(
        self,
        data: Any,
        *,
        feature_names: Optional[Sequence[str]] = None,
    ) -> "AnomalyModel":
        """
        Fit anomaly detectors from bounded synthetic input.

        This is internal-facing. Public consumers should use safe summaries only.
        """
        opts = self.options
        issues: list[AnomalyIssue] = []
        start_time = time.monotonic()

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="anomaly_disabled",
                message="Anomaly detection is disabled.",
            )
            self.detectors = ()
            self.calibrators = MappingProxyType({})
            self.feature_names = ()
            self.fitted = True
            self.fitted_at = _now_utc()
            self.issues = tuple(issues)
            self.metadata = {
                "anomaly_version": ANOMALY_VERSION,
                "options": opts.safe_summary(),
                "fitted": True,
                "disabled": True,
                "caveats": list(_ANOMALY_CAVEATS),
                "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
            }
            object.__setattr__(self, "fingerprint", self._compute_fingerprint())
            object.__setattr__(self, "model_id", self.fingerprint[:32])
            return self

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Anomaly fitting requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            self.detectors = ()
            self.calibrators = MappingProxyType({})
            self.feature_names = ()
            self.fitted = True
            self.fitted_at = _now_utc()
            self.issues = tuple(issues)
            self.metadata = {
                "anomaly_version": ANOMALY_VERSION,
                "options": opts.safe_summary(),
                "fitted": True,
                "invalid": True,
                "caveats": list(_ANOMALY_CAVEATS),
                "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
            }
            object.__setattr__(self, "fingerprint", self._compute_fingerprint())
            object.__setattr__(self, "model_id", self.fingerprint[:32])
            return self

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Anomaly fitting is blocked in production-like environments.",
            )
            self.detectors = ()
            self.calibrators = MappingProxyType({})
            self.feature_names = ()
            self.fitted = True
            self.fitted_at = _now_utc()
            self.issues = tuple(issues)
            self.metadata = {
                "anomaly_version": ANOMALY_VERSION,
                "options": opts.safe_summary(),
                "fitted": True,
                "invalid": True,
                "caveats": list(_ANOMALY_CAVEATS),
                "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
            }
            object.__setattr__(self, "fingerprint", self._compute_fingerprint())
            object.__setattr__(self, "model_id", self.fingerprint[:32])
            return self

        anomaly_input = (
            data
            if isinstance(data, AnomalyInput)
            else build_anomaly_input(data, feature_names=feature_names, options=opts)
        )

        if not anomaly_input.rows:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="empty_anomaly_input",
                message="Anomaly fitting input is empty.",
            )
            self.detectors = ()
            self.calibrators = MappingProxyType({})
            self.feature_names = anomaly_input.feature_names
            self.fitted = True
            self.fitted_at = _now_utc()
            self.issues = tuple(issues)
            self.metadata = {
                "anomaly_version": ANOMALY_VERSION,
                "options": opts.safe_summary(),
                "input": anomaly_input.to_public_dict(),
                "fitted": True,
                "invalid": True,
                "caveats": list(_ANOMALY_CAVEATS),
                "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
            }
            object.__setattr__(self, "fingerprint", self._compute_fingerprint())
            object.__setattr__(self, "model_id", self.fingerprint[:32])
            return self

        detectors: list[BaseAnomalyDetector] = []

        for method in opts.methods:
            if (time.monotonic() - start_time) * 1000.0 > float(opts.max_time_ms):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="fit_time_budget_exhausted",
                    message="Anomaly fitting stopped after reaching configured time budget.",
                    details={
                        "remaining_methods": [
                            candidate.value
                            for candidate in opts.methods
                            if candidate not in {detector.method for detector in detectors}
                        ]
                    },
                )
                break

            detector_cls = _DETECTOR_CLASSES.get(method)

            if detector_cls is None:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="unsupported_anomaly_method",
                    message="Anomaly method is unsupported and was skipped.",
                    field=method.value,
                )
                continue

            detector = detector_cls(opts)

            try:
                detector.fit(anomaly_input.feature_names, anomaly_input.rows)
            except Exception as exc:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="detector_fit_failed",
                    message="Anomaly detector failed to fit and was skipped.",
                    field=method.value,
                    details={"exception_type": type(exc).__name__},
                )
                logger.debug(
                    "Anomaly detector fit failure for %s: %s",
                    method.value,
                    type(exc).__name__,
                    exc_info=True,
                )
                continue

            if detector.fitted:
                detectors.append(detector)

        if not detectors:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_fitted_detectors",
                message="No anomaly detectors were fitted successfully.",
            )

        calibrators: dict[str, ScoreCalibrator] = {}
        calibration_indices = _deterministic_sample_indices(
            len(anomaly_input.rows),
            min(len(anomaly_input.rows), opts.max_calibration_rows),
            opts,
            "calibration_rows",
            len(anomaly_input.rows),
        )

        for detector in detectors:
            raw_scores: list[float] = []

            for index in calibration_indices:
                try:
                    score = detector.score(anomaly_input.rows[index])
                except Exception:
                    continue

                raw_scores.append(float(score.raw_score))

            calibrators[detector.method.value] = ScoreCalibrator.fit(
                raw_scores,
                opts.normalization_method,
            )

        elapsed_ms = int((time.monotonic() - start_time) * 1000.0)

        self.feature_names = anomaly_input.feature_names
        self.detectors = tuple(detectors)
        self.calibrators = MappingProxyType(calibrators)
        self.fitted = True
        self.fitted_at = _now_utc()
        self.issues = tuple(issues)
        self.metadata = {
            "anomaly_version": ANOMALY_VERSION,
            "options": opts.safe_summary(),
            "input": anomaly_input.to_public_dict(),
            "input_fingerprint": anomaly_input.fingerprint,
            "fitted": True,
            "fitted_at": self.fitted_at.isoformat(),
            "fit_elapsed_ms": elapsed_ms,
            "detector_count": len(detectors),
            "calibrator_count": len(calibrators),
            "issues": [issue.to_dict() for issue in issues[: opts.max_issues]],
            "issue_count": len(issues),
            "caveats": list(_ANOMALY_CAVEATS),
            "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
        }

        object.__setattr__(self, "fingerprint", self._compute_fingerprint())
        object.__setattr__(self, "model_id", self.fingerprint[:32])

        if opts.register_model:
            get_anomaly_registry().register(self)

        return self

    def score(
        self,
        data: Any,
        *,
        feature_names: Optional[Sequence[str]] = None,
        include_contributions: Optional[bool] = None,
    ) -> AnomalyResult:
        """
        Score bounded synthetic input using this fitted anomaly model.

        Scores are investigative prioritization signals only. They are not
        probabilities of guilt and must not trigger automatic adverse customer
        action.
        """
        opts = self.options
        issues: list[AnomalyIssue] = []
        start_time = time.monotonic()

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="anomaly_disabled",
                message="Anomaly detection is disabled.",
            )
            return AnomalyResult(
                ok=True,
                model_id=self.model_id,
                records=(),
                counts={"submitted": 0, "scored": 0, "rejected": 0, "detectors": len(self.detectors)},
                issues=tuple(issues),
                metadata={
                    "anomaly_version": ANOMALY_VERSION,
                    "model_id": self.model_id,
                    "model_fingerprint": self.fingerprint,
                    "disabled": True,
                    "caveats": list(_ANOMALY_CAVEATS),
                    "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
                },
                fingerprint="",
            )

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Anomaly scoring requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return AnomalyResult(
                ok=False,
                model_id=self.model_id,
                records=(),
                counts={"submitted": 0, "scored": 0, "rejected": 0, "detectors": len(self.detectors)},
                issues=tuple(issues),
                metadata={
                    "anomaly_version": ANOMALY_VERSION,
                    "model_id": self.model_id,
                    "model_fingerprint": self.fingerprint,
                    "invalid": True,
                    "caveats": list(_ANOMALY_CAVEATS),
                    "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
                },
                fingerprint="",
            )

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Anomaly scoring is blocked in production-like environments.",
            )
            return AnomalyResult(
                ok=False,
                model_id=self.model_id,
                records=(),
                counts={"submitted": 0, "scored": 0, "rejected": 0, "detectors": len(self.detectors)},
                issues=tuple(issues),
                metadata={
                    "anomaly_version": ANOMALY_VERSION,
                    "model_id": self.model_id,
                    "model_fingerprint": self.fingerprint,
                    "invalid": True,
                    "caveats": list(_ANOMALY_CAVEATS),
                    "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
                },
                fingerprint="",
            )

        if not self.fitted:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="auto_fit_unfitted_model",
                message="Anomaly model was unfitted and was auto-fitted on scoring input.",
            )
            self.fit(data, feature_names=feature_names)

        resolved_feature_names = feature_names or self.feature_names or None

        anomaly_input = (
            data
            if isinstance(data, AnomalyInput)
            else build_anomaly_input(
                data,
                feature_names=resolved_feature_names,
                options=opts,
            )
        )

        if not anomaly_input.rows:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="empty_scoring_input",
                message="Anomaly scoring input is empty.",
            )
            return AnomalyResult(
                ok=True,
                model_id=self.model_id,
                records=(),
                counts={
                    "submitted": anomaly_input.counts.get("submitted", 0),
                    "processed": 0,
                    "scored": 0,
                    "rejected": 0,
                    "detectors": len(self.detectors),
                },
                issues=tuple(issues),
                metadata={
                    "anomaly_version": ANOMALY_VERSION,
                    "model_id": self.model_id,
                    "model_fingerprint": self.fingerprint,
                    "input_fingerprint": anomaly_input.fingerprint,
                    "empty_input": True,
                    "caveats": list(_ANOMALY_CAVEATS),
                    "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
                },
                fingerprint="",
            )

        records: list[AnomalyRecord] = []
        rejected = 0
        include = opts.include_contributions if include_contributions is None else bool(include_contributions)

        for index, (subject, row) in enumerate(zip(anomaly_input.subjects, anomaly_input.rows)):
            if (time.monotonic() - start_time) * 1000.0 > float(opts.max_time_ms):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="score_time_budget_exhausted",
                    message="Anomaly scoring stopped after reaching configured time budget.",
                    details={
                        "processed": len(records),
                        "remaining": max(0, len(anomaly_input.rows) - index),
                    },
                )
                break

            detector_scores: dict[str, float] = {}
            aggregated: dict[str, dict[str, Any]] = defaultdict(
                lambda: {"effect": 0.0, "magnitude": 0.0, "methods": set()}
            )

            for detector in self.detectors:
                try:
                    score = detector.score(row)
                except Exception as exc:
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="detector_score_failed",
                        message="Anomaly detector failed to score row and was skipped.",
                        field=detector.method.value,
                        details={
                            "index": index,
                            "exception_type": type(exc).__name__,
                        },
                    )
                    continue

                calibrator = self.calibrators.get(detector.method.value)

                if calibrator is not None:
                    normalized = calibrator.transform(score.raw_score)
                else:
                    normalized = _clip_float(score.raw_score, 0.0, 1.0, 0.0)

                detector_scores[detector.method.value] = _round6(normalized)

                if include:
                    weight = max(
                        0.01,
                        float(self.options.weights.get(detector.method.value, 1.0)),
                    ) * max(0.0, normalized)

                    for contribution in score.contributions:
                        feature = str(contribution.get("feature", ""))

                        if not feature:
                            continue

                        bucket = aggregated[feature]
                        bucket["effect"] += float(contribution.get("effect", 0.0)) * weight
                        bucket["magnitude"] += float(contribution.get("magnitude", 0.0)) * weight
                        bucket["methods"].add(str(contribution.get("method", detector.method.value)))

            combined = self._combine_detector_scores(detector_scores)
            risk = self._risk_band(combined)
            is_anomalous = combined >= float(opts.threshold)

            contributions: list[dict[str, Any]] = []
            total_magnitude = sum(float(item["magnitude"]) for item in aggregated.values())

            for feature, item in aggregated.items():
                magnitude = float(item["magnitude"])
                normalized_magnitude = magnitude / total_magnitude if total_magnitude > 0 else 0.0
                contributions.append(
                    _make_contribution(
                        feature=feature,
                        effect=float(item["effect"]),
                        magnitude=normalized_magnitude,
                        method=",".join(sorted(item["methods"])) or "ensemble",
                    )
                )

            records.append(
                AnomalyRecord(
                    subject_ref_hash=subject,
                    score=combined,
                    risk_band=risk,
                    is_anomalous=is_anomalous,
                    detector_scores=detector_scores,
                    contributions=_top_contributions(contributions, opts.top_contributions),
                    metadata={
                        "model_id": self.model_id,
                        "model_fingerprint": self.fingerprint,
                        "threshold": _round6(opts.threshold),
                        "ensemble_method": opts.ensemble_method.value,
                        "normalization_method": opts.normalization_method.value,
                        "detector_count": len(self.detectors),
                        "index": index,
                        "caveats": list(_ANOMALY_CAVEATS),
                        "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
                    },
                )
            )

        counts = {
            "submitted": int(anomaly_input.counts.get("submitted", len(anomaly_input.rows))),
            "processed": len(anomaly_input.rows),
            "scored": len(records),
            "rejected": rejected,
            "anomalous": sum(1 for record in records if record.is_anomalous),
            "detectors": len(self.detectors),
        }

        ok = not any(issue.severity == IssueSeverity.ERROR for issue in issues)

        metadata = {
            "anomaly_version": ANOMALY_VERSION,
            "model_id": self.model_id,
            "model_fingerprint": self.fingerprint,
            "input_fingerprint": anomaly_input.fingerprint,
            "feature_count": len(self.feature_names),
            "detector_count": len(self.detectors),
            "options": opts.safe_summary(),
            "score_elapsed_ms": int((time.monotonic() - start_time) * 1000.0),
            "caveats": list(_ANOMALY_CAVEATS),
            "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
        }

        return AnomalyResult(
            ok=ok,
            model_id=self.model_id,
            records=tuple(records),
            counts=counts,
            issues=tuple(issues),
            metadata=metadata,
            fingerprint="",
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe model summary.

        This does not include raw feature values, subject hashes, or detector
        internal row stores.
        """
        feature_sample = list(self.feature_names[: self.options.max_summary_items])

        return {
            "model_id": self.model_id,
            "fingerprint": self.fingerprint,
            "fitted": bool(self.fitted),
            "fitted_at": self.fitted_at.isoformat(),
            "options": self.options.safe_summary(),
            "feature_count": len(self.feature_names),
            "feature_names_sample": feature_sample,
            "feature_names_truncated": len(self.feature_names) > len(feature_sample),
            "detector_count": len(self.detectors),
            "detectors": [
                {
                    "method": detector.method.value,
                    "fitted": bool(detector.fitted),
                    "feature_count": len(detector.feature_names),
                    "summary": detector.safe_summary(),
                    "fingerprint": detector.fingerprint(),
                }
                for detector in self.detectors
            ],
            "calibrators": {
                key: calibrator.safe_summary()
                for key, calibrator in sorted(self.calibrators.items())
            },
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_ANOMALY_CAVEATS),
            "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
        }

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return safe API-facing model summary.
        """
        return self.safe_summary()

    def to_internal_dict(self) -> dict[str, Any]:
        """
        Return fuller internal model representation.

        This remains safe in the sense that it does not expose raw feature
        values or subject-label pairs, but it may expose detector summaries and
        fitted statistics. Use with care.
        """
        payload = self.safe_summary()
        payload["internal_only"] = True
        return payload


# -----------------------------------------------------------------------------
# Process-local anomaly registry
# -----------------------------------------------------------------------------


class AnomalyRegistry:
    """
    Bounded process-local anomaly model registry.

    This registry is not durable, not distributed, and not production-ready.
    It exists only to support local prototype workflows, tests, and developer
    tooling.
    """

    def __init__(self, max_models: int = 1_000) -> None:
        self.max_models = max(1, int(max_models))
        self._models: dict[str, AnomalyModel] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, model: AnomalyModel) -> str:
        """
        Register one anomaly model and return its model id.
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

    def get(self, model_id: Any) -> Optional[AnomalyModel]:
        """
        Return one registered anomaly model by id.
        """
        key = _clean_text(model_id, 128)

        with self._lock:
            return self._models.get(key)

    def list_ids(self) -> tuple[str, ...]:
        """
        Return registered anomaly model ids in insertion order.
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
                        "fingerprint": model.fingerprint,
                        "fitted": bool(model.fitted),
                        "fitted_at": model.fitted_at.isoformat(),
                        "feature_count": len(model.feature_names),
                        "detector_count": len(model.detectors),
                        "detectors": [detector.method.value for detector in model.detectors],
                        "calibrator_count": len(model.calibrators),
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


_default_registry: Optional[AnomalyRegistry] = None
_default_registry_lock = threading.Lock()


def get_anomaly_registry() -> AnomalyRegistry:
    """
    Return the process-wide anomaly registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None:
            _default_registry = AnomalyRegistry()

        return _default_registry


def register_anomaly_model(model: AnomalyModel) -> str:
    """
    Register one anomaly model in the process-local registry.
    """
    return get_anomaly_registry().register(model)


def get_registered_anomaly_model(model_id: Any) -> Optional[AnomalyModel]:
    """
    Return one registered anomaly model.
    """
    return get_anomaly_registry().get(model_id)


def list_registered_anomaly_models(*, limit: int = 50) -> list[dict[str, Any]]:
    """
    Return safe registered anomaly model summaries.
    """
    return get_anomaly_registry().summarize(limit=limit)


# -----------------------------------------------------------------------------
# Default model and public API
# -----------------------------------------------------------------------------


_default_model: Optional[AnomalyModel] = None
_default_model_lock = threading.Lock()


def get_anomaly_model(
    options: AnomalyOptions | None = None,
    *,
    rebuild: bool = False,
) -> AnomalyModel:
    """
    Return a process-wide anomaly model.

    If options are supplied or rebuild is True, a new model is created and
    becomes the default.
    """
    global _default_model

    with _default_model_lock:
        if _default_model is None or rebuild or options is not None:
            _default_model = AnomalyModel(options=options or AnomalyOptions.from_settings())

        return _default_model


def fit_anomaly_model(
    data: Any,
    options: AnomalyOptions | None = None,
    *,
    model: AnomalyModel | None = None,
    feature_names: Optional[Sequence[str]] = None,
) -> AnomalyModel:
    """
    Fit one bounded anomaly model from synthetic input.
    """
    active_model = model or get_anomaly_model(options)
    return active_model.fit(data, feature_names=feature_names)


def score_anomaly_model(
    model: AnomalyModel,
    data: Any,
    *,
    feature_names: Optional[Sequence[str]] = None,
    include_contributions: Optional[bool] = None,
) -> AnomalyResult:
    """
    Score synthetic input using one fitted anomaly model.
    """
    return model.score(
        data,
        feature_names=feature_names,
        include_contributions=include_contributions,
    )


def detect_anomalies(
    data: Any,
    options: AnomalyOptions | None = None,
    *,
    model: AnomalyModel | None = None,
    feature_names: Optional[Sequence[str]] = None,
    include_contributions: Optional[bool] = None,
) -> AnomalyResult:
    """
    Fit if needed and score synthetic input for anomalies.

    This convenience helper is suitable for tests, prototypes, and offline
    fixtures. For production-like workflows, fit and score should be separated
    and governed by reviewed experiment tracking.
    """
    active_model = model or get_anomaly_model(options)

    if not active_model.fitted:
        active_model.fit(data, feature_names=feature_names)

    return active_model.score(
        data,
        feature_names=feature_names or active_model.feature_names or None,
        include_contributions=include_contributions,
    )


def get_anomaly_metadata() -> dict[str, Any]:
    """
    Return safe, serializable anomaly ML metadata.

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
    options = AnomalyOptions.from_settings()
    registry = get_anomaly_registry()

    return {
        "package": "muleguard.backend.ml.anomaly",
        "version": ANOMALY_VERSION,
        "methods": [method.value for method in AnomalyMethod],
        "ensemble_methods": [method.value for method in EnsembleMethod],
        "normalization_methods": [method.value for method in NormalizationMethod],
        "missing_policies": [policy.value for policy in MissingPolicy],
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
            "max_k": _HARD_MAX_K,
            "max_trees": _HARD_MAX_TREES,
            "max_tree_depth": _HARD_MAX_TREE_DEPTH,
            "max_stored_rows": _HARD_MAX_STORED_ROWS,
            "max_calibration_rows": _HARD_MAX_CALIBRATION_ROWS,
            "max_covariance_features": _HARD_MAX_COVARIANCE_FEATURES,
            "max_pca_features": _HARD_MAX_PCA_FEATURES,
            "max_pca_components": _HARD_MAX_PCA_COMPONENTS,
            "max_power_iterations": _HARD_MAX_POWER_ITERATIONS,
            "max_time_ms": _HARD_MAX_TIME_MS,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "top_contributions": _HARD_MAX_TOP_CONTRIBUTIONS,
        },
        "forbidden_anomaly_field_count": len(_FORBIDDEN_ANOMALY_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_ANOMALY_CAVEATS),
        "safety_flags": dict(_ANOMALY_SAFETY_FLAGS),
    }


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "AnomalyInput",
    "AnomalyIssue",
    "AnomalyMethod",
    "AnomalyModel",
    "AnomalyOptions",
    "AnomalyRecord",
    "AnomalyRegistry",
    "AnomalyResult",
    "BaseAnomalyDetector",
    "DetectorScore",
    "EnsembleMethod",
    "IsolationForestDetector",
    "IssueSeverity",
    "LocalOutlierFactorDetector",
    "MahalanobisDetector",
    "MissingPolicy",
    "NormalizationMethod",
    "PCAResidualDetector",
    "RobustZDetector",
    "ScoreCalibrator",
    "build_anomaly_input",
    "detect_anomalies",
    "fit_anomaly_model",
    "get_anomaly_metadata",
    "get_anomaly_model",
    "get_anomaly_registry",
    "get_registered_anomaly_model",
    "list_registered_anomaly_models",
    "register_anomaly_model",
    "score_anomaly_model",
]