"""
MULEGUARD backend ML evaluation.

This module provides the canonical bounded evaluation orchestration layer for
the synthetic MULEGUARD machine-learning subsystem.

Primary responsibilities:

- evaluate fitted synthetic supervised, anomaly, fallback, hybrid, or external
  prediction artefacts against held-out labelled or unlabelled synthetic data;
- compute honest, bounded classification, ranking, calibration, distribution,
  threshold, slice, and stability summaries;
- enforce strict separation between selection data and reporting data wherever
  split metadata is available;
- support threshold sweeps and operating-point selection using validation data
  only when validation data is present;
- support bounded slice analysis without exposing raw feature values,
  subject-label pairs, raw identifiers, or raw narratives;
- support bounded paired model comparison using deterministic bootstrap
  intervals;
- reject leakage-prone feature inputs such as ground-truth labels, injected
  scenario IDs, fraud-ring IDs, raw complaint narratives, raw identifiers,
  secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values from public summaries;
- provide safe artifacts, fingerprints, issue reporting, phase records, and
  API-facing summaries;
- remain import-safe, dependency-light, and resilient when optional ML
  submodules are unavailable.

This module evaluates synthetic model outputs only. It does not train models,
deploy models, persist durable artefacts, call external systems, authenticate
users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for evaluation.
- Synthetic labels are evaluation fixtures only. They are not proof of
  wrongdoing.
- Labels must never be used as features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone feature inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden feature inputs. Subject linkage is pseudonymous
  and salted.
- Model probabilities, anomaly scores, fallback scores, and evaluation metrics
  are investigative prioritisation artefacts only. They are not probabilities
  of guilt.
- Feature contributions are operational attributions only. They are not causal
  proof.
- Evaluation outputs are investigative leads only.
- Evaluation handling never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable metrics are reported honestly as unavailable rather
  than invented.
- The bundled evaluation registry is process-local, non-durable, and bounded
  for local prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external model runtimes.
- This module does not deploy, promote to production serving, retire from
  production serving, upload, replace, or execute external models.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable experiment tracker or model registry.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, evaluation
metrics, and case dispositions are investigative leads or human workflow
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
import time
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError

logger = logging.getLogger("muleguard.backend.ml.evaluate")


# -----------------------------------------------------------------------------
# Optional ML submodule imports
# -----------------------------------------------------------------------------


try:
    from app.ml import anomaly as anomaly_module
except Exception:  # pragma: no cover - resilience for partial deployments
    anomaly_module = None  # type: ignore[assignment]

try:
    from app.ml import fallback as fallback_module
except Exception:  # pragma: no cover
    fallback_module = None  # type: ignore[assignment]

try:
    from app.ml import labels as labels_module
except Exception:  # pragma: no cover
    labels_module = None  # type: ignore[assignment]

try:
    from app.ml import model_service as model_service_module
except Exception:  # pragma: no cover
    model_service_module = None  # type: ignore[assignment]

try:
    from app.ml import preprocessing as preprocessing_module
except Exception:  # pragma: no cover
    preprocessing_module = None  # type: ignore[assignment]

try:
    from app.ml import splits as splits_module
except Exception:  # pragma: no cover
    splits_module = None  # type: ignore[assignment]

try:
    from app.ml import supervised as supervised_module
except Exception:  # pragma: no cover
    supervised_module = None  # type: ignore[assignment]


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

EVALUATION_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.evaluate.default.salt"
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

_DEFAULT_MAX_SLICES: Final[int] = 100
_HARD_MAX_SLICES: Final[int] = 1_000

_DEFAULT_MAX_SLICE_GROUPS: Final[int] = 64
_HARD_MAX_SLICE_GROUPS: Final[int] = 1_000

_DEFAULT_MIN_SLICE_COUNT: Final[int] = 10

_DEFAULT_MAX_THRESHOLD_POINTS: Final[int] = 200
_HARD_MAX_THRESHOLD_POINTS: Final[int] = 2_000

_DEFAULT_MAX_BOOTSTRAP_ITERATIONS: Final[int] = 200
_HARD_MAX_BOOTSTRAP_ITERATIONS: Final[int] = 5_000

_DEFAULT_MAX_CANDIDATES: Final[int] = 10
_HARD_MAX_CANDIDATES: Final[int] = 100

_DEFAULT_MAX_PAIRWISE: Final[int] = 45
_HARD_MAX_PAIRWISE: Final[int] = 1_000

_DEFAULT_MAX_ARTIFACTS: Final[int] = 20
_HARD_MAX_ARTIFACTS: Final[int] = 200

_DEFAULT_MAX_PHASES: Final[int] = 25
_HARD_MAX_PHASES: Final[int] = 200

_DEFAULT_MAX_JOBS: Final[int] = 1_000
_HARD_MAX_JOBS: Final[int] = 10_000

_DEFAULT_THRESHOLD: Final[float] = 0.50
_DEFAULT_ECE_BINS: Final[int] = 10

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

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

_FORBIDDEN_EVAL_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_EVAL_TOKENS: Final[tuple[str, ...]] = (
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

_DEFAULT_POSITIVE_LABEL_CODES: Final[tuple[int, ...]] = (2, 3)
_DEFAULT_NEGATIVE_LABEL_CODES: Final[tuple[int, ...]] = (1,)
_DEFAULT_IGNORE_LABEL_CODES: Final[tuple[int, ...]] = (0,)

_EVALUATION_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML evaluation only. Do not use with real customer data.",
    "Evaluation metrics and model scores are investigative prioritisation artefacts only and are not proof of wrongdoing.",
    "Model, anomaly, and fallback scores are not probabilities of guilt.",
    "Feature contributions are operational attributions only and are not causal proof.",
    "Evaluation must not trigger automatic adverse customer action.",
    "Labels must never be used as features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected as features.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Unavailable metrics are reported honestly as unavailable rather than invented.",
    "Threshold selection uses validation data when available and reports when selection data is unavailable.",
    "The bundled evaluation registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_EVALUATION_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_evaluation": True,
        "bounded_evaluation_required": True,
        "scores_are_investigative_priority_only": True,
        "contributions_are_not_causal_proof": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class EvaluationTarget(str, Enum):
    """
    Evaluation target.
    """

    AUTO = "auto"
    SUPERVISED = "supervised"
    ANOMALY = "anomaly"
    FALLBACK = "fallback"
    HYBRID = "hybrid"
    EXTERNAL = "external"


class EvaluationSplit(str, Enum):
    """
    Canonical evaluation split.
    """

    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    ALL = "all"


class EvaluationStatus(str, Enum):
    """
    Evaluation job status.
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    DEGRADED = "DEGRADED"


class EvaluationPhase(str, Enum):
    """
    Evaluation job phase.
    """

    VALIDATE_INPUTS = "validate_inputs"
    RESOLVE_PREDICTIONS = "resolve_predictions"
    COMPUTE_METRICS = "compute_metrics"
    THRESHOLD_SELECTION = "threshold_selection"
    SLICE_ANALYSIS = "slice_analysis"
    STABILITY_ANALYSIS = "stability_analysis"
    REGISTER_JOB = "register_job"
    FINALIZE = "finalize"


class ThresholdPolicy(str, Enum):
    """
    Operating-point selection policy.
    """

    FIXED = "fixed"
    MAX_F1 = "max_f1"
    MAX_YOU_J = "max_you_j"
    MIN_FNR_AT_FPR = "min_fnr_at_fpr"
    MAX_PRECISION_AT_RECALL = "max_precision_at_recall"
    BALANCED_ACCURACY = "balanced_accuracy"


class SliceMethod(str, Enum):
    """
    Bounded slice construction method.
    """

    NUMERIC_QUANTILE = "numeric_quantile"
    CATEGORICAL_HASH = "categorical_hash"
    BINARY_FLAG = "binary_flag"
    MISSING = "missing"


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
    if settings is None:
        return default

    if isinstance(settings, Mapping):
        return settings.get(name, default)

    return getattr(settings, name, default)


def _as_bool(value: object, default: bool = False) -> bool:
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
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float) -> float:
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default

    if math.isnan(result) or math.isinf(result):
        return default

    return result


def _clamp_int(value: object, minimum: int, maximum: int, default: int) -> int:
    parsed = _as_int(value, default)
    return max(minimum, min(parsed, maximum))


def _clamp_float(value: object, minimum: float, maximum: float, default: float) -> float:
    parsed = _as_float(value, default)
    return max(minimum, min(parsed, default))


def _csv(value: object) -> list[str]:
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return [part.strip() for part in str(value).split(",") if part.strip()]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _normalize_unicode(value: Any) -> str:
    # Enum members are unwrapped to their value first. For a `str`-mixin enum,
    # `str(Member)` is "ClassName.MEMBER", not "member" — so an enum passed
    # through here normalised to a token nothing recognised. That is what made
    # money-trail detection see zero money edges: every `GraphEdgeType.SENT`
    # edge normalised to `graph_edge_type_sent`, fell through the known-type
    # set, and became `related_to`.
    if isinstance(value, Enum):
        value = value.value

    return unicodedata.normalize("NFKC", str(value if value is not None else ""))


def _clean_text(value: Any, limit: int = _MAX_TEXT_LENGTH) -> str:
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
    text = _normalize_unicode(value).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = _SEPARATOR_RE.sub("_", text)
    text = _MULTI_UNDERSCORE_RE.sub("_", text)
    return text.strip("_").lower()


def _canonical_field_name(key: Any) -> str:
    return _normalize_token(key)


def _is_safe_hash(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and _HASH_RE.match(text))


def _is_forbidden_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_EVAL_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_EVAL_TOKENS)


def _is_label_leakage_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _LABEL_LEAKAGE_FIELDS:
        return True

    return any(token in canonical for token in _LABEL_LEAKAGE_TOKENS)


def _is_sensitive_detail_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    return any(token in canonical for token in _SENSITIVE_DETAIL_TOKENS)


def _safe_detail_value(value: Any, depth: int = 0) -> Any:
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
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:100]]

    return f"<{type(value).__name__}>"


def _safe_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
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
    if math.isnan(value) or math.isinf(value):
        return 0.0

    return round(float(value), 6)


def _coerce_optional_float(value: Any, *, allow_bool: bool = False) -> Optional[float]:
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


def _coerce_int_label(value: Any) -> Optional[int]:
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

    if isinstance(value, Enum):
        return _coerce_int_label(value.value)

    token = _normalize_token(value)

    if not token:
        return None

    if token in _LOCAL_LABEL_CODES:
        return int(_LOCAL_LABEL_CODES[token])

    try:
        return int(token)
    except (TypeError, ValueError):
        return None


def _coerce_int_tuple(value: Any, default: tuple[int, ...]) -> tuple[int, ...]:
    if value is None:
        return default

    out: list[int] = []

    for item in _as_sequence(value):
        code = _coerce_int_label(item)

        if code is not None:
            out.append(code)

    if not out:
        return default

    return tuple(sorted(set(out)))


def _as_sequence(value: Any) -> list[Any]:
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


def _normalize_enum_option(enum_cls: type[Enum], value: Any, default: Any) -> Any:
    if value is None:
        return default

    if isinstance(value, enum_cls):
        return value

    token = _normalize_token(value)

    for member in enum_cls:
        if token == _normalize_token(member.value) or token == member.name.lower():
            return member

    try:
        return enum_cls(value)
    except Exception:
        return default


def _target_value(target: Any) -> str:
    return _clean_text(getattr(target, "value", target), 64) or EvaluationTarget.AUTO.value


def _split_value(split: Any) -> str:
    return _clean_text(getattr(split, "value", split), 32) or EvaluationSplit.ALL.value


def _json_default(value: Any) -> Any:
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
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    )


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _hmac_hex(salt: str, domain: str, message: str) -> str:
    key = salt.encode("utf-8", errors="replace")
    payload = f"{domain}\x00{message}".encode("utf-8", errors="replace")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _stable_rank(salt: str, domain: str, *parts: Any) -> int:
    message = "\x00".join(str(part) for part in parts)
    digest = hmac.new(
        salt.encode("utf-8", errors="replace"),
        f"{domain}\x00{message}".encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).digest()
    return int.from_bytes(digest[:8], "big")


def _ensure_salt(salt: Any) -> str:
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _subject_hash(value: Any, options: "EvalOptions") -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.evaluate.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _fingerprint_payload(payload: Any) -> str:
    try:
        return _sha256_hex(_canonical_json(payload))
    except Exception:
        return _sha256_hex(str(_safe_detail_value(payload)))


def _append_issue(
    issues: list["EvaluationIssue"],
    max_issues: int,
    *,
    severity: IssueSeverity,
    code: str,
    message: str,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    limit = max(1, int(max_issues))

    if len(issues) >= limit:
        if issues and issues[-1].code == "issue_list_truncated":
            return

        issues[-1] = EvaluationIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        EvaluationIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _has_error(issues: Sequence[EvaluationIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0

    return sum(float(value) for value in values) / float(len(values))


def _stddev(values: Sequence[float], mean_value: Optional[float] = None) -> float:
    if len(values) < 2:
        return 0.0

    mu = _mean(values) if mean_value is None else float(mean_value)
    total = sum((float(value) - mu) ** 2 for value in values)
    result = total / float(len(values) - 1)

    return result if math.isfinite(result) and result > 0 else 0.0


def _quantile_sorted(sorted_values: Sequence[float], q: float) -> float:
    if not sorted_values:
        return 0.0

    q = _clamp_float(q, 0.0, 1.0, 0.0)
    idx = (len(sorted_values) - 1) * q
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))

    if lo == hi:
        return float(sorted_values[lo])

    return float(sorted_values[lo]) * (hi - idx) + float(sorted_values[hi]) * (idx - lo)


def _module_available(module: Any, *names: str) -> bool:
    if module is None:
        return False

    return all(hasattr(module, name) for name in names)


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvalOptions:
    """
    Bounded evaluation harness policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    target: EvaluationTarget | str = EvaluationTarget.AUTO
    split: EvaluationSplit | str = EvaluationSplit.TEST
    selection_split: EvaluationSplit | str = EvaluationSplit.VALIDATION

    threshold: float = _DEFAULT_THRESHOLD
    threshold_policy: ThresholdPolicy | str = ThresholdPolicy.FIXED
    ece_bins: int = _DEFAULT_ECE_BINS

    max_records: int = _DEFAULT_MAX_RECORDS
    max_features: int = _DEFAULT_MAX_FEATURES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_slices: int = _DEFAULT_MAX_SLICES
    max_slice_groups: int = _DEFAULT_MAX_SLICE_GROUPS
    min_slice_count: int = _DEFAULT_MIN_SLICE_COUNT
    max_threshold_points: int = _DEFAULT_MAX_THRESHOLD_POINTS
    max_bootstrap_iterations: int = _DEFAULT_MAX_BOOTSTRAP_ITERATIONS
    max_candidates: int = _DEFAULT_MAX_CANDIDATES
    max_pairwise: int = _DEFAULT_MAX_PAIRWISE
    max_artifacts: int = _DEFAULT_MAX_ARTIFACTS
    max_phases: int = _DEFAULT_MAX_PHASES
    max_jobs: int = _DEFAULT_MAX_JOBS

    include_contributions: bool = True
    include_slices: bool = True
    include_stability: bool = True
    include_threshold_sweep: bool = True
    register_jobs: bool = True
    drop_forbidden_fields: bool = False

    risk_thresholds: Mapping[str, float] = dataclass_field(
        default_factory=lambda: {
            "low": 0.35,
            "medium": 0.55,
            "high": 0.75,
            "critical": 0.90,
        }
    )

    def __post_init__(self) -> None:
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
            "target",
            _normalize_enum_option(EvaluationTarget, self.target, EvaluationTarget.AUTO),
        )
        object.__setattr__(
            self,
            "split",
            _normalize_enum_option(EvaluationSplit, self.split, EvaluationSplit.TEST),
        )
        object.__setattr__(
            self,
            "selection_split",
            _normalize_enum_option(EvaluationSplit, self.selection_split, EvaluationSplit.VALIDATION),
        )
        object.__setattr__(
            self,
            "threshold_policy",
            _normalize_enum_option(ThresholdPolicy, self.threshold_policy, ThresholdPolicy.FIXED),
        )

        object.__setattr__(
            self,
            "threshold",
            _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD),
        )
        object.__setattr__(
            self,
            "ece_bins",
            _clamp_int(self.ece_bins, 2, 100, _DEFAULT_ECE_BINS),
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
            "max_slices",
            _clamp_int(self.max_slices, 0, _HARD_MAX_SLICES, _DEFAULT_MAX_SLICES),
        )
        object.__setattr__(
            self,
            "max_slice_groups",
            _clamp_int(
                self.max_slice_groups,
                1,
                _HARD_MAX_SLICE_GROUPS,
                _DEFAULT_MAX_SLICE_GROUPS,
            ),
        )
        object.__setattr__(
            self,
            "min_slice_count",
            max(1, _as_int(self.min_slice_count, _DEFAULT_MIN_SLICE_COUNT)),
        )
        object.__setattr__(
            self,
            "max_threshold_points",
            _clamp_int(
                self.max_threshold_points,
                2,
                _HARD_MAX_THRESHOLD_POINTS,
                _DEFAULT_MAX_THRESHOLD_POINTS,
            ),
        )
        object.__setattr__(
            self,
            "max_bootstrap_iterations",
            _clamp_int(
                self.max_bootstrap_iterations,
                0,
                _HARD_MAX_BOOTSTRAP_ITERATIONS,
                _DEFAULT_MAX_BOOTSTRAP_ITERATIONS,
            ),
        )
        object.__setattr__(
            self,
            "max_candidates",
            _clamp_int(self.max_candidates, 1, _HARD_MAX_CANDIDATES, _DEFAULT_MAX_CANDIDATES),
        )
        object.__setattr__(
            self,
            "max_pairwise",
            _clamp_int(self.max_pairwise, 0, _HARD_MAX_PAIRWISE, _DEFAULT_MAX_PAIRWISE),
        )
        object.__setattr__(
            self,
            "max_artifacts",
            _clamp_int(self.max_artifacts, 0, _HARD_MAX_ARTIFACTS, _DEFAULT_MAX_ARTIFACTS),
        )
        object.__setattr__(
            self,
            "max_phases",
            _clamp_int(self.max_phases, 1, _HARD_MAX_PHASES, _DEFAULT_MAX_PHASES),
        )
        object.__setattr__(
            self,
            "max_jobs",
            _clamp_int(self.max_jobs, 1, _HARD_MAX_JOBS, _DEFAULT_MAX_JOBS),
        )

        object.__setattr__(self, "include_contributions", _as_bool(self.include_contributions, True))
        object.__setattr__(self, "include_slices", _as_bool(self.include_slices, True))
        object.__setattr__(self, "include_stability", _as_bool(self.include_stability, True))
        object.__setattr__(self, "include_threshold_sweep", _as_bool(self.include_threshold_sweep, True))
        object.__setattr__(self, "register_jobs", _as_bool(self.register_jobs, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))

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

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "EvalOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_EVALUATE_SALT", None)
            or _setting(settings, "ML_TRAIN_MODEL_SALT", None)
            or _setting(settings, "ML_MODEL_SERVICE_SALT", None)
            or _setting(settings, "ML_ANOMALY_SALT", None)
            or _setting(settings, "ML_SUPERVISED_SALT", None)
            or _setting(settings, "ML_FALLBACK_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_EVALUATE_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_EVALUATE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_EVALUATE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_EVALUATE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_EVALUATE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            target=str(_setting(settings, "ML_EVALUATE_TARGET", EvaluationTarget.AUTO.value)),
            split=str(_setting(settings, "ML_EVALUATE_SPLIT", EvaluationSplit.TEST.value)),
            selection_split=str(
                _setting(settings, "ML_EVALUATE_SELECTION_SPLIT", EvaluationSplit.VALIDATION.value)
            ),
            threshold=_as_float(_setting(settings, "ML_EVALUATE_THRESHOLD", _DEFAULT_THRESHOLD), _DEFAULT_THRESHOLD),
            threshold_policy=str(
                _setting(settings, "ML_EVALUATE_THRESHOLD_POLICY", ThresholdPolicy.FIXED.value)
            ),
            ece_bins=_as_int(_setting(settings, "ML_EVALUATE_ECE_BINS", _DEFAULT_ECE_BINS), _DEFAULT_ECE_BINS),
            max_records=_as_int(
                _setting(settings, "ML_EVALUATE_MAX_RECORDS", _DEFAULT_MAX_RECORDS),
                _DEFAULT_MAX_RECORDS,
            ),
            max_features=_as_int(
                _setting(settings, "ML_EVALUATE_MAX_FEATURES", _DEFAULT_MAX_FEATURES),
                _DEFAULT_MAX_FEATURES,
            ),
            max_issues=_as_int(
                _setting(settings, "ML_EVALUATE_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "ML_EVALUATE_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_slices=_as_int(_setting(settings, "ML_EVALUATE_MAX_SLICES", _DEFAULT_MAX_SLICES), _DEFAULT_MAX_SLICES),
            max_threshold_points=_as_int(
                _setting(settings, "ML_EVALUATE_MAX_THRESHOLD_POINTS", _DEFAULT_MAX_THRESHOLD_POINTS),
                _DEFAULT_MAX_THRESHOLD_POINTS,
            ),
            max_bootstrap_iterations=_as_int(
                _setting(settings, "ML_EVALUATE_MAX_BOOTSTRAP_ITERATIONS", _DEFAULT_MAX_BOOTSTRAP_ITERATIONS),
                _DEFAULT_MAX_BOOTSTRAP_ITERATIONS,
            ),
            max_candidates=_as_int(
                _setting(settings, "ML_EVALUATE_MAX_CANDIDATES", _DEFAULT_MAX_CANDIDATES),
                _DEFAULT_MAX_CANDIDATES,
            ),
            max_jobs=_as_int(_setting(settings, "ML_EVALUATE_MAX_JOBS", _DEFAULT_MAX_JOBS), _DEFAULT_MAX_JOBS),
            include_contributions=_as_bool(
                _setting(settings, "ML_EVALUATE_INCLUDE_CONTRIBUTIONS", True),
                True,
            ),
            include_slices=_as_bool(_setting(settings, "ML_EVALUATE_INCLUDE_SLICES", True), True),
            include_stability=_as_bool(_setting(settings, "ML_EVALUATE_INCLUDE_STABILITY", True), True),
            include_threshold_sweep=_as_bool(
                _setting(settings, "ML_EVALUATE_INCLUDE_THRESHOLD_SWEEP", True),
                True,
            ),
            register_jobs=_as_bool(_setting(settings, "ML_EVALUATE_REGISTER_JOBS", True), True),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ML_EVALUATE_DROP_FORBIDDEN_FIELDS", False),
                False,
            ),
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "synthetic_required": self.synthetic_required,
            "dataset_mode": self.dataset_mode,
            "production_like": self.production_like,
            "allow_in_production": self.allow_in_production,
            "namespace": self.namespace,
            "seed": self.seed,
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
            "target": self.target.value if isinstance(self.target, EvaluationTarget) else str(self.target),
            "split": self.split.value if isinstance(self.split, EvaluationSplit) else str(self.split),
            "selection_split": (
                self.selection_split.value
                if isinstance(self.selection_split, EvaluationSplit)
                else str(self.selection_split)
            ),
            "threshold": round(self.threshold, 6),
            "threshold_policy": (
                self.threshold_policy.value
                if isinstance(self.threshold_policy, ThresholdPolicy)
                else str(self.threshold_policy)
            ),
            "ece_bins": self.ece_bins,
            "limits": {
                "max_records": self.max_records,
                "max_features": self.max_features,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_slices": self.max_slices,
                "max_slice_groups": self.max_slice_groups,
                "min_slice_count": self.min_slice_count,
                "max_threshold_points": self.max_threshold_points,
                "max_bootstrap_iterations": self.max_bootstrap_iterations,
                "max_candidates": self.max_candidates,
                "max_pairwise": self.max_pairwise,
                "max_artifacts": self.max_artifacts,
                "max_phases": self.max_phases,
                "max_jobs": self.max_jobs,
            },
            "flags": {
                "include_contributions": self.include_contributions,
                "include_slices": self.include_slices,
                "include_stability": self.include_stability,
                "include_threshold_sweep": self.include_threshold_sweep,
                "register_jobs": self.register_jobs,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
            "risk_thresholds": dict(self.risk_thresholds),
        }


# -----------------------------------------------------------------------------
# Issue, phase, artifact, prediction, slice, and result models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvaluationIssue:
    """
    Safe evaluation issue.
    """

    severity: IssueSeverity
    code: str
    message: str
    field: Optional[str] = None
    details: dict[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "severity",
            _normalize_enum_option(IssueSeverity, self.severity, IssueSeverity.WARNING),
        )
        object.__setattr__(self, "code", _clean_text(self.code, 100))
        object.__setattr__(self, "message", _clean_text(self.message, 300))
        object.__setattr__(
            self,
            "field",
            _clean_text(self.field, 200) if self.field else None,
        )
        object.__setattr__(self, "details", _safe_details(self.details))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
        }

        if self.field:
            payload["field"] = self.field

        if self.details:
            payload["details"] = self.details

        return payload


@dataclass(frozen=True, slots=True)
class EvaluationPhaseRecord:
    """
    One bounded evaluation phase record.
    """

    phase: EvaluationPhase | str
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    ok: bool
    issue_count: int
    details: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "phase",
            _normalize_enum_option(EvaluationPhase, self.phase, EvaluationPhase.FINALIZE),
        )
        object.__setattr__(self, "started_at", _ensure_utc(self.started_at) or _now_utc())
        object.__setattr__(self, "finished_at", _ensure_utc(self.finished_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "ok", _as_bool(self.ok, False))
        object.__setattr__(self, "issue_count", max(0, _as_int(self.issue_count, 0)))
        object.__setattr__(self, "details", MappingProxyType(_safe_detail_value(self.details) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "ok": bool(self.ok),
            "issue_count": int(self.issue_count),
            "details": _safe_detail_value(self.details),
        }


@dataclass(frozen=True, slots=True)
class EvaluationArtifact:
    """
    Safe evaluation artifact summary.

    Artifacts are summaries only. This module does not write files or persist
    durable evaluation artefacts.
    """

    kind: str
    artifact_id: Optional[str] = None
    fingerprint: str = ""
    status: str = ""
    summary: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _normalize_token(self.kind) or "artifact")
        object.__setattr__(
            self,
            "artifact_id",
            _clean_text(self.artifact_id, 128) if self.artifact_id else None,
        )
        object.__setattr__(self, "fingerprint", _clean_text(self.fingerprint, 128))
        object.__setattr__(self, "status", _clean_text(self.status, 32))
        object.__setattr__(self, "summary", MappingProxyType(_safe_detail_value(self.summary) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "artifact_id": self.artifact_id,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "summary": _safe_detail_value(self.summary),
        }


@dataclass(frozen=True, slots=True)
class PredictionSnapshot:
    """
    One bounded prediction snapshot.

    Scores are investigative prioritisation outputs only.
    """

    subject_ref_hash: Optional[str] = None
    index: Optional[int] = None
    score: Optional[float] = None
    predicted_label: Optional[int] = None
    probabilities: Mapping[str, float] = dataclass_field(default_factory=dict)
    contributions: tuple[dict[str, Any], ...] = ()
    source: str = "external"
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "subject_ref_hash",
            _clean_text(self.subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower()
            if self.subject_ref_hash
            else None,
        )
        object.__setattr__(
            self,
            "index",
            max(0, _as_int(self.index, 0)) if self.index is not None else None,
        )

        if self.score is not None:
            object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))

        object.__setattr__(
            self,
            "predicted_label",
            _coerce_int_label(self.predicted_label) if self.predicted_label is not None else None,
        )
        object.__setattr__(
            self,
            "probabilities",
            MappingProxyType(
                {
                    _clean_text(key, 100): _round6(_clip_float(_coerce_optional_float(value, allow_bool=True), 0.0, 1.0, 0.0))
                    for key, value in (self.probabilities or {}).items()
                    if _coerce_optional_float(value, allow_bool=True) is not None
                }
            ),
        )
        object.__setattr__(self, "contributions", tuple(self.contributions or ()))
        object.__setattr__(self, "source", _clean_text(self.source, 64) or "external")
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))


@dataclass(frozen=True, slots=True)
class SliceSpec:
    """
    One bounded slice specification.
    """

    feature: str
    method: SliceMethod | str = SliceMethod.NUMERIC_QUANTILE
    bins: int = 4
    min_count: int = _DEFAULT_MIN_SLICE_COUNT
    params: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "feature", _canonical_field_name(self.feature))
        object.__setattr__(
            self,
            "method",
            _normalize_enum_option(SliceMethod, self.method, SliceMethod.NUMERIC_QUANTILE),
        )
        object.__setattr__(
            self,
            "bins",
            _clamp_int(self.bins, 2, 100, 4),
        )
        object.__setattr__(
            self,
            "min_count",
            max(1, _as_int(self.min_count, _DEFAULT_MIN_SLICE_COUNT)),
        )
        object.__setattr__(self, "params", MappingProxyType(_safe_detail_value(self.params) or {}))


@dataclass(frozen=True, slots=True)
class SliceResult:
    """
    One bounded slice result.

    Raw feature values and raw bucket boundaries are omitted.
    """

    slice_id: str
    feature: str
    method: str
    bucket: str
    count: int
    positive_count: int = 0
    negative_count: int = 0
    score_mean: Optional[float] = None
    score_median: Optional[float] = None
    metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "slice_id", _clean_text(self.slice_id, 128))
        object.__setattr__(self, "feature", _clean_text(self.feature, 200))
        object.__setattr__(self, "method", _clean_text(self.method, 64))
        object.__setattr__(self, "bucket", _clean_text(self.bucket, 64))
        object.__setattr__(self, "count", max(0, _as_int(self.count, 0)))
        object.__setattr__(self, "positive_count", max(0, _as_int(self.positive_count, 0)))
        object.__setattr__(self, "negative_count", max(0, _as_int(self.negative_count, 0)))

        if self.score_mean is not None:
            object.__setattr__(self, "score_mean", _round6(_clip_float(self.score_mean, 0.0, 1.0, 0.0)))

        if self.score_median is not None:
            object.__setattr__(self, "score_median", _round6(_clip_float(self.score_median, 0.0, 1.0, 0.0)))

        object.__setattr__(self, "metrics", MappingProxyType(_safe_detail_value(self.metrics) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "slice_id": self.slice_id,
            "feature": self.feature,
            "method": self.method,
            "bucket": self.bucket,
            "count": int(self.count),
            "positive_count": int(self.positive_count),
            "negative_count": int(self.negative_count),
            "score_mean": float(self.score_mean) if self.score_mean is not None else None,
            "score_median": float(self.score_median) if self.score_median is not None else None,
            "metrics": _safe_detail_value(self.metrics),
        }


@dataclass(frozen=True, slots=True)
class ThresholdPoint:
    """
    One bounded threshold sweep point.
    """

    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    fpr: Optional[float] = None
    fnr: Optional[float] = None
    tnr: Optional[float] = None
    balanced_accuracy: Optional[float] = None
    you_j: Optional[float] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "threshold", _round6(_clip_float(self.threshold, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "tp", max(0, _as_int(self.tp, 0)))
        object.__setattr__(self, "fp", max(0, _as_int(self.fp, 0)))
        object.__setattr__(self, "tn", max(0, _as_int(self.tn, 0)))
        object.__setattr__(self, "fn", max(0, _as_int(self.fn, 0)))

        for name in (
            "precision",
            "recall",
            "f1",
            "fpr",
            "fnr",
            "tnr",
            "balanced_accuracy",
            "you_j",
        ):
            value = getattr(self, name)

            if value is not None:
                object.__setattr__(self, name, _round6(_clip_float(value, -1.0, 1.0, 0.0)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": float(self.threshold),
            "tp": int(self.tp),
            "fp": int(self.fp),
            "tn": int(self.tn),
            "fn": int(self.fn),
            "precision": float(self.precision) if self.precision is not None else None,
            "recall": float(self.recall) if self.recall is not None else None,
            "f1": float(self.f1) if self.f1 is not None else None,
            "fpr": float(self.fpr) if self.fpr is not None else None,
            "fnr": float(self.fnr) if self.fnr is not None else None,
            "tnr": float(self.tnr) if self.tnr is not None else None,
            "balanced_accuracy": float(self.balanced_accuracy) if self.balanced_accuracy is not None else None,
            "you_j": float(self.you_j) if self.you_j is not None else None,
        }


@dataclass(frozen=True, slots=True)
class BootstrapInterval:
    """
    Bounded deterministic bootstrap interval.
    """

    metric: str
    point_estimate: Optional[float] = None
    ci_low: Optional[float] = None
    ci_high: Optional[float] = None
    iterations: int = 0
    available: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric", _clean_text(self.metric, 100))

        for name in ("point_estimate", "ci_low", "ci_high"):
            value = getattr(self, name)

            if value is not None:
                object.__setattr__(self, name, _round6(_clip_float(value, -1e12, 1e12, 0.0)))

        object.__setattr__(self, "iterations", max(0, _as_int(self.iterations, 0)))
        object.__setattr__(self, "available", _as_bool(self.available, False))

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "point_estimate": float(self.point_estimate) if self.point_estimate is not None else None,
            "ci_low": float(self.ci_low) if self.ci_low is not None else None,
            "ci_high": float(self.ci_high) if self.ci_high is not None else None,
            "iterations": int(self.iterations),
            "available": bool(self.available),
        }


@dataclass(slots=True)
class EvaluationJobRequest:
    """
    Bounded evaluation job request.
    """

    features: Any = None
    labels: Any = None
    predictions: Any = None
    model: Any = None
    model_id: Optional[str] = None
    target: EvaluationTarget | str | None = None
    split: EvaluationSplit | str | None = None
    selection_split: EvaluationSplit | str | None = None
    threshold: Optional[float] = None
    threshold_policy: ThresholdPolicy | str | None = None
    positive_label_codes: Sequence[int] | None = None
    negative_label_codes: Sequence[int] | None = None
    ignore_label_codes: Sequence[int] | None = None
    max_fpr: Optional[float] = None
    min_recall: Optional[float] = None
    min_precision: Optional[float] = None
    slices: Sequence[Any] | None = None
    include_contributions: Optional[bool] = None
    include_slices: Optional[bool] = None
    include_stability: Optional[bool] = None
    include_threshold_sweep: Optional[bool] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    job_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.target = (
            _normalize_enum_option(EvaluationTarget, self.target, None)
            if self.target is not None
            else None
        )
        self.split = (
            _normalize_enum_option(EvaluationSplit, self.split, None)
            if self.split is not None
            else None
        )
        self.selection_split = (
            _normalize_enum_option(EvaluationSplit, self.selection_split, None)
            if self.selection_split is not None
            else None
        )
        self.threshold_policy = (
            _normalize_enum_option(ThresholdPolicy, self.threshold_policy, None)
            if self.threshold_policy is not None
            else None
        )
        self.model_id = _clean_text(self.model_id, 128) if self.model_id else None

        if self.threshold is not None:
            self.threshold = _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)

        if self.max_fpr is not None:
            self.max_fpr = _clamp_float(self.max_fpr, 0.0, 1.0, 0.0)

        if self.min_recall is not None:
            self.min_recall = _clamp_float(self.min_recall, 0.0, 1.0, 0.0)

        if self.min_precision is not None:
            self.min_precision = _clamp_float(self.min_precision, 0.0, 1.0, 0.0)

        self.positive_label_codes = _coerce_int_tuple(
            self.positive_label_codes,
            _DEFAULT_POSITIVE_LABEL_CODES,
        )
        self.negative_label_codes = _coerce_int_tuple(
            self.negative_label_codes,
            _DEFAULT_NEGATIVE_LABEL_CODES,
        )
        self.ignore_label_codes = _coerce_int_tuple(
            self.ignore_label_codes,
            _DEFAULT_IGNORE_LABEL_CODES,
        )

        self.slices = _coerce_slice_specs(self.slices)
        self.metadata = _safe_detail_value(self.metadata) or {}
        self.tags = tuple(
            dict.fromkeys(
                _clean_text(tag, 100)
                for tag in (self.tags or ())
                if _clean_text(tag, 100)
            )
        )
        self.idempotency_key = _clean_text(self.idempotency_key, 200) if self.idempotency_key else None
        self.job_id = _clean_text(self.job_id, 128) if self.job_id else None

        if self.include_contributions is not None:
            self.include_contributions = _as_bool(self.include_contributions, True)

        if self.include_slices is not None:
            self.include_slices = _as_bool(self.include_slices, True)

        if self.include_stability is not None:
            self.include_stability = _as_bool(self.include_stability, True)

        if self.include_threshold_sweep is not None:
            self.include_threshold_sweep = _as_bool(self.include_threshold_sweep, True)


@dataclass(slots=True)
class EvaluationCandidate:
    """
    One bounded comparison candidate.
    """

    name: str = "candidate"
    model: Any = None
    model_id: Optional[str] = None
    predictions: Any = None
    target: EvaluationTarget | str | None = None
    threshold: Optional[float] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        self.name = _clean_text(self.name, 128) or "candidate"
        self.model_id = _clean_text(self.model_id, 128) if self.model_id else None
        self.target = (
            _normalize_enum_option(EvaluationTarget, self.target, None)
            if self.target is not None
            else None
        )

        if self.threshold is not None:
            self.threshold = _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)

        self.metadata = _safe_detail_value(self.metadata) or {}


@dataclass(slots=True)
class EvaluationComparisonRequest:
    """
    Bounded paired model comparison request.
    """

    features: Any = None
    labels: Any = None
    candidates: Sequence[Any] = dataclass_field(default_factory=tuple)
    split: EvaluationSplit | str | None = None
    positive_label_codes: Sequence[int] | None = None
    negative_label_codes: Sequence[int] | None = None
    ignore_label_codes: Sequence[int] | None = None
    primary_metric: str = "roc_auc"
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    job_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.split = (
            _normalize_enum_option(EvaluationSplit, self.split, None)
            if self.split is not None
            else None
        )
        self.positive_label_codes = _coerce_int_tuple(
            self.positive_label_codes,
            _DEFAULT_POSITIVE_LABEL_CODES,
        )
        self.negative_label_codes = _coerce_int_tuple(
            self.negative_label_codes,
            _DEFAULT_NEGATIVE_LABEL_CODES,
        )
        self.ignore_label_codes = _coerce_int_tuple(
            self.ignore_label_codes,
            _DEFAULT_IGNORE_LABEL_CODES,
        )
        self.primary_metric = _normalize_token(self.primary_metric) or "roc_auc"
        self.candidates = tuple(
            _coerce_candidate(item)
            for item in (self.candidates or ())
        )
        self.metadata = _safe_detail_value(self.metadata) or {}
        self.tags = tuple(
            dict.fromkeys(
                _clean_text(tag, 100)
                for tag in (self.tags or ())
                if _clean_text(tag, 100)
            )
        )
        self.idempotency_key = _clean_text(self.idempotency_key, 200) if self.idempotency_key else None
        self.job_id = _clean_text(self.job_id, 128) if self.job_id else None


@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    """
    One bounded candidate evaluation summary.
    """

    name: str
    target: str
    threshold: float
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _clean_text(self.name, 128) or "candidate")
        object.__setattr__(self, "target", _clean_text(self.target, 64) or EvaluationTarget.AUTO.value)
        object.__setattr__(self, "threshold", _round6(_clip_float(self.threshold, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts or {})))
        object.__setattr__(self, "metrics", MappingProxyType(_safe_detail_value(self.metrics) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target": self.target,
            "threshold": float(self.threshold),
            "counts": dict(self.counts),
            "metrics": _safe_detail_value(self.metrics),
        }


@dataclass(frozen=True, slots=True)
class PairwiseComparison:
    """
    One bounded pairwise comparison result.
    """

    baseline: str
    candidate: str
    metric: str
    baseline_value: Optional[float] = None
    candidate_value: Optional[float] = None
    delta: Optional[float] = None
    interval: Optional[BootstrapInterval] = None
    verdict: str = "UNCERTAIN"

    def __post_init__(self) -> None:
        object.__setattr__(self, "baseline", _clean_text(self.baseline, 128) or "baseline")
        object.__setattr__(self, "candidate", _clean_text(self.candidate, 128) or "candidate")
        object.__setattr__(self, "metric", _clean_text(self.metric, 100))

        for name in ("baseline_value", "candidate_value", "delta"):
            value = getattr(self, name)

            if value is not None:
                object.__setattr__(self, name, _round6(_clip_float(value, -1e12, 1e12, 0.0)))

        object.__setattr__(self, "verdict", _clean_text(self.verdict, 32) or "UNCERTAIN")

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline,
            "candidate": self.candidate,
            "metric": self.metric,
            "baseline_value": float(self.baseline_value) if self.baseline_value is not None else None,
            "candidate_value": float(self.candidate_value) if self.candidate_value is not None else None,
            "delta": float(self.delta) if self.delta is not None else None,
            "interval": self.interval.to_dict() if self.interval is not None else None,
            "verdict": self.verdict,
        }


@dataclass(frozen=True, slots=True)
class EvaluationComparisonResult:
    """
    Safe paired model comparison result.
    """

    ok: bool = True
    status: EvaluationStatus = EvaluationStatus.SUCCEEDED
    job_id: str = ""
    split: str = EvaluationSplit.TEST.value
    primary_metric: str = "roc_auc"
    candidates: tuple[CandidateEvaluation, ...] = ()
    pairwise: tuple[PairwiseComparison, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[EvaluationIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(EvaluationStatus, self.status, EvaluationStatus.SUCCEEDED),
        )
        object.__setattr__(self, "job_id", _clean_text(self.job_id, 128))
        object.__setattr__(self, "split", _clean_text(self.split, 32) or EvaluationSplit.TEST.value)
        object.__setattr__(self, "primary_metric", _clean_text(self.primary_metric, 100) or "roc_auc")
        object.__setattr__(self, "candidates", tuple(self.candidates or ()))
        object.__setattr__(self, "pairwise", tuple(self.pairwise or ()))
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts or {})))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": EVALUATION_VERSION,
                        "ok": self.ok,
                        "status": self.status.value,
                        "job_id": self.job_id,
                        "split": self.split,
                        "primary_metric": self.primary_metric,
                        "candidates": [candidate.to_dict() for candidate in self.candidates],
                        "pairwise": [pair.to_dict() for pair in self.pairwise],
                        "counts": self.counts,
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status.value,
            "job_id": self.job_id,
            "split": self.split,
            "primary_metric": self.primary_metric,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "pairwise": [pair.to_dict() for pair in self.pairwise],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_EVALUATION_CAVEATS),
            "safety_flags": dict(_EVALUATION_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class EvaluationJobResult:
    """
    Safe evaluation job result.

    Public summaries deliberately exclude raw feature values, subject-label
    pairs, raw identifiers, raw narratives, secrets, tokens, passwords, database
    URLs, filesystem paths, and model artifact paths.
    """

    job_id: str
    status: EvaluationStatus
    target: EvaluationTarget
    split: EvaluationSplit
    threshold: float
    created_at: datetime = dataclass_field(default_factory=_now_utc)
    finished_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    binary_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    multiclass_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    calibration: Mapping[str, Any] = dataclass_field(default_factory=dict)
    score_distribution: Mapping[str, Any] = dataclass_field(default_factory=dict)
    threshold_curve: tuple[ThresholdPoint, ...] = ()
    selected_threshold: Optional[ThresholdPoint] = None
    threshold_selection_source: str = "none"
    slices: tuple[SliceResult, ...] = ()
    stability: Mapping[str, Any] = dataclass_field(default_factory=dict)
    artifacts: tuple[EvaluationArtifact, ...] = ()
    phases: tuple[EvaluationPhaseRecord, ...] = ()
    issues: tuple[EvaluationIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_id", _clean_text(self.job_id, 128))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(EvaluationStatus, self.status, EvaluationStatus.FAILED),
        )
        object.__setattr__(
            self,
            "target",
            _normalize_enum_option(EvaluationTarget, self.target, EvaluationTarget.AUTO),
        )
        object.__setattr__(
            self,
            "split",
            _normalize_enum_option(EvaluationSplit, self.split, EvaluationSplit.TEST),
        )
        object.__setattr__(self, "threshold", _round6(_clip_float(self.threshold, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())
        object.__setattr__(self, "finished_at", _ensure_utc(self.finished_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts or {})))
        object.__setattr__(self, "metrics", MappingProxyType(_safe_detail_value(self.metrics) or {}))
        object.__setattr__(self, "binary_metrics", MappingProxyType(_safe_detail_value(self.binary_metrics) or {}))
        object.__setattr__(
            self,
            "multiclass_metrics",
            MappingProxyType(_safe_detail_value(self.multiclass_metrics) or {}),
        )
        object.__setattr__(self, "calibration", MappingProxyType(_safe_detail_value(self.calibration) or {}))
        object.__setattr__(
            self,
            "score_distribution",
            MappingProxyType(_safe_detail_value(self.score_distribution) or {}),
        )
        object.__setattr__(self, "threshold_curve", tuple(self.threshold_curve or ())[:_HARD_MAX_THRESHOLD_POINTS])
        object.__setattr__(
            self,
            "threshold_selection_source",
            _clean_text(self.threshold_selection_source, 64) or "none",
        )
        object.__setattr__(self, "slices", tuple(self.slices or ())[:_HARD_MAX_SLICES])
        object.__setattr__(self, "stability", MappingProxyType(_safe_detail_value(self.stability) or {}))
        object.__setattr__(self, "artifacts", tuple(self.artifacts or ())[:_HARD_MAX_ARTIFACTS])
        object.__setattr__(self, "phases", tuple(self.phases or ())[:_HARD_MAX_PHASES])
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": EVALUATION_VERSION,
                        "job_id": self.job_id,
                        "status": self.status.value,
                        "target": self.target.value,
                        "split": self.split.value,
                        "threshold": self.threshold,
                        "counts": self.counts,
                        "metrics": self.metrics,
                        "binary_metrics": self.binary_metrics,
                        "multiclass_metrics": self.multiclass_metrics,
                        "calibration": self.calibration,
                        "score_distribution": self.score_distribution,
                        "selected_threshold": (
                            self.selected_threshold.to_dict()
                            if self.selected_threshold is not None
                            else None
                        ),
                        "threshold_selection_source": self.threshold_selection_source,
                        "slice_count": len(self.slices),
                        "stability": self.stability,
                        "artifact_count": len(self.artifacts),
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "target": self.target.value,
            "split": self.split.value,
            "threshold": float(self.threshold),
            "created_at": self.created_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "counts": dict(self.counts),
            "metrics": _safe_detail_value(self.metrics),
            "binary_metrics": _safe_detail_value(self.binary_metrics),
            "multiclass_metrics": _safe_detail_value(self.multiclass_metrics),
            "calibration": _safe_detail_value(self.calibration),
            "score_distribution": _safe_detail_value(self.score_distribution),
            "threshold_curve": [point.to_dict() for point in self.threshold_curve],
            "selected_threshold": (
                self.selected_threshold.to_dict()
                if self.selected_threshold is not None
                else None
            ),
            "threshold_selection_source": self.threshold_selection_source,
            "slices": [slice_result.to_dict() for slice_result in self.slices],
            "stability": _safe_detail_value(self.stability),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "phases": [phase.to_dict() for phase in self.phases],
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_EVALUATION_CAVEATS),
            "safety_flags": dict(_EVALUATION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local evaluation registry
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _RegisteredEvaluationJob:
    result: EvaluationJobResult
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class EvaluationRegistry:
    """
    Bounded process-local evaluation registry.

    This registry is not durable, not distributed, and not production-ready.
    It exists only to support local prototype workflows, tests, and developer
    tooling.
    """

    def __init__(self, max_jobs: int = _DEFAULT_MAX_JOBS) -> None:
        self.max_jobs = max(1, int(max_jobs))
        self._jobs: dict[str, _RegisteredEvaluationJob] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, result: EvaluationJobResult) -> str:
        """
        Register one evaluation result and return its job id.
        """
        with self._lock:
            job_id = _clean_text(result.job_id, 128)

            if not job_id:
                job_id = result.fingerprint[:32] or _sha256_hex(str(len(self._jobs) + 1))[:32]

            if job_id in self._jobs:
                self._jobs[job_id] = _RegisteredEvaluationJob(result=result, registered_at=_now_utc())
                return job_id

            self._jobs[job_id] = _RegisteredEvaluationJob(result=result, registered_at=_now_utc())
            self._order.append(job_id)

            if len(self._order) > self.max_jobs:
                evict_id = self._order.pop(0)
                self._jobs.pop(evict_id, None)

            return job_id

    def get_result(self, job_id: Any) -> Optional[EvaluationJobResult]:
        """
        Return one registered evaluation result.
        """
        key = _clean_text(job_id, 128)

        with self._lock:
            entry = self._jobs.get(key)
            return entry.result if entry is not None else None

    def list_results(self, *, limit: int = 50) -> tuple[EvaluationJobResult, ...]:
        """
        Return registered evaluation results in insertion order.
        """
        with self._lock:
            out: list[EvaluationJobResult] = []

            for job_id in self._order[: max(1, int(limit))]:
                entry = self._jobs.get(job_id)

                if entry is not None:
                    out.append(entry.result)

            return tuple(out)

    def summarize(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """
        Return safe registry summaries.
        """
        with self._lock:
            out: list[dict[str, Any]] = []

            for job_id in self._order[: max(1, int(limit))]:
                entry = self._jobs.get(job_id)

                if entry is None:
                    continue

                result = entry.result

                out.append(
                    {
                        "job_id": result.job_id,
                        "status": result.status.value,
                        "target": result.target.value,
                        "split": result.split.value,
                        "threshold": float(result.threshold),
                        "created_at": result.created_at.isoformat(),
                        "finished_at": result.finished_at.isoformat(),
                        "duration_ms": int(result.duration_ms),
                        "fingerprint": result.fingerprint,
                        "issue_count": len(result.issues),
                        "artifact_count": len(result.artifacts),
                        "slice_count": len(result.slices),
                    }
                )

            return out

    def clear(self) -> None:
        """
        Clear the process-local registry.
        """
        with self._lock:
            self._jobs.clear()
            self._order.clear()

    def safe_summary(self, *, limit: int = 50) -> dict[str, Any]:
        """
        Return safe registry summary.
        """
        with self._lock:
            status_counter = Counter(entry.result.status.value for entry in self._jobs.values())
            target_counter = Counter(entry.result.target.value for entry in self._jobs.values())
            split_counter = Counter(entry.result.split.value for entry in self._jobs.values())

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_jobs": self.max_jobs,
            "registered_jobs": len(self._order),
            "by_status": dict(status_counter),
            "by_target": dict(target_counter),
            "by_split": dict(split_counter),
            "recent": self.summarize(limit=limit),
        }


_default_registry: Optional[EvaluationRegistry] = None
_default_registry_lock = threading.Lock()


def get_eval_registry(
    max_jobs: int | None = None,
    *,
    rebuild: bool = False,
) -> EvaluationRegistry:
    """
    Return the process-wide evaluation registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = EvaluationRegistry(
                max_jobs=max_jobs if max_jobs is not None else _DEFAULT_MAX_JOBS
            )

        return _default_registry


# -----------------------------------------------------------------------------
# Input extraction and sanitization
# -----------------------------------------------------------------------------


def _coerce_slice_specs(value: Any) -> tuple[SliceSpec, ...]:
    if value is None:
        return ()

    out: list[SliceSpec] = []

    for item in _as_sequence(value):
        if isinstance(item, SliceSpec):
            out.append(item)
            continue

        if isinstance(item, Mapping):
            try:
                out.append(SliceSpec(**item))
                continue
            except Exception:
                pass

        feature = _canonical_field_name(item)

        if feature:
            out.append(SliceSpec(feature=feature))

    return tuple(out)


def _coerce_candidate(value: Any) -> EvaluationCandidate:
    if isinstance(value, EvaluationCandidate):
        return value

    if isinstance(value, Mapping):
        try:
            return EvaluationCandidate(**value)
        except Exception:
            return EvaluationCandidate(name="candidate", predictions=value)

    return EvaluationCandidate(name="candidate", predictions=value)


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, EvaluationJobResult):
        return []

    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "examples", "vectors", "features"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])

        if "feature_names" in data and "rows" in data:
            return _as_sequence(data["rows"])

        return [data]

    if hasattr(data, "feature_names") and hasattr(data, "rows"):
        return _as_sequence(getattr(data, "rows"))

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray, memoryview)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _extract_subject(record: Any, options: EvalOptions) -> Optional[str]:
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


def _extract_feature_mapping(record: Any) -> dict[str, Any]:
    if isinstance(record, Mapping):
        candidate = record.get("features")

        if isinstance(candidate, Mapping):
            return dict(candidate)

        candidate = record.get("values")

        if isinstance(candidate, Mapping):
            return dict(candidate)

        return {
            key: value
            for key, value in record.items()
            if key not in _SUBJECT_KEYS and key not in _NON_FEATURE_KEYS
        }

    candidate = getattr(record, "features", None)

    if isinstance(candidate, Mapping):
        return dict(candidate)

    candidate = getattr(record, "values", None)

    if isinstance(candidate, Mapping):
        return dict(candidate)

    return {}


def _clean_records(
    records: Sequence[Any],
    options: EvalOptions,
    issues: list[EvaluationIssue],
) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    seen_subjects: set[str] = set()

    for index, record in enumerate(records):
        subject = _extract_subject(record, options)
        features = _extract_feature_mapping(record)
        clean_features: dict[str, Any] = {}
        valid = True

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
                valid = False
                break

            if canonical in clean_features:
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

            clean_features[canonical] = raw_value

        if not valid:
            continue

        if subject:
            if subject in seen_subjects:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.INFO,
                    code="duplicate_subject_reference",
                    message="Duplicate subject reference detected in evaluation input.",
                    details={"index": index},
                )
            else:
                seen_subjects.add(subject)

        out_record: dict[str, Any] = {
            "index": index,
            "features": clean_features,
        }

        if subject:
            out_record["subject_ref_hash"] = subject

        cleaned.append(out_record)

    return cleaned


def _scan_labels(
    labels: Any,
    options: EvalOptions,
    issues: list[EvaluationIssue],
) -> bool:
    """
    Scan label input for forbidden secret/PII-like fields.

    Label-like fields are allowed in label input but are rejected in feature
    input.
    """
    if labels is None:
        return True

    ok = True

    def scan_mapping(mp: Mapping[Any, Any], prefix: str) -> None:
        nonlocal ok

        for raw_key in mp.keys():
            key = _clean_text(raw_key, 200)
            canonical = _canonical_field_name(key)

            if not canonical:
                continue

            if _is_forbidden_key(canonical):
                if options.drop_forbidden_fields:
                    _append_issue(
                        issues,
                        options.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="forbidden_label_field_dropped",
                        message="Forbidden label metadata field omitted.",
                        field=key,
                        details={"prefix": prefix},
                    )
                    continue

                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="forbidden_label_field",
                    message="Forbidden label metadata field rejected.",
                    field=key,
                    details={"prefix": prefix},
                )
                ok = False

    if isinstance(labels, Mapping):
        scan_mapping(labels, "labels")

        for container_key in ("records", "items", "rows"):
            if container_key in labels:
                for index, record in enumerate(_as_sequence(labels[container_key])):
                    if isinstance(record, Mapping):
                        scan_mapping(record, f"labels.{container_key}[{index}]")

        metadata = labels.get("metadata")

        if isinstance(metadata, Mapping):
            scan_mapping(metadata, "labels.metadata")
    else:
        metadata = getattr(labels, "metadata", None)

        if isinstance(metadata, Mapping):
            scan_mapping(metadata, "labels.metadata")

        records = getattr(labels, "records", None) or getattr(labels, "items", None)

        if records is not None:
            for index, record in enumerate(_as_sequence(records)):
                if isinstance(record, Mapping):
                    scan_mapping(record, f"labels.records[{index}]")
        elif isinstance(labels, Sequence) and not isinstance(labels, (str, bytes, bytearray, memoryview)):
            for index, record in enumerate(labels):
                if isinstance(record, Mapping):
                    scan_mapping(record, f"labels[{index}]")

    return ok


@dataclass(slots=True)
class _LabelIndex:
    by_subject: dict[str, int] = dataclass_field(default_factory=dict)
    weights_by_subject: dict[str, float] = dataclass_field(default_factory=dict)
    splits_by_subject: dict[str, str] = dataclass_field(default_factory=dict)
    by_index: list[Optional[int]] = dataclass_field(default_factory=list)
    weights_by_index: list[float] = dataclass_field(default_factory=list)
    splits_by_index: list[str] = dataclass_field(default_factory=list)


def _label_code_from_mapping(mapping: Mapping[Any, Any]) -> Any:
    for key in ("label_code", "label", "target", "y", "synthetic_label"):
        if key in mapping:
            return mapping[key]

    return None


def _subject_from_mapping(mapping: Mapping[Any, Any]) -> Any:
    for key in _SUBJECT_KEYS:
        if key in mapping:
            return mapping[key]

    return None


def _build_label_index(labels: Any, record_count: int, options: EvalOptions) -> _LabelIndex:
    index = _LabelIndex(
        by_index=[None] * max(0, record_count),
        weights_by_index=[1.0] * max(0, record_count),
        splits_by_index=[EvaluationSplit.TRAIN.value] * max(0, record_count),
    )

    if labels is None:
        return index

    def add_item(position: Optional[int], subject: Any, raw_label: Any, raw_weight: Any, raw_split: Any) -> None:
        code = _coerce_int_label(raw_label)
        weight = _clip_float(_coerce_optional_float(raw_weight, allow_bool=True), 0.0, 100.0, 1.0)
        split = _normalize_token(raw_split) or EvaluationSplit.TRAIN.value
        subject_hash = _subject_hash(subject, options) if subject is not None else None

        if subject_hash:
            if code is not None:
                index.by_subject[subject_hash] = code
            index.weights_by_subject[subject_hash] = weight
            index.splits_by_subject[subject_hash] = split

        if position is not None and 0 <= position < len(index.by_index):
            index.by_index[position] = code
            index.weights_by_index[position] = weight
            index.splits_by_index[position] = split

    if isinstance(labels, Mapping):
        subject_hashes = labels.get("subject_hashes") or labels.get("subjects")
        label_codes = labels.get("label_codes") or labels.get("labels") or labels.get("y")
        weights = labels.get("weights")
        splits = labels.get("splits")
        records = labels.get("records") or labels.get("items") or labels.get("rows")

        if subject_hashes is not None and label_codes is not None:
            subjects = _as_sequence(subject_hashes)
            codes = _as_sequence(label_codes)
            weight_seq = _as_sequence(weights) if weights is not None else []
            split_seq = _as_sequence(splits) if splits is not None else []

            for position in range(min(len(subjects), len(codes), max(record_count, len(codes)))):
                add_item(
                    position,
                    subjects[position],
                    codes[position],
                    weight_seq[position] if position < len(weight_seq) else 1.0,
                    split_seq[position] if position < len(split_seq) else EvaluationSplit.TRAIN.value,
                )

            return index

        if records is not None:
            for position, record in enumerate(_as_sequence(records)):
                if isinstance(record, Mapping):
                    add_item(
                        position,
                        _subject_from_mapping(record),
                        _label_code_from_mapping(record),
                        record.get("weight", 1.0),
                        record.get("split", EvaluationSplit.TRAIN.value),
                    )
                else:
                    add_item(position, None, record, 1.0, EvaluationSplit.TRAIN.value)

            return index

        if label_codes is not None:
            codes = _as_sequence(label_codes)
            weight_seq = _as_sequence(weights) if weights is not None else []
            split_seq = _as_sequence(splits) if splits is not None else []

            for position, code in enumerate(codes):
                add_item(
                    position,
                    None,
                    code,
                    weight_seq[position] if position < len(weight_seq) else 1.0,
                    split_seq[position] if position < len(split_seq) else EvaluationSplit.TRAIN.value,
                )

            return index

        code = _label_code_from_mapping(labels)

        if code is not None:
            add_item(
                0,
                _subject_from_mapping(labels),
                code,
                labels.get("weight", 1.0),
                labels.get("split", EvaluationSplit.TRAIN.value),
            )

        return index

    if hasattr(labels, "subject_hashes") and hasattr(labels, "label_codes"):
        subjects = _as_sequence(getattr(labels, "subject_hashes", ()) or ())
        codes = _as_sequence(getattr(labels, "label_codes", ()) or ())
        weights = _as_sequence(getattr(labels, "weights", ()) or ())
        splits = _as_sequence(getattr(labels, "splits", ()) or ())

        for position in range(min(len(subjects), len(codes), max(record_count, len(codes)))):
            add_item(
                position,
                subjects[position],
                codes[position],
                weights[position] if position < len(weights) else 1.0,
                splits[position] if position < len(splits) else EvaluationSplit.TRAIN.value,
            )

        return index

    records = getattr(labels, "records", None) or getattr(labels, "items", None)

    if records is not None:
        for position, record in enumerate(_as_sequence(records)):
            if isinstance(record, Mapping):
                add_item(
                    position,
                    _subject_from_mapping(record),
                    _label_code_from_mapping(record),
                    record.get("weight", 1.0),
                    record.get("split", EvaluationSplit.TRAIN.value),
                )
            else:
                add_item(position, None, record, 1.0, EvaluationSplit.TRAIN.value)

        return index

    for position, item in enumerate(_as_sequence(labels)):
        if isinstance(item, Mapping):
            add_item(
                position,
                _subject_from_mapping(item),
                _label_code_from_mapping(item),
                item.get("weight", 1.0),
                item.get("split", EvaluationSplit.TRAIN.value),
            )
        else:
            add_item(position, None, item, 1.0, EvaluationSplit.TRAIN.value)

    return index


def _label_summary(label_index: _LabelIndex) -> dict[str, Any]:
    counter = Counter(code for code in label_index.by_index if code is not None)
    counter.update(label_index.by_subject.values())
    total = sum(counter.values())

    distribution = {
        str(code): _round6(float(count) / float(total))
        for code, count in sorted(counter.items())
    } if total > 0 else {}

    return {
        "available": total > 0,
        "label_count": int(total),
        "class_count": int(len(counter)),
        "class_distribution": distribution,
        "records_omitted": True,
        "subject_label_pairs_omitted": True,
    }


def _records_feature_names(records: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    observed: set[str] = set()

    for record in records:
        features = record.get("features") if isinstance(record, Mapping) else {}

        if isinstance(features, Mapping):
            observed.update(_canonical_field_name(key) for key in features if _canonical_field_name(key))

    return tuple(sorted(observed))


def _input_fingerprint(records: Sequence[Mapping[str, Any]], label_index: _LabelIndex) -> str:
    feature_names = _records_feature_names(records)
    summary = _label_summary(label_index)

    payload = {
        "version": EVALUATION_VERSION,
        "record_count": len(records),
        "feature_count": len(feature_names),
        "feature_names_sample": list(feature_names[:_DEFAULT_MAX_SUMMARY_ITEMS]),
        "feature_names_truncated": len(feature_names) > _DEFAULT_MAX_SUMMARY_ITEMS,
        "label_summary": summary,
    }

    return _fingerprint_payload(payload)


def _derive_job_id(
    request: Any,
    options: EvalOptions,
    target: EvaluationTarget,
    split: EvaluationSplit,
    input_fp: str,
) -> str:
    payload = {
        "version": EVALUATION_VERSION,
        "target": target.value,
        "split": split.value,
        "options": options.safe_summary(),
        "request_metadata": _safe_detail_value(getattr(request, "metadata", {})),
        "tags": list(getattr(request, "tags", ()) or ()),
        "idempotency_key": getattr(request, "idempotency_key", None),
        "input_fingerprint": input_fp,
    }

    return _sha256_hex(_canonical_json(payload))[:32]


# -----------------------------------------------------------------------------
# Prediction resolution
# -----------------------------------------------------------------------------


def _prediction_from_item(item: Any, fallback_index: int, source: str) -> Optional[PredictionSnapshot]:
    if item is None:
        return None

    if isinstance(item, PredictionSnapshot):
        return item

    subject: Any = None
    index: Optional[int] = None
    score: Any = None
    predicted_label: Any = None
    probabilities: Any = None
    contributions: Any = None
    metadata: Any = None

    if isinstance(item, Mapping):
        subject = _subject_from_mapping(item)
        index = item.get("index")
        score = (
            item.get("score")
            if item.get("score") is not None
            else item.get("probability")
            if item.get("probability") is not None
            else item.get("positive_probability")
            if item.get("positive_probability") is not None
            else item.get("risk_score")
        )
        predicted_label = (
            item.get("predicted_label")
            if item.get("predicted_label") is not None
            else item.get("label_code")
            if item.get("label_code") is not None
            else item.get("prediction")
            if item.get("prediction") is not None
            else item.get("y_pred")
        )
        probabilities = item.get("probabilities") or item.get("probability_map")
        contributions = item.get("contributions") or item.get("features") or item.get("explanations")
        metadata = item.get("metadata")
    else:
        subject = getattr(item, "subject_ref_hash", None) or getattr(item, "subject_hash", None)
        index = getattr(item, "index", None)
        score = (
            getattr(item, "score", None)
            if getattr(item, "score", None) is not None
            else getattr(item, "probability", None)
            if getattr(item, "probability", None) is not None
            else getattr(item, "positive_probability", None)
            if getattr(item, "positive_probability", None) is not None
            else getattr(item, "risk_score", None)
        )
        predicted_label = (
            getattr(item, "predicted_label", None)
            if getattr(item, "predicted_label", None) is not None
            else getattr(item, "label_code", None)
            if getattr(item, "label_code", None) is not None
            else getattr(item, "prediction", None)
            if getattr(item, "prediction", None) is not None
            else getattr(item, "y_pred", None)
        )
        probabilities = getattr(item, "probabilities", None) or getattr(item, "probability_map", None)
        contributions = getattr(item, "contributions", None) or getattr(item, "explanations", None)
        metadata = getattr(item, "metadata", None)

    score_float = _coerce_optional_float(score, allow_bool=True)
    predicted_int = _coerce_int_label(predicted_label)

    prob_map: dict[str, float] = {}

    if isinstance(probabilities, Mapping):
        for key, value in probabilities.items():
            numeric = _coerce_optional_float(value, allow_bool=True)

            if numeric is not None:
                prob_map[_clean_text(key, 100)] = _round6(_clip_float(numeric, 0.0, 1.0, 0.0))

    contrib_tuple: tuple[dict[str, Any], ...] = ()

    if isinstance(contributions, Sequence) and not isinstance(contributions, (str, bytes, bytearray, memoryview)):
        contrib_tuple = tuple(
            dict(item)
            for item in contributions
            if isinstance(item, Mapping)
        )

    if score_float is None and predicted_int is not None:
        score_float = 1.0 if predicted_int in _DEFAULT_POSITIVE_LABEL_CODES else 0.0

    if score_float is None and prob_map:
        positive_candidates = [
            value
            for key, value in prob_map.items()
            if _normalize_token(key) in {"review", "escalate", "positive", "investigate", "high_priority", "critical", "urgent"}
        ]

        if positive_candidates:
            score_float = max(positive_candidates)
        else:
            score_float = max(prob_map.values())

    return PredictionSnapshot(
        subject_ref_hash=subject,
        index=_as_int(index, fallback_index) if index is not None else fallback_index,
        score=score_float,
        predicted_label=predicted_int,
        probabilities=prob_map,
        contributions=contrib_tuple,
        source=source,
        metadata=metadata,
    )


def _resolve_predictions(
    request: EvaluationJobRequest,
    records: Sequence[Mapping[str, Any]],
    options: EvalOptions,
    issues: list[EvaluationIssue],
) -> tuple[PredictionSnapshot, ...]:
    if request.predictions is not None:
        out: list[PredictionSnapshot] = []

        for index, item in enumerate(_as_sequence(request.predictions)):
            pred = _prediction_from_item(item, index, EvaluationTarget.EXTERNAL.value)

            if pred is not None:
                out.append(pred)

        if out:
            return tuple(out)

        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="external_predictions_unparsed",
            message="External prediction input could not be parsed and was ignored.",
        )

    # Model service inference.
    service = None

    if request.model is not None and hasattr(request.model, "infer"):
        service = request.model
    elif model_service_module is not None and request.model_id:
        getter = getattr(model_service_module, "get_model_service", None)

        if callable(getter):
            try:
                service = getter()
            except Exception:
                service = None

    if service is not None and hasattr(service, "infer"):
        try:
            response = service.infer(
                {
                    "records": list(records),
                    "model_id": request.model_id,
                    "mode": _target_value(request.target),
                    "threshold": request.threshold,
                    "include_contributions": bool(
                        request.include_contributions
                        if request.include_contributions is not None
                        else options.include_contributions
                    ),
                }
            )
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="model_service_infer_failed",
                message="Model service inference failed.",
                details={"exception_type": type(exc).__name__},
            )
            response = None

        if response is not None:
            out = []

            for index, item in enumerate(getattr(response, "records", ()) or ()):
                pred = _prediction_from_item(item, index, _target_value(request.target) or EvaluationTarget.HYBRID.value)

                if pred is not None:
                    out.append(pred)

            if out:
                return tuple(out)

    # Direct supervised model.
    if (
        supervised_module is not None
        and request.model is not None
        and hasattr(request.model, "parameters")
        and hasattr(supervised_module, "predict_supervised_model")
    ):
        try:
            batch = supervised_module.predict_supervised_model(
                request.model,
                list(records),
                include_contributions=bool(
                    request.include_contributions
                    if request.include_contributions is not None
                    else options.include_contributions
                ),
            )
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="supervised_prediction_failed",
                message="Supervised prediction failed.",
                details={"exception_type": type(exc).__name__},
            )
            batch = None

        if batch is not None:
            out = []

            for index, item in enumerate(getattr(batch, "predictions", ()) or ()):
                pred = _prediction_from_item(item, index, EvaluationTarget.SUPERVISED.value)

                if pred is not None:
                    out.append(pred)

            if out:
                return tuple(out)

    # Direct anomaly model.
    if anomaly_module is not None and request.model is not None and hasattr(request.model, "score"):
        try:
            result = request.model.score(
                list(records),
                include_contributions=bool(
                    request.include_contributions
                    if request.include_contributions is not None
                    else options.include_contributions
                ),
            )
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="anomaly_scoring_failed",
                message="Anomaly scoring failed.",
                details={"exception_type": type(exc).__name__},
            )
            result = None

        if result is not None:
            out = []

            for index, item in enumerate(getattr(result, "records", ()) or ()):
                pred = _prediction_from_item(item, index, EvaluationTarget.ANOMALY.value)

                if pred is not None:
                    out.append(pred)

            if out:
                return tuple(out)

    # Fallback scoring.
    if fallback_module is not None and hasattr(fallback_module, "score_fallback_batch"):
        try:
            result = fallback_module.score_fallback_batch(list(records))
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="fallback_scoring_failed",
                message="Fallback scoring failed.",
                details={"exception_type": type(exc).__name__},
            )
            result = None

        if result is not None:
            out = []

            for index, item in enumerate(getattr(result, "records", ()) or ()):
                pred = _prediction_from_item(item, index, EvaluationTarget.FALLBACK.value)

                if pred is not None:
                    out.append(pred)

            if out:
                return tuple(out)

    _append_issue(
        issues,
        options.max_issues,
        severity=IssueSeverity.ERROR,
        code="no_predictions_available",
        message="No predictions could be resolved from request input or available model integrations.",
    )
    return ()


# -----------------------------------------------------------------------------
# Row construction
# -----------------------------------------------------------------------------


def _build_eval_rows(
    records: Sequence[Mapping[str, Any]],
    predictions: Sequence[PredictionSnapshot],
    label_index: _LabelIndex,
    options: EvalOptions,
    issues: list[EvaluationIssue],
) -> list[dict[str, Any]]:
    pred_by_subject: dict[str, tuple[int, PredictionSnapshot]] = {}
    pred_by_index: dict[int, tuple[int, PredictionSnapshot]] = {}
    used: set[int] = set()

    for pred_position, pred in enumerate(predictions):
        if pred.subject_ref_hash:
            pred_by_subject.setdefault(pred.subject_ref_hash, (pred_position, pred))

        if pred.index is not None:
            pred_by_index.setdefault(int(pred.index), (pred_position, pred))

    rows: list[dict[str, Any]] = []

    for record in records:
        index = int(record.get("index", len(rows)))
        subject = record.get("subject_ref_hash")
        features = record.get("features") if isinstance(record.get("features"), Mapping) else {}

        pred_pair = None

        if subject and subject in pred_by_subject:
            pred_pair = pred_by_subject[subject]
        elif index in pred_by_index:
            pred_pair = pred_by_index[index]

        pred = pred_pair[1] if pred_pair is not None else None

        if pred_pair is not None:
            used.add(pred_pair[0])

        label_code = None
        weight = 1.0
        split = EvaluationSplit.TRAIN.value

        if subject and subject in label_index.by_subject:
            label_code = label_index.by_subject[subject]
            weight = label_index.weights_by_subject.get(subject, 1.0)
            split = label_index.splits_by_subject.get(subject, EvaluationSplit.TRAIN.value)
        elif 0 <= index < len(label_index.by_index):
            label_code = label_index.by_index[index]
            weight = label_index.weights_by_index[index] if index < len(label_index.weights_by_index) else 1.0
            split = label_index.splits_by_index[index] if index < len(label_index.splits_by_index) else EvaluationSplit.TRAIN.value

        rows.append(
            {
                "subject_ref_hash": subject,
                "index": index,
                "features": dict(features),
                "label_code": label_code,
                "weight": _clip_float(weight, 0.0, 100.0, 1.0),
                "split": _normalize_token(split) or EvaluationSplit.TRAIN.value,
                "score": pred.score if pred is not None else None,
                "predicted_label": pred.predicted_label if pred is not None else None,
                "probabilities": dict(pred.probabilities) if pred is not None else {},
                "contributions": tuple(pred.contributions) if pred is not None else (),
                "source": pred.source if pred is not None else "none",
            }
        )

    for pred_position, pred in enumerate(predictions):
        if pred_position in used:
            continue

        index = pred.index if pred.index is not None else len(rows)
        subject = pred.subject_ref_hash

        label_code = None
        weight = 1.0
        split = EvaluationSplit.TRAIN.value

        if subject and subject in label_index.by_subject:
            label_code = label_index.by_subject[subject]
            weight = label_index.weights_by_subject.get(subject, 1.0)
            split = label_index.splits_by_subject.get(subject, EvaluationSplit.TRAIN.value)
        elif 0 <= index < len(label_index.by_index):
            label_code = label_index.by_index[index]
            weight = label_index.weights_by_index[index] if index < len(label_index.weights_by_index) else 1.0
            split = label_index.splits_by_index[index] if index < len(label_index.splits_by_index) else EvaluationSplit.TRAIN.value

        rows.append(
            {
                "subject_ref_hash": subject,
                "index": index,
                "features": {},
                "label_code": label_code,
                "weight": _clip_float(weight, 0.0, 100.0, 1.0),
                "split": _normalize_token(split) or EvaluationSplit.TRAIN.value,
                "score": pred.score,
                "predicted_label": pred.predicted_label,
                "probabilities": dict(pred.probabilities),
                "contributions": tuple(pred.contributions),
                "source": pred.source,
            }
        )

    if not rows:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="no_evaluation_rows",
            message="No evaluation rows could be constructed.",
        )

    return rows


def _filter_rows_by_split(
    rows: Sequence[Mapping[str, Any]],
    split: EvaluationSplit,
) -> list[dict[str, Any]]:
    if split == EvaluationSplit.ALL:
        return [dict(row) for row in rows]

    target = split.value

    return [
        dict(row)
        for row in rows
        if _normalize_token(row.get("split")) == target
    ]


# -----------------------------------------------------------------------------
# Metric helpers
# -----------------------------------------------------------------------------


def _binary_label(
    label_code: Optional[int],
    positive_codes: set[int],
    negative_codes: set[int],
    ignore_codes: set[int],
) -> Optional[int]:
    if label_code is None:
        return None

    code = int(label_code)

    if code in ignore_codes:
        return None

    if code in positive_codes:
        return 1

    if code in negative_codes:
        return 0

    return None


def _binary_roc_auc(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
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


def _log_loss_binary(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    total = 0.0
    count = 0

    for label, score in zip(y_true, scores):
        if label not in (0, 1):
            continue

        p = _clip_float(score, 1e-12, 1.0 - 1e-12, 0.5)
        total -= float(label) * math.log(p) + (1.0 - float(label)) * math.log(1.0 - p)
        count += 1

    if count <= 0:
        return None

    return _round6(total / float(count))


def _brier_binary(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    total = 0.0
    count = 0

    for label, score in zip(y_true, scores):
        if label not in (0, 1):
            continue

        p = _clip_float(score, 0.0, 1.0, 0.0)
        total += (p - float(label)) ** 2
        count += 1

    if count <= 0:
        return None

    return _round6(total / float(count))


def _ece_binary(y_true: Sequence[int], scores: Sequence[float], bins: int) -> Optional[float]:
    pairs = [
        (int(label), _clip_float(float(score), 0.0, 1.0, 0.0))
        for label, score in zip(y_true, scores)
        if label in (0, 1)
    ]

    if not pairs:
        return None

    bin_count = max(2, int(bins))
    totals = [0.0 for _ in range(bin_count)]
    confidences = [0.0 for _ in range(bin_count)]
    accuracies = [0.0 for _ in range(bin_count)]

    for label, score in pairs:
        confidence = max(score, 1.0 - score)
        correct = 1.0 if (score >= 0.5 and label == 1) or (score < 0.5 and label == 0) else 0.0
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


def _calibration_curve(y_true: Sequence[int], scores: Sequence[float], bins: int) -> list[dict[str, Any]]:
    pairs = [
        (int(label), _clip_float(float(score), 0.0, 1.0, 0.0))
        for label, score in zip(y_true, scores)
        if label in (0, 1)
    ]

    if not pairs:
        return []

    bin_count = max(2, int(bins))
    totals = [0.0 for _ in range(bin_count)]
    predicted = [0.0 for _ in range(bin_count)]
    observed = [0.0 for _ in range(bin_count)]

    for label, score in pairs:
        index = min(bin_count - 1, int(score * bin_count))
        totals[index] += 1.0
        predicted[index] += score
        observed[index] += float(label)

    out: list[dict[str, Any]] = []

    for index in range(bin_count):
        if totals[index] <= 0:
            continue

        out.append(
            {
                "bin": index,
                "count": int(totals[index]),
                "avg_predicted": _round6(predicted[index] / totals[index]),
                "avg_observed": _round6(observed[index] / totals[index]),
            }
        )

    return out


def _binary_confusion(y_true: Sequence[int], scores: Sequence[float], threshold: float) -> dict[str, int]:
    tp = fp = tn = fn = 0
    cut = _clip_float(threshold, 0.0, 1.0, 0.5)

    for label, score in zip(y_true, scores):
        if label not in (0, 1):
            continue

        predicted = 1 if _clip_float(score, 0.0, 1.0, 0.0) >= cut else 0

        if predicted == 1 and label == 1:
            tp += 1
        elif predicted == 1 and label == 0:
            fp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _rates_from_confusion(confusion: Mapping[str, int]) -> dict[str, Optional[float]]:
    tp = int(confusion.get("tp", 0))
    fp = int(confusion.get("fp", 0))
    tn = int(confusion.get("tn", 0))
    fn = int(confusion.get("fn", 0))

    precision = float(tp) / float(tp + fp) if (tp + fp) > 0 else None
    recall = float(tp) / float(tp + fn) if (tp + fn) > 0 else None
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )
    fpr = float(fp) / float(fp + tn) if (fp + tn) > 0 else None
    tnr = float(tn) / float(tn + fp) if (tn + fp) > 0 else None
    fnr = float(fn) / float(fn + tp) if (fn + tp) > 0 else None
    balanced_accuracy = (
        (recall + tnr) / 2.0
        if recall is not None and tnr is not None
        else None
    )
    you_j = (
        (recall - fpr)
        if recall is not None and fpr is not None
        else None
    )

    return {
        "precision": _round6(precision) if precision is not None else None,
        "recall": _round6(recall) if recall is not None else None,
        "f1": _round6(f1) if f1 is not None else None,
        "fpr": _round6(fpr) if fpr is not None else None,
        "tnr": _round6(tnr) if tnr is not None else None,
        "fnr": _round6(fnr) if fnr is not None else None,
        "balanced_accuracy": _round6(balanced_accuracy) if balanced_accuracy is not None else None,
        "you_j": _round6(you_j) if you_j is not None else None,
    }


def _multiclass_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    classes: Sequence[int],
) -> dict[str, Any]:
    class_list = sorted({int(code) for code in classes if code is not None})

    if not class_list:
        return {}

    index_map = {code: position for position, code in enumerate(class_list)}
    k = len(class_list)
    confusion = [[0 for _ in range(k)] for _ in range(k)]
    correct = 0
    total = 0

    for true_label, predicted_label in zip(y_true, y_pred):
        if true_label is None or predicted_label is None:
            continue

        true_index = index_map.get(int(true_label))
        pred_index = index_map.get(int(predicted_label))

        if true_index is None or pred_index is None:
            continue

        confusion[true_index][pred_index] += 1
        total += 1

        if true_index == pred_index:
            correct += 1

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

    for class_index, class_code in enumerate(class_list):
        tp = confusion[class_index][class_index]
        fp = sum(confusion[row][class_index] for row in range(k)) - tp
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
                "class_code": int(class_code),
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

    return {
        "accuracy": _round6(accuracy),
        "macro_precision": _round6(macro_precision / float(k)),
        "macro_recall": _round6(macro_recall / float(k)),
        "macro_f1": _round6(macro_f1 / float(k)),
        "weighted_precision": _round6(weighted_precision),
        "weighted_recall": _round6(weighted_recall),
        "weighted_f1": _round6(weighted_f1),
        "per_class": per_class,
        "confusion": confusion,
        "classes": class_list,
        "total": int(total),
    }


def _score_distribution(scores: Sequence[float]) -> dict[str, Any]:
    values = sorted(
        _round6(_clip_float(score, 0.0, 1.0, 0.0))
        for score in scores
        if _coerce_optional_float(score, allow_bool=True) is not None
    )

    if not values:
        return {"available": False, "count": 0}

    mean = _mean(values)

    return {
        "available": True,
        "count": len(values),
        "min": _round6(values[0]),
        "max": _round6(values[-1]),
        "mean": _round6(mean),
        "std": _round6(_stddev(values, mean)),
        "p05": _round6(_quantile_sorted(values, 0.05)),
        "p25": _round6(_quantile_sorted(values, 0.25)),
        "p50": _round6(_quantile_sorted(values, 0.50)),
        "p75": _round6(_quantile_sorted(values, 0.75)),
        "p95": _round6(_quantile_sorted(values, 0.95)),
    }


def _compute_metrics(
    rows: Sequence[Mapping[str, Any]],
    threshold: float,
    request: EvaluationJobRequest,
    options: EvalOptions,
) -> dict[str, Any]:
    positive_codes = set(request.positive_label_codes or _DEFAULT_POSITIVE_LABEL_CODES)
    negative_codes = set(request.negative_label_codes or _DEFAULT_NEGATIVE_LABEL_CODES)
    ignore_codes = set(request.ignore_label_codes or _DEFAULT_IGNORE_LABEL_CODES)

    binary_y: list[int] = []
    binary_scores: list[float] = []
    multiclass_y: list[int] = []
    multiclass_pred: list[int] = []
    all_scores: list[float] = []
    labelled = 0
    scored = 0
    predicted = 0

    for row in rows:
        label_code = row.get("label_code")
        score = _coerce_optional_float(row.get("score"), allow_bool=True)
        predicted_label = _coerce_int_label(row.get("predicted_label"))

        if label_code is not None:
            labelled += 1

        if score is not None:
            scored += 1
            all_scores.append(_clip_float(score, 0.0, 1.0, 0.0))

        if predicted_label is not None:
            predicted += 1

        binary_label = _binary_label(
            _coerce_int_label(label_code),
            positive_codes,
            negative_codes,
            ignore_codes,
        )

        if binary_label is not None and score is not None:
            binary_y.append(binary_label)
            binary_scores.append(_clip_float(score, 0.0, 1.0, 0.0))

        if label_code is not None and predicted_label is not None and int(label_code) not in ignore_codes:
            multiclass_y.append(int(label_code))
            multiclass_pred.append(int(predicted_label))

    metrics: dict[str, Any] = {
        "available": bool(rows),
        "counts": {
            "rows": len(rows),
            "labelled": labelled,
            "scored": scored,
            "predicted": predicted,
            "binary_evaluable": len(binary_y),
            "multiclass_evaluable": len(multiclass_y),
        },
        "score_distribution": _score_distribution(all_scores),
    }

    if binary_y:
        confusion = _binary_confusion(binary_y, binary_scores, threshold)
        rates = _rates_from_confusion(confusion)
        metrics["binary"] = {
            "available": True,
            "threshold": _round6(threshold),
            "confusion": confusion,
            "roc_auc": _binary_roc_auc(binary_y, binary_scores),
            "pr_auc": _binary_pr_auc(binary_y, binary_scores),
            "log_loss": _log_loss_binary(binary_y, binary_scores),
            "brier_score": _brier_binary(binary_y, binary_scores),
            "expected_calibration_error": _ece_binary(binary_y, binary_scores, options.ece_bins),
            **rates,
        }
        metrics["calibration"] = {
            "available": True,
            "bins": options.ece_bins,
            "curve": _calibration_curve(binary_y, binary_scores, options.ece_bins),
            "expected_calibration_error": metrics["binary"]["expected_calibration_error"],
        }
    else:
        metrics["binary"] = {"available": False, "reason": "insufficient_binary_labels_or_scores"}
        metrics["calibration"] = {"available": False, "reason": "insufficient_binary_labels_or_scores"}

    if multiclass_y:
        metrics["multiclass"] = _multiclass_metrics(multiclass_y, multiclass_pred, sorted(set(multiclass_y)))
    else:
        metrics["multiclass"] = {"available": False, "reason": "insufficient_predicted_labels"}

    return metrics


# -----------------------------------------------------------------------------
# Threshold sweep
# -----------------------------------------------------------------------------


def _threshold_candidates(scores: Sequence[float], max_points: int) -> tuple[float, ...]:
    values = sorted(
        {
            _round6(_clip_float(score, 0.0, 1.0, 0.0))
            for score in scores
            if _coerce_optional_float(score, allow_bool=True) is not None
        }
    )

    if not values:
        return (0.0, 0.5, 1.0)

    limit = max(3, int(max_points))

    if len(values) <= limit:
        out = values
    else:
        positions = {0, len(values) - 1}

        for index in range(limit - 2):
            positions.add(int(round((len(values) - 1) * float(index + 1) / float(limit - 1))))

        out = [values[position] for position in sorted(positions)]

    if 0.0 not in out:
        out.insert(0, 0.0)

    if 1.0 not in out:
        out.append(1.0)

    return tuple(sorted(set(_round6(value) for value in out)))


def _threshold_point(y_true: Sequence[int], scores: Sequence[float], threshold: float) -> ThresholdPoint:
    confusion = _binary_confusion(y_true, scores, threshold)
    rates = _rates_from_confusion(confusion)

    return ThresholdPoint(
        threshold=threshold,
        tp=confusion["tp"],
        fp=confusion["fp"],
        tn=confusion["tn"],
        fn=confusion["fn"],
        precision=rates["precision"],
        recall=rates["recall"],
        f1=rates["f1"],
        fpr=rates["fpr"],
        fnr=rates["fnr"],
        tnr=rates["tnr"],
        balanced_accuracy=rates["balanced_accuracy"],
        you_j=rates["you_j"],
    )


def _select_threshold_point(
    points: Sequence[ThresholdPoint],
    policy: ThresholdPolicy,
    fixed_threshold: float,
    max_fpr: Optional[float],
    min_recall: Optional[float],
    min_precision: Optional[float],
) -> ThresholdPoint:
    if not points:
        return ThresholdPoint(threshold=fixed_threshold, tp=0, fp=0, tn=0, fn=0)

    if policy == ThresholdPolicy.FIXED:
        closest = min(points, key=lambda point: abs(float(point.threshold) - float(fixed_threshold)))
        return closest

    if policy == ThresholdPolicy.MAX_F1:
        return max(
            points,
            key=lambda point: (
                float(point.f1 if point.f1 is not None else -1.0),
                -abs(float(point.threshold) - 0.5),
                float(point.threshold),
            ),
        )

    if policy == ThresholdPolicy.MAX_YOU_J:
        return max(
            points,
            key=lambda point: (
                float(point.you_j if point.you_j is not None else -1.0),
                float(point.f1 if point.f1 is not None else -1.0),
                float(point.threshold),
            ),
        )

    if policy == ThresholdPolicy.BALANCED_ACCURACY:
        return max(
            points,
            key=lambda point: (
                float(point.balanced_accuracy if point.balanced_accuracy is not None else -1.0),
                float(point.f1 if point.f1 is not None else -1.0),
                float(point.threshold),
            ),
        )

    if policy == ThresholdPolicy.MIN_FNR_AT_FPR and max_fpr is not None:
        eligible = [
            point
            for point in points
            if point.fpr is not None and float(point.fpr) <= float(max_fpr)
        ]

        if eligible:
            return min(
                eligible,
                key=lambda point: (
                    float(point.fnr if point.fnr is not None else 1.0),
                    -float(point.f1 if point.f1 is not None else -1.0),
                    float(point.threshold),
                ),
            )

    if policy == ThresholdPolicy.MAX_PRECISION_AT_RECALL and min_recall is not None:
        eligible = [
            point
            for point in points
            if point.recall is not None and float(point.recall) >= float(min_recall)
        ]

        if eligible:
            return max(
                eligible,
                key=lambda point: (
                    float(point.precision if point.precision is not None else -1.0),
                    float(point.f1 if point.f1 is not None else -1.0),
                    float(point.threshold),
                ),
            )

    if min_precision is not None:
        eligible = [
            point
            for point in points
            if point.precision is not None and float(point.precision) >= float(min_precision)
        ]

        if eligible:
            return max(
                eligible,
                key=lambda point: (
                    float(point.recall if point.recall is not None else -1.0),
                    float(point.f1 if point.f1 is not None else -1.0),
                    float(point.threshold),
                ),
            )

    return max(
        points,
        key=lambda point: (
            float(point.f1 if point.f1 is not None else -1.0),
            float(point.threshold),
        ),
    )


def _threshold_sweep(
    rows: Sequence[Mapping[str, Any]],
    request: EvaluationJobRequest,
    options: EvalOptions,
) -> tuple[tuple[ThresholdPoint, ...], Optional[ThresholdPoint], str]:
    positive_codes = set(request.positive_label_codes or _DEFAULT_POSITIVE_LABEL_CODES)
    negative_codes = set(request.negative_label_codes or _DEFAULT_NEGATIVE_LABEL_CODES)
    ignore_codes = set(request.ignore_label_codes or _DEFAULT_IGNORE_LABEL_CODES)

    y_true: list[int] = []
    scores: list[float] = []

    for row in rows:
        binary_label = _binary_label(
            _coerce_int_label(row.get("label_code")),
            positive_codes,
            negative_codes,
            ignore_codes,
        )
        score = _coerce_optional_float(row.get("score"), allow_bool=True)

        if binary_label is None or score is None:
            continue

        y_true.append(binary_label)
        scores.append(_clip_float(score, 0.0, 1.0, 0.0))

    if not y_true:
        return (), None, "unavailable"

    candidates = _threshold_candidates(scores, options.max_threshold_points)
    points = tuple(_threshold_point(y_true, scores, threshold) for threshold in candidates)

    policy = _normalize_enum_option(
        ThresholdPolicy,
        request.threshold_policy or options.threshold_policy,
        ThresholdPolicy.FIXED,
    )
    fixed_threshold = request.threshold if request.threshold is not None else options.threshold
    selected = _select_threshold_point(
        points,
        policy,
        fixed_threshold,
        request.max_fpr,
        request.min_recall,
        request.min_precision,
    )

    return points, selected, policy.value


# -----------------------------------------------------------------------------
# Slice analysis
# -----------------------------------------------------------------------------


_BOOTSTRAP_SAMPLE_CAP: Final[int] = 2_000

_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "features",
        "labels",
        "predictions",
        "model",
        "model_id",
        "target",
        "split",
        "selection_split",
        "threshold",
        "threshold_policy",
        "positive_label_codes",
        "negative_label_codes",
        "ignore_label_codes",
        "max_fpr",
        "min_recall",
        "min_precision",
        "slices",
        "include_contributions",
        "include_slices",
        "include_stability",
        "include_threshold_sweep",
        "metadata",
        "tags",
        "job_id",
        "idempotency_key",
    }
)

_COMPARISON_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "features",
        "labels",
        "candidates",
        "split",
        "positive_label_codes",
        "negative_label_codes",
        "ignore_label_codes",
        "primary_metric",
        "metadata",
        "tags",
        "job_id",
        "idempotency_key",
    }
)

_METRIC_KEYS: Final[tuple[str, ...]] = (
    "roc_auc",
    "pr_auc",
    "f1",
    "precision",
    "recall",
    "fpr",
    "fnr",
    "tnr",
    "balanced_accuracy",
    "you_j",
    "log_loss",
    "brier_score",
    "expected_calibration_error",
    "accuracy",
    "macro_f1",
    "weighted_f1",
)

_BINARY_BOOTSTRAP_METRICS: Final[tuple[str, ...]] = (
    "roc_auc",
    "pr_auc",
    "f1",
    "precision",
    "recall",
    "balanced_accuracy",
    "you_j",
    "log_loss",
    "brier_score",
    "expected_calibration_error",
)


def _slice_group_key(feature: str, bucket: str, options: EvalOptions) -> str:
    """
    Return a bounded pseudonymous slice group id.

    Raw bucket semantics are not exposed beyond safe bucket labels such as
    ``q0``, ``q1``, ``true``, ``false``, ``missing``, or a hash token.
    """
    domain = f"muleguard.ml.evaluate.slice.{_normalize_token(options.namespace)}"
    return _hmac_hex(options.salt, domain, f"{feature}\x00{bucket}")[:32]


def _slice_groups(
    rows: Sequence[Mapping[str, Any]],
    spec: SliceSpec,
    options: EvalOptions,
) -> list[tuple[str, str, list[dict[str, Any]]]]:
    """
    Build bounded slice groups for one slice specification.

    This never returns raw feature values. Numeric buckets are quantile labels,
    categorical buckets are salted hash tokens, and binary buckets are
    ``true``/``false``/``missing``.
    """
    if not rows:
        return []

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    method = spec.method

    if method == SliceMethod.NUMERIC_QUANTILE:
        values: list[float] = []

        for row in rows:
            features = row.get("features")

            if not isinstance(features, Mapping):
                continue

            numeric = _coerce_optional_float(features.get(spec.feature), allow_bool=True)

            if numeric is not None:
                values.append(_clip_float(numeric, -1e12, 1e12, 0.0))

        if len(values) < max(spec.min_count, options.min_slice_count):
            return []

        sorted_values = sorted(values)
        bins = max(2, int(spec.bins))
        edges = [
            _quantile_sorted(sorted_values, float(index) / float(bins))
            for index in range(1, bins)
        ]

        for row in rows:
            features = row.get("features")

            if not isinstance(features, Mapping):
                features = {}

            numeric = _coerce_optional_float(features.get(spec.feature), allow_bool=True)

            if numeric is None:
                bucket = "missing"
            else:
                bucket = f"q{bisect.bisect_right(edges, _clip_float(numeric, -1e12, 1e12, 0.0))}"

            groups[bucket].append(dict(row))

    elif method == SliceMethod.CATEGORICAL_HASH:
        domain = f"muleguard.ml.evaluate.slice_category.{_normalize_token(options.namespace)}"

        for row in rows:
            features = row.get("features")

            if not isinstance(features, Mapping):
                features = {}

            raw = features.get(spec.feature)
            token = _normalize_token(raw)

            if not token:
                bucket = "missing"
            else:
                bucket = _hmac_hex(options.salt, domain, token)[:12]

            groups[bucket].append(dict(row))

    elif method == SliceMethod.BINARY_FLAG:
        for row in rows:
            features = row.get("features")

            if not isinstance(features, Mapping):
                features = {}

            parsed = _coerce_bool(features.get(spec.feature))

            if parsed is None:
                bucket = "missing"
            else:
                bucket = "true" if parsed else "false"

            groups[bucket].append(dict(row))

    else:
        for row in rows:
            features = row.get("features")

            if not isinstance(features, Mapping):
                features = {}

            raw = features.get(spec.feature)
            bucket = "missing" if raw is None or (isinstance(raw, str) and not raw.strip()) else "present"
            groups[bucket].append(dict(row))

    out: list[tuple[str, str, list[dict[str, Any]]]] = []
    min_count = max(spec.min_count, options.min_slice_count)

    for bucket, bucket_rows in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        if len(bucket_rows) < min_count:
            continue

        slice_id = _slice_group_key(spec.feature, bucket, options)
        out.append((slice_id, bucket, bucket_rows))

    return out


def _feature_slice_specs(
    rows: Sequence[Mapping[str, Any]],
    request: EvaluationJobRequest,
    options: EvalOptions,
) -> tuple[SliceSpec, ...]:
    """
    Resolve explicit or automatic bounded slice specifications.
    """
    if request.slices:
        return tuple(request.slices[: options.max_slice_groups])

    if not rows:
        return ()

    stats: dict[str, dict[str, Any]] = {}
    sample_limit = min(len(rows), max(options.min_slice_count * 20, 1_000))

    for row in rows[:sample_limit]:
        features = row.get("features")

        if not isinstance(features, Mapping):
            continue

        for raw_feature, raw_value in features.items():
            feature = _canonical_field_name(raw_feature)

            if not feature:
                continue

            if feature in _SUBJECT_KEYS or feature in _NON_FEATURE_KEYS:
                continue

            if _is_forbidden_key(feature) or _is_label_leakage_key(feature):
                continue

            stat = stats.setdefault(
                feature,
                {
                    "count": 0,
                    "missing": 0,
                    "nonmissing": 0,
                    "numeric": 0,
                    "bool": 0,
                    "distinct": set(),
                },
            )

            stat["count"] += 1

            if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
                stat["missing"] += 1
                continue

            stat["nonmissing"] += 1

            parsed_bool = _coerce_bool(raw_value)

            if parsed_bool is not None:
                stat["bool"] += 1

            parsed_float = _coerce_optional_float(raw_value, allow_bool=False)

            if parsed_float is not None:
                stat["numeric"] += 1

            if len(stat["distinct"]) < 20:
                stat["distinct"].add(_normalize_token(raw_value) or str(raw_value))

    eligible = [
        (feature, stat)
        for feature, stat in stats.items()
        if int(stat.get("nonmissing", 0)) >= options.min_slice_count
    ]
    eligible.sort(key=lambda item: (-int(item[1].get("nonmissing", 0)), item[0]))

    specs: list[SliceSpec] = []

    for feature, stat in eligible[: options.max_slice_groups]:
        nonmissing = max(1, int(stat.get("nonmissing", 0)))
        bool_count = int(stat.get("bool", 0))
        numeric_count = int(stat.get("numeric", 0))
        distinct = stat.get("distinct") or set()

        if bool_count == nonmissing and len(distinct) <= 2:
            method = SliceMethod.BINARY_FLAG
        elif numeric_count >= int(0.8 * nonmissing) and len(distinct) > 2:
            method = SliceMethod.NUMERIC_QUANTILE
        else:
            method = SliceMethod.CATEGORICAL_HASH

        specs.append(
            SliceSpec(
                feature=feature,
                method=method,
                bins=4,
                min_count=options.min_slice_count,
            )
        )

    return tuple(specs)


def _binary_metrics_from_arrays(
    y_true: Sequence[int],
    scores: Sequence[float],
    threshold: float,
    options: EvalOptions,
) -> dict[str, Any]:
    """
    Compute bounded binary metrics from aligned label/score arrays.
    """
    if not y_true or not scores:
        return {"available": False, "reason": "insufficient_binary_labels_or_scores"}

    confusion = _binary_confusion(y_true, scores, threshold)
    rates = _rates_from_confusion(confusion)

    return {
        "available": True,
        "threshold": _round6(threshold),
        "count": len(y_true),
        "positive_count": sum(1 for label in y_true if int(label) == 1),
        "negative_count": sum(1 for label in y_true if int(label) == 0),
        "confusion": confusion,
        "roc_auc": _binary_roc_auc(y_true, scores),
        "pr_auc": _binary_pr_auc(y_true, scores),
        "log_loss": _log_loss_binary(y_true, scores),
        "brier_score": _brier_binary(y_true, scores),
        "expected_calibration_error": _ece_binary(y_true, scores, options.ece_bins),
        **rates,
    }


def _extract_binary_arrays(
    rows: Sequence[Mapping[str, Any]],
    request: Any,
) -> tuple[list[int], list[float], list[str]]:
    """
    Extract aligned binary labels, scores, and row keys.
    """
    positive_codes = set(
        getattr(request, "positive_label_codes", None) or _DEFAULT_POSITIVE_LABEL_CODES
    )
    negative_codes = set(
        getattr(request, "negative_label_codes", None) or _DEFAULT_NEGATIVE_LABEL_CODES
    )
    ignore_codes = set(
        getattr(request, "ignore_label_codes", None) or _DEFAULT_IGNORE_LABEL_CODES
    )

    y: list[int] = []
    scores: list[float] = []
    keys: list[str] = []

    for row in rows:
        label_code = _coerce_int_label(row.get("label_code"))
        binary_label = _binary_label(label_code, positive_codes, negative_codes, ignore_codes)
        score = _coerce_optional_float(row.get("score"), allow_bool=True)

        if binary_label is None or score is None:
            continue

        key = _row_alignment_key(row)

        if key is None:
            continue

        y.append(binary_label)
        scores.append(_clip_float(score, 0.0, 1.0, 0.0))
        keys.append(key)

    return y, scores, keys


def _row_alignment_key(row: Mapping[str, Any]) -> Optional[str]:
    """
    Return a stable alignment key for one evaluation row.
    """
    subject = row.get("subject_ref_hash")

    if subject:
        return str(subject).lower()

    index = row.get("index")

    if index is not None:
        return f"index:{int(index)}"

    return None


def _align_rows(
    left_rows: Sequence[Mapping[str, Any]],
    right_rows: Sequence[Mapping[str, Any]],
    request: Any,
) -> tuple[list[int], list[float], list[float]]:
    """
    Align two row sets by subject hash or index and extract paired binary arrays.
    """
    positive_codes = set(
        getattr(request, "positive_label_codes", None) or _DEFAULT_POSITIVE_LABEL_CODES
    )
    negative_codes = set(
        getattr(request, "negative_label_codes", None) or _DEFAULT_NEGATIVE_LABEL_CODES
    )
    ignore_codes = set(
        getattr(request, "ignore_label_codes", None) or _DEFAULT_IGNORE_LABEL_CODES
    )

    left_map: dict[str, Mapping[str, Any]] = {}
    right_map: dict[str, Mapping[str, Any]] = {}

    for row in left_rows:
        key = _row_alignment_key(row)

        if key:
            left_map[key] = row

    for row in right_rows:
        key = _row_alignment_key(row)

        if key:
            right_map[key] = row

    y: list[int] = []
    left_scores: list[float] = []
    right_scores: list[float] = []

    for key in sorted(set(left_map) & set(right_map)):
        left = left_map[key]
        right = right_map[key]

        label_code = _coerce_int_label(left.get("label_code"))

        if label_code is None:
            label_code = _coerce_int_label(right.get("label_code"))

        binary_label = _binary_label(label_code, positive_codes, negative_codes, ignore_codes)
        left_score = _coerce_optional_float(left.get("score"), allow_bool=True)
        right_score = _coerce_optional_float(right.get("score"), allow_bool=True)

        if binary_label is None or left_score is None or right_score is None:
            continue

        y.append(binary_label)
        left_scores.append(_clip_float(left_score, 0.0, 1.0, 0.0))
        right_scores.append(_clip_float(right_score, 0.0, 1.0, 0.0))

    return y, left_scores, right_scores


def _metric_value_from_arrays(
    metric: str,
    y_true: Sequence[int],
    scores: Sequence[float],
    threshold: float,
    options: EvalOptions,
) -> Optional[float]:
    """
    Compute one binary metric from arrays.
    """
    resolved = _normalize_token(metric)

    if resolved not in _BINARY_BOOTSTRAP_METRICS:
        return None

    metrics = _binary_metrics_from_arrays(y_true, scores, threshold, options)

    if not metrics.get("available"):
        return None

    return _coerce_optional_float(metrics.get(resolved), allow_bool=False)


def _metric_from_core(core: Mapping[str, Any], metric: str) -> Optional[float]:
    """
    Extract one metric value from a core metrics mapping.
    """
    if not isinstance(core, Mapping):
        return None

    resolved = _normalize_token(metric)
    value = core.get(resolved)

    if value is not None:
        return _coerce_optional_float(value, allow_bool=False)

    for section in ("binary", "multiclass"):
        nested = core.get(section)

        if isinstance(nested, Mapping):
            value = nested.get(resolved)

            if value is not None:
                return _coerce_optional_float(value, allow_bool=False)

    return None


def _single_bootstrap_interval(
    rows: Sequence[Mapping[str, Any]],
    metric: str,
    threshold: float,
    request: Any,
    options: EvalOptions,
) -> BootstrapInterval:
    """
    Compute one deterministic non-paired bootstrap interval.
    """
    resolved_metric = _normalize_token(metric)
    y, scores, _keys = _extract_binary_arrays(rows, request)

    if not y or resolved_metric not in _BINARY_BOOTSTRAP_METRICS:
        return BootstrapInterval(
            metric=resolved_metric,
            point_estimate=None,
            ci_low=None,
            ci_high=None,
            iterations=0,
            available=False,
        )

    original = _metric_value_from_arrays(resolved_metric, y, scores, threshold, options)
    iterations = max(0, int(options.max_bootstrap_iterations))
    n = len(y)
    sample_n = min(n, _BOOTSTRAP_SAMPLE_CAP)

    if iterations <= 0 or sample_n < 2 or original is None:
        return BootstrapInterval(
            metric=resolved_metric,
            point_estimate=original,
            ci_low=None,
            ci_high=None,
            iterations=iterations,
            available=False,
        )

    domain = f"muleguard.ml.evaluate.bootstrap_single.{resolved_metric}"
    values: list[float] = []

    for iteration in range(iterations):
        sampled_y: list[int] = []
        sampled_scores: list[float] = []

        for draw in range(sample_n):
            index = _stable_rank(
                options.salt,
                domain,
                iteration,
                draw,
                n,
            ) % n
            sampled_y.append(y[index])
            sampled_scores.append(scores[index])

        value = _metric_value_from_arrays(resolved_metric, sampled_y, sampled_scores, threshold, options)

        if value is not None:
            values.append(float(value))

    if not values:
        return BootstrapInterval(
            metric=resolved_metric,
            point_estimate=original,
            ci_low=None,
            ci_high=None,
            iterations=iterations,
            available=False,
        )

    ordered = sorted(values)
    ci_low = _quantile_sorted(ordered, 0.025)
    ci_high = _quantile_sorted(ordered, 0.975)

    return BootstrapInterval(
        metric=resolved_metric,
        point_estimate=original,
        ci_low=ci_low,
        ci_high=ci_high,
        iterations=len(values),
        available=True,
    )


def _paired_bootstrap_interval(
    y_true: Sequence[int],
    baseline_scores: Sequence[float],
    candidate_scores: Sequence[float],
    metric: str,
    baseline_threshold: float,
    candidate_threshold: float,
    options: EvalOptions,
) -> BootstrapInterval:
    """
    Compute one deterministic paired bootstrap interval for metric delta.
    """
    resolved_metric = _normalize_token(metric)
    n = min(len(y_true), len(baseline_scores), len(candidate_scores))

    if (
        n <= 0
        or resolved_metric not in _BINARY_BOOTSTRAP_METRICS
        or options.max_bootstrap_iterations <= 0
    ):
        return BootstrapInterval(
            metric=resolved_metric,
            point_estimate=None,
            ci_low=None,
            ci_high=None,
            iterations=0,
            available=False,
        )

    baseline_original = _metric_value_from_arrays(
        resolved_metric,
        y_true[:n],
        baseline_scores[:n],
        baseline_threshold,
        options,
    )
    candidate_original = _metric_value_from_arrays(
        resolved_metric,
        y_true[:n],
        candidate_scores[:n],
        candidate_threshold,
        options,
    )

    original_delta = (
        candidate_original - baseline_original
        if baseline_original is not None and candidate_original is not None
        else None
    )

    sample_n = min(n, _BOOTSTRAP_SAMPLE_CAP)
    iterations = max(0, int(options.max_bootstrap_iterations))

    if sample_n < 2 or iterations <= 0:
        return BootstrapInterval(
            metric=resolved_metric,
            point_estimate=original_delta,
            ci_low=None,
            ci_high=None,
            iterations=iterations,
            available=False,
        )

    domain = f"muleguard.ml.evaluate.bootstrap_paired.{resolved_metric}"
    deltas: list[float] = []

    for iteration in range(iterations):
        sampled_y: list[int] = []
        sampled_baseline: list[float] = []
        sampled_candidate: list[float] = []

        for draw in range(sample_n):
            index = _stable_rank(
                options.salt,
                domain,
                iteration,
                draw,
                n,
            ) % n
            sampled_y.append(y_true[index])
            sampled_baseline.append(baseline_scores[index])
            sampled_candidate.append(candidate_scores[index])

        baseline_value = _metric_value_from_arrays(
            resolved_metric,
            sampled_y,
            sampled_baseline,
            baseline_threshold,
            options,
        )
        candidate_value = _metric_value_from_arrays(
            resolved_metric,
            sampled_y,
            sampled_candidate,
            candidate_threshold,
            options,
        )

        if baseline_value is not None and candidate_value is not None:
            deltas.append(float(candidate_value - baseline_value))

    if not deltas:
        return BootstrapInterval(
            metric=resolved_metric,
            point_estimate=original_delta,
            ci_low=None,
            ci_high=None,
            iterations=iterations,
            available=False,
        )

    ordered = sorted(deltas)
    ci_low = _quantile_sorted(ordered, 0.025)
    ci_high = _quantile_sorted(ordered, 0.975)
    point_estimate = original_delta if original_delta is not None else _mean(deltas)

    return BootstrapInterval(
        metric=resolved_metric,
        point_estimate=point_estimate,
        ci_low=ci_low,
        ci_high=ci_high,
        iterations=len(deltas),
        available=True,
    )


def _verdict_from_interval(interval: Optional[BootstrapInterval], delta: Optional[float]) -> str:
    """
    Return a bounded pairwise verdict.

    This is an evaluation artefact only. It is not an adjudication.
    """
    if interval is not None and interval.available:
        low = _coerce_optional_float(interval.ci_low, allow_bool=False)
        high = _coerce_optional_float(interval.ci_high, allow_bool=False)

        if low is not None and high is not None:
            if low > 1e-12:
                return "IMPROVES"

            if high < -1e-12:
                return "DEGRADES"

            return "UNCERTAIN"

    if delta is not None:
        if delta > 1e-12:
            return "IMPROVES"

        if delta < -1e-12:
            return "DEGRADES"

        return "NEUTRAL"

    return "UNCERTAIN"


def _analyze_slices(
    rows: Sequence[Mapping[str, Any]],
    request: EvaluationJobRequest,
    options: EvalOptions,
    issues: list[EvaluationIssue],
    threshold: float,
) -> tuple[SliceResult, ...]:
    """
    Produce bounded slice summaries.

    Slice outputs are investigative diagnostics only. They are not causal proof
    and must not trigger automatic adverse customer action.
    """
    if options.max_slices <= 0 or not rows:
        return ()

    specs = _feature_slice_specs(rows, request, options)

    if not specs:
        return ()

    positive_codes = set(request.positive_label_codes or _DEFAULT_POSITIVE_LABEL_CODES)
    negative_codes = set(request.negative_label_codes or _DEFAULT_NEGATIVE_LABEL_CODES)
    ignore_codes = set(request.ignore_label_codes or _DEFAULT_IGNORE_LABEL_CODES)

    slices: list[SliceResult] = []

    for spec in specs:
        groups = _slice_groups(rows, spec, options)

        for slice_id, bucket, group_rows in groups:
            if len(slices) >= options.max_slices:
                break

            y: list[int] = []
            scores: list[float] = []
            score_values: list[float] = []
            positive_count = 0
            negative_count = 0

            for row in group_rows:
                label_code = _coerce_int_label(row.get("label_code"))
                binary_label = _binary_label(label_code, positive_codes, negative_codes, ignore_codes)
                score = _coerce_optional_float(row.get("score"), allow_bool=True)

                if binary_label == 1:
                    positive_count += 1
                elif binary_label == 0:
                    negative_count += 1

                if score is not None:
                    clipped = _clip_float(score, 0.0, 1.0, 0.0)
                    score_values.append(clipped)

                if binary_label is not None and score is not None:
                    y.append(binary_label)
                    scores.append(_clip_float(score, 0.0, 1.0, 0.0))

            metrics = (
                _binary_metrics_from_arrays(y, scores, threshold, options)
                if y and scores
                else {"available": False, "reason": "insufficient_binary_labels_or_scores"}
            )

            ordered_scores = sorted(score_values)
            score_mean = _mean(ordered_scores) if ordered_scores else None
            score_median = _quantile_sorted(ordered_scores, 0.5) if ordered_scores else None

            slices.append(
                SliceResult(
                    slice_id=slice_id,
                    feature=spec.feature,
                    method=spec.method.value,
                    bucket=bucket,
                    count=len(group_rows),
                    positive_count=positive_count,
                    negative_count=negative_count,
                    score_mean=score_mean,
                    score_median=score_median,
                    metrics=metrics,
                )
            )

        if len(slices) >= options.max_slices:
            break

    if not slices:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="no_slices_produced",
            message="No bounded slices could be produced from the evaluation rows.",
        )

    return tuple(slices)


def _core_metrics(
    rows: Sequence[Mapping[str, Any]],
    threshold: float,
    request: Any,
    options: EvalOptions,
) -> dict[str, Any]:
    """
    Compute bounded core metrics and flat aliases for one row set.
    """
    positive_codes = set(
        getattr(request, "positive_label_codes", None) or _DEFAULT_POSITIVE_LABEL_CODES
    )
    negative_codes = set(
        getattr(request, "negative_label_codes", None) or _DEFAULT_NEGATIVE_LABEL_CODES
    )
    ignore_codes = set(
        getattr(request, "ignore_label_codes", None) or _DEFAULT_IGNORE_LABEL_CODES
    )

    binary_y: list[int] = []
    binary_scores: list[float] = []
    multiclass_y: list[int] = []
    multiclass_pred: list[int] = []
    all_scores: list[float] = []

    labelled = 0
    scored = 0
    predicted = 0

    for row in rows:
        label_code = _coerce_int_label(row.get("label_code"))
        score = _coerce_optional_float(row.get("score"), allow_bool=True)
        predicted_label = _coerce_int_label(row.get("predicted_label"))

        if label_code is not None:
            labelled += 1

        if score is not None:
            scored += 1
            all_scores.append(_clip_float(score, 0.0, 1.0, 0.0))

        if predicted_label is not None:
            predicted += 1

        binary_label = _binary_label(label_code, positive_codes, negative_codes, ignore_codes)

        if binary_label is not None and score is not None:
            binary_y.append(binary_label)
            binary_scores.append(_clip_float(score, 0.0, 1.0, 0.0))

        if (
            label_code is not None
            and predicted_label is not None
            and int(label_code) not in ignore_codes
        ):
            multiclass_y.append(int(label_code))
            multiclass_pred.append(int(predicted_label))

    counts = {
        "rows": len(rows),
        "labelled": labelled,
        "scored": scored,
        "predicted": predicted,
        "binary_evaluable": len(binary_y),
        "multiclass_evaluable": len(multiclass_y),
    }

    out: dict[str, Any] = {
        "available": bool(rows),
        "counts": counts,
        "score_distribution": _score_distribution(all_scores),
    }

    if binary_y and binary_scores:
        binary = _binary_metrics_from_arrays(binary_y, binary_scores, threshold, options)
        out["binary"] = binary

        for key in (
            "roc_auc",
            "pr_auc",
            "f1",
            "precision",
            "recall",
            "fpr",
            "fnr",
            "tnr",
            "balanced_accuracy",
            "you_j",
            "log_loss",
            "brier_score",
            "expected_calibration_error",
        ):
            out[key] = binary.get(key)
    else:
        out["binary"] = {"available": False, "reason": "insufficient_binary_labels_or_scores"}

    if multiclass_y and multiclass_pred:
        classes = sorted(set(multiclass_y))
        multiclass = _multiclass_metrics(multiclass_y, multiclass_pred, classes)
        out["multiclass"] = multiclass
        out["accuracy"] = multiclass.get("accuracy")
        out["macro_f1"] = multiclass.get("macro_f1")
        out["weighted_f1"] = multiclass.get("weighted_f1")
    else:
        out["multiclass"] = {"available": False, "reason": "insufficient_predicted_labels"}

    return out


def _stability_analysis(
    all_rows: Sequence[Mapping[str, Any]],
    reporting_rows: Sequence[Mapping[str, Any]],
    request: EvaluationJobRequest,
    options: EvalOptions,
    issues: list[EvaluationIssue],
    threshold: float,
    slices: Sequence[SliceResult],
) -> dict[str, Any]:
    """
    Produce bounded stability and uncertainty diagnostics.

    Stability summaries are investigative diagnostics only. They are not proof
    of model correctness or regulatory compliance.
    """
    out: dict[str, Any] = {
        "available": bool(all_rows),
        "counts_by_split": {},
        "metrics_by_split": {},
        "score_distribution_by_split": {},
        "deltas": {},
        "bootstrap": {},
        "slice_summary": {},
    }

    if not all_rows:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="stability_unavailable",
            message="Stability analysis is unavailable because no evaluation rows are present.",
        )
        return out

    for split in (EvaluationSplit.TRAIN, EvaluationSplit.VALIDATION, EvaluationSplit.TEST):
        split_rows = _filter_rows_by_split(all_rows, split)
        out["counts_by_split"][split.value] = len(split_rows)

        if not split_rows:
            continue

        core = _core_metrics(split_rows, threshold, request, options)
        selected_metrics: dict[str, Any] = {}

        for metric in _METRIC_KEYS:
            value = _metric_from_core(core, metric)

            if value is not None:
                selected_metrics[metric] = _round6(value)

        out["metrics_by_split"][split.value] = selected_metrics
        out["score_distribution_by_split"][split.value] = core.get("score_distribution", {})

    validation_metrics = out["metrics_by_split"].get(EvaluationSplit.VALIDATION.value, {})
    test_metrics = out["metrics_by_split"].get(EvaluationSplit.TEST.value, {})

    for metric in _METRIC_KEYS:
        validation_value = _coerce_optional_float(validation_metrics.get(metric), allow_bool=False)
        test_value = _coerce_optional_float(test_metrics.get(metric), allow_bool=False)

        if validation_value is not None and test_value is not None:
            out["deltas"][metric] = {
                "validation": _round6(validation_value),
                "test": _round6(test_value),
                "test_minus_validation": _round6(test_value - validation_value),
            }

    if options.max_bootstrap_iterations > 0 and reporting_rows:
        for metric in _BINARY_BOOTSTRAP_METRICS:
            interval = _single_bootstrap_interval(
                reporting_rows,
                metric,
                threshold,
                request,
                options,
            )

            if interval.available or interval.point_estimate is not None:
                out["bootstrap"][metric] = interval.to_dict()

    if slices:
        f1_values: list[float] = []
        score_means: list[float] = []

        for slice_result in slices:
            if slice_result.score_mean is not None:
                score_means.append(float(slice_result.score_mean))

            metrics = slice_result.metrics

            if isinstance(metrics, Mapping) and metrics.get("available"):
                f1 = _coerce_optional_float(metrics.get("f1"), allow_bool=False)

                if f1 is not None:
                    f1_values.append(float(f1))

        out["slice_summary"] = {
            "slice_count": len(slices),
            "total_slice_rows": sum(int(slice_result.count) for slice_result in slices),
            "score_mean_min": _round6(min(score_means)) if score_means else None,
            "score_mean_max": _round6(max(score_means)) if score_means else None,
            "f1_min": _round6(min(f1_values)) if f1_values else None,
            "f1_max": _round6(max(f1_values)) if f1_values else None,
            "f1_range": _round6(max(f1_values) - min(f1_values)) if len(f1_values) > 1 else None,
        }

    return _safe_detail_value(out) or {}


# -----------------------------------------------------------------------------
# Evaluation artifacts and phase helpers
# -----------------------------------------------------------------------------


def _phase_record(
    phase: EvaluationPhase | str,
    started_mono: float,
    started_dt: datetime,
    ok: bool,
    issue_base: int,
    issues: Sequence[EvaluationIssue],
    details: Optional[Mapping[str, Any]] = None,
) -> EvaluationPhaseRecord:
    """
    Build one bounded evaluation phase record.
    """
    finished_dt = _now_utc()
    duration_ms = int((time.monotonic() - started_mono) * 1000.0)

    return EvaluationPhaseRecord(
        phase=phase,
        started_at=started_dt,
        finished_at=finished_dt,
        duration_ms=max(0, duration_ms),
        ok=bool(ok),
        issue_count=max(0, len(issues) - issue_base),
        details=details or {},
    )


def _safe_summary_from_object(obj: Any) -> dict[str, Any]:
    """
    Return safe summary from an object exposing common summary methods.
    """
    if obj is None:
        return {}

    for name in ("to_public_dict", "safe_summary", "summary", "to_dict"):
        method = getattr(obj, name, None)

        if callable(method):
            try:
                payload = method()
            except Exception:
                continue

            if isinstance(payload, Mapping):
                sanitized = _safe_detail_value(payload)
                return sanitized if isinstance(sanitized, dict) else {}

    return {}


def _build_evaluation_artifacts(
    job_id: str,
    status: EvaluationStatus,
    metrics: Mapping[str, Any],
    threshold_curve: Sequence[ThresholdPoint],
    selected_threshold: Optional[ThresholdPoint],
    slices: Sequence[SliceResult],
    stability: Mapping[str, Any],
    label_index: _LabelIndex,
    options: EvalOptions,
) -> tuple[EvaluationArtifact, ...]:
    """
    Build bounded safe evaluation artifact summaries.

    Artifacts are summaries only. This module does not write files or persist
    durable evaluation artefacts.
    """
    artifacts: list[EvaluationArtifact] = []
    seen: set[tuple[str, str]] = set()
    status_text = status.value

    def add(
        kind: str,
        artifact_id: Optional[str],
        fingerprint: str,
        summary: Mapping[str, Any],
    ) -> None:
        if len(artifacts) >= options.max_artifacts:
            return

        resolved_id = _clean_text(artifact_id, 128) or _clean_text(fingerprint, 128) or kind
        key = (_normalize_token(kind), resolved_id)

        if key in seen:
            return

        seen.add(key)
        artifacts.append(
            EvaluationArtifact(
                kind=kind,
                artifact_id=artifact_id,
                fingerprint=fingerprint,
                status=status_text,
                summary=summary,
            )
        )

    safe_metrics = _safe_detail_value(metrics) or {}

    add(
        "evaluation_report",
        job_id,
        _fingerprint_payload(safe_metrics),
        {
            "counts": safe_metrics.get("counts", {}),
            "binary_available": bool((safe_metrics.get("binary") or {}).get("available")),
            "multiclass_available": bool((safe_metrics.get("multiclass") or {}).get("available")),
            "score_distribution": safe_metrics.get("score_distribution", {}),
        },
    )

    if threshold_curve:
        add(
            "threshold_curve",
            job_id,
            _fingerprint_payload([point.to_dict() for point in threshold_curve]),
            {
                "point_count": len(threshold_curve),
                "selected_threshold": (
                    selected_threshold.to_dict()
                    if selected_threshold is not None
                    else None
                ),
            },
        )

    if slices:
        add(
            "slice_analysis",
            job_id,
            _fingerprint_payload([slice_result.to_dict() for slice_result in slices[: options.max_summary_items]]),
            {
                "slice_count": len(slices),
                "top_slices": [
                    slice_result.to_dict()
                    for slice_result in slices[: options.max_summary_items]
                ],
                "truncated": len(slices) > options.max_summary_items,
            },
        )

    if stability:
        add(
            "stability_analysis",
            job_id,
            _fingerprint_payload(stability),
            {"summary": stability},
        )

    label_summary = _label_summary(label_index)

    if label_summary.get("available"):
        add(
            "label_summary",
            job_id,
            _fingerprint_payload(label_summary),
            {"summary": label_summary},
        )

    return tuple(artifacts)


def _status_from_issues(
    issues: Sequence[EvaluationIssue],
    default: EvaluationStatus = EvaluationStatus.SUCCEEDED,
) -> EvaluationStatus:
    """
    Derive evaluation status from issue severities.
    """
    if _has_error(issues):
        return EvaluationStatus.FAILED

    if any(issue.severity == IssueSeverity.WARNING for issue in issues):
        return EvaluationStatus.DEGRADED

    return default


# -----------------------------------------------------------------------------
# Request coercion
# -----------------------------------------------------------------------------


def _coerce_request(request: Any) -> EvaluationJobRequest:
    """
    Coerce flexible evaluation input into one bounded request.
    """
    if isinstance(request, EvaluationJobRequest):
        return request

    if isinstance(request, Mapping):
        if any(key in request for key in _REQUEST_KEYS):
            try:
                return EvaluationJobRequest(**request)
            except Exception:
                pass

        return EvaluationJobRequest(features=request)

    if (
        hasattr(request, "parameters")
        or hasattr(request, "score")
        or hasattr(request, "infer")
        or hasattr(request, "predict_supervised_model")
    ):
        return EvaluationJobRequest(model=request)

    return EvaluationJobRequest(features=request)


def _coerce_comparison_request(request: Any) -> EvaluationComparisonRequest:
    """
    Coerce flexible comparison input into one bounded comparison request.
    """
    if isinstance(request, EvaluationComparisonRequest):
        return request

    if isinstance(request, Mapping):
        if any(key in request for key in _COMPARISON_REQUEST_KEYS):
            try:
                return EvaluationComparisonRequest(**request)
            except Exception:
                pass

        return EvaluationComparisonRequest(features=request)

    if (
        hasattr(request, "parameters")
        or hasattr(request, "score")
        or hasattr(request, "infer")
    ):
        return EvaluationComparisonRequest(candidates=[EvaluationCandidate(name="candidate", model=request)])

    return EvaluationComparisonRequest(features=request)


def _candidate_request(
    candidate: EvaluationCandidate,
    records: Sequence[Mapping[str, Any]],
    comparison_request: EvaluationComparisonRequest,
    split: EvaluationSplit,
    options: EvalOptions,
) -> EvaluationJobRequest:
    """
    Build one bounded internal request for one comparison candidate.
    """
    threshold = candidate.threshold if candidate.threshold is not None else options.threshold

    return EvaluationJobRequest(
        features=list(records),
        labels=comparison_request.labels,
        predictions=candidate.predictions,
        model=candidate.model,
        model_id=candidate.model_id,
        target=candidate.target,
        split=split,
        threshold=threshold,
        positive_label_codes=comparison_request.positive_label_codes,
        negative_label_codes=comparison_request.negative_label_codes,
        ignore_label_codes=comparison_request.ignore_label_codes,
        include_contributions=False,
        include_slices=False,
        include_stability=False,
        include_threshold_sweep=False,
        metadata=candidate.metadata,
    )


# -----------------------------------------------------------------------------
# Evaluation harness
# -----------------------------------------------------------------------------


class EvaluationHarness:
    """
    Bounded deterministic synthetic ML evaluation harness.

    This harness resolves predictions from supplied external predictions, model
    service objects, supervised models, anomaly models, or fallback scoring;
    computes honest metrics; performs bounded threshold selection, slice
    analysis, and stability diagnostics; and registers process-local evaluation
    jobs.

    It does not train models, deploy models, persist durable artefacts, call
    external systems, or take adverse action.
    """

    def __init__(self, options: EvalOptions | None = None) -> None:
        self.options = options or EvalOptions.from_settings()
        self._lock = threading.RLock()

    def run(self, request: Any) -> EvaluationJobResult:
        """
        Run one bounded synthetic evaluation job.
        """
        opts = self.options
        issues: list[EvaluationIssue] = []
        phases: list[EvaluationPhaseRecord] = []

        started_at = _now_utc()
        started_mono = time.monotonic()

        req = _coerce_request(request)

        target = _normalize_enum_option(
            EvaluationTarget,
            req.target or opts.target,
            EvaluationTarget.AUTO,
        )
        split = _normalize_enum_option(
            EvaluationSplit,
            req.split or opts.split,
            EvaluationSplit.TEST,
        )
        selection_split = _normalize_enum_option(
            EvaluationSplit,
            req.selection_split or opts.selection_split,
            EvaluationSplit.VALIDATION,
        )
        policy = _normalize_enum_option(
            ThresholdPolicy,
            req.threshold_policy or opts.threshold_policy,
            ThresholdPolicy.FIXED,
        )
        threshold = req.threshold if req.threshold is not None else opts.threshold
        threshold = _clamp_float(threshold, 0.0, 1.0, opts.threshold)

        rows_all: list[dict[str, Any]] = []
        rows: list[dict[str, Any]] = []
        predictions: tuple[PredictionSnapshot, ...] = ()
        label_index = _LabelIndex()
        input_fp = ""
        job_id = ""
        metrics: dict[str, Any] = {}
        threshold_curve: tuple[ThresholdPoint, ...] = ()
        selected_threshold: Optional[ThresholdPoint] = None
        threshold_selection_source = "none"
        slices: tuple[SliceResult, ...] = ()
        stability: dict[str, Any] = {}
        artifacts: tuple[EvaluationArtifact, ...] = ()
        submitted = 0
        cleaned: list[dict[str, Any]] = []

        def make_result(
            status: EvaluationStatus,
        ) -> EvaluationJobResult:
            """
            Build one safe evaluation job result from current harness state.
            """
            resolved_job_id = job_id or _sha256_hex(
                _canonical_json(
                    {
                        "version": EVALUATION_VERSION,
                        "target": target.value,
                        "split": split.value,
                        "input_fingerprint": input_fp,
                        "metadata": _safe_detail_value(req.metadata),
                        "tags": list(req.tags),
                        "issue_count": len(issues),
                    }
                )
            )[:32]

            safe_metrics = _safe_detail_value(metrics) or {}
            counts = dict(safe_metrics.get("counts") or {})
            counts.update(
                {
                    "submitted": submitted,
                    "processed": len(rows_all),
                    "evaluated": len(rows),
                    "slices": len(slices),
                    "artifacts": len(artifacts),
                    "issues": len(issues),
                }
            )

            metadata = {
                "evaluation_version": EVALUATION_VERSION,
                "target": target.value,
                "split": split.value,
                "selection_split": selection_split.value,
                "threshold_policy": policy.value,
                "threshold": _round6(threshold),
                "input_fingerprint": input_fp,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "label_summary": _label_summary(label_index),
                "threshold_selection_source": threshold_selection_source,
                "registry_backend": "process_local_in_memory",
                "registry_durable": False,
                "registry_distributed": False,
                "caveats": list(_EVALUATION_CAVEATS),
                "safety_flags": dict(_EVALUATION_SAFETY_FLAGS),
            }

            return EvaluationJobResult(
                job_id=resolved_job_id,
                status=status,
                target=target,
                split=split,
                threshold=threshold,
                created_at=started_at,
                finished_at=_now_utc(),
                duration_ms=int((time.monotonic() - started_mono) * 1000.0),
                counts=counts,
                metrics=safe_metrics,
                binary_metrics=safe_metrics.get("binary", {}),
                multiclass_metrics=safe_metrics.get("multiclass", {}),
                calibration=safe_metrics.get("calibration", {}),
                score_distribution=safe_metrics.get("score_distribution", {}),
                threshold_curve=threshold_curve,
                selected_threshold=selected_threshold,
                threshold_selection_source=threshold_selection_source,
                slices=slices,
                stability=stability,
                artifacts=artifacts,
                phases=tuple(phases[: opts.max_phases]),
                issues=tuple(issues),
                metadata=metadata,
                fingerprint="",
            )

        def register_and_finalize(result: EvaluationJobResult) -> EvaluationJobResult:
            """
            Register the final job in the process-local registry and append
            final lifecycle phases.
            """
            phase_mono = time.monotonic()
            phase_dt = _now_utc()
            issue_base = len(issues)

            registered = bool(opts.register_jobs)

            if opts.register_jobs:
                register_details = {
                    "registered": True,
                    "registry_backend": "process_local_in_memory",
                    "registry_durable": False,
                    "registry_distributed": False,
                }
            else:
                register_details = {
                    "registered": False,
                    "reason": "registration_disabled",
                }

            final_phases = list(phases)
            final_phases.append(
                EvaluationPhaseRecord(
                    phase=EvaluationPhase.REGISTER_JOB,
                    started_at=phase_dt,
                    finished_at=_now_utc(),
                    duration_ms=int((time.monotonic() - phase_mono) * 1000.0),
                    ok=True,
                    issue_count=0,
                    details=register_details,
                )
            )

            finalize_mono = time.monotonic()
            finalize_dt = _now_utc()
            final_ok = result.status in {
                EvaluationStatus.SUCCEEDED,
                EvaluationStatus.DEGRADED,
            } and not _has_error(issues)

            final_phases.append(
                EvaluationPhaseRecord(
                    phase=EvaluationPhase.FINALIZE,
                    started_at=finalize_dt,
                    finished_at=_now_utc(),
                    duration_ms=int((time.monotonic() - finalize_mono) * 1000.0),
                    ok=final_ok,
                    issue_count=0,
                    details={"final_status": result.status.value},
                )
            )

            final_metadata = dict(result.metadata)
            final_metadata.update(
                {
                    "registered": registered,
                    "registry_backend": "process_local_in_memory",
                    "registry_durable": False,
                    "registry_distributed": False,
                }
            )

            candidate_result = replace(
                result,
                phases=tuple(final_phases[: opts.max_phases]),
                finished_at=_now_utc(),
                duration_ms=int((time.monotonic() - started_mono) * 1000.0),
                metadata=final_metadata,
                fingerprint="",
            )

            if not opts.register_jobs:
                return candidate_result

            try:
                get_eval_registry(opts.max_jobs).register(candidate_result)
                return candidate_result
            except Exception as exc:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="evaluation_job_registration_failed",
                    message="Evaluation job registration failed.",
                    details={"exception_type": type(exc).__name__},
                )

                failure_phases = list(phases)
                failure_phases.append(
                    EvaluationPhaseRecord(
                        phase=EvaluationPhase.REGISTER_JOB,
                        started_at=phase_dt,
                        finished_at=_now_utc(),
                        duration_ms=int((time.monotonic() - phase_mono) * 1000.0),
                        ok=False,
                        issue_count=max(0, len(issues) - issue_base),
                        details={
                            "registered": False,
                            "exception_type": type(exc).__name__,
                        },
                    )
                )

                failure_finalize_mono = time.monotonic()
                failure_finalize_dt = _now_utc()

                failure_phases.append(
                    EvaluationPhaseRecord(
                        phase=EvaluationPhase.FINALIZE,
                        started_at=failure_finalize_dt,
                        finished_at=_now_utc(),
                        duration_ms=int((time.monotonic() - failure_finalize_mono) * 1000.0),
                        ok=False,
                        issue_count=0,
                        details={"final_status": EvaluationStatus.FAILED.value},
                    )
                )

                failure_metadata = dict(result.metadata)
                failure_metadata.update(
                    {
                        "registered": False,
                        "registry_backend": "process_local_in_memory",
                        "registry_durable": False,
                        "registry_distributed": False,
                    }
                )

                return replace(
                    result,
                    status=EvaluationStatus.FAILED,
                    phases=tuple(failure_phases[: opts.max_phases]),
                    issues=tuple(issues),
                    finished_at=_now_utc(),
                    duration_ms=int((time.monotonic() - started_mono) * 1000.0),
                    metadata=failure_metadata,
                    fingerprint="",
                )

        # ------------------------------------------------------------------
        # Phase: validate inputs
        # ------------------------------------------------------------------

        phase_mono = time.monotonic()
        phase_dt = _now_utc()
        issue_base = len(issues)

        policy_status = EvaluationStatus.SUCCEEDED

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="evaluation_disabled",
                message="Evaluation harness is disabled.",
            )
            policy_status = EvaluationStatus.BLOCKED

        elif opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Evaluation harness requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            policy_status = EvaluationStatus.BLOCKED

        elif opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Evaluation harness is blocked in production-like environments.",
            )
            policy_status = EvaluationStatus.BLOCKED

        else:
            if not _scan_labels(req.labels, opts, issues):
                policy_status = EvaluationStatus.FAILED

            raw_records = _iter_records(req.features)
            submitted = len(raw_records)

            if submitted > opts.max_records:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="evaluation_input_truncated",
                    message="Evaluation input exceeded configured record limit and was truncated.",
                    details={
                        "submitted": submitted,
                        "max_records": opts.max_records,
                    },
                )
                raw_records = raw_records[: opts.max_records]

            cleaned = _clean_records(raw_records, opts, issues)
            label_index = _build_label_index(req.labels, len(cleaned), opts)
            input_fp = _input_fingerprint(cleaned, label_index)

            if req.job_id:
                job_id = req.job_id
            elif req.idempotency_key:
                job_id = _sha256_hex(
                    f"{opts.namespace}|{req.idempotency_key}|{input_fp}"
                )[:32]
            else:
                job_id = _derive_job_id(req, opts, target, split, input_fp)

        validation_ok = policy_status == EvaluationStatus.SUCCEEDED and not _has_error(issues)

        phases.append(
            _phase_record(
                phase=EvaluationPhase.VALIDATE_INPUTS,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=validation_ok,
                issue_base=issue_base,
                issues=issues,
                details={
                    "policy_status": policy_status.value,
                    "record_count": len(cleaned),
                    "feature_count": len(_records_feature_names(cleaned)),
                    "label_summary": _label_summary(label_index),
                    "input_fingerprint": input_fp,
                    "job_id": job_id,
                    "target": target.value,
                    "split": split.value,
                },
            )
        )

        if policy_status != EvaluationStatus.SUCCEEDED or _has_error(issues):
            return register_and_finalize(
                make_result(
                    policy_status
                    if policy_status != EvaluationStatus.SUCCEEDED
                    else EvaluationStatus.FAILED
                )
            )

        # ------------------------------------------------------------------
        # Phase: resolve predictions
        # ------------------------------------------------------------------

        phase_mono = time.monotonic()
        phase_dt = _now_utc()
        issue_base = len(issues)

        predictions = _resolve_predictions(req, cleaned, opts, issues)

        if not predictions:
            phases.append(
                _phase_record(
                    phase=EvaluationPhase.RESOLVE_PREDICTIONS,
                    started_mono=phase_mono,
                    started_dt=phase_dt,
                    ok=False,
                    issue_base=issue_base,
                    issues=issues,
                    details={"prediction_count": 0},
                )
            )
            return register_and_finalize(make_result(EvaluationStatus.FAILED))

        rows_all = _build_eval_rows(cleaned, predictions, label_index, opts, issues)

        if not rows_all:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_evaluation_rows",
                message="No evaluation rows could be constructed from predictions and labels.",
            )
            phases.append(
                _phase_record(
                    phase=EvaluationPhase.RESOLVE_PREDICTIONS,
                    started_mono=phase_mono,
                    started_dt=phase_dt,
                    ok=False,
                    issue_base=issue_base,
                    issues=issues,
                    details={"prediction_count": len(predictions), "row_count": 0},
                )
            )
            return register_and_finalize(make_result(EvaluationStatus.FAILED))

        rows = _filter_rows_by_split(rows_all, split)

        if not rows:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="evaluation_split_unavailable",
                message="Requested evaluation split is unavailable; using all available rows.",
                details={
                    "requested_split": split.value,
                    "available_rows": len(rows_all),
                },
            )
            rows = rows_all

        phases.append(
            _phase_record(
                phase=EvaluationPhase.RESOLVE_PREDICTIONS,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=True,
                issue_base=issue_base,
                issues=issues,
                details={
                    "prediction_count": len(predictions),
                    "row_count": len(rows_all),
                    "evaluated_row_count": len(rows),
                    "requested_split": split.value,
                },
            )
        )

        # ------------------------------------------------------------------
        # Phase: compute metrics
        # ------------------------------------------------------------------

        phase_mono = time.monotonic()
        phase_dt = _now_utc()
        issue_base = len(issues)

        metrics = _compute_metrics(rows, threshold, req, opts)

        phases.append(
            _phase_record(
                phase=EvaluationPhase.COMPUTE_METRICS,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=True,
                issue_base=issue_base,
                issues=issues,
                details={
                    "counts": metrics.get("counts", {}),
                    "binary_available": bool((metrics.get("binary") or {}).get("available")),
                    "multiclass_available": bool((metrics.get("multiclass") or {}).get("available")),
                },
            )
        )

        # ------------------------------------------------------------------
        # Phase: threshold selection
        # ------------------------------------------------------------------

        phase_mono = time.monotonic()
        phase_dt = _now_utc()
        issue_base = len(issues)

        include_sweep = (
            req.include_threshold_sweep
            if req.include_threshold_sweep is not None
            else opts.include_threshold_sweep
        )

        if policy != ThresholdPolicy.FIXED or include_sweep:
            selection_rows = _filter_rows_by_split(rows_all, selection_split)
            selection_source = selection_split.value

            if not selection_rows and split != selection_split:
                selection_rows = rows
                selection_source = f"{selection_split.value}_fallback_{split.value}"

                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="threshold_selection_split_unavailable",
                    message="Configured threshold selection split is unavailable; using reporting split for threshold sweep.",
                    details={
                        "selection_split": selection_split.value,
                        "reporting_split": split.value,
                    },
                )
            elif not selection_rows:
                selection_rows = rows
                selection_source = split.value if rows else "none"

            if selection_rows:
                points, selected, policy_source = _threshold_sweep(selection_rows, req, opts)
                threshold_curve = points

                if policy != ThresholdPolicy.FIXED and selected is not None:
                    threshold = selected.threshold
                    selected_threshold = selected
                    threshold_selection_source = f"{selection_source}:{policy_source}"
                    metrics = _compute_metrics(rows, threshold, req, opts)
                else:
                    threshold_selection_source = (
                        "fixed"
                        if policy == ThresholdPolicy.FIXED
                        else "unavailable"
                    )
            else:
                threshold_selection_source = "unavailable"
        else:
            threshold_selection_source = "fixed"

        phases.append(
            _phase_record(
                phase=EvaluationPhase.THRESHOLD_SELECTION,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=True,
                issue_base=issue_base,
                issues=issues,
                details={
                    "policy": policy.value,
                    "threshold": _round6(threshold),
                    "curve_points": len(threshold_curve),
                    "selection_source": threshold_selection_source,
                },
            )
        )

        # ------------------------------------------------------------------
        # Phase: slice analysis
        # ------------------------------------------------------------------

        phase_mono = time.monotonic()
        phase_dt = _now_utc()
        issue_base = len(issues)

        include_slices = (
            req.include_slices
            if req.include_slices is not None
            else opts.include_slices
        )

        if include_slices and opts.max_slices > 0:
            slices = _analyze_slices(rows, req, opts, issues, threshold)

        phases.append(
            _phase_record(
                phase=EvaluationPhase.SLICE_ANALYSIS,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=True,
                issue_base=issue_base,
                issues=issues,
                details={
                    "included": bool(include_slices and opts.max_slices > 0),
                    "slice_count": len(slices),
                },
            )
        )

        # ------------------------------------------------------------------
        # Phase: stability analysis
        # ------------------------------------------------------------------

        phase_mono = time.monotonic()
        phase_dt = _now_utc()
        issue_base = len(issues)

        include_stability = (
            req.include_stability
            if req.include_stability is not None
            else opts.include_stability
        )

        if include_stability:
            stability = _stability_analysis(
                rows_all,
                rows,
                req,
                opts,
                issues,
                threshold,
                slices,
            )

        phases.append(
            _phase_record(
                phase=EvaluationPhase.STABILITY_ANALYSIS,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=True,
                issue_base=issue_base,
                issues=issues,
                details={
                    "included": bool(include_stability),
                    "bootstrap_iterations": opts.max_bootstrap_iterations,
                    "slice_count": len(slices),
                },
            )
        )

        artifacts = _build_evaluation_artifacts(
            job_id=job_id,
            status=_status_from_issues(issues),
            metrics=metrics,
            threshold_curve=threshold_curve,
            selected_threshold=selected_threshold,
            slices=slices,
            stability=stability,
            label_index=label_index,
            options=opts,
        )

        status = _status_from_issues(issues)

        return register_and_finalize(make_result(status))

    def compare(self, request: Any) -> EvaluationComparisonResult:
        """
        Run one bounded paired synthetic model comparison.

        Comparison outputs are investigative evaluation artefacts only. They are
        not adjudications and must not trigger automatic adverse customer action.
        """
        opts = self.options
        issues: list[EvaluationIssue] = []

        started_at = _now_utc()
        started_mono = time.monotonic()

        req = _coerce_comparison_request(request)

        split = _normalize_enum_option(
            EvaluationSplit,
            req.split or opts.split,
            EvaluationSplit.TEST,
        )
        primary_metric = _normalize_token(req.primary_metric) or "roc_auc"

        status = EvaluationStatus.SUCCEEDED
        job_id = ""
        input_fp = ""
        submitted = 0
        cleaned: list[dict[str, Any]] = []
        label_index = _LabelIndex()
        candidate_evals: list[CandidateEvaluation] = []
        candidate_rows: list[list[dict[str, Any]]] = []
        pairwise: list[PairwiseComparison] = []

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="evaluation_disabled",
                message="Evaluation harness is disabled.",
            )
            status = EvaluationStatus.BLOCKED

        elif opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Evaluation harness requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            status = EvaluationStatus.BLOCKED

        elif opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Evaluation harness is blocked in production-like environments.",
            )
            status = EvaluationStatus.BLOCKED

        else:
            candidates = tuple(req.candidates[: opts.max_candidates])

            if not candidates:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="no_comparison_candidates",
                    message="Comparison request contains no candidates.",
                )
                status = EvaluationStatus.FAILED
            else:
                if not _scan_labels(req.labels, opts, issues):
                    status = EvaluationStatus.FAILED

                raw_records = _iter_records(req.features)
                submitted = len(raw_records)

                if submitted > opts.max_records:
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="comparison_input_truncated",
                        message="Comparison input exceeded configured record limit and was truncated.",
                        details={
                            "submitted": submitted,
                            "max_records": opts.max_records,
                        },
                    )
                    raw_records = raw_records[: opts.max_records]

                cleaned = _clean_records(raw_records, opts, issues)
                label_index = _build_label_index(req.labels, len(cleaned), opts)
                input_fp = _input_fingerprint(cleaned, label_index)

                if req.job_id:
                    job_id = req.job_id
                elif req.idempotency_key:
                    job_id = _sha256_hex(
                        f"{opts.namespace}|{req.idempotency_key}|{input_fp}"
                    )[:32]
                else:
                    job_id = _sha256_hex(
                        _canonical_json(
                            {
                                "version": EVALUATION_VERSION,
                                "kind": "comparison",
                                "split": split.value,
                                "primary_metric": primary_metric,
                                "input_fingerprint": input_fp,
                                "metadata": _safe_detail_value(req.metadata),
                                "tags": list(req.tags),
                            }
                        )
                    )[:32]

                for candidate in candidates:
                    cand_req = _candidate_request(candidate, cleaned, req, split, opts)
                    preds = _resolve_predictions(cand_req, cleaned, opts, issues)
                    rows_all = _build_eval_rows(cleaned, preds, label_index, opts, issues)
                    rows = _filter_rows_by_split(rows_all, split)

                    if not rows and rows_all:
                        _append_issue(
                            issues,
                            opts.max_issues,
                            severity=IssueSeverity.WARNING,
                            code="comparison_split_unavailable",
                            message="Requested comparison split is unavailable for one candidate; using all available rows.",
                            details={
                                "candidate": candidate.name,
                                "requested_split": split.value,
                            },
                        )
                        rows = rows_all

                    core = _core_metrics(
                        rows,
                        cand_req.threshold if cand_req.threshold is not None else opts.threshold,
                        cand_req,
                        opts,
                    )

                    candidate_evals.append(
                        CandidateEvaluation(
                            name=candidate.name,
                            target=_target_value(cand_req.target),
                            threshold=cand_req.threshold if cand_req.threshold is not None else opts.threshold,
                            counts=core.get("counts", {}),
                            metrics=core,
                        )
                    )
                    candidate_rows.append(rows)

                if len(candidate_evals) >= 2 and opts.max_pairwise > 0:
                    baseline = candidate_evals[0]
                    baseline_rows = candidate_rows[0]
                    baseline_threshold = baseline.threshold

                    pair_count = min(len(candidate_evals) - 1, opts.max_pairwise)

                    for index in range(1, pair_count + 1):
                        cand = candidate_evals[index]
                        cand_rows = candidate_rows[index]
                        cand_threshold = cand.threshold

                        baseline_value = _metric_from_core(baseline.metrics, primary_metric)
                        cand_value = _metric_from_core(cand.metrics, primary_metric)
                        delta = (
                            cand_value - baseline_value
                            if baseline_value is not None and cand_value is not None
                            else None
                        )

                        y, baseline_scores, cand_scores = _align_rows(
                            baseline_rows,
                            cand_rows,
                            req,
                        )

                        interval = _paired_bootstrap_interval(
                            y,
                            baseline_scores,
                            cand_scores,
                            primary_metric,
                            baseline_threshold,
                            cand_threshold,
                            opts,
                        )

                        verdict = _verdict_from_interval(interval, delta)

                        pairwise.append(
                            PairwiseComparison(
                                baseline=baseline.name,
                                candidate=cand.name,
                                metric=primary_metric,
                                baseline_value=baseline_value,
                                candidate_value=cand_value,
                                delta=delta,
                                interval=interval if interval.available or interval.point_estimate is not None else None,
                                verdict=verdict,
                            )
                        )

                status = _status_from_issues(issues)

        counts = {
            "submitted": submitted,
            "candidates": len(candidate_evals),
            "pairwise": len(pairwise),
            "issues": len(issues),
        }

        metadata = {
            "evaluation_version": EVALUATION_VERSION,
            "kind": "comparison",
            "split": split.value,
            "primary_metric": primary_metric,
            "input_fingerprint": input_fp,
            "idempotency_key": req.idempotency_key,
            "tags": list(req.tags),
            "request_metadata": _safe_detail_value(req.metadata),
            "label_summary": _label_summary(label_index),
            "registry_backend": "process_local_in_memory",
            "registry_durable": False,
            "registry_distributed": False,
            "caveats": list(_EVALUATION_CAVEATS),
            "safety_flags": dict(_EVALUATION_SAFETY_FLAGS),
        }

        return EvaluationComparisonResult(
            ok=status not in {EvaluationStatus.FAILED, EvaluationStatus.BLOCKED},
            status=status,
            job_id=job_id,
            split=split.value,
            primary_metric=primary_metric,
            candidates=tuple(candidate_evals),
            pairwise=tuple(pairwise),
            counts=counts,
            issues=tuple(issues),
            metadata=metadata,
            fingerprint="",
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe harness summary.
        """
        return {
            "options": self.options.safe_summary(),
            "submodules": {
                "model_service": _module_available(model_service_module, "ModelService"),
                "labels": _module_available(labels_module, "LabelSet"),
                "splits": _module_available(splits_module, "build_split_plan_from_label_set"),
                "preprocessing": _module_available(preprocessing_module, "Preprocessor"),
                "supervised": _module_available(supervised_module, "SupervisedTrainer"),
                "anomaly": _module_available(anomaly_module, "AnomalyModel"),
                "fallback": _module_available(fallback_module, "score_fallback_batch"),
            },
            "registry": get_eval_registry(self.options.max_jobs).safe_summary(
                limit=self.options.max_summary_items
            ),
            "caveats": list(_EVALUATION_CAVEATS),
            "safety_flags": dict(_EVALUATION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default harness and public API
# -----------------------------------------------------------------------------


_default_harness: Optional[EvaluationHarness] = None
_default_harness_lock = threading.Lock()


def get_eval_harness(
    options: EvalOptions | None = None,
    *,
    rebuild: bool = False,
) -> EvaluationHarness:
    """
    Return a process-wide evaluation harness.

    If options are supplied or rebuild is True, a new harness is created and
    becomes the default.
    """
    global _default_harness

    with _default_harness_lock:
        if _default_harness is None or rebuild or options is not None:
            _default_harness = EvaluationHarness(options=options or EvalOptions.from_settings())

        return _default_harness


def evaluate_job(
    request: Any,
    options: EvalOptions | None = None,
    *,
    harness: EvaluationHarness | None = None,
) -> EvaluationJobResult:
    """
    Run one bounded synthetic evaluation job.
    """
    active_harness = harness or get_eval_harness(options)
    return active_harness.run(request)


def evaluate_model(
    request: Any,
    options: EvalOptions | None = None,
    *,
    harness: EvaluationHarness | None = None,
) -> EvaluationJobResult:
    """
    Convenience alias for `evaluate_job`.
    """
    return evaluate_job(request, options=options, harness=harness)


def compare_models(
    request: Any,
    options: EvalOptions | None = None,
    *,
    harness: EvaluationHarness | None = None,
) -> EvaluationComparisonResult:
    """
    Run one bounded paired synthetic model comparison.
    """
    active_harness = harness or get_eval_harness(options)
    return active_harness.compare(request)


def get_evaluation_job(job_id: Any) -> Optional[EvaluationJobResult]:
    """
    Return one registered evaluation job result.
    """
    return get_eval_registry().get_result(job_id)


def list_evaluation_jobs(*, limit: int = 50) -> tuple[EvaluationJobResult, ...]:
    """
    Return registered evaluation job results.
    """
    return get_eval_registry().list_results(limit=limit)


def summarize_evaluation_jobs(*, limit: int = 50) -> list[dict[str, Any]]:
    """
    Return safe registered evaluation job summaries.
    """
    return get_eval_registry().summarize(limit=limit)


def get_eval_metadata() -> dict[str, Any]:
    """
    Return safe, serializable evaluation harness metadata.

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
    options = EvalOptions.from_settings()
    registry = get_eval_registry(options.max_jobs)

    return {
        "package": "muleguard.backend.ml.evaluate",
        "version": EVALUATION_VERSION,
        "targets": [target.value for target in EvaluationTarget],
        "splits": [split.value for split in EvaluationSplit],
        "statuses": [status.value for status in EvaluationStatus],
        "phases": [phase.value for phase in EvaluationPhase],
        "threshold_policies": [policy.value for policy in ThresholdPolicy],
        "slice_methods": [method.value for method in SliceMethod],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "submodule_availability": {
            "model_service": _module_available(model_service_module, "ModelService"),
            "labels": _module_available(labels_module, "LabelSet"),
            "splits": _module_available(splits_module, "build_split_plan_from_label_set"),
            "preprocessing": _module_available(preprocessing_module, "Preprocessor"),
            "supervised": _module_available(supervised_module, "SupervisedTrainer"),
            "anomaly": _module_available(anomaly_module, "AnomalyModel"),
            "fallback": _module_available(fallback_module, "score_fallback_batch"),
        },
        "registry": registry.safe_summary(limit=options.max_summary_items),
        "hard_limits": {
            "max_records": _HARD_MAX_RECORDS,
            "max_features": _HARD_MAX_FEATURES,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_slices": _HARD_MAX_SLICES,
            "max_slice_groups": _HARD_MAX_SLICE_GROUPS,
            "max_threshold_points": _HARD_MAX_THRESHOLD_POINTS,
            "max_bootstrap_iterations": _HARD_MAX_BOOTSTRAP_ITERATIONS,
            "max_candidates": _HARD_MAX_CANDIDATES,
            "max_pairwise": _HARD_MAX_PAIRWISE,
            "max_artifacts": _HARD_MAX_ARTIFACTS,
            "max_phases": _HARD_MAX_PHASES,
            "max_jobs": _HARD_MAX_JOBS,
        },
        "forbidden_eval_field_count": len(_FORBIDDEN_EVAL_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_EVALUATION_CAVEATS),
        "safety_flags": dict(_EVALUATION_SAFETY_FLAGS),
    }


__all__ = [
    "BootstrapInterval",
    "CandidateEvaluation",
    "EvaluationArtifact",
    "EvaluationComparisonRequest",
    "EvaluationComparisonResult",
    "EvaluationCandidate",
    "EvaluationHarness",
    "EvaluationIssue",
    "EvaluationJobRequest",
    "EvaluationJobResult",
    "EvaluationPhaseRecord",
    "EvaluationPhase",
    "EvaluationRegistry",
    "EvaluationSplit",
    "EvaluationStatus",
    "EvaluationTarget",
    "IssueSeverity",
    "PairwiseComparison",
    "PredictionSnapshot",
    "SliceMethod",
    "SliceResult",
    "SliceSpec",
    "ThresholdPoint",
    "ThresholdPolicy",
    "compare_models",
    "evaluate_job",
    "evaluate_model",
    "get_eval_harness",
    "get_eval_metadata",
    "get_eval_registry",
    "get_evaluation_job",
    "list_evaluation_jobs",
    "summarize_evaluation_jobs",
]