"""
MULEGUARD backend ML training harness.

This module provides the canonical bounded training orchestration layer for the
synthetic MULEGUARD machine-learning subsystem.

Primary responsibilities:

- run end-to-end synthetic ML training jobs through the MULEGUARD ML stack;
- validate and sanitize training requests before invoking downstream ML modules;
- coordinate label resolution, split planning, preprocessing, supervised
  training, anomaly fitting, governance checks, evaluation, and process-local
  catalog registration through `app.ml.model_service` when available;
- provide deterministic, bounded, reproducible training job results with safe
  summaries, phase records, artifact summaries, issue reporting, fingerprints,
  and product-safety caveats;
- maintain a bounded process-local training job registry for local prototype
  workflows, tests, developer tooling, and offline evaluation harnesses;
- reject leakage-prone inputs such as ground-truth labels, injected scenario
  IDs, fraud-ring IDs, raw complaint narratives, raw identifiers, secrets,
  tokens, passwords, database URLs, filesystem paths, and model artifact paths;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values, subject-label pairs, and sensitive metadata from
  public summaries;
- remain import-safe, dependency-light, and resilient when optional ML
  submodules are unavailable.

This module orchestrates training only. It does not persist data, call external
systems, authenticate users, authorize actions, deploy models to production
serving infrastructure, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for training, evaluation, or inference.
- Synthetic labels are evaluation fixtures only. They are not proof of
  wrongdoing.
- Labels must never be used as features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone feature inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden feature inputs. Subject linkage is pseudonymous
  and salted.
- Model probabilities, anomaly scores, and fallback scores are investigative
  prioritization signals only. They are not probabilities of guilt.
- Feature contributions are operational attributions only. They are not causal
  proof.
- Training outputs are investigative leads only.
- Training handling never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable capabilities are reported honestly rather than
  invented.
- The bundled training job registry and model catalog are process-local,
  non-durable, and bounded for local prototype use only.
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
correlations, anomaly scores, fallback scores, model predictions, and case
dispositions are investigative leads or human workflow artefacts only. They are
not proof of wrongdoing and must not trigger automatic adverse customer action.
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
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError

logger = logging.getLogger("muleguard.backend.ml.train_model")


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

TRAIN_MODEL_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.train_model.default.salt"
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

_DEFAULT_MAX_PHASES: Final[int] = 25
_HARD_MAX_PHASES: Final[int] = 200

_DEFAULT_MAX_ARTIFACTS: Final[int] = 20
_HARD_MAX_ARTIFACTS: Final[int] = 200

_DEFAULT_MAX_JOBS: Final[int] = 1_000
_HARD_MAX_JOBS: Final[int] = 10_000

_DEFAULT_REVIEW_THRESHOLD: Final[float] = 0.60

_DEFAULT_MIN_TRAIN_SAMPLES: Final[int] = 20
_DEFAULT_MIN_VALIDATION_SAMPLES: Final[int] = 5
_DEFAULT_MIN_TEST_SAMPLES: Final[int] = 5
_DEFAULT_MIN_CLASS_SUPPORT: Final[int] = 3
_DEFAULT_MAX_CLASS_IMBALANCE: Final[float] = 100.0

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

_FORBIDDEN_TRAIN_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_TRAIN_TOKENS: Final[tuple[str, ...]] = (
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

_TRAIN_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML training orchestration only. Do not use with real customer data.",
    "Training outputs are investigative prioritization artefacts only and are not proof of wrongdoing.",
    "Model, anomaly, and fallback scores are not probabilities of guilt.",
    "Feature contributions are operational attributions only and are not causal proof.",
    "Training must not trigger automatic adverse customer action.",
    "Labels must never be used as features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected as features.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Unavailable capabilities are reported honestly rather than invented.",
    "The bundled training job registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_TRAIN_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_training_jobs": True,
        "bounded_training_required": True,
        "scores_are_investigative_priority_only": True,
        "contributions_are_not_causal_proof": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class TrainingMode(str, Enum):
    """
    Training job mode.
    """

    AUTO = "auto"
    SUPERVISED = "supervised"
    ANOMALY = "anomaly"
    FALLBACK = "fallback"
    HYBRID = "hybrid"


class JobStatus(str, Enum):
    """
    Training job status.
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class TrainingPhase(str, Enum):
    """
    Training job phase.
    """

    VALIDATE_INPUTS = "validate_inputs"
    BUILD_REQUEST = "build_request"
    TRAIN_MODEL = "train_model"
    EVALUATE_MODEL = "evaluate_model"
    REGISTER_JOB = "register_job"
    FINALIZE = "finalize"


class ArtifactKind(str, Enum):
    """
    Safe artifact kind.

    Artifacts are summaries only. This module does not write files or persist
    durable model artifacts.
    """

    MODEL = "model"
    SUPERVISED_MODEL = "supervised_model"
    ANOMALY_MODEL = "anomaly_model"
    PREPROCESSOR = "preprocessor"
    SPLIT_PLAN = "split_plan"
    LABEL_SET = "label_set"
    EVALUATION_REPORT = "evaluation_report"
    GOVERNANCE_REPORT = "governance_report"


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

    if canonical in _FORBIDDEN_TRAIN_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_TRAIN_TOKENS)


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


def _mode_value(mode: Any) -> str:
    return _clean_text(getattr(mode, "value", mode), 64) or TrainingMode.AUTO.value


def _parse_float_mapping(value: Any) -> dict[str, float]:
    if value is None:
        return {}

    out: dict[str, float] = {}

    if isinstance(value, Mapping):
        for raw_key, raw_value in value.items():
            key = _normalize_token(raw_key)
            numeric = _coerce_optional_float(raw_value, allow_bool=True)

            if key and numeric is not None and numeric > 0:
                out[key] = _round6(numeric)

        return out

    for part in _csv(value):
        if "=" not in part:
            continue

        raw_key, raw_value = part.split("=", 1)
        key = _normalize_token(raw_key)
        numeric = _coerce_optional_float(raw_value, allow_bool=True)

        if key and numeric is not None and numeric > 0:
            out[key] = _round6(numeric)

    return out


def _merge_mappings(*maps: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}

    for mp in maps:
        if not isinstance(mp, Mapping):
            continue

        for raw_key, raw_value in mp.items():
            key = _canonical_field_name(raw_key)

            if not key:
                continue

            out[key] = _safe_detail_value(raw_value)

    return out


def _safe_replace(obj: Any, **kwargs: Any) -> Any:
    if obj is None:
        return None

    valid = {
        key: value
        for key, value in kwargs.items()
        if value is not None and hasattr(obj, key)
    }

    if not valid:
        return obj

    try:
        return replace(obj, **valid)
    except Exception:
        return obj


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


def _ensure_salt(salt: Any) -> str:
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _subject_hash(value: Any, options: "TrainModelOptions") -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.train_model.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _fingerprint_payload(payload: Any) -> str:
    try:
        return _sha256_hex(_canonical_json(payload))
    except Exception:
        return _sha256_hex(str(_safe_detail_value(payload)))


def _append_issue(
    issues: list["TrainingIssue"],
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

        issues[-1] = TrainingIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        TrainingIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _has_error(issues: Sequence[TrainingIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


# -----------------------------------------------------------------------------
# Issue, phase, artifact, options, request, and result models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrainingIssue:
    """
    Safe training issue.

    Issues never contain raw feature values, raw labels, raw narratives, raw
    identifiers, secrets, tokens, passwords, database URLs, filesystem paths, or
    model artifact paths.
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
class TrainingPhaseRecord:
    """
    One bounded training phase record.
    """

    phase: TrainingPhase | str
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
            _normalize_enum_option(TrainingPhase, self.phase, TrainingPhase.FINALIZE),
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
class ArtifactSummary:
    """
    Safe artifact summary.

    Artifacts are summaries only. This module does not write files or persist
    durable model artifacts.
    """

    kind: ArtifactKind | str
    artifact_id: Optional[str] = None
    fingerprint: str = ""
    status: str = ""
    summary: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "kind",
            _normalize_enum_option(ArtifactKind, self.kind, ArtifactKind.MODEL),
        )
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
            "kind": self.kind.value,
            "artifact_id": self.artifact_id,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "summary": _safe_detail_value(self.summary),
        }


@dataclass(frozen=True, slots=True)
class TrainModelOptions:
    """
    Bounded training harness policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    mode: TrainingMode | str = TrainingMode.AUTO
    allow_fallback: bool = True
    auto_activate: bool = False

    require_evaluation_for_candidate: bool = True
    min_train_samples: int = _DEFAULT_MIN_TRAIN_SAMPLES
    min_validation_samples: int = _DEFAULT_MIN_VALIDATION_SAMPLES
    min_test_samples: int = _DEFAULT_MIN_TEST_SAMPLES
    min_class_support: int = _DEFAULT_MIN_CLASS_SUPPORT
    max_class_imbalance_ratio: float = _DEFAULT_MAX_CLASS_IMBALANCE
    min_roc_auc: float = 0.0

    review_threshold: float = _DEFAULT_REVIEW_THRESHOLD
    risk_thresholds: Mapping[str, float] = dataclass_field(
        default_factory=lambda: {
            "low": 0.35,
            "medium": 0.55,
            "high": 0.75,
            "critical": 0.90,
        }
    )
    hybrid_weights: Mapping[str, float] = dataclass_field(
        default_factory=lambda: {
            "supervised": 0.50,
            "anomaly": 0.30,
            "fallback": 0.20,
        }
    )

    max_records: int = _DEFAULT_MAX_RECORDS
    max_features: int = _DEFAULT_MAX_FEATURES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_phases: int = _DEFAULT_MAX_PHASES
    max_artifacts: int = _DEFAULT_MAX_ARTIFACTS
    max_jobs: int = _DEFAULT_MAX_JOBS

    drop_forbidden_fields: bool = False
    register_jobs: bool = True
    expose_metrics: bool = True
    expose_governance: bool = True

    label_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    split_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    preprocess_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    supervised_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    anomaly_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fallback_options: Mapping[str, Any] = dataclass_field(default_factory=dict)

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
            "mode",
            _normalize_enum_option(TrainingMode, self.mode, TrainingMode.AUTO),
        )
        object.__setattr__(self, "allow_fallback", _as_bool(self.allow_fallback, True))
        object.__setattr__(self, "auto_activate", _as_bool(self.auto_activate, False))
        object.__setattr__(
            self,
            "require_evaluation_for_candidate",
            _as_bool(self.require_evaluation_for_candidate, True),
        )

        object.__setattr__(
            self,
            "min_train_samples",
            max(0, _as_int(self.min_train_samples, _DEFAULT_MIN_TRAIN_SAMPLES)),
        )
        object.__setattr__(
            self,
            "min_validation_samples",
            max(0, _as_int(self.min_validation_samples, _DEFAULT_MIN_VALIDATION_SAMPLES)),
        )
        object.__setattr__(
            self,
            "min_test_samples",
            max(0, _as_int(self.min_test_samples, _DEFAULT_MIN_TEST_SAMPLES)),
        )
        object.__setattr__(
            self,
            "min_class_support",
            max(0, _as_int(self.min_class_support, _DEFAULT_MIN_CLASS_SUPPORT)),
        )
        object.__setattr__(
            self,
            "max_class_imbalance_ratio",
            max(1.0, _as_float(self.max_class_imbalance_ratio, _DEFAULT_MAX_CLASS_IMBALANCE)),
        )
        object.__setattr__(
            self,
            "min_roc_auc",
            _clamp_float(self.min_roc_auc, 0.0, 1.0, 0.0),
        )

        object.__setattr__(
            self,
            "review_threshold",
            _clamp_float(self.review_threshold, 0.0, 1.0, _DEFAULT_REVIEW_THRESHOLD),
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
            "hybrid_weights",
            MappingProxyType(_parse_float_mapping(self.hybrid_weights) or {"supervised": 1.0}),
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
            "max_phases",
            _clamp_int(self.max_phases, 1, _HARD_MAX_PHASES, _DEFAULT_MAX_PHASES),
        )
        object.__setattr__(
            self,
            "max_artifacts",
            _clamp_int(self.max_artifacts, 1, _HARD_MAX_ARTIFACTS, _DEFAULT_MAX_ARTIFACTS),
        )
        object.__setattr__(
            self,
            "max_jobs",
            _clamp_int(self.max_jobs, 1, _HARD_MAX_JOBS, _DEFAULT_MAX_JOBS),
        )

        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))
        object.__setattr__(self, "register_jobs", _as_bool(self.register_jobs, True))
        object.__setattr__(self, "expose_metrics", _as_bool(self.expose_metrics, True))
        object.__setattr__(self, "expose_governance", _as_bool(self.expose_governance, True))

        object.__setattr__(self, "label_options", MappingProxyType(_safe_detail_value(self.label_options) or {}))
        object.__setattr__(self, "split_options", MappingProxyType(_safe_detail_value(self.split_options) or {}))
        object.__setattr__(
            self,
            "preprocess_options",
            MappingProxyType(_safe_detail_value(self.preprocess_options) or {}),
        )
        object.__setattr__(
            self,
            "supervised_options",
            MappingProxyType(_safe_detail_value(self.supervised_options) or {}),
        )
        object.__setattr__(
            self,
            "anomaly_options",
            MappingProxyType(_safe_detail_value(self.anomaly_options) or {}),
        )
        object.__setattr__(
            self,
            "fallback_options",
            MappingProxyType(_safe_detail_value(self.fallback_options) or {}),
        )

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "TrainModelOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_TRAIN_MODEL_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_TRAIN_MODEL_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_TRAIN_MODEL_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_TRAIN_MODEL_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_TRAIN_MODEL_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_TRAIN_MODEL_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            mode=str(_setting(settings, "ML_TRAIN_MODEL_MODE", TrainingMode.AUTO.value)),
            allow_fallback=_as_bool(_setting(settings, "ML_TRAIN_MODEL_ALLOW_FALLBACK", True), True),
            auto_activate=_as_bool(_setting(settings, "ML_TRAIN_MODEL_AUTO_ACTIVATE", False), False),
            require_evaluation_for_candidate=_as_bool(
                _setting(settings, "ML_TRAIN_MODEL_REQUIRE_EVALUATION_FOR_CANDIDATE", True),
                True,
            ),
            min_train_samples=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MIN_TRAIN_SAMPLES", _DEFAULT_MIN_TRAIN_SAMPLES),
                _DEFAULT_MIN_TRAIN_SAMPLES,
            ),
            min_validation_samples=_as_int(
                _setting(
                    settings,
                    "ML_TRAIN_MODEL_MIN_VALIDATION_SAMPLES",
                    _DEFAULT_MIN_VALIDATION_SAMPLES,
                ),
                _DEFAULT_MIN_VALIDATION_SAMPLES,
            ),
            min_test_samples=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MIN_TEST_SAMPLES", _DEFAULT_MIN_TEST_SAMPLES),
                _DEFAULT_MIN_TEST_SAMPLES,
            ),
            min_class_support=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MIN_CLASS_SUPPORT", _DEFAULT_MIN_CLASS_SUPPORT),
                _DEFAULT_MIN_CLASS_SUPPORT,
            ),
            max_class_imbalance_ratio=_as_float(
                _setting(
                    settings,
                    "ML_TRAIN_MODEL_MAX_CLASS_IMBALANCE_RATIO",
                    _DEFAULT_MAX_CLASS_IMBALANCE,
                ),
                _DEFAULT_MAX_CLASS_IMBALANCE,
            ),
            min_roc_auc=_as_float(_setting(settings, "ML_TRAIN_MODEL_MIN_ROC_AUC", 0.0), 0.0),
            review_threshold=_as_float(
                _setting(settings, "ML_TRAIN_MODEL_REVIEW_THRESHOLD", _DEFAULT_REVIEW_THRESHOLD),
                _DEFAULT_REVIEW_THRESHOLD,
            ),
            risk_thresholds={
                "low": _as_float(_setting(settings, "ML_TRAIN_MODEL_RISK_LOW", 0.35), 0.35),
                "medium": _as_float(_setting(settings, "ML_TRAIN_MODEL_RISK_MEDIUM", 0.55), 0.55),
                "high": _as_float(_setting(settings, "ML_TRAIN_MODEL_RISK_HIGH", 0.75), 0.75),
                "critical": _as_float(_setting(settings, "ML_TRAIN_MODEL_RISK_CRITICAL", 0.90), 0.90),
            },
            hybrid_weights=_parse_float_mapping(
                _setting(
                    settings,
                    "ML_TRAIN_MODEL_HYBRID_WEIGHTS",
                    "supervised=0.50,anomaly=0.30,fallback=0.20",
                )
            ),
            max_records=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MAX_RECORDS", _DEFAULT_MAX_RECORDS),
                _DEFAULT_MAX_RECORDS,
            ),
            max_features=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MAX_FEATURES", _DEFAULT_MAX_FEATURES),
                _DEFAULT_MAX_FEATURES,
            ),
            max_issues=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_phases=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MAX_PHASES", _DEFAULT_MAX_PHASES),
                _DEFAULT_MAX_PHASES,
            ),
            max_artifacts=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MAX_ARTIFACTS", _DEFAULT_MAX_ARTIFACTS),
                _DEFAULT_MAX_ARTIFACTS,
            ),
            max_jobs=_as_int(
                _setting(settings, "ML_TRAIN_MODEL_MAX_JOBS", _DEFAULT_MAX_JOBS),
                _DEFAULT_MAX_JOBS,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ML_TRAIN_MODEL_DROP_FORBIDDEN_FIELDS", False),
                False,
            ),
            register_jobs=_as_bool(_setting(settings, "ML_TRAIN_MODEL_REGISTER_JOBS", True), True),
            expose_metrics=_as_bool(_setting(settings, "ML_TRAIN_MODEL_EXPOSE_METRICS", True), True),
            expose_governance=_as_bool(
                _setting(settings, "ML_TRAIN_MODEL_EXPOSE_GOVERNANCE", True),
                True,
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
            "mode": self.mode.value if isinstance(self.mode, TrainingMode) else str(self.mode),
            "allow_fallback": self.allow_fallback,
            "auto_activate": self.auto_activate,
            "governance": {
                "require_evaluation_for_candidate": self.require_evaluation_for_candidate,
                "min_train_samples": self.min_train_samples,
                "min_validation_samples": self.min_validation_samples,
                "min_test_samples": self.min_test_samples,
                "min_class_support": self.min_class_support,
                "max_class_imbalance_ratio": round(self.max_class_imbalance_ratio, 6),
                "min_roc_auc": round(self.min_roc_auc, 6),
            },
            "thresholds": {
                "review_threshold": round(self.review_threshold, 6),
                "risk_thresholds": dict(self.risk_thresholds),
                "hybrid_weights": dict(self.hybrid_weights),
            },
            "limits": {
                "max_records": self.max_records,
                "max_features": self.max_features,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_phases": self.max_phases,
                "max_artifacts": self.max_artifacts,
                "max_jobs": self.max_jobs,
            },
            "flags": {
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "register_jobs": self.register_jobs,
                "expose_metrics": self.expose_metrics,
                "expose_governance": self.expose_governance,
            },
            "submodule_override_keys": {
                "label_options": sorted(self.label_options),
                "split_options": sorted(self.split_options),
                "preprocess_options": sorted(self.preprocess_options),
                "supervised_options": sorted(self.supervised_options),
                "anomaly_options": sorted(self.anomaly_options),
                "fallback_options": sorted(self.fallback_options),
            },
        }


@dataclass(slots=True)
class TrainingJobRequest:
    """
    Bounded training job request.
    """

    features: Any = None
    labels: Any = None
    mode: TrainingMode | str | None = None
    feature_names: Optional[Sequence[str]] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    observation_time: Optional[datetime] = None
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    idempotency_key: Optional[str] = None
    job_id: Optional[str] = None

    label_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    split_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    preprocess_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    supervised_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    anomaly_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fallback_options: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        self.mode = (
            _normalize_enum_option(TrainingMode, self.mode, None)
            if self.mode is not None
            else None
        )
        self.metadata = _safe_detail_value(self.metadata) or {}
        self.observation_time = _ensure_utc(self.observation_time)
        self.tags = tuple(
            dict.fromkeys(
                _clean_text(tag, 100)
                for tag in (self.tags or ())
                if _clean_text(tag, 100)
            )
        )
        self.idempotency_key = _clean_text(self.idempotency_key, 200) if self.idempotency_key else None
        self.job_id = _clean_text(self.job_id, 128) if self.job_id else None

        self.label_options = _safe_detail_value(self.label_options) or {}
        self.split_options = _safe_detail_value(self.split_options) or {}
        self.preprocess_options = _safe_detail_value(self.preprocess_options) or {}
        self.supervised_options = _safe_detail_value(self.supervised_options) or {}
        self.anomaly_options = _safe_detail_value(self.anomaly_options) or {}
        self.fallback_options = _safe_detail_value(self.fallback_options) or {}

        if self.feature_names is not None:
            self.feature_names = tuple(
                dict.fromkeys(
                    _canonical_field_name(name)
                    for name in self.feature_names
                    if _canonical_field_name(name)
                )
            )


@dataclass(frozen=True, slots=True)
class TrainingJobResult:
    """
    Safe training job result.

    Public summaries deliberately exclude raw feature values, subject-label
    pairs, raw identifiers, raw narratives, secrets, tokens, passwords, database
    URLs, filesystem paths, and model artifact paths.
    """

    job_id: str
    status: JobStatus
    mode: TrainingMode
    kind: str
    model_id: str = ""
    created_at: datetime = dataclass_field(default_factory=_now_utc)
    finished_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    phases: tuple[TrainingPhaseRecord, ...] = ()
    metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    governance: Mapping[str, Any] = dataclass_field(default_factory=dict)
    split_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    preprocessing_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    label_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    artifacts: tuple[ArtifactSummary, ...] = ()
    issues: tuple[TrainingIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_id", _clean_text(self.job_id, 128))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(JobStatus, self.status, JobStatus.FAILED),
        )
        object.__setattr__(
            self,
            "mode",
            _normalize_enum_option(TrainingMode, self.mode, TrainingMode.AUTO),
        )
        object.__setattr__(self, "kind", _normalize_token(self.kind) or "none")
        object.__setattr__(self, "model_id", _clean_text(self.model_id, 128))
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())
        object.__setattr__(self, "finished_at", _ensure_utc(self.finished_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "phases", tuple(self.phases or ())[: _HARD_MAX_PHASES])
        object.__setattr__(self, "metrics", MappingProxyType(_safe_detail_value(self.metrics) or {}))
        object.__setattr__(self, "governance", MappingProxyType(_safe_detail_value(self.governance) or {}))
        object.__setattr__(self, "split_summary", MappingProxyType(_safe_detail_value(self.split_summary) or {}))
        object.__setattr__(
            self,
            "preprocessing_summary",
            MappingProxyType(_safe_detail_value(self.preprocessing_summary) or {}),
        )
        object.__setattr__(self, "label_summary", MappingProxyType(_safe_detail_value(self.label_summary) or {}))
        object.__setattr__(self, "artifacts", tuple(self.artifacts or ())[: _HARD_MAX_ARTIFACTS])
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": TRAIN_MODEL_VERSION,
                        "job_id": self.job_id,
                        "status": self.status.value,
                        "mode": self.mode.value,
                        "kind": self.kind,
                        "model_id": self.model_id,
                        "metrics": self.metrics,
                        "governance": self.governance,
                        "phases": [phase.to_dict() for phase in self.phases],
                        "artifacts": [artifact.to_dict() for artifact in self.artifacts],
                        "issues": [issue.to_dict() for issue in self.issues],
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "mode": self.mode.value,
            "kind": self.kind,
            "model_id": self.model_id,
            "created_at": self.created_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "phases": [phase.to_dict() for phase in self.phases],
            "metrics": _safe_detail_value(self.metrics),
            "governance": _safe_detail_value(self.governance),
            "split_summary": _safe_detail_value(self.split_summary),
            "preprocessing_summary": _safe_detail_value(self.preprocessing_summary),
            "label_summary": _safe_detail_value(self.label_summary),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_TRAIN_CAVEATS),
            "safety_flags": dict(_TRAIN_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local training job registry
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _RegisteredTrainingJob:
    result: TrainingJobResult
    service: Any = None
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class TrainingJobRegistry:
    """
    Bounded process-local training job registry.

    This registry is not durable, not distributed, and not production-ready.
    It exists only to support local prototype workflows, tests, and developer
    tooling.
    """

    def __init__(self, max_jobs: int = _DEFAULT_MAX_JOBS) -> None:
        self.max_jobs = max(1, int(max_jobs))
        self._jobs: dict[str, _RegisteredTrainingJob] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, result: TrainingJobResult, *, service: Any = None) -> str:
        """
        Register one training job result and return its job id.
        """
        with self._lock:
            job_id = _clean_text(result.job_id, 128)

            if not job_id:
                job_id = result.fingerprint[:32] or _sha256_hex(str(len(self._jobs) + 1))[:32]

            if job_id in self._jobs:
                self._jobs[job_id] = _RegisteredTrainingJob(
                    result=result,
                    service=service,
                    registered_at=_now_utc(),
                )
                return job_id

            self._jobs[job_id] = _RegisteredTrainingJob(
                result=result,
                service=service,
                registered_at=_now_utc(),
            )
            self._order.append(job_id)

            if len(self._order) > self.max_jobs:
                evict_id = self._order.pop(0)
                self._jobs.pop(evict_id, None)

            return job_id

    def get(self, job_id: Any) -> Optional[_RegisteredTrainingJob]:
        """
        Return one registered job entry.
        """
        key = _clean_text(job_id, 128)

        with self._lock:
            return self._jobs.get(key)

    def get_result(self, job_id: Any) -> Optional[TrainingJobResult]:
        """
        Return one registered job result.
        """
        entry = self.get(job_id)
        return entry.result if entry is not None else None

    def get_service(self, job_id: Any) -> Any:
        """
        Return the process-local model service associated with one job, when
        available.
        """
        entry = self.get(job_id)
        return entry.service if entry is not None else None

    def list_results(self, *, limit: int = 50) -> tuple[TrainingJobResult, ...]:
        """
        Return registered job results in insertion order.
        """
        with self._lock:
            out: list[TrainingJobResult] = []

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
                        "mode": result.mode.value,
                        "kind": result.kind,
                        "model_id": result.model_id,
                        "created_at": result.created_at.isoformat(),
                        "finished_at": result.finished_at.isoformat(),
                        "duration_ms": int(result.duration_ms),
                        "fingerprint": result.fingerprint,
                        "issue_count": len(result.issues),
                        "artifact_count": len(result.artifacts),
                        "has_service": entry.service is not None,
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
            mode_counter = Counter(entry.result.mode.value for entry in self._jobs.values())
            kind_counter = Counter(entry.result.kind for entry in self._jobs.values())

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_jobs": self.max_jobs,
            "registered_jobs": len(self._order),
            "by_status": dict(status_counter),
            "by_mode": dict(mode_counter),
            "by_kind": dict(kind_counter),
            "recent": self.summarize(limit=limit),
        }


_default_registry: Optional[TrainingJobRegistry] = None
_default_registry_lock = threading.Lock()


# `get_train_job_registry` is defined once, further down this module. An
# earlier duplicate definition lived here and rebuilt the registry whenever
# `max_jobs` was supplied, discarding the records of every in-flight and
# completed training job. Python keeps the last definition, so the correct
# behaviour was already in effect and this copy only misled anyone reading the
# file from the top.


# -----------------------------------------------------------------------------
# Input extraction and sanitization
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "features",
        "labels",
        "mode",
        "feature_names",
        "metadata",
        "observation_time",
        "tags",
        "idempotency_key",
        "job_id",
        "label_options",
        "split_options",
        "preprocess_options",
        "supervised_options",
        "anomaly_options",
        "fallback_options",
    }
)


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, TrainingJobResult):
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


def _extract_subject(record: Any, options: TrainModelOptions) -> Optional[str]:
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


def _coerce_request(request: Any) -> TrainingJobRequest:
    if isinstance(request, TrainingJobRequest):
        return request

    if isinstance(request, Mapping):
        if any(key in request for key in _REQUEST_KEYS):
            try:
                return TrainingJobRequest(**request)
            except Exception:
                pass

        return TrainingJobRequest(features=request)

    return TrainingJobRequest(features=request)


def _clean_training_records(
    records: Sequence[Any],
    options: TrainModelOptions,
    issues: list[TrainingIssue],
) -> Optional[list[dict[str, Any]]]:
    """
    Clean and bound training feature records.

    Returns None when the input must be rejected.
    """
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

        if not clean_features:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="empty_feature_row",
                message="Row had no valid feature fields and was skipped.",
                details={"index": index},
            )
            continue

        if subject:
            if subject in seen_subjects:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.INFO,
                    code="duplicate_subject_reference",
                    message="Duplicate subject reference detected in training input.",
                    details={"index": index},
                )
            else:
                seen_subjects.add(subject)

        out_record: dict[str, Any] = {"features": clean_features}

        if subject:
            out_record["subject_ref_hash"] = subject

        cleaned.append(out_record)

    if not cleaned:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="no_valid_training_records",
            message="No valid training records remained after sanitization.",
        )
        return None

    return cleaned


def _scan_labels(
    labels: Any,
    options: TrainModelOptions,
    issues: list[TrainingIssue],
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


def _label_code_from_mapping(mapping: Mapping[Any, Any]) -> Any:
    for key in ("label_code", "label", "target", "y", "synthetic_label"):
        if key in mapping:
            return mapping[key]

    return None


def _iter_label_codes(labels: Any) -> Iterable[Any]:
    if labels is None:
        return

    if isinstance(labels, Mapping):
        for key in ("label_codes", "labels", "y"):
            if key in labels:
                for code in _as_sequence(labels[key]):
                    yield code
                return

        for key in ("records", "items", "rows"):
            if key in labels:
                for record in _as_sequence(labels[key]):
                    if isinstance(record, Mapping):
                        code = _label_code_from_mapping(record)

                        if code is not None:
                            yield code
                    else:
                        yield record
                return

        code = _label_code_from_mapping(labels)

        if code is not None:
            yield code

        return

    for attr in ("label_codes", "labels", "y"):
        seq = getattr(labels, attr, None)

        if seq is not None:
            for code in _as_sequence(seq):
                yield code
            return

    records = getattr(labels, "records", None) or getattr(labels, "items", None)

    if records is not None:
        for record in _as_sequence(records):
            if isinstance(record, Mapping):
                code = _label_code_from_mapping(record)

                if code is not None:
                    yield code
            else:
                yield record
        return

    for item in _as_sequence(labels):
        if isinstance(item, Mapping):
            code = _label_code_from_mapping(item)

            if code is not None:
                yield code
        else:
            yield item


def _label_class_counter(labels: Any) -> tuple[Counter[int], int]:
    counter: Counter[int] = Counter()
    total = 0

    for raw_code in _iter_label_codes(labels):
        code = _coerce_int_label(raw_code)
        total += 1

        if code is not None:
            counter[code] += 1

    return counter, total


def _label_summary(labels: Any) -> dict[str, Any]:
    if labels is None:
        return {"available": False}

    counter, total = _label_class_counter(labels)

    distribution = {
        str(code): _round6(float(count) / float(total))
        for code, count in sorted(counter.items())
    } if total > 0 else {}

    return {
        "available": True,
        "label_count": int(total),
        "class_count": int(len(counter)),
        "class_distribution": distribution,
        "records_omitted": True,
        "subject_label_pairs_omitted": True,
    }


def _records_feature_names(records: Sequence[Any]) -> tuple[str, ...]:
    observed: set[str] = set()

    for record in records:
        features = _extract_feature_mapping(record)

        for raw_key in features.keys():
            canonical = _canonical_field_name(raw_key)

            if canonical:
                observed.add(canonical)

    return tuple(sorted(observed))


def _input_fingerprint(records: Sequence[Any], labels: Any) -> str:
    feature_names = _records_feature_names(records)
    counter, total = _label_class_counter(labels)

    payload = {
        "version": TRAIN_MODEL_VERSION,
        "record_count": len(records),
        "feature_count": len(feature_names),
        "feature_names_sample": list(feature_names[:_DEFAULT_MAX_SUMMARY_ITEMS]),
        "feature_names_truncated": len(feature_names) > _DEFAULT_MAX_SUMMARY_ITEMS,
        "label_count": total,
        "class_distribution": {
            str(code): _round6(float(count) / float(total))
            for code, count in sorted(counter.items())
        }
        if total > 0
        else {},
    }

    return _fingerprint_payload(payload)


def _derive_job_id(
    request: TrainingJobRequest,
    options: TrainModelOptions,
    mode: TrainingMode,
    input_fp: str,
) -> str:
    payload = {
        "version": TRAIN_MODEL_VERSION,
        "mode": mode.value,
        "options": options.safe_summary(),
        "request_metadata": _safe_detail_value(request.metadata),
        "tags": list(request.tags),
        "observation_time": (
            _ensure_utc(request.observation_time).isoformat()
            if _ensure_utc(request.observation_time)
            else None
        ),
        "idempotency_key": request.idempotency_key,
        "input_fingerprint": input_fp,
    }

    return _sha256_hex(_canonical_json(payload))[:32]


# -----------------------------------------------------------------------------
# Model service bridge helpers
# -----------------------------------------------------------------------------


def _resolve_mode(requested: Any, default: Any, labels: Any) -> TrainingMode:
    """
    Resolve training mode.
    """
    default_mode = _normalize_enum_option(TrainingMode, default, TrainingMode.AUTO)
    mode = (
        _normalize_enum_option(TrainingMode, requested, default_mode)
        if requested is not None
        else default_mode
    )

    if mode == TrainingMode.AUTO:
        return TrainingMode.SUPERVISED if labels is not None else TrainingMode.ANOMALY

    return mode


def _build_model_service_options(
    options: TrainModelOptions,
    request: TrainingJobRequest,
) -> Any:
    """
    Build model-service options from training-harness options and request
    overrides.
    """
    if model_service_module is None:
        return None

    cls = getattr(model_service_module, "ModelServiceOptions", None)

    if cls is None:
        return None

    try:
        base = cls.from_settings()
    except Exception:
        base = cls()

    mode = request.mode or options.mode

    overrides = {
        "enabled": options.enabled,
        "synthetic_required": options.synthetic_required,
        "dataset_mode": options.dataset_mode,
        "production_like": options.production_like,
        "allow_in_production": options.allow_in_production,
        "salt": options.salt,
        "namespace": options.namespace,
        "seed": options.seed,
        "mode": _mode_value(mode),
        "allow_fallback": options.allow_fallback,
        "auto_activate": options.auto_activate,
        "require_evaluation_for_candidate": options.require_evaluation_for_candidate,
        "min_train_samples": options.min_train_samples,
        "min_validation_samples": options.min_validation_samples,
        "min_test_samples": options.min_test_samples,
        "min_class_support": options.min_class_support,
        "max_class_imbalance_ratio": options.max_class_imbalance_ratio,
        "min_roc_auc": options.min_roc_auc,
        "review_threshold": options.review_threshold,
        "risk_thresholds": dict(options.risk_thresholds),
        "hybrid_weights": dict(options.hybrid_weights),
        "max_records": options.max_records,
        "max_features": options.max_features,
        "max_issues": options.max_issues,
        "max_summary_items": options.max_summary_items,
        "max_contributions": 20,
        "max_catalog_entries": options.max_jobs,
        "max_audit_events": max(1, options.max_jobs * 2),
        "label_options": _merge_mappings(options.label_options, request.label_options),
        "split_options": _merge_mappings(options.split_options, request.split_options),
        "preprocess_options": _merge_mappings(options.preprocess_options, request.preprocess_options),
        "supervised_options": _merge_mappings(options.supervised_options, request.supervised_options),
        "anomaly_options": _merge_mappings(options.anomaly_options, request.anomaly_options),
        "fallback_options": _merge_mappings(options.fallback_options, request.fallback_options),
    }

    return _safe_replace(base, **overrides)


def _build_model_service_request(
    request: TrainingJobRequest,
    cleaned_records: Sequence[Mapping[str, Any]],
    options: TrainModelOptions,
) -> dict[str, Any]:
    """
    Build a model-service training request from sanitized harness input.
    """
    mode = request.mode or options.mode

    return {
        "features": list(cleaned_records),
        "labels": request.labels,
        "mode": _mode_value(mode),
        "feature_names": request.feature_names,
        "metadata": request.metadata,
        "observation_time": request.observation_time,
        "tags": request.tags,
        "label_options": request.label_options,
        "split_options": request.split_options,
        "preprocess_options": request.preprocess_options,
        "supervised_options": request.supervised_options,
        "anomaly_options": request.anomaly_options,
    }


def _call_model_service_train(
    request: TrainingJobRequest,
    cleaned_records: Sequence[Mapping[str, Any]],
    options: TrainModelOptions,
    service: Any,
    issues: list[TrainingIssue],
) -> tuple[Any, Any]:
    """
    Invoke model-service training.

    Returns `(training_result, service)`.
    """
    ms_request = _build_model_service_request(request, cleaned_records, options)

    if service is not None:
        train_method = getattr(service, "train", None)

        if callable(train_method):
            try:
                result = train_method(ms_request)
                return result, service
            except Exception as exc:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="model_service_train_failed",
                    message="Model service training call failed.",
                    details={"exception_type": type(exc).__name__},
                )
                return None, service

        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="model_service_train_unavailable",
            message="Provided service does not expose a train method.",
        )
        return None, service

    if model_service_module is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="model_service_unavailable",
            message="Model service module is unavailable.",
        )
        return None, None

    ms_options = _build_model_service_options(options, request)
    cls = getattr(model_service_module, "ModelService", None)

    if cls is not None:
        try:
            svc = cls(options=ms_options) if ms_options is not None else cls()
            result = svc.train(ms_request)
            return result, svc
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="model_service_train_failed",
                message="Model service training failed.",
                details={"exception_type": type(exc).__name__},
            )

    func = getattr(model_service_module, "train_model_service", None)

    if callable(func):
        try:
            result = func(ms_request, options=ms_options)
            getter = getattr(model_service_module, "get_model_service", None)
            svc = getter() if callable(getter) else None
            return result, svc
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="model_service_train_failed",
                message="Model service training function failed.",
                details={"exception_type": type(exc).__name__},
            )

    _append_issue(
        issues,
        options.max_issues,
        severity=IssueSeverity.ERROR,
        code="model_service_api_unavailable",
        message="Model service does not expose a supported training API.",
    )
    return None, None


def _convert_issues(raw_issues: Any, options: TrainModelOptions) -> tuple[TrainingIssue, ...]:
    """
    Convert downstream issues into harness-safe issues.
    """
    out: list[TrainingIssue] = []

    for issue in raw_issues or ():
        if isinstance(issue, TrainingIssue):
            out.append(issue)
            continue

        severity = _normalize_enum_option(
            IssueSeverity,
            getattr(issue, "severity", "warning"),
            IssueSeverity.WARNING,
        )
        code = _clean_text(getattr(issue, "code", "unknown"), 100)
        message = _clean_text(getattr(issue, "message", ""), 300)
        field = getattr(issue, "field", None)
        details = getattr(issue, "details", {})

        out.append(
            TrainingIssue(
                severity=severity,
                code=code,
                message=message,
                field=_clean_text(field, 200) if field else None,
                details=_safe_details(details if isinstance(details, Mapping) else None),
            )
        )

        if len(out) >= options.max_issues:
            break

    return tuple(out)


def _job_status(result: Any) -> JobStatus:
    """
    Map downstream training result status to harness job status.
    """
    status = getattr(result, "status", None)
    value = _clean_text(getattr(status, "value", status), 32).upper()
    ok = bool(getattr(result, "ok", False))

    if value == "BLOCKED":
        return JobStatus.BLOCKED

    if value == "FAILED" or not ok:
        return JobStatus.FAILED

    return JobStatus.SUCCEEDED


def _kind_from_result(result: Any) -> str:
    """
    Return normalized kind from downstream result.
    """
    return _normalize_token(getattr(result, "kind", "none")) or "none"


def _extract_metrics(result: Any, options: TrainModelOptions) -> dict[str, Any]:
    """
    Extract safe metric summary from downstream result.
    """
    if not options.expose_metrics:
        return {"available": False, "omitted": True}

    raw = getattr(result, "metrics", {}) or {}

    if not isinstance(raw, Mapping):
        raw = {}

    snapshot: dict[str, Any] = {"available": bool(raw)}
    selected = (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "pr_auc",
        "log_loss",
        "brier_score",
        "expected_calibration_error",
        "macro_f1",
        "weighted_f1",
    )

    for split in ("validation", "test"):
        report = raw.get(split)

        if not isinstance(report, Mapping):
            continue

        report_metrics = report.get("metrics")

        if not isinstance(report_metrics, Mapping):
            report_metrics = {}

        split_snapshot: dict[str, Any] = {
            "ok": bool(report.get("ok", False)),
            "counts": _safe_detail_value(report.get("counts")),
        }

        for key in selected:
            numeric = _coerce_optional_float(report_metrics.get(key), allow_bool=False)

            if numeric is not None:
                split_snapshot[key] = _round6(numeric)
                snapshot[f"{split}_{key}"] = _round6(numeric)

        snapshot[split] = split_snapshot

    return _safe_detail_value(snapshot) or {}


def _extract_governance(result: Any, options: TrainModelOptions) -> dict[str, Any]:
    """
    Extract safe governance summary from downstream result.
    """
    if not options.expose_governance:
        return {"available": False, "omitted": True}

    raw = getattr(result, "governance", {}) or {}

    if not isinstance(raw, Mapping):
        raw = {}

    return _safe_detail_value(raw) or {}


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


def _get_catalog_entry(service: Any, model_id: str) -> Any:
    """
    Return process-local catalog entry for a model id when available.
    """
    if service is None or not model_id:
        return None

    for name in ("get_catalog_entry", "get_entry", "_get_entry"):
        method = getattr(service, name, None)

        if callable(method):
            try:
                return method(model_id)
            except Exception:
                continue

    return None


def _object_fingerprint(obj: Any) -> str:
    """
    Return safe fingerprint for an object when available.
    """
    if obj is None:
        return ""

    fp = getattr(obj, "fingerprint", None)

    if callable(fp):
        try:
            return _clean_text(fp(), 128)
        except Exception:
            pass

    if isinstance(fp, str):
        return _clean_text(fp, 128)

    summary = _safe_summary_from_object(obj)

    if summary:
        return _fingerprint_payload(summary)

    return ""


def _build_artifacts(
    result: Any,
    service: Any,
    label_summary: Mapping[str, Any],
    options: TrainModelOptions,
) -> tuple[ArtifactSummary, ...]:
    """
    Build bounded safe artifact summaries.

    Artifacts are summaries only. This module does not write files or persist
    durable model artifacts.
    """
    artifacts: list[ArtifactSummary] = []
    seen: set[tuple[str, str]] = set()

    model_id = _clean_text(getattr(result, "model_id", ""), 128) if result is not None else ""
    result_fingerprint = _clean_text(getattr(result, "fingerprint", ""), 128) if result is not None else ""
    raw_status = getattr(result, "status", "") if result is not None else ""
    result_status = _clean_text(getattr(raw_status, "value", raw_status), 32)
    result_kind = _normalize_token(getattr(result, "kind", "none") if result is not None else "none") or "none"

    def add(
        kind: ArtifactKind,
        artifact_id: Optional[str],
        fingerprint: str,
        status: str,
        summary: Mapping[str, Any],
    ) -> None:
        if len(artifacts) >= options.max_artifacts:
            return

        fid = _clean_text(artifact_id, 128) or _clean_text(fingerprint, 128) or kind.value
        key = (kind.value, fid)

        if key in seen:
            return

        seen.add(key)
        artifacts.append(
            ArtifactSummary(
                kind=kind,
                artifact_id=artifact_id,
                fingerprint=fingerprint,
                status=status,
                summary=summary,
            )
        )

    entry = _get_catalog_entry(service, model_id)
    entry_summary = _safe_summary_from_object(entry)

    if model_id:
        add(
            ArtifactKind.MODEL,
            model_id,
            _clean_text(entry_summary.get("fingerprint"), 128) or result_fingerprint,
            _clean_text(entry_summary.get("status"), 32) or result_status,
            {"kind": result_kind, "entry": entry_summary or {}},
        )

    if entry is not None:
        supervised = getattr(entry, "supervised_model", None)

        if supervised is not None:
            supervised_status = getattr(supervised, "status", None)
            add(
                ArtifactKind.SUPERVISED_MODEL,
                _clean_text(getattr(supervised, "model_id", None), 128) or model_id,
                _object_fingerprint(supervised) or result_fingerprint,
                _clean_text(getattr(supervised_status, "value", supervised_status), 32) or result_status,
                {
                    "summary": _safe_summary_from_object(supervised),
                    "label_summary": label_summary,
                },
            )

        anomaly = getattr(entry, "anomaly_model", None)

        if anomaly is not None:
            anomaly_status = getattr(anomaly, "status", None)
            add(
                ArtifactKind.ANOMALY_MODEL,
                _clean_text(getattr(anomaly, "model_id", None), 128) or model_id,
                _object_fingerprint(anomaly) or result_fingerprint,
                _clean_text(getattr(anomaly_status, "value", anomaly_status), 32) or result_status,
                {
                    "summary": _safe_summary_from_object(anomaly),
                    "label_summary": label_summary,
                },
            )

        preprocessor = getattr(entry, "preprocessor", None)

        if preprocessor is not None:
            add(
                ArtifactKind.PREPROCESSOR,
                None,
                _object_fingerprint(preprocessor) or result_fingerprint,
                result_status,
                {"summary": _safe_summary_from_object(preprocessor)},
            )

    split_summary = _safe_detail_value(getattr(result, "split_summary", {}) if result is not None else {}) or {}

    if isinstance(split_summary, Mapping) and split_summary:
        add(
            ArtifactKind.SPLIT_PLAN,
            None,
            _fingerprint_payload(split_summary),
            result_status,
            {"summary": split_summary},
        )

    if label_summary:
        add(
            ArtifactKind.LABEL_SET,
            None,
            _fingerprint_payload(label_summary),
            result_status,
            {"summary": label_summary},
        )

    metrics = _safe_detail_value(getattr(result, "metrics", {}) if result is not None else {}) or {}

    if isinstance(metrics, Mapping) and metrics:
        add(
            ArtifactKind.EVALUATION_REPORT,
            None,
            _fingerprint_payload(metrics),
            result_status,
            {"summary": metrics},
        )

    governance = _safe_detail_value(getattr(result, "governance", {}) if result is not None else {}) or {}

    if isinstance(governance, Mapping) and governance:
        add(
            ArtifactKind.GOVERNANCE_REPORT,
            None,
            _fingerprint_payload(governance),
            result_status,
            {"summary": governance},
        )

    return tuple(artifacts)


def _filter_records_feature_names(
    records: Sequence[Mapping[str, Any]],
    feature_names: Optional[Sequence[str]],
    options: TrainModelOptions,
    issues: list[TrainingIssue],
) -> list[dict[str, Any]]:
    """
    Filter record feature mappings to requested feature names.
    """
    if not feature_names:
        return [dict(record) for record in records]

    allowed = set(
        dict.fromkeys(
            _canonical_field_name(name)
            for name in feature_names
            if _canonical_field_name(name)
        )
    )

    out: list[dict[str, Any]] = []

    for index, record in enumerate(records):
        features = record.get("features") if isinstance(record, Mapping) else {}

        if not isinstance(features, Mapping):
            features = {}

        filtered = {
            key: value
            for key, value in features.items()
            if key in allowed
        }

        if not filtered:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="empty_feature_row_after_filter",
                message="Row had no requested feature fields and was skipped.",
                details={"index": index},
            )
            continue

        new_record = dict(record)
        new_record["features"] = filtered
        out.append(new_record)

    return out


def _phase_record(
    phase: TrainingPhase | str,
    started_mono: float,
    started_dt: datetime,
    ok: bool,
    issue_base: int,
    issues: Sequence[TrainingIssue],
    details: Optional[Mapping[str, Any]] = None,
) -> TrainingPhaseRecord:
    """
    Build one bounded phase record.
    """
    finished_dt = _now_utc()
    duration_ms = int((time.monotonic() - started_mono) * 1000.0)

    return TrainingPhaseRecord(
        phase=phase,
        started_at=started_dt,
        finished_at=finished_dt,
        duration_ms=max(0, duration_ms),
        ok=bool(ok),
        issue_count=max(0, len(issues) - issue_base),
        details=details or {},
    )


def _module_available(module: Any, *names: str) -> bool:
    """
    Return True when a module exposes required attributes.
    """
    if module is None:
        return False

    return all(hasattr(module, name) for name in names)


# -----------------------------------------------------------------------------
# Safe registry accessor
# -----------------------------------------------------------------------------


def get_train_job_registry(
    max_jobs: int | None = None,
    *,
    rebuild: bool = False,
) -> TrainingJobRegistry:
    """
    Return the process-wide training job registry.

    Unlike a naive accessor, supplying `max_jobs` does not reset an existing
    registry unless `rebuild=True`.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = TrainingJobRegistry(
                max_jobs=max_jobs if max_jobs is not None else _DEFAULT_MAX_JOBS
            )

        return _default_registry


# -----------------------------------------------------------------------------
# Training harness
# -----------------------------------------------------------------------------


class TrainModelHarness:
    """
    Bounded deterministic synthetic ML training harness.

    This harness validates and sanitizes training input, resolves mode, invokes
    the model-service orchestration layer when available, records safe phase
    history, builds artifact summaries, applies governance checks, and registers
    process-local training jobs.

    It does not deploy models, persist durable artifacts, call external systems,
    or take adverse action.
    """

    def __init__(self, options: TrainModelOptions | None = None) -> None:
        self.options = options or TrainModelOptions.from_settings()
        self._lock = threading.RLock()

    def run(self, request: Any) -> TrainingJobResult:
        """
        Run one bounded synthetic training job.
        """
        opts = self.options
        issues: list[TrainingIssue] = []
        phases: list[TrainingPhaseRecord] = []

        started_at = _now_utc()
        started_mono = time.monotonic()

        req = _coerce_request(request)
        mode = _resolve_mode(req.mode, opts.mode, req.labels)

        service: Any = None
        train_result: Any = None
        label_summary: dict[str, Any] = {}
        input_fp: str = ""
        job_id: str = ""
        cleaned: Optional[list[dict[str, Any]]] = None

        def make_result(
            status: JobStatus,
            kind: str,
            model_id: str = "",
        ) -> TrainingJobResult:
            """
            Build one safe training job result from current harness state.
            """
            resolved_job_id = job_id or _sha256_hex(
                _canonical_json(
                    {
                        "version": TRAIN_MODEL_VERSION,
                        "mode": mode.value,
                        "input_fingerprint": input_fp,
                        "metadata": _safe_detail_value(req.metadata),
                        "tags": list(req.tags),
                        "issue_count": len(issues),
                    }
                )
            )[:32]

            metrics = _extract_metrics(train_result, opts) if train_result is not None else {}
            governance = _extract_governance(train_result, opts) if train_result is not None else {}

            split_summary = (
                _safe_detail_value(getattr(train_result, "split_summary", {}))
                if train_result is not None
                else {}
            ) or {}

            preprocessing_summary = (
                _safe_detail_value(getattr(train_result, "preprocessing_summary", {}))
                if train_result is not None
                else {}
            ) or {}

            artifacts = _build_artifacts(train_result, service, label_summary, opts)

            observation_time = _ensure_utc(req.observation_time)

            metadata = {
                "train_model_version": TRAIN_MODEL_VERSION,
                "mode": mode.value,
                "requested_mode": _mode_value(req.mode) if req.mode is not None else None,
                "input_fingerprint": input_fp,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "observation_time": observation_time.isoformat() if observation_time else None,
                "request_metadata": _safe_detail_value(req.metadata),
                "training_result_fingerprint": (
                    _clean_text(getattr(train_result, "fingerprint", ""), 128)
                    if train_result is not None
                    else None
                ),
                "registered": False,
                "registry_backend": "process_local_in_memory",
                "registry_durable": False,
                "registry_distributed": False,
                "caveats": list(_TRAIN_CAVEATS),
                "safety_flags": dict(_TRAIN_SAFETY_FLAGS),
            }

            return TrainingJobResult(
                job_id=resolved_job_id,
                status=status,
                mode=mode,
                kind=_normalize_token(kind) or mode.value,
                model_id=_clean_text(model_id, 128),
                created_at=started_at,
                finished_at=_now_utc(),
                duration_ms=int((time.monotonic() - started_mono) * 1000.0),
                phases=tuple(phases),
                metrics=metrics,
                governance=governance,
                split_summary=split_summary,
                preprocessing_summary=preprocessing_summary,
                label_summary=label_summary,
                artifacts=artifacts,
                issues=tuple(issues),
                metadata=metadata,
                fingerprint="",
            )

        def register_and_finalize(result: TrainingJobResult) -> TrainingJobResult:
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

            success_phases = list(phases)
            success_phases.append(
                TrainingPhaseRecord(
                    phase=TrainingPhase.REGISTER_JOB,
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
            final_ok = result.status == JobStatus.SUCCEEDED and not _has_error(issues)

            success_phases.append(
                TrainingPhaseRecord(
                    phase=TrainingPhase.FINALIZE,
                    started_at=finalize_dt,
                    finished_at=_now_utc(),
                    duration_ms=int((time.monotonic() - finalize_mono) * 1000.0),
                    ok=final_ok,
                    issue_count=0,
                    details={"final_status": result.status.value},
                )
            )

            success_metadata = dict(result.metadata)
            success_metadata.update(
                {
                    "registered": registered,
                    "registry_backend": "process_local_in_memory",
                    "registry_durable": False,
                    "registry_distributed": False,
                }
            )

            candidate = replace(
                result,
                phases=tuple(success_phases),
                finished_at=_now_utc(),
                duration_ms=int((time.monotonic() - started_mono) * 1000.0),
                metadata=success_metadata,
                fingerprint="",
            )

            if not opts.register_jobs:
                return candidate

            try:
                get_train_job_registry(opts.max_jobs).register(candidate, service=service)
                return candidate
            except Exception as exc:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="training_job_registration_failed",
                    message="Training job registration failed.",
                    details={"exception_type": type(exc).__name__},
                )

                failure_phases = list(phases)
                failure_phases.append(
                    TrainingPhaseRecord(
                        phase=TrainingPhase.REGISTER_JOB,
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
                    TrainingPhaseRecord(
                        phase=TrainingPhase.FINALIZE,
                        started_at=failure_finalize_dt,
                        finished_at=_now_utc(),
                        duration_ms=int((time.monotonic() - failure_finalize_mono) * 1000.0),
                        ok=False,
                        issue_count=0,
                        details={"final_status": JobStatus.FAILED.value},
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
                    status=JobStatus.FAILED,
                    phases=tuple(failure_phases),
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

        policy_status = JobStatus.SUCCEEDED

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="training_disabled",
                message="Training harness is disabled.",
            )
            policy_status = JobStatus.BLOCKED

        elif opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Training harness requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            policy_status = JobStatus.BLOCKED

        elif opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Training harness is blocked in production-like environments.",
            )
            policy_status = JobStatus.BLOCKED

        else:
            if not _scan_labels(req.labels, opts, issues):
                policy_status = JobStatus.FAILED

            raw_records = _iter_records(req.features)

            if not raw_records:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="empty_feature_input",
                    message="Training feature input is empty.",
                )
                policy_status = JobStatus.FAILED
            else:
                if len(raw_records) > opts.max_records:
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="training_input_truncated",
                        message="Training input exceeded configured record limit and was truncated.",
                        details={
                            "submitted": len(raw_records),
                            "max_records": opts.max_records,
                        },
                    )
                    raw_records = raw_records[: opts.max_records]

                cleaned = _clean_training_records(raw_records, opts, issues)

                if cleaned is None:
                    policy_status = JobStatus.FAILED
                else:
                    if req.feature_names:
                        cleaned = _filter_records_feature_names(
                            cleaned,
                            req.feature_names,
                            opts,
                            issues,
                        )

                        if not cleaned:
                            _append_issue(
                                issues,
                                opts.max_issues,
                                severity=IssueSeverity.ERROR,
                                code="no_records_after_feature_filter",
                                message="No training records remained after requested feature filtering.",
                            )
                            policy_status = JobStatus.FAILED

                    if policy_status == JobStatus.SUCCEEDED:
                        label_summary = _label_summary(req.labels)
                        input_fp = _input_fingerprint(cleaned, req.labels)

                        if req.job_id:
                            job_id = req.job_id
                        elif req.idempotency_key:
                            job_id = _sha256_hex(
                                f"{opts.namespace}|{req.idempotency_key}|{input_fp}"
                            )[:32]
                        else:
                            job_id = _derive_job_id(req, opts, mode, input_fp)

        validation_ok = policy_status == JobStatus.SUCCEEDED and not _has_error(issues)
        feature_count = len(_records_feature_names(cleaned)) if cleaned else 0

        phases.append(
            _phase_record(
                phase=TrainingPhase.VALIDATE_INPUTS,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=validation_ok,
                issue_base=issue_base,
                issues=issues,
                details={
                    "policy_status": policy_status.value,
                    "record_count": len(cleaned or []),
                    "feature_count": feature_count,
                    "label_summary": label_summary,
                    "input_fingerprint": input_fp,
                    "job_id": job_id,
                    "mode": mode.value,
                },
            )
        )

        if policy_status != JobStatus.SUCCEEDED or _has_error(issues):
            return register_and_finalize(
                make_result(
                    status=policy_status if policy_status != JobStatus.SUCCEEDED else JobStatus.FAILED,
                    kind=mode.value,
                    model_id="",
                )
            )

        # ------------------------------------------------------------------
        # Phase: build request
        # ------------------------------------------------------------------

        phase_mono = time.monotonic()
        phase_dt = _now_utc()
        issue_base = len(issues)

        phases.append(
            _phase_record(
                phase=TrainingPhase.BUILD_REQUEST,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=True,
                issue_base=issue_base,
                issues=issues,
                details={
                    "mode": mode.value,
                    "record_count": len(cleaned or []),
                    "feature_count": feature_count,
                    "job_id": job_id,
                    "input_fingerprint": input_fp,
                },
            )
        )

        # ------------------------------------------------------------------
        # Phase: train model
        # ------------------------------------------------------------------

        phase_mono = time.monotonic()
        phase_dt = _now_utc()
        issue_base = len(issues)

        if mode == TrainingMode.FALLBACK:
            train_status = JobStatus.SUCCEEDED
            kind = TrainingMode.FALLBACK.value
            model_id = ""
        else:
            train_result, service = _call_model_service_train(
                req,
                cleaned or [],
                opts,
                None,
                issues,
            )

            if train_result is None:
                train_status = JobStatus.FAILED
                kind = mode.value
                model_id = ""
            else:
                train_status = _job_status(train_result)
                kind = _kind_from_result(train_result) or mode.value
                model_id = _clean_text(getattr(train_result, "model_id", ""), 128)

        phases.append(
            _phase_record(
                phase=TrainingPhase.TRAIN_MODEL,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=train_status == JobStatus.SUCCEEDED,
                issue_base=issue_base,
                issues=issues,
                details={
                    "status": train_status.value,
                    "kind": kind,
                    "model_id": model_id,
                    "mode": mode.value,
                },
            )
        )

        if train_status != JobStatus.SUCCEEDED:
            return register_and_finalize(make_result(train_status, kind, model_id))

        # ------------------------------------------------------------------
        # Phase: evaluate model
        # ------------------------------------------------------------------

        phase_mono = time.monotonic()
        phase_dt = _now_utc()
        issue_base = len(issues)

        if mode == TrainingMode.FALLBACK:
            eval_ok = True
            eval_details = {"evaluation_required": False}
        else:
            governance = _extract_governance(train_result, opts)
            metrics = _extract_metrics(train_result, opts)
            gov_ok = bool(governance.get("ok", True)) if isinstance(governance, Mapping) else True
            eval_ok = gov_ok and not _has_error(issues)
            eval_details = {
                "governance_ok": gov_ok,
                "metrics_available": bool(metrics),
            }

        eval_status = JobStatus.SUCCEEDED if eval_ok else JobStatus.FAILED

        phases.append(
            _phase_record(
                phase=TrainingPhase.EVALUATE_MODEL,
                started_mono=phase_mono,
                started_dt=phase_dt,
                ok=eval_ok,
                issue_base=issue_base,
                issues=issues,
                details=eval_details,
            )
        )

        return register_and_finalize(make_result(eval_status, kind, model_id))

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
            "registry": get_train_job_registry(self.options.max_jobs).safe_summary(
                limit=self.options.max_summary_items
            ),
            "caveats": list(_TRAIN_CAVEATS),
            "safety_flags": dict(_TRAIN_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default harness and public API
# -----------------------------------------------------------------------------


_default_harness: Optional[TrainModelHarness] = None
_default_harness_lock = threading.Lock()


def get_train_model_harness(
    options: TrainModelOptions | None = None,
    *,
    rebuild: bool = False,
) -> TrainModelHarness:
    """
    Return a process-wide training harness.

    If options are supplied or rebuild is True, a new harness is created and
    becomes the default.
    """
    global _default_harness

    with _default_harness_lock:
        if _default_harness is None or rebuild or options is not None:
            _default_harness = TrainModelHarness(options=options or TrainModelOptions.from_settings())

        return _default_harness


def run_training_job(
    request: Any,
    options: TrainModelOptions | None = None,
    *,
    harness: TrainModelHarness | None = None,
) -> TrainingJobResult:
    """
    Run one bounded synthetic training job.
    """
    active_harness = harness or get_train_model_harness(options)
    return active_harness.run(request)


def train_model(
    request: Any,
    options: TrainModelOptions | None = None,
    *,
    harness: TrainModelHarness | None = None,
) -> TrainingJobResult:
    """
    Convenience alias for `run_training_job`.
    """
    return run_training_job(request, options=options, harness=harness)


def get_training_job(job_id: Any) -> Optional[TrainingJobResult]:
    """
    Return one registered training job result.
    """
    return get_train_job_registry().get_result(job_id)


def get_training_job_service(job_id: Any) -> Any:
    """
    Return the process-local model service associated with one training job,
    when available.
    """
    return get_train_job_registry().get_service(job_id)


def list_training_jobs(*, limit: int = 50) -> tuple[TrainingJobResult, ...]:
    """
    Return registered training job results.
    """
    return get_train_job_registry().list_results(limit=limit)


def summarize_training_jobs(*, limit: int = 50) -> list[dict[str, Any]]:
    """
    Return safe registered training job summaries.
    """
    return get_train_job_registry().summarize(limit=limit)


def get_train_model_metadata() -> dict[str, Any]:
    """
    Return safe, serializable training harness metadata.

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
    options = TrainModelOptions.from_settings()
    registry = get_train_job_registry(options.max_jobs)

    return {
        "package": "muleguard.backend.ml.train_model",
        "version": TRAIN_MODEL_VERSION,
        "modes": [mode.value for mode in TrainingMode],
        "job_statuses": [status.value for status in JobStatus],
        "training_phases": [phase.value for phase in TrainingPhase],
        "artifact_kinds": [kind.value for kind in ArtifactKind],
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
            "max_phases": _HARD_MAX_PHASES,
            "max_artifacts": _HARD_MAX_ARTIFACTS,
            "max_jobs": _HARD_MAX_JOBS,
        },
        "forbidden_train_field_count": len(_FORBIDDEN_TRAIN_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_TRAIN_CAVEATS),
        "safety_flags": dict(_TRAIN_SAFETY_FLAGS),
    }


__all__ = [
    "ArtifactKind",
    "ArtifactSummary",
    "IssueSeverity",
    "JobStatus",
    "TrainModelHarness",
    "TrainModelOptions",
    "TrainingIssue",
    "TrainingJobRegistry",
    "TrainingJobRequest",
    "TrainingJobResult",
    "TrainingMode",
    "TrainingPhase",
    "TrainingPhaseRecord",
    "get_train_job_registry",
    "get_train_model_harness",
    "get_train_model_metadata",
    "get_training_job",
    "get_training_job_service",
    "list_training_jobs",
    "run_training_job",
    "summarize_training_jobs",
    "train_model",
]