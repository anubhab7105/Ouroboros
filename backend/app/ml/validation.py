"""
MULEGUARD backend ML validation.

This module provides the canonical bounded validation orchestration layer for
the synthetic MULEGUARD machine-learning subsystem.

Primary responsibilities:

- validate synthetic ML feature records, schemas, labels, splits, predictions,
  model artefact metadata, privacy posture, leakage posture, duplication,
  distribution drift, and pipeline consistency before training, evaluation,
  explanation, inference, or developer-tooling use;
- provide deterministic, bounded, API-safe validation reports with explicit
  check results, issue reporting, fingerprints, aggregate statistics, and safe
  summaries;
- enforce strict leakage resistance by rejecting ground-truth labels, injected
  scenario IDs, fraud-ring IDs, raw complaint narratives, raw identifiers,
  secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths when they appear as feature inputs;
- preserve privacy by using salted one-way pseudonymous subject hashes, by
  detecting likely PII/secret/free-text feature values without retaining raw
  values, and by excluding raw feature values, subject-label pairs, and
  sensitive metadata from public summaries;
- validate feature schemas, types, ranges, cardinality, missingness, category
  concentration, entropy, duplicates, label coverage, split isolation,
  prediction bounds, model metadata, and bounded distribution drift;
- remain import-safe, dependency-light, and resilient when optional ML
  submodules are unavailable.

This module validates synthetic ML artefacts only. It does not train models,
deploy models, evaluate models as authoritative truth, persist data, call
external systems, authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for validation, training, evaluation, or
  inference.
- Validation outputs are operational quality gates only. They are not proof of
  wrongdoing.
- Model probabilities, anomaly scores, fallback scores, and validation metrics
  are investigative prioritization artefacts only. They are not probabilities of
  guilt.
- Feature contributions and feature importance are operational attributions
  only. They are not causal proof.
- Labels must never be used as features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone feature inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden feature inputs. Subject linkage is pseudonymous
  and salted.
- Validation handling never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable validations are reported honestly as unavailable or
  skipped rather than invented.
- The bundled validation registry is process-local, non-durable, and bounded for
  local prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external model runtimes.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models.
- This module does not generate synthetic ingestion records.
- This module does not replace ingestion validation.
- This module does not replace feature schema authoring; it validates and
  infers bounded schemas for synthetic ML workflows.
- This module is not a durable data quality platform.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, explanations,
validation reports, and case dispositions are investigative leads or human
workflow artefacts only. They are not proof of wrongdoing and must not trigger
automatic adverse customer action.
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
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError

logger = logging.getLogger("muleguard.backend.ml.validation")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

VALIDATION_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.validation.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_RECORDS: Final[int] = 10_000
_HARD_MAX_RECORDS: Final[int] = 100_000

_DEFAULT_MAX_FEATURES: Final[int] = 512
_HARD_MAX_FEATURES: Final[int] = 4_096

_DEFAULT_MAX_CELLS: Final[int] = 5_000_000
_HARD_MAX_CELLS: Final[int] = 100_000_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_CHECKS: Final[int] = 250
_HARD_MAX_CHECKS: Final[int] = 2_000

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_CATEGORIES: Final[int] = 1_000
_HARD_MAX_CATEGORIES: Final[int] = 10_000

_DEFAULT_MAX_NUMERIC_SAMPLE: Final[int] = 5_000
_HARD_MAX_NUMERIC_SAMPLE: Final[int] = 20_000

_DEFAULT_MAX_DISTINCT_TRACKED: Final[int] = 10_000
_HARD_MAX_DISTINCT_TRACKED: Final[int] = 100_000

_DEFAULT_MAX_REPORTS: Final[int] = 1_000
_HARD_MAX_REPORTS: Final[int] = 10_000

_DEFAULT_MAX_TIME_MS: Final[int] = 30_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_DEFAULT_THRESHOLD: Final[float] = 0.50

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_PHONE_IN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\+?91[\s-]?)?[6-9]\d{9}"
)
_PAN_RE: Final[re.Pattern[str]] = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_AADHAAR_RE: Final[re.Pattern[str]] = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
_UPI_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9.\-_]{2,128}@[A-Za-z]{2,64}\b"
)
_IPV4_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
_IFSC_RE: Final[re.Pattern[str]] = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
_CARD_DIGITS_RE: Final[re.Pattern[str]] = re.compile(r"\b\d{13,19}\b")
_SECRET_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|bearer|private[_-]?key)\b\s*[:=]?\s*\S+"
)

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
        "index",
        "source_index",
        "split",
        "weight",
        "label",
        "label_code",
        "target",
        "y",
        "prediction",
        "predictions",
        "score",
        "probability",
        "positive_probability",
        "risk_score",
        "anomaly_score",
        "predicted_label",
        "y_pred",
    }
)

_FORBIDDEN_VALIDATION_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_VALIDATION_TOKENS: Final[tuple[str, ...]] = (
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

_DEFAULT_ALLOWED_LABEL_CODES: Final[tuple[int, ...]] = (0, 1, 2, 3, 4)
_DEFAULT_POSITIVE_LABEL_CODES: Final[tuple[int, ...]] = (2, 3)
_DEFAULT_NEGATIVE_LABEL_CODES: Final[tuple[int, ...]] = (1,)
_DEFAULT_IGNORE_LABEL_CODES: Final[tuple[int, ...]] = (0,)

_VALIDATION_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML validation only. Do not use with real customer data.",
    "Validation reports are operational quality gates only and are not proof of wrongdoing.",
    "Model, anomaly, fallback, and validation scores are not probabilities of guilt.",
    "Feature statistics and schema inference are operational diagnostics only and are not causal proof.",
    "Validation must not trigger automatic adverse customer action.",
    "Labels must never be used as features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected as features.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Unavailable validations are reported honestly as skipped or unavailable rather than invented.",
    "The bundled validation registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_VALIDATION_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_validation": True,
        "bounded_validation_required": True,
        "validation_is_operational_quality_gate_only": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class FeatureType(str, Enum):
    """
    Bounded feature datatype.
    """

    NUMERIC = "numeric"
    BOOLEAN = "boolean"
    CATEGORICAL = "categorical"
    HASH = "hash"
    TEXT = "text"
    UNKNOWN = "unknown"


class DatasetRole(str, Enum):
    """
    Dataset role for validation policy.
    """

    UNKNOWN = "unknown"
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    INFERENCE = "inference"
    FIXTURE = "fixture"


class PolicyAction(str, Enum):
    """
    Policy action for validation findings.
    """

    ALLOW = "allow"
    WARN = "warn"
    DROP = "drop"
    REJECT = "reject"


class ValidationStatus(str, Enum):
    """
    Overall validation report status.
    """

    PASSED = "PASSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


class CheckStatus(str, Enum):
    """
    Individual check status.
    """

    PASS = "PASS"
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


class ValidationCategory(str, Enum):
    """
    Validation check category.
    """

    POLICY = "policy"
    SCHEMA = "schema"
    PRIVACY = "privacy"
    LEAKAGE = "leakage"
    COMPLETENESS = "completeness"
    VALIDITY = "validity"
    CONSISTENCY = "consistency"
    DISTRIBUTION = "distribution"
    DUPLICATES = "duplicates"
    LABELS = "labels"
    SPLITS = "splits"
    PREDICTIONS = "predictions"
    MODEL = "model"
    DRIFT = "drift"
    FINALIZE = "finalize"


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

    if canonical in _FORBIDDEN_VALIDATION_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_VALIDATION_TOKENS)


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


def _enum_value(value: Any, default: str = "") -> str:
    return _clean_text(getattr(value, "value", value), 128) or default


def _policy_action(value: Any, default: PolicyAction) -> PolicyAction:
    return _normalize_enum_option(PolicyAction, value, default)


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


def _subject_hash(value: Any, options: "ValidationOptions") -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.validation.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _fingerprint_payload(payload: Any) -> str:
    try:
        return _sha256_hex(_canonical_json(payload))
    except Exception:
        return _sha256_hex(str(_safe_detail_value(payload)))


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


def _median(values: Sequence[float]) -> float:
    if not values:
        return 0.0

    ordered = sorted(float(value) for value in values)
    mid = len(ordered) // 2

    if len(ordered) % 2 == 1:
        return ordered[mid]

    return (ordered[mid - 1] + ordered[mid]) / 2.0


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


def _time_exceeded(start_time: float, max_time_ms: int) -> bool:
    return (time.monotonic() - start_time) * 1000.0 > float(max(1, int(max_time_ms)))


def _elapsed_ms(start_time: float) -> int:
    return int((time.monotonic() - start_time) * 1000.0)


def _luhn_valid(digits: str) -> bool:
    if not digits or not digits.isdigit():
        return False

    total = 0
    reverse = digits[::-1]

    for index, char in enumerate(reverse):
        value = ord(char) - 48

        if index % 2 == 1:
            value *= 2

            if value > 9:
                value -= 9

        total += value

    return total % 10 == 0


def _append_issue(
    issues: list["ValidationIssue"],
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

        issues[-1] = ValidationIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        ValidationIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _has_error(issues: Sequence[ValidationIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _record_check(
    checks: list["ValidationCheck"],
    issues: list[ValidationIssue],
    options: "ValidationOptions",
    *,
    category: ValidationCategory | str,
    status: CheckStatus | str,
    message: str,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
    issue_code: Optional[str] = None,
    issue_severity: Optional[IssueSeverity] = None,
) -> None:
    """
    Record one bounded validation check and optionally one issue.
    """
    resolved_category = _normalize_enum_option(
        ValidationCategory,
        category,
        ValidationCategory.FINALIZE,
    )
    resolved_status = _normalize_enum_option(CheckStatus, status, CheckStatus.INFO)

    limit = max(1, int(options.max_checks))

    if len(checks) >= limit:
        if checks and checks[-1].check_id.endswith("truncated"):
            return

        checks[-1] = ValidationCheck(
            check_id=_sha256_hex(f"check_truncated|{len(checks)}")[:16] + "_truncated",
            category=ValidationCategory.FINALIZE,
            status=CheckStatus.WARN,
            message="Check list truncated by configured limit.",
        )
    else:
        check_id = _sha256_hex(
            _canonical_json(
                {
                    "category": resolved_category.value,
                    "status": resolved_status.value,
                    "field": field,
                    "message": message,
                    "index": len(checks),
                }
            )
        )[:16]

        checks.append(
            ValidationCheck(
                check_id=check_id,
                category=resolved_category,
                status=resolved_status,
                message=_clean_text(message, 300),
                field=_clean_text(field, 200) if field else None,
                details=_safe_details(details),
            )
        )

    if issue_severity is None:
        if resolved_status == CheckStatus.FAIL:
            issue_severity = IssueSeverity.ERROR
        elif resolved_status == CheckStatus.WARN:
            issue_severity = IssueSeverity.WARNING
        else:
            issue_severity = None

    if issue_severity is not None:
        _append_issue(
            issues,
            options.max_issues,
            severity=issue_severity,
            code=issue_code or f"{resolved_category.value}_{resolved_status.value.lower()}",
            message=_clean_text(message, 300),
            field=field,
            details=details,
        )


# -----------------------------------------------------------------------------
# Core models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """
    Safe validation issue.

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
class ValidationCheck:
    """
    One bounded validation check result.
    """

    check_id: str
    category: ValidationCategory
    status: CheckStatus
    message: str
    field: Optional[str] = None
    details: dict[str, Any] = dataclass_field(default_factory=dict)
    occurred_at: datetime = dataclass_field(default_factory=_now_utc)

    def __post_init__(self) -> None:
        object.__setattr__(self, "check_id", _clean_text(self.check_id, 64))
        object.__setattr__(
            self,
            "category",
            _normalize_enum_option(ValidationCategory, self.category, ValidationCategory.FINALIZE),
        )
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(CheckStatus, self.status, CheckStatus.INFO),
        )
        object.__setattr__(self, "message", _clean_text(self.message, 300))
        object.__setattr__(
            self,
            "field",
            _clean_text(self.field, 200) if self.field else None,
        )
        object.__setattr__(self, "details", _safe_details(self.details))
        object.__setattr__(self, "occurred_at", _ensure_utc(self.occurred_at) or _now_utc())

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "category": self.category.value,
            "status": self.status.value,
            "message": self.message,
            "field": self.field,
            "details": self.details,
            "occurred_at": self.occurred_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class FeatureSchema:
    """
    One bounded feature schema definition.
    """

    name: str
    dtype: FeatureType | str = FeatureType.UNKNOWN
    nullable: bool = True
    required: bool = False
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    allowed_values: tuple[str, ...] = ()
    privacy_sensitive: bool = False
    leakage_sensitive: bool = False
    description: str = ""
    source: str = "inferred"
    unit: str = ""
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _canonical_field_name(self.name))
        object.__setattr__(
            self,
            "dtype",
            _normalize_enum_option(FeatureType, self.dtype, FeatureType.UNKNOWN),
        )
        object.__setattr__(self, "nullable", _as_bool(self.nullable, True))
        object.__setattr__(self, "required", _as_bool(self.required, False))

        if self.min_value is not None:
            object.__setattr__(self, "min_value", _round6(_as_float(self.min_value, 0.0)))

        if self.max_value is not None:
            object.__setattr__(self, "max_value", _round6(_as_float(self.max_value, 0.0)))

        object.__setattr__(
            self,
            "allowed_values",
            tuple(
                dict.fromkeys(
                    _normalize_token(value)
                    for value in (self.allowed_values or ())
                    if _normalize_token(value)
                )
            ),
        )
        object.__setattr__(self, "privacy_sensitive", _as_bool(self.privacy_sensitive, False))
        object.__setattr__(self, "leakage_sensitive", _as_bool(self.leakage_sensitive, False))
        object.__setattr__(self, "description", _clean_text(self.description, 300))
        object.__setattr__(self, "source", _clean_text(self.source, 64) or "inferred")
        object.__setattr__(self, "unit", _clean_text(self.unit, 64))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dtype": self.dtype.value,
            "nullable": bool(self.nullable),
            "required": bool(self.required),
            "min_value": float(self.min_value) if self.min_value is not None else None,
            "max_value": float(self.max_value) if self.max_value is not None else None,
            "allowed_values": list(self.allowed_values),
            "privacy_sensitive": bool(self.privacy_sensitive),
            "leakage_sensitive": bool(self.leakage_sensitive),
            "description": self.description,
            "source": self.source,
            "unit": self.unit,
            "metadata": _safe_detail_value(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ValidationOptions:
    """
    Bounded ML validation policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    dataset_role: DatasetRole | str = DatasetRole.UNKNOWN

    missing_policy: PolicyAction | str = PolicyAction.WARN
    type_policy: PolicyAction | str = PolicyAction.WARN
    range_policy: PolicyAction | str = PolicyAction.WARN
    category_policy: PolicyAction | str = PolicyAction.WARN
    unknown_feature_policy: PolicyAction | str = PolicyAction.WARN
    duplicate_policy: PolicyAction | str = PolicyAction.WARN
    privacy_policy: PolicyAction | str = PolicyAction.REJECT
    leakage_policy: PolicyAction | str = PolicyAction.REJECT
    target_copy_policy: PolicyAction | str = PolicyAction.WARN
    prediction_policy: PolicyAction | str = PolicyAction.WARN
    model_policy: PolicyAction | str = PolicyAction.WARN
    drift_policy: PolicyAction | str = PolicyAction.WARN
    split_policy: PolicyAction | str = PolicyAction.WARN

    max_missing_rate: float = 0.50
    min_nonmissing_rate: float = 0.50
    max_duplicate_rate: float = 0.05
    max_cardinality: int = _DEFAULT_MAX_CATEGORIES
    rare_category_share: float = 0.001
    top_category_share_limit: float = 0.95
    entropy_floor: float = 0.10
    hhi_ceiling: float = 0.95

    score_min: float = 0.0
    score_max: float = 1.0
    max_extreme_score_rate: float = 0.25

    min_label_coverage: float = 0.80
    min_train_samples: int = 20
    min_validation_samples: int = 5
    min_test_samples: int = 5
    min_class_support: int = 3
    max_class_imbalance_ratio: float = 100.0

    drift_warn: float = 0.10
    drift_fail: float = 0.25

    allowed_label_codes: tuple[int, ...] = _DEFAULT_ALLOWED_LABEL_CODES
    positive_label_codes: tuple[int, ...] = _DEFAULT_POSITIVE_LABEL_CODES
    negative_label_codes: tuple[int, ...] = _DEFAULT_NEGATIVE_LABEL_CODES
    ignore_label_codes: tuple[int, ...] = _DEFAULT_IGNORE_LABEL_CODES

    threshold: float = _DEFAULT_THRESHOLD

    max_records: int = _DEFAULT_MAX_RECORDS
    max_features: int = _DEFAULT_MAX_FEATURES
    max_cells: int = _DEFAULT_MAX_CELLS
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_checks: int = _DEFAULT_MAX_CHECKS
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_categories: int = _DEFAULT_MAX_CATEGORIES
    max_numeric_sample: int = _DEFAULT_MAX_NUMERIC_SAMPLE
    max_distinct_tracked: int = _DEFAULT_MAX_DISTINCT_TRACKED
    max_reports: int = _DEFAULT_MAX_REPORTS
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    include_stats: bool = True
    include_drift: bool = True
    include_duplicates: bool = True
    include_privacy_scan: bool = True
    include_target_copy_scan: bool = True
    infer_schema: bool = True
    strict_schema: bool = False
    register_reports: bool = True
    drop_forbidden_fields: bool = False

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
            "dataset_role",
            _normalize_enum_option(DatasetRole, self.dataset_role, DatasetRole.UNKNOWN),
        )

        object.__setattr__(self, "missing_policy", _policy_action(self.missing_policy, PolicyAction.WARN))
        object.__setattr__(self, "type_policy", _policy_action(self.type_policy, PolicyAction.WARN))
        object.__setattr__(self, "range_policy", _policy_action(self.range_policy, PolicyAction.WARN))
        object.__setattr__(self, "category_policy", _policy_action(self.category_policy, PolicyAction.WARN))
        object.__setattr__(
            self,
            "unknown_feature_policy",
            _policy_action(self.unknown_feature_policy, PolicyAction.WARN),
        )
        object.__setattr__(self, "duplicate_policy", _policy_action(self.duplicate_policy, PolicyAction.WARN))
        object.__setattr__(self, "privacy_policy", _policy_action(self.privacy_policy, PolicyAction.REJECT))
        object.__setattr__(self, "leakage_policy", _policy_action(self.leakage_policy, PolicyAction.REJECT))
        object.__setattr__(self, "target_copy_policy", _policy_action(self.target_copy_policy, PolicyAction.WARN))
        object.__setattr__(self, "prediction_policy", _policy_action(self.prediction_policy, PolicyAction.WARN))
        object.__setattr__(self, "model_policy", _policy_action(self.model_policy, PolicyAction.WARN))
        object.__setattr__(self, "drift_policy", _policy_action(self.drift_policy, PolicyAction.WARN))
        object.__setattr__(self, "split_policy", _policy_action(self.split_policy, PolicyAction.WARN))

        object.__setattr__(self, "max_missing_rate", _clamp_float(self.max_missing_rate, 0.0, 1.0, 0.50))
        object.__setattr__(self, "min_nonmissing_rate", _clamp_float(self.min_nonmissing_rate, 0.0, 1.0, 0.50))
        object.__setattr__(self, "max_duplicate_rate", _clamp_float(self.max_duplicate_rate, 0.0, 1.0, 0.05))
        object.__setattr__(self, "rare_category_share", _clamp_float(self.rare_category_share, 0.0, 1.0, 0.001))
        object.__setattr__(self, "top_category_share_limit", _clamp_float(self.top_category_share_limit, 0.0, 1.0, 0.95))
        object.__setattr__(self, "entropy_floor", _clamp_float(self.entropy_floor, 0.0, 1.0, 0.10))
        object.__setattr__(self, "hhi_ceiling", _clamp_float(self.hhi_ceiling, 0.0, 1.0, 0.95))

        object.__setattr__(self, "score_min", _clamp_float(self.score_min, -1e12, 1e12, 0.0))
        object.__setattr__(self, "score_max", _clamp_float(self.score_max, -1e12, 1e12, 1.0))

        if self.score_max < self.score_min:
            object.__setattr__(self, "score_max", self.score_min)

        object.__setattr__(self, "max_extreme_score_rate", _clamp_float(self.max_extreme_score_rate, 0.0, 1.0, 0.25))
        object.__setattr__(self, "min_label_coverage", _clamp_float(self.min_label_coverage, 0.0, 1.0, 0.80))
        object.__setattr__(self, "min_train_samples", max(0, _as_int(self.min_train_samples, 20)))
        object.__setattr__(self, "min_validation_samples", max(0, _as_int(self.min_validation_samples, 5)))
        object.__setattr__(self, "min_test_samples", max(0, _as_int(self.min_test_samples, 5)))
        object.__setattr__(self, "min_class_support", max(0, _as_int(self.min_class_support, 3)))
        object.__setattr__(self, "max_class_imbalance_ratio", max(1.0, _as_float(self.max_class_imbalance_ratio, 100.0)))
        object.__setattr__(self, "drift_warn", _clamp_float(self.drift_warn, 0.0, 10.0, 0.10))
        object.__setattr__(self, "drift_fail", max(self.drift_warn, _clamp_float(self.drift_fail, 0.0, 10.0, 0.25)))
        object.__setattr__(self, "threshold", _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD))

        object.__setattr__(self, "allowed_label_codes", _coerce_int_tuple(self.allowed_label_codes, _DEFAULT_ALLOWED_LABEL_CODES))
        object.__setattr__(self, "positive_label_codes", _coerce_int_tuple(self.positive_label_codes, _DEFAULT_POSITIVE_LABEL_CODES))
        object.__setattr__(self, "negative_label_codes", _coerce_int_tuple(self.negative_label_codes, _DEFAULT_NEGATIVE_LABEL_CODES))
        object.__setattr__(self, "ignore_label_codes", _coerce_int_tuple(self.ignore_label_codes, _DEFAULT_IGNORE_LABEL_CODES))

        object.__setattr__(self, "max_records", _clamp_int(self.max_records, 1, _HARD_MAX_RECORDS, _DEFAULT_MAX_RECORDS))
        object.__setattr__(self, "max_features", _clamp_int(self.max_features, 1, _HARD_MAX_FEATURES, _DEFAULT_MAX_FEATURES))
        object.__setattr__(self, "max_cells", _clamp_int(self.max_cells, 1, _HARD_MAX_CELLS, _DEFAULT_MAX_CELLS))
        object.__setattr__(self, "max_issues", _clamp_int(self.max_issues, 1, _HARD_MAX_ISSUES, _DEFAULT_MAX_ISSUES))
        object.__setattr__(self, "max_checks", _clamp_int(self.max_checks, 1, _HARD_MAX_CHECKS, _DEFAULT_MAX_CHECKS))
        object.__setattr__(
            self,
            "max_summary_items",
            _clamp_int(self.max_summary_items, 1, _HARD_MAX_SUMMARY_ITEMS, _DEFAULT_MAX_SUMMARY_ITEMS),
        )
        object.__setattr__(self, "max_categories", _clamp_int(self.max_categories, 1, _HARD_MAX_CATEGORIES, _DEFAULT_MAX_CATEGORIES))
        object.__setattr__(
            self,
            "max_numeric_sample",
            _clamp_int(self.max_numeric_sample, 2, _HARD_MAX_NUMERIC_SAMPLE, _DEFAULT_MAX_NUMERIC_SAMPLE),
        )
        object.__setattr__(
            self,
            "max_distinct_tracked",
            _clamp_int(self.max_distinct_tracked, 1, _HARD_MAX_DISTINCT_TRACKED, _DEFAULT_MAX_DISTINCT_TRACKED),
        )
        object.__setattr__(self, "max_reports", _clamp_int(self.max_reports, 1, _HARD_MAX_REPORTS, _DEFAULT_MAX_REPORTS))
        object.__setattr__(self, "max_time_ms", _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS))

        object.__setattr__(self, "include_stats", _as_bool(self.include_stats, True))
        object.__setattr__(self, "include_drift", _as_bool(self.include_drift, True))
        object.__setattr__(self, "include_duplicates", _as_bool(self.include_duplicates, True))
        object.__setattr__(self, "include_privacy_scan", _as_bool(self.include_privacy_scan, True))
        object.__setattr__(self, "include_target_copy_scan", _as_bool(self.include_target_copy_scan, True))
        object.__setattr__(self, "infer_schema", _as_bool(self.infer_schema, True))
        object.__setattr__(self, "strict_schema", _as_bool(self.strict_schema, False))
        object.__setattr__(self, "register_reports", _as_bool(self.register_reports, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ValidationOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_VALIDATION_SALT", None)
            or _setting(settings, "ML_EXPLAIN_SALT", None)
            or _setting(settings, "ML_EVALUATE_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_VALIDATION_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_VALIDATION_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_VALIDATION_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_VALIDATION_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_VALIDATION_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            dataset_role=str(_setting(settings, "ML_VALIDATION_DATASET_ROLE", DatasetRole.UNKNOWN.value)),
            missing_policy=str(_setting(settings, "ML_VALIDATION_MISSING_POLICY", PolicyAction.WARN.value)),
            type_policy=str(_setting(settings, "ML_VALIDATION_TYPE_POLICY", PolicyAction.WARN.value)),
            range_policy=str(_setting(settings, "ML_VALIDATION_RANGE_POLICY", PolicyAction.WARN.value)),
            category_policy=str(_setting(settings, "ML_VALIDATION_CATEGORY_POLICY", PolicyAction.WARN.value)),
            unknown_feature_policy=str(
                _setting(settings, "ML_VALIDATION_UNKNOWN_FEATURE_POLICY", PolicyAction.WARN.value)
            ),
            duplicate_policy=str(_setting(settings, "ML_VALIDATION_DUPLICATE_POLICY", PolicyAction.WARN.value)),
            privacy_policy=str(_setting(settings, "ML_VALIDATION_PRIVACY_POLICY", PolicyAction.REJECT.value)),
            leakage_policy=str(_setting(settings, "ML_VALIDATION_LEAKAGE_POLICY", PolicyAction.REJECT.value)),
            target_copy_policy=str(
                _setting(settings, "ML_VALIDATION_TARGET_COPY_POLICY", PolicyAction.WARN.value)
            ),
            prediction_policy=str(_setting(settings, "ML_VALIDATION_PREDICTION_POLICY", PolicyAction.WARN.value)),
            model_policy=str(_setting(settings, "ML_VALIDATION_MODEL_POLICY", PolicyAction.WARN.value)),
            drift_policy=str(_setting(settings, "ML_VALIDATION_DRIFT_POLICY", PolicyAction.WARN.value)),
            split_policy=str(_setting(settings, "ML_VALIDATION_SPLIT_POLICY", PolicyAction.WARN.value)),
            max_missing_rate=_as_float(_setting(settings, "ML_VALIDATION_MAX_MISSING_RATE", 0.50), 0.50),
            min_nonmissing_rate=_as_float(_setting(settings, "ML_VALIDATION_MIN_NONMISSING_RATE", 0.50), 0.50),
            max_duplicate_rate=_as_float(_setting(settings, "ML_VALIDATION_MAX_DUPLICATE_RATE", 0.05), 0.05),
            max_cardinality=_as_int(_setting(settings, "ML_VALIDATION_MAX_CARDINALITY", _DEFAULT_MAX_CATEGORIES), _DEFAULT_MAX_CATEGORIES),
            rare_category_share=_as_float(_setting(settings, "ML_VALIDATION_RARE_CATEGORY_SHARE", 0.001), 0.001),
            top_category_share_limit=_as_float(_setting(settings, "ML_VALIDATION_TOP_CATEGORY_SHARE_LIMIT", 0.95), 0.95),
            entropy_floor=_as_float(_setting(settings, "ML_VALIDATION_ENTROPY_FLOOR", 0.10), 0.10),
            hhi_ceiling=_as_float(_setting(settings, "ML_VALIDATION_HHI_CEILING", 0.95), 0.95),
            score_min=_as_float(_setting(settings, "ML_VALIDATION_SCORE_MIN", 0.0), 0.0),
            score_max=_as_float(_setting(settings, "ML_VALIDATION_SCORE_MAX", 1.0), 1.0),
            max_extreme_score_rate=_as_float(
                _setting(settings, "ML_VALIDATION_MAX_EXTREME_SCORE_RATE", 0.25),
                0.25,
            ),
            min_label_coverage=_as_float(_setting(settings, "ML_VALIDATION_MIN_LABEL_COVERAGE", 0.80), 0.80),
            min_train_samples=_as_int(_setting(settings, "ML_VALIDATION_MIN_TRAIN_SAMPLES", 20), 20),
            min_validation_samples=_as_int(_setting(settings, "ML_VALIDATION_MIN_VALIDATION_SAMPLES", 5), 5),
            min_test_samples=_as_int(_setting(settings, "ML_VALIDATION_MIN_TEST_SAMPLES", 5), 5),
            min_class_support=_as_int(_setting(settings, "ML_VALIDATION_MIN_CLASS_SUPPORT", 3), 3),
            max_class_imbalance_ratio=_as_float(
                _setting(settings, "ML_VALIDATION_MAX_CLASS_IMBALANCE_RATIO", 100.0),
                100.0,
            ),
            drift_warn=_as_float(_setting(settings, "ML_VALIDATION_DRIFT_WARN", 0.10), 0.10),
            drift_fail=_as_float(_setting(settings, "ML_VALIDATION_DRIFT_FAIL", 0.25), 0.25),
            allowed_label_codes=_coerce_int_tuple(
                _setting(settings, "ML_VALIDATION_ALLOWED_LABEL_CODES", None),
                _DEFAULT_ALLOWED_LABEL_CODES,
            ),
            positive_label_codes=_coerce_int_tuple(
                _setting(settings, "ML_VALIDATION_POSITIVE_LABEL_CODES", None),
                _DEFAULT_POSITIVE_LABEL_CODES,
            ),
            negative_label_codes=_coerce_int_tuple(
                _setting(settings, "ML_VALIDATION_NEGATIVE_LABEL_CODES", None),
                _DEFAULT_NEGATIVE_LABEL_CODES,
            ),
            ignore_label_codes=_coerce_int_tuple(
                _setting(settings, "ML_VALIDATION_IGNORE_LABEL_CODES", None),
                _DEFAULT_IGNORE_LABEL_CODES,
            ),
            threshold=_as_float(_setting(settings, "ML_VALIDATION_THRESHOLD", _DEFAULT_THRESHOLD), _DEFAULT_THRESHOLD),
            max_records=_as_int(_setting(settings, "ML_VALIDATION_MAX_RECORDS", _DEFAULT_MAX_RECORDS), _DEFAULT_MAX_RECORDS),
            max_features=_as_int(_setting(settings, "ML_VALIDATION_MAX_FEATURES", _DEFAULT_MAX_FEATURES), _DEFAULT_MAX_FEATURES),
            max_cells=_as_int(_setting(settings, "ML_VALIDATION_MAX_CELLS", _DEFAULT_MAX_CELLS), _DEFAULT_MAX_CELLS),
            max_issues=_as_int(_setting(settings, "ML_VALIDATION_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_checks=_as_int(_setting(settings, "ML_VALIDATION_MAX_CHECKS", _DEFAULT_MAX_CHECKS), _DEFAULT_MAX_CHECKS),
            max_summary_items=_as_int(
                _setting(settings, "ML_VALIDATION_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_categories=_as_int(
                _setting(settings, "ML_VALIDATION_MAX_CATEGORIES", _DEFAULT_MAX_CATEGORIES),
                _DEFAULT_MAX_CATEGORIES,
            ),
            max_numeric_sample=_as_int(
                _setting(settings, "ML_VALIDATION_MAX_NUMERIC_SAMPLE", _DEFAULT_MAX_NUMERIC_SAMPLE),
                _DEFAULT_MAX_NUMERIC_SAMPLE,
            ),
            max_reports=_as_int(_setting(settings, "ML_VALIDATION_MAX_REPORTS", _DEFAULT_MAX_REPORTS), _DEFAULT_MAX_REPORTS),
            max_time_ms=_as_int(_setting(settings, "ML_VALIDATION_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS), _DEFAULT_MAX_TIME_MS),
            include_stats=_as_bool(_setting(settings, "ML_VALIDATION_INCLUDE_STATS", True), True),
            include_drift=_as_bool(_setting(settings, "ML_VALIDATION_INCLUDE_DRIFT", True), True),
            include_duplicates=_as_bool(_setting(settings, "ML_VALIDATION_INCLUDE_DUPLICATES", True), True),
            include_privacy_scan=_as_bool(_setting(settings, "ML_VALIDATION_INCLUDE_PRIVACY_SCAN", True), True),
            include_target_copy_scan=_as_bool(
                _setting(settings, "ML_VALIDATION_INCLUDE_TARGET_COPY_SCAN", True),
                True,
            ),
            infer_schema=_as_bool(_setting(settings, "ML_VALIDATION_INFER_SCHEMA", True), True),
            strict_schema=_as_bool(_setting(settings, "ML_VALIDATION_STRICT_SCHEMA", False), False),
            register_reports=_as_bool(_setting(settings, "ML_VALIDATION_REGISTER_REPORTS", True), True),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ML_VALIDATION_DROP_FORBIDDEN_FIELDS", False),
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
            "dataset_role": self.dataset_role.value if isinstance(self.dataset_role, DatasetRole) else str(self.dataset_role),
            "policies": {
                "missing": self.missing_policy.value,
                "type": self.type_policy.value,
                "range": self.range_policy.value,
                "category": self.category_policy.value,
                "unknown_feature": self.unknown_feature_policy.value,
                "duplicate": self.duplicate_policy.value,
                "privacy": self.privacy_policy.value,
                "leakage": self.leakage_policy.value,
                "target_copy": self.target_copy_policy.value,
                "prediction": self.prediction_policy.value,
                "model": self.model_policy.value,
                "drift": self.drift_policy.value,
                "split": self.split_policy.value,
            },
            "thresholds": {
                "max_missing_rate": round(self.max_missing_rate, 6),
                "min_nonmissing_rate": round(self.min_nonmissing_rate, 6),
                "max_duplicate_rate": round(self.max_duplicate_rate, 6),
                "max_cardinality": self.max_cardinality,
                "rare_category_share": round(self.rare_category_share, 6),
                "top_category_share_limit": round(self.top_category_share_limit, 6),
                "entropy_floor": round(self.entropy_floor, 6),
                "hhi_ceiling": round(self.hhi_ceiling, 6),
                "score_min": round(self.score_min, 6),
                "score_max": round(self.score_max, 6),
                "max_extreme_score_rate": round(self.max_extreme_score_rate, 6),
                "min_label_coverage": round(self.min_label_coverage, 6),
                "min_train_samples": self.min_train_samples,
                "min_validation_samples": self.min_validation_samples,
                "min_test_samples": self.min_test_samples,
                "min_class_support": self.min_class_support,
                "max_class_imbalance_ratio": round(self.max_class_imbalance_ratio, 6),
                "drift_warn": round(self.drift_warn, 6),
                "drift_fail": round(self.drift_fail, 6),
                "threshold": round(self.threshold, 6),
            },
            "label_codes": {
                "allowed": list(self.allowed_label_codes),
                "positive": list(self.positive_label_codes),
                "negative": list(self.negative_label_codes),
                "ignore": list(self.ignore_label_codes),
            },
            "limits": {
                "max_records": self.max_records,
                "max_features": self.max_features,
                "max_cells": self.max_cells,
                "max_issues": self.max_issues,
                "max_checks": self.max_checks,
                "max_summary_items": self.max_summary_items,
                "max_categories": self.max_categories,
                "max_numeric_sample": self.max_numeric_sample,
                "max_distinct_tracked": self.max_distinct_tracked,
                "max_reports": self.max_reports,
                "max_time_ms": self.max_time_ms,
            },
            "flags": {
                "include_stats": self.include_stats,
                "include_drift": self.include_drift,
                "include_duplicates": self.include_duplicates,
                "include_privacy_scan": self.include_privacy_scan,
                "include_target_copy_scan": self.include_target_copy_scan,
                "infer_schema": self.infer_schema,
                "strict_schema": self.strict_schema,
                "register_reports": self.register_reports,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
        }


@dataclass(slots=True)
class ValidationRequest:
    """
    Bounded ML validation request.
    """

    features: Any = None
    labels: Any = None
    predictions: Any = None
    model: Any = None
    schema: Any = None
    reference_profile: Any = None
    split_map: Any = None
    dataset_role: DatasetRole | str | None = None
    threshold: Optional[float] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.dataset_role = (
            _normalize_enum_option(DatasetRole, self.dataset_role, None)
            if self.dataset_role is not None
            else None
        )

        if self.threshold is not None:
            self.threshold = _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)

        self.metadata = _safe_detail_value(self.metadata) or {}
        self.tags = tuple(
            dict.fromkeys(
                _clean_text(tag, 100)
                for tag in (self.tags or ())
                if _clean_text(tag, 100)
            )
        )
        self.request_id = _clean_text(self.request_id, 128) if self.request_id else None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) if self.idempotency_key else None


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """
    Safe ML validation report.

    Public summaries deliberately exclude raw feature values, subject-label
    pairs, raw identifiers, raw narratives, secrets, tokens, passwords, database
    URLs, filesystem paths, and model artifact paths.
    """

    ok: bool = True
    status: ValidationStatus = ValidationStatus.PASSED
    request_id: str = ""
    dataset_role: DatasetRole = DatasetRole.UNKNOWN
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    checks: tuple[ValidationCheck, ...] = ()
    issues: tuple[ValidationIssue, ...] = ()
    schema_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    feature_stats: Mapping[str, Any] = dataclass_field(default_factory=dict)
    label_stats: Mapping[str, Any] = dataclass_field(default_factory=dict)
    split_stats: Mapping[str, Any] = dataclass_field(default_factory=dict)
    prediction_stats: Mapping[str, Any] = dataclass_field(default_factory=dict)
    privacy: Mapping[str, Any] = dataclass_field(default_factory=dict)
    leakage: Mapping[str, Any] = dataclass_field(default_factory=dict)
    duplicates: Mapping[str, Any] = dataclass_field(default_factory=dict)
    drift: Mapping[str, Any] = dataclass_field(default_factory=dict)
    model_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(ValidationStatus, self.status, ValidationStatus.PASSED),
        )
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(
            self,
            "dataset_role",
            _normalize_enum_option(DatasetRole, self.dataset_role, DatasetRole.UNKNOWN),
        )
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "counts", MappingProxyType({str(k): max(0, _as_int(v, 0)) for k, v in (self.counts or {}).items()}))
        object.__setattr__(self, "checks", tuple(self.checks or ()))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "schema_summary", MappingProxyType(_safe_detail_value(self.schema_summary) or {}))
        object.__setattr__(self, "feature_stats", MappingProxyType(_safe_detail_value(self.feature_stats) or {}))
        object.__setattr__(self, "label_stats", MappingProxyType(_safe_detail_value(self.label_stats) or {}))
        object.__setattr__(self, "split_stats", MappingProxyType(_safe_detail_value(self.split_stats) or {}))
        object.__setattr__(self, "prediction_stats", MappingProxyType(_safe_detail_value(self.prediction_stats) or {}))
        object.__setattr__(self, "privacy", MappingProxyType(_safe_detail_value(self.privacy) or {}))
        object.__setattr__(self, "leakage", MappingProxyType(_safe_detail_value(self.leakage) or {}))
        object.__setattr__(self, "duplicates", MappingProxyType(_safe_detail_value(self.duplicates) or {}))
        object.__setattr__(self, "drift", MappingProxyType(_safe_detail_value(self.drift) or {}))
        object.__setattr__(self, "model_summary", MappingProxyType(_safe_detail_value(self.model_summary) or {}))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": VALIDATION_VERSION,
                        "ok": self.ok,
                        "status": self.status.value,
                        "request_id": self.request_id,
                        "dataset_role": self.dataset_role.value,
                        "counts": self.counts,
                        "checks": [check.to_dict() for check in self.checks],
                        "issues": [issue.to_dict() for issue in self.issues],
                        "schema_summary": self.schema_summary,
                        "label_stats": self.label_stats,
                        "split_stats": self.split_stats,
                        "prediction_stats": self.prediction_stats,
                        "privacy": self.privacy,
                        "leakage": self.leakage,
                        "duplicates": self.duplicates,
                        "drift": self.drift,
                        "model_summary": self.model_summary,
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status.value,
            "request_id": self.request_id,
            "dataset_role": self.dataset_role.value,
            "generated_at": self.generated_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "counts": dict(self.counts),
            "checks": [check.to_dict() for check in self.checks],
            "issues": [issue.to_dict() for issue in self.issues],
            "schema_summary": _safe_detail_value(self.schema_summary),
            "feature_stats": _safe_detail_value(self.feature_stats),
            "label_stats": _safe_detail_value(self.label_stats),
            "split_stats": _safe_detail_value(self.split_stats),
            "prediction_stats": _safe_detail_value(self.prediction_stats),
            "privacy": _safe_detail_value(self.privacy),
            "leakage": _safe_detail_value(self.leakage),
            "duplicates": _safe_detail_value(self.duplicates),
            "drift": _safe_detail_value(self.drift),
            "model_summary": _safe_detail_value(self.model_summary),
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_VALIDATION_CAVEATS),
            "safety_flags": dict(_VALIDATION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local validation registry
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _RegisteredValidationReport:
    report: ValidationReport
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class ValidationRegistry:
    """
    Bounded process-local validation report registry.

    This registry is not durable, not distributed, and not production-ready.
    It exists only to support local prototype workflows, tests, and developer
    tooling.
    """

    def __init__(self, max_reports: int = _DEFAULT_MAX_REPORTS) -> None:
        self.max_reports = max(1, int(max_reports))
        self._reports: dict[str, _RegisteredValidationReport] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, report: ValidationReport) -> str:
        """
        Register one validation report and return its request id.
        """
        with self._lock:
            request_id = _clean_text(report.request_id, 128)

            if not request_id:
                request_id = report.fingerprint[:32] or _sha256_hex(str(len(self._reports) + 1))[:32]

            if request_id in self._reports:
                self._reports[request_id] = _RegisteredValidationReport(
                    report=report,
                    registered_at=_now_utc(),
                )
                return request_id

            self._reports[request_id] = _RegisteredValidationReport(
                report=report,
                registered_at=_now_utc(),
            )
            self._order.append(request_id)

            if len(self._order) > self.max_reports:
                evict_id = self._order.pop(0)
                self._reports.pop(evict_id, None)

            return request_id

    def get_report(self, request_id: Any) -> Optional[ValidationReport]:
        """
        Return one registered validation report.
        """
        key = _clean_text(request_id, 128)

        with self._lock:
            entry = self._reports.get(key)
            return entry.report if entry is not None else None

    def list_reports(self, *, limit: int = 50) -> tuple[ValidationReport, ...]:
        """
        Return registered validation reports in insertion order.
        """
        with self._lock:
            out: list[ValidationReport] = []

            for request_id in self._order[: max(1, int(limit))]:
                entry = self._reports.get(request_id)

                if entry is not None:
                    out.append(entry.report)

            return tuple(out)

    def summarize(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """
        Return safe registry summaries.
        """
        with self._lock:
            out: list[dict[str, Any]] = []

            for request_id in self._order[: max(1, int(limit))]:
                entry = self._reports.get(request_id)

                if entry is None:
                    continue

                report = entry.report

                out.append(
                    {
                        "request_id": report.request_id,
                        "status": report.status.value,
                        "dataset_role": report.dataset_role.value,
                        "generated_at": report.generated_at.isoformat(),
                        "duration_ms": int(report.duration_ms),
                        "fingerprint": report.fingerprint,
                        "issue_count": len(report.issues),
                        "check_count": len(report.checks),
                        "counts": dict(report.counts),
                    }
                )

            return out

    def clear(self) -> None:
        """
        Clear the process-local registry.
        """
        with self._lock:
            self._reports.clear()
            self._order.clear()

    def safe_summary(self, *, limit: int = 50) -> dict[str, Any]:
        """
        Return safe registry summary.
        """
        with self._lock:
            status_counter = Counter(entry.report.status.value for entry in self._reports.values())
            role_counter = Counter(entry.report.dataset_role.value for entry in self._reports.values())

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_reports": self.max_reports,
            "registered_reports": len(self._order),
            "by_status": dict(status_counter),
            "by_dataset_role": dict(role_counter),
            "recent": self.summarize(limit=limit),
        }


_default_registry: Optional[ValidationRegistry] = None
_default_registry_lock = threading.Lock()


def get_validation_registry(
    max_reports: int | None = None,
    *,
    rebuild: bool = False,
) -> ValidationRegistry:
    """
    Return the process-wide validation registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = ValidationRegistry(
                max_reports=max_reports if max_reports is not None else _DEFAULT_MAX_REPORTS
            )

        return _default_registry


# -----------------------------------------------------------------------------
# Input extraction helpers
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "features",
        "labels",
        "predictions",
        "model",
        "schema",
        "reference_profile",
        "split_map",
        "dataset_role",
        "threshold",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


def _coerce_request(request: Any) -> ValidationRequest:
    if isinstance(request, ValidationRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if "features" not in payload:
            for key in ("records", "rows", "items", "examples", "vectors"):
                if key in payload:
                    payload["features"] = payload[key]
                    break

        if any(key in payload for key in _REQUEST_KEYS):
            clean = {key: value for key, value in payload.items() if key in _REQUEST_KEYS}

            try:
                return ValidationRequest(**clean)
            except Exception:
                return ValidationRequest(features=payload.get("features", request))

        return ValidationRequest(features=request)

    if hasattr(request, "features"):
        try:
            return ValidationRequest(features=getattr(request, "features"))
        except Exception:
            pass

    return ValidationRequest(features=request)


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, ValidationReport):
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


def _extract_subject(record: Any, options: ValidationOptions) -> Optional[str]:
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


def _subject_from_mapping(mapping: Mapping[Any, Any]) -> Any:
    for key in _SUBJECT_KEYS:
        if key in mapping:
            return mapping[key]

    return None


def _label_code_from_mapping(mapping: Mapping[Any, Any]) -> Any:
    for key in ("label_code", "label", "target", "y", "synthetic_label"):
        if key in mapping:
            return mapping[key]

    return None


# -----------------------------------------------------------------------------
# Value classification and normalization
# -----------------------------------------------------------------------------


def _classify_value(value: Any) -> tuple[FeatureType, Any]:
    if value is None:
        return FeatureType.UNKNOWN, None

    if isinstance(value, str) and not value.strip():
        return FeatureType.UNKNOWN, None

    if isinstance(value, bool):
        return FeatureType.BOOLEAN, value

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return FeatureType.NUMERIC, normalized.timestamp() if normalized else None

    numeric = _coerce_optional_float(value, allow_bool=False)

    if numeric is not None:
        return FeatureType.NUMERIC, _round6(numeric)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return FeatureType.TEXT, f"<binary:{len(value)} bytes>"

    text = _clean_text(value, 1000)

    if not text:
        return FeatureType.UNKNOWN, None

    if _is_safe_hash(text):
        return FeatureType.HASH, text.lower()

    if len(text) > 200 and text.count(" ") >= 10:
        return FeatureType.TEXT, text

    token = _normalize_token(text)

    if token:
        return FeatureType.CATEGORICAL, token

    return FeatureType.CATEGORICAL, text


def _normalize_value_for_type(value: Any, dtype: FeatureType) -> tuple[FeatureType, Any, bool]:
    """
    Return (resolved_type, normalized_value, valid).
    """
    kind, normalized = _classify_value(value)

    if normalized is None:
        return kind, None, False

    if dtype == FeatureType.NUMERIC:
        numeric = _coerce_optional_float(value, allow_bool=True)

        if numeric is None:
            return kind, normalized, False

        return FeatureType.NUMERIC, _round6(numeric), True

    if dtype == FeatureType.BOOLEAN:
        parsed = _coerce_bool(value)

        if parsed is None:
            return kind, normalized, False

        return FeatureType.BOOLEAN, parsed, True

    if dtype == FeatureType.CATEGORICAL:
        if kind == FeatureType.NUMERIC:
            return FeatureType.CATEGORICAL, str(normalized), True

        if kind in {FeatureType.CATEGORICAL, FeatureType.HASH, FeatureType.TEXT}:
            return FeatureType.CATEGORICAL, str(normalized), True

        return kind, normalized, False

    if dtype == FeatureType.HASH:
        text = _clean_text(value, 256)

        if _is_safe_hash(text):
            return FeatureType.HASH, text.lower(), True

        return kind, normalized, False

    if dtype == FeatureType.TEXT:
        return FeatureType.TEXT, "", True

    return kind, normalized, True


def _safe_row_payload(features: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}

    for key, value in sorted(features.items()):
        if value is None:
            out[key] = None
        elif isinstance(value, bool):
            out[key] = value
        elif isinstance(value, (int, float)):
            out[key] = _round6(float(value))
        else:
            out[key] = _normalize_token(value) or _clean_text(value, 128)

    return out


def _row_fingerprint(
    features: Mapping[str, Any],
    options: ValidationOptions,
    row_index: int,
) -> str:
    payload = _safe_row_payload(features)
    domain = f"muleguard.ml.validation.row.{_normalize_token(options.namespace)}"
    message = _canonical_json(payload)
    return _hmac_hex(options.salt, domain, f"{row_index}\x00{message}")[:32]


# -----------------------------------------------------------------------------
# Privacy scanning
# -----------------------------------------------------------------------------


def _scan_string_for_privacy(value: Any, feature: str) -> list[str]:
    if not isinstance(value, str):
        return []

    text = _clean_text(value, 2000)

    if not text:
        return []

    detectors: list[str] = []

    if _EMAIL_RE.search(text):
        detectors.append("email_or_upi_like")
    elif _UPI_RE.search(text):
        detectors.append("upi_like")

    if _PHONE_IN_RE.search(text):
        detectors.append("phone_like")

    if _PAN_RE.search(text):
        detectors.append("pan_like")

    if _AADHAAR_RE.search(text):
        detectors.append("aadhaar_like")

    if _IPV4_RE.search(text):
        detectors.append("ipv4_like")

    if _IFSC_RE.search(text):
        detectors.append("ifsc_like")

    if _SECRET_ASSIGNMENT_RE.search(text):
        detectors.append("secret_assignment_like")

    for candidate in _CARD_DIGITS_RE.findall(text):
        if _luhn_valid(candidate):
            detectors.append("card_like")
            break

    if len(text) > 200 and text.count(" ") >= 10:
        detectors.append("free_text_like")

    return tuple(dict.fromkeys(detectors))


# -----------------------------------------------------------------------------
# Schema helpers
# -----------------------------------------------------------------------------


def _schema_hint(feature: str) -> Optional[FeatureSchema]:
    name = _canonical_field_name(feature)

    if not name:
        return None

    tokens = name.split("_")
    last = tokens[-1] if tokens else ""

    if last in {"flag", "bool", "boolean"} or name.startswith("is_") or name.startswith("has_"):
        return FeatureSchema(
            name=name,
            dtype=FeatureType.BOOLEAN,
            nullable=True,
            source="hint",
            description="Boolean-like synthetic flag.",
        )

    if any(token in tokens for token in ("score", "probability", "confidence", "anomaly_score", "risk_score")):
        return FeatureSchema(
            name=name,
            dtype=FeatureType.NUMERIC,
            min_value=0.0,
            max_value=1.0,
            nullable=True,
            source="hint",
            description="Bounded synthetic score.",
        )

    if any(token in tokens for token in ("share", "ratio", "pct", "percentage", "hhi")):
        return FeatureSchema(
            name=name,
            dtype=FeatureType.NUMERIC,
            min_value=0.0,
            max_value=1.0,
            nullable=True,
            source="hint",
            description="Bounded synthetic share or ratio.",
        )

    if any(token in tokens for token in ("entropy",)):
        return FeatureSchema(
            name=name,
            dtype=FeatureType.NUMERIC,
            min_value=0.0,
            nullable=True,
            source="hint",
            description="Non-negative synthetic entropy.",
        )

    if any(token in tokens for token in ("count", "amount", "sum", "max", "min", "days", "hours", "minutes", "seconds", "degree", "path_count", "link_count", "distinct_count", "velocity", "burstiness")):
        return FeatureSchema(
            name=name,
            dtype=FeatureType.NUMERIC,
            min_value=0.0,
            nullable=True,
            source="hint",
            description="Non-negative synthetic count or amount.",
        )

    if last == "hash" or name.endswith("_hash"):
        return FeatureSchema(
            name=name,
            dtype=FeatureType.HASH,
            nullable=True,
            source="hint",
            description="Pseudonymous hash-like synthetic field.",
        )

    return None


def _infer_schema_from_records(
    records: Sequence[Any],
    options: ValidationOptions,
) -> dict[str, FeatureSchema]:
    schemas: dict[str, FeatureSchema] = {}
    observed: dict[str, dict[str, Any]] = {}

    for record in records:
        features = _extract_feature_mapping(record)

        for raw_key, raw_value in features.items():
            feature = _canonical_field_name(raw_key)

            if not feature:
                continue

            if feature in _SUBJECT_KEYS or feature in _NON_FEATURE_KEYS:
                continue

            state = observed.setdefault(
                feature,
                {
                    "types": Counter(),
                    "missing": 0,
                    "nonmissing": 0,
                    "numeric_min": None,
                    "numeric_max": None,
                    "categories": set(),
                    "category_truncated": False,
                },
            )

            if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
                state["missing"] += 1
                continue

            state["nonmissing"] += 1
            kind, normalized = _classify_value(raw_value)
            state["types"][kind.value] += 1

            if kind == FeatureType.NUMERIC and normalized is not None:
                value = float(normalized)

                if state["numeric_min"] is None or value < float(state["numeric_min"]):
                    state["numeric_min"] = value

                if state["numeric_max"] is None or value > float(state["numeric_max"]):
                    state["numeric_max"] = value

            elif kind in {FeatureType.CATEGORICAL, FeatureType.HASH, FeatureType.TEXT}:
                if len(state["categories"]) < options.max_distinct_tracked:
                    state["categories"].add(str(normalized))
                else:
                    state["category_truncated"] = True

    for feature, state in observed.items():
        hint = _schema_hint(feature)
        types: Counter[str] = state["types"]
        dominant = types.most_common(1)[0][0] if types else FeatureType.UNKNOWN.value

        if hint is not None and hint.dtype.value != FeatureType.UNKNOWN.value:
            dtype = hint.dtype
        elif dominant == FeatureType.NUMERIC.value and types[FeatureType.CATEGORICAL.value] == 0:
            dtype = FeatureType.NUMERIC
        elif dominant == FeatureType.BOOLEAN.value:
            dtype = FeatureType.BOOLEAN
        elif dominant == FeatureType.HASH.value:
            dtype = FeatureType.HASH
        elif dominant == FeatureType.TEXT.value:
            dtype = FeatureType.TEXT
        else:
            dtype = FeatureType.CATEGORICAL

        min_value = hint.min_value if hint is not None else None
        max_value = hint.max_value if hint is not None else None

        if dtype == FeatureType.NUMERIC:
            if state["numeric_min"] is not None:
                observed_min = _round6(float(state["numeric_min"]))

                if min_value is None:
                    min_value = observed_min
                else:
                    min_value = min(float(min_value), observed_min)

            if state["numeric_max"] is not None:
                observed_max = _round6(float(state["numeric_max"]))

                if max_value is None:
                    max_value = observed_max
                else:
                    max_value = max(float(max_value), observed_max)

        allowed_values: tuple[str, ...] = ()

        if dtype in {FeatureType.CATEGORICAL, FeatureType.HASH} and not state["category_truncated"]:
            allowed_values = tuple(sorted(str(item) for item in state["categories"]))

        schemas[feature] = FeatureSchema(
            name=feature,
            dtype=dtype,
            nullable=int(state["missing"]) > 0,
            required=False,
            min_value=min_value,
            max_value=max_value,
            allowed_values=allowed_values,
            privacy_sensitive=hint.privacy_sensitive if hint is not None else False,
            leakage_sensitive=_is_label_leakage_key(feature) or _is_forbidden_key(feature),
            description=hint.description if hint is not None else "",
            source="inferred",
            unit=hint.unit if hint is not None else "",
            metadata={
                "observed_missing": int(state["missing"]),
                "observed_nonmissing": int(state["nonmissing"]),
                "observed_types": dict(types),
                "category_truncated": bool(state["category_truncated"]),
            },
        )

    return schemas


def _coerce_schema_item(item: Any) -> Optional[FeatureSchema]:
    if isinstance(item, FeatureSchema):
        return item

    if isinstance(item, Mapping):
        try:
            return FeatureSchema(**item)
        except Exception:
            return None

    feature = _canonical_field_name(item)

    if feature:
        return FeatureSchema(name=feature, source="explicit")

    return None


def _resolve_schema(
    explicit_schema: Any,
    records: Sequence[Any],
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> dict[str, FeatureSchema]:
    schemas: dict[str, FeatureSchema] = {}

    if explicit_schema is not None:
        for item in _as_sequence(explicit_schema):
            schema = _coerce_schema_item(item)

            if schema is not None and schema.name:
                schemas[schema.name] = schema

        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.SCHEMA,
            status=CheckStatus.PASS,
            message="Explicit feature schema provided.",
            details={"schema_count": len(schemas)},
        )

    if options.infer_schema:
        inferred = _infer_schema_from_records(records, options)

        for feature, schema in inferred.items():
            if feature not in schemas:
                schemas[feature] = schema
            elif options.strict_schema:
                continue
            else:
                existing = schemas[feature]
                merged = replace(
                    existing,
                    dtype=existing.dtype if existing.dtype != FeatureType.UNKNOWN else schema.dtype,
                    nullable=existing.nullable or schema.nullable,
                    min_value=existing.min_value if existing.min_value is not None else schema.min_value,
                    max_value=existing.max_value if existing.max_value is not None else schema.max_value,
                    allowed_values=existing.allowed_values or schema.allowed_values,
                    leakage_sensitive=existing.leakage_sensitive or schema.leakage_sensitive,
                    source=f"{existing.source}+{schema.source}",
                    metadata={**dict(existing.metadata), **{"inferred": schema.metadata}},
                )
                schemas[feature] = merged

        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.SCHEMA,
            status=CheckStatus.PASS,
            message="Feature schema inference completed.",
            details={"schema_count": len(schemas)},
        )

    if not schemas:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.SCHEMA,
            status=CheckStatus.WARN,
            message="No feature schema could be resolved.",
            issue_code="schema_unavailable",
        )

    if len(schemas) > options.max_features:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.SCHEMA,
            status=CheckStatus.WARN,
            message="Feature schema count exceeded configured limit and was truncated.",
            details={"schema_count": len(schemas), "max_features": options.max_features},
            issue_code="schema_limit_applied",
        )
        schemas = dict(sorted(schemas.items())[: options.max_features])

    return schemas


def _schema_summary(schemas: Mapping[str, FeatureSchema], options: ValidationOptions) -> dict[str, Any]:
    dtype_counter = Counter(schema.dtype.value for schema in schemas.values())
    names = sorted(schemas)

    return {
        "feature_count": len(schemas),
        "dtype_counts": dict(dtype_counter),
        "feature_names_sample": names[: options.max_summary_items],
        "feature_names_truncated": len(names) > options.max_summary_items,
        "required_count": sum(1 for schema in schemas.values() if schema.required),
        "nullable_count": sum(1 for schema in schemas.values() if schema.nullable),
        "privacy_sensitive_count": sum(1 for schema in schemas.values() if schema.privacy_sensitive),
        "leakage_sensitive_count": sum(1 for schema in schemas.values() if schema.leakage_sensitive),
        "schemas": [
            schema.to_dict()
            for schema in list(schemas.values())[: options.max_summary_items]
        ],
        "schemas_truncated": len(schemas) > options.max_summary_items,
    }


# -----------------------------------------------------------------------------
# Record validation and normalization
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _CellCounts:
    total: int = 0
    missing: int = 0
    invalid_type: int = 0
    out_of_range: int = 0
    invalid_category: int = 0
    privacy_flags: int = 0
    leakage_flags: int = 0
    unknown_features: int = 0
    dropped_cells: int = 0
    rejected_records: int = 0


def _validate_and_normalize_records(
    raw_records: Sequence[Any],
    schemas: Mapping[str, FeatureSchema],
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> tuple[list[dict[str, Any]], _CellCounts]:
    cleaned: list[dict[str, Any]] = []
    counts = _CellCounts()
    seen_subjects: set[str] = set()
    schema_keys = set(schemas)

    for source_index, record in enumerate(raw_records):
        if _time_exceeded(time.monotonic(), options.max_time_ms):
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.POLICY,
                status=CheckStatus.WARN,
                message="Record validation stopped after reaching configured time budget.",
                details={"processed": len(cleaned), "remaining": max(0, len(raw_records) - source_index)},
                issue_code="validation_time_budget_exhausted",
            )
            break

        subject = _extract_subject(record, options)
        features = _extract_feature_mapping(record)
        clean_features: dict[str, Any] = {}
        reject_record = False

        if subject:
            if subject in seen_subjects:
                _record_check(
                    checks,
                    issues,
                    options,
                    category=ValidationCategory.DUPLICATES,
                    status=CheckStatus.INFO,
                    message="Duplicate subject reference detected in validation input.",
                    field="subject_ref_hash",
                    details={"source_index": source_index},
                )
            else:
                seen_subjects.add(subject)

        for raw_key, raw_value in features.items():
            key_text = _clean_text(raw_key, 200)
            feature = _canonical_field_name(key_text)

            if not feature:
                _record_check(
                    checks,
                    issues,
                    options,
                    category=ValidationCategory.SCHEMA,
                    status=CheckStatus.WARN,
                    message="Feature name could not be canonicalized and was omitted.",
                    field=key_text or None,
                    details={"source_index": source_index},
                    issue_code="invalid_feature_name",
                )
                continue

            if feature in _SUBJECT_KEYS or feature in _NON_FEATURE_KEYS:
                continue

            counts.total += 1

            if _is_forbidden_key(feature) or _is_label_leakage_key(feature):
                counts.leakage_flags += 1

                if options.leakage_policy == PolicyAction.REJECT:
                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.LEAKAGE,
                        status=CheckStatus.FAIL,
                        message="Forbidden or label-like feature field rejected.",
                        field=key_text,
                        details={"source_index": source_index},
                        issue_code="forbidden_feature",
                    )
                    reject_record = True
                    break

                if options.leakage_policy == PolicyAction.DROP or options.drop_forbidden_fields:
                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.LEAKAGE,
                        status=CheckStatus.WARN,
                        message="Forbidden or label-like feature field dropped.",
                        field=key_text,
                        details={"source_index": source_index},
                        issue_code="forbidden_feature_dropped",
                    )
                    counts.dropped_cells += 1
                    continue

                _record_check(
                    checks,
                    issues,
                    options,
                    category=ValidationCategory.LEAKAGE,
                    status=CheckStatus.WARN,
                    message="Forbidden or label-like feature field detected but allowed by policy.",
                    field=key_text,
                    details={"source_index": source_index},
                    issue_code="forbidden_feature_allowed",
                )

            if feature not in schema_keys:
                counts.unknown_features += 1

                if options.unknown_feature_policy == PolicyAction.REJECT:
                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.SCHEMA,
                        status=CheckStatus.FAIL,
                        message="Unknown feature rejected by strict schema policy.",
                        field=key_text,
                        details={"source_index": source_index},
                        issue_code="unknown_feature_rejected",
                    )
                    reject_record = True
                    break

                if options.unknown_feature_policy == PolicyAction.DROP:
                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.SCHEMA,
                        status=CheckStatus.INFO,
                        message="Unknown feature dropped.",
                        field=key_text,
                        details={"source_index": source_index},
                    )
                    counts.dropped_cells += 1
                    continue

            schema = schemas.get(feature)

            if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
                counts.missing += 1

                if schema is not None and schema.required:
                    if options.missing_policy == PolicyAction.REJECT:
                        _record_check(
                            checks,
                            issues,
                            options,
                            category=ValidationCategory.COMPLETENESS,
                            status=CheckStatus.FAIL,
                            message="Required feature missing.",
                            field=feature,
                            details={"source_index": source_index},
                            issue_code="required_feature_missing",
                        )
                        reject_record = True
                        break

                    if options.missing_policy == PolicyAction.DROP:
                        counts.dropped_cells += 1
                        continue

                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.COMPLETENESS,
                        status=CheckStatus.WARN,
                        message="Required feature missing.",
                        field=feature,
                        details={"source_index": source_index},
                        issue_code="required_feature_missing",
                    )

                if schema is not None and not schema.nullable:
                    if options.missing_policy in {PolicyAction.REJECT, PolicyAction.WARN}:
                        _record_check(
                            checks,
                            issues,
                            options,
                            category=ValidationCategory.COMPLETENESS,
                            status=CheckStatus.WARN if options.missing_policy != PolicyAction.REJECT else CheckStatus.FAIL,
                            message="Non-nullable feature missing.",
                            field=feature,
                            details={"source_index": source_index},
                            issue_code="non_nullable_feature_missing",
                        )

                        if options.missing_policy == PolicyAction.REJECT:
                            reject_record = True
                            break

                clean_features[feature] = None
                continue

            if options.include_privacy_scan:
                detectors = _scan_string_for_privacy(raw_value, feature)

                if detectors:
                    counts.privacy_flags += 1

                    if options.privacy_policy == PolicyAction.REJECT:
                        _record_check(
                            checks,
                            issues,
                            options,
                            category=ValidationCategory.PRIVACY,
                            status=CheckStatus.FAIL,
                            message="Likely PII, secret, or free-text feature value rejected.",
                            field=feature,
                            details={
                                "source_index": source_index,
                                "detectors": list(detectors),
                                "value_retained": False,
                            },
                            issue_code="privacy_sensitive_value",
                        )
                        reject_record = True
                        break

                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.PRIVACY,
                        status=CheckStatus.WARN,
                        message="Likely PII, secret, or free-text feature value detected and dropped.",
                        field=feature,
                        details={
                            "source_index": source_index,
                            "detectors": list(detectors),
                            "value_retained": False,
                        },
                        issue_code="privacy_sensitive_value_dropped",
                    )
                    counts.dropped_cells += 1
                    clean_features[feature] = None
                    continue

            dtype = schema.dtype if schema is not None else FeatureType.UNKNOWN
            resolved_type, normalized, valid = _normalize_value_for_type(raw_value, dtype)

            if not valid:
                counts.invalid_type += 1

                if options.type_policy == PolicyAction.REJECT:
                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.VALIDITY,
                        status=CheckStatus.FAIL,
                        message="Feature value type mismatch rejected.",
                        field=feature,
                        details={
                            "source_index": source_index,
                            "expected": dtype.value,
                            "observed": resolved_type.value,
                        },
                        issue_code="feature_type_mismatch",
                    )
                    reject_record = True
                    break

                if options.type_policy == PolicyAction.DROP:
                    counts.dropped_cells += 1
                    clean_features[feature] = None
                    continue

                _record_check(
                    checks,
                    issues,
                    options,
                    category=ValidationCategory.VALIDITY,
                    status=CheckStatus.WARN,
                    message="Feature value type mismatch.",
                    field=feature,
                    details={
                        "source_index": source_index,
                        "expected": dtype.value,
                        "observed": resolved_type.value,
                    },
                    issue_code="feature_type_mismatch",
                )

            if schema is not None and resolved_type == FeatureType.NUMERIC and normalized is not None:
                value = float(normalized)

                if schema.min_value is not None and value < float(schema.min_value):
                    counts.out_of_range += 1

                    if options.range_policy == PolicyAction.REJECT:
                        _record_check(
                            checks,
                            issues,
                            options,
                            category=ValidationCategory.VALIDITY,
                            status=CheckStatus.FAIL,
                            message="Numeric feature below minimum rejected.",
                            field=feature,
                            details={
                                "source_index": source_index,
                                "min_value": float(schema.min_value),
                            },
                            issue_code="feature_below_min",
                        )
                        reject_record = True
                        break

                    if options.range_policy == PolicyAction.DROP:
                        counts.dropped_cells += 1
                        clean_features[feature] = None
                        continue

                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.VALIDITY,
                        status=CheckStatus.WARN,
                        message="Numeric feature below minimum.",
                        field=feature,
                        details={
                            "source_index": source_index,
                            "min_value": float(schema.min_value),
                        },
                        issue_code="feature_below_min",
                    )

                if schema.max_value is not None and value > float(schema.max_value):
                    counts.out_of_range += 1

                    if options.range_policy == PolicyAction.REJECT:
                        _record_check(
                            checks,
                            issues,
                            options,
                            category=ValidationCategory.VALIDITY,
                            status=CheckStatus.FAIL,
                            message="Numeric feature above maximum rejected.",
                            field=feature,
                            details={
                                "source_index": source_index,
                                "max_value": float(schema.max_value),
                            },
                            issue_code="feature_above_max",
                        )
                        reject_record = True
                        break

                    if options.range_policy == PolicyAction.DROP:
                        counts.dropped_cells += 1
                        clean_features[feature] = None
                        continue

                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.VALIDITY,
                        status=CheckStatus.WARN,
                        message="Numeric feature above maximum.",
                        field=feature,
                        details={
                            "source_index": source_index,
                            "max_value": float(schema.max_value),
                        },
                        issue_code="feature_above_max",
                    )

            if schema is not None and schema.allowed_values and normalized is not None:
                token = _normalize_token(normalized) or str(normalized)

                if token not in schema.allowed_values:
                    counts.invalid_category += 1

                    if options.category_policy == PolicyAction.REJECT:
                        _record_check(
                            checks,
                            issues,
                            options,
                            category=ValidationCategory.VALIDITY,
                            status=CheckStatus.FAIL,
                            message="Category value not in allowed values rejected.",
                            field=feature,
                            details={"source_index": source_index},
                            issue_code="invalid_category_value",
                        )
                        reject_record = True
                        break

                    if options.category_policy == PolicyAction.DROP:
                        counts.dropped_cells += 1
                        clean_features[feature] = None
                        continue

                    _record_check(
                        checks,
                        issues,
                        options,
                        category=ValidationCategory.VALIDITY,
                        status=CheckStatus.WARN,
                        message="Category value not in allowed values.",
                        field=feature,
                        details={"source_index": source_index},
                        issue_code="invalid_category_value",
                    )

            if normalized is not None:
                clean_features[feature] = normalized
            else:
                clean_features[feature] = None

        if reject_record:
            counts.rejected_records += 1
            continue

        if not clean_features:
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.COMPLETENESS,
                status=CheckStatus.WARN,
                message="Record had no valid feature cells after validation and was skipped.",
                details={"source_index": source_index},
                issue_code="empty_valid_record",
            )
            continue

        cleaned.append(
            {
                "index": len(cleaned),
                "source_index": source_index,
                "subject_ref_hash": subject,
                "features": clean_features,
            }
        )

    if not cleaned:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.COMPLETENESS,
            status=CheckStatus.FAIL,
            message="No valid records remained after validation.",
            issue_code="no_valid_records",
        )

    return cleaned, counts


# -----------------------------------------------------------------------------
# Feature statistics
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _FeatureAccumulator:
    name: str
    dtype: FeatureType
    total: int = 0
    missing: int = 0
    invalid: int = 0
    numeric: list[float] = dataclass_field(default_factory=list)
    numeric_truncated: bool = False
    numeric_set: set[float] = dataclass_field(default_factory=set)
    numeric_set_truncated: bool = False
    bool_true: int = 0
    bool_false: int = 0
    categories: Counter[str] = dataclass_field(default_factory=Counter)
    category_set: set[str] = dataclass_field(default_factory=set)
    category_truncated: bool = False


def _aggregate_feature_stats(
    records: Sequence[Mapping[str, Any]],
    schemas: Mapping[str, FeatureSchema],
    options: ValidationOptions,
) -> dict[str, Any]:
    accumulators: dict[str, _FeatureAccumulator] = {
        feature: _FeatureAccumulator(
            name=feature,
            dtype=schema.dtype if schema is not None else FeatureType.UNKNOWN,
        )
        for feature, schema in schemas.items()
    }

    for record in records:
        features = record.get("features")

        if not isinstance(features, Mapping):
            continue

        for feature, value in features.items():
            acc = accumulators.get(feature)

            if acc is None:
                continue

            acc.total += 1

            if value is None:
                acc.missing += 1
                continue

            if isinstance(value, bool):
                if value:
                    acc.bool_true += 1
                else:
                    acc.bool_false += 1
                continue

            numeric = _coerce_optional_float(value, allow_bool=False)

            if numeric is not None:
                rounded = _round6(numeric)

                if len(acc.numeric) < options.max_numeric_sample:
                    acc.numeric.append(rounded)
                else:
                    acc.numeric_truncated = True

                if len(acc.numeric_set) < options.max_distinct_tracked:
                    acc.numeric_set.add(rounded)
                else:
                    acc.numeric_set_truncated = True

                continue

            token = _normalize_token(value) or _clean_text(value, 128)

            if not token:
                acc.invalid += 1
                continue

            if len(acc.categories) < options.max_categories:
                acc.categories[token] += 1
            else:
                acc.categories["__other__"] += 1
                acc.category_truncated = True

            if len(acc.category_set) < options.max_distinct_tracked:
                acc.category_set.add(token)
            else:
                acc.category_truncated = True

    out: dict[str, Any] = {}

    for feature, acc in accumulators.items():
        nonmissing = acc.total - acc.missing
        missing_rate = _round6(float(acc.missing) / float(acc.total)) if acc.total > 0 else 0.0
        payload: dict[str, Any] = {
            "dtype": acc.dtype.value,
            "total": acc.total,
            "missing": acc.missing,
            "nonmissing": nonmissing,
            "invalid": acc.invalid,
            "missing_rate": missing_rate,
            "nonmissing_rate": _round6(1.0 - missing_rate) if acc.total > 0 else 0.0,
        }

        if acc.dtype == FeatureType.NUMERIC and acc.numeric:
            ordered = sorted(acc.numeric)
            mean_value = _mean(ordered)
            payload["numeric"] = {
                "available": True,
                "sample_count": len(ordered),
                "sample_truncated": acc.numeric_truncated,
                "min": _round6(ordered[0]),
                "max": _round6(ordered[-1]),
                "mean": _round6(mean_value),
                "std": _round6(_stddev(ordered, mean_value)),
                "p05": _round6(_quantile_sorted(ordered, 0.05)),
                "p25": _round6(_quantile_sorted(ordered, 0.25)),
                "p50": _round6(_quantile_sorted(ordered, 0.50)),
                "p75": _round6(_quantile_sorted(ordered, 0.75)),
                "p95": _round6(_quantile_sorted(ordered, 0.95)),
                "zero_rate": _round6(sum(1 for value in ordered if value == 0.0) / float(len(ordered))),
                "negative_rate": _round6(sum(1 for value in ordered if value < 0.0) / float(len(ordered))),
                "distinct": len(acc.numeric_set),
                "distinct_truncated": acc.numeric_set_truncated,
            }
        elif acc.dtype == FeatureType.BOOLEAN:
            bool_total = acc.bool_true + acc.bool_false
            payload["boolean"] = {
                "available": bool_total > 0,
                "true_count": acc.bool_true,
                "false_count": acc.bool_false,
                "true_rate": _round6(float(acc.bool_true) / float(bool_total)) if bool_total > 0 else None,
            }
        else:
            category_total = sum(acc.categories.values())
            top = acc.categories.most_common(1)[0] if acc.categories else (None, 0)
            shares = [float(count) / float(category_total) for count in acc.categories.values()] if category_total > 0 else []
            entropy = 0.0

            if shares and len(shares) > 1:
                entropy = -sum(p * math.log(p) for p in shares if p > 0) / math.log(len(shares))

            hhi = sum(p * p for p in shares) if shares else 0.0
            rare_count = sum(count for category, count in acc.categories.items() if category != "__other__" and float(count) / float(category_total) < options.rare_category_share) if category_total > 0 else 0

            payload["categorical"] = {
                "available": category_total > 0,
                "distinct": len(acc.category_set),
                "distinct_truncated": acc.category_truncated,
                "top_category_share": _round6(float(top[1]) / float(category_total)) if category_total > 0 else None,
                "entropy": _round6(entropy),
                "hhi": _round6(hhi),
                "rare_share": _round6(float(rare_count) / float(category_total)) if category_total > 0 else None,
                "category_counts_sample": [
                    {"category": category, "count": count}
                    for category, count in acc.categories.most_common(options.max_summary_items)
                ],
                "category_counts_truncated": len(acc.categories) > options.max_summary_items,
            }

        out[feature] = payload

    return out


def _validate_feature_stats(
    feature_stats: Mapping[str, Any],
    schemas: Mapping[str, FeatureSchema],
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> None:
    if not feature_stats:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DISTRIBUTION,
            status=CheckStatus.SKIP,
            message="Feature statistics unavailable.",
        )
        return

    high_missing: list[str] = []
    low_entropy: list[str] = []
    high_hhi: list[str] = []
    high_cardinality: list[str] = []

    for feature, stats in feature_stats.items():
        if not isinstance(stats, Mapping):
            continue

        missing_rate = _coerce_optional_float(stats.get("missing_rate"), allow_bool=False)

        if missing_rate is not None and missing_rate > options.max_missing_rate:
            high_missing.append(feature)

        categorical = stats.get("categorical")

        if isinstance(categorical, Mapping):
            entropy = _coerce_optional_float(categorical.get("entropy"), allow_bool=False)
            hhi = _coerce_optional_float(categorical.get("hhi"), allow_bool=False)
            distinct = _coerce_optional_float(categorical.get("distinct"), allow_bool=False)
            top_share = _coerce_optional_float(categorical.get("top_category_share"), allow_bool=False)

            if entropy is not None and entropy < options.entropy_floor and (distinct or 0) > 1:
                low_entropy.append(feature)

            if hhi is not None and hhi > options.hhi_ceiling:
                high_hhi.append(feature)

            if distinct is not None and distinct > options.max_cardinality:
                high_cardinality.append(feature)

            if top_share is not None and top_share > options.top_category_share_limit:
                _record_check(
                    checks,
                    issues,
                    options,
                    category=ValidationCategory.DISTRIBUTION,
                    status=CheckStatus.WARN,
                    message="Categorical feature has excessive top-category concentration.",
                    field=feature,
                    details={"top_category_share": _round6(top_share), "limit": options.top_category_share_limit},
                    issue_code="high_top_category_share",
                )

    if high_missing:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.COMPLETENESS,
            status=CheckStatus.WARN,
            message="Features exceed configured missing-rate limit.",
            details={
                "feature_count": len(high_missing),
                "features_sample": high_missing[: options.max_summary_items],
                "truncated": len(high_missing) > options.max_summary_items,
            },
            issue_code="high_missing_rate",
        )

    if low_entropy:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DISTRIBUTION,
            status=CheckStatus.INFO,
            message="Categorical features have low entropy.",
            details={
                "feature_count": len(low_entropy),
                "features_sample": low_entropy[: options.max_summary_items],
                "truncated": len(low_entropy) > options.max_summary_items,
            },
        )

    if high_hhi:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DISTRIBUTION,
            status=CheckStatus.WARN,
            message="Categorical features have high Herfindahl-Hirschman concentration.",
            details={
                "feature_count": len(high_hhi),
                "features_sample": high_hhi[: options.max_summary_items],
                "truncated": len(high_hhi) > options.max_summary_items,
            },
            issue_code="high_categorical_hhi",
        )

    if high_cardinality:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DISTRIBUTION,
            status=CheckStatus.WARN,
            message="Categorical features exceed configured cardinality limit.",
            details={
                "feature_count": len(high_cardinality),
                "features_sample": high_cardinality[: options.max_summary_items],
                "truncated": len(high_cardinality) > options.max_summary_items,
            },
            issue_code="high_cardinality",
        )

    _record_check(
        checks,
        issues,
        options,
        category=ValidationCategory.DISTRIBUTION,
        status=CheckStatus.PASS,
        message="Feature distribution validation completed.",
        details={"feature_count": len(feature_stats)},
    )


# -----------------------------------------------------------------------------
# Label helpers
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _LabelIndex:
    """
    Internal bounded label index.

    This structure is internal-facing. Public reports must expose only safe
    aggregate label statistics and must never expose subject-label pairs.
    """

    by_subject: dict[str, int] = dataclass_field(default_factory=dict)
    weights_by_subject: dict[str, float] = dataclass_field(default_factory=dict)
    splits_by_subject: dict[str, str] = dataclass_field(default_factory=dict)

    by_source: list[Optional[int]] = dataclass_field(default_factory=list)
    weights_by_source: list[float] = dataclass_field(default_factory=list)
    splits_by_source: list[str] = dataclass_field(default_factory=list)
    subjects_by_source: list[Optional[str]] = dataclass_field(default_factory=list)

    split_conflicts: set[str] = dataclass_field(default_factory=set)


def _build_label_index(labels: Any, record_count: int, options: ValidationOptions) -> _LabelIndex:
    """
    Build a bounded label index from flexible label input.

    Supports:

    - mapping with parallel arrays: `subject_hashes`, `label_codes`, `weights`,
      `splits`;
    - mapping with `records`, `items`, or `rows`;
    - mapping with a single label record;
    - object with parallel attributes;
    - object with `records` or `items`;
    - plain sequence of label codes or label records.

    This never retains raw narratives, raw identifiers, secrets, tokens,
    passwords, database URLs, filesystem paths, or model artifact paths.
    """
    count = max(0, int(record_count))

    index = _LabelIndex(
        by_source=[None] * count,
        weights_by_source=[1.0] * count,
        splits_by_source=[DatasetRole.UNKNOWN.value] * count,
        subjects_by_source=[None] * count,
    )

    if labels is None:
        return index

    def add_item(
        position: Optional[int],
        subject: Any,
        raw_label: Any,
        raw_weight: Any,
        raw_split: Any,
    ) -> None:
        code = _coerce_int_label(raw_label)
        weight = _clip_float(_coerce_optional_float(raw_weight, allow_bool=True), 0.0, 100.0, 1.0)
        split = _normalize_token(raw_split) or DatasetRole.UNKNOWN.value
        subject_hash = _subject_hash(subject, options) if subject is not None else None

        if subject_hash:
            existing_code = index.by_subject.get(subject_hash)

            if existing_code is not None and code is not None and existing_code != code:
                index.split_conflicts.add(subject_hash)

            if code is not None:
                index.by_subject[subject_hash] = code

            index.weights_by_subject[subject_hash] = weight

            existing_split = index.splits_by_subject.get(subject_hash)

            if (
                existing_split is not None
                and existing_split != split
                and split != DatasetRole.UNKNOWN.value
                and existing_split != DatasetRole.UNKNOWN.value
            ):
                index.split_conflicts.add(subject_hash)

            index.splits_by_subject[subject_hash] = split

        if position is not None and 0 <= position < count:
            index.by_source[position] = code
            index.weights_by_source[position] = weight
            index.splits_by_source[position] = split
            index.subjects_by_source[position] = subject_hash

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

            for position in range(min(len(subjects), len(codes), max(count, len(codes)))):
                add_item(
                    position,
                    subjects[position],
                    codes[position],
                    weight_seq[position] if position < len(weight_seq) else 1.0,
                    split_seq[position] if position < len(split_seq) else DatasetRole.UNKNOWN.value,
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
                        record.get("split", DatasetRole.UNKNOWN.value),
                    )
                else:
                    add_item(position, None, record, 1.0, DatasetRole.UNKNOWN.value)

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
                    split_seq[position] if position < len(split_seq) else DatasetRole.UNKNOWN.value,
                )

            return index

        code = _label_code_from_mapping(labels)

        if code is not None:
            add_item(
                0,
                _subject_from_mapping(labels),
                code,
                labels.get("weight", 1.0),
                labels.get("split", DatasetRole.UNKNOWN.value),
            )

        return index

    if hasattr(labels, "subject_hashes") and hasattr(labels, "label_codes"):
        subjects = _as_sequence(getattr(labels, "subject_hashes", ()) or ())
        codes = _as_sequence(getattr(labels, "label_codes", ()) or ())
        weights = _as_sequence(getattr(labels, "weights", ()) or ())
        splits = _as_sequence(getattr(labels, "splits", ()) or ())

        for position in range(min(len(subjects), len(codes), max(count, len(codes)))):
            add_item(
                position,
                subjects[position],
                codes[position],
                weights[position] if position < len(weights) else 1.0,
                splits[position] if position < len(splits) else DatasetRole.UNKNOWN.value,
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
                    record.get("split", DatasetRole.UNKNOWN.value),
                )
            else:
                add_item(position, None, record, 1.0, DatasetRole.UNKNOWN.value)

        return index

    for position, item in enumerate(_as_sequence(labels)):
        if isinstance(item, Mapping):
            add_item(
                position,
                _subject_from_mapping(item),
                _label_code_from_mapping(item),
                item.get("weight", 1.0),
                item.get("split", DatasetRole.UNKNOWN.value),
            )
        else:
            add_item(position, None, item, 1.0, DatasetRole.UNKNOWN.value)

    return index


def _label_entries(label_index: _LabelIndex) -> list[tuple[Optional[int], Optional[str]]]:
    """
    Return de-duplicated logical label entries.

    Positional labels are preferred. Subject-only labels are appended only when
    the subject was not already represented positionally.
    """
    entries: list[tuple[Optional[int], Optional[str]]] = []
    seen_subjects: set[str] = set()

    for position, code in enumerate(label_index.by_source):
        subject = (
            label_index.subjects_by_source[position]
            if position < len(label_index.subjects_by_source)
            else None
        )

        if subject:
            seen_subjects.add(subject)

        entries.append((code, subject))

    for subject, code in label_index.by_subject.items():
        if subject in seen_subjects:
            continue

        entries.append((code, subject))

    return entries


def _label_summary(label_index: _LabelIndex) -> dict[str, Any]:
    """
    Return a safe aggregate label summary.

    This never exposes subject-label pairs.
    """
    counter: Counter[int] = Counter()

    for code, _subject in _label_entries(label_index):
        if code is not None:
            counter[int(code)] += 1

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


def _split_summary(label_index: _LabelIndex) -> dict[str, Any]:
    """
    Return a safe aggregate split summary.
    """
    counter: Counter[str] = Counter()

    for _code, subject in _label_entries(label_index):
        split = None

        if subject and subject in label_index.splits_by_subject:
            split = label_index.splits_by_subject.get(subject)
        else:
            for position, entry_subject in enumerate(label_index.subjects_by_source):
                if entry_subject == subject and position < len(label_index.splits_by_source):
                    split = label_index.splits_by_source[position]
                    break

        split = _normalize_token(split) or DatasetRole.UNKNOWN.value

        if split != DatasetRole.UNKNOWN.value:
            counter[split] += 1

    return {
        "available": bool(counter),
        "counts": dict(counter),
        "conflict_count": len(label_index.split_conflicts),
    }


def _lookup_label(
    label_index: _LabelIndex,
    position: int,
    subject: Optional[str],
) -> Optional[int]:
    """
    Return one label code for a record by subject hash or positional index.
    """
    if subject and subject in label_index.by_subject:
        return label_index.by_subject[subject]

    if 0 <= position < len(label_index.by_source):
        return label_index.by_source[position]

    return None


def _binary_label(
    label_code: Optional[int],
    positive_codes: set[int],
    negative_codes: set[int],
    ignore_codes: set[int],
) -> Optional[int]:
    """
    Map a label code to binary 1/0/None.
    """
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


def _validate_labels(
    label_index: _LabelIndex,
    record_count: int,
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> dict[str, Any]:
    """
    Validate aggregate label properties.

    Label validation is operational quality gating only. It is not proof of
    wrongdoing and must not trigger automatic adverse customer action.
    """
    summary = _label_summary(label_index)

    if not summary.get("available"):
        if options.dataset_role in {
            DatasetRole.TRAIN,
            DatasetRole.VALIDATION,
            DatasetRole.TEST,
        }:
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.LABELS,
                status=CheckStatus.WARN,
                message="Labels unavailable for supervised dataset role.",
                details=summary,
                issue_code="labels_unavailable",
            )
        else:
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.LABELS,
                status=CheckStatus.SKIP,
                message="Labels not supplied for validation.",
            )

        return summary

    allowed = set(options.allowed_label_codes)
    counter: Counter[int] = Counter()

    for code, _subject in _label_entries(label_index):
        if code is not None:
            counter[int(code)] += 1

    invalid_codes = sorted(code for code in counter if code not in allowed)

    if invalid_codes:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.LABELS,
            status=CheckStatus.WARN,
            message="Label codes outside allowed set detected.",
            details={
                "invalid_codes": invalid_codes[: options.max_summary_items],
                "truncated": len(invalid_codes) > options.max_summary_items,
            },
            issue_code="invalid_label_code",
        )

    labelled = sum(1 for code, _subject in _label_entries(label_index) if code is not None)
    coverage = _round6(float(labelled) / float(record_count)) if record_count > 0 else 0.0

    summary["coverage"] = coverage
    summary["labelled"] = labelled
    summary["record_count"] = int(record_count)

    if (
        options.dataset_role
        in {
            DatasetRole.TRAIN,
            DatasetRole.VALIDATION,
            DatasetRole.TEST,
        }
        and coverage < options.min_label_coverage
    ):
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.LABELS,
            status=CheckStatus.WARN,
            message="Label coverage below configured minimum.",
            details={
                "coverage": coverage,
                "min_label_coverage": options.min_label_coverage,
            },
            issue_code="low_label_coverage",
        )

    if counter:
        min_support = min(counter.values())
        max_support = max(counter.values())
        imbalance = float(max_support) / float(min_support) if min_support > 0 else 0.0

        summary["min_class_support"] = int(min_support)
        summary["max_class_support"] = int(max_support)
        summary["class_imbalance_ratio"] = _round6(imbalance)

        if min_support < options.min_class_support:
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.LABELS,
                status=CheckStatus.WARN,
                message="At least one label class has insufficient support.",
                details={
                    "min_support": int(min_support),
                    "min_class_support": int(options.min_class_support),
                },
                issue_code="low_class_support",
            )

        if imbalance > options.max_class_imbalance_ratio:
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.LABELS,
                status=CheckStatus.WARN,
                message="Label class imbalance exceeds configured maximum.",
                details={
                    "imbalance_ratio": _round6(imbalance),
                    "max_ratio": _round6(options.max_class_imbalance_ratio),
                },
                issue_code="high_class_imbalance",
            )

    if label_index.split_conflicts:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.LABELS,
            status=CheckStatus.WARN,
            message="Conflicting label or split assignments detected for subjects.",
            details={"conflict_count": len(label_index.split_conflicts)},
            issue_code="label_split_conflict",
        )

    _record_check(
        checks,
        issues,
        options,
        category=ValidationCategory.LABELS,
        status=CheckStatus.PASS,
        message="Label validation completed.",
        details={
            "label_count": int(summary.get("label_count", 0)),
            "class_count": int(summary.get("class_count", 0)),
        },
    )

    return summary


def _validate_splits(
    label_index: _LabelIndex,
    record_count: int,
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> dict[str, Any]:
    """
    Validate bounded split metadata and isolation.
    """
    summary = _split_summary(label_index)
    summary["record_count"] = int(record_count)

    if not summary.get("available"):
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.SPLITS,
            status=CheckStatus.SKIP,
            message="Split metadata unavailable.",
        )
        return summary

    counts = dict(summary.get("counts") or {})
    train_count = int(counts.get(DatasetRole.TRAIN.value, 0))
    validation_count = int(counts.get(DatasetRole.VALIDATION.value, 0))
    test_count = int(counts.get(DatasetRole.TEST.value, 0))

    if train_count < options.min_train_samples:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.SPLITS,
            status=CheckStatus.WARN,
            message="Train split below configured minimum.",
            details={
                "train_count": train_count,
                "min_train_samples": options.min_train_samples,
            },
            issue_code="low_train_samples",
        )

    if validation_count and validation_count < options.min_validation_samples:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.SPLITS,
            status=CheckStatus.WARN,
            message="Validation split below configured minimum.",
            details={
                "validation_count": validation_count,
                "min_validation_samples": options.min_validation_samples,
            },
            issue_code="low_validation_samples",
        )

    if test_count and test_count < options.min_test_samples:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.SPLITS,
            status=CheckStatus.WARN,
            message="Test split below configured minimum.",
            details={
                "test_count": test_count,
                "min_test_samples": options.min_test_samples,
            },
            issue_code="low_test_samples",
        )

    if label_index.split_conflicts:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.SPLITS,
            status=(
                CheckStatus.FAIL
                if options.split_policy == PolicyAction.REJECT
                else CheckStatus.WARN
            ),
            message="Subject appears in conflicting splits.",
            details={"conflict_count": len(label_index.split_conflicts)},
            issue_code="split_overlap",
        )

    _record_check(
        checks,
        issues,
        options,
        category=ValidationCategory.SPLITS,
        status=CheckStatus.PASS,
        message="Split validation completed.",
        details={"counts": counts},
    )

    return summary


# -----------------------------------------------------------------------------
# Prediction helpers
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _PredictionIndex:
    """
    Internal bounded prediction index.
    """

    by_subject: dict[str, tuple[Optional[float], Optional[int]]] = dataclass_field(default_factory=dict)
    by_index: dict[int, tuple[Optional[float], Optional[int]]] = dataclass_field(default_factory=dict)

    by_source: list[tuple[Optional[float], Optional[int]]] = dataclass_field(default_factory=list)
    subjects_by_source: list[Optional[str]] = dataclass_field(default_factory=list)

    submitted: int = 0
    scored: int = 0
    predicted_labels: int = 0
    out_of_range: int = 0
    extreme: int = 0


def _iter_prediction_items(data: Any) -> list[Any]:
    """
    Convert flexible prediction input into a list of prediction-like items.
    """
    if data is None:
        return []

    if isinstance(data, Mapping):
        for key in ("predictions", "records", "items", "rows", "scores", "probabilities", "values"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])

        if any(
            key in data
            for key in (
                "score",
                "probability",
                "positive_probability",
                "risk_score",
                "anomaly_score",
                "predicted_label",
                "label_code",
                "prediction",
                "y_pred",
            )
        ):
            return [data]

        if data and all(
            _coerce_optional_float(value, allow_bool=True) is not None
            for value in data.values()
        ):
            return [
                {"subject_ref_hash": key, "score": value}
                for key, value in data.items()
            ]

        return [data]

    for attr in ("predictions", "records", "items", "rows", "scores"):
        seq = getattr(data, attr, None)

        if seq is not None and not callable(seq):
            return _as_sequence(seq)

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray, memoryview)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _is_extreme_score(score: Optional[float], options: ValidationOptions) -> bool:
    """
    Return True when a score is effectively pinned to a boundary.
    """
    if score is None:
        return False

    if math.isclose(float(options.score_min), 0.0, abs_tol=1e-12) and math.isclose(
        float(options.score_max),
        1.0,
        abs_tol=1e-12,
    ):
        return float(score) <= 1e-9 or float(score) >= 1.0 - 1e-9

    return (
        float(score) <= float(options.score_min) + 1e-9
        or float(score) >= float(options.score_max) - 1e-9
    )


def _is_out_of_range_score(score: Optional[float], options: ValidationOptions) -> bool:
    """
    Return True when a score violates configured bounds.
    """
    if score is None:
        return False

    return (
        float(score) < float(options.score_min) - 1e-9
        or float(score) > float(options.score_max) + 1e-9
    )


def _prediction_from_item(
    item: Any,
    fallback_index: int,
    options: ValidationOptions,
) -> dict[str, Any]:
    """
    Convert one prediction-like item into a bounded internal prediction record.
    """
    subject: Any = None
    index: Any = fallback_index
    score: Any = None
    predicted_label: Any = None
    probabilities: Any = None

    if isinstance(item, Mapping):
        subject = _subject_from_mapping(item)
        index = item.get("index", fallback_index)
        score = (
            item.get("score")
            if item.get("score") is not None
            else item.get("probability")
            if item.get("probability") is not None
            else item.get("positive_probability")
            if item.get("positive_probability") is not None
            else item.get("risk_score")
            if item.get("risk_score") is not None
            else item.get("anomaly_score")
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
    elif hasattr(item, "score") or hasattr(item, "probability") or hasattr(item, "risk_score"):
        subject = getattr(item, "subject_ref_hash", None) or getattr(item, "subject_hash", None)
        index = getattr(item, "index", fallback_index)
        score = (
            getattr(item, "score", None)
            if getattr(item, "score", None) is not None
            else getattr(item, "probability", None)
            if getattr(item, "probability", None) is not None
            else getattr(item, "positive_probability", None)
            if getattr(item, "positive_probability", None) is not None
            else getattr(item, "risk_score", None)
            if getattr(item, "risk_score", None) is not None
            else getattr(item, "anomaly_score", None)
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
    else:
        numeric = _coerce_optional_float(item, allow_bool=True)

        if numeric is not None:
            score = numeric

    score_float = _coerce_optional_float(score, allow_bool=True)
    predicted_int = _coerce_int_label(predicted_label)

    if score_float is None and predicted_int is not None:
        binary = _binary_label(
            predicted_int,
            set(options.positive_label_codes),
            set(options.negative_label_codes),
            set(options.ignore_label_codes),
        )

        if binary is not None:
            score_float = float(binary)

    if score_float is None and isinstance(probabilities, Mapping):
        prob_map: dict[str, float] = {}

        for key, value in probabilities.items():
            numeric = _coerce_optional_float(value, allow_bool=True)

            if numeric is not None:
                prob_map[_normalize_token(key) or _clean_text(key, 100)] = _clip_float(
                    numeric,
                    0.0,
                    1.0,
                    0.0,
                )

        if prob_map:
            positive_keys = {
                "review",
                "escalate",
                "positive",
                "investigate",
                "high_priority",
                "critical",
                "urgent",
                "1",
                "true",
                "yes",
            }
            positive_values = [
                value
                for key, value in prob_map.items()
                if key in positive_keys
            ]

            score_float = max(positive_values) if positive_values else max(prob_map.values())

    return {
        "subject_ref_hash": _subject_hash(subject, options) if subject is not None else None,
        "index": _as_int(index, fallback_index) if index is not None else fallback_index,
        "score": _round6(score_float) if score_float is not None else None,
        "predicted_label": predicted_int,
    }


def _build_prediction_index(
    predictions: Any,
    record_count: int,
    options: ValidationOptions,
) -> _PredictionIndex:
    """
    Build a bounded prediction index from flexible prediction input.
    """
    count = max(0, int(record_count))
    index = _PredictionIndex(
        by_source=[(None, None) for _ in range(count)],
        subjects_by_source=[None for _ in range(count)],
    )

    items = _iter_prediction_items(predictions)
    index.submitted = len(items)

    positive_codes = set(options.positive_label_codes)
    negative_codes = set(options.negative_label_codes)
    ignore_codes = set(options.ignore_label_codes)

    for position, item in enumerate(items):
        pred = _prediction_from_item(item, position, options)
        score = pred.get("score")
        predicted_label = pred.get("predicted_label")
        subject = pred.get("subject_ref_hash")
        explicit_index = pred.get("index")

        pair = (score, predicted_label)

        if score is not None:
            index.scored += 1

            if _is_out_of_range_score(score, options):
                index.out_of_range += 1

            if _is_extreme_score(score, options):
                index.extreme += 1

        if predicted_label is not None:
            index.predicted_labels += 1
        elif score is not None:
            binary = _binary_label(
                int(round(float(score))) if float(score) in (0.0, 1.0) else None,
                positive_codes,
                negative_codes,
                ignore_codes,
            )

            if binary is not None:
                predicted_label = binary
                pair = (score, predicted_label)
                index.predicted_labels += 1

        if subject:
            index.by_subject.setdefault(subject, pair)

        if isinstance(explicit_index, int) and explicit_index >= 0:
            index.by_index.setdefault(explicit_index, pair)

        if position < count:
            index.by_source[position] = pair
            index.subjects_by_source[position] = subject
        elif isinstance(explicit_index, int) and 0 <= explicit_index < count:
            if index.by_source[explicit_index] == (None, None):
                index.by_source[explicit_index] = pair
                index.subjects_by_source[explicit_index] = subject

    return index


def _lookup_prediction(
    position: int,
    subject: Optional[str],
    prediction_index: _PredictionIndex,
) -> tuple[Optional[float], Optional[int]]:
    """
    Return one prediction for a record by explicit index, position, or subject.
    """
    pair = prediction_index.by_index.get(position)

    if pair is None and 0 <= position < len(prediction_index.by_source):
        pair = prediction_index.by_source[position]

    if (pair is None or pair == (None, None)) and subject:
        pair = prediction_index.by_subject.get(subject)

    if pair is None:
        return (None, None)

    return pair


def _binary_roc_auc(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    """
    Compute bounded binary ROC AUC using rank statistics.
    """
    pairs = sorted(
        (float(score), int(label))
        for score, label in zip(scores, y_true)
        if label in (0, 1)
    )

    positives = sum(1 for _score, label in pairs if label == 1)
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
    Compute bounded binary PR AUC / average precision.
    """
    pairs = sorted(
        (float(score), int(label))
        for score, label in zip(scores, y_true)
        if label in (0, 1)
    )

    positives = sum(1 for _score, label in pairs if label == 1)

    if positives <= 0 or len(pairs) <= positives:
        return None

    pairs.sort(key=lambda item: -item[0])

    tp = 0
    fp = 0
    ap = 0.0
    previous_recall = 0.0

    for _score, label in pairs:
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
    """
    Compute bounded binary log loss.
    """
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
    """
    Compute bounded binary Brier score.
    """
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


def _accuracy_multiclass(y_true: Sequence[int], y_pred: Sequence[int]) -> Optional[float]:
    """
    Compute bounded multiclass accuracy.
    """
    total = 0
    correct = 0

    for true_label, predicted_label in zip(y_true, y_pred):
        if true_label is None or predicted_label is None:
            continue

        total += 1

        if int(true_label) == int(predicted_label):
            correct += 1

    if total <= 0:
        return None

    return _round6(float(correct) / float(total))


def _validate_predictions(
    records: Sequence[Mapping[str, Any]],
    label_index: _LabelIndex,
    prediction_index: _PredictionIndex,
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> dict[str, Any]:
    """
    Validate bounded prediction artefacts against records and labels.

    Prediction validation is operational quality gating only. Prediction scores
    are investigative prioritisation artefacts, not probabilities of guilt.
    """
    summary: dict[str, Any] = {
        "available": prediction_index.submitted > 0,
        "submitted": int(prediction_index.submitted),
        "scored": int(prediction_index.scored),
        "predicted_labels": int(prediction_index.predicted_labels),
        "out_of_range": int(prediction_index.out_of_range),
        "extreme": int(prediction_index.extreme),
        "matched": 0,
        "binary_evaluable": 0,
        "multiclass_evaluable": 0,
        "raw_values_retained": False,
    }

    if prediction_index.submitted <= 0:
        if options.dataset_role == DatasetRole.INFERENCE:
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.PREDICTIONS,
                status=CheckStatus.WARN,
                message="No predictions supplied for inference-role validation.",
                issue_code="predictions_unavailable",
            )
        else:
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.PREDICTIONS,
                status=CheckStatus.SKIP,
                message="Predictions not supplied for validation.",
            )

        return summary

    positive_codes = set(options.positive_label_codes)
    negative_codes = set(options.negative_label_codes)
    ignore_codes = set(options.ignore_label_codes)

    matched = 0
    y_binary: list[int] = []
    scores_binary: list[float] = []
    y_multi: list[int] = []
    pred_multi: list[int] = []

    for record in records:
        position = int(record.get("index", 0))
        subject = record.get("subject_ref_hash")
        score, predicted_label = _lookup_prediction(position, subject, prediction_index)

        if score is None and predicted_label is None:
            continue

        matched += 1

        label_code = _lookup_label(label_index, position, subject)
        binary_label = _binary_label(label_code, positive_codes, negative_codes, ignore_codes)

        if binary_label is not None and score is not None:
            y_binary.append(binary_label)
            scores_binary.append(_clip_float(score, 0.0, 1.0, 0.0))

        if label_code is not None and predicted_label is not None:
            y_multi.append(int(label_code))
            pred_multi.append(int(predicted_label))

    summary["matched"] = matched
    summary["binary_evaluable"] = len(y_binary)
    summary["multiclass_evaluable"] = len(y_multi)

    if prediction_index.out_of_range > 0:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.PREDICTIONS,
            status=(
                CheckStatus.FAIL
                if options.prediction_policy == PolicyAction.REJECT
                else CheckStatus.WARN
            ),
            message="Prediction scores outside configured bounds.",
            details={
                "out_of_range": prediction_index.out_of_range,
                "score_min": _round6(options.score_min),
                "score_max": _round6(options.score_max),
            },
            issue_code="prediction_out_of_range",
        )

    extreme_rate = (
        _round6(float(prediction_index.extreme) / float(prediction_index.scored))
        if prediction_index.scored > 0
        else 0.0
    )
    summary["extreme_rate"] = extreme_rate

    if extreme_rate > options.max_extreme_score_rate:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.PREDICTIONS,
            status=CheckStatus.WARN,
            message="Prediction score distribution is excessively pinned to boundaries.",
            details={
                "extreme_rate": extreme_rate,
                "max_extreme_score_rate": _round6(options.max_extreme_score_rate),
            },
            issue_code="prediction_extreme_rate",
        )

    if matched <= 0:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.PREDICTIONS,
            status=CheckStatus.WARN,
            message="Predictions could not be aligned to validation records.",
            details={"submitted": prediction_index.submitted, "records": len(records)},
            issue_code="prediction_alignment_failed",
        )
        return summary

    if y_binary and scores_binary:
        roc_auc = _binary_roc_auc(y_binary, scores_binary)
        pr_auc = _binary_pr_auc(y_binary, scores_binary)
        log_loss = _log_loss_binary(y_binary, scores_binary)
        brier = _brier_binary(y_binary, scores_binary)

        summary["binary_metrics"] = {
            "available": True,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "log_loss": log_loss,
            "brier_score": brier,
            "positive_count": sum(1 for label in y_binary if int(label) == 1),
            "negative_count": sum(1 for label in y_binary if int(label) == 0),
        }

        if roc_auc is not None and roc_auc < 0.50:
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.PREDICTIONS,
                status=CheckStatus.INFO,
                message="Binary ROC AUC is below chance on aligned validation labels.",
                details={"roc_auc": roc_auc},
            )
    else:
        summary["binary_metrics"] = {
            "available": False,
            "reason": "insufficient_aligned_binary_labels_or_scores",
        }

    if y_multi and pred_multi:
        accuracy = _accuracy_multiclass(y_multi, pred_multi)
        summary["multiclass_metrics"] = {
            "available": accuracy is not None,
            "accuracy": accuracy,
            "count": len(y_multi),
        }
    else:
        summary["multiclass_metrics"] = {
            "available": False,
            "reason": "insufficient_aligned_predicted_labels",
        }

    _record_check(
        checks,
        issues,
        options,
        category=ValidationCategory.PREDICTIONS,
        status=CheckStatus.PASS,
        message="Prediction validation completed.",
        details={
            "submitted": prediction_index.submitted,
            "matched": matched,
            "scored": prediction_index.scored,
            "binary_evaluable": len(y_binary),
            "multiclass_evaluable": len(y_multi),
        },
    )

    return summary


# -----------------------------------------------------------------------------
# Model metadata helpers
# -----------------------------------------------------------------------------


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


def _model_feature_names(model: Any) -> tuple[str, ...]:
    """
    Return fitted feature names for a model-like object when available.
    """
    if model is None:
        return ()

    params = getattr(model, "parameters", None)

    if params is not None:
        names = getattr(params, "feature_names", None)

        if names:
            return tuple(
                dict.fromkeys(
                    _canonical_field_name(name)
                    for name in _as_sequence(names)
                    if _canonical_field_name(name)
                )
            )

    names = getattr(model, "feature_names", None)

    if names:
        return tuple(
            dict.fromkeys(
                _canonical_field_name(name)
                for name in _as_sequence(names)
                if _canonical_field_name(name)
            )
        )

    return ()


def _validate_model(
    model: Any,
    schemas: Mapping[str, FeatureSchema],
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> dict[str, Any]:
    """
    Validate bounded model metadata.

    This does not execute models, load artifacts, or call external runtimes.
    """
    if model is None:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.MODEL,
            status=CheckStatus.SKIP,
            message="Model metadata not supplied.",
        )
        return {"available": False, "raw_values_retained": False}

    summary = _safe_summary_from_object(model)
    feature_names = _model_feature_names(model)

    leakage_names = [
        name
        for name in feature_names
        if _is_label_leakage_key(name) or _is_forbidden_key(name)
    ]

    privacy_names = [
        name
        for name in feature_names
        if any(token in name for token in _SENSITIVE_DETAIL_TOKENS)
    ]

    if leakage_names:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.LEAKAGE,
            status=(
                CheckStatus.FAIL
                if options.leakage_policy == PolicyAction.REJECT
                else CheckStatus.WARN
            ),
            message="Model feature names include leakage-prone fields.",
            details={
                "feature_count": len(leakage_names),
                "features_sample": leakage_names[: options.max_summary_items],
                "truncated": len(leakage_names) > options.max_summary_items,
            },
            issue_code="model_feature_leakage_names",
        )

    if privacy_names:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.PRIVACY,
            status=CheckStatus.WARN,
            message="Model feature names include privacy-sensitive tokens.",
            details={
                "feature_count": len(privacy_names),
                "features_sample": privacy_names[: options.max_summary_items],
                "truncated": len(privacy_names) > options.max_summary_items,
            },
            issue_code="model_feature_privacy_names",
        )

    if schemas:
        schema_names = set(schemas)
        unknown_model_features = [
            name
            for name in feature_names
            if name not in schema_names
        ]

        if unknown_model_features:
            _record_check(
                checks,
                issues,
                options,
                category=ValidationCategory.MODEL,
                status=(
                    CheckStatus.FAIL
                    if options.model_policy == PolicyAction.REJECT
                    else CheckStatus.WARN
                ),
                message="Model feature names are not fully represented in validated schema.",
                details={
                    "unknown_count": len(unknown_model_features),
                    "features_sample": unknown_model_features[: options.max_summary_items],
                    "truncated": len(unknown_model_features) > options.max_summary_items,
                },
                issue_code="model_schema_feature_mismatch",
            )

    summary.update(
        {
            "available": True,
            "feature_count": len(feature_names),
            "feature_names_sample": list(feature_names[: options.max_summary_items]),
            "feature_names_truncated": len(feature_names) > options.max_summary_items,
            "leakage_sensitive_feature_count": len(leakage_names),
            "privacy_sensitive_feature_count": len(privacy_names),
            "raw_values_retained": False,
            "model_artifact_paths_retained": False,
        }
    )

    _record_check(
        checks,
        issues,
        options,
        category=ValidationCategory.MODEL,
        status=CheckStatus.PASS,
        message="Model metadata validation completed.",
        details={
            "feature_count": len(feature_names),
            "summary_keys": sorted(summary)[: options.max_summary_items],
        },
    )

    return summary


# -----------------------------------------------------------------------------
# Duplicate and target-copy helpers
# -----------------------------------------------------------------------------


def _detect_duplicates(
    records: Sequence[Mapping[str, Any]],
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> dict[str, Any]:
    """
    Detect bounded exact row duplicates and duplicate subject references.

    Raw row payloads are never retained.
    """
    if not records:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DUPLICATES,
            status=CheckStatus.SKIP,
            message="Duplicate detection skipped because no valid records are present.",
        )
        return {"available": False, "raw_values_retained": False}

    row_counter: Counter[str] = Counter()
    subject_counter: Counter[str] = Counter()

    for record in records:
        features = record.get("features")

        if not isinstance(features, Mapping):
            features = {}

        position = int(record.get("index", 0))
        row_counter[_row_fingerprint(features, options, position)] += 1

        subject = record.get("subject_ref_hash")

        if subject:
            subject_counter[str(subject).lower()] += 1

    total = len(records)
    unique_rows = len(row_counter)
    duplicate_rows = max(0, total - unique_rows)
    duplicate_rate = _round6(float(duplicate_rows) / float(total)) if total > 0 else 0.0

    subject_duplicates = sum(
        max(0, count - 1)
        for count in subject_counter.values()
        if count > 1
    )
    subject_duplicate_rate = (
        _round6(float(subject_duplicates) / float(total))
        if total > 0
        else 0.0
    )

    summary = {
        "available": True,
        "records": total,
        "unique_rows": unique_rows,
        "duplicate_rows": duplicate_rows,
        "duplicate_rate": duplicate_rate,
        "subjects": len(subject_counter),
        "subject_duplicates": subject_duplicates,
        "subject_duplicate_rate": subject_duplicate_rate,
        "raw_values_retained": False,
    }

    if duplicate_rate > options.max_duplicate_rate:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DUPLICATES,
            status=(
                CheckStatus.FAIL
                if options.duplicate_policy == PolicyAction.REJECT
                else CheckStatus.WARN
            ),
            message="Exact row duplicate rate exceeds configured maximum.",
            details={
                "duplicate_rate": duplicate_rate,
                "max_duplicate_rate": _round6(options.max_duplicate_rate),
            },
            issue_code="high_exact_duplicate_rate",
        )

    if subject_duplicate_rate > options.max_duplicate_rate:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DUPLICATES,
            status=(
                CheckStatus.FAIL
                if options.duplicate_policy == PolicyAction.REJECT
                else CheckStatus.WARN
            ),
            message="Duplicate subject reference rate exceeds configured maximum.",
            details={
                "subject_duplicate_rate": subject_duplicate_rate,
                "max_duplicate_rate": _round6(options.max_duplicate_rate),
            },
            issue_code="high_subject_duplicate_rate",
        )

    _record_check(
        checks,
        issues,
        options,
        category=ValidationCategory.DUPLICATES,
        status=CheckStatus.PASS,
        message="Duplicate detection completed.",
        details={
            "duplicate_rows": duplicate_rows,
            "subject_duplicates": subject_duplicates,
        },
    )

    return summary


def _feature_binary_value(
    value: Any,
    options: ValidationOptions,
) -> Optional[int]:
    """
    Best-effort binary interpretation of a feature value.

    This is intentionally conservative and never retains raw values.
    """
    parsed_bool = _coerce_bool(value)

    if parsed_bool is not None:
        return 1 if parsed_bool else 0

    numeric = _coerce_optional_float(value, allow_bool=False)

    if numeric is not None:
        if math.isclose(numeric, 0.0, abs_tol=1e-12):
            return 0

        if math.isclose(numeric, 1.0, abs_tol=1e-12):
            return 1

    token = _normalize_token(value)

    if token in _TRUE_VALUES:
        return 1

    if token in _FALSE_VALUES:
        return 0

    code = _coerce_int_label(value)

    if code is not None:
        return _binary_label(
            code,
            set(options.positive_label_codes),
            set(options.negative_label_codes),
            set(options.ignore_label_codes),
        )

    return None


def _detect_target_copy(
    records: Sequence[Mapping[str, Any]],
    label_index: _LabelIndex,
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> dict[str, Any]:
    """
    Detect features that appear to copy the target label.

    Target-copy detection is a leakage heuristic only. It is not causal proof.
    """
    if not records:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.LEAKAGE,
            status=CheckStatus.SKIP,
            message="Target-copy detection skipped because no valid records are present.",
        )
        return {"available": False, "raw_values_retained": False}

    if not label_index.by_subject and not any(code is not None for code in label_index.by_source):
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.LEAKAGE,
            status=CheckStatus.SKIP,
            message="Target-copy detection skipped because labels are unavailable.",
        )
        return {"available": False, "reason": "labels_unavailable", "raw_values_retained": False}

    positive_codes = set(options.positive_label_codes)
    negative_codes = set(options.negative_label_codes)
    ignore_codes = set(options.ignore_label_codes)

    stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "total": 0,
            "code_match": 0,
            "binary_total": 0,
            "binary_match": 0,
        }
    )

    for record in records:
        position = int(record.get("index", 0))
        subject = record.get("subject_ref_hash")
        label_code = _lookup_label(label_index, position, subject)

        if label_code is None:
            continue

        binary_label = _binary_label(label_code, positive_codes, negative_codes, ignore_codes)
        features = record.get("features")

        if not isinstance(features, Mapping):
            continue

        for feature, value in features.items():
            feature = _canonical_field_name(feature)

            if not feature:
                continue

            bucket = stats[feature]
            bucket["total"] += 1

            feature_code = _coerce_int_label(value)

            if feature_code is not None and feature_code == int(label_code):
                bucket["code_match"] += 1

            feature_binary = _feature_binary_value(value, options)

            if feature_binary is not None and binary_label is not None:
                bucket["binary_total"] += 1

                if feature_binary == binary_label:
                    bucket["binary_match"] += 1

    flagged: list[dict[str, Any]] = []

    for feature, bucket in stats.items():
        total = int(bucket.get("total", 0))

        if total <= 0:
            continue

        code_rate = _round6(float(bucket.get("code_match", 0)) / float(total))
        binary_total = int(bucket.get("binary_total", 0))
        binary_rate = (
            _round6(float(bucket.get("binary_match", 0)) / float(binary_total))
            if binary_total > 0
            else None
        )
        max_rate = max(
            code_rate,
            float(binary_rate) if binary_rate is not None else 0.0,
        )

        if max_rate >= 0.98:
            flagged.append(
                {
                    "feature": feature,
                    "code_match_rate": code_rate,
                    "binary_match_rate": binary_rate,
                    "max_match_rate": _round6(max_rate),
                    "total": total,
                }
            )

    flagged.sort(key=lambda item: (-float(item["max_match_rate"]), str(item["feature"])))
    flagged = flagged[: options.max_summary_items]

    summary = {
        "available": True,
        "flagged_count": len(flagged),
        "flagged_sample": flagged,
        "truncated": len(stats) > options.max_summary_items,
        "raw_values_retained": False,
    }

    if flagged:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.LEAKAGE,
            status=(
                CheckStatus.FAIL
                if options.target_copy_policy == PolicyAction.REJECT
                else CheckStatus.WARN
            ),
            message="Features strongly resemble the target label.",
            details={
                "flagged_count": len(flagged),
                "features_sample": [item["feature"] for item in flagged],
            },
            issue_code="target_copy_detected",
        )
    else:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.LEAKAGE,
            status=CheckStatus.PASS,
            message="Target-copy detection completed without high-confidence copies.",
            details={"features_checked": len(stats)},
        )

    return summary


# -----------------------------------------------------------------------------
# Drift helpers
# -----------------------------------------------------------------------------


def _profile_from_feature_stats(feature_stats: Any) -> dict[str, Any]:
    """
    Convert feature statistics into a compact drift profile.

    The profile contains aggregate statistics only and never raw feature values.
    """
    if not isinstance(feature_stats, Mapping):
        return {}

    profile: dict[str, Any] = {}

    for feature, stats in feature_stats.items():
        feature = _canonical_field_name(feature)

        if not feature or not isinstance(stats, Mapping):
            continue

        item: dict[str, Any] = {
            "dtype": _enum_value(stats.get("dtype"), FeatureType.UNKNOWN.value),
            "missing_rate": _coerce_optional_float(stats.get("missing_rate"), allow_bool=False),
            "nonmissing_rate": _coerce_optional_float(stats.get("nonmissing_rate"), allow_bool=False),
        }

        numeric = stats.get("numeric")

        if isinstance(numeric, Mapping):
            item["numeric"] = {
                key: _coerce_optional_float(numeric.get(key), allow_bool=False)
                for key in (
                    "min",
                    "max",
                    "mean",
                    "std",
                    "p05",
                    "p25",
                    "p50",
                    "p75",
                    "p95",
                    "zero_rate",
                    "negative_rate",
                    "distinct",
                )
            }

        categorical = stats.get("categorical")

        if isinstance(categorical, Mapping):
            counts = categorical.get("category_counts_sample")
            normalized_counts: list[dict[str, Any]] = []

            if isinstance(counts, Sequence) and not isinstance(counts, (str, bytes, bytearray, memoryview)):
                for entry in counts[:_DEFAULT_MAX_SUMMARY_ITEMS]:
                    if not isinstance(entry, Mapping):
                        continue

                    category = _normalize_token(entry.get("category")) or _clean_text(entry.get("category"), 128)
                    count = _coerce_optional_float(entry.get("count"), allow_bool=False)

                    if category and count is not None and count > 0:
                        normalized_counts.append({"category": category, "count": _round6(float(count))})

            item["categorical"] = {
                "distinct": _coerce_optional_float(categorical.get("distinct"), allow_bool=False),
                "top_category_share": _coerce_optional_float(
                    categorical.get("top_category_share"),
                    allow_bool=False,
                ),
                "entropy": _coerce_optional_float(categorical.get("entropy"), allow_bool=False),
                "hhi": _coerce_optional_float(categorical.get("hhi"), allow_bool=False),
                "category_counts_sample": normalized_counts,
                "truncated": _as_bool(categorical.get("category_counts_truncated"), False)
                or _as_bool(categorical.get("distinct_truncated"), False),
            }

        boolean = stats.get("boolean")

        if isinstance(boolean, Mapping):
            item["boolean"] = {
                "true_rate": _coerce_optional_float(boolean.get("true_rate"), allow_bool=False),
            }

        profile[feature] = item

    return profile


def _normalize_reference_profile(reference_profile: Any) -> dict[str, Any]:
    """
    Normalize supported reference profile shapes.
    """
    if reference_profile is None:
        return {}

    if isinstance(reference_profile, Mapping):
        for key in ("feature_stats", "profile", "stats", "summary"):
            if key in reference_profile:
                return _profile_from_feature_stats(reference_profile[key])

        if any(
            isinstance(value, Mapping)
            and ("dtype" in value or "numeric" in value or "categorical" in value)
            for value in reference_profile.values()
        ):
            return _profile_from_feature_stats(reference_profile)

    summary = _safe_summary_from_object(reference_profile)

    if summary:
        return _normalize_reference_profile(summary)

    return {}


def _numeric_drift_score(current: Mapping[str, Any], reference: Mapping[str, Any]) -> Optional[float]:
    """
    Compute bounded numeric distribution drift score.

    This is a summary-based approximation, not a raw-sample PSI.
    """
    cur = current.get("numeric")
    ref = reference.get("numeric")

    if not isinstance(cur, Mapping) or not isinstance(ref, Mapping):
        return None

    cur_mean = _coerce_optional_float(cur.get("mean"), allow_bool=False)
    ref_mean = _coerce_optional_float(ref.get("mean"), allow_bool=False)
    cur_std = _coerce_optional_float(cur.get("std"), allow_bool=False)
    ref_std = _coerce_optional_float(ref.get("std"), allow_bool=False)

    scores: list[float] = []

    if cur_mean is not None and ref_mean is not None:
        cur_std_value = float(cur_std) if cur_std is not None else 0.0
        ref_std_value = float(ref_std) if ref_std is not None else 0.0
        denom = math.sqrt(cur_std_value * cur_std_value + ref_std_value * ref_std_value + 1e-12)
        z = abs(float(cur_mean) - float(ref_mean)) / denom
        scores.append(min(1.0, z / 3.0))

    if cur_std is not None and ref_std is not None and float(ref_std) > 0:
        ratio = abs(math.log((float(cur_std) + 1e-12) / (float(ref_std) + 1e-12)))
        scores.append(min(1.0, ratio / 2.0))

    quantile_keys = ("p05", "p25", "p50", "p75", "p95")
    q_scores: list[float] = []

    cur_iqr = None

    if cur.get("p75") is not None and cur.get("p25") is not None:
        cur_iqr = abs(float(cur["p75"]) - float(cur["p25"]))

    ref_iqr = None

    if ref.get("p75") is not None and ref.get("p25") is not None:
        ref_iqr = abs(float(ref["p75"]) - float(ref["p25"]))

    scale_candidates = [
        value
        for value in (cur_iqr, ref_iqr, cur_std, ref_std)
        if value is not None and float(value) > 0
    ]
    scale = max(scale_candidates) if scale_candidates else 1.0

    for key in quantile_keys:
        cur_value = _coerce_optional_float(cur.get(key), allow_bool=False)
        ref_value = _coerce_optional_float(ref.get(key), allow_bool=False)

        if cur_value is None or ref_value is None:
            continue

        q_scores.append(abs(float(cur_value) - float(ref_value)) / max(float(scale), 1e-6))

    if q_scores:
        scores.append(min(1.0, _mean(q_scores)))

    if not scores:
        cur_min = _coerce_optional_float(cur.get("min"), allow_bool=False)
        cur_max = _coerce_optional_float(cur.get("max"), allow_bool=False)
        ref_min = _coerce_optional_float(ref.get("min"), allow_bool=False)
        ref_max = _coerce_optional_float(ref.get("max"), allow_bool=False)

        if None not in (cur_min, cur_max, ref_min, ref_max):
            cur_range = max(float(cur_max) - float(cur_min), 1e-6)
            ref_range = max(float(ref_max) - float(ref_min), 1e-6)
            midpoint_shift = abs(
                (float(cur_min) + float(cur_max)) / 2.0
                - (float(ref_min) + float(ref_max)) / 2.0
            ) / max(cur_range, ref_range)
            range_shift = abs(cur_range - ref_range) / max(cur_range, ref_range)
            scores.append(min(1.0, max(midpoint_shift, range_shift)))

    if not scores:
        return None

    return _round6(max(scores))


def _categorical_drift_score(
    current: Mapping[str, Any],
    reference: Mapping[str, Any],
) -> tuple[Optional[float], bool]:
    """
    Compute bounded categorical PSI-like drift score.

    Returns `(score, approximate)`.
    """
    cur = current.get("categorical")
    ref = reference.get("categorical")

    if not isinstance(cur, Mapping) or not isinstance(ref, Mapping):
        return None, False

    approximate = bool(cur.get("truncated")) or bool(ref.get("truncated"))

    cur_counts = Counter()
    ref_counts = Counter()

    for entry in cur.get("category_counts_sample") or ():
        if isinstance(entry, Mapping):
            category = _normalize_token(entry.get("category")) or _clean_text(entry.get("category"), 128)
            count = _coerce_optional_float(entry.get("count"), allow_bool=False)

            if category and count is not None and count > 0:
                cur_counts[category] += float(count)

    for entry in ref.get("category_counts_sample") or ():
        if isinstance(entry, Mapping):
            category = _normalize_token(entry.get("category")) or _clean_text(entry.get("category"), 128)
            count = _coerce_optional_float(entry.get("count"), allow_bool=False)

            if category and count is not None and count > 0:
                ref_counts[category] += float(count)

    cur_total = sum(cur_counts.values())
    ref_total = sum(ref_counts.values())

    if cur_total <= 0 or ref_total <= 0:
        return None, approximate

    categories = set(cur_counts) | set(ref_counts)
    eps = 1e-6
    psi = 0.0

    for category in categories:
        p = (float(cur_counts.get(category, 0.0)) + eps) / (cur_total + eps * len(categories))
        q = (float(ref_counts.get(category, 0.0)) + eps) / (ref_total + eps * len(categories))
        psi += (p - q) * math.log(p / q)

    return _round6(min(2.0, max(0.0, psi))), approximate


def _compute_drift(
    feature_stats: Mapping[str, Any],
    reference_profile: Any,
    options: ValidationOptions,
) -> dict[str, Any]:
    """
    Compute bounded distribution drift diagnostics.

    Drift diagnostics are operational monitoring artefacts only. They are not
    proof of model degradation or wrongdoing.
    """
    if not feature_stats or reference_profile is None:
        return {
            "available": False,
            "reason": "reference_profile_or_stats_unavailable",
            "raw_values_retained": False,
        }

    current_profile = _profile_from_feature_stats(feature_stats)
    reference = _normalize_reference_profile(reference_profile)

    if not current_profile or not reference:
        return {
            "available": False,
            "reason": "profile_unavailable",
            "raw_values_retained": False,
        }

    scores: list[dict[str, Any]] = []
    compared = 0
    missing_reference = 0
    warn_count = 0
    fail_count = 0

    for feature, current in current_profile.items():
        reference_item = reference.get(feature)

        if not isinstance(reference_item, Mapping):
            missing_reference += 1
            continue

        compared += 1
        numeric_score = _numeric_drift_score(current, reference_item)
        categorical_score, approximate = _categorical_drift_score(current, reference_item)
        boolean_cur = current.get("boolean")
        boolean_ref = reference_item.get("boolean")
        boolean_score = None

        if isinstance(boolean_cur, Mapping) and isinstance(boolean_ref, Mapping):
            cur_rate = _coerce_optional_float(boolean_cur.get("true_rate"), allow_bool=False)
            ref_rate = _coerce_optional_float(boolean_ref.get("true_rate"), allow_bool=False)

            if cur_rate is not None and ref_rate is not None:
                boolean_score = _round6(min(1.0, abs(float(cur_rate) - float(ref_rate)) * 2.0))

        candidate_scores = [
            value
            for value in (numeric_score, categorical_score, boolean_score)
            if value is not None
        ]

        if not candidate_scores:
            continue

        score = _round6(max(candidate_scores))
        level = "PASS"

        if score >= options.drift_fail:
            level = "FAIL"
            fail_count += 1
        elif score >= options.drift_warn:
            level = "WARN"
            warn_count += 1

        scores.append(
            {
                "feature": feature,
                "score": score,
                "level": level,
                "numeric_score": numeric_score,
                "categorical_score": categorical_score,
                "boolean_score": boolean_score,
                "approximate": bool(approximate),
            }
        )

    scores.sort(key=lambda item: (-float(item["score"]), str(item["feature"])))
    top = scores[: options.max_summary_items]
    max_score = float(scores[0]["score"]) if scores else None

    return {
        "available": compared > 0,
        "method": "summary_based_approximation",
        "compared_features": compared,
        "missing_reference_features": missing_reference,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "max_score": _round6(max_score) if max_score is not None else None,
        "drift_warn": _round6(options.drift_warn),
        "drift_fail": _round6(options.drift_fail),
        "top_features": top,
        "truncated": len(scores) > options.max_summary_items,
        "raw_values_retained": False,
    }


def _validate_drift(
    drift: Mapping[str, Any],
    options: ValidationOptions,
    checks: list[ValidationCheck],
    issues: list[ValidationIssue],
) -> None:
    """
    Record bounded drift validation checks.
    """
    if not drift or not drift.get("available"):
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DRIFT,
            status=CheckStatus.SKIP,
            message="Drift analysis unavailable.",
            details=_safe_detail_value(drift) or {},
        )
        return

    fail_count = int(drift.get("fail_count", 0))
    warn_count = int(drift.get("warn_count", 0))

    if fail_count > 0:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DRIFT,
            status=(
                CheckStatus.FAIL
                if options.drift_policy == PolicyAction.REJECT
                else CheckStatus.WARN
            ),
            message="Features exceed configured hard drift failure threshold.",
            details={
                "fail_count": fail_count,
                "drift_fail": _round6(options.drift_fail),
                "top_features": drift.get("top_features", [])[: options.max_summary_items],
            },
            issue_code="drift_fail",
        )
    elif warn_count > 0:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DRIFT,
            status=CheckStatus.WARN,
            message="Features exceed configured drift warning threshold.",
            details={
                "warn_count": warn_count,
                "drift_warn": _round6(options.drift_warn),
                "top_features": drift.get("top_features", [])[: options.max_summary_items],
            },
            issue_code="drift_warn",
        )
    else:
        _record_check(
            checks,
            issues,
            options,
            category=ValidationCategory.DRIFT,
            status=CheckStatus.PASS,
            message="Drift analysis completed within configured thresholds.",
            details={
                "compared_features": int(drift.get("compared_features", 0)),
                "max_score": drift.get("max_score"),
            },
        )


# -----------------------------------------------------------------------------
# Privacy and leakage summaries
# -----------------------------------------------------------------------------


def _privacy_summary(
    cell_counts: _CellCounts,
    schemas: Mapping[str, FeatureSchema],
    options: ValidationOptions,
) -> dict[str, Any]:
    """
    Return bounded privacy posture summary.

    Raw values are never retained.
    """
    return {
        "available": True,
        "scan_enabled": bool(options.include_privacy_scan),
        "policy": options.privacy_policy.value,
        "flagged_cells": int(cell_counts.privacy_flags),
        "dropped_cells": int(cell_counts.dropped_cells),
        "privacy_sensitive_schema_count": sum(
            1
            for schema in schemas.values()
            if schema.privacy_sensitive
        ),
        "raw_values_retained": False,
        "narratives_retained": False,
        "identifiers_retained": False,
        "secrets_retained": False,
    }


def _leakage_summary(
    cell_counts: _CellCounts,
    schemas: Mapping[str, FeatureSchema],
    target_copy: Mapping[str, Any],
    model_summary: Mapping[str, Any],
    options: ValidationOptions,
) -> dict[str, Any]:
    """
    Return bounded leakage posture summary.

    Raw values and subject-label pairs are never retained.
    """
    leakage_features = [
        name
        for name, schema in schemas.items()
        if schema.leakage_sensitive
    ]
    leakage_features.sort()

    return {
        "available": True,
        "policy": options.leakage_policy.value,
        "flagged_feature_cells": int(cell_counts.leakage_flags),
        "rejected_records": int(cell_counts.rejected_records),
        "schema_leakage_sensitive_count": len(leakage_features),
        "schema_leakage_sensitive_sample": leakage_features[: options.max_summary_items],
        "schema_leakage_sensitive_truncated": len(leakage_features) > options.max_summary_items,
        "target_copy_flagged_count": int(target_copy.get("flagged_count", 0)) if isinstance(target_copy, Mapping) else 0,
        "model_leakage_sensitive_feature_count": (
            int(model_summary.get("leakage_sensitive_feature_count", 0))
            if isinstance(model_summary, Mapping)
            else 0
        ),
        "labels_used_as_features_detected": bool(
            int(cell_counts.leakage_flags) > 0
            or (isinstance(target_copy, Mapping) and int(target_copy.get("flagged_count", 0)) > 0)
            or (isinstance(model_summary, Mapping) and int(model_summary.get("leakage_sensitive_feature_count", 0)) > 0)
        ),
        "raw_values_retained": False,
        "subject_label_pairs_retained": False,
    }


# -----------------------------------------------------------------------------
# Fingerprint and status helpers
# -----------------------------------------------------------------------------


def _records_feature_names(records: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    """
    Return sorted observed feature names from validated records.
    """
    observed: set[str] = set()

    for record in records:
        features = record.get("features")

        if isinstance(features, Mapping):
            observed.update(
                _canonical_field_name(key)
                for key in features
                if _canonical_field_name(key)
            )

    return tuple(sorted(observed))


def _input_fingerprint(
    records: Sequence[Mapping[str, Any]],
    label_index: _LabelIndex,
) -> str:
    """
    Return deterministic safe input fingerprint.

    The fingerprint is derived from aggregate structure only and never from raw
    feature values or subject-label pairs.
    """
    feature_names = _records_feature_names(records)
    labels = _label_summary(label_index)

    payload = {
        "version": VALIDATION_VERSION,
        "record_count": len(records),
        "feature_count": len(feature_names),
        "feature_names_sample": list(feature_names[:_DEFAULT_MAX_SUMMARY_ITEMS]),
        "feature_names_truncated": len(feature_names) > _DEFAULT_MAX_SUMMARY_ITEMS,
        "label_summary": labels,
    }

    return _fingerprint_payload(payload)


def _initial_request_id(
    request: ValidationRequest,
    options: ValidationOptions,
    dataset_role: DatasetRole,
) -> str:
    """
    Return a preliminary request id before full input fingerprint is available.
    """
    if request.request_id:
        return request.request_id

    if request.idempotency_key:
        return _sha256_hex(
            f"{options.namespace}|{dataset_role.value}|{request.idempotency_key}"
        )[:32]

    payload = {
        "version": VALIDATION_VERSION,
        "stage": "initial",
        "dataset_role": dataset_role.value,
        "options": options.safe_summary(),
        "metadata": _safe_detail_value(request.metadata),
        "tags": list(request.tags),
        "threshold": request.threshold,
    }

    return _sha256_hex(_canonical_json(payload))[:32]


def _derive_request_id(
    request: ValidationRequest,
    options: ValidationOptions,
    dataset_role: DatasetRole,
    input_fp: str,
) -> str:
    """
    Return deterministic final request id.
    """
    if request.request_id:
        return request.request_id

    if request.idempotency_key:
        return _sha256_hex(
            f"{options.namespace}|{dataset_role.value}|{request.idempotency_key}|{input_fp}"
        )[:32]

    payload = {
        "version": VALIDATION_VERSION,
        "dataset_role": dataset_role.value,
        "options": options.safe_summary(),
        "metadata": _safe_detail_value(request.metadata),
        "tags": list(request.tags),
        "threshold": request.threshold,
        "input_fingerprint": input_fp,
    }

    return _sha256_hex(_canonical_json(payload))[:32]


def _finalize_status(
    checks: Sequence[ValidationCheck],
    issues: Sequence[ValidationIssue],
    options: ValidationOptions,
) -> ValidationStatus:
    """
    Derive bounded overall validation status.
    """
    if any(check.status == CheckStatus.FAIL for check in checks) or _has_error(issues):
        return ValidationStatus.FAILED

    if (
        any(check.status == CheckStatus.WARN for check in checks)
        or any(issue.severity == IssueSeverity.WARNING for issue in issues)
    ):
        return ValidationStatus.DEGRADED

    return ValidationStatus.PASSED


# -----------------------------------------------------------------------------
# Validation harness
# -----------------------------------------------------------------------------


class ValidationHarness:
    """
    Bounded deterministic synthetic ML validation harness.

    This harness validates synthetic feature records, schemas, labels, splits,
    predictions, model metadata, privacy posture, leakage posture, duplicates,
    target-copy risks, and bounded distribution drift.

    It does not train models, deploy models, evaluate models as authoritative
    truth, persist durable artefacts, call external systems, or take adverse
    action.
    """

    def __init__(self, options: ValidationOptions | None = None) -> None:
        self.options = options or ValidationOptions.from_settings()
        self._lock = threading.RLock()

    def validate(self, request: Any) -> ValidationReport:
        """
        Run one bounded synthetic ML validation job.
        """
        opts = self.options
        checks: list[ValidationCheck] = []
        issues: list[ValidationIssue] = []

        generated_at = _now_utc()
        start_time = time.monotonic()

        req = _coerce_request(request)
        dataset_role = _normalize_enum_option(
            DatasetRole,
            req.dataset_role or opts.dataset_role,
            DatasetRole.UNKNOWN,
        )
        threshold = req.threshold if req.threshold is not None else opts.threshold
        request_id = _initial_request_id(req, opts, dataset_role)

        def make_report(
            status: ValidationStatus,
            counts: Optional[Mapping[str, int]] = None,
            **sections: Any,
        ) -> ValidationReport:
            """
            Build and optionally register one safe validation report.
            """
            resolved_counts = {
                "checks": len(checks),
                "issues": len(issues),
                **{
                    str(key): max(0, _as_int(value, 0))
                    for key, value in (counts or {}).items()
                },
            }

            metadata = {
                "validation_version": VALIDATION_VERSION,
                "request_id": request_id,
                "dataset_role": dataset_role.value,
                "threshold": _round6(threshold),
                "options": opts.safe_summary(),
                "elapsed_ms": _elapsed_ms(start_time),
                "registry_backend": "process_local_in_memory",
                "registry_durable": False,
                "registry_distributed": False,
                "raw_values_retained": False,
                "subject_label_pairs_retained": False,
                "narratives_retained": False,
                "identifiers_retained": False,
                "secrets_retained": False,
                "model_artifact_paths_retained": False,
                "caveats": list(_VALIDATION_CAVEATS),
                "safety_flags": dict(_VALIDATION_SAFETY_FLAGS),
            }

            report = ValidationReport(
                ok=status in {ValidationStatus.PASSED, ValidationStatus.DEGRADED},
                status=status,
                request_id=request_id,
                dataset_role=dataset_role,
                generated_at=generated_at,
                duration_ms=_elapsed_ms(start_time),
                counts=resolved_counts,
                checks=tuple(checks[: opts.max_checks]),
                issues=tuple(issues[: opts.max_issues]),
                schema_summary=sections.get("schema_summary", {}),
                feature_stats=sections.get("feature_stats", {}),
                label_stats=sections.get("label_stats", {}),
                split_stats=sections.get("split_stats", {}),
                prediction_stats=sections.get("prediction_stats", {}),
                privacy=sections.get("privacy", {}),
                leakage=sections.get("leakage", {}),
                duplicates=sections.get("duplicates", {}),
                drift=sections.get("drift", {}),
                model_summary=sections.get("model_summary", {}),
                metadata=metadata,
                fingerprint="",
            )

            if opts.register_reports:
                try:
                    get_validation_registry(opts.max_reports).register(report)
                except Exception as exc:
                    _record_check(
                        checks,
                        issues,
                        opts,
                        category=ValidationCategory.FINALIZE,
                        # A WARN, not a failure: the validation itself
                        # completed and only its registration in the in-memory
                        # registry did not, so the report is still returned to
                        # the caller. (`CheckStatus` has no ERROR member; this
                        # line previously read `CheckStatus.ERROR if False else
                        # CheckStatus.WARN`, which only avoided an
                        # AttributeError because the branch was unreachable.)
                        status=CheckStatus.WARN,
                        message="Validation report registration failed.",
                        details={"exception_type": type(exc).__name__},
                        issue_code="validation_report_registration_failed",
                    )

            return report

        # ------------------------------------------------------------------
        # Policy gate
        # ------------------------------------------------------------------

        if not opts.enabled:
            _record_check(
                checks,
                issues,
                opts,
                category=ValidationCategory.POLICY,
                status=CheckStatus.SKIP,
                message="ML validation harness is disabled.",
                issue_code="validation_disabled",
                issue_severity=IssueSeverity.INFO,
            )
            return make_report(ValidationStatus.BLOCKED, {"submitted": 0, "processed": 0})

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _record_check(
                checks,
                issues,
                opts,
                category=ValidationCategory.POLICY,
                status=CheckStatus.FAIL,
                message="ML validation harness requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
                issue_code="non_synthetic_dataset",
            )
            return make_report(ValidationStatus.BLOCKED, {"submitted": 0, "processed": 0})

        if opts.production_like and not opts.allow_in_production:
            _record_check(
                checks,
                issues,
                opts,
                category=ValidationCategory.POLICY,
                status=CheckStatus.FAIL,
                message="ML validation harness is blocked in production-like environments.",
                issue_code="production_like_blocked",
            )
            return make_report(ValidationStatus.BLOCKED, {"submitted": 0, "processed": 0})

        # ------------------------------------------------------------------
        # Input bounding
        # ------------------------------------------------------------------

        raw_records = _iter_records(req.features)
        submitted = len(raw_records)

        max_records_by_cells = max(
            1,
            int(opts.max_cells) // max(1, int(opts.max_features)),
        )
        limit = min(int(opts.max_records), max_records_by_cells)

        if submitted > limit:
            _record_check(
                checks,
                issues,
                opts,
                category=ValidationCategory.POLICY,
                status=CheckStatus.WARN,
                message="Validation input exceeded configured bounds and was truncated.",
                details={
                    "submitted": submitted,
                    "limit": limit,
                    "max_records": opts.max_records,
                    "max_cells": opts.max_cells,
                    "max_features": opts.max_features,
                },
                issue_code="validation_input_truncated",
            )
            raw_records = raw_records[:limit]

        if not raw_records:
            _record_check(
                checks,
                issues,
                opts,
                category=ValidationCategory.COMPLETENESS,
                status=CheckStatus.FAIL,
                message="Validation feature input is empty.",
                issue_code="empty_feature_input",
            )
            return make_report(ValidationStatus.FAILED, {"submitted": submitted, "processed": 0})

        # ------------------------------------------------------------------
        # Schema resolution
        # ------------------------------------------------------------------

        schemas = _resolve_schema(req.schema, raw_records, opts, checks, issues)
        schema_summary = _schema_summary(schemas, opts)

        # ------------------------------------------------------------------
        # Record validation
        # ------------------------------------------------------------------

        cleaned, cell_counts = _validate_and_normalize_records(
            raw_records,
            schemas,
            opts,
            checks,
            issues,
        )

        if not cleaned:
            _record_check(
                checks,
                issues,
                opts,
                category=ValidationCategory.COMPLETENESS,
                status=CheckStatus.FAIL,
                message="No valid records remained after validation.",
                issue_code="no_valid_records",
            )
            return make_report(
                ValidationStatus.FAILED,
                {
                    "submitted": submitted,
                    "processed": len(raw_records),
                    "valid_records": 0,
                    "rejected_records": cell_counts.rejected_records,
                    "features": len(schemas),
                    "cells_total": cell_counts.total,
                    "missing_cells": cell_counts.missing,
                    "invalid_type_cells": cell_counts.invalid_type,
                    "out_of_range_cells": cell_counts.out_of_range,
                    "invalid_category_cells": cell_counts.invalid_category,
                    "privacy_flagged_cells": cell_counts.privacy_flags,
                    "leakage_flagged_cells": cell_counts.leakage_flags,
                    "unknown_feature_cells": cell_counts.unknown_features,
                    "dropped_cells": cell_counts.dropped_cells,
                },
                schema_summary=schema_summary,
                privacy=_privacy_summary(cell_counts, schemas, opts),
                leakage=_leakage_summary(
                    cell_counts,
                    schemas,
                    {"available": False, "flagged_count": 0},
                    {"available": False},
                    opts,
                ),
            )

        # ------------------------------------------------------------------
        # Feature statistics
        # ------------------------------------------------------------------

        feature_stats = (
            _aggregate_feature_stats(cleaned, schemas, opts)
            if opts.include_stats
            else {}
        )

        if opts.include_stats:
            _validate_feature_stats(feature_stats, schemas, opts, checks, issues)
        else:
            _record_check(
                checks,
                issues,
                opts,
                category=ValidationCategory.DISTRIBUTION,
                status=CheckStatus.SKIP,
                message="Feature statistics disabled by policy.",
            )

        # ------------------------------------------------------------------
        # Labels and splits
        # ------------------------------------------------------------------

        label_index = _build_label_index(req.labels, len(cleaned), opts)
        label_stats = _validate_labels(label_index, len(cleaned), opts, checks, issues)
        split_stats = _validate_splits(label_index, len(cleaned), opts, checks, issues)

        # ------------------------------------------------------------------
        # Predictions
        # ------------------------------------------------------------------

        prediction_index = _build_prediction_index(req.predictions, len(cleaned), opts)
        prediction_stats = _validate_predictions(
            cleaned,
            label_index,
            prediction_index,
            opts,
            checks,
            issues,
        )

        # ------------------------------------------------------------------
        # Model metadata
        # ------------------------------------------------------------------

        model_summary = _validate_model(req.model, schemas, opts, checks, issues)

        # ------------------------------------------------------------------
        # Duplicates and target copy
        # ------------------------------------------------------------------

        duplicates = (
            _detect_duplicates(cleaned, opts, checks, issues)
            if opts.include_duplicates
            else {"available": False, "reason": "disabled_by_policy", "raw_values_retained": False}
        )

        target_copy = (
            _detect_target_copy(cleaned, label_index, opts, checks, issues)
            if opts.include_target_copy_scan
            else {"available": False, "reason": "disabled_by_policy", "raw_values_retained": False}
        )

        # ------------------------------------------------------------------
        # Privacy and leakage summaries
        # ------------------------------------------------------------------

        privacy = _privacy_summary(cell_counts, schemas, opts)
        leakage = _leakage_summary(cell_counts, schemas, target_copy, model_summary, opts)

        # ------------------------------------------------------------------
        # Drift
        # ------------------------------------------------------------------

        if opts.include_drift and req.reference_profile is not None and feature_stats:
            drift = _compute_drift(feature_stats, req.reference_profile, opts)
            _validate_drift(drift, opts, checks, issues)
        else:
            drift = {
                "available": False,
                "reason": (
                    "disabled_by_policy"
                    if not opts.include_drift
                    else "reference_profile_or_stats_unavailable"
                ),
                "raw_values_retained": False,
            }
            _record_check(
                checks,
                issues,
                opts,
                category=ValidationCategory.DRIFT,
                status=CheckStatus.SKIP,
                message="Drift analysis skipped.",
                details=drift,
            )

        # ------------------------------------------------------------------
        # Finalize
        # ------------------------------------------------------------------

        input_fp = _input_fingerprint(cleaned, label_index)
        request_id = _derive_request_id(req, opts, dataset_role, input_fp)

        counts = {
            "submitted": submitted,
            "processed": len(raw_records),
            "valid_records": len(cleaned),
            "rejected_records": cell_counts.rejected_records,
            "features": len(schemas),
            "cells_total": cell_counts.total,
            "missing_cells": cell_counts.missing,
            "invalid_type_cells": cell_counts.invalid_type,
            "out_of_range_cells": cell_counts.out_of_range,
            "invalid_category_cells": cell_counts.invalid_category,
            "privacy_flagged_cells": cell_counts.privacy_flags,
            "leakage_flagged_cells": cell_counts.leakage_flags,
            "unknown_feature_cells": cell_counts.unknown_features,
            "dropped_cells": cell_counts.dropped_cells,
            "labels": int(label_stats.get("label_count", 0)),
            "predictions_submitted": int(prediction_stats.get("submitted", 0)),
            "predictions_matched": int(prediction_stats.get("matched", 0)),
            "duplicates": int(duplicates.get("duplicate_rows", 0)) if isinstance(duplicates, Mapping) else 0,
            "target_copy_flags": int(target_copy.get("flagged_count", 0)) if isinstance(target_copy, Mapping) else 0,
            "drift_features_compared": int(drift.get("compared_features", 0)) if isinstance(drift, Mapping) else 0,
        }

        status = _finalize_status(checks, issues, opts)

        return make_report(
            status,
            counts,
            schema_summary=schema_summary,
            feature_stats=feature_stats,
            label_stats=label_stats,
            split_stats=split_stats,
            prediction_stats=prediction_stats,
            privacy=privacy,
            leakage=leakage,
            duplicates=duplicates,
            drift=drift,
            model_summary=model_summary,
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe harness summary.
        """
        return {
            "options": self.options.safe_summary(),
            "registry": get_validation_registry(self.options.max_reports).safe_summary(
                limit=self.options.max_summary_items
            ),
            "caveats": list(_VALIDATION_CAVEATS),
            "safety_flags": dict(_VALIDATION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default harness and public API
# -----------------------------------------------------------------------------


_default_harness: Optional[ValidationHarness] = None
_default_harness_lock = threading.Lock()


def get_validation_options(settings: Any | None = None) -> ValidationOptions:
    """
    Return validation options from settings.
    """
    return ValidationOptions.from_settings(settings)


def get_validation_harness(
    options: ValidationOptions | None = None,
    *,
    rebuild: bool = False,
) -> ValidationHarness:
    """
    Return a process-wide validation harness.

    If options are supplied or rebuild is True, a new harness is created and
    becomes the default.
    """
    global _default_harness

    with _default_harness_lock:
        if _default_harness is None or rebuild or options is not None:
            _default_harness = ValidationHarness(
                options=options or ValidationOptions.from_settings()
            )

        return _default_harness


def validate_ml(
    request: Any,
    options: ValidationOptions | None = None,
    *,
    harness: ValidationHarness | None = None,
) -> ValidationReport:
    """
    Run one bounded synthetic ML validation job.
    """
    active_harness = harness or get_validation_harness(options)
    return active_harness.validate(request)


def validate_records(
    records: Any,
    labels: Any = None,
    predictions: Any = None,
    model: Any = None,
    schema: Any = None,
    reference_profile: Any = None,
    options: ValidationOptions | None = None,
    *,
    harness: ValidationHarness | None = None,
    **kwargs: Any,
) -> ValidationReport:
    """
    Convenience helper for validating records with optional labels,
    predictions, model metadata, schema, and reference profile.
    """
    request = ValidationRequest(
        features=records,
        labels=labels,
        predictions=predictions,
        model=model,
        schema=schema,
        reference_profile=reference_profile,
        **kwargs,
    )
    return validate_ml(request, options=options, harness=harness)


def get_validation_report(request_id: Any) -> Optional[ValidationReport]:
    """
    Return one registered validation report.
    """
    return get_validation_registry().get_report(request_id)


def list_validation_reports(*, limit: int = 50) -> tuple[ValidationReport, ...]:
    """
    Return registered validation reports.
    """
    return get_validation_registry().list_reports(limit=limit)


def summarize_validation_reports(*, limit: int = 50) -> list[dict[str, Any]]:
    """
    Return safe registered validation report summaries.
    """
    return get_validation_registry().summarize(limit=limit)


def get_validation_metadata() -> dict[str, Any]:
    """
    Return safe, serializable validation harness metadata.

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
    options = ValidationOptions.from_settings()
    registry = get_validation_registry(options.max_reports)

    return {
        "package": "muleguard.backend.ml.validation",
        "version": VALIDATION_VERSION,
        "feature_types": [dtype.value for dtype in FeatureType],
        "dataset_roles": [role.value for role in DatasetRole],
        "policy_actions": [action.value for action in PolicyAction],
        "validation_statuses": [status.value for status in ValidationStatus],
        "check_statuses": [status.value for status in CheckStatus],
        "validation_categories": [category.value for category in ValidationCategory],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "registry": registry.safe_summary(limit=options.max_summary_items),
        "hard_limits": {
            "max_records": _HARD_MAX_RECORDS,
            "max_features": _HARD_MAX_FEATURES,
            "max_cells": _HARD_MAX_CELLS,
            "max_issues": _HARD_MAX_ISSUES,
            "max_checks": _HARD_MAX_CHECKS,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_categories": _HARD_MAX_CATEGORIES,
            "max_numeric_sample": _HARD_MAX_NUMERIC_SAMPLE,
            "max_distinct_tracked": _HARD_MAX_DISTINCT_TRACKED,
            "max_reports": _HARD_MAX_REPORTS,
            "max_time_ms": _HARD_MAX_TIME_MS,
        },
        "forbidden_validation_field_count": len(_FORBIDDEN_VALIDATION_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_VALIDATION_CAVEATS),
        "safety_flags": dict(_VALIDATION_SAFETY_FLAGS),
    }


__all__ = [
    "CheckStatus",
    "DatasetRole",
    "FeatureSchema",
    "FeatureType",
    "IssueSeverity",
    "PolicyAction",
    "ValidationCategory",
    "ValidationCheck",
    "ValidationHarness",
    "ValidationIssue",
    "ValidationOptions",
    "ValidationRegistry",
    "ValidationReport",
    "ValidationRequest",
    "ValidationStatus",
    "get_validation_harness",
    "get_validation_metadata",
    "get_validation_options",
    "get_validation_registry",
    "get_validation_report",
    "list_validation_reports",
    "summarize_validation_reports",
    "validate_ml",
    "validate_records",
]