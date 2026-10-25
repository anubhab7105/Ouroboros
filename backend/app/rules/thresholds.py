"""
MULEGUARD backend rules thresholds.

This module provides the canonical bounded threshold-policy layer for the
synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- select, calibrate, monitor, and apply safe operational thresholds for bounded
  synthetic rule scores, model probabilities, anomaly scores, fallback scores,
  and investigative prioritization signals;
- support deterministic threshold policies including fixed, quantile, Youden J,
  max-F1, constrained recall/FPR, constrained precision/recall, cost-sensitive,
  EWMA-adaptive, and hybrid policies;
- provide bounded stability estimation using deterministic bootstrap resampling;
- provide bounded distribution-drift diagnostics against safe reference score
  profiles;
- enforce strict product-safety constraints, including absolute prohibition of
  automatic adverse customer action;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values, raw identifiers, raw narratives, subject-label
  pairs, secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited score-record fields;
- maintain a bounded process-local threshold-profile registry for local
  prototype workflows, tests, developer tooling, and offline evaluation
  harnesses;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module selects and applies operational thresholds only. It does not train
models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for threshold calibration, monitoring, or
  debugging.
- Threshold outputs are investigative prioritization artefacts only. They are
  not proof of wrongdoing.
- Threshold scores and selected operating points are not probabilities of guilt.
- Labels may be used only as evaluation targets for bounded threshold selection.
  Labels must never be treated as score features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as score-record feature fields.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden inputs. Subject linkage is pseudonymous and
  salted.
- Threshold handling must never trigger automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable thresholds are reported honestly as unavailable
  rather than invented.
- The bundled threshold registry is process-local, non-durable, and bounded for
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
- This module is not a durable decisioning platform.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, rule scores,
threshold profiles, explanations, validation reports, and case dispositions are
investigative leads or human workflow artefacts only. They are not proof of
wrongdoing and must not trigger automatic adverse customer action.
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
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

try:
    from app.exceptions import ConfigurationError
    from app.exceptions import ValidationError as MuleGuardValidationError
except Exception:  # pragma: no cover - resilience for partial deployments

    class ConfigurationError(RuntimeError):
        """Fallback configuration error."""

        def __init__(self, message: str, *, details: Optional[Mapping[str, Any]] = None) -> None:
            super().__init__(message)
            self.details = dict(details or {})

    class MuleGuardValidationError(ValueError):
        """Fallback validation error."""

        def __init__(self, message: str, *, details: Optional[Mapping[str, Any]] = None) -> None:
            super().__init__(message)
            self.details = dict(details or {})


logger = logging.getLogger("muleguard.backend.rules.thresholds")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

THRESHOLD_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.rules.thresholds.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_OBSERVATIONS: Final[int] = 10_000
_HARD_MAX_OBSERVATIONS: Final[int] = 100_000

_DEFAULT_MAX_FIELDS: Final[int] = 256
_HARD_MAX_FIELDS: Final[int] = 4_096

_DEFAULT_MAX_CANDIDATES: Final[int] = 128
_HARD_MAX_CANDIDATES: Final[int] = 1_024

_DEFAULT_MAX_STABILITY_CANDIDATES: Final[int] = 64
_HARD_MAX_STABILITY_CANDIDATES: Final[int] = 256

_DEFAULT_STABILITY_REPEATS: Final[int] = 8
_HARD_MAX_STABILITY_REPEATS: Final[int] = 200
_DEFAULT_MIN_STABILITY_SAMPLES: Final[int] = 32
_DEFAULT_MAX_STABILITY_SAMPLE: Final[int] = 512
_HARD_MAX_STABILITY_SAMPLE: Final[int] = 5_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_PROFILES: Final[int] = 1_000
_HARD_MAX_PROFILES: Final[int] = 10_000

_DEFAULT_MAX_TIME_MS: Final[int] = 20_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_DEFAULT_THRESHOLD: Final[float] = 0.60
_DEFAULT_TARGET_POSITIVE_RATE: Final[float] = 0.05
_DEFAULT_MAX_FPR: Final[float] = 0.05
_DEFAULT_MIN_RECALL: Final[float] = 0.50
_DEFAULT_MIN_PRECISION: Final[float] = 0.50
_DEFAULT_COST_FP: Final[float] = 1.0
_DEFAULT_COST_FN: Final[float] = 1.0
_DEFAULT_EWMA_DECAY: Final[float] = 0.95

_DEFAULT_DRIFT_WARN: Final[float] = 0.10
_DEFAULT_DRIFT_FAIL: Final[float] = 0.25

_DEFAULT_QUANTILES: Final[tuple[float, ...]] = (
    0.01,
    0.05,
    0.25,
    0.50,
    0.75,
    0.95,
    0.99,
)

_DEFAULT_RISK_THRESHOLDS: Final[Mapping[str, float]] = MappingProxyType(
    {
        "low": 0.35,
        "medium": 0.55,
        "high": 0.75,
        "critical": 0.90,
    }
)

_DEFAULT_POLICY_WEIGHTS: Final[Mapping[str, float]] = MappingProxyType(
    {
        "recall": 0.25,
        "precision": 0.25,
        "f1": 0.20,
        "balanced_accuracy": 0.15,
        "you_j": 0.10,
        "fpr_penalty": 0.15,
    }
)

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256
_MAX_REASON_TEXT_LENGTH: Final[int] = 300
_THRESHOLD_EPS: Final[float] = 1e-6

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

_SCORE_KEYS: Final[tuple[str, ...]] = (
    "score",
    "probability",
    "positive_probability",
    "risk_score",
    "anomaly_score",
    "fallback_score",
    "model_score",
    "rule_score",
    "prediction",
    "y_score",
)

_LABEL_KEYS: Final[tuple[str, ...]] = (
    "label",
    "label_code",
    "target",
    "y",
    "ground_truth",
    "ground_truth_label",
    "truth_label",
    "fraud_label",
    "is_fraud",
    "synthetic_label",
)

_SPLIT_KEYS: Final[tuple[str, ...]] = (
    "split",
    "dataset_role",
    "fold",
    "partition",
)

_WEIGHT_KEYS: Final[tuple[str, ...]] = (
    "weight",
    "sample_weight",
    "importance_weight",
)

_NON_SCORE_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        "metadata",
        "metadata_json",
        "tags",
        "caveats",
        "safety_flags",
        "issues",
        "counts",
        "validation",
    }
)

_FORBIDDEN_THRESHOLD_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_THRESHOLD_TOKENS: Final[tuple[str, ...]] = (
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

_PROHIBITED_ACTION_TOKENS: Final[tuple[str, ...]] = (
    "freeze",
    "frozen",
    "block",
    "blocked",
    "blacklist",
    "close",
    "closed",
    "restrict",
    "restricted",
    "deny",
    "denied",
    "termination",
    "terminate",
    "suspend",
    "suspended",
    "punish",
    "punishment",
    "penalize",
    "penalty",
    "law_enforcement",
    "police",
    "arrest",
    "prosecute",
    "prosecution",
    "credit_decision",
    "employment_decision",
    "housing_decision",
    "insurance_decision",
    "benefit_decision",
    "adverse_action",
    "customer_harm",
    "automatic_action",
    "auto_action",
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

_THRESHOLD_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic threshold calibration only. Do not use with real customer data.",
    "Threshold profiles are operational prioritization artefacts only and are not proof of wrongdoing.",
    "Threshold scores and selected operating points are not probabilities of guilt.",
    "Threshold monitoring must not trigger automatic adverse customer action.",
    "Labels may be used only as evaluation targets, never as score features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected as score-record fields.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Unavailable thresholds are reported honestly as unavailable rather than invented.",
    "The bundled threshold registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_THRESHOLD_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_labels_as_score_features": True,
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
        "deterministic_threshold_selection": True,
        "bounded_threshold_selection_required": True,
        "thresholds_are_operational_prioritization_only": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class ThresholdPolicy(str, Enum):
    """
    Bounded threshold selection policy.
    """

    FIXED = "fixed"
    QUANTILE = "quantile"
    YOU_J = "you_j"
    MAX_F1 = "max_f1"
    MIN_RECALL_AT_FPR = "min_recall_at_fpr"
    MIN_PRECISION_AT_RECALL = "min_precision_at_recall"
    COST_SENSITIVE = "cost_sensitive"
    ADAPTIVE_EWMA = "adaptive_ewma"
    HYBRID = "hybrid"


class ThresholdStatus(str, Enum):
    """
    Threshold profile status.
    """

    PASSED = "PASSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


class ThresholdSource(str, Enum):
    """
    Threshold profile source.
    """

    REQUEST = "request"
    SYNTHETIC_PROFILE = "synthetic_profile"
    BUILTIN = "builtin"
    IMPORTED = "imported"
    DERIVED = "derived"


class ScoreKind(str, Enum):
    """
    Operational score kind.
    """

    GENERIC = "generic"
    PROBABILITY = "probability"
    RISK_SCORE = "risk_score"
    ANOMALY_SCORE = "anomaly_score"
    FALLBACK_SCORE = "fallback_score"
    RULE_SCORE = "rule_score"


class RiskBand(str, Enum):
    """
    Operational risk band.
    """

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNAVAILABLE = "unavailable"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


_LABEL_DEPENDENT_POLICIES: Final[frozenset[ThresholdPolicy]] = frozenset(
    {
        ThresholdPolicy.YOU_J,
        ThresholdPolicy.MAX_F1,
        ThresholdPolicy.MIN_RECALL_AT_FPR,
        ThresholdPolicy.MIN_PRECISION_AT_RECALL,
        ThresholdPolicy.COST_SENSITIVE,
        ThresholdPolicy.HYBRID,
    }
)


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

    if parsed < minimum:
        return minimum

    if parsed > maximum:
        return maximum

    return parsed


def _clamp_float(value: object, minimum: float, maximum: float, default: float) -> float:
    parsed = _as_float(value, default)

    if parsed < minimum:
        return minimum

    if parsed > maximum:
        return maximum

    return parsed


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

    if canonical in _FORBIDDEN_THRESHOLD_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_THRESHOLD_TOKENS)


def _is_label_leakage_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _LABEL_LEAKAGE_FIELDS:
        return True

    return any(token in canonical for token in _LABEL_LEAKAGE_TOKENS)


def _is_forbidden_score_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _SUBJECT_KEYS:
        return False

    if _is_label_leakage_key(canonical):
        return False

    return _is_forbidden_key(canonical)


def _is_sensitive_detail_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    return any(token in canonical for token in _SENSITIVE_DETAIL_TOKENS)


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


def _looks_like_sensitive_literal(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    text = _clean_text(value, 2000)

    if not text:
        return False

    if _EMAIL_RE.search(text):
        return True

    if _UPI_RE.search(text):
        return True

    if _PHONE_IN_RE.search(text):
        return True

    if _PAN_RE.search(text):
        return True

    if _AADHAAR_RE.search(text):
        return True

    if _IPV4_RE.search(text):
        return True

    if _IFSC_RE.search(text):
        return True

    if _SECRET_ASSIGNMENT_RE.search(text):
        return True

    for candidate in _CARD_DIGITS_RE.findall(text):
        if _luhn_valid(candidate):
            return True

    if len(text) > 200 and text.count(" ") >= 10:
        return True

    return False


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
        text = _clean_text(value, 300)

        if not text:
            return None

        if _looks_like_sensitive_literal(text):
            return "[redacted]"

        return text

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


def _as_mapping(value: Any) -> dict[str, Any]:
    sanitized = _safe_detail_value(value)
    return sanitized if isinstance(sanitized, dict) else {}


def _safe_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    if not details:
        return {}

    return _as_mapping(details)


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


def _normalize_tags(value: Any, limit: int = 50) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        tag = _clean_text(item, 100)

        if tag:
            out.append(tag)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


def _normalize_quantile_tuple(value: Any, default: tuple[float, ...]) -> tuple[float, ...]:
    if value is None:
        return default

    out: list[float] = []

    for item in _as_sequence(value):
        q = _coerce_optional_float(item, allow_bool=False)

        if q is None:
            continue

        out.append(_round6(_clamp_float(q, 0.0, 1.0, 0.0)))

    if not out:
        return default

    return tuple(sorted(set(out)))


def _normalize_float_mapping(
    value: Any,
    default: Mapping[str, float],
    *,
    minimum: float = 0.0,
    maximum: float = 1.0,
) -> dict[str, float]:
    out = {
        str(key): _round6(_clamp_float(raw, minimum, maximum, minimum))
        for key, raw in dict(default).items()
    }

    if isinstance(value, Mapping):
        for raw_key, raw_value in value.items():
            key = _clean_text(raw_key, 100)

            if not key:
                continue

            numeric = _coerce_optional_float(raw_value, allow_bool=False)

            if numeric is None:
                continue

            out[key] = _round6(_clamp_float(numeric, minimum, maximum, minimum))

    return out


def _contains_prohibited_action(*values: Any) -> bool:
    parts: list[str] = []

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 3 or value is None:
            return

        if isinstance(value, Mapping):
            for raw_key, raw_value in list(value.items())[:100]:
                parts.append(str(raw_key))
                visit(raw_value, depth + 1)
            return

        if isinstance(value, (list, tuple, set, frozenset)):
            for item in list(value)[:100]:
                visit(item, depth + 1)
            return

        parts.append(str(value))

    for value in values:
        visit(value)

    text = " ".join(parts).lower()

    if not text:
        return False

    return any(token in text for token in _PROHIBITED_ACTION_TOKENS)


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


def _weighted_quantile(pairs: Sequence[tuple[float, float]], q: float) -> Optional[float]:
    cleaned = [
        (float(score), float(weight))
        for score, weight in pairs
        if score is not None and weight is not None and float(weight) > 0
    ]

    if not cleaned:
        return None

    cleaned.sort(key=lambda item: item[0])
    total = sum(weight for _score, weight in cleaned)

    if total <= 0:
        return None

    target = _clamp_float(q, 0.0, 1.0, 0.0) * total
    cumulative = 0.0

    for score, weight in cleaned:
        cumulative += weight

        if cumulative >= target - 1e-12:
            return _round6(score)

    return _round6(cleaned[-1][0])


def _time_exceeded(start_time: float, max_time_ms: int) -> bool:
    return (time.monotonic() - start_time) * 1000.0 > float(max(1, int(max_time_ms)))


def _elapsed_ms(start_time: float) -> int:
    return int((time.monotonic() - start_time) * 1000.0)


class _DetRandom:
    """
    Deterministic dependency-light pseudo-random generator.

    This is not cryptographically secure. It is used only for deterministic
    sampling and bootstrap resampling in bounded threshold workflows.
    """

    def __init__(self, salt: str, domain: str, *seed_parts: Any) -> None:
        self.salt = salt
        self.domain = domain
        self.seed_parts = seed_parts
        self.counter = 0

    def _rank(self, *extra: Any) -> int:
        self.counter += 1
        return _stable_rank(self.salt, self.domain, *self.seed_parts, self.counter, *extra)

    def random(self) -> float:
        rank = self._rank()
        return float(rank & ((1 << 53) - 1)) / float(1 << 53)

    def randrange(self, n: int) -> int:
        if n <= 0:
            return 0

        value = int(self.random() * float(n))

        if value >= n:
            value = n - 1

        return max(0, value)

    def shuffle(self, values: list[Any]) -> None:
        for i in range(len(values) - 1, 0, -1):
            j = self.randrange(i + 1)
            values[i], values[j] = values[j], values[i]


def _deterministic_sample_indices(
    n: int,
    count: int,
    options: "ThresholdOptions",
    domain: str,
    *parts: Any,
) -> list[int]:
    if n <= 0:
        return []

    count = max(0, min(int(count), n))

    if count >= n:
        return list(range(n))

    values = list(range(n))
    rng = _DetRandom(
        options.salt,
        domain,
        options.seed,
        options.namespace,
        n,
        count,
        *parts,
    )
    rng.shuffle(values)
    return sorted(values[:count])


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ThresholdIssue:
    """
    Safe threshold issue.

    Issues never contain raw score values, raw labels, raw narratives, raw
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


def _as_issue(value: Any) -> ThresholdIssue:
    if isinstance(value, ThresholdIssue):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(ThresholdIssue, "__dataclass_fields__", {}).keys())
        clean = {key: item for key, item in value.items() if key in fields}

        try:
            return ThresholdIssue(**clean)
        except Exception:
            return ThresholdIssue(
                severity=IssueSeverity.WARNING,
                code="malformed_issue",
                message="Malformed issue omitted.",
            )

    return ThresholdIssue(
        severity=IssueSeverity.WARNING,
        code="invalid_issue",
        message="Invalid issue omitted.",
    )


def _append_issue(
    issues: list[ThresholdIssue],
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

        issues[-1] = ThresholdIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        ThresholdIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _has_error(issues: Sequence[ThresholdIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[Any]) -> tuple[ThresholdIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[ThresholdIssue] = []

    for issue in issues:
        item = _as_issue(issue)
        key = (
            item.severity.value,
            item.code,
            item.message,
            item.field,
        )

        if key in seen:
            continue

        seen.add(key)
        out.append(item)

    return tuple(out)


def _truncate_issues(
    issues: Sequence[Any],
    max_issues: int = _DEFAULT_MAX_ISSUES,
) -> tuple[ThresholdIssue, ...]:
    limit = max(1, int(max_issues))
    coerced = [_as_issue(issue) for issue in issues]

    if len(coerced) <= limit:
        return tuple(coerced)

    out = coerced[: limit - 1]
    _append_issue(
        out,
        limit,
        severity=IssueSeverity.WARNING,
        code="issue_list_truncated",
        message="Issue list truncated by configured limit.",
    )
    return tuple(out)


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


def _coerce_mapping_setting(value: Any) -> dict[str, Any]:
    """
    Coerce common settings mapping shapes into a plain dict.

    Supports mappings and JSON-like strings. Invalid values return an empty
    mapping rather than raising.
    """
    if value is None:
        return {}

    if isinstance(value, Mapping):
        return {
            _clean_text(key, 128): item
            for key, item in value.items()
            if _clean_text(key, 128)
        }

    if isinstance(value, str):
        text = value.strip()

        if not text:
            return {}

        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None

        if isinstance(parsed, Mapping):
            return {
                _clean_text(key, 128): item
                for key, item in parsed.items()
                if _clean_text(key, 128)
            }

    return {}


def _normalize_quantile_tuple(value: Any, default: tuple[float, ...]) -> tuple[float, ...]:
    """
    Normalize a quantile specification into a bounded sorted tuple.
    """
    if value is None:
        return default

    if isinstance(value, str):
        seq: list[Any] = _csv(value)
    else:
        seq = _as_sequence(value)

    out: list[float] = []

    for item in seq:
        q = _coerce_optional_float(item, allow_bool=False)

        if q is None:
            continue

        out.append(_round6(_clamp_float(q, 0.0, 1.0, 0.0)))

    if not out:
        return default

    return tuple(sorted(set(out)))


def _normalize_float_mapping(
    value: Any,
    default: Mapping[str, float],
    *,
    minimum: float = 0.0,
    maximum: float = 1.0,
) -> dict[str, float]:
    """
    Normalize a float mapping with bounds and deterministic defaults.
    """
    out = {
        str(key): _round6(_clamp_float(raw, minimum, maximum, minimum))
        for key, raw in dict(default).items()
    }

    parsed = value if isinstance(value, Mapping) else _coerce_mapping_setting(value)

    for raw_key, raw_value in parsed.items():
        key = _clean_text(raw_key, 128)

        if not key:
            continue

        numeric = _coerce_optional_float(raw_value, allow_bool=False)

        if numeric is None:
            continue

        out[key] = _round6(_clamp_float(numeric, minimum, maximum, minimum))

    if not any(float(weight) > 0 for weight in out.values()):
        out = {
            str(key): _round6(_clamp_float(raw, minimum, maximum, minimum))
            for key, raw in dict(default).items()
        }

    return out


def _optional_float_setting(settings: Any, name: str, default: Optional[float] = None) -> Optional[float]:
    raw = _setting(settings, name, None)

    if raw is None:
        return default

    numeric = _coerce_optional_float(raw, allow_bool=False)

    if numeric is None:
        return default

    return numeric


@dataclass(frozen=True, slots=True)
class ThresholdOptions:
    """
    Bounded threshold-policy options.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    default_policy: ThresholdPolicy | str = ThresholdPolicy.HYBRID
    score_kind: ScoreKind | str = ScoreKind.GENERIC
    selection_split: str = "validation"

    default_threshold: float = _DEFAULT_THRESHOLD
    target_positive_rate: float = _DEFAULT_TARGET_POSITIVE_RATE
    max_fpr: float = _DEFAULT_MAX_FPR
    min_recall: float = _DEFAULT_MIN_RECALL
    min_precision: float = _DEFAULT_MIN_PRECISION
    max_cost: Optional[float] = None

    cost_false_positive: float = _DEFAULT_COST_FP
    cost_false_negative: float = _DEFAULT_COST_FN
    ewma_decay: float = _DEFAULT_EWMA_DECAY

    score_min: float = 0.0
    score_max: float = 1.0

    allowed_label_codes: tuple[int, ...] = _DEFAULT_ALLOWED_LABEL_CODES
    positive_label_codes: tuple[int, ...] = _DEFAULT_POSITIVE_LABEL_CODES
    negative_label_codes: tuple[int, ...] = _DEFAULT_NEGATIVE_LABEL_CODES
    ignore_label_codes: tuple[int, ...] = _DEFAULT_IGNORE_LABEL_CODES

    default_quantiles: tuple[float, ...] = _DEFAULT_QUANTILES
    policy_weights: Mapping[str, float] = dataclass_field(default_factory=lambda: dict(_DEFAULT_POLICY_WEIGHTS))
    risk_thresholds: Mapping[str, float] = dataclass_field(default_factory=lambda: dict(_DEFAULT_RISK_THRESHOLDS))

    drift_warn: float = _DEFAULT_DRIFT_WARN
    drift_fail: float = _DEFAULT_DRIFT_FAIL

    max_observations: int = _DEFAULT_MAX_OBSERVATIONS
    max_fields: int = _DEFAULT_MAX_FIELDS
    max_candidates: int = _DEFAULT_MAX_CANDIDATES
    max_stability_candidates: int = _DEFAULT_MAX_STABILITY_CANDIDATES
    stability_repeats: int = _DEFAULT_STABILITY_REPEATS
    min_stability_samples: int = _DEFAULT_MIN_STABILITY_SAMPLES
    max_stability_sample: int = _DEFAULT_MAX_STABILITY_SAMPLE
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_profiles: int = _DEFAULT_MAX_PROFILES
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    include_candidates: bool = True
    include_stability: bool = True
    include_drift: bool = True
    register_profiles: bool = True
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
            "default_policy",
            _normalize_enum_option(ThresholdPolicy, self.default_policy, ThresholdPolicy.HYBRID),
        )
        object.__setattr__(
            self,
            "score_kind",
            _normalize_enum_option(ScoreKind, self.score_kind, ScoreKind.GENERIC),
        )
        object.__setattr__(
            self,
            "selection_split",
            _normalize_token(self.selection_split) or "validation",
        )

        object.__setattr__(
            self,
            "default_threshold",
            _round6(_clamp_float(self.default_threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)),
        )
        object.__setattr__(
            self,
            "target_positive_rate",
            _round6(_clamp_float(self.target_positive_rate, 0.0, 1.0, _DEFAULT_TARGET_POSITIVE_RATE)),
        )
        object.__setattr__(
            self,
            "max_fpr",
            _round6(_clamp_float(self.max_fpr, 0.0, 1.0, _DEFAULT_MAX_FPR)),
        )
        object.__setattr__(
            self,
            "min_recall",
            _round6(_clamp_float(self.min_recall, 0.0, 1.0, _DEFAULT_MIN_RECALL)),
        )
        object.__setattr__(
            self,
            "min_precision",
            _round6(_clamp_float(self.min_precision, 0.0, 1.0, _DEFAULT_MIN_PRECISION)),
        )

        if self.max_cost is not None:
            object.__setattr__(
                self,
                "max_cost",
                _round6(_clamp_float(self.max_cost, 0.0, 1e12, 0.0)),
            )

        object.__setattr__(
            self,
            "cost_false_positive",
            _round6(_clamp_float(self.cost_false_positive, 0.0, 1e9, _DEFAULT_COST_FP)),
        )
        object.__setattr__(
            self,
            "cost_false_negative",
            _round6(_clamp_float(self.cost_false_negative, 0.0, 1e9, _DEFAULT_COST_FN)),
        )
        object.__setattr__(
            self,
            "ewma_decay",
            _round6(_clamp_float(self.ewma_decay, 0.01, 1.0, _DEFAULT_EWMA_DECAY)),
        )

        score_min = _clamp_float(self.score_min, -1e12, 1e12, 0.0)
        score_max = _clamp_float(self.score_max, -1e12, 1e12, 1.0)

        if score_max <= score_min:
            score_max = score_min + 1.0

        object.__setattr__(self, "score_min", _round6(score_min))
        object.__setattr__(self, "score_max", _round6(score_max))

        object.__setattr__(
            self,
            "allowed_label_codes",
            _coerce_int_tuple(self.allowed_label_codes, _DEFAULT_ALLOWED_LABEL_CODES),
        )
        object.__setattr__(
            self,
            "positive_label_codes",
            _coerce_int_tuple(self.positive_label_codes, _DEFAULT_POSITIVE_LABEL_CODES),
        )
        object.__setattr__(
            self,
            "negative_label_codes",
            _coerce_int_tuple(self.negative_label_codes, _DEFAULT_NEGATIVE_LABEL_CODES),
        )
        object.__setattr__(
            self,
            "ignore_label_codes",
            _coerce_int_tuple(self.ignore_label_codes, _DEFAULT_IGNORE_LABEL_CODES),
        )

        object.__setattr__(
            self,
            "default_quantiles",
            _normalize_quantile_tuple(self.default_quantiles, _DEFAULT_QUANTILES),
        )
        object.__setattr__(
            self,
            "policy_weights",
            MappingProxyType(
                _normalize_float_mapping(
                    self.policy_weights,
                    _DEFAULT_POLICY_WEIGHTS,
                    minimum=0.0,
                    maximum=10.0,
                )
            ),
        )

        thresholds = _normalize_float_mapping(
            self.risk_thresholds,
            _DEFAULT_RISK_THRESHOLDS,
            minimum=0.0,
            maximum=1.0,
        )
        low = thresholds.get("low", 0.35)
        medium = max(low, thresholds.get("medium", 0.55))
        high = max(medium, thresholds.get("high", 0.75))
        critical = max(high, thresholds.get("critical", 0.90))

        object.__setattr__(
            self,
            "risk_thresholds",
            MappingProxyType(
                {
                    "low": _round6(low),
                    "medium": _round6(medium),
                    "high": _round6(high),
                    "critical": _round6(critical),
                }
            ),
        )

        object.__setattr__(
            self,
            "drift_warn",
            _round6(_clamp_float(self.drift_warn, 0.0, 10.0, _DEFAULT_DRIFT_WARN)),
        )
        object.__setattr__(
            self,
            "drift_fail",
            _round6(
                max(
                    self.drift_warn,
                    _clamp_float(self.drift_fail, 0.0, 10.0, _DEFAULT_DRIFT_FAIL),
                )
            ),
        )

        object.__setattr__(
            self,
            "max_observations",
            _clamp_int(self.max_observations, 1, _HARD_MAX_OBSERVATIONS, _DEFAULT_MAX_OBSERVATIONS),
        )
        object.__setattr__(
            self,
            "max_fields",
            _clamp_int(self.max_fields, 1, _HARD_MAX_FIELDS, _DEFAULT_MAX_FIELDS),
        )
        object.__setattr__(
            self,
            "max_candidates",
            _clamp_int(self.max_candidates, 2, _HARD_MAX_CANDIDATES, _DEFAULT_MAX_CANDIDATES),
        )
        object.__setattr__(
            self,
            "max_stability_candidates",
            _clamp_int(
                self.max_stability_candidates,
                2,
                _HARD_MAX_STABILITY_CANDIDATES,
                _DEFAULT_MAX_STABILITY_CANDIDATES,
            ),
        )
        object.__setattr__(
            self,
            "stability_repeats",
            _clamp_int(self.stability_repeats, 0, _HARD_MAX_STABILITY_REPEATS, _DEFAULT_STABILITY_REPEATS),
        )
        object.__setattr__(
            self,
            "min_stability_samples",
            max(2, _as_int(self.min_stability_samples, _DEFAULT_MIN_STABILITY_SAMPLES)),
        )
        object.__setattr__(
            self,
            "max_stability_sample",
            _clamp_int(
                self.max_stability_sample,
                2,
                _HARD_MAX_STABILITY_SAMPLE,
                _DEFAULT_MAX_STABILITY_SAMPLE,
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
            _clamp_int(self.max_summary_items, 1, _HARD_MAX_SUMMARY_ITEMS, _DEFAULT_MAX_SUMMARY_ITEMS),
        )
        object.__setattr__(
            self,
            "max_profiles",
            _clamp_int(self.max_profiles, 1, _HARD_MAX_PROFILES, _DEFAULT_MAX_PROFILES),
        )
        object.__setattr__(
            self,
            "max_time_ms",
            _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS),
        )

        object.__setattr__(self, "include_candidates", _as_bool(self.include_candidates, True))
        object.__setattr__(self, "include_stability", _as_bool(self.include_stability, True))
        object.__setattr__(self, "include_drift", _as_bool(self.include_drift, True))
        object.__setattr__(self, "register_profiles", _as_bool(self.register_profiles, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ThresholdOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "RULES_THRESHOLD_SALT", None)
            or _setting(settings, "RULES_ENGINE_SALT", None)
            or _setting(settings, "RULES_SALT", None)
            or _setting(settings, "ML_VALIDATION_SALT", None)
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
            enabled=_as_bool(_setting(settings, "RULES_THRESHOLD_ENABLED", True), True)
            and _as_bool(_setting(settings, "RULES_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "RULES_THRESHOLD_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "RULES_THRESHOLD_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "RULES_THRESHOLD_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "RULES_THRESHOLD_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            default_policy=str(_setting(settings, "RULES_THRESHOLD_DEFAULT_POLICY", ThresholdPolicy.HYBRID.value)),
            score_kind=str(_setting(settings, "RULES_THRESHOLD_SCORE_KIND", ScoreKind.GENERIC.value)),
            selection_split=str(_setting(settings, "RULES_THRESHOLD_SELECTION_SPLIT", "validation")),
            default_threshold=_as_float(
                _setting(settings, "RULES_THRESHOLD_DEFAULT", _DEFAULT_THRESHOLD),
                _DEFAULT_THRESHOLD,
            ),
            target_positive_rate=_as_float(
                _setting(settings, "RULES_THRESHOLD_TARGET_POSITIVE_RATE", _DEFAULT_TARGET_POSITIVE_RATE),
                _DEFAULT_TARGET_POSITIVE_RATE,
            ),
            max_fpr=_as_float(_setting(settings, "RULES_THRESHOLD_MAX_FPR", _DEFAULT_MAX_FPR), _DEFAULT_MAX_FPR),
            min_recall=_as_float(_setting(settings, "RULES_THRESHOLD_MIN_RECALL", _DEFAULT_MIN_RECALL), _DEFAULT_MIN_RECALL),
            min_precision=_as_float(
                _setting(settings, "RULES_THRESHOLD_MIN_PRECISION", _DEFAULT_MIN_PRECISION),
                _DEFAULT_MIN_PRECISION,
            ),
            max_cost=_optional_float_setting(settings, "RULES_THRESHOLD_MAX_COST", None),
            cost_false_positive=_as_float(
                _setting(settings, "RULES_THRESHOLD_COST_FP", _DEFAULT_COST_FP),
                _DEFAULT_COST_FP,
            ),
            cost_false_negative=_as_float(
                _setting(settings, "RULES_THRESHOLD_COST_FN", _DEFAULT_COST_FN),
                _DEFAULT_COST_FN,
            ),
            ewma_decay=_as_float(_setting(settings, "RULES_THRESHOLD_EWMA_DECAY", _DEFAULT_EWMA_DECAY), _DEFAULT_EWMA_DECAY),
            score_min=_as_float(_setting(settings, "RULES_THRESHOLD_SCORE_MIN", 0.0), 0.0),
            score_max=_as_float(_setting(settings, "RULES_THRESHOLD_SCORE_MAX", 1.0), 1.0),
            allowed_label_codes=_coerce_int_tuple(
                _setting(settings, "RULES_THRESHOLD_ALLOWED_LABEL_CODES", None),
                _DEFAULT_ALLOWED_LABEL_CODES,
            ),
            positive_label_codes=_coerce_int_tuple(
                _setting(settings, "RULES_THRESHOLD_POSITIVE_LABEL_CODES", None),
                _DEFAULT_POSITIVE_LABEL_CODES,
            ),
            negative_label_codes=_coerce_int_tuple(
                _setting(settings, "RULES_THRESHOLD_NEGATIVE_LABEL_CODES", None),
                _DEFAULT_NEGATIVE_LABEL_CODES,
            ),
            ignore_label_codes=_coerce_int_tuple(
                _setting(settings, "RULES_THRESHOLD_IGNORE_LABEL_CODES", None),
                _DEFAULT_IGNORE_LABEL_CODES,
            ),
            default_quantiles=_normalize_quantile_tuple(
                _setting(settings, "RULES_THRESHOLD_QUANTILES", None),
                _DEFAULT_QUANTILES,
            ),
            policy_weights=_coerce_mapping_setting(
                _setting(settings, "RULES_THRESHOLD_POLICY_WEIGHTS", None)
            ),
            risk_thresholds=_coerce_mapping_setting(
                _setting(settings, "RULES_THRESHOLD_RISK_THRESHOLDS", None)
            ),
            drift_warn=_as_float(_setting(settings, "RULES_THRESHOLD_DRIFT_WARN", _DEFAULT_DRIFT_WARN), _DEFAULT_DRIFT_WARN),
            drift_fail=_as_float(_setting(settings, "RULES_THRESHOLD_DRIFT_FAIL", _DEFAULT_DRIFT_FAIL), _DEFAULT_DRIFT_FAIL),
            max_observations=_as_int(
                _setting(settings, "RULES_THRESHOLD_MAX_OBSERVATIONS", _DEFAULT_MAX_OBSERVATIONS),
                _DEFAULT_MAX_OBSERVATIONS,
            ),
            max_fields=_as_int(_setting(settings, "RULES_THRESHOLD_MAX_FIELDS", _DEFAULT_MAX_FIELDS), _DEFAULT_MAX_FIELDS),
            max_candidates=_as_int(
                _setting(settings, "RULES_THRESHOLD_MAX_CANDIDATES", _DEFAULT_MAX_CANDIDATES),
                _DEFAULT_MAX_CANDIDATES,
            ),
            max_stability_candidates=_as_int(
                _setting(settings, "RULES_THRESHOLD_MAX_STABILITY_CANDIDATES", _DEFAULT_MAX_STABILITY_CANDIDATES),
                _DEFAULT_MAX_STABILITY_CANDIDATES,
            ),
            stability_repeats=_as_int(
                _setting(settings, "RULES_THRESHOLD_STABILITY_REPEATS", _DEFAULT_STABILITY_REPEATS),
                _DEFAULT_STABILITY_REPEATS,
            ),
            min_stability_samples=_as_int(
                _setting(settings, "RULES_THRESHOLD_MIN_STABILITY_SAMPLES", _DEFAULT_MIN_STABILITY_SAMPLES),
                _DEFAULT_MIN_STABILITY_SAMPLES,
            ),
            max_stability_sample=_as_int(
                _setting(settings, "RULES_THRESHOLD_MAX_STABILITY_SAMPLE", _DEFAULT_MAX_STABILITY_SAMPLE),
                _DEFAULT_MAX_STABILITY_SAMPLE,
            ),
            max_issues=_as_int(_setting(settings, "RULES_THRESHOLD_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(
                _setting(settings, "RULES_THRESHOLD_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_profiles=_as_int(
                _setting(settings, "RULES_THRESHOLD_MAX_PROFILES", _DEFAULT_MAX_PROFILES),
                _DEFAULT_MAX_PROFILES,
            ),
            max_time_ms=_as_int(
                _setting(settings, "RULES_THRESHOLD_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS),
                _DEFAULT_MAX_TIME_MS,
            ),
            include_candidates=_as_bool(_setting(settings, "RULES_THRESHOLD_INCLUDE_CANDIDATES", True), True),
            include_stability=_as_bool(_setting(settings, "RULES_THRESHOLD_INCLUDE_STABILITY", True), True),
            include_drift=_as_bool(_setting(settings, "RULES_THRESHOLD_INCLUDE_DRIFT", True), True),
            register_profiles=_as_bool(_setting(settings, "RULES_THRESHOLD_REGISTER_PROFILES", True), True),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "RULES_THRESHOLD_DROP_FORBIDDEN_FIELDS", False),
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
            "default_policy": _enum_value(self.default_policy, ThresholdPolicy.HYBRID.value),
            "score_kind": _enum_value(self.score_kind, ScoreKind.GENERIC.value),
            "selection_split": self.selection_split,
            "thresholds": {
                "default_threshold": _round6(self.default_threshold),
                "target_positive_rate": _round6(self.target_positive_rate),
                "max_fpr": _round6(self.max_fpr),
                "min_recall": _round6(self.min_recall),
                "min_precision": _round6(self.min_precision),
                "max_cost": _round6(self.max_cost) if self.max_cost is not None else None,
                "cost_false_positive": _round6(self.cost_false_positive),
                "cost_false_negative": _round6(self.cost_false_negative),
                "ewma_decay": _round6(self.ewma_decay),
                "score_min": _round6(self.score_min),
                "score_max": _round6(self.score_max),
                "drift_warn": _round6(self.drift_warn),
                "drift_fail": _round6(self.drift_fail),
            },
            "risk_thresholds": dict(self.risk_thresholds),
            "policy_weights": dict(self.policy_weights),
            "label_codes": {
                "allowed": list(self.allowed_label_codes),
                "positive": list(self.positive_label_codes),
                "negative": list(self.negative_label_codes),
                "ignore": list(self.ignore_label_codes),
            },
            "quantiles": list(self.default_quantiles),
            "limits": {
                "max_observations": self.max_observations,
                "max_fields": self.max_fields,
                "max_candidates": self.max_candidates,
                "max_stability_candidates": self.max_stability_candidates,
                "stability_repeats": self.stability_repeats,
                "min_stability_samples": self.min_stability_samples,
                "max_stability_sample": self.max_stability_sample,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_profiles": self.max_profiles,
                "max_time_ms": self.max_time_ms,
            },
            "flags": {
                "include_candidates": self.include_candidates,
                "include_stability": self.include_stability,
                "include_drift": self.include_drift,
                "register_profiles": self.register_profiles,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "observations",
        "labels",
        "policy",
        "score_field",
        "label_field",
        "score_kind",
        "threshold",
        "target_positive_rate",
        "max_fpr",
        "min_recall",
        "min_precision",
        "max_cost",
        "cost_false_positive",
        "cost_false_negative",
        "ewma_decay",
        "quantiles",
        "positive_label_codes",
        "negative_label_codes",
        "ignore_label_codes",
        "reference_profile",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class ThresholdRequest:
    """
    Bounded threshold-selection request.
    """

    observations: Any = None
    labels: Any = None
    policy: ThresholdPolicy | str | None = None
    score_field: Optional[str] = None
    label_field: Optional[str] = None
    score_kind: ScoreKind | str | None = None
    threshold: Optional[float] = None
    target_positive_rate: Optional[float] = None
    max_fpr: Optional[float] = None
    min_recall: Optional[float] = None
    min_precision: Optional[float] = None
    max_cost: Optional[float] = None
    cost_false_positive: Optional[float] = None
    cost_false_negative: Optional[float] = None
    ewma_decay: Optional[float] = None
    quantiles: Optional[Sequence[float]] = None
    positive_label_codes: Optional[Sequence[int]] = None
    negative_label_codes: Optional[Sequence[int]] = None
    ignore_label_codes: Optional[Sequence[int]] = None
    reference_profile: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        if self.policy is not None:
            self.policy = _normalize_enum_option(ThresholdPolicy, self.policy, None)

        if self.score_kind is not None:
            self.score_kind = _normalize_enum_option(ScoreKind, self.score_kind, None)

        if self.score_field is not None:
            self.score_field = _canonical_field_name(self.score_field) or None

        if self.label_field is not None:
            self.label_field = _canonical_field_name(self.label_field) or None

        if self.threshold is not None:
            self.threshold = _round6(_clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD))

        if self.target_positive_rate is not None:
            self.target_positive_rate = _round6(
                _clamp_float(self.target_positive_rate, 0.0, 1.0, _DEFAULT_TARGET_POSITIVE_RATE)
            )

        if self.max_fpr is not None:
            self.max_fpr = _round6(_clamp_float(self.max_fpr, 0.0, 1.0, _DEFAULT_MAX_FPR))

        if self.min_recall is not None:
            self.min_recall = _round6(_clamp_float(self.min_recall, 0.0, 1.0, _DEFAULT_MIN_RECALL))

        if self.min_precision is not None:
            self.min_precision = _round6(
                _clamp_float(self.min_precision, 0.0, 1.0, _DEFAULT_MIN_PRECISION)
            )

        if self.max_cost is not None:
            self.max_cost = _round6(_clamp_float(self.max_cost, 0.0, 1e12, 0.0))

        if self.cost_false_positive is not None:
            self.cost_false_positive = _round6(
                _clamp_float(self.cost_false_positive, 0.0, 1e9, _DEFAULT_COST_FP)
            )

        if self.cost_false_negative is not None:
            self.cost_false_negative = _round6(
                _clamp_float(self.cost_false_negative, 0.0, 1e9, _DEFAULT_COST_FN)
            )

        if self.ewma_decay is not None:
            self.ewma_decay = _round6(_clamp_float(self.ewma_decay, 0.01, 1.0, _DEFAULT_EWMA_DECAY))

        if self.quantiles is not None:
            self.quantiles = _normalize_quantile_tuple(self.quantiles, _DEFAULT_QUANTILES)

        if self.positive_label_codes is not None:
            self.positive_label_codes = _coerce_int_tuple(
                self.positive_label_codes,
                _DEFAULT_POSITIVE_LABEL_CODES,
            )

        if self.negative_label_codes is not None:
            self.negative_label_codes = _coerce_int_tuple(
                self.negative_label_codes,
                _DEFAULT_NEGATIVE_LABEL_CODES,
            )

        if self.ignore_label_codes is not None:
            self.ignore_label_codes = _coerce_int_tuple(
                self.ignore_label_codes,
                _DEFAULT_IGNORE_LABEL_CODES,
            )

        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) if self.request_id else None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) if self.idempotency_key else None


def _coerce_threshold_request(request: Any) -> ThresholdRequest:
    """
    Coerce flexible threshold input into one bounded request.
    """
    if isinstance(request, ThresholdRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if "observations" not in payload:
            for key in ("records", "rows", "items", "scores", "predictions", "values"):
                if key in payload:
                    payload["observations"] = payload[key]
                    break

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(ThresholdRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return ThresholdRequest(**clean)
            except Exception:
                return ThresholdRequest(observations=payload.get("observations", request))

        return ThresholdRequest(observations=request)

    return ThresholdRequest(observations=request)


# -----------------------------------------------------------------------------
# Observation extraction and sanitization
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _Observation:
    subject_ref_hash: Optional[str] = None
    index: int = 0
    score: float = 0.0
    label_code: Optional[int] = None
    weight: float = 1.0
    split: str = "unknown"


@dataclass(slots=True)
class _ExternalLabelIndex:
    by_source: list[Optional[int]] = dataclass_field(default_factory=list)
    by_subject: dict[str, int] = dataclass_field(default_factory=dict)


def _iter_observations(data: Any) -> list[Any]:
    """
    Convert flexible observation input into a list of observation-like items.
    """
    if data is None:
        return []

    if isinstance(data, ThresholdProfile):
        return []

    if isinstance(data, Mapping):
        for key in ("observations", "records", "rows", "items", "scores", "predictions", "values"):
            if key in data and not isinstance(data[key], Mapping):
                seq = _as_sequence(data[key])

                if key in {"scores", "predictions", "values"} and (
                    "labels" in data or "label_codes" in data or "subjects" in data or "subject_hashes" in data
                ):
                    scores = seq
                    labels = _as_sequence(data.get("labels") or data.get("label_codes") or [])
                    subjects = _as_sequence(data.get("subject_hashes") or data.get("subjects") or [])
                    weights = _as_sequence(data.get("weights") or [])
                    splits = _as_sequence(data.get("splits") or [])
                    out: list[Any] = []

                    for position in range(len(scores)):
                        item: dict[str, Any] = {"score": scores[position], "index": position}

                        if position < len(labels):
                            item["label"] = labels[position]

                        if position < len(subjects):
                            item["subject_ref_hash"] = subjects[position]

                        if position < len(weights):
                            item["weight"] = weights[position]

                        if position < len(splits):
                            item["split"] = splits[position]

                        out.append(item)

                    return out

                return seq

        if "feature_names" in data and "rows" in data:
            return _as_sequence(data["rows"])

        if data and not any(key in data for key in _SCORE_KEYS + _LABEL_KEYS + _SUBJECT_KEYS):
            numeric_values = [
                _coerce_optional_float(value, allow_bool=True)
                for value in data.values()
            ]

            if numeric_values and all(value is not None for value in numeric_values):
                return [
                    {"subject_ref_hash": key, "score": value}
                    for key, value in data.items()
                ]

        return [data]

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray, memoryview)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _extract_subject(record: Any, options: ThresholdOptions) -> Optional[str]:
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

    if value is None:
        return None

    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.rules.thresholds.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _extract_score(
    record: Any,
    options: ThresholdOptions,
    score_field: Optional[str],
    issues: list[ThresholdIssue],
    index: int,
) -> Optional[float]:
    if score_field:
        if _is_forbidden_key(score_field) or _is_label_leakage_key(score_field):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_score_field",
                message="Requested score field is forbidden or label-leakage prone.",
                field=score_field,
                details={"index": index},
            )
            return None

    value: Any = None

    if isinstance(record, Mapping):
        candidates: list[Any] = []

        if score_field:
            candidates.append(record.get(score_field))
            features = record.get("features")

            if isinstance(features, Mapping):
                candidates.append(features.get(score_field))

        for key in _SCORE_KEYS:
            if key in record:
                candidates.append(record[key])

        for candidate in candidates:
            if candidate is None:
                continue

            if isinstance(candidate, str) and _looks_like_sensitive_literal(candidate):
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="sensitive_score_value_omitted",
                    message="Score value appeared sensitive and was omitted.",
                    details={"index": index, "value_retained": False},
                )
                return None

            numeric = _coerce_optional_float(candidate, allow_bool=True)

            if numeric is not None:
                return numeric

        return None

    if isinstance(record, (str, bytes, bytearray, memoryview)):
        if isinstance(record, str) and _looks_like_sensitive_literal(record):
            return None

        return _coerce_optional_float(record, allow_bool=True)

    numeric = _coerce_optional_float(record, allow_bool=True)

    if numeric is not None:
        return numeric

    score_attr = getattr(record, "score", None)

    if score_attr is not None:
        return _coerce_optional_float(score_attr, allow_bool=True)

    return None


def _extract_label(
    record: Any,
    options: ThresholdOptions,
    label_field: Optional[str],
    issues: list[ThresholdIssue],
    index: int,
) -> Optional[int]:
    if label_field and _is_forbidden_key(label_field) and not _is_label_leakage_key(label_field):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="forbidden_label_field",
            message="Requested label field is forbidden.",
            field=label_field,
            details={"index": index},
        )
        return None

    value: Any = None

    if isinstance(record, Mapping):
        candidates: list[Any] = []

        if label_field:
            candidates.append(record.get(label_field))
            features = record.get("features")

            if isinstance(features, Mapping):
                candidates.append(features.get(label_field))

        for key in _LABEL_KEYS:
            if key in record:
                candidates.append(record[key])

        for candidate in candidates:
            code = _coerce_int_label(candidate)

            if code is not None:
                return code

        return None

    for attr in _LABEL_KEYS:
        candidate = getattr(record, attr, None)

        if candidate is not None:
            code = _coerce_int_label(candidate)

            if code is not None:
                return code

    return _coerce_int_label(record)


def _extract_weight(record: Any, options: ThresholdOptions) -> float:
    value: Any = None

    if isinstance(record, Mapping):
        for key in _WEIGHT_KEYS:
            if key in record:
                value = record[key]
                break
    else:
        for attr in _WEIGHT_KEYS:
            candidate = getattr(record, attr, None)

            if candidate is not None:
                value = candidate
                break

    numeric = _coerce_optional_float(value, allow_bool=True)

    if numeric is None:
        return 1.0

    return _round6(_clamp_float(numeric, 0.0, 100.0, 1.0))


def _extract_split(record: Any, options: ThresholdOptions) -> str:
    value: Any = None

    if isinstance(record, Mapping):
        for key in _SPLIT_KEYS:
            if key in record:
                value = record[key]
                break
    else:
        for attr in _SPLIT_KEYS:
            candidate = getattr(record, attr, None)

            if candidate is not None:
                value = candidate
                break

    token = _normalize_token(value)

    return token or "unknown"


def _build_external_label_index(
    labels: Any,
    count: int,
    options: ThresholdOptions,
) -> _ExternalLabelIndex:
    index = _ExternalLabelIndex(by_source=[None] * max(0, int(count)))

    if labels is None:
        return index

    def add_item(position: Optional[int], subject: Any, raw_label: Any) -> None:
        code = _coerce_int_label(raw_label)

        if code is None:
            return

        subject_hash = _extract_subject({"subject_ref_hash": subject}, options) if subject is not None else None

        if subject_hash:
            index.by_subject[subject_hash] = code

        if position is not None and 0 <= position < len(index.by_source):
            index.by_source[position] = code

    if isinstance(labels, Mapping):
        subject_hashes = labels.get("subject_hashes") or labels.get("subjects")
        label_codes = labels.get("label_codes") or labels.get("labels") or labels.get("y")
        records = labels.get("records") or labels.get("items") or labels.get("rows")

        if subject_hashes is not None and label_codes is not None:
            subjects = _as_sequence(subject_hashes)
            codes = _as_sequence(label_codes)

            for position in range(min(len(subjects), len(codes), max(count, len(codes)))):
                add_item(position, subjects[position], codes[position])

            return index

        if records is not None:
            for position, record in enumerate(_as_sequence(records)):
                if isinstance(record, Mapping):
                    subject = None

                    for key in _SUBJECT_KEYS:
                        if key in record:
                            subject = record[key]
                            break

                    add_item(position, subject, _extract_label(record, options, None, [], position))
                else:
                    add_item(position, None, record)

            return index

        if label_codes is not None:
            for position, code in enumerate(_as_sequence(label_codes)):
                add_item(position, None, code)

            return index

        add_item(0, None, _extract_label(labels, options, None, [], 0))
        return index

    if hasattr(labels, "subject_hashes") and hasattr(labels, "label_codes"):
        subjects = _as_sequence(getattr(labels, "subject_hashes", ()) or ())
        codes = _as_sequence(getattr(labels, "label_codes", ()) or ())

        for position in range(min(len(subjects), len(codes), max(count, len(codes)))):
            add_item(position, subjects[position], codes[position])

        return index

    records = getattr(labels, "records", None) or getattr(labels, "items", None)

    if records is not None:
        for position, record in enumerate(_as_sequence(records)):
            if isinstance(record, Mapping):
                subject = None

                for key in _SUBJECT_KEYS:
                    if key in record:
                        subject = record[key]
                        break

                add_item(position, subject, _extract_label(record, options, None, [], position))
            else:
                add_item(position, None, record)

        return index

    for position, item in enumerate(_as_sequence(labels)):
        if isinstance(item, Mapping):
            subject = None

            for key in _SUBJECT_KEYS:
                if key in item:
                    subject = item[key]
                    break

            add_item(position, subject, _extract_label(item, options, None, [], position))
        else:
            add_item(position, None, item)

    return index


def _sanitize_observations(
    raw_items: Sequence[Any],
    labels: Any,
    options: ThresholdOptions,
    request: ThresholdRequest,
    issues: list[ThresholdIssue],
    start_time: float,
) -> tuple[list[_Observation], dict[str, int]]:
    count = max(0, int(len(raw_items)))
    label_index = _build_external_label_index(labels, count, options)
    observations: list[_Observation] = []
    counts = {
        "submitted": count,
        "processed": 0,
        "scored": 0,
        "labeled": 0,
        "positive": 0,
        "negative": 0,
        "unlabeled": 0,
        "invalid_score": 0,
        "out_of_range_score": 0,
        "invalid_label": 0,
        "zero_weight": 0,
    }
    allowed_labels = set(options.allowed_label_codes)
    positive_labels = set(options.positive_label_codes)
    negative_labels = set(options.negative_label_codes)

    if request.score_field and (_is_forbidden_key(request.score_field) or _is_label_leakage_key(request.score_field)):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="forbidden_score_field",
            message="Requested score field is forbidden or label-leakage prone.",
            field=request.score_field,
        )
        return observations, counts

    for source_index, item in enumerate(raw_items):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="observation_sanitization_time_budget_exhausted",
                message="Observation sanitization stopped after reaching configured time budget.",
                details={
                    "processed": len(observations),
                    "remaining": max(0, count - source_index),
                },
            )
            break

        counts["processed"] += 1
        subject = _extract_subject(item, options)
        raw_score = _extract_score(item, options, request.score_field, issues, source_index)

        if raw_score is None:
            counts["invalid_score"] += 1
            continue

        score = _round6(_clip_float(raw_score, options.score_min, options.score_max, options.score_min))

        if raw_score < options.score_min or raw_score > options.score_max:
            counts["out_of_range_score"] += 1
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="score_out_of_range_clipped",
                message="Score outside configured bounds was clipped for bounded threshold calibration.",
                details={"source_index": source_index, "value_retained": False},
            )

        label_code = _extract_label(item, options, request.label_field, issues, source_index)

        if label_code is None and subject and subject in label_index.by_subject:
            label_code = label_index.by_subject[subject]

        if label_code is None and source_index < len(label_index.by_source):
            label_code = label_index.by_source[source_index]

        if label_code is not None and label_code not in allowed_labels:
            counts["invalid_label"] += 1
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="invalid_label_code_ignored",
                message="Label code outside allowed set was ignored for threshold calibration.",
                details={"source_index": source_index},
            )
            label_code = None

        weight = _extract_weight(item, options)

        if weight <= 0:
            counts["zero_weight"] += 1
            continue

        split = _extract_split(item, options)
        observations.append(
            _Observation(
                subject_ref_hash=subject,
                index=len(observations),
                score=score,
                label_code=label_code,
                weight=weight,
                split=split,
            )
        )
        counts["scored"] += 1

        if label_code is None:
            counts["unlabeled"] += 1
        else:
            counts["labeled"] += 1

            if label_code in positive_labels:
                counts["positive"] += 1
            elif label_code in negative_labels:
                counts["negative"] += 1
            else:
                counts["unlabeled"] += 1

    return observations, counts


def _filter_observations_by_split(
    observations: Sequence[_Observation],
    selection_split: str,
    options: ThresholdOptions,
    issues: list[ThresholdIssue],
) -> list[_Observation]:
    split_token = _normalize_token(selection_split) or "validation"
    known_splits = {
        obs.split
        for obs in observations
        if obs.split and obs.split != "unknown"
    }

    if not known_splits:
        return list(observations)

    filtered = [obs for obs in observations if obs.split == split_token]

    if filtered:
        return filtered

    _append_issue(
        issues,
        options.max_issues,
        severity=IssueSeverity.WARNING,
        code="selection_split_unavailable",
        message="Configured selection split was unavailable; using all observations for bounded calibration.",
        details={
            "selection_split": split_token,
            "known_splits": sorted(known_splits)[: options.max_summary_items],
        },
    )
    return list(observations)


def _label_summary(observations: Sequence[_Observation], options: ThresholdOptions) -> dict[str, Any]:
    counter: Counter[int] = Counter()
    positive_labels = set(options.positive_label_codes)
    negative_labels = set(options.negative_label_codes)
    ignore_labels = set(options.ignore_label_codes)
    total_weight = 0.0
    positive_weight = 0.0
    negative_weight = 0.0
    ignore_weight = 0.0

    for obs in observations:
        total_weight += float(obs.weight)

        if obs.label_code is None:
            continue

        code = int(obs.label_code)
        counter[code] += 1

        if code in positive_labels:
            positive_weight += float(obs.weight)
        elif code in negative_labels:
            negative_weight += float(obs.weight)
        elif code in ignore_labels:
            ignore_weight += float(obs.weight)

    labeled_weight = positive_weight + negative_weight + ignore_weight
    distribution = {
        str(code): _round6(float(count) / float(sum(counter.values())))
        for code, count in sorted(counter.items())
    } if counter else {}

    return {
        "available": bool(counter),
        "observation_count": len(observations),
        "labeled_count": sum(counter.values()),
        "class_count": len(counter),
        "class_distribution": distribution,
        "total_weight": _round6(total_weight),
        "labeled_weight": _round6(labeled_weight),
        "positive_weight": _round6(positive_weight),
        "negative_weight": _round6(negative_weight),
        "ignore_weight": _round6(ignore_weight),
        "subject_label_pairs_omitted": True,
        "raw_labels_omitted": True,
    }


def _score_profile(observations: Sequence[_Observation], options: ThresholdOptions) -> dict[str, Any]:
    if not observations:
        return {
            "available": False,
            "count": 0,
            "raw_values_retained": False,
        }

    pairs = [
        (float(obs.score), float(obs.weight))
        for obs in observations
        if obs.score is not None and float(obs.weight) > 0
    ]

    if not pairs:
        return {
            "available": False,
            "count": 0,
            "raw_values_retained": False,
        }

    scores = sorted(score for score, _weight in pairs)
    weights = [weight for _score, weight in pairs]
    total_weight = sum(weights)
    mean_value = _mean(scores)
    std_value = _stddev(scores, mean_value)
    quantiles = {}

    for q in options.default_quantiles:
        key = f"p{int(round(float(q) * 100.0)):02d}"
        value = _weighted_quantile(pairs, float(q))

        if value is not None:
            quantiles[key] = value

    return {
        "available": True,
        "count": len(pairs),
        "total_weight": _round6(total_weight),
        "min": _round6(scores[0]),
        "max": _round6(scores[-1]),
        "mean": _round6(mean_value),
        "std": _round6(std_value),
        "median": _round6(_weighted_quantile(pairs, 0.50) or _median(scores)),
        "quantiles": quantiles,
        "raw_values_retained": False,
        "subject_score_pairs_omitted": True,
    }


# -----------------------------------------------------------------------------
# Metrics and candidate models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ThresholdMetrics:
    """
    Bounded threshold evaluation metrics.
    """

    available: bool = False
    supervised_available: bool = False
    threshold: float = 0.0
    total_weight: float = 0.0
    labeled_weight: float = 0.0
    positive_weight: float = 0.0
    negative_weight: float = 0.0
    unlabeled_weight: float = 0.0
    predicted_positive_weight: float = 0.0
    tp: float = 0.0
    fp: float = 0.0
    tn: float = 0.0
    fn: float = 0.0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    true_positive_rate: float = 0.0
    false_positive_rate: float = 0.0
    specificity: float = 0.0
    balanced_accuracy: float = 0.0
    you_j: float = 0.0
    cost: float = 0.0
    cost_rate: float = 0.0
    positive_rate: float = 0.0
    predicted_positive_rate: float = 0.0
    mean_score: float = 0.0
    median_score: float = 0.0
    std_score: float = 0.0
    min_score: float = 0.0
    max_score: float = 0.0
    quantiles: Mapping[str, float] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "available", _as_bool(self.available, False))
        object.__setattr__(self, "supervised_available", _as_bool(self.supervised_available, False))
        object.__setattr__(self, "threshold", _round6(_clip_float(self.threshold, 0.0, 1.0, 0.0)))

        for name in (
            "total_weight",
            "labeled_weight",
            "positive_weight",
            "negative_weight",
            "unlabeled_weight",
            "predicted_positive_weight",
            "tp",
            "fp",
            "tn",
            "fn",
            "cost",
            "cost_rate",
            "mean_score",
            "median_score",
            "std_score",
            "min_score",
            "max_score",
        ):
            object.__setattr__(self, name, _round6(max(0.0, _clip_float(getattr(self, name), 0.0, 1e18, 0.0))))

        for name in (
            "accuracy",
            "precision",
            "recall",
            "f1",
            "true_positive_rate",
            "false_positive_rate",
            "specificity",
            "balanced_accuracy",
            "positive_rate",
            "predicted_positive_rate",
        ):
            object.__setattr__(self, name, _round6(_clip_float(getattr(self, name), 0.0, 1.0, 0.0)))

        object.__setattr__(self, "you_j", _round6(_clip_float(self.you_j, -1.0, 1.0, 0.0)))
        object.__setattr__(self, "quantiles", MappingProxyType(_normalize_float_mapping(self.quantiles, {}, minimum=0.0, maximum=1e18)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": bool(self.available),
            "supervised_available": bool(self.supervised_available),
            "threshold": float(self.threshold),
            "total_weight": float(self.total_weight),
            "labeled_weight": float(self.labeled_weight),
            "positive_weight": float(self.positive_weight),
            "negative_weight": float(self.negative_weight),
            "unlabeled_weight": float(self.unlabeled_weight),
            "predicted_positive_weight": float(self.predicted_positive_weight),
            "confusion": {
                "tp": float(self.tp),
                "fp": float(self.fp),
                "tn": float(self.tn),
                "fn": float(self.fn),
            },
            "accuracy": float(self.accuracy),
            "precision": float(self.precision),
            "recall": float(self.recall),
            "f1": float(self.f1),
            "true_positive_rate": float(self.true_positive_rate),
            "false_positive_rate": float(self.false_positive_rate),
            "specificity": float(self.specificity),
            "balanced_accuracy": float(self.balanced_accuracy),
            "you_j": float(self.you_j),
            "cost": float(self.cost),
            "cost_rate": float(self.cost_rate),
            "positive_rate": float(self.positive_rate),
            "predicted_positive_rate": float(self.predicted_positive_rate),
            "score_stats": {
                "mean": float(self.mean_score),
                "median": float(self.median_score),
                "std": float(self.std_score),
                "min": float(self.min_score),
                "max": float(self.max_score),
            },
            "quantiles": dict(self.quantiles),
        }


@dataclass(frozen=True, slots=True)
class ThresholdCandidate:
    """
    One bounded candidate operating point.
    """

    threshold: float = 0.0
    policy: ThresholdPolicy | str = ThresholdPolicy.FIXED
    metrics: ThresholdMetrics = dataclass_field(default_factory=ThresholdMetrics)
    composite_score: Optional[float] = None
    rank: int = 0
    reasons: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "threshold", _round6(_clip_float(self.threshold, 0.0, 1.0, 0.0)))
        object.__setattr__(
            self,
            "policy",
            _normalize_enum_option(ThresholdPolicy, self.policy, ThresholdPolicy.FIXED),
        )

        if isinstance(self.metrics, Mapping):
            fields = set(getattr(ThresholdMetrics, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in self.metrics.items() if key in fields}

            try:
                object.__setattr__(self, "metrics", ThresholdMetrics(**clean))
            except Exception:
                object.__setattr__(self, "metrics", ThresholdMetrics())

        if self.composite_score is not None:
            object.__setattr__(
                self,
                "composite_score",
                _round6(_clip_float(self.composite_score, 0.0, 10.0, 0.0)),
            )

        object.__setattr__(self, "rank", max(0, _as_int(self.rank, 0)))
        object.__setattr__(
            self,
            "reasons",
            tuple(
                dict.fromkeys(
                    _clean_text(reason, 200)
                    for reason in (self.reasons or ())
                    if _clean_text(reason, 200)
                )
            )[:50],
        )
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": float(self.threshold),
            "policy": _enum_value(self.policy, ThresholdPolicy.FIXED.value),
            "metrics": self.metrics.to_dict(),
            "composite_score": float(self.composite_score) if self.composite_score is not None else None,
            "rank": int(self.rank),
            "reasons": list(self.reasons),
            "metadata": _safe_detail_value(self.metadata),
        }


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


def _evaluate_threshold(
    observations: Sequence[_Observation],
    threshold: float,
    options: ThresholdOptions,
) -> ThresholdMetrics:
    threshold = _round6(_clip_float(threshold, options.score_min, options.score_max, options.score_min))
    positive_codes = set(options.positive_label_codes)
    negative_codes = set(options.negative_label_codes)
    ignore_codes = set(options.ignore_label_codes)

    total_weight = 0.0
    labeled_weight = 0.0
    positive_weight = 0.0
    negative_weight = 0.0
    unlabeled_weight = 0.0
    predicted_positive_weight = 0.0
    tp = 0.0
    fp = 0.0
    tn = 0.0
    fn = 0.0
    scores: list[float] = []
    score_weights: list[tuple[float, float]] = []

    for obs in observations:
        weight = max(0.0, float(obs.weight))

        if weight <= 0 or obs.score is None:
            continue

        score = float(obs.score)
        total_weight += weight
        scores.append(score)
        score_weights.append((score, weight))
        predicted = score >= threshold

        if predicted:
            predicted_positive_weight += weight

        label = _binary_label(obs.label_code, positive_codes, negative_codes, ignore_codes)

        if label is None:
            unlabeled_weight += weight
            continue

        labeled_weight += weight

        if label == 1:
            positive_weight += weight

            if predicted:
                tp += weight
            else:
                fn += weight
        else:
            negative_weight += weight

            if predicted:
                fp += weight
            else:
                tn += weight

    if total_weight <= 0:
        return ThresholdMetrics(threshold=threshold)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    accuracy = (tp + tn) / labeled_weight if labeled_weight > 0 else 0.0
    balanced_accuracy = ((recall + tnr) / 2.0) if (positive_weight > 0 and negative_weight > 0) else accuracy
    you_j = recall - fpr
    cost = fp * float(options.cost_false_positive) + fn * float(options.cost_false_negative)
    cost_rate = cost / labeled_weight if labeled_weight > 0 else 0.0
    positive_rate = positive_weight / labeled_weight if labeled_weight > 0 else 0.0
    predicted_positive_rate = predicted_positive_weight / total_weight if total_weight > 0 else 0.0

    mean_score = _mean(scores) if scores else 0.0
    std_score = _stddev(scores, mean_score) if len(scores) > 1 else 0.0
    quantiles = {}

    for q in options.default_quantiles:
        key = f"p{int(round(float(q) * 100.0)):02d}"
        value = _weighted_quantile(score_weights, float(q))

        if value is not None:
            quantiles[key] = value

    return ThresholdMetrics(
        available=True,
        supervised_available=labeled_weight > 0 and (positive_weight + negative_weight) > 0,
        threshold=threshold,
        total_weight=total_weight,
        labeled_weight=labeled_weight,
        positive_weight=positive_weight,
        negative_weight=negative_weight,
        unlabeled_weight=unlabeled_weight,
        predicted_positive_weight=predicted_positive_weight,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        true_positive_rate=recall,
        false_positive_rate=fpr,
        specificity=tnr,
        balanced_accuracy=balanced_accuracy,
        you_j=you_j,
        cost=cost,
        cost_rate=cost_rate,
        positive_rate=positive_rate,
        predicted_positive_rate=predicted_positive_rate,
        mean_score=mean_score,
        median_score=_weighted_quantile(score_weights, 0.50) or _median(scores),
        std_score=std_score,
        min_score=min(scores) if scores else 0.0,
        max_score=max(scores) if scores else 0.0,
        quantiles=quantiles,
    )


def _subsample_sorted(values: Sequence[float], count: int) -> list[float]:
    if count <= 0:
        return []

    if len(values) <= count:
        return list(values)

    if count == 1:
        return [values[len(values) // 2]]

    step = float(len(values) - 1) / float(count - 1)
    indices = sorted({min(len(values) - 1, max(0, int(round(i * step)))) for i in range(count)})
    return [values[index] for index in indices]


def _generate_candidates(
    observations: Sequence[_Observation],
    options: ThresholdOptions,
    request: ThresholdRequest,
    issues: list[ThresholdIssue],
) -> list[float]:
    if not observations:
        return [options.default_threshold]

    scores = sorted(float(obs.score) for obs in observations if obs.score is not None)

    if not scores:
        return [options.default_threshold]

    target_positive_rate = (
        request.target_positive_rate
        if request.target_positive_rate is not None
        else options.target_positive_rate
    )
    default_threshold = (
        request.threshold
        if request.threshold is not None
        else options.default_threshold
    )
    quantiles = tuple(request.quantiles or options.default_quantiles)

    priority: list[float] = []
    priority.extend(
        [
            default_threshold,
            options.score_min,
            options.score_max,
            (options.score_min + options.score_max) / 2.0,
        ]
    )
    priority.extend(float(value) for value in options.risk_thresholds.values())

    target_quantile = _weighted_quantile(
        [(float(obs.score), float(obs.weight)) for obs in observations],
        max(0.0, min(1.0, 1.0 - float(target_positive_rate))),
    )

    if target_quantile is not None:
        priority.append(float(target_quantile))

    for q in quantiles:
        value = _weighted_quantile(
            [(float(obs.score), float(obs.weight)) for obs in observations],
            float(q),
        )

        if value is not None:
            priority.append(float(value))

    unique_scores = sorted(set(scores))
    max_candidates = max(2, int(options.max_candidates))

    if len(unique_scores) + len(priority) <= max_candidates:
        candidates = sorted(set(priority + unique_scores))
    else:
        remaining = max(1, max_candidates - len(set(priority)))
        sampled = _subsample_sorted(unique_scores, remaining)
        candidates = sorted(set(priority + sampled))

    clipped = [
        _round6(_clip_float(value, options.score_min, options.score_max, options.default_threshold))
        for value in candidates
    ]
    out = sorted(set(clipped))

    if len(out) > max_candidates:
        out = _subsample_sorted(out, max_candidates)

    if not out:
        out = [options.default_threshold]
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="threshold_candidate_generation_fallback",
            message="No threshold candidates could be generated; using default threshold.",
        )

    return out


def _composite_score(metrics: ThresholdMetrics, options: ThresholdOptions) -> float:
    weights = dict(options.policy_weights)
    total = sum(max(0.0, float(value)) for value in weights.values())

    if total <= 0:
        return 0.0

    components = {
        "recall": float(metrics.recall),
        "precision": float(metrics.precision),
        "f1": float(metrics.f1),
        "balanced_accuracy": float(metrics.balanced_accuracy),
        "you_j": max(0.0, float(metrics.you_j)),
        "fpr_penalty": max(0.0, 1.0 - float(metrics.false_positive_rate)),
    }
    score = 0.0

    for key, weight in weights.items():
        value = max(0.0, float(weight))

        if value <= 0:
            continue

        score += value * float(components.get(key, 0.0))

    return _round6(score / total)


def _tie_break_key(
    candidate: ThresholdCandidate,
    default_threshold: float,
    maximize: bool = True,
) -> tuple[Any, ...]:
    metrics = candidate.metrics
    primary = float(
        max(
            metrics.recall,
            metrics.precision,
            metrics.f1,
            metrics.balanced_accuracy,
            max(0.0, metrics.you_j),
        )
    )
    distance = abs(float(candidate.threshold) - float(default_threshold))

    if maximize:
        return (
            primary,
            -float(metrics.predicted_positive_rate),
            -distance,
            float(candidate.threshold),
        )

    return (
        -primary,
        float(metrics.predicted_positive_rate),
        distance,
        -float(candidate.threshold),
    )


def _choose_threshold(
    observations: Sequence[_Observation],
    options: ThresholdOptions,
    request: ThresholdRequest,
    issues: list[ThresholdIssue],
    start_time: float,
) -> tuple[Optional[ThresholdCandidate], list[ThresholdCandidate]]:
    if not observations:
        return None, []

    candidates = _generate_candidates(observations, options, request, issues)
    default_threshold = (
        request.threshold
        if request.threshold is not None
        else options.default_threshold
    )
    policy = _normalize_enum_option(
        ThresholdPolicy,
        request.policy or options.default_policy,
        ThresholdPolicy.HYBRID,
    )
    target_positive_rate = (
        request.target_positive_rate
        if request.target_positive_rate is not None
        else options.target_positive_rate
    )
    max_fpr = request.max_fpr if request.max_fpr is not None else options.max_fpr
    min_recall = request.min_recall if request.min_recall is not None else options.min_recall
    min_precision = request.min_precision if request.min_precision is not None else options.min_precision
    max_cost = request.max_cost if request.max_cost is not None else options.max_cost
    ewma_decay = request.ewma_decay if request.ewma_decay is not None else options.ewma_decay

    metrics_cache: dict[float, ThresholdMetrics] = {}

    def get_metrics(threshold: float) -> ThresholdMetrics:
        key = _round6(_clip_float(threshold, options.score_min, options.score_max, options.score_min))

        if key not in metrics_cache:
            metrics_cache[key] = _evaluate_threshold(observations, key, options)

        return metrics_cache[key]

    evaluated: list[ThresholdCandidate] = []

    for threshold in candidates:
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="threshold_candidate_evaluation_time_budget_exhausted",
                message="Threshold candidate evaluation stopped after reaching configured time budget.",
                details={
                    "evaluated": len(evaluated),
                    "remaining": max(0, len(candidates) - len(evaluated)),
                },
            )
            break

        metrics = get_metrics(threshold)
        evaluated.append(
            ThresholdCandidate(
                threshold=threshold,
                policy=policy,
                metrics=metrics,
                composite_score=_composite_score(metrics, options),
            )
        )

    if not evaluated:
        metrics = get_metrics(default_threshold)
        evaluated = [
            ThresholdCandidate(
                threshold=default_threshold,
                policy=policy,
                metrics=metrics,
                composite_score=_composite_score(metrics, options),
            )
        ]

    supervised = any(candidate.metrics.supervised_available for candidate in evaluated)

    if policy == ThresholdPolicy.FIXED:
        threshold = _round6(_clip_float(default_threshold, options.score_min, options.score_max, options.default_threshold))
        metrics = get_metrics(threshold)
        selected = ThresholdCandidate(
            threshold=threshold,
            policy=policy,
            metrics=metrics,
            composite_score=_composite_score(metrics, options),
            reasons=("fixed_threshold",),
        )
        return selected, evaluated

    if policy == ThresholdPolicy.QUANTILE:
        threshold = _weighted_quantile(
            [(float(obs.score), float(obs.weight)) for obs in observations],
            max(0.0, min(1.0, 1.0 - float(target_positive_rate))),
        )

        if threshold is None:
            threshold = default_threshold

        threshold = _round6(_clip_float(threshold, options.score_min, options.score_max, options.default_threshold))
        metrics = get_metrics(threshold)
        selected = ThresholdCandidate(
            threshold=threshold,
            policy=policy,
            metrics=metrics,
            composite_score=_composite_score(metrics, options),
            reasons=(
                "target_positive_rate_quantile",
                f"target_positive_rate={_round6(float(target_positive_rate))}",
            ),
        )
        return selected, evaluated

    if not supervised:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="label_dependent_policy_fallback",
            message="Label-dependent threshold policy fell back to quantile because supervised labels are unavailable.",
            details={"requested_policy": _enum_value(policy, ThresholdPolicy.HYBRID.value)},
        )
        threshold = _weighted_quantile(
            [(float(obs.score), float(obs.weight)) for obs in observations],
            max(0.0, min(1.0, 1.0 - float(target_positive_rate))),
        )

        if threshold is None:
            threshold = default_threshold

        threshold = _round6(_clip_float(threshold, options.score_min, options.score_max, options.default_threshold))
        metrics = get_metrics(threshold)
        selected = ThresholdCandidate(
            threshold=threshold,
            policy=ThresholdPolicy.QUANTILE,
            metrics=metrics,
            composite_score=_composite_score(metrics, options),
            reasons=("label_dependent_fallback_to_quantile",),
        )
        return selected, evaluated

    if policy == ThresholdPolicy.YOU_J:
        selected = max(
            evaluated,
            key=lambda candidate: (
                float(candidate.metrics.you_j),
                -float(candidate.metrics.predicted_positive_rate),
                -abs(float(candidate.threshold) - float(default_threshold)),
                float(candidate.threshold),
            ),
        )
        selected = replace(selected, policy=policy, reasons=("max_youden_j",))
        return selected, evaluated

    if policy == ThresholdPolicy.MAX_F1:
        selected = max(
            evaluated,
            key=lambda candidate: (
                float(candidate.metrics.f1),
                -float(candidate.metrics.predicted_positive_rate),
                -abs(float(candidate.threshold) - float(default_threshold)),
                float(candidate.threshold),
            ),
        )
        selected = replace(selected, policy=policy, reasons=("max_f1",))
        return selected, evaluated

    if policy == ThresholdPolicy.MIN_RECALL_AT_FPR:
        feasible = [
            candidate
            for candidate in evaluated
            if float(candidate.metrics.false_positive_rate) <= float(max_fpr) + _THRESHOLD_EPS
        ]

        if feasible:
            selected = max(
                feasible,
                key=lambda candidate: (
                    float(candidate.metrics.recall),
                    -float(candidate.metrics.false_positive_rate),
                    -float(candidate.metrics.predicted_positive_rate),
                    float(candidate.threshold),
                ),
            )
            reasons = ("feasible_max_fpr", "max_recall")
        else:
            selected = min(
                evaluated,
                key=lambda candidate: (
                    float(candidate.metrics.false_positive_rate),
                    -float(candidate.metrics.recall),
                    float(candidate.threshold),
                ),
            )
            reasons = ("no_feasible_max_fpr", "min_fpr_then_max_recall")

        selected = replace(selected, policy=policy, reasons=reasons, metadata={"max_fpr": _round6(float(max_fpr))})
        return selected, evaluated

    if policy == ThresholdPolicy.MIN_PRECISION_AT_RECALL:
        feasible = [
            candidate
            for candidate in evaluated
            if float(candidate.metrics.recall) >= float(min_recall) - _THRESHOLD_EPS
        ]

        if feasible:
            selected = max(
                feasible,
                key=lambda candidate: (
                    float(candidate.metrics.precision),
                    -float(candidate.metrics.predicted_positive_rate),
                    float(candidate.threshold),
                ),
            )
            reasons = ("feasible_min_recall", "max_precision")
        else:
            selected = max(
                evaluated,
                key=lambda candidate: (
                    float(candidate.metrics.recall),
                    float(candidate.metrics.precision),
                    float(candidate.threshold),
                ),
            )
            reasons = ("no_feasible_min_recall", "max_recall_then_precision")

        selected = replace(
            selected,
            policy=policy,
            reasons=reasons,
            metadata={"min_recall": _round6(float(min_recall))},
        )
        return selected, evaluated

    if policy == ThresholdPolicy.COST_SENSITIVE:
        feasible = [
            candidate
            for candidate in evaluated
            if max_cost is None or float(candidate.metrics.cost_rate) <= float(max_cost) + _THRESHOLD_EPS
        ]

        pool = feasible or evaluated
        selected = min(
            pool,
            key=lambda candidate: (
                float(candidate.metrics.cost_rate),
                float(candidate.metrics.predicted_positive_rate),
                abs(float(candidate.threshold) - float(default_threshold)),
                float(candidate.threshold),
            ),
        )
        selected = replace(
            selected,
            policy=policy,
            reasons=("min_expected_cost_rate", "feasible_max_cost" if feasible else "no_feasible_max_cost"),
            metadata={
                "max_cost": _round6(float(max_cost)) if max_cost is not None else None,
                "cost_false_positive": _round6(float(options.cost_false_positive)),
                "cost_false_negative": _round6(float(options.cost_false_negative)),
            },
        )
        return selected, evaluated

    if policy == ThresholdPolicy.ADAPTIVE_EWMA:
        current = _weighted_quantile(
            [(float(obs.score), float(obs.weight)) for obs in observations],
            max(0.0, min(1.0, 1.0 - float(target_positive_rate))),
        )

        if current is None:
            current = default_threshold

        reference = _reference_threshold(request.reference_profile)
        decay = _clip_float(ewma_decay, 0.01, 1.0, _DEFAULT_EWMA_DECAY)

        if reference is None:
            threshold = current
            reasons = ("ewma_no_reference", "target_positive_rate_quantile")
        else:
            threshold = float(decay) * float(reference) + (1.0 - float(decay)) * float(current)
            reasons = ("ewma_blended_with_reference", "target_positive_rate_quantile")

        threshold = _round6(_clip_float(threshold, options.score_min, options.score_max, options.default_threshold))
        metrics = get_metrics(threshold)
        selected = ThresholdCandidate(
            threshold=threshold,
            policy=policy,
            metrics=metrics,
            composite_score=_composite_score(metrics, options),
            reasons=reasons,
            metadata={
                "ewma_decay": _round6(float(decay)),
                "reference_threshold": _round6(float(reference)) if reference is not None else None,
                "current_quantile_threshold": _round6(float(current)),
            },
        )
        return selected, evaluated

    # Hybrid policy.
    scored: list[ThresholdCandidate] = []

    for candidate in evaluated:
        composite = _composite_score(candidate.metrics, options)
        scored.append(
            replace(
                candidate,
                policy=policy,
                composite_score=composite,
                reasons=("hybrid_composite_score",),
            )
        )

    selected = max(
        scored,
        key=lambda candidate: (
            float(candidate.composite_score or 0.0),
            -float(candidate.metrics.predicted_positive_rate),
            -abs(float(candidate.threshold) - float(default_threshold)),
            float(candidate.threshold),
        ),
    )
    return selected, scored


def _reference_threshold(reference_profile: Any) -> Optional[float]:
    if reference_profile is None:
        return None

    if isinstance(reference_profile, ThresholdProfile):
        return _coerce_optional_float(reference_profile.threshold, allow_bool=False)

    if isinstance(reference_profile, Mapping):
        for key in ("threshold", "selected_threshold", "operating_point"):
            value = _coerce_optional_float(reference_profile.get(key), allow_bool=False)

            if value is not None:
                return value

        metadata = reference_profile.get("metadata")

        if isinstance(metadata, Mapping):
            for key in ("threshold", "selected_threshold", "operating_point"):
                value = _coerce_optional_float(metadata.get(key), allow_bool=False)

                if value is not None:
                    return value

    value = getattr(reference_profile, "threshold", None)
    return _coerce_optional_float(value, allow_bool=False)


def _normalize_reference_profile(reference_profile: Any) -> dict[str, Any]:
    if reference_profile is None:
        return {}

    if isinstance(reference_profile, ThresholdProfile):
        profile = _as_mapping(reference_profile.score_profile)

        if profile:
            return profile

        return _as_mapping(reference_profile.metadata.get("score_profile"))

    if isinstance(reference_profile, Mapping):
        for key in ("score_profile", "profile", "stats", "summary"):
            value = reference_profile.get(key)

            if isinstance(value, Mapping):
                return _as_mapping(value)

        if any(key in reference_profile for key in ("mean", "std", "min", "max", "quantiles")):
            return _as_mapping(reference_profile)

    summary = _safe_detail_value(reference_profile)

    if isinstance(summary, Mapping):
        return _normalize_reference_profile(summary)

    return {}


def _compute_drift(
    current_profile: Mapping[str, Any],
    reference_profile: Any,
    options: ThresholdOptions,
) -> dict[str, Any]:
    reference = _normalize_reference_profile(reference_profile)

    if not current_profile.get("available") or not reference:
        return {
            "available": False,
            "reason": "reference_or_current_profile_unavailable",
            "raw_values_retained": False,
        }

    components: dict[str, float] = {}
    scale_candidates: list[float] = []

    for source in (current_profile, reference):
        mean_value = _coerce_optional_float(source.get("mean"), allow_bool=False)
        std_value = _coerce_optional_float(source.get("std"), allow_bool=False)
        min_value = _coerce_optional_float(source.get("min"), allow_bool=False)
        max_value = _coerce_optional_float(source.get("max"), allow_bool=False)

        if mean_value is not None and std_value is not None:
            scale_candidates.append(max(abs(float(std_value)), 1e-6))

        if min_value is not None and max_value is not None:
            scale_candidates.append(max(abs(float(max_value) - float(min_value)), 1e-6))

    scale = max(scale_candidates) if scale_candidates else max(options.score_max - options.score_min, 1.0)

    for key in ("mean", "std", "median", "min", "max"):
        cur = _coerce_optional_float(current_profile.get(key), allow_bool=False)
        ref = _coerce_optional_float(reference.get(key), allow_bool=False)

        if cur is None or ref is None:
            continue

        components[key] = _round6(min(1.0, abs(float(cur) - float(ref)) / max(float(scale), 1e-6)))

    cur_quantiles = current_profile.get("quantiles")
    ref_quantiles = reference.get("quantiles")

    if isinstance(cur_quantiles, Mapping) and isinstance(ref_quantiles, Mapping):
        for key in sorted(set(cur_quantiles) & set(ref_quantiles)):
            cur = _coerce_optional_float(cur_quantiles.get(key), allow_bool=False)
            ref = _coerce_optional_float(ref_quantiles.get(key), allow_bool=False)

            if cur is None or ref is None:
                continue

            components[f"quantile_{key}"] = _round6(
                min(1.0, abs(float(cur) - float(ref)) / max(float(scale), 1e-6))
            )

    cur_positive = _coerce_optional_float(current_profile.get("positive_rate"), allow_bool=False)
    ref_positive = _coerce_optional_float(reference.get("positive_rate"), allow_bool=False)

    if cur_positive is not None and ref_positive is not None:
        components["positive_rate"] = _round6(min(1.0, abs(float(cur_positive) - float(ref_positive))))

    if not components:
        return {
            "available": False,
            "reason": "no_comparable_profile_fields",
            "raw_values_retained": False,
        }

    score = _round6(max(components.values()))
    level = "PASS"

    if score >= float(options.drift_fail):
        level = "FAIL"
    elif score >= float(options.drift_warn):
        level = "WARN"

    top = sorted(components.items(), key=lambda item: (-float(item[1]), item[0]))[: options.max_summary_items]

    return {
        "available": True,
        "method": "summary_based_score_drift",
        "score": score,
        "level": level,
        "drift_warn": _round6(float(options.drift_warn)),
        "drift_fail": _round6(float(options.drift_fail)),
        "components": dict(top),
        "component_count": len(components),
        "truncated": len(components) > options.max_summary_items,
        "raw_values_retained": False,
    }


def _estimate_stability(
    observations: Sequence[_Observation],
    options: ThresholdOptions,
    request: ThresholdRequest,
    issues: list[ThresholdIssue],
    start_time: float,
) -> dict[str, Any]:
    if not options.include_stability:
        return {"available": False, "reason": "disabled_by_policy"}

    if len(observations) < max(2, int(options.min_stability_samples)):
        return {
            "available": False,
            "reason": "insufficient_observations",
            "observation_count": len(observations),
            "min_stability_samples": int(options.min_stability_samples),
        }

    repeats = max(0, int(options.stability_repeats))

    if repeats <= 0:
        return {"available": False, "reason": "stability_repeats_zero"}

    sample_size = min(int(options.max_stability_sample), len(observations))
    thresholds: list[float] = []
    stability_options = replace(
        options,
        include_stability=False,
        register_profiles=False,
        max_candidates=min(int(options.max_candidates), int(options.max_stability_candidates)),
        stability_repeats=0,
    )
    rng = _DetRandom(
        options.salt,
        f"muleguard.rules.thresholds.stability.{_normalize_token(options.namespace)}",
        options.seed,
        len(observations),
        sample_size,
        repeats,
    )

    for repeat in range(repeats):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="threshold_stability_time_budget_exhausted",
                message="Threshold stability estimation stopped after reaching configured time budget.",
                details={"completed_repeats": len(thresholds), "requested_repeats": repeats},
            )
            break

        indices = [rng.randrange(len(observations)) for _ in range(sample_size)]
        resampled = [observations[index] for index in indices]
        local_issues: list[ThresholdIssue] = []
        selected, _candidates = _choose_threshold(
            resampled,
            stability_options,
            request,
            local_issues,
            time.monotonic(),
        )

        if selected is not None:
            thresholds.append(float(selected.threshold))

    if len(thresholds) < 2:
        return {
            "available": False,
            "reason": "insufficient_stability_replicates",
            "requested_repeats": repeats,
            "completed_repeats": len(thresholds),
        }

    mean_value = _mean(thresholds)
    std_value = _stddev(thresholds, mean_value)
    min_value = min(thresholds)
    max_value = max(thresholds)
    range_scale = max(float(options.score_max) - float(options.score_min), 1e-6)
    normalized_spread = min(1.0, float(std_value) / max(0.25 * range_scale, 1e-6))
    stability = _round6(max(0.0, min(1.0, 1.0 - normalized_spread)))

    return {
        "available": True,
        "method": "deterministic_bootstrap_replicate_thresholds",
        "repeats_requested": repeats,
        "repeats_completed": len(thresholds),
        "sample_size": sample_size,
        "mean_threshold": _round6(mean_value),
        "std_threshold": _round6(std_value),
        "min_threshold": _round6(min_value),
        "max_threshold": _round6(max_value),
        "stability": stability,
        "raw_values_retained": False,
    }


# -----------------------------------------------------------------------------
# Profile model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ThresholdProfile:
    """
    Safe bounded threshold profile.
    """

    ok: bool = True
    status: ThresholdStatus | str = ThresholdStatus.PASSED
    policy: ThresholdPolicy | str = ThresholdPolicy.HYBRID
    source: ThresholdSource | str = ThresholdSource.SYNTHETIC_PROFILE
    score_kind: ScoreKind | str = ScoreKind.GENERIC
    threshold: float = _DEFAULT_THRESHOLD
    metrics: ThresholdMetrics = dataclass_field(default_factory=ThresholdMetrics)
    candidates: tuple[ThresholdCandidate, ...] = ()
    stability: Mapping[str, Any] = dataclass_field(default_factory=dict)
    drift: Mapping[str, Any] = dataclass_field(default_factory=dict)
    score_profile: Mapping[str, Any] = dataclass_field(default_factory=dict)
    label_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[ThresholdIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(ThresholdStatus, self.status, ThresholdStatus.PASSED),
        )
        object.__setattr__(
            self,
            "policy",
            _normalize_enum_option(ThresholdPolicy, self.policy, ThresholdPolicy.HYBRID),
        )
        object.__setattr__(
            self,
            "source",
            _normalize_enum_option(ThresholdSource, self.source, ThresholdSource.SYNTHETIC_PROFILE),
        )
        object.__setattr__(
            self,
            "score_kind",
            _normalize_enum_option(ScoreKind, self.score_kind, ScoreKind.GENERIC),
        )
        object.__setattr__(self, "threshold", _round6(_clip_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)))

        if isinstance(self.metrics, Mapping):
            fields = set(getattr(ThresholdMetrics, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in self.metrics.items() if key in fields}

            try:
                object.__setattr__(self, "metrics", ThresholdMetrics(**clean))
            except Exception:
                object.__setattr__(self, "metrics", ThresholdMetrics())

        object.__setattr__(self, "candidates", tuple(self.candidates or ()))
        object.__setattr__(self, "stability", MappingProxyType(_as_mapping(self.stability)))
        object.__setattr__(self, "drift", MappingProxyType(_as_mapping(self.drift)))
        object.__setattr__(self, "score_profile", MappingProxyType(_as_mapping(self.score_profile)))
        object.__setattr__(self, "label_summary", MappingProxyType(_as_mapping(self.label_summary)))
        object.__setattr__(
            self,
            "counts",
            MappingProxyType(
                {
                    str(key): max(0, _as_int(value, 0))
                    for key, value in (self.counts or {}).items()
                }
            ),
        )
        object.__setattr__(self, "issues", tuple(_as_issue(issue) for issue in (self.issues or ())))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": THRESHOLD_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, ThresholdStatus.PASSED.value),
                        "policy": _enum_value(self.policy, ThresholdPolicy.HYBRID.value),
                        "source": _enum_value(self.source, ThresholdSource.SYNTHETIC_PROFILE.value),
                        "score_kind": _enum_value(self.score_kind, ScoreKind.GENERIC.value),
                        "threshold": float(self.threshold),
                        "metrics": self.metrics.to_dict(),
                        "counts": self.counts,
                        "stability": self.stability,
                        "drift": self.drift,
                        "score_profile": self.score_profile,
                        "label_summary": self.label_summary,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": _enum_value(self.status, ThresholdStatus.PASSED.value),
            "policy": _enum_value(self.policy, ThresholdPolicy.HYBRID.value),
            "source": _enum_value(self.source, ThresholdSource.SYNTHETIC_PROFILE.value),
            "score_kind": _enum_value(self.score_kind, ScoreKind.GENERIC.value),
            "threshold": float(self.threshold),
            "metrics": self.metrics.to_dict(),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "stability": _safe_detail_value(self.stability),
            "drift": _safe_detail_value(self.drift),
            "score_profile": _safe_detail_value(self.score_profile),
            "label_summary": _safe_detail_value(self.label_summary),
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "request_id": self.request_id,
            "generated_at": self.generated_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "fingerprint": self.fingerprint,
            "caveats": list(_THRESHOLD_CAVEATS),
            "safety_flags": dict(_THRESHOLD_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Decision models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ThresholdDecision:
    """
    Safe bounded decision for one score.
    """

    score: Optional[float] = None
    threshold: float = _DEFAULT_THRESHOLD
    band: RiskBand | str = RiskBand.UNAVAILABLE
    flagged: bool = False
    review_recommended: bool = False
    decision_source: str = "threshold_profile"
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.score is not None:
            object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))

        object.__setattr__(self, "threshold", _round6(_clip_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)))
        object.__setattr__(
            self,
            "band",
            _normalize_enum_option(RiskBand, self.band, RiskBand.UNAVAILABLE),
        )
        object.__setattr__(self, "flagged", _as_bool(self.flagged, False))
        object.__setattr__(self, "review_recommended", _as_bool(self.review_recommended, False))
        object.__setattr__(self, "decision_source", _clean_text(self.decision_source, 100) or "threshold_profile")
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": float(self.score) if self.score is not None else None,
            "threshold": float(self.threshold),
            "band": _enum_value(self.band, RiskBand.UNAVAILABLE.value),
            "flagged": bool(self.flagged),
            "review_recommended": bool(self.review_recommended),
            "decision_source": self.decision_source,
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_THRESHOLD_CAVEATS),
            "safety_flags": dict(_THRESHOLD_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class ThresholdRecordResult:
    """
    Safe bounded per-record threshold result.
    """

    subject_ref_hash: Optional[str] = None
    index: Optional[int] = None
    score: Optional[float] = None
    threshold: float = _DEFAULT_THRESHOLD
    band: RiskBand | str = RiskBand.UNAVAILABLE
    flagged: bool = False
    review_recommended: bool = False
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

        object.__setattr__(self, "threshold", _round6(_clip_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)))
        object.__setattr__(
            self,
            "band",
            _normalize_enum_option(RiskBand, self.band, RiskBand.UNAVAILABLE),
        )
        object.__setattr__(self, "flagged", _as_bool(self.flagged, False))
        object.__setattr__(self, "review_recommended", _as_bool(self.review_recommended, False))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_ref_hash": self.subject_ref_hash,
            "index": int(self.index) if self.index is not None else None,
            "score": float(self.score) if self.score is not None else None,
            "threshold": float(self.threshold),
            "band": _enum_value(self.band, RiskBand.UNAVAILABLE.value),
            "flagged": bool(self.flagged),
            "review_recommended": bool(self.review_recommended),
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_THRESHOLD_CAVEATS),
            "safety_flags": dict(_THRESHOLD_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local threshold registry
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _RegisteredThresholdProfile:
    profile: ThresholdProfile
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class ThresholdRegistry:
    """
    Bounded process-local threshold profile registry.

    This registry is not durable, not distributed, and not production-ready.
    It exists only to support local prototype workflows, tests, and developer
    tooling.
    """

    def __init__(self, max_profiles: int = _DEFAULT_MAX_PROFILES) -> None:
        self.max_profiles = max(1, int(max_profiles))
        self._profiles: dict[str, _RegisteredThresholdProfile] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, profile: ThresholdProfile) -> str:
        """
        Register one threshold profile and return its profile id.
        """
        with self._lock:
            profile_id = _clean_text(profile.request_id, 128)

            if not profile_id:
                profile_id = profile.fingerprint[:32] or _sha256_hex(str(len(self._profiles) + 1))[:32]

            if profile_id in self._profiles:
                self._profiles[profile_id] = _RegisteredThresholdProfile(
                    profile=profile,
                    registered_at=_now_utc(),
                )
                return profile_id

            self._profiles[profile_id] = _RegisteredThresholdProfile(
                profile=profile,
                registered_at=_now_utc(),
            )
            self._order.append(profile_id)

            if len(self._order) > self.max_profiles:
                evict_id = self._order.pop(0)
                self._profiles.pop(evict_id, None)

            return profile_id

    def get_profile(self, profile_id: Any) -> Optional[ThresholdProfile]:
        """
        Return one registered threshold profile.
        """
        key = _clean_text(profile_id, 128)

        with self._lock:
            entry = self._profiles.get(key)
            return entry.profile if entry is not None else None

    def latest_profile(self) -> Optional[ThresholdProfile]:
        """
        Return the most recently registered profile.
        """
        with self._lock:
            if not self._order:
                return None

            entry = self._profiles.get(self._order[-1])
            return entry.profile if entry is not None else None

    def list_profiles(self, *, limit: int = 50) -> tuple[ThresholdProfile, ...]:
        """
        Return registered profiles in insertion order.
        """
        with self._lock:
            out: list[ThresholdProfile] = []

            for profile_id in self._order[: max(1, int(limit))]:
                entry = self._profiles.get(profile_id)

                if entry is not None:
                    out.append(entry.profile)

            return tuple(out)

    def summarize(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """
        Return safe registry summaries.
        """
        with self._lock:
            out: list[dict[str, Any]] = []

            for profile_id in self._order[: max(1, int(limit))]:
                entry = self._profiles.get(profile_id)

                if entry is None:
                    continue

                profile = entry.profile

                out.append(
                    {
                        "profile_id": profile.request_id or profile_id,
                        "status": _enum_value(profile.status, ThresholdStatus.PASSED.value),
                        "policy": _enum_value(profile.policy, ThresholdPolicy.HYBRID.value),
                        "source": _enum_value(profile.source, ThresholdSource.SYNTHETIC_PROFILE.value),
                        "score_kind": _enum_value(profile.score_kind, ScoreKind.GENERIC.value),
                        "threshold": float(profile.threshold),
                        "generated_at": profile.generated_at.isoformat(),
                        "duration_ms": int(profile.duration_ms),
                        "fingerprint": profile.fingerprint,
                        "issue_count": len(profile.issues),
                        "counts": dict(profile.counts),
                    }
                )

            return out

    def clear(self) -> None:
        """
        Clear the process-local registry.
        """
        with self._lock:
            self._profiles.clear()
            self._order.clear()

    def safe_summary(self, *, limit: int = 50) -> dict[str, Any]:
        """
        Return safe registry summary.
        """
        with self._lock:
            status_counter = Counter(
                _enum_value(entry.profile.status, ThresholdStatus.PASSED.value)
                for entry in self._profiles.values()
            )
            policy_counter = Counter(
                _enum_value(entry.profile.policy, ThresholdPolicy.HYBRID.value)
                for entry in self._profiles.values()
            )

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_profiles": self.max_profiles,
            "registered_profiles": len(self._order),
            "by_status": dict(status_counter),
            "by_policy": dict(policy_counter),
            "recent": self.summarize(limit=limit),
        }


_default_registry: Optional[ThresholdRegistry] = None
_default_registry_lock = threading.Lock()


def get_threshold_registry(
    max_profiles: int | None = None,
    *,
    rebuild: bool = False,
) -> ThresholdRegistry:
    """
    Return the process-wide threshold registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = ThresholdRegistry(
                max_profiles=max_profiles if max_profiles is not None else _DEFAULT_MAX_PROFILES
            )

        return _default_registry


# -----------------------------------------------------------------------------
# Threshold engine
# -----------------------------------------------------------------------------


def _risk_band_for_score(score: Optional[float], options: ThresholdOptions) -> RiskBand:
    if score is None:
        return RiskBand.UNAVAILABLE

    value = float(score)
    thresholds = options.risk_thresholds

    if value >= float(thresholds.get("critical", 0.90)):
        return RiskBand.CRITICAL

    if value >= float(thresholds.get("high", 0.75)):
        return RiskBand.HIGH

    if value >= float(thresholds.get("medium", 0.55)):
        return RiskBand.MEDIUM

    if value >= float(thresholds.get("low", 0.35)):
        return RiskBand.LOW

    return RiskBand.MINIMAL


class ThresholdEngine:
    """
    Bounded deterministic synthetic threshold engine.

    This engine selects operational thresholds for synthetic investigative
    prioritization signals. It does not authorize actions, does not deploy
    models, does not persist durable artifacts, and must not trigger automatic
    adverse customer action.
    """

    def __init__(
        self,
        options: ThresholdOptions | None = None,
        registry: ThresholdRegistry | None = None,
    ) -> None:
        self.options = options or ThresholdOptions.from_settings()
        self.registry = registry or get_threshold_registry(self.options.max_profiles)
        self._lock = threading.RLock()

    def _effective_options(self, request: ThresholdRequest) -> ThresholdOptions:
        opts = self.options

        updates: dict[str, Any] = {}

        if request.score_kind is not None:
            updates["score_kind"] = request.score_kind

        if request.positive_label_codes is not None:
            updates["positive_label_codes"] = request.positive_label_codes

        if request.negative_label_codes is not None:
            updates["negative_label_codes"] = request.negative_label_codes

        if request.ignore_label_codes is not None:
            updates["ignore_label_codes"] = request.ignore_label_codes

        if request.quantiles is not None:
            updates["default_quantiles"] = request.quantiles

        if request.cost_false_positive is not None:
            updates["cost_false_positive"] = request.cost_false_positive

        if request.cost_false_negative is not None:
            updates["cost_false_negative"] = request.cost_false_negative

        if request.max_cost is not None:
            updates["max_cost"] = request.max_cost

        if request.ewma_decay is not None:
            updates["ewma_decay"] = request.ewma_decay

        if not updates:
            return opts

        return replace(opts, **updates)

    def select(self, request: Any) -> ThresholdProfile:
        """
        Select one bounded synthetic threshold profile.
        """
        base_opts = self.options
        issues: list[ThresholdIssue] = []
        generated_at = _now_utc()
        start_time = time.monotonic()

        req = _coerce_threshold_request(request)
        opts = self._effective_options(req)
        policy = _normalize_enum_option(
            ThresholdPolicy,
            req.policy or opts.default_policy,
            ThresholdPolicy.HYBRID,
        )
        score_kind = _normalize_enum_option(
            ScoreKind,
            req.score_kind or opts.score_kind,
            ScoreKind.GENERIC,
        )
        source = ThresholdSource.REQUEST if req.threshold is not None else ThresholdSource.SYNTHETIC_PROFILE
        request_id = req.request_id or _derive_threshold_request_id(req, opts, policy, score_kind, None)

        def make_profile(
            ok: bool,
            status: ThresholdStatus,
            threshold: float = opts.default_threshold,
            metrics: Optional[ThresholdMetrics] = None,
            candidates: Sequence[ThresholdCandidate] = (),
            stability: Optional[Mapping[str, Any]] = None,
            drift: Optional[Mapping[str, Any]] = None,
            score_profile: Optional[Mapping[str, Any]] = None,
            label_summary: Optional[Mapping[str, Any]] = None,
            counts: Optional[Mapping[str, int]] = None,
        ) -> ThresholdProfile:
            resolved_counts: dict[str, int] = {
                "submitted": 0,
                "processed": 0,
                "scored": 0,
                "labeled": 0,
                "positive": 0,
                "negative": 0,
                "unlabeled": 0,
                "candidates_generated": len(candidates),
                "candidates_evaluated": len(candidates),
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update(
                    {
                        str(key): max(0, _as_int(value, 0))
                        for key, value in counts.items()
                    }
                )

            resolved_counts["issues"] = len(issues)
            resolved_counts["candidates_generated"] = len(candidates)
            resolved_counts["candidates_evaluated"] = len(candidates)

            metadata = {
                "threshold_version": THRESHOLD_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "policy": _enum_value(policy, ThresholdPolicy.HYBRID.value),
                "source": _enum_value(source, ThresholdSource.SYNTHETIC_PROFILE.value),
                "score_kind": _enum_value(score_kind, ScoreKind.GENERIC.value),
                "selection_split": opts.selection_split,
                "threshold": _round6(threshold),
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "registry": self.registry.safe_summary(limit=opts.max_summary_items),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_values_retained": False,
                "subject_label_pairs_retained": False,
                "subject_score_pairs_retained": False,
                "narratives_retained": False,
                "identifiers_retained": False,
                "secrets_retained": False,
                "caveats": list(_THRESHOLD_CAVEATS),
                "safety_flags": dict(_THRESHOLD_SAFETY_FLAGS),
            }

            profile = ThresholdProfile(
                ok=ok,
                status=status,
                policy=policy,
                source=source,
                score_kind=score_kind,
                threshold=threshold,
                metrics=metrics or ThresholdMetrics(threshold=threshold),
                candidates=tuple(candidates[: opts.max_summary_items]),
                stability=stability or {"available": False, "reason": "not_computed"},
                drift=drift or {"available": False, "reason": "not_computed"},
                score_profile=score_profile or {"available": False},
                label_summary=label_summary or {"available": False},
                counts=resolved_counts,
                issues=tuple(issues[: opts.max_issues]),
                metadata=metadata,
                request_id=request_id,
                generated_at=generated_at,
                duration_ms=_elapsed_ms(start_time),
                fingerprint="",
            )

            if opts.register_profiles and profile.ok:
                try:
                    self.registry.register(profile)
                except Exception as exc:
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="threshold_profile_registration_failed",
                        message="Threshold profile registration failed.",
                        details={"exception_type": type(exc).__name__},
                    )

            return profile

        if not base_opts.enabled:
            _append_issue(
                issues,
                base_opts.max_issues,
                severity=IssueSeverity.INFO,
                code="threshold_engine_disabled",
                message="Threshold engine is disabled.",
            )
            return make_profile(False, ThresholdStatus.BLOCKED)

        if base_opts.synthetic_required and base_opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                base_opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Threshold engine requires synthetic dataset mode.",
                details={"dataset_mode": base_opts.dataset_mode},
            )
            return make_profile(False, ThresholdStatus.BLOCKED)

        if base_opts.production_like and not base_opts.allow_in_production:
            _append_issue(
                issues,
                base_opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Threshold engine is blocked in production-like environments.",
            )
            return make_profile(False, ThresholdStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags, req.reference_profile):
            _append_issue(
                issues,
                base_opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_threshold_action_metadata",
                message="Threshold request metadata contains prohibited adverse-action language.",
            )
            return make_profile(False, ThresholdStatus.BLOCKED)

        raw_items = _iter_observations(req.observations)
        submitted = len(raw_items)

        if submitted > opts.max_observations:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="threshold_input_truncated",
                message="Threshold input exceeded configured observation limit and was truncated.",
                details={
                    "submitted": submitted,
                    "max_observations": opts.max_observations,
                },
            )
            raw_items = raw_items[: opts.max_observations]

        observations, counts = _sanitize_observations(
            raw_items,
            req.labels,
            opts,
            req,
            issues,
            start_time,
        )

        if not observations:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_valid_threshold_observations",
                message="No valid observations remained after sanitization.",
            )
            return make_profile(
                False,
                ThresholdStatus.FAILED,
                counts=counts,
            )

        filtered = _filter_observations_by_split(observations, opts.selection_split, opts, issues)
        counts["filtered_by_split"] = len(filtered)
        counts["used_for_calibration"] = len(filtered)

        if not filtered:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_split_filtered_observations",
                message="No observations remained after split filtering.",
            )
            return make_profile(
                False,
                ThresholdStatus.FAILED,
                counts=counts,
            )

        selected, candidates = _choose_threshold(filtered, opts, req, issues, start_time)

        if selected is None:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="threshold_selection_failed",
                message="Threshold selection failed.",
            )
            return make_profile(
                False,
                ThresholdStatus.FAILED,
                counts=counts,
                candidates=candidates,
            )

        request_id = _derive_threshold_request_id(req, opts, policy, score_kind, selected.threshold)
        score_prof = _score_profile(filtered, opts)
        label_sum = _label_summary(filtered, opts)
        stability = _estimate_stability(filtered, opts, req, issues, start_time)
        drift = (
            _compute_drift(score_prof, req.reference_profile, opts)
            if opts.include_drift
            else {"available": False, "reason": "disabled_by_policy"}
        )

        status = ThresholdStatus.PASSED

        if _has_error(issues):
            status = ThresholdStatus.FAILED
        elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
            status = ThresholdStatus.DEGRADED
        elif policy in _LABEL_DEPENDENT_POLICIES and not selected.metrics.supervised_available:
            status = ThresholdStatus.DEGRADED

        ranked_candidates = candidates

        if opts.include_candidates:
            ranked_candidates = sorted(
                candidates,
                key=lambda candidate: (
                    -float(candidate.composite_score or 0.0),
                    -float(candidate.metrics.recall),
                    float(candidate.threshold),
                ),
            )[: opts.max_summary_items]
        else:
            ranked_candidates = (selected,)

        counts.update(
            {
                "candidates_generated": len(candidates),
                "candidates_evaluated": len(candidates),
                "stability_available": 1 if stability.get("available") else 0,
                "drift_available": 1 if drift.get("available") else 0,
            }
        )

        return make_profile(
            ok=status in {ThresholdStatus.PASSED, ThresholdStatus.DEGRADED},
            status=status,
            threshold=selected.threshold,
            metrics=selected.metrics,
            candidates=ranked_candidates,
            stability=stability,
            drift=drift,
            score_profile=score_prof,
            label_summary=label_sum,
            counts=counts,
        )

    def classify_score(
        self,
        score: Any,
        profile: ThresholdProfile | None = None,
    ) -> ThresholdDecision:
        """
        Classify one score against a threshold profile.

        This is operational prioritization only. It does not authorize adverse
        action.
        """
        opts = self.options
        active_profile = profile or self.registry.latest_profile()
        threshold = (
            float(active_profile.threshold)
            if active_profile is not None
            else float(opts.default_threshold)
        )
        numeric = _coerce_optional_float(score, allow_bool=True)

        if numeric is None:
            return ThresholdDecision(
                score=None,
                threshold=threshold,
                band=RiskBand.UNAVAILABLE,
                flagged=False,
                review_recommended=False,
                decision_source="threshold_profile" if active_profile is not None else "default_threshold",
                metadata={
                    "reason": "score_unavailable",
                    "profile_fingerprint": active_profile.fingerprint if active_profile is not None else None,
                },
            )

        clipped = _round6(_clip_float(numeric, opts.score_min, opts.score_max, opts.score_min))
        band = _risk_band_for_score(clipped, opts)
        flagged = clipped >= float(threshold)
        review_recommended = bool(
            flagged
            or band in {RiskBand.HIGH, RiskBand.CRITICAL}
        )

        return ThresholdDecision(
            score=clipped,
            threshold=threshold,
            band=band,
            flagged=flagged,
            review_recommended=review_recommended,
            decision_source="threshold_profile" if active_profile is not None else "default_threshold",
            metadata={
                "profile_fingerprint": active_profile.fingerprint if active_profile is not None else None,
                "policy": _enum_value(active_profile.policy, ThresholdPolicy.HYBRID.value)
                if active_profile is not None
                else _enum_value(opts.default_policy, ThresholdPolicy.HYBRID.value),
                "caveats": list(_THRESHOLD_CAVEATS),
                "safety_flags": dict(_THRESHOLD_SAFETY_FLAGS),
            },
        )

    def classify_observations(
        self,
        observations: Any,
        profile: ThresholdProfile | None = None,
    ) -> tuple[ThresholdRecordResult, ...]:
        """
        Classify bounded observations against a threshold profile.

        Labels are not retained in output. Raw subject identifiers are not
        retained.
        """
        opts = self.options
        active_profile = profile or self.registry.latest_profile()
        threshold = (
            float(active_profile.threshold)
            if active_profile is not None
            else float(opts.default_threshold)
        )
        raw_items = _iter_observations(observations)

        if len(raw_items) > opts.max_observations:
            raw_items = raw_items[: opts.max_observations]

        issues: list[ThresholdIssue] = []
        sanitized, _counts = _sanitize_observations(
            raw_items,
            None,
            opts,
            ThresholdRequest(),
            issues,
            time.monotonic(),
        )
        out: list[ThresholdRecordResult] = []

        for obs in sanitized:
            band = _risk_band_for_score(obs.score, opts)
            flagged = float(obs.score) >= float(threshold)
            review_recommended = bool(
                flagged
                or band in {RiskBand.HIGH, RiskBand.CRITICAL}
            )
            out.append(
                ThresholdRecordResult(
                    subject_ref_hash=obs.subject_ref_hash,
                    index=obs.index,
                    score=obs.score,
                    threshold=threshold,
                    band=band,
                    flagged=flagged,
                    review_recommended=review_recommended,
                    metadata={
                        "profile_fingerprint": active_profile.fingerprint if active_profile is not None else None,
                        "policy": _enum_value(active_profile.policy, ThresholdPolicy.HYBRID.value)
                        if active_profile is not None
                        else _enum_value(opts.default_policy, ThresholdPolicy.HYBRID.value),
                        "split": obs.split,
                        "caveats": list(_THRESHOLD_CAVEATS),
                        "safety_flags": dict(_THRESHOLD_SAFETY_FLAGS),
                    },
                )
            )

        return tuple(out)

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe engine summary.
        """
        return {
            "options": self.options.safe_summary(),
            "registry": self.registry.safe_summary(limit=self.options.max_summary_items),
            "caveats": list(_THRESHOLD_CAVEATS),
            "safety_flags": dict(_THRESHOLD_SAFETY_FLAGS),
        }


def _derive_threshold_request_id(
    request: ThresholdRequest,
    options: ThresholdOptions,
    policy: ThresholdPolicy,
    score_kind: ScoreKind,
    threshold: Optional[float],
) -> str:
    if request.request_id:
        return request.request_id

    payload = {
        "version": THRESHOLD_VERSION,
        "policy": _enum_value(policy, ThresholdPolicy.HYBRID.value),
        "score_kind": _enum_value(score_kind, ScoreKind.GENERIC.value),
        "threshold": _round6(threshold) if threshold is not None else None,
        "options": options.safe_summary(),
        "metadata": _safe_detail_value(request.metadata),
        "tags": list(request.tags),
        "idempotency_key": request.idempotency_key,
    }

    return _sha256_hex(_canonical_json(payload))[:32]


_default_engine: Optional[ThresholdEngine] = None
_default_engine_lock = threading.Lock()


def get_threshold_options(settings: Any | None = None) -> ThresholdOptions:
    """
    Return threshold options from settings.
    """
    return ThresholdOptions.from_settings(settings)


def get_threshold_engine(
    options: ThresholdOptions | None = None,
    *,
    rebuild: bool = False,
) -> ThresholdEngine:
    """
    Return a process-wide threshold engine.

    If options are supplied or rebuild is True, a new engine is created and
    becomes the default.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = ThresholdEngine(
                options=options or ThresholdOptions.from_settings()
            )

        return _default_engine


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def select_threshold(
    request: Any,
    options: ThresholdOptions | None = None,
    *,
    engine: ThresholdEngine | None = None,
) -> ThresholdProfile:
    """
    Select one bounded synthetic threshold profile.
    """
    active_engine = engine or get_threshold_engine(options)
    return active_engine.select(request)


def calibrate_threshold(
    request: Any,
    options: ThresholdOptions | None = None,
    *,
    engine: ThresholdEngine | None = None,
) -> ThresholdProfile:
    """
    Alias for select_threshold.
    """
    return select_threshold(request, options=options, engine=engine)


def classify_score(
    score: Any,
    profile: ThresholdProfile | None = None,
    options: ThresholdOptions | None = None,
    *,
    engine: ThresholdEngine | None = None,
) -> ThresholdDecision:
    """
    Classify one score against a threshold profile.
    """
    active_engine = engine or get_threshold_engine(options)
    return active_engine.classify_score(score, profile=profile)


def classify_observations(
    observations: Any,
    profile: ThresholdProfile | None = None,
    options: ThresholdOptions | None = None,
    *,
    engine: ThresholdEngine | None = None,
) -> tuple[ThresholdRecordResult, ...]:
    """
    Classify bounded observations against a threshold profile.
    """
    active_engine = engine or get_threshold_engine(options)
    return active_engine.classify_observations(observations, profile=profile)


def get_threshold_profile(profile_id: Any, *, registry: ThresholdRegistry | None = None) -> Optional[ThresholdProfile]:
    """
    Return one registered threshold profile.
    """
    active_registry = registry or get_threshold_registry()
    return active_registry.get_profile(profile_id)


def get_latest_threshold_profile(*, registry: ThresholdRegistry | None = None) -> Optional[ThresholdProfile]:
    """
    Return the latest registered threshold profile.
    """
    active_registry = registry or get_threshold_registry()
    return active_registry.latest_profile()


def list_threshold_profiles(
    *,
    limit: int = 50,
    registry: ThresholdRegistry | None = None,
) -> tuple[ThresholdProfile, ...]:
    """
    Return registered threshold profiles.
    """
    active_registry = registry or get_threshold_registry()
    return active_registry.list_profiles(limit=limit)


def summarize_threshold_profiles(
    *,
    limit: int = 50,
    registry: ThresholdRegistry | None = None,
) -> list[dict[str, Any]]:
    """
    Return safe registered threshold profile summaries.
    """
    active_registry = registry or get_threshold_registry()
    return active_registry.summarize(limit=limit)


def get_thresholds_health(
    *,
    engine: ThresholdEngine | None = None,
) -> dict[str, Any]:
    """
    Return safe threshold-engine health.
    """
    active_engine = engine or get_threshold_engine()
    opts = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=opts.max_summary_items)
    issues: list[ThresholdIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="threshold_engine_disabled",
            message="Threshold engine is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Threshold engine requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Threshold engine is blocked in production-like environments.",
        )
    elif int(registry_summary.get("registered_profiles", 0)) <= 0:
        status = "DEGRADED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="no_registered_threshold_profiles",
            message="No threshold profiles are registered in the process-local registry.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "default_policy": _enum_value(opts.default_policy, ThresholdPolicy.HYBRID.value),
        "score_kind": _enum_value(opts.score_kind, ScoreKind.GENERIC.value),
        "registry": registry_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(_THRESHOLD_CAVEATS),
        "safety_flags": dict(_THRESHOLD_SAFETY_FLAGS),
    }


def get_thresholds_metadata(*, limit: int = _DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
    """
    Return safe, serializable threshold metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, raw score values, subject-label pairs,
    or real customer data.
    """
    options = ThresholdOptions.from_settings()
    registry = get_threshold_registry(options.max_profiles)

    return {
        "package": "muleguard.backend.rules.thresholds",
        "version": THRESHOLD_VERSION,
        "policies": [policy.value for policy in ThresholdPolicy],
        "statuses": [status.value for status in ThresholdStatus],
        "sources": [source.value for source in ThresholdSource],
        "score_kinds": [kind.value for kind in ScoreKind],
        "risk_bands": [band.value for band in RiskBand],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "registry": registry.safe_summary(limit=limit),
        "hard_limits": {
            "max_observations": _HARD_MAX_OBSERVATIONS,
            "max_fields": _HARD_MAX_FIELDS,
            "max_candidates": _HARD_MAX_CANDIDATES,
            "max_stability_candidates": _HARD_MAX_STABILITY_CANDIDATES,
            "stability_repeats": _HARD_MAX_STABILITY_REPEATS,
            "max_stability_sample": _HARD_MAX_STABILITY_SAMPLE,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_profiles": _HARD_MAX_PROFILES,
            "max_time_ms": _HARD_MAX_TIME_MS,
        },
        "forbidden_threshold_field_count": len(_FORBIDDEN_THRESHOLD_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(_PROHIBITED_ACTION_TOKENS),
        "caveats": list(_THRESHOLD_CAVEATS),
        "safety_flags": dict(_THRESHOLD_SAFETY_FLAGS),
    }


__all__ = [
    "IssueSeverity",
    "RiskBand",
    "ScoreKind",
    "ThresholdCandidate",
    "ThresholdDecision",
    "ThresholdEngine",
    "ThresholdIssue",
    "ThresholdMetrics",
    "ThresholdOptions",
    "ThresholdPolicy",
    "ThresholdProfile",
    "ThresholdRecordResult",
    "ThresholdRegistry",
    "ThresholdRequest",
    "ThresholdSource",
    "ThresholdStatus",
    "calibrate_threshold",
    "classify_observations",
    "classify_score",
    "get_latest_threshold_profile",
    "get_threshold_engine",
    "get_threshold_options",
    "get_threshold_profile",
    "get_threshold_registry",
    "get_thresholds_health",
    "get_thresholds_metadata",
    "list_threshold_profiles",
    "select_threshold",
    "summarize_threshold_profiles",
]