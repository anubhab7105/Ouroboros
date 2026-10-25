"""
MULEGUARD backend rules engine.

This module provides the canonical bounded rule-engine implementation for the
synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- define, register, validate, activate, retire, and evaluate safe investigative
  rules against bounded synthetic records;
- support nested boolean condition trees with bounded depth, breadth, and
  literal counts;
- enforce strict product-safety constraints on rule actions, including absolute
  prohibition of automatic adverse customer action;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values, raw identifiers, raw narratives, subject-label
  pairs, secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited rule condition fields;
- provide deterministic, bounded, API-safe rule evaluation results with matched
  rules, operational effects, safe reasons, score components, issues,
  fingerprints, and metadata;
- maintain a bounded process-local rule registry for local prototype workflows,
  tests, developer tooling, and offline evaluation harnesses;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module orchestrates investigative rules only. It does not train models,
deploy models, persist durable artifacts, call external systems, authenticate
users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for rule authoring, registration,
  evaluation, or debugging.
- Rule outputs are investigative prioritization artefacts only. They are not
  proof of wrongdoing.
- Rule scores are not probabilities of guilt.
- Rule reasons and contributions are operational attributions only. They are
  not causal proof.
- Labels must never be used as rule features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as rule condition fields.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden inputs. Subject linkage is pseudonymous and
  salted.
- Rule actions must never trigger automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, denying, terminating,
  suspending, referring to law enforcement, or making credit, employment,
  housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable capabilities are reported honestly rather than
  invented.
- The bundled rule registry is process-local, non-durable, and bounded for local
  prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external rule engines.
- This module does not deploy, promote to production serving, retire from
  production serving, upload, replace, or execute external rules.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable decisioning platform.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, rule
evaluations, explanations, validation reports, and case dispositions are
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


logger = logging.getLogger("muleguard.backend.rules.engine")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

RULE_ENGINE_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.rules.engine.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_RECORDS: Final[int] = 10_000
_HARD_MAX_RECORDS: Final[int] = 100_000

_DEFAULT_MAX_FEATURES: Final[int] = 512
_HARD_MAX_FEATURES: Final[int] = 4_096

_DEFAULT_MAX_RULES: Final[int] = 1_000
_HARD_MAX_RULES: Final[int] = 10_000

_DEFAULT_MAX_RULES_EVALUATED: Final[int] = 256
_HARD_MAX_RULES_EVALUATED: Final[int] = 10_000

_DEFAULT_MAX_CONDITIONS: Final[int] = 32
_HARD_MAX_CONDITIONS: Final[int] = 1_000

_DEFAULT_MAX_CONDITION_DEPTH: Final[int] = 8
_HARD_MAX_CONDITION_DEPTH: Final[int] = 32

_DEFAULT_MAX_CONDITION_CHILDREN: Final[int] = 16
_HARD_MAX_CONDITION_CHILDREN: Final[int] = 256

_DEFAULT_MAX_EXPRESSION_NODES: Final[int] = 256
_HARD_MAX_EXPRESSION_NODES: Final[int] = 10_000

_DEFAULT_MAX_LITERALS: Final[int] = 64
_HARD_MAX_LITERALS: Final[int] = 1_000

_DEFAULT_MAX_CONDITION_VALUES: Final[int] = 100
_HARD_MAX_CONDITION_VALUES: Final[int] = 1_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_REASONS: Final[int] = 20
_HARD_MAX_REASONS: Final[int] = 500

_DEFAULT_MAX_TIME_MS: Final[int] = 30_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_DEFAULT_THRESHOLD: Final[float] = 0.60

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256
_MAX_REASON_TEXT_LENGTH: Final[int] = 300

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

_FORBIDDEN_RULE_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_RULE_TOKENS: Final[tuple[str, ...]] = (
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

_ALLOWED_EFFECT_TOKENS: Final[set[str]] = {
    "prioritize",
    "flag_for_review",
    "escalate_to_human",
    "annotate",
    "suppress",
    "none",
}

_GROUP_LOGICS: Final[frozenset[str]] = frozenset({"all", "any", "none", "not"})

_OPERATOR_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "eq": "eq",
        "equal": "eq",
        "equals": "eq",
        "==": "eq",
        "ne": "ne",
        "not_equal": "ne",
        "!=": "ne",
        "gt": "gt",
        "greater_than": "gt",
        ">": "gt",
        "gte": "gte",
        "greater_or_equal": "gte",
        "greater_than_or_equal": "gte",
        ">=": "gte",
        "lt": "lt",
        "less_than": "lt",
        "<": "lt",
        "lte": "lte",
        "less_or_equal": "lte",
        "less_than_or_equal": "lte",
        "<=": "lte",
        "between": "between",
        "in": "in",
        "any_of": "in",
        "not_in": "not_in",
        "not_any_of": "not_in",
        "contains": "contains",
        "not_contains": "not_contains",
        "startswith": "starts_with",
        "starts_with": "starts_with",
        "begins_with": "starts_with",
        "endswith": "ends_with",
        "ends_with": "ends_with",
        "not_startswith": "not_starts_with",
        "not_starts_with": "not_starts_with",
        "not_endswith": "not_ends_with",
        "not_ends_with": "not_ends_with",
        "is_null": "is_null",
        "null": "is_null",
        "missing": "is_null",
        "not_null": "not_null",
        "not_missing": "not_null",
        "present": "not_null",
        "true": "true",
        "is_true": "true",
        "false": "false",
        "is_false": "false",
        "zero": "zero",
        "nonzero": "nonzero",
        "not_zero": "nonzero",
        "finite": "finite",
    }
)

_SUPPORTED_OPERATORS: Final[set[str]] = {
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "between",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "starts_with",
    "not_starts_with",
    "ends_with",
    "not_ends_with",
    "is_null",
    "not_null",
    "true",
    "false",
    "zero",
    "nonzero",
    "finite",
}

_CONDITION_REQUIRES_VALUE: Final[frozenset[str]] = frozenset(
    {
        "eq",
        "ne",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
        "not_in",
        "contains",
        "not_contains",
        "starts_with",
        "not_starts_with",
        "ends_with",
        "not_ends_with",
    }
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

_RULE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic rule evaluation only. Do not use with real customer data.",
    "Rule outputs are investigative prioritization artefacts only and are not proof of wrongdoing.",
    "Rule scores are not probabilities of guilt.",
    "Rule reasons and contributions are operational attributions only and are not causal proof.",
    "Rule evaluation must not trigger automatic adverse customer action.",
    "Labels must never be used as rule features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected as rule condition fields.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Unavailable rules or conditions are reported honestly as unavailable rather than invented.",
    "The bundled rule registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_RULE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_rule_evaluation": True,
        "bounded_rule_evaluation_required": True,
        "scores_are_investigative_priority_only": True,
        "reasons_are_operational_attributions_only": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class RuleSeverity(str, Enum):
    """
    Rule severity.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(str, Enum):
    """
    Rule lifecycle status.
    """

    DRAFT = "draft"
    ACTIVE = "active"
    RETIRED = "retired"
    BLOCKED = "blocked"


class RuleKind(str, Enum):
    """
    Rule kind.
    """

    DETECTION = "detection"
    PRIORITIZATION = "prioritization"
    ANNOTATION = "annotation"
    GUARDRAIL = "guardrail"


class ActionEffect(str, Enum):
    """
    Allowed investigative rule effect.

    Adverse actions are prohibited.
    """

    PRIORITIZE = "prioritize"
    FLAG_FOR_REVIEW = "flag_for_review"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    ANNOTATE = "annotate"
    SUPPRESS = "suppress"
    NONE = "none"


class EvaluationMode(str, Enum):
    """
    Rule evaluation mode.

    All modes are investigative only. None permit automatic adverse action.
    """

    DRY_RUN = "dry_run"
    SHADOW = "shadow"
    REVIEW = "review"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


_SEVERITY_WEIGHTS: Final[Mapping[str, float]] = MappingProxyType(
    {
        RuleSeverity.INFO.value: 0.05,
        RuleSeverity.LOW.value: 0.15,
        RuleSeverity.MEDIUM.value: 0.35,
        RuleSeverity.HIGH.value: 0.60,
        RuleSeverity.CRITICAL.value: 0.85,
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

    if canonical in _FORBIDDEN_RULE_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_RULE_TOKENS)


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


def _normalize_operator(value: Any) -> str:
    token = _normalize_token(value)

    if not token:
        return "unsupported"

    if token in _OPERATOR_ALIASES:
        return str(_OPERATOR_ALIASES[token])

    if token in _SUPPORTED_OPERATORS:
        return token

    return "unsupported"


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


def _subject_hash(value: Any, options: "RuleEngineOptions") -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.rules.engine.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _fingerprint_payload(payload: Any) -> str:
    try:
        return _sha256_hex(_canonical_json(payload))
    except Exception:
        return _sha256_hex(str(_safe_detail_value(payload)))


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


def _contains_prohibited_action(*values: Any) -> bool:
    text = " ".join(
        _normalize_token(value)
        for value in values
        if value is not None
    ).lower()

    if not text:
        return False

    return any(token in text for token in _PROHIBITED_ACTION_TOKENS)


def _safe_reason_text(value: Any) -> str:
    text = _clean_text(value, _MAX_REASON_TEXT_LENGTH)

    if not text:
        return ""

    if _looks_like_sensitive_literal(text):
        return "sensitive detail omitted"

    return text


def _sanitize_literal(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "[truncated-depth]"

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return int(value)

    if isinstance(value, float):
        return _round6(value) if math.isfinite(value) else None

    if isinstance(value, Decimal):
        if not value.is_finite():
            return None

        try:
            return _round6(float(value))
        except (OverflowError, ValueError):
            return None

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, Enum):
        return _sanitize_literal(value.value, depth + 1)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:100]:
            key = _clean_text(raw_key, 128)

            if not key or _is_sensitive_detail_key(key):
                continue

            out[key] = _sanitize_literal(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_sanitize_literal(item, depth + 1) for item in list(value)[:100]]

    text = _clean_text(value, 300)

    if not text:
        return None

    if _looks_like_sensitive_literal(text):
        return None

    if _is_safe_hash(text):
        return text.lower()

    numeric = _coerce_optional_float(text, allow_bool=False)

    if numeric is not None:
        return _round6(numeric)

    parsed_bool = _coerce_bool(text)

    if parsed_bool is not None:
        return parsed_bool

    token = _normalize_token(text)

    if token:
        return token

    return text


def _literal_summary(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    numeric = _coerce_optional_float(value, allow_bool=False)

    if numeric is not None:
        return _round6(numeric)

    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        return {
            "count": len(items),
            "sample": [_literal_summary(item) for item in items[:5]],
            "truncated": len(items) > 5,
        }

    text = _clean_text(value, 128)

    if not text:
        return None

    if _is_safe_hash(text):
        return {"kind": "hash", "fingerprint": text[:16]}

    if _looks_like_sensitive_literal(text):
        return {"kind": "redacted"}

    token = _normalize_token(text)

    return token or text


def _normalize_tags(value: Any, limit: int = 50) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        tag = _clean_text(item, 100)

        if tag:
            out.append(tag)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleIssue:
    """
    Safe rule issue.

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


def _append_issue(
    issues: list[RuleIssue],
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

        issues[-1] = RuleIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        RuleIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _has_error(issues: Sequence[RuleIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


# -----------------------------------------------------------------------------
# Condition model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleCondition:
    """
    One bounded rule condition node.

    A node may be either:

    - a leaf condition over one sanitized synthetic feature field; or
    - a boolean group over child conditions using `all`, `any`, `none`, or
      `not`.

    Conditions operate on sanitized synthetic feature fields only. Prohibited,
    leakage-prone, privacy-sensitive, raw narrative, and raw identifier fields
    are rejected during validation and evaluation.
    """

    field: Optional[str] = None
    operator: str = "eq"
    value: Any = None
    values: tuple[Any, ...] = ()
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    children: tuple["RuleCondition", ...] = ()
    logic: str = "all"
    negate: bool = False
    description: str = ""
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        metadata = _as_mapping(self.metadata)

        raw_children = _as_sequence(self.children)
        children: list[RuleCondition] = []

        for item in raw_children:
            if isinstance(item, RuleCondition):
                children.append(item)
            elif isinstance(item, Mapping):
                try:
                    children.append(RuleCondition(**item))
                except Exception:
                    continue
            else:
                token = _canonical_field_name(item)

                if token:
                    children.append(
                        RuleCondition(
                            field=token,
                            operator="not_null",
                        )
                    )

        field_token = _canonical_field_name(self.field)
        raw_operator = _normalize_token(self.operator)
        raw_logic = _normalize_token(self.logic)

        is_group = bool(children) or (
            not field_token
            and (
                raw_operator in _GROUP_LOGICS
                or raw_operator in {"group", "logic"}
                or raw_logic in _GROUP_LOGICS
            )
        )

        if is_group:
            if raw_logic in _GROUP_LOGICS:
                logic = raw_logic
            elif raw_operator in _GROUP_LOGICS:
                logic = raw_operator
            else:
                logic = "all"

            if logic == "not":
                children = children[:1]

            children = children[:_HARD_MAX_CONDITION_CHILDREN]

            object.__setattr__(self, "field", None)
            object.__setattr__(self, "operator", "group")
            object.__setattr__(self, "logic", logic)
            object.__setattr__(self, "children", tuple(children))
            object.__setattr__(self, "value", None)
            object.__setattr__(self, "values", ())
            object.__setattr__(self, "min_value", None)
            object.__setattr__(self, "max_value", None)

            metadata["node_type"] = "group"
            metadata["child_count"] = len(children)
        else:
            object.__setattr__(self, "field", field_token)
            object.__setattr__(self, "operator", _normalize_operator(self.operator))
            object.__setattr__(self, "logic", "all")
            object.__setattr__(self, "children", ())

            original_value = self.value
            sanitized_value = _sanitize_literal(self.value)

            if (
                sanitized_value is None
                and original_value is not None
                and _looks_like_sensitive_literal(original_value)
            ):
                metadata["value_redacted"] = True

            object.__setattr__(self, "value", sanitized_value)

            original_values = _as_sequence(self.values)
            sanitized_values: list[Any] = []
            redacted_values = 0

            for item in original_values[:_HARD_MAX_CONDITION_VALUES]:
                sanitized_item = _sanitize_literal(item)

                if (
                    sanitized_item is None
                    and item is not None
                    and _looks_like_sensitive_literal(item)
                ):
                    redacted_values += 1
                    continue

                if sanitized_item is not None:
                    sanitized_values.append(sanitized_item)

            object.__setattr__(
                self,
                "values",
                tuple(dict.fromkeys(sanitized_values)),
            )

            if redacted_values:
                metadata["values_redacted_count"] = int(redacted_values)

            if self.min_value is not None:
                object.__setattr__(
                    self,
                    "min_value",
                    _round6(_clamp_float(self.min_value, -1e12, 1e12, 0.0)),
                )

            if self.max_value is not None:
                object.__setattr__(
                    self,
                    "max_value",
                    _round6(_clamp_float(self.max_value, -1e12, 1e12, 0.0)),
                )

            metadata["node_type"] = "leaf"

        object.__setattr__(self, "description", _clean_text(self.description, 300))
        object.__setattr__(self, "negate", _as_bool(self.negate, False))
        object.__setattr__(self, "metadata", MappingProxyType(metadata))


def _coerce_condition(value: Any) -> Optional[RuleCondition]:
    if isinstance(value, RuleCondition):
        return value

    if isinstance(value, Mapping):
        try:
            return RuleCondition(**value)
        except Exception:
            return None

    token = _canonical_field_name(value)

    if token:
        return RuleCondition(field=token, operator="not_null")

    return None


def _condition_is_group(condition: Optional[RuleCondition]) -> bool:
    if condition is None:
        return False

    return condition.operator == "group" or bool(condition.children)


def _condition_payload(
    condition: Optional[RuleCondition],
    depth: int = 0,
    max_depth: int = 6,
    max_children: int = 10,
) -> Optional[dict[str, Any]]:
    if condition is None:
        return None

    if depth > max_depth:
        return {"truncated": True}

    if _condition_is_group(condition):
        children = list(condition.children or ())
        return {
            "node_type": "group",
            "logic": condition.logic,
            "negate": bool(condition.negate),
            "child_count": len(children),
            "children": [
                _condition_payload(child, depth + 1, max_depth, max_children)
                for child in children[:max_children]
            ],
            "children_truncated": len(children) > max_children,
            "description": condition.description,
        }

    values = list(condition.values or ())

    return {
        "node_type": "leaf",
        "field": condition.field,
        "operator": condition.operator,
        "negate": bool(condition.negate),
        "value": _literal_summary(condition.value),
        "values_count": len(values),
        "values_sample": [_literal_summary(item) for item in values[:5]],
        "values_truncated": len(values) > 5,
        "min_value": float(condition.min_value) if condition.min_value is not None else None,
        "max_value": float(condition.max_value) if condition.max_value is not None else None,
        "description": condition.description,
        "metadata": _safe_detail_value(condition.metadata),
    }


def _condition_requires_value(operator: str) -> bool:
    return operator in _CONDITION_REQUIRES_VALUE


def _condition_has_value(condition: RuleCondition) -> bool:
    if condition.operator == "between":
        return condition.min_value is not None and condition.max_value is not None

    if condition.operator in {"in", "not_in"}:
        return bool(condition.values)

    return condition.value is not None


# -----------------------------------------------------------------------------
# Action model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleAction:
    """
    One bounded investigative rule action.

    Adverse actions are prohibited. Allowed effects are operational
    prioritization, review flagging, human escalation, annotation, suppression,
    or no-op only.
    """

    effect: Any = ActionEffect.FLAG_FOR_REVIEW
    requested_effect: str = ""
    score_delta: float = 0.0
    reason_code: str = ""
    reason_message: str = ""
    tags: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        raw_effect = _clean_text(getattr(self.effect, "value", self.effect), 128)
        normalized_effect = _normalize_enum_option(
            ActionEffect,
            raw_effect,
            ActionEffect.ANNOTATE,
        )

        metadata = _as_mapping(self.metadata)

        prohibited = _contains_prohibited_action(
            raw_effect,
            self.reason_code,
            self.reason_message,
            metadata,
        )

        if prohibited:
            normalized_effect = ActionEffect.ANNOTATE
            metadata["prohibited_action_detected"] = True
            metadata["requested_effect_redacted"] = _normalize_token(raw_effect) or "unknown"

        reason_code = _clean_text(self.reason_code, 100)

        if _looks_like_sensitive_literal(reason_code):
            reason_code = ""

        object.__setattr__(self, "effect", normalized_effect)
        object.__setattr__(self, "requested_effect", raw_effect)
        object.__setattr__(
            self,
            "score_delta",
            _round6(_clamp_float(self.score_delta, -10.0, 10.0, 0.0)),
        )
        object.__setattr__(self, "reason_code", reason_code)
        object.__setattr__(self, "reason_message", _safe_reason_text(self.reason_message))
        object.__setattr__(self, "tags", _normalize_tags(self.tags))
        object.__setattr__(self, "metadata", MappingProxyType(metadata))


# -----------------------------------------------------------------------------
# Rule definition model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """
    One bounded investigative rule definition.

    Rules are operational prioritization artefacts only. They are not
    adjudications and must not trigger automatic adverse customer action.
    """

    rule_id: str = ""
    name: str = ""
    description: str = ""
    kind: Any = RuleKind.DETECTION
    severity: Any = RuleSeverity.MEDIUM
    status: Any = RuleStatus.DRAFT
    priority: int = 0
    enabled: bool = True
    conditions: tuple[RuleCondition, ...] = ()
    condition: Optional[RuleCondition] = None
    condition_logic: str = "all"
    action: Any = None
    score_delta: float = 0.0
    tags: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    owner: str = ""
    version: str = "v1"
    created_at: datetime = dataclass_field(default_factory=_now_utc)
    updated_at: datetime = dataclass_field(default_factory=_now_utc)

    def __post_init__(self) -> None:
        conditions: list[RuleCondition] = []

        for item in _as_sequence(self.conditions):
            condition = _coerce_condition(item)

            if condition is not None:
                conditions.append(condition)

        conditions = tuple(conditions[:_HARD_MAX_CONDITIONS])

        root = _coerce_condition(self.condition)
        nodes: list[RuleCondition] = []

        if root is not None:
            nodes.append(root)

        if conditions:
            logic = _normalize_token(self.condition_logic)

            if logic not in _GROUP_LOGICS:
                logic = "all"

            nodes.append(
                RuleCondition(
                    operator="group",
                    logic=logic,
                    children=tuple(conditions),
                )
            )

        if len(nodes) == 1:
            root = nodes[0]
        elif len(nodes) > 1:
            root = RuleCondition(
                operator="group",
                logic="all",
                children=tuple(nodes),
            )
        else:
            root = None

        if self.action is None:
            action = RuleAction()
        elif isinstance(self.action, RuleAction):
            action = self.action
        elif isinstance(self.action, Mapping):
            try:
                action = RuleAction(**self.action)
            except Exception:
                action = RuleAction()
        else:
            action = RuleAction(effect=self.action)

        condition_logic = _normalize_token(self.condition_logic)

        if condition_logic not in _GROUP_LOGICS:
            condition_logic = "all"

        object.__setattr__(self, "rule_id", _clean_text(self.rule_id, 128).lower())
        object.__setattr__(self, "name", _clean_text(self.name, 200))
        object.__setattr__(self, "description", _clean_text(self.description, 500))

        object.__setattr__(
            self,
            "kind",
            _normalize_enum_option(RuleKind, self.kind, RuleKind.DETECTION),
        )
        object.__setattr__(
            self,
            "severity",
            _normalize_enum_option(RuleSeverity, self.severity, RuleSeverity.MEDIUM),
        )
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(RuleStatus, self.status, RuleStatus.DRAFT),
        )

        object.__setattr__(self, "priority", _clamp_int(self.priority, -100, 100, 0))
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "conditions", conditions)
        object.__setattr__(self, "condition", root)
        object.__setattr__(self, "condition_logic", condition_logic)
        object.__setattr__(self, "action", action)
        object.__setattr__(
            self,
            "score_delta",
            _round6(_clamp_float(self.score_delta, -10.0, 10.0, 0.0)),
        )
        object.__setattr__(self, "tags", _normalize_tags(self.tags))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))
        object.__setattr__(self, "owner", _clean_text(self.owner, 128))
        object.__setattr__(self, "version", _clean_text(self.version, 64) or "v1")
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())
        object.__setattr__(self, "updated_at", _ensure_utc(self.updated_at) or _now_utc())

        if not self.name:
            object.__setattr__(self, "name", self.rule_id or "unnamed_rule")


def _derive_rule_id(definition: RuleDefinition) -> str:
    action = definition.action if isinstance(definition.action, RuleAction) else RuleAction()

    payload = {
        "version": RULE_ENGINE_VERSION,
        "name": definition.name,
        "kind": _enum_value(definition.kind, RuleKind.DETECTION.value),
        "severity": _enum_value(definition.severity, RuleSeverity.MEDIUM.value),
        "condition": _condition_payload(definition.condition),
        "action": {
            "effect": _enum_value(action.effect, ActionEffect.ANNOTATE.value),
            "score_delta": float(action.score_delta),
            "reason_code": action.reason_code,
        },
    }

    return _sha256_hex(_canonical_json(payload))[:32]


# -----------------------------------------------------------------------------
# Evaluation models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """
    One bounded matched rule result.
    """

    rule_id: str
    severity: RuleSeverity | str
    score_contribution: float
    effects: tuple[str, ...] = ()
    reasons: tuple[dict[str, Any], ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", _clean_text(self.rule_id, 128).lower())
        object.__setattr__(
            self,
            "severity",
            _normalize_enum_option(RuleSeverity, self.severity, RuleSeverity.MEDIUM),
        )
        object.__setattr__(
            self,
            "score_contribution",
            _round6(_clip_float(self.score_contribution, 0.0, 1.0, 0.0)),
        )
        object.__setattr__(
            self,
            "effects",
            tuple(
                dict.fromkeys(
                    _clean_text(effect, 100)
                    for effect in (self.effects or ())
                    if _clean_text(effect, 100)
                )
            ),
        )
        object.__setattr__(self, "reasons", tuple(self.reasons or ())[:_HARD_MAX_REASONS])
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": _enum_value(self.severity, RuleSeverity.MEDIUM.value),
            "score_contribution": float(self.score_contribution),
            "effects": list(self.effects),
            "reasons": [_safe_detail_value(reason) for reason in self.reasons],
            "metadata": _safe_detail_value(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RuleRecordResult:
    """
    One bounded per-record rule evaluation result.
    """

    subject_ref_hash: Optional[str] = None
    index: Optional[int] = None
    score: Optional[float] = None
    risk_band: str = "unavailable"
    review_recommended: bool = False
    matched_rules: tuple[RuleMatch, ...] = ()
    effects: tuple[str, ...] = ()
    reasons: tuple[dict[str, Any], ...] = ()
    decision_source: str = "rule_engine"
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

        object.__setattr__(self, "risk_band", _normalize_token(self.risk_band) or "unavailable")
        object.__setattr__(self, "review_recommended", _as_bool(self.review_recommended, False))
        object.__setattr__(self, "matched_rules", tuple(self.matched_rules or ()))
        object.__setattr__(
            self,
            "effects",
            tuple(
                dict.fromkeys(
                    _clean_text(effect, 100)
                    for effect in (self.effects or ())
                    if _clean_text(effect, 100)
                )
            ),
        )
        object.__setattr__(self, "reasons", tuple(self.reasons or ())[:_HARD_MAX_REASONS])
        object.__setattr__(self, "decision_source", _clean_text(self.decision_source, 100) or "rule_engine")
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_ref_hash": self.subject_ref_hash,
            "index": int(self.index) if self.index is not None else None,
            "score": float(self.score) if self.score is not None else None,
            "risk_band": self.risk_band,
            "review_recommended": bool(self.review_recommended),
            "matched_rules": [match.to_dict() for match in self.matched_rules],
            "effects": list(self.effects),
            "reasons": [_safe_detail_value(reason) for reason in self.reasons],
            "decision_source": self.decision_source,
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_RULE_CAVEATS),
            "safety_flags": dict(_RULE_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class RuleEvaluationResult:
    """
    Safe rule evaluation result.

    Public summaries deliberately exclude raw feature values, subject-label
    pairs, raw identifiers, raw narratives, secrets, tokens, passwords, database
    URLs, filesystem paths, and model artifact paths.
    """

    ok: bool = True
    mode: EvaluationMode = EvaluationMode.SHADOW
    records: tuple[RuleRecordResult, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[RuleIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "mode",
            _normalize_enum_option(EvaluationMode, self.mode, EvaluationMode.SHADOW),
        )
        object.__setattr__(self, "records", tuple(self.records or ()))
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
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": RULE_ENGINE_VERSION,
                        "ok": self.ok,
                        "mode": self.mode.value,
                        "counts": self.counts,
                        "record_count": len(self.records),
                        "issue_count": len(self.issues),
                        "metadata": _safe_detail_value(self.metadata),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "mode": self.mode.value,
            "records": [record.to_dict() for record in self.records],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_RULE_CAVEATS),
            "safety_flags": dict(_RULE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleEngineOptions:
    """
    Bounded rule-engine policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    mode: EvaluationMode | str = EvaluationMode.SHADOW
    threshold: float = _DEFAULT_THRESHOLD

    include_drafts: bool = False
    include_retired: bool = False
    include_reasons: bool = True
    include_value_buckets: bool = True
    drop_forbidden_fields: bool = False

    max_records: int = _DEFAULT_MAX_RECORDS
    max_features: int = _DEFAULT_MAX_FEATURES
    max_rules: int = _DEFAULT_MAX_RULES
    max_rules_evaluated: int = _DEFAULT_MAX_RULES_EVALUATED
    max_conditions: int = _DEFAULT_MAX_CONDITIONS
    max_condition_depth: int = _DEFAULT_MAX_CONDITION_DEPTH
    max_condition_children: int = _DEFAULT_MAX_CONDITION_CHILDREN
    max_expression_nodes: int = _DEFAULT_MAX_EXPRESSION_NODES
    max_literals: int = _DEFAULT_MAX_LITERALS
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_reasons: int = _DEFAULT_MAX_REASONS
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

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
            "mode",
            _normalize_enum_option(EvaluationMode, self.mode, EvaluationMode.SHADOW),
        )
        object.__setattr__(
            self,
            "threshold",
            _round6(_clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)),
        )

        object.__setattr__(self, "include_drafts", _as_bool(self.include_drafts, False))
        object.__setattr__(self, "include_retired", _as_bool(self.include_retired, False))
        object.__setattr__(self, "include_reasons", _as_bool(self.include_reasons, True))
        object.__setattr__(self, "include_value_buckets", _as_bool(self.include_value_buckets, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))

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
            "max_rules",
            _clamp_int(self.max_rules, 1, _HARD_MAX_RULES, _DEFAULT_MAX_RULES),
        )
        object.__setattr__(
            self,
            "max_rules_evaluated",
            _clamp_int(
                self.max_rules_evaluated,
                1,
                _HARD_MAX_RULES_EVALUATED,
                _DEFAULT_MAX_RULES_EVALUATED,
            ),
        )
        object.__setattr__(
            self,
            "max_conditions",
            _clamp_int(self.max_conditions, 1, _HARD_MAX_CONDITIONS, _DEFAULT_MAX_CONDITIONS),
        )
        object.__setattr__(
            self,
            "max_condition_depth",
            _clamp_int(
                self.max_condition_depth,
                1,
                _HARD_MAX_CONDITION_DEPTH,
                _DEFAULT_MAX_CONDITION_DEPTH,
            ),
        )
        object.__setattr__(
            self,
            "max_condition_children",
            _clamp_int(
                self.max_condition_children,
                1,
                _HARD_MAX_CONDITION_CHILDREN,
                _DEFAULT_MAX_CONDITION_CHILDREN,
            ),
        )
        object.__setattr__(
            self,
            "max_expression_nodes",
            _clamp_int(
                self.max_expression_nodes,
                1,
                _HARD_MAX_EXPRESSION_NODES,
                _DEFAULT_MAX_EXPRESSION_NODES,
            ),
        )
        object.__setattr__(
            self,
            "max_literals",
            _clamp_int(self.max_literals, 1, _HARD_MAX_LITERALS, _DEFAULT_MAX_LITERALS),
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
            "max_reasons",
            _clamp_int(self.max_reasons, 1, _HARD_MAX_REASONS, _DEFAULT_MAX_REASONS),
        )
        object.__setattr__(
            self,
            "max_time_ms",
            _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS),
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
                    "low": _round6(low),
                    "medium": _round6(medium),
                    "high": _round6(high),
                    "critical": _round6(critical),
                }
            ),
        )

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "RuleEngineOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "RULES_ENGINE_SALT", None)
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
            enabled=_as_bool(_setting(settings, "RULES_ENGINE_ENABLED", True), True)
            and _as_bool(_setting(settings, "RULES_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "RULES_ENGINE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "RULES_ENGINE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "RULES_ENGINE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "RULES_ENGINE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            mode=str(_setting(settings, "RULES_ENGINE_MODE", EvaluationMode.SHADOW.value)),
            threshold=_as_float(_setting(settings, "RULES_ENGINE_THRESHOLD", _DEFAULT_THRESHOLD), _DEFAULT_THRESHOLD),
            include_drafts=_as_bool(_setting(settings, "RULES_ENGINE_INCLUDE_DRAFTS", False), False),
            include_retired=_as_bool(_setting(settings, "RULES_ENGINE_INCLUDE_RETIRED", False), False),
            include_reasons=_as_bool(_setting(settings, "RULES_ENGINE_INCLUDE_REASONS", True), True),
            include_value_buckets=_as_bool(
                _setting(settings, "RULES_ENGINE_INCLUDE_VALUE_BUCKETS", True),
                True,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "RULES_ENGINE_DROP_FORBIDDEN_FIELDS", False),
                False,
            ),
            max_records=_as_int(_setting(settings, "RULES_ENGINE_MAX_RECORDS", _DEFAULT_MAX_RECORDS), _DEFAULT_MAX_RECORDS),
            max_features=_as_int(_setting(settings, "RULES_ENGINE_MAX_FEATURES", _DEFAULT_MAX_FEATURES), _DEFAULT_MAX_FEATURES),
            max_rules=_as_int(_setting(settings, "RULES_ENGINE_MAX_RULES", _DEFAULT_MAX_RULES), _DEFAULT_MAX_RULES),
            max_rules_evaluated=_as_int(
                _setting(settings, "RULES_ENGINE_MAX_RULES_EVALUATED", _DEFAULT_MAX_RULES_EVALUATED),
                _DEFAULT_MAX_RULES_EVALUATED,
            ),
            max_conditions=_as_int(
                _setting(settings, "RULES_ENGINE_MAX_CONDITIONS", _DEFAULT_MAX_CONDITIONS),
                _DEFAULT_MAX_CONDITIONS,
            ),
            max_condition_depth=_as_int(
                _setting(settings, "RULES_ENGINE_MAX_CONDITION_DEPTH", _DEFAULT_MAX_CONDITION_DEPTH),
                _DEFAULT_MAX_CONDITION_DEPTH,
            ),
            max_condition_children=_as_int(
                _setting(settings, "RULES_ENGINE_MAX_CONDITION_CHILDREN", _DEFAULT_MAX_CONDITION_CHILDREN),
                _DEFAULT_MAX_CONDITION_CHILDREN,
            ),
            max_expression_nodes=_as_int(
                _setting(settings, "RULES_ENGINE_MAX_EXPRESSION_NODES", _DEFAULT_MAX_EXPRESSION_NODES),
                _DEFAULT_MAX_EXPRESSION_NODES,
            ),
            max_literals=_as_int(
                _setting(settings, "RULES_ENGINE_MAX_LITERALS", _DEFAULT_MAX_LITERALS),
                _DEFAULT_MAX_LITERALS,
            ),
            max_issues=_as_int(_setting(settings, "RULES_ENGINE_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(
                _setting(settings, "RULES_ENGINE_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_reasons=_as_int(_setting(settings, "RULES_ENGINE_MAX_REASONS", _DEFAULT_MAX_REASONS), _DEFAULT_MAX_REASONS),
            max_time_ms=_as_int(_setting(settings, "RULES_ENGINE_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS), _DEFAULT_MAX_TIME_MS),
            risk_thresholds={
                "low": _as_float(_setting(settings, "RULES_ENGINE_RISK_LOW", 0.35), 0.35),
                "medium": _as_float(_setting(settings, "RULES_ENGINE_RISK_MEDIUM", 0.55), 0.55),
                "high": _as_float(_setting(settings, "RULES_ENGINE_RISK_HIGH", 0.75), 0.75),
                "critical": _as_float(_setting(settings, "RULES_ENGINE_RISK_CRITICAL", 0.90), 0.90),
            },
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
            "mode": self.mode.value if isinstance(self.mode, EvaluationMode) else str(self.mode),
            "threshold": _round6(self.threshold),
            "risk_thresholds": dict(self.risk_thresholds),
            "limits": {
                "max_records": self.max_records,
                "max_features": self.max_features,
                "max_rules": self.max_rules,
                "max_rules_evaluated": self.max_rules_evaluated,
                "max_conditions": self.max_conditions,
                "max_condition_depth": self.max_condition_depth,
                "max_condition_children": self.max_condition_children,
                "max_expression_nodes": self.max_expression_nodes,
                "max_literals": self.max_literals,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_reasons": self.max_reasons,
                "max_time_ms": self.max_time_ms,
            },
            "flags": {
                "include_drafts": self.include_drafts,
                "include_retired": self.include_retired,
                "include_reasons": self.include_reasons,
                "include_value_buckets": self.include_value_buckets,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "records",
        "rule_ids",
        "mode",
        "threshold",
        "include_reasons",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class RuleEvaluationRequest:
    """
    Bounded rule evaluation request.
    """

    records: Any = None
    rule_ids: Any = None
    mode: EvaluationMode | str | None = None
    threshold: Optional[float] = None
    include_reasons: Optional[bool] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        if self.rule_ids is not None:
            self.rule_ids = tuple(
                dict.fromkeys(
                    _clean_text(rule_id, 128).lower()
                    for rule_id in _as_sequence(self.rule_ids)
                    if _clean_text(rule_id, 128)
                )
            )

        self.mode = (
            _normalize_enum_option(EvaluationMode, self.mode, None)
            if self.mode is not None
            else None
        )

        if self.threshold is not None:
            self.threshold = _round6(_clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD))

        if self.include_reasons is not None:
            self.include_reasons = _as_bool(self.include_reasons, True)

        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) if self.request_id else None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) if self.idempotency_key else None


def _coerce_evaluation_request(request: Any) -> RuleEvaluationRequest:
    """
    Coerce flexible rule evaluation input into one bounded request.
    """
    if isinstance(request, RuleEvaluationRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if "records" not in payload:
            for key in ("features", "rows", "items", "examples", "vectors"):
                if key in payload:
                    payload["records"] = payload[key]
                    break

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(RuleEvaluationRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return RuleEvaluationRequest(**clean)
            except Exception:
                return RuleEvaluationRequest(records=payload.get("records", request))

        return RuleEvaluationRequest(records=request)

    return RuleEvaluationRequest(records=request)


# -----------------------------------------------------------------------------
# Input extraction and sanitization
# -----------------------------------------------------------------------------


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, RuleEvaluationResult):
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


def _extract_subject(record: Any, options: RuleEngineOptions) -> Optional[str]:
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


def _normalize_record_value(value: Any, depth: int = 0) -> Any:
    if depth > 2:
        return "[truncated-depth]"

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return int(value)

    if isinstance(value, float):
        return _round6(value) if math.isfinite(value) else None

    if isinstance(value, Decimal):
        if not value.is_finite():
            return None

        try:
            return _round6(float(value))
        except (OverflowError, ValueError):
            return None

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, Enum):
        return _normalize_record_value(value.value, depth + 1)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        keys = sorted(
            dict.fromkeys(
                _canonical_field_name(key)
                for key in value
                if _canonical_field_name(key)
            )
        )
        return tuple(keys[:50])

    if isinstance(value, (list, tuple, set, frozenset)):
        out: list[Any] = []

        for item in list(value)[:50]:
            normalized = _normalize_record_value(item, depth + 1)

            if normalized is not None:
                out.append(normalized)

        return tuple(out)

    text = _clean_text(value, 300)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    numeric = _coerce_optional_float(text, allow_bool=False)

    if numeric is not None:
        return _round6(numeric)

    parsed_bool = _coerce_bool(text)

    if parsed_bool is not None:
        return parsed_bool

    token = _normalize_token(text)

    if token:
        return token

    return text


def _sanitize_records(
    raw_records: Sequence[Any],
    options: RuleEngineOptions,
    issues: list[RuleIssue],
    start_time: Optional[float] = None,
) -> list[dict[str, Any]]:
    """
    Sanitize and bound rule evaluation records.

    Raw values, raw narratives, raw identifiers, secrets, and leakage-prone
    fields are omitted or rejected according to policy.
    """
    if start_time is None:
        start_time = time.monotonic()

    cleaned: list[dict[str, Any]] = []
    seen_subjects: set[str] = set()

    for source_index, record in enumerate(raw_records):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="record_sanitization_time_budget_exhausted",
                message="Record sanitization stopped after reaching configured time budget.",
                details={"processed": len(cleaned), "remaining": max(0, len(raw_records) - source_index)},
            )
            break

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
                    details={"source_index": source_index},
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
                        details={"source_index": source_index},
                    )
                    continue

                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="forbidden_feature",
                    message="Forbidden or label-like feature field rejected.",
                    field=key_text,
                    details={"source_index": source_index},
                )
                valid = False
                break

            if len(clean_features) >= options.max_features:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="feature_limit_reached",
                    message="Additional feature fields omitted due to configured feature limit.",
                    details={"source_index": source_index, "max_features": options.max_features},
                )
                break

            if isinstance(raw_value, str) and _looks_like_sensitive_literal(raw_value):
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="privacy_sensitive_value_dropped",
                    message="Likely PII, secret, or free-text feature value omitted.",
                    field=key_text,
                    details={
                        "source_index": source_index,
                        "value_retained": False,
                    },
                )
                continue

            clean_features[canonical] = _normalize_record_value(raw_value)

        if not valid:
            continue

        if not clean_features:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="empty_feature_row",
                message="Row had no valid feature fields and was skipped.",
                details={"source_index": source_index},
            )
            continue

        if subject:
            if subject in seen_subjects:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.INFO,
                    code="duplicate_subject_reference",
                    message="Duplicate subject reference detected in rule input.",
                    details={"source_index": source_index},
                )
            else:
                seen_subjects.add(subject)

        cleaned.append(
            {
                "index": len(cleaned),
                "source_index": source_index,
                "subject_ref_hash": subject,
                "features": clean_features,
            }
        )

    return cleaned


def _records_feature_names(records: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
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


def _input_fingerprint(records: Sequence[Mapping[str, Any]], options: RuleEngineOptions) -> str:
    feature_names = _records_feature_names(records)
    subjects = {
        str(record.get("subject_ref_hash")).lower()
        for record in records
        if record.get("subject_ref_hash")
    }

    payload = {
        "version": RULE_ENGINE_VERSION,
        "record_count": len(records),
        "feature_count": len(feature_names),
        "feature_names_sample": list(feature_names[: options.max_summary_items]),
        "feature_names_truncated": len(feature_names) > options.max_summary_items,
        "subject_count": len(subjects),
    }

    return _fingerprint_payload(payload)


def _derive_request_id(
    request: RuleEvaluationRequest,
    options: RuleEngineOptions,
    mode: EvaluationMode,
    threshold: float,
    input_fp: Optional[str] = None,
) -> str:
    payload = {
        "version": RULE_ENGINE_VERSION,
        "mode": mode.value,
        "threshold": _round6(threshold),
        "options": options.safe_summary(),
        "metadata": _safe_detail_value(request.metadata),
        "tags": list(request.tags),
        "input_fingerprint": input_fp,
    }

    return _sha256_hex(_canonical_json(payload))[:32]


# -----------------------------------------------------------------------------
# Rule validation
# -----------------------------------------------------------------------------


def _validate_condition_tree(
    condition: Optional[RuleCondition],
    options: RuleEngineOptions,
    rule_id: str,
    issues: list[RuleIssue],
    depth: int = 1,
    state: Optional[dict[str, Any]] = None,
) -> None:
    if condition is None:
        return

    if state is None:
        state = {"nodes": 0, "node_limit_reported": False, "depth_limit_reported": False}

    state["nodes"] = int(state.get("nodes", 0)) + 1

    if state["nodes"] > options.max_expression_nodes and not state.get("node_limit_reported"):
        state["node_limit_reported"] = True
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="rule_expression_node_limit_exceeded",
            message="Rule condition tree exceeded configured expression node limit.",
            details={
                "rule_id": rule_id,
                "node_count": state["nodes"],
                "max_expression_nodes": options.max_expression_nodes,
            },
        )
        return

    if depth > options.max_condition_depth and not state.get("depth_limit_reported"):
        state["depth_limit_reported"] = True
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="rule_condition_depth_limit_exceeded",
            message="Rule condition tree exceeded configured depth limit.",
            details={
                "rule_id": rule_id,
                "depth": depth,
                "max_condition_depth": options.max_condition_depth,
            },
        )
        return

    if _condition_is_group(condition):
        children = list(condition.children or ())

        if not children:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="empty_rule_condition_group",
                message="Rule condition group has no children.",
                details={"rule_id": rule_id},
            )
            return

        if len(children) > options.max_condition_children:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="rule_condition_children_limit_exceeded",
                message="Rule condition group exceeded configured child limit.",
                details={
                    "rule_id": rule_id,
                    "child_count": len(children),
                    "max_condition_children": options.max_condition_children,
                },
            )

        if condition.logic not in _GROUP_LOGICS:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="unsupported_rule_condition_logic",
                message="Rule condition group uses unsupported logic.",
                details={"rule_id": rule_id, "logic": condition.logic},
            )

        if condition.logic == "not" and len(children) != 1:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="rule_not_group_child_count",
                message="Rule NOT group should contain exactly one child; only the first child is used.",
                details={"rule_id": rule_id, "child_count": len(children)},
            )

        for child in children[: options.max_condition_children]:
            _validate_condition_tree(
                child,
                options,
                rule_id,
                issues,
                depth + 1,
                state,
            )

        return

    field = condition.field

    if not field:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="empty_rule_condition_field",
            message="Rule condition has no usable field name.",
            details={"rule_id": rule_id},
        )
        return

    if _is_forbidden_key(field) or _is_label_leakage_key(field):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="forbidden_rule_condition_field",
            message="Rule condition field is prohibited or leakage-prone.",
            field=field,
            details={"rule_id": rule_id},
        )

    if condition.operator not in _SUPPORTED_OPERATORS:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="unsupported_rule_operator",
            message="Rule condition uses an unsupported operator.",
            field=field,
            details={"rule_id": rule_id, "operator": condition.operator},
        )

    if any(token in field for token in _SENSITIVE_DETAIL_TOKENS):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="privacy_sensitive_rule_condition_field",
            message="Rule condition field appears privacy-sensitive.",
            field=field,
            details={"rule_id": rule_id},
        )

    if _condition_requires_value(condition.operator) and not _condition_has_value(condition):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="rule_condition_value_required",
            message="Rule condition operator requires a value or bounded value set.",
            field=field,
            details={"rule_id": rule_id, "operator": condition.operator},
        )

    if condition.metadata.get("value_redacted") and _condition_requires_value(condition.operator):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="rule_condition_value_redacted",
            message="Rule condition value was redacted because it appeared sensitive.",
            field=field,
            details={"rule_id": rule_id, "operator": condition.operator},
        )

    if condition.operator == "between":
        if condition.min_value is None or condition.max_value is None:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="rule_condition_between_bounds_required",
                message="Between condition requires both min_value and max_value.",
                field=field,
                details={"rule_id": rule_id},
            )
        elif float(condition.min_value) > float(condition.max_value):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="rule_condition_between_bounds_inverted",
                message="Between condition min_value is greater than max_value.",
                field=field,
                details={"rule_id": rule_id},
            )

    if condition.operator in {"in", "not_in"} and not condition.values:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="rule_condition_values_required",
            message="Membership condition requires at least one sanitized value.",
            field=field,
            details={"rule_id": rule_id, "operator": condition.operator},
        )

    if len(condition.values) > options.max_literals:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="rule_condition_literal_limit_exceeded",
            message="Rule condition literal count exceeded configured limit.",
            field=field,
            details={
                "rule_id": rule_id,
                "literal_count": len(condition.values),
                "max_literals": options.max_literals,
            },
        )


def _validate_rule_definition(
    rule: RuleDefinition,
    options: RuleEngineOptions,
) -> list[RuleIssue]:
    """
    Validate one bounded rule definition.

    Validation is operational quality gating only. It is not proof of
    correctness and must not trigger automatic adverse customer action.
    """
    issues: list[RuleIssue] = []

    if not rule.rule_id:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="missing_rule_id",
            message="Rule id is required.",
        )

    if not rule.name:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="missing_rule_name",
            message="Rule name is empty.",
            details={"rule_id": rule.rule_id},
        )

    if rule.condition is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="rule_without_conditions",
            message="Rule has no conditions and will never trigger.",
            details={"rule_id": rule.rule_id},
        )
    else:
        _validate_condition_tree(
            rule.condition,
            options,
            rule.rule_id,
            issues,
        )

    action = rule.action if isinstance(rule.action, RuleAction) else RuleAction()

    if action.metadata.get("prohibited_action_detected"):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="prohibited_rule_action",
            message="Rule action is prohibited. Only investigative effects are allowed.",
            details={
                "rule_id": rule.rule_id,
                "requested_effect": _normalize_token(action.requested_effect) or "unknown",
            },
        )

    if rule.status == RuleStatus.ACTIVE and rule.severity == RuleSeverity.CRITICAL:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="active_critical_rule",
            message="Active critical rule requires additional governance review before real use.",
            details={"rule_id": rule.rule_id},
        )

    return issues


# -----------------------------------------------------------------------------
# Condition evaluation helpers
# -----------------------------------------------------------------------------


def _count_condition_nodes(condition: Optional[RuleCondition]) -> int:
    """
    Count bounded condition expression nodes.
    """
    if condition is None:
        return 0

    if _condition_is_group(condition):
        return 1 + sum(_count_condition_nodes(child) for child in condition.children)

    return 1


def _count_condition_leaves(condition: Optional[RuleCondition]) -> int:
    """
    Count bounded leaf conditions.
    """
    if condition is None:
        return 0

    if _condition_is_group(condition):
        return sum(_count_condition_leaves(child) for child in condition.children)

    return 1


def _classified_value(value: Any) -> tuple[str, Any]:
    """
    Classify one record or literal value into a bounded comparison kind.

    Raw free text and likely sensitive literals are not retained beyond safe
    normalized tokens.
    """
    if value is _MISSING or value is None:
        return "missing", None

    if isinstance(value, bool):
        return "boolean", value

    numeric = _coerce_optional_float(value, allow_bool=False)

    if numeric is not None:
        return "numeric", numeric

    if isinstance(value, (list, tuple, set, frozenset)):
        tokens = tuple(
            dict.fromkeys(
                _normalize_token(item)
                for item in value
                if _normalize_token(item)
            )
        )

        if tokens:
            return "sequence", tokens

        return "missing", None

    token = _normalize_token(value)

    if token:
        return "categorical", token

    return "other", _clean_text(value, 128)


def _value_bucket(value: Any, options: RuleEngineOptions) -> str:
    """
    Return a bounded, non-sensitive bucket label for one value.

    This never returns raw values.
    """
    if not options.include_value_buckets:
        return ""

    kind, parsed = _classified_value(value)

    if kind == "missing":
        return "missing"

    if kind == "boolean":
        return "boolean"

    if kind == "numeric":
        return "numeric"

    if kind == "sequence":
        return "sequence"

    if isinstance(parsed, str) and _is_safe_hash(parsed):
        return "hash"

    if isinstance(value, str) and len(value) > 200 and value.count(" ") >= 10:
        return "free_text_omitted"

    return "categorical"


def _equality_match(value: Any, condition_value: Any) -> bool:
    """
    Bounded equality comparison.
    """
    kind, parsed = _classified_value(value)
    cond_kind, cond_parsed = _classified_value(condition_value)

    if kind == "missing" or cond_kind == "missing":
        return False

    if kind == "numeric" and cond_kind == "numeric" and parsed is not None and cond_parsed is not None:
        return math.isclose(float(parsed), float(cond_parsed), rel_tol=1e-9, abs_tol=1e-12)

    if kind == "boolean" and cond_kind == "boolean":
        return bool(parsed) == bool(cond_parsed)

    if kind == "sequence" and cond_kind == "sequence":
        return tuple(parsed or ()) == tuple(cond_parsed or ())

    if kind == "sequence" and cond_kind == "categorical" and isinstance(parsed, tuple):
        return str(cond_parsed) in {str(item) for item in parsed}

    if kind == "categorical" and cond_kind == "categorical":
        return str(parsed) == str(cond_parsed)

    return str(parsed) == str(cond_parsed)


def _membership_match(value: Any, condition_values: Sequence[Any]) -> bool:
    """
    Bounded membership comparison.
    """
    kind, parsed = _classified_value(value)

    if kind == "missing" or not condition_values:
        return False

    if kind == "numeric" and parsed is not None:
        for item in condition_values:
            item_kind, item_parsed = _classified_value(item)

            if item_kind == "numeric" and item_parsed is not None:
                if math.isclose(float(parsed), float(item_parsed), rel_tol=1e-9, abs_tol=1e-12):
                    return True

        return False

    if kind == "boolean":
        allowed_bools = {bool(item) for item in condition_values if isinstance(item, bool)}
        return bool(parsed) in allowed_bools

    if kind == "categorical":
        allowed_tokens = {str(item) for item in condition_values if item is not None}
        return str(parsed) in allowed_tokens

    if kind == "sequence" and isinstance(parsed, tuple):
        allowed_tokens = {str(item) for item in condition_values if item is not None}
        return any(str(item) in allowed_tokens for item in parsed)

    return False


def _contains_match(value: Any, condition_value: Any) -> bool:
    """
    Bounded containment comparison.

    This is intentionally conservative and does not execute patterns.
    """
    kind, parsed = _classified_value(value)
    cond_kind, cond_parsed = _classified_value(condition_value)

    if kind == "missing" or cond_kind == "missing" or cond_parsed is None:
        return False

    needle = str(cond_parsed)

    if not needle:
        return False

    if kind == "sequence" and isinstance(parsed, tuple):
        return needle in {str(item) for item in parsed}

    if kind == "categorical":
        return needle in str(parsed)

    return False


def _starts_with_match(value: Any, condition_value: Any) -> bool:
    """
    Bounded prefix comparison.
    """
    kind, parsed = _classified_value(value)
    cond_kind, cond_parsed = _classified_value(condition_value)

    if kind == "missing" or cond_kind == "missing" or cond_parsed is None:
        return False

    needle = str(cond_parsed)

    if not needle:
        return False

    if kind == "sequence" and isinstance(parsed, tuple):
        return any(str(item).startswith(needle) for item in parsed)

    if kind == "categorical":
        return str(parsed).startswith(needle)

    return False


def _ends_with_match(value: Any, condition_value: Any) -> bool:
    """
    Bounded suffix comparison.
    """
    kind, parsed = _classified_value(value)
    cond_kind, cond_parsed = _classified_value(condition_value)

    if kind == "missing" or cond_kind == "missing" or cond_parsed is None:
        return False

    needle = str(cond_parsed)

    if not needle:
        return False

    if kind == "sequence" and isinstance(parsed, tuple):
        return any(str(item).endswith(needle) for item in parsed)

    if kind == "categorical":
        return str(parsed).endswith(needle)

    return False


def _numeric_compare(
    value: Any,
    operator: str,
    condition: RuleCondition,
) -> Optional[bool]:
    """
    Bounded numeric comparison.

    Returns None when the condition is structurally invalid for comparison.
    Returns False when the record value is missing or non-numeric but the
    condition itself is valid.
    """
    kind, parsed = _classified_value(value)

    if operator == "between":
        if condition.min_value is None or condition.max_value is None:
            return None

        if kind != "numeric" or parsed is None:
            return False

        return float(condition.min_value) <= float(parsed) <= float(condition.max_value)

    if operator in {"gt", "gte", "lt", "lte"}:
        if condition.value is None:
            return None

        cond_kind, cond_parsed = _classified_value(condition.value)

        if cond_kind != "numeric" or cond_parsed is None:
            return None

        if kind != "numeric" or parsed is None:
            return False

        left = float(parsed)
        right = float(cond_parsed)

        if operator == "gt":
            return left > right

        if operator == "gte":
            return left >= right

        if operator == "lt":
            return left < right

        return left <= right

    return None


def _leaf_match(
    condition: RuleCondition,
    value: Any,
) -> Optional[bool]:
    """
    Evaluate one bounded leaf condition against one sanitized value.

    Returns None when the condition is invalid or cannot be safely evaluated.
    """
    operator = condition.operator

    if operator == "is_null":
        return value is _MISSING or value is None

    if operator == "not_null":
        return value is not _MISSING and value is not None

    if operator == "true":
        return _coerce_bool(value if value is not _MISSING else None) is True

    if operator == "false":
        return _coerce_bool(value if value is not _MISSING else None) is False

    if operator == "zero":
        kind, parsed = _classified_value(value)
        return (
            kind == "numeric"
            and parsed is not None
            and math.isclose(float(parsed), 0.0, abs_tol=1e-12)
        )

    if operator == "nonzero":
        kind, parsed = _classified_value(value)
        return (
            kind == "numeric"
            and parsed is not None
            and not math.isclose(float(parsed), 0.0, abs_tol=1e-12)
        )

    if operator == "finite":
        kind, parsed = _classified_value(value)
        return kind == "numeric" and parsed is not None and math.isfinite(float(parsed))

    if operator in {"eq", "ne"}:
        if condition.value is None:
            return None

        kind, _parsed = _classified_value(value)

        if kind == "missing":
            return False

        matched = _equality_match(value, condition.value)
        return matched if operator == "eq" else not matched

    if operator in {"gt", "gte", "lt", "lte", "between"}:
        return _numeric_compare(value, operator, condition)

    if operator in {"in", "not_in"}:
        if not condition.values:
            return None

        kind, _parsed = _classified_value(value)

        if kind == "missing":
            return False

        matched = _membership_match(value, condition.values)
        return matched if operator == "in" else not matched

    if operator in {"contains", "not_contains"}:
        if condition.value is None:
            return None

        kind, _parsed = _classified_value(value)

        if kind == "missing":
            return False

        matched = _contains_match(value, condition.value)
        return matched if operator == "contains" else not matched

    if operator in {"starts_with", "not_starts_with"}:
        if condition.value is None:
            return None

        kind, _parsed = _classified_value(value)

        if kind == "missing":
            return False

        matched = _starts_with_match(value, condition.value)
        return matched if operator == "starts_with" else not matched

    if operator in {"ends_with", "not_ends_with"}:
        if condition.value is None:
            return None

        kind, _parsed = _classified_value(value)

        if kind == "missing":
            return False

        matched = _ends_with_match(value, condition.value)
        return matched if operator == "ends_with" else not matched

    return None


def _evaluate_condition_node(
    condition: Optional[RuleCondition],
    record: Mapping[str, Any],
    options: RuleEngineOptions,
    issues: list[RuleIssue],
    rule_id: str,
    depth: int = 1,
    include_reasons: bool = True,
) -> tuple[Optional[bool], list[dict[str, Any]], dict[str, int]]:
    """
    Evaluate one bounded condition node against one sanitized record.

    Returns `(matched, reasons, stats)`. `matched` is None when the condition is
    invalid or prohibited for this record.
    """
    if condition is None:
        return None, [], {}

    if depth > options.max_condition_depth:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="rule_condition_depth_limit_exceeded_during_evaluation",
            message="Rule condition depth exceeded configured limit during evaluation.",
            details={"rule_id": rule_id, "depth": depth},
        )
        return None, [], {}

    if _condition_is_group(condition):
        children = list(condition.children or ())

        if not children:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="empty_rule_condition_group_during_evaluation",
                message="Rule condition group has no children.",
                details={"rule_id": rule_id},
            )
            return None, [], {}

        child_results: list[bool] = []
        reasons: list[dict[str, Any]] = []
        stats = {"leaf_count": 0, "matched_leaf_count": 0}

        for child in children[: options.max_condition_children]:
            matched, child_reasons, child_stats = _evaluate_condition_node(
                child,
                record,
                options,
                issues,
                rule_id,
                depth + 1,
                include_reasons,
            )

            if matched is None:
                return None, [], {}

            child_results.append(bool(matched))
            stats["leaf_count"] += int(child_stats.get("leaf_count", 0))
            stats["matched_leaf_count"] += int(child_stats.get("matched_leaf_count", 0))

            if include_reasons:
                reasons.extend(child_reasons)

        logic = condition.logic

        if logic == "all":
            base = all(child_results)
        elif logic == "any":
            base = any(child_results)
        elif logic == "none":
            base = not any(child_results)
        elif logic == "not":
            base = not child_results[0] if child_results else False
        else:
            base = all(child_results)

        if condition.negate:
            base = not base

        if include_reasons:
            reasons.append(
                {
                    "node_type": "group",
                    "logic": logic,
                    "matched": bool(base),
                    "negated": bool(condition.negate),
                    "child_count": len(children),
                    "matched_child_count": sum(1 for item in child_results if item),
                    "description": condition.description,
                }
            )

        return bool(base), reasons, stats

    field = condition.field

    if not field:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="empty_rule_condition_field_during_evaluation",
            message="Rule condition has no usable field name.",
            details={"rule_id": rule_id},
        )
        return None, [], {}

    if _is_forbidden_key(field) or _is_label_leakage_key(field):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="forbidden_rule_condition_field_during_evaluation",
            message="Rule condition field is prohibited or leakage-prone.",
            field=field,
            details={"rule_id": rule_id},
        )
        return None, [], {}

    if condition.operator not in _SUPPORTED_OPERATORS:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="unsupported_rule_operator_during_evaluation",
            message="Rule condition uses an unsupported operator.",
            field=field,
            details={"rule_id": rule_id, "operator": condition.operator},
        )
        return None, [], {}

    features = record.get("features")

    if not isinstance(features, Mapping):
        features = {}

    value = features.get(field, _MISSING)
    matched = _leaf_match(condition, value)

    if matched is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_rule_condition_during_evaluation",
            message="Rule condition is invalid for this record and was not evaluated.",
            field=field,
            details={"rule_id": rule_id, "operator": condition.operator},
        )
        return None, [], {}

    if condition.negate:
        matched = not matched

    reason = {
        "node_type": "leaf",
        "field": field,
        "operator": condition.operator,
        "matched": bool(matched),
        "negated": bool(condition.negate),
        "value_bucket": _value_bucket(value, options),
        "description": condition.description,
    }

    stats = {
        "leaf_count": 1,
        "matched_leaf_count": 1 if matched else 0,
    }

    return bool(matched), ([reason] if include_reasons else []), stats


def _rule_score(
    rule: RuleDefinition,
    stats: Mapping[str, int],
    options: RuleEngineOptions,
) -> float:
    """
    Compute bounded rule score contribution.

    The score is an investigative prioritization signal only. It is not a
    probability of guilt.
    """
    severity = _enum_value(rule.severity, RuleSeverity.MEDIUM.value)
    base = float(_SEVERITY_WEIGHTS.get(severity, 0.35))

    action = rule.action if isinstance(rule.action, RuleAction) else RuleAction()
    action_delta = float(action.score_delta or 0.0)

    leaf_count = max(0, int(stats.get("leaf_count", 0)))
    matched_leaf_count = max(0, int(stats.get("matched_leaf_count", 0)))

    condition_factor = 1.0

    if leaf_count > 0:
        condition_factor = _clip_float(
            float(matched_leaf_count) / float(leaf_count),
            0.0,
            1.0,
            1.0,
        )

    priority_factor = 1.0 + _clip_float(float(rule.priority), -100.0, 100.0, 0.0) / 200.0
    raw = (base + action_delta + float(rule.score_delta)) * condition_factor * priority_factor

    return _round6(_clip_float(raw, 0.0, 1.0, 0.0))


def _risk_band(score: Optional[float], options: RuleEngineOptions) -> str:
    """
    Map one bounded score to an operational risk band.

    Risk bands are investigative prioritization labels only.
    """
    if score is None:
        return "unavailable"

    thresholds = options.risk_thresholds
    value = float(score)

    if value >= float(thresholds.get("critical", 0.90)):
        return "critical"

    if value >= float(thresholds.get("high", 0.75)):
        return "high"

    if value >= float(thresholds.get("medium", 0.55)):
        return "medium"

    if value >= float(thresholds.get("low", 0.35)):
        return "low"

    return "minimal"


def _evaluate_rule(
    rule: RuleDefinition,
    record: Mapping[str, Any],
    options: RuleEngineOptions,
    issues: list[RuleIssue],
    include_reasons: bool,
    start_time: float,
) -> Optional[RuleMatch]:
    """
    Evaluate one rule against one sanitized record.

    Returns None when the rule does not match, is disabled, is filtered by
    lifecycle policy, is prohibited, or cannot be safely evaluated.
    """
    if not rule.enabled:
        return None

    if rule.status == RuleStatus.BLOCKED:
        return None

    if rule.status == RuleStatus.RETIRED and not options.include_retired:
        return None

    if rule.status == RuleStatus.DRAFT and not options.include_drafts:
        return None

    if rule.condition is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="rule_without_conditions",
            message="Rule has no conditions and was skipped.",
            details={"rule_id": rule.rule_id},
        )
        return None

    if _time_exceeded(start_time, options.max_time_ms):
        return None

    matched, reasons, stats = _evaluate_condition_node(
        rule.condition,
        record,
        options,
        issues,
        rule.rule_id,
        include_reasons=include_reasons,
    )

    if matched is None:
        return None

    if not matched:
        return None

    action = rule.action if isinstance(rule.action, RuleAction) else RuleAction()

    if (
        action.metadata.get("prohibited_action_detected")
        or _contains_prohibited_action(
            action.requested_effect,
            action.reason_code,
            action.reason_message,
            action.metadata,
        )
    ):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="prohibited_rule_action",
            message="Rule action is prohibited and was not applied.",
            details={"rule_id": rule.rule_id},
        )
        return None

    score = _rule_score(rule, stats, options)
    effects: list[str] = []

    if action.effect != ActionEffect.NONE:
        effects.append(_enum_value(action.effect, ActionEffect.ANNOTATE.value))

    if include_reasons:
        if action.reason_code or action.reason_message:
            reasons.append(
                {
                    "type": "action",
                    "rule_id": rule.rule_id,
                    "effect": _enum_value(action.effect, ActionEffect.ANNOTATE.value),
                    "reason_code": action.reason_code,
                    "reason_message": action.reason_message,
                }
            )

        reasons.append(
            {
                "type": "rule_summary",
                "rule_id": rule.rule_id,
                "severity": _enum_value(rule.severity, RuleSeverity.MEDIUM.value),
                "matched_leaf_count": int(stats.get("matched_leaf_count", 0)),
                "leaf_count": int(stats.get("leaf_count", 0)),
                "score_contribution": score,
            }
        )

    return RuleMatch(
        rule_id=rule.rule_id,
        severity=rule.severity,
        score_contribution=score,
        effects=tuple(effects),
        reasons=tuple(reasons[: options.max_reasons]),
        metadata={
            "kind": _enum_value(rule.kind, RuleKind.DETECTION.value),
            "status": _enum_value(rule.status, RuleStatus.DRAFT.value),
            "priority": int(rule.priority),
            "tags": list(rule.tags),
            "action_effect": _enum_value(action.effect, ActionEffect.ANNOTATE.value),
            "requested_effect": _normalize_token(action.requested_effect) or "unknown",
            "prohibited_action_detected": bool(action.metadata.get("prohibited_action_detected", False)),
            "matched_leaf_count": int(stats.get("matched_leaf_count", 0)),
            "leaf_count": int(stats.get("leaf_count", 0)),
        },
    )


# -----------------------------------------------------------------------------
# Process-local rule registry
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _RegisteredRule:
    definition: RuleDefinition
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class RuleRegistry:
    """
    Bounded process-local rule registry.

    This registry is not durable, not distributed, and not production-ready.
    It exists only to support local prototype workflows, tests, developer
    tooling, and offline evaluation harnesses.
    """

    def __init__(self, max_rules: int = _DEFAULT_MAX_RULES) -> None:
        self.max_rules = max(1, int(max_rules))
        self._rules: dict[str, _RegisteredRule] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(
        self,
        definition: Any,
        *,
        replace: bool = False,
        validate: bool = True,
        options: RuleEngineOptions | None = None,
    ) -> str:
        """
        Register one rule definition and return its rule id.

        Registration is process-local only. It does not deploy rules to
        production and does not authorize actions.
        """
        opts = options or RuleEngineOptions.from_settings()

        if isinstance(definition, Mapping):
            fields = set(getattr(RuleDefinition, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in definition.items() if key in fields}

            try:
                definition = RuleDefinition(**clean)
            except Exception as exc:
                raise MuleGuardValidationError(
                    "Rule definition mapping could not be parsed.",
                    details={"exception_type": type(exc).__name__},
                ) from exc

        if not isinstance(definition, RuleDefinition):
            raise MuleGuardValidationError("Rule definition must be RuleDefinition or mapping.")

        if validate:
            issues = _validate_rule_definition(definition, opts)

            if _has_error(issues):
                raise MuleGuardValidationError(
                    "Rule validation failed.",
                    details={"issues": [issue.to_dict() for issue in issues]},
                )

        with self._lock:
            rule_id = definition.rule_id

            if not rule_id:
                rule_id = _derive_rule_id(definition)
                definition = replace(definition, rule_id=rule_id)

            existing = self._rules.get(rule_id)

            if existing is not None and not replace:
                raise MuleGuardValidationError(
                    "Rule id already registered.",
                    details={"rule_id": rule_id},
                )

            self._rules[rule_id] = _RegisteredRule(
                definition=definition,
                registered_at=_now_utc(),
            )

            if rule_id not in self._order:
                self._order.append(rule_id)

            if len(self._order) > self.max_rules:
                evict_id = self._order.pop(0)
                self._rules.pop(evict_id, None)

            return rule_id

    def get(self, rule_id: Any) -> Optional[RuleDefinition]:
        """
        Return one registered rule definition.
        """
        key = _clean_text(rule_id, 128).lower()

        with self._lock:
            entry = self._rules.get(key)
            return entry.definition if entry is not None else None

    def snapshot(self) -> tuple[RuleDefinition, ...]:
        """
        Return registered rule definitions in insertion order.
        """
        with self._lock:
            return tuple(
                self._rules[rule_id].definition
                for rule_id in self._order
                if rule_id in self._rules
            )

    def activate(self, rule_id: Any) -> RuleDefinition:
        """
        Mark one process-local rule as ACTIVE.

        This does not deploy rules to production.
        """
        key = _clean_text(rule_id, 128).lower()

        with self._lock:
            entry = self._rules.get(key)

            if entry is None:
                raise MuleGuardValidationError(
                    "Rule not found in process-local registry.",
                    details={"rule_id": key},
                )

            updated = replace(
                entry.definition,
                status=RuleStatus.ACTIVE,
                enabled=True,
                updated_at=_now_utc(),
            )

            entry.definition = updated
            return updated

    def retire(self, rule_id: Any) -> RuleDefinition:
        """
        Mark one process-local rule as RETIRED.
        """
        key = _clean_text(rule_id, 128).lower()

        with self._lock:
            entry = self._rules.get(key)

            if entry is None:
                raise MuleGuardValidationError(
                    "Rule not found in process-local registry.",
                    details={"rule_id": key},
                )

            updated = replace(
                entry.definition,
                status=RuleStatus.RETIRED,
                enabled=False,
                updated_at=_now_utc(),
            )

            entry.definition = updated
            return updated

    def block(self, rule_id: Any) -> RuleDefinition:
        """
        Mark one process-local rule as BLOCKED.
        """
        key = _clean_text(rule_id, 128).lower()

        with self._lock:
            entry = self._rules.get(key)

            if entry is None:
                raise MuleGuardValidationError(
                    "Rule not found in process-local registry.",
                    details={"rule_id": key},
                )

            updated = replace(
                entry.definition,
                status=RuleStatus.BLOCKED,
                enabled=False,
                updated_at=_now_utc(),
            )

            entry.definition = updated
            return updated

    def clear(self) -> None:
        """
        Clear the process-local registry.
        """
        with self._lock:
            self._rules.clear()
            self._order.clear()

    def summarize(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """
        Return safe registry summaries.
        """
        with self._lock:
            out: list[dict[str, Any]] = []

            for rule_id in self._order[: max(1, int(limit))]:
                entry = self._rules.get(rule_id)

                if entry is None:
                    continue

                rule = entry.definition
                action = rule.action if isinstance(rule.action, RuleAction) else RuleAction()

                out.append(
                    {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "kind": _enum_value(rule.kind, RuleKind.DETECTION.value),
                        "severity": _enum_value(rule.severity, RuleSeverity.MEDIUM.value),
                        "status": _enum_value(rule.status, RuleStatus.DRAFT.value),
                        "enabled": bool(rule.enabled),
                        "priority": int(rule.priority),
                        "condition_node_count": _count_condition_nodes(rule.condition),
                        "condition_leaf_count": _count_condition_leaves(rule.condition),
                        "condition_logic": rule.condition_logic,
                        "action_effect": _enum_value(action.effect, ActionEffect.ANNOTATE.value),
                        "requested_effect": _normalize_token(action.requested_effect) or "unknown",
                        "prohibited_action_detected": bool(
                            action.metadata.get("prohibited_action_detected", False)
                        ),
                        "tags": list(rule.tags),
                        "owner": rule.owner,
                        "version": rule.version,
                        "created_at": rule.created_at.isoformat(),
                        "updated_at": rule.updated_at.isoformat(),
                        "registered_at": entry.registered_at.isoformat(),
                    }
                )

            return out

    def safe_summary(self, *, limit: int = 50) -> dict[str, Any]:
        """
        Return safe registry summary.
        """
        with self._lock:
            status_counter = Counter(
                _enum_value(entry.definition.status, RuleStatus.DRAFT.value)
                for entry in self._rules.values()
            )
            severity_counter = Counter(
                _enum_value(entry.definition.severity, RuleSeverity.MEDIUM.value)
                for entry in self._rules.values()
            )
            kind_counter = Counter(
                _enum_value(entry.definition.kind, RuleKind.DETECTION.value)
                for entry in self._rules.values()
            )
            prohibited_count = sum(
                1
                for entry in self._rules.values()
                if isinstance(entry.definition.action, RuleAction)
                and entry.definition.action.metadata.get("prohibited_action_detected")
            )

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_rules": self.max_rules,
            "registered_rules": len(self._order),
            "by_status": dict(status_counter),
            "by_severity": dict(severity_counter),
            "by_kind": dict(kind_counter),
            "prohibited_action_count": int(prohibited_count),
            "recent": self.summarize(limit=limit),
        }


_default_registry: Optional[RuleRegistry] = None
_default_registry_lock = threading.Lock()


def get_rule_registry(
    max_rules: int | None = None,
    *,
    rebuild: bool = False,
) -> RuleRegistry:
    """
    Return the process-wide rule registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = RuleRegistry(
                max_rules=max_rules if max_rules is not None else _DEFAULT_MAX_RULES
            )

        return _default_registry


# -----------------------------------------------------------------------------
# Rule engine
# -----------------------------------------------------------------------------


class RuleEngine:
    """
    Bounded deterministic synthetic rule engine.

    This engine evaluates investigative rules against sanitized synthetic
    records. It does not authorize actions, does not deploy rules, does not
    persist durable artifacts, and must not trigger automatic adverse customer
    action.
    """

    def __init__(
        self,
        options: RuleEngineOptions | None = None,
        registry: RuleRegistry | None = None,
    ) -> None:
        self.options = options or RuleEngineOptions.from_settings()
        self.registry = registry or get_rule_registry(self.options.max_rules)
        self._lock = threading.RLock()

    def _select_rules(
        self,
        requested_ids: Optional[Sequence[str]],
        mode: EvaluationMode,
        issues: list[RuleIssue],
    ) -> tuple[RuleDefinition, ...]:
        """
        Select bounded rules eligible for evaluation.
        """
        opts = self.options
        rules = self.registry.snapshot()

        requested = (
            set(
                dict.fromkeys(
                    _clean_text(rule_id, 128).lower()
                    for rule_id in requested_ids
                    if _clean_text(rule_id, 128)
                )
            )
            if requested_ids
            else None
        )

        selected: list[RuleDefinition] = []

        for rule in rules:
            if requested is not None and rule.rule_id not in requested:
                continue

            if not rule.enabled:
                continue

            if rule.status == RuleStatus.BLOCKED:
                continue

            if rule.status == RuleStatus.RETIRED and not opts.include_retired:
                continue

            if rule.status == RuleStatus.DRAFT:
                if opts.include_drafts or mode == EvaluationMode.DRY_RUN:
                    selected.append(rule)
                continue

            selected.append(rule)

        if requested is not None:
            found = {rule.rule_id for rule in selected}
            missing = sorted(requested - found)

            if missing:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="requested_rules_unavailable",
                    message="Some requested rules were not available for evaluation.",
                    details={
                        "missing_count": len(missing),
                        "missing_sample": missing[: opts.max_summary_items],
                        "truncated": len(missing) > opts.max_summary_items,
                    },
                )

        selected.sort(
            key=lambda rule: (
                -int(rule.priority),
                -float(
                    _SEVERITY_WEIGHTS.get(
                        _enum_value(rule.severity, RuleSeverity.MEDIUM.value),
                        0.35,
                    )
                ),
                rule.rule_id,
            )
        )

        if len(selected) > opts.max_rules_evaluated:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="rule_evaluation_truncated",
                message="Selected rule count exceeded configured evaluation limit and was truncated.",
                details={
                    "selected": len(selected),
                    "max_rules_evaluated": opts.max_rules_evaluated,
                },
            )
            selected = selected[: opts.max_rules_evaluated]

        return tuple(selected)

    def evaluate(self, request: Any) -> RuleEvaluationResult:
        """
        Evaluate one bounded synthetic rule request.
        """
        opts = self.options
        issues: list[RuleIssue] = []
        start_time = time.monotonic()

        req = _coerce_evaluation_request(request)
        mode = _normalize_enum_option(
            EvaluationMode,
            req.mode or opts.mode,
            EvaluationMode.SHADOW,
        )
        threshold = req.threshold if req.threshold is not None else opts.threshold
        threshold = _round6(_clamp_float(threshold, 0.0, 1.0, opts.threshold))
        include_reasons = (
            req.include_reasons
            if req.include_reasons is not None
            else opts.include_reasons
        )

        input_fp: Optional[str] = None
        request_id = _derive_request_id(req, opts, mode, threshold, None)

        def make_result(
            ok: bool,
            records: Sequence[RuleRecordResult] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> RuleEvaluationResult:
            """
            Build one safe rule evaluation result.
            """
            resolved_counts: dict[str, int] = {
                "submitted": 0,
                "processed": 0,
                "scored": 0,
                "matched_records": 0,
                "triggered_rules": 0,
                "review_recommended": 0,
                "selected_rules": 0,
                "by_effect": 0,
                "by_band": 0,
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

            metadata = {
                "rules_engine_version": RULE_ENGINE_VERSION,
                "mode": mode.value,
                "threshold": _round6(threshold),
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "input_fingerprint": input_fp,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "registry": self.registry.safe_summary(limit=opts.max_summary_items),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_values_retained": False,
                "subject_label_pairs_retained": False,
                "narratives_retained": False,
                "identifiers_retained": False,
                "secrets_retained": False,
                "caveats": list(_RULE_CAVEATS),
                "safety_flags": dict(_RULE_SAFETY_FLAGS),
            }

            return RuleEvaluationResult(
                ok=ok,
                mode=mode,
                records=tuple(records),
                counts=resolved_counts,
                issues=tuple(issues),
                metadata=metadata,
                fingerprint="",
            )

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="rule_engine_disabled",
                message="Rule engine is disabled.",
            )
            return make_result(False)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Rule engine requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Rule engine is blocked in production-like environments.",
            )
            return make_result(False)

        raw_records = _iter_records(req.records)
        submitted = len(raw_records)

        if submitted > opts.max_records:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="rule_input_truncated",
                message="Rule input exceeded configured record limit and was truncated.",
                details={
                    "submitted": submitted,
                    "max_records": opts.max_records,
                },
            )
            raw_records = raw_records[: opts.max_records]

        cleaned = _sanitize_records(raw_records, opts, issues, start_time=start_time)

        if not cleaned:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_valid_rule_records",
                message="No valid records remained after sanitization.",
            )
            return make_result(
                False,
                counts={
                    "submitted": submitted,
                    "processed": len(raw_records),
                },
            )

        input_fp = _input_fingerprint(cleaned, opts)
        request_id = _derive_request_id(req, opts, mode, threshold, input_fp)

        selected_rules = self._select_rules(req.rule_ids, mode, issues)

        if not selected_rules:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="no_rules_available",
                message="No rules were available for evaluation.",
            )
            return make_result(
                not _has_error(issues),
                records=(),
                counts={
                    "submitted": submitted,
                    "processed": len(cleaned),
                    "selected_rules": 0,
                },
            )

        record_results: list[RuleRecordResult] = []
        triggered_rule_counter: Counter[str] = Counter()
        effect_counter: Counter[str] = Counter()
        band_counter: Counter[str] = Counter()
        scored = 0
        matched_records = 0
        review_recommended = 0

        for record in cleaned:
            if _time_exceeded(start_time, opts.max_time_ms):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="rule_evaluation_time_budget_exhausted",
                    message="Rule evaluation stopped after reaching configured time budget.",
                    details={"processed_records": len(record_results)},
                )
                break

            matches: list[RuleMatch] = []
            all_effects: list[str] = []
            all_reasons: list[dict[str, Any]] = []
            score_components: dict[str, float] = {}

            for rule in selected_rules:
                if _time_exceeded(start_time, opts.max_time_ms):
                    break

                match = _evaluate_rule(
                    rule,
                    record,
                    opts,
                    issues,
                    include_reasons,
                    start_time,
                )

                if match is None:
                    continue

                matches.append(match)
                triggered_rule_counter[match.rule_id] += 1
                score_components[match.rule_id] = float(match.score_contribution)

                for effect in match.effects:
                    all_effects.append(effect)
                    effect_counter[effect] += 1

                if include_reasons:
                    all_reasons.extend(match.reasons)

            combined = 1.0

            for match in matches:
                combined *= max(0.0, 1.0 - float(match.score_contribution))

            # `None` means "could not be evaluated", not "nothing fired".
            #
            # The noisy-OR of an empty match set is exactly 0.0, so a record
            # that was checked against the rule pack and matched nothing has a
            # score of zero and a minimal band. That is a finding: the account
            # was assessed and nothing stood out.
            #
            # Reserving `None` for "no rules were available to evaluate" keeps
            # the two states apart. Returning `None` whenever nothing matched
            # meant an ordinary, fully-populated account was reported as
            # `unavailable` — the mirror of the error this codebase is careful
            # about elsewhere (never render "not assessed" as a zero), and it
            # would bury the genuinely unassessable records among thousands of
            # unremarkable ones. Records with no usable features are already
            # dropped with an `empty_feature_row` issue, and partial data is
            # what the guardrail rule is for.
            score = _round6(1.0 - combined) if selected_rules else None

            if score is not None:
                scored += 1

            band = _risk_band(score, opts)
            band_counter[band] += 1

            review = bool(
                score is not None
                and (
                    float(score) >= float(threshold)
                    or ActionEffect.FLAG_FOR_REVIEW.value in all_effects
                    or ActionEffect.ESCALATE_TO_HUMAN.value in all_effects
                )
            )

            if review:
                review_recommended += 1

            if matches:
                matched_records += 1

            record_results.append(
                RuleRecordResult(
                    subject_ref_hash=record.get("subject_ref_hash"),
                    index=int(record.get("index", len(record_results))),
                    score=score,
                    risk_band=band,
                    review_recommended=review,
                    matched_rules=tuple(matches),
                    effects=tuple(dict.fromkeys(all_effects)),
                    reasons=tuple(all_reasons[: opts.max_reasons]),
                    decision_source="rule_engine",
                    metadata={
                        "mode": mode.value,
                        "threshold": _round6(threshold),
                        "score_components": score_components,
                        "matched_rule_count": len(matches),
                        "caveats": list(_RULE_CAVEATS),
                        "safety_flags": dict(_RULE_SAFETY_FLAGS),
                    },
                )
            )

        counts = {
            "submitted": submitted,
            "processed": len(cleaned),
            "scored": scored,
            "matched_records": matched_records,
            "triggered_rules": len(triggered_rule_counter),
            "review_recommended": review_recommended,
            "selected_rules": len(selected_rules),
            "by_effect": sum(effect_counter.values()),
            "by_band": sum(band_counter.values()),
        }

        result = make_result(
            ok=not _has_error(issues),
            records=record_results,
            counts=counts,
        )

        metadata = dict(result.metadata)
        metadata.update(
            _safe_detail_value(
                {
                    "selected_rule_ids": [
                        rule.rule_id for rule in selected_rules[: opts.max_summary_items]
                    ],
                    "selected_rule_ids_truncated": len(selected_rules) > opts.max_summary_items,
                    "triggered_rule_counts": dict(triggered_rule_counter),
                    "effect_counts": dict(effect_counter),
                    "band_counts": dict(band_counter),
                }
            )
            or {}
        )

        return replace(result, metadata=metadata, fingerprint="")

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe engine summary.
        """
        return {
            "options": self.options.safe_summary(),
            "registry": self.registry.safe_summary(limit=self.options.max_summary_items),
            "caveats": list(_RULE_CAVEATS),
            "safety_flags": dict(_RULE_SAFETY_FLAGS),
        }


_default_engine: Optional[RuleEngine] = None
_default_engine_lock = threading.Lock()


def get_rule_engine(
    options: RuleEngineOptions | None = None,
    *,
    rebuild: bool = False,
) -> RuleEngine:
    """
    Return a process-wide rule engine.

    If options are supplied or rebuild is True, a new engine is created and
    becomes the default.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = RuleEngine(options=options or RuleEngineOptions.from_settings())

        return _default_engine


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def register_rule(
    definition: Any,
    *,
    replace: bool = False,
    validate: bool = True,
    options: RuleEngineOptions | None = None,
    registry: RuleRegistry | None = None,
) -> str:
    """
    Register one bounded investigative rule definition.

    This is process-local registration only. It does not deploy rules to
    production.
    """
    active_registry = registry or get_rule_registry()
    return active_registry.register(
        definition,
        replace=replace,
        validate=validate,
        options=options,
    )


def get_rule(rule_id: Any, *, registry: RuleRegistry | None = None) -> Optional[RuleDefinition]:
    """
    Return one registered rule definition.
    """
    active_registry = registry or get_rule_registry()
    return active_registry.get(rule_id)


def activate_rule(rule_id: Any, *, registry: RuleRegistry | None = None) -> RuleDefinition:
    """
    Mark one process-local rule as ACTIVE.

    This does not deploy rules to production.
    """
    active_registry = registry or get_rule_registry()
    return active_registry.activate(rule_id)


def retire_rule(rule_id: Any, *, registry: RuleRegistry | None = None) -> RuleDefinition:
    """
    Mark one process-local rule as RETIRED.
    """
    active_registry = registry or get_rule_registry()
    return active_registry.retire(rule_id)


def block_rule(rule_id: Any, *, registry: RuleRegistry | None = None) -> RuleDefinition:
    """
    Mark one process-local rule as BLOCKED.
    """
    active_registry = registry or get_rule_registry()
    return active_registry.block(rule_id)


def evaluate_rules(
    request: Any,
    options: RuleEngineOptions | None = None,
    *,
    engine: RuleEngine | None = None,
) -> RuleEvaluationResult:
    """
    Evaluate one bounded synthetic rule request.
    """
    active_engine = engine or get_rule_engine(options)
    return active_engine.evaluate(request)


def dry_run_rules(
    request: Any,
    options: RuleEngineOptions | None = None,
    *,
    engine: RuleEngine | None = None,
) -> RuleEvaluationResult:
    """
    Run one bounded dry-run rule evaluation.
    """
    req = _coerce_evaluation_request(request)
    req.mode = EvaluationMode.DRY_RUN
    return evaluate_rules(req, options=options, engine=engine)


def list_rules(*, registry: RuleRegistry | None = None) -> tuple[RuleDefinition, ...]:
    """
    Return registered rule definitions.
    """
    active_registry = registry or get_rule_registry()
    return active_registry.snapshot()


def summarize_rules(*, limit: int = 50, registry: RuleRegistry | None = None) -> list[dict[str, Any]]:
    """
    Return safe registered rule summaries.
    """
    active_registry = registry or get_rule_registry()
    return active_registry.summarize(limit=limit)


def get_rules_health(*, engine: RuleEngine | None = None) -> dict[str, Any]:
    """
    Return safe rule-engine health.
    """
    active_engine = engine or get_rule_engine()
    opts = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=opts.max_summary_items)

    issues: list[RuleIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="rule_engine_disabled",
            message="Rule engine is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Rule engine requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Rule engine is blocked in production-like environments.",
        )
    elif int(registry_summary.get("registered_rules", 0)) <= 0:
        status = "DEGRADED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="no_registered_rules",
            message="No rules are registered in the process-local registry.",
        )
    elif int(registry_summary.get("prohibited_action_count", 0)) > 0:
        status = "DEGRADED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="prohibited_rule_actions_present",
            message="One or more registered rules contain prohibited action metadata.",
            details={
                "count": int(registry_summary.get("prohibited_action_count", 0)),
            },
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "mode": opts.mode.value if isinstance(opts.mode, EvaluationMode) else str(opts.mode),
        "registry": registry_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(_RULE_CAVEATS),
        "safety_flags": dict(_RULE_SAFETY_FLAGS),
    }


def get_rules_metadata() -> dict[str, Any]:
    """
    Return safe, serializable rules-engine metadata.

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
    options = RuleEngineOptions.from_settings()
    registry = get_rule_registry(options.max_rules)

    return {
        "package": "muleguard.backend.rules.engine",
        "version": RULE_ENGINE_VERSION,
        "severities": [severity.value for severity in RuleSeverity],
        "statuses": [status.value for status in RuleStatus],
        "kinds": [kind.value for kind in RuleKind],
        "effects": [effect.value for effect in ActionEffect],
        "modes": [mode.value for mode in EvaluationMode],
        "operators": sorted(_SUPPORTED_OPERATORS),
        "condition_logics": sorted(_GROUP_LOGICS),
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "registry": registry.safe_summary(limit=options.max_summary_items),
        "hard_limits": {
            "max_records": _HARD_MAX_RECORDS,
            "max_features": _HARD_MAX_FEATURES,
            "max_rules": _HARD_MAX_RULES,
            "max_rules_evaluated": _HARD_MAX_RULES_EVALUATED,
            "max_conditions": _HARD_MAX_CONDITIONS,
            "max_condition_depth": _HARD_MAX_CONDITION_DEPTH,
            "max_condition_children": _HARD_MAX_CONDITION_CHILDREN,
            "max_expression_nodes": _HARD_MAX_EXPRESSION_NODES,
            "max_literals": _HARD_MAX_LITERALS,
            "max_condition_values": _HARD_MAX_CONDITION_VALUES,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_reasons": _HARD_MAX_REASONS,
            "max_time_ms": _HARD_MAX_TIME_MS,
        },
        "forbidden_rule_field_count": len(_FORBIDDEN_RULE_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(_PROHIBITED_ACTION_TOKENS),
        "caveats": list(_RULE_CAVEATS),
        "safety_flags": dict(_RULE_SAFETY_FLAGS),
    }


__all__ = [
    "ActionEffect",
    "EvaluationMode",
    "IssueSeverity",
    "RuleAction",
    "RuleCondition",
    "RuleDefinition",
    "RuleEngine",
    "RuleEngineOptions",
    "RuleEvaluationRequest",
    "RuleEvaluationResult",
    "RuleIssue",
    "RuleKind",
    "RuleMatch",
    "RuleRecordResult",
    "RuleRegistry",
    "RuleSeverity",
    "RuleStatus",
    "activate_rule",
    "block_rule",
    "dry_run_rules",
    "evaluate_rules",
    "get_rule",
    "get_rule_engine",
    "get_rule_registry",
    "get_rules_health",
    "get_rules_metadata",
    "list_rules",
    "register_rule",
    "retire_rule",
    "summarize_rules",
]