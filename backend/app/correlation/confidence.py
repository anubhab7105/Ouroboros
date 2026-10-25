"""
MULEGUARD backend correlation confidence.

This module provides the canonical bounded confidence-combination and
corroboration layer for the synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- combine bounded correlation evidence from multiple synthetic detectors,
  including exact-reference, identifier-match, entity-association,
  temporal-association, narrative-similarity, and generic detectors;
- produce deterministic, bounded, privacy-preserving confidence records for
  pseudonymous subject pairs or candidate groups;
- compute support, confidence, uncertainty, corroboration, conflict, and
  operational tier signals without claiming calibrated probabilities of guilt;
- enforce strict privacy by using salted one-way pseudonymous subject, pair,
  and candidate references, and by never retaining raw identifiers, raw
  narratives, raw feature values, subject-label pairs, secrets, tokens,
  passwords, database URLs, filesystem paths, or model artifact paths;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited correlation fields;
- provide safe summaries, issue reporting, fingerprints, and metadata suitable
  for local prototype workflows, tests, developer tooling, and offline
  evaluation harnesses;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module combines investigative correlation evidence only. It does not train
models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for confidence combination.
- Confidence records are investigative prioritization artefacts only. They are
  not proof of wrongdoing, common control, or criminal association.
- Confidence, support, uncertainty, and tier values are not probabilities of
  guilt.
- Labels must never be used as confidence features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden inputs. Subject, pair, and candidate linkage is
  pseudonymous and salted.
- Currency amounts are never converted or blended across currencies.
- Confidence handling must never trigger automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable confidence signals are reported honestly as
  unavailable rather than invented.
- This module does not claim statistical calibration.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external correlation engines or model runtimes.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models or correlation rules.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable decisioning platform.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, correlation
candidates, normalized records, extracted narrative features, confidence
records, explanations, validation reports, and case dispositions are
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
from dataclasses import dataclass, field as dataclass_field
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


logger = logging.getLogger("muleguard.backend.correlation.confidence")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

CONFIDENCE_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.correlation.confidence.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

DEFAULT_MAX_RECORDS: Final[int] = 10_000
HARD_MAX_RECORDS: Final[int] = 100_000

DEFAULT_MAX_CANDIDATES: Final[int] = 10_000
HARD_MAX_CANDIDATES: Final[int] = 100_000

DEFAULT_MAX_EVIDENCE_PER_GROUP: Final[int] = 50
HARD_MAX_EVIDENCE_PER_GROUP: Final[int] = 500

DEFAULT_MAX_GROUPS: Final[int] = 5_000
HARD_MAX_GROUPS: Final[int] = 50_000

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

DEFAULT_MAX_TIME_MS: Final[int] = 30_000
HARD_MAX_TIME_MS: Final[int] = 300_000

DEFAULT_MAX_REASON_TEXT_LENGTH: Final[int] = 200
HARD_MAX_REASON_TEXT_LENGTH: Final[int] = 500

DEFAULT_MIN_SUPPORT: Final[float] = 0.20
DEFAULT_CONFLICT_PENALTY: Final[float] = 0.35
DEFAULT_CORROBORATION_BONUS: Final[float] = 0.10
DEFAULT_UNCERTAINTY_FLOOR: Final[float] = 0.05

DEFAULT_LOW_THRESHOLD: Final[float] = 0.35
DEFAULT_MODERATE_THRESHOLD: Final[float] = 0.60
DEFAULT_ELEVATED_THRESHOLD: Final[float] = 0.80

MAX_TEXT_LENGTH: Final[int] = 512
MAX_HASH_LENGTH: Final[int] = 256

CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

_MISSING: Final[object] = object()

SUBJECT_KEYS: Final[tuple[str, ...]] = (
    "subject_ref_hash",
    "subject_hash",
    "subject",
    "account_id",
    "acct_id",
    "id",
    "complaint_id",
    "transaction_id",
    "entity_id",
    "alert_id",
    "case_id",
)

SOURCE_KEYS: Final[tuple[str, ...]] = (
    "source_ref_hash",
    "source_hash",
    "source",
    "source_account_id",
    "sender_account_id",
    "sender",
    "from_account_id",
    "from",
    "src",
)

TARGET_KEYS: Final[tuple[str, ...]] = (
    "target_ref_hash",
    "target_hash",
    "target",
    "target_account_id",
    "receiver_account_id",
    "receiver",
    "to_account_id",
    "to",
    "dst",
)

CANDIDATE_ID_KEYS: Final[tuple[str, ...]] = (
    "correlation_id",
    "candidate_id",
    "id",
    "extraction_id",
)

DETECTOR_KEYS: Final[tuple[str, ...]] = (
    "detector",
    "source_engine",
    "algorithm",
    "provider",
    "engine",
)

CATEGORY_KEYS: Final[tuple[str, ...]] = (
    "category",
    "record_category",
    "source_category",
    "target_category",
)

SCORE_KEYS: Final[tuple[str, ...]] = (
    "score",
    "confidence",
    "risk_score",
    "priority_score",
)

NON_FEATURE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "metadata",
        "metadata_json",
        "caveats",
        "safety_flags",
        "issues",
        "counts",
        "validation",
        "features",
        "values",
    }
)

FORBIDDEN_FIELDS: Final[frozenset[str]] = frozenset(
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

FORBIDDEN_TOKENS: Final[tuple[str, ...]] = (
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

LABEL_LEAKAGE_FIELDS: Final[frozenset[str]] = frozenset(
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

LABEL_LEAKAGE_TOKENS: Final[tuple[str, ...]] = (
    "ground_truth",
    "truth_label",
    "fraud_label",
    "is_fraud",
    "scenario_id",
    "ring_id",
    "fraud_ring",
    "synthetic_label",
)

SENSITIVE_DETAIL_TOKENS: Final[tuple[str, ...]] = (
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

PROHIBITED_ACTION_TOKENS: Final[tuple[str, ...]] = (
    "freeze",
    "frozen",
    "block",
    "blocked",
    "blacklist",
    "close_account",
    "restrict",
    "restricted",
    "deny_service",
    "terminate",
    "suspend_account",
    "punish",
    "penalize",
    "law_enforcement",
    "arrest",
    "prosecute",
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

CONFIDENCE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic correlation confidence combination only. Do not use with real customer data.",
    "Confidence records are investigative prioritization artefacts only and are not proof of wrongdoing.",
    "Confidence, support, uncertainty, and tier values are not probabilities of guilt.",
    "This module does not claim statistical calibration.",
    "Raw identifiers, raw narratives, and raw feature values are never retained.",
    "Subject, pair, and candidate linkage is salted and pseudonymous.",
    "Labels must never be used as confidence features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Confidence combination must not trigger automatic adverse customer action.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

CONFIDENCE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_raw_identifiers_retained": True,
        "no_raw_narratives_retained": True,
        "no_raw_feature_values_retained": True,
        "salted_pseudonymous_subject_references": True,
        "salted_pseudonymous_pair_references": True,
        "salted_pseudonymous_candidate_references": True,
        "no_labels_as_features": True,
        "no_ground_truth_fields_accepted": True,
        "no_fraud_label_fields_accepted": True,
        "no_scenario_ids_accepted": True,
        "no_fraud_ring_ids_accepted": True,
        "no_secrets_accepted": True,
        "no_tokens_accepted": True,
        "no_passwords_accepted": True,
        "no_database_urls_accepted": True,
        "no_model_artifact_paths_accepted": True,
        "deterministic_confidence_combination": True,
        "bounded_confidence_combination_required": True,
        "confidence_is_not_probability_of_guilt": True,
        "no_statistical_calibration_claim": True,
        "scores_are_investigative_priority_only": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)

_DEFAULT_DETECTOR_WEIGHTS: Final[Mapping[str, float]] = MappingProxyType(
    {
        "exact_reference": 0.90,
        "identifier_match": 0.70,
        "entity_association": 0.60,
        "temporal_association": 0.50,
        "narrative_similarity": 0.40,
        "generic": 0.30,
        "other": 0.20,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class DetectorKind(str, Enum):
    """
    Bounded correlation detector kind.
    """

    EXACT_REFERENCE = "exact_reference"
    IDENTIFIER_MATCH = "identifier_match"
    ENTITY_ASSOCIATION = "entity_association"
    TEMPORAL_ASSOCIATION = "temporal_association"
    NARRATIVE_SIMILARITY = "narrative_similarity"
    GENERIC = "generic"
    OTHER = "other"


class ConfidenceTier(str, Enum):
    """
    Bounded investigative confidence tier.

    Tiers are prioritization labels only. They are not probabilities of guilt.
    """

    LOW = "low"
    MODERATE = "moderate"
    ELEVATED = "elevated"
    HIGH = "high"
    UNSCORED = "unscoped"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class AnalysisStatus(str, Enum):
    """
    Overall confidence-analysis status.
    """

    PASSED = "PASSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


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

    text = str(value).strip().lower()

    if text in _TRUE_VALUES:
        return True

    if text in _FALSE_VALUES:
        return False

    return default


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return default


def _as_float(value: object, default: float = 0.0) -> float:
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return default

    if math.isnan(result) or math.isinf(result):
        return default

    return result


def _clamp_int(value: object, minimum: int, maximum: int, default: int) -> int:
    return max(minimum, min(_as_int(value, default), maximum))


def _clamp_float(value: object, minimum: float, maximum: float, default: float) -> float:
    parsed = _as_float(value, default)

    if math.isnan(parsed) or math.isinf(parsed):
        return default

    return max(minimum, min(maximum, parsed))


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


def _clean_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    text = _normalize_unicode(value)
    text = CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if limit <= 0:
        return ""

    return text[:limit] if len(text) > limit else text


def _normalize_token(value: Any) -> str:
    text = _normalize_unicode(value).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = SEPARATOR_RE.sub("_", text)
    text = MULTI_UNDERSCORE_RE.sub("_", text)
    return text.strip("_").lower()


def _canonical_field_name(key: Any) -> str:
    return _normalize_token(key)


def _is_safe_hash(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and HASH_RE.match(text))


def _is_forbidden_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in FORBIDDEN_FIELDS:
        return True

    if canonical.startswith("raw_") or canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in FORBIDDEN_TOKENS)


def _is_label_leakage_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in LABEL_LEAKAGE_FIELDS:
        return True

    return any(token in canonical for token in LABEL_LEAKAGE_TOKENS)


def _is_sensitive_detail_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)
    return bool(canonical) and any(token in canonical for token in SENSITIVE_DETAIL_TOKENS)


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
        return _clean_text(value, 300) or None

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

            if not key or _is_sensitive_detail_key(key) or _is_forbidden_key(key) or _is_label_leakage_key(key):
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:100]]

    return f"<{type(value).__name__}>"


def _as_mapping(value: Any) -> dict[str, Any]:
    sanitized = _safe_detail_value(value)
    return sanitized if isinstance(sanitized, dict) else {}


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
        return (1.0 if value else 0.0) if allow_bool else None

    if isinstance(value, (int, float)):
        result = float(value)
        return result if math.isfinite(result) else None

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
    return hmac.new(
        salt.encode("utf-8", errors="replace"),
        f"{domain}\x00{message}".encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()


def _ensure_salt(salt: Any) -> str:
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _pseudonymous_reference(value: Any, options: "ConfidenceOptions", domain_suffix: str) -> Optional[str]:
    text = _clean_text(value, MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.correlation.confidence.{domain_suffix}.{namespace}"
    return _hmac_hex(options.salt, domain, text)[:40]


def _pair_hash(
    left: str,
    right: str,
    options: ConfidenceOptions,
) -> str:
    ordered = tuple(sorted((left, right)))
    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.correlation.confidence.pair.{namespace}"
    return _hmac_hex(options.salt, domain, _canonical_json(list(ordered)))[:40]


def _fingerprint_payload(payload: Any) -> str:
    try:
        return _sha256_hex(_canonical_json(payload))
    except Exception:
        return _sha256_hex(str(_safe_detail_value(payload)))


def _time_exceeded(start_time: float, max_time_ms: int) -> bool:
    return (time.monotonic() - start_time) * 1000.0 > float(max(1, int(max_time_ms)))


def _elapsed_ms(start_time: float) -> int:
    return int((time.monotonic() - start_time) * 1000.0)


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
    return bool(text) and any(token in text for token in PROHIBITED_ACTION_TOKENS)


def _normalize_tags(value: Any, limit: int = 50) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        tag = _clean_text(item, 100)

        if tag:
            out.append(tag)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


def _pick(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]

    return None


def _sanitize_reasons(
    value: Any,
    options: ConfidenceOptions,
    issues: list["ConfidenceIssue"],
    details: Mapping[str, Any],
) -> tuple[str, ...]:
    out: list[str] = []
    filtered = 0

    for item in _as_sequence(value):
        reason = _clean_text(item, int(options.max_reason_text_length))

        if not reason:
            continue

        lowered = reason.lower()

        if any(token in lowered for token in PROHIBITED_ACTION_TOKENS):
            filtered += 1
            continue

        out.append(reason)

        if len(out) >= 50:
            break

    if filtered:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="prohibited_reason_filtered",
            message="Correlation reason contained prohibited adverse-action language and was filtered.",
            details={**dict(details), "filtered_count": filtered},
        )

    return tuple(dict.fromkeys(out))


def _append_issue(
    issues: list["ConfidenceIssue"],
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

        issues[-1] = ConfidenceIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        ConfidenceIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence["ConfidenceIssue"]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence["ConfidenceIssue"]) -> tuple["ConfidenceIssue", ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list["ConfidenceIssue"] = []

    for issue in issues:
        key = (
            _enum_value(issue.severity),
            issue.code,
            issue.message,
            issue.field,
        )

        if key in seen:
            continue

        seen.add(key)
        out.append(issue)

    return tuple(out)


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfidenceOptions:
    """
    Bounded correlation-confidence combination policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    max_records: int = DEFAULT_MAX_RECORDS
    max_candidates: int = DEFAULT_MAX_CANDIDATES
    max_evidence_per_group: int = DEFAULT_MAX_EVIDENCE_PER_GROUP
    max_groups: int = DEFAULT_MAX_GROUPS
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS
    max_reason_text_length: int = DEFAULT_MAX_REASON_TEXT_LENGTH

    min_support: float = DEFAULT_MIN_SUPPORT
    conflict_penalty: float = DEFAULT_CONFLICT_PENALTY
    corroboration_bonus: float = DEFAULT_CORROBORATION_BONUS
    uncertainty_floor: float = DEFAULT_UNCERTAINTY_FLOOR

    low_threshold: float = DEFAULT_LOW_THRESHOLD
    moderate_threshold: float = DEFAULT_MODERATE_THRESHOLD
    elevated_threshold: float = DEFAULT_ELEVATED_THRESHOLD

    weights: Mapping[str, float] = dataclass_field(default_factory=lambda: dict(_DEFAULT_DETECTOR_WEIGHTS))

    aggregate_by_pair: bool = True
    include_reasons: bool = True
    drop_forbidden_fields: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_token(self.dataset_mode) or "synthetic")
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(self, "salt", _ensure_salt(self.salt))
        object.__setattr__(self, "namespace", _normalize_token(self.namespace) or _DEFAULT_NAMESPACE)
        object.__setattr__(self, "seed", int(self.seed))

        object.__setattr__(
            self,
            "max_records",
            _clamp_int(self.max_records, 1, HARD_MAX_RECORDS, DEFAULT_MAX_RECORDS),
        )
        object.__setattr__(
            self,
            "max_candidates",
            _clamp_int(self.max_candidates, 1, HARD_MAX_CANDIDATES, DEFAULT_MAX_CANDIDATES),
        )
        object.__setattr__(
            self,
            "max_evidence_per_group",
            _clamp_int(
                self.max_evidence_per_group,
                1,
                HARD_MAX_EVIDENCE_PER_GROUP,
                DEFAULT_MAX_EVIDENCE_PER_GROUP,
            ),
        )
        object.__setattr__(
            self,
            "max_groups",
            _clamp_int(self.max_groups, 1, HARD_MAX_GROUPS, DEFAULT_MAX_GROUPS),
        )
        object.__setattr__(
            self,
            "max_issues",
            _clamp_int(self.max_issues, 1, HARD_MAX_ISSUES, DEFAULT_MAX_ISSUES),
        )
        object.__setattr__(
            self,
            "max_summary_items",
            _clamp_int(
                self.max_summary_items,
                1,
                HARD_MAX_SUMMARY_ITEMS,
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
        )
        object.__setattr__(
            self,
            "max_time_ms",
            _clamp_int(self.max_time_ms, 100, HARD_MAX_TIME_MS, DEFAULT_MAX_TIME_MS),
        )
        object.__setattr__(
            self,
            "max_reason_text_length",
            _clamp_int(
                self.max_reason_text_length,
                20,
                HARD_MAX_REASON_TEXT_LENGTH,
                DEFAULT_MAX_REASON_TEXT_LENGTH,
            ),
        )

        object.__setattr__(
            self,
            "min_support",
            _round6(_clamp_float(self.min_support, 0.0, 1.0, DEFAULT_MIN_SUPPORT)),
        )
        object.__setattr__(
            self,
            "conflict_penalty",
            _round6(_clamp_float(self.conflict_penalty, 0.0, 1.0, DEFAULT_CONFLICT_PENALTY)),
        )
        object.__setattr__(
            self,
            "corroboration_bonus",
            _round6(
                _clamp_float(
                    self.corroboration_bonus,
                    0.0,
                    0.50,
                    DEFAULT_CORROBORATION_BONUS,
                )
            ),
        )
        object.__setattr__(
            self,
            "uncertainty_floor",
            _round6(
                _clamp_float(
                    self.uncertainty_floor,
                    0.0,
                    0.50,
                    DEFAULT_UNCERTAINTY_FLOOR,
                )
            ),
        )

        low = _round6(_clamp_float(self.low_threshold, 0.0, 1.0, DEFAULT_LOW_THRESHOLD))
        moderate = _round6(_clamp_float(self.moderate_threshold, low, 1.0, DEFAULT_MODERATE_THRESHOLD))
        elevated = _round6(_clamp_float(self.elevated_threshold, moderate, 1.0, DEFAULT_ELEVATED_THRESHOLD))

        object.__setattr__(self, "low_threshold", low)
        object.__setattr__(self, "moderate_threshold", moderate)
        object.__setattr__(self, "elevated_threshold", elevated)

        normalized_weights: dict[str, float] = {}

        for kind in DetectorKind:
            default_weight = float(_DEFAULT_DETECTOR_WEIGHTS.get(kind.value, 0.20))
            supplied = self.weights.get(kind.value, default_weight) if isinstance(self.weights, Mapping) else default_weight
            normalized_weights[kind.value] = _round6(_clamp_float(supplied, 0.0, 1.0, default_weight))

        object.__setattr__(self, "weights", MappingProxyType(normalized_weights))

        object.__setattr__(self, "aggregate_by_pair", _as_bool(self.aggregate_by_pair, True))
        object.__setattr__(self, "include_reasons", _as_bool(self.include_reasons, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, True))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ConfidenceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "CORRELATION_CONFIDENCE_SALT", None)
            or _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_SALT", None)
            or _setting(settings, "CORRELATION_TEMPORAL_ASSOCIATION_SALT", None)
            or _setting(settings, "CORRELATION_ENTITY_ASSOCIATION_SALT", None)
            or _setting(settings, "CORRELATION_IDENTIFIER_MATCH_SALT", None)
            or _setting(settings, "CORRELATION_EXACT_REFERENCE_SALT", None)
            or _setting(settings, "CORRELATION_SALT", None)
            or _setting(settings, "CORRELATION_NORMALIZER_SALT", None)
            or _setting(settings, "GRAPH_CYCLE_SALT", None)
            or _setting(settings, "ML_VALIDATION_SALT", None)
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
            enabled=_as_bool(_setting(settings, "CORRELATION_CONFIDENCE_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "CORRELATION_CONFIDENCE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "CORRELATION_CONFIDENCE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "CORRELATION_CONFIDENCE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "CORRELATION_CONFIDENCE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_records=_as_int(
                _setting(settings, "CORRELATION_CONFIDENCE_MAX_RECORDS", DEFAULT_MAX_RECORDS),
                DEFAULT_MAX_RECORDS,
            ),
            max_candidates=_as_int(
                _setting(settings, "CORRELATION_CONFIDENCE_MAX_CANDIDATES", DEFAULT_MAX_CANDIDATES),
                DEFAULT_MAX_CANDIDATES,
            ),
            max_evidence_per_group=_as_int(
                _setting(
                    settings,
                    "CORRELATION_CONFIDENCE_MAX_EVIDENCE_PER_GROUP",
                    DEFAULT_MAX_EVIDENCE_PER_GROUP,
                ),
                DEFAULT_MAX_EVIDENCE_PER_GROUP,
            ),
            max_groups=_as_int(
                _setting(settings, "CORRELATION_CONFIDENCE_MAX_GROUPS", DEFAULT_MAX_GROUPS),
                DEFAULT_MAX_GROUPS,
            ),
            max_issues=_as_int(
                _setting(settings, "CORRELATION_CONFIDENCE_MAX_ISSUES", DEFAULT_MAX_ISSUES),
                DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(
                    settings,
                    "CORRELATION_CONFIDENCE_MAX_SUMMARY_ITEMS",
                    DEFAULT_MAX_SUMMARY_ITEMS,
                ),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "CORRELATION_CONFIDENCE_MAX_TIME_MS", DEFAULT_MAX_TIME_MS),
                DEFAULT_MAX_TIME_MS,
            ),
            max_reason_text_length=_as_int(
                _setting(
                    settings,
                    "CORRELATION_CONFIDENCE_MAX_REASON_TEXT_LENGTH",
                    DEFAULT_MAX_REASON_TEXT_LENGTH,
                ),
                DEFAULT_MAX_REASON_TEXT_LENGTH,
            ),
            min_support=_as_float(
                _setting(settings, "CORRELATION_CONFIDENCE_MIN_SUPPORT", DEFAULT_MIN_SUPPORT),
                DEFAULT_MIN_SUPPORT,
            ),
            conflict_penalty=_as_float(
                _setting(settings, "CORRELATION_CONFIDENCE_CONFLICT_PENALTY", DEFAULT_CONFLICT_PENALTY),
                DEFAULT_CONFLICT_PENALTY,
            ),
            corroboration_bonus=_as_float(
                _setting(settings, "CORRELATION_CONFIDENCE_CORROBORATION_BONUS", DEFAULT_CORROBORATION_BONUS),
                DEFAULT_CORROBORATION_BONUS,
            ),
            uncertainty_floor=_as_float(
                _setting(settings, "CORRELATION_CONFIDENCE_UNCERTAINTY_FLOOR", DEFAULT_UNCERTAINTY_FLOOR),
                DEFAULT_UNCERTAINTY_FLOOR,
            ),
            low_threshold=_as_float(
                _setting(settings, "CORRELATION_CONFIDENCE_LOW_THRESHOLD", DEFAULT_LOW_THRESHOLD),
                DEFAULT_LOW_THRESHOLD,
            ),
            moderate_threshold=_as_float(
                _setting(settings, "CORRELATION_CONFIDENCE_MODERATE_THRESHOLD", DEFAULT_MODERATE_THRESHOLD),
                DEFAULT_MODERATE_THRESHOLD,
            ),
            elevated_threshold=_as_float(
                _setting(settings, "CORRELATION_CONFIDENCE_ELEVATED_THRESHOLD", DEFAULT_ELEVATED_THRESHOLD),
                DEFAULT_ELEVATED_THRESHOLD,
            ),
            aggregate_by_pair=_as_bool(
                _setting(settings, "CORRELATION_CONFIDENCE_AGGREGATE_BY_PAIR", True),
                True,
            ),
            include_reasons=_as_bool(
                _setting(settings, "CORRELATION_CONFIDENCE_INCLUDE_REASONS", True),
                True,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "CORRELATION_CONFIDENCE_DROP_FORBIDDEN_FIELDS", True),
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
            "limits": {
                "max_records": self.max_records,
                "max_candidates": self.max_candidates,
                "max_evidence_per_group": self.max_evidence_per_group,
                "max_groups": self.max_groups,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
                "max_reason_text_length": self.max_reason_text_length,
            },
            "scoring": {
                "min_support": _round6(self.min_support),
                "conflict_penalty": _round6(self.conflict_penalty),
                "corroboration_bonus": _round6(self.corroboration_bonus),
                "uncertainty_floor": _round6(self.uncertainty_floor),
                "thresholds": {
                    "low": _round6(self.low_threshold),
                    "moderate": _round6(self.moderate_threshold),
                    "elevated": _round6(self.elevated_threshold),
                },
                "detector_weights": dict(self.weights),
            },
            "flags": {
                "aggregate_by_pair": self.aggregate_by_pair,
                "include_reasons": self.include_reasons,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "candidates",
        "results",
        "exact_reference",
        "identifier_match",
        "entity_association",
        "temporal_association",
        "narrative_similarity",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)

_CANDIDATE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "correlation_id",
        "candidate_id",
        "detector",
        "source_engine",
        "algorithm",
        "provider",
        "engine",
        "source_ref_hash",
        "target_ref_hash",
        "source",
        "target",
        "source_category",
        "target_category",
        "source_index",
        "target_index",
        "score",
        "confidence",
        "corroborated",
        "reasons",
        "reference_hash",
        "identifier_hash",
        "entity_hash",
        "temporal_delta_seconds",
    }
)


@dataclass(slots=True)
class ConfidenceRequest:
    """
    Bounded correlation-confidence request.
    """

    candidates: Any = None
    results: Any = None
    exact_reference: Any = None
    identifier_match: Any = None
    entity_association: Any = None
    temporal_association: Any = None
    narrative_similarity: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> ConfidenceRequest:
    if isinstance(request, ConfidenceRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(ConfidenceRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return ConfidenceRequest(**clean)
            except Exception:
                return ConfidenceRequest(candidates=payload.get("candidates", request))

        if any(key in payload for key in _CANDIDATE_KEYS):
            return ConfidenceRequest(candidates=[payload])

        return ConfidenceRequest(metadata=request)

    if isinstance(request, (list, tuple, set, frozenset)):
        return ConfidenceRequest(candidates=request)

    return ConfidenceRequest(candidates=request)


# -----------------------------------------------------------------------------
# Public models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfidenceIssue:
    """
    Safe confidence issue.
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
        object.__setattr__(self, "field", _clean_text(self.field, 200) or None)
        object.__setattr__(self, "details", _as_mapping(self.details))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "severity": _enum_value(self.severity, IssueSeverity.WARNING.value),
            "code": self.code,
            "message": self.message,
        }

        if self.field:
            payload["field"] = self.field

        if self.details:
            payload["details"] = self.details

        return payload


@dataclass(frozen=True, slots=True)
class ConfidenceEvidence:
    """
    One bounded evidence contribution inside a confidence record.
    """

    evidence_id: str = ""
    detector: DetectorKind | str = DetectorKind.GENERIC
    source_ref_hash: Optional[str] = None
    target_ref_hash: Optional[str] = None
    source_category: str = ""
    target_category: str = ""
    source_index: int = 0
    target_index: int = 0
    score: float = 0.0
    confidence: float = 0.0
    signal: float = 0.0
    corroborated: bool = False
    reasons: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "detector",
            _normalize_enum_option(DetectorKind, self.detector, DetectorKind.GENERIC),
        )
        object.__setattr__(
            self,
            "source_ref_hash",
            _clean_text(self.source_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(
            self,
            "target_ref_hash",
            _clean_text(self.target_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(self, "source_category", _normalize_token(self.source_category))
        object.__setattr__(self, "target_category", _normalize_token(self.target_category))
        object.__setattr__(self, "source_index", max(0, _as_int(self.source_index, 0)))
        object.__setattr__(self, "target_index", max(0, _as_int(self.target_index, 0)))
        object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "confidence", _round6(_clip_float(self.confidence, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "signal", _round6(_clip_float(self.signal, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "corroborated", _as_bool(self.corroborated, False))
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

        if not self.evidence_id:
            object.__setattr__(
                self,
                "evidence_id",
                _fingerprint_payload(
                    {
                        "detector": _enum_value(self.detector),
                        "source": self.source_ref_hash or f"{self.source_category}:{self.source_index}",
                        "target": self.target_ref_hash or f"{self.target_category}:{self.target_index}",
                        "signal": self.signal,
                    }
                )[:32],
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "detector": _enum_value(self.detector, DetectorKind.GENERIC.value),
            "source_ref_hash": self.source_ref_hash,
            "target_ref_hash": self.target_ref_hash,
            "source_category": self.source_category,
            "target_category": self.target_category,
            "source_index": int(self.source_index),
            "target_index": int(self.target_index),
            "score": float(self.score),
            "confidence": float(self.confidence),
            "signal": float(self.signal),
            "corroborated": bool(self.corroborated),
            "reasons": list(self.reasons),
            "metadata": _safe_detail_value(self.metadata),
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
        }


@dataclass(frozen=True, slots=True)
class ConfidenceRecord:
    """
    One bounded combined confidence record for a pseudonymous pair or candidate
    group.
    """

    pair_hash: str = ""
    source_ref_hash: Optional[str] = None
    target_ref_hash: Optional[str] = None
    source_category: str = ""
    target_category: str = ""
    support_score: float = 0.0
    confidence_score: float = 0.0
    uncertainty: float = 1.0
    evidence_count: int = 0
    corroborating_count: int = 0
    conflicting_count: int = 0
    detector_count: int = 0
    tier: ConfidenceTier | str = ConfidenceTier.UNSCORED
    primary_detector: DetectorKind | str = DetectorKind.GENERIC
    reasons: tuple[str, ...] = ()
    evidence: tuple[ConfidenceEvidence, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "pair_hash", _clean_text(self.pair_hash, MAX_HASH_LENGTH).lower())
        object.__setattr__(
            self,
            "source_ref_hash",
            _clean_text(self.source_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(
            self,
            "target_ref_hash",
            _clean_text(self.target_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(self, "source_category", _normalize_token(self.source_category))
        object.__setattr__(self, "target_category", _normalize_token(self.target_category))
        object.__setattr__(self, "support_score", _round6(_clip_float(self.support_score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "confidence_score", _round6(_clip_float(self.confidence_score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "uncertainty", _round6(_clip_float(self.uncertainty, 0.0, 1.0, 1.0)))
        object.__setattr__(self, "evidence_count", max(0, _as_int(self.evidence_count, 0)))
        object.__setattr__(self, "corroborating_count", max(0, _as_int(self.corroborating_count, 0)))
        object.__setattr__(self, "conflicting_count", max(0, _as_int(self.conflicting_count, 0)))
        object.__setattr__(self, "detector_count", max(0, _as_int(self.detector_count, 0)))
        object.__setattr__(
            self,
            "tier",
            _normalize_enum_option(ConfidenceTier, self.tier, ConfidenceTier.UNSCORED),
        )
        object.__setattr__(
            self,
            "primary_detector",
            _normalize_enum_option(DetectorKind, self.primary_detector, DetectorKind.GENERIC),
        )
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
        object.__setattr__(self, "evidence", tuple(self.evidence or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair_hash": self.pair_hash,
            "source_ref_hash": self.source_ref_hash,
            "target_ref_hash": self.target_ref_hash,
            "source_category": self.source_category,
            "target_category": self.target_category,
            "support_score": float(self.support_score),
            "confidence_score": float(self.confidence_score),
            "uncertainty": float(self.uncertainty),
            "evidence_count": int(self.evidence_count),
            "corroborating_count": int(self.corroborating_count),
            "conflicting_count": int(self.conflicting_count),
            "detector_count": int(self.detector_count),
            "tier": _enum_value(self.tier, ConfidenceTier.UNSCORED.value),
            "primary_detector": _enum_value(self.primary_detector, DetectorKind.GENERIC.value),
            "reasons": list(self.reasons),
            "evidence": [item.to_dict() for item in self.evidence],
            "metadata": _safe_detail_value(self.metadata),
            "confidence_semantics": "investigative_prioritization_only_not_probability_of_guilt",
            "calibration_claimed": False,
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "caveats": list(CONFIDENCE_CAVEATS),
            "safety_flags": dict(CONFIDENCE_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class ConfidenceResult:
    """
    Safe bounded confidence-analysis result.
    """

    ok: bool = True
    status: AnalysisStatus | str = AnalysisStatus.PASSED
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    records: tuple[ConfidenceRecord, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[ConfidenceIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(AnalysisStatus, self.status, AnalysisStatus.PASSED),
        )
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "records", tuple(self.records or ()))
        object.__setattr__(
            self,
            "counts",
            MappingProxyType(
                {str(key): max(0, _as_int(value, 0)) for key, value in (self.counts or {}).items()}
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
                        "version": CONFIDENCE_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, AnalysisStatus.PASSED.value),
                        "request_id": self.request_id,
                        "record_count": len(self.records),
                        "record_pair_hashes": [record.pair_hash for record in self.records[:64]],
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": _enum_value(self.status, AnalysisStatus.PASSED.value),
            "request_id": self.request_id,
            "generated_at": self.generated_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "records": [record.to_dict() for record in self.records],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(CONFIDENCE_CAVEATS),
            "safety_flags": dict(CONFIDENCE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Internal models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Evidence:
    detector: DetectorKind
    signal: float
    score: float
    confidence: float
    corroborated: bool
    source_ref_hash: Optional[str]
    target_ref_hash: Optional[str]
    source_category: str
    target_category: str
    source_index: int
    target_index: int
    candidate_ref_hash: Optional[str]
    reasons: tuple[str, ...]
    metadata: Mapping[str, Any]


@dataclass(slots=True)
class _Group:
    pair_hash: str
    source_ref_hash: Optional[str]
    target_ref_hash: Optional[str]
    source_category: str
    target_category: str
    evidence: list[_Evidence] = dataclass_field(default_factory=list)


# -----------------------------------------------------------------------------
# Record extraction
# -----------------------------------------------------------------------------


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, ConfidenceResult):
        return []

    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "candidates", "examples"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])

        return [data]

    for attr in ("candidates", "records", "rows", "items"):
        try:
            value = getattr(data, attr, None)
        except Exception:
            value = None

        if value is not None and not isinstance(value, Mapping):
            return _as_sequence(value)

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray, memoryview)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _looks_like_candidate_mapping(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False

    return any(key in value for key in _CANDIDATE_KEYS)


def _iter_source_records(source: Any) -> list[Any]:
    if source is None:
        return []

    if isinstance(source, Mapping) and not _looks_like_candidate_mapping(source):
        out: list[Any] = []

        for value in source.values():
            out.extend(_iter_records(value))

        return out

    return _iter_records(source)


def _extract_view(record: Any) -> dict[str, Any]:
    view: dict[str, Any] = {}

    if isinstance(record, Mapping):
        for raw_key, raw_value in record.items():
            key = _canonical_field_name(raw_key)

            if not key or key in NON_FEATURE_KEYS:
                continue

            view.setdefault(key, raw_value)

        for container in ("features", "values"):
            nested = record.get(container)

            if not isinstance(nested, Mapping):
                continue

            for raw_key, raw_value in nested.items():
                key = _canonical_field_name(raw_key)

                if key and key not in NON_FEATURE_KEYS:
                    view[key] = raw_value
    else:
        for key in (
            *CANDIDATE_ID_KEYS,
            *DETECTOR_KEYS,
            *SOURCE_KEYS,
            *TARGET_KEYS,
            *CATEGORY_KEYS,
            *SCORE_KEYS,
            "corroborated",
            "reasons",
            "reference_hash",
            "identifier_hash",
            "entity_hash",
            "temporal_delta_seconds",
            "source_index",
            "target_index",
        ):
            try:
                value = getattr(record, key, None)
            except Exception:
                continue

            if value is not None:
                view[key] = value

        nested = getattr(record, "features", None)

        if isinstance(nested, Mapping):
            for raw_key, raw_value in nested.items():
                key = _canonical_field_name(raw_key)

                if key and key not in NON_FEATURE_KEYS:
                    view[key] = raw_value

    return view


def _extract_metadata(record: Any) -> dict[str, Any]:
    if isinstance(record, Mapping):
        return _as_mapping(record.get("metadata"))

    return _as_mapping(getattr(record, "metadata", None))


def _infer_detector(view: Mapping[str, Any], metadata: Mapping[str, Any]) -> DetectorKind:
    explicit = _pick(view, DETECTOR_KEYS)

    if explicit is None:
        explicit = _pick(metadata, DETECTOR_KEYS)

    inferred = _normalize_enum_option(DetectorKind, explicit, None)

    if inferred is not None:
        return inferred

    if "reference_hash" in view or "reference_hash" in metadata:
        return DetectorKind.EXACT_REFERENCE

    if "identifier_hash" in view or "identifier_hash" in metadata:
        return DetectorKind.IDENTIFIER_MATCH

    if "entity_hash" in view or "entity_hash" in metadata:
        return DetectorKind.ENTITY_ASSOCIATION

    if "temporal_delta_seconds" in view or "temporal_delta_seconds" in metadata:
        return DetectorKind.TEMPORAL_ASSOCIATION

    if "token_hashes" in view or "narrative_similarity" in view or "narrative_similarity" in metadata:
        return DetectorKind.NARRATIVE_SIMILARITY

    return DetectorKind.GENERIC


def _normalize_unit_signal(value: Any) -> float:
    numeric = _coerce_optional_float(value, allow_bool=True)

    if numeric is None:
        return 0.0

    if numeric <= 1.0:
        return _round6(_clip_float(numeric, 0.0, 1.0, 0.0))

    if numeric <= 100.0:
        return _round6(_clip_float(numeric / 100.0, 0.0, 1.0, 0.0))

    return 1.0


def _identity_token(
    ref_hash: Optional[str],
    category: str,
    index: int,
    candidate_ref_hash: Optional[str],
) -> str:
    if ref_hash:
        return ref_hash

    return f"{category or 'unknown'}:{int(index)}:{candidate_ref_hash or 'anonymous'}"


# -----------------------------------------------------------------------------
# Sanitization
# -----------------------------------------------------------------------------


def _sanitize_candidate(
    record: Any,
    options: ConfidenceOptions,
    issues: list[ConfidenceIssue],
    index: int,
    start_time: float,
) -> Optional[_Evidence]:
    if _time_exceeded(start_time, options.max_time_ms):
        return None

    view = _extract_view(record)
    metadata = _extract_metadata(record)

    for raw_key in list(view) + list(metadata):
        canonical = _canonical_field_name(raw_key)

        if not canonical:
            continue

        if _is_forbidden_key(canonical) or _is_label_leakage_key(canonical):
            if options.drop_forbidden_fields:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="forbidden_confidence_field_dropped",
                    message="Forbidden or leakage-prone confidence field omitted.",
                    field=canonical,
                    details={"index": index},
                )
                view.pop(canonical, None)
                metadata.pop(canonical, None)
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_confidence_field",
                message="Forbidden or leakage-prone confidence field rejected.",
                field=canonical,
                details={"index": index},
            )
            return None

    detector = _infer_detector(view, metadata)

    source_raw = _pick(view, SOURCE_KEYS)
    target_raw = _pick(view, TARGET_KEYS)

    if source_raw is None:
        source_raw = metadata.get("source_ref_hash") or metadata.get("source")

    if target_raw is None:
        target_raw = metadata.get("target_ref_hash") or metadata.get("target")

    source_ref_hash = _pseudonymous_reference(source_raw, options, "source")
    target_ref_hash = _pseudonymous_reference(target_raw, options, "target")

    source_category = _normalize_token(
        _pick(view, ("source_category", "category"))
        or metadata.get("source_category")
        or ""
    )

    target_category = _normalize_token(
        _pick(view, ("target_category", "category"))
        or metadata.get("target_category")
        or ""
    )

    source_index = max(0, _as_int(_pick(view, ("source_index", "index")) or metadata.get("source_index"), index))
    target_index = max(0, _as_int(_pick(view, ("target_index",)) or metadata.get("target_index"), 0))

    candidate_id = _pick(view, CANDIDATE_ID_KEYS) or metadata.get("correlation_id") or metadata.get("candidate_id")
    candidate_ref_hash = _pseudonymous_reference(candidate_id, options, "candidate")

    raw_score = _pick(view, SCORE_KEYS)
    raw_confidence = view.get("confidence")

    if raw_confidence is None:
        raw_confidence = metadata.get("confidence")

    score = _normalize_unit_signal(raw_score)
    confidence = _normalize_unit_signal(raw_confidence)

    if confidence == 0.0 and score > 0.0:
        confidence = score

    if score == 0.0 and confidence > 0.0:
        score = confidence

    signal = _round6(0.65 * score + 0.35 * confidence)

    corroborated = _as_bool(
        _pick(view, ("corroborated",)) or metadata.get("corroborated"),
        False,
    )

    reasons = _sanitize_reasons(
        _pick(view, ("reasons",)) or metadata.get("reasons") or (),
        options,
        issues,
        {"index": index, "detector": detector.value},
    )

    safe_metadata = _as_mapping(metadata)
    safe_metadata.pop("reasons", None)
    safe_metadata.pop("score", None)
    safe_metadata.pop("confidence", None)
    safe_metadata.pop("corroborated", None)

    safe_metadata.update(
        {
            "detector": detector.value,
            "signal": signal,
            "score": score,
            "confidence": confidence,
            "corroborated": corroborated,
            "candidate_ref_hash": candidate_ref_hash,
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "monetary_conversion_performed": False,
        }
    )

    if signal <= 0.0 and not reasons:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="zero_signal_confidence_evidence",
            message="Confidence evidence had zero normalized signal and was retained only for auditability.",
            details={"index": index, "detector": detector.value},
        )

    return _Evidence(
        detector=detector,
        signal=signal,
        score=score,
        confidence=confidence,
        corroborated=corroborated,
        source_ref_hash=source_ref_hash,
        target_ref_hash=target_ref_hash,
        source_category=source_category,
        target_category=target_category,
        source_index=source_index,
        target_index=target_index,
        candidate_ref_hash=candidate_ref_hash,
        reasons=reasons,
        metadata=MappingProxyType(safe_metadata),
    )


# -----------------------------------------------------------------------------
# Grouping and scoring
# -----------------------------------------------------------------------------


def _group_key(evidence: _Evidence, options: ConfidenceOptions) -> tuple[str, Optional[str], Optional[str], str, str]:
    source_identity = _identity_token(
        evidence.source_ref_hash,
        evidence.source_category,
        evidence.source_index,
        evidence.candidate_ref_hash,
    )

    target_identity = _identity_token(
        evidence.target_ref_hash,
        evidence.target_category,
        evidence.target_index,
        evidence.candidate_ref_hash,
    )

    if not options.aggregate_by_pair:
        pair = evidence.candidate_ref_hash or _fingerprint_payload(
            {
                "source": source_identity,
                "target": target_identity,
                "detector": evidence.detector.value,
            }
        )[:40]
        return (pair, evidence.source_ref_hash, evidence.target_ref_hash, evidence.source_category, evidence.target_category)

    pair = _pair_hash(source_identity, target_identity, options)
    return (pair, evidence.source_ref_hash, evidence.target_ref_hash, evidence.source_category, evidence.target_category)


def _evidence_sort_key(evidence: _Evidence) -> tuple[float, str, str, str, str, int, int]:
    return (
        -float(evidence.signal),
        evidence.detector.value,
        evidence.source_category,
        evidence.target_category,
        evidence.candidate_ref_hash or "",
        int(evidence.source_index),
        int(evidence.target_index),
    )


def _tier_for_confidence(confidence: float, options: ConfidenceOptions) -> ConfidenceTier:
    if confidence <= 0.0:
        return ConfidenceTier.UNSCORED

    if confidence >= float(options.elevated_threshold):
        return ConfidenceTier.HIGH

    if confidence >= float(options.moderate_threshold):
        return ConfidenceTier.ELEVATED

    if confidence >= float(options.low_threshold):
        return ConfidenceTier.MODERATE

    return ConfidenceTier.LOW


def _combine_evidence(
    group: _Group,
    options: ConfidenceOptions,
) -> ConfidenceRecord:
    evidences = sorted(group.evidence, key=_evidence_sort_key)
    capped = evidences[: int(options.max_evidence_per_group)]

    if not capped:
        return ConfidenceRecord(
            pair_hash=group.pair_hash,
            source_ref_hash=group.source_ref_hash,
            target_ref_hash=group.target_ref_hash,
            source_category=group.source_category,
            target_category=group.target_category,
            support_score=0.0,
            confidence_score=0.0,
            uncertainty=1.0,
            evidence_count=0,
            corroborating_count=0,
            conflicting_count=0,
            detector_count=0,
            tier=ConfidenceTier.UNSCORED,
            primary_detector=DetectorKind.GENERIC,
            reasons=("no_evidence_available", "operational_lead_only_not_proof"),
            evidence=(),
            metadata={
                "confidence_semantics": "investigative_prioritization_only",
                "calibration_claimed": False,
                "raw_identifiers_retained": False,
                "raw_narratives_retained": False,
            },
        )

    weights: list[float] = []
    signals: list[float] = []
    detector_counter: Counter[str] = Counter()
    corroborating_count = 0
    weak_count = 0

    for evidence in capped:
        weight = float(options.weights.get(evidence.detector.value, 0.20))
        signal = float(evidence.signal)

        weights.append(weight)
        signals.append(signal)
        detector_counter[evidence.detector.value] += 1

        if evidence.corroborated or signal >= float(options.min_support):
            corroborating_count += 1

        if signal < float(options.min_support):
            weak_count += 1

    total_weight = sum(weights)
    weighted_mean = (sum(w * s for w, s in zip(weights, signals)) / total_weight) if total_weight > 0 else 0.0

    noisy = 1.0
    for w, s in zip(weights, signals):
        noisy *= 1.0 - _clip_float(w * s, 0.0, 1.0, 0.0)

    noisy = _clip_float(1.0 - noisy, 0.0, 1.0, 0.0)

    variance = (
        sum(w * ((s - weighted_mean) ** 2) for w, s in zip(weights, signals)) / total_weight
        if total_weight > 0
        else 0.0
    )

    std_dev = math.sqrt(max(0.0, variance))
    agreement = _clip_float(1.0 - min(1.0, std_dev * 1.5), 0.0, 1.0, 0.0)

    conflict_ratio = weak_count / float(len(capped)) if capped else 0.0
    conflict = _clip_float(
        0.50 * conflict_ratio + 0.50 * min(1.0, std_dev * 1.75),
        0.0,
        1.0,
        0.0,
    )

    corroboration = _clip_float((len(capped) - 1) / 3.0, 0.0, 1.0, 0.0)

    support = _clip_float(
        0.55 * noisy + 0.25 * weighted_mean + 0.20 * agreement,
        0.0,
        1.0,
        0.0,
    )

    confidence = _clip_float(
        support * (1.0 - float(options.conflict_penalty) * conflict)
        + float(options.corroboration_bonus) * corroboration * (1.0 - support),
        0.0,
        1.0,
        0.0,
    )

    evidence_strength = _clip_float(total_weight / max(1.0, float(len(capped)) * 0.75), 0.0, 1.0, 0.0)
    uncertainty = _clip_float(
        1.0 - (0.55 * evidence_strength + 0.45 * agreement),
        float(options.uncertainty_floor),
        1.0,
        1.0,
    )

    primary_detector = DetectorKind.GENERIC
    best_weighted_signal = -1.0

    for evidence in capped:
        weight = float(options.weights.get(evidence.detector.value, 0.20))
        candidate_score = weight * float(evidence.signal)

        if candidate_score > best_weighted_signal:
            best_weighted_signal = candidate_score
            primary_detector = evidence.detector

    tier = _tier_for_confidence(confidence, options)

    reasons: list[str] = [
        "combined_correlation_evidence",
        f"evidence_count_{len(capped)}",
        f"detector_count_{len(detector_counter)}",
        f"primary_detector_{primary_detector.value}",
        "operational_lead_only_not_proof",
        "synthetic_bounded_confidence_only",
    ]

    if corroborating_count:
        reasons.append(f"corroborating_evidence_{corroborating_count}")

    if weak_count:
        reasons.append(f"weak_evidence_{weak_count}")

    if conflict >= 0.35:
        reasons.append("evidence_conflict_detected")

    if len(capped) == 1:
        reasons.append("single_source_evidence")

    if len(detector_counter) <= 1 and len(capped) > 1:
        reasons.append("same_detector_repetition_only")

    if uncertainty >= 0.75:
        reasons.append("high_uncertainty")

    if confidence >= float(options.elevated_threshold):
        reasons.append("elevated_investigative_priority")

    public_evidence: list[ConfidenceEvidence] = []

    for idx, evidence in enumerate(capped):
        public_evidence.append(
            ConfidenceEvidence(
                evidence_id=_fingerprint_payload(
                    {
                        "pair_hash": group.pair_hash,
                        "index": idx,
                        "detector": evidence.detector.value,
                        "candidate": evidence.candidate_ref_hash or "",
                        "signal": evidence.signal,
                    }
                )[:32],
                detector=evidence.detector,
                source_ref_hash=evidence.source_ref_hash,
                target_ref_hash=evidence.target_ref_hash,
                source_category=evidence.source_category,
                target_category=evidence.target_category,
                source_index=evidence.source_index,
                target_index=evidence.target_index,
                score=evidence.score,
                confidence=evidence.confidence,
                signal=evidence.signal,
                corroborated=evidence.corroborated,
                reasons=evidence.reasons if options.include_reasons else (),
                metadata=evidence.metadata,
            )
        )

    metadata = {
        "confidence_version": CONFIDENCE_VERSION,
        "pair_hash": group.pair_hash,
        "support_score": _round6(support),
        "confidence_score": _round6(confidence),
        "uncertainty": _round6(uncertainty),
        "weighted_mean_signal": _round6(weighted_mean),
        "noisy_or_support": _round6(noisy),
        "agreement": _round6(agreement),
        "conflict": _round6(conflict),
        "corroboration": _round6(corroboration),
        "detector_counts": dict(detector_counter),
        "confidence_semantics": "investigative_prioritization_only_not_probability_of_guilt",
        "calibration_claimed": False,
        "raw_identifiers_retained": False,
        "raw_narratives_retained": False,
        "monetary_conversion_performed": False,
    }

    return ConfidenceRecord(
        pair_hash=group.pair_hash,
        source_ref_hash=group.source_ref_hash,
        target_ref_hash=group.target_ref_hash,
        source_category=group.source_category,
        target_category=group.target_category,
        support_score=support,
        confidence_score=confidence,
        uncertainty=uncertainty,
        evidence_count=len(capped),
        corroborating_count=corroborating_count,
        conflicting_count=weak_count,
        detector_count=len(detector_counter),
        tier=tier,
        primary_detector=primary_detector,
        reasons=tuple(reasons) if options.include_reasons else (),
        evidence=tuple(public_evidence),
        metadata=metadata,
    )


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------


class ConfidenceEngine:
    """
    Bounded deterministic synthetic correlation-confidence engine.

    This engine combines investigative correlation evidence only. It does not
    authorize actions, deploy models, persist durable artifacts, or take adverse
    action.
    """

    def __init__(self, options: ConfidenceOptions | None = None) -> None:
        self.options = options or ConfidenceOptions.from_settings()
        self._lock = threading.RLock()

    def analyze(self, request: Any) -> ConfidenceResult:
        """
        Run one bounded synthetic confidence-combination job.
        """
        opts = self.options
        issues: list[ConfidenceIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)

        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": CONFIDENCE_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: AnalysisStatus,
            records: Sequence[ConfidenceRecord] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> ConfidenceResult:
            resolved_counts: dict[str, int] = {
                "submitted": 0,
                "sanitized": 0,
                "groups": 0,
                "records": len(records),
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update(
                    {str(key): max(0, _as_int(value, 0)) for key, value in counts.items()}
                )

            resolved_counts["issues"] = len(issues)
            resolved_counts["records"] = len(records)

            metadata = {
                "confidence_version": CONFIDENCE_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_identifiers_retained": False,
                "raw_narratives_retained": False,
                "subject_label_pairs_retained": False,
                "secrets_retained": False,
                "monetary_conversion_performed": False,
                "calibration_claimed": False,
                "caveats": list(CONFIDENCE_CAVEATS),
                "safety_flags": dict(CONFIDENCE_SAFETY_FLAGS),
            }

            return ConfidenceResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                records=tuple(records),
                counts=resolved_counts,
                issues=_dedupe_issues(issues)[: opts.max_issues],
                metadata=metadata,
                fingerprint="",
            )

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="confidence_engine_disabled",
                message="Confidence engine is disabled.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Confidence engine requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Confidence engine is blocked in production-like environments.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_confidence_action_metadata",
                message="Confidence request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        with self._lock:
            sources: tuple[Any, ...] = (
                req.candidates,
                req.results,
                req.exact_reference,
                req.identifier_match,
                req.entity_association,
                req.temporal_association,
                req.narrative_similarity,
            )

            raw_records: list[Any] = []

            for source in sources:
                raw_records.extend(_iter_source_records(source))

            submitted = len(raw_records)

            if submitted > int(opts.max_candidates):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="confidence_input_truncated",
                    message="Confidence input exceeded configured candidate limit and was truncated.",
                    details={
                        "submitted": submitted,
                        "max_candidates": int(opts.max_candidates),
                    },
                )
                raw_records = raw_records[: int(opts.max_candidates)]

            groups: dict[str, _Group] = {}
            sanitized = 0

            for index, record in enumerate(raw_records):
                if _time_exceeded(start_time, opts.max_time_ms):
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="confidence_sanitization_time_budget_exhausted",
                        message="Confidence sanitization stopped after reaching configured time budget.",
                        details={
                            "processed": sanitized,
                            "remaining": max(0, len(raw_records) - index),
                        },
                    )
                    break

                evidence = _sanitize_candidate(record, opts, issues, index, start_time)

                if evidence is None:
                    continue

                sanitized += 1

                key_tuple = _group_key(evidence, opts)
                pair_hash = key_tuple[0]

                group = groups.get(pair_hash)

                if group is None:
                    group = _Group(
                        pair_hash=pair_hash,
                        source_ref_hash=key_tuple[1],
                        target_ref_hash=key_tuple[2],
                        source_category=key_tuple[3],
                        target_category=key_tuple[4],
                    )
                    groups[pair_hash] = group

                if len(group.evidence) >= int(opts.max_evidence_per_group):
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="confidence_group_evidence_truncated",
                        message="Confidence group evidence exceeded configured per-group limit.",
                        details={"pair_hash": pair_hash, "max_evidence_per_group": int(opts.max_evidence_per_group)},
                    )
                    continue

                group.evidence.append(evidence)

            if len(groups) > int(opts.max_groups):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="confidence_group_limit_truncated",
                    message="Confidence groups exceeded configured group limit and were truncated.",
                    details={
                        "groups": len(groups),
                        "max_groups": int(opts.max_groups),
                    },
                )

            records: list[ConfidenceRecord] = []

            for pair_hash in sorted(groups):
                if _time_exceeded(start_time, opts.max_time_ms):
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="confidence_scoring_time_budget_exhausted",
                        message="Confidence scoring stopped after reaching configured time budget.",
                    )
                    break

                records.append(_combine_evidence(groups[pair_hash], opts))

            if len(records) > int(opts.max_groups):
                records.sort(
                    key=lambda record: (
                        -float(record.confidence_score),
                        -float(record.support_score),
                        record.pair_hash,
                    )
                )
                records = records[: int(opts.max_groups)]

            records.sort(
                key=lambda record: (
                    -float(record.confidence_score),
                    -float(record.support_score),
                    float(record.uncertainty),
                    record.tier.value,
                    record.pair_hash,
                )
            )

            detector_counts: Counter[str] = Counter()
            tier_counts: Counter[str] = Counter()
            corroborating_groups = 0
            conflicting_groups = 0

            for record in records:
                tier_counts[record.tier.value] += 1

                for item in record.evidence:
                    detector_counts[item.detector.value] += 1

                if record.corroborating_count:
                    corroborating_groups += 1

                if record.conflicting_count:
                    conflicting_groups += 1

            counts = {
                "submitted": submitted,
                "sanitized": sanitized,
                "groups": len(groups),
                "records": len(records),
                "evidence_total": sum(record.evidence_count for record in records),
                "corroborating_groups": corroborating_groups,
                "conflicting_groups": conflicting_groups,
                "detector_exact_reference": detector_counts.get(DetectorKind.EXACT_REFERENCE.value, 0),
                "detector_identifier_match": detector_counts.get(DetectorKind.IDENTIFIER_MATCH.value, 0),
                "detector_entity_association": detector_counts.get(DetectorKind.ENTITY_ASSOCIATION.value, 0),
                "detector_temporal_association": detector_counts.get(DetectorKind.TEMPORAL_ASSOCIATION.value, 0),
                "detector_narrative_similarity": detector_counts.get(DetectorKind.NARRATIVE_SIMILARITY.value, 0),
                "detector_generic": detector_counts.get(DetectorKind.GENERIC.value, 0),
                "tier_low": tier_counts.get(ConfidenceTier.LOW.value, 0),
                "tier_moderate": tier_counts.get(ConfidenceTier.MODERATE.value, 0),
                "tier_elevated": tier_counts.get(ConfidenceTier.ELEVATED.value, 0),
                "tier_high": tier_counts.get(ConfidenceTier.HIGH.value, 0),
                "tier_unscoped": tier_counts.get(ConfidenceTier.UNSCORED.value, 0),
            }

            status = AnalysisStatus.PASSED

            if _has_error(issues):
                status = AnalysisStatus.FAILED
            elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
                status = AnalysisStatus.DEGRADED
            elif not records:
                status = AnalysisStatus.SKIPPED

            return make_result(
                ok=status in {AnalysisStatus.PASSED, AnalysisStatus.DEGRADED},
                status=status,
                records=records,
                counts=counts,
            )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "caveats": list(CONFIDENCE_CAVEATS),
            "safety_flags": dict(CONFIDENCE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default engine and public API
# -----------------------------------------------------------------------------


_default_engine: Optional[ConfidenceEngine] = None
_default_engine_lock = threading.Lock()


def get_confidence_options(settings: Any | None = None) -> ConfidenceOptions:
    """
    Return confidence options from settings.
    """
    return ConfidenceOptions.from_settings(settings)


def get_confidence_engine(
    options: ConfidenceOptions | None = None,
    *,
    rebuild: bool = False,
) -> ConfidenceEngine:
    """
    Return a process-wide confidence engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = ConfidenceEngine(options=options or ConfidenceOptions.from_settings())

        return _default_engine


def score_confidence(
    request: Any,
    options: ConfidenceOptions | None = None,
    *,
    engine: ConfidenceEngine | None = None,
) -> ConfidenceResult:
    """
    Combine bounded synthetic correlation evidence into confidence records.
    """
    active_engine = engine or get_confidence_engine(options)
    return active_engine.analyze(request)


def combine_correlation_confidence(
    request: Any,
    options: ConfidenceOptions | None = None,
    *,
    engine: ConfidenceEngine | None = None,
) -> ConfidenceResult:
    """
    Alias for `score_confidence`.
    """
    return score_confidence(request, options=options, engine=engine)


def export_confidence_summary(result: ConfidenceResult) -> dict[str, Any]:
    """
    Export a safe public confidence summary.
    """
    return result.to_dict()


def get_confidence_health(*, engine: ConfidenceEngine | None = None) -> dict[str, Any]:
    """
    Return safe confidence-engine health.
    """
    active_engine = engine or get_confidence_engine()
    opts = active_engine.options
    issues: list[ConfidenceIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="confidence_engine_disabled",
            message="Confidence engine is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Confidence engine requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Confidence engine is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(CONFIDENCE_CAVEATS),
        "safety_flags": dict(CONFIDENCE_SAFETY_FLAGS),
    }


def get_confidence_metadata(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
) -> dict[str, Any]:
    """
    Return safe, serializable confidence-engine metadata.

    This is useful for startup logs, diagnostic endpoints, tests, developer
    tooling, and architecture documentation checks.

    It must not expose raw identifiers, raw narratives, secrets, environment
    files, database URLs, tokens, passwords, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, or real customer data.
    """
    options = ConfidenceOptions.from_settings()

    return {
        "package": "muleguard.backend.correlation.confidence",
        "version": CONFIDENCE_VERSION,
        "detector_kinds": [kind.value for kind in DetectorKind],
        "confidence_tiers": [tier.value for tier in ConfidenceTier],
        "analysis_statuses": [status.value for status in AnalysisStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "hard_limits": {
            "max_records": HARD_MAX_RECORDS,
            "max_candidates": HARD_MAX_CANDIDATES,
            "max_evidence_per_group": HARD_MAX_EVIDENCE_PER_GROUP,
            "max_groups": HARD_MAX_GROUPS,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
            "max_reason_text_length": HARD_MAX_REASON_TEXT_LENGTH,
        },
        "forbidden_field_count": len(FORBIDDEN_FIELDS),
        "label_leakage_field_count": len(LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(PROHIBITED_ACTION_TOKENS),
        "summary_item_limit": max(1, int(limit)),
        "caveats": list(CONFIDENCE_CAVEATS),
        "safety_flags": dict(CONFIDENCE_SAFETY_FLAGS),
    }


__all__ = [
    "AnalysisStatus",
    "CONFIDENCE_VERSION",
    "ConfidenceEngine",
    "ConfidenceEvidence",
    "ConfidenceIssue",
    "ConfidenceOptions",
    "ConfidenceRecord",
    "ConfidenceRequest",
    "ConfidenceResult",
    "ConfidenceTier",
    "DetectorKind",
    "IssueSeverity",
    "combine_correlation_confidence",
    "export_confidence_summary",
    "get_confidence_engine",
    "get_confidence_health",
    "get_confidence_metadata",
    "get_confidence_options",
    "score_confidence",
]