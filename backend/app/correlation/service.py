"""
MULEGUARD backend correlation service.

This module provides the canonical bounded correlation service orchestrator for
the synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- orchestrate the bounded synthetic correlation pipeline across normalization,
  exact-reference matching, identifier matching, entity association, temporal
  association, narrative structural extraction, and confidence combination;
- provide a single deterministic, API-safe service entrypoint for local
  prototype workflows, tests, developer tooling, and offline evaluation
  harnesses;
- preserve privacy by using salted one-way pseudonymous references and by
  excluding raw feature values, raw identifiers, raw narratives, subject-label
  pairs, secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited correlation fields;
- report unavailable components honestly rather than inventing results;
- maintain a bounded process-local service cache for idempotent local prototype
  workflows;
- remain import-safe, dependency-light, and resilient when optional correlation
  submodules are unavailable.

This module orchestrates investigative correlation workflows only. It does not
train models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for correlation orchestration.
- Correlation service outputs are investigative leads only. They are not proof
  of wrongdoing, common control, or criminal association.
- Confidence, support, uncertainty, and tier values are not probabilities of
  guilt.
- Labels must never be used as correlation features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as correlation inputs.
- Raw complaint narratives are forbidden inputs to non-narrative components and
  are never retained, logged, or returned.
- Raw identifiers are forbidden outputs. Subject, pair, and candidate linkage is
  pseudonymous and salted.
- Currency amounts are never converted or blended across currencies.
- Correlation orchestration must never trigger automatic adverse customer action
  such as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable correlations are reported honestly as unavailable
  rather than invented.
- The bundled service cache is process-local, non-durable, and bounded for local
  prototype use only.
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
records, service summaries, explanations, validation reports, and case
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
from collections import Counter, OrderedDict, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timedelta, timezone
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


logger = logging.getLogger("muleguard.backend.correlation.service")


# -----------------------------------------------------------------------------
# Optional correlation component imports
# -----------------------------------------------------------------------------

_NORMALIZE_IMPL: Optional[Any] = None
_EXACT_REFERENCE_IMPL: Optional[Any] = None
_IDENTIFIER_MATCH_IMPL: Optional[Any] = None
_ENTITY_ASSOCIATION_IMPL: Optional[Any] = None
_TEMPORAL_ASSOCIATION_IMPL: Optional[Any] = None
_NARRATIVE_EXTRACTION_IMPL: Optional[Any] = None
_CONFIDENCE_IMPL: Optional[Any] = None

try:
    from app.correlation.normalizers import normalize_correlation_request as _NORMALIZE_IMPL
except Exception:
    try:
        from .normalizers import normalize_correlation_request as _NORMALIZE_IMPL
    except Exception:
        _NORMALIZE_IMPL = None

try:
    from app.correlation.exact_reference import correlate_exact_references as _EXACT_REFERENCE_IMPL
except Exception:
    try:
        from .exact_reference import correlate_exact_references as _EXACT_REFERENCE_IMPL
    except Exception:
        _EXACT_REFERENCE_IMPL = None

try:
    from app.correlation.identifier_match import correlate_identifier_matches as _IDENTIFIER_MATCH_IMPL
except Exception:
    try:
        from .identifier_match import correlate_identifier_matches as _IDENTIFIER_MATCH_IMPL
    except Exception:
        _IDENTIFIER_MATCH_IMPL = None

try:
    from app.correlation.entity_association import correlate_entity_associations as _ENTITY_ASSOCIATION_IMPL
except Exception:
    try:
        from .entity_association import correlate_entity_associations as _ENTITY_ASSOCIATION_IMPL
    except Exception:
        _ENTITY_ASSOCIATION_IMPL = None

try:
    from app.correlation.temporal_association import correlate_temporal_associations as _TEMPORAL_ASSOCIATION_IMPL
except Exception:
    try:
        from .temporal_association import correlate_temporal_associations as _TEMPORAL_ASSOCIATION_IMPL
    except Exception:
        _TEMPORAL_ASSOCIATION_IMPL = None

try:
    from app.correlation.narrative_extraction import extract_narratives as _NARRATIVE_EXTRACTION_IMPL
except Exception:
    try:
        from .narrative_extraction import extract_narratives as _NARRATIVE_EXTRACTION_IMPL
    except Exception:
        _NARRATIVE_EXTRACTION_IMPL = None

try:
    from app.correlation.confidence import score_confidence as _CONFIDENCE_IMPL
except Exception:
    try:
        from .confidence import score_confidence as _CONFIDENCE_IMPL
    except Exception:
        _CONFIDENCE_IMPL = None


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

SERVICE_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.correlation.service.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

DEFAULT_MAX_RECORDS: Final[int] = 10_000
HARD_MAX_RECORDS: Final[int] = 100_000

DEFAULT_MAX_CANDIDATES: Final[int] = 5_000
HARD_MAX_CANDIDATES: Final[int] = 100_000

DEFAULT_MAX_CONFIDENCE_RECORDS: Final[int] = 1_000
HARD_MAX_CONFIDENCE_RECORDS: Final[int] = 20_000

DEFAULT_MAX_SAMPLE_CANDIDATES: Final[int] = 25
HARD_MAX_SAMPLE_CANDIDATES: Final[int] = 200

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

DEFAULT_MAX_TIME_MS: Final[int] = 60_000
HARD_MAX_TIME_MS: Final[int] = 600_000

DEFAULT_MAX_CACHE_ENTRIES: Final[int] = 64
HARD_MAX_CACHE_ENTRIES: Final[int] = 10_000

DEFAULT_CACHE_TTL_SECONDS: Final[int] = 300
HARD_MAX_CACHE_TTL_SECONDS: Final[int] = 86_400

MAX_TEXT_LENGTH: Final[int] = 512
MAX_HASH_LENGTH: Final[int] = 256
MAX_REASON_TEXT_LENGTH: Final[int] = 200

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

NARRATIVE_KEYS: Final[tuple[str, ...]] = (
    "narrative",
    "narrative_raw",
    "narrative_normalized",
    "description",
    "details",
    "notes",
    "summary",
    "text",
    "content",
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

SERVICE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic correlation service orchestration only. Do not use with real customer data.",
    "Correlation service outputs are investigative leads only and are not proof of wrongdoing.",
    "Confidence, support, uncertainty, and tier values are not probabilities of guilt.",
    "Raw identifiers, raw narratives, and raw feature values are never retained in public summaries.",
    "Subject, pair, and candidate linkage is salted and pseudonymous.",
    "Labels must never be used as correlation features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Unavailable components are reported honestly rather than invented.",
    "Correlation orchestration must not trigger automatic adverse customer action.",
    "The bundled service cache is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

SERVICE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_raw_identifiers_retained": True,
        "no_raw_narratives_retained": True,
        "no_raw_feature_values_retained": True,
        "salted_pseudonymous_references": True,
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
        "deterministic_correlation_service": True,
        "bounded_correlation_service_required": True,
        "confidence_is_not_probability_of_guilt": True,
        "no_statistical_calibration_claim": True,
        "scores_are_investigative_priority_only": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)

COMPONENT_NORMALIZER: Final[str] = "normalizer"
COMPONENT_EXACT_REFERENCE: Final[str] = "exact_reference"
COMPONENT_IDENTIFIER_MATCH: Final[str] = "identifier_match"
COMPONENT_ENTITY_ASSOCIATION: Final[str] = "entity_association"
COMPONENT_TEMPORAL_ASSOCIATION: Final[str] = "temporal_association"
COMPONENT_NARRATIVE_EXTRACTION: Final[str] = "narrative_extraction"
COMPONENT_CONFIDENCE: Final[str] = "confidence"

COMPONENT_ORDER: Final[tuple[str, ...]] = (
    COMPONENT_NORMALIZER,
    COMPONENT_EXACT_REFERENCE,
    COMPONENT_IDENTIFIER_MATCH,
    COMPONENT_ENTITY_ASSOCIATION,
    COMPONENT_TEMPORAL_ASSOCIATION,
    COMPONENT_NARRATIVE_EXTRACTION,
    COMPONENT_CONFIDENCE,
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class AnalysisStatus(str, Enum):
    """
    Overall service/component analysis status.
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


def _get_value(obj: Any, keys: Sequence[str]) -> Any:
    if isinstance(obj, Mapping):
        return _pick(obj, keys)

    for key in keys:
        try:
            value = getattr(obj, key, None)
        except Exception:
            value = None

        if value is not None:
            return value

    return None


def _safe_reasons(value: Any, limit: int = 50) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        reason = _clean_text(item, MAX_REASON_TEXT_LENGTH)

        if not reason:
            continue

        lowered = reason.lower()

        if any(token in lowered for token in PROHIBITED_ACTION_TOKENS):
            continue

        out.append(reason)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ServiceIssue:
    """
    Safe service issue.

    Issues never contain raw identifiers, raw narratives, raw labels, secrets,
    tokens, passwords, database URLs, filesystem paths, or model artifact paths.
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


def _append_issue(
    issues: list[ServiceIssue],
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

        issues[-1] = ServiceIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        ServiceIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[ServiceIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[ServiceIssue]) -> tuple[ServiceIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[ServiceIssue] = []

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
class ServiceOptions:
    """
    Bounded correlation service policy.
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
    max_confidence_records: int = DEFAULT_MAX_CONFIDENCE_RECORDS
    max_sample_candidates: int = DEFAULT_MAX_SAMPLE_CANDIDATES
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS

    use_cache: bool = True
    max_cache_entries: int = DEFAULT_MAX_CACHE_ENTRIES
    cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS
    cache_by_idempotency_only: bool = True

    run_normalizer: bool = True
    run_exact_reference: bool = True
    run_identifier_match: bool = True
    run_entity_association: bool = True
    run_temporal_association: bool = True
    run_narrative_extraction: bool = False
    run_confidence: bool = True

    include_component_issues: bool = True
    include_candidate_samples: bool = True
    include_confidence_records: bool = True
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
            "max_confidence_records",
            _clamp_int(
                self.max_confidence_records,
                1,
                HARD_MAX_CONFIDENCE_RECORDS,
                DEFAULT_MAX_CONFIDENCE_RECORDS,
            ),
        )
        object.__setattr__(
            self,
            "max_sample_candidates",
            _clamp_int(
                self.max_sample_candidates,
                0,
                HARD_MAX_SAMPLE_CANDIDATES,
                DEFAULT_MAX_SAMPLE_CANDIDATES,
            ),
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

        object.__setattr__(self, "use_cache", _as_bool(self.use_cache, True))
        object.__setattr__(
            self,
            "max_cache_entries",
            _clamp_int(
                self.max_cache_entries,
                1,
                HARD_MAX_CACHE_ENTRIES,
                DEFAULT_MAX_CACHE_ENTRIES,
            ),
        )
        object.__setattr__(
            self,
            "cache_ttl_seconds",
            _clamp_int(
                self.cache_ttl_seconds,
                1,
                HARD_MAX_CACHE_TTL_SECONDS,
                DEFAULT_CACHE_TTL_SECONDS,
            ),
        )
        object.__setattr__(
            self,
            "cache_by_idempotency_only",
            _as_bool(self.cache_by_idempotency_only, True),
        )

        object.__setattr__(self, "run_normalizer", _as_bool(self.run_normalizer, True))
        object.__setattr__(self, "run_exact_reference", _as_bool(self.run_exact_reference, True))
        object.__setattr__(self, "run_identifier_match", _as_bool(self.run_identifier_match, True))
        object.__setattr__(self, "run_entity_association", _as_bool(self.run_entity_association, True))
        object.__setattr__(self, "run_temporal_association", _as_bool(self.run_temporal_association, True))
        object.__setattr__(self, "run_narrative_extraction", _as_bool(self.run_narrative_extraction, False))
        object.__setattr__(self, "run_confidence", _as_bool(self.run_confidence, True))

        object.__setattr__(
            self,
            "include_component_issues",
            _as_bool(self.include_component_issues, True),
        )
        object.__setattr__(
            self,
            "include_candidate_samples",
            _as_bool(self.include_candidate_samples, True),
        )
        object.__setattr__(
            self,
            "include_confidence_records",
            _as_bool(self.include_confidence_records, True),
        )
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, True))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ServiceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "CORRELATION_SERVICE_SALT", None)
            or _setting(settings, "CORRELATION_CONFIDENCE_SALT", None)
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
            enabled=_as_bool(_setting(settings, "CORRELATION_SERVICE_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "CORRELATION_SERVICE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "CORRELATION_SERVICE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_records=_as_int(
                _setting(settings, "CORRELATION_SERVICE_MAX_RECORDS", DEFAULT_MAX_RECORDS),
                DEFAULT_MAX_RECORDS,
            ),
            max_candidates=_as_int(
                _setting(settings, "CORRELATION_SERVICE_MAX_CANDIDATES", DEFAULT_MAX_CANDIDATES),
                DEFAULT_MAX_CANDIDATES,
            ),
            max_confidence_records=_as_int(
                _setting(
                    settings,
                    "CORRELATION_SERVICE_MAX_CONFIDENCE_RECORDS",
                    DEFAULT_MAX_CONFIDENCE_RECORDS,
                ),
                DEFAULT_MAX_CONFIDENCE_RECORDS,
            ),
            max_sample_candidates=_as_int(
                _setting(
                    settings,
                    "CORRELATION_SERVICE_MAX_SAMPLE_CANDIDATES",
                    DEFAULT_MAX_SAMPLE_CANDIDATES,
                ),
                DEFAULT_MAX_SAMPLE_CANDIDATES,
            ),
            max_issues=_as_int(
                _setting(settings, "CORRELATION_SERVICE_MAX_ISSUES", DEFAULT_MAX_ISSUES),
                DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(
                    settings,
                    "CORRELATION_SERVICE_MAX_SUMMARY_ITEMS",
                    DEFAULT_MAX_SUMMARY_ITEMS,
                ),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "CORRELATION_SERVICE_MAX_TIME_MS", DEFAULT_MAX_TIME_MS),
                DEFAULT_MAX_TIME_MS,
            ),
            use_cache=_as_bool(_setting(settings, "CORRELATION_SERVICE_USE_CACHE", True), True),
            max_cache_entries=_as_int(
                _setting(settings, "CORRELATION_SERVICE_MAX_CACHE_ENTRIES", DEFAULT_MAX_CACHE_ENTRIES),
                DEFAULT_MAX_CACHE_ENTRIES,
            ),
            cache_ttl_seconds=_as_int(
                _setting(settings, "CORRELATION_SERVICE_CACHE_TTL_SECONDS", DEFAULT_CACHE_TTL_SECONDS),
                DEFAULT_CACHE_TTL_SECONDS,
            ),
            cache_by_idempotency_only=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_CACHE_BY_IDEMPOTENCY_ONLY", True),
                True,
            ),
            run_normalizer=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_RUN_NORMALIZER", True),
                True,
            ),
            run_exact_reference=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_RUN_EXACT_REFERENCE", True),
                True,
            ),
            run_identifier_match=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_RUN_IDENTIFIER_MATCH", True),
                True,
            ),
            run_entity_association=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_RUN_ENTITY_ASSOCIATION", True),
                True,
            ),
            run_temporal_association=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_RUN_TEMPORAL_ASSOCIATION", True),
                True,
            ),
            run_narrative_extraction=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_RUN_NARRATIVE_EXTRACTION", False),
                False,
            ),
            run_confidence=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_RUN_CONFIDENCE", True),
                True,
            ),
            include_component_issues=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_INCLUDE_COMPONENT_ISSUES", True),
                True,
            ),
            include_candidate_samples=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_INCLUDE_CANDIDATE_SAMPLES", True),
                True,
            ),
            include_confidence_records=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_INCLUDE_CONFIDENCE_RECORDS", True),
                True,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "CORRELATION_SERVICE_DROP_FORBIDDEN_FIELDS", True),
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
                "max_confidence_records": self.max_confidence_records,
                "max_sample_candidates": self.max_sample_candidates,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
            },
            "cache": {
                "use_cache": self.use_cache,
                "max_cache_entries": self.max_cache_entries,
                "cache_ttl_seconds": self.cache_ttl_seconds,
                "cache_by_idempotency_only": self.cache_by_idempotency_only,
            },
            "components": {
                "run_normalizer": self.run_normalizer,
                "run_exact_reference": self.run_exact_reference,
                "run_identifier_match": self.run_identifier_match,
                "run_entity_association": self.run_entity_association,
                "run_temporal_association": self.run_temporal_association,
                "run_narrative_extraction": self.run_narrative_extraction,
                "run_confidence": self.run_confidence,
            },
            "flags": {
                "include_component_issues": self.include_component_issues,
                "include_candidate_samples": self.include_candidate_samples,
                "include_confidence_records": self.include_confidence_records,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "complaints",
        "transactions",
        "alerts",
        "cases",
        "entity_links",
        "notes",
        "candidates",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class ServiceRequest:
    """
    Bounded correlation service request.
    """

    complaints: Any = None
    transactions: Any = None
    alerts: Any = None
    cases: Any = None
    entity_links: Any = None
    notes: Any = None
    candidates: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> ServiceRequest:
    if isinstance(request, ServiceRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(ServiceRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return ServiceRequest(**clean)
            except Exception:
                return ServiceRequest(metadata=request)

        return ServiceRequest(metadata=request)

    if isinstance(request, (list, tuple, set, frozenset)):
        return ServiceRequest(complaints=request)

    return ServiceRequest(metadata=request)


# -----------------------------------------------------------------------------
# Component and result models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComponentReport:
    """
    Safe bounded report for one correlation pipeline component.
    """

    name: str = ""
    status: AnalysisStatus | str = AnalysisStatus.SKIPPED
    ok: bool = False
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[ServiceIssue, ...] = ()
    fingerprint: str = ""
    sample_candidates: tuple[Mapping[str, Any], ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_token(self.name))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(AnalysisStatus, self.status, AnalysisStatus.SKIPPED),
        )
        object.__setattr__(self, "ok", _as_bool(self.ok, False))
        object.__setattr__(
            self,
            "counts",
            MappingProxyType(
                {str(key): max(0, _as_int(value, 0)) for key, value in (self.counts or {}).items()}
            ),
        )
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "fingerprint", _clean_text(self.fingerprint, 128))
        object.__setattr__(
            self,
            "sample_candidates",
            tuple(_as_mapping(item) for item in (self.sample_candidates or ())),
        )
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": _enum_value(self.status, AnalysisStatus.SKIPPED.value),
            "ok": bool(self.ok),
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "fingerprint": self.fingerprint,
            "sample_candidates": [dict(item) for item in self.sample_candidates],
            "metadata": _safe_detail_value(self.metadata),
            "raw_values_retained": False,
        }


@dataclass(frozen=True, slots=True)
class ServiceResult:
    """
    Safe bounded correlation service result.
    """

    ok: bool = True
    status: AnalysisStatus | str = AnalysisStatus.PASSED
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    normalized_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    components: tuple[ComponentReport, ...] = ()
    confidence_records: tuple[Mapping[str, Any], ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[ServiceIssue, ...] = ()
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
        object.__setattr__(self, "normalized_summary", MappingProxyType(_as_mapping(self.normalized_summary)))
        object.__setattr__(self, "components", tuple(self.components or ()))
        object.__setattr__(
            self,
            "confidence_records",
            tuple(_as_mapping(item) for item in (self.confidence_records or ())),
        )
        object.__setattr__(
            self,
            "counts",
            MappingProxyType(
                {str(key): max(-1, _as_int(value, 0)) for key, value in (self.counts or {}).items()}
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
                        "version": SERVICE_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, AnalysisStatus.PASSED.value),
                        "request_id": self.request_id,
                        "component_fingerprints": [
                            component.fingerprint for component in self.components
                        ],
                        "confidence_record_count": len(self.confidence_records),
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
            "normalized_summary": _safe_detail_value(self.normalized_summary),
            "components": [component.to_dict() for component in self.components],
            "confidence_records": [dict(record) for record in self.confidence_records],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(SERVICE_CAVEATS),
            "safety_flags": dict(SERVICE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local service cache
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _CachedServiceResult:
    result: ServiceResult
    expires_at: datetime


class ServiceCache:
    """
    Bounded process-local correlation service cache.
    """

    def __init__(
        self,
        max_entries: int = DEFAULT_MAX_CACHE_ENTRIES,
        ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    ) -> None:
        self.max_entries = max(1, int(max_entries))
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._entries: OrderedDict[str, _CachedServiceResult] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[ServiceResult]:
        clean_key = _clean_text(key, 256)

        with self._lock:
            entry = self._entries.get(clean_key)

            if entry is None:
                return None

            if entry.expires_at <= _now_utc():
                self._entries.pop(clean_key, None)
                return None

            self._entries.move_to_end(clean_key)
            return entry.result

    def set(self, key: str, result: ServiceResult) -> str:
        clean_key = _clean_text(key, 256) or result.fingerprint

        with self._lock:
            expires_at = _now_utc() + timedelta(seconds=int(self.ttl_seconds))
            self._entries[clean_key] = _CachedServiceResult(result=result, expires_at=expires_at)
            self._entries.move_to_end(clean_key)

            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

        return clean_key

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def safe_summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "backend": "process_local_in_memory",
                "durable": False,
                "distributed": False,
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl_seconds,
                "entries": len(self._entries),
            }


_default_cache: Optional[ServiceCache] = None
_default_cache_lock = threading.Lock()


def get_service_cache(
    max_entries: int | None = None,
    ttl_seconds: int | None = None,
    *,
    rebuild: bool = False,
) -> ServiceCache:
    global _default_cache

    with _default_cache_lock:
        if _default_cache is None or rebuild:
            _default_cache = ServiceCache(
                max_entries=max_entries if max_entries is not None else DEFAULT_MAX_CACHE_ENTRIES,
                ttl_seconds=ttl_seconds if ttl_seconds is not None else DEFAULT_CACHE_TTL_SECONDS,
            )

        return _default_cache


# -----------------------------------------------------------------------------
# Record helpers
# -----------------------------------------------------------------------------


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, ServiceResult):
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


def _count_records_safe(value: Any) -> int:
    if value is None:
        return 0

    if isinstance(value, Mapping):
        for key in ("records", "rows", "items", "candidates", "examples"):
            if key in value and isinstance(value[key], (list, tuple, set, frozenset)):
                return len(value[key])

        return 1

    if isinstance(value, (list, tuple, set, frozenset)):
        return len(value)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        try:
            return len(value)
        except Exception:
            return -1

    return -1


def _strip_mapping_record(record: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "[truncated-depth]"

    if not isinstance(record, Mapping):
        return record

    out: dict[str, Any] = {}

    for raw_key, raw_value in record.items():
        key = _canonical_field_name(raw_key)

        if not key:
            continue

        if key in NARRATIVE_KEYS or _is_forbidden_key(key):
            continue

        if isinstance(raw_value, Mapping):
            out[raw_key] = _strip_mapping_record(raw_value, depth + 1)
        elif isinstance(raw_value, (list, tuple, set, frozenset)):
            out[raw_key] = [
                _strip_mapping_record(item, depth + 1) if isinstance(item, Mapping) else item
                for item in list(raw_value)[:100]
            ]
        else:
            out[raw_key] = raw_value

    return out


def _strip_records(value: Any) -> list[Any]:
    return [_strip_mapping_record(record) for record in _iter_records(value)]


def _group_normalized_records(result: Any) -> dict[str, list[Any]]:
    groups: dict[str, list[Any]] = defaultdict(list)

    for record in getattr(result, "records", ()) or ():
        category = _normalize_token(_get_value(record, ("category", "record_category")) or "unknown")

        if hasattr(record, "to_dict"):
            try:
                item = record.to_dict()
            except Exception:
                item = _as_mapping(record)
        else:
            item = _as_mapping(record)

        groups[category].append(item)

    return dict(groups)


def _summarize_normalized_result(result: Any) -> dict[str, Any]:
    if result is None:
        return {}

    records = getattr(result, "records", ()) or ()
    by_category = Counter(
        _normalize_token(_get_value(record, ("category", "record_category")) or "unknown")
        for record in records
    )

    return {
        "record_count": len(records),
        "by_category": dict(by_category),
        "counts": dict(getattr(result, "counts", {}) or {}),
        "fingerprint": _clean_text(getattr(result, "fingerprint", ""), 128),
        "status": _enum_value(getattr(result, "status", AnalysisStatus.PASSED), AnalysisStatus.PASSED.value),
        "ok": bool(getattr(result, "ok", True)),
        "raw_values_retained": False,
    }


def _build_detector_payload(
    request: ServiceRequest,
    normalized_groups: Mapping[str, Sequence[Any]],
    use_normalized: bool,
    request_id: str,
) -> dict[str, Any]:
    if use_normalized:
        complaints = list(normalized_groups.get("complaint", ()))
        transactions = list(normalized_groups.get("transaction", ()))
        alerts = list(normalized_groups.get("alert", ()))
        cases = list(normalized_groups.get("case", ()))
        entity_links = list(normalized_groups.get("entity_link", ()))
    else:
        complaints = _strip_records(request.complaints)
        transactions = _strip_records(request.transactions)
        alerts = _strip_records(request.alerts)
        cases = _strip_records(request.cases)
        entity_links = _strip_records(request.entity_links)

    return {
        "complaints": complaints,
        "transactions": transactions,
        "alerts": alerts,
        "cases": cases,
        "entity_links": entity_links,
        "metadata": _as_mapping(request.metadata),
        "tags": list(request.tags),
        "request_id": request_id,
        "idempotency_key": request.idempotency_key,
    }


def _build_narrative_payload(request: ServiceRequest, request_id: str) -> dict[str, Any]:
    return {
        "complaints": _iter_records(request.complaints),
        "cases": _iter_records(request.cases),
        "alerts": _iter_records(request.alerts),
        "notes": _iter_records(request.notes),
        "metadata": _as_mapping(request.metadata),
        "tags": list(request.tags),
        "request_id": request_id,
        "idempotency_key": request.idempotency_key,
    }


def _candidate_sort_key(candidate: Any) -> tuple[float, float, str]:
    score = _coerce_optional_float(_get_value(candidate, ("score",)), allow_bool=True) or 0.0
    confidence = _coerce_optional_float(_get_value(candidate, ("confidence",)), allow_bool=True) or 0.0
    candidate_id = _clean_text(_get_value(candidate, CANDIDATE_ID_KEYS), 128)
    return (-float(score), -float(confidence), candidate_id)


def _candidate_sample(candidate: Any) -> dict[str, Any]:
    return {
        "correlation_id": _clean_text(_get_value(candidate, ("correlation_id", "candidate_id", "id")), 128) or None,
        "kind": _clean_text(_get_value(candidate, ("kind",)), 100) or None,
        "detector": _clean_text(_get_value(candidate, DETECTOR_KEYS), 100) or None,
        "source_ref_hash": _clean_text(_get_value(candidate, SOURCE_KEYS), MAX_HASH_LENGTH).lower() or None,
        "target_ref_hash": _clean_text(_get_value(candidate, TARGET_KEYS), MAX_HASH_LENGTH).lower() or None,
        "source_category": _normalize_token(_get_value(candidate, ("source_category",)) or ""),
        "target_category": _normalize_token(_get_value(candidate, ("target_category",)) or ""),
        "source_index": max(0, _as_int(_get_value(candidate, ("source_index",)), 0)),
        "target_index": max(0, _as_int(_get_value(candidate, ("target_index",)), 0)),
        "score": _round6(_clip_float(_coerce_optional_float(_get_value(candidate, ("score",)), allow_bool=True), 0.0, 1.0, 0.0)),
        "confidence": _round6(
            _clip_float(_coerce_optional_float(_get_value(candidate, ("confidence",)), allow_bool=True), 0.0, 1.0, 0.0)
        ),
        "corroborated": _as_bool(_get_value(candidate, ("corroborated",)), False),
        "reasons": list(_safe_reasons(_get_value(candidate, ("reasons",)))),
        "raw_identifiers_retained": False,
        "raw_narratives_retained": False,
    }


def _narrative_sample(extraction: Any) -> dict[str, Any]:
    token_hashes = _get_value(extraction, ("token_hashes",)) or ()
    token_hash_count = len(token_hashes) if isinstance(token_hashes, (list, tuple, set, frozenset)) else 0

    return {
        "extraction_id": _clean_text(_get_value(extraction, ("extraction_id", "id")), 128) or None,
        "category": _normalize_token(_get_value(extraction, ("category",)) or ""),
        "source_index": max(0, _as_int(_get_value(extraction, ("source_index", "index")), 0)),
        "subject_ref_hash": _clean_text(_get_value(extraction, ("subject_ref_hash",)), MAX_HASH_LENGTH).lower() or None,
        "char_count": max(0, _as_int(_get_value(extraction, ("char_count",)), 0)),
        "token_count": max(0, _as_int(_get_value(extraction, ("token_count",)), 0)),
        "unique_token_count": max(0, _as_int(_get_value(extraction, ("unique_token_count",)), 0)),
        "token_hash_count": max(0, token_hash_count),
        "raw_narrative_retained": False,
        "raw_pii_retained": False,
    }


def _confidence_record_sample(record: Any) -> dict[str, Any]:
    return {
        "pair_hash": _clean_text(_get_value(record, ("pair_hash",)), MAX_HASH_LENGTH).lower(),
        "source_ref_hash": _clean_text(_get_value(record, ("source_ref_hash",)), MAX_HASH_LENGTH).lower() or None,
        "target_ref_hash": _clean_text(_get_value(record, ("target_ref_hash",)), MAX_HASH_LENGTH).lower() or None,
        "source_category": _normalize_token(_get_value(record, ("source_category",)) or ""),
        "target_category": _normalize_token(_get_value(record, ("target_category",)) or ""),
        "support_score": _round6(
            _clip_float(_coerce_optional_float(_get_value(record, ("support_score",)), allow_bool=True), 0.0, 1.0, 0.0)
        ),
        "confidence_score": _round6(
            _clip_float(_coerce_optional_float(_get_value(record, ("confidence_score", "confidence")), 0.0, 1.0, 0.0), 0.0, 1.0, 0.0)
        ),
        "uncertainty": _round6(
            _clip_float(_coerce_optional_float(_get_value(record, ("uncertainty",)), allow_bool=True), 0.0, 1.0, 1.0)
        ),
        "evidence_count": max(0, _as_int(_get_value(record, ("evidence_count",)), 0)),
        "corroborating_count": max(0, _as_int(_get_value(record, ("corroborating_count",)), 0)),
        "conflicting_count": max(0, _as_int(_get_value(record, ("conflicting_count",)), 0)),
        "detector_count": max(0, _as_int(_get_value(record, ("detector_count",)), 0)),
        "tier": _clean_text(_get_value(record, ("tier",)), 100) or "unscoped",
        "primary_detector": _clean_text(_get_value(record, ("primary_detector",)), 100) or "generic",
        "reasons": list(_safe_reasons(_get_value(record, ("reasons",)))),
        "confidence_semantics": "investigative_prioritization_only_not_probability_of_guilt",
        "calibration_claimed": False,
        "raw_identifiers_retained": False,
        "raw_narratives_retained": False,
    }


def _component_samples(
    name: str,
    result: Any,
    options: ServiceOptions,
) -> list[dict[str, Any]]:
    if not options.include_candidate_samples or options.max_sample_candidates <= 0:
        return []

    if name == COMPONENT_NORMALIZER:
        return []

    if name == COMPONENT_NARRATIVE_EXTRACTION:
        items = getattr(result, "extractions", ()) or ()
        return [_narrative_sample(item) for item in list(items)[: int(options.max_sample_candidates)]]

    if name == COMPONENT_CONFIDENCE:
        items = getattr(result, "records", ()) or ()
        return [_confidence_record_sample(item) for item in list(items)[: int(options.max_sample_candidates)]]

    items = getattr(result, "candidates", ()) or ()
    return [_candidate_sample(item) for item in list(items)[: int(options.max_sample_candidates)]]


# -----------------------------------------------------------------------------
# Component runner
# -----------------------------------------------------------------------------


def _run_component(
    name: str,
    func: Any,
    payload: Any,
    options: ServiceOptions,
    issues: list[ServiceIssue],
    start_time: float,
) -> tuple[ComponentReport, Optional[Any]]:
    component_issues: list[ServiceIssue] = []

    if func is None:
        _append_issue(
            component_issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code=f"{name}_unavailable",
            message="Correlation component is unavailable in this deployment.",
        )
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code=f"{name}_unavailable",
            message="Correlation component is unavailable in this deployment.",
            details={"component": name},
        )
        return (
            ComponentReport(
                name=name,
                status=AnalysisStatus.SKIPPED,
                ok=False,
                counts={"component_unavailable": 1},
                issues=tuple(component_issues),
                fingerprint="",
                sample_candidates=(),
                metadata={
                    "component": name,
                    "reason": "unavailable",
                    "raw_values_retained": False,
                },
            ),
            None,
        )

    if _time_exceeded(start_time, options.max_time_ms):
        _append_issue(
            component_issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code=f"{name}_skipped_time_budget",
            message="Correlation component skipped after service time budget was exhausted.",
        )
        return (
            ComponentReport(
                name=name,
                status=AnalysisStatus.SKIPPED,
                ok=False,
                counts={"time_budget_exhausted": 1},
                issues=tuple(component_issues),
                fingerprint="",
                sample_candidates=(),
                metadata={
                    "component": name,
                    "reason": "time_budget_exhausted",
                    "raw_values_retained": False,
                },
            ),
            None,
        )

    try:
        result = func(payload)
    except Exception as exc:
        _append_issue(
            component_issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code=f"{name}_failed",
            message="Correlation component failed unexpectedly.",
            details={"exception_type": type(exc).__name__},
        )
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code=f"{name}_failed",
            message="Correlation component failed unexpectedly.",
            details={"component": name, "exception_type": type(exc).__name__},
        )
        return (
            ComponentReport(
                name=name,
                status=AnalysisStatus.FAILED,
                ok=False,
                counts={"component_failures": 1},
                issues=tuple(component_issues),
                fingerprint="",
                sample_candidates=(),
                metadata={
                    "component": name,
                    "reason": "exception",
                    "raw_values_retained": False,
                },
            ),
            None,
        )

    status = _normalize_enum_option(
        AnalysisStatus,
        getattr(result, "status", AnalysisStatus.PASSED),
        AnalysisStatus.PASSED,
    )
    ok = bool(getattr(result, "ok", status in {AnalysisStatus.PASSED, AnalysisStatus.DEGRADED}))
    counts = {str(key): max(0, _as_int(value, 0)) for key, value in (getattr(result, "counts", {}) or {}).items()}
    counts["component_attempts"] = 1

    if options.include_component_issues:
        for issue in getattr(result, "issues", ()) or ():
            severity = _normalize_enum_option(
                IssueSeverity,
                getattr(issue, "severity", IssueSeverity.WARNING),
                IssueSeverity.WARNING,
            )
            code = _clean_text(f"{name}_{getattr(issue, 'code', 'issue')}", 100)
            message = _clean_text(getattr(issue, "message", ""), 300)
            field_name = _clean_text(getattr(issue, "field", None), 200) or None
            details = _as_mapping(getattr(issue, "details", {}))
            component_issues.append(
                ServiceIssue(
                    severity=severity,
                    code=code,
                    message=message,
                    field=field_name,
                    details=details,
                )
            )

    samples = _component_samples(name, result, options)
    fingerprint = _clean_text(getattr(result, "fingerprint", ""), 128)

    metadata = {
        "component": name,
        "status": _enum_value(status, AnalysisStatus.PASSED.value),
        "ok": ok,
        "result_class": type(result).__name__,
        "raw_values_retained": False,
        "raw_identifiers_retained": False,
        "raw_narratives_retained": False,
    }

    return (
        ComponentReport(
            name=name,
            status=status,
            ok=ok,
            counts=counts,
            issues=tuple(_dedupe_issues(component_issues)[: options.max_issues]),
            fingerprint=fingerprint,
            sample_candidates=tuple(samples),
            metadata=metadata,
        ),
        result,
    )


# -----------------------------------------------------------------------------
# Cache key
# -----------------------------------------------------------------------------


def _service_cache_key(request: ServiceRequest, options: ServiceOptions) -> Optional[str]:
    if not options.use_cache:
        return None

    if options.cache_by_idempotency_only and not request.idempotency_key:
        return None

    sources = (
        request.complaints,
        request.transactions,
        request.alerts,
        request.cases,
        request.entity_links,
        request.notes,
        request.candidates,
    )

    cacheable = all(
        value is None or isinstance(value, (list, tuple, set, frozenset, Mapping))
        for value in sources
    )

    if not cacheable:
        return None

    counts = {
        "complaints": _count_records_safe(request.complaints),
        "transactions": _count_records_safe(request.transactions),
        "alerts": _count_records_safe(request.alerts),
        "cases": _count_records_safe(request.cases),
        "entity_links": _count_records_safe(request.entity_links),
        "notes": _count_records_safe(request.notes),
        "candidates": _count_records_safe(request.candidates),
    }

    payload = {
        "version": SERVICE_VERSION,
        "idempotency_key": request.idempotency_key,
        "request_metadata": _safe_detail_value(request.metadata),
        "tags": list(request.tags),
        "counts": counts,
        "options": options.safe_summary(),
    }

    return _sha256_hex(_canonical_json(payload))[:64]


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------


class CorrelationServiceEngine:
    """
    Bounded deterministic synthetic correlation service orchestrator.
    """

    def __init__(
        self,
        options: ServiceOptions | None = None,
        cache: ServiceCache | None = None,
    ) -> None:
        self.options = options or ServiceOptions.from_settings()
        self.cache = cache or get_service_cache(
            max_entries=self.options.max_cache_entries,
            ttl_seconds=self.options.cache_ttl_seconds,
        )
        self._lock = threading.RLock()

    def run(self, request: Any) -> ServiceResult:
        """
        Run one bounded synthetic correlation service job.
        """
        opts = self.options
        issues: list[ServiceIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)

        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": SERVICE_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                    "counts": {
                        "complaints": _count_records_safe(req.complaints),
                        "transactions": _count_records_safe(req.transactions),
                        "alerts": _count_records_safe(req.alerts),
                        "cases": _count_records_safe(req.cases),
                        "candidates": _count_records_safe(req.candidates),
                    },
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: AnalysisStatus,
            normalized_summary: Optional[Mapping[str, Any]] = None,
            components: Sequence[ComponentReport] = (),
            confidence_records: Sequence[Mapping[str, Any]] = (),
            counts: Optional[Mapping[str, int]] = None,
            cache_key: Optional[str] = None,
        ) -> ServiceResult:
            resolved_counts: dict[str, int] = {
                "submitted_complaints": _count_records_safe(req.complaints),
                "submitted_transactions": _count_records_safe(req.transactions),
                "submitted_alerts": _count_records_safe(req.alerts),
                "submitted_cases": _count_records_safe(req.cases),
                "submitted_notes": _count_records_safe(req.notes),
                "submitted_candidates": _count_records_safe(req.candidates),
                "components_total": len(components),
                "components_passed": sum(1 for component in components if component.ok),
                "components_failed": sum(
                    1 for component in components if component.status == AnalysisStatus.FAILED
                ),
                "components_blocked": sum(
                    1 for component in components if component.status == AnalysisStatus.BLOCKED
                ),
                "components_skipped": sum(
                    1 for component in components if component.status == AnalysisStatus.SKIPPED
                ),
                "confidence_records": len(confidence_records),
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update(
                    {str(key): max(-1, _as_int(value, 0)) for key, value in counts.items()}
                )

            resolved_counts["issues"] = len(issues) + sum(len(component.issues) for component in components)
            resolved_counts["components_total"] = len(components)
            resolved_counts["components_passed"] = sum(1 for component in components if component.ok)
            resolved_counts["components_failed"] = sum(
                1 for component in components if component.status == AnalysisStatus.FAILED
            )
            resolved_counts["components_blocked"] = sum(
                1 for component in components if component.status == AnalysisStatus.BLOCKED
            )
            resolved_counts["components_skipped"] = sum(
                1 for component in components if component.status == AnalysisStatus.SKIPPED
            )
            resolved_counts["confidence_records"] = len(confidence_records)

            metadata = {
                "service_version": SERVICE_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "cache": self.cache.safe_summary(),
                "cache_key": cache_key,
                "elapsed_ms": _elapsed_ms(start_time),
                "component_order": list(COMPONENT_ORDER),
                "raw_values_retained": False,
                "raw_identifiers_retained": False,
                "raw_narratives_retained": False,
                "subject_label_pairs_retained": False,
                "secrets_retained": False,
                "monetary_conversion_performed": False,
                "calibration_claimed": False,
                "caveats": list(SERVICE_CAVEATS),
                "safety_flags": dict(SERVICE_SAFETY_FLAGS),
            }

            return ServiceResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                normalized_summary=_as_mapping(normalized_summary),
                components=tuple(components),
                confidence_records=tuple(confidence_records),
                counts=resolved_counts,
                issues=tuple(_dedupe_issues(issues)[: opts.max_issues]),
                metadata=metadata,
                fingerprint="",
            )

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="correlation_service_disabled",
                message="Correlation service is disabled.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Correlation service requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Correlation service is blocked in production-like environments.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_correlation_service_action_metadata",
                message="Correlation service request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        cache_key = _service_cache_key(req, opts)

        if cache_key:
            cached = self.cache.get(cache_key)

            if cached is not None:
                cached_metadata = dict(cached.metadata)
                cached_metadata.update(
                    {
                        "cached": True,
                        "cache_hit": True,
                        "cache_key": cache_key,
                        "request_id": request_id,
                    }
                )
                return replace(
                    cached,
                    metadata=MappingProxyType(cached_metadata),
                    fingerprint="",
                )

        components: list[ComponentReport] = []
        component_results: dict[str, Any] = {}
        normalized_summary: dict[str, Any] = {}
        normalized_groups: dict[str, list[Any]] = {}
        use_normalized = False

        with self._lock:
            if opts.run_normalizer:
                normalizer_payload = {
                    "complaints": req.complaints,
                    "transactions": req.transactions,
                    "accounts": None,
                    "entities": None,
                    "entity_links": req.entity_links,
                    "alerts": req.alerts,
                    "cases": req.cases,
                    "metadata": req.metadata,
                    "tags": req.tags,
                    "request_id": request_id,
                    "idempotency_key": req.idempotency_key,
                }

                normalizer_report, normalizer_result = _run_component(
                    COMPONENT_NORMALIZER,
                    _NORMALIZE_IMPL,
                    normalizer_payload,
                    opts,
                    issues,
                    start_time,
                )

                components.append(normalizer_report)

                if normalizer_result is not None:
                    component_results[COMPONENT_NORMALIZER] = normalizer_result
                    normalized_summary = _summarize_normalized_result(normalizer_result)
                    normalized_groups = _group_normalized_records(normalizer_result)
                    use_normalized = bool(normalizer_report.ok and normalized_groups)

            detector_specs: tuple[tuple[str, Any], ...] = (
                (COMPONENT_EXACT_REFERENCE, _EXACT_REFERENCE_IMPL if opts.run_exact_reference else None),
                (COMPONENT_IDENTIFIER_MATCH, _IDENTIFIER_MATCH_IMPL if opts.run_identifier_match else None),
                (COMPONENT_ENTITY_ASSOCIATION, _ENTITY_ASSOCIATION_IMPL if opts.run_entity_association else None),
                (COMPONENT_TEMPORAL_ASSOCIATION, _TEMPORAL_ASSOCIATION_IMPL if opts.run_temporal_association else None),
            )

            detector_payload = _build_detector_payload(req, normalized_groups, use_normalized, request_id)

            for name, func in detector_specs:
                if func is None and not (
                    (name == COMPONENT_EXACT_REFERENCE and opts.run_exact_reference)
                    or (name == COMPONENT_IDENTIFIER_MATCH and opts.run_identifier_match)
                    or (name == COMPONENT_ENTITY_ASSOCIATION and opts.run_entity_association)
                    or (name == COMPONENT_TEMPORAL_ASSOCIATION and opts.run_temporal_association)
                ):
                    continue

                report, result = _run_component(
                    name,
                    func,
                    detector_payload,
                    opts,
                    issues,
                    start_time,
                )

                components.append(report)

                if result is not None:
                    component_results[name] = result

            if opts.run_narrative_extraction:
                narrative_payload = _build_narrative_payload(req, request_id)
                narrative_report, narrative_result = _run_component(
                    COMPONENT_NARRATIVE_EXTRACTION,
                    _NARRATIVE_EXTRACTION_IMPL,
                    narrative_payload,
                    opts,
                    issues,
                    start_time,
                )

                components.append(narrative_report)

                if narrative_result is not None:
                    component_results[COMPONENT_NARRATIVE_EXTRACTION] = narrative_result

            collected_candidates: list[Any] = []

            for name in (
                COMPONENT_EXACT_REFERENCE,
                COMPONENT_IDENTIFIER_MATCH,
                COMPONENT_ENTITY_ASSOCIATION,
                COMPONENT_TEMPORAL_ASSOCIATION,
            ):
                result = component_results.get(name)

                if result is None:
                    continue

                collected_candidates.extend(getattr(result, "candidates", ()) or ())

            if req.candidates is not None:
                collected_candidates.extend(_strip_records(req.candidates))

            if len(collected_candidates) > int(opts.max_candidates):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="service_candidate_input_truncated",
                    message="Collected correlation candidates exceeded configured limit and were truncated.",
                    details={
                        "collected": len(collected_candidates),
                        "max_candidates": int(opts.max_candidates),
                    },
                )
                collected_candidates.sort(key=_candidate_sort_key)
                collected_candidates = collected_candidates[: int(opts.max_candidates)]

            confidence_records: list[dict[str, Any]] = []

            if opts.run_confidence and collected_candidates:
                confidence_payload = {
                    "candidates": collected_candidates,
                    "metadata": req.metadata,
                    "tags": req.tags,
                    "request_id": request_id,
                    "idempotency_key": req.idempotency_key,
                }

                confidence_report, confidence_result = _run_component(
                    COMPONENT_CONFIDENCE,
                    _CONFIDENCE_IMPL,
                    confidence_payload,
                    opts,
                    issues,
                    start_time,
                )

                components.append(confidence_report)

                if confidence_result is not None:
                    component_results[COMPONENT_CONFIDENCE] = confidence_result

                    if opts.include_confidence_records:
                        records = list(getattr(confidence_result, "records", ()) or ())
                        records.sort(
                            key=lambda record: (
                                -float(
                                    _clip_float(
                                        _coerce_optional_float(
                                            _get_value(record, ("confidence_score", "confidence")),
                                            allow_bool=True,
                                        ),
                                        0.0,
                                        1.0,
                                        0.0,
                                    )
                                ),
                                -float(
                                    _clip_float(
                                        _coerce_optional_float(
                                            _get_value(record, ("support_score",)),
                                            allow_bool=True,
                                        ),
                                        0.0,
                                        1.0,
                                        0.0,
                                    )
                                ),
                                _clean_text(_get_value(record, ("pair_hash",)), 128),
                            )
                        )
                        confidence_records = [
                            _confidence_record_sample(record)
                            for record in records[: int(opts.max_confidence_records)]
                        ]

            component_statuses = [component.status for component in components]
            attempted = [component for component in components if component.status != AnalysisStatus.SKIPPED]
            passed = [component for component in attempted if component.ok]
            failed = [component for component in attempted if component.status == AnalysisStatus.FAILED]
            blocked = [component for component in attempted if component.status == AnalysisStatus.BLOCKED]
            skipped = [component for component in components if component.status == AnalysisStatus.SKIPPED]

            warning_issues = any(
                issue.severity == IssueSeverity.WARNING
                for component in components
                for issue in component.issues
            ) or any(issue.severity == IssueSeverity.WARNING for issue in issues)

            if not components or not attempted:
                status = AnalysisStatus.SKIPPED
            elif blocked and not passed:
                status = AnalysisStatus.BLOCKED
            elif failed and not passed:
                status = AnalysisStatus.FAILED
            elif failed or skipped or warning_issues:
                status = AnalysisStatus.DEGRADED
            else:
                status = AnalysisStatus.PASSED

            ok = status in {AnalysisStatus.PASSED, AnalysisStatus.DEGRADED}

            counts = {
                "normalized_records": int(normalized_summary.get("record_count", 0) or 0),
                "collected_candidates": len(collected_candidates),
                "confidence_records": len(confidence_records),
                "component_results": len(component_results),
            }

            for name in (
                COMPONENT_EXACT_REFERENCE,
                COMPONENT_IDENTIFIER_MATCH,
                COMPONENT_ENTITY_ASSOCIATION,
                COMPONENT_TEMPORAL_ASSOCIATION,
            ):
                result = component_results.get(name)
                counts[f"{name}_candidates"] = len(getattr(result, "candidates", ()) or ()) if result else 0

            result_obj = make_result(
                ok=ok,
                status=status,
                normalized_summary=normalized_summary,
                components=components,
                confidence_records=confidence_records,
                counts=counts,
                cache_key=cache_key,
            )

            if cache_key and result_obj.ok:
                self.cache.set(cache_key, result_obj)

            return result_obj

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "cache": self.cache.safe_summary(),
            "components": {
                COMPONENT_NORMALIZER: _NORMALIZE_IMPL is not None,
                COMPONENT_EXACT_REFERENCE: _EXACT_REFERENCE_IMPL is not None,
                COMPONENT_IDENTIFIER_MATCH: _IDENTIFIER_MATCH_IMPL is not None,
                COMPONENT_ENTITY_ASSOCIATION: _ENTITY_ASSOCIATION_IMPL is not None,
                COMPONENT_TEMPORAL_ASSOCIATION: _TEMPORAL_ASSOCIATION_IMPL is not None,
                COMPONENT_NARRATIVE_EXTRACTION: _NARRATIVE_EXTRACTION_IMPL is not None,
                COMPONENT_CONFIDENCE: _CONFIDENCE_IMPL is not None,
            },
            "caveats": list(SERVICE_CAVEATS),
            "safety_flags": dict(SERVICE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default engine and public API
# -----------------------------------------------------------------------------


_default_engine: Optional[CorrelationServiceEngine] = None
_default_engine_lock = threading.Lock()


def get_service_options(settings: Any | None = None) -> ServiceOptions:
    """
    Return correlation service options from settings.
    """
    return ServiceOptions.from_settings(settings)


def get_service_engine(
    options: ServiceOptions | None = None,
    *,
    rebuild: bool = False,
) -> CorrelationServiceEngine:
    """
    Return a process-wide correlation service engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = CorrelationServiceEngine(
                options=options or ServiceOptions.from_settings()
            )

        return _default_engine


def run_correlation_service(
    request: Any,
    options: ServiceOptions | None = None,
    *,
    engine: CorrelationServiceEngine | None = None,
) -> ServiceResult:
    """
    Run one bounded synthetic correlation service job.
    """
    active_engine = engine or get_service_engine(options)
    return active_engine.run(request)


def execute_correlation_pipeline(
    request: Any,
    options: ServiceOptions | None = None,
    *,
    engine: CorrelationServiceEngine | None = None,
) -> ServiceResult:
    """
    Alias for `run_correlation_service`.
    """
    return run_correlation_service(request, options=options, engine=engine)


def correlate_through_service(
    request: Any,
    options: ServiceOptions | None = None,
    *,
    engine: CorrelationServiceEngine | None = None,
) -> ServiceResult:
    """
    Alias for `run_correlation_service`.
    """
    return run_correlation_service(request, options=options, engine=engine)


def export_service_summary(result: ServiceResult) -> dict[str, Any]:
    """
    Export a safe public correlation service summary.
    """
    return result.to_dict()


def clear_service_cache(*, cache: ServiceCache | None = None) -> None:
    """
    Clear the process-local correlation service cache.
    """
    active_cache = cache or get_service_cache()
    active_cache.clear()


def get_service_health(*, engine: CorrelationServiceEngine | None = None) -> dict[str, Any]:
    """
    Return safe correlation service health.
    """
    active_engine = engine or get_service_engine()
    opts = active_engine.options
    cache_summary = active_engine.cache.safe_summary()
    issues: list[ServiceIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="correlation_service_disabled",
            message="Correlation service is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Correlation service requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Correlation service is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "cache": cache_summary,
        "options": opts.safe_summary(),
        "components": {
            COMPONENT_NORMALIZER: _NORMALIZE_IMPL is not None,
            COMPONENT_EXACT_REFERENCE: _EXACT_REFERENCE_IMPL is not None,
            COMPONENT_IDENTIFIER_MATCH: _IDENTIFIER_MATCH_IMPL is not None,
            COMPONENT_ENTITY_ASSOCIATION: _ENTITY_ASSOCIATION_IMPL is not None,
            COMPONENT_TEMPORAL_ASSOCIATION: _TEMPORAL_ASSOCIATION_IMPL is not None,
            COMPONENT_NARRATIVE_EXTRACTION: _NARRATIVE_EXTRACTION_IMPL is not None,
            COMPONENT_CONFIDENCE: _CONFIDENCE_IMPL is not None,
        },
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(SERVICE_CAVEATS),
        "safety_flags": dict(SERVICE_SAFETY_FLAGS),
    }


def get_service_metadata(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
) -> dict[str, Any]:
    """
    Return safe, serializable correlation service metadata.

    This is useful for startup logs, diagnostic endpoints, tests, developer
    tooling, and architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, raw feature values, subject-label
    pairs, or real customer data.
    """
    options = ServiceOptions.from_settings()
    cache = get_service_cache(options.max_cache_entries, options.cache_ttl_seconds)

    return {
        "package": "muleguard.backend.correlation.service",
        "version": SERVICE_VERSION,
        "component_order": list(COMPONENT_ORDER),
        "analysis_statuses": [status.value for status in AnalysisStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "cache": cache.safe_summary(),
        "components": {
            COMPONENT_NORMALIZER: _NORMALIZE_IMPL is not None,
            COMPONENT_EXACT_REFERENCE: _EXACT_REFERENCE_IMPL is not None,
            COMPONENT_IDENTIFIER_MATCH: _IDENTIFIER_MATCH_IMPL is not None,
            COMPONENT_ENTITY_ASSOCIATION: _ENTITY_ASSOCIATION_IMPL is not None,
            COMPONENT_TEMPORAL_ASSOCIATION: _TEMPORAL_ASSOCIATION_IMPL is not None,
            COMPONENT_NARRATIVE_EXTRACTION: _NARRATIVE_EXTRACTION_IMPL is not None,
            COMPONENT_CONFIDENCE: _CONFIDENCE_IMPL is not None,
        },
        "hard_limits": {
            "max_records": HARD_MAX_RECORDS,
            "max_candidates": HARD_MAX_CANDIDATES,
            "max_confidence_records": HARD_MAX_CONFIDENCE_RECORDS,
            "max_sample_candidates": HARD_MAX_SAMPLE_CANDIDATES,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
            "max_cache_entries": HARD_MAX_CACHE_ENTRIES,
            "max_cache_ttl_seconds": HARD_MAX_CACHE_TTL_SECONDS,
        },
        "forbidden_field_count": len(FORBIDDEN_FIELDS),
        "label_leakage_field_count": len(LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(PROHIBITED_ACTION_TOKENS),
        "summary_item_limit": max(1, int(limit)),
        "caveats": list(SERVICE_CAVEATS),
        "safety_flags": dict(SERVICE_SAFETY_FLAGS),
    }


__all__ = [
    "AnalysisStatus",
    "ComponentReport",
    "CorrelationServiceEngine",
    "IssueSeverity",
    "SERVICE_VERSION",
    "ServiceCache",
    "ServiceIssue",
    "ServiceOptions",
    "ServiceRequest",
    "ServiceResult",
    "clear_service_cache",
    "correlate_through_service",
    "execute_correlation_pipeline",
    "export_service_summary",
    "get_service_cache",
    "get_service_engine",
    "get_service_health",
    "get_service_metadata",
    "get_service_options",
    "run_correlation_service",
]