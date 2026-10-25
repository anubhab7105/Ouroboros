"""
MULEGUARD backend rules evidence.

This module provides the canonical bounded investigative-evidence boundary for
the synthetic MULEGUARD prototype.

Primary responsibilities:

- define, validate, package, seal, verify, export, import, register, and
  summarize safe investigative evidence bundles for bounded synthetic
  workflows;
- preserve privacy by using salted one-way pseudonymous subject/source/case/
  actor hashes and by excluding raw feature values, raw identifiers, raw
  narratives, subject-label pairs, secrets, tokens, passwords, database URLs,
  filesystem paths, and model artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited evidence fields;
- provide deterministic integrity seals, bounded chain-of-custody events,
  safe evidence fingerprints, validation reports, and API-safe exports;
- enforce strict product-safety constraints, including absolute prohibition of
  automatic adverse customer action;
- maintain a bounded process-local evidence registry for local prototype
  workflows, tests, developer tooling, and offline evaluation harnesses;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module packages investigative evidence metadata only. It does not train
models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, adjudicate guilt, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for evidence packaging, sealing,
  verification, export, import, or debugging.
- Evidence bundles are investigative prioritization artefacts only. They are
  not proof of wrongdoing.
- Evidence scores, references, summaries, and chain events are operational
  attributions only. They are not causal proof.
- Labels must never be used as evidence payload fields.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as evidence fields.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden retained inputs. Subject, source, case, and
  actor linkage is pseudonymous and salted.
- Evidence handling must never trigger automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable capabilities are reported honestly rather than
  invented.
- The bundled evidence registry is process-local, non-durable, and bounded for
  local prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external evidence stores.
- This module does not deploy, promote, retire, upload, replace, or serve
  production evidence systems.
- This module does not generate synthetic ingestion records.
- This module does not replace ingestion validation.
- This module does not replace feature schema validation.
- This module is not a durable evidence management system.
- This module is not a legal evidence locker.
- This module is not a chain-of-custody certification system.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, rule
evaluations, threshold profiles, evidence bundles, explanations, validation
reports, and case dispositions are investigative leads or human workflow
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


logger = logging.getLogger("muleguard.backend.rules.evidence")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

EVIDENCE_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.rules.evidence.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_ITEMS: Final[int] = 256
_HARD_MAX_ITEMS: Final[int] = 10_000

_DEFAULT_MAX_CHAIN_EVENTS: Final[int] = 128
_HARD_MAX_CHAIN_EVENTS: Final[int] = 10_000

_DEFAULT_MAX_BUNDLES: Final[int] = 1_000
_HARD_MAX_BUNDLES: Final[int] = 10_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_TIME_MS: Final[int] = 20_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256
_MAX_ITEM_SUMMARY_LENGTH: Final[int] = 180
_MAX_BUNDLE_NAME_LENGTH: Final[int] = 200
_MAX_BUNDLE_DESCRIPTION_LENGTH: Final[int] = 500
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
    "subject_ref",
    "subject_hash",
    "subject",
    "account_id",
    "acct_id",
)

_SOURCE_REF_KEYS: Final[tuple[str, ...]] = (
    "source_ref_hash",
    "source_ref",
    "source_hash",
    "source_id",
    "alert_id",
    "event_ref",
    "record_ref",
)

_CASE_REF_KEYS: Final[tuple[str, ...]] = (
    "case_ref_hash",
    "case_ref",
    "case_hash",
    "case_id",
)

_ACTOR_REF_KEYS: Final[tuple[str, ...]] = (
    "actor_ref_hash",
    "actor_ref",
    "actor_hash",
    "reviewer_ref",
    "reviewer_id",
    "actor_id",
)

_ITEM_ID_KEYS: Final[tuple[str, ...]] = (
    "item_id",
    "evidence_id",
    "id",
)

_NON_EVIDENCE_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        "caveats",
        "counts",
        "issues",
        "metadata",
        "safety_flags",
        "validation",
    }
)

_FORBIDDEN_EVIDENCE_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_EVIDENCE_TOKENS: Final[tuple[str, ...]] = (
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

_NARRATIVE_HINT_TOKENS: Final[tuple[str, ...]] = (
    "customer said",
    "user said",
    "complaint text",
    "narrative",
    "allegation",
    "accused",
    "fraudster",
    "criminal",
    "guilty",
    "innocent",
)

_EVIDENCE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic evidence packaging only. Do not use with real customer data.",
    "Evidence bundles are investigative prioritization artefacts only and are not proof of wrongdoing.",
    "Evidence summaries and chain events are operational attributions only and are not causal proof.",
    "Evidence handling must not trigger automatic adverse customer action.",
    "Labels must never be used as evidence payload fields.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected as evidence fields.",
    "Raw complaint narratives and raw identifiers are forbidden retained inputs.",
    "Unavailable evidence or seals are reported honestly as unavailable rather than invented.",
    "The bundled evidence registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
    "Evidence seals are deterministic local integrity markers, not legal signatures.",
)

_EVIDENCE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_labels_as_evidence_fields": True,
        "no_raw_values_in_public_summaries": True,
        "no_ground_truth_fields_accepted": True,
        "no_fraud_label_fields_accepted": True,
        "no_scenario_ids_accepted": True,
        "no_fraud_ring_ids_accepted": True,
        "no_raw_narratives_accepted": True,
        "no_raw_identifiers_retained": True,
        "no_secrets_accepted": True,
        "no_tokens_accepted": True,
        "no_passwords_accepted": True,
        "no_database_urls_accepted": True,
        "no_model_artifact_paths_accepted": True,
        "salted_pseudonymous_reference_hashes": True,
        "deterministic_evidence_sealing": True,
        "bounded_evidence_packaging_required": True,
        "evidence_is_investigative_lead_only": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
        "not_legal_evidence_locker": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class EvidenceClass(str, Enum):
    """
    Bounded investigative evidence item class.
    """

    ALERT = "alert"
    RULE_MATCH = "rule_match"
    MODEL_SCORE = "model_score"
    ANOMALY_SCORE = "anomaly_score"
    FALLBACK_SCORE = "fallback_score"
    THRESHOLD = "threshold"
    EXPLANATION = "explanation"
    VALIDATION = "validation"
    GRAPH_RELATIONSHIP = "graph_relationship"
    COMPLAINT_CORRELATION = "complaint_correlation"
    CASE_REFERENCE = "case_reference"
    HUMAN_REVIEW_REFERENCE = "human_review_reference"
    OPERATIONAL_ANNOTATION = "operational_annotation"


class EvidenceStatus(str, Enum):
    """
    Evidence bundle lifecycle status.
    """

    DRAFT = "draft"
    SEALED = "sealed"
    VERIFIED = "verified"
    RETIRED = "retired"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"


class EvidenceSensitivity(str, Enum):
    """
    Bounded operational sensitivity label.

    This does not imply real PII is present. It is a prototype handling hint.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntegrityAlgorithm(str, Enum):
    """
    Bounded local integrity algorithm.
    """

    SHA256 = "sha256"
    HMAC_SHA256 = "hmac_sha256"


class ChainEventType(str, Enum):
    """
    Bounded process-local chain-of-custody event type.
    """

    CREATED = "created"
    VALIDATED = "validated"
    SEALED = "sealed"
    VERIFIED = "verified"
    EXPORTED = "exported"
    IMPORTED = "imported"
    REGISTERED = "registered"
    RETIRED = "retired"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    ANNOTATED = "annotated"


class EvidenceValidationStatus(str, Enum):
    """
    Overall evidence validation status.
    """

    PASSED = "PASSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


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
    return max(minimum, min(_as_int(value, default), maximum))


def _clamp_float(value: object, minimum: float, maximum: float, default: float) -> float:
    return max(minimum, min(_as_float(value, default), maximum))


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

    if canonical in _FORBIDDEN_EVIDENCE_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_EVIDENCE_TOKENS)


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

    return (
        any(token in canonical for token in _SENSITIVE_DETAIL_TOKENS)
        or _is_label_leakage_key(canonical)
    )


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

    return False


def _looks_like_narrative(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    text = _clean_text(value, 2000).lower()

    if not text:
        return False

    words = text.split()

    if len(words) >= 15 and len(text) >= 80:
        return True

    return any(token in text for token in _NARRATIVE_HINT_TOKENS)


def _sanitize_safe_text(value: Any, limit: int = _MAX_REASON_TEXT_LENGTH) -> str:
    text = _clean_text(value, limit)

    if not text:
        return ""

    if _contains_prohibited_action(text):
        return "[prohibited action omitted]"

    if _looks_like_sensitive_literal(text):
        return "[redacted]"

    if _looks_like_narrative(text):
        return "[redacted narrative-like text]"

    return text


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

        if _looks_like_sensitive_literal(text) or _looks_like_narrative(text):
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

            if not key or _is_sensitive_detail_key(key) or _is_forbidden_key(key):
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:100]]

    return f"<{type(value).__name__}>"


def _as_mapping(value: Any) -> dict[str, Any]:
    sanitized = _safe_detail_value(value)
    return sanitized if isinstance(sanitized, dict) else {}


def _sanitize_metadata(value: Any) -> dict[str, Any]:
    clean = _as_mapping(value)

    if not clean:
        return {}

    if _contains_prohibited_action(clean):
        return {"prohibited_action_detected": True}

    return clean


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


def _normalize_tag(value: Any) -> str:
    token = _normalize_token(value)

    if not token or _contains_prohibited_action(token):
        return ""

    return _clean_text(token, 100)


def _normalize_tags(value: Any, limit: int = 50) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        tag = _normalize_tag(item)

        if tag:
            out.append(tag)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


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


def _coerce_safe_hash(value: Any) -> Optional[str]:
    text = _clean_text(value, _MAX_SUBJECT_HASH_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    return None


def _record_get(record: Any, keys: Sequence[str], default: Any = None) -> Any:
    if isinstance(record, Mapping):
        for key in keys:
            if key in record:
                return record[key]

        return default

    for key in keys:
        value = getattr(record, key, _MISSING)

        if value is not _MISSING:
            return value

    return default


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceIssue:
    """
    Safe evidence issue.

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
        object.__setattr__(self, "details", _as_mapping(self.details))

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


def _as_issue(value: Any) -> EvidenceIssue:
    if isinstance(value, EvidenceIssue):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(EvidenceIssue, "__dataclass_fields__", {}).keys())
        clean = {key: item for key, item in value.items() if key in fields}

        try:
            return EvidenceIssue(**clean)
        except Exception:
            return EvidenceIssue(
                severity=IssueSeverity.WARNING,
                code="malformed_issue",
                message="Malformed issue omitted.",
            )

    return EvidenceIssue(
        severity=IssueSeverity.WARNING,
        code="invalid_issue",
        message="Invalid issue omitted.",
    )


def _append_issue(
    issues: list[EvidenceIssue],
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

        issues[-1] = EvidenceIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        EvidenceIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[EvidenceIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[Any]) -> tuple[EvidenceIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[EvidenceIssue] = []

    for issue in issues:
        item = _as_issue(issue)
        key = (item.severity.value, item.code, item.message, item.field)

        if key in seen:
            continue

        seen.add(key)
        out.append(item)

    return tuple(out)


def _truncate_issues(
    issues: Sequence[Any],
    max_issues: int = _DEFAULT_MAX_ISSUES,
) -> tuple[EvidenceIssue, ...]:
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
# Payload and fingerprint helpers
# -----------------------------------------------------------------------------


def _item_payload(item: Any) -> dict[str, Any]:
    return {
        "item_id": _clean_text(getattr(item, "item_id", ""), 128).lower(),
        "evidence_class": _enum_value(getattr(item, "evidence_class", EvidenceClass.OPERATIONAL_ANNOTATION), EvidenceClass.OPERATIONAL_ANNOTATION.value),
        "subject_ref_hash": _coerce_safe_hash(getattr(item, "subject_ref_hash", None)),
        "source_ref_hash": _coerce_safe_hash(getattr(item, "source_ref_hash", None)),
        "source_system": _normalize_token(getattr(item, "source_system", "")),
        "summary": _sanitize_safe_text(getattr(item, "summary", ""), _MAX_ITEM_SUMMARY_LENGTH),
        "metadata": _sanitize_metadata(getattr(item, "metadata", {}) or {}),
        "created_at": _ensure_utc(getattr(item, "created_at", None)) or _now_utc(),
        "sensitivity": _enum_value(getattr(item, "sensitivity", EvidenceSensitivity.LOW), EvidenceSensitivity.LOW.value),
        "payload_hash": _coerce_safe_hash(getattr(item, "payload_hash", None)),
    }


def _item_fingerprint(item: Any) -> str:
    return _fingerprint_payload(_item_payload(item))


def _event_payload(event: Any) -> dict[str, Any]:
    return {
        "event_id": _clean_text(getattr(event, "event_id", ""), 128).lower(),
        "bundle_id": _clean_text(getattr(event, "bundle_id", ""), 128).lower(),
        "event_type": _enum_value(getattr(event, "event_type", ChainEventType.ANNOTATED), ChainEventType.ANNOTATED.value),
        "actor_ref_hash": _coerce_safe_hash(getattr(event, "actor_ref_hash", None)),
        "occurred_at": _ensure_utc(getattr(event, "occurred_at", None)) or _now_utc(),
        "details": _sanitize_metadata(getattr(event, "details", {}) or {}),
        "previous_event_hash": _coerce_safe_hash(getattr(event, "previous_event_hash", None)),
    }


def _event_fingerprint(event: Any) -> str:
    return _fingerprint_payload(_event_payload(event))


def _seal_payload(seal: Any) -> Optional[dict[str, Any]]:
    if seal is None:
        return None

    return {
        "algorithm": _enum_value(getattr(seal, "algorithm", IntegrityAlgorithm.HMAC_SHA256), IntegrityAlgorithm.HMAC_SHA256.value),
        "sealed_at": _ensure_utc(getattr(seal, "sealed_at", None)) or _now_utc(),
        "bundle_fingerprint": _clean_text(getattr(seal, "bundle_fingerprint", ""), 128).lower(),
        "payload_digest": _clean_text(getattr(seal, "payload_digest", ""), 128).lower(),
        "seal_hmac": _clean_text(getattr(seal, "seal_hmac", ""), 128).lower(),
        "verifier_ref_hash": _coerce_safe_hash(getattr(seal, "verifier_ref_hash", None)),
        "metadata": _sanitize_metadata(getattr(seal, "metadata", {}) or {}),
    }


def _bundle_content_payload(bundle: Any) -> dict[str, Any]:
    items = []

    for item in getattr(bundle, "items", ()) or ():
        if hasattr(item, "to_dict"):
            items.append(item.to_dict())
        else:
            items.append(_item_payload(item))

    events = []

    for event in getattr(bundle, "chain_events", ()) or ():
        if hasattr(event, "to_dict"):
            events.append(event.to_dict())
        else:
            events.append(_event_payload(event))

    return {
        "bundle_id": _clean_text(getattr(bundle, "bundle_id", ""), 128).lower(),
        "name": _sanitize_safe_text(getattr(bundle, "name", ""), _MAX_BUNDLE_NAME_LENGTH),
        "description": _sanitize_safe_text(getattr(bundle, "description", ""), _MAX_BUNDLE_DESCRIPTION_LENGTH),
        "subject_ref_hash": _coerce_safe_hash(getattr(bundle, "subject_ref_hash", None)),
        "case_ref_hash": _coerce_safe_hash(getattr(bundle, "case_ref_hash", None)),
        "status": _enum_value(getattr(bundle, "status", EvidenceStatus.DRAFT), EvidenceStatus.DRAFT.value),
        "sensitivity": _enum_value(getattr(bundle, "sensitivity", EvidenceSensitivity.LOW), EvidenceSensitivity.LOW.value),
        "items": items,
        "chain_events": events,
        "tags": list(getattr(bundle, "tags", ()) or ()),
        "metadata": _sanitize_metadata(getattr(bundle, "metadata", {}) or {}),
        "created_at": _ensure_utc(getattr(bundle, "created_at", None)) or _now_utc(),
        "updated_at": _ensure_utc(getattr(bundle, "updated_at", None)) or _now_utc(),
    }


def _bundle_identity_payload(bundle: Any) -> dict[str, Any]:
    payload = _bundle_content_payload(bundle)
    payload["seal"] = _seal_payload(getattr(bundle, "seal", None))
    return payload


def _compute_bundle_digest(bundle: Any) -> str:
    return _fingerprint_payload(_bundle_content_payload(bundle))


def _compute_bundle_fingerprint(bundle: Any) -> str:
    return _fingerprint_payload(_bundle_identity_payload(bundle))


def _genesis_hash(bundle_id: Any) -> str:
    return _sha256_hex(f"muleguard.rules.evidence.genesis|{_clean_text(bundle_id, 128).lower()}")


# -----------------------------------------------------------------------------
# Evidence models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """
    One bounded investigative evidence item.

    Evidence items contain safe operational metadata only. Raw narratives,
    raw identifiers, raw labels, secrets, and artifact paths are omitted or
    rejected.
    """

    item_id: str = ""
    evidence_class: Any = EvidenceClass.OPERATIONAL_ANNOTATION
    subject_ref_hash: Optional[str] = None
    source_ref_hash: Optional[str] = None
    source_system: str = ""
    summary: str = ""
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    created_at: datetime = dataclass_field(default_factory=_now_utc)
    sensitivity: Any = EvidenceSensitivity.LOW
    payload_hash: Optional[str] = None
    item_fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "item_id", _clean_text(self.item_id, 128).lower())
        object.__setattr__(
            self,
            "evidence_class",
            _normalize_enum_option(EvidenceClass, self.evidence_class, EvidenceClass.OPERATIONAL_ANNOTATION),
        )
        object.__setattr__(
            self,
            "sensitivity",
            _normalize_enum_option(EvidenceSensitivity, self.sensitivity, EvidenceSensitivity.LOW),
        )
        object.__setattr__(self, "subject_ref_hash", _coerce_safe_hash(self.subject_ref_hash))
        object.__setattr__(self, "source_ref_hash", _coerce_safe_hash(self.source_ref_hash))
        object.__setattr__(self, "payload_hash", _coerce_safe_hash(self.payload_hash))

        source_system = _normalize_token(self.source_system)

        if _is_forbidden_key(source_system) or _contains_prohibited_action(source_system):
            source_system = ""

        object.__setattr__(self, "source_system", source_system)
        object.__setattr__(self, "summary", _sanitize_safe_text(self.summary, _MAX_ITEM_SUMMARY_LENGTH))
        object.__setattr__(self, "metadata", MappingProxyType(_sanitize_metadata(self.metadata)))
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())

        if not self.item_fingerprint:
            object.__setattr__(self, "item_fingerprint", _item_fingerprint(self))

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "evidence_class": _enum_value(self.evidence_class, EvidenceClass.OPERATIONAL_ANNOTATION.value),
            "subject_ref_hash": self.subject_ref_hash,
            "source_ref_hash": self.source_ref_hash,
            "source_system": self.source_system,
            "summary": self.summary,
            "metadata": _safe_detail_value(self.metadata),
            "created_at": self.created_at.isoformat(),
            "sensitivity": _enum_value(self.sensitivity, EvidenceSensitivity.LOW.value),
            "payload_hash": self.payload_hash,
            "item_fingerprint": self.item_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class EvidenceChainEvent:
    """
    One bounded process-local chain-of-custody event.

    This is not a legal custody record. It is a deterministic local integrity
    marker for prototype workflows.
    """

    event_id: str = ""
    bundle_id: str = ""
    event_type: Any = ChainEventType.ANNOTATED
    actor_ref_hash: Optional[str] = None
    occurred_at: datetime = dataclass_field(default_factory=_now_utc)
    details: Mapping[str, Any] = dataclass_field(default_factory=dict)
    previous_event_hash: Optional[str] = None
    event_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _clean_text(self.event_id, 128).lower())
        object.__setattr__(self, "bundle_id", _clean_text(self.bundle_id, 128).lower())
        object.__setattr__(
            self,
            "event_type",
            _normalize_enum_option(ChainEventType, self.event_type, ChainEventType.ANNOTATED),
        )
        object.__setattr__(self, "actor_ref_hash", _coerce_safe_hash(self.actor_ref_hash))
        object.__setattr__(self, "previous_event_hash", _coerce_safe_hash(self.previous_event_hash))
        object.__setattr__(self, "occurred_at", _ensure_utc(self.occurred_at) or _now_utc())
        object.__setattr__(self, "details", MappingProxyType(_sanitize_metadata(self.details)))

        if not self.event_hash:
            object.__setattr__(self, "event_hash", _event_fingerprint(self))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "bundle_id": self.bundle_id,
            "event_type": _enum_value(self.event_type, ChainEventType.ANNOTATED.value),
            "actor_ref_hash": self.actor_ref_hash,
            "occurred_at": self.occurred_at.isoformat(),
            "details": _safe_detail_value(self.details),
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
        }


@dataclass(frozen=True, slots=True)
class EvidenceSeal:
    """
    One bounded deterministic local integrity seal.

    This is not a production cryptographic signature and not a legal seal.
    """

    algorithm: Any = IntegrityAlgorithm.HMAC_SHA256
    sealed_at: datetime = dataclass_field(default_factory=_now_utc)
    bundle_fingerprint: str = ""
    payload_digest: str = ""
    seal_hmac: str = ""
    verifier_ref_hash: Optional[str] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "algorithm",
            _normalize_enum_option(IntegrityAlgorithm, self.algorithm, IntegrityAlgorithm.HMAC_SHA256),
        )
        object.__setattr__(self, "sealed_at", _ensure_utc(self.sealed_at) or _now_utc())
        object.__setattr__(self, "bundle_fingerprint", _clean_text(self.bundle_fingerprint, 128).lower())
        object.__setattr__(self, "payload_digest", _clean_text(self.payload_digest, 128).lower())
        object.__setattr__(self, "seal_hmac", _clean_text(self.seal_hmac, 128).lower())
        object.__setattr__(self, "verifier_ref_hash", _coerce_safe_hash(self.verifier_ref_hash))
        object.__setattr__(self, "metadata", MappingProxyType(_sanitize_metadata(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": _enum_value(self.algorithm, IntegrityAlgorithm.HMAC_SHA256.value),
            "sealed_at": self.sealed_at.isoformat(),
            "bundle_fingerprint": self.bundle_fingerprint,
            "payload_digest": self.payload_digest,
            "seal_hmac": self.seal_hmac,
            "verifier_ref_hash": self.verifier_ref_hash,
            "metadata": _safe_detail_value(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """
    One bounded investigative evidence bundle.

    Evidence bundles are synthetic operational artefacts only. They are not
    proof of wrongdoing and must not trigger automatic adverse customer action.
    """

    bundle_id: str = ""
    name: str = ""
    description: str = ""
    subject_ref_hash: Optional[str] = None
    case_ref_hash: Optional[str] = None
    status: Any = EvidenceStatus.DRAFT
    sensitivity: Any = EvidenceSensitivity.LOW
    items: tuple[EvidenceItem, ...] = ()
    chain_events: tuple[EvidenceChainEvent, ...] = ()
    tags: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    created_at: datetime = dataclass_field(default_factory=_now_utc)
    updated_at: datetime = dataclass_field(default_factory=_now_utc)
    seal: Optional[EvidenceSeal] = None
    fingerprint: str = ""

    def __post_init__(self) -> None:
        items = tuple(
            item
            for item in (_coerce_evidence_item(value) for value in _as_sequence(self.items))
            if item is not None
        )[:_HARD_MAX_ITEMS]

        events = tuple(
            event
            for event in (_coerce_evidence_event(value) for value in _as_sequence(self.chain_events))
            if event is not None
        )[:_HARD_MAX_CHAIN_EVENTS]

        object.__setattr__(self, "bundle_id", _clean_text(self.bundle_id, 128).lower())
        object.__setattr__(self, "name", _sanitize_safe_text(self.name, _MAX_BUNDLE_NAME_LENGTH))
        object.__setattr__(self, "description", _sanitize_safe_text(self.description, _MAX_BUNDLE_DESCRIPTION_LENGTH))
        object.__setattr__(self, "subject_ref_hash", _coerce_safe_hash(self.subject_ref_hash))
        object.__setattr__(self, "case_ref_hash", _coerce_safe_hash(self.case_ref_hash))

        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(EvidenceStatus, self.status, EvidenceStatus.DRAFT),
        )
        object.__setattr__(
            self,
            "sensitivity",
            _normalize_enum_option(EvidenceSensitivity, self.sensitivity, EvidenceSensitivity.LOW),
        )

        object.__setattr__(self, "items", items)
        object.__setattr__(self, "chain_events", events)
        object.__setattr__(self, "tags", _normalize_tags(self.tags))
        object.__setattr__(self, "metadata", MappingProxyType(_sanitize_metadata(self.metadata)))
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())
        object.__setattr__(self, "updated_at", _ensure_utc(self.updated_at) or _now_utc())
        object.__setattr__(self, "seal", _coerce_evidence_seal(self.seal))

        if not self.name:
            object.__setattr__(self, "name", self.bundle_id or "unnamed_evidence_bundle")

        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", _compute_bundle_fingerprint(self))

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "name": self.name,
            "description": self.description,
            "subject_ref_hash": self.subject_ref_hash,
            "case_ref_hash": self.case_ref_hash,
            "status": _enum_value(self.status, EvidenceStatus.DRAFT.value),
            "sensitivity": _enum_value(self.sensitivity, EvidenceSensitivity.LOW.value),
            "items": [item.to_dict() for item in self.items],
            "chain_events": [event.to_dict() for event in self.chain_events],
            "tags": list(self.tags),
            "metadata": _safe_detail_value(self.metadata),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "seal": self.seal.to_dict() if self.seal is not None else None,
            "fingerprint": self.fingerprint,
            "caveats": list(_EVIDENCE_CAVEATS),
            "safety_flags": dict(_EVIDENCE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Coercion helpers
# -----------------------------------------------------------------------------


def _coerce_evidence_item(
    value: Any,
    options: "EvidenceOptions | None" = None,
    issues: Optional[list[EvidenceIssue]] = None,
) -> Optional[EvidenceItem]:
    if isinstance(value, EvidenceItem):
        return value

    if isinstance(value, Mapping):
        item_id = _record_get(value, _ITEM_ID_KEYS)
        subject_raw = _record_get(value, _SUBJECT_KEYS)
        source_raw = _record_get(value, _SOURCE_REF_KEYS)

        if options is not None:
            subject_hash = _hash_ref(subject_raw, options)
            source_hash = _hash_ref(source_raw, options)
        else:
            subject_hash = _coerce_safe_hash(subject_raw)
            source_hash = _coerce_safe_hash(source_raw)

        if issues is not None and subject_raw is not None and subject_hash is None:
            _append_issue(
                issues,
                options.max_issues if options is not None else _DEFAULT_MAX_ISSUES,
                severity=IssueSeverity.WARNING,
                code="evidence_subject_ref_omitted",
                message="Evidence subject reference was omitted because it was not safe to retain.",
                details={"item_id": _clean_text(item_id, 128) if item_id else None},
            )

        try:
            return EvidenceItem(
                item_id=_clean_text(item_id, 128).lower(),
                evidence_class=_record_get(value, ("evidence_class", "class", "kind"), EvidenceClass.OPERATIONAL_ANNOTATION),
                subject_ref_hash=subject_hash,
                source_ref_hash=source_hash,
                source_system=_record_get(value, ("source_system", "source", "producer"), ""),
                summary=_record_get(value, ("summary", "message", "reason", "note"), ""),
                metadata=_record_get(value, ("metadata", "details", "attributes"), {}),
                created_at=_record_get(value, ("created_at", "timestamp", "occurred_at"), _now_utc()),
                sensitivity=_record_get(value, ("sensitivity", "handling"), EvidenceSensitivity.LOW),
                payload_hash=_record_get(value, ("payload_hash", "content_hash", "hash"), None),
            )
        except Exception:
            return None

    text = _sanitize_safe_text(value, _MAX_ITEM_SUMMARY_LENGTH)

    if text:
        return EvidenceItem(
            evidence_class=EvidenceClass.OPERATIONAL_ANNOTATION,
            summary=text,
        )

    return None


def _coerce_evidence_event(
    value: Any,
    options: "EvidenceOptions | None" = None,
    issues: Optional[list[EvidenceIssue]] = None,
) -> Optional[EvidenceChainEvent]:
    if isinstance(value, EvidenceChainEvent):
        return value

    if isinstance(value, Mapping):
        actor_raw = _record_get(value, _ACTOR_REF_KEYS)

        if options is not None:
            actor_hash = _hash_ref(actor_raw, options)
        else:
            actor_hash = _coerce_safe_hash(actor_raw)

        if issues is not None and actor_raw is not None and actor_hash is None:
            _append_issue(
                issues,
                options.max_issues if options is not None else _DEFAULT_MAX_ISSUES,
                severity=IssueSeverity.WARNING,
                code="evidence_actor_ref_omitted",
                message="Evidence actor reference was omitted because it was not safe to retain.",
            )

        try:
            return EvidenceChainEvent(
                event_id=_clean_text(_record_get(value, ("event_id", "id"), ""), 128).lower(),
                bundle_id=_clean_text(_record_get(value, ("bundle_id", "evidence_bundle_id"), ""), 128).lower(),
                event_type=_record_get(value, ("event_type", "type", "action"), ChainEventType.ANNOTATED),
                actor_ref_hash=actor_hash,
                occurred_at=_record_get(value, ("occurred_at", "timestamp", "created_at"), _now_utc()),
                details=_record_get(value, ("details", "metadata", "attributes"), {}),
                previous_event_hash=_record_get(value, ("previous_event_hash", "prev_hash"), None),
                event_hash=_record_get(value, ("event_hash", "hash"), ""),
            )
        except Exception:
            return None

    return None


def _coerce_evidence_seal(value: Any) -> Optional[EvidenceSeal]:
    if value is None:
        return None

    if isinstance(value, EvidenceSeal):
        return value

    if isinstance(value, Mapping):
        try:
            return EvidenceSeal(
                algorithm=value.get("algorithm", IntegrityAlgorithm.HMAC_SHA256),
                sealed_at=value.get("sealed_at", _now_utc()),
                bundle_fingerprint=value.get("bundle_fingerprint", ""),
                payload_digest=value.get("payload_digest", ""),
                seal_hmac=value.get("seal_hmac", ""),
                verifier_ref_hash=value.get("verifier_ref_hash"),
                metadata=value.get("metadata", {}),
            )
        except Exception:
            return None

    return None


def _coerce_evidence_bundle(
    value: Any,
    options: "EvidenceOptions | None" = None,
    issues: Optional[list[EvidenceIssue]] = None,
) -> Optional[EvidenceBundle]:
    if isinstance(value, EvidenceBundle):
        return value

    if not isinstance(value, Mapping):
        return None

    subject_raw = _record_get(value, _SUBJECT_KEYS)
    case_raw = _record_get(value, _CASE_REF_KEYS)

    if options is not None:
        subject_hash = _hash_ref(subject_raw, options)
        case_hash = _hash_ref(case_raw, options)
    else:
        subject_hash = _coerce_safe_hash(subject_raw)
        case_hash = _coerce_safe_hash(case_raw)

    items = [
        item
        for item in (
            _coerce_evidence_item(item_value, options, issues)
            for item_value in _as_sequence(value.get("items", ()))
        )
        if item is not None
    ]

    events = [
        event
        for event in (
            _coerce_evidence_event(event_value, options, issues)
            for event_value in _as_sequence(value.get("chain_events", value.get("events", ())))
        )
        if event is not None
    ]

    try:
        return EvidenceBundle(
            bundle_id=_clean_text(value.get("bundle_id", value.get("id", "")), 128).lower(),
            name=value.get("name", ""),
            description=value.get("description", ""),
            subject_ref_hash=subject_hash,
            case_ref_hash=case_hash,
            status=value.get("status", EvidenceStatus.DRAFT),
            sensitivity=value.get("sensitivity", EvidenceSensitivity.LOW),
            items=tuple(items),
            chain_events=tuple(events),
            tags=value.get("tags", ()),
            metadata=value.get("metadata", {}),
            created_at=value.get("created_at", _now_utc()),
            updated_at=value.get("updated_at", _now_utc()),
            seal=_coerce_evidence_seal(value.get("seal")),
            fingerprint=_clean_text(value.get("fingerprint", ""), 128).lower(),
        )
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceOptions:
    """
    Bounded evidence-policy options.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    max_items: int = _DEFAULT_MAX_ITEMS
    max_chain_events: int = _DEFAULT_MAX_CHAIN_EVENTS
    max_bundles: int = _DEFAULT_MAX_BUNDLES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    max_item_summary_length: int = _MAX_ITEM_SUMMARY_LENGTH
    max_bundle_name_length: int = _MAX_BUNDLE_NAME_LENGTH
    max_bundle_description_length: int = _MAX_BUNDLE_DESCRIPTION_LENGTH

    require_subject_hash: bool = False
    auto_seal_on_create: bool = False
    register_bundles: bool = True
    verify_on_register: bool = True
    include_chain_events: bool = True
    redact_sensitive_literals: bool = True
    drop_prohibited_actions: bool = True

    retention_policy: str = "process_local_only"

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

        object.__setattr__(self, "max_items", _clamp_int(self.max_items, 1, _HARD_MAX_ITEMS, _DEFAULT_MAX_ITEMS))
        object.__setattr__(
            self,
            "max_chain_events",
            _clamp_int(self.max_chain_events, 1, _HARD_MAX_CHAIN_EVENTS, _DEFAULT_MAX_CHAIN_EVENTS),
        )
        object.__setattr__(self, "max_bundles", _clamp_int(self.max_bundles, 1, _HARD_MAX_BUNDLES, _DEFAULT_MAX_BUNDLES))
        object.__setattr__(self, "max_issues", _clamp_int(self.max_issues, 1, _HARD_MAX_ISSUES, _DEFAULT_MAX_ISSUES))
        object.__setattr__(
            self,
            "max_summary_items",
            _clamp_int(self.max_summary_items, 1, _HARD_MAX_SUMMARY_ITEMS, _DEFAULT_MAX_SUMMARY_ITEMS),
        )
        object.__setattr__(self, "max_time_ms", _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS))

        object.__setattr__(
            self,
            "max_item_summary_length",
            _clamp_int(self.max_item_summary_length, 20, 512, _MAX_ITEM_SUMMARY_LENGTH),
        )
        object.__setattr__(
            self,
            "max_bundle_name_length",
            _clamp_int(self.max_bundle_name_length, 20, 512, _MAX_BUNDLE_NAME_LENGTH),
        )
        object.__setattr__(
            self,
            "max_bundle_description_length",
            _clamp_int(self.max_bundle_description_length, 40, 1024, _MAX_BUNDLE_DESCRIPTION_LENGTH),
        )

        object.__setattr__(self, "require_subject_hash", _as_bool(self.require_subject_hash, False))
        object.__setattr__(self, "auto_seal_on_create", _as_bool(self.auto_seal_on_create, False))
        object.__setattr__(self, "register_bundles", _as_bool(self.register_bundles, True))
        object.__setattr__(self, "verify_on_register", _as_bool(self.verify_on_register, True))
        object.__setattr__(self, "include_chain_events", _as_bool(self.include_chain_events, True))
        object.__setattr__(self, "redact_sensitive_literals", _as_bool(self.redact_sensitive_literals, True))
        object.__setattr__(self, "drop_prohibited_actions", _as_bool(self.drop_prohibited_actions, True))
        object.__setattr__(
            self,
            "retention_policy",
            _normalize_token(self.retention_policy) or "process_local_only",
        )

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "EvidenceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "RULES_EVIDENCE_SALT", None)
            or _setting(settings, "RULES_THRESHOLD_SALT", None)
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
            enabled=_as_bool(_setting(settings, "RULES_EVIDENCE_ENABLED", True), True)
            and _as_bool(_setting(settings, "RULES_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "RULES_EVIDENCE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "RULES_EVIDENCE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "RULES_EVIDENCE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "RULES_EVIDENCE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_items=_as_int(_setting(settings, "RULES_EVIDENCE_MAX_ITEMS", _DEFAULT_MAX_ITEMS), _DEFAULT_MAX_ITEMS),
            max_chain_events=_as_int(
                _setting(settings, "RULES_EVIDENCE_MAX_CHAIN_EVENTS", _DEFAULT_MAX_CHAIN_EVENTS),
                _DEFAULT_MAX_CHAIN_EVENTS,
            ),
            max_bundles=_as_int(
                _setting(settings, "RULES_EVIDENCE_MAX_BUNDLES", _DEFAULT_MAX_BUNDLES),
                _DEFAULT_MAX_BUNDLES,
            ),
            max_issues=_as_int(
                _setting(settings, "RULES_EVIDENCE_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "RULES_EVIDENCE_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "RULES_EVIDENCE_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS),
                _DEFAULT_MAX_TIME_MS,
            ),
            require_subject_hash=_as_bool(
                _setting(settings, "RULES_EVIDENCE_REQUIRE_SUBJECT_HASH", False),
                False,
            ),
            auto_seal_on_create=_as_bool(
                _setting(settings, "RULES_EVIDENCE_AUTO_SEAL_ON_CREATE", False),
                False,
            ),
            register_bundles=_as_bool(
                _setting(settings, "RULES_EVIDENCE_REGISTER_BUNDLES", True),
                True,
            ),
            verify_on_register=_as_bool(
                _setting(settings, "RULES_EVIDENCE_VERIFY_ON_REGISTER", True),
                True,
            ),
            include_chain_events=_as_bool(
                _setting(settings, "RULES_EVIDENCE_INCLUDE_CHAIN_EVENTS", True),
                True,
            ),
            redact_sensitive_literals=_as_bool(
                _setting(settings, "RULES_EVIDENCE_REDACT_SENSITIVE_LITERALS", True),
                True,
            ),
            drop_prohibited_actions=_as_bool(
                _setting(settings, "RULES_EVIDENCE_DROP_PROHIBITED_ACTIONS", True),
                True,
            ),
            retention_policy=str(
                _setting(settings, "RULES_EVIDENCE_RETENTION_POLICY", "process_local_only")
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
            "retention_policy": self.retention_policy,
            "limits": {
                "max_items": self.max_items,
                "max_chain_events": self.max_chain_events,
                "max_bundles": self.max_bundles,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
                "max_item_summary_length": self.max_item_summary_length,
                "max_bundle_name_length": self.max_bundle_name_length,
                "max_bundle_description_length": self.max_bundle_description_length,
            },
            "flags": {
                "require_subject_hash": self.require_subject_hash,
                "auto_seal_on_create": self.auto_seal_on_create,
                "register_bundles": self.register_bundles,
                "verify_on_register": self.verify_on_register,
                "include_chain_events": self.include_chain_events,
                "redact_sensitive_literals": self.redact_sensitive_literals,
                "drop_prohibited_actions": self.drop_prohibited_actions,
            },
        }


def _hash_ref(value: Any, options: EvidenceOptions) -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    if _looks_like_narrative(text):
        return None

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.rules.evidence.ref.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _seal_domain(options: EvidenceOptions) -> str:
    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    return f"muleguard.rules.evidence.seal.{safe_namespace}"


# -----------------------------------------------------------------------------
# Request and report models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class EvidenceRequest:
    """
    Bounded evidence creation request.
    """

    items: Any = None
    subject_ref: Any = None
    case_ref: Any = None
    actor_ref: Any = None
    bundle_id: Optional[str] = None
    name: str = ""
    description: str = ""
    status: Any = EvidenceStatus.DRAFT
    sensitivity: Any = EvidenceSensitivity.LOW
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    auto_seal: Optional[bool] = None
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.bundle_id = _clean_text(self.bundle_id, 128).lower() if self.bundle_id else None
        self.status = _normalize_enum_option(EvidenceStatus, self.status, EvidenceStatus.DRAFT)
        self.sensitivity = _normalize_enum_option(
            EvidenceSensitivity,
            self.sensitivity,
            EvidenceSensitivity.LOW,
        )
        self.tags = _normalize_tags(self.tags)
        self.metadata = _sanitize_metadata(self.metadata)
        self.request_id = _clean_text(self.request_id, 128) if self.request_id else None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) if self.idempotency_key else None

        if self.auto_seal is not None:
            self.auto_seal = _as_bool(self.auto_seal, False)


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "items",
        "subject_ref",
        "case_ref",
        "actor_ref",
        "bundle_id",
        "name",
        "description",
        "status",
        "sensitivity",
        "tags",
        "metadata",
        "auto_seal",
        "request_id",
        "idempotency_key",
    }
)


def _coerce_request(request: Any) -> EvidenceRequest:
    if isinstance(request, EvidenceRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if "items" not in payload:
            for key in ("evidence_items", "records", "rows", "alerts", "matches", "observations"):
                if key in payload:
                    payload["items"] = payload[key]
                    break

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(EvidenceRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return EvidenceRequest(**clean)
            except Exception:
                return EvidenceRequest(items=payload.get("items", request))

        return EvidenceRequest(items=request)

    return EvidenceRequest(items=request)


@dataclass(frozen=True, slots=True)
class EvidenceValidationReport:
    """
    Safe bounded evidence validation report.
    """

    ok: bool = True
    status: EvidenceValidationStatus | str = EvidenceValidationStatus.PASSED
    bundle_id: str = ""
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[EvidenceIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(
                EvidenceValidationStatus,
                self.status,
                EvidenceValidationStatus.PASSED,
            ),
        )
        object.__setattr__(self, "bundle_id", _clean_text(self.bundle_id, 128).lower())
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
        object.__setattr__(self, "metadata", MappingProxyType(_sanitize_metadata(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": EVIDENCE_VERSION,
                        "ok": self.ok,
                        "status": self.status.value if isinstance(self.status, EvidenceValidationStatus) else str(self.status),
                        "bundle_id": self.bundle_id,
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                        "metadata": _safe_detail_value(self.metadata),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status.value if isinstance(self.status, EvidenceValidationStatus) else str(self.status),
            "bundle_id": self.bundle_id,
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_EVIDENCE_CAVEATS),
            "safety_flags": dict(_EVIDENCE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local evidence registry
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _RegisteredEvidenceBundle:
    bundle: EvidenceBundle
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class EvidenceRegistry:
    """
    Bounded process-local evidence bundle registry.

    This registry is not durable, not distributed, and not production-ready.
    It exists only to support local prototype workflows, tests, and developer
    tooling.
    """

    def __init__(self, max_bundles: int = _DEFAULT_MAX_BUNDLES) -> None:
        self.max_bundles = max(1, int(max_bundles))
        self._bundles: dict[str, _RegisteredEvidenceBundle] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, bundle: EvidenceBundle) -> str:
        with self._lock:
            bundle_id = _clean_text(bundle.bundle_id, 128).lower()

            if not bundle_id:
                bundle_id = bundle.fingerprint[:32] or _sha256_hex(str(len(self._bundles) + 1))[:32]
                bundle = replace(bundle, bundle_id=bundle_id, fingerprint="")

            self._bundles[bundle_id] = _RegisteredEvidenceBundle(
                bundle=bundle,
                registered_at=_now_utc(),
            )

            if bundle_id not in self._order:
                self._order.append(bundle_id)

            if len(self._order) > self.max_bundles:
                evict_id = self._order.pop(0)
                self._bundles.pop(evict_id, None)

            return bundle_id

    def get_bundle(self, bundle_id: Any) -> Optional[EvidenceBundle]:
        key = _clean_text(bundle_id, 128).lower()

        with self._lock:
            entry = self._bundles.get(key)
            return entry.bundle if entry is not None else None

    def list_bundles(self, *, limit: int = 50) -> tuple[EvidenceBundle, ...]:
        with self._lock:
            out: list[EvidenceBundle] = []

            for bundle_id in self._order[: max(1, int(limit))]:
                entry = self._bundles.get(bundle_id)

                if entry is not None:
                    out.append(entry.bundle)

            return tuple(out)

    def summarize(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            out: list[dict[str, Any]] = []

            for bundle_id in self._order[: max(1, int(limit))]:
                entry = self._bundles.get(bundle_id)

                if entry is None:
                    continue

                bundle = entry.bundle

                out.append(
                    {
                        "bundle_id": bundle.bundle_id,
                        "name": bundle.name,
                        "status": _enum_value(bundle.status, EvidenceStatus.DRAFT.value),
                        "sensitivity": _enum_value(bundle.sensitivity, EvidenceSensitivity.LOW.value),
                        "subject_ref_hash": bundle.subject_ref_hash,
                        "case_ref_hash": bundle.case_ref_hash,
                        "item_count": len(bundle.items),
                        "chain_event_count": len(bundle.chain_events),
                        "sealed": bundle.seal is not None,
                        "created_at": bundle.created_at.isoformat(),
                        "updated_at": bundle.updated_at.isoformat(),
                        "registered_at": entry.registered_at.isoformat(),
                        "fingerprint": bundle.fingerprint,
                        "tags": list(bundle.tags),
                    }
                )

            return out

    def clear(self) -> None:
        with self._lock:
            self._bundles.clear()
            self._order.clear()

    def safe_summary(self, *, limit: int = 50) -> dict[str, Any]:
        with self._lock:
            status_counter = Counter(
                _enum_value(entry.bundle.status, EvidenceStatus.DRAFT.value)
                for entry in self._bundles.values()
            )
            sealed_count = sum(1 for entry in self._bundles.values() if entry.bundle.seal is not None)

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_bundles": self.max_bundles,
            "registered_bundles": len(self._order),
            "sealed_bundles": int(sealed_count),
            "by_status": dict(status_counter),
            "recent": self.summarize(limit=limit),
        }


_default_registry: Optional[EvidenceRegistry] = None
_default_registry_lock = threading.Lock()


def get_evidence_registry(
    max_bundles: int | None = None,
    *,
    rebuild: bool = False,
) -> EvidenceRegistry:
    """
    Return the process-wide evidence registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = EvidenceRegistry(
                max_bundles=max_bundles if max_bundles is not None else _DEFAULT_MAX_BUNDLES
            )

        return _default_registry


# -----------------------------------------------------------------------------
# Evidence harness
# -----------------------------------------------------------------------------


class EvidenceHarness:
    """
    Bounded deterministic synthetic evidence harness.

    This harness packages, validates, seals, verifies, exports, imports, and
    registers investigative evidence bundles for synthetic workflows only. It
    does not authorize actions, does not deploy systems, does not persist
    durable artifacts, and must not trigger automatic adverse customer action.
    """

    def __init__(
        self,
        options: EvidenceOptions | None = None,
        registry: EvidenceRegistry | None = None,
    ) -> None:
        self.options = options or EvidenceOptions.from_settings()
        self.registry = registry or get_evidence_registry(self.options.max_bundles)
        self._lock = threading.RLock()

    def _policy_gate(self, issues: list[EvidenceIssue]) -> Optional[EvidenceValidationStatus]:
        opts = self.options

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="evidence_harness_disabled",
                message="Evidence harness is disabled.",
            )
            return EvidenceValidationStatus.BLOCKED

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Evidence harness requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return EvidenceValidationStatus.BLOCKED

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Evidence harness is blocked in production-like environments.",
            )
            return EvidenceValidationStatus.BLOCKED

        return None

    def _new_event(
        self,
        bundle_id: str,
        event_type: Any,
        actor_ref: Any,
        details: Optional[Mapping[str, Any]] = None,
        previous_event_hash: Optional[str] = None,
        occurred_at: Optional[datetime] = None,
    ) -> EvidenceChainEvent:
        opts = self.options
        actor_hash = _hash_ref(actor_ref, opts) if actor_ref is not None else None
        prev = previous_event_hash or _genesis_hash(bundle_id)

        return EvidenceChainEvent(
            event_id=_sha256_hex(
                _canonical_json(
                    {
                        "bundle_id": bundle_id,
                        "event_type": _enum_value(event_type, ChainEventType.ANNOTATED.value),
                        "actor": actor_hash,
                        "previous": prev,
                        "occurred_at": _ensure_utc(occurred_at) or _now_utc(),
                    }
                )
            )[:32],
            bundle_id=bundle_id,
            event_type=event_type,
            actor_ref_hash=actor_hash,
            occurred_at=_ensure_utc(occurred_at) or _now_utc(),
            details=details or {},
            previous_event_hash=prev,
            event_hash="",
        )

    def _last_event_hash(self, bundle: EvidenceBundle) -> str:
        if bundle.chain_events:
            return str(bundle.chain_events[-1].event_hash)

        return _genesis_hash(bundle.bundle_id)

    def _append_event(self, bundle: EvidenceBundle, event: EvidenceChainEvent) -> EvidenceBundle:
        opts = self.options
        events = list(bundle.chain_events)

        if len(events) >= opts.max_chain_events:
            metadata = dict(bundle.metadata)
            metadata["chain_event_limit_reached"] = True
            return replace(
                bundle,
                metadata=metadata,
                updated_at=_now_utc(),
                fingerprint="",
            )

        events.append(event)

        return replace(
            bundle,
            chain_events=tuple(events),
            updated_at=_now_utc(),
            fingerprint="",
        )

    def _derive_bundle_id(
        self,
        request: EvidenceRequest,
        items: Sequence[EvidenceItem],
        subject_hash: Optional[str],
        case_hash: Optional[str],
    ) -> str:
        payload = {
            "version": EVIDENCE_VERSION,
            "name": _sanitize_safe_text(request.name, self.options.max_bundle_name_length),
            "subject_ref_hash": subject_hash,
            "case_ref_hash": case_hash,
            "item_fingerprints": [item.item_fingerprint for item in items[: self.options.max_summary_items]],
            "tags": list(request.tags),
            "metadata": _safe_detail_value(request.metadata),
            "request_id": request.request_id,
            "idempotency_key": request.idempotency_key,
        }

        return _sha256_hex(_canonical_json(payload))[:32]

    def create_bundle(self, request: Any) -> EvidenceBundle:
        opts = self.options
        issues: list[EvidenceIssue] = []
        start_time = time.monotonic()
        req = _coerce_request(request)

        gate = self._policy_gate(issues)

        if gate is not None:
            return EvidenceBundle(
                bundle_id=req.bundle_id or _sha256_hex(str(start_time))[:32],
                name="blocked_evidence_bundle",
                description="Evidence creation blocked by policy.",
                status=EvidenceStatus.BLOCKED,
                metadata={"reason": gate.value, "issues": [issue.to_dict() for issue in issues]},
                fingerprint="",
            )

        items: list[EvidenceItem] = []

        for index, item_value in enumerate(_as_sequence(req.items)):
            if _time_exceeded(start_time, opts.max_time_ms):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="evidence_item_extraction_time_budget_exhausted",
                    message="Evidence item extraction stopped after reaching time budget.",
                    details={"processed": len(items)},
                )
                break

            item = _coerce_evidence_item(item_value, opts, issues)

            if item is None:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="evidence_item_omitted",
                    message="Evidence item was omitted because it could not be safely parsed.",
                    details={"index": index},
                )
                continue

            items.append(item)

            if len(items) >= opts.max_items:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="evidence_item_limit_reached",
                    message="Additional evidence items omitted due to configured item limit.",
                    details={"max_items": opts.max_items},
                )
                break

        subject_hash = _hash_ref(req.subject_ref, opts)
        case_hash = _hash_ref(req.case_ref, opts)

        if opts.require_subject_hash and subject_hash is None:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="evidence_subject_hash_required",
                message="Evidence subject hash is required by policy.",
            )

        bundle_id = req.bundle_id or self._derive_bundle_id(req, items, subject_hash, case_hash)
        created_at = _now_utc()

        bundle = EvidenceBundle(
            bundle_id=bundle_id,
            name=req.name,
            description=req.description,
            subject_ref_hash=subject_hash,
            case_ref_hash=case_hash,
            status=req.status,
            sensitivity=req.sensitivity,
            items=tuple(items),
            chain_events=(),
            tags=req.tags,
            metadata=req.metadata,
            created_at=created_at,
            updated_at=created_at,
            seal=None,
            fingerprint="",
        )

        if opts.include_chain_events:
            created_event = self._new_event(
                bundle.bundle_id,
                ChainEventType.CREATED,
                req.actor_ref,
                {
                    "item_count": len(items),
                    "subject_linked": subject_hash is not None,
                    "case_linked": case_hash is not None,
                },
                previous_event_hash=_genesis_hash(bundle.bundle_id),
                occurred_at=created_at,
            )
            bundle = self._append_event(bundle, created_event)

        report = self.validate_bundle(bundle)

        if report.status in {EvidenceValidationStatus.FAILED, EvidenceValidationStatus.BLOCKED}:
            bundle = replace(bundle, status=EvidenceStatus.BLOCKED, fingerprint="")
        elif req.auto_seal if req.auto_seal is not None else opts.auto_seal_on_create:
            bundle = self.seal_bundle(bundle, req.actor_ref)

        if opts.register_bundles and _enum_value(bundle.status, EvidenceStatus.DRAFT.value) not in {
            EvidenceStatus.BLOCKED.value,
            EvidenceStatus.QUARANTINED.value,
        }:
            self.registry.register(bundle)

        return bundle

    def validate_bundle(self, bundle: Any) -> EvidenceValidationReport:
        opts = self.options
        issues: list[EvidenceIssue] = []
        start_time = time.monotonic()

        gate = self._policy_gate(issues)
        bundle_obj = _coerce_evidence_bundle(bundle, opts, issues)

        if bundle_obj is None:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="malformed_evidence_bundle",
                message="Evidence bundle could not be parsed.",
            )
            return EvidenceValidationReport(
                ok=False,
                status=EvidenceValidationStatus.FAILED,
                bundle_id="",
                counts={"items": 0, "chain_events": 0, "issues": len(issues)},
                issues=_truncate_issues(issues, opts.max_issues),
                metadata={"elapsed_ms": _elapsed_ms(start_time)},
                fingerprint="",
            )

        if gate is not None:
            return EvidenceValidationReport(
                ok=False,
                status=gate,
                bundle_id=bundle_obj.bundle_id,
                counts={
                    "items": len(bundle_obj.items),
                    "chain_events": len(bundle_obj.chain_events),
                    "issues": len(issues),
                },
                issues=_truncate_issues(issues, opts.max_issues),
                metadata={
                    "bundle_fingerprint": bundle_obj.fingerprint,
                    "sealed": bundle_obj.seal is not None,
                    "elapsed_ms": _elapsed_ms(start_time),
                },
                fingerprint="",
            )

        if not bundle_obj.bundle_id:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="missing_evidence_bundle_id",
                message="Evidence bundle id is required.",
            )

        if not bundle_obj.items:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="empty_evidence_bundle",
                message="Evidence bundle has no items.",
            )

        if len(bundle_obj.items) > opts.max_items:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="evidence_item_limit_exceeded",
                message="Evidence bundle exceeded configured item limit.",
                details={"item_count": len(bundle_obj.items), "max_items": opts.max_items},
            )

        item_ids = Counter(item.item_id for item in bundle_obj.items if item.item_id)
        duplicate_item_ids = sorted(item_id for item_id, count in item_ids.items() if count > 1)

        if duplicate_item_ids:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="duplicate_evidence_item_ids",
                message="Duplicate evidence item ids detected.",
                details={
                    "duplicate_count": len(duplicate_item_ids),
                    "duplicates_sample": duplicate_item_ids[: opts.max_summary_items],
                    "truncated": len(duplicate_item_ids) > opts.max_summary_items,
                },
            )

        for item in bundle_obj.items:
            expected_fingerprint = _item_fingerprint(item)

            if item.item_fingerprint and item.item_fingerprint != expected_fingerprint:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="evidence_item_fingerprint_mismatch",
                    message="Evidence item fingerprint does not match item payload.",
                    field=item.item_id or None,
                )

            if _contains_prohibited_action(item.summary, item.metadata, item.source_system):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="prohibited_action_in_evidence_item",
                    message="Evidence item contains prohibited action language.",
                    field=item.item_id or None,
                )

        if len(bundle_obj.chain_events) > opts.max_chain_events:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="evidence_chain_event_limit_exceeded",
                message="Evidence bundle exceeded configured chain event limit.",
                details={
                    "event_count": len(bundle_obj.chain_events),
                    "max_chain_events": opts.max_chain_events,
                },
            )

        previous_hash = _genesis_hash(bundle_obj.bundle_id)
        previous_time: Optional[datetime] = None

        for event in bundle_obj.chain_events:
            expected_event_hash = _event_fingerprint(event)

            if event.event_hash != expected_event_hash:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="evidence_chain_event_hash_mismatch",
                    message="Evidence chain event hash does not match event payload.",
                    field=event.event_id or None,
                )

            if event.previous_event_hash != previous_hash:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="evidence_chain_continuity_break",
                    message="Evidence chain event previous hash does not match prior event.",
                    field=event.event_id or None,
                )

            if previous_time is not None and event.occurred_at < previous_time:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="evidence_chain_time_regression",
                    message="Evidence chain event timestamp is earlier than prior event.",
                    field=event.event_id or None,
                )

            previous_hash = str(event.event_hash)
            previous_time = event.occurred_at

        if _contains_prohibited_action(
            bundle_obj.name,
            bundle_obj.description,
            bundle_obj.tags,
            bundle_obj.metadata,
        ):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_action_in_evidence_bundle",
                message="Evidence bundle contains prohibited action language.",
            )

        if bundle_obj.seal is None:
            if bundle_obj.status == EvidenceStatus.SEALED:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="sealed_bundle_without_seal",
                    message="Evidence bundle status is SEALED but no seal is present.",
                )
            else:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.INFO,
                    code="evidence_seal_unavailable",
                    message="Evidence bundle is not sealed.",
                )
        else:
            digest = _compute_bundle_digest(bundle_obj)

            if bundle_obj.seal.payload_digest != digest:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="evidence_seal_digest_mismatch",
                    message="Evidence seal payload digest does not match bundle content.",
                )

            expected_hmac = _hmac_hex(opts.salt, _seal_domain(opts), digest)

            if not hmac.compare_digest(
                str(bundle_obj.seal.seal_hmac).encode("utf-8", errors="replace"),
                str(expected_hmac).encode("utf-8", errors="replace"),
            ):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="evidence_seal_hmac_mismatch",
                    message="Evidence seal HMAC does not match configured local salt and namespace.",
                )

        expected_fingerprint = _compute_bundle_fingerprint(bundle_obj)

        if bundle_obj.fingerprint and bundle_obj.fingerprint != expected_fingerprint:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="evidence_bundle_fingerprint_mismatch",
                message="Evidence bundle fingerprint does not match bundle payload.",
            )

        if bundle_obj.status in {EvidenceStatus.BLOCKED, EvidenceStatus.QUARANTINED}:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="evidence_bundle_blocked_or_quarantined",
                message="Evidence bundle is blocked or quarantined and must not be used.",
                details={"status": _enum_value(bundle_obj.status, EvidenceStatus.DRAFT.value)},
            )

        if _has_error(issues) or bundle_obj.status in {EvidenceStatus.BLOCKED, EvidenceStatus.QUARANTINED}:
            status = EvidenceValidationStatus.BLOCKED if bundle_obj.status == EvidenceStatus.BLOCKED else EvidenceValidationStatus.FAILED
        elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
            status = EvidenceValidationStatus.DEGRADED
        else:
            status = EvidenceValidationStatus.PASSED

        counts = {
            "items": len(bundle_obj.items),
            "chain_events": len(bundle_obj.chain_events),
            "sealed": 1 if bundle_obj.seal is not None else 0,
            "issues": len(issues),
        }

        return EvidenceValidationReport(
            ok=status in {EvidenceValidationStatus.PASSED, EvidenceValidationStatus.DEGRADED},
            status=status,
            bundle_id=bundle_obj.bundle_id,
            counts=counts,
            issues=_truncate_issues(issues, opts.max_issues),
            metadata={
                "bundle_fingerprint": bundle_obj.fingerprint,
                "bundle_status": _enum_value(bundle_obj.status, EvidenceStatus.DRAFT.value),
                "subject_linked": bundle_obj.subject_ref_hash is not None,
                "case_linked": bundle_obj.case_ref_hash is not None,
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_values_retained": False,
                "subject_label_pairs_retained": False,
                "narratives_retained": False,
                "identifiers_retained": False,
                "secrets_retained": False,
            },
            fingerprint="",
        )

    def seal_bundle(self, bundle: Any, actor_ref: Any = None) -> EvidenceBundle:
        opts = self.options
        bundle_obj = _coerce_evidence_bundle(bundle, opts)

        if bundle_obj is None:
            raise MuleGuardValidationError("Evidence bundle could not be parsed for sealing.")

        report = self.validate_bundle(bundle_obj)

        if report.status in {EvidenceValidationStatus.FAILED, EvidenceValidationStatus.BLOCKED}:
            return replace(bundle_obj, status=EvidenceStatus.BLOCKED, fingerprint="")

        digest = _compute_bundle_digest(bundle_obj)
        pre_fingerprint = bundle_obj.fingerprint or _compute_bundle_fingerprint(bundle_obj)
        sealed_at = _now_utc()
        actor_hash = _hash_ref(actor_ref, opts) if actor_ref is not None else None

        seal = EvidenceSeal(
            algorithm=IntegrityAlgorithm.HMAC_SHA256,
            sealed_at=sealed_at,
            bundle_fingerprint=pre_fingerprint,
            payload_digest=digest,
            seal_hmac=_hmac_hex(opts.salt, _seal_domain(opts), digest),
            verifier_ref_hash=actor_hash,
            metadata={
                "local_integrity_marker": True,
                "legal_signature": False,
                "production_ready": False,
            },
        )

        sealed_bundle = replace(
            bundle_obj,
            seal=seal,
            status=EvidenceStatus.SEALED,
            updated_at=sealed_at,
            fingerprint="",
        )

        if opts.include_chain_events:
            event = self._new_event(
                sealed_bundle.bundle_id,
                ChainEventType.SEALED,
                actor_ref,
                {
                    "algorithm": IntegrityAlgorithm.HMAC_SHA256.value,
                    "payload_digest_prefix": digest[:16],
                },
                previous_event_hash=self._last_event_hash(bundle_obj),
                occurred_at=sealed_at,
            )
            sealed_bundle = self._append_event(sealed_bundle, event)

        if opts.register_bundles:
            self.registry.register(sealed_bundle)

        return sealed_bundle

    def verify_bundle(self, bundle: Any) -> EvidenceValidationReport:
        opts = self.options
        bundle_obj = _coerce_evidence_bundle(bundle, opts)

        if bundle_obj is None:
            return EvidenceValidationReport(
                ok=False,
                status=EvidenceValidationStatus.FAILED,
                counts={"items": 0, "chain_events": 0, "issues": 1},
                issues=(
                    EvidenceIssue(
                        severity=IssueSeverity.ERROR,
                        code="malformed_evidence_bundle",
                        message="Evidence bundle could not be parsed for verification.",
                    ),
                ),
                metadata={},
                fingerprint="",
            )

        report = self.validate_bundle(bundle_obj)

        if report.ok and bundle_obj.seal is not None:
            verified_at = _now_utc()

            if opts.include_chain_events:
                event = self._new_event(
                    bundle_obj.bundle_id,
                    ChainEventType.VERIFIED,
                    None,
                    {
                        "validation_status": report.status.value if isinstance(report.status, EvidenceValidationStatus) else str(report.status),
                        "verified_at": verified_at.isoformat(),
                    },
                    previous_event_hash=self._last_event_hash(bundle_obj),
                    occurred_at=verified_at,
                )
                verified_bundle = self._append_event(bundle_obj, event)

                if opts.register_bundles:
                    self.registry.register(verified_bundle)

        return report

    def export_bundle(self, bundle: Any) -> dict[str, Any]:
        opts = self.options
        bundle_obj = _coerce_evidence_bundle(bundle, opts)

        if bundle_obj is None:
            return {
                "ok": False,
                "error": "malformed_evidence_bundle",
                "caveats": list(_EVIDENCE_CAVEATS),
                "safety_flags": dict(_EVIDENCE_SAFETY_FLAGS),
            }

        return {
            "ok": True,
            "document_type": "evidence_bundle",
            "evidence_version": EVIDENCE_VERSION,
            "bundle": bundle_obj.to_dict(),
            "raw_values_retained": False,
            "subject_label_pairs_retained": False,
            "narratives_retained": False,
            "identifiers_retained": False,
            "secrets_retained": False,
            "caveats": list(_EVIDENCE_CAVEATS),
            "safety_flags": dict(_EVIDENCE_SAFETY_FLAGS),
        }

    def import_bundle(self, payload: Any) -> EvidenceBundle:
        opts = self.options
        issues: list[EvidenceIssue] = []
        bundle_obj = _coerce_evidence_bundle(payload, opts, issues)

        if bundle_obj is None:
            raise MuleGuardValidationError(
                "Evidence bundle payload could not be parsed.",
                details={"issues": [issue.to_dict() for issue in issues]},
            )

        if not bundle_obj.bundle_id:
            bundle_obj = replace(
                bundle_obj,
                bundle_id=self._derive_bundle_id(
                    EvidenceRequest(),
                    bundle_obj.items,
                    bundle_obj.subject_ref_hash,
                    bundle_obj.case_ref_hash,
                ),
                fingerprint="",
            )

        if opts.include_chain_events and not bundle_obj.chain_events:
            imported_event = self._new_event(
                bundle_obj.bundle_id,
                ChainEventType.IMPORTED,
                None,
                {"item_count": len(bundle_obj.items)},
                previous_event_hash=_genesis_hash(bundle_obj.bundle_id),
            )
            bundle_obj = self._append_event(bundle_obj, imported_event)

        report = self.validate_bundle(bundle_obj)

        if report.status in {EvidenceValidationStatus.FAILED, EvidenceValidationStatus.BLOCKED}:
            bundle_obj = replace(bundle_obj, status=EvidenceStatus.BLOCKED, fingerprint="")
        elif opts.register_bundles:
            self.registry.register(bundle_obj)

        return bundle_obj

    def register_bundle(self, bundle: Any) -> str:
        opts = self.options
        bundle_obj = _coerce_evidence_bundle(bundle, opts)

        if bundle_obj is None:
            raise MuleGuardValidationError("Evidence bundle could not be parsed for registration.")

        if opts.verify_on_register:
            report = self.validate_bundle(bundle_obj)

            if report.status in {EvidenceValidationStatus.FAILED, EvidenceValidationStatus.BLOCKED}:
                raise MuleGuardValidationError(
                    "Evidence bundle validation failed before registration.",
                    details={"issues": [issue.to_dict() for issue in report.issues]},
                )

        if opts.include_chain_events:
            has_registered_event = any(
                _enum_value(event.event_type, ChainEventType.ANNOTATED.value) == ChainEventType.REGISTERED.value
                for event in bundle_obj.chain_events
            )

            if not has_registered_event:
                event = self._new_event(
                    bundle_obj.bundle_id,
                    ChainEventType.REGISTERED,
                    None,
                    {"registry_backend": "process_local_in_memory"},
                    previous_event_hash=self._last_event_hash(bundle_obj),
                )
                bundle_obj = self._append_event(bundle_obj, event)

        return self.registry.register(bundle_obj)

    def append_event(
        self,
        bundle_id: Any,
        event_type: Any,
        actor_ref: Any = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> EvidenceBundle:
        opts = self.options
        key = _clean_text(bundle_id, 128).lower()
        bundle_obj = self.registry.get_bundle(key)

        if bundle_obj is None:
            raise MuleGuardValidationError(
                "Evidence bundle not found in process-local registry.",
                details={"bundle_id": key},
            )

        event = self._new_event(
            bundle_obj.bundle_id,
            event_type,
            actor_ref,
            details,
            previous_event_hash=self._last_event_hash(bundle_obj),
        )
        updated = self._append_event(bundle_obj, event)
        self.registry.register(updated)
        return updated

    def _set_status(
        self,
        bundle_id: Any,
        status: EvidenceStatus,
        event_type: ChainEventType,
        actor_ref: Any,
        details: Optional[Mapping[str, Any]] = None,
    ) -> EvidenceBundle:
        key = _clean_text(bundle_id, 128).lower()
        bundle_obj = self.registry.get_bundle(key)

        if bundle_obj is None:
            raise MuleGuardValidationError(
                "Evidence bundle not found in process-local registry.",
                details={"bundle_id": key},
            )

        updated = replace(
            bundle_obj,
            status=status,
            updated_at=_now_utc(),
            fingerprint="",
        )

        if self.options.include_chain_events:
            event = self._new_event(
                updated.bundle_id,
                event_type,
                actor_ref,
                details or {"status": status.value},
                previous_event_hash=self._last_event_hash(updated),
            )
            updated = self._append_event(updated, event)

        self.registry.register(updated)
        return updated

    def retire_bundle(
        self,
        bundle_id: Any,
        actor_ref: Any = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> EvidenceBundle:
        return self._set_status(
            bundle_id,
            EvidenceStatus.RETIRED,
            ChainEventType.RETIRED,
            actor_ref,
            details,
        )

    def block_bundle(
        self,
        bundle_id: Any,
        actor_ref: Any = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> EvidenceBundle:
        return self._set_status(
            bundle_id,
            EvidenceStatus.BLOCKED,
            ChainEventType.BLOCKED,
            actor_ref,
            details,
        )

    def quarantine_bundle(
        self,
        bundle_id: Any,
        actor_ref: Any = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> EvidenceBundle:
        return self._set_status(
            bundle_id,
            EvidenceStatus.QUARANTINED,
            ChainEventType.QUARANTINED,
            actor_ref,
            details,
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "registry": self.registry.safe_summary(limit=self.options.max_summary_items),
            "caveats": list(_EVIDENCE_CAVEATS),
            "safety_flags": dict(_EVIDENCE_SAFETY_FLAGS),
        }


_default_harness: Optional[EvidenceHarness] = None
_default_harness_lock = threading.Lock()


def get_evidence_options(settings: Any | None = None) -> EvidenceOptions:
    """
    Return evidence options from settings.
    """
    return EvidenceOptions.from_settings(settings)


def get_evidence_harness(
    options: EvidenceOptions | None = None,
    *,
    rebuild: bool = False,
) -> EvidenceHarness:
    """
    Return a process-wide evidence harness.

    If options are supplied or rebuild is True, a new harness is created and
    becomes the default.
    """
    global _default_harness

    with _default_harness_lock:
        if _default_harness is None or rebuild or options is not None:
            _default_harness = EvidenceHarness(
                options=options or EvidenceOptions.from_settings()
            )

        return _default_harness


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def create_evidence_bundle(
    request: Any,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> EvidenceBundle:
    """
    Create one bounded synthetic evidence bundle.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.create_bundle(request)


def validate_evidence_bundle(
    bundle: Any,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> EvidenceValidationReport:
    """
    Validate one bounded synthetic evidence bundle.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.validate_bundle(bundle)


def seal_evidence_bundle(
    bundle: Any,
    actor_ref: Any = None,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> EvidenceBundle:
    """
    Seal one bounded synthetic evidence bundle.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.seal_bundle(bundle, actor_ref)


def verify_evidence_bundle(
    bundle: Any,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> EvidenceValidationReport:
    """
    Verify one bounded synthetic evidence bundle.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.verify_bundle(bundle)


def export_evidence_bundle(
    bundle: Any,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> dict[str, Any]:
    """
    Export one bounded synthetic evidence bundle as a safe mapping.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.export_bundle(bundle)


def import_evidence_bundle(
    payload: Any,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> EvidenceBundle:
    """
    Import one bounded synthetic evidence bundle from a safe mapping.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.import_bundle(payload)


def register_evidence_bundle(
    bundle: Any,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> str:
    """
    Register one bounded synthetic evidence bundle in the process-local registry.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.register_bundle(bundle)


def get_evidence_bundle(bundle_id: Any, *, registry: EvidenceRegistry | None = None) -> Optional[EvidenceBundle]:
    """
    Return one registered evidence bundle.
    """
    active_registry = registry or get_evidence_registry()
    return active_registry.get_bundle(bundle_id)


def list_evidence_bundles(
    *,
    limit: int = 50,
    registry: EvidenceRegistry | None = None,
) -> tuple[EvidenceBundle, ...]:
    """
    Return registered evidence bundles.
    """
    active_registry = registry or get_evidence_registry()
    return active_registry.list_bundles(limit=limit)


def summarize_evidence_bundles(
    *,
    limit: int = 50,
    registry: EvidenceRegistry | None = None,
) -> list[dict[str, Any]]:
    """
    Return safe registered evidence bundle summaries.
    """
    active_registry = registry or get_evidence_registry()
    return active_registry.summarize(limit=limit)


def append_evidence_event(
    bundle_id: Any,
    event_type: Any,
    actor_ref: Any = None,
    details: Optional[Mapping[str, Any]] = None,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> EvidenceBundle:
    """
    Append one bounded process-local chain event to a registered evidence bundle.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.append_event(bundle_id, event_type, actor_ref, details)


def retire_evidence_bundle(
    bundle_id: Any,
    actor_ref: Any = None,
    details: Optional[Mapping[str, Any]] = None,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> EvidenceBundle:
    """
    Mark one registered evidence bundle as retired.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.retire_bundle(bundle_id, actor_ref, details)


def block_evidence_bundle(
    bundle_id: Any,
    actor_ref: Any = None,
    details: Optional[Mapping[str, Any]] = None,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> EvidenceBundle:
    """
    Mark one registered evidence bundle as blocked.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.block_bundle(bundle_id, actor_ref, details)


def quarantine_evidence_bundle(
    bundle_id: Any,
    actor_ref: Any = None,
    details: Optional[Mapping[str, Any]] = None,
    options: EvidenceOptions | None = None,
    *,
    harness: EvidenceHarness | None = None,
) -> EvidenceBundle:
    """
    Mark one registered evidence bundle as quarantined.
    """
    active_harness = harness or get_evidence_harness(options)
    return active_harness.quarantine_bundle(bundle_id, actor_ref, details)


def get_evidence_health(*, harness: EvidenceHarness | None = None) -> dict[str, Any]:
    """
    Return safe evidence-harness health.
    """
    active_harness = harness or get_evidence_harness()
    opts = active_harness.options
    registry_summary = active_harness.registry.safe_summary(limit=opts.max_summary_items)
    issues: list[EvidenceIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="evidence_harness_disabled",
            message="Evidence harness is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Evidence harness requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Evidence harness is blocked in production-like environments.",
        )
    elif int(registry_summary.get("registered_bundles", 0)) <= 0:
        status = "DEGRADED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.WARNING,
            code="no_registered_evidence_bundles",
            message="No evidence bundles are registered in the process-local registry.",
        )
    elif int(registry_summary.get("sealed_bundles", 0)) <= 0:
        status = "DEGRADED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="no_sealed_evidence_bundles",
            message="Registered evidence bundles exist, but none are sealed.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "retention_policy": opts.retention_policy,
        "registry": registry_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(_EVIDENCE_CAVEATS),
        "safety_flags": dict(_EVIDENCE_SAFETY_FLAGS),
    }


def get_evidence_metadata() -> dict[str, Any]:
    """
    Return safe, serializable evidence-harness metadata.

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
    options = EvidenceOptions.from_settings()
    registry = get_evidence_registry(options.max_bundles)

    return {
        "package": "muleguard.backend.rules.evidence",
        "version": EVIDENCE_VERSION,
        "evidence_classes": [item.value for item in EvidenceClass],
        "evidence_statuses": [item.value for item in EvidenceStatus],
        "sensitivity_levels": [item.value for item in EvidenceSensitivity],
        "integrity_algorithms": [item.value for item in IntegrityAlgorithm],
        "chain_event_types": [item.value for item in ChainEventType],
        "validation_statuses": [item.value for item in EvidenceValidationStatus],
        "issue_severities": [item.value for item in IssueSeverity],
        "default_options": options.safe_summary(),
        "registry": registry.safe_summary(limit=options.max_summary_items),
        "hard_limits": {
            "max_items": _HARD_MAX_ITEMS,
            "max_chain_events": _HARD_MAX_CHAIN_EVENTS,
            "max_bundles": _HARD_MAX_BUNDLES,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": _HARD_MAX_TIME_MS,
        },
        "forbidden_evidence_field_count": len(_FORBIDDEN_EVIDENCE_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(_PROHIBITED_ACTION_TOKENS),
        "caveats": list(_EVIDENCE_CAVEATS),
        "safety_flags": dict(_EVIDENCE_SAFETY_FLAGS),
    }


__all__ = [
    "ChainEventType",
    "EvidenceBundle",
    "EvidenceChainEvent",
    "EvidenceClass",
    "EvidenceHarness",
    "EvidenceIssue",
    "EvidenceOptions",
    "EvidenceRegistry",
    "EvidenceRequest",
    "EvidenceSeal",
    "EvidenceSensitivity",
    "EvidenceStatus",
    "EvidenceValidationReport",
    "EvidenceValidationStatus",
    "IntegrityAlgorithm",
    "IssueSeverity",
    "append_evidence_event",
    "block_evidence_bundle",
    "create_evidence_bundle",
    "export_evidence_bundle",
    "get_evidence_bundle",
    "get_evidence_harness",
    "get_evidence_health",
    "get_evidence_metadata",
    "get_evidence_options",
    "get_evidence_registry",
    "import_evidence_bundle",
    "list_evidence_bundles",
    "quarantine_evidence_bundle",
    "register_evidence_bundle",
    "retire_evidence_bundle",
    "seal_evidence_bundle",
    "summarize_evidence_bundles",
    "validate_evidence_bundle",
    "verify_evidence_bundle",
]