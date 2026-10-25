"""
MULEGUARD backend correlation package.

This package provides the canonical bounded correlation analysis layer for the
synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- detect and score bounded correlations between synthetic complaints,
  transactions, accounts, entities, alerts, and cases;
- support deterministic structural matching using pseudonymous hashes, temporal
  proximity, currency-aligned amount equality, and bounded categorical overlap;
- enforce strict product-safety constraints, including absolute prohibition of
  automatic adverse customer action;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values, raw identifiers, raw narratives, subject-label
  pairs, secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited correlation fields;
- provide bounded, API-safe correlation results with candidate scores,
  operational reasons, safe summaries, issue reporting, fingerprints, and
  metadata;
- maintain a bounded process-local correlation registry for local prototype
  workflows, tests, developer tooling, and offline evaluation harnesses;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module orchestrates investigative correlations only. It does not train
models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for correlation analysis.
- Correlation outputs are investigative prioritization artefacts only. They are
  not proof of wrongdoing, common control, or criminal association.
- Correlation scores and confidences are not probabilities of guilt.
- Labels must never be used as correlation features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as correlation inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden inputs. Subject linkage is pseudonymous and
  salted.
- Currency amounts are never converted or blended across currencies. Correlation
  matching requires strict currency alignment.
- Correlation handling must never trigger automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable correlations are reported honestly as unavailable
  rather than invented.
- The bundled correlation registry is process-local, non-durable, and bounded
  for local prototype use only.
- This package does not claim production readiness.
- This package does not claim regulatory compliance.

Explicit non-goals:

- This package does not access databases.
- This package does not call external correlation engines or model runtimes.
- This package does not deploy, promote, retire, upload, replace, or serve
  production models or correlation rules.
- This package does not generate synthetic ingestion records.
- This package does not replace feature schema validation.
- This package does not replace ingestion validation.
- This package is not a durable decisioning platform.
- This package is not an authorization engine.
- This package is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, correlation
candidates, explanations, validation reports, and case dispositions are
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
from collections import Counter, defaultdict
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


logger = logging.getLogger("muleguard.backend.correlation")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

CORRELATION_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.correlation.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_RECORDS: Final[int] = 10_000
_HARD_MAX_RECORDS: Final[int] = 100_000

_DEFAULT_MAX_CANDIDATES: Final[int] = 500
_HARD_MAX_CANDIDATES: Final[int] = 10_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_REGISTRATIONS: Final[int] = 1_000
_HARD_MAX_REGISTRATIONS: Final[int] = 10_000

_DEFAULT_MAX_TIME_MS: Final[int] = 30_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_DEFAULT_TEMPORAL_TOLERANCE_HOURS: Final[int] = 24
_HARD_MAX_TEMPORAL_TOLERANCE_HOURS: Final[int] = 720

_DEFAULT_MIN_CONFIDENCE: Final[float] = 0.50

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_HASH_LENGTH: Final[int] = 256
_MAX_REASON_TEXT_LENGTH: Final[int] = 300

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")

_MISSING: Final[object] = object()

_SUBJECT_KEYS: Final[tuple[str, ...]] = (
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

_NON_FEATURE_KEYS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_CORRELATION_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_CORRELATION_TOKENS: Final[tuple[str, ...]] = (
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

_CORRELATION_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic correlation analysis only. Do not use with real customer data.",
    "Correlation candidates are investigative leads only and are not proof of wrongdoing.",
    "Correlation scores and confidences are not probabilities of guilt.",
    "Correlation analysis must not trigger automatic adverse customer action.",
    "Labels must never be used as correlation features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Currency amounts are never converted or blended across currencies.",
    "Unavailable correlations are reported honestly as unavailable rather than invented.",
    "The bundled correlation registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_CORRELATION_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_correlation": True,
        "bounded_correlation_required": True,
        "scores_are_investigative_priority_only": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class CorrelationKind(str, Enum):
    """
    Bounded correlation kind.
    """

    COMPLAINT_TO_TRANSACTION = "complaint_to_transaction"
    COMPLAINT_TO_COMPLAINT = "complaint_to_complaint"
    ACCOUNT_TO_ENTITY = "account_to_entity"
    ALERT_TO_CASE = "alert_to_case"
    TRANSACTION_TO_TRANSACTION = "transaction_to_transaction"
    EXPLICIT = "explicit"
    OTHER = "other"


class CorrelationStatus(str, Enum):
    """
    Correlation candidate operational status.
    """

    UNREVIEWED = "unreviewed"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class AnalysisStatus(str, Enum):
    """
    Overall correlation analysis status.
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


def _parse_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, bool):
        return None

    if isinstance(value, datetime):
        return _ensure_utc(value)

    if isinstance(value, (int, float, Decimal)):
        try:
            numeric = float(value)
        except (TypeError, ValueError, OverflowError):
            return None

        if not math.isfinite(numeric):
            return None

        if abs(numeric) > 1_000_000_000_000:
            numeric /= 1000.0

        try:
            return datetime.fromtimestamp(numeric, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    text = _normalize_unicode(value).strip()

    if not text:
        return None

    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        return _ensure_utc(datetime.fromisoformat(text))
    except Exception:
        pass

    try:
        numeric = float(text)
    except (TypeError, ValueError):
        return None

    if not math.isfinite(numeric):
        return None

    if abs(numeric) > 1_000_000_000_000:
        numeric /= 1000.0

    try:
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


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

    return text[:limit] if len(text) > limit else text


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

    if canonical in _FORBIDDEN_CORRELATION_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_CORRELATION_TOKENS)


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


def _normalize_currency(value: Any) -> Optional[str]:
    text = _normalize_unicode(value).strip().upper()
    text = re.sub(r"[^A-Z]", "", text)

    if _CURRENCY_RE.match(text):
        return text

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


def _subject_hash(value: Any, options: "CorrelationOptions") -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.correlation.subject.{safe_namespace}"
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
    return bool(text) and any(token in text for token in _PROHIBITED_ACTION_TOKENS)


def _normalize_tags(value: Any, limit: int = 50) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        tag = _clean_text(item, 100)

        if tag:
            out.append(tag)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


def _append_issue(
    issues: list["CorrelationIssue"],
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

        issues[-1] = CorrelationIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        CorrelationIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _has_error(issues: Sequence["CorrelationIssue"]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CorrelationIssue:
    """
    Safe correlation issue.
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


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CorrelationOptions:
    """
    Bounded correlation analysis policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    temporal_tolerance_hours: int = _DEFAULT_TEMPORAL_TOLERANCE_HOURS
    min_confidence: float = _DEFAULT_MIN_CONFIDENCE

    max_records: int = _DEFAULT_MAX_RECORDS
    max_candidates: int = _DEFAULT_MAX_CANDIDATES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_registrations: int = _DEFAULT_MAX_REGISTRATIONS
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    include_complaint_to_transaction: bool = True
    include_complaint_to_complaint: bool = True
    include_account_to_entity: bool = True
    include_alert_to_case: bool = True
    include_transaction_to_transaction: bool = False

    drop_forbidden_fields: bool = False
    register_results: bool = True

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
            "temporal_tolerance_hours",
            _clamp_int(self.temporal_tolerance_hours, 0, _HARD_MAX_TEMPORAL_TOLERANCE_HOURS, _DEFAULT_TEMPORAL_TOLERANCE_HOURS),
        )
        object.__setattr__(
            self,
            "min_confidence",
            _round6(_clamp_float(self.min_confidence, 0.0, 1.0, _DEFAULT_MIN_CONFIDENCE)),
        )

        object.__setattr__(self, "max_records", _clamp_int(self.max_records, 1, _HARD_MAX_RECORDS, _DEFAULT_MAX_RECORDS))
        object.__setattr__(self, "max_candidates", _clamp_int(self.max_candidates, 1, _HARD_MAX_CANDIDATES, _DEFAULT_MAX_CANDIDATES))
        object.__setattr__(self, "max_issues", _clamp_int(self.max_issues, 1, _HARD_MAX_ISSUES, _DEFAULT_MAX_ISSUES))
        object.__setattr__(self, "max_summary_items", _clamp_int(self.max_summary_items, 1, _HARD_MAX_SUMMARY_ITEMS, _DEFAULT_MAX_SUMMARY_ITEMS))
        object.__setattr__(self, "max_registrations", _clamp_int(self.max_registrations, 1, _HARD_MAX_REGISTRATIONS, _DEFAULT_MAX_REGISTRATIONS))
        object.__setattr__(self, "max_time_ms", _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS))

        object.__setattr__(self, "include_complaint_to_transaction", _as_bool(self.include_complaint_to_transaction, True))
        object.__setattr__(self, "include_complaint_to_complaint", _as_bool(self.include_complaint_to_complaint, True))
        object.__setattr__(self, "include_account_to_entity", _as_bool(self.include_account_to_entity, True))
        object.__setattr__(self, "include_alert_to_case", _as_bool(self.include_alert_to_case, True))
        object.__setattr__(self, "include_transaction_to_transaction", _as_bool(self.include_transaction_to_transaction, False))

        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))
        object.__setattr__(self, "register_results", _as_bool(self.register_results, True))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "CorrelationOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "CORRELATION_SALT", None)
            or _setting(settings, "GRAPH_CYCLE_SALT", None)
            or _setting(settings, "GRAPH_COMMUNITY_SALT", None)
            or _setting(settings, "GRAPH_FILTER_SALT", None)
            or _setting(settings, "GRAPH_SERIALIZATION_SALT", None)
            or _setting(settings, "ML_VALIDATION_SALT", None)
            or _setting(settings, "ML_MODEL_SERVICE_SALT", None)
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
            enabled=_as_bool(_setting(settings, "CORRELATION_ENABLED", True), True),
            synthetic_required=_as_bool(_setting(settings, "CORRELATION_REQUIRE_SYNTHETIC", True), True),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(_setting(settings, "CORRELATION_ALLOW_IN_PRODUCTION", False), False),
            salt=salt,
            namespace=str(_setting(settings, "CORRELATION_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "CORRELATION_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            temporal_tolerance_hours=_as_int(
                _setting(settings, "CORRELATION_TEMPORAL_TOLERANCE_HOURS", _DEFAULT_TEMPORAL_TOLERANCE_HOURS),
                _DEFAULT_TEMPORAL_TOLERANCE_HOURS,
            ),
            min_confidence=_as_float(_setting(settings, "CORRELATION_MIN_CONFIDENCE", _DEFAULT_MIN_CONFIDENCE), _DEFAULT_MIN_CONFIDENCE),
            max_records=_as_int(_setting(settings, "CORRELATION_MAX_RECORDS", _DEFAULT_MAX_RECORDS), _DEFAULT_MAX_RECORDS),
            max_candidates=_as_int(_setting(settings, "CORRELATION_MAX_CANDIDATES", _DEFAULT_MAX_CANDIDATES), _DEFAULT_MAX_CANDIDATES),
            max_issues=_as_int(_setting(settings, "CORRELATION_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(
                _setting(settings, "CORRELATION_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_registrations=_as_int(
                _setting(settings, "CORRELATION_MAX_REGISTRATIONS", _DEFAULT_MAX_REGISTRATIONS),
                _DEFAULT_MAX_REGISTRATIONS,
            ),
            max_time_ms=_as_int(_setting(settings, "CORRELATION_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS), _DEFAULT_MAX_TIME_MS),
            include_complaint_to_transaction=_as_bool(
                _setting(settings, "CORRELATION_INCLUDE_COMPLAINT_TO_TRANSACTION", True),
                True,
            ),
            include_complaint_to_complaint=_as_bool(
                _setting(settings, "CORRELATION_INCLUDE_COMPLAINT_TO_COMPLAINT", True),
                True,
            ),
            include_account_to_entity=_as_bool(
                _setting(settings, "CORRELATION_INCLUDE_ACCOUNT_TO_ENTITY", True),
                True,
            ),
            include_alert_to_case=_as_bool(
                _setting(settings, "CORRELATION_INCLUDE_ALERT_TO_CASE", True),
                True,
            ),
            include_transaction_to_transaction=_as_bool(
                _setting(settings, "CORRELATION_INCLUDE_TRANSACTION_TO_TRANSACTION", False),
                False,
            ),
            drop_forbidden_fields=_as_bool(_setting(settings, "CORRELATION_DROP_FORBIDDEN_FIELDS", False), False),
            register_results=_as_bool(_setting(settings, "CORRELATION_REGISTER_RESULTS", True), True),
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
            "temporal_tolerance_hours": self.temporal_tolerance_hours,
            "min_confidence": _round6(self.min_confidence),
            "limits": {
                "max_records": self.max_records,
                "max_candidates": self.max_candidates,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_registrations": self.max_registrations,
                "max_time_ms": self.max_time_ms,
            },
            "inclusions": {
                "complaint_to_transaction": self.include_complaint_to_transaction,
                "complaint_to_complaint": self.include_complaint_to_complaint,
                "account_to_entity": self.include_account_to_entity,
                "alert_to_case": self.include_alert_to_case,
                "transaction_to_transaction": self.include_transaction_to_transaction,
            },
            "flags": {
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "register_results": self.register_results,
            },
        }


# -----------------------------------------------------------------------------
# Request and Result models
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "complaints",
        "transactions",
        "accounts",
        "entities",
        "entity_links",
        "alerts",
        "cases",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class CorrelationRequest:
    """
    Bounded correlation analysis request.
    """

    complaints: Any = None
    transactions: Any = None
    accounts: Any = None
    entities: Any = None
    entity_links: Any = None
    alerts: Any = None
    cases: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> CorrelationRequest:
    if isinstance(request, CorrelationRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(CorrelationRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return CorrelationRequest(**clean)
            except Exception:
                return CorrelationRequest(metadata=request)

        return CorrelationRequest(metadata=request)

    return CorrelationRequest(metadata=request)


@dataclass(frozen=True, slots=True)
class CorrelationCandidate:
    """
    One bounded correlation candidate.

    Candidates are investigative leads only. They are not proof of wrongdoing.
    """

    correlation_id: str = ""
    kind: CorrelationKind | str = CorrelationKind.OTHER
    source_ref_hash: Optional[str] = None
    target_ref_hash: Optional[str] = None
    confidence: float = 0.0
    score: float = 0.0
    status: CorrelationStatus | str = CorrelationStatus.UNREVIEWED
    reasons: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _normalize_enum_option(CorrelationKind, self.kind, CorrelationKind.OTHER))
        object.__setattr__(
            self,
            "source_ref_hash",
            _clean_text(self.source_ref_hash, _MAX_HASH_LENGTH).lower() if self.source_ref_hash else None,
        )
        object.__setattr__(
            self,
            "target_ref_hash",
            _clean_text(self.target_ref_hash, _MAX_HASH_LENGTH).lower() if self.target_ref_hash else None,
        )
        object.__setattr__(self, "confidence", _round6(_clip_float(self.confidence, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(CorrelationStatus, self.status, CorrelationStatus.UNREVIEWED),
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
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.correlation_id:
            object.__setattr__(
                self,
                "correlation_id",
                _fingerprint_payload(
                    {
                        "kind": _enum_value(self.kind),
                        "source": self.source_ref_hash,
                        "target": self.target_ref_hash,
                    }
                )[:32],
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "kind": _enum_value(self.kind, CorrelationKind.OTHER.value),
            "source_ref_hash": self.source_ref_hash,
            "target_ref_hash": self.target_ref_hash,
            "confidence": float(self.confidence),
            "score": float(self.score),
            "status": _enum_value(self.status, CorrelationStatus.UNREVIEWED.value),
            "reasons": list(self.reasons),
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_CORRELATION_CAVEATS),
            "safety_flags": dict(_CORRELATION_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    """
    Safe bounded correlation analysis result.
    """

    ok: bool = True
    status: AnalysisStatus | str = AnalysisStatus.PASSED
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    candidates: tuple[CorrelationCandidate, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[CorrelationIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(self, "status", _normalize_enum_option(AnalysisStatus, self.status, AnalysisStatus.PASSED))
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "candidates", tuple(self.candidates or ()))
        object.__setattr__(
            self,
            "counts",
            MappingProxyType({str(key): max(0, _as_int(value, 0)) for key, value in (self.counts or {}).items()}),
        )
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": CORRELATION_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, AnalysisStatus.PASSED.value),
                        "request_id": self.request_id,
                        "candidate_count": len(self.candidates),
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
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_CORRELATION_CAVEATS),
            "safety_flags": dict(_CORRELATION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local correlation registry
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _RegisteredCorrelation:
    candidate: CorrelationCandidate
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class CorrelationRegistry:
    """
    Bounded process-local correlation registry.
    """

    def __init__(self, max_registrations: int = _DEFAULT_MAX_REGISTRATIONS) -> None:
        self.max_registrations = max(1, int(max_registrations))
        self._registrations: dict[str, _RegisteredCorrelation] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, candidate: CorrelationCandidate) -> str:
        with self._lock:
            cid = _clean_text(candidate.correlation_id, 128)

            if not cid:
                cid = candidate.fingerprint[:32] if hasattr(candidate, "fingerprint") else _sha256_hex(str(len(self._registrations) + 1))[:32]

            if cid in self._registrations:
                self._registrations[cid] = _RegisteredCorrelation(candidate=candidate, registered_at=_now_utc())
                return cid

            self._registrations[cid] = _RegisteredCorrelation(candidate=candidate, registered_at=_now_utc())
            self._order.append(cid)

            if len(self._order) > self.max_registrations:
                evict_id = self._order.pop(0)
                self._registrations.pop(evict_id, None)

            return cid

    def get(self, correlation_id: Any) -> Optional[CorrelationCandidate]:
        key = _clean_text(correlation_id, 128)

        with self._lock:
            entry = self._registrations.get(key)
            return entry.candidate if entry is not None else None

    def list_candidates(self, *, limit: int = 50) -> tuple[CorrelationCandidate, ...]:
        with self._lock:
            out: list[CorrelationCandidate] = []

            for cid in self._order[: max(1, int(limit))]:
                entry = self._registrations.get(cid)

                if entry is not None:
                    out.append(entry.candidate)

            return tuple(out)

    def summarize(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            out: list[dict[str, Any]] = []

            for cid in self._order[: max(1, int(limit))]:
                entry = self._registrations.get(cid)

                if entry is None:
                    continue

                candidate = entry.candidate

                out.append(
                    {
                        "correlation_id": candidate.correlation_id,
                        "kind": _enum_value(candidate.kind, CorrelationKind.OTHER.value),
                        "confidence": float(candidate.confidence),
                        "score": float(candidate.score),
                        "status": _enum_value(candidate.status, CorrelationStatus.UNREVIEWED.value),
                        "registered_at": entry.registered_at.isoformat(),
                    }
                )

            return out

    def clear(self) -> None:
        with self._lock:
            self._registrations.clear()
            self._order.clear()

    def safe_summary(self, *, limit: int = 50) -> dict[str, Any]:
        with self._lock:
            status_counter = Counter(
                _enum_value(entry.candidate.status, CorrelationStatus.UNREVIEWED.value)
                for entry in self._registrations.values()
            )
            kind_counter = Counter(
                _enum_value(entry.candidate.kind, CorrelationKind.OTHER.value)
                for entry in self._registrations.values()
            )

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_registrations": self.max_registrations,
            "registered_candidates": len(self._order),
            "by_status": dict(status_counter),
            "by_kind": dict(kind_counter),
            "recent": self.summarize(limit=limit),
        }


_default_registry: Optional[CorrelationRegistry] = None
_default_registry_lock = threading.Lock()


def get_correlation_registry(
    max_registrations: int | None = None,
    *,
    rebuild: bool = False,
) -> CorrelationRegistry:
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = CorrelationRegistry(
                max_registrations=max_registrations if max_registrations is not None else _DEFAULT_MAX_REGISTRATIONS
            )

        return _default_registry


# -----------------------------------------------------------------------------
# Input extraction and sanitization
# -----------------------------------------------------------------------------


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, CorrelationResult):
        return []

    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "examples"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])

        return [data]

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray, memoryview)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _extract_subject(record: Any, options: CorrelationOptions) -> Optional[str]:
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


def _sanitize_records(
    raw_records: Sequence[Any],
    category: str,
    options: CorrelationOptions,
    issues: list[CorrelationIssue],
    start_time: float,
) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []

    for source_index, record in enumerate(raw_records):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="record_sanitization_time_budget_exhausted",
                message="Record sanitization stopped after reaching configured time budget.",
                details={"category": category, "processed": len(cleaned), "remaining": max(0, len(raw_records) - source_index)},
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
                        details={"category": category, "source_index": source_index},
                    )
                    continue

                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="forbidden_feature",
                    message="Forbidden or label-like feature field rejected.",
                    field=key_text,
                    details={"category": category, "source_index": source_index},
                )
                valid = False
                break

            clean_features[canonical] = raw_value

        if not valid:
            continue

        cleaned.append(
            {
                "index": len(cleaned),
                "source_index": source_index,
                "category": category,
                "subject_ref_hash": subject,
                "features": clean_features,
            }
        )

    return cleaned


# -----------------------------------------------------------------------------
# Correlation Engine
# -----------------------------------------------------------------------------


class CorrelationEngine:
    """
    Bounded deterministic synthetic correlation engine.
    """

    def __init__(self, options: CorrelationOptions | None = None, registry: CorrelationRegistry | None = None) -> None:
        self.options = options or CorrelationOptions.from_settings()
        self.registry = registry or get_correlation_registry(self.options.max_registrations)
        self._lock = threading.RLock()

    def _correlate_complaints_to_transactions(
        self,
        complaints: Sequence[Mapping[str, Any]],
        transactions: Sequence[Mapping[str, Any]],
        options: CorrelationOptions,
        issues: list[CorrelationIssue],
        start_time: float,
    ) -> list[CorrelationCandidate]:
        candidates: list[CorrelationCandidate] = []
        tolerance = timedelta(hours=int(options.temporal_tolerance_hours))

        txn_by_account: dict[str, list[Mapping[str, Any]]] = defaultdict(list)

        for txn in transactions:
            sender = txn.get("features", {}).get("sender_account_id") or txn.get("features", {}).get("sender")
            receiver = txn.get("features", {}).get("receiver_account_id") or txn.get("features", {}).get("receiver")

            if sender:
                txn_by_account[_clean_text(sender, _MAX_HASH_LENGTH).lower()].append(txn)
            if receiver:
                txn_by_account[_clean_text(receiver, _MAX_HASH_LENGTH).lower()].append(txn)

        for complaint in complaints:
            if _time_exceeded(start_time, options.max_time_ms):
                break

            c_features = complaint.get("features", {})
            c_subject = complaint.get("subject_ref_hash")
            c_victim = _clean_text(c_features.get("victim_account_id") or c_features.get("victim"), _MAX_HASH_LENGTH).lower()
            c_suspect = _clean_text(c_features.get("suspected_account_id") or c_features.get("suspect"), _MAX_HASH_LENGTH).lower()
            c_time = _parse_datetime(c_features.get("reported_at") or c_features.get("occurred_at"))
            c_amount = _coerce_optional_float(c_features.get("amount"), allow_bool=False)
            c_currency = _normalize_currency(c_features.get("currency"))

            target_accounts = set()
            if c_victim:
                target_accounts.add(c_victim)
            if c_suspect:
                target_accounts.add(c_suspect)
            if c_subject:
                target_accounts.add(c_subject)

            for account_hash in target_accounts:
                for txn in txn_by_account.get(account_hash, []):
                    t_features = txn.get("features", {})
                    t_subject = txn.get("subject_ref_hash")
                    t_time = _parse_datetime(t_features.get("occurred_at") or t_features.get("timestamp"))
                    t_amount = _coerce_optional_float(t_features.get("amount"), allow_bool=False)
                    t_currency = _normalize_currency(t_features.get("currency"))

                    reasons: list[str] = []
                    confidence = 0.0

                    if c_time and t_time:
                        delta = abs((c_time - t_time).total_seconds())
                        if delta <= tolerance.total_seconds():
                            reasons.append("temporal_proximity")
                            confidence += 0.4

                    if c_amount is not None and t_amount is not None and c_currency and t_currency and c_currency == t_currency:
                        if math.isclose(float(c_amount), float(t_amount), rel_tol=1e-4, abs_tol=0.01):
                            reasons.append("exact_amount_match")
                            confidence += 0.5
                        elif float(c_amount) > 0 and float(t_amount) > 0:
                            ratio = min(float(c_amount), float(t_amount)) / max(float(c_amount), float(t_amount))
                            if ratio >= 0.8:
                                reasons.append("approximate_amount_match")
                                confidence += 0.2

                    if account_hash == c_victim:
                        reasons.append("victim_account_overlap")
                        confidence += 0.1

                    if account_hash == c_suspect:
                        reasons.append("suspect_account_overlap")
                        confidence += 0.1

                    confidence = min(1.0, confidence)

                    if confidence >= options.min_confidence and reasons:
                        target_hash = t_subject or _clean_text(t_features.get("id"), _MAX_HASH_LENGTH).lower()

                        candidates.append(
                            CorrelationCandidate(
                                kind=CorrelationKind.COMPLAINT_TO_TRANSACTION,
                                source_ref_hash=c_subject,
                                target_ref_hash=target_hash,
                                confidence=confidence,
                                score=confidence,
                                status=CorrelationStatus.UNREVIEWED,
                                reasons=tuple(reasons),
                                metadata={
                                    "account_overlap_hash": account_hash,
                                    "currency_aligned": bool(c_currency and t_currency and c_currency == t_currency),
                                    "raw_values_retained": False,
                                },
                            )
                        )

        return candidates

    def _correlate_complaints_to_complaints(
        self,
        complaints: Sequence[Mapping[str, Any]],
        options: CorrelationOptions,
        issues: list[CorrelationIssue],
        start_time: float,
    ) -> list[CorrelationCandidate]:
        candidates: list[CorrelationCandidate] = []

        for i in range(len(complaints)):
            if _time_exceeded(start_time, options.max_time_ms):
                break

            c1 = complaints[i]
            c1_features = c1.get("features", {})
            c1_subject = c1.get("subject_ref_hash")
            c1_victim = _clean_text(c1_features.get("victim_account_id") or c1_features.get("victim"), _MAX_HASH_LENGTH).lower()
            c1_suspect = _clean_text(c1_features.get("suspected_account_id") or c1_features.get("suspect"), _MAX_HASH_LENGTH).lower()

            for j in range(i + 1, len(complaints)):
                c2 = complaints[j]
                c2_features = c2.get("features", {})
                c2_subject = c2.get("subject_ref_hash")
                c2_victim = _clean_text(c2_features.get("victim_account_id") or c2_features.get("victim"), _MAX_HASH_LENGTH).lower()
                c2_suspect = _clean_text(c2_features.get("suspected_account_id") or c2_features.get("suspect"), _MAX_HASH_LENGTH).lower()

                reasons: list[str] = []
                confidence = 0.0

                if c1_victim and c2_victim and c1_victim == c2_victim:
                    reasons.append("shared_victim")
                    confidence += 0.6

                if c1_suspect and c2_suspect and c1_suspect == c2_suspect:
                    reasons.append("shared_suspect")
                    confidence += 0.6

                confidence = min(1.0, confidence)

                if confidence >= options.min_confidence and reasons:
                    candidates.append(
                        CorrelationCandidate(
                            kind=CorrelationKind.COMPLAINT_TO_COMPLAINT,
                            source_ref_hash=c1_subject,
                            target_ref_hash=c2_subject,
                            confidence=confidence,
                            score=confidence,
                            status=CorrelationStatus.UNREVIEWED,
                            reasons=tuple(reasons),
                            metadata={"raw_values_retained": False},
                        )
                    )

        return candidates

    def analyze(self, request: Any) -> CorrelationResult:
        """
        Run one bounded synthetic correlation analysis job.
        """
        opts = self.options
        issues: list[CorrelationIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)
        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": CORRELATION_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: AnalysisStatus,
            candidates: Sequence[CorrelationCandidate] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> CorrelationResult:
            resolved_counts: dict[str, int] = {
                "submitted": 0,
                "processed": 0,
                "candidates_generated": len(candidates),
                "candidates_registered": 0,
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update({str(key): max(0, _as_int(value, 0)) for key, value in counts.items()})

            resolved_counts["issues"] = len(issues)

            metadata = {
                "correlation_version": CORRELATION_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
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
                "caveats": list(_CORRELATION_CAVEATS),
                "safety_flags": dict(_CORRELATION_SAFETY_FLAGS),
            }

            return CorrelationResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                candidates=tuple(candidates),
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
                code="correlation_engine_disabled",
                message="Correlation engine is disabled.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Correlation engine requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Correlation engine is blocked in production-like environments.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_correlation_action_metadata",
                message="Correlation request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        raw_complaints = _iter_records(req.complaints)[: opts.max_records]
        raw_transactions = _iter_records(req.transactions)[: opts.max_records]
        raw_accounts = _iter_records(req.accounts)[: opts.max_records]
        raw_entities = _iter_records(req.entities)[: opts.max_records]

        complaints = _sanitize_records(raw_complaints, "complaint", opts, issues, start_time)
        transactions = _sanitize_records(raw_transactions, "transaction", opts, issues, start_time)
        accounts = _sanitize_records(raw_accounts, "account", opts, issues, start_time)
        entities = _sanitize_records(raw_entities, "entity", opts, issues, start_time)

        all_candidates: list[CorrelationCandidate] = []

        if opts.include_complaint_to_transaction and complaints and transactions:
            all_candidates.extend(
                self._correlate_complaints_to_transactions(complaints, transactions, opts, issues, start_time)
            )

        if opts.include_complaint_to_complaint and len(complaints) > 1:
            all_candidates.extend(
                self._correlate_complaints_to_complaints(complaints, opts, issues, start_time)
            )

        # Sort by confidence descending, then by deterministic hash tie-break
        all_candidates.sort(
            key=lambda c: (
                -float(c.confidence),
                c.source_ref_hash or "",
                c.target_ref_hash or "",
            )
        )

        if len(all_candidates) > opts.max_candidates:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="candidate_limit_truncation",
                message="Correlation candidates exceeded configured limit and were truncated.",
                details={
                    "generated": len(all_candidates),
                    "max_candidates": opts.max_candidates,
                },
            )
            all_candidates = all_candidates[: opts.max_candidates]

        registered_count = 0

        if opts.register_results:
            for candidate in all_candidates:
                try:
                    self.registry.register(candidate)
                    registered_count += 1
                except Exception as exc:
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="candidate_registration_failed",
                        message="Correlation candidate registration failed.",
                        details={"exception_type": type(exc).__name__},
                    )

        counts = {
            "complaints_sanitized": len(complaints),
            "transactions_sanitized": len(transactions),
            "accounts_sanitized": len(accounts),
            "entities_sanitized": len(entities),
            "candidates_generated": len(all_candidates),
            "candidates_registered": registered_count,
        }

        status = AnalysisStatus.PASSED

        if _has_error(issues):
            status = AnalysisStatus.FAILED
        elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
            status = AnalysisStatus.DEGRADED
        elif not all_candidates:
            status = AnalysisStatus.SKIPPED

        return make_result(
            ok=status in {AnalysisStatus.PASSED, AnalysisStatus.DEGRADED},
            status=status,
            candidates=all_candidates,
            counts=counts,
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "registry": self.registry.safe_summary(limit=self.options.max_summary_items),
            "caveats": list(_CORRELATION_CAVEATS),
            "safety_flags": dict(_CORRELATION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default engine and public API
# -----------------------------------------------------------------------------


_default_engine: Optional[CorrelationEngine] = None
_default_engine_lock = threading.Lock()


def get_correlation_options(settings: Any | None = None) -> CorrelationOptions:
    return CorrelationOptions.from_settings(settings)


def get_correlation_engine(
    options: CorrelationOptions | None = None,
    *,
    rebuild: bool = False,
) -> CorrelationEngine:
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = CorrelationEngine(options=options or CorrelationOptions.from_settings())

        return _default_engine


def correlate(
    request: Any,
    options: CorrelationOptions | None = None,
    *,
    engine: CorrelationEngine | None = None,
) -> CorrelationResult:
    """
    Run one bounded synthetic correlation analysis job.
    """
    active_engine = engine or get_correlation_engine(options)
    return active_engine.analyze(request)


def analyze_correlations(
    request: Any,
    options: CorrelationOptions | None = None,
    *,
    engine: CorrelationEngine | None = None,
) -> CorrelationResult:
    """
    Alias for `correlate`.
    """
    return correlate(request, options=options, engine=engine)


def get_correlation_candidate(correlation_id: Any, *, registry: CorrelationRegistry | None = None) -> Optional[CorrelationCandidate]:
    """
    Return one registered correlation candidate.
    """
    active_registry = registry or get_correlation_registry()
    return active_registry.get(correlation_id)


def list_correlation_candidates(*, limit: int = 50, registry: CorrelationRegistry | None = None) -> tuple[CorrelationCandidate, ...]:
    """
    Return registered correlation candidates.
    """
    active_registry = registry or get_correlation_registry()
    return active_registry.list_candidates(limit=limit)


def summarize_correlation_candidates(*, limit: int = 50, registry: CorrelationRegistry | None = None) -> list[dict[str, Any]]:
    """
    Return safe registered correlation candidate summaries.
    """
    active_registry = registry or get_correlation_registry()
    return active_registry.summarize(limit=limit)


def get_correlation_health(*, engine: CorrelationEngine | None = None) -> dict[str, Any]:
    """
    Return safe correlation-engine health.
    """
    active_engine = engine or get_correlation_engine()
    opts = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=opts.max_summary_items)
    issues: list[CorrelationIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="correlation_engine_disabled",
            message="Correlation engine is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Correlation engine requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Correlation engine is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "registry": registry_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(_CORRELATION_CAVEATS),
        "safety_flags": dict(_CORRELATION_SAFETY_FLAGS),
    }


def get_correlation_metadata() -> dict[str, Any]:
    """
    Return safe, serializable correlation-engine metadata.
    """
    options = CorrelationOptions.from_settings()
    registry = get_correlation_registry(options.max_registrations)

    return {
        "package": "muleguard.backend.correlation",
        "version": CORRELATION_VERSION,
        "kinds": [kind.value for kind in CorrelationKind],
        "statuses": [status.value for status in CorrelationStatus],
        "analysis_statuses": [status.value for status in AnalysisStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "registry": registry.safe_summary(limit=options.max_summary_items),
        "hard_limits": {
            "max_records": _HARD_MAX_RECORDS,
            "max_candidates": _HARD_MAX_CANDIDATES,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_registrations": _HARD_MAX_REGISTRATIONS,
            "max_time_ms": _HARD_MAX_TIME_MS,
            "max_temporal_tolerance_hours": _HARD_MAX_TEMPORAL_TOLERANCE_HOURS,
        },
        "forbidden_correlation_field_count": len(_FORBIDDEN_CORRELATION_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_CORRELATION_CAVEATS),
        "safety_flags": dict(_CORRELATION_SAFETY_FLAGS),
    }


__all__ = [
    "AnalysisStatus",
    "CorrelationCandidate",
    "CorrelationEngine",
    "CorrelationIssue",
    "CorrelationKind",
    "CorrelationOptions",
    "CorrelationRegistry",
    "CorrelationRequest",
    "CorrelationResult",
    "CorrelationStatus",
    "IssueSeverity",
    "analyze_correlations",
    "correlate",
    "get_correlation_candidate",
    "get_correlation_engine",
    "get_correlation_health",
    "get_correlation_metadata",
    "get_correlation_options",
    "get_correlation_registry",
    "list_correlation_candidates",
    "summarize_correlation_candidates",
]