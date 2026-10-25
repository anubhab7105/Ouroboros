"""
MULEGUARD backend correlation normalizers.

This module provides the canonical bounded normalization layer for the
synthetic MULEGUARD correlation analysis subsystem.

Primary responsibilities:

- normalize raw correlation inputs (complaints, transactions, accounts,
  entities, alerts, and cases) into bounded, sanitized, pseudonymous records;
- enforce strict field allowlists and blocklists, rejecting raw PII, ground
  truth labels, raw narratives, secrets, tokens, passwords, database URLs,
  filesystem paths, and model artifact paths;
- canonicalize field names, timestamps, currencies, and bounded numeric
  amounts;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values, raw identifiers, raw narratives, subject-label
  pairs, secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited correlation fields;
- provide deterministic, bounded, API-safe normalization results with safe
  summaries, issue reporting, fingerprints, and metadata;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module normalizes correlation inputs only. It does not train models,
deploy models, persist durable artifacts, call external systems, authenticate
users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for correlation normalization.
- Normalized outputs are investigative leads only. They are not proof of
  wrongdoing, common control, or criminal association.
- Labels must never be used as correlation features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as normalization inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden inputs. Subject linkage is pseudonymous and
  salted.
- Currency amounts are never converted or blended across currencies.
- Normalization handling must never trigger automatic adverse customer action
  such as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable normalizations are reported honestly as unavailable
  rather than invented.
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
candidates, normalized records, explanations, validation reports, and case
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
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
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


logger = logging.getLogger("muleguard.backend.correlation.normalizers")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

NORMALIZER_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.correlation.normalizers.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"

DEFAULT_MAX_RECORDS: Final[int] = 10_000
HARD_MAX_RECORDS: Final[int] = 100_000

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

DEFAULT_MAX_TIME_MS: Final[int] = 30_000
HARD_MAX_TIME_MS: Final[int] = 300_000

MAX_TEXT_LENGTH: Final[int] = 512
MAX_HASH_LENGTH: Final[int] = 256
MAX_REASON_TEXT_LENGTH: Final[int] = 300

CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")
CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")

MONEY_QUANT: Final[Decimal] = Decimal("0.01")

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

FORBIDDEN_NORMALIZER_FIELDS: Final[frozenset[str]] = frozenset(
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

FORBIDDEN_NORMALIZER_TOKENS: Final[tuple[str, ...]] = (
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

NORMALIZER_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic correlation normalization only. Do not use with real customer data.",
    "Normalized records are investigative inputs only and are not proof of wrongdoing.",
    "Normalization must not trigger automatic adverse customer action.",
    "Labels must never be used as correlation features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Currency amounts are never converted or blended across currencies.",
    "The bundled normalizer is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

NORMALIZER_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_normalization": True,
        "bounded_normalization_required": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)

# Allowed fields per category (canonicalized)
ALLOWED_COMPLAINT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "complaint_id",
        "reported_at",
        "category",
        "victim_account_id",
        "suspected_account_id",
        "transaction_reference",
        "amount",
        "currency",
    }
)

ALLOWED_TRANSACTION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "transaction_id",
        "sender_account_id",
        "receiver_account_id",
        "amount",
        "currency",
        "occurred_at",
        "status",
        "channel",
    }
)

ALLOWED_ACCOUNT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "account_id",
        "account_type",
        "status",
        "created_at",
    }
)

ALLOWED_ENTITY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "entity_id",
        "entity_type",
        "identifier_hash",
    }
)

ALLOWED_ALERT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "alert_id",
        "alert_type",
        "triggered_at",
        "source_system",
    }
)

ALLOWED_CASE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "case_id",
        "case_type",
        "opened_at",
        "status",
    }
)

CATEGORY_ALLOWED_FIELDS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "complaint": ALLOWED_COMPLAINT_FIELDS,
        "transaction": ALLOWED_TRANSACTION_FIELDS,
        "account": ALLOWED_ACCOUNT_FIELDS,
        "entity": ALLOWED_ENTITY_FIELDS,
        "alert": ALLOWED_ALERT_FIELDS,
        "case": ALLOWED_CASE_FIELDS,
    }
)

# Field aliases mapping raw/common names to canonical names
FIELD_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "id": "id",
        "acct_id": "account_id",
        "account": "account_id",
        "sender": "sender_account_id",
        "from_account_id": "sender_account_id",
        "receiver": "receiver_account_id",
        "to_account_id": "receiver_account_id",
        "victim": "victim_account_id",
        "suspect": "suspected_account_id",
        "suspect_account_id": "suspected_account_id",
        "txn_id": "transaction_id",
        "txn_reference": "transaction_reference",
        "transaction_ref": "transaction_reference",
        "timestamp": "occurred_at",
        "time": "occurred_at",
        "date": "occurred_at",
        "filed_at": "reported_at",
        "reported_date": "reported_at",
        "created_date": "created_at",
        "opened_date": "opened_at",
        "triggered_date": "triggered_at",
        "ccy": "currency",
        "value": "amount",
        "kind": "category",
        "type": "category",
        "alert_category": "alert_type",
        "case_category": "case_type",
        "entity_kind": "entity_type",
        "account_kind": "account_type",
        "state": "status",
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class RecordCategory(str, Enum):
    """
    Bounded record category.
    """

    COMPLAINT = "complaint"
    TRANSACTION = "transaction"
    ACCOUNT = "account"
    ENTITY = "entity"
    ALERT = "alert"
    CASE = "case"
    UNKNOWN = "unknown"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class NormalizationStatus(str, Enum):
    """
    Overall normalization status.
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


def _parse_decimal(value: Any) -> Optional[Decimal]:
    if isinstance(value, Decimal):
        return value if value.is_finite() else None

    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        try:
            return Decimal(str(value))
        except (InvalidOperation, ValueError):
            return None

    text = _normalize_unicode(value).strip().replace(",", "")

    if not text:
        return None

    try:
        parsed = Decimal(text)
    except (InvalidOperation, ValueError, TypeError):
        return None

    return parsed if parsed.is_finite() else None


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

    if canonical in FORBIDDEN_NORMALIZER_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in FORBIDDEN_NORMALIZER_TOKENS)


def _is_label_leakage_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in LABEL_LEAKAGE_FIELDS:
        return True

    return any(token in canonical for token in LABEL_LEAKAGE_TOKENS)


def _is_sensitive_detail_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    return any(token in canonical for token in SENSITIVE_DETAIL_TOKENS)


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

    if CURRENCY_RE.match(text):
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


def _subject_hash(value: Any, options: "NormalizationOptions") -> Optional[str]:
    text = _clean_text(value, MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.correlation.normalizers.subject.{safe_namespace}"
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


def _append_issue(
    issues: list["NormalizationIssue"],
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

        issues[-1] = NormalizationIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        NormalizationIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _has_error(issues: Sequence["NormalizationIssue"]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence["NormalizationIssue"]) -> tuple["NormalizationIssue", ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list["NormalizationIssue"] = []

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
# Issue and Result Models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizationIssue:
    """
    Safe normalization issue.
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
class NormalizedRecord:
    """
    One bounded normalized record.
    """

    category: RecordCategory | str = RecordCategory.UNKNOWN
    subject_ref_hash: Optional[str] = None
    features: Mapping[str, Any] = dataclass_field(default_factory=dict)
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "category",
            _normalize_enum_option(RecordCategory, self.category, RecordCategory.UNKNOWN),
        )
        object.__setattr__(
            self,
            "subject_ref_hash",
            _clean_text(self.subject_ref_hash, MAX_HASH_LENGTH).lower() if self.subject_ref_hash else None,
        )
        object.__setattr__(self, "features", MappingProxyType(_as_mapping(self.features)))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": _enum_value(self.category, RecordCategory.UNKNOWN.value),
            "subject_ref_hash": self.subject_ref_hash,
            "features": _safe_detail_value(self.features),
            "metadata": _safe_detail_value(self.metadata),
            "raw_values_retained": False,
        }


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    """
    Safe bounded normalization result.
    """

    ok: bool = True
    status: NormalizationStatus | str = NormalizationStatus.PASSED
    records: tuple[NormalizedRecord, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[NormalizationIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(NormalizationStatus, self.status, NormalizationStatus.PASSED),
        )
        object.__setattr__(self, "records", tuple(self.records or ()))
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
                        "version": NORMALIZER_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, NormalizationStatus.PASSED.value),
                        "record_count": len(self.records),
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": _enum_value(self.status, NormalizationStatus.PASSED.value),
            "records": [record.to_dict() for record in self.records],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(NORMALIZER_CAVEATS),
            "safety_flags": dict(NORMALIZER_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizationOptions:
    """
    Bounded normalization policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE

    max_records: int = DEFAULT_MAX_RECORDS
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS

    drop_forbidden_fields: bool = True
    strict_currency_matching: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_token(self.dataset_mode) or "synthetic")
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(self, "salt", _ensure_salt(self.salt))
        object.__setattr__(self, "namespace", _normalize_token(self.namespace) or _DEFAULT_NAMESPACE)

        object.__setattr__(self, "max_records", _clamp_int(self.max_records, 1, HARD_MAX_RECORDS, DEFAULT_MAX_RECORDS))
        object.__setattr__(self, "max_issues", _clamp_int(self.max_issues, 1, HARD_MAX_ISSUES, DEFAULT_MAX_ISSUES))
        object.__setattr__(self, "max_summary_items", _clamp_int(self.max_summary_items, 1, HARD_MAX_SUMMARY_ITEMS, DEFAULT_MAX_SUMMARY_ITEMS))
        object.__setattr__(self, "max_time_ms", _clamp_int(self.max_time_ms, 100, HARD_MAX_TIME_MS, DEFAULT_MAX_TIME_MS))

        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, True))
        object.__setattr__(self, "strict_currency_matching", _as_bool(self.strict_currency_matching, True))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "NormalizationOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "CORRELATION_NORMALIZER_SALT", None)
            or _setting(settings, "CORRELATION_SALT", None)
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
            enabled=_as_bool(_setting(settings, "CORRELATION_NORMALIZER_ENABLED", True), True),
            synthetic_required=_as_bool(_setting(settings, "CORRELATION_NORMALIZER_REQUIRE_SYNTHETIC", True), True),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(_setting(settings, "CORRELATION_NORMALIZER_ALLOW_IN_PRODUCTION", False), False),
            salt=salt,
            namespace=str(_setting(settings, "CORRELATION_NORMALIZER_NAMESPACE", _DEFAULT_NAMESPACE)),
            max_records=_as_int(_setting(settings, "CORRELATION_NORMALIZER_MAX_RECORDS", DEFAULT_MAX_RECORDS), DEFAULT_MAX_RECORDS),
            max_issues=_as_int(_setting(settings, "CORRELATION_NORMALIZER_MAX_ISSUES", DEFAULT_MAX_ISSUES), DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(_setting(settings, "CORRELATION_NORMALIZER_MAX_SUMMARY_ITEMS", DEFAULT_MAX_SUMMARY_ITEMS), DEFAULT_MAX_SUMMARY_ITEMS),
            max_time_ms=_as_int(_setting(settings, "CORRELATION_NORMALIZER_MAX_TIME_MS", DEFAULT_MAX_TIME_MS), DEFAULT_MAX_TIME_MS),
            drop_forbidden_fields=_as_bool(_setting(settings, "CORRELATION_NORMALIZER_DROP_FORBIDDEN_FIELDS", True), True),
            strict_currency_matching=_as_bool(_setting(settings, "CORRELATION_NORMALIZER_STRICT_CURRENCY", True), True),
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "synthetic_required": self.synthetic_required,
            "dataset_mode": self.dataset_mode,
            "production_like": self.production_like,
            "allow_in_production": self.allow_in_production,
            "namespace": self.namespace,
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
            "limits": {
                "max_records": self.max_records,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
            },
            "flags": {
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "strict_currency_matching": self.strict_currency_matching,
            },
        }


# -----------------------------------------------------------------------------
# Request model
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
class NormalizationRequest:
    """
    Bounded normalization request.
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


def _coerce_request(request: Any) -> NormalizationRequest:
    if isinstance(request, NormalizationRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(NormalizationRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return NormalizationRequest(**clean)
            except Exception:
                return NormalizationRequest(metadata=request)

        return NormalizationRequest(metadata=request)

    return NormalizationRequest(metadata=request)


# -----------------------------------------------------------------------------
# Input extraction and sanitization
# -----------------------------------------------------------------------------


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, NormalizationResult):
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


def _extract_subject(record: Any, options: NormalizationOptions) -> Optional[str]:
    value: Any = None

    if isinstance(record, Mapping):
        for key in SUBJECT_KEYS:
            if key in record:
                value = record[key]
                break
    else:
        for attr in SUBJECT_KEYS:
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
            if key not in SUBJECT_KEYS and key not in NON_FEATURE_KEYS
        }

    candidate = getattr(record, "features", None)

    if isinstance(candidate, Mapping):
        return dict(candidate)

    candidate = getattr(record, "values", None)

    if isinstance(candidate, Mapping):
        return dict(candidate)

    return {}


def _sanitize_record(
    record: Any,
    category: RecordCategory,
    options: NormalizationOptions,
    issues: list[NormalizationIssue],
    index: int,
) -> Optional[dict[str, Any]]:
    """
    Sanitize and canonicalize one record based on its category.
    """
    subject = _extract_subject(record, options)
    features = _extract_feature_mapping(record)
    clean_features: dict[str, Any] = {}
    allowed_fields = CATEGORY_ALLOWED_FIELDS.get(category.value, frozenset())

    for raw_key, raw_value in features.items():
        key_text = _clean_text(raw_key, 200)
        canonical = _canonical_field_name(key_text)

        if not canonical:
            continue

        # Apply aliases
        canonical = FIELD_ALIASES.get(canonical, canonical)

        if canonical in SUBJECT_KEYS or canonical in NON_FEATURE_KEYS:
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
                    details={"category": category.value, "index": index},
                )
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_feature",
                message="Forbidden or label-like feature field rejected.",
                field=key_text,
                details={"category": category.value, "index": index},
            )
            return None

        if allowed_fields and canonical not in allowed_fields:
            # Check if it's an ID field that maps to a known subject
            if canonical.endswith("_id") or canonical == "id":
                # Allow IDs but ensure they are hashed if they are raw
                pass
            else:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.INFO,
                    code="unknown_feature_dropped",
                    message="Feature field not in allowed list for category and was omitted.",
                    field=key_text,
                    details={"category": category.value, "index": index},
                )
                continue

        if canonical in clean_features:
            continue

        # Type-specific normalization
        if canonical.endswith("_at") or canonical.endswith("_date") or canonical == "timestamp":
            dt = _parse_datetime(raw_value)
            if dt:
                clean_features[canonical] = dt.isoformat()
            else:
                clean_features[canonical] = None
        elif canonical == "currency":
            curr = _normalize_currency(raw_value)
            if curr:
                clean_features[canonical] = curr
            else:
                clean_features[canonical] = None
        elif canonical == "amount":
            dec = _parse_decimal(raw_value)
            if dec is not None and dec >= 0:
                clean_features[canonical] = str(dec.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP))
            else:
                clean_features[canonical] = None
        elif canonical.endswith("_id") or canonical == "id" or canonical == "identifier_hash":
            text = _clean_text(raw_value, MAX_HASH_LENGTH)
            if text:
                if _is_safe_hash(text):
                    clean_features[canonical] = text.lower()
                else:
                    # Hash raw IDs to ensure pseudonymity
                    domain = f"muleguard.correlation.normalizers.field.{category.value}.{canonical}"
                    clean_features[canonical] = _hmac_hex(options.salt, domain, text)[:40]
            else:
                clean_features[canonical] = None
        elif canonical in {"status", "category", "type", "channel", "kind"}:
            clean_features[canonical] = _normalize_token(raw_value) or None
        else:
            clean_features[canonical] = _clean_text(raw_value, MAX_TEXT_LENGTH) or None

    # Ensure amount and currency are paired
    if "amount" in clean_features and clean_features["amount"] is not None:
        if "currency" not in clean_features or clean_features["currency"] is None:
            clean_features["currency"] = "UNKNOWN"
    elif "currency" in clean_features and clean_features["currency"] is not None:
        if "amount" not in clean_features or clean_features["amount"] is None:
            clean_features["amount"] = None
            clean_features["currency"] = None

    return {
        "category": category.value,
        "subject_ref_hash": subject,
        "features": clean_features,
    }


def _sanitize_records(
    raw_records: Sequence[Any],
    category: RecordCategory,
    options: NormalizationOptions,
    issues: list[NormalizationIssue],
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
                details={"category": category.value, "processed": len(cleaned), "remaining": max(0, len(raw_records) - source_index)},
            )
            break

        sanitized = _sanitize_record(record, category, options, issues, source_index)

        if sanitized is not None:
            cleaned.append(sanitized)

    return cleaned


# -----------------------------------------------------------------------------
# Normalizer Engine
# -----------------------------------------------------------------------------


class CorrelationNormalizer:
    """
    Bounded deterministic synthetic correlation normalizer.
    """

    def __init__(self, options: NormalizationOptions | None = None) -> None:
        self.options = options or NormalizationOptions.from_settings()
        self._lock = threading.RLock()

    def normalize(self, request: Any) -> NormalizationResult:
        """
        Run one bounded synthetic normalization job.
        """
        opts = self.options
        issues: list[NormalizationIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)
        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": NORMALIZER_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: NormalizationStatus,
            records: Sequence[NormalizedRecord] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> NormalizationResult:
            resolved_counts: dict[str, int] = {
                "submitted": 0,
                "processed": 0,
                "normalized": len(records),
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update({str(key): max(0, _as_int(value, 0)) for key, value in counts.items()})

            resolved_counts["issues"] = len(issues)

            metadata = {
                "normalizer_version": NORMALIZER_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_values_retained": False,
                "subject_label_pairs_retained": False,
                "narratives_retained": False,
                "identifiers_retained": False,
                "secrets_retained": False,
                "caveats": list(NORMALIZER_CAVEATS),
                "safety_flags": dict(NORMALIZER_SAFETY_FLAGS),
            }

            return NormalizationResult(
                ok=ok,
                status=status,
                records=tuple(records),
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
                code="normalizer_disabled",
                message="Correlation normalizer is disabled.",
            )
            return make_result(False, NormalizationStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Correlation normalizer requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, NormalizationStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Correlation normalizer is blocked in production-like environments.",
            )
            return make_result(False, NormalizationStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_normalization_action_metadata",
                message="Normalization request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, NormalizationStatus.BLOCKED)

        # Process each category
        all_raw = []
        category_map = {
            "complaint": (req.complaints, RecordCategory.COMPLAINT),
            "transaction": (req.transactions, RecordCategory.TRANSACTION),
            "account": (req.accounts, RecordCategory.ACCOUNT),
            "entity": (req.entities, RecordCategory.ENTITY),
            "alert": (req.alerts, RecordCategory.ALERT),
            "case": (req.cases, RecordCategory.CASE),
        }

        total_submitted = 0
        category_counts = {}

        for cat_name, (raw_data, cat_enum) in category_map.items():
            raw_records = _iter_records(raw_data)[: opts.max_records]
            count = len(raw_records)
            total_submitted += count
            category_counts[f"{cat_name}_submitted"] = count

            if count > 0:
                sanitized = _sanitize_records(raw_records, cat_enum, opts, issues, start_time)
                category_counts[f"{cat_name}_normalized"] = len(sanitized)
                
                for rec in sanitized:
                    all_raw.append(rec)

        if total_submitted > opts.max_records:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="normalization_input_truncated",
                message="Normalization input exceeded configured record limit and was truncated.",
                details={
                    "submitted": total_submitted,
                    "max_records": opts.max_records,
                },
            )
            all_raw = all_raw[: opts.max_records]

        normalized_records = [
            NormalizedRecord(
                category=rec["category"],
                subject_ref_hash=rec["subject_ref_hash"],
                features=rec["features"],
                metadata={"source_category": rec["category"]},
            )
            for rec in all_raw
        ]

        status = NormalizationStatus.PASSED

        if _has_error(issues):
            status = NormalizationStatus.FAILED
        elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
            status = NormalizationStatus.DEGRADED
        elif not normalized_records:
            status = NormalizationStatus.SKIPPED

        return make_result(
            ok=status in {NormalizationStatus.PASSED, NormalizationStatus.DEGRADED},
            status=status,
            records=normalized_records,
            counts=category_counts,
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "caveats": list(NORMALIZER_CAVEATS),
            "safety_flags": dict(NORMALIZER_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default normalizer and public API
# -----------------------------------------------------------------------------


_default_normalizer: Optional[CorrelationNormalizer] = None
_default_normalizer_lock = threading.Lock()


def get_normalization_options(settings: Any | None = None) -> NormalizationOptions:
    return NormalizationOptions.from_settings(settings)


def get_correlation_normalizer(
    options: NormalizationOptions | None = None,
    *,
    rebuild: bool = False,
) -> CorrelationNormalizer:
    global _default_normalizer

    with _default_normalizer_lock:
        if _default_normalizer is None or rebuild or options is not None:
            _default_normalizer = CorrelationNormalizer(options=options or NormalizationOptions.from_settings())

        return _default_normalizer


def normalize_correlation_request(
    request: Any,
    options: NormalizationOptions | None = None,
    *,
    normalizer: CorrelationNormalizer | None = None,
) -> NormalizationResult:
    """
    Normalize one bounded synthetic correlation request.
    """
    active_normalizer = normalizer or get_correlation_normalizer(options)
    return active_normalizer.normalize(request)


def normalize_records(
    records: Any,
    category: RecordCategory | str,
    options: NormalizationOptions | None = None,
    *,
    normalizer: CorrelationNormalizer | None = None,
) -> NormalizationResult:
    """
    Convenience helper for normalizing records of a single category.
    """
    cat_enum = _normalize_enum_option(RecordCategory, category, RecordCategory.UNKNOWN)
    
    req_kwargs = {f"{cat_enum.value}s": records}
    request = NormalizationRequest(**req_kwargs)
    
    return normalize_correlation_request(request, options=options, normalizer=normalizer)


def get_normalization_health(*, normalizer: CorrelationNormalizer | None = None) -> dict[str, Any]:
    """
    Return safe normalizer health.
    """
    active_normalizer = normalizer or get_correlation_normalizer()
    opts = active_normalizer.options
    issues: list[NormalizationIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="normalizer_disabled",
            message="Correlation normalizer is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Correlation normalizer requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Correlation normalizer is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(NORMALIZER_CAVEATS),
        "safety_flags": dict(NORMALIZER_SAFETY_FLAGS),
    }


def get_normalization_metadata() -> dict[str, Any]:
    """
    Return safe, serializable normalizer metadata.
    """
    options = NormalizationOptions.from_settings()

    return {
        "package": "muleguard.backend.correlation.normalizers",
        "version": NORMALIZER_VERSION,
        "categories": [cat.value for cat in RecordCategory],
        "statuses": [status.value for status in NormalizationStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "allowed_fields": {
            cat: sorted(list(fields)) for cat, fields in CATEGORY_ALLOWED_FIELDS.items()
        },
        "hard_limits": {
            "max_records": HARD_MAX_RECORDS,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
        },
        "forbidden_normalizer_field_count": len(FORBIDDEN_NORMALIZER_FIELDS),
        "label_leakage_field_count": len(LABEL_LEAKAGE_FIELDS),
        "caveats": list(NORMALIZER_CAVEATS),
        "safety_flags": dict(NORMALIZER_SAFETY_FLAGS),
    }


__all__ = [
    "CorrelationNormalizer",
    "IssueSeverity",
    "NormalizedRecord",
    "NormalizationIssue",
    "NormalizationOptions",
    "NormalizationRequest",
    "NormalizationResult",
    "NormalizationStatus",
    "RecordCategory",
    "get_correlation_normalizer",
    "get_normalization_health",
    "get_normalization_metadata",
    "get_normalization_options",
    "normalize_correlation_request",
    "normalize_records",
]