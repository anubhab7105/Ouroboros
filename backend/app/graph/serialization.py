"""
MULEGUARD backend graph serialization.

This module provides the canonical bounded serialization and deserialization
layer for the synthetic MULEGUARD investigative graph subsystem.

Primary responsibilities:

- serialize bounded synthetic graph structures (nodes, edges, communities,
  cycles) into safe, deterministic, JSON-compatible dictionaries;
- deserialize safe dictionaries back into internal graph models with strict
  validation against limits and leakage policies;
- enforce hard maximums on serialization size (nodes, edges, string lengths,
  metadata depth) to prevent unbounded resource consumption;
- reject or redact leakage-prone fields (raw identifiers, PII, secrets, ground
  truth labels, raw narratives, monetary amounts) during serialization;
- preserve privacy by ensuring all node and edge references are salted, one-way
  pseudonymous hashes;
- provide safe export formats (bounded JSON, highly aggregated summaries)
  suitable for external consumption, reporting, or developer tooling;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module serializes and deserializes graph data only. It does not execute
graph algorithms, train models, deploy models, persist durable artifacts, call
external systems, authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be serialized or exported.
- Serialized graph outputs are investigative leads only. They are not proof of
  wrongdoing, syndicates, cartels, or criminal associations.
- Currency amounts and monetary values are never serialized. Edge weights are
  derived from interaction counts, not monetary values.
- Labels, ground-truth style fields, raw complaint narratives, and raw
  identifiers are strictly forbidden in serialized outputs.
- Node and edge linkage is pseudonymous and salted.
- Graph serialization must never trigger automatic adverse customer action.
- Undefined or unavailable serialization targets are reported honestly rather
  than invented.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external graph databases or model runtimes.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models or graphs.
- This module does not generate synthetic ingestion records.
- This module is not a durable graph store.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, cycle
candidates, community candidates, filtered graphs, serialized graphs,
explanations, validation reports, and case dispositions are investigative leads
or human workflow artefacts only. They are not proof of wrongdoing and must not
trigger automatic adverse customer action.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
import threading
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


logger = logging.getLogger("muleguard.backend.graph.serialization")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

SERIALIZATION_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.graph.serialization.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"

DEFAULT_MAX_NODES: Final[int] = 5_000
HARD_MAX_NODES: Final[int] = 50_000

DEFAULT_MAX_EDGES: Final[int] = 10_000
HARD_MAX_EDGES: Final[int] = 100_000

DEFAULT_MAX_STRING_LENGTH: Final[int] = 256
HARD_MAX_STRING_LENGTH: Final[int] = 1_024

DEFAULT_MAX_METADATA_DEPTH: Final[int] = 4
HARD_MAX_METADATA_DEPTH: Final[int] = 8

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_NODE_HASH_LENGTH: Final[int] = 256
_MAX_EDGE_HASH_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

_FORBIDDEN_SERIALIZATION_FIELDS: Final[frozenset[str]] = frozenset(
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
        "amount",
        "value",
        "currency",
        "balance",
        "transaction_amount",
    }
)

_FORBIDDEN_SERIALIZATION_TOKENS: Final[tuple[str, ...]] = (
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
    "device_id_raw",
    "account_number",
    "ifsc",
    "customer_id",
    "customer_data",
    "real_data",
    "amount",
    "value",
    "currency",
    "balance",
    "transaction_amount",
    "money",
    "fund",
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
    "device_id_raw",
    "dsn",
    "email_address",
    "file_path",
    "filesystem",
    "fraud_label",
    "ground_truth",
    "ifsc",
    "ip_address_raw",
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
    "amount",
    "value",
    "currency",
    "balance",
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

_SERIALIZATION_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic graph serialization only. Do not use with real customer data.",
    "Serialized graph outputs are investigative leads only and are not proof of wrongdoing.",
    "Currency amounts and monetary values are never serialized. Edge weights are structural counts.",
    "Labels, ground-truth fields, raw narratives, and raw identifiers are strictly forbidden in serialized outputs.",
    "Node and edge linkage is pseudonymous and salted.",
    "Graph serialization must not trigger automatic adverse customer action.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_SERIALIZATION_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_monetary_values_serialized": True,
        "no_labels_as_graph_features": True,
        "no_raw_values_in_serialized_outputs": True,
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
        "salted_pseudonymous_node_references": True,
        "salted_pseudonymous_edge_references": True,
        "deterministic_graph_serialization": True,
        "bounded_graph_serialization_required": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class NodeKind(str, Enum):
    """
    Bounded graph node kind.
    """

    ACCOUNT = "account"
    ENTITY = "entity"
    UNKNOWN = "unknown"


class EdgeKind(str, Enum):
    """
    Bounded graph edge kind.
    """

    TRANSACTION = "transaction"
    ENTITY_LINK = "entity_link"
    EXPLICIT = "explicit"
    OTHER = "other"


class SerializationFormat(str, Enum):
    """
    Bounded serialization format.
    """

    JSON = "json"
    SAFE_SUMMARY = "safe_summary"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class SerializationStatus(str, Enum):
    """
    Overall serialization status.
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


def _upper_token(value: Any) -> str:
    return _normalize_token(value).upper()


def _canonical_field_name(key: Any) -> str:
    return _normalize_token(key)


def _is_safe_hash(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and _HASH_RE.match(text))


def _is_forbidden_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_SERIALIZATION_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_SERIALIZATION_TOKENS)


def _is_label_leakage_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _LABEL_LEAKAGE_FIELDS:
        return True

    return any(token in canonical for token in _LABEL_LEAKAGE_TOKENS)


def _is_sensitive_detail_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)
    return bool(canonical) and any(token in canonical for token in _SENSITIVE_DETAIL_TOKENS)


def _safe_detail_value(value: Any, depth: int = 0) -> Any:
    if depth > HARD_MAX_METADATA_DEPTH:
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


def _clip(value: Optional[float], minimum: float, maximum: float, default: float = 0.0) -> float:
    if value is None:
        return default

    if math.isnan(value) or math.isinf(value):
        return default

    return max(minimum, min(maximum, float(value)))


def _round6(value: float) -> float:
    if math.isnan(value) or math.isinf(value):
        return 0.0

    return round(float(value), 6)


def _coerce_float(value: Any, *, allow_bool: bool = False) -> Optional[float]:
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
        return _coerce_float(value.value, allow_bool=allow_bool)

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


def _normalize_enum(enum_cls: type[Enum], value: Any, default: Any) -> Any:
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


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SerializationIssue:
    """
    Safe serialization issue.
    """

    severity: IssueSeverity
    code: str
    message: str
    field: Optional[str] = None
    details: dict[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", _normalize_enum(IssueSeverity, self.severity, IssueSeverity.WARNING))
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
    issues: list[SerializationIssue],
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

        issues[-1] = SerializationIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        SerializationIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[SerializationIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[SerializationIssue]) -> tuple[SerializationIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[SerializationIssue] = []

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
class SerializationOptions:
    """
    Bounded graph serialization policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE

    format: SerializationFormat | str = SerializationFormat.JSON

    max_nodes: int = DEFAULT_MAX_NODES
    max_edges: int = DEFAULT_MAX_EDGES
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH
    max_metadata_depth: int = DEFAULT_MAX_METADATA_DEPTH
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS

    redact_forbidden_fields: bool = True
    redact_label_leakage: bool = True
    redact_monetary_values: bool = True

    include_node_metadata: bool = False
    include_edge_metadata: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_token(self.dataset_mode) or "synthetic")
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(self, "salt", _ensure_salt(self.salt))
        object.__setattr__(self, "namespace", _normalize_token(self.namespace) or _DEFAULT_NAMESPACE)

        object.__setattr__(self, "format", _normalize_enum(SerializationFormat, self.format, SerializationFormat.JSON))

        object.__setattr__(self, "max_nodes", _clamp_int(self.max_nodes, 1, HARD_MAX_NODES, DEFAULT_MAX_NODES))
        object.__setattr__(self, "max_edges", _clamp_int(self.max_edges, 1, HARD_MAX_EDGES, DEFAULT_MAX_EDGES))
        object.__setattr__(self, "max_string_length", _clamp_int(self.max_string_length, 1, HARD_MAX_STRING_LENGTH, DEFAULT_MAX_STRING_LENGTH))
        object.__setattr__(self, "max_metadata_depth", _clamp_int(self.max_metadata_depth, 1, HARD_MAX_METADATA_DEPTH, DEFAULT_MAX_METADATA_DEPTH))
        object.__setattr__(self, "max_issues", _clamp_int(self.max_issues, 1, HARD_MAX_ISSUES, DEFAULT_MAX_ISSUES))
        object.__setattr__(self, "max_summary_items", _clamp_int(self.max_summary_items, 1, HARD_MAX_SUMMARY_ITEMS, DEFAULT_MAX_SUMMARY_ITEMS))

        object.__setattr__(self, "redact_forbidden_fields", _as_bool(self.redact_forbidden_fields, True))
        object.__setattr__(self, "redact_label_leakage", _as_bool(self.redact_label_leakage, True))
        object.__setattr__(self, "redact_monetary_values", _as_bool(self.redact_monetary_values, True))

        object.__setattr__(self, "include_node_metadata", _as_bool(self.include_node_metadata, False))
        object.__setattr__(self, "include_edge_metadata", _as_bool(self.include_edge_metadata, False))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "SerializationOptions":
        if settings is None:
            try:
                from app.core.config import get_settings
                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "GRAPH_SERIALIZATION_SALT", None)
            or _setting(settings, "GRAPH_FILTER_SALT", None)
            or _setting(settings, "GRAPH_COMMUNITY_SALT", None)
            or _setting(settings, "GRAPH_CYCLE_SALT", None)
            or _setting(settings, "RULES_THRESHOLD_SALT", None)
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
        production_values = {value.lower() for value in _csv(_setting(settings, "BACKEND_PRODUCTION_LIKE_ENVS", "production,staging,prod,stage"))}

        if not production_values:
            production_values = {"production", "staging", "prod", "stage"}

        return cls(
            enabled=_as_bool(_setting(settings, "GRAPH_SERIALIZATION_ENABLED", True), True),
            synthetic_required=_as_bool(_setting(settings, "GRAPH_SERIALIZATION_REQUIRE_SYNTHETIC", True), True),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(_setting(settings, "GRAPH_SERIALIZATION_ALLOW_IN_PRODUCTION", False), False),
            salt=salt,
            namespace=str(_setting(settings, "GRAPH_SERIALIZATION_NAMESPACE", _DEFAULT_NAMESPACE)),
            format=str(_setting(settings, "GRAPH_SERIALIZATION_FORMAT", SerializationFormat.JSON.value)),
            max_nodes=_as_int(_setting(settings, "GRAPH_SERIALIZATION_MAX_NODES", DEFAULT_MAX_NODES), DEFAULT_MAX_NODES),
            max_edges=_as_int(_setting(settings, "GRAPH_SERIALIZATION_MAX_EDGES", DEFAULT_MAX_EDGES), DEFAULT_MAX_EDGES),
            max_string_length=_as_int(_setting(settings, "GRAPH_SERIALIZATION_MAX_STRING_LENGTH", DEFAULT_MAX_STRING_LENGTH), DEFAULT_MAX_STRING_LENGTH),
            max_metadata_depth=_as_int(_setting(settings, "GRAPH_SERIALIZATION_MAX_METADATA_DEPTH", DEFAULT_MAX_METADATA_DEPTH), DEFAULT_MAX_METADATA_DEPTH),
            max_issues=_as_int(_setting(settings, "GRAPH_SERIALIZATION_MAX_ISSUES", DEFAULT_MAX_ISSUES), DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(_setting(settings, "GRAPH_SERIALIZATION_MAX_SUMMARY_ITEMS", DEFAULT_MAX_SUMMARY_ITEMS), DEFAULT_MAX_SUMMARY_ITEMS),
            redact_forbidden_fields=_as_bool(_setting(settings, "GRAPH_SERIALIZATION_REDACT_FORBIDDEN", True), True),
            redact_label_leakage=_as_bool(_setting(settings, "GRAPH_SERIALIZATION_REDACT_LABELS", True), True),
            redact_monetary_values=_as_bool(_setting(settings, "GRAPH_SERIALIZATION_REDACT_MONETARY", True), True),
            include_node_metadata=_as_bool(_setting(settings, "GRAPH_SERIALIZATION_INCLUDE_NODE_METADATA", False), False),
            include_edge_metadata=_as_bool(_setting(settings, "GRAPH_SERIALIZATION_INCLUDE_EDGE_METADATA", False), False),
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
            "format": _enum_value(self.format, SerializationFormat.JSON.value),
            "limits": {
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
                "max_string_length": self.max_string_length,
                "max_metadata_depth": self.max_metadata_depth,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
            },
            "redaction": {
                "redact_forbidden_fields": self.redact_forbidden_fields,
                "redact_label_leakage": self.redact_label_leakage,
                "redact_monetary_values": self.redact_monetary_values,
            },
            "inclusion": {
                "include_node_metadata": self.include_node_metadata,
                "include_edge_metadata": self.include_edge_metadata,
            },
        }


# -----------------------------------------------------------------------------
# Internal Graph Models for Serialization
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class SerializableNode:
    """
    Bounded serializable node.
    """

    node_hash: str
    kind: NodeKind | str = NodeKind.UNKNOWN
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    degree: int = 0
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_hash", _clean_text(self.node_hash, _MAX_NODE_HASH_LENGTH).lower())
        object.__setattr__(self, "kind", _normalize_enum(NodeKind, self.kind, NodeKind.UNKNOWN))
        object.__setattr__(self, "first_seen", _clean_text(self.first_seen, 64) or None)
        object.__setattr__(self, "last_seen", _clean_text(self.last_seen, 64) or None)
        object.__setattr__(self, "degree", max(0, _as_int(self.degree, 0)))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))


@dataclass(slots=True)
class SerializableEdge:
    """
    Bounded serializable edge.
    """

    edge_hash: str
    source_hash: str
    target_hash: str
    kind: EdgeKind | str = EdgeKind.OTHER
    weight: float = 1.0
    timestamp: Optional[str] = None
    verification_state: str = "UNVERIFIED"
    match_method: str = "EXACT"
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_hash", _clean_text(self.edge_hash, _MAX_EDGE_HASH_LENGTH).lower())
        object.__setattr__(self, "source_hash", _clean_text(self.source_hash, _MAX_NODE_HASH_LENGTH).lower())
        object.__setattr__(self, "target_hash", _clean_text(self.target_hash, _MAX_NODE_HASH_LENGTH).lower())
        object.__setattr__(self, "kind", _normalize_enum(EdgeKind, self.kind, EdgeKind.OTHER))
        object.__setattr__(self, "weight", _round6(max(0.0, _coerce_float(self.weight, allow_bool=True) or 1.0)))
        object.__setattr__(self, "timestamp", _clean_text(self.timestamp, 64) or None)
        object.__setattr__(self, "verification_state", _upper_token(self.verification_state) or "UNVERIFIED")
        object.__setattr__(self, "match_method", _upper_token(self.match_method) or "EXACT")
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))


@dataclass(slots=True)
class SerializableGraph:
    """
    Bounded serializable graph.
    """

    nodes: tuple[SerializableNode, ...] = ()
    edges: tuple[SerializableEdge, ...] = ()
    fingerprint: str = ""
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "nodes", tuple(self.nodes or ()))
        object.__setattr__(self, "edges", tuple(self.edges or ()))
        object.__setattr__(self, "fingerprint", _clean_text(self.fingerprint, 128))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))


# -----------------------------------------------------------------------------
# Serialization Result
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SerializationResult:
    """
    Safe bounded serialization result.
    """

    ok: bool = True
    status: SerializationStatus | str = SerializationStatus.PASSED
    format: SerializationFormat | str = SerializationFormat.JSON
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    data: Any = None
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[SerializationIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(self, "status", _normalize_enum(SerializationStatus, self.status, SerializationStatus.PASSED))
        object.__setattr__(self, "format", _normalize_enum(SerializationFormat, self.format, SerializationFormat.JSON))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "counts", MappingProxyType({str(key): max(0, _as_int(value, 0)) for key, value in (self.counts or {}).items()}))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": SERIALIZATION_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, SerializationStatus.PASSED.value),
                        "format": _enum_value(self.format, SerializationFormat.JSON.value),
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": _enum_value(self.status, SerializationStatus.PASSED.value),
            "format": _enum_value(self.format, SerializationFormat.JSON.value),
            "generated_at": self.generated_at.isoformat(),
            "data": self.data,
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_SERIALIZATION_CAVEATS),
            "safety_flags": dict(_SERIALIZATION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Core Serialization Logic
# -----------------------------------------------------------------------------


def _serialize_node(
    node: Any,
    options: SerializationOptions,
    issues: list[SerializationIssue],
) -> Optional[SerializableNode]:
    """
    Serialize one internal node into a bounded SerializableNode.
    """
    if isinstance(node, SerializableNode):
        return node

    if isinstance(node, Mapping):
        node_hash = _clean_text(node.get("node_hash") or node.get("id") or node.get("subject_ref_hash"), _MAX_NODE_HASH_LENGTH).lower()
        kind = _normalize_enum(NodeKind, node.get("kind"), NodeKind.UNKNOWN)
        first_seen = _parse_datetime(node.get("first_seen"))
        last_seen = _parse_datetime(node.get("last_seen"))
        degree = _as_int(node.get("degree"), 0)
        metadata = node.get("metadata", {})
    else:
        node_hash = _clean_text(getattr(node, "node_hash", None) or getattr(node, "id", None), _MAX_NODE_HASH_LENGTH).lower()
        kind = _normalize_enum(NodeKind, getattr(node, "kind", NodeKind.UNKNOWN), NodeKind.UNKNOWN)
        first_seen = getattr(node, "first_seen", None)
        last_seen = getattr(node, "last_seen", None)
        degree = _as_int(getattr(node, "degree", 0), 0)
        metadata = getattr(node, "metadata", {})

    if not node_hash:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="missing_node_hash",
            message="Node is missing a valid pseudonymous hash.",
        )
        return None

    if not _is_safe_hash(node_hash):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_node_hash_format",
            message="Node hash is not a valid pseudonymous hash format.",
            field="node_hash",
        )
        return None

    safe_metadata = {}
    if options.include_node_metadata and isinstance(metadata, Mapping):
        safe_metadata = _as_mapping(metadata)

    return SerializableNode(
        node_hash=node_hash,
        kind=kind,
        first_seen=first_seen.isoformat() if first_seen else None,
        last_seen=last_seen.isoformat() if last_seen else None,
        degree=degree,
        metadata=safe_metadata,
    )


def _serialize_edge(
    edge: Any,
    options: SerializationOptions,
    issues: list[SerializationIssue],
) -> Optional[SerializableEdge]:
    """
    Serialize one internal edge into a bounded SerializableEdge.
    """
    if isinstance(edge, SerializableEdge):
        return edge

    if isinstance(edge, Mapping):
        edge_hash = _clean_text(edge.get("edge_hash") or edge.get("id"), _MAX_EDGE_HASH_LENGTH).lower()
        source_hash = _clean_text(edge.get("source_hash") or edge.get("source"), _MAX_NODE_HASH_LENGTH).lower()
        target_hash = _clean_text(edge.get("target_hash") or edge.get("target"), _MAX_NODE_HASH_LENGTH).lower()
        kind = _normalize_enum(EdgeKind, edge.get("kind"), EdgeKind.OTHER)
        weight = _coerce_float(edge.get("weight"), allow_bool=True) or 1.0
        timestamp = _parse_datetime(edge.get("timestamp") or edge.get("occurred_at"))
        verification_state = _upper_token(edge.get("verification_state") or "UNVERIFIED")
        match_method = _upper_token(edge.get("match_method") or "EXACT")
        metadata = edge.get("metadata", {})
    else:
        edge_hash = _clean_text(getattr(edge, "edge_hash", None) or getattr(edge, "id", None), _MAX_EDGE_HASH_LENGTH).lower()
        source_hash = _clean_text(getattr(edge, "source_hash", None) or getattr(edge, "source", None), _MAX_NODE_HASH_LENGTH).lower()
        target_hash = _clean_text(getattr(edge, "target_hash", None) or getattr(edge, "target", None), _MAX_NODE_HASH_LENGTH).lower()
        kind = _normalize_enum(EdgeKind, getattr(edge, "kind", EdgeKind.OTHER), EdgeKind.OTHER)
        weight = _coerce_float(getattr(edge, "weight", 1.0), allow_bool=True) or 1.0
        timestamp = getattr(edge, "timestamp", None)
        verification_state = _upper_token(getattr(edge, "verification_state", "UNVERIFIED"))
        match_method = _upper_token(getattr(edge, "match_method", "EXACT"))
        metadata = getattr(edge, "metadata", {})

    if not edge_hash:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="missing_edge_hash",
            message="Edge is missing a valid pseudonymous hash.",
        )
        return None

    if not _is_safe_hash(edge_hash):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_edge_hash_format",
            message="Edge hash is not a valid pseudonymous hash format.",
            field="edge_hash",
        )
        return None

    if not source_hash or not target_hash:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="missing_edge_endpoints",
            message="Edge is missing source or target node hashes.",
        )
        return None

    if not _is_safe_hash(source_hash) or not _is_safe_hash(target_hash):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_edge_endpoint_format",
            message="Edge source or target is not a valid pseudonymous hash format.",
        )
        return None

    safe_metadata = {}
    if options.include_edge_metadata and isinstance(metadata, Mapping):
        safe_metadata = _as_mapping(metadata)

    return SerializableEdge(
        edge_hash=edge_hash,
        source_hash=source_hash,
        target_hash=target_hash,
        kind=kind,
        weight=weight,
        timestamp=timestamp.isoformat() if timestamp else None,
        verification_state=verification_state,
        match_method=match_method,
        metadata=safe_metadata,
    )


def _serialize_graph(
    graph: Any,
    options: SerializationOptions,
    issues: list[SerializationIssue],
) -> SerializableGraph:
    """
    Serialize an internal graph structure into a bounded SerializableGraph.
    """
    nodes_in = []
    edges_in = []

    if isinstance(graph, Mapping):
        nodes_in = _as_sequence(graph.get("nodes", []))
        edges_in = _as_sequence(graph.get("edges", []))
        fingerprint = _clean_text(graph.get("fingerprint"), 128)
        metadata = graph.get("metadata", {})
    else:
        nodes_in = _as_sequence(getattr(graph, "nodes", []))
        edges_in = _as_sequence(getattr(graph, "edges", []))
        fingerprint = _clean_text(getattr(graph, "fingerprint", ""), 128)
        metadata = getattr(graph, "metadata", {})

    serialized_nodes: list[SerializableNode] = []
    for node in nodes_in[: options.max_nodes]:
        s_node = _serialize_node(node, options, issues)
        if s_node:
            serialized_nodes.append(s_node)

    if len(nodes_in) > options.max_nodes:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="node_limit_truncation",
            message="Node count exceeded configured limit and was truncated.",
            details={"submitted": len(nodes_in), "max_nodes": options.max_nodes},
        )

    serialized_edges: list[SerializableEdge] = []
    for edge in edges_in[: options.max_edges]:
        s_edge = _serialize_edge(edge, options, issues)
        if s_edge:
            serialized_edges.append(s_edge)

    if len(edges_in) > options.max_edges:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="edge_limit_truncation",
            message="Edge count exceeded configured limit and was truncated.",
            details={"submitted": len(edges_in), "max_edges": options.max_edges},
        )

    return SerializableGraph(
        nodes=tuple(serialized_nodes),
        edges=tuple(serialized_edges),
        fingerprint=fingerprint,
        metadata=_as_mapping(metadata),
    )


def _graph_to_dict(graph: SerializableGraph) -> dict[str, Any]:
    """
    Convert a SerializableGraph into a safe JSON-compatible dictionary.
    """
    return {
        "version": SERIALIZATION_VERSION,
        "fingerprint": graph.fingerprint,
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "nodes": [
            {
                "node_hash": node.node_hash,
                "kind": _enum_value(node.kind, NodeKind.UNKNOWN.value),
                "first_seen": node.first_seen,
                "last_seen": node.last_seen,
                "degree": node.degree,
                "metadata": _safe_detail_value(node.metadata),
            }
            for node in graph.nodes
        ],
        "edges": [
            {
                "edge_hash": edge.edge_hash,
                "source_hash": edge.source_hash,
                "target_hash": edge.target_hash,
                "kind": _enum_value(edge.kind, EdgeKind.OTHER.value),
                "weight": float(edge.weight),
                "timestamp": edge.timestamp,
                "verification_state": edge.verification_state,
                "match_method": edge.match_method,
                "metadata": _safe_detail_value(edge.metadata),
            }
            for edge in graph.edges
        ],
        "metadata": _safe_detail_value(graph.metadata),
    }


def _generate_safe_summary(graph: SerializableGraph, options: SerializationOptions) -> dict[str, Any]:
    """
    Generate a highly aggregated, safe summary of the graph.
    """
    node_kinds = Counter(_enum_value(node.kind, NodeKind.UNKNOWN.value) for node in graph.nodes)
    edge_kinds = Counter(_enum_value(edge.kind, EdgeKind.OTHER.value) for edge in graph.edges)
    
    total_weight = sum(float(edge.weight) for edge in graph.edges)

    return {
        "version": SERIALIZATION_VERSION,
        "format": SerializationFormat.SAFE_SUMMARY.value,
        "fingerprint": graph.fingerprint,
        "counts": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "total_edge_weight": _round6(total_weight),
        },
        "node_kinds": dict(node_kinds),
        "edge_kinds": dict(edge_kinds),
        "metadata": _safe_detail_value(graph.metadata),
        "raw_values_retained": False,
        "subject_label_pairs_retained": False,
        "monetary_values_retained": False,
    }


# -----------------------------------------------------------------------------
# Core Deserialization Logic
# -----------------------------------------------------------------------------


def _deserialize_node(
    node_dict: Mapping[str, Any],
    options: SerializationOptions,
    issues: list[SerializationIssue],
) -> Optional[SerializableNode]:
    """
    Deserialize a safe node dictionary back into a SerializableNode.
    """
    if not isinstance(node_dict, Mapping):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_node_format",
            message="Node is not a valid mapping.",
        )
        return None

    node_hash = _clean_text(node_dict.get("node_hash"), _MAX_NODE_HASH_LENGTH).lower()
    kind = _normalize_enum(NodeKind, node_dict.get("kind"), NodeKind.UNKNOWN)
    first_seen = _clean_text(node_dict.get("first_seen"), 64) or None
    last_seen = _clean_text(node_dict.get("last_seen"), 64) or None
    degree = _as_int(node_dict.get("degree"), 0)
    metadata = node_dict.get("metadata", {})

    if not node_hash or not _is_safe_hash(node_hash):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_node_hash_on_deserialize",
            message="Node hash is missing or invalid during deserialization.",
            field="node_hash",
        )
        return None

    return SerializableNode(
        node_hash=node_hash,
        kind=kind,
        first_seen=first_seen,
        last_seen=last_seen,
        degree=degree,
        metadata=_as_mapping(metadata),
    )


def _deserialize_edge(
    edge_dict: Mapping[str, Any],
    options: SerializationOptions,
    issues: list[SerializationIssue],
) -> Optional[SerializableEdge]:
    """
    Deserialize a safe edge dictionary back into a SerializableEdge.
    """
    if not isinstance(edge_dict, Mapping):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_edge_format",
            message="Edge is not a valid mapping.",
        )
        return None

    edge_hash = _clean_text(edge_dict.get("edge_hash"), _MAX_EDGE_HASH_LENGTH).lower()
    source_hash = _clean_text(edge_dict.get("source_hash"), _MAX_NODE_HASH_LENGTH).lower()
    target_hash = _clean_text(edge_dict.get("target_hash"), _MAX_NODE_HASH_LENGTH).lower()
    kind = _normalize_enum(EdgeKind, edge_dict.get("kind"), EdgeKind.OTHER)
    weight = _coerce_float(edge_dict.get("weight"), allow_bool=True) or 1.0
    timestamp = _clean_text(edge_dict.get("timestamp"), 64) or None
    verification_state = _upper_token(edge_dict.get("verification_state") or "UNVERIFIED")
    match_method = _upper_token(edge_dict.get("match_method") or "EXACT")
    metadata = edge_dict.get("metadata", {})

    if not edge_hash or not _is_safe_hash(edge_hash):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_edge_hash_on_deserialize",
            message="Edge hash is missing or invalid during deserialization.",
            field="edge_hash",
        )
        return None

    if not source_hash or not target_hash or not _is_safe_hash(source_hash) or not _is_safe_hash(target_hash):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_edge_endpoints_on_deserialize",
            message="Edge source or target hashes are missing or invalid during deserialization.",
        )
        return None

    return SerializableEdge(
        edge_hash=edge_hash,
        source_hash=source_hash,
        target_hash=target_hash,
        kind=kind,
        weight=weight,
        timestamp=timestamp,
        verification_state=verification_state,
        match_method=match_method,
        metadata=_as_mapping(metadata),
    )


def _deserialize_graph(
    data: Any,
    options: SerializationOptions,
    issues: list[SerializationIssue],
) -> SerializableGraph:
    """
    Deserialize a safe dictionary back into a SerializableGraph.
    """
    if not isinstance(data, Mapping):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="invalid_graph_format",
            message="Graph data is not a valid mapping.",
        )
        return SerializableGraph()

    nodes_in = _as_sequence(data.get("nodes", []))
    edges_in = _as_sequence(data.get("edges", []))
    fingerprint = _clean_text(data.get("fingerprint"), 128)
    metadata = data.get("metadata", {})

    serialized_nodes: list[SerializableNode] = []
    for node in nodes_in[: options.max_nodes]:
        s_node = _deserialize_node(node, options, issues)
        if s_node:
            serialized_nodes.append(s_node)

    serialized_edges: list[SerializableEdge] = []
    for edge in edges_in[: options.max_edges]:
        s_edge = _deserialize_edge(edge, options, issues)
        if s_edge:
            serialized_edges.append(s_edge)

    return SerializableGraph(
        nodes=tuple(serialized_nodes),
        edges=tuple(serialized_edges),
        fingerprint=fingerprint,
        metadata=_as_mapping(metadata),
    )


# -----------------------------------------------------------------------------
# Serialization Engine
# -----------------------------------------------------------------------------


class SerializationEngine:
    """
    Bounded deterministic synthetic graph serialization engine.
    """

    def __init__(self, options: SerializationOptions | None = None) -> None:
        self.options = options or SerializationOptions.from_settings()
        self._lock = threading.RLock()

    def serialize(self, graph: Any, *, format: SerializationFormat | str | None = None) -> SerializationResult:
        """
        Serialize one bounded synthetic graph.
        """
        opts = self.options
        issues: list[SerializationIssue] = []
        generated_at = _now_utc()

        fmt = _normalize_enum(SerializationFormat, format or opts.format, SerializationFormat.JSON)

        def make_result(
            ok: bool,
            status: SerializationStatus,
            data: Any = None,
            counts: Optional[Mapping[str, int]] = None,
        ) -> SerializationResult:
            resolved_counts: dict[str, int] = {
                "nodes": 0,
                "edges": 0,
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update({str(key): max(0, _as_int(value, 0)) for key, value in counts.items()})

            resolved_counts["issues"] = len(issues)

            metadata = {
                "serialization_version": SERIALIZATION_VERSION,
                "format": _enum_value(fmt, SerializationFormat.JSON.value),
                "options": opts.safe_summary(),
                "generated_at": generated_at.isoformat(),
                "raw_values_retained": False,
                "subject_label_pairs_retained": False,
                "monetary_values_retained": False,
                "caveats": list(_SERIALIZATION_CAVEATS),
                "safety_flags": dict(_SERIALIZATION_SAFETY_FLAGS),
            }

            return SerializationResult(
                ok=ok,
                status=status,
                format=fmt,
                generated_at=generated_at,
                data=data,
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
                code="serialization_engine_disabled",
                message="Serialization engine is disabled.",
            )
            return make_result(False, SerializationStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Serialization engine requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, SerializationStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Serialization engine is blocked in production-like environments.",
            )
            return make_result(False, SerializationStatus.BLOCKED)

        if _contains_prohibited_action(graph):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_serialization_action_metadata",
                message="Graph metadata contains prohibited adverse-action language.",
            )
            return make_result(False, SerializationStatus.BLOCKED)

        serialized_graph = _serialize_graph(graph, opts, issues)

        if not serialized_graph.nodes and not serialized_graph.edges:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="empty_serialized_graph",
                message="Serialized graph contains no valid nodes or edges.",
            )

        if fmt == SerializationFormat.SAFE_SUMMARY:
            data = _generate_safe_summary(serialized_graph, opts)
        else:
            data = _graph_to_dict(serialized_graph)

        counts = {
            "nodes": len(serialized_graph.nodes),
            "edges": len(serialized_graph.edges),
        }

        status = SerializationStatus.PASSED

        if _has_error(issues):
            status = SerializationStatus.FAILED
        elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
            status = SerializationStatus.DEGRADED

        return make_result(
            ok=status in {SerializationStatus.PASSED, SerializationStatus.DEGRADED},
            status=status,
            data=data,
            counts=counts,
        )

    def deserialize(self, data: Any) -> SerializationResult:
        """
        Deserialize one bounded synthetic graph.
        """
        opts = self.options
        issues: list[SerializationIssue] = []
        generated_at = _now_utc()

        def make_result(
            ok: bool,
            status: SerializationStatus,
            graph: Optional[SerializableGraph] = None,
            counts: Optional[Mapping[str, int]] = None,
        ) -> SerializationResult:
            resolved_counts: dict[str, int] = {
                "nodes": 0,
                "edges": 0,
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update({str(key): max(0, _as_int(value, 0)) for key, value in counts.items()})

            resolved_counts["issues"] = len(issues)

            metadata = {
                "serialization_version": SERIALIZATION_VERSION,
                "format": SerializationFormat.JSON.value,
                "options": opts.safe_summary(),
                "generated_at": generated_at.isoformat(),
                "caveats": list(_SERIALIZATION_CAVEATS),
                "safety_flags": dict(_SERIALIZATION_SAFETY_FLAGS),
            }

            return SerializationResult(
                ok=ok,
                status=status,
                format=SerializationFormat.JSON,
                generated_at=generated_at,
                data=graph,
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
                code="serialization_engine_disabled",
                message="Serialization engine is disabled.",
            )
            return make_result(False, SerializationStatus.BLOCKED)

        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception as exc:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="invalid_json_payload",
                    message="Deserialization payload is not valid JSON.",
                    details={"exception_type": type(exc).__name__},
                )
                return make_result(False, SerializationStatus.FAILED)

        if not isinstance(data, Mapping):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="invalid_deserialization_format",
                message="Deserialization payload must be a JSON object.",
            )
            return make_result(False, SerializationStatus.FAILED)

        if _contains_prohibited_action(data):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_deserialization_action_metadata",
                message="Deserialization payload contains prohibited adverse-action language.",
            )
            return make_result(False, SerializationStatus.BLOCKED)

        serialized_graph = _deserialize_graph(data, opts, issues)

        counts = {
            "nodes": len(serialized_graph.nodes),
            "edges": len(serialized_graph.edges),
        }

        status = SerializationStatus.PASSED

        if _has_error(issues):
            status = SerializationStatus.FAILED
        elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
            status = SerializationStatus.DEGRADED

        return make_result(
            ok=status in {SerializationStatus.PASSED, SerializationStatus.DEGRADED},
            status=status,
            graph=serialized_graph,
            counts=counts,
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe engine summary.
        """
        return {
            "options": self.options.safe_summary(),
            "caveats": list(_SERIALIZATION_CAVEATS),
            "safety_flags": dict(_SERIALIZATION_SAFETY_FLAGS),
        }


_default_engine: Optional[SerializationEngine] = None
_default_engine_lock = threading.Lock()


def get_serialization_options(settings: Any | None = None) -> SerializationOptions:
    """
    Return serialization options from settings.
    """
    return SerializationOptions.from_settings(settings)


def get_serialization_engine(
    options: SerializationOptions | None = None,
    *,
    rebuild: bool = False,
) -> SerializationEngine:
    """
    Return a process-wide serialization engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = SerializationEngine(options=options or SerializationOptions.from_settings())

        return _default_engine


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def serialize_graph(
    graph: Any,
    options: SerializationOptions | None = None,
    *,
    engine: SerializationEngine | None = None,
    format: SerializationFormat | str | None = None,
) -> SerializationResult:
    """
    Serialize one bounded synthetic graph.
    """
    active_engine = engine or get_serialization_engine(options)
    return active_engine.serialize(graph, format=format)


def deserialize_graph(
    data: Any,
    options: SerializationOptions | None = None,
    *,
    engine: SerializationEngine | None = None,
) -> SerializationResult:
    """
    Deserialize one bounded synthetic graph.
    """
    active_engine = engine or get_serialization_engine(options)
    return active_engine.deserialize(data)


def export_graph_summary(
    graph: Any,
    options: SerializationOptions | None = None,
    *,
    engine: SerializationEngine | None = None,
) -> SerializationResult:
    """
    Export a highly aggregated, safe summary of a bounded synthetic graph.
    """
    active_engine = engine or get_serialization_engine(options)
    return active_engine.serialize(graph, format=SerializationFormat.SAFE_SUMMARY)


def get_serialization_health(*, engine: SerializationEngine | None = None) -> dict[str, Any]:
    """
    Return safe serialization-engine health.
    """
    active_engine = engine or get_serialization_engine()
    opts = active_engine.options
    issues: list[SerializationIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="serialization_engine_disabled",
            message="Serialization engine is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Serialization engine requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Serialization engine is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "format": _enum_value(opts.format, SerializationFormat.JSON.value),
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(_SERIALIZATION_CAVEATS),
        "safety_flags": dict(_SERIALIZATION_SAFETY_FLAGS),
    }


def get_serialization_metadata(*, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
    """
    Return safe, serializable serialization-engine metadata.
    """
    options = SerializationOptions.from_settings()

    return {
        "package": "muleguard.backend.graph.serialization",
        "version": SERIALIZATION_VERSION,
        "node_kinds": [kind.value for kind in NodeKind],
        "edge_kinds": [kind.value for kind in EdgeKind],
        "formats": [fmt.value for fmt in SerializationFormat],
        "statuses": [status.value for status in SerializationStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "hard_limits": {
            "max_nodes": HARD_MAX_NODES,
            "max_edges": HARD_MAX_EDGES,
            "max_string_length": HARD_MAX_STRING_LENGTH,
            "max_metadata_depth": HARD_MAX_METADATA_DEPTH,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
        },
        "forbidden_serialization_field_count": len(_FORBIDDEN_SERIALIZATION_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(_PROHIBITED_ACTION_TOKENS),
        "caveats": list(_SERIALIZATION_CAVEATS),
        "safety_flags": dict(_SERIALIZATION_SAFETY_FLAGS),
    }


__all__ = [
    "EdgeKind",
    "IssueSeverity",
    "NodeKind",
    "SerializableEdge",
    "SerializableGraph",
    "SerializableNode",
    "SerializationEngine",
    "SerializationFormat",
    "SerializationIssue",
    "SerializationOptions",
    "SerializationResult",
    "SerializationStatus",
    "deserialize_graph",
    "export_graph_summary",
    "get_serialization_engine",
    "get_serialization_health",
    "get_serialization_metadata",
    "get_serialization_options",
    "serialize_graph",
]