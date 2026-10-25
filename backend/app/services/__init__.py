"""
MULEGUARD backend services package.

This package provides the canonical bounded service registry, health, and
orchestration layer for the synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- register, discover, summarize, and health-check bounded backend services in a
  deterministic, process-local registry;
- provide a safe service execution orchestrator for local prototype workflows,
  tests, developer tooling, and offline evaluation harnesses;
- enforce strict product-safety constraints, including synthetic-first operation
  and absolute prohibition of automatic adverse customer action;
- preserve privacy by excluding raw feature values, raw identifiers, raw
  narratives, subject-label pairs, secrets, tokens, passwords, database URLs,
  filesystem paths, model artifact paths, and executable/handler references from
  public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited service fields;
- report unavailable services, unavailable health checks, and unavailable
  handlers honestly rather than inventing results;
- remain import-safe, dependency-light, and resilient when optional project
  modules or configuration settings are unavailable.

This module orchestrates investigative service workflows only. It does not
train models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for service orchestration.
- Service outputs are investigative leads or human workflow artefacts only.
  They are not proof of wrongdoing, syndicates, cartels, or criminal
  associations.
- Shared entities, devices, IPs, phones, emails, UPI handles, or addresses are
  association patterns only. They are not proof of common control.
- Labels may not be used as service features or service policy criteria.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected.
- Raw complaint narratives are forbidden inputs.
- Raw identifiers are forbidden outputs. Service linkage is pseudonymous where
  required by downstream components.
- Service operations must never trigger automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable services are reported honestly as unavailable rather
  than invented.
- The bundled service registry is process-local, non-durable, and bounded for
  local prototype use only.
- This package does not claim production readiness.
- This package does not claim regulatory compliance.

Explicit non-goals:

- This package does not access databases.
- This package does not call external services, model runtimes, graph databases,
  queues, caches, or network APIs.
- This package does not deploy, promote, retire, upload, replace, or serve
  production models or services.
- This package does not generate synthetic ingestion records.
- This package does not replace feature schema validation.
- This package does not replace ingestion validation.
- This package is not a durable service mesh.
- This package is not an authorization engine.
- This package is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, cycle
candidates, community candidates, filtered graphs, serialized graphs,
correlation candidates, confidence records, service results, explanations,
validation reports, and case dispositions are investigative leads or human
workflow artefacts only. They are not proof of wrongdoing and must not trigger
automatic adverse customer action.
"""

from __future__ import annotations

import hashlib
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
from typing import Any, Callable, Final, Optional

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


logger = logging.getLogger("muleguard.backend.services")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

SERVICES_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

DEFAULT_MAX_SERVICES: Final[int] = 256
HARD_MAX_SERVICES: Final[int] = 10_000

DEFAULT_MAX_PAYLOAD_DEPTH: Final[int] = 4
HARD_MAX_PAYLOAD_DEPTH: Final[int] = 8

DEFAULT_MAX_PAYLOAD_ITEMS: Final[int] = 100
HARD_MAX_PAYLOAD_ITEMS: Final[int] = 1_000

DEFAULT_MAX_TEXT_LENGTH: Final[int] = 512
HARD_MAX_TEXT_LENGTH: Final[int] = 4_096

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

DEFAULT_MAX_TIME_MS: Final[int] = 30_000
HARD_MAX_TIME_MS: Final[int] = 300_000

DEFAULT_MAX_RESULT_ITEMS: Final[int] = 100
HARD_MAX_RESULT_ITEMS: Final[int] = 1_000

MAX_REASON_TEXT_LENGTH: Final[int] = 300

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")

_FORBIDDEN_SERVICE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "apikey",
        "artifact_path",
        "auth_header",
        "authorization",
        "bearer",
        "callable",
        "card_number",
        "class",
        "command",
        "config",
        "connection_string",
        "cookie",
        "credential",
        "credentials",
        "cvv",
        "database_url",
        "directory",
        "dsn",
        "email_address",
        "endpoint",
        "environment",
        "eval",
        "exec",
        "file_path",
        "filename",
        "filesystem_path",
        "fraud_label",
        "fraud_ring_id",
        "function",
        "ground_truth",
        "ground_truth_label",
        "handler",
        "health_handler",
        "host",
        "identifier_raw",
        "ifsc",
        "import",
        "ip_address",
        "is_fraud",
        "marshal",
        "model_artifact_path",
        "model_path",
        "module",
        "narrative",
        "narrative_normalized",
        "narrative_raw",
        "otp",
        "pan",
        "pass",
        "passwd",
        "password",
        "password_hash",
        "path",
        "phone_number",
        "pickle",
        "pin",
        "port",
        "private_key",
        "raw_identifier",
        "raw_payload",
        "refresh_token",
        "ring_id",
        "scenario_id",
        "script",
        "secret",
        "secret_key",
        "session",
        "settings",
        "shell",
        "socket",
        "source_payload_hash",
        "subprocess",
        "token",
        "truth_label",
        "upi_id",
        "uri",
        "url",
    }
)

_FORBIDDEN_SERVICE_TOKENS: Final[tuple[str, ...]] = (
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
    "marshal",
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
    "file_path",
    "filesystem",
    "directory",
    "filename",
    "url",
    "uri",
    "endpoint",
    "host",
    "port",
    "handler",
    "callable",
    "function",
    "class",
    "module",
    "import",
    "eval",
    "exec",
    "compile",
    "subprocess",
    "shell",
    "command",
    "script",
    "socket",
    "environment",
    "config",
    "settings",
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
    "handler",
    "health_handler",
    "callable",
    "function",
    "class",
    "module",
    "import",
    "eval",
    "exec",
    "compile",
    "subprocess",
    "shell",
    "command",
    "script",
    "socket",
    "environment",
    "config",
    "settings",
    "url",
    "uri",
    "endpoint",
    "host",
    "port",
    "path",
    "filename",
    "directory",
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

_SERVICE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic backend service orchestration only. Do not use with real customer data.",
    "Service results are investigative leads or human workflow artefacts only and are not proof of wrongdoing.",
    "Service outputs must not trigger automatic adverse customer action.",
    "Labels must never be used as service features or policy criteria.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives, raw identifiers, secrets, tokens, passwords, database URLs, filesystem paths, and model artifact paths are forbidden.",
    "Unavailable services, handlers, and health checks are reported honestly rather than invented.",
    "The bundled service registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_SERVICE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
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
        "no_filesystem_paths_accepted": True,
        "no_model_artifact_paths_accepted": True,
        "no_executable_handlers_in_public_summaries": True,
        "deterministic_service_registry": True,
        "bounded_service_orchestration_required": True,
        "scores_are_investigative_priority_only": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)

_CRITICAL_TRUE_SAFETY_FLAGS: Final[tuple[str, ...]] = (
    "synthetic_only_by_default",
    "no_real_customer_data_by_default",
    "no_automatic_adverse_customer_action",
    "human_review_required_for_consequential_action",
    "not_production_ready",
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class ServiceKind(str, Enum):
    """
    Bounded backend service kind.
    """

    GENERAL = "general"
    INGESTION = "ingestion"
    FEATURE_SCHEMA = "feature_schema"
    GRAPH = "graph"
    CORRELATION = "correlation"
    ML = "ml"
    EXPLAINABILITY = "explainability"
    REPORTING = "reporting"
    EVALUATION = "evaluation"
    PRIVACY = "privacy"
    SECURITY = "security"
    ORCHESTRATION = "orchestration"


class ServiceLifecycleState(str, Enum):
    """
    Bounded service lifecycle state.
    """

    REGISTERED = "registered"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    BLOCKED = "blocked"
    DEGRADED = "degraded"
    FAILED = "failed"


class HealthStatus(str, Enum):
    """
    Bounded service health status.
    """

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    BLOCKED = "blocked"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class ExecutionStatus(str, Enum):
    """
    Bounded service execution status.
    """

    PASSED = "PASSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"


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


def _clean_text(value: Any, limit: int = DEFAULT_MAX_TEXT_LENGTH) -> str:
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


def _is_forbidden_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_SERVICE_FIELDS:
        return True

    if canonical.startswith("raw_") or canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_SERVICE_TOKENS)


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
    if depth > HARD_MAX_PAYLOAD_DEPTH:
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

    if callable(value):
        return "<callable>"

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:HARD_MAX_PAYLOAD_ITEMS]:
            key = _clean_text(raw_key, 128)

            if not key or _is_sensitive_detail_key(key) or _is_forbidden_key(key) or _is_label_leakage_key(key):
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:HARD_MAX_PAYLOAD_ITEMS]]

    return f"<{type(value).__name__}>"


def _as_mapping(value: Any) -> dict[str, Any]:
    sanitized = _safe_detail_value(value)
    return sanitized if isinstance(sanitized, dict) else {}


def _as_counts(value: Any) -> Mapping[str, int]:
    return MappingProxyType(
        {
            str(key): max(0, _as_int(item, 0))
            for key, item in _as_mapping(value).items()
        }
    )


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

    if callable(value):
        return "<callable>"

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
            for raw_key, raw_value in list(value.items())[:HARD_MAX_PAYLOAD_ITEMS]:
                parts.append(str(raw_key))
                visit(raw_value, depth + 1)
            return

        if isinstance(value, (list, tuple, set, frozenset)):
            for item in list(value)[:HARD_MAX_PAYLOAD_ITEMS]:
                visit(item, depth + 1)
            return

        parts.append(str(value))

    for value in values:
        visit(value)

    text = " ".join(parts).lower()
    return bool(text) and any(token in text for token in _PROHIBITED_ACTION_TOKENS)


def _normalize_tags(value: Any, limit: int = 100) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        tag = _clean_text(item, 128)

        if tag:
            out.append(tag)

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
    tokens, passwords, database URLs, filesystem paths, model artifact paths, or
    executable handler references.
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
        object.__setattr__(self, "message", _clean_text(self.message, MAX_REASON_TEXT_LENGTH))
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


def _coerce_issue(value: Any) -> ServiceIssue:
    if isinstance(value, ServiceIssue):
        return value

    if isinstance(value, Mapping):
        return ServiceIssue(
            severity=value.get("severity", IssueSeverity.WARNING),
            code=value.get("code", "unstructured_issue"),
            message=value.get("message", ""),
            field=value.get("field"),
            details=value.get("details", {}),
        )

    return ServiceIssue(
        severity=IssueSeverity.WARNING,
        code="unstructured_issue",
        message=_clean_text(value, MAX_REASON_TEXT_LENGTH),
    )


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
            message=_clean_text(message, MAX_REASON_TEXT_LENGTH),
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
    Bounded backend service orchestration policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    max_services: int = DEFAULT_MAX_SERVICES
    max_payload_depth: int = DEFAULT_MAX_PAYLOAD_DEPTH
    max_payload_items: int = DEFAULT_MAX_PAYLOAD_ITEMS
    max_text_length: int = DEFAULT_MAX_TEXT_LENGTH
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS
    max_result_items: int = DEFAULT_MAX_RESULT_ITEMS

    drop_forbidden_fields: bool = True
    include_result_data: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_token(self.dataset_mode) or "synthetic")
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(
            self,
            "max_services",
            _clamp_int(self.max_services, 1, HARD_MAX_SERVICES, DEFAULT_MAX_SERVICES),
        )
        object.__setattr__(
            self,
            "max_payload_depth",
            _clamp_int(self.max_payload_depth, 1, HARD_MAX_PAYLOAD_DEPTH, DEFAULT_MAX_PAYLOAD_DEPTH),
        )
        object.__setattr__(
            self,
            "max_payload_items",
            _clamp_int(self.max_payload_items, 1, HARD_MAX_PAYLOAD_ITEMS, DEFAULT_MAX_PAYLOAD_ITEMS),
        )
        object.__setattr__(
            self,
            "max_text_length",
            _clamp_int(self.max_text_length, 1, HARD_MAX_TEXT_LENGTH, DEFAULT_MAX_TEXT_LENGTH),
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
            "max_result_items",
            _clamp_int(self.max_result_items, 1, HARD_MAX_RESULT_ITEMS, DEFAULT_MAX_RESULT_ITEMS),
        )

        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, True))
        object.__setattr__(self, "include_result_data", _as_bool(self.include_result_data, True))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ServiceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

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
            enabled=_as_bool(_setting(settings, "SERVICES_ENABLED", True), True),
            synthetic_required=_as_bool(_setting(settings, "SERVICES_REQUIRE_SYNTHETIC", True), True),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(_setting(settings, "SERVICES_ALLOW_IN_PRODUCTION", False), False),
            max_services=_as_int(_setting(settings, "SERVICES_MAX_SERVICES", DEFAULT_MAX_SERVICES), DEFAULT_MAX_SERVICES),
            max_payload_depth=_as_int(
                _setting(settings, "SERVICES_MAX_PAYLOAD_DEPTH", DEFAULT_MAX_PAYLOAD_DEPTH),
                DEFAULT_MAX_PAYLOAD_DEPTH,
            ),
            max_payload_items=_as_int(
                _setting(settings, "SERVICES_MAX_PAYLOAD_ITEMS", DEFAULT_MAX_PAYLOAD_ITEMS),
                DEFAULT_MAX_PAYLOAD_ITEMS,
            ),
            max_text_length=_as_int(
                _setting(settings, "SERVICES_MAX_TEXT_LENGTH", DEFAULT_MAX_TEXT_LENGTH),
                DEFAULT_MAX_TEXT_LENGTH,
            ),
            max_issues=_as_int(_setting(settings, "SERVICES_MAX_ISSUES", DEFAULT_MAX_ISSUES), DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(
                _setting(settings, "SERVICES_MAX_SUMMARY_ITEMS", DEFAULT_MAX_SUMMARY_ITEMS),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(_setting(settings, "SERVICES_MAX_TIME_MS", DEFAULT_MAX_TIME_MS), DEFAULT_MAX_TIME_MS),
            max_result_items=_as_int(
                _setting(settings, "SERVICES_MAX_RESULT_ITEMS", DEFAULT_MAX_RESULT_ITEMS),
                DEFAULT_MAX_RESULT_ITEMS,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "SERVICES_DROP_FORBIDDEN_FIELDS", True),
                True,
            ),
            include_result_data=_as_bool(
                _setting(settings, "SERVICES_INCLUDE_RESULT_DATA", True),
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
            "limits": {
                "max_services": self.max_services,
                "max_payload_depth": self.max_payload_depth,
                "max_payload_items": self.max_payload_items,
                "max_text_length": self.max_text_length,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
                "max_result_items": self.max_result_items,
            },
            "flags": {
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "include_result_data": self.include_result_data,
            },
        }


# -----------------------------------------------------------------------------
# Payload sanitization
# -----------------------------------------------------------------------------


def _sanitize_payload(
    value: Any,
    options: ServiceOptions,
    issues: list[ServiceIssue],
    depth: int = 0,
) -> tuple[Any, bool]:
    """
    Sanitize one service payload deterministically.

    Returns ``(sanitized_value, ok)``. If ``ok`` is false, the payload contained
    forbidden or leakage-prone content and must not be executed.
    """
    if depth > int(options.max_payload_depth):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="payload_depth_truncated",
            message="Payload depth exceeded configured limit and was truncated.",
            details={"depth": depth, "max_payload_depth": int(options.max_payload_depth)},
        )
        return "[truncated-depth]", True

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        truncated = False

        for index, (raw_key, raw_value) in enumerate(value.items()):
            if index >= int(options.max_payload_items):
                truncated = True
                break

            key = _clean_text(raw_key, 128)

            if not key:
                continue

            canonical = _canonical_field_name(key)

            if _is_forbidden_key(canonical) or _is_label_leakage_key(canonical):
                if options.drop_forbidden_fields:
                    _append_issue(
                        issues,
                        options.max_issues,
                        severity=IssueSeverity.INFO,
                        code="forbidden_payload_field_dropped",
                        message="Forbidden or leakage-prone payload field omitted.",
                        field=canonical,
                        details={"depth": depth},
                    )
                    continue

                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="forbidden_payload_field",
                    message="Forbidden or leakage-prone payload field rejected.",
                    field=canonical,
                    details={"depth": depth},
                )
                return None, False

            sanitized_child, child_ok = _sanitize_payload(raw_value, options, issues, depth + 1)

            if not child_ok:
                return None, False

            out[key] = sanitized_child

        if truncated:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="payload_item_truncated",
                message="Payload item count exceeded configured limit and was truncated.",
                details={"depth": depth, "max_payload_items": int(options.max_payload_items)},
            )

        return out, True

    if isinstance(value, (list, tuple, set, frozenset)):
        out_list: list[Any] = []
        truncated = False

        for index, item in enumerate(value):
            if index >= int(options.max_payload_items):
                truncated = True
                break

            sanitized_item, item_ok = _sanitize_payload(item, options, issues, depth + 1)

            if not item_ok:
                return None, False

            out_list.append(sanitized_item)

        if truncated:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="payload_sequence_truncated",
                message="Payload sequence exceeded configured item limit and was truncated.",
                details={"depth": depth, "max_payload_items": int(options.max_payload_items)},
            )

        return out_list, True

    if isinstance(value, str):
        return _clean_text(value, int(options.max_text_length)), True

    if isinstance(value, bool):
        return value, True

    if isinstance(value, int):
        return value, True

    if isinstance(value, float):
        return value if math.isfinite(value) else None, True

    if isinstance(value, Decimal):
        return str(value) if value.is_finite() else None, True

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None, True

    if isinstance(value, Enum):
        return _sanitize_payload(value.value, options, issues, depth)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>", True

    if callable(value):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="callable_payload_rejected",
            message="Executable callable payload was rejected.",
            details={"depth": depth},
        )
        return None, False

    return f"<{type(value).__name__}>", True


# -----------------------------------------------------------------------------
# Descriptor, health, request, and result models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ServiceDescriptor:
    """
    One bounded backend service descriptor.

    Handlers are optional process-local callables used only for local prototype
    orchestration. Handler references are never exposed in public summaries.
    """

    service_id: str = ""
    kind: ServiceKind | str = ServiceKind.GENERAL
    display_name: str = ""
    description: str = ""
    version: str = SERVICES_VERSION
    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False
    capabilities: Sequence[str] = ()
    dependencies: Sequence[str] = ()
    safety_flags: Mapping[str, Any] = dataclass_field(default_factory=dict)
    caveats: Sequence[str] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    handler: Optional[Callable[[Any], Any]] = None
    health_handler: Optional[Callable[[], Mapping[str, Any]]] = None
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _normalize_enum_option(ServiceKind, self.kind, ServiceKind.GENERAL))
        object.__setattr__(
            self,
            "service_id",
            _clean_text(self.service_id, 128).lower() or _enum_value(self.kind, ServiceKind.GENERAL.value),
        )
        object.__setattr__(self, "display_name", _clean_text(self.display_name, 200))
        object.__setattr__(self, "description", _clean_text(self.description, 500))
        object.__setattr__(self, "version", _clean_text(self.version, 64) or SERVICES_VERSION)

        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_token(self.dataset_mode) or "synthetic")
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(self, "capabilities", _normalize_tags(self.capabilities, limit=100))
        object.__setattr__(self, "dependencies", _normalize_tags(self.dependencies, limit=100))

        merged_flags = dict(_SERVICE_SAFETY_FLAGS)
        merged_flags.update(
            {
                str(key): _as_bool(value, False)
                for key, value in _as_mapping(self.safety_flags).items()
            }
        )

        for key in _CRITICAL_TRUE_SAFETY_FLAGS:
            merged_flags[key] = True

        object.__setattr__(self, "safety_flags", MappingProxyType(merged_flags))

        user_caveats = _normalize_tags(self.caveats, limit=100)
        merged_caveats = tuple(dict.fromkeys([*_SERVICE_CAVEATS, *user_caveats]))[:100]
        object.__setattr__(self, "caveats", merged_caveats)

        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not callable(self.handler):
            object.__setattr__(self, "handler", None)

        if not callable(self.health_handler):
            object.__setattr__(self, "health_handler", None)

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(self.safe_summary()),
            )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "kind": _enum_value(self.kind, ServiceKind.GENERAL.value),
            "display_name": self.display_name,
            "description": self.description,
            "version": self.version,
            "enabled": self.enabled,
            "synthetic_required": self.synthetic_required,
            "dataset_mode": self.dataset_mode,
            "production_like": self.production_like,
            "allow_in_production": self.allow_in_production,
            "capabilities": list(self.capabilities),
            "dependencies": list(self.dependencies),
            "safety_flags": dict(self.safety_flags),
            "caveats": list(self.caveats),
            "metadata": _safe_detail_value(self.metadata),
            "handler_registered": callable(self.handler),
            "health_handler_registered": callable(self.health_handler),
            "fingerprint": self.fingerprint,
            "raw_values_retained": False,
            "executable_handler_exposed": False,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.safe_summary()


@dataclass(frozen=True, slots=True)
class ServiceHealth:
    """
    One bounded service health report.
    """

    service_id: str = ""
    kind: ServiceKind | str = ServiceKind.GENERAL
    status: HealthStatus | str = HealthStatus.UNKNOWN
    lifecycle_state: ServiceLifecycleState | str = ServiceLifecycleState.REGISTERED
    ok: bool = False
    checked_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    issues: tuple[ServiceIssue, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_id", _clean_text(self.service_id, 128).lower())
        object.__setattr__(self, "kind", _normalize_enum_option(ServiceKind, self.kind, ServiceKind.GENERAL))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(HealthStatus, self.status, HealthStatus.UNKNOWN),
        )
        object.__setattr__(
            self,
            "lifecycle_state",
            _normalize_enum_option(
                ServiceLifecycleState,
                self.lifecycle_state,
                ServiceLifecycleState.REGISTERED,
            ),
        )
        object.__setattr__(self, "ok", _as_bool(self.ok, False))
        object.__setattr__(self, "checked_at", _ensure_utc(self.checked_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "issues", tuple(_coerce_issue(issue) for issue in (self.issues or ())))
        object.__setattr__(self, "counts", _as_counts(self.counts))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": SERVICES_VERSION,
                        "service_id": self.service_id,
                        "kind": _enum_value(self.kind),
                        "status": _enum_value(self.status),
                        "lifecycle_state": _enum_value(self.lifecycle_state),
                        "ok": self.ok,
                        "issue_count": len(self.issues),
                        "counts": self.counts,
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "kind": _enum_value(self.kind, ServiceKind.GENERAL.value),
            "status": _enum_value(self.status, HealthStatus.UNKNOWN.value),
            "lifecycle_state": _enum_value(self.lifecycle_state, ServiceLifecycleState.REGISTERED.value),
            "ok": bool(self.ok),
            "checked_at": self.checked_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "issues": [issue.to_dict() for issue in self.issues],
            "counts": dict(self.counts),
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "raw_values_retained": False,
            "caveats": list(_SERVICE_CAVEATS),
            "safety_flags": dict(_SERVICE_SAFETY_FLAGS),
        }


@dataclass(slots=True)
class ServiceRequest:
    """
    One bounded service execution request.
    """

    service_id: str = ""
    payload: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.service_id = _clean_text(self.service_id, 128).lower()
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags, limit=100)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


@dataclass(frozen=True, slots=True)
class ServiceResult:
    """
    One bounded service execution result.
    """

    ok: bool = True
    status: ExecutionStatus | str = ExecutionStatus.PASSED
    service_id: str = ""
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    data: Any = None
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[ServiceIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(ExecutionStatus, self.status, ExecutionStatus.PASSED),
        )
        object.__setattr__(self, "service_id", _clean_text(self.service_id, 128).lower())
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "data", _safe_detail_value(self.data))
        object.__setattr__(self, "counts", _as_counts(self.counts))
        object.__setattr__(self, "issues", tuple(_coerce_issue(issue) for issue in (self.issues or ())))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": SERVICES_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, ExecutionStatus.PASSED.value),
                        "service_id": self.service_id,
                        "request_id": self.request_id,
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": bool(self.ok),
            "status": _enum_value(self.status, ExecutionStatus.PASSED.value),
            "service_id": self.service_id,
            "request_id": self.request_id,
            "generated_at": self.generated_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "data": self.data,
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "raw_values_retained": False,
            "caveats": list(_SERVICE_CAVEATS),
            "safety_flags": dict(_SERVICE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Coercion helpers
# -----------------------------------------------------------------------------


def _coerce_descriptor(value: Any) -> Optional[ServiceDescriptor]:
    if isinstance(value, ServiceDescriptor):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(ServiceDescriptor, "__dataclass_fields__", {}).keys())
        clean = {key: item for key, item in value.items() if key in fields}

        # Never accept handler references from untrusted mappings.
        clean.pop("handler", None)
        clean.pop("health_handler", None)

        try:
            return ServiceDescriptor(**clean)
        except Exception:
            return None

    return None


def _coerce_request(request: Any) -> ServiceRequest:
    if isinstance(request, ServiceRequest):
        return request

    if isinstance(request, Mapping):
        fields = set(getattr(ServiceRequest, "__dataclass_fields__", {}).keys())

        if any(key in request for key in fields):
            clean = {key: value for key, value in request.items() if key in fields}

            try:
                return ServiceRequest(**clean)
            except Exception:
                return ServiceRequest(service_id="", payload=request)

        return ServiceRequest(service_id="", payload=request)

    if isinstance(request, (list, tuple, set, frozenset)):
        return ServiceRequest(service_id="", payload=request)

    return ServiceRequest(service_id="", payload=request)


# -----------------------------------------------------------------------------
# Process-local service registry
# -----------------------------------------------------------------------------


class ServiceRegistry:
    """
    Bounded process-local service registry.

    This registry is non-durable and intended for local prototype workflows,
    tests, developer tooling, and offline evaluation harnesses only.
    """

    def __init__(self, max_services: int = DEFAULT_MAX_SERVICES) -> None:
        self.max_services = max(1, int(max_services))
        self._descriptors: dict[str, ServiceDescriptor] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, descriptor: Any, *, replace: bool = True) -> Optional[str]:
        resolved = _coerce_descriptor(descriptor)

        if resolved is None:
            return None

        service_id = resolved.service_id

        with self._lock:
            if service_id in self._descriptors:
                if not replace:
                    return service_id

                self._descriptors[service_id] = resolved

                if service_id in self._order:
                    self._order.remove(service_id)

                self._order.append(service_id)
                return service_id

            if len(self._order) >= self.max_services:
                evicted = self._order.pop(0)
                self._descriptors.pop(evicted, None)

            self._descriptors[service_id] = resolved
            self._order.append(service_id)
            return service_id

    def unregister(self, service_id: Any) -> bool:
        key = _clean_text(service_id, 128).lower()

        with self._lock:
            if key not in self._descriptors:
                return False

            self._descriptors.pop(key, None)

            if key in self._order:
                self._order.remove(key)

            return True

    def get(self, service_id: Any) -> Optional[ServiceDescriptor]:
        key = _clean_text(service_id, 128).lower()

        with self._lock:
            return self._descriptors.get(key)

    def list_descriptors(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> tuple[ServiceDescriptor, ...]:
        count = max(0, int(limit))

        with self._lock:
            if count == 0:
                return ()

            return tuple(
                self._descriptors[service_id]
                for service_id in self._order[:count]
                if service_id in self._descriptors
            )

    def summarize(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> list[dict[str, Any]]:
        return [descriptor.safe_summary() for descriptor in self.list_descriptors(limit=limit)]

    def clear(self) -> None:
        with self._lock:
            self._descriptors.clear()
            self._order.clear()

    def safe_summary(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
        with self._lock:
            kind_counter = Counter(
                _enum_value(descriptor.kind, ServiceKind.GENERAL.value)
                for descriptor in self._descriptors.values()
            )
            enabled_counter = Counter(
                "enabled" if descriptor.enabled else "disabled"
                for descriptor in self._descriptors.values()
            )

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_services": self.max_services,
            "registered_services": len(self._order),
            "by_kind": dict(kind_counter),
            "by_enabled": dict(enabled_counter),
            "recent": self.summarize(limit=limit),
            "raw_values_retained": False,
            "executable_handlers_exposed": False,
        }


_default_registry: Optional[ServiceRegistry] = None
_default_registry_lock = threading.Lock()


def get_service_registry(
    max_services: int | None = None,
    *,
    rebuild: bool = False,
) -> ServiceRegistry:
    """
    Return a process-wide bounded service registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = ServiceRegistry(
                max_services=max_services if max_services is not None else DEFAULT_MAX_SERVICES
            )

        return _default_registry


# -----------------------------------------------------------------------------
# Orchestrator helpers
# -----------------------------------------------------------------------------


def _execution_status_from_health(status: HealthStatus) -> ExecutionStatus:
    if status == HealthStatus.HEALTHY:
        return ExecutionStatus.PASSED

    if status == HealthStatus.DEGRADED:
        return ExecutionStatus.DEGRADED

    if status == HealthStatus.UNHEALTHY:
        return ExecutionStatus.FAILED

    if status in {HealthStatus.BLOCKED, HealthStatus.DISABLED}:
        return ExecutionStatus.BLOCKED

    if status == HealthStatus.UNAVAILABLE:
        return ExecutionStatus.UNAVAILABLE

    return ExecutionStatus.SKIPPED


def _aggregate_health_status(healths: Sequence[ServiceHealth]) -> tuple[HealthStatus, bool]:
    if not healths:
        return HealthStatus.UNAVAILABLE, False

    statuses = Counter(_enum_value(health.status, HealthStatus.UNKNOWN.value) for health in healths)

    if statuses.get(HealthStatus.UNHEALTHY.value, 0):
        return HealthStatus.UNHEALTHY, False

    if statuses.get(HealthStatus.BLOCKED.value, 0):
        return HealthStatus.BLOCKED, False

    if statuses.get(HealthStatus.DISABLED.value, 0):
        return HealthStatus.DISABLED, False

    if statuses.get(HealthStatus.DEGRADED.value, 0) or statuses.get(HealthStatus.UNKNOWN.value, 0):
        return HealthStatus.DEGRADED, any(health.ok for health in healths)

    if statuses.get(HealthStatus.HEALTHY.value, 0):
        return HealthStatus.HEALTHY, all(health.ok for health in healths)

    return HealthStatus.UNAVAILABLE, False


# -----------------------------------------------------------------------------
# Orchestrator
# -----------------------------------------------------------------------------


class ServicesOrchestrator:
    """
    Bounded deterministic synthetic backend service orchestrator.

    This orchestrator executes registered local service handlers only. It does
    not authorize actions, deploy services, persist durable artifacts, call
    external systems, or take adverse action.
    """

    def __init__(
        self,
        options: ServiceOptions | None = None,
        registry: ServiceRegistry | None = None,
    ) -> None:
        self.options = options or ServiceOptions.from_settings()
        self.registry = registry or get_service_registry(self.options.max_services)
        self._lock = threading.RLock()

    def _global_block_reason(self) -> Optional[tuple[HealthStatus, str, str]]:
        opts = self.options

        if not opts.enabled:
            return (
                HealthStatus.DISABLED,
                "services_disabled",
                "Backend service orchestration is disabled.",
            )

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            return (
                HealthStatus.BLOCKED,
                "non_synthetic_dataset",
                "Backend service orchestration requires synthetic dataset mode.",
            )

        if opts.production_like and not opts.allow_in_production:
            return (
                HealthStatus.BLOCKED,
                "production_like_blocked",
                "Backend service orchestration is blocked in production-like environments.",
            )

        return None

    def _descriptor_block_reason(
        self,
        descriptor: ServiceDescriptor,
    ) -> Optional[tuple[HealthStatus, str, str]]:
        if not descriptor.enabled:
            return (
                HealthStatus.DISABLED,
                "service_disabled",
                "Service is disabled.",
            )

        if descriptor.synthetic_required and descriptor.dataset_mode != "synthetic":
            return (
                HealthStatus.BLOCKED,
                "service_non_synthetic_dataset",
                "Service requires synthetic dataset mode.",
            )

        if descriptor.production_like and not descriptor.allow_in_production:
            return (
                HealthStatus.BLOCKED,
                "service_production_like_blocked",
                "Service is blocked in production-like environments.",
            )

        return None

    def _policy_block_reason(
        self,
        descriptor: Optional[ServiceDescriptor],
    ) -> Optional[tuple[HealthStatus, str, str]]:
        global_reason = self._global_block_reason()

        if global_reason is not None:
            return global_reason

        if descriptor is None:
            return None

        return self._descriptor_block_reason(descriptor)

    def health_one(self, descriptor: ServiceDescriptor) -> ServiceHealth:
        """
        Return one bounded service health report.
        """
        opts = self.options
        issues: list[ServiceIssue] = []
        start_time = time.monotonic()

        block = self._policy_block_reason(descriptor)

        if block is not None:
            status, code, message = block
            lifecycle = (
                ServiceLifecycleState.DISABLED
                if status == HealthStatus.DISABLED
                else ServiceLifecycleState.BLOCKED
            )

            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO if status == HealthStatus.DISABLED else IssueSeverity.ERROR,
                code=code,
                message=message,
            )

            return ServiceHealth(
                service_id=descriptor.service_id,
                kind=descriptor.kind,
                status=status,
                lifecycle_state=lifecycle,
                ok=False,
                checked_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                issues=tuple(_dedupe_issues(issues)[: opts.max_issues]),
                counts={"policy_blocks": 1},
                metadata={
                    "descriptor": descriptor.safe_summary(),
                    "raw_values_retained": False,
                    "executable_handler_exposed": False,
                },
                fingerprint="",
            )

        if not callable(descriptor.handler):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="service_handler_unavailable",
                message="Service handler is unavailable in this deployment.",
            )

            return ServiceHealth(
                service_id=descriptor.service_id,
                kind=descriptor.kind,
                status=HealthStatus.UNAVAILABLE,
                lifecycle_state=ServiceLifecycleState.UNAVAILABLE,
                ok=False,
                checked_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                issues=tuple(_dedupe_issues(issues)[: opts.max_issues]),
                counts={"handler_unavailable": 1},
                metadata={
                    "descriptor": descriptor.safe_summary(),
                    "raw_values_retained": False,
                    "executable_handler_exposed": False,
                },
                fingerprint="",
            )

        if callable(descriptor.health_handler):
            try:
                health_payload = descriptor.health_handler()
            except Exception as exc:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="service_health_handler_failed",
                    message="Service health handler failed unexpectedly.",
                    details={"exception_type": type(exc).__name__},
                )

                return ServiceHealth(
                    service_id=descriptor.service_id,
                    kind=descriptor.kind,
                    status=HealthStatus.UNHEALTHY,
                    lifecycle_state=ServiceLifecycleState.FAILED,
                    ok=False,
                    checked_at=_now_utc(),
                    duration_ms=_elapsed_ms(start_time),
                    issues=tuple(_dedupe_issues(issues)[: opts.max_issues]),
                    counts={"health_failures": 1},
                    metadata={
                        "descriptor": descriptor.safe_summary(),
                        "raw_values_retained": False,
                        "executable_handler_exposed": False,
                    },
                    fingerprint="",
                )

            payload = _as_mapping(health_payload)
            ok = _as_bool(payload.get("ok"), True)
            status = _normalize_enum_option(
                HealthStatus,
                payload.get("status"),
                HealthStatus.HEALTHY if ok else HealthStatus.DEGRADED,
            )
            lifecycle = _normalize_enum_option(
                ServiceLifecycleState,
                payload.get("lifecycle_state"),
                ServiceLifecycleState.AVAILABLE,
            )
            health_issues = tuple(
                _coerce_issue(issue)
                for issue in _as_sequence(payload.get("issues", ()))
            )
            issues.extend(health_issues)

            return ServiceHealth(
                service_id=descriptor.service_id,
                kind=descriptor.kind,
                status=status,
                lifecycle_state=lifecycle,
                ok=ok,
                checked_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                issues=tuple(_dedupe_issues(issues)[: opts.max_issues]),
                counts=_as_counts(payload.get("counts", {})),
                metadata={
                    "descriptor": descriptor.safe_summary(),
                    "health_payload": _safe_detail_value(payload.get("metadata", {})),
                    "raw_values_retained": False,
                    "executable_handler_exposed": False,
                },
                fingerprint="",
            )

        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="service_health_check_unavailable",
            message="Service handler is registered but no health check is available.",
        )

        return ServiceHealth(
            service_id=descriptor.service_id,
            kind=descriptor.kind,
            status=HealthStatus.UNKNOWN,
            lifecycle_state=ServiceLifecycleState.AVAILABLE,
            ok=False,
            checked_at=_now_utc(),
            duration_ms=_elapsed_ms(start_time),
            issues=tuple(_dedupe_issues(issues)[: opts.max_issues]),
            counts={"health_checks_unavailable": 1},
            metadata={
                "descriptor": descriptor.safe_summary(),
                "raw_values_retained": False,
                "executable_handler_exposed": False,
            },
            fingerprint="",
        )

    def health(self, service_id: Any | None = None) -> tuple[ServiceHealth, ...]:
        """
        Return bounded health reports for one service or all registered services.
        """
        if service_id is not None:
            descriptor = self.registry.get(service_id)

            if descriptor is None:
                return (
                    ServiceHealth(
                        service_id=_clean_text(service_id, 128).lower(),
                        kind=ServiceKind.GENERAL,
                        status=HealthStatus.UNAVAILABLE,
                        lifecycle_state=ServiceLifecycleState.UNAVAILABLE,
                        ok=False,
                        issues=(
                            ServiceIssue(
                                severity=IssueSeverity.INFO,
                                code="service_not_registered",
                                message="Service is not registered in the process-local registry.",
                            ),
                        ),
                        counts={"unknown_services": 1},
                        metadata={"raw_values_retained": False},
                    ),
                )

            return (self.health_one(descriptor),)

        descriptors = self.registry.list_descriptors(limit=self.options.max_services)
        return tuple(self.health_one(descriptor) for descriptor in descriptors)

    def run(self, request: Any) -> ServiceResult:
        """
        Run one bounded synthetic service execution job.
        """
        opts = self.options
        issues: list[ServiceIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)

        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": SERVICES_VERSION,
                    "service_id": req.service_id,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                    "payload_shape": type(req.payload).__name__,
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: ExecutionStatus,
            data: Any = None,
            counts: Optional[Mapping[str, int]] = None,
            metadata: Optional[Mapping[str, Any]] = None,
            descriptor: Optional[ServiceDescriptor] = None,
        ) -> ServiceResult:
            resolved_counts: dict[str, int] = {
                "issues": len(issues),
                "executions": 1 if status not in {ExecutionStatus.BLOCKED, ExecutionStatus.SKIPPED} else 0,
            }

            if counts:
                resolved_counts.update(
                    {str(key): max(0, _as_int(value, 0)) for key, value in counts.items()}
                )

            resolved_counts["issues"] = len(issues)

            resolved_metadata: dict[str, Any] = {
                "services_version": SERVICES_VERSION,
                "service_id": req.service_id,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "registry": self.registry.safe_summary(limit=opts.max_summary_items),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_values_retained": False,
                "raw_identifiers_retained": False,
                "raw_narratives_retained": False,
                "subject_label_pairs_retained": False,
                "secrets_retained": False,
                "executable_handler_exposed": False,
                "caveats": list(_SERVICE_CAVEATS),
                "safety_flags": dict(_SERVICE_SAFETY_FLAGS),
            }

            if descriptor is not None:
                resolved_metadata["descriptor"] = descriptor.safe_summary()

            if metadata:
                resolved_metadata.update(_as_mapping(metadata))

            return ServiceResult(
                ok=ok,
                status=status,
                service_id=req.service_id,
                request_id=request_id,
                generated_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                data=data if opts.include_result_data else None,
                counts=resolved_counts,
                issues=tuple(_dedupe_issues(issues)[: opts.max_issues]),
                metadata=resolved_metadata,
                fingerprint="",
            )

        block = self._policy_block_reason(None)

        if block is not None:
            status, code, message = block
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO if status == HealthStatus.DISABLED else IssueSeverity.ERROR,
                code=code,
                message=message,
            )
            return make_result(False, _execution_status_from_health(status))

        if not req.service_id:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="missing_service_id",
                message="Service request is missing service_id.",
                field="service_id",
            )
            return make_result(False, ExecutionStatus.FAILED)

        descriptor = self.registry.get(req.service_id)

        if descriptor is None:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="service_not_registered",
                message="Service is not registered in the process-local registry.",
                field="service_id",
                details={"service_id": req.service_id},
            )
            return make_result(False, ExecutionStatus.UNAVAILABLE)

        block = self._policy_block_reason(descriptor)

        if block is not None:
            status, code, message = block
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO if status == HealthStatus.DISABLED else IssueSeverity.ERROR,
                code=code,
                message=message,
                details={"service_id": descriptor.service_id},
            )
            return make_result(
                False,
                _execution_status_from_health(status),
                descriptor=descriptor,
            )

        if not callable(descriptor.handler):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="service_handler_unavailable",
                message="Service handler is unavailable in this deployment.",
                details={"service_id": descriptor.service_id},
            )
            return make_result(False, ExecutionStatus.UNAVAILABLE, descriptor=descriptor)

        sanitized_payload, payload_ok = _sanitize_payload(req.payload, opts, issues)

        if not payload_ok:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="service_payload_rejected",
                message="Service payload was rejected due to forbidden or leakage-prone content.",
                details={"service_id": descriptor.service_id},
            )
            return make_result(False, ExecutionStatus.FAILED, descriptor=descriptor)

        if _contains_prohibited_action(sanitized_payload, req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_service_action_metadata",
                message="Service request contains prohibited adverse-action language.",
                details={"service_id": descriptor.service_id},
            )
            return make_result(False, ExecutionStatus.BLOCKED, descriptor=descriptor)

        if _time_exceeded(start_time, opts.max_time_ms):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="service_time_budget_exhausted",
                message="Service execution skipped after reaching configured time budget.",
                details={"service_id": descriptor.service_id},
            )
            return make_result(False, ExecutionStatus.SKIPPED, descriptor=descriptor)

        try:
            handler_result = descriptor.handler(sanitized_payload)
        except Exception as exc:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="service_handler_failed",
                message="Service handler failed unexpectedly.",
                details={
                    "service_id": descriptor.service_id,
                    "exception_type": type(exc).__name__,
                },
            )
            return make_result(False, ExecutionStatus.FAILED, descriptor=descriptor)

        duration_ms = _elapsed_ms(start_time)

        if isinstance(handler_result, ServiceResult):
            merged_metadata = dict(handler_result.metadata)
            merged_metadata.update(
                {
                    "descriptor": descriptor.safe_summary(),
                    "services_version": SERVICES_VERSION,
                    "request_id": request_id,
                    "elapsed_ms": duration_ms,
                    "raw_values_retained": False,
                    "executable_handler_exposed": False,
                }
            )

            return ServiceResult(
                ok=handler_result.ok,
                status=handler_result.status,
                service_id=descriptor.service_id,
                request_id=request_id,
                generated_at=handler_result.generated_at,
                duration_ms=duration_ms,
                data=handler_result.data,
                counts=handler_result.counts,
                issues=handler_result.issues,
                metadata=merged_metadata,
                fingerprint="",
            )

        if isinstance(handler_result, Mapping):
            payload = _as_mapping(handler_result)
            ok = _as_bool(payload.get("ok"), True)
            status = _normalize_enum_option(
                ExecutionStatus,
                payload.get("status"),
                ExecutionStatus.PASSED if ok else ExecutionStatus.FAILED,
            )
            result_issues = tuple(
                _coerce_issue(issue)
                for issue in _as_sequence(payload.get("issues", ()))
            )
            issues.extend(result_issues)

            return make_result(
                ok=ok,
                status=status,
                data=payload.get("data", payload),
                counts=payload.get("counts", {}),
                metadata={
                    "handler_metadata": payload.get("metadata", {}),
                    "descriptor": descriptor.safe_summary(),
                },
                descriptor=descriptor,
            )

        if hasattr(handler_result, "to_dict"):
            try:
                data = handler_result.to_dict()
            except Exception:
                data = _safe_detail_value(handler_result)
        else:
            data = _safe_detail_value(handler_result)

        ok = bool(_as_bool(getattr(handler_result, "ok", True), True))
        status = _normalize_enum_option(
            ExecutionStatus,
            getattr(handler_result, "status", ExecutionStatus.PASSED if ok else ExecutionStatus.FAILED),
            ExecutionStatus.PASSED if ok else ExecutionStatus.FAILED,
        )

        return make_result(
            ok=ok,
            status=status,
            data=data,
            counts=getattr(handler_result, "counts", {}),
            metadata={
                "handler_metadata": getattr(handler_result, "metadata", {}),
                "descriptor": descriptor.safe_summary(),
            },
            descriptor=descriptor,
        )

    def run_many(self, requests: Any, *, limit: int | None = None) -> tuple[ServiceResult, ...]:
        """
        Run multiple bounded synthetic service jobs.
        """
        items = _as_sequence(requests)
        max_items = min(
            int(limit) if limit is not None else int(self.options.max_services),
            len(items),
        )

        results: list[ServiceResult] = []

        for item in items[:max_items]:
            results.append(self.run(item))

            if _time_exceeded(results[0].generated_at.timestamp() if results else time.monotonic(), self.options.max_time_ms):
                break

        return tuple(results)

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "registry": self.registry.safe_summary(limit=self.options.max_summary_items),
            "caveats": list(_SERVICE_CAVEATS),
            "safety_flags": dict(_SERVICE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default orchestrator and public API
# -----------------------------------------------------------------------------


_default_orchestrator: Optional[ServicesOrchestrator] = None
_default_orchestrator_lock = threading.Lock()


def get_services_options(settings: Any | None = None) -> ServiceOptions:
    """
    Return backend service options from settings.
    """
    return ServiceOptions.from_settings(settings)


def get_services_orchestrator(
    options: ServiceOptions | None = None,
    *,
    rebuild: bool = False,
) -> ServicesOrchestrator:
    """
    Return a process-wide backend service orchestrator.
    """
    global _default_orchestrator

    with _default_orchestrator_lock:
        if _default_orchestrator is None or rebuild or options is not None:
            resolved_options = options or ServiceOptions.from_settings()
            _default_orchestrator = ServicesOrchestrator(
                options=resolved_options,
                registry=get_service_registry(resolved_options.max_services),
            )

        return _default_orchestrator


def register_service_descriptor(
    descriptor: Any,
    *,
    registry: ServiceRegistry | None = None,
    replace: bool = True,
) -> Optional[str]:
    """
    Register one bounded service descriptor.
    """
    active_registry = registry or get_service_registry()
    return active_registry.register(descriptor, replace=replace)


def unregister_service_descriptor(
    service_id: Any,
    *,
    registry: ServiceRegistry | None = None,
) -> bool:
    """
    Unregister one bounded service descriptor.
    """
    active_registry = registry or get_service_registry()
    return active_registry.unregister(service_id)


def list_service_descriptors(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: ServiceRegistry | None = None,
) -> tuple[ServiceDescriptor, ...]:
    """
    Return registered service descriptors.
    """
    active_registry = registry or get_service_registry()
    return active_registry.list_descriptors(limit=limit)


def get_service_descriptor(
    service_id: Any,
    *,
    registry: ServiceRegistry | None = None,
) -> Optional[ServiceDescriptor]:
    """
    Return one registered service descriptor.
    """
    active_registry = registry or get_service_registry()
    return active_registry.get(service_id)


def run_service(
    request: Any,
    options: ServiceOptions | None = None,
    *,
    orchestrator: ServicesOrchestrator | None = None,
) -> ServiceResult:
    """
    Run one bounded synthetic service execution job.
    """
    active_orchestrator = orchestrator or get_services_orchestrator(options)
    return active_orchestrator.run(request)


def run_services(
    requests: Any,
    options: ServiceOptions | None = None,
    *,
    orchestrator: ServicesOrchestrator | None = None,
    limit: int | None = None,
) -> tuple[ServiceResult, ...]:
    """
    Run multiple bounded synthetic service execution jobs.
    """
    active_orchestrator = orchestrator or get_services_orchestrator(options)
    return active_orchestrator.run_many(requests, limit=limit)


def get_services_health(
    service_id: Any | None = None,
    *,
    orchestrator: ServicesOrchestrator | None = None,
) -> dict[str, Any]:
    """
    Return safe backend service health.
    """
    active_orchestrator = orchestrator or get_services_orchestrator()
    healths = active_orchestrator.health(service_id=service_id)
    aggregate_status, aggregate_ok = _aggregate_health_status(healths)

    status_counter = Counter(_enum_value(health.status, HealthStatus.UNKNOWN.value) for health in healths)
    lifecycle_counter = Counter(
        _enum_value(health.lifecycle_state, ServiceLifecycleState.REGISTERED.value)
        for health in healths
    )

    return {
        "status": _enum_value(aggregate_status, HealthStatus.UNKNOWN.value),
        "ok": bool(aggregate_ok),
        "service_id": _clean_text(service_id, 128).lower() if service_id is not None else None,
        "services_total": len(healths),
        "by_status": dict(status_counter),
        "by_lifecycle_state": dict(lifecycle_counter),
        "health": [health.to_dict() for health in healths],
        "options": active_orchestrator.options.safe_summary(),
        "registry": active_orchestrator.registry.safe_summary(limit=active_orchestrator.options.max_summary_items),
        "caveats": list(_SERVICE_CAVEATS),
        "safety_flags": dict(_SERVICE_SAFETY_FLAGS),
    }


def export_services_summary(result: ServiceResult) -> dict[str, Any]:
    """
    Export a safe public service result summary.
    """
    return result.to_dict()


def clear_service_registry(*, registry: ServiceRegistry | None = None) -> None:
    """
    Clear the process-local service registry.
    """
    active_registry = registry or get_service_registry()
    active_registry.clear()


def get_services_metadata(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    orchestrator: ServicesOrchestrator | None = None,
) -> dict[str, Any]:
    """
    Return safe, serializable backend service metadata.

    This is useful for startup logs, diagnostic endpoints, tests, developer
    tooling, and architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, filesystem paths, executable handler
    references, or real customer data.
    """
    active_orchestrator = orchestrator or get_services_orchestrator()
    options = active_orchestrator.options
    registry_summary = active_orchestrator.registry.safe_summary(limit=limit)

    return {
        "package": "muleguard.backend.services",
        "version": SERVICES_VERSION,
        "service_kinds": [kind.value for kind in ServiceKind],
        "lifecycle_states": [state.value for state in ServiceLifecycleState],
        "health_statuses": [status.value for status in HealthStatus],
        "execution_statuses": [status.value for status in ExecutionStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "registry": registry_summary,
        "hard_limits": {
            "max_services": HARD_MAX_SERVICES,
            "max_payload_depth": HARD_MAX_PAYLOAD_DEPTH,
            "max_payload_items": HARD_MAX_PAYLOAD_ITEMS,
            "max_text_length": HARD_MAX_TEXT_LENGTH,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
            "max_result_items": HARD_MAX_RESULT_ITEMS,
        },
        "forbidden_service_field_count": len(_FORBIDDEN_SERVICE_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(_PROHIBITED_ACTION_TOKENS),
        "summary_item_limit": max(1, int(limit)),
        "caveats": list(_SERVICE_CAVEATS),
        "safety_flags": dict(_SERVICE_SAFETY_FLAGS),
    }


__all__ = [
    "ExecutionStatus",
    "HealthStatus",
    "IssueSeverity",
    "SERVICES_VERSION",
    "ServiceDescriptor",
    "ServiceHealth",
    "ServiceIssue",
    "ServiceKind",
    "ServiceLifecycleState",
    "ServiceOptions",
    "ServiceRegistry",
    "ServiceRequest",
    "ServiceResult",
    "ServicesOrchestrator",
    "clear_service_registry",
    "export_services_summary",
    "get_service_descriptor",
    "get_service_registry",
    "get_services_health",
    "get_services_metadata",
    "get_services_options",
    "get_services_orchestrator",
    "list_service_descriptors",
    "register_service_descriptor",
    "run_service",
    "run_services",
    "unregister_service_descriptor",
]