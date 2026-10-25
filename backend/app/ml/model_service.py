"""
MULEGUARD backend ML model service.

This module provides the canonical bounded orchestration layer for the synthetic
MULEGUARD machine-learning subsystem.

Primary responsibilities:

- coordinate feature validation, synthetic labeling, splitting, preprocessing,
  supervised training, anomaly fitting, fallback scoring, evaluation, governance
  checks, model cataloging, promotion/retirement, inference routing, health
  reporting, and safe metadata exposure;
- provide a single import-safe service facade for ML APIs, evaluation harnesses,
  tests, seeders, offline fixtures, and developer tooling;
- enforce deterministic train/validation/test isolation and prevent label or
  target leakage into preprocessing, supervised training, anomaly fitting, or
  fallback scoring;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values, subject-label pairs, raw identifiers, raw
  narratives, secrets, tokens, passwords, database URLs, filesystem paths, and
  model artifact paths from public summaries;
- provide bounded, honest, API-safe results with explicit unavailable-score
  handling, contribution reporting, fingerprints, issue reporting, and product
  safety caveats;
- remain dependency-light and resilient when optional ML submodules are absent.

This module orchestrates ML workflows only. It does not persist data, call
external systems, authenticate users, authorize actions, deploy models to
production serving infrastructure, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for training, evaluation, or inference.
- Synthetic labels are evaluation fixtures only. They are not proof of
  wrongdoing.
- Labels must never be used as features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden in public outputs. Subject linkage is
  pseudonymous and salted.
- Model probabilities, anomaly scores, and fallback scores are investigative
  prioritization signals only. They are not probabilities of guilt.
- Feature contributions are operational attributions only. They are not causal
  proof.
- Supervised, anomaly, and fallback outputs are investigative leads only.
- Model service handling never triggers automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, or otherwise
  harming accounts or customers.
- Undefined or unavailable scores are reported honestly as unavailable rather
  than invented.
- The bundled model catalog is process-local, non-durable, and bounded for local
  prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external model runtimes.
- This module does not deploy, promote to production serving, retire from
  production serving, upload, replace, or execute external models.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable model registry or experiment tracker.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, and case
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
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError

logger = logging.getLogger("muleguard.backend.ml.model_service")


# -----------------------------------------------------------------------------
# Optional ML submodule imports
# -----------------------------------------------------------------------------


try:
    from app.ml import anomaly as anomaly_module
except Exception:  # pragma: no cover - resilience for partial deployments
    anomaly_module = None  # type: ignore[assignment]

try:
    from app.ml import fallback as fallback_module
except Exception:  # pragma: no cover
    fallback_module = None  # type: ignore[assignment]

try:
    from app.ml import labels as labels_module
except Exception:  # pragma: no cover
    labels_module = None  # type: ignore[assignment]

try:
    from app.ml import preprocessing as preprocessing_module
except Exception:  # pragma: no cover
    preprocessing_module = None  # type: ignore[assignment]

try:
    from app.ml import splits as splits_module
except Exception:  # pragma: no cover
    splits_module = None  # type: ignore[assignment]

try:
    from app.ml import supervised as supervised_module
except Exception:  # pragma: no cover
    supervised_module = None  # type: ignore[assignment]


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

MODEL_SERVICE_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.model_service.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_RECORDS: Final[int] = 10_000
_HARD_MAX_RECORDS: Final[int] = 100_000

_DEFAULT_MAX_FEATURES: Final[int] = 512
_HARD_MAX_FEATURES: Final[int] = 4_096

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_CONTRIBUTIONS: Final[int] = 20
_HARD_MAX_CONTRIBUTIONS: Final[int] = 200

_DEFAULT_MAX_CATALOG_ENTRIES: Final[int] = 1_000
_HARD_MAX_CATALOG_ENTRIES: Final[int] = 10_000

_DEFAULT_MAX_AUDIT_EVENTS: Final[int] = 2_000
_HARD_MAX_AUDIT_EVENTS: Final[int] = 20_000

_DEFAULT_REVIEW_THRESHOLD: Final[float] = 0.60
_DEFAULT_MAX_LATENCY_MS: Final[int] = 15_000
_HARD_MAX_LATENCY_MS: Final[int] = 300_000

_DEFAULT_MIN_TRAIN_SAMPLES: Final[int] = 20
_DEFAULT_MIN_VALIDATION_SAMPLES: Final[int] = 5
_DEFAULT_MIN_TEST_SAMPLES: Final[int] = 5
_DEFAULT_MIN_CLASS_SUPPORT: Final[int] = 3
_DEFAULT_MAX_CLASS_IMBALANCE: Final[float] = 100.0

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_SUBJECT_HASH_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

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
    }
)

_MODEL_SERVICE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML model service orchestration only. Do not use with real customer data.",
    "Model, anomaly, and fallback scores are investigative prioritization signals, not probabilities of guilt.",
    "Feature contributions are operational attributions only and are not causal proof.",
    "Model service outputs must not trigger automatic adverse customer action.",
    "Labels must never be used as features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Unavailable scores are reported honestly as unavailable rather than invented.",
    "The bundled model catalog is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_MODEL_SERVICE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_model_service": True,
        "bounded_model_service_required": True,
        "scores_are_investigative_priority_only": True,
        "contributions_are_not_causal_proof": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class ServiceMode(str, Enum):
    """
    Model service operating mode.
    """

    AUTO = "auto"
    SUPERVISED = "supervised"
    ANOMALY = "anomaly"
    FALLBACK = "fallback"
    HYBRID = "hybrid"


class LifecycleStatus(str, Enum):
    """
    Process-local model lifecycle status.

    Status changes are operational metadata only. This module does not deploy or
    serve production models.
    """

    DRAFT = "DRAFT"
    TRAINED = "TRAINED"
    EVALUATED = "EVALUATED"
    CANDIDATE = "CANDIDATE"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class DecisionSource(str, Enum):
    """
    Source of an inference score.
    """

    SUPERVISED_MODEL = "supervised_model"
    ANOMALY_MODEL = "anomaly_model"
    FALLBACK_HEURISTIC = "fallback_heuristic"
    HYBRID_ENSEMBLE = "hybrid_ensemble"
    UNAVAILABLE = "unavailable"


class HealthStatus(str, Enum):
    """
    Service health status.
    """

    OK = "OK"
    DEGRADED = "DEGRADED"
    BLOCKED = "BLOCKED"
    DISABLED = "DISABLED"
    ERROR = "ERROR"


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
            if not key:
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
    return default


def _parse_float_mapping(value: Any) -> dict[str, float]:
    if value is None:
        return {}
    out: dict[str, float] = {}
    if isinstance(value, Mapping):
        for raw_key, raw_value in value.items():
            key = _normalize_token(raw_key)
            numeric = _coerce_optional_float(raw_value, allow_bool=True)
            if key and numeric is not None and numeric > 0:
                out[key] = _round6(numeric)
        return out
    for part in _csv(value):
        if "=" not in part:
            continue
        raw_key, raw_value = part.split("=", 1)
        key = _normalize_token(raw_key)
        numeric = _coerce_optional_float(raw_value, allow_bool=True)
        if key and numeric is not None and numeric > 0:
            out[key] = _round6(numeric)
    return out


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


def _subject_hash(value: Any, options: "ModelServiceOptions") -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)
    if not text:
        return None
    if _is_safe_hash(text):
        return text.lower()
    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.model_service.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _fingerprint_payload(payload: Any) -> str:
    try:
        return _sha256_hex(_canonical_json(payload))
    except Exception:
        return _sha256_hex(str(payload))


def _append_issue(
    issues: list["ServiceIssue"],
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
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _risk_band(score: Optional[float], thresholds: Mapping[str, float]) -> str:
    if score is None:
        return "UNKNOWN"
    value = _clip_float(score, 0.0, 1.0, 0.0)
    critical = _clip_float(thresholds.get("critical", 0.90), 0.0, 1.0, 0.90)
    high = _clip_float(thresholds.get("high", 0.75), 0.0, 1.0, 0.75)
    medium = _clip_float(thresholds.get("medium", 0.55), 0.0, 1.0, 0.55)
    low = _clip_float(thresholds.get("low", 0.35), 0.0, 1.0, 0.35)
    if value >= critical:
        return "CRITICAL"
    if value >= high:
        return "HIGH"
    if value >= medium:
        return "MEDIUM"
    if value >= low:
        return "LOW"
    return "LOW"


def _merge_options(base: Any, *overrides: Optional[Mapping[str, Any]]) -> Any:
    merged: dict[str, Any] = {}
    for override in overrides:
        if isinstance(override, Mapping):
            merged.update(override)
    if not merged:
        return base
    kwargs = {key: value for key, value in merged.items() if hasattr(base, key)}
    if not kwargs:
        return base
    try:
        return replace(base, **kwargs)
    except Exception:
        return base


def _module_available(module: Any, *names: str) -> bool:
    if module is None:
        return False
    return all(hasattr(module, name) for name in names)


# -----------------------------------------------------------------------------
# Issue and catalog models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ServiceIssue:
    """
    Safe model-service issue.
    """

    severity: IssueSeverity
    code: str
    message: str
    field: Optional[str] = None
    details: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "severity": self.severity.value,
            "code": _clean_text(self.code, 100),
            "message": _clean_text(self.message, 300),
        }
        if self.field:
            payload["field"] = _clean_text(self.field, 200)
        if self.details:
            payload["details"] = self.details
        return payload


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """
    Bounded process-local audit event.

    Audit events never contain raw feature values, raw labels, raw narratives,
    raw identifiers, secrets, tokens, passwords, database URLs, filesystem paths,
    or model artifact paths.
    """

    event_id: str
    occurred_at: datetime
    actor: str
    action: str
    model_id: Optional[str] = None
    status: Optional[str] = None
    details: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "occurred_at", _ensure_utc(self.occurred_at) or _now_utc())
        object.__setattr__(self, "actor", _clean_text(self.actor, 128) or "model_service")
        object.__setattr__(self, "action", _clean_text(self.action, 100))
        object.__setattr__(
            self,
            "model_id",
            _clean_text(self.model_id, 128) if self.model_id else None,
        )
        object.__setattr__(
            self,
            "status",
            _clean_text(self.status, 32) if self.status else None,
        )
        object.__setattr__(self, "details", MappingProxyType(_safe_detail_value(self.details) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "occurred_at": self.occurred_at.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "model_id": self.model_id,
            "status": self.status,
            "details": _safe_detail_value(self.details),
        }


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ModelServiceOptions:
    """
    Bounded model-service orchestration policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    mode: ServiceMode | str = ServiceMode.AUTO
    allow_fallback: bool = True
    auto_activate: bool = False

    require_evaluation_for_candidate: bool = True
    min_train_samples: int = _DEFAULT_MIN_TRAIN_SAMPLES
    min_validation_samples: int = _DEFAULT_MIN_VALIDATION_SAMPLES
    min_test_samples: int = _DEFAULT_MIN_TEST_SAMPLES
    min_class_support: int = _DEFAULT_MIN_CLASS_SUPPORT
    max_class_imbalance_ratio: float = _DEFAULT_MAX_CLASS_IMBALANCE
    min_roc_auc: float = 0.0

    review_threshold: float = _DEFAULT_REVIEW_THRESHOLD
    risk_thresholds: Mapping[str, float] = dataclass_field(
        default_factory=lambda: {
            "low": 0.35,
            "medium": 0.55,
            "high": 0.75,
            "critical": 0.90,
        }
    )
    hybrid_weights: Mapping[str, float] = dataclass_field(
        default_factory=lambda: {
            "supervised": 0.50,
            "anomaly": 0.30,
            "fallback": 0.20,
        }
    )

    max_records: int = _DEFAULT_MAX_RECORDS
    max_features: int = _DEFAULT_MAX_FEATURES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_contributions: int = _DEFAULT_MAX_CONTRIBUTIONS
    max_catalog_entries: int = _DEFAULT_MAX_CATALOG_ENTRIES
    max_audit_events: int = _DEFAULT_MAX_AUDIT_EVENTS
    max_latency_ms: int = _DEFAULT_MAX_LATENCY_MS

    label_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    split_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    preprocess_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    supervised_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    anomaly_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fallback_options: Mapping[str, Any] = dataclass_field(default_factory=dict)

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
            _normalize_enum_option(ServiceMode, self.mode, ServiceMode.AUTO),
        )
        object.__setattr__(self, "allow_fallback", _as_bool(self.allow_fallback, True))
        object.__setattr__(self, "auto_activate", _as_bool(self.auto_activate, False))
        object.__setattr__(
            self,
            "require_evaluation_for_candidate",
            _as_bool(self.require_evaluation_for_candidate, True),
        )

        object.__setattr__(
            self,
            "min_train_samples",
            max(0, _as_int(self.min_train_samples, _DEFAULT_MIN_TRAIN_SAMPLES)),
        )
        object.__setattr__(
            self,
            "min_validation_samples",
            max(0, _as_int(self.min_validation_samples, _DEFAULT_MIN_VALIDATION_SAMPLES)),
        )
        object.__setattr__(
            self,
            "min_test_samples",
            max(0, _as_int(self.min_test_samples, _DEFAULT_MIN_TEST_SAMPLES)),
        )
        object.__setattr__(
            self,
            "min_class_support",
            max(0, _as_int(self.min_class_support, _DEFAULT_MIN_CLASS_SUPPORT)),
        )
        object.__setattr__(
            self,
            "max_class_imbalance_ratio",
            max(1.0, _as_float(self.max_class_imbalance_ratio, _DEFAULT_MAX_CLASS_IMBALANCE)),
        )
        object.__setattr__(
            self,
            "min_roc_auc",
            _clamp_float(self.min_roc_auc, 0.0, 1.0, 0.0),
        )

        object.__setattr__(
            self,
            "review_threshold",
            _clamp_float(self.review_threshold, 0.0, 1.0, _DEFAULT_REVIEW_THRESHOLD),
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
                    "low": round(low, 6),
                    "medium": round(medium, 6),
                    "high": round(high, 6),
                    "critical": round(critical, 6),
                }
            ),
        )

        object.__setattr__(
            self,
            "hybrid_weights",
            MappingProxyType(_parse_float_mapping(self.hybrid_weights) or {"supervised": 1.0}),
        )

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
            "max_contributions",
            _clamp_int(
                self.max_contributions,
                1,
                _HARD_MAX_CONTRIBUTIONS,
                _DEFAULT_MAX_CONTRIBUTIONS,
            ),
        )
        object.__setattr__(
            self,
            "max_catalog_entries",
            _clamp_int(
                self.max_catalog_entries,
                1,
                _HARD_MAX_CATALOG_ENTRIES,
                _DEFAULT_MAX_CATALOG_ENTRIES,
            ),
        )
        object.__setattr__(
            self,
            "max_audit_events",
            _clamp_int(
                self.max_audit_events,
                1,
                _HARD_MAX_AUDIT_EVENTS,
                _DEFAULT_MAX_AUDIT_EVENTS,
            ),
        )
        object.__setattr__(
            self,
            "max_latency_ms",
            _clamp_int(self.max_latency_ms, 100, _HARD_MAX_LATENCY_MS, _DEFAULT_MAX_LATENCY_MS),
        )

        object.__setattr__(self, "label_options", MappingProxyType(_safe_detail_value(self.label_options) or {}))
        object.__setattr__(self, "split_options", MappingProxyType(_safe_detail_value(self.split_options) or {}))
        object.__setattr__(self, "preprocess_options", MappingProxyType(_safe_detail_value(self.preprocess_options) or {}))
        object.__setattr__(self, "supervised_options", MappingProxyType(_safe_detail_value(self.supervised_options) or {}))
        object.__setattr__(self, "anomaly_options", MappingProxyType(_safe_detail_value(self.anomaly_options) or {}))
        object.__setattr__(self, "fallback_options", MappingProxyType(_safe_detail_value(self.fallback_options) or {}))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ModelServiceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_MODEL_SERVICE_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_MODEL_SERVICE_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_MODEL_SERVICE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_MODEL_SERVICE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_MODEL_SERVICE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_MODEL_SERVICE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            mode=str(_setting(settings, "ML_MODEL_SERVICE_MODE", ServiceMode.AUTO.value)),
            allow_fallback=_as_bool(_setting(settings, "ML_MODEL_SERVICE_ALLOW_FALLBACK", True), True),
            auto_activate=_as_bool(_setting(settings, "ML_MODEL_SERVICE_AUTO_ACTIVATE", False), False),
            require_evaluation_for_candidate=_as_bool(
                _setting(settings, "ML_MODEL_SERVICE_REQUIRE_EVALUATION_FOR_CANDIDATE", True),
                True,
            ),
            min_train_samples=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MIN_TRAIN_SAMPLES", _DEFAULT_MIN_TRAIN_SAMPLES),
                _DEFAULT_MIN_TRAIN_SAMPLES,
            ),
            min_validation_samples=_as_int(
                _setting(
                    settings,
                    "ML_MODEL_SERVICE_MIN_VALIDATION_SAMPLES",
                    _DEFAULT_MIN_VALIDATION_SAMPLES,
                ),
                _DEFAULT_MIN_VALIDATION_SAMPLES,
            ),
            min_test_samples=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MIN_TEST_SAMPLES", _DEFAULT_MIN_TEST_SAMPLES),
                _DEFAULT_MIN_TEST_SAMPLES,
            ),
            min_class_support=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MIN_CLASS_SUPPORT", _DEFAULT_MIN_CLASS_SUPPORT),
                _DEFAULT_MIN_CLASS_SUPPORT,
            ),
            max_class_imbalance_ratio=_as_float(
                _setting(
                    settings,
                    "ML_MODEL_SERVICE_MAX_CLASS_IMBALANCE_RATIO",
                    _DEFAULT_MAX_CLASS_IMBALANCE,
                ),
                _DEFAULT_MAX_CLASS_IMBALANCE,
            ),
            min_roc_auc=_as_float(_setting(settings, "ML_MODEL_SERVICE_MIN_ROC_AUC", 0.0), 0.0),
            review_threshold=_as_float(
                _setting(settings, "ML_MODEL_SERVICE_REVIEW_THRESHOLD", _DEFAULT_REVIEW_THRESHOLD),
                _DEFAULT_REVIEW_THRESHOLD,
            ),
            risk_thresholds={
                "low": _as_float(_setting(settings, "ML_MODEL_SERVICE_RISK_LOW", 0.35), 0.35),
                "medium": _as_float(_setting(settings, "ML_MODEL_SERVICE_RISK_MEDIUM", 0.55), 0.55),
                "high": _as_float(_setting(settings, "ML_MODEL_SERVICE_RISK_HIGH", 0.75), 0.75),
                "critical": _as_float(_setting(settings, "ML_MODEL_SERVICE_RISK_CRITICAL", 0.90), 0.90),
            },
            hybrid_weights=_parse_float_mapping(
                _setting(
                    settings,
                    "ML_MODEL_SERVICE_HYBRID_WEIGHTS",
                    "supervised=0.50,anomaly=0.30,fallback=0.20",
                )
            ),
            max_records=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MAX_RECORDS", _DEFAULT_MAX_RECORDS),
                _DEFAULT_MAX_RECORDS,
            ),
            max_features=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MAX_FEATURES", _DEFAULT_MAX_FEATURES),
                _DEFAULT_MAX_FEATURES,
            ),
            max_issues=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_contributions=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MAX_CONTRIBUTIONS", _DEFAULT_MAX_CONTRIBUTIONS),
                _DEFAULT_MAX_CONTRIBUTIONS,
            ),
            max_catalog_entries=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MAX_CATALOG_ENTRIES", _DEFAULT_MAX_CATALOG_ENTRIES),
                _DEFAULT_MAX_CATALOG_ENTRIES,
            ),
            max_audit_events=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MAX_AUDIT_EVENTS", _DEFAULT_MAX_AUDIT_EVENTS),
                _DEFAULT_MAX_AUDIT_EVENTS,
            ),
            max_latency_ms=_as_int(
                _setting(settings, "ML_MODEL_SERVICE_MAX_LATENCY_MS", _DEFAULT_MAX_LATENCY_MS),
                _DEFAULT_MAX_LATENCY_MS,
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
            "mode": self.mode.value if isinstance(self.mode, ServiceMode) else str(self.mode),
            "allow_fallback": self.allow_fallback,
            "auto_activate": self.auto_activate,
            "governance": {
                "require_evaluation_for_candidate": self.require_evaluation_for_candidate,
                "min_train_samples": self.min_train_samples,
                "min_validation_samples": self.min_validation_samples,
                "min_test_samples": self.min_test_samples,
                "min_class_support": self.min_class_support,
                "max_class_imbalance_ratio": round(self.max_class_imbalance_ratio, 6),
                "min_roc_auc": round(self.min_roc_auc, 6),
            },
            "thresholds": {
                "review_threshold": round(self.review_threshold, 6),
                "risk_thresholds": dict(self.risk_thresholds),
                "hybrid_weights": dict(self.hybrid_weights),
            },
            "limits": {
                "max_records": self.max_records,
                "max_features": self.max_features,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_contributions": self.max_contributions,
                "max_catalog_entries": self.max_catalog_entries,
                "max_audit_events": self.max_audit_events,
                "max_latency_ms": self.max_latency_ms,
            },
            "submodule_override_keys": {
                "label_options": sorted(self.label_options),
                "split_options": sorted(self.split_options),
                "preprocess_options": sorted(self.preprocess_options),
                "supervised_options": sorted(self.supervised_options),
                "anomaly_options": sorted(self.anomaly_options),
                "fallback_options": sorted(self.fallback_options),
            },
        }


# -----------------------------------------------------------------------------
# Request/result models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class TrainingRequest:
    """
    Bounded training request.
    """

    features: Any = None
    labels: Any = None
    mode: ServiceMode | str | None = None
    feature_names: Optional[Sequence[str]] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    observation_time: Optional[datetime] = None
    tags: tuple[str, ...] = ()
    label_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    split_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    preprocess_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    supervised_options: Mapping[str, Any] = dataclass_field(default_factory=dict)
    anomaly_options: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "mode",
            _normalize_enum_option(ServiceMode, self.mode, None) if self.mode is not None else None,
        )
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})
        object.__setattr__(self, "observation_time", _ensure_utc(self.observation_time))
        object.__setattr__(
            self,
            "tags",
            tuple(
                dict.fromkeys(
                    _clean_text(tag, 100)
                    for tag in (self.tags or ())
                    if _clean_text(tag, 100)
                )
            ),
        )
        object.__setattr__(self, "label_options", _safe_detail_value(self.label_options) or {})
        object.__setattr__(self, "split_options", _safe_detail_value(self.split_options) or {})
        object.__setattr__(self, "preprocess_options", _safe_detail_value(self.preprocess_options) or {})
        object.__setattr__(self, "supervised_options", _safe_detail_value(self.supervised_options) or {})
        object.__setattr__(self, "anomaly_options", _safe_detail_value(self.anomaly_options) or {})


@dataclass(slots=True)
class TrainingResult:
    """
    Safe training result.
    """

    ok: bool = True
    model_id: str = ""
    kind: str = "none"
    status: LifecycleStatus = LifecycleStatus.DRAFT
    metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    governance: Mapping[str, Any] = dataclass_field(default_factory=dict)
    split_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    preprocessing_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    issues: tuple[ServiceIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", _normalize_enum_option(LifecycleStatus, self.status, LifecycleStatus.DRAFT))
        object.__setattr__(self, "metrics", _safe_detail_value(self.metrics) or {})
        object.__setattr__(self, "governance", _safe_detail_value(self.governance) or {})
        object.__setattr__(self, "split_summary", _safe_detail_value(self.split_summary) or {})
        object.__setattr__(self, "preprocessing_summary", _safe_detail_value(self.preprocessing_summary) or {})
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})
        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": MODEL_SERVICE_VERSION,
                        "ok": self.ok,
                        "model_id": self.model_id,
                        "kind": self.kind,
                        "status": self.status.value,
                        "metrics": self.metrics,
                        "governance": self.governance,
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "model_id": self.model_id,
            "kind": self.kind,
            "status": self.status.value,
            "metrics": _safe_detail_value(self.metrics),
            "governance": _safe_detail_value(self.governance),
            "split_summary": _safe_detail_value(self.split_summary),
            "preprocessing_summary": _safe_detail_value(self.preprocessing_summary),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_MODEL_SERVICE_CAVEATS),
            "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
        }


@dataclass(slots=True)
class InferenceRequest:
    """
    Bounded inference request.
    """

    records: Any = None
    model_id: Optional[str] = None
    mode: ServiceMode | str | None = None
    threshold: Optional[float] = None
    include_contributions: bool = True
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fallback_options: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "mode",
            _normalize_enum_option(ServiceMode, self.mode, None) if self.mode is not None else None,
        )
        object.__setattr__(
            self,
            "model_id",
            _clean_text(self.model_id, 128) if self.model_id else None,
        )
        if self.threshold is not None:
            object.__setattr__(self, "threshold", _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_REVIEW_THRESHOLD))
        object.__setattr__(self, "include_contributions", _as_bool(self.include_contributions, True))
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})
        object.__setattr__(self, "fallback_options", _safe_detail_value(self.fallback_options) or {})


@dataclass(frozen=True, slots=True)
class InferenceRecord:
    """
    One inference record.

    Scores are investigative prioritization outputs only.
    """

    subject_ref_hash: Optional[str] = None
    score: Optional[float] = None
    risk_band: str = "UNKNOWN"
    review_recommended: bool = False
    decision_source: DecisionSource | str = DecisionSource.UNAVAILABLE
    components: Mapping[str, float] = dataclass_field(default_factory=dict)
    contributions: tuple[dict[str, Any], ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "subject_ref_hash",
            _clean_text(self.subject_ref_hash, _MAX_SUBJECT_HASH_LENGTH).lower()
            if self.subject_ref_hash
            else None,
        )
        if self.score is not None:
            object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "risk_band", _clean_text(self.risk_band, 32) or "UNKNOWN")
        object.__setattr__(self, "review_recommended", _as_bool(self.review_recommended, False))
        object.__setattr__(
            self,
            "decision_source",
            _normalize_enum_option(DecisionSource, self.decision_source, DecisionSource.UNAVAILABLE),
        )
        object.__setattr__(
            self,
            "components",
            MappingProxyType(
                {
                    _clean_text(key, 100): _round6(_clip_float(_coerce_optional_float(value, allow_bool=True), 0.0, 1.0, 0.0))
                    for key, value in (self.components or {}).items()
                    if _coerce_optional_float(value, allow_bool=True) is not None
                }
            ),
        )
        object.__setattr__(self, "contributions", tuple(self.contributions or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_ref_hash": self.subject_ref_hash,
            "score": float(self.score) if self.score is not None else None,
            "risk_band": self.risk_band,
            "review_recommended": bool(self.review_recommended),
            "decision_source": (
                self.decision_source.value
                if isinstance(self.decision_source, DecisionSource)
                else str(self.decision_source)
            ),
            "components": dict(self.components),
            "contributions": [dict(item) for item in self.contributions],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_MODEL_SERVICE_CAVEATS),
            "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
        }


@dataclass(slots=True)
class InferenceResponse:
    """
    Safe inference response.
    """

    ok: bool = True
    model_id: str = ""
    mode: ServiceMode = ServiceMode.AUTO
    decision_source: DecisionSource = DecisionSource.UNAVAILABLE
    records: tuple[InferenceRecord, ...] = ()
    counts: dict[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[ServiceIssue, ...] = ()
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _normalize_enum_option(ServiceMode, self.mode, ServiceMode.AUTO))
        object.__setattr__(
            self,
            "decision_source",
            _normalize_enum_option(DecisionSource, self.decision_source, DecisionSource.UNAVAILABLE),
        )
        object.__setattr__(self, "records", tuple(self.records or ()))
        object.__setattr__(self, "counts", dict(self.counts or {}))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", _safe_detail_value(self.metadata) or {})
        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": MODEL_SERVICE_VERSION,
                        "model_id": self.model_id,
                        "mode": self.mode.value,
                        "decision_source": self.decision_source.value,
                        "counts": self.counts,
                        "scores": [record.score for record in self.records],
                        "bands": [record.risk_band for record in self.records],
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "model_id": self.model_id,
            "mode": self.mode.value,
            "decision_source": self.decision_source.value,
            "counts": dict(self.counts),
            "records": [record.to_dict() for record in self.records],
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_MODEL_SERVICE_CAVEATS),
            "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
        }


@dataclass(slots=True)
class ServiceHealth:
    """
    Safe service health summary.
    """

    status: HealthStatus = HealthStatus.OK
    enabled: bool = True
    mode: ServiceMode = ServiceMode.AUTO
    modules: Mapping[str, bool] = dataclass_field(default_factory=dict)
    catalog: Mapping[str, Any] = dataclass_field(default_factory=dict)
    active_models: tuple[dict[str, Any], ...] = ()
    limits: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[ServiceIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", _normalize_enum_option(HealthStatus, self.status, HealthStatus.OK))
        object.__setattr__(self, "mode", _normalize_enum_option(ServiceMode, self.mode, ServiceMode.AUTO))
        object.__setattr__(self, "modules", MappingProxyType(dict(self.modules or {})))
        object.__setattr__(self, "catalog", MappingProxyType(_safe_detail_value(self.catalog) or {}))
        object.__setattr__(self, "active_models", tuple(self.active_models or ()))
        object.__setattr__(self, "limits", MappingProxyType(dict(self.limits or {})))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "enabled": bool(self.enabled),
            "mode": self.mode.value,
            "modules": dict(self.modules),
            "catalog": _safe_detail_value(self.catalog),
            "active_models": list(self.active_models),
            "limits": dict(self.limits),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_MODEL_SERVICE_CAVEATS),
            "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Internal raw matrix fallback
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _RawRow:
    subject_ref_hash: Optional[str] = None
    values: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(self.values or {})))


@dataclass(frozen=True, slots=True)
class _RawMatrix:
    feature_names: tuple[str, ...] = ()
    rows: tuple[_RawRow, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "feature_names",
            tuple(_canonical_field_name(name) for name in (self.feature_names or ()) if _canonical_field_name(name)),
        )
        object.__setattr__(self, "rows", tuple(self.rows or ()))


# -----------------------------------------------------------------------------
# Catalog entry
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class ModelCatalogEntry:
    """
    Process-local bounded model catalog entry.

    Internal model objects are not exposed in public summaries.
    """

    model_id: str
    kind: str
    status: LifecycleStatus
    created_at: datetime
    updated_at: datetime
    fingerprint: str
    tags: tuple[str, ...] = ()
    metrics_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    governance: Mapping[str, Any] = dataclass_field(default_factory=dict)
    split_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    preprocessing_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    label_summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    supervised_model: Any = None
    anomaly_model: Any = None
    preprocessor: Any = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_id", _clean_text(self.model_id, 128))
        object.__setattr__(self, "kind", _normalize_token(self.kind) or "none")
        object.__setattr__(self, "status", _normalize_enum_option(LifecycleStatus, self.status, LifecycleStatus.DRAFT))
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())
        object.__setattr__(self, "updated_at", _ensure_utc(self.updated_at) or _now_utc())
        object.__setattr__(self, "fingerprint", _clean_text(self.fingerprint, 128))
        object.__setattr__(
            self,
            "tags",
            tuple(dict.fromkeys(_clean_text(tag, 100) for tag in (self.tags or ()) if _clean_text(tag, 100))),
        )
        object.__setattr__(self, "metrics_summary", MappingProxyType(_safe_detail_value(self.metrics_summary) or {}))
        object.__setattr__(self, "governance", MappingProxyType(_safe_detail_value(self.governance) or {}))
        object.__setattr__(self, "split_summary", MappingProxyType(_safe_detail_value(self.split_summary) or {}))
        object.__setattr__(
            self,
            "preprocessing_summary",
            MappingProxyType(_safe_detail_value(self.preprocessing_summary) or {}),
        )
        object.__setattr__(self, "label_summary", MappingProxyType(_safe_detail_value(self.label_summary) or {}))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "kind": self.kind,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "fingerprint": self.fingerprint,
            "tags": list(self.tags),
            "metrics_summary": _safe_detail_value(self.metrics_summary),
            "governance": _safe_detail_value(self.governance),
            "split_summary": _safe_detail_value(self.split_summary),
            "preprocessing_summary": _safe_detail_value(self.preprocessing_summary),
            "label_summary": _safe_detail_value(self.label_summary),
            "metadata": _safe_detail_value(self.metadata),
            "has_supervised_model": self.supervised_model is not None,
            "has_anomaly_model": self.anomaly_model is not None,
            "has_preprocessor": self.preprocessor is not None,
            "caveats": list(_MODEL_SERVICE_CAVEATS),
            "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Input helpers
# -----------------------------------------------------------------------------


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []
    if isinstance(data, (TrainingResult, InferenceResponse, ServiceHealth)):
        return []
    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "examples", "vectors", "features"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])
        if "feature_names" in data and "rows" in data:
            return _as_sequence(data["rows"])
        return [data]
    if hasattr(data, "feature_names") and hasattr(data, "rows"):
        return _as_sequence(data.rows)
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray, memoryview)):
        return list(data)
    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]
    return [data]


def _extract_subject(record: Any, options: ModelServiceOptions) -> Optional[str]:
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


def _prepared_record(record: Any, options: ModelServiceOptions) -> dict[str, Any]:
    subject = _extract_subject(record, options)
    features = _extract_feature_mapping(record)
    out: dict[str, Any] = {"features": features}
    if subject:
        out["subject_ref_hash"] = subject
    return out


def _matrix_from_raw(records: Sequence[Mapping[str, Any]], feature_names: Optional[Sequence[str]] = None) -> _RawMatrix:
    if feature_names is not None:
        names = tuple(
            dict.fromkeys(
                _canonical_field_name(name)
                for name in feature_names
                if _canonical_field_name(name)
            )
        )
    else:
        observed: set[str] = set()
        for record in records:
            features = record.get("features") if isinstance(record, Mapping) else {}
            if isinstance(features, Mapping):
                observed.update(_canonical_field_name(key) for key in features if _canonical_field_name(key))
        names = tuple(sorted(observed))

    rows: list[_RawRow] = []
    for record in records:
        features = record.get("features") if isinstance(record, Mapping) else {}
        if not isinstance(features, Mapping):
            features = {}
        values = {name: features.get(name) for name in names}
        rows.append(
            _RawRow(
                subject_ref_hash=record.get("subject_ref_hash") if isinstance(record, Mapping) else None,
                values=values,
            )
        )
    return _RawMatrix(feature_names=names, rows=tuple(rows))


def _matrix_feature_names(matrix: Any) -> tuple[str, ...]:
    names = getattr(matrix, "feature_names", ()) or ()
    return tuple(_canonical_field_name(name) for name in names if _canonical_field_name(name))


def _matrix_rows(matrix: Any) -> tuple[Any, ...]:
    return tuple(getattr(matrix, "rows", ()) or ())


# -----------------------------------------------------------------------------
# Label/split helpers
# -----------------------------------------------------------------------------


def _resolve_label_set(
    labels: Any,
    options: ModelServiceOptions,
    request_label_options: Mapping[str, Any],
    issues: list[ServiceIssue],
) -> Any:
    if labels is None:
        return None

    if labels_module is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="labels_module_unavailable",
            message="Labels module is unavailable; supervised training cannot proceed.",
        )
        return None

    if hasattr(labels_module, "LabelSet") and isinstance(labels, labels_module.LabelSet):
        return labels

    label_opts = None
    if hasattr(labels_module, "LabelOptions"):
        label_opts = _merge_options(
            labels_module.LabelOptions.from_settings(),
            options.label_options,
            request_label_options,
        )

    if hasattr(labels_module, "label_set_from_records"):
        try:
            return labels_module.label_set_from_records(labels, options=label_opts)
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="label_set_construction_failed",
                message="Label set construction failed.",
                details={"exception_type": type(exc).__name__},
            )
            return None

    if hasattr(labels_module, "build_synthetic_labels"):
        try:
            return labels_module.build_synthetic_labels(label_records=labels, options=label_opts)
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="label_set_construction_failed",
                message="Label set construction failed.",
                details={"exception_type": type(exc).__name__},
            )
            return None

    _append_issue(
        issues,
        options.max_issues,
        severity=IssueSeverity.ERROR,
        code="label_set_api_unavailable",
        message="Labels module does not expose a supported label-set constructor.",
    )
    return None


def _label_maps(label_set: Any) -> tuple[dict[str, int], dict[str, float], dict[str, str]]:
    label_map: dict[str, int] = {}
    weight_map: dict[str, float] = {}
    split_map: dict[str, str] = {}

    if label_set is None:
        return label_map, weight_map, split_map

    subjects = tuple(getattr(label_set, "subject_hashes", ()) or ())
    codes = tuple(getattr(label_set, "label_codes", ()) or ())
    weights = tuple(getattr(label_set, "weights", ()) or ())
    splits = tuple(getattr(label_set, "splits", ()) or ())

    for index, subject in enumerate(subjects):
        text = _clean_text(subject, _MAX_SUBJECT_HASH_LENGTH).lower()
        if not text:
            continue
        if index < len(codes) and codes[index] is not None:
            label_map[text] = int(codes[index])
        if index < len(weights) and weights[index] is not None:
            weight_map[text] = _clip_float(_coerce_optional_float(weights[index], allow_bool=True), 0.0, 100.0, 1.0)
        if index < len(splits) and splits[index] is not None:
            split_map[text] = _normalize_token(splits[index]) or "train"

    return label_map, weight_map, split_map


def _build_training_splits(
    feature_records: Sequence[Any],
    label_set: Any,
    split_plan: Any,
    options: ModelServiceOptions,
    issues: list[ServiceIssue],
    require_labels: bool,
) -> dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]]:
    feature_map: dict[str, dict[str, Any]] = {}

    for index, record in enumerate(feature_records):
        subject = _extract_subject(record, options)
        if not subject:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="missing_subject_reference",
                message="Feature record missing subject reference and was skipped.",
                details={"index": index},
            )
            continue
        if subject in feature_map:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="duplicate_subject_reference",
                message="Duplicate subject reference in feature input and later occurrence was skipped.",
                details={"index": index},
            )
            continue
        feature_map[subject] = _extract_feature_mapping(record)

    label_map, weight_map, _split_map = _label_maps(label_set)

    buckets: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {
        "train": ([], []),
        "validation": ([], []),
        "test": ([], []),
    }

    if split_plan is not None and hasattr(split_plan, "partitions"):
        partitions = split_plan.partitions()
        for split_name, items in partitions.items():
            normalized_split = _normalize_token(split_name) or "train"
            if normalized_split not in buckets:
                normalized_split = "train"
            records, metas = buckets[normalized_split]
            for item in items:
                subject = _clean_text(getattr(item, "subject_ref_hash", None), _MAX_SUBJECT_HASH_LENGTH).lower()
                if not subject:
                    continue
                features = feature_map.get(subject)
                if features is None:
                    _append_issue(
                        issues,
                        options.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="split_subject_missing_features",
                        message="Split item subject was missing from feature input.",
                        details={"split": normalized_split},
                    )
                    continue
                label = getattr(item, "label_code", None)
                if label is None:
                    label = label_map.get(subject)
                if require_labels and label is None:
                    _append_issue(
                        issues,
                        options.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="split_subject_unlabeled",
                        message="Split item subject was unlabeled and was skipped for supervised training.",
                        details={"split": normalized_split},
                    )
                    continue
                weight = getattr(item, "weight", None)
                if weight is None:
                    weight = weight_map.get(subject, 1.0)
                records.append({"subject_ref_hash": subject, "features": features})
                metas.append(
                    {
                        "subject_ref_hash": subject,
                        "label_code": int(label) if label is not None else None,
                        "weight": _clip_float(_coerce_optional_float(weight, allow_bool=True), 0.0, 100.0, 1.0),
                        "split": normalized_split,
                    }
                )
        return buckets

    records, metas = buckets["train"]
    if label_map:
        subjects = [subject for subject in feature_map if subject in label_map]
    else:
        subjects = list(feature_map)

    for subject in subjects:
        features = feature_map[subject]
        label = label_map.get(subject)
        if require_labels and label is None:
            continue
        weight = weight_map.get(subject, 1.0)
        records.append({"subject_ref_hash": subject, "features": features})
        metas.append(
            {
                "subject_ref_hash": subject,
                "label_code": int(label) if label is not None else None,
                "weight": _clip_float(_coerce_optional_float(weight, allow_bool=True), 0.0, 100.0, 1.0),
                "split": "train",
            }
        )

    return buckets


def _build_split_plan(
    label_set: Any,
    options: ModelServiceOptions,
    request_split_options: Mapping[str, Any],
    issues: list[ServiceIssue],
) -> Any:
    if label_set is None or splits_module is None:
        return None

    if not hasattr(splits_module, "build_split_plan_from_label_set"):
        return None

    split_opts = None
    if hasattr(splits_module, "SplitOptions"):
        split_opts = _merge_options(
            splits_module.SplitOptions.from_settings(),
            options.split_options,
            request_split_options,
        )

    try:
        return splits_module.build_split_plan_from_label_set(label_set, options=split_opts)
    except Exception as exc:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="split_plan_construction_failed",
            message="Split plan construction failed; falling back to single train split.",
            details={"exception_type": type(exc).__name__},
        )
        return None


def _summarize_split_plan(split_plan: Any, buckets: Mapping[str, tuple[list[Any], list[Any]]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "counts": {
            split: len(records)
            for split, (records, _metas) in buckets.items()
        }
    }
    if split_plan is not None and hasattr(split_plan, "to_public_dict"):
        try:
            summary["plan"] = split_plan.to_public_dict()
        except Exception:
            pass
    return summary


# -----------------------------------------------------------------------------
# Preprocessing/dataset helpers
# -----------------------------------------------------------------------------


def _fit_preprocessor(
    train_records: Sequence[Mapping[str, Any]],
    options: ModelServiceOptions,
    request_preprocess_options: Mapping[str, Any],
    issues: list[ServiceIssue],
) -> Any:
    if preprocessing_module is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="preprocessing_module_unavailable",
            message="Preprocessing module unavailable; using raw bounded matrix fallback.",
        )
        return None

    prep_opts = None
    if hasattr(preprocessing_module, "PreprocessOptions"):
        prep_opts = _merge_options(
            preprocessing_module.PreprocessOptions.from_settings(),
            options.preprocess_options,
            request_preprocess_options,
        )

    try:
        preprocessor = preprocessing_module.Preprocessor(options=prep_opts)
        preprocessor.fit(list(train_records))
        return preprocessor
    except Exception as exc:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="preprocessor_fit_failed",
            message="Preprocessor fit failed; using raw bounded matrix fallback.",
            details={"exception_type": type(exc).__name__},
        )
        return None


def _transform_with_preprocessor(
    preprocessor: Any,
    records: Sequence[Mapping[str, Any]],
    options: ModelServiceOptions,
    stage: Any = None,
) -> Any:
    if preprocessor is None:
        return _matrix_from_raw(records)
    try:
        if stage is not None:
            return preprocessor.transform(list(records), stage=stage)
        return preprocessor.transform(list(records))
    except Exception as exc:
        _append_issue(
            [],
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="preprocessor_transform_failed",
            message="Preprocessor transform failed; using raw bounded matrix fallback.",
            details={"exception_type": type(exc).__name__},
        )
        return _matrix_from_raw(records)


def _build_supervised_dataset(
    parts: Sequence[tuple[Any, Sequence[Mapping[str, Any]]]],
    options: ModelServiceOptions,
    issues: list[ServiceIssue],
) -> Any:
    if supervised_module is None or not hasattr(supervised_module, "TrainingDataset"):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="supervised_module_unavailable",
            message="Supervised module unavailable; supervised dataset cannot be built.",
        )
        return None

    feature_names: tuple[str, ...] = ()
    x: list[tuple[float, ...]] = []
    y: list[int] = []
    weights: list[float] = []
    splits: list[str] = []
    subjects: list[Optional[str]] = []

    for matrix, metas in parts:
        names = _matrix_feature_names(matrix)
        if not feature_names and names:
            feature_names = names
        elif names and names != feature_names:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="matrix_feature_name_mismatch",
                message="Matrix feature names differed; using first non-empty feature name set.",
            )

        rows = _matrix_rows(matrix)
        for index, row in enumerate(rows):
            if index >= len(metas):
                break
            meta = metas[index]
            label = meta.get("label_code")
            if label is None:
                continue
            values = getattr(row, "values", {}) or {}
            row_vector: list[float] = []
            for name in feature_names:
                numeric = _coerce_optional_float(values.get(name), allow_bool=True)
                row_vector.append(_round6(_clip_float(numeric, -1e12, 1e12, 0.0)))
            x.append(tuple(row_vector))
            y.append(int(label))
            weights.append(_clip_float(_coerce_optional_float(meta.get("weight"), allow_bool=True), 0.0, 100.0, 1.0))
            splits.append(_normalize_token(meta.get("split")) or "train")
            subject = meta.get("subject_ref_hash") or getattr(row, "subject_ref_hash", None)
            subjects.append(_clean_text(subject, _MAX_SUBJECT_HASH_LENGTH).lower() if subject else None)

    if not x:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="empty_supervised_dataset",
            message="No labeled rows were available for supervised dataset construction.",
        )
        return None

    classes = tuple(sorted(set(y)))
    counts = {
        "samples": len(x),
        "features": len(feature_names),
        "classes": len(classes),
        "train": sum(1 for split in splits if split == "train"),
        "validation": sum(1 for split in splits if split == "validation"),
        "test": sum(1 for split in splits if split == "test"),
    }

    try:
        return supervised_module.TrainingDataset(
            feature_names=feature_names,
            classes=classes,
            x=tuple(x),
            y=tuple(y),
            weights=tuple(weights),
            splits=tuple(splits),
            subjects=tuple(subjects),
            counts=counts,
            metadata={
                "supervised_version": getattr(supervised_module, "SUPERVISED_VERSION", "v1"),
                "model_service_version": MODEL_SERVICE_VERSION,
                "caveats": list(_MODEL_SERVICE_CAVEATS),
                "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
            },
        )
    except Exception as exc:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="supervised_dataset_construction_failed",
            message="Supervised dataset construction failed.",
            details={"exception_type": type(exc).__name__},
        )
        return None


# -----------------------------------------------------------------------------
# Governance/metrics helpers
# -----------------------------------------------------------------------------


def _metric_summary(supervised_model: Any) -> dict[str, Any]:
    if supervised_model is None:
        return {}

    metrics = getattr(supervised_model, "metrics", {}) or {}
    out: dict[str, Any] = {}
    keys = (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "pr_auc",
        "log_loss",
        "brier_score",
        "expected_calibration_error",
        "macro_f1",
        "weighted_f1",
    )

    for split in ("validation", "test"):
        report = metrics.get(split)
        if not isinstance(report, Mapping):
            continue
        report_metrics = report.get("metrics") if isinstance(report.get("metrics"), Mapping) else {}
        summary = {key: report_metrics.get(key) for key in keys if key in report_metrics}
        summary["counts"] = report.get("counts")
        summary["ok"] = report.get("ok")
        out[split] = _safe_detail_value(summary) or {}

    return out


def _governance_check(
    dataset: Any,
    supervised_model: Any,
    anomaly_model: Any,
    bucket_counts: Mapping[str, int],
    options: ModelServiceOptions,
    issues: list[ServiceIssue],
) -> tuple[bool, dict[str, Any]]:
    ok = True
    details: dict[str, Any] = {"checks": []}

    def check(name: str, passed: bool, message: str, data: Optional[Mapping[str, Any]] = None) -> None:
        nonlocal ok
        details["checks"].append(
            {
                "name": name,
                "passed": bool(passed),
                "message": message,
                "details": _safe_detail_value(data) or {},
            }
        )
        if not passed:
            ok = False

    train_count = int(bucket_counts.get("train", 0))
    val_count = int(bucket_counts.get("validation", 0))
    test_count = int(bucket_counts.get("test", 0))

    if dataset is not None:
        dataset_counts = getattr(dataset, "counts", {}) or {}
        train_count = int(dataset_counts.get("train", train_count))
        val_count = int(dataset_counts.get("validation", val_count))
        test_count = int(dataset_counts.get("test", test_count))

    check(
        "min_train_samples",
        train_count >= options.min_train_samples,
        "Training sample count below configured minimum.",
        {"train_count": train_count, "min_train_samples": options.min_train_samples},
    )

    if options.require_evaluation_for_candidate:
        check(
            "min_validation_samples",
            val_count >= options.min_validation_samples,
            "Validation sample count below configured minimum.",
            {"validation_count": val_count, "min_validation_samples": options.min_validation_samples},
        )
        check(
            "min_test_samples",
            test_count >= options.min_test_samples,
            "Test sample count below configured minimum.",
            {"test_count": test_count, "min_test_samples": options.min_test_samples},
        )

    if dataset is not None:
        classes = tuple(getattr(dataset, "classes", ()) or ())
        y = tuple(getattr(dataset, "y", ()) or ())
        class_counter = Counter(int(code) for code in y)
        check(
            "minimum_classes",
            len(classes) >= 2,
            "Supervised dataset must contain at least two classes.",
            {"class_count": len(classes)},
        )
        if class_counter:
            min_support = min(class_counter.values())
            max_support = max(class_counter.values())
            check(
                "min_class_support",
                min_support >= options.min_class_support,
                "At least one class has insufficient support.",
                {"min_support": min_support, "min_class_support": options.min_class_support},
            )
            imbalance = float(max_support) / float(min_support) if min_support > 0 else 0.0
            check(
                "class_imbalance",
                imbalance <= options.max_class_imbalance_ratio,
                "Class imbalance exceeds configured maximum.",
                {"imbalance_ratio": _round6(imbalance), "max_ratio": options.max_class_imbalance_ratio},
            )

        feature_names = tuple(getattr(dataset, "feature_names", ()) or ())
        if feature_names and labels_module is not None and hasattr(labels_module, "assert_no_label_leakage"):
            try:
                labels_module.assert_no_label_leakage({name: 0 for name in feature_names})
                check("label_leakage_scan", True, "Feature names passed label leakage scan.")
            except Exception as exc:
                check(
                    "label_leakage_scan",
                    False,
                    "Feature names failed label leakage scan.",
                    {"exception_type": type(exc).__name__},
                )

        metrics = _metric_summary(supervised_model)
        if options.min_roc_auc > 0:
            best_auc = None
            for split in ("validation", "test"):
                value = (metrics.get(split) or {}).get("roc_auc")
                numeric = _coerce_optional_float(value, allow_bool=False)
                if numeric is not None and (best_auc is None or numeric > best_auc):
                    best_auc = numeric
            check(
                "min_roc_auc",
                best_auc is not None and float(best_auc) >= options.min_roc_auc,
                "Best available ROC AUC is below configured minimum or unavailable.",
                {"best_roc_auc": best_auc, "min_roc_auc": options.min_roc_auc},
            )

    if anomaly_model is not None:
        fitted = bool(getattr(anomaly_model, "fitted", False))
        check("anomaly_fitted", fitted, "Anomaly model is not fitted.", {"fitted": fitted})

    if supervised_model is None and anomaly_model is None:
        check("model_present", False, "No supervised or anomaly model was produced.")

    details["ok"] = ok
    details["counts"] = {
        "train": train_count,
        "validation": val_count,
        "test": test_count,
    }
    return ok, details


def _preprocessing_summary(preprocessor: Any, matrix: Any, options: ModelServiceOptions) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "available": preprocessor is not None,
        "feature_count": len(_matrix_feature_names(matrix)),
        "row_count": len(_matrix_rows(matrix)),
    }
    if preprocessor is not None and hasattr(preprocessor, "safe_summary"):
        try:
            safe = preprocessor.safe_summary()
            summary["output_feature_count"] = safe.get("output_feature_count")
            summary["selected_feature_count"] = safe.get("selected_feature_count")
            summary["input_feature_count"] = safe.get("input_feature_count")
        except Exception:
            pass
    names = _matrix_feature_names(matrix)
    summary["feature_names_sample"] = list(names[: options.max_summary_items])
    summary["feature_names_truncated"] = len(names) > options.max_summary_items
    return summary


def _label_summary(label_set: Any) -> dict[str, Any]:
    if label_set is None:
        return {"available": False}
    if hasattr(label_set, "to_public_dict"):
        try:
            payload = label_set.to_public_dict()
            payload.pop("records", None)
            return _safe_detail_value(payload) or {}
        except Exception:
            pass
    subjects = tuple(getattr(label_set, "subject_hashes", ()) or ())
    codes = tuple(getattr(label_set, "label_codes", ()) or ())
    counter = Counter(int(code) for code in codes if code is not None)
    return {
        "available": True,
        "subject_count": len(subjects),
        "label_count": len(codes),
        "class_distribution": {
            str(code): float(count) / float(len(codes)) if codes else 0.0
            for code, count in sorted(counter.items())
        },
    }


def _combined_model_id(supervised_model: Any, anomaly_model: Any, metadata: Mapping[str, Any]) -> str:
    parts: list[str] = []
    if supervised_model is not None:
        parts.append(str(getattr(supervised_model, "model_id", "") or getattr(supervised_model, "fingerprint", "")))
    if anomaly_model is not None:
        parts.append(str(getattr(anomaly_model, "model_id", "") or getattr(anomaly_model, "fingerprint", "")))
    if not parts:
        parts.append(_fingerprint_payload(_safe_detail_value(metadata) or {}))
    return _sha256_hex("|".join(parts))[:32]


def _status_from_supervised_model(model: Any) -> LifecycleStatus:
    status = getattr(model, "status", None)
    value = getattr(status, "value", status)
    try:
        return LifecycleStatus(str(value))
    except Exception:
        return LifecycleStatus.TRAINED


# -----------------------------------------------------------------------------
# Contribution merging
# -----------------------------------------------------------------------------


def _merge_contributions(
    sources: Sequence[tuple[str, Sequence[Mapping[str, Any]]]],
    limit: int,
) -> tuple[dict[str, Any], ...]:
    aggregated: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"effect": 0.0, "magnitude": 0.0, "sources": set(), "method": ""}
    )

    for source, contributions in sources:
        for contribution in contributions or ():
            if not isinstance(contribution, Mapping):
                continue
            feature = _clean_text(contribution.get("feature"), 200)
            if not feature:
                continue
            bucket = aggregated[feature]
            effect = _coerce_optional_float(contribution.get("effect"), allow_bool=True)
            if effect is None:
                effect = _coerce_optional_float(contribution.get("contribution"), allow_bool=True) or 0.0
            magnitude = _coerce_optional_float(contribution.get("magnitude"), allow_bool=True) or abs(float(effect))
            bucket["effect"] += float(effect)
            bucket["magnitude"] += float(magnitude)
            bucket["sources"].add(source)
            if not bucket["method"]:
                bucket["method"] = _clean_text(contribution.get("method"), 100)

    if not aggregated:
        return ()

    total_magnitude = sum(float(item["magnitude"]) for item in aggregated.values())
    out: list[dict[str, Any]] = []

    for feature, item in aggregated.items():
        magnitude = float(item["magnitude"])
        normalized = magnitude / total_magnitude if total_magnitude > 0 else 0.0
        effect = float(item["effect"])
        direction = "increase" if effect > 0 else "decrease" if effect < 0 else "neutral"
        out.append(
            {
                "feature": feature,
                "effect": _round6(effect),
                "magnitude": _round6(normalized),
                "direction": direction,
                "method": item["method"] or ",".join(sorted(item["sources"])) or "ensemble",
                "sources": sorted(item["sources"]),
                "interpretation": "operational attribution only, not causal proof",
            }
        )

    out.sort(key=lambda item: (-float(item["magnitude"]), str(item["feature"])))
    return tuple(out[: max(1, int(limit))])


def _combine_hybrid(components: Mapping[str, Optional[float]], weights: Mapping[str, float]) -> Optional[float]:
    total = 0.0
    weight_sum = 0.0
    for source, value in components.items():
        numeric = _coerce_optional_float(value, allow_bool=True)
        if numeric is None:
            continue
        weight = _coerce_optional_float(weights.get(source, 1.0), allow_bool=True) or 0.0
        if weight <= 0:
            continue
        total += _clip_float(numeric, 0.0, 1.0, 0.0) * float(weight)
        weight_sum += float(weight)
    if weight_sum <= 0:
        return None
    return _round6(_clip_float(total / weight_sum, 0.0, 1.0, 0.0))


# -----------------------------------------------------------------------------
# Model service
# -----------------------------------------------------------------------------


class ModelService:
    """
    Bounded deterministic synthetic ML model service.

    This service orchestrates the MULEGUARD ML subsystem:

    - label resolution;
    - split planning;
    - preprocessing;
    - supervised training;
    - anomaly fitting;
    - governance checks;
    - process-local cataloging;
    - promotion/retirement metadata;
    - inference routing;
    - fallback scoring;
    - health and metadata exposure.

    It does not deploy models to production serving infrastructure, does not
    persist data, does not call external systems, and does not take adverse
    action.
    """

    def __init__(self, options: ModelServiceOptions | None = None) -> None:
        self.options = options or ModelServiceOptions.from_settings()
        self._catalog: dict[str, ModelCatalogEntry] = {}
        self._order: list[str] = []
        self._audits: list[AuditEvent] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Internal catalog/audit helpers
    # ------------------------------------------------------------------

    def _audit(
        self,
        action: str,
        model_id: Optional[str] = None,
        status: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> AuditEvent:
        """
        Append one bounded process-local audit event.
        """
        event = AuditEvent(
            event_id=_sha256_hex(
                f"{action}|{model_id or ''}|{time.time_ns()}|{len(self._audits)}"
            )[:32],
            occurred_at=_now_utc(),
            actor="model_service",
            action=action,
            model_id=model_id,
            status=status,
            details=details,
        )

        with self._lock:
            self._audits.append(event)

            if len(self._audits) > self.options.max_audit_events:
                self._audits = self._audits[-self.options.max_audit_events :]

        return event

    def _register_entry(self, entry: ModelCatalogEntry) -> ModelCatalogEntry:
        """
        Register or replace one process-local catalog entry.
        """
        with self._lock:
            if entry.model_id in self._catalog:
                self._catalog[entry.model_id] = entry
                return entry

            self._catalog[entry.model_id] = entry
            self._order.append(entry.model_id)

            if len(self._order) > self.options.max_catalog_entries:
                evict_id = self._order.pop(0)
                self._catalog.pop(evict_id, None)

            return entry

    def _get_entry(self, model_id: Any) -> Optional[ModelCatalogEntry]:
        """
        Return one catalog entry by model id.
        """
        key = _clean_text(model_id, 128)

        with self._lock:
            return self._catalog.get(key)

    def _active_entry(self, mode: ServiceMode) -> Optional[ModelCatalogEntry]:
        """
        Return the most recently registered active entry compatible with mode.
        """
        if mode == ServiceMode.AUTO:
            desired = {"supervised", "anomaly", "hybrid"}
        elif mode == ServiceMode.HYBRID:
            desired = {"hybrid", "supervised", "anomaly"}
        else:
            desired = {mode.value}

        with self._lock:
            for model_id in reversed(self._order):
                entry = self._catalog.get(model_id)

                if entry is None or entry.status != LifecycleStatus.ACTIVE:
                    continue

                if entry.kind not in desired:
                    continue

                if mode == ServiceMode.SUPERVISED and entry.supervised_model is None:
                    continue

                if mode == ServiceMode.ANOMALY and entry.anomaly_model is None:
                    continue

                if (
                    mode == ServiceMode.HYBRID
                    and entry.supervised_model is None
                    and entry.anomaly_model is None
                ):
                    continue

                return entry

        return None

    def _deactivate_others(self, active_id: str, kind: str) -> None:
        """
        Mark other active entries of compatible kinds as retired.

        This is process-local lifecycle metadata only. It does not stop
        production serving because this module does not serve production models.
        """
        with self._lock:
            for model_id, entry in self._catalog.items():
                if model_id == active_id:
                    continue

                if entry.status != LifecycleStatus.ACTIVE:
                    continue

                if kind == "hybrid" and entry.kind not in {"hybrid", "supervised", "anomaly"}:
                    continue

                if kind in {"supervised", "anomaly"} and entry.kind not in {kind, "hybrid"}:
                    continue

                entry.status = LifecycleStatus.RETIRED
                entry.updated_at = _now_utc()

    @staticmethod
    def _entry_feature_names(entry: Optional[ModelCatalogEntry]) -> tuple[str, ...]:
        """
        Return fitted feature names for one catalog entry when available.
        """
        if entry is None:
            return ()

        preprocessor = entry.preprocessor

        if preprocessor is not None:
            names = getattr(preprocessor, "feature_names", None)

            if names:
                return tuple(
                    _canonical_field_name(name)
                    for name in names
                    if _canonical_field_name(name)
                )

        supervised = entry.supervised_model

        if supervised is not None:
            params = getattr(supervised, "parameters", None)
            names = getattr(params, "feature_names", None) if params is not None else None

            if names:
                return tuple(
                    _canonical_field_name(name)
                    for name in names
                    if _canonical_field_name(name)
                )

        anomaly = entry.anomaly_model

        if anomaly is not None:
            names = getattr(anomaly, "feature_names", None)

            if names:
                return tuple(
                    _canonical_field_name(name)
                    for name in names
                    if _canonical_field_name(name)
                )

        summary = entry.preprocessing_summary or {}
        names = summary.get("feature_names_sample")

        if isinstance(names, Sequence) and not summary.get("feature_names_truncated"):
            return tuple(
                _canonical_field_name(name)
                for name in names
                if _canonical_field_name(name)
            )

        return ()

    @staticmethod
    def _resolve_mode(requested: Any, default: Any, labels: Any) -> ServiceMode:
        """
        Resolve service mode.
        """
        default_mode = _normalize_enum_option(ServiceMode, default, ServiceMode.AUTO)
        mode = (
            _normalize_enum_option(ServiceMode, requested, default_mode)
            if requested is not None
            else default_mode
        )

        if mode == ServiceMode.AUTO:
            return ServiceMode.SUPERVISED if labels is not None else ServiceMode.ANOMALY

        return mode

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, request: Any) -> TrainingResult:
        """
        Train or fit one bounded synthetic model and register it locally.
        """
        opts = self.options
        issues: list[ServiceIssue] = []
        start_time = time.monotonic()

        if isinstance(request, TrainingRequest):
            req = request
        elif isinstance(request, Mapping):
            try:
                req = TrainingRequest(**request)
            except Exception as exc:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="invalid_training_request",
                    message="Training request mapping could not be parsed.",
                    details={"exception_type": type(exc).__name__},
                )
                req = TrainingRequest()
        else:
            req = TrainingRequest(features=request)

        mode = self._resolve_mode(req.mode, opts.mode, req.labels)

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="model_service_disabled",
                message="Model service is disabled.",
            )
            return TrainingResult(
                ok=False,
                kind=mode.value,
                status=LifecycleStatus.BLOCKED,
                issues=tuple(issues),
                metadata={"mode": mode.value},
            )

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Model service requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return TrainingResult(
                ok=False,
                kind=mode.value,
                status=LifecycleStatus.BLOCKED,
                issues=tuple(issues),
            )

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Model service training is blocked in production-like environments.",
            )
            return TrainingResult(
                ok=False,
                kind=mode.value,
                status=LifecycleStatus.BLOCKED,
                issues=tuple(issues),
            )

        if mode == ServiceMode.FALLBACK:
            return TrainingResult(
                ok=True,
                kind=mode.value,
                status=LifecycleStatus.DRAFT,
                metadata={"message": "Fallback scoring requires no training."},
                issues=tuple(issues),
            )

        feature_records = _iter_records(req.features)

        if not feature_records:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="empty_feature_input",
                message="Training feature input is empty.",
            )
            return TrainingResult(
                ok=False,
                kind=mode.value,
                status=LifecycleStatus.FAILED,
                issues=tuple(issues),
            )

        if len(feature_records) > opts.max_records:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="training_input_truncated",
                message="Training input exceeded configured record limit and was truncated.",
                details={
                    "submitted": len(feature_records),
                    "max_records": opts.max_records,
                },
            )
            feature_records = feature_records[: opts.max_records]

        label_set = _resolve_label_set(req.labels, opts, req.label_options, issues)
        require_labels = mode in {ServiceMode.SUPERVISED, ServiceMode.HYBRID}

        if require_labels and label_set is None:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="missing_labels",
                message="Supervised or hybrid training requires labels.",
            )
            return TrainingResult(
                ok=False,
                kind=mode.value,
                status=LifecycleStatus.FAILED,
                issues=tuple(issues),
            )

        split_plan = _build_split_plan(label_set, opts, req.split_options, issues)
        buckets = _build_training_splits(
            feature_records,
            label_set,
            split_plan,
            opts,
            issues,
            require_labels,
        )

        if not buckets.get("train", ([], []))[0] and label_set is not None:
            label_map, weight_map, split_map = _label_maps(label_set)

            if label_map:
                rebuilt: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {
                    "train": ([], []),
                    "validation": ([], []),
                    "test": ([], []),
                }

                for index, record in enumerate(feature_records):
                    subject = _extract_subject(record, opts)

                    if not subject or subject not in label_map:
                        continue

                    split = _normalize_token(split_map.get(subject)) or "train"

                    if split not in rebuilt:
                        split = "train"

                    features = _extract_feature_mapping(record)
                    rebuilt[split][0].append(
                        {
                            "subject_ref_hash": subject,
                            "features": features,
                        }
                    )
                    rebuilt[split][1].append(
                        {
                            "subject_ref_hash": subject,
                            "label_code": int(label_map[subject]),
                            "weight": _clip_float(
                                _coerce_optional_float(weight_map.get(subject, 1.0), allow_bool=True),
                                0.0,
                                100.0,
                                1.0,
                            ),
                            "split": split,
                        }
                    )

                buckets = rebuilt

        if req.feature_names:
            allowed = tuple(
                dict.fromkeys(
                    _canonical_field_name(name)
                    for name in req.feature_names
                    if _canonical_field_name(name)
                )
            )
            allowed_set = set(allowed)
            filtered_buckets: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {}

            for split, (records, metas) in buckets.items():
                filtered_records = [
                    {
                        **record,
                        "features": {
                            key: value
                            for key, value in (record.get("features") or {}).items()
                            if key in allowed_set
                        },
                    }
                    for record in records
                ]
                filtered_buckets[split] = (filtered_records, metas)

            buckets = filtered_buckets

        bucket_counts = {
            split: len(records)
            for split, (records, _metas) in buckets.items()
        }

        train_records, train_meta = buckets["train"]

        if not train_records:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_training_records",
                message="No training records were available after alignment.",
            )
            return TrainingResult(
                ok=False,
                kind=mode.value,
                status=LifecycleStatus.FAILED,
                split_summary=_summarize_split_plan(split_plan, buckets),
                issues=tuple(issues),
            )

        preprocessor = _fit_preprocessor(train_records, opts, req.preprocess_options, issues)

        stage_transform = None
        if preprocessing_module is not None and hasattr(preprocessing_module, "PreprocessingStage"):
            stage_transform = preprocessing_module.PreprocessingStage.TRANSFORM

        train_matrix = _transform_with_preprocessor(preprocessor, train_records, opts, stage_transform)

        val_records, val_meta = buckets["validation"]
        test_records, test_meta = buckets["test"]

        val_matrix = (
            _transform_with_preprocessor(preprocessor, val_records, opts, stage_transform)
            if val_records
            else _matrix_from_raw([], _matrix_feature_names(train_matrix))
        )
        test_matrix = (
            _transform_with_preprocessor(preprocessor, test_records, opts, stage_transform)
            if test_records
            else _matrix_from_raw([], _matrix_feature_names(train_matrix))
        )

        dataset = None
        supervised_model = None

        if require_labels and supervised_module is not None:
            dataset = _build_supervised_dataset(
                [
                    (train_matrix, train_meta),
                    (val_matrix, val_meta),
                    (test_matrix, test_meta),
                ],
                opts,
                issues,
            )

            if dataset is not None and getattr(dataset, "x", ()):
                sup_opts = None
                if hasattr(supervised_module, "SupervisedOptions"):
                    sup_opts = _merge_options(
                        supervised_module.SupervisedOptions.from_settings(),
                        opts.supervised_options,
                        req.supervised_options,
                    )

                try:
                    trainer = supervised_module.SupervisedTrainer(options=sup_opts)
                    supervised_model = trainer.train(dataset, metadata=req.metadata)
                except Exception as exc:
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.ERROR,
                        code="supervised_training_failed",
                        message="Supervised training failed.",
                        details={"exception_type": type(exc).__name__},
                    )

        anomaly_model = None

        if mode in {ServiceMode.ANOMALY, ServiceMode.HYBRID}:
            if anomaly_module is None:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="anomaly_module_unavailable",
                    message="Anomaly module unavailable.",
                )
            else:
                anom_opts = None
                if hasattr(anomaly_module, "AnomalyOptions"):
                    anom_opts = _merge_options(
                        anomaly_module.AnomalyOptions.from_settings(),
                        opts.anomaly_options,
                        req.anomaly_options,
                    )

                try:
                    anomaly_model = anomaly_module.AnomalyModel(options=anom_opts)
                    anomaly_model.fit(
                        train_matrix,
                        feature_names=_matrix_feature_names(train_matrix),
                    )
                except Exception as exc:
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.ERROR,
                        code="anomaly_fitting_failed",
                        message="Anomaly fitting failed.",
                        details={"exception_type": type(exc).__name__},
                    )

        governance_ok, governance = _governance_check(
            dataset,
            supervised_model,
            anomaly_model,
            bucket_counts,
            opts,
            issues,
        )

        if supervised_model is not None:
            status = _status_from_supervised_model(supervised_model)
        elif anomaly_model is not None:
            status = LifecycleStatus.TRAINED
        else:
            status = LifecycleStatus.FAILED

        if governance_ok and status in {LifecycleStatus.TRAINED, LifecycleStatus.EVALUATED}:
            status = LifecycleStatus.CANDIDATE

        if opts.auto_activate and status == LifecycleStatus.CANDIDATE:
            status = LifecycleStatus.ACTIVE

        model_id = _combined_model_id(supervised_model, anomaly_model, req.metadata)
        created_at = _now_utc()

        entry = ModelCatalogEntry(
            model_id=model_id,
            kind=mode.value,
            status=status,
            created_at=created_at,
            updated_at=created_at,
            fingerprint=_fingerprint_payload(
                {
                    "model_id": model_id,
                    "kind": mode.value,
                    "status": status.value,
                    "supervised_fingerprint": (
                        getattr(supervised_model, "fingerprint", None)
                        if supervised_model is not None
                        else None
                    ),
                    "anomaly_fingerprint": (
                        getattr(anomaly_model, "fingerprint", None)
                        if anomaly_model is not None
                        else None
                    ),
                    "governance": governance,
                }
            ),
            tags=req.tags,
            metrics_summary=_metric_summary(supervised_model),
            governance=governance,
            split_summary=_summarize_split_plan(split_plan, buckets),
            preprocessing_summary=_preprocessing_summary(preprocessor, train_matrix, opts),
            label_summary=_label_summary(label_set),
            metadata={
                "model_service_version": MODEL_SERVICE_VERSION,
                "request_metadata": _safe_detail_value(req.metadata),
                "observation_time": (
                    _ensure_utc(req.observation_time).isoformat()
                    if _ensure_utc(req.observation_time)
                    else None
                ),
                "training_elapsed_ms": int((time.monotonic() - start_time) * 1000.0),
                "caveats": list(_MODEL_SERVICE_CAVEATS),
                "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
            },
            supervised_model=supervised_model,
            anomaly_model=anomaly_model,
            preprocessor=preprocessor,
        )

        self._register_entry(entry)

        if status == LifecycleStatus.ACTIVE:
            self._deactivate_others(model_id, entry.kind)

        self._audit(
            action="train",
            model_id=model_id,
            status=status.value,
            details={
                "kind": mode.value,
                "governance_ok": governance_ok,
                "issue_count": len(issues),
            },
        )

        ok = (
            status not in {LifecycleStatus.FAILED, LifecycleStatus.BLOCKED}
            and not any(issue.severity == IssueSeverity.ERROR for issue in issues)
        )

        return TrainingResult(
            ok=ok,
            model_id=model_id,
            kind=mode.value,
            status=status,
            metrics=entry.metrics_summary,
            governance=entry.governance,
            split_summary=entry.split_summary,
            preprocessing_summary=entry.preprocessing_summary,
            issues=tuple(issues),
            metadata=entry.metadata,
            fingerprint=entry.fingerprint,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def promote(
        self,
        model_id: Any,
        *,
        force: bool = False,
        reason: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Mark one process-local catalog entry as ACTIVE.

        This does not deploy or serve production models.
        """
        entry = self._get_entry(model_id)

        if entry is None:
            raise MuleGuardValidationError(
                "Model not found in process-local catalog.",
                details={"model_id": _clean_text(model_id, 128)},
            )

        governance_ok = bool(entry.governance.get("ok", False))

        if not force and not governance_ok:
            raise MuleGuardValidationError(
                "Model governance check failed; promotion blocked.",
                details={
                    "model_id": entry.model_id,
                    "governance": _safe_detail_value(entry.governance),
                },
            )

        entry.status = LifecycleStatus.ACTIVE
        entry.updated_at = _now_utc()
        self._deactivate_others(entry.model_id, entry.kind)

        self._audit(
            action="promote",
            model_id=entry.model_id,
            status=entry.status.value,
            details={
                "force": force,
                "reason": _clean_text(reason, 300),
            },
        )

        return entry.to_public_dict()

    def retire(self, model_id: Any, *, reason: Optional[str] = None) -> dict[str, Any]:
        """
        Mark one process-local catalog entry as RETIRED.
        """
        entry = self._get_entry(model_id)

        if entry is None:
            raise MuleGuardValidationError(
                "Model not found in process-local catalog.",
                details={"model_id": _clean_text(model_id, 128)},
            )

        entry.status = LifecycleStatus.RETIRED
        entry.updated_at = _now_utc()

        self._audit(
            action="retire",
            model_id=entry.model_id,
            status=entry.status.value,
            details={"reason": _clean_text(reason, 300)},
        )

        return entry.to_public_dict()

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def infer(self, request: Any) -> InferenceResponse:
        """
        Produce bounded investigative inference from synthetic records.

        Scores are investigative prioritization outputs only. They are not
        probabilities of guilt and must not trigger automatic adverse customer
        action.
        """
        opts = self.options
        issues: list[ServiceIssue] = []
        start_time = time.monotonic()

        if isinstance(request, InferenceRequest):
            req = request
        elif isinstance(request, Mapping):
            try:
                req = InferenceRequest(**request)
            except Exception as exc:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="invalid_inference_request",
                    message="Inference request mapping could not be parsed.",
                    details={"exception_type": type(exc).__name__},
                )
                req = InferenceRequest()
        else:
            req = InferenceRequest(records=request)

        mode = self._resolve_mode(req.mode, opts.mode, None)

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="model_service_disabled",
                message="Model service is disabled.",
            )
            return InferenceResponse(
                ok=False,
                mode=mode,
                decision_source=DecisionSource.UNAVAILABLE,
                issues=tuple(issues),
                metadata={"disabled": True},
            )

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Model service requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return InferenceResponse(
                ok=False,
                mode=mode,
                decision_source=DecisionSource.UNAVAILABLE,
                issues=tuple(issues),
                metadata={"invalid": True},
            )

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Model service inference is blocked in production-like environments.",
            )
            return InferenceResponse(
                ok=False,
                mode=mode,
                decision_source=DecisionSource.UNAVAILABLE,
                issues=tuple(issues),
                metadata={"blocked": True},
            )

        raw_records = _iter_records(req.records)
        submitted = len(raw_records)

        if submitted > opts.max_records:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="inference_input_truncated",
                message="Inference input exceeded configured record limit and was truncated.",
                details={
                    "submitted": submitted,
                    "max_records": opts.max_records,
                },
            )
            raw_records = raw_records[: opts.max_records]

        prepared = [_prepared_record(record, opts) for record in raw_records]

        entry: Optional[ModelCatalogEntry] = None

        if req.model_id:
            entry = self._get_entry(req.model_id)

            if entry is None:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="model_not_found",
                    message="Requested model id not found in process-local catalog.",
                )
        else:
            entry = self._active_entry(mode)

        if entry is not None and mode == ServiceMode.AUTO:
            try:
                mode = ServiceMode(entry.kind)
            except ValueError:
                if entry.supervised_model is not None and entry.anomaly_model is not None:
                    mode = ServiceMode.HYBRID
                elif entry.supervised_model is not None:
                    mode = ServiceMode.SUPERVISED
                elif entry.anomaly_model is not None:
                    mode = ServiceMode.ANOMALY
                else:
                    mode = ServiceMode.FALLBACK

        stage_transform = None
        if preprocessing_module is not None and hasattr(preprocessing_module, "PreprocessingStage"):
            stage_transform = preprocessing_module.PreprocessingStage.TRANSFORM

        if entry is not None and entry.preprocessor is not None:
            matrix = _transform_with_preprocessor(entry.preprocessor, prepared, opts, stage_transform)
        else:
            names = self._entry_feature_names(entry)
            matrix = _matrix_from_raw(prepared, names or None)

        fallback_reason: Optional[str] = None

        if entry is None:
            fallback_reason = "no_active_model"
        elif mode == ServiceMode.SUPERVISED and entry.supervised_model is None:
            fallback_reason = "supervised_model_unavailable"
        elif mode == ServiceMode.ANOMALY and entry.anomaly_model is None:
            fallback_reason = "anomaly_model_unavailable"
        elif (
            mode == ServiceMode.HYBRID
            and entry.supervised_model is None
            and entry.anomaly_model is None
        ):
            fallback_reason = "hybrid_sources_unavailable"

        sup_batch = None

        if (
            entry is not None
            and entry.supervised_model is not None
            and supervised_module is not None
            and mode in {ServiceMode.SUPERVISED, ServiceMode.HYBRID}
        ):
            try:
                sup_batch = supervised_module.predict_supervised_model(
                    entry.supervised_model,
                    matrix or prepared,
                    include_contributions=req.include_contributions,
                )
            except Exception as exc:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="supervised_prediction_failed",
                    message="Supervised prediction failed.",
                    details={"exception_type": type(exc).__name__},
                )

                if mode == ServiceMode.SUPERVISED:
                    fallback_reason = "supervised_prediction_failed"

            if (
                mode == ServiceMode.SUPERVISED
                and sup_batch is not None
                and not getattr(sup_batch, "predictions", ())
            ):
                fallback_reason = "supervised_prediction_empty"

        anom_result = None

        if (
            entry is not None
            and entry.anomaly_model is not None
            and mode in {ServiceMode.ANOMALY, ServiceMode.HYBRID}
        ):
            try:
                anom_result = entry.anomaly_model.score(
                    matrix or prepared,
                    include_contributions=req.include_contributions,
                )
            except Exception as exc:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="anomaly_scoring_failed",
                    message="Anomaly scoring failed.",
                    details={"exception_type": type(exc).__name__},
                )

                if mode == ServiceMode.ANOMALY:
                    fallback_reason = "anomaly_scoring_failed"

            if (
                mode == ServiceMode.ANOMALY
                and anom_result is not None
                and not getattr(anom_result, "records", ())
            ):
                fallback_reason = "anomaly_scoring_empty"

        fallback_result = None
        use_fallback = (
            mode == ServiceMode.FALLBACK
            or mode == ServiceMode.HYBRID
            or (opts.allow_fallback and (entry is None or fallback_reason is not None))
        )

        if use_fallback:
            if fallback_module is None:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.INFO,
                    code="fallback_module_unavailable",
                    message="Fallback module unavailable.",
                )
            elif not opts.allow_fallback:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.INFO,
                    code="fallback_disabled_by_policy",
                    message="Fallback scoring is disabled by policy.",
                )
            else:
                fb_opts = None
                if hasattr(fallback_module, "FallbackOptions"):
                    fb_opts = _merge_options(
                        fallback_module.FallbackOptions.from_settings(),
                        opts.fallback_options,
                        req.fallback_options,
                    )

                try:
                    fallback_result = fallback_module.score_fallback_batch(prepared, options=fb_opts)
                except Exception as exc:
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="fallback_scoring_failed",
                        message="Fallback scoring failed.",
                        details={"exception_type": type(exc).__name__},
                    )

        sup_by_index: dict[int, Any] = {}
        sup_by_subject: dict[str, Any] = {}

        if sup_batch is not None:
            for prediction in getattr(sup_batch, "predictions", ()) or ():
                metadata = getattr(prediction, "metadata", {}) or {}
                index = metadata.get("index")

                if isinstance(index, int):
                    sup_by_index[index] = prediction

                subject = getattr(prediction, "subject_ref_hash", None)

                if subject:
                    sup_by_subject[str(subject).lower()] = prediction

        anom_by_index: dict[int, Any] = {}
        anom_by_subject: dict[str, Any] = {}

        if anom_result is not None:
            for record in getattr(anom_result, "records", ()) or ():
                metadata = getattr(record, "metadata", {}) or {}
                index = metadata.get("index")

                if isinstance(index, int):
                    anom_by_index[index] = record

                subject = getattr(record, "subject_ref_hash", None)

                if subject:
                    anom_by_subject[str(subject).lower()] = record

        fb_by_index: dict[int, Any] = {}
        fb_by_subject: dict[str, Any] = {}

        if fallback_result is not None:
            for index, record in enumerate(getattr(fallback_result, "records", ()) or ()):
                fb_by_index[index] = record
                subject = getattr(record, "subject_ref_hash", None)

                if subject:
                    fb_by_subject[str(subject).lower()] = record

        threshold = req.threshold if req.threshold is not None else opts.review_threshold
        threshold = _clamp_float(threshold, 0.0, 1.0, opts.review_threshold)

        response_records: list[InferenceRecord] = []
        decision_counter: Counter[str] = Counter()
        band_counter: Counter[str] = Counter()
        scored = 0
        unavailable = 0

        source_map = {
            "supervised": DecisionSource.SUPERVISED_MODEL,
            "anomaly": DecisionSource.ANOMALY_MODEL,
            "fallback": DecisionSource.FALLBACK_HEURISTIC,
        }

        for index, prepared_record in enumerate(prepared):
            subject = prepared_record.get("subject_ref_hash")
            subject_key = str(subject).lower() if subject else None

            components: dict[str, float] = {}
            contribution_sources: list[tuple[str, Sequence[Mapping[str, Any]]]] = []

            if mode in {ServiceMode.SUPERVISED, ServiceMode.HYBRID}:
                sup = sup_by_index.get(index)

                if sup is None and subject_key:
                    sup = sup_by_subject.get(subject_key)

                if sup is not None:
                    value = _coerce_optional_float(getattr(sup, "score", None), allow_bool=True)

                    if value is not None:
                        components["supervised"] = _round6(_clip_float(value, 0.0, 1.0, 0.0))

                        if req.include_contributions:
                            contribution_sources.append(
                                ("supervised", getattr(sup, "contributions", ()) or ())
                            )

            if mode in {ServiceMode.ANOMALY, ServiceMode.HYBRID}:
                anom = anom_by_index.get(index)

                if anom is None and subject_key:
                    anom = anom_by_subject.get(subject_key)

                if anom is not None:
                    value = _coerce_optional_float(getattr(anom, "score", None), allow_bool=True)

                    if value is not None:
                        components["anomaly"] = _round6(_clip_float(value, 0.0, 1.0, 0.0))

                        if req.include_contributions:
                            contribution_sources.append(
                                ("anomaly", getattr(anom, "contributions", ()) or ())
                            )

            if use_fallback:
                fb = fb_by_index.get(index)

                if fb is None and subject_key:
                    fb = fb_by_subject.get(subject_key)

                if fb is not None:
                    value = _coerce_optional_float(getattr(fb, "score", None), allow_bool=True)

                    if value is not None:
                        components["fallback"] = _round6(_clip_float(value, 0.0, 1.0, 0.0))

                        if req.include_contributions:
                            contribution_sources.append(
                                ("fallback", getattr(fb, "contributions", ()) or ())
                            )

            score: Optional[float] = None
            source = DecisionSource.UNAVAILABLE

            if mode == ServiceMode.SUPERVISED:
                if "supervised" in components:
                    score = components["supervised"]
                    source = DecisionSource.SUPERVISED_MODEL
                elif "fallback" in components and opts.allow_fallback:
                    score = components["fallback"]
                    source = DecisionSource.FALLBACK_HEURISTIC

            elif mode == ServiceMode.ANOMALY:
                if "anomaly" in components:
                    score = components["anomaly"]
                    source = DecisionSource.ANOMALY_MODEL
                elif "fallback" in components and opts.allow_fallback:
                    score = components["fallback"]
                    source = DecisionSource.FALLBACK_HEURISTIC

            elif mode == ServiceMode.FALLBACK:
                if "fallback" in components:
                    score = components["fallback"]
                    source = DecisionSource.FALLBACK_HEURISTIC

            elif mode == ServiceMode.HYBRID:
                combined = _combine_hybrid(components, opts.hybrid_weights)

                if combined is None and components:
                    best_key, best_value = max(
                        components.items(),
                        key=lambda item: (
                            float(opts.hybrid_weights.get(item[0], 1.0)),
                            item[1],
                            item[0],
                        ),
                    )
                    combined = best_value

                if combined is not None:
                    score = _round6(_clip_float(combined, 0.0, 1.0, 0.0))

                    if len(components) == 1:
                        source = source_map.get(next(iter(components)), DecisionSource.UNAVAILABLE)
                    else:
                        source = DecisionSource.HYBRID_ENSEMBLE

            if score is None:
                unavailable += 1
            else:
                scored += 1

            risk = _risk_band(score, opts.risk_thresholds)
            review = score is not None and score >= float(threshold)

            contributions = (
                _merge_contributions(contribution_sources, opts.max_contributions)
                if req.include_contributions and contribution_sources
                else ()
            )

            decision_counter[source.value] += 1
            band_counter[risk] += 1

            response_records.append(
                InferenceRecord(
                    subject_ref_hash=subject,
                    score=score,
                    risk_band=risk,
                    review_recommended=review,
                    decision_source=source,
                    components=components,
                    contributions=contributions,
                    metadata={
                        "model_id": entry.model_id if entry is not None else None,
                        "model_fingerprint": entry.fingerprint if entry is not None else None,
                        "mode": mode.value,
                        "threshold": _round6(threshold),
                        "fallback_reason": fallback_reason,
                        "components_available": sorted(components),
                        "index": index,
                        "caveats": list(_MODEL_SERVICE_CAVEATS),
                        "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
                    },
                )
            )

        counts = {
            "submitted": submitted,
            "processed": len(prepared),
            "scored": scored,
            "unavailable": unavailable,
            "review_recommended": sum(1 for record in response_records if record.review_recommended),
            "by_source": dict(decision_counter),
            "by_band": dict(band_counter),
        }

        overall_source = DecisionSource.UNAVAILABLE

        if decision_counter:
            top_value = decision_counter.most_common(1)[0][0]
            overall_source = _normalize_enum_option(
                DecisionSource,
                top_value,
                DecisionSource.UNAVAILABLE,
            )

        ok = not any(issue.severity == IssueSeverity.ERROR for issue in issues)

        metadata = {
            "model_service_version": MODEL_SERVICE_VERSION,
            "model_id": entry.model_id if entry is not None else None,
            "model_fingerprint": entry.fingerprint if entry is not None else None,
            "mode": mode.value,
            "decision_source": overall_source.value,
            "fallback_reason": fallback_reason,
            "threshold": _round6(threshold),
            "counts": counts,
            "latency_ms": int((time.monotonic() - start_time) * 1000.0),
            "options": opts.safe_summary(),
            "caveats": list(_MODEL_SERVICE_CAVEATS),
            "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
        }

        return InferenceResponse(
            ok=ok,
            model_id=entry.model_id if entry is not None else "",
            mode=mode,
            decision_source=overall_source,
            records=tuple(response_records),
            counts=counts,
            issues=tuple(issues),
            metadata=metadata,
            fingerprint="",
        )

    # ------------------------------------------------------------------
    # Health and metadata
    # ------------------------------------------------------------------

    def health(self) -> ServiceHealth:
        """
        Return safe service health.
        """
        opts = self.options
        issues: list[ServiceIssue] = []

        modules = {
            "labels": _module_available(labels_module, "LabelSet", "label_set_from_records"),
            "splits": _module_available(splits_module, "build_split_plan_from_label_set"),
            "preprocessing": _module_available(preprocessing_module, "Preprocessor"),
            "supervised": _module_available(
                supervised_module,
                "SupervisedTrainer",
                "predict_supervised_model",
            ),
            "anomaly": _module_available(anomaly_module, "AnomalyModel"),
            "fallback": _module_available(fallback_module, "score_fallback_batch"),
        }

        with self._lock:
            entries = [
                self._catalog[model_id]
                for model_id in self._order
                if model_id in self._catalog
            ]

        active_models = [
            entry.to_public_dict()
            for entry in entries
            if entry.status == LifecycleStatus.ACTIVE
        ]

        kind_counter = Counter(entry.kind for entry in entries)
        status_counter = Counter(entry.status.value for entry in entries)

        catalog_summary = {
            "total": len(entries),
            "active": len(active_models),
            "by_kind": dict(kind_counter),
            "by_status": dict(status_counter),
            "max_catalog_entries": opts.max_catalog_entries,
            "audit_events": len(self._audits),
            "max_audit_events": opts.max_audit_events,
        }

        if not opts.enabled:
            status = HealthStatus.DISABLED
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="model_service_disabled",
                message="Model service is disabled.",
            )
        elif opts.synthetic_required and opts.dataset_mode != "synthetic":
            status = HealthStatus.BLOCKED
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Model service requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
        elif opts.production_like and not opts.allow_in_production:
            status = HealthStatus.BLOCKED
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Model service is blocked in production-like environments.",
            )
        elif opts.mode == ServiceMode.SUPERVISED and not modules["supervised"]:
            status = HealthStatus.DEGRADED
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="supervised_module_unavailable",
                message="Supervised module is unavailable.",
            )
        elif opts.mode == ServiceMode.ANOMALY and not modules["anomaly"]:
            status = HealthStatus.DEGRADED
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="anomaly_module_unavailable",
                message="Anomaly module is unavailable.",
            )
        elif not active_models:
            status = HealthStatus.DEGRADED

            if opts.allow_fallback or opts.mode == ServiceMode.FALLBACK:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="no_active_model_fallback_available",
                    message="No active model is registered, but fallback scoring is available.",
                )
            else:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="no_active_model",
                    message="No active model is registered.",
                )
        else:
            status = HealthStatus.OK

        limits = {
            "max_records": opts.max_records,
            "max_features": opts.max_features,
            "max_issues": opts.max_issues,
            "max_summary_items": opts.max_summary_items,
            "max_contributions": opts.max_contributions,
            "max_catalog_entries": opts.max_catalog_entries,
            "max_audit_events": opts.max_audit_events,
            "max_latency_ms": opts.max_latency_ms,
        }

        metadata = {
            "model_service_version": MODEL_SERVICE_VERSION,
            "generated_at": _now_utc().isoformat(),
            "modules": modules,
            "catalog": catalog_summary,
            "options": opts.safe_summary(),
            "caveats": list(_MODEL_SERVICE_CAVEATS),
            "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
        }

        return ServiceHealth(
            status=status,
            enabled=opts.enabled,
            mode=opts.mode if isinstance(opts.mode, ServiceMode) else ServiceMode.AUTO,
            modules=modules,
            catalog=catalog_summary,
            active_models=tuple(active_models),
            limits=limits,
            issues=tuple(issues),
            metadata=metadata,
        )

    def metadata(self) -> dict[str, Any]:
        """
        Return safe, serializable model-service metadata.
        """
        opts = self.options
        health = self.health()

        return {
            "package": "muleguard.backend.ml.model_service",
            "version": MODEL_SERVICE_VERSION,
            "modes": [mode.value for mode in ServiceMode],
            "lifecycle_statuses": [status.value for status in LifecycleStatus],
            "decision_sources": [source.value for source in DecisionSource],
            "health_statuses": [status.value for status in HealthStatus],
            "issue_severities": [severity.value for severity in IssueSeverity],
            "default_options": opts.safe_summary(),
            "health": health.to_dict(),
            "submodule_availability": dict(health.modules),
            "hard_limits": {
                "max_records": _HARD_MAX_RECORDS,
                "max_features": _HARD_MAX_FEATURES,
                "max_issues": _HARD_MAX_ISSUES,
                "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
                "max_contributions": _HARD_MAX_CONTRIBUTIONS,
                "max_catalog_entries": _HARD_MAX_CATALOG_ENTRIES,
                "max_audit_events": _HARD_MAX_AUDIT_EVENTS,
                "max_latency_ms": _HARD_MAX_LATENCY_MS,
            },
            "caveats": list(_MODEL_SERVICE_CAVEATS),
            "safety_flags": dict(_MODEL_SERVICE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default service and public API
# -----------------------------------------------------------------------------


_default_service: Optional[ModelService] = None
_default_service_lock = threading.Lock()


def get_model_service(
    options: ModelServiceOptions | None = None,
    *,
    rebuild: bool = False,
) -> ModelService:
    """
    Return a process-wide model service.

    If options are supplied or rebuild is True, a new service is created and
    becomes the default.
    """
    global _default_service

    with _default_service_lock:
        if _default_service is None or rebuild or options is not None:
            _default_service = ModelService(options=options or ModelServiceOptions.from_settings())

        return _default_service


def train_model_service(
    request: Any,
    options: ModelServiceOptions | None = None,
    *,
    service: ModelService | None = None,
) -> TrainingResult:
    """
    Train or fit one bounded synthetic model.
    """
    active_service = service or get_model_service(options)
    return active_service.train(request)


def infer_model_service(
    request: Any,
    options: ModelServiceOptions | None = None,
    *,
    service: ModelService | None = None,
) -> InferenceResponse:
    """
    Produce bounded synthetic inference.
    """
    active_service = service or get_model_service(options)
    return active_service.infer(request)


def promote_model(
    model_id: Any,
    *,
    force: bool = False,
    reason: Optional[str] = None,
    service: ModelService | None = None,
) -> dict[str, Any]:
    """
    Promote one process-local model entry to ACTIVE.
    """
    active_service = service or get_model_service()
    return active_service.promote(model_id, force=force, reason=reason)


def retire_model(
    model_id: Any,
    *,
    reason: Optional[str] = None,
    service: ModelService | None = None,
) -> dict[str, Any]:
    """
    Retire one process-local model entry.
    """
    active_service = service or get_model_service()
    return active_service.retire(model_id, reason=reason)


def get_model_health(
    service: ModelService | None = None,
) -> dict[str, Any]:
    """
    Return safe model-service health.
    """
    active_service = service or get_model_service()
    return active_service.health().to_dict()


def get_model_metadata(
    service: ModelService | None = None,
) -> dict[str, Any]:
    """
    Return safe model-service metadata.
    """
    active_service = service or get_model_service()
    return active_service.metadata()


def model_service_metadata(
    service: ModelService | None = None,
) -> dict[str, Any]:
    """
    Alias for `get_model_metadata`.
    """
    return get_model_metadata(service=service)


__all__ = [
    "AuditEvent",
    "DecisionSource",
    "HealthStatus",
    "InferenceRecord",
    "InferenceRequest",
    "InferenceResponse",
    "IssueSeverity",
    "LifecycleStatus",
    "ModelCatalogEntry",
    "ModelService",
    "ModelServiceOptions",
    "ServiceHealth",
    "ServiceIssue",
    "ServiceMode",
    "TrainingRequest",
    "TrainingResult",
    "get_model_health",
    "get_model_metadata",
    "get_model_service",
    "infer_model_service",
    "model_service_metadata",
    "promote_model",
    "retire_model",
    "train_model_service",
]