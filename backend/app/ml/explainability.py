"""
MULEGUARD backend ML explainability.

This module provides the canonical bounded explainability layer for the
synthetic MULEGUARD machine-learning subsystem.

Primary responsibilities:

- produce safe, bounded, deterministic explanations for synthetic supervised,
  anomaly, fallback, hybrid, model-service, and external prediction artefacts;
- support global feature importance and local instance-level contribution
  analysis using transparent, bounded attribution methods;
- combine coefficient attribution, model-native contributions, permutation
  importance, local surrogate modelling, sensitivity analysis, and hybrid
  component attribution into operational review signals only;
- preserve privacy by using salted one-way pseudonymous subject hashes and by
  excluding raw feature values, subject-label pairs, raw identifiers, raw
  narratives, secrets, tokens, passwords, database URLs, filesystem paths, and
  model artifact paths from public summaries;
- enforce strict leakage resistance by rejecting ground-truth labels, injected
  scenario IDs, fraud-ring IDs, raw complaint narratives, raw identifiers, and
  other leakage-prone feature inputs;
- provide bounded diagnostics, fingerprints, issue reporting, safe caches, and
  API-facing summaries;
- remain import-safe, dependency-light, and resilient when optional ML
  submodules are unavailable.

This module explains synthetic model behaviour only. It does not train models,
deploy models, evaluate models as authoritative truth, persist data, call
external systems, authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for explanation generation.
- Explanations are operational attributions only. They are not causal proof.
- Feature contributions are investigative review signals only. They are not
  proof of wrongdoing.
- Model probabilities, anomaly scores, fallback scores, and explanation scores
  are investigative prioritization signals only. They are not probabilities of
  guilt.
- Labels must never be used as features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as leakage-prone feature inputs.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden feature inputs. Subject linkage is pseudonymous
  and salted.
- Explainability handling never triggers automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, or otherwise
  harming accounts or customers.
- Undefined or unavailable explanations are reported honestly as unavailable
  rather than invented.
- The bundled explanation cache is process-local, non-durable, and bounded for
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
- This module is not a durable explanation store.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, explanations,
and case dispositions are investigative leads or human workflow artefacts only.
They are not proof of wrongdoing and must not trigger automatic adverse customer
action.
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
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError

logger = logging.getLogger("muleguard.backend.ml.explainability")


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
    from app.ml import model_service as model_service_module
except Exception:  # pragma: no cover
    model_service_module = None  # type: ignore[assignment]

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

EXPLAINABILITY_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.ml.explainability.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_RECORDS: Final[int] = 5_000
_HARD_MAX_RECORDS: Final[int] = 100_000

_DEFAULT_MAX_FEATURES: Final[int] = 256
_HARD_MAX_FEATURES: Final[int] = 4_096

_DEFAULT_MAX_INSTANCES: Final[int] = 100
_HARD_MAX_INSTANCES: Final[int] = 10_000

_DEFAULT_MAX_LOCAL_SAMPLES: Final[int] = 128
_HARD_MAX_LOCAL_SAMPLES: Final[int] = 2_048

_DEFAULT_MAX_LOCAL_FEATURES: Final[int] = 32
_HARD_MAX_LOCAL_FEATURES: Final[int] = 256

_DEFAULT_MAX_GLOBAL_FEATURES: Final[int] = 64
_HARD_MAX_GLOBAL_FEATURES: Final[int] = 1_024

_DEFAULT_MAX_PERMUTATION_RECORDS: Final[int] = 2_000
_HARD_MAX_PERMUTATION_RECORDS: Final[int] = 20_000

_DEFAULT_MAX_CONTRIBUTIONS: Final[int] = 20
_HARD_MAX_CONTRIBUTIONS: Final[int] = 200

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_CACHE_ENTRIES: Final[int] = 256
_HARD_MAX_CACHE_ENTRIES: Final[int] = 10_000

_DEFAULT_MAX_TIME_MS: Final[int] = 20_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_DEFAULT_THRESHOLD: Final[float] = 0.50
_DEFAULT_RIDGE_ALPHA: Final[float] = 1e-2
_DEFAULT_KERNEL_BANDWIDTH_FACTOR: Final[float] = 0.75
_DEFAULT_MIN_STABILITY_SAMPLES: Final[int] = 32
_DEFAULT_STABILITY_REPEATS: Final[int] = 8
_HARD_MAX_STABILITY_REPEATS: Final[int] = 200

_DEFAULT_TOP_K: Final[int] = 20
_HARD_TOP_K: Final[int] = 200

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
        "index",
        "source_index",
    }
)

_FORBIDDEN_EXPLAIN_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_EXPLAIN_TOKENS: Final[tuple[str, ...]] = (
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

_DEFAULT_POSITIVE_LABEL_CODES: Final[tuple[int, ...]] = (2, 3)
_DEFAULT_NEGATIVE_LABEL_CODES: Final[tuple[int, ...]] = (1,)
_DEFAULT_IGNORE_LABEL_CODES: Final[tuple[int, ...]] = (0,)

_METHOD_WEIGHTS: Final[Mapping[str, float]] = MappingProxyType(
    {
        "coefficient": 1.00,
        "model_contributions": 0.90,
        "local_surrogate": 0.80,
        "hybrid": 0.70,
        "sensitivity": 0.60,
        "permutation": 0.50,
    }
)

_EXPLAIN_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic explainability only. Do not use with real customer data.",
    "Explanations are operational attributions only and are not causal proof.",
    "Feature contributions are investigative review signals only and are not proof of wrongdoing.",
    "Model, anomaly, fallback, and explanation scores are not probabilities of guilt.",
    "Explainability must not trigger automatic adverse customer action.",
    "Labels must never be used as features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected as features.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Unavailable explanations are reported honestly as unavailable rather than invented.",
    "The bundled explanation cache is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_EXPLAIN_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_explainability": True,
        "bounded_explainability_required": True,
        "explanations_are_operational_attributions_only": True,
        "contributions_are_not_causal_proof": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class ExplanationScope(str, Enum):
    """
    Explanation scope.
    """

    GLOBAL = "global"
    LOCAL = "local"
    BOTH = "both"


class ExplanationMethod(str, Enum):
    """
    Bounded explainability method.
    """

    COEFFICIENT = "coefficient"
    MODEL_CONTRIBUTIONS = "model_contributions"
    LOCAL_SURROGATE = "local_surrogate"
    PERMUTATION = "permutation"
    SENSITIVITY = "sensitivity"
    HYBRID = "hybrid"


class ExplanationTarget(str, Enum):
    """
    Explanation target source.
    """

    AUTO = "auto"
    SUPERVISED = "supervised"
    ANOMALY = "anomaly"
    FALLBACK = "fallback"
    HYBRID = "hybrid"
    MODEL_SERVICE = "model_service"
    EXTERNAL = "external"


class BaselinePolicy(str, Enum):
    """
    Baseline construction policy for perturbation-based explanations.
    """

    MEDIAN = "median"
    MEAN = "mean"
    ZERO = "zero"
    MAJORITY = "majority"


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


def _is_forbidden_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_EXPLAIN_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_EXPLAIN_TOKENS)


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


def _module_available(module: Any, *names: str) -> bool:
    if module is None:
        return False

    return all(hasattr(module, name) for name in names)


def _time_exceeded(start_time: float, max_time_ms: int) -> bool:
    return (time.monotonic() - start_time) * 1000.0 > float(max(1, int(max_time_ms)))


def _elapsed_ms(start_time: float) -> int:
    return int((time.monotonic() - start_time) * 1000.0)


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExplanationIssue:
    """
    Safe explainability issue.

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
    issues: list[ExplanationIssue],
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

        issues[-1] = ExplanationIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        ExplanationIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )
    )


def _has_error(issues: Sequence[ExplanationIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


# -----------------------------------------------------------------------------
# Explanation data models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Contribution:
    """
    One bounded feature contribution.

    Contributions are operational attributions only. They are not causal proof.
    """

    feature: str
    effect: float = 0.0
    magnitude: float = 0.0
    direction: str = "neutral"
    method: str = "explainability"
    value_bucket: str = ""
    baseline_bucket: str = ""
    confidence: float = 0.0
    stability: float = 0.0
    sources: tuple[str, ...] = ()
    details: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "feature", _canonical_field_name(self.feature))
        object.__setattr__(self, "effect", _round6(_clip_float(self.effect, -1e12, 1e12, 0.0)))
        object.__setattr__(self, "magnitude", _round6(max(0.0, _clip_float(self.magnitude, 0.0, 1e12, abs(self.effect)))))

        direction = _normalize_token(self.direction)

        if direction not in {"increase", "decrease", "neutral"}:
            if self.effect > 0:
                direction = "increase"
            elif self.effect < 0:
                direction = "decrease"
            else:
                direction = "neutral"

        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "method", _clean_text(self.method, 100) or "explainability")
        object.__setattr__(self, "value_bucket", _clean_text(self.value_bucket, 64))
        object.__setattr__(self, "baseline_bucket", _clean_text(self.baseline_bucket, 64))
        object.__setattr__(self, "confidence", _round6(_clip_float(self.confidence, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "stability", _round6(_clip_float(self.stability, 0.0, 1.0, 0.0)))
        object.__setattr__(
            self,
            "sources",
            tuple(
                dict.fromkeys(
                    _clean_text(source, 100)
                    for source in (self.sources or ())
                    if _clean_text(source, 100)
                )
            ),
        )
        object.__setattr__(self, "details", MappingProxyType(_safe_detail_value(self.details) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "effect": float(self.effect),
            "magnitude": float(self.magnitude),
            "direction": self.direction,
            "method": self.method,
            "value_bucket": self.value_bucket,
            "baseline_bucket": self.baseline_bucket,
            "confidence": float(self.confidence),
            "stability": float(self.stability),
            "sources": list(self.sources),
            "details": _safe_detail_value(self.details),
            "interpretation": "operational attribution only, not causal proof",
        }


@dataclass(frozen=True, slots=True)
class GlobalImportance:
    """
    One bounded global feature importance record.
    """

    feature: str
    method: str
    score: float = 0.0
    mean_abs_effect: float = 0.0
    rank: int = 0
    stability: float = 0.0
    available: bool = True
    sources: tuple[str, ...] = ()
    details: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "feature", _canonical_field_name(self.feature))
        object.__setattr__(self, "method", _clean_text(self.method, 100) or "explainability")
        object.__setattr__(self, "score", _round6(max(0.0, _clip_float(self.score, 0.0, 1e12, 0.0))))
        object.__setattr__(self, "mean_abs_effect", _round6(max(0.0, _clip_float(self.mean_abs_effect, 0.0, 1e12, self.score))))
        object.__setattr__(self, "rank", max(0, _as_int(self.rank, 0)))
        object.__setattr__(self, "stability", _round6(_clip_float(self.stability, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "available", _as_bool(self.available, True))
        object.__setattr__(
            self,
            "sources",
            tuple(
                dict.fromkeys(
                    _clean_text(source, 100)
                    for source in (self.sources or ())
                    if _clean_text(source, 100)
                )
            ),
        )
        object.__setattr__(self, "details", MappingProxyType(_safe_detail_value(self.details) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "method": self.method,
            "score": float(self.score),
            "mean_abs_effect": float(self.mean_abs_effect),
            "rank": int(self.rank),
            "stability": float(self.stability),
            "available": bool(self.available),
            "sources": list(self.sources),
            "details": _safe_detail_value(self.details),
        }


@dataclass(frozen=True, slots=True)
class LocalExplanation:
    """
    One bounded local explanation.
    """

    subject_ref_hash: Optional[str] = None
    index: Optional[int] = None
    target: str = "auto"
    score: Optional[float] = None
    baseline_score: Optional[float] = None
    contributions: tuple[Contribution, ...] = ()
    methods: tuple[str, ...] = ()
    confidence: float = 0.0
    stability: float = 0.0
    summary: Mapping[str, Any] = dataclass_field(default_factory=dict)
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
        object.__setattr__(self, "target", _clean_text(self.target, 64) or "auto")

        if self.score is not None:
            object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))

        if self.baseline_score is not None:
            object.__setattr__(self, "baseline_score", _round6(_clip_float(self.baseline_score, 0.0, 1.0, 0.0)))

        object.__setattr__(self, "contributions", tuple(self.contributions or ()))
        object.__setattr__(
            self,
            "methods",
            tuple(
                dict.fromkeys(
                    _clean_text(method, 100)
                    for method in (self.methods or ())
                    if _clean_text(method, 100)
                )
            ),
        )
        object.__setattr__(self, "confidence", _round6(_clip_float(self.confidence, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "stability", _round6(_clip_float(self.stability, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "summary", MappingProxyType(_safe_detail_value(self.summary) or {}))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_ref_hash": self.subject_ref_hash,
            "index": int(self.index) if self.index is not None else None,
            "target": self.target,
            "score": float(self.score) if self.score is not None else None,
            "baseline_score": float(self.baseline_score) if self.baseline_score is not None else None,
            "contributions": [contribution.to_dict() for contribution in self.contributions],
            "methods": list(self.methods),
            "confidence": float(self.confidence),
            "stability": float(self.stability),
            "summary": _safe_detail_value(self.summary),
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_EXPLAIN_CAVEATS),
            "safety_flags": dict(_EXPLAIN_SAFETY_FLAGS),
        }


@dataclass(slots=True)
class ExplanationRequest:
    """
    Bounded explainability request.
    """

    features: Any = None
    labels: Any = None
    model: Any = None
    model_id: Optional[str] = None
    target: ExplanationTarget | str | None = None
    scope: ExplanationScope | str | None = None
    methods: Sequence[ExplanationMethod | str] | None = None
    instance_refs: Sequence[Any] | None = None
    feature_names: Optional[Sequence[str]] = None
    target_label: Optional[int] = None
    top_k: Optional[int] = None
    positive_label_codes: Sequence[int] | None = None
    negative_label_codes: Sequence[int] | None = None
    ignore_label_codes: Sequence[int] | None = None
    threshold: Optional[float] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.target = (
            _normalize_enum_option(ExplanationTarget, self.target, None)
            if self.target is not None
            else None
        )
        self.scope = (
            _normalize_enum_option(ExplanationScope, self.scope, None)
            if self.scope is not None
            else None
        )
        self.methods = (
            tuple(
                dict.fromkeys(
                    _normalize_enum_option(ExplanationMethod, method, None)
                    for method in _as_sequence(self.methods)
                )
            )
            if self.methods is not None
            else None
        )
        self.methods = tuple(method for method in (self.methods or ()) if isinstance(method, ExplanationMethod)) or None
        self.instance_refs = tuple(_as_sequence(self.instance_refs)) if self.instance_refs is not None else None
        self.feature_names = (
            tuple(
                dict.fromkeys(
                    _canonical_field_name(name)
                    for name in self.feature_names
                    if _canonical_field_name(name)
                )
            )
            if self.feature_names is not None
            else None
        )
        self.model_id = _clean_text(self.model_id, 128) if self.model_id else None
        self.target_label = _coerce_int_label(self.target_label)

        if self.top_k is not None:
            self.top_k = _clamp_int(self.top_k, 1, _HARD_TOP_K, _DEFAULT_TOP_K)

        if self.threshold is not None:
            self.threshold = _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD)

        self.positive_label_codes = _coerce_int_tuple(self.positive_label_codes, _DEFAULT_POSITIVE_LABEL_CODES)
        self.negative_label_codes = _coerce_int_tuple(self.negative_label_codes, _DEFAULT_NEGATIVE_LABEL_CODES)
        self.ignore_label_codes = _coerce_int_tuple(self.ignore_label_codes, _DEFAULT_IGNORE_LABEL_CODES)

        self.metadata = _safe_detail_value(self.metadata) or {}
        self.tags = tuple(
            dict.fromkeys(
                _clean_text(tag, 100)
                for tag in (self.tags or ())
                if _clean_text(tag, 100)
            )
        )
        self.request_id = _clean_text(self.request_id, 128) if self.request_id else None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) if self.idempotency_key else None


@dataclass(frozen=True, slots=True)
class ExplanationResult:
    """
    Safe explainability result.

    Public summaries deliberately exclude raw feature values, subject-label
    pairs, raw identifiers, raw narratives, secrets, tokens, passwords, database
    URLs, filesystem paths, and model artifact paths.
    """

    ok: bool = True
    model_id: str = ""
    target: ExplanationTarget = ExplanationTarget.AUTO
    scope: ExplanationScope = ExplanationScope.BOTH
    methods: tuple[str, ...] = ()
    global_importance: tuple[GlobalImportance, ...] = ()
    local_explanations: tuple[LocalExplanation, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[ExplanationIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(self, "model_id", _clean_text(self.model_id, 128))
        object.__setattr__(
            self,
            "target",
            _normalize_enum_option(ExplanationTarget, self.target, ExplanationTarget.AUTO),
        )
        object.__setattr__(
            self,
            "scope",
            _normalize_enum_option(ExplanationScope, self.scope, ExplanationScope.BOTH),
        )
        object.__setattr__(
            self,
            "methods",
            tuple(
                dict.fromkeys(
                    _clean_text(method, 100)
                    for method in (self.methods or ())
                    if _clean_text(method, 100)
                )
            ),
        )
        object.__setattr__(self, "global_importance", tuple(self.global_importance or ()))
        object.__setattr__(self, "local_explanations", tuple(self.local_explanations or ()))
        object.__setattr__(self, "counts", MappingProxyType({str(k): max(0, _as_int(v, 0)) for k, v in (self.counts or {}).items()}))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": EXPLAINABILITY_VERSION,
                        "ok": self.ok,
                        "model_id": self.model_id,
                        "target": self.target.value,
                        "scope": self.scope.value,
                        "methods": list(self.methods),
                        "global_count": len(self.global_importance),
                        "local_count": len(self.local_explanations),
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "model_id": self.model_id,
            "target": self.target.value,
            "scope": self.scope.value,
            "methods": list(self.methods),
            "global_importance": [importance.to_dict() for importance in self.global_importance],
            "local_explanations": [explanation.to_dict() for explanation in self.local_explanations],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_EXPLAIN_CAVEATS),
            "safety_flags": dict(_EXPLAIN_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


def _default_methods() -> tuple[ExplanationMethod, ...]:
    return (
        ExplanationMethod.COEFFICIENT,
        ExplanationMethod.MODEL_CONTRIBUTIONS,
        ExplanationMethod.LOCAL_SURROGATE,
        ExplanationMethod.PERMUTATION,
        ExplanationMethod.SENSITIVITY,
        ExplanationMethod.HYBRID,
    )


def _normalize_methods(value: Any) -> tuple[ExplanationMethod, ...]:
    if value is None:
        return _default_methods()

    raw_items = value if isinstance(value, (list, tuple, set)) else _csv(value)
    out: list[ExplanationMethod] = []

    for item in raw_items:
        member = _normalize_enum_option(ExplanationMethod, item, None)

        if isinstance(member, ExplanationMethod):
            out.append(member)

    if not out:
        return _default_methods()

    return tuple(dict.fromkeys(out))


@dataclass(frozen=True, slots=True)
class ExplainOptions:
    """
    Bounded explainability policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    scope: ExplanationScope | str = ExplanationScope.BOTH
    target: ExplanationTarget | str = ExplanationTarget.AUTO
    methods: tuple[ExplanationMethod, ...] = _default_methods()
    baseline_policy: BaselinePolicy | str = BaselinePolicy.MEDIAN

    threshold: float = _DEFAULT_THRESHOLD
    ridge_alpha: float = _DEFAULT_RIDGE_ALPHA
    kernel_bandwidth_factor: float = _DEFAULT_KERNEL_BANDWIDTH_FACTOR
    min_stability_samples: int = _DEFAULT_MIN_STABILITY_SAMPLES
    stability_repeats: int = _DEFAULT_STABILITY_REPEATS
    top_k: int = _DEFAULT_TOP_K

    max_records: int = _DEFAULT_MAX_RECORDS
    max_features: int = _DEFAULT_MAX_FEATURES
    max_instances: int = _DEFAULT_MAX_INSTANCES
    max_local_samples: int = _DEFAULT_MAX_LOCAL_SAMPLES
    max_local_features: int = _DEFAULT_MAX_LOCAL_FEATURES
    max_global_features: int = _DEFAULT_MAX_GLOBAL_FEATURES
    max_permutation_records: int = _DEFAULT_MAX_PERMUTATION_RECORDS
    max_contributions: int = _DEFAULT_MAX_CONTRIBUTIONS
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_cache_entries: int = _DEFAULT_MAX_CACHE_ENTRIES
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    include_value_buckets: bool = True
    include_stability: bool = True
    use_cache: bool = True
    drop_forbidden_fields: bool = False

    positive_label_codes: tuple[int, ...] = _DEFAULT_POSITIVE_LABEL_CODES
    negative_label_codes: tuple[int, ...] = _DEFAULT_NEGATIVE_LABEL_CODES
    ignore_label_codes: tuple[int, ...] = _DEFAULT_IGNORE_LABEL_CODES

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
            "scope",
            _normalize_enum_option(ExplanationScope, self.scope, ExplanationScope.BOTH),
        )
        object.__setattr__(
            self,
            "target",
            _normalize_enum_option(ExplanationTarget, self.target, ExplanationTarget.AUTO),
        )
        object.__setattr__(self, "methods", _normalize_methods(self.methods))
        object.__setattr__(
            self,
            "baseline_policy",
            _normalize_enum_option(BaselinePolicy, self.baseline_policy, BaselinePolicy.MEDIAN),
        )

        object.__setattr__(self, "threshold", _clamp_float(self.threshold, 0.0, 1.0, _DEFAULT_THRESHOLD))
        object.__setattr__(self, "ridge_alpha", max(0.0, _as_float(self.ridge_alpha, _DEFAULT_RIDGE_ALPHA)))
        object.__setattr__(
            self,
            "kernel_bandwidth_factor",
            max(0.05, _as_float(self.kernel_bandwidth_factor, _DEFAULT_KERNEL_BANDWIDTH_FACTOR)),
        )
        object.__setattr__(self, "min_stability_samples", max(2, _as_int(self.min_stability_samples, _DEFAULT_MIN_STABILITY_SAMPLES)))
        object.__setattr__(
            self,
            "stability_repeats",
            _clamp_int(self.stability_repeats, 0, _HARD_MAX_STABILITY_REPEATS, _DEFAULT_STABILITY_REPEATS),
        )
        object.__setattr__(self, "top_k", _clamp_int(self.top_k, 1, _HARD_TOP_K, _DEFAULT_TOP_K))

        object.__setattr__(self, "max_records", _clamp_int(self.max_records, 1, _HARD_MAX_RECORDS, _DEFAULT_MAX_RECORDS))
        object.__setattr__(self, "max_features", _clamp_int(self.max_features, 1, _HARD_MAX_FEATURES, _DEFAULT_MAX_FEATURES))
        object.__setattr__(self, "max_instances", _clamp_int(self.max_instances, 1, _HARD_MAX_INSTANCES, _DEFAULT_MAX_INSTANCES))
        object.__setattr__(self, "max_local_samples", _clamp_int(self.max_local_samples, 4, _HARD_MAX_LOCAL_SAMPLES, _DEFAULT_MAX_LOCAL_SAMPLES))
        object.__setattr__(self, "max_local_features", _clamp_int(self.max_local_features, 1, _HARD_MAX_LOCAL_FEATURES, _DEFAULT_MAX_LOCAL_FEATURES))
        object.__setattr__(self, "max_global_features", _clamp_int(self.max_global_features, 1, _HARD_MAX_GLOBAL_FEATURES, _DEFAULT_MAX_GLOBAL_FEATURES))
        object.__setattr__(self, "max_permutation_records", _clamp_int(self.max_permutation_records, 10, _HARD_MAX_PERMUTATION_RECORDS, _DEFAULT_MAX_PERMUTATION_RECORDS))
        object.__setattr__(self, "max_contributions", _clamp_int(self.max_contributions, 1, _HARD_MAX_CONTRIBUTIONS, _DEFAULT_MAX_CONTRIBUTIONS))
        object.__setattr__(self, "max_issues", _clamp_int(self.max_issues, 1, _HARD_MAX_ISSUES, _DEFAULT_MAX_ISSUES))
        object.__setattr__(self, "max_summary_items", _clamp_int(self.max_summary_items, 1, _HARD_MAX_SUMMARY_ITEMS, _DEFAULT_MAX_SUMMARY_ITEMS))
        object.__setattr__(self, "max_cache_entries", _clamp_int(self.max_cache_entries, 1, _HARD_MAX_CACHE_ENTRIES, _DEFAULT_MAX_CACHE_ENTRIES))
        object.__setattr__(self, "max_time_ms", _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS))

        object.__setattr__(self, "include_value_buckets", _as_bool(self.include_value_buckets, True))
        object.__setattr__(self, "include_stability", _as_bool(self.include_stability, True))
        object.__setattr__(self, "use_cache", _as_bool(self.use_cache, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))

        object.__setattr__(self, "positive_label_codes", _coerce_int_tuple(self.positive_label_codes, _DEFAULT_POSITIVE_LABEL_CODES))
        object.__setattr__(self, "negative_label_codes", _coerce_int_tuple(self.negative_label_codes, _DEFAULT_NEGATIVE_LABEL_CODES))
        object.__setattr__(self, "ignore_label_codes", _coerce_int_tuple(self.ignore_label_codes, _DEFAULT_IGNORE_LABEL_CODES))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ExplainOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_EXPLAIN_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_EXPLAIN_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_EXPLAIN_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_EXPLAIN_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ML_EXPLAIN_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ML_EXPLAIN_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            scope=str(_setting(settings, "ML_EXPLAIN_SCOPE", ExplanationScope.BOTH.value)),
            target=str(_setting(settings, "ML_EXPLAIN_TARGET", ExplanationTarget.AUTO.value)),
            methods=_normalize_methods(_setting(settings, "ML_EXPLAIN_METHODS", None)),
            baseline_policy=str(_setting(settings, "ML_EXPLAIN_BASELINE_POLICY", BaselinePolicy.MEDIAN.value)),
            threshold=_as_float(_setting(settings, "ML_EXPLAIN_THRESHOLD", _DEFAULT_THRESHOLD), _DEFAULT_THRESHOLD),
            ridge_alpha=_as_float(_setting(settings, "ML_EXPLAIN_RIDGE_ALPHA", _DEFAULT_RIDGE_ALPHA), _DEFAULT_RIDGE_ALPHA),
            kernel_bandwidth_factor=_as_float(
                _setting(settings, "ML_EXPLAIN_KERNEL_BANDWIDTH_FACTOR", _DEFAULT_KERNEL_BANDWIDTH_FACTOR),
                _DEFAULT_KERNEL_BANDWIDTH_FACTOR,
            ),
            min_stability_samples=_as_int(
                _setting(settings, "ML_EXPLAIN_MIN_STABILITY_SAMPLES", _DEFAULT_MIN_STABILITY_SAMPLES),
                _DEFAULT_MIN_STABILITY_SAMPLES,
            ),
            stability_repeats=_as_int(
                _setting(settings, "ML_EXPLAIN_STABILITY_REPEATS", _DEFAULT_STABILITY_REPEATS),
                _DEFAULT_STABILITY_REPEATS,
            ),
            top_k=_as_int(_setting(settings, "ML_EXPLAIN_TOP_K", _DEFAULT_TOP_K), _DEFAULT_TOP_K),
            max_records=_as_int(_setting(settings, "ML_EXPLAIN_MAX_RECORDS", _DEFAULT_MAX_RECORDS), _DEFAULT_MAX_RECORDS),
            max_features=_as_int(_setting(settings, "ML_EXPLAIN_MAX_FEATURES", _DEFAULT_MAX_FEATURES), _DEFAULT_MAX_FEATURES),
            max_instances=_as_int(_setting(settings, "ML_EXPLAIN_MAX_INSTANCES", _DEFAULT_MAX_INSTANCES), _DEFAULT_MAX_INSTANCES),
            max_local_samples=_as_int(
                _setting(settings, "ML_EXPLAIN_MAX_LOCAL_SAMPLES", _DEFAULT_MAX_LOCAL_SAMPLES),
                _DEFAULT_MAX_LOCAL_SAMPLES,
            ),
            max_local_features=_as_int(
                _setting(settings, "ML_EXPLAIN_MAX_LOCAL_FEATURES", _DEFAULT_MAX_LOCAL_FEATURES),
                _DEFAULT_MAX_LOCAL_FEATURES,
            ),
            max_global_features=_as_int(
                _setting(settings, "ML_EXPLAIN_MAX_GLOBAL_FEATURES", _DEFAULT_MAX_GLOBAL_FEATURES),
                _DEFAULT_MAX_GLOBAL_FEATURES,
            ),
            max_permutation_records=_as_int(
                _setting(settings, "ML_EXPLAIN_MAX_PERMUTATION_RECORDS", _DEFAULT_MAX_PERMUTATION_RECORDS),
                _DEFAULT_MAX_PERMUTATION_RECORDS,
            ),
            max_contributions=_as_int(
                _setting(settings, "ML_EXPLAIN_MAX_CONTRIBUTIONS", _DEFAULT_MAX_CONTRIBUTIONS),
                _DEFAULT_MAX_CONTRIBUTIONS,
            ),
            max_issues=_as_int(_setting(settings, "ML_EXPLAIN_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(
                _setting(settings, "ML_EXPLAIN_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS),
                _DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_cache_entries=_as_int(
                _setting(settings, "ML_EXPLAIN_MAX_CACHE_ENTRIES", _DEFAULT_MAX_CACHE_ENTRIES),
                _DEFAULT_MAX_CACHE_ENTRIES,
            ),
            max_time_ms=_as_int(_setting(settings, "ML_EXPLAIN_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS), _DEFAULT_MAX_TIME_MS),
            include_value_buckets=_as_bool(_setting(settings, "ML_EXPLAIN_INCLUDE_VALUE_BUCKETS", True), True),
            include_stability=_as_bool(_setting(settings, "ML_EXPLAIN_INCLUDE_STABILITY", True), True),
            use_cache=_as_bool(_setting(settings, "ML_EXPLAIN_USE_CACHE", True), True),
            drop_forbidden_fields=_as_bool(_setting(settings, "ML_EXPLAIN_DROP_FORBIDDEN_FIELDS", False), False),
            positive_label_codes=_coerce_int_tuple(
                _setting(settings, "ML_EXPLAIN_POSITIVE_LABEL_CODES", None),
                _DEFAULT_POSITIVE_LABEL_CODES,
            ),
            negative_label_codes=_coerce_int_tuple(
                _setting(settings, "ML_EXPLAIN_NEGATIVE_LABEL_CODES", None),
                _DEFAULT_NEGATIVE_LABEL_CODES,
            ),
            ignore_label_codes=_coerce_int_tuple(
                _setting(settings, "ML_EXPLAIN_IGNORE_LABEL_CODES", None),
                _DEFAULT_IGNORE_LABEL_CODES,
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
            "scope": self.scope.value if isinstance(self.scope, ExplanationScope) else str(self.scope),
            "target": self.target.value if isinstance(self.target, ExplanationTarget) else str(self.target),
            "methods": [method.value for method in self.methods],
            "baseline_policy": self.baseline_policy.value if isinstance(self.baseline_policy, BaselinePolicy) else str(self.baseline_policy),
            "threshold": round(self.threshold, 6),
            "ridge_alpha": round(self.ridge_alpha, 8),
            "kernel_bandwidth_factor": round(self.kernel_bandwidth_factor, 6),
            "min_stability_samples": self.min_stability_samples,
            "stability_repeats": self.stability_repeats,
            "top_k": self.top_k,
            "limits": {
                "max_records": self.max_records,
                "max_features": self.max_features,
                "max_instances": self.max_instances,
                "max_local_samples": self.max_local_samples,
                "max_local_features": self.max_local_features,
                "max_global_features": self.max_global_features,
                "max_permutation_records": self.max_permutation_records,
                "max_contributions": self.max_contributions,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_cache_entries": self.max_cache_entries,
                "max_time_ms": self.max_time_ms,
            },
            "flags": {
                "include_value_buckets": self.include_value_buckets,
                "include_stability": self.include_stability,
                "use_cache": self.use_cache,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
            "label_codes": {
                "positive": list(self.positive_label_codes),
                "negative": list(self.negative_label_codes),
                "ignore": list(self.ignore_label_codes),
            },
        }


# -----------------------------------------------------------------------------
# Input extraction and sanitization
# -----------------------------------------------------------------------------


def _subject_hash(value: Any, options: ExplainOptions) -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.ml.explainability.subject.{safe_namespace}"
    return _hmac_hex(options.salt, domain, text)


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, ExplanationResult):
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


def _extract_subject(record: Any, options: ExplainOptions) -> Optional[str]:
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


def _classify_feature_value(value: Any) -> tuple[str, Any]:
    if value is None:
        return "missing", None

    if isinstance(value, str) and not value.strip():
        return "missing", None

    if isinstance(value, bool):
        return "boolean", value

    numeric = _coerce_optional_float(value, allow_bool=False)

    if numeric is not None:
        return "numeric", numeric

    parsed_bool = _coerce_bool(value)

    if parsed_bool is not None:
        return "boolean", parsed_bool

    token = _normalize_token(value)

    if token:
        return "categorical", token

    return "categorical", _sha256_hex(_clean_text(value, 200))[:12]


def _model_feature_value(kind: str, value: Any) -> Any:
    if kind == "numeric":
        return float(value)

    if kind == "boolean":
        return bool(value)

    if kind == "categorical":
        return str(value)

    return None


def _sanitize_records(
    raw_records: Sequence[Any],
    options: ExplainOptions,
    issues: list[ExplanationIssue],
    allowed_features: Optional[Sequence[str]] = None,
) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    allowed_set = (
        set(
            dict.fromkeys(
                _canonical_field_name(name)
                for name in allowed_features
                if _canonical_field_name(name)
            )
        )
        if allowed_features is not None
        else None
    )

    for source_index, record in enumerate(raw_records):
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

            if allowed_set is not None and canonical not in allowed_set:
                continue

            if canonical in clean_features:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="duplicate_feature_alias",
                    message="Duplicate feature alias omitted.",
                    field=key_text,
                    details={"source_index": source_index},
                )
                continue

            kind, value = _classify_feature_value(raw_value)
            clean_features[canonical] = _model_feature_value(kind, value)

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

        cleaned.append(
            {
                "index": len(cleaned),
                "source_index": source_index,
                "subject_ref_hash": subject,
                "features": clean_features,
            }
        )

    if not cleaned:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="no_valid_explanation_records",
            message="No valid explanation records remained after sanitization.",
        )

    return cleaned


def _scan_labels(
    labels: Any,
    options: ExplainOptions,
    issues: list[ExplanationIssue],
) -> bool:
    """
    Scan label input for forbidden secret/PII-like fields.

    Label-like fields are allowed in label input but are rejected in feature
    input.
    """
    if labels is None:
        return True

    ok = True

    def scan_mapping(mp: Mapping[Any, Any], prefix: str) -> None:
        nonlocal ok

        for raw_key in mp.keys():
            key = _clean_text(raw_key, 200)
            canonical = _canonical_field_name(key)

            if not canonical:
                continue

            if _is_forbidden_key(canonical) and not _is_label_leakage_key(canonical):
                if options.drop_forbidden_fields:
                    _append_issue(
                        issues,
                        options.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="forbidden_label_field_dropped",
                        message="Forbidden label metadata field omitted.",
                        field=key,
                        details={"prefix": prefix},
                    )
                    continue

                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="forbidden_label_field",
                    message="Forbidden label metadata field rejected.",
                    field=key,
                    details={"prefix": prefix},
                )
                ok = False

    if isinstance(labels, Mapping):
        scan_mapping(labels, "labels")

        for container_key in ("records", "items", "rows"):
            if container_key in labels:
                for index, record in enumerate(_as_sequence(labels[container_key])):
                    if isinstance(record, Mapping):
                        scan_mapping(record, f"labels.{container_key}[{index}]")

        metadata = labels.get("metadata")

        if isinstance(metadata, Mapping):
            scan_mapping(metadata, "labels.metadata")
    else:
        metadata = getattr(labels, "metadata", None)

        if isinstance(metadata, Mapping):
            scan_mapping(metadata, "labels.metadata")

        records = getattr(labels, "records", None) or getattr(labels, "items", None)

        if records is not None:
            for index, record in enumerate(_as_sequence(records)):
                if isinstance(record, Mapping):
                    scan_mapping(record, f"labels.records[{index}]")
        elif isinstance(labels, Sequence) and not isinstance(labels, (str, bytes, bytearray, memoryview)):
            for index, record in enumerate(labels):
                if isinstance(record, Mapping):
                    scan_mapping(record, f"labels[{index}]")

    return ok


# -----------------------------------------------------------------------------
# Feature statistics and safe buckets
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _FeatureStats:
    feature: str
    numeric: list[float] = dataclass_field(default_factory=list)
    bool_true: int = 0
    bool_false: int = 0
    categories: Counter[str] = dataclass_field(default_factory=Counter)
    missing: int = 0
    total: int = 0


def _discover_feature_names(
    records: Sequence[Mapping[str, Any]],
    options: ExplainOptions,
    requested: Optional[Sequence[str]] = None,
) -> tuple[str, ...]:
    counts: Counter[str] = Counter()

    for record in records:
        features = record.get("features")

        if isinstance(features, Mapping):
            counts.update(_canonical_field_name(key) for key in features if _canonical_field_name(key))

    if requested is not None:
        names = [
            name
            for name in dict.fromkeys(_canonical_field_name(item) for item in requested if _canonical_field_name(item))
            if counts.get(name, 0) > 0
        ]
    else:
        names = [name for name, _count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]

    if len(names) > options.max_features:
        names = names[: options.max_features]

    return tuple(names)


def _build_feature_stats(
    records: Sequence[Mapping[str, Any]],
    feature_names: Sequence[str],
    options: ExplainOptions,
) -> dict[str, _FeatureStats]:
    stats = {
        feature: _FeatureStats(feature=feature)
        for feature in feature_names
    }

    for record in records:
        features = record.get("features")

        if not isinstance(features, Mapping):
            continue

        for feature in feature_names:
            stat = stats.get(feature)

            if stat is None:
                continue

            stat.total += 1
            kind, value = _classify_feature_value(features.get(feature))

            if kind == "missing":
                stat.missing += 1
            elif kind == "numeric":
                stat.numeric.append(float(value))
            elif kind == "boolean":
                if value:
                    stat.bool_true += 1
                else:
                    stat.bool_false += 1
            else:
                stat.categories[str(value)] += 1

    return stats


def _nonmissing_count(stats: _FeatureStats) -> int:
    return len(stats.numeric) + stats.bool_true + stats.bool_false + sum(stats.categories.values())


def _feature_priority(stats: _FeatureStats) -> float:
    nonmissing = _nonmissing_count(stats)

    if nonmissing <= 0:
        return 0.0

    variance = _stddev(stats.numeric) if len(stats.numeric) > 1 else 0.0
    diversity = float(len(stats.categories))
    return float(nonmissing) * (1.0 + variance + 0.1 * diversity)


def _select_candidate_features(
    stats: Mapping[str, _FeatureStats],
    options: ExplainOptions,
    requested: Optional[Sequence[str]] = None,
) -> tuple[str, ...]:
    if requested is not None:
        names = [
            name
            for name in dict.fromkeys(_canonical_field_name(item) for item in requested if _canonical_field_name(item))
            if name in stats and _nonmissing_count(stats[name]) > 0
        ]
    else:
        names = [
            name
            for name, stat in sorted(
                stats.items(),
                key=lambda item: (-_feature_priority(item[1]), item[0]),
            )
            # `item` is the sort key's parameter and is not in scope here; the
            # filter has to use the comprehension's own loop variable, or this
            # raises NameError for every explanation that reaches it.
            if _nonmissing_count(stat) > 0
        ]

    return tuple(names[: max(1, int(options.max_features))])


def _baseline_value(stats: _FeatureStats, policy: BaselinePolicy | str) -> Any:
    resolved_policy = _normalize_enum_option(BaselinePolicy, policy, BaselinePolicy.MEDIAN)

    if stats.numeric:
        if resolved_policy == BaselinePolicy.ZERO:
            return 0.0

        if resolved_policy == BaselinePolicy.MEAN:
            return _round6(_mean(stats.numeric))

        return _round6(_median(stats.numeric))

    if stats.bool_true + stats.bool_false > 0:
        if resolved_policy == BaselinePolicy.ZERO:
            return False

        return stats.bool_true >= stats.bool_false

    if stats.categories:
        return stats.categories.most_common(1)[0][0]

    return None


def _value_bucket(
    feature: str,
    value: Any,
    stats: Optional[_FeatureStats],
    options: ExplainOptions,
) -> str:
    if not options.include_value_buckets:
        return ""

    kind, parsed = _classify_feature_value(value)

    if kind == "missing" or parsed is None:
        return "missing"

    if kind == "boolean":
        return "true" if parsed else "false"

    if kind == "numeric":
        if stats is None or not stats.numeric:
            return "numeric"

        ordered = sorted(stats.numeric)
        position = bisect.bisect_right(ordered, float(parsed))
        percentile = float(position) / float(len(ordered))
        bucket_index = min(4, max(0, int(percentile * 5.0)))
        return f"q{bucket_index}"

    domain = f"muleguard.ml.explainability.bucket.{_normalize_token(options.namespace)}"
    return _hmac_hex(options.salt, domain, f"{feature}\x00{parsed}")[:10]


def _data_fingerprint(
    records: Sequence[Mapping[str, Any]],
    feature_names: Sequence[str],
    label_summary: Mapping[str, Any],
) -> str:
    payload = {
        "version": EXPLAINABILITY_VERSION,
        "record_count": len(records),
        "feature_count": len(feature_names),
        "feature_names_sample": list(feature_names[:_DEFAULT_MAX_SUMMARY_ITEMS]),
        "feature_names_truncated": len(feature_names) > _DEFAULT_MAX_SUMMARY_ITEMS,
        "label_summary": label_summary,
    }

    return _fingerprint_payload(payload)


# -----------------------------------------------------------------------------
# Label helpers
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _LabelIndex:
    by_subject: dict[str, int] = dataclass_field(default_factory=dict)
    by_source: list[Optional[int]] = dataclass_field(default_factory=list)


def _label_code_from_mapping(mapping: Mapping[Any, Any]) -> Any:
    """
    Extract a label-like code from a mapping.
    """
    for key in ("label_code", "label", "target", "y", "synthetic_label"):
        if key in mapping:
            return mapping[key]

    return None


def _subject_from_mapping(mapping: Mapping[Any, Any]) -> Any:
    """
    Extract a subject-like reference from a mapping.
    """
    for key in _SUBJECT_KEYS:
        if key in mapping:
            return mapping[key]

    return None


def _build_label_index(labels: Any, record_count: int, options: ExplainOptions) -> _LabelIndex:
    """
    Build a bounded label index from flexible label input.

    This index is internal-facing. Public summaries must expose only safe
    aggregate label statistics.
    """
    index = _LabelIndex(by_source=[None] * max(0, int(record_count)))

    if labels is None:
        return index

    def add_item(position: Optional[int], subject: Any, raw_label: Any) -> None:
        code = _coerce_int_label(raw_label)

        if code is None:
            return

        subject_hash = _subject_hash(subject, options) if subject is not None else None

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

            for position in range(min(len(subjects), len(codes), max(record_count, len(codes)))):
                add_item(position, subjects[position], codes[position])

            return index

        if records is not None:
            for position, record in enumerate(_as_sequence(records)):
                if isinstance(record, Mapping):
                    add_item(
                        position,
                        _subject_from_mapping(record),
                        _label_code_from_mapping(record),
                    )
                else:
                    add_item(position, None, record)

            return index

        if label_codes is not None:
            for position, code in enumerate(_as_sequence(label_codes)):
                add_item(position, None, code)

            return index

        code = _label_code_from_mapping(labels)

        if code is not None:
            add_item(0, _subject_from_mapping(labels), code)

        return index

    if hasattr(labels, "subject_hashes") and hasattr(labels, "label_codes"):
        subjects = _as_sequence(getattr(labels, "subject_hashes", ()) or ())
        codes = _as_sequence(getattr(labels, "label_codes", ()) or ())

        for position in range(min(len(subjects), len(codes), max(record_count, len(codes)))):
            add_item(position, subjects[position], codes[position])

        return index

    records = getattr(labels, "records", None) or getattr(labels, "items", None)

    if records is not None:
        for position, record in enumerate(_as_sequence(records)):
            if isinstance(record, Mapping):
                add_item(
                    position,
                    _subject_from_mapping(record),
                    _label_code_from_mapping(record),
                )
            else:
                add_item(position, None, record)

        return index

    for position, item in enumerate(_as_sequence(labels)):
        if isinstance(item, Mapping):
            add_item(
                position,
                _subject_from_mapping(item),
                _label_code_from_mapping(item),
            )
        else:
            add_item(position, None, item)

    return index


def _label_summary(label_index: _LabelIndex) -> dict[str, Any]:
    """
    Return a safe aggregate label summary.

    This never exposes subject-label pairs.
    """
    counter: Counter[int] = Counter()

    for code in label_index.by_source:
        if code is not None:
            counter[int(code)] += 1

    for code in label_index.by_subject.values():
        counter[int(code)] += 1

    total = sum(counter.values())

    distribution = {
        str(code): _round6(float(count) / float(total))
        for code, count in sorted(counter.items())
    } if total > 0 else {}

    return {
        "available": total > 0,
        "label_count": int(total),
        "class_count": int(len(counter)),
        "class_distribution": distribution,
        "records_omitted": True,
        "subject_label_pairs_omitted": True,
    }


def _binary_label(
    label_code: Optional[int],
    positive_codes: set[int],
    negative_codes: set[int],
    ignore_codes: set[int],
) -> Optional[int]:
    """
    Map a label code to binary 1/0/None.
    """
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


# -----------------------------------------------------------------------------
# Internal score snapshot helpers
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ScoreSnapshot:
    """
    Internal bounded score snapshot.

    This is not part of the public API.
    """

    subject_ref_hash: Optional[str] = None
    index: Optional[int] = None
    score: Optional[float] = None
    predicted_label: Optional[int] = None
    probabilities: Mapping[str, float] = dataclass_field(default_factory=dict)
    contributions: tuple[dict[str, Any], ...] = ()
    source: str = "none"
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

        object.__setattr__(
            self,
            "predicted_label",
            _coerce_int_label(self.predicted_label) if self.predicted_label is not None else None,
        )
        object.__setattr__(
            self,
            "probabilities",
            MappingProxyType(
                {
                    _clean_text(key, 100): _round6(
                        _clip_float(_coerce_optional_float(value, allow_bool=True), 0.0, 1.0, 0.0)
                    )
                    for key, value in (self.probabilities or {}).items()
                    if _coerce_optional_float(value, allow_bool=True) is not None
                }
            ),
        )
        object.__setattr__(self, "contributions", tuple(self.contributions or ()))
        object.__setattr__(self, "source", _clean_text(self.source, 64) or "none")
        object.__setattr__(self, "metadata", MappingProxyType(_safe_detail_value(self.metadata) or {}))


class _DetRandom:
    """
    Deterministic dependency-light pseudo-random generator.

    This is not cryptographically secure. It is used only for deterministic
    sampling, shuffling, and perturbation in bounded explainability workflows.
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

    def choice(self, seq: Sequence[Any]) -> Any:
        if not seq:
            return None

        return seq[self.randrange(len(seq))]

    def shuffle(self, values: list[Any]) -> None:
        for i in range(len(values) - 1, 0, -1):
            j = self.randrange(i + 1)
            values[i], values[j] = values[j], values[i]


def _deterministic_indices(
    n: int,
    count: int,
    options: ExplainOptions,
    domain: str,
    *parts: Any,
) -> list[int]:
    """
    Return deterministic sampled indices.
    """
    if n <= 0:
        return []

    count = max(0, min(int(count), n))

    if count >= n:
        return list(range(n))

    values = list(range(n))
    rng = _DetRandom(options.salt, domain, options.seed, options.namespace, n, count, *parts)
    rng.shuffle(values)
    return sorted(values[:count])


def _safe_summary_from_object(obj: Any) -> dict[str, Any]:
    """
    Return safe summary from an object exposing common summary methods.
    """
    if obj is None:
        return {}

    for name in ("to_public_dict", "safe_summary", "summary", "to_dict"):
        method = getattr(obj, name, None)

        if callable(method):
            try:
                payload = method()
            except Exception:
                continue

            if isinstance(payload, Mapping):
                sanitized = _safe_detail_value(payload)
                return sanitized if isinstance(sanitized, dict) else {}

    return {}


def _object_fingerprint(obj: Any) -> str:
    """
    Return deterministic safe fingerprint for an object when available.
    """
    if obj is None:
        return "none"

    fp = getattr(obj, "fingerprint", None)

    if callable(fp):
        try:
            return _clean_text(fp(), 128)
        except Exception:
            pass

    if isinstance(fp, str):
        return _clean_text(fp, 128)

    summary = _safe_summary_from_object(obj)

    if summary:
        return _fingerprint_payload(summary)

    return _sha256_hex(type(obj).__name__)[:32]


def _model_feature_names(model: Any) -> tuple[str, ...]:
    """
    Return fitted feature names for a model-like object when available.
    """
    if model is None:
        return ()

    params = getattr(model, "parameters", None)

    if params is not None:
        names = getattr(params, "feature_names", None)

        if names:
            return tuple(
                dict.fromkeys(
                    _canonical_field_name(name)
                    for name in names
                    if _canonical_field_name(name)
                )
            )

    names = getattr(model, "feature_names", None)

    if names:
        return tuple(
            dict.fromkeys(
                _canonical_field_name(name)
                for name in names
                if _canonical_field_name(name)
            )
        )

    return ()


def _is_prediction_sequence(model: Any) -> bool:
    """
    Return True when model input appears to be external prediction output.
    """
    if model is None:
        return False

    if isinstance(model, Mapping):
        return any(key in model for key in ("predictions", "records", "items", "rows", "scores"))

    if isinstance(model, (str, bytes, bytearray, memoryview)):
        return False

    if hasattr(model, "score") or hasattr(model, "infer") or hasattr(model, "parameters"):
        return False

    return isinstance(model, (Sequence, Iterable))


def _resolve_target(
    requested: Any,
    default: Any,
    model: Any,
) -> ExplanationTarget:
    """
    Resolve explanation target.
    """
    target = _normalize_enum_option(
        ExplanationTarget,
        requested if requested is not None else default,
        ExplanationTarget.AUTO,
    )

    if target != ExplanationTarget.AUTO:
        return target

    if model is None:
        return ExplanationTarget.FALLBACK

    if _is_prediction_sequence(model):
        return ExplanationTarget.EXTERNAL

    if supervised_module is not None and hasattr(model, "parameters"):
        return ExplanationTarget.SUPERVISED

    if hasattr(model, "score"):
        return ExplanationTarget.ANOMALY

    if hasattr(model, "infer"):
        return ExplanationTarget.MODEL_SERVICE

    if fallback_module is not None:
        return ExplanationTarget.FALLBACK

    return ExplanationTarget.EXTERNAL


def _contribution_from_mapping(
    mapping: Any,
    default_method: str,
    default_confidence: float = 0.70,
) -> Optional[Contribution]:
    """
    Convert a contribution-like mapping into a bounded Contribution.
    """
    if isinstance(mapping, Contribution):
        return mapping

    if not isinstance(mapping, Mapping):
        feature = _canonical_field_name(getattr(mapping, "feature", ""))

        if not feature:
            return None

        effect = _coerce_optional_float(getattr(mapping, "effect", 0.0), allow_bool=True) or 0.0
        magnitude = _coerce_optional_float(getattr(mapping, "magnitude", abs(effect)), allow_bool=True)
        return Contribution(
            feature=feature,
            effect=effect,
            magnitude=magnitude if magnitude is not None else abs(effect),
            direction=_clean_text(getattr(mapping, "direction", ""), 32),
            method=_clean_text(getattr(mapping, "method", default_method), 100) or default_method,
            confidence=_clip_float(_coerce_optional_float(getattr(mapping, "confidence", default_confidence), allow_bool=True), 0.0, 1.0, default_confidence),
            stability=_clip_float(_coerce_optional_float(getattr(mapping, "stability", default_confidence), allow_bool=True), 0.0, 1.0, default_confidence),
            sources=tuple(_clean_text(source, 100) for source in (getattr(mapping, "sources", (default_method,)) or (default_method,))),
            details=_safe_detail_value(getattr(mapping, "details", {})) or {},
        )

    feature = _canonical_field_name(mapping.get("feature"))

    if not feature:
        return None

    effect = _coerce_optional_float(mapping.get("effect"), allow_bool=True)

    if effect is None:
        effect = _coerce_optional_float(mapping.get("contribution"), allow_bool=True) or 0.0

    magnitude = _coerce_optional_float(mapping.get("magnitude"), allow_bool=True)

    if magnitude is None:
        magnitude = abs(float(effect))

    direction = _normalize_token(mapping.get("direction"))

    if direction not in {"increase", "decrease", "neutral"}:
        if float(effect) > 0:
            direction = "increase"
        elif float(effect) < 0:
            direction = "decrease"
        else:
            direction = "neutral"

    method = _clean_text(mapping.get("method"), 100) or default_method
    confidence = _clip_float(
        _coerce_optional_float(mapping.get("confidence"), allow_bool=True),
        0.0,
        1.0,
        default_confidence,
    )
    stability = _clip_float(
        _coerce_optional_float(mapping.get("stability"), allow_bool=True),
        0.0,
        1.0,
        confidence,
    )
    sources_raw = mapping.get("sources") or (method,)
    sources = tuple(
        dict.fromkeys(
            _clean_text(source, 100)
            for source in _as_sequence(sources_raw)
            if _clean_text(source, 100)
        )
    ) or (method,)

    return Contribution(
        feature=feature,
        effect=float(effect),
        magnitude=float(magnitude),
        direction=direction,
        method=method,
        value_bucket=_clean_text(mapping.get("value_bucket"), 64),
        baseline_bucket=_clean_text(mapping.get("baseline_bucket"), 64),
        confidence=confidence,
        stability=stability,
        sources=sources,
        details=_safe_detail_value(mapping.get("details")) or {},
    )


def _score_snapshot_from_item(
    item: Any,
    fallback_index: int,
    source: str,
) -> _ScoreSnapshot:
    """
    Convert one prediction-like item into one bounded score snapshot.
    """
    subject: Any = None
    index: Any = fallback_index
    score: Any = None
    predicted_label: Any = None
    probabilities: Any = None
    contributions: Any = None
    metadata: Any = None

    if isinstance(item, Mapping):
        subject = _subject_from_mapping(item)
        index = item.get("index", fallback_index)
        score = (
            item.get("score")
            if item.get("score") is not None
            else item.get("probability")
            if item.get("probability") is not None
            else item.get("positive_probability")
            if item.get("positive_probability") is not None
            else item.get("risk_score")
            if item.get("risk_score") is not None
            else item.get("anomaly_score")
        )
        predicted_label = (
            item.get("predicted_label")
            if item.get("predicted_label") is not None
            else item.get("label_code")
            if item.get("label_code") is not None
            else item.get("prediction")
            if item.get("prediction") is not None
            else item.get("y_pred")
        )
        probabilities = item.get("probabilities") or item.get("probability_map")
        contributions = item.get("contributions") or item.get("explanations") or item.get("feature_contributions")
        metadata = item.get("metadata")
    elif hasattr(item, "score") or hasattr(item, "probability") or hasattr(item, "risk_score"):
        subject = getattr(item, "subject_ref_hash", None) or getattr(item, "subject_hash", None)
        index = getattr(item, "index", fallback_index)
        score = (
            getattr(item, "score", None)
            if getattr(item, "score", None) is not None
            else getattr(item, "probability", None)
            if getattr(item, "probability", None) is not None
            else getattr(item, "positive_probability", None)
            if getattr(item, "positive_probability", None) is not None
            else getattr(item, "risk_score", None)
            if getattr(item, "risk_score", None) is not None
            else getattr(item, "anomaly_score", None)
        )
        predicted_label = (
            getattr(item, "predicted_label", None)
            if getattr(item, "predicted_label", None) is not None
            else getattr(item, "label_code", None)
            if getattr(item, "label_code", None) is not None
            else getattr(item, "prediction", None)
            if getattr(item, "prediction", None) is not None
            else getattr(item, "y_pred", None)
        )
        probabilities = getattr(item, "probabilities", None) or getattr(item, "probability_map", None)
        contributions = getattr(item, "contributions", None) or getattr(item, "explanations", None)
        metadata = getattr(item, "metadata", None)
    else:
        numeric = _coerce_optional_float(item, allow_bool=True)

        if numeric is not None:
            score = numeric

    score_float = _coerce_optional_float(score, allow_bool=True)
    predicted_int = _coerce_int_label(predicted_label)

    prob_map: dict[str, float] = {}

    if isinstance(probabilities, Mapping):
        for key, value in probabilities.items():
            numeric = _coerce_optional_float(value, allow_bool=True)

            if numeric is not None:
                prob_map[_clean_text(key, 100)] = _round6(_clip_float(numeric, 0.0, 1.0, 0.0))

    contrib_tuple: tuple[dict[str, Any], ...] = ()

    if contributions is not None:
        for contribution in _as_sequence(contributions):
            if isinstance(contribution, Mapping):
                contrib_tuple += (dict(contribution),)
            elif hasattr(contribution, "feature"):
                contrib_tuple += (
                    {
                        "feature": getattr(contribution, "feature", ""),
                        "effect": getattr(contribution, "effect", 0.0),
                        "magnitude": getattr(contribution, "magnitude", None),
                        "direction": getattr(contribution, "direction", ""),
                        "method": getattr(contribution, "method", source),
                        "confidence": getattr(contribution, "confidence", 0.7),
                        "stability": getattr(contribution, "stability", 0.7),
                        "sources": getattr(contribution, "sources", (source,)),
                        "details": getattr(contribution, "details", {}),
                    },
                )

    if score_float is None and predicted_int is not None:
        score_float = 1.0 if predicted_int in set(_DEFAULT_POSITIVE_LABEL_CODES) else 0.0

    if score_float is None and prob_map:
        positive_candidates = [
            value
            for key, value in prob_map.items()
            if _normalize_token(key) in {
                "review",
                "escalate",
                "positive",
                "investigate",
                "high_priority",
                "critical",
                "urgent",
            }
        ]

        if positive_candidates:
            score_float = max(positive_candidates)
        else:
            score_float = max(prob_map.values())

    return _ScoreSnapshot(
        subject_ref_hash=subject,
        index=_as_int(index, fallback_index) if index is not None else fallback_index,
        score=score_float,
        predicted_label=predicted_int,
        probabilities=prob_map,
        contributions=contrib_tuple,
        source=source,
        metadata=metadata,
    )


def _snapshots_from_object(obj: Any, source: str) -> tuple[_ScoreSnapshot, ...]:
    """
    Convert batch-like objects into bounded score snapshots.
    """
    if obj is None:
        return ()

    items: list[Any] = []

    if isinstance(obj, Mapping):
        for key in ("predictions", "records", "items", "rows", "scores", "probabilities", "values"):
            if key in obj and not isinstance(obj[key], Mapping):
                items = _as_sequence(obj[key])
                break
        else:
            items = [obj]
    elif isinstance(obj, (str, bytes, bytearray, memoryview)):
        return ()
    elif hasattr(obj, "predictions"):
        items = _as_sequence(getattr(obj, "predictions", ()) or ())
    elif hasattr(obj, "records"):
        items = _as_sequence(getattr(obj, "records", ()) or ())
    elif hasattr(obj, "items") and not callable(getattr(obj, "items", None)):
        items = _as_sequence(getattr(obj, "items", ()) or ())
    elif hasattr(obj, "rows"):
        items = _as_sequence(getattr(obj, "rows", ()) or ())
    elif isinstance(obj, Sequence):
        items = list(obj)
    elif isinstance(obj, Iterable):
        try:
            items = list(obj)
        except Exception:
            items = [obj]
    else:
        items = [obj]

    return tuple(
        _score_snapshot_from_item(item, index, source)
        for index, item in enumerate(items)
    )


def _score_with_fallback(
    records: Sequence[Mapping[str, Any]],
    options: ExplainOptions,
    issues: list[ExplanationIssue],
) -> tuple[_ScoreSnapshot, ...]:
    """
    Score records using heuristic fallback when available.
    """
    if fallback_module is None or not hasattr(fallback_module, "score_fallback_batch"):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="fallback_module_unavailable",
            message="Fallback scoring module is unavailable.",
        )
        return ()

    try:
        result = fallback_module.score_fallback_batch(list(records))
    except Exception as exc:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="fallback_scoring_failed",
            message="Fallback scoring failed.",
            details={"exception_type": type(exc).__name__},
        )
        return ()

    return _snapshots_from_object(result, ExplanationTarget.FALLBACK.value)


def _score_records(
    records: Sequence[Mapping[str, Any]],
    request: ExplanationRequest,
    options: ExplainOptions,
    issues: list[ExplanationIssue],
) -> tuple[_ScoreSnapshot, ...]:
    """
    Resolve bounded score snapshots for records.

    This supports supervised models, anomaly models, model-service objects,
    fallback scoring, external prediction sequences, and simple callables.
    """
    if not records:
        return ()

    target = _resolve_target(request.target, options.target, request.model)
    model = request.model
    raw_snapshots: tuple[_ScoreSnapshot, ...] = ()

    if model is None:
        raw_snapshots = _score_with_fallback(records, options, issues)
    elif target == ExplanationTarget.EXTERNAL or _is_prediction_sequence(model):
        raw_snapshots = _snapshots_from_object(model, ExplanationTarget.EXTERNAL.value)
    elif (
        target in {ExplanationTarget.SUPERVISED, ExplanationTarget.AUTO}
        and supervised_module is not None
        and hasattr(model, "parameters")
        and hasattr(supervised_module, "predict_supervised_model")
    ):
        try:
            batch = supervised_module.predict_supervised_model(
                model,
                list(records),
                include_contributions=True,
            )
            raw_snapshots = _snapshots_from_object(batch, ExplanationTarget.SUPERVISED.value)
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="supervised_prediction_failed",
                message="Supervised prediction failed.",
                details={"exception_type": type(exc).__name__},
            )

    if (
        not raw_snapshots
        and target in {ExplanationTarget.ANOMALY, ExplanationTarget.AUTO}
        and hasattr(model, "score")
    ):
        try:
            result = model.score(list(records), include_contributions=True)
            raw_snapshots = _snapshots_from_object(result, ExplanationTarget.ANOMALY.value)
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="anomaly_scoring_failed",
                message="Anomaly scoring failed.",
                details={"exception_type": type(exc).__name__},
            )

    if (
        not raw_snapshots
        and target in {ExplanationTarget.MODEL_SERVICE, ExplanationTarget.AUTO}
        and hasattr(model, "infer")
    ):
        try:
            response = model.infer(
                {
                    "records": list(records),
                    "model_id": request.model_id,
                    "mode": target.value,
                    "include_contributions": True,
                }
            )
            raw_snapshots = _snapshots_from_object(response, ExplanationTarget.MODEL_SERVICE.value)
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="model_service_infer_failed",
                message="Model service inference failed.",
                details={"exception_type": type(exc).__name__},
            )

    if not raw_snapshots and target in {ExplanationTarget.FALLBACK, ExplanationTarget.AUTO}:
        raw_snapshots = _score_with_fallback(records, options, issues)

    if not raw_snapshots and callable(model):
        try:
            output = model(list(records))
            raw_snapshots = _snapshots_from_object(output, "callable")
        except Exception as exc:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="callable_model_scoring_failed",
                message="Callable model scoring failed.",
                details={"exception_type": type(exc).__name__},
            )

    if not raw_snapshots:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="no_scores_available",
            message="No scores could be resolved for explanation.",
        )
        return ()

    by_subject: dict[str, _ScoreSnapshot] = {}
    by_index: dict[int, _ScoreSnapshot] = {}

    for snapshot in raw_snapshots:
        if snapshot.subject_ref_hash:
            by_subject.setdefault(snapshot.subject_ref_hash, snapshot)

        if snapshot.index is not None:
            by_index.setdefault(int(snapshot.index), snapshot)

    aligned: list[_ScoreSnapshot] = []

    for position, record in enumerate(records):
        subject = record.get("subject_ref_hash")
        snapshot = by_index.get(position)

        if snapshot is None and subject:
            snapshot = by_subject.get(str(subject).lower())

        if snapshot is None:
            aligned.append(
                _ScoreSnapshot(
                    subject_ref_hash=subject,
                    index=position,
                    source="none",
                )
            )
            continue

        aligned.append(
            replace(
                snapshot,
                subject_ref_hash=subject or snapshot.subject_ref_hash,
                index=position,
            )
        )

    return tuple(aligned)


# -----------------------------------------------------------------------------
# Coefficient attribution helpers
# -----------------------------------------------------------------------------


def _extract_coefficients(
    model: Any,
    feature_names: Sequence[str],
    target_label: Optional[int],
    issues: list[ExplanationIssue],
    options: ExplainOptions,
) -> Optional[dict[str, float]]:
    """
    Extract bounded linear coefficients from a supervised model when available.
    """
    if model is None or supervised_module is None:
        return None

    params = getattr(model, "parameters", None)

    if params is None:
        return None

    weights = getattr(params, "weights", None)

    if weights is None:
        return None

    rows = list(_as_sequence(weights))

    if not rows:
        return None

    classes = tuple(
        _coerce_int_label(code)
        for code in _as_sequence(getattr(params, "classes", ()) or ())
        if _coerce_int_label(code) is not None
    )
    model_features = tuple(
        _canonical_field_name(name)
        for name in _as_sequence(getattr(params, "feature_names", ()) or ())
        if _canonical_field_name(name)
    )

    resolved_target = target_label

    if resolved_target is None and classes:
        resolved_target = max(classes)

    if len(rows) == 1:
        row = list(_as_sequence(rows[0]))
    else:
        if resolved_target is not None and resolved_target in classes:
            index = classes.index(resolved_target)
        else:
            index = len(rows) - 1

        index = max(0, min(index, len(rows) - 1))
        row = list(_as_sequence(rows[index]))

    coefficients: dict[str, float] = {}
    names = model_features if model_features else tuple(feature_names)

    for position, name in enumerate(names):
        if position >= len(row):
            break

        numeric = _coerce_optional_float(row[position], allow_bool=True)

        if numeric is None:
            continue

        coefficients[name] = _round6(_clip_float(numeric, -1e6, 1e6, 0.0))

    if not coefficients:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="coefficients_unavailable",
            message="No usable linear coefficients were extracted.",
        )
        return None

    return coefficients


def _coefficient_global_map(
    coefficients: Optional[Mapping[str, float]],
    stats: Mapping[str, _FeatureStats],
    options: ExplainOptions,
) -> dict[str, dict[str, Any]]:
    """
    Build a bounded global coefficient importance map.
    """
    if not coefficients:
        return {}

    out: dict[str, dict[str, Any]] = {}

    for feature, coef in coefficients.items():
        stat = stats.get(feature)
        scale = 1.0

        if stat is not None and len(stat.numeric) > 1:
            scale = max(_stddev(stat.numeric), 1e-6)

        raw = abs(float(coef)) * scale
        out[feature] = {
            "score": _round6(raw),
            "mean_abs_effect": _round6(raw),
            "stability": 1.0,
            "sources": ("coefficient",),
            "coefficient": _round6(float(coef)),
            "scale": _round6(scale),
        }

    return out


def _coefficient_local_contributions(
    record: Mapping[str, Any],
    coefficients: Optional[Mapping[str, float]],
    stats: Mapping[str, _FeatureStats],
    options: ExplainOptions,
) -> tuple[Contribution, ...]:
    """
    Build bounded local coefficient contributions for one record.
    """
    if not coefficients:
        return ()

    features = record.get("features")

    if not isinstance(features, Mapping):
        return ()

    out: list[Contribution] = []

    for feature, coef in coefficients.items():
        stat = stats.get(feature)
        baseline = _baseline_value(stat, options.baseline_policy) if stat is not None else None
        kind, value = _classify_feature_value(features.get(feature))
        effect = 0.0

        if kind == "numeric" and isinstance(baseline, (int, float)):
            scale = 1.0

            if stat is not None and len(stat.numeric) > 1:
                scale = max(_stddev(stat.numeric), 1e-6)

            effect = float(coef) * (float(value) - float(baseline)) / scale
        elif kind == "boolean" and isinstance(baseline, bool):
            effect = float(coef) * (float(bool(value)) - float(baseline))
        elif kind == "categorical":
            if baseline is None:
                effect = float(coef)
            else:
                effect = float(coef) if str(value) != str(baseline) else 0.0

        effect = _clip_float(effect, -10.0, 10.0, 0.0)

        if abs(effect) <= 1e-12:
            continue

        out.append(
            Contribution(
                feature=feature,
                effect=effect,
                magnitude=abs(effect),
                method=ExplanationMethod.COEFFICIENT.value,
                value_bucket=_value_bucket(feature, value, stat, options),
                baseline_bucket=_value_bucket(feature, baseline, stat, options),
                confidence=0.90,
                stability=1.00,
                sources=(ExplanationMethod.COEFFICIENT.value,),
                details={
                    "coefficient": _round6(float(coef)),
                    "feature_kind": kind,
                },
            )
        )

    return tuple(out)


# -----------------------------------------------------------------------------
# Native contribution helpers
# -----------------------------------------------------------------------------


def _native_global_map(
    snapshots: Sequence[_ScoreSnapshot],
    options: ExplainOptions,
) -> dict[str, dict[str, Any]]:
    """
    Aggregate native model contributions into a bounded global map.
    """
    aggregates: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "sum_magnitude": 0.0,
            "sum_effect": 0.0,
            "count": 0,
            "sources": set(),
            "confidence": 0.0,
            "stability": 0.0,
        }
    )

    for snapshot in snapshots:
        for raw in snapshot.contributions:
            contribution = _contribution_from_mapping(raw, snapshot.source or "model_contributions", 0.75)

            if contribution is None:
                continue

            bucket = aggregates[contribution.feature]
            bucket["sum_magnitude"] += float(contribution.magnitude)
            bucket["sum_effect"] += float(contribution.effect)
            bucket["count"] += 1
            bucket["sources"].update(contribution.sources or (snapshot.source,))
            bucket["confidence"] += float(contribution.confidence)
            bucket["stability"] += float(contribution.stability)

    out: dict[str, dict[str, Any]] = {}

    for feature, bucket in aggregates.items():
        count = max(1, int(bucket["count"]))
        mean_abs = float(bucket["sum_magnitude"]) / float(count)
        out[feature] = {
            "score": _round6(mean_abs),
            "mean_abs_effect": _round6(mean_abs),
            "mean_effect": _round6(float(bucket["sum_effect"]) / float(count)),
            "count": count,
            "stability": _round6(float(bucket["stability"]) / float(count)),
            "confidence": _round6(float(bucket["confidence"]) / float(count)),
            "sources": tuple(sorted(bucket["sources"])) or (ExplanationMethod.MODEL_CONTRIBUTIONS.value,),
        }

    return out


def _native_local_contributions(
    snapshot: _ScoreSnapshot,
    options: ExplainOptions,
) -> tuple[Contribution, ...]:
    """
    Convert native snapshot contributions into bounded Contribution objects.
    """
    out: list[Contribution] = []

    for raw in snapshot.contributions:
        contribution = _contribution_from_mapping(
            raw,
            snapshot.source or ExplanationMethod.MODEL_CONTRIBUTIONS.value,
            0.75,
        )

        if contribution is not None:
            out.append(contribution)

    return tuple(out)


# -----------------------------------------------------------------------------
# Perturbation and surrogate helpers
# -----------------------------------------------------------------------------


def _sample_feature_value(
    stat: Optional[_FeatureStats],
    rng: _DetRandom,
    sorted_numeric: Optional[Sequence[float]] = None,
) -> Any:
    """
    Sample one plausible feature value from bounded empirical statistics.
    """
    if stat is None:
        return None

    if stat.numeric:
        ordered = list(sorted_numeric) if sorted_numeric is not None else sorted(stat.numeric)

        if not ordered:
            return None

        return _round6(_quantile_sorted(ordered, rng.random()))

    bool_total = stat.bool_true + stat.bool_false

    if bool_total > 0:
        p = float(stat.bool_true) / float(bool_total)
        return rng.random() < p

    if stat.categories:
        items = list(stat.categories.items())
        total = sum(count for _category, count in items)

        if total <= 0:
            return items[0][0] if items else None

        target = rng.random() * float(total)
        cumulative = 0.0

        for category, count in items:
            cumulative += float(count)

            if target <= cumulative:
                return category

        return items[-1][0]

    return None


def _transform_vector(
    sample_features: Mapping[str, Any],
    instance_features: Mapping[str, Any],
    selected_features: Sequence[str],
    stats: Mapping[str, _FeatureStats],
    options: ExplainOptions,
) -> list[float]:
    """
    Transform selected features into a bounded numeric vector for local
    surrogate fitting.
    """
    out: list[float] = []

    for feature in selected_features:
        stat = stats.get(feature)
        s_kind, s_value = _classify_feature_value(sample_features.get(feature))
        i_kind, i_value = _classify_feature_value(instance_features.get(feature))

        if s_kind == "missing":
            out.append(0.0)
            continue

        if s_kind == "numeric" and i_kind == "numeric":
            baseline = _baseline_value(stat, options.baseline_policy) if stat is not None else 0.0
            scale = 1.0

            if stat is not None and len(stat.numeric) > 1:
                scale = max(_stddev(stat.numeric), 1e-6)

            base = float(baseline) if isinstance(baseline, (int, float)) else 0.0
            out.append(_clip_float((float(s_value) - base) / scale, -100.0, 100.0, 0.0))
            continue

        if s_kind == "boolean" and i_kind == "boolean":
            out.append(1.0 if bool(s_value) else 0.0)
            continue

        if s_kind == "categorical" and i_kind == "categorical":
            out.append(1.0 if str(s_value) == str(i_value) else 0.0)
            continue

        out.append(1.0 if str(s_value) == str(i_value) else 0.0)

    return out


def _solve_linear(matrix: Sequence[Sequence[float]], rhs: Sequence[float]) -> list[float]:
    """
    Solve a small dense linear system using Gauss-Jordan elimination.

    Returns zeros when solving fails.
    """
    n = len(matrix)

    if n <= 0:
        return []

    augmented: list[list[float]] = []

    for i, row in enumerate(matrix):
        if len(row) != n:
            return [0.0 for _ in range(n)]

        values = [float(value) if math.isfinite(float(value)) else 0.0 for value in row]
        values.append(float(rhs[i]) if i < len(rhs) and math.isfinite(float(rhs[i])) else 0.0)
        augmented.append(values)

    for col in range(n):
        pivot_row = max(range(col, n), key=lambda r: abs(augmented[r][col]))
        pivot_value = augmented[pivot_row][col]

        if abs(pivot_value) < 1e-12:
            augmented[col][col] += 1e-8
            pivot_value = augmented[col][col]

            if abs(pivot_value) < 1e-12:
                return [0.0 for _ in range(n)]

        if pivot_row != col:
            augmented[col], augmented[pivot_row] = augmented[pivot_row], augmented[col]
            pivot_value = augmented[col][col]

        for j in range(col, n + 1):
            augmented[col][j] /= pivot_value

        for row in range(n):
            if row == col:
                continue

            factor = augmented[row][col]

            if abs(factor) < 1e-15:
                continue

            for j in range(col, n + 1):
                augmented[row][j] -= factor * augmented[col][j]

    out: list[float] = []

    for i in range(n):
        value = augmented[i][n]
        out.append(value if math.isfinite(value) else 0.0)

    return out


def _fit_ridge(
    x_matrix: Sequence[Sequence[float]],
    y_values: Sequence[float],
    weights: Sequence[float],
    alpha: float,
    feature_count: int,
) -> tuple[list[float], float]:
    """
    Fit a bounded weighted ridge regression.

    Returns coefficients and pseudo R².
    """
    n = len(x_matrix)

    if n <= 0 or feature_count <= 0:
        return [0.0 for _ in range(feature_count)], 0.0

    weight_sum = sum(float(weight) for weight in weights if float(weight) > 0)

    if weight_sum <= 0:
        return [0.0 for _ in range(feature_count)], 0.0

    x_bar = [0.0 for _ in range(feature_count)]
    y_bar = 0.0

    for i in range(n):
        w = max(0.0, float(weights[i]))

        if w <= 0:
            continue

        y_bar += w * float(y_values[i])

        for j in range(feature_count):
            x_bar[j] += w * float(x_matrix[i][j])

    y_bar /= weight_sum

    for j in range(feature_count):
        x_bar[j] /= weight_sum

    a_matrix = [[alpha if i == j else 0.0 for j in range(feature_count)] for i in range(feature_count)]
    b_vector = [0.0 for _ in range(feature_count)]
    sst = 0.0

    for i in range(n):
        w = max(0.0, float(weights[i]))

        if w <= 0:
            continue

        yc = float(y_values[i]) - y_bar
        sst += w * yc * yc

        xc = [float(x_matrix[i][j]) - x_bar[j] for j in range(feature_count)]

        for j in range(feature_count):
            b_vector[j] += w * xc[j] * yc

            for k in range(feature_count):
                a_matrix[j][k] += w * xc[j] * xc[k]

    beta = _solve_linear(a_matrix, b_vector)

    if len(beta) != feature_count:
        beta = [0.0 for _ in range(feature_count)]

    sse = 0.0

    for i in range(n):
        w = max(0.0, float(weights[i]))

        if w <= 0:
            continue

        yc = float(y_values[i]) - y_bar
        xc = [float(x_matrix[i][j]) - x_bar[j] for j in range(feature_count)]
        pred = sum(beta[j] * xc[j] for j in range(feature_count))
        sse += w * (yc - pred) ** 2

    r2 = 1.0 - (sse / sst) if sst > 0 else 0.0
    r2 = _clip_float(r2, 0.0, 1.0, 0.0)

    return [_round6(value) for value in beta], _round6(r2)


def _select_local_features(
    record: Mapping[str, Any],
    feature_names: Sequence[str],
    stats: Mapping[str, _FeatureStats],
    coefficients: Optional[Mapping[str, float]],
    options: ExplainOptions,
) -> tuple[str, ...]:
    """
    Select bounded local features for surrogate and sensitivity analysis.
    """
    features = record.get("features")

    if not isinstance(features, Mapping):
        features = {}

    scored: list[tuple[float, str]] = []

    for feature in feature_names:
        stat = stats.get(feature)

        if stat is None or _nonmissing_count(stat) <= 0:
            continue

        priority = _feature_priority(stat)
        coef = abs(float(coefficients.get(feature, 0.0))) if coefficients else 0.0
        present = 1.0 if feature in features and _classify_feature_value(features.get(feature))[0] != "missing" else 0.0
        scored.append((priority + 10.0 * coef + 0.5 * present, feature))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return tuple(feature for _score, feature in scored[: max(1, int(options.max_local_features))])


def _local_surrogate_contributions(
    record: Mapping[str, Any],
    snapshot: _ScoreSnapshot,
    feature_names: Sequence[str],
    stats: Mapping[str, _FeatureStats],
    coefficients: Optional[Mapping[str, float]],
    request: ExplanationRequest,
    options: ExplainOptions,
    start_time: float,
) -> tuple[tuple[Contribution, ...], dict[str, float], float]:
    """
    Fit a bounded local surrogate and return local contributions, global beta
    magnitudes, and confidence.
    """
    if snapshot.score is None:
        return (), {}, 0.0

    selected = _select_local_features(record, feature_names, stats, coefficients, options)

    if not selected:
        return (), {}, 0.0

    n_samples = max(8, min(int(options.max_local_samples), 128))
    rng = _DetRandom(
        options.salt,
        f"muleguard.ml.explainability.surrogate.{_normalize_token(options.namespace)}",
        options.seed,
        record.get("index", 0),
        len(selected),
        n_samples,
    )

    sorted_numerics = {
        feature: sorted(stats[feature].numeric)
        for feature in selected
        if feature in stats and stats[feature].numeric
    }

    perturbed: list[dict[str, Any]] = []

    for sample_index in range(n_samples):
        features = dict(record.get("features") or {})

        for feature in selected:
            features[feature] = _sample_feature_value(
                stats.get(feature),
                rng,
                sorted_numerics.get(feature),
            )

        perturbed.append(
            {
                "index": sample_index,
                "source_index": record.get("index"),
                "subject_ref_hash": record.get("subject_ref_hash"),
                "features": features,
            }
        )

    perturbed.append(
        {
            "index": n_samples,
            "source_index": record.get("index"),
            "subject_ref_hash": record.get("subject_ref_hash"),
            "features": dict(record.get("features") or {}),
        }
    )

    internal_issues: list[ExplanationIssue] = []
    sample_snapshots = _score_records(perturbed, request, options, internal_issues)

    if len(sample_snapshots) != len(perturbed):
        return (), {}, 0.0

    instance_features = record.get("features") if isinstance(record.get("features"), Mapping) else {}
    instance_z = _transform_vector(instance_features, instance_features, selected, stats, options)

    x_matrix: list[list[float]] = []
    y_values: list[float] = []
    weights: list[float] = []

    for sample, sample_snapshot in zip(perturbed, sample_snapshots):
        score = sample_snapshot.score

        if score is None:
            continue

        sample_features = sample.get("features") if isinstance(sample.get("features"), Mapping) else {}
        z = _transform_vector(sample_features, instance_features, selected, stats, options)
        distance_sq = sum((zi - zj) ** 2 for zi, zj in zip(z, instance_z))
        x_matrix.append(z)
        y_values.append(float(score))
        weights.append(math.exp(-0.5 * float(distance_sq)))

    if len(x_matrix) < 4:
        return (), {}, 0.0

    median_weight = _median(weights) if weights else 1.0

    if median_weight <= 0:
        weights = [1.0 for _ in weights]
    else:
        weights = [max(1e-6, float(weight) / float(median_weight)) for weight in weights]

    beta, r2 = _fit_ridge(
        x_matrix,
        y_values,
        weights,
        max(1e-6, float(options.ridge_alpha)),
        len(selected),
    )

    contributions: list[Contribution] = []
    global_terms: dict[str, float] = {}

    for feature, coefficient, z_inst in zip(selected, beta, instance_z):
        effect = float(coefficient) * float(z_inst)
        effect = _clip_float(effect, -10.0, 10.0, 0.0)
        magnitude = abs(effect)
        global_terms[feature] = abs(float(coefficient))

        stat = stats.get(feature)
        baseline = _baseline_value(stat, options.baseline_policy) if stat is not None else None
        kind, value = _classify_feature_value(instance_features.get(feature))

        if magnitude <= 1e-12:
            continue

        contributions.append(
            Contribution(
                feature=feature,
                effect=effect,
                magnitude=magnitude,
                method=ExplanationMethod.LOCAL_SURROGATE.value,
                value_bucket=_value_bucket(feature, value, stat, options),
                baseline_bucket=_value_bucket(feature, baseline, stat, options),
                confidence=_clip_float(r2, 0.05, 1.0, 0.30),
                stability=_clip_float(r2, 0.05, 1.0, 0.30),
                sources=(ExplanationMethod.LOCAL_SURROGATE.value,),
                details={
                    "local_coefficient": _round6(float(coefficient)),
                    "pseudo_r2": _round6(float(r2)),
                    "sample_count": len(x_matrix),
                },
            )
        )

    return tuple(contributions), global_terms, _clip_float(r2, 0.05, 1.0, 0.30)


def _sensitivity_local_contributions(
    record: Mapping[str, Any],
    snapshot: _ScoreSnapshot,
    feature_names: Sequence[str],
    stats: Mapping[str, _FeatureStats],
    coefficients: Optional[Mapping[str, float]],
    request: ExplanationRequest,
    options: ExplainOptions,
    start_time: float,
) -> tuple[Contribution, ...]:
    """
    Build bounded local sensitivity contributions by ablating selected features
    to baseline values.
    """
    if snapshot.score is None:
        return ()

    selected = _select_local_features(record, feature_names, stats, coefficients, options)

    if not selected:
        return ()

    varied: list[dict[str, Any]] = []
    varied_features: list[str] = []

    for feature in selected:
        stat = stats.get(feature)
        baseline = _baseline_value(stat, options.baseline_policy) if stat is not None else None

        if baseline is None:
            continue

        features = dict(record.get("features") or {})
        features[feature] = baseline

        varied.append(
            {
                "index": len(varied),
                "source_index": record.get("index"),
                "subject_ref_hash": record.get("subject_ref_hash"),
                "features": features,
            }
        )
        varied_features.append(feature)

        if _time_exceeded(start_time, options.max_time_ms) or len(varied) >= options.max_local_features:
            break

    if not varied:
        return ()

    internal_issues: list[ExplanationIssue] = []
    varied_snapshots = _score_records(varied, request, options, internal_issues)

    contributions: list[Contribution] = []

    for feature, varied_snapshot in zip(varied_features, varied_snapshots):
        if varied_snapshot.score is None:
            continue

        effect = float(snapshot.score) - float(varied_snapshot.score)
        effect = _clip_float(effect, -10.0, 10.0, 0.0)

        if abs(effect) <= 1e-12:
            continue

        stat = stats.get(feature)
        baseline = _baseline_value(stat, options.baseline_policy) if stat is not None else None
        kind, value = _classify_feature_value((record.get("features") or {}).get(feature))

        contributions.append(
            Contribution(
                feature=feature,
                effect=effect,
                magnitude=abs(effect),
                method=ExplanationMethod.SENSITIVITY.value,
                value_bucket=_value_bucket(feature, value, stat, options),
                baseline_bucket=_value_bucket(feature, baseline, stat, options),
                confidence=0.60,
                stability=0.60,
                sources=(ExplanationMethod.SENSITIVITY.value,),
                details={
                    "baseline_score": _round6(float(varied_snapshot.score)),
                    "original_score": _round6(float(snapshot.score)),
                },
            )
        )

    return tuple(contributions)


def _sensitivity_global_map(
    records: Sequence[Mapping[str, Any]],
    snapshots: Sequence[_ScoreSnapshot],
    feature_names: Sequence[str],
    stats: Mapping[str, _FeatureStats],
    request: ExplanationRequest,
    options: ExplainOptions,
    issues: list[ExplanationIssue],
    start_time: float,
) -> dict[str, dict[str, Any]]:
    """
    Build bounded global sensitivity importance by ablating features to
    baseline values on a deterministic sample.
    """
    if not records or not snapshots:
        return {}

    sample_size = min(len(records), 256, max(16, int(options.max_permutation_records)))
    sample_indices = _deterministic_indices(
        len(records),
        sample_size,
        options,
        "sensitivity_sample",
        len(records),
        sample_size,
    )

    sample_records = [dict(records[index]) for index in sample_indices]
    original_scores = [snapshots[index].score for index in sample_indices]
    out: dict[str, dict[str, Any]] = {}

    for feature in feature_names[: max(1, int(options.max_global_features))]:
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="sensitivity_time_budget_exhausted",
                message="Global sensitivity analysis stopped after reaching configured time budget.",
                field=feature,
            )
            break

        stat = stats.get(feature)
        baseline = _baseline_value(stat, options.baseline_policy) if stat is not None else None

        if baseline is None:
            continue

        varied: list[dict[str, Any]] = []
        original_subset: list[float] = []

        for position, record in enumerate(sample_records):
            score = original_scores[position]

            if score is None:
                continue

            features = dict(record.get("features") or {})
            features[feature] = baseline
            varied.append({**record, "index": len(varied), "features": features})
            original_subset.append(float(score))

        if not varied:
            continue

        internal_issues: list[ExplanationIssue] = []
        varied_snapshots = _score_records(varied, request, options, internal_issues)
        deltas: list[float] = []

        for original, varied_snapshot in zip(original_subset, varied_snapshots):
            if varied_snapshot.score is None:
                continue

            deltas.append(abs(float(original) - float(varied_snapshot.score)))

        if not deltas:
            continue

        score = _round6(_mean(deltas))
        out[feature] = {
            "score": score,
            "mean_abs_effect": score,
            "stability": 0.65,
            "sources": (ExplanationMethod.SENSITIVITY.value,),
            "sample_count": len(deltas),
        }

    return out


def _permutation_global_map(
    records: Sequence[Mapping[str, Any]],
    snapshots: Sequence[_ScoreSnapshot],
    feature_names: Sequence[str],
    request: ExplanationRequest,
    options: ExplainOptions,
    issues: list[ExplanationIssue],
    start_time: float,
) -> dict[str, dict[str, Any]]:
    """
    Build bounded global permutation importance by deterministically permuting
    feature values on a sample.
    """
    if not records or not snapshots:
        return {}

    sample_size = min(len(records), 512, max(32, int(options.max_permutation_records)))
    sample_indices = _deterministic_indices(
        len(records),
        sample_size,
        options,
        "permutation_sample",
        len(records),
        sample_size,
    )

    sample_records = [dict(records[index]) for index in sample_indices]
    original_scores = [snapshots[index].score for index in sample_indices]
    out: dict[str, dict[str, Any]] = {}

    for feature in feature_names[: max(1, int(options.max_global_features))]:
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="permutation_time_budget_exhausted",
                message="Global permutation analysis stopped after reaching configured time budget.",
                field=feature,
            )
            break

        values = [record.get("features", {}).get(feature) for record in sample_records]
        rng = _DetRandom(
            options.salt,
            f"muleguard.ml.explainability.permutation.{_normalize_token(options.namespace)}",
            options.seed,
            feature,
            len(values),
        )
        shuffled = list(values)
        rng.shuffle(shuffled)

        permuted: list[dict[str, Any]] = []
        original_subset: list[float] = []

        for position, record in enumerate(sample_records):
            score = original_scores[position]

            if score is None:
                continue

            features = dict(record.get("features") or {})
            features[feature] = shuffled[position]
            permuted.append({**record, "index": len(permuted), "features": features})
            original_subset.append(float(score))

        if not permuted:
            continue

        internal_issues: list[ExplanationIssue] = []
        permuted_snapshots = _score_records(permuted, request, options, internal_issues)
        deltas: list[float] = []

        for original, permuted_snapshot in zip(original_subset, permuted_snapshots):
            if permuted_snapshot.score is None:
                continue

            deltas.append(abs(float(original) - float(permuted_snapshot.score)))

        if not deltas:
            continue

        score = _round6(_mean(deltas))
        out[feature] = {
            "score": score,
            "mean_abs_effect": score,
            "stability": 0.55,
            "sources": (ExplanationMethod.PERMUTATION.value,),
            "sample_count": len(deltas),
        }

    return out


# -----------------------------------------------------------------------------
# Aggregation helpers
# -----------------------------------------------------------------------------


def _estimate_stability(sources: Sequence[tuple[str, Sequence[Contribution]]]) -> float:
    """
    Estimate bounded local stability from agreement across methods.
    """
    vectors: list[dict[str, float]] = []

    for _method, contributions in sources:
        vector = {
            contribution.feature: max(0.0, float(contribution.magnitude))
            for contribution in contributions
            if contribution.feature
        }

        if vector:
            vectors.append(vector)

    if not vectors:
        return 0.0

    if len(vectors) == 1:
        values = list(vectors[0].values())
        return _clip_float(_mean([min(1.0, value) for value in values]), 0.0, 1.0, 0.5)

    similarities: list[float] = []
    features = sorted({feature for vector in vectors for feature in vector})

    for i in range(len(vectors)):
        for j in range(i + 1, len(vectors)):
            left = vectors[i]
            right = vectors[j]
            dot = 0.0
            left_norm = 0.0
            right_norm = 0.0

            for feature in features:
                a = float(left.get(feature, 0.0))
                b = float(right.get(feature, 0.0))
                dot += a * b
                left_norm += a * a
                right_norm += b * b

            if left_norm <= 0 or right_norm <= 0:
                continue

            similarity = dot / math.sqrt(left_norm * right_norm)
            similarities.append(_clip_float(similarity, 0.0, 1.0, 0.0))

    if not similarities:
        return 0.5

    return _round6(_clip_float(_mean(similarities), 0.0, 1.0, 0.5))


def _merge_local_contributions(
    sources: Sequence[tuple[str, Sequence[Contribution]]],
    options: ExplainOptions,
) -> tuple[Contribution, ...]:
    """
    Merge local contributions from multiple bounded methods.
    """
    aggregates: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "effect": 0.0,
            "magnitude": 0.0,
            "weight": 0.0,
            "confidence": 0.0,
            "stability": 0.0,
            "sources": set(),
            "methods": set(),
            "details": {},
            "value_bucket": "",
            "baseline_bucket": "",
        }
    )

    for method, contributions in sources:
        method_weight = max(0.01, float(_METHOD_WEIGHTS.get(method, 0.50)))

        for contribution in contributions:
            if not contribution.feature:
                continue

            confidence = max(0.01, float(contribution.confidence or 0.5))
            weight = method_weight * confidence
            bucket = aggregates[contribution.feature]
            bucket["effect"] += float(contribution.effect) * weight
            bucket["magnitude"] += float(contribution.magnitude) * weight
            bucket["weight"] += weight
            bucket["confidence"] += confidence * weight
            bucket["stability"] += float(contribution.stability or confidence) * weight
            bucket["sources"].update(contribution.sources or (method,))
            bucket["methods"].add(method)

            if not bucket["value_bucket"]:
                bucket["value_bucket"] = contribution.value_bucket

            if not bucket["baseline_bucket"]:
                bucket["baseline_bucket"] = contribution.baseline_bucket

            if isinstance(contribution.details, Mapping):
                bucket["details"][method] = _safe_detail_value(contribution.details)

    if not aggregates:
        return ()

    total_magnitude = sum(float(bucket["magnitude"]) for bucket in aggregates.values())
    out: list[Contribution] = []
    multiple = len({method for method, _contributions in sources if _contributions}) > 1

    for feature, bucket in aggregates.items():
        weight = max(1e-12, float(bucket["weight"]))
        effect = float(bucket["effect"]) / weight
        raw_magnitude = float(bucket["magnitude"]) / weight
        normalized_magnitude = raw_magnitude / total_magnitude if total_magnitude > 0 else 0.0
        confidence = float(bucket["confidence"]) / weight
        stability = float(bucket["stability"]) / weight
        methods = tuple(sorted(bucket["methods"]))
        method_label = ExplanationMethod.HYBRID.value if multiple and len(methods) > 1 else (methods[0] if methods else "explainability")

        out.append(
            Contribution(
                feature=feature,
                effect=effect,
                magnitude=normalized_magnitude,
                method=method_label,
                value_bucket=str(bucket["value_bucket"]),
                baseline_bucket=str(bucket["baseline_bucket"]),
                confidence=confidence,
                stability=stability,
                sources=tuple(sorted(bucket["sources"])) or methods,
                details={
                    "raw_magnitude": _round6(raw_magnitude),
                    "methods": list(methods),
                    "method_details": bucket["details"],
                },
            )
        )

    out.sort(key=lambda item: (-float(item.magnitude), item.feature))
    return tuple(out[: max(1, int(options.max_contributions))])


def _build_global_importance(
    method_maps: Mapping[str, Mapping[str, Mapping[str, Any]]],
    options: ExplainOptions,
) -> tuple[GlobalImportance, ...]:
    """
    Build bounded global importance records from method-specific maps.
    """
    out: list[GlobalImportance] = []
    normalized_maps: dict[str, dict[str, dict[str, Any]]] = {}

    for method, mp in method_maps.items():
        if not mp:
            continue

        items = sorted(
            mp.items(),
            key=lambda kv: (-float(kv[1].get("score", 0.0)), kv[0]),
        )[: max(1, int(options.max_global_features))]

        max_score = max((float(data.get("score", 0.0)) for _feature, data in items), default=0.0)
        normalized: dict[str, dict[str, Any]] = {}

        for feature, data in items:
            raw = float(data.get("score", 0.0))
            norm = raw / max_score if max_score > 0 else 0.0
            normalized[feature] = {
                "score": _round6(_clip_float(norm, 0.0, 1.0, 0.0)),
                "raw": _round6(raw),
                "mean_abs_effect": _round6(float(data.get("mean_abs_effect", raw))),
                "stability": _round6(float(data.get("stability", 0.5))),
                "sources": tuple(data.get("sources") or (method,)),
                "details": {
                    key: value
                    for key, value in data.items()
                    if key not in {"score", "mean_abs_effect", "stability", "sources"}
                },
            }

        normalized_maps[method] = normalized

        ranked = sorted(normalized.items(), key=lambda kv: (-float(kv[1]["score"]), kv[0]))

        for rank, (feature, data) in enumerate(ranked, start=1):
            out.append(
                GlobalImportance(
                    feature=feature,
                    method=method,
                    score=float(data["score"]),
                    mean_abs_effect=float(data["mean_abs_effect"]),
                    rank=rank,
                    stability=float(data["stability"]),
                    available=True,
                    sources=tuple(data["sources"]),
                    details={"raw_score": float(data["raw"]), **data["details"]},
                )
            )

    if len(normalized_maps) > 1:
        hybrid: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "score": 0.0,
                "raw": 0.0,
                "weight": 0.0,
                "stability": 0.0,
                "sources": set(),
                "methods": set(),
            }
        )

        for method, normalized in normalized_maps.items():
            weight = max(0.01, float(_METHOD_WEIGHTS.get(method, 0.50)))

            for feature, data in normalized.items():
                bucket = hybrid[feature]
                bucket["score"] += float(data["score"]) * weight
                bucket["raw"] += float(data["raw"]) * weight
                bucket["weight"] += weight
                bucket["stability"] += float(data["stability"]) * weight
                bucket["sources"].update(data["sources"])
                bucket["methods"].add(method)

        ranked_hybrid: list[tuple[str, dict[str, Any]]] = []

        for feature, bucket in hybrid.items():
            weight = max(1e-12, float(bucket["weight"]))
            bucket["score"] = _round6(_clip_float(float(bucket["score"]) / weight, 0.0, 1.0, 0.0))
            bucket["raw"] = _round6(float(bucket["raw"]) / weight)
            bucket["stability"] = _round6(float(bucket["stability"]) / weight)
            ranked_hybrid.append((feature, bucket))

        ranked_hybrid.sort(key=lambda item: (-float(item[1]["score"]), item[0]))
        ranked_hybrid = ranked_hybrid[: max(1, int(options.max_global_features))]

        for rank, (feature, bucket) in enumerate(ranked_hybrid, start=1):
            out.append(
                GlobalImportance(
                    feature=feature,
                    method=ExplanationMethod.HYBRID.value,
                    score=float(bucket["score"]),
                    mean_abs_effect=float(bucket["raw"]),
                    rank=rank,
                    stability=float(bucket["stability"]),
                    available=True,
                    sources=tuple(sorted(bucket["sources"])) or tuple(sorted(bucket["methods"])),
                    details={
                        "methods": sorted(bucket["methods"]),
                        "raw_score": float(bucket["raw"]),
                    },
                )
            )

    return tuple(out)


def _select_instance_records(
    records: Sequence[Mapping[str, Any]],
    snapshots: Sequence[_ScoreSnapshot],
    request: ExplanationRequest,
    options: ExplainOptions,
) -> list[Mapping[str, Any]]:
    """
    Select bounded instances for local explanation.
    """
    if not records:
        return []

    limit = max(1, min(int(options.max_instances), len(records)))
    by_index = {int(record.get("index", position)): record for position, record in enumerate(records)}
    by_subject: dict[str, Mapping[str, Any]] = {}

    for record in records:
        subject = record.get("subject_ref_hash")

        if subject:
            by_subject.setdefault(str(subject).lower(), record)

    selected: list[Mapping[str, Any]] = []
    seen: set[int] = set()

    if request.instance_refs:
        for ref in _as_sequence(request.instance_refs)[:limit]:
            record = None

            if isinstance(ref, Mapping):
                index = _coerce_optional_float(ref.get("index"), allow_bool=False)
                subject = _subject_from_mapping(ref)

                if index is not None and int(index) in by_index:
                    record = by_index[int(index)]
                elif subject:
                    subject_hash = _subject_hash(subject, options)
                    record = by_subject.get(str(subject_hash or subject).lower())
            elif isinstance(ref, int):
                record = by_index.get(ref)
            else:
                subject_hash = _subject_hash(ref, options)
                record = by_subject.get(str(subject_hash or ref).lower())

            if record is not None:
                index = int(record.get("index", -1))

                if index not in seen:
                    seen.add(index)
                    selected.append(record)

            if len(selected) >= limit:
                break

    if selected:
        return selected

    scored: list[tuple[float, int, Mapping[str, Any]]] = []

    for position, record in enumerate(records):
        snapshot = snapshots[position] if position < len(snapshots) else None
        score = snapshot.score if snapshot is not None and snapshot.score is not None else -1.0
        scored.append((float(score), int(record.get("index", position)), record))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [record for _score, _index, record in scored[:limit]]


# -----------------------------------------------------------------------------
# Process-local explanation cache
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _CacheEntry:
    result: ExplanationResult
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class ExplanationCache:
    """
    Bounded process-local explanation cache.

    This cache is not durable, not distributed, and not production-ready. It
    exists only to support local prototype workflows, tests, and developer
    tooling.
    """

    def __init__(self, max_entries: int = _DEFAULT_MAX_CACHE_ENTRIES) -> None:
        self.max_entries = max(1, int(max_entries))
        self._entries: dict[str, _CacheEntry] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[ExplanationResult]:
        """
        Return one cached result.
        """
        clean_key = _clean_text(key, 256)

        with self._lock:
            entry = self._entries.get(clean_key)

            if entry is None:
                return None

            if clean_key in self._order:
                self._order.remove(clean_key)

            self._order.append(clean_key)
            return entry.result

    def set(self, key: str, result: ExplanationResult) -> str:
        """
        Store one result and return its cache key.
        """
        clean_key = _clean_text(key, 256) or result.fingerprint

        with self._lock:
            if clean_key in self._entries:
                self._entries[clean_key] = _CacheEntry(result=result, registered_at=_now_utc())

                if clean_key in self._order:
                    self._order.remove(clean_key)

                self._order.append(clean_key)
                return clean_key

            self._entries[clean_key] = _CacheEntry(result=result, registered_at=_now_utc())
            self._order.append(clean_key)

            if len(self._order) > self.max_entries:
                evict_key = self._order.pop(0)
                self._entries.pop(evict_key, None)

            return clean_key

    def clear(self) -> None:
        """
        Clear the process-local cache.
        """
        with self._lock:
            self._entries.clear()
            self._order.clear()

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe cache summary.
        """
        with self._lock:
            return {
                "backend": "process_local_in_memory",
                "durable": False,
                "distributed": False,
                "max_entries": self.max_entries,
                "entries": len(self._entries),
            }


_default_cache: Optional[ExplanationCache] = None
_default_cache_lock = threading.Lock()


def get_explain_cache(
    max_entries: int | None = None,
    *,
    rebuild: bool = False,
) -> ExplanationCache:
    """
    Return the process-wide explanation cache.
    """
    global _default_cache

    with _default_cache_lock:
        if _default_cache is None or rebuild:
            _default_cache = ExplanationCache(
                max_entries=max_entries if max_entries is not None else _DEFAULT_MAX_CACHE_ENTRIES
            )

        return _default_cache


# -----------------------------------------------------------------------------
# Harness request helpers
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "features",
        "labels",
        "model",
        "model_id",
        "target",
        "scope",
        "methods",
        "instance_refs",
        "feature_names",
        "target_label",
        "top_k",
        "positive_label_codes",
        "negative_label_codes",
        "ignore_label_codes",
        "threshold",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


def _coerce_request(request: Any) -> ExplanationRequest:
    """
    Coerce flexible explainability input into one bounded request.
    """
    if isinstance(request, ExplanationRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if "features" not in payload:
            for key in ("records", "rows", "items", "examples", "vectors"):
                if key in payload:
                    payload["features"] = payload[key]
                    break

        if any(key in payload for key in _REQUEST_KEYS):
            clean = {key: value for key, value in payload.items() if key in _REQUEST_KEYS}

            try:
                return ExplanationRequest(**clean)
            except Exception:
                return ExplanationRequest(features=payload.get("features", request))

        return ExplanationRequest(features=request)

    if hasattr(request, "features"):
        try:
            return ExplanationRequest(features=getattr(request, "features"))
        except Exception:
            pass

    if (
        hasattr(request, "parameters")
        or hasattr(request, "score")
        or hasattr(request, "infer")
        or _is_prediction_sequence(request)
    ):
        return ExplanationRequest(model=request)

    return ExplanationRequest(features=request)


def _request_fingerprint(
    request: ExplanationRequest,
    options: ExplainOptions,
    target: ExplanationTarget,
    scope: ExplanationScope,
    methods: Sequence[ExplanationMethod],
    feature_names: Sequence[str],
) -> str:
    """
    Return deterministic safe request fingerprint.
    """
    instance_refs: list[str] = []

    for ref in _as_sequence(request.instance_refs) or ():
        if isinstance(ref, Mapping):
            subject = _subject_from_mapping(ref)
            index = ref.get("index")
            instance_refs.append(
                _clean_text(
                    _subject_hash(subject, options) if subject is not None else index,
                    128,
                )
            )
        elif isinstance(ref, int):
            instance_refs.append(str(ref))
        else:
            instance_refs.append(_clean_text(_subject_hash(ref, options) or ref, 128))

    payload = {
        "version": EXPLAINABILITY_VERSION,
        "target": target.value,
        "scope": scope.value,
        "methods": [method.value for method in methods],
        "model_id": request.model_id,
        "feature_names_sample": list(feature_names[: options.max_summary_items]),
        "feature_names_truncated": len(feature_names) > options.max_summary_items,
        "target_label": request.target_label,
        "top_k": request.top_k,
        "threshold": request.threshold,
        "positive_label_codes": list(request.positive_label_codes),
        "negative_label_codes": list(request.negative_label_codes),
        "ignore_label_codes": list(request.ignore_label_codes),
        "tags": list(request.tags),
        "metadata": _safe_detail_value(request.metadata),
        "instance_refs": instance_refs[: options.max_instances],
        "idempotency_key": request.idempotency_key,
    }

    return _fingerprint_payload(payload)


# -----------------------------------------------------------------------------
# Explainability harness
# -----------------------------------------------------------------------------


class ExplainabilityHarness:
    """
    Bounded deterministic synthetic ML explainability harness.

    This harness produces operational attribution summaries for synthetic model
    outputs. It does not prove causality, does not adjudicate wrongdoing, and
    must not trigger automatic adverse customer action.
    """

    def __init__(self, options: ExplainOptions | None = None) -> None:
        self.options = options or ExplainOptions.from_settings()
        self._lock = threading.RLock()

    def explain(self, request: Any) -> ExplanationResult:
        """
        Generate one bounded explanation result.
        """
        opts = self.options
        issues: list[ExplanationIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)
        target = _resolve_target(req.target, opts.target, req.model)
        scope = _normalize_enum_option(ExplanationScope, req.scope or opts.scope, ExplanationScope.BOTH)
        methods = tuple(req.methods or opts.methods)
        top_k = req.top_k or opts.top_k
        threshold = req.threshold if req.threshold is not None else opts.threshold

        model_id = _clean_text(req.model_id, 128) or _object_fingerprint(req.model)[:32]
        model_fp = _object_fingerprint(req.model)

        def blocked_result(
            ok: bool,
            metadata_extra: Optional[Mapping[str, Any]] = None,
        ) -> ExplanationResult:
            metadata = {
                "explainability_version": EXPLAINABILITY_VERSION,
                "model_id": model_id,
                "model_fingerprint": model_fp,
                "target": target.value,
                "scope": scope.value,
                "methods": [method.value for method in methods],
                "options": opts.safe_summary(),
                "caveats": list(_EXPLAIN_CAVEATS),
                "safety_flags": dict(_EXPLAIN_SAFETY_FLAGS),
            }

            if metadata_extra:
                metadata.update(_safe_detail_value(metadata_extra) or {})

            return ExplanationResult(
                ok=ok,
                model_id=model_id,
                target=target,
                scope=scope,
                methods=tuple(method.value for method in methods),
                global_importance=(),
                local_explanations=(),
                counts={
                    "submitted": 0,
                    "processed": 0,
                    "features": 0,
                    "instances": 0,
                    "scores_available": 0,
                    "global_items": 0,
                    "local_items": 0,
                    "cached": 0,
                },
                issues=tuple(issues),
                metadata=metadata,
                fingerprint="",
            )

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="explainability_disabled",
                message="Explainability harness is disabled.",
            )
            return blocked_result(False, {"disabled": True})

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Explainability harness requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return blocked_result(False, {"invalid": True})

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Explainability harness is blocked in production-like environments.",
            )
            return blocked_result(False, {"blocked": True})

        if not _scan_labels(req.labels, opts, issues):
            return blocked_result(False, {"invalid_labels": True})

        raw_records = _iter_records(req.features)
        submitted = len(raw_records)

        if submitted > opts.max_records:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="explanation_input_truncated",
                message="Explanation input exceeded configured record limit and was truncated.",
                details={
                    "submitted": submitted,
                    "max_records": opts.max_records,
                },
            )
            raw_records = raw_records[: opts.max_records]

        allowed_features = req.feature_names or _model_feature_names(req.model) or None
        cleaned = _sanitize_records(raw_records, opts, issues, allowed_features=allowed_features)

        if not cleaned:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_valid_explanation_input",
                message="No valid explanation input remained after sanitization.",
            )
            return blocked_result(False, {"empty_input": True})

        feature_names = _discover_feature_names(cleaned, opts, allowed_features)

        if not feature_names:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="no_explainable_features",
                message="No explainable features were available.",
            )
            return blocked_result(False, {"no_features": True})

        stats = _build_feature_stats(cleaned, feature_names, opts)
        label_index = _build_label_index(req.labels, len(cleaned), opts)
        labels_summary = _label_summary(label_index)
        data_fp = _data_fingerprint(cleaned, feature_names, labels_summary)
        req_fp = _request_fingerprint(req, opts, target, scope, methods, feature_names)
        cache_key = _sha256_hex(f"{opts.namespace}|{model_fp}|{data_fp}|{req_fp}")[:64]

        if opts.use_cache:
            cached = get_explain_cache(opts.max_cache_entries).get(cache_key)

            if cached is not None:
                metadata = dict(cached.metadata)
                metadata.update(
                    {
                        "cached": True,
                        "cache_hit": True,
                        "cache_key": cache_key,
                    }
                )
                return replace(
                    cached,
                    metadata=metadata,
                    fingerprint="",
                )

        snapshots = _score_records(cleaned, req, opts, issues)
        scores_available = sum(1 for snapshot in snapshots if snapshot.score is not None)
        snapshots_by_index = {
            int(snapshot.index): snapshot
            for snapshot in snapshots
            if snapshot.index is not None
        }

        coefficients = _extract_coefficients(
            req.model,
            feature_names,
            req.target_label,
            issues,
            opts,
        )

        method_maps: dict[str, dict[str, dict[str, Any]]] = {}

        if ExplanationMethod.COEFFICIENT in methods:
            coefficient_map = _coefficient_global_map(coefficients, stats, opts)

            if coefficient_map:
                method_maps[ExplanationMethod.COEFFICIENT.value] = coefficient_map

        if ExplanationMethod.MODEL_CONTRIBUTIONS in methods:
            native_map = _native_global_map(snapshots, opts)

            if native_map:
                method_maps[ExplanationMethod.MODEL_CONTRIBUTIONS.value] = native_map

        if ExplanationMethod.PERMUTATION in methods and scores_available > 0:
            if _time_exceeded(start_time, opts.max_time_ms):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="permutation_skipped_time_budget",
                    message="Permutation analysis skipped due to time budget.",
                )
            else:
                permutation_map = _permutation_global_map(
                    cleaned,
                    snapshots,
                    feature_names,
                    req,
                    opts,
                    issues,
                    start_time,
                )

                if permutation_map:
                    method_maps[ExplanationMethod.PERMUTATION.value] = permutation_map

        if ExplanationMethod.SENSITIVITY in methods and scores_available > 0:
            if _time_exceeded(start_time, opts.max_time_ms):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="sensitivity_skipped_time_budget",
                    message="Sensitivity analysis skipped due to time budget.",
                )
            else:
                sensitivity_map = _sensitivity_global_map(
                    cleaned,
                    snapshots,
                    feature_names,
                    req,
                    opts,
                    issues,
                    start_time,
                )

                if sensitivity_map:
                    method_maps[ExplanationMethod.SENSITIVITY.value] = sensitivity_map

        global_importance = _build_global_importance(method_maps, opts) if method_maps else ()

        local_explanations: list[LocalExplanation] = []
        surrogate_global_accum: dict[str, dict[str, float]] = defaultdict(
            lambda: {"sum_abs_beta": 0.0, "count": 0}
        )

        if scope in {ExplanationScope.LOCAL, ExplanationScope.BOTH}:
            selected_records = _select_instance_records(cleaned, snapshots, req, opts)
            mean_scores = [
                float(snapshot.score)
                for snapshot in snapshots
                if snapshot.score is not None
            ]
            baseline_score = _round6(_mean(mean_scores)) if mean_scores else None

            for record in selected_records:
                if _time_exceeded(start_time, opts.max_time_ms):
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="local_explanation_time_budget_exhausted",
                        message="Local explanation generation stopped after reaching configured time budget.",
                        details={"processed_instances": len(local_explanations)},
                    )
                    break

                index = int(record.get("index", len(local_explanations)))
                snapshot = snapshots_by_index.get(index)

                if snapshot is None:
                    snapshot = _ScoreSnapshot(
                        subject_ref_hash=record.get("subject_ref_hash"),
                        index=index,
                        source="none",
                    )

                sources: list[tuple[str, tuple[Contribution, ...]]] = []

                if ExplanationMethod.COEFFICIENT in methods and coefficients:
                    coefficient_contributions = _coefficient_local_contributions(
                        record,
                        coefficients,
                        stats,
                        opts,
                    )

                    if coefficient_contributions:
                        sources.append((ExplanationMethod.COEFFICIENT.value, coefficient_contributions))

                if ExplanationMethod.MODEL_CONTRIBUTIONS in methods and snapshot.contributions:
                    native_contributions = _native_local_contributions(snapshot, opts)

                    if native_contributions:
                        sources.append((ExplanationMethod.MODEL_CONTRIBUTIONS.value, native_contributions))

                if ExplanationMethod.LOCAL_SURROGATE in methods and snapshot.score is not None:
                    surrogate_contributions, surrogate_terms, _confidence = _local_surrogate_contributions(
                        record,
                        snapshot,
                        feature_names,
                        stats,
                        coefficients,
                        req,
                        opts,
                        start_time,
                    )

                    if surrogate_contributions:
                        sources.append((ExplanationMethod.LOCAL_SURROGATE.value, surrogate_contributions))

                    for feature, abs_beta in surrogate_terms.items():
                        bucket = surrogate_global_accum[feature]
                        bucket["sum_abs_beta"] += float(abs_beta)
                        bucket["count"] += 1

                if ExplanationMethod.SENSITIVITY in methods and snapshot.score is not None:
                    sensitivity_contributions = _sensitivity_local_contributions(
                        record,
                        snapshot,
                        feature_names,
                        stats,
                        coefficients,
                        req,
                        opts,
                        start_time,
                    )

                    if sensitivity_contributions:
                        sources.append((ExplanationMethod.SENSITIVITY.value, sensitivity_contributions))

                if not sources:
                    continue

                merged = _merge_local_contributions(sources, opts)

                if not merged:
                    continue

                stability = _estimate_stability(sources) if opts.include_stability else 0.0
                confidence = _round6(
                    _clip_float(
                        _mean([float(contribution.confidence) for contribution in merged]),
                        0.0,
                        1.0,
                        0.5,
                    )
                )
                methods_used = tuple(
                    dict.fromkeys(
                        method
                        for method, contributions in sources
                        if contributions
                    )
                )

                local_explanations.append(
                    LocalExplanation(
                        subject_ref_hash=record.get("subject_ref_hash"),
                        index=index,
                        target=target.value,
                        score=snapshot.score,
                        baseline_score=baseline_score,
                        contributions=merged,
                        methods=methods_used,
                        confidence=confidence,
                        stability=stability,
                        summary={
                            "contribution_count": len(merged),
                            "top_features": [
                                contribution.feature
                                for contribution in merged[: min(5, len(merged))]
                            ],
                        },
                        metadata={
                            "model_id": model_id,
                            "model_fingerprint": model_fp,
                            "source": snapshot.source,
                            "caveats": list(_EXPLAIN_CAVEATS),
                            "safety_flags": dict(_EXPLAIN_SAFETY_FLAGS),
                        },
                    )
                )

        if surrogate_global_accum and ExplanationMethod.LOCAL_SURROGATE in methods:
            surrogate_map: dict[str, dict[str, Any]] = {}

            for feature, bucket in surrogate_global_accum.items():
                count = max(1, int(bucket["count"]))
                score = _round6(float(bucket["sum_abs_beta"]) / float(count))
                surrogate_map[feature] = {
                    "score": score,
                    "mean_abs_effect": score,
                    "stability": 0.50,
                    "sources": (ExplanationMethod.LOCAL_SURROGATE.value,),
                    "instance_count": count,
                }

            if surrogate_map:
                method_maps[ExplanationMethod.LOCAL_SURROGATE.value] = surrogate_map
                global_importance = _build_global_importance(method_maps, opts)

        if ExplanationMethod.HYBRID in methods and len(method_maps) > 1:
            pass
        elif ExplanationMethod.HYBRID not in methods:
            global_importance = tuple(
                item
                for item in global_importance
                if item.method != ExplanationMethod.HYBRID.value
            )

        if top_k and top_k > 0:
            grouped: dict[str, list[GlobalImportance]] = defaultdict(list)

            for item in global_importance:
                grouped[item.method].append(item)

            limited: list[GlobalImportance] = []

            for method, items in grouped.items():
                items.sort(key=lambda item: (-float(item.score), item.feature))
                limited.extend(items[: max(1, int(top_k))])

            global_importance = tuple(limited)

        counts = {
            "submitted": submitted,
            "processed": len(cleaned),
            "features": len(feature_names),
            "instances": len(local_explanations),
            "scores_available": scores_available,
            "global_items": len(global_importance),
            "local_items": len(local_explanations),
            "cached": 0,
            "methods_used": len(method_maps),
        }

        metadata = {
            "explainability_version": EXPLAINABILITY_VERSION,
            "model_id": model_id,
            "model_fingerprint": model_fp,
            "target": target.value,
            "scope": scope.value,
            "methods_requested": [method.value for method in methods],
            "methods_used": sorted(method_maps),
            "threshold": _round6(threshold),
            "top_k": int(top_k),
            "data_fingerprint": data_fp,
            "request_fingerprint": req_fp,
            "cache_key": cache_key,
            "label_summary": labels_summary,
            "feature_names_sample": list(feature_names[: opts.max_summary_items]),
            "feature_names_truncated": len(feature_names) > opts.max_summary_items,
            "options": opts.safe_summary(),
            "elapsed_ms": _elapsed_ms(start_time),
            "caveats": list(_EXPLAIN_CAVEATS),
            "safety_flags": dict(_EXPLAIN_SAFETY_FLAGS),
        }

        result = ExplanationResult(
            ok=not _has_error(issues),
            model_id=model_id,
            target=target,
            scope=scope,
            methods=tuple(sorted(method_maps)) or tuple(method.value for method in methods),
            global_importance=global_importance,
            local_explanations=tuple(local_explanations),
            counts=counts,
            issues=tuple(issues),
            metadata=metadata,
            fingerprint="",
        )

        if opts.use_cache and result.ok:
            get_explain_cache(opts.max_cache_entries).set(cache_key, result)

        return result

    def safe_summary(self) -> dict[str, Any]:
        """
        Return safe harness summary.
        """
        return {
            "options": self.options.safe_summary(),
            "submodules": {
                "model_service": _module_available(model_service_module, "ModelService"),
                "labels": _module_available(labels_module, "LabelSet"),
                "splits": _module_available(splits_module, "build_split_plan_from_label_set"),
                "preprocessing": _module_available(preprocessing_module, "Preprocessor"),
                "supervised": _module_available(supervised_module, "SupervisedTrainer"),
                "anomaly": _module_available(anomaly_module, "AnomalyModel"),
                "fallback": _module_available(fallback_module, "score_fallback_batch"),
            },
            "cache": get_explain_cache(self.options.max_cache_entries).safe_summary(),
            "caveats": list(_EXPLAIN_CAVEATS),
            "safety_flags": dict(_EXPLAIN_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default harness and public API
# -----------------------------------------------------------------------------


_default_harness: Optional[ExplainabilityHarness] = None
_default_harness_lock = threading.Lock()


def get_explain_options(settings: Any | None = None) -> ExplainOptions:
    """
    Return explainability options from settings.
    """
    return ExplainOptions.from_settings(settings)


def get_explainability_harness(
    options: ExplainOptions | None = None,
    *,
    rebuild: bool = False,
) -> ExplainabilityHarness:
    """
    Return a process-wide explainability harness.

    If options are supplied or rebuild is True, a new harness is created and
    becomes the default.
    """
    global _default_harness

    with _default_harness_lock:
        if _default_harness is None or rebuild or options is not None:
            _default_harness = ExplainabilityHarness(
                options=options or ExplainOptions.from_settings()
            )

        return _default_harness


def explain_model(
    request: Any,
    options: ExplainOptions | None = None,
    *,
    harness: ExplainabilityHarness | None = None,
) -> ExplanationResult:
    """
    Generate one bounded synthetic explanation result.
    """
    active_harness = harness or get_explainability_harness(options)
    return active_harness.explain(request)


def explain_records(
    records: Any,
    model: Any = None,
    options: ExplainOptions | None = None,
    *,
    harness: ExplainabilityHarness | None = None,
    **kwargs: Any,
) -> ExplanationResult:
    """
    Convenience helper for explaining records with an optional model.
    """
    request = ExplanationRequest(
        features=records,
        model=model,
        **kwargs,
    )
    return explain_model(request, options=options, harness=harness)


def explain_prediction(
    record: Any,
    model: Any = None,
    options: ExplainOptions | None = None,
    *,
    harness: ExplainabilityHarness | None = None,
    **kwargs: Any,
) -> ExplanationResult:
    """
    Convenience helper for explaining one record.
    """
    return explain_records(
        [record],
        model=model,
        options=options,
        harness=harness,
        **kwargs,
    )


def get_explain_metadata() -> dict[str, Any]:
    """
    Return safe, serializable explainability metadata.

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
    options = ExplainOptions.from_settings()
    cache = get_explain_cache(options.max_cache_entries)

    return {
        "package": "muleguard.backend.ml.explainability",
        "version": EXPLAINABILITY_VERSION,
        "scopes": [scope.value for scope in ExplanationScope],
        "targets": [target.value for target in ExplanationTarget],
        "methods": [method.value for method in ExplanationMethod],
        "baseline_policies": [policy.value for policy in BaselinePolicy],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "cache": cache.safe_summary(),
        "hard_limits": {
            "max_records": _HARD_MAX_RECORDS,
            "max_features": _HARD_MAX_FEATURES,
            "max_instances": _HARD_MAX_INSTANCES,
            "max_local_samples": _HARD_MAX_LOCAL_SAMPLES,
            "max_local_features": _HARD_MAX_LOCAL_FEATURES,
            "max_global_features": _HARD_MAX_GLOBAL_FEATURES,
            "max_permutation_records": _HARD_MAX_PERMUTATION_RECORDS,
            "max_contributions": _HARD_MAX_CONTRIBUTIONS,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_cache_entries": _HARD_MAX_CACHE_ENTRIES,
            "max_time_ms": _HARD_MAX_TIME_MS,
            "top_k": _HARD_TOP_K,
            "stability_repeats": _HARD_MAX_STABILITY_REPEATS,
        },
        "forbidden_explain_field_count": len(_FORBIDDEN_EXPLAIN_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_EXPLAIN_CAVEATS),
        "safety_flags": dict(_EXPLAIN_SAFETY_FLAGS),
    }


__all__ = [
    "BaselinePolicy",
    "Contribution",
    "ExplanationCache",
    "ExplanationIssue",
    "ExplanationMethod",
    "ExplanationRequest",
    "ExplanationResult",
    "ExplanationScope",
    "ExplanationTarget",
    "ExplainabilityHarness",
    "ExplainOptions",
    "GlobalImportance",
    "IssueSeverity",
    "LocalExplanation",
    "explain_model",
    "explain_prediction",
    "explain_records",
    "get_explain_cache",
    "get_explain_metadata",
    "get_explain_options",
    "get_explainability_harness",
]