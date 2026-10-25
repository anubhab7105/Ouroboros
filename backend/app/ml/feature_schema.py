"""
MULEGUARD backend ML feature schema.

This module provides the canonical feature-schema layer for the synthetic
MULEGUARD machine-learning subsystem.

Primary responsibilities:

- define bounded, versioned, explainable feature specifications for synthetic
  ML feature construction;
- enforce leakage-resistant feature naming and field policies;
- reject ground-truth labels, injected scenario IDs, fraud-ring IDs, raw
  complaint narratives, raw identifiers, secrets, tokens, passwords, database
  URLs, filesystem paths, and model artifact paths as features;
- provide deterministic feature validation, normalization, alias resolution,
  domain checking, missing-value policy, and safe validation results;
- expose a machine-readable feature catalog and JSON-schema projection for
  downstream feature builders, scoring services, evaluation harnesses, tests,
  and developer tooling;
- keep ML feature semantics explicitly investigative and non-adjudicative.

This module defines schema only. It does not compute features, train models,
score accounts, evaluate models, persist data, call external systems, or take
adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be represented as a feature.
- Ground-truth labels, scenario IDs, and fraud-ring IDs are forbidden features.
- Raw complaint narratives are forbidden features.
- Raw identifiers are forbidden features. Only pseudonymous, already-hashed
  references may be used outside this feature schema, and even those are not
  declared as model features here.
- Risk scores are investigative prioritization signals only. They are not
  probabilities of guilt.
- Heuristic or graph-derived features are association or anomaly signals only.
  They are not proof of wrongdoing.
- Feature explanations and importances are operational attributions only. They
  are not causal proof.
- Feature validation never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unsupported capabilities must remain honest and bounded.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call model runtimes.
- This module does not train, promote, retire, upload, replace, or execute
  models.
- This module does not generate synthetic data.
- This module does not replace `app.ingestion.validators` for ingestion record
  validation.
- This module does not replace `app.ml.features` for actual feature computation.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, and case dispositions are investigative leads or human workflow
artefacts only. They are not proof of wrongdoing and must not trigger automatic
adverse customer action.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from functools import lru_cache
from types import MappingProxyType
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError
from app.core.vocabularies import (
    AccountStatus,
    AccountType,
    Channel,
    MatchMethod,
    VerificationState,
)

logger = logging.getLogger("muleguard.backend.ml.feature_schema")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

FEATURE_SCHEMA_VERSION: Final[str] = "v1"
FEATURE_CATALOG_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

DEFAULT_MAX_FEATURES: Final[int] = 512
HARD_MAX_FEATURES: Final[int] = 4_096

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_STRING_LENGTH: Final[int] = 512
HARD_MAX_STRING_LENGTH: Final[int] = 4_096

DEFAULT_MAX_SET_ITEMS: Final[int] = 100
HARD_MAX_SET_ITEMS: Final[int] = 1_000

DEFAULT_MAX_VECTOR_ITEMS: Final[int] = 128
HARD_MAX_VECTOR_ITEMS: Final[int] = 4_096

DEFAULT_MAX_METADATA_DEPTH: Final[int] = 6
HARD_MAX_METADATA_DEPTH: Final[int] = 12

DEFAULT_MAX_MAPPING_KEYS: Final[int] = 100
HARD_MAX_MAPPING_KEYS: Final[int] = 1_000

_MAX_NAME_LENGTH: Final[int] = 128
_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_DESCRIPTION_LENGTH: Final[int] = 1_000

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_FEATURE_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{1,127}$")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,128}$")

_MISSING: Final[object] = object()

_FORBIDDEN_FEATURE_FIELDS: Final[frozenset[str]] = frozenset(
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
        "label",
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

_FORBIDDEN_FEATURE_TOKENS: Final[tuple[str, ...]] = (
    "ground_truth",
    "truth_label",
    "fraud_label",
    "is_fraud",
    # `scenario` rather than `scenario_id` alone: the generator also plants
    # `scenario_type` on every labelled account, and that is the same leak
    # under a different suffix. Matching the stem catches `scenario_id`,
    # `scenario_type`, `scenario_label` and anything else of that shape. No
    # behavioural feature in the catalogue contains the word.
    "scenario",
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
    "fraud",
    "ground_truth",
    "hash",
    "identifier_hash",
    "ifsc",
    "ip_address",
    "label",
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
    "ring",
    "scenario",
    "secret",
    "secret_key",
    "token",
    "upi_id",
)

# The categorical vocabularies, derived from the persisted enums.
#
# The catalogue is what tells a reviewer which values a one-hot feature can
# take, so a list that disagrees with the column describes a model nobody
# trained. These were hand-written and had drifted on every field: statuses
# named INACTIVE, PENDING, SUSPENDED and RESTRICTED, none of which the
# account table accepts, and omitted REVIEW_REQUIRED, which it does. Values
# outside the vocabulary fall back to OTHER, so the drift showed up as a
# categorical feature that never varied rather than as an error.
def _enum_tokens(enum_cls: type[Enum]) -> tuple[str, ...]:
    """
    Return one enum's values in declaration order.
    """
    return tuple(str(member.value) for member in enum_cls)


_ACCOUNT_STATUSES: Final[tuple[str, ...]] = _enum_tokens(AccountStatus)

_ACCOUNT_TYPES: Final[tuple[str, ...]] = _enum_tokens(AccountType)

_CHANNELS: Final[tuple[str, ...]] = _enum_tokens(Channel)

_MATCH_METHODS: Final[tuple[str, ...]] = _enum_tokens(MatchMethod)

_VERIFICATION_STATES: Final[tuple[str, ...]] = _enum_tokens(VerificationState)

_COMPLAINT_CATEGORIES: Final[tuple[str, ...]] = (
    "unauthorized_transfer",
    "account_takeover",
    "identity_theft",
    "phishing",
    "scam",
    "other",
)

_MATCH_METHODS: Final[tuple[str, ...]] = (
    "EXACT",
    "HASHED",
    "HEURISTIC",
    "MANUAL",
)

_VERIFICATION_STATES: Final[tuple[str, ...]] = (
    "UNVERIFIED",
    "PENDING",
    "VERIFIED",
    "REJECTED",
    "STALE",
)

_FEATURE_SCHEMA_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML feature schema only. Do not use with real customer data.",
    "Features are investigative inputs only and are not proof of wrongdoing.",
    "Feature validation must not trigger automatic adverse customer action.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are forbidden features.",
    "Raw complaint narratives and raw identifiers are forbidden features.",
    "Risk scores are investigative priority scores, not probabilities of guilt.",
    "Heuristic fallback scores are not calibrated model probabilities.",
    "Graph, entity-link, complaint, and anomaly features are association or signal features only.",
    "Feature importance and explanation factors are operational attributions, not causal proof.",
    "Undefined metrics or unsupported capabilities must be reported honestly as unavailable.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_FEATURE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_ground_truth_labels_as_features": True,
        "no_scenario_ids_as_features": True,
        "no_fraud_ring_ids_as_features": True,
        "no_raw_narratives_as_features": True,
        "no_raw_identifiers_as_features": True,
        "no_secrets_as_features": True,
        "no_tokens_as_features": True,
        "no_passwords_as_features": True,
        "no_database_urls_as_features": True,
        "no_model_artifact_paths_as_features": True,
        "risk_scores_are_investigative_priority_only": True,
        "heuristic_scores_are_not_calibrated_probabilities": True,
        "graph_features_are_association_signals_only": True,
        "explanations_are_not_causal_proof": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class FeatureDType(str, Enum):
    """
    Supported feature value types.
    """

    INT = "int"
    FLOAT = "float"
    DECIMAL = "decimal"
    BOOL = "bool"
    STRING = "string"
    ENUM = "enum"
    DATETIME = "datetime"
    DURATION = "duration"
    RATIO = "ratio"
    PERCENT = "percent"
    SCORE = "score"
    COUNT = "count"
    AMOUNT = "amount"
    SET = "set"
    VECTOR = "vector"


class FeatureCategory(str, Enum):
    """
    Broad feature category labels.
    """

    VOLUME = "volume"
    VELOCITY = "velocity"
    BALANCE = "balance"
    COUNTERPARTY = "counterparty"
    CHANNEL = "channel"
    TEMPORAL = "temporal"
    ENTITY = "entity"
    LINK = "link"
    COMPLAINT = "complaint"
    GRAPH = "graph"
    NETWORK = "network"
    TREND = "trend"
    ANOMALY = "anomaly"
    PROFILE = "profile"
    OTHER = "other"


class FeatureWindow(str, Enum):
    """
    Bounded feature windows.
    """

    NONE = "none"
    ONE_HOUR = "1h"
    ONE_DAY = "24h"
    SEVEN_DAY = "7d"
    THIRTY_DAY = "30d"
    NINETY_DAY = "90d"
    ONE_YEAR = "365d"
    ALL = "all"


class FeatureAggregation(str, Enum):
    """
    Aggregation semantics for derived features.
    """

    RAW = "raw"
    COUNT = "count"
    SUM = "sum"
    MEAN = "mean"
    MEDIAN = "median"
    MAX = "max"
    MIN = "min"
    STDDEV = "stddev"
    CV = "cv"
    DISTINCT_COUNT = "distinct_count"
    ENTROPY = "entropy"
    GINI = "gini"
    HHI = "hhi"
    RATIO = "ratio"
    RATE = "rate"
    SLOPE = "slope"
    VOLATILITY = "volatility"
    BURSTINESS = "burstiness"
    RECENCY = "recency"
    INTERARRIVAL = "interarrival"
    DURATION = "duration"
    SET = "set"
    TOP_N_SHARE = "top_n_share"
    NEW_RATIO = "new_ratio"
    REPEAT_RATIO = "repeat_ratio"
    SHARE = "share"
    DEGREE = "degree"
    PATH_COUNT = "path_count"
    CYCLE_INDICATOR = "cycle_indicator"
    SCORE = "score"
    FLAG = "flag"
    DELTA = "delta"


class FeatureTransform(str, Enum):
    """
    Deterministic transform hints.
    """

    IDENTITY = "identity"
    LOG1P = "log1p"
    SQRT = "sqrt"
    ZSCORE = "zscore"
    ROBUST_ZSCORE = "robust_zscore"
    MINMAX = "minmax"
    RANK = "rank"
    BUCKET = "bucket"
    FREQUENCY = "frequency"
    ONE_HOT = "one_hot"
    HASH = "hash"
    CLIP = "clip"
    ABS = "abs"
    DIFF = "diff"
    PCT_CHANGE = "pct_change"
    EWMA = "ewma"


class FeatureMissingStrategy(str, Enum):
    """
    Missing-value policy.
    """

    ERROR = "error"
    ZERO = "zero"
    NONE = "none"
    MEDIAN = "median"
    MODE = "mode"
    FORWARD_FILL = "forward_fill"
    BACKWARD_FILL = "backward_fill"
    INTERPOLATE = "interpolate"
    CONSTANT = "constant"
    DROP = "drop"


class FeaturePrivacy(str, Enum):
    """
    Privacy classification for feature metadata.
    """

    SYNTHETIC = "synthetic"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


class FeatureLeakage(str, Enum):
    """
    Leakage-risk classification.
    """

    SAFE = "safe"
    CAUTION = "caution"
    FORBIDDEN = "forbidden"


class FeatureStability(str, Enum):
    """
    Expected temporal stability.
    """

    STABLE = "stable"
    DRIFT_PRONE = "drift_prone"
    VOLATILE = "volatile"


class FeatureSource(str, Enum):
    """
    Logical source family for a feature.
    """

    ACCOUNT = "account"
    TRANSACTION = "transaction"
    COMPLAINT = "complaint"
    ENTITY = "entity"
    ENTITY_LINK = "entity_link"
    GRAPH = "graph"
    DERIVED = "derived"
    SYSTEM = "system"


class FeatureEncoding(str, Enum):
    """
    Suggested encoding for categorical or set features.
    """

    NONE = "none"
    ORDINAL = "ordinal"
    ONE_HOT = "one_hot"
    HASH = "hash"
    FREQUENCY = "frequency"
    BINARY = "binary"


class FeatureRole(str, Enum):
    """
    Model-input role.
    """

    NUMERIC = "numeric"
    CATEGORICAL = "categorical"
    BOOLEAN = "boolean"
    TEMPORAL = "temporal"
    SET = "set"
    VECTOR = "vector"
    COMPOSITE = "composite"


class FeatureIssueSeverity(str, Enum):
    """
    Validation issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


# -----------------------------------------------------------------------------
# Derived constant sets
# -----------------------------------------------------------------------------

_NUMERIC_DTYPES: Final[frozenset[FeatureDType]] = frozenset(
    {
        FeatureDType.INT,
        FeatureDType.FLOAT,
        FeatureDType.DECIMAL,
        FeatureDType.COUNT,
        FeatureDType.AMOUNT,
        FeatureDType.RATIO,
        FeatureDType.PERCENT,
        FeatureDType.SCORE,
        FeatureDType.DURATION,
    }
)

_TEXT_DTYPES: Final[frozenset[FeatureDType]] = frozenset(
    {
        FeatureDType.STRING,
        FeatureDType.ENUM,
    }
)

_TEMPORAL_DTYPES: Final[frozenset[FeatureDType]] = frozenset(
    {
        FeatureDType.DATETIME,
        FeatureDType.DURATION,
    }
)


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _setting(settings: Any, name: str, default: Any = None) -> Any:
    """
    Read a setting from either a typed settings object or mapping.
    """
    if settings is None:
        return default

    if isinstance(settings, Mapping):
        return settings.get(name, default)

    return getattr(settings, name, default)


def _as_bool(value: object, default: bool = False) -> bool:
    """
    Convert common configuration representations to boolean.
    """
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
    """
    Safely convert a setting to int.
    """
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float) -> float:
    """
    Safely convert a setting to float.
    """
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default

    if math.isnan(result) or math.isinf(result):
        return default

    return result


def _clamp_int(value: object, minimum: int, maximum: int, default: int) -> int:
    """
    Clamp an integer-like value into bounds.
    """
    parsed = _as_int(value, default)
    return max(minimum, min(parsed, maximum))


def _csv(value: object) -> list[str]:
    """
    Parse comma-separated settings into a clean list.
    """
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return [part.strip() for part in str(value).split(",") if part.strip()]


def _normalize_unicode(value: Any) -> str:
    """
    Normalize Unicode text deterministically.

    Enum members are unwrapped to their value first: for a `str`-mixin enum
    `str(Member)` is "ClassName.MEMBER", not "member", so an enum reaching
    here would normalise to a token nothing recognises.
    """
    if isinstance(value, Enum):
        value = value.value

    return unicodedata.normalize("NFKC", str(value if value is not None else ""))


def _clean_text(value: Any, limit: int = _MAX_TEXT_LENGTH) -> str:
    """
    Return a safe single-line text value.
    """
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
    """
    Normalize a token-like value into lower snake_case.
    """
    text = _normalize_unicode(value).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = _SEPARATOR_RE.sub("_", text)
    text = _MULTI_UNDERSCORE_RE.sub("_", text)
    return text.strip("_").lower()


def _canonical_feature_name(value: Any) -> str:
    """
    Return a canonical feature name token.
    """
    return _normalize_token(value)


def _is_forbidden_feature_name(value: Any) -> bool:
    """
    Return True when a feature name or alias is forbidden.
    """
    canonical = _canonical_feature_name(value)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_FEATURE_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_FEATURE_TOKENS)


def _is_sensitive_key(key: Any) -> bool:
    """
    Return True when a detail key appears sensitive or leakage-prone.
    """
    canonical = _canonical_feature_name(key)

    if not canonical:
        return False

    return any(token in canonical for token in _SENSITIVE_DETAIL_TOKENS)


def _safe_detail_value(value: Any, depth: int = 0) -> Any:
    """
    Convert arbitrary detail values into bounded, safe representations.
    """
    if depth > DEFAULT_MAX_METADATA_DEPTH:
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

        for raw_key, raw_value in list(value.items())[:DEFAULT_MAX_MAPPING_KEYS]:
            key = _clean_text(raw_key, 128)

            if not key or _is_sensitive_key(key):
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _safe_detail_value(item, depth + 1)
            for item in list(value)[:DEFAULT_MAX_SET_ITEMS]
        ]

    if isinstance(value, (set, frozenset)):
        return [
            _safe_detail_value(item, depth + 1)
            for item in list(value)[:DEFAULT_MAX_SET_ITEMS]
        ]

    return f"<{type(value).__name__}>"


def _safe_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return safe issue details.
    """
    if not details:
        return {}

    sanitized = _safe_detail_value(details)

    if isinstance(sanitized, dict):
        return sanitized

    if sanitized is None:
        return {}

    return {"value": sanitized}


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    """
    Normalize datetimes to timezone-aware UTC.
    """
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _to_decimal(value: Any) -> Optional[Decimal]:
    """
    Convert a value to finite Decimal when possible.
    """
    if isinstance(value, Decimal):
        return value if value.is_finite() else None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return Decimal(value)

    if isinstance(value, float):
        if not math.isfinite(value):
            return None

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


def _decimal_to_float(value: Optional[Decimal]) -> Optional[float]:
    """
    Convert Decimal to float for JSON-schema bounds when safe.
    """
    if value is None:
        return None

    if not value.is_finite():
        return None

    try:
        result = float(value)
    except (OverflowError, ValueError):
        return None

    if math.isnan(result) or math.isinf(result):
        return None

    return result


@lru_cache(maxsize=256)
def _compile_pattern(pattern: str) -> re.Pattern[str]:
    """
    Compile and cache a safe regular expression pattern.
    """
    return re.compile(pattern)


def _enum_from_value(
    enum_cls: type[Enum],
    value: Any,
    *,
    field_name: str,
) -> Enum:
    """
    Convert a value to an enum member or raise ConfigurationError.
    """
    if isinstance(value, enum_cls):
        return value

    text = _normalize_token(value)

    if not text:
        raise ConfigurationError(
            f"Invalid {field_name}.",
            details={
                "field": field_name,
                "allowed_values": [str(member.value) for member in enum_cls],
            },
        )

    for candidate in (text, text.upper(), text.lower()):
        try:
            return enum_cls(candidate)  # type: ignore[call-arg]
        except ValueError:
            pass

    try:
        return enum_cls[text.upper()]  # type: ignore[index]
    except KeyError:
        pass

    raise ConfigurationError(
        f"Invalid {field_name}.",
        details={
            "field": field_name,
            "allowed_values": [str(member.value) for member in enum_cls],
        },
    )


def _matches_allowed(value: Any, allowed_values: Sequence[Any]) -> bool:
    """
    Return True when a value matches one allowed token.
    """
    if not allowed_values:
        return True

    value_token = _normalize_token(value).upper()

    if not value_token:
        return False

    allowed_tokens = {
        _normalize_token(item).upper()
        for item in allowed_values
        if _normalize_token(item)
    }

    return value_token in allowed_tokens


def _is_safe_hash(value: Any) -> bool:
    """
    Return True when a value looks like a pseudonymous hash.
    """
    text = str(value or "").strip()
    return bool(text and _HASH_RE.match(text))


def _canonical_json(value: Any) -> str:
    """
    Return deterministic canonical JSON.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    )


def _json_default(value: Any) -> Any:
    """
    JSON serializer fallback for canonicalization.
    """
    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, Decimal):
        return str(value) if value.is_finite() else None

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)

    if isinstance(value, tuple):
        return list(value)

    return str(value)


def _sha256_hex(value: str) -> str:
    """
    Return SHA-256 hex digest for a string.
    """
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


# -----------------------------------------------------------------------------
# Coercion helpers
# -----------------------------------------------------------------------------


def _coerce_int(value: Any, *, strict: bool = True) -> Optional[int]:
    """
    Coerce a value to int.
    """
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    dec = _to_decimal(value)

    if dec is None:
        return None

    if dec != dec.to_integral_value():
        if strict:
            return None
        return int(dec)

    return int(dec)


def _coerce_float(value: Any) -> Optional[float]:
    """
    Coerce a value to finite float.
    """
    if isinstance(value, bool):
        return None

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, int):
        return float(value)

    if isinstance(value, Decimal):
        if not value.is_finite():
            return None
        try:
            result = float(value)
        except (OverflowError, ValueError):
            return None
        return result if math.isfinite(result) else None

    text = _normalize_unicode(value).strip().replace(",", "")

    if not text:
        return None

    try:
        result = float(text)
    except (TypeError, ValueError):
        return None

    return result if math.isfinite(result) else None


def _coerce_decimal(value: Any) -> Optional[Decimal]:
    """
    Coerce a value to finite Decimal.
    """
    return _to_decimal(value)


def _coerce_bool(value: Any) -> Optional[bool]:
    """
    Coerce a value to bool.
    """
    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value == 0:
            return False
        if value == 1:
            return True
        return None

    if isinstance(value, float):
        if not math.isfinite(value):
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

    text = _normalize_unicode(value).strip().lower()

    if text in _TRUE_VALUES:
        return True

    if text in _FALSE_VALUES:
        return False

    return None


def _coerce_datetime(value: Any) -> Optional[datetime]:
    """
    Coerce a value to timezone-aware UTC datetime.
    """
    if isinstance(value, bool):
        return None

    if isinstance(value, datetime):
        return _ensure_utc(value)

    if isinstance(value, (int, float, Decimal)):
        numeric = _coerce_float(value)

        if numeric is None:
            return None

        if abs(numeric) > 1_000_000_000_000:
            numeric = numeric / 1000.0

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
        parsed = datetime.fromisoformat(text)
        return _ensure_utc(parsed)
    except Exception:
        pass

    try:
        numeric = float(text)
    except (TypeError, ValueError):
        return None

    if not math.isfinite(numeric):
        return None

    if abs(numeric) > 1_000_000_000_000:
        numeric = numeric / 1000.0

    try:
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _coerce_duration(value: Any) -> Optional[float]:
    """
    Coerce a value to duration seconds as float.
    """
    if isinstance(value, bool):
        return None

    if isinstance(value, timedelta):
        return float(value.total_seconds())

    return _coerce_float(value)


def _coerce_set(value: Any, *, max_items: int) -> Optional[tuple[Any, ...]]:
    """
    Coerce a value to a bounded tuple of unique items.
    """
    if isinstance(value, bool):
        return None

    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return None

    if isinstance(value, Mapping):
        items: Sequence[Any] = list(value.keys())
    elif isinstance(value, Sequence):
        items = list(value)
    elif isinstance(value, (set, frozenset)):
        items = list(value)
    else:
        return None

    limited = items[: max(1, int(max_items)) + 1]
    out: list[Any] = []
    seen: set[str] = set()

    for item in limited:
        if isinstance(item, Decimal):
            canonical = str(item)
        elif isinstance(item, datetime):
            normalized = _ensure_utc(item)
            canonical = normalized.isoformat() if normalized else ""
        elif isinstance(item, Enum):
            canonical = str(item.value)
        else:
            canonical = _clean_text(item, 300)

        if not canonical:
            continue

        key = canonical.lower()

        if key in seen:
            continue

        seen.add(key)
        out.append(canonical)

    return tuple(out)


def _coerce_vector(value: Any, *, max_items: int) -> Optional[tuple[float, ...]]:
    """
    Coerce a value to a bounded tuple of finite floats.
    """
    if isinstance(value, bool):
        return None

    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return None

    if isinstance(value, Mapping):
        items: Sequence[Any] = list(value.values())
    elif isinstance(value, Sequence):
        items = list(value)
    elif isinstance(value, (set, frozenset)):
        items = list(value)
    else:
        return None

    limited = items[: max(1, int(max_items)) + 1]
    out: list[float] = []

    for item in limited:
        numeric = _coerce_float(item)

        if numeric is None:
            return None

        out.append(numeric)

    return tuple(out)


# -----------------------------------------------------------------------------
# Domain model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeatureDomain:
    """
    Bounded value domain for one feature.
    """

    min_value: Optional[Decimal] = None
    max_value: Optional[Decimal] = None
    allowed_values: tuple[Any, ...] = ()
    pattern: Optional[str] = None
    cardinality: Optional[int] = None
    nullable: bool = True
    default: Optional[Any] = None
    unit: Optional[str] = None

    def __post_init__(self) -> None:
        """
        Normalize and validate domain constraints.
        """
        min_value = _to_decimal(self.min_value) if self.min_value is not None else None
        max_value = _to_decimal(self.max_value) if self.max_value is not None else None

        if min_value is not None and max_value is not None and min_value > max_value:
            min_value, max_value = max_value, min_value

        object.__setattr__(self, "min_value", min_value)
        object.__setattr__(self, "max_value", max_value)

        object.__setattr__(
            self,
            "allowed_values",
            tuple(
                _clean_text(item, 200) if isinstance(item, str) else item
                for item in (self.allowed_values or ())
            ),
        )

        if self.pattern:
            pattern = _clean_text(self.pattern, 512)

            try:
                _compile_pattern(pattern)
            except re.error as exc:
                raise ConfigurationError(
                    "Invalid feature domain pattern.",
                    details={"reason": type(exc).__name__},
                ) from exc

            object.__setattr__(self, "pattern", pattern or None)
        else:
            object.__setattr__(self, "pattern", None)

        if self.cardinality is not None:
            object.__setattr__(
                self,
                "cardinality",
                max(0, _as_int(self.cardinality, 0)),
            )

        object.__setattr__(self, "nullable", _as_bool(self.nullable, True))
        object.__setattr__(self, "default", _safe_detail_value(self.default))
        object.__setattr__(
            self,
            "unit",
            _clean_text(self.unit, 64) or None,
        )

    def safe_dict(self) -> dict[str, Any]:
        """
        Return a safe serializable domain summary.
        """
        return {
            "min_value": str(self.min_value) if self.min_value is not None else None,
            "max_value": str(self.max_value) if self.max_value is not None else None,
            "allowed_values": [
                str(item) for item in self.allowed_values[:50]
            ],
            "allowed_value_count": len(self.allowed_values),
            "pattern": self.pattern,
            "cardinality": self.cardinality,
            "nullable": self.nullable,
            "default": _safe_detail_value(self.default),
            "unit": self.unit,
        }


def _ratio_domain(nullable: bool = True) -> FeatureDomain:
    """
    Return a bounded ratio domain.
    """
    return FeatureDomain(min_value=Decimal(0), max_value=Decimal(1), nullable=nullable)


def _score_domain(nullable: bool = True) -> FeatureDomain:
    """
    Return a bounded score domain.

    Scores are investigative priority signals, not probabilities of guilt.
    """
    return FeatureDomain(min_value=Decimal(0), max_value=Decimal(1), nullable=nullable)


def _percent_domain(nullable: bool = True) -> FeatureDomain:
    """
    Return a bounded percentage domain.
    """
    return FeatureDomain(min_value=Decimal(0), max_value=Decimal(100), nullable=nullable)


def _count_domain(nullable: bool = True) -> FeatureDomain:
    """
    Return a non-negative count domain.
    """
    return FeatureDomain(min_value=Decimal(0), nullable=nullable)


def _amount_domain(nullable: bool = True) -> FeatureDomain:
    """
    Return a non-negative amount domain.
    """
    return FeatureDomain(min_value=Decimal(0), nullable=nullable)


def _duration_domain(nullable: bool = True) -> FeatureDomain:
    """
    Return a non-negative duration domain in seconds.
    """
    return FeatureDomain(min_value=Decimal(0), nullable=nullable)


def _enum_domain(*values: str, nullable: bool = True) -> FeatureDomain:
    """
    Return an enum domain.
    """
    return FeatureDomain(allowed_values=tuple(values), nullable=nullable)


def _auto_domain(
    domain: FeatureDomain,
    dtype: FeatureDType,
    category: FeatureCategory,
) -> FeatureDomain:
    """
    Apply conservative automatic domain defaults.
    """
    min_value = domain.min_value
    max_value = domain.max_value

    if dtype in {FeatureDType.RATIO, FeatureDType.SCORE}:
        if min_value is None:
            min_value = Decimal(0)
        if max_value is None:
            max_value = Decimal(1)

    elif dtype == FeatureDType.PERCENT:
        if min_value is None:
            min_value = Decimal(0)
        if max_value is None:
            max_value = Decimal(100)

    elif dtype in {FeatureDType.COUNT, FeatureDType.DURATION}:
        if min_value is None:
            min_value = Decimal(0)

    if category == FeatureCategory.COUNTERPARTY and dtype == FeatureDType.FLOAT:
        if min_value is None:
            min_value = Decimal(0)

    if category == FeatureCategory.TEMPORAL and dtype == FeatureDType.FLOAT:
        if min_value is None:
            min_value = Decimal(0)

    return replace(domain, min_value=min_value, max_value=max_value)


# -----------------------------------------------------------------------------
# Validation options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeatureValidationOptions:
    """
    Bounded feature-vector validation policy.
    """

    allow_unknown: bool = False
    coerce: bool = True
    strict: bool = True
    require_all: bool = False
    fill_defaults: bool = True
    drop_invalid: bool = False
    treat_empty_string_as_missing: bool = True
    exclude_deprecated: bool = False

    max_features: int = DEFAULT_MAX_FEATURES
    max_issues: int = DEFAULT_MAX_ISSUES
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH
    max_set_items: int = DEFAULT_MAX_SET_ITEMS
    max_vector_items: int = DEFAULT_MAX_VECTOR_ITEMS

    def __post_init__(self) -> None:
        """
        Normalize and clamp option values.
        """
        object.__setattr__(self, "allow_unknown", _as_bool(self.allow_unknown, False))
        object.__setattr__(self, "coerce", _as_bool(self.coerce, True))
        object.__setattr__(self, "strict", _as_bool(self.strict, True))
        object.__setattr__(self, "require_all", _as_bool(self.require_all, False))
        object.__setattr__(self, "fill_defaults", _as_bool(self.fill_defaults, True))
        object.__setattr__(self, "drop_invalid", _as_bool(self.drop_invalid, False))
        object.__setattr__(
            self,
            "treat_empty_string_as_missing",
            _as_bool(self.treat_empty_string_as_missing, True),
        )
        object.__setattr__(self, "exclude_deprecated", _as_bool(self.exclude_deprecated, False))

        object.__setattr__(
            self,
            "max_features",
            _clamp_int(
                self.max_features,
                1,
                HARD_MAX_FEATURES,
                DEFAULT_MAX_FEATURES,
            ),
        )

        object.__setattr__(
            self,
            "max_issues",
            _clamp_int(
                self.max_issues,
                1,
                HARD_MAX_ISSUES,
                DEFAULT_MAX_ISSUES,
            ),
        )

        object.__setattr__(
            self,
            "max_string_length",
            _clamp_int(
                self.max_string_length,
                1,
                HARD_MAX_STRING_LENGTH,
                DEFAULT_MAX_STRING_LENGTH,
            ),
        )

        object.__setattr__(
            self,
            "max_set_items",
            _clamp_int(
                self.max_set_items,
                1,
                HARD_MAX_SET_ITEMS,
                DEFAULT_MAX_SET_ITEMS,
            ),
        )

        object.__setattr__(
            self,
            "max_vector_items",
            _clamp_int(
                self.max_vector_items,
                1,
                HARD_MAX_VECTOR_ITEMS,
                DEFAULT_MAX_VECTOR_ITEMS,
            ),
        )

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "FeatureValidationOptions":
        """
        Build validation options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        return cls(
            allow_unknown=_as_bool(
                _setting(settings, "ML_FEATURE_ALLOW_UNKNOWN", False),
                False,
            ),
            coerce=_as_bool(_setting(settings, "ML_FEATURE_COERCE", True), True),
            strict=_as_bool(_setting(settings, "ML_FEATURE_STRICT", True), True),
            require_all=_as_bool(_setting(settings, "ML_FEATURE_REQUIRE_ALL", False), False),
            fill_defaults=_as_bool(_setting(settings, "ML_FEATURE_FILL_DEFAULTS", True), True),
            drop_invalid=_as_bool(_setting(settings, "ML_FEATURE_DROP_INVALID", False), False),
            treat_empty_string_as_missing=_as_bool(
                _setting(settings, "ML_FEATURE_EMPTY_STRING_AS_MISSING", True),
                True,
            ),
            exclude_deprecated=_as_bool(
                _setting(settings, "ML_FEATURE_EXCLUDE_DEPRECATED", False),
                False,
            ),
            max_features=_as_int(
                _setting(settings, "ML_FEATURE_MAX_FEATURES", DEFAULT_MAX_FEATURES),
                DEFAULT_MAX_FEATURES,
            ),
            max_issues=_as_int(
                _setting(settings, "ML_FEATURE_MAX_ISSUES", DEFAULT_MAX_ISSUES),
                DEFAULT_MAX_ISSUES,
            ),
            max_string_length=_as_int(
                _setting(settings, "ML_FEATURE_MAX_STRING_LENGTH", DEFAULT_MAX_STRING_LENGTH),
                DEFAULT_MAX_STRING_LENGTH,
            ),
            max_set_items=_as_int(
                _setting(settings, "ML_FEATURE_MAX_SET_ITEMS", DEFAULT_MAX_SET_ITEMS),
                DEFAULT_MAX_SET_ITEMS,
            ),
            max_vector_items=_as_int(
                _setting(settings, "ML_FEATURE_MAX_VECTOR_ITEMS", DEFAULT_MAX_VECTOR_ITEMS),
                DEFAULT_MAX_VECTOR_ITEMS,
            ),
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable options summary.
        """
        return {
            "allow_unknown": self.allow_unknown,
            "coerce": self.coerce,
            "strict": self.strict,
            "require_all": self.require_all,
            "fill_defaults": self.fill_defaults,
            "drop_invalid": self.drop_invalid,
            "treat_empty_string_as_missing": self.treat_empty_string_as_missing,
            "exclude_deprecated": self.exclude_deprecated,
            "max_features": self.max_features,
            "max_issues": self.max_issues,
            "max_string_length": self.max_string_length,
            "max_set_items": self.max_set_items,
            "max_vector_items": self.max_vector_items,
        }


# -----------------------------------------------------------------------------
# Issue and result models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeatureValidationIssue:
    """
    Safe feature validation issue.

    Issues never contain raw feature values.
    """

    severity: FeatureIssueSeverity
    code: str
    message: str
    feature: Optional[str] = None
    field: Optional[str] = None
    details: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable issue mapping.
        """
        payload: dict[str, Any] = {
            "severity": self.severity.value,
            "code": _clean_text(self.code, 100),
            "message": _clean_text(self.message, 300),
        }

        if self.feature:
            payload["feature"] = _clean_text(self.feature, 200)

        if self.field:
            payload["field"] = _clean_text(self.field, 200)

        if self.details:
            payload["details"] = self.details

        return payload


def _issue(
    *,
    severity: FeatureIssueSeverity,
    code: str,
    message: str,
    feature: Optional[str] = None,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> FeatureValidationIssue:
    """
    Build one safe validation issue.
    """
    return FeatureValidationIssue(
        severity=severity,
        code=_clean_text(code, 100),
        message=_clean_text(message, 300),
        feature=_clean_text(feature, 200) if feature else None,
        field=_clean_text(field, 200) if field else None,
        details=_safe_details(details),
    )


@dataclass(slots=True)
class FeatureValidationResult:
    """
    Safe feature-vector validation result.

    The `normalized` mapping may contain feature values for downstream internal
    use. Public summaries deliberately exclude values.
    """

    ok: bool = True
    submitted: int = 0

    accepted: list[str] = dataclass_field(default_factory=list)
    rejected: list[str] = dataclass_field(default_factory=list)
    skipped: list[str] = dataclass_field(default_factory=list)
    unknown: list[str] = dataclass_field(default_factory=list)
    forbidden: list[str] = dataclass_field(default_factory=list)

    issues: list[FeatureValidationIssue] = dataclass_field(default_factory=list)
    normalized: dict[str, Any] = dataclass_field(default_factory=dict)
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)

    max_issues: int = DEFAULT_MAX_ISSUES

    _issue_count: int = dataclass_field(default=0, repr=False, compare=False)
    _issue_truncated: bool = dataclass_field(default=False, repr=False, compare=False)

    def add_issue(self, issue: FeatureValidationIssue) -> bool:
        """
        Add one safe issue entry.

        Returns False when the bounded issue list is already truncated.
        """
        if self._issue_truncated:
            if issue.severity == FeatureIssueSeverity.ERROR:
                self.ok = False
            return False

        if len(self.issues) >= max(1, int(self.max_issues)):
            self._issue_truncated = True
            self.issues.append(
                _issue(
                    severity=FeatureIssueSeverity.WARNING,
                    code="issue_list_truncated",
                    message="Issue list truncated by configured limit.",
                )
            )

            if issue.severity == FeatureIssueSeverity.ERROR:
                self.ok = False

            return False

        self.issues.append(issue)
        self._issue_count += 1

        if issue.severity == FeatureIssueSeverity.ERROR:
            self.ok = False

        return True

    def add_error(
        self,
        *,
        code: str,
        message: str,
        feature: Optional[str] = None,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe error entry.
        """
        return self.add_issue(
            _issue(
                severity=FeatureIssueSeverity.ERROR,
                code=code,
                message=message,
                feature=feature,
                field=field,
                details=details,
            )
        )

    def add_warning(
        self,
        *,
        code: str,
        message: str,
        feature: Optional[str] = None,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe warning entry.
        """
        return self.add_issue(
            _issue(
                severity=FeatureIssueSeverity.WARNING,
                code=code,
                message=message,
                feature=feature,
                field=field,
                details=details,
            )
        )

    def add_info(
        self,
        *,
        code: str,
        message: str,
        feature: Optional[str] = None,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe info entry.
        """
        return self.add_issue(
            _issue(
                severity=FeatureIssueSeverity.INFO,
                code=code,
                message=message,
                feature=feature,
                field=field,
                details=details,
            )
        )

    def finalize(self, options: Optional[FeatureValidationOptions] = None) -> None:
        """
        Finalize safe metadata for the result.
        """
        self.metadata.update(
            {
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "feature_catalog_version": FEATURE_CATALOG_VERSION,
                "submitted": self.submitted,
                "accepted_count": len(self.accepted),
                "rejected_count": len(self.rejected),
                "skipped_count": len(self.skipped),
                "unknown_count": len(self.unknown),
                "forbidden_count": len(self.forbidden),
                "issue_count": self._issue_count,
                "issue_truncated": self._issue_truncated,
                "normalized_feature_count": len(self.normalized),
                "caveats": list(_FEATURE_SCHEMA_CAVEATS),
                "safety_flags": dict(_FEATURE_SAFETY_FLAGS),
            }
        )

        if options is not None:
            self.metadata["options"] = options.safe_summary()

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include normalized feature values.
        """
        return {
            "ok": self.ok,
            "counts": {
                "submitted": self.submitted,
                "accepted": len(self.accepted),
                "rejected": len(self.rejected),
                "skipped": len(self.skipped),
                "unknown": len(self.unknown),
                "forbidden": len(self.forbidden),
                "issues": self._issue_count,
                "normalized_features": len(self.normalized),
            },
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
            "caveats": list(_FEATURE_SCHEMA_CAVEATS),
        }


# -----------------------------------------------------------------------------
# Feature specification
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    """
    One bounded, versioned feature specification.
    """

    name: str
    label: str
    description: str
    dtype: FeatureDType | str
    category: FeatureCategory | str
    window: FeatureWindow | str
    aggregation: FeatureAggregation | str
    source: FeatureSource | str

    transform: FeatureTransform | str = FeatureTransform.IDENTITY
    role: FeatureRole | str | None = None
    encoding: FeatureEncoding | str = FeatureEncoding.NONE
    privacy: FeaturePrivacy | str = FeaturePrivacy.SYNTHETIC
    leakage: FeatureLeakage | str = FeatureLeakage.SAFE
    stability: FeatureStability | str = FeatureStability.STABLE
    domain: FeatureDomain | Mapping[str, Any] | None = None
    missing_strategy: FeatureMissingStrategy | str = FeatureMissingStrategy.ERROR

    unit: Optional[str] = None
    version: str = FEATURE_SCHEMA_VERSION
    tags: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()

    required: bool = False
    explainable: bool = True
    model_ready: bool = True
    deprecated: bool = False
    replacement: Optional[str] = None

    def __post_init__(self) -> None:
        """
        Normalize and validate the feature specification.
        """
        name = _canonical_feature_name(self.name)

        if not name or not _FEATURE_NAME_RE.match(name):
            raise ConfigurationError(
                "Invalid feature name.",
                details={"name": _clean_text(self.name, 200)},
            )

        if _is_forbidden_feature_name(name):
            raise ConfigurationError(
                "Forbidden feature name.",
                details={"name": name},
            )

        object.__setattr__(self, "name", name)

        dtype = _enum_from_value(FeatureDType, self.dtype, field_name="dtype")
        category = _enum_from_value(FeatureCategory, self.category, field_name="category")
        window = _enum_from_value(FeatureWindow, self.window, field_name="window")
        aggregation = _enum_from_value(
            FeatureAggregation,
            self.aggregation,
            field_name="aggregation",
        )
        source = _enum_from_value(FeatureSource, self.source, field_name="source")
        transform = _enum_from_value(FeatureTransform, self.transform, field_name="transform")
        encoding = _enum_from_value(FeatureEncoding, self.encoding, field_name="encoding")
        privacy = _enum_from_value(FeaturePrivacy, self.privacy, field_name="privacy")
        leakage = _enum_from_value(FeatureLeakage, self.leakage, field_name="leakage")
        stability = _enum_from_value(FeatureStability, self.stability, field_name="stability")
        missing_strategy = _enum_from_value(
            FeatureMissingStrategy,
            self.missing_strategy,
            field_name="missing_strategy",
        )

        object.__setattr__(self, "dtype", dtype)
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "window", window)
        object.__setattr__(self, "aggregation", aggregation)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "transform", transform)
        object.__setattr__(self, "encoding", encoding)
        object.__setattr__(self, "privacy", privacy)
        object.__setattr__(self, "leakage", leakage)
        object.__setattr__(self, "stability", stability)
        object.__setattr__(self, "missing_strategy", missing_strategy)

        if leakage == FeatureLeakage.FORBIDDEN:
            raise ConfigurationError(
                "Forbidden leakage class cannot be registered as a feature.",
                details={"name": name},
            )

        if self.role is None:
            if dtype in _NUMERIC_DTYPES:
                role = FeatureRole.NUMERIC
            elif dtype in _TEXT_DTYPES:
                role = FeatureRole.CATEGORICAL
            elif dtype == FeatureDType.BOOL:
                role = FeatureRole.BOOLEAN
            elif dtype in _TEMPORAL_DTYPES:
                role = FeatureRole.TEMPORAL
            elif dtype == FeatureDType.SET:
                role = FeatureRole.SET
            elif dtype == FeatureDType.VECTOR:
                role = FeatureRole.VECTOR
            else:
                role = FeatureRole.COMPOSITE
        else:
            role = _enum_from_value(FeatureRole, self.role, field_name="role")

        object.__setattr__(self, "role", role)

        domain = self.domain

        if isinstance(domain, Mapping):
            domain = FeatureDomain(**domain)
        elif domain is None:
            domain = FeatureDomain()

        domain = _auto_domain(domain, dtype, category)
        object.__setattr__(self, "domain", domain)

        object.__setattr__(
            self,
            "label",
            _clean_text(self.label, 200) or name.replace("_", " ").title(),
        )

        object.__setattr__(
            self,
            "description",
            _clean_text(self.description, _MAX_DESCRIPTION_LENGTH),
        )

        object.__setattr__(
            self,
            "unit",
            _clean_text(self.unit, 64) or None,
        )

        object.__setattr__(
            self,
            "version",
            _clean_text(self.version, 32) or FEATURE_SCHEMA_VERSION,
        )

        tags = tuple(
            dict.fromkeys(
                _clean_text(tag, 100)
                for tag in (self.tags or ())
                if _clean_text(tag, 100)
            )
        )
        object.__setattr__(self, "tags", tags)

        aliases: list[str] = []

        for raw_alias in self.aliases or ():
            alias = _canonical_feature_name(raw_alias)

            if not alias or alias == name:
                continue

            if _is_forbidden_feature_name(alias):
                raise ConfigurationError(
                    "Forbidden feature alias.",
                    details={"alias": alias, "feature": name},
                )

            aliases.append(alias)

        object.__setattr__(self, "aliases", tuple(dict.fromkeys(aliases)))

        dependencies = tuple(
            dict.fromkeys(
                _canonical_feature_name(dep)
                for dep in (self.dependencies or ())
                if _canonical_feature_name(dep)
            )
        )
        object.__setattr__(self, "dependencies", dependencies)

        object.__setattr__(
            self,
            "replacement",
            _canonical_feature_name(self.replacement) if self.replacement else None,
        )

        object.__setattr__(self, "required", _as_bool(self.required, False))
        object.__setattr__(self, "explainable", _as_bool(self.explainable, True))
        object.__setattr__(self, "model_ready", _as_bool(self.model_ready, True))
        object.__setattr__(self, "deprecated", _as_bool(self.deprecated, False))

    # ------------------------------------------------------------------
    # Value validation
    # ------------------------------------------------------------------

    def _zero_value(self) -> Any:
        """
        Return a safe zero-like value for missing policy.
        """
        dtype = self.dtype

        if dtype in {FeatureDType.INT, FeatureDType.COUNT}:
            return 0

        if dtype in {
            FeatureDType.FLOAT,
            FeatureDType.RATIO,
            FeatureDType.PERCENT,
            FeatureDType.SCORE,
            FeatureDType.DURATION,
        }:
            return 0.0

        if dtype in {FeatureDType.DECIMAL, FeatureDType.AMOUNT}:
            return Decimal(0)

        if dtype == FeatureDType.BOOL:
            return False

        if dtype == FeatureDType.SET:
            return ()

        if dtype == FeatureDType.VECTOR:
            return ()

        return None

    def _coerce_value(self, value: Any, options: FeatureValidationOptions) -> Any:
        """
        Coerce a raw value according to dtype.
        """
        dtype = self.dtype

        if dtype in {FeatureDType.INT, FeatureDType.COUNT}:
            return _coerce_int(value, strict=options.strict)

        if dtype in {FeatureDType.FLOAT, FeatureDType.RATIO, FeatureDType.PERCENT, FeatureDType.SCORE}:
            return _coerce_float(value)

        if dtype in {FeatureDType.DECIMAL, FeatureDType.AMOUNT}:
            return _coerce_decimal(value)

        if dtype == FeatureDType.BOOL:
            return _coerce_bool(value)

        if dtype in {FeatureDType.STRING, FeatureDType.ENUM}:
            return _clean_text(value, options.max_string_length)

        if dtype == FeatureDType.DATETIME:
            return _coerce_datetime(value)

        if dtype == FeatureDType.DURATION:
            return _coerce_duration(value)

        if dtype == FeatureDType.SET:
            return _coerce_set(value, max_items=options.max_set_items)

        if dtype == FeatureDType.VECTOR:
            return _coerce_vector(value, max_items=options.max_vector_items)

        return None

    def _type_matches_soft(self, value: Any) -> bool:
        """
        Return True when value is already compatible without coercion.
        """
        dtype = self.dtype

        if dtype in {FeatureDType.INT, FeatureDType.COUNT}:
            return isinstance(value, int) and not isinstance(value, bool)

        if dtype in {
            FeatureDType.FLOAT,
            FeatureDType.DECIMAL,
            FeatureDType.RATIO,
            FeatureDType.PERCENT,
            FeatureDType.SCORE,
            FeatureDType.AMOUNT,
            FeatureDType.DURATION,
        }:
            return isinstance(value, (int, float, Decimal)) and not isinstance(value, bool)

        if dtype == FeatureDType.BOOL:
            return isinstance(value, bool)

        if dtype in {FeatureDType.STRING, FeatureDType.ENUM}:
            return isinstance(value, str)

        if dtype == FeatureDType.DATETIME:
            return isinstance(value, datetime)

        if dtype == FeatureDType.SET:
            return isinstance(value, (list, tuple, set, frozenset)) and not isinstance(
                value,
                (str, bytes, bytearray),
            )

        if dtype == FeatureDType.VECTOR:
            return isinstance(value, (list, tuple)) and not isinstance(
                value,
                (str, bytes, bytearray),
            )

        return False

    def _validate_numeric_domain(
        self,
        normalized: Any,
        issues: list[FeatureValidationIssue],
    ) -> None:
        """
        Validate numeric domain bounds.
        """
        dec = _to_decimal(normalized)

        if dec is None:
            issues.append(
                _issue(
                    severity=FeatureIssueSeverity.ERROR,
                    code="invalid_type",
                    message="Value is not a valid numeric feature value.",
                    feature=self.name,
                    details={"expected_dtype": self.dtype.value},
                )
            )
            return

        if self.domain.min_value is not None and dec < self.domain.min_value:
            issues.append(
                _issue(
                    severity=FeatureIssueSeverity.ERROR,
                    code="out_of_range",
                    message="Numeric feature value is below the allowed minimum.",
                    feature=self.name,
                    details={
                        "min_value": str(self.domain.min_value),
                        "max_value": str(self.domain.max_value) if self.domain.max_value else None,
                    },
                )
            )

        if self.domain.max_value is not None and dec > self.domain.max_value:
            issues.append(
                _issue(
                    severity=FeatureIssueSeverity.ERROR,
                    code="out_of_range",
                    message="Numeric feature value is above the allowed maximum.",
                    feature=self.name,
                    details={
                        "min_value": str(self.domain.min_value) if self.domain.min_value else None,
                        "max_value": str(self.domain.max_value),
                    },
                )
            )

    def validate_value(
        self,
        value: Any,
        options: Optional[FeatureValidationOptions] = None,
    ) -> tuple[bool, Any, list[FeatureValidationIssue]]:
        """
        Validate and normalize one feature value.

        Returns:
            `(ok, normalized_value, issues)`.
        """
        opts = options or FeatureValidationOptions()
        issues: list[FeatureValidationIssue] = []

        missing = (
            value is _MISSING
            or value is None
            or (
                opts.treat_empty_string_as_missing
                and isinstance(value, str)
                and not value.strip()
            )
        )

        if missing:
            if self.domain.default is not None and opts.fill_defaults:
                value = self.domain.default
                missing = False
            elif not self.domain.nullable:
                if self.missing_strategy == FeatureMissingStrategy.ERROR:
                    issues.append(
                        _issue(
                            severity=FeatureIssueSeverity.ERROR,
                            code="missing_required" if value is _MISSING else "nullable_violation",
                            message="Required feature value is missing.",
                            feature=self.name,
                        )
                    )
                    return False, None, issues

                if self.missing_strategy == FeatureMissingStrategy.ZERO:
                    return True, self._zero_value(), []

                if self.missing_strategy in {
                    FeatureMissingStrategy.NONE,
                    FeatureMissingStrategy.DROP,
                }:
                    return True, None, []

                issues.append(
                    _issue(
                        severity=FeatureIssueSeverity.WARNING,
                        code="imputation_unavailable",
                        message="Configured imputation is not available in schema validation.",
                        feature=self.name,
                        details={"missing_strategy": self.missing_strategy.value},
                    )
                )
                return True, None, issues
            else:
                return True, None, []

        if not opts.coerce:
            if not self._type_matches_soft(value):
                issues.append(
                    _issue(
                        severity=FeatureIssueSeverity.ERROR,
                        code="invalid_type",
                        message="Value type does not match feature dtype.",
                        feature=self.name,
                        details={
                            "expected_dtype": self.dtype.value,
                            "actual_type": type(value).__name__,
                        },
                    )
                )
                return False, None, issues

            normalized = value
        else:
            normalized = self._coerce_value(value, opts)

            if normalized is None and not (
                self.dtype == FeatureDType.BOOL and value is False
            ):
                issues.append(
                    _issue(
                        severity=FeatureIssueSeverity.ERROR,
                        code="invalid_type",
                        message="Value could not be coerced to feature dtype.",
                        feature=self.name,
                        details={
                            "expected_dtype": self.dtype.value,
                            "actual_type": type(value).__name__,
                        },
                    )
                )
                return False, None, issues

        if self.dtype in _NUMERIC_DTYPES:
            self._validate_numeric_domain(normalized, issues)

        if self.dtype in {FeatureDType.STRING, FeatureDType.ENUM}:
            text = _clean_text(normalized, opts.max_string_length)

            if len(text) > opts.max_string_length:
                issues.append(
                    _issue(
                        severity=FeatureIssueSeverity.ERROR,
                        code="string_too_long",
                        message="String feature value exceeds configured length limit.",
                        feature=self.name,
                        details={"max_string_length": opts.max_string_length},
                    )
                )

            if self.domain.pattern:
                try:
                    pattern = _compile_pattern(self.domain.pattern)
                except re.error:
                    issues.append(
                        _issue(
                            severity=FeatureIssueSeverity.ERROR,
                            code="invalid_pattern",
                            message="Feature domain pattern is invalid.",
                            feature=self.name,
                        )
                    )
                else:
                    if not pattern.fullmatch(text):
                        issues.append(
                            _issue(
                                severity=FeatureIssueSeverity.ERROR,
                                code="invalid_pattern",
                                message="String feature value does not match required pattern.",
                                feature=self.name,
                            )
                        )

            if self.dtype == FeatureDType.ENUM and self.domain.allowed_values:
                if not _matches_allowed(text, self.domain.allowed_values):
                    issues.append(
                        _issue(
                            severity=FeatureIssueSeverity.ERROR,
                            code="invalid_enum",
                            message="Enum feature value is not allowed.",
                            feature=self.name,
                            details={
                                "allowed_value_count": len(self.domain.allowed_values),
                            },
                        )
                    )

            normalized = text

        if self.dtype == FeatureDType.SET:
            if not isinstance(normalized, tuple):
                issues.append(
                    _issue(
                        severity=FeatureIssueSeverity.ERROR,
                        code="invalid_set",
                        message="Set feature value is invalid.",
                        feature=self.name,
                    )
                )
            else:
                max_cardinality = self.domain.cardinality or opts.max_set_items

                if len(normalized) > max_cardinality:
                    issues.append(
                        _issue(
                            severity=FeatureIssueSeverity.ERROR,
                            code="cardinality_exceeded",
                            message="Set feature value exceeds allowed cardinality.",
                            feature=self.name,
                            details={"max_cardinality": max_cardinality},
                        )
                    )

                if self.domain.allowed_values:
                    for item in normalized:
                        if not _matches_allowed(item, self.domain.allowed_values):
                            issues.append(
                                _issue(
                                    severity=FeatureIssueSeverity.ERROR,
                                    code="invalid_enum",
                                    message="Set item is not allowed.",
                                    feature=self.name,
                                )
                            )
                            break

        if self.dtype == FeatureDType.VECTOR:
            if not isinstance(normalized, tuple):
                issues.append(
                    _issue(
                        severity=FeatureIssueSeverity.ERROR,
                        code="invalid_vector",
                        message="Vector feature value is invalid.",
                        feature=self.name,
                    )
                )
            else:
                max_cardinality = self.domain.cardinality or opts.max_vector_items

                if len(normalized) > max_cardinality:
                    issues.append(
                        _issue(
                            severity=FeatureIssueSeverity.ERROR,
                            code="cardinality_exceeded",
                            message="Vector feature value exceeds allowed cardinality.",
                            feature=self.name,
                            details={"max_cardinality": max_cardinality},
                        )
                    )

                if self.domain.min_value is not None or self.domain.max_value is not None:
                    for item in normalized:
                        item_issues: list[FeatureValidationIssue] = []
                        self._validate_numeric_domain(item, item_issues)

                        if item_issues:
                            issues.extend(item_issues)
                            break

        has_error = any(issue.severity == FeatureIssueSeverity.ERROR for issue in issues)
        return not has_error, normalized, issues

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def safe_dict(self) -> dict[str, Any]:
        """
        Return a safe serializable feature specification summary.
        """
        return {
            "name": self.name,
            "label": self.label,
            "description": self.description,
            "dtype": self.dtype.value,
            "category": self.category.value,
            "window": self.window.value,
            "aggregation": self.aggregation.value,
            "transform": self.transform.value,
            "source": self.source.value,
            "role": self.role.value,
            "encoding": self.encoding.value,
            "privacy": self.privacy.value,
            "leakage": self.leakage.value,
            "stability": self.stability.value,
            "missing_strategy": self.missing_strategy.value,
            "unit": self.unit,
            "version": self.version,
            "tags": list(self.tags),
            "aliases": list(self.aliases),
            "dependencies": list(self.dependencies),
            "required": self.required,
            "explainable": self.explainable,
            "model_ready": self.model_ready,
            "deprecated": self.deprecated,
            "replacement": self.replacement,
            "domain": self.domain.safe_dict(),
        }


# -----------------------------------------------------------------------------
# Feature group model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeatureGroup:
    """
    Named group of related feature specifications.
    """

    name: str
    label: str
    description: str
    features: tuple[str, ...]
    category: FeatureCategory | str = FeatureCategory.OTHER
    window: FeatureWindow | str = FeatureWindow.NONE
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """
        Normalize group metadata.
        """
        name = _canonical_feature_name(self.name)

        if not name:
            raise ConfigurationError("Invalid feature group name.")

        object.__setattr__(self, "name", name)

        object.__setattr__(
            self,
            "label",
            _clean_text(self.label, 200) or name.replace("_", " ").title(),
        )

        object.__setattr__(
            self,
            "description",
            _clean_text(self.description, _MAX_DESCRIPTION_LENGTH),
        )

        object.__setattr__(
            self,
            "features",
            tuple(
                dict.fromkeys(
                    _canonical_feature_name(item)
                    for item in (self.features or ())
                    if _canonical_feature_name(item)
                )
            ),
        )

        object.__setattr__(
            self,
            "category",
            _enum_from_value(FeatureCategory, self.category, field_name="category"),
        )

        object.__setattr__(
            self,
            "window",
            _enum_from_value(FeatureWindow, self.window, field_name="window"),
        )

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

    def safe_dict(self) -> dict[str, Any]:
        """
        Return a safe serializable group summary.
        """
        return {
            "name": self.name,
            "label": self.label,
            "description": self.description,
            "features": list(self.features),
            "category": (
                self.category.value
                if isinstance(self.category, FeatureCategory)
                else str(self.category)
            ),
            "window": (
                self.window.value
                if isinstance(self.window, FeatureWindow)
                else str(self.window)
            ),
            "tags": list(self.tags),
        }

# -----------------------------------------------------------------------------
# Feature vector model
# -----------------------------------------------------------------------------

import threading

DEFAULT_MAX_VECTORS_PER_CALL: Final[int] = 1_000
HARD_MAX_VECTORS_PER_CALL: Final[int] = 10_000


def _serialize_feature_value(value: Any) -> Any:
    """
    Serialize one feature value into a JSON-safe representation.

    This is used for fingerprints, public summaries, and internal dictionaries.
    It never emits raw secrets, tokens, passwords, database URLs, filesystem
    paths, model artifact paths, raw complaint narratives, ground-truth labels,
    scenario IDs, or fraud-ring IDs.
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        return _clean_text(value, DEFAULT_MAX_STRING_LENGTH)

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, Decimal):
        return str(value) if value.is_finite() else None

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, timedelta):
        seconds = value.total_seconds()
        return seconds if math.isfinite(seconds) else None

    if isinstance(value, Enum):
        return _serialize_feature_value(value.value)

    if isinstance(value, (tuple, list, set, frozenset)):
        items = list(value)[:DEFAULT_MAX_SET_ITEMS]
        serialized = [_serialize_feature_value(item) for item in items]

        if isinstance(value, (set, frozenset)):
            try:
                serialized.sort(key=lambda item: str(item))
            except Exception:
                pass

        return serialized

    if isinstance(value, Mapping):
        return _safe_detail_value(value)

    return _clean_text(value, 300)


def _json_safe_features(features: Mapping[str, Any]) -> dict[str, Any]:
    """
    Return a JSON-safe copy of a feature mapping.
    """
    return {
        str(key): _serialize_feature_value(value)
        for key, value in features.items()
    }


@dataclass(slots=True)
class FeatureVector:
    """
    Validated feature vector with safe metadata.

    The `features` mapping is intended for internal model-preparation use.
    Public summaries deliberately omit feature values and expose only counts,
    names, fingerprints, and validation metadata.
    """

    subject_ref_hash: Optional[str] = None
    features: dict[str, Any] = dataclass_field(default_factory=dict)
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    validation: Optional[FeatureValidationResult] = None
    fingerprint: Optional[str] = None

    #: The real identifier of the subject this vector describes, for internal
    #: use only.
    #:
    #: `subject_ref_hash` is a one-way hash, so it identifies a subject without
    #: naming one -- which is the right thing to put in an API response and
    #: useless as a foreign key. The service layer needs the actual id to write
    #: a `model_assessments` row per account, and without it every vector was
    #: silently discarded: `analysis.py` drops any vector whose account cannot
    #: be resolved, so a run over 500 accounts scored 0 of them and reported
    #: `processed=0 errors=0` -- no failures, because nothing was ever
    #: attempted.
    #:
    #: Kept as a field of its own rather than a metadata key because
    #: `to_public_dict()` serialises `metadata` wholesale, and a raw account id
    #: does not belong in an API response. This field is excluded from
    #: `to_public_dict()` and from `compute_fingerprint()`, so the public shape
    #: and the fingerprint stay pseudonymous and unchanged.
    subject_id: Optional[str] = None

    def __post_init__(self) -> None:
        """
        Normalize vector identity, keys, metadata, and fingerprint.
        """
        if self.subject_ref_hash is not None:
            cleaned = _clean_text(self.subject_ref_hash, 256)
            self.subject_ref_hash = cleaned.lower() if cleaned and _is_safe_hash(cleaned) else cleaned or None

        normalized_features: dict[str, Any] = {}

        for raw_key, raw_value in (self.features or {}).items():
            key = _canonical_feature_name(raw_key)

            if not key:
                continue

            normalized_features[key] = raw_value

        self.features = normalized_features
        self.metadata = _safe_detail_value(self.metadata) or {}

        if self.subject_id is not None:
            self.subject_id = _clean_text(self.subject_id, 200) or None

        if self.fingerprint is None:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> Optional[str]:
        """
        Return a deterministic SHA-256 fingerprint for this vector.

        The fingerprint commits to subject reference, feature values, metadata,
        and schema version. It does not reveal feature values.
        """
        payload = {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "subject_ref_hash": self.subject_ref_hash,
            "features": _json_safe_features(self.features),
            "metadata": _safe_detail_value(self.metadata),
        }

        try:
            return _sha256_hex(_canonical_json(payload))
        except Exception:
            return None

    def get(self, name: str, default: Any = None) -> Any:
        """
        Return one feature value by canonical or aliased name.
        """
        return self.features.get(_canonical_feature_name(name), default)

    def __contains__(self, name: object) -> bool:
        """
        Return True when a feature name is present.
        """
        if not isinstance(name, str):
            return False

        return _canonical_feature_name(name) in self.features

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include feature values.
        """
        return {
            "subject_ref_hash": self.subject_ref_hash,
            "fingerprint": self.fingerprint,
            "feature_count": len(self.features),
            "feature_names": sorted(self.features),
            "metadata": _safe_detail_value(self.metadata),
            "validation": self.validation.to_response_dict() if self.validation is not None else None,
            "caveats": list(_FEATURE_SCHEMA_CAVEATS),
            "safety_flags": dict(_FEATURE_SAFETY_FLAGS),
        }

    def to_internal_dict(self, *, include_features: bool = True) -> dict[str, Any]:
        """
        Return a fuller internal representation for tests and tooling.

        Feature values are serialized into JSON-safe forms.
        """
        payload = self.to_public_dict()
        payload.pop("feature_names", None)

        if include_features:
            payload["features"] = _json_safe_features(self.features)
        else:
            payload["features_omitted"] = True

        return payload


def _downgrade_issue(
    issue: FeatureValidationIssue,
    *,
    strict: bool,
) -> FeatureValidationIssue:
    """
    Downgrade an error issue to a warning when non-strict validation is used.
    """
    if strict or issue.severity != FeatureIssueSeverity.ERROR:
        return issue

    return replace(issue, severity=FeatureIssueSeverity.WARNING)


class FeatureCatalog:
    """
    Bounded, versioned catalog of feature specifications and feature groups.

    The catalog is the authoritative schema for ML feature vectors in the
    MULEGUARD synthetic prototype. It validates feature names, aliases,
    domains, leakage policy, missing-value policy, and model-readiness metadata.
    """

    def __init__(
        self,
        version: str = FEATURE_CATALOG_VERSION,
        specs: Sequence[FeatureSpec | Mapping[str, Any]] | None = None,
        groups: Sequence[FeatureGroup | Mapping[str, Any]] | None = None,
    ) -> None:
        self.version = _clean_text(version, 32) or FEATURE_CATALOG_VERSION

        self._lock = threading.RLock()
        self._specs: dict[str, FeatureSpec] = {}
        self._alias_map: dict[str, str] = {}
        self._groups: dict[str, FeatureGroup] = {}
        self._fingerprint_cache: Optional[str] = None

        for spec in specs or ():
            self.add_spec(spec)

        for group in groups or ():
            self.add_group(group)

    # ------------------------------------------------------------------
    # Container protocol
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        """
        Return the number of registered feature specifications.
        """
        with self._lock:
            return len(self._specs)

    def __contains__(self, name: object) -> bool:
        """
        Return True when a feature name or alias is registered.
        """
        if not isinstance(name, str):
            return False

        return self._resolve_name(name) is not None

    def __iter__(self):
        """
        Iterate feature specifications in registration order.
        """
        with self._lock:
            return iter(list(self._specs.values()))

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def add_spec(
        self,
        spec: FeatureSpec | Mapping[str, Any],
        *,
        replace: bool = False,
    ) -> FeatureSpec:
        """
        Register one feature specification.
        """
        if isinstance(spec, Mapping):
            spec = FeatureSpec(**spec)

        if not isinstance(spec, FeatureSpec):
            raise ConfigurationError(
                "Feature catalog spec must be a FeatureSpec or mapping.",
                details={"type": type(spec).__name__},
            )

        with self._lock:
            existing = self._specs.get(spec.name)

            if existing is not None and not replace:
                raise ConfigurationError(
                    "Duplicate feature specification name.",
                    details={"name": spec.name},
                )

            if existing is not None:
                for alias in existing.aliases:
                    if self._alias_map.get(alias) == existing.name:
                        self._alias_map.pop(alias, None)

            for alias in spec.aliases:
                if alias in self._specs and alias != spec.name:
                    raise ConfigurationError(
                        "Feature alias conflicts with an existing feature name.",
                        details={"alias": alias, "feature": spec.name},
                    )

                mapped = self._alias_map.get(alias)

                if mapped is not None and mapped != spec.name:
                    raise ConfigurationError(
                        "Duplicate feature alias.",
                        details={"alias": alias, "existing_feature": mapped, "feature": spec.name},
                    )

                self._alias_map[alias] = spec.name

            self._specs[spec.name] = spec
            self._fingerprint_cache = None
            return spec

    def extend(self, specs: Iterable[FeatureSpec | Mapping[str, Any]]) -> "FeatureCatalog":
        """
        Register multiple feature specifications.
        """
        for spec in specs:
            self.add_spec(spec)

        return self

    def add_group(
        self,
        group: FeatureGroup | Mapping[str, Any],
        *,
        replace: bool = True,
    ) -> FeatureGroup:
        """
        Register one feature group.
        """
        if isinstance(group, Mapping):
            group = FeatureGroup(**group)

        if not isinstance(group, FeatureGroup):
            raise ConfigurationError(
                "Feature catalog group must be a FeatureGroup or mapping.",
                details={"type": type(group).__name__},
            )

        with self._lock:
            missing = [
                feature
                for feature in group.features
                if self._resolve_name(feature) is None
            ]

            if missing:
                raise ConfigurationError(
                    "Feature group references unknown features.",
                    details={
                        "group": group.name,
                        "missing_features": missing[:50],
                    },
                )

            if group.name in self._groups and not replace:
                raise ConfigurationError(
                    "Duplicate feature group name.",
                    details={"name": group.name},
                )

            self._groups[group.name] = group
            self._fingerprint_cache = None
            return group

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def _resolve_name(self, name: Any) -> Optional[str]:
        """
        Resolve a feature name or alias to a canonical feature name.
        """
        canonical = _canonical_feature_name(name)

        if not canonical:
            return None

        with self._lock:
            if canonical in self._specs:
                return canonical

            return self._alias_map.get(canonical)

    def get_spec(self, name: Any) -> Optional[FeatureSpec]:
        """
        Return one feature specification by name or alias.
        """
        resolved = self._resolve_name(name)

        if resolved is None:
            return None

        with self._lock:
            return self._specs.get(resolved)

    def require_spec(self, name: Any) -> FeatureSpec:
        """
        Return one feature specification or raise a safe validation error.
        """
        spec = self.get_spec(name)

        if spec is None:
            raise MuleGuardValidationError(
                "Unknown feature name.",
                details={
                    "field": "feature",
                    "value": _clean_text(name, 200),
                },
            )

        return spec

    @property
    def names(self) -> tuple[str, ...]:
        """
        Return all canonical feature names in registration order.
        """
        with self._lock:
            return tuple(self._specs.keys())

    @property
    def active_names(self) -> tuple[str, ...]:
        """
        Return non-deprecated feature names.
        """
        with self._lock:
            return tuple(
                name
                for name, spec in self._specs.items()
                if not spec.deprecated
            )

    @property
    def model_ready_names(self) -> tuple[str, ...]:
        """
        Return feature names marked model-ready and non-deprecated.
        """
        with self._lock:
            return tuple(
                name
                for name, spec in self._specs.items()
                if spec.model_ready and not spec.deprecated
            )

    @property
    def required_names(self) -> tuple[str, ...]:
        """
        Return required feature names.
        """
        with self._lock:
            return tuple(
                name
                for name, spec in self._specs.items()
                if spec.required and not spec.deprecated
            )

    @property
    def explainable_names(self) -> tuple[str, ...]:
        """
        Return explainable feature names.
        """
        with self._lock:
            return tuple(
                name
                for name, spec in self._specs.items()
                if spec.explainable and not spec.deprecated
            )

    @property
    def groups(self) -> tuple[FeatureGroup, ...]:
        """
        Return all registered feature groups.
        """
        with self._lock:
            return tuple(self._groups.values())

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_vector(
        self,
        features: Any,
        *,
        options: FeatureValidationOptions | None = None,
        subject_ref_hash: Any = None,
        subject_id: Any = None,
    ) -> FeatureVector:
        """
        Validate and normalize one feature vector.

        Args:
            features: Mapping of feature names/aliases to raw values.
            options: Optional validation policy.
            subject_ref_hash: Optional pseudonymous subject reference hash.
            subject_id: Optional real subject identifier, for internal use
                only. Never included in `to_public_dict()`.

        Returns:
            FeatureVector containing normalized features and safe validation
            metadata.
        """
        opts = options or FeatureValidationOptions.from_settings()
        result = FeatureValidationResult(max_issues=opts.max_issues)

        if not isinstance(features, Mapping):
            result.add_error(
                code="feature_vector_not_object",
                message="Feature vector must be a mapping.",
                details={"type": type(features).__name__},
            )
            result.finalize(opts)

            return FeatureVector(
                subject_ref_hash=None,
                features={},
                metadata={"catalog_version": self.version},
                validation=result,
                subject_id=subject_id,
            )

        submitted = len(features)
        result.submitted = submitted

        if submitted > opts.max_features:
            result.add_error(
                code="too_many_features",
                message="Feature vector exceeds configured feature limit.",
                details={
                    "submitted": submitted,
                    "max_features": opts.max_features,
                },
            )

        items = list(features.items())[: opts.max_features]

        normalized: dict[str, Any] = {}
        seen_names: set[str] = set()

        with self._lock:
            specs_snapshot = dict(self._specs)

            for raw_key, raw_value in items:
                key_text = _clean_text(raw_key, 200)
                canonical = _canonical_feature_name(key_text)

                if not canonical:
                    result.add_warning(
                        code="invalid_feature_name",
                        message="Feature name was empty or invalid and was omitted.",
                        field=key_text or None,
                    )
                    continue

                if _is_forbidden_feature_name(canonical):
                    result.forbidden.append(canonical)
                    result.add_error(
                        code="forbidden_feature",
                        message="Forbidden feature name omitted.",
                        feature=canonical,
                    )
                    continue

                resolved = self._resolve_name(canonical)

                if resolved is None:
                    result.unknown.append(canonical)

                    if opts.allow_unknown:
                        normalized[canonical] = _safe_detail_value(raw_value)
                        result.add_warning(
                            code="unknown_feature_allowed",
                            message="Unknown feature was allowed by configuration.",
                            feature=canonical,
                        )
                    elif opts.strict:
                        result.add_error(
                            code="unknown_feature",
                            message="Unknown feature omitted.",
                            feature=canonical,
                        )
                    else:
                        result.add_warning(
                            code="unknown_feature",
                            message="Unknown feature omitted.",
                            feature=canonical,
                        )

                    continue

                if resolved in seen_names:
                    result.add_warning(
                        code="duplicate_feature_alias",
                        message="Duplicate feature alias omitted.",
                        feature=resolved,
                        field=key_text,
                    )
                    continue

                seen_names.add(resolved)
                spec = specs_snapshot.get(resolved)

                if spec is None:
                    result.add_error(
                        code="unknown_feature",
                        message="Feature specification disappeared during validation.",
                        feature=resolved,
                    )
                    continue

                if opts.exclude_deprecated and spec.deprecated:
                    result.skipped.append(resolved)
                    continue

                ok, value, issues = spec.validate_value(raw_value, opts)

                for issue in issues:
                    result.add_issue(_downgrade_issue(issue, strict=opts.strict))

                if ok:
                    normalized[resolved] = value
                    result.accepted.append(resolved)
                else:
                    result.rejected.append(resolved)

            for name, spec in specs_snapshot.items():
                if name in seen_names:
                    continue

                if opts.exclude_deprecated and spec.deprecated:
                    result.skipped.append(name)
                    continue

                ok, value, issues = spec.validate_value(_MISSING, opts)

                for issue in issues:
                    result.add_issue(_downgrade_issue(issue, strict=opts.strict))

                if ok:
                    if value is not None or spec.required:
                        normalized[name] = value
                        result.accepted.append(name)
                    else:
                        result.skipped.append(name)
                else:
                    result.rejected.append(name)

            for name in list(normalized):
                spec = specs_snapshot.get(name)

                if spec is None or not spec.dependencies:
                    continue

                missing_dependencies = [
                    dependency
                    for dependency in spec.dependencies
                    if dependency not in normalized
                ]

                if missing_dependencies:
                    result.add_warning(
                        code="dependency_missing",
                        message="Feature dependencies are missing.",
                        feature=name,
                        details={
                            "missing_dependencies": missing_dependencies[:50],
                        },
                    )

        if len(normalized) > opts.max_features:
            ordered_names: list[str] = [
                name
                for name in specs_snapshot
                if name in normalized
            ]
            ordered_names.extend(
                name
                for name in normalized
                if name not in specs_snapshot
            )

            kept = set(ordered_names[: opts.max_features])
            dropped = [name for name in normalized if name not in kept]

            for name in dropped:
                normalized.pop(name, None)
                result.skipped.append(name)

            result.add_warning(
                code="max_features_exceeded",
                message="Feature vector truncated to configured feature limit.",
                details={
                    "max_features": opts.max_features,
                    "dropped_count": len(dropped),
                },
            )

        safe_subject = _clean_text(subject_ref_hash, 256) or None

        if safe_subject and not _is_safe_hash(safe_subject):
            result.add_warning(
                code="subject_ref_hash_format",
                message="Subject reference was not recognized as a pseudonymous hash and was omitted.",
            )
            safe_subject = None
        elif safe_subject:
            safe_subject = safe_subject.lower()

        metadata = {
            "catalog_version": self.version,
            "feature_count": len(normalized),
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
        }

        result.finalize(opts)

        return FeatureVector(
            subject_ref_hash=safe_subject,
            features=normalized,
            metadata=metadata,
            validation=result,
            subject_id=subject_id,
        )

    def validate_vectors(
        self,
        vectors: Any,
        *,
        options: FeatureValidationOptions | None = None,
    ) -> list[FeatureVector]:
        """
        Validate multiple feature vectors.

        Accepts:

        - a single mapping;
        - a single FeatureVector;
        - a sequence of mappings or FeatureVector objects.
        """
        opts = options or FeatureValidationOptions.from_settings()
        results: list[FeatureVector] = []

        if isinstance(vectors, (Mapping, FeatureVector)):
            candidates: Sequence[Any] = [vectors]
        elif isinstance(vectors, Sequence) and not isinstance(vectors, (str, bytes, bytearray)):
            candidates = vectors
        else:
            result = FeatureValidationResult(max_issues=opts.max_issues)
            result.add_error(
                code="feature_vectors_not_iterable",
                message="Feature vectors must be a mapping, FeatureVector, or sequence.",
                details={"type": type(vectors).__name__},
            )
            result.finalize(opts)
            return [
                FeatureVector(
                    features={},
                    metadata={"catalog_version": self.version},
                    validation=result,
                )
            ]

        max_vectors = min(HARD_MAX_VECTORS_PER_CALL, max(1, DEFAULT_MAX_VECTORS_PER_CALL))

        for index, candidate in enumerate(candidates[:max_vectors]):
            if isinstance(candidate, FeatureVector):
                features = candidate.features
                subject = candidate.subject_ref_hash
            elif isinstance(candidate, Mapping):
                features = candidate
                subject = candidate.get("subject_ref_hash")
            else:
                result = FeatureValidationResult(max_issues=opts.max_issues)
                result.add_error(
                    code="invalid_feature_vector",
                    message="Feature vector must be a mapping or FeatureVector.",
                    details={"index": index, "type": type(candidate).__name__},
                )
                result.finalize(opts)
                results.append(
                    FeatureVector(
                        features={},
                        metadata={"catalog_version": self.version, "index": index},
                        validation=result,
                    )
                )
                continue

            results.append(
                self.validate_vector(
                    features,
                    options=opts,
                    subject_ref_hash=subject,
                )
            )

        if len(candidates) > max_vectors:
            result = FeatureValidationResult(max_issues=opts.max_issues)
            result.add_warning(
                code="max_vectors_exceeded",
                message="Vector batch truncated by configured limit.",
                details={
                    "submitted": len(candidates),
                    "max_vectors": max_vectors,
                },
            )
            result.finalize(opts)
            results.append(
                FeatureVector(
                    features={},
                    metadata={"catalog_version": self.version, "truncated_batch": True},
                    validation=result,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def fingerprint(self) -> str:
        """
        Return a deterministic catalog fingerprint.
        """
        with self._lock:
            if self._fingerprint_cache is not None:
                return self._fingerprint_cache

            payload = {
                "version": self.version,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "features": [
                    spec.safe_dict()
                    for spec in self._specs.values()
                ],
                "groups": [
                    group.safe_dict()
                    for group in self._groups.values()
                ],
            }

            try:
                self._fingerprint_cache = _sha256_hex(_canonical_json(payload))
            except Exception:
                self._fingerprint_cache = _sha256_hex(str(len(self._specs)))

            return self._fingerprint_cache

    def to_dict(
        self,
        *,
        include_specs: bool = True,
        include_groups: bool = True,
    ) -> dict[str, Any]:
        """
        Return a safe serializable catalog representation.
        """
        with self._lock:
            payload: dict[str, Any] = {
                "version": self.version,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "feature_count": len(self._specs),
                "group_count": len(self._groups),
                "names": list(self._specs.keys()),
                "fingerprint": self.fingerprint(),
                "caveats": list(_FEATURE_SCHEMA_CAVEATS),
                "safety_flags": dict(_FEATURE_SAFETY_FLAGS),
            }

            if include_specs:
                payload["features"] = [
                    spec.safe_dict()
                    for spec in self._specs.values()
                ]

            if include_groups:
                payload["groups"] = [
                    group.safe_dict()
                    for group in self._groups.values()
                ]

            return payload

    def to_json_schema(
        self,
        *,
        allow_unknown: bool = False,
        title: str = "MULEGUARD Feature Vector",
    ) -> dict[str, Any]:
        """
        Return a JSON Schema projection for feature vectors.

        This schema is intended for documentation, client validation, and
        integration tests. Server-side `FeatureCatalog.validate_vector` remains
        authoritative.
        """
        properties: dict[str, Any] = {}
        required: list[str] = []

        with self._lock:
            for spec in self._specs.values():
                if spec.deprecated:
                    continue

                properties[spec.name] = _spec_json_schema(spec)

                if spec.required and not spec.domain.nullable:
                    required.append(spec.name)

        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": _clean_text(title, 200) or "MULEGUARD Feature Vector",
            "description": (
                "Bounded synthetic MULEGUARD ML feature vector schema. "
                "Features are investigative inputs only and are not proof of wrongdoing."
            ),
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": bool(allow_unknown),
            "x-muleguard": {
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "feature_catalog_version": self.version,
                "catalog_fingerprint": self.fingerprint(),
                "caveats": list(_FEATURE_SCHEMA_CAVEATS),
                "safety_flags": dict(_FEATURE_SAFETY_FLAGS),
            },
        }


def _nullable_json_type(base: Any, nullable: bool) -> Any:
    """
    Return a JSON Schema type expression that permits null when requested.
    """
    if not nullable:
        return base

    if isinstance(base, list):
        if "null" in base:
            return base

        return [*base, "null"]

    return [base, "null"]


def _spec_json_schema(spec: FeatureSpec) -> dict[str, Any]:
    """
    Return a JSON Schema fragment for one feature specification.
    """
    dtype = spec.dtype
    domain = spec.domain
    nullable = domain.nullable

    if dtype in {FeatureDType.INT, FeatureDType.COUNT}:
        schema: dict[str, Any] = {"type": "integer"}

        if domain.min_value is not None:
            schema["minimum"] = _decimal_to_float(domain.min_value)

        if domain.max_value is not None:
            schema["maximum"] = _decimal_to_float(domain.max_value)

    elif dtype in {
        FeatureDType.FLOAT,
        FeatureDType.RATIO,
        FeatureDType.PERCENT,
        FeatureDType.SCORE,
        FeatureDType.DURATION,
    }:
        schema = {"type": "number"}

        if domain.min_value is not None:
            schema["minimum"] = _decimal_to_float(domain.min_value)

        if domain.max_value is not None:
            schema["maximum"] = _decimal_to_float(domain.max_value)

    elif dtype in {FeatureDType.DECIMAL, FeatureDType.AMOUNT}:
        schema = {"type": ["number", "string"]}

        if domain.min_value is not None:
            schema["x-minimum"] = str(domain.min_value)

        if domain.max_value is not None:
            schema["x-maximum"] = str(domain.max_value)

    elif dtype == FeatureDType.BOOL:
        schema = {"type": "boolean"}

    elif dtype == FeatureDType.STRING:
        schema = {
            "type": "string",
            "maxLength": DEFAULT_MAX_STRING_LENGTH,
        }

        if domain.pattern:
            schema["pattern"] = domain.pattern

    elif dtype == FeatureDType.ENUM:
        allowed = [str(value) for value in domain.allowed_values]

        if allowed:
            schema = {
                "type": "string",
                "enum": allowed,
            }
        else:
            schema = {
                "type": "string",
                "maxLength": DEFAULT_MAX_STRING_LENGTH,
            }

    elif dtype == FeatureDType.DATETIME:
        schema = {
            "type": "string",
            "format": "date-time",
        }

    elif dtype == FeatureDType.SET:
        if domain.allowed_values:
            items: dict[str, Any] = {
                "type": "string",
                "enum": [str(value) for value in domain.allowed_values],
            }
        else:
            items = {
                "type": ["string", "number", "boolean"],
            }

        schema = {
            "type": "array",
            "uniqueItems": True,
            "maxItems": domain.cardinality or DEFAULT_MAX_SET_ITEMS,
            "items": items,
        }

    elif dtype == FeatureDType.VECTOR:
        item_schema: dict[str, Any] = {"type": "number"}

        if domain.min_value is not None:
            item_schema["minimum"] = _decimal_to_float(domain.min_value)

        if domain.max_value is not None:
            item_schema["maximum"] = _decimal_to_float(domain.max_value)

        schema = {
            "type": "array",
            "maxItems": domain.cardinality or DEFAULT_MAX_VECTOR_ITEMS,
            "items": item_schema,
        }

    else:
        schema = {}

    schema["type"] = _nullable_json_type(schema.get("type", "string"), nullable)
    schema["description"] = spec.description
    schema["x-muleguard"] = {
        "name": spec.name,
        "label": spec.label,
        "dtype": spec.dtype.value,
        "category": spec.category.value,
        "window": spec.window.value,
        "aggregation": spec.aggregation.value,
        "source": spec.source.value,
        "role": spec.role.value,
        "encoding": spec.encoding.value,
        "privacy": spec.privacy.value,
        "leakage": spec.leakage.value,
        "stability": spec.stability.value,
        "missing_strategy": spec.missing_strategy.value,
        "unit": spec.unit,
        "version": spec.version,
        "tags": list(spec.tags),
        "aliases": list(spec.aliases),
        "dependencies": list(spec.dependencies),
        "required": spec.required,
        "explainable": spec.explainable,
        "model_ready": spec.model_ready,
        "deprecated": spec.deprecated,
        "replacement": spec.replacement,
    }

    return schema


# -----------------------------------------------------------------------------
# Default synthetic feature catalog
# -----------------------------------------------------------------------------


def _fs(
    name: str,
    label: str,
    description: str,
    dtype: FeatureDType,
    category: FeatureCategory,
    window: FeatureWindow,
    aggregation: FeatureAggregation,
    source: FeatureSource,
    **kwargs: Any,
) -> FeatureSpec:
    """
    Convenience constructor for default feature specifications.
    """
    kwargs.setdefault("privacy", FeaturePrivacy.SYNTHETIC)
    kwargs.setdefault("leakage", FeatureLeakage.SAFE)
    kwargs.setdefault("stability", FeatureStability.STABLE)
    kwargs.setdefault("missing_strategy", FeatureMissingStrategy.NONE)
    kwargs.setdefault("explainable", True)
    kwargs.setdefault("model_ready", True)

    return FeatureSpec(
        name=name,
        label=label,
        description=description,
        dtype=dtype,
        category=category,
        window=window,
        aggregation=aggregation,
        source=source,
        **kwargs,
    )


# Behavioural segments, aligned with the account types above. "wallet" is
# gone because no such account type exists; "merchant" is present because one
# does, and a merchant's inbound pattern is the main hard negative the
# detector has to get right.
_ACCOUNT_SEGMENT_VALUES: Final[tuple[str, ...]] = (
    "retail",
    "business",
    "merchant",
    "dormant",
    "other",
)


def build_default_feature_catalog() -> FeatureCatalog:
    """
    Build the canonical bounded synthetic MULEGUARD feature catalog.

    The catalog contains investigative feature specifications only. It does not
    include ground-truth labels, scenario IDs, fraud-ring IDs, raw complaint
    narratives, raw identifiers, secrets, tokens, passwords, database URLs,
    filesystem paths, or model artifact paths.
    """
    catalog = FeatureCatalog(version=FEATURE_CATALOG_VERSION)

    specs: list[FeatureSpec] = [
        # -----------------------------------------------------------------
        # Account profile and static observational features
        # -----------------------------------------------------------------
        _fs(
            "account_age_days",
            "Account age in days",
            "Age of the synthetic account in days at observation time.",
            FeatureDType.COUNT,
            FeatureCategory.PROFILE,
            FeatureWindow.NONE,
            FeatureAggregation.RAW,
            FeatureSource.ACCOUNT,
            required=True,
            missing_strategy=FeatureMissingStrategy.ERROR,
            domain=FeatureDomain(min_value=Decimal(0), nullable=False),
        ),
        _fs(
            "account_type_enum",
            "Account type",
            "Synthetic account type label.",
            FeatureDType.ENUM,
            FeatureCategory.PROFILE,
            FeatureWindow.NONE,
            FeatureAggregation.RAW,
            FeatureSource.ACCOUNT,
            domain=_enum_domain(*_ACCOUNT_TYPES, nullable=True),
        ),
        _fs(
            "account_status_enum",
            "Account status",
            "Observational synthetic account status label. Status does not authorize adverse action.",
            FeatureDType.ENUM,
            FeatureCategory.PROFILE,
            FeatureWindow.NONE,
            FeatureAggregation.RAW,
            FeatureSource.ACCOUNT,
            domain=_enum_domain(*_ACCOUNT_STATUSES, nullable=True),
        ),
        _fs(
            "account_segment_enum",
            "Account segment",
            "Synthetic behavioural segment label used for profiling only.",
            FeatureDType.ENUM,
            FeatureCategory.PROFILE,
            FeatureWindow.NONE,
            FeatureAggregation.RAW,
            FeatureSource.ACCOUNT,
            domain=_enum_domain(*_ACCOUNT_SEGMENT_VALUES, nullable=True),
        ),
        _fs(
            "is_dormant_flag",
            "Dormant account flag",
            "Whether the synthetic account is marked dormant.",
            FeatureDType.BOOL,
            FeatureCategory.PROFILE,
            FeatureWindow.NONE,
            FeatureAggregation.FLAG,
            FeatureSource.ACCOUNT,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(nullable=False),
        ),
        _fs(
            "is_wallet_flag",
            "Wallet account flag",
            "Whether the synthetic account is a wallet-type account.",
            FeatureDType.BOOL,
            FeatureCategory.PROFILE,
            FeatureWindow.NONE,
            FeatureAggregation.FLAG,
            FeatureSource.ACCOUNT,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(nullable=False),
        ),
        _fs(
            "is_business_flag",
            "Business account flag",
            "Whether the synthetic account is a business-type account.",
            FeatureDType.BOOL,
            FeatureCategory.PROFILE,
            FeatureWindow.NONE,
            FeatureAggregation.FLAG,
            FeatureSource.ACCOUNT,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(nullable=False),
        ),

        # -----------------------------------------------------------------
        # Balance features
        # -----------------------------------------------------------------
        _fs(
            "balance_mean_30d",
            "Mean balance, 30 days",
            "Mean synthetic account balance over a 30-day window.",
            FeatureDType.AMOUNT,
            FeatureCategory.BALANCE,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.MEAN,
            FeatureSource.ACCOUNT,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(min_value=Decimal(0), nullable=False),
        ),
        _fs(
            "balance_min_30d",
            "Minimum balance, 30 days",
            "Minimum synthetic account balance over a 30-day window.",
            FeatureDType.AMOUNT,
            FeatureCategory.BALANCE,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.MIN,
            FeatureSource.ACCOUNT,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(min_value=Decimal(0), nullable=False),
        ),
        _fs(
            "balance_max_30d",
            "Maximum balance, 30 days",
            "Maximum synthetic account balance over a 30-day window.",
            FeatureDType.AMOUNT,
            FeatureCategory.BALANCE,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.MAX,
            FeatureSource.ACCOUNT,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(min_value=Decimal(0), nullable=False),
        ),
        _fs(
            "balance_stddev_30d",
            "Balance standard deviation, 30 days",
            "Standard deviation of synthetic balance over a 30-day window.",
            FeatureDType.FLOAT,
            FeatureCategory.BALANCE,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.STDDEV,
            FeatureSource.ACCOUNT,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(min_value=Decimal(0), nullable=False),
        ),
        _fs(
            "balance_cv_30d",
            "Balance coefficient of variation, 30 days",
            "Ratio of balance standard deviation to mean balance.",
            FeatureDType.RATIO,
            FeatureCategory.BALANCE,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.CV,
            FeatureSource.ACCOUNT,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "balance_slope_30d",
            "Balance slope, 30 days",
            "Linear trend slope of synthetic balance over a 30-day window.",
            FeatureDType.FLOAT,
            FeatureCategory.TREND,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SLOPE,
            FeatureSource.ACCOUNT,
            domain=FeatureDomain(nullable=True),
        ),
        _fs(
            "balance_drop_ratio_7d",
            "Balance drop ratio, 7 days",
            "Relative decline in synthetic balance over a 7-day window.",
            FeatureDType.RATIO,
            FeatureCategory.TREND,
            FeatureWindow.SEVEN_DAY,
            FeatureAggregation.RATIO,
            FeatureSource.ACCOUNT,
            domain=_ratio_domain(nullable=True),
        ),

        # -----------------------------------------------------------------
        # Transaction volume features
        # -----------------------------------------------------------------
        _fs(
            "txn_count_1h",
            "Transaction count, 1 hour",
            "Count of synthetic transactions in a 1-hour window.",
            FeatureDType.COUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.ONE_HOUR,
            FeatureAggregation.COUNT,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "txn_count_24h",
            "Transaction count, 24 hours",
            "Count of synthetic transactions in a 24-hour window.",
            FeatureDType.COUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.ONE_DAY,
            FeatureAggregation.COUNT,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "txn_count_7d",
            "Transaction count, 7 days",
            "Count of synthetic transactions in a 7-day window.",
            FeatureDType.COUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.SEVEN_DAY,
            FeatureAggregation.COUNT,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "txn_count_30d",
            "Transaction count, 30 days",
            "Count of synthetic transactions in a 30-day window.",
            FeatureDType.COUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.COUNT,
            FeatureSource.TRANSACTION,
            required=True,
            missing_strategy=FeatureMissingStrategy.ERROR,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "txn_count_90d",
            "Transaction count, 90 days",
            "Count of synthetic transactions in a 90-day window.",
            FeatureDType.COUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.NINETY_DAY,
            FeatureAggregation.COUNT,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "txn_count_all",
            "Transaction count, all time",
            "Count of synthetic transactions across the available observation window.",
            FeatureDType.COUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.ALL,
            FeatureAggregation.COUNT,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "txn_amount_sum_24h",
            "Transaction amount sum, 24 hours",
            "Sum of synthetic transaction amounts in a 24-hour window.",
            FeatureDType.AMOUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.ONE_DAY,
            FeatureAggregation.SUM,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_amount_domain(nullable=False),
        ),
        _fs(
            "txn_amount_sum_7d",
            "Transaction amount sum, 7 days",
            "Sum of synthetic transaction amounts in a 7-day window.",
            FeatureDType.AMOUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.SEVEN_DAY,
            FeatureAggregation.SUM,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_amount_domain(nullable=False),
        ),
        _fs(
            "txn_amount_sum_30d",
            "Transaction amount sum, 30 days",
            "Sum of synthetic transaction amounts in a 30-day window.",
            FeatureDType.AMOUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SUM,
            FeatureSource.TRANSACTION,
            required=True,
            missing_strategy=FeatureMissingStrategy.ERROR,
            domain=_amount_domain(nullable=False),
        ),
        _fs(
            "txn_amount_mean_24h",
            "Mean transaction amount, 24 hours",
            "Mean synthetic transaction amount in a 24-hour window.",
            FeatureDType.AMOUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.ONE_DAY,
            FeatureAggregation.MEAN,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_amount_domain(nullable=False),
        ),
        _fs(
            "txn_amount_mean_30d",
            "Mean transaction amount, 30 days",
            "Mean synthetic transaction amount in a 30-day window.",
            FeatureDType.AMOUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.MEAN,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_amount_domain(nullable=False),
        ),
        _fs(
            "txn_amount_median_30d",
            "Median transaction amount, 30 days",
            "Median synthetic transaction amount in a 30-day window.",
            FeatureDType.AMOUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.MEDIAN,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_amount_domain(nullable=False),
        ),
        _fs(
            "txn_amount_max_24h",
            "Maximum transaction amount, 24 hours",
            "Maximum synthetic transaction amount in a 24-hour window.",
            FeatureDType.AMOUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.ONE_DAY,
            FeatureAggregation.MAX,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_amount_domain(nullable=False),
        ),
        _fs(
            "txn_amount_max_30d",
            "Maximum transaction amount, 30 days",
            "Maximum synthetic transaction amount in a 30-day window.",
            FeatureDType.AMOUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.MAX,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_amount_domain(nullable=False),
        ),
        _fs(
            "txn_amount_min_30d",
            "Minimum transaction amount, 30 days",
            "Minimum synthetic transaction amount in a 30-day window.",
            FeatureDType.AMOUNT,
            FeatureCategory.VOLUME,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.MIN,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_amount_domain(nullable=False),
        ),
        _fs(
            "txn_amount_stddev_30d",
            "Transaction amount standard deviation, 30 days",
            "Standard deviation of synthetic transaction amounts in a 30-day window.",
            FeatureDType.FLOAT,
            FeatureCategory.VOLUME,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.STDDEV,
            FeatureSource.TRANSACTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(min_value=Decimal(0), nullable=False),
        ),
        _fs(
            "txn_amount_cv_30d",
            "Transaction amount coefficient of variation, 30 days",
            "Ratio of transaction amount standard deviation to mean amount.",
            FeatureDType.RATIO,
            FeatureCategory.VOLUME,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.CV,
            FeatureSource.TRANSACTION,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "txn_amount_zscore_30d",
            "Transaction amount z-score, 30 days",
            "Standardized transaction amount deviation over a 30-day window.",
            FeatureDType.FLOAT,
            FeatureCategory.ANOMALY,
            FeatureWindow.THIRTY_DAY,
            # The aggregation is a score; the standardisation is a transform.
            # `ZSCORE` is a member of `FeatureTransform`, not of
            # `FeatureAggregation`, and passing it here raised an
            # AttributeError while the catalogue was being built — which made
            # every caller of `get_feature_catalog()` fail.
            FeatureAggregation.SCORE,
            FeatureSource.DERIVED,
            transform=FeatureTransform.ZSCORE,
            leakage=FeatureLeakage.CAUTION,
            domain=FeatureDomain(min_value=Decimal(-10), max_value=Decimal(10), nullable=True),
        ),
        _fs(
            "txn_amount_anomaly_score_30d",
            "Transaction amount anomaly score, 30 days",
            "Bounded synthetic anomaly score for transaction amount behaviour.",
            FeatureDType.SCORE,
            FeatureCategory.ANOMALY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SCORE,
            FeatureSource.DERIVED,
            leakage=FeatureLeakage.CAUTION,
            stability=FeatureStability.DRIFT_PRONE,
            domain=_score_domain(nullable=True),
        ),

        # -----------------------------------------------------------------
        # Velocity and temporal features
        # -----------------------------------------------------------------
        _fs(
            "txn_count_velocity_ratio_7d_30d",
            "Transaction velocity ratio, 7d to 30d",
            "Ratio of 7-day transaction count to daily average 30-day transaction count.",
            FeatureDType.RATIO,
            FeatureCategory.VELOCITY,
            FeatureWindow.SEVEN_DAY,
            FeatureAggregation.RATIO,
            FeatureSource.DERIVED,
            dependencies=("txn_count_7d", "txn_count_30d"),
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "txn_count_burstiness_24h",
            "Transaction burstiness, 24 hours",
            "Bounded burstiness measure for synthetic transaction timing.",
            FeatureDType.FLOAT,
            FeatureCategory.VELOCITY,
            FeatureWindow.ONE_DAY,
            FeatureAggregation.BURSTINESS,
            FeatureSource.DERIVED,
            domain=FeatureDomain(min_value=Decimal(0), nullable=True),
        ),
        _fs(
            "txn_interarrival_mean_seconds_24h",
            "Mean interarrival time, 24 hours",
            "Mean seconds between synthetic transactions in a 24-hour window.",
            FeatureDType.DURATION,
            FeatureCategory.TEMPORAL,
            FeatureWindow.ONE_DAY,
            FeatureAggregation.INTERARRIVAL,
            FeatureSource.DERIVED,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_duration_domain(nullable=False),
        ),
        _fs(
            "txn_night_ratio_30d",
            "Night transaction ratio, 30 days",
            "Share of synthetic transactions occurring in configured night hours.",
            FeatureDType.RATIO,
            FeatureCategory.TEMPORAL,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "txn_weekend_ratio_30d",
            "Weekend transaction ratio, 30 days",
            "Share of synthetic transactions occurring on weekend days.",
            FeatureDType.RATIO,
            FeatureCategory.TEMPORAL,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "txn_hour_entropy_30d",
            "Hour entropy, 30 days",
            "Normalized entropy of synthetic transaction hour-of-day distribution.",
            FeatureDType.RATIO,
            FeatureCategory.TEMPORAL,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.ENTROPY,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "txn_day_entropy_30d",
            "Day entropy, 30 days",
            "Normalized entropy of synthetic transaction day-of-week distribution.",
            FeatureDType.RATIO,
            FeatureCategory.TEMPORAL,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.ENTROPY,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "txn_count_delta_7d_vs_prior_7d",
            "Transaction count delta, 7d vs prior 7d",
            "Absolute change in synthetic transaction count versus prior 7-day window.",
            FeatureDType.FLOAT,
            FeatureCategory.TREND,
            FeatureWindow.SEVEN_DAY,
            FeatureAggregation.DELTA,
            FeatureSource.DERIVED,
            domain=FeatureDomain(nullable=True),
        ),
        _fs(
            "txn_amount_delta_7d_vs_prior_7d",
            "Transaction amount delta, 7d vs prior 7d",
            "Absolute change in synthetic transaction amount versus prior 7-day window.",
            FeatureDType.FLOAT,
            FeatureCategory.TREND,
            FeatureWindow.SEVEN_DAY,
            FeatureAggregation.DELTA,
            FeatureSource.DERIVED,
            domain=FeatureDomain(nullable=True),
        ),
        _fs(
            "txn_count_pct_change_7d",
            "Transaction count percent change, 7 days",
            "Percent change in synthetic transaction count over a 7-day window.",
            FeatureDType.FLOAT,
            FeatureCategory.TREND,
            FeatureWindow.SEVEN_DAY,
            # Same mix-up as the z-score feature above: `PCT_CHANGE` is a
            # `FeatureTransform`, not a `FeatureAggregation`. The thing being
            # aggregated is a count; the percentage change is the transform.
            FeatureAggregation.COUNT,
            FeatureSource.DERIVED,
            transform=FeatureTransform.PCT_CHANGE,
            domain=FeatureDomain(min_value=Decimal(-100), max_value=Decimal(1000), nullable=True),
        ),

        # -----------------------------------------------------------------
        # Counterparty features
        # -----------------------------------------------------------------
        _fs(
            "counterparty_distinct_count_30d",
            "Distinct counterparty count, 30 days",
            "Number of distinct synthetic counterparties in a 30-day window.",
            FeatureDType.COUNT,
            FeatureCategory.COUNTERPARTY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.TRANSACTION,
            required=True,
            missing_strategy=FeatureMissingStrategy.ERROR,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "counterparty_new_ratio_30d",
            "New counterparty ratio, 30 days",
            "Share of synthetic counterparties first observed in the window.",
            FeatureDType.RATIO,
            FeatureCategory.COUNTERPARTY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.NEW_RATIO,
            FeatureSource.DERIVED,
            dependencies=("txn_count_30d", "counterparty_distinct_count_30d"),
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "counterparty_repeat_ratio_30d",
            "Repeat counterparty ratio, 30 days",
            "Share of synthetic transactions involving repeat counterparties.",
            FeatureDType.RATIO,
            FeatureCategory.COUNTERPARTY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.REPEAT_RATIO,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "counterparty_top1_share_30d",
            "Top counterparty share, 30 days",
            "Share of synthetic transaction volume attributable to the top counterparty.",
            FeatureDType.RATIO,
            FeatureCategory.COUNTERPARTY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.TOP_N_SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "counterparty_top5_share_30d",
            "Top five counterparty share, 30 days",
            "Share of synthetic transaction volume attributable to the top five counterparties.",
            FeatureDType.RATIO,
            FeatureCategory.COUNTERPARTY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.TOP_N_SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "counterparty_hhi_30d",
            "Counterparty Herfindahl index, 30 days",
            "Concentration index for synthetic counterparty distribution.",
            FeatureDType.RATIO,
            FeatureCategory.COUNTERPARTY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.HHI,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "counterparty_entropy_30d",
            "Counterparty entropy, 30 days",
            "Normalized entropy of synthetic counterparty distribution.",
            FeatureDType.RATIO,
            FeatureCategory.COUNTERPARTY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.ENTROPY,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "outbound_amount_share_30d",
            "Outbound amount share, 30 days",
            "Share of synthetic transaction amount sent outward.",
            FeatureDType.RATIO,
            FeatureCategory.COUNTERPARTY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "inbound_outbound_amount_ratio_30d",
            "Inbound to outbound amount ratio, 30 days",
            "Ratio of inbound to outbound synthetic transaction amount.",
            FeatureDType.FLOAT,
            FeatureCategory.COUNTERPARTY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.RATIO,
            FeatureSource.DERIVED,
            domain=FeatureDomain(min_value=Decimal(0), nullable=True),
        ),

        # -----------------------------------------------------------------
        # Channel features
        # -----------------------------------------------------------------
        _fs(
            "channel_upi_share_30d",
            "UPI channel share, 30 days",
            "Share of synthetic transactions using the UPI channel.",
            FeatureDType.RATIO,
            FeatureCategory.CHANNEL,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "channel_wallet_share_30d",
            "Wallet channel share, 30 days",
            "Share of synthetic transactions using wallet channels.",
            FeatureDType.RATIO,
            FeatureCategory.CHANNEL,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "channel_cash_share_30d",
            "Cash channel share, 30 days",
            "Share of synthetic transactions using cash channels.",
            FeatureDType.RATIO,
            FeatureCategory.CHANNEL,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "channel_external_share_30d",
            "External channel share, 30 days",
            "Share of synthetic transactions using external channels.",
            FeatureDType.RATIO,
            FeatureCategory.CHANNEL,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "channel_entropy_30d",
            "Channel entropy, 30 days",
            "Normalized entropy of synthetic channel distribution.",
            FeatureDType.RATIO,
            FeatureCategory.CHANNEL,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.ENTROPY,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "channel_switch_count_7d",
            "Channel switch count, 7 days",
            "Count of synthetic channel switches in a 7-day window.",
            FeatureDType.COUNT,
            FeatureCategory.CHANNEL,
            FeatureWindow.SEVEN_DAY,
            FeatureAggregation.COUNT,
            FeatureSource.DERIVED,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),

        # -----------------------------------------------------------------
        # Entity and link features
        # -----------------------------------------------------------------
        _fs(
            "entity_link_count_30d",
            "Entity link count, 30 days",
            "Count of synthetic account-entity links in a 30-day window.",
            FeatureDType.COUNT,
            FeatureCategory.LINK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.COUNT,
            FeatureSource.ENTITY_LINK,
            required=True,
            missing_strategy=FeatureMissingStrategy.ERROR,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "device_distinct_count_30d",
            "Distinct device entity count, 30 days",
            "Number of distinct pseudonymous device entities linked in a 30-day window.",
            FeatureDType.COUNT,
            FeatureCategory.ENTITY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.ENTITY,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "ip_distinct_count_30d",
            "Distinct IP entity count, 30 days",
            "Number of distinct pseudonymous IP entities linked in a 30-day window.",
            FeatureDType.COUNT,
            FeatureCategory.ENTITY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.ENTITY,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "phone_distinct_count_30d",
            "Distinct phone entity count, 30 days",
            "Number of distinct pseudonymous phone entities linked in a 30-day window.",
            FeatureDType.COUNT,
            FeatureCategory.ENTITY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.ENTITY,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "email_distinct_count_30d",
            "Distinct email entity count, 30 days",
            "Number of distinct pseudonymous email entities linked in a 30-day window.",
            FeatureDType.COUNT,
            FeatureCategory.ENTITY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.ENTITY,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "upi_distinct_count_30d",
            "Distinct UPI entity count, 30 days",
            "Number of distinct pseudonymous UPI entities linked in a 30-day window.",
            FeatureDType.COUNT,
            FeatureCategory.ENTITY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.ENTITY,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "shared_device_account_count_30d",
            "Shared device account count, 30 days",
            "Number of synthetic accounts sharing pseudonymous device entities.",
            FeatureDType.COUNT,
            FeatureCategory.ENTITY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.ENTITY,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "shared_ip_account_count_30d",
            "Shared IP account count, 30 days",
            "Number of synthetic accounts sharing pseudonymous IP entities.",
            FeatureDType.COUNT,
            FeatureCategory.ENTITY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.ENTITY,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "shared_upi_account_count_30d",
            "Shared UPI account count, 30 days",
            "Number of synthetic accounts sharing pseudonymous UPI entities.",
            FeatureDType.COUNT,
            FeatureCategory.ENTITY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.ENTITY,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "entity_link_heuristic_ratio_30d",
            "Heuristic entity link ratio, 30 days",
            "Share of synthetic entity links produced by heuristic matching.",
            FeatureDType.RATIO,
            FeatureCategory.LINK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "entity_link_unverified_ratio_30d",
            "Unverified entity link ratio, 30 days",
            "Share of synthetic entity links that remain unverified.",
            FeatureDType.RATIO,
            FeatureCategory.LINK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "entity_link_confidence_mean_30d",
            "Mean entity link confidence, 30 days",
            "Mean confidence of synthetic entity links in a 30-day window.",
            FeatureDType.RATIO,
            FeatureCategory.LINK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.MEAN,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),

        # -----------------------------------------------------------------
        # Complaint features
        # -----------------------------------------------------------------
        _fs(
            "complaint_count_30d",
            "Complaint count, 30 days",
            "Count of synthetic complaints associated with the subject in a 30-day window.",
            FeatureDType.COUNT,
            FeatureCategory.COMPLAINT,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.COUNT,
            FeatureSource.COMPLAINT,
            required=True,
            missing_strategy=FeatureMissingStrategy.ERROR,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "complaint_rate_30d",
            "Complaint rate, 30 days",
            "Synthetic complaints per day over a 30-day window.",
            FeatureDType.FLOAT,
            FeatureCategory.COMPLAINT,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.RATE,
            FeatureSource.DERIVED,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(min_value=Decimal(0), nullable=False),
        ),
        _fs(
            "complaint_category_entropy_30d",
            "Complaint category entropy, 30 days",
            "Normalized entropy of synthetic complaint category distribution.",
            FeatureDType.RATIO,
            FeatureCategory.COMPLAINT,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.ENTROPY,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "complaint_victim_count_30d",
            "Victim account count, 30 days",
            "Number of distinct synthetic victim accounts referenced in complaints.",
            FeatureDType.COUNT,
            FeatureCategory.COMPLAINT,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.COMPLAINT,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "complaint_suspect_count_30d",
            "Suspect account count, 30 days",
            "Number of distinct synthetic suspected accounts referenced in complaints. This is an investigative label only.",
            FeatureDType.COUNT,
            FeatureCategory.COMPLAINT,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.COMPLAINT,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "complaint_recency_days",
            "Complaint recency in days",
            "Days since the most recent synthetic complaint, when available.",
            FeatureDType.COUNT,
            FeatureCategory.COMPLAINT,
            FeatureWindow.ALL,
            FeatureAggregation.RECENCY,
            FeatureSource.COMPLAINT,
            domain=_count_domain(nullable=True),
        ),
        _fs(
            "complaint_linked_txn_ratio_30d",
            "Complaint linked transaction ratio, 30 days",
            "Share of synthetic complaints referencing a known transaction.",
            FeatureDType.RATIO,
            FeatureCategory.COMPLAINT,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SHARE,
            FeatureSource.DERIVED,
            domain=_ratio_domain(nullable=True),
        ),

        # -----------------------------------------------------------------
        # Graph and network features
        # -----------------------------------------------------------------
        _fs(
            "graph_degree_30d",
            "Graph degree, 30 days",
            "Total synthetic graph degree in a bounded 30-day view.",
            FeatureDType.COUNT,
            FeatureCategory.NETWORK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DEGREE,
            FeatureSource.GRAPH,
            required=True,
            missing_strategy=FeatureMissingStrategy.ERROR,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "graph_in_degree_30d",
            "Graph in-degree, 30 days",
            "Inbound synthetic graph degree in a bounded 30-day view.",
            FeatureDType.COUNT,
            FeatureCategory.NETWORK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DEGREE,
            FeatureSource.GRAPH,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "graph_out_degree_30d",
            "Graph out-degree, 30 days",
            "Outbound synthetic graph degree in a bounded 30-day view.",
            FeatureDType.COUNT,
            FeatureCategory.NETWORK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DEGREE,
            FeatureSource.GRAPH,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "graph_page_rank_norm_30d",
            "Normalized graph centrality, 30 days",
            "Bounded normalized centrality score from synthetic graph analysis.",
            FeatureDType.SCORE,
            FeatureCategory.NETWORK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SCORE,
            FeatureSource.GRAPH,
            leakage=FeatureLeakage.CAUTION,
            stability=FeatureStability.DRIFT_PRONE,
            domain=_score_domain(nullable=True),
        ),
        _fs(
            "graph_betweenness_norm_30d",
            "Normalized betweenness, 30 days",
            "Bounded normalized betweenness measure from synthetic graph analysis.",
            FeatureDType.RATIO,
            FeatureCategory.NETWORK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SCORE,
            FeatureSource.GRAPH,
            leakage=FeatureLeakage.CAUTION,
            stability=FeatureStability.DRIFT_PRONE,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "graph_cycle_indicator_30d",
            "Graph cycle indicator, 30 days",
            "Whether bounded synthetic graph exploration detected cycle-like structure.",
            FeatureDType.BOOL,
            FeatureCategory.GRAPH,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.CYCLE_INDICATOR,
            FeatureSource.GRAPH,
            leakage=FeatureLeakage.CAUTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=FeatureDomain(nullable=False),
        ),
        _fs(
            "graph_path_count_30d",
            "Graph path count, 30 days",
            "Count of bounded candidate synthetic graph paths.",
            FeatureDType.COUNT,
            FeatureCategory.GRAPH,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.PATH_COUNT,
            FeatureSource.GRAPH,
            leakage=FeatureLeakage.CAUTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "graph_intermediary_score_30d",
            "Intermediary structure score, 30 days",
            "Bounded heuristic score for intermediary-like synthetic flow structure. This is not proof of wrongdoing.",
            FeatureDType.SCORE,
            FeatureCategory.GRAPH,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SCORE,
            FeatureSource.GRAPH,
            leakage=FeatureLeakage.CAUTION,
            stability=FeatureStability.VOLATILE,
            domain=_score_domain(nullable=True),
        ),
        _fs(
            "graph_source_concentration_30d",
            "Source concentration, 30 days",
            "Concentration of inbound synthetic flow sources.",
            FeatureDType.RATIO,
            FeatureCategory.GRAPH,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.HHI,
            FeatureSource.GRAPH,
            leakage=FeatureLeakage.CAUTION,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "graph_beneficiary_concentration_30d",
            "Beneficiary concentration, 30 days",
            "Concentration of outbound synthetic flow beneficiaries.",
            FeatureDType.RATIO,
            FeatureCategory.GRAPH,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.HHI,
            FeatureSource.GRAPH,
            leakage=FeatureLeakage.CAUTION,
            domain=_ratio_domain(nullable=True),
        ),
        _fs(
            "graph_shared_entity_cluster_size_30d",
            "Shared entity cluster size, 30 days",
            "Size of bounded synthetic shared-entity cluster.",
            FeatureDType.COUNT,
            FeatureCategory.NETWORK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.DISTINCT_COUNT,
            FeatureSource.GRAPH,
            leakage=FeatureLeakage.CAUTION,
            missing_strategy=FeatureMissingStrategy.ZERO,
            domain=_count_domain(nullable=False),
        ),
        _fs(
            "graph_neighbor_complaint_ratio_30d",
            "Neighbour complaint ratio, 30 days",
            "Share of bounded synthetic graph neighbours associated with complaints.",
            FeatureDType.RATIO,
            FeatureCategory.NETWORK,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.RATE,
            FeatureSource.GRAPH,
            leakage=FeatureLeakage.CAUTION,
            domain=_ratio_domain(nullable=True),
        ),

        # -----------------------------------------------------------------
        # Composite anomaly features
        # -----------------------------------------------------------------
        _fs(
            "velocity_anomaly_score_30d",
            "Velocity anomaly score, 30 days",
            "Bounded synthetic anomaly score for transaction velocity behaviour.",
            FeatureDType.SCORE,
            FeatureCategory.ANOMALY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SCORE,
            FeatureSource.DERIVED,
            leakage=FeatureLeakage.CAUTION,
            stability=FeatureStability.DRIFT_PRONE,
            domain=_score_domain(nullable=True),
        ),
        _fs(
            "network_anomaly_score_30d",
            "Network anomaly score, 30 days",
            "Bounded synthetic anomaly score for graph and entity-link structure.",
            FeatureDType.SCORE,
            FeatureCategory.ANOMALY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SCORE,
            FeatureSource.DERIVED,
            leakage=FeatureLeakage.CAUTION,
            stability=FeatureStability.VOLATILE,
            domain=_score_domain(nullable=True),
        ),
        _fs(
            "composite_anomaly_score_30d",
            "Composite anomaly score, 30 days",
            "Bounded composite synthetic anomaly score. This is an investigative prioritization signal only.",
            FeatureDType.SCORE,
            FeatureCategory.ANOMALY,
            FeatureWindow.THIRTY_DAY,
            FeatureAggregation.SCORE,
            FeatureSource.DERIVED,
            leakage=FeatureLeakage.CAUTION,
            stability=FeatureStability.VOLATILE,
            dependencies=(
                "txn_amount_anomaly_score_30d",
                "velocity_anomaly_score_30d",
                "network_anomaly_score_30d",
            ),
            domain=_score_domain(nullable=True),
        ),

        # -----------------------------------------------------------------
        # Metadata features, generally not model-ready
        # -----------------------------------------------------------------
        _fs(
            "observation_time",
            "Observation time",
            "UTC timestamp representing the feature snapshot time.",
            FeatureDType.DATETIME,
            FeatureCategory.TEMPORAL,
            FeatureWindow.NONE,
            FeatureAggregation.RAW,
            FeatureSource.SYSTEM,
            model_ready=False,
            domain=FeatureDomain(nullable=True),
        ),
        _fs(
            "feature_snapshot_version",
            "Feature snapshot version",
            "Version label for the synthetic feature snapshot.",
            FeatureDType.STRING,
            FeatureCategory.PROFILE,
            FeatureWindow.NONE,
            FeatureAggregation.RAW,
            FeatureSource.SYSTEM,
            model_ready=False,
            domain=FeatureDomain(
                max_value=None,
                nullable=True,
                pattern=r"^[A-Za-z0-9._:-]{1,64}$",
            ),
        ),
    ]

    catalog.extend(specs)

    groups = [
        FeatureGroup(
            name="account_profile",
            label="Account profile",
            description="Static and observational synthetic account profile features.",
            features=(
                "account_age_days",
                "account_type_enum",
                "account_status_enum",
                "account_segment_enum",
                "is_dormant_flag",
                "is_wallet_flag",
                "is_business_flag",
            ),
            category=FeatureCategory.PROFILE,
            window=FeatureWindow.NONE,
            tags=("profile", "static"),
        ),
        FeatureGroup(
            name="balance_features",
            label="Balance features",
            description="Synthetic balance level and trend features.",
            features=(
                "balance_mean_30d",
                "balance_min_30d",
                "balance_max_30d",
                "balance_stddev_30d",
                "balance_cv_30d",
                "balance_slope_30d",
                "balance_drop_ratio_7d",
            ),
            category=FeatureCategory.BALANCE,
            window=FeatureWindow.THIRTY_DAY,
            tags=("balance", "trend"),
        ),
        FeatureGroup(
            name="transaction_volume",
            label="Transaction volume",
            description="Synthetic transaction count and amount features.",
            features=(
                "txn_count_1h",
                "txn_count_24h",
                "txn_count_7d",
                "txn_count_30d",
                "txn_count_90d",
                "txn_count_all",
                "txn_amount_sum_24h",
                "txn_amount_sum_7d",
                "txn_amount_sum_30d",
                "txn_amount_mean_24h",
                "txn_amount_mean_30d",
                "txn_amount_median_30d",
                "txn_amount_max_24h",
                "txn_amount_max_30d",
                "txn_amount_min_30d",
                "txn_amount_stddev_30d",
                "txn_amount_cv_30d",
            ),
            category=FeatureCategory.VOLUME,
            window=FeatureWindow.THIRTY_DAY,
            tags=("volume", "amount", "count"),
        ),
        FeatureGroup(
            name="transaction_velocity",
            label="Transaction velocity",
            description="Synthetic velocity, timing, and burstiness features.",
            features=(
                "txn_count_velocity_ratio_7d_30d",
                "txn_count_burstiness_24h",
                "txn_interarrival_mean_seconds_24h",
                "txn_night_ratio_30d",
                "txn_weekend_ratio_30d",
                "txn_hour_entropy_30d",
                "txn_day_entropy_30d",
                "txn_count_delta_7d_vs_prior_7d",
                "txn_amount_delta_7d_vs_prior_7d",
                "txn_count_pct_change_7d",
            ),
            category=FeatureCategory.VELOCITY,
            window=FeatureWindow.SEVEN_DAY,
            tags=("velocity", "temporal"),
        ),
        FeatureGroup(
            name="counterparty_features",
            label="Counterparty features",
            description="Synthetic counterparty diversity, concentration, and direction features.",
            features=(
                "counterparty_distinct_count_30d",
                "counterparty_new_ratio_30d",
                "counterparty_repeat_ratio_30d",
                "counterparty_top1_share_30d",
                "counterparty_top5_share_30d",
                "counterparty_hhi_30d",
                "counterparty_entropy_30d",
                "outbound_amount_share_30d",
                "inbound_outbound_amount_ratio_30d",
            ),
            category=FeatureCategory.COUNTERPARTY,
            window=FeatureWindow.THIRTY_DAY,
            tags=("counterparty", "concentration"),
        ),
        FeatureGroup(
            name="channel_features",
            label="Channel features",
            description="Synthetic payment channel mix and switching features.",
            features=(
                "channel_upi_share_30d",
                "channel_wallet_share_30d",
                "channel_cash_share_30d",
                "channel_external_share_30d",
                "channel_entropy_30d",
                "channel_switch_count_7d",
            ),
            category=FeatureCategory.CHANNEL,
            window=FeatureWindow.THIRTY_DAY,
            tags=("channel", "mix"),
        ),
        FeatureGroup(
            name="entity_link_features",
            label="Entity link features",
            description="Synthetic pseudonymous entity and link features. Links are association signals only.",
            features=(
                "entity_link_count_30d",
                "device_distinct_count_30d",
                "ip_distinct_count_30d",
                "phone_distinct_count_30d",
                "email_distinct_count_30d",
                "upi_distinct_count_30d",
                "shared_device_account_count_30d",
                "shared_ip_account_count_30d",
                "shared_upi_account_count_30d",
                "entity_link_heuristic_ratio_30d",
                "entity_link_unverified_ratio_30d",
                "entity_link_confidence_mean_30d",
            ),
            category=FeatureCategory.LINK,
            window=FeatureWindow.THIRTY_DAY,
            tags=("entity", "link", "association"),
        ),
        FeatureGroup(
            name="complaint_features",
            label="Complaint features",
            description="Synthetic complaint count, category, recency, and linkage features. Raw narratives are not features.",
            features=(
                "complaint_count_30d",
                "complaint_rate_30d",
                "complaint_category_entropy_30d",
                "complaint_victim_count_30d",
                "complaint_suspect_count_30d",
                "complaint_recency_days",
                "complaint_linked_txn_ratio_30d",
            ),
            category=FeatureCategory.COMPLAINT,
            window=FeatureWindow.THIRTY_DAY,
            tags=("complaint", "workflow"),
        ),
        FeatureGroup(
            name="graph_network_features",
            label="Graph and network features",
            description="Bounded synthetic graph, network, shared-entity, and candidate-path features. These are investigative associations only.",
            features=(
                "graph_degree_30d",
                "graph_in_degree_30d",
                "graph_out_degree_30d",
                "graph_page_rank_norm_30d",
                "graph_betweenness_norm_30d",
                "graph_cycle_indicator_30d",
                "graph_path_count_30d",
                "graph_intermediary_score_30d",
                "graph_source_concentration_30d",
                "graph_beneficiary_concentration_30d",
                "graph_shared_entity_cluster_size_30d",
                "graph_neighbor_complaint_ratio_30d",
            ),
            category=FeatureCategory.NETWORK,
            window=FeatureWindow.THIRTY_DAY,
            tags=("graph", "network", "association"),
        ),
        FeatureGroup(
            name="anomaly_features",
            label="Anomaly features",
            description="Bounded synthetic anomaly and composite prioritization scores. Scores are not probabilities of guilt.",
            features=(
                "txn_amount_zscore_30d",
                "txn_amount_anomaly_score_30d",
                "velocity_anomaly_score_30d",
                "network_anomaly_score_30d",
                "composite_anomaly_score_30d",
            ),
            category=FeatureCategory.ANOMALY,
            window=FeatureWindow.THIRTY_DAY,
            tags=("anomaly", "score", "caution"),
        ),
        FeatureGroup(
            name="metadata_features",
            label="Metadata features",
            description="Snapshot metadata features that are generally not model-ready.",
            features=(
                "observation_time",
                "feature_snapshot_version",
            ),
            category=FeatureCategory.OTHER,
            window=FeatureWindow.NONE,
            tags=("metadata", "non_model_ready"),
        ),
    ]

    for group in groups:
        catalog.add_group(group)

    return catalog


_default_catalog: Optional[FeatureCatalog] = None
_default_catalog_lock = threading.Lock()


def get_feature_catalog(
    settings: Any | None = None,
    *,
    rebuild: bool = False,
) -> FeatureCatalog:
    """
    Return the process-wide default feature catalog.

    If `rebuild=True`, a fresh catalog is constructed and becomes the default.
    This is useful for tests or explicit reload workflows.
    """
    global _default_catalog

    _ = settings

    with _default_catalog_lock:
        if _default_catalog is None or rebuild:
            _default_catalog = build_default_feature_catalog()

        return _default_catalog


def validate_feature_vector(
    features: Any,
    *,
    catalog: FeatureCatalog | None = None,
    options: FeatureValidationOptions | None = None,
    subject_ref_hash: Any = None,
) -> FeatureVector:
    """
    Validate one feature vector against the default or supplied catalog.
    """
    active_catalog = catalog or get_feature_catalog()
    return active_catalog.validate_vector(
        features,
        options=options,
        subject_ref_hash=subject_ref_hash,
    )


def validate_feature_vectors(
    vectors: Any,
    *,
    catalog: FeatureCatalog | None = None,
    options: FeatureValidationOptions | None = None,
) -> list[FeatureVector]:
    """
    Validate multiple feature vectors against the default or supplied catalog.
    """
    active_catalog = catalog or get_feature_catalog()
    return active_catalog.validate_vectors(vectors, options=options)


def get_feature_spec(name: Any) -> Optional[FeatureSpec]:
    """
    Return one feature specification from the default catalog.
    """
    return get_feature_catalog().get_spec(name)


def require_feature_spec(name: Any) -> FeatureSpec:
    """
    Return one feature specification from the default catalog or raise.
    """
    return get_feature_catalog().require_spec(name)


def resolve_feature_name(name: Any) -> Optional[str]:
    """
    Resolve a feature name or alias to a canonical feature name.
    """
    return get_feature_catalog()._resolve_name(name)


def list_feature_names(*, active_only: bool = False) -> tuple[str, ...]:
    """
    Return feature names from the default catalog.
    """
    catalog = get_feature_catalog()

    if active_only:
        return catalog.active_names

    return catalog.names


def get_feature_json_schema(
    *,
    allow_unknown: bool = False,
    title: str = "MULEGUARD Feature Vector",
) -> dict[str, Any]:
    """
    Return the default catalog JSON Schema projection.
    """
    return get_feature_catalog().to_json_schema(
        allow_unknown=allow_unknown,
        title=title,
    )


def is_forbidden_feature_name(name: Any) -> bool:
    """
    Return True when a feature name or alias is forbidden.
    """
    return _is_forbidden_feature_name(name)


def get_feature_metadata(*, include_names: bool = True) -> dict[str, Any]:
    """
    Return safe, serializable feature-schema metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, or real customer data.
    """
    catalog = get_feature_catalog()
    catalog_dict = catalog.to_dict(include_specs=False, include_groups=False)
    default_options = FeatureValidationOptions()

    payload: dict[str, Any] = {
        "package": "muleguard.backend.ml.feature_schema",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_catalog_version": catalog.version,
        "catalog_fingerprint": catalog.fingerprint(),
        "feature_count": len(catalog),
        "group_count": len(catalog.groups),
        "required_feature_count": len(catalog.required_names),
        "model_ready_feature_count": len(catalog.model_ready_names),
        "explainable_feature_count": len(catalog.explainable_names),
        "default_options": default_options.safe_summary(),
        "hard_limits": {
            "max_features": HARD_MAX_FEATURES,
            "max_issues": HARD_MAX_ISSUES,
            "max_string_length": HARD_MAX_STRING_LENGTH,
            "max_set_items": HARD_MAX_SET_ITEMS,
            "max_vector_items": HARD_MAX_VECTOR_ITEMS,
            "max_metadata_depth": HARD_MAX_METADATA_DEPTH,
            "max_mapping_keys": HARD_MAX_MAPPING_KEYS,
            "max_vectors_per_call": HARD_MAX_VECTORS_PER_CALL,
        },
        "forbidden_feature_field_count": len(_FORBIDDEN_FEATURE_FIELDS),
        "caveats": list(_FEATURE_SCHEMA_CAVEATS),
        "safety_flags": dict(_FEATURE_SAFETY_FLAGS),
        "catalog_summary": catalog_dict,
    }

    if include_names:
        payload["feature_names"] = list(catalog.names)
        payload["group_names"] = [group.name for group in catalog.groups]

    return payload


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "FeatureAggregation",
    "FeatureCatalog",
    "FeatureCategory",
    "FeatureDomain",
    "FeatureDType",
    "FeatureEncoding",
    "FeatureGroup",
    "FeatureIssueSeverity",
    "FeatureLeakage",
    "FeatureMissingStrategy",
    "FeaturePrivacy",
    "FeatureRole",
    "FeatureSource",
    "FeatureSpec",
    "FeatureStability",
    "FeatureTransform",
    "FeatureValidationIssue",
    "FeatureValidationOptions",
    "FeatureValidationResult",
    "FeatureVector",
    "FeatureWindow",
    "build_default_feature_catalog",
    "get_feature_catalog",
    "get_feature_json_schema",
    "get_feature_metadata",
    "get_feature_spec",
    "is_forbidden_feature_name",
    "list_feature_names",
    "require_feature_spec",
    "resolve_feature_name",
    "validate_feature_vector",
    "validate_feature_vectors",
]