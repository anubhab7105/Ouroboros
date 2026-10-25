"""
MULEGUARD backend ML feature construction.

This module builds bounded, deterministic, leakage-aware, privacy-preserving
synthetic ML feature vectors for the MULEGUARD investigative prototype.

Primary responsibilities:

- construct feature vectors for synthetic accounts from synthetic accounts,
  transactions, complaints, pseudonymous entities, entity links, and optional
  balance snapshots;
- enforce the canonical feature schema from `app.ml.feature_schema`;
- reject or omit leakage-prone inputs such as ground-truth labels, injected
  scenario IDs, fraud-ring IDs, raw complaint narratives, raw identifiers,
  secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths;
- keep all computations bounded by hard caps for record counts, sample sizes,
  counterparty cardinality, graph traversal, path enumeration, and issue
  reporting;
- produce pseudonymous subject references using salted HMAC hashing;
- return safe feature build results whose public summaries do not expose raw
  record content, raw narratives, raw identifiers, secrets, or feature values;
- remain import-safe and usable by ML services, APIs, tests, seeders, offline
  evaluation harnesses, and developer tooling.

This module constructs features only. It does not train models, score accounts,
evaluate models, persist data, call external systems, authenticate users,
authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for feature construction.
- Ground-truth labels, injected scenario IDs, and fraud-ring IDs are forbidden
  inputs and are never emitted.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden feature inputs. Subject references are
  pseudonymously hashed.
- Risk and anomaly features are investigative prioritization signals only.
  They are not probabilities of guilt.
- Heuristic fallback scores are not calibrated model probabilities.
- Graph, entity-link, complaint, and anomaly features are association or
  operational signal features only. They are not proof of wrongdoing.
- Feature construction never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Undefined or unavailable metrics are reported honestly as unavailable rather
  than invented.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call model runtimes.
- This module does not train, promote, retire, upload, replace, or execute
  models.
- This module does not generate synthetic data.
- This module does not replace ingestion validation.
- This module does not replace feature schema validation; it delegates final
  vector validation to `app.ml.feature_schema`.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, and case dispositions are investigative leads or human workflow
artefacts only. They are not proof of wrongdoing and must not trigger automatic
adverse customer action.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import re
import threading
import unicodedata
from enum import Enum
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Final, Optional

from app.ml.feature_schema import (
    FeatureCatalog,
    FeatureValidationOptions,
    FeatureValidationResult,
    FeatureVector,
    get_feature_catalog,
)
from app.core.vocabularies import (
    AccountStatus,
    AccountType,
    Channel,
    EntityType,
    MatchMethod,
    TransactionStatus,
    VerificationState,
)

logger = logging.getLogger("muleguard.backend.ml.features")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

FEATURES_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_MAX_ACCOUNTS: Final[int] = 10_000
_HARD_MAX_ACCOUNTS: Final[int] = 100_000

_DEFAULT_MAX_TRANSACTIONS: Final[int] = 100_000
_HARD_MAX_TRANSACTIONS: Final[int] = 250_000

_DEFAULT_MAX_COMPLAINTS: Final[int] = 10_000
_HARD_MAX_COMPLAINTS: Final[int] = 100_000

_DEFAULT_MAX_ENTITIES: Final[int] = 10_000
_HARD_MAX_ENTITIES: Final[int] = 100_000

_DEFAULT_MAX_LINKS: Final[int] = 50_000
_HARD_MAX_LINKS: Final[int] = 250_000

_DEFAULT_MAX_BALANCES: Final[int] = 50_000
_HARD_MAX_BALANCES: Final[int] = 250_000

_DEFAULT_MAX_FEATURE_SAMPLES: Final[int] = 5_000
_HARD_MAX_FEATURE_SAMPLES: Final[int] = 20_000

_DEFAULT_MAX_COUNTERPARTIES: Final[int] = 5_000
_HARD_MAX_COUNTERPARTIES: Final[int] = 20_000

_DEFAULT_MAX_GRAPH_NODES: Final[int] = 20_000
_HARD_MAX_GRAPH_NODES: Final[int] = 50_000

_DEFAULT_MAX_GRAPH_EDGES: Final[int] = 100_000
_HARD_MAX_GRAPH_EDGES: Final[int] = 250_000

_DEFAULT_PAGERANK_ITERATIONS: Final[int] = 20
_HARD_MAX_PAGERANK_ITERATIONS: Final[int] = 100

_DEFAULT_PAGERANK_DAMPING: Final[float] = 0.85

_DEFAULT_MAX_PATHS: Final[int] = 10_000
_HARD_MAX_PATHS: Final[int] = 100_000

_DEFAULT_MAX_COMPONENT_SIZE: Final[int] = 1_000
_HARD_MAX_COMPONENT_SIZE: Final[int] = 10_000

_DEFAULT_MAX_ACCOUNTS_PER_ENTITY: Final[int] = 100
_HARD_MAX_ACCOUNTS_PER_ENTITY: Final[int] = 1_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_WARNINGS: Final[int] = 50
_HARD_MAX_WARNINGS: Final[int] = 200

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_ID_LENGTH: Final[int] = 128
_MAX_REFERENCE_LENGTH: Final[int] = 128
_MAX_CATEGORY_LENGTH: Final[int] = 100
_MAX_SOURCE_LENGTH: Final[int] = 100

_ZERO: Final[Decimal] = Decimal("0")
_ONE: Final[Decimal] = Decimal("1")
_MONEY_QUANT: Final[Decimal] = Decimal("0.01")

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")

_SUBJECT_DOMAIN: Final[str] = "muleguard.ml.feature.subject"
_DEFAULT_SALT: Final[str] = "muleguard.ml.features.default.salt"

# Must match `AccountType` in app/models.py and `_ACCOUNT_TYPES` in
# app/ml/feature_schema.py. These three lists are separate by design — the
# builder does not import the ORM — which is exactly why they drifted: this
# one held SAVINGS / CURRENT / WALLET / UPI / CARD, none of which the model
# defines, so `_normalize_enum` fell through to OTHER for every account and
# `account_type_enum`, `account_segment_enum`, `is_wallet_flag` and
# `is_business_flag` were constant across the whole dataset.
_ACCOUNT_TYPES: Final[frozenset[str]] = frozenset(
    str(member.value) for member in AccountType
)

# Categorical vocabularies, derived from the persisted enums.
#
# These were listed by hand and had drifted from the columns they describe:
# statuses included INACTIVE, PENDING, SUSPENDED and RESTRICTED, which the
# account table cannot hold, and omitted REVIEW_REQUIRED, which it can.
# A value outside the vocabulary normalises to the OTHER fallback, so each
# stale list meant one categorical signal was constant across every feature
# vector ever built — present in the schema, informative about nothing.
_ACCOUNT_STATUSES: Final[frozenset[str]] = frozenset(
    str(member.value) for member in AccountStatus
)

_TRANSACTION_STATUSES: Final[frozenset[str]] = frozenset(
    str(member.value) for member in TransactionStatus
)

_CHANNELS: Final[frozenset[str]] = frozenset(
    str(member.value) for member in Channel
)

_ENTITY_TYPES: Final[frozenset[str]] = frozenset(
    str(member.value) for member in EntityType
)

_MATCH_METHODS: Final[frozenset[str]] = frozenset(
    str(member.value) for member in MatchMethod
)

_VERIFICATION_STATES: Final[frozenset[str]] = frozenset(
    str(member.value) for member in VerificationState
)

_COMPLAINT_CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        "unauthorized_transfer",
        "account_takeover",
        "identity_theft",
        "phishing",
        "scam",
        "other",
    }
)

_NIGHT_HOURS: Final[frozenset[int]] = frozenset({22, 23, 0, 1, 2, 3, 4, 5})

_FORBIDDEN_FEATURE_INPUT_KEYS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_FEATURE_INPUT_TOKENS: Final[tuple[str, ...]] = (
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

_FEATURE_BUILD_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML feature construction only. Do not use with real customer data.",
    "Constructed features are investigative inputs only and are not proof of wrongdoing.",
    "Feature construction must not trigger automatic adverse customer action.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are forbidden inputs.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Risk and anomaly features are investigative prioritization signals, not probabilities of guilt.",
    "Heuristic fallback scores are not calibrated model probabilities.",
    "Graph, entity-link, complaint, and anomaly features are association or operational signal features only.",
    "Unavailable metrics are reported as unavailable rather than invented.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_FEATURE_SAFETY_FLAGS: Final[dict[str, bool]] = {
    "synthetic_only_by_default": True,
    "no_real_customer_data_by_default": True,
    "no_ground_truth_labels_accepted": True,
    "no_scenario_ids_accepted": True,
    "no_fraud_ring_ids_accepted": True,
    "no_raw_narratives_accepted": True,
    "no_raw_identifiers_accepted": True,
    "no_secrets_accepted": True,
    "no_tokens_accepted": True,
    "no_passwords_accepted": True,
    "no_database_urls_accepted": True,
    "no_model_artifact_paths_accepted": True,
    "risk_scores_are_investigative_priority_only": True,
    "heuristic_scores_are_not_calibrated_probabilities": True,
    "graph_features_are_association_signals_only": True,
    "no_automatic_adverse_customer_action": True,
    "not_production_ready": True,
}


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


def _clamp_float(value: object, minimum: float, maximum: float, default: float) -> float:
    """
    Clamp a float-like value into bounds.
    """
    parsed = _as_float(value, default)
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


def _now_utc() -> datetime:
    """
    Return timezone-aware UTC current time.
    """
    return datetime.now(timezone.utc)


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    """
    Normalize datetimes to timezone-aware UTC.

    Naive datetimes are assumed to already be UTC.
    """
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


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


def _upper_token(value: Any) -> str:
    """
    Normalize a token-like value into upper snake_case.
    """
    return _normalize_token(value).upper()


def _lower_token(value: Any) -> str:
    """
    Normalize a token-like value into lower snake_case.
    """
    return _normalize_token(value)


def _is_forbidden_input_key(key: Any) -> bool:
    """
    Return True when an input key is forbidden for feature construction.
    """
    canonical = _normalize_token(key)

    if not canonical:
        return False

    if canonical in _FORBIDDEN_FEATURE_INPUT_KEYS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_FEATURE_INPUT_TOKENS)


def _is_sensitive_key(key: Any) -> bool:
    """
    Return True when a detail key appears sensitive or leakage-prone.
    """
    canonical = _normalize_token(key)

    if not canonical:
        return False

    return any(token in canonical for token in _SENSITIVE_DETAIL_TOKENS)


def _safe_detail_value(value: Any, depth: int = 0) -> Any:
    """
    Convert arbitrary detail values into bounded, safe representations.
    """
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

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:100]:
            key = _clean_text(raw_key, 128)

            if not key or _is_sensitive_key(key):
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            _safe_detail_value(item, depth + 1)
            for item in list(value)[:100]
        ]

    return f"<{type(value).__name__}>"


def _parse_datetime(value: Any) -> Optional[datetime]:
    """
    Parse a datetime-like value into timezone-aware UTC.
    """
    if isinstance(value, bool):
        return None

    if isinstance(value, datetime):
        return _ensure_utc(value)

    if isinstance(value, (int, float, Decimal)):
        numeric = _as_float(value, math.nan)

        if math.isnan(numeric) or math.isinf(numeric):
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

    if math.isnan(numeric) or math.isinf(numeric):
        return None

    if abs(numeric) > 1_000_000_000_000:
        numeric = numeric / 1000.0

    try:
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _parse_decimal(value: Any) -> Optional[Decimal]:
    """
    Parse a decimal-like value.
    """
    if isinstance(value, Decimal):
        return value if value.is_finite() else None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return Decimal(value)

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
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


def _quantize_money(value: Optional[Decimal]) -> Decimal:
    """
    Quantize a monetary value to two decimal places.
    """
    if value is None or not value.is_finite():
        return _ZERO

    try:
        return value.quantize(_MONEY_QUANT, rounding=ROUND_HALF_UP)
    except Exception:
        return _ZERO


def _decimal_to_float(value: Optional[Decimal], default: float = 0.0) -> float:
    """
    Convert Decimal to finite float.
    """
    if value is None or not value.is_finite():
        return default

    try:
        result = float(value)
    except (OverflowError, ValueError):
        return default

    if math.isnan(result) or math.isinf(result):
        return default

    return result


def _clip_float(
    value: Optional[float],
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
    default: float = 0.0,
) -> float:
    """
    Clip a float into bounds.
    """
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


def _ratio_squash(value: Optional[float]) -> float:
    """
    Squash a non-negative ratio into [0, 1).

    This is used where a feature schema expects a ratio but the raw ratio can
    exceed one.
    """
    if value is None:
        return 0.0

    if math.isnan(value) or math.isinf(value):
        return 0.0

    safe = max(0.0, float(value))
    result = safe / (1.0 + safe)

    return _clip_float(result, 0.0, 1.0, 0.0)


def _normalized_entropy(weights: Mapping[Any, Any]) -> float:
    """
    Return normalized Shannon entropy in [0, 1].
    """
    numeric: list[float] = []

    for value in weights.values():
        if isinstance(value, Decimal):
            float_value = _decimal_to_float(value, 0.0)
        else:
            try:
                float_value = float(value)
            except (TypeError, ValueError):
                float_value = 0.0

        if math.isnan(float_value) or math.isinf(float_value):
            float_value = 0.0

        if float_value > 0:
            numeric.append(float_value)

    total = sum(numeric)

    if total <= 0 or len(numeric) <= 1:
        return 0.0

    entropy = 0.0

    for value in numeric:
        p = value / total

        if p > 0:
            entropy -= p * math.log(p)

    norm = math.log(len(numeric))

    if norm <= 0:
        return 0.0

    return _clip_float(entropy / norm, 0.0, 1.0, 0.0)


def _hhi(weights: Mapping[Any, Any]) -> float:
    """
    Return Herfindahl-Hirschman Index in [0, 1].
    """
    numeric: list[float] = []

    for value in weights.values():
        if isinstance(value, Decimal):
            float_value = _decimal_to_float(value, 0.0)
        else:
            try:
                float_value = float(value)
            except (TypeError, ValueError):
                float_value = 0.0

        if math.isnan(float_value) or math.isinf(float_value):
            float_value = 0.0

        if float_value > 0:
            numeric.append(float_value)

    total = sum(numeric)

    if total <= 0:
        return 0.0

    result = sum((value / total) ** 2 for value in numeric)
    return _clip_float(result, 0.0, 1.0, 0.0)


def _top_share(weights: Mapping[Any, Any], top_n: int) -> float:
    """
    Return share of top-N weights.
    """
    numeric: list[tuple[float, str]] = []

    for key, value in weights.items():
        if isinstance(value, Decimal):
            float_value = _decimal_to_float(value, 0.0)
        else:
            try:
                float_value = float(value)
            except (TypeError, ValueError):
                float_value = 0.0

        if math.isnan(float_value) or math.isinf(float_value):
            float_value = 0.0

        if float_value > 0:
            numeric.append((float_value, str(key)))

    if not numeric:
        return 0.0

    numeric.sort(key=lambda item: (-item[0], item[1]))
    total = sum(value for value, _ in numeric)

    if total <= 0:
        return 0.0

    selected = numeric[: max(1, int(top_n))]
    result = sum(value for value, _ in selected) / total
    return _clip_float(result, 0.0, 1.0, 0.0)


def _median_decimal(values: Sequence[Decimal]) -> Decimal:
    """
    Return median of Decimal values.
    """
    if not values:
        return _ZERO

    ordered = sorted(values)
    mid = len(ordered) // 2

    if len(ordered) % 2 == 1:
        return _quantize_money(ordered[mid])

    return _quantize_money((ordered[mid - 1] + ordered[mid]) / Decimal(2))


def _population_stddev_float(values: Sequence[Decimal], mean: Decimal) -> float:
    """
    Return population standard deviation as float.
    """
    if len(values) < 2:
        return 0.0

    mean_float = _decimal_to_float(mean, 0.0)
    total = 0.0
    count = 0

    for value in values:
        float_value = _decimal_to_float(value, mean_float)

        if math.isnan(float_value) or math.isinf(float_value):
            continue

        delta = float_value - mean_float
        total += delta * delta
        count += 1

    if count <= 1:
        return 0.0

    variance = total / float(count)

    if variance <= 0 or math.isnan(variance) or math.isinf(variance):
        return 0.0

    result = math.sqrt(variance)
    return result if math.isfinite(result) else 0.0


def _ensure_salt(salt: Any) -> str:
    """
    Ensure the feature salt is non-empty and sufficiently long.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _subject_hash(account_id: str, salt: str) -> str:
    """
    Return a salted, domain-separated pseudonymous subject hash.
    """
    message = f"{_SUBJECT_DOMAIN}\x00{account_id}".encode("utf-8", errors="replace")
    return hmac.new(
        salt.encode("utf-8", errors="replace"),
        message,
        hashlib.sha256,
    ).hexdigest()


def _normalize_currency(value: Any) -> str:
    """
    Normalize a currency code.
    """
    text = _upper_token(value).replace("_", "")
    text = re.sub(r"[^A-Z]", "", text)

    if _CURRENCY_RE.match(text):
        return text

    return ""


def _normalize_enum(value: Any, allowed: frozenset[str], default: str) -> str:
    """
    Normalize an upper-case enum-like value.
    """
    text = _upper_token(value)

    if text in allowed:
        return text

    return default


def _normalize_lower_enum(value: Any, allowed: frozenset[str], default: str) -> str:
    """
    Normalize a lower-case enum-like value.
    """
    text = _lower_token(value)

    if text in allowed:
        return text

    return default


def _normalize_channel(value: Any) -> str:
    """
    Normalize a payment channel.
    """
    text = _upper_token(value)

    aliases = {
        "CARD_PAYMENT": "CARD",
        "DEBIT": "CARD",
        "CREDIT": "CARD",
        "CASH_DEPOSIT": "CASH",
        "CASH_WITHDRAWAL": "CASH",
        "INTERNAL_TRANSFER": "INTERNAL",
        "EXTERNAL_TRANSFER": "EXTERNAL",
        "WIRE": "NEFT",
        "REAL_TIME": "RTGS",
        "INSTANT": "IMPS",
    }

    resolved = aliases.get(text, text)

    if resolved in _CHANNELS:
        return resolved

    return "UNKNOWN"


def _normalize_confidence(value: Any) -> Optional[Decimal]:
    """
    Normalize confidence into [0, 1].
    """
    parsed = _parse_decimal(value)

    if parsed is None:
        return None

    if parsed < 0:
        return _ZERO

    if Decimal(1) < parsed <= Decimal(100):
        parsed = parsed / Decimal(100)

    if parsed > 1:
        return _ONE

    return parsed.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)


def _record_to_mapping(
    record: Any,
    allowed_attrs: Sequence[str],
    aliases: Mapping[str, str],
) -> dict[str, Any]:
    """
    Convert a record-like object into a safe mapping.

    Forbidden keys are omitted. Unknown keys are omitted. Aliases are resolved.
    """
    allowed = {_normalize_token(item) for item in allowed_attrs}
    out: dict[str, Any] = {}

    if isinstance(record, Mapping):
        items = record.items()
    else:
        items = [(attr, getattr(record, attr, None)) for attr in allowed_attrs]

    for raw_key, raw_value in items:
        key = _normalize_token(raw_key)

        if not key:
            continue

        if _is_forbidden_input_key(key):
            continue

        target = aliases.get(key, key)

        if target in allowed:
            if target not in out:
                out[target] = raw_value

    return out


def _pick(mapping: Mapping[str, Any], *names: str) -> Any:
    """
    Return the first non-empty value among candidate names.
    """
    for name in names:
        key = _normalize_token(name)

        if key not in mapping:
            continue

        value = mapping[key]

        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        return value

    return None


def _as_sequence(value: Any) -> list[Any]:
    """
    Convert a flexible source into a list.
    """
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


def _get_source_collection(source: Any, names: Sequence[str]) -> Any:
    """
    Retrieve a collection from a dataset-like source.
    """
    for name in names:
        if isinstance(source, Mapping):
            if name in source:
                return source[name]
        else:
            value = getattr(source, name, None)

            if value is not None:
                return value

    return None


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeatureBuildOptions:
    """
    Bounded ML feature construction policy.

    Hard caps prevent accidental unbounded feature construction.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT

    max_accounts: int = _DEFAULT_MAX_ACCOUNTS
    max_transactions: int = _DEFAULT_MAX_TRANSACTIONS
    max_complaints: int = _DEFAULT_MAX_COMPLAINTS
    max_entities: int = _DEFAULT_MAX_ENTITIES
    max_links: int = _DEFAULT_MAX_LINKS
    max_balances: int = _DEFAULT_MAX_BALANCES

    max_feature_samples: int = _DEFAULT_MAX_FEATURE_SAMPLES
    max_counterparties: int = _DEFAULT_MAX_COUNTERPARTIES
    max_paths: int = _DEFAULT_MAX_PATHS
    max_graph_nodes: int = _DEFAULT_MAX_GRAPH_NODES
    max_graph_edges: int = _DEFAULT_MAX_GRAPH_EDGES
    max_component_size: int = _DEFAULT_MAX_COMPONENT_SIZE
    max_accounts_per_entity: int = _DEFAULT_MAX_ACCOUNTS_PER_ENTITY

    pagerank_iterations: int = _DEFAULT_PAGERANK_ITERATIONS
    pagerank_damping: float = _DEFAULT_PAGERANK_DAMPING

    include_graph: bool = True
    include_anomaly: bool = True
    include_balance: bool = True
    include_complaint: bool = True
    include_entity: bool = True

    max_issues: int = _DEFAULT_MAX_ISSUES
    max_warnings: int = _DEFAULT_MAX_WARNINGS

    def __post_init__(self) -> None:
        """
        Normalize and clamp option values.
        """
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(
            self,
            "dataset_mode",
            _lower_token(self.dataset_mode) or "synthetic",
        )
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))
        object.__setattr__(self, "salt", _ensure_salt(self.salt))

        object.__setattr__(
            self,
            "max_accounts",
            _clamp_int(self.max_accounts, 0, _HARD_MAX_ACCOUNTS, _DEFAULT_MAX_ACCOUNTS),
        )
        object.__setattr__(
            self,
            "max_transactions",
            _clamp_int(self.max_transactions, 0, _HARD_MAX_TRANSACTIONS, _DEFAULT_MAX_TRANSACTIONS),
        )
        object.__setattr__(
            self,
            "max_complaints",
            _clamp_int(self.max_complaints, 0, _HARD_MAX_COMPLAINTS, _DEFAULT_MAX_COMPLAINTS),
        )
        object.__setattr__(
            self,
            "max_entities",
            _clamp_int(self.max_entities, 0, _HARD_MAX_ENTITIES, _DEFAULT_MAX_ENTITIES),
        )
        object.__setattr__(
            self,
            "max_links",
            _clamp_int(self.max_links, 0, _HARD_MAX_LINKS, _DEFAULT_MAX_LINKS),
        )
        object.__setattr__(
            self,
            "max_balances",
            _clamp_int(self.max_balances, 0, _HARD_MAX_BALANCES, _DEFAULT_MAX_BALANCES),
        )

        object.__setattr__(
            self,
            "max_feature_samples",
            _clamp_int(
                self.max_feature_samples,
                10,
                _HARD_MAX_FEATURE_SAMPLES,
                _DEFAULT_MAX_FEATURE_SAMPLES,
            ),
        )
        object.__setattr__(
            self,
            "max_counterparties",
            _clamp_int(
                self.max_counterparties,
                10,
                _HARD_MAX_COUNTERPARTIES,
                _DEFAULT_MAX_COUNTERPARTIES,
            ),
        )
        object.__setattr__(
            self,
            "max_paths",
            _clamp_int(self.max_paths, 1, _HARD_MAX_PATHS, _DEFAULT_MAX_PATHS),
        )
        object.__setattr__(
            self,
            "max_graph_nodes",
            _clamp_int(self.max_graph_nodes, 0, _HARD_MAX_GRAPH_NODES, _DEFAULT_MAX_GRAPH_NODES),
        )
        object.__setattr__(
            self,
            "max_graph_edges",
            _clamp_int(self.max_graph_edges, 0, _HARD_MAX_GRAPH_EDGES, _DEFAULT_MAX_GRAPH_EDGES),
        )
        object.__setattr__(
            self,
            "max_component_size",
            _clamp_int(
                self.max_component_size,
                1,
                _HARD_MAX_COMPONENT_SIZE,
                _DEFAULT_MAX_COMPONENT_SIZE,
            ),
        )
        object.__setattr__(
            self,
            "max_accounts_per_entity",
            _clamp_int(
                self.max_accounts_per_entity,
                1,
                _HARD_MAX_ACCOUNTS_PER_ENTITY,
                _DEFAULT_MAX_ACCOUNTS_PER_ENTITY,
            ),
        )

        object.__setattr__(
            self,
            "pagerank_iterations",
            _clamp_int(
                self.pagerank_iterations,
                1,
                _HARD_MAX_PAGERANK_ITERATIONS,
                _DEFAULT_PAGERANK_ITERATIONS,
            ),
        )
        object.__setattr__(
            self,
            "pagerank_damping",
            _clamp_float(self.pagerank_damping, 0.0, 0.99, _DEFAULT_PAGERANK_DAMPING),
        )

        object.__setattr__(self, "include_graph", _as_bool(self.include_graph, True))
        object.__setattr__(self, "include_anomaly", _as_bool(self.include_anomaly, True))
        object.__setattr__(self, "include_balance", _as_bool(self.include_balance, True))
        object.__setattr__(self, "include_complaint", _as_bool(self.include_complaint, True))
        object.__setattr__(self, "include_entity", _as_bool(self.include_entity, True))

        object.__setattr__(
            self,
            "max_issues",
            _clamp_int(self.max_issues, 1, _HARD_MAX_ISSUES, _DEFAULT_MAX_ISSUES),
        )
        object.__setattr__(
            self,
            "max_warnings",
            _clamp_int(self.max_warnings, 1, _HARD_MAX_WARNINGS, _DEFAULT_MAX_WARNINGS),
        )

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "FeatureBuildOptions":
        """
        Build feature construction options from runtime settings.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ML_FEATURE_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ML_FEATURES_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ML_FEATURES_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ML_FEATURES_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            max_accounts=_as_int(
                _setting(settings, "ML_FEATURES_MAX_ACCOUNTS", _DEFAULT_MAX_ACCOUNTS),
                _DEFAULT_MAX_ACCOUNTS,
            ),
            max_transactions=_as_int(
                _setting(settings, "ML_FEATURES_MAX_TRANSACTIONS", _DEFAULT_MAX_TRANSACTIONS),
                _DEFAULT_MAX_TRANSACTIONS,
            ),
            max_complaints=_as_int(
                _setting(settings, "ML_FEATURES_MAX_COMPLAINTS", _DEFAULT_MAX_COMPLAINTS),
                _DEFAULT_MAX_COMPLAINTS,
            ),
            max_entities=_as_int(
                _setting(settings, "ML_FEATURES_MAX_ENTITIES", _DEFAULT_MAX_ENTITIES),
                _DEFAULT_MAX_ENTITIES,
            ),
            max_links=_as_int(
                _setting(settings, "ML_FEATURES_MAX_LINKS", _DEFAULT_MAX_LINKS),
                _DEFAULT_MAX_LINKS,
            ),
            max_balances=_as_int(
                _setting(settings, "ML_FEATURES_MAX_BALANCES", _DEFAULT_MAX_BALANCES),
                _DEFAULT_MAX_BALANCES,
            ),
            max_feature_samples=_as_int(
                _setting(settings, "ML_FEATURES_MAX_SAMPLES", _DEFAULT_MAX_FEATURE_SAMPLES),
                _DEFAULT_MAX_FEATURE_SAMPLES,
            ),
            max_counterparties=_as_int(
                _setting(settings, "ML_FEATURES_MAX_COUNTERPARTIES", _DEFAULT_MAX_COUNTERPARTIES),
                _DEFAULT_MAX_COUNTERPARTIES,
            ),
            max_paths=_as_int(
                _setting(settings, "ML_FEATURES_MAX_PATHS", _DEFAULT_MAX_PATHS),
                _DEFAULT_MAX_PATHS,
            ),
            max_graph_nodes=_as_int(
                _setting(settings, "ML_FEATURES_MAX_GRAPH_NODES", _DEFAULT_MAX_GRAPH_NODES),
                _DEFAULT_MAX_GRAPH_NODES,
            ),
            max_graph_edges=_as_int(
                _setting(settings, "ML_FEATURES_MAX_GRAPH_EDGES", _DEFAULT_MAX_GRAPH_EDGES),
                _DEFAULT_MAX_GRAPH_EDGES,
            ),
            max_component_size=_as_int(
                _setting(settings, "ML_FEATURES_MAX_COMPONENT_SIZE", _DEFAULT_MAX_COMPONENT_SIZE),
                _DEFAULT_MAX_COMPONENT_SIZE,
            ),
            max_accounts_per_entity=_as_int(
                _setting(
                    settings,
                    "ML_FEATURES_MAX_ACCOUNTS_PER_ENTITY",
                    _DEFAULT_MAX_ACCOUNTS_PER_ENTITY,
                ),
                _DEFAULT_MAX_ACCOUNTS_PER_ENTITY,
            ),
            pagerank_iterations=_as_int(
                _setting(settings, "ML_FEATURES_PAGERANK_ITERATIONS", _DEFAULT_PAGERANK_ITERATIONS),
                _DEFAULT_PAGERANK_ITERATIONS,
            ),
            pagerank_damping=_as_float(
                _setting(settings, "ML_FEATURES_PAGERANK_DAMPING", _DEFAULT_PAGERANK_DAMPING),
                _DEFAULT_PAGERANK_DAMPING,
            ),
            include_graph=_as_bool(_setting(settings, "ML_FEATURES_INCLUDE_GRAPH", True), True),
            include_anomaly=_as_bool(_setting(settings, "ML_FEATURES_INCLUDE_ANOMALY", True), True),
            include_balance=_as_bool(_setting(settings, "ML_FEATURES_INCLUDE_BALANCE", True), True),
            include_complaint=_as_bool(_setting(settings, "ML_FEATURES_INCLUDE_COMPLAINT", True), True),
            include_entity=_as_bool(_setting(settings, "ML_FEATURES_INCLUDE_ENTITY", True), True),
            max_issues=_as_int(
                _setting(settings, "ML_FEATURES_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_warnings=_as_int(
                _setting(settings, "ML_FEATURES_MAX_WARNINGS", _DEFAULT_MAX_WARNINGS),
                _DEFAULT_MAX_WARNINGS,
            ),
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable options summary.

        The salt is never included.
        """
        return {
            "enabled": self.enabled,
            "synthetic_required": self.synthetic_required,
            "dataset_mode": self.dataset_mode,
            "production_like": self.production_like,
            "allow_in_production": self.allow_in_production,
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
            "limits": {
                "max_accounts": self.max_accounts,
                "max_transactions": self.max_transactions,
                "max_complaints": self.max_complaints,
                "max_entities": self.max_entities,
                "max_links": self.max_links,
                "max_balances": self.max_balances,
                "max_feature_samples": self.max_feature_samples,
                "max_counterparties": self.max_counterparties,
                "max_paths": self.max_paths,
                "max_graph_nodes": self.max_graph_nodes,
                "max_graph_edges": self.max_graph_edges,
                "max_component_size": self.max_component_size,
                "max_accounts_per_entity": self.max_accounts_per_entity,
                "max_issues": self.max_issues,
                "max_warnings": self.max_warnings,
            },
            "graph": {
                "include_graph": self.include_graph,
                "pagerank_iterations": self.pagerank_iterations,
                "pagerank_damping": round(self.pagerank_damping, 4),
            },
            "includes": {
                "balance": self.include_balance,
                "complaint": self.include_complaint,
                "entity": self.include_entity,
                "anomaly": self.include_anomaly,
            },
        }


# -----------------------------------------------------------------------------
# Normalized input models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _Account:
    id: str
    account_type: str
    status: str
    created_at: Optional[datetime]
    balance_snapshots: list[tuple[datetime, Decimal, str]] = field(default_factory=list)


@dataclass(slots=True)
class _Txn:
    id: Optional[str]
    reference: Optional[str]
    sender: str
    receiver: str
    amount: Decimal
    currency: str
    occurred_at: datetime
    status: str
    channel: str


@dataclass(slots=True)
class _Complaint:
    id: Optional[str]
    reference: Optional[str]
    reported_at: datetime
    category: str
    victim: Optional[str]
    suspect: Optional[str]
    amount: Optional[Decimal]
    currency: Optional[str]
    transaction_reference: Optional[str]


@dataclass(slots=True)
class _Entity:
    id: str
    entity_type: str


@dataclass(slots=True)
class _Link:
    id: Optional[str]
    account_id: str
    entity_id: str
    entity_type: str
    match_method: str
    verification_state: str
    confidence: Optional[Decimal]
    valid_from: datetime
    valid_to: Optional[datetime]
    source: Optional[str]


@dataclass(slots=True)
class _Balance:
    account_id: str
    timestamp: datetime
    amount: Decimal
    currency: str


# -----------------------------------------------------------------------------
# Record normalization
# -----------------------------------------------------------------------------


_ACCOUNT_ALIASES: Final[Mapping[str, str]] = {
    "account_id": "id",
    "acct_id": "id",
    "type": "account_type",
    "state": "status",
}

_TXN_ALIASES: Final[Mapping[str, str]] = {
    "transaction_id": "id",
    "txn_id": "id",
    "from_account_id": "sender",
    "to_account_id": "receiver",
    "sender_account_id": "sender",
    "receiver_account_id": "receiver",
    "sender": "sender",
    "receiver": "receiver",
    "from": "sender",
    "to": "receiver",
    "timestamp": "occurred_at",
    "time": "occurred_at",
    "date": "occurred_at",
    "value": "amount",
    "ccy": "currency",
}

_COMPLAINT_ALIASES: Final[Mapping[str, str]] = {
    "complaint_id": "id",
    "filed_at": "reported_at",
    "reported_date": "reported_at",
    "txn_reference": "transaction_reference",
    "transaction_ref": "transaction_reference",
    "suspect_account_id": "suspect",
    "suspected_account_id": "suspect",
    "suspect": "suspect",
    "victim_account_id": "victim",
    "victim": "victim",
    "value": "amount",
    "ccy": "currency",
}

_ENTITY_ALIASES: Final[Mapping[str, str]] = {
    "entity_id": "id",
    "kind": "entity_type",
}

_LINK_ALIASES: Final[Mapping[str, str]] = {
    "link_id": "id",
    "account": "account_id",
    "entity": "entity_id",
    "from_account_id": "account_id",
    "to_entity_id": "entity_id",
    "start_at": "valid_from",
    "end_at": "valid_to",
    "method": "match_method",
    "state": "verification_state",
}

_BALANCE_ALIASES: Final[Mapping[str, str]] = {
    "account": "account_id",
    "occurred_at": "timestamp",
    "time": "timestamp",
    "date": "timestamp",
    "value": "amount",
    "ccy": "currency",
}


def _extract_balance_snapshots(metadata: Any) -> list[tuple[datetime, Decimal, str]]:
    """
    Extract safe synthetic balance snapshots from account metadata.

    This does not read raw narratives or sensitive values.
    """
    if not isinstance(metadata, Mapping):
        return []

    raw = metadata.get("balance_snapshots")

    if raw is None:
        raw = metadata.get("balances")

    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return []

    out: list[tuple[datetime, Decimal, str]] = []

    for item in list(raw)[:1_000]:
        if not isinstance(item, Mapping):
            continue

        timestamp = _parse_datetime(_pick(item, "timestamp", "occurred_at", "time", "date"))
        amount = _parse_decimal(_pick(item, "amount", "value"))
        currency = _normalize_currency(_pick(item, "currency", "ccy")) or "UNKNOWN"

        if timestamp is None or amount is None or amount <= 0:
            continue

        out.append((timestamp, _quantize_money(amount), currency))

    out.sort(key=lambda item: (item[0], item[2], item[1]))
    return out


def _normalize_account(record: Any) -> Optional[_Account]:
    """
    Normalize one synthetic account record.
    """
    mapping = _record_to_mapping(
        record,
        (
            "id",
            "account_type",
            "status",
            "created_at",
            "metadata_json",
            "metadata",
            "balance_snapshots",
            "balances",
        ),
        _ACCOUNT_ALIASES,
    )

    account_id = _clean_text(_pick(mapping, "id"), _MAX_ID_LENGTH)

    if not account_id:
        return None

    metadata = _pick(mapping, "metadata_json", "metadata")
    balance_snapshots = _extract_balance_snapshots(metadata)

    explicit_balances = mapping.get("balance_snapshots") or mapping.get("balances")

    if not balance_snapshots:
        balance_snapshots = _extract_balance_snapshots({"balance_snapshots": explicit_balances})

    created_at = _parse_datetime(_pick(mapping, "created_at"))

    return _Account(
        id=account_id,
        account_type=_normalize_enum(_pick(mapping, "account_type"), _ACCOUNT_TYPES, "OTHER"),
        status=_normalize_enum(_pick(mapping, "status"), _ACCOUNT_STATUSES, "ACTIVE"),
        created_at=created_at,
        balance_snapshots=balance_snapshots,
    )


def _normalize_txn(record: Any) -> Optional[_Txn]:
    """
    Normalize one synthetic transaction record.
    """
    mapping = _record_to_mapping(
        record,
        (
            "id",
            "reference",
            "sender",
            "receiver",
            "amount",
            "currency",
            "occurred_at",
            "status",
            "channel",
        ),
        _TXN_ALIASES,
    )

    sender = _clean_text(_pick(mapping, "sender"), _MAX_ID_LENGTH)
    receiver = _clean_text(_pick(mapping, "receiver"), _MAX_ID_LENGTH)
    amount = _parse_decimal(_pick(mapping, "amount"))
    occurred_at = _parse_datetime(_pick(mapping, "occurred_at"))

    if not sender or not receiver or sender == receiver:
        return None

    if amount is None or amount <= 0:
        return None

    if occurred_at is None:
        return None

    status = _normalize_enum(_pick(mapping, "status"), _TRANSACTION_STATUSES, "UNKNOWN")

    if status != "COMPLETED":
        return None

    return _Txn(
        id=_clean_text(_pick(mapping, "id"), _MAX_ID_LENGTH) or None,
        reference=_clean_text(_pick(mapping, "reference"), _MAX_REFERENCE_LENGTH) or None,
        sender=sender,
        receiver=receiver,
        amount=_quantize_money(amount),
        currency=_normalize_currency(_pick(mapping, "currency")) or "UNKNOWN",
        occurred_at=occurred_at,
        status=status,
        channel=_normalize_channel(_pick(mapping, "channel")),
    )


def _normalize_complaint(record: Any) -> Optional[_Complaint]:
    """
    Normalize one synthetic complaint record.

    Raw narratives are intentionally not read.
    """
    mapping = _record_to_mapping(
        record,
        (
            "id",
            "reference",
            "reported_at",
            "category",
            "transaction_reference",
            "victim",
            "suspect",
            "amount",
            "currency",
        ),
        _COMPLAINT_ALIASES,
    )

    reported_at = _parse_datetime(_pick(mapping, "reported_at"))

    if reported_at is None:
        return None

    victim = _clean_text(_pick(mapping, "victim"), _MAX_ID_LENGTH) or None
    suspect = _clean_text(_pick(mapping, "suspect"), _MAX_ID_LENGTH) or None

    if not victim and not suspect:
        return None

    amount = _parse_decimal(_pick(mapping, "amount"))
    currency = _normalize_currency(_pick(mapping, "currency")) or None

    if amount is not None and amount <= 0:
        amount = None
        currency = None

    return _Complaint(
        id=_clean_text(_pick(mapping, "id"), _MAX_ID_LENGTH) or None,
        reference=_clean_text(_pick(mapping, "reference"), _MAX_REFERENCE_LENGTH) or None,
        reported_at=reported_at,
        category=_normalize_lower_enum(_pick(mapping, "category"), _COMPLAINT_CATEGORIES, "other"),
        victim=victim,
        suspect=suspect,
        amount=_quantize_money(amount) if amount is not None else None,
        currency=currency,
        transaction_reference=_clean_text(
            _pick(mapping, "transaction_reference"),
            _MAX_REFERENCE_LENGTH,
        )
        or None,
    )


def _normalize_entity(record: Any) -> Optional[_Entity]:
    """
    Normalize one pseudonymous synthetic entity record.
    """
    mapping = _record_to_mapping(
        record,
        ("id", "entity_type"),
        _ENTITY_ALIASES,
    )

    entity_id = _clean_text(_pick(mapping, "id"), _MAX_ID_LENGTH)

    if not entity_id:
        return None

    return _Entity(
        id=entity_id,
        entity_type=_normalize_enum(_pick(mapping, "entity_type"), _ENTITY_TYPES, "OTHER"),
    )


def _normalize_link(record: Any, entity_types: Mapping[str, str]) -> Optional[_Link]:
    """
    Normalize one synthetic account-entity link record.
    """
    mapping = _record_to_mapping(
        record,
        (
            "id",
            "account_id",
            "entity_id",
            "entity_type",
            "match_method",
            "verification_state",
            "confidence",
            "valid_from",
            "valid_to",
            "source",
        ),
        _LINK_ALIASES,
    )

    account_id = _clean_text(_pick(mapping, "account_id"), _MAX_ID_LENGTH)
    entity_id = _clean_text(_pick(mapping, "entity_id"), _MAX_ID_LENGTH)
    valid_from = _parse_datetime(_pick(mapping, "valid_from"))

    if not account_id or not entity_id or valid_from is None:
        return None

    valid_to = _parse_datetime(_pick(mapping, "valid_to"))

    if valid_to is not None and valid_to < valid_from:
        valid_to = valid_from

    entity_type = _normalize_enum(
        _pick(mapping, "entity_type") or entity_types.get(entity_id),
        _ENTITY_TYPES,
        "OTHER",
    )

    return _Link(
        id=_clean_text(_pick(mapping, "id"), _MAX_ID_LENGTH) or None,
        account_id=account_id,
        entity_id=entity_id,
        entity_type=entity_type,
        match_method=_normalize_enum(_pick(mapping, "match_method"), _MATCH_METHODS, "HEURISTIC"),
        verification_state=_normalize_enum(
            _pick(mapping, "verification_state"),
            _VERIFICATION_STATES,
            "UNVERIFIED",
        ),
        confidence=_normalize_confidence(_pick(mapping, "confidence")),
        valid_from=valid_from,
        valid_to=valid_to,
        source=_clean_text(_pick(mapping, "source"), _MAX_SOURCE_LENGTH) or None,
    )


def _normalize_balance(record: Any) -> Optional[_Balance]:
    """
    Normalize one optional synthetic balance snapshot.
    """
    mapping = _record_to_mapping(
        record,
        ("account_id", "timestamp", "amount", "currency"),
        _BALANCE_ALIASES,
    )

    account_id = _clean_text(_pick(mapping, "account_id"), _MAX_ID_LENGTH)
    timestamp = _parse_datetime(_pick(mapping, "timestamp"))
    amount = _parse_decimal(_pick(mapping, "amount"))

    if not account_id or timestamp is None or amount is None or amount <= 0:
        return None

    return _Balance(
        account_id=account_id,
        timestamp=timestamp,
        amount=_quantize_money(amount),
        currency=_normalize_currency(_pick(mapping, "currency")) or "UNKNOWN",
    )


def _normalize_many(
    raw_items: Iterable[Any],
    normalizer: Any,
    limit: int,
    sort_key: Any = None,
) -> tuple[list[Any], int]:
    """
    Normalize and cap a sequence of records.

    Returns `(records, truncated_count)`.
    """
    out: list[Any] = []

    for item in raw_items:
        record = normalizer(item)

        if record is None:
            continue

        out.append(record)

    if sort_key is not None:
        out.sort(key=sort_key)

    if limit >= 0 and len(out) > limit:
        truncated = len(out) - limit
        return out[:limit], truncated

    return out, 0


# -----------------------------------------------------------------------------
# Window stats
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WindowMetrics:
    """
    Immutable metrics for one bounded observation window.
    """

    count: int = 0
    primary_currency: Optional[str] = None

    amount_sum: Decimal = _ZERO
    amount_mean: Decimal = _ZERO
    amount_median: Decimal = _ZERO
    amount_max: Decimal = _ZERO
    amount_min: Decimal = _ZERO
    amount_stddev: float = 0.0
    amount_cv: float = 0.0
    amount_zscore: float = 0.0

    distinct_counterparties: int = 0
    inbound_distinct: int = 0
    outbound_distinct: int = 0
    inbound_counterparties: tuple[str, ...] = ()
    outbound_counterparties: tuple[str, ...] = ()

    new_counterparty_ratio: float = 0.0
    repeat_counterparty_ratio: float = 0.0

    top1_share: float = 0.0
    top5_share: float = 0.0
    counterparty_hhi: float = 0.0
    counterparty_entropy: float = 0.0

    inbound_hhi: float = 0.0
    outbound_hhi: float = 0.0

    inbound_txn_count: int = 0
    outbound_txn_count: int = 0
    inbound_amount: Decimal = _ZERO
    outbound_amount: Decimal = _ZERO

    outbound_amount_share: float = 0.0
    inbound_outbound_amount_ratio: Optional[float] = None

    channel_shares: Mapping[str, float] = field(default_factory=dict)
    channel_entropy: float = 0.0
    channel_switch_count: int = 0

    night_ratio: float = 0.0
    weekend_ratio: float = 0.0
    hour_entropy: float = 0.0
    day_entropy: float = 0.0

    interarrival_mean_seconds: float = 0.0
    burstiness: float = 0.0

    truncated_amounts: bool = False
    truncated_timestamps: bool = False
    truncated_counterparties: bool = False


def _empty_window_metrics() -> WindowMetrics:
    """
    Return a safe zeroed window metric object.
    """
    return WindowMetrics()


def _sum_currency_amounts(
    counterparty_amounts: Mapping[str, Mapping[str, Decimal]],
    currency: Optional[str],
) -> Decimal:
    """
    Sum amounts for one currency across counterparties.
    """
    if not currency:
        return _ZERO

    total = _ZERO

    for amounts in counterparty_amounts.values():
        total += amounts.get(currency, _ZERO)

    return _quantize_money(total)


def _counterparty_weights(
    counts: Mapping[str, int],
    amounts: Mapping[str, Mapping[str, Decimal]],
    currency: Optional[str],
) -> dict[str, float]:
    """
    Return bounded counterparty weights.

    Amount weights are preferred when available. Count weights are used as a
    fallback so concentration and entropy remain computable.
    """
    weights: dict[str, float] = {}

    for counterparty, count in counts.items():
        amount = _ZERO

        if currency:
            amount = amounts.get(counterparty, {}).get(currency, _ZERO)

        if amount > 0:
            weights[counterparty] = _decimal_to_float(amount, 0.0)
        else:
            weights[counterparty] = float(max(0, int(count)))

    return weights


class _WindowStats:
    """
    Mutable accumulator for one bounded observation window.
    """

    def __init__(self, max_samples: int, max_counterparties: int) -> None:
        self.max_samples = max(1, int(max_samples))
        self.max_counterparties = max(1, int(max_counterparties))

        self.count = 0
        self.inbound_txn_count = 0
        self.outbound_txn_count = 0

        self.currency_counts: dict[str, int] = {}
        self.amount_by_currency: dict[str, Decimal] = {}
        self.amounts: list[tuple[str, Decimal]] = []

        self.cp_in_counts: dict[str, int] = {}
        self.cp_out_counts: dict[str, int] = {}
        self.cp_in_amounts: dict[str, dict[str, Decimal]] = {}
        self.cp_out_amounts: dict[str, dict[str, Decimal]] = {}

        self.channel_counts: dict[str, int] = {}
        self.hour_counts: dict[int, int] = {}
        self.day_counts: dict[int, int] = {}
        self.timestamps: list[datetime] = []

        self.night_count = 0
        self.weekend_count = 0

        self.last_channel: Optional[str] = None
        self.switch_count = 0

        self.truncated_amounts = False
        self.truncated_timestamps = False
        self.truncated_counterparties = False

    def add(self, txn: _Txn, direction: str) -> None:
        """
        Add one completed transaction to the window.
        """
        self.count += 1

        if direction == "out":
            self.outbound_txn_count += 1
            counterparty = txn.receiver
        else:
            self.inbound_txn_count += 1
            counterparty = txn.sender

        self.currency_counts[txn.currency] = (
            self.currency_counts.get(txn.currency, 0) + 1
        )
        self.amount_by_currency[txn.currency] = (
            self.amount_by_currency.get(txn.currency, _ZERO) + txn.amount
        )

        if len(self.amounts) < self.max_samples:
            self.amounts.append((txn.currency, txn.amount))
        else:
            self.truncated_amounts = True

        if direction == "out":
            self.cp_out_counts[counterparty] = (
                self.cp_out_counts.get(counterparty, 0) + 1
            )
            bucket = self.cp_out_amounts.setdefault(counterparty, {})
            bucket[txn.currency] = bucket.get(txn.currency, _ZERO) + txn.amount
        else:
            self.cp_in_counts[counterparty] = (
                self.cp_in_counts.get(counterparty, 0) + 1
            )
            bucket = self.cp_in_amounts.setdefault(counterparty, {})
            bucket[txn.currency] = bucket.get(txn.currency, _ZERO) + txn.amount

        self.channel_counts[txn.channel] = (
            self.channel_counts.get(txn.channel, 0) + 1
        )

        if self.last_channel is not None and txn.channel != self.last_channel:
            self.switch_count += 1

        self.last_channel = txn.channel

        hour = txn.occurred_at.hour
        day = txn.occurred_at.weekday()

        self.hour_counts[hour] = self.hour_counts.get(hour, 0) + 1
        self.day_counts[day] = self.day_counts.get(day, 0) + 1

        if hour in _NIGHT_HOURS:
            self.night_count += 1

        if day >= 5:
            self.weekend_count += 1

        if len(self.timestamps) < self.max_samples:
            self.timestamps.append(txn.occurred_at)
        else:
            self.truncated_timestamps = True

    def _primary_currency(self) -> Optional[str]:
        """
        Return the dominant currency for the window.
        """
        if not self.currency_counts:
            return None

        return sorted(
            self.currency_counts.items(),
            key=lambda item: (
                -item[1],
                -_decimal_to_float(self.amount_by_currency.get(item[0], _ZERO), 0.0),
                item[0],
            ),
        )[0][0]

    def _cap_counterparties(
        self,
        counts: Mapping[str, int],
        amounts: Mapping[str, Mapping[str, Decimal]],
    ) -> tuple[dict[str, int], dict[str, dict[str, Decimal]], bool]:
        """
        Cap counterparty cardinality deterministically.
        """
        if len(counts) <= self.max_counterparties:
            return dict(counts), {key: dict(value) for key, value in amounts.items()}, False

        def sort_key(item: tuple[str, int]) -> tuple[float, float, str]:
            counterparty, count = item
            total_amount = sum(amounts.get(counterparty, {}).values(), _ZERO)
            return (
                -float(count),
                -_decimal_to_float(total_amount, 0.0),
                counterparty,
            )

        kept_counts = dict(
            sorted(counts.items(), key=sort_key)[: self.max_counterparties]
        )
        kept_amounts = {
            counterparty: dict(amounts.get(counterparty, {}))
            for counterparty in kept_counts
        }

        return kept_counts, kept_amounts, True

    def finalize(
        self,
        window_start: Optional[datetime],
        first_seen_map: Mapping[str, datetime],
    ) -> WindowMetrics:
        """
        Finalize accumulated stats into immutable metrics.
        """
        primary = self._primary_currency()
        amount_sum = self.amount_by_currency.get(primary, _ZERO) if primary else _ZERO
        amount_count = self.currency_counts.get(primary, 0) if primary else 0

        sample = (
            [amount for currency, amount in self.amounts if currency == primary]
            if primary
            else []
        )

        if amount_count > len(sample):
            self.truncated_amounts = True

        mean = (
            _quantize_money(amount_sum / Decimal(amount_count))
            if amount_count > 0
            else _ZERO
        )

        if sample:
            median = _median_decimal(sample)
            max_amount = max(sample)
            min_amount = min(sample)
        elif amount_count > 0:
            median = mean
            max_amount = mean
            min_amount = mean
        else:
            median = _ZERO
            max_amount = _ZERO
            min_amount = _ZERO

        stddev = _population_stddev_float(sample, mean)
        mean_float = _decimal_to_float(mean, 0.0)
        cv = stddev / mean_float if mean_float > 0 else 0.0

        max_float = _decimal_to_float(max_amount, mean_float)

        if stddev > 0:
            zscore = (max_float - mean_float) / stddev
        else:
            zscore = 0.0

        zscore = _clip_float(zscore, -10.0, 10.0, 0.0)

        cp_in_counts, cp_in_amounts, in_trunc = self._cap_counterparties(
            self.cp_in_counts,
            self.cp_in_amounts,
        )
        cp_out_counts, cp_out_amounts, out_trunc = self._cap_counterparties(
            self.cp_out_counts,
            self.cp_out_amounts,
        )

        if in_trunc or out_trunc:
            self.truncated_counterparties = True

        union_counts: dict[str, int] = defaultdict(int)

        for counterparty, value in cp_in_counts.items():
            union_counts[counterparty] += value

        for counterparty, value in cp_out_counts.items():
            union_counts[counterparty] += value

        distinct = len(union_counts)

        new_count = 0

        if window_start is not None and first_seen_map:
            for counterparty in union_counts:
                first_seen = first_seen_map.get(counterparty)

                if first_seen is not None and first_seen >= window_start:
                    new_count += 1

        new_ratio = new_count / distinct if distinct > 0 else 0.0
        repeat_ratio = (
            max(0, self.count - distinct) / self.count if self.count > 0 else 0.0
        )

        union_amounts: dict[str, Decimal] = defaultdict(lambda: _ZERO)

        for counterparty, currency_map in cp_in_amounts.items():
            if primary:
                union_amounts[counterparty] += currency_map.get(primary, _ZERO)

        for counterparty, currency_map in cp_out_amounts.items():
            if primary:
                union_amounts[counterparty] += currency_map.get(primary, _ZERO)

        total_union_amount = sum(union_amounts.values(), _ZERO)

        if total_union_amount > 0:
            union_weights = {
                counterparty: _decimal_to_float(amount, 0.0)
                for counterparty, amount in union_amounts.items()
            }
        else:
            union_weights = {
                counterparty: float(count)
                for counterparty, count in union_counts.items()
            }

        top1 = _top_share(union_weights, 1)
        top5 = _top_share(union_weights, 5)
        counterparty_hhi = _hhi(union_weights)
        counterparty_entropy = _normalized_entropy(union_weights)

        inbound_amount = _sum_currency_amounts(cp_in_amounts, primary)
        outbound_amount = _sum_currency_amounts(cp_out_amounts, primary)
        total_amount = inbound_amount + outbound_amount

        inbound_weights = _counterparty_weights(
            cp_in_counts,
            cp_in_amounts,
            primary,
        )
        outbound_weights = _counterparty_weights(
            cp_out_counts,
            cp_out_amounts,
            primary,
        )

        inbound_hhi = _hhi(inbound_weights)
        outbound_hhi = _hhi(outbound_weights)

        if total_amount > 0:
            outbound_amount_share = _decimal_to_float(outbound_amount, 0.0) / (
                _decimal_to_float(total_amount, 1.0)
            )
            inbound_outbound_ratio = (
                _decimal_to_float(inbound_amount, 0.0)
                / _decimal_to_float(outbound_amount, 1.0)
                if outbound_amount > 0
                else None
            )
        else:
            total_txn_direction_count = self.inbound_txn_count + self.outbound_txn_count
            outbound_amount_share = (
                self.outbound_txn_count / total_txn_direction_count
                if total_txn_direction_count > 0
                else 0.0
            )
            inbound_outbound_ratio = (
                self.inbound_txn_count / self.outbound_txn_count
                if self.outbound_txn_count > 0
                else None
            )

        channel_total = sum(self.channel_counts.values())
        channel_shares = {
            channel: count / channel_total
            for channel, count in self.channel_counts.items()
            if channel_total > 0
        }

        timestamps = sorted(self.timestamps)
        intervals: list[float] = []

        for left, right in zip(timestamps, timestamps[1:]):
            seconds = (right - left).total_seconds()

            if seconds >= 0 and math.isfinite(seconds):
                intervals.append(float(seconds))

        if intervals:
            interarrival_mean = sum(intervals) / float(len(intervals))
            interval_mean = interarrival_mean
            interval_var = sum(
                (value - interval_mean) ** 2 for value in intervals
            ) / float(len(intervals))
            interval_stddev = math.sqrt(interval_var) if interval_var > 0 else 0.0
            burstiness = (
                interval_stddev / interval_mean if interval_mean > 0 else 0.0
            )
        else:
            interarrival_mean = 0.0
            burstiness = 0.0

        return WindowMetrics(
            count=self.count,
            primary_currency=primary,
            amount_sum=amount_sum,
            amount_mean=mean,
            amount_median=median,
            amount_max=max_amount,
            amount_min=min_amount,
            amount_stddev=_clip_float(stddev, 0.0, None, 0.0),
            amount_cv=_clip_float(cv, 0.0, None, 0.0),
            amount_zscore=zscore,
            distinct_counterparties=distinct,
            inbound_distinct=len(cp_in_counts),
            outbound_distinct=len(cp_out_counts),
            inbound_counterparties=tuple(sorted(cp_in_counts)),
            outbound_counterparties=tuple(sorted(cp_out_counts)),
            new_counterparty_ratio=_clip_float(new_ratio, 0.0, 1.0, 0.0),
            repeat_counterparty_ratio=_clip_float(repeat_ratio, 0.0, 1.0, 0.0),
            top1_share=_clip_float(top1, 0.0, 1.0, 0.0),
            top5_share=_clip_float(top5, 0.0, 1.0, 0.0),
            counterparty_hhi=_clip_float(counterparty_hhi, 0.0, 1.0, 0.0),
            counterparty_entropy=_clip_float(counterparty_entropy, 0.0, 1.0, 0.0),
            inbound_hhi=_clip_float(inbound_hhi, 0.0, 1.0, 0.0),
            outbound_hhi=_clip_float(outbound_hhi, 0.0, 1.0, 0.0),
            inbound_txn_count=self.inbound_txn_count,
            outbound_txn_count=self.outbound_txn_count,
            inbound_amount=inbound_amount,
            outbound_amount=outbound_amount,
            outbound_amount_share=_clip_float(outbound_amount_share, 0.0, 1.0, 0.0),
            inbound_outbound_amount_ratio=(
                _clip_float(inbound_outbound_ratio, 0.0, None, 0.0)
                if inbound_outbound_ratio is not None
                else None
            ),
            channel_shares={
                channel: _clip_float(share, 0.0, 1.0, 0.0)
                for channel, share in channel_shares.items()
            },
            channel_entropy=_normalized_entropy(self.channel_counts),
            channel_switch_count=self.switch_count,
            night_ratio=_clip_float(
                self.night_count / self.count if self.count else 0.0,
                0.0,
                1.0,
                0.0,
            ),
            weekend_ratio=_clip_float(
                self.weekend_count / self.count if self.count else 0.0,
                0.0,
                1.0,
                0.0,
            ),
            hour_entropy=_normalized_entropy(self.hour_counts),
            day_entropy=_normalized_entropy(self.day_counts),
            interarrival_mean_seconds=_clip_float(
                interarrival_mean,
                0.0,
                None,
                0.0,
            ),
            burstiness=_clip_float(burstiness, 0.0, None, 0.0),
            truncated_amounts=self.truncated_amounts,
            truncated_timestamps=self.truncated_timestamps,
            truncated_counterparties=self.truncated_counterparties,
        )


# -----------------------------------------------------------------------------
# Derived metric containers
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BalanceMetrics:
    """
    Bounded synthetic balance metrics.
    """

    snapshot_count: int = 0
    primary_currency: Optional[str] = None
    mean: Decimal = _ZERO
    minimum: Decimal = _ZERO
    maximum: Decimal = _ZERO
    stddev: float = 0.0
    cv: float = 0.0
    slope: float = 0.0
    drop_ratio_7d: float = 0.0


@dataclass(frozen=True, slots=True)
class ComplaintMetrics:
    """
    Bounded synthetic complaint metrics.

    Raw narratives are never read or represented here.
    """

    count_30d: int = 0
    rate_30d: float = 0.0
    category_entropy: float = 0.0
    victim_count_30d: int = 0
    suspect_count_30d: int = 0
    recency_days: Optional[int] = None
    linked_txn_ratio_30d: float = 0.0


@dataclass(frozen=True, slots=True)
class LinkMetrics:
    """
    Bounded synthetic entity-link metrics.

    Links are association signals only.
    """

    count_30d: int = 0
    device_distinct_count_30d: int = 0
    ip_distinct_count_30d: int = 0
    phone_distinct_count_30d: int = 0
    email_distinct_count_30d: int = 0
    upi_distinct_count_30d: int = 0
    shared_device_account_count_30d: int = 0
    shared_ip_account_count_30d: int = 0
    shared_upi_account_count_30d: int = 0
    heuristic_ratio_30d: float = 0.0
    unverified_ratio_30d: float = 0.0
    confidence_mean_30d: Optional[float] = None


@dataclass(frozen=True, slots=True)
class GraphIndices:
    """
    Bounded transaction graph indices for one observation horizon.
    """

    adj: Mapping[str, set[str]] = field(default_factory=dict)
    out_edges: Mapping[str, set[str]] = field(default_factory=dict)
    in_edges: Mapping[str, set[str]] = field(default_factory=dict)
    node_count: int = 0
    edge_count: int = 0
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class GraphMetrics:
    """
    Bounded synthetic graph metrics.

    These are investigative association signals only. They are not proof of
    wrongdoing.
    """

    degree_30d: int = 0
    in_degree_30d: int = 0
    out_degree_30d: int = 0
    page_rank_norm_30d: float = 0.0
    betweenness_norm_30d: Optional[float] = None
    cycle_indicator_30d: bool = False
    path_count_30d: int = 0
    intermediary_score_30d: float = 0.0
    source_concentration_30d: float = 0.0
    beneficiary_concentration_30d: float = 0.0
    shared_entity_cluster_size_30d: int = 1
    neighbor_complaint_ratio_30d: float = 0.0


@dataclass(frozen=True, slots=True)
class AnomalyMetrics:
    """
    Bounded heuristic anomaly scores.

    These are investigative prioritization signals only. They are not
    calibrated probabilities of guilt.
    """

    amount_score_30d: float = 0.0
    velocity_score_30d: float = 0.0
    network_score_30d: float = 0.0
    composite_score_30d: float = 0.0


@dataclass(slots=True)
class _PreparedDataset:
    """
    Normalized and indexed synthetic dataset for feature construction.
    """

    accounts: list[_Account] = field(default_factory=list)
    txns: list[_Txn] = field(default_factory=list)
    complaints: list[_Complaint] = field(default_factory=list)
    entities: list[_Entity] = field(default_factory=list)
    links: list[_Link] = field(default_factory=list)
    balances: list[_Balance] = field(default_factory=list)

    txns_by_account: dict[str, list[_Txn]] = field(default_factory=dict)
    complaints_by_account: dict[str, list[_Complaint]] = field(default_factory=dict)
    links_by_account: dict[str, list[_Link]] = field(default_factory=dict)
    balances_by_account: dict[str, list[_Balance]] = field(default_factory=dict)

    account_entities: dict[str, set[str]] = field(default_factory=dict)
    entity_to_accounts: dict[str, set[str]] = field(default_factory=dict)

    known_txn_refs: set[str] = field(default_factory=set)
    truncated: dict[str, int] = field(default_factory=dict)


# -----------------------------------------------------------------------------
# Build issues and result
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeatureBuildIssue:
    """
    Safe feature-build issue.

    Issues never contain raw feature values, raw narratives, raw identifiers,
    secrets, tokens, passwords, database URLs, filesystem paths, or model
    artifact paths.
    """

    severity: str
    code: str
    message: str
    account_id: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable issue mapping.
        """
        payload: dict[str, Any] = {
            "severity": _clean_text(self.severity, 20),
            "code": _clean_text(self.code, 100),
            "message": _clean_text(self.message, 300),
        }

        if self.account_id:
            payload["account_id"] = _clean_text(self.account_id, 200)

        if self.details:
            payload["details"] = self.details

        return payload


@dataclass(slots=True)
class FeatureBuildResult:
    """
    Safe ML feature construction result.

    The `vectors` list is intended for internal downstream use. Public
    summaries deliberately exclude feature values.
    """

    ok: bool = True
    observation_time: datetime = field(default_factory=_now_utc)

    vectors: list[FeatureVector] = field(default_factory=list)
    rejected_accounts: list[str] = field(default_factory=list)
    issues: list[FeatureBuildIssue] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)

    max_issues: int = _DEFAULT_MAX_ISSUES
    max_warnings: int = _DEFAULT_MAX_WARNINGS

    _error_count: int = field(default=0, repr=False, compare=False)
    _warning_count: int = field(default=0, repr=False, compare=False)
    _issue_truncated: bool = field(default=False, repr=False, compare=False)
    _warning_truncated: bool = field(default=False, repr=False, compare=False)

    def add_error(
        self,
        *,
        code: str,
        message: str,
        account_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe error entry.
        """
        if self._issue_truncated:
            self.ok = False
            return False

        if self._error_count >= max(1, int(self.max_issues)):
            self._issue_truncated = True
            self.issues.append(
                FeatureBuildIssue(
                    severity="error",
                    code="issue_list_truncated",
                    message="Error list truncated by configured limit.",
                )
            )
            self.ok = False
            return False

        self.issues.append(
            FeatureBuildIssue(
                severity="error",
                code=_clean_text(code, 100),
                message=_clean_text(message, 300),
                account_id=_clean_text(account_id, 200) if account_id else None,
                details=_safe_detail_value(details) or {},
            )
        )

        self._error_count += 1
        self.ok = False
        return True

    def add_warning(
        self,
        *,
        code: str,
        message: str,
        account_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe warning entry.
        """
        if self._warning_truncated:
            return False

        if self._warning_count >= max(1, int(self.max_warnings)):
            self._warning_truncated = True
            self.issues.append(
                FeatureBuildIssue(
                    severity="warning",
                    code="warning_list_truncated",
                    message="Warning list truncated by configured limit.",
                )
            )
            return False

        self.issues.append(
            FeatureBuildIssue(
                severity="warning",
                code=_clean_text(code, 100),
                message=_clean_text(message, 300),
                account_id=_clean_text(account_id, 200) if account_id else None,
                details=_safe_detail_value(details) or {},
            )
        )

        self._warning_count += 1
        return True

    def add_info(
        self,
        *,
        code: str,
        message: str,
        account_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe info entry.
        """
        self.issues.append(
            FeatureBuildIssue(
                severity="info",
                code=_clean_text(code, 100),
                message=_clean_text(message, 300),
                account_id=_clean_text(account_id, 200) if account_id else None,
                details=_safe_detail_value(details) or {},
            )
        )
        return True

    def finalize(
        self,
        options: Optional[FeatureBuildOptions] = None,
        catalog: Optional[FeatureCatalog] = None,
    ) -> None:
        """
        Finalize safe metadata for the result.
        """
        self.counts.update(
            {
                "vectors_built": len(self.vectors),
                "accounts_rejected": len(self.rejected_accounts),
                "errors": self._error_count,
                "warnings": self._warning_count,
            }
        )

        self.metadata.update(
            {
                "features_version": FEATURES_VERSION,
                "observation_time": self.observation_time.isoformat(),
                "error_truncated": self._issue_truncated,
                "warning_truncated": self._warning_truncated,
                "caveats": list(_FEATURE_BUILD_CAVEATS),
                "safety_flags": dict(_FEATURE_SAFETY_FLAGS),
            }
        )

        if options is not None:
            self.metadata["options"] = options.safe_summary()

        if catalog is not None:
            self.metadata["catalog_version"] = catalog.version
            self.metadata["catalog_fingerprint"] = catalog.fingerprint()

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include feature values.
        """
        return {
            "ok": self.ok,
            "observation_time": self.observation_time.isoformat(),
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(_FEATURE_BUILD_CAVEATS),
            "safety_flags": dict(_FEATURE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Dataset preparation
# -----------------------------------------------------------------------------


def _prepare_dataset(
    dataset: Any,
    options: FeatureBuildOptions,
    result: FeatureBuildResult,
) -> _PreparedDataset:
    """
    Normalize and index bounded synthetic dataset inputs.
    """
    prepared = _PreparedDataset()

    raw_accounts = _as_sequence(
        _get_source_collection(dataset, ("accounts", "account_records"))
    )
    accounts, accounts_truncated = _normalize_many(
        raw_accounts,
        _normalize_account,
        options.max_accounts,
        sort_key=lambda item: item.id,
    )
    prepared.accounts = accounts
    prepared.truncated["accounts"] = accounts_truncated

    if accounts_truncated:
        result.add_warning(
            code="accounts_truncated",
            message="Account input exceeded configured limit and was truncated.",
            details={"truncated_count": accounts_truncated},
        )

    raw_txns = _as_sequence(
        _get_source_collection(dataset, ("transactions", "txn_records", "txns"))
    )
    txns, txns_truncated = _normalize_many(
        raw_txns,
        _normalize_txn,
        options.max_transactions,
        sort_key=lambda item: (item.occurred_at, item.sender, item.receiver),
    )
    prepared.txns = txns
    prepared.truncated["transactions"] = txns_truncated

    if txns_truncated:
        result.add_warning(
            code="transactions_truncated",
            message="Transaction input exceeded configured limit and was truncated.",
            details={"truncated_count": txns_truncated},
        )

    raw_complaints = _as_sequence(
        _get_source_collection(dataset, ("complaints", "complaint_records"))
    )
    complaints, complaints_truncated = _normalize_many(
        raw_complaints,
        _normalize_complaint,
        options.max_complaints,
        sort_key=lambda item: item.reported_at,
    )
    prepared.complaints = complaints
    prepared.truncated["complaints"] = complaints_truncated

    if complaints_truncated:
        result.add_warning(
            code="complaints_truncated",
            message="Complaint input exceeded configured limit and was truncated.",
            details={"truncated_count": complaints_truncated},
        )

    raw_entities = _as_sequence(
        _get_source_collection(dataset, ("entities", "entity_records"))
    )
    entities, entities_truncated = _normalize_many(
        raw_entities,
        _normalize_entity,
        options.max_entities,
        sort_key=lambda item: item.id,
    )
    prepared.entities = entities
    prepared.truncated["entities"] = entities_truncated

    if entities_truncated:
        result.add_warning(
            code="entities_truncated",
            message="Entity input exceeded configured limit and was truncated.",
            details={"truncated_count": entities_truncated},
        )

    entity_types = {entity.id: entity.entity_type for entity in entities}

    raw_links = _as_sequence(
        _get_source_collection(
            dataset,
            ("entity_links", "links", "account_entity_links"),
        )
    )
    links, links_truncated = _normalize_many(
        raw_links,
        lambda raw: _normalize_link(raw, entity_types),
        options.max_links,
        sort_key=lambda item: (item.valid_from, item.account_id, item.entity_id),
    )
    prepared.links = links
    prepared.truncated["entity_links"] = links_truncated

    if links_truncated:
        result.add_warning(
            code="entity_links_truncated",
            message="Entity-link input exceeded configured limit and was truncated.",
            details={"truncated_count": links_truncated},
        )

    raw_balances = _as_sequence(
        _get_source_collection(dataset, ("balances", "balance_snapshots"))
    )
    balances, balances_truncated = _normalize_many(
        raw_balances,
        _normalize_balance,
        options.max_balances,
        sort_key=lambda item: (item.account_id, item.timestamp),
    )
    prepared.balances = balances
    prepared.truncated["balances"] = balances_truncated

    if balances_truncated:
        result.add_warning(
            code="balances_truncated",
            message="Balance input exceeded configured limit and was truncated.",
            details={"truncated_count": balances_truncated},
        )

    txns_by_account: dict[str, list[_Txn]] = defaultdict(list)

    for txn in txns:
        txns_by_account[txn.sender].append(txn)
        txns_by_account[txn.receiver].append(txn)

    for account_id, account_txns in txns_by_account.items():
        account_txns.sort(key=lambda item: (item.occurred_at, item.sender, item.receiver))
        txns_by_account[account_id] = account_txns

    prepared.txns_by_account = dict(txns_by_account)

    complaints_by_account: dict[str, list[_Complaint]] = defaultdict(list)

    for complaint in complaints:
        if complaint.victim:
            complaints_by_account[complaint.victim].append(complaint)

        if complaint.suspect and complaint.suspect != complaint.victim:
            complaints_by_account[complaint.suspect].append(complaint)

    prepared.complaints_by_account = dict(complaints_by_account)

    links_by_account: dict[str, list[_Link]] = defaultdict(list)
    account_entities: dict[str, set[str]] = defaultdict(set)
    entity_to_accounts: dict[str, set[str]] = defaultdict(set)

    for link in links:
        links_by_account[link.account_id].append(link)
        account_entities[link.account_id].add(link.entity_id)

        accounts_for_entity = entity_to_accounts[link.entity_id]

        if len(accounts_for_entity) < options.max_accounts_per_entity:
            accounts_for_entity.add(link.account_id)
        elif link.account_id in accounts_for_entity:
            accounts_for_entity.add(link.account_id)

    prepared.links_by_account = dict(links_by_account)
    prepared.account_entities = dict(account_entities)
    prepared.entity_to_accounts = dict(entity_to_accounts)

    balances_by_account: dict[str, list[_Balance]] = defaultdict(list)

    for balance in balances:
        balances_by_account[balance.account_id].append(balance)

    for account in accounts:
        for timestamp, amount, currency in account.balance_snapshots:
            balances_by_account[account.id].append(
                _Balance(
                    account_id=account.id,
                    timestamp=timestamp,
                    amount=amount,
                    currency=currency,
                )
            )

    for account_id, account_balances in balances_by_account.items():
        account_balances.sort(key=lambda item: (item.timestamp, item.currency, item.amount))
        balances_by_account[account_id] = account_balances

    prepared.balances_by_account = dict(balances_by_account)

    known_txn_refs: set[str] = set()

    for txn in txns:
        if txn.id:
            known_txn_refs.add(txn.id)

        if txn.reference:
            known_txn_refs.add(txn.reference)

    prepared.known_txn_refs = known_txn_refs

    return prepared


# -----------------------------------------------------------------------------
# Graph construction
# -----------------------------------------------------------------------------


def _build_graph_indices(
    txns: Sequence[_Txn],
    observation_time: datetime,
    options: FeatureBuildOptions,
    result: FeatureBuildResult,
) -> GraphIndices:
    """
    Build bounded directed transaction graph indices for a 30-day horizon.
    """
    start = observation_time - timedelta(days=30)

    adj: dict[str, set[str]] = defaultdict(set)
    out_edges: dict[str, set[str]] = defaultdict(set)
    in_edges: dict[str, set[str]] = defaultdict(set)

    nodes: set[str] = set()
    edge_count = 0
    truncated = False

    for txn in txns:
        # Strictly before `observation_time`, matching the dataset read in
        # app/services/features.py (`occurred_at < observation_time`) and the
        # caveat the API publishes ("Every query is bounded strictly before
        # as_of"). This was `>`, which includes an event dated exactly at the
        # cutoff — so the two layers disagreed about the boundary and the
        # published caveat described only one of them.
        if txn.occurred_at >= observation_time or txn.occurred_at < start:
            continue

        sender_known = txn.sender in nodes
        receiver_known = txn.receiver in nodes

        if not sender_known and len(nodes) >= options.max_graph_nodes:
            truncated = True
            continue

        if not receiver_known and len(nodes) >= options.max_graph_nodes:
            truncated = True
            continue

        if edge_count >= options.max_graph_edges:
            truncated = True
            continue

        nodes.add(txn.sender)
        nodes.add(txn.receiver)

        if txn.receiver not in out_edges[txn.sender]:
            out_edges[txn.sender].add(txn.receiver)
            in_edges[txn.receiver].add(txn.sender)
            adj[txn.sender].add(txn.receiver)
            adj[txn.receiver].add(txn.sender)
            edge_count += 1

    if truncated:
        result.add_warning(
            code="graph_truncated",
            message="Transaction graph construction was truncated by configured limits.",
            details={
                "node_count": len(nodes),
                "edge_count": edge_count,
                "max_graph_nodes": options.max_graph_nodes,
                "max_graph_edges": options.max_graph_edges,
            },
        )

    return GraphIndices(
        adj=dict(adj),
        out_edges=dict(out_edges),
        in_edges=dict(in_edges),
        node_count=len(nodes),
        edge_count=edge_count,
        truncated=truncated,
    )


def _local_nodes(
    start: str,
    adj: Mapping[str, set[str]],
    max_nodes: int,
) -> set[str]:
    """
    Return a bounded local undirected neighborhood.
    """
    nodes = {start}
    queue = [start]
    head = 0

    while head < len(queue) and len(nodes) < max_nodes:
        current = queue[head]
        head += 1

        for neighbor in adj.get(current, ()):
            if neighbor in nodes:
                continue

            nodes.add(neighbor)
            queue.append(neighbor)

            if len(nodes) >= max_nodes:
                break

    return nodes


def _local_pagerank(
    account_id: str,
    nodes: set[str],
    out_edges: Mapping[str, set[str]],
    options: FeatureBuildOptions,
) -> float:
    """
    Compute bounded local PageRank and normalize to [0, 1].
    """
    n = len(nodes)

    if n <= 1:
        return 0.0

    node_list = sorted(nodes)
    local_out = {
        node: [
            target
            for target in out_edges.get(node, ())
            if target in nodes
        ]
        for node in node_list
    }

    scores = {node: 1.0 / float(n) for node in node_list}
    damping = float(options.pagerank_damping)

    for _ in range(int(options.pagerank_iterations)):
        new_scores = {node: (1.0 - damping) / float(n) for node in node_list}
        dangling = 0.0

        for node in node_list:
            if not local_out[node]:
                dangling += scores[node]

        dangling_share = damping * dangling / float(n)

        for node in node_list:
            outs = local_out[node]

            if not outs:
                continue

            contribution = damping * scores[node] / float(len(outs))

            for target in outs:
                new_scores[target] += contribution

        for node in node_list:
            new_scores[node] += dangling_share
            new_scores[node] = _clip_float(new_scores[node], 0.0, 1.0, 0.0)

        scores = new_scores

    max_rank = max(scores.values(), default=0.0)

    if max_rank <= 0:
        return 0.0

    return _clip_float(scores.get(account_id, 0.0) / max_rank, 0.0, 1.0, 0.0)


def _local_betweenness(
    account_id: str,
    nodes: set[str],
    out_edges: Mapping[str, set[str]],
) -> Optional[float]:
    """
    Compute a bounded approximate betweenness score.

    Returns None when the local subgraph is too large for safe prototype
    computation.
    """
    n = len(nodes)

    if n > 120:
        return None

    node_list = sorted(nodes)
    local_out = {
        node: [
            target
            for target in out_edges.get(node, ())
            if target in nodes
        ]
        for node in node_list
    }

    edge_count = sum(len(targets) for targets in local_out.values())

    if edge_count > 1_000:
        return None

    sources = node_list[: min(n, 30)]
    cb = {node: 0.0 for node in node_list}

    for source in sources:
        stack: list[str] = []
        predecessors: dict[str, list[str]] = {node: [] for node in node_list}
        sigma = {node: 0.0 for node in node_list}
        distance = {node: -1 for node in node_list}

        sigma[source] = 1.0
        distance[source] = 0

        queue = [source]
        head = 0

        while head < len(queue):
            current = queue[head]
            head += 1
            stack.append(current)

            for target in local_out.get(current, ()):
                if distance[target] < 0:
                    distance[target] = distance[current] + 1
                    queue.append(target)

                if distance[target] == distance[current] + 1:
                    sigma[target] += sigma[current]
                    predecessors[target].append(current)

        delta = {node: 0.0 for node in node_list}

        for target in reversed(stack):
            for predecessor in predecessors[target]:
                if sigma[target] > 0:
                    delta[predecessor] += (
                        sigma[predecessor] / sigma[target]
                    ) * (1.0 + delta[target])

            if target != source:
                cb[target] += delta[target]

    max_cb = max(cb.values(), default=0.0)

    if max_cb <= 0:
        return None

    return _clip_float(cb.get(account_id, 0.0) / max_cb, 0.0, 1.0, 0.0)


def _entity_cluster_size(
    account_id: str,
    account_entities: Mapping[str, set[str]],
    entity_to_accounts: Mapping[str, set[str]],
    options: FeatureBuildOptions,
) -> int:
    """
    Return bounded shared-entity cluster size.
    """
    accounts = {account_id}
    entities = set(account_entities.get(account_id, ()))
    queue = list(entities)
    head = 0

    while head < len(queue) and len(accounts) < options.max_component_size:
        entity = queue[head]
        head += 1

        linked_accounts = list(entity_to_accounts.get(entity, ()))[: options.max_accounts_per_entity]

        for linked_account in linked_accounts:
            if linked_account in accounts:
                continue

            accounts.add(linked_account)

            for next_entity in account_entities.get(linked_account, ()):
                if next_entity not in entities:
                    entities.add(next_entity)
                    queue.append(next_entity)

            if len(accounts) >= options.max_component_size:
                break

    return len(accounts)


def _build_graph_metrics(
    account_id: str,
    window_30d: WindowMetrics,
    graph: GraphIndices,
    account_entities: Mapping[str, set[str]],
    entity_to_accounts: Mapping[str, set[str]],
    complaint_accounts_30d: set[str],
    options: FeatureBuildOptions,
) -> GraphMetrics:
    """
    Build bounded synthetic graph metrics for one account.
    """
    in_neighbors = set(window_30d.inbound_counterparties)
    out_neighbors = set(window_30d.outbound_counterparties)
    all_neighbors = in_neighbors | out_neighbors

    degree = len(all_neighbors)
    in_degree = len(in_neighbors)
    out_degree = len(out_neighbors)

    local_node_set = _local_nodes(
        account_id,
        graph.adj,
        options.max_graph_nodes,
    )

    page_rank = _local_pagerank(
        account_id,
        local_node_set,
        graph.out_edges,
        options,
    )

    betweenness = _local_betweenness(
        account_id,
        local_node_set,
        graph.out_edges,
    )

    cycle_indicator = any(
        neighbor in out_neighbors
        for neighbor in in_neighbors
    )

    path_count = min(
        options.max_paths,
        in_degree * out_degree,
    )

    intermediary_score = _ratio_squash(float(path_count))

    source_concentration = _clip_float(
        window_30d.inbound_hhi,
        0.0,
        1.0,
        0.0,
    )

    beneficiary_concentration = _clip_float(
        window_30d.outbound_hhi,
        0.0,
        1.0,
        0.0,
    )

    shared_cluster_size = _entity_cluster_size(
        account_id,
        account_entities,
        entity_to_accounts,
        options,
    )

    neighbor_sample = list(all_neighbors)[: options.max_counterparties]
    neighbor_complaint_count = sum(
        1
        for neighbor in neighbor_sample
        if neighbor in complaint_accounts_30d
    )
    neighbor_complaint_ratio = (
        neighbor_complaint_count / float(len(neighbor_sample))
        if neighbor_sample
        else 0.0
    )

    return GraphMetrics(
        degree_30d=degree,
        in_degree_30d=in_degree,
        out_degree_30d=out_degree,
        page_rank_norm_30d=_clip_float(page_rank, 0.0, 1.0, 0.0),
        betweenness_norm_30d=betweenness,
        cycle_indicator_30d=bool(cycle_indicator),
        path_count_30d=int(path_count),
        intermediary_score_30d=_clip_float(intermediary_score, 0.0, 1.0, 0.0),
        source_concentration_30d=source_concentration,
        beneficiary_concentration_30d=beneficiary_concentration,
        shared_entity_cluster_size_30d=int(shared_cluster_size),
        neighbor_complaint_ratio_30d=_clip_float(
            neighbor_complaint_ratio,
            0.0,
            1.0,
            0.0,
        ),
    )


# -----------------------------------------------------------------------------
# Window, balance, complaint, link, and anomaly builders
# -----------------------------------------------------------------------------


_WINDOW_SPECS: Final[tuple[tuple[str, Optional[timedelta], Optional[timedelta]], ...]] = (
    ("1h", timedelta(hours=1), None),
    ("24h", timedelta(days=1), None),
    ("7d", timedelta(days=7), None),
    ("30d", timedelta(days=30), None),
    ("90d", timedelta(days=90), None),
    ("all", None, None),
    ("prior7", timedelta(days=14), timedelta(days=7)),
)


def _build_windows(
    account_id: str,
    txns_by_account: Mapping[str, Sequence[_Txn]],
    observation_time: datetime,
    options: FeatureBuildOptions,
) -> dict[str, WindowMetrics]:
    """
    Build bounded time-window transaction metrics for one account.
    """
    account_txns = list(txns_by_account.get(account_id, ()))
    account_txns.sort(key=lambda item: (item.occurred_at, item.sender, item.receiver))

    first_seen_map: dict[str, datetime] = {}

    for txn in account_txns:
        if txn.occurred_at >= observation_time:
            continue

        counterparty = txn.receiver if txn.sender == account_id else txn.sender

        existing = first_seen_map.get(counterparty)

        if existing is None or txn.occurred_at < existing:
            first_seen_map[counterparty] = txn.occurred_at

    windows: dict[str, WindowMetrics] = {}

    for name, start_delta, end_delta in _WINDOW_SPECS:
        stats = _WindowStats(
            max_samples=options.max_feature_samples,
            max_counterparties=options.max_counterparties,
        )

        window_start = observation_time - start_delta if start_delta is not None else None
        window_end = observation_time - end_delta if end_delta is not None else None

        for txn in account_txns:
            if txn.occurred_at >= observation_time:
                continue

            if window_start is not None and txn.occurred_at < window_start:
                continue

            if window_end is not None and txn.occurred_at >= window_end:
                continue

            direction = "out" if txn.sender == account_id else "in"
            stats.add(txn, direction)

        windows[name] = stats.finalize(window_start, first_seen_map)

    return windows


def _nearest_balance_value(
    snapshots: Sequence[_Balance],
    target: datetime,
) -> Optional[Decimal]:
    """
    Return nearest balance value at or before target timestamp.
    """
    best: Optional[Decimal] = None
    best_time: Optional[datetime] = None

    for snapshot in snapshots:
        if snapshot.timestamp > target:
            continue

        if best_time is None or snapshot.timestamp > best_time:
            best_time = snapshot.timestamp
            best = snapshot.amount

    return best


def _build_balance_metrics(
    account_id: str,
    balances_by_account: Mapping[str, Sequence[_Balance]],
    observation_time: datetime,
    options: FeatureBuildOptions,
) -> BalanceMetrics:
    """
    Build bounded synthetic balance metrics for one account.
    """
    raw_snapshots = list(balances_by_account.get(account_id, ()))
    snapshots = [
        snapshot
        for snapshot in raw_snapshots
        if snapshot.timestamp < observation_time
    ]

    if not snapshots:
        return BalanceMetrics()

    currency_counts: dict[str, int] = defaultdict(int)

    for snapshot in snapshots:
        currency_counts[snapshot.currency] += 1

    primary_currency = sorted(
        currency_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )[0][0]

    filtered = [
        snapshot
        for snapshot in snapshots
        if snapshot.currency == primary_currency
    ]

    filtered.sort(key=lambda item: item.timestamp)

    start_30d = observation_time - timedelta(days=30)
    window = [
        snapshot
        for snapshot in filtered
        if snapshot.timestamp >= start_30d
    ]

    if not window:
        window = filtered[-1:]

    amounts = [snapshot.amount for snapshot in window]
    count = len(amounts)
    total = sum(amounts, _ZERO)
    mean = _quantize_money(total / Decimal(count))
    minimum = min(amounts)
    maximum = max(amounts)
    stddev = _population_stddev_float(amounts, mean)
    mean_float = _decimal_to_float(mean, 0.0)
    cv = stddev / mean_float if mean_float > 0 else 0.0

    slope = 0.0

    if count >= 2:
        base_time = window[0].timestamp
        xs = [
            (snapshot.timestamp - base_time).total_seconds() / 86_400.0
            for snapshot in window
        ]
        ys = [
            _decimal_to_float(snapshot.amount, 0.0)
            for snapshot in window
        ]

        mean_x = sum(xs) / float(count)
        mean_y = sum(ys) / float(count)

        covariance = sum(
            (x - mean_x) * (y - mean_y)
            for x, y in zip(xs, ys)
        )
        variance_x = sum((x - mean_x) ** 2 for x in xs)

        if variance_x > 0:
            slope = covariance / variance_x

        slope = _clip_float(slope, -1e12, 1e12, 0.0)

    start_7d = observation_time - timedelta(days=7)
    start_value = _nearest_balance_value(window, start_7d)
    end_value = _nearest_balance_value(window, observation_time)

    drop_ratio = 0.0

    if start_value is not None and start_value > 0 and end_value is not None:
        drop_ratio = max(
            0.0,
            _decimal_to_float(start_value - end_value, 0.0)
            / _decimal_to_float(start_value, 1.0),
        )

    return BalanceMetrics(
        snapshot_count=count,
        primary_currency=primary_currency,
        mean=mean,
        minimum=minimum,
        maximum=maximum,
        stddev=_clip_float(stddev, 0.0, None, 0.0),
        cv=_clip_float(cv, 0.0, None, 0.0),
        slope=slope,
        drop_ratio_7d=_clip_float(drop_ratio, 0.0, 1.0, 0.0),
    )


def _build_complaint_metrics(
    account_id: str,
    complaints_by_account: Mapping[str, Sequence[_Complaint]],
    known_txn_refs: set[str],
    observation_time: datetime,
    options: FeatureBuildOptions,
) -> ComplaintMetrics:
    """
    Build bounded synthetic complaint metrics for one account.

    Raw narratives are never read.
    """
    start_30d = observation_time - timedelta(days=30)

    count = 0
    linked = 0
    latest: Optional[datetime] = None

    categories: dict[str, int] = defaultdict(int)
    victims: set[str] = set()
    suspects: set[str] = set()

    for complaint in complaints_by_account.get(account_id, ()):
        if complaint.reported_at >= observation_time:
            continue

        if complaint.reported_at < start_30d:
            continue

        count += 1
        categories[complaint.category] += 1

        if complaint.victim:
            victims.add(complaint.victim)

        if complaint.suspect:
            suspects.add(complaint.suspect)

        if complaint.transaction_reference and complaint.transaction_reference in known_txn_refs:
            linked += 1

        if latest is None or complaint.reported_at > latest:
            latest = complaint.reported_at

    recency_days = None

    if latest is not None:
        delta = observation_time - latest
        recency_days = max(0, int(delta.total_seconds() // 86_400))

    rate = float(count) / 30.0
    category_entropy = _normalized_entropy(categories)
    linked_ratio = float(linked) / float(count) if count > 0 else 0.0

    return ComplaintMetrics(
        count_30d=count,
        rate_30d=_clip_float(rate, 0.0, None, 0.0),
        category_entropy=_clip_float(category_entropy, 0.0, 1.0, 0.0),
        victim_count_30d=len(victims),
        suspect_count_30d=len(suspects),
        recency_days=recency_days,
        linked_txn_ratio_30d=_clip_float(linked_ratio, 0.0, 1.0, 0.0),
    )


def _build_link_metrics(
    account_id: str,
    links_by_account: Mapping[str, Sequence[_Link]],
    entity_to_accounts: Mapping[str, set[str]],
    observation_time: datetime,
    options: FeatureBuildOptions,
) -> LinkMetrics:
    """
    Build bounded synthetic entity-link metrics for one account.
    """
    start_30d = observation_time - timedelta(days=30)

    count = 0
    heuristic_count = 0
    unverified_count = 0
    confidences: list[float] = []

    distinct_by_type: dict[str, set[str]] = defaultdict(set)
    shared_by_type: dict[str, set[str]] = defaultdict(set)

    for link in links_by_account.get(account_id, ()):
        if link.valid_from > observation_time:
            continue

        if link.valid_to is not None and link.valid_to < start_30d:
            continue

        count += 1
        distinct_by_type[link.entity_type].add(link.entity_id)

        if link.match_method == "HEURISTIC":
            heuristic_count += 1

        if link.verification_state == "UNVERIFIED":
            unverified_count += 1

        if link.confidence is not None:
            confidences.append(_decimal_to_float(link.confidence, 0.0))

        shared_accounts = shared_by_type[link.entity_type]

        for linked_account in list(entity_to_accounts.get(link.entity_id, ()))[: options.max_accounts_per_entity]:
            if len(shared_accounts) >= options.max_accounts_per_entity:
                break

            shared_accounts.add(linked_account)

    confidence_mean = (
        sum(confidences) / float(len(confidences))
        if confidences
        else None
    )

    return LinkMetrics(
        count_30d=count,
        device_distinct_count_30d=len(distinct_by_type.get("DEVICE", ())),
        ip_distinct_count_30d=len(distinct_by_type.get("IP", ())),
        phone_distinct_count_30d=len(distinct_by_type.get("PHONE", ())),
        email_distinct_count_30d=len(distinct_by_type.get("EMAIL", ())),
        upi_distinct_count_30d=len(distinct_by_type.get("UPI", ())),
        shared_device_account_count_30d=len(shared_by_type.get("DEVICE", ())),
        shared_ip_account_count_30d=len(shared_by_type.get("IP", ())),
        shared_upi_account_count_30d=len(shared_by_type.get("UPI", ())),
        heuristic_ratio_30d=_clip_float(
            float(heuristic_count) / float(count) if count > 0 else 0.0,
            0.0,
            1.0,
            0.0,
        ),
        unverified_ratio_30d=_clip_float(
            float(unverified_count) / float(count) if count > 0 else 0.0,
            0.0,
            1.0,
            0.0,
        ),
        confidence_mean_30d=(
            _clip_float(confidence_mean, 0.0, 1.0, 0.0)
            if confidence_mean is not None
            else None
        ),
    )


def _build_anomaly_metrics(
    windows: Mapping[str, WindowMetrics],
    graph: GraphMetrics,
    links: LinkMetrics,
) -> AnomalyMetrics:
    """
    Build bounded heuristic anomaly scores.

    These scores are investigative prioritization signals only. They are not
    calibrated probabilities of guilt.
    """
    w7 = windows.get("7d", _empty_window_metrics())
    w24 = windows.get("24h", _empty_window_metrics())
    w30 = windows.get("30d", _empty_window_metrics())

    amount_score = _ratio_squash(abs(w30.amount_zscore) / 3.0)

    daily_30 = float(w30.count) / 30.0 if w30.count > 0 else 0.0
    daily_7 = float(w7.count) / 7.0 if w7.count > 0 else 0.0

    if daily_30 > 0:
        velocity_raw = daily_7 / daily_30
    else:
        velocity_raw = float(w7.count)

    velocity_component = _ratio_squash(velocity_raw)
    burst_component = _ratio_squash(w24.burstiness)
    switch_component = _clip_float(
        float(w7.channel_switch_count) / float(w7.count + 1),
        0.0,
        1.0,
        0.0,
    )
    night_component = _clip_float(w30.night_ratio, 0.0, 1.0, 0.0)
    weekend_component = _clip_float(w30.weekend_ratio, 0.0, 1.0, 0.0)

    velocity_score = _clip_float(
        (
            0.35 * velocity_component
            + 0.20 * burst_component
            + 0.15 * switch_component
            + 0.20 * night_component
            + 0.10 * weekend_component
        ),
        0.0,
        1.0,
        0.0,
    )

    path_component = _ratio_squash(float(graph.path_count_30d))
    cluster_component = _ratio_squash(float(graph.shared_entity_cluster_size_30d))
    neighbor_component = _clip_float(graph.neighbor_complaint_ratio_30d, 0.0, 1.0, 0.0)
    entity_component = _clip_float(
        (links.heuristic_ratio_30d + links.unverified_ratio_30d) / 2.0,
        0.0,
        1.0,
        0.0,
    )
    cycle_component = 1.0 if graph.cycle_indicator_30d else 0.0
    betweenness_component = graph.betweenness_norm_30d or 0.0

    network_score = _clip_float(
        (
            0.20 * graph.page_rank_norm_30d
            + 0.15 * betweenness_component
            + 0.10 * cycle_component
            + 0.15 * path_component
            + 0.10 * cluster_component
            + 0.15 * neighbor_component
            + 0.15 * entity_component
        ),
        0.0,
        1.0,
        0.0,
    )

    composite_score = _clip_float(
        (
            0.40 * amount_score
            + 0.30 * velocity_score
            + 0.30 * network_score
        ),
        0.0,
        1.0,
        0.0,
    )

    return AnomalyMetrics(
        amount_score_30d=_clip_float(amount_score, 0.0, 1.0, 0.0),
        velocity_score_30d=velocity_score,
        network_score_30d=network_score,
        composite_score_30d=composite_score,
    )


# -----------------------------------------------------------------------------
# Feature dictionary assembly
# -----------------------------------------------------------------------------


def _infer_account_segment(
    account: _Account,
    windows: Mapping[str, WindowMetrics],
) -> str:
    """
    Infer a safe synthetic account segment label.
    """
    w90 = windows.get("90d", _empty_window_metrics())

    if account.status == "DORMANT" or w90.count == 0:
        return "dormant"

    if account.account_type == "MERCHANT":
        return "merchant"

    if account.account_type == "BUSINESS":
        return "business"

    if account.account_type == "INDIVIDUAL":
        return "retail"

    return "other"


def _build_feature_dict(
    account: _Account,
    windows: Mapping[str, WindowMetrics],
    balance: BalanceMetrics,
    complaints: ComplaintMetrics,
    links: LinkMetrics,
    graph: GraphMetrics,
    anomaly: AnomalyMetrics,
    observation_time: datetime,
) -> dict[str, Any]:
    """
    Assemble one raw feature dictionary for schema validation.
    """
    w1h = windows.get("1h", _empty_window_metrics())
    w24 = windows.get("24h", _empty_window_metrics())
    w7 = windows.get("7d", _empty_window_metrics())
    w30 = windows.get("30d", _empty_window_metrics())
    w90 = windows.get("90d", _empty_window_metrics())
    wall = windows.get("all", _empty_window_metrics())
    prior7 = windows.get("prior7", _empty_window_metrics())

    if account.created_at is not None and observation_time >= account.created_at:
        age_delta = observation_time - account.created_at
        age_days = max(0, int(age_delta.total_seconds() // 86_400))
    else:
        age_days = 0

    segment = _infer_account_segment(account, windows)

    daily_30 = float(w30.count) / 30.0 if w30.count > 0 else 0.0
    daily_7 = float(w7.count) / 7.0 if w7.count > 0 else 0.0

    if daily_30 > 0:
        velocity_raw = daily_7 / daily_30
    else:
        velocity_raw = float(w7.count)

    count_delta = float(w7.count - prior7.count)
    amount_delta = _decimal_to_float(w7.amount_sum - prior7.amount_sum, 0.0)

    if prior7.count > 0:
        pct_change = ((float(w7.count) - float(prior7.count)) / float(prior7.count)) * 100.0
    elif w7.count > 0:
        pct_change = 100.0
    else:
        pct_change = 0.0

    channel_shares = w30.channel_shares

    return {
        # Profile
        "account_age_days": age_days,
        "account_type_enum": account.account_type,
        "account_status_enum": account.status,
        "account_segment_enum": segment,
        "is_dormant_flag": account.status == "DORMANT" or w90.count == 0,
        # `is_wallet_flag` is retained because the catalogue declares it and a
        # feature vector must match the schema, but no account type in this
        # platform is a wallet, so it is constantly false and says so here
        # rather than silently testing a value that cannot occur.
        "is_wallet_flag": False,
        "is_business_flag": account.account_type in ("BUSINESS", "MERCHANT"),

        # Balance
        "balance_mean_30d": balance.mean,
        "balance_min_30d": balance.minimum,
        "balance_max_30d": balance.maximum,
        "balance_stddev_30d": balance.stddev,
        "balance_cv_30d": balance.cv,
        "balance_slope_30d": balance.slope,
        "balance_drop_ratio_7d": balance.drop_ratio_7d,

        # Transaction volume
        "txn_count_1h": w1h.count,
        "txn_count_24h": w24.count,
        "txn_count_7d": w7.count,
        "txn_count_30d": w30.count,
        "txn_count_90d": w90.count,
        "txn_count_all": wall.count,

        "txn_amount_sum_24h": w24.amount_sum,
        "txn_amount_sum_7d": w7.amount_sum,
        "txn_amount_sum_30d": w30.amount_sum,

        "txn_amount_mean_24h": w24.amount_mean,
        "txn_amount_mean_30d": w30.amount_mean,
        "txn_amount_median_30d": w30.amount_median,
        "txn_amount_max_24h": w24.amount_max,
        "txn_amount_max_30d": w30.amount_max,
        "txn_amount_min_30d": w30.amount_min,
        "txn_amount_stddev_30d": w30.amount_stddev,
        "txn_amount_cv_30d": w30.amount_cv,
        "txn_amount_zscore_30d": w30.amount_zscore,
        "txn_amount_anomaly_score_30d": anomaly.amount_score_30d,

        # Velocity and temporal
        "txn_count_velocity_ratio_7d_30d": _ratio_squash(velocity_raw),
        "txn_count_burstiness_24h": w24.burstiness,
        "txn_interarrival_mean_seconds_24h": w24.interarrival_mean_seconds,
        "txn_night_ratio_30d": w30.night_ratio,
        "txn_weekend_ratio_30d": w30.weekend_ratio,
        "txn_hour_entropy_30d": w30.hour_entropy,
        "txn_day_entropy_30d": w30.day_entropy,
        "txn_count_delta_7d_vs_prior_7d": count_delta,
        "txn_amount_delta_7d_vs_prior_7d": amount_delta,
        "txn_count_pct_change_7d": _clip_float(pct_change, -100.0, 1000.0, 0.0),

        # Counterparty
        "counterparty_distinct_count_30d": w30.distinct_counterparties,
        "counterparty_new_ratio_30d": w30.new_counterparty_ratio,
        "counterparty_repeat_ratio_30d": w30.repeat_counterparty_ratio,
        "counterparty_top1_share_30d": w30.top1_share,
        "counterparty_top5_share_30d": w30.top5_share,
        "counterparty_hhi_30d": w30.counterparty_hhi,
        "counterparty_entropy_30d": w30.counterparty_entropy,
        "outbound_amount_share_30d": w30.outbound_amount_share,
        "inbound_outbound_amount_ratio_30d": w30.inbound_outbound_amount_ratio,

        # Channel
        "channel_upi_share_30d": float(channel_shares.get("UPI", 0.0)),
        "channel_wallet_share_30d": float(channel_shares.get("WALLET", 0.0)),
        "channel_cash_share_30d": float(channel_shares.get("CASH", 0.0)),
        "channel_external_share_30d": float(channel_shares.get("EXTERNAL", 0.0)),
        "channel_entropy_30d": w30.channel_entropy,
        "channel_switch_count_7d": w7.channel_switch_count,

        # Entity and link
        "entity_link_count_30d": links.count_30d,
        "device_distinct_count_30d": links.device_distinct_count_30d,
        "ip_distinct_count_30d": links.ip_distinct_count_30d,
        "phone_distinct_count_30d": links.phone_distinct_count_30d,
        "email_distinct_count_30d": links.email_distinct_count_30d,
        "upi_distinct_count_30d": links.upi_distinct_count_30d,
        "shared_device_account_count_30d": links.shared_device_account_count_30d,
        "shared_ip_account_count_30d": links.shared_ip_account_count_30d,
        "shared_upi_account_count_30d": links.shared_upi_account_count_30d,
        "entity_link_heuristic_ratio_30d": links.heuristic_ratio_30d,
        "entity_link_unverified_ratio_30d": links.unverified_ratio_30d,
        "entity_link_confidence_mean_30d": links.confidence_mean_30d,

        # Complaint
        "complaint_count_30d": complaints.count_30d,
        "complaint_rate_30d": complaints.rate_30d,
        "complaint_category_entropy_30d": complaints.category_entropy,
        "complaint_victim_count_30d": complaints.victim_count_30d,
        "complaint_suspect_count_30d": complaints.suspect_count_30d,
        "complaint_recency_days": complaints.recency_days,
        "complaint_linked_txn_ratio_30d": complaints.linked_txn_ratio_30d,

        # Graph and network
        "graph_degree_30d": graph.degree_30d,
        "graph_in_degree_30d": graph.in_degree_30d,
        "graph_out_degree_30d": graph.out_degree_30d,
        "graph_page_rank_norm_30d": graph.page_rank_norm_30d,
        "graph_betweenness_norm_30d": graph.betweenness_norm_30d,
        "graph_cycle_indicator_30d": graph.cycle_indicator_30d,
        "graph_path_count_30d": graph.path_count_30d,
        "graph_intermediary_score_30d": graph.intermediary_score_30d,
        "graph_source_concentration_30d": graph.source_concentration_30d,
        "graph_beneficiary_concentration_30d": graph.beneficiary_concentration_30d,
        "graph_shared_entity_cluster_size_30d": graph.shared_entity_cluster_size_30d,
        "graph_neighbor_complaint_ratio_30d": graph.neighbor_complaint_ratio_30d,

        # Composite anomaly
        "velocity_anomaly_score_30d": anomaly.velocity_score_30d,
        "network_anomaly_score_30d": anomaly.network_score_30d,
        "composite_anomaly_score_30d": anomaly.composite_score_30d,

        # Metadata
        "observation_time": observation_time,
        "feature_snapshot_version": FEATURES_VERSION,
    }


# -----------------------------------------------------------------------------
# Builder
# -----------------------------------------------------------------------------


class FeatureBuilder:
    """
    Bounded synthetic ML feature builder.

    This builder constructs feature vectors from normalized synthetic dataset
    inputs and validates them against the canonical feature catalog.
    """

    def __init__(
        self,
        options: FeatureBuildOptions | None = None,
        catalog: FeatureCatalog | None = None,
    ) -> None:
        self.options = options or FeatureBuildOptions.from_settings()
        self.catalog = catalog or get_feature_catalog()
        self._lock = threading.RLock()

    def build(
        self,
        dataset: Any,
        account_ids: Optional[Iterable[str]] = None,
        observation_time: Optional[datetime] = None,
    ) -> FeatureBuildResult:
        """
        Build bounded feature vectors for one synthetic dataset.
        """
        opts = self.options
        obs = _ensure_utc(observation_time) or _now_utc()

        result = FeatureBuildResult(
            observation_time=obs,
            max_issues=opts.max_issues,
            max_warnings=opts.max_warnings,
        )

        if not opts.enabled:
            result.add_info(
                code="features_disabled",
                message="Feature construction is disabled.",
            )
            result.finalize(opts, self.catalog)
            return result

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            result.add_error(
                code="non_synthetic_dataset",
                message="Feature construction requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            result.finalize(opts, self.catalog)
            return result

        if opts.production_like and not opts.allow_in_production:
            result.add_error(
                code="production_like_blocked",
                message="Feature construction is blocked in production-like environments.",
            )
            result.finalize(opts, self.catalog)
            return result

        with self._lock:
            prepared = _prepare_dataset(dataset, opts, result)

            result.counts.update(
                {
                    "accounts_available": len(prepared.accounts),
                    "transactions_available": len(prepared.txns),
                    "complaints_available": len(prepared.complaints),
                    "entities_available": len(prepared.entities),
                    "links_available": len(prepared.links),
                    "balances_available": len(prepared.balances),
                }
            )

            account_index = {account.id: account for account in prepared.accounts}

            if account_ids is None:
                target_accounts = prepared.accounts[: opts.max_accounts]
            else:
                requested_ids: list[str] = []
                seen: set[str] = set()

                for raw_id in account_ids:
                    cleaned = _clean_text(raw_id, _MAX_ID_LENGTH)

                    if not cleaned or cleaned in seen:
                        continue

                    seen.add(cleaned)
                    requested_ids.append(cleaned)

                if len(requested_ids) > opts.max_accounts:
                    result.add_warning(
                        code="account_ids_truncated",
                        message="Requested account IDs exceeded configured limit.",
                        details={
                            "requested": len(requested_ids),
                            "max_accounts": opts.max_accounts,
                        },
                    )
                    requested_ids = requested_ids[: opts.max_accounts]

                target_accounts = []

                for account_id in requested_ids:
                    account = account_index.get(account_id)

                    if account is None:
                        result.add_warning(
                            code="unknown_account",
                            message="Requested account was not present in dataset.",
                            account_id=account_id,
                        )
                        continue

                    target_accounts.append(account)

            graph = _build_graph_indices(
                prepared.txns,
                obs,
                opts,
                result,
            )

            result.counts.update(
                {
                    "graph_nodes": graph.node_count,
                    "graph_edges": graph.edge_count,
                }
            )

            start_30d = obs - timedelta(days=30)
            complaint_accounts_30d: set[str] = set()

            for complaint in prepared.complaints:
                if complaint.reported_at > obs or complaint.reported_at < start_30d:
                    continue

                if complaint.victim:
                    complaint_accounts_30d.add(complaint.victim)

                if complaint.suspect:
                    complaint_accounts_30d.add(complaint.suspect)

            validation_options = FeatureValidationOptions.from_settings()

            for account in target_accounts:
                try:
                    windows = _build_windows(
                        account.id,
                        prepared.txns_by_account,
                        obs,
                        opts,
                    )

                    balance = _build_balance_metrics(
                        account.id,
                        prepared.balances_by_account,
                        obs,
                        opts,
                    )

                    complaints = _build_complaint_metrics(
                        account.id,
                        prepared.complaints_by_account,
                        prepared.known_txn_refs,
                        obs,
                        opts,
                    )

                    links = _build_link_metrics(
                        account.id,
                        prepared.links_by_account,
                        prepared.entity_to_accounts,
                        obs,
                        opts,
                    )

                    graph_metrics = _build_graph_metrics(
                        account.id,
                        windows.get("30d", _empty_window_metrics()),
                        graph,
                        prepared.account_entities,
                        prepared.entity_to_accounts,
                        complaint_accounts_30d,
                        opts,
                    )

                    anomaly = _build_anomaly_metrics(
                        windows,
                        graph_metrics,
                        links,
                    )

                    raw_features = _build_feature_dict(
                        account,
                        windows,
                        balance,
                        complaints,
                        links,
                        graph_metrics,
                        anomaly,
                        obs,
                    )

                    subject_ref_hash = _subject_hash(account.id, opts.salt)

                    vector = self.catalog.validate_vector(
                        raw_features,
                        options=validation_options,
                        subject_ref_hash=subject_ref_hash,
                        # The hash identifies the subject without
                        # naming one, which is right for an API
                        # response and useless as a foreign key. The
                        # service layer needs the real id to write one
                        # assessment row per account.
                        subject_id=account.id,
                    )

                    result.vectors.append(vector)

                    if vector.validation is not None and not vector.validation.ok:
                        result.rejected_accounts.append(account.id)
                        result.add_error(
                            code="feature_validation_failed",
                            message="Feature vector failed schema validation.",
                            account_id=account.id,
                            details={
                                "issue_count": len(vector.validation.issues),
                                "rejected_feature_count": len(
                                    vector.validation.rejected
                                ),
                            },
                        )

                except Exception as exc:
                    result.rejected_accounts.append(account.id)
                    result.add_error(
                        code="feature_build_failed",
                        message="Feature construction failed for account.",
                        account_id=account.id,
                        details={"exception_type": type(exc).__name__},
                    )
                    logger.debug(
                        "Feature build failure for account %s: %s",
                        account.id,
                        type(exc).__name__,
                        exc_info=True,
                    )

            result.counts.update(
                {
                    "accounts_requested": len(target_accounts),
                    "accounts_built": len(
                        [
                            vector
                            for vector in result.vectors
                            if vector.validation is not None and vector.validation.ok
                        ]
                    ),
                    "accounts_rejected": len(result.rejected_accounts),
                }
            )

            result.finalize(opts, self.catalog)
            return result


# -----------------------------------------------------------------------------
# Default builder and public API
# -----------------------------------------------------------------------------


_default_builder: Optional[FeatureBuilder] = None
_default_builder_lock = threading.Lock()


def get_feature_builder(
    options: FeatureBuildOptions | None = None,
    catalog: FeatureCatalog | None = None,
    *,
    rebuild: bool = False,
) -> FeatureBuilder:
    """
    Return a process-wide feature builder.

    If options or catalog are supplied, or rebuild is True, a new builder is
    constructed and becomes the default.
    """
    global _default_builder

    with _default_builder_lock:
        if _default_builder is None or rebuild or options is not None or catalog is not None:
            _default_builder = FeatureBuilder(options=options, catalog=catalog)

        return _default_builder


def build_feature_vectors(
    dataset: Any,
    account_ids: Optional[Iterable[str]] = None,
    *,
    options: FeatureBuildOptions | None = None,
    catalog: FeatureCatalog | None = None,
    observation_time: Optional[datetime] = None,
) -> FeatureBuildResult:
    """
    Build bounded synthetic ML feature vectors for a dataset.
    """
    builder = get_feature_builder(options=options, catalog=catalog)
    return builder.build(
        dataset,
        account_ids=account_ids,
        observation_time=observation_time,
    )


def build_feature_vector(
    account_id: str,
    dataset: Any,
    *,
    options: FeatureBuildOptions | None = None,
    catalog: FeatureCatalog | None = None,
    observation_time: Optional[datetime] = None,
) -> FeatureVector:
    """
    Build one bounded synthetic ML feature vector for one account.

    Returns an empty validated vector with diagnostics when construction fails.
    """
    result = build_feature_vectors(
        dataset,
        account_ids=[account_id],
        options=options,
        catalog=catalog,
        observation_time=observation_time,
    )

    if result.vectors:
        return result.vectors[0]

    validation = FeatureValidationResult(max_issues=_DEFAULT_MAX_ISSUES)
    validation.add_error(
        code="feature_vector_not_built",
        message="Feature vector could not be built.",
        details={"account_id": _clean_text(account_id, 200)},
    )
    validation.finalize()

    return FeatureVector(
        features={},
        metadata={"account_id": _clean_text(account_id, 200)},
        validation=validation,
    )


def get_features_metadata() -> dict[str, Any]:
    """
    Return safe, serializable ML feature-construction metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, feature values, or real customer data.
    """
    options = FeatureBuildOptions.from_settings()
    catalog = get_feature_catalog()
    builder = get_feature_builder()

    return {
        "package": "muleguard.backend.ml.features",
        "version": FEATURES_VERSION,
        "feature_schema_version": catalog.version,
        "catalog_fingerprint": catalog.fingerprint(),
        "feature_count": len(catalog),
        "default_options": options.safe_summary(),
        "builder_backend": "in_memory_deterministic",
        "distributed": False,
        "durable": False,
        "hard_limits": {
            "max_accounts": _HARD_MAX_ACCOUNTS,
            "max_transactions": _HARD_MAX_TRANSACTIONS,
            "max_complaints": _HARD_MAX_COMPLAINTS,
            "max_entities": _HARD_MAX_ENTITIES,
            "max_links": _HARD_MAX_LINKS,
            "max_balances": _HARD_MAX_BALANCES,
            "max_feature_samples": _HARD_MAX_FEATURE_SAMPLES,
            "max_counterparties": _HARD_MAX_COUNTERPARTIES,
            "max_paths": _HARD_MAX_PATHS,
            "max_graph_nodes": _HARD_MAX_GRAPH_NODES,
            "max_graph_edges": _HARD_MAX_GRAPH_EDGES,
            "max_component_size": _HARD_MAX_COMPONENT_SIZE,
            "max_accounts_per_entity": _HARD_MAX_ACCOUNTS_PER_ENTITY,
            "max_issues": _HARD_MAX_ISSUES,
            "max_warnings": _HARD_MAX_WARNINGS,
        },
        "caveats": list(_FEATURE_BUILD_CAVEATS),
        "safety_flags": dict(_FEATURE_SAFETY_FLAGS),
        "catalog_summary": catalog.to_dict(include_specs=False, include_groups=False),
        "builder_stats": {
            "catalog_version": builder.catalog.version,
            "options": builder.options.safe_summary(),
        },
    }


__all__ = [
    "AnomalyMetrics",
    "BalanceMetrics",
    "ComplaintMetrics",
    "FeatureBuildIssue",
    "FeatureBuildOptions",
    "FeatureBuildResult",
    "FeatureBuilder",
    "GraphIndices",
    "GraphMetrics",
    "LinkMetrics",
    "WindowMetrics",
    "build_feature_vector",
    "build_feature_vectors",
    "get_feature_builder",
    "get_features_metadata",
]