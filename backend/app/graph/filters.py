"""
MULEGUARD backend graph filters.

This module provides the canonical bounded graph-filtering layer for the
synthetic MULEGUARD investigative graph subsystem.

Primary responsibilities:

- apply bounded, deterministic filters to synthetic investigative graphs based
  on node kinds, edge kinds, degree thresholds, time windows, verification
  states, and match methods;
- preserve graph structural integrity by pruning orphaned edges when incident
  nodes are filtered out;
- preserve privacy by using salted one-way pseudonymous node references and by
  excluding raw feature values, raw identifiers, raw narratives, subject-label
  pairs, secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited graph fields;
- provide deterministic, bounded, API-safe filter results with safe graph
  summaries, issue reporting, fingerprints, and metadata;
- maintain a bounded process-local filter cache for local prototype workflows,
  tests, developer tooling, and offline evaluation harnesses;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module filters structural graph data only. It does not train models,
deploy models, persist durable artifacts, call external systems, authenticate
users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for graph construction or filtering.
- Filtered graph outputs are investigative leads only. They are not proof of
  wrongdoing, syndicates, cartels, or criminal associations.
- Shared entities, devices, IPs, phones, emails, UPI handles, or addresses are
  association patterns only. They are not proof of common control.
- Only completed transactions are treated as settled fund movement by default.
  Pending, failed, reversed, cancelled, and disputed records remain distinct.
- Currency amounts are never converted or blended across currencies. This module
  performs structural filtering, not monetary adjudication. Edge weights are
  derived from interaction counts, not monetary values.
- Labels may not be used as graph features or filter criteria.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as graph fields.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden outputs. Node linkage is pseudonymous and salted.
- Graph filtering must never trigger automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, denying, terminating,
  suspending, referring to law enforcement, or making credit, employment,
  housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable filter results are reported honestly as unavailable
  rather than invented.
- The bundled filter cache is process-local, non-durable, and bounded for local
  prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external graph databases or model runtimes.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models or graphs.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable graph store.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, cycle
candidates, community candidates, filtered graphs, explanations, validation
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
from collections import OrderedDict
import time
import unicodedata
from collections import Counter
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


logger = logging.getLogger("muleguard.backend.graph.filters")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

FILTERS_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.graph.filters.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_NODES: Final[int] = 20_000
_HARD_MAX_NODES: Final[int] = 100_000

_DEFAULT_MAX_EDGES: Final[int] = 100_000
_HARD_MAX_EDGES: Final[int] = 1_000_000

_DEFAULT_MAX_RECORDS: Final[int] = 100_000
_HARD_MAX_RECORDS: Final[int] = 1_000_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
_HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_DEFAULT_MAX_CACHE_ENTRIES: Final[int] = 128
_HARD_MAX_CACHE_ENTRIES: Final[int] = 10_000

_DEFAULT_MAX_TIME_MS: Final[int] = 30_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_DEFAULT_WINDOW_DAYS: Final[int] = 90
_HARD_MAX_WINDOW_DAYS: Final[int] = 3_650

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_NODE_HASH_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

_MISSING: Final[object] = object()

_SUBJECT_KEYS: Final[tuple[str, ...]] = (
    "subject_ref_hash",
    "subject_hash",
    "subject",
    "account_id",
    "acct_id",
    "id",
)

_SOURCE_KEYS: Final[tuple[str, ...]] = (
    "source",
    "source_hash",
    "source_account_id",
    "sender_account_id",
    "sender",
    "from_account_id",
    "from",
    "src",
)

_TARGET_KEYS: Final[tuple[str, ...]] = (
    "target",
    "target_hash",
    "target_account_id",
    "receiver_account_id",
    "receiver",
    "to_account_id",
    "to",
    "dst",
)

_TIMESTAMP_KEYS: Final[tuple[str, ...]] = (
    "occurred_at",
    "timestamp",
    "valid_from",
    "reported_at",
    "created_at",
    "time",
    "date",
)

_FORBIDDEN_GRAPH_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_GRAPH_TOKENS: Final[tuple[str, ...]] = (
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

_COMPLETED_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "COMPLETED",
        "SETTLED",
        "SUCCESS",
    }
)

_VERIFIED_STATES: Final[frozenset[str]] = frozenset(
    {
        "VERIFIED",
        "CONFIRMED",
    }
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

_FILTER_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic graph filtering only. Do not use with real customer data.",
    "Filtered graph outputs are investigative leads only and are not proof of wrongdoing.",
    "Shared entities, devices, IPs, phones, emails, UPI handles, or addresses are association patterns only.",
    "Only completed transactions are treated as settled fund movement by default.",
    "Currency amounts are never converted or blended across currencies. Edge weights are structural.",
    "Labels must never be used as graph features or filter criteria.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Graph filtering must not trigger automatic adverse customer action.",
    "The bundled filter cache is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_FILTER_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_labels_as_graph_features": True,
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
        "salted_pseudonymous_node_references": True,
        "deterministic_graph_filtering": True,
        "bounded_graph_filtering_required": True,
        "only_completed_transactions_settled_by_default": True,
        "no_cross_currency_blending": True,
        "edge_weights_are_structural_not_monetary": True,
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


class FilterOp(str, Enum):
    """
    Bounded filter operation.
    """

    INCLUDE = "include"
    EXCLUDE = "exclude"
    MIN = "min"
    MAX = "max"
    BETWEEN = "between"
    EQUALS = "equals"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class AnalysisStatus(str, Enum):
    """
    Overall filter-analysis status.
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

    if canonical in _FORBIDDEN_GRAPH_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_GRAPH_TOKENS)


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


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FilterIssue:
    """
    Safe filter issue.

    Issues never contain raw node identifiers, raw narratives, raw labels,
    secrets, tokens, passwords, database URLs, filesystem paths, or model
    artifact paths.
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
            _normalize_enum(IssueSeverity, self.severity, IssueSeverity.WARNING),
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
    issues: list[FilterIssue],
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

        issues[-1] = FilterIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        FilterIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[FilterIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[FilterIssue]) -> tuple[FilterIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[FilterIssue] = []

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
# Filter criteria models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NodeFilterCriteria:
    """
    Bounded node filter criteria.
    """

    include_kinds: tuple[str, ...] = ()
    exclude_kinds: tuple[str, ...] = ()
    min_degree: Optional[int] = None
    max_degree: Optional[int] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "include_kinds",
            tuple(dict.fromkeys(_upper_token(k) for k in _as_sequence(self.include_kinds) if _upper_token(k))),
        )
        object.__setattr__(
            self,
            "exclude_kinds",
            tuple(dict.fromkeys(_upper_token(k) for k in _as_sequence(self.exclude_kinds) if _upper_token(k))),
        )

        if self.min_degree is not None:
            object.__setattr__(self, "min_degree", max(0, _as_int(self.min_degree, 0)))

        if self.max_degree is not None:
            object.__setattr__(self, "max_degree", max(0, _as_int(self.max_degree, 0)))

        object.__setattr__(self, "created_after", _ensure_utc(_parse_datetime(self.created_after)))
        object.__setattr__(self, "created_before", _ensure_utc(_parse_datetime(self.created_before)))


@dataclass(frozen=True, slots=True)
class EdgeFilterCriteria:
    """
    Bounded edge filter criteria.
    """

    include_kinds: tuple[str, ...] = ()
    exclude_kinds: tuple[str, ...] = ()
    min_weight: Optional[float] = None
    max_weight: Optional[float] = None
    occurred_after: Optional[datetime] = None
    occurred_before: Optional[datetime] = None
    include_verification_states: tuple[str, ...] = ()
    exclude_verification_states: tuple[str, ...] = ()
    include_match_methods: tuple[str, ...] = ()
    exclude_match_methods: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "include_kinds",
            tuple(dict.fromkeys(_upper_token(k) for k in _as_sequence(self.include_kinds) if _upper_token(k))),
        )
        object.__setattr__(
            self,
            "exclude_kinds",
            tuple(dict.fromkeys(_upper_token(k) for k in _as_sequence(self.exclude_kinds) if _upper_token(k))),
        )

        if self.min_weight is not None:
            object.__setattr__(self, "min_weight", _round6(max(0.0, _coerce_float(self.min_weight, allow_bool=True) or 0.0)))

        if self.max_weight is not None:
            object.__setattr__(self, "max_weight", _round6(max(0.0, _coerce_float(self.max_weight, allow_bool=True) or 0.0)))

        object.__setattr__(self, "occurred_after", _ensure_utc(_parse_datetime(self.occurred_after)))
        object.__setattr__(self, "occurred_before", _ensure_utc(_parse_datetime(self.occurred_before)))

        object.__setattr__(
            self,
            "include_verification_states",
            tuple(dict.fromkeys(_upper_token(s) for s in _as_sequence(self.include_verification_states) if _upper_token(s))),
        )
        object.__setattr__(
            self,
            "exclude_verification_states",
            tuple(dict.fromkeys(_upper_token(s) for s in _as_sequence(self.exclude_verification_states) if _upper_token(s))),
        )
        object.__setattr__(
            self,
            "include_match_methods",
            tuple(dict.fromkeys(_upper_token(m) for m in _as_sequence(self.include_match_methods) if _upper_token(m))),
        )
        object.__setattr__(
            self,
            "exclude_match_methods",
            tuple(dict.fromkeys(_upper_token(m) for m in _as_sequence(self.exclude_match_methods) if _upper_token(m))),
        )


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FilterOptions:
    """
    Bounded graph-filter policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    max_nodes: int = _DEFAULT_MAX_NODES
    max_edges: int = _DEFAULT_MAX_EDGES
    max_records: int = _DEFAULT_MAX_RECORDS
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_cache_entries: int = _DEFAULT_MAX_CACHE_ENTRIES
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    window_days: int = _DEFAULT_WINDOW_DAYS
    max_window_days: int = _HARD_MAX_WINDOW_DAYS

    include_non_completed_transactions: bool = False
    include_unverified_links: bool = True
    require_completed_transactions: bool = True
    prune_orphan_edges: bool = True

    use_cache: bool = True
    register_results: bool = True
    drop_forbidden_fields: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_token(self.dataset_mode) or "synthetic")
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(self, "salt", _ensure_salt(self.salt))
        object.__setattr__(self, "namespace", _normalize_token(self.namespace) or _DEFAULT_NAMESPACE)
        object.__setattr__(self, "seed", int(self.seed))

        object.__setattr__(self, "max_nodes", _clamp_int(self.max_nodes, 2, _HARD_MAX_NODES, _DEFAULT_MAX_NODES))
        object.__setattr__(self, "max_edges", _clamp_int(self.max_edges, 1, _HARD_MAX_EDGES, _DEFAULT_MAX_EDGES))
        object.__setattr__(self, "max_records", _clamp_int(self.max_records, 1, _HARD_MAX_RECORDS, _DEFAULT_MAX_RECORDS))
        object.__setattr__(self, "max_issues", _clamp_int(self.max_issues, 1, _HARD_MAX_ISSUES, _DEFAULT_MAX_ISSUES))
        object.__setattr__(self, "max_summary_items", _clamp_int(self.max_summary_items, 1, _HARD_MAX_SUMMARY_ITEMS, _DEFAULT_MAX_SUMMARY_ITEMS))
        object.__setattr__(self, "max_cache_entries", _clamp_int(self.max_cache_entries, 1, _HARD_MAX_CACHE_ENTRIES, _DEFAULT_MAX_CACHE_ENTRIES))
        object.__setattr__(self, "max_time_ms", _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS))

        object.__setattr__(self, "window_days", _clamp_int(self.window_days, 1, _HARD_MAX_WINDOW_DAYS, _DEFAULT_WINDOW_DAYS))
        object.__setattr__(self, "max_window_days", _clamp_int(self.max_window_days, 1, _HARD_MAX_WINDOW_DAYS, _HARD_MAX_WINDOW_DAYS))

        object.__setattr__(self, "include_non_completed_transactions", _as_bool(self.include_non_completed_transactions, False))
        object.__setattr__(self, "include_unverified_links", _as_bool(self.include_unverified_links, True))
        object.__setattr__(self, "require_completed_transactions", _as_bool(self.require_completed_transactions, True))
        object.__setattr__(self, "prune_orphan_edges", _as_bool(self.prune_orphan_edges, True))

        object.__setattr__(self, "use_cache", _as_bool(self.use_cache, True))
        object.__setattr__(self, "register_results", _as_bool(self.register_results, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "FilterOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "GRAPH_FILTER_SALT", None)
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
            enabled=_as_bool(_setting(settings, "GRAPH_FILTER_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(_setting(settings, "GRAPH_FILTER_REQUIRE_SYNTHETIC", True), True),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(_setting(settings, "GRAPH_FILTER_ALLOW_IN_PRODUCTION", False), False),
            salt=salt,
            namespace=str(_setting(settings, "GRAPH_FILTER_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "GRAPH_FILTER_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_nodes=_as_int(_setting(settings, "GRAPH_FILTER_MAX_NODES", _DEFAULT_MAX_NODES), _DEFAULT_MAX_NODES),
            max_edges=_as_int(_setting(settings, "GRAPH_FILTER_MAX_EDGES", _DEFAULT_MAX_EDGES), _DEFAULT_MAX_EDGES),
            max_records=_as_int(_setting(settings, "GRAPH_FILTER_MAX_RECORDS", _DEFAULT_MAX_RECORDS), _DEFAULT_MAX_RECORDS),
            max_issues=_as_int(_setting(settings, "GRAPH_FILTER_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(_setting(settings, "GRAPH_FILTER_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS), _DEFAULT_MAX_SUMMARY_ITEMS),
            max_cache_entries=_as_int(_setting(settings, "GRAPH_FILTER_MAX_CACHE_ENTRIES", _DEFAULT_MAX_CACHE_ENTRIES), _DEFAULT_MAX_CACHE_ENTRIES),
            max_time_ms=_as_int(_setting(settings, "GRAPH_FILTER_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS), _DEFAULT_MAX_TIME_MS),
            window_days=_as_int(_setting(settings, "GRAPH_FILTER_WINDOW_DAYS", _DEFAULT_WINDOW_DAYS), _DEFAULT_WINDOW_DAYS),
            max_window_days=_as_int(_setting(settings, "GRAPH_FILTER_MAX_WINDOW_DAYS", _HARD_MAX_WINDOW_DAYS), _HARD_MAX_WINDOW_DAYS),
            include_non_completed_transactions=_as_bool(_setting(settings, "GRAPH_FILTER_INCLUDE_NON_COMPLETED", False), False),
            include_unverified_links=_as_bool(_setting(settings, "GRAPH_FILTER_INCLUDE_UNVERIFIED_LINKS", True), True),
            require_completed_transactions=_as_bool(_setting(settings, "GRAPH_FILTER_REQUIRE_COMPLETED", True), True),
            prune_orphan_edges=_as_bool(_setting(settings, "GRAPH_FILTER_PRUNE_ORPHAN_EDGES", True), True),
            use_cache=_as_bool(_setting(settings, "GRAPH_FILTER_USE_CACHE", True), True),
            register_results=_as_bool(_setting(settings, "GRAPH_FILTER_REGISTER_RESULTS", True), True),
            drop_forbidden_fields=_as_bool(_setting(settings, "GRAPH_FILTER_DROP_FORBIDDEN_FIELDS", False), False),
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
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
                "max_records": self.max_records,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_cache_entries": self.max_cache_entries,
                "max_time_ms": self.max_time_ms,
                "window_days": self.window_days,
                "max_window_days": self.max_window_days,
            },
            "flags": {
                "include_non_completed_transactions": self.include_non_completed_transactions,
                "include_unverified_links": self.include_unverified_links,
                "require_completed_transactions": self.require_completed_transactions,
                "prune_orphan_edges": self.prune_orphan_edges,
                "use_cache": self.use_cache,
                "register_results": self.register_results,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "accounts",
        "transactions",
        "entities",
        "entity_links",
        "nodes",
        "edges",
        "observations",
        "observation_time",
        "window_start",
        "window_end",
        "node_filter",
        "edge_filter",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class GraphFilterRequest:
    """
    Bounded graph-filter request.
    """

    accounts: Any = None
    transactions: Any = None
    entities: Any = None
    entity_links: Any = None
    nodes: Any = None
    edges: Any = None
    observations: Any = None
    observation_time: Optional[datetime] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    node_filter: Any = None
    edge_filter: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.observation_time = _ensure_utc(_parse_datetime(self.observation_time))
        self.window_start = _ensure_utc(_parse_datetime(self.window_start))
        self.window_end = _ensure_utc(_parse_datetime(self.window_end))
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None

        if self.node_filter is not None and not isinstance(self.node_filter, NodeFilterCriteria):
            if isinstance(self.node_filter, Mapping):
                try:
                    self.node_filter = NodeFilterCriteria(**self.node_filter)
                except Exception:
                    self.node_filter = NodeFilterCriteria()
            else:
                self.node_filter = NodeFilterCriteria()

        if self.edge_filter is not None and not isinstance(self.edge_filter, EdgeFilterCriteria):
            if isinstance(self.edge_filter, Mapping):
                try:
                    self.edge_filter = EdgeFilterCriteria(**self.edge_filter)
                except Exception:
                    self.edge_filter = EdgeFilterCriteria()
            else:
                self.edge_filter = EdgeFilterCriteria()


def _coerce_request(request: Any) -> GraphFilterRequest:
    if isinstance(request, GraphFilterRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if "edges" not in payload and "observations" in payload:
            payload["edges"] = payload["observations"]

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(GraphFilterRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return GraphFilterRequest(**clean)
            except Exception:
                return GraphFilterRequest(edges=payload.get("edges", request))

        return GraphFilterRequest(edges=request)

    if isinstance(request, (list, tuple, set, frozenset)):
        return GraphFilterRequest(edges=request)

    return GraphFilterRequest(edges=request)


# -----------------------------------------------------------------------------
# Internal graph models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _Node:
    node_hash: str
    kind: NodeKind
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    degree: int = 0


@dataclass(frozen=True, slots=True)
class _Edge:
    source: str
    target: str
    kind: EdgeKind
    weight: float
    timestamp: Optional[datetime]
    verification_state: str
    match_method: str
    edge_hash: str


@dataclass(slots=True)
class _Graph:
    nodes: dict[str, _Node] = dataclass_field(default_factory=dict)
    edges: list[_Edge] = dataclass_field(default_factory=list)
    node_kinds: dict[str, NodeKind] = dataclass_field(default_factory=dict)
    undirected_neighbors: dict[str, dict[str, float]] = dataclass_field(default_factory=dict)
    degrees: dict[str, int] = dataclass_field(default_factory=dict)
    total_edge_weight: float = 0.0
    fingerprint: str = ""
    counts: dict[str, int] = dataclass_field(default_factory=dict)
    truncated: dict[str, bool] = dataclass_field(default_factory=dict)


# -----------------------------------------------------------------------------
# Graph construction
# -----------------------------------------------------------------------------


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, FilterResult):
        return []

    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "edges", "transactions", "entity_links", "accounts", "entities"):
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


def _sanitize_record(
    record: Any,
    options: FilterOptions,
    issues: list[FilterIssue],
    index: int,
) -> Optional[dict[str, Any]]:
    if not isinstance(record, Mapping):
        numeric = _coerce_float(record, allow_bool=False)

        if numeric is not None:
            return {"score": numeric, "index": index}

        return None

    out: dict[str, Any] = {}

    for raw_key, raw_value in record.items():
        key = _canonical_field_name(raw_key)

        if not key:
            continue

        if _is_forbidden_key(key) or _is_label_leakage_key(key):
            if options.drop_forbidden_fields:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="forbidden_graph_field_dropped",
                    message="Forbidden or leakage-prone graph field omitted.",
                    field=key,
                    details={"index": index},
                )
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_graph_field",
                message="Forbidden or leakage-prone graph field rejected.",
                field=key,
                details={"index": index},
            )
            return None

        if key in _NON_FEATURE_KEYS:
            continue

        out[key] = raw_value

    return out


def _pick(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]

    return None


def _node_hash_for(raw: Any, kind: NodeKind, options: FilterOptions) -> Optional[str]:
    text = _clean_text(raw, 256)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    domain = f"muleguard.graph.filters.node.{kind.value}.{_normalize_token(options.namespace)}"
    return _hmac_hex(options.salt, domain, text)[:40]


def _resolve_node(
    raw: Any,
    kind: NodeKind,
    account_map: Mapping[str, str],
    entity_map: Mapping[str, str],
    options: FilterOptions,
) -> Optional[str]:
    text = _clean_text(raw, 256)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    if kind == NodeKind.ACCOUNT and text in account_map:
        return account_map[text]

    if kind == NodeKind.ENTITY and text in entity_map:
        return entity_map[text]

    if text in account_map:
        return account_map[text]

    if text in entity_map:
        return entity_map[text]

    return _node_hash_for(text, kind, options)


def _ensure_node(
    graph: _Graph,
    node_hash: str,
    kind: NodeKind,
    timestamp: Optional[datetime],
    options: FilterOptions,
    issues: list[FilterIssue],
) -> bool:
    if node_hash in graph.nodes:
        existing = graph.nodes[node_hash]

        if existing.kind != kind and existing.kind != NodeKind.UNKNOWN and kind != NodeKind.UNKNOWN:
            existing.kind = NodeKind.UNKNOWN
            graph.node_kinds[node_hash] = NodeKind.UNKNOWN
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="conflicting_node_kind",
                message="Node reference appeared with conflicting kinds and was marked unknown.",
            )

        if timestamp is not None:
            if existing.first_seen is None or timestamp < existing.first_seen:
                existing.first_seen = timestamp

            if existing.last_seen is None or timestamp > existing.last_seen:
                existing.last_seen = timestamp

        return True

    if len(graph.nodes) >= options.max_nodes:
        graph.truncated["nodes"] = True
        return False

    graph.nodes[node_hash] = _Node(node_hash=node_hash, kind=kind, first_seen=timestamp, last_seen=timestamp)
    graph.node_kinds[node_hash] = kind
    return True


def _edge_hash(
    source: str,
    target: str,
    kind: EdgeKind,
    timestamp: Optional[datetime],
    verification_state: str,
    match_method: str,
    options: FilterOptions,
) -> str:
    bucket = timestamp.isoformat() if timestamp is not None else "unknown"

    payload = {
        "source": source,
        "target": target,
        "kind": kind.value,
        "timestamp": bucket,
        "verification": verification_state,
        "method": match_method,
    }

    domain = f"muleguard.graph.filters.edge.{_normalize_token(options.namespace)}"
    return _hmac_hex(options.salt, domain, _canonical_json(payload))[:40]


def _add_edge(
    graph: _Graph,
    source: str,
    target: str,
    kind: EdgeKind,
    timestamp: Optional[datetime],
    verification_state: str,
    match_method: str,
    options: FilterOptions,
    issues: list[FilterIssue],
) -> None:
    if not source or not target or source == target:
        return

    if len(graph.edges) >= options.max_edges:
        graph.truncated["edges"] = True
        return

    if not _ensure_node(graph, source, NodeKind.ACCOUNT if kind == EdgeKind.TRANSACTION else NodeKind.UNKNOWN, timestamp, options, issues):
        graph.truncated["nodes"] = True
        return

    if not _ensure_node(graph, target, NodeKind.ACCOUNT if kind == EdgeKind.TRANSACTION else NodeKind.UNKNOWN, timestamp, options, issues):
        graph.truncated["nodes"] = True
        return

    # Canonical undirected ordering
    if source > target:
        source, target = target, source

    edge = _Edge(
        source=source,
        target=target,
        kind=kind,
        weight=1.0,
        timestamp=timestamp,
        verification_state=verification_state,
        match_method=match_method,
        edge_hash=_edge_hash(source, target, kind, timestamp, verification_state, match_method, options),
    )

    graph.edges.append(edge)


def _within_window(
    timestamp: Optional[datetime],
    valid_to: Optional[datetime],
    window_start: datetime,
    window_end: datetime,
) -> bool:
    if valid_to is not None and valid_to < window_start:
        return False

    if timestamp is not None:
        if timestamp > window_end:
            return False

        if timestamp < window_start:
            return False

    return True


def _build_graph(
    request: GraphFilterRequest,
    options: FilterOptions,
    issues: list[FilterIssue],
    start_time: float,
) -> _Graph:
    graph = _Graph()

    observation = request.observation_time or _now_utc()
    window_end = request.window_end or observation
    window_start = request.window_start or (window_end - timedelta(days=int(options.window_days)))

    if window_end < window_start:
        window_start, window_end = window_end, window_start

    max_span = timedelta(days=int(options.max_window_days))

    if window_end - window_start > max_span:
        window_start = window_end - max_span
        graph.truncated["window"] = True

    account_map: dict[str, str] = {}
    entity_map: dict[str, str] = {}

    def collect_nodes(raw_records: Any, kind: NodeKind, target_map: dict[str, str]) -> None:
        for index, raw in enumerate(_iter_records(raw_records)[: options.max_records]):
            if _time_exceeded(start_time, options.max_time_ms):
                graph.truncated["records"] = True
                break

            record = _sanitize_record(raw, options, issues, index)

            if record is None:
                continue

            identifier = _pick(record, ("id", "account_id", "entity_id", "subject_ref_hash", "subject_hash"))
            text = _clean_text(identifier, 256)

            if not text:
                continue

            node_hash = _resolve_node(text, kind, account_map, entity_map, options)

            if not node_hash:
                continue

            timestamp = _parse_datetime(_pick(record, _TIMESTAMP_KEYS))
            _ensure_node(graph, node_hash, kind, timestamp, options, issues)
            target_map[text] = node_hash

    collect_nodes(request.accounts, NodeKind.ACCOUNT, account_map)
    collect_nodes(request.entities, NodeKind.ENTITY, entity_map)
    collect_nodes(request.nodes, NodeKind.UNKNOWN, {})

    # Transactions -> undirected structural edges (weight = interaction count).
    edge_weights: dict[tuple[str, str], float] = {}

    for index, raw in enumerate(_iter_records(request.transactions)[: options.max_records]):
        if _time_exceeded(start_time, options.max_time_ms):
            graph.truncated["records"] = True
            break

        record = _sanitize_record(raw, options, issues, index)

        if record is None:
            continue

        status = _upper_token(_pick(record, ("status", "transaction_status")))

        if options.require_completed_transactions and not options.include_non_completed_transactions:
            if status and status not in _COMPLETED_STATUSES:
                continue

        timestamp = _parse_datetime(_pick(record, _TIMESTAMP_KEYS))

        if not _within_window(timestamp, None, window_start, window_end):
            continue

        sender_raw = _pick(record, _SOURCE_KEYS)
        receiver_raw = _pick(record, _TARGET_KEYS)

        sender = _resolve_node(sender_raw, NodeKind.ACCOUNT, account_map, entity_map, options)
        receiver = _resolve_node(receiver_raw, NodeKind.ACCOUNT, account_map, entity_map, options)

        if not sender or not receiver or sender == receiver:
            continue

        pair = tuple(sorted((sender, receiver)))
        edge_weights[pair] = edge_weights.get(pair, 0.0) + 1.0

        _add_edge(
            graph,
            sender,
            receiver,
            EdgeKind.TRANSACTION,
            timestamp,
            "VERIFIED" if status in _COMPLETED_STATUSES else "UNVERIFIED",
            "EXACT",
            options,
            issues,
        )

    # Entity links -> undirected bipartite association edges.
    for index, raw in enumerate(_iter_records(request.entity_links)[: options.max_records]):
        if _time_exceeded(start_time, options.max_time_ms):
            graph.truncated["records"] = True
            break

        record = _sanitize_record(raw, options, issues, index)

        if record is None:
            continue

        verification = _upper_token(_pick(record, ("verification_state", "verification"))) or "UNVERIFIED"
        match_method = _upper_token(_pick(record, ("match_method", "method"))) or "HEURISTIC"

        if verification not in _VERIFIED_STATES and not options.include_unverified_links:
            continue

        timestamp = _parse_datetime(_pick(record, ("valid_from", "first_seen_at", "occurred_at", "created_at")))
        valid_to = _parse_datetime(_pick(record, ("valid_to", "last_seen_at")))

        if not _within_window(timestamp, valid_to, window_start, window_end):
            continue

        account_raw = _pick(record, ("account_id", "account", "source_account_id"))
        entity_raw = _pick(record, ("entity_id", "entity", "target_entity_id"))

        account_hash = _resolve_node(account_raw, NodeKind.ACCOUNT, account_map, entity_map, options)
        entity_hash = _resolve_node(entity_raw, NodeKind.ENTITY, account_map, entity_map, options)

        if not account_hash or not entity_hash or account_hash == entity_hash:
            continue

        _ensure_node(graph, account_hash, NodeKind.ACCOUNT, timestamp, options, issues)
        _ensure_node(graph, entity_hash, NodeKind.ENTITY, timestamp, options, issues)

        pair = tuple(sorted((account_hash, entity_hash)))
        edge_weights[pair] = edge_weights.get(pair, 0.0) + 1.0

        _add_edge(
            graph,
            account_hash,
            entity_hash,
            EdgeKind.ENTITY_LINK,
            timestamp,
            verification,
            match_method,
            options,
            issues,
        )

    # Explicit edges.
    for index, raw in enumerate(_iter_records(request.edges)[: options.max_records]):
        if _time_exceeded(start_time, options.max_time_ms):
            graph.truncated["records"] = True
            break

        record = _sanitize_record(raw, options, issues, index)

        if record is None:
            continue

        source_raw = _pick(record, _SOURCE_KEYS)
        target_raw = _pick(record, _TARGET_KEYS)

        if source_raw is None or target_raw is None:
            continue

        edge_kind = _normalize_enum(EdgeKind, _pick(record, ("edge_kind", "edge_type", "kind")), EdgeKind.EXPLICIT)

        timestamp = _parse_datetime(_pick(record, _TIMESTAMP_KEYS))
        valid_to = _parse_datetime(_pick(record, ("valid_to",)))

        if not _within_window(timestamp, valid_to, window_start, window_end):
            continue

        source = _resolve_node(source_raw, NodeKind.UNKNOWN, account_map, entity_map, options)
        target = _resolve_node(target_raw, NodeKind.UNKNOWN, account_map, entity_map, options)

        if not source or not target or source == target:
            continue

        verification = _upper_token(_pick(record, ("verification_state", "verification"))) or "UNVERIFIED"
        match_method = _upper_token(_pick(record, ("match_method", "method"))) or "EXACT"

        pair = tuple(sorted((source, target)))
        edge_weights[pair] = edge_weights.get(pair, 0.0) + 1.0

        _add_edge(
            graph,
            source,
            target,
            edge_kind,
            timestamp,
            verification,
            match_method,
            options,
            issues,
        )

    # Deduplicate edges and apply structural weights.
    graph.edges.sort(key=lambda edge: edge.edge_hash)
    deduped: list[_Edge] = []
    seen_edges: set[str] = set()

    for edge in graph.edges:
        if edge.edge_hash in seen_edges:
            continue

        seen_edges.add(edge.edge_hash)
        pair = tuple(sorted((edge.source, edge.target)))
        weight = edge_weights.get(pair, 1.0)
        deduped.append(replace(edge, weight=weight))

    graph.edges = deduped[: options.max_edges]

    if len(deduped) > options.max_edges:
        graph.truncated["edges"] = True

    # Finalize node kinds from incident edges.
    for edge in graph.edges:
        if edge.kind == EdgeKind.TRANSACTION:
            for node_hash in (edge.source, edge.target):
                current = graph.node_kinds.get(node_hash, NodeKind.UNKNOWN)

                if current == NodeKind.UNKNOWN:
                    graph.node_kinds[node_hash] = NodeKind.ACCOUNT
                    if node_hash in graph.nodes:
                        graph.nodes[node_hash].kind = NodeKind.ACCOUNT

    # Build undirected adjacency and degrees.
    for node_hash in sorted(graph.nodes):
        graph.undirected_neighbors[node_hash] = {}
        graph.degrees[node_hash] = 0

    total_weight = 0.0

    for edge in graph.edges:
        graph.undirected_neighbors[edge.source][edge.target] = graph.undirected_neighbors[edge.source].get(edge.target, 0.0) + edge.weight
        graph.undirected_neighbors[edge.target][edge.source] = graph.undirected_neighbors[edge.target].get(edge.source, 0.0) + edge.weight
        graph.degrees[edge.source] += 1
        graph.degrees[edge.target] += 1
        total_weight += edge.weight

    graph.total_edge_weight = total_weight

    for node_hash in list(graph.undirected_neighbors):
        graph.undirected_neighbors[node_hash] = dict(sorted(graph.undirected_neighbors[node_hash].items()))

    graph.counts = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "transaction_edges": sum(1 for edge in graph.edges if edge.kind == EdgeKind.TRANSACTION),
        "entity_link_edges": sum(1 for edge in graph.edges if edge.kind == EdgeKind.ENTITY_LINK),
    }

    # Streaming deterministic graph fingerprint.
    digest = hashlib.sha256()
    digest.update(f"muleguard.graph.filters.{FILTERS_VERSION}|{len(graph.nodes)}|{len(graph.edges)}\n".encode("utf-8", errors="replace"))

    for edge in graph.edges:
        digest.update(f"{edge.edge_hash}|{edge.kind.value}|{_round6(edge.weight)}\n".encode("utf-8", errors="replace"))

    graph.fingerprint = digest.hexdigest()

    return graph


# -----------------------------------------------------------------------------
# Filter application
# -----------------------------------------------------------------------------


def _apply_node_filters(
    graph: _Graph,
    criteria: Optional[NodeFilterCriteria],
    options: FilterOptions,
) -> set[str]:
    """
    Apply node filters and return the set of retained node hashes.
    """
    if criteria is None:
        return set(graph.nodes.keys())

    retained: set[str] = set()

    for node_hash, node in graph.nodes.items():
        if criteria.include_kinds and _enum_value(node.kind, NodeKind.UNKNOWN.value).upper() not in criteria.include_kinds:
            continue

        if criteria.exclude_kinds and _enum_value(node.kind, NodeKind.UNKNOWN.value).upper() in criteria.exclude_kinds:
            continue

        degree = graph.degrees.get(node_hash, 0)

        if criteria.min_degree is not None and degree < criteria.min_degree:
            continue

        if criteria.max_degree is not None and degree > criteria.max_degree:
            continue

        if criteria.created_after is not None and (node.first_seen is None or node.first_seen < criteria.created_after):
            continue

        if criteria.created_before is not None and (node.first_seen is None or node.first_seen > criteria.created_before):
            continue

        retained.add(node_hash)

    return retained


def _apply_edge_filters(
    graph: _Graph,
    criteria: Optional[EdgeFilterCriteria],
    options: FilterOptions,
) -> set[str]:
    """
    Apply edge filters and return the set of retained edge hashes.
    """
    if criteria is None:
        return {edge.edge_hash for edge in graph.edges}

    retained: set[str] = set()

    for edge in graph.edges:
        if criteria.include_kinds and _enum_value(edge.kind, EdgeKind.OTHER.value).upper() not in criteria.include_kinds:
            continue

        if criteria.exclude_kinds and _enum_value(edge.kind, EdgeKind.OTHER.value).upper() in criteria.exclude_kinds:
            continue

        if criteria.min_weight is not None and edge.weight < criteria.min_weight:
            continue

        if criteria.max_weight is not None and edge.weight > criteria.max_weight:
            continue

        if criteria.occurred_after is not None and (edge.timestamp is None or edge.timestamp < criteria.occurred_after):
            continue

        if criteria.occurred_before is not None and (edge.timestamp is None or edge.timestamp > criteria.occurred_before):
            continue

        if criteria.include_verification_states and edge.verification_state.upper() not in criteria.include_verification_states:
            continue

        if criteria.exclude_verification_states and edge.verification_state.upper() in criteria.exclude_verification_states:
            continue

        if criteria.include_match_methods and edge.match_method.upper() not in criteria.include_match_methods:
            continue

        if criteria.exclude_match_methods and edge.match_method.upper() in criteria.exclude_match_methods:
            continue

        retained.add(edge.edge_hash)

    return retained


def _prune_orphan_edges(
    graph: _Graph,
    retained_nodes: set[str],
    retained_edges: set[str],
) -> tuple[set[str], set[str]]:
    """
    Remove edges where either source or target node was filtered out.
    """
    final_edges: set[str] = set()

    for edge_hash in retained_edges:
        for edge in graph.edges:
            if edge.edge_hash == edge_hash:
                if edge.source in retained_nodes and edge.target in retained_nodes:
                    final_edges.add(edge_hash)
                break

    final_nodes: set[str] = set()

    for node_hash in retained_nodes:
        # Keep node if it has at least one retained edge, or if no edges were retained at all
        has_edge = any(
            edge.source == node_hash or edge.target == node_hash
            for edge in graph.edges
            if edge.edge_hash in final_edges
        )
        
        if has_edge or not final_edges:
            final_nodes.add(node_hash)

    return final_nodes, final_edges


def _compute_filtered_metrics(
    graph: _Graph,
    retained_nodes: set[str],
    retained_edges: set[str],
) -> dict[str, Any]:
    """
    Compute bounded structural metrics for the filtered graph.
    """
    filtered_edges = [edge for edge in graph.edges if edge.edge_hash in retained_edges]
    
    total_weight = sum(edge.weight for edge in filtered_edges)
    
    kind_counts = Counter(edge.kind.value for edge in filtered_edges)
    
    return {
        "node_count": len(retained_nodes),
        "edge_count": len(retained_edges),
        "total_edge_weight": _round6(total_weight),
        "transaction_edge_count": kind_counts.get(EdgeKind.TRANSACTION.value, 0),
        "entity_link_edge_count": kind_counts.get(EdgeKind.ENTITY_LINK.value, 0),
        "explicit_edge_count": kind_counts.get(EdgeKind.EXPLICIT.value, 0),
        "other_edge_count": kind_counts.get(EdgeKind.OTHER.value, 0),
    }


# -----------------------------------------------------------------------------
# Public filter models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FilteredGraphSummary:
    """
    Safe bounded filtered graph summary.
    """

    node_count: int = 0
    edge_count: int = 0
    transaction_edge_count: int = 0
    entity_link_edge_count: int = 0
    explicit_edge_count: int = 0
    other_edge_count: int = 0
    total_edge_weight: float = 0.0
    fingerprint: str = ""
    truncated: Mapping[str, bool] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": int(self.node_count),
            "edge_count": int(self.edge_count),
            "transaction_edge_count": int(self.transaction_edge_count),
            "entity_link_edge_count": int(self.entity_link_edge_count),
            "explicit_edge_count": int(self.explicit_edge_count),
            "other_edge_count": int(self.other_edge_count),
            "total_edge_weight": _round6(self.total_edge_weight),
            "fingerprint": self.fingerprint,
            "truncated": dict(self.truncated),
            "raw_values_retained": False,
        }


@dataclass(frozen=True, slots=True)
class FilterResult:
    """
    Safe bounded filter result.
    """

    ok: bool = True
    status: AnalysisStatus | str = AnalysisStatus.PASSED
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    original_graph_summary: FilteredGraphSummary = dataclass_field(default_factory=FilteredGraphSummary)
    filtered_graph_summary: FilteredGraphSummary = dataclass_field(default_factory=FilteredGraphSummary)
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[FilterIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(self, "status", _normalize_enum(AnalysisStatus, self.status, AnalysisStatus.PASSED))
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "counts", MappingProxyType({str(key): max(0, _as_int(value, 0)) for key, value in (self.counts or {}).items()}))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": FILTERS_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, AnalysisStatus.PASSED.value),
                        "original_graph": self.original_graph_summary.fingerprint,
                        "filtered_graph": self.filtered_graph_summary.fingerprint,
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": _enum_value(self.status, AnalysisStatus.PASSED.value),
            "request_id": self.request_id,
            "generated_at": self.generated_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "original_graph_summary": self.original_graph_summary.to_dict(),
            "filtered_graph_summary": self.filtered_graph_summary.to_dict(),
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_FILTER_CAVEATS),
            "safety_flags": dict(_FILTER_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local filter cache
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _CachedFilterResult:
    result: FilterResult
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class FilterCache:
    """
    Bounded process-local filter cache.
    """

    def __init__(self, max_entries: int = _DEFAULT_MAX_CACHE_ENTRIES) -> None:
        self.max_entries = max(1, int(max_entries))
        self._entries: OrderedDict[str, _CachedFilterResult] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[FilterResult]:
        clean_key = _clean_text(key, 256)

        with self._lock:
            entry = self._entries.get(clean_key)

            if entry is None:
                return None

            self._entries.move_to_end(clean_key)
            return entry.result

    def set(self, key: str, result: FilterResult) -> str:
        clean_key = _clean_text(key, 256) or result.fingerprint

        with self._lock:
            self._entries[clean_key] = _CachedFilterResult(result=result, registered_at=_now_utc())
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
                "entries": len(self._entries),
            }


_default_cache: Optional[FilterCache] = None
_default_cache_lock = threading.Lock()


def get_filter_cache(max_entries: int | None = None, *, rebuild: bool = False) -> FilterCache:
    global _default_cache

    with _default_cache_lock:
        if _default_cache is None or rebuild:
            _default_cache = FilterCache(max_entries=max_entries if max_entries is not None else _DEFAULT_MAX_CACHE_ENTRIES)

        return _default_cache


# -----------------------------------------------------------------------------
# Filter engine
# -----------------------------------------------------------------------------


class FilterEngine:
    """
    Bounded deterministic synthetic graph filter engine.
    """

    def __init__(self, options: FilterOptions | None = None, cache: FilterCache | None = None) -> None:
        self.options = options or FilterOptions.from_settings()
        self.cache = cache or get_filter_cache(self.options.max_cache_entries)
        self._lock = threading.RLock()

    def filter(self, request: Any) -> FilterResult:
        """
        Run one bounded synthetic graph filter job.
        """
        opts = self.options
        issues: list[FilterIssue] = []
        generated_at = _now_utc()
        start_time = time.monotonic()

        req = _coerce_request(request)
        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": FILTERS_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: AnalysisStatus,
            original_summary: Optional[FilteredGraphSummary] = None,
            filtered_summary: Optional[FilteredGraphSummary] = None,
            counts: Optional[Mapping[str, int]] = None,
            cache_key: Optional[str] = None,
        ) -> FilterResult:
            resolved_counts: dict[str, int] = {
                "original_nodes": 0,
                "original_edges": 0,
                "filtered_nodes": 0,
                "filtered_edges": 0,
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update({str(key): max(0, _as_int(value, 0)) for key, value in counts.items()})

            resolved_counts["issues"] = len(issues)

            metadata = {
                "filters_version": FILTERS_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "cache": self.cache.safe_summary(),
                "cache_key": cache_key,
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_values_retained": False,
                "subject_label_pairs_retained": False,
                "narratives_retained": False,
                "identifiers_retained": False,
                "secrets_retained": False,
                "caveats": list(_FILTER_CAVEATS),
                "safety_flags": dict(_FILTER_SAFETY_FLAGS),
            }

            return FilterResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=generated_at,
                duration_ms=_elapsed_ms(start_time),
                original_graph_summary=original_summary or FilteredGraphSummary(),
                filtered_graph_summary=filtered_summary or FilteredGraphSummary(),
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
                code="filter_engine_disabled",
                message="Filter engine is disabled.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Filter engine requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Filter engine is blocked in production-like environments.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_filter_action_metadata",
                message="Filter request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        with self._lock:
            graph = _build_graph(req, opts, issues, start_time)

            original_metrics = _compute_filtered_metrics(
                graph,
                set(graph.nodes.keys()),
                {edge.edge_hash for edge in graph.edges},
            )

            original_summary = FilteredGraphSummary(
                node_count=original_metrics["node_count"],
                edge_count=original_metrics["edge_count"],
                transaction_edge_count=original_metrics["transaction_edge_count"],
                entity_link_edge_count=original_metrics["entity_link_edge_count"],
                explicit_edge_count=original_metrics["explicit_edge_count"],
                other_edge_count=original_metrics["other_edge_count"],
                total_edge_weight=original_metrics["total_edge_weight"],
                fingerprint=graph.fingerprint,
                truncated=dict(graph.truncated),
            )

            if not graph.nodes or not graph.edges:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="empty_filter_graph",
                    message="No valid graph nodes or edges were available for filtering.",
                )
                return make_result(
                    False,
                    AnalysisStatus.SKIPPED,
                    original_summary=original_summary,
                    filtered_summary=FilteredGraphSummary(fingerprint=graph.fingerprint, truncated=dict(graph.truncated)),
                    counts=original_metrics,
                )

            cache_key: Optional[str] = None

            if opts.use_cache:
                cache_key = _sha256_hex(
                    _canonical_json(
                        {
                            "graph": graph.fingerprint,
                            "options": opts.safe_summary(),
                            "node_filter": _safe_detail_value(req.node_filter),
                            "edge_filter": _safe_detail_value(req.edge_filter),
                        }
                    )
                )[:64]

                cached = self.cache.get(cache_key)

                if cached is not None:
                    metadata = dict(cached.metadata)
                    metadata.update(
                        {
                            "cached": True,
                            "cache_hit": True,
                            "cache_key": cache_key,
                            "request_id": request_id,
                        }
                    )
                    return replace(cached, metadata=MappingProxyType(metadata), fingerprint="")

            retained_nodes = _apply_node_filters(graph, req.node_filter, opts)
            retained_edges = _apply_edge_filters(graph, req.edge_filter, opts)

            if opts.prune_orphan_edges:
                retained_nodes, retained_edges = _prune_orphan_edges(graph, retained_nodes, retained_edges)

            filtered_metrics = _compute_filtered_metrics(graph, retained_nodes, retained_edges)

            # Compute filtered graph fingerprint
            filtered_digest = hashlib.sha256()
            filtered_digest.update(f"muleguard.graph.filters.filtered.{FILTERS_VERSION}|{len(retained_nodes)}|{len(retained_edges)}\n".encode("utf-8", errors="replace"))

            for edge in graph.edges:
                if edge.edge_hash in retained_edges:
                    filtered_digest.update(f"{edge.edge_hash}|{edge.kind.value}|{_round6(edge.weight)}\n".encode("utf-8", errors="replace"))

            filtered_fingerprint = filtered_digest.hexdigest()

            filtered_summary = FilteredGraphSummary(
                node_count=filtered_metrics["node_count"],
                edge_count=filtered_metrics["edge_count"],
                transaction_edge_count=filtered_metrics["transaction_edge_count"],
                entity_link_edge_count=filtered_metrics["entity_link_edge_count"],
                explicit_edge_count=filtered_metrics["explicit_edge_count"],
                other_edge_count=filtered_metrics["other_edge_count"],
                total_edge_weight=filtered_metrics["total_edge_weight"],
                fingerprint=filtered_fingerprint,
                truncated=dict(graph.truncated),
            )

            counts = {
                "original_nodes": original_metrics["node_count"],
                "original_edges": original_metrics["edge_count"],
                "filtered_nodes": filtered_metrics["node_count"],
                "filtered_edges": filtered_metrics["edge_count"],
                "removed_nodes": original_metrics["node_count"] - filtered_metrics["node_count"],
                "removed_edges": original_metrics["edge_count"] - filtered_metrics["edge_count"],
            }

            status = AnalysisStatus.PASSED

            if _has_error(issues):
                status = AnalysisStatus.FAILED
            elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
                status = AnalysisStatus.DEGRADED
            elif filtered_metrics["node_count"] == 0 or filtered_metrics["edge_count"] == 0:
                status = AnalysisStatus.SKIPPED

            result = make_result(
                ok=status in {AnalysisStatus.PASSED, AnalysisStatus.DEGRADED},
                status=status,
                original_summary=original_summary,
                filtered_summary=filtered_summary,
                counts=counts,
                cache_key=cache_key,
            )

            if opts.use_cache and cache_key and result.ok:
                self.cache.set(cache_key, result)

            return result

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "cache": self.cache.safe_summary(),
            "caveats": list(_FILTER_CAVEATS),
            "safety_flags": dict(_FILTER_SAFETY_FLAGS),
        }


_default_engine: Optional[FilterEngine] = None
_default_engine_lock = threading.Lock()


def get_filter_options(settings: Any | None = None) -> FilterOptions:
    return FilterOptions.from_settings(settings)


def get_filter_engine(
    options: FilterOptions | None = None,
    *,
    rebuild: bool = False,
) -> FilterEngine:
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = FilterEngine(options=options or FilterOptions.from_settings())

        return _default_engine


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def filter_graph(
    request: Any,
    options: FilterOptions | None = None,
    *,
    engine: FilterEngine | None = None,
) -> FilterResult:
    """
    Filter one bounded synthetic graph.
    """
    active_engine = engine or get_filter_engine(options)
    return active_engine.filter(request)


def apply_graph_filters(
    request: Any,
    options: FilterOptions | None = None,
    *,
    engine: FilterEngine | None = None,
) -> FilterResult:
    """
    Alias for `filter_graph`.
    """
    return filter_graph(request, options=options, engine=engine)


def get_filter_result(request_id: Any, *, cache: FilterCache | None = None) -> Optional[FilterResult]:
    """
    Return one cached filter result.
    """
    active_cache = cache or get_filter_cache()
    return active_cache.get(request_id)


def get_filters_health(*, engine: FilterEngine | None = None) -> dict[str, Any]:
    """
    Return safe filter-engine health.
    """
    active_engine = engine or get_filter_engine()
    opts = active_engine.options
    cache_summary = active_engine.cache.safe_summary()
    issues: list[FilterIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="filter_engine_disabled",
            message="Filter engine is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Filter engine requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Filter engine is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "cache": cache_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(_FILTER_CAVEATS),
        "safety_flags": dict(_FILTER_SAFETY_FLAGS),
    }


def get_filters_metadata(*, limit: int = _DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
    """
    Return safe, serializable filter-engine metadata.
    """
    options = FilterOptions.from_settings()
    cache = get_filter_cache(options.max_cache_entries)

    return {
        "package": "muleguard.backend.graph.filters",
        "version": FILTERS_VERSION,
        "node_kinds": [kind.value for kind in NodeKind],
        "edge_kinds": [kind.value for kind in EdgeKind],
        "filter_ops": [op.value for op in FilterOp],
        "statuses": [status.value for status in AnalysisStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "cache": cache.safe_summary(),
        "hard_limits": {
            "max_nodes": _HARD_MAX_NODES,
            "max_edges": _HARD_MAX_EDGES,
            "max_records": _HARD_MAX_RECORDS,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_cache_entries": _HARD_MAX_CACHE_ENTRIES,
            "max_time_ms": _HARD_MAX_TIME_MS,
            "max_window_days": _HARD_MAX_WINDOW_DAYS,
        },
        "forbidden_graph_field_count": len(_FORBIDDEN_GRAPH_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(_PROHIBITED_ACTION_TOKENS),
        "caveats": list(_FILTER_CAVEATS),
        "safety_flags": dict(_FILTER_SAFETY_FLAGS),
    }


__all__ = [
    "AnalysisStatus",
    "EdgeFilterCriteria",
    "EdgeKind",
    "FilterCache",
    "FilterEngine",
    "FilterIssue",
    "FilterOp",
    "FilterOptions",
    "FilterResult",
    "FilteredGraphSummary",
    "GraphFilterRequest",
    "IssueSeverity",
    "NodeFilterCriteria",
    "NodeKind",
    "apply_graph_filters",
    "filter_graph",
    "get_filter_cache",
    "get_filter_engine",
    "get_filter_options",
    "get_filter_result",
    "get_filters_health",
    "get_filters_metadata",
]