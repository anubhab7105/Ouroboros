"""
MULEGUARD backend graph cycle detection.

This module provides the canonical bounded cycle-detection layer for the
synthetic MULEGUARD investigative graph subsystem.

Primary responsibilities:

- detect bounded directed cycles, reciprocal pairs, self-loops, entity-link
  bipartite cycles, and optional weak undirected projection cycles in synthetic
  investigative graphs;
- compute strongly connected components using an iterative, bounded Tarjan
  algorithm;
- enumerate simple cycles within bounded search budgets and deterministic
  ordering;
- produce deterministic cycle fingerprints, structural features, heuristic
  prioritization scores, operational reasons, and safe validation results;
- preserve privacy by using salted one-way pseudonymous node references and by
  excluding raw feature values, raw identifiers, raw narratives, subject-label
  pairs, secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited graph fields;
- maintain a bounded process-local cycle-analysis cache for local prototype
  workflows, tests, developer tooling, and offline evaluation harnesses;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module detects structural graph patterns only. It does not train models,
deploy models, persist durable artifacts, call external systems, authenticate
users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for graph construction or cycle detection.
- Cycle candidates are investigative leads only. They are not proof of
  wrongdoing, layering, integration, common control, or criminal association.
- Directed transaction cycles are structural flow patterns only. They are not
  evidence of intent.
- Entity-link cycles are association patterns only. Shared devices, IPs,
  phones, emails, UPI handles, or addresses are not proof of common control.
- Weak undirected projection cycles are deliberately weaker signals and are
  disabled by default.
- Only completed transactions are treated as settled fund movement by default.
  Pending, failed, reversed, cancelled, and disputed records remain distinct.
- Currency amounts are never converted or blended across currencies. This
  module performs structural detection, not monetary adjudication.
- Labels may not be used as graph features or cycle-scoring inputs.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected as graph fields.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are forbidden outputs. Node linkage is pseudonymous and salted.
- Cycle handling must never trigger automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, denying, terminating,
  suspending, referring to law enforcement, or making credit, employment,
  housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable cycle results are reported honestly as unavailable
  rather than invented.
- The bundled cycle cache is process-local, non-durable, and bounded for local
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
from collections import Counter, OrderedDict, deque
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


logger = logging.getLogger("muleguard.backend.graph.cycles")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

CYCLES_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.graph.cycles.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_NODES: Final[int] = 20_000
_HARD_MAX_NODES: Final[int] = 100_000

_DEFAULT_MAX_EDGES: Final[int] = 100_000
_HARD_MAX_EDGES: Final[int] = 1_000_000

_DEFAULT_MAX_RECORDS: Final[int] = 100_000
_HARD_MAX_RECORDS: Final[int] = 1_000_000

_DEFAULT_MAX_CYCLES: Final[int] = 500
_HARD_MAX_CYCLES: Final[int] = 20_000

_DEFAULT_MAX_CANDIDATES: Final[int] = 100
_HARD_MAX_CANDIDATES: Final[int] = 5_000

_DEFAULT_MAX_CYCLE_LENGTH: Final[int] = 12
_HARD_MAX_CYCLE_LENGTH: Final[int] = 64

_DEFAULT_MIN_CYCLE_LENGTH: Final[int] = 2

_DEFAULT_MAX_SEARCH_STEPS: Final[int] = 500_000
_HARD_MAX_SEARCH_STEPS: Final[int] = 10_000_000

_DEFAULT_MAX_SEARCH_SEEDS: Final[int] = 256
_HARD_MAX_SEARCH_SEEDS: Final[int] = 10_000

_DEFAULT_MAX_SCC_SIZE: Final[int] = 2_000
_HARD_MAX_SCC_SIZE: Final[int] = 20_000

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

_DEFAULT_SEVERITY_THRESHOLD: Final[float] = 0.60

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_NODE_HASH_LENGTH: Final[int] = 256
_MAX_REASON_TEXT_LENGTH: Final[int] = 300

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

_EXACT_METHODS: Final[frozenset[str]] = frozenset(
    {
        "EXACT",
        "HASHED",
    }
)

_HEURISTIC_METHODS: Final[frozenset[str]] = frozenset(
    {
        "HEURISTIC",
        "INFERRED",
        "FUZZY",
    }
)

_DEFAULT_RISK_THRESHOLDS: Final[Mapping[str, float]] = MappingProxyType(
    {
        "low": 0.25,
        "medium": 0.45,
        "high": 0.65,
        "critical": 0.85,
    }
)

_CYCLE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic graph cycle detection only. Do not use with real customer data.",
    "Cycle candidates are investigative leads only and are not proof of wrongdoing.",
    "Directed transaction cycles are structural flow patterns, not evidence of intent.",
    "Entity-link cycles are association patterns, not proof of common control.",
    "Weak undirected projection cycles are weaker signals and are disabled by default.",
    "Only completed transactions are treated as settled fund movement by default.",
    "Currency amounts are never converted or blended across currencies.",
    "Labels must never be used as graph features or cycle-scoring inputs.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden inputs.",
    "Cycle scores are heuristic prioritization signals, not probabilities of guilt.",
    "Cycle detection must not trigger automatic adverse customer action.",
    "The bundled cycle cache is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_CYCLE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
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
        "deterministic_cycle_detection": True,
        "bounded_cycle_detection_required": True,
        "only_completed_transactions_settled_by_default": True,
        "no_cross_currency_blending": True,
        "weak_projection_disabled_by_default": True,
        "cycle_scores_are_heuristic_priority_only": True,
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


class CycleKind(str, Enum):
    """
    Bounded cycle kind.
    """

    SELF_LOOP = "self_loop"
    RECIPROCAL = "reciprocal"
    DIRECTED_SIMPLE = "directed_simple"
    ENTITY_LINK_BIPARTITE = "entity_link_bipartite"
    UNDIRECTED_SIMPLE = "undirected_simple"
    WEAK_PROJECTION = "weak_projection"


class CycleMode(str, Enum):
    """
    Cycle detection mode.
    """

    SCC_ONLY = "scc_only"
    BOUNDED_EXACT = "bounded_exact"
    LOCAL_HEURISTIC = "local_heuristic"
    HYBRID = "hybrid"


class CycleSeverity(str, Enum):
    """
    Operational cycle severity.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    # Declared `ERROR`, like its siblings. It was spelled `error` in lower
    # case while all fourteen call sites in this module use
    # `IssueSeverity.ERROR`, so every one of them raised AttributeError the
    # moment a cycle analysis hit an error path. The string value is
    # unchanged, so nothing serialised is affected.
    ERROR = "error"


class AnalysisStatus(str, Enum):
    """
    Overall cycle-analysis status.
    """

    PASSED = "PASSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


_DIRECTED_CYCLE_KINDS: Final[frozenset[CycleKind]] = frozenset(
    {
        CycleKind.SELF_LOOP,
        CycleKind.RECIPROCAL,
        CycleKind.DIRECTED_SIMPLE,
    }
)

_UNDIRECTED_CYCLE_KINDS: Final[frozenset[CycleKind]] = frozenset(
    {
        CycleKind.ENTITY_LINK_BIPARTITE,
        CycleKind.UNDIRECTED_SIMPLE,
        CycleKind.WEAK_PROJECTION,
    }
)


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


def _coerce_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value

    if value is None:
        return None

    numeric = _coerce_float(value, allow_bool=False)

    if numeric is not None:
        if numeric == 0.0:
            return False
        if numeric == 1.0:
            return True
        return None

    text = _normalize_token(value)

    if text in _TRUE_VALUES:
        return True

    if text in _FALSE_VALUES:
        return False

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


class _DetRandom:
    """
    Deterministic dependency-light pseudo-random generator.

    Not cryptographically secure. Used only for deterministic local-heuristic
    seed selection in bounded cycle detection.
    """

    def __init__(self, salt: str, domain: str, *seed_parts: Any) -> None:
        self.salt = salt
        self.domain = domain
        self.seed_parts = seed_parts
        self.counter = 0

    def randrange(self, n: int) -> int:
        if n <= 0:
            return 0

        self.counter += 1
        rank = _stable_rank(self.salt, self.domain, *self.seed_parts, self.counter)
        value = int((float(rank & ((1 << 53) - 1)) / float(1 << 53)) * float(n))
        return max(0, min(n - 1, value))


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CycleIssue:
    """
    Safe cycle issue.

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
    issues: list[CycleIssue],
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

        issues[-1] = CycleIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        CycleIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[CycleIssue]) -> bool:
    return any(issue.severity == IssueSeverity.error for issue in issues)


def _dedupe_issues(issues: Sequence[CycleIssue]) -> tuple[CycleIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[CycleIssue] = []

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
class CycleOptions:
    """
    Bounded cycle-detection policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    mode: CycleMode | str = CycleMode.HYBRID

    max_nodes: int = _DEFAULT_MAX_NODES
    max_edges: int = _DEFAULT_MAX_EDGES
    max_records: int = _DEFAULT_MAX_RECORDS
    max_cycles: int = _DEFAULT_MAX_CYCLES
    max_candidates: int = _DEFAULT_MAX_CANDIDATES
    min_cycle_length: int = _DEFAULT_MIN_CYCLE_LENGTH
    max_cycle_length: int = _DEFAULT_MAX_CYCLE_LENGTH
    max_search_steps: int = _DEFAULT_MAX_SEARCH_STEPS
    max_search_seeds: int = _DEFAULT_MAX_SEARCH_SEEDS
    max_scc_size: int = _DEFAULT_MAX_SCC_SIZE
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_summary_items: int = _DEFAULT_MAX_SUMMARY_ITEMS
    max_cache_entries: int = _DEFAULT_MAX_CACHE_ENTRIES
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    window_days: int = _DEFAULT_WINDOW_DAYS
    max_window_days: int = _HARD_MAX_WINDOW_DAYS

    include_self_loops: bool = False
    include_reciprocal: bool = True
    include_directed_cycles: bool = True
    include_entity_link_cycles: bool = True
    include_undirected_cycles: bool = False
    include_weak_projection: bool = False
    include_non_completed_transactions: bool = False
    include_unverified_links: bool = True

    require_completed_transactions: bool = True
    require_alternating_bipartite: bool = True
    require_distinct_cycle_nodes: bool = True

    severity_threshold: float = _DEFAULT_SEVERITY_THRESHOLD
    risk_thresholds: Mapping[str, float] = dataclass_field(default_factory=lambda: dict(_DEFAULT_RISK_THRESHOLDS))

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
        object.__setattr__(self, "mode", _normalize_enum(CycleMode, self.mode, CycleMode.HYBRID))

        object.__setattr__(self, "max_nodes", _clamp_int(self.max_nodes, 2, _HARD_MAX_NODES, _DEFAULT_MAX_NODES))
        object.__setattr__(self, "max_edges", _clamp_int(self.max_edges, 1, _HARD_MAX_EDGES, _DEFAULT_MAX_EDGES))
        object.__setattr__(self, "max_records", _clamp_int(self.max_records, 1, _HARD_MAX_RECORDS, _DEFAULT_MAX_RECORDS))
        object.__setattr__(self, "max_cycles", _clamp_int(self.max_cycles, 1, _HARD_MAX_CYCLES, _DEFAULT_MAX_CYCLES))
        object.__setattr__(self, "max_candidates", _clamp_int(self.max_candidates, 1, _HARD_MAX_CANDIDATES, _DEFAULT_MAX_CANDIDATES))

        min_length = _clamp_int(self.min_cycle_length, 2, _HARD_MAX_CYCLE_LENGTH, _DEFAULT_MIN_CYCLE_LENGTH)
        max_length = _clamp_int(self.max_cycle_length, min_length, _HARD_MAX_CYCLE_LENGTH, _DEFAULT_MAX_CYCLE_LENGTH)
        object.__setattr__(self, "min_cycle_length", min_length)
        object.__setattr__(self, "max_cycle_length", max_length)

        object.__setattr__(self, "max_search_steps", _clamp_int(self.max_search_steps, 100, _HARD_MAX_SEARCH_STEPS, _DEFAULT_MAX_SEARCH_STEPS))
        object.__setattr__(self, "max_search_seeds", _clamp_int(self.max_search_seeds, 1, _HARD_MAX_SEARCH_SEEDS, _DEFAULT_MAX_SEARCH_SEEDS))
        object.__setattr__(self, "max_scc_size", _clamp_int(self.max_scc_size, 2, _HARD_MAX_SCC_SIZE, _DEFAULT_MAX_SCC_SIZE))
        object.__setattr__(self, "max_issues", _clamp_int(self.max_issues, 1, _HARD_MAX_ISSUES, _DEFAULT_MAX_ISSUES))
        object.__setattr__(self, "max_summary_items", _clamp_int(self.max_summary_items, 1, _HARD_MAX_SUMMARY_ITEMS, _DEFAULT_MAX_SUMMARY_ITEMS))
        object.__setattr__(self, "max_cache_entries", _clamp_int(self.max_cache_entries, 1, _HARD_MAX_CACHE_ENTRIES, _DEFAULT_MAX_CACHE_ENTRIES))
        object.__setattr__(self, "max_time_ms", _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS))

        object.__setattr__(self, "window_days", _clamp_int(self.window_days, 1, _HARD_MAX_WINDOW_DAYS, _DEFAULT_WINDOW_DAYS))
        object.__setattr__(self, "max_window_days", _clamp_int(self.max_window_days, 1, _HARD_MAX_WINDOW_DAYS, _HARD_MAX_WINDOW_DAYS))

        object.__setattr__(self, "include_self_loops", _as_bool(self.include_self_loops, False))
        object.__setattr__(self, "include_reciprocal", _as_bool(self.include_reciprocal, True))
        object.__setattr__(self, "include_directed_cycles", _as_bool(self.include_directed_cycles, True))
        object.__setattr__(self, "include_entity_link_cycles", _as_bool(self.include_entity_link_cycles, True))
        object.__setattr__(self, "include_undirected_cycles", _as_bool(self.include_undirected_cycles, False))
        object.__setattr__(self, "include_weak_projection", _as_bool(self.include_weak_projection, False))
        object.__setattr__(self, "include_non_completed_transactions", _as_bool(self.include_non_completed_transactions, False))
        object.__setattr__(self, "include_unverified_links", _as_bool(self.include_unverified_links, True))

        object.__setattr__(self, "require_completed_transactions", _as_bool(self.require_completed_transactions, True))
        object.__setattr__(self, "require_alternating_bipartite", _as_bool(self.require_alternating_bipartite, True))
        object.__setattr__(self, "require_distinct_cycle_nodes", _as_bool(self.require_distinct_cycle_nodes, True))

        object.__setattr__(self, "severity_threshold", _round6(_clamp_float(self.severity_threshold, 0.0, 1.0, _DEFAULT_SEVERITY_THRESHOLD)))

        thresholds = dict(self.risk_thresholds or {})
        low = _clamp_float(thresholds.get("low", 0.25), 0.0, 1.0, 0.25)
        medium = max(low, _clamp_float(thresholds.get("medium", 0.45), 0.0, 1.0, 0.45))
        high = max(medium, _clamp_float(thresholds.get("high", 0.65), 0.0, 1.0, 0.65))
        critical = max(high, _clamp_float(thresholds.get("critical", 0.85), 0.0, 1.0, 0.85))

        object.__setattr__(
            self,
            "risk_thresholds",
            MappingProxyType(
                {
                    "low": _round6(low),
                    "medium": _round6(medium),
                    "high": _round6(high),
                    "critical": _round6(critical),
                }
            ),
        )

        object.__setattr__(self, "use_cache", _as_bool(self.use_cache, True))
        object.__setattr__(self, "register_results", _as_bool(self.register_results, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, False))

        # Safety invariants that configuration must not weaken.
        object.__setattr__(self, "include_weak_projection", _as_bool(self.include_weak_projection, False))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "CycleOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "GRAPH_CYCLE_SALT", None)
            or _setting(settings, "RULES_THRESHOLD_SALT", None)
            or _setting(settings, "RULES_ENGINE_SALT", None)
            or _setting(settings, "ML_VALIDATION_SALT", None)
            or _setting(settings, "ML_EXPLAIN_SALT", None)
            or _setting(settings, "ML_EVALUATE_SALT", None)
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

        raw_thresholds = _setting(settings, "GRAPH_CYCLE_RISK_THRESHOLDS", None)
        thresholds = raw_thresholds if isinstance(raw_thresholds, Mapping) else {
            "low": _as_float(_setting(settings, "GRAPH_CYCLE_RISK_LOW", 0.25), 0.25),
            "medium": _as_float(_setting(settings, "GRAPH_CYCLE_RISK_MEDIUM", 0.45), 0.45),
            "high": _as_float(_setting(settings, "GRAPH_CYCLE_RISK_HIGH", 0.65), 0.65),
            "critical": _as_float(_setting(settings, "GRAPH_CYCLE_RISK_CRITICAL", 0.85), 0.85),
        }

        return cls(
            enabled=_as_bool(_setting(settings, "GRAPH_CYCLE_ENABLED", True), True)
            and _as_bool(_setting(settings, "ML_ENABLED", True), True),
            synthetic_required=_as_bool(_setting(settings, "GRAPH_CYCLE_REQUIRE_SYNTHETIC", True), True),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(_setting(settings, "GRAPH_CYCLE_ALLOW_IN_PRODUCTION", False), False),
            salt=salt,
            namespace=str(_setting(settings, "GRAPH_CYCLE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "GRAPH_CYCLE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            mode=str(_setting(settings, "GRAPH_CYCLE_MODE", CycleMode.HYBRID.value)),
            max_nodes=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_NODES", _DEFAULT_MAX_NODES), _DEFAULT_MAX_NODES),
            max_edges=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_EDGES", _DEFAULT_MAX_EDGES), _DEFAULT_MAX_EDGES),
            max_records=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_RECORDS", _DEFAULT_MAX_RECORDS), _DEFAULT_MAX_RECORDS),
            max_cycles=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_CYCLES", _DEFAULT_MAX_CYCLES), _DEFAULT_MAX_CYCLES),
            max_candidates=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_CANDIDATES", _DEFAULT_MAX_CANDIDATES), _DEFAULT_MAX_CANDIDATES),
            min_cycle_length=_as_int(_setting(settings, "GRAPH_CYCLE_MIN_LENGTH", _DEFAULT_MIN_CYCLE_LENGTH), _DEFAULT_MIN_CYCLE_LENGTH),
            max_cycle_length=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_LENGTH", _DEFAULT_MAX_CYCLE_LENGTH), _DEFAULT_MAX_CYCLE_LENGTH),
            max_search_steps=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_SEARCH_STEPS", _DEFAULT_MAX_SEARCH_STEPS), _DEFAULT_MAX_SEARCH_STEPS),
            max_search_seeds=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_SEARCH_SEEDS", _DEFAULT_MAX_SEARCH_SEEDS), _DEFAULT_MAX_SEARCH_SEEDS),
            max_scc_size=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_SCC_SIZE", _DEFAULT_MAX_SCC_SIZE), _DEFAULT_MAX_SCC_SIZE),
            max_issues=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_SUMMARY_ITEMS", _DEFAULT_MAX_SUMMARY_ITEMS), _DEFAULT_MAX_SUMMARY_ITEMS),
            max_cache_entries=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_CACHE_ENTRIES", _DEFAULT_MAX_CACHE_ENTRIES), _DEFAULT_MAX_CACHE_ENTRIES),
            max_time_ms=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS), _DEFAULT_MAX_TIME_MS),
            window_days=_as_int(_setting(settings, "GRAPH_CYCLE_WINDOW_DAYS", _DEFAULT_WINDOW_DAYS), _DEFAULT_WINDOW_DAYS),
            max_window_days=_as_int(_setting(settings, "GRAPH_CYCLE_MAX_WINDOW_DAYS", _HARD_MAX_WINDOW_DAYS), _HARD_MAX_WINDOW_DAYS),
            include_self_loops=_as_bool(_setting(settings, "GRAPH_CYCLE_INCLUDE_SELF_LOOPS", False), False),
            include_reciprocal=_as_bool(_setting(settings, "GRAPH_CYCLE_INCLUDE_RECIPROCAL", True), True),
            include_directed_cycles=_as_bool(_setting(settings, "GRAPH_CYCLE_INCLUDE_DIRECTED", True), True),
            include_entity_link_cycles=_as_bool(_setting(settings, "GRAPH_CYCLE_INCLUDE_ENTITY_LINKS", True), True),
            include_undirected_cycles=_as_bool(_setting(settings, "GRAPH_CYCLE_INCLUDE_UNDIRECTED", False), False),
            include_weak_projection=_as_bool(_setting(settings, "GRAPH_CYCLE_INCLUDE_WEAK_PROJECTION", False), False),
            include_non_completed_transactions=_as_bool(_setting(settings, "GRAPH_CYCLE_INCLUDE_NON_COMPLETED", False), False),
            include_unverified_links=_as_bool(_setting(settings, "GRAPH_CYCLE_INCLUDE_UNVERIFIED_LINKS", True), True),
            require_completed_transactions=_as_bool(_setting(settings, "GRAPH_CYCLE_REQUIRE_COMPLETED", True), True),
            require_alternating_bipartite=_as_bool(_setting(settings, "GRAPH_CYCLE_REQUIRE_ALTERNATING", True), True),
            require_distinct_cycle_nodes=_as_bool(_setting(settings, "GRAPH_CYCLE_REQUIRE_DISTINCT", True), True),
            severity_threshold=_as_float(_setting(settings, "GRAPH_CYCLE_SEVERITY_THRESHOLD", _DEFAULT_SEVERITY_THRESHOLD), _DEFAULT_SEVERITY_THRESHOLD),
            risk_thresholds=thresholds,
            use_cache=_as_bool(_setting(settings, "GRAPH_CYCLE_USE_CACHE", True), True),
            register_results=_as_bool(_setting(settings, "GRAPH_CYCLE_REGISTER_RESULTS", True), True),
            drop_forbidden_fields=_as_bool(_setting(settings, "GRAPH_CYCLE_DROP_FORBIDDEN_FIELDS", False), False),
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
            "mode": _enum_value(self.mode, CycleMode.HYBRID.value),
            "limits": {
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
                "max_records": self.max_records,
                "max_cycles": self.max_cycles,
                "max_candidates": self.max_candidates,
                "min_cycle_length": self.min_cycle_length,
                "max_cycle_length": self.max_cycle_length,
                "max_search_steps": self.max_search_steps,
                "max_search_seeds": self.max_search_seeds,
                "max_scc_size": self.max_scc_size,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_cache_entries": self.max_cache_entries,
                "max_time_ms": self.max_time_ms,
                "window_days": self.window_days,
                "max_window_days": self.max_window_days,
            },
            "flags": {
                "include_self_loops": self.include_self_loops,
                "include_reciprocal": self.include_reciprocal,
                "include_directed_cycles": self.include_directed_cycles,
                "include_entity_link_cycles": self.include_entity_link_cycles,
                "include_undirected_cycles": self.include_undirected_cycles,
                "include_weak_projection": self.include_weak_projection,
                "include_non_completed_transactions": self.include_non_completed_transactions,
                "include_unverified_links": self.include_unverified_links,
                "require_completed_transactions": self.require_completed_transactions,
                "require_alternating_bipartite": self.require_alternating_bipartite,
                "require_distinct_cycle_nodes": self.require_distinct_cycle_nodes,
                "use_cache": self.use_cache,
                "register_results": self.register_results,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
            "severity_threshold": _round6(self.severity_threshold),
            "risk_thresholds": dict(self.risk_thresholds),
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
        "mode",
        "subject_refs",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class CycleRequest:
    """
    Bounded cycle-analysis request.
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
    mode: CycleMode | str | None = None
    subject_refs: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        if self.mode is not None:
            self.mode = _normalize_enum(CycleMode, self.mode, None)

        self.observation_time = _ensure_utc(_parse_datetime(self.observation_time))
        self.window_start = _ensure_utc(_parse_datetime(self.window_start))
        self.window_end = _ensure_utc(_parse_datetime(self.window_end))
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> CycleRequest:
    if isinstance(request, CycleRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if "edges" not in payload and "observations" in payload:
            payload["edges"] = payload["observations"]

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(CycleRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return CycleRequest(**clean)
            except Exception:
                return CycleRequest(edges=payload.get("edges", request))

        return CycleRequest(edges=request)

    if isinstance(request, (list, tuple, set, frozenset)):
        return CycleRequest(edges=request)

    return CycleRequest(edges=request)


# -----------------------------------------------------------------------------
# Internal graph models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _Node:
    node_hash: str
    kind: NodeKind
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass(frozen=True, slots=True)
class _Edge:
    source: str
    target: str
    kind: EdgeKind
    directed: bool
    timestamp: Optional[datetime]
    verification_state: str
    match_method: str
    edge_hash: str


@dataclass(slots=True)
class _Graph:
    nodes: dict[str, _Node] = dataclass_field(default_factory=dict)
    edges: list[_Edge] = dataclass_field(default_factory=list)
    node_kinds: dict[str, NodeKind] = dataclass_field(default_factory=dict)
    directed_neighbors: dict[str, set[str]] = dataclass_field(default_factory=dict)
    undirected_neighbors: dict[str, set[str]] = dataclass_field(default_factory=dict)
    projection_neighbors: dict[str, set[str]] = dataclass_field(default_factory=dict)
    out_edges: dict[str, list[_Edge]] = dataclass_field(default_factory=dict)
    und_edges: dict[str, list[_Edge]] = dataclass_field(default_factory=dict)
    directed_pairs: set[tuple[str, str]] = dataclass_field(default_factory=set)
    sccs: tuple[tuple[str, ...], ...] = ()
    fingerprint: str = ""
    counts: dict[str, int] = dataclass_field(default_factory=dict)
    truncated: dict[str, bool] = dataclass_field(default_factory=dict)


# -----------------------------------------------------------------------------
# Graph construction
# -----------------------------------------------------------------------------


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, CycleAnalysisResult):
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
    options: CycleOptions,
    issues: list[CycleIssue],
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


def _pick(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]

    return None


def _node_hash_for(raw: Any, kind: NodeKind, options: CycleOptions) -> Optional[str]:
    text = _clean_text(raw, 256)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    domain = f"muleguard.graph.cycles.node.{kind.value}.{_normalize_token(options.namespace)}"
    return _hmac_hex(options.salt, domain, text)[:40]


def _resolve_node(
    raw: Any,
    kind: NodeKind,
    account_map: Mapping[str, str],
    entity_map: Mapping[str, str],
    options: CycleOptions,
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
    options: CycleOptions,
    issues: list[CycleIssue],
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
    directed: bool,
    timestamp: Optional[datetime],
    verification_state: str,
    match_method: str,
    options: CycleOptions,
) -> str:
    bucket = timestamp.isoformat() if timestamp is not None else "unknown"

    payload = {
        "source": source,
        "target": target,
        "kind": kind.value,
        "directed": bool(directed),
        "timestamp": bucket,
        "verification": verification_state,
        "method": match_method,
    }

    domain = f"muleguard.graph.cycles.edge.{_normalize_token(options.namespace)}"
    return _hmac_hex(options.salt, domain, _canonical_json(payload))[:40]


def _add_edge(
    graph: _Graph,
    source: str,
    target: str,
    kind: EdgeKind,
    directed: bool,
    timestamp: Optional[datetime],
    verification_state: str,
    match_method: str,
    options: CycleOptions,
    issues: list[CycleIssue],
) -> None:
    if not source or not target:
        return

    if kind == EdgeKind.TRANSACTION and not options.include_self_loops and source == target:
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

    if not directed and source > target:
        source, target = target, source

    edge = _Edge(
        source=source,
        target=target,
        kind=kind,
        directed=directed,
        timestamp=timestamp,
        verification_state=verification_state,
        match_method=match_method,
        edge_hash=_edge_hash(source, target, kind, directed, timestamp, verification_state, match_method, options),
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
    request: CycleRequest,
    options: CycleOptions,
    issues: list[CycleIssue],
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

    # Transactions -> directed settled-flow edges.
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

        if not sender or not receiver:
            continue

        _add_edge(
            graph,
            sender,
            receiver,
            EdgeKind.TRANSACTION,
            True,
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

        if not account_hash or not entity_hash:
            continue

        _ensure_node(graph, account_hash, NodeKind.ACCOUNT, timestamp, options, issues)
        _ensure_node(graph, entity_hash, NodeKind.ENTITY, timestamp, options, issues)

        _add_edge(
            graph,
            account_hash,
            entity_hash,
            EdgeKind.ENTITY_LINK,
            False,
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
        direction = _normalize_token(_pick(record, ("direction", "edge_direction"))) or "directed"
        directed = direction not in {"undirected", "both", "bidirectional"}

        if edge_kind == EdgeKind.ENTITY_LINK:
            directed = False

        timestamp = _parse_datetime(_pick(record, _TIMESTAMP_KEYS))
        valid_to = _parse_datetime(_pick(record, ("valid_to",)))

        if not _within_window(timestamp, valid_to, window_start, window_end):
            continue

        source = _resolve_node(source_raw, NodeKind.UNKNOWN, account_map, entity_map, options)
        target = _resolve_node(target_raw, NodeKind.UNKNOWN, account_map, entity_map, options)

        if not source or not target:
            continue

        verification = _upper_token(_pick(record, ("verification_state", "verification"))) or "UNVERIFIED"
        match_method = _upper_token(_pick(record, ("match_method", "method"))) or "EXACT"

        _add_edge(
            graph,
            source,
            target,
            edge_kind,
            directed,
            timestamp,
            verification,
            match_method,
            options,
            issues,
        )

    # Deterministic ordering and deduplication.
    graph.edges.sort(
        key=lambda edge: (
            edge.edge_hash,
            edge.source,
            edge.target,
            edge.kind.value,
            edge.timestamp.isoformat() if edge.timestamp else "",
        )
    )

    deduped: list[_Edge] = []
    seen_edges: set[str] = set()

    for edge in graph.edges:
        if edge.edge_hash in seen_edges:
            continue

        seen_edges.add(edge.edge_hash)
        deduped.append(edge)

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

        elif edge.kind == EdgeKind.ENTITY_LINK:
            for node_hash in (edge.source, edge.target):
                current = graph.node_kinds.get(node_hash, NodeKind.UNKNOWN)

                if current == NodeKind.UNKNOWN:
                    # Role is inferred conservatively; bipartite validation
                    # still requires explicit alternation where possible.
                    graph.node_kinds[node_hash] = NodeKind.UNKNOWN

    for node_hash in sorted(graph.nodes):
        graph.directed_neighbors[node_hash] = set()
        graph.undirected_neighbors[node_hash] = set()
        graph.projection_neighbors[node_hash] = set()
        graph.out_edges[node_hash] = []
        graph.und_edges[node_hash] = []

    for edge in graph.edges:
        if edge.directed:
            graph.directed_neighbors.setdefault(edge.source, set()).add(edge.target)
            graph.out_edges.setdefault(edge.source, []).append(edge)
            graph.directed_pairs.add((edge.source, edge.target))

            if edge.source != edge.target:
                graph.projection_neighbors.setdefault(edge.source, set()).add(edge.target)
                graph.projection_neighbors.setdefault(edge.target, set()).add(edge.source)
        else:
            graph.undirected_neighbors.setdefault(edge.source, set()).add(edge.target)
            graph.undirected_neighbors.setdefault(edge.target, set()).add(edge.source)
            graph.und_edges.setdefault(edge.source, []).append(edge)
            graph.und_edges.setdefault(edge.target, []).append(edge)
            graph.projection_neighbors.setdefault(edge.source, set()).add(edge.target)
            graph.projection_neighbors.setdefault(edge.target, set()).add(edge.source)

    for mapping in (
        graph.directed_neighbors,
        graph.undirected_neighbors,
        graph.projection_neighbors,
    ):
        for node_hash in list(mapping):
            mapping[node_hash] = set(sorted(mapping[node_hash]))

    graph.counts = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "directed_edges": sum(1 for edge in graph.edges if edge.directed),
        "undirected_edges": sum(1 for edge in graph.edges if not edge.directed),
        "self_loop_edges": sum(1 for edge in graph.edges if edge.source == edge.target),
        "transaction_edges": sum(1 for edge in graph.edges if edge.kind == EdgeKind.TRANSACTION),
        "entity_link_edges": sum(1 for edge in graph.edges if edge.kind == EdgeKind.ENTITY_LINK),
    }

    # Streaming deterministic graph fingerprint.
    digest = hashlib.sha256()
    digest.update(f"muleguard.graph.cycles.{CYCLES_VERSION}|{len(graph.nodes)}|{len(graph.edges)}\n".encode("utf-8", errors="replace"))

    for edge in graph.edges:
        digest.update(f"{edge.edge_hash}|{edge.kind.value}|{int(edge.directed)}\n".encode("utf-8", errors="replace"))

    graph.fingerprint = digest.hexdigest()

    return graph


# -----------------------------------------------------------------------------
# Strongly connected components: iterative Tarjan
# -----------------------------------------------------------------------------


def _strongly_connected_components(graph: _Graph, options: CycleOptions) -> tuple[tuple[str, ...], ...]:
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[tuple[str, ...]] = []
    counter = 0

    adjacency = {
        node_hash: sorted(graph.directed_neighbors.get(node_hash, ()))
        for node_hash in graph.nodes
    }

    for root in sorted(graph.nodes):
        if root in indices:
            continue

        counter += 1
        indices[root] = counter
        lowlinks[root] = counter
        stack.append(root)
        on_stack.add(root)

        work: list[tuple[str, int]] = [(root, 0)]

        while work:
            node_hash, cursor = work[-1]
            neighbors = adjacency.get(node_hash, ())

            if cursor >= len(neighbors):
                work.pop()

                if work:
                    parent = work[-1][0]
                    lowlinks[parent] = min(lowlinks[parent], lowlinks[node_hash])

                if lowlinks[node_hash] == indices[node_hash]:
                    component: list[str] = []

                    while stack:
                        member = stack.pop()
                        on_stack.discard(member)
                        component.append(member)

                        if member == node_hash:
                            break

                    components.append(tuple(sorted(component)))

                continue

            work[-1] = (node_hash, cursor + 1)
            neighbor = neighbors[cursor]

            if neighbor not in indices:
                counter += 1
                indices[neighbor] = counter
                lowlinks[neighbor] = counter
                stack.append(neighbor)
                on_stack.add(neighbor)
                work.append((neighbor, 0))
            elif neighbor in on_stack:
                lowlinks[node_hash] = min(lowlinks[node_hash], indices[neighbor])

    return tuple(sorted(components, key=lambda component: (len(component), component)))


# -----------------------------------------------------------------------------
# Search budget
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _SearchBudget:
    max_steps: int
    max_cycles: int
    steps: int = 0
    found: int = 0
    truncated: bool = False

    def consume(self) -> bool:
        self.steps += 1

        if self.steps > self.max_steps:
            self.truncated = True
            return False

        return True

    def record_cycle(self) -> bool:
        self.found += 1

        if self.found > self.max_cycles:
            self.truncated = True
            return False

        return True


# -----------------------------------------------------------------------------
# Cycle enumeration
# -----------------------------------------------------------------------------


def _enumerate_directed_cycles(
    graph: _Graph,
    sccs: Sequence[Sequence[str]],
    seeds: Optional[set[str]],
    options: CycleOptions,
    budget: _SearchBudget,
) -> list[tuple[str, ...]]:
    """
    Bounded simple directed cycle enumeration.

    Each simple cycle is enumerated once by restricting traversal to nodes
    greater than or equal to the cycle's minimum node. This is a bounded
    Johnson-style restriction, not a claim of complete enumeration when search
    budgets are exhausted.
    """
    found: list[tuple[str, ...]] = []

    for component in sccs:
        if len(component) < 2:
            continue

        if len(component) > options.max_scc_size:
            budget.truncated = True
            continue

        comp_set = set(component)

        for start in component:
            if seeds is not None and start not in seeds:
                continue

            if budget.truncated:
                return found

            allowed = {node_hash for node_hash in comp_set if node_hash >= start}
            path = [start]
            on_path = {start}

            adjacency = {
                node_hash: sorted(
                    neighbor
                    for neighbor in graph.directed_neighbors.get(node_hash, ())
                    if neighbor in allowed
                )
                for node_hash in allowed
            }

            work: list[tuple[str, int]] = [(start, 0)]

            while work:
                if budget.truncated:
                    return found

                node_hash, cursor = work[-1]
                neighbors = adjacency.get(node_hash, ())

                if cursor >= len(neighbors):
                    work.pop()

                    if path:
                        removed = path.pop()
                        on_path.discard(removed)

                    continue

                work[-1] = (node_hash, cursor + 1)

                if not budget.consume():
                    return found

                neighbor = neighbors[cursor]

                if neighbor == start:
                    if len(path) >= max(2, int(options.min_cycle_length)) and len(path) <= int(options.max_cycle_length):
                        if budget.record_cycle():
                            found.append(tuple(path))

                    continue

                if neighbor < start or neighbor not in allowed or neighbor in on_path:
                    continue

                if len(path) >= int(options.max_cycle_length):
                    continue

                path.append(neighbor)
                on_path.add(neighbor)
                work.append((neighbor, 0))

    return found


def _undirected_components(graph: _Graph, projection: bool) -> list[tuple[str, ...]]:
    adjacency = graph.projection_neighbors if projection else graph.undirected_neighbors
    seen: set[str] = set()
    components: list[tuple[str, ...]] = []

    for root in sorted(graph.nodes):
        if root in seen:
            continue

        queue = deque([root])
        seen.add(root)
        component: list[str] = []

        while queue:
            node_hash = queue.popleft()
            component.append(node_hash)

            for neighbor in sorted(adjacency.get(node_hash, ())):
                if neighbor in seen:
                    continue

                seen.add(neighbor)
                queue.append(neighbor)

        components.append(tuple(sorted(component)))

    return components


def _enumerate_undirected_cycles(
    graph: _Graph,
    *,
    bipartite: bool,
    projection: bool,
    options: CycleOptions,
    budget: _SearchBudget,
) -> list[tuple[str, ...]]:
    """
    Bounded simple undirected cycle enumeration.

    For bipartite entity-link graphs, traversal requires alternating account and
    entity node kinds and even cycle length >= 4.

    For weak projection, direction is intentionally ignored and results are
    labelled as weaker structural signals only.
    """
    found: list[tuple[str, ...]] = []
    adjacency_source = graph.projection_neighbors if projection else graph.undirected_neighbors
    components = _undirected_components(graph, projection=projection)
    min_length = 4 if bipartite else max(3, int(options.min_cycle_length))

    for component in components:
        if len(component) < min_length:
            continue

        if len(component) > options.max_scc_size:
            budget.truncated = True
            continue

        comp_set = set(component)

        for start in component:
            if budget.truncated:
                return found

            allowed = {node_hash for node_hash in comp_set if node_hash >= start}

            adjacency = {
                node_hash: sorted(
                    neighbor
                    for neighbor in adjacency_source.get(node_hash, ())
                    if neighbor in allowed
                )
                for node_hash in allowed
            }

            path = [start]
            on_path = {start}

            # Frame: (node, parent, cursor)
            work: list[tuple[str, Optional[str], int]] = [(start, None, 0)]

            while work:
                if budget.truncated:
                    return found

                node_hash, parent, cursor = work[-1]
                neighbors = adjacency.get(node_hash, ())

                if cursor >= len(neighbors):
                    work.pop()

                    if path:
                        removed = path.pop()
                        on_path.discard(removed)

                    continue

                work[-1] = (node_hash, parent, cursor + 1)

                if not budget.consume():
                    return found

                neighbor = neighbors[cursor]

                if neighbor == parent:
                    continue

                if neighbor == start:
                    length = len(path)

                    if length >= min_length and length <= int(options.max_cycle_length):
                        if not bipartite or length % 2 == 0:
                            if budget.record_cycle():
                                found.append(tuple(path))

                    continue

                if neighbor < start or neighbor not in allowed or neighbor in on_path:
                    continue

                if len(path) >= int(options.max_cycle_length):
                    continue

                if bipartite and options.require_alternating_bipartite:
                    current_kind = graph.node_kinds.get(node_hash, NodeKind.UNKNOWN)
                    neighbor_kind = graph.node_kinds.get(neighbor, NodeKind.UNKNOWN)

                    if current_kind == NodeKind.UNKNOWN or neighbor_kind == NodeKind.UNKNOWN:
                        continue

                    if current_kind == neighbor_kind:
                        continue

                path.append(neighbor)
                on_path.add(neighbor)
                work.append((neighbor, node_hash, 0))

    return found


def _detect_self_loops(graph: _Graph, options: CycleOptions) -> list[tuple[str, ...]]:
    if not options.include_self_loops:
        return []

    out: list[tuple[str, ...]] = []
    seen: set[str] = set()

    for edge in graph.edges:
        if edge.source != edge.target:
            continue

        if edge.edge_hash in seen:
            continue

        seen.add(edge.edge_hash)
        out.append((edge.source,))

    return out


def _detect_reciprocal_pairs(graph: _Graph, options: CycleOptions) -> list[tuple[str, ...]]:
    if not options.include_reciprocal:
        return []

    out: list[tuple[str, ...]] = []
    seen: set[tuple[str, str]] = set()

    for source, target in sorted(graph.directed_pairs):
        if source == target:
            continue

        pair = tuple(sorted((source, target)))

        if pair in seen:
            continue

        if (pair[1], pair[0]) in graph.directed_pairs:
            seen.add(pair)
            out.append(pair)

    return out


# -----------------------------------------------------------------------------
# Canonicalization and materialization
# -----------------------------------------------------------------------------


def _canonical_directed_nodes(nodes: Sequence[str]) -> tuple[str, ...]:
    if not nodes:
        return ()

    values = tuple(nodes)
    min_index = min(range(len(values)), key=lambda index: (values[index], index))
    rotated = values[min_index:] + values[:min_index]
    return rotated


def _canonical_undirected_nodes(nodes: Sequence[str]) -> tuple[str, ...]:
    if not nodes:
        return ()

    values = tuple(nodes)
    forward = _canonical_directed_nodes(values)
    reverse = _canonical_directed_nodes(tuple(reversed(values)))
    return min(forward, reverse)


def _cycle_fingerprint(kind: CycleKind, nodes: Sequence[str], options: CycleOptions) -> str:
    if kind in _UNDIRECTED_CYCLE_KINDS:
        canonical = _canonical_undirected_nodes(nodes)
    else:
        canonical = _canonical_directed_nodes(nodes)

    payload = {
        "kind": kind.value,
        "nodes": list(canonical),
    }

    domain = f"muleguard.graph.cycles.signature.{_normalize_token(options.namespace)}"
    return _hmac_hex(options.salt, domain, _canonical_json(payload))[:40]


def _find_directed_edge(graph: _Graph, source: str, target: str) -> Optional[_Edge]:
    candidates = [
        edge
        for edge in graph.out_edges.get(source, ())
        if edge.directed and edge.target == target
    ]

    if not candidates:
        return None

    return min(candidates, key=lambda edge: edge.edge_hash)


def _find_undirected_edge(graph: _Graph, source: str, target: str, *, projection: bool = False) -> Optional[_Edge]:
    candidates: list[_Edge] = []

    if projection:
        for edge in graph.edges:
            if {edge.source, edge.target} == {source, target}:
                candidates.append(edge)
    else:
        for edge in graph.und_edges.get(source, ()):
            if {edge.source, edge.target} == {source, target}:
                candidates.append(edge)

        for edge in graph.und_edges.get(target, ()):
            if {edge.source, edge.target} == {source, target}:
                candidates.append(edge)

    if not candidates:
        return None

    return min(candidates, key=lambda edge: edge.edge_hash)


@dataclass(frozen=True, slots=True)
class CycleEdge:
    """
    Safe pseudonymous cycle edge reference.
    """

    source_hash: str
    target_hash: str
    edge_kind: str
    edge_fingerprint: str
    occurred_at: Optional[str] = None
    verification_state: str = "UNVERIFIED"
    match_method: str = "EXACT"
    directed: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_hash": self.source_hash,
            "target_hash": self.target_hash,
            "edge_kind": self.edge_kind,
            "edge_fingerprint": self.edge_fingerprint,
            "occurred_at": self.occurred_at,
            "verification_state": self.verification_state,
            "match_method": self.match_method,
            "directed": bool(self.directed),
        }


def _to_cycle_edge(edge: _Edge) -> CycleEdge:
    return CycleEdge(
        source_hash=edge.source,
        target_hash=edge.target,
        edge_kind=edge.kind.value,
        edge_fingerprint=edge.edge_hash,
        occurred_at=edge.timestamp.isoformat() if edge.timestamp else None,
        verification_state=edge.verification_state,
        match_method=edge.match_method,
        directed=bool(edge.directed),
    )


def _materialize_cycle(
    graph: _Graph,
    nodes: Sequence[str],
    kind: CycleKind,
    options: CycleOptions,
) -> Optional[tuple[tuple[str, ...], tuple[CycleEdge, ...]]]:
    values = tuple(nodes)

    if not values:
        return None

    if kind == CycleKind.SELF_LOOP:
        if len(values) != 1:
            return None

        edge = _find_directed_edge(graph, values[0], values[0])

        if edge is None:
            edge = _find_undirected_edge(graph, values[0], values[0], projection=True)

        if edge is None:
            return None

        return values, (_to_cycle_edge(edge),)

    length = len(values)

    if length < 2:
        return None

    edges: list[CycleEdge] = []

    for index in range(length):
        source = values[index]
        target = values[(index + 1) % length]

        if kind in _DIRECTED_CYCLE_KINDS:
            edge = _find_directed_edge(graph, source, target)

            if edge is None and kind == CycleKind.RECIPROCAL:
                # Reciprocal pairs are materialized from both directed edges.
                edge = _find_directed_edge(graph, source, target)

            if edge is None:
                return None
        elif kind == CycleKind.WEAK_PROJECTION:
            edge = _find_undirected_edge(graph, source, target, projection=True)

            if edge is None:
                return None
        else:
            edge = _find_undirected_edge(graph, source, target)

            if edge is None:
                return None

        edges.append(_to_cycle_edge(edge))

    return values, tuple(edges)


# -----------------------------------------------------------------------------
# Scoring and validation
# -----------------------------------------------------------------------------


def _severity_for_score(score: float, options: CycleOptions) -> CycleSeverity:
    thresholds = options.risk_thresholds

    if score >= float(thresholds.get("critical", 0.85)):
        return CycleSeverity.CRITICAL

    if score >= float(thresholds.get("high", 0.65)):
        return CycleSeverity.HIGH

    if score >= float(thresholds.get("medium", 0.45)):
        return CycleSeverity.MEDIUM

    if score >= float(thresholds.get("low", 0.25)):
        return CycleSeverity.LOW

    return CycleSeverity.INFO


def _score_cycle(
    graph: _Graph,
    nodes: Sequence[str],
    edges: Sequence[CycleEdge],
    kind: CycleKind,
    options: CycleOptions,
) -> tuple[float, CycleSeverity, dict[str, float], tuple[str, ...]]:
    length = len(nodes)
    directed = kind in _DIRECTED_CYCLE_KINDS

    if length <= 1:
        length_factor = 0.60
    else:
        length_factor = 1.0 / (1.0 + 0.12 * max(0, length - 2))

    reciprocity = 0.0

    if directed and length >= 2:
        matches = 0

        for index in range(length):
            source = nodes[index]
            target = nodes[(index + 1) % length]

            if (target, source) in graph.directed_pairs:
                matches += 1

        reciprocity = float(matches) / float(length)

    verified_count = 0

    for edge in edges:
        if edge.verification_state in _VERIFIED_STATES or edge.match_method in _EXACT_METHODS:
            verified_count += 1

    verification_fraction = float(verified_count) / float(len(edges)) if edges else 0.0

    timestamps: list[datetime] = []

    for edge in edges:
        parsed = _parse_datetime(edge.occurred_at)

        if parsed is not None:
            timestamps.append(parsed)

    temporal_span_hours: Optional[float] = None
    temporal_factor = 0.5

    if len(timestamps) >= 2:
        span = max(timestamps) - min(timestamps)
        temporal_span_hours = _round6(max(0.0, span.total_seconds() / 3600.0))
        temporal_factor = 1.0 / (1.0 + float(temporal_span_hours) / 72.0)

    entity_share = 0.0

    if kind == CycleKind.ENTITY_LINK_BIPARTITE and length > 0:
        entity_count = sum(
            1
            for node_hash in nodes
            if graph.node_kinds.get(node_hash) == NodeKind.ENTITY
        )
        entity_share = _clip(float(entity_count) / float(length), 0.0, 1.0, 0.0)

    structure_factor = entity_share if kind == CycleKind.ENTITY_LINK_BIPARTITE else reciprocity

    score = (
        0.30 * length_factor
        + 0.25 * reciprocity
        + 0.20 * verification_fraction
        + 0.15 * temporal_factor
        + 0.10 * structure_factor
    )

    if kind == CycleKind.WEAK_PROJECTION:
        score *= 0.55

    if kind == CycleKind.SELF_LOOP:
        score *= 0.65

    score = _round6(_clip(score, 0.0, 1.0, 0.0))
    severity = _severity_for_score(score, options)

    features = {
        "length": float(length),
        "length_factor": _round6(length_factor),
        "reciprocity": _round6(reciprocity),
        "verification_fraction": _round6(verification_fraction),
        "temporal_factor": _round6(temporal_factor),
        "entity_share": _round6(entity_share),
        "structure_factor": _round6(structure_factor),
        "score": score,
    }

    if temporal_span_hours is not None:
        features["temporal_span_hours"] = temporal_span_hours

    reasons: list[str] = []

    if kind == CycleKind.SELF_LOOP:
        reasons.append("self_reference_pattern")
    elif kind == CycleKind.RECIPROCAL:
        reasons.append("reciprocal_flow_pattern")
    elif kind == CycleKind.ENTITY_LINK_BIPARTITE:
        reasons.append("shared_entity_association_cycle")
    elif kind == CycleKind.WEAK_PROJECTION:
        reasons.append("weak_undirected_projection_cycle")
    else:
        reasons.append("directed_structural_cycle")

    if length >= 2 and length <= 4:
        reasons.append("short_cycle_structure")

    if reciprocity >= 0.5:
        reasons.append("reciprocal_edges_present")

    if verification_fraction < 0.5:
        reasons.append("unverified_or_heuristic_edges_present")

    if temporal_span_hours is not None and temporal_span_hours > 168.0:
        reasons.append("wide_temporal_span")

    if kind == CycleKind.ENTITY_LINK_BIPARTITE and entity_share >= 0.25:
        reasons.append("shared_entity_cluster_signal")

    reasons.append("operational_lead_only_not_proof")

    return score, severity, features, tuple(reasons)


def _validate_candidate(
    graph: _Graph,
    nodes: Sequence[str],
    edges: Sequence[CycleEdge],
    kind: CycleKind,
    options: CycleOptions,
) -> list[CycleIssue]:
    issues: list[CycleIssue] = []
    length = len(nodes)

    if length == 0:
        issues.append(
            CycleIssue(
                severity=IssueSeverity.ERROR,
                code="empty_cycle",
                message="Cycle has no nodes.",
            )
        )
        return issues

    if kind != CycleKind.SELF_LOOP:
        if options.require_distinct_cycle_nodes and len(set(nodes)) != length:
            issues.append(
                CycleIssue(
                    severity=IssueSeverity.ERROR,
                    code="duplicate_cycle_node",
                    message="Cycle contains repeated non-closing nodes.",
                )
            )

        if length < int(options.min_cycle_length) or length > int(options.max_cycle_length):
            issues.append(
                CycleIssue(
                    severity=IssueSeverity.ERROR,
                    code="cycle_length_out_of_bounds",
                    message="Cycle length is outside configured bounds.",
                )
            )

    if len(edges) != (1 if kind == CycleKind.SELF_LOOP else length):
        issues.append(
            CycleIssue(
                severity=IssueSeverity.ERROR,
                code="cycle_edge_count_mismatch",
                message="Cycle edge count does not match cycle structure.",
            )
        )

    if kind == CycleKind.ENTITY_LINK_BIPARTITE:
        if length < 4 or length % 2 != 0:
            issues.append(
                CycleIssue(
                    severity=IssueSeverity.ERROR,
                    code="invalid_bipartite_cycle_length",
                    message="Entity-link cycles must be even and at least four nodes.",
                )
            )

        if options.require_alternating_bipartite:
            for index in range(length):
                current = graph.node_kinds.get(nodes[index], NodeKind.UNKNOWN)
                neighbor = graph.node_kinds.get(nodes[(index + 1) % length], NodeKind.UNKNOWN)

                if current == NodeKind.UNKNOWN or neighbor == NodeKind.UNKNOWN or current == neighbor:
                    issues.append(
                        CycleIssue(
                            severity=IssueSeverity.ERROR,
                            code="invalid_bipartite_alternation",
                            message="Entity-link cycle does not alternate account and entity nodes.",
                        )
                    )
                    break

    for edge in edges:
        if edge.source_hash not in graph.nodes or edge.target_hash not in graph.nodes:
            issues.append(
                CycleIssue(
                    severity=IssueSeverity.ERROR,
                    code="cycle_edge_reference_missing",
                    message="Cycle edge references an unknown node.",
                )
            )
            break

        timestamp = _parse_datetime(edge.occurred_at)

        if timestamp is not None and timestamp > _now_utc() + timedelta(days=1):
            issues.append(
                CycleIssue(
                    severity=IssueSeverity.WARNING,
                    code="future_cycle_edge_timestamp",
                    message="Cycle edge timestamp is in the future.",
                )
            )

    return issues


# -----------------------------------------------------------------------------
# Public cycle models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CycleCandidate:
    """
    One bounded cycle candidate.

    Internal representations may include pseudonymous node hashes. Public
    summaries deliberately omit node and edge identifiers.
    """

    fingerprint: str = ""
    kind: CycleKind | str = CycleKind.DIRECTED_SIMPLE
    nodes: tuple[str, ...] = ()
    edges: tuple[CycleEdge, ...] = ()
    length: int = 0
    score: float = 0.0
    severity: CycleSeverity | str = CycleSeverity.INFO
    features: Mapping[str, float] = dataclass_field(default_factory=dict)
    reasons: tuple[str, ...] = ()
    valid: bool = True
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _normalize_enum(CycleKind, self.kind, CycleKind.DIRECTED_SIMPLE))
        object.__setattr__(self, "nodes", tuple(_clean_text(node, _MAX_NODE_HASH_LENGTH).lower() for node in (self.nodes or ())))
        object.__setattr__(self, "edges", tuple(self.edges or ()))
        object.__setattr__(self, "length", max(0, _as_int(self.length, len(self.nodes))))
        object.__setattr__(self, "score", _round6(_clip(self.score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "severity", _normalize_enum(CycleSeverity, self.severity, CycleSeverity.INFO))
        object.__setattr__(self, "features", MappingProxyType({str(key): _round6(float(value)) for key, value in (self.features or {}).items()}))
        object.__setattr__(self, "reasons", tuple(_clean_text(reason, 200) for reason in (self.reasons or ()))[:50])
        object.__setattr__(self, "valid", _as_bool(self.valid, True))
        object.__setattr__(self, "first_seen", _clean_text(self.first_seen, 64) or None)
        object.__setattr__(self, "last_seen", _clean_text(self.last_seen, 64) or None)
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", _fingerprint_payload({"kind": _enum_value(self.kind), "nodes": list(self.nodes)}))

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return a safe summary without node or edge identifiers.
        """
        return {
            "cycle_fingerprint": self.fingerprint,
            "kind": _enum_value(self.kind, CycleKind.DIRECTED_SIMPLE.value),
            "length": int(self.length),
            "score": float(self.score),
            "severity": _enum_value(self.severity, CycleSeverity.INFO.value),
            "valid": bool(self.valid),
            "reasons": list(self.reasons),
            "features": dict(self.features),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "metadata": _safe_detail_value(self.metadata),
            "nodes_omitted": True,
            "edges_omitted": True,
        }

    def to_internal_dict(self) -> dict[str, Any]:
        """
        Return a fuller internal representation with pseudonymous references.
        """
        payload = self.to_public_dict()
        payload.pop("nodes_omitted", None)
        payload.pop("edges_omitted", None)
        payload["canonical_nodes"] = list(self.nodes)
        payload["edges"] = [edge.to_dict() for edge in self.edges]
        payload["internal_only"] = True
        return payload


@dataclass(frozen=True, slots=True)
class CycleGraphSummary:
    """
    Safe bounded graph summary.
    """

    node_count: int = 0
    edge_count: int = 0
    directed_edge_count: int = 0
    undirected_edge_count: int = 0
    transaction_edge_count: int = 0
    entity_link_edge_count: int = 0
    scc_count: int = 0
    max_scc_size: int = 0
    self_loop_count: int = 0
    reciprocal_pair_count: int = 0
    fingerprint: str = ""
    truncated: Mapping[str, bool] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": int(self.node_count),
            "edge_count": int(self.edge_count),
            "directed_edge_count": int(self.directed_edge_count),
            "undirected_edge_count": int(self.undirected_edge_count),
            "transaction_edge_count": int(self.transaction_edge_count),
            "entity_link_edge_count": int(self.entity_link_edge_count),
            "scc_count": int(self.scc_count),
            "max_scc_size": int(self.max_scc_size),
            "self_loop_count": int(self.self_loop_count),
            "reciprocal_pair_count": int(self.reciprocal_pair_count),
            "fingerprint": self.fingerprint,
            "truncated": dict(self.truncated),
            "raw_values_retained": False,
        }


@dataclass(frozen=True, slots=True)
class CycleAnalysisResult:
    """
    Safe bounded cycle-analysis result.
    """

    ok: bool = True
    status: AnalysisStatus | str = AnalysisStatus.PASSED
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    graph_summary: CycleGraphSummary = dataclass_field(default_factory=CycleGraphSummary)
    cycles: tuple[CycleCandidate, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[CycleIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(self, "status", _normalize_enum(AnalysisStatus, self.status, AnalysisStatus.PASSED))
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "cycles", tuple(self.cycles or ()))
        object.__setattr__(self, "counts", MappingProxyType({str(key): max(0, _as_int(value, 0)) for key, value in (self.counts or {}).items()}))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": CYCLES_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, AnalysisStatus.PASSED.value),
                        "graph": self.graph_summary.fingerprint,
                        "cycle_count": len(self.cycles),
                        "cycle_fingerprints": [cycle.fingerprint for cycle in self.cycles[:64]],
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
            "graph_summary": self.graph_summary.to_dict(),
            "cycles": [cycle.to_public_dict() for cycle in self.cycles],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_CYCLE_CAVEATS),
            "safety_flags": dict(_CYCLE_SAFETY_FLAGS),
        }

    def to_internal_dict(self) -> dict[str, Any]:
        payload = self.to_public_dict()
        payload["cycles"] = [cycle.to_internal_dict() for cycle in self.cycles]
        payload["internal_only"] = True
        return payload


# -----------------------------------------------------------------------------
# Process-local cycle cache
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _CachedCycleResult:
    result: CycleAnalysisResult
    registered_at: datetime = dataclass_field(default_factory=_now_utc)


class CycleCache:
    """
    Bounded process-local cycle-analysis cache.

    This cache is not durable, not distributed, and not production-ready.
    """

    def __init__(self, max_entries: int = _DEFAULT_MAX_CACHE_ENTRIES) -> None:
        self.max_entries = max(1, int(max_entries))
        self._entries: OrderedDict[str, _CachedCycleResult] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[CycleAnalysisResult]:
        clean_key = _clean_text(key, 256)

        with self._lock:
            entry = self._entries.get(clean_key)

            if entry is None:
                return None

            self._entries.move_to_end(clean_key)
            return entry.result

    def set(self, key: str, result: CycleAnalysisResult) -> str:
        clean_key = _clean_text(key, 256) or result.fingerprint

        with self._lock:
            self._entries[clean_key] = _CachedCycleResult(result=result, registered_at=_now_utc())
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


_default_cache: Optional[CycleCache] = None
_default_cache_lock = threading.Lock()


def get_cycle_cache(max_entries: int | None = None, *, rebuild: bool = False) -> CycleCache:
    global _default_cache

    with _default_cache_lock:
        if _default_cache is None or rebuild:
            _default_cache = CycleCache(max_entries=max_entries if max_entries is not None else _DEFAULT_MAX_CACHE_ENTRIES)

        return _default_cache


# -----------------------------------------------------------------------------
# Cycle engine
# -----------------------------------------------------------------------------


class CycleEngine:
    """
    Bounded deterministic synthetic graph cycle engine.

    This engine detects structural investigative leads only. It does not
    authorize actions, does not deploy models, does not persist durable
    artifacts, and must not trigger automatic adverse customer action.
    """

    def __init__(self, options: CycleOptions | None = None, cache: CycleCache | None = None) -> None:
        self.options = options or CycleOptions.from_settings()
        self.cache = cache or get_cycle_cache(self.options.max_cache_entries)
        self._lock = threading.RLock()

    def _local_seeds(self, graph: _Graph, options: CycleOptions) -> set[str]:
        degrees = {
            node_hash: len(graph.directed_neighbors.get(node_hash, ())) + len(graph.undirected_neighbors.get(node_hash, ()))
            for node_hash in graph.nodes
        }

        ranked = sorted(
            degrees.items(),
            key=lambda item: (-int(item[1]), item[0]),
        )

        seed_count = max(1, min(int(options.max_search_seeds), len(ranked)))
        return {node_hash for node_hash, _degree in ranked[:seed_count]}

    def _build_candidates(
        self,
        graph: _Graph,
        options: CycleOptions,
        issues: list[CycleIssue],
        start_time: float,
    ) -> tuple[list[CycleCandidate], dict[str, int]]:
        raw_patterns: list[tuple[CycleKind, tuple[str, ...]]] = []
        counts: dict[str, int] = {
            "self_loop_patterns": 0,
            "reciprocal_patterns": 0,
            "directed_patterns": 0,
            "bipartite_patterns": 0,
            "undirected_patterns": 0,
            "weak_projection_patterns": 0,
        }

        mode = _normalize_enum(CycleMode, options.mode, CycleMode.HYBRID)

        if mode != CycleMode.SCC_ONLY:
            if options.include_self_loops:
                for nodes in _detect_self_loops(graph, options):
                    raw_patterns.append((CycleKind.SELF_LOOP, nodes))
                    counts["self_loop_patterns"] += 1

            if options.include_reciprocal:
                for nodes in _detect_reciprocal_pairs(graph, options):
                    raw_patterns.append((CycleKind.RECIPROCAL, nodes))
                    counts["reciprocal_patterns"] += 1

        budget = _SearchBudget(
            max_steps=int(options.max_search_steps),
            max_cycles=int(options.max_cycles),
        )

        if mode != CycleMode.SCC_ONLY and options.include_directed_cycles:
            seeds: Optional[set[str]] = None

            if mode == CycleMode.LOCAL_HEURISTIC:
                seeds = self._local_seeds(graph, options)

            directed_nodes = _enumerate_directed_cycles(
                graph,
                graph.sccs,
                seeds,
                options,
                budget,
            )

            for nodes in directed_nodes:
                if len(nodes) == 2:
                    kind = CycleKind.RECIPROCAL
                else:
                    kind = CycleKind.DIRECTED_SIMPLE

                raw_patterns.append((kind, nodes))
                counts["directed_patterns"] += 1

        if mode != CycleMode.SCC_ONLY and options.include_entity_link_cycles and graph.undirected_neighbors:
            bipartite_budget = _SearchBudget(
                max_steps=max(1000, int(options.max_search_steps) // 2),
                max_cycles=max(1, int(options.max_cycles) // 2),
            )

            bipartite_nodes = _enumerate_undirected_cycles(
                graph,
                bipartite=True,
                projection=False,
                options=options,
                budget=bipartite_budget,
            )

            for nodes in bipartite_nodes:
                raw_patterns.append((CycleKind.ENTITY_LINK_BIPARTITE, nodes))
                counts["bipartite_patterns"] += 1

            if bipartite_budget.truncated:
                budget.truncated = True

        if mode != CycleMode.SCC_ONLY and options.include_undirected_cycles and graph.undirected_neighbors:
            undirected_budget = _SearchBudget(
                max_steps=max(1000, int(options.max_search_steps) // 3),
                max_cycles=max(1, int(options.max_cycles) // 3),
            )

            undirected_nodes = _enumerate_undirected_cycles(
                graph,
                bipartite=False,
                projection=False,
                options=options,
                budget=undirected_budget,
            )

            for nodes in undirected_nodes:
                raw_patterns.append((CycleKind.UNDIRECTED_SIMPLE, nodes))
                counts["undirected_patterns"] += 1

            if undirected_budget.truncated:
                budget.truncated = True

        if mode != CycleMode.SCC_ONLY and options.include_weak_projection and graph.projection_neighbors:
            weak_budget = _SearchBudget(
                max_steps=max(1000, int(options.max_search_steps) // 4),
                max_cycles=max(1, int(options.max_cycles) // 4),
            )

            weak_nodes = _enumerate_undirected_cycles(
                graph,
                bipartite=False,
                projection=True,
                options=options,
                budget=weak_budget,
            )

            for nodes in weak_nodes:
                raw_patterns.append((CycleKind.WEAK_PROJECTION, nodes))
                counts["weak_projection_patterns"] += 1

            if weak_budget.truncated:
                budget.truncated = True

        deduped: dict[tuple[str, str], CycleCandidate] = {}
        duplicates = 0
        invalid = 0
        detected = 0

        for kind, nodes in raw_patterns:
            if _time_exceeded(start_time, options.max_time_ms):
                budget.truncated = True
                break

            detected += 1
            materialized = _materialize_cycle(graph, nodes, kind, options)

            if materialized is None:
                invalid += 1
                continue

            materialized_nodes, materialized_edges = materialized

            validation_issues = _validate_candidate(graph, materialized_nodes, materialized_edges, kind, options)

            if _has_error(validation_issues):
                invalid += 1
                continue

            score, severity, features, reasons = _score_cycle(
                graph,
                materialized_nodes,
                materialized_edges,
                kind,
                options,
            )

            fingerprint = _cycle_fingerprint(kind, materialized_nodes, options)
            key = (kind.value, fingerprint)

            timestamps = [
                _parse_datetime(edge.occurred_at)
                for edge in materialized_edges
                if _parse_datetime(edge.occurred_at) is not None
            ]

            first_seen = min(timestamps).isoformat() if timestamps else None
            last_seen = max(timestamps).isoformat() if timestamps else None

            candidate = CycleCandidate(
                fingerprint=fingerprint,
                kind=kind,
                nodes=materialized_nodes,
                edges=materialized_edges,
                length=len(materialized_nodes),
                score=score,
                severity=severity,
                features=features,
                reasons=reasons,
                valid=not _has_error(validation_issues),
                first_seen=first_seen,
                last_seen=last_seen,
                metadata={
                    "directed": kind in _DIRECTED_CYCLE_KINDS,
                    "bipartite": kind == CycleKind.ENTITY_LINK_BIPARTITE,
                    "weak_projection": kind == CycleKind.WEAK_PROJECTION,
                    "operational_lead_only": True,
                    "raw_values_retained": False,
                },
            )

            existing = deduped.get(key)

            if existing is not None:
                duplicates += 1

                if (
                    float(candidate.score) > float(existing.score)
                    or (
                        float(candidate.score) == float(existing.score)
                        and candidate.nodes < existing.nodes
                    )
                ):
                    deduped[key] = candidate

                continue

            deduped[key] = candidate

        candidates = sorted(
            deduped.values(),
            key=lambda candidate: (
                -float(candidate.score),
                _enum_value(candidate.kind),
                candidate.fingerprint,
                candidate.nodes,
            ),
        )

        counts["detected_patterns"] = detected
        counts["duplicates_removed"] = duplicates
        counts["invalid_candidates"] = invalid
        counts["unique_candidates"] = len(candidates)
        counts["returned_candidates"] = min(len(candidates), int(options.max_candidates))

        if budget.truncated or any(graph.truncated.values()):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="cycle_detection_truncated",
                message="Cycle detection was truncated by configured search, graph, or time limits.",
                details={
                    "search_steps": budget.steps,
                    "search_cycles": budget.found,
                    "graph_truncated": dict(graph.truncated),
                },
            )

        return candidates[: options.max_candidates], counts

    def analyze(self, request: Any) -> CycleAnalysisResult:
        """
        Run one bounded synthetic cycle-analysis job.
        """
        opts = self.options
        issues: list[CycleIssue] = []
        generated_at = _now_utc()
        start_time = time.monotonic()

        req = _coerce_request(request)
        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": CYCLES_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: AnalysisStatus,
            graph_summary: Optional[CycleGraphSummary] = None,
            candidates: Sequence[CycleCandidate] = (),
            counts: Optional[Mapping[str, int]] = None,
            cache_key: Optional[str] = None,
        ) -> CycleAnalysisResult:
            resolved_counts: dict[str, int] = {
                "nodes": 0,
                "edges": 0,
                "scc_count": 0,
                "returned_candidates": len(candidates),
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update({str(key): max(0, _as_int(value, 0)) for key, value in counts.items()})

            resolved_counts["issues"] = len(issues)
            resolved_counts["returned_candidates"] = len(candidates)

            metadata = {
                "cycles_version": CYCLES_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "mode": _enum_value(opts.mode, CycleMode.HYBRID.value),
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
                "caveats": list(_CYCLE_CAVEATS),
                "safety_flags": dict(_CYCLE_SAFETY_FLAGS),
            }

            return CycleAnalysisResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=generated_at,
                duration_ms=_elapsed_ms(start_time),
                graph_summary=graph_summary or CycleGraphSummary(),
                cycles=tuple(candidates),
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
                code="cycle_engine_disabled",
                message="Cycle engine is disabled.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Cycle engine requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Cycle engine is blocked in production-like environments.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_cycle_action_metadata",
                message="Cycle request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        with self._lock:
            graph = _build_graph(req, opts, issues, start_time)

            if not graph.nodes or not graph.edges:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="empty_cycle_graph",
                    message="No valid graph nodes or edges were available for cycle detection.",
                )
                return make_result(
                    False,
                    AnalysisStatus.SKIPPED,
                    graph_summary=CycleGraphSummary(
                        node_count=len(graph.nodes),
                        edge_count=len(graph.edges),
                        fingerprint=graph.fingerprint,
                        truncated=dict(graph.truncated),
                    ),
                )

            graph.sccs = _strongly_connected_components(graph, opts)

            cache_key: Optional[str] = None

            if opts.use_cache:
                cache_key = _sha256_hex(
                    _canonical_json(
                        {
                            "graph": graph.fingerprint,
                            "options": opts.safe_summary(),
                            "mode": _enum_value(opts.mode, CycleMode.HYBRID.value),
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

            candidates, counts = self._build_candidates(graph, opts, issues, start_time)

            reciprocal_count = sum(1 for candidate in candidates if candidate.kind == CycleKind.RECIPROCAL)
            self_loop_count = sum(1 for candidate in candidates if candidate.kind == CycleKind.SELF_LOOP)

            graph_summary = CycleGraphSummary(
                node_count=len(graph.nodes),
                edge_count=len(graph.edges),
                directed_edge_count=graph.counts.get("directed_edges", 0),
                undirected_edge_count=graph.counts.get("undirected_edges", 0),
                transaction_edge_count=graph.counts.get("transaction_edges", 0),
                entity_link_edge_count=graph.counts.get("entity_link_edges", 0),
                scc_count=len(graph.sccs),
                max_scc_size=max((len(component) for component in graph.sccs), default=0),
                self_loop_count=self_loop_count,
                reciprocal_pair_count=reciprocal_count,
                fingerprint=graph.fingerprint,
                truncated=dict(graph.truncated),
            )

            counts.update(
                {
                    "nodes": len(graph.nodes),
                    "edges": len(graph.edges),
                    "scc_count": len(graph.sccs),
                }
            )

            status = AnalysisStatus.PASSED

            if _has_error(issues):
                status = AnalysisStatus.FAILED
            elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
                status = AnalysisStatus.DEGRADED
            elif not candidates:
                status = AnalysisStatus.PASSED

            result = make_result(
                ok=status in {AnalysisStatus.PASSED, AnalysisStatus.DEGRADED},
                status=status,
                graph_summary=graph_summary,
                candidates=candidates,
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
            "caveats": list(_CYCLE_CAVEATS),
            "safety_flags": dict(_CYCLE_SAFETY_FLAGS),
        }


_default_engine: Optional[CycleEngine] = None
_default_engine_lock = threading.Lock()


def get_cycle_options(settings: Any | None = None) -> CycleOptions:
    """
    Return cycle options from settings.
    """
    return CycleOptions.from_settings(settings)


def get_cycle_engine(
    options: CycleOptions | None = None,
    *,
    rebuild: bool = False,
) -> CycleEngine:
    """
    Return a process-wide cycle engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = CycleEngine(options=options or CycleOptions.from_settings())

        return _default_engine


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def detect_cycles(
    request: Any,
    options: CycleOptions | None = None,
    *,
    engine: CycleEngine | None = None,
) -> CycleAnalysisResult:
    """
    Detect bounded synthetic graph cycle candidates.
    """
    active_engine = engine or get_cycle_engine(options)
    return active_engine.analyze(request)


def detect_cycle_candidates(
    request: Any,
    options: CycleOptions | None = None,
    *,
    engine: CycleEngine | None = None,
) -> CycleAnalysisResult:
    """
    Alias for `detect_cycles`.
    """
    return detect_cycles(request, options=options, engine=engine)


def analyze_graph_cycles(
    request: Any,
    options: CycleOptions | None = None,
    *,
    engine: CycleEngine | None = None,
) -> CycleAnalysisResult:
    """
    Alias for `detect_cycles`.
    """
    return detect_cycles(request, options=options, engine=engine)


def validate_cycle_candidate(
    candidate: CycleCandidate,
    edges: Any,
    options: CycleOptions | None = None,
) -> tuple[bool, list[dict[str, Any]]]:
    """
    Validate one cycle candidate against a bounded edge set.

    This helper builds a small process-local graph from the supplied edges and
    checks structural consistency. It does not persist anything.
    """
    opts = options or CycleOptions.from_settings()
    issues: list[CycleIssue] = []
    start_time = time.monotonic()

    request = CycleRequest(edges=edges)
    graph = _build_graph(request, opts, issues, start_time)

    validation_issues = _validate_candidate(
        graph,
        candidate.nodes,
        candidate.edges,
        _normalize_enum(CycleKind, candidate.kind, CycleKind.DIRECTED_SIMPLE),
        opts,
    )

    all_issues = list(issues) + validation_issues

    if candidate.fingerprint:
        expected = _cycle_fingerprint(
            _normalize_enum(CycleKind, candidate.kind, CycleKind.DIRECTED_SIMPLE),
            candidate.nodes,
            opts,
        )

        if expected != candidate.fingerprint:
            all_issues.append(
                CycleIssue(
                    severity=IssueSeverity.ERROR,
                    code="cycle_fingerprint_mismatch",
                    message="Cycle fingerprint does not match canonical node structure.",
                )
            )

    return not _has_error(all_issues), [issue.to_dict() for issue in _dedupe_issues(all_issues)]


def export_cycle_summary(result: CycleAnalysisResult) -> dict[str, Any]:
    """
    Export a safe public cycle-analysis summary.
    """
    return result.to_public_dict()


def get_cycles_health(*, engine: CycleEngine | None = None) -> dict[str, Any]:
    """
    Return safe cycle-engine health.
    """
    active_engine = engine or get_cycle_engine()
    opts = active_engine.options
    cache_summary = active_engine.cache.safe_summary()
    issues: list[CycleIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="cycle_engine_disabled",
            message="Cycle engine is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Cycle engine requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Cycle engine is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "mode": _enum_value(opts.mode, CycleMode.HYBRID.value),
        "cache": cache_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(_CYCLE_CAVEATS),
        "safety_flags": dict(_CYCLE_SAFETY_FLAGS),
    }


def get_cycles_metadata(*, limit: int = _DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
    """
    Return safe, serializable cycle-engine metadata.

    This is useful for startup logs, diagnostic endpoints, tests, developer
    tooling, and architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, raw feature values, subject-label
    pairs, or real customer data.
    """
    options = CycleOptions.from_settings()
    cache = get_cycle_cache(options.max_cache_entries)

    return {
        "package": "muleguard.backend.graph.cycles",
        "version": CYCLES_VERSION,
        "node_kinds": [kind.value for kind in NodeKind],
        "edge_kinds": [kind.value for kind in EdgeKind],
        "cycle_kinds": [kind.value for kind in CycleKind],
        "modes": [mode.value for mode in CycleMode],
        "severities": [severity.value for severity in CycleSeverity],
        "statuses": [status.value for status in AnalysisStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "default_options": options.safe_summary(),
        "cache": cache.safe_summary(),
        "hard_limits": {
            "max_nodes": _HARD_MAX_NODES,
            "max_edges": _HARD_MAX_EDGES,
            "max_records": _HARD_MAX_RECORDS,
            "max_cycles": _HARD_MAX_CYCLES,
            "max_candidates": _HARD_MAX_CANDIDATES,
            "max_cycle_length": _HARD_MAX_CYCLE_LENGTH,
            "max_search_steps": _HARD_MAX_SEARCH_STEPS,
            "max_search_seeds": _HARD_MAX_SEARCH_SEEDS,
            "max_scc_size": _HARD_MAX_SCC_SIZE,
            "max_issues": _HARD_MAX_ISSUES,
            "max_summary_items": _HARD_MAX_SUMMARY_ITEMS,
            "max_cache_entries": _HARD_MAX_CACHE_ENTRIES,
            "max_time_ms": _HARD_MAX_TIME_MS,
            "max_window_days": _HARD_MAX_WINDOW_DAYS,
        },
        "forbidden_graph_field_count": len(_FORBIDDEN_GRAPH_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(_PROHIBITED_ACTION_TOKENS),
        "caveats": list(_CYCLE_CAVEATS),
        "safety_flags": dict(_CYCLE_SAFETY_FLAGS),
    }


__all__ = [
    "AnalysisStatus",
    "CycleAnalysisResult",
    "CycleCandidate",
    "CycleEdge",
    "CycleEngine",
    "CycleGraphSummary",
    "CycleIssue",
    "CycleKind",
    "CycleMode",
    "CycleOptions",
    "CycleRequest",
    "CycleSeverity",
    "EdgeKind",
    "IssueSeverity",
    "NodeKind",
    "analyze_graph_cycles",
    "detect_cycle_candidates",
    "detect_cycles",
    "export_cycle_summary",
    "get_cycle_cache",
    "get_cycle_engine",
    "get_cycle_options",
    "get_cycles_health",
    "get_cycles_metadata",
    "validate_cycle_candidate",
]