"""
MULEGUARD backend graph metrics.

This module provides the canonical bounded graph-metrics layer for the synthetic
MULEGUARD investigative prototype.

Primary responsibilities:

- compute bounded, deterministic, privacy-preserving structural metrics from
  synthetic graph views produced by `app.graph.builder` or compatible graph
  payloads;
- support degree, density, reciprocity, component, clustering, centrality,
  shared-entity, transaction-flow, complaint-correlation, and workflow metrics;
- enforce bounded computation for large graphs using deterministic sampling,
  neighbor caps, time budgets, issue caps, and honest truncation reporting;
- preserve privacy by using salted one-way pseudonymous node identifiers and by
  excluding raw feature values, raw identifiers, raw complaint narratives,
  subject-label pairs, secrets, tokens, passwords, database URLs, filesystem
  paths, and model artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited graph fields;
- report mixed-currency activity only as per-currency counts and never convert
  or aggregate amounts across currencies;
- remain import-safe, dependency-light, and usable by graph services, rules,
  ML feature builders, evaluation harnesses, tests, seeders, offline fixtures,
  and developer tooling.

This module computes metrics only. It does not traverse unbounded paths, train
models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for graph metrics.
- Graph metrics are investigative association and structure signals only. They
  are not proof of common control, fraud, intent, conspiracy, or wrongdoing.
- Centrality, shared-entity, intermediary, and flow metrics are heuristic
  prioritization signals only. They are not probabilities of guilt.
- Only completed synthetic transactions should be modeled as settled money-flow
  edges by upstream builders. Metrics do not infer settlement from non-completed
  records.
- Mixed-currency amounts are reported per currency only. No FX conversion or
  cross-currency aggregation is performed.
- Raw complaint narratives, raw identifiers, ground-truth labels, scenario IDs,
  fraud-ring IDs, secrets, tokens, passwords, database URLs, filesystem paths,
  and model artifact paths are never retained or exposed.
- Graph metrics never trigger automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, denying, terminating,
  suspending, referring to law enforcement, or making credit, employment,
  housing, insurance, benefits, or other consequential decisions.
- Truncation, emptiness, and unavailability are reported honestly rather than
  silently omitted or invented.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external graph engines.
- This module does not persist durable metric stores.
- This module does not generate synthetic ingestion records.
- This module does not replace ingestion validation.
- This module does not replace feature schema validation.
- This module is not a legal evidence system.
- This module is not an authorization engine.
- This module is not a regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, rule
evaluations, threshold profiles, evidence bundles, explanations, validation
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
import time
import unicodedata
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

try:
    from app.exceptions import ConfigurationError
except Exception:  # pragma: no cover - resilience for partial deployments

    class ConfigurationError(RuntimeError):
        """Fallback configuration error."""

        def __init__(self, message: str, *, details: Optional[Mapping[str, Any]] = None) -> None:
            super().__init__(message)
            self.details = dict(details or {})


try:
    from app.graph import (
        GRAPH_CAVEATS,
        GRAPH_SAFETY_FLAGS,
        GraphStatus,
        IssueSeverity,
    )
except Exception:  # pragma: no cover - local fallback for standalone tests

    class IssueSeverity(str, Enum):
        """Fallback issue severity."""

        INFO = "info"
        WARNING = "warning"
        ERROR = "error"

    class GraphStatus(str, Enum):
        """Fallback graph status."""

        AVAILABLE = "available"
        EMPTY = "empty"
        TRUNCATED = "truncated"
        DEGRADED = "degraded"
        BLOCKED = "blocked"
        FAILED = "failed"
        UNAVAILABLE = "unavailable"

    GRAPH_CAVEATS = (
        "Synthetic graph analytics only. Do not use with real customer data.",
        "Graph relationships are investigative leads only and are not proof of wrongdoing.",
        "Graph metrics must not trigger automatic adverse customer action.",
        "This prototype is not production-ready and does not claim regulatory compliance.",
    )

    GRAPH_SAFETY_FLAGS = MappingProxyType(
        {
            "synthetic_only_by_default": True,
            "no_real_customer_data_by_default": True,
            "no_automatic_adverse_customer_action": True,
            "not_production_ready": True,
        }
    )


logger = logging.getLogger("muleguard.backend.graph.metrics")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

GRAPH_METRICS_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.graph.metrics.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_NODES: Final[int] = 20_000
_HARD_MAX_NODES: Final[int] = 50_000

_DEFAULT_MAX_EDGES: Final[int] = 100_000
_HARD_MAX_EDGES: Final[int] = 250_000

_DEFAULT_MAX_NEIGHBORS: Final[int] = 200
_HARD_MAX_NEIGHBORS: Final[int] = 5_000

_DEFAULT_MAX_TOP_ITEMS: Final[int] = 50
_HARD_MAX_TOP_ITEMS: Final[int] = 500

_DEFAULT_MAX_SAMPLE_NODES: Final[int] = 512
_HARD_MAX_SAMPLE_NODES: Final[int] = 10_000

_DEFAULT_MAX_PAGERANK_NODES: Final[int] = 5_000
_HARD_MAX_PAGERANK_NODES: Final[int] = 20_000

_DEFAULT_MAX_BETWEENNESS_NODES: Final[int] = 100
_HARD_MAX_BETWEENNESS_NODES: Final[int] = 500

_DEFAULT_PAGERANK_ITERATIONS: Final[int] = 40
_HARD_MAX_PAGERANK_ITERATIONS: Final[int] = 200

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_TIME_MS: Final[int] = 20_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_NODE_ID_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")

_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_PHONE_IN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\+?91[\s-]?)?[6-9]\d{9}"
)
_PAN_RE: Final[re.Pattern[str]] = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_AADHAAR_RE: Final[re.Pattern[str]] = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
_UPI_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9.\-_]{2,128}@[A-Za-z]{2,64}\b"
)
_IPV4_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
_IFSC_RE: Final[re.Pattern[str]] = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
_CARD_DIGITS_RE: Final[re.Pattern[str]] = re.compile(r"\b\d{13,19}\b")
_SECRET_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|bearer|private[_-]?key)\b\s*[:=]?\s*\S+"
)

_MISSING: Final[object] = object()

_FORBIDDEN_METRICS_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_METRICS_TOKENS: Final[tuple[str, ...]] = (
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

_NODE_TYPE_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "acct": "account",
        "account_node": "account",
        "txn": "transaction",
        "tx": "transaction",
        "transaction_node": "transaction",
        "ent": "entity",
        "entity_node": "entity",
        "cmpl": "complaint",
        "complaint_node": "complaint",
        "alert_node": "alert",
        "assessment_node": "assessment",
        "model_assessment": "assessment",
        "model_assessment_node": "assessment",
        "investigation_case": "case",
        "case_node": "case",
    }
)

_EDGE_TYPE_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "transfer_sent": "sent",
        "sent_to": "sent",
        "outbound": "sent",
        "transfer_received": "received",
        "received_from": "received",
        "inbound": "received",
        "link": "linked_to",
        "linked": "linked_to",
        "entity_link": "linked_to",
        "relation": "related_to",
        "related": "related_to",
        "correlation": "correlated_with",
        "correlated": "correlated_with",
        "complaint_correlation": "correlated_with",
        "alert": "alerted_on",
        "alerted": "alerted_on",
        "scored_by": "assessed_by",
        "assessed": "assessed_by",
        "case_attached": "attached_to_case",
        "attached": "attached_to_case",
    }
)

_METRICS_CAVEATS: Final[tuple[str, ...]] = (
    *(GRAPH_CAVEATS if isinstance(GRAPH_CAVEATS, tuple) else tuple(GRAPH_CAVEATS)),
    "Graph metrics are bounded structural and investigative diagnostics only.",
    "Centrality and shared-entity metrics are association or prioritization signals only.",
    "Top-node identifiers are omitted from public metric summaries by default.",
    "Currency amounts are never converted across currencies and are not exposed by default.",
    "Metric truncation and sampling are reported honestly.",
)

_METRICS_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        **dict(GRAPH_SAFETY_FLAGS),
        "graph_metrics_are_investigative_only": True,
        "centrality_is_not_probability_of_guilt": True,
        "shared_entity_metrics_are_association_signals_only": True,
        "top_node_ids_omitted_by_default": True,
        "amounts_not_exposed_by_default": True,
        "no_cross_currency_conversion": True,
        "deterministic_bounded_metrics": True,
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

    if canonical in _FORBIDDEN_METRICS_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_METRICS_TOKENS)


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


def _luhn_valid(digits: str) -> bool:
    if not digits or not digits.isdigit():
        return False

    total = 0
    reverse = digits[::-1]

    for index, char in enumerate(reverse):
        value = ord(char) - 48

        if index % 2 == 1:
            value *= 2

            if value > 9:
                value -= 9

        total += value

    return total % 10 == 0


def _looks_like_sensitive_literal(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    text = _clean_text(value, 2000)

    if not text:
        return False

    if _EMAIL_RE.search(text):
        return True

    if _UPI_RE.search(text):
        return True

    if _PHONE_IN_RE.search(text):
        return True

    if _PAN_RE.search(text):
        return True

    if _AADHAAR_RE.search(text):
        return True

    if _IPV4_RE.search(text):
        return True

    if _IFSC_RE.search(text):
        return True

    if _SECRET_ASSIGNMENT_RE.search(text):
        return True

    for candidate in _CARD_DIGITS_RE.findall(text):
        if _luhn_valid(candidate):
            return True

    return False


def _looks_like_narrative(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    text = _clean_text(value, 2000).lower()

    if not text:
        return False

    words = text.split()

    if len(words) >= 15 and len(text) >= 80:
        return True

    narrative_tokens = (
        "customer said",
        "user said",
        "complaint text",
        "narrative",
        "allegation",
        "accused",
        "fraudster",
        "criminal",
        "guilty",
        "innocent",
    )

    return any(token in text for token in narrative_tokens)


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
        text = _clean_text(value, 300)

        if not text:
            return None

        if _looks_like_sensitive_literal(text) or _looks_like_narrative(text):
            return "[redacted]"

        return text

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


def _median_sorted(sorted_values: Sequence[float]) -> float:
    if not sorted_values:
        return 0.0

    mid = len(sorted_values) // 2

    if len(sorted_values) % 2 == 1:
        return float(sorted_values[mid])

    return (float(sorted_values[mid - 1]) + float(sorted_values[mid])) / 2.0


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


def _normalized_entropy(counter: Counter[Any]) -> float:
    total = sum(counter.values())

    if total <= 0:
        return 0.0

    unique = len(counter)

    if unique <= 1:
        return 0.0

    entropy = 0.0

    for count in counter.values():
        if count <= 0:
            continue

        p = float(count) / float(total)
        entropy -= p * math.log(p)

    norm = math.log(float(unique))

    if norm <= 0:
        return 0.0

    return _round6(_clip_float(entropy / norm, 0.0, 1.0, 0.0))


def _gini(values: Sequence[float]) -> float:
    cleaned = sorted(max(0.0, float(value)) for value in values)
    n = len(cleaned)

    if n <= 0:
        return 0.0

    total = sum(cleaned)

    if total <= 0:
        return 0.0

    weighted = sum((2 * (index + 1) - n - 1) * value for index, value in enumerate(cleaned))
    result = weighted / (float(n) * total)

    return _round6(_clip_float(result, 0.0, 1.0, 0.0))


def _top_share(values: Sequence[float], top_n: int) -> float:
    cleaned = [max(0.0, float(value)) for value in values if float(value) > 0]

    if not cleaned:
        return 0.0

    total = sum(cleaned)

    if total <= 0:
        return 0.0

    top = sorted(cleaned, reverse=True)[: max(1, int(top_n))]
    return _round6(_clip_float(sum(top) / total, 0.0, 1.0, 0.0))


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
        return {str(key): item for key, item in value.items()}

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


def _time_exceeded(start_time: float, max_time_ms: int) -> bool:
    return (time.monotonic() - start_time) * 1000.0 > float(max(1, int(max_time_ms)))


def _elapsed_ms(start_time: float) -> int:
    return int((time.monotonic() - start_time) * 1000.0)


def _normalize_node_type(value: Any) -> str:
    token = _normalize_token(value)

    if not token:
        return "unknown"

    token = _NODE_TYPE_ALIASES.get(token, token)

    known = {
        "account",
        "transaction",
        "entity",
        "complaint",
        "alert",
        "assessment",
        "case",
    }

    return token if token in known else "unknown"


def _normalize_edge_type(value: Any) -> str:
    token = _normalize_token(value)

    if not token:
        return "related_to"

    token = _EDGE_TYPE_ALIASES.get(token, token)

    known = {
        "sent",
        "received",
        "linked_to",
        "related_to",
        "correlated_with",
        "alerted_on",
        "assessed_by",
        "attached_to_case",
    }

    return token if token in known else "related_to"


def _normalize_currency(value: Any) -> str:
    text = _normalize_unicode(value).strip().upper()
    text = re.sub(r"[^A-Z]", "", text)

    if _CURRENCY_RE.match(text):
        return text

    return ""


def _normalize_currencies(value: Any) -> tuple[str, ...]:
    out: list[str] = []

    if value is None:
        return ()

    if isinstance(value, (str, bytes, bytearray, memoryview)):
        currency = _normalize_currency(value)
        return (currency,) if currency else ()

    if isinstance(value, Mapping):
        for key in value.keys():
            currency = _normalize_currency(key)

            if currency:
                out.append(currency)

        return tuple(dict.fromkeys(out))

    for item in _as_sequence(value):
        currency = _normalize_currency(item)

        if currency:
            out.append(currency)

    return tuple(dict.fromkeys(out))


def _normalize_roles(value: Any) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        token = _normalize_token(item)

        if token and not _is_forbidden_key(token) and not _is_label_leakage_key(token):
            out.append(token)

        if len(out) >= 20:
            break

    return tuple(dict.fromkeys(out))


def _get_field(record: Any, keys: Sequence[str], default: Any = None) -> Any:
    if isinstance(record, Mapping):
        for key in keys:
            if key in record:
                return record[key]

        return default

    for key in keys:
        value = getattr(record, key, _MISSING)

        if value is not _MISSING:
            return value

    return default


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphMetricsIssue:
    """
    Safe graph metrics issue.

    Issues never contain raw feature values, raw narratives, raw identifiers,
    secrets, tokens, passwords, database URLs, filesystem paths, or model
    artifact paths.
    """

    severity: IssueSeverity
    code: str
    message: str
    field: Optional[str] = None
    details: Mapping[str, Any] = dataclass_field(default_factory=dict)

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
        object.__setattr__(self, "details", MappingProxyType(_as_mapping(self.details)))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
        }

        if self.field:
            payload["field"] = self.field

        if self.details:
            payload["details"] = _safe_detail_value(self.details)

        return payload


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


def _append_issue(
    issues: list[GraphMetricsIssue],
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

        issues[-1] = GraphMetricsIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        GraphMetricsIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[GraphMetricsIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _has_warning(issues: Sequence[GraphMetricsIssue]) -> bool:
    return any(issue.severity == IssueSeverity.WARNING for issue in issues)


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphMetricsOptions:
    """
    Bounded graph metrics policy.
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
    max_neighbors: int = _DEFAULT_MAX_NEIGHBORS
    max_top_items: int = _DEFAULT_MAX_TOP_ITEMS
    max_sample_nodes: int = _DEFAULT_MAX_SAMPLE_NODES
    max_pagerank_nodes: int = _DEFAULT_MAX_PAGERANK_NODES
    max_betweenness_nodes: int = _DEFAULT_MAX_BETWEENNESS_NODES
    pagerank_iterations: int = _DEFAULT_PAGERANK_ITERATIONS
    pagerank_damping: float = 0.85
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    include_components: bool = True
    include_clustering: bool = True
    include_centralities: bool = True
    include_shared_entity_metrics: bool = True
    include_transaction_metrics: bool = True
    include_complaint_metrics: bool = True
    include_workflow_metrics: bool = True

    expose_top_node_ids: bool = False
    expose_amounts: bool = False

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
            "max_nodes",
            _clamp_int(self.max_nodes, 1, _HARD_MAX_NODES, _DEFAULT_MAX_NODES),
        )
        object.__setattr__(
            self,
            "max_edges",
            _clamp_int(self.max_edges, 0, _HARD_MAX_EDGES, _DEFAULT_MAX_EDGES),
        )
        object.__setattr__(
            self,
            "max_neighbors",
            _clamp_int(self.max_neighbors, 1, _HARD_MAX_NEIGHBORS, _DEFAULT_MAX_NEIGHBORS),
        )
        object.__setattr__(
            self,
            "max_top_items",
            _clamp_int(self.max_top_items, 1, _HARD_MAX_TOP_ITEMS, _DEFAULT_MAX_TOP_ITEMS),
        )
        object.__setattr__(
            self,
            "max_sample_nodes",
            _clamp_int(self.max_sample_nodes, 2, _HARD_MAX_SAMPLE_NODES, _DEFAULT_MAX_SAMPLE_NODES),
        )
        object.__setattr__(
            self,
            "max_pagerank_nodes",
            _clamp_int(
                self.max_pagerank_nodes,
                2,
                _HARD_MAX_PAGERANK_NODES,
                _DEFAULT_MAX_PAGERANK_NODES,
            ),
        )
        object.__setattr__(
            self,
            "max_betweenness_nodes",
            _clamp_int(
                self.max_betweenness_nodes,
                0,
                _HARD_MAX_BETWEENNESS_NODES,
                _DEFAULT_MAX_BETWEENNESS_NODES,
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
            _clamp_float(self.pagerank_damping, 0.0, 0.99, 0.85),
        )
        object.__setattr__(
            self,
            "max_issues",
            _clamp_int(self.max_issues, 1, _HARD_MAX_ISSUES, _DEFAULT_MAX_ISSUES),
        )
        object.__setattr__(
            self,
            "max_time_ms",
            _clamp_int(self.max_time_ms, 100, _HARD_MAX_TIME_MS, _DEFAULT_MAX_TIME_MS),
        )

        object.__setattr__(self, "include_components", _as_bool(self.include_components, True))
        object.__setattr__(self, "include_clustering", _as_bool(self.include_clustering, True))
        object.__setattr__(self, "include_centralities", _as_bool(self.include_centralities, True))
        object.__setattr__(
            self,
            "include_shared_entity_metrics",
            _as_bool(self.include_shared_entity_metrics, True),
        )
        object.__setattr__(
            self,
            "include_transaction_metrics",
            _as_bool(self.include_transaction_metrics, True),
        )
        object.__setattr__(self, "include_complaint_metrics", _as_bool(self.include_complaint_metrics, True))
        object.__setattr__(self, "include_workflow_metrics", _as_bool(self.include_workflow_metrics, True))

        # Top node IDs are not exposed in public summaries by default.
        object.__setattr__(self, "expose_top_node_ids", _as_bool(self.expose_top_node_ids, False))

        # Amounts are never exposed by metrics summaries.
        object.__setattr__(self, "expose_amounts", False)

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "GraphMetricsOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "GRAPH_METRICS_SALT", None)
            or _setting(settings, "GRAPH_SALT", None)
            or _setting(settings, "RULES_EVIDENCE_SALT", None)
            or _setting(settings, "RULES_THRESHOLD_SALT", None)
            or _setting(settings, "RULES_ENGINE_SALT", None)
            or _setting(settings, "RULES_SALT", None)
            or _setting(settings, "ML_VALIDATION_SALT", None)
            or _setting(settings, "ML_EXPLAIN_SALT", None)
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
            enabled=_as_bool(_setting(settings, "GRAPH_METRICS_ENABLED", True), True)
            and _as_bool(_setting(settings, "GRAPH_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "GRAPH_METRICS_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "GRAPH_METRICS_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "GRAPH_METRICS_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "GRAPH_METRICS_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_nodes=_as_int(_setting(settings, "GRAPH_METRICS_MAX_NODES", _DEFAULT_MAX_NODES), _DEFAULT_MAX_NODES),
            max_edges=_as_int(_setting(settings, "GRAPH_METRICS_MAX_EDGES", _DEFAULT_MAX_EDGES), _DEFAULT_MAX_EDGES),
            max_neighbors=_as_int(
                _setting(settings, "GRAPH_METRICS_MAX_NEIGHBORS", _DEFAULT_MAX_NEIGHBORS),
                _DEFAULT_MAX_NEIGHBORS,
            ),
            max_top_items=_as_int(
                _setting(settings, "GRAPH_METRICS_MAX_TOP_ITEMS", _DEFAULT_MAX_TOP_ITEMS),
                _DEFAULT_MAX_TOP_ITEMS,
            ),
            max_sample_nodes=_as_int(
                _setting(settings, "GRAPH_METRICS_MAX_SAMPLE_NODES", _DEFAULT_MAX_SAMPLE_NODES),
                _DEFAULT_MAX_SAMPLE_NODES,
            ),
            max_pagerank_nodes=_as_int(
                _setting(settings, "GRAPH_METRICS_MAX_PAGERANK_NODES", _DEFAULT_MAX_PAGERANK_NODES),
                _DEFAULT_MAX_PAGERANK_NODES,
            ),
            max_betweenness_nodes=_as_int(
                _setting(settings, "GRAPH_METRICS_MAX_BETWEENNESS_NODES", _DEFAULT_MAX_BETWEENNESS_NODES),
                _DEFAULT_MAX_BETWEENNESS_NODES,
            ),
            pagerank_iterations=_as_int(
                _setting(settings, "GRAPH_METRICS_PAGERANK_ITERATIONS", _DEFAULT_PAGERANK_ITERATIONS),
                _DEFAULT_PAGERANK_ITERATIONS,
            ),
            pagerank_damping=_as_float(
                _setting(settings, "GRAPH_METRICS_PAGERANK_DAMPING", 0.85),
                0.85,
            ),
            max_issues=_as_int(_setting(settings, "GRAPH_METRICS_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_time_ms=_as_int(_setting(settings, "GRAPH_METRICS_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS), _DEFAULT_MAX_TIME_MS),
            include_components=_as_bool(_setting(settings, "GRAPH_METRICS_INCLUDE_COMPONENTS", True), True),
            include_clustering=_as_bool(_setting(settings, "GRAPH_METRICS_INCLUDE_CLUSTERING", True), True),
            include_centralities=_as_bool(_setting(settings, "GRAPH_METRICS_INCLUDE_CENTRALITIES", True), True),
            include_shared_entity_metrics=_as_bool(
                _setting(settings, "GRAPH_METRICS_INCLUDE_SHARED_ENTITY", True),
                True,
            ),
            include_transaction_metrics=_as_bool(
                _setting(settings, "GRAPH_METRICS_INCLUDE_TRANSACTIONS", True),
                True,
            ),
            include_complaint_metrics=_as_bool(
                _setting(settings, "GRAPH_METRICS_INCLUDE_COMPLAINTS", True),
                True,
            ),
            include_workflow_metrics=_as_bool(
                _setting(settings, "GRAPH_METRICS_INCLUDE_WORKFLOW", True),
                True,
            ),
            expose_top_node_ids=_as_bool(_setting(settings, "GRAPH_METRICS_EXPOSE_TOP_NODE_IDS", False), False),
            expose_amounts=False,
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
                "max_neighbors": self.max_neighbors,
                "max_top_items": self.max_top_items,
                "max_sample_nodes": self.max_sample_nodes,
                "max_pagerank_nodes": self.max_pagerank_nodes,
                "max_betweenness_nodes": self.max_betweenness_nodes,
                "pagerank_iterations": self.pagerank_iterations,
                "pagerank_damping": _round6(self.pagerank_damping),
                "max_issues": self.max_issues,
                "max_time_ms": self.max_time_ms,
            },
            "includes": {
                "components": self.include_components,
                "clustering": self.include_clustering,
                "centralities": self.include_centralities,
                "shared_entities": self.include_shared_entity_metrics,
                "transactions": self.include_transaction_metrics,
                "complaints": self.include_complaint_metrics,
                "workflow": self.include_workflow_metrics,
            },
            "exposure": {
                "top_node_ids": self.expose_top_node_ids,
                "amounts": self.expose_amounts,
            },
        }


# -----------------------------------------------------------------------------
# Normalized graph model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _NormalizedEdge:
    source: str
    target: str
    edge_type: str
    weight: int
    currencies: tuple[str, ...]
    roles: tuple[str, ...]
    channels: tuple[str, ...]
    count: int


@dataclass(frozen=True, slots=True)
class _NormalizedGraph:
    node_ids: tuple[str, ...]
    node_types: Mapping[str, str]
    edges: tuple[_NormalizedEdge, ...]
    out_adj: Mapping[str, tuple[str, ...]]
    in_adj: Mapping[str, tuple[str, ...]]
    undirected: Mapping[str, frozenset[str]]
    node_type_counts: Mapping[str, int]
    edge_type_counts: Mapping[str, int]
    input_node_count: int
    input_edge_count: int
    truncated_nodes: bool
    truncated_edges: bool
    skipped_forbidden_nodes: int
    skipped_forbidden_edges: int
    fingerprint: str


def _hash_identifier(value: Any, options: GraphMetricsOptions, domain: str) -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    if _looks_like_sensitive_literal(text) or _looks_like_narrative(text):
        return None

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    full_domain = f"muleguard.graph.metrics.{domain}.{safe_namespace}"
    return _hmac_hex(options.salt, full_domain, text)


def _sample_indices(
    n: int,
    count: int,
    options: GraphMetricsOptions,
    domain: str,
    *parts: Any,
) -> list[int]:
    if n <= 0:
        return []

    count = max(0, min(int(count), n))

    if count >= n:
        return list(range(n))

    values = list(range(n))

    def sort_key(index: int) -> int:
        return _stable_rank(
            options.salt,
            f"muleguard.graph.metrics.sample.{domain}",
            options.seed,
            options.namespace,
            n,
            count,
            index,
            *parts,
        )

    values.sort(key=sort_key)
    return sorted(values[:count])


def _extract_edge_attributes(edge: Any) -> dict[str, Any]:
    attributes = _get_field(edge, ("attributes", "metadata", "details", "attrs"), {})

    if not isinstance(attributes, Mapping):
        attributes = {}

    out: dict[str, Any] = {}

    count = _get_field(attributes, ("count",), None)
    count_value = _as_int(count, 1) if count is not None else 1
    out["count"] = max(1, count_value)

    currencies = _normalize_currencies(_get_field(attributes, ("currencies", "currency"), None))

    if not currencies:
        amount_by_currency = _get_field(attributes, ("amount_by_currency",), None)
        currencies = _normalize_currencies(amount_by_currency)

    out["currencies"] = currencies
    out["roles"] = _normalize_roles(_get_field(attributes, ("roles", "role"), None))
    out["channels"] = tuple(
        dict.fromkeys(
            _normalize_token(item)
            for item in _as_sequence(_get_field(attributes, ("channels", "channel"), ()))
            if _normalize_token(item)
        )
    )

    return out


def _normalize_graph(
    view: Any,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
    start_time: float,
) -> Optional[_NormalizedGraph]:
    if view is None:
        return None

    raw_nodes = _as_sequence(_get_field(view, ("nodes", "graph_nodes", "vertices"), ()))
    raw_edges = _as_sequence(_get_field(view, ("edges", "graph_edges", "links"), ()))

    input_node_count = len(raw_nodes)
    input_edge_count = len(raw_edges)

    truncated_nodes = False
    truncated_edges = False

    if input_node_count > options.max_nodes:
        truncated_nodes = True
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="graph_metrics_nodes_truncated",
            message="Graph metrics node input exceeded configured limit and was truncated.",
            details={"submitted": input_node_count, "max_nodes": options.max_nodes},
        )
        raw_nodes = raw_nodes[: options.max_nodes]

    if input_edge_count > options.max_edges:
        truncated_edges = True
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="graph_metrics_edges_truncated",
            message="Graph metrics edge input exceeded configured limit and was truncated.",
            details={"submitted": input_edge_count, "max_edges": options.max_edges},
        )
        raw_edges = raw_edges[: options.max_edges]

    node_types: dict[str, str] = {}
    skipped_forbidden_nodes = 0

    for index, raw_node in enumerate(raw_nodes):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="graph_metrics_time_budget_exhausted",
                message="Graph normalization stopped after reaching configured time budget.",
                details={"phase": "nodes", "processed": len(node_types)},
            )
            break

        fields = raw_node if isinstance(raw_node, Mapping) else {}
        forbidden_keys = [
            key
            for key in fields.keys()
            if _is_forbidden_key(key) or _is_label_leakage_key(key)
        ]

        if forbidden_keys:
            skipped_forbidden_nodes += 1
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_graph_node_field",
                message="Forbidden graph node field rejected.",
                field=forbidden_keys[0],
                details={"index": index, "forbidden_count": len(forbidden_keys)},
            )
            continue

        raw_id = _get_field(raw_node, ("node_id", "id", "node", "subject_ref_hash"), None)
        node_id = _hash_identifier(raw_id, options, "node")

        if node_id is None:
            skipped_forbidden_nodes += 1
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="graph_node_id_unusable",
                message="Graph node identifier was unusable and node was skipped.",
                details={"index": index},
            )
            continue

        node_type = _normalize_node_type(_get_field(raw_node, ("node_type", "type", "kind"), "unknown"))
        node_types[node_id] = node_type

    edges: list[_NormalizedEdge] = []
    skipped_forbidden_edges = 0

    for index, raw_edge in enumerate(raw_edges):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="graph_metrics_time_budget_exhausted",
                message="Graph normalization stopped after reaching configured time budget.",
                details={"phase": "edges", "processed": len(edges)},
            )
            break

        fields = raw_edge if isinstance(raw_edge, Mapping) else {}
        forbidden_keys = [
            key
            for key in fields.keys()
            if _is_forbidden_key(key) or _is_label_leakage_key(key)
        ]

        attributes = _get_field(raw_edge, ("attributes", "metadata", "details", "attrs"), {})

        if isinstance(attributes, Mapping):
            forbidden_keys.extend(
                key
                for key in attributes.keys()
                if _is_forbidden_key(key) or _is_label_leakage_key(key)
            )

        if forbidden_keys:
            skipped_forbidden_edges += 1
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_graph_edge_field",
                message="Forbidden graph edge field rejected.",
                field=forbidden_keys[0],
                details={"index": index, "forbidden_count": len(forbidden_keys)},
            )
            continue

        raw_source = _get_field(raw_edge, ("source_node_id", "source", "from", "src"), None)
        raw_target = _get_field(raw_edge, ("target_node_id", "target", "to", "dst"), None)

        source = _hash_identifier(raw_source, options, "node")
        target = _hash_identifier(raw_target, options, "node")

        if source is None or target is None:
            skipped_forbidden_edges += 1
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="graph_edge_endpoint_unusable",
                message="Graph edge endpoint was unusable and edge was skipped.",
                details={"index": index},
            )
            continue

        if source == target:
            continue

        if node_types and source not in node_types:
            node_types[source] = "unknown"

        if node_types and target not in node_types:
            node_types[target] = "unknown"

        edge_type = _normalize_edge_type(_get_field(raw_edge, ("edge_type", "type", "relation"), "related_to"))
        weight = max(1, _as_int(_get_field(raw_edge, ("weight",), 1), 1))

        attrs = _extract_edge_attributes(raw_edge)

        edges.append(
            _NormalizedEdge(
                source=source,
                target=target,
                edge_type=edge_type,
                weight=weight,
                currencies=attrs["currencies"],
                roles=attrs["roles"],
                channels=attrs["channels"],
                count=attrs["count"],
            )
        )

    node_ids = tuple(sorted(node_types))

    if not node_ids and not edges:
        return _NormalizedGraph(
            node_ids=(),
            node_types=MappingProxyType({}),
            edges=(),
            out_adj=MappingProxyType({}),
            in_adj=MappingProxyType({}),
            undirected=MappingProxyType({}),
            node_type_counts=MappingProxyType({}),
            edge_type_counts=MappingProxyType({}),
            input_node_count=input_node_count,
            input_edge_count=input_edge_count,
            truncated_nodes=truncated_nodes,
            truncated_edges=truncated_edges,
            skipped_forbidden_nodes=skipped_forbidden_nodes,
            skipped_forbidden_edges=skipped_forbidden_edges,
            fingerprint="",
        )

    out_sets: dict[str, set[str]] = defaultdict(set)
    in_sets: dict[str, set[str]] = defaultdict(set)
    undirected_sets: dict[str, set[str]] = defaultdict(set)
    edge_type_counter: Counter[str] = Counter()

    for edge in edges:
        if node_ids and edge.source not in node_types:
            continue

        if node_ids and edge.target not in node_types:
            continue

        out_sets[edge.source].add(edge.target)
        in_sets[edge.target].add(edge.source)
        undirected_sets[edge.source].add(edge.target)
        undirected_sets[edge.target].add(edge.source)
        edge_type_counter[edge.edge_type] += 1

    for node_id in node_ids:
        out_sets.setdefault(node_id, set())
        in_sets.setdefault(node_id, set())
        undirected_sets.setdefault(node_id, set())

    node_type_counter: Counter[str] = Counter(node_types.values())

    fingerprint = _fingerprint_payload(
        {
            "version": GRAPH_METRICS_VERSION,
            "nodes": list(node_ids),
            "edges": [
                (edge.source, edge.target, edge.edge_type, edge.weight)
                for edge in edges
            ],
        }
    )

    return _NormalizedGraph(
        node_ids=node_ids,
        node_types=MappingProxyType(node_types),
        edges=tuple(edges),
        out_adj=MappingProxyType({key: tuple(sorted(value)) for key, value in out_sets.items()}),
        in_adj=MappingProxyType({key: tuple(sorted(value)) for key, value in in_sets.items()}),
        undirected=MappingProxyType({key: frozenset(value) for key, value in undirected_sets.items()}),
        node_type_counts=MappingProxyType(dict(node_type_counter)),
        edge_type_counts=MappingProxyType(dict(edge_type_counter)),
        input_node_count=input_node_count,
        input_edge_count=input_edge_count,
        truncated_nodes=truncated_nodes,
        truncated_edges=truncated_edges,
        skipped_forbidden_nodes=skipped_forbidden_nodes,
        skipped_forbidden_edges=skipped_forbidden_edges,
        fingerprint=fingerprint,
    )


# -----------------------------------------------------------------------------
# Distribution stats
# -----------------------------------------------------------------------------


def _distribution_stats(values: Sequence[float], *, name: str) -> dict[str, Any]:
    cleaned = [
        _round6(float(value))
        for value in values
        if value is not None and math.isfinite(float(value))
    ]

    if not cleaned:
        return {"available": False, "name": name}

    ordered = sorted(cleaned)
    n = len(ordered)
    mean_value = _mean(ordered)
    counter = Counter(ordered)

    return {
        "available": True,
        "name": name,
        "count": n,
        "min": _round6(ordered[0]),
        "max": _round6(ordered[-1]),
        "mean": _round6(mean_value),
        "std": _round6(_stddev(ordered, mean_value)),
        "median": _round6(_median_sorted(ordered)),
        "p95": _round6(_quantile_sorted(ordered, 0.95)),
        "entropy": _normalized_entropy(counter),
        "gini": _gini(ordered),
        "top1_share": _top_share(ordered, 1),
        "top5_share": _top_share(ordered, 5),
        "distinct": len(counter),
    }


# -----------------------------------------------------------------------------
# Metric computations
# -----------------------------------------------------------------------------


def _compute_basic_metrics(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
) -> dict[str, Any]:
    node_count = len(graph.node_ids)
    edge_count = len(graph.edges)

    if node_count <= 0:
        return {
            "available": False,
            "node_count": 0,
            "edge_count": 0,
            "reason": "empty_graph",
        }

    directed_possible = float(node_count * (node_count - 1))
    undirected_possible = directed_possible / 2.0

    directed_density = float(edge_count) / directed_possible if directed_possible > 0 else 0.0

    undirected_pairs = {
        tuple(sorted((edge.source, edge.target)))
        for edge in graph.edges
    }
    undirected_density = float(len(undirected_pairs)) / undirected_possible if undirected_possible > 0 else 0.0

    pair_directions: dict[tuple[str, str], set[str]] = defaultdict(set)

    for edge in graph.edges:
        key = tuple(sorted((edge.source, edge.target)))
        pair_directions[key].add(f"{edge.source}->{edge.target}")

    reciprocal_pairs = sum(1 for directions in pair_directions.values() if len(directions) >= 2)
    reciprocity = float(reciprocal_pairs) / float(len(pair_directions)) if pair_directions else 0.0

    degrees = [len(graph.undirected.get(node_id, ())) for node_id in graph.node_ids]
    isolated_nodes = sum(1 for degree in degrees if degree == 0)

    self_edges = sum(1 for edge in graph.edges if edge.source == edge.target)

    return {
        "available": True,
        "node_count": node_count,
        "edge_count": edge_count,
        "undirected_pair_count": len(undirected_pairs),
        "directed_density": _round6(_clip_float(directed_density, 0.0, 1.0, 0.0)),
        "undirected_density": _round6(_clip_float(undirected_density, 0.0, 1.0, 0.0)),
        "reciprocity": _round6(_clip_float(reciprocity, 0.0, 1.0, 0.0)),
        "reciprocal_pair_count": reciprocal_pairs,
        "isolated_node_count": isolated_nodes,
        "isolated_node_rate": _round6(float(isolated_nodes) / float(node_count)) if node_count > 0 else 0.0,
        "self_edge_count": self_edges,
        "node_type_counts": dict(graph.node_type_counts),
        "edge_type_counts": dict(graph.edge_type_counts),
        "input_node_count": graph.input_node_count,
        "input_edge_count": graph.input_edge_count,
        "truncated_nodes": bool(graph.truncated_nodes),
        "truncated_edges": bool(graph.truncated_edges),
        "skipped_forbidden_nodes": int(graph.skipped_forbidden_nodes),
        "skipped_forbidden_edges": int(graph.skipped_forbidden_edges),
    }


def _compute_degree_metrics(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
) -> dict[str, Any]:
    if not graph.node_ids:
        return {"available": False, "reason": "empty_graph"}

    degrees: list[float] = []
    in_degrees: list[float] = []
    out_degrees: list[float] = []

    for node_id in graph.node_ids:
        degrees.append(float(len(graph.undirected.get(node_id, ()))))
        in_degrees.append(float(len(graph.in_adj.get(node_id, ()))))
        out_degrees.append(float(len(graph.out_adj.get(node_id, ()))))

    return {
        "available": True,
        "degree": _distribution_stats(degrees, name="degree"),
        "in_degree": _distribution_stats(in_degrees, name="in_degree"),
        "out_degree": _distribution_stats(out_degrees, name="out_degree"),
    }


def _compute_components(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
    start_time: float,
) -> dict[str, Any]:
    if not options.include_components:
        return {"available": False, "reason": "disabled_by_policy"}

    if not graph.node_ids:
        return {"available": False, "reason": "empty_graph"}

    visited: set[str] = set()
    component_sizes: list[int] = []

    for root in graph.node_ids:
        if root in visited:
            continue

        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="component_time_budget_exhausted",
                message="Component detection stopped after reaching configured time budget.",
                details={"components_found": len(component_sizes)},
            )
            break

        queue = deque([root])
        visited.add(root)
        size = 0

        while queue:
            node_id = queue.popleft()
            size += 1

            for neighbor in graph.undirected.get(node_id, ()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        component_sizes.append(size)

    if not component_sizes:
        return {"available": False, "reason": "no_components_found"}

    size_counter = Counter(component_sizes)
    largest = max(component_sizes)
    singletons = sum(1 for size in component_sizes if size == 1)

    return {
        "available": True,
        "component_count": len(component_sizes),
        "largest_component_size": largest,
        "largest_component_share": _round6(float(largest) / float(len(graph.node_ids))) if graph.node_ids else 0.0,
        "singleton_count": singletons,
        "component_size_stats": _distribution_stats([float(size) for size in component_sizes], name="component_size"),
        "component_size_entropy": _normalized_entropy(size_counter),
    }


def _compute_clustering(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
    start_time: float,
) -> dict[str, Any]:
    if not options.include_clustering:
        return {"available": False, "reason": "disabled_by_policy"}

    if len(graph.node_ids) < 3:
        return {"available": False, "reason": "insufficient_nodes"}

    sample_indices = _sample_indices(
        len(graph.node_ids),
        options.max_sample_nodes,
        options,
        "clustering",
        len(graph.node_ids),
    )
    sample_nodes = [graph.node_ids[index] for index in sample_indices]
    coefficients: list[float] = []

    for node_id in sample_nodes:
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="clustering_time_budget_exhausted",
                message="Clustering computation stopped after reaching configured time budget.",
                details={"sampled_nodes": len(coefficients)},
            )
            break

        neighbors = list(graph.undirected.get(node_id, ()))
        k = len(neighbors)

        if k < 2:
            coefficients.append(0.0)
            continue

        if k > options.max_neighbors:
            selected_indices = _sample_indices(
                k,
                options.max_neighbors,
                options,
                "clustering_neighbors",
                node_id,
                k,
            )
            neighbors = [neighbors[index] for index in selected_indices]
            k = len(neighbors)

        neighbor_set = set(neighbors)
        links = 0

        for i in range(k):
            left = neighbors[i]

            for j in range(i + 1, k):
                right = neighbors[j]

                if right in graph.undirected.get(left, ()):
                    links += 1

        possible = k * (k - 1) / 2.0
        coefficients.append(float(links) / possible if possible > 0 else 0.0)

    if not coefficients:
        return {"available": False, "reason": "no_sampled_nodes"}

    return {
        "available": True,
        "sample_size": len(coefficients),
        "sampling_enabled": len(graph.node_ids) > len(coefficients),
        "average_local_clustering": _round6(_mean(coefficients)),
        "clustering_stats": _distribution_stats(coefficients, name="local_clustering"),
    }


def _compute_pagerank(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
    start_time: float,
) -> Optional[dict[str, float]]:
    node_count = len(graph.node_ids)

    if node_count <= 0:
        return None

    if node_count > options.max_pagerank_nodes:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="pagerank_skipped_large_graph",
            message="PageRank skipped because graph exceeds configured PageRank node limit.",
            details={"node_count": node_count, "max_pagerank_nodes": options.max_pagerank_nodes},
        )
        return None

    node_list = list(graph.node_ids)
    n = len(node_list)
    scores = {node_id: 1.0 / float(n) for node_id in node_list}
    damping = float(options.pagerank_damping)

    out_degrees = {node_id: len(graph.out_adj.get(node_id, ())) for node_id in node_list}
    dangling_nodes = [node_id for node_id in node_list if out_degrees[node_id] == 0]

    for _iteration in range(int(options.pagerank_iterations)):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="pagerank_time_budget_exhausted",
                message="PageRank stopped after reaching configured time budget.",
                details={"iteration": _iteration},
            )
            break

        dangling_mass = sum(scores[node_id] for node_id in dangling_nodes)
        base = (1.0 - damping) / float(n)
        dangling_share = damping * dangling_mass / float(n)

        next_scores = {node_id: base + dangling_share for node_id in node_list}

        for source in node_list:
            out_neighbors = graph.out_adj.get(source, ())

            if not out_neighbors:
                continue

            contribution = damping * scores[source] / float(len(out_neighbors))

            for target in out_neighbors:
                next_scores[target] += contribution

        total = sum(next_scores.values())

        if total > 0:
            for node_id in node_list:
                next_scores[node_id] /= total

        scores = next_scores

    return {node_id: _round6(score) for node_id, score in scores.items()}


def _compute_betweenness(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
    start_time: float,
) -> Optional[dict[str, float]]:
    node_count = len(graph.node_ids)

    if node_count <= 2:
        return None

    if options.max_betweenness_nodes <= 0:
        return None

    if node_count > options.max_betweenness_nodes:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="betweenness_skipped_large_graph",
            message="Betweenness skipped because graph exceeds configured betweenness node limit.",
            details={"node_count": node_count, "max_betweenness_nodes": options.max_betweenness_nodes},
        )
        return None

    node_list = list(graph.node_ids)
    betweenness = {node_id: 0.0 for node_id in node_list}

    for source in node_list:
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="betweenness_time_budget_exhausted",
                message="Betweenness computation stopped after reaching configured time budget.",
                details={"processed_sources": node_list.index(source)},
            )
            break

        stack: list[str] = []
        predecessors: dict[str, list[str]] = {node_id: [] for node_id in node_list}
        sigma = {node_id: 0.0 for node_id in node_list}
        distance = {node_id: -1 for node_id in node_list}

        sigma[source] = 1.0
        distance[source] = 0
        queue = deque([source])

        while queue:
            current = queue.popleft()
            stack.append(current)

            for neighbor in graph.out_adj.get(current, ()):
                if distance[neighbor] < 0:
                    distance[neighbor] = distance[current] + 1
                    queue.append(neighbor)

                if distance[neighbor] == distance[current] + 1:
                    sigma[neighbor] += sigma[current]
                    predecessors[neighbor].append(current)

        delta = {node_id: 0.0 for node_id in node_list}

        while stack:
            current = stack.pop()

            for predecessor in predecessors[current]:
                if sigma[current] > 0:
                    delta[predecessor] += (sigma[predecessor] / sigma[current]) * (1.0 + delta[current])

            if current != source:
                betweenness[current] += delta[current]

    normalization = float((node_count - 1) * (node_count - 2))

    if normalization > 0:
        for node_id in node_list:
            betweenness[node_id] = _round6(betweenness[node_id] / normalization)

    return betweenness


def _compute_centrality_metrics(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
    start_time: float,
) -> dict[str, Any]:
    if not options.include_centralities:
        return {"available": False, "reason": "disabled_by_policy"}

    if not graph.node_ids:
        return {"available": False, "reason": "empty_graph"}

    node_count = len(graph.node_ids)
    denominator = float(node_count - 1) if node_count > 1 else 1.0

    degree_centrality = [
        len(graph.undirected.get(node_id, ())) / denominator
        for node_id in graph.node_ids
    ]
    in_centrality = [
        len(graph.in_adj.get(node_id, ())) / denominator
        for node_id in graph.node_ids
    ]
    out_centrality = [
        len(graph.out_adj.get(node_id, ())) / denominator
        for node_id in graph.node_ids
    ]

    payload: dict[str, Any] = {
        "available": True,
        "degree_centrality": _distribution_stats(degree_centrality, name="degree_centrality"),
        "in_degree_centrality": _distribution_stats(in_centrality, name="in_degree_centrality"),
        "out_degree_centrality": _distribution_stats(out_centrality, name="out_degree_centrality"),
    }

    pagerank_scores = _compute_pagerank(graph, options, issues, start_time)

    if pagerank_scores:
        values = list(pagerank_scores.values())
        payload["pagerank"] = _distribution_stats(values, name="pagerank")
        payload["pagerank"]["computed"] = True
    else:
        payload["pagerank"] = {"available": False, "computed": False}

    betweenness_scores = _compute_betweenness(graph, options, issues, start_time)

    if betweenness_scores:
        values = list(betweenness_scores.values())
        payload["betweenness"] = _distribution_stats(values, name="betweenness")
        payload["betweenness"]["computed"] = True
    else:
        payload["betweenness"] = {"available": False, "computed": False}

    return payload


def _compute_shared_entity_metrics(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
    start_time: float,
) -> dict[str, Any]:
    if not options.include_shared_entity_metrics:
        return {"available": False, "reason": "disabled_by_policy"}

    entity_nodes = {
        node_id
        for node_id in graph.node_ids
        if graph.node_types.get(node_id) == "entity"
    }

    if not entity_nodes:
        return {"available": False, "reason": "no_entity_nodes"}

    account_nodes = {
        node_id
        for node_id in graph.node_ids
        if graph.node_types.get(node_id) == "account"
    }

    entity_to_accounts: dict[str, set[str]] = defaultdict(set)

    for edge in graph.edges:
        if edge.edge_type != "linked_to":
            continue

        source_type = graph.node_types.get(edge.source)
        target_type = graph.node_types.get(edge.target)

        if source_type == "account" and target_type == "entity":
            entity_to_accounts[edge.target].add(edge.source)
        elif source_type == "entity" and target_type == "account":
            entity_to_accounts[edge.source].add(edge.target)

    if not entity_to_accounts:
        return {"available": False, "reason": "no_account_entity_links"}

    accounts_per_entity: list[float] = []
    shared_entity_count = 0
    max_accounts = 0

    for entity_id, accounts in entity_to_accounts.items():
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="shared_entity_time_budget_exhausted",
                message="Shared-entity metrics stopped after reaching configured time budget.",
                details={"processed_entities": len(accounts_per_entity)},
            )
            break

        count = len(accounts)
        accounts_per_entity.append(float(count))
        max_accounts = max(max_accounts, count)

        if count >= 2:
            shared_entity_count += 1

    if not accounts_per_entity:
        return {"available": False, "reason": "no_entity_account_counts"}

    return {
        "available": True,
        "entity_count": len(entity_nodes),
        "account_count": len(account_nodes),
        "linked_entity_count": len(entity_to_accounts),
        "shared_entity_count": shared_entity_count,
        "shared_entity_rate": _round6(float(shared_entity_count) / float(len(entity_to_accounts)))
        if entity_to_accounts
        else 0.0,
        "max_accounts_per_entity": max_accounts,
        "accounts_per_entity_stats": _distribution_stats(accounts_per_entity, name="accounts_per_entity"),
    }


def _compute_transaction_metrics(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
    start_time: float,
) -> dict[str, Any]:
    if not options.include_transaction_metrics:
        return {"available": False, "reason": "disabled_by_policy"}

    transaction_nodes = {
        node_id
        for node_id in graph.node_ids
        if graph.node_types.get(node_id) == "transaction"
    }

    sent_edges = [edge for edge in graph.edges if edge.edge_type == "sent"]
    received_edges = [edge for edge in graph.edges if edge.edge_type == "received"]

    if not transaction_nodes and not sent_edges and not received_edges:
        return {"available": False, "reason": "no_transaction_nodes_or_edges"}

    tx_in_accounts: dict[str, set[str]] = defaultdict(set)
    tx_out_accounts: dict[str, set[str]] = defaultdict(set)

    for edge in sent_edges:
        if graph.node_types.get(edge.source) == "account" and graph.node_types.get(edge.target) == "transaction":
            tx_in_accounts[edge.target].add(edge.source)

    for edge in received_edges:
        if graph.node_types.get(edge.source) == "transaction" and graph.node_types.get(edge.target) == "account":
            tx_out_accounts[edge.source].add(edge.target)

    transfer_path_count = 0
    multi_input_transactions = 0
    multi_output_transactions = 0

    for tx_node in transaction_nodes:
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="transaction_metrics_time_budget_exhausted",
                message="Transaction metrics stopped after reaching configured time budget.",
                details={"processed_transactions": transfer_path_count},
            )
            break

        in_accounts = tx_in_accounts.get(tx_node, set())
        out_accounts = tx_out_accounts.get(tx_node, set())

        if len(in_accounts) > 1:
            multi_input_transactions += 1

        if len(out_accounts) > 1:
            multi_output_transactions += 1

        if in_accounts and out_accounts:
            transfer_path_count += min(len(in_accounts), len(out_accounts))

    currency_edge_counts: Counter[str] = Counter()
    currency_transaction_counts: Counter[str] = Counter()
    channel_counts: Counter[str] = Counter()

    for edge in graph.edges:
        if edge.edge_type not in {"sent", "received"}:
            continue

        for currency in edge.currencies:
            currency_edge_counts[currency] += 1

        for channel in edge.channels:
            channel_counts[channel] += 1

    for tx_node in transaction_nodes:
        currencies_for_tx: set[str] = set()

        for edge in graph.edges:
            if edge.edge_type in {"sent", "received"} and (edge.source == tx_node or edge.target == tx_node):
                currencies_for_tx.update(edge.currencies)

        for currency in currencies_for_tx:
            currency_transaction_counts[currency] += 1

    return {
        "available": True,
        "transaction_node_count": len(transaction_nodes),
        "sent_edge_count": len(sent_edges),
        "received_edge_count": len(received_edges),
        "transfer_path_count": transfer_path_count,
        "multi_input_transaction_count": multi_input_transactions,
        "multi_output_transaction_count": multi_output_transactions,
        "currency_edge_counts": dict(sorted(currency_edge_counts.items())),
        "currency_transaction_counts": dict(sorted(currency_transaction_counts.items())),
        "channel_counts": dict(sorted(channel_counts.items())),
        "currencies_observed": sorted(set(currency_edge_counts) | set(currency_transaction_counts)),
        "amounts_exposed": False,
        "cross_currency_conversion": False,
    }


def _compute_complaint_metrics(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
    start_time: float,
) -> dict[str, Any]:
    if not options.include_complaint_metrics:
        return {"available": False, "reason": "disabled_by_policy"}

    complaint_nodes = {
        node_id
        for node_id in graph.node_ids
        if graph.node_types.get(node_id) == "complaint"
    }

    if not complaint_nodes:
        return {"available": False, "reason": "no_complaint_nodes"}

    complaint_account_edges = 0
    complaint_transaction_edges = 0
    role_counts: Counter[str] = Counter()
    accounts_connected: set[str] = set()
    complaints_with_account = 0

    for edge in graph.edges:
        if edge.edge_type != "correlated_with":
            continue

        source_type = graph.node_types.get(edge.source)
        target_type = graph.node_types.get(edge.target)

        if source_type == "complaint" and target_type == "account":
            complaint_account_edges += 1
            accounts_connected.add(edge.target)
            role_counts.update(edge.roles)
        elif source_type == "account" and target_type == "complaint":
            complaint_account_edges += 1
            accounts_connected.add(edge.source)
            role_counts.update(edge.roles)
        elif source_type == "complaint" and target_type == "transaction":
            complaint_transaction_edges += 1
            role_counts.update(edge.roles)
        elif source_type == "transaction" and target_type == "complaint":
            complaint_transaction_edges += 1
            role_counts.update(edge.roles)

    for complaint_node in complaint_nodes:
        if _time_exceeded(start_time, options.max_time_ms):
            break

        if any(
            edge.source == complaint_node and graph.node_types.get(edge.target) == "account"
            for edge in graph.edges
        ):
            complaints_with_account += 1

    return {
        "available": True,
        "complaint_node_count": len(complaint_nodes),
        "complaint_account_edge_count": complaint_account_edges,
        "complaint_transaction_edge_count": complaint_transaction_edges,
        "distinct_connected_account_count": len(accounts_connected),
        "complaints_with_account_count": complaints_with_account,
        "role_counts": dict(sorted(role_counts.items())),
        "raw_narratives_retained": False,
    }


def _compute_workflow_metrics(
    graph: _NormalizedGraph,
    options: GraphMetricsOptions,
    issues: list[GraphMetricsIssue],
) -> dict[str, Any]:
    if not options.include_workflow_metrics:
        return {"available": False, "reason": "disabled_by_policy"}

    node_counts = Counter(graph.node_types.values())
    edge_counts = Counter(edge.edge_type for edge in graph.edges)

    return {
        "available": True,
        "alert_node_count": int(node_counts.get("alert", 0)),
        "assessment_node_count": int(node_counts.get("assessment", 0)),
        "case_node_count": int(node_counts.get("case", 0)),
        "alerted_on_edge_count": int(edge_counts.get("alerted_on", 0)),
        "assessed_by_edge_count": int(edge_counts.get("assessed_by", 0)),
        "attached_to_case_edge_count": int(edge_counts.get("attached_to_case", 0)),
    }


# -----------------------------------------------------------------------------
# Result model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphMetricsResult:
    """
    Safe bounded graph metrics result.

    Public summaries deliberately exclude raw node attributes, raw edge payloads,
    raw identifiers, raw narratives, subject-label pairs, secrets, tokens,
    passwords, database URLs, filesystem paths, and model artifact paths.
    """

    ok: bool = True
    status: GraphStatus | str = GraphStatus.AVAILABLE
    graph_fingerprint: str = ""
    built_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0

    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    basic_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    degree_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    component_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    clustering_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    centrality_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    shared_entity_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    transaction_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    complaint_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    workflow_metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)

    issues: tuple[GraphMetricsIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(GraphStatus, self.status, GraphStatus.AVAILABLE),
        )
        object.__setattr__(self, "graph_fingerprint", _clean_text(self.graph_fingerprint, 128).lower())
        object.__setattr__(self, "built_at", _ensure_utc(self.built_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))

        object.__setattr__(self, "counts", MappingProxyType({str(k): max(0, _as_int(v, 0)) for k, v in (self.counts or {}).items()}))
        object.__setattr__(self, "basic_metrics", MappingProxyType(_as_mapping(self.basic_metrics)))
        object.__setattr__(self, "degree_metrics", MappingProxyType(_as_mapping(self.degree_metrics)))
        object.__setattr__(self, "component_metrics", MappingProxyType(_as_mapping(self.component_metrics)))
        object.__setattr__(self, "clustering_metrics", MappingProxyType(_as_mapping(self.clustering_metrics)))
        object.__setattr__(self, "centrality_metrics", MappingProxyType(_as_mapping(self.centrality_metrics)))
        object.__setattr__(self, "shared_entity_metrics", MappingProxyType(_as_mapping(self.shared_entity_metrics)))
        object.__setattr__(self, "transaction_metrics", MappingProxyType(_as_mapping(self.transaction_metrics)))
        object.__setattr__(self, "complaint_metrics", MappingProxyType(_as_mapping(self.complaint_metrics)))
        object.__setattr__(self, "workflow_metrics", MappingProxyType(_as_mapping(self.workflow_metrics)))
        object.__setattr__(self, "issues", tuple(_as_issue(issue) for issue in (self.issues or ())))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": GRAPH_METRICS_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, GraphStatus.AVAILABLE.value),
                        "graph_fingerprint": self.graph_fingerprint,
                        "counts": dict(self.counts),
                        "basic_metrics": self.basic_metrics,
                        "degree_metrics": self.degree_metrics,
                        "component_metrics": self.component_metrics,
                        "clustering_metrics": self.clustering_metrics,
                        "centrality_metrics": self.centrality_metrics,
                        "shared_entity_metrics": self.shared_entity_metrics,
                        "transaction_metrics": self.transaction_metrics,
                        "complaint_metrics": self.complaint_metrics,
                        "workflow_metrics": self.workflow_metrics,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": _enum_value(self.status, GraphStatus.AVAILABLE.value),
            "graph_fingerprint": self.graph_fingerprint,
            "built_at": self.built_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "counts": dict(self.counts),
            "basic_metrics": _safe_detail_value(self.basic_metrics),
            "degree_metrics": _safe_detail_value(self.degree_metrics),
            "component_metrics": _safe_detail_value(self.component_metrics),
            "clustering_metrics": _safe_detail_value(self.clustering_metrics),
            "centrality_metrics": _safe_detail_value(self.centrality_metrics),
            "shared_entity_metrics": _safe_detail_value(self.shared_entity_metrics),
            "transaction_metrics": _safe_detail_value(self.transaction_metrics),
            "complaint_metrics": _safe_detail_value(self.complaint_metrics),
            "workflow_metrics": _safe_detail_value(self.workflow_metrics),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "raw_node_ids_exposed": False,
            "raw_attributes_exposed": False,
            "amounts_exposed": False,
            "caveats": list(_METRICS_CAVEATS),
            "safety_flags": dict(_METRICS_SAFETY_FLAGS),
        }

    def to_internal_dict(self) -> dict[str, Any]:
        payload = self.to_public_dict()
        payload["internal_only"] = True
        return payload


def _as_issue(value: Any) -> GraphMetricsIssue:
    if isinstance(value, GraphMetricsIssue):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(GraphMetricsIssue, "__dataclass_fields__", {}).keys())
        clean = {key: item for key, item in value.items() if key in fields}

        try:
            return GraphMetricsIssue(**clean)
        except Exception:
            return GraphMetricsIssue(
                severity=IssueSeverity.WARNING,
                code="malformed_issue",
                message="Malformed issue omitted.",
            )

    return GraphMetricsIssue(
        severity=IssueSeverity.WARNING,
        code="invalid_issue",
        message="Invalid issue omitted.",
    )


def _enum_value(value: Any, default: str = "") -> str:
    return _clean_text(getattr(value, "value", value), 128) or default


# -----------------------------------------------------------------------------
# Metrics harness
# -----------------------------------------------------------------------------


class GraphMetricsHarness:
    """
    Bounded deterministic synthetic graph metrics harness.

    This harness computes structural graph metrics only. It does not authorize
    actions, does not deploy systems, does not persist durable artifacts, and
    must not trigger automatic adverse customer action.
    """

    def __init__(self, options: GraphMetricsOptions | None = None) -> None:
        self.options = options or GraphMetricsOptions.from_settings()
        self._lock = threading.RLock()

    def compute(self, view: Any) -> GraphMetricsResult:
        opts = self.options
        issues: list[GraphMetricsIssue] = []
        start_time = time.monotonic()

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="graph_metrics_disabled",
                message="Graph metrics harness is disabled.",
            )
            return GraphMetricsResult(
                ok=False,
                status=GraphStatus.BLOCKED,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                counts={},
                issues=tuple(issues),
                metadata={"options": opts.safe_summary()},
                fingerprint="",
            )

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Graph metrics require synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return GraphMetricsResult(
                ok=False,
                status=GraphStatus.BLOCKED,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                counts={},
                issues=tuple(issues),
                metadata={"options": opts.safe_summary()},
                fingerprint="",
            )

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Graph metrics are blocked in production-like environments.",
            )
            return GraphMetricsResult(
                ok=False,
                status=GraphStatus.BLOCKED,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                counts={},
                issues=tuple(issues),
                metadata={"options": opts.safe_summary()},
                fingerprint="",
            )

        graph = _normalize_graph(view, opts, issues, start_time)

        if graph is None:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="graph_metrics_input_unavailable",
                message="Graph metrics input could not be normalized.",
            )
            return GraphMetricsResult(
                ok=False,
                status=GraphStatus.FAILED,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                counts={},
                issues=tuple(issues),
                metadata={"options": opts.safe_summary()},
                fingerprint="",
            )

        if not graph.node_ids:
            return GraphMetricsResult(
                ok=True,
                status=GraphStatus.EMPTY,
                graph_fingerprint=graph.fingerprint,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                counts={
                    "nodes": 0,
                    "edges": 0,
                    "input_nodes": graph.input_node_count,
                    "input_edges": graph.input_edge_count,
                },
                basic_metrics={
                    "available": False,
                    "reason": "empty_graph",
                    "node_type_counts": {},
                    "edge_type_counts": {},
                },
                issues=tuple(issues),
                metadata={
                    "graph_fingerprint": graph.fingerprint,
                    "options": opts.safe_summary(),
                    "raw_node_ids_exposed": False,
                    "raw_attributes_exposed": False,
                    "amounts_exposed": False,
                },
                fingerprint="",
            )

        basic = _compute_basic_metrics(graph, opts, issues)
        degree = _compute_degree_metrics(graph, opts, issues)

        components = (
            _compute_components(graph, opts, issues, start_time)
            if not _time_exceeded(start_time, opts.max_time_ms)
            else {"available": False, "reason": "time_budget_exhausted"}
        )
        clustering = (
            _compute_clustering(graph, opts, issues, start_time)
            if not _time_exceeded(start_time, opts.max_time_ms)
            else {"available": False, "reason": "time_budget_exhausted"}
        )
        centrality = (
            _compute_centrality_metrics(graph, opts, issues, start_time)
            if not _time_exceeded(start_time, opts.max_time_ms)
            else {"available": False, "reason": "time_budget_exhausted"}
        )
        shared_entities = (
            _compute_shared_entity_metrics(graph, opts, issues, start_time)
            if not _time_exceeded(start_time, opts.max_time_ms)
            else {"available": False, "reason": "time_budget_exhausted"}
        )
        transactions = (
            _compute_transaction_metrics(graph, opts, issues, start_time)
            if not _time_exceeded(start_time, opts.max_time_ms)
            else {"available": False, "reason": "time_budget_exhausted"}
        )
        complaints = (
            _compute_complaint_metrics(graph, opts, issues, start_time)
            if not _time_exceeded(start_time, opts.max_time_ms)
            else {"available": False, "reason": "time_budget_exhausted"}
        )
        workflow = _compute_workflow_metrics(graph, opts, issues)

        counts = {
            "nodes": len(graph.node_ids),
            "edges": len(graph.edges),
            "input_nodes": graph.input_node_count,
            "input_edges": graph.input_edge_count,
            "node_types": len(graph.node_type_counts),
            "edge_types": len(graph.edge_type_counts),
            "issues": len(issues),
        }

        if graph.truncated_nodes or graph.truncated_edges or _time_exceeded(start_time, opts.max_time_ms):
            status = GraphStatus.TRUNCATED
        elif _has_error(issues):
            status = GraphStatus.FAILED
        elif _has_warning(issues):
            status = GraphStatus.DEGRADED
        else:
            status = GraphStatus.AVAILABLE

        metadata = {
            "graph_metrics_version": GRAPH_METRICS_VERSION,
            "graph_fingerprint": graph.fingerprint,
            "options": opts.safe_summary(),
            "built_at": _now_utc().isoformat(),
            "duration_ms": _elapsed_ms(start_time),
            "raw_node_ids_exposed": False,
            "raw_attributes_exposed": False,
            "amounts_exposed": False,
            "cross_currency_conversion": False,
            "caveats": list(_METRICS_CAVEATS),
            "safety_flags": dict(_METRICS_SAFETY_FLAGS),
        }

        return GraphMetricsResult(
            ok=status in {GraphStatus.AVAILABLE, GraphStatus.DEGRADED, GraphStatus.TRUNCATED},
            status=status,
            graph_fingerprint=graph.fingerprint,
            built_at=_now_utc(),
            duration_ms=_elapsed_ms(start_time),
            counts=counts,
            basic_metrics=basic,
            degree_metrics=degree,
            component_metrics=components,
            clustering_metrics=clustering,
            centrality_metrics=centrality,
            shared_entity_metrics=shared_entities,
            transaction_metrics=transactions,
            complaint_metrics=complaints,
            workflow_metrics=workflow,
            issues=tuple(issues),
            metadata=metadata,
            fingerprint="",
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "caveats": list(_METRICS_CAVEATS),
            "safety_flags": dict(_METRICS_SAFETY_FLAGS),
        }


_default_harness: Optional[GraphMetricsHarness] = None
_default_harness_lock = threading.Lock()


def get_graph_metrics_harness(
    options: GraphMetricsOptions | None = None,
    *,
    rebuild: bool = False,
) -> GraphMetricsHarness:
    """
    Return a process-wide graph metrics harness.
    """
    global _default_harness

    with _default_harness_lock:
        if _default_harness is None or rebuild or options is not None:
            _default_harness = GraphMetricsHarness(options=options or GraphMetricsOptions.from_settings())

        return _default_harness


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def compute_graph_metrics(
    view: Any,
    options: GraphMetricsOptions | None = None,
    *,
    harness: GraphMetricsHarness | None = None,
) -> GraphMetricsResult:
    """
    Compute bounded synthetic graph metrics.
    """
    active_harness = harness or get_graph_metrics_harness(options)
    return active_harness.compute(view)


def summarize_graph_metrics(result: Any) -> dict[str, Any]:
    """
    Return safe public summary for a metrics result.
    """
    if isinstance(result, GraphMetricsResult):
        return result.to_public_dict()

    if isinstance(result, Mapping):
        return _safe_detail_value(result) or {}

    return {}


def get_graph_metrics_metadata() -> dict[str, Any]:
    """
    Return safe, serializable graph metrics metadata.
    """
    options = GraphMetricsOptions.from_settings()

    return {
        "package": "muleguard.backend.graph.metrics",
        "version": GRAPH_METRICS_VERSION,
        "node_types": [
            "account",
            "transaction",
            "entity",
            "complaint",
            "alert",
            "assessment",
            "case",
            "unknown",
        ],
        "edge_types": [
            "sent",
            "received",
            "linked_to",
            "related_to",
            "correlated_with",
            "alerted_on",
            "assessed_by",
            "attached_to_case",
        ],
        "statuses": [member.value for member in GraphStatus],
        "issue_severities": [member.value for member in IssueSeverity],
        "default_options": options.safe_summary(),
        "builder_backend": "in_memory_deterministic",
        "distributed": False,
        "durable": False,
        "hard_limits": {
            "max_nodes": _HARD_MAX_NODES,
            "max_edges": _HARD_MAX_EDGES,
            "max_neighbors": _HARD_MAX_NEIGHBORS,
            "max_top_items": _HARD_MAX_TOP_ITEMS,
            "max_sample_nodes": _HARD_MAX_SAMPLE_NODES,
            "max_pagerank_nodes": _HARD_MAX_PAGERANK_NODES,
            "max_betweenness_nodes": _HARD_MAX_BETWEENNESS_NODES,
            "pagerank_iterations": _HARD_MAX_PAGERANK_ITERATIONS,
            "max_issues": _HARD_MAX_ISSUES,
            "max_time_ms": _HARD_MAX_TIME_MS,
        },
        "forbidden_metrics_field_count": len(_FORBIDDEN_METRICS_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_METRICS_CAVEATS),
        "safety_flags": dict(_METRICS_SAFETY_FLAGS),
    }


__all__ = [
    "GraphMetricsHarness",
    "GraphMetricsIssue",
    "GraphMetricsOptions",
    "GraphMetricsResult",
    "compute_graph_metrics",
    "get_graph_metrics_harness",
    "get_graph_metrics_metadata",
    "summarize_graph_metrics",
]