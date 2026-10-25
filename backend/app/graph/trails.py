"""
MULEGUARD backend graph trails.

This module provides the canonical bounded candidate money-trail detection layer
for the synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- detect bounded, deterministic, pseudonymous candidate money trails from
  synthetic graph views produced by `app.graph.builder` or compatible graph
  payloads;
- support downstream, upstream, and bidirectional bounded trail exploration over
  `sent` and `received` money-flow edges;
- enforce strict bounds for seeds, trails, trail length, branching, scanned
  nodes, issue reporting, and time budget;
- preserve privacy by using salted one-way pseudonymous node identifiers and by
  excluding raw feature values, raw identifiers, raw complaint narratives,
  subject-label pairs, secrets, tokens, passwords, database URLs, filesystem
  paths, model artifact paths, and currency amounts from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited graph fields;
- report mixed-currency trails only as per-trail currency sets and currency
  counts, never converting or aggregating amounts across currencies;
- provide safe trail results with bounded trail sequences, heuristic scores,
  score components, counts, diagnostics, fingerprints, and API-safe summaries;
- remain import-safe, dependency-light, and usable by graph services, rules,
  ML feature builders, evaluation harnesses, tests, seeders, offline fixtures,
  and developer tooling.

This module detects candidate trails only. It does not traverse unbounded paths,
train models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for trail detection.
- Candidate money trails are heuristic investigative flow views only. They are
  not proof of layering, integration, placement, common control, fraud, intent,
  conspiracy, or wrongdoing.
- Trail ordering, scores, and ranking are operational prioritization signals
  only. They are not probabilities of guilt and are not legal, evidentiary, or
  causal priority.
- Only completed synthetic transactions should be modeled as settled money-flow
  edges by upstream builders. Trail detection does not infer settlement from
  non-completed records.
- Mixed-currency amounts are never converted. Currency amounts are not exposed.
  Currency codes may be reported as safe aggregate trail metadata.
- Raw complaint narratives, raw identifiers, ground-truth labels, scenario IDs,
  fraud-ring IDs, secrets, tokens, passwords, database URLs, filesystem paths,
  and model artifact paths are never retained or exposed.
- Trail detection never triggers automatic adverse customer action such as
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
- This module does not persist durable trail snapshots.
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
from collections import Counter, defaultdict
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
        "Graph analytics must not trigger automatic adverse customer action.",
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


logger = logging.getLogger("muleguard.backend.graph.trails")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

TRAILS_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.graph.trails.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_SEEDS: Final[int] = 100
_HARD_MAX_SEEDS: Final[int] = 1_000

_DEFAULT_MAX_TRAILS: Final[int] = 100
_HARD_MAX_TRAILS: Final[int] = 5_000

_DEFAULT_MAX_TRAIL_EDGES: Final[int] = 8
_HARD_MAX_TRAIL_EDGES: Final[int] = 32

_DEFAULT_MIN_TRAIL_EDGES: Final[int] = 2
_HARD_MIN_TRAIL_EDGES: Final[int] = 1

_DEFAULT_MAX_BRANCHING: Final[int] = 20
_HARD_MAX_BRANCHING: Final[int] = 500

_DEFAULT_MAX_SCAN_NODES: Final[int] = 5_000
_HARD_MAX_SCAN_NODES: Final[int] = 50_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_TIME_MS: Final[int] = 20_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_INPUT_MAX_NODES: Final[int] = 50_000
_INPUT_MAX_EDGES: Final[int] = 250_000

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

_DIRECTION_DOWNSTREAM: Final[str] = "downstream"
_DIRECTION_UPSTREAM: Final[str] = "upstream"
_DIRECTION_BOTH: Final[str] = "both"

_TRAIL_DIRECTIONS: Final[tuple[str, ...]] = (
    _DIRECTION_DOWNSTREAM,
    _DIRECTION_UPSTREAM,
    _DIRECTION_BOTH,
)

_DIRECTION_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "out": _DIRECTION_DOWNSTREAM,
        "outgoing": _DIRECTION_DOWNSTREAM,
        "outbound": _DIRECTION_DOWNSTREAM,
        "forward": _DIRECTION_DOWNSTREAM,
        "down": _DIRECTION_DOWNSTREAM,
        "in": _DIRECTION_UPSTREAM,
        "incoming": _DIRECTION_UPSTREAM,
        "inbound": _DIRECTION_UPSTREAM,
        "backward": _DIRECTION_UPSTREAM,
        "reverse": _DIRECTION_UPSTREAM,
        "up": _DIRECTION_UPSTREAM,
        "bidirectional": _DIRECTION_BOTH,
        "all": _DIRECTION_BOTH,
        "both": _DIRECTION_BOTH,
    }
)

_FORBIDDEN_TRAIL_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_TRAIL_TOKENS: Final[tuple[str, ...]] = (
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

_MONEY_FLOW_EDGE_TYPES: Final[frozenset[str]] = frozenset({"sent", "received"})

_TRAIL_CAVEATS: Final[tuple[str, ...]] = (
    *(GRAPH_CAVEATS if isinstance(GRAPH_CAVEATS, tuple) else tuple(GRAPH_CAVEATS)),
    "Candidate money trails are heuristic flow views only.",
    "Candidate trails are not proof of layering, integration, placement, common control, fraud, intent, or wrongdoing.",
    "Trail ordering, ranking, and scores are investigative prioritization signals only.",
    "Trail scores are not probabilities of guilt.",
    "Currency amounts are not exposed by trail summaries.",
    "Mixed-currency trails are reported only as currency sets and currency counts.",
    "No FX conversion or cross-currency aggregation is performed.",
    "Trail extraction must not trigger automatic adverse customer action.",
)

_TRAIL_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        **dict(GRAPH_SAFETY_FLAGS),
        "candidate_trails_are_heuristic_views_only": True,
        "trail_scores_are_not_probabilities_of_guilt": True,
        "trail_ordering_is_not_legal_priority": True,
        "bounded_trail_detection_required": True,
        "deterministic_trail_detection": True,
        "raw_attributes_not_exposed": True,
        "amounts_not_exposed": True,
        "no_cross_currency_conversion": True,
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

    if canonical in _FORBIDDEN_TRAIL_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_TRAIL_TOKENS)


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


def _normalize_trail_direction(value: Any, default: str = _DIRECTION_DOWNSTREAM) -> str:
    token = _normalize_token(value)

    if token in _TRAIL_DIRECTIONS:
        return token

    alias = _DIRECTION_ALIASES.get(token)

    if alias is not None:
        return alias

    return default


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


def _normalize_optional_currency_set(value: Any) -> Optional[tuple[str, ...]]:
    if value is None:
        return None

    currencies = _normalize_currencies(value)

    if not currencies:
        return None

    return currencies


def _enum_value(value: Any, default: str = "") -> str:
    return _clean_text(getattr(value, "value", value), 128) or default


def _scan_forbidden_fields(fields: Mapping[str, Any]) -> list[str]:
    forbidden: list[str] = []

    for raw_key in fields.keys():
        key = _clean_text(raw_key, 200)
        canonical = _canonical_field_name(key)

        if not canonical:
            continue

        if _is_forbidden_key(canonical) or _is_label_leakage_key(canonical):
            forbidden.append(key)

    return forbidden


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


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrailIssue:
    """
    Safe trail issue.

    Issues never contain raw feature values, raw narratives, raw identifiers,
    secrets, tokens, passwords, database URLs, filesystem paths, model artifact
    paths, or currency amounts.
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


def _append_issue(
    issues: list[TrailIssue],
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

        issues[-1] = TrailIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        TrailIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[TrailIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _has_warning(issues: Sequence[TrailIssue]) -> bool:
    return any(issue.severity == IssueSeverity.WARNING for issue in issues)


def _as_issue(value: Any) -> TrailIssue:
    if isinstance(value, TrailIssue):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(TrailIssue, "__dataclass_fields__", {}).keys())
        clean = {key: item for key, item in value.items() if key in fields}

        try:
            return TrailIssue(**clean)
        except Exception:
            return TrailIssue(
                severity=IssueSeverity.WARNING,
                code="malformed_issue",
                message="Malformed issue omitted.",
            )

    return TrailIssue(
        severity=IssueSeverity.WARNING,
        code="invalid_issue",
        message="Invalid issue omitted.",
    )


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrailOptions:
    """
    Bounded candidate money-trail detection policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    direction: str = _DIRECTION_DOWNSTREAM

    max_seeds: int = _DEFAULT_MAX_SEEDS
    max_trails: int = _DEFAULT_MAX_TRAILS
    max_trail_edges: int = _DEFAULT_MAX_TRAIL_EDGES
    min_trail_edges: int = _DEFAULT_MIN_TRAIL_EDGES
    max_branching_per_node: int = _DEFAULT_MAX_BRANCHING
    max_scan_nodes: int = _DEFAULT_MAX_SCAN_NODES
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    allowed_currencies: Optional[tuple[str, ...]] = None

    include_cycles: bool = False
    include_partial_trails: bool = False
    deterministic_order: bool = True
    expose_node_ids: bool = False
    expose_edge_ids: bool = False
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
            "direction",
            _normalize_trail_direction(self.direction, _DIRECTION_DOWNSTREAM),
        )

        object.__setattr__(
            self,
            "max_seeds",
            _clamp_int(self.max_seeds, 1, _HARD_MAX_SEEDS, _DEFAULT_MAX_SEEDS),
        )
        object.__setattr__(
            self,
            "max_trails",
            _clamp_int(self.max_trails, 1, _HARD_MAX_TRAILS, _DEFAULT_MAX_TRAILS),
        )
        object.__setattr__(
            self,
            "max_trail_edges",
            _clamp_int(self.max_trail_edges, 1, _HARD_MAX_TRAIL_EDGES, _DEFAULT_MAX_TRAIL_EDGES),
        )
        object.__setattr__(
            self,
            "min_trail_edges",
            _clamp_int(
                self.min_trail_edges,
                _HARD_MIN_TRAIL_EDGES,
                self.max_trail_edges,
                _DEFAULT_MIN_TRAIL_EDGES,
            ),
        )
        object.__setattr__(
            self,
            "max_branching_per_node",
            _clamp_int(
                self.max_branching_per_node,
                1,
                _HARD_MAX_BRANCHING,
                _DEFAULT_MAX_BRANCHING,
            ),
        )
        object.__setattr__(
            self,
            "max_scan_nodes",
            _clamp_int(self.max_scan_nodes, 1, _HARD_MAX_SCAN_NODES, _DEFAULT_MAX_SCAN_NODES),
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

        object.__setattr__(
            self,
            "allowed_currencies",
            _normalize_optional_currency_set(self.allowed_currencies),
        )

        object.__setattr__(self, "include_cycles", _as_bool(self.include_cycles, False))
        object.__setattr__(self, "include_partial_trails", _as_bool(self.include_partial_trails, False))
        object.__setattr__(self, "deterministic_order", _as_bool(self.deterministic_order, True))

        # Node IDs are pseudonymous, but public trail summaries omit them by
        # default to reduce linkage exposure.
        object.__setattr__(self, "expose_node_ids", _as_bool(self.expose_node_ids, False))
        object.__setattr__(self, "expose_edge_ids", _as_bool(self.expose_edge_ids, False))

        # Amounts are never exposed by trail summaries.
        object.__setattr__(self, "expose_amounts", False)

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "TrailOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "GRAPH_TRAILS_SALT", None)
            or _setting(settings, "GRAPH_NEIGHBORHOOD_SALT", None)
            or _setting(settings, "GRAPH_METRICS_SALT", None)
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
            enabled=_as_bool(_setting(settings, "GRAPH_TRAILS_ENABLED", True), True)
            and _as_bool(_setting(settings, "GRAPH_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "GRAPH_TRAILS_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "GRAPH_TRAILS_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "GRAPH_TRAILS_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "GRAPH_TRAILS_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            direction=str(_setting(settings, "GRAPH_TRAILS_DIRECTION", _DIRECTION_DOWNSTREAM)),
            max_seeds=_as_int(_setting(settings, "GRAPH_TRAILS_MAX_SEEDS", _DEFAULT_MAX_SEEDS), _DEFAULT_MAX_SEEDS),
            max_trails=_as_int(_setting(settings, "GRAPH_TRAILS_MAX_TRAILS", _DEFAULT_MAX_TRAILS), _DEFAULT_MAX_TRAILS),
            max_trail_edges=_as_int(
                _setting(settings, "GRAPH_TRAILS_MAX_TRAIL_EDGES", _DEFAULT_MAX_TRAIL_EDGES),
                _DEFAULT_MAX_TRAIL_EDGES,
            ),
            min_trail_edges=_as_int(
                _setting(settings, "GRAPH_TRAILS_MIN_TRAIL_EDGES", _DEFAULT_MIN_TRAIL_EDGES),
                _DEFAULT_MIN_TRAIL_EDGES,
            ),
            max_branching_per_node=_as_int(
                _setting(settings, "GRAPH_TRAILS_MAX_BRANCHING", _DEFAULT_MAX_BRANCHING),
                _DEFAULT_MAX_BRANCHING,
            ),
            max_scan_nodes=_as_int(
                _setting(settings, "GRAPH_TRAILS_MAX_SCAN_NODES", _DEFAULT_MAX_SCAN_NODES),
                _DEFAULT_MAX_SCAN_NODES,
            ),
            max_issues=_as_int(_setting(settings, "GRAPH_TRAILS_MAX_ISSUES", _DEFAULT_MAX_ISSUES), _DEFAULT_MAX_ISSUES),
            max_time_ms=_as_int(_setting(settings, "GRAPH_TRAILS_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS), _DEFAULT_MAX_TIME_MS),
            allowed_currencies=_normalize_optional_currency_set(
                _setting(settings, "GRAPH_TRAILS_ALLOWED_CURRENCIES", None)
            ),
            include_cycles=_as_bool(_setting(settings, "GRAPH_TRAILS_INCLUDE_CYCLES", False), False),
            include_partial_trails=_as_bool(
                _setting(settings, "GRAPH_TRAILS_INCLUDE_PARTIAL_TRAILS", False),
                False,
            ),
            deterministic_order=_as_bool(_setting(settings, "GRAPH_TRAILS_DETERMINISTIC_ORDER", True), True),
            expose_node_ids=_as_bool(_setting(settings, "GRAPH_TRAILS_EXPOSE_NODE_IDS", False), False),
            expose_edge_ids=_as_bool(_setting(settings, "GRAPH_TRAILS_EXPOSE_EDGE_IDS", False), False),
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
            "direction": self.direction,
            "limits": {
                "max_seeds": self.max_seeds,
                "max_trails": self.max_trails,
                "max_trail_edges": self.max_trail_edges,
                "min_trail_edges": self.min_trail_edges,
                "max_branching_per_node": self.max_branching_per_node,
                "max_scan_nodes": self.max_scan_nodes,
                "max_issues": self.max_issues,
                "max_time_ms": self.max_time_ms,
            },
            "allowed_currencies": list(self.allowed_currencies) if self.allowed_currencies else None,
            "flags": {
                "include_cycles": self.include_cycles,
                "include_partial_trails": self.include_partial_trails,
                "deterministic_order": self.deterministic_order,
                "expose_node_ids": self.expose_node_ids,
                "expose_edge_ids": self.expose_edge_ids,
                "expose_amounts": self.expose_amounts,
            },
        }


# -----------------------------------------------------------------------------
# Normalized flow graph
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _FlowEdge:
    source: str
    target: str
    edge_types: tuple[str, ...]
    currencies: tuple[str, ...]
    weight: int

    def merged_with(self, other: "_FlowEdge") -> "_FlowEdge":
        return _FlowEdge(
            source=self.source,
            target=self.target,
            edge_types=tuple(dict.fromkeys([*self.edge_types, *other.edge_types])),
            currencies=tuple(dict.fromkeys([*self.currencies, *other.currencies])),
            weight=max(1, int(self.weight) + int(other.weight)),
        )


@dataclass(frozen=True, slots=True)
class _NormalizedTrailGraph:
    node_ids: tuple[str, ...]
    node_types: Mapping[str, str]
    flow_adj: Mapping[str, Mapping[str, _FlowEdge]]
    flow_rev: Mapping[str, Mapping[str, _FlowEdge]]
    input_node_count: int
    input_edge_count: int
    money_edge_count: int
    truncated_nodes: bool
    truncated_edges: bool
    skipped_forbidden_nodes: int
    skipped_forbidden_edges: int
    fingerprint: str


def _hash_identifier(value: Any, options: TrailOptions, domain: str) -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    if _looks_like_sensitive_literal(text) or _looks_like_narrative(text):
        return None

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    full_domain = f"muleguard.graph.trails.{domain}.{safe_namespace}"
    return _hmac_hex(options.salt, full_domain, text)


def _extract_edge_currencies(edge: Any) -> tuple[str, ...]:
    attributes = _get_field(edge, ("attributes", "metadata", "details", "attrs"), {})

    if not isinstance(attributes, Mapping):
        attributes = {}

    currencies = _get_field(attributes, ("currencies", "currency"), None)

    if currencies is None:
        currencies = _get_field(attributes, ("amount_by_currency",), None)

    return _normalize_currencies(currencies)


def _add_flow_edge(
    adj: dict[str, dict[str, _FlowEdge]],
    source: str,
    target: str,
    edge_type: str,
    currencies: tuple[str, ...],
    weight: int,
) -> None:
    bucket = adj.setdefault(source, {})
    incoming = _FlowEdge(
        source=source,
        target=target,
        edge_types=(edge_type,),
        currencies=currencies,
        weight=max(1, int(weight)),
    )

    existing = bucket.get(target)

    if existing is None:
        bucket[target] = incoming
    else:
        bucket[target] = existing.merged_with(incoming)


def _freeze_flow_adj(
    adj: Mapping[str, Mapping[str, _FlowEdge]],
) -> Mapping[str, Mapping[str, _FlowEdge]]:
    return MappingProxyType(
        {
            source: MappingProxyType(dict(targets))
            for source, targets in adj.items()
        }
    )


def _normalize_trail_graph(
    view: Any,
    options: TrailOptions,
    issues: list[TrailIssue],
    start_time: float,
) -> Optional[_NormalizedTrailGraph]:
    if view is None:
        return None

    raw_nodes = _as_sequence(_get_field(view, ("nodes", "graph_nodes", "vertices"), ()))
    raw_edges = _as_sequence(_get_field(view, ("edges", "graph_edges", "links"), ()))

    input_node_count = len(raw_nodes)
    input_edge_count = len(raw_edges)

    truncated_nodes = False
    truncated_edges = False

    if input_node_count > _INPUT_MAX_NODES:
        truncated_nodes = True
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="trail_input_nodes_truncated",
            message="Trail input nodes exceeded hard input limit and were truncated.",
            details={"submitted": input_node_count, "limit": _INPUT_MAX_NODES},
        )
        raw_nodes = raw_nodes[:_INPUT_MAX_NODES]

    if input_edge_count > _INPUT_MAX_EDGES:
        truncated_edges = True
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="trail_input_edges_truncated",
            message="Trail input edges exceeded hard input limit and were truncated.",
            details={"submitted": input_edge_count, "limit": _INPUT_MAX_EDGES},
        )
        raw_edges = raw_edges[:_INPUT_MAX_EDGES]

    node_types: dict[str, str] = {}
    skipped_forbidden_nodes = 0

    for index, raw_node in enumerate(raw_nodes):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="trail_normalization_time_budget_exhausted",
                message="Graph normalization stopped after reaching configured time budget.",
                details={"phase": "nodes", "processed": len(node_types)},
            )
            break

        if isinstance(raw_node, Mapping):
            forbidden = _scan_forbidden_fields(raw_node)

            if forbidden:
                skipped_forbidden_nodes += 1
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="forbidden_trail_node_field",
                    message="Forbidden graph node field rejected.",
                    field=forbidden[0],
                    details={"index": index, "forbidden_count": len(forbidden)},
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
                code="trail_node_id_unusable",
                message="Graph node identifier was unusable and node was skipped.",
                details={"index": index},
            )
            continue

        node_type = _normalize_node_type(_get_field(raw_node, ("node_type", "type", "kind"), "unknown"))
        node_types[node_id] = node_type

    flow_adj: dict[str, dict[str, _FlowEdge]] = {}
    flow_rev: dict[str, dict[str, _FlowEdge]] = {}
    skipped_forbidden_edges = 0
    money_edge_count = 0

    for index, raw_edge in enumerate(raw_edges):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="trail_normalization_time_budget_exhausted",
                message="Graph normalization stopped after reaching configured time budget.",
                details={"phase": "edges", "processed": money_edge_count},
            )
            break

        if isinstance(raw_edge, Mapping):
            forbidden = _scan_forbidden_fields(raw_edge)

            attributes = _get_field(raw_edge, ("attributes", "metadata", "details", "attrs"), {})

            if isinstance(attributes, Mapping):
                forbidden.extend(_scan_forbidden_fields(attributes))

            if forbidden:
                skipped_forbidden_edges += 1
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="forbidden_trail_edge_field",
                    message="Forbidden graph edge field rejected.",
                    field=forbidden[0],
                    details={"index": index, "forbidden_count": len(forbidden)},
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
                code="trail_edge_endpoint_unusable",
                message="Graph edge endpoint was unusable and edge was skipped.",
                details={"index": index},
            )
            continue

        if source == target:
            continue

        edge_type = _normalize_edge_type(_get_field(raw_edge, ("edge_type", "type", "relation"), "related_to"))

        if edge_type not in _MONEY_FLOW_EDGE_TYPES:
            continue

        if source not in node_types:
            if len(node_types) >= _INPUT_MAX_NODES:
                skipped_forbidden_edges += 1
                continue

            node_types[source] = "unknown"

        if target not in node_types:
            if len(node_types) >= _INPUT_MAX_NODES:
                skipped_forbidden_edges += 1
                continue

            node_types[target] = "unknown"

        currencies = _extract_edge_currencies(raw_edge)
        weight = max(1, _as_int(_get_field(raw_edge, ("weight", "count"), 1), 1))

        _add_flow_edge(flow_adj, source, target, edge_type, currencies, weight)
        _add_flow_edge(flow_rev, target, source, edge_type, currencies, weight)

        money_edge_count += 1

    node_ids = tuple(sorted(node_types))

    fingerprint = _fingerprint_payload(
        {
            "version": TRAILS_VERSION,
            "nodes": list(node_ids),
            "flow_edges": [
                (
                    source,
                    target,
                    edge.edge_types,
                    edge.currencies,
                    edge.weight,
                )
                for source, targets in sorted(flow_adj.items())
                for target, edge in sorted(targets.items())
            ],
        }
    )

    return _NormalizedTrailGraph(
        node_ids=node_ids,
        node_types=MappingProxyType(node_types),
        flow_adj=_freeze_flow_adj(flow_adj),
        flow_rev=_freeze_flow_adj(flow_rev),
        input_node_count=input_node_count,
        input_edge_count=input_edge_count,
        money_edge_count=money_edge_count,
        truncated_nodes=truncated_nodes,
        truncated_edges=truncated_edges,
        skipped_forbidden_nodes=skipped_forbidden_nodes,
        skipped_forbidden_edges=skipped_forbidden_edges,
        fingerprint=fingerprint,
    )


# -----------------------------------------------------------------------------
# Trail models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Trail:
    """
    One bounded candidate money trail.

    Candidate trails are heuristic investigative flow views only. They are not
    proof of layering, integration, placement, common control, fraud, intent,
    conspiracy, or wrongdoing.
    """

    trail_id: str
    direction: str
    seed_node_id: str
    node_sequence: tuple[str, ...]
    edge_types: tuple[str, ...]
    currencies: tuple[str, ...]
    edge_count: int
    account_count: int
    transaction_count: int
    score: float
    score_components: Mapping[str, float]
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "trail_id", _clean_text(self.trail_id, 128).lower())
        object.__setattr__(self, "direction", _normalize_trail_direction(self.direction, _DIRECTION_DOWNSTREAM))
        object.__setattr__(self, "seed_node_id", _clean_text(self.seed_node_id, _MAX_NODE_ID_LENGTH).lower())
        object.__setattr__(
            self,
            "node_sequence",
            tuple(
                _clean_text(node_id, _MAX_NODE_ID_LENGTH).lower()
                for node_id in (self.node_sequence or ())
                if _clean_text(node_id, _MAX_NODE_ID_LENGTH)
            ),
        )
        object.__setattr__(
            self,
            "edge_types",
            tuple(
                _normalize_edge_type(edge_type)
                for edge_type in (self.edge_types or ())
            ),
        )
        object.__setattr__(
            self,
            "currencies",
            tuple(
                dict.fromkeys(
                    _normalize_currency(currency)
                    for currency in (self.currencies or ())
                    if _normalize_currency(currency)
                )
            ),
        )
        object.__setattr__(self, "edge_count", max(0, _as_int(self.edge_count, 0)))
        object.__setattr__(self, "account_count", max(0, _as_int(self.account_count, 0)))
        object.__setattr__(self, "transaction_count", max(0, _as_int(self.transaction_count, 0)))
        object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))
        object.__setattr__(
            self,
            "score_components",
            MappingProxyType(
                {
                    _clean_text(key, 100): _round6(_clip_float(value, 0.0, 1.0, 0.0))
                    for key, value in (self.score_components or {}).items()
                }
            ),
        )
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self, *, include_node_ids: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "trail_id": self.trail_id,
            "direction": self.direction,
            "edge_count": int(self.edge_count),
            "account_count": int(self.account_count),
            "transaction_count": int(self.transaction_count),
            "currencies": list(self.currencies),
            "currency_count": len(self.currencies),
            "score": float(self.score),
            "score_components": dict(self.score_components),
            "metadata": _safe_detail_value(self.metadata),
        }

        if include_node_ids:
            payload["seed_node_id"] = self.seed_node_id
            payload["node_sequence"] = list(self.node_sequence)
            payload["edge_types"] = list(self.edge_types)
        else:
            payload["node_ids_omitted"] = True

        return payload


@dataclass(frozen=True, slots=True)
class TrailResult:
    """
    Safe bounded trail detection result.

    Public summaries deliberately exclude raw attributes, raw identifiers, raw
    narratives, subject-label pairs, secrets, tokens, passwords, database URLs,
    filesystem paths, model artifact paths, and currency amounts.
    """

    ok: bool = True
    status: GraphStatus | str = GraphStatus.AVAILABLE
    graph_fingerprint: str = ""
    direction: str = _DIRECTION_DOWNSTREAM
    built_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0

    seeds_requested: int = 0
    seeds_used: int = 0
    seeds_missing: int = 0

    trails: tuple[Trail, ...] = ()

    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    node_type_counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    edge_type_counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    currency_counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    length_distribution: Mapping[int, int] = dataclass_field(default_factory=dict)

    issues: tuple[TrailIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    expose_node_ids: bool = False
    expose_edge_ids: bool = False
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(GraphStatus, self.status, GraphStatus.AVAILABLE),
        )
        object.__setattr__(self, "graph_fingerprint", _clean_text(self.graph_fingerprint, 128).lower())
        object.__setattr__(
            self,
            "direction",
            _normalize_trail_direction(self.direction, _DIRECTION_DOWNSTREAM),
        )
        object.__setattr__(self, "built_at", _ensure_utc(self.built_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))

        object.__setattr__(self, "seeds_requested", max(0, _as_int(self.seeds_requested, 0)))
        object.__setattr__(self, "seeds_used", max(0, _as_int(self.seeds_used, 0)))
        object.__setattr__(self, "seeds_missing", max(0, _as_int(self.seeds_missing, 0)))
        object.__setattr__(self, "trails", tuple(self.trails or ()))

        object.__setattr__(
            self,
            "counts",
            MappingProxyType(
                {
                    str(key): max(0, _as_int(value, 0))
                    for key, value in (self.counts or {}).items()
                }
            ),
        )
        object.__setattr__(
            self,
            "node_type_counts",
            MappingProxyType(
                {
                    _normalize_node_type(key): max(0, _as_int(value, 0))
                    for key, value in (self.node_type_counts or {}).items()
                }
            ),
        )
        object.__setattr__(
            self,
            "edge_type_counts",
            MappingProxyType(
                {
                    _normalize_edge_type(key): max(0, _as_int(value, 0))
                    for key, value in (self.edge_type_counts or {}).items()
                }
            ),
        )
        object.__setattr__(
            self,
            "currency_counts",
            MappingProxyType(
                {
                    _normalize_currency(key): max(0, _as_int(value, 0))
                    for key, value in (self.currency_counts or {}).items()
                    if _normalize_currency(key)
                }
            ),
        )
        object.__setattr__(
            self,
            "length_distribution",
            MappingProxyType(
                {
                    max(0, _as_int(key, 0)): max(0, _as_int(value, 0))
                    for key, value in (self.length_distribution or {}).items()
                }
            ),
        )

        object.__setattr__(self, "issues", tuple(_as_issue(issue) for issue in (self.issues or ())))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))
        object.__setattr__(self, "expose_node_ids", _as_bool(self.expose_node_ids, False))
        object.__setattr__(self, "expose_edge_ids", _as_bool(self.expose_edge_ids, False))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": TRAILS_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, GraphStatus.AVAILABLE.value),
                        "graph_fingerprint": self.graph_fingerprint,
                        "direction": self.direction,
                        "seeds_requested": self.seeds_requested,
                        "seeds_used": self.seeds_used,
                        "seeds_missing": self.seeds_missing,
                        "trail_count": len(self.trails),
                        "counts": dict(self.counts),
                        "node_type_counts": dict(self.node_type_counts),
                        "edge_type_counts": dict(self.edge_type_counts),
                        "currency_counts": dict(self.currency_counts),
                        "length_distribution": {
                            str(key): value
                            for key, value in self.length_distribution.items()
                        },
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def __len__(self) -> int:
        return len(self.trails)

    def to_public_dict(self) -> dict[str, Any]:
        scores = [trail.score for trail in self.trails]
        lengths = [trail.edge_count for trail in self.trails]

        payload: dict[str, Any] = {
            "ok": self.ok,
            "status": _enum_value(self.status, GraphStatus.AVAILABLE.value),
            "graph_fingerprint": self.graph_fingerprint,
            "direction": self.direction,
            "built_at": self.built_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "seeds_requested": int(self.seeds_requested),
            "seeds_used": int(self.seeds_used),
            "seeds_missing": int(self.seeds_missing),
            "trail_count": len(self.trails),
            "counts": dict(self.counts),
            "node_type_counts": dict(self.node_type_counts),
            "edge_type_counts": dict(self.edge_type_counts),
            "currency_counts": dict(self.currency_counts),
            "length_distribution": {
                str(key): int(value)
                for key, value in self.length_distribution.items()
            },
            "score_summary": {
                "available": bool(scores),
                "min": _round6(min(scores)) if scores else None,
                "max": _round6(max(scores)) if scores else None,
                "mean": _round6(sum(scores) / float(len(scores))) if scores else None,
            },
            "length_summary": {
                "available": bool(lengths),
                "min": int(min(lengths)) if lengths else None,
                "max": int(max(lengths)) if lengths else None,
                "mean": _round6(sum(lengths) / float(len(lengths))) if lengths else None,
            },
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "raw_attributes_exposed": False,
            "amounts_exposed": False,
            "cross_currency_conversion": False,
            "caveats": list(_TRAIL_CAVEATS),
            "safety_flags": dict(_TRAIL_SAFETY_FLAGS),
        }

        if self.expose_node_ids:
            payload["trails"] = [trail.to_dict(include_node_ids=True) for trail in self.trails]
        else:
            payload["trails_omitted"] = True
            payload["trail_summaries"] = [
                trail.to_dict(include_node_ids=False)
                for trail in self.trails
            ]

        return payload

    def to_internal_dict(self) -> dict[str, Any]:
        payload = self.to_public_dict()
        payload.pop("trails_omitted", None)
        payload["trails"] = [trail.to_dict(include_node_ids=True) for trail in self.trails]
        payload["internal_only"] = True
        return payload


# -----------------------------------------------------------------------------
# Trail scoring helpers
# -----------------------------------------------------------------------------


def _is_account_like(node_type: str) -> bool:
    return node_type in {"account", "unknown"}


def _is_transaction_like(node_type: str) -> bool:
    return node_type in {"transaction", "unknown"}


def _trail_score(
    node_sequence: Sequence[str],
    edge_types: Sequence[str],
    currencies: Sequence[str],
    node_types: Mapping[str, str],
    options: TrailOptions,
) -> tuple[float, dict[str, float]]:
    edge_count = len(edge_types)

    if edge_count <= 0:
        return 0.0, {}

    account_count = sum(
        1
        for node_id in node_sequence
        if _is_account_like(node_types.get(node_id, "unknown"))
    )
    transaction_count = sum(
        1
        for node_id in node_sequence
        if _is_transaction_like(node_types.get(node_id, "unknown"))
    )

    length_score = _clip_float(
        float(edge_count) / float(max(1, int(options.max_trail_edges))),
        0.0,
        1.0,
        0.0,
    )

    account_positions = max(1, account_count)
    distinct_accounts = len(
        {
            node_id
            for node_id in node_sequence
            if _is_account_like(node_types.get(node_id, "unknown"))
        }
    )
    diversity_score = _clip_float(float(distinct_accounts) / float(account_positions), 0.0, 1.0, 0.0)

    expected_transactions = max(1, edge_count // 2)
    transaction_score = _clip_float(float(transaction_count) / float(expected_transactions), 0.0, 1.0, 0.0)

    distinct_currencies = len({currency for currency in currencies if currency})

    if distinct_currencies <= 1:
        currency_score = 1.0
    else:
        currency_score = max(0.0, 1.0 - 0.25 * float(distinct_currencies - 1))

    composite = (
        0.40 * length_score
        + 0.25 * diversity_score
        + 0.20 * transaction_score
        + 0.15 * currency_score
    )

    components = {
        "length": _round6(length_score),
        "account_diversity": _round6(diversity_score),
        "transaction_structure": _round6(transaction_score),
        "currency_consistency": _round6(currency_score),
    }

    return _round6(_clip_float(composite, 0.0, 1.0, 0.0)), components


def _trail_id(
    options: TrailOptions,
    direction: str,
    seed_node_id: str,
    node_sequence: Sequence[str],
) -> str:
    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.graph.trails.trail.{safe_namespace}"
    message = "|".join([direction, seed_node_id, *node_sequence])
    return _hmac_hex(options.salt, domain, message)[:64]


def _node_rank(options: TrailOptions, node_id: str) -> int:
    return _stable_rank(
        options.salt,
        "muleguard.graph.trails.node_order",
        options.seed,
        options.namespace,
        node_id,
    )


def _candidate_sort_key(options: TrailOptions, node_id: str, edge: _FlowEdge) -> tuple[int, int, str]:
    return (
        -int(edge.weight),
        _node_rank(options, node_id),
        node_id,
    )


# -----------------------------------------------------------------------------
# Trail detection internals
# -----------------------------------------------------------------------------


def _select_default_seeds(
    graph: _NormalizedTrailGraph,
    direction: str,
    options: TrailOptions,
    issues: list[TrailIssue],
) -> list[str]:
    account_nodes = [
        node_id
        for node_id in graph.node_ids
        if _is_account_like(graph.node_types.get(node_id, "unknown"))
    ]

    if direction == _DIRECTION_UPSTREAM:
        candidate_nodes = [
            node_id
            for node_id in account_nodes
            if graph.flow_rev.get(node_id)
        ]
    else:
        candidate_nodes = [
            node_id
            for node_id in account_nodes
            if graph.flow_adj.get(node_id)
        ]

    if not candidate_nodes:
        candidate_nodes = account_nodes

    def sort_key(node_id: str) -> tuple[int, str]:
        if options.deterministic_order:
            return (_node_rank(options, node_id), node_id)

        return (0, node_id)

    candidate_nodes.sort(key=sort_key)

    if len(candidate_nodes) > options.max_seeds:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="trail_seed_limit_applied",
            message="Default seed candidates exceeded configured seed limit and were truncated.",
            details={
                "candidates": len(candidate_nodes),
                "max_seeds": options.max_seeds,
            },
        )
        candidate_nodes = candidate_nodes[: options.max_seeds]

    return candidate_nodes


def _extract_seeds(
    graph: _NormalizedTrailGraph,
    seeds: Any,
    direction: str,
    options: TrailOptions,
    issues: list[TrailIssue],
) -> tuple[list[str], int, int]:
    raw_seeds = _as_sequence(seeds)

    if not raw_seeds:
        selected = _select_default_seeds(graph, direction, options, issues)
        return selected, len(selected), 0

    if len(raw_seeds) > options.max_seeds:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="trail_seed_limit_truncated",
            message="Seed input exceeded configured limit and was truncated.",
            details={
                "submitted": len(raw_seeds),
                "max_seeds": options.max_seeds,
            },
        )
        raw_seeds = raw_seeds[: options.max_seeds]

    selected: list[str] = []
    missing = 0

    for seed in raw_seeds:
        raw_id: Any

        if isinstance(seed, Mapping):
            raw_id = _get_field(
                seed,
                (
                    "node_id",
                    "id",
                    "subject_ref_hash",
                    "subject_ref",
                    "subject_hash",
                    "account_id",
                    "acct_id",
                ),
                None,
            )
        else:
            raw_id = seed

        seed_id = _hash_identifier(raw_id, options, "seed")

        if seed_id is None:
            missing += 1
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="trail_seed_unusable",
                message="Seed identifier was unusable and was skipped.",
            )
            continue

        if seed_id not in graph.node_types:
            missing += 1
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.INFO,
                code="trail_seed_not_found",
                message="Seed node was not found in normalized graph.",
            )
            continue

        if not _is_account_like(graph.node_types.get(seed_id, "unknown")):
            missing += 1
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.INFO,
                code="trail_seed_not_account_like",
                message="Seed node is not account-like and was skipped.",
                details={"node_type": graph.node_types.get(seed_id, "unknown")},
            )
            continue

        if seed_id not in selected:
            selected.append(seed_id)

        if len(selected) >= options.max_seeds:
            break

    def sort_key(node_id: str) -> tuple[int, str]:
        if options.deterministic_order:
            return (_node_rank(options, node_id), node_id)

        return (0, node_id)

    selected.sort(key=sort_key)
    return selected, len(selected), missing


def _valid_trail(
    node_sequence: Sequence[str],
    edge_count: int,
    node_types: Mapping[str, str],
    options: TrailOptions,
) -> bool:
    if edge_count < options.min_trail_edges:
        return False

    if not node_sequence:
        return False

    first_type = node_types.get(node_sequence[0], "unknown")
    last_type = node_types.get(node_sequence[-1], "unknown")

    return _is_account_like(first_type) and _is_account_like(last_type)


def _detect_trails_for_adjacency(
    graph: _NormalizedTrailGraph,
    adj: Mapping[str, Mapping[str, _FlowEdge]],
    seeds: Sequence[str],
    direction: str,
    options: TrailOptions,
    issues: list[TrailIssue],
    start_time: float,
) -> tuple[list[Trail], int, bool]:
    trails: list[Trail] = []
    seen_keys: set[str] = set()
    scanned_nodes: set[str] = set()
    truncated = False
    branch_cap_events = 0

    allowed_currencies = set(options.allowed_currencies) if options.allowed_currencies else None

    for seed in seeds:
        if len(trails) >= options.max_trails:
            truncated = True
            break

        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="trail_time_budget_exhausted",
                message="Trail detection stopped after reaching configured time budget.",
                details={"trails_found": len(trails), "direction": direction},
            )
            truncated = True
            break

        stack: list[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], frozenset[str]]] = [
            (seed, (seed,), (), (), frozenset({seed}))
        ]

        while stack:
            if len(trails) >= options.max_trails:
                truncated = True
                break

            if len(scanned_nodes) > options.max_scan_nodes:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="trail_scan_node_limit_reached",
                    message="Trail detection stopped after reaching configured scan-node limit.",
                    details={"scanned_nodes": len(scanned_nodes), "direction": direction},
                )
                truncated = True
                break

            if _time_exceeded(start_time, options.max_time_ms):
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="trail_time_budget_exhausted",
                    message="Trail detection stopped after reaching configured time budget.",
                    details={"trails_found": len(trails), "direction": direction},
                )
                truncated = True
                break

            node, node_sequence, edge_types, currencies, visited = stack.pop()
            scanned_nodes.add(node)

            edge_count = len(edge_types)
            neighbors = dict(adj.get(node, {}))

            candidate_items: list[tuple[str, _FlowEdge]] = []

            for next_node, flow_edge in neighbors.items():
                if not options.include_cycles and next_node in visited:
                    continue

                if allowed_currencies is not None and flow_edge.currencies:
                    if not allowed_currencies.intersection(flow_edge.currencies):
                        continue

                candidate_items.append((next_node, flow_edge))

            candidate_items.sort(
                key=lambda item: _candidate_sort_key(options, item[0], item[1])
            )

            if len(candidate_items) > options.max_branching_per_node:
                branch_cap_events += 1
                candidate_items = candidate_items[: options.max_branching_per_node]

            terminal = not candidate_items or edge_count >= options.max_trail_edges

            if terminal and _valid_trail(node_sequence, edge_count, graph.node_types, options):
                trail_key = "|".join(node_sequence)

                if trail_key not in seen_keys:
                    seen_keys.add(trail_key)

                    score, components = _trail_score(
                        node_sequence,
                        edge_types,
                        currencies,
                        graph.node_types,
                        options,
                    )

                    account_count = sum(
                        1
                        for node_id in node_sequence
                        if _is_account_like(graph.node_types.get(node_id, "unknown"))
                    )
                    transaction_count = sum(
                        1
                        for node_id in node_sequence
                        if _is_transaction_like(graph.node_types.get(node_id, "unknown"))
                    )

                    trails.append(
                        Trail(
                            trail_id=_trail_id(options, direction, seed, node_sequence),
                            direction=direction,
                            seed_node_id=seed,
                            node_sequence=node_sequence,
                            edge_types=edge_types,
                            currencies=tuple(dict.fromkeys(currencies)),
                            edge_count=edge_count,
                            account_count=account_count,
                            transaction_count=transaction_count,
                            score=score,
                            score_components=components,
                            metadata={
                                "terminal": bool(terminal),
                                "max_length_reached": edge_count >= options.max_trail_edges,
                                "partial": bool(options.include_partial_trails and not terminal),
                            },
                        )
                    )

                    if len(trails) >= options.max_trails:
                        truncated = True
                        break

            if options.include_partial_trails and edge_count >= options.min_trail_edges and not terminal:
                if _valid_trail(node_sequence, edge_count, graph.node_types, options):
                    trail_key = "|".join(node_sequence)

                    if trail_key not in seen_keys:
                        seen_keys.add(trail_key)

                        score, components = _trail_score(
                            node_sequence,
                            edge_types,
                            currencies,
                            graph.node_types,
                            options,
                        )

                        account_count = sum(
                            1
                            for node_id in node_sequence
                            if _is_account_like(graph.node_types.get(node_id, "unknown"))
                        )
                        transaction_count = sum(
                            1
                            for node_id in node_sequence
                            if _is_transaction_like(graph.node_types.get(node_id, "unknown"))
                        )

                        trails.append(
                            Trail(
                                trail_id=_trail_id(options, direction, seed, node_sequence),
                                direction=direction,
                                seed_node_id=seed,
                                node_sequence=node_sequence,
                                edge_types=edge_types,
                                currencies=tuple(dict.fromkeys(currencies)),
                                edge_count=edge_count,
                                account_count=account_count,
                                transaction_count=transaction_count,
                                score=score,
                                score_components=components,
                                metadata={
                                    "terminal": False,
                                    "max_length_reached": False,
                                    "partial": True,
                                },
                            )
                        )

                        if len(trails) >= options.max_trails:
                            truncated = True
                            break

            if terminal:
                continue

            # Push candidates in reverse order so deterministic sorting is
            # preserved when popping from the stack.
            for next_node, flow_edge in reversed(candidate_items):
                next_edge_types = (*edge_types, *flow_edge.edge_types)
                next_currencies = (*currencies, *flow_edge.currencies)
                next_visited = visited | {next_node}

                stack.append(
                    (
                        next_node,
                        (*node_sequence, next_node),
                        next_edge_types,
                        next_currencies,
                        next_visited,
                    )
                )

    if branch_cap_events > 0:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="trail_branch_cap_applied",
            message="Trail branching cap applied to one or more nodes.",
            details={"events": branch_cap_events, "direction": direction},
        )

    trails.sort(
        key=lambda item: (
            -float(item.score),
            -int(item.edge_count),
            item.direction,
            item.seed_node_id,
            item.trail_id,
        )
    )

    return trails, len(scanned_nodes), truncated


# -----------------------------------------------------------------------------
# Trail harness
# -----------------------------------------------------------------------------


class TrailHarness:
    """
    Bounded deterministic synthetic candidate money-trail harness.

    This harness detects candidate trails only. Candidate trails are heuristic
    investigative flow views. They are not proof of wrongdoing and must not
    trigger automatic adverse customer action.
    """

    def __init__(self, options: TrailOptions | None = None) -> None:
        self.options = options or TrailOptions.from_settings()
        self._lock = threading.RLock()

    def detect(self, view: Any, seeds: Any = None) -> TrailResult:
        """
        Detect bounded candidate money trails from one graph view.
        """
        opts = self.options
        issues: list[TrailIssue] = []
        start_time = time.monotonic()

        def blocked_result(status: GraphStatus) -> TrailResult:
            return TrailResult(
                ok=status != GraphStatus.FAILED,
                status=status,
                direction=opts.direction,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                seeds_requested=0,
                seeds_used=0,
                seeds_missing=0,
                trails=(),
                counts={},
                node_type_counts={},
                edge_type_counts={},
                currency_counts={},
                length_distribution={},
                issues=tuple(issues),
                metadata={"options": opts.safe_summary()},
                expose_node_ids=opts.expose_node_ids,
                expose_edge_ids=opts.expose_edge_ids,
                fingerprint="",
            )

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="trails_disabled",
                message="Trail detection is disabled.",
            )
            return blocked_result(GraphStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Trail detection requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return blocked_result(GraphStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Trail detection is blocked in production-like environments.",
            )
            return blocked_result(GraphStatus.BLOCKED)

        graph = _normalize_trail_graph(view, opts, issues, start_time)

        if graph is None:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="trail_graph_unavailable",
                message="Graph input could not be normalized for trail detection.",
            )
            return blocked_result(GraphStatus.FAILED)

        if not graph.node_ids or graph.money_edge_count <= 0:
            return TrailResult(
                ok=True,
                status=GraphStatus.EMPTY,
                graph_fingerprint=graph.fingerprint,
                direction=opts.direction,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                seeds_requested=len(_as_sequence(seeds)),
                seeds_used=0,
                seeds_missing=0,
                trails=(),
                counts={
                    "nodes": len(graph.node_ids),
                    "money_edges": graph.money_edge_count,
                    "trails": 0,
                },
                node_type_counts=dict(Counter(graph.node_types.values())),
                edge_type_counts={},
                currency_counts={},
                length_distribution={},
                issues=tuple(issues),
                metadata={
                    "graph_fingerprint": graph.fingerprint,
                    "options": opts.safe_summary(),
                },
                expose_node_ids=opts.expose_node_ids,
                expose_edge_ids=opts.expose_edge_ids,
                fingerprint="",
            )

        directions: list[str] = []

        if opts.direction == _DIRECTION_BOTH:
            directions = [_DIRECTION_DOWNSTREAM, _DIRECTION_UPSTREAM]
        else:
            directions = [opts.direction]

        all_trails: list[Trail] = []
        total_seeds_requested = 0
        total_seeds_used = 0
        total_seeds_missing = 0
        total_scanned_nodes = 0
        truncated = False

        for direction in directions:
            if len(all_trails) >= opts.max_trails:
                truncated = True
                break

            if _time_exceeded(start_time, opts.max_time_ms):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="trail_time_budget_exhausted",
                    message="Trail detection stopped before processing all requested directions.",
                    details={"direction": direction},
                )
                truncated = True
                break

            selected_seeds, seeds_used, seeds_missing = _extract_seeds(
                graph,
                seeds,
                direction,
                opts,
                issues,
            )

            total_seeds_requested += max(len(_as_sequence(seeds)), len(selected_seeds))
            total_seeds_used += seeds_used
            total_seeds_missing += seeds_missing

            if not selected_seeds:
                continue

            adj = graph.flow_adj if direction == _DIRECTION_DOWNSTREAM else graph.flow_rev

            direction_trails, scanned_nodes, direction_truncated = _detect_trails_for_adjacency(
                graph=graph,
                adj=adj,
                seeds=selected_seeds,
                direction=direction,
                options=opts,
                issues=issues,
                start_time=start_time,
            )

            all_trails.extend(direction_trails)
            total_scanned_nodes += scanned_nodes

            if direction_truncated:
                truncated = True

            if len(all_trails) > opts.max_trails:
                all_trails = all_trails[: opts.max_trails]
                truncated = True

        all_trails.sort(
            key=lambda item: (
                -float(item.score),
                -int(item.edge_count),
                item.direction,
                item.seed_node_id,
                item.trail_id,
            )
        )

        if len(all_trails) > opts.max_trails:
            all_trails = all_trails[: opts.max_trails]
            truncated = True

        node_type_counter: Counter[str] = Counter()
        edge_type_counter: Counter[str] = Counter()
        currency_counter: Counter[str] = Counter()
        length_counter: Counter[int] = Counter()

        for trail in all_trails:
            for node_id in trail.node_sequence:
                node_type_counter[graph.node_types.get(node_id, "unknown")] += 1

            for edge_type in trail.edge_types:
                edge_type_counter[edge_type] += 1

            for currency in trail.currencies:
                currency_counter[currency] += 1

            length_counter[int(trail.edge_count)] += 1

        counts = {
            "seeds_requested": total_seeds_requested,
            "seeds_used": total_seeds_used,
            "seeds_missing": total_seeds_missing,
            "trails": len(all_trails),
            "scanned_nodes": total_scanned_nodes,
            "nodes": len(graph.node_ids),
            "money_edges": graph.money_edge_count,
            "input_nodes": graph.input_node_count,
            "input_edges": graph.input_edge_count,
            "issues": len(issues),
        }

        if _has_error(issues):
            status = GraphStatus.FAILED
        elif truncated or graph.truncated_nodes or graph.truncated_edges or _time_exceeded(start_time, opts.max_time_ms):
            status = GraphStatus.TRUNCATED
        elif len(all_trails) == 0:
            status = GraphStatus.EMPTY
        elif _has_warning(issues):
            status = GraphStatus.DEGRADED
        else:
            status = GraphStatus.AVAILABLE

        metadata = {
            "trail_version": TRAILS_VERSION,
            "graph_fingerprint": graph.fingerprint,
            "directions": directions,
            "options": opts.safe_summary(),
            "scanned_nodes": total_scanned_nodes,
            "trail_limit_applied": truncated,
            "node_limit_applied": graph.truncated_nodes,
            "edge_limit_applied": graph.truncated_edges,
            "raw_attributes_exposed": False,
            "amounts_exposed": False,
            "cross_currency_conversion": False,
            "caveats": list(_TRAIL_CAVEATS),
            "safety_flags": dict(_TRAIL_SAFETY_FLAGS),
        }

        return TrailResult(
            ok=status in {GraphStatus.AVAILABLE, GraphStatus.DEGRADED, GraphStatus.TRUNCATED, GraphStatus.EMPTY},
            status=status,
            graph_fingerprint=graph.fingerprint,
            direction=opts.direction,
            built_at=_now_utc(),
            duration_ms=_elapsed_ms(start_time),
            seeds_requested=total_seeds_requested,
            seeds_used=total_seeds_used,
            seeds_missing=total_seeds_missing,
            trails=tuple(all_trails),
            counts=counts,
            node_type_counts=dict(node_type_counter),
            edge_type_counts=dict(edge_type_counter),
            currency_counts=dict(currency_counter),
            length_distribution=dict(sorted(length_counter.items())),
            issues=tuple(issues),
            metadata=metadata,
            expose_node_ids=opts.expose_node_ids,
            expose_edge_ids=opts.expose_edge_ids,
            fingerprint="",
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "caveats": list(_TRAIL_CAVEATS),
            "safety_flags": dict(_TRAIL_SAFETY_FLAGS),
        }


_default_harness: Optional[TrailHarness] = None
_default_harness_lock = threading.Lock()


def get_trail_harness(
    options: TrailOptions | None = None,
    *,
    rebuild: bool = False,
) -> TrailHarness:
    """
    Return a process-wide trail harness.
    """
    global _default_harness

    with _default_harness_lock:
        if _default_harness is None or rebuild or options is not None:
            _default_harness = TrailHarness(options=options or TrailOptions.from_settings())

        return _default_harness


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def detect_money_trails(
    view: Any,
    seeds: Any = None,
    options: TrailOptions | None = None,
    *,
    harness: TrailHarness | None = None,
) -> TrailResult:
    """
    Detect bounded synthetic candidate money trails.
    """
    active_harness = harness or get_trail_harness(options)
    return active_harness.detect(view, seeds)


def summarize_trails(result: Any) -> dict[str, Any]:
    """
    Return safe public summary for a trail result.
    """
    if isinstance(result, TrailResult):
        return result.to_public_dict()

    if isinstance(result, Mapping):
        return _safe_detail_value(result) or {}

    return {}


def get_trail_metadata() -> dict[str, Any]:
    """
    Return safe, serializable trail metadata.
    """
    options = TrailOptions.from_settings()

    return {
        "package": "muleguard.backend.graph.trails",
        "version": TRAILS_VERSION,
        "directions": list(_TRAIL_DIRECTIONS),
        "money_flow_edge_types": sorted(_MONEY_FLOW_EDGE_TYPES),
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
        "backend": "in_memory_deterministic",
        "distributed": False,
        "durable": False,
        "hard_limits": {
            "max_seeds": _HARD_MAX_SEEDS,
            "max_trails": _HARD_MAX_TRAILS,
            "max_trail_edges": _HARD_MAX_TRAIL_EDGES,
            "max_branching_per_node": _HARD_MAX_BRANCHING,
            "max_scan_nodes": _HARD_MAX_SCAN_NODES,
            "max_issues": _HARD_MAX_ISSUES,
            "max_time_ms": _HARD_MAX_TIME_MS,
        },
        "forbidden_field_count": len(_FORBIDDEN_TRAIL_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_TRAIL_CAVEATS),
        "safety_flags": dict(_TRAIL_SAFETY_FLAGS),
    }


__all__ = [
    "Trail",
    "TrailHarness",
    "TrailIssue",
    "TrailOptions",
    "TrailResult",
    "detect_money_trails",
    "get_trail_harness",
    "get_trail_metadata",
    "summarize_trails",
]