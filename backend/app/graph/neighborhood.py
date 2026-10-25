"""
MULEGUARD backend graph neighborhood.

This module provides the canonical bounded neighborhood-extraction layer for the
synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- extract bounded, deterministic, pseudonymous graph neighborhoods around one or
  more seed nodes from synthetic graph views produced by `app.graph.builder` or
  compatible graph payloads;
- support directed outgoing, incoming, and bidirectional bounded traversal with
  configurable depth, node, edge, neighbor, seed, and time budgets;
- preserve privacy by using salted one-way pseudonymous node identifiers and by
  excluding raw feature values, raw identifiers, raw complaint narratives,
  subject-label pairs, secrets, tokens, passwords, database URLs, filesystem
  paths, and model artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited graph fields;
- provide safe neighborhood results with bounded node and edge sets, distance
  metadata, degree metadata, type counts, truncation diagnostics, fingerprints,
  and API-safe summaries;
- remain import-safe, dependency-light, and usable by graph services, rules,
  ML feature builders, evaluation harnesses, tests, seeders, offline fixtures,
  and developer tooling.

This module extracts neighborhoods only. It does not traverse unbounded paths,
train models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for neighborhood extraction.
- Graph neighborhoods are investigative association views only. They are not
  proof of common control, fraud, intent, conspiracy, or wrongdoing.
- Neighborhood ordering and distance are heuristic operational views only. They
  are not legal, evidentiary, or causal priority.
- Only completed synthetic transactions should be modeled as settled money-flow
  edges by upstream builders. Neighborhood extraction does not infer settlement.
- Mixed-currency amounts are never converted. Currency amounts are not exposed
  by neighborhood summaries.
- Raw complaint narratives, raw identifiers, ground-truth labels, scenario IDs,
  fraud-ring IDs, secrets, tokens, passwords, database URLs, filesystem paths,
  and model artifact paths are never retained or exposed.
- Neighborhood extraction never triggers automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Truncation, emptiness, and unavailability are reported honestly rather than
  silently omitted or invented.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external graph engines.
- This module does not persist durable neighborhood snapshots.
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


logger = logging.getLogger("muleguard.backend.graph.neighborhood")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

NEIGHBORHOOD_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.graph.neighborhood.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

_DEFAULT_MAX_SEEDS: Final[int] = 100
_HARD_MAX_SEEDS: Final[int] = 1_000

_DEFAULT_MAX_NODES: Final[int] = 1_000
_HARD_MAX_NODES: Final[int] = 10_000

_DEFAULT_MAX_EDGES: Final[int] = 2_000
_HARD_MAX_EDGES: Final[int] = 20_000

_DEFAULT_MAX_DEPTH: Final[int] = 3
_HARD_MAX_DEPTH: Final[int] = 5

_DEFAULT_MAX_NEIGHBORS_PER_NODE: Final[int] = 200
_HARD_MAX_NEIGHBORS_PER_NODE: Final[int] = 1_000

_DEFAULT_MAX_ISSUES: Final[int] = 100
_HARD_MAX_ISSUES: Final[int] = 500

_DEFAULT_MAX_TIME_MS: Final[int] = 15_000
_HARD_MAX_TIME_MS: Final[int] = 300_000

_INPUT_MAX_NODES: Final[int] = _HARD_MAX_NODES
_INPUT_MAX_EDGES: Final[int] = _HARD_MAX_EDGES

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_NODE_ID_LENGTH: Final[int] = 256

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

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

_DIRECTION_OUTGOING: Final[str] = "outgoing"
_DIRECTION_INCOMING: Final[str] = "incoming"
_DIRECTION_BOTH: Final[str] = "both"

_DIRECTIONS: Final[tuple[str, ...]] = (
    _DIRECTION_OUTGOING,
    _DIRECTION_INCOMING,
    _DIRECTION_BOTH,
)

_DIRECTION_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "out": _DIRECTION_OUTGOING,
        "outbound": _DIRECTION_OUTGOING,
        "downstream": _DIRECTION_OUTGOING,
        "in": _DIRECTION_INCOMING,
        "inbound": _DIRECTION_INCOMING,
        "upstream": _DIRECTION_INCOMING,
        "bidirectional": _DIRECTION_BOTH,
        "all": _DIRECTION_BOTH,
        "undirected": _DIRECTION_BOTH,
    }
)

_FORBIDDEN_NEIGHBORHOOD_FIELDS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_NEIGHBORHOOD_TOKENS: Final[tuple[str, ...]] = (
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

_NEIGHBORHOOD_CAVEATS: Final[tuple[str, ...]] = (
    *(GRAPH_CAVEATS if isinstance(GRAPH_CAVEATS, tuple) else tuple(GRAPH_CAVEATS)),
    "Graph neighborhoods are bounded investigative views only.",
    "Neighborhood ordering and distance are heuristic operational views only.",
    "Node and edge identifiers are pseudonymous and salted.",
    "Raw node attributes and raw edge payloads are never exposed in public summaries.",
    "Neighborhood extraction must not trigger automatic adverse customer action.",
)

_NEIGHBORHOOD_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        **dict(GRAPH_SAFETY_FLAGS),
        "neighborhoods_are_investigative_views_only": True,
        "bounded_neighborhood_extraction_required": True,
        "deterministic_neighborhood_extraction": True,
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

    if canonical in _FORBIDDEN_NEIGHBORHOOD_FIELDS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in _FORBIDDEN_NEIGHBORHOOD_TOKENS)


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


def _normalize_direction(value: Any, default: str = _DIRECTION_BOTH) -> str:
    token = _normalize_token(value)

    if token in _DIRECTIONS:
        return token

    alias = _DIRECTION_ALIASES.get(token)

    if alias is not None:
        return alias

    return default


def _normalize_optional_token_set(value: Any) -> Optional[tuple[str, ...]]:
    if value is None:
        return None

    tokens: list[str] = []

    for item in _as_sequence(value):
        token = _normalize_token(item)

        if token:
            tokens.append(token)

    if not tokens:
        return None

    return tuple(dict.fromkeys(tokens))


def _normalize_node_type_set(value: Any) -> Optional[tuple[str, ...]]:
    tokens = _normalize_optional_token_set(value)

    if tokens is None:
        return None

    return tuple(dict.fromkeys(_normalize_node_type(token) for token in tokens))


def _normalize_edge_type_set(value: Any) -> Optional[tuple[str, ...]]:
    tokens = _normalize_optional_token_set(value)

    if tokens is None:
        return None

    return tuple(dict.fromkeys(_normalize_edge_type(token) for token in tokens))


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


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NeighborhoodIssue:
    """
    Safe neighborhood issue.

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
    issues: list[NeighborhoodIssue],
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

        issues[-1] = NeighborhoodIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        NeighborhoodIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=_clean_text(field, 200) if field else None,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[NeighborhoodIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _has_warning(issues: Sequence[NeighborhoodIssue]) -> bool:
    return any(issue.severity == IssueSeverity.WARNING for issue in issues)


def _as_issue(value: Any) -> NeighborhoodIssue:
    if isinstance(value, NeighborhoodIssue):
        return value

    if isinstance(value, Mapping):
        fields = set(getattr(NeighborhoodIssue, "__dataclass_fields__", {}).keys())
        clean = {key: item for key, item in value.items() if key in fields}

        try:
            return NeighborhoodIssue(**clean)
        except Exception:
            return NeighborhoodIssue(
                severity=IssueSeverity.WARNING,
                code="malformed_issue",
                message="Malformed issue omitted.",
            )

    return NeighborhoodIssue(
        severity=IssueSeverity.WARNING,
        code="invalid_issue",
        message="Invalid issue omitted.",
    )


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NeighborhoodOptions:
    """
    Bounded neighborhood extraction policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    direction: str = _DIRECTION_BOTH
    max_seeds: int = _DEFAULT_MAX_SEEDS
    max_nodes: int = _DEFAULT_MAX_NODES
    max_edges: int = _DEFAULT_MAX_EDGES
    max_depth: int = _DEFAULT_MAX_DEPTH
    max_neighbors_per_node: int = _DEFAULT_MAX_NEIGHBORS_PER_NODE
    max_issues: int = _DEFAULT_MAX_ISSUES
    max_time_ms: int = _DEFAULT_MAX_TIME_MS

    allowed_node_types: Optional[tuple[str, ...]] = None
    allowed_edge_types: Optional[tuple[str, ...]] = None

    include_isolated_seeds: bool = True
    include_internal_edges: bool = True
    deterministic_order: bool = True

    expose_node_ids: bool = True
    expose_edge_ids: bool = False
    expose_raw_attributes: bool = False

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
            _normalize_direction(self.direction, _DIRECTION_BOTH),
        )

        object.__setattr__(
            self,
            "max_seeds",
            _clamp_int(self.max_seeds, 1, _HARD_MAX_SEEDS, _DEFAULT_MAX_SEEDS),
        )
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
            "max_depth",
            _clamp_int(self.max_depth, 0, _HARD_MAX_DEPTH, _DEFAULT_MAX_DEPTH),
        )
        object.__setattr__(
            self,
            "max_neighbors_per_node",
            _clamp_int(
                self.max_neighbors_per_node,
                1,
                _HARD_MAX_NEIGHBORS_PER_NODE,
                _DEFAULT_MAX_NEIGHBORS_PER_NODE,
            ),
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
            "allowed_node_types",
            _normalize_node_type_set(self.allowed_node_types),
        )
        object.__setattr__(
            self,
            "allowed_edge_types",
            _normalize_edge_type_set(self.allowed_edge_types),
        )

        object.__setattr__(self, "include_isolated_seeds", _as_bool(self.include_isolated_seeds, True))
        object.__setattr__(self, "include_internal_edges", _as_bool(self.include_internal_edges, True))
        object.__setattr__(self, "deterministic_order", _as_bool(self.deterministic_order, True))

        # Pseudonymous node IDs may be exposed to authorized internal consumers.
        object.__setattr__(self, "expose_node_ids", _as_bool(self.expose_node_ids, True))

        # Edge IDs and raw attributes are not exposed by default.
        object.__setattr__(self, "expose_edge_ids", _as_bool(self.expose_edge_ids, False))
        object.__setattr__(self, "expose_raw_attributes", False)

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "NeighborhoodOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "GRAPH_NEIGHBORHOOD_SALT", None)
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
            enabled=_as_bool(_setting(settings, "GRAPH_NEIGHBORHOOD_ENABLED", True), True)
            and _as_bool(_setting(settings, "GRAPH_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "GRAPH_NEIGHBORHOOD_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "GRAPH_NEIGHBORHOOD_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "GRAPH_NEIGHBORHOOD_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "GRAPH_NEIGHBORHOOD_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            direction=str(_setting(settings, "GRAPH_NEIGHBORHOOD_DIRECTION", _DIRECTION_BOTH)),
            max_seeds=_as_int(_setting(settings, "GRAPH_NEIGHBORHOOD_MAX_SEEDS", _DEFAULT_MAX_SEEDS), _DEFAULT_MAX_SEEDS),
            max_nodes=_as_int(_setting(settings, "GRAPH_NEIGHBORHOOD_MAX_NODES", _DEFAULT_MAX_NODES), _DEFAULT_MAX_NODES),
            max_edges=_as_int(_setting(settings, "GRAPH_NEIGHBORHOOD_MAX_EDGES", _DEFAULT_MAX_EDGES), _DEFAULT_MAX_EDGES),
            max_depth=_as_int(_setting(settings, "GRAPH_NEIGHBORHOOD_MAX_DEPTH", _DEFAULT_MAX_DEPTH), _DEFAULT_MAX_DEPTH),
            max_neighbors_per_node=_as_int(
                _setting(
                    settings,
                    "GRAPH_NEIGHBORHOOD_MAX_NEIGHBORS_PER_NODE",
                    _DEFAULT_MAX_NEIGHBORS_PER_NODE,
                ),
                _DEFAULT_MAX_NEIGHBORS_PER_NODE,
            ),
            max_issues=_as_int(
                _setting(settings, "GRAPH_NEIGHBORHOOD_MAX_ISSUES", _DEFAULT_MAX_ISSUES),
                _DEFAULT_MAX_ISSUES,
            ),
            max_time_ms=_as_int(
                _setting(settings, "GRAPH_NEIGHBORHOOD_MAX_TIME_MS", _DEFAULT_MAX_TIME_MS),
                _DEFAULT_MAX_TIME_MS,
            ),
            allowed_node_types=_normalize_node_type_set(
                _setting(settings, "GRAPH_NEIGHBORHOOD_ALLOWED_NODE_TYPES", None)
            ),
            allowed_edge_types=_normalize_edge_type_set(
                _setting(settings, "GRAPH_NEIGHBORHOOD_ALLOWED_EDGE_TYPES", None)
            ),
            include_isolated_seeds=_as_bool(
                _setting(settings, "GRAPH_NEIGHBORHOOD_INCLUDE_ISOLATED_SEEDS", True),
                True,
            ),
            include_internal_edges=_as_bool(
                _setting(settings, "GRAPH_NEIGHBORHOOD_INCLUDE_INTERNAL_EDGES", True),
                True,
            ),
            deterministic_order=_as_bool(
                _setting(settings, "GRAPH_NEIGHBORHOOD_DETERMINISTIC_ORDER", True),
                True,
            ),
            expose_node_ids=_as_bool(_setting(settings, "GRAPH_NEIGHBORHOOD_EXPOSE_NODE_IDS", True), True),
            expose_edge_ids=_as_bool(_setting(settings, "GRAPH_NEIGHBORHOOD_EXPOSE_EDGE_IDS", False), False),
            expose_raw_attributes=False,
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
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
                "max_depth": self.max_depth,
                "max_neighbors_per_node": self.max_neighbors_per_node,
                "max_issues": self.max_issues,
                "max_time_ms": self.max_time_ms,
            },
            "filters": {
                "allowed_node_types": list(self.allowed_node_types) if self.allowed_node_types else None,
                "allowed_edge_types": list(self.allowed_edge_types) if self.allowed_edge_types else None,
            },
            "flags": {
                "include_isolated_seeds": self.include_isolated_seeds,
                "include_internal_edges": self.include_internal_edges,
                "deterministic_order": self.deterministic_order,
                "expose_node_ids": self.expose_node_ids,
                "expose_edge_ids": self.expose_edge_ids,
                "expose_raw_attributes": self.expose_raw_attributes,
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


@dataclass(frozen=True, slots=True)
class _NormalizedGraph:
    node_ids: tuple[str, ...]
    node_types: Mapping[str, str]
    edges: tuple[_NormalizedEdge, ...]
    out_neighbors: Mapping[str, Mapping[str, tuple[str, ...]]]
    in_neighbors: Mapping[str, Mapping[str, tuple[str, ...]]]
    all_neighbors: Mapping[str, Mapping[str, tuple[str, ...]]]
    input_node_count: int
    input_edge_count: int
    truncated_nodes: bool
    truncated_edges: bool
    skipped_forbidden_nodes: int
    skipped_forbidden_edges: int
    fingerprint: str


def _hash_identifier(value: Any, options: NeighborhoodOptions, domain: str) -> Optional[str]:
    text = _clean_text(value, _MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    if _looks_like_sensitive_literal(text) or _looks_like_narrative(text):
        return None

    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    full_domain = f"muleguard.graph.neighborhood.{domain}.{safe_namespace}"
    return _hmac_hex(options.salt, full_domain, text)


def _freeze_neighbor_map(raw: Mapping[str, dict[str, set[str]]]) -> Mapping[str, Mapping[str, tuple[str, ...]]]:
    out: dict[str, Mapping[str, tuple[str, ...]]] = {}

    for node_id, neighbors in raw.items():
        frozen_neighbors: dict[str, tuple[str, ...]] = {}

        for neighbor, edge_types in neighbors.items():
            frozen_neighbors[neighbor] = tuple(sorted(set(edge_types)))

        out[node_id] = MappingProxyType(frozen_neighbors)

    return MappingProxyType(out)


def _normalize_graph(
    view: Any,
    options: NeighborhoodOptions,
    issues: list[NeighborhoodIssue],
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

    if input_node_count > _INPUT_MAX_NODES:
        truncated_nodes = True
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="neighborhood_input_nodes_truncated",
            message="Neighborhood input nodes exceeded hard input limit and were truncated.",
            details={"submitted": input_node_count, "limit": _INPUT_MAX_NODES},
        )
        raw_nodes = raw_nodes[:_INPUT_MAX_NODES]

    if input_edge_count > _INPUT_MAX_EDGES:
        truncated_edges = True
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="neighborhood_input_edges_truncated",
            message="Neighborhood input edges exceeded hard input limit and were truncated.",
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
                code="neighborhood_normalization_time_budget_exhausted",
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
                    code="forbidden_neighborhood_node_field",
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
                code="neighborhood_node_id_unusable",
                message="Graph node identifier was unusable and node was skipped.",
                details={"index": index},
            )
            continue

        node_type = _normalize_node_type(_get_field(raw_node, ("node_type", "type", "kind"), "unknown"))
        node_types[node_id] = node_type

    edges: list[_NormalizedEdge] = []
    skipped_forbidden_edges = 0

    out_raw: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    in_raw: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    all_raw: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for index, raw_edge in enumerate(raw_edges):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="neighborhood_normalization_time_budget_exhausted",
                message="Graph normalization stopped after reaching configured time budget.",
                details={"phase": "edges", "processed": len(edges)},
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
                    code="forbidden_neighborhood_edge_field",
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
                code="neighborhood_edge_endpoint_unusable",
                message="Graph edge endpoint was unusable and edge was skipped.",
                details={"index": index},
            )
            continue

        if source == target:
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

        edge_type = _normalize_edge_type(_get_field(raw_edge, ("edge_type", "type", "relation"), "related_to"))
        weight = max(1, _as_int(_get_field(raw_edge, ("weight", "count"), 1), 1))

        edges.append(
            _NormalizedEdge(
                source=source,
                target=target,
                edge_type=edge_type,
                weight=weight,
            )
        )

        out_raw[source][target].add(edge_type)
        in_raw[target][source].add(edge_type)
        all_raw[source][target].add(edge_type)
        all_raw[target][source].add(edge_type)

    node_ids = tuple(sorted(node_types))

    fingerprint = _fingerprint_payload(
        {
            "version": NEIGHBORHOOD_VERSION,
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
        out_neighbors=_freeze_neighbor_map(out_raw),
        in_neighbors=_freeze_neighbor_map(in_raw),
        all_neighbors=_freeze_neighbor_map(all_raw),
        input_node_count=input_node_count,
        input_edge_count=input_edge_count,
        truncated_nodes=truncated_nodes,
        truncated_edges=truncated_edges,
        skipped_forbidden_nodes=skipped_forbidden_nodes,
        skipped_forbidden_edges=skipped_forbidden_edges,
        fingerprint=fingerprint,
    )


# -----------------------------------------------------------------------------
# Neighborhood models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NeighborhoodNode:
    """
    One bounded pseudonymous neighborhood node.
    """

    node_id: str
    node_type: str
    distance: int
    degree: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _clean_text(self.node_id, _MAX_NODE_ID_LENGTH).lower())
        object.__setattr__(self, "node_type", _normalize_node_type(self.node_type))
        object.__setattr__(self, "distance", max(0, _as_int(self.distance, 0)))
        object.__setattr__(self, "degree", max(0, _as_int(self.degree, 0)))

    def to_dict(self, *, include_id: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "node_type": self.node_type,
            "distance": int(self.distance),
            "degree": int(self.degree),
        }

        if include_id:
            payload["node_id"] = self.node_id

        return payload


@dataclass(frozen=True, slots=True)
class NeighborhoodEdge:
    """
    One bounded pseudonymous neighborhood edge.
    """

    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str
    weight: int = 1
    min_distance: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_id", _clean_text(self.edge_id, _MAX_NODE_ID_LENGTH).lower())
        object.__setattr__(self, "source_node_id", _clean_text(self.source_node_id, _MAX_NODE_ID_LENGTH).lower())
        object.__setattr__(self, "target_node_id", _clean_text(self.target_node_id, _MAX_NODE_ID_LENGTH).lower())
        object.__setattr__(self, "edge_type", _normalize_edge_type(self.edge_type))
        object.__setattr__(self, "weight", max(1, _as_int(self.weight, 1)))
        object.__setattr__(self, "min_distance", max(0, _as_int(self.min_distance, 0)))

    def to_dict(self, *, include_ids: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "edge_type": self.edge_type,
            "weight": int(self.weight),
            "min_distance": int(self.min_distance),
        }

        if include_ids:
            payload.update(
                {
                    "edge_id": self.edge_id,
                    "source_node_id": self.source_node_id,
                    "target_node_id": self.target_node_id,
                }
            )

        return payload


@dataclass(frozen=True, slots=True)
class NeighborhoodResult:
    """
    Safe bounded neighborhood extraction result.

    Public summaries deliberately exclude raw attributes, raw identifiers, raw
    narratives, subject-label pairs, secrets, tokens, passwords, database URLs,
    filesystem paths, and model artifact paths.
    """

    ok: bool = True
    status: GraphStatus | str = GraphStatus.AVAILABLE
    graph_fingerprint: str = ""
    built_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0

    seeds_requested: int = 0
    seeds_found: int = 0
    seeds_missing: int = 0

    nodes: tuple[NeighborhoodNode, ...] = ()
    edges: tuple[NeighborhoodEdge, ...] = ()

    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    node_type_counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    edge_type_counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    depth_distribution: Mapping[int, int] = dataclass_field(default_factory=dict)

    issues: tuple[NeighborhoodIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    expose_node_ids: bool = True
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
        object.__setattr__(self, "built_at", _ensure_utc(self.built_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))

        object.__setattr__(self, "seeds_requested", max(0, _as_int(self.seeds_requested, 0)))
        object.__setattr__(self, "seeds_found", max(0, _as_int(self.seeds_found, 0)))
        object.__setattr__(self, "seeds_missing", max(0, _as_int(self.seeds_missing, 0)))

        object.__setattr__(self, "nodes", tuple(self.nodes or ()))
        object.__setattr__(self, "edges", tuple(self.edges or ()))

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
            "depth_distribution",
            MappingProxyType(
                {
                    max(0, _as_int(key, 0)): max(0, _as_int(value, 0))
                    for key, value in (self.depth_distribution or {}).items()
                }
            ),
        )

        object.__setattr__(self, "issues", tuple(_as_issue(issue) for issue in (self.issues or ())))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))
        object.__setattr__(self, "expose_node_ids", _as_bool(self.expose_node_ids, True))
        object.__setattr__(self, "expose_edge_ids", _as_bool(self.expose_edge_ids, False))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": NEIGHBORHOOD_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, GraphStatus.AVAILABLE.value),
                        "graph_fingerprint": self.graph_fingerprint,
                        "seeds_requested": self.seeds_requested,
                        "seeds_found": self.seeds_found,
                        "seeds_missing": self.seeds_missing,
                        "node_count": len(self.nodes),
                        "edge_count": len(self.edges),
                        "counts": dict(self.counts),
                        "node_type_counts": dict(self.node_type_counts),
                        "edge_type_counts": dict(self.edge_type_counts),
                        "depth_distribution": {
                            str(key): value
                            for key, value in self.depth_distribution.items()
                        },
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def __len__(self) -> int:
        return len(self.nodes)

    def node_ids(self) -> tuple[str, ...]:
        return tuple(node.node_id for node in self.nodes)

    def edge_ids(self) -> tuple[str, ...]:
        return tuple(edge.edge_id for edge in self.edges)

    def to_public_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "status": _enum_value(self.status, GraphStatus.AVAILABLE.value),
            "graph_fingerprint": self.graph_fingerprint,
            "built_at": self.built_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "seeds_requested": int(self.seeds_requested),
            "seeds_found": int(self.seeds_found),
            "seeds_missing": int(self.seeds_missing),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "counts": dict(self.counts),
            "node_type_counts": dict(self.node_type_counts),
            "edge_type_counts": dict(self.edge_type_counts),
            "depth_distribution": {
                str(key): int(value)
                for key, value in self.depth_distribution.items()
            },
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "raw_attributes_exposed": False,
            "amounts_exposed": False,
            "caveats": list(_NEIGHBORHOOD_CAVEATS),
            "safety_flags": dict(_NEIGHBORHOOD_SAFETY_FLAGS),
        }

        if self.expose_node_ids:
            payload["nodes"] = [node.to_dict(include_id=True) for node in self.nodes]
        else:
            payload["nodes_omitted"] = True

        if self.expose_edge_ids:
            payload["edges"] = [edge.to_dict(include_ids=True) for edge in self.edges]
        else:
            payload["edges_omitted"] = True

        return payload

    def to_internal_dict(self) -> dict[str, Any]:
        payload = self.to_public_dict()
        payload.pop("nodes_omitted", None)
        payload.pop("edges_omitted", None)

        payload["nodes"] = [node.to_dict(include_id=True) for node in self.nodes]
        payload["edges"] = [edge.to_dict(include_ids=True) for edge in self.edges]
        payload["internal_only"] = True

        return payload


# -----------------------------------------------------------------------------
# Neighborhood extraction helpers
# -----------------------------------------------------------------------------


def _extract_seed_id(seed: Any, options: NeighborhoodOptions) -> Optional[str]:
    if seed is None:
        return None

    if isinstance(seed, Mapping):
        raw = _get_field(
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
        raw = seed

    return _hash_identifier(raw, options, "seed")


def _node_rank(options: NeighborhoodOptions, node_id: str) -> int:
    return _stable_rank(
        options.salt,
        "muleguard.graph.neighborhood.node_order",
        options.seed,
        options.namespace,
        node_id,
    )


def _edge_rank(options: NeighborhoodOptions, edge: _NormalizedEdge) -> int:
    return _stable_rank(
        options.salt,
        "muleguard.graph.neighborhood.edge_order",
        options.seed,
        options.namespace,
        edge.source,
        edge.target,
        edge.edge_type,
    )


def _edge_id(options: NeighborhoodOptions, edge: _NormalizedEdge) -> str:
    safe_namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.graph.neighborhood.edge.{safe_namespace}"
    message = f"{edge.source}|{edge.target}|{edge.edge_type}"
    return _hmac_hex(options.salt, domain, message)[:64]


def _neighbor_map_for_direction(
    graph: _NormalizedGraph,
    node_id: str,
    direction: str,
) -> Mapping[str, tuple[str, ...]]:
    if direction == _DIRECTION_OUTGOING:
        return graph.out_neighbors.get(node_id, {})

    if direction == _DIRECTION_INCOMING:
        return graph.in_neighbors.get(node_id, {})

    merged: dict[str, set[str]] = {}

    for neighbor, edge_types in graph.out_neighbors.get(node_id, {}).items():
        merged.setdefault(neighbor, set()).update(edge_types)

    for neighbor, edge_types in graph.in_neighbors.get(node_id, {}).items():
        merged.setdefault(neighbor, set()).update(edge_types)

    return MappingProxyType({key: tuple(sorted(value)) for key, value in merged.items()})


def _allowed_edge_types(options: NeighborhoodOptions) -> Optional[set[str]]:
    if options.allowed_edge_types is None:
        return None

    return set(options.allowed_edge_types)


def _allowed_node_types(options: NeighborhoodOptions) -> Optional[set[str]]:
    if options.allowed_node_types is None:
        return None

    return set(options.allowed_node_types)


# -----------------------------------------------------------------------------
# Neighborhood harness
# -----------------------------------------------------------------------------


class NeighborhoodHarness:
    """
    Bounded deterministic synthetic graph neighborhood harness.

    This harness extracts bounded neighborhoods from synthetic graph views. It
    does not authorize actions, does not deploy systems, does not persist
    durable artifacts, and must not trigger automatic adverse customer action.
    """

    def __init__(self, options: NeighborhoodOptions | None = None) -> None:
        self.options = options or NeighborhoodOptions.from_settings()
        self._lock = threading.RLock()

    def extract(self, view: Any, seeds: Any) -> NeighborhoodResult:
        """
        Extract one bounded neighborhood.
        """
        opts = self.options
        issues: list[NeighborhoodIssue] = []
        start_time = time.monotonic()

        def blocked_result(status: GraphStatus) -> NeighborhoodResult:
            return NeighborhoodResult(
                ok=status != GraphStatus.FAILED,
                status=status,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                seeds_requested=0,
                seeds_found=0,
                seeds_missing=0,
                nodes=(),
                edges=(),
                counts={},
                node_type_counts={},
                edge_type_counts={},
                depth_distribution={},
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
                code="neighborhood_disabled",
                message="Neighborhood extraction is disabled.",
            )
            return blocked_result(GraphStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Neighborhood extraction requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return blocked_result(GraphStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Neighborhood extraction is blocked in production-like environments.",
            )
            return blocked_result(GraphStatus.BLOCKED)

        graph = _normalize_graph(view, opts, issues, start_time)

        if graph is None:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="neighborhood_graph_unavailable",
                message="Graph input could not be normalized.",
            )
            return blocked_result(GraphStatus.FAILED)

        seed_raw = _as_sequence(seeds)
        seeds_requested = len(seed_raw)

        if seeds_requested > opts.max_seeds:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="neighborhood_seed_limit_applied",
                message="Seed count exceeded configured limit and was truncated.",
                details={"submitted": seeds_requested, "max_seeds": opts.max_seeds},
            )
            seed_raw = seed_raw[: opts.max_seeds]
            seeds_requested = len(seed_raw)

        seed_ids: list[str] = []
        seeds_missing = 0

        for seed in seed_raw:
            seed_id = _extract_seed_id(seed, opts)

            if seed_id is None:
                seeds_missing += 1
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="neighborhood_seed_unusable",
                    message="Seed identifier was unusable and was skipped.",
                )
                continue

            if seed_id not in graph.node_types:
                seeds_missing += 1
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.INFO,
                    code="neighborhood_seed_not_found",
                    message="Seed node was not found in normalized graph.",
                )
                continue

            if opts.allowed_node_types is not None:
                node_type = graph.node_types.get(seed_id, "unknown")

                if node_type not in set(opts.allowed_node_types):
                    seeds_missing += 1
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.INFO,
                        code="neighborhood_seed_type_filtered",
                        message="Seed node type was filtered by policy.",
                        details={"node_type": node_type},
                    )
                    continue

            seed_ids.append(seed_id)

        unique_seed_ids = list(dict.fromkeys(seed_ids))
        seeds_found = len(unique_seed_ids)

        if seeds_found == 0:
            return NeighborhoodResult(
                ok=True,
                status=GraphStatus.EMPTY,
                graph_fingerprint=graph.fingerprint,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                seeds_requested=seeds_requested,
                seeds_found=0,
                seeds_missing=seeds_missing,
                nodes=(),
                edges=(),
                counts={"seeds_requested": seeds_requested, "seeds_found": 0, "seeds_missing": seeds_missing},
                node_type_counts={},
                edge_type_counts={},
                depth_distribution={},
                issues=tuple(issues),
                metadata={
                    "graph_fingerprint": graph.fingerprint,
                    "options": opts.safe_summary(),
                },
                expose_node_ids=opts.expose_node_ids,
                expose_edge_ids=opts.expose_edge_ids,
                fingerprint="",
            )

        selected: dict[str, int] = {}

        def seed_sort_key(node_id: str) -> tuple[int, str]:
            if opts.deterministic_order:
                return (_node_rank(opts, node_id), node_id)
            return (0, node_id)

        for seed_id in sorted(unique_seed_ids, key=seed_sort_key):
            if len(selected) >= opts.max_nodes:
                break

            selected[seed_id] = 0

        queue: deque[tuple[str, int]] = deque(
            (seed_id, 0) for seed_id in selected
        )

        node_limit_truncated = False
        neighbor_cap_events = 0
        allowed_node_types = _allowed_node_types(opts)
        allowed_edge_types = _allowed_edge_types(opts)

        while queue:
            if len(selected) >= opts.max_nodes:
                node_limit_truncated = True
                break

            if _time_exceeded(start_time, opts.max_time_ms):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="neighborhood_time_budget_exhausted",
                    message="Neighborhood extraction stopped after reaching configured time budget.",
                    details={"selected_nodes": len(selected)},
                )
                break

            node_id, depth = queue.popleft()

            if depth >= opts.max_depth:
                continue

            neighbors = _neighbor_map_for_direction(graph, node_id, opts.direction)

            if not neighbors:
                continue

            candidates: list[str] = []

            for neighbor_id, edge_types in neighbors.items():
                if neighbor_id in selected:
                    continue

                if allowed_node_types is not None:
                    neighbor_type = graph.node_types.get(neighbor_id, "unknown")

                    if neighbor_type not in allowed_node_types:
                        continue

                if allowed_edge_types is not None:
                    if not any(edge_type in allowed_edge_types for edge_type in edge_types):
                        continue

                candidates.append(neighbor_id)

            def candidate_sort_key(candidate_id: str) -> tuple[int, str]:
                if opts.deterministic_order:
                    return (_node_rank(opts, candidate_id), candidate_id)
                return (0, candidate_id)

            candidates = sorted(set(candidates), key=candidate_sort_key)

            if len(candidates) > opts.max_neighbors_per_node:
                neighbor_cap_events += 1
                candidates = candidates[: opts.max_neighbors_per_node]

            for candidate_id in candidates:
                if len(selected) >= opts.max_nodes:
                    node_limit_truncated = True
                    break

                selected[candidate_id] = depth + 1
                queue.append((candidate_id, depth + 1))

        if neighbor_cap_events > 0:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="neighborhood_neighbor_cap_applied",
                message="One or more nodes had more neighbors than configured per-node neighbor cap.",
                details={"events": neighbor_cap_events},
            )

        if node_limit_truncated:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.WARNING,
                code="neighborhood_node_limit_truncated",
                message="Neighborhood node limit reached; additional nodes were not selected.",
                details={"max_nodes": opts.max_nodes},
            )

        selected_set = set(selected)
        degree_counter: Counter[str] = Counter()
        included_edges: list[_NormalizedEdge] = []

        if opts.include_internal_edges and opts.max_edges > 0:
            candidate_edges: list[_NormalizedEdge] = []

            for edge in graph.edges:
                if edge.source not in selected_set or edge.target not in selected_set:
                    continue

                if allowed_edge_types is not None and edge.edge_type not in allowed_edge_types:
                    continue

                candidate_edges.append(edge)

            def edge_sort_key(edge: _NormalizedEdge) -> tuple[int, str, str, str]:
                if opts.deterministic_order:
                    return (_edge_rank(opts, edge), edge.source, edge.target, edge.edge_type)
                return (0, edge.source, edge.target, edge.edge_type)

            candidate_edges.sort(key=edge_sort_key)

            if len(candidate_edges) > opts.max_edges:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="neighborhood_edge_limit_truncated",
                    message="Neighborhood edge limit reached; additional edges were not included.",
                    details={"max_edges": opts.max_edges},
                )
                candidate_edges = candidate_edges[: opts.max_edges]

            included_edges = candidate_edges

            for edge in included_edges:
                degree_counter[edge.source] += 1
                degree_counter[edge.target] += 1

        def node_sort_key(item: tuple[str, int]) -> tuple[int, int, str]:
            node_id, distance = item

            if opts.deterministic_order:
                return (distance, _node_rank(opts, node_id), node_id)

            return (distance, 0, node_id)

        nodes = tuple(
            NeighborhoodNode(
                node_id=node_id,
                node_type=graph.node_types.get(node_id, "unknown"),
                distance=distance,
                degree=int(degree_counter.get(node_id, 0)),
            )
            for node_id, distance in sorted(selected.items(), key=node_sort_key)
        )

        edges = tuple(
            NeighborhoodEdge(
                edge_id=_edge_id(opts, edge),
                source_node_id=edge.source,
                target_node_id=edge.target,
                edge_type=edge.edge_type,
                weight=edge.weight,
                min_distance=min(
                    int(selected.get(edge.source, 0)),
                    int(selected.get(edge.target, 0)),
                ),
            )
            for edge in included_edges
        )

        node_type_counter = Counter(node.node_type for node in nodes)
        edge_type_counter = Counter(edge.edge_type for edge in edges)
        depth_counter = Counter(selected.values())

        counts = {
            "seeds_requested": seeds_requested,
            "seeds_found": seeds_found,
            "seeds_missing": seeds_missing,
            "nodes": len(nodes),
            "edges": len(edges),
            "input_nodes": graph.input_node_count,
            "input_edges": graph.input_edge_count,
            "issues": len(issues),
        }

        if _has_error(issues):
            status = GraphStatus.FAILED
        elif node_limit_truncated or graph.truncated_nodes or graph.truncated_edges or _time_exceeded(start_time, opts.max_time_ms):
            status = GraphStatus.TRUNCATED
        elif len(nodes) == 0:
            status = GraphStatus.EMPTY
        elif _has_warning(issues):
            status = GraphStatus.DEGRADED
        else:
            status = GraphStatus.AVAILABLE

        metadata = {
            "neighborhood_version": NEIGHBORHOOD_VERSION,
            "graph_fingerprint": graph.fingerprint,
            "direction": opts.direction,
            "max_depth": opts.max_depth,
            "node_limit_applied": node_limit_truncated,
            "edge_limit_applied": len(included_edges) >= opts.max_edges and opts.max_edges > 0,
            "neighbor_cap_events": neighbor_cap_events,
            "options": opts.safe_summary(),
            "raw_attributes_exposed": False,
            "amounts_exposed": False,
            "cross_currency_conversion": False,
            "caveats": list(_NEIGHBORHOOD_CAVEATS),
            "safety_flags": dict(_NEIGHBORHOOD_SAFETY_FLAGS),
        }

        return NeighborhoodResult(
            ok=status in {GraphStatus.AVAILABLE, GraphStatus.DEGRADED, GraphStatus.TRUNCATED, GraphStatus.EMPTY},
            status=status,
            graph_fingerprint=graph.fingerprint,
            built_at=_now_utc(),
            duration_ms=_elapsed_ms(start_time),
            seeds_requested=seeds_requested,
            seeds_found=seeds_found,
            seeds_missing=seeds_missing,
            nodes=nodes,
            edges=edges,
            counts=counts,
            node_type_counts=dict(node_type_counter),
            edge_type_counts=dict(edge_type_counter),
            depth_distribution=dict(sorted(depth_counter.items())),
            issues=tuple(issues),
            metadata=metadata,
            expose_node_ids=opts.expose_node_ids,
            expose_edge_ids=opts.expose_edge_ids,
            fingerprint="",
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "caveats": list(_NEIGHBORHOOD_CAVEATS),
            "safety_flags": dict(_NEIGHBORHOOD_SAFETY_FLAGS),
        }


_default_harness: Optional[NeighborhoodHarness] = None
_default_harness_lock = threading.Lock()


def get_neighborhood_harness(
    options: NeighborhoodOptions | None = None,
    *,
    rebuild: bool = False,
) -> NeighborhoodHarness:
    """
    Return a process-wide neighborhood harness.
    """
    global _default_harness

    with _default_harness_lock:
        if _default_harness is None or rebuild or options is not None:
            _default_harness = NeighborhoodHarness(
                options=options or NeighborhoodOptions.from_settings()
            )

        return _default_harness


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def extract_neighborhood(
    view: Any,
    seeds: Any,
    options: NeighborhoodOptions | None = None,
    *,
    harness: NeighborhoodHarness | None = None,
) -> NeighborhoodResult:
    """
    Extract one bounded synthetic graph neighborhood.
    """
    active_harness = harness or get_neighborhood_harness(options)
    return active_harness.extract(view, seeds)


def summarize_neighborhood(result: Any) -> dict[str, Any]:
    """
    Return safe public summary for a neighborhood result.
    """
    if isinstance(result, NeighborhoodResult):
        return result.to_public_dict()

    if isinstance(result, Mapping):
        return _safe_detail_value(result) or {}

    return {}


def get_neighborhood_metadata() -> dict[str, Any]:
    """
    Return safe, serializable neighborhood metadata.
    """
    options = NeighborhoodOptions.from_settings()

    return {
        "package": "muleguard.backend.graph.neighborhood",
        "version": NEIGHBORHOOD_VERSION,
        "directions": list(_DIRECTIONS),
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
            "max_nodes": _HARD_MAX_NODES,
            "max_edges": _HARD_MAX_EDGES,
            "max_depth": _HARD_MAX_DEPTH,
            "max_neighbors_per_node": _HARD_MAX_NEIGHBORS_PER_NODE,
            "max_issues": _HARD_MAX_ISSUES,
            "max_time_ms": _HARD_MAX_TIME_MS,
        },
        "forbidden_field_count": len(_FORBIDDEN_NEIGHBORHOOD_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_NEIGHBORHOOD_CAVEATS),
        "safety_flags": dict(_NEIGHBORHOOD_SAFETY_FLAGS),
    }


__all__ = [
    "NeighborhoodEdge",
    "NeighborhoodHarness",
    "NeighborhoodIssue",
    "NeighborhoodNode",
    "NeighborhoodOptions",
    "NeighborhoodResult",
    "extract_neighborhood",
    "get_neighborhood_harness",
    "get_neighborhood_metadata",
    "summarize_neighborhood",
]