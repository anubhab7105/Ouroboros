"""
MULEGUARD backend graph builder.

This module provides the canonical bounded graph construction layer for the
synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- build bounded, deterministic, pseudonymous graph views from synthetic
  accounts, transactions, entities, entity links, complaints, alerts,
  assessments, and case references;
- enforce strict graph bounds for nodes, edges, depth, paths, trails, shared
  groups, accounts per entity, communities, date span, issue reporting, and
  time budget;
- preserve privacy by using salted one-way pseudonymous node identifiers and by
  excluding raw feature values, raw identifiers, raw complaint narratives,
  subject-label pairs, secrets, tokens, passwords, database URLs, filesystem
  paths, and model artifact paths from public summaries;
- enforce leakage resistance by rejecting label-like, ground-truth-like,
  scenario-id, fraud-ring-id, raw-narrative, raw-identifier, and other
  prohibited graph input fields;
- model completed synthetic transactions as directed money-flow edges through
  transaction nodes, while pending, failed, reversed, cancelled, and disputed
  transactions are excluded from settled-money graph edges;
- report mixed-currency amounts only per currency, never converting or
  aggregating across currencies;
- provide safe graph views with bounded adjacency maps, degree helpers,
  fingerprints, issue lists, public summaries, and internal summaries;
- remain import-safe, dependency-light, and usable by graph services, rules,
  ML feature builders, evaluation harnesses, tests, seeders, offline fixtures,
  and developer tooling.

This module builds graph structures only. It does not traverse unbounded paths,
train models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for graph construction.
- Graph relationships are investigative association signals only. They are not
  proof of common control, fraud, intent, conspiracy, or wrongdoing.
- Candidate paths, trails, clusters, and centrality outputs derived from this
  graph are heuristic investigative views only.
- Only completed transactions represent settled fund movement. Pending, failed,
  reversed, cancelled, and disputed transactions must remain distinct and are
  not treated as settled money-flow edges by this builder.
- Mixed-currency amounts are reported per currency and are never converted.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw identifiers are not retained. Node linkage is pseudonymous and salted.
- Ground-truth labels, injected scenario IDs, fraud-ring IDs, secrets, tokens,
  passwords, database URLs, filesystem paths, and model artifact paths are
  rejected or omitted.
- Graph construction never triggers automatic adverse customer action such as
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
- This module does not persist durable graph snapshots.
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
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

try:
    from app.exceptions import (
        ConfigurationError,
        ValidationError as MuleGuardValidationError,
    )
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


try:
    from app.graph import (
        GRAPH_CAVEATS,
        GRAPH_SAFETY_FLAGS,
        GraphEdgeType,
        GraphNodeType,
        GraphPolicy,
        GraphStatus,
        IssueSeverity,
    )
except Exception as exc:  # pragma: no cover - hard dependency for builder
    raise ConfigurationError(
        "MULEGUARD graph package is required for graph builder.",
        details={"exception_type": type(exc).__name__},
    ) from exc


logger = logging.getLogger("muleguard.backend.graph.builder")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

GRAPH_BUILDER_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.graph.builder.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"

_MAX_TEXT_LENGTH: Final[int] = 512
_MAX_NODE_ID_LENGTH: Final[int] = 256
_MAX_ISSUE_TEXT_LENGTH: Final[int] = 300

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

_ACCOUNT_ID_KEYS: Final[tuple[str, ...]] = (
    "id",
    "account_id",
    "acct_id",
    "subject_ref_hash",
    "subject_ref",
    "subject_hash",
    "subject",
)

_TRANSACTION_ID_KEYS: Final[tuple[str, ...]] = (
    "id",
    "transaction_id",
    "txn_id",
    "reference",
    "transaction_reference",
    "txn_reference",
    "ref",
)

_ENTITY_ID_KEYS: Final[tuple[str, ...]] = (
    "id",
    "entity_id",
    "entity_ref_hash",
    "entity_ref",
)

_COMPLAINT_ID_KEYS: Final[tuple[str, ...]] = (
    "id",
    "complaint_id",
    "reference",
    "complaint_reference",
)

_ALERT_ID_KEYS: Final[tuple[str, ...]] = (
    "id",
    "alert_id",
    "reference",
    "alert_reference",
)

_ASSESSMENT_ID_KEYS: Final[tuple[str, ...]] = (
    "id",
    "assessment_id",
    "model_assessment_id",
    "reference",
)

_CASE_ID_KEYS: Final[tuple[str, ...]] = (
    "id",
    "case_id",
    "investigation_case_id",
    "reference",
)

_SENDER_KEYS: Final[tuple[str, ...]] = (
    "sender_account_id",
    "sender",
    "from_account_id",
    "from",
    "source_account_id",
)

_RECEIVER_KEYS: Final[tuple[str, ...]] = (
    "receiver_account_id",
    "receiver",
    "to_account_id",
    "to",
    "beneficiary_account_id",
)

_VICTIM_KEYS: Final[tuple[str, ...]] = (
    "victim_account_id",
    "victim",
    "complainant_account_id",
    "complainant",
)

_SUSPECT_KEYS: Final[tuple[str, ...]] = (
    "suspected_account_id",
    "suspect_account_id",
    "suspect",
    "subject_account_id",
)

_TRANSACTION_REF_KEYS: Final[tuple[str, ...]] = (
    "transaction_reference",
    "transaction_ref",
    "txn_reference",
    "txn_ref",
    "reference",
)

_ACCOUNT_REF_KEYS: Final[tuple[str, ...]] = (
    "account_id",
    "account_ref",
    "subject_ref_hash",
    "subject_ref",
    "subject",
    "id",
)

_ENTITY_REF_KEYS: Final[tuple[str, ...]] = (
    "entity_id",
    "entity_ref",
    "entity_ref_hash",
)

_ALERT_REF_KEYS: Final[tuple[str, ...]] = (
    "alert_id",
    "alert_ref",
    "alert_reference",
)

_COMPLAINT_REF_KEYS: Final[tuple[str, ...]] = (
    "complaint_id",
    "complaint_ref",
    "complaint_reference",
)

_ASSESSMENT_REF_KEYS: Final[tuple[str, ...]] = (
    "assessment_id",
    "assessment_ref",
    "model_assessment_id",
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

_SAFE_NODE_ATTRIBUTE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "account_type",
        "status",
        "entity_type",
        "category",
        "state",
        "severity",
        "scoring_mode",
        "risk_band",
        "source_system",
        "kind",
    }
)

_SAFE_EDGE_ATTRIBUTE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "count",
        "currencies",
        "amount_by_currency",
        "channels",
        "roles",
        "match_method",
        "verification_state",
        "confidence",
        "category",
        "state",
        "source_system",
    }
)

_COMPLETED_TRANSACTION_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "completed",
        "complete",
        "settled",
        "success",
        "succeeded",
        "posted",
    }
)

_BUILDER_CAVEATS: Final[tuple[str, ...]] = (
    *(GRAPH_CAVEATS if isinstance(GRAPH_CAVEATS, tuple) else tuple(GRAPH_CAVEATS)),
    "Graph builder constructs bounded synthetic graph views only.",
    "Graph builder does not perform unbounded traversal, path explosion, or production serving.",
    "Node identifiers are salted one-way pseudonymous hashes.",
    "Raw node attributes and raw edge payloads are never exposed in public summaries.",
)


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


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


def _to_decimal(value: Any) -> Optional[Decimal]:
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
    if value is None or not value.is_finite():
        return Decimal("0.00")

    try:
        return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal("0.00")


def _normalize_currency(value: Any) -> str:
    text = _normalize_unicode(value).strip().upper()
    text = re.sub(r"[^A-Z]", "", text)

    if _CURRENCY_RE.match(text):
        return text

    return ""


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


def _ensure_salt(salt: Any) -> str:
    text = str(salt or "").strip()

    if not text:
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


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


def _fingerprint_payload(payload: Any) -> str:
    try:
        return _sha256_hex(_canonical_json(payload))
    except Exception:
        return _sha256_hex(str(_safe_detail_value(payload)))


def _time_exceeded(start_time: float, max_time_ms: int) -> bool:
    return (time.monotonic() - start_time) * 1000.0 > float(max(1, int(max_time_ms)))


def _elapsed_ms(start_time: float) -> int:
    return int((time.monotonic() - start_time) * 1000.0)


def _enum_value(value: Any, default: str = "") -> str:
    return _clean_text(getattr(value, "value", value), 128) or default


def _pick(record: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in record:
            value = record[key]

            if value is None:
                continue

            if isinstance(value, str) and not value.strip():
                continue

            return value

    return None


def _record_fields(record: Any) -> dict[str, Any]:
    if isinstance(record, Mapping):
        return dict(record)

    known_keys = (
        _ACCOUNT_ID_KEYS
        + _TRANSACTION_ID_KEYS
        + _ENTITY_ID_KEYS
        + _COMPLAINT_ID_KEYS
        + _ALERT_ID_KEYS
        + _ASSESSMENT_ID_KEYS
        + _CASE_ID_KEYS
        + _SENDER_KEYS
        + _RECEIVER_KEYS
        + _VICTIM_KEYS
        + _SUSPECT_KEYS
        + _TRANSACTION_REF_KEYS
        + _ACCOUNT_REF_KEYS
        + _ENTITY_REF_KEYS
        + _ALERT_REF_KEYS
        + _COMPLAINT_REF_KEYS
        + _ASSESSMENT_REF_KEYS
        + (
            "account_type",
            "type",
            "status",
            "state",
            "entity_type",
            "kind",
            "match_method",
            "method",
            "verification_state",
            "confidence",
            "category",
            "severity",
            "scoring_mode",
            "risk_band",
            "source_system",
            "source",
            "amount",
            "value",
            "currency",
            "ccy",
            "channel",
            "occurred_at",
            "timestamp",
            "reported_at",
            "created_at",
        )
    )

    out: dict[str, Any] = {}

    for key in known_keys:
        value = getattr(record, key, _MISSING)

        if value is not _MISSING:
            out[key] = value

    return out


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


def _safe_token_value(value: Any, limit: int = 100) -> str:
    text = _clean_text(value, limit)

    if not text:
        return ""

    if _looks_like_sensitive_literal(text) or _looks_like_narrative(text):
        return "[redacted]"

    token = _normalize_token(text)

    return token or text


def _sanitize_node_attributes(attributes: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
    if not attributes:
        return MappingProxyType({})

    out: dict[str, Any] = {}

    for raw_key, raw_value in list(attributes.items())[:50]:
        key = _canonical_field_name(raw_key)

        if key not in _SAFE_NODE_ATTRIBUTE_KEYS:
            continue

        if _is_forbidden_key(key) or _is_label_leakage_key(key) or _is_sensitive_detail_key(key):
            continue

        token = _safe_token_value(raw_value)

        if token:
            out[key] = token

    return MappingProxyType(out)


def _sanitize_edge_attributes(attributes: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
    if not attributes:
        return MappingProxyType({"count": 1})

    out: dict[str, Any] = {}

    for raw_key, raw_value in list(attributes.items())[:100]:
        key = _canonical_field_name(raw_key)

        if key not in _SAFE_EDGE_ATTRIBUTE_KEYS:
            continue

        if _is_forbidden_key(key) or _is_label_leakage_key(key) or _is_sensitive_detail_key(key):
            continue

        if key == "count":
            out[key] = max(1, int(_clip_float(_to_decimal(raw_value) or 1, 1, 1_000_000, 1)))
        elif key == "confidence":
            numeric = _to_decimal(raw_value)

            if numeric is not None:
                out[key] = _round6(_clip_float(float(numeric), 0.0, 1.0, 0.0))
        elif key == "amount_by_currency":
            if isinstance(raw_value, Mapping):
                amounts: dict[str, Decimal] = {}

                for currency, amount in list(raw_value.items())[:20]:
                    normalized_currency = _normalize_currency(currency)
                    decimal_amount = _to_decimal(amount)

                    if normalized_currency and decimal_amount is not None and decimal_amount > 0:
                        amounts[normalized_currency] = _quantize_money(decimal_amount)

                if amounts:
                    out[key] = MappingProxyType(dict(sorted(amounts.items())))
        elif key in {"currencies", "channels", "roles"}:
            values = [
                _safe_token_value(item, 64)
                for item in _as_sequence(raw_value)
                if _safe_token_value(item, 64)
            ]

            if values:
                out[key] = tuple(dict.fromkeys(values))
        else:
            token = _safe_token_value(raw_value)

            if token:
                out[key] = token

    out.setdefault("count", 1)
    return MappingProxyType(out)


def _merge_edge_attributes(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
) -> Mapping[str, Any]:
    merged: dict[str, Any] = dict(old)

    merged["count"] = int(old.get("count", 1)) + int(new.get("count", 1))

    for tuple_key in ("currencies", "channels", "roles"):
        existing = tuple(old.get(tuple_key, ()) or ())
        incoming = tuple(new.get(tuple_key, ()) or ())
        combined = tuple(dict.fromkeys([*existing, *incoming]))

        if combined:
            merged[tuple_key] = combined

    old_amounts = old.get("amount_by_currency") or {}
    new_amounts = new.get("amount_by_currency") or {}

    if old_amounts or new_amounts:
        amounts: dict[str, Decimal] = {}

        for currency, amount in dict(old_amounts).items():
            decimal_amount = _to_decimal(amount)

            if decimal_amount is not None:
                amounts[currency] = decimal_amount

        for currency, amount in dict(new_amounts).items():
            decimal_amount = _to_decimal(amount)

            if decimal_amount is None:
                continue

            amounts[currency] = _quantize_money(amounts.get(currency, Decimal("0.00")) + decimal_amount)

        if amounts:
            merged["amount_by_currency"] = MappingProxyType(
                {currency: _quantize_money(amount) for currency, amount in sorted(amounts.items())}
            )

    for scalar_key in ("match_method", "verification_state", "category", "state", "source_system"):
        if scalar_key in new and new[scalar_key]:
            merged[scalar_key] = new[scalar_key]
        elif scalar_key in old and old[scalar_key]:
            merged[scalar_key] = old[scalar_key]

    if "confidence" in new and new["confidence"] is not None:
        merged["confidence"] = new["confidence"]
    elif "confidence" in old and old["confidence"] is not None:
        merged["confidence"] = old["confidence"]

    return MappingProxyType(merged)


# -----------------------------------------------------------------------------
# Issue model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphIssue:
    """
    Safe graph builder issue.

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
        object.__setattr__(self, "message", _clean_text(self.message, _MAX_ISSUE_TEXT_LENGTH))
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
    issues: list[GraphIssue],
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

        issues[-1] = GraphIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        GraphIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, _MAX_ISSUE_TEXT_LENGTH),
            field=_clean_text(field, 200) if field else None,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[GraphIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _has_warning(issues: Sequence[GraphIssue]) -> bool:
    return any(issue.severity == IssueSeverity.WARNING for issue in issues)


# -----------------------------------------------------------------------------
# Graph node, edge, and view models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphNode:
    """
    One bounded pseudonymous graph node.
    """

    node_id: str
    node_type: GraphNodeType | str
    attributes: Mapping[str, Any] = dataclass_field(default_factory=dict)
    created_at: datetime = dataclass_field(default_factory=_now_utc)

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _clean_text(self.node_id, _MAX_NODE_ID_LENGTH).lower())
        object.__setattr__(
            self,
            "node_type",
            _normalize_enum_option(GraphNodeType, self.node_type, GraphNodeType.ACCOUNT),
        )
        object.__setattr__(self, "attributes", _sanitize_node_attributes(self.attributes))
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())

    def to_dict(self, *, include_attributes: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
        }

        if include_attributes:
            payload["attributes"] = _safe_detail_value(self.attributes)

        return payload


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """
    One bounded pseudonymous graph edge.
    """

    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: GraphEdgeType | str
    weight: int = 1
    attributes: Mapping[str, Any] = dataclass_field(default_factory=dict)
    created_at: datetime = dataclass_field(default_factory=_now_utc)
    updated_at: datetime = dataclass_field(default_factory=_now_utc)

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_id", _clean_text(self.edge_id, _MAX_NODE_ID_LENGTH).lower())
        object.__setattr__(self, "source_node_id", _clean_text(self.source_node_id, _MAX_NODE_ID_LENGTH).lower())
        object.__setattr__(self, "target_node_id", _clean_text(self.target_node_id, _MAX_NODE_ID_LENGTH).lower())
        object.__setattr__(
            self,
            "edge_type",
            _normalize_enum_option(GraphEdgeType, self.edge_type, GraphEdgeType.RELATED_TO),
        )
        object.__setattr__(self, "weight", max(1, int(self.weight)))
        object.__setattr__(self, "attributes", _sanitize_edge_attributes(self.attributes))
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at) or _now_utc())
        object.__setattr__(self, "updated_at", _ensure_utc(self.updated_at) or _now_utc())

    def to_dict(self, *, include_attributes: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "edge_type": self.edge_type.value,
            "weight": int(self.weight),
        }

        if include_attributes:
            payload["attributes"] = _safe_detail_value(self.attributes)

        return payload


@dataclass(frozen=True, slots=True)
class GraphView:
    """
    Safe bounded graph view.

    Public summaries deliberately exclude raw attributes, raw identifiers, raw
    narratives, subject-label pairs, secrets, tokens, passwords, database URLs,
    filesystem paths, and model artifact paths.
    """

    status: GraphStatus | str = GraphStatus.AVAILABLE
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()
    built_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    node_type_counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    edge_type_counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[GraphIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    adjacency: Mapping[str, tuple[str, ...]] = dataclass_field(init=False, default_factory=dict)
    reverse_adjacency: Mapping[str, tuple[str, ...]] = dataclass_field(init=False, default_factory=dict)
    undirected_adjacency: Mapping[str, tuple[str, ...]] = dataclass_field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(GraphStatus, self.status, GraphStatus.AVAILABLE),
        )
        object.__setattr__(self, "nodes", tuple(self.nodes or ()))
        object.__setattr__(self, "edges", tuple(self.edges or ()))
        object.__setattr__(self, "built_at", _ensure_utc(self.built_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, int(self.duration_ms)))
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts or {})))
        object.__setattr__(self, "node_type_counts", MappingProxyType(dict(self.node_type_counts or {})))
        object.__setattr__(self, "edge_type_counts", MappingProxyType(dict(self.edge_type_counts or {})))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        adjacency: dict[str, set[str]] = defaultdict(set)
        reverse_adjacency: dict[str, set[str]] = defaultdict(set)
        undirected: dict[str, set[str]] = defaultdict(set)

        for node in self.nodes:
            adjacency.setdefault(node.node_id, set())
            reverse_adjacency.setdefault(node.node_id, set())
            undirected.setdefault(node.node_id, set())

        for edge in self.edges:
            adjacency[edge.source_node_id].add(edge.target_node_id)
            reverse_adjacency[edge.target_node_id].add(edge.source_node_id)
            undirected[edge.source_node_id].add(edge.target_node_id)
            undirected[edge.target_node_id].add(edge.source_node_id)

        object.__setattr__(
            self,
            "adjacency",
            MappingProxyType(
                {key: tuple(sorted(value)) for key, value in sorted(adjacency.items())}
            ),
        )
        object.__setattr__(
            self,
            "reverse_adjacency",
            MappingProxyType(
                {key: tuple(sorted(value)) for key, value in sorted(reverse_adjacency.items())}
            ),
        )
        object.__setattr__(
            self,
            "undirected_adjacency",
            MappingProxyType(
                {key: tuple(sorted(value)) for key, value in sorted(undirected.items())}
            ),
        )

        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", self._compute_fingerprint())

    def _compute_fingerprint(self) -> str:
        payload = {
            "version": GRAPH_BUILDER_VERSION,
            "status": _enum_value(self.status, GraphStatus.AVAILABLE.value),
            "node_ids": sorted(node.node_id for node in self.nodes),
            "edges": sorted(
                (
                    edge.source_node_id,
                    edge.target_node_id,
                    _enum_value(edge.edge_type, GraphEdgeType.RELATED_TO.value),
                    int(edge.weight),
                )
                for edge in self.edges
            ),
            "counts": dict(self.counts),
        }

        return _fingerprint_payload(payload)

    def __len__(self) -> int:
        return len(self.nodes)

    def node_ids(self) -> tuple[str, ...]:
        return tuple(node.node_id for node in self.nodes)

    def edge_ids(self) -> tuple[str, ...]:
        return tuple(edge.edge_id for edge in self.edges)

    def degree(self, node_id: Any) -> int:
        key = _clean_text(node_id, _MAX_NODE_ID_LENGTH).lower()
        return len(self.undirected_adjacency.get(key, ()))

    def in_degree(self, node_id: Any) -> int:
        key = _clean_text(node_id, _MAX_NODE_ID_LENGTH).lower()
        return len(self.reverse_adjacency.get(key, ()))

    def out_degree(self, node_id: Any) -> int:
        key = _clean_text(node_id, _MAX_NODE_ID_LENGTH).lower()
        return len(self.adjacency.get(key, ()))

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "status": _enum_value(self.status, GraphStatus.AVAILABLE.value),
            "built_at": self.built_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "counts": dict(self.counts),
            "node_type_counts": dict(self.node_type_counts),
            "edge_type_counts": dict(self.edge_type_counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "nodes_omitted": True,
            "edges_omitted": True,
            "raw_attributes_omitted": True,
            "caveats": list(_BUILDER_CAVEATS),
            "safety_flags": dict(GRAPH_SAFETY_FLAGS),
        }

    def to_internal_dict(self, *, include_attributes: bool = False) -> dict[str, Any]:
        payload = self.to_public_dict()
        payload.pop("nodes_omitted", None)
        payload.pop("edges_omitted", None)
        payload.pop("raw_attributes_omitted", None)

        payload["nodes"] = [
            node.to_dict(include_attributes=include_attributes)
            for node in self.nodes
        ]
        payload["edges"] = [
            edge.to_dict(include_attributes=include_attributes)
            for edge in self.edges
        ]
        payload["adjacency"] = {
            key: list(value)
            for key, value in self.adjacency.items()
        }
        payload["reverse_adjacency"] = {
            key: list(value)
            for key, value in self.reverse_adjacency.items()
        }
        payload["undirected_adjacency"] = {
            key: list(value)
            for key, value in self.undirected_adjacency.items()
        }
        payload["internal_only"] = True

        return payload


# -----------------------------------------------------------------------------
# Internal builder state
# -----------------------------------------------------------------------------


class _GraphBuilderState:
    """
    Mutable internal graph builder state.
    """

    def __init__(self, policy: GraphPolicy) -> None:
        self.policy = policy
        self.start_time = time.monotonic()
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}
        self.adjacency: dict[str, set[str]] = defaultdict(set)
        self.reverse_adjacency: dict[str, set[str]] = defaultdict(set)
        self.issues: list[GraphIssue] = []
        self.counts: Counter[str] = Counter()
        self.node_type_counts: Counter[str] = Counter()
        self.edge_type_counts: Counter[str] = Counter()
        self.transaction_nodes_by_ref: dict[str, str] = {}
        self.truncated_nodes = False
        self.truncated_edges = False
        self.time_budget_exhausted = False
        self.blocked = False
        self.block_reason = ""

    def time_exceeded(self) -> bool:
        return _time_exceeded(self.start_time, self.policy.max_time_ms)

    def add_issue(
        self,
        *,
        severity: IssueSeverity,
        code: str,
        message: str,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        _append_issue(
            self.issues,
            self.policy.max_issues,
            severity=severity,
            code=code,
            message=message,
            field=field,
            details=details,
        )


# -----------------------------------------------------------------------------
# Graph builder
# -----------------------------------------------------------------------------


class GraphBuilder:
    """
    Bounded deterministic synthetic graph builder.

    This builder constructs pseudonymous graph views from synthetic records. It
    does not traverse unbounded paths, does not persist durable artifacts, and
    must not trigger automatic adverse customer action.
    """

    def __init__(self, policy: GraphPolicy | None = None) -> None:
        self.policy = policy or GraphPolicy.from_settings()
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Hash helpers
    # ------------------------------------------------------------------

    def _hash_identifier(self, raw: Any, domain: str) -> Optional[str]:
        text = _clean_text(raw, _MAX_TEXT_LENGTH)

        if not text:
            return None

        if _is_safe_hash(text):
            return text.lower()

        safe_namespace = _normalize_token(self.policy.namespace) or _DEFAULT_NAMESPACE
        full_domain = f"muleguard.graph.builder.{domain}.{safe_namespace}"
        return _hmac_hex(self.policy.salt, full_domain, text)

    def _hash_message(self, message: str, domain: str) -> str:
        safe_namespace = _normalize_token(self.policy.namespace) or _DEFAULT_NAMESPACE
        full_domain = f"muleguard.graph.builder.{domain}.{safe_namespace}"
        return _hmac_hex(self.policy.salt, full_domain, message)

    # ------------------------------------------------------------------
    # Node/edge helpers
    # ------------------------------------------------------------------

    def _add_node(
        self,
        state: _GraphBuilderState,
        node_type: GraphNodeType,
        raw_id: Any,
        attributes: Optional[Mapping[str, Any]] = None,
        id_domain: Optional[str] = None,
    ) -> Optional[str]:
        if state.time_exceeded():
            state.time_budget_exhausted = True
            return None

        node_id = self._hash_identifier(raw_id, id_domain or node_type.value)

        if not node_id:
            return None

        existing = state.nodes.get(node_id)

        if existing is not None:
            return node_id

        if len(state.nodes) >= state.policy.max_nodes:
            if not state.truncated_nodes:
                state.truncated_nodes = True
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="graph_node_limit_reached",
                    message="Graph node limit reached. Additional nodes were not added.",
                    details={"max_nodes": state.policy.max_nodes},
                )
            return None

        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            attributes=attributes or {},
            created_at=_now_utc(),
        )

        state.nodes[node_id] = node
        state.node_type_counts[node_type.value] += 1
        state.counts["nodes_added"] += 1
        return node_id

    def _add_edge(
        self,
        state: _GraphBuilderState,
        source_node_id: Optional[str],
        target_node_id: Optional[str],
        edge_type: GraphEdgeType,
        attributes: Optional[Mapping[str, Any]] = None,
        weight: int = 1,
    ) -> Optional[str]:
        if state.time_exceeded():
            state.time_budget_exhausted = True
            return None

        if not source_node_id or not target_node_id:
            return None

        if source_node_id == target_node_id:
            state.add_issue(
                severity=IssueSeverity.INFO,
                code="self_edge_skipped",
                message="Self-referential graph edge skipped.",
                details={"edge_type": edge_type.value},
            )
            return None

        if source_node_id not in state.nodes or target_node_id not in state.nodes:
            state.add_issue(
                severity=IssueSeverity.WARNING,
                code="edge_endpoint_missing",
                message="Graph edge endpoint missing and edge skipped.",
                details={"edge_type": edge_type.value},
            )
            return None

        edge_id = self._hash_message(
            f"{source_node_id}|{target_node_id}|{edge_type.value}",
            "edge",
        )

        sanitized_attributes = _sanitize_edge_attributes(attributes)
        existing = state.edges.get(edge_id)

        if existing is not None:
            merged = _merge_edge_attributes(existing.attributes, sanitized_attributes)
            updated = replace(
                existing,
                weight=max(1, existing.weight + max(1, int(weight))),
                attributes=merged,
                updated_at=_now_utc(),
            )
            state.edges[edge_id] = updated
            state.counts["edges_updated"] += 1
            return edge_id

        if len(state.edges) >= state.policy.max_edges:
            if not state.truncated_edges:
                state.truncated_edges = True
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="graph_edge_limit_reached",
                    message="Graph edge limit reached. Additional edges were not added.",
                    details={"max_edges": state.policy.max_edges},
                )
            return None

        edge = GraphEdge(
            edge_id=edge_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            edge_type=edge_type,
            weight=max(1, int(weight)),
            attributes=sanitized_attributes,
            created_at=_now_utc(),
            updated_at=_now_utc(),
        )

        state.edges[edge_id] = edge
        state.adjacency[source_node_id].add(target_node_id)
        state.reverse_adjacency[target_node_id].add(source_node_id)
        state.edge_type_counts[edge_type.value] += 1
        state.counts["edges_added"] += 1
        return edge_id

    # ------------------------------------------------------------------
    # Collection helpers
    # ------------------------------------------------------------------

    def _iter_collection(self, dataset: Any, names: Sequence[str]) -> list[Any]:
        if dataset is None:
            return []

        if isinstance(dataset, Mapping):
            for name in names:
                if name in dataset:
                    return _as_sequence(dataset[name])

            return []

        for name in names:
            value = getattr(dataset, name, None)

            if value is not None:
                return _as_sequence(value)

        return []

    def _safe_record(
        self,
        record: Any,
        state: _GraphBuilderState,
        *,
        collection: str,
        index: int,
    ) -> Optional[dict[str, Any]]:
        fields = _record_fields(record)

        if not fields:
            return None

        forbidden = _scan_forbidden_fields(fields)

        if forbidden:
            state.add_issue(
                severity=IssueSeverity.ERROR,
                code="forbidden_graph_input_field",
                message="Forbidden or leakage-prone graph input field rejected.",
                field=forbidden[0] if forbidden else None,
                details={
                    "collection": collection,
                    "index": index,
                    "forbidden_count": len(forbidden),
                },
            )
            return None

        return fields

    # ------------------------------------------------------------------
    # Record adders
    # ------------------------------------------------------------------

    def _add_accounts(self, state: _GraphBuilderState, dataset: Any) -> None:
        records = self._iter_collection(dataset, ("accounts", "account_records"))

        for index, record in enumerate(records):
            if state.time_exceeded():
                state.time_budget_exhausted = True
                break

            fields = self._safe_record(record, state, collection="accounts", index=index)

            if fields is None:
                continue

            raw_id = _pick(fields, _ACCOUNT_ID_KEYS)

            if raw_id is None:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="account_missing_id",
                    message="Account record missing identifier and was skipped.",
                    details={"collection": "accounts", "index": index},
                )
                continue

            attributes = {
                "account_type": _safe_token_value(_pick(fields, ("account_type", "type"))),
                "status": _safe_token_value(_pick(fields, ("status", "state"))),
            }

            self._add_node(
                state,
                GraphNodeType.ACCOUNT,
                raw_id,
                attributes=attributes,
                id_domain="account",
            )

    def _add_entities(self, state: _GraphBuilderState, dataset: Any) -> None:
        records = self._iter_collection(dataset, ("entities", "entity_records"))

        for index, record in enumerate(records):
            if state.time_exceeded():
                state.time_budget_exhausted = True
                break

            fields = self._safe_record(record, state, collection="entities", index=index)

            if fields is None:
                continue

            raw_id = _pick(fields, _ENTITY_ID_KEYS)

            if raw_id is None:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="entity_missing_id",
                    message="Entity record missing identifier and was skipped.",
                    details={"collection": "entities", "index": index},
                )
                continue

            attributes = {
                "entity_type": _safe_token_value(_pick(fields, ("entity_type", "kind", "type"))),
            }

            self._add_node(
                state,
                GraphNodeType.ENTITY,
                raw_id,
                attributes=attributes,
                id_domain="entity",
            )

    def _add_entity_links(self, state: _GraphBuilderState, dataset: Any) -> None:
        records = self._iter_collection(
            dataset,
            ("entity_links", "links", "account_entity_links"),
        )

        for index, record in enumerate(records):
            if state.time_exceeded():
                state.time_budget_exhausted = True
                break

            fields = self._safe_record(record, state, collection="entity_links", index=index)

            if fields is None:
                continue

            raw_account = _pick(fields, _ACCOUNT_REF_KEYS)
            raw_entity = _pick(fields, _ENTITY_REF_KEYS)

            if raw_account is None or raw_entity is None:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="entity_link_missing_endpoint",
                    message="Entity link missing account or entity reference and was skipped.",
                    details={"collection": "entity_links", "index": index},
                )
                continue

            account_node = self._add_node(
                state,
                GraphNodeType.ACCOUNT,
                raw_account,
                attributes={},
                id_domain="account",
            )
            entity_node = self._add_node(
                state,
                GraphNodeType.ENTITY,
                raw_entity,
                attributes={
                    "entity_type": _safe_token_value(_pick(fields, ("entity_type", "kind", "type"))),
                },
                id_domain="entity",
            )

            confidence = _to_decimal(_pick(fields, ("confidence",)))
            attributes = {
                "match_method": _safe_token_value(_pick(fields, ("match_method", "method"))),
                "verification_state": _safe_token_value(_pick(fields, ("verification_state", "state"))),
                "confidence": (
                    _round6(_clip_float(float(confidence), 0.0, 1.0, 0.0))
                    if confidence is not None
                    else None
                ),
                "roles": ("entity_link",),
                "count": 1,
            }

            self._add_edge(
                state,
                account_node,
                entity_node,
                GraphEdgeType.LINKED_TO,
                attributes=attributes,
            )

    def _add_transactions(self, state: _GraphBuilderState, dataset: Any) -> None:
        if not self.policy.include_transactions:
            return

        records = self._iter_collection(dataset, ("transactions", "transaction_records", "txns"))

        for index, record in enumerate(records):
            if state.time_exceeded():
                state.time_budget_exhausted = True
                break

            fields = self._safe_record(record, state, collection="transactions", index=index)

            if fields is None:
                continue

            status_token = _normalize_token(_pick(fields, ("status", "state"))) or "unknown"

            if status_token not in _COMPLETED_TRANSACTION_TOKENS:
                state.counts["transactions_skipped_not_completed"] += 1
                continue

            raw_sender = _pick(fields, _SENDER_KEYS)
            raw_receiver = _pick(fields, _RECEIVER_KEYS)

            if raw_sender is None or raw_receiver is None:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="transaction_missing_endpoint",
                    message="Transaction missing sender or receiver and was skipped.",
                    details={"collection": "transactions", "index": index},
                )
                continue

            sender_hash = self._hash_identifier(raw_sender, "account")
            receiver_hash = self._hash_identifier(raw_receiver, "account")

            if sender_hash == receiver_hash:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="transaction_self_transfer_skipped",
                    message="Transaction sender and receiver are the same and was skipped.",
                    details={"collection": "transactions", "index": index},
                )
                continue

            amount = _to_decimal(_pick(fields, ("amount", "value")))
            currency = _normalize_currency(_pick(fields, ("currency", "ccy")))

            if amount is None or amount <= 0:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="transaction_missing_amount",
                    message="Transaction missing positive amount and was skipped.",
                    details={"collection": "transactions", "index": index},
                )
                continue

            if not currency:
                currency = "UNKNOWN"

            sender_node = self._add_node(
                state,
                GraphNodeType.ACCOUNT,
                raw_sender,
                attributes={},
                id_domain="account",
            )
            receiver_node = self._add_node(
                state,
                GraphNodeType.ACCOUNT,
                raw_receiver,
                attributes={},
                id_domain="account",
            )

            raw_tx_id = _pick(fields, _TRANSACTION_ID_KEYS)

            if raw_tx_id is None:
                occurred_at = _pick(fields, ("occurred_at", "timestamp", "time", "date"))
                channel = _safe_token_value(_pick(fields, ("channel",)))

                derived_message = _canonical_json(
                    {
                        "sender": sender_hash,
                        "receiver": receiver_hash,
                        "amount": str(_quantize_money(amount)),
                        "currency": currency,
                        "occurred_at": _clean_text(occurred_at, 64),
                        "channel": channel,
                    }
                )
                raw_tx_id = self._hash_message(derived_message, "transaction_derived")

            tx_attributes = {
                "kind": "transaction",
                "source_system": "synthetic_ingestion",
            }

            tx_node = self._add_node(
                state,
                GraphNodeType.TRANSACTION,
                raw_tx_id,
                attributes=tx_attributes,
                id_domain="transaction",
            )

            if tx_node is None:
                continue

            for raw_ref in (
                _pick(fields, ("id", "transaction_id", "txn_id")),
                _pick(fields, ("reference", "transaction_reference", "txn_reference", "ref")),
            ):
                if raw_ref is None:
                    continue

                ref_hash = self._hash_identifier(raw_ref, "transaction_ref")

                if ref_hash:
                    state.transaction_nodes_by_ref.setdefault(ref_hash, tx_node)

            channel = _safe_token_value(_pick(fields, ("channel",)))
            edge_attributes = {
                "count": 1,
                "currencies": (currency,),
                "amount_by_currency": {currency: _quantize_money(amount)},
                "channels": (channel,) if channel else (),
            }

            self._add_edge(
                state,
                sender_node,
                tx_node,
                GraphEdgeType.SENT,
                attributes=edge_attributes,
            )
            self._add_edge(
                state,
                tx_node,
                receiver_node,
                GraphEdgeType.RECEIVED,
                attributes=edge_attributes,
            )

    def _add_complaints(self, state: _GraphBuilderState, dataset: Any) -> None:
        if not self.policy.include_complaints:
            return

        records = self._iter_collection(dataset, ("complaints", "complaint_records"))

        for index, record in enumerate(records):
            if state.time_exceeded():
                state.time_budget_exhausted = True
                break

            fields = self._safe_record(record, state, collection="complaints", index=index)

            if fields is None:
                continue

            raw_complaint_id = _pick(fields, _COMPLAINT_ID_KEYS)

            if raw_complaint_id is None:
                raw_complaint_id = self._hash_message(
                    _canonical_json(
                        {
                            "victim": self._hash_identifier(_pick(fields, _VICTIM_KEYS), "account"),
                            "suspect": self._hash_identifier(_pick(fields, _SUSPECT_KEYS), "account"),
                            "category": _safe_token_value(_pick(fields, ("category",))),
                            "reported_at": _clean_text(_pick(fields, ("reported_at", "created_at")), 64),
                        }
                    ),
                    "complaint_derived",
                )

            complaint_node = self._add_node(
                state,
                GraphNodeType.COMPLAINT,
                raw_complaint_id,
                attributes={
                    "category": _safe_token_value(_pick(fields, ("category",))),
                    "source_system": _safe_token_value(_pick(fields, ("source_system", "source"))),
                },
                id_domain="complaint",
            )

            if complaint_node is None:
                continue

            raw_victim = _pick(fields, _VICTIM_KEYS)
            raw_suspect = _pick(fields, _SUSPECT_KEYS)

            if raw_victim is not None:
                victim_node = self._add_node(
                    state,
                    GraphNodeType.ACCOUNT,
                    raw_victim,
                    attributes={},
                    id_domain="account",
                )
                self._add_edge(
                    state,
                    complaint_node,
                    victim_node,
                    GraphEdgeType.CORRELATED_WITH,
                    attributes={"roles": ("victim",), "count": 1},
                )

            if raw_suspect is not None:
                suspect_node = self._add_node(
                    state,
                    GraphNodeType.ACCOUNT,
                    raw_suspect,
                    attributes={},
                    id_domain="account",
                )
                self._add_edge(
                    state,
                    complaint_node,
                    suspect_node,
                    GraphEdgeType.CORRELATED_WITH,
                    attributes={"roles": ("suspect",), "count": 1},
                )

            raw_transaction_ref = _pick(fields, _TRANSACTION_REF_KEYS)

            if raw_transaction_ref is not None:
                ref_hash = self._hash_identifier(raw_transaction_ref, "transaction_ref")

                if ref_hash:
                    tx_node = state.transaction_nodes_by_ref.get(ref_hash)

                    if tx_node is not None:
                        self._add_edge(
                            state,
                            complaint_node,
                            tx_node,
                            GraphEdgeType.CORRELATED_WITH,
                            attributes={"roles": ("transaction_reference",), "count": 1},
                        )

    def _add_alerts(self, state: _GraphBuilderState, dataset: Any) -> None:
        if not self.policy.include_alerts:
            return

        records = self._iter_collection(dataset, ("alerts", "alert_records"))

        for index, record in enumerate(records):
            if state.time_exceeded():
                state.time_budget_exhausted = True
                break

            fields = self._safe_record(record, state, collection="alerts", index=index)

            if fields is None:
                continue

            raw_alert_id = _pick(fields, _ALERT_ID_KEYS)

            if raw_alert_id is None:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="alert_missing_id",
                    message="Alert record missing identifier and was skipped.",
                    details={"collection": "alerts", "index": index},
                )
                continue

            alert_node = self._add_node(
                state,
                GraphNodeType.ALERT,
                raw_alert_id,
                attributes={
                    "state": _safe_token_value(_pick(fields, ("state", "status"))),
                    "severity": _safe_token_value(_pick(fields, ("severity",))),
                },
                id_domain="alert",
            )

            if alert_node is None:
                continue

            raw_account = _pick(fields, _ACCOUNT_REF_KEYS)

            if raw_account is not None:
                account_node = self._add_node(
                    state,
                    GraphNodeType.ACCOUNT,
                    raw_account,
                    attributes={},
                    id_domain="account",
                )
                self._add_edge(
                    state,
                    alert_node,
                    account_node,
                    GraphEdgeType.ALERTED_ON,
                    attributes={"roles": ("alert",), "count": 1},
                )

    def _add_assessments(self, state: _GraphBuilderState, dataset: Any) -> None:
        if not self.policy.include_assessments:
            return

        records = self._iter_collection(
            dataset,
            ("assessments", "assessment_records", "model_assessments"),
        )

        for index, record in enumerate(records):
            if state.time_exceeded():
                state.time_budget_exhausted = True
                break

            fields = self._safe_record(record, state, collection="assessments", index=index)

            if fields is None:
                continue

            raw_assessment_id = _pick(fields, _ASSESSMENT_ID_KEYS)

            if raw_assessment_id is None:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="assessment_missing_id",
                    message="Assessment record missing identifier and was skipped.",
                    details={"collection": "assessments", "index": index},
                )
                continue

            assessment_node = self._add_node(
                state,
                GraphNodeType.ASSESSMENT,
                raw_assessment_id,
                attributes={
                    "scoring_mode": _safe_token_value(_pick(fields, ("scoring_mode", "mode"))),
                    "risk_band": _safe_token_value(_pick(fields, ("risk_band", "band"))),
                },
                id_domain="assessment",
            )

            if assessment_node is None:
                continue

            raw_account = _pick(fields, _ACCOUNT_REF_KEYS)

            if raw_account is not None:
                account_node = self._add_node(
                    state,
                    GraphNodeType.ACCOUNT,
                    raw_account,
                    attributes={},
                    id_domain="account",
                )
                self._add_edge(
                    state,
                    account_node,
                    assessment_node,
                    GraphEdgeType.ASSESSED_BY,
                    attributes={"roles": ("assessment",), "count": 1},
                )

    def _add_cases(self, state: _GraphBuilderState, dataset: Any) -> None:
        if not self.policy.include_cases:
            return

        records = self._iter_collection(dataset, ("cases", "case_records", "investigation_cases"))

        for index, record in enumerate(records):
            if state.time_exceeded():
                state.time_budget_exhausted = True
                break

            fields = self._safe_record(record, state, collection="cases", index=index)

            if fields is None:
                continue

            raw_case_id = _pick(fields, _CASE_ID_KEYS)

            if raw_case_id is None:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="case_missing_id",
                    message="Case record missing identifier and was skipped.",
                    details={"collection": "cases", "index": index},
                )
                continue

            case_node = self._add_node(
                state,
                GraphNodeType.CASE,
                raw_case_id,
                attributes={
                    "state": _safe_token_value(_pick(fields, ("status", "state"))),
                    "source_system": _safe_token_value(_pick(fields, ("source_system", "source"))),
                },
                id_domain="case",
            )

            if case_node is None:
                continue

            raw_account = _pick(fields, _ACCOUNT_REF_KEYS)

            if raw_account is not None:
                account_node = self._add_node(
                    state,
                    GraphNodeType.ACCOUNT,
                    raw_account,
                    attributes={},
                    id_domain="account",
                )
                self._add_edge(
                    state,
                    account_node,
                    case_node,
                    GraphEdgeType.ATTACHED_TO_CASE,
                    attributes={"roles": ("account",), "count": 1},
                )

            raw_alert = _pick(fields, _ALERT_REF_KEYS)

            if raw_alert is not None:
                alert_node = self._add_node(
                    state,
                    GraphNodeType.ALERT,
                    raw_alert,
                    attributes={},
                    id_domain="alert",
                )
                self._add_edge(
                    state,
                    alert_node,
                    case_node,
                    GraphEdgeType.ATTACHED_TO_CASE,
                    attributes={"roles": ("alert",), "count": 1},
                )

            raw_complaint = _pick(fields, _COMPLAINT_REF_KEYS)

            if raw_complaint is not None:
                complaint_node = self._add_node(
                    state,
                    GraphNodeType.COMPLAINT,
                    raw_complaint,
                    attributes={},
                    id_domain="complaint",
                )
                self._add_edge(
                    state,
                    complaint_node,
                    case_node,
                    GraphEdgeType.ATTACHED_TO_CASE,
                    attributes={"roles": ("complaint",), "count": 1},
                )

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(self, dataset: Any) -> GraphView:
        """
        Build one bounded synthetic graph view.
        """
        policy = self.policy
        state = _GraphBuilderState(policy)

        with self._lock:
            if not policy.enabled:
                state.blocked = True
                state.block_reason = "graph_disabled"
                state.add_issue(
                    severity=IssueSeverity.INFO,
                    code="graph_disabled",
                    message="Graph builder is disabled by policy.",
                )
            elif policy.synthetic_required and policy.dataset_mode != "synthetic":
                state.blocked = True
                state.block_reason = "non_synthetic_dataset"
                state.add_issue(
                    severity=IssueSeverity.ERROR,
                    code="non_synthetic_dataset",
                    message="Graph builder requires synthetic dataset mode.",
                    details={"dataset_mode": policy.dataset_mode},
                )
            elif policy.production_like and not policy.allow_in_production:
                state.blocked = True
                state.block_reason = "production_like_blocked"
                state.add_issue(
                    severity=IssueSeverity.ERROR,
                    code="production_like_blocked",
                    message="Graph builder is blocked in production-like environments.",
                )
            else:
                if policy.include_entities:
                    self._add_entities(state, dataset)

                self._add_accounts(state, dataset)

                if policy.include_entities:
                    self._add_entity_links(state, dataset)

                if policy.include_transactions:
                    self._add_transactions(state, dataset)

                if policy.include_complaints:
                    self._add_complaints(state, dataset)

                if policy.include_alerts:
                    self._add_alerts(state, dataset)

                if policy.include_assessments:
                    self._add_assessments(state, dataset)

                if policy.include_cases:
                    self._add_cases(state, dataset)

            if state.time_budget_exhausted:
                state.add_issue(
                    severity=IssueSeverity.WARNING,
                    code="graph_build_time_budget_exhausted",
                    message="Graph construction stopped after reaching configured time budget.",
                    details={"max_time_ms": policy.max_time_ms},
                )

            nodes = tuple(state.nodes.values())
            edges = tuple(state.edges.values())

            if state.blocked:
                status = GraphStatus.BLOCKED
            elif _has_error(state.issues):
                status = GraphStatus.FAILED
            elif len(nodes) == 0:
                status = GraphStatus.EMPTY
            elif state.truncated_nodes or state.truncated_edges or state.time_budget_exhausted:
                status = GraphStatus.TRUNCATED
            elif _has_warning(state.issues):
                status = GraphStatus.DEGRADED
            else:
                status = GraphStatus.AVAILABLE

            counts = dict(state.counts)
            counts.update(
                {
                    "nodes": len(nodes),
                    "edges": len(edges),
                    "issues": len(state.issues),
                    "node_limit": policy.max_nodes,
                    "edge_limit": policy.max_edges,
                }
            )

            metadata = {
                "graph_builder_version": GRAPH_BUILDER_VERSION,
                "policy": policy.safe_summary(),
                "built_at": _now_utc().isoformat(),
                "node_limit_applied": state.truncated_nodes,
                "edge_limit_applied": state.truncated_edges,
                "time_budget_exhausted": state.time_budget_exhausted,
                "blocked": state.blocked,
                "block_reason": state.block_reason,
                "raw_attributes_exposed": False,
                "raw_narratives_retained": False,
                "raw_identifiers_retained": False,
                "subject_label_pairs_retained": False,
                "secrets_retained": False,
                "mixed_currency_conversion_allowed": False,
                "caveats": list(_BUILDER_CAVEATS),
                "safety_flags": dict(GRAPH_SAFETY_FLAGS),
            }

            return GraphView(
                status=status,
                nodes=nodes,
                edges=edges,
                built_at=_now_utc(),
                duration_ms=_elapsed_ms(state.start_time),
                counts=counts,
                node_type_counts=dict(state.node_type_counts),
                edge_type_counts=dict(state.edge_type_counts),
                issues=tuple(state.issues),
                metadata=metadata,
                fingerprint="",
            )


# -----------------------------------------------------------------------------
# Default builder and public API
# -----------------------------------------------------------------------------


_default_builder: Optional[GraphBuilder] = None
_default_builder_lock = threading.Lock()


def get_graph_builder(
    policy: GraphPolicy | None = None,
    *,
    rebuild: bool = False,
) -> GraphBuilder:
    """
    Return a process-wide graph builder.

    If policy is supplied or rebuild is True, a new builder is created and
    becomes the default.
    """
    global _default_builder

    with _default_builder_lock:
        if _default_builder is None or rebuild or policy is not None:
            _default_builder = GraphBuilder(policy=policy or GraphPolicy.from_settings())

        return _default_builder


def build_graph(
    dataset: Any,
    policy: GraphPolicy | None = None,
    *,
    builder: GraphBuilder | None = None,
    settings: Any | None = None,
) -> GraphView:
    """
    Build one bounded synthetic graph view.
    """
    if builder is not None:
        return builder.build(dataset)

    resolved_policy = policy

    if resolved_policy is None:
        resolved_policy = GraphPolicy.from_settings(settings)

    active_builder = get_graph_builder(resolved_policy)
    return active_builder.build(dataset)


def get_graph_builder_metadata() -> dict[str, Any]:
    """
    Return safe, serializable graph-builder metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, raw node attributes, raw identifiers,
    or real customer data.
    """
    policy = GraphPolicy.from_settings()

    return {
        "package": "muleguard.backend.graph.builder",
        "version": GRAPH_BUILDER_VERSION,
        "node_types": [member.value for member in GraphNodeType],
        "edge_types": [member.value for member in GraphEdgeType],
        "statuses": [member.value for member in GraphStatus],
        "issue_severities": [member.value for member in IssueSeverity],
        "default_policy": policy.safe_summary(),
        "builder_backend": "in_memory_deterministic",
        "distributed": False,
        "durable": False,
        "hard_limits": {
            "max_nodes": getattr(policy, "max_nodes", 0),
            "max_edges": getattr(policy, "max_edges", 0),
            "max_depth": getattr(policy, "max_depth", 0),
            "max_paths": getattr(policy, "max_paths", 0),
            "max_trails": getattr(policy, "max_trails", 0),
            "max_shared_groups": getattr(policy, "max_shared_groups", 0),
            "max_accounts_per_entity": getattr(policy, "max_accounts_per_entity", 0),
            "max_communities": getattr(policy, "max_communities", 0),
            "max_community_size": getattr(policy, "max_community_size", 0),
            "max_date_span_days": getattr(policy, "max_date_span_days", 0),
            "max_time_ms": getattr(policy, "max_time_ms", 0),
            "max_issues": getattr(policy, "max_issues", 0),
            "max_summary_items": getattr(policy, "max_summary_items", 0),
        },
        "forbidden_graph_field_count": len(_FORBIDDEN_GRAPH_FIELDS),
        "label_leakage_field_count": len(_LABEL_LEAKAGE_FIELDS),
        "caveats": list(_BUILDER_CAVEATS),
        "safety_flags": dict(GRAPH_SAFETY_FLAGS),
    }


__all__ = [
    "GraphBuilder",
    "GraphEdge",
    "GraphIssue",
    "GraphNode",
    "GraphView",
    "build_graph",
    "get_graph_builder",
    "get_graph_builder_metadata",
]