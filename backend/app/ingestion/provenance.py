"""
MULEGUARD backend ingestion provenance.

This module provides the canonical provenance, lineage, integrity, and audit
path layer for synthetic MULEGUARD ingestion workflows.

Primary responsibilities:

- build safe, deterministic provenance envelopes for ingestion batches and
  records;
- produce salted, one-way record fingerprints without storing raw complaint
  narratives, raw identifiers, secrets, tokens, passwords, database URLs, model
  artifact paths, ground-truth labels, scenario IDs, or fraud-ring IDs;
- compute bounded Merkle roots and audit paths for batch integrity;
- maintain an optional process-local hash-chained provenance ledger for local
  prototype lineage;
- sign provenance envelopes using keyed HMAC integrity for local trust;
- verify record hashes, Merkle roots, signatures, and chain links;
- return safe public summaries that exclude record content and sensitive values;
- remain import-safe, dependency-light, and usable by loaders, normalizers,
  validators, dedupe, seeders, services, tests, and offline fixtures.

This module records provenance only. It does not persist data, call external
systems, authenticate users, authorize actions, train models, generate reports,
or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be ingested.
- Ground-truth labels, injected scenario IDs, and fraud-ring IDs are forbidden
  in provenance inputs and are omitted from provenance payloads.
- Raw complaint narratives are never stored, logged, signed, returned, or
  included in public summaries.
- Complaint narratives may contribute only a salted one-way narrative hash when
  present in controlled synthetic complaint records.
- Entity raw identifiers are forbidden. Only pseudonymous identifier hashes are
  accepted.
- Secrets, tokens, passwords, database URLs, model artifact paths, filesystem
  paths, and raw sensitive identifiers are never exposed.
- Provenance indexes and ledgers are bounded by hard caps and sliding-window
  pruning.
- Provenance signatures are keyed HMAC integrity markers for local prototype
  use. They are not public-key signatures and do not provide non-repudiation.
- Duplicate, near-duplicate, lineage, chain, and Merkle outputs are operational
  ingestion hygiene artefacts only. They are not investigative correlations,
  not proof of duplication, and not proof of wrongdoing.
- Provenance handling never freezes, blocks, blacklists, closes, restricts, or
  otherwise takes adverse action against accounts or customers.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not write to the database.
- This module does not call real banking systems.
- This module does not authenticate or authorize users.
- This module does not generate synthetic data.
- This module does not perform final business-rule validation; use
  `app.ingestion.normalizers` and `app.ingestion.validators` for that.
- This module does not train or evaluate models.
- This module is not a distributed provenance service. Production
  multi-instance deployments should replace the local ledger with a reviewed
  durable append-only store such as a database audit log, WORM storage, or a
  transparency log.

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
import json
import logging
import math
import re
import threading
import time
import unicodedata
import uuid
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Final, Optional

logger = logging.getLogger("muleguard.backend.ingestion.provenance")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

PROVENANCE_VERSION: Final[str] = "v1"
PROVENANCE_SCHEMA_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_MAX_RECORDS: Final[int] = 10_000
_HARD_MAX_RECORDS: Final[int] = 100_000

_DEFAULT_MAX_ISSUES_RETURNED: Final[int] = 100
_HARD_MAX_ISSUES_RETURNED: Final[int] = 500

_DEFAULT_MAX_STRING_LENGTH: Final[int] = 512
_HARD_MAX_STRING_LENGTH: Final[int] = 4_096

_DEFAULT_MAX_METADATA_DEPTH: Final[int] = 6
_HARD_MAX_METADATA_DEPTH: Final[int] = 12

_DEFAULT_MAX_LIST_LENGTH: Final[int] = 100
_HARD_MAX_LIST_LENGTH: Final[int] = 1_000

_DEFAULT_MAX_MAPPING_KEYS: Final[int] = 100
_HARD_MAX_MAPPING_KEYS: Final[int] = 1_000

_DEFAULT_LEDGER_MAX_ENTRIES: Final[int] = 10_000
_HARD_LEDGER_MAX_ENTRIES: Final[int] = 100_000

_DEFAULT_RETENTION_SECONDS: Final[float] = 86_400.0
_DEFAULT_PRUNE_INTERVAL_SECONDS: Final[float] = 60.0

_GENESIS_HASH: Final[str] = hashlib.sha256(
    b"muleguard-provenance-genesis-v1"
).hexdigest()

_DOMAIN_RECORD: Final[str] = "muleguard.provenance.record"
_DOMAIN_NARRATIVE: Final[str] = "muleguard.provenance.narrative"
_DOMAIN_METADATA: Final[str] = "muleguard.provenance.metadata"
_DOMAIN_CHAIN: Final[str] = "muleguard.provenance.chain"
_DOMAIN_SIGNATURE: Final[str] = "muleguard.provenance.signature"
_DOMAIN_ACTOR: Final[str] = "muleguard.provenance.actor"

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")

_PLACEHOLDER_MARKERS: Final[tuple[str, ...]] = (
    "change_me",
    "changeme",
    "placeholder",
    "replace_me",
    "replace-me",
    "your_",
    "example_",
    "todo",
    "fixme",
)

_SUPPORTED_ENTITY_TYPES: Final[tuple[str, ...]] = (
    "accounts",
    "transactions",
    "complaints",
    "entities",
    "entity_links",
)

_ALLOWED_FIELDS: Final[Mapping[str, frozenset[str]]] = {
    "accounts": frozenset(
        {
            "id",
            "account_type",
            "status",
            "created_at",
            "metadata_json",
        }
    ),
    "transactions": frozenset(
        {
            "id",
            "reference",
            "sender_account_id",
            "receiver_account_id",
            "amount",
            "currency",
            "occurred_at",
            "status",
            "channel",
            "metadata_json",
        }
    ),
    "complaints": frozenset(
        {
            "id",
            "reference",
            "reported_at",
            "category",
            "narrative_raw",
            "transaction_reference",
            "victim_account_id",
            "suspected_account_id",
            "amount",
            "currency",
            "source",
            "metadata_json",
        }
    ),
    "entities": frozenset(
        {
            "id",
            "entity_type",
            "identifier_hash",
            "identifier_display",
            "source",
            "first_seen_at",
            "last_seen_at",
            "metadata_json",
        }
    ),
    "entity_links": frozenset(
        {
            "id",
            "account_id",
            "entity_id",
            "match_method",
            "confidence",
            "verification_state",
            "valid_from",
            "valid_to",
            "source",
            "metadata_json",
        }
    ),
}

_FIELD_ALIASES: Final[Mapping[str, Mapping[str, str]]] = {
    "accounts": {
        "account_id": "id",
        "acct_id": "id",
        "type": "account_type",
        "state": "status",
    },
    "transactions": {
        "transaction_id": "id",
        "txn_id": "id",
        "from_account_id": "sender_account_id",
        "to_account_id": "receiver_account_id",
        "sender": "sender_account_id",
        "receiver": "receiver_account_id",
        "from": "sender_account_id",
        "to": "receiver_account_id",
        "timestamp": "occurred_at",
        "time": "occurred_at",
        "date": "occurred_at",
        "value": "amount",
        "ccy": "currency",
    },
    "complaints": {
        "complaint_id": "id",
        "filed_at": "reported_at",
        "reported_date": "reported_at",
        "txn_reference": "transaction_reference",
        "transaction_ref": "transaction_reference",
        "suspect_account_id": "suspected_account_id",
        "suspect": "suspected_account_id",
        "victim": "victim_account_id",
    },
    "entities": {
        "entity_id": "id",
        "kind": "entity_type",
        "hashed_identifier": "identifier_hash",
        "hash": "identifier_hash",
    },
    "entity_links": {
        "link_id": "id",
        "account": "account_id",
        "entity": "entity_id",
        "from_account_id": "account_id",
        "to_entity_id": "entity_id",
        "start_at": "valid_from",
        "end_at": "valid_to",
        "method": "match_method",
        "state": "verification_state",
    },
}

_FORBIDDEN_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
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

_FORBIDDEN_KEY_TOKENS: Final[tuple[str, ...]] = (
    "ground_truth",
    "fraud_label",
    "is_fraud",
    "scenario_id",
    "ring_id",
    "fraud_ring",
    "truth_label",
    "identifier_raw",
    "raw_identifier",
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
    "ifsc",
    "account_number",
    "narrative",
    "real_data",
    "customer_data",
)

_SENSITIVE_METADATA_KEYS: Final[frozenset[str]] = frozenset(
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
        "file_path",
        "ground_truth",
        "ground_truth_label",
        "id_token",
        "identifier_hash",
        "is_fraud",
        "label",
        "model_artifact_path",
        "model_path",
        "narrative",
        "narrative_raw",
        "narrative_normalized",
        "otp",
        "pan",
        "pass",
        "passwd",
        "password",
        "password_hash",
        "payload_hash",
        "pickle",
        "pin",
        "private_key",
        "raw_payload",
        "refresh_token",
        "ring_id",
        "scenario_id",
        "secret",
        "secret_key",
        "session",
        "source_payload_hash",
        "token",
    }
)

_SENSITIVE_METADATA_TOKENS: Final[tuple[str, ...]] = (
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

_PROVENANCE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype ingestion provenance only. Do not use with real customer data.",
    "Provenance records are operational lineage artefacts only and are not proof of wrongdoing.",
    "Provenance handling must not trigger automatic adverse customer action.",
    "Raw complaint narratives are never stored, logged, signed, or returned.",
    "Complaint narratives may contribute only a salted one-way narrative hash.",
    "Entity raw identifiers are forbidden. Only pseudonymous identifier hashes are accepted.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are rejected or omitted.",
    "Provenance signatures are local HMAC integrity markers, not public-key signatures.",
    "Merkle roots and audit paths are bounded operational integrity aids only.",
    "The bundled ledger is process-local, non-durable, and not distributed.",
    "This module does not persist data or call external systems.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class ProvenanceSourceKind(str, Enum):
    """
    Safe source-kind labels for provenance.
    """

    API = "api"
    SEED = "seed"
    GENERATOR = "generator"
    FILE = "file"
    TEST = "test"
    FIXTURE = "fixture"
    IMPORT = "import"
    UNKNOWN = "unknown"


class ProvenanceDataClassification(str, Enum):
    """
    Safe data-classification labels for provenance.

    MULEGUARD is synthetic-first. Real-data classifications are not accepted by
    default.
    """

    SYNTHETIC = "synthetic"
    DEMO = "demo"
    TEST = "test"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    PUBLIC = "public"


class ProvenanceSeverity(str, Enum):
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


def _clean_text(value: Any, limit: int = _DEFAULT_MAX_STRING_LENGTH) -> str:
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


def _canonical_field_name(key: Any) -> str:
    """
    Convert a field name to a conservative canonical snake_case form.
    """
    text = _normalize_unicode(key).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = _SEPARATOR_RE.sub("_", text)
    text = _MULTI_UNDERSCORE_RE.sub("_", text)
    return text.strip("_").lower()


def _normalize_entity_type(value: Any) -> str:
    """
    Normalize an ingestion entity type.
    """
    text = _canonical_field_name(value)

    aliases = {
        "account": "accounts",
        "txn": "transactions",
        "transaction": "transactions",
        "complaint": "complaints",
        "entity": "entities",
        "entity_link": "entity_links",
        "account_entity_link": "entity_links",
        "account_entity_links": "entity_links",
    }

    return aliases.get(text, text)


def _safe_source_name(value: Any) -> str:
    """
    Return a safe basename-like source label.

    Full paths are never returned.
    """
    text = _normalize_unicode(value).strip()

    if not text:
        return ""

    text = text.replace("\\", "/")
    text = text.rsplit("/", 1)[-1]
    return _clean_text(text, 200)


def _normalize_source_kind(value: Any) -> str:
    """
    Normalize a source-kind-like value.
    """
    text = _canonical_field_name(value)

    aliases = {
        "rest": ProvenanceSourceKind.API.value,
        "http": ProvenanceSourceKind.API.value,
        "https": ProvenanceSourceKind.API.value,
        "seeded": ProvenanceSourceKind.SEED.value,
        "synthetic_generator": ProvenanceSourceKind.GENERATOR.value,
        "generator": ProvenanceSourceKind.GENERATOR.value,
        "local_file": ProvenanceSourceKind.FILE.value,
        "filesystem": ProvenanceSourceKind.FILE.value,
        "unit_test": ProvenanceSourceKind.TEST.value,
        "integration_test": ProvenanceSourceKind.TEST.value,
        "fixture": ProvenanceSourceKind.FIXTURE.value,
        "fixtures": ProvenanceSourceKind.FIXTURE.value,
        "bulk_import": ProvenanceSourceKind.IMPORT.value,
    }

    resolved = aliases.get(text, text)

    try:
        return ProvenanceSourceKind(resolved).value
    except ValueError:
        return ProvenanceSourceKind.UNKNOWN.value


def _normalize_classification(
    value: Any,
    source_kind: str,
    options: "ProvenanceOptions",
) -> tuple[str, bool]:
    """
    Normalize a data classification.

    Returns `(classification, downgraded)`.

    MULEGUARD is synthetic-first. Non-synthetic classifications are downgraded
    unless explicitly allowed by configuration.
    """
    text = _canonical_field_name(value)

    if not text:
        if source_kind in {
            ProvenanceSourceKind.TEST.value,
            ProvenanceSourceKind.FIXTURE.value,
        }:
            return ProvenanceDataClassification.TEST.value, False

        if source_kind == ProvenanceSourceKind.SEED.value:
            return ProvenanceDataClassification.DEMO.value, False

        return ProvenanceDataClassification.SYNTHETIC.value, False

    try:
        classification = ProvenanceDataClassification(text).value
    except ValueError:
        classification = text

    synthetic_like = {
        ProvenanceDataClassification.SYNTHETIC.value,
        ProvenanceDataClassification.DEMO.value,
        ProvenanceDataClassification.TEST.value,
    }

    if classification in synthetic_like:
        return classification, False

    if options.allow_non_synthetic_classification and classification in {
        ProvenanceDataClassification.INTERNAL.value,
        ProvenanceDataClassification.RESTRICTED.value,
        ProvenanceDataClassification.PUBLIC.value,
    }:
        return classification, False

    return ProvenanceDataClassification.SYNTHETIC.value, True


def _is_forbidden_key(canonical: str, target: str, entity_type: str) -> bool:
    """
    Return True when a top-level record key is forbidden.

    Complaint `narrative_raw` is intentionally allowed for controlled synthetic
    complaint ingestion. Other raw fields are forbidden.
    """
    if entity_type == "complaints" and (
        canonical == "narrative_raw" or target == "narrative_raw"
    ):
        return False

    if canonical in _FORBIDDEN_TOP_LEVEL_KEYS or target in _FORBIDDEN_TOP_LEVEL_KEYS:
        return True

    if canonical.startswith("raw_") or target.startswith("raw_"):
        return True

    if (canonical.endswith("_raw") and canonical != "narrative_raw") or (
        target.endswith("_raw") and target != "narrative_raw"
    ):
        return True

    for token in _FORBIDDEN_KEY_TOKENS:
        if token in canonical or token in target:
            return True

    return False


def _is_sensitive_key(key: Any) -> bool:
    """
    Return True when a metadata or detail key appears sensitive.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _SENSITIVE_METADATA_KEYS:
        return True

    return any(token in canonical for token in _SENSITIVE_METADATA_TOKENS)


def _is_placeholder_secret(value: str) -> bool:
    """
    Return True when a value looks like a placeholder secret.
    """
    if not value:
        return True

    lowered = value.strip().lower()

    if not lowered:
        return True

    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _ensure_salt(salt: Any) -> str:
    """
    Ensure the provenance salt is non-empty, sufficiently long, and not an
    obvious placeholder.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text or _is_placeholder_secret(text):
        text = "muleguard-ingestion-provenance-default-salt"

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _decimal_to_canonical(value: Decimal) -> str:
    """
    Return a stable canonical decimal string.
    """
    if not value.is_finite():
        return "non_finite"

    text = format(value, "f")

    if "." in text:
        text = text.rstrip("0").rstrip(".")

    return text or "0"


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


def _canonical_scalar(value: Any, limit: int = 1024) -> str:
    """
    Convert a field value into a stable canonical string for hashing.

    This is used only as input to one-way hashing. It is not returned directly
    in public summaries.
    """
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, int):
        return str(value)

    if isinstance(value, float):
        if not math.isfinite(value):
            return "non_finite"

        return _decimal_to_canonical(Decimal(str(value)))

    if isinstance(value, Decimal):
        return _decimal_to_canonical(value)

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else "invalid_datetime"

    if isinstance(value, str):
        return _clean_text(value, limit)

    if isinstance(value, Enum):
        return _canonical_scalar(value.value, limit)

    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)

        if len(raw) > 256:
            return f"<binary:{len(raw)} bytes>"

        return raw.hex()

    if isinstance(value, Mapping):
        try:
            return _clean_text(_canonical_json(value), limit)
        except Exception:
            return _clean_text(str(value), limit)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        try:
            return _clean_text(_canonical_json(list(value)), limit)
        except Exception:
            return _clean_text(str(value), limit)

    return _clean_text(str(value), limit)


def _json_default(value: Any) -> Any:
    """
    JSON serializer fallback for canonicalization.
    """
    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)

        if len(raw) > 256:
            return f"<binary:{len(raw)} bytes>"

        return raw.hex()

    return str(value)


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


def _canonical_for_hash(value: Any) -> str:
    """
    Return a canonical string for hashing.
    """
    if isinstance(value, Mapping):
        return _canonical_json(value)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return _canonical_json(list(value))

    return _canonical_scalar(value)


def _hmac_hex(salt: str, domain: str, message: str) -> str:
    """
    Return a domain-separated HMAC-SHA256 hex digest.
    """
    key = salt.encode("utf-8", errors="replace")
    payload = f"{domain}\x00{message}".encode("utf-8", errors="replace")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _hash_value(value: Any, salt: str, domain: str) -> str:
    """
    Return a salted, domain-separated one-way hash for a value.
    """
    return _hmac_hex(salt, domain, _canonical_for_hash(value))


def _merkle_parent(left: str, right: str) -> str:
    """
    Return a deterministic Merkle parent hash.

    Merkle internals use unsalted SHA-256 because leaves are already salted
    record fingerprints.
    """
    payload = f"{left}\x00{right}".encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


def _merkle_root(leaves: Sequence[str]) -> Optional[str]:
    """
    Compute a bounded Merkle root from leaf hashes.
    """
    if not leaves:
        return None

    current = list(leaves)

    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])

        current = [
            _merkle_parent(current[index], current[index + 1])
            for index in range(0, len(current), 2)
        ]

    return current[0]


def _merkle_layers(leaves: Sequence[str]) -> list[list[str]]:
    """
    Compute Merkle layers for audit path generation.
    """
    if not leaves:
        return []

    layers: list[list[str]] = [list(leaves)]
    current = list(leaves)

    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])

        current = [
            _merkle_parent(current[index], current[index + 1])
            for index in range(0, len(current), 2)
        ]
        layers.append(current)

    return layers


def _constant_time_equals(left: Optional[str], right: Optional[str]) -> bool:
    """
    Constant-time string comparison for hashes and signatures.
    """
    if left is None or right is None:
        return False

    try:
        return hmac.compare_digest(
            str(left).encode("utf-8", errors="replace"),
            str(right).encode("utf-8", errors="replace"),
        )
    except Exception:
        return False


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
        return str(value)

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, Enum):
        return _safe_detail_value(value.value, depth + 1)

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:20]:
            key = _clean_text(raw_key, 100)

            if not key or _is_sensitive_key(key):
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:20]]

    return f"<{type(value).__name__}>"


def _safe_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return safe issue details.

    Details must never contain raw narratives, secrets, tokens, passwords,
    database URLs, model artifact paths, or sensitive identifiers.
    """
    if not details:
        return {}

    sanitized = _safe_detail_value(details)

    if isinstance(sanitized, dict):
        return sanitized

    if sanitized is None:
        return {}

    return {"value": sanitized}


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProvenanceOptions:
    """
    Bounded ingestion provenance policy.

    Hard caps prevent client-controlled or configuration-controlled unbounded
    provenance surfaces.
    """

    enabled: bool = True
    schema_version: str = PROVENANCE_SCHEMA_VERSION
    salt: str = ""

    max_records: int = _DEFAULT_MAX_RECORDS
    max_issues_returned: int = _DEFAULT_MAX_ISSUES_RETURNED
    max_string_length: int = _DEFAULT_MAX_STRING_LENGTH
    max_metadata_depth: int = _DEFAULT_MAX_METADATA_DEPTH
    max_list_length: int = _DEFAULT_MAX_LIST_LENGTH
    max_mapping_keys: int = _DEFAULT_MAX_MAPPING_KEYS

    include_record_hashes: bool = True
    include_merkle_root: bool = True
    include_chain: bool = True
    sign_provenance: bool = True

    drop_unknown_fields: bool = True
    allow_non_synthetic_classification: bool = False

    ledger_max_entries: int = _DEFAULT_LEDGER_MAX_ENTRIES
    retention_seconds: float = _DEFAULT_RETENTION_SECONDS
    prune_interval_seconds: float = _DEFAULT_PRUNE_INTERVAL_SECONDS

    public_include_signature: bool = False

    def __post_init__(self) -> None:
        """
        Normalize and clamp option values.
        """
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "salt", _ensure_salt(self.salt))

        object.__setattr__(
            self,
            "schema_version",
            _clean_text(self.schema_version, 32) or PROVENANCE_SCHEMA_VERSION,
        )

        object.__setattr__(
            self,
            "max_records",
            _clamp_int(
                self.max_records,
                1,
                _HARD_MAX_RECORDS,
                _DEFAULT_MAX_RECORDS,
            ),
        )

        object.__setattr__(
            self,
            "max_issues_returned",
            _clamp_int(
                self.max_issues_returned,
                1,
                _HARD_MAX_ISSUES_RETURNED,
                _DEFAULT_MAX_ISSUES_RETURNED,
            ),
        )

        object.__setattr__(
            self,
            "max_string_length",
            _clamp_int(
                self.max_string_length,
                1,
                _HARD_MAX_STRING_LENGTH,
                _DEFAULT_MAX_STRING_LENGTH,
            ),
        )

        object.__setattr__(
            self,
            "max_metadata_depth",
            _clamp_int(
                self.max_metadata_depth,
                1,
                _HARD_MAX_METADATA_DEPTH,
                _DEFAULT_MAX_METADATA_DEPTH,
            ),
        )

        object.__setattr__(
            self,
            "max_list_length",
            _clamp_int(
                self.max_list_length,
                1,
                _HARD_MAX_LIST_LENGTH,
                _DEFAULT_MAX_LIST_LENGTH,
            ),
        )

        object.__setattr__(
            self,
            "max_mapping_keys",
            _clamp_int(
                self.max_mapping_keys,
                1,
                _HARD_MAX_MAPPING_KEYS,
                _DEFAULT_MAX_MAPPING_KEYS,
            ),
        )

        object.__setattr__(
            self,
            "include_record_hashes",
            _as_bool(self.include_record_hashes, True),
        )
        object.__setattr__(
            self,
            "include_merkle_root",
            _as_bool(self.include_merkle_root, True),
        )
        object.__setattr__(self, "include_chain", _as_bool(self.include_chain, True))
        object.__setattr__(self, "sign_provenance", _as_bool(self.sign_provenance, True))
        object.__setattr__(
            self,
            "drop_unknown_fields",
            _as_bool(self.drop_unknown_fields, True),
        )
        object.__setattr__(
            self,
            "allow_non_synthetic_classification",
            _as_bool(self.allow_non_synthetic_classification, False),
        )

        object.__setattr__(
            self,
            "ledger_max_entries",
            _clamp_int(
                self.ledger_max_entries,
                1,
                _HARD_LEDGER_MAX_ENTRIES,
                _DEFAULT_LEDGER_MAX_ENTRIES,
            ),
        )

        object.__setattr__(
            self,
            "retention_seconds",
            max(0.0, _as_float(self.retention_seconds, _DEFAULT_RETENTION_SECONDS)),
        )

        object.__setattr__(
            self,
            "prune_interval_seconds",
            max(
                1.0,
                _as_float(self.prune_interval_seconds, _DEFAULT_PRUNE_INTERVAL_SECONDS),
            ),
        )

        object.__setattr__(
            self,
            "public_include_signature",
            _as_bool(self.public_include_signature, False),
        )

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ProvenanceOptions":
        """
        Build provenance options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "PROVENANCE_SALT", None)
            or _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
            or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
            or _setting(settings, "BACKEND_SECRET_KEY", None)
            or ""
        )

        hard_max_records = _clamp_int(
            _setting(settings, "PROVENANCE_HARD_MAX_RECORDS", _HARD_MAX_RECORDS),
            1,
            _HARD_MAX_RECORDS,
            _HARD_MAX_RECORDS,
        )

        max_records = _clamp_int(
            _setting(settings, "PROVENANCE_MAX_RECORDS", _DEFAULT_MAX_RECORDS),
            1,
            hard_max_records,
            _DEFAULT_MAX_RECORDS,
        )

        hard_max_issues = _clamp_int(
            _setting(
                settings,
                "PROVENANCE_HARD_MAX_ISSUES_RETURNED",
                _HARD_MAX_ISSUES_RETURNED,
            ),
            1,
            _HARD_MAX_ISSUES_RETURNED,
            _HARD_MAX_ISSUES_RETURNED,
        )

        max_issues = _clamp_int(
            _setting(
                settings,
                "PROVENANCE_MAX_ISSUES_RETURNED",
                _DEFAULT_MAX_ISSUES_RETURNED,
            ),
            1,
            hard_max_issues,
            _DEFAULT_MAX_ISSUES_RETURNED,
        )

        hard_max_ledger = _clamp_int(
            _setting(settings, "PROVENANCE_HARD_LEDGER_MAX_ENTRIES", _HARD_LEDGER_MAX_ENTRIES),
            1,
            _HARD_LEDGER_MAX_ENTRIES,
            _HARD_LEDGER_MAX_ENTRIES,
        )

        ledger_max_entries = _clamp_int(
            _setting(settings, "PROVENANCE_LEDGER_MAX_ENTRIES", _DEFAULT_LEDGER_MAX_ENTRIES),
            1,
            hard_max_ledger,
            _DEFAULT_LEDGER_MAX_ENTRIES,
        )

        return cls(
            enabled=_as_bool(_setting(settings, "PROVENANCE_ENABLED", True), True),
            schema_version=str(
                _setting(settings, "PROVENANCE_SCHEMA_VERSION", PROVENANCE_SCHEMA_VERSION)
            ),
            salt=salt,
            max_records=max_records,
            max_issues_returned=max_issues,
            max_string_length=_clamp_int(
                _setting(settings, "PROVENANCE_MAX_STRING_LENGTH", _DEFAULT_MAX_STRING_LENGTH),
                1,
                _HARD_MAX_STRING_LENGTH,
                _DEFAULT_MAX_STRING_LENGTH,
            ),
            max_metadata_depth=_clamp_int(
                _setting(settings, "PROVENANCE_MAX_METADATA_DEPTH", _DEFAULT_MAX_METADATA_DEPTH),
                1,
                _HARD_MAX_METADATA_DEPTH,
                _DEFAULT_MAX_METADATA_DEPTH,
            ),
            max_list_length=_clamp_int(
                _setting(settings, "PROVENANCE_MAX_LIST_LENGTH", _DEFAULT_MAX_LIST_LENGTH),
                1,
                _HARD_MAX_LIST_LENGTH,
                _DEFAULT_MAX_LIST_LENGTH,
            ),
            max_mapping_keys=_clamp_int(
                _setting(settings, "PROVENANCE_MAX_MAPPING_KEYS", _DEFAULT_MAX_MAPPING_KEYS),
                1,
                _HARD_MAX_MAPPING_KEYS,
                _DEFAULT_MAX_MAPPING_KEYS,
            ),
            include_record_hashes=_as_bool(
                _setting(settings, "PROVENANCE_INCLUDE_RECORD_HASHES", True),
                True,
            ),
            include_merkle_root=_as_bool(
                _setting(settings, "PROVENANCE_INCLUDE_MERKLE_ROOT", True),
                True,
            ),
            include_chain=_as_bool(_setting(settings, "PROVENANCE_INCLUDE_CHAIN", True), True),
            sign_provenance=_as_bool(_setting(settings, "PROVENANCE_SIGN", True), True),
            drop_unknown_fields=_as_bool(
                _setting(settings, "PROVENANCE_DROP_UNKNOWN_FIELDS", True),
                True,
            ),
            allow_non_synthetic_classification=_as_bool(
                _setting(settings, "PROVENANCE_ALLOW_NON_SYNTHETIC_CLASSIFICATION", False),
                False,
            ),
            ledger_max_entries=ledger_max_entries,
            retention_seconds=_as_float(
                _setting(settings, "PROVENANCE_RETENTION_SECONDS", _DEFAULT_RETENTION_SECONDS),
                _DEFAULT_RETENTION_SECONDS,
            ),
            prune_interval_seconds=_as_float(
                _setting(
                    settings,
                    "PROVENANCE_PRUNE_INTERVAL_SECONDS",
                    _DEFAULT_PRUNE_INTERVAL_SECONDS,
                ),
                _DEFAULT_PRUNE_INTERVAL_SECONDS,
            ),
            public_include_signature=_as_bool(
                _setting(settings, "PROVENANCE_PUBLIC_INCLUDE_SIGNATURE", False),
                False,
            ),
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable summary of provenance options.

        The salt is never included.
        """
        return {
            "enabled": self.enabled,
            "schema_version": self.schema_version,
            "max_records": self.max_records,
            "max_issues_returned": self.max_issues_returned,
            "max_string_length": self.max_string_length,
            "max_metadata_depth": self.max_metadata_depth,
            "max_list_length": self.max_list_length,
            "max_mapping_keys": self.max_mapping_keys,
            "include_record_hashes": self.include_record_hashes,
            "include_merkle_root": self.include_merkle_root,
            "include_chain": self.include_chain,
            "sign_provenance": self.sign_provenance,
            "drop_unknown_fields": self.drop_unknown_fields,
            "allow_non_synthetic_classification": self.allow_non_synthetic_classification,
            "ledger_max_entries": self.ledger_max_entries,
            "retention_seconds": round(self.retention_seconds, 3),
            "prune_interval_seconds": round(self.prune_interval_seconds, 3),
            "public_include_signature": self.public_include_signature,
            "salt_configured": bool(self.salt and not _is_placeholder_secret(self.salt)),
        }


# -----------------------------------------------------------------------------
# Issue, record, audit models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class ProvenanceIssue:
    """
    Safe provenance issue.

    Issues never contain raw narratives, secrets, tokens, passwords, database
    URLs, model artifact paths, or sensitive identifiers.
    """

    severity: ProvenanceSeverity
    code: str
    message: str
    entity_type: str = ""
    index: Optional[int] = None
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

        if self.entity_type:
            payload["entity_type"] = _clean_text(self.entity_type, 100)

        if self.index is not None:
            payload["index"] = int(self.index)

        if self.field:
            payload["field"] = _clean_text(self.field, 200)

        if self.details:
            payload["details"] = self.details

        return payload


@dataclass(slots=True)
class ProvenanceRecord:
    """
    Safe per-record provenance.

    This contains one-way hashes only. It never contains raw record content.
    """

    index: int
    record_id: Optional[str] = None
    record_hash: Optional[str] = None
    leaf_index: Optional[int] = None
    fields_hashed: tuple[str, ...] = ()
    narrative_hash: Optional[str] = None
    metadata_hash: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable record provenance mapping.
        """
        payload: dict[str, Any] = {
            "index": int(self.index),
        }

        if self.record_id:
            payload["record_id"] = _clean_text(self.record_id, 200)

        if self.record_hash:
            payload["record_hash"] = self.record_hash

        if self.leaf_index is not None:
            payload["leaf_index"] = int(self.leaf_index)

        if self.fields_hashed:
            payload["fields_hashed"] = list(self.fields_hashed)

        if self.narrative_hash:
            payload["narrative_hash"] = self.narrative_hash

        if self.metadata_hash:
            payload["metadata_hash"] = self.metadata_hash

        return payload


@dataclass(frozen=True, slots=True)
class ProvenanceAuditStep:
    """
    One Merkle audit path step.
    """

    hash: str
    side: str

    def to_dict(self) -> dict[str, str]:
        """
        Return a JSON-serializable step mapping.
        """
        return {
            "hash": self.hash,
            "side": self.side,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceAuditPath:
    """
    Safe Merkle audit path for one record leaf.
    """

    batch_id: str
    entity_type: str
    leaf_index: int
    record_index: int
    leaf_hash: str
    root_hash: str
    algorithm: str = "sha256-merkle-v1"
    steps: tuple[ProvenanceAuditStep, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable audit path mapping.
        """
        return {
            "batch_id": self.batch_id,
            "entity_type": self.entity_type,
            "leaf_index": int(self.leaf_index),
            "record_index": int(self.record_index),
            "leaf_hash": self.leaf_hash,
            "root_hash": self.root_hash,
            "algorithm": self.algorithm,
            "steps": [step.to_dict() for step in self.steps],
        }


# -----------------------------------------------------------------------------
# Batch provenance model
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class ProvenanceBatch:
    """
    Safe ingestion batch provenance envelope.

    The internal `records` list contains one-way record hashes only. Public
    summaries exclude record content entirely.
    """

    version: str = PROVENANCE_VERSION
    batch_id: str = ""
    entity_type: str = ""

    source_system: str = "api"
    source_kind: str = ProvenanceSourceKind.API.value
    source_name: Optional[str] = None
    content_type: Optional[str] = None
    data_classification: str = ProvenanceDataClassification.SYNTHETIC.value

    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    actor_hash: Optional[str] = None

    requested_at: Optional[datetime] = None
    generated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    record_count: int = 0
    valid_record_count: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    duplicated_count: int = 0
    skipped_count: int = 0

    truncated: bool = False
    partial: bool = False
    ok: bool = True

    source_checksum: Optional[str] = None
    merkle_root: Optional[str] = None

    previous_chain_hash: Optional[str] = None
    chain_hash: Optional[str] = None
    chain_seq: Optional[int] = None
    signature: Optional[str] = None

    records: list[ProvenanceRecord] = dataclass_field(default_factory=list)
    issues: list[ProvenanceIssue] = dataclass_field(default_factory=list)
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)
    caveats: list[str] = dataclass_field(default_factory=list)

    max_issues: int = _DEFAULT_MAX_ISSUES_RETURNED

    _issue_count: int = dataclass_field(default=0, repr=False, compare=False)
    _issue_truncated: bool = dataclass_field(default=False, repr=False, compare=False)

    # ------------------------------------------------------------------
    # Issue helpers
    # ------------------------------------------------------------------

    def add_issue(
        self,
        *,
        severity: ProvenanceSeverity,
        code: str,
        message: str,
        index: Optional[int] = None,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe issue entry.

        Returns False when the bounded issue list is already truncated.
        """
        if self._issue_truncated:
            if severity == ProvenanceSeverity.ERROR:
                self.ok = False
            return False

        if len(self.issues) >= max(1, int(self.max_issues)):
            self._issue_truncated = True
            self.issues.append(
                ProvenanceIssue(
                    severity=ProvenanceSeverity.WARNING,
                    code="issue_list_truncated",
                    message="Issue list truncated by configured limit.",
                    entity_type=self.entity_type,
                )
            )

            if severity == ProvenanceSeverity.ERROR:
                self.ok = False

            return False

        self.issues.append(
            ProvenanceIssue(
                severity=severity,
                code=_clean_text(code, 100),
                message=_clean_text(message, 300),
                entity_type=_clean_text(self.entity_type, 100),
                index=int(index) if index is not None else None,
                field=_clean_text(field, 200) if field else None,
                details=_safe_details(details),
            )
        )

        self._issue_count += 1

        if severity == ProvenanceSeverity.ERROR:
            self.ok = False

        return True

    # ------------------------------------------------------------------
    # Finalization
    # ------------------------------------------------------------------

    def finalize(self, options: Optional[ProvenanceOptions] = None) -> None:
        """
        Finalize safe metadata and timestamps.
        """
        now = _now_utc()

        if self.requested_at is None:
            self.requested_at = now

        if self.generated_at is None:
            self.generated_at = now

        if self.completed_at is None:
            self.completed_at = now

        if not self.caveats:
            self.caveats = list(_PROVENANCE_CAVEATS)

        self.valid_record_count = len(
            [record for record in self.records if record.record_hash]
        )

        self.metadata.update(
            {
                "provenance_version": self.version,
                "schema_version": options.schema_version if options else PROVENANCE_SCHEMA_VERSION,
                "record_count": self.record_count,
                "valid_record_count": self.valid_record_count,
                "merkle_algorithm": "sha256-merkle-v1" if self.merkle_root else None,
                "signature_algorithm": "hmac-sha256-v1" if self.signature else None,
                "chain_algorithm": "hmac-sha256-chain-v1" if self.chain_hash else None,
                "partial": self.partial,
                "truncated": self.truncated,
                "issue_count": self._issue_count,
                "issue_truncated": self._issue_truncated,
            }
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_public_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately excludes record content, raw narratives, raw
        identifiers, and sensitive metadata.
        """
        integrity: dict[str, Any] = {
            "source_checksum": self.source_checksum,
            "merkle_root": self.merkle_root,
            "previous_chain_hash": self.previous_chain_hash,
            "chain_hash": self.chain_hash,
            "chain_seq": self.chain_seq,
        }

        if self.signature:
            integrity["signature_algorithm"] = "hmac-sha256-v1"

        return {
            "ok": self.ok,
            "version": self.version,
            "batch_id": self.batch_id,
            "entity_type": self.entity_type,
            "source": {
                "system": self.source_system,
                "kind": self.source_kind,
                "name": self.source_name,
                "content_type": self.content_type,
                "classification": self.data_classification,
            },
            "context": {
                "request_id": self.request_id,
                "correlation_id": self.correlation_id,
            },
            "timing": {
                "requested_at": self.requested_at.isoformat() if self.requested_at else None,
                "generated_at": self.generated_at.isoformat() if self.generated_at else None,
                "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            },
            "counts": {
                "record_count": self.record_count,
                "valid_record_count": self.valid_record_count,
                "accepted_count": self.accepted_count,
                "rejected_count": self.rejected_count,
                "duplicated_count": self.duplicated_count,
                "skipped_count": self.skipped_count,
            },
            "integrity": integrity,
            "partial": self.partial,
            "truncated": self.truncated,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "caveats": list(self.caveats or _PROVENANCE_CAVEATS),
        }

    def to_internal_dict(self, *, include_records: bool = True) -> dict[str, Any]:
        """
        Return a fuller internal representation for tests and tooling.

        Even this representation contains only one-way hashes, not raw record
        content.
        """
        payload = self.to_public_dict()

        if include_records:
            payload["records"] = [record.to_dict() for record in self.records]
        else:
            payload["records_omitted"] = True

        if self.signature:
            payload["integrity"]["signature"] = self.signature

        return payload


# -----------------------------------------------------------------------------
# Metadata sanitization
# -----------------------------------------------------------------------------


def _sanitize_metadata_value(
    value: Any,
    options: ProvenanceOptions,
    issues: Optional[ProvenanceBatch],
    index: int,
    path: str,
    depth: int = 0,
) -> Any:
    """
    Recursively sanitize metadata into a bounded, safe structure.
    """
    if depth > options.max_metadata_depth:
        if issues is not None:
            issues.add_issue(
                severity=ProvenanceSeverity.WARNING,
                code="metadata_too_deep",
                message="Metadata depth exceeded configured limit.",
                index=index,
                field=path,
            )
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
        return _clean_text(value, options.max_string_length)

    if isinstance(value, Decimal):
        return str(value) if value.is_finite() else None

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, Enum):
        return _sanitize_metadata_value(
            value.value,
            options,
            issues,
            index,
            path,
            depth + 1,
        )

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        if len(value) > options.max_mapping_keys and issues is not None:
            issues.add_issue(
                severity=ProvenanceSeverity.WARNING,
                code="metadata_too_many_keys",
                message="Metadata key count exceeded configured limit.",
                index=index,
                field=path,
                details={"max_mapping_keys": options.max_mapping_keys},
            )

        out: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[: options.max_mapping_keys]:
            key = _canonical_field_name(raw_key)

            if not key:
                continue

            if _is_sensitive_key(key):
                if issues is not None:
                    issues.add_issue(
                        severity=ProvenanceSeverity.WARNING,
                        code="metadata_sensitive_key_dropped",
                        message="Sensitive metadata key omitted.",
                        index=index,
                        field=f"{path}.{key}" if path else key,
                    )
                continue

            child_path = f"{path}.{key}" if path else key
            out[key] = _sanitize_metadata_value(
                raw_value,
                options,
                issues,
                index,
                child_path,
                depth + 1,
            )

        return dict(sorted(out.items()))

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > options.max_list_length and issues is not None:
            issues.add_issue(
                severity=ProvenanceSeverity.WARNING,
                code="metadata_too_many_items",
                message="Metadata item count exceeded configured limit.",
                index=index,
                field=path,
                details={"max_list_length": options.max_list_length},
            )

        limited = list(value)[: options.max_list_length]
        return [
            _sanitize_metadata_value(
                item,
                options,
                issues,
                index,
                f"{path}[{position}]",
                depth + 1,
            )
            for position, item in enumerate(limited)
        ]

    if isinstance(value, (set, frozenset)):
        limited = list(value)[: options.max_list_length]
        sanitized = [
            _sanitize_metadata_value(
                item,
                options,
                issues,
                index,
                f"{path}[]",
                depth + 1,
            )
            for item in limited
        ]

        try:
            return sorted(sanitized, key=lambda item: str(item))
        except Exception:
            return sanitized

    if issues is not None:
        issues.add_issue(
            severity=ProvenanceSeverity.WARNING,
            code="unsupported_metadata_value",
            message="Unsupported metadata value omitted.",
            index=index,
            field=path,
            details={"type": type(value).__name__},
        )

    return None


# -----------------------------------------------------------------------------
# Record sanitization and hashing
# -----------------------------------------------------------------------------


def _sanitize_record_for_provenance(
    entity_type: str,
    record: Any,
    options: ProvenanceOptions,
    issues: Optional[ProvenanceBatch] = None,
    index: int = 0,
) -> Optional[tuple[Optional[str], Optional[str], Optional[str], tuple[str, ...], Optional[str]]]:
    """
    Sanitize one record and compute safe one-way hashes.

    Returns:
        `(record_hash, narrative_hash, metadata_hash, fields_hashed, record_id)`
        or None when the record is unusable.

    This never retains raw narrative text. Complaint narratives are represented
    only by a salted one-way narrative hash.
    """
    if not isinstance(record, Mapping):
        if issues is not None:
            issues.add_issue(
                severity=ProvenanceSeverity.ERROR,
                code="record_not_object",
                message="Record must be a mapping.",
                index=index,
            )
        return None

    allowed = _ALLOWED_FIELDS.get(entity_type)
    aliases = _FIELD_ALIASES.get(entity_type, {})

    safe: dict[str, str] = {}
    fields: list[str] = []
    narrative_hash: Optional[str] = None
    metadata_hash: Optional[str] = None

    for raw_key, raw_value in record.items():
        key_text = _clean_text(raw_key, 200)
        canonical = _canonical_field_name(key_text)

        if not canonical:
            if issues is not None:
                issues.add_issue(
                    severity=ProvenanceSeverity.WARNING,
                    code="invalid_field_name",
                    message="Field name could not be canonicalized and was omitted.",
                    index=index,
                    field=key_text or None,
                )
            continue

        target = aliases.get(canonical, canonical)

        if _is_forbidden_key(canonical, target, entity_type):
            if issues is not None:
                issues.add_issue(
                    severity=ProvenanceSeverity.ERROR,
                    code="forbidden_field",
                    message="Forbidden field omitted from provenance.",
                    index=index,
                    field=key_text,
                )
            continue

        if allowed is not None and target not in allowed:
            if options.drop_unknown_fields:
                if issues is not None:
                    issues.add_issue(
                        severity=ProvenanceSeverity.WARNING,
                        code="unknown_field_dropped",
                        message="Unknown field omitted from provenance.",
                        index=index,
                        field=key_text,
                    )
                continue

            target = canonical

        if target in safe:
            if issues is not None:
                issues.add_issue(
                    severity=ProvenanceSeverity.WARNING,
                    code="duplicate_field_alias",
                    message="Duplicate field alias omitted from provenance.",
                    index=index,
                    field=key_text,
                )
            continue

        if target == "narrative_raw":
            if raw_value is None:
                continue

            narrative_hash = _hash_value(raw_value, options.salt, _DOMAIN_NARRATIVE)
            safe["narrative_hash"] = narrative_hash
            fields.append("narrative_raw")
            continue

        if target == "metadata_json":
            sanitized_metadata = _sanitize_metadata_value(
                raw_value,
                options,
                issues,
                index,
                "metadata_json",
                depth=0,
            )

            if sanitized_metadata not in (None, {}, [], ()):
                metadata_hash = _hash_value(
                    sanitized_metadata,
                    options.salt,
                    _DOMAIN_METADATA,
                )
                safe["metadata_hash"] = metadata_hash
                fields.append("metadata_json")

            continue

        safe[target] = _canonical_scalar(raw_value, options.max_string_length)
        fields.append(target)

    payload = {
        "__entity_type": entity_type,
        "__schema_version": options.schema_version,
        **safe,
    }

    record_hash = _hash_value(payload, options.salt, _DOMAIN_RECORD)
    record_id = safe.get("id")

    return record_hash, narrative_hash, metadata_hash, tuple(sorted(set(fields))), record_id


# -----------------------------------------------------------------------------
# Extraction helpers
# -----------------------------------------------------------------------------


def _extract_records(source: Any) -> list[Any]:
    """
    Extract a bounded list of records from a flexible source.
    """
    if source is None:
        return []

    if hasattr(source, "records"):
        source = getattr(source, "records")

    if isinstance(source, Mapping):
        if "records" in source:
            source = source["records"]
        elif "items" in source:
            source = source["items"]
        else:
            return [source]

    if isinstance(source, Sequence) and not isinstance(source, (str, bytes, bytearray)):
        return list(source)

    if isinstance(source, Iterable) and not isinstance(source, (str, bytes, bytearray)):
        try:
            return list(source)
        except Exception:
            return [source]

    return [source]


def _extract_counts(counts: Any) -> dict[str, int]:
    """
    Extract safe integer counts from a flexible counts source.
    """
    if counts is None:
        return {}

    if hasattr(counts, "counts"):
        counts = getattr(counts, "counts")

    if isinstance(counts, Mapping):
        return {
            str(key): _as_int(value, 0)
            for key, value in counts.items()
        }

    return {}


# -----------------------------------------------------------------------------
# Signing
# -----------------------------------------------------------------------------


def _batch_signing_payload(batch: ProvenanceBatch) -> str:
    """
    Return canonical signing payload for a batch.

    The payload commits to batch identity, counts, integrity roots, and chain
    state. It does not include raw record content.
    """
    payload = {
        "version": batch.version,
        "batch_id": batch.batch_id,
        "entity_type": batch.entity_type,
        "source_system": batch.source_system,
        "source_kind": batch.source_kind,
        "source_name": batch.source_name,
        "content_type": batch.content_type,
        "data_classification": batch.data_classification,
        "request_id": batch.request_id,
        "correlation_id": batch.correlation_id,
        "actor_hash": batch.actor_hash,
        "requested_at": batch.requested_at.isoformat() if batch.requested_at else None,
        "generated_at": batch.generated_at.isoformat() if batch.generated_at else None,
        "completed_at": batch.completed_at.isoformat() if batch.completed_at else None,
        "record_count": batch.record_count,
        "valid_record_count": batch.valid_record_count,
        "accepted_count": batch.accepted_count,
        "rejected_count": batch.rejected_count,
        "duplicated_count": batch.duplicated_count,
        "skipped_count": batch.skipped_count,
        "partial": batch.partial,
        "truncated": batch.truncated,
        "source_checksum": batch.source_checksum,
        "merkle_root": batch.merkle_root,
        "previous_chain_hash": batch.previous_chain_hash,
        "chain_hash": batch.chain_hash,
        "chain_seq": batch.chain_seq,
    }

    return _canonical_json(payload)


def sign_batch(
    batch: ProvenanceBatch,
    options: ProvenanceOptions | None = None,
) -> ProvenanceBatch:
    """
    Sign a batch provenance envelope using keyed HMAC integrity.

    This is a local prototype integrity marker, not a public-key signature.
    """
    opts = options or ProvenanceOptions.from_settings()
    batch.signature = _hmac_hex(
        opts.salt,
        _DOMAIN_SIGNATURE,
        _batch_signing_payload(batch),
    )
    return batch


def verify_batch_signature(
    batch: ProvenanceBatch,
    options: ProvenanceOptions | None = None,
) -> bool:
    """
    Verify a batch HMAC signature.
    """
    if not batch.signature:
        return False

    opts = options or ProvenanceOptions.from_settings()
    expected = _hmac_hex(
        opts.salt,
        _DOMAIN_SIGNATURE,
        _batch_signing_payload(batch),
    )

    return _constant_time_equals(expected, batch.signature)


# -----------------------------------------------------------------------------
# Ledger
# -----------------------------------------------------------------------------


class ProvenanceLedger:
    """
    Bounded, thread-safe, process-local hash-chained provenance ledger.

    This ledger is intended for local prototype, demo, test, and CI use. It is
    not durable and is not shared across processes or hosts.
    """

    def __init__(self, options: ProvenanceOptions | None = None) -> None:
        self.options = options or ProvenanceOptions.from_settings()

        self._lock = threading.RLock()
        self._entries: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._seq = 0
        self._last_chain_hash = _GENESIS_HASH
        self._last_prune = time.monotonic()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_chain_hash(
        self,
        batch: ProvenanceBatch,
        previous_chain_hash: str,
        seq: int,
        salt: str,
    ) -> str:
        """
        Compute a chained hash for one batch.
        """
        payload = [
            previous_chain_hash or _GENESIS_HASH,
            batch.merkle_root or "",
            batch.batch_id or "",
            str(int(seq)),
            batch.entity_type or "",
            batch.source_system or "",
        ]

        return _hash_value(payload, salt, _DOMAIN_CHAIN)

    def _prune(self, force: bool = False) -> None:
        """
        Prune expired and over-capacity ledger entries.
        """
        now_monotonic = time.monotonic()

        if (
            not force
            and now_monotonic - self._last_prune < float(self.options.prune_interval_seconds)
        ):
            return

        self._last_prune = now_monotonic
        now = _now_utc()
        retention = float(self.options.retention_seconds)

        expired: list[str] = []

        for batch_id, entry in self._entries.items():
            created_at = entry.get("created_at")

            if not isinstance(created_at, datetime):
                continue

            if retention > 0 and (now - created_at).total_seconds() > retention:
                expired.append(batch_id)

        for batch_id in expired:
            self._entries.pop(batch_id, None)

        while len(self._entries) > int(self.options.ledger_max_entries):
            self._entries.popitem(last=False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, batch: ProvenanceBatch) -> ProvenanceBatch:
        """
        Append one batch to the ledger and update chain metadata.
        """
        with self._lock:
            self._prune()

            self._seq += 1
            seq = self._seq
            previous = self._last_chain_hash

            chain_hash = self._compute_chain_hash(
                batch,
                previous,
                seq,
                self.options.salt,
            )

            batch.previous_chain_hash = previous
            batch.chain_seq = seq
            batch.chain_hash = chain_hash

            self._entries[batch.batch_id] = {
                "batch_id": batch.batch_id,
                "entity_type": batch.entity_type,
                "merkle_root": batch.merkle_root,
                "previous_chain_hash": previous,
                "chain_hash": chain_hash,
                "chain_seq": seq,
                "created_at": _now_utc(),
            }

            self._entries.move_to_end(batch.batch_id)
            self._last_chain_hash = chain_hash

            return batch

    def verify(self, batch: ProvenanceBatch, options: ProvenanceOptions | None = None) -> bool:
        """
        Verify a batch chain hash.
        """
        if not batch.chain_hash:
            return False

        opts = options or self.options
        expected = self._compute_chain_hash(
            batch,
            batch.previous_chain_hash or _GENESIS_HASH,
            int(batch.chain_seq or 0),
            opts.salt,
        )

        return _constant_time_equals(expected, batch.chain_hash)

    def clear(self) -> None:
        """
        Clear the ledger. Intended for tests.
        """
        with self._lock:
            self._entries.clear()
            self._seq = 0
            self._last_chain_hash = _GENESIS_HASH
            self._last_prune = time.monotonic()

    def stats(self) -> dict[str, Any]:
        """
        Return safe ledger statistics.
        """
        with self._lock:
            self._prune()

            return {
                "backend": "memory",
                "distributed": False,
                "durable": False,
                "max_entries": self.options.ledger_max_entries,
                "active_entries": len(self._entries),
                "sequence": self._seq,
                "retention_seconds": round(self.options.retention_seconds, 3),
            }


_default_ledger: Optional[ProvenanceLedger] = None
_default_ledger_lock = threading.Lock()


def get_provenance_ledger(options: ProvenanceOptions | None = None) -> ProvenanceLedger:
    """
    Return a process-wide provenance ledger.

    If options are provided, a new ledger is created and becomes the default.
    This is useful for tests or applications that construct options explicitly.
    """
    global _default_ledger

    with _default_ledger_lock:
        if _default_ledger is None or options is not None:
            _default_ledger = ProvenanceLedger(options=options)

        return _default_ledger


def seal_batch(
    batch: ProvenanceBatch,
    options: ProvenanceOptions | None = None,
    ledger: ProvenanceLedger | None = None,
) -> ProvenanceBatch:
    """
    Chain and sign a batch provenance envelope.
    """
    opts = options or ProvenanceOptions.from_settings()

    if opts.include_chain:
        active_ledger = ledger or get_provenance_ledger(opts)
        active_ledger.append(batch)

    if opts.sign_provenance:
        sign_batch(batch, opts)

    return batch


# -----------------------------------------------------------------------------
# Build API
# -----------------------------------------------------------------------------


def build_batch_provenance(
    entity_type: str,
    records: Any,
    *,
    batch_id: Optional[str] = None,
    source_system: str = "api",
    source_kind: str = ProvenanceSourceKind.API.value,
    source_name: Optional[str] = None,
    content_type: Optional[str] = None,
    data_classification: str = ProvenanceDataClassification.SYNTHETIC.value,
    source_checksum: Optional[str] = None,
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    actor: Any = None,
    counts: Any = None,
    requested_at: Optional[datetime] = None,
    options: ProvenanceOptions | None = None,
    ledger: ProvenanceLedger | None = None,
    seal: bool = True,
) -> ProvenanceBatch:
    """
    Build a bounded, safe provenance envelope for one ingestion batch.

    Args:
        entity_type: Ingestion entity type, e.g. accounts, transactions,
            complaints, entities, entity_links. Unknown types are supported in
            generic mode.
        records: Records, record payload, loader result, normalizer result, or
            any iterable of mappings.
        batch_id: Optional stable batch identifier. Generated when omitted.
        source_system: Safe source-system label.
        source_kind: Safe source-kind label.
        source_name: Safe basename-like source name. Full paths are not stored.
        content_type: Safe content-type label.
        data_classification: Safe classification label. Non-synthetic values are
            downgraded unless explicitly allowed.
        source_checksum: Optional upstream checksum, e.g. from loader.
        request_id: Optional safe request ID.
        correlation_id: Optional safe correlation ID.
        actor: Optional actor-like value. Only a salted one-way actor hash is
            stored.
        counts: Optional counts mapping or result object with `.counts`.
        requested_at: Optional request timestamp.
        options: Optional provenance policy. Resolved from settings when absent.
        ledger: Optional ledger. Defaults to process-wide ledger.
        seal: When True, chain and sign the batch.

    Returns:
        ProvenanceBatch containing one-way hashes, integrity roots, chain state,
        signature, and safe issues.
    """
    opts = options or ProvenanceOptions.from_settings()
    normalized_type = _normalize_entity_type(entity_type)
    record_list = _extract_records(records)
    submitted = len(record_list)

    resolved_batch_id = str(batch_id or f"prov-{uuid.uuid4().hex[:16]}")
    resolved_source_system = _clean_text(source_system, 100) or "api"
    resolved_source_kind = _normalize_source_kind(source_kind)
    resolved_source_name = _safe_source_name(source_name) or None
    resolved_content_type = _clean_text(content_type, 100) or None
    resolved_request_id = _clean_text(request_id, 128) or None
    resolved_correlation_id = _clean_text(correlation_id, 128) or None
    resolved_source_checksum = _clean_text(source_checksum, 128) or None

    classification, downgraded = _normalize_classification(
        data_classification,
        resolved_source_kind,
        opts,
    )

    actor_hash = None

    if actor is not None:
        actor_hash = _hash_value(actor, opts.salt, _DOMAIN_ACTOR)

    batch = ProvenanceBatch(
        version=PROVENANCE_VERSION,
        batch_id=resolved_batch_id,
        entity_type=normalized_type,
        source_system=resolved_source_system,
        source_kind=resolved_source_kind,
        source_name=resolved_source_name,
        content_type=resolved_content_type,
        data_classification=classification,
        request_id=resolved_request_id,
        correlation_id=resolved_correlation_id,
        actor_hash=actor_hash,
        requested_at=_ensure_utc(requested_at) or _now_utc(),
        record_count=submitted,
        max_issues=opts.max_issues_returned,
        source_checksum=resolved_source_checksum,
    )

    if downgraded:
        batch.add_issue(
            severity=ProvenanceSeverity.WARNING,
            code="classification_downgraded",
            message="Non-synthetic data classification was downgraded to synthetic.",
            details={"requested": _clean_text(data_classification, 100)},
        )

    if not opts.enabled:
        batch.add_issue(
            severity=ProvenanceSeverity.INFO,
            code="provenance_disabled",
            message="Provenance is disabled. No record hashes were computed.",
        )
        batch.finalize(opts)
        return batch

    limit = min(submitted, opts.max_records)

    if submitted > opts.max_records:
        batch.partial = True
        batch.truncated = True
        batch.add_issue(
            severity=ProvenanceSeverity.ERROR,
            code="batch_too_large",
            message="Batch exceeds configured provenance limit. Only the first records were provenanced.",
            details={
                "submitted": submitted,
                "max_records": opts.max_records,
            },
        )

    leaves: list[str] = []

    for index in range(limit):
        record = record_list[index]
        result = _sanitize_record_for_provenance(
            normalized_type,
            record,
            opts,
            batch,
            index,
        )

        if result is None:
            batch.records.append(
                ProvenanceRecord(
                    index=index,
                    record_hash=None,
                )
            )
            continue

        record_hash, narrative_hash, metadata_hash, fields_hashed, record_id = result

        provenance_record = ProvenanceRecord(
            index=index,
            record_id=record_id,
            record_hash=record_hash if opts.include_record_hashes else None,
            leaf_index=None,
            fields_hashed=fields_hashed,
            narrative_hash=narrative_hash,
            metadata_hash=metadata_hash,
        )

        batch.records.append(provenance_record)

        if opts.include_record_hashes and record_hash:
            provenance_record.leaf_index = len(leaves)
            leaves.append(record_hash)

    batch.valid_record_count = len(leaves)

    if opts.include_merkle_root and leaves:
        batch.merkle_root = _merkle_root(leaves)

    extracted_counts = _extract_counts(counts)

    batch.accepted_count = extracted_counts.get(
        "accepted",
        batch.valid_record_count,
    )
    batch.rejected_count = extracted_counts.get("rejected", 0)
    batch.duplicated_count = extracted_counts.get("duplicated", 0)
    batch.skipped_count = extracted_counts.get("skipped", 0)

    if seal:
        seal_batch(batch, opts, ledger=ledger)

    batch.finalize(opts)
    return batch


def build_record_provenance(
    entity_type: str,
    record: Any,
    index: int = 0,
    options: ProvenanceOptions | None = None,
) -> ProvenanceRecord:
    """
    Build safe provenance for one record without batch chaining or signing.
    """
    opts = options or ProvenanceOptions.from_settings()
    normalized_type = _normalize_entity_type(entity_type)

    result = _sanitize_record_for_provenance(
        normalized_type,
        record,
        opts,
        None,
        index,
    )

    if result is None:
        return ProvenanceRecord(index=index, record_hash=None)

    record_hash, narrative_hash, metadata_hash, fields_hashed, record_id = result

    return ProvenanceRecord(
        index=index,
        record_id=record_id,
        record_hash=record_hash if opts.include_record_hashes else None,
        leaf_index=None,
        fields_hashed=fields_hashed,
        narrative_hash=narrative_hash,
        metadata_hash=metadata_hash,
    )


# -----------------------------------------------------------------------------
# Verification API
# -----------------------------------------------------------------------------


def _make_issue(
    *,
    severity: ProvenanceSeverity,
    code: str,
    message: str,
    entity_type: str = "",
    index: Optional[int] = None,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> ProvenanceIssue:
    """
    Build one safe provenance issue.
    """
    return ProvenanceIssue(
        severity=severity,
        code=_clean_text(code, 100),
        message=_clean_text(message, 300),
        entity_type=_clean_text(entity_type, 100),
        index=int(index) if index is not None else None,
        field=_clean_text(field, 200) if field else None,
        details=_safe_details(details),
    )


def verify_batch_provenance(
    batch: ProvenanceBatch,
    records: Any,
    options: ProvenanceOptions | None = None,
    ledger: ProvenanceLedger | None = None,
) -> tuple[bool, list[ProvenanceIssue]]:
    """
    Verify record hashes, Merkle root, signature, and chain hash.

    Returns `(ok, issues)`.
    """
    opts = options or ProvenanceOptions.from_settings()
    record_list = _extract_records(records)
    issues: list[ProvenanceIssue] = []

    if len(record_list) != batch.record_count:
        issues.append(
            _make_issue(
                severity=ProvenanceSeverity.ERROR,
                code="record_count_mismatch",
                message="Record count does not match provenance batch.",
                entity_type=batch.entity_type,
                details={
                    "expected": batch.record_count,
                    "actual": len(record_list),
                },
            )
        )

    leaves: list[str] = []

    for provenance_record in batch.records:
        index = provenance_record.index

        if index >= len(record_list):
            issues.append(
                _make_issue(
                    severity=ProvenanceSeverity.ERROR,
                    code="missing_record_for_provenance",
                    message="Provenance record index is missing from supplied records.",
                    entity_type=batch.entity_type,
                    index=index,
                )
            )
            continue

        result = _sanitize_record_for_provenance(
            batch.entity_type,
            record_list[index],
            opts,
            None,
            index,
        )

        if result is None:
            issues.append(
                _make_issue(
                    severity=ProvenanceSeverity.ERROR,
                    code="record_hash_failed",
                    message="Record could not be hashed for verification.",
                    entity_type=batch.entity_type,
                    index=index,
                )
            )
            continue

        record_hash, _, _, _, _ = result

        if provenance_record.record_hash:
            if not _constant_time_equals(provenance_record.record_hash, record_hash):
                issues.append(
                    _make_issue(
                        severity=ProvenanceSeverity.ERROR,
                        code="record_hash_mismatch",
                        message="Record hash does not match provenance batch.",
                        entity_type=batch.entity_type,
                        index=index,
                    )
                )
            else:
                leaves.append(record_hash or "")
        elif record_hash:
            leaves.append(record_hash)

    if batch.merkle_root:
        recomputed_root = _merkle_root(leaves) if leaves else None

        if not _constant_time_equals(recomputed_root, batch.merkle_root):
            issues.append(
                _make_issue(
                    severity=ProvenanceSeverity.ERROR,
                    code="merkle_root_mismatch",
                    message="Merkle root does not match provenance batch.",
                    entity_type=batch.entity_type,
                )
            )

    if batch.signature and not verify_batch_signature(batch, opts):
        issues.append(
            _make_issue(
                severity=ProvenanceSeverity.ERROR,
                code="signature_mismatch",
                message="Batch signature does not verify.",
                entity_type=batch.entity_type,
            )
        )

    if batch.chain_hash:
        active_ledger = ledger or get_provenance_ledger(opts)

        if not active_ledger.verify(batch, opts):
            issues.append(
                _make_issue(
                    severity=ProvenanceSeverity.ERROR,
                    code="chain_hash_mismatch",
                    message="Batch chain hash does not verify.",
                    entity_type=batch.entity_type,
                )
            )

    ok = not any(issue.severity == ProvenanceSeverity.ERROR for issue in issues)
    return ok, issues


# -----------------------------------------------------------------------------
# Audit path API
# -----------------------------------------------------------------------------


def generate_audit_path(
    batch: ProvenanceBatch,
    record_index: int,
) -> Optional[ProvenanceAuditPath]:
    """
    Generate a Merkle audit path for one record index.

    Returns None when the record has no hash or the batch has no Merkle root.
    """
    if not batch.merkle_root:
        return None

    provenance_record = next(
        (record for record in batch.records if record.index == record_index),
        None,
    )

    if provenance_record is None or not provenance_record.record_hash:
        return None

    if provenance_record.leaf_index is None:
        return None

    leaves = [
        record.record_hash
        for record in batch.records
        if record.record_hash is not None
    ]

    if not leaves:
        return None

    layers = _merkle_layers(leaves)

    if not layers:
        return None

    root_hash = layers[-1][0] if layers else batch.merkle_root
    steps: list[ProvenanceAuditStep] = []
    index = int(provenance_record.leaf_index)

    for layer in layers[:-1]:
        sibling_index = index ^ 1

        if sibling_index < len(layer):
            sibling_hash = layer[sibling_index]
            side = "right" if index % 2 == 0 else "left"
        else:
            sibling_hash = layer[index]
            side = "duplicate"

        steps.append(
            ProvenanceAuditStep(
                hash=sibling_hash,
                side=side,
            )
        )

        index //= 2

    return ProvenanceAuditPath(
        batch_id=batch.batch_id,
        entity_type=batch.entity_type,
        leaf_index=int(provenance_record.leaf_index),
        record_index=int(record_index),
        leaf_hash=provenance_record.record_hash,
        root_hash=root_hash,
        steps=tuple(steps),
    )


def verify_audit_path(
    path: ProvenanceAuditPath,
    *,
    leaf_hash: Optional[str] = None,
    root_hash: Optional[str] = None,
) -> bool:
    """
    Verify a Merkle audit path.
    """
    current = leaf_hash or path.leaf_hash

    if not current:
        return False

    if leaf_hash and not _constant_time_equals(leaf_hash, path.leaf_hash):
        return False

    for step in path.steps:
        if step.side == "left":
            current = _merkle_parent(step.hash, current)
        elif step.side == "right":
            current = _merkle_parent(current, step.hash)
        elif step.side == "duplicate":
            current = _merkle_parent(current, current)
        else:
            return False

    expected = root_hash or path.root_hash
    return _constant_time_equals(current, expected)


def get_record_provenance(
    batch: ProvenanceBatch,
    record_index: int,
) -> Optional[ProvenanceRecord]:
    """
    Return provenance for one record index.
    """
    return next(
        (record for record in batch.records if record.index == record_index),
        None,
    )


def provenance_record_map(batch: ProvenanceBatch) -> dict[int, dict[str, Any]]:
    """
    Return a safe mapping of record index to record provenance dictionary.
    """
    return {
        record.index: record.to_dict()
        for record in batch.records
    }


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_provenance_metadata() -> dict[str, Any]:
    """
    Return safe, serializable provenance-layer metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, or real customer data.
    """
    default_options = ProvenanceOptions()

    return {
        "package": "muleguard.backend.ingestion.provenance",
        "version": PROVENANCE_VERSION,
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "supported_entity_types": list(_SUPPORTED_ENTITY_TYPES),
        "source_kinds": [kind.value for kind in ProvenanceSourceKind],
        "data_classifications": [
            classification.value
            for classification in ProvenanceDataClassification
        ],
        "default_options": default_options.safe_summary(),
        "hard_limits": {
            "max_records": _HARD_MAX_RECORDS,
            "max_issues_returned": _HARD_MAX_ISSUES_RETURNED,
            "max_string_length": _HARD_MAX_STRING_LENGTH,
            "max_metadata_depth": _HARD_MAX_METADATA_DEPTH,
            "max_list_length": _HARD_MAX_LIST_LENGTH,
            "max_mapping_keys": _HARD_MAX_MAPPING_KEYS,
            "ledger_max_entries": _HARD_LEDGER_MAX_ENTRIES,
        },
        "forbidden_top_level_key_count": len(_FORBIDDEN_TOP_LEVEL_KEYS),
        "caveats": list(_PROVENANCE_CAVEATS),
        "safety_flags": {
            "synthetic_only_by_default": True,
            "no_real_customer_data_by_default": True,
            "no_raw_narrative_storage": True,
            "no_raw_narrative_logging": True,
            "no_raw_narrative_in_summaries": True,
            "no_raw_identifier_storage": True,
            "no_ground_truth_labels_accepted": True,
            "no_scenario_ids_accepted": True,
            "no_fraud_ring_ids_accepted": True,
            "no_secrets_in_summaries": True,
            "salted_one_way_record_hashes": True,
            "bounded_merkle_indexes_required": True,
            "bounded_ledger_required": True,
            "local_hmac_integrity_only": True,
            "no_public_key_signatures": True,
            "no_automatic_adverse_customer_action": True,
            "not_production_ready": True,
        },
    }


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "PROVENANCE_SCHEMA_VERSION",
    "PROVENANCE_VERSION",
    "ProvenanceAuditPath",
    "ProvenanceAuditStep",
    "ProvenanceBatch",
    "ProvenanceDataClassification",
    "ProvenanceIssue",
    "ProvenanceLedger",
    "ProvenanceOptions",
    "ProvenanceRecord",
    "ProvenanceSeverity",
    "ProvenanceSourceKind",
    "build_batch_provenance",
    "build_record_provenance",
    "generate_audit_path",
    "get_provenance_ledger",
    "get_provenance_metadata",
    "get_record_provenance",
    "provenance_record_map",
    "seal_batch",
    "sign_batch",
    "verify_audit_path",
    "verify_batch_provenance",
    "verify_batch_signature",
]