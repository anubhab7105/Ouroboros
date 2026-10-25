"""
MULEGUARD backend ingestion normalizers.

This module provides the canonical normalization layer for synthetic MULEGUARD
ingestion workflows.

Primary responsibilities:

- normalize bounded ingestion records for accounts, transactions, complaints,
  pseudonymous entities, and account-entity links before validation and
  persistence;
- apply deterministic field aliasing, whitespace/control-character cleanup,
  Unicode normalization, enum canonicalization, currency normalization,
  timestamp normalization, monetary quantization, confidence normalization,
  and bounded metadata sanitization;
- reject or omit leakage-prone fields such as ground-truth labels, scenario IDs,
  fraud-ring IDs, raw identifiers, secrets, tokens, passwords, database URLs,
  and model artifact paths;
- preserve clearly synthetic complaint narrative text only where explicitly
  required by the synthetic complaint workflow, while never returning narratives
  in public summaries, issues, warnings, or diagnostics;
- produce safe, structured normalization results with bounded error and warning
  reporting;
- remain import-safe, dependency-light, and usable by API endpoints, services,
  seeders, tests, and offline fixtures.

This module normalizes records only. It does not persist data, call external
systems, authenticate users, authorize actions, train models, generate reports,
or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be ingested.
- Ground-truth labels, injected scenario IDs, and fraud-ring IDs must not be
  accepted, persisted, returned, logged, or exported.
- Raw complaint narratives may be normalized only for controlled synthetic
  complaint ingestion, but are never returned in normalization summaries,
  errors, warnings, or diagnostics.
- Entity identifiers must be pseudonymously hashed. Raw identifier fields are
  rejected or omitted.
- Secrets, tokens, passwords, database URLs, model artifact paths, and raw
  sensitive identifiers are never logged or returned.
- Normalization is bounded and deterministic.
- Unknown fields are omitted by default to reduce accidental leakage surface.
- Normalization never triggers automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, or restricting accounts.
- Ingested records are investigative inputs only. They are not proof of
  wrongdoing.

Explicit non-goals:

- This module does not write to the database.
- This module does not call real banking systems.
- This module does not authenticate or authorize users.
- This module does not generate synthetic data.
- This module does not validate final business rules; use
  `app.ingestion.validators` for strict validation.
- This module does not train or evaluate models.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, and case dispositions are investigative leads or human workflow
artefacts only. They are not proof of wrongdoing and must not trigger automatic
adverse customer action.
"""

from __future__ import annotations

import logging
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Final, Optional

from app.core.vocabularies import (
    AccountStatus,
    AccountType,
    Channel,
    EntityType,
    MatchMethod,
    TransactionStatus,
    VerificationState,
)

logger = logging.getLogger("muleguard.backend.ingestion.normalizers")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

NORMALIZERS_VERSION: Final[str] = "v1"
SOURCE_SYSTEM_DEFAULT: Final[str] = "api"
DEFAULT_CURRENCY: Final[str] = "INR"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

DATASET_MODE_SYNTHETIC: Final[str] = "synthetic"

SUPPORTED_INGESTION_ENTITY_TYPES: Final[tuple[str, ...]] = (
    "accounts",
    "transactions",
    "complaints",
    "entities",
    "entity_links",
)

DEFAULT_MAX_BATCH_SIZE: Final[int] = 1_000
HARD_MAX_BATCH_SIZE: Final[int] = 10_000

DEFAULT_MAX_ERRORS_RETURNED: Final[int] = 100
HARD_MAX_ERRORS_RETURNED: Final[int] = 500

DEFAULT_MAX_WARNINGS_RETURNED: Final[int] = 50
HARD_MAX_WARNINGS_RETURNED: Final[int] = 200

DEFAULT_MAX_STRING_LENGTH: Final[int] = 512
HARD_MAX_STRING_LENGTH: Final[int] = 4_096

DEFAULT_MAX_ID_LENGTH: Final[int] = 128
HARD_MAX_ID_LENGTH: Final[int] = 256

DEFAULT_MAX_REFERENCE_LENGTH: Final[int] = 128
HARD_MAX_REFERENCE_LENGTH: Final[int] = 256

DEFAULT_MAX_NARRATIVE_LENGTH: Final[int] = 20_000
HARD_MAX_NARRATIVE_LENGTH: Final[int] = 100_000

DEFAULT_MAX_METADATA_DEPTH: Final[int] = 6
HARD_MAX_METADATA_DEPTH: Final[int] = 12

DEFAULT_MAX_LIST_LENGTH: Final[int] = 100
HARD_MAX_LIST_LENGTH: Final[int] = 1_000

DEFAULT_MAX_MAPPING_KEYS: Final[int] = 100
HARD_MAX_MAPPING_KEYS: Final[int] = 1_000

MAX_SOURCE_LENGTH: Final[int] = 100
MAX_CATEGORY_LENGTH: Final[int] = 100
MAX_DISPLAY_LENGTH: Final[int] = 200

MONEY_QUANT: Final[Decimal] = Decimal("0.01")
CONFIDENCE_QUANT: Final[Decimal] = Decimal("0.0001")

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_NARRATIVE_CONTROL_RE: Final[re.Pattern[str]] = re.compile(
    r"[\x00-\x09\x0b-\x1f\x7f]"
)
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")
_HEX_LIKE_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]+$")


# -----------------------------------------------------------------------------
# Canonical enum sets
# -----------------------------------------------------------------------------

# The accepted vocabularies are derived from the persisted enums rather than
# listed here.
#
# They were listed here, and they had drifted. The normalizer accepted
# SAVINGS, CURRENT, WALLET, UPI and CARD as account types while the column is
# `enum_column(AccountType)` over INDIVIDUAL, BUSINESS, MERCHANT and OTHER —
# so every account that passed validation was then refused by the database,
# and the only values it could actually store were rejected as unknown. The
# same had happened to account statuses, transaction statuses, channels,
# entity types, match methods and verification states.
#
# Deriving them means the two cannot drift again: adding a member to an enum
# makes it ingestible, and removing one makes it refused, with no second list
# to remember.
def _enum_values(enum_cls: type[Enum]) -> frozenset[str]:
    """
    Return one enum's values as the accepted ingestion vocabulary.
    """
    return frozenset(str(member.value) for member in enum_cls)


ACCOUNT_TYPES: Final[frozenset[str]] = _enum_values(AccountType)

ACCOUNT_STATUSES: Final[frozenset[str]] = _enum_values(AccountStatus)

TRANSACTION_STATUSES: Final[frozenset[str]] = _enum_values(TransactionStatus)

CHANNELS: Final[frozenset[str]] = _enum_values(Channel)

ENTITY_TYPES: Final[frozenset[str]] = _enum_values(EntityType)

MATCH_METHODS: Final[frozenset[str]] = _enum_values(MatchMethod)

VERIFICATION_STATES: Final[frozenset[str]] = _enum_values(VerificationState)

COMPLAINT_CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        "unauthorized_transfer",
        "account_takeover",
        "identity_theft",
        "phishing",
        "scam",
        "other",
    }
)


# -----------------------------------------------------------------------------
# Safe alias tables
# -----------------------------------------------------------------------------

# Aliases map a caller's wording onto a persisted value. They carry genuine
# synonyms only.
#
# A name with no honest destination is deliberately absent, so the record is
# refused with the allowed list rather than quietly relabelled. SAVINGS is the
# clearest case: `AccountType` classifies the *holder* — individual, business,
# merchant — and a savings account is a product, so mapping one to the other
# would be inventing a fact about the account holder. The rejection message
# names the four values and the operator learns what the field means; a
# silent coercion would have produced a dataset of confidently wrong labels.
#
# The same reasoning keeps enforcement states out of the status aliases.
# MULEGUARD never freezes, blocks or restricts an account, so it has no value
# to store for SUSPENDED or BLOCKED, and folding them into REVIEW_REQUIRED
# would record a decision somebody else made as one of ours.
_ACCOUNT_TYPE_ALIASES: Final[Mapping[str, str]] = {
    "CONSUMER": "INDIVIDUAL",
    "INDIVIDUAL_ACCOUNT": "INDIVIDUAL",
    "PERSON": "INDIVIDUAL",
    "PERSONAL": "INDIVIDUAL",
    "RETAIL": "INDIVIDUAL",
    "BUSINESS_ACCOUNT": "BUSINESS",
    "COMPANY": "BUSINESS",
    "CORPORATE": "BUSINESS",
    "ORGANISATION": "BUSINESS",
    "ORGANIZATION": "BUSINESS",
    "MERCHANT_ACCOUNT": "MERCHANT",
    "SELLER": "MERCHANT",
    "VENDOR": "MERCHANT",
    "UNKNOWN": "OTHER",
    "UNSPECIFIED": "OTHER",
}

_ACCOUNT_STATUS_ALIASES: Final[Mapping[str, str]] = {
    "ENABLED": "ACTIVE",
    "LIVE": "ACTIVE",
    "OPEN": "ACTIVE",
    "IDLE": "DORMANT",
    "INACTIVE": "DORMANT",
    "CLOSED_ACCOUNT": "CLOSED",
    "TERMINATED": "CLOSED",
    "FLAGGED": "REVIEW_REQUIRED",
    "NEEDS_REVIEW": "REVIEW_REQUIRED",
    "UNDER_REVIEW": "REVIEW_REQUIRED",
}

# CANCELLED and VOID mean no money moved, which is what FAILED records.
# CHARGEBACK means money came back, which is REVERSED. DISPUTED is absent on
# purpose: the word says somebody is contesting the transfer, not whether it
# settled, and a dispute belongs in a complaint record where the correlation
# machinery can use it.
_TRANSACTION_STATUS_ALIASES: Final[Mapping[str, str]] = {
    "DONE": "COMPLETED",
    "SETTLED": "COMPLETED",
    "SUCCESS": "COMPLETED",
    "SUCCESSFUL": "COMPLETED",
    "IN_PROGRESS": "PENDING",
    "PROCESSING": "PENDING",
    "QUEUED": "PENDING",
    "CANCELED": "FAILED",
    "CANCELLED": "FAILED",
    "ERROR": "FAILED",
    "FAILURE": "FAILED",
    "VOID": "FAILED",
    "CHARGEBACK": "REVERSED",
    "REFUND": "REVERSED",
    "REVERSAL": "REVERSED",
}

# CASH, WALLET and EXTERNAL have no channel value to map onto. A cash deposit
# is not a transfer between two accounts in this model at all, so a record
# describing one is refused rather than filed under the nearest rail.
_CHANNEL_ALIASES: Final[Mapping[str, str]] = {
    "CARD_PAYMENT": "CARD",
    "CREDIT": "CARD",
    "DEBIT": "CARD",
    "INTERNAL_TRANSFER": "INTERNAL",
    "OWN_ACCOUNT": "INTERNAL",
    "INSTANT": "IMPS",
    "REAL_TIME": "RTGS",
    "WIRE": "NEFT",
}

# Entity types are hashed by design, which is why the persisted values carry
# the `_HASH` suffix. An alias that drops the suffix is accepted, because a
# caller saying "PHONE" means the phone entity and the hashing happens on the
# way in. NAME, ACCOUNT_NUMBER and CARD_NUMBER are absent: there is no entity
# type for them, and accepting them would invite raw identifiers into a table
# built to hold only hashes.
_ENTITY_TYPE_ALIASES: Final[Mapping[str, str]] = {
    "DEVICE_ID": "DEVICE",
    "DEVICE_FINGERPRINT": "DEVICE",
    "MOBILE": "PHONE_HASH",
    "PHONE": "PHONE_HASH",
    "PHONE_NUMBER": "PHONE_HASH",
    "MSISDN": "PHONE_HASH",
    "EMAIL": "EMAIL_HASH",
    "EMAIL_ADDRESS": "EMAIL_HASH",
    "MAIL": "EMAIL_HASH",
    "UPI": "UPI_ID",
    "UPI_HANDLE": "UPI_ID",
    "VPA": "UPI_ID",
    "ADDRESS": "ADDRESS_HASH",
    "BILLING_ADDRESS": "ADDRESS_HASH",
    "HOME_ADDRESS": "ADDRESS_HASH",
    "POSTAL_ADDRESS": "ADDRESS_HASH",
    "IP": "IP_HASH",
    "IP_ADDRESS": "IP_HASH",
    "UNSPECIFIED": "OTHER",
}

# A hash match is an exact match on the hash, so HASHED maps to EXACT. Fuzzy
# and heuristic matching is what NORMALIZED records: the comparison was made
# on a cleaned-up form of the value rather than the value itself.
_MATCH_METHOD_ALIASES: Final[Mapping[str, str]] = {
    "DIRECT": "EXACT",
    "EXACT_MATCH": "EXACT",
    "HASH": "EXACT",
    "HASHED": "EXACT",
    "HASHED_IDENTIFIER": "EXACT",
    "FUZZY": "NORMALIZED",
    "HEURISTIC": "NORMALIZED",
    "HEURISTICS": "NORMALIZED",
    "INFERRED": "NORMALIZED",
    "NARRATIVE": "NARRATIVE_EXTRACTION",
    "HUMAN": "MANUAL",
    "USER": "MANUAL",
}

# A link whose verification has lapsed or is still queued needs somebody to
# look at it, which is what NEEDS_REVIEW is for. Treating a stale link as
# UNVERIFIED would lose the fact that it was once verified.
_VERIFICATION_STATE_ALIASES: Final[Mapping[str, str]] = {
    "NOT_VERIFIED": "UNVERIFIED",
    "UNCONFIRMED": "UNVERIFIED",
    "APPROVED": "VERIFIED",
    "CONFIRMED": "VERIFIED",
    "DENIED": "REJECTED",
    "DISMISSED": "REJECTED",
    "AWAITING": "NEEDS_REVIEW",
    "EXPIRED": "NEEDS_REVIEW",
    "OUTDATED": "NEEDS_REVIEW",
    "PENDING": "NEEDS_REVIEW",
    "QUEUED": "NEEDS_REVIEW",
    "STALE": "NEEDS_REVIEW",
}

_COMPLAINT_CATEGORY_ALIASES: Final[Mapping[str, str]] = {
    "unauthorised_transfer": "unauthorized_transfer",
    "unauthorised": "unauthorized_transfer",
    "unauthorized": "unauthorized_transfer",
    "account_takeover": "account_takeover",
    "ato": "account_takeover",
    "identity_theft": "identity_theft",
    "identity": "identity_theft",
    "phishing": "phishing",
    "phish": "phishing",
    "scam": "scam",
    "fraud_scam": "scam",
    "misc": "other",
    "unknown": "other",
}


# -----------------------------------------------------------------------------
# Allowed and forbidden field registries
# -----------------------------------------------------------------------------

ALLOWED_FIELDS: Final[Mapping[str, frozenset[str]]] = {
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

FIELD_ALIASES: Final[Mapping[str, Mapping[str, str]]] = {
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

FORBIDDEN_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
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
        "fraud_label",
        "fraud_ring_id",
        "ground_truth",
        "ground_truth_label",
        "identifier_raw",
        "is_fraud",
        "label",
        "model_artifact_path",
        "model_path",
        "otp",
        "pan",
        "pass",
        "passwd",
        "password",
        "password_hash",
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

_NORMALIZER_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype ingestion normalization only. Do not use with real customer data.",
    "Normalized records are investigative inputs only and are not proof of wrongdoing.",
    "Normalization must not trigger automatic adverse customer action.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are rejected or omitted.",
    "Raw complaint narratives are normalized only for controlled synthetic complaint ingestion and are never returned in public summaries.",
    "Entity identifiers must be pseudonymously hashed. Raw identifier fields are rejected or omitted.",
    "Unknown fields are omitted by default to reduce accidental leakage surface.",
    "Normalization is deterministic and bounded by configured limits.",
    "This module does not persist data or call external systems.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
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


def _clean_text(value: Any, limit: int = DEFAULT_MAX_STRING_LENGTH) -> str:
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


def _clean_narrative(value: Any, limit: int = DEFAULT_MAX_NARRATIVE_LENGTH) -> str:
    """
    Return bounded synthetic narrative text.

    Newlines are preserved as paragraph breaks. Other control characters are
    removed.
    """
    text = _normalize_unicode(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _NARRATIVE_CONTROL_RE.sub(" ", text)

    lines: list[str] = []

    for raw_line in text.split("\n"):
        line = " ".join(raw_line.split())

        if line:
            lines.append(line)

    text = "\n".join(lines).strip()

    if limit <= 0:
        return ""

    if len(text) > limit:
        return text[:limit]

    return text


def _normalize_token(value: Any) -> str:
    """
    Normalize a token-like value to uppercase underscore form.
    """
    text = _normalize_unicode(value).strip()

    if not text:
        return ""

    text = text.upper()
    text = re.sub(r"[^A-Z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_")


def _normalize_lower_token(value: Any) -> str:
    """
    Normalize a lower-case token-like value.
    """
    text = _normalize_unicode(value).strip()

    if not text:
        return ""

    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_")


def _canonical_field_name(key: Any) -> str:
    """
    Convert a field name to a conservative canonical snake_case form.
    """
    text = _normalize_unicode(key).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_").lower()


def _normalize_entity_type(value: Any) -> str:
    """
    Normalize an ingestion entity type.
    """
    text = _normalize_lower_token(value)

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


def _normalize_currency(value: Any) -> str:
    """
    Normalize a currency code.
    """
    text = _normalize_unicode(value).strip().upper()
    text = re.sub(r"[^A-Z]", "", text)

    if _CURRENCY_RE.match(text):
        return text

    return text or ""


def _is_forbidden_key(key: Any, entity_type: Optional[str] = None) -> bool:
    """
    Return True when a top-level record key is forbidden.

    Complaint `narrative_raw` is intentionally allowed for controlled synthetic
    complaint ingestion. Other raw fields are forbidden.
    """
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if entity_type == "complaints" and canonical == "narrative_raw":
        return False

    if canonical in FORBIDDEN_TOP_LEVEL_KEYS:
        return True

    if canonical.startswith("raw_"):
        return True

    if canonical.endswith("_raw") and canonical != "narrative_raw":
        return True

    return any(token in canonical for token in _FORBIDDEN_KEY_TOKENS)


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


def _as_record_sequence(records: Any) -> list[Any]:
    """
    Normalize record input into a list.
    """
    if records is None:
        return []

    if isinstance(records, Mapping):
        return [records]

    if isinstance(records, Sequence) and not isinstance(records, (str, bytes, bytearray)):
        return list(records)

    return [records]


def _parse_datetime(value: Any) -> Optional[datetime]:
    """
    Parse a datetime-like value into timezone-aware UTC.
    """
    if isinstance(value, datetime):
        return _ensure_utc(value)

    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return None

        if not math.isfinite(numeric):
            return None

        # Support seconds and milliseconds epoch values.
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


def _datetime_to_iso(value: Optional[datetime]) -> Optional[str]:
    """
    Convert a datetime to stable UTC ISO-8601 text.
    """
    normalized = _ensure_utc(value)

    if normalized is None:
        return None

    return normalized.isoformat()


def _parse_decimal(value: Any) -> Optional[Decimal]:
    """
    Parse a decimal-like value without preserving binary float artifacts.
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

    text = _normalize_unicode(value).strip()

    if not text:
        return None

    # Allow common thousands separators but do not accept arbitrary text.
    text = text.replace(",", "")

    try:
        parsed = Decimal(text)
    except (InvalidOperation, ValueError, TypeError):
        return None

    return parsed if parsed.is_finite() else None


def _quantize_money(value: Optional[Decimal]) -> Optional[Decimal]:
    """
    Quantize a monetary value to two decimal places.
    """
    if value is None or not value.is_finite():
        return None

    try:
        return value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    except Exception:
        return None


def _quantize_confidence(value: Optional[Decimal]) -> Optional[Decimal]:
    """
    Quantize a confidence value to four decimal places.

    Percent-like values in `(1, 100]` are normalized to fractions in `[0.01, 1]`.
    """
    if value is None or not value.is_finite():
        return None

    parsed = value

    if Decimal("1") < parsed <= Decimal("100"):
        parsed = parsed / Decimal("100")

    try:
        return parsed.quantize(CONFIDENCE_QUANT, rounding=ROUND_HALF_UP)
    except Exception:
        return None


def _safe_detail_value(value: Any, depth: int = 0) -> Any:
    """
    Convert an arbitrary detail value into a bounded, safe representation.
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
        return _datetime_to_iso(value)

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
        limited = list(value)[:20]
        return [_safe_detail_value(item, depth + 1) for item in limited]

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
class NormalizationOptions:
    """
    Bounded ingestion normalization policy.

    Hard caps prevent client-controlled or configuration-controlled unbounded
    normalization surfaces.
    """

    max_batch_size: int = DEFAULT_MAX_BATCH_SIZE
    max_errors_returned: int = DEFAULT_MAX_ERRORS_RETURNED
    max_warnings_returned: int = DEFAULT_MAX_WARNINGS_RETURNED

    max_string_length: int = DEFAULT_MAX_STRING_LENGTH
    max_id_length: int = DEFAULT_MAX_ID_LENGTH
    max_reference_length: int = DEFAULT_MAX_REFERENCE_LENGTH
    max_narrative_length: int = DEFAULT_MAX_NARRATIVE_LENGTH

    max_metadata_depth: int = DEFAULT_MAX_METADATA_DEPTH
    max_list_length: int = DEFAULT_MAX_LIST_LENGTH
    max_mapping_keys: int = DEFAULT_MAX_MAPPING_KEYS

    default_currency: str = DEFAULT_CURRENCY
    source_system: Optional[str] = SOURCE_SYSTEM_DEFAULT

    fill_default_currency: bool = True
    sort_metadata_keys: bool = True
    drop_unknown_fields: bool = True

    def __post_init__(self) -> None:
        """
        Normalize and clamp option values.
        """
        object.__setattr__(
            self,
            "max_batch_size",
            _clamp_int(
                self.max_batch_size,
                1,
                HARD_MAX_BATCH_SIZE,
                DEFAULT_MAX_BATCH_SIZE,
            ),
        )

        object.__setattr__(
            self,
            "max_errors_returned",
            _clamp_int(
                self.max_errors_returned,
                1,
                HARD_MAX_ERRORS_RETURNED,
                DEFAULT_MAX_ERRORS_RETURNED,
            ),
        )

        object.__setattr__(
            self,
            "max_warnings_returned",
            _clamp_int(
                self.max_warnings_returned,
                1,
                HARD_MAX_WARNINGS_RETURNED,
                DEFAULT_MAX_WARNINGS_RETURNED,
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
            "max_id_length",
            _clamp_int(
                self.max_id_length,
                1,
                HARD_MAX_ID_LENGTH,
                DEFAULT_MAX_ID_LENGTH,
            ),
        )

        object.__setattr__(
            self,
            "max_reference_length",
            _clamp_int(
                self.max_reference_length,
                1,
                HARD_MAX_REFERENCE_LENGTH,
                DEFAULT_MAX_REFERENCE_LENGTH,
            ),
        )

        object.__setattr__(
            self,
            "max_narrative_length",
            _clamp_int(
                self.max_narrative_length,
                1,
                HARD_MAX_NARRATIVE_LENGTH,
                DEFAULT_MAX_NARRATIVE_LENGTH,
            ),
        )

        object.__setattr__(
            self,
            "max_metadata_depth",
            _clamp_int(
                self.max_metadata_depth,
                1,
                HARD_MAX_METADATA_DEPTH,
                DEFAULT_MAX_METADATA_DEPTH,
            ),
        )

        object.__setattr__(
            self,
            "max_list_length",
            _clamp_int(
                self.max_list_length,
                1,
                HARD_MAX_LIST_LENGTH,
                DEFAULT_MAX_LIST_LENGTH,
            ),
        )

        object.__setattr__(
            self,
            "max_mapping_keys",
            _clamp_int(
                self.max_mapping_keys,
                1,
                HARD_MAX_MAPPING_KEYS,
                DEFAULT_MAX_MAPPING_KEYS,
            ),
        )

        object.__setattr__(
            self,
            "default_currency",
            _normalize_currency(self.default_currency) or DEFAULT_CURRENCY,
        )

        if self.source_system is not None:
            source = _clean_text(self.source_system, MAX_SOURCE_LENGTH)
            object.__setattr__(self, "source_system", source or None)

        object.__setattr__(
            self,
            "fill_default_currency",
            _as_bool(self.fill_default_currency, True),
        )

        object.__setattr__(
            self,
            "sort_metadata_keys",
            _as_bool(self.sort_metadata_keys, True),
        )

        object.__setattr__(
            self,
            "drop_unknown_fields",
            _as_bool(self.drop_unknown_fields, True),
        )

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "NormalizationOptions":
        """
        Build normalization options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        hard_max_batch_size = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_BATCH_SIZE", HARD_MAX_BATCH_SIZE),
            1,
            HARD_MAX_BATCH_SIZE,
            HARD_MAX_BATCH_SIZE,
        )

        max_batch_size = _clamp_int(
            _setting(settings, "INGESTION_MAX_BATCH_SIZE", DEFAULT_MAX_BATCH_SIZE),
            1,
            hard_max_batch_size,
            DEFAULT_MAX_BATCH_SIZE,
        )

        hard_max_errors = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_ERRORS_RETURNED", HARD_MAX_ERRORS_RETURNED),
            1,
            HARD_MAX_ERRORS_RETURNED,
            HARD_MAX_ERRORS_RETURNED,
        )

        max_errors = _clamp_int(
            _setting(settings, "INGESTION_MAX_ERRORS_RETURNED", DEFAULT_MAX_ERRORS_RETURNED),
            1,
            hard_max_errors,
            DEFAULT_MAX_ERRORS_RETURNED,
        )

        hard_max_narrative = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_NARRATIVE_LENGTH", HARD_MAX_NARRATIVE_LENGTH),
            1,
            HARD_MAX_NARRATIVE_LENGTH,
            HARD_MAX_NARRATIVE_LENGTH,
        )

        max_narrative = _clamp_int(
            _setting(settings, "INGESTION_MAX_NARRATIVE_LENGTH", DEFAULT_MAX_NARRATIVE_LENGTH),
            1,
            hard_max_narrative,
            DEFAULT_MAX_NARRATIVE_LENGTH,
        )

        hard_max_depth = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_JSON_DEPTH", HARD_MAX_METADATA_DEPTH),
            1,
            HARD_MAX_METADATA_DEPTH,
            HARD_MAX_METADATA_DEPTH,
        )

        max_depth = _clamp_int(
            _setting(settings, "INGESTION_MAX_JSON_DEPTH", DEFAULT_MAX_METADATA_DEPTH),
            1,
            hard_max_depth,
            DEFAULT_MAX_METADATA_DEPTH,
        )

        hard_max_list = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_LIST_LENGTH", HARD_MAX_LIST_LENGTH),
            1,
            HARD_MAX_LIST_LENGTH,
            HARD_MAX_LIST_LENGTH,
        )

        max_list = _clamp_int(
            _setting(settings, "INGESTION_MAX_LIST_LENGTH", DEFAULT_MAX_LIST_LENGTH),
            1,
            hard_max_list,
            DEFAULT_MAX_LIST_LENGTH,
        )

        hard_max_mapping = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_MAPPING_KEYS", HARD_MAX_MAPPING_KEYS),
            1,
            HARD_MAX_MAPPING_KEYS,
            HARD_MAX_MAPPING_KEYS,
        )

        max_mapping = _clamp_int(
            _setting(settings, "INGESTION_MAX_MAPPING_KEYS", DEFAULT_MAX_MAPPING_KEYS),
            1,
            hard_max_mapping,
            DEFAULT_MAX_MAPPING_KEYS,
        )

        return cls(
            max_batch_size=max_batch_size,
            max_errors_returned=max_errors,
            max_warnings_returned=max(
                1,
                min(
                    max_errors // 2 or DEFAULT_MAX_WARNINGS_RETURNED,
                    HARD_MAX_WARNINGS_RETURNED,
                ),
            ),
            max_string_length=_clamp_int(
                _setting(settings, "INGESTION_MAX_STRING_LENGTH", DEFAULT_MAX_STRING_LENGTH),
                1,
                HARD_MAX_STRING_LENGTH,
                DEFAULT_MAX_STRING_LENGTH,
            ),
            max_id_length=_clamp_int(
                _setting(settings, "INGESTION_MAX_ID_LENGTH", DEFAULT_MAX_ID_LENGTH),
                1,
                HARD_MAX_ID_LENGTH,
                DEFAULT_MAX_ID_LENGTH,
            ),
            max_reference_length=_clamp_int(
                _setting(settings, "INGESTION_MAX_REFERENCE_LENGTH", DEFAULT_MAX_REFERENCE_LENGTH),
                1,
                HARD_MAX_REFERENCE_LENGTH,
                DEFAULT_MAX_REFERENCE_LENGTH,
            ),
            max_narrative_length=max_narrative,
            max_metadata_depth=max_depth,
            max_list_length=max_list,
            max_mapping_keys=max_mapping,
            default_currency=_normalize_currency(
                _setting(settings, "BACKEND_DEFAULT_CURRENCY", DEFAULT_CURRENCY)
            )
            or DEFAULT_CURRENCY,
            source_system=_clean_text(
                _setting(settings, "INGESTION_SOURCE_SYSTEM", SOURCE_SYSTEM_DEFAULT),
                MAX_SOURCE_LENGTH,
            )
            or SOURCE_SYSTEM_DEFAULT,
            fill_default_currency=_as_bool(
                _setting(settings, "INGESTION_FILL_DEFAULT_CURRENCY", True),
                True,
            ),
            sort_metadata_keys=_as_bool(
                _setting(settings, "INGESTION_SORT_METADATA_KEYS", True),
                True,
            ),
            drop_unknown_fields=_as_bool(
                _setting(settings, "INGESTION_DROP_UNKNOWN_FIELDS", True),
                True,
            ),
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable summary of normalization options.
        """
        return {
            "max_batch_size": self.max_batch_size,
            "max_errors_returned": self.max_errors_returned,
            "max_warnings_returned": self.max_warnings_returned,
            "max_string_length": self.max_string_length,
            "max_id_length": self.max_id_length,
            "max_reference_length": self.max_reference_length,
            "max_narrative_length": self.max_narrative_length,
            "max_metadata_depth": self.max_metadata_depth,
            "max_list_length": self.max_list_length,
            "max_mapping_keys": self.max_mapping_keys,
            "default_currency": self.default_currency,
            "source_system": self.source_system,
            "fill_default_currency": self.fill_default_currency,
            "sort_metadata_keys": self.sort_metadata_keys,
            "drop_unknown_fields": self.drop_unknown_fields,
        }


# -----------------------------------------------------------------------------
# Issue and result models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class NormalizationIssue:
    """
    Safe normalization issue.

    Issues never contain raw narratives, secrets, tokens, passwords, database
    URLs, model artifact paths, or sensitive identifiers.
    """

    severity: str
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
            "severity": _clean_text(self.severity, 20),
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
class NormalizationResult:
    """
    Safe ingestion normalization result.

    The `normalized` list may contain complaint narrative text for downstream
    validation and persistence. Public summaries deliberately exclude normalized
    records.
    """

    ok: bool = True
    entity_type: str = ""
    submitted: int = 0
    normalized: list[dict[str, Any]] = dataclass_field(default_factory=list)
    rejected: list[int] = dataclass_field(default_factory=list)
    issues: list[NormalizationIssue] = dataclass_field(default_factory=list)
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)

    max_errors: int = DEFAULT_MAX_ERRORS_RETURNED
    max_warnings: int = DEFAULT_MAX_WARNINGS_RETURNED

    _error_count: int = 0
    _warning_count: int = 0
    _error_truncated: bool = False
    _warning_truncated: bool = False

    def add_error(
        self,
        *,
        code: str,
        message: str,
        index: Optional[int] = None,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe error entry.

        Returns False when the bounded error list is already truncated.
        """
        if self._error_truncated:
            self.ok = False
            return False

        entry = NormalizationIssue(
            severity="error",
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            entity_type=_clean_text(self.entity_type, 100),
            index=int(index) if index is not None else None,
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )

        self.issues.append(entry)
        self._error_count += 1
        self.ok = False

        if self._error_count >= max(1, int(self.max_errors)):
            self._error_truncated = True
            self.issues.append(
                NormalizationIssue(
                    severity="error",
                    code="error_list_truncated",
                    message="Error list truncated by configured limit.",
                    entity_type=_clean_text(self.entity_type, 100),
                )
            )

        return True

    def add_warning(
        self,
        *,
        code: str,
        message: str,
        index: Optional[int] = None,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Add one safe warning entry.
        """
        if self._warning_truncated:
            return False

        entry = NormalizationIssue(
            severity="warning",
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            entity_type=_clean_text(self.entity_type, 100),
            index=int(index) if index is not None else None,
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )

        self.issues.append(entry)
        self._warning_count += 1

        if self._warning_count >= max(1, int(self.max_warnings)):
            self._warning_truncated = True
            self.issues.append(
                NormalizationIssue(
                    severity="warning",
                    code="warning_list_truncated",
                    message="Warning list truncated by configured limit.",
                    entity_type=_clean_text(self.entity_type, 100),
                )
            )

        return True

    def finalize(self, options: Optional[NormalizationOptions] = None) -> None:
        """
        Finalize safe metadata for the result.
        """
        self.metadata.update(
            {
                "normalizer_version": NORMALIZERS_VERSION,
                "entity_type": self.entity_type,
                "submitted": self.submitted,
                "normalized_count": len(self.normalized),
                "rejected_count": len(self.rejected),
                "error_count": self._error_count,
                "warning_count": self._warning_count,
                "error_truncated": self._error_truncated,
                "warning_truncated": self._warning_truncated,
            }
        )

        if options is not None:
            self.metadata["max_batch_size"] = options.max_batch_size
            self.metadata["max_errors_returned"] = options.max_errors_returned
            self.metadata["max_warnings_returned"] = options.max_warnings_returned
            self.metadata["drop_unknown_fields"] = options.drop_unknown_fields
            self.metadata["fill_default_currency"] = options.fill_default_currency

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include normalized records, raw narratives,
        identifier hashes, or sensitive values.
        """
        return {
            "ok": self.ok,
            "entity_type": self.entity_type,
            "counts": {
                "submitted": self.submitted,
                "normalized": len(self.normalized),
                "rejected": len(self.rejected),
                "errors": self._error_count,
                "warnings": self._warning_count,
            },
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
            "caveats": list(_NORMALIZER_CAVEATS),
        }


# -----------------------------------------------------------------------------
# Field extraction
# -----------------------------------------------------------------------------


def _extract_allowed_fields(
    record: Any,
    entity_type: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> Optional[dict[str, Any]]:
    """
    Extract allowed fields from a record.

    Forbidden fields are omitted and recorded as errors. Unknown fields are
    omitted and recorded as warnings when `drop_unknown_fields` is enabled.
    """
    if not isinstance(record, Mapping):
        result.add_error(
            code="record_not_object",
            message="Record must be a JSON object.",
            index=index,
        )
        return None

    allowed = ALLOWED_FIELDS.get(entity_type, frozenset())
    aliases = FIELD_ALIASES.get(entity_type, {})
    source: dict[str, Any] = {}

    for raw_key, raw_value in record.items():
        key = _clean_text(raw_key, 200)

        if not key:
            continue

        canonical = _canonical_field_name(key)

        if not canonical:
            continue

        if _is_forbidden_key(canonical, entity_type):
            result.add_error(
                code="forbidden_field",
                message="Forbidden field omitted.",
                index=index,
                field=key,
            )
            continue

        target = aliases.get(canonical, canonical)

        if target in allowed:
            if target in source:
                result.add_warning(
                    code="duplicate_field_alias",
                    message="Duplicate field alias omitted.",
                    index=index,
                    field=key,
                )
                continue

            source[target] = raw_value
            continue

        if options.drop_unknown_fields:
            result.add_warning(
                code="unknown_field_dropped",
                message="Unknown field omitted.",
                index=index,
                field=key,
            )
            continue

        source[canonical] = raw_value

    return source


# -----------------------------------------------------------------------------
# Field normalizers
# -----------------------------------------------------------------------------


def _normalize_identifier_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
    *,
    required: bool = True,
) -> Optional[str]:
    """
    Normalize a required or optional bounded identifier.
    """
    value = fields.get(name)

    if value is None:
        if required:
            result.add_error(
                code="missing_field",
                message="Required identifier is missing.",
                index=index,
                field=name,
            )
        return None

    text = _clean_text(value, options.max_id_length)

    if not text:
        if required:
            result.add_error(
                code="missing_field",
                message="Required identifier is empty.",
                index=index,
                field=name,
            )
        return None

    return text


def _normalize_reference_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
    *,
    required: bool = False,
) -> Optional[str]:
    """
    Normalize an optional bounded reference.
    """
    value = fields.get(name)

    if value is None:
        if required:
            result.add_error(
                code="missing_field",
                message="Required reference is missing.",
                index=index,
                field=name,
            )
        return None

    text = _clean_text(value, options.max_reference_length)

    if not text:
        if required:
            result.add_error(
                code="missing_field",
                message="Required reference is empty.",
                index=index,
                field=name,
            )
        return None

    return text


def _normalize_upper_enum_field(
    fields: Mapping[str, Any],
    name: str,
    aliases: Mapping[str, str],
    allowed: frozenset[str],
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
    *,
    required: bool = True,
) -> Optional[str]:
    """
    Normalize an upper-case enum-like field.

    Unknown values are preserved in normalized token form so strict validators
    can reject them with stable errors.
    """
    value = fields.get(name)

    if value is None:
        if required:
            result.add_error(
                code="missing_field",
                message="Required field is missing.",
                index=index,
                field=name,
            )
        return None

    token = _normalize_token(value)

    if not token:
        if required:
            result.add_error(
                code="invalid_enum",
                message="Field value is empty.",
                index=index,
                field=name,
            )
        return None

    resolved = aliases.get(token, token)

    if resolved in allowed:
        return resolved

    return resolved


def _normalize_lower_enum_field(
    fields: Mapping[str, Any],
    name: str,
    aliases: Mapping[str, str],
    allowed: frozenset[str],
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
    *,
    required: bool = True,
) -> Optional[str]:
    """
    Normalize a lower-case enum-like field.
    """
    value = fields.get(name)

    if value is None:
        if required:
            result.add_error(
                code="missing_field",
                message="Required field is missing.",
                index=index,
                field=name,
            )
        return None

    token = _normalize_lower_token(value)

    if not token:
        if required:
            result.add_error(
                code="invalid_enum",
                message="Field value is empty.",
                index=index,
                field=name,
            )
        return None

    resolved = aliases.get(token, token)

    if resolved in allowed:
        return resolved

    return resolved


def _normalize_datetime_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
    *,
    required: bool = True,
) -> Optional[str]:
    """
    Normalize a timestamp field to stable UTC ISO-8601 text.
    """
    value = fields.get(name)

    if value is None:
        if required:
            result.add_error(
                code="missing_field",
                message="Required timestamp is missing.",
                index=index,
                field=name,
            )
        return None

    parsed = _parse_datetime(value)

    if parsed is None:
        result.add_error(
            code="invalid_timestamp",
            message="Timestamp is invalid.",
            index=index,
            field=name,
        )
        return None

    return _datetime_to_iso(parsed)


def _normalize_amount_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
    *,
    required: bool = True,
) -> Optional[str]:
    """
    Normalize a monetary amount to a bounded two-decimal string.
    """
    value = fields.get(name)

    if value is None:
        if required:
            result.add_error(
                code="missing_field",
                message="Required amount is missing.",
                index=index,
                field=name,
            )
        return None

    parsed = _parse_decimal(value)

    if parsed is None:
        result.add_error(
            code="invalid_amount",
            message="Amount is invalid.",
            index=index,
            field=name,
        )
        return None

    quantized = _quantize_money(parsed)

    if quantized is None:
        result.add_error(
            code="invalid_amount",
            message="Amount could not be normalized.",
            index=index,
            field=name,
        )
        return None

    return str(quantized)


def _normalize_confidence_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> Optional[str]:
    """
    Normalize a confidence value to a bounded four-decimal string.
    """
    value = fields.get(name)

    if value is None:
        return None

    parsed = _parse_decimal(value)

    if parsed is None:
        result.add_error(
            code="invalid_confidence",
            message="Confidence is invalid.",
            index=index,
            field=name,
        )
        return None

    quantized = _quantize_confidence(parsed)

    if quantized is None:
        result.add_error(
            code="invalid_confidence",
            message="Confidence could not be normalized.",
            index=index,
            field=name,
        )
        return None

    return str(quantized)


def _normalize_currency_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
    *,
    amount_present: bool = False,
) -> Optional[str]:
    """
    Normalize a currency field.

    When an amount is present and currency is missing, the configured default
    currency may be filled.
    """
    value = fields.get(name)

    if value is None:
        if amount_present and options.fill_default_currency:
            return options.default_currency

        return None

    text = _normalize_currency(value)

    if not text:
        result.add_error(
            code="invalid_currency",
            message="Currency is invalid.",
            index=index,
            field=name,
        )
        return None

    return text


def _normalize_source_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> Optional[str]:
    """
    Normalize a safe source label.
    """
    value = fields.get(name)

    if value is None:
        return options.source_system

    text = _clean_text(value, MAX_SOURCE_LENGTH)

    if not text:
        result.add_warning(
            code="invalid_source",
            message="Source value was empty and defaulted.",
            index=index,
            field=name,
        )
        return options.source_system

    return text


def _normalize_narrative_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> Optional[str]:
    """
    Normalize bounded synthetic complaint narrative text.

    The narrative is retained for downstream controlled persistence but is never
    returned in public summaries.
    """
    value = fields.get(name)

    if value is None:
        result.add_error(
            code="narrative_required",
            message="Complaint narrative is required.",
            index=index,
            field=name,
        )
        return None

    text = _clean_narrative(value, options.max_narrative_length)

    if not text:
        result.add_error(
            code="narrative_required",
            message="Complaint narrative is empty.",
            index=index,
            field=name,
        )
        return None

    return text


def _normalize_identifier_hash_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> Optional[str]:
    """
    Normalize a pseudonymous identifier hash.

    Raw identifiers are not accepted. This helper only canonicalizes casing and
    whitespace; strict validators enforce hash shape and length.
    """
    value = fields.get(name)

    if value is None:
        result.add_error(
            code="identifier_hash_invalid",
            message="Pseudonymous identifier hash is required.",
            index=index,
            field=name,
        )
        return None

    text = _normalize_unicode(value).strip().lower()
    text = re.sub(r"\s+", "", text)

    if not text:
        result.add_error(
            code="identifier_hash_invalid",
            message="Pseudonymous identifier hash is empty.",
            index=index,
            field=name,
        )
        return None

    if len(text) > options.max_id_length:
        result.add_error(
            code="identifier_hash_invalid",
            message="Pseudonymous identifier hash is too long.",
            index=index,
            field=name,
        )
        return None

    return text


def _normalize_display_field(
    fields: Mapping[str, Any],
    name: str,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> Optional[str]:
    """
    Normalize a masked display label.

    This must never contain raw identifiers.
    """
    value = fields.get(name)

    if value is None:
        return None

    text = _clean_text(value, MAX_DISPLAY_LENGTH)

    if not text:
        result.add_warning(
            code="invalid_display",
            message="Display label was empty and omitted.",
            index=index,
            field=name,
        )
        return None

    # Defensive redaction: if a caller accidentally supplies something that
    # looks like a raw identifier, omit it rather than persist it.
    if "@" in text or re.search(r"\b\d{10,}\b", text):
        result.add_warning(
            code="display_label_redacted",
            message="Display label appeared raw-sensitive and was omitted.",
            index=index,
            field=name,
        )
        return None

    return text


# -----------------------------------------------------------------------------
# Metadata sanitization
# -----------------------------------------------------------------------------


def _sanitize_metadata_value(
    value: Any,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
    path: str,
    depth: int = 0,
) -> Any:
    """
    Recursively sanitize metadata into a bounded, safe structure.
    """
    if depth > options.max_metadata_depth:
        result.add_warning(
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
        return _datetime_to_iso(value)

    if isinstance(value, Enum):
        return _sanitize_metadata_value(
            value.value,
            options,
            result,
            index,
            path,
            depth + 1,
        )

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        if len(value) > options.max_mapping_keys:
            result.add_warning(
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
                result.add_warning(
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
                result,
                index,
                child_path,
                depth + 1,
            )

        if options.sort_metadata_keys:
            return dict(sorted(out.items()))

        return out

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > options.max_list_length:
            result.add_warning(
                code="metadata_too_many_items",
                message="Metadata item count exceeded configured limit.",
                index=index,
                field=path,
                details={"max_list_length": options.max_list_length},
            )

        limited = list(value)[: options.max_list_length]
        sanitized = [
            _sanitize_metadata_value(
                item,
                options,
                result,
                index,
                f"{path}[{position}]",
                depth + 1,
            )
            for position, item in enumerate(limited)
        ]

        return sanitized

    if isinstance(value, (set, frozenset)):
        limited = list(value)[: options.max_list_length]
        sanitized = [
            _sanitize_metadata_value(
                item,
                options,
                result,
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

    result.add_warning(
        code="unsupported_metadata_value",
        message="Unsupported metadata value omitted.",
        index=index,
        field=path,
        details={"type": type(value).__name__},
    )
    return None


def _normalize_metadata_field(
    fields: Mapping[str, Any],
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> Optional[dict[str, Any]]:
    """
    Normalize bounded `metadata_json`.
    """
    value = fields.get("metadata_json")

    if value is None:
        return None

    if not isinstance(value, Mapping):
        result.add_error(
            code="invalid_metadata",
            message="metadata_json must be a JSON object.",
            index=index,
            field="metadata_json",
        )
        return None

    sanitized = _sanitize_metadata_value(
        value,
        options,
        result,
        index,
        "metadata_json",
        depth=0,
    )

    if sanitized is None:
        return None

    if not isinstance(sanitized, dict):
        result.add_error(
            code="invalid_metadata",
            message="metadata_json could not be normalized to an object.",
            index=index,
            field="metadata_json",
        )
        return None

    return sanitized or None


# -----------------------------------------------------------------------------
# Entity-specific normalizers
# -----------------------------------------------------------------------------


def _normalize_account(
    fields: Mapping[str, Any],
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> dict[str, Any]:
    """
    Normalize one synthetic account record.
    """
    out: dict[str, Any] = {}

    account_id = _normalize_identifier_field(
        fields,
        "id",
        options,
        result,
        index,
        required=True,
    )

    if account_id:
        out["id"] = account_id

    account_type = _normalize_upper_enum_field(
        fields,
        "account_type",
        _ACCOUNT_TYPE_ALIASES,
        ACCOUNT_TYPES,
        options,
        result,
        index,
        required=True,
    )

    if account_type:
        out["account_type"] = account_type

    status = _normalize_upper_enum_field(
        fields,
        "status",
        _ACCOUNT_STATUS_ALIASES,
        ACCOUNT_STATUSES,
        options,
        result,
        index,
        required=True,
    )

    if status:
        out["status"] = status

    created_at = _normalize_datetime_field(
        fields,
        "created_at",
        options,
        result,
        index,
        required=True,
    )

    if created_at:
        out["created_at"] = created_at

    metadata = _normalize_metadata_field(fields, options, result, index)

    if metadata is not None:
        out["metadata_json"] = metadata

    return out


def _normalize_transaction(
    fields: Mapping[str, Any],
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> dict[str, Any]:
    """
    Normalize one synthetic transaction record.
    """
    out: dict[str, Any] = {}

    transaction_id = _normalize_identifier_field(
        fields,
        "id",
        options,
        result,
        index,
        required=True,
    )

    if transaction_id:
        out["id"] = transaction_id

    reference = _normalize_reference_field(
        fields,
        "reference",
        options,
        result,
        index,
        required=False,
    )

    if reference:
        out["reference"] = reference

    sender_account_id = _normalize_identifier_field(
        fields,
        "sender_account_id",
        options,
        result,
        index,
        required=True,
    )

    if sender_account_id:
        out["sender_account_id"] = sender_account_id

    receiver_account_id = _normalize_identifier_field(
        fields,
        "receiver_account_id",
        options,
        result,
        index,
        required=True,
    )

    if receiver_account_id:
        out["receiver_account_id"] = receiver_account_id

    amount = _normalize_amount_field(
        fields,
        "amount",
        options,
        result,
        index,
        required=True,
    )

    if amount:
        out["amount"] = amount

    currency = _normalize_currency_field(
        fields,
        "currency",
        options,
        result,
        index,
        amount_present=amount is not None,
    )

    if currency:
        out["currency"] = currency

    occurred_at = _normalize_datetime_field(
        fields,
        "occurred_at",
        options,
        result,
        index,
        required=True,
    )

    if occurred_at:
        out["occurred_at"] = occurred_at

    status = _normalize_upper_enum_field(
        fields,
        "status",
        _TRANSACTION_STATUS_ALIASES,
        TRANSACTION_STATUSES,
        options,
        result,
        index,
        required=True,
    )

    if status:
        out["status"] = status

    channel = _normalize_upper_enum_field(
        fields,
        "channel",
        _CHANNEL_ALIASES,
        CHANNELS,
        options,
        result,
        index,
        required=True,
    )

    if channel:
        out["channel"] = channel

    metadata = _normalize_metadata_field(fields, options, result, index)

    if metadata is not None:
        out["metadata_json"] = metadata

    return out


def _normalize_complaint(
    fields: Mapping[str, Any],
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> dict[str, Any]:
    """
    Normalize one synthetic complaint record.

    `narrative_raw` is retained for downstream controlled persistence but is
    never returned in public summaries.
    """
    out: dict[str, Any] = {}

    complaint_id = _normalize_identifier_field(
        fields,
        "id",
        options,
        result,
        index,
        required=True,
    )

    if complaint_id:
        out["id"] = complaint_id

    reference = _normalize_reference_field(
        fields,
        "reference",
        options,
        result,
        index,
        required=False,
    )

    if reference:
        out["reference"] = reference

    reported_at = _normalize_datetime_field(
        fields,
        "reported_at",
        options,
        result,
        index,
        required=True,
    )

    if reported_at:
        out["reported_at"] = reported_at

    category = _normalize_lower_enum_field(
        fields,
        "category",
        _COMPLAINT_CATEGORY_ALIASES,
        COMPLAINT_CATEGORIES,
        options,
        result,
        index,
        required=True,
    )

    if category:
        out["category"] = category

    narrative = _normalize_narrative_field(
        fields,
        "narrative_raw",
        options,
        result,
        index,
    )

    if narrative:
        out["narrative_raw"] = narrative

    transaction_reference = _normalize_reference_field(
        fields,
        "transaction_reference",
        options,
        result,
        index,
        required=False,
    )

    if transaction_reference:
        out["transaction_reference"] = transaction_reference

    victim_account_id = _normalize_identifier_field(
        fields,
        "victim_account_id",
        options,
        result,
        index,
        required=False,
    )

    if victim_account_id:
        out["victim_account_id"] = victim_account_id

    suspected_account_id = _normalize_identifier_field(
        fields,
        "suspected_account_id",
        options,
        result,
        index,
        required=False,
    )

    if suspected_account_id:
        out["suspected_account_id"] = suspected_account_id

    amount = _normalize_amount_field(
        fields,
        "amount",
        options,
        result,
        index,
        required=False,
    )

    if amount:
        out["amount"] = amount

    currency = _normalize_currency_field(
        fields,
        "currency",
        options,
        result,
        index,
        amount_present=amount is not None,
    )

    if currency:
        out["currency"] = currency

    source = _normalize_source_field(fields, "source", options, result, index)

    if source:
        out["source"] = source

    metadata = _normalize_metadata_field(fields, options, result, index)

    if metadata is not None:
        out["metadata_json"] = metadata

    return out


def _normalize_entity(
    fields: Mapping[str, Any],
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> dict[str, Any]:
    """
    Normalize one pseudonymous synthetic entity record.

    Raw identifiers are never accepted.
    """
    out: dict[str, Any] = {}

    entity_id = _normalize_identifier_field(
        fields,
        "id",
        options,
        result,
        index,
        required=True,
    )

    if entity_id:
        out["id"] = entity_id

    entity_type = _normalize_upper_enum_field(
        fields,
        "entity_type",
        _ENTITY_TYPE_ALIASES,
        ENTITY_TYPES,
        options,
        result,
        index,
        required=True,
    )

    if entity_type:
        out["entity_type"] = entity_type

    identifier_hash = _normalize_identifier_hash_field(
        fields,
        "identifier_hash",
        options,
        result,
        index,
    )

    if identifier_hash:
        out["identifier_hash"] = identifier_hash

    identifier_display = _normalize_display_field(
        fields,
        "identifier_display",
        options,
        result,
        index,
    )

    if identifier_display:
        out["identifier_display"] = identifier_display

    source = _normalize_source_field(fields, "source", options, result, index)

    if source:
        out["source"] = source

    first_seen_at = _normalize_datetime_field(
        fields,
        "first_seen_at",
        options,
        result,
        index,
        required=False,
    )

    if first_seen_at:
        out["first_seen_at"] = first_seen_at

    last_seen_at = _normalize_datetime_field(
        fields,
        "last_seen_at",
        options,
        result,
        index,
        required=False,
    )

    if last_seen_at:
        out["last_seen_at"] = last_seen_at

    metadata = _normalize_metadata_field(fields, options, result, index)

    if metadata is not None:
        out["metadata_json"] = metadata

    return out


def _normalize_entity_link(
    fields: Mapping[str, Any],
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> dict[str, Any]:
    """
    Normalize one synthetic account-entity link record.

    Links are investigative associations only.
    """
    out: dict[str, Any] = {}

    link_id = _normalize_identifier_field(
        fields,
        "id",
        options,
        result,
        index,
        required=True,
    )

    if link_id:
        out["id"] = link_id

    account_id = _normalize_identifier_field(
        fields,
        "account_id",
        options,
        result,
        index,
        required=True,
    )

    if account_id:
        out["account_id"] = account_id

    entity_id = _normalize_identifier_field(
        fields,
        "entity_id",
        options,
        result,
        index,
        required=True,
    )

    if entity_id:
        out["entity_id"] = entity_id

    match_method = _normalize_upper_enum_field(
        fields,
        "match_method",
        _MATCH_METHOD_ALIASES,
        MATCH_METHODS,
        options,
        result,
        index,
        required=True,
    )

    if match_method:
        out["match_method"] = match_method

    confidence = _normalize_confidence_field(
        fields,
        "confidence",
        options,
        result,
        index,
    )

    if confidence:
        out["confidence"] = confidence

    verification_state = _normalize_upper_enum_field(
        fields,
        "verification_state",
        _VERIFICATION_STATE_ALIASES,
        VERIFICATION_STATES,
        options,
        result,
        index,
        required=False,
    )

    if verification_state:
        out["verification_state"] = verification_state

    valid_from = _normalize_datetime_field(
        fields,
        "valid_from",
        options,
        result,
        index,
        required=True,
    )

    if valid_from:
        out["valid_from"] = valid_from

    valid_to = _normalize_datetime_field(
        fields,
        "valid_to",
        options,
        result,
        index,
        required=False,
    )

    if valid_to:
        out["valid_to"] = valid_to

    source = _normalize_source_field(fields, "source", options, result, index)

    if source:
        out["source"] = source

    metadata = _normalize_metadata_field(fields, options, result, index)

    if metadata is not None:
        out["metadata_json"] = metadata

    return out


_RECORD_NORMALIZERS = {
    "accounts": _normalize_account,
    "transactions": _normalize_transaction,
    "complaints": _normalize_complaint,
    "entities": _normalize_entity,
    "entity_links": _normalize_entity_link,
}


# -----------------------------------------------------------------------------
# Record and batch normalization
# -----------------------------------------------------------------------------


def _normalize_one_record(
    entity_type: str,
    record: Any,
    options: NormalizationOptions,
    result: NormalizationResult,
    index: int,
) -> Optional[dict[str, Any]]:
    """
    Normalize one record.

    Returns None when the record has normalization errors and should not be
    passed to strict validation or persistence.
    """
    fields = _extract_allowed_fields(record, entity_type, options, result, index)

    if fields is None:
        result.rejected.append(index)
        return None

    start_errors = result._error_count
    normalizer = _RECORD_NORMALIZERS.get(entity_type)

    if normalizer is None:
        result.add_error(
            code="unsupported_entity_type",
            message="Unsupported ingestion entity type.",
            index=index,
        )
        result.rejected.append(index)
        return None

    normalized = normalizer(fields, options, result, index)

    if result._error_count != start_errors:
        result.rejected.append(index)
        return None

    if not normalized:
        result.add_error(
            code="empty_record",
            message="Record normalized to an empty object.",
            index=index,
        )
        result.rejected.append(index)
        return None

    return normalized


def normalize_ingestion_batch(
    entity_type: str,
    records: Any,
    options: NormalizationOptions | None = None,
) -> NormalizationResult:
    """
    Normalize one bounded ingestion batch.

    Args:
        entity_type: One of accounts, transactions, complaints, entities,
            entity_links.
        records: Sequence of record mappings, or a single mapping.
        options: Optional normalization policy. Resolved from settings when
            absent.

    Returns:
        NormalizationResult with normalized records and safe issues.
    """
    opts = options or NormalizationOptions.from_settings()
    normalized_type = _normalize_entity_type(entity_type)

    result = NormalizationResult(
        entity_type=normalized_type,
        max_errors=opts.max_errors_returned,
        max_warnings=opts.max_warnings_returned,
    )

    if normalized_type not in ALLOWED_FIELDS:
        result.add_error(
            code="unsupported_entity_type",
            message="Unsupported ingestion entity type.",
            details={"allowed_entity_types": list(SUPPORTED_INGESTION_ENTITY_TYPES)},
        )
        result.finalize(opts)
        return result

    record_list = _as_record_sequence(records)
    result.submitted = len(record_list)

    if result.submitted > opts.max_batch_size:
        result.add_error(
            code="batch_too_large",
            message="Batch exceeds configured maximum size.",
            details={
                "submitted": result.submitted,
                "max_batch_size": opts.max_batch_size,
            },
        )
        result.rejected.extend(range(result.submitted))
        result.finalize(opts)
        return result

    for index, raw_record in enumerate(record_list):
        if result._error_truncated:
            result.rejected.extend(range(index, result.submitted))
            break

        normalized = _normalize_one_record(
            normalized_type,
            raw_record,
            opts,
            result,
            index,
        )

        if normalized is not None:
            result.normalized.append(normalized)

    result.finalize(opts)
    return result


def normalize_ingestion_records(
    entity_type: str,
    records: Any,
    options: NormalizationOptions | None = None,
) -> NormalizationResult:
    """
    Alias for `normalize_ingestion_batch`.
    """
    return normalize_ingestion_batch(entity_type, records, options=options)


def _options_with_payload_overrides(
    options: NormalizationOptions,
    overrides: Any,
) -> NormalizationOptions:
    """
    Apply only safe payload-level overrides.

    Clients must not be able to raise hard limits.
    """
    if not isinstance(overrides, Mapping):
        return options

    updates: dict[str, Any] = {}

    if "source_system" in overrides:
        source = _clean_text(overrides["source_system"], MAX_SOURCE_LENGTH)
        updates["source_system"] = source or options.source_system

    if "default_currency" in overrides:
        currency = _normalize_currency(overrides["default_currency"])
        updates["default_currency"] = currency or options.default_currency

    if "fill_default_currency" in overrides:
        updates["fill_default_currency"] = overrides["fill_default_currency"]

    if not updates:
        return options

    return replace(options, **updates)


def normalize_ingestion_payload(
    entity_type: str,
    payload: Any,
    options: NormalizationOptions | None = None,
) -> NormalizationResult:
    """
    Normalize an ingestion payload shaped like:

        {
          "records": [...],
          "options": {"source_system": "seed"}
        }

    or a bare list/mapping of records.
    """
    opts = options or NormalizationOptions.from_settings()

    if isinstance(payload, Mapping):
        records = payload.get("records", payload.get("items", []))
        payload_options = payload.get("options")
        opts = _options_with_payload_overrides(opts, payload_options)
    else:
        records = payload

    return normalize_ingestion_batch(entity_type, records, options=opts)


def normalize_account_records(
    records: Any,
    options: NormalizationOptions | None = None,
) -> NormalizationResult:
    """
    Normalize synthetic account records.
    """
    return normalize_ingestion_batch("accounts", records, options=options)


def normalize_transaction_records(
    records: Any,
    options: NormalizationOptions | None = None,
) -> NormalizationResult:
    """
    Normalize synthetic transaction records.
    """
    return normalize_ingestion_batch("transactions", records, options=options)


def normalize_complaint_records(
    records: Any,
    options: NormalizationOptions | None = None,
) -> NormalizationResult:
    """
    Normalize synthetic complaint records.
    """
    return normalize_ingestion_batch("complaints", records, options=options)


def normalize_entity_records(
    records: Any,
    options: NormalizationOptions | None = None,
) -> NormalizationResult:
    """
    Normalize pseudonymous synthetic entity records.
    """
    return normalize_ingestion_batch("entities", records, options=options)


def normalize_entity_link_records(
    records: Any,
    options: NormalizationOptions | None = None,
) -> NormalizationResult:
    """
    Normalize synthetic account-entity link records.
    """
    return normalize_ingestion_batch("entity_links", records, options=options)


# -----------------------------------------------------------------------------
# Optional stateful normalizer wrapper
# -----------------------------------------------------------------------------


class IngestionNormalizer:
    """
    Stateless wrapper around ingestion normalization.

    This is provided for API/service symmetry with `IngestionValidator`.
    """

    def __init__(self, options: NormalizationOptions | None = None) -> None:
        self.options = options or NormalizationOptions.from_settings()

    def normalize_batch(
        self,
        entity_type: str,
        records: Any,
    ) -> NormalizationResult:
        """
        Normalize one batch.
        """
        return normalize_ingestion_batch(
            entity_type,
            records,
            options=self.options,
        )

    def normalize_payload(
        self,
        entity_type: str,
        payload: Any,
    ) -> NormalizationResult:
        """
        Normalize one payload.
        """
        return normalize_ingestion_payload(
            entity_type,
            payload,
            options=self.options,
        )


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_ingestion_normalizer_metadata() -> dict[str, Any]:
    """
    Return safe, serializable ingestion-normalizer metadata.

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
    default_options = NormalizationOptions()

    return {
        "package": "muleguard.backend.ingestion.normalizers",
        "version": NORMALIZERS_VERSION,
        "supported_entity_types": list(SUPPORTED_INGESTION_ENTITY_TYPES),
        "default_options": default_options.safe_summary(),
        "hard_limits": {
            "max_batch_size": HARD_MAX_BATCH_SIZE,
            "max_errors_returned": HARD_MAX_ERRORS_RETURNED,
            "max_warnings_returned": HARD_MAX_WARNINGS_RETURNED,
            "max_string_length": HARD_MAX_STRING_LENGTH,
            "max_id_length": HARD_MAX_ID_LENGTH,
            "max_reference_length": HARD_MAX_REFERENCE_LENGTH,
            "max_narrative_length": HARD_MAX_NARRATIVE_LENGTH,
            "max_metadata_depth": HARD_MAX_METADATA_DEPTH,
            "max_list_length": HARD_MAX_LIST_LENGTH,
            "max_mapping_keys": HARD_MAX_MAPPING_KEYS,
        },
        "forbidden_top_level_key_count": len(FORBIDDEN_TOP_LEVEL_KEYS),
        "caveats": list(_NORMALIZER_CAVEATS),
        "safety_flags": {
            "synthetic_only_by_default": True,
            "no_real_customer_data_by_default": True,
            "no_ground_truth_labels_accepted": True,
            "no_scenario_ids_accepted": True,
            "no_fraud_ring_ids_accepted": True,
            "no_raw_identifier_fields_accepted": True,
            "no_raw_narrative_in_summaries": True,
            "no_secrets_in_summaries": True,
            "bounded_normalization_required": True,
            "deterministic_normalization": True,
            "unknown_fields_dropped_by_default": True,
            "no_automatic_adverse_customer_action": True,
            "not_production_ready": True,
        },
    }


__all__ = [
    "IngestionNormalizer",
    "NORMALIZERS_VERSION",
    "NormalizationIssue",
    "NormalizationOptions",
    "NormalizationResult",
    "get_ingestion_normalizer_metadata",
    "normalize_account_records",
    "normalize_complaint_records",
    "normalize_entity_link_records",
    "normalize_entity_records",
    "normalize_ingestion_batch",
    "normalize_ingestion_payload",
    "normalize_ingestion_records",
    "normalize_transaction_records",
]