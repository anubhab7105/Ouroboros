"""
MULEGUARD backend transactions service.

This module provides the canonical bounded synthetic transaction profiling,
normalization, linkage, aggregation, and summarization service for the
MULEGUARD investigative prototype.

Primary responsibilities:

- normalize bounded synthetic transaction records into privacy-preserving
  transaction profiles using salted one-way pseudonymous references;
- derive bounded directed transfer edges between pseudonymous counterparties
  without retaining raw account identifiers, raw transaction identifiers, raw
  narratives, raw monetary amounts, or raw timestamps;
- canonicalize transaction status, channel, payment rail, direction, currency,
  amount bucket, and temporal bucket signals using deterministic bounded maps;
- compute bounded investigative priority scores and tiers for human review
  triage only, with explicit non-calibration and non-adverse-action caveats;
- maintain a bounded process-local transaction profile and edge registry for
  local prototype workflows, tests, developer tooling, and offline evaluation
  harnesses;
- expose a safe service descriptor compatible with the MULEGUARD backend
  services registry when available;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module profiles and summarizes synthetic transactions only. It does not
authenticate users, authorize actions, freeze accounts, block accounts,
blacklist accounts, close accounts, restrict services, deny services, terminate
relationships, suspend accounts, refer matters to law enforcement, make credit,
employment, housing, insurance, benefits, or other consequential decisions,
train models, deploy models, persist durable artifacts, call external systems,
or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for transaction profiling.
- Transaction profiles, edges, and priority scores are investigative leads or
  human workflow artefacts only. They are not proof of wrongdoing.
- Priority scores and tiers are not probabilities of guilt.
- Labels must never be used as transaction features or priority criteria.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected.
- Raw complaint narratives, descriptions, notes, and free-text fields are
  forbidden inputs and are never read, hashed, stored, logged, or returned.
- Raw account identifiers and raw transaction identifiers are not retained.
  They are hashed immediately into salted pseudonymous references.
- Raw monetary amounts are not retained. Only bounded ordinal amount buckets are
  emitted, and amounts are never converted or blended across currencies.
- Raw timestamps are not retained. Only bounded month, weekday, and hour-bucket
  signals are emitted.
- Transaction operations must never trigger automatic adverse customer action
  such as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable transaction signals are reported honestly as
  unavailable rather than invented.
- The bundled transaction registry is process-local, non-durable, and bounded
  for local prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external payment networks, core banking systems,
  card schemes, UPI switches, wallets, ledgers, graph databases, model runtimes,
  or network APIs.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models or transaction decisioning rules.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable transaction store.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, cycle
candidates, community candidates, filtered graphs, serialized graphs,
correlation candidates, confidence records, account profiles, transaction
profiles, transaction edges, priority scores, explanations, validation reports,
and case dispositions are investigative leads or human workflow artefacts only.
They are not proof of wrongdoing and must not trigger automatic adverse customer
action.
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
from decimal import Decimal, InvalidOperation
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Final, Optional

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


logger = logging.getLogger("muleguard.backend.services.transactions")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

TRANSACTIONS_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.services.transactions.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

DEFAULT_MAX_TRANSACTIONS: Final[int] = 10_000
HARD_MAX_TRANSACTIONS: Final[int] = 100_000

DEFAULT_MAX_EDGES: Final[int] = 50_000
HARD_MAX_EDGES: Final[int] = 500_000

DEFAULT_MAX_PROFILES: Final[int] = 10_000
HARD_MAX_PROFILES: Final[int] = 100_000

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

DEFAULT_MAX_TIME_MS: Final[int] = 30_000
HARD_MAX_TIME_MS: Final[int] = 300_000

MAX_TEXT_LENGTH: Final[int] = 512
MAX_HASH_LENGTH: Final[int] = 256
MAX_REASON_TEXT_LENGTH: Final[int] = 300
MAX_MAPPING_ITEMS: Final[int] = 100

DEFAULT_LOW_THRESHOLD: Final[float] = 0.20
DEFAULT_MODERATE_THRESHOLD: Final[float] = 0.40
DEFAULT_ELEVATED_THRESHOLD: Final[float] = 0.65

DEFAULT_PRIORITY_AMOUNT_WEIGHT: Final[float] = 0.40
DEFAULT_PRIORITY_DEGREE_WEIGHT: Final[float] = 0.20
DEFAULT_PRIORITY_EDGE_WEIGHT: Final[float] = 0.15
DEFAULT_PRIORITY_TEMPORAL_WEIGHT: Final[float] = 0.15
DEFAULT_PRIORITY_STATUS_WEIGHT: Final[float] = 0.10

MAX_COUNTERPARTY_DEGREE: Final[int] = 50
MAX_INCIDENT_EDGE_SCORE: Final[float] = 10.0

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")
_NUMERIC_CLEAN_RE: Final[re.Pattern[str]] = re.compile(r"[^\d.\-]")

_MISSING: Final[object] = object()

TXN_REF_KEYS: Final[tuple[str, ...]] = (
    "transaction_ref_hash",
    "transaction_hash",
    "reference_hash",
    "txn_ref_hash",
)

RAW_TXN_KEYS: Final[tuple[str, ...]] = (
    "transaction_id",
    "txn_id",
    "id",
    "uuid",
    "guid",
)

SENDER_KEYS: Final[tuple[str, ...]] = (
    "sender_account_id",
    "sender_acct_id",
    "from_account_id",
    "source_account_id",
    "sender",
    "from",
    "src_account",
    "debit_account_id",
)

RECEIVER_KEYS: Final[tuple[str, ...]] = (
    "receiver_account_id",
    "receiver_acct_id",
    "to_account_id",
    "target_account_id",
    "receiver",
    "to",
    "dst_account",
    "credit_account_id",
)

AMOUNT_KEYS: Final[tuple[str, ...]] = (
    "amount",
    "value",
    "transaction_amount",
    "txn_amount",
)

CURRENCY_KEYS: Final[tuple[str, ...]] = (
    "currency",
    "ccy",
    "currency_code",
)

OCCURRED_KEYS: Final[tuple[str, ...]] = (
    "occurred_at",
    "timestamp",
    "time",
    "date",
    "transaction_date",
    "posted_at",
    "booked_at",
)

STATUS_KEYS: Final[tuple[str, ...]] = (
    "status",
    "transaction_status",
    "txn_status",
    "state",
)

CHANNEL_KEYS: Final[tuple[str, ...]] = (
    "channel",
    "source_channel",
    "access_channel",
    "origination_channel",
)

RAIL_KEYS: Final[tuple[str, ...]] = (
    "rail",
    "payment_rail",
    "network",
    "instrument",
    "scheme",
)

DIRECTION_KEYS: Final[tuple[str, ...]] = (
    "direction",
    "txn_direction",
    "transaction_direction",
)

NON_FEATURE_KEYS: Final[frozenset[str]] = frozenset(
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

FORBIDDEN_TXN_FIELDS: Final[frozenset[str]] = frozenset(
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
        "content",
        "cookie",
        "credential",
        "credentials",
        "cvv",
        "database_url",
        "description",
        "details",
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
        "notes",
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
        "summary",
        "text",
        "token",
        "truth_label",
        "upi_id",
    }
)

FORBIDDEN_TXN_TOKENS: Final[tuple[str, ...]] = (
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
    "description",
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
    "customer_data",
    "real_data",
    "amount_raw",
    "raw_amount",
    "currency_raw",
    "raw_currency",
    "timestamp_raw",
    "raw_timestamp",
)

LABEL_LEAKAGE_FIELDS: Final[frozenset[str]] = frozenset(
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

LABEL_LEAKAGE_TOKENS: Final[tuple[str, ...]] = (
    "ground_truth",
    "truth_label",
    "fraud_label",
    "is_fraud",
    "scenario_id",
    "ring_id",
    "fraud_ring",
    "synthetic_label",
)

SENSITIVE_DETAIL_TOKENS: Final[tuple[str, ...]] = (
    "access_key",
    "account_id",
    "account_number",
    "amount",
    "api_key",
    "apikey",
    "artifact_path",
    "authorization",
    "balance",
    "card_number",
    "connection_string",
    "credential",
    "currency",
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
    "monetary_value",
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
    "timestamp",
    "token",
    "transaction_id",
    "transaction_amount",
    "truth_label",
    "upi_id",
    "value",
)

PROHIBITED_ACTION_TOKENS: Final[tuple[str, ...]] = (
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
    "terminated",
    "suspend",
    "suspended",
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

TRANSACTION_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic transaction profiling only. Do not use with real customer data.",
    "Transaction profiles, edges, and priority scores are investigative leads only and are not proof of wrongdoing.",
    "Priority scores and tiers are not probabilities of guilt.",
    "Transaction profiling must not trigger automatic adverse customer action.",
    "Labels must never be used as transaction features or priority criteria.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives, descriptions, notes, secrets, tokens, passwords, database URLs, filesystem paths, and model artifact paths are forbidden.",
    "Raw account identifiers and raw transaction identifiers are not retained. They are hashed immediately into salted pseudonymous references.",
    "Raw monetary amounts are not retained. Only bounded ordinal amount buckets are emitted.",
    "Currency amounts are never converted or blended across currencies.",
    "Raw timestamps are not retained. Only bounded month, weekday, and hour-bucket signals are emitted.",
    "The bundled transaction registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

TRANSACTION_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_raw_identifiers_retained": True,
        "no_raw_narratives_retained": True,
        "no_raw_monetary_values_retained": True,
        "no_raw_timestamps_retained": True,
        "salted_pseudonymous_transaction_references": True,
        "salted_pseudonymous_party_references": True,
        "no_labels_as_features": True,
        "no_ground_truth_fields_accepted": True,
        "no_fraud_label_fields_accepted": True,
        "no_scenario_ids_accepted": True,
        "no_fraud_ring_ids_accepted": True,
        "no_secrets_accepted": True,
        "no_tokens_accepted": True,
        "no_passwords_accepted": True,
        "no_database_urls_accepted": True,
        "no_filesystem_paths_accepted": True,
        "no_model_artifact_paths_accepted": True,
        "deterministic_transaction_profiling": True,
        "bounded_transaction_profiling_required": True,
        "no_cross_currency_blending": True,
        "priority_is_investigative_only": True,
        "priority_is_not_probability_of_guilt": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)

CRITICAL_TRUE_SAFETY_FLAGS: Final[tuple[str, ...]] = (
    "synthetic_only_by_default",
    "no_real_customer_data_by_default",
    "no_automatic_adverse_customer_action",
    "human_review_required_for_consequential_action",
    "not_production_ready",
)

TRANSACTION_STATUS_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "completed": "COMPLETED",
        "complete": "COMPLETED",
        "settled": "COMPLETED",
        "posted": "COMPLETED",
        "booked": "COMPLETED",
        "success": "COMPLETED",
        "successful": "COMPLETED",
        "processed": "COMPLETED",
        "pending": "PENDING",
        "processing": "PENDING",
        "initiated": "PENDING",
        "in_progress": "PENDING",
        "queued": "PENDING",
        "failed": "FAILED",
        "failure": "FAILED",
        "declined": "FAILED",
        "rejected": "FAILED",
        "bounced": "FAILED",
        "error": "FAILED",
        "reversed": "REVERSED",
        "reversal": "REVERSED",
        "refunded": "REVERSED",
        "refund": "REVERSED",
        "chargeback": "REVERSED",
        "cancelled": "REVERSED",
        "canceled": "REVERSED",
        "void": "REVERSED",
    }
)

TRANSACTION_CHANNEL_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "digital": "DIGITAL",
        "online": "DIGITAL",
        "mobile": "DIGITAL",
        "web": "DIGITAL",
        "internet": "DIGITAL",
        "branch": "BRANCH",
        "branch_office": "BRANCH",
        "atm": "ATM",
        "agent": "AGENT",
        "banking_correspondent": "AGENT",
        "correspondent": "AGENT",
        "api": "API",
        "batch": "BATCH",
        "bulk": "BATCH",
        "pos": "POS",
        "terminal": "POS",
        "card_present": "POS",
        "other": "OTHER",
    }
)

PAYMENT_RAIL_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "card": "CARD",
        "credit_card": "CARD",
        "debit_card": "CARD",
        "upi": "UPI",
        "netbanking": "NETBANKING",
        "net_banking": "NETBANKING",
        "wallet": "WALLET",
        "neft": "NEFT",
        "rtgs": "RTGS",
        "imps": "IMPS",
        "cash": "CASH",
        "cheque": "CHEQUE",
        "check": "CHEQUE",
        "internal": "INTERNAL",
        "book_transfer": "INTERNAL",
        "other": "OTHER",
    }
)

DIRECTION_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "debit": "DEBIT",
        "credit": "CREDIT",
        "transfer": "TRANSFER",
        "sent": "DEBIT",
        "received": "CREDIT",
        "outgoing": "DEBIT",
        "incoming": "CREDIT",
    }
)

AMOUNT_BUCKET_SPECS: Final[tuple[tuple[Optional[Decimal], str, int, float], ...]] = (
    (Decimal("1"), "micro", 1, 0.15),
    (Decimal("10"), "small", 2, 0.30),
    (Decimal("100"), "moderate", 3, 0.50),
    (Decimal("1000"), "large", 4, 0.70),
    (Decimal("10000"), "very_large", 5, 0.85),
    (None, "extreme", 6, 1.00),
)

COUNT_BUCKET_SPECS: Final[tuple[tuple[Optional[int], str, float], ...]] = (
    (0, "zero", 0.00),
    (9, "low", 0.20),
    (99, "moderate", 0.45),
    (999, "elevated", 0.70),
    (9999, "high", 0.90),
    (None, "very_high", 1.00),
)

_ALL_TXN_VIEW_KEYS: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            *TXN_REF_KEYS,
            *RAW_TXN_KEYS,
            *SENDER_KEYS,
            *RECEIVER_KEYS,
            *AMOUNT_KEYS,
            *CURRENCY_KEYS,
            *OCCURRED_KEYS,
            *STATUS_KEYS,
            *CHANNEL_KEYS,
            *RAIL_KEYS,
            *DIRECTION_KEYS,
        }
    )
)

_TXN_LIKE_KEYS: Final[frozenset[str]] = frozenset(_ALL_TXN_VIEW_KEYS)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class TransactionStatus(str, Enum):
    """
    Bounded observational transaction status.
    """

    COMPLETED = "completed"
    PENDING = "pending"
    FAILED = "failed"
    REVERSED = "reversed"
    UNKNOWN = "unknown"


class TransactionChannel(str, Enum):
    """
    Bounded transaction origination or access channel.
    """

    DIGITAL = "digital"
    BRANCH = "branch"
    ATM = "atm"
    AGENT = "agent"
    API = "api"
    BATCH = "batch"
    POS = "pos"
    OTHER = "other"
    UNKNOWN = "unknown"


class PaymentRail(str, Enum):
    """
    Bounded payment rail or instrument.
    """

    CARD = "card"
    UPI = "upi"
    NETBANKING = "netbanking"
    WALLET = "wallet"
    NEFT = "neft"
    RTGS = "rtgs"
    IMPS = "imps"
    CASH = "cash"
    CHEQUE = "cheque"
    INTERNAL = "internal"
    OTHER = "other"
    UNKNOWN = "unknown"


class TransactionDirection(str, Enum):
    """
    Bounded directional hint.

    Direction is descriptive only and must not be interpreted as authorization
    to take adverse action.
    """

    DEBIT = "debit"
    CREDIT = "credit"
    TRANSFER = "transfer"
    UNKNOWN = "unknown"


class PriorityTier(str, Enum):
    """
    Bounded investigative priority tier.

    Tiers are human-review triage labels only. They are not probabilities of
    guilt and must not trigger automatic adverse action.
    """

    LOW = "low"
    MODERATE = "moderate"
    ELEVATED = "elevated"
    HIGH = "high"
    UNSCORED = "unscoped"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ServiceStatus(str, Enum):
    """
    Overall transactions service status.
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


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return default


def _as_float(value: object, default: float = 0.0) -> float:
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return default

    if math.isnan(result) or math.isinf(result):
        return default

    return result


def _clamp_int(value: object, minimum: int, maximum: int, default: int) -> int:
    return max(minimum, min(_as_int(value, default), maximum))


def _clamp_float(value: object, minimum: float, maximum: float, default: float) -> float:
    parsed = _as_float(value, default)

    if math.isnan(parsed) or math.isinf(parsed):
        return default

    return max(minimum, min(maximum, parsed))


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


def _clean_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
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


def _canonical_field_name(key: Any) -> str:
    return _normalize_token(key)


def _is_safe_hash(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and _HASH_RE.match(text))


def _is_forbidden_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in FORBIDDEN_TXN_FIELDS:
        return True

    if canonical.startswith("raw_") or canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in FORBIDDEN_TXN_TOKENS)


def _is_label_leakage_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in LABEL_LEAKAGE_FIELDS:
        return True

    return any(token in canonical for token in LABEL_LEAKAGE_TOKENS)


def _is_sensitive_detail_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)
    return bool(canonical) and any(token in canonical for token in SENSITIVE_DETAIL_TOKENS)


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

    if callable(value):
        return "<callable>"

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:MAX_MAPPING_ITEMS]:
            key = _clean_text(raw_key, 128)

            if (
                not key
                or _is_sensitive_detail_key(key)
                or _is_forbidden_key(key)
                or _is_label_leakage_key(key)
            ):
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:MAX_MAPPING_ITEMS]]

    return f"<{type(value).__name__}>"


def _as_mapping(value: Any) -> dict[str, Any]:
    sanitized = _safe_detail_value(value)
    return sanitized if isinstance(sanitized, dict) else {}


def _as_counts(value: Any) -> Mapping[str, int]:
    if not isinstance(value, Mapping):
        return MappingProxyType({})

    return MappingProxyType(
        {
            str(key): max(0, _as_int(item, 0))
            for key, item in list(value.items())[:1_000]
        }
    )


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

    if callable(value):
        return "<callable>"

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


def _account_ref_hash(value: Any, options: "TransactionsServiceOptions") -> Optional[str]:
    text = _clean_text(value, MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.services.transactions.account.{namespace}"
    return _hmac_hex(options.salt, domain, text)[:40]


def _transaction_ref_hash(value: Any, options: "TransactionsServiceOptions") -> Optional[str]:
    text = _clean_text(value, MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.services.transactions.transaction.{namespace}"
    return _hmac_hex(options.salt, domain, text)[:40]


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
            for raw_key, raw_value in list(value.items())[:MAX_MAPPING_ITEMS]:
                parts.append(str(raw_key))
                visit(raw_value, depth + 1)
            return

        if isinstance(value, (list, tuple, set, frozenset)):
            for item in list(value)[:MAX_MAPPING_ITEMS]:
                visit(item, depth + 1)
            return

        if callable(value):
            return

        parts.append(str(value))

    for value in values:
        visit(value)

    text = " ".join(parts).lower()
    return bool(text) and any(token in text for token in PROHIBITED_ACTION_TOKENS)


def _normalize_tags(value: Any, limit: int = 100) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        tag = _clean_text(item, 128)

        if tag:
            out.append(tag)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


def _pick(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]

    return None


def _get_value(obj: Any, keys: Sequence[str]) -> Any:
    if isinstance(obj, Mapping):
        return _pick(obj, keys)

    for key in keys:
        try:
            value = getattr(obj, key, None)
        except Exception:
            value = None

        if value is not None:
            return value

    return None


def _coerce_non_negative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0

    return max(0, _as_int(value, 0))


def _parse_decimal_abs(value: Any) -> Optional[Decimal]:
    if isinstance(value, bool):
        return None

    if isinstance(value, Decimal):
        return abs(value) if value.is_finite() else None

    if isinstance(value, (int, float)):
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError, OverflowError):
            return None

        return abs(parsed) if parsed.is_finite() else None

    if isinstance(value, Enum):
        return _parse_decimal_abs(value.value)

    if isinstance(value, str):
        text = _normalize_unicode(value).strip()

        if not text:
            return None

        cleaned = _NUMERIC_CLEAN_RE.sub("", text)

        if not cleaned:
            return None

        try:
            parsed = Decimal(cleaned)
        except (InvalidOperation, ValueError, OverflowError):
            return None

        return abs(parsed) if parsed.is_finite() else None

    return None


def _normalize_currency(value: Any) -> Optional[str]:
    text = _normalize_unicode(value).strip().upper()
    text = re.sub(r"[^A-Z]", "", text)

    if _CURRENCY_RE.match(text):
        return text

    return None


def _hour_bucket(hour: int) -> str:
    safe_hour = max(0, min(23, int(hour)))

    if safe_hour <= 3:
        return "00-03"

    if safe_hour <= 7:
        return "04-07"

    if safe_hour <= 11:
        return "08-11"

    if safe_hour <= 15:
        return "12-15"

    if safe_hour <= 19:
        return "16-19"

    return "20-23"


def _timestamp_parts(value: Any) -> tuple[Optional[str], Optional[int], Optional[str]]:
    parsed = _parse_datetime(value)

    if parsed is None:
        return None, None, None

    month = parsed.strftime("%Y-%m")
    weekday = int(parsed.weekday())
    hour = int(parsed.hour)

    return month, weekday, _hour_bucket(hour)


def _amount_bucket(amount: Optional[Decimal]) -> tuple[str, int, float]:
    if amount is None:
        return "unknown", -1, 0.0

    if amount == 0:
        return "zero", 0, 0.0

    if amount < 0:
        amount = abs(amount)

    for bound, label, ordinal, score in AMOUNT_BUCKET_SPECS:
        if bound is None or amount < bound:
            return label, ordinal, score

    return "extreme", 6, 1.0


def _bucket_count(count: int) -> tuple[str, float]:
    safe_count = max(0, int(count))

    for upper, label, score in COUNT_BUCKET_SPECS:
        if upper is None or safe_count <= upper:
            return label, score

    return "very_high", 1.0


def _dominant(counter: Counter[str]) -> Optional[str]:
    if not counter:
        return None

    return max(counter.items(), key=lambda item: (item[1], item[0]))[0]


def _prefer_value(existing: Any, incoming: Any) -> Any:
    unknown_values = {"", "unknown", "none", "null", "-1"}

    existing_text = _clean_text(existing, 128).lower()
    incoming_text = _clean_text(incoming, 128).lower()

    if existing_text in unknown_values and incoming_text not in unknown_values:
        return incoming

    return existing


def _safe_reasons(value: Any, limit: int = 50) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        reason = _clean_text(item, MAX_REASON_TEXT_LENGTH)

        if not reason:
            continue

        lowered = reason.lower()

        if any(token in lowered for token in PROHIBITED_ACTION_TOKENS):
            continue

        out.append(reason)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


# -----------------------------------------------------------------------------
# Issue model and helpers
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TransactionIssue:
    """
    Safe transaction-service issue.

    Issues never contain raw identifiers, raw narratives, raw labels, raw
    monetary values, raw timestamps, secrets, tokens, passwords, database URLs,
    filesystem paths, model artifact paths, or executable handler references.
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
            _normalize_enum_option(IssueSeverity, self.severity, IssueSeverity.WARNING),
        )
        object.__setattr__(self, "code", _clean_text(self.code, 100))
        object.__setattr__(self, "message", _clean_text(self.message, MAX_REASON_TEXT_LENGTH))
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


def _coerce_issue(value: Any) -> TransactionIssue:
    if isinstance(value, TransactionIssue):
        return value

    if isinstance(value, Mapping):
        return TransactionIssue(
            severity=value.get("severity", IssueSeverity.WARNING),
            code=value.get("code", "unstructured_issue"),
            message=value.get("message", ""),
            field=value.get("field"),
            details=value.get("details", {}),
        )

    return TransactionIssue(
        severity=IssueSeverity.WARNING,
        code="unstructured_issue",
        message=_clean_text(value, MAX_REASON_TEXT_LENGTH),
    )


def _append_issue(
    issues: list[TransactionIssue],
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

        issues[-1] = TransactionIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        TransactionIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, MAX_REASON_TEXT_LENGTH),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[TransactionIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[TransactionIssue]) -> tuple[TransactionIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[TransactionIssue] = []

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
class TransactionsServiceOptions:
    """
    Bounded synthetic transactions service policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    max_transactions: int = DEFAULT_MAX_TRANSACTIONS
    max_edges: int = DEFAULT_MAX_EDGES
    max_profiles: int = DEFAULT_MAX_PROFILES
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS

    include_edges: bool = True
    include_priority: bool = True
    register_profiles: bool = True
    drop_forbidden_fields: bool = True

    low_threshold: float = DEFAULT_LOW_THRESHOLD
    moderate_threshold: float = DEFAULT_MODERATE_THRESHOLD
    elevated_threshold: float = DEFAULT_ELEVATED_THRESHOLD

    priority_amount_weight: float = DEFAULT_PRIORITY_AMOUNT_WEIGHT
    priority_degree_weight: float = DEFAULT_PRIORITY_DEGREE_WEIGHT
    priority_edge_weight: float = DEFAULT_PRIORITY_EDGE_WEIGHT
    priority_temporal_weight: float = DEFAULT_PRIORITY_TEMPORAL_WEIGHT
    priority_status_weight: float = DEFAULT_PRIORITY_STATUS_WEIGHT

    def __post_init__(self) -> None:
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_token(self.dataset_mode) or "synthetic")
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(self, "salt", _ensure_salt(self.salt))
        object.__setattr__(self, "namespace", _normalize_token(self.namespace) or _DEFAULT_NAMESPACE)
        object.__setattr__(self, "seed", int(self.seed))

        object.__setattr__(
            self,
            "max_transactions",
            _clamp_int(self.max_transactions, 1, HARD_MAX_TRANSACTIONS, DEFAULT_MAX_TRANSACTIONS),
        )
        object.__setattr__(
            self,
            "max_edges",
            _clamp_int(self.max_edges, 0, HARD_MAX_EDGES, DEFAULT_MAX_EDGES),
        )
        object.__setattr__(
            self,
            "max_profiles",
            _clamp_int(self.max_profiles, 1, HARD_MAX_PROFILES, DEFAULT_MAX_PROFILES),
        )
        object.__setattr__(
            self,
            "max_issues",
            _clamp_int(self.max_issues, 1, HARD_MAX_ISSUES, DEFAULT_MAX_ISSUES),
        )
        object.__setattr__(
            self,
            "max_summary_items",
            _clamp_int(
                self.max_summary_items,
                1,
                HARD_MAX_SUMMARY_ITEMS,
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
        )
        object.__setattr__(
            self,
            "max_time_ms",
            _clamp_int(self.max_time_ms, 100, HARD_MAX_TIME_MS, DEFAULT_MAX_TIME_MS),
        )

        object.__setattr__(self, "include_edges", _as_bool(self.include_edges, True))
        object.__setattr__(self, "include_priority", _as_bool(self.include_priority, True))
        object.__setattr__(self, "register_profiles", _as_bool(self.register_profiles, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, True))

        low = _round6(_clamp_float(self.low_threshold, 0.0, 1.0, DEFAULT_LOW_THRESHOLD))
        moderate = _round6(
            _clamp_float(
                self.moderate_threshold,
                low,
                1.0,
                max(low, DEFAULT_MODERATE_THRESHOLD),
            )
        )
        elevated = _round6(
            _clamp_float(
                self.elevated_threshold,
                moderate,
                1.0,
                max(moderate, DEFAULT_ELEVATED_THRESHOLD),
            )
        )

        object.__setattr__(self, "low_threshold", low)
        object.__setattr__(self, "moderate_threshold", moderate)
        object.__setattr__(self, "elevated_threshold", elevated)

        amount_w = _clamp_float(self.priority_amount_weight, 0.0, 1.0, DEFAULT_PRIORITY_AMOUNT_WEIGHT)
        degree_w = _clamp_float(self.priority_degree_weight, 0.0, 1.0, DEFAULT_PRIORITY_DEGREE_WEIGHT)
        edge_w = _clamp_float(self.priority_edge_weight, 0.0, 1.0, DEFAULT_PRIORITY_EDGE_WEIGHT)
        temporal_w = _clamp_float(self.priority_temporal_weight, 0.0, 1.0, DEFAULT_PRIORITY_TEMPORAL_WEIGHT)
        status_w = _clamp_float(self.priority_status_weight, 0.0, 1.0, DEFAULT_PRIORITY_STATUS_WEIGHT)

        total = amount_w + degree_w + edge_w + temporal_w + status_w

        if total <= 0.0:
            amount_w = DEFAULT_PRIORITY_AMOUNT_WEIGHT
            degree_w = DEFAULT_PRIORITY_DEGREE_WEIGHT
            edge_w = DEFAULT_PRIORITY_EDGE_WEIGHT
            temporal_w = DEFAULT_PRIORITY_TEMPORAL_WEIGHT
            status_w = DEFAULT_PRIORITY_STATUS_WEIGHT
            total = amount_w + degree_w + edge_w + temporal_w + status_w

        object.__setattr__(self, "priority_amount_weight", _round6(amount_w / total))
        object.__setattr__(self, "priority_degree_weight", _round6(degree_w / total))
        object.__setattr__(self, "priority_edge_weight", _round6(edge_w / total))
        object.__setattr__(self, "priority_temporal_weight", _round6(temporal_w / total))
        object.__setattr__(self, "priority_status_weight", _round6(status_w / total))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "TransactionsServiceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "TRANSACTIONS_SERVICE_SALT", None)
            or _setting(settings, "SERVICES_TRANSACTIONS_SALT", None)
            or _setting(settings, "ACCOUNTS_SERVICE_SALT", None)
            or _setting(settings, "CORRELATION_SERVICE_SALT", None)
            or _setting(settings, "CORRELATION_SALT", None)
            or _setting(settings, "GRAPH_CYCLE_SALT", None)
            or _setting(settings, "ML_VALIDATION_SALT", None)
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
            enabled=_as_bool(_setting(settings, "TRANSACTIONS_SERVICE_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "TRANSACTIONS_SERVICE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "TRANSACTIONS_SERVICE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "TRANSACTIONS_SERVICE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "TRANSACTIONS_SERVICE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_transactions=_as_int(
                _setting(settings, "TRANSACTIONS_SERVICE_MAX_TRANSACTIONS", DEFAULT_MAX_TRANSACTIONS),
                DEFAULT_MAX_TRANSACTIONS,
            ),
            max_edges=_as_int(
                _setting(settings, "TRANSACTIONS_SERVICE_MAX_EDGES", DEFAULT_MAX_EDGES),
                DEFAULT_MAX_EDGES,
            ),
            max_profiles=_as_int(
                _setting(settings, "TRANSACTIONS_SERVICE_MAX_PROFILES", DEFAULT_MAX_PROFILES),
                DEFAULT_MAX_PROFILES,
            ),
            max_issues=_as_int(
                _setting(settings, "TRANSACTIONS_SERVICE_MAX_ISSUES", DEFAULT_MAX_ISSUES),
                DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "TRANSACTIONS_SERVICE_MAX_SUMMARY_ITEMS", DEFAULT_MAX_SUMMARY_ITEMS),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "TRANSACTIONS_SERVICE_MAX_TIME_MS", DEFAULT_MAX_TIME_MS),
                DEFAULT_MAX_TIME_MS,
            ),
            include_edges=_as_bool(_setting(settings, "TRANSACTIONS_SERVICE_INCLUDE_EDGES", True), True),
            include_priority=_as_bool(_setting(settings, "TRANSACTIONS_SERVICE_INCLUDE_PRIORITY", True), True),
            register_profiles=_as_bool(
                _setting(settings, "TRANSACTIONS_SERVICE_REGISTER_PROFILES", True),
                True,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "TRANSACTIONS_SERVICE_DROP_FORBIDDEN_FIELDS", True),
                True,
            ),
            low_threshold=_as_float(
                _setting(settings, "TRANSACTIONS_SERVICE_LOW_THRESHOLD", DEFAULT_LOW_THRESHOLD),
                DEFAULT_LOW_THRESHOLD,
            ),
            moderate_threshold=_as_float(
                _setting(settings, "TRANSACTIONS_SERVICE_MODERATE_THRESHOLD", DEFAULT_MODERATE_THRESHOLD),
                DEFAULT_MODERATE_THRESHOLD,
            ),
            elevated_threshold=_as_float(
                _setting(settings, "TRANSACTIONS_SERVICE_ELEVATED_THRESHOLD", DEFAULT_ELEVATED_THRESHOLD),
                DEFAULT_ELEVATED_THRESHOLD,
            ),
            priority_amount_weight=_as_float(
                _setting(settings, "TRANSACTIONS_SERVICE_PRIORITY_AMOUNT_WEIGHT", DEFAULT_PRIORITY_AMOUNT_WEIGHT),
                DEFAULT_PRIORITY_AMOUNT_WEIGHT,
            ),
            priority_degree_weight=_as_float(
                _setting(settings, "TRANSACTIONS_SERVICE_PRIORITY_DEGREE_WEIGHT", DEFAULT_PRIORITY_DEGREE_WEIGHT),
                DEFAULT_PRIORITY_DEGREE_WEIGHT,
            ),
            priority_edge_weight=_as_float(
                _setting(settings, "TRANSACTIONS_SERVICE_PRIORITY_EDGE_WEIGHT", DEFAULT_PRIORITY_EDGE_WEIGHT),
                DEFAULT_PRIORITY_EDGE_WEIGHT,
            ),
            priority_temporal_weight=_as_float(
                _setting(settings, "TRANSACTIONS_SERVICE_PRIORITY_TEMPORAL_WEIGHT", DEFAULT_PRIORITY_TEMPORAL_WEIGHT),
                DEFAULT_PRIORITY_TEMPORAL_WEIGHT,
            ),
            priority_status_weight=_as_float(
                _setting(settings, "TRANSACTIONS_SERVICE_PRIORITY_STATUS_WEIGHT", DEFAULT_PRIORITY_STATUS_WEIGHT),
                DEFAULT_PRIORITY_STATUS_WEIGHT,
            ),
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
                "max_transactions": self.max_transactions,
                "max_edges": self.max_edges,
                "max_profiles": self.max_profiles,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
            },
            "priority": {
                "include_priority": self.include_priority,
                "low_threshold": _round6(self.low_threshold),
                "moderate_threshold": _round6(self.moderate_threshold),
                "elevated_threshold": _round6(self.elevated_threshold),
                "weights": {
                    "amount": _round6(self.priority_amount_weight),
                    "degree": _round6(self.priority_degree_weight),
                    "edge": _round6(self.priority_edge_weight),
                    "temporal": _round6(self.priority_temporal_weight),
                    "status": _round6(self.priority_status_weight),
                },
            },
            "flags": {
                "include_edges": self.include_edges,
                "register_profiles": self.register_profiles,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
            "monetary_policy": "bounded_amount_buckets_only_no_raw_values_no_cross_currency_blending",
            "temporal_policy": "bounded_month_weekday_hour_buckets_only_no_raw_timestamps",
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "transactions",
        "transfers",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class TransactionsRequest:
    """
    Bounded synthetic transactions service request.
    """

    transactions: Any = None
    transfers: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> TransactionsRequest:
    if isinstance(request, TransactionsRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(TransactionsRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return TransactionsRequest(**clean)
            except Exception:
                return TransactionsRequest(
                    transactions=payload.get("transactions", payload.get("transfers", request))
                )

        if any(_canonical_field_name(key) in _TXN_LIKE_KEYS for key in payload):
            return TransactionsRequest(transactions=[payload])

        return TransactionsRequest(metadata=request)

    if isinstance(request, (list, tuple, set, frozenset)):
        return TransactionsRequest(transactions=request)

    return TransactionsRequest(transactions=request)


# -----------------------------------------------------------------------------
# Public models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TransactionEdge:
    """
    One bounded directed synthetic transfer edge.

    Edges are structural association hints only. They are not proof of common
    control, wrongdoing, or criminal association.
    """

    edge_id: str = ""
    source_ref_hash: str = ""
    target_ref_hash: str = ""
    currency: str = "UNKNOWN"
    count_bucket: str = "zero"
    count_score: float = 0.0
    amount_bucket: str = "unknown"
    amount_score: float = 0.0
    first_month: Optional[str] = None
    last_month: Optional[str] = None
    dominant_status: TransactionStatus | str = TransactionStatus.UNKNOWN
    dominant_channel: TransactionChannel | str = TransactionChannel.UNKNOWN
    dominant_rail: PaymentRail | str = PaymentRail.UNKNOWN
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source_ref_hash",
            _clean_text(self.source_ref_hash, MAX_HASH_LENGTH).lower(),
        )
        object.__setattr__(
            self,
            "target_ref_hash",
            _clean_text(self.target_ref_hash, MAX_HASH_LENGTH).lower(),
        )

        currency_text = _clean_text(self.currency, 16).upper()
        object.__setattr__(self, "currency", currency_text or "UNKNOWN")

        object.__setattr__(self, "count_bucket", _normalize_token(self.count_bucket) or "zero")
        object.__setattr__(self, "count_score", _round6(_clip_float(self.count_score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "amount_bucket", _normalize_token(self.amount_bucket) or "unknown")
        object.__setattr__(self, "amount_score", _round6(_clip_float(self.amount_score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "first_month", _clean_text(self.first_month, 7) or None)
        object.__setattr__(self, "last_month", _clean_text(self.last_month, 7) or None)
        object.__setattr__(
            self,
            "dominant_status",
            _normalize_enum_option(TransactionStatus, self.dominant_status, TransactionStatus.UNKNOWN),
        )
        object.__setattr__(
            self,
            "dominant_channel",
            _normalize_enum_option(TransactionChannel, self.dominant_channel, TransactionChannel.UNKNOWN),
        )
        object.__setattr__(
            self,
            "dominant_rail",
            _normalize_enum_option(PaymentRail, self.dominant_rail, PaymentRail.UNKNOWN),
        )
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.edge_id:
            object.__setattr__(
                self,
                "edge_id",
                _fingerprint_payload(
                    {
                        "source": self.source_ref_hash,
                        "target": self.target_ref_hash,
                        "currency": self.currency,
                        "count_bucket": self.count_bucket,
                        "amount_bucket": self.amount_bucket,
                    }
                )[:32],
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_ref_hash": self.source_ref_hash,
            "target_ref_hash": self.target_ref_hash,
            "currency": self.currency,
            "count_bucket": self.count_bucket,
            "count_score": float(self.count_score),
            "amount_bucket": self.amount_bucket,
            "amount_score": float(self.amount_score),
            "first_month": self.first_month,
            "last_month": self.last_month,
            "dominant_status": _enum_value(self.dominant_status, TransactionStatus.UNKNOWN.value),
            "dominant_channel": _enum_value(self.dominant_channel, TransactionChannel.UNKNOWN.value),
            "dominant_rail": _enum_value(self.dominant_rail, PaymentRail.UNKNOWN.value),
            "metadata": _safe_detail_value(self.metadata),
            "raw_identifiers_retained": False,
            "raw_monetary_values_retained": False,
            "raw_timestamps_retained": False,
            "cross_currency_blending_performed": False,
            "association_is_not_proof_of_common_control": True,
        }


@dataclass(frozen=True, slots=True)
class TransactionProfile:
    """
    One bounded synthetic transaction profile.

    Profiles are investigative human-workflow artefacts only. They are not
    proof of wrongdoing and must not trigger automatic adverse action.
    """

    transaction_ref_hash: str = ""
    sender_ref_hash: Optional[str] = None
    receiver_ref_hash: Optional[str] = None
    status: TransactionStatus | str = TransactionStatus.UNKNOWN
    channel: TransactionChannel | str = TransactionChannel.UNKNOWN
    rail: PaymentRail | str = PaymentRail.UNKNOWN
    direction: TransactionDirection | str = TransactionDirection.UNKNOWN
    occurred_month: Optional[str] = None
    occurred_weekday: Optional[int] = None
    occurred_hour_bucket: Optional[str] = None
    currency: Optional[str] = None
    amount_bucket: str = "unknown"
    amount_ordinal: int = -1
    amount_score: float = 0.0
    priority_score: float = 0.0
    priority_tier: PriorityTier | str = PriorityTier.UNSCORED
    priority_reasons: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "transaction_ref_hash",
            _clean_text(self.transaction_ref_hash, MAX_HASH_LENGTH).lower(),
        )
        object.__setattr__(
            self,
            "sender_ref_hash",
            _clean_text(self.sender_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(
            self,
            "receiver_ref_hash",
            _clean_text(self.receiver_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(TransactionStatus, self.status, TransactionStatus.UNKNOWN),
        )
        object.__setattr__(
            self,
            "channel",
            _normalize_enum_option(TransactionChannel, self.channel, TransactionChannel.UNKNOWN),
        )
        object.__setattr__(
            self,
            "rail",
            _normalize_enum_option(PaymentRail, self.rail, PaymentRail.UNKNOWN),
        )
        object.__setattr__(
            self,
            "direction",
            _normalize_enum_option(TransactionDirection, self.direction, TransactionDirection.UNKNOWN),
        )
        object.__setattr__(self, "occurred_month", _clean_text(self.occurred_month, 7) or None)

        weekday = self.occurred_weekday

        if weekday is None:
            object.__setattr__(self, "occurred_weekday", None)
        else:
            parsed_weekday = _as_int(weekday, -1)
            object.__setattr__(
                self,
                "occurred_weekday",
                parsed_weekday if 0 <= parsed_weekday <= 6 else None,
            )

        object.__setattr__(self, "occurred_hour_bucket", _clean_text(self.occurred_hour_bucket, 8) or None)

        currency_text = _clean_text(self.currency, 16).upper()
        object.__setattr__(self, "currency", currency_text or None)

        object.__setattr__(self, "amount_bucket", _normalize_token(self.amount_bucket) or "unknown")
        object.__setattr__(self, "amount_ordinal", max(-1, min(6, _as_int(self.amount_ordinal, -1))))
        object.__setattr__(self, "amount_score", _round6(_clip_float(self.amount_score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "priority_score", _round6(_clip_float(self.priority_score, 0.0, 1.0, 0.0)))
        object.__setattr__(
            self,
            "priority_tier",
            _normalize_enum_option(PriorityTier, self.priority_tier, PriorityTier.UNSCORED),
        )
        object.__setattr__(self, "priority_reasons", _safe_reasons(self.priority_reasons, limit=50))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "transaction_ref_hash": self.transaction_ref_hash,
            "sender_ref_hash": self.sender_ref_hash,
            "receiver_ref_hash": self.receiver_ref_hash,
            "status": _enum_value(self.status, TransactionStatus.UNKNOWN.value),
            "channel": _enum_value(self.channel, TransactionChannel.UNKNOWN.value),
            "rail": _enum_value(self.rail, PaymentRail.UNKNOWN.value),
            "direction": _enum_value(self.direction, TransactionDirection.UNKNOWN.value),
            "occurred_month": self.occurred_month,
            "occurred_weekday": self.occurred_weekday,
            "occurred_hour_bucket": self.occurred_hour_bucket,
            "currency": self.currency,
            "amount_bucket": self.amount_bucket,
            "amount_ordinal": int(self.amount_ordinal),
            "amount_score": float(self.amount_score),
            "priority_score": float(self.priority_score),
            "priority_tier": _enum_value(self.priority_tier, PriorityTier.UNSCORED.value),
            "priority_reasons": list(self.priority_reasons),
            "metadata": _safe_detail_value(self.metadata),
            "priority_semantics": "investigative_human_review_triage_only_not_probability_of_guilt",
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "raw_monetary_values_retained": False,
            "raw_timestamps_retained": False,
            "cross_currency_blending_performed": False,
            "labels_used_as_features": False,
            "caveats": list(TRANSACTION_CAVEATS),
            "safety_flags": dict(TRANSACTION_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class TransactionsResult:
    """
    Safe bounded transactions service result.
    """

    ok: bool = True
    status: ServiceStatus | str = ServiceStatus.PASSED
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    profiles: tuple[TransactionProfile, ...] = ()
    edges: tuple[TransactionEdge, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[TransactionIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(ServiceStatus, self.status, ServiceStatus.PASSED),
        )
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "profiles", tuple(self.profiles or ()))
        object.__setattr__(self, "edges", tuple(self.edges or ()))
        object.__setattr__(self, "counts", _as_counts(self.counts))
        object.__setattr__(
            self,
            "issues",
            tuple(_coerce_issue(issue) for issue in (self.issues or ())),
        )
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": TRANSACTIONS_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, ServiceStatus.PASSED.value),
                        "request_id": self.request_id,
                        "profile_count": len(self.profiles),
                        "profile_hashes": [
                            profile.transaction_ref_hash for profile in self.profiles[:64]
                        ],
                        "edge_count": len(self.edges),
                        "edge_ids": [edge.edge_id for edge in self.edges[:64]],
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": bool(self.ok),
            "status": _enum_value(self.status, ServiceStatus.PASSED.value),
            "request_id": self.request_id,
            "generated_at": self.generated_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "profiles": [profile.to_dict() for profile in self.profiles],
            "edges": [edge.to_dict() for edge in self.edges],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(TRANSACTION_CAVEATS),
            "safety_flags": dict(TRANSACTION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local transaction registry
# -----------------------------------------------------------------------------


class TransactionRegistry:
    """
    Bounded process-local transaction profile and edge registry.

    This registry is non-durable and intended for local prototype workflows,
    tests, developer tooling, and offline evaluation harnesses only.
    """

    def __init__(
        self,
        max_profiles: int = DEFAULT_MAX_PROFILES,
        max_edges: int = DEFAULT_MAX_EDGES,
    ) -> None:
        self.max_profiles = max(1, int(max_profiles))
        self.max_edges = max(0, int(max_edges))
        self._profiles: dict[str, TransactionProfile] = {}
        self._profile_order: list[str] = []
        self._edges: dict[str, TransactionEdge] = {}
        self._edge_order: list[str] = []
        self._lock = threading.RLock()

    def register_profile(self, profile: TransactionProfile) -> str:
        profile_hash = _clean_text(profile.transaction_ref_hash, MAX_HASH_LENGTH).lower()

        if not profile_hash:
            return ""

        with self._lock:
            if profile_hash in self._profiles:
                self._profiles[profile_hash] = profile

                if profile_hash in self._profile_order:
                    self._profile_order.remove(profile_hash)

                self._profile_order.append(profile_hash)
                return profile_hash

            if len(self._profile_order) >= self.max_profiles:
                evicted = self._profile_order.pop(0)
                self._profiles.pop(evicted, None)

            self._profiles[profile_hash] = profile
            self._profile_order.append(profile_hash)
            return profile_hash

    def register_edge(self, edge: TransactionEdge) -> str:
        edge_id = _clean_text(edge.edge_id, 128)

        if not edge_id or self.max_edges <= 0:
            return ""

        with self._lock:
            if edge_id in self._edges:
                self._edges[edge_id] = edge

                if edge_id in self._edge_order:
                    self._edge_order.remove(edge_id)

                self._edge_order.append(edge_id)
                return edge_id

            if len(self._edge_order) >= self.max_edges:
                evicted = self._edge_order.pop(0)
                self._edges.pop(evicted, None)

            self._edges[edge_id] = edge
            self._edge_order.append(edge_id)
            return edge_id

    def get_profile(self, transaction_ref_hash: Any) -> Optional[TransactionProfile]:
        key = _clean_text(transaction_ref_hash, MAX_HASH_LENGTH).lower()

        with self._lock:
            return self._profiles.get(key)

    def list_profiles(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> tuple[TransactionProfile, ...]:
        count = max(0, int(limit))

        with self._lock:
            if count == 0:
                return ()

            return tuple(
                self._profiles[profile_hash]
                for profile_hash in self._profile_order[:count]
                if profile_hash in self._profiles
            )

    def list_edges(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> tuple[TransactionEdge, ...]:
        count = max(0, int(limit))

        with self._lock:
            if count == 0:
                return ()

            return tuple(
                self._edges[edge_id]
                for edge_id in self._edge_order[:count]
                if edge_id in self._edges
            )

    def search_profiles(
        self,
        *,
        status: Any = None,
        channel: Any = None,
        rail: Any = None,
        direction: Any = None,
        currency: Any = None,
        amount_bucket: Any = None,
        min_priority: Optional[float] = None,
        max_priority: Optional[float] = None,
        limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    ) -> tuple[TransactionProfile, ...]:
        normalized_status = (
            _normalize_enum_option(TransactionStatus, status, None)
            if status is not None
            else None
        )
        normalized_channel = (
            _normalize_enum_option(TransactionChannel, channel, None)
            if channel is not None
            else None
        )
        normalized_rail = (
            _normalize_enum_option(PaymentRail, rail, None)
            if rail is not None
            else None
        )
        normalized_direction = (
            _normalize_enum_option(TransactionDirection, direction, None)
            if direction is not None
            else None
        )
        normalized_currency = (
            _clean_text(currency, 16).upper()
            if currency is not None
            else None
        )
        normalized_amount_bucket = (
            _normalize_token(amount_bucket)
            if amount_bucket is not None
            else None
        )
        min_score = _clip_float(min_priority, 0.0, 1.0, 0.0) if min_priority is not None else None
        max_score = _clip_float(max_priority, 0.0, 1.0, 1.0) if max_priority is not None else None
        count = max(0, int(limit))

        with self._lock:
            candidates = list(self._profiles.values())

        filtered: list[TransactionProfile] = []

        for profile in candidates:
            if normalized_status is not None and profile.status != normalized_status:
                continue

            if normalized_channel is not None and profile.channel != normalized_channel:
                continue

            if normalized_rail is not None and profile.rail != normalized_rail:
                continue

            if normalized_direction is not None and profile.direction != normalized_direction:
                continue

            if normalized_currency is not None and profile.currency != normalized_currency:
                continue

            if normalized_amount_bucket is not None and profile.amount_bucket != normalized_amount_bucket:
                continue

            if min_score is not None and float(profile.priority_score) < float(min_score):
                continue

            if max_score is not None and float(profile.priority_score) > float(max_score):
                continue

            filtered.append(profile)

        filtered.sort(
            key=lambda profile: (
                -float(profile.priority_score),
                -float(profile.amount_score),
                profile.transaction_ref_hash,
            )
        )

        return tuple(filtered[:count])

    def summarize_profiles(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> list[dict[str, Any]]:
        return [profile.to_dict() for profile in self.list_profiles(limit=limit)]

    def summarize_edges(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> list[dict[str, Any]]:
        return [edge.to_dict() for edge in self.list_edges(limit=limit)]

    def clear(self) -> None:
        with self._lock:
            self._profiles.clear()
            self._profile_order.clear()
            self._edges.clear()
            self._edge_order.clear()

    def safe_summary(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
        with self._lock:
            status_counter = Counter(
                _enum_value(profile.status, TransactionStatus.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            channel_counter = Counter(
                _enum_value(profile.channel, TransactionChannel.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            rail_counter = Counter(
                _enum_value(profile.rail, PaymentRail.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            amount_counter = Counter(profile.amount_bucket for profile in self._profiles.values())
            currency_counter = Counter(
                profile.currency or "UNKNOWN"
                for profile in self._profiles.values()
            )
            tier_counter = Counter(
                _enum_value(profile.priority_tier, PriorityTier.UNSCORED.value)
                for profile in self._profiles.values()
            )
            edge_currency_counter = Counter(edge.currency for edge in self._edges.values())

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_profiles": self.max_profiles,
            "max_edges": self.max_edges,
            "registered_profiles": len(self._profile_order),
            "registered_edges": len(self._edge_order),
            "by_status": dict(status_counter),
            "by_channel": dict(channel_counter),
            "by_rail": dict(rail_counter),
            "by_amount_bucket": dict(amount_counter),
            "by_currency": dict(currency_counter),
            "by_priority_tier": dict(tier_counter),
            "edges_by_currency": dict(edge_currency_counter),
            "recent_profiles": self.summarize_profiles(limit=limit),
            "recent_edges": self.summarize_edges(limit=min(limit, 20)),
            "raw_identifiers_retained": False,
            "raw_monetary_values_retained": False,
            "raw_timestamps_retained": False,
        }


_default_registry: Optional[TransactionRegistry] = None
_default_registry_lock = threading.Lock()


def get_transaction_registry(
    max_profiles: int | None = None,
    max_edges: int | None = None,
    *,
    rebuild: bool = False,
) -> TransactionRegistry:
    """
    Return a process-wide bounded transaction registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = TransactionRegistry(
                max_profiles=max_profiles if max_profiles is not None else DEFAULT_MAX_PROFILES,
                max_edges=max_edges if max_edges is not None else DEFAULT_MAX_EDGES,
            )

        return _default_registry


# -----------------------------------------------------------------------------
# View extraction and sanitization
# -----------------------------------------------------------------------------


def _extract_view(record: Any, keys: Sequence[str]) -> dict[str, Any]:
    view: dict[str, Any] = {}

    if isinstance(record, Mapping):
        for raw_key, raw_value in record.items():
            key = _canonical_field_name(raw_key)

            if not key or key in NON_FEATURE_KEYS:
                continue

            view.setdefault(key, raw_value)

        for container in ("features", "values"):
            nested = record.get(container)

            if not isinstance(nested, Mapping):
                continue

            for raw_key, raw_value in nested.items():
                key = _canonical_field_name(raw_key)

                if key and key not in NON_FEATURE_KEYS:
                    view[key] = raw_value
    else:
        for key in keys:
            try:
                value = getattr(record, key, None)
            except Exception:
                continue

            if value is not None:
                view[key] = value

        nested = getattr(record, "features", None)

        if isinstance(nested, Mapping):
            for raw_key, raw_value in nested.items():
                key = _canonical_field_name(raw_key)

                if key and key not in NON_FEATURE_KEYS:
                    view[key] = raw_value

    return view


def _clean_view(
    view: Mapping[str, Any],
    options: TransactionsServiceOptions,
    issues: list[TransactionIssue],
    context: Mapping[str, Any],
) -> Optional[dict[str, Any]]:
    clean: dict[str, Any] = {}

    for raw_key in sorted(view):
        raw_value = view[raw_key]
        canonical = _canonical_field_name(raw_key)

        if not canonical or canonical in NON_FEATURE_KEYS:
            continue

        if _is_forbidden_key(canonical) or _is_label_leakage_key(canonical):
            if options.drop_forbidden_fields:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="forbidden_transaction_field_dropped",
                    message="Forbidden or leakage-prone transaction field omitted.",
                    field=canonical,
                    details=dict(context),
                )
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_transaction_field",
                message="Forbidden or leakage-prone transaction field rejected.",
                field=canonical,
                details=dict(context),
            )
            return None

        clean[canonical] = raw_value

    return clean


def _normalize_transaction_status(
    value: Any,
    issues: list[TransactionIssue],
    options: TransactionsServiceOptions,
    context: Mapping[str, Any],
) -> TransactionStatus:
    text = _clean_text(value, 200)
    token = _normalize_token(text)

    if not token:
        return TransactionStatus.UNKNOWN

    if any(prohibited in token for prohibited in PROHIBITED_ACTION_TOKENS):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="unsupported_transaction_status_normalized_to_unknown",
            message="Transaction status contained adverse-action language and was normalized to unknown for safety.",
            field="status",
            details=dict(context),
        )
        return TransactionStatus.UNKNOWN

    mapped = TRANSACTION_STATUS_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(TransactionStatus, mapped, TransactionStatus.UNKNOWN)

    return _normalize_enum_option(TransactionStatus, token, TransactionStatus.UNKNOWN)


def _normalize_transaction_channel(value: Any) -> TransactionChannel:
    token = _normalize_token(value)

    if not token:
        return TransactionChannel.UNKNOWN

    mapped = TRANSACTION_CHANNEL_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(TransactionChannel, mapped, TransactionChannel.UNKNOWN)

    return _normalize_enum_option(TransactionChannel, token, TransactionChannel.UNKNOWN)


def _normalize_payment_rail(value: Any) -> PaymentRail:
    token = _normalize_token(value)

    if not token:
        return PaymentRail.UNKNOWN

    mapped = PAYMENT_RAIL_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(PaymentRail, mapped, PaymentRail.UNKNOWN)

    return _normalize_enum_option(PaymentRail, token, PaymentRail.UNKNOWN)


def _normalize_direction(value: Any) -> TransactionDirection:
    token = _normalize_token(value)

    if not token:
        return TransactionDirection.UNKNOWN

    mapped = DIRECTION_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(TransactionDirection, mapped, TransactionDirection.UNKNOWN)

    return _normalize_enum_option(TransactionDirection, token, TransactionDirection.UNKNOWN)


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, TransactionsResult):
        return []

    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "transactions", "transfers", "examples"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])

        return [data]

    for attr in ("transactions", "transfers", "records", "rows", "items"):
        try:
            value = getattr(data, attr, None)
        except Exception:
            value = None

        if value is not None and not isinstance(value, Mapping):
            return _as_sequence(value)

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray, memoryview)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _count_records_safe(value: Any) -> int:
    if value is None:
        return 0

    if isinstance(value, Mapping):
        for key in ("records", "rows", "items", "transactions", "transfers", "examples"):
            if key in value and isinstance(value[key], (list, tuple, set, frozenset)):
                return len(value[key])

        return 1

    if isinstance(value, (list, tuple, set, frozenset)):
        return len(value)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        try:
            return len(value)
        except Exception:
            return -1

    for attr in ("transactions", "transfers", "records", "rows", "items"):
        try:
            nested = getattr(value, attr, None)
        except Exception:
            nested = None

        if nested is None or isinstance(nested, Mapping):
            continue

        if isinstance(nested, (list, tuple, set, frozenset)):
            return len(nested)

        if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes, bytearray, memoryview)):
            try:
                return len(nested)
            except Exception:
                return -1

    return -1


# -----------------------------------------------------------------------------
# Transaction sanitization
# -----------------------------------------------------------------------------


def _synthesize_transaction_ref_hash(
    base: Mapping[str, Any],
    index: int,
    options: TransactionsServiceOptions,
) -> str:
    payload = {
        "version": TRANSACTIONS_VERSION,
        "namespace": _normalize_token(options.namespace) or _DEFAULT_NAMESPACE,
        "sender": base.get("sender_ref_hash") or "",
        "receiver": base.get("receiver_ref_hash") or "",
        "currency": base.get("currency") or "",
        "amount_bucket": base.get("amount_bucket") or "unknown",
        "occurred_month": base.get("occurred_month") or "",
        "occurred_hour_bucket": base.get("occurred_hour_bucket") or "",
        "status": base.get("status") or "",
        "channel": base.get("channel") or "",
        "rail": base.get("rail") or "",
        "direction": base.get("direction") or "",
        "index": int(index),
    }

    return _fingerprint_payload(payload)[:40]


def _sanitize_transaction(
    record: Any,
    options: TransactionsServiceOptions,
    issues: list[TransactionIssue],
    index: int,
    start_time: float,
) -> Optional[dict[str, Any]]:
    if _time_exceeded(start_time, options.max_time_ms):
        return None

    context = {"record_type": "transaction", "index": index}
    view = _extract_view(record, _ALL_TXN_VIEW_KEYS)
    clean = _clean_view(view, options, issues, context)

    if clean is None:
        return None

    non_status_clean = {
        key: value
        for key, value in clean.items()
        if key not in STATUS_KEYS
    }

    if _contains_prohibited_action(non_status_clean):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="prohibited_transaction_metadata",
            message="Transaction record contains prohibited adverse-action language.",
            details=context,
        )
        return None

    sender_raw = _pick(clean, SENDER_KEYS)
    receiver_raw = _pick(clean, RECEIVER_KEYS)

    if sender_raw is None and receiver_raw is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="missing_transaction_party",
            message="Transaction record is missing both sender and receiver party references.",
            field="sender_account_id",
            details=context,
        )
        return None

    sender_hash = _account_ref_hash(sender_raw, options) if sender_raw is not None else None
    receiver_hash = _account_ref_hash(receiver_raw, options) if receiver_raw is not None else None

    if sender_raw is not None and not sender_hash:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="unreadable_sender_reference",
            message="Sender reference could not be converted to a pseudonymous account hash.",
            field="sender_account_id",
            details=context,
        )
        return None

    if receiver_raw is not None and not receiver_hash:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="unreadable_receiver_reference",
            message="Receiver reference could not be converted to a pseudonymous account hash.",
            field="receiver_account_id",
            details=context,
        )
        return None

    txn_raw = _pick(clean, TXN_REF_KEYS)

    if txn_raw is None:
        txn_raw = _pick(clean, RAW_TXN_KEYS)

    txn_hash = _transaction_ref_hash(txn_raw, options) if txn_raw is not None else None

    amount_raw = _pick(clean, AMOUNT_KEYS)
    amount = _parse_decimal_abs(amount_raw)

    currency = _normalize_currency(_pick(clean, CURRENCY_KEYS))

    if amount is not None and currency is None:
        currency = "UNKNOWN"

    amount_bucket, amount_ordinal, amount_score = _amount_bucket(amount)

    status = _normalize_transaction_status(
        _pick(clean, STATUS_KEYS),
        issues,
        options,
        context,
    )
    channel = _normalize_transaction_channel(_pick(clean, CHANNEL_KEYS))
    rail = _normalize_payment_rail(_pick(clean, RAIL_KEYS))
    direction = _normalize_direction(_pick(clean, DIRECTION_KEYS))

    occurred_month, occurred_weekday, occurred_hour_bucket = _timestamp_parts(
        _pick(clean, OCCURRED_KEYS)
    )

    base = {
        "transaction_ref_hash": txn_hash or "",
        "sender_ref_hash": sender_hash,
        "receiver_ref_hash": receiver_hash,
        "status": _enum_value(status, TransactionStatus.UNKNOWN.value),
        "channel": _enum_value(channel, TransactionChannel.UNKNOWN.value),
        "rail": _enum_value(rail, PaymentRail.UNKNOWN.value),
        "direction": _enum_value(direction, TransactionDirection.UNKNOWN.value),
        "occurred_month": occurred_month,
        "occurred_weekday": occurred_weekday,
        "occurred_hour_bucket": occurred_hour_bucket,
        "currency": currency,
        "amount_bucket": amount_bucket,
        "amount_ordinal": amount_ordinal,
        "amount_score": amount_score,
        "source_indices": [index],
        "metadata": {
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "raw_monetary_values_retained": False,
            "raw_timestamps_retained": False,
            "labels_used_as_features": False,
            "cross_currency_blending_performed": False,
        },
    }

    if not base["transaction_ref_hash"]:
        base["transaction_ref_hash"] = _synthesize_transaction_ref_hash(base, index, options)

    return base


def _merge_transaction_base(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    for key in (
        "sender_ref_hash",
        "receiver_ref_hash",
        "currency",
        "status",
        "channel",
        "rail",
        "direction",
        "occurred_month",
        "occurred_weekday",
        "occurred_hour_bucket",
        "amount_bucket",
    ):
        existing[key] = _prefer_value(existing.get(key), incoming.get(key))

    existing_ordinal = max(-1, _as_int(existing.get("amount_ordinal"), -1))
    incoming_ordinal = max(-1, _as_int(incoming.get("amount_ordinal"), -1))

    if incoming_ordinal > existing_ordinal:
        existing["amount_ordinal"] = incoming_ordinal
        existing["amount_bucket"] = incoming.get("amount_bucket", existing.get("amount_bucket"))
        existing["amount_score"] = _clip_float(incoming.get("amount_score"), 0.0, 1.0, 0.0)

    existing_score = _clip_float(existing.get("amount_score"), 0.0, 1.0, 0.0)
    incoming_score = _clip_float(incoming.get("amount_score"), 0.0, 1.0, 0.0)

    if incoming_score > existing_score:
        existing["amount_score"] = incoming_score

    existing_month = existing.get("occurred_month")
    incoming_month = incoming.get("occurred_month")

    if incoming_month:
        if not existing_month or str(incoming_month) < str(existing_month):
            existing["occurred_month"] = incoming_month

    source_indices = existing.setdefault("source_indices", [])

    for source_index in incoming.get("source_indices", ()): 
        if source_index not in source_indices:
            source_indices.append(source_index)

        if len(source_indices) > 100:
            break

    return existing


# -----------------------------------------------------------------------------
# Priority scoring
# -----------------------------------------------------------------------------


def _temporal_anomaly_score(
    weekday: Optional[int],
    hour_bucket: Optional[str],
) -> float:
    score = 0.0

    if hour_bucket == "00-03":
        score = max(score, 0.60)
    elif hour_bucket == "20-23":
        score = max(score, 0.30)

    if weekday in {5, 6}:
        score = max(score, 0.20)

    return _round6(_clip_float(score, 0.0, 1.0, 0.0))


def _status_signal_score(status: Any) -> float:
    normalized = _normalize_enum_option(TransactionStatus, status, TransactionStatus.UNKNOWN)

    if normalized == TransactionStatus.REVERSED:
        return 0.50

    if normalized == TransactionStatus.FAILED:
        return 0.40

    if normalized == TransactionStatus.PENDING:
        return 0.10

    return 0.0


def _compute_transaction_priority(
    base: Mapping[str, Any],
    degree_score: float,
    edge_score: float,
    options: TransactionsServiceOptions,
) -> tuple[float, PriorityTier, tuple[str, ...]]:
    if not options.include_priority:
        return 0.0, PriorityTier.UNSCORED, ("priority_disabled",)

    amount_score = _clip_float(base.get("amount_score"), 0.0, 1.0, 0.0)
    temporal_score = _temporal_anomaly_score(
        base.get("occurred_weekday"),
        base.get("occurred_hour_bucket"),
    )
    status_score = _status_signal_score(base.get("status"))

    degree_score = _clip_float(degree_score, 0.0, 1.0, 0.0)
    edge_score = _clip_float(edge_score, 0.0, 1.0, 0.0)

    score = (
        amount_score * float(options.priority_amount_weight)
        + degree_score * float(options.priority_degree_weight)
        + edge_score * float(options.priority_edge_weight)
        + temporal_score * float(options.priority_temporal_weight)
        + status_score * float(options.priority_status_weight)
    )

    score = _round6(_clip_float(score, 0.0, 1.0, 0.0))

    if score <= 0.0:
        tier = PriorityTier.UNSCORED
    elif score >= float(options.elevated_threshold):
        tier = PriorityTier.HIGH
    elif score >= float(options.moderate_threshold):
        tier = PriorityTier.ELEVATED
    elif score >= float(options.low_threshold):
        tier = PriorityTier.MODERATE
    else:
        tier = PriorityTier.LOW

    reasons: list[str] = [
        "synthetic_structural_signals_only",
        "operational_lead_only_not_proof",
        "priority_is_not_probability_of_guilt",
        "no_automatic_adverse_action",
        "no_raw_monetary_values_used",
        "no_cross_currency_blending",
    ]

    if amount_score >= 0.70:
        reasons.append("high_amount_bucket")
    elif amount_score >= 0.45:
        reasons.append("moderate_amount_bucket")

    if degree_score >= 0.50:
        reasons.append("high_counterparty_degree")

    if edge_score >= 0.50:
        reasons.append("high_incident_edge_volume")

    if temporal_score >= 0.50:
        reasons.append("late_night_activity_bucket")
    elif temporal_score >= 0.20:
        reasons.append("weekend_or_evening_activity_bucket")

    if status_score >= 0.40:
        reasons.append("failed_or_reversed_status_signal")

    if score >= float(options.elevated_threshold):
        reasons.append("high_investigative_priority")

    return score, tier, tuple(dict.fromkeys(reasons))


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------


class TransactionsServiceEngine:
    """
    Bounded deterministic synthetic transactions service engine.
    """

    def __init__(
        self,
        options: TransactionsServiceOptions | None = None,
        registry: TransactionRegistry | None = None,
    ) -> None:
        self.options = options or TransactionsServiceOptions.from_settings()
        self.registry = registry or get_transaction_registry(
            max_profiles=self.options.max_profiles,
            max_edges=self.options.max_edges,
        )
        self._lock = threading.RLock()

    def normalize(self, request: Any) -> TransactionsResult:
        """
        Run one bounded synthetic transaction profiling job.
        """
        opts = self.options
        issues: list[TransactionIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)
        source = req.transactions if req.transactions is not None else req.transfers

        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": TRANSACTIONS_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                    "counts": {
                        "transactions": _count_records_safe(source),
                    },
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: ServiceStatus,
            profiles: Sequence[TransactionProfile] = (),
            edges: Sequence[TransactionEdge] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> TransactionsResult:
            resolved_counts: dict[str, int] = {
                "submitted_transactions": _count_records_safe(source),
                "sanitized_transactions": 0,
                "profiles": len(profiles),
                "edges": len(edges),
                "registered_profiles": 0,
                "registered_edges": 0,
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update(
                    {str(key): max(0, _as_int(value, 0)) for key, value in counts.items()}
                )

            resolved_counts["profiles"] = len(profiles)
            resolved_counts["edges"] = len(edges)
            resolved_counts["issues"] = len(issues)

            metadata = {
                "transactions_version": TRANSACTIONS_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "registry": self.registry.safe_summary(limit=opts.max_summary_items),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_identifiers_retained": False,
                "raw_narratives_retained": False,
                "raw_monetary_values_retained": False,
                "raw_timestamps_retained": False,
                "subject_label_pairs_retained": False,
                "secrets_retained": False,
                "labels_used_as_features": False,
                "cross_currency_blending_performed": False,
                "priority_semantics": "investigative_human_review_triage_only",
                "caveats": list(TRANSACTION_CAVEATS),
                "safety_flags": dict(TRANSACTION_SAFETY_FLAGS),
            }

            return TransactionsResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                profiles=tuple(profiles),
                edges=tuple(edges),
                counts=resolved_counts,
                issues=_dedupe_issues(issues)[: opts.max_issues],
                metadata=metadata,
                fingerprint="",
            )

        if not opts.enabled:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.INFO,
                code="transactions_service_disabled",
                message="Transactions service is disabled.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Transactions service requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Transactions service is blocked in production-like environments.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_transactions_action_metadata",
                message="Transactions request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        with self._lock:
            raw_transactions = _iter_records(source)[: opts.max_transactions]
            submitted = _count_records_safe(source)

            if submitted > int(opts.max_transactions):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="transactions_input_truncated",
                    message="Transaction input exceeded configured record limit and was truncated.",
                    details={
                        "submitted": submitted,
                        "max_transactions": int(opts.max_transactions),
                    },
                )

            bases: dict[str, dict[str, Any]] = {}
            sanitized = 0

            for index, record in enumerate(raw_transactions):
                if _time_exceeded(start_time, opts.max_time_ms):
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="transaction_sanitization_time_budget_exhausted",
                        message="Transaction sanitization stopped after reaching configured time budget.",
                        details={
                            "processed": sanitized,
                            "remaining": max(0, len(raw_transactions) - index),
                        },
                    )
                    break

                base = _sanitize_transaction(record, opts, issues, index, start_time)

                if base is None:
                    continue

                txn_hash = _clean_text(base.get("transaction_ref_hash"), MAX_HASH_LENGTH).lower()

                if not txn_hash:
                    continue

                existing = bases.get(txn_hash)

                if existing is None:
                    bases[txn_hash] = base
                else:
                    _merge_transaction_base(existing, base)

                sanitized += 1

            if len(bases) > int(opts.max_profiles):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="transaction_profiles_truncated_before_edges",
                    message="Transaction bases exceeded configured profile limit and were truncated.",
                    details={
                        "generated": len(bases),
                        "max_profiles": int(opts.max_profiles),
                    },
                )
                retained_hashes = sorted(bases)[: int(opts.max_profiles)]
                bases = {txn_hash: bases[txn_hash] for txn_hash in retained_hashes}

            edges_internal: dict[tuple[str, str, str], dict[str, Any]] = {}

            if opts.include_edges:
                for base in bases.values():
                    sender = base.get("sender_ref_hash")
                    receiver = base.get("receiver_ref_hash")

                    if not sender or not receiver or sender == receiver:
                        continue

                    currency = _clean_text(base.get("currency"), 16).upper() or "UNKNOWN"
                    key = (sender, receiver, currency)

                    agg = edges_internal.get(key)

                    if agg is None:
                        agg = {
                            "count": 0,
                            "max_amount_score": -1.0,
                            "max_amount_bucket": "unknown",
                            "first_month": None,
                            "last_month": None,
                            "status_counts": Counter(),
                            "channel_counts": Counter(),
                            "rail_counts": Counter(),
                        }
                        edges_internal[key] = agg

                    agg["count"] += 1

                    amount_score = _clip_float(base.get("amount_score"), 0.0, 1.0, 0.0)

                    if amount_score > float(agg["max_amount_score"]):
                        agg["max_amount_score"] = amount_score
                        agg["max_amount_bucket"] = _clean_text(base.get("amount_bucket"), 32) or "unknown"

                    month = base.get("occurred_month")

                    if month:
                        month_text = _clean_text(month, 7)

                        if not agg["first_month"] or month_text < str(agg["first_month"]):
                            agg["first_month"] = month_text

                        if not agg["last_month"] or month_text > str(agg["last_month"]):
                            agg["last_month"] = month_text

                    status = _clean_text(base.get("status"), 32)

                    if status:
                        agg["status_counts"][status] += 1

                    channel = _clean_text(base.get("channel"), 32)

                    if channel:
                        agg["channel_counts"][channel] += 1

                    rail = _clean_text(base.get("rail"), 32)

                    if rail:
                        agg["rail_counts"][rail] += 1

            edges: list[TransactionEdge] = []

            for (source_hash, target_hash, currency), agg in sorted(edges_internal.items()):
                count_bucket, count_score = _bucket_count(int(agg.get("count", 0)))
                amount_score = _clip_float(agg.get("max_amount_score"), 0.0, 1.0, 0.0)

                if amount_score <= 0.0:
                    amount_bucket = "unknown"
                else:
                    amount_bucket = _clean_text(agg.get("max_amount_bucket"), 32) or "unknown"

                edge_id = _fingerprint_payload(
                    {
                        "version": TRANSACTIONS_VERSION,
                        "source": source_hash,
                        "target": target_hash,
                        "currency": currency,
                        "count_bucket": count_bucket,
                        "amount_bucket": amount_bucket,
                    }
                )[:32]

                edges.append(
                    TransactionEdge(
                        edge_id=edge_id,
                        source_ref_hash=source_hash,
                        target_ref_hash=target_hash,
                        currency=currency,
                        count_bucket=count_bucket,
                        count_score=count_score,
                        amount_bucket=amount_bucket,
                        amount_score=amount_score,
                        first_month=agg.get("first_month"),
                        last_month=agg.get("last_month"),
                        dominant_status=_dominant(agg["status_counts"]) or TransactionStatus.UNKNOWN.value,
                        dominant_channel=_dominant(agg["channel_counts"]) or TransactionChannel.UNKNOWN.value,
                        dominant_rail=_dominant(agg["rail_counts"]) or PaymentRail.UNKNOWN.value,
                        metadata={
                            "raw_identifiers_retained": False,
                            "raw_monetary_values_retained": False,
                            "raw_timestamps_retained": False,
                            "cross_currency_blending_performed": False,
                            "association_is_not_proof_of_common_control": True,
                        },
                    )
                )

            edges.sort(
                key=lambda edge: (
                    -float(edge.count_score),
                    -float(edge.amount_score),
                    edge.currency,
                    edge.source_ref_hash,
                    edge.target_ref_hash,
                    edge.edge_id,
                )
            )

            if len(edges) > int(opts.max_edges):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="transaction_edges_truncated",
                    message="Transaction edges exceeded configured limit and were truncated.",
                    details={
                        "generated": len(edges),
                        "max_edges": int(opts.max_edges),
                    },
                )
                edges = edges[: int(opts.max_edges)]

            counterparties: dict[str, set[str]] = defaultdict(set)
            incident_scores: dict[str, float] = defaultdict(float)

            for edge in edges:
                counterparties[edge.source_ref_hash].add(edge.target_ref_hash)
                counterparties[edge.target_ref_hash].add(edge.source_ref_hash)
                incident_scores[edge.source_ref_hash] += float(edge.count_score)
                incident_scores[edge.target_ref_hash] += float(edge.count_score)

            profiles: list[TransactionProfile] = []

            for txn_hash in sorted(bases):
                base = bases[txn_hash]
                sender = base.get("sender_ref_hash")
                receiver = base.get("receiver_ref_hash")

                sender_degree = len(counterparties.get(sender, ())) if sender else 0
                receiver_degree = len(counterparties.get(receiver, ())) if receiver else 0
                degree = max(sender_degree, receiver_degree)
                degree_score = _round6(min(1.0, float(degree) / float(MAX_COUNTERPARTY_DEGREE)))

                sender_edge_score = incident_scores.get(sender, 0.0) if sender else 0.0
                receiver_edge_score = incident_scores.get(receiver, 0.0) if receiver else 0.0
                edge_score = _round6(
                    min(1.0, float(max(sender_edge_score, receiver_edge_score)) / MAX_INCIDENT_EDGE_SCORE)
                )

                priority_score, priority_tier, priority_reasons = _compute_transaction_priority(
                    base,
                    degree_score,
                    edge_score,
                    opts,
                )

                profiles.append(
                    TransactionProfile(
                        transaction_ref_hash=txn_hash,
                        sender_ref_hash=sender,
                        receiver_ref_hash=receiver,
                        status=base.get("status", TransactionStatus.UNKNOWN.value),
                        channel=base.get("channel", TransactionChannel.UNKNOWN.value),
                        rail=base.get("rail", PaymentRail.UNKNOWN.value),
                        direction=base.get("direction", TransactionDirection.UNKNOWN.value),
                        occurred_month=base.get("occurred_month"),
                        occurred_weekday=base.get("occurred_weekday"),
                        occurred_hour_bucket=base.get("occurred_hour_bucket"),
                        currency=base.get("currency"),
                        amount_bucket=base.get("amount_bucket", "unknown"),
                        amount_ordinal=base.get("amount_ordinal", -1),
                        amount_score=base.get("amount_score", 0.0),
                        priority_score=priority_score,
                        priority_tier=priority_tier,
                        priority_reasons=priority_reasons,
                        metadata=base.get("metadata", {}),
                    )
                )

            profiles.sort(
                key=lambda profile: (
                    -float(profile.priority_score),
                    -float(profile.amount_score),
                    profile.transaction_ref_hash,
                )
            )

            if len(profiles) > int(opts.max_profiles):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="transaction_profiles_truncated",
                    message="Transaction profiles exceeded configured limit and were truncated.",
                    details={
                        "generated": len(profiles),
                        "max_profiles": int(opts.max_profiles),
                    },
                )
                profiles = profiles[: int(opts.max_profiles)]

            registered_profiles = 0
            registered_edges = 0

            if opts.register_profiles:
                for profile in profiles:
                    try:
                        self.registry.register_profile(profile)
                        registered_profiles += 1
                    except Exception as exc:
                        _append_issue(
                            issues,
                            opts.max_issues,
                            severity=IssueSeverity.WARNING,
                            code="transaction_profile_registration_failed",
                            message="Transaction profile registration failed.",
                            details={"exception_type": type(exc).__name__},
                        )

                for edge in edges:
                    try:
                        self.registry.register_edge(edge)
                        registered_edges += 1
                    except Exception as exc:
                        _append_issue(
                            issues,
                            opts.max_issues,
                            severity=IssueSeverity.WARNING,
                            code="transaction_edge_registration_failed",
                            message="Transaction edge registration failed.",
                            details={"exception_type": type(exc).__name__},
                        )

            status_counter = Counter(_enum_value(profile.status) for profile in profiles)
            channel_counter = Counter(_enum_value(profile.channel) for profile in profiles)
            rail_counter = Counter(_enum_value(profile.rail) for profile in profiles)
            direction_counter = Counter(_enum_value(profile.direction) for profile in profiles)
            amount_counter = Counter(profile.amount_bucket for profile in profiles)
            currency_counter = Counter(profile.currency or "UNKNOWN" for profile in profiles)
            tier_counter = Counter(_enum_value(profile.priority_tier) for profile in profiles)
            edge_currency_counter = Counter(edge.currency for edge in edges)

            counts = {
                "sanitized_transactions": sanitized,
                "registered_profiles": registered_profiles,
                "registered_edges": registered_edges,
                "profiles_with_sender": sum(1 for profile in profiles if profile.sender_ref_hash),
                "profiles_with_receiver": sum(1 for profile in profiles if profile.receiver_ref_hash),
                "profiles_with_both_parties": sum(
                    1
                    for profile in profiles
                    if profile.sender_ref_hash and profile.receiver_ref_hash
                ),
                "profiles_with_edges": sum(
                    1
                    for profile in profiles
                    if profile.sender_ref_hash
                    and profile.receiver_ref_hash
                    and profile.sender_ref_hash != profile.receiver_ref_hash
                ),
                "status_completed": status_counter.get(TransactionStatus.COMPLETED.value, 0),
                "status_pending": status_counter.get(TransactionStatus.PENDING.value, 0),
                "status_failed": status_counter.get(TransactionStatus.FAILED.value, 0),
                "status_reversed": status_counter.get(TransactionStatus.REVERSED.value, 0),
                "status_unknown": status_counter.get(TransactionStatus.UNKNOWN.value, 0),
                "channel_digital": channel_counter.get(TransactionChannel.DIGITAL.value, 0),
                "channel_branch": channel_counter.get(TransactionChannel.BRANCH.value, 0),
                "channel_atm": channel_counter.get(TransactionChannel.ATM.value, 0),
                "channel_agent": channel_counter.get(TransactionChannel.AGENT.value, 0),
                "channel_api": channel_counter.get(TransactionChannel.API.value, 0),
                "channel_batch": channel_counter.get(TransactionChannel.BATCH.value, 0),
                "channel_pos": channel_counter.get(TransactionChannel.POS.value, 0),
                "channel_other": channel_counter.get(TransactionChannel.OTHER.value, 0),
                "channel_unknown": channel_counter.get(TransactionChannel.UNKNOWN.value, 0),
                "rail_card": rail_counter.get(PaymentRail.CARD.value, 0),
                "rail_upi": rail_counter.get(PaymentRail.UPI.value, 0),
                "rail_netbanking": rail_counter.get(PaymentRail.NETBANKING.value, 0),
                "rail_wallet": rail_counter.get(PaymentRail.WALLET.value, 0),
                "rail_neft": rail_counter.get(PaymentRail.NEFT.value, 0),
                "rail_rtgs": rail_counter.get(PaymentRail.RTGS.value, 0),
                "rail_imps": rail_counter.get(PaymentRail.IMPS.value, 0),
                "rail_cash": rail_counter.get(PaymentRail.CASH.value, 0),
                "rail_cheque": rail_counter.get(PaymentRail.CHEQUE.value, 0),
                "rail_internal": rail_counter.get(PaymentRail.INTERNAL.value, 0),
                "rail_other": rail_counter.get(PaymentRail.OTHER.value, 0),
                "rail_unknown": rail_counter.get(PaymentRail.UNKNOWN.value, 0),
                "direction_debit": direction_counter.get(TransactionDirection.DEBIT.value, 0),
                "direction_credit": direction_counter.get(TransactionDirection.CREDIT.value, 0),
                "direction_transfer": direction_counter.get(TransactionDirection.TRANSFER.value, 0),
                "direction_unknown": direction_counter.get(TransactionDirection.UNKNOWN.value, 0),
                "amount_unknown": amount_counter.get("unknown", 0),
                "amount_zero": amount_counter.get("zero", 0),
                "amount_micro": amount_counter.get("micro", 0),
                "amount_small": amount_counter.get("small", 0),
                "amount_moderate": amount_counter.get("moderate", 0),
                "amount_large": amount_counter.get("large", 0),
                "amount_very_large": amount_counter.get("very_large", 0),
                "amount_extreme": amount_counter.get("extreme", 0),
                "currency_unknown": currency_counter.get("UNKNOWN", 0),
                "tier_low": tier_counter.get(PriorityTier.LOW.value, 0),
                "tier_moderate": tier_counter.get(PriorityTier.MODERATE.value, 0),
                "tier_elevated": tier_counter.get(PriorityTier.ELEVATED.value, 0),
                "tier_high": tier_counter.get(PriorityTier.HIGH.value, 0),
                "tier_unscoped": tier_counter.get(PriorityTier.UNSCORED.value, 0),
                "edges_by_currency_unknown": edge_currency_counter.get("UNKNOWN", 0),
            }

            for currency, count in currency_counter.items():
                if currency and currency != "UNKNOWN":
                    counts[f"currency_{currency.lower()}"] = count

            for currency, count in edge_currency_counter.items():
                if currency and currency != "UNKNOWN":
                    counts[f"edge_currency_{currency.lower()}"] = count

            status = ServiceStatus.PASSED

            if _has_error(issues):
                status = ServiceStatus.FAILED
            elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
                status = ServiceStatus.DEGRADED
            elif not profiles:
                status = ServiceStatus.SKIPPED

            return make_result(
                ok=status in {ServiceStatus.PASSED, ServiceStatus.DEGRADED},
                status=status,
                profiles=profiles,
                edges=edges,
                counts=counts,
            )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "registry": self.registry.safe_summary(limit=self.options.max_summary_items),
            "caveats": list(TRANSACTION_CAVEATS),
            "safety_flags": dict(TRANSACTION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default engine and public API
# -----------------------------------------------------------------------------


_default_engine: Optional[TransactionsServiceEngine] = None
_default_engine_lock = threading.Lock()


def get_transactions_options(settings: Any | None = None) -> TransactionsServiceOptions:
    """
    Return transactions service options from settings.
    """
    return TransactionsServiceOptions.from_settings(settings)


def get_transactions_engine(
    options: TransactionsServiceOptions | None = None,
    *,
    rebuild: bool = False,
) -> TransactionsServiceEngine:
    """
    Return a process-wide transactions service engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            resolved_options = options or TransactionsServiceOptions.from_settings()
            _default_engine = TransactionsServiceEngine(
                options=resolved_options,
                registry=get_transaction_registry(
                    max_profiles=resolved_options.max_profiles,
                    max_edges=resolved_options.max_edges,
                ),
            )

        return _default_engine


def normalize_transactions(
    request: Any,
    options: TransactionsServiceOptions | None = None,
    *,
    engine: TransactionsServiceEngine | None = None,
) -> TransactionsResult:
    """
    Normalize bounded synthetic transaction records into privacy-preserving
    profiles and directed transfer edges.
    """
    active_engine = engine or get_transactions_engine(options)
    return active_engine.normalize(request)


def get_transaction_profile(
    transaction_ref_hash: Any,
    *,
    registry: TransactionRegistry | None = None,
) -> Optional[TransactionProfile]:
    """
    Return one registered transaction profile by pseudonymous transaction hash.
    """
    active_registry = registry or get_transaction_registry()
    return active_registry.get_profile(transaction_ref_hash)


def list_transaction_profiles(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: TransactionRegistry | None = None,
) -> tuple[TransactionProfile, ...]:
    """
    Return registered transaction profiles.
    """
    active_registry = registry or get_transaction_registry()
    return active_registry.list_profiles(limit=limit)


def list_transaction_edges(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: TransactionRegistry | None = None,
) -> tuple[TransactionEdge, ...]:
    """
    Return registered transaction edges.
    """
    active_registry = registry or get_transaction_registry()
    return active_registry.list_edges(limit=limit)


def search_transaction_profiles(
    *,
    status: Any = None,
    channel: Any = None,
    rail: Any = None,
    direction: Any = None,
    currency: Any = None,
    amount_bucket: Any = None,
    min_priority: Optional[float] = None,
    max_priority: Optional[float] = None,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: TransactionRegistry | None = None,
) -> tuple[TransactionProfile, ...]:
    """
    Search registered transaction profiles using bounded safe filters.
    """
    active_registry = registry or get_transaction_registry()
    return active_registry.search_profiles(
        status=status,
        channel=channel,
        rail=rail,
        direction=direction,
        currency=currency,
        amount_bucket=amount_bucket,
        min_priority=min_priority,
        max_priority=max_priority,
        limit=limit,
    )


def export_transactions_summary(result: TransactionsResult) -> dict[str, Any]:
    """
    Export a safe public transactions service summary.
    """
    return result.to_dict()


def clear_transaction_registry(*, registry: TransactionRegistry | None = None) -> None:
    """
    Clear the process-local transaction registry.
    """
    active_registry = registry or get_transaction_registry()
    active_registry.clear()


def get_transactions_health(*, engine: TransactionsServiceEngine | None = None) -> dict[str, Any]:
    """
    Return safe transactions service health.
    """
    active_engine = engine or get_transactions_engine()
    opts = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=opts.max_summary_items)
    issues: list[TransactionIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="transactions_service_disabled",
            message="Transactions service is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Transactions service requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Transactions service is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "registry": registry_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(TRANSACTION_CAVEATS),
        "safety_flags": dict(TRANSACTION_SAFETY_FLAGS),
    }


def get_transactions_metadata(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    engine: TransactionsServiceEngine | None = None,
) -> dict[str, Any]:
    """
    Return safe, serializable transactions service metadata.

    This is useful for startup logs, diagnostic endpoints, tests, developer
    tooling, and architecture documentation checks.

    It must not expose raw identifiers, raw narratives, raw monetary values,
    raw timestamps, secrets, environment files, database URLs, tokens,
    passwords, ground-truth labels, scenario IDs, fraud-ring IDs, model artifact
    paths, filesystem paths, executable handler references, or real customer
    data.
    """
    active_engine = engine or get_transactions_engine()
    options = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=limit)

    amount_buckets = [
        {
            "bound": None if bound is None else str(bound),
            "label": label,
            "ordinal": ordinal,
            "score": _round6(float(score)),
        }
        for bound, label, ordinal, score in AMOUNT_BUCKET_SPECS
    ]

    count_buckets = [
        {
            "upper": upper,
            "label": label,
            "score": _round6(float(score)),
        }
        for upper, label, score in COUNT_BUCKET_SPECS
    ]

    return {
        "package": "muleguard.backend.services.transactions",
        "version": TRANSACTIONS_VERSION,
        "transaction_statuses": [status.value for status in TransactionStatus],
        "transaction_channels": [channel.value for channel in TransactionChannel],
        "payment_rails": [rail.value for rail in PaymentRail],
        "transaction_directions": [direction.value for direction in TransactionDirection],
        "priority_tiers": [tier.value for tier in PriorityTier],
        "service_statuses": [status.value for status in ServiceStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "amount_buckets": amount_buckets,
        "count_buckets": count_buckets,
        "status_map": dict(TRANSACTION_STATUS_MAP),
        "channel_map": dict(TRANSACTION_CHANNEL_MAP),
        "rail_map": dict(PAYMENT_RAIL_MAP),
        "direction_map": dict(DIRECTION_MAP),
        "default_options": options.safe_summary(),
        "registry": registry_summary,
        "hard_limits": {
            "max_transactions": HARD_MAX_TRANSACTIONS,
            "max_edges": HARD_MAX_EDGES,
            "max_profiles": HARD_MAX_PROFILES,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
        },
        "forbidden_transaction_field_count": len(FORBIDDEN_TXN_FIELDS),
        "label_leakage_field_count": len(LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(PROHIBITED_ACTION_TOKENS),
        "summary_item_limit": max(1, int(limit)),
        "monetary_policy": "bounded_amount_buckets_only_no_raw_values_no_cross_currency_blending",
        "temporal_policy": "bounded_month_weekday_hour_buckets_only_no_raw_timestamps",
        "caveats": list(TRANSACTION_CAVEATS),
        "safety_flags": dict(TRANSACTION_SAFETY_FLAGS),
    }


# -----------------------------------------------------------------------------
# Optional backend services registry integration
# -----------------------------------------------------------------------------


try:
    from app.services import (
        ServiceDescriptor as _RegistryServiceDescriptor,
        ServiceKind as _RegistryServiceKind,
        get_service_registry as _get_registry_service_registry,
    )
except Exception:  # pragma: no cover - resilience for partial deployments
    _RegistryServiceDescriptor = None
    _RegistryServiceKind = None
    _get_registry_service_registry = None


def build_transactions_service_descriptor(
    options: TransactionsServiceOptions | None = None,
    *,
    engine: TransactionsServiceEngine | None = None,
) -> Any:
    """
    Build a bounded service descriptor for the transactions service.

    If the backend services registry descriptor is unavailable, this returns a
    safe plain dictionary representation instead of failing.
    """
    active_engine = engine or get_transactions_engine(options)

    def _handler(payload: Any) -> dict[str, Any]:
        return active_engine.normalize(payload).to_dict()

    def _health() -> dict[str, Any]:
        return get_transactions_health(engine=active_engine)

    if _RegistryServiceDescriptor is None:
        return {
            "service_id": "transactions",
            "kind": "general",
            "display_name": "Transactions Service",
            "description": "Bounded synthetic transaction profiling and edge derivation service.",
            "version": TRANSACTIONS_VERSION,
            "enabled": active_engine.options.enabled,
            "synthetic_required": active_engine.options.synthetic_required,
            "dataset_mode": active_engine.options.dataset_mode,
            "production_like": active_engine.options.production_like,
            "allow_in_production": active_engine.options.allow_in_production,
            "capabilities": [
                "transactions",
                "profiling",
                "edges",
                "privacy",
                "synthetic_only",
                "no_raw_monetary_values",
                "no_raw_timestamps",
            ],
            "handler_registered": True,
            "health_handler_registered": True,
            "raw_values_retained": False,
            "executable_handler_exposed": False,
            "caveats": list(TRANSACTION_CAVEATS),
            "safety_flags": dict(TRANSACTION_SAFETY_FLAGS),
        }

    kind = getattr(_RegistryServiceKind, "GENERAL", "general") if _RegistryServiceKind else "general"

    return _RegistryServiceDescriptor(
        service_id="transactions",
        kind=kind,
        display_name="Transactions Service",
        description="Bounded synthetic transaction profiling, edge derivation, and priority summarization service.",
        version=TRANSACTIONS_VERSION,
        enabled=active_engine.options.enabled,
        synthetic_required=active_engine.options.synthetic_required,
        dataset_mode=active_engine.options.dataset_mode,
        production_like=active_engine.options.production_like,
        allow_in_production=active_engine.options.allow_in_production,
        capabilities=(
            "transactions",
            "profiling",
            "edges",
            "privacy",
            "synthetic_only",
            "no_automatic_adverse_action",
            "no_raw_monetary_values",
            "no_raw_timestamps",
        ),
        handler=_handler,
        health_handler=_health,
        metadata={
            "service_module": "app.services.transactions",
            "registry_backend": "process_local_in_memory",
            "raw_values_retained": False,
            "raw_monetary_values_retained": False,
            "raw_timestamps_retained": False,
            "cross_currency_blending_performed": False,
        },
    )


def register_transactions_service(
    options: TransactionsServiceOptions | None = None,
    *,
    engine: TransactionsServiceEngine | None = None,
    registry: Any | None = None,
    replace: bool = True,
) -> Optional[str]:
    """
    Register the transactions service descriptor with the backend services
    registry when available.
    """
    if _get_registry_service_registry is None:
        return None

    active_registry = registry or _get_registry_service_registry()
    descriptor = build_transactions_service_descriptor(options=options, engine=engine)

    try:
        return active_registry.register(descriptor, replace=replace)
    except Exception:
        return None


__all__ = [
    "IssueSeverity",
    "PaymentRail",
    "PriorityTier",
    "ServiceStatus",
    "TRANSACTIONS_VERSION",
    "TransactionChannel",
    "TransactionDirection",
    "TransactionEdge",
    "TransactionIssue",
    "TransactionProfile",
    "TransactionRegistry",
    "TransactionStatus",
    "TransactionsRequest",
    "TransactionsResult",
    "TransactionsServiceEngine",
    "TransactionsServiceOptions",
    "build_transactions_service_descriptor",
    "clear_transaction_registry",
    "export_transactions_summary",
    "get_transaction_profile",
    "get_transaction_registry",
    "get_transactions_engine",
    "get_transactions_health",
    "get_transactions_metadata",
    "get_transactions_options",
    "list_transaction_edges",
    "list_transaction_profiles",
    "normalize_transactions",
    "register_transactions_service",
    "search_transaction_profiles",
]