"""
MULEGUARD backend accounts service.

This module provides the canonical bounded synthetic account profiling,
normalization, linking, and summarization service for the MULEGUARD
investigative prototype.

Primary responsibilities:

- normalize bounded synthetic account records into privacy-preserving account
  profiles using salted one-way pseudonymous account references;
- summarize bounded account lifecycle, channel, activity, and association
  signals without retaining raw identifiers, raw narratives, raw monetary
  values, labels, ground-truth fields, secrets, tokens, passwords, database
  URLs, filesystem paths, or model artifact paths;
- attach bounded synthetic account links derived from structural relationships
  such as transfers, shared devices, shared network indicators, complaint
  references, alert references, case references, entity associations, temporal
  associations, exact-reference matches, and identifier matches;
- compute bounded investigative priority scores and tiers for human review
  triage only, with explicit non-calibration and non-adverse-action caveats;
- maintain a bounded process-local account profile registry for local prototype
  workflows, tests, developer tooling, and offline evaluation harnesses;
- expose a safe service descriptor compatible with the MULEGUARD backend
  services registry when available;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module profiles and summarizes synthetic accounts only. It does not
authenticate users, authorize actions, freeze accounts, block accounts,
blacklist accounts, close accounts, restrict services, deny services,
terminate relationships, suspend accounts, refer matters to law enforcement,
make credit, employment, housing, insurance, benefits, or other consequential
decisions, train models, deploy models, persist durable artifacts, call
external systems, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for account profiling.
- Account profiles and priority scores are investigative leads or human
  workflow artefacts only. They are not proof of wrongdoing.
- Priority scores and tiers are not probabilities of guilt.
- Labels must never be used as account features or priority criteria.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected.
- Raw complaint narratives are forbidden inputs and are never read, hashed,
  stored, logged, or returned.
- Raw account identifiers are forbidden outputs. Account linkage is pseudonymous
  and salted.
- Monetary amounts, balances, transaction values, and currency amounts are
  never retained or summarized. Only bounded non-monetary count buckets are
  used.
- Account operations must never trigger automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable account signals are reported honestly as unavailable
  rather than invented.
- The bundled account registry is process-local, non-durable, and bounded for
  local prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external identity providers, core banking systems,
  KYC systems, watchlists, sanctions lists, graph databases, model runtimes, or
  network APIs.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models or account decisioning rules.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable account store.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, cycle
candidates, community candidates, filtered graphs, serialized graphs,
correlation candidates, confidence records, account profiles, account priority
scores, explanations, validation reports, and case dispositions are
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
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from decimal import Decimal
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


logger = logging.getLogger("muleguard.backend.services.accounts")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

ACCOUNTS_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.services.accounts.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

DEFAULT_MAX_ACCOUNTS: Final[int] = 10_000
HARD_MAX_ACCOUNTS: Final[int] = 100_000

DEFAULT_MAX_LINKS: Final[int] = 20_000
HARD_MAX_LINKS: Final[int] = 200_000

DEFAULT_MAX_PROFILES: Final[int] = 10_000
HARD_MAX_PROFILES: Final[int] = 100_000

DEFAULT_MAX_METRICS: Final[int] = 16
HARD_MAX_METRICS: Final[int] = 64

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

DEFAULT_MAX_TIME_MS: Final[int] = 30_000
HARD_MAX_TIME_MS: Final[int] = 300_000

MAX_TEXT_LENGTH: Final[int] = 512
MAX_HASH_LENGTH: Final[int] = 256
MAX_REASON_TEXT_LENGTH: Final[int] = 300

DEFAULT_LOW_THRESHOLD: Final[float] = 0.20
DEFAULT_MODERATE_THRESHOLD: Final[float] = 0.40
DEFAULT_ELEVATED_THRESHOLD: Final[float] = 0.65
DEFAULT_LINK_WEIGHT: Final[float] = 0.20

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")

_MISSING: Final[object] = object()

ACCOUNT_REF_KEYS: Final[tuple[str, ...]] = (
    "account_ref_hash",
    "account_hash",
    "account_reference_hash",
    "acct_ref_hash",
)

RAW_ACCOUNT_KEYS: Final[tuple[str, ...]] = (
    "account_id",
    "acct_id",
    "id",
    "uuid",
    "guid",
)

STATUS_KEYS: Final[tuple[str, ...]] = (
    "status",
    "account_status",
    "lifecycle_state",
    "state",
)

KIND_KEYS: Final[tuple[str, ...]] = (
    "account_kind",
    "account_type",
    "kind",
    "type",
    "segment",
)

CHANNEL_KEYS: Final[tuple[str, ...]] = (
    "channel",
    "source_channel",
    "access_channel",
    "origination_channel",
)

CREATED_KEYS: Final[tuple[str, ...]] = (
    "opened_at",
    "created_at",
    "onboarded_at",
    "creation_date",
    "opening_date",
)

LAST_SEEN_KEYS: Final[tuple[str, ...]] = (
    "last_seen_at",
    "last_activity_at",
    "updated_at",
    "activity_date",
    "last_updated_at",
)

METRIC_KEYS: Final[tuple[str, ...]] = (
    "transaction_count",
    "login_count",
    "device_count",
    "ip_count",
    "complaint_count",
    "alert_count",
    "correlation_count",
)

LINK_RELATION_KEYS: Final[tuple[str, ...]] = (
    "relation",
    "link_kind",
    "relationship",
    "edge_kind",
    "association_kind",
)

LINK_SOURCE_KEYS: Final[tuple[str, ...]] = (
    "source_account_id",
    "source_acct_id",
    "source_account_ref_hash",
    "source_ref_hash",
    "source_hash",
    "from_account_id",
    "from_acct_id",
    "src",
)

LINK_TARGET_KEYS: Final[tuple[str, ...]] = (
    "target_account_id",
    "target_acct_id",
    "target_account_ref_hash",
    "target_ref_hash",
    "target_hash",
    "to_account_id",
    "to_acct_id",
    "dst",
)

LINK_COUNT_KEYS: Final[tuple[str, ...]] = (
    "count",
    "frequency",
    "interaction_count",
    "event_count",
    "link_count",
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

FORBIDDEN_ACCOUNT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "apikey",
        "artifact_path",
        "auth_header",
        "authorization",
        "balance",
        "bearer",
        "card_number",
        "connection_string",
        "cookie",
        "credential",
        "credentials",
        "currency",
        "cvv",
        "customer_data",
        "customer_id",
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
        "monetary_value",
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
        "transaction_amount",
        "truth_label",
        "upi_id",
        "value",
        "amount",
    }
)

FORBIDDEN_ACCOUNT_TOKENS: Final[tuple[str, ...]] = (
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
    "amount",
    "value",
    "currency",
    "balance",
    "transaction_amount",
    "monetary",
    "money",
    "fund",
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
    "token",
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

ACCOUNT_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic account profiling only. Do not use with real customer data.",
    "Account profiles and priority scores are investigative leads only and are not proof of wrongdoing.",
    "Priority scores and tiers are not probabilities of guilt.",
    "Account profiling must not trigger automatic adverse customer action.",
    "Labels must never be used as account features or priority criteria.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives, raw identifiers, secrets, tokens, passwords, database URLs, filesystem paths, and model artifact paths are forbidden.",
    "Monetary amounts, balances, transaction values, and currency amounts are never retained or summarized.",
    "Only bounded non-monetary count buckets are retained.",
    "The bundled account registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

ACCOUNT_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_raw_identifiers_retained": True,
        "no_raw_narratives_retained": True,
        "no_monetary_values_retained": True,
        "salted_pseudonymous_account_references": True,
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
        "deterministic_account_profiling": True,
        "bounded_account_profiling_required": True,
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

DEFAULT_PRIORITY_WEIGHTS: Final[Mapping[str, float]] = MappingProxyType(
    {
        "transaction_count": 0.16,
        "login_count": 0.08,
        "device_count": 0.10,
        "ip_count": 0.08,
        "complaint_count": 0.22,
        "alert_count": 0.18,
        "correlation_count": 0.18,
    }
)

COUNT_BUCKETS: Final[tuple[tuple[Optional[int], str, float], ...]] = (
    (0, "zero", 0.0),
    (9, "low", 5.0),
    (99, "moderate", 50.0),
    (999, "elevated", 500.0),
    (9_999, "high", 5_000.0),
    (None, "very_high", 10_000.0),
)

ACCOUNT_STATUS_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "open": "OPEN",
        "active": "OPEN",
        "live": "OPEN",
        "new": "OPEN",
        "created": "OPEN",
        "dormant": "DORMANT",
        "inactive": "DORMANT",
        "idle": "DORMANT",
        "quiet": "DORMANT",
        "closed": "CLOSED",
        "cancelled": "CLOSED",
        "canceled": "CLOSED",
        "completed": "CLOSED",
    }
)

ACCOUNT_KIND_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "personal": "PERSONAL",
        "individual": "PERSONAL",
        "retail": "PERSONAL",
        "business": "BUSINESS",
        "company": "BUSINESS",
        "corporate": "BUSINESS",
        "merchant": "MERCHANT",
        "shop": "MERCHANT",
        "vendor": "MERCHANT",
        "payee": "MERCHANT",
        "entity": "ENTITY",
        "organization": "ENTITY",
        "organisation": "ENTITY",
        "synthetic": "ENTITY",
    }
)

ACCOUNT_CHANNEL_MAP: Final[Mapping[str, str]] = MappingProxyType(
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
        "api": "API",
        "batch": "BATCH",
        "bulk": "BATCH",
    }
)

LINK_RELATION_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "transfer": "TRANSFER",
        "payment": "TRANSFER",
        "remittance": "TRANSFER",
        "device": "SHARED_DEVICE",
        "shared_device": "SHARED_DEVICE",
        "ip": "SHARED_IP",
        "network": "SHARED_IP",
        "shared_ip": "SHARED_IP",
        "complaint": "COMPLAINT",
        "alert": "ALERT",
        "case": "CASE",
        "entity": "ENTITY",
        "entity_association": "ENTITY",
        "temporal": "TEMPORAL",
        "temporal_association": "TEMPORAL",
        "reference": "EXACT_REFERENCE",
        "exact_reference": "EXACT_REFERENCE",
        "identifier": "IDENTIFIER",
        "identifier_match": "IDENTIFIER",
    }
)

_ALL_ACCOUNT_VIEW_KEYS: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            *ACCOUNT_REF_KEYS,
            *RAW_ACCOUNT_KEYS,
            *STATUS_KEYS,
            *KIND_KEYS,
            *CHANNEL_KEYS,
            *CREATED_KEYS,
            *LAST_SEEN_KEYS,
            *METRIC_KEYS,
        }
    )
)

_ALL_LINK_VIEW_KEYS: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            *LINK_RELATION_KEYS,
            *LINK_SOURCE_KEYS,
            *LINK_TARGET_KEYS,
            *LINK_COUNT_KEYS,
            *ACCOUNT_REF_KEYS,
        }
    )
)

_ACCOUNT_LIKE_KEYS: Final[frozenset[str]] = frozenset(_ALL_ACCOUNT_VIEW_KEYS)
_LINK_LIKE_KEYS: Final[frozenset[str]] = frozenset(_ALL_LINK_VIEW_KEYS)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class AccountKind(str, Enum):
    """
    Bounded synthetic account kind.
    """

    PERSONAL = "personal"
    BUSINESS = "business"
    MERCHANT = "merchant"
    ENTITY = "entity"
    UNKNOWN = "unknown"


class AccountLifecycleState(str, Enum):
    """
    Bounded observational account lifecycle state.

    These states are descriptive only. They must not be interpreted as
    authorization to take adverse action.
    """

    OPEN = "open"
    DORMANT = "dormant"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class AccountChannel(str, Enum):
    """
    Bounded account origination or access channel.
    """

    DIGITAL = "digital"
    BRANCH = "branch"
    ATM = "atm"
    AGENT = "agent"
    API = "api"
    BATCH = "batch"
    UNKNOWN = "unknown"


class LinkRelation(str, Enum):
    """
    Bounded account link relation.
    """

    TRANSFER = "transfer"
    SHARED_DEVICE = "shared_device"
    SHARED_IP = "shared_ip"
    COMPLAINT = "complaint"
    ALERT = "alert"
    CASE = "case"
    ENTITY = "entity"
    TEMPORAL = "temporal"
    EXACT_REFERENCE = "exact_reference"
    IDENTIFIER = "identifier"
    OTHER = "other"


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
    Overall accounts service status.
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

    if canonical in FORBIDDEN_ACCOUNT_FIELDS:
        return True

    if canonical.startswith("raw_") or canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in FORBIDDEN_ACCOUNT_TOKENS)


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

        for raw_key, raw_value in list(value.items())[:100]:
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
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:100]]

    return f"<{type(value).__name__}>"


def _as_mapping(value: Any) -> dict[str, Any]:
    sanitized = _safe_detail_value(value)
    return sanitized if isinstance(sanitized, dict) else {}


def _as_counts(value: Any) -> Mapping[str, int]:
    return MappingProxyType(
        {
            str(key): max(0, _as_int(item, 0))
            for key, item in _as_mapping(value).items()
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


def _account_ref_hash(value: Any, options: "AccountsServiceOptions") -> Optional[str]:
    text = _clean_text(value, MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.services.accounts.account.{namespace}"
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
            for raw_key, raw_value in list(value.items())[:100]:
                parts.append(str(raw_key))
                visit(raw_value, depth + 1)
            return

        if isinstance(value, (list, tuple, set, frozenset)):
            for item in list(value)[:100]:
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

    parsed = _as_int(value, 0)
    return max(0, parsed)


def _bucket_count(count: int) -> tuple[str, float]:
    safe_count = max(0, int(count))

    for upper, label, midpoint in COUNT_BUCKETS:
        if upper is None or safe_count <= upper:
            return label, float(midpoint)

    return "very_high", 10_000.0


def _metric_bucket(count: int) -> dict[str, Any]:
    label, value = _bucket_count(count)

    return {
        "bucket": label,
        "bucket_value": _round6(value),
        "raw_count_retained": False,
        "monetary_value_retained": False,
    }


def _normalize_month(value: Any) -> Optional[str]:
    parsed = _parse_datetime(value)

    if parsed is None:
        return None

    return parsed.strftime("%Y-%m")


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
class AccountIssue:
    """
    Safe account-service issue.

    Issues never contain raw identifiers, raw narratives, raw labels, monetary
    values, secrets, tokens, passwords, database URLs, filesystem paths, model
    artifact paths, or executable handler references.
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


def _coerce_issue(value: Any) -> AccountIssue:
    if isinstance(value, AccountIssue):
        return value

    if isinstance(value, Mapping):
        return AccountIssue(
            severity=value.get("severity", IssueSeverity.WARNING),
            code=value.get("code", "unstructured_issue"),
            message=value.get("message", ""),
            field=value.get("field"),
            details=value.get("details", {}),
        )

    return AccountIssue(
        severity=IssueSeverity.WARNING,
        code="unstructured_issue",
        message=_clean_text(value, MAX_REASON_TEXT_LENGTH),
    )


def _append_issue(
    issues: list[AccountIssue],
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

        issues[-1] = AccountIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        AccountIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, MAX_REASON_TEXT_LENGTH),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[AccountIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[AccountIssue]) -> tuple[AccountIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[AccountIssue] = []

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
class AccountsServiceOptions:
    """
    Bounded synthetic accounts service policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    max_accounts: int = DEFAULT_MAX_ACCOUNTS
    max_links: int = DEFAULT_MAX_LINKS
    max_profiles: int = DEFAULT_MAX_PROFILES
    max_metrics: int = DEFAULT_MAX_METRICS
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS

    include_links: bool = True
    include_priority: bool = True
    register_profiles: bool = True
    drop_forbidden_fields: bool = True

    low_threshold: float = DEFAULT_LOW_THRESHOLD
    moderate_threshold: float = DEFAULT_MODERATE_THRESHOLD
    elevated_threshold: float = DEFAULT_ELEVATED_THRESHOLD
    link_weight: float = DEFAULT_LINK_WEIGHT
    priority_weights: Mapping[str, float] = dataclass_field(
        default_factory=lambda: dict(DEFAULT_PRIORITY_WEIGHTS)
    )

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
            "max_accounts",
            _clamp_int(self.max_accounts, 1, HARD_MAX_ACCOUNTS, DEFAULT_MAX_ACCOUNTS),
        )
        object.__setattr__(
            self,
            "max_links",
            _clamp_int(self.max_links, 0, HARD_MAX_LINKS, DEFAULT_MAX_LINKS),
        )
        object.__setattr__(
            self,
            "max_profiles",
            _clamp_int(self.max_profiles, 1, HARD_MAX_PROFILES, DEFAULT_MAX_PROFILES),
        )
        object.__setattr__(
            self,
            "max_metrics",
            _clamp_int(self.max_metrics, 1, HARD_MAX_METRICS, DEFAULT_MAX_METRICS),
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

        object.__setattr__(self, "include_links", _as_bool(self.include_links, True))
        object.__setattr__(self, "include_priority", _as_bool(self.include_priority, True))
        object.__setattr__(self, "register_profiles", _as_bool(self.register_profiles, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, True))

        low = _round6(_clamp_float(self.low_threshold, 0.0, 1.0, DEFAULT_LOW_THRESHOLD))
        moderate = _round6(_clamp_float(self.moderate_threshold, low, 1.0, max(low, DEFAULT_MODERATE_THRESHOLD)))
        elevated = _round6(_clamp_float(self.elevated_threshold, moderate, 1.0, max(moderate, DEFAULT_ELEVATED_THRESHOLD)))

        object.__setattr__(self, "low_threshold", low)
        object.__setattr__(self, "moderate_threshold", moderate)
        object.__setattr__(self, "elevated_threshold", elevated)
        object.__setattr__(
            self,
            "link_weight",
            _round6(_clamp_float(self.link_weight, 0.0, 1.0, DEFAULT_LINK_WEIGHT)),
        )

        supplied_weights = (
            self.priority_weights
            if isinstance(self.priority_weights, Mapping)
            else DEFAULT_PRIORITY_WEIGHTS
        )

        normalized_weights: dict[str, float] = {}

        for metric, default_weight in DEFAULT_PRIORITY_WEIGHTS.items():
            supplied = supplied_weights.get(metric, default_weight)
            normalized_weights[metric] = _round6(
                _clamp_float(supplied, 0.0, 1.0, float(default_weight))
            )

        object.__setattr__(self, "priority_weights", MappingProxyType(normalized_weights))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "AccountsServiceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ACCOUNTS_SERVICE_SALT", None)
            or _setting(settings, "SERVICES_ACCOUNTS_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ACCOUNTS_SERVICE_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ACCOUNTS_SERVICE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ACCOUNTS_SERVICE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ACCOUNTS_SERVICE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ACCOUNTS_SERVICE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_accounts=_as_int(
                _setting(settings, "ACCOUNTS_SERVICE_MAX_ACCOUNTS", DEFAULT_MAX_ACCOUNTS),
                DEFAULT_MAX_ACCOUNTS,
            ),
            max_links=_as_int(
                _setting(settings, "ACCOUNTS_SERVICE_MAX_LINKS", DEFAULT_MAX_LINKS),
                DEFAULT_MAX_LINKS,
            ),
            max_profiles=_as_int(
                _setting(settings, "ACCOUNTS_SERVICE_MAX_PROFILES", DEFAULT_MAX_PROFILES),
                DEFAULT_MAX_PROFILES,
            ),
            max_metrics=_as_int(
                _setting(settings, "ACCOUNTS_SERVICE_MAX_METRICS", DEFAULT_MAX_METRICS),
                DEFAULT_MAX_METRICS,
            ),
            max_issues=_as_int(
                _setting(settings, "ACCOUNTS_SERVICE_MAX_ISSUES", DEFAULT_MAX_ISSUES),
                DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "ACCOUNTS_SERVICE_MAX_SUMMARY_ITEMS", DEFAULT_MAX_SUMMARY_ITEMS),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "ACCOUNTS_SERVICE_MAX_TIME_MS", DEFAULT_MAX_TIME_MS),
                DEFAULT_MAX_TIME_MS,
            ),
            include_links=_as_bool(_setting(settings, "ACCOUNTS_SERVICE_INCLUDE_LINKS", True), True),
            include_priority=_as_bool(_setting(settings, "ACCOUNTS_SERVICE_INCLUDE_PRIORITY", True), True),
            register_profiles=_as_bool(_setting(settings, "ACCOUNTS_SERVICE_REGISTER_PROFILES", True), True),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ACCOUNTS_SERVICE_DROP_FORBIDDEN_FIELDS", True),
                True,
            ),
            low_threshold=_as_float(
                _setting(settings, "ACCOUNTS_SERVICE_LOW_THRESHOLD", DEFAULT_LOW_THRESHOLD),
                DEFAULT_LOW_THRESHOLD,
            ),
            moderate_threshold=_as_float(
                _setting(settings, "ACCOUNTS_SERVICE_MODERATE_THRESHOLD", DEFAULT_MODERATE_THRESHOLD),
                DEFAULT_MODERATE_THRESHOLD,
            ),
            elevated_threshold=_as_float(
                _setting(settings, "ACCOUNTS_SERVICE_ELEVATED_THRESHOLD", DEFAULT_ELEVATED_THRESHOLD),
                DEFAULT_ELEVATED_THRESHOLD,
            ),
            link_weight=_as_float(
                _setting(settings, "ACCOUNTS_SERVICE_LINK_WEIGHT", DEFAULT_LINK_WEIGHT),
                DEFAULT_LINK_WEIGHT,
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
                "max_accounts": self.max_accounts,
                "max_links": self.max_links,
                "max_profiles": self.max_profiles,
                "max_metrics": self.max_metrics,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
            },
            "priority": {
                "include_priority": self.include_priority,
                "low_threshold": _round6(self.low_threshold),
                "moderate_threshold": _round6(self.moderate_threshold),
                "elevated_threshold": _round6(self.elevated_threshold),
                "link_weight": _round6(self.link_weight),
                "weights": dict(self.priority_weights),
            },
            "flags": {
                "include_links": self.include_links,
                "register_profiles": self.register_profiles,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "accounts",
        "links",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class AccountsRequest:
    """
    Bounded synthetic accounts service request.
    """

    accounts: Any = None
    links: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> AccountsRequest:
    if isinstance(request, AccountsRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(AccountsRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return AccountsRequest(**clean)
            except Exception:
                return AccountsRequest(accounts=payload.get("accounts", request))

        if any(_canonical_field_name(key) in _ACCOUNT_LIKE_KEYS for key in payload):
            return AccountsRequest(accounts=[payload])

        if any(_canonical_field_name(key) in _LINK_LIKE_KEYS for key in payload):
            return AccountsRequest(links=[payload])

        return AccountsRequest(metadata=request)

    if isinstance(request, (list, tuple, set, frozenset)):
        return AccountsRequest(accounts=request)

    return AccountsRequest(metadata=request)


# -----------------------------------------------------------------------------
# Public models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AccountLink:
    """
    One bounded synthetic account link.

    Links are structural association hints only. They are not proof of common
    control, wrongdoing, or criminal association.
    """

    link_id: str = ""
    relation: LinkRelation | str = LinkRelation.OTHER
    source_ref_hash: str = ""
    target_ref_hash: str = ""
    count_bucket: str = "zero"
    count_value: float = 0.0
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "relation",
            _normalize_enum_option(LinkRelation, self.relation, LinkRelation.OTHER),
        )
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
        object.__setattr__(self, "count_bucket", _normalize_token(self.count_bucket) or "zero")
        object.__setattr__(self, "count_value", _round6(_clip_float(self.count_value, 0.0, 10_000.0, 0.0)))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.link_id:
            object.__setattr__(
                self,
                "link_id",
                _fingerprint_payload(
                    {
                        "relation": _enum_value(self.relation),
                        "source": self.source_ref_hash,
                        "target": self.target_ref_hash,
                        "count_bucket": self.count_bucket,
                    }
                )[:32],
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "link_id": self.link_id,
            "relation": _enum_value(self.relation, LinkRelation.OTHER.value),
            "source_ref_hash": self.source_ref_hash,
            "target_ref_hash": self.target_ref_hash,
            "count_bucket": self.count_bucket,
            "count_value": float(self.count_value),
            "metadata": _safe_detail_value(self.metadata),
            "raw_identifiers_retained": False,
            "monetary_values_retained": False,
            "association_is_not_proof_of_common_control": True,
        }


@dataclass(frozen=True, slots=True)
class AccountProfile:
    """
    One bounded synthetic account profile.

    Profiles are investigative human-workflow artefacts only. They are not
    proof of wrongdoing and must not trigger automatic adverse action.
    """

    account_ref_hash: str = ""
    kind: AccountKind | str = AccountKind.UNKNOWN
    lifecycle_state: AccountLifecycleState | str = AccountLifecycleState.UNKNOWN
    channel: AccountChannel | str = AccountChannel.UNKNOWN
    opened_month: Optional[str] = None
    last_seen_month: Optional[str] = None
    metrics: Mapping[str, Any] = dataclass_field(default_factory=dict)
    links: tuple[AccountLink, ...] = ()
    link_count: int = 0
    priority_score: float = 0.0
    priority_tier: PriorityTier | str = PriorityTier.UNSCORED
    priority_reasons: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "account_ref_hash",
            _clean_text(self.account_ref_hash, MAX_HASH_LENGTH).lower(),
        )
        object.__setattr__(
            self,
            "kind",
            _normalize_enum_option(AccountKind, self.kind, AccountKind.UNKNOWN),
        )
        object.__setattr__(
            self,
            "lifecycle_state",
            _normalize_enum_option(
                AccountLifecycleState,
                self.lifecycle_state,
                AccountLifecycleState.UNKNOWN,
            ),
        )
        object.__setattr__(
            self,
            "channel",
            _normalize_enum_option(AccountChannel, self.channel, AccountChannel.UNKNOWN),
        )
        object.__setattr__(
            self,
            "opened_month",
            _clean_text(self.opened_month, 16) or None,
        )
        object.__setattr__(
            self,
            "last_seen_month",
            _clean_text(self.last_seen_month, 16) or None,
        )
        object.__setattr__(self, "metrics", MappingProxyType(_as_mapping(self.metrics)))
        object.__setattr__(self, "links", tuple(self.links or ()))
        object.__setattr__(self, "link_count", max(0, _as_int(self.link_count, len(self.links))))
        object.__setattr__(
            self,
            "priority_score",
            _round6(_clip_float(self.priority_score, 0.0, 1.0, 0.0)),
        )
        object.__setattr__(
            self,
            "priority_tier",
            _normalize_enum_option(PriorityTier, self.priority_tier, PriorityTier.UNSCORED),
        )
        object.__setattr__(
            self,
            "priority_reasons",
            _safe_reasons(self.priority_reasons, limit=50),
        )
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_ref_hash": self.account_ref_hash,
            "kind": _enum_value(self.kind, AccountKind.UNKNOWN.value),
            "lifecycle_state": _enum_value(
                self.lifecycle_state,
                AccountLifecycleState.UNKNOWN.value,
            ),
            "channel": _enum_value(self.channel, AccountChannel.UNKNOWN.value),
            "opened_month": self.opened_month,
            "last_seen_month": self.last_seen_month,
            "metrics": _safe_detail_value(self.metrics),
            "links": [link.to_dict() for link in self.links],
            "link_count": int(self.link_count),
            "priority_score": float(self.priority_score),
            "priority_tier": _enum_value(self.priority_tier, PriorityTier.UNSCORED.value),
            "priority_reasons": list(self.priority_reasons),
            "metadata": _safe_detail_value(self.metadata),
            "priority_semantics": "investigative_human_review_triage_only_not_probability_of_guilt",
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "monetary_values_retained": False,
            "labels_used_as_features": False,
            "caveats": list(ACCOUNT_CAVEATS),
            "safety_flags": dict(ACCOUNT_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class AccountsResult:
    """
    Safe bounded accounts service result.
    """

    ok: bool = True
    status: ServiceStatus | str = ServiceStatus.PASSED
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    profiles: tuple[AccountProfile, ...] = ()
    links: tuple[AccountLink, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[AccountIssue, ...] = ()
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
        object.__setattr__(self, "links", tuple(self.links or ()))
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
                        "version": ACCOUNTS_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, ServiceStatus.PASSED.value),
                        "request_id": self.request_id,
                        "profile_count": len(self.profiles),
                        "profile_hashes": [
                            profile.account_ref_hash for profile in self.profiles[:64]
                        ],
                        "link_count": len(self.links),
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
            "links": [link.to_dict() for link in self.links],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(ACCOUNT_CAVEATS),
            "safety_flags": dict(ACCOUNT_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local account registry
# -----------------------------------------------------------------------------


class AccountProfileRegistry:
    """
    Bounded process-local account profile registry.

    This registry is non-durable and intended for local prototype workflows,
    tests, developer tooling, and offline evaluation harnesses only.
    """

    def __init__(self, max_profiles: int = DEFAULT_MAX_PROFILES) -> None:
        self.max_profiles = max(1, int(max_profiles))
        self._profiles: dict[str, AccountProfile] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register(self, profile: AccountProfile) -> str:
        account_hash = _clean_text(profile.account_ref_hash, MAX_HASH_LENGTH).lower()

        if not account_hash:
            return ""

        with self._lock:
            if account_hash in self._profiles:
                self._profiles[account_hash] = profile

                if account_hash in self._order:
                    self._order.remove(account_hash)

                self._order.append(account_hash)
                return account_hash

            if len(self._order) >= self.max_profiles:
                evicted = self._order.pop(0)
                self._profiles.pop(evicted, None)

            self._profiles[account_hash] = profile
            self._order.append(account_hash)
            return account_hash

    def get(self, account_ref_hash: Any) -> Optional[AccountProfile]:
        key = _clean_text(account_ref_hash, MAX_HASH_LENGTH).lower()

        with self._lock:
            return self._profiles.get(key)

    def list_profiles(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> tuple[AccountProfile, ...]:
        count = max(0, int(limit))

        with self._lock:
            if count == 0:
                return ()

            return tuple(
                self._profiles[account_hash]
                for account_hash in self._order[:count]
                if account_hash in self._profiles
            )

    def search_profiles(
        self,
        *,
        kind: Any = None,
        lifecycle_state: Any = None,
        channel: Any = None,
        min_priority: Optional[float] = None,
        max_priority: Optional[float] = None,
        limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    ) -> tuple[AccountProfile, ...]:
        normalized_kind = (
            _normalize_enum_option(AccountKind, kind, None)
            if kind is not None
            else None
        )
        normalized_state = (
            _normalize_enum_option(AccountLifecycleState, lifecycle_state, None)
            if lifecycle_state is not None
            else None
        )
        normalized_channel = (
            _normalize_enum_option(AccountChannel, channel, None)
            if channel is not None
            else None
        )
        min_score = _clip_float(min_priority, 0.0, 1.0, 0.0) if min_priority is not None else None
        max_score = _clip_float(max_priority, 0.0, 1.0, 1.0) if max_priority is not None else None
        count = max(0, int(limit))

        with self._lock:
            candidates = list(self._profiles.values())

        filtered: list[AccountProfile] = []

        for profile in candidates:
            if normalized_kind is not None and profile.kind != normalized_kind:
                continue

            if normalized_state is not None and profile.lifecycle_state != normalized_state:
                continue

            if normalized_channel is not None and profile.channel != normalized_channel:
                continue

            if min_score is not None and float(profile.priority_score) < float(min_score):
                continue

            if max_score is not None and float(profile.priority_score) > float(max_score):
                continue

            filtered.append(profile)

        filtered.sort(
            key=lambda profile: (
                -float(profile.priority_score),
                -float(profile.link_count),
                profile.account_ref_hash,
            )
        )

        return tuple(filtered[:count])

    def summarize(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> list[dict[str, Any]]:
        return [profile.to_dict() for profile in self.list_profiles(limit=limit)]

    def clear(self) -> None:
        with self._lock:
            self._profiles.clear()
            self._order.clear()

    def safe_summary(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
        with self._lock:
            kind_counter = Counter(
                _enum_value(profile.kind, AccountKind.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            state_counter = Counter(
                _enum_value(profile.lifecycle_state, AccountLifecycleState.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            tier_counter = Counter(
                _enum_value(profile.priority_tier, PriorityTier.UNSCORED.value)
                for profile in self._profiles.values()
            )

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_profiles": self.max_profiles,
            "registered_profiles": len(self._order),
            "by_kind": dict(kind_counter),
            "by_lifecycle_state": dict(state_counter),
            "by_priority_tier": dict(tier_counter),
            "recent": self.summarize(limit=limit),
            "raw_identifiers_retained": False,
            "monetary_values_retained": False,
        }


_default_registry: Optional[AccountProfileRegistry] = None
_default_registry_lock = threading.Lock()


def get_account_profile_registry(
    max_profiles: int | None = None,
    *,
    rebuild: bool = False,
) -> AccountProfileRegistry:
    """
    Return a process-wide bounded account profile registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = AccountProfileRegistry(
                max_profiles=max_profiles if max_profiles is not None else DEFAULT_MAX_PROFILES
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
    options: AccountsServiceOptions,
    issues: list[AccountIssue],
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
                    code="forbidden_account_field_dropped",
                    message="Forbidden or leakage-prone account field omitted.",
                    field=canonical,
                    details=dict(context),
                )
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_account_field",
                message="Forbidden or leakage-prone account field rejected.",
                field=canonical,
                details=dict(context),
            )
            return None

        clean[canonical] = raw_value

    return clean


def _normalize_account_kind(value: Any) -> AccountKind:
    token = _normalize_token(value)

    if not token:
        return AccountKind.UNKNOWN

    mapped = ACCOUNT_KIND_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(AccountKind, mapped, AccountKind.UNKNOWN)

    return _normalize_enum_option(AccountKind, token, AccountKind.UNKNOWN)


def _normalize_account_state(value: Any, issues: list[AccountIssue], options: AccountsServiceOptions, context: Mapping[str, Any]) -> AccountLifecycleState:
    text = _clean_text(value, 200)
    token = _normalize_token(text)

    if not token:
        return AccountLifecycleState.UNKNOWN

    if any(prohibited in token for prohibited in PROHIBITED_ACTION_TOKENS):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="unsupported_account_status_normalized_to_unknown",
            message="Account status contained adverse-action language and was normalized to unknown for safety.",
            field="status",
            details=dict(context),
        )
        return AccountLifecycleState.UNKNOWN

    mapped = ACCOUNT_STATUS_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(AccountLifecycleState, mapped, AccountLifecycleState.UNKNOWN)

    return _normalize_enum_option(AccountLifecycleState, token, AccountLifecycleState.UNKNOWN)


def _normalize_account_channel(value: Any) -> AccountChannel:
    token = _normalize_token(value)

    if not token:
        return AccountChannel.UNKNOWN

    mapped = ACCOUNT_CHANNEL_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(AccountChannel, mapped, AccountChannel.UNKNOWN)

    return _normalize_enum_option(AccountChannel, token, AccountChannel.UNKNOWN)


def _normalize_link_relation(value: Any) -> LinkRelation:
    token = _normalize_token(value)

    if not token:
        return LinkRelation.OTHER

    mapped = LINK_RELATION_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(LinkRelation, mapped, LinkRelation.OTHER)

    return _normalize_enum_option(LinkRelation, token, LinkRelation.OTHER)


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, AccountsResult):
        return []

    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "accounts", "links", "examples"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])

        return [data]

    for attr in ("accounts", "links", "records", "rows", "items"):
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
        for key in ("records", "rows", "items", "accounts", "links", "examples"):
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

    return -1


# -----------------------------------------------------------------------------
# Account and link sanitization
# -----------------------------------------------------------------------------


def _sanitize_account(
    record: Any,
    options: AccountsServiceOptions,
    issues: list[AccountIssue],
    index: int,
    start_time: float,
) -> Optional[dict[str, Any]]:
    if _time_exceeded(start_time, options.max_time_ms):
        return None

    context = {"record_type": "account", "index": index}
    view = _extract_view(record, _ALL_ACCOUNT_VIEW_KEYS)
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
            code="prohibited_account_metadata",
            message="Account record contains prohibited adverse-action language.",
            details=context,
        )
        return None

    raw_ref = _pick(clean, ACCOUNT_REF_KEYS)

    if raw_ref is None:
        raw_ref = _pick(clean, RAW_ACCOUNT_KEYS)

    if raw_ref is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="missing_account_identifier",
            message="Account record is missing a usable pseudonymous or raw account identifier.",
            field="account_id",
            details=context,
        )
        return None

    account_hash = _account_ref_hash(raw_ref, options)

    if not account_hash:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="unreadable_account_identifier",
            message="Account identifier could not be converted to a pseudonymous reference.",
            field="account_id",
            details=context,
        )
        return None

    kind = _normalize_account_kind(_pick(clean, KIND_KEYS))
    lifecycle_state = _normalize_account_state(
        _pick(clean, STATUS_KEYS),
        issues,
        options,
        context,
    )
    channel = _normalize_account_channel(_pick(clean, CHANNEL_KEYS))

    opened_month: Optional[str] = None

    for key in CREATED_KEYS:
        if key in clean:
            opened_month = _normalize_month(clean[key])

            if opened_month:
                break

    last_seen_month: Optional[str] = None

    for key in LAST_SEEN_KEYS:
        if key in clean:
            last_seen_month = _normalize_month(clean[key])

            if last_seen_month:
                break

    metrics: dict[str, Any] = {}

    for metric_key in METRIC_KEYS:
        if len(metrics) >= int(options.max_metrics):
            break

        if metric_key not in clean:
            continue

        count = _coerce_non_negative_int(clean[metric_key])
        metrics[metric_key] = _metric_bucket(count)

    return {
        "account_ref_hash": account_hash,
        "kind": _enum_value(kind, AccountKind.UNKNOWN.value),
        "lifecycle_state": _enum_value(
            lifecycle_state,
            AccountLifecycleState.UNKNOWN.value,
        ),
        "channel": _enum_value(channel, AccountChannel.UNKNOWN.value),
        "opened_month": opened_month,
        "last_seen_month": last_seen_month,
        "metrics": metrics,
        "source_indices": [index],
        "metadata": {
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "monetary_values_retained": False,
            "labels_used_as_features": False,
        },
    }


def _sanitize_link(
    record: Any,
    options: AccountsServiceOptions,
    issues: list[AccountIssue],
    index: int,
    start_time: float,
) -> Optional[AccountLink]:
    if _time_exceeded(start_time, options.max_time_ms):
        return None

    context = {"record_type": "link", "index": index}
    view = _extract_view(record, _ALL_LINK_VIEW_KEYS)
    clean = _clean_view(view, options, issues, context)

    if clean is None:
        return None

    if _contains_prohibited_action(clean):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="prohibited_link_metadata",
            message="Account link record contains prohibited adverse-action language.",
            details=context,
        )
        return None

    source_raw = _pick(clean, LINK_SOURCE_KEYS)

    if source_raw is None:
        source_raw = _pick(clean, ACCOUNT_REF_KEYS)

    target_raw = _pick(clean, LINK_TARGET_KEYS)

    if target_raw is None:
        target_raw = _pick(clean, ACCOUNT_REF_KEYS)

    if source_raw is None or target_raw is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="missing_link_endpoints",
            message="Account link is missing source or target endpoint.",
            field="source_account_id",
            details=context,
        )
        return None

    source_hash = _account_ref_hash(source_raw, options)
    target_hash = _account_ref_hash(target_raw, options)

    if not source_hash or not target_hash:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="unreadable_link_endpoint",
            message="Account link endpoint could not be converted to a pseudonymous reference.",
            details=context,
        )
        return None

    if source_hash == target_hash:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="self_link_ignored",
            message="Self-link was ignored.",
            details=context,
        )
        return None

    relation = _normalize_link_relation(_pick(clean, LINK_RELATION_KEYS))
    count = _coerce_non_negative_int(_pick(clean, LINK_COUNT_KEYS))
    bucket_label, bucket_value = _bucket_count(count)

    return AccountLink(
        relation=relation,
        source_ref_hash=source_hash,
        target_ref_hash=target_hash,
        count_bucket=bucket_label,
        count_value=bucket_value,
        metadata={
            "raw_identifiers_retained": False,
            "monetary_values_retained": False,
            "association_is_not_proof_of_common_control": True,
        },
    )


def _merge_account_base(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    for key in ("kind", "lifecycle_state", "channel"):
        if existing.get(key) in {AccountKind.UNKNOWN.value, AccountLifecycleState.UNKNOWN.value, AccountChannel.UNKNOWN.value}:
            if incoming.get(key) not in {None, AccountKind.UNKNOWN.value, AccountLifecycleState.UNKNOWN.value, AccountChannel.UNKNOWN.value}:
                existing[key] = incoming[key]

    existing_opened = existing.get("opened_month")
    incoming_opened = incoming.get("opened_month")

    if incoming_opened:
        if not existing_opened or str(incoming_opened) < str(existing_opened):
            existing["opened_month"] = incoming_opened

    existing_last_seen = existing.get("last_seen_month")
    incoming_last_seen = incoming.get("last_seen_month")

    if incoming_last_seen:
        if not existing_last_seen or str(incoming_last_seen) > str(existing_last_seen):
            existing["last_seen_month"] = incoming_last_seen

    existing_metrics = existing.setdefault("metrics", {})

    for metric_key, metric_value in (incoming.get("metrics") or {}).items():
        existing_item = existing_metrics.get(metric_key)

        if not isinstance(existing_item, Mapping):
            existing_metrics[metric_key] = metric_value
            continue

        existing_value = _as_float(existing_item.get("bucket_value"), 0.0)
        incoming_value = _as_float(metric_value.get("bucket_value"), 0.0)

        if incoming_value > existing_value:
            existing_metrics[metric_key] = metric_value

    source_indices = existing.setdefault("source_indices", [])

    for index in incoming.get("source_indices", ()): 
        if index not in source_indices:
            source_indices.append(index)

        if len(source_indices) > 100:
            break

    return existing


def _stub_account_base(account_hash: str, index: int) -> dict[str, Any]:
    return {
        "account_ref_hash": account_hash,
        "kind": AccountKind.UNKNOWN.value,
        "lifecycle_state": AccountLifecycleState.UNKNOWN.value,
        "channel": AccountChannel.UNKNOWN.value,
        "opened_month": None,
        "last_seen_month": None,
        "metrics": {},
        "source_indices": [index],
        "metadata": {
            "stub_profile": True,
            "raw_identifiers_retained": False,
            "monetary_values_retained": False,
        },
    }


def _compute_priority(
    metrics: Mapping[str, Any],
    link_count: int,
    options: AccountsServiceOptions,
) -> tuple[float, PriorityTier, tuple[str, ...]]:
    if not options.include_priority:
        return 0.0, PriorityTier.UNSCORED, ("priority_disabled",)

    total_weight = sum(float(weight) for weight in options.priority_weights.values()) + float(
        options.link_weight
    )

    if total_weight <= 0.0:
        return 0.0, PriorityTier.UNSCORED, ("no_priority_weights",)

    score = 0.0
    reasons: list[str] = []

    for metric_key, weight in sorted(options.priority_weights.items()):
        item = metrics.get(metric_key)

        if not isinstance(item, Mapping):
            continue

        bucket_value = _as_float(item.get("bucket_value"), 0.0)
        normalized = min(1.0, bucket_value / 10_000.0)
        score += float(weight) * normalized

        if normalized >= 0.50:
            reasons.append(f"elevated_{metric_key}")

    link_normalized = min(1.0, float(max(0, link_count)) / 100.0)
    score += float(options.link_weight) * link_normalized

    if link_normalized >= 0.50:
        reasons.append("high_linked_account_count")

    score = _round6(_clip_float(score / total_weight, 0.0, 1.0, 0.0))

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

    reasons.extend(
        (
            "synthetic_structural_signals_only",
            "operational_lead_only_not_proof",
            "priority_is_not_probability_of_guilt",
            "no_automatic_adverse_action",
        )
    )

    return score, tier, tuple(dict.fromkeys(reasons))


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------


class AccountsServiceEngine:
    """
    Bounded deterministic synthetic accounts service engine.
    """

    def __init__(
        self,
        options: AccountsServiceOptions | None = None,
        registry: AccountProfileRegistry | None = None,
    ) -> None:
        self.options = options or AccountsServiceOptions.from_settings()
        self.registry = registry or get_account_profile_registry(self.options.max_profiles)
        self._lock = threading.RLock()

    def normalize(self, request: Any) -> AccountsResult:
        """
        Run one bounded synthetic account profiling job.
        """
        opts = self.options
        issues: list[AccountIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)

        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": ACCOUNTS_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                    "counts": {
                        "accounts": _count_records_safe(req.accounts),
                        "links": _count_records_safe(req.links),
                    },
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: ServiceStatus,
            profiles: Sequence[AccountProfile] = (),
            links: Sequence[AccountLink] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> AccountsResult:
            resolved_counts: dict[str, int] = {
                "submitted_accounts": _count_records_safe(req.accounts),
                "submitted_links": _count_records_safe(req.links),
                "profiles": len(profiles),
                "links": len(links),
                "registered_profiles": 0,
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update(
                    {str(key): max(0, _as_int(value, 0)) for key, value in counts.items()}
                )

            resolved_counts["profiles"] = len(profiles)
            resolved_counts["links"] = len(links)
            resolved_counts["issues"] = len(issues)

            metadata = {
                "accounts_version": ACCOUNTS_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "registry": self.registry.safe_summary(limit=opts.max_summary_items),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_identifiers_retained": False,
                "raw_narratives_retained": False,
                "monetary_values_retained": False,
                "subject_label_pairs_retained": False,
                "secrets_retained": False,
                "labels_used_as_features": False,
                "priority_semantics": "investigative_human_review_triage_only",
                "caveats": list(ACCOUNT_CAVEATS),
                "safety_flags": dict(ACCOUNT_SAFETY_FLAGS),
            }

            return AccountsResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                profiles=tuple(profiles),
                links=tuple(links),
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
                code="accounts_service_disabled",
                message="Accounts service is disabled.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Accounts service requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Accounts service is blocked in production-like environments.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_accounts_action_metadata",
                message="Accounts request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        with self._lock:
            raw_accounts = _iter_records(req.accounts)[: opts.max_accounts]
            raw_links = _iter_records(req.links)[: opts.max_links] if opts.include_links else []

            if _count_records_safe(req.accounts) > int(opts.max_accounts):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="accounts_input_truncated",
                    message="Account input exceeded configured record limit and was truncated.",
                    details={
                        "submitted": _count_records_safe(req.accounts),
                        "max_accounts": int(opts.max_accounts),
                    },
                )

            if _count_records_safe(req.links) > int(opts.max_links):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="links_input_truncated",
                    message="Account link input exceeded configured record limit and was truncated.",
                    details={
                        "submitted": _count_records_safe(req.links),
                        "max_links": int(opts.max_links),
                    },
                )

            bases: dict[str, dict[str, Any]] = {}
            sanitized_accounts = 0

            for index, record in enumerate(raw_accounts):
                if _time_exceeded(start_time, opts.max_time_ms):
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="account_sanitization_time_budget_exhausted",
                        message="Account sanitization stopped after reaching configured time budget.",
                        details={
                            "processed": sanitized_accounts,
                            "remaining": max(0, len(raw_accounts) - index),
                        },
                    )
                    break

                base = _sanitize_account(record, opts, issues, index, start_time)

                if base is None:
                    continue

                account_hash = base["account_ref_hash"]
                existing = bases.get(account_hash)

                if existing is None:
                    bases[account_hash] = base
                else:
                    _merge_account_base(existing, base)

                sanitized_accounts += 1

            links: list[AccountLink] = []
            links_by_hash: dict[str, list[AccountLink]] = defaultdict(list)
            sanitized_links = 0

            for index, record in enumerate(raw_links):
                if _time_exceeded(start_time, opts.max_time_ms):
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="link_sanitization_time_budget_exhausted",
                        message="Account link sanitization stopped after reaching configured time budget.",
                        details={
                            "processed": sanitized_links,
                            "remaining": max(0, len(raw_links) - index),
                        },
                    )
                    break

                link = _sanitize_link(record, opts, issues, index, start_time)

                if link is None:
                    continue

                links.append(link)
                links_by_hash[link.source_ref_hash].append(link)
                links_by_hash[link.target_ref_hash].append(link)
                sanitized_links += 1

                if link.source_ref_hash not in bases:
                    if len(bases) < int(opts.max_profiles):
                        bases[link.source_ref_hash] = _stub_account_base(
                            link.source_ref_hash,
                            index,
                        )
                    else:
                        _append_issue(
                            issues,
                            opts.max_issues,
                            severity=IssueSeverity.WARNING,
                            code="account_profile_limit_reached",
                            message="Account profile limit reached; link endpoint was not materialized as a profile.",
                            details={"account_ref_hash": link.source_ref_hash},
                        )

                if link.target_ref_hash not in bases:
                    if len(bases) < int(opts.max_profiles):
                        bases[link.target_ref_hash] = _stub_account_base(
                            link.target_ref_hash,
                            index,
                        )
                    else:
                        _append_issue(
                            issues,
                            opts.max_issues,
                            severity=IssueSeverity.WARNING,
                            code="account_profile_limit_reached",
                            message="Account profile limit reached; link endpoint was not materialized as a profile.",
                            details={"account_ref_hash": link.target_ref_hash},
                        )

            if len(bases) > int(opts.max_profiles):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="account_profiles_truncated",
                    message="Account profiles exceeded configured limit and were truncated.",
                    details={
                        "generated": len(bases),
                        "max_profiles": int(opts.max_profiles),
                    },
                )
                retained_hashes = sorted(bases)[: int(opts.max_profiles)]
                bases = {account_hash: bases[account_hash] for account_hash in retained_hashes}

            profiles: list[AccountProfile] = []

            for account_hash in sorted(bases):
                base = bases[account_hash]
                profile_links = tuple(
                    sorted(
                        links_by_hash.get(account_hash, ()),
                        key=lambda item: (_enum_value(item.relation), item.link_id),
                    )
                )

                counterparts = {
                    link.target_ref_hash
                    if link.source_ref_hash == account_hash
                    else link.source_ref_hash
                    for link in profile_links
                }

                link_count = len(counterparts)
                metrics = dict(base.get("metrics") or {})

                if link_count:
                    metrics["linked_account_count"] = _metric_bucket(link_count)

                priority_score, priority_tier, priority_reasons = _compute_priority(
                    metrics,
                    link_count,
                    opts,
                )

                profiles.append(
                    AccountProfile(
                        account_ref_hash=account_hash,
                        kind=base.get("kind", AccountKind.UNKNOWN.value),
                        lifecycle_state=base.get(
                            "lifecycle_state",
                            AccountLifecycleState.UNKNOWN.value,
                        ),
                        channel=base.get("channel", AccountChannel.UNKNOWN.value),
                        opened_month=base.get("opened_month"),
                        last_seen_month=base.get("last_seen_month"),
                        metrics=metrics,
                        links=profile_links,
                        link_count=link_count,
                        priority_score=priority_score,
                        priority_tier=priority_tier,
                        priority_reasons=priority_reasons,
                        metadata=base.get("metadata", {}),
                    )
                )

            profiles.sort(
                key=lambda profile: (
                    -float(profile.priority_score),
                    -int(profile.link_count),
                    profile.account_ref_hash,
                )
            )

            if len(profiles) > int(opts.max_profiles):
                profiles = profiles[: int(opts.max_profiles)]

            registered = 0

            if opts.register_profiles:
                for profile in profiles:
                    try:
                        self.registry.register(profile)
                        registered += 1
                    except Exception as exc:
                        _append_issue(
                            issues,
                            opts.max_issues,
                            severity=IssueSeverity.WARNING,
                            code="account_profile_registration_failed",
                            message="Account profile registration failed.",
                            details={"exception_type": type(exc).__name__},
                        )

            kind_counter = Counter(_enum_value(profile.kind) for profile in profiles)
            state_counter = Counter(_enum_value(profile.lifecycle_state) for profile in profiles)
            channel_counter = Counter(_enum_value(profile.channel) for profile in profiles)
            tier_counter = Counter(_enum_value(profile.priority_tier) for profile in profiles)
            relation_counter = Counter(_enum_value(link.relation) for link in links)

            counts = {
                "sanitized_accounts": sanitized_accounts,
                "sanitized_links": sanitized_links,
                "registered_profiles": registered,
                "profiles_with_links": sum(1 for profile in profiles if profile.link_count),
                "kind_personal": kind_counter.get(AccountKind.PERSONAL.value, 0),
                "kind_business": kind_counter.get(AccountKind.BUSINESS.value, 0),
                "kind_merchant": kind_counter.get(AccountKind.MERCHANT.value, 0),
                "kind_entity": kind_counter.get(AccountKind.ENTITY.value, 0),
                "kind_unknown": kind_counter.get(AccountKind.UNKNOWN.value, 0),
                "state_open": state_counter.get(AccountLifecycleState.OPEN.value, 0),
                "state_dormant": state_counter.get(AccountLifecycleState.DORMANT.value, 0),
                "state_closed": state_counter.get(AccountLifecycleState.CLOSED.value, 0),
                "state_unknown": state_counter.get(AccountLifecycleState.UNKNOWN.value, 0),
                "channel_digital": channel_counter.get(AccountChannel.DIGITAL.value, 0),
                "channel_branch": channel_counter.get(AccountChannel.BRANCH.value, 0),
                "channel_atm": channel_counter.get(AccountChannel.ATM.value, 0),
                "channel_agent": channel_counter.get(AccountChannel.AGENT.value, 0),
                "channel_api": channel_counter.get(AccountChannel.API.value, 0),
                "channel_batch": channel_counter.get(AccountChannel.BATCH.value, 0),
                "channel_unknown": channel_counter.get(AccountChannel.UNKNOWN.value, 0),
                "tier_low": tier_counter.get(PriorityTier.LOW.value, 0),
                "tier_moderate": tier_counter.get(PriorityTier.MODERATE.value, 0),
                "tier_elevated": tier_counter.get(PriorityTier.ELEVATED.value, 0),
                "tier_high": tier_counter.get(PriorityTier.HIGH.value, 0),
                "tier_unscoped": tier_counter.get(PriorityTier.UNSCORED.value, 0),
                "link_transfer": relation_counter.get(LinkRelation.TRANSFER.value, 0),
                "link_shared_device": relation_counter.get(LinkRelation.SHARED_DEVICE.value, 0),
                "link_shared_ip": relation_counter.get(LinkRelation.SHARED_IP.value, 0),
                "link_complaint": relation_counter.get(LinkRelation.COMPLAINT.value, 0),
                "link_alert": relation_counter.get(LinkRelation.ALERT.value, 0),
                "link_case": relation_counter.get(LinkRelation.CASE.value, 0),
                "link_entity": relation_counter.get(LinkRelation.ENTITY.value, 0),
                "link_temporal": relation_counter.get(LinkRelation.TEMPORAL.value, 0),
                "link_exact_reference": relation_counter.get(LinkRelation.EXACT_REFERENCE.value, 0),
                "link_identifier": relation_counter.get(LinkRelation.IDENTIFIER.value, 0),
                "link_other": relation_counter.get(LinkRelation.OTHER.value, 0),
            }

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
                links=links,
                counts=counts,
            )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "registry": self.registry.safe_summary(limit=self.options.max_summary_items),
            "caveats": list(ACCOUNT_CAVEATS),
            "safety_flags": dict(ACCOUNT_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default engine and public API
# -----------------------------------------------------------------------------


_default_engine: Optional[AccountsServiceEngine] = None
_default_engine_lock = threading.Lock()


def get_accounts_options(settings: Any | None = None) -> AccountsServiceOptions:
    """
    Return accounts service options from settings.
    """
    return AccountsServiceOptions.from_settings(settings)


def get_accounts_engine(
    options: AccountsServiceOptions | None = None,
    *,
    rebuild: bool = False,
) -> AccountsServiceEngine:
    """
    Return a process-wide accounts service engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            resolved_options = options or AccountsServiceOptions.from_settings()
            _default_engine = AccountsServiceEngine(
                options=resolved_options,
                registry=get_account_profile_registry(resolved_options.max_profiles),
            )

        return _default_engine


def normalize_accounts(
    request: Any,
    options: AccountsServiceOptions | None = None,
    *,
    engine: AccountsServiceEngine | None = None,
) -> AccountsResult:
    """
    Normalize bounded synthetic account records into privacy-preserving profiles.
    """
    active_engine = engine or get_accounts_engine(options)
    return active_engine.normalize(request)


def get_account_profile(
    account_ref_hash: Any,
    *,
    registry: AccountProfileRegistry | None = None,
) -> Optional[AccountProfile]:
    """
    Return one registered account profile by pseudonymous account reference.
    """
    active_registry = registry or get_account_profile_registry()
    return active_registry.get(account_ref_hash)


def list_account_profiles(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: AccountProfileRegistry | None = None,
) -> tuple[AccountProfile, ...]:
    """
    Return registered account profiles.
    """
    active_registry = registry or get_account_profile_registry()
    return active_registry.list_profiles(limit=limit)


def search_account_profiles(
    *,
    kind: Any = None,
    lifecycle_state: Any = None,
    channel: Any = None,
    min_priority: Optional[float] = None,
    max_priority: Optional[float] = None,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: AccountProfileRegistry | None = None,
) -> tuple[AccountProfile, ...]:
    """
    Search registered account profiles using bounded safe filters.
    """
    active_registry = registry or get_account_profile_registry()
    return active_registry.search_profiles(
        kind=kind,
        lifecycle_state=lifecycle_state,
        channel=channel,
        min_priority=min_priority,
        max_priority=max_priority,
        limit=limit,
    )


def export_accounts_summary(result: AccountsResult) -> dict[str, Any]:
    """
    Export a safe public accounts service summary.
    """
    return result.to_dict()


def clear_account_registry(*, registry: AccountProfileRegistry | None = None) -> None:
    """
    Clear the process-local account profile registry.
    """
    active_registry = registry or get_account_profile_registry()
    active_registry.clear()


def get_accounts_health(*, engine: AccountsServiceEngine | None = None) -> dict[str, Any]:
    """
    Return safe accounts service health.
    """
    active_engine = engine or get_accounts_engine()
    opts = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=opts.max_summary_items)
    issues: list[AccountIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="accounts_service_disabled",
            message="Accounts service is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Accounts service requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Accounts service is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "registry": registry_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(ACCOUNT_CAVEATS),
        "safety_flags": dict(ACCOUNT_SAFETY_FLAGS),
    }


def get_accounts_metadata(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    engine: AccountsServiceEngine | None = None,
) -> dict[str, Any]:
    """
    Return safe, serializable accounts service metadata.

    This is useful for startup logs, diagnostic endpoints, tests, developer
    tooling, and architecture documentation checks.

    It must not expose raw identifiers, raw narratives, monetary values,
    secrets, environment files, database URLs, tokens, passwords, ground-truth
    labels, scenario IDs, fraud-ring IDs, model artifact paths, filesystem
    paths, executable handler references, or real customer data.
    """
    active_engine = engine or get_accounts_engine()
    options = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=limit)

    return {
        "package": "muleguard.backend.services.accounts",
        "version": ACCOUNTS_VERSION,
        "account_kinds": [kind.value for kind in AccountKind],
        "lifecycle_states": [state.value for state in AccountLifecycleState],
        "channels": [channel.value for channel in AccountChannel],
        "link_relations": [relation.value for relation in LinkRelation],
        "priority_tiers": [tier.value for tier in PriorityTier],
        "service_statuses": [status.value for status in ServiceStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "metric_keys": list(METRIC_KEYS),
        "count_buckets": [
            {"upper": upper, "label": label, "midpoint": midpoint}
            for upper, label, midpoint in COUNT_BUCKETS
        ],
        "default_options": options.safe_summary(),
        "registry": registry_summary,
        "hard_limits": {
            "max_accounts": HARD_MAX_ACCOUNTS,
            "max_links": HARD_MAX_LINKS,
            "max_profiles": HARD_MAX_PROFILES,
            "max_metrics": HARD_MAX_METRICS,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
        },
        "forbidden_account_field_count": len(FORBIDDEN_ACCOUNT_FIELDS),
        "label_leakage_field_count": len(LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(PROHIBITED_ACTION_TOKENS),
        "summary_item_limit": max(1, int(limit)),
        "caveats": list(ACCOUNT_CAVEATS),
        "safety_flags": dict(ACCOUNT_SAFETY_FLAGS),
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
    try:
        from . import (
            ServiceDescriptor as _RegistryServiceDescriptor,
            ServiceKind as _RegistryServiceKind,
            get_service_registry as _get_registry_service_registry,
        )
    except Exception:
        _RegistryServiceDescriptor = None
        _RegistryServiceKind = None
        _get_registry_service_registry = None


def build_accounts_service_descriptor(
    options: AccountsServiceOptions | None = None,
    *,
    engine: AccountsServiceEngine | None = None,
) -> Any:
    """
    Build a bounded service descriptor for the accounts service.

    If the backend services registry descriptor is unavailable, this returns a
    safe plain dictionary representation instead of failing.
    """
    active_engine = engine or get_accounts_engine(options)

    def _handler(payload: Any) -> dict[str, Any]:
        return active_engine.normalize(payload).to_dict()

    def _health() -> dict[str, Any]:
        return get_accounts_health(engine=active_engine)

    if _RegistryServiceDescriptor is None:
        return {
            "service_id": "accounts",
            "kind": "general",
            "display_name": "Accounts Service",
            "description": "Bounded synthetic account profiling and linking service.",
            "version": ACCOUNTS_VERSION,
            "enabled": active_engine.options.enabled,
            "synthetic_required": active_engine.options.synthetic_required,
            "dataset_mode": active_engine.options.dataset_mode,
            "production_like": active_engine.options.production_like,
            "allow_in_production": active_engine.options.allow_in_production,
            "capabilities": [
                "accounts",
                "profiling",
                "linking",
                "privacy",
                "synthetic_only",
            ],
            "handler_registered": True,
            "health_handler_registered": True,
            "raw_values_retained": False,
            "executable_handler_exposed": False,
            "caveats": list(ACCOUNT_CAVEATS),
            "safety_flags": dict(ACCOUNT_SAFETY_FLAGS),
        }

    kind = getattr(_RegistryServiceKind, "GENERAL", "general") if _RegistryServiceKind else "general"

    return _RegistryServiceDescriptor(
        service_id="accounts",
        kind=kind,
        display_name="Accounts Service",
        description="Bounded synthetic account profiling, linking, and priority summarization service.",
        version=ACCOUNTS_VERSION,
        enabled=active_engine.options.enabled,
        synthetic_required=active_engine.options.synthetic_required,
        dataset_mode=active_engine.options.dataset_mode,
        production_like=active_engine.options.production_like,
        allow_in_production=active_engine.options.allow_in_production,
        capabilities=(
            "accounts",
            "profiling",
            "linking",
            "privacy",
            "synthetic_only",
            "no_automatic_adverse_action",
        ),
        handler=_handler,
        health_handler=_health,
        metadata={
            "service_module": "app.services.accounts",
            "registry_backend": "process_local_in_memory",
            "raw_values_retained": False,
            "monetary_values_retained": False,
        },
    )


def register_accounts_service(
    options: AccountsServiceOptions | None = None,
    *,
    engine: AccountsServiceEngine | None = None,
    registry: Any | None = None,
    replace: bool = True,
) -> Optional[str]:
    """
    Register the accounts service descriptor with the backend services registry
    when available.
    """
    if _get_registry_service_registry is None:
        return None

    active_registry = registry or _get_registry_service_registry()
    descriptor = build_accounts_service_descriptor(options=options, engine=engine)

    try:
        return active_registry.register(descriptor, replace=replace)
    except Exception:
        return None


__all__ = [
    "ACCOUNTS_VERSION",
    "AccountChannel",
    "AccountIssue",
    "AccountKind",
    "AccountLifecycleState",
    "AccountLink",
    "AccountProfile",
    "AccountProfileRegistry",
    "AccountsRequest",
    "AccountsResult",
    "AccountsServiceEngine",
    "AccountsServiceOptions",
    "IssueSeverity",
    "LinkRelation",
    "PriorityTier",
    "ServiceStatus",
    "build_accounts_service_descriptor",
    "clear_account_registry",
    "export_accounts_summary",
    "get_account_profile",
    "get_account_profile_registry",
    "get_accounts_engine",
    "get_accounts_health",
    "get_accounts_metadata",
    "get_accounts_options",
    "list_account_profiles",
    "normalize_accounts",
    "register_accounts_service",
    "search_account_profiles",
]