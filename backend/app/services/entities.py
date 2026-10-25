"""
MULEGUARD backend entities service.

This module provides the canonical bounded synthetic entity profiling,
normalization, co-occurrence linkage, and investigative attention service for
the MULEGUARD investigative prototype.

Primary responsibilities:

- normalize bounded synthetic entity observations into privacy-preserving
  entity profiles using salted one-way pseudonymous entity references;
- support bounded synthetic entity kinds including devices, network indicators,
  phone handles, email handles, UPI/VPA handles, addresses, accounts, subjects,
  organizations, and generic entities;
- never retain, log, return, hash-and-store, or otherwise persist raw entity
  identifiers, raw PII, raw narratives, raw monetary amounts, raw timestamps,
  labels, ground-truth fields, secrets, tokens, passwords, database URLs,
  filesystem paths, or model artifact paths;
- derive bounded entity co-occurrence links from synthetic observations without
  implying common control, ownership, wrongdoing, or criminal association;
- canonicalize entity kind, status, channel, source category, and temporal
  bucket signals using deterministic bounded maps;
- compute bounded investigative attention scores and tiers for human review
  triage only, with explicit non-calibration and non-adverse-action caveats;
- maintain a bounded process-local entity profile and link registry for local
  prototype workflows, tests, developer tooling, and offline evaluation
  harnesses;
- expose a safe service descriptor compatible with the MULEGUARD backend
  services registry when available;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module profiles and summarizes synthetic entities only. It does not
authenticate users, authorize actions, freeze accounts, block accounts,
blacklist accounts, close accounts, restrict services, deny services, terminate
relationships, suspend accounts, refer matters to law enforcement, make credit,
employment, housing, insurance, benefits, or other consequential decisions,
train models, deploy models, persist durable artifacts, call external systems,
or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for entity profiling.
- Entity profiles, links, and attention scores are investigative leads or human
  workflow artefacts only. They are not proof of wrongdoing.
- Attention scores and tiers are not probabilities of guilt.
- Shared devices, IPs, phones, emails, UPI handles, addresses, or other entities
  are association patterns only. They are not proof of common control.
- Labels must never be used as entity features or attention criteria.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected.
- Raw entity identifiers are not retained. When raw entity values are accepted
  transiently, they are normalized and hashed immediately into salted
  pseudonymous references and then discarded.
- Raw narratives are forbidden inputs.
- Raw monetary amounts are not retained.
- Raw timestamps are not retained. Only bounded month and age-bucket signals
  are emitted.
- Entity operations must never trigger automatic adverse customer action such
  as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable entity signals are reported honestly as unavailable
  rather than invented.
- The bundled entity registry is process-local, non-durable, and bounded for
  local prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external identity providers, device fingerprinting
  services, IP geolocation services, phone carriers, email verification
  services, UPI directories, address services, watchlists, sanctions lists,
  graph databases, model runtimes, or network APIs.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models or entity decisioning rules.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable entity store.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, cycle
candidates, community candidates, filtered graphs, serialized graphs,
correlation candidates, confidence records, account profiles, transaction
profiles, complaint profiles, entity profiles, entity links, attention scores,
explanations, validation reports, and case dispositions are investigative leads
or human workflow artefacts only. They are not proof of wrongdoing and must not
trigger automatic adverse customer action.
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


logger = logging.getLogger("muleguard.backend.services.entities")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

ENTITIES_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.services.entities.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

DEFAULT_MAX_RECORDS: Final[int] = 10_000
HARD_MAX_RECORDS: Final[int] = 100_000

DEFAULT_MAX_ENTITIES: Final[int] = 10_000
HARD_MAX_ENTITIES: Final[int] = 100_000

DEFAULT_MAX_LINKS: Final[int] = 50_000
HARD_MAX_LINKS: Final[int] = 500_000

DEFAULT_MAX_PROFILES: Final[int] = 10_000
HARD_MAX_PROFILES: Final[int] = 100_000

DEFAULT_MAX_ENTITIES_PER_RECORD: Final[int] = 16
HARD_MAX_ENTITIES_PER_RECORD: Final[int] = 128

DEFAULT_MAX_ASSOCIATED_REFS: Final[int] = 20
HARD_MAX_ASSOCIATED_REFS: Final[int] = 200

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

DEFAULT_PRIORITY_DEGREE_WEIGHT: Final[float] = 0.28
DEFAULT_PRIORITY_DIVERSITY_WEIGHT: Final[float] = 0.16
DEFAULT_PRIORITY_RECENCY_WEIGHT: Final[float] = 0.20
DEFAULT_PRIORITY_LINKAGE_WEIGHT: Final[float] = 0.20
DEFAULT_PRIORITY_SOURCE_WEIGHT: Final[float] = 0.10
DEFAULT_PRIORITY_STATUS_WEIGHT: Final[float] = 0.06

DEGREE_CAP: Final[int] = 50
ACCOUNT_CAP: Final[int] = 20
TRANSACTION_CAP: Final[int] = 50
COMPLAINT_CAP: Final[int] = 10
ALERT_CAP: Final[int] = 10
SOURCE_CATEGORY_CAP: Final[int] = 5

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")
_NON_DIGIT_RE: Final[re.Pattern[str]] = re.compile(r"\D")

_MISSING: Final[object] = object()

ENTITY_REF_KEYS: Final[tuple[str, ...]] = (
    "entity_ref_hash",
    "entity_hash",
    "reference_hash",
)

KIND_KEYS: Final[tuple[str, ...]] = (
    "entity_kind",
    "kind",
    "entity_type",
    "type",
    "category",
)

SAFE_ENTITY_HASH_KEYS: Final[tuple[str, ...]] = (
    "device_hash",
    "ip_hash",
    "phone_hash",
    "email_hash",
    "upi_hash",
    "address_hash",
    "account_hash",
    "subject_hash",
    "organization_hash",
    "entity_hash",
)

TRANSIENT_RAW_ENTITY_KEYS: Final[tuple[str, ...]] = (
    "device_id",
    "device_identifier",
    "device_ref",
    "device",
    "ip_address",
    "ip",
    "client_ip",
    "source_ip",
    "phone_number",
    "phone",
    "msisdn",
    "mobile_number",
    "email_address",
    "email",
    "e_mail",
    "upi_id",
    "upi_handle",
    "vpa",
    "upi",
    "address",
    "postal_address",
    "address_line",
    "location",
    "entity_value",
    "identifier",
    "handle",
    "alias",
    "entity_id",
    "uuid",
    "guid",
)

SOURCE_CATEGORY_KEYS: Final[tuple[str, ...]] = (
    "source_category",
    "record_category",
    "origin_category",
    "source_record_category",
    "observation_source",
)

STATUS_KEYS: Final[tuple[str, ...]] = (
    "status",
    "entity_status",
    "lifecycle_state",
    "state",
)

CHANNEL_KEYS: Final[tuple[str, ...]] = (
    "channel",
    "source_channel",
    "observed_channel",
    "intake_channel",
)

TIMESTAMP_KEYS: Final[tuple[str, ...]] = (
    "observed_at",
    "occurred_at",
    "created_at",
    "received_at",
    "triggered_at",
    "opened_at",
    "timestamp",
    "time",
    "date",
)

ACCOUNT_REF_KEYS: Final[tuple[str, ...]] = (
    "account_ref_hash",
    "account_hash",
    "account_id",
    "acct_id",
    "sender_account_id",
    "receiver_account_id",
    "victim_account_id",
    "suspected_account_id",
    "reporter_account_id",
    "subject_account_id",
    "target_account_id",
    "counterparty_account_id",
    "payee_account_id",
)

TRANSACTION_REF_KEYS: Final[tuple[str, ...]] = (
    "transaction_ref_hash",
    "transaction_hash",
    "transaction_id",
    "txn_id",
)

COMPLAINT_REF_KEYS: Final[tuple[str, ...]] = (
    "complaint_ref_hash",
    "complaint_hash",
    "complaint_id",
    "case_id",
    "report_id",
)

ALERT_REF_KEYS: Final[tuple[str, ...]] = (
    "alert_ref_hash",
    "alert_hash",
    "alert_id",
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

FORBIDDEN_ENTITY_FIELDS: Final[frozenset[str]] = frozenset(
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
        "file_path",
        "fraud_label",
        "fraud_ring_id",
        "ground_truth",
        "ground_truth_label",
        "identifier_raw",
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
    }
)

FORBIDDEN_ENTITY_TOKENS: Final[tuple[str, ...]] = (
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
    "customer_data",
    "real_data",
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

ENTITY_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic entity profiling only. Do not use with real customer data.",
    "Entity profiles, links, and attention scores are investigative leads only and are not proof of wrongdoing.",
    "Attention scores and tiers are not probabilities of guilt.",
    "Shared entities are association patterns only and are not proof of common control.",
    "Entity profiling must not trigger automatic adverse customer action.",
    "Labels must never be used as entity features or attention criteria.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw entity identifiers are not retained. Raw values are transient, normalized, and salted-hashed immediately.",
    "Raw narratives, secrets, tokens, passwords, database URLs, filesystem paths, and model artifact paths are forbidden.",
    "Raw timestamps are not retained. Only bounded month and age-bucket signals are emitted.",
    "The bundled entity registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

ENTITY_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_raw_identifiers_retained": True,
        "no_raw_narratives_retained": True,
        "no_raw_timestamps_retained": True,
        "salted_pseudonymous_entity_references": True,
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
        "deterministic_entity_profiling": True,
        "bounded_entity_profiling_required": True,
        "attention_is_investigative_only": True,
        "attention_is_not_probability_of_guilt": True,
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

ENTITY_KIND_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "device": "DEVICE",
        "device_id": "DEVICE",
        "device_identifier": "DEVICE",
        "ip": "IP",
        "ip_address": "IP",
        "network": "IP",
        "phone": "PHONE",
        "phone_number": "PHONE",
        "msisdn": "PHONE",
        "mobile": "PHONE",
        "email": "EMAIL",
        "email_address": "EMAIL",
        "upi": "UPI",
        "upi_id": "UPI",
        "vpa": "UPI",
        "address": "ADDRESS",
        "postal_address": "ADDRESS",
        "location": "ADDRESS",
        "account": "ACCOUNT",
        "acct": "ACCOUNT",
        "subject": "SUBJECT",
        "person": "SUBJECT",
        "organization": "ORGANIZATION",
        "organisation": "ORGANIZATION",
        "org": "ORGANIZATION",
        "entity": "GENERIC",
        "generic": "GENERIC",
        "unknown": "UNKNOWN",
    }
)

ENTITY_STATUS_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "active": "ACTIVE",
        "live": "ACTIVE",
        "current": "ACTIVE",
        "observed": "ACTIVE",
        "inactive": "INACTIVE",
        "dormant": "INACTIVE",
        "idle": "INACTIVE",
        "stale": "STALE",
        "old": "STALE",
        "expired": "STALE",
        "unknown": "UNKNOWN",
    }
)

ENTITY_CHANNEL_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "digital": "DIGITAL",
        "online": "DIGITAL",
        "mobile": "DIGITAL",
        "web": "DIGITAL",
        "app": "DIGITAL",
        "branch": "BRANCH",
        "atm": "ATM",
        "agent": "AGENT",
        "api": "API",
        "batch": "BATCH",
        "other": "OTHER",
        "unknown": "UNKNOWN",
    }
)

SOURCE_CATEGORY_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "complaint": "COMPLAINT",
        "report": "COMPLAINT",
        "transaction": "TRANSACTION",
        "txn": "TRANSACTION",
        "transfer": "TRANSACTION",
        "payment": "TRANSACTION",
        "alert": "ALERT",
        "case": "CASE",
        "note": "NOTE",
        "entity": "ENTITY",
        "other": "OTHER",
        "unknown": "UNKNOWN",
    }
)

COUNT_BUCKET_SPECS: Final[tuple[tuple[Optional[int], str, float], ...]] = (
    (0, "zero", 0.00),
    (2, "low", 0.20),
    (9, "moderate", 0.45),
    (49, "elevated", 0.70),
    (99, "high", 0.90),
    (None, "very_high", 1.00),
)

ELEVATED_SOURCE_CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        "complaint",
        "alert",
        "case",
    }
)

_SAFE_ENTITY_HASH_KIND_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "device_hash": "DEVICE",
        "ip_hash": "IP",
        "phone_hash": "PHONE",
        "email_hash": "EMAIL",
        "upi_hash": "UPI",
        "address_hash": "ADDRESS",
        "account_hash": "ACCOUNT",
        "subject_hash": "SUBJECT",
        "organization_hash": "ORGANIZATION",
        "entity_hash": "GENERIC",
    }
)

_TRANSIENT_RAW_ENTITY_KIND_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "device_id": "DEVICE",
        "device_identifier": "DEVICE",
        "device_ref": "DEVICE",
        "device": "DEVICE",
        "ip_address": "IP",
        "ip": "IP",
        "client_ip": "IP",
        "source_ip": "IP",
        "phone_number": "PHONE",
        "phone": "PHONE",
        "msisdn": "PHONE",
        "mobile_number": "PHONE",
        "email_address": "EMAIL",
        "email": "EMAIL",
        "e_mail": "EMAIL",
        "upi_id": "UPI",
        "upi_handle": "UPI",
        "vpa": "UPI",
        "upi": "UPI",
        "address": "ADDRESS",
        "postal_address": "ADDRESS",
        "address_line": "ADDRESS",
        "location": "ADDRESS",
        "entity_value": "GENERIC",
        "identifier": "GENERIC",
        "handle": "GENERIC",
        "alias": "GENERIC",
        "entity_id": "GENERIC",
        "uuid": "GENERIC",
        "guid": "GENERIC",
    }
)

_TRANSIENT_RAW_ENTITY_CANONICAL_KEYS: Final[frozenset[str]] = frozenset(
    _TRANSIENT_RAW_ENTITY_KIND_MAP.keys()
)

_ALL_ENTITY_VIEW_KEYS: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            *ENTITY_REF_KEYS,
            *KIND_KEYS,
            *SAFE_ENTITY_HASH_KEYS,
            *TRANSIENT_RAW_ENTITY_KEYS,
            *SOURCE_CATEGORY_KEYS,
            *STATUS_KEYS,
            *CHANNEL_KEYS,
            *TIMESTAMP_KEYS,
            *ACCOUNT_REF_KEYS,
            *TRANSACTION_REF_KEYS,
            *COMPLAINT_REF_KEYS,
            *ALERT_REF_KEYS,
        }
    )
)

_ENTITY_LIKE_KEYS: Final[frozenset[str]] = frozenset(_ALL_ENTITY_VIEW_KEYS)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class EntityKind(str, Enum):
    """
    Bounded synthetic entity kind.
    """

    DEVICE = "device"
    IP = "ip"
    PHONE = "phone"
    EMAIL = "email"
    UPI = "upi"
    ADDRESS = "address"
    ACCOUNT = "account"
    SUBJECT = "subject"
    ORGANIZATION = "organization"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class EntityStatus(str, Enum):
    """
    Bounded observational entity status.

    These states are descriptive only. They must not be interpreted as
    authorization to take adverse action.
    """

    ACTIVE = "active"
    INACTIVE = "inactive"
    STALE = "stale"
    UNKNOWN = "unknown"


class EntityChannel(str, Enum):
    """
    Bounded entity observation channel.
    """

    DIGITAL = "digital"
    BRANCH = "branch"
    ATM = "atm"
    AGENT = "agent"
    API = "api"
    BATCH = "batch"
    OTHER = "other"
    UNKNOWN = "unknown"


class SourceCategory(str, Enum):
    """
    Bounded source record category for entity observations.
    """

    COMPLAINT = "complaint"
    TRANSACTION = "transaction"
    ALERT = "alert"
    CASE = "case"
    NOTE = "note"
    ENTITY = "entity"
    OTHER = "other"
    UNKNOWN = "unknown"


class PriorityTier(str, Enum):
    """
    Bounded investigative attention tier.

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
    Overall entities service status.
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

    if canonical in FORBIDDEN_ENTITY_FIELDS:
        return True

    if canonical.startswith("raw_") or canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in FORBIDDEN_ENTITY_TOKENS)


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


def _coerce_scalar_text(value: Any) -> Optional[str]:
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return _clean_text(value, 256) or None

    if isinstance(value, (int, float, Decimal)):
        try:
            return _clean_text(value, 256) or None
        except Exception:
            return None

    if isinstance(value, Enum):
        return _coerce_scalar_text(value.value)

    return None


def _months_between(dt: Optional[datetime], now: Optional[datetime] = None) -> Optional[int]:
    normalized = _ensure_utc(dt)

    if normalized is None:
        return None

    reference = _ensure_utc(now) or _now_utc()

    if normalized > reference:
        return 0

    months = (reference.year - normalized.year) * 12 + (reference.month - normalized.month)

    if reference.day < normalized.day:
        months -= 1

    return max(0, months)


def _bucket_from_count(count: int, specs: Sequence[tuple[Optional[int], str, float]]) -> tuple[str, float]:
    safe_count = max(0, int(count))

    for upper, label, score in specs:
        if upper is None or safe_count <= upper:
            return label, score

    return specs[-1][1], specs[-1][2]


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
# Entity normalization helpers
# -----------------------------------------------------------------------------


def _normalize_entity_kind(value: Any) -> EntityKind:
    token = _normalize_token(value)

    if not token:
        return EntityKind.UNKNOWN

    mapped = ENTITY_KIND_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(EntityKind, mapped, EntityKind.UNKNOWN)

    return _normalize_enum_option(EntityKind, token, EntityKind.UNKNOWN)


def _normalize_entity_status(
    value: Any,
    issues: list["EntityIssue"],
    options: "EntitiesServiceOptions",
    context: Mapping[str, Any],
) -> EntityStatus:
    text = _clean_text(value, 200)
    token = _normalize_token(text)

    if not token:
        return EntityStatus.UNKNOWN

    if any(prohibited in token for prohibited in PROHIBITED_ACTION_TOKENS):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="unsupported_entity_status_normalized_to_unknown",
            message="Entity status contained adverse-action language and was normalized to unknown for safety.",
            field="status",
            details=dict(context),
        )
        return EntityStatus.UNKNOWN

    mapped = ENTITY_STATUS_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(EntityStatus, mapped, EntityStatus.UNKNOWN)

    return _normalize_enum_option(EntityStatus, token, EntityStatus.UNKNOWN)


def _normalize_entity_channel(value: Any) -> EntityChannel:
    token = _normalize_token(value)

    if not token:
        return EntityChannel.UNKNOWN

    mapped = ENTITY_CHANNEL_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(EntityChannel, mapped, EntityChannel.UNKNOWN)

    return _normalize_enum_option(EntityChannel, token, EntityChannel.UNKNOWN)


def _normalize_source_category(value: Any) -> SourceCategory:
    token = _normalize_token(value)

    if not token:
        return SourceCategory.UNKNOWN

    mapped = SOURCE_CATEGORY_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(SourceCategory, mapped, SourceCategory.UNKNOWN)

    return _normalize_enum_option(SourceCategory, token, SourceCategory.UNKNOWN)


def _normalize_entity_value(value: str, kind: EntityKind) -> str:
    text = _clean_text(value, 256)

    if not text:
        return ""

    if kind == EntityKind.EMAIL:
        return text.lower().strip()

    if kind == EntityKind.UPI:
        return text.lower().strip()

    if kind == EntityKind.PHONE:
        digits = _NON_DIGIT_RE.sub("", text)
        return digits or text.lower().strip()

    if kind == EntityKind.IP:
        return text.lower().strip()

    if kind == EntityKind.ADDRESS:
        return " ".join(text.lower().split())

    if kind == EntityKind.DEVICE:
        return text.lower().strip()

    return text.lower().strip()


def _entity_ref_hash(
    value: Any,
    kind: EntityKind,
    options: "EntitiesServiceOptions",
) -> Optional[str]:
    text = _coerce_scalar_text(value)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    normalized = _normalize_entity_value(text, kind)

    if not normalized:
        return None

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.services.entities.entity.{kind.value}.{namespace}"
    return _hmac_hex(options.salt, domain, normalized)[:40]


def _party_ref_hash(
    value: Any,
    options: "EntitiesServiceOptions",
    domain_suffix: str,
) -> Optional[str]:
    text = _coerce_scalar_text(value)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.services.entities.{domain_suffix}.{namespace}"
    return _hmac_hex(options.salt, domain, text.lower().strip())[:40]


def _account_ref_hash(value: Any, options: "EntitiesServiceOptions") -> Optional[str]:
    return _party_ref_hash(value, options, "account")


def _transaction_ref_hash(value: Any, options: "EntitiesServiceOptions") -> Optional[str]:
    return _party_ref_hash(value, options, "transaction")


def _complaint_ref_hash(value: Any, options: "EntitiesServiceOptions") -> Optional[str]:
    return _party_ref_hash(value, options, "complaint")


def _alert_ref_hash(value: Any, options: "EntitiesServiceOptions") -> Optional[str]:
    return _party_ref_hash(value, options, "alert")


# -----------------------------------------------------------------------------
# Issue model and helpers
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EntityIssue:
    """
    Safe entity-service issue.

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


def _coerce_issue(value: Any) -> EntityIssue:
    if isinstance(value, EntityIssue):
        return value

    if isinstance(value, Mapping):
        return EntityIssue(
            severity=value.get("severity", IssueSeverity.WARNING),
            code=value.get("code", "unstructured_issue"),
            message=value.get("message", ""),
            field=value.get("field"),
            details=value.get("details", {}),
        )

    return EntityIssue(
        severity=IssueSeverity.WARNING,
        code="unstructured_issue",
        message=_clean_text(value, MAX_REASON_TEXT_LENGTH),
    )


def _append_issue(
    issues: list[EntityIssue],
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

        issues[-1] = EntityIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        EntityIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, MAX_REASON_TEXT_LENGTH),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[EntityIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[EntityIssue]) -> tuple[EntityIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[EntityIssue] = []

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
class EntitiesServiceOptions:
    """
    Bounded synthetic entities service policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    max_records: int = DEFAULT_MAX_RECORDS
    max_entities: int = DEFAULT_MAX_ENTITIES
    max_links: int = DEFAULT_MAX_LINKS
    max_profiles: int = DEFAULT_MAX_PROFILES
    max_entities_per_record: int = DEFAULT_MAX_ENTITIES_PER_RECORD
    max_associated_refs: int = DEFAULT_MAX_ASSOCIATED_REFS
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS

    allow_raw_entity_values: bool = True
    include_links: bool = True
    include_priority: bool = True
    register_profiles: bool = True
    drop_forbidden_fields: bool = True

    low_threshold: float = DEFAULT_LOW_THRESHOLD
    moderate_threshold: float = DEFAULT_MODERATE_THRESHOLD
    elevated_threshold: float = DEFAULT_ELEVATED_THRESHOLD

    priority_degree_weight: float = DEFAULT_PRIORITY_DEGREE_WEIGHT
    priority_diversity_weight: float = DEFAULT_PRIORITY_DIVERSITY_WEIGHT
    priority_recency_weight: float = DEFAULT_PRIORITY_RECENCY_WEIGHT
    priority_linkage_weight: float = DEFAULT_PRIORITY_LINKAGE_WEIGHT
    priority_source_weight: float = DEFAULT_PRIORITY_SOURCE_WEIGHT
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
            "max_records",
            _clamp_int(self.max_records, 1, HARD_MAX_RECORDS, DEFAULT_MAX_RECORDS),
        )
        object.__setattr__(
            self,
            "max_entities",
            _clamp_int(self.max_entities, 1, HARD_MAX_ENTITIES, DEFAULT_MAX_ENTITIES),
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
            "max_entities_per_record",
            _clamp_int(
                self.max_entities_per_record,
                1,
                HARD_MAX_ENTITIES_PER_RECORD,
                DEFAULT_MAX_ENTITIES_PER_RECORD,
            ),
        )
        object.__setattr__(
            self,
            "max_associated_refs",
            _clamp_int(
                self.max_associated_refs,
                1,
                HARD_MAX_ASSOCIATED_REFS,
                DEFAULT_MAX_ASSOCIATED_REFS,
            ),
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

        object.__setattr__(self, "allow_raw_entity_values", _as_bool(self.allow_raw_entity_values, True))
        object.__setattr__(self, "include_links", _as_bool(self.include_links, True))
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

        degree_w = _clamp_float(self.priority_degree_weight, 0.0, 1.0, DEFAULT_PRIORITY_DEGREE_WEIGHT)
        diversity_w = _clamp_float(
            self.priority_diversity_weight,
            0.0,
            1.0,
            DEFAULT_PRIORITY_DIVERSITY_WEIGHT,
        )
        recency_w = _clamp_float(self.priority_recency_weight, 0.0, 1.0, DEFAULT_PRIORITY_RECENCY_WEIGHT)
        linkage_w = _clamp_float(self.priority_linkage_weight, 0.0, 1.0, DEFAULT_PRIORITY_LINKAGE_WEIGHT)
        source_w = _clamp_float(self.priority_source_weight, 0.0, 1.0, DEFAULT_PRIORITY_SOURCE_WEIGHT)
        status_w = _clamp_float(self.priority_status_weight, 0.0, 1.0, DEFAULT_PRIORITY_STATUS_WEIGHT)

        total = degree_w + diversity_w + recency_w + linkage_w + source_w + status_w

        if total <= 0.0:
            degree_w = DEFAULT_PRIORITY_DEGREE_WEIGHT
            diversity_w = DEFAULT_PRIORITY_DIVERSITY_WEIGHT
            recency_w = DEFAULT_PRIORITY_RECENCY_WEIGHT
            linkage_w = DEFAULT_PRIORITY_LINKAGE_WEIGHT
            source_w = DEFAULT_PRIORITY_SOURCE_WEIGHT
            status_w = DEFAULT_PRIORITY_STATUS_WEIGHT
            total = degree_w + diversity_w + recency_w + linkage_w + source_w + status_w

        object.__setattr__(self, "priority_degree_weight", _round6(degree_w / total))
        object.__setattr__(self, "priority_diversity_weight", _round6(diversity_w / total))
        object.__setattr__(self, "priority_recency_weight", _round6(recency_w / total))
        object.__setattr__(self, "priority_linkage_weight", _round6(linkage_w / total))
        object.__setattr__(self, "priority_source_weight", _round6(source_w / total))
        object.__setattr__(self, "priority_status_weight", _round6(status_w / total))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "EntitiesServiceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "ENTITIES_SERVICE_SALT", None)
            or _setting(settings, "SERVICES_ENTITIES_SALT", None)
            or _setting(settings, "COMPLAINTS_SERVICE_SALT", None)
            or _setting(settings, "TRANSACTIONS_SERVICE_SALT", None)
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
            enabled=_as_bool(_setting(settings, "ENTITIES_SERVICE_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "ENTITIES_SERVICE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "ENTITIES_SERVICE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "ENTITIES_SERVICE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "ENTITIES_SERVICE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_records=_as_int(
                _setting(settings, "ENTITIES_SERVICE_MAX_RECORDS", DEFAULT_MAX_RECORDS),
                DEFAULT_MAX_RECORDS,
            ),
            max_entities=_as_int(
                _setting(settings, "ENTITIES_SERVICE_MAX_ENTITIES", DEFAULT_MAX_ENTITIES),
                DEFAULT_MAX_ENTITIES,
            ),
            max_links=_as_int(
                _setting(settings, "ENTITIES_SERVICE_MAX_LINKS", DEFAULT_MAX_LINKS),
                DEFAULT_MAX_LINKS,
            ),
            max_profiles=_as_int(
                _setting(settings, "ENTITIES_SERVICE_MAX_PROFILES", DEFAULT_MAX_PROFILES),
                DEFAULT_MAX_PROFILES,
            ),
            max_entities_per_record=_as_int(
                _setting(
                    settings,
                    "ENTITIES_SERVICE_MAX_ENTITIES_PER_RECORD",
                    DEFAULT_MAX_ENTITIES_PER_RECORD,
                ),
                DEFAULT_MAX_ENTITIES_PER_RECORD,
            ),
            max_associated_refs=_as_int(
                _setting(
                    settings,
                    "ENTITIES_SERVICE_MAX_ASSOCIATED_REFS",
                    DEFAULT_MAX_ASSOCIATED_REFS,
                ),
                DEFAULT_MAX_ASSOCIATED_REFS,
            ),
            max_issues=_as_int(
                _setting(settings, "ENTITIES_SERVICE_MAX_ISSUES", DEFAULT_MAX_ISSUES),
                DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "ENTITIES_SERVICE_MAX_SUMMARY_ITEMS", DEFAULT_MAX_SUMMARY_ITEMS),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "ENTITIES_SERVICE_MAX_TIME_MS", DEFAULT_MAX_TIME_MS),
                DEFAULT_MAX_TIME_MS,
            ),
            allow_raw_entity_values=_as_bool(
                _setting(settings, "ENTITIES_SERVICE_ALLOW_RAW_ENTITY_VALUES", True),
                True,
            ),
            include_links=_as_bool(_setting(settings, "ENTITIES_SERVICE_INCLUDE_LINKS", True), True),
            include_priority=_as_bool(_setting(settings, "ENTITIES_SERVICE_INCLUDE_PRIORITY", True), True),
            register_profiles=_as_bool(
                _setting(settings, "ENTITIES_SERVICE_REGISTER_PROFILES", True),
                True,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "ENTITIES_SERVICE_DROP_FORBIDDEN_FIELDS", True),
                True,
            ),
            low_threshold=_as_float(
                _setting(settings, "ENTITIES_SERVICE_LOW_THRESHOLD", DEFAULT_LOW_THRESHOLD),
                DEFAULT_LOW_THRESHOLD,
            ),
            moderate_threshold=_as_float(
                _setting(settings, "ENTITIES_SERVICE_MODERATE_THRESHOLD", DEFAULT_MODERATE_THRESHOLD),
                DEFAULT_MODERATE_THRESHOLD,
            ),
            elevated_threshold=_as_float(
                _setting(settings, "ENTITIES_SERVICE_ELEVATED_THRESHOLD", DEFAULT_ELEVATED_THRESHOLD),
                DEFAULT_ELEVATED_THRESHOLD,
            ),
            priority_degree_weight=_as_float(
                _setting(settings, "ENTITIES_SERVICE_PRIORITY_DEGREE_WEIGHT", DEFAULT_PRIORITY_DEGREE_WEIGHT),
                DEFAULT_PRIORITY_DEGREE_WEIGHT,
            ),
            priority_diversity_weight=_as_float(
                _setting(
                    settings,
                    "ENTITIES_SERVICE_PRIORITY_DIVERSITY_WEIGHT",
                    DEFAULT_PRIORITY_DIVERSITY_WEIGHT,
                ),
                DEFAULT_PRIORITY_DIVERSITY_WEIGHT,
            ),
            priority_recency_weight=_as_float(
                _setting(settings, "ENTITIES_SERVICE_PRIORITY_RECENCY_WEIGHT", DEFAULT_PRIORITY_RECENCY_WEIGHT),
                DEFAULT_PRIORITY_RECENCY_WEIGHT,
            ),
            priority_linkage_weight=_as_float(
                _setting(settings, "ENTITIES_SERVICE_PRIORITY_LINKAGE_WEIGHT", DEFAULT_PRIORITY_LINKAGE_WEIGHT),
                DEFAULT_PRIORITY_LINKAGE_WEIGHT,
            ),
            priority_source_weight=_as_float(
                _setting(settings, "ENTITIES_SERVICE_PRIORITY_SOURCE_WEIGHT", DEFAULT_PRIORITY_SOURCE_WEIGHT),
                DEFAULT_PRIORITY_SOURCE_WEIGHT,
            ),
            priority_status_weight=_as_float(
                _setting(settings, "ENTITIES_SERVICE_PRIORITY_STATUS_WEIGHT", DEFAULT_PRIORITY_STATUS_WEIGHT),
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
                "max_records": self.max_records,
                "max_entities": self.max_entities,
                "max_links": self.max_links,
                "max_profiles": self.max_profiles,
                "max_entities_per_record": self.max_entities_per_record,
                "max_associated_refs": self.max_associated_refs,
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
                    "degree": _round6(self.priority_degree_weight),
                    "diversity": _round6(self.priority_diversity_weight),
                    "recency": _round6(self.priority_recency_weight),
                    "linkage": _round6(self.priority_linkage_weight),
                    "source": _round6(self.priority_source_weight),
                    "status": _round6(self.priority_status_weight),
                },
            },
            "flags": {
                "allow_raw_entity_values": self.allow_raw_entity_values,
                "include_links": self.include_links,
                "register_profiles": self.register_profiles,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
            "entity_policy": "salted_pseudonymous_references_only_no_raw_identifier_retention",
            "temporal_policy": "bounded_month_and_age_buckets_only_no_raw_timestamps",
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "entities",
        "observations",
        "records",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class EntitiesRequest:
    """
    Bounded synthetic entities service request.
    """

    entities: Any = None
    observations: Any = None
    records: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> EntitiesRequest:
    if isinstance(request, EntitiesRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(EntitiesRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return EntitiesRequest(**clean)
            except Exception:
                return EntitiesRequest(
                    entities=payload.get(
                        "entities",
                        payload.get("observations", payload.get("records", request)),
                    )
                )

        if any(_canonical_field_name(key) in _ENTITY_LIKE_KEYS for key in payload):
            return EntitiesRequest(entities=[payload])

        return EntitiesRequest(metadata=request)

    if isinstance(request, (list, tuple, set, frozenset)):
        return EntitiesRequest(entities=request)

    return EntitiesRequest(entities=request)


# -----------------------------------------------------------------------------
# Public models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EntityLink:
    """
    One bounded synthetic entity co-occurrence link.

    Links are structural association hints only. They are not proof of common
    control, ownership, wrongdoing, or criminal association.
    """

    link_id: str = ""
    source_ref_hash: str = ""
    target_ref_hash: str = ""
    source_kind: EntityKind | str = EntityKind.UNKNOWN
    target_kind: EntityKind | str = EntityKind.UNKNOWN
    count_bucket: str = "zero"
    count_score: float = 0.0
    first_month: Optional[str] = None
    last_month: Optional[str] = None
    dominant_source_category: SourceCategory | str = SourceCategory.UNKNOWN
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
        object.__setattr__(
            self,
            "source_kind",
            _normalize_enum_option(EntityKind, self.source_kind, EntityKind.UNKNOWN),
        )
        object.__setattr__(
            self,
            "target_kind",
            _normalize_enum_option(EntityKind, self.target_kind, EntityKind.UNKNOWN),
        )
        object.__setattr__(self, "count_bucket", _normalize_token(self.count_bucket) or "zero")
        object.__setattr__(self, "count_score", _round6(_clip_float(self.count_score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "first_month", _clean_text(self.first_month, 7) or None)
        object.__setattr__(self, "last_month", _clean_text(self.last_month, 7) or None)
        object.__setattr__(
            self,
            "dominant_source_category",
            _normalize_enum_option(
                SourceCategory,
                self.dominant_source_category,
                SourceCategory.UNKNOWN,
            ),
        )
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.link_id:
            object.__setattr__(
                self,
                "link_id",
                _fingerprint_payload(
                    {
                        "source": self.source_ref_hash,
                        "target": self.target_ref_hash,
                        "source_kind": _enum_value(self.source_kind),
                        "target_kind": _enum_value(self.target_kind),
                        "count_bucket": self.count_bucket,
                    }
                )[:32],
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "link_id": self.link_id,
            "source_ref_hash": self.source_ref_hash,
            "target_ref_hash": self.target_ref_hash,
            "source_kind": _enum_value(self.source_kind, EntityKind.UNKNOWN.value),
            "target_kind": _enum_value(self.target_kind, EntityKind.UNKNOWN.value),
            "count_bucket": self.count_bucket,
            "count_score": float(self.count_score),
            "first_month": self.first_month,
            "last_month": self.last_month,
            "dominant_source_category": _enum_value(
                self.dominant_source_category,
                SourceCategory.UNKNOWN.value,
            ),
            "metadata": _safe_detail_value(self.metadata),
            "raw_identifiers_retained": False,
            "raw_timestamps_retained": False,
            "association_is_not_proof_of_common_control": True,
        }


@dataclass(frozen=True, slots=True)
class EntityProfile:
    """
    One bounded synthetic entity profile.

    Profiles are investigative human-workflow artefacts only. They are not
    proof of wrongdoing and must not trigger automatic adverse action.
    """

    entity_ref_hash: str = ""
    kind: EntityKind | str = EntityKind.UNKNOWN
    status: EntityStatus | str = EntityStatus.UNKNOWN
    channel: EntityChannel | str = EntityChannel.UNKNOWN
    first_seen_month: Optional[str] = None
    last_seen_month: Optional[str] = None
    months_since_last_seen: Optional[int] = None
    source_categories: tuple[str, ...] = ()
    linked_account_count_bucket: str = "zero"
    linked_account_count_score: float = 0.0
    linked_transaction_count_bucket: str = "zero"
    linked_transaction_count_score: float = 0.0
    linked_complaint_count_bucket: str = "zero"
    linked_complaint_count_score: float = 0.0
    linked_alert_count_bucket: str = "zero"
    linked_alert_count_score: float = 0.0
    co_entity_count_bucket: str = "zero"
    co_entity_count_score: float = 0.0
    priority_score: float = 0.0
    priority_tier: PriorityTier | str = PriorityTier.UNSCORED
    priority_reasons: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "entity_ref_hash",
            _clean_text(self.entity_ref_hash, MAX_HASH_LENGTH).lower(),
        )
        object.__setattr__(
            self,
            "kind",
            _normalize_enum_option(EntityKind, self.kind, EntityKind.UNKNOWN),
        )
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(EntityStatus, self.status, EntityStatus.UNKNOWN),
        )
        object.__setattr__(
            self,
            "channel",
            _normalize_enum_option(EntityChannel, self.channel, EntityChannel.UNKNOWN),
        )
        object.__setattr__(self, "first_seen_month", _clean_text(self.first_seen_month, 7) or None)
        object.__setattr__(self, "last_seen_month", _clean_text(self.last_seen_month, 7) or None)

        if self.months_since_last_seen is None:
            object.__setattr__(self, "months_since_last_seen", None)
        else:
            object.__setattr__(
                self,
                "months_since_last_seen",
                max(0, _as_int(self.months_since_last_seen, 0)),
            )

        object.__setattr__(
            self,
            "source_categories",
            tuple(
                sorted(
                    {
                        _normalize_token(item)
                        for item in (self.source_categories or ())
                        if _normalize_token(item)
                    }
                )
            )[:20],
        )

        object.__setattr__(
            self,
            "linked_account_count_bucket",
            _normalize_token(self.linked_account_count_bucket) or "zero",
        )
        object.__setattr__(
            self,
            "linked_account_count_score",
            _round6(_clip_float(self.linked_account_count_score, 0.0, 1.0, 0.0)),
        )
        object.__setattr__(
            self,
            "linked_transaction_count_bucket",
            _normalize_token(self.linked_transaction_count_bucket) or "zero",
        )
        object.__setattr__(
            self,
            "linked_transaction_count_score",
            _round6(_clip_float(self.linked_transaction_count_score, 0.0, 1.0, 0.0)),
        )
        object.__setattr__(
            self,
            "linked_complaint_count_bucket",
            _normalize_token(self.linked_complaint_count_bucket) or "zero",
        )
        object.__setattr__(
            self,
            "linked_complaint_count_score",
            _round6(_clip_float(self.linked_complaint_count_score, 0.0, 1.0, 0.0)),
        )
        object.__setattr__(
            self,
            "linked_alert_count_bucket",
            _normalize_token(self.linked_alert_count_bucket) or "zero",
        )
        object.__setattr__(
            self,
            "linked_alert_count_score",
            _round6(_clip_float(self.linked_alert_count_score, 0.0, 1.0, 0.0)),
        )
        object.__setattr__(
            self,
            "co_entity_count_bucket",
            _normalize_token(self.co_entity_count_bucket) or "zero",
        )
        object.__setattr__(
            self,
            "co_entity_count_score",
            _round6(_clip_float(self.co_entity_count_score, 0.0, 1.0, 0.0)),
        )
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
            "entity_ref_hash": self.entity_ref_hash,
            "kind": _enum_value(self.kind, EntityKind.UNKNOWN.value),
            "status": _enum_value(self.status, EntityStatus.UNKNOWN.value),
            "channel": _enum_value(self.channel, EntityChannel.UNKNOWN.value),
            "first_seen_month": self.first_seen_month,
            "last_seen_month": self.last_seen_month,
            "months_since_last_seen": self.months_since_last_seen,
            "source_categories": list(self.source_categories),
            "linked_account_count_bucket": self.linked_account_count_bucket,
            "linked_account_count_score": float(self.linked_account_count_score),
            "linked_transaction_count_bucket": self.linked_transaction_count_bucket,
            "linked_transaction_count_score": float(self.linked_transaction_count_score),
            "linked_complaint_count_bucket": self.linked_complaint_count_bucket,
            "linked_complaint_count_score": float(self.linked_complaint_count_score),
            "linked_alert_count_bucket": self.linked_alert_count_bucket,
            "linked_alert_count_score": float(self.linked_alert_count_score),
            "co_entity_count_bucket": self.co_entity_count_bucket,
            "co_entity_count_score": float(self.co_entity_count_score),
            "priority_score": float(self.priority_score),
            "priority_tier": _enum_value(self.priority_tier, PriorityTier.UNSCORED.value),
            "priority_reasons": list(self.priority_reasons),
            "metadata": _safe_detail_value(self.metadata),
            "priority_semantics": "investigative_human_review_triage_only_not_probability_of_guilt",
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "raw_timestamps_retained": False,
            "labels_used_as_features": False,
            "caveats": list(ENTITY_CAVEATS),
            "safety_flags": dict(ENTITY_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class EntitiesResult:
    """
    Safe bounded entities service result.
    """

    ok: bool = True
    status: ServiceStatus | str = ServiceStatus.PASSED
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    profiles: tuple[EntityProfile, ...] = ()
    links: tuple[EntityLink, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[EntityIssue, ...] = ()
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
                        "version": ENTITIES_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, ServiceStatus.PASSED.value),
                        "request_id": self.request_id,
                        "profile_count": len(self.profiles),
                        "profile_hashes": [
                            profile.entity_ref_hash for profile in self.profiles[:64]
                        ],
                        "link_count": len(self.links),
                        "link_ids": [link.link_id for link in self.links[:64]],
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
            "caveats": list(ENTITY_CAVEATS),
            "safety_flags": dict(ENTITY_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local entity registry
# -----------------------------------------------------------------------------


class EntityRegistry:
    """
    Bounded process-local entity profile and link registry.

    This registry is non-durable and intended for local prototype workflows,
    tests, developer tooling, and offline evaluation harnesses only.
    """

    def __init__(
        self,
        max_profiles: int = DEFAULT_MAX_PROFILES,
        max_links: int = DEFAULT_MAX_LINKS,
    ) -> None:
        self.max_profiles = max(1, int(max_profiles))
        self.max_links = max(0, int(max_links))
        self._profiles: dict[str, EntityProfile] = {}
        self._profile_order: list[str] = []
        self._links: dict[str, EntityLink] = {}
        self._link_order: list[str] = []
        self._lock = threading.RLock()

    def register_profile(self, profile: EntityProfile) -> str:
        profile_hash = _clean_text(profile.entity_ref_hash, MAX_HASH_LENGTH).lower()

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

    def register_link(self, link: EntityLink) -> str:
        link_id = _clean_text(link.link_id, 128)

        if not link_id or self.max_links <= 0:
            return ""

        with self._lock:
            if link_id in self._links:
                self._links[link_id] = link

                if link_id in self._link_order:
                    self._link_order.remove(link_id)

                self._link_order.append(link_id)
                return link_id

            if len(self._link_order) >= self.max_links:
                evicted = self._link_order.pop(0)
                self._links.pop(evicted, None)

            self._links[link_id] = link
            self._link_order.append(link_id)
            return link_id

    def get_profile(self, entity_ref_hash: Any) -> Optional[EntityProfile]:
        key = _clean_text(entity_ref_hash, MAX_HASH_LENGTH).lower()

        with self._lock:
            return self._profiles.get(key)

    def list_profiles(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> tuple[EntityProfile, ...]:
        count = max(0, int(limit))

        with self._lock:
            if count == 0:
                return ()

            return tuple(
                self._profiles[profile_hash]
                for profile_hash in self._profile_order[:count]
                if profile_hash in self._profiles
            )

    def list_links(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> tuple[EntityLink, ...]:
        count = max(0, int(limit))

        with self._lock:
            if count == 0:
                return ()

            return tuple(
                self._links[link_id]
                for link_id in self._link_order[:count]
                if link_id in self._links
            )

    def search_profiles(
        self,
        *,
        kind: Any = None,
        status: Any = None,
        channel: Any = None,
        source_category: Any = None,
        min_priority: Optional[float] = None,
        max_priority: Optional[float] = None,
        limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    ) -> tuple[EntityProfile, ...]:
        normalized_kind = (
            _normalize_enum_option(EntityKind, kind, None)
            if kind is not None
            else None
        )
        normalized_status = (
            _normalize_enum_option(EntityStatus, status, None)
            if status is not None
            else None
        )
        normalized_channel = (
            _normalize_enum_option(EntityChannel, channel, None)
            if channel is not None
            else None
        )
        normalized_source = (
            _normalize_token(source_category)
            if source_category is not None
            else None
        )
        min_score = _clip_float(min_priority, 0.0, 1.0, 0.0) if min_priority is not None else None
        max_score = _clip_float(max_priority, 0.0, 1.0, 1.0) if max_priority is not None else None
        count = max(0, int(limit))

        with self._lock:
            candidates = list(self._profiles.values())

        filtered: list[EntityProfile] = []

        for profile in candidates:
            if normalized_kind is not None and profile.kind != normalized_kind:
                continue

            if normalized_status is not None and profile.status != normalized_status:
                continue

            if normalized_channel is not None and profile.channel != normalized_channel:
                continue

            if normalized_source is not None and normalized_source not in profile.source_categories:
                continue

            if min_score is not None and float(profile.priority_score) < float(min_score):
                continue

            if max_score is not None and float(profile.priority_score) > float(max_score):
                continue

            filtered.append(profile)

        filtered.sort(
            key=lambda profile: (
                -float(profile.priority_score),
                -float(profile.co_entity_count_score),
                profile.entity_ref_hash,
            )
        )

        return tuple(filtered[:count])

    def summarize_profiles(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> list[dict[str, Any]]:
        return [profile.to_dict() for profile in self.list_profiles(limit=limit)]

    def summarize_links(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> list[dict[str, Any]]:
        return [link.to_dict() for link in self.list_links(limit=limit)]

    def clear(self) -> None:
        with self._lock:
            self._profiles.clear()
            self._profile_order.clear()
            self._links.clear()
            self._link_order.clear()

    def safe_summary(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
        with self._lock:
            kind_counter = Counter(
                _enum_value(profile.kind, EntityKind.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            status_counter = Counter(
                _enum_value(profile.status, EntityStatus.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            channel_counter = Counter(
                _enum_value(profile.channel, EntityChannel.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            tier_counter = Counter(
                _enum_value(profile.priority_tier, PriorityTier.UNSCORED.value)
                for profile in self._profiles.values()
            )
            source_counter: Counter[str] = Counter()

            for profile in self._profiles.values():
                source_counter.update(profile.source_categories)

        return {
            "backend": "process_local_in_memory",
            "durable": False,
            "distributed": False,
            "max_profiles": self.max_profiles,
            "max_links": self.max_links,
            "registered_profiles": len(self._profile_order),
            "registered_links": len(self._link_order),
            "by_kind": dict(kind_counter),
            "by_status": dict(status_counter),
            "by_channel": dict(channel_counter),
            "by_source_category": dict(source_counter),
            "by_priority_tier": dict(tier_counter),
            "recent_profiles": self.summarize_profiles(limit=limit),
            "recent_links": self.summarize_links(limit=min(limit, 20)),
            "raw_identifiers_retained": False,
            "raw_timestamps_retained": False,
        }


_default_registry: Optional[EntityRegistry] = None
_default_registry_lock = threading.Lock()


def get_entity_registry(
    max_profiles: int | None = None,
    max_links: int | None = None,
    *,
    rebuild: bool = False,
) -> EntityRegistry:
    """
    Return a process-wide bounded entity registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = EntityRegistry(
                max_profiles=max_profiles if max_profiles is not None else DEFAULT_MAX_PROFILES,
                max_links=max_links if max_links is not None else DEFAULT_MAX_LINKS,
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
    options: EntitiesServiceOptions,
    issues: list[EntityIssue],
    context: Mapping[str, Any],
) -> tuple[Optional[dict[str, Any]], dict[str, list[Any]]]:
    clean: dict[str, Any] = {}
    transient: dict[str, list[Any]] = defaultdict(list)

    for raw_key in sorted(view):
        raw_value = view[raw_key]
        canonical = _canonical_field_name(raw_key)

        if not canonical or canonical in NON_FEATURE_KEYS:
            continue

        if canonical in _TRANSIENT_RAW_ENTITY_CANONICAL_KEYS:
            if options.allow_raw_entity_values:
                transient[canonical].append(raw_value)
                continue

            if options.drop_forbidden_fields:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.INFO,
                    code="raw_entity_field_dropped",
                    message="Raw entity field omitted because raw entity value ingestion is disabled.",
                    field=canonical,
                    details=dict(context),
                )
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="raw_entity_field_rejected",
                message="Raw entity field rejected because raw entity value ingestion is disabled.",
                field=canonical,
                details=dict(context),
            )
            return None, {}

        if _is_forbidden_key(canonical) or _is_label_leakage_key(canonical):
            if options.drop_forbidden_fields:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="forbidden_entity_field_dropped",
                    message="Forbidden or leakage-prone entity field omitted.",
                    field=canonical,
                    details=dict(context),
                )
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_entity_field",
                message="Forbidden or leakage-prone entity field rejected.",
                field=canonical,
                details=dict(context),
            )
            return None, {}

        clean[canonical] = raw_value

    return clean, dict(transient)


def _entity_kind_from_transient(canonical: str, explicit_kind: EntityKind) -> EntityKind:
    mapped = _TRANSIENT_RAW_ENTITY_KIND_MAP.get(canonical)

    if mapped is None:
        return explicit_kind if explicit_kind != EntityKind.UNKNOWN else EntityKind.GENERIC

    kind = _normalize_enum_option(EntityKind, mapped, EntityKind.GENERIC)

    if kind == EntityKind.GENERIC and explicit_kind != EntityKind.UNKNOWN:
        return explicit_kind

    return kind


def _add_entity_ref(
    refs: dict[str, EntityKind],
    entity_hash: Optional[str],
    kind: EntityKind,
) -> None:
    if not entity_hash:
        return

    existing = refs.get(entity_hash)

    if existing is None:
        refs[entity_hash] = kind
        return

    if existing == EntityKind.UNKNOWN and kind != EntityKind.UNKNOWN:
        refs[entity_hash] = kind


def _extract_entity_refs(
    clean: Mapping[str, Any],
    transient: Mapping[str, Sequence[Any]],
    options: EntitiesServiceOptions,
    issues: list[EntityIssue],
    context: Mapping[str, Any],
) -> tuple[tuple[str, EntityKind], ...]:
    refs: dict[str, EntityKind] = {}

    explicit_kind = _normalize_entity_kind(_pick(clean, KIND_KEYS))
    explicit_ref = _pick(clean, ENTITY_REF_KEYS)

    if explicit_ref is not None:
        for value in _as_sequence(explicit_ref):
            entity_hash = _entity_ref_hash(value, explicit_kind, options)
            _add_entity_ref(refs, entity_hash, explicit_kind)

    for canonical, kind_token in _SAFE_ENTITY_HASH_KIND_MAP.items():
        if canonical not in clean:
            continue

        kind = _normalize_enum_option(EntityKind, kind_token, EntityKind.GENERIC)

        for value in _as_sequence(clean[canonical]):
            entity_hash = _entity_ref_hash(value, kind, options)
            _add_entity_ref(refs, entity_hash, kind)

    for canonical, values in transient.items():
        kind = _entity_kind_from_transient(canonical, explicit_kind)

        for container in values:
            for value in _as_sequence(container):
                entity_hash = _entity_ref_hash(value, kind, options)
                _add_entity_ref(refs, entity_hash, kind)

    if not refs:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="missing_entity_reference",
            message="Entity observation is missing a usable entity reference.",
            field="entity_ref_hash",
            details=dict(context),
        )
        return ()

    items = sorted(refs.items(), key=lambda item: (item[1].value, item[0]))

    if len(items) > int(options.max_entities_per_record):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="entity_record_truncated",
            message="Entity observation exceeded configured per-record entity limit and was truncated.",
            details={
                **dict(context),
                "generated": len(items),
                "max_entities_per_record": int(options.max_entities_per_record),
            },
        )
        items = items[: int(options.max_entities_per_record)]

    return tuple(items)


def _extract_associated_refs(
    clean: Mapping[str, Any],
    keys: Sequence[str],
    hasher: Callable[[Any, EntitiesServiceOptions], Optional[str]],
    options: EntitiesServiceOptions,
    issues: list[EntityIssue],
    context: Mapping[str, Any],
    field_name: str,
) -> tuple[str, ...]:
    refs: list[str] = []
    seen: set[str] = set()

    for key in keys:
        if key not in clean:
            continue

        for value in _as_sequence(clean[key]):
            hashed = hasher(value, options)

            if not hashed or hashed in seen:
                continue

            seen.add(hashed)
            refs.append(hashed)

            if len(refs) >= int(options.max_associated_refs):
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="associated_refs_truncated",
                    message="Associated references exceeded configured limit and were truncated.",
                    field=field_name,
                    details={
                        **dict(context),
                        "max_associated_refs": int(options.max_associated_refs),
                    },
                )
                return tuple(refs)

    return tuple(refs)


def _synthesize_entity_observation_id(
    entity_refs: Sequence[tuple[str, EntityKind]],
    index: int,
    options: EntitiesServiceOptions,
) -> str:
    payload = {
        "version": ENTITIES_VERSION,
        "namespace": _normalize_token(options.namespace) or _DEFAULT_NAMESPACE,
        "entities": [
            {"hash": entity_hash, "kind": kind.value}
            for entity_hash, kind in sorted(entity_refs, key=lambda item: item[0])
        ],
        "index": int(index),
    }

    return _fingerprint_payload(payload)[:40]


def _sanitize_observation(
    record: Any,
    options: EntitiesServiceOptions,
    issues: list[EntityIssue],
    index: int,
    start_time: float,
    now: datetime,
) -> Optional[dict[str, Any]]:
    if _time_exceeded(start_time, options.max_time_ms):
        return None

    context = {"record_type": "entity_observation", "index": index}
    view = _extract_view(record, _ALL_ENTITY_VIEW_KEYS)
    clean, transient = _clean_view(view, options, issues, context)

    if clean is None:
        return None

    if _contains_prohibited_action(clean):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.ERROR,
            code="prohibited_entity_metadata",
            message="Entity observation contains prohibited adverse-action language.",
            details=context,
        )
        return None

    entity_refs = _extract_entity_refs(clean, transient, options, issues, context)

    if not entity_refs:
        return None

    account_refs = _extract_associated_refs(
        clean,
        ACCOUNT_REF_KEYS,
        _account_ref_hash,
        options,
        issues,
        context,
        "account_id",
    )

    transaction_refs = _extract_associated_refs(
        clean,
        TRANSACTION_REF_KEYS,
        _transaction_ref_hash,
        options,
        issues,
        context,
        "transaction_id",
    )

    complaint_refs = _extract_associated_refs(
        clean,
        COMPLAINT_REF_KEYS,
        _complaint_ref_hash,
        options,
        issues,
        context,
        "complaint_id",
    )

    alert_refs = _extract_associated_refs(
        clean,
        ALERT_REF_KEYS,
        _alert_ref_hash,
        options,
        issues,
        context,
        "alert_id",
    )

    timestamp: Optional[datetime] = None

    for key in TIMESTAMP_KEYS:
        if key in clean:
            parsed = _parse_datetime(clean[key])

            if parsed is not None:
                timestamp = parsed
                break

    source_category = _normalize_source_category(_pick(clean, SOURCE_CATEGORY_KEYS))
    status = _normalize_entity_status(_pick(clean, STATUS_KEYS), issues, options, context)
    channel = _normalize_entity_channel(_pick(clean, CHANNEL_KEYS))

    observation_id = _pick(clean, ("observation_id", "record_id"))
    observation_hash = _party_ref_hash(observation_id, options, "observation") if observation_id else None

    if not observation_hash:
        observation_hash = _synthesize_entity_observation_id(entity_refs, index, options)

    return {
        "observation_hash": observation_hash,
        "entity_refs": entity_refs,
        "account_refs": account_refs,
        "transaction_refs": transaction_refs,
        "complaint_refs": complaint_refs,
        "alert_refs": alert_refs,
        "timestamp": timestamp,
        "month": timestamp.strftime("%Y-%m") if timestamp else None,
        "source_category": _enum_value(source_category, SourceCategory.UNKNOWN.value),
        "status": _enum_value(status, EntityStatus.UNKNOWN.value),
        "channel": _enum_value(channel, EntityChannel.UNKNOWN.value),
        "source_indices": [index],
        "metadata": {
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "raw_timestamps_retained": False,
            "labels_used_as_features": False,
            "raw_entity_values_allowed": bool(options.allow_raw_entity_values),
        },
    }


def _merge_entity_base(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    existing_kind = _normalize_entity_kind(existing.get("kind"))
    incoming_kind = _normalize_entity_kind(incoming.get("kind"))

    if existing_kind == EntityKind.UNKNOWN and incoming_kind != EntityKind.UNKNOWN:
        existing["kind"] = incoming.get("kind")
    elif existing_kind != EntityKind.UNKNOWN and incoming_kind != EntityKind.UNKNOWN and existing_kind != incoming_kind:
        existing.setdefault("kind_conflicts", []).append(incoming_kind.value)

    existing_status = _normalize_entity_status(
        existing.get("status"),
        [],
        EntitiesServiceOptions(),
        {},
    )
    incoming_status = _normalize_entity_status(
        incoming.get("status"),
        [],
        EntitiesServiceOptions(),
        {},
    )

    if existing_status == EntityStatus.UNKNOWN and incoming_status != EntityStatus.UNKNOWN:
        existing["status"] = incoming.get("status")

    existing_channel = _normalize_entity_channel(existing.get("channel"))
    incoming_channel = _normalize_entity_channel(incoming.get("channel"))

    if existing_channel == EntityChannel.UNKNOWN and incoming_channel != EntityChannel.UNKNOWN:
        existing["channel"] = incoming.get("channel")

    existing_first_dt = existing.get("first_seen_dt")
    incoming_first_dt = incoming.get("first_seen_dt")

    if incoming_first_dt is not None:
        if existing_first_dt is None or incoming_first_dt < existing_first_dt:
            existing["first_seen_dt"] = incoming_first_dt
            existing["first_seen_month"] = incoming.get("first_seen_month")

    existing_last_dt = existing.get("last_seen_dt")
    incoming_last_dt = incoming.get("last_seen_dt")

    if incoming_last_dt is not None:
        if existing_last_dt is None or incoming_last_dt > existing_last_dt:
            existing["last_seen_dt"] = incoming_last_dt
            existing["last_seen_month"] = incoming.get("last_seen_month")

    source_categories = set(existing.get("source_categories") or ())
    source_categories.update(incoming.get("source_categories") or ())
    existing["source_categories"] = source_categories

    for key in (
        "account_refs",
        "transaction_refs",
        "complaint_refs",
        "alert_refs",
        "observation_hashes",
    ):
        values = set(existing.get(key) or ())
        values.update(incoming.get(key) or ())
        existing[key] = values

    source_indices = existing.setdefault("source_indices", [])

    for source_index in incoming.get("source_indices", ()): 
        if source_index not in source_indices:
            source_indices.append(source_index)

        if len(source_indices) > 100:
            break

    return existing


def _new_entity_base(
    entity_hash: str,
    kind: EntityKind,
    observation: Mapping[str, Any],
) -> dict[str, Any]:
    timestamp = observation.get("timestamp")
    month = observation.get("month")

    return {
        "entity_ref_hash": entity_hash,
        "kind": _enum_value(kind, EntityKind.UNKNOWN.value),
        "status": observation.get("status", EntityStatus.UNKNOWN.value),
        "channel": observation.get("channel", EntityChannel.UNKNOWN.value),
        "first_seen_dt": timestamp,
        "last_seen_dt": timestamp,
        "first_seen_month": month,
        "last_seen_month": month,
        "source_categories": {observation.get("source_category", SourceCategory.UNKNOWN.value)},
        "account_refs": set(observation.get("account_refs") or ()),
        "transaction_refs": set(observation.get("transaction_refs") or ()),
        "complaint_refs": set(observation.get("complaint_refs") or ()),
        "alert_refs": set(observation.get("alert_refs") or ()),
        "observation_hashes": {observation.get("observation_hash", "")},
        "source_indices": list(observation.get("source_indices") or ()),
        "kind_conflicts": [],
        "metadata": dict(observation.get("metadata") or {}),
    }


# -----------------------------------------------------------------------------
# Priority scoring
# -----------------------------------------------------------------------------


def _degree_score(count: int) -> float:
    return _round6(min(1.0, max(0, int(count)) / float(DEGREE_CAP)))


def _diversity_score(categories: Sequence[str]) -> float:
    unique = {
        _normalize_token(item)
        for item in categories
        if _normalize_token(item) and _normalize_token(item) != SourceCategory.UNKNOWN.value
    }

    return _round6(min(1.0, len(unique) / float(SOURCE_CATEGORY_CAP)))


def _recency_score(months: Optional[int]) -> float:
    if months is None:
        return 0.0

    safe_months = max(0, int(months))

    if safe_months <= 0:
        return 1.00

    if safe_months <= 1:
        return 0.85

    if safe_months <= 3:
        return 0.65

    if safe_months <= 6:
        return 0.45

    if safe_months <= 12:
        return 0.25

    return 0.10


def _linkage_score(
    account_count: int,
    transaction_count: int,
    complaint_count: int,
    alert_count: int,
) -> float:
    account_norm = min(1.0, max(0, int(account_count)) / float(ACCOUNT_CAP))
    transaction_norm = min(1.0, max(0, int(transaction_count)) / float(TRANSACTION_CAP))
    complaint_norm = min(1.0, max(0, int(complaint_count)) / float(COMPLAINT_CAP))
    alert_norm = min(1.0, max(0, int(alert_count)) / float(ALERT_CAP))

    score = (
        account_norm * 0.30
        + transaction_norm * 0.30
        + complaint_norm * 0.20
        + alert_norm * 0.20
    )

    return _round6(_clip_float(score, 0.0, 1.0, 0.0))


def _source_score(categories: Sequence[str]) -> float:
    normalized = {
        _normalize_token(item)
        for item in categories
        if _normalize_token(item)
    }

    elevated = normalized & ELEVATED_SOURCE_CATEGORIES

    if not elevated:
        return 0.0

    return _round6(min(1.0, len(elevated) / 3.0))


def _status_score(status: Any) -> float:
    normalized = _normalize_enum_option(EntityStatus, status, EntityStatus.UNKNOWN)

    if normalized == EntityStatus.ACTIVE:
        return 0.60

    if normalized == EntityStatus.INACTIVE:
        return 0.30

    if normalized == EntityStatus.STALE:
        return 0.15

    return 0.0


def _compute_entity_priority(
    base: Mapping[str, Any],
    co_entity_count: int,
    options: EntitiesServiceOptions,
    now: datetime,
) -> tuple[float, PriorityTier, tuple[str, ...]]:
    if not options.include_priority:
        return 0.0, PriorityTier.UNSCORED, ("priority_disabled",)

    degree = _degree_score(co_entity_count)
    diversity = _diversity_score(base.get("source_categories") or ())
    months = _months_between(base.get("last_seen_dt"), now)
    recency = _recency_score(months)
    linkage = _linkage_score(
        len(base.get("account_refs") or ()),
        len(base.get("transaction_refs") or ()),
        len(base.get("complaint_refs") or ()),
        len(base.get("alert_refs") or ()),
    )
    source = _source_score(base.get("source_categories") or ())
    status = _status_score(base.get("status"))

    score = (
        degree * float(options.priority_degree_weight)
        + diversity * float(options.priority_diversity_weight)
        + recency * float(options.priority_recency_weight)
        + linkage * float(options.priority_linkage_weight)
        + source * float(options.priority_source_weight)
        + status * float(options.priority_status_weight)
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
        "attention_is_not_probability_of_guilt",
        "no_automatic_adverse_action",
        "no_raw_identifiers_used",
        "no_raw_timestamps_used",
    ]

    if degree >= 0.50:
        reasons.append("high_co_occurrence_degree")

    if diversity >= 0.50:
        reasons.append("multi_source_observation_diversity")

    if recency >= 0.65:
        reasons.append("recent_observation_bucket")

    if linkage >= 0.50:
        reasons.append("multiple_linked_party_references")

    if source >= 0.50:
        reasons.append("elevated_source_category_signal")

    if status >= 0.60:
        reasons.append("active_status_signal")

    if base.get("kind_conflicts"):
        reasons.append("entity_kind_conflict_observed")

    if score >= float(options.elevated_threshold):
        reasons.append("high_investigative_attention")

    return score, tier, tuple(dict.fromkeys(reasons))


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------


class EntitiesServiceEngine:
    """
    Bounded deterministic synthetic entities service engine.
    """

    def __init__(
        self,
        options: EntitiesServiceOptions | None = None,
        registry: EntityRegistry | None = None,
    ) -> None:
        self.options = options or EntitiesServiceOptions.from_settings()
        self.registry = registry or get_entity_registry(
            max_profiles=self.options.max_profiles,
            max_links=self.options.max_links,
        )
        self._lock = threading.RLock()

    def normalize(self, request: Any) -> EntitiesResult:
        """
        Run one bounded synthetic entity profiling job.
        """
        opts = self.options
        issues: list[EntityIssue] = []
        start_time = time.monotonic()
        now = _now_utc()

        req = _coerce_request(request)
        source = req.entities

        if source is None:
            source = req.observations
        if source is None:
            source = req.records

        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": ENTITIES_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                    "counts": {
                        "records": _count_records_safe(source),
                    },
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: ServiceStatus,
            profiles: Sequence[EntityProfile] = (),
            links: Sequence[EntityLink] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> EntitiesResult:
            resolved_counts: dict[str, int] = {
                "submitted_records": _count_records_safe(source),
                "sanitized_observations": 0,
                "profiles": len(profiles),
                "links": len(links),
                "registered_profiles": 0,
                "registered_links": 0,
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
                "entities_version": ENTITIES_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "registry": self.registry.safe_summary(limit=opts.max_summary_items),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_identifiers_retained": False,
                "raw_narratives_retained": False,
                "raw_timestamps_retained": False,
                "subject_label_pairs_retained": False,
                "secrets_retained": False,
                "labels_used_as_features": False,
                "raw_entity_values_allowed": bool(opts.allow_raw_entity_values),
                "attention_semantics": "investigative_human_review_triage_only",
                "caveats": list(ENTITY_CAVEATS),
                "safety_flags": dict(ENTITY_SAFETY_FLAGS),
            }

            return EntitiesResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=now,
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
                code="entities_service_disabled",
                message="Entities service is disabled.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Entities service requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Entities service is blocked in production-like environments.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_entities_action_metadata",
                message="Entities request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        with self._lock:
            raw_records = _iter_records(source)[: opts.max_records]
            submitted = _count_records_safe(source)

            if submitted > int(opts.max_records):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="entities_input_truncated",
                    message="Entity input exceeded configured record limit and was truncated.",
                    details={
                        "submitted": submitted,
                        "max_records": int(opts.max_records),
                    },
                )

            bases: dict[str, dict[str, Any]] = {}
            edge_aggregates: dict[tuple[str, str], dict[str, Any]] = {}
            sanitized = 0

            for index, record in enumerate(raw_records):
                if _time_exceeded(start_time, opts.max_time_ms):
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="entity_sanitization_time_budget_exhausted",
                        message="Entity sanitization stopped after reaching configured time budget.",
                        details={
                            "processed": sanitized,
                            "remaining": max(0, len(raw_records) - index),
                        },
                    )
                    break

                observation = _sanitize_observation(record, opts, issues, index, start_time, now)

                if observation is None:
                    continue

                sanitized += 1

                entity_refs: tuple[tuple[str, EntityKind], ...] = observation["entity_refs"]

                for entity_hash, kind in entity_refs:
                    existing = bases.get(entity_hash)

                    base_payload = {
                        "kind": _enum_value(kind, EntityKind.UNKNOWN.value),
                        "status": observation.get("status", EntityStatus.UNKNOWN.value),
                        "channel": observation.get("channel", EntityChannel.UNKNOWN.value),
                        "first_seen_dt": observation.get("timestamp"),
                        "last_seen_dt": observation.get("timestamp"),
                        "first_seen_month": observation.get("month"),
                        "last_seen_month": observation.get("month"),
                        "source_categories": {observation.get("source_category", SourceCategory.UNKNOWN.value)},
                        "account_refs": set(observation.get("account_refs") or ()),
                        "transaction_refs": set(observation.get("transaction_refs") or ()),
                        "complaint_refs": set(observation.get("complaint_refs") or ()),
                        "alert_refs": set(observation.get("alert_refs") or ()),
                        "observation_hashes": {observation.get("observation_hash", "")},
                        "source_indices": list(observation.get("source_indices") or ()),
                        "kind_conflicts": [],
                        "metadata": dict(observation.get("metadata") or {}),
                    }

                    if existing is None:
                        bases[entity_hash] = _new_entity_base(entity_hash, kind, observation)
                    else:
                        _merge_entity_base(existing, base_payload)

                if opts.include_links:
                    sorted_refs = sorted(entity_refs, key=lambda item: item[0])

                    for i in range(len(sorted_refs)):
                        left_hash, left_kind = sorted_refs[i]

                        for j in range(i + 1, len(sorted_refs)):
                            right_hash, right_kind = sorted_refs[j]

                            if left_hash == right_hash:
                                continue

                            key = (left_hash, right_hash)
                            agg = edge_aggregates.get(key)

                            if agg is None:
                                agg = {
                                    "count": 0,
                                    "source_kind": _enum_value(left_kind, EntityKind.UNKNOWN.value),
                                    "target_kind": _enum_value(right_kind, EntityKind.UNKNOWN.value),
                                    "first_month": observation.get("month"),
                                    "last_month": observation.get("month"),
                                    "source_counts": Counter(),
                                }
                                edge_aggregates[key] = agg

                            agg["count"] += 1
                            agg["source_counts"][observation.get("source_category", SourceCategory.UNKNOWN.value)] += 1

                            month = observation.get("month")

                            if month:
                                if not agg["first_month"] or str(month) < str(agg["first_month"]):
                                    agg["first_month"] = month

                                if not agg["last_month"] or str(month) > str(agg["last_month"]):
                                    agg["last_month"] = month

            if len(bases) > int(opts.max_entities):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="entity_profiles_truncated",
                    message="Entity profiles exceeded configured limit and were truncated.",
                    details={
                        "generated": len(bases),
                        "max_entities": int(opts.max_entities),
                    },
                )
                retained_hashes = sorted(bases)[: int(opts.max_entities)]
                bases = {entity_hash: bases[entity_hash] for entity_hash in retained_hashes}

            links: list[EntityLink] = []

            for (source_hash, target_hash), agg in sorted(edge_aggregates.items()):
                count_bucket, count_score = _bucket_from_count(int(agg.get("count", 0)), COUNT_BUCKET_SPECS)
                source_counts: Counter[str] = agg.get("source_counts") or Counter()
                dominant_source = max(source_counts.items(), key=lambda item: (item[1], item[0]))[0] if source_counts else SourceCategory.UNKNOWN.value

                source_kind = agg.get("source_kind", EntityKind.UNKNOWN.value)
                target_kind = agg.get("target_kind", EntityKind.UNKNOWN.value)

                source_base = bases.get(source_hash)
                target_base = bases.get(target_hash)

                if source_base:
                    source_kind = source_base.get("kind", source_kind)

                if target_base:
                    target_kind = target_base.get("kind", target_kind)

                link_id = _fingerprint_payload(
                    {
                        "version": ENTITIES_VERSION,
                        "source": source_hash,
                        "target": target_hash,
                        "source_kind": source_kind,
                        "target_kind": target_kind,
                        "count_bucket": count_bucket,
                    }
                )[:32]

                links.append(
                    EntityLink(
                        link_id=link_id,
                        source_ref_hash=source_hash,
                        target_ref_hash=target_hash,
                        source_kind=source_kind,
                        target_kind=target_kind,
                        count_bucket=count_bucket,
                        count_score=count_score,
                        first_month=agg.get("first_month"),
                        last_month=agg.get("last_month"),
                        dominant_source_category=dominant_source,
                        metadata={
                            "raw_identifiers_retained": False,
                            "raw_timestamps_retained": False,
                            "association_is_not_proof_of_common_control": True,
                        },
                    )
                )

            links.sort(
                key=lambda link: (
                    -float(link.count_score),
                    link.source_kind.value if isinstance(link.source_kind, EntityKind) else str(link.source_kind),
                    link.target_kind.value if isinstance(link.target_kind, EntityKind) else str(link.target_kind),
                    link.source_ref_hash,
                    link.target_ref_hash,
                    link.link_id,
                )
            )

            if len(links) > int(opts.max_links):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="entity_links_truncated",
                    message="Entity links exceeded configured limit and were truncated.",
                    details={
                        "generated": len(links),
                        "max_links": int(opts.max_links),
                    },
                )
                links = links[: int(opts.max_links)]

            counterparties: dict[str, set[str]] = defaultdict(set)

            for link in links:
                counterparties[link.source_ref_hash].add(link.target_ref_hash)
                counterparties[link.target_ref_hash].add(link.source_ref_hash)

            profiles: list[EntityProfile] = []

            for entity_hash in sorted(bases):
                base = bases[entity_hash]
                co_entity_count = len(counterparties.get(entity_hash, ()))
                priority_score, priority_tier, priority_reasons = _compute_entity_priority(
                    base,
                    co_entity_count,
                    opts,
                    now,
                )

                account_bucket, account_score = _bucket_from_count(
                    len(base.get("account_refs") or ()),
                    COUNT_BUCKET_SPECS,
                )
                transaction_bucket, transaction_score = _bucket_from_count(
                    len(base.get("transaction_refs") or ()),
                    COUNT_BUCKET_SPECS,
                )
                complaint_bucket, complaint_score = _bucket_from_count(
                    len(base.get("complaint_refs") or ()),
                    COUNT_BUCKET_SPECS,
                )
                alert_bucket, alert_score = _bucket_from_count(
                    len(base.get("alert_refs") or ()),
                    COUNT_BUCKET_SPECS,
                )
                co_bucket, co_score = _bucket_from_count(co_entity_count, COUNT_BUCKET_SPECS)

                months_since = _months_between(base.get("last_seen_dt"), now)

                metadata = dict(base.get("metadata") or {})
                metadata.update(
                    {
                        "observation_count": len(base.get("observation_hashes") or ()),
                        "kind_conflicts": sorted(set(base.get("kind_conflicts") or ())),
                        "raw_identifiers_retained": False,
                        "raw_timestamps_retained": False,
                        "labels_used_as_features": False,
                    }
                )

                profiles.append(
                    EntityProfile(
                        entity_ref_hash=entity_hash,
                        kind=base.get("kind", EntityKind.UNKNOWN.value),
                        status=base.get("status", EntityStatus.UNKNOWN.value),
                        channel=base.get("channel", EntityChannel.UNKNOWN.value),
                        first_seen_month=base.get("first_seen_month"),
                        last_seen_month=base.get("last_seen_month"),
                        months_since_last_seen=months_since,
                        source_categories=tuple(sorted(base.get("source_categories") or ())),
                        linked_account_count_bucket=account_bucket,
                        linked_account_count_score=account_score,
                        linked_transaction_count_bucket=transaction_bucket,
                        linked_transaction_count_score=transaction_score,
                        linked_complaint_count_bucket=complaint_bucket,
                        linked_complaint_count_score=complaint_score,
                        linked_alert_count_bucket=alert_bucket,
                        linked_alert_count_score=alert_score,
                        co_entity_count_bucket=co_bucket,
                        co_entity_count_score=co_score,
                        priority_score=priority_score,
                        priority_tier=priority_tier,
                        priority_reasons=priority_reasons,
                        metadata=metadata,
                    )
                )

            profiles.sort(
                key=lambda profile: (
                    -float(profile.priority_score),
                    -float(profile.co_entity_count_score),
                    profile.entity_ref_hash,
                )
            )

            if len(profiles) > int(opts.max_profiles):
                profiles = profiles[: int(opts.max_profiles)]

            registered_profiles = 0
            registered_links = 0

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
                            code="entity_profile_registration_failed",
                            message="Entity profile registration failed.",
                            details={"exception_type": type(exc).__name__},
                        )

                for link in links:
                    try:
                        self.registry.register_link(link)
                        registered_links += 1
                    except Exception as exc:
                        _append_issue(
                            issues,
                            opts.max_issues,
                            severity=IssueSeverity.WARNING,
                            code="entity_link_registration_failed",
                            message="Entity link registration failed.",
                            details={"exception_type": type(exc).__name__},
                        )

            kind_counter = Counter(_enum_value(profile.kind) for profile in profiles)
            status_counter = Counter(_enum_value(profile.status) for profile in profiles)
            channel_counter = Counter(_enum_value(profile.channel) for profile in profiles)
            tier_counter = Counter(_enum_value(profile.priority_tier) for profile in profiles)
            source_counter: Counter[str] = Counter()

            for profile in profiles:
                source_counter.update(profile.source_categories)

            counts = {
                "sanitized_observations": sanitized,
                "registered_profiles": registered_profiles,
                "registered_links": registered_links,
                "profiles_with_links": sum(1 for profile in profiles if profile.co_entity_count_bucket != "zero"),
                "profiles_with_accounts": sum(1 for profile in profiles if profile.linked_account_count_bucket != "zero"),
                "profiles_with_transactions": sum(1 for profile in profiles if profile.linked_transaction_count_bucket != "zero"),
                "profiles_with_complaints": sum(1 for profile in profiles if profile.linked_complaint_count_bucket != "zero"),
                "profiles_with_alerts": sum(1 for profile in profiles if profile.linked_alert_count_bucket != "zero"),
                "kind_device": kind_counter.get(EntityKind.DEVICE.value, 0),
                "kind_ip": kind_counter.get(EntityKind.IP.value, 0),
                "kind_phone": kind_counter.get(EntityKind.PHONE.value, 0),
                "kind_email": kind_counter.get(EntityKind.EMAIL.value, 0),
                "kind_upi": kind_counter.get(EntityKind.UPI.value, 0),
                "kind_address": kind_counter.get(EntityKind.ADDRESS.value, 0),
                "kind_account": kind_counter.get(EntityKind.ACCOUNT.value, 0),
                "kind_subject": kind_counter.get(EntityKind.SUBJECT.value, 0),
                "kind_organization": kind_counter.get(EntityKind.ORGANIZATION.value, 0),
                "kind_generic": kind_counter.get(EntityKind.GENERIC.value, 0),
                "kind_unknown": kind_counter.get(EntityKind.UNKNOWN.value, 0),
                "status_active": status_counter.get(EntityStatus.ACTIVE.value, 0),
                "status_inactive": status_counter.get(EntityStatus.INACTIVE.value, 0),
                "status_stale": status_counter.get(EntityStatus.STALE.value, 0),
                "status_unknown": status_counter.get(EntityStatus.UNKNOWN.value, 0),
                "channel_digital": channel_counter.get(EntityChannel.DIGITAL.value, 0),
                "channel_branch": channel_counter.get(EntityChannel.BRANCH.value, 0),
                "channel_atm": channel_counter.get(EntityChannel.ATM.value, 0),
                "channel_agent": channel_counter.get(EntityChannel.AGENT.value, 0),
                "channel_api": channel_counter.get(EntityChannel.API.value, 0),
                "channel_batch": channel_counter.get(EntityChannel.BATCH.value, 0),
                "channel_other": channel_counter.get(EntityChannel.OTHER.value, 0),
                "channel_unknown": channel_counter.get(EntityChannel.UNKNOWN.value, 0),
                "source_complaint": source_counter.get(SourceCategory.COMPLAINT.value, 0),
                "source_transaction": source_counter.get(SourceCategory.TRANSACTION.value, 0),
                "source_alert": source_counter.get(SourceCategory.ALERT.value, 0),
                "source_case": source_counter.get(SourceCategory.CASE.value, 0),
                "source_note": source_counter.get(SourceCategory.NOTE.value, 0),
                "source_entity": source_counter.get(SourceCategory.ENTITY.value, 0),
                "source_other": source_counter.get(SourceCategory.OTHER.value, 0),
                "source_unknown": source_counter.get(SourceCategory.UNKNOWN.value, 0),
                "tier_low": tier_counter.get(PriorityTier.LOW.value, 0),
                "tier_moderate": tier_counter.get(PriorityTier.MODERATE.value, 0),
                "tier_elevated": tier_counter.get(PriorityTier.ELEVATED.value, 0),
                "tier_high": tier_counter.get(PriorityTier.HIGH.value, 0),
                "tier_unscoped": tier_counter.get(PriorityTier.UNSCORED.value, 0),
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
            "caveats": list(ENTITY_CAVEATS),
            "safety_flags": dict(ENTITY_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Record iteration helpers
# -----------------------------------------------------------------------------


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, EntitiesResult):
        return []

    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "entities", "observations", "examples"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])

        return [data]

    for attr in ("entities", "observations", "records", "rows", "items"):
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
        for key in ("records", "rows", "items", "entities", "observations", "examples"):
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

    for attr in ("entities", "observations", "records", "rows", "items"):
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
# Default engine and public API
# -----------------------------------------------------------------------------


_default_engine: Optional[EntitiesServiceEngine] = None
_default_engine_lock = threading.Lock()


def get_entities_options(settings: Any | None = None) -> EntitiesServiceOptions:
    """
    Return entities service options from settings.
    """
    return EntitiesServiceOptions.from_settings(settings)


def get_entities_engine(
    options: EntitiesServiceOptions | None = None,
    *,
    rebuild: bool = False,
) -> EntitiesServiceEngine:
    """
    Return a process-wide entities service engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            resolved_options = options or EntitiesServiceOptions.from_settings()
            _default_engine = EntitiesServiceEngine(
                options=resolved_options,
                registry=get_entity_registry(
                    max_profiles=resolved_options.max_profiles,
                    max_links=resolved_options.max_links,
                ),
            )

        return _default_engine


def normalize_entities(
    request: Any,
    options: EntitiesServiceOptions | None = None,
    *,
    engine: EntitiesServiceEngine | None = None,
) -> EntitiesResult:
    """
    Normalize bounded synthetic entity observations into privacy-preserving
    entity profiles and co-occurrence links.
    """
    active_engine = engine or get_entities_engine(options)
    return active_engine.normalize(request)


def get_entity_profile(
    entity_ref_hash: Any,
    *,
    registry: EntityRegistry | None = None,
) -> Optional[EntityProfile]:
    """
    Return one registered entity profile by pseudonymous entity hash.
    """
    active_registry = registry or get_entity_registry()
    return active_registry.get_profile(entity_ref_hash)


def list_entity_profiles(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: EntityRegistry | None = None,
) -> tuple[EntityProfile, ...]:
    """
    Return registered entity profiles.
    """
    active_registry = registry or get_entity_registry()
    return active_registry.list_profiles(limit=limit)


def list_entity_links(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: EntityRegistry | None = None,
) -> tuple[EntityLink, ...]:
    """
    Return registered entity links.
    """
    active_registry = registry or get_entity_registry()
    return active_registry.list_links(limit=limit)


def search_entity_profiles(
    *,
    kind: Any = None,
    status: Any = None,
    channel: Any = None,
    source_category: Any = None,
    min_priority: Optional[float] = None,
    max_priority: Optional[float] = None,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: EntityRegistry | None = None,
) -> tuple[EntityProfile, ...]:
    """
    Search registered entity profiles using bounded safe filters.
    """
    active_registry = registry or get_entity_registry()
    return active_registry.search_profiles(
        kind=kind,
        status=status,
        channel=channel,
        source_category=source_category,
        min_priority=min_priority,
        max_priority=max_priority,
        limit=limit,
    )


def export_entities_summary(result: EntitiesResult) -> dict[str, Any]:
    """
    Export a safe public entities service summary.
    """
    return result.to_dict()


def clear_entity_registry(*, registry: EntityRegistry | None = None) -> None:
    """
    Clear the process-local entity registry.
    """
    active_registry = registry or get_entity_registry()
    active_registry.clear()


def get_entities_health(*, engine: EntitiesServiceEngine | None = None) -> dict[str, Any]:
    """
    Return safe entities service health.
    """
    active_engine = engine or get_entities_engine()
    opts = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=opts.max_summary_items)
    issues: list[EntityIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="entities_service_disabled",
            message="Entities service is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Entities service requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Entities service is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "registry": registry_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(ENTITY_CAVEATS),
        "safety_flags": dict(ENTITY_SAFETY_FLAGS),
    }


def get_entities_metadata(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    engine: EntitiesServiceEngine | None = None,
) -> dict[str, Any]:
    """
    Return safe, serializable entities service metadata.

    This is useful for startup logs, diagnostic endpoints, tests, developer
    tooling, and architecture documentation checks.

    It must not expose raw identifiers, raw narratives, raw timestamps,
    secrets, environment files, database URLs, tokens, passwords, ground-truth
    labels, scenario IDs, fraud-ring IDs, model artifact paths, filesystem
    paths, executable handler references, or real customer data.
    """
    active_engine = engine or get_entities_engine()
    options = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=limit)

    count_buckets = [
        {
            "upper": upper,
            "label": label,
            "score": _round6(float(score)),
        }
        for upper, label, score in COUNT_BUCKET_SPECS
    ]

    return {
        "package": "muleguard.backend.services.entities",
        "version": ENTITIES_VERSION,
        "entity_kinds": [kind.value for kind in EntityKind],
        "entity_statuses": [status.value for status in EntityStatus],
        "entity_channels": [channel.value for channel in EntityChannel],
        "source_categories": [category.value for category in SourceCategory],
        "priority_tiers": [tier.value for tier in PriorityTier],
        "service_statuses": [status.value for status in ServiceStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "count_buckets": count_buckets,
        "kind_map": dict(ENTITY_KIND_MAP),
        "status_map": dict(ENTITY_STATUS_MAP),
        "channel_map": dict(ENTITY_CHANNEL_MAP),
        "source_category_map": dict(SOURCE_CATEGORY_MAP),
        "safe_entity_hash_keys": list(SAFE_ENTITY_HASH_KEYS),
        "transient_raw_entity_keys": list(TRANSIENT_RAW_ENTITY_KEYS),
        "default_options": options.safe_summary(),
        "registry": registry_summary,
        "hard_limits": {
            "max_records": HARD_MAX_RECORDS,
            "max_entities": HARD_MAX_ENTITIES,
            "max_links": HARD_MAX_LINKS,
            "max_profiles": HARD_MAX_PROFILES,
            "max_entities_per_record": HARD_MAX_ENTITIES_PER_RECORD,
            "max_associated_refs": HARD_MAX_ASSOCIATED_REFS,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
        },
        "forbidden_entity_field_count": len(FORBIDDEN_ENTITY_FIELDS),
        "label_leakage_field_count": len(LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(PROHIBITED_ACTION_TOKENS),
        "summary_item_limit": max(1, int(limit)),
        "entity_policy": "salted_pseudonymous_references_only_no_raw_identifier_retention",
        "temporal_policy": "bounded_month_and_age_buckets_only_no_raw_timestamps",
        "caveats": list(ENTITY_CAVEATS),
        "safety_flags": dict(ENTITY_SAFETY_FLAGS),
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


def build_entities_service_descriptor(
    options: EntitiesServiceOptions | None = None,
    *,
    engine: EntitiesServiceEngine | None = None,
) -> Any:
    """
    Build a bounded service descriptor for the entities service.

    If the backend services registry descriptor is unavailable, this returns a
    safe plain dictionary representation instead of failing.
    """
    active_engine = engine or get_entities_engine(options)

    def _handler(payload: Any) -> dict[str, Any]:
        return active_engine.normalize(payload).to_dict()

    def _health() -> dict[str, Any]:
        return get_entities_health(engine=active_engine)

    if _RegistryServiceDescriptor is None:
        return {
            "service_id": "entities",
            "kind": "general",
            "display_name": "Entities Service",
            "description": "Bounded synthetic entity profiling and co-occurrence linkage service.",
            "version": ENTITIES_VERSION,
            "enabled": active_engine.options.enabled,
            "synthetic_required": active_engine.options.synthetic_required,
            "dataset_mode": active_engine.options.dataset_mode,
            "production_like": active_engine.options.production_like,
            "allow_in_production": active_engine.options.allow_in_production,
            "capabilities": [
                "entities",
                "profiling",
                "links",
                "privacy",
                "synthetic_only",
                "no_raw_identifiers",
                "no_raw_timestamps",
            ],
            "handler_registered": True,
            "health_handler_registered": True,
            "raw_values_retained": False,
            "executable_handler_exposed": False,
            "caveats": list(ENTITY_CAVEATS),
            "safety_flags": dict(ENTITY_SAFETY_FLAGS),
        }

    kind = getattr(_RegistryServiceKind, "GENERAL", "general") if _RegistryServiceKind else "general"

    return _RegistryServiceDescriptor(
        service_id="entities",
        kind=kind,
        display_name="Entities Service",
        description=(
            "Bounded synthetic entity profiling, co-occurrence linkage, and "
            "investigative attention summarization service."
        ),
        version=ENTITIES_VERSION,
        enabled=active_engine.options.enabled,
        synthetic_required=active_engine.options.synthetic_required,
        dataset_mode=active_engine.options.dataset_mode,
        production_like=active_engine.options.production_like,
        allow_in_production=active_engine.options.allow_in_production,
        capabilities=(
            "entities",
            "profiling",
            "links",
            "privacy",
            "synthetic_only",
            "no_automatic_adverse_action",
            "no_raw_identifiers",
            "no_raw_timestamps",
        ),
        handler=_handler,
        health_handler=_health,
        metadata={
            "service_module": "app.services.entities",
            "registry_backend": "process_local_in_memory",
            "raw_values_retained": False,
            "raw_identifiers_retained": False,
            "raw_timestamps_retained": False,
            "raw_entity_values_allowed": bool(active_engine.options.allow_raw_entity_values),
        },
    )


def register_entities_service(
    options: EntitiesServiceOptions | None = None,
    *,
    engine: EntitiesServiceEngine | None = None,
    registry: Any | None = None,
    replace: bool = True,
) -> Optional[str]:
    """
    Register the entities service descriptor with the backend services registry
    when available.
    """
    if _get_registry_service_registry is None:
        return None

    active_registry = registry or _get_registry_service_registry()
    descriptor = build_entities_service_descriptor(options=options, engine=engine)

    try:
        return active_registry.register(descriptor, replace=replace)
    except Exception:
        return None


__all__ = [
    "ENTITIES_VERSION",
    "EntityChannel",
    "EntityIssue",
    "EntityKind",
    "EntityLink",
    "EntityProfile",
    "EntityRegistry",
    "EntityStatus",
    "EntitiesRequest",
    "EntitiesResult",
    "EntitiesServiceEngine",
    "EntitiesServiceOptions",
    "IssueSeverity",
    "PriorityTier",
    "ServiceStatus",
    "SourceCategory",
    "build_entities_service_descriptor",
    "clear_entity_registry",
    "export_entities_summary",
    "get_entity_profile",
    "get_entity_registry",
    "get_entities_engine",
    "get_entities_health",
    "get_entities_metadata",
    "get_entities_options",
    "list_entity_links",
    "list_entity_profiles",
    "normalize_entities",
    "register_entities_service",
    "search_entity_profiles",
]