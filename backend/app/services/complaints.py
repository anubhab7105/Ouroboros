"""
MULEGUARD backend complaints service.

This module provides the canonical bounded synthetic complaint normalization,
redacted structural profiling, linkage summarization, and investigative
priority service for the MULEGUARD investigative prototype.

Primary responsibilities:

- normalize bounded synthetic complaint, report, case-intake, and dispute
  records into privacy-preserving complaint profiles using salted one-way
  pseudonymous references;
- extract only bounded, non-retaining structural signals from complaint
  narratives when narrative feature extraction is explicitly enabled;
- never retain, log, return, hash-and-store, or otherwise persist raw complaint
  narrative text, raw free-text descriptions, raw identifiers, raw monetary
  amounts, raw timestamps, labels, ground-truth fields, secrets, tokens,
  passwords, database URLs, filesystem paths, or model artifact paths;
- derive bounded complaint-to-account and complaint-to-subject linkage hints
  using salted pseudonymous references only;
- canonicalize complaint category, status, severity, channel, product domain,
  amount bucket, and temporal bucket signals using deterministic bounded maps;
- compute bounded investigative priority scores and tiers for human review
  triage only, with explicit non-calibration and non-adverse-action caveats;
- maintain a bounded process-local complaint profile registry for local
  prototype workflows, tests, developer tooling, and offline evaluation
  harnesses;
- expose a safe service descriptor compatible with the MULEGUARD backend
  services registry when available;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module profiles and summarizes synthetic complaints only. It does not
authenticate users, authorize actions, freeze accounts, block accounts,
blacklist accounts, close accounts, restrict services, deny services, terminate
relationships, suspend accounts, refer matters to law enforcement, make credit,
employment, housing, insurance, benefits, or other consequential decisions,
train models, deploy models, persist durable artifacts, call external systems,
or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for complaint profiling.
- Complaint profiles and priority scores are investigative leads or human
  workflow artefacts only. They are not proof of wrongdoing.
- Priority scores and tiers are not probabilities of guilt.
- Labels must never be used as complaint features or priority criteria.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected.
- Raw complaint narratives, descriptions, notes, statements, and free-text
  fields are never retained. When narrative feature extraction is enabled,
  narrative text is processed transiently and only bounded redacted structural
  counts, ratios, and buckets are emitted.
- Raw account identifiers and raw complaint identifiers are not retained. They
  are hashed immediately into salted pseudonymous references.
- Raw monetary amounts are not retained. Only bounded ordinal amount buckets are
  emitted, and amounts are never converted or blended across currencies.
- Raw timestamps are not retained. Only bounded month, weekday, hour-bucket,
  and age-bucket signals are emitted.
- Complaint operations must never trigger automatic adverse customer action
  such as freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable complaint signals are reported honestly as
  unavailable rather than invented.
- The bundled complaint registry is process-local, non-durable, and bounded for
  local prototype use only.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external complaint management systems, CRM systems,
  case management systems, contact center platforms, payment networks, core
  banking systems, card schemes, UPI switches, wallets, ledgers, graph
  databases, model runtimes, or network APIs.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models or complaint decisioning rules.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable complaint store.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, complaint profiles, anomaly scores, fallback scores, model
predictions, cycle candidates, community candidates, filtered graphs,
serialized graphs, correlation candidates, confidence records, account
profiles, transaction profiles, priority scores, explanations, validation
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


logger = logging.getLogger("muleguard.backend.services.complaints")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

COMPLAINTS_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.services.complaints.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

DEFAULT_MAX_COMPLAINTS: Final[int] = 10_000
HARD_MAX_COMPLAINTS: Final[int] = 100_000

DEFAULT_MAX_PROFILES: Final[int] = 10_000
HARD_MAX_PROFILES: Final[int] = 100_000

DEFAULT_MAX_NARRATIVE_LENGTH: Final[int] = 4_096
HARD_MAX_NARRATIVE_LENGTH: Final[int] = 32_768

DEFAULT_MAX_NARRATIVE_CHUNKS: Final[int] = 8
HARD_MAX_NARRATIVE_CHUNKS: Final[int] = 64

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

DEFAULT_PRIORITY_SEVERITY_WEIGHT: Final[float] = 0.28
DEFAULT_PRIORITY_AMOUNT_WEIGHT: Final[float] = 0.18
DEFAULT_PRIORITY_TEMPORAL_WEIGHT: Final[float] = 0.14
DEFAULT_PRIORITY_NARRATIVE_WEIGHT: Final[float] = 0.16
DEFAULT_PRIORITY_LINKAGE_WEIGHT: Final[float] = 0.12
DEFAULT_PRIORITY_STATUS_WEIGHT: Final[float] = 0.12

MAX_LINKAGE_ACCOUNTS: Final[int] = 10

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")
_NUMERIC_CLEAN_RE: Final[re.Pattern[str]] = re.compile(r"[^\d.\-]")

_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)
_URL_RE: Final[re.Pattern[str]] = re.compile(r"(?:https?://|www\.)", re.IGNORECASE)
_PHONE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}"
)
_IP_RE: Final[re.Pattern[str]] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NUMERIC_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\b\d+(?:[.,]\d+)*\b")
_CURRENCY_MENTION_RE: Final[re.Pattern[str]] = re.compile(
    r"[$€£₹¥₩₽]|\b(?:USD|INR|EUR|GBP|JPY|CNY|KRW|RUB)\b",
    re.IGNORECASE,
)
_DATE_RE: Final[re.Pattern[str]] = re.compile(
    r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b"
)
_ID_LIKE_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Z]{2,5}\d{4,12}[A-Z]?\b|\b\d{9,16}\b"
)
_SENTENCE_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"[.!?]+")
_PARAGRAPH_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"\n\s*\n")
_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9]+")
_PUNCTUATION_RE: Final[re.Pattern[str]] = re.compile(r"[^\w\s]", re.UNICODE)

_MISSING: Final[object] = object()

COMPLAINT_REF_KEYS: Final[tuple[str, ...]] = (
    "complaint_ref_hash",
    "complaint_hash",
    "reference_hash",
    "case_ref_hash",
    "report_ref_hash",
)

RAW_COMPLAINT_KEYS: Final[tuple[str, ...]] = (
    "complaint_id",
    "case_id",
    "report_id",
    "id",
    "uuid",
    "guid",
)

REPORTER_KEYS: Final[tuple[str, ...]] = (
    "reporter_account_id",
    "complainant_account_id",
    "victim_account_id",
    "subject_account_id",
    "account_id",
    "acct_id",
    "customer_account_id",
)

SUBJECT_ACCOUNT_KEYS: Final[tuple[str, ...]] = (
    "suspected_account_id",
    "accused_account_id",
    "target_account_id",
    "counterparty_account_id",
    "receiver_account_id",
    "payee_account_id",
)

PRODUCT_KEYS: Final[tuple[str, ...]] = (
    "product",
    "product_domain",
    "service",
    "service_domain",
    "channel_product",
)

CATEGORY_KEYS: Final[tuple[str, ...]] = (
    "category",
    "complaint_category",
    "issue_category",
    "report_category",
    "type",
)

STATUS_KEYS: Final[tuple[str, ...]] = (
    "status",
    "complaint_status",
    "case_status",
    "report_status",
    "state",
)

SEVERITY_KEYS: Final[tuple[str, ...]] = (
    "severity",
    "complaint_severity",
    "urgency",
    "risk_level",
    "priority",
)

CHANNEL_KEYS: Final[tuple[str, ...]] = (
    "channel",
    "source_channel",
    "submission_channel",
    "origination_channel",
    "intake_channel",
)

RECEIVED_KEYS: Final[tuple[str, ...]] = (
    "received_at",
    "reported_at",
    "created_at",
    "submitted_at",
    "filed_at",
    "opened_at",
    "intake_at",
    "timestamp",
    "date",
)

OCCURRED_KEYS: Final[tuple[str, ...]] = (
    "occurred_at",
    "incident_at",
    "event_at",
    "transaction_date",
    "effective_date",
)

RESOLVED_KEYS: Final[tuple[str, ...]] = (
    "resolved_at",
    "closed_at",
    "completed_at",
    "disposed_at",
)

AMOUNT_KEYS: Final[tuple[str, ...]] = (
    "amount",
    "claimed_amount",
    "loss_amount",
    "disputed_amount",
    "value",
)

CURRENCY_KEYS: Final[tuple[str, ...]] = (
    "currency",
    "ccy",
    "currency_code",
)

NARRATIVE_KEYS: Final[tuple[str, ...]] = (
    "narrative",
    "narrative_raw",
    "narrative_normalized",
    "description",
    "details",
    "notes",
    "summary",
    "text",
    "content",
    "complaint_text",
    "statement",
    "reporter_statement",
    "free_text",
)

NARRATIVE_TOKENS: Final[tuple[str, ...]] = (
    "narrative",
    "description",
    "details",
    "notes",
    "summary",
    "text",
    "content",
    "statement",
    "free_text",
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

FORBIDDEN_COMPLAINT_FIELDS: Final[frozenset[str]] = frozenset(
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

FORBIDDEN_COMPLAINT_TOKENS: Final[tuple[str, ...]] = (
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

COMPLAINT_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic complaint profiling only. Do not use with real customer data.",
    "Complaint profiles and priority scores are investigative leads only and are not proof of wrongdoing.",
    "Priority scores and tiers are not probabilities of guilt.",
    "Complaint profiling must not trigger automatic adverse customer action.",
    "Labels must never be used as complaint features or priority criteria.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives are never retained. Narrative features are transient, bounded, and redacted.",
    "Raw account identifiers and raw complaint identifiers are not retained. They are hashed immediately into salted pseudonymous references.",
    "Raw monetary amounts are not retained. Only bounded ordinal amount buckets are emitted.",
    "Currency amounts are never converted or blended across currencies.",
    "Raw timestamps are not retained. Only bounded month, weekday, hour-bucket, and age-bucket signals are emitted.",
    "The bundled complaint registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

COMPLAINT_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_raw_identifiers_retained": True,
        "no_raw_narratives_retained": True,
        "no_raw_monetary_values_retained": True,
        "no_raw_timestamps_retained": True,
        "salted_pseudonymous_complaint_references": True,
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
        "deterministic_complaint_profiling": True,
        "bounded_complaint_profiling_required": True,
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

COMPLAINT_CATEGORY_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "fraud": "FRAUD",
        "scam": "FRAUD",
        "fraudulent": "FRAUD",
        "unauthorized_transaction": "UNAUTHORIZED_TRANSACTION",
        "unauthorized": "UNAUTHORIZED_TRANSACTION",
        "transaction_dispute": "UNAUTHORIZED_TRANSACTION",
        "account_takeover": "ACCOUNT_TAKEOVER",
        "ato": "ACCOUNT_TAKEOVER",
        " takeover": "ACCOUNT_TAKEOVER",
        "phishing": "PHISHING",
        "smishing": "PHISHING",
        "vishing": "PHISHING",
        "identity_theft": "IDENTITY_THEFT",
        "impersonation": "IDENTITY_THEFT",
        "payment_failure": "PAYMENT_FAILURE",
        "failed_payment": "PAYMENT_FAILURE",
        "declined_transaction": "PAYMENT_FAILURE",
        "settlement_issue": "PAYMENT_FAILURE",
        "dispute": "DISPUTE",
        "chargeback": "DISPUTE",
        "refund": "DISPUTE",
        "harassment": "HARASSMENT",
        "abuse": "HARASSMENT",
        "threat": "HARASSMENT",
        "service_issue": "SERVICE_ISSUE",
        "technical_issue": "SERVICE_ISSUE",
        "other": "OTHER",
        "unknown": "UNKNOWN",
    }
)

COMPLAINT_STATUS_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "new": "NEW",
        "created": "NEW",
        "intake": "NEW",
        "open": "OPEN",
        "active": "OPEN",
        "in_progress": "IN_PROGRESS",
        "investigating": "IN_PROGRESS",
        "under_review": "IN_PROGRESS",
        "pending": "PENDING",
        "awaiting_information": "PENDING",
        "escalated": "ESCALATED",
        "resolved": "RESOLVED",
        "closed": "CLOSED",
        "completed": "CLOSED",
        "cancelled": "CLOSED",
        "canceled": "CLOSED",
        "withdrawn": "CLOSED",
    }
)

COMPLAINT_SEVERITY_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "info": "INFO",
        "informational": "INFO",
        "low": "LOW",
        "minor": "LOW",
        "medium": "MODERATE",
        "moderate": "MODERATE",
        "normal": "MODERATE",
        "high": "HIGH",
        "major": "HIGH",
        "serious": "HIGH",
        "critical": "CRITICAL",
        "severe": "CRITICAL",
        "urgent": "CRITICAL",
    }
)

COMPLAINT_CHANNEL_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "web": "WEB",
        "website": "WEB",
        "portal": "WEB",
        "mobile": "MOBILE",
        "app": "MOBILE",
        "mobile_app": "MOBILE",
        "api": "API",
        "email": "EMAIL",
        "phone": "PHONE",
        "telephone": "PHONE",
        "call_center": "PHONE",
        "chat": "CHAT",
        "live_chat": "CHAT",
        "social": "SOCIAL",
        "social_media": "SOCIAL",
        "branch": "BRANCH",
        "letter": "MAIL",
        "mail": "MAIL",
        "in_person": "BRANCH",
        "other": "OTHER",
    }
)

PRODUCT_DOMAIN_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "payments": "PAYMENTS",
        "payment": "PAYMENTS",
        "cards": "CARDS",
        "card": "CARDS",
        "credit_card": "CARDS",
        "debit_card": "CARDS",
        "transfers": "TRANSFERS",
        "transfer": "TRANSFERS",
        "remittance": "TRANSFERS",
        "wallet": "WALLETS",
        "wallets": "WALLETS",
        "upi": "UPI",
        "netbanking": "NETBANKING",
        "net_banking": "NETBANKING",
        "loans": "LOANS",
        "loan": "LOANS",
        "credit": "LOANS",
        "deposits": "DEPOSITS",
        "deposit": "DEPOSITS",
        "savings": "DEPOSITS",
        "markets": "MARKETS",
        "trading": "MARKETS",
        "investment": "MARKETS",
        "investments": "MARKETS",
        "insurance": "INSURANCE",
        "other": "OTHER",
        "unknown": "UNKNOWN",
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

CHAR_BUCKET_SPECS: Final[tuple[tuple[Optional[int], str, float], ...]] = (
    (0, "empty", 0.00),
    (99, "tiny", 0.15),
    (499, "short", 0.35),
    (1999, "medium", 0.55),
    (9999, "long", 0.75),
    (None, "very_long", 0.95),
)

COUNT_BUCKET_SPECS: Final[tuple[tuple[Optional[int], str, float], ...]] = (
    (0, "zero", 0.00),
    (2, "low", 0.20),
    (9, "moderate", 0.45),
    (49, "elevated", 0.70),
    (99, "high", 0.90),
    (None, "very_high", 1.00),
)

RATIO_BUCKET_SPECS: Final[tuple[tuple[float, str, float], ...]] = (
    (0.01, "none", 0.00),
    (0.10, "low", 0.25),
    (0.30, "moderate", 0.50),
    (0.60, "high", 0.75),
    (1.01, "very_high", 1.00),
)

CREDENTIAL_TERMS: Final[tuple[str, ...]] = (
    "otp",
    "password",
    "passwd",
    "pin",
    "cvv",
    "pan",
    "aadhaar",
    "upi",
    "card number",
    "account number",
    "secret",
    "token",
)

PAYMENT_TERMS: Final[tuple[str, ...]] = (
    "payment",
    "transfer",
    "transaction",
    "refund",
    "debit",
    "credit",
    "settlement",
    "chargeback",
    "dispute",
    "wallet",
    "upi",
    "neft",
    "rtgs",
    "imps",
)

URGENCY_TERMS: Final[tuple[str, ...]] = (
    "urgent",
    "immediately",
    "right now",
    "asap",
    "today",
    "overdue",
    "deadline",
    "final notice",
)

THREAT_TERMS: Final[tuple[str, ...]] = (
    "threat",
    "blackmail",
    "coerc",
    "harass",
    "abuse",
    "intimidat",
    "stalk",
)

_ALL_COMPLAINT_VIEW_KEYS: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            *COMPLAINT_REF_KEYS,
            *RAW_COMPLAINT_KEYS,
            *REPORTER_KEYS,
            *SUBJECT_ACCOUNT_KEYS,
            *PRODUCT_KEYS,
            *CATEGORY_KEYS,
            *STATUS_KEYS,
            *SEVERITY_KEYS,
            *CHANNEL_KEYS,
            *RECEIVED_KEYS,
            *OCCURRED_KEYS,
            *RESOLVED_KEYS,
            *AMOUNT_KEYS,
            *CURRENCY_KEYS,
            *NARRATIVE_KEYS,
        }
    )
)

# ---------------------------------------------------------------------------
# Text normalisation helpers
# ---------------------------------------------------------------------------
# Defined above their first use: the module-level constants just below call
# `_normalize_token` while the module body is still executing, and with the
# definitions further down the file the name does not exist yet and the
# import fails with a NameError.
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


_COMPLAINT_LIKE_KEYS: Final[frozenset[str]] = frozenset(_ALL_COMPLAINT_VIEW_KEYS)
_NARRATIVE_CANONICAL_KEYS: Final[frozenset[str]] = frozenset(
    _normalize_token(key) for key in NARRATIVE_KEYS
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class ComplaintCategory(str, Enum):
    """
    Bounded synthetic complaint category.
    """

    FRAUD = "fraud"
    UNAUTHORIZED_TRANSACTION = "unauthorized_transaction"
    ACCOUNT_TAKEOVER = "account_takeover"
    PHISHING = "phishing"
    IDENTITY_THEFT = "identity_theft"
    PAYMENT_FAILURE = "payment_failure"
    DISPUTE = "dispute"
    HARASSMENT = "harassment"
    SERVICE_ISSUE = "service_issue"
    OTHER = "other"
    UNKNOWN = "unknown"


class ComplaintStatus(str, Enum):
    """
    Bounded observational complaint status.

    These states are descriptive only. They must not be interpreted as
    authorization to take adverse action.
    """

    NEW = "new"
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class ComplaintSeverity(str, Enum):
    """
    Bounded complaint severity.
    """

    INFO = "info"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ComplaintChannel(str, Enum):
    """
    Bounded complaint intake channel.
    """

    WEB = "web"
    MOBILE = "mobile"
    API = "api"
    EMAIL = "email"
    PHONE = "phone"
    CHAT = "chat"
    SOCIAL = "social"
    BRANCH = "branch"
    MAIL = "mail"
    OTHER = "other"
    UNKNOWN = "unknown"


class ProductDomain(str, Enum):
    """
    Bounded product or service domain.
    """

    PAYMENTS = "payments"
    CARDS = "cards"
    TRANSFERS = "transfers"
    WALLETS = "wallets"
    UPI = "upi"
    NETBANKING = "netbanking"
    LOANS = "loans"
    DEPOSITS = "deposits"
    MARKETS = "markets"
    INSURANCE = "insurance"
    OTHER = "other"
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
    Overall complaints service status.
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



def _canonical_field_name(key: Any) -> str:
    return _normalize_token(key)


def _is_safe_hash(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and _HASH_RE.match(text))


def _is_narrative_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in _NARRATIVE_CANONICAL_KEYS:
        return True

    return any(token in canonical for token in NARRATIVE_TOKENS)


def _is_forbidden_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in FORBIDDEN_COMPLAINT_FIELDS:
        return True

    if canonical.startswith("raw_") or canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in FORBIDDEN_COMPLAINT_TOKENS)


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


def _complaint_ref_hash(value: Any, options: "ComplaintsServiceOptions") -> Optional[str]:
    text = _clean_text(value, MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.services.complaints.complaint.{namespace}"
    return _hmac_hex(options.salt, domain, text)[:40]


def _account_ref_hash(value: Any, options: "ComplaintsServiceOptions") -> Optional[str]:
    text = _clean_text(value, MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.services.complaints.account.{namespace}"
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


def _timestamp_parts(
    value: Any,
    now: Optional[datetime] = None,
    compute_age: bool = False,
) -> tuple[Optional[str], Optional[int], Optional[str], Optional[int]]:
    parsed = _parse_datetime(value)

    if parsed is None:
        return None, None, None, None

    month = parsed.strftime("%Y-%m")
    weekday = int(parsed.weekday())
    hour = int(parsed.hour)
    months_since = _months_between(parsed, now) if compute_age else None

    return month, weekday, _hour_bucket(hour), months_since


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


def _bucket_from_count(count: int, specs: Sequence[tuple[Optional[int], str, float]]) -> tuple[str, float]:
    safe_count = max(0, int(count))

    for upper, label, score in specs:
        if upper is None or safe_count <= upper:
            return label, score

    return specs[-1][1], specs[-1][2]


def _bucket_from_ratio(ratio: float, specs: Sequence[tuple[float, str, float]]) -> tuple[str, float]:
    safe_ratio = _clip_float(ratio, 0.0, 1.0, 0.0)

    for upper, label, score in specs:
        if safe_ratio < upper:
            return label, score

    return specs[-1][1], specs[-1][2]


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
# Narrative structure helpers
# -----------------------------------------------------------------------------


def _empty_narrative_features() -> dict[str, Any]:
    return {
        "present": False,
        "char_count": 0,
        "token_count": 0,
        "sentence_count": 0,
        "paragraph_count": 0,
        "uppercase_ratio": 0.0,
        "digit_ratio": 0.0,
        "punctuation_ratio": 0.0,
        "email_like_count": 0,
        "url_like_count": 0,
        "phone_like_count": 0,
        "ip_like_count": 0,
        "numeric_token_count": 0,
        "currency_mention_count": 0,
        "date_like_count": 0,
        "id_like_count": 0,
        "credential_mention_count": 0,
        "payment_mention_count": 0,
        "urgency_mention_count": 0,
        "threat_mention_count": 0,
        "raw_narrative_retained": False,
        "narrative_redacted": True,
    }


def _finalize_narrative_features(features: Mapping[str, Any]) -> dict[str, Any]:
    safe = _empty_narrative_features()

    for key, value in features.items():
        if key in safe:
            safe[key] = value

    char_count = max(0, _as_int(safe.get("char_count"), 0))
    token_count = max(0, _as_int(safe.get("token_count"), 0))
    sentence_count = max(0, _as_int(safe.get("sentence_count"), 0))
    paragraph_count = max(0, _as_int(safe.get("paragraph_count"), 0))

    safe["char_count"] = char_count
    safe["token_count"] = token_count
    safe["sentence_count"] = sentence_count
    safe["paragraph_count"] = paragraph_count

    for key in (
        "email_like_count",
        "url_like_count",
        "phone_like_count",
        "ip_like_count",
        "numeric_token_count",
        "currency_mention_count",
        "date_like_count",
        "id_like_count",
        "credential_mention_count",
        "payment_mention_count",
        "urgency_mention_count",
        "threat_mention_count",
    ):
        safe[key] = max(0, _as_int(safe.get(key), 0))

    for key in ("uppercase_ratio", "digit_ratio", "punctuation_ratio"):
        safe[key] = _round6(_clip_float(safe.get(key), 0.0, 1.0, 0.0))

    safe["present"] = bool(safe.get("present")) or char_count > 0 or token_count > 0
    safe["raw_narrative_retained"] = False
    safe["narrative_redacted"] = True

    char_bucket, char_score = _bucket_from_count(char_count, CHAR_BUCKET_SPECS)
    token_bucket, token_score = _bucket_from_count(token_count, COUNT_BUCKET_SPECS)
    sentence_bucket, sentence_score = _bucket_from_count(sentence_count, COUNT_BUCKET_SPECS)
    paragraph_bucket, paragraph_score = _bucket_from_count(paragraph_count, COUNT_BUCKET_SPECS)

    upper_bucket, upper_score = _bucket_from_ratio(float(safe["uppercase_ratio"]), RATIO_BUCKET_SPECS)
    digit_bucket, digit_score = _bucket_from_ratio(float(safe["digit_ratio"]), RATIO_BUCKET_SPECS)
    punct_bucket, punct_score = _bucket_from_ratio(float(safe["punctuation_ratio"]), RATIO_BUCKET_SPECS)

    safe.update(
        {
            "char_bucket": char_bucket,
            "char_bucket_score": _round6(char_score),
            "token_bucket": token_bucket,
            "token_bucket_score": _round6(token_score),
            "sentence_bucket": sentence_bucket,
            "sentence_bucket_score": _round6(sentence_score),
            "paragraph_bucket": paragraph_bucket,
            "paragraph_bucket_score": _round6(paragraph_score),
            "uppercase_bucket": upper_bucket,
            "uppercase_bucket_score": _round6(upper_score),
            "digit_bucket": digit_bucket,
            "digit_bucket_score": _round6(digit_score),
            "punctuation_bucket": punct_bucket,
            "punctuation_bucket_score": _round6(punct_score),
        }
    )

    return safe


def _normalize_narrative_structure(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _finalize_narrative_features(_empty_narrative_features())

    features = _empty_narrative_features()

    numeric_keys = {
        "char_count",
        "token_count",
        "sentence_count",
        "paragraph_count",
        "email_like_count",
        "url_like_count",
        "phone_like_count",
        "ip_like_count",
        "numeric_token_count",
        "currency_mention_count",
        "date_like_count",
        "id_like_count",
        "credential_mention_count",
        "payment_mention_count",
        "urgency_mention_count",
        "threat_mention_count",
    }

    ratio_keys = {"uppercase_ratio", "digit_ratio", "punctuation_ratio"}

    for raw_key, raw_value in value.items():
        key = _clean_text(raw_key, 64)

        if not key:
            continue

        if key == "present":
            features["present"] = _as_bool(raw_value, False)
        elif key in numeric_keys:
            features[key] = max(0, _as_int(raw_value, 0))
        elif key in ratio_keys:
            features[key] = _round6(_clip_float(raw_value, 0.0, 1.0, 0.0))
        elif key in {
            "char_bucket",
            "token_bucket",
            "sentence_bucket",
            "paragraph_bucket",
            "uppercase_bucket",
            "digit_bucket",
            "punctuation_bucket",
        }:
            features[key] = _normalize_token(raw_value) or "none"
        elif key.endswith("_score"):
            features[key] = _round6(_clip_float(raw_value, 0.0, 1.0, 0.0))
        elif key in {"raw_narrative_retained", "narrative_redacted"}:
            features[key] = _as_bool(raw_value, key == "narrative_redacted")

    return _finalize_narrative_features(features)


def _coerce_narrative_text(value: Any, limit: int) -> Optional[str]:
    if limit <= 0:
        return None

    if isinstance(value, (str, bytes, bytearray, memoryview)):
        text = _normalize_unicode(value)
    elif isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        text = _normalize_unicode(value)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        parts: list[str] = []

        for item in value:
            if isinstance(item, (str, bytes, bytearray, memoryview)):
                parts.append(_normalize_unicode(item))
            elif isinstance(item, (int, float, Decimal)) and not isinstance(item, bool):
                parts.append(_normalize_unicode(item))

            if len(parts) >= 16:
                break

        text = " ".join(parts)
    else:
        return None

    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = " ".join(text.split())

    if not text:
        return None

    return text[:limit]


def _count_terms(text: str, terms: Sequence[str]) -> int:
    lowered = text.lower()
    count = 0

    for term in terms:
        if not term:
            continue

        count += lowered.count(term)

        if count >= 10_000:
            return 10_000

    return count


def _analyze_narrative_text(text: str, options: ComplaintsServiceOptions) -> dict[str, Any]:
    bounded = text[: int(options.max_narrative_length)]
    char_count = len(bounded)

    if char_count == 0:
        return _empty_narrative_features()

    tokens = _TOKEN_RE.findall(bounded)
    token_count = len(tokens)

    sentences = [part.strip() for part in _SENTENCE_SPLIT_RE.split(bounded) if part.strip()]
    sentence_count = len(sentences)

    paragraphs = [part.strip() for part in _PARAGRAPH_SPLIT_RE.split(bounded) if part.strip()]
    paragraph_count = max(1, len(paragraphs)) if bounded.strip() else 0

    alpha_count = sum(1 for ch in bounded if ch.isalpha())
    upper_count = sum(1 for ch in bounded if ch.isupper())
    digit_count = sum(1 for ch in bounded if ch.isdigit())
    punct_count = len(_PUNCTUATION_RE.findall(bounded))

    uppercase_ratio = (upper_count / alpha_count) if alpha_count else 0.0
    digit_ratio = (digit_count / char_count) if char_count else 0.0
    punctuation_ratio = (punct_count / char_count) if char_count else 0.0

    features = _empty_narrative_features()
    features.update(
        {
            "present": True,
            "char_count": char_count,
            "token_count": token_count,
            "sentence_count": sentence_count,
            "paragraph_count": paragraph_count,
            "uppercase_ratio": _round6(uppercase_ratio),
            "digit_ratio": _round6(digit_ratio),
            "punctuation_ratio": _round6(punctuation_ratio),
            "email_like_count": len(_EMAIL_RE.findall(bounded)),
            "url_like_count": len(_URL_RE.findall(bounded)),
            "phone_like_count": len(_PHONE_RE.findall(bounded)),
            "ip_like_count": len(_IP_RE.findall(bounded)),
            "numeric_token_count": len(_NUMERIC_TOKEN_RE.findall(bounded)),
            "currency_mention_count": len(_CURRENCY_MENTION_RE.findall(bounded)),
            "date_like_count": len(_DATE_RE.findall(bounded)),
            "id_like_count": len(_ID_LIKE_RE.findall(bounded)),
            "credential_mention_count": _count_terms(bounded, CREDENTIAL_TERMS),
            "payment_mention_count": _count_terms(bounded, PAYMENT_TERMS),
            "urgency_mention_count": _count_terms(bounded, URGENCY_TERMS),
            "threat_mention_count": _count_terms(bounded, THREAT_TERMS),
        }
    )

    return _finalize_narrative_features(features)


def _merge_narrative_features(
    existing: Mapping[str, Any],
    incoming: Mapping[str, Any],
) -> dict[str, Any]:
    base = _normalize_narrative_structure(existing)
    other = _normalize_narrative_structure(incoming)

    if not other.get("present"):
        return base

    if not base.get("present"):
        return other

    merged = _empty_narrative_features()
    merged["present"] = True

    additive_keys = (
        "char_count",
        "token_count",
        "sentence_count",
        "paragraph_count",
        "email_like_count",
        "url_like_count",
        "phone_like_count",
        "ip_like_count",
        "numeric_token_count",
        "currency_mention_count",
        "date_like_count",
        "id_like_count",
        "credential_mention_count",
        "payment_mention_count",
        "urgency_mention_count",
        "threat_mention_count",
    )

    for key in additive_keys:
        merged[key] = max(0, _as_int(base.get(key), 0) + _as_int(other.get(key), 0))

    base_chars = max(0, _as_int(base.get("char_count"), 0))
    other_chars = max(0, _as_int(other.get("char_count"), 0))
    total_chars = base_chars + other_chars

    for key in ("uppercase_ratio", "digit_ratio", "punctuation_ratio"):
        base_value = _clip_float(base.get(key), 0.0, 1.0, 0.0)
        other_value = _clip_float(other.get(key), 0.0, 1.0, 0.0)

        if total_chars > 0:
            merged[key] = _round6(
                (base_value * base_chars + other_value * other_chars) / float(total_chars)
            )
        else:
            merged[key] = _round6(max(base_value, other_value))

    return _finalize_narrative_features(merged)


def _narrative_features_from_texts(
    texts: Sequence[str],
    options: ComplaintsServiceOptions,
) -> dict[str, Any]:
    if not options.allow_narrative_features or not texts:
        return _finalize_narrative_features(_empty_narrative_features())

    aggregate = _empty_narrative_features()

    for text in list(texts)[: int(options.max_narrative_chunks)]:
        analyzed = _analyze_narrative_text(text, options)
        aggregate = _merge_narrative_features(aggregate, analyzed)

    return _finalize_narrative_features(aggregate)


def _narrative_intensity_score(features: Mapping[str, Any]) -> float:
    if not features or not features.get("present"):
        return 0.0

    uppercase_score = _clip_float(features.get("uppercase_bucket_score"), 0.0, 1.0, 0.0)
    digit_score = _clip_float(features.get("digit_bucket_score"), 0.0, 1.0, 0.0)
    punctuation_score = _clip_float(features.get("punctuation_bucket_score"), 0.0, 1.0, 0.0)

    credential_score = min(1.0, _as_int(features.get("credential_mention_count"), 0) / 20.0)
    urgency_score = min(1.0, _as_int(features.get("urgency_mention_count"), 0) / 10.0)
    threat_score = min(1.0, _as_int(features.get("threat_mention_count"), 0) / 5.0)

    score = (
        uppercase_score * 0.15
        + digit_score * 0.15
        + punctuation_score * 0.10
        + credential_score * 0.20
        + urgency_score * 0.15
        + threat_score * 0.25
    )

    return _round6(_clip_float(score, 0.0, 1.0, 0.0))


# -----------------------------------------------------------------------------
# Issue model and helpers
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComplaintIssue:
    """
    Safe complaint-service issue.

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


def _coerce_issue(value: Any) -> ComplaintIssue:
    if isinstance(value, ComplaintIssue):
        return value

    if isinstance(value, Mapping):
        return ComplaintIssue(
            severity=value.get("severity", IssueSeverity.WARNING),
            code=value.get("code", "unstructured_issue"),
            message=value.get("message", ""),
            field=value.get("field"),
            details=value.get("details", {}),
        )

    return ComplaintIssue(
        severity=IssueSeverity.WARNING,
        code="unstructured_issue",
        message=_clean_text(value, MAX_REASON_TEXT_LENGTH),
    )


def _append_issue(
    issues: list[ComplaintIssue],
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

        issues[-1] = ComplaintIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        ComplaintIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, MAX_REASON_TEXT_LENGTH),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[ComplaintIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[ComplaintIssue]) -> tuple[ComplaintIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[ComplaintIssue] = []

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
class ComplaintsServiceOptions:
    """
    Bounded synthetic complaints service policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    max_complaints: int = DEFAULT_MAX_COMPLAINTS
    max_profiles: int = DEFAULT_MAX_PROFILES
    max_narrative_length: int = DEFAULT_MAX_NARRATIVE_LENGTH
    max_narrative_chunks: int = DEFAULT_MAX_NARRATIVE_CHUNKS
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS

    allow_narrative_features: bool = True
    include_priority: bool = True
    register_profiles: bool = True
    drop_forbidden_fields: bool = True

    low_threshold: float = DEFAULT_LOW_THRESHOLD
    moderate_threshold: float = DEFAULT_MODERATE_THRESHOLD
    elevated_threshold: float = DEFAULT_ELEVATED_THRESHOLD

    priority_severity_weight: float = DEFAULT_PRIORITY_SEVERITY_WEIGHT
    priority_amount_weight: float = DEFAULT_PRIORITY_AMOUNT_WEIGHT
    priority_temporal_weight: float = DEFAULT_PRIORITY_TEMPORAL_WEIGHT
    priority_narrative_weight: float = DEFAULT_PRIORITY_NARRATIVE_WEIGHT
    priority_linkage_weight: float = DEFAULT_PRIORITY_LINKAGE_WEIGHT
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
            "max_complaints",
            _clamp_int(self.max_complaints, 1, HARD_MAX_COMPLAINTS, DEFAULT_MAX_COMPLAINTS),
        )
        object.__setattr__(
            self,
            "max_profiles",
            _clamp_int(self.max_profiles, 1, HARD_MAX_PROFILES, DEFAULT_MAX_PROFILES),
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
            "max_narrative_chunks",
            _clamp_int(
                self.max_narrative_chunks,
                1,
                HARD_MAX_NARRATIVE_CHUNKS,
                DEFAULT_MAX_NARRATIVE_CHUNKS,
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

        object.__setattr__(self, "allow_narrative_features", _as_bool(self.allow_narrative_features, True))
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

        severity_w = _clamp_float(
            self.priority_severity_weight,
            0.0,
            1.0,
            DEFAULT_PRIORITY_SEVERITY_WEIGHT,
        )
        amount_w = _clamp_float(self.priority_amount_weight, 0.0, 1.0, DEFAULT_PRIORITY_AMOUNT_WEIGHT)
        temporal_w = _clamp_float(
            self.priority_temporal_weight,
            0.0,
            1.0,
            DEFAULT_PRIORITY_TEMPORAL_WEIGHT,
        )
        narrative_w = _clamp_float(
            self.priority_narrative_weight,
            0.0,
            1.0,
            DEFAULT_PRIORITY_NARRATIVE_WEIGHT,
        )
        linkage_w = _clamp_float(
            self.priority_linkage_weight,
            0.0,
            1.0,
            DEFAULT_PRIORITY_LINKAGE_WEIGHT,
        )
        status_w = _clamp_float(self.priority_status_weight, 0.0, 1.0, DEFAULT_PRIORITY_STATUS_WEIGHT)

        total = severity_w + amount_w + temporal_w + narrative_w + linkage_w + status_w

        if total <= 0.0:
            severity_w = DEFAULT_PRIORITY_SEVERITY_WEIGHT
            amount_w = DEFAULT_PRIORITY_AMOUNT_WEIGHT
            temporal_w = DEFAULT_PRIORITY_TEMPORAL_WEIGHT
            narrative_w = DEFAULT_PRIORITY_NARRATIVE_WEIGHT
            linkage_w = DEFAULT_PRIORITY_LINKAGE_WEIGHT
            status_w = DEFAULT_PRIORITY_STATUS_WEIGHT
            total = severity_w + amount_w + temporal_w + narrative_w + linkage_w + status_w

        object.__setattr__(self, "priority_severity_weight", _round6(severity_w / total))
        object.__setattr__(self, "priority_amount_weight", _round6(amount_w / total))
        object.__setattr__(self, "priority_temporal_weight", _round6(temporal_w / total))
        object.__setattr__(self, "priority_narrative_weight", _round6(narrative_w / total))
        object.__setattr__(self, "priority_linkage_weight", _round6(linkage_w / total))
        object.__setattr__(self, "priority_status_weight", _round6(status_w / total))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ComplaintsServiceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "COMPLAINTS_SERVICE_SALT", None)
            or _setting(settings, "SERVICES_COMPLAINTS_SALT", None)
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
            enabled=_as_bool(_setting(settings, "COMPLAINTS_SERVICE_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "COMPLAINTS_SERVICE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "COMPLAINTS_SERVICE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(_setting(settings, "COMPLAINTS_SERVICE_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "COMPLAINTS_SERVICE_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_complaints=_as_int(
                _setting(settings, "COMPLAINTS_SERVICE_MAX_COMPLAINTS", DEFAULT_MAX_COMPLAINTS),
                DEFAULT_MAX_COMPLAINTS,
            ),
            max_profiles=_as_int(
                _setting(settings, "COMPLAINTS_SERVICE_MAX_PROFILES", DEFAULT_MAX_PROFILES),
                DEFAULT_MAX_PROFILES,
            ),
            max_narrative_length=_as_int(
                _setting(settings, "COMPLAINTS_SERVICE_MAX_NARRATIVE_LENGTH", DEFAULT_MAX_NARRATIVE_LENGTH),
                DEFAULT_MAX_NARRATIVE_LENGTH,
            ),
            max_narrative_chunks=_as_int(
                _setting(settings, "COMPLAINTS_SERVICE_MAX_NARRATIVE_CHUNKS", DEFAULT_MAX_NARRATIVE_CHUNKS),
                DEFAULT_MAX_NARRATIVE_CHUNKS,
            ),
            max_issues=_as_int(
                _setting(settings, "COMPLAINTS_SERVICE_MAX_ISSUES", DEFAULT_MAX_ISSUES),
                DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(settings, "COMPLAINTS_SERVICE_MAX_SUMMARY_ITEMS", DEFAULT_MAX_SUMMARY_ITEMS),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "COMPLAINTS_SERVICE_MAX_TIME_MS", DEFAULT_MAX_TIME_MS),
                DEFAULT_MAX_TIME_MS,
            ),
            allow_narrative_features=_as_bool(
                _setting(settings, "COMPLAINTS_SERVICE_ALLOW_NARRATIVE_FEATURES", True),
                True,
            ),
            include_priority=_as_bool(_setting(settings, "COMPLAINTS_SERVICE_INCLUDE_PRIORITY", True), True),
            register_profiles=_as_bool(
                _setting(settings, "COMPLAINTS_SERVICE_REGISTER_PROFILES", True),
                True,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "COMPLAINTS_SERVICE_DROP_FORBIDDEN_FIELDS", True),
                True,
            ),
            low_threshold=_as_float(
                _setting(settings, "COMPLAINTS_SERVICE_LOW_THRESHOLD", DEFAULT_LOW_THRESHOLD),
                DEFAULT_LOW_THRESHOLD,
            ),
            moderate_threshold=_as_float(
                _setting(settings, "COMPLAINTS_SERVICE_MODERATE_THRESHOLD", DEFAULT_MODERATE_THRESHOLD),
                DEFAULT_MODERATE_THRESHOLD,
            ),
            elevated_threshold=_as_float(
                _setting(settings, "COMPLAINTS_SERVICE_ELEVATED_THRESHOLD", DEFAULT_ELEVATED_THRESHOLD),
                DEFAULT_ELEVATED_THRESHOLD,
            ),
            priority_severity_weight=_as_float(
                _setting(
                    settings,
                    "COMPLAINTS_SERVICE_PRIORITY_SEVERITY_WEIGHT",
                    DEFAULT_PRIORITY_SEVERITY_WEIGHT,
                ),
                DEFAULT_PRIORITY_SEVERITY_WEIGHT,
            ),
            priority_amount_weight=_as_float(
                _setting(settings, "COMPLAINTS_SERVICE_PRIORITY_AMOUNT_WEIGHT", DEFAULT_PRIORITY_AMOUNT_WEIGHT),
                DEFAULT_PRIORITY_AMOUNT_WEIGHT,
            ),
            priority_temporal_weight=_as_float(
                _setting(
                    settings,
                    "COMPLAINTS_SERVICE_PRIORITY_TEMPORAL_WEIGHT",
                    DEFAULT_PRIORITY_TEMPORAL_WEIGHT,
                ),
                DEFAULT_PRIORITY_TEMPORAL_WEIGHT,
            ),
            priority_narrative_weight=_as_float(
                _setting(
                    settings,
                    "COMPLAINTS_SERVICE_PRIORITY_NARRATIVE_WEIGHT",
                    DEFAULT_PRIORITY_NARRATIVE_WEIGHT,
                ),
                DEFAULT_PRIORITY_NARRATIVE_WEIGHT,
            ),
            priority_linkage_weight=_as_float(
                _setting(settings, "COMPLAINTS_SERVICE_PRIORITY_LINKAGE_WEIGHT", DEFAULT_PRIORITY_LINKAGE_WEIGHT),
                DEFAULT_PRIORITY_LINKAGE_WEIGHT,
            ),
            priority_status_weight=_as_float(
                _setting(settings, "COMPLAINTS_SERVICE_PRIORITY_STATUS_WEIGHT", DEFAULT_PRIORITY_STATUS_WEIGHT),
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
                "max_complaints": self.max_complaints,
                "max_profiles": self.max_profiles,
                "max_narrative_length": self.max_narrative_length,
                "max_narrative_chunks": self.max_narrative_chunks,
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
                    "severity": _round6(self.priority_severity_weight),
                    "amount": _round6(self.priority_amount_weight),
                    "temporal": _round6(self.priority_temporal_weight),
                    "narrative": _round6(self.priority_narrative_weight),
                    "linkage": _round6(self.priority_linkage_weight),
                    "status": _round6(self.priority_status_weight),
                },
            },
            "flags": {
                "allow_narrative_features": self.allow_narrative_features,
                "register_profiles": self.register_profiles,
                "drop_forbidden_fields": self.drop_forbidden_fields,
            },
            "narrative_policy": "transient_redacted_structural_features_only_no_raw_retention",
            "monetary_policy": "bounded_amount_buckets_only_no_raw_values_no_cross_currency_blending",
            "temporal_policy": "bounded_month_weekday_hour_age_buckets_only_no_raw_timestamps",
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "complaints",
        "reports",
        "cases",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class ComplaintsRequest:
    """
    Bounded synthetic complaints service request.
    """

    complaints: Any = None
    reports: Any = None
    cases: Any = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    tags: Sequence[str] = dataclass_field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> ComplaintsRequest:
    if isinstance(request, ComplaintsRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(ComplaintsRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return ComplaintsRequest(**clean)
            except Exception:
                return ComplaintsRequest(
                    complaints=payload.get("complaints", payload.get("reports", payload.get("cases", request)))
                )

        if any(_canonical_field_name(key) in _COMPLAINT_LIKE_KEYS for key in payload):
            return ComplaintsRequest(complaints=[payload])

        return ComplaintsRequest(metadata=request)

    if isinstance(request, (list, tuple, set, frozenset)):
        return ComplaintsRequest(complaints=request)

    return ComplaintsRequest(complaints=request)


# -----------------------------------------------------------------------------
# Public models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComplaintProfile:
    """
    One bounded synthetic complaint profile.

    Profiles are investigative human-workflow artefacts only. They are not
    proof of wrongdoing and must not trigger automatic adverse action.
    """

    complaint_ref_hash: str = ""
    category: ComplaintCategory | str = ComplaintCategory.UNKNOWN
    status: ComplaintStatus | str = ComplaintStatus.UNKNOWN
    severity: ComplaintSeverity | str = ComplaintSeverity.UNKNOWN
    channel: ComplaintChannel | str = ComplaintChannel.UNKNOWN
    product_domain: ProductDomain | str = ProductDomain.UNKNOWN

    reporter_ref_hash: Optional[str] = None
    subject_ref_hashes: tuple[str, ...] = ()
    related_account_ref_hashes: tuple[str, ...] = ()

    received_month: Optional[str] = None
    received_weekday: Optional[int] = None
    received_hour_bucket: Optional[str] = None
    months_since_received: Optional[int] = None

    occurred_month: Optional[str] = None
    occurred_weekday: Optional[int] = None
    occurred_hour_bucket: Optional[str] = None

    resolved_month: Optional[str] = None

    currency: Optional[str] = None
    amount_bucket: str = "unknown"
    amount_ordinal: int = -1
    amount_score: float = 0.0

    narrative_structure: Mapping[str, Any] = dataclass_field(default_factory=dict)

    priority_score: float = 0.0
    priority_tier: PriorityTier | str = PriorityTier.UNSCORED
    priority_reasons: tuple[str, ...] = ()

    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "complaint_ref_hash",
            _clean_text(self.complaint_ref_hash, MAX_HASH_LENGTH).lower(),
        )
        object.__setattr__(
            self,
            "category",
            _normalize_enum_option(ComplaintCategory, self.category, ComplaintCategory.UNKNOWN),
        )
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(ComplaintStatus, self.status, ComplaintStatus.UNKNOWN),
        )
        object.__setattr__(
            self,
            "severity",
            _normalize_enum_option(ComplaintSeverity, self.severity, ComplaintSeverity.UNKNOWN),
        )
        object.__setattr__(
            self,
            "channel",
            _normalize_enum_option(ComplaintChannel, self.channel, ComplaintChannel.UNKNOWN),
        )
        object.__setattr__(
            self,
            "product_domain",
            _normalize_enum_option(ProductDomain, self.product_domain, ProductDomain.UNKNOWN),
        )

        object.__setattr__(
            self,
            "reporter_ref_hash",
            _clean_text(self.reporter_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(
            self,
            "subject_ref_hashes",
            tuple(
                sorted(
                    {
                        _clean_text(item, MAX_HASH_LENGTH).lower()
                        for item in (self.subject_ref_hashes or ())
                        if _clean_text(item, MAX_HASH_LENGTH)
                    }
                )
            )[:MAX_LINKAGE_ACCOUNTS],
        )
        object.__setattr__(
            self,
            "related_account_ref_hashes",
            tuple(
                sorted(
                    {
                        _clean_text(item, MAX_HASH_LENGTH).lower()
                        for item in (self.related_account_ref_hashes or ())
                        if _clean_text(item, MAX_HASH_LENGTH)
                    }
                )
            )[:MAX_LINKAGE_ACCOUNTS],
        )

        object.__setattr__(self, "received_month", _clean_text(self.received_month, 7) or None)

        if self.received_weekday is None:
            object.__setattr__(self, "received_weekday", None)
        else:
            parsed_weekday = _as_int(self.received_weekday, -1)
            object.__setattr__(
                self,
                "received_weekday",
                parsed_weekday if 0 <= parsed_weekday <= 6 else None,
            )

        object.__setattr__(self, "received_hour_bucket", _clean_text(self.received_hour_bucket, 8) or None)
        object.__setattr__(
            self,
            "months_since_received",
            max(0, _as_int(self.months_since_received, 0))
            if self.months_since_received is not None
            else None,
        )

        object.__setattr__(self, "occurred_month", _clean_text(self.occurred_month, 7) or None)

        if self.occurred_weekday is None:
            object.__setattr__(self, "occurred_weekday", None)
        else:
            parsed_weekday = _as_int(self.occurred_weekday, -1)
            object.__setattr__(
                self,
                "occurred_weekday",
                parsed_weekday if 0 <= parsed_weekday <= 6 else None,
            )

        object.__setattr__(self, "occurred_hour_bucket", _clean_text(self.occurred_hour_bucket, 8) or None)
        object.__setattr__(self, "resolved_month", _clean_text(self.resolved_month, 7) or None)

        currency_text = _clean_text(self.currency, 16).upper()
        object.__setattr__(self, "currency", currency_text or None)

        object.__setattr__(self, "amount_bucket", _normalize_token(self.amount_bucket) or "unknown")
        object.__setattr__(self, "amount_ordinal", max(-1, min(6, _as_int(self.amount_ordinal, -1))))
        object.__setattr__(self, "amount_score", _round6(_clip_float(self.amount_score, 0.0, 1.0, 0.0)))
        object.__setattr__(
            self,
            "narrative_structure",
            MappingProxyType(_normalize_narrative_structure(self.narrative_structure)),
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
            "complaint_ref_hash": self.complaint_ref_hash,
            "category": _enum_value(self.category, ComplaintCategory.UNKNOWN.value),
            "status": _enum_value(self.status, ComplaintStatus.UNKNOWN.value),
            "severity": _enum_value(self.severity, ComplaintSeverity.UNKNOWN.value),
            "channel": _enum_value(self.channel, ComplaintChannel.UNKNOWN.value),
            "product_domain": _enum_value(self.product_domain, ProductDomain.UNKNOWN.value),
            "reporter_ref_hash": self.reporter_ref_hash,
            "subject_ref_hashes": list(self.subject_ref_hashes),
            "related_account_ref_hashes": list(self.related_account_ref_hashes),
            "received_month": self.received_month,
            "received_weekday": self.received_weekday,
            "received_hour_bucket": self.received_hour_bucket,
            "months_since_received": self.months_since_received,
            "occurred_month": self.occurred_month,
            "occurred_weekday": self.occurred_weekday,
            "occurred_hour_bucket": self.occurred_hour_bucket,
            "resolved_month": self.resolved_month,
            "currency": self.currency,
            "amount_bucket": self.amount_bucket,
            "amount_ordinal": int(self.amount_ordinal),
            "amount_score": float(self.amount_score),
            "narrative_structure": dict(self.narrative_structure),
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
            "caveats": list(COMPLAINT_CAVEATS),
            "safety_flags": dict(COMPLAINT_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class ComplaintsResult:
    """
    Safe bounded complaints service result.
    """

    ok: bool = True
    status: ServiceStatus | str = ServiceStatus.PASSED
    request_id: str = ""
    generated_at: datetime = dataclass_field(default_factory=_now_utc)
    duration_ms: int = 0
    profiles: tuple[ComplaintProfile, ...] = ()
    counts: Mapping[str, int] = dataclass_field(default_factory=dict)
    issues: tuple[ComplaintIssue, ...] = ()
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
                        "version": COMPLAINTS_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, ServiceStatus.PASSED.value),
                        "request_id": self.request_id,
                        "profile_count": len(self.profiles),
                        "profile_hashes": [
                            profile.complaint_ref_hash for profile in self.profiles[:64]
                        ],
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
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(COMPLAINT_CAVEATS),
            "safety_flags": dict(COMPLAINT_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Process-local complaint registry
# -----------------------------------------------------------------------------


class ComplaintRegistry:
    """
    Bounded process-local complaint profile registry.

    This registry is non-durable and intended for local prototype workflows,
    tests, developer tooling, and offline evaluation harnesses only.
    """

    def __init__(self, max_profiles: int = DEFAULT_MAX_PROFILES) -> None:
        self.max_profiles = max(1, int(max_profiles))
        self._profiles: dict[str, ComplaintProfile] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def register_profile(self, profile: ComplaintProfile) -> str:
        profile_hash = _clean_text(profile.complaint_ref_hash, MAX_HASH_LENGTH).lower()

        if not profile_hash:
            return ""

        with self._lock:
            if profile_hash in self._profiles:
                self._profiles[profile_hash] = profile

                if profile_hash in self._order:
                    self._order.remove(profile_hash)

                self._order.append(profile_hash)
                return profile_hash

            if len(self._order) >= self.max_profiles:
                evicted = self._order.pop(0)
                self._profiles.pop(evicted, None)

            self._profiles[profile_hash] = profile
            self._order.append(profile_hash)
            return profile_hash

    def get_profile(self, complaint_ref_hash: Any) -> Optional[ComplaintProfile]:
        key = _clean_text(complaint_ref_hash, MAX_HASH_LENGTH).lower()

        with self._lock:
            return self._profiles.get(key)

    def list_profiles(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> tuple[ComplaintProfile, ...]:
        count = max(0, int(limit))

        with self._lock:
            if count == 0:
                return ()

            return tuple(
                self._profiles[profile_hash]
                for profile_hash in self._order[:count]
                if profile_hash in self._profiles
            )

    def search_profiles(
        self,
        *,
        category: Any = None,
        status: Any = None,
        severity: Any = None,
        channel: Any = None,
        product_domain: Any = None
        ,
        amount_bucket: Any = None,
        min_priority: Optional[float] = None,
        max_priority: Optional[float] = None,
        limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    ) -> tuple[ComplaintProfile, ...]:
        normalized_category = (
            _normalize_enum_option(ComplaintCategory, category, None)
            if category is not None
            else None
        )
        normalized_status = (
            _normalize_enum_option(ComplaintStatus, status, None)
            if status is not None
            else None
        )
        normalized_severity = (
            _normalize_enum_option(ComplaintSeverity, severity, None)
            if severity is not None
            else None
        )
        normalized_channel = (
            _normalize_enum_option(ComplaintChannel, channel, None)
            if channel is not None
            else None
        )
        normalized_product = (
            _normalize_enum_option(ProductDomain, product_domain, None)
            if product_domain is not None
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

        filtered: list[ComplaintProfile] = []

        for profile in candidates:
            if normalized_category is not None and profile.category != normalized_category:
                continue

            if normalized_status is not None and profile.status != normalized_status:
                continue

            if normalized_severity is not None and profile.severity != normalized_severity:
                continue

            if normalized_channel is not None and profile.channel != normalized_channel:
                continue

            if normalized_product is not None and profile.product_domain != normalized_product:
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
                profile.complaint_ref_hash,
            )
        )

        return tuple(filtered[:count])

    def summarize_profiles(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> list[dict[str, Any]]:
        return [profile.to_dict() for profile in self.list_profiles(limit=limit)]

    def clear(self) -> None:
        with self._lock:
            self._profiles.clear()
            self._order.clear()

    def safe_summary(self, *, limit: int = DEFAULT_MAX_SUMMARY_ITEMS) -> dict[str, Any]:
        with self._lock:
            category_counter = Counter(
                _enum_value(profile.category, ComplaintCategory.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            status_counter = Counter(
                _enum_value(profile.status, ComplaintStatus.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            severity_counter = Counter(
                _enum_value(profile.severity, ComplaintSeverity.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            channel_counter = Counter(
                _enum_value(profile.channel, ComplaintChannel.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            product_counter = Counter(
                _enum_value(profile.product_domain, ProductDomain.UNKNOWN.value)
                for profile in self._profiles.values()
            )
            amount_counter = Counter(profile.amount_bucket for profile in self._profiles.values())
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
            "by_category": dict(category_counter),
            "by_status": dict(status_counter),
            "by_severity": dict(severity_counter),
            "by_channel": dict(channel_counter),
            "by_product_domain": dict(product_counter),
            "by_amount_bucket": dict(amount_counter),
            "by_priority_tier": dict(tier_counter),
            "recent_profiles": self.summarize_profiles(limit=limit),
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "raw_monetary_values_retained": False,
            "raw_timestamps_retained": False,
        }


_default_registry: Optional[ComplaintRegistry] = None
_default_registry_lock = threading.Lock()


def get_complaint_registry(
    max_profiles: int | None = None,
    *,
    rebuild: bool = False,
) -> ComplaintRegistry:
    """
    Return a process-wide bounded complaint registry.
    """
    global _default_registry

    with _default_registry_lock:
        if _default_registry is None or rebuild:
            _default_registry = ComplaintRegistry(
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


def _normalize_complaint_category(value: Any) -> ComplaintCategory:
    token = _normalize_token(value)

    if not token:
        return ComplaintCategory.UNKNOWN

    mapped = COMPLAINT_CATEGORY_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(ComplaintCategory, mapped, ComplaintCategory.UNKNOWN)

    return _normalize_enum_option(ComplaintCategory, token, ComplaintCategory.UNKNOWN)


def _normalize_complaint_status(
    value: Any,
    issues: list[ComplaintIssue],
    options: ComplaintsServiceOptions,
    context: Mapping[str, Any],
) -> ComplaintStatus:
    text = _clean_text(value, 200)
    token = _normalize_token(text)

    if not token:
        return ComplaintStatus.UNKNOWN

    if any(prohibited in token for prohibited in PROHIBITED_ACTION_TOKENS):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="unsupported_complaint_status_normalized_to_unknown",
            message="Complaint status contained adverse-action language and was normalized to unknown for safety.",
            field="status",
            details=dict(context),
        )
        return ComplaintStatus.UNKNOWN

    mapped = COMPLAINT_STATUS_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(ComplaintStatus, mapped, ComplaintStatus.UNKNOWN)

    return _normalize_enum_option(ComplaintStatus, token, ComplaintStatus.UNKNOWN)


def _normalize_complaint_severity(value: Any) -> ComplaintSeverity:
    token = _normalize_token(value)

    if not token:
        return ComplaintSeverity.UNKNOWN

    mapped = COMPLAINT_SEVERITY_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(ComplaintSeverity, mapped, ComplaintSeverity.UNKNOWN)

    return _normalize_enum_option(ComplaintSeverity, token, ComplaintSeverity.UNKNOWN)


def _normalize_complaint_channel(value: Any) -> ComplaintChannel:
    token = _normalize_token(value)

    if not token:
        return ComplaintChannel.UNKNOWN

    mapped = COMPLAINT_CHANNEL_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(ComplaintChannel, mapped, ComplaintChannel.UNKNOWN)

    return _normalize_enum_option(ComplaintChannel, token, ComplaintChannel.UNKNOWN)


def _normalize_product_domain(value: Any) -> ProductDomain:
    token = _normalize_token(value)

    if not token:
        return ProductDomain.UNKNOWN

    mapped = PRODUCT_DOMAIN_MAP.get(token)

    if mapped is not None:
        return _normalize_enum_option(ProductDomain, mapped, ProductDomain.UNKNOWN)

    return _normalize_enum_option(ProductDomain, token, ProductDomain.UNKNOWN)


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, ComplaintsResult):
        return []

    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "complaints", "reports", "cases", "examples"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])

        return [data]

    for attr in ("complaints", "reports", "cases", "records", "rows", "items"):
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
        for key in ("records", "rows", "items", "complaints", "reports", "cases", "examples"):
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

    for attr in ("complaints", "reports", "cases", "records", "rows", "items"):
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


def _synthesize_complaint_ref_hash(
    base: Mapping[str, Any],
    index: int,
    options: ComplaintsServiceOptions,
) -> str:
    payload = {
        "version": COMPLAINTS_VERSION,
        "namespace": _normalize_token(options.namespace) or _DEFAULT_NAMESPACE,
        "reporter": base.get("reporter_ref_hash") or "",
        "subjects": list(base.get("subject_ref_hashes") or ()),
        "category": base.get("category") or "",
        "status": base.get("status") or "",
        "severity": base.get("severity") or "",
        "channel": base.get("channel") or "",
        "product_domain": base.get("product_domain") or "",
        "received_month": base.get("received_month") or "",
        "occurred_month": base.get("occurred_month") or "",
        "currency": base.get("currency") or "",
        "amount_bucket": base.get("amount_bucket") or "unknown",
        "index": int(index),
    }

    return _fingerprint_payload(payload)[:40]


def _sanitize_complaint(
    record: Any,
    options: ComplaintsServiceOptions,
    issues: list[ComplaintIssue],
    index: int,
    start_time: float,
    now: datetime,
) -> Optional[dict[str, Any]]:
    if _time_exceeded(start_time, options.max_time_ms):
        return None

    context = {"record_type": "complaint", "index": index}
    view = _extract_view(record, _ALL_COMPLAINT_VIEW_KEYS)

    clean: dict[str, Any] = {}
    narrative_texts: list[str] = []

    for raw_key in sorted(view):
        raw_value = view[raw_key]
        canonical = _canonical_field_name(raw_key)

        if not canonical or canonical in NON_FEATURE_KEYS:
            continue

        if _is_narrative_key(canonical):
            if options.allow_narrative_features:
                text = _coerce_narrative_text(raw_value, int(options.max_narrative_length))

                if text:
                    narrative_texts.append(text)
            else:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.INFO,
                    code="narrative_field_dropped",
                    message="Narrative field omitted because narrative feature extraction is disabled.",
                    field=canonical,
                    details=dict(context),
                )
            continue

        if _is_forbidden_key(canonical) or _is_label_leakage_key(canonical):
            if options.drop_forbidden_fields:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="forbidden_complaint_field_dropped",
                    message="Forbidden or leakage-prone complaint field omitted.",
                    field=canonical,
                    details=dict(context),
                )
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_complaint_field",
                message="Forbidden or leakage-prone complaint field rejected.",
                field=canonical,
                details=dict(context),
            )
            return None

        clean[canonical] = raw_value

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
            code="prohibited_complaint_metadata",
            message="Complaint record contains prohibited adverse-action language.",
            details=context,
        )
        return None

    complaint_raw = _pick(clean, COMPLAINT_REF_KEYS)

    if complaint_raw is None:
        complaint_raw = _pick(clean, RAW_COMPLAINT_KEYS)

    complaint_hash = _complaint_ref_hash(complaint_raw, options) if complaint_raw is not None else None

    reporter_raw = _pick(clean, REPORTER_KEYS)
    reporter_hash = _account_ref_hash(reporter_raw, options) if reporter_raw is not None else None

    if reporter_raw is not None and not reporter_hash:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="unreadable_reporter_reference",
            message="Reporter reference could not be converted to a pseudonymous account hash.",
            field="reporter_account_id",
            details=context,
        )

    subject_hashes: set[str] = set()

    for key in SUBJECT_ACCOUNT_KEYS:
        if key not in clean:
            continue

        hashed = _account_ref_hash(clean[key], options)

        if hashed:
            subject_hashes.add(hashed)
        else:
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="unreadable_subject_reference",
                message="Subject account reference could not be converted to a pseudonymous account hash.",
                field=key,
                details=context,
            )

    if reporter_hash:
        subject_hashes.discard(reporter_hash)

    category = _normalize_complaint_category(_pick(clean, CATEGORY_KEYS))
    status = _normalize_complaint_status(_pick(clean, STATUS_KEYS), issues, options, context)
    severity = _normalize_complaint_severity(_pick(clean, SEVERITY_KEYS))
    channel = _normalize_complaint_channel(_pick(clean, CHANNEL_KEYS))
    product_domain = _normalize_product_domain(_pick(clean, PRODUCT_KEYS))

    received_month, received_weekday, received_hour_bucket, months_since_received = _timestamp_parts(
        _pick(clean, RECEIVED_KEYS),
        now=now,
        compute_age=True,
    )

    occurred_month, occurred_weekday, occurred_hour_bucket, _ = _timestamp_parts(
        _pick(clean, OCCURRED_KEYS),
        now=now,
        compute_age=False,
    )

    resolved_month, _, _, _ = _timestamp_parts(
        _pick(clean, RESOLVED_KEYS),
        now=now,
        compute_age=False,
    )

    amount = _parse_decimal_abs(_pick(clean, AMOUNT_KEYS))
    currency = _normalize_currency(_pick(clean, CURRENCY_KEYS))

    if amount is not None and currency is None:
        currency = "UNKNOWN"

    amount_bucket, amount_ordinal, amount_score = _amount_bucket(amount)
    narrative_structure = _narrative_features_from_texts(narrative_texts, options)

    related_accounts = set(subject_hashes)

    if reporter_hash:
        related_accounts.add(reporter_hash)

    base = {
        "complaint_ref_hash": complaint_hash or "",
        "category": _enum_value(category, ComplaintCategory.UNKNOWN.value),
        "status": _enum_value(status, ComplaintStatus.UNKNOWN.value),
        "severity": _enum_value(severity, ComplaintSeverity.UNKNOWN.value),
        "channel": _enum_value(channel, ComplaintChannel.UNKNOWN.value),
        "product_domain": _enum_value(product_domain, ProductDomain.UNKNOWN.value),
        "reporter_ref_hash": reporter_hash,
        "subject_ref_hashes": tuple(sorted(subject_hashes))[:MAX_LINKAGE_ACCOUNTS],
        "related_account_ref_hashes": tuple(sorted(related_accounts))[:MAX_LINKAGE_ACCOUNTS],
        "received_month": received_month,
        "received_weekday": received_weekday,
        "received_hour_bucket": received_hour_bucket,
        "months_since_received": months_since_received,
        "occurred_month": occurred_month,
        "occurred_weekday": occurred_weekday,
        "occurred_hour_bucket": occurred_hour_bucket,
        "resolved_month": resolved_month,
        "currency": currency,
        "amount_bucket": amount_bucket,
        "amount_ordinal": amount_ordinal,
        "amount_score": amount_score,
        "narrative_structure": narrative_structure,
        "source_indices": [index],
        "metadata": {
            "raw_identifiers_retained": False,
            "raw_narratives_retained": False,
            "raw_monetary_values_retained": False,
            "raw_timestamps_retained": False,
            "labels_used_as_features": False,
            "cross_currency_blending_performed": False,
            "narrative_features_enabled": bool(options.allow_narrative_features),
        },
    }

    if not base["complaint_ref_hash"]:
        base["complaint_ref_hash"] = _synthesize_complaint_ref_hash(base, index, options)

    return base


def _merge_complaint_base(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    for key in (
        "category",
        "status",
        "severity",
        "channel",
        "product_domain",
        "reporter_ref_hash",
        "currency",
        "amount_bucket",
        "received_month",
        "received_weekday",
        "received_hour_bucket",
        "occurred_month",
        "occurred_weekday",
        "occurred_hour_bucket",
        "resolved_month",
    ):
        existing[key] = _prefer_value(existing.get(key), incoming.get(key))

    existing_subjects = set(existing.get("subject_ref_hashes") or ())
    existing_subjects.update(incoming.get("subject_ref_hashes") or ())
    existing["subject_ref_hashes"] = tuple(sorted(existing_subjects))[:MAX_LINKAGE_ACCOUNTS]

    existing_related = set(existing.get("related_account_ref_hashes") or ())
    existing_related.update(incoming.get("related_account_ref_hashes") or ())
    existing["related_account_ref_hashes"] = tuple(sorted(existing_related))[:MAX_LINKAGE_ACCOUNTS]

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

    existing_months = existing.get("months_since_received")
    incoming_months = incoming.get("months_since_received")

    if incoming_months is not None:
        if existing_months is None or _as_int(incoming_months, 0) > _as_int(existing_months, 0):
            existing["months_since_received"] = max(0, _as_int(incoming_months, 0))

    existing["narrative_structure"] = _merge_narrative_features(
        existing.get("narrative_structure") or {},
        incoming.get("narrative_structure") or {},
    )

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


def _severity_score(severity: Any) -> float:
    normalized = _normalize_enum_option(ComplaintSeverity, severity, ComplaintSeverity.UNKNOWN)

    if normalized == ComplaintSeverity.CRITICAL:
        return 0.95

    if normalized == ComplaintSeverity.HIGH:
        return 0.75

    if normalized == ComplaintSeverity.MODERATE:
        return 0.50

    if normalized == ComplaintSeverity.LOW:
        return 0.25

    if normalized == ComplaintSeverity.INFO:
        return 0.10

    return 0.0


def _status_score(status: Any) -> float:
    normalized = _normalize_enum_option(ComplaintStatus, status, ComplaintStatus.UNKNOWN)

    if normalized == ComplaintStatus.ESCALATED:
        return 0.80

    if normalized in {
        ComplaintStatus.NEW,
        ComplaintStatus.OPEN,
        ComplaintStatus.IN_PROGRESS,
        ComplaintStatus.PENDING,
    }:
        return 0.50

    if normalized in {ComplaintStatus.RESOLVED, ComplaintStatus.CLOSED}:
        return 0.10

    return 0.0


def _age_score(months: Optional[int]) -> float:
    if months is None:
        return 0.0

    safe_months = max(0, int(months))

    if safe_months <= 0:
        return 0.05

    if safe_months <= 1:
        return 0.15

    if safe_months <= 3:
        return 0.35

    if safe_months <= 6:
        return 0.55

    if safe_months <= 12:
        return 0.75

    return 0.90


def _linkage_score(related_count: int) -> float:
    return _round6(min(1.0, max(0, int(related_count)) / float(MAX_LINKAGE_ACCOUNTS)))


def _compute_complaint_priority(
    base: Mapping[str, Any],
    options: ComplaintsServiceOptions,
) -> tuple[float, PriorityTier, tuple[str, ...]]:
    if not options.include_priority:
        return 0.0, PriorityTier.UNSCORED, ("priority_disabled",)

    severity_score = _severity_score(base.get("severity"))
    amount_score = _clip_float(base.get("amount_score"), 0.0, 1.0, 0.0)
    temporal_score = _age_score(base.get("months_since_received"))
    narrative_score = _narrative_intensity_score(base.get("narrative_structure") or {})
    linkage_score = _linkage_score(len(base.get("related_account_ref_hashes") or ()))
    status_score = _status_score(base.get("status"))

    score = (
        severity_score * float(options.priority_severity_weight)
        + amount_score * float(options.priority_amount_weight)
        + temporal_score * float(options.priority_temporal_weight)
        + narrative_score * float(options.priority_narrative_weight)
        + linkage_score * float(options.priority_linkage_weight)
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
        "no_raw_narratives_used",
        "no_raw_monetary_values_used",
        "no_cross_currency_blending",
    ]

    if severity_score >= 0.75:
        reasons.append("high_or_critical_severity")

    if amount_score >= 0.70:
        reasons.append("high_amount_bucket")
    elif amount_score >= 0.45:
        reasons.append("moderate_amount_bucket")

    if temporal_score >= 0.55:
        reasons.append("aged_unresolved_complaint_bucket")

    if narrative_score >= 0.50:
        reasons.append("elevated_redacted_narrative_structure_signal")

    if linkage_score >= 0.50:
        reasons.append("multiple_related_account_references")

    if status_score >= 0.80:
        reasons.append("escalated_status_signal")
    elif status_score >= 0.50:
        reasons.append("open_or_pending_status_signal")

    if score >= float(options.elevated_threshold):
        reasons.append("high_investigative_priority")

    return score, tier, tuple(dict.fromkeys(reasons))


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------


class ComplaintsServiceEngine:
    """
    Bounded deterministic synthetic complaints service engine.
    """

    def __init__(
        self,
        options: ComplaintsServiceOptions | None = None,
        registry: ComplaintRegistry | None = None,
    ) -> None:
        self.options = options or ComplaintsServiceOptions.from_settings()
        self.registry = registry or get_complaint_registry(self.options.max_profiles)
        self._lock = threading.RLock()

    def normalize(self, request: Any) -> ComplaintsResult:
        """
        Run one bounded synthetic complaint profiling job.
        """
        opts = self.options
        issues: list[ComplaintIssue] = []
        start_time = time.monotonic()
        now = _now_utc()

        req = _coerce_request(request)
        source = req.complaints
        if source is None:
            source = req.reports
        if source is None:
            source = req.cases

        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": COMPLAINTS_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                    "counts": {
                        "complaints": _count_records_safe(source),
                    },
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: ServiceStatus,
            profiles: Sequence[ComplaintProfile] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> ComplaintsResult:
            resolved_counts: dict[str, int] = {
                "submitted_complaints": _count_records_safe(source),
                "sanitized_complaints": 0,
                "profiles": len(profiles),
                "registered_profiles": 0,
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update(
                    {str(key): max(0, _as_int(value, 0)) for key, value in counts.items()}
                )

            resolved_counts["profiles"] = len(profiles)
            resolved_counts["issues"] = len(issues)

            metadata = {
                "complaints_version": COMPLAINTS_VERSION,
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
                "narrative_features_enabled": bool(opts.allow_narrative_features),
                "priority_semantics": "investigative_human_review_triage_only",
                "caveats": list(COMPLAINT_CAVEATS),
                "safety_flags": dict(COMPLAINT_SAFETY_FLAGS),
            }

            return ComplaintsResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=now,
                duration_ms=_elapsed_ms(start_time),
                profiles=tuple(profiles),
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
                code="complaints_service_disabled",
                message="Complaints service is disabled.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Complaints service requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Complaints service is blocked in production-like environments.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_complaints_action_metadata",
                message="Complaints request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, ServiceStatus.BLOCKED)

        with self._lock:
            raw_complaints = _iter_records(source)[: opts.max_complaints]
            submitted = _count_records_safe(source)

            if submitted > int(opts.max_complaints):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="complaints_input_truncated",
                    message="Complaint input exceeded configured record limit and was truncated.",
                    details={
                        "submitted": submitted,
                        "max_complaints": int(opts.max_complaints),
                    },
                )

            bases: dict[str, dict[str, Any]] = {}
            sanitized = 0

            for index, record in enumerate(raw_complaints):
                if _time_exceeded(start_time, opts.max_time_ms):
                    _append_issue(
                        issues,
                        opts.max_issues,
                        severity=IssueSeverity.WARNING,
                        code="complaint_sanitization_time_budget_exhausted",
                        message="Complaint sanitization stopped after reaching configured time budget.",
                        details={
                            "processed": sanitized,
                            "remaining": max(0, len(raw_complaints) - index),
                        },
                    )
                    break

                base = _sanitize_complaint(record, opts, issues, index, start_time, now)

                if base is None:
                    continue

                complaint_hash = _clean_text(base.get("complaint_ref_hash"), MAX_HASH_LENGTH).lower()

                if not complaint_hash:
                    continue

                existing = bases.get(complaint_hash)

                if existing is None:
                    bases[complaint_hash] = base
                else:
                    _merge_complaint_base(existing, base)

                sanitized += 1

            if len(bases) > int(opts.max_profiles):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="complaint_profiles_truncated",
                    message="Complaint profiles exceeded configured limit and were truncated.",
                    details={
                        "generated": len(bases),
                        "max_profiles": int(opts.max_profiles),
                    },
                )
                retained_hashes = sorted(bases)[: int(opts.max_profiles)]
                bases = {complaint_hash: bases[complaint_hash] for complaint_hash in retained_hashes}

            profiles: list[ComplaintProfile] = []

            for complaint_hash in sorted(bases):
                base = bases[complaint_hash]
                priority_score, priority_tier, priority_reasons = _compute_complaint_priority(base, opts)

                profiles.append(
                    ComplaintProfile(
                        complaint_ref_hash=complaint_hash,
                        category=base.get("category", ComplaintCategory.UNKNOWN.value),
                        status=base.get("status", ComplaintStatus.UNKNOWN.value),
                        severity=base.get("severity", ComplaintSeverity.UNKNOWN.value),
                        channel=base.get("channel", ComplaintChannel.UNKNOWN.value),
                        product_domain=base.get("product_domain", ProductDomain.UNKNOWN.value),
                        reporter_ref_hash=base.get("reporter_ref_hash"),
                        subject_ref_hashes=base.get("subject_ref_hashes", ()),
                        related_account_ref_hashes=base.get("related_account_ref_hashes", ()),
                        received_month=base.get("received_month"),
                        received_weekday=base.get("received_weekday"),
                        received_hour_bucket=base.get("received_hour_bucket"),
                        months_since_received=base.get("months_since_received"),
                        occurred_month=base.get("occurred_month"),
                        occurred_weekday=base.get("occurred_weekday"),
                        occurred_hour_bucket=base.get("occurred_hour_bucket"),
                        resolved_month=base.get("resolved_month"),
                        currency=base.get("currency"),
                        amount_bucket=base.get("amount_bucket", "unknown"),
                        amount_ordinal=base.get("amount_ordinal", -1),
                        amount_score=base.get("amount_score", 0.0),
                        narrative_structure=base.get("narrative_structure", {}),
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
                    profile.complaint_ref_hash,
                )
            )

            if len(profiles) > int(opts.max_profiles):
                profiles = profiles[: int(opts.max_profiles)]

            registered_profiles = 0

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
                            code="complaint_profile_registration_failed",
                            message="Complaint profile registration failed.",
                            details={"exception_type": type(exc).__name__},
                        )

            category_counter = Counter(_enum_value(profile.category) for profile in profiles)
            status_counter = Counter(_enum_value(profile.status) for profile in profiles)
            severity_counter = Counter(_enum_value(profile.severity) for profile in profiles)
            channel_counter = Counter(_enum_value(profile.channel) for profile in profiles)
            product_counter = Counter(_enum_value(profile.product_domain) for profile in profiles)
            amount_counter = Counter(profile.amount_bucket for profile in profiles)
            currency_counter = Counter(profile.currency or "UNKNOWN" for profile in profiles)
            tier_counter = Counter(_enum_value(profile.priority_tier) for profile in profiles)

            counts = {
                "sanitized_complaints": sanitized,
                "registered_profiles": registered_profiles,
                "profiles_with_reporter": sum(1 for profile in profiles if profile.reporter_ref_hash),
                "profiles_with_subjects": sum(1 for profile in profiles if profile.subject_ref_hashes),
                "profiles_with_related_accounts": sum(
                    1 for profile in profiles if profile.related_account_ref_hashes
                ),
                "profiles_with_narrative_features": sum(
                    1 for profile in profiles if profile.narrative_structure.get("present")
                ),
                "profiles_with_amount": sum(
                    1 for profile in profiles if profile.amount_ordinal >= 0
                ),
                "category_fraud": category_counter.get(ComplaintCategory.FRAUD.value, 0),
                "category_unauthorized_transaction": category_counter.get(
                    ComplaintCategory.UNAUTHORIZED_TRANSACTION.value,
                    0,
                ),
                "category_account_takeover": category_counter.get(
                    ComplaintCategory.ACCOUNT_TAKEOVER.value,
                    0,
                ),
                "category_phishing": category_counter.get(ComplaintCategory.PHISHING.value, 0),
                "category_identity_theft": category_counter.get(
                    ComplaintCategory.IDENTITY_THEFT.value,
                    0,
                ),
                "category_payment_failure": category_counter.get(
                    ComplaintCategory.PAYMENT_FAILURE.value,
                    0,
                ),
                "category_dispute": category_counter.get(ComplaintCategory.DISPUTE.value, 0),
                "category_harassment": category_counter.get(ComplaintCategory.HARASSMENT.value, 0),
                "category_service_issue": category_counter.get(ComplaintCategory.SERVICE_ISSUE.value, 0),
                "category_other": category_counter.get(ComplaintCategory.OTHER.value, 0),
                "category_unknown": category_counter.get(ComplaintCategory.UNKNOWN.value, 0),
                "status_new": status_counter.get(ComplaintStatus.NEW.value, 0),
                "status_open": status_counter.get(ComplaintStatus.OPEN.value, 0),
                "status_in_progress": status_counter.get(ComplaintStatus.IN_PROGRESS.value, 0),
                "status_pending": status_counter.get(ComplaintStatus.PENDING.value, 0),
                "status_escalated": status_counter.get(ComplaintStatus.ESCALATED.value, 0),
                "status_resolved": status_counter.get(ComplaintStatus.RESOLVED.value, 0),
                "status_closed": status_counter.get(ComplaintStatus.CLOSED.value, 0),
                "status_unknown": status_counter.get(ComplaintStatus.UNKNOWN.value, 0),
                "severity_info": severity_counter.get(ComplaintSeverity.INFO.value, 0),
                "severity_low": severity_counter.get(ComplaintSeverity.LOW.value, 0),
                "severity_moderate": severity_counter.get(ComplaintSeverity.MODERATE.value, 0),
                "severity_high": severity_counter.get(ComplaintSeverity.HIGH.value, 0),
                "severity_critical": severity_counter.get(ComplaintSeverity.CRITICAL.value, 0),
                "severity_unknown": severity_counter.get(ComplaintSeverity.UNKNOWN.value, 0),
                "channel_web": channel_counter.get(ComplaintChannel.WEB.value, 0),
                "channel_mobile": channel_counter.get(ComplaintChannel.MOBILE.value, 0),
                "channel_api": channel_counter.get(ComplaintChannel.API.value, 0),
                "channel_email": channel_counter.get(ComplaintChannel.EMAIL.value, 0),
                "channel_phone": channel_counter.get(ComplaintChannel.PHONE.value, 0),
                "channel_chat": channel_counter.get(ComplaintChannel.CHAT.value, 0),
                "channel_social": channel_counter.get(ComplaintChannel.SOCIAL.value, 0),
                "channel_branch": channel_counter.get(ComplaintChannel.BRANCH.value, 0),
                "channel_mail": channel_counter.get(ComplaintChannel.MAIL.value, 0),
                "channel_other": channel_counter.get(ComplaintChannel.OTHER.value, 0),
                "channel_unknown": channel_counter.get(ComplaintChannel.UNKNOWN.value, 0),
                "product_payments": product_counter.get(ProductDomain.PAYMENTS.value, 0),
                "product_cards": product_counter.get(ProductDomain.CARDS.value, 0),
                "product_transfers": product_counter.get(ProductDomain.TRANSFERS.value, 0),
                "product_wallets": product_counter.get(ProductDomain.WALLETS.value, 0),
                "product_upi": product_counter.get(ProductDomain.UPI.value, 0),
                "product_netbanking": product_counter.get(ProductDomain.NETBANKING.value, 0),
                "product_loans": product_counter.get(ProductDomain.LOANS.value, 0),
                "product_deposits": product_counter.get(ProductDomain.DEPOSITS.value, 0),
                "product_markets": product_counter.get(ProductDomain.MARKETS.value, 0),
                "product_insurance": product_counter.get(ProductDomain.INSURANCE.value, 0),
                "product_other": product_counter.get(ProductDomain.OTHER.value, 0),
                "product_unknown": product_counter.get(ProductDomain.UNKNOWN.value, 0),
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
            }

            for currency, count in currency_counter.items():
                if currency and currency != "UNKNOWN":
                    counts[f"currency_{currency.lower()}"] = count

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
                counts=counts,
            )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "registry": self.registry.safe_summary(limit=self.options.max_summary_items),
            "caveats": list(COMPLAINT_CAVEATS),
            "safety_flags": dict(COMPLAINT_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default engine and public API
# -----------------------------------------------------------------------------


_default_engine: Optional[ComplaintsServiceEngine] = None
_default_engine_lock = threading.Lock()


def get_complaints_options(settings: Any | None = None) -> ComplaintsServiceOptions:
    """
    Return complaints service options from settings.
    """
    return ComplaintsServiceOptions.from_settings(settings)


def get_complaints_engine(
    options: ComplaintsServiceOptions | None = None,
    *,
    rebuild: bool = False,
) -> ComplaintsServiceEngine:
    """
    Return a process-wide complaints service engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            resolved_options = options or ComplaintsServiceOptions.from_settings()
            _default_engine = ComplaintsServiceEngine(
                options=resolved_options,
                registry=get_complaint_registry(resolved_options.max_profiles),
            )

        return _default_engine


def normalize_complaints(
    request: Any,
    options: ComplaintsServiceOptions | None = None,
    *,
    engine: ComplaintsServiceEngine | None = None,
) -> ComplaintsResult:
    """
    Normalize bounded synthetic complaint records into privacy-preserving
    redacted complaint profiles.
    """
    active_engine = engine or get_complaints_engine(options)
    return active_engine.normalize(request)


def get_complaint_profile(
    complaint_ref_hash: Any,
    *,
    registry: ComplaintRegistry | None = None,
) -> Optional[ComplaintProfile]:
    """
    Return one registered complaint profile by pseudonymous complaint hash.
    """
    active_registry = registry or get_complaint_registry()
    return active_registry.get_profile(complaint_ref_hash)


def list_complaint_profiles(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: ComplaintRegistry | None = None,
) -> tuple[ComplaintProfile, ...]:
    """
    Return registered complaint profiles.
    """
    active_registry = registry or get_complaint_registry()
    return active_registry.list_profiles(limit=limit)


def search_complaint_profiles(
    *,
    category: Any = None,
    status: Any = None,
    severity: Any = None,
    channel: Any = None,
    product_domain: Any = None,
    amount_bucket: Any = None,
    min_priority: Optional[float] = None,
    max_priority: Optional[float] = None,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    registry: ComplaintRegistry | None = None,
) -> tuple[ComplaintProfile, ...]:
    """
    Search registered complaint profiles using bounded safe filters.
    """
    active_registry = registry or get_complaint_registry()
    return active_registry.search_profiles(
        category=category,
        status=status,
        severity=severity,
        channel=channel,
        product_domain=product_domain,
        amount_bucket=amount_bucket,
        min_priority=min_priority,
        max_priority=max_priority,
        limit=limit,
    )


def export_complaints_summary(result: ComplaintsResult) -> dict[str, Any]:
    """
    Export a safe public complaints service summary.
    """
    return result.to_dict()


def clear_complaint_registry(*, registry: ComplaintRegistry | None = None) -> None:
    """
    Clear the process-local complaint registry.
    """
    active_registry = registry or get_complaint_registry()
    active_registry.clear()


def get_complaints_health(*, engine: ComplaintsServiceEngine | None = None) -> dict[str, Any]:
    """
    Return safe complaints service health.
    """
    active_engine = engine or get_complaints_engine()
    opts = active_engine.options
    registry_summary = active_engine.registry.safe_summary(limit=opts.max_summary_items)
    issues: list[ComplaintIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="complaints_service_disabled",
            message="Complaints service is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Complaints service requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Complaints service is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "registry": registry_summary,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(COMPLAINT_CAVEATS),
        "safety_flags": dict(COMPLAINT_SAFETY_FLAGS),
    }


def get_complaints_metadata(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
    engine: ComplaintsServiceEngine | None = None,
) -> dict[str, Any]:
    """
    Return safe, serializable complaints service metadata.

    This is useful for startup logs, diagnostic endpoints, tests, developer
    tooling, and architecture documentation checks.

    It must not expose raw identifiers, raw narratives, raw monetary values,
    raw timestamps, secrets, environment files, database URLs, tokens,
    passwords, ground-truth labels, scenario IDs, fraud-ring IDs, model artifact
    paths, filesystem paths, executable handler references, or real customer
    data.
    """
    active_engine = engine or get_complaints_engine()
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

    char_buckets = [
        {
            "upper": upper,
            "label": label,
            "score": _round6(float(score)),
        }
        for upper, label, score in CHAR_BUCKET_SPECS
    ]

    count_buckets = [
        {
            "upper": upper,
            "label": label,
            "score": _round6(float(score)),
        }
        for upper, label, score in COUNT_BUCKET_SPECS
    ]

    ratio_buckets = [
        {
            "upper": upper,
            "label": label,
            "score": _round6(float(score)),
        }
        for upper, label, score in RATIO_BUCKET_SPECS
    ]

    narrative_feature_keys = sorted(_empty_narrative_features().keys())

    return {
        "package": "muleguard.backend.services.complaints",
        "version": COMPLAINTS_VERSION,
        "complaint_categories": [category.value for category in ComplaintCategory],
        "complaint_statuses": [status.value for status in ComplaintStatus],
        "complaint_severities": [severity.value for severity in ComplaintSeverity],
        "complaint_channels": [channel.value for channel in ComplaintChannel],
        "product_domains": [domain.value for domain in ProductDomain],
        "priority_tiers": [tier.value for tier in PriorityTier],
        "service_statuses": [status.value for status in ServiceStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "amount_buckets": amount_buckets,
        "char_buckets": char_buckets,
        "count_buckets": count_buckets,
        "ratio_buckets": ratio_buckets,
        "category_map": dict(COMPLAINT_CATEGORY_MAP),
        "status_map": dict(COMPLAINT_STATUS_MAP),
        "severity_map": dict(COMPLAINT_SEVERITY_MAP),
        "channel_map": dict(COMPLAINT_CHANNEL_MAP),
        "product_domain_map": dict(PRODUCT_DOMAIN_MAP),
        "narrative_feature_keys": narrative_feature_keys,
        "credential_terms": list(CREDENTIAL_TERMS),
        "payment_terms": list(PAYMENT_TERMS),
        "urgency_terms": list(URGENCY_TERMS),
        "threat_terms": list(THREAT_TERMS),
        "default_options": options.safe_summary(),
        "registry": registry_summary,
        "hard_limits": {
            "max_complaints": HARD_MAX_COMPLAINTS,
            "max_profiles": HARD_MAX_PROFILES,
            "max_narrative_length": HARD_MAX_NARRATIVE_LENGTH,
            "max_narrative_chunks": HARD_MAX_NARRATIVE_CHUNKS,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
        },
        "forbidden_complaint_field_count": len(FORBIDDEN_COMPLAINT_FIELDS),
        "label_leakage_field_count": len(LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(PROHIBITED_ACTION_TOKENS),
        "summary_item_limit": max(1, int(limit)),
        "narrative_policy": "transient_redacted_structural_features_only_no_raw_retention",
        "monetary_policy": "bounded_amount_buckets_only_no_raw_values_no_cross_currency_blending",
        "temporal_policy": "bounded_month_weekday_hour_age_buckets_only_no_raw_timestamps",
        "caveats": list(COMPLAINT_CAVEATS),
        "safety_flags": dict(COMPLAINT_SAFETY_FLAGS),
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


def build_complaints_service_descriptor(
    options: ComplaintsServiceOptions | None = None,
    *,
    engine: ComplaintsServiceEngine | None = None,
) -> Any:
    """
    Build a bounded service descriptor for the complaints service.

    If the backend services registry descriptor is unavailable, this returns a
    safe plain dictionary representation instead of failing.
    """
    active_engine = engine or get_complaints_engine(options)

    def _handler(payload: Any) -> dict[str, Any]:
        return active_engine.normalize(payload).to_dict()

    def _health() -> dict[str, Any]:
        return get_complaints_health(engine=active_engine)

    if _RegistryServiceDescriptor is None:
        return {
            "service_id": "complaints",
            "kind": "general",
            "display_name": "Complaints Service",
            "description": "Bounded synthetic complaint normalization and redacted structural profiling service.",
            "version": COMPLAINTS_VERSION,
            "enabled": active_engine.options.enabled,
            "synthetic_required": active_engine.options.synthetic_required,
            "dataset_mode": active_engine.options.dataset_mode,
            "production_like": active_engine.options.production_like,
            "allow_in_production": active_engine.options.allow_in_production,
            "capabilities": [
                "complaints",
                "profiling",
                "privacy",
                "redaction",
                "synthetic_only",
                "no_raw_narratives",
                "no_raw_monetary_values",
                "no_raw_timestamps",
            ],
            "handler_registered": True,
            "health_handler_registered": True,
            "raw_values_retained": False,
            "executable_handler_exposed": False,
            "caveats": list(COMPLAINT_CAVEATS),
            "safety_flags": dict(COMPLAINT_SAFETY_FLAGS),
        }

    kind = getattr(_RegistryServiceKind, "GENERAL", "general") if _RegistryServiceKind else "general"

    return _RegistryServiceDescriptor(
        service_id="complaints",
        kind=kind,
        display_name="Complaints Service",
        description=(
            "Bounded synthetic complaint normalization, redacted structural profiling, "
            "linkage summarization, and investigative priority service."
        ),
        version=COMPLAINTS_VERSION,
        enabled=active_engine.options.enabled,
        synthetic_required=active_engine.options.synthetic_required,
        dataset_mode=active_engine.options.dataset_mode,
        production_like=active_engine.options.production_like,
        allow_in_production=active_engine.options.allow_in_production,
        capabilities=(
            "complaints",
            "profiling",
            "privacy",
            "redaction",
            "synthetic_only",
            "no_automatic_adverse_action",
            "no_raw_narratives",
            "no_raw_monetary_values",
            "no_raw_timestamps",
        ),
        handler=_handler,
        health_handler=_health,
        metadata={
            "service_module": "app.services.complaints",
            "registry_backend": "process_local_in_memory",
            "raw_values_retained": False,
            "raw_narratives_retained": False,
            "raw_monetary_values_retained": False,
            "raw_timestamps_retained": False,
            "cross_currency_blending_performed": False,
            "narrative_features_enabled": bool(active_engine.options.allow_narrative_features),
        },
    )


def register_complaints_service(
    options: ComplaintsServiceOptions | None = None,
    *,
    engine: ComplaintsServiceEngine | None = None,
    registry: Any | None = None,
    replace: bool = True,
) -> Optional[str]:
    """
    Register the complaints service descriptor with the backend services
    registry when available.
    """
    if _get_registry_service_registry is None:
        return None

    active_registry = registry or _get_registry_service_registry()
    descriptor = build_complaints_service_descriptor(options=options, engine=engine)

    try:
        return active_registry.register(descriptor, replace=replace)
    except Exception:
        return None


__all__ = [
    "COMPLAINTS_VERSION",
    "ComplaintCategory",
    "ComplaintChannel",
    "ComplaintIssue",
    "ComplaintProfile",
    "ComplaintRegistry",
    "ComplaintSeverity",
    "ComplaintStatus",
    "ComplaintsRequest",
    "ComplaintsResult",
    "ComplaintsServiceEngine",
    "ComplaintsServiceOptions",
    "IssueSeverity",
    "PriorityTier",
    "ProductDomain",
    "ServiceStatus",
    "build_complaints_service_descriptor",
    "clear_complaint_registry",
    "export_complaints_summary",
    "get_complaint_profile",
    "get_complaint_registry",
    "get_complaints_engine",
    "get_complaints_health",
    "get_complaints_metadata",
    "get_complaints_options",
    "list_complaint_profiles",
    "normalize_complaints",
    "register_complaints_service",
    "search_complaint_profiles",
]