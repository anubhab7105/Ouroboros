"""
MULEGUARD backend correlation exact reference matching.

This module provides the canonical bounded exact-reference correlation layer
for the synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- detect exact reference matches between synthetic complaints, transactions,
  alerts, and cases using shared pseudonymous reference hashes;
- enforce strict privacy by hashing raw reference identifiers (e.g.,
  transaction references, case IDs) using a shared, salted, one-way domain
  before matching, ensuring raw identifiers are never retained or compared;
- provide bounded, deterministic, API-safe correlation results with candidate
  scores, operational reasons, safe summaries, issue reporting, fingerprints,
  and metadata;
- reject leakage-prone inputs such as ground-truth labels, injected scenario
  IDs, fraud-ring IDs, raw complaint narratives, raw identifiers, secrets,
  tokens, passwords, database URLs, filesystem paths, and model artifact paths;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module correlates records by exact reference only. It does not train
models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for correlation.
- Exact reference matches are investigative leads only. They are not proof of
  wrongdoing, common control, or criminal association.
- Raw reference identifiers are never retained. They are hashed using a shared,
  salted, one-way domain before matching.
- Labels must never be used as correlation features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected.
- Raw complaint narratives are forbidden inputs.
- Correlation handling must never trigger automatic adverse customer action.
- Undefined or unavailable matches are reported honestly as unavailable.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external correlation engines.
- This module does not deploy, promote, retire, or serve production models.
- This module does not generate synthetic ingestion records.
- This module is not a durable decisioning platform.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, correlation
candidates, normalized records, explanations, validation reports, and case
dispositions are investigative leads or human workflow artefacts only. They are
not proof of wrongdoing and must not trigger automatic adverse customer action.
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
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional


# -----------------------------------------------------------------------------
# Time helpers
# -----------------------------------------------------------------------------
# Defined here, above their first use, because the dataclasses below reference
# `_now_utc` as a `default_factory`, which is evaluated when the class body
# runs. Defined further down the module, the name does not exist yet and the
# import fails with a NameError.


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)

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


logger = logging.getLogger("muleguard.backend.correlation.exact_reference")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

EXACT_REFERENCE_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.correlation.exact_reference.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"

DEFAULT_MAX_RECORDS: Final[int] = 10_000
HARD_MAX_RECORDS: Final[int] = 100_000

DEFAULT_MAX_CANDIDATES: Final[int] = 500
HARD_MAX_CANDIDATES: Final[int] = 10_000

DEFAULT_MAX_OCCURRENCES: Final[int] = 50_000
HARD_MAX_OCCURRENCES: Final[int] = 500_000

DEFAULT_MAX_BUCKET_SIZE: Final[int] = 128
HARD_MAX_BUCKET_SIZE: Final[int] = 2_000

DEFAULT_MAX_REFERENCES_PER_RECORD: Final[int] = 8
HARD_MAX_REFERENCES_PER_RECORD: Final[int] = 64

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

DEFAULT_MAX_TIME_MS: Final[int] = 30_000
HARD_MAX_TIME_MS: Final[int] = 300_000

DEFAULT_MIN_REFERENCE_LENGTH: Final[int] = 4
HARD_MIN_REFERENCE_LENGTH: Final[int] = 1
HARD_MAX_REFERENCE_LENGTH: Final[int] = 512

DEFAULT_MAX_REFERENCE_LENGTH: Final[int] = 256

DEFAULT_TEMPORAL_TOLERANCE_SECONDS: Final[int] = 86_400
HARD_MAX_TEMPORAL_TOLERANCE_SECONDS: Final[int] = 2_592_000

MAX_TEXT_LENGTH: Final[int] = 512
MAX_HASH_LENGTH: Final[int] = 256

CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")
CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")

# Reference tokens must be opaque identifiers, never narratives, credentials,
# connection strings, or assignment expressions.
REFERENCE_UNSAFE_RE: Final[re.Pattern[str]] = re.compile(r"[@=:]")

_MISSING: Final[object] = object()

SUBJECT_KEYS: Final[tuple[str, ...]] = (
    "subject_ref_hash",
    "subject_hash",
    "subject",
    "account_id",
    "acct_id",
    "id",
    "complaint_id",
    "transaction_id",
    "entity_id",
    "alert_id",
    "case_id",
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

FORBIDDEN_FIELDS: Final[frozenset[str]] = frozenset(
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

FORBIDDEN_TOKENS: Final[tuple[str, ...]] = (
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

EXACT_REFERENCE_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic exact reference correlation only. Do not use with real customer data.",
    "Exact reference matches are investigative leads only and are not proof of wrongdoing.",
    "Raw reference identifiers are never retained. They are hashed using a shared, salted, one-way domain.",
    "Confidence describes reference equality only. It is not a probability of guilt.",
    "Correlation must not trigger automatic adverse customer action.",
    "Labels must never be used as correlation features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "Raw complaint narratives and raw identifiers are forbidden retained inputs.",
    "Currency amounts are never converted or blended across currencies.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

EXACT_REFERENCE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_raw_reference_identifiers_retained": True,
        "shared_salted_one_way_reference_hashes": True,
        "salted_pseudonymous_subject_hashes": True,
        "no_labels_as_features": True,
        "no_raw_values_in_public_summaries": True,
        "no_ground_truth_fields_accepted": True,
        "no_fraud_label_fields_accepted": True,
        "no_scenario_ids_accepted": True,
        "no_fraud_ring_ids_accepted": True,
        "no_raw_narratives_accepted": True,
        "no_secrets_accepted": True,
        "no_tokens_accepted": True,
        "no_passwords_accepted": True,
        "no_database_urls_accepted": True,
        "no_model_artifact_paths_accepted": True,
        "deterministic_exact_reference_matching": True,
        "bounded_exact_reference_matching_required": True,
        "no_cross_currency_blending": True,
        "confidence_is_reference_equality_only": True,
        "scores_are_investigative_priority_only": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)

CATEGORY_ORDER: Final[tuple[str, ...]] = ("complaint", "transaction", "alert", "case")

_CATEGORY_ORDER_INDEX: Final[Mapping[str, int]] = MappingProxyType(
    {category: position for position, category in enumerate(CATEGORY_ORDER)}
)

# Canonical reference field -> reference kind token.
# The same kind token shares the same hashing domain across categories, so a
# complaint's `transaction_reference` and a transaction's `reference` collide
# exactly when their canonical raw tokens are equal, without retaining either.
REFERENCE_FIELD_KINDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "reference": "transaction",
        "transaction_reference": "transaction",
        "case_reference": "case",
        "alert_reference": "alert",
        "entity_reference": "entity",
        "account_reference": "account",
        "generic_reference": "generic",
    }
)

CATEGORY_REFERENCE_FIELDS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "complaint": ("transaction_reference", "reference"),
        "transaction": ("reference", "transaction_reference"),
        "alert": ("reference", "transaction_reference", "case_reference", "alert_reference"),
        "case": ("reference", "case_reference", "transaction_reference"),
    }
)

REFERENCE_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ref": "reference",
        "reference_id": "reference",
        "txn_reference": "transaction_reference",
        "transaction_ref": "transaction_reference",
        "txn_ref": "transaction_reference",
        "case_ref": "case_reference",
        "alert_ref": "alert_reference",
        "entity_ref": "entity_reference",
        "account_ref": "account_reference",
    }
)

ACCOUNT_REFERENCE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "account_id",
        "acct_id",
        "victim_account_id",
        "suspected_account_id",
        "sender_account_id",
        "receiver_account_id",
    }
)

TIMESTAMP_PRIORITY: Final[tuple[str, ...]] = (
    "reported_at",
    "occurred_at",
    "triggered_at",
    "opened_at",
    "created_at",
    "timestamp",
    "time",
    "date",
)

CATEGORY_ALLOWED_FIELDS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "complaint": frozenset(
            {
                "transaction_reference",
                "reference",
                "reported_at",
                "occurred_at",
                "victim_account_id",
                "suspected_account_id",
                "amount",
                "currency",
            }
        ),
        "transaction": frozenset(
            {
                "reference",
                "transaction_reference",
                "occurred_at",
                "sender_account_id",
                "receiver_account_id",
                "amount",
                "currency",
            }
        ),
        "alert": frozenset(
            {
                "reference",
                "transaction_reference",
                "case_reference",
                "alert_reference",
                "triggered_at",
                "account_id",
            }
        ),
        "case": frozenset(
            {
                "reference",
                "case_reference",
                "transaction_reference",
                "opened_at",
                "account_id",
            }
        ),
    }
)

_ALL_VIEW_FIELDS: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            *SUBJECT_KEYS,
            *REFERENCE_FIELD_KINDS,
            *REFERENCE_ALIASES,
            *ACCOUNT_REFERENCE_FIELDS,
            *TIMESTAMP_PRIORITY,
            "amount",
            "currency",
        }
    )
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class ReferenceKind(str, Enum):
    """
    Bounded reference domain.

    Reference kinds sharing a kind token share a hashing domain.
    """

    TRANSACTION = "transaction"
    CASE = "case"
    ALERT = "alert"
    ACCOUNT = "account"
    ENTITY = "entity"
    GENERIC = "generic"


class CorrelationKind(str, Enum):
    """
    Bounded pairwise correlation kind.
    """

    COMPLAINT_TO_TRANSACTION = "complaint_to_transaction"
    COMPLAINT_TO_CASE = "complaint_to_case"
    COMPLAINT_TO_ALERT = "complaint_to_alert"
    TRANSACTION_TO_CASE = "transaction_to_case"
    TRANSACTION_TO_ALERT = "transaction_to_alert"
    ALERT_TO_CASE = "alert_to_case"
    SAME_CATEGORY = "same_category"
    OTHER = "other"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class AnalysisStatus(str, Enum):
    """
    Overall exact-reference analysis status.
    """

    PASSED = "PASSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


_PAIR_KINDS: Final[Mapping[tuple[str, str], CorrelationKind]] = MappingProxyType(
    {
        ("complaint", "transaction"): CorrelationKind.COMPLAINT_TO_TRANSACTION,
        ("complaint", "case"): CorrelationKind.COMPLAINT_TO_CASE,
        ("complaint", "alert"): CorrelationKind.COMPLAINT_TO_ALERT,
        ("transaction", "case"): CorrelationKind.TRANSACTION_TO_CASE,
        ("alert", "transaction"): CorrelationKind.TRANSACTION_TO_ALERT,
        ("transaction", "alert"): CorrelationKind.TRANSACTION_TO_ALERT,
        ("alert", "case"): CorrelationKind.ALERT_TO_CASE,
    }
)


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExactReferenceOptions:
    """
    Bounded exact-reference correlation policy.

    Hard caps prevent hub explosion, unbounded candidate growth, and unbounded
    runtime.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE

    max_records: int = DEFAULT_MAX_RECORDS
    max_candidates: int = DEFAULT_MAX_CANDIDATES
    max_occurrences: int = DEFAULT_MAX_OCCURRENCES
    max_bucket_size: int = DEFAULT_MAX_BUCKET_SIZE
    max_references_per_record: int = DEFAULT_MAX_REFERENCES_PER_RECORD
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS

    min_reference_length: int = DEFAULT_MIN_REFERENCE_LENGTH
    max_reference_length: int = DEFAULT_MAX_REFERENCE_LENGTH

    temporal_tolerance_seconds: int = DEFAULT_TEMPORAL_TOLERANCE_SECONDS
    min_score: float = 0.0

    include_same_category: bool = False
    require_account_overlap: bool = False
    require_temporal_proximity: bool = False
    require_currency_alignment: bool = False
    strict_currency_matching: bool = True

    drop_forbidden_fields: bool = True
    include_reasons: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_token(self.dataset_mode) or "synthetic")
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(self, "salt", _ensure_salt(self.salt))
        object.__setattr__(self, "namespace", _normalize_token(self.namespace) or _DEFAULT_NAMESPACE)

        object.__setattr__(
            self,
            "max_records",
            _clamp_int(self.max_records, 1, HARD_MAX_RECORDS, DEFAULT_MAX_RECORDS),
        )
        object.__setattr__(
            self,
            "max_candidates",
            _clamp_int(self.max_candidates, 1, HARD_MAX_CANDIDATES, DEFAULT_MAX_CANDIDATES),
        )
        object.__setattr__(
            self,
            "max_occurrences",
            _clamp_int(self.max_occurrences, 1, HARD_MAX_OCCURRENCES, DEFAULT_MAX_OCCURRENCES),
        )
        object.__setattr__(
            self,
            "max_bucket_size",
            _clamp_int(self.max_bucket_size, 2, HARD_MAX_BUCKET_SIZE, DEFAULT_MAX_BUCKET_SIZE),
        )
        object.__setattr__(
            self,
            "max_references_per_record",
            _clamp_int(
                self.max_references_per_record,
                1,
                HARD_MAX_REFERENCES_PER_RECORD,
                DEFAULT_MAX_REFERENCES_PER_RECORD,
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

        min_len = _clamp_int(
            self.min_reference_length,
            HARD_MIN_REFERENCE_LENGTH,
            HARD_MAX_REFERENCE_LENGTH,
            DEFAULT_MIN_REFERENCE_LENGTH,
        )
        max_len = _clamp_int(
            self.max_reference_length,
            min_len,
            HARD_MAX_REFERENCE_LENGTH,
            DEFAULT_MAX_REFERENCE_LENGTH,
        )

        object.__setattr__(self, "min_reference_length", min_len)
        object.__setattr__(self, "max_reference_length", max_len)

        object.__setattr__(
            self,
            "temporal_tolerance_seconds",
            _clamp_int(
                self.temporal_tolerance_seconds,
                0,
                HARD_MAX_TEMPORAL_TOLERANCE_SECONDS,
                DEFAULT_TEMPORAL_TOLERANCE_SECONDS,
            ),
        )
        object.__setattr__(
            self,
            "min_score",
            _round6(_clamp_float(self.min_score, 0.0, 1.0, 0.0)),
        )

        object.__setattr__(self, "include_same_category", _as_bool(self.include_same_category, False))
        object.__setattr__(self, "require_account_overlap", _as_bool(self.require_account_overlap, False))
        object.__setattr__(self, "require_temporal_proximity", _as_bool(self.require_temporal_proximity, False))
        object.__setattr__(self, "require_currency_alignment", _as_bool(self.require_currency_alignment, False))
        object.__setattr__(self, "strict_currency_matching", _as_bool(self.strict_currency_matching, True))
        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, True))
        object.__setattr__(self, "include_reasons", _as_bool(self.include_reasons, True))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "ExactReferenceOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "CORRELATION_EXACT_REFERENCE_SALT", None)
            or _setting(settings, "CORRELATION_SALT", None)
            or _setting(settings, "CORRELATION_NORMALIZER_SALT", None)
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
            enabled=_as_bool(_setting(settings, "CORRELATION_EXACT_REFERENCE_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_NAMESPACE", _DEFAULT_NAMESPACE)
            ),
            max_records=_as_int(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_MAX_RECORDS", DEFAULT_MAX_RECORDS),
                DEFAULT_MAX_RECORDS,
            ),
            max_candidates=_as_int(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_MAX_CANDIDATES", DEFAULT_MAX_CANDIDATES),
                DEFAULT_MAX_CANDIDATES,
            ),
            max_occurrences=_as_int(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_MAX_OCCURRENCES", DEFAULT_MAX_OCCURRENCES),
                DEFAULT_MAX_OCCURRENCES,
            ),
            max_bucket_size=_as_int(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_MAX_BUCKET_SIZE", DEFAULT_MAX_BUCKET_SIZE),
                DEFAULT_MAX_BUCKET_SIZE,
            ),
            max_references_per_record=_as_int(
                _setting(
                    settings,
                    "CORRELATION_EXACT_REFERENCE_MAX_REFERENCES_PER_RECORD",
                    DEFAULT_MAX_REFERENCES_PER_RECORD,
                ),
                DEFAULT_MAX_REFERENCES_PER_RECORD,
            ),
            max_issues=_as_int(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_MAX_ISSUES", DEFAULT_MAX_ISSUES),
                DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(
                    settings,
                    "CORRELATION_EXACT_REFERENCE_MAX_SUMMARY_ITEMS",
                    DEFAULT_MAX_SUMMARY_ITEMS,
                ),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_MAX_TIME_MS", DEFAULT_MAX_TIME_MS),
                DEFAULT_MAX_TIME_MS,
            ),
            min_reference_length=_as_int(
                _setting(
                    settings,
                    "CORRELATION_EXACT_REFERENCE_MIN_REFERENCE_LENGTH",
                    DEFAULT_MIN_REFERENCE_LENGTH,
                ),
                DEFAULT_MIN_REFERENCE_LENGTH,
            ),
            max_reference_length=_as_int(
                _setting(
                    settings,
                    "CORRELATION_EXACT_REFERENCE_MAX_REFERENCE_LENGTH",
                    DEFAULT_MAX_REFERENCE_LENGTH,
                ),
                DEFAULT_MAX_REFERENCE_LENGTH,
            ),
            temporal_tolerance_seconds=_as_int(
                _setting(
                    settings,
                    "CORRELATION_EXACT_REFERENCE_TEMPORAL_TOLERANCE_SECONDS",
                    DEFAULT_TEMPORAL_TOLERANCE_SECONDS,
                ),
                DEFAULT_TEMPORAL_TOLERANCE_SECONDS,
            ),
            min_score=_as_float(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_MIN_SCORE", 0.0),
                0.0,
            ),
            include_same_category=_as_bool(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_INCLUDE_SAME_CATEGORY", False),
                False,
            ),
            require_account_overlap=_as_bool(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_REQUIRE_ACCOUNT_OVERLAP", False),
                False,
            ),
            require_temporal_proximity=_as_bool(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_REQUIRE_TEMPORAL_PROXIMITY", False),
                False,
            ),
            require_currency_alignment=_as_bool(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_REQUIRE_CURRENCY_ALIGNMENT", False),
                False,
            ),
            strict_currency_matching=_as_bool(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_STRICT_CURRENCY", True),
                True,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_DROP_FORBIDDEN_FIELDS", True),
                True,
            ),
            include_reasons=_as_bool(
                _setting(settings, "CORRELATION_EXACT_REFERENCE_INCLUDE_REASONS", True),
                True,
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
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
            "limits": {
                "max_records": self.max_records,
                "max_candidates": self.max_candidates,
                "max_occurrences": self.max_occurrences,
                "max_bucket_size": self.max_bucket_size,
                "max_references_per_record": self.max_references_per_record,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
                "min_reference_length": self.min_reference_length,
                "max_reference_length": self.max_reference_length,
                "temporal_tolerance_seconds": self.temporal_tolerance_seconds,
            },
            "min_score": _round6(self.min_score),
            "flags": {
                "include_same_category": self.include_same_category,
                "require_account_overlap": self.require_account_overlap,
                "require_temporal_proximity": self.require_temporal_proximity,
                "require_currency_alignment": self.require_currency_alignment,
                "strict_currency_matching": self.strict_currency_matching,
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "include_reasons": self.include_reasons,
            },
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "complaints",
        "transactions",
        "alerts",
        "cases",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class ExactReferenceRequest:
    """
    Bounded exact-reference correlation request.
    """

    complaints: Any = None
    transactions: Any = None
    alerts: Any = None
    cases: Any = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    tags: Sequence[str] = field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> ExactReferenceRequest:
    if isinstance(request, ExactReferenceRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(ExactReferenceRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return ExactReferenceRequest(**clean)
            except Exception:
                return ExactReferenceRequest(metadata=request)

        return ExactReferenceRequest(metadata=request)

    return ExactReferenceRequest(metadata=request)


# -----------------------------------------------------------------------------
# Candidate and result models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExactReferenceCandidate:
    """
    One bounded exact-reference correlation candidate.

    `confidence` describes reference equality only. It is not a probability of
    guilt. `score` is an investigative prioritization signal only.

    All identifiers exposed here are salted, one-way pseudonymous hashes. Raw
    reference tokens and raw account identifiers are never retained.
    """

    correlation_id: str = ""
    kind: CorrelationKind | str = CorrelationKind.OTHER
    reference_kind: ReferenceKind | str = ReferenceKind.GENERIC
    reference_hash: str = ""
    source_category: str = ""
    target_category: str = ""
    source_ref_hash: Optional[str] = None
    target_ref_hash: Optional[str] = None
    source_index: int = 0
    target_index: int = 0
    confidence: float = 1.0
    score: float = 0.0
    corroborated: bool = False
    reasons: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "kind",
            _normalize_enum_option(CorrelationKind, self.kind, CorrelationKind.OTHER),
        )
        object.__setattr__(
            self,
            "reference_kind",
            _normalize_enum_option(ReferenceKind, self.reference_kind, ReferenceKind.GENERIC),
        )
        object.__setattr__(
            self,
            "reference_hash",
            _clean_text(self.reference_hash, MAX_HASH_LENGTH).lower(),
        )
        object.__setattr__(self, "source_category", _normalize_token(self.source_category))
        object.__setattr__(self, "target_category", _normalize_token(self.target_category))
        object.__setattr__(
            self,
            "source_ref_hash",
            _clean_text(self.source_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(
            self,
            "target_ref_hash",
            _clean_text(self.target_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(self, "source_index", max(0, _as_int(self.source_index, 0)))
        object.__setattr__(self, "target_index", max(0, _as_int(self.target_index, 0)))
        object.__setattr__(self, "confidence", _round6(_clip_float(self.confidence, 0.0, 1.0, 1.0)))
        object.__setattr__(self, "score", _round6(_clip_float(self.score, 0.0, 1.0, 0.0)))
        object.__setattr__(self, "corroborated", _as_bool(self.corroborated, False))
        object.__setattr__(
            self,
            "reasons",
            tuple(
                dict.fromkeys(
                    _clean_text(reason, 200)
                    for reason in (self.reasons or ())
                    if _clean_text(reason, 200)
                )
            )[:50],
        )
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.correlation_id:
            object.__setattr__(
                self,
                "correlation_id",
                _fingerprint_payload(
                    {
                        "kind": _enum_value(self.kind),
                        "reference_kind": _enum_value(self.reference_kind),
                        "reference_hash": self.reference_hash,
                        "source": self.source_ref_hash or f"{self.source_category}:{self.source_index}",
                        "target": self.target_ref_hash or f"{self.target_category}:{self.target_index}",
                    }
                )[:32],
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "kind": _enum_value(self.kind, CorrelationKind.OTHER.value),
            "reference_kind": _enum_value(self.reference_kind, ReferenceKind.GENERIC.value),
            "reference_hash": self.reference_hash,
            "source_category": self.source_category,
            "target_category": self.target_category,
            "source_ref_hash": self.source_ref_hash,
            "target_ref_hash": self.target_ref_hash,
            "source_index": int(self.source_index),
            "target_index": int(self.target_index),
            "confidence": float(self.confidence),
            "score": float(self.score),
            "corroborated": bool(self.corroborated),
            "reasons": list(self.reasons),
            "metadata": _safe_detail_value(self.metadata),
            "confidence_semantics": "reference_equality_only_not_probability_of_guilt",
            "raw_reference_retained": False,
            "caveats": list(EXACT_REFERENCE_CAVEATS),
            "safety_flags": dict(EXACT_REFERENCE_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class ExactReferenceIssue:
    """
    Safe exact-reference issue.

    This class was referenced fifteen times in this module and exported in
    `__all__`, but never defined: tier-1 exact-reference correlation raised
    `NameError` the first time it recorded any issue. Its shape is taken from
    the sibling issue types in this package (`IdentifierMatchIssue`,
    `EntityAssociationIssue`, `ConfidenceIssue`), which this module's call
    sites already assume -- `severity`, `code`, `message`, `field`, `details`
    and `to_dict()`.

    Bounds are enforced in `__post_init__` rather than at the call sites, so a
    long message or an unexpected details payload cannot widen what an issue
    carries. No raw reference text is retained.
    """

    severity: IssueSeverity
    code: str
    message: str
    field: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "severity",
            _normalize_enum_option(IssueSeverity, self.severity, IssueSeverity.WARNING),
        )
        object.__setattr__(self, "code", _clean_text(self.code, 100))
        object.__setattr__(self, "message", _clean_text(self.message, 300))
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


@dataclass(frozen=True, slots=True)
class ExactReferenceResult:
    """
    Safe bounded exact-reference correlation result.
    """

    ok: bool = True
    status: AnalysisStatus | str = AnalysisStatus.PASSED
    request_id: str = ""
    generated_at: datetime = field(default_factory=_now_utc)
    duration_ms: int = 0
    candidates: tuple[ExactReferenceCandidate, ...] = ()
    counts: Mapping[str, int] = field(default_factory=dict)
    issues: tuple["ExactReferenceIssue", ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(AnalysisStatus, self.status, AnalysisStatus.PASSED),
        )
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "candidates", tuple(self.candidates or ()))
        object.__setattr__(
            self,
            "counts",
            MappingProxyType(
                {str(key): max(0, _as_int(value, 0)) for key, value in (self.counts or {}).items()}
            ),
        )
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": EXACT_REFERENCE_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, AnalysisStatus.PASSED.value),
                        "request_id": self.request_id,
                        "candidate_count": len(self.candidates),
                        "candidate_ids": [candidate.correlation_id for candidate in self.candidates[:64]],
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": _enum_value(self.status, AnalysisStatus.PASSED.value),
            "request_id": self.request_id,
            "generated_at": self.generated_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(EXACT_REFERENCE_CAVEATS),
            "safety_flags": dict(EXACT_REFERENCE_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class _ReferenceBinding:
    """
    One normalized reference binding.

    A binding pairs a reference kind with the salted, one-way hash of the
    reference token that was observed. Raw reference tokens are never
    retained on the binding.
    """

    kind: ReferenceKind
    reference_hash: str


@dataclass(frozen=True, slots=True)
class _ReferenceRecord:
    """
    One normalized record prepared for exact-reference matching in a bounded,
    privacy-safe context.

    Raw feature values are not retained. Only pseudonymous references, hashed
    account references, a normalized timestamp, a currency code, and a bounded
    numeric amount are kept for corroboration.
    """

    category: str
    index: int
    subject_ref_hash: Optional[str]
    bindings: tuple[_ReferenceBinding, ...] = ()
    account_refs: tuple[str, ...] = ()
    timestamp: Optional[datetime] = None
    currency: Optional[str] = None
    amount: Optional[float] = None


@dataclass(frozen=True, slots=True)
class _Occurrence:
    """
    One reference-bucket occurrence used for pairwise matching.
    """

    category: str
    index: int
    subject_ref_hash: Optional[str]
    account_refs: tuple[str, ...]
    timestamp: Optional[datetime]
    currency: Optional[str]
    amount: Optional[float]


# -----------------------------------------------------------------------------
# Runtime helpers
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
    return max(minimum, min(_as_float(value, default), default if math.isnan(_as_float(value, default)) else maximum))


def _csv(value: object) -> list[str]:
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return [part.strip() for part in str(value).split(",") if part.strip()]




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
    text = CONTROL_CHAR_RE.sub(" ", text)
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
    text = SEPARATOR_RE.sub("_", text)
    text = MULTI_UNDERSCORE_RE.sub("_", text)
    return text.strip("_").lower()


def _canonical_field_name(key: Any) -> str:
    return _normalize_token(key)


def _is_safe_hash(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and HASH_RE.match(text))


def _is_forbidden_key(key: Any) -> bool:
    canonical = _canonical_field_name(key)

    if not canonical:
        return False

    if canonical in FORBIDDEN_FIELDS:
        return True

    if canonical.startswith("raw_") or canonical.endswith("_raw"):
        return True

    return any(token in canonical for token in FORBIDDEN_TOKENS)


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


def _coerce_optional_float(value: Any, *, allow_bool: bool = False) -> Optional[float]:
    if value is None:
        return None

    if isinstance(value, bool):
        return (1.0 if value else 0.0) if allow_bool else None

    if isinstance(value, (int, float)):
        result = float(value)
        return result if math.isfinite(result) else None

    if isinstance(value, Decimal):
        if not value.is_finite():
            return None

        try:
            result = float(value)
        except (OverflowError, ValueError):
            return None

        return result if math.isfinite(result) else None

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.timestamp() if normalized else None

    if isinstance(value, Enum):
        return _coerce_optional_float(value.value, allow_bool=allow_bool)

    if isinstance(value, str):
        text = value.strip().replace(",", "")

        if not text:
            return None

        lowered = text.lower()

        if allow_bool:
            if lowered in _TRUE_VALUES:
                return 1.0
            if lowered in _FALSE_VALUES:
                return 0.0

        try:
            result = float(text)
        except (TypeError, ValueError):
            return None

        return result if math.isfinite(result) else None

    return None


def _normalize_currency(value: Any) -> Optional[str]:
    text = _normalize_unicode(value).strip().upper()
    text = re.sub(r"[^A-Z]", "", text)

    if CURRENCY_RE.match(text):
        return text

    return None


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


def _subject_hash(value: Any, options: ExactReferenceOptions) -> Optional[str]:
    """
    Return a salted, one-way pseudonymous subject/account reference.

    Already-safe hashes are preserved in lowercase. Raw values are hashed and
    never retained.
    """
    text = _clean_text(value, MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.correlation.exact_reference.subject.{namespace}"
    return _hmac_hex(options.salt, domain, text)[:40]


def _canonical_reference_token(value: Any, options: ExactReferenceOptions) -> Optional[str]:
    """
    Canonicalize an opaque reference token without retaining it.

    Canonicalization is deterministic: NFKC, control-character removal,
    whitespace collapse, and case folding. Credential-like assignment syntax
    and free-text-like values are rejected outright.
    """
    text = _clean_text(value, options.max_reference_length)

    if not text:
        return None

    if len(text) < int(options.min_reference_length):
        return None

    if len(text) > int(options.max_reference_length):
        return None

    if REFERENCE_UNSAFE_RE.search(text):
        return None

    if text.count(" ") >= 4:
        return None

    folded = text.upper()

    if len(folded) < int(options.min_reference_length):
        return None

    return folded


def _reference_hash(
    token: str,
    kind: ReferenceKind,
    options: ExactReferenceOptions,
) -> str:
    """
    Hash a canonical reference token in a shared, kind-scoped domain.

    The same kind token shares the same domain across categories, enabling
    exact reference collision detection without retaining raw references.
    """
    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.correlation.exact_reference.reference.{kind.value}.{namespace}"
    return _hmac_hex(options.salt, domain, token)[:40]


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

        parts.append(str(value))

    for value in values:
        visit(value)

    text = " ".join(parts).lower()
    return bool(text) and any(token in text for token in PROHIBITED_ACTION_TOKENS)


def _normalize_tags(value: Any, limit: int = 50) -> tuple[str, ...]:
    out: list[str] = []

    for item in _as_sequence(value):
        tag = _clean_text(item, 100)

        if tag:
            out.append(tag)

        if len(out) >= limit:
            break

    return tuple(dict.fromkeys(out))


def _iter_records(data: Any) -> list[Any]:
    if data is None:
        return []

    if isinstance(data, ExactReferenceResult):
        return []

    if isinstance(data, Mapping):
        for key in ("records", "rows", "items", "examples"):
            if key in data and not isinstance(data[key], Mapping):
                return _as_sequence(data[key])

        return [data]

    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray, memoryview)):
        return list(data)

    if isinstance(data, Iterable):
        try:
            return list(data)
        except Exception:
            return [data]

    return [data]


def _extract_view(record: Any) -> dict[str, Any]:
    """
    Build a flat canonical view of a record without retaining forbidden data.

    Nested `features`/`values` take precedence over top-level fields. Forbidden
    and leakage-prone keys are detected later by the sanitizer.
    """
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

                if not key or key in NON_FEATURE_KEYS:
                    continue

                view[key] = raw_value
    else:
        for key in _ALL_VIEW_FIELDS:
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


def _extract_subject(
    record: Any,
    options: ExactReferenceOptions,
    view: Mapping[str, Any],
) -> Optional[str]:
    for key in SUBJECT_KEYS:
        if key in view and view[key] is not None:
            hashed = _subject_hash(view[key], options)

            if hashed:
                return hashed

    if isinstance(record, Mapping):
        for key in SUBJECT_KEYS:
            if key in record:
                hashed = _subject_hash(record[key], options)

                if hashed:
                    return hashed

    return None


# -----------------------------------------------------------------------------
# Issue helpers
# -----------------------------------------------------------------------------


def _append_issue(
    issues: list[ExactReferenceIssue],
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

        issues[-1] = ExactReferenceIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        ExactReferenceIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[ExactReferenceIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[ExactReferenceIssue]) -> tuple[ExactReferenceIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[ExactReferenceIssue] = []

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
# Sanitization
# -----------------------------------------------------------------------------


def _sanitize_record(
    record: Any,
    category: str,
    options: ExactReferenceOptions,
    issues: list[ExactReferenceIssue],
    index: int,
    start_time: float,
) -> Optional[_ReferenceRecord]:
    """
    Reduce one record to correlation-safe context.

    Raw reference tokens are hashed immediately and never stored. Raw account
    identifiers are hashed immediately and never stored. Forbidden and
    leakage-prone fields are rejected or dropped according to policy.
    """
    if _time_exceeded(start_time, options.max_time_ms):
        return None

    view = _extract_view(record)
    subject = _extract_subject(record, options, view)
    allowed = CATEGORY_ALLOWED_FIELDS.get(category, frozenset())

    bindings: dict[tuple[str, str], None] = {}
    accounts: set[str] = set()
    rejected = False
    reference_count = 0

    for raw_key in sorted(view):
        raw_value = view[raw_key]
        canonical = _canonical_field_name(raw_key)
        canonical = REFERENCE_ALIASES.get(canonical, canonical)

        if not canonical or canonical in NON_FEATURE_KEYS:
            continue

        if _is_forbidden_key(canonical) or _is_label_leakage_key(canonical):
            if options.drop_forbidden_fields:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="forbidden_field_dropped",
                    message="Forbidden or leakage-prone field omitted.",
                    field=canonical,
                    details={"category": category, "index": index},
                )
                continue

            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.ERROR,
                code="forbidden_field",
                message="Forbidden or leakage-prone field rejected.",
                field=canonical,
                details={"category": category, "index": index},
            )
            rejected = True
            break

        if canonical in ACCOUNT_REFERENCE_FIELDS:
            hashed_account = _subject_hash(raw_value, options)

            if hashed_account:
                accounts.add(hashed_account)

            continue

        if canonical in SUBJECT_KEYS:
            continue

        if canonical not in allowed:
            continue

        if canonical in REFERENCE_FIELD_KINDS:
            if reference_count >= int(options.max_references_per_record):
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="reference_limit_per_record",
                    message="Additional reference fields omitted due to per-record limit.",
                    field=canonical,
                    details={"category": category, "index": index},
                )
                continue

            token = _canonical_reference_token(raw_value, options)

            if token is None:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.INFO,
                    code="reference_token_not_usable",
                    message="Reference token was empty, too short, free-text-like, or credential-like and was omitted.",
                    field=canonical,
                    details={"category": category, "index": index},
                )
                continue

            kind = _normalize_enum_option(
                ReferenceKind,
                REFERENCE_FIELD_KINDS.get(canonical, "generic"),
                ReferenceKind.GENERIC,
            )
            hashed = _reference_hash(token, kind, options)
            bindings[(kind.value, hashed)] = None
            reference_count += 1

    if rejected:
        return None

    timestamp: Optional[datetime] = None

    for field_name in TIMESTAMP_PRIORITY:
        if field_name in view:
            parsed = _parse_datetime(view[field_name])

            if parsed is not None:
                timestamp = parsed
                break

    currency: Optional[str] = None
    amount: Optional[float] = None

    if "currency" in view:
        currency = _normalize_currency(view["currency"])

    if "amount" in view:
        numeric = _coerce_optional_float(view["amount"], allow_bool=False)

        if numeric is not None and math.isfinite(numeric):
            amount = _round6(abs(float(numeric)))

    if amount is not None and currency is None:
        # Never attach an unaligned monetary value to a match.
        amount = None

    ordered_bindings = tuple(
        _ReferenceBinding(
            kind=_normalize_enum_option(ReferenceKind, kind_token, ReferenceKind.GENERIC),
            reference_hash=reference_hash,
        )
        for kind_token, reference_hash in sorted(bindings)
    )

    return _ReferenceRecord(
        category=category,
        index=index,
        subject_ref_hash=subject,
        bindings=ordered_bindings,
        account_refs=tuple(sorted(accounts)),
        timestamp=timestamp,
        currency=currency,
        amount=amount,
    )


def _sanitize_category(
    raw_records: Sequence[Any],
    category: str,
    options: ExactReferenceOptions,
    issues: list[ExactReferenceIssue],
    start_time: float,
) -> list[_ReferenceRecord]:
    cleaned: list[_ReferenceRecord] = []

    for source_index, record in enumerate(raw_records):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="sanitization_time_budget_exhausted",
                message="Sanitization stopped after reaching configured time budget.",
                details={
                    "category": category,
                    "processed": len(cleaned),
                    "remaining": max(0, len(raw_records) - source_index),
                },
            )
            break

        sanitized = _sanitize_record(
            record,
            category,
            options,
            issues,
            source_index,
            start_time,
        )

        if sanitized is not None:
            cleaned.append(sanitized)

    return cleaned


# -----------------------------------------------------------------------------
# Reference indexing
# -----------------------------------------------------------------------------


def _occurrence_sort_key(occurrence: _Occurrence) -> tuple[int, int, str]:
    return (
        int(_CATEGORY_ORDER_INDEX.get(occurrence.category, len(CATEGORY_ORDER))),
        int(occurrence.index),
        occurrence.subject_ref_hash or "",
    )


def _build_reference_index(
    records: Sequence[_ReferenceRecord],
    options: ExactReferenceOptions,
    issues: list[ExactReferenceIssue],
    start_time: float,
) -> tuple[dict[tuple[str, str], list[_Occurrence]], dict[str, int]]:
    """
    Build a bounded reference index keyed by (reference kind, reference hash).

    Hub buckets are deterministically sorted and capped. Truncation is reported
    honestly rather than silently dropping matches.
    """
    buckets: dict[tuple[str, str], list[_Occurrence]] = defaultdict(list)
    stats: dict[str, int] = {
        "references_hashed": 0,
        "occurrences_indexed": 0,
        "hub_truncations": 0,
        "occurrence_limit_truncations": 0,
    }

    for record in records:
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="indexing_time_budget_exhausted",
                message="Reference indexing stopped after reaching configured time budget.",
            )
            break

        for binding in record.bindings:
            key = (binding.kind.value, binding.reference_hash)
            bucket = buckets[key]

            if len(bucket) >= int(options.max_bucket_size):
                stats["hub_truncations"] += 1
                continue

            if stats["occurrences_indexed"] >= int(options.max_occurrences):
                stats["occurrence_limit_truncations"] += 1
                continue

            bucket.append(
                _Occurrence(
                    category=record.category,
                    index=record.index,
                    subject_ref_hash=record.subject_ref_hash,
                    account_refs=record.account_refs,
                    timestamp=record.timestamp,
                    currency=record.currency,
                    amount=record.amount,
                )
            )

            stats["references_hashed"] += 1
            stats["occurrences_indexed"] += 1

    for key in list(buckets):
        buckets[key].sort(key=_occurrence_sort_key)

        if len(buckets[key]) > int(options.max_bucket_size):
            stats["hub_truncations"] += 1
            buckets[key] = buckets[key][: int(options.max_bucket_size)]

    if stats["hub_truncations"]:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="reference_hub_truncated",
            message="One or more reference buckets exceeded configured hub capacity and were truncated.",
            details={"hub_truncations": stats["hub_truncations"]},
        )

    if stats["occurrence_limit_truncations"]:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="reference_occurrence_limit_truncated",
            message="Reference index exceeded configured occurrence budget.",
            details={"occurrence_limit_truncations": stats["occurrence_limit_truncations"]},
        )

    return dict(buckets), stats


# -----------------------------------------------------------------------------
# Scoring and pairing
# -----------------------------------------------------------------------------


def _temporal_delta_seconds(
    left: Optional[datetime],
    right: Optional[datetime],
) -> Optional[float]:
    if left is None or right is None:
        return None

    try:
        delta = abs((left - right).total_seconds())
    except (OverflowError, ValueError):
        return None

    if not math.isfinite(delta):
        return None

    return float(delta)


def _score_pair(
    left: _Occurrence,
    right: _Occurrence,
    bucket_size: int,
    options: ExactReferenceOptions,
) -> tuple[float, bool, list[str]]:
    """
    Score one exact-reference pair using bounded structural corroboration.

    Confidence is fixed at reference equality; this function computes only the
    investigative prioritization score. No monetary conversion is performed.
    """
    account_overlap = bool(set(left.account_refs) & set(right.account_refs))

    delta = _temporal_delta_seconds(left.timestamp, right.timestamp)
    temporal = (
        delta is not None
        and delta <= float(options.temporal_tolerance_seconds)
    )

    left_currency = left.currency
    right_currency = right.currency

    currency_aligned = bool(
        left_currency
        and right_currency
        and left_currency == right_currency
    )

    currency_conflict = bool(
        left_currency
        and right_currency
        and left_currency != right_currency
    )

    amount_match = False

    if (
        options.strict_currency_matching
        and currency_aligned
        and left.amount is not None
        and right.amount is not None
    ):
        amount_match = math.isclose(
            float(left.amount),
            float(right.amount),
            rel_tol=1e-6,
            abs_tol=0.01,
        )

    if options.require_account_overlap and not account_overlap:
        return 0.0, False, []

    if options.require_temporal_proximity and not temporal:
        return 0.0, False, []

    if options.require_currency_alignment and not currency_aligned:
        return 0.0, False, []

    base = (
        0.70
        + (0.12 if account_overlap else 0.0)
        + (0.12 if temporal else 0.0)
        + (0.06 if amount_match else 0.0)
    )

    hub_dilution = 1.0 / (
        1.0 + 0.02 * max(0, int(bucket_size) - 2)
    )

    score = _round6(_clip_float(base * hub_dilution, 0.0, 1.0, 0.0))
    corroborated = bool(account_overlap or temporal or amount_match)

    reasons: list[str] = ["exact_reference_match"]

    if account_overlap:
        reasons.append("account_overlap")

    if temporal:
        reasons.append("temporal_proximity")

    if amount_match:
        reasons.append("currency_aligned_amount_match")

    if currency_conflict:
        reasons.append("currency_mismatch_no_amount_comparison")

    if not corroborated:
        reasons.append("uncorroborated_reference_match")

    if int(bucket_size) > 2:
        reasons.append("shared_reference_hub")

    reasons.append("operational_lead_only_not_proof")

    return score, corroborated, reasons


def _pair_identity(occurrence: _Occurrence) -> str:
    if occurrence.subject_ref_hash:
        return occurrence.subject_ref_hash

    return f"{occurrence.category}:{occurrence.index}"


def _match_reference_index(
    buckets: Mapping[tuple[str, str], Sequence[_Occurrence]],
    options: ExactReferenceOptions,
    issues: list[ExactReferenceIssue],
    start_time: float,
) -> tuple[list[ExactReferenceCandidate], dict[str, int]]:
    """
    Generate bounded deterministic pairwise exact-reference candidates.
    """
    candidates: list[ExactReferenceCandidate] = []
    seen: set[tuple[str, str, str, str]] = set()

    stats: dict[str, int] = {
        "pairs_evaluated": 0,
        "candidates_generated": 0,
        "duplicate_candidates_removed": 0,
        "below_min_score": 0,
    }

    for key in sorted(buckets):
        kind_token, reference_hash = key
        occurrences = buckets[key]
        bucket_size = len(occurrences)

        if bucket_size < 2:
            continue

        for i in range(bucket_size):
            if _time_exceeded(start_time, options.max_time_ms):
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="pairing_time_budget_exhausted",
                    message="Pairwise matching stopped after reaching configured time budget.",
                )
                return candidates, stats

            left = occurrences[i]

            for j in range(i + 1, bucket_size):
                right = occurrences[j]

                if left.category == right.category and not options.include_same_category:
                    continue

                stats["pairs_evaluated"] += 1

                score, corroborated, reasons = _score_pair(
                    left,
                    right,
                    bucket_size,
                    options,
                )

                if not reasons:
                    continue

                if score < float(options.min_score):
                    stats["below_min_score"] += 1
                    continue

                left_identity = _pair_identity(left)
                right_identity = _pair_identity(right)

                dedupe_key = (kind_token, reference_hash, left_identity, right_identity)

                if dedupe_key in seen:
                    stats["duplicate_candidates_removed"] += 1
                    continue

                seen.add(dedupe_key)

                if left.category == right.category:
                    pair_kind = CorrelationKind.SAME_CATEGORY
                else:
                    pair_kind = _PAIR_KINDS.get(
                        (left.category, right.category),
                        CorrelationKind.OTHER,
                    )

                correlation_id = _fingerprint_payload(
                    {
                        "version": EXACT_REFERENCE_VERSION,
                        "reference_kind": kind_token,
                        "reference_hash": reference_hash,
                        "source": left_identity,
                        "target": right_identity,
                    }
                )[:32]

                candidates.append(
                    ExactReferenceCandidate(
                        correlation_id=correlation_id,
                        kind=pair_kind,
                        reference_kind=_normalize_enum_option(
                            ReferenceKind,
                            kind_token,
                            ReferenceKind.GENERIC,
                        ),
                        reference_hash=reference_hash,
                        source_category=left.category,
                        target_category=right.category,
                        source_ref_hash=left.subject_ref_hash,
                        target_ref_hash=right.subject_ref_hash,
                        source_index=int(left.index),
                        target_index=int(right.index),
                        confidence=1.0,
                        score=score,
                        corroborated=corroborated,
                        reasons=tuple(reasons) if options.include_reasons else (),
                        metadata={
                            "reference_kind": kind_token,
                            "bucket_size": int(bucket_size),
                            "corroborated": bool(corroborated),
                            "confidence_semantics": "reference_equality_only",
                            "raw_reference_retained": False,
                            "raw_account_identifiers_retained": False,
                            "monetary_conversion_performed": False,
                        },
                    )
                )

                stats["candidates_generated"] += 1

    candidates.sort(
        key=lambda candidate: (
            -float(candidate.score),
            -float(candidate.confidence),
            candidate.reference_kind.value,
            candidate.reference_hash,
            candidate.source_category,
            int(candidate.source_index),
            candidate.target_category,
            int(candidate.target_index),
            candidate.correlation_id,
        )
    )

    if len(candidates) > int(options.max_candidates):
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.WARNING,
            code="candidate_limit_truncated",
            message="Exact-reference candidates exceeded configured limit and were truncated.",
            details={
                "generated": len(candidates),
                "max_candidates": int(options.max_candidates),
            },
        )
        candidates = candidates[: int(options.max_candidates)]

    return candidates, stats


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------


class ExactReferenceEngine:
    """
    Bounded deterministic synthetic exact-reference correlation engine.

    This engine correlates investigative records by salted exact reference
    equality only. It does not authorize actions, deploy models, persist durable
    artifacts, or take adverse action.
    """

    def __init__(self, options: ExactReferenceOptions | None = None) -> None:
        self.options = options or ExactReferenceOptions.from_settings()
        self._lock = threading.RLock()

    def correlate(self, request: Any) -> ExactReferenceResult:
        """
        Run one bounded synthetic exact-reference correlation job.
        """
        opts = self.options
        issues: list[ExactReferenceIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)

        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": EXACT_REFERENCE_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: AnalysisStatus,
            candidates: Sequence[ExactReferenceCandidate] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> ExactReferenceResult:
            resolved_counts: dict[str, int] = {
                "submitted": 0,
                "sanitized": 0,
                "reference_buckets": 0,
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update(
                    {str(key): max(0, _as_int(value, 0)) for key, value in counts.items()}
                )

            resolved_counts["issues"] = len(issues)

            metadata = {
                "exact_reference_version": EXACT_REFERENCE_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_reference_identifiers_retained": False,
                "raw_account_identifiers_retained": False,
                "subject_label_pairs_retained": False,
                "narratives_retained": False,
                "secrets_retained": False,
                "monetary_conversion_performed": False,
                "caveats": list(EXACT_REFERENCE_CAVEATS),
                "safety_flags": dict(EXACT_REFERENCE_SAFETY_FLAGS),
            }

            return ExactReferenceResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                candidates=tuple(candidates),
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
                code="exact_reference_engine_disabled",
                message="Exact-reference engine is disabled.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Exact-reference engine requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Exact-reference engine is blocked in production-like environments.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_exact_reference_action_metadata",
                message="Request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, AnalysisStatus.BLOCKED)

        with self._lock:
            category_sources: tuple[tuple[str, Any], ...] = (
                ("complaint", req.complaints),
                ("transaction", req.transactions),
                ("alert", req.alerts),
                ("case", req.cases),
            )

            all_records: list[_ReferenceRecord] = []
            counts: dict[str, int] = {}
            submitted = 0

            for category, raw_data in category_sources:
                raw_records = _iter_records(raw_data)[: opts.max_records]
                submitted += len(raw_records)
                counts[f"{category}_submitted"] = len(raw_records)

                sanitized = _sanitize_category(
                    raw_records,
                    category,
                    opts,
                    issues,
                    start_time,
                )

                counts[f"{category}_sanitized"] = len(sanitized)
                all_records.extend(sanitized)

            if submitted > int(opts.max_records):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="exact_reference_input_truncated",
                    message="Exact-reference input exceeded configured record limit and was truncated.",
                    details={
                        "submitted": submitted,
                        "max_records": int(opts.max_records),
                    },
                )
                all_records = all_records[: int(opts.max_records)]

            counts["submitted"] = submitted
            counts["sanitized"] = len(all_records)

            if not all_records:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="empty_exact_reference_input",
                    message="No valid records remained for exact-reference correlation.",
                )
                return make_result(False, AnalysisStatus.SKIPPED, counts=counts)

            buckets, index_stats = _build_reference_index(
                all_records,
                opts,
                issues,
                start_time,
            )

            counts["reference_buckets"] = len(buckets)
            counts.update(index_stats)

            candidates, pair_stats = _match_reference_index(
                buckets,
                opts,
                issues,
                start_time,
            )

            counts.update(pair_stats)
            counts["candidates_returned"] = len(candidates)

            status = AnalysisStatus.PASSED

            if _has_error(issues):
                status = AnalysisStatus.FAILED
            elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
                status = AnalysisStatus.DEGRADED
            elif not candidates:
                status = AnalysisStatus.SKIPPED

            return make_result(
                ok=status in {AnalysisStatus.PASSED, AnalysisStatus.DEGRADED},
                status=status,
                candidates=candidates,
                counts=counts,
            )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "caveats": list(EXACT_REFERENCE_CAVEATS),
            "safety_flags": dict(EXACT_REFERENCE_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default engine and public API
# -----------------------------------------------------------------------------


_default_engine: Optional[ExactReferenceEngine] = None
_default_engine_lock = threading.Lock()


def get_exact_reference_options(
    settings: Any | None = None,
) -> ExactReferenceOptions:
    """
    Return exact-reference options from settings.
    """
    return ExactReferenceOptions.from_settings(settings)


def get_exact_reference_engine(
    options: ExactReferenceOptions | None = None,
    *,
    rebuild: bool = False,
) -> ExactReferenceEngine:
    """
    Return a process-wide exact-reference engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = ExactReferenceEngine(
                options=options or ExactReferenceOptions.from_settings()
            )

        return _default_engine


def correlate_exact_references(
    request: Any,
    options: ExactReferenceOptions | None = None,
    *,
    engine: ExactReferenceEngine | None = None,
) -> ExactReferenceResult:
    """
    Correlate bounded synthetic records by salted exact reference equality.
    """
    active_engine = engine or get_exact_reference_engine(options)
    return active_engine.correlate(request)


def find_exact_reference_matches(
    request: Any,
    options: ExactReferenceOptions | None = None,
    *,
    engine: ExactReferenceEngine | None = None,
) -> ExactReferenceResult:
    """
    Alias for `correlate_exact_references`.
    """
    return correlate_exact_references(request, options=options, engine=engine)


def export_exact_reference_summary(result: ExactReferenceResult) -> dict[str, Any]:
    """
    Export a safe public exact-reference summary.
    """
    return result.to_dict()


def get_exact_reference_health(
    *,
    engine: ExactReferenceEngine | None = None,
) -> dict[str, Any]:
    """
    Return safe exact-reference engine health.
    """
    active_engine = engine or get_exact_reference_engine()
    opts = active_engine.options
    issues: list[ExactReferenceIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="exact_reference_engine_disabled",
            message="Exact-reference engine is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Exact-reference engine requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Exact-reference engine is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(EXACT_REFERENCE_CAVEATS),
        "safety_flags": dict(EXACT_REFERENCE_SAFETY_FLAGS),
    }


def get_exact_reference_metadata(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
) -> dict[str, Any]:
    """
    Return safe, serializable exact-reference metadata.

    This is useful for startup logs, diagnostic endpoints, tests, developer
    tooling, and architecture documentation checks.

    It must not expose raw reference tokens, raw identifiers, secrets,
    environment files, database URLs, tokens, passwords, raw complaint
    narratives, ground-truth labels, scenario IDs, fraud-ring IDs, model
    artifact paths, or real customer data.
    """
    options = ExactReferenceOptions.from_settings()

    return {
        "package": "muleguard.backend.correlation.exact_reference",
        "version": EXACT_REFERENCE_VERSION,
        "reference_kinds": [kind.value for kind in ReferenceKind],
        "correlation_kinds": [kind.value for kind in CorrelationKind],
        "analysis_statuses": [status.value for status in AnalysisStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "categories": list(CATEGORY_ORDER),
        "reference_field_kinds": dict(REFERENCE_FIELD_KINDS),
        "reference_aliases": dict(REFERENCE_ALIASES),
        "category_allowed_fields": {
            category: sorted(fields)
            for category, fields in CATEGORY_ALLOWED_FIELDS.items()
        },
        "default_options": options.safe_summary(),
        "hard_limits": {
            "max_records": HARD_MAX_RECORDS,
            "max_candidates": HARD_MAX_CANDIDATES,
            "max_occurrences": HARD_MAX_OCCURRENCES,
            "max_bucket_size": HARD_MAX_BUCKET_SIZE,
            "max_references_per_record": HARD_MAX_REFERENCES_PER_RECORD,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
            "max_reference_length": HARD_MAX_REFERENCE_LENGTH,
            "max_temporal_tolerance_seconds": HARD_MAX_TEMPORAL_TOLERANCE_SECONDS,
        },
        "forbidden_field_count": len(FORBIDDEN_FIELDS),
        "label_leakage_field_count": len(LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(PROHIBITED_ACTION_TOKENS),
        "summary_item_limit": max(1, int(limit)),
        "caveats": list(EXACT_REFERENCE_CAVEATS),
        "safety_flags": dict(EXACT_REFERENCE_SAFETY_FLAGS),
    }


__all__ = [
    "AnalysisStatus",
    "CorrelationKind",
    "EXACT_REFERENCE_VERSION",
    "ExactReferenceCandidate",
    "ExactReferenceEngine",
    "ExactReferenceIssue",
    "ExactReferenceOptions",
    "ExactReferenceRequest",
    "ExactReferenceResult",
    "IssueSeverity",
    "ReferenceKind",
    "correlate_exact_references",
    "export_exact_reference_summary",
    "find_exact_reference_matches",
    "get_exact_reference_engine",
    "get_exact_reference_health",
    "get_exact_reference_metadata",
    "get_exact_reference_options",
]