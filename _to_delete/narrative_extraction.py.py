"""
MULEGUARD backend correlation narrative extraction.

This module provides the canonical bounded narrative extraction and
structural feature layer for the synthetic MULEGUARD investigative prototype.

Primary responsibilities:

- extract bounded structural features from synthetic complaint, case, alert,
  and note narratives without retaining raw unredacted text;
- enforce strict privacy by tokenizing, normalizing, and immediately hashing
  narrative words using a shared, salted, one-way domain, ensuring raw PII,
  raw identifiers, and raw narratives are never retained, logged, or exposed;
- provide bounded, deterministic, API-safe extraction results with structural
  counts, salted token hashes for private similarity matching, safe summaries,
  issue reporting, fingerprints, and metadata;
- reject leakage-prone inputs such as ground-truth labels, injected scenario
  IDs, fraud-ring IDs, secrets, tokens, passwords, database URLs, filesystem
  paths, and model artifact paths;
- remain import-safe, dependency-light, and resilient when optional project
  modules are unavailable.

This module extracts structural narrative features only. It does not train
models, deploy models, persist durable artifacts, call external systems,
authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for narrative extraction.
- Extracted narrative features are investigative leads only. They are not proof
  of wrongdoing, common control, or criminal association.
- Raw unredacted narratives are never retained. They are tokenized and hashed
  using a shared, salted, one-way domain immediately upon ingestion.
- Labels must never be used as extraction features.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected.
- Extraction handling must never trigger automatic adverse customer action.
- Undefined or unavailable extractions are reported honestly as unavailable.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external NLP or LLM engines.
- This module does not deploy, promote, retire, or serve production models.
- This module does not generate synthetic ingestion records.
- This module is not a durable decisioning platform.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, correlation
candidates, normalized records, extracted narrative features, explanations,
validation reports, and case dispositions are investigative leads or human
workflow artefacts only. They are not proof of wrongdoing and must not trigger
automatic adverse customer action.
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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional

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


logger = logging.getLogger("muleguard.backend.correlation.narrative_extraction")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

NARRATIVE_EXTRACTION_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.correlation.narrative_extraction.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"

DEFAULT_MAX_RECORDS: Final[int] = 10_000
HARD_MAX_RECORDS: Final[int] = 100_000

DEFAULT_MAX_TEXT_LENGTH: Final[int] = 4_096
HARD_MAX_TEXT_LENGTH: Final[int] = 32_768

DEFAULT_MAX_TOKENS_PER_RECORD: Final[int] = 500
HARD_MAX_TOKENS_PER_RECORD: Final[int] = 5_000

DEFAULT_MIN_TOKEN_LENGTH: Final[int] = 3
HARD_MIN_TOKEN_LENGTH: Final[int] = 1
HARD_MAX_MIN_TOKEN_LENGTH: Final[int] = 10

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

DEFAULT_MAX_TIME_MS: Final[int] = 30_000
HARD_MAX_TIME_MS: Final[int] = 300_000

MAX_TEXT_LENGTH: Final[int] = 512
MAX_HASH_LENGTH: Final[int] = 256

CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")
HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{32,256}$")
TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9]+")

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

NARRATIVE_KEYS: Final[tuple[str, ...]] = (
    "narrative",
    "description",
    "details",
    "notes",
    "summary",
    "text",
    "content",
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
    "narrative_raw",
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

NARRATIVE_EXTRACTION_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic narrative extraction only. Do not use with real customer data.",
    "Extracted narrative features are investigative leads only and are not proof of wrongdoing.",
    "Raw unredacted narratives are never retained. They are tokenized and hashed immediately.",
    "Token hashes enable private structural similarity matching without exposing raw words.",
    "Extraction must not trigger automatic adverse customer action.",
    "Labels must never be used as extraction features.",
    "Ground-truth style fields such as ground_truth, is_fraud, fraud_label, scenario_id, and ring_id are rejected.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

NARRATIVE_EXTRACTION_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_raw_narratives_retained": True,
        "no_raw_pii_retained": True,
        "shared_salted_one_way_token_hashes": True,
        "salted_pseudonymous_subject_hashes": True,
        "no_labels_as_features": True,
        "no_raw_values_in_public_summaries": True,
        "no_ground_truth_fields_accepted": True,
        "no_fraud_label_fields_accepted": True,
        "no_scenario_ids_accepted": True,
        "no_fraud_ring_ids_accepted": True,
        "no_secrets_accepted": True,
        "no_tokens_accepted": True,
        "no_passwords_accepted": True,
        "no_database_urls_accepted": True,
        "no_model_artifact_paths_accepted": True,
        "deterministic_narrative_extraction": True,
        "bounded_narrative_extraction_required": True,
        "scores_are_investigative_priority_only": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
    }
)

CATEGORY_ORDER: Final[tuple[str, ...]] = ("complaint", "case", "alert", "note")

_CATEGORY_ORDER_INDEX: Final[Mapping[str, int]] = MappingProxyType(
    {category: position for position, category in enumerate(CATEGORY_ORDER)}
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class NarrativeCategory(str, Enum):
    """
    Bounded narrative category.
    """

    COMPLAINT = "complaint"
    CASE = "case"
    ALERT = "alert"
    NOTE = "note"
    OTHER = "other"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ExtractionStatus(str, Enum):
    """
    Overall narrative extraction status.
    """

    PASSED = "PASSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NarrativeExtractionOptions:
    """
    Bounded narrative extraction policy.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE

    max_records: int = DEFAULT_MAX_RECORDS
    max_text_length: int = DEFAULT_MAX_TEXT_LENGTH
    max_tokens_per_record: int = DEFAULT_MAX_TOKENS_PER_RECORD
    min_token_length: int = DEFAULT_MIN_TOKEN_LENGTH
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_time_ms: int = DEFAULT_MAX_TIME_MS

    drop_forbidden_fields: bool = True
    include_token_hashes: bool = True

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
            "max_text_length",
            _clamp_int(self.max_text_length, 10, HARD_MAX_TEXT_LENGTH, DEFAULT_MAX_TEXT_LENGTH),
        )
        object.__setattr__(
            self,
            "max_tokens_per_record",
            _clamp_int(
                self.max_tokens_per_record,
                1,
                HARD_MAX_TOKENS_PER_RECORD,
                DEFAULT_MAX_TOKENS_PER_RECORD,
            ),
        )
        object.__setattr__(
            self,
            "min_token_length",
            _clamp_int(
                self.min_token_length,
                HARD_MIN_TOKEN_LENGTH,
                HARD_MAX_MIN_TOKEN_LENGTH,
                DEFAULT_MIN_TOKEN_LENGTH,
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

        object.__setattr__(self, "drop_forbidden_fields", _as_bool(self.drop_forbidden_fields, True))
        object.__setattr__(self, "include_token_hashes", _as_bool(self.include_token_hashes, True))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "NarrativeExtractionOptions":
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_SALT", None)
            or _setting(settings, "CORRELATION_TEMPORAL_ASSOCIATION_SALT", None)
            or _setting(settings, "CORRELATION_ENTITY_ASSOCIATION_SALT", None)
            or _setting(settings, "CORRELATION_IDENTIFIER_MATCH_SALT", None)
            or _setting(settings, "CORRELATION_EXACT_REFERENCE_SALT", None)
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
            enabled=_as_bool(_setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_ENABLED", True), True),
            synthetic_required=_as_bool(
                _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(
                _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_ALLOW_IN_PRODUCTION", False),
                False,
            ),
            salt=salt,
            namespace=str(
                _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_NAMESPACE", _DEFAULT_NAMESPACE)
            ),
            max_records=_as_int(
                _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_MAX_RECORDS", DEFAULT_MAX_RECORDS),
                DEFAULT_MAX_RECORDS,
            ),
            max_text_length=_as_int(
                _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_MAX_TEXT_LENGTH", DEFAULT_MAX_TEXT_LENGTH),
                DEFAULT_MAX_TEXT_LENGTH,
            ),
            max_tokens_per_record=_as_int(
                _setting(
                    settings,
                    "CORRELATION_NARRATIVE_EXTRACTION_MAX_TOKENS_PER_RECORD",
                    DEFAULT_MAX_TOKENS_PER_RECORD,
                ),
                DEFAULT_MAX_TOKENS_PER_RECORD,
            ),
            min_token_length=_as_int(
                _setting(
                    settings,
                    "CORRELATION_NARRATIVE_EXTRACTION_MIN_TOKEN_LENGTH",
                    DEFAULT_MIN_TOKEN_LENGTH,
                ),
                DEFAULT_MIN_TOKEN_LENGTH,
            ),
            max_issues=_as_int(
                _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_MAX_ISSUES", DEFAULT_MAX_ISSUES),
                DEFAULT_MAX_ISSUES,
            ),
            max_summary_items=_as_int(
                _setting(
                    settings,
                    "CORRELATION_NARRATIVE_EXTRACTION_MAX_SUMMARY_ITEMS",
                    DEFAULT_MAX_SUMMARY_ITEMS,
                ),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_time_ms=_as_int(
                _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_MAX_TIME_MS", DEFAULT_MAX_TIME_MS),
                DEFAULT_MAX_TIME_MS,
            ),
            drop_forbidden_fields=_as_bool(
                _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_DROP_FORBIDDEN_FIELDS", True),
                True,
            ),
            include_token_hashes=_as_bool(
                _setting(settings, "CORRELATION_NARRATIVE_EXTRACTION_INCLUDE_TOKEN_HASHES", True),
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
                "max_text_length": self.max_text_length,
                "max_tokens_per_record": self.max_tokens_per_record,
                "min_token_length": self.min_token_length,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_time_ms": self.max_time_ms,
            },
            "flags": {
                "drop_forbidden_fields": self.drop_forbidden_fields,
                "include_token_hashes": self.include_token_hashes,
            },
        }


# -----------------------------------------------------------------------------
# Request model
# -----------------------------------------------------------------------------


_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "complaints",
        "cases",
        "alerts",
        "notes",
        "metadata",
        "tags",
        "request_id",
        "idempotency_key",
    }
)


@dataclass(slots=True)
class NarrativeExtractionRequest:
    """
    Bounded narrative extraction request.
    """

    complaints: Any = None
    cases: Any = None
    alerts: Any = None
    notes: Any = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    tags: Sequence[str] = field(default_factory=tuple)
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        self.metadata = _as_mapping(self.metadata)
        self.tags = _normalize_tags(self.tags)
        self.request_id = _clean_text(self.request_id, 128) or None
        self.idempotency_key = _clean_text(self.idempotency_key, 200) or None


def _coerce_request(request: Any) -> NarrativeExtractionRequest:
    if isinstance(request, NarrativeExtractionRequest):
        return request

    if isinstance(request, Mapping):
        payload = dict(request)

        if any(key in payload for key in _REQUEST_KEYS):
            fields = set(getattr(NarrativeExtractionRequest, "__dataclass_fields__", {}).keys())
            clean = {key: value for key, value in payload.items() if key in fields}

            try:
                return NarrativeExtractionRequest(**clean)
            except Exception:
                return NarrativeExtractionRequest(metadata=request)

        return NarrativeExtractionRequest(metadata=request)

    return NarrativeExtractionRequest(metadata=request)


# -----------------------------------------------------------------------------
# Candidate and result models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExtractedNarrative:
    """
    One bounded extracted narrative feature set.

    Raw text is never retained. Only structural counts and salted token hashes
    are exposed for private downstream similarity matching.
    """

    extraction_id: str = ""
    category: NarrativeCategory | str = NarrativeCategory.OTHER
    source_index: int = 0
    subject_ref_hash: Optional[str] = None
    char_count: int = 0
    token_count: int = 0
    unique_token_count: int = 0
    token_hashes: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "category",
            _normalize_enum_option(NarrativeCategory, self.category, NarrativeCategory.OTHER),
        )
        object.__setattr__(self, "source_index", max(0, _as_int(self.source_index, 0)))
        object.__setattr__(
            self,
            "subject_ref_hash",
            _clean_text(self.subject_ref_hash, MAX_HASH_LENGTH).lower() or None,
        )
        object.__setattr__(self, "char_count", max(0, _as_int(self.char_count, 0)))
        object.__setattr__(self, "token_count", max(0, _as_int(self.token_count, 0)))
        object.__setattr__(self, "unique_token_count", max(0, _as_int(self.unique_token_count, 0)))
        object.__setattr__(
            self,
            "token_hashes",
            tuple(
                _clean_text(h, 64).lower()
                for h in (self.token_hashes or ())
                if _clean_text(h, 64)
            )[:500],
        )
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.extraction_id:
            object.__setattr__(
                self,
                "extraction_id",
                _fingerprint_payload(
                    {
                        "category": _enum_value(self.category),
                        "source_index": self.source_index,
                        "subject": self.subject_ref_hash,
                        "char_count": self.char_count,
                        "token_count": self.token_count,
                    }
                )[:32],
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "extraction_id": self.extraction_id,
            "category": _enum_value(self.category, NarrativeCategory.OTHER.value),
            "source_index": int(self.source_index),
            "subject_ref_hash": self.subject_ref_hash,
            "char_count": int(self.char_count),
            "token_count": int(self.token_count),
            "unique_token_count": int(self.unique_token_count),
            "token_hashes": list(self.token_hashes),
            "metadata": _safe_detail_value(self.metadata),
            "raw_narrative_retained": False,
            "raw_pii_retained": False,
            "caveats": list(NARRATIVE_EXTRACTION_CAVEATS),
            "safety_flags": dict(NARRATIVE_EXTRACTION_SAFETY_FLAGS),
        }


@dataclass(frozen=True, slots=True)
class NarrativeExtractionResult:
    """
    Safe bounded narrative extraction result.
    """

    ok: bool = True
    status: ExtractionStatus | str = ExtractionStatus.PASSED
    request_id: str = ""
    generated_at: datetime = field(default_factory=_now_utc)
    duration_ms: int = 0
    extractions: tuple[ExtractedNarrative, ...] = ()
    counts: Mapping[str, int] = field(default_factory=dict)
    issues: tuple["NarrativeExtractionIssue", ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(
            self,
            "status",
            _normalize_enum_option(ExtractionStatus, self.status, ExtractionStatus.PASSED),
        )
        object.__setattr__(self, "request_id", _clean_text(self.request_id, 128))
        object.__setattr__(self, "generated_at", _ensure_utc(self.generated_at) or _now_utc())
        object.__setattr__(self, "duration_ms", max(0, _as_int(self.duration_ms, 0)))
        object.__setattr__(self, "extractions", tuple(self.extractions or ()))
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
                        "version": NARRATIVE_EXTRACTION_VERSION,
                        "ok": self.ok,
                        "status": _enum_value(self.status, ExtractionStatus.PASSED.value),
                        "request_id": self.request_id,
                        "extraction_count": len(self.extractions),
                        "extraction_ids": [ext.extraction_id for ext in self.extractions[:64]],
                        "counts": self.counts,
                        "issue_count": len(self.issues),
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": _enum_value(self.status, ExtractionStatus.PASSED.value),
            "request_id": self.request_id,
            "generated_at": self.generated_at.isoformat(),
            "duration_ms": int(self.duration_ms),
            "extractions": [ext.to_dict() for ext in self.extractions],
            "counts": dict(self.counts),
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(NARRATIVE_EXTRACTION_CAVEATS),
            "safety_flags": dict(NARRATIVE_EXTRACTION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Internal models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NarrativeExtractionIssue:
    """
    Safe narrative extraction issue.
    """

    severity: IssueSeverity
    code: str
    message: str
    field: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _normalize_unicode(value: Any) -> str:
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


def _subject_hash(value: Any, options: NarrativeExtractionOptions) -> Optional[str]:
    text = _clean_text(value, MAX_TEXT_LENGTH)

    if not text:
        return None

    if _is_safe_hash(text):
        return text.lower()

    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.correlation.narrative_extraction.subject.{namespace}"
    return _hmac_hex(options.salt, domain, text)[:40]


def _token_hash(value: str, options: NarrativeExtractionOptions) -> str:
    namespace = _normalize_token(options.namespace) or _DEFAULT_NAMESPACE
    domain = f"muleguard.correlation.narrative_extraction.token.{namespace}"
    return _hmac_hex(options.salt, domain, value.lower())[:32]


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

    if isinstance(data, NarrativeExtractionResult):
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
        for key in (*SUBJECT_KEYS, *NARRATIVE_KEYS):
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
    options: NarrativeExtractionOptions,
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
    issues: list[NarrativeExtractionIssue],
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

        issues[-1] = NarrativeExtractionIssue(
            severity=IssueSeverity.WARNING,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        NarrativeExtractionIssue(
            severity=severity,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[NarrativeExtractionIssue]) -> bool:
    return any(issue.severity == IssueSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[NarrativeExtractionIssue]) -> tuple[NarrativeExtractionIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[NarrativeExtractionIssue] = []

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
# Sanitization and Extraction
# -----------------------------------------------------------------------------


def _extract_narrative_text(view: Mapping[str, Any]) -> Optional[str]:
    for key in NARRATIVE_KEYS:
        if key in view and view[key] is not None:
            text = _normalize_unicode(view[key]).strip()
            if text:
                return text
    return None


def _sanitize_record(
    record: Any,
    category: NarrativeCategory,
    options: NarrativeExtractionOptions,
    issues: list[NarrativeExtractionIssue],
    index: int,
    start_time: float,
) -> Optional[ExtractedNarrative]:
    if _time_exceeded(start_time, options.max_time_ms):
        return None

    view = _extract_view(record)
    subject = _extract_subject(record, options, view)
    raw_text = _extract_narrative_text(view)

    if raw_text is None:
        _append_issue(
            issues,
            options.max_issues,
            severity=IssueSeverity.INFO,
            code="missing_narrative_text",
            message="Record is missing a valid narrative text field.",
            field="narrative",
            details={"category": category.value, "index": index},
        )
        return None

    # Check for forbidden fields in the view
    for raw_key in view:
        canonical = _canonical_field_name(raw_key)
        if _is_forbidden_key(canonical) or _is_label_leakage_key(canonical):
            if options.drop_forbidden_fields:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="forbidden_field_dropped",
                    message="Forbidden or leakage-prone field omitted.",
                    field=canonical,
                    details={"category": category.value, "index": index},
                )
            else:
                _append_issue(
                    issues,
                    options.max_issues,
                    severity=IssueSeverity.ERROR,
                    code="forbidden_field",
                    message="Forbidden or leakage-prone field rejected.",
                    field=canonical,
                    details={"category": category.value, "index": index},
                )
                return None

    # Truncate raw text immediately
    bounded_text = raw_text[: int(options.max_text_length)]
    char_count = len(bounded_text)

    # Tokenize and hash
    raw_tokens = TOKEN_RE.findall(bounded_text.lower())
    
    filtered_tokens = [
        t for t in raw_tokens if len(t) >= int(options.min_token_length)
    ][: int(options.max_tokens_per_record)]

    token_count = len(filtered_tokens)
    unique_tokens = set(filtered_tokens)
    unique_token_count = len(unique_tokens)

    token_hashes: tuple[str, ...] = ()
    if options.include_token_hashes:
        token_hashes = tuple(
            _token_hash(t, options) for t in sorted(unique_tokens)
        )

    return ExtractedNarrative(
        category=category,
        source_index=index,
        subject_ref_hash=subject,
        char_count=char_count,
        token_count=token_count,
        unique_token_count=unique_token_count,
        token_hashes=token_hashes,
        metadata={
            "raw_narrative_retained": False,
            "raw_pii_retained": False,
            "text_truncated": len(raw_text) > int(options.max_text_length),
            "tokens_truncated": len(raw_tokens) > int(options.max_tokens_per_record),
        },
    )


def _sanitize_category(
    raw_records: Sequence[Any],
    category: NarrativeCategory,
    options: NarrativeExtractionOptions,
    issues: list[NarrativeExtractionIssue],
    start_time: float,
) -> list[ExtractedNarrative]:
    cleaned: list[ExtractedNarrative] = []

    for source_index, record in enumerate(raw_records):
        if _time_exceeded(start_time, options.max_time_ms):
            _append_issue(
                issues,
                options.max_issues,
                severity=IssueSeverity.WARNING,
                code="sanitization_time_budget_exhausted",
                message="Sanitization stopped after reaching configured time budget.",
                details={
                    "category": category.value,
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
# Engine
# -----------------------------------------------------------------------------


class NarrativeExtractionEngine:
    """
    Bounded deterministic synthetic narrative extraction engine.
    """

    def __init__(self, options: NarrativeExtractionOptions | None = None) -> None:
        self.options = options or NarrativeExtractionOptions.from_settings()
        self._lock = threading.RLock()

    def extract(self, request: Any) -> NarrativeExtractionResult:
        """
        Run one bounded synthetic narrative extraction job.
        """
        opts = self.options
        issues: list[NarrativeExtractionIssue] = []
        start_time = time.monotonic()

        req = _coerce_request(request)

        request_id = req.request_id or _sha256_hex(
            _canonical_json(
                {
                    "version": NARRATIVE_EXTRACTION_VERSION,
                    "metadata": _safe_detail_value(req.metadata),
                    "tags": list(req.tags),
                    "idempotency_key": req.idempotency_key,
                }
            )
        )[:32]

        def make_result(
            ok: bool,
            status: ExtractionStatus,
            extractions: Sequence[ExtractedNarrative] = (),
            counts: Optional[Mapping[str, int]] = None,
        ) -> NarrativeExtractionResult:
            resolved_counts: dict[str, int] = {
                "submitted": 0,
                "extracted": len(extractions),
                "issues": len(issues),
            }

            if counts:
                resolved_counts.update(
                    {str(key): max(0, _as_int(value, 0)) for key, value in counts.items()}
                )

            resolved_counts["issues"] = len(issues)

            metadata = {
                "narrative_extraction_version": NARRATIVE_EXTRACTION_VERSION,
                "request_id": request_id,
                "idempotency_key": req.idempotency_key,
                "tags": list(req.tags),
                "request_metadata": _safe_detail_value(req.metadata),
                "options": opts.safe_summary(),
                "elapsed_ms": _elapsed_ms(start_time),
                "raw_narratives_retained": False,
                "raw_pii_retained": False,
                "subject_label_pairs_retained": False,
                "secrets_retained": False,
                "caveats": list(NARRATIVE_EXTRACTION_CAVEATS),
                "safety_flags": dict(NARRATIVE_EXTRACTION_SAFETY_FLAGS),
            }

            return NarrativeExtractionResult(
                ok=ok,
                status=status,
                request_id=request_id,
                generated_at=_now_utc(),
                duration_ms=_elapsed_ms(start_time),
                extractions=tuple(extractions),
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
                code="narrative_extraction_engine_disabled",
                message="Narrative extraction engine is disabled.",
            )
            return make_result(False, ExtractionStatus.BLOCKED)

        if opts.synthetic_required and opts.dataset_mode != "synthetic":
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="non_synthetic_dataset",
                message="Narrative extraction engine requires synthetic dataset mode.",
                details={"dataset_mode": opts.dataset_mode},
            )
            return make_result(False, ExtractionStatus.BLOCKED)

        if opts.production_like and not opts.allow_in_production:
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="production_like_blocked",
                message="Narrative extraction engine is blocked in production-like environments.",
            )
            return make_result(False, ExtractionStatus.BLOCKED)

        if _contains_prohibited_action(req.metadata, req.tags):
            _append_issue(
                issues,
                opts.max_issues,
                severity=IssueSeverity.ERROR,
                code="prohibited_narrative_extraction_action_metadata",
                message="Request metadata contains prohibited adverse-action language.",
            )
            return make_result(False, ExtractionStatus.BLOCKED)

        with self._lock:
            category_sources: tuple[tuple[str, NarrativeCategory, Any], ...] = (
                ("complaint", NarrativeCategory.COMPLAINT, req.complaints),
                ("case", NarrativeCategory.CASE, req.cases),
                ("alert", NarrativeCategory.ALERT, req.alerts),
                ("note", NarrativeCategory.NOTE, req.notes),
            )

            all_extractions: list[ExtractedNarrative] = []
            counts: dict[str, int] = {}
            submitted = 0

            for category_name, category_enum, raw_data in category_sources:
                raw_records = _iter_records(raw_data)[: opts.max_records]
                submitted += len(raw_records)
                counts[f"{category_name}_submitted"] = len(raw_records)

                extracted = _sanitize_category(
                    raw_records,
                    category_enum,
                    opts,
                    issues,
                    start_time,
                )

                counts[f"{category_name}_extracted"] = len(extracted)
                all_extractions.extend(extracted)

            if submitted > int(opts.max_records):
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="narrative_extraction_input_truncated",
                    message="Narrative extraction input exceeded configured record limit and was truncated.",
                    details={
                        "submitted": submitted,
                        "max_records": int(opts.max_records),
                    },
                )
                all_extractions = all_extractions[: int(opts.max_records)]

            counts["submitted"] = submitted
            counts["extracted"] = len(all_extractions)

            if not all_extractions:
                _append_issue(
                    issues,
                    opts.max_issues,
                    severity=IssueSeverity.WARNING,
                    code="empty_narrative_extraction_input",
                    message="No valid narratives remained for extraction.",
                )
                return make_result(False, ExtractionStatus.SKIPPED, counts=counts)

            status = ExtractionStatus.PASSED

            if _has_error(issues):
                status = ExtractionStatus.FAILED
            elif any(issue.severity == IssueSeverity.WARNING for issue in issues):
                status = ExtractionStatus.DEGRADED

            return make_result(
                ok=status in {ExtractionStatus.PASSED, ExtractionStatus.DEGRADED},
                status=status,
                extractions=all_extractions,
                counts=counts,
            )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "options": self.options.safe_summary(),
            "caveats": list(NARRATIVE_EXTRACTION_CAVEATS),
            "safety_flags": dict(NARRATIVE_EXTRACTION_SAFETY_FLAGS),
        }


# -----------------------------------------------------------------------------
# Default engine and public API
# -----------------------------------------------------------------------------


_default_engine: Optional[NarrativeExtractionEngine] = None
_default_engine_lock = threading.Lock()


def get_narrative_extraction_options(
    settings: Any | None = None,
) -> NarrativeExtractionOptions:
    """
    Return narrative extraction options from settings.
    """
    return NarrativeExtractionOptions.from_settings(settings)


def get_narrative_extraction_engine(
    options: NarrativeExtractionOptions | None = None,
    *,
    rebuild: bool = False,
) -> NarrativeExtractionEngine:
    """
    Return a process-wide narrative extraction engine.
    """
    global _default_engine

    with _default_engine_lock:
        if _default_engine is None or rebuild or options is not None:
            _default_engine = NarrativeExtractionEngine(
                options=options or NarrativeExtractionOptions.from_settings()
            )

        return _default_engine


def extract_narratives(
    request: Any,
    options: NarrativeExtractionOptions | None = None,
    *,
    engine: NarrativeExtractionEngine | None = None,
) -> NarrativeExtractionResult:
    """
    Extract bounded structural features from synthetic narratives.
    """
    active_engine = engine or get_narrative_extraction_engine(options)
    return active_engine.extract(request)


def export_narrative_extraction_summary(result: NarrativeExtractionResult) -> dict[str, Any]:
    """
    Export a safe public narrative extraction summary.
    """
    return result.to_dict()


def get_narrative_extraction_health(
    *,
    engine: NarrativeExtractionEngine | None = None,
) -> dict[str, Any]:
    """
    Return safe narrative extraction engine health.
    """
    active_engine = engine or get_narrative_extraction_engine()
    opts = active_engine.options
    issues: list[NarrativeExtractionIssue] = []

    if not opts.enabled:
        status = "DISABLED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.INFO,
            code="narrative_extraction_engine_disabled",
            message="Narrative extraction engine is disabled.",
        )
    elif opts.synthetic_required and opts.dataset_mode != "synthetic":
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="non_synthetic_dataset",
            message="Narrative extraction engine requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
    elif opts.production_like and not opts.allow_in_production:
        status = "BLOCKED"
        _append_issue(
            issues,
            opts.max_issues,
            severity=IssueSeverity.ERROR,
            code="production_like_blocked",
            message="Narrative extraction engine is blocked in production-like environments.",
        )
    else:
        status = "OK"

    return {
        "status": status,
        "enabled": opts.enabled,
        "options": opts.safe_summary(),
        "issues": [issue.to_dict() for issue in issues],
        "caveats": list(NARRATIVE_EXTRACTION_CAVEATS),
        "safety_flags": dict(NARRATIVE_EXTRACTION_SAFETY_FLAGS),
    }


def get_narrative_extraction_metadata(
    *,
    limit: int = DEFAULT_MAX_SUMMARY_ITEMS,
) -> dict[str, Any]:
    """
    Return safe, serializable narrative extraction metadata.
    """
    options = NarrativeExtractionOptions.from_settings()

    return {
        "package": "muleguard.backend.correlation.narrative_extraction",
        "version": NARRATIVE_EXTRACTION_VERSION,
        "narrative_categories": [cat.value for cat in NarrativeCategory],
        "extraction_statuses": [status.value for status in ExtractionStatus],
        "issue_severities": [severity.value for severity in IssueSeverity],
        "narrative_keys": list(NARRATIVE_KEYS),
        "default_options": options.safe_summary(),
        "hard_limits": {
            "max_records": HARD_MAX_RECORDS,
            "max_text_length": HARD_MAX_TEXT_LENGTH,
            "max_tokens_per_record": HARD_MAX_TOKENS_PER_RECORD,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_time_ms": HARD_MAX_TIME_MS,
        },
        "forbidden_field_count": len(FORBIDDEN_FIELDS),
        "label_leakage_field_count": len(LABEL_LEAKAGE_FIELDS),
        "prohibited_action_token_count": len(PROHIBITED_ACTION_TOKENS),
        "summary_item_limit": max(1, int(limit)),
        "caveats": list(NARRATIVE_EXTRACTION_CAVEATS),
        "safety_flags": dict(NARRATIVE_EXTRACTION_SAFETY_FLAGS),
    }


__all__ = [
    "ExtractedNarrative",
    "ExtractionStatus",
    "IssueSeverity",
    "NARRATIVE_EXTRACTION_VERSION",
    "NarrativeCategory",
    "NarrativeExtractionEngine",
    "NarrativeExtractionIssue",
    "NarrativeExtractionOptions",
    "NarrativeExtractionRequest",
    "NarrativeExtractionResult",
    "export_narrative_extraction_summary",
    "extract_narratives",
    "get_narrative_extraction_engine",
    "get_narrative_extraction_health",
    "get_narrative_extraction_metadata",
    "get_narrative_extraction_options",
]