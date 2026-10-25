"""
MULEGUARD backend ingestion validators.

This module provides the canonical validation layer for synthetic MULEGUARD
ingestion workflows.

Primary responsibilities:

- validate bounded ingestion batches for accounts, transactions, complaints,
  pseudonymous entities, and account-entity links;
- enforce strict, deterministic, privacy-preserving record schemas;
- reject leakage-prone fields such as ground-truth labels, scenario IDs,
  fraud-ring IDs, raw identifiers, secrets, tokens, passwords, database URLs,
  and model artifact paths;
- enforce bounded batch sizes, error-reporting limits, narrative limits,
  metadata depth limits, future-timestamp tolerance, and duplicate handling;
- preserve referential integrity across generated and persisted synthetic
  records;
- return safe, structured validation results without exposing raw complaint
  narratives or sensitive values in errors, warnings, or summaries;
- remain import-safe and usable by API endpoints, services, seeders, tests, and
  offline fixtures.

This module validates records only. It does not persist data, call external
systems, train models, generate reports, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be ingested.
- Ground-truth labels, injected scenario IDs, and fraud-ring IDs must not be
  accepted, persisted, returned, logged, or exported.
- Raw complaint narratives may be accepted only for controlled synthetic
  complaint ingestion, but are never returned in validation summaries,
  errors, warnings, or diagnostics.
- Entity identifiers must be pseudonymously hashed. Raw identifiers are not
  accepted.
- Secrets, tokens, passwords, database URLs, model artifact paths, and raw
  sensitive identifiers are never logged or returned.
- Validation is bounded and deterministic.
- Duplicate handling is explicit and configurable.
- Referential integrity is enforced when enabled.
- Validation never triggers automatic adverse customer action such as freezing,
  blocking, blacklisting, closing, or restricting accounts.
- Ingested records are investigative inputs only. They are not proof of
  wrongdoing.

Explicit non-goals:

- This module does not write to the database.
- This module does not call real banking systems.
- This module does not authenticate or authorize users.
- This module does not generate synthetic data.
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Final, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic import ValidationError as PydanticValidationError

from app.core.vocabularies import (
    AccountStatus,
    AccountType,
    Channel,
    EntityType,
    MatchMethod,
    TransactionStatus,
    VerificationState,
)

logger = logging.getLogger("muleguard.backend.ingestion.validators")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

VALIDATORS_VERSION: Final[str] = "v1"
SOURCE_SYSTEM_DEFAULT: Final[str] = "api"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

DATASET_MODE_SYNTHETIC: Final[str] = "synthetic"

DUPLICATE_STRATEGY_REJECT: Final[str] = "reject"
DUPLICATE_STRATEGY_SKIP: Final[str] = "skip"
DUPLICATE_STRATEGIES: Final[tuple[str, ...]] = (
    DUPLICATE_STRATEGY_REJECT,
    DUPLICATE_STRATEGY_SKIP,
)

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

DEFAULT_FUTURE_TOLERANCE_MINUTES: Final[int] = 5

DEFAULT_MAX_NARRATIVE_LENGTH: Final[int] = 20_000
HARD_MAX_NARRATIVE_LENGTH: Final[int] = 100_000

DEFAULT_MAX_METADATA_DEPTH: Final[int] = 6
HARD_MAX_METADATA_DEPTH: Final[int] = 12

DEFAULT_MAX_LIST_LENGTH: Final[int] = 100
HARD_MAX_LIST_LENGTH: Final[int] = 1_000

DEFAULT_MAX_MAPPING_KEYS: Final[int] = 100
HARD_MAX_MAPPING_KEYS: Final[int] = 1_000

MAX_ID_LENGTH: Final[int] = 128
MAX_REFERENCE_LENGTH: Final[int] = 128
MAX_STRING_LENGTH: Final[int] = 512
MAX_CATEGORY_LENGTH: Final[int] = 100
MAX_SOURCE_LENGTH: Final[int] = 100
MAX_DISPLAY_LENGTH: Final[int] = 200

MIN_IDENTIFIER_HASH_LENGTH: Final[int] = 32
MAX_IDENTIFIER_HASH_LENGTH: Final[int] = 128

MAX_AMOUNT: Final[Decimal] = Decimal("1E30")
MONEY_QUANT: Final[Decimal] = Decimal("0.01")
CONFIDENCE_QUANT: Final[Decimal] = Decimal("0.0001")

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{32,128}$")
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")

# Accepted vocabularies, derived from the persisted enums.
#
# Validation is the last gate before the database, so the one place these may
# come from is the enums the columns are declared over. They used to be listed
# here, and they disagreed with those enums on every field: SAVINGS was an
# accepted account type and INDIVIDUAL — the only kind the column can hold —
# was refused, so a correct record failed validation and an accepted one
# failed to insert.
#
# `app.ingestion.normalizers` derives the same sets from the same source, so
# the normalizer and the validator cannot disagree with each other either.
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
        "device_id",
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

_FORBIDDEN_TOP_LEVEL_TOKENS: Final[tuple[str, ...]] = (
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

_KNOWN_VALUE_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "amount_required",
        "amount_too_large",
        "currency_required_with_amount",
        "currency_without_amount",
        "duplicate_record",
        "future_timestamp",
        "identifier_invalid",
        "identifier_required",
        "identifier_hash_invalid",
        "invalid_amount",
        "invalid_category",
        "invalid_channel",
        "invalid_confidence",
        "invalid_enum",
        "invalid_identifier",
        "invalid_reference",
        "invalid_source",
        "invalid_timestamp",
        "invalid_time_range",
        "metadata_too_deep",
        "metadata_too_many_items",
        "metadata_too_many_keys",
        "narrative_required",
        "narrative_too_long",
        "non_synthetic_dataset",
        "record_not_object",
        "self_reference_transaction",
        "same_victim_and_suspect",
        "timestamp_after_allowed_range",
        "timestamp_before_allowed_range",
        "unsupported_entity_type",
        "unsupported_metadata_value",
        "batch_too_large",
        "forbidden_field",
        "unknown_field",
        "missing_field",
        "unknown_account",
        "unknown_entity",
        "unknown_transaction_reference",
        "error_list_truncated",
        "warning_list_truncated",
    }
)

_VALIDATOR_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype ingestion validation only. Do not use with real customer data.",
    "Validated records are investigative inputs only and are not proof of wrongdoing.",
    "Validation must not trigger automatic adverse customer action.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are rejected.",
    "Raw complaint narratives are never returned in validation summaries, errors, or warnings.",
    "Entity identifiers must be pseudonymously hashed. Raw identifiers are rejected.",
    "Batch processing is bounded by configured batch size and error-reporting limits.",
    "Duplicate handling is deterministic and configurable.",
    "Referential integrity is enforced when enabled.",
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


def _parse_datetime(value: Any, default: Optional[datetime] = None) -> Optional[datetime]:
    """
    Parse a datetime-like value into timezone-aware UTC.
    """
    if isinstance(value, datetime):
        return _ensure_utc(value)

    text = str(value or "").strip()

    if not text:
        return default

    try:
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"

        parsed = datetime.fromisoformat(text)
        return _ensure_utc(parsed)
    except Exception:
        return default


def _normalize_currency(value: Any) -> str:
    """
    Normalize a currency code.
    """
    text = str(value or "INR").strip().upper()

    if _CURRENCY_RE.match(text):
        return text

    return "INR"


def _clean_text(value: Any, limit: int = MAX_STRING_LENGTH) -> str:
    """
    Return a safe single-line text value.
    """
    text = str(value if value is not None else "")
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if len(text) > limit:
        return text[:limit]

    return text


def _clean_narrative(value: Any, limit: int = DEFAULT_MAX_NARRATIVE_LENGTH) -> str:
    """
    Return bounded synthetic narrative text.

    Control characters are removed. Normal whitespace is preserved.
    """
    text = str(value if value is not None else "")
    text = text.replace("\x00", "")
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.strip()

    if len(text) > limit:
        return text[:limit]

    return text


def _normalize_token(value: Any) -> str:
    """
    Normalize a token-like value to uppercase underscore form.
    """
    return str(value if value is not None else "").strip().upper().replace(" ", "_").replace("-", "_")


def _normalize_lower_token(value: Any) -> str:
    """
    Normalize a lower-case token-like value.
    """
    return str(value if value is not None else "").strip().lower().replace(" ", "_").replace("-", "_")


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
        "entity_links": "entity_links",
        "account_entity_link": "entity_links",
        "account_entity_links": "entity_links",
    }

    return aliases.get(text, text)


def _normalize_duplicate_strategy(value: Any, default: str = DUPLICATE_STRATEGY_REJECT) -> str:
    """
    Normalize a duplicate-handling strategy.
    """
    text = _normalize_lower_token(value)

    aliases = {
        "fail": DUPLICATE_STRATEGY_REJECT,
        "error": DUPLICATE_STRATEGY_REJECT,
        "deny": DUPLICATE_STRATEGY_REJECT,
        "drop": DUPLICATE_STRATEGY_SKIP,
        "ignore": DUPLICATE_STRATEGY_SKIP,
        "silent": DUPLICATE_STRATEGY_SKIP,
    }

    resolved = aliases.get(text, text)

    if resolved in DUPLICATE_STRATEGIES:
        return resolved

    return default


def _is_sensitive_metadata_key(key: str) -> bool:
    """
    Return True when a metadata key appears sensitive or leakage-prone.
    """
    lowered = key.strip().lower()
    return any(token in lowered for token in _SENSITIVE_METADATA_TOKENS)


def _is_forbidden_top_level_key(key: str) -> bool:
    """
    Return True when a top-level record key is forbidden.

    Complaint narrative_raw is intentionally allowed for controlled synthetic
    complaint ingestion. It is never returned in validation summaries.
    """
    lowered = key.strip().lower()

    if lowered == "narrative_raw":
        return False

    if lowered in FORBIDDEN_TOP_LEVEL_KEYS:
        return True

    if lowered.startswith("raw_") or (lowered.endswith("_raw") and lowered != "narrative_raw"):
        return True

    return any(token in lowered for token in _FORBIDDEN_TOP_LEVEL_TOKENS)


def _is_production_like_settings(settings: Any) -> bool:
    """
    Return True when the runtime environment is production-like.
    """
    env = str(_setting(settings, "BACKEND_ENV", "local")).strip().lower()

    configured_values = _csv(
        _setting(
            settings,
            "BACKEND_PRODUCTION_LIKE_ENVS",
            "production,staging,prod,stage",
        )
    )

    production_like_values = {value.lower() for value in configured_values}

    if not production_like_values:
        production_like_values = {"production", "staging", "prod", "stage"}

    return env in production_like_values


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IngestionValidationOptions:
    """
    Bounded ingestion validation policy.

    Hard caps prevent client-controlled or configuration-controlled unbounded
    validation surfaces.
    """

    max_batch_size: int = DEFAULT_MAX_BATCH_SIZE
    max_errors_returned: int = DEFAULT_MAX_ERRORS_RETURNED
    max_warnings_returned: int = DEFAULT_MAX_WARNINGS_RETURNED
    future_tolerance_minutes: int = DEFAULT_FUTURE_TOLERANCE_MINUTES

    max_narrative_length: int = DEFAULT_MAX_NARRATIVE_LENGTH
    max_metadata_depth: int = DEFAULT_MAX_METADATA_DEPTH
    max_list_length: int = DEFAULT_MAX_LIST_LENGTH
    max_mapping_keys: int = DEFAULT_MAX_MAPPING_KEYS

    duplicate_strategy: str = DUPLICATE_STRATEGY_REJECT
    enforce_referential_integrity: bool = True

    synthetic_required: bool = True
    dataset_mode: str = DATASET_MODE_SYNTHETIC
    production_like: bool = False

    source_system: Optional[str] = None
    min_date: Optional[datetime] = None
    max_date: Optional[datetime] = None

    def __post_init__(self) -> None:
        """
        Normalize and clamp option values.
        """
        hard_max_batch_size = max(
            1,
            _as_int(self.max_batch_size, DEFAULT_MAX_BATCH_SIZE),
        )

        object.__setattr__(
            self,
            "max_batch_size",
            _clamp_int(
                self.max_batch_size,
                1,
                min(hard_max_batch_size, HARD_MAX_BATCH_SIZE),
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
            "future_tolerance_minutes",
            max(0, _as_int(self.future_tolerance_minutes, DEFAULT_FUTURE_TOLERANCE_MINUTES)),
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
            "duplicate_strategy",
            _normalize_duplicate_strategy(self.duplicate_strategy),
        )

        object.__setattr__(
            self,
            "enforce_referential_integrity",
            _as_bool(self.enforce_referential_integrity, True),
        )

        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_lower_token(self.dataset_mode) or DATASET_MODE_SYNTHETIC)
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))

        if self.source_system is not None:
            source = _clean_text(self.source_system, MAX_SOURCE_LENGTH)
            object.__setattr__(self, "source_system", source or None)

        min_date = _ensure_utc(self.min_date) if isinstance(self.min_date, datetime) else _parse_datetime(self.min_date)
        max_date = _ensure_utc(self.max_date) if isinstance(self.max_date, datetime) else _parse_datetime(self.max_date)

        if min_date is not None and max_date is not None and max_date < min_date:
            min_date, max_date = max_date, min_date

        object.__setattr__(self, "min_date", min_date)
        object.__setattr__(self, "max_date", max_date)

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "IngestionValidationOptions":
        """
        Build validation options from runtime settings with safe defaults.
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
            max_warnings_returned=max(1, min(max_errors // 2 or DEFAULT_MAX_WARNINGS_RETURNED, HARD_MAX_WARNINGS_RETURNED)),
            future_tolerance_minutes=max(
                0,
                _as_int(
                    _setting(
                        settings,
                        "INGESTION_FUTURE_TOLERANCE_MINUTES",
                        DEFAULT_FUTURE_TOLERANCE_MINUTES,
                    ),
                    DEFAULT_FUTURE_TOLERANCE_MINUTES,
                ),
            ),
            max_narrative_length=max_narrative,
            max_metadata_depth=max_depth,
            max_list_length=max_list,
            max_mapping_keys=max_mapping,
            duplicate_strategy=_normalize_duplicate_strategy(
                _setting(settings, "INGESTION_DUPLICATE_STRATEGY", DUPLICATE_STRATEGY_REJECT)
            ),
            enforce_referential_integrity=_as_bool(
                _setting(settings, "INGESTION_ENFORCE_REFERENTIAL_INTEGRITY", True),
                True,
            ),
            synthetic_required=_as_bool(
                _setting(settings, "INGESTION_REQUIRE_SYNTHETIC", True),
                True,
            ),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", DATASET_MODE_SYNTHETIC)).strip().lower(),
            production_like=_is_production_like_settings(settings),
            source_system=_clean_text(
                _setting(settings, "INGESTION_SOURCE_SYSTEM", SOURCE_SYSTEM_DEFAULT),
                MAX_SOURCE_LENGTH,
            )
            or SOURCE_SYSTEM_DEFAULT,
            min_date=_parse_datetime(_setting(settings, "SYNTHETIC_DATE_START", None)),
            max_date=_parse_datetime(_setting(settings, "SYNTHETIC_DATE_END", None)),
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable summary of validation options.
        """
        return {
            "max_batch_size": self.max_batch_size,
            "max_errors_returned": self.max_errors_returned,
            "max_warnings_returned": self.max_warnings_returned,
            "future_tolerance_minutes": self.future_tolerance_minutes,
            "max_narrative_length": self.max_narrative_length,
            "max_metadata_depth": self.max_metadata_depth,
            "max_list_length": self.max_list_length,
            "max_mapping_keys": self.max_mapping_keys,
            "duplicate_strategy": self.duplicate_strategy,
            "enforce_referential_integrity": self.enforce_referential_integrity,
            "synthetic_required": self.synthetic_required,
            "dataset_mode": self.dataset_mode,
            "production_like": self.production_like,
            "source_system": self.source_system,
            "min_date": self.min_date.isoformat() if self.min_date else None,
            "max_date": self.max_date.isoformat() if self.max_date else None,
        }


# -----------------------------------------------------------------------------
# Metadata validation
# -----------------------------------------------------------------------------


def _validate_metadata_value(
    value: Any,
    options: IngestionValidationOptions,
    depth: int = 0,
) -> Any:
    """
    Validate and normalize arbitrary metadata into a bounded, safe structure.

    Raises ValueError with stable codes for invalid metadata.
    """
    if depth > options.max_metadata_depth:
        raise ValueError("metadata_too_deep")

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("unsupported_metadata_value")
        return value

    if isinstance(value, str):
        return _clean_text(value, MAX_STRING_LENGTH)

    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("unsupported_metadata_value")
        return str(value)

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, Mapping):
        if len(value) > options.max_mapping_keys:
            raise ValueError("metadata_too_many_keys")

        sanitized: dict[str, Any] = {}

        for raw_key, raw_value in value.items():
            key = str(raw_key)

            if _is_sensitive_metadata_key(key):
                raise ValueError("forbidden_metadata_key")

            clean_key = _clean_text(key, 128)

            if not clean_key:
                raise ValueError("invalid_metadata_key")

            sanitized[clean_key] = _validate_metadata_value(raw_value, options, depth + 1)

        return sanitized

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > options.max_list_length:
            raise ValueError("metadata_too_many_items")

        return [_validate_metadata_value(item, options, depth + 1) for item in value]

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    raise ValueError("unsupported_metadata_value")


def _sanitize_error_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return safe error details.

    Error details must never contain raw narratives, secrets, tokens,
    passwords, database URLs, model artifact paths, or sensitive identifiers.
    """
    if not details:
        return {}

    try:
        sanitized = _validate_metadata_value(details, IngestionValidationOptions())
    except ValueError:
        return {"reason": "details_sanitization_failed"}

    if isinstance(sanitized, dict):
        return sanitized

    return {"value": sanitized}


# -----------------------------------------------------------------------------
# Context and result models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class IngestionValidationContext:
    """
    Mutable validation context for referential integrity and duplicate
    detection across one or more bounded batches.
    """

    known_account_ids: set[str] = field(default_factory=set)
    known_entity_ids: set[str] = field(default_factory=set)
    known_transaction_refs: set[str] = field(default_factory=set)

    batch_account_ids: set[str] = field(default_factory=set)
    batch_entity_ids: set[str] = field(default_factory=set)
    batch_transaction_refs: set[str] = field(default_factory=set)

    seen_natural_keys: dict[str, set[tuple[str, tuple[Any, ...]]]] = field(default_factory=dict)
    now: datetime = field(default_factory=_now_utc)

    def account_exists(self, account_id: Optional[str]) -> bool:
        if not account_id:
            return False
        return account_id in self.known_account_ids or account_id in self.batch_account_ids

    def entity_exists(self, entity_id: Optional[str]) -> bool:
        if not entity_id:
            return False
        return entity_id in self.known_entity_ids or entity_id in self.batch_entity_ids

    def transaction_ref_exists(self, reference: Optional[str]) -> bool:
        if not reference:
            return False
        return reference in self.known_transaction_refs or reference in self.batch_transaction_refs

    def register_account(self, account_id: str) -> None:
        self.batch_account_ids.add(account_id)

    def register_entity(self, entity_id: str) -> None:
        self.batch_entity_ids.add(entity_id)

    def register_transaction_ref(self, reference: str) -> None:
        self.batch_transaction_refs.add(reference)

    def register_seen_key(self, entity_type: str, key_name: str, key: tuple[Any, ...]) -> None:
        self.seen_natural_keys.setdefault(entity_type, set()).add((key_name, key))

    def has_seen_key(self, entity_type: str, key_name: str, key: tuple[Any, ...]) -> bool:
        return (key_name, key) in self.seen_natural_keys.get(entity_type, set())


@dataclass(slots=True)
class IngestionValidationResult:
    """
    Safe ingestion validation result.

    The `accepted` list may contain complaint narrative text for downstream
    persistence. Public summaries deliberately exclude accepted records.
    """

    ok: bool = True
    entity_type: str = ""
    submitted: int = 0

    accepted: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[int] = field(default_factory=list)
    duplicated: list[int] = field(default_factory=list)
    skipped: list[int] = field(default_factory=list)

    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    max_errors: int = DEFAULT_MAX_ERRORS_RETURNED
    max_warnings: int = DEFAULT_MAX_WARNINGS_RETURNED

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

        if len(self.errors) >= max(1, int(self.max_errors)):
            self._error_truncated = True
            self.errors.append(
                {
                    "code": "error_list_truncated",
                    "message": "Error list truncated by configured limit.",
                    "entity_type": self.entity_type,
                }
            )
            self.ok = False
            return False

        entry: dict[str, Any] = {
            "code": _clean_text(code, 100),
            "message": _clean_text(message, 300),
            "entity_type": _clean_text(self.entity_type, 100),
        }

        if index is not None:
            entry["index"] = int(index)

        if field:
            entry["field"] = _clean_text(field, 200)

        safe_details = _sanitize_error_details(details)

        if safe_details:
            entry["details"] = safe_details

        self.errors.append(entry)
        self.ok = False
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

        if len(self.warnings) >= max(1, int(self.max_warnings)):
            self._warning_truncated = True
            self.warnings.append(
                {
                    "code": "warning_list_truncated",
                    "message": "Warning list truncated by configured limit.",
                    "entity_type": self.entity_type,
                }
            )
            return False

        entry: dict[str, Any] = {
            "code": _clean_text(code, 100),
            "message": _clean_text(message, 300),
            "entity_type": _clean_text(self.entity_type, 100),
        }

        if index is not None:
            entry["index"] = int(index)

        if field:
            entry["field"] = _clean_text(field, 200)

        safe_details = _sanitize_error_details(details)

        if safe_details:
            entry["details"] = safe_details

        self.warnings.append(entry)
        return True

    def finalize(self, options: Optional[IngestionValidationOptions] = None) -> None:
        """
        Finalize safe metadata for the result.
        """
        self.metadata.update(
            {
                "validator_version": VALIDATORS_VERSION,
                "entity_type": self.entity_type,
                "submitted": self.submitted,
                "accepted_count": len(self.accepted),
                "rejected_count": len(self.rejected),
                "duplicated_count": len(self.duplicated),
                "skipped_count": len(self.skipped),
                "error_count": len(self.errors),
                "warning_count": len(self.warnings),
                "error_truncated": self._error_truncated,
                "warning_truncated": self._warning_truncated,
            }
        )

        if options is not None:
            self.metadata["duplicate_strategy"] = options.duplicate_strategy
            self.metadata["max_batch_size"] = options.max_batch_size
            self.metadata["max_errors_returned"] = options.max_errors_returned

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include accepted records, raw narratives,
        identifier hashes, or sensitive values.
        """
        return {
            "ok": self.ok,
            "entity_type": self.entity_type,
            "counts": {
                "submitted": self.submitted,
                "accepted": len(self.accepted),
                "rejected": len(self.rejected),
                "duplicated": len(self.duplicated),
                "skipped": len(self.skipped),
            },
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
            "caveats": list(_VALIDATOR_CAVEATS),
        }


# -----------------------------------------------------------------------------
# Pydantic validation helpers
# -----------------------------------------------------------------------------


def _options_from_info(info: ValidationInfo | None) -> IngestionValidationOptions:
    """
    Resolve validation options from Pydantic validation context.
    """
    if info is None:
        return IngestionValidationOptions()

    context = info.context

    if isinstance(context, Mapping):
        options = context.get("options")

        if isinstance(options, IngestionValidationOptions):
            return options

    return IngestionValidationOptions()


def _validate_required_id(value: Any, info: ValidationInfo | None, field_name: str = "id") -> str:
    """
    Validate a required bounded identifier.
    """
    text = _clean_text(value, MAX_ID_LENGTH)

    if not text:
        raise ValueError("identifier_required")

    if not _ID_RE.match(text):
        raise ValueError("identifier_invalid")

    return text


def _validate_optional_id(value: Any, info: ValidationInfo | None) -> Optional[str]:
    """
    Validate an optional bounded identifier.

    Empty strings are normalized to None.
    """
    if value is None:
        return None

    text = _clean_text(value, MAX_ID_LENGTH)

    if not text:
        return None

    if not _ID_RE.match(text):
        raise ValueError("identifier_invalid")

    return text


def _validate_optional_reference(value: Any, info: ValidationInfo | None) -> Optional[str]:
    """
    Validate an optional bounded reference.

    Empty strings are normalized to None.
    """
    if value is None:
        return None

    text = _clean_text(value, MAX_REFERENCE_LENGTH)

    if not text:
        return None

    if not _ID_RE.match(text):
        raise ValueError("invalid_reference")

    return text


def _validate_optional_text(value: Any, info: ValidationInfo | None, limit: int = MAX_STRING_LENGTH) -> Optional[str]:
    """
    Validate optional safe text.
    """
    if value is None:
        return None

    text = _clean_text(value, limit)
    return text or None


def _validate_enum(value: Any, info: ValidationInfo | None, allowed: frozenset[str], field_name: str) -> str:
    """
    Validate a required upper-case enum-like field.
    """
    text = _normalize_token(value)

    if text in allowed:
        return text

    raise ValueError(f"invalid_{field_name}")


def _validate_lower_enum(value: Any, info: ValidationInfo | None, allowed: frozenset[str], field_name: str) -> str:
    """
    Validate a required lower-case enum-like field.
    """
    text = _normalize_lower_token(value)

    if text in allowed:
        return text

    raise ValueError(f"invalid_{field_name}")


def _validate_identifier_hash(value: Any, info: ValidationInfo | None) -> str:
    """
    Validate a pseudonymous identifier hash.

    Raw identifiers are never accepted.
    """
    text = str(value if value is not None else "").strip().lower()

    if not text:
        raise ValueError("identifier_hash_invalid")

    if len(text) < MIN_IDENTIFIER_HASH_LENGTH or len(text) > MAX_IDENTIFIER_HASH_LENGTH:
        raise ValueError("identifier_hash_invalid")

    if not _HASH_RE.match(text):
        raise ValueError("identifier_hash_invalid")

    return text


def _validate_datetime(
    value: Any,
    info: ValidationInfo | None,
    field_name: str,
    *,
    require_not_future: bool = False,
) -> datetime:
    """
    Validate a timezone-aware UTC timestamp.
    """
    options = _options_from_info(info)

    if isinstance(value, datetime):
        parsed = _ensure_utc(value)
    else:
        parsed = _parse_datetime(value)

    if parsed is None:
        raise ValueError("invalid_timestamp")

    if options.min_date is not None and parsed < options.min_date:
        raise ValueError("timestamp_before_allowed_range")

    if options.max_date is not None and parsed > options.max_date:
        raise ValueError("timestamp_after_allowed_range")

    if require_not_future:
        future_limit = _now_utc() + timedelta(minutes=options.future_tolerance_minutes)

        if parsed > future_limit:
            raise ValueError("future_timestamp")

    return parsed


def _validate_amount(
    value: Any,
    info: ValidationInfo | None,
    *,
    optional: bool = False,
) -> Optional[Decimal]:
    """
    Validate a positive bounded monetary amount.
    """
    if value is None:
        if optional:
            return None
        raise ValueError("amount_required")

    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("invalid_amount") from exc

    if not parsed.is_finite():
        raise ValueError("invalid_amount")

    if parsed <= 0:
        raise ValueError("invalid_amount")

    quantized = parsed.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    if quantized <= 0:
        raise ValueError("invalid_amount")

    if abs(quantized) > MAX_AMOUNT:
        raise ValueError("amount_too_large")

    return quantized


def _validate_confidence(value: Any, info: ValidationInfo | None) -> Optional[Decimal]:
    """
    Validate a synthetic link confidence value in [0, 1].
    """
    if value is None:
        return None

    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("invalid_confidence") from exc

    if not parsed.is_finite():
        raise ValueError("invalid_confidence")

    if parsed < 0 or parsed > 1:
        raise ValueError("invalid_confidence")

    return parsed.quantize(CONFIDENCE_QUANT, rounding=ROUND_HALF_UP)


def _validate_narrative(value: Any, info: ValidationInfo | None) -> str:
    """
    Validate bounded synthetic complaint narrative text.

    The narrative is retained for controlled persistence but is never returned
    in validation summaries.
    """
    options = _options_from_info(info)
    text = _clean_narrative(value, options.max_narrative_length)

    if not text:
        raise ValueError("narrative_required")

    if len(text) > options.max_narrative_length:
        raise ValueError("narrative_too_long")

    return text


# -----------------------------------------------------------------------------
# Pydantic ingestion models
# -----------------------------------------------------------------------------


class _IngestionBase(BaseModel):
    """
    Strict base model for ingestion records.

    Unknown fields are forbidden to reduce leakage risk and accidental acceptance
    of ground-truth, scenario, ring, raw identifier, or secret fields.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
        populate_by_name=True,
    )


class AccountIngestion(_IngestionBase):
    """
    Synthetic account ingestion record.
    """

    id: str
    account_type: str
    status: str
    created_at: datetime
    metadata_json: Optional[dict[str, Any]] = None

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_required_id(value, info, "id")

    @field_validator("account_type")
    @classmethod
    def _validate_account_type(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_enum(value, info, ACCOUNT_TYPES, "account_type")

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_enum(value, info, ACCOUNT_STATUSES, "status")

    @field_validator("created_at")
    @classmethod
    def _validate_created_at(cls, value: Any, info: ValidationInfo) -> datetime:
        return _validate_datetime(value, info, "created_at", require_not_future=True)

    @field_validator("metadata_json")
    @classmethod
    def _validate_metadata(cls, value: Any, info: ValidationInfo) -> Optional[dict[str, Any]]:
        if value is None:
            return None

        options = _options_from_info(info)
        sanitized = _validate_metadata_value(value, options)

        if sanitized is None:
            return None

        if not isinstance(sanitized, dict):
            raise ValueError("unsupported_metadata_value")

        return sanitized


class TransactionIngestion(_IngestionBase):
    """
    Synthetic transaction ingestion record.
    """

    id: str
    reference: Optional[str] = None
    sender_account_id: str
    receiver_account_id: str
    amount: Decimal
    currency: str
    occurred_at: datetime
    status: str
    channel: str
    metadata_json: Optional[dict[str, Any]] = None

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_required_id(value, info, "id")

    @field_validator("reference")
    @classmethod
    def _validate_reference(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        return _validate_optional_reference(value, info)

    @field_validator("sender_account_id", "receiver_account_id")
    @classmethod
    def _validate_account_id(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_required_id(value, info, "account_id")

    @field_validator("amount")
    @classmethod
    def _validate_amount(cls, value: Any, info: ValidationInfo) -> Decimal:
        parsed = _validate_amount(value, info, optional=False)

        if parsed is None:
            raise ValueError("amount_required")

        return parsed

    @field_validator("currency")
    @classmethod
    def _validate_currency(cls, value: Any, info: ValidationInfo) -> str:
        return _normalize_currency(value)

    @field_validator("occurred_at")
    @classmethod
    def _validate_occurred_at(cls, value: Any, info: ValidationInfo) -> datetime:
        return _validate_datetime(value, info, "occurred_at", require_not_future=True)

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_enum(value, info, TRANSACTION_STATUSES, "status")

    @field_validator("channel")
    @classmethod
    def _validate_channel(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_enum(value, info, CHANNELS, "channel")

    @field_validator("metadata_json")
    @classmethod
    def _validate_metadata(cls, value: Any, info: ValidationInfo) -> Optional[dict[str, Any]]:
        if value is None:
            return None

        options = _options_from_info(info)
        sanitized = _validate_metadata_value(value, options)

        if sanitized is None:
            return None

        if not isinstance(sanitized, dict):
            raise ValueError("unsupported_metadata_value")

        return sanitized

    @model_validator(mode="after")
    def _check_parties(self) -> "TransactionIngestion":
        if self.sender_account_id == self.receiver_account_id:
            raise ValueError("self_reference_transaction")

        return self


class ComplaintIngestion(_IngestionBase):
    """
    Synthetic complaint ingestion record.

    `narrative_raw` is accepted only for controlled synthetic complaint
    ingestion. It is never returned in validation summaries, errors, warnings,
    or diagnostics.
    """

    id: str
    reference: Optional[str] = None
    reported_at: datetime
    category: str
    narrative_raw: str
    transaction_reference: Optional[str] = None
    victim_account_id: Optional[str] = None
    suspected_account_id: Optional[str] = None
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    source: Optional[str] = None
    metadata_json: Optional[dict[str, Any]] = None

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_required_id(value, info, "id")

    @field_validator("reference", "transaction_reference")
    @classmethod
    def _validate_reference(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        return _validate_optional_reference(value, info)

    @field_validator("reported_at")
    @classmethod
    def _validate_reported_at(cls, value: Any, info: ValidationInfo) -> datetime:
        return _validate_datetime(value, info, "reported_at", require_not_future=True)

    @field_validator("category")
    @classmethod
    def _validate_category(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_lower_enum(value, info, COMPLAINT_CATEGORIES, "category")

    @field_validator("narrative_raw")
    @classmethod
    def _validate_narrative(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_narrative(value, info)

    @field_validator("victim_account_id", "suspected_account_id")
    @classmethod
    def _validate_optional_account_id(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        return _validate_optional_id(value, info)

    @field_validator("amount")
    @classmethod
    def _validate_amount(cls, value: Any, info: ValidationInfo) -> Optional[Decimal]:
        return _validate_amount(value, info, optional=True)

    @field_validator("currency")
    @classmethod
    def _validate_currency(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        if value is None:
            return None

        text = _normalize_currency(value)
        return text if text else None

    @field_validator("source")
    @classmethod
    def _validate_source(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        return _validate_optional_text(value, info, MAX_SOURCE_LENGTH)

    @field_validator("metadata_json")
    @classmethod
    def _validate_metadata(cls, value: Any, info: ValidationInfo) -> Optional[dict[str, Any]]:
        if value is None:
            return None

        options = _options_from_info(info)
        sanitized = _validate_metadata_value(value, options)

        if sanitized is None:
            return None

        if not isinstance(sanitized, dict):
            raise ValueError("unsupported_metadata_value")

        return sanitized

    @model_validator(mode="after")
    def _check_complaint_consistency(self) -> "ComplaintIngestion":
        if self.victim_account_id and self.suspected_account_id:
            if self.victim_account_id == self.suspected_account_id:
                raise ValueError("same_victim_and_suspect")

        if self.amount is not None and not self.currency:
            raise ValueError("currency_required_with_amount")

        if self.amount is None and self.currency:
            raise ValueError("currency_without_amount")

        return self


class EntityIngestion(_IngestionBase):
    """
    Pseudonymous synthetic entity ingestion record.

    Raw identifiers are never accepted. Only hashed identifiers are allowed.
    """

    id: str
    entity_type: str
    identifier_hash: str
    identifier_display: Optional[str] = None
    source: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    metadata_json: Optional[dict[str, Any]] = None

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_required_id(value, info, "id")

    @field_validator("entity_type")
    @classmethod
    def _validate_entity_type(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_enum(value, info, ENTITY_TYPES, "entity_type")

    @field_validator("identifier_hash")
    @classmethod
    def _validate_identifier_hash(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_identifier_hash(value, info)

    @field_validator("identifier_display")
    @classmethod
    def _validate_identifier_display(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        return _validate_optional_text(value, info, MAX_DISPLAY_LENGTH)

    @field_validator("source")
    @classmethod
    def _validate_source(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        return _validate_optional_text(value, info, MAX_SOURCE_LENGTH)

    @field_validator("first_seen_at", "last_seen_at")
    @classmethod
    def _validate_seen_at(cls, value: Any, info: ValidationInfo) -> Optional[datetime]:
        if value is None:
            return None

        return _validate_datetime(value, info, "seen_at", require_not_future=True)

    @field_validator("metadata_json")
    @classmethod
    def _validate_metadata(cls, value: Any, info: ValidationInfo) -> Optional[dict[str, Any]]:
        if value is None:
            return None

        options = _options_from_info(info)
        sanitized = _validate_metadata_value(value, options)

        if sanitized is None:
            return None

        if not isinstance(sanitized, dict):
            raise ValueError("unsupported_metadata_value")

        return sanitized

    @model_validator(mode="after")
    def _check_seen_range(self) -> "EntityIngestion":
        if self.first_seen_at and self.last_seen_at and self.last_seen_at < self.first_seen_at:
            raise ValueError("invalid_time_range")

        return self


class EntityLinkIngestion(_IngestionBase):
    """
    Synthetic account-entity link ingestion record.

    Links are investigative associations only. They are not proof of common
    control or wrongdoing.
    """

    id: str
    account_id: str
    entity_id: str
    match_method: str
    confidence: Optional[Decimal] = None
    verification_state: Optional[str] = None
    valid_from: datetime
    valid_to: Optional[datetime] = None
    source: Optional[str] = None
    metadata_json: Optional[dict[str, Any]] = None

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_required_id(value, info, "id")

    @field_validator("account_id", "entity_id")
    @classmethod
    def _validate_linked_id(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_required_id(value, info, "linked_id")

    @field_validator("match_method")
    @classmethod
    def _validate_match_method(cls, value: Any, info: ValidationInfo) -> str:
        return _validate_enum(value, info, MATCH_METHODS, "match_method")

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, value: Any, info: ValidationInfo) -> Optional[Decimal]:
        return _validate_confidence(value, info)

    @field_validator("verification_state")
    @classmethod
    def _validate_verification_state(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        if value is None:
            return None

        return _validate_enum(value, info, VERIFICATION_STATES, "verification_state")

    @field_validator("valid_from")
    @classmethod
    def _validate_valid_from(cls, value: Any, info: ValidationInfo) -> datetime:
        return _validate_datetime(value, info, "valid_from", require_not_future=True)

    @field_validator("valid_to")
    @classmethod
    def _validate_valid_to(cls, value: Any, info: ValidationInfo) -> Optional[datetime]:
        if value is None:
            return None

        return _validate_datetime(value, info, "valid_to", require_not_future=False)

    @field_validator("source")
    @classmethod
    def _validate_source(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        return _validate_optional_text(value, info, MAX_SOURCE_LENGTH)

    @field_validator("metadata_json")
    @classmethod
    def _validate_metadata(cls, value: Any, info: ValidationInfo) -> Optional[dict[str, Any]]:
        if value is None:
            return None

        options = _options_from_info(info)
        sanitized = _validate_metadata_value(value, options)

        if sanitized is None:
            return None

        if not isinstance(sanitized, dict):
            raise ValueError("unsupported_metadata_value")

        return sanitized

    @model_validator(mode="after")
    def _check_valid_range(self) -> "EntityLinkIngestion":
        if self.valid_to is not None and self.valid_to < self.valid_from:
            raise ValueError("invalid_time_range")

        return self


RECORD_MODELS: Final[dict[str, type[_IngestionBase]]] = {
    "accounts": AccountIngestion,
    "transactions": TransactionIngestion,
    "complaints": ComplaintIngestion,
    "entities": EntityIngestion,
    "entity_links": EntityLinkIngestion,
}


# -----------------------------------------------------------------------------
# Error mapping helpers
# -----------------------------------------------------------------------------


def _extract_known_code(message: str) -> str:
    """
    Extract a stable known error code from a safe ValueError message.
    """
    lowered = str(message or "").lower()

    for code in sorted(_KNOWN_VALUE_ERROR_CODES, key=len, reverse=True):
        if code in lowered:
            return code

    return "invalid_field"


def _pydantic_field_path(loc: Sequence[Any]) -> str:
    """
    Build a safe field path from Pydantic error location.
    """
    parts: list[str] = []

    for item in loc:
        text = str(item).strip()

        if not text or text == "body":
            continue

        parts.append(text)

    return ".".join(parts) or "__root__"


def _add_pydantic_errors(
    result: IngestionValidationResult,
    exc: PydanticValidationError,
    index: int,
    options: IngestionValidationOptions,
) -> None:
    """
    Map Pydantic validation errors into safe result errors.

    Error messages are intentionally generic and never include input values.
    """
    for error in exc.errors(include_url=False):
        if result._error_truncated:
            return

        error_type = str(error.get("type") or "")
        loc = error.get("loc") or ()
        field_path = _pydantic_field_path(loc)
        message = str(error.get("msg") or "")

        if error_type == "extra_forbidden":
            key = field_path.split(".")[-1] if field_path else ""

            if _is_forbidden_top_level_key(key):
                code = "forbidden_field"
                safe_message = "Field is not accepted."
            else:
                code = "unknown_field"
                safe_message = "Unknown field."

            result.add_error(
                code=code,
                message=safe_message,
                index=index,
                field=field_path or None,
            )
            continue

        if error_type == "missing":
            result.add_error(
                code="missing_field",
                message="Required field is missing.",
                index=index,
                field=field_path or None,
            )
            continue

        if "pattern" in error_type:
            result.add_error(
                code="invalid_identifier",
                message="Identifier format is invalid.",
                index=index,
                field=field_path or None,
            )
            continue

        if "datetime" in error_type:
            result.add_error(
                code="invalid_timestamp",
                message="Timestamp is invalid.",
                index=index,
                field=field_path or None,
            )
            continue

        if "decimal" in error_type or "amount" in message.lower():
            result.add_error(
                code="invalid_amount",
                message="Amount is invalid.",
                index=index,
                field=field_path or None,
            )
            continue

        if error_type == "value_error":
            code = _extract_known_code(message)
            result.add_error(
                code=code,
                message="Invalid value.",
                index=index,
                field=field_path or None,
            )
            continue

        result.add_error(
            code="invalid_field",
            message="Invalid value.",
            index=index,
            field=field_path or None,
        )


def _precheck_forbidden_keys(
    record: Mapping[str, Any],
    result: IngestionValidationResult,
    index: int,
) -> bool:
    """
    Reject forbidden top-level keys before Pydantic validation.

    Returns True when at least one forbidden key was found.
    """
    found = False

    for raw_key in record.keys():
        key = str(raw_key)

        if _is_forbidden_top_level_key(key):
            found = True
            result.add_error(
                code="forbidden_field",
                message="Field is not accepted.",
                index=index,
                field=key,
            )

            if result._error_truncated:
                break

    return found


# -----------------------------------------------------------------------------
# Duplicate and referential integrity helpers
# -----------------------------------------------------------------------------


def _hashable_key_value(value: Any) -> Any:
    """
    Convert a record value into a hashable, stable key component.
    """
    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else ""

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, Mapping):
        return "<mapping>"

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "<sequence>"

    if value is None:
        return ""

    return str(value)


def _natural_keys(entity_type: str, record: Mapping[str, Any]) -> list[tuple[str, tuple[Any, ...]]]:
    """
    Return deterministic natural keys for duplicate detection.
    """
    keys: list[tuple[str, tuple[Any, ...]]] = []

    record_id = record.get("id")

    if record_id:
        keys.append(("id", (_hashable_key_value(record_id),)))

    reference = record.get("reference")

    if reference:
        keys.append(("reference", (_hashable_key_value(reference),)))

    if entity_type == "transactions":
        keys.append(
            (
                "txn_flow",
                (
                    _hashable_key_value(record.get("sender_account_id")),
                    _hashable_key_value(record.get("receiver_account_id")),
                    _hashable_key_value(record.get("occurred_at")),
                    _hashable_key_value(record.get("amount")),
                    _hashable_key_value(record.get("currency")),
                    _hashable_key_value(record.get("channel")),
                ),
            )
        )

    elif entity_type == "entities":
        keys.append(
            (
                "entity_identity",
                (
                    _hashable_key_value(record.get("entity_type")),
                    _hashable_key_value(record.get("identifier_hash")),
                ),
            )
        )

    elif entity_type == "entity_links":
        keys.append(
            (
                "link",
                (
                    _hashable_key_value(record.get("account_id")),
                    _hashable_key_value(record.get("entity_id")),
                    _hashable_key_value(record.get("valid_from")),
                    _hashable_key_value(record.get("source") or ""),
                ),
            )
        )

    return keys


def _detect_duplicate(
    entity_type: str,
    record: Mapping[str, Any],
    context: IngestionValidationContext,
) -> Optional[str]:
    """
    Return the name of the first duplicate natural key, or None.
    """
    for key_name, key in _natural_keys(entity_type, record):
        if context.has_seen_key(entity_type, key_name, key):
            return key_name

    return None


def _register_record(
    entity_type: str,
    record: Mapping[str, Any],
    context: IngestionValidationContext,
) -> None:
    """
    Register accepted record identifiers and natural keys in the context.
    """
    record_id = record.get("id")

    if entity_type == "accounts" and record_id:
        context.register_account(str(record_id))

    elif entity_type == "entities" and record_id:
        context.register_entity(str(record_id))

    elif entity_type == "transactions":
        if record_id:
            context.register_transaction_ref(str(record_id))

        reference = record.get("reference")

        if reference:
            context.register_transaction_ref(str(reference))

    for key_name, key in _natural_keys(entity_type, record):
        context.register_seen_key(entity_type, key_name, key)


def _validate_referential_integrity(
    entity_type: str,
    index: int,
    record: Mapping[str, Any],
    context: IngestionValidationContext,
    options: IngestionValidationOptions,
    result: IngestionValidationResult,
) -> bool:
    """
    Validate referential integrity for one record.

    Returns True when the record passes referential checks.
    """
    if not options.enforce_referential_integrity:
        return True

    ok = True

    if entity_type == "transactions":
        sender = str(record.get("sender_account_id") or "")
        receiver = str(record.get("receiver_account_id") or "")

        if not context.account_exists(sender):
            ok = False
            result.add_error(
                code="unknown_account",
                message="Transaction references an unknown account.",
                index=index,
                field="sender_account_id",
            )

        if not context.account_exists(receiver):
            ok = False
            result.add_error(
                code="unknown_account",
                message="Transaction references an unknown account.",
                index=index,
                field="receiver_account_id",
            )

    elif entity_type == "entity_links":
        account_id = str(record.get("account_id") or "")
        entity_id = str(record.get("entity_id") or "")

        if not context.account_exists(account_id):
            ok = False
            result.add_error(
                code="unknown_account",
                message="Entity link references an unknown account.",
                index=index,
                field="account_id",
            )

        if not context.entity_exists(entity_id):
            ok = False
            result.add_error(
                code="unknown_entity",
                message="Entity link references an unknown entity.",
                index=index,
                field="entity_id",
            )

    elif entity_type == "complaints":
        victim = record.get("victim_account_id")
        suspected = record.get("suspected_account_id")
        transaction_reference = record.get("transaction_reference")

        if victim and not context.account_exists(str(victim)):
            ok = False
            result.add_error(
                code="unknown_account",
                message="Complaint references an unknown victim account.",
                index=index,
                field="victim_account_id",
            )

        if suspected and not context.account_exists(str(suspected)):
            ok = False
            result.add_error(
                code="unknown_account",
                message="Complaint references an unknown suspected account.",
                index=index,
                field="suspected_account_id",
            )

        if transaction_reference and not context.transaction_ref_exists(str(transaction_reference)):
            ok = False
            result.add_error(
                code="unknown_transaction_reference",
                message="Complaint references an unknown transaction.",
                index=index,
                field="transaction_reference",
            )

    return ok


# -----------------------------------------------------------------------------
# Batch helpers
# -----------------------------------------------------------------------------


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


def _options_with_payload_overrides(
    options: IngestionValidationOptions,
    overrides: Any,
) -> IngestionValidationOptions:
    """
    Apply only safe payload-level overrides.

    Clients must not be able to raise hard limits.
    """
    if not isinstance(overrides, Mapping):
        return options

    updates: dict[str, Any] = {}

    if "duplicate_strategy" in overrides:
        updates["duplicate_strategy"] = overrides["duplicate_strategy"]

    if "source_system" in overrides:
        updates["source_system"] = overrides["source_system"]

    if not updates:
        return options

    return replace(options, **updates)


# -----------------------------------------------------------------------------
# Public validation API
# -----------------------------------------------------------------------------


def validate_ingestion_batch(
    entity_type: str,
    records: Any,
    options: IngestionValidationOptions | None = None,
    context: IngestionValidationContext | None = None,
) -> IngestionValidationResult:
    """
    Validate one bounded ingestion batch.

    Args:
        entity_type: One of accounts, transactions, complaints, entities,
            entity_links.
        records: Sequence of record mappings, or a single mapping.
        options: Optional validation policy. Resolved from settings when absent.
        context: Optional mutable context for referential integrity and
            duplicate detection across multiple batches.

    Returns:
        IngestionValidationResult with safe errors/warnings and accepted
        records for downstream persistence.
    """
    opts = options or IngestionValidationOptions.from_settings()
    ctx = context or IngestionValidationContext()

    normalized_type = _normalize_entity_type(entity_type)
    result = IngestionValidationResult(
        entity_type=normalized_type,
        max_errors=opts.max_errors_returned,
        max_warnings=opts.max_warnings_returned,
    )

    if normalized_type not in RECORD_MODELS:
        result.add_error(
            code="unsupported_entity_type",
            message="Unsupported ingestion entity type.",
            details={"allowed_entity_types": list(SUPPORTED_INGESTION_ENTITY_TYPES)},
        )
        result.finalize(opts)
        return result

    if opts.synthetic_required and opts.dataset_mode != DATASET_MODE_SYNTHETIC:
        result.add_error(
            code="non_synthetic_dataset",
            message="Ingestion requires synthetic dataset mode.",
            details={"dataset_mode": opts.dataset_mode},
        )
        result.finalize(opts)
        return result

    if opts.production_like:
        result.add_warning(
            code="production_like_environment",
            message="Production-like environment detected. Ingestion should be disabled by deployment policy.",
        )

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
        result.finalize(opts)
        return result

    model = RECORD_MODELS[normalized_type]

    for index, raw_record in enumerate(record_list):
        if result._error_truncated:
            break

        if not isinstance(raw_record, Mapping):
            result.add_error(
                code="record_not_object",
                message="Record must be a JSON object.",
                index=index,
            )
            result.rejected.append(index)
            continue

        if _precheck_forbidden_keys(raw_record, result, index):
            result.rejected.append(index)
            continue

        try:
            validated = model.model_validate(raw_record, context={"options": opts})
        except PydanticValidationError as exc:
            _add_pydantic_errors(result, exc, index, opts)
            result.rejected.append(index)
            continue

        record = validated.model_dump(mode="python")

        duplicate_key = _detect_duplicate(normalized_type, record, ctx)

        if duplicate_key is not None:
            if opts.duplicate_strategy == DUPLICATE_STRATEGY_SKIP:
                result.duplicated.append(index)
            else:
                result.add_error(
                    code="duplicate_record",
                    message="Duplicate record rejected by duplicate strategy.",
                    index=index,
                    details={"duplicate_key": duplicate_key},
                )
                result.rejected.append(index)

            continue

        if not _validate_referential_integrity(
            normalized_type,
            index,
            record,
            ctx,
            opts,
            result,
        ):
            result.rejected.append(index)
            continue

        _register_record(normalized_type, record, ctx)
        result.accepted.append(record)

    result.finalize(opts)
    return result


def validate_ingestion_records(
    entity_type: str,
    records: Any,
    options: IngestionValidationOptions | None = None,
    context: IngestionValidationContext | None = None,
) -> IngestionValidationResult:
    """
    Alias for `validate_ingestion_batch`.
    """
    return validate_ingestion_batch(entity_type, records, options=options, context=context)


def validate_ingestion_payload(
    entity_type: str,
    payload: Any,
    options: IngestionValidationOptions | None = None,
    context: IngestionValidationContext | None = None,
) -> IngestionValidationResult:
    """
    Validate an ingestion payload shaped like:

        {
          "records": [...],
          "options": {"duplicate_strategy": "skip"}
        }

    or a bare list/mapping of records.
    """
    opts = options or IngestionValidationOptions.from_settings()

    if isinstance(payload, Mapping):
        records = payload.get("records", payload.get("items", []))
        payload_options = payload.get("options")
        opts = _options_with_payload_overrides(opts, payload_options)
    else:
        records = payload

    return validate_ingestion_batch(entity_type, records, options=opts, context=context)


def validate_account_record(
    record: Mapping[str, Any],
    options: IngestionValidationOptions | None = None,
    context: IngestionValidationContext | None = None,
) -> IngestionValidationResult:
    """
    Validate one synthetic account record.
    """
    return validate_ingestion_batch("accounts", [record], options=options, context=context)


def validate_transaction_record(
    record: Mapping[str, Any],
    options: IngestionValidationOptions | None = None,
    context: IngestionValidationContext | None = None,
) -> IngestionValidationResult:
    """
    Validate one synthetic transaction record.
    """
    return validate_ingestion_batch("transactions", [record], options=options, context=context)


def validate_complaint_record(
    record: Mapping[str, Any],
    options: IngestionValidationOptions | None = None,
    context: IngestionValidationContext | None = None,
) -> IngestionValidationResult:
    """
    Validate one synthetic complaint record.
    """
    return validate_ingestion_batch("complaints", [record], options=options, context=context)


def validate_entity_record(
    record: Mapping[str, Any],
    options: IngestionValidationOptions | None = None,
    context: IngestionValidationContext | None = None,
) -> IngestionValidationResult:
    """
    Validate one pseudonymous synthetic entity record.
    """
    return validate_ingestion_batch("entities", [record], options=options, context=context)


def validate_entity_link_record(
    record: Mapping[str, Any],
    options: IngestionValidationOptions | None = None,
    context: IngestionValidationContext | None = None,
) -> IngestionValidationResult:
    """
    Validate one synthetic account-entity link record.
    """
    return validate_ingestion_batch("entity_links", [record], options=options, context=context)


# -----------------------------------------------------------------------------
# Optional stateful validator wrapper
# -----------------------------------------------------------------------------


class IngestionValidator:
    """
    Stateful wrapper around ingestion validation.

    This is useful when validating multiple dependent batches in sequence, for
    example accounts, then entities, then entity links, then transactions, then
    complaints.
    """

    def __init__(
        self,
        options: IngestionValidationOptions | None = None,
        context: IngestionValidationContext | None = None,
    ) -> None:
        self.options = options or IngestionValidationOptions.from_settings()
        self.context = context or IngestionValidationContext()

    def validate_batch(
        self,
        entity_type: str,
        records: Any,
    ) -> IngestionValidationResult:
        """
        Validate one batch using the shared context.
        """
        return validate_ingestion_batch(
            entity_type,
            records,
            options=self.options,
            context=self.context,
        )

    def validate_payload(
        self,
        entity_type: str,
        payload: Any,
    ) -> IngestionValidationResult:
        """
        Validate one payload using the shared context.
        """
        return validate_ingestion_payload(
            entity_type,
            payload,
            options=self.options,
            context=self.context,
        )

    def reset_context(self) -> None:
        """
        Reset mutable context while preserving options.
        """
        self.context = IngestionValidationContext()


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_ingestion_validator_metadata() -> dict[str, Any]:
    """
    Return safe, serializable ingestion-validator metadata.

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
    default_options = IngestionValidationOptions()

    return {
        "package": "muleguard.backend.ingestion.validators",
        "version": VALIDATORS_VERSION,
        "supported_entity_types": list(SUPPORTED_INGESTION_ENTITY_TYPES),
        "duplicate_strategies": list(DUPLICATE_STRATEGIES),
        "default_options": default_options.safe_summary(),
        "hard_limits": {
            "max_batch_size": HARD_MAX_BATCH_SIZE,
            "max_errors_returned": HARD_MAX_ERRORS_RETURNED,
            "max_warnings_returned": HARD_MAX_WARNINGS_RETURNED,
            "max_narrative_length": HARD_MAX_NARRATIVE_LENGTH,
            "max_metadata_depth": HARD_MAX_METADATA_DEPTH,
            "max_list_length": HARD_MAX_LIST_LENGTH,
            "max_mapping_keys": HARD_MAX_MAPPING_KEYS,
        },
        "forbidden_top_level_key_count": len(FORBIDDEN_TOP_LEVEL_KEYS),
        "caveats": list(_VALIDATOR_CAVEATS),
        "safety_flags": {
            "synthetic_only_by_default": True,
            "no_real_customer_data_by_default": True,
            "no_ground_truth_labels_accepted": True,
            "no_scenario_ids_accepted": True,
            "no_fraud_ring_ids_accepted": True,
            "no_raw_identifier_fields_accepted": True,
            "no_raw_narrative_in_summaries": True,
            "no_secrets_in_summaries": True,
            "bounded_batch_size_required": True,
            "bounded_error_reporting_required": True,
            "deterministic_duplicate_handling": True,
            "referential_integrity_enforced_when_enabled": True,
            "no_automatic_adverse_customer_action": True,
            "not_production_ready": True,
        },
    }


__all__ = [
    "AccountIngestion",
    "ComplaintIngestion",
    "EntityIngestion",
    "EntityLinkIngestion",
    "IngestionValidationContext",
    "IngestionValidationOptions",
    "IngestionValidationResult",
    "IngestionValidator",
    "RECORD_MODELS",
    "TransactionIngestion",
    "VALIDATORS_VERSION",
    "get_ingestion_validator_metadata",
    "validate_account_record",
    "validate_complaint_record",
    "validate_entity_link_record",
    "validate_entity_record",
    "validate_ingestion_batch",
    "validate_ingestion_payload",
    "validate_ingestion_records",
    "validate_transaction_record",
]