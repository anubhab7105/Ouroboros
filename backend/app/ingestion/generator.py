"""
MULEGUARD backend synthetic ingestion data generator.

This module generates bounded, deterministic, privacy-preserving synthetic
datasets suitable for MULEGUARD ingestion workflows, demo seeding, fixtures,
tests, and offline evaluation preparation.

Primary responsibilities:

- generate synthetic accounts, transactions, complaints, pseudonymous entities,
  and account-entity links as ingestion-compatible payload dictionaries;
- remain deterministic for a given seed, salt, and policy;
- enforce hard bounds on record counts, batch sizes, date spans, narrative
  lengths, metadata depth, and monetary precision;
- preserve referential integrity across generated records;
- produce pseudonymous entity identifiers using salted HMAC hashing;
- avoid real customer data, secrets, tokens, passwords, database URLs, raw
  identifier disclosure, model artifact paths, ground-truth labels, injected
  scenario IDs, and fraud-ring IDs in public output;
- provide batch iteration helpers compatible with the bounded ingestion API;
- remain dependency-light and safe to import.

This module does not persist data. It produces records only. Persistence,
validation, authorization, auditing, and transactional commit behaviour belong
to the ingestion service and API layers.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Generated records are investigative inputs only.
- Generated records are not proof of wrongdoing.
- Generated records must not trigger automatic adverse customer action.
- Raw complaint narratives may be generated only as clearly synthetic template
  text for controlled ingestion/seeding workflows. They are never returned in
  ingestion API responses by the API layer.
- Entity identifiers are hashed with domain separation and a salt. Raw
  identifiers are not persisted in output.
- Public manifests contain safe metadata only.
- Ground-truth labels, scenario IDs, and fraud-ring IDs are not included in
  public generator output.
- No filesystem, network, database, ML artifact, or external identity-provider
  access is performed.

Explicit non-goals:

- This module does not ingest data into the database.
- This module does not call real banking systems.
- This module does not generate real customer data.
- This module does not train models.
- This module does not evaluate models.
- This module does not generate reports.
- This module does not claim production readiness.

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
import random
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Final, Optional

from app.exceptions import ConfigurationError, ValidationError as MuleGuardValidationError
from app.core.vocabularies import (
    AccountStatus as _AccountStatus,
    AccountType as _AccountType,
    Channel as _Channel,
    EntityType as _EntityType,
    MatchMethod as _MatchMethod,
    TransactionStatus as _TransactionStatus,
    VerificationState as _VerificationState,
)

logger = logging.getLogger("muleguard.backend.ingestion.generator")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

GENERATOR_VERSION: Final[str] = "v1"
SOURCE_SYSTEM: Final[str] = "synthetic_generator"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")

# The default activity window is RELATIVE TO NOW, not a fixed calendar year.
#
# It used to be hardcoded to 2025-01-01 .. 2025-12-31, which worked for exactly
# as long as 2025 was the present and then failed silently and completely.
# `app/services/features.py` builds its point-in-time dataset over a bounded
# lookback -- `_DEFAULT_LOOKBACK_DAYS = 180` -- ending at the analysis `as_of`.
# Once "now" moved past mid-2026, every generated transaction sat outside that
# horizon, so the dataset came back with
#
#     counts={'accounts': 507, 'transactions': 0, 'complaints': 0, ...}
#
# feature vectors were computed over nothing, no account could be scored, and
# the run failed with `no_accounts_scored` -- after reporting 20,000
# transactions successfully ingested. The data was there; it was just all too
# old to be in scope, and nothing in the error said so.
#
# 180 days ending now keeps generated activity inside that lookback and also
# covers the rule and feature windows that sit inside it
# (FEATURE_LONG_TERM_WINDOW_DAYS and FEATURE_BASELINE_WINDOW_DAYS are 90,
# RULE_CYCLE_WINDOW_DAYS is 30). Override with --date-start/--date-end or the
# SYNTHETIC_DATE_START/SYNTHETIC_DATE_END settings.
#
# These are functions rather than module constants so the window tracks the
# clock in a long-running process instead of freezing at import time.
_DEFAULT_WINDOW_DAYS: Final[int] = 180


def _default_date_end() -> datetime:
    return datetime.now(timezone.utc)


def _default_date_start() -> datetime:
    return _default_date_end() - timedelta(days=_DEFAULT_WINDOW_DAYS)

_DEFAULT_SEED: Final[int] = 42
_DEFAULT_SALT: Final[str] = "muleguard.synthetic.generator.default.salt"

_DEFAULT_ACCOUNTS: Final[int] = 1_200
_HARD_MAX_ACCOUNTS: Final[int] = 100_000

_DEFAULT_TRANSACTIONS: Final[int] = 25_000
_HARD_MAX_TRANSACTIONS: Final[int] = 250_000

_DEFAULT_COMPLAINTS: Final[int] = 150
_HARD_MAX_COMPLAINTS: Final[int] = 100_000

_DEFAULT_ENTITIES: Final[int] = 400
_HARD_MAX_ENTITIES: Final[int] = 100_000

_DEFAULT_ENTITY_LINKS: Final[int] = 1_200
_HARD_MAX_ENTITY_LINKS: Final[int] = 250_000

_DEFAULT_MAX_BATCH_SIZE: Final[int] = 1_000
_HARD_MAX_BATCH_SIZE: Final[int] = 10_000

_HARD_MAX_DATE_SPAN_DAYS: Final[int] = 3_650
_HARD_MAX_NARRATIVE_LENGTH: Final[int] = 20_000
_HARD_MAX_METADATA_DEPTH: Final[int] = 6
_HARD_MAX_METADATA_SEQUENCE_LENGTH: Final[int] = 50
_HARD_MAX_METADATA_MAPPING_KEYS: Final[int] = 50

_DEFAULT_MIN_AMOUNT: Final[Decimal] = Decimal("1.00")
_DEFAULT_MAX_AMOUNT: Final[Decimal] = Decimal("500000.00")

_GENERATOR_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic generator output only. Not real customer or bank data.",
    "Generated records are investigative inputs only and are not proof of wrongdoing.",
    "Generated records must not trigger automatic adverse customer action.",
    "Entity identifiers are pseudonymously hashed and raw identifiers are not emitted.",
    "Complaint narratives are synthetic template text only.",
    "Public manifests do not include ground-truth labels, scenario IDs, or fraud-ring IDs.",
    "Generation is deterministic for a given seed, salt, and policy.",
    "This module does not persist data or connect to real banking systems.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
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
        "body",
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


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class AccountProfile(str, Enum):
    """
    Synthetic account behavioural profile.

    Profiles are generator-internal labels used to shape synthetic activity.
    They are not ground-truth fraud labels.
    """

    RETAIL = "retail"
    BUSINESS = "business"
    WALLET = "wallet"
    DORMANT = "dormant"
    OTHER = "other"
    SOURCE = "source"
    MULE = "mule"
    FUNNEL = "funnel"
    BENEFICIARY = "beneficiary"


# The generated vocabularies are the persisted ones, re-exported.
#
# This module used to declare its own AccountType, AccountStatus,
# TransactionStatus, Channel, EntityType, MatchMethod and VerificationState,
# and every one of them disagreed with the enums the database columns are
# declared over. Generated accounts came out as SAVINGS and CURRENT, which
# the account-type column — INDIVIDUAL, BUSINESS, MERCHANT, OTHER — cannot
# hold, so the generate-then-ingest path, which is the whole demo, could not
# complete. Re-exporting rather than redeclaring means the generator can only
# produce values the platform can store.
#
# `AccountProfile` and `TransactionKind` below stay local: they describe the
# generator's own notion of what it is building and are never persisted.
AccountType = _AccountType
AccountStatus = _AccountStatus
TransactionStatus = _TransactionStatus
Channel = _Channel
EntityType = _EntityType
MatchMethod = _MatchMethod
VerificationState = _VerificationState


class TransactionKind(str, Enum):
    """
    Synthetic transaction pattern label.

    These labels describe generated flow shape only. They are not accusations,
    ground-truth labels, scenario IDs, or ring IDs.
    """

    NOISE = "noise"
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    MULE_IN = "mule_in"
    MULE_OUT = "mule_out"
    FUNNEL = "funnel"
    BENEFICIARY = "beneficiary"
    CHAIN = "chain"
    REVERSAL = "reversal"


class ComplaintCategory(str, Enum):
    """
    Synthetic complaint category labels.
    """

    UNAUTHORIZED_TRANSFER = "unauthorized_transfer"
    ACCOUNT_TAKEOVER = "account_takeover"
    IDENTITY_THEFT = "identity_theft"
    PHISHING = "phishing"
    SCAM = "scam"
    OTHER = "other"


# -----------------------------------------------------------------------------
# Weight tables
# -----------------------------------------------------------------------------

_NOISE_PROFILE_WEIGHTS: Final[Mapping[AccountProfile, float]] = {
    AccountProfile.RETAIL: 0.50,
    AccountProfile.BUSINESS: 0.16,
    AccountProfile.WALLET: 0.16,
    AccountProfile.DORMANT: 0.12,
    AccountProfile.OTHER: 0.06,
}

_PROFILE_AMOUNT_SCALE: Final[Mapping[AccountProfile, float]] = {
    AccountProfile.RETAIL: 2_500.0,
    AccountProfile.BUSINESS: 25_000.0,
    AccountProfile.WALLET: 5_000.0,
    AccountProfile.DORMANT: 500.0,
    AccountProfile.OTHER: 2_000.0,
    AccountProfile.SOURCE: 15_000.0,
    AccountProfile.MULE: 20_000.0,
    AccountProfile.FUNNEL: 50_000.0,
    AccountProfile.BENEFICIARY: 100_000.0,
}

# The weights cover the six rails the transaction table can record. The
# wallet, cash, external and unknown shares the generator used to emit have
# been folded into UPI and INTERNAL, which is where that volume would
# plausibly sit in an Indian retail payments mix.
_CHANNEL_WEIGHTS: Final[Mapping[Channel, float]] = {
    Channel.UPI: 0.52,
    Channel.NEFT: 0.16,
    Channel.IMPS: 0.11,
    Channel.CARD: 0.08,
    Channel.INTERNAL: 0.08,
    Channel.RTGS: 0.05,
}

# Entity types carry the `_HASH` suffix because that is what the table holds:
# the identifier is hashed on the way in and the raw value is never stored.
# The name, card and wallet types the generator used to emit have no place to
# go, and inventing a NAME entity would have meant generating raw personal
# names into a table designed to hold none.
_ENTITY_TYPE_WEIGHTS: Final[Mapping[EntityType, float]] = {
    EntityType.DEVICE: 0.30,
    EntityType.IP_HASH: 0.21,
    EntityType.UPI_ID: 0.19,
    EntityType.PHONE_HASH: 0.12,
    EntityType.EMAIL_HASH: 0.11,
    EntityType.ADDRESS_HASH: 0.05,
    EntityType.OTHER: 0.02,
}

_COMPLAINT_CATEGORY_WEIGHTS: Final[Mapping[ComplaintCategory, float]] = {
    ComplaintCategory.UNAUTHORIZED_TRANSFER: 0.38,
    ComplaintCategory.ACCOUNT_TAKEOVER: 0.18,
    ComplaintCategory.IDENTITY_THEFT: 0.14,
    ComplaintCategory.PHISHING: 0.14,
    ComplaintCategory.SCAM: 0.12,
    ComplaintCategory.OTHER: 0.04,
}

_COMPLAINT_NARRATIVE_TEMPLATES: Final[tuple[str, ...]] = (
    "Synthetic complaint: an unauthorized {channel} transfer of {amount} {currency} was reported by a demo account holder.",
    "Synthetic complaint: a demo customer reported possible account takeover after unexpected {channel} activity.",
    "Synthetic complaint: a synthetic profile described phishing messages that led to an attempted {channel} transfer.",
    "Synthetic complaint: a demo customer reported a scam-like request for an urgent {channel} payment.",
    "Synthetic complaint: a synthetic account holder reported identity misuse connected to {channel} transactions.",
    "Synthetic complaint: a demo reviewer flagged unusual {channel} activity for investigation.",
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


def _parse_datetime(value: Any, default: datetime) -> datetime:
    """
    Parse a datetime-like setting value.
    """
    if isinstance(value, datetime):
        normalized = _ensure_utc(value)

        if normalized is not None:
            return normalized

        return default

    text = str(value or "").strip()

    if not text:
        return default

    try:
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"

        parsed = datetime.fromisoformat(text)
        normalized = _ensure_utc(parsed)

        if normalized is not None:
            return normalized

    except Exception:
        pass

    return default


def _quantize_money(value: Decimal) -> Decimal:
    """
    Quantize a monetary value to two decimal places.
    """
    if not value.is_finite():
        return _DEFAULT_MIN_AMOUNT

    if value <= 0:
        return _DEFAULT_MIN_AMOUNT

    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _parse_decimal(value: Any, default: Decimal) -> Decimal:
    """
    Parse a decimal-like setting value.
    """
    if value is None:
        return default

    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return default

    if not parsed.is_finite() or parsed <= 0:
        return default

    return _quantize_money(parsed)


def _clean_text(value: Any, limit: int = 512) -> str:
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


def _clean_narrative(value: Any, limit: int = _HARD_MAX_NARRATIVE_LENGTH) -> str:
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


def _is_sensitive_metadata_key(key: str) -> bool:
    """
    Return True when a metadata key appears sensitive or leakage-prone.
    """
    lowered = key.strip().lower()

    if lowered in _SENSITIVE_METADATA_KEYS:
        return True

    return any(token in lowered for token in _SENSITIVE_METADATA_TOKENS)


def _safe_metadata_value(value: Any, depth: int = 0) -> Any:
    """
    Convert arbitrary metadata into a bounded, safe structure.
    """
    if depth > _HARD_MAX_METADATA_DEPTH:
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
        return _clean_text(value, 512)

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Enum):
        return _safe_metadata_value(value.value, depth + 1)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:_HARD_MAX_METADATA_MAPPING_KEYS]:
            key = str(raw_key)

            if _is_sensitive_metadata_key(key):
                continue

            sanitized[key] = _safe_metadata_value(raw_value, depth + 1)

        return sanitized

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        limited = list(value)[:_HARD_MAX_METADATA_SEQUENCE_LENGTH]
        return [_safe_metadata_value(item, depth + 1) for item in limited]

    return f"<{type(value).__name__}>"


def _safe_metadata(value: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    """
    Return sanitized metadata suitable for synthetic record payloads.
    """
    if not value:
        return None

    sanitized = _safe_metadata_value(value)

    if isinstance(sanitized, dict) and sanitized:
        return sanitized

    return None


def _stable_hash(parts: Sequence[str]) -> str:
    """
    Return a stable SHA-256 digest for generator identifiers.
    """
    payload = "|".join(str(part) for part in parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _hmac_hex(key: str, message: str) -> str:
    """
    Return HMAC-SHA256 hex digest.
    """
    return hmac.new(
        key.encode("utf-8", errors="replace"),
        message.encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()


def _ensure_salt(salt: Optional[str]) -> str:
    """
    Ensure the generator salt is non-empty and sufficiently long.

    The salt is never emitted in public manifests.
    """
    text = str(salt or _DEFAULT_SALT).strip()

    if not text:
        text = _DEFAULT_SALT

    if len(text.encode("utf-8", errors="replace")) < 16:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    return text


def _normalize_currency(value: Any) -> str:
    """
    Normalize a currency code.
    """
    text = str(value or "INR").strip().upper()

    if _CURRENCY_RE.match(text):
        return text

    return "INR"


def _weighted_choice(rng: random.Random, weights: Mapping[Any, float]) -> Any:
    """
    Choose a weighted key deterministically from the supplied RNG.
    """
    items = [(key, max(0.0, float(value))) for key, value in weights.items()]

    if not items:
        raise ConfigurationError("Weighted choice requires at least one item.")

    total = sum(value for _, value in items)

    if total <= 0:
        return items[0][0]

    threshold = rng.random() * total
    cumulative = 0.0

    for key, value in items:
        cumulative += value

        if threshold <= cumulative:
            return key

    return items[-1][0]


def _random_datetime(rng: random.Random, start: datetime, end: datetime) -> datetime:
    """
    Return a deterministic random timezone-aware datetime in [start, end].
    """
    start = _ensure_utc(start) or _default_date_start()
    end = _ensure_utc(end) or start

    if end < start:
        start, end = end, start

    delta_seconds = int((end - start).total_seconds())

    if delta_seconds <= 0:
        return start

    return start + timedelta(seconds=rng.randrange(delta_seconds + 1))


def _random_amount(
    rng: random.Random,
    scale: float,
    min_amount: Decimal,
    max_amount: Decimal,
) -> Decimal:
    """
    Generate a bounded synthetic monetary amount.
    """
    safe_scale = max(float(min_amount), float(scale))
    mu = math.log(max(safe_scale, 1.0))
    sigma = 0.78

    try:
        raw = rng.lognormvariate(mu, sigma)
        value = Decimal(str(raw))
    except Exception:
        value = Decimal(str(safe_scale))

    if not value.is_finite():
        value = Decimal(str(safe_scale))

    value = max(min_amount, min(max_amount, value))
    return _quantize_money(value)


def _unique_id(
    prefix: str,
    parts: Sequence[Any],
    policy: "GenerationPolicy",
    used: set[str],
) -> str:
    """
    Return a stable, bounded, collision-checked identifier.
    """
    base_parts = [str(policy.seed), prefix, *[str(part) for part in parts]]

    for attempt in range(1_000):
        material = "|".join([*base_parts, str(attempt)])
        digest = _hmac_hex(policy.salt, material)[:24]
        candidate = f"{prefix}-{digest}"

        if candidate not in used:
            used.add(candidate)
            return candidate

    raise ConfigurationError("Unable to generate a unique synthetic identifier.")


def _hash_identifier(raw: str, salt: str, domain: str) -> str:
    """
    Return a domain-separated pseudonymous identifier hash.
    """
    material = "\x00".join([domain, salt, raw])
    return _hmac_hex(salt, material)


# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GenerationPolicy:
    """
    Bounded synthetic generation policy.

    This policy is intentionally conservative. Hard caps prevent accidental
    unbounded generation.
    """

    seed: int = _DEFAULT_SEED
    salt: str = _DEFAULT_SALT

    accounts: int = _DEFAULT_ACCOUNTS
    transactions: int = _DEFAULT_TRANSACTIONS
    complaints: int = _DEFAULT_COMPLAINTS
    entities: int = _DEFAULT_ENTITIES
    entity_links: int = _DEFAULT_ENTITY_LINKS

    date_start: datetime = field(default_factory=_default_date_start)
    date_end: datetime = field(default_factory=_default_date_end)

    currency: str = "INR"
    min_amount: Decimal = _DEFAULT_MIN_AMOUNT
    max_amount: Decimal = _DEFAULT_MAX_AMOUNT

    mule_cluster_count: Optional[int] = None
    mule_cluster_min_size: int = 4
    mule_cluster_max_size: int = 12

    cluster_account_rate: float = 0.35
    cluster_transaction_rate: float = 0.55
    cluster_complaint_rate: float = 0.70
    shared_entity_rate: float = 0.35
    individual_entity_rate: float = 0.25

    completed_rate: float = 0.86
    pending_rate: float = 0.05
    failed_rate: float = 0.04
    reversed_rate: float = 0.03
    cancelled_rate: float = 0.01
    disputed_rate: float = 0.01

    max_batch_size: int = _DEFAULT_MAX_BATCH_SIZE
    include_manifest: bool = True

    def __post_init__(self) -> None:
        """
        Normalize and clamp policy values.
        """
        object.__setattr__(self, "seed", int(self.seed) & ((1 << 64) - 1))
        object.__setattr__(self, "salt", _ensure_salt(self.salt))

        object.__setattr__(
            self,
            "accounts",
            _clamp_int(self.accounts, 0, _HARD_MAX_ACCOUNTS, _DEFAULT_ACCOUNTS),
        )
        object.__setattr__(
            self,
            "transactions",
            _clamp_int(self.transactions, 0, _HARD_MAX_TRANSACTIONS, _DEFAULT_TRANSACTIONS),
        )
        object.__setattr__(
            self,
            "complaints",
            _clamp_int(self.complaints, 0, _HARD_MAX_COMPLAINTS, _DEFAULT_COMPLAINTS),
        )
        object.__setattr__(
            self,
            "entities",
            _clamp_int(self.entities, 0, _HARD_MAX_ENTITIES, _DEFAULT_ENTITIES),
        )
        object.__setattr__(
            self,
            "entity_links",
            _clamp_int(self.entity_links, 0, _HARD_MAX_ENTITY_LINKS, _DEFAULT_ENTITY_LINKS),
        )

        date_start = _ensure_utc(self.date_start) or _default_date_start()
        date_end = _ensure_utc(self.date_end) or _default_date_end()

        if date_end < date_start:
            date_start, date_end = date_end, date_start

        max_span = timedelta(days=_HARD_MAX_DATE_SPAN_DAYS)

        if date_end - date_start > max_span:
            date_end = date_start + max_span

        object.__setattr__(self, "date_start", date_start)
        object.__setattr__(self, "date_end", date_end)

        object.__setattr__(self, "currency", _normalize_currency(self.currency))

        min_amount = _parse_decimal(self.min_amount, _DEFAULT_MIN_AMOUNT)
        max_amount = _parse_decimal(self.max_amount, _DEFAULT_MAX_AMOUNT)

        if max_amount < min_amount:
            max_amount = min_amount

        object.__setattr__(self, "min_amount", min_amount)
        object.__setattr__(self, "max_amount", max_amount)

        if self.mule_cluster_count is not None:
            object.__setattr__(
                self,
                "mule_cluster_count",
                _clamp_int(self.mule_cluster_count, 0, 5_000, 0),
            )

        object.__setattr__(
            self,
            "mule_cluster_min_size",
            _clamp_int(self.mule_cluster_min_size, 2, 100, 4),
        )
        object.__setattr__(
            self,
            "mule_cluster_max_size",
            _clamp_int(self.mule_cluster_max_size, 2, 200, 12),
        )

        if self.mule_cluster_max_size < self.mule_cluster_min_size:
            object.__setattr__(
                self,
                "mule_cluster_max_size",
                self.mule_cluster_min_size,
            )

        for rate_name, default_value in (
            ("cluster_account_rate", 0.35),
            ("cluster_transaction_rate", 0.55),
            ("cluster_complaint_rate", 0.70),
            ("shared_entity_rate", 0.35),
            ("individual_entity_rate", 0.25),
            ("completed_rate", 0.86),
            ("pending_rate", 0.05),
            ("failed_rate", 0.04),
            ("reversed_rate", 0.03),
            ("cancelled_rate", 0.01),
            ("disputed_rate", 0.01),
        ):
            current = getattr(self, rate_name)
            object.__setattr__(
                self,
                rate_name,
                _clamp_float(current, 0.0, 1.0, float(default_value)),
            )

        object.__setattr__(
            self,
            "max_batch_size",
            _clamp_int(self.max_batch_size, 1, _HARD_MAX_BATCH_SIZE, _DEFAULT_MAX_BATCH_SIZE),
        )
        object.__setattr__(self, "include_manifest", bool(self.include_manifest))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "GenerationPolicy":
        """
        Build a policy from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        salt = str(
            _setting(settings, "SYNTHETIC_GENERATOR_SALT", None)
            or _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
            or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
            or _setting(settings, "BACKEND_SECRET_KEY", None)
            or _DEFAULT_SALT
        )

        return cls(
            seed=_as_int(_setting(settings, "SEED_RANDOM_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            salt=salt,
            accounts=_as_int(_setting(settings, "SEED_ACCOUNTS", _DEFAULT_ACCOUNTS), _DEFAULT_ACCOUNTS),
            transactions=_as_int(_setting(settings, "SEED_TRANSACTIONS", _DEFAULT_TRANSACTIONS), _DEFAULT_TRANSACTIONS),
            complaints=_as_int(_setting(settings, "SEED_COMPLAINTS", _DEFAULT_COMPLAINTS), _DEFAULT_COMPLAINTS),
            entities=_as_int(_setting(settings, "SEED_ENTITIES", _DEFAULT_ENTITIES), _DEFAULT_ENTITIES),
            entity_links=_as_int(_setting(settings, "SEED_ENTITY_LINKS", _DEFAULT_ENTITY_LINKS), _DEFAULT_ENTITY_LINKS),
            date_start=_parse_datetime(
                _setting(settings, "SYNTHETIC_DATE_START", None),
                _default_date_start(),
            ),
            date_end=_parse_datetime(
                _setting(settings, "SYNTHETIC_DATE_END", None),
                _default_date_end(),
            ),
            currency=_normalize_currency(_setting(settings, "BACKEND_DEFAULT_CURRENCY", "INR")),
            min_amount=_parse_decimal(
                _setting(settings, "SYNTHETIC_MIN_AMOUNT", None),
                _DEFAULT_MIN_AMOUNT,
            ),
            max_amount=_parse_decimal(
                _setting(settings, "SYNTHETIC_MAX_AMOUNT", None),
                _DEFAULT_MAX_AMOUNT,
            ),
            mule_cluster_count=(
                _as_int(_setting(settings, "SYNTHETIC_MULE_CLUSTER_COUNT", None), 0)
                if _setting(settings, "SYNTHETIC_MULE_CLUSTER_COUNT", None) is not None
                else None
            ),
            mule_cluster_min_size=_as_int(
                _setting(settings, "SYNTHETIC_MULE_CLUSTER_MIN_SIZE", 4),
                4,
            ),
            mule_cluster_max_size=_as_int(
                _setting(settings, "SYNTHETIC_MULE_CLUSTER_MAX_SIZE", 12),
                12,
            ),
            cluster_account_rate=_as_float(
                _setting(settings, "SYNTHETIC_CLUSTER_ACCOUNT_RATE", 0.35),
                0.35,
            ),
            cluster_transaction_rate=_as_float(
                _setting(settings, "SYNTHETIC_CLUSTER_TRANSACTION_RATE", 0.55),
                0.55,
            ),
            cluster_complaint_rate=_as_float(
                _setting(settings, "SYNTHETIC_CLUSTER_COMPLAINT_RATE", 0.70),
                0.70,
            ),
            shared_entity_rate=_as_float(
                _setting(settings, "SYNTHETIC_SHARED_ENTITY_RATE", 0.35),
                0.35,
            ),
            individual_entity_rate=_as_float(
                _setting(settings, "SYNTHETIC_INDIVIDUAL_ENTITY_RATE", 0.25),
                0.25,
            ),
            completed_rate=_as_float(_setting(settings, "SYNTHETIC_COMPLETED_RATE", 0.86), 0.86),
            pending_rate=_as_float(_setting(settings, "SYNTHETIC_PENDING_RATE", 0.05), 0.05),
            failed_rate=_as_float(_setting(settings, "SYNTHETIC_FAILED_RATE", 0.04), 0.04),
            reversed_rate=_as_float(_setting(settings, "SYNTHETIC_REVERSED_RATE", 0.03), 0.03),
            cancelled_rate=_as_float(_setting(settings, "SYNTHETIC_CANCELLED_RATE", 0.01), 0.01),
            disputed_rate=_as_float(_setting(settings, "SYNTHETIC_DISPUTED_RATE", 0.01), 0.01),
            max_batch_size=_as_int(
                _setting(settings, "INGESTION_MAX_BATCH_SIZE", _DEFAULT_MAX_BATCH_SIZE),
                _DEFAULT_MAX_BATCH_SIZE,
            ),
            include_manifest=_as_bool(_setting(settings, "SYNTHETIC_INCLUDE_MANIFEST", True), True),
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe policy summary for manifests and diagnostics.

        This never includes the salt.
        """
        return {
            "version": GENERATOR_VERSION,
            "accounts": self.accounts,
            "transactions": self.transactions,
            "complaints": self.complaints,
            "entities": self.entities,
            "entity_links": self.entity_links,
            "date_start": self.date_start.isoformat(),
            "date_end": self.date_end.isoformat(),
            "currency": self.currency,
            "min_amount": str(self.min_amount),
            "max_amount": str(self.max_amount),
            "mule_cluster_count": self.mule_cluster_count,
            "mule_cluster_min_size": self.mule_cluster_min_size,
            "mule_cluster_max_size": self.mule_cluster_max_size,
            "rates": {
                "cluster_account_rate": round(self.cluster_account_rate, 4),
                "cluster_transaction_rate": round(self.cluster_transaction_rate, 4),
                "cluster_complaint_rate": round(self.cluster_complaint_rate, 4),
                "shared_entity_rate": round(self.shared_entity_rate, 4),
                "individual_entity_rate": round(self.individual_entity_rate, 4),
                "completed_rate": round(self.completed_rate, 4),
                "pending_rate": round(self.pending_rate, 4),
                "failed_rate": round(self.failed_rate, 4),
                "reversed_rate": round(self.reversed_rate, 4),
                "cancelled_rate": round(self.cancelled_rate, 4),
                "disputed_rate": round(self.disputed_rate, 4),
            },
            "max_batch_size": self.max_batch_size,
            "include_manifest": self.include_manifest,
        }


# -----------------------------------------------------------------------------
# Internal generation models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class _Cluster:
    """
    Internal synthetic cluster model.

    Cluster identity is intentionally not emitted in public records or manifests.
    """

    accounts: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    mules: list[str] = field(default_factory=list)
    funnels: list[str] = field(default_factory=list)
    beneficiaries: list[str] = field(default_factory=list)
    transaction_refs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SyntheticDataset:
    """
    Generated synthetic dataset compatible with MULEGUARD ingestion payloads.
    """

    accounts: list[dict[str, Any]] = field(default_factory=list)
    transactions: list[dict[str, Any]] = field(default_factory=list)
    complaints: list[dict[str, Any]] = field(default_factory=list)
    entities: list[dict[str, Any]] = field(default_factory=list)
    entity_links: list[dict[str, Any]] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)

    #: Ground truth, kept apart from the records on purpose.
    #:
    #: One entry per generated account: its behavioural profile and, for a
    #: clustered account, its ring id. Precision and recall cannot be computed
    #: without these, and a model trained on them has learned nothing, so they
    #: travel in their own collection rather than on the records.
    #:
    #: `to_dict()` omits this, and the ingestion API refuses every field in
    #: it, so a labels list cannot be loaded by accident. Reach for it only
    #: from an evaluation path, and never join it onto a feature row.
    labels: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable dataset representation.

        `labels` is deliberately absent. This is the method a caller reaches
        for when writing the dataset out or handing it to a loader, and a
        ground-truth label in that payload is one careless join from being a
        feature. Evaluation reads `dataset.labels` directly, which is a
        separate and visible act.
        """
        return {
            "accounts": self.accounts,
            "transactions": self.transactions,
            "complaints": self.complaints,
            "entities": self.entities,
            "entity_links": self.entity_links,
            "manifest": self.manifest,
        }

    def counts(self) -> dict[str, int]:
        """
        Return safe record counts.
        """
        return {
            "accounts": len(self.accounts),
            "transactions": len(self.transactions),
            "complaints": len(self.complaints),
            "entities": len(self.entities),
            "entity_links": len(self.entity_links),
        }

    def iter_batches(
        self,
        max_batch_size: Optional[int] = None,
    ) -> Iterator["SyntheticBatch"]:
        """
        Iterate ingestion-compatible batches in dependency-safe order.
        """
        return iter_ingestion_batches(self, max_batch_size=max_batch_size)


@dataclass(frozen=True, slots=True)
class SyntheticBatch:
    """
    One bounded ingestion batch.
    """

    entity_type: str
    records: list[dict[str, Any]]
    options: dict[str, Any]
    index: int
    total_batches: int

    def to_request_payload(self) -> dict[str, Any]:
        """
        Return a payload compatible with ingestion batch endpoints.
        """
        return {
            "records": self.records,
            "options": self.options,
        }


# -----------------------------------------------------------------------------
# Account generation
# -----------------------------------------------------------------------------


def _account_type_for_profile(profile: AccountProfile, rng: random.Random) -> AccountType:
    """
    Choose a plausible synthetic account type for a profile.

    `AccountType` classifies the account holder — individual, business,
    merchant — not the banking product. The generator's profiles are
    behavioural, so the mapping reads off who would plausibly hold an account
    behaving that way: a funnel account is usually registered to a business or
    a merchant, a mule account almost always to an individual.
    """
    if profile == AccountProfile.BUSINESS:
        return AccountType.BUSINESS

    if profile == AccountProfile.FUNNEL:
        return _weighted_choice(
            rng,
            {
                AccountType.BUSINESS: 0.45,
                AccountType.MERCHANT: 0.35,
                AccountType.INDIVIDUAL: 0.20,
            },
        )

    if profile in {AccountProfile.WALLET, AccountProfile.MULE}:
        return _weighted_choice(
            rng,
            {
                AccountType.INDIVIDUAL: 0.90,
                AccountType.OTHER: 0.10,
            },
        )

    if profile == AccountProfile.BENEFICIARY:
        return _weighted_choice(
            rng,
            {
                AccountType.INDIVIDUAL: 0.70,
                AccountType.BUSINESS: 0.20,
                AccountType.MERCHANT: 0.10,
            },
        )

    if profile == AccountProfile.DORMANT:
        return AccountType.INDIVIDUAL

    return _weighted_choice(
        rng,
        {
            AccountType.INDIVIDUAL: 0.80,
            AccountType.BUSINESS: 0.10,
            AccountType.MERCHANT: 0.05,
            AccountType.OTHER: 0.05,
        },
    )


def _account_status_for_profile(profile: AccountProfile, rng: random.Random) -> AccountStatus:
    """
    Choose a plausible observational synthetic account status.

    Status labels do not authorize adverse action, which is why there is no
    suspended or restricted value to generate: the platform has no business
    recording an enforcement decision it does not make. REVIEW_REQUIRED means
    somebody should look, and that is as far as it goes.
    """
    if profile == AccountProfile.DORMANT:
        return _weighted_choice(
            rng,
            {
                AccountStatus.DORMANT: 0.90,
                AccountStatus.ACTIVE: 0.10,
            },
        )

    if profile in {AccountProfile.SOURCE, AccountProfile.MULE, AccountProfile.FUNNEL}:
        return _weighted_choice(
            rng,
            {
                AccountStatus.ACTIVE: 0.93,
                AccountStatus.DORMANT: 0.04,
                AccountStatus.REVIEW_REQUIRED: 0.03,
            },
        )

    return _weighted_choice(
        rng,
        {
            AccountStatus.ACTIVE: 0.90,
            AccountStatus.DORMANT: 0.06,
            AccountStatus.REVIEW_REQUIRED: 0.03,
            AccountStatus.CLOSED: 0.01,
        },
    )


def _make_account(
    policy: GenerationPolicy,
    rng: random.Random,
    index: int,
    profile: AccountProfile,
    used_ids: set[str],
) -> dict[str, Any]:
    """
    Build one synthetic account ingestion record.
    """
    account_id = _unique_id("acct", [index, profile.value], policy, used_ids)

    creation_start = policy.date_start - timedelta(days=730)
    creation_end = policy.date_end - timedelta(minutes=1)

    if creation_end < creation_start:
        creation_end = creation_start

    created_at = _random_datetime(rng, creation_start, creation_end)
    account_type = _account_type_for_profile(profile, rng)
    status = _account_status_for_profile(profile, rng)

    # The behavioural profile is NOT written into the record.
    #
    # `profile` is the generator's own ground truth under a gentler name: it
    # says what the generator was asked to build, which is exactly what a
    # model is supposed to infer. It used to be placed in `metadata_json`,
    # which is persisted and is not on the ingestion field blocklist, so it
    # survived into the database where a feature built from account metadata
    # would read it. A model that learns the generator's intent scores
    # perfectly in evaluation and has learned nothing.
    #
    # Profiles reach evaluation through `SyntheticDataset.labels`, which is
    # not ingestible, so getting at them is a deliberate act.
    metadata = _safe_metadata(
        {
            "synthetic": True,
            "source": SOURCE_SYSTEM,
            "generator_version": GENERATOR_VERSION,
        }
    )

    return {
        "id": account_id,
        "account_type": account_type.value,
        "status": status.value,
        "created_at": created_at.isoformat(),
        "metadata_json": metadata,
    }


def _plan_cluster_sizes(policy: GenerationPolicy, rng: random.Random) -> list[int]:
    """
    Plan synthetic cluster sizes within bounded budgets.
    """
    if policy.accounts < 4:
        return []

    cluster_budget_accounts = int(policy.accounts * policy.cluster_account_rate)

    if cluster_budget_accounts < 4:
        return []

    if policy.mule_cluster_count is not None:
        max_clusters = max(0, int(policy.mule_cluster_count))
    else:
        max_clusters = max(1, min(500, policy.accounts // 20))

    if max_clusters <= 0:
        return []

    sizes: list[int] = []
    remaining = cluster_budget_accounts

    for _ in range(max_clusters):
        min_size = min(policy.mule_cluster_min_size, remaining)
        max_size = min(policy.mule_cluster_max_size, remaining)

        if min_size < 2 or max_size < min_size:
            break

        size = rng.randint(min_size, max_size)
        sizes.append(size)
        remaining -= size

        if remaining < policy.mule_cluster_min_size:
            break

    return sizes


def _generate_accounts_and_clusters(
    policy: GenerationPolicy,
    rng: random.Random,
) -> tuple[list[dict[str, Any]], list[_Cluster], dict[str, AccountProfile]]:
    """
    Generate synthetic accounts and internal cluster plans.
    """
    accounts: list[dict[str, Any]] = []
    clusters: list[_Cluster] = []
    profiles: dict[str, AccountProfile] = {}
    used_ids: set[str] = set()

    index = 0
    cluster_sizes = _plan_cluster_sizes(policy, rng)

    for size in cluster_sizes:
        if len(accounts) + size > policy.accounts:
            break

        cluster = _Cluster()

        source_count = max(1, size // 5)
        mule_count = max(1, size // 3)
        funnel_count = max(1, size // 4)
        beneficiary_count = max(1, size - source_count - mule_count - funnel_count)

        total_assigned = source_count + mule_count + funnel_count + beneficiary_count

        if total_assigned > size:
            excess = total_assigned - size
            beneficiary_count = max(1, beneficiary_count - excess)
            funnel_count = max(1, funnel_count - max(0, excess - (beneficiary_count - 1)))
            mule_count = max(1, mule_count - max(0, excess - (beneficiary_count - 1) - (funnel_count - 1)))
            source_count = max(1, size - mule_count - funnel_count - beneficiary_count)

        role_plan: list[AccountProfile] = (
            [AccountProfile.SOURCE] * source_count
            + [AccountProfile.MULE] * mule_count
            + [AccountProfile.FUNNEL] * funnel_count
            + [AccountProfile.BENEFICIARY] * beneficiary_count
        )

        while len(role_plan) < size:
            role_plan.append(AccountProfile.MULE)

        role_plan = role_plan[:size]
        rng.shuffle(role_plan)

        for role in role_plan:
            account = _make_account(policy, rng, index, role, used_ids)
            account_id = str(account["id"])

            accounts.append(account)
            profiles[account_id] = role
            cluster.accounts.append(account_id)

            if role == AccountProfile.SOURCE:
                cluster.sources.append(account_id)
            elif role == AccountProfile.MULE:
                cluster.mules.append(account_id)
            elif role == AccountProfile.FUNNEL:
                cluster.funnels.append(account_id)
            elif role == AccountProfile.BENEFICIARY:
                cluster.beneficiaries.append(account_id)

            index += 1

        if len(cluster.accounts) >= 2:
            clusters.append(cluster)

    while len(accounts) < policy.accounts:
        profile = _weighted_choice(rng, _NOISE_PROFILE_WEIGHTS)
        account = _make_account(policy, rng, index, profile, used_ids)
        account_id = str(account["id"])

        accounts.append(account)
        profiles[account_id] = profile
        index += 1

    return accounts, clusters, profiles


# -----------------------------------------------------------------------------
# Entity generation
# -----------------------------------------------------------------------------


def _raw_identifier(entity_type: EntityType, rng: random.Random, index: int) -> str:
    """
    Generate a clearly synthetic raw identifier.

    The raw value is hashed immediately and never emitted.
    """
    token = f"{index}-{rng.getrandbits(96):024x}"

    if entity_type == EntityType.DEVICE:
        return f"device-{token}"

    if entity_type == EntityType.IP_HASH:
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"

    if entity_type == EntityType.PHONE_HASH:
        return f"+91-9{rng.randint(100000000, 999999999)}"

    if entity_type == EntityType.EMAIL_HASH:
        return f"user{token}@muleguard.local"

    if entity_type == EntityType.UPI_ID:
        return f"user{token}@muleguard"

    if entity_type == EntityType.ADDRESS_HASH:
        return f"Synthetic Address {token}"

    return f"other-{token}"


def _mask_identifier(entity_type: EntityType, raw: str) -> str:
    """
    Return a masked, non-reversible display label.
    """
    if entity_type == EntityType.IP_HASH:
        parts = raw.split(".")

        if len(parts) == 4:
            return f"10.*.*.{parts[-1]}"

        return "IP ****"

    if entity_type == EntityType.PHONE_HASH:
        return f"+91-****-****{raw[-4:]}"

    if entity_type == EntityType.EMAIL_HASH and "@" in raw:
        local, _, domain = raw.partition("@")
        first = local[:1] or "*"
        return f"{first}***@{domain}"

    if entity_type == EntityType.UPI_ID and "@" in raw:
        local, _, domain = raw.partition("@")
        first = local[:1] or "*"
        return f"{first}***@{domain}"

    if entity_type == EntityType.DEVICE:
        return f"device-****{raw[-4:]}"

    if entity_type == EntityType.ADDRESS_HASH:
        return "Address ****"

    return f"{entity_type.value.lower()}-****"


def _make_entity(
    policy: GenerationPolicy,
    rng: random.Random,
    index: int,
    entity_type: EntityType,
    used_ids: set[str],
) -> dict[str, Any]:
    """
    Build one pseudonymous synthetic entity ingestion record.
    """
    entity_id = _unique_id("ent", [index, entity_type.value], policy, used_ids)

    raw = _raw_identifier(entity_type, rng, index)
    identifier_hash = _hash_identifier(
        raw,
        policy.salt,
        domain=f"muleguard.entity.{entity_type.value}",
    )

    first_seen = _random_datetime(
        rng,
        policy.date_start - timedelta(days=180),
        policy.date_end,
    )
    last_seen = _random_datetime(rng, first_seen, policy.date_end)

    metadata = _safe_metadata(
        {
            "synthetic": True,
            "source": SOURCE_SYSTEM,
            "entity_kind": entity_type.value,
            "generator_version": GENERATOR_VERSION,
        }
    )

    return {
        "id": entity_id,
        "entity_type": entity_type.value,
        "identifier_hash": identifier_hash,
        "identifier_display": _mask_identifier(entity_type, raw),
        "source": SOURCE_SYSTEM,
        "first_seen_at": first_seen.isoformat(),
        "last_seen_at": last_seen.isoformat(),
        "metadata_json": metadata,
    }


def _link_confidence_and_state(
    rng: random.Random,
    match_method: MatchMethod,
) -> tuple[Decimal, VerificationState]:
    """
    Choose plausible synthetic link confidence and verification state.
    """
    if match_method == MatchMethod.EXACT:
        confidence = Decimal(str(round(rng.uniform(0.92, 1.0), 4)))
        state = _weighted_choice(
            rng,
            {
                VerificationState.VERIFIED: 0.55,
                VerificationState.NEEDS_REVIEW: 0.30,
                VerificationState.UNVERIFIED: 0.15,
            },
        )
    elif match_method == MatchMethod.NORMALIZED:
        confidence = Decimal(str(round(rng.uniform(0.80, 0.98), 4)))
        state = _weighted_choice(
            rng,
            {
                VerificationState.VERIFIED: 0.35,
                VerificationState.NEEDS_REVIEW: 0.35,
                VerificationState.UNVERIFIED: 0.30,
            },
        )
    elif match_method == MatchMethod.MANUAL:
        confidence = Decimal(str(round(rng.uniform(0.70, 0.95), 4)))
        state = _weighted_choice(
            rng,
            {
                VerificationState.NEEDS_REVIEW: 0.45,
                VerificationState.VERIFIED: 0.30,
                VerificationState.UNVERIFIED: 0.25,
            },
        )
    else:
        confidence = Decimal(str(round(rng.uniform(0.45, 0.85), 4)))
        state = _weighted_choice(
            rng,
            {
                VerificationState.UNVERIFIED: 0.60,
                VerificationState.NEEDS_REVIEW: 0.35,
                VerificationState.REJECTED: 0.05,
            },
        )

    return _quantize_money(confidence * Decimal("100")) / Decimal("100"), state


def _make_entity_link(
    policy: GenerationPolicy,
    rng: random.Random,
    index: int,
    account_id: str,
    entity_id: str,
    match_method: MatchMethod,
    used_ids: set[str],
    used_keys: set[tuple[str, str, str, str]],
) -> Optional[dict[str, Any]]:
    """
    Build one time-bound synthetic account-entity link.

    Returns None when the link would duplicate an existing key.
    """
    valid_from = _random_datetime(rng, policy.date_start, policy.date_end)
    valid_to: Optional[datetime] = None

    if rng.random() < 0.35:
        candidate_valid_to = valid_from + timedelta(days=rng.randint(1, 365))

        if candidate_valid_to > policy.date_end:
            candidate_valid_to = policy.date_end

        if candidate_valid_to > valid_from:
            valid_to = candidate_valid_to

    source = SOURCE_SYSTEM
    key = (account_id, entity_id, valid_from.isoformat(), source)

    if key in used_keys:
        return None

    used_keys.add(key)

    link_id = _unique_id("link", [index, account_id, entity_id, valid_from.isoformat()], policy, used_ids)
    confidence, verification_state = _link_confidence_and_state(rng, match_method)

    metadata = _safe_metadata(
        {
            "synthetic": True,
            "source": SOURCE_SYSTEM,
            "generator_version": GENERATOR_VERSION,
        }
    )

    return {
        "id": link_id,
        "account_id": account_id,
        "entity_id": entity_id,
        "match_method": match_method.value,
        "confidence": str(confidence),
        "verification_state": verification_state.value,
        "valid_from": valid_from.isoformat(),
        "valid_to": valid_to.isoformat() if valid_to else None,
        "source": source,
        "metadata_json": metadata,
    }


def _generate_entities_and_links(
    policy: GenerationPolicy,
    rng: random.Random,
    accounts: Sequence[dict[str, Any]],
    clusters: Sequence[_Cluster],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Generate pseudonymous entities and bounded account-entity links.
    """
    entities: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []

    used_entity_ids: set[str] = set()
    used_link_ids: set[str] = set()
    used_link_keys: set[tuple[str, str, str, str]] = set()

    account_ids = [str(account["id"]) for account in accounts if account.get("id")]

    if not account_ids or policy.entities <= 0:
        return entities, links

    entity_index = 0
    link_index = 0

    # Cluster-shared entities.
    for cluster in clusters:
        if len(entities) >= policy.entities:
            break

        if not cluster.accounts:
            continue

        shared_target = max(1, int(policy.entities * policy.shared_entity_rate / max(1, len(clusters))))
        shared_count = min(shared_target, rng.randint(1, 3), policy.entities - len(entities))

        for _ in range(shared_count):
            entity_type = _weighted_choice(rng, _ENTITY_TYPE_WEIGHTS)
            entity = _make_entity(policy, rng, entity_index, entity_type, used_entity_ids)
            entity_id = str(entity["id"])

            entities.append(entity)
            entity_index += 1

            max_subset = min(len(cluster.accounts), 8, policy.entity_links - len(links))

            if max_subset >= 2:
                subset = rng.sample(cluster.accounts, max_subset)
                match_method = _weighted_choice(
                    rng,
                    {
                        MatchMethod.EXACT: 0.55,
                        MatchMethod.NORMALIZED: 0.25,
                        MatchMethod.ENTITY_TEMPORAL: 0.20,
                    },
                )

                for account_id in subset:
                    if len(links) >= policy.entity_links:
                        break

                    link = _make_entity_link(
                        policy,
                        rng,
                        link_index,
                        account_id,
                        entity_id,
                        match_method,
                        used_link_ids,
                        used_link_keys,
                    )

                    if link is not None:
                        links.append(link)
                        link_index += 1

    # Individual entities for some accounts.
    shuffled_accounts = list(account_ids)
    rng.shuffle(shuffled_accounts)

    individual_target = int(policy.entities * policy.individual_entity_rate)

    for account_id in shuffled_accounts:
        if len(entities) >= policy.entities:
            break

        if individual_target <= 0:
            break

        individual_target -= 1

        entity_type = _weighted_choice(rng, _ENTITY_TYPE_WEIGHTS)
        entity = _make_entity(policy, rng, entity_index, entity_type, used_entity_ids)
        entity_id = str(entity["id"])

        entities.append(entity)
        entity_index += 1

        if len(links) < policy.entity_links:
            link = _make_entity_link(
                policy,
                rng,
                link_index,
                account_id,
                entity_id,
                MatchMethod.EXACT,
                used_link_ids,
                used_link_keys,
            )

            if link is not None:
                links.append(link)
                link_index += 1

    # Fill remaining entities as noise entities without mandatory links.
    while len(entities) < policy.entities:
        entity_type = _weighted_choice(rng, _ENTITY_TYPE_WEIGHTS)
        entity = _make_entity(policy, rng, entity_index, entity_type, used_entity_ids)
        entities.append(entity)
        entity_index += 1

    # Fill remaining links with random account-entity associations.
    while len(links) < policy.entity_links and entities and account_ids:
        account_id = rng.choice(account_ids)
        entity_id = str(rng.choice(entities)["id"])

        match_method = _weighted_choice(
            rng,
            {
                MatchMethod.NORMALIZED: 0.55,
                MatchMethod.ENTITY_TEMPORAL: 0.25,
                MatchMethod.EXACT: 0.15,
                MatchMethod.MANUAL: 0.05,
            },
        )

        link = _make_entity_link(
            policy,
            rng,
            link_index,
            account_id,
            entity_id,
            match_method,
            used_link_ids,
            used_link_keys,
        )

        if link is None:
            continue

        links.append(link)
        link_index += 1

    return entities, links


# -----------------------------------------------------------------------------
# Transaction generation
# -----------------------------------------------------------------------------


def _choose_transaction_status(policy: GenerationPolicy, rng: random.Random) -> TransactionStatus:
    """
    Choose a synthetic transaction status from policy rates.

    The table records four states. The cancelled rate joins FAILED, since a
    cancelled transfer moved no money and that is what FAILED means here. The
    disputed rate joins COMPLETED: a disputed transfer did settle, and the
    dispute itself belongs in a complaint record, which is where the
    correlation machinery can act on it.
    """
    weights = {
        TransactionStatus.COMPLETED: policy.completed_rate + policy.disputed_rate,
        TransactionStatus.PENDING: policy.pending_rate,
        TransactionStatus.FAILED: policy.failed_rate + policy.cancelled_rate,
        TransactionStatus.REVERSED: policy.reversed_rate,
    }

    if sum(weights.values()) <= 0:
        return TransactionStatus.COMPLETED

    return _weighted_choice(rng, weights)


def _make_transaction(
    policy: GenerationPolicy,
    rng: random.Random,
    index: int,
    sender_account_id: str,
    receiver_account_id: str,
    amount: Decimal,
    occurred_at: datetime,
    kind: TransactionKind,
    status: TransactionStatus,
    used_ids: set[str],
    used_refs: set[str],
) -> dict[str, Any]:
    """
    Build one synthetic transaction ingestion record.
    """
    transaction_id = _unique_id("txn", [index, sender_account_id, receiver_account_id], policy, used_ids)
    reference = _unique_id("txnref", [index, kind.value, occurred_at.isoformat()], policy, used_refs)

    channel = _weighted_choice(rng, _CHANNEL_WEIGHTS)

    metadata = _safe_metadata(
        {
            "synthetic": True,
            "source": SOURCE_SYSTEM,
            "kind": kind.value,
            "channel": channel.value,
            "generator_version": GENERATOR_VERSION,
        }
    )

    return {
        "id": transaction_id,
        "reference": reference,
        "sender_account_id": sender_account_id,
        "receiver_account_id": receiver_account_id,
        "amount": str(amount),
        "currency": policy.currency,
        "occurred_at": occurred_at.isoformat(),
        "status": status.value,
        "channel": channel.value,
        "metadata_json": metadata,
    }


def _choose_cluster_pair(
    rng: random.Random,
    cluster: _Cluster,
    account_profiles: Mapping[str, AccountProfile],
) -> tuple[str, str, TransactionKind]:
    """
    Choose a plausible synthetic cluster transaction pair.
    """
    pattern = _weighted_choice(
        rng,
        {
            TransactionKind.MULE_IN: 0.28 if cluster.sources and cluster.mules else 0.01,
            TransactionKind.MULE_OUT: 0.30 if cluster.mules and (cluster.funnels or cluster.beneficiaries) else 0.01,
            TransactionKind.FUNNEL: 0.18 if cluster.funnels and cluster.beneficiaries else 0.01,
            TransactionKind.CHAIN: 0.08 if len(cluster.mules) >= 2 else 0.01,
            TransactionKind.DEPOSIT: 0.06 if cluster.sources else 0.01,
            TransactionKind.WITHDRAWAL: 0.05 if cluster.beneficiaries else 0.01,
            TransactionKind.NOISE: 0.05,
        },
    )

    any_account = rng.choice(cluster.accounts) if cluster.accounts else ""

    if pattern == TransactionKind.MULE_IN and cluster.sources and cluster.mules:
        sender = rng.choice(cluster.sources)
        receiver = rng.choice(cluster.mules)
    elif pattern == TransactionKind.MULE_OUT and cluster.mules:
        sender = rng.choice(cluster.mules)

        if cluster.funnels and rng.random() < 0.70:
            receiver = rng.choice(cluster.funnels)
            pattern = TransactionKind.MULE_OUT
        elif cluster.beneficiaries:
            receiver = rng.choice(cluster.beneficiaries)
            pattern = TransactionKind.BENEFICIARY
        else:
            receiver = rng.choice(cluster.accounts)
    elif pattern == TransactionKind.FUNNEL and cluster.funnels and cluster.beneficiaries:
        sender = rng.choice(cluster.funnels)
        receiver = rng.choice(cluster.beneficiaries)
    elif pattern == TransactionKind.CHAIN and len(cluster.mules) >= 2:
        sender, receiver = rng.sample(cluster.mules, 2)
    elif pattern == TransactionKind.DEPOSIT and cluster.sources:
        sender = rng.choice(cluster.sources)
        receiver = rng.choice(cluster.accounts)
    elif pattern == TransactionKind.WITHDRAWAL and cluster.beneficiaries:
        sender = rng.choice(cluster.accounts)
        receiver = rng.choice(cluster.beneficiaries)
    else:
        sender = rng.choice(cluster.accounts)
        receiver = rng.choice(cluster.accounts)
        pattern = TransactionKind.NOISE

    if not sender or not receiver or sender == receiver:
        candidates = [account for account in cluster.accounts if account != sender]

        if candidates:
            receiver = rng.choice(candidates)
        else:
            receiver = any_account

    if sender == receiver:
        pattern = TransactionKind.NOISE

    return sender, receiver, pattern


def _generate_cluster_transactions(
    policy: GenerationPolicy,
    rng: random.Random,
    clusters: Sequence[_Cluster],
    account_profiles: Mapping[str, AccountProfile],
    budget: int,
    used_ids: set[str],
    used_refs: set[str],
) -> list[dict[str, Any]]:
    """
    Generate bounded synthetic cluster transactions.
    """
    transactions: list[dict[str, Any]] = []

    if budget <= 0 or not clusters:
        return transactions

    total_cluster_accounts = sum(len(cluster.accounts) for cluster in clusters)

    if total_cluster_accounts <= 0:
        return transactions

    remaining = budget
    index = 0

    for cluster_position, cluster in enumerate(clusters):
        if remaining <= 0:
            break

        if cluster_position == len(clusters) - 1:
            allocation = remaining
        else:
            allocation = int(budget * len(cluster.accounts) / total_cluster_accounts)
            allocation = max(0, min(allocation, remaining))

        remaining -= allocation

        if allocation <= 0 or len(cluster.accounts) < 2:
            continue

        base_time = _random_datetime(
            rng,
            policy.date_start,
            policy.date_end - timedelta(hours=1),
        )

        cluster_transactions: list[dict[str, Any]] = []

        for _ in range(allocation):
            sender, receiver, kind = _choose_cluster_pair(rng, cluster, account_profiles)

            if not sender or not receiver or sender == receiver:
                continue

            sender_profile = account_profiles.get(sender, AccountProfile.OTHER)
            receiver_profile = account_profiles.get(receiver, AccountProfile.OTHER)
            scale = max(
                _PROFILE_AMOUNT_SCALE.get(sender_profile, 2_000.0),
                _PROFILE_AMOUNT_SCALE.get(receiver_profile, 2_000.0),
            )

            if kind in {TransactionKind.MULE_OUT, TransactionKind.FUNNEL, TransactionKind.BENEFICIARY}:
                scale *= rng.uniform(0.75, 1.25)

            amount = _random_amount(rng, scale, policy.min_amount, policy.max_amount)
            occurred_at = base_time + timedelta(minutes=rng.randint(0, 10_080))

            if occurred_at > policy.date_end:
                occurred_at = policy.date_end

            if kind in {TransactionKind.MULE_IN, TransactionKind.MULE_OUT, TransactionKind.FUNNEL}:
                status = (
                    TransactionStatus.COMPLETED
                    if rng.random() < 0.92
                    else _choose_transaction_status(policy, rng)
                )
            else:
                status = _choose_transaction_status(policy, rng)

            transaction = _make_transaction(
                policy,
                rng,
                index,
                sender,
                receiver,
                amount,
                occurred_at,
                kind,
                status,
                used_ids,
                used_refs,
            )

            cluster_transactions.append(transaction)
            cluster.transaction_refs.append(str(transaction["reference"]))
            index += 1

        cluster_transactions.sort(key=lambda item: item.get("occurred_at") or "")
        transactions.extend(cluster_transactions)

    return transactions


def _generate_noise_transactions(
    policy: GenerationPolicy,
    rng: random.Random,
    accounts: Sequence[dict[str, Any]],
    account_profiles: Mapping[str, AccountProfile],
    count: int,
    start_index: int,
    used_ids: set[str],
    used_refs: set[str],
) -> list[dict[str, Any]]:
    """
    Generate bounded synthetic background noise transactions.
    """
    transactions: list[dict[str, Any]] = []

    if count <= 0 or len(accounts) < 2:
        return transactions

    account_ids = [str(account["id"]) for account in accounts if account.get("id")]

    if len(account_ids) < 2:
        return transactions

    index = start_index

    for _ in range(count):
        sender, receiver = rng.sample(account_ids, 2)

        sender_profile = account_profiles.get(sender, AccountProfile.OTHER)
        receiver_profile = account_profiles.get(receiver, AccountProfile.OTHER)
        scale = (
            _PROFILE_AMOUNT_SCALE.get(sender_profile, 2_000.0)
            + _PROFILE_AMOUNT_SCALE.get(receiver_profile, 2_000.0)
        ) / 2.0

        amount = _random_amount(rng, scale, policy.min_amount, policy.max_amount)
        occurred_at = _random_datetime(rng, policy.date_start, policy.date_end)
        status = _choose_transaction_status(policy, rng)

        transaction = _make_transaction(
            policy,
            rng,
            index,
            sender,
            receiver,
            amount,
            occurred_at,
            TransactionKind.NOISE,
            status,
            used_ids,
            used_refs,
        )

        transactions.append(transaction)
        index += 1

    return transactions


def _generate_transactions(
    policy: GenerationPolicy,
    rng: random.Random,
    accounts: Sequence[dict[str, Any]],
    clusters: Sequence[_Cluster],
    account_profiles: Mapping[str, AccountProfile],
) -> list[dict[str, Any]]:
    """
    Generate bounded synthetic transactions with referential integrity.
    """
    used_ids: set[str] = set()
    used_refs: set[str] = set()

    if policy.transactions <= 0 or len(accounts) < 2:
        return []

    cluster_budget = int(policy.transactions * policy.cluster_transaction_rate) if clusters else 0
    cluster_transactions = _generate_cluster_transactions(
        policy,
        rng,
        clusters,
        account_profiles,
        cluster_budget,
        used_ids,
        used_refs,
    )

    remaining = max(0, policy.transactions - len(cluster_transactions))
    noise_transactions = _generate_noise_transactions(
        policy,
        rng,
        accounts,
        account_profiles,
        remaining,
        len(cluster_transactions),
        used_ids,
        used_refs,
    )

    transactions = [*cluster_transactions, *noise_transactions]
    transactions.sort(key=lambda item: item.get("occurred_at") or "")

    return transactions[: policy.transactions]


# -----------------------------------------------------------------------------
# Complaint generation
# -----------------------------------------------------------------------------


def _synthetic_narrative(
    rng: random.Random,
    category: ComplaintCategory,
    channel: Channel,
    amount: Optional[Decimal],
    currency: str,
) -> str:
    """
    Generate clearly synthetic complaint narrative template text.
    """
    template = rng.choice(_COMPLAINT_NARRATIVE_TEMPLATES)

    amount_text = str(amount) if amount is not None else "an unspecified"
    category_text = category.value.replace("_", " ")

    narrative = template.format(
        channel=channel.value,
        amount=amount_text,
        currency=currency,
        category=category_text,
    )

    suffixes = (
        " This is synthetic demo text.",
        " No real customer data is present.",
        " Generated for investigative workflow testing only.",
        " Treat as an investigative lead only.",
    )

    narrative = f"{narrative}{rng.choice(suffixes)}"
    return _clean_narrative(narrative, _HARD_MAX_NARRATIVE_LENGTH)


def _make_complaint(
    policy: GenerationPolicy,
    rng: random.Random,
    index: int,
    account_ids: Sequence[str],
    transaction_refs: Sequence[str],
    transaction_time_by_ref: Mapping[str, datetime],
    used_ids: set[str],
    used_refs: set[str],
) -> Optional[dict[str, Any]]:
    """
    Build one synthetic complaint ingestion record.
    """
    if not account_ids:
        return None

    complaint_id = _unique_id("cmpl", [index], policy, used_ids)
    reference = _unique_id("cmplref", [index, complaint_id], policy, used_refs)

    category = _weighted_choice(rng, _COMPLAINT_CATEGORY_WEIGHTS)
    channel = _weighted_choice(rng, _CHANNEL_WEIGHTS)

    amount: Optional[Decimal] = None

    if rng.random() < 0.80:
        amount = _random_amount(
            rng,
            10_000.0,
            policy.min_amount,
            policy.max_amount,
        )

    narrative = _synthetic_narrative(
        rng,
        category,
        channel,
        amount,
        policy.currency,
    )

    victim_account_id: Optional[str] = None
    suspected_account_id: Optional[str] = None

    if len(account_ids) >= 2 and rng.random() < 0.85:
        victim_account_id, suspected_account_id = rng.sample(list(account_ids), 2)
    elif account_ids:
        victim_account_id = rng.choice(list(account_ids))

    transaction_reference: Optional[str] = None
    reported_at = _random_datetime(rng, policy.date_start, policy.date_end)

    if transaction_refs and rng.random() < 0.65:
        candidate_ref = rng.choice(list(transaction_refs))
        transaction_reference = candidate_ref

        related_time = transaction_time_by_ref.get(candidate_ref)

        if related_time is not None:
            reported_at = related_time + timedelta(hours=rng.randint(1, 720))

            if reported_at > policy.date_end:
                reported_at = policy.date_end

            if reported_at < policy.date_start:
                reported_at = policy.date_start

    metadata = _safe_metadata(
        {
            "synthetic": True,
            "source": SOURCE_SYSTEM,
            "category": category.value,
            "channel_hint": channel.value,
            "generator_version": GENERATOR_VERSION,
        }
    )

    return {
        "id": complaint_id,
        "reference": reference,
        "reported_at": reported_at.isoformat(),
        "category": category.value,
        "narrative_raw": narrative,
        "transaction_reference": transaction_reference,
        "victim_account_id": victim_account_id,
        "suspected_account_id": suspected_account_id,
        "amount": str(amount) if amount is not None else None,
        "currency": policy.currency if amount is not None else None,
        "source": SOURCE_SYSTEM,
        "metadata_json": metadata,
    }


def _generate_complaints(
    policy: GenerationPolicy,
    rng: random.Random,
    accounts: Sequence[dict[str, Any]],
    clusters: Sequence[_Cluster],
    transactions: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate bounded synthetic complaints with optional transaction references.
    """
    if policy.complaints <= 0 or not accounts:
        return []

    account_ids = [str(account["id"]) for account in accounts if account.get("id")]

    if not account_ids:
        return []

    completed_refs = [
        str(transaction["reference"])
        for transaction in transactions
        if transaction.get("reference")
        and str(transaction.get("status", "")).upper() == TransactionStatus.COMPLETED.value
    ]

    transaction_time_by_ref: dict[str, datetime] = {}

    for transaction in transactions:
        ref = transaction.get("reference")
        occurred_at = transaction.get("occurred_at")

        if not ref or not occurred_at:
            continue

        try:
            transaction_time_by_ref[str(ref)] = datetime.fromisoformat(str(occurred_at))
        except Exception:
            continue

    used_ids: set[str] = set()
    used_refs: set[str] = set()

    complaints: list[dict[str, Any]] = []
    cluster_complaint_count = int(policy.complaints * policy.cluster_complaint_rate) if clusters else 0
    individual_complaint_count = max(0, policy.complaints - cluster_complaint_count)

    index = 0

    # Cluster-linked complaints.
    for _ in range(cluster_complaint_count):
        if len(complaints) >= policy.complaints:
            break

        cluster = rng.choice(list(clusters))
        cluster_account_ids = [account_id for account_id in cluster.accounts if account_id in account_ids]

        if len(cluster_account_ids) < 2:
            continue

        complaint = _make_complaint(
            policy,
            rng,
            index,
            cluster_account_ids,
            cluster.transaction_refs or completed_refs,
            transaction_time_by_ref,
            used_ids,
            used_refs,
        )

        if complaint is not None:
            complaints.append(complaint)
            index += 1

    # Individual/noise complaints.
    while len(complaints) < policy.complaints:
        complaint = _make_complaint(
            policy,
            rng,
            index,
            account_ids,
            completed_refs,
            transaction_time_by_ref,
            used_ids,
            used_refs,
        )

        if complaint is None:
            break

        complaints.append(complaint)
        index += 1

    complaints.sort(key=lambda item: item.get("reported_at") or "")
    return complaints[: policy.complaints]


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------


def _validate_dataset(
    dataset: SyntheticDataset,
    policy: GenerationPolicy,
) -> None:
    """
    Validate referential integrity and basic safety invariants.

    This does not replace API-level Pydantic validation. It catches generator
    bugs before records are handed to ingestion services.
    """
    account_ids = {str(record.get("id")) for record in dataset.accounts if record.get("id")}
    entity_ids = {str(record.get("id")) for record in dataset.entities if record.get("id")}
    transaction_refs = {
        str(record.get("reference"))
        for record in dataset.transactions
        if record.get("reference")
    }

    if len(account_ids) != len(dataset.accounts):
        raise MuleGuardValidationError(
            "Generated account identifiers are not unique.",
            details={"reason": "duplicate_account_id"},
        )

    if len(entity_ids) != len(dataset.entities):
        raise MuleGuardValidationError(
            "Generated entity identifiers are not unique.",
            details={"reason": "duplicate_entity_id"},
        )

    for transaction in dataset.transactions:
        sender = str(transaction.get("sender_account_id") or "")
        receiver = str(transaction.get("receiver_account_id") or "")

        if sender not in account_ids:
            raise MuleGuardValidationError(
                "Generated transaction references an unknown sender account.",
                details={"reason": "unknown_sender_account", "field": "sender_account_id"},
            )

        if receiver not in account_ids:
            raise MuleGuardValidationError(
                "Generated transaction references an unknown receiver account.",
                details={"reason": "unknown_receiver_account", "field": "receiver_account_id"},
            )

        if sender == receiver:
            raise MuleGuardValidationError(
                "Generated transaction sender and receiver must differ.",
                details={"reason": "self_reference_transaction"},
            )

    for link in dataset.entity_links:
        account_id = str(link.get("account_id") or "")
        entity_id = str(link.get("entity_id") or "")

        if account_id not in account_ids:
            raise MuleGuardValidationError(
                "Generated entity link references an unknown account.",
                details={"reason": "unknown_link_account", "field": "account_id"},
            )

        if entity_id not in entity_ids:
            raise MuleGuardValidationError(
                "Generated entity link references an unknown entity.",
                details={"reason": "unknown_link_entity", "field": "entity_id"},
            )

    for complaint in dataset.complaints:
        victim = complaint.get("victim_account_id")
        suspected = complaint.get("suspected_account_id")
        transaction_reference = complaint.get("transaction_reference")

        if victim and str(victim) not in account_ids:
            raise MuleGuardValidationError(
                "Generated complaint references an unknown victim account.",
                details={"reason": "unknown_victim_account", "field": "victim_account_id"},
            )

        if suspected and str(suspected) not in account_ids:
            raise MuleGuardValidationError(
                "Generated complaint references an unknown suspected account.",
                details={"reason": "unknown_suspected_account", "field": "suspected_account_id"},
            )

        if victim and suspected and str(victim) == str(suspected):
            raise MuleGuardValidationError(
                "Generated complaint victim and suspected account must differ.",
                details={"reason": "same_victim_and_suspect"},
            )

        if transaction_reference and str(transaction_reference) not in transaction_refs:
            raise MuleGuardValidationError(
                "Generated complaint references an unknown transaction.",
                details={"reason": "unknown_transaction_reference", "field": "transaction_reference"},
            )

    if len(dataset.accounts) > policy.accounts:
        raise MuleGuardValidationError(
            "Generated account count exceeds policy.",
            details={"reason": "account_count_exceeds_policy"},
        )

    if len(dataset.transactions) > policy.transactions:
        raise MuleGuardValidationError(
            "Generated transaction count exceeds policy.",
            details={"reason": "transaction_count_exceeds_policy"},
        )

    if len(dataset.complaints) > policy.complaints:
        raise MuleGuardValidationError(
            "Generated complaint count exceeds policy.",
            details={"reason": "complaint_count_exceeds_policy"},
        )

    if len(dataset.entities) > policy.entities:
        raise MuleGuardValidationError(
            "Generated entity count exceeds policy.",
            details={"reason": "entity_count_exceeds_policy"},
        )

    if len(dataset.entity_links) > policy.entity_links:
        raise MuleGuardValidationError(
            "Generated entity link count exceeds policy.",
            details={"reason": "entity_link_count_exceeds_policy"},
        )


# -----------------------------------------------------------------------------
# Manifest
# -----------------------------------------------------------------------------


def _build_manifest(
    policy: GenerationPolicy,
    dataset: SyntheticDataset,
    cluster_count: int,
) -> dict[str, Any]:
    """
    Build a safe generator manifest.

    The manifest never includes the salt, raw identifiers, ground-truth labels,
    scenario IDs, or fraud-ring IDs.
    """
    seed_fingerprint = _hmac_hex(policy.salt, f"seed:{policy.seed}")

    counts = dataset.counts()

    generation_id = _stable_hash(
        [
            GENERATOR_VERSION,
            seed_fingerprint,
            str(counts["accounts"]),
            str(counts["transactions"]),
            str(counts["complaints"]),
            str(counts["entities"]),
            str(counts["entity_links"]),
            policy.date_start.isoformat(),
            policy.date_end.isoformat(),
        ]
    )[:32]

    return {
        "generator": "muleguard.synthetic.generator",
        "version": GENERATOR_VERSION,
        "generation_id": generation_id,
        "generated_at": _now_utc().isoformat(),
        "seed_fingerprint": seed_fingerprint,
        "cluster_count": cluster_count,
        "counts": counts,
        "ingestion_order": [
            "accounts",
            "entities",
            "entity_links",
            "transactions",
            "complaints",
        ],
        "policy": policy.safe_summary(),
        "caveats": list(_GENERATOR_CAVEATS),
        "safety_flags": {
            "synthetic_only": True,
            "no_real_customer_data": True,
            "no_ground_truth_labels_in_manifest": True,
            "no_scenario_ids_in_manifest": True,
            "no_fraud_ring_ids_in_manifest": True,
            "no_raw_identifier_disclosure": True,
            "no_secrets_in_manifest": True,
            "no_automatic_adverse_action": True,
            "not_production_ready": True,
        },
    }


def _build_labels(
    accounts: Sequence[Mapping[str, Any]],
    clusters: Sequence["_Cluster"],
    account_profiles: Mapping[str, AccountProfile],
) -> list[dict[str, Any]]:
    """
    Build the ground-truth label set, kept out of the records.

    One entry per generated account. `is_mule` collapses the behavioural
    profile into the binary target an evaluation actually uses, and the
    profile itself is kept because the multiclass view is occasionally what
    you want and recomputing it from the binary one is impossible.

    `ring_id` is what makes a grouped split possible. Without it an evaluation
    can only split randomly, which puts four accounts of a five-account ring
    in training and the fifth in test, and then reports how well the model
    memorised that ring.
    """
    ring_of: dict[str, str] = {}

    for index, cluster in enumerate(clusters):
        ring_id = f"ring-{index + 1:04d}"

        for account_id in cluster.accounts:
            ring_of[str(account_id)] = ring_id

    mule_profiles = {
        AccountProfile.MULE,
        AccountProfile.FUNNEL,
    }

    labels: list[dict[str, Any]] = []

    for account in accounts:
        account_id = str(account.get("id"))
        profile = account_profiles.get(account_id)

        labels.append(
            {
                "account_id": account_id,
                "profile": profile.value if profile is not None else None,
                "is_mule": bool(profile in mule_profiles),
                "ring_id": ring_of.get(account_id),
            }
        )

    return labels


# -----------------------------------------------------------------------------
# Public generation API
# -----------------------------------------------------------------------------


def generate_synthetic_dataset(
    policy: GenerationPolicy | None = None,
    settings: Any | None = None,
) -> SyntheticDataset:
    """
    Generate a bounded synthetic dataset for ingestion workflows.

    The records are ingestion-compatible dictionaries. Ground truth is
    returned alongside them in `dataset.labels` rather than on them, so that
    loading a dataset cannot load its answers. Nothing here persists records
    or touches a database or network.
    """
    resolved_policy = policy or GenerationPolicy.from_settings(settings)
    rng = random.Random(resolved_policy.seed)

    accounts, clusters, account_profiles = _generate_accounts_and_clusters(resolved_policy, rng)
    entities, entity_links = _generate_entities_and_links(resolved_policy, rng, accounts, clusters)
    transactions = _generate_transactions(resolved_policy, rng, accounts, clusters, account_profiles)
    complaints = _generate_complaints(resolved_policy, rng, accounts, clusters, transactions)

    dataset = SyntheticDataset(
        accounts=accounts,
        transactions=transactions,
        complaints=complaints,
        entities=entities,
        entity_links=entity_links,
        manifest={},
        labels=_build_labels(accounts, clusters, account_profiles),
    )

    _validate_dataset(dataset, resolved_policy)

    if resolved_policy.include_manifest:
        dataset.manifest = _build_manifest(resolved_policy, dataset, len(clusters))
    else:
        dataset.manifest = {
            "generator": "muleguard.synthetic.generator",
            "version": GENERATOR_VERSION,
            "counts": dataset.counts(),
            "caveats": list(_GENERATOR_CAVEATS),
        }

    return dataset


def build_ingestion_payloads(
    dataset: SyntheticDataset,
    *,
    source_system: str = SOURCE_SYSTEM,
) -> dict[str, dict[str, Any]]:
    """
    Build ingestion endpoint request payloads from a generated dataset.

    Recommended ingestion order is:

    1. accounts
    2. entities
    3. entity_links
    4. transactions
    5. complaints
    """
    generation_id = str(dataset.manifest.get("generation_id") or _stable_hash([SOURCE_SYSTEM])[:16])

    def options(entity_type: str) -> dict[str, Any]:
        return {
            "source_system": _clean_text(source_system, 100),
            "source_batch_id": _clean_text(f"{generation_id}-{entity_type}", 100),
            "dry_run": False,
            "allow_partial": False,
            "on_duplicate": "reject",
        }

    return {
        "accounts": {
            "records": dataset.accounts,
            "options": options("accounts"),
        },
        "entities": {
            "records": dataset.entities,
            "options": options("entities"),
        },
        "entity_links": {
            "records": dataset.entity_links,
            "options": options("entity_links"),
        },
        "transactions": {
            "records": dataset.transactions,
            "options": options("transactions"),
        },
        "complaints": {
            "records": dataset.complaints,
            "options": options("complaints"),
        },
    }


def iter_ingestion_batches(
    dataset: SyntheticDataset,
    *,
    max_batch_size: Optional[int] = None,
    source_system: str = SOURCE_SYSTEM,
) -> Iterator[SyntheticBatch]:
    """
    Iterate dependency-safe ingestion batches from a generated dataset.

    This helper chunks records according to the policy batch size or an explicit
    override. It never mutates the dataset.
    """
    payloads = build_ingestion_payloads(dataset, source_system=source_system)
    generation_id = str(dataset.manifest.get("generation_id") or "synthetic")

    ordered_types = (
        "accounts",
        "entities",
        "entity_links",
        "transactions",
        "complaints",
    )

    resolved_max_batch_size = max(
        1,
        min(
            int(max_batch_size or dataset.manifest.get("policy", {}).get("max_batch_size", _DEFAULT_MAX_BATCH_SIZE)),
            _HARD_MAX_BATCH_SIZE,
        ),
    )

    total_batches = 0

    for entity_type in ordered_types:
        records = payloads[entity_type]["records"]

        if not records:
            continue

        total_batches += math.ceil(len(records) / resolved_max_batch_size)

    emitted = 0

    for entity_type in ordered_types:
        records = payloads[entity_type]["records"]
        base_options = payloads[entity_type]["options"]

        if not records:
            continue

        for start in range(0, len(records), resolved_max_batch_size):
            chunk = records[start : start + resolved_max_batch_size]
            batch_index = start // resolved_max_batch_size

            options = dict(base_options)
            options["source_batch_id"] = _clean_text(
                f"{generation_id}-{entity_type}-{batch_index}",
                100,
            )

            emitted += 1

            yield SyntheticBatch(
                entity_type=entity_type,
                records=chunk,
                options=options,
                index=emitted - 1,
                total_batches=total_batches,
            )


def get_generator_metadata() -> dict[str, Any]:
    """
    Return safe generator metadata for diagnostics and documentation checks.
    """
    default_policy = GenerationPolicy()

    return {
        "package": "muleguard.backend.ingestion.generator",
        "version": GENERATOR_VERSION,
        "source_system": SOURCE_SYSTEM,
        "hard_limits": {
            "max_accounts": _HARD_MAX_ACCOUNTS,
            "max_transactions": _HARD_MAX_TRANSACTIONS,
            "max_complaints": _HARD_MAX_COMPLAINTS,
            "max_entities": _HARD_MAX_ENTITIES,
            "max_entity_links": _HARD_MAX_ENTITY_LINKS,
            "max_batch_size": _HARD_MAX_BATCH_SIZE,
            "max_date_span_days": _HARD_MAX_DATE_SPAN_DAYS,
            "max_narrative_length": _HARD_MAX_NARRATIVE_LENGTH,
        },
        "default_policy": default_policy.safe_summary(),
        "caveats": list(_GENERATOR_CAVEATS),
        "safety_flags": {
            "synthetic_only": True,
            "no_real_customer_data": True,
            "no_ground_truth_labels_in_public_output": True,
            "no_scenario_ids_in_public_output": True,
            "no_fraud_ring_ids_in_public_output": True,
            "no_raw_identifier_disclosure": True,
            "no_secrets_in_public_output": True,
            "no_automatic_adverse_action": True,
            "does_not_persist_data": True,
            "not_production_ready": True,
        },
    }


__all__ = [
    "AccountProfile",
    "AccountStatus",
    "AccountType",
    "Channel",
    "ComplaintCategory",
    "EntityType",
    "GenerationPolicy",
    "MatchMethod",
    "SyntheticBatch",
    "SyntheticDataset",
    "TransactionKind",
    "TransactionStatus",
    "VerificationState",
    "build_ingestion_payloads",
    "generate_synthetic_dataset",
    "get_generator_metadata",
    "iter_ingestion_batches",
]