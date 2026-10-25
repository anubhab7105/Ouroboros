"""
MULEGUARD backend synthetic demo seeding and reset.

This module provisions bounded, deterministic, privacy-preserving synthetic
MULEGUARD datasets for local demo, test, fixture, and offline evaluation
workflows.

Primary responsibilities:

- generate synthetic accounts, transactions, complaints, pseudonymous entities,
  and account-entity links using `app.ingestion.generator`;
- persist generated records in dependency-safe order through bounded batches;
- remain idempotent for a given seed, salt, and policy;
- enforce synthetic-first, local-only, production-like-blocked seeding policy;
- provide an explicitly confirmed local demo reset surface;
- record safe audit events for material seeding and reset operations;
- return bounded, sanitized summaries without exposing raw narratives,
  secrets, tokens, passwords, database URLs, model artifact paths,
  ground-truth labels, scenario IDs, fraud-ring IDs, or real customer data.

This module does not fabricate investigative conclusions. It only creates
synthetic investigative inputs.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be seeded.
- Seeding is blocked in production-like environments.
- Reset is destructive and requires an explicit confirmation phrase.
- Reset is limited to local/demo synthetic workflow data and must not be used
  against real customer systems.
- Generated records are investigative inputs only.
- Generated records are not proof of wrongdoing.
- Generated records must not trigger automatic adverse customer action.
- Raw complaint narratives may be persisted only where required by the
  synthetic complaint workflow, but are never returned in seed summaries.
- Entity identifiers are pseudonymously hashed by the generator and raw
  identifiers are not emitted.
- Public summaries do not include ground-truth labels, injected scenario IDs,
  or fraud-ring IDs.
- Audit metadata is sanitized before persistence.

Explicit non-goals:

- This module does not connect to real banking systems.
- This module does not ingest real customer data.
- This module does not train models.
- This module does not evaluate models.
- This module does not generate reports.
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

import argparse
import hashlib
import json
import logging
import re
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Final, Optional

from sqlalchemy import delete, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db import session_scope
from app.exceptions import (
    ConfigurationError,
    FeatureFlagDisabledError,
    ValidationError as MuleGuardValidationError,
)
from app.ingestion.generator import (
    GenerationPolicy,
    SyntheticDataset,
    generate_synthetic_dataset,
)
from app.models import (
    Account,
    AccountEntityLink,
    AccountStatus,
    AccountType,
    AuditEvent,
    AuditOutcome,
    Channel,
    Complaint,
    Entity,
    EntityType,
    MatchMethod,
    Transaction,
    TransactionStatus,
    VerificationState,
)

logger = logging.getLogger("muleguard.backend.ingestion.seed")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

SEED_VERSION: Final[str] = "v1"
SOURCE_SYSTEM: Final[str] = "seed"
RESET_SOURCE_SYSTEM: Final[str] = "seed_reset"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_MAX_BATCH_SIZE: Final[int] = 1_000
_HARD_MAX_BATCH_SIZE: Final[int] = 10_000
_MAX_ERRORS_RETURNED: Final[int] = 100
_MAX_STRING_LENGTH: Final[int] = 512
_MAX_NARRATIVE_LENGTH: Final[int] = 20_000
_MAX_METADATA_DEPTH: Final[int] = 6
_MAX_METADATA_SEQUENCE_LENGTH: Final[int] = 50
_MAX_METADATA_MAPPING_KEYS: Final[int] = 50

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")

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

_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
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

_SENSITIVE_KEY_TOKENS: Final[tuple[str, ...]] = (
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

_SEED_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype seeding only. Do not use with real customer data.",
    "Seeded records are investigative inputs only and are not proof of wrongdoing.",
    "Seeding must not trigger automatic adverse customer action.",
    "Seeding is blocked in production-like environments.",
    "Reset is destructive and requires an explicit confirmation phrase.",
    "Raw complaint narratives may be persisted for synthetic workflow testing but are never returned in seed summaries.",
    "Entity identifiers are pseudonymously hashed and raw identifiers are not emitted.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed.",
    "Batch processing is bounded by configured batch size and error-reporting limits.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _get_settings() -> Any:
    """
    Resolve settings lazily to avoid import cycles.
    """
    try:
        from app.core.config import get_settings

        return get_settings()
    except Exception:
        return {}


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


def _parse_dt(value: Any, default: Optional[datetime] = None) -> Optional[datetime]:
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


def _parse_decimal(value: Any, default: Optional[Decimal] = None) -> Optional[Decimal]:
    """
    Parse a decimal-like value and quantize monetary precision.
    """
    if value is None or value == "":
        return default

    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return default

    if not parsed.is_finite():
        return default

    return parsed.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _normalize_currency(value: Any) -> str:
    """
    Normalize a currency code.
    """
    text = str(value or "INR").strip().upper()

    if _CURRENCY_RE.match(text):
        return text

    return "INR"


def _clean_text(value: Any, limit: int = _MAX_STRING_LENGTH) -> str:
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


def _clean_narrative(value: Any, limit: int = _MAX_NARRATIVE_LENGTH) -> str:
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


def _enum_str(value: Any) -> Optional[str]:
    """
    Return a stable string for enum-like values.
    """
    if value is None:
        return None

    return str(getattr(value, "value", value))


def _enum_from_string(enum_cls: Any, value: Any, default: Any = None) -> Any:
    """
    Coerce a value to an enum member when possible.
    """
    if value is None:
        return default

    if isinstance(value, enum_cls):
        return value

    text = str(value).strip().upper().replace(" ", "_").replace("-", "_")

    try:
        return enum_cls(text)
    except Exception:
        pass

    try:
        return getattr(enum_cls, text)
    except Exception:
        return default


def _stable_hash(parts: Sequence[Any]) -> str:
    """
    Return a stable SHA-256 digest for generator identifiers.
    """
    payload = "|".join(str(part) for part in parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _contains_placeholder(value: str) -> bool:
    """
    Detect obvious template or placeholder secret values.
    """
    if not value:
        return True

    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _is_production_like(settings: Any) -> bool:
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


def _is_synthetic_mode(settings: Any) -> bool:
    """
    Return True when dataset mode is synthetic.
    """
    return str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower() == "synthetic"


def _is_sensitive_key(key: str) -> bool:
    """
    Return True when a metadata key appears sensitive or leakage-prone.
    """
    lowered = key.strip().lower()

    if lowered in _SENSITIVE_KEYS:
        return True

    return any(token in lowered for token in _SENSITIVE_KEY_TOKENS)


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    """
    Convert arbitrary metadata into a bounded, safe structure.
    """
    if depth > _MAX_METADATA_DEPTH:
        return "[truncated-depth]"

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return value

    if isinstance(value, str):
        return _clean_text(value, _MAX_STRING_LENGTH)

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Mapping):
        return _sanitize_mapping(value, depth + 1)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        limited = list(value)[:_MAX_METADATA_SEQUENCE_LENGTH]
        items = [_sanitize_value(item, depth + 1) for item in limited]

        if len(value) > _MAX_METADATA_SEQUENCE_LENGTH:
            items.append({"_truncated": True})

        return items

    return f"<{type(value).__name__}>"


def _sanitize_mapping(value: Any, depth: int = 0) -> dict[str, Any]:
    """
    Return sanitized metadata suitable for persistence and responses.
    """
    if depth > _MAX_METADATA_DEPTH:
        return {"_truncated": True}

    if not isinstance(value, Mapping):
        return {}

    sanitized: dict[str, Any] = {}

    for raw_key, raw_value in list(value.items())[:_MAX_METADATA_MAPPING_KEYS]:
        key = str(raw_key)

        if _is_sensitive_key(key):
            continue

        sanitized[key] = _sanitize_value(raw_value, depth + 1)

        if len(sanitized) >= _MAX_METADATA_MAPPING_KEYS:
            sanitized["_truncated_keys"] = True
            break

    return sanitized


def _model_columns(model: Any) -> set[str]:
    """
    Return mapped column names for a SQLAlchemy model when available.
    """
    table = getattr(model, "__table__", None)

    if table is not None:
        return {str(column.name) for column in table.columns}

    mapper = getattr(model, "__mapper__", None)

    if mapper is not None:
        try:
            return {str(prop.key) for prop in mapper.column_attrs}
        except Exception:
            pass

    return set()


def _is_mapped_model(value: Any) -> bool:
    """
    Return True when a value looks like a SQLAlchemy mapped model.
    """
    return hasattr(value, "__table__") or hasattr(value, "__mapper__")


def _construct_model(model: Any, values: Mapping[str, Any]) -> Any:
    """
    Construct a model using only mapped columns when column metadata is
    available.
    """
    columns = _model_columns(model)

    if columns:
        kwargs = {
            key: value
            for key, value in values.items()
            if key in columns
        }
    else:
        kwargs = dict(values)

    return model(**kwargs)


def _set_attr_if_exists(obj: Any, name: str, value: Any) -> None:
    """
    Set an attribute only when it exists and assignment is safe.
    """
    if value is None:
        return

    if not hasattr(obj, name):
        return

    try:
        setattr(obj, name, value)
    except Exception:
        pass


def _bump(counter: dict[str, int], key: str, amount: int = 1) -> None:
    """
    Increment a bounded counter.
    """
    counter[key] = int(counter.get(key, 0)) + int(amount)


def _chunked(items: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    """
    Chunk a sequence into bounded pieces.
    """
    safe_size = max(1, min(int(size), _HARD_MAX_BATCH_SIZE))

    for start in range(0, len(items), safe_size):
        yield items[start : start + safe_size]


# -----------------------------------------------------------------------------
# Result models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class SeedResult:
    """
    Safe seeding/reset result.

    This object never contains passwords, tokens, raw secrets, raw complaint
    narratives, database URLs, model artifact paths, ground-truth labels,
    scenario IDs, fraud-ring IDs, or real customer data.
    """

    ok: bool = True
    dry_run: bool = False
    reset: bool = False
    started_at: datetime = field(default_factory=_now_utc)
    finished_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    generation_id: Optional[str] = None
    source_system: str = SOURCE_SYSTEM
    source_batch_id: Optional[str] = None
    accepted: dict[str, int] = field(default_factory=dict)
    duplicated: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def finalize(self, started_monotonic: float) -> None:
        """
        Finalize timing metadata.
        """
        self.finished_at = _now_utc()
        self.duration_seconds = round(time.monotonic() - started_monotonic, 3)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a safe JSON-serializable summary.
        """
        return {
            "ok": self.ok,
            "dry_run": self.dry_run,
            "reset": self.reset,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "generation_id": self.generation_id,
            "source_system": self.source_system,
            "source_batch_id": self.source_batch_id,
            "counts": dict(self.counts),
            "accepted": dict(self.accepted),
            "duplicated": dict(self.duplicated),
            "skipped": dict(self.skipped),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "caveats": list(_SEED_CAVEATS),
        }


@dataclass(frozen=True, slots=True)
class SeedOptions:
    """
    Bounded seeding options.
    """

    dry_run: bool = False
    allow_partial: bool = False
    force: bool = False
    reset: bool = False
    confirm_phrase: Optional[str] = None
    source_system: Optional[str] = None
    source_batch_id: Optional[str] = None
    policy: Optional[GenerationPolicy] = None
    request_id: Optional[str] = None
    actor: Optional[Any] = None


# -----------------------------------------------------------------------------
# Error helpers
# -----------------------------------------------------------------------------


def _append_error(
    result: SeedResult,
    *,
    entity_type: Optional[str] = None,
    index: Optional[int] = None,
    code: Optional[str] = None,
    message: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Append one safe error entry.
    """
    if len(result.errors) >= _MAX_ERRORS_RETURNED:
        result.ok = False
        return

    entry: dict[str, Any] = {}

    if entity_type:
        entry["entity_type"] = _clean_text(entity_type, 100)

    if index is not None:
        entry["index"] = int(index)

    if code:
        entry["code"] = _clean_text(code, 100)

    if message:
        entry["message"] = _clean_text(message, 300)

    if details:
        entry["details"] = _sanitize_mapping(details)

    result.errors.append(entry)
    result.ok = False


# -----------------------------------------------------------------------------
# Policy and safety guards
# -----------------------------------------------------------------------------


def _ensure_seed_allowed(settings: Any, *, reset: bool = False) -> None:
    """
    Fail closed when seeding/reset is not allowed by runtime policy.
    """
    if _is_production_like(settings):
        raise FeatureFlagDisabledError(
            "Synthetic seeding/reset is not allowed in production-like environments."
        )

    if not _as_bool(_setting(settings, "SEED_DEMO_DATA", True), True):
        raise FeatureFlagDisabledError(
            "Synthetic demo seeding is disabled by SEED_DEMO_DATA=false."
        )

    if not _is_synthetic_mode(settings) and not _as_bool(
        _setting(settings, "SEED_ALLOW_NON_SYNTHETIC", False),
        False,
    ):
        raise FeatureFlagDisabledError(
            "Synthetic seeding requires BACKEND_DATASET_MODE=synthetic."
        )

    if reset:
        if not _as_bool(_setting(settings, "SEED_RESET_ALLOW_DEMO_ONLY", True), True):
            raise FeatureFlagDisabledError(
                "Synthetic demo reset is disabled by SEED_RESET_ALLOW_DEMO_ONLY=false."
            )

        if _as_bool(_setting(settings, "SEED_RESET_BLOCK_PRODUCTION", True), True):
            if _is_production_like(settings):
                raise FeatureFlagDisabledError(
                    "Synthetic demo reset is blocked in production-like environments."
                )


def _validate_reset_confirmation(settings: Any, confirm_phrase: Optional[str]) -> None:
    """
    Validate the destructive reset confirmation phrase.
    """
    if not _as_bool(_setting(settings, "SEED_RESET_REQUIRES_CONFIRM_PHRASE", True), True):
        return

    expected = str(
        _setting(settings, "DB_RESET_CONFIRM_PHRASE", "RESET_SYNTHETIC_DEMO")
        or "RESET_SYNTHETIC_DEMO"
    ).strip()

    supplied = str(confirm_phrase or "").strip()

    if supplied != expected:
        raise MuleGuardValidationError(
            "Reset confirmation phrase is required.",
            details={
                "reason": "confirm_phrase_mismatch",
                "setting": "DB_RESET_CONFIRM_PHRASE",
            },
        )


def _existing_account_count(db: Session) -> int:
    """
    Return current account count for idempotency checks.
    """
    try:
        return int(db.scalar(select(func.count()).select_from(Account)) or 0)
    except SQLAlchemyError:
        return 0


# -----------------------------------------------------------------------------
# Audit helpers
# -----------------------------------------------------------------------------


def _add_audit_event(
    db: Session,
    *,
    action: str,
    outcome: AuditOutcome,
    request_id: Optional[str] = None,
    actor: Optional[Any] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Add a safe audit event to the current session.

    The caller is responsible for committing the transaction.
    """
    values: dict[str, Any] = {
        "actor_id": str(getattr(actor, "id", "")) if actor is not None and hasattr(actor, "id") else None,
        "actor_username": str(getattr(actor, "username", "")) if actor is not None and hasattr(actor, "username") else None,
        "actor_role": _enum_str(getattr(actor, "role", None)) if actor is not None else None,
        "action": _clean_text(action, 100),
        "resource_type": _clean_text(resource_type, 100) if resource_type is not None else None,
        "resource_id": _clean_text(resource_id, 128) if resource_id is not None else None,
        "outcome": outcome,
        "request_id": _clean_text(request_id, 64) if request_id is not None else None,
        "metadata_json": _sanitize_mapping(metadata or {}),
    }

    event = _construct_model(AuditEvent, values)
    db.add(event)


def _audit_seed(
    db: Session,
    settings: Any,
    options: SeedOptions,
    result: SeedResult,
) -> None:
    """
    Record a safe audit event for a material seeding operation.
    """
    outcome = AuditOutcome.SUCCESS if result.ok else AuditOutcome.FAILURE

    metadata: dict[str, Any] = {
        "seed_version": SEED_VERSION,
        "dry_run": bool(options.dry_run),
        "reset": bool(options.reset),
        "force": bool(options.force),
        "allow_partial": bool(options.allow_partial),
        "generation_id": result.generation_id,
        "source_system": result.source_system,
        "source_batch_id": result.source_batch_id,
        "duration_seconds": result.duration_seconds,
        "accepted": dict(result.accepted),
        "duplicated": dict(result.duplicated),
        "skipped": dict(result.skipped),
        "error_count": len(result.errors),
        "warning_count": len(result.warnings),
        "dataset_mode": str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")),
        "production_like": _is_production_like(settings),
    }

    _add_audit_event(
        db,
        action="seed_demo",
        outcome=outcome,
        request_id=options.request_id,
        actor=options.actor,
        resource_type="synthetic_dataset",
        resource_id=result.generation_id,
        metadata=metadata,
    )


def _audit_reset(
    db: Session,
    settings: Any,
    *,
    dry_run: bool,
    request_id: Optional[str],
    actor: Optional[Any],
    result: SeedResult,
) -> None:
    """
    Record a safe audit event for a material reset operation.
    """
    outcome = AuditOutcome.SUCCESS if result.ok else AuditOutcome.FAILURE

    metadata: dict[str, Any] = {
        "seed_version": SEED_VERSION,
        "dry_run": bool(dry_run),
        "deleted_counts": dict(result.counts),
        "error_count": len(result.errors),
        "warning_count": len(result.warnings),
        "dataset_mode": str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")),
        "production_like": _is_production_like(settings),
    }

    _add_audit_event(
        db,
        action="seed_reset",
        outcome=outcome,
        request_id=request_id,
        actor=actor,
        resource_type="synthetic_dataset",
        resource_id=None,
        metadata=metadata,
    )


# -----------------------------------------------------------------------------
# Provenance helpers
# -----------------------------------------------------------------------------


def _apply_provenance(
    obj: Any,
    options: SeedOptions,
    record: Mapping[str, Any],
) -> None:
    """
    Attach safe provenance metadata when supported by the persistence model.
    """
    now = _now_utc()
    source_system = options.source_system or SOURCE_SYSTEM

    _set_attr_if_exists(obj, "source_system", source_system)
    _set_attr_if_exists(obj, "source_batch_id", options.source_batch_id)
    _set_attr_if_exists(obj, "ingested_at", now)
    _set_attr_if_exists(obj, "ingestion_request_id", options.request_id)
    _set_attr_if_exists(obj, "ingestion_run_id", options.source_batch_id)
    _set_attr_if_exists(obj, "synthetic", True)
    _set_attr_if_exists(obj, "data_classification", "synthetic")

    if hasattr(obj, "metadata_json"):
        existing = getattr(obj, "metadata_json", None)

        if isinstance(existing, Mapping):
            metadata = dict(existing)
        elif existing is None:
            metadata = {}
        else:
            metadata = {"original_metadata": _sanitize_value(existing)}

        metadata.update(
            {
                "synthetic": True,
                "source_system": source_system,
                "source_batch_id": options.source_batch_id,
                "ingestion_request_id": options.request_id,
                "seed_version": SEED_VERSION,
            }
        )

        _set_attr_if_exists(obj, "metadata_json", _sanitize_mapping(metadata))

    # Preserve caller-supplied deterministic references when supported.
    _set_attr_if_exists(obj, "external_reference", record.get("reference"))


# -----------------------------------------------------------------------------
# Record builders
# -----------------------------------------------------------------------------


def _build_account(record: Mapping[str, Any]) -> dict[str, Any]:
    """
    Build one Account persistence mapping.
    """
    account_id = _clean_text(record.get("id"), 128)

    if not account_id:
        raise ValueError("Account id is required.")

    return {
        "id": account_id,
        "account_type": _enum_from_string(
            AccountType,
            record.get("account_type"),
            AccountType.OTHER,
        ),
        "status": _enum_from_string(
            AccountStatus,
            record.get("status"),
            AccountStatus.ACTIVE,
        ),
        "created_at": _parse_dt(record.get("created_at"), _now_utc()),
        "metadata_json": _sanitize_mapping(record.get("metadata_json")),
    }


def _build_entity(record: Mapping[str, Any]) -> dict[str, Any]:
    """
    Build one Entity persistence mapping.
    """
    entity_id = _clean_text(record.get("id"), 128)
    identifier_hash = _clean_text(record.get("identifier_hash"), 256)

    if not entity_id:
        raise ValueError("Entity id is required.")

    if not identifier_hash:
        raise ValueError("Entity identifier_hash is required.")

    return {
        "id": entity_id,
        "entity_type": _enum_from_string(
            EntityType,
            record.get("entity_type"),
            EntityType.OTHER,
        ),
        "identifier_hash": identifier_hash,
        "identifier_display": _clean_text(record.get("identifier_display"), 200),
        "source": _clean_text(record.get("source") or SOURCE_SYSTEM, 100),
        "first_seen_at": _parse_dt(record.get("first_seen_at")),
        "last_seen_at": _parse_dt(record.get("last_seen_at")),
        "metadata_json": _sanitize_mapping(record.get("metadata_json")),
    }


def _build_entity_link(record: Mapping[str, Any]) -> dict[str, Any]:
    """
    Build one AccountEntityLink persistence mapping.
    """
    link_id = _clean_text(record.get("id"), 128)
    account_id = _clean_text(record.get("account_id"), 128)
    entity_id = _clean_text(record.get("entity_id"), 128)

    if not link_id:
        raise ValueError("Entity link id is required.")

    if not account_id:
        raise ValueError("Entity link account_id is required.")

    if not entity_id:
        raise ValueError("Entity link entity_id is required.")

    valid_from = _parse_dt(record.get("valid_from"), _now_utc())

    return {
        "id": link_id,
        "account_id": account_id,
        "entity_id": entity_id,
        # UNKNOWN rather than a specific method: an unreadable value means
        # nobody knows how the link was established, and NORMALIZED would be
        # a claim about the matching that was done.
        "match_method": _enum_from_string(
            MatchMethod,
            record.get("match_method"),
            MatchMethod.UNKNOWN,
        ),
        "confidence": _parse_decimal(record.get("confidence"), Decimal("0.50")),
        "verification_state": _enum_from_string(
            VerificationState,
            record.get("verification_state"),
            VerificationState.UNVERIFIED,
        ),
        "valid_from": valid_from,
        "valid_to": _parse_dt(record.get("valid_to")),
        "source": _clean_text(record.get("source") or SOURCE_SYSTEM, 100),
        "metadata_json": _sanitize_mapping(record.get("metadata_json")),
    }


def _build_transaction(record: Mapping[str, Any]) -> dict[str, Any]:
    """
    Build one Transaction persistence mapping.
    """
    transaction_id = _clean_text(record.get("id"), 128)
    sender_account_id = _clean_text(record.get("sender_account_id"), 128)
    receiver_account_id = _clean_text(record.get("receiver_account_id"), 128)

    if not transaction_id:
        raise ValueError("Transaction id is required.")

    if not sender_account_id:
        raise ValueError("Transaction sender_account_id is required.")

    if not receiver_account_id:
        raise ValueError("Transaction receiver_account_id is required.")

    if sender_account_id == receiver_account_id:
        raise ValueError("Transaction sender and receiver must differ.")

    return {
        "id": transaction_id,
        "reference": _clean_text(record.get("reference"), 128),
        "sender_account_id": sender_account_id,
        "receiver_account_id": receiver_account_id,
        "amount": _parse_decimal(record.get("amount"), Decimal("0.01")),
        "currency": _normalize_currency(record.get("currency")),
        "occurred_at": _parse_dt(record.get("occurred_at"), _now_utc()),
        "status": _enum_from_string(
            TransactionStatus,
            record.get("status"),
            TransactionStatus.COMPLETED,
        ),
        # The channel column has no UNKNOWN value, and it is not nullable, so
        # an unreadable channel falls back to the table's own default rather
        # than to a payment rail the record never named.
        "channel": _enum_from_string(
            Channel,
            record.get("channel"),
            Channel.INTERNAL,
        ),
        "metadata_json": _sanitize_mapping(record.get("metadata_json")),
    }


def _build_complaint(record: Mapping[str, Any]) -> dict[str, Any]:
    """
    Build one Complaint persistence mapping.
    """
    complaint_id = _clean_text(record.get("id"), 128)

    if not complaint_id:
        raise ValueError("Complaint id is required.")

    narrative = _clean_narrative(record.get("narrative_raw"), _MAX_NARRATIVE_LENGTH)
    amount = _parse_decimal(record.get("amount"))

    return {
        "id": complaint_id,
        "reference": _clean_text(record.get("reference"), 128),
        "reported_at": _parse_dt(record.get("reported_at"), _now_utc()),
        "category": _clean_text(record.get("category") or "other", 100),
        "narrative_raw": narrative,
        "transaction_reference": _clean_text(record.get("transaction_reference"), 128) or None,
        "victim_account_id": _clean_text(record.get("victim_account_id"), 128) or None,
        "suspected_account_id": _clean_text(record.get("suspected_account_id"), 128) or None,
        "amount": amount,
        "currency": _normalize_currency(record.get("currency")) if amount is not None else None,
        "source": _clean_text(record.get("source") or SOURCE_SYSTEM, 100),
        "metadata_json": _sanitize_mapping(record.get("metadata_json")),
    }


# -----------------------------------------------------------------------------
# Persistence helpers
# -----------------------------------------------------------------------------


def _add_chunk(
    db: Session,
    model: Any,
    records: Sequence[Mapping[str, Any]],
    builder: Any,
    entity_type: str,
    options: SeedOptions,
    result: SeedResult,
) -> None:
    """
    Add one bounded chunk of records to the session.
    """
    for index, record in enumerate(records):
        try:
            values = builder(record)
        except Exception as exc:
            _append_error(
                result,
                entity_type=entity_type,
                index=index,
                code=type(exc).__name__,
                message="Record could not be built.",
                details={"reason": "builder_failed"},
            )

            if not options.allow_partial:
                raise

            continue

        obj_id = values.get("id")

        if not obj_id:
            _append_error(
                result,
                entity_type=entity_type,
                index=index,
                code="missing_id",
                message="Record is missing an identifier.",
            )

            if not options.allow_partial:
                raise MuleGuardValidationError(
                    "Seeded record is missing an identifier.",
                    details={"entity_type": entity_type, "index": index},
                )

            continue

        try:
            existing = db.get(model, str(obj_id))
        except SQLAlchemyError as exc:
            _append_error(
                result,
                entity_type=entity_type,
                index=index,
                code=type(exc).__name__,
                message="Existing record lookup failed.",
            )

            if not options.allow_partial:
                raise

            continue

        if existing is not None:
            _bump(result.duplicated, entity_type)
            continue

        try:
            obj = _construct_model(model, values)
            _apply_provenance(obj, options, record)
            db.add(obj)
            _bump(result.accepted, entity_type)
        except Exception as exc:
            _append_error(
                result,
                entity_type=entity_type,
                index=index,
                code=type(exc).__name__,
                message="Record could not be constructed.",
            )

            if not options.allow_partial:
                raise


def _persist_chunk(
    db: Session,
    model: Any,
    records: Sequence[Mapping[str, Any]],
    builder: Any,
    entity_type: str,
    options: SeedOptions,
    result: SeedResult,
) -> None:
    """
    Persist one bounded chunk with optional partial-failure tolerance.
    """
    if options.dry_run:
        for index, record in enumerate(records):
            try:
                values = builder(record)
            except Exception:
                _append_error(
                    result,
                    entity_type=entity_type,
                    index=index,
                    code="dry_run_builder_failed",
                    message="Record failed dry-run validation.",
                )
                continue

            obj_id = values.get("id")

            if not obj_id:
                _append_error(
                    result,
                    entity_type=entity_type,
                    index=index,
                    code="missing_id",
                    message="Record is missing an identifier.",
                )
                continue

            try:
                existing = db.get(model, str(obj_id))
            except SQLAlchemyError:
                existing = None

            if existing is not None:
                _bump(result.duplicated, entity_type)
            else:
                _bump(result.accepted, entity_type)

        return

    if options.allow_partial:
        try:
            with db.begin_nested():
                _add_chunk(
                    db,
                    model,
                    records,
                    builder,
                    entity_type,
                    options,
                    result,
                )
                db.flush()
        except SQLAlchemyError as exc:
            _append_error(
                result,
                entity_type=entity_type,
                code=type(exc).__name__,
                message="Chunk could not be persisted.",
                details={"reason": "savepoint_rollback"},
            )
            return
    else:
        _add_chunk(
            db,
            model,
            records,
            builder,
            entity_type,
            options,
            result,
        )
        db.flush()


def _persist_dataset(
    db: Session,
    dataset: SyntheticDataset,
    options: SeedOptions,
    result: SeedResult,
    settings: Any,
) -> None:
    """
    Persist a generated synthetic dataset in dependency-safe order.
    """
    policy_summary = dataset.manifest.get("policy", {})

    if isinstance(policy_summary, Mapping):
        max_batch_size = _as_int(policy_summary.get("max_batch_size"), _DEFAULT_MAX_BATCH_SIZE)
    else:
        max_batch_size = _DEFAULT_MAX_BATCH_SIZE

    max_batch_size = max(1, min(int(max_batch_size), _HARD_MAX_BATCH_SIZE))

    plan: tuple[tuple[str, Sequence[Mapping[str, Any]], Any, Any], ...] = (
        ("accounts", dataset.accounts, Account, _build_account),
        ("entities", dataset.entities, Entity, _build_entity),
        ("entity_links", dataset.entity_links, AccountEntityLink, _build_entity_link),
        ("transactions", dataset.transactions, Transaction, _build_transaction),
        ("complaints", dataset.complaints, Complaint, _build_complaint),
    )

    for entity_type, records, model, builder in plan:
        if not records:
            continue

        for chunk in _chunked(records, max_batch_size):
            _persist_chunk(
                db,
                model,
                chunk,
                builder,
                entity_type,
                options,
                result,
            )

            if not result.ok and not options.allow_partial:
                return


# -----------------------------------------------------------------------------
# Reset helpers
# -----------------------------------------------------------------------------


def _collect_reset_models(settings: Any) -> tuple[Any, ...]:
    """
    Return models to reset in dependency-safe order.

    Core synthetic investigative inputs are always included. Optional workflow
    artefacts are included when configured and available.
    """
    ordered: list[Any] = []
    seen: set[str] = set()

    def add(model: Any) -> None:
        if model is None or not _is_mapped_model(model):
            return

        name = getattr(model, "__name__", str(model))

        if name in seen:
            return

        seen.add(name)
        ordered.append(model)

    include_workflow = _as_bool(
        _setting(settings, "SEED_RESET_INCLUDE_WORKFLOW_DATA", True),
        True,
    )

    if include_workflow:
        try:
            import app.models as models_module
        except Exception:
            models_module = None  # type: ignore[assignment]

        optional_names = (
            "CaseEvidence",
            "CaseEvent",
            "InvestigationCase",
            "ComplaintCorrelation",
            "GraphAnalysisRun",
            "ModelAssessment",
            "Alert",
        )

        if models_module is not None:
            for name in optional_names:
                add(getattr(models_module, name, None))

    add(AccountEntityLink)
    add(Complaint)
    add(Transaction)
    add(Entity)
    add(Account)

    return tuple(ordered)


def reset_demo_data(
    db: Session,
    settings: Any | None = None,
    *,
    confirm_phrase: Optional[str] = None,
    dry_run: bool = False,
    request_id: Optional[str] = None,
    actor: Optional[Any] = None,
) -> SeedResult:
    """
    Reset local synthetic demo data.

    This is destructive and is blocked in production-like environments. It
    requires an explicit confirmation phrase unless disabled by configuration.

    The reset targets synthetic workflow data only. It does not delete users or
    audit history.
    """
    resolved_settings = settings if settings is not None else _get_settings()
    started = time.monotonic()
    result = SeedResult(
        dry_run=dry_run,
        reset=True,
        source_system=RESET_SOURCE_SYSTEM,
    )

    try:
        _ensure_seed_allowed(resolved_settings, reset=True)
        _validate_reset_confirmation(resolved_settings, confirm_phrase)

        models = _collect_reset_models(resolved_settings)

        for model in models:
            name = getattr(model, "__name__", str(model))

            try:
                count = int(db.scalar(select(func.count()).select_from(model)) or 0)
            except SQLAlchemyError as exc:
                count = 0
                _append_error(
                    result,
                    entity_type=name,
                    code=type(exc).__name__,
                    message="Could not count records during reset dry-run.",
                )

            result.counts[name] = count

            if not dry_run:
                try:
                    db.execute(delete(model))
                except SQLAlchemyError as exc:
                    _append_error(
                        result,
                        entity_type=name,
                        code=type(exc).__name__,
                        message="Could not delete records during reset.",
                    )

                    if not _as_bool(
                        _setting(resolved_settings, "SEED_RESET_ALLOW_PARTIAL", False),
                        False,
                    ):
                        raise

        if not dry_run:
            _audit_reset(
                db,
                resolved_settings,
                dry_run=dry_run,
                request_id=request_id,
                actor=actor,
                result=result,
            )
            db.commit()

    except Exception:
        if not dry_run:
            try:
                db.rollback()
            except Exception:
                logger.exception("Failed to rollback reset transaction.")

        raise

    result.finalize(started)
    return result


# -----------------------------------------------------------------------------
# Public seeding API
# -----------------------------------------------------------------------------


def seed_demo_data(
    db: Session,
    settings: Any | None = None,
    *,
    options: SeedOptions | None = None,
    **kwargs: Any,
) -> SeedResult:
    """
    Seed bounded synthetic MULEGUARD demo data.

    This function is idempotent for a given generation policy. Existing records
    with the same deterministic identifiers are skipped.

    Args:
        db: Active SQLAlchemy session.
        settings: Optional runtime settings. Resolved lazily when omitted.
        options: Optional structured seeding options.
        **kwargs: Convenience keyword arguments mapped into SeedOptions.

    Returns:
        A safe SeedResult summary.

    Raises:
        FeatureFlagDisabledError: When seeding is disabled or production-like.
        MuleGuardValidationError: When reset confirmation or record validation fails.
        SQLAlchemyError: When non-partial persistence fails.
    """
    resolved_settings = settings if settings is not None else _get_settings()
    opts = options or SeedOptions(**kwargs)
    started = time.monotonic()

    result = SeedResult(
        dry_run=opts.dry_run,
        reset=opts.reset,
        source_system=opts.source_system or SOURCE_SYSTEM,
        source_batch_id=opts.source_batch_id,
    )

    try:
        _ensure_seed_allowed(resolved_settings, reset=opts.reset)

        if opts.reset:
            reset_result = reset_demo_data(
                db,
                resolved_settings,
                confirm_phrase=opts.confirm_phrase,
                dry_run=opts.dry_run,
                request_id=opts.request_id,
                actor=opts.actor,
            )

            result.counts.update(reset_result.counts)
            result.warnings.extend(reset_result.warnings)
            result.errors.extend(reset_result.errors)

            if not reset_result.ok:
                result.ok = False

        policy = opts.policy or GenerationPolicy.from_settings(resolved_settings)
        dataset = generate_synthetic_dataset(policy)

        generation_id = str(dataset.manifest.get("generation_id") or "").strip() or None
        result.generation_id = generation_id
        result.counts.update(dataset.counts())

        if not result.source_batch_id:
            result.source_batch_id = f"seed-{generation_id or _stable_hash([str(_now_utc())])[:12]}"

        opts = replace(opts, source_batch_id=result.source_batch_id)

        if not opts.force and _existing_account_count(db) > 0:
            for key, value in result.counts.items():
                _bump(result.skipped, key, int(value))

            result.warnings.append(
                "Synthetic accounts already exist; use force=True or reset=True to reseed."
            )
            result.finalize(started)
            return result

        _persist_dataset(
            db,
            dataset,
            opts,
            result,
            resolved_settings,
        )

        if not opts.dry_run:
            _audit_seed(
                db,
                resolved_settings,
                opts,
                result,
            )
            db.commit()

    except MuleGuardValidationError:
        if not opts.dry_run:
            try:
                db.rollback()
            except Exception:
                logger.exception("Failed to rollback seeding validation transaction.")

        result.ok = False
        result.finalize(started)
        raise

    except Exception as exc:
        if not opts.dry_run:
            try:
                db.rollback()
            except Exception:
                logger.exception("Failed to rollback seeding transaction.")

        _append_error(
            result,
            code=type(exc).__name__,
            message="Seeding failed.",
            details={"reason": "unexpected_failure"},
        )

        result.ok = False
        result.finalize(started)

        if not opts.allow_partial:
            raise

    result.finalize(started)
    return result


def bootstrap_demo_data(
    db: Session,
    settings: Any | None = None,
    *,
    reset: bool = False,
    confirm_phrase: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
    allow_partial: bool = False,
    policy: GenerationPolicy | None = None,
    request_id: Optional[str] = None,
    actor: Optional[Any] = None,
) -> SeedResult:
    """
    Convenience wrapper for demo bootstrapping.

    This is equivalent to calling `seed_demo_data` with structured options.
    """
    options = SeedOptions(
        dry_run=dry_run,
        allow_partial=allow_partial,
        force=force,
        reset=reset,
        confirm_phrase=confirm_phrase,
        policy=policy,
        request_id=request_id,
        actor=actor,
    )

    return seed_demo_data(
        db,
        settings=settings,
        options=options,
    )


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_seed_metadata() -> dict[str, Any]:
    """
    Return safe, serializable seeding-layer metadata.

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
    default_policy = GenerationPolicy()

    return {
        "package": "muleguard.backend.ingestion.seed",
        "version": SEED_VERSION,
        "source_system": SOURCE_SYSTEM,
        "default_max_batch_size": _DEFAULT_MAX_BATCH_SIZE,
        "hard_max_batch_size": _HARD_MAX_BATCH_SIZE,
        "max_errors_returned": _MAX_ERRORS_RETURNED,
        "default_policy": default_policy.safe_summary(),
        "caveats": list(_SEED_CAVEATS),
        "safety_flags": {
            "synthetic_only_by_default": True,
            "no_real_customer_data_by_default": True,
            "production_like_blocked": True,
            "reset_requires_confirmation_by_default": True,
            "no_ground_truth_labels_exposed": True,
            "no_scenario_ids_exposed": True,
            "no_fraud_ring_ids_exposed": True,
            "no_raw_narrative_in_summaries": True,
            "no_secrets_in_summaries": True,
            "no_automatic_adverse_customer_action": True,
            "not_production_ready": True,
        },
    }


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def _build_policy_from_args(settings: Any, args: argparse.Namespace) -> GenerationPolicy:
    """
    Build a generation policy from settings and CLI overrides.
    """
    policy = GenerationPolicy.from_settings(settings)
    overrides: dict[str, Any] = {}

    if args.seed is not None:
        overrides["seed"] = int(args.seed)

    if args.accounts is not None:
        overrides["accounts"] = int(args.accounts)

    if args.transactions is not None:
        overrides["transactions"] = int(args.transactions)

    if args.complaints is not None:
        overrides["complaints"] = int(args.complaints)

    if args.entities is not None:
        overrides["entities"] = int(args.entities)

    if args.entity_links is not None:
        overrides["entity_links"] = int(args.entity_links)

    if args.batch_size is not None:
        overrides["max_batch_size"] = int(args.batch_size)

    if args.currency is not None:
        overrides["currency"] = _normalize_currency(args.currency)

    if args.min_amount is not None:
        parsed_min = _parse_decimal(args.min_amount, policy.min_amount)

        if parsed_min is not None:
            overrides["min_amount"] = parsed_min

    if args.max_amount is not None:
        parsed_max = _parse_decimal(args.max_amount, policy.max_amount)

        if parsed_max is not None:
            overrides["max_amount"] = parsed_max

    if args.date_start is not None:
        parsed_start = _parse_dt(args.date_start, policy.date_start)

        if parsed_start is not None:
            overrides["date_start"] = parsed_start

    if args.date_end is not None:
        parsed_end = _parse_dt(args.date_end, policy.date_end)

        if parsed_end is not None:
            overrides["date_end"] = parsed_end

    if overrides:
        policy = replace(policy, **overrides)

    return policy


def _print_result(result: SeedResult, *, as_json: bool) -> None:
    """
    Print a safe seeding summary.
    """
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return

    for warning in result.warnings:
        print(f"[WARN] {warning}", file=sys.stderr)

    for key, value in sorted(result.counts.items()):
        print(f"[COUNT] {key}: {value}", file=sys.stderr)

    for key, value in sorted(result.accepted.items()):
        print(f"[ACCEPTED] {key}: {value}", file=sys.stderr)

    for key, value in sorted(result.duplicated.items()):
        print(f"[DUPLICATED] {key}: {value}", file=sys.stderr)

    for key, value in sorted(result.skipped.items()):
        print(f"[SKIPPED] {key}: {value}", file=sys.stderr)

    for error in result.errors:
        print(
            f"[ERROR] {error.get('entity_type') or '-'} "
            f"{error.get('code') or ''} {error.get('message') or ''}".strip(),
            file=sys.stderr,
        )

    if result.ok:
        print(
            f"Seeding completed successfully in {result.duration_seconds}s.",
            file=sys.stderr,
        )
    else:
        print(
            f"Seeding completed with errors in {result.duration_seconds}s.",
            file=sys.stderr,
        )


def main(argv: Optional[list[str]] = None) -> int:
    """
    CLI entrypoint for synthetic demo seeding and reset.
    """
    parser = argparse.ArgumentParser(
        prog="python -m app.ingestion.seed",
        description=(
            "Seed or reset bounded synthetic MULEGUARD demo data. "
            "This is a local-only synthetic prototype action."
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and report planned actions without writing.",
    )

    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset local synthetic demo data before seeding.",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow seeding even when synthetic accounts already exist.",
    )

    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Continue past bounded row/chunk failures where safe.",
    )

    parser.add_argument(
        "--confirm",
        type=str,
        default=None,
        help="Confirmation phrase required for destructive reset.",
    )

    parser.add_argument(
        "--source-system",
        type=str,
        default=SOURCE_SYSTEM,
        help="Safe source-system label attached to provenance metadata.",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Override deterministic generator seed.",
    )

    parser.add_argument("--accounts", type=int, default=None)
    parser.add_argument("--transactions", type=int, default=None)
    parser.add_argument("--complaints", type=int, default=None)
    parser.add_argument("--entities", type=int, default=None)
    parser.add_argument("--entity-links", dest="entity_links", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--currency", type=str, default=None)
    parser.add_argument("--min-amount", type=str, default=None)
    parser.add_argument("--max-amount", type=str, default=None)
    parser.add_argument("--date-start", type=str, default=None)
    parser.add_argument("--date-end", type=str, default=None)

    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging.",
    )

    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stderr,
    )

    settings = _get_settings()
    policy = _build_policy_from_args(settings, args)

    options = SeedOptions(
        dry_run=bool(args.dry_run),
        allow_partial=bool(args.allow_partial),
        force=bool(args.force),
        reset=bool(args.reset),
        confirm_phrase=args.confirm,
        source_system=_clean_text(args.source_system, 100) or SOURCE_SYSTEM,
        policy=policy,
    )

    started = time.monotonic()
    result = SeedResult(
        dry_run=options.dry_run,
        reset=options.reset,
        source_system=options.source_system or SOURCE_SYSTEM,
    )

    try:
        with session_scope() as db:
            result = seed_demo_data(db, settings=settings, options=options)
    except Exception as exc:
        _append_error(
            result,
            code=type(exc).__name__,
            message="Seeding command failed.",
            details={"reason": "cli_failure"},
        )
        result.ok = False
        result.finalize(started)

    _print_result(result, as_json=bool(args.json))

    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "SeedOptions",
    "SeedResult",
    "bootstrap_demo_data",
    "get_seed_metadata",
    "main",
    "reset_demo_data",
    "seed_demo_data",
]