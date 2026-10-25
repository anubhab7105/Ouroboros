"""
MULEGUARD backend API v1 ingestion endpoints.

This module implements the versioned `/api/v1/ingestion` surface for bounded,
validated, synthetic-first bulk ingestion into MULEGUARD.

Implemented endpoints:

- GET  /api/v1/ingestion/status
- POST /api/v1/ingestion/accounts
- POST /api/v1/ingestion/transactions
- POST /api/v1/ingestion/complaints
- POST /api/v1/ingestion/entities
- POST /api/v1/ingestion/entity-links

Design goals:

- provide real, persisted, validated bulk ingestion for synthetic MULEGUARD
  accounts, transactions, complaints, pseudonymous entities, and account-entity
  links;
- enforce server-side RBAC through dependency permissions;
- keep batch sizes, error reporting, and duplicate handling bounded;
- preserve deterministic references where supplied by the caller;
- report accepted, rejected, duplicated, and skipped counts honestly;
- support dry-run validation without writes;
- support optional partial ingestion only when explicitly enabled;
- record safe audit metadata for material ingestion batches;
- avoid exposing passwords, tokens, secrets, database URLs, raw complaint
  narratives in error responses, synthetic ground-truth labels, scenario IDs,
  ring IDs, or real customer data.

Explicit non-goals:

- This module does not ingest real customer data.
- This module does not connect to real banking systems or complaint systems.
- This module does not create ground-truth labels or fraud-ring identifiers.
- This module does not freeze, block, blacklist, close, restrict, or otherwise
  take adverse action against accounts or customers.
- This module does not expose raw complaint narratives in responses.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Ingested records are
synthetic investigative inputs only. Alerts, scores, graph relationships,
candidate money trails, entity links, and complaint correlations remain
investigative leads and must not trigger automatic adverse customer action.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Annotated, Any, Final, Literal, Optional

from fastapi import APIRouter, Depends, Request, Response
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError as PydanticValidationError,
    field_validator,
)
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import (
    Permission,
    RequestIDDep,
    SessionDep,
    SettingsDep,
    require_permission,
)
from app.exceptions import (
    FeatureFlagDisabledError,
    IngestionValidationError,
    InternalError,
    SyntheticDataRequiredError,
    ValidationError as MuleGuardValidationError,
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
    User,
    VerificationState,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.ingestion")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["ingestion"])


# -----------------------------------------------------------------------------
# Permission fallback
# -----------------------------------------------------------------------------

INGESTION_PERMISSION: Final[Any] = getattr(
    Permission,
    "INGESTION_WRITE",
    getattr(Permission, "USER_MANAGE", None),
)


# -----------------------------------------------------------------------------
# Constants and limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_NARRATIVE_LENGTH: Final[int] = 20_000
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_MAPPING_KEYS: Final[int] = 100
_MAX_JSON_DEPTH: Final[int] = 6

_DEFAULT_MAX_BATCH_SIZE: Final[int] = 1_000
_HARD_MAX_BATCH_SIZE: Final[int] = 10_000
_DEFAULT_MAX_ERRORS: Final[int] = 100
_HARD_MAX_ERRORS: Final[int] = 500

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_IDENTIFIER_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9+/=_-]{16,128}$")

_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "apikey",
        "auth_header",
        "authorization",
        "bearer",
        "body",
        "card_number",
        "cookie",
        "credential",
        "credentials",
        "cvv",
        "id_token",
        "identifier_hash",
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
        "pin",
        "private_key",
        "raw_payload",
        "refresh_token",
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
    "authorization",
    "card_number",
    "credential",
    "customer_data",
    "customer_id",
    "device_id",
    "email_address",
    "fraud",
    "ground_truth",
    "hash",
    "ifsc",
    "identifier_hash",
    "ip_address",
    "label",
    "narrative",
    "passphrase",
    "password",
    "passwd",
    "payload_hash",
    "phone_number",
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

_INGESTION_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype ingestion only. Do not send real customer data.",
    "Ingestion responses do not return raw complaint narratives.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs must not be ingested through this API.",
    "Ingested records are investigative inputs only and do not trigger automatic adverse customer action.",
    "Batch processing is bounded by configured batch size and error-reporting limits.",
    "Dry-run mode validates records without persisting them.",
    "Duplicate handling is deterministic and configurable.",
)


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _setting(settings: Any, name: str, default: Any = None) -> Any:
    """
    Read a setting from either a Pydantic settings object or mapping.
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


def _enum_str(value: Any) -> Optional[str]:
    """
    Return a stable string for enum-like values.
    """
    if value is None:
        return None

    return str(getattr(value, "value", value))


def _clean_text(value: Any, limit: int = _MAX_STRING_LENGTH) -> str:
    """
    Return a safe single-line text value.
    """
    text = str(value or "")
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if len(text) > limit:
        return text[:limit]

    return text


def _clean_narrative(value: str) -> str:
    """
    Remove NUL bytes from narrative text while preserving normal whitespace.

    The narrative is stored as raw synthetic complaint text. It is never
    returned in ingestion responses.
    """
    return str(value or "").replace("\x00", "")


def _new_id() -> str:
    """
    Generate a stable runtime identifier.
    """
    return str(uuid.uuid4())


def _str_or_none(value: Any) -> Optional[str]:
    """
    Return a stripped string or None.
    """
    if value is None:
        return None

    text = str(value).strip()
    return text or None


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


def _is_sensitive_key(key: str) -> bool:
    """
    Return True when a metadata key appears sensitive or leakage-prone.
    """
    lowered = key.strip().lower()

    if lowered in _SENSITIVE_KEYS:
        return True

    return any(token in lowered for token in _SENSITIVE_KEY_TOKENS)


def _sanitize_json_value(
    value: Any,
    depth: int = 0,
    *,
    max_sequence_length: int = _MAX_LIST_LENGTH,
    max_mapping_keys: int = _MAX_MAPPING_KEYS,
) -> Any:
    """
    Convert an arbitrary JSON-like value into a safe persisted/response value.
    """
    if depth > _MAX_JSON_DEPTH:
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

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        return _sanitize_json_object(
            value,
            depth + 1,
            max_sequence_length=max_sequence_length,
            max_mapping_keys=max_mapping_keys,
        )

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        original_length = len(value)
        limited = list(value)[:max_sequence_length]
        items = [
            _sanitize_json_value(
                item,
                depth + 1,
                max_sequence_length=max_sequence_length,
                max_mapping_keys=max_mapping_keys,
            )
            for item in limited
        ]

        if original_length > max_sequence_length:
            items.append({"_truncated": True})

        return items

    return f"<{type(value).__name__}>"


def _sanitize_json_object(
    value: Mapping[Any, Any],
    depth: int = 0,
    *,
    max_sequence_length: int = _MAX_LIST_LENGTH,
    max_mapping_keys: int = _MAX_MAPPING_KEYS,
) -> dict[str, Any]:
    """
    Return a sanitized JSON object suitable for persistence and responses.
    """
    if depth > _MAX_JSON_DEPTH:
        return {"_truncated": True}

    sanitized: dict[str, Any] = {}

    for raw_key, raw_value in list(value.items())[:max_mapping_keys]:
        key = str(raw_key)

        if _is_sensitive_key(key):
            continue

        sanitized[key] = _sanitize_json_value(
            raw_value,
            depth + 1,
            max_sequence_length=max_sequence_length,
            max_mapping_keys=max_mapping_keys,
        )

        if len(sanitized) >= max_mapping_keys:
            sanitized["_truncated_keys"] = True
            break

    return sanitized


def _sanitize_input_mapping(value: Any) -> Optional[dict[str, Any]]:
    """
    Sanitize caller-supplied metadata mapping.
    """
    if value is None:
        return None

    if not isinstance(value, Mapping):
        return None

    sanitized = _sanitize_json_object(
        value,
        max_sequence_length=100,
        max_mapping_keys=100,
    )

    return sanitized or None


def _payload_hash(value: Mapping[str, Any]) -> str:
    """
    Return a stable SHA-256 digest for sanitized payload lineage.

    This is not a secret and is not used for authentication.
    """
    canonical = json.dumps(
        _sanitize_json_object(value),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _set_provenance(
    obj: Any,
    *,
    options: Mapping[str, Any],
    request_id: str,
    record_mapping: Mapping[str, Any],
) -> None:
    """
    Attach safe ingestion provenance fields when the model supports them.
    """
    source_system = _clean_text(
        options.get("source_system") or "api",
        100,
    )
    source_batch_id = _clean_text(
        options.get("source_batch_id") or request_id,
        100,
    )

    if hasattr(obj, "source_system"):
        obj.source_system = source_system

    if hasattr(obj, "source_batch_id"):
        obj.source_batch_id = source_batch_id

    if hasattr(obj, "ingestion_run_id"):
        obj.ingestion_run_id = _clean_text(request_id, 64)

    if hasattr(obj, "source_payload_hash"):
        obj.source_payload_hash = _payload_hash(record_mapping)

    # Fall back to `metadata_json`.
    #
    # None of the ingested models carries dedicated provenance columns, so
    # without this the whole function is a no-op and an ingested record has no
    # recorded origin at all — which makes "where did this account come from"
    # unanswerable six months later, exactly the question provenance exists to
    # answer. Every ingested model (Account, Transaction, Complaint, Entity,
    # AccountEntityLink) does have `metadata_json`, so the fields go there
    # under one reserved key rather than scattered at the top level, where
    # they would collide with whatever the source system sends.
    #
    # The payload hash is of the submitted record, which is how a re-ingested
    # record can be recognised as byte-identical to the one already stored.
    if not hasattr(obj, "source_system") and hasattr(obj, "metadata_json"):
        existing = obj.metadata_json

        merged: dict[str, Any] = dict(existing) if isinstance(existing, Mapping) else {}
        merged["_ingestion"] = {
            "source_system": source_system,
            "source_batch_id": source_batch_id,
            "request_id": _clean_text(request_id, 64),
            "payload_hash": _payload_hash(record_mapping),
        }

        obj.metadata_json = merged


def _client_ip(request: Request, settings: Any) -> str:
    """
    Return a best-effort client IP.

    Proxy headers are trusted only when BACKEND_TRUST_PROXY_HEADERS=true.
    """
    trust_proxy = _as_bool(
        _setting(settings, "BACKEND_TRUST_PROXY_HEADERS", False),
        False,
    )

    if trust_proxy:
        forwarded_for = request.headers.get("X-Forwarded-For")

        if forwarded_for:
            first = forwarded_for.split(",", 1)[0].strip()

            if first:
                return first

        real_ip = request.headers.get("X-Real-IP")

        if real_ip:
            return real_ip.strip()

    if request.client and request.client.host:
        return request.client.host

    return ""


def _hash_value(value: str, salt: str) -> str:
    """
    Return a stable SHA-256 hash for safe audit storage.
    """
    payload = f"{salt}:{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ip_hash(request: Request, settings: Any) -> Optional[str]:
    """
    Return a hashed client IP for audit storage, or None when disabled.
    """
    mode = str(_setting(settings, "PRIVACY_IP_LOG_MODE", "hashed")).strip().lower()

    if mode in {"none", "off", "disabled"}:
        return None

    ip = _client_ip(request, settings)

    if not ip:
        return None

    salt = str(
        _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
        or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
        or _setting(settings, "BACKEND_SECRET_KEY", None)
        or "muleguard-ingestion"
    )

    return _hash_value(ip, salt)


def _add_audit_event(
    db: Session,
    *,
    action: str,
    outcome: AuditOutcome,
    request_id: Optional[str] = None,
    actor: Optional[User] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_hash: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Add a safe audit event to the current session.

    The caller is responsible for committing the transaction.
    """
    safe_metadata = _sanitize_json_object(metadata or {}, max_sequence_length=50, max_mapping_keys=50)

    event = AuditEvent(
        actor_id=str(actor.id) if actor is not None else None,
        actor_username=str(actor.username) if actor is not None else None,
        actor_role=_enum_str(actor.role) if actor is not None else None,
        action=_clean_text(action, 100),
        resource_type=_clean_text(resource_type, 100) if resource_type is not None else None,
        resource_id=_clean_text(resource_id, 128) if resource_id is not None else None,
        outcome=outcome,
        request_id=_clean_text(request_id, 64) if request_id is not None else None,
        ip_hash=ip_hash,
        metadata_json=safe_metadata,
    )

    db.add(event)


# -----------------------------------------------------------------------------
# Ingestion policy helpers
# -----------------------------------------------------------------------------


def _ensure_ingestion_enabled(settings: Any) -> None:
    """
    Fail closed when ingestion is disabled or unsafe.
    """
    if not _as_bool(_setting(settings, "INGESTION_API_ENABLED", True), True):
        raise FeatureFlagDisabledError("Ingestion endpoints are disabled by configuration.")

    if not _as_bool(_setting(settings, "INGESTION_ENABLED", True), True):
        raise FeatureFlagDisabledError("Ingestion subsystem is disabled by configuration.")

    if _is_production_like(settings):
        allow_production = _as_bool(
            _setting(settings, "INGESTION_ALLOW_IN_PRODUCTION", False),
            False,
        )

        if not allow_production:
            raise FeatureFlagDisabledError(
                "Ingestion is disabled in production-like environments."
            )

    require_synthetic = _as_bool(
        _setting(settings, "INGESTION_REQUIRE_SYNTHETIC", True),
        True,
    )

    if require_synthetic:
        dataset_mode = str(
            _setting(settings, "BACKEND_DATASET_MODE", "synthetic")
        ).strip().lower()

        if dataset_mode != "synthetic":
            raise SyntheticDataRequiredError(
                "Ingestion requires BACKEND_DATASET_MODE=synthetic."
            )


def _max_batch_size(settings: Any) -> int:
    """
    Return bounded maximum batch size.
    """
    configured = max(
        1,
        _as_int(
            _setting(settings, "INGESTION_MAX_BATCH_SIZE", _DEFAULT_MAX_BATCH_SIZE),
            _DEFAULT_MAX_BATCH_SIZE,
        ),
    )

    hard = max(
        configured,
        _as_int(
            _setting(settings, "INGESTION_HARD_MAX_BATCH_SIZE", _HARD_MAX_BATCH_SIZE),
            _HARD_MAX_BATCH_SIZE,
        ),
    )

    return min(configured, hard)


def _max_errors_returned(settings: Any) -> int:
    """
    Return bounded maximum row errors returned.
    """
    configured = max(
        1,
        _as_int(
            _setting(settings, "INGESTION_MAX_ERRORS_RETURNED", _DEFAULT_MAX_ERRORS),
            _DEFAULT_MAX_ERRORS,
        ),
    )

    hard = max(
        configured,
        _as_int(
            _setting(settings, "INGESTION_HARD_MAX_ERRORS_RETURNED", _HARD_MAX_ERRORS),
            _HARD_MAX_ERRORS,
        ),
    )

    return min(configured, hard)


def _future_toleranceance(settings: Any) -> timedelta:
    """
    Return future timestamp tolerance for ingestion records.
    """
    minutes = max(
        0,
        _as_int(
            _setting(settings, "INGESTION_FUTURE_TOLERANCE_MINUTES", 5),
            5,
        ),
    )

    return timedelta(minutes=minutes)


def _validate_not_future(
    value: Optional[datetime],
    *,
    row: int,
    field_name: str,
    row_errors: list[dict[str, Any]],
    settings: Any,
    max_errors: int,
) -> Optional[datetime]:
    """
    Reject future timestamps beyond configured tolerance.
    """
    normalized = _ensure_utc(value)

    if normalized is None:
        return None

    if normalized > _now_utc() + _future_toleranceance(settings):
        _append_error(
            row_errors,
            {
                "row": row,
                "field": field_name,
                "code": "future_timestamp",
                "message": f"{field_name} must not be in the future.",
            },
            max_errors,
        )

    return normalized


# -----------------------------------------------------------------------------
# Options resolution
# -----------------------------------------------------------------------------


class IngestionOptions(BaseModel):
    """
    Optional batch-level ingestion controls.
    """

    model_config = ConfigDict(extra="forbid")

    source_system: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Logical source system or generator name.",
    )
    source_batch_id: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Caller-supplied batch identifier.",
    )
    dry_run: bool = Field(
        default=False,
        description="Validate without persisting records.",
    )
    allow_partial: Optional[bool] = Field(
        default=None,
        description=(
            "Allow valid records to be persisted when some records fail. "
            "Defaults to INGESTION_ALLOW_PARTIAL_BATCH."
        ),
    )
    on_duplicate: Optional[Literal["reject", "skip"]] = Field(
        default=None,
        description=(
            "Duplicate handling strategy. Defaults to INGESTION_DUPLICATE_STRATEGY."
        ),
    )

    @field_validator("source_system", "source_batch_id")
    @classmethod
    def _validate_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > 100:
            raise ValueError("value is too long")

        return normalized


def _resolve_options(
    options: Optional[IngestionOptions],
    settings: Any,
) -> dict[str, Any]:
    """
    Resolve effective batch options.
    """
    allow_partial_default = _as_bool(
        _setting(settings, "INGESTION_ALLOW_PARTIAL_BATCH", False),
        False,
    )

    duplicate_default = str(
        _setting(settings, "INGESTION_DUPLICATE_STRATEGY", "reject")
        or "reject"
    ).strip().lower()

    if duplicate_default not in {"reject", "skip"}:
        duplicate_default = "reject"

    resolved: dict[str, Any] = {
        "source_system": None,
        "source_batch_id": None,
        "dry_run": False,
        "allow_partial": allow_partial_default,
        "on_duplicate": duplicate_default,
    }

    if options is None:
        return resolved

    resolved["source_system"] = options.source_system
    resolved["source_batch_id"] = options.source_batch_id
    resolved["dry_run"] = bool(options.dry_run)

    if options.allow_partial is not None:
        resolved["allow_partial"] = bool(options.allow_partial)

    if options.on_duplicate is not None:
        resolved["on_duplicate"] = str(options.on_duplicate)

    return resolved


# -----------------------------------------------------------------------------
# Batch error helpers
# -----------------------------------------------------------------------------


def _append_error(
    row_errors: list[dict[str, Any]],
    error: Mapping[str, Any],
    max_errors: int,
) -> None:
    """
    Append a bounded row error.
    """
    real_errors = [item for item in row_errors if not isinstance(item, Mapping) or "_truncated" not in item]

    if len(real_errors) >= max_errors:
        if not any(isinstance(item, Mapping) and "_truncated" in item for item in row_errors):
            row_errors.append({"_truncated": True})
        return

    row_errors.append(dict(error))


def _row_error(
    row: int,
    code: str,
    message: str,
    *,
    field: Optional[str] = None,
) -> dict[str, Any]:
    """
    Build a safe row error payload.
    """
    payload: dict[str, Any] = {
        "row": int(row),
        "code": _clean_text(code, 100),
        "message": _clean_text(message, 300),
    }

    if field:
        payload["field"] = _clean_text(field, 200)

    return payload


def _pydantic_row_errors(
    row: int,
    exc: PydanticValidationError,
    row_errors: list[dict[str, Any]],
    max_errors: int,
) -> None:
    """
    Convert Pydantic validation errors into safe row errors.
    """
    for raw_error in exc.errors():
        loc = raw_error.get("loc") or ()
        field_parts: list[str] = []

        for part in loc:
            text = str(part)

            if text in {"body", "records"}:
                continue

            field_parts.append(text)

        field = ".".join(field_parts) or None

        if field and _is_sensitive_key(field):
            message = "Invalid or missing value."
        else:
            message = _clean_text(raw_error.get("msg") or "Invalid or missing value.", 300)

        error_type = str(raw_error.get("type") or "value_error").strip()

        _append_error(
            row_errors,
            _row_error(
                row,
                code=error_type,
                message=message,
                field=field,
            ),
            max_errors,
        )


def _rejected_row_count(row_errors: Sequence[Mapping[str, Any]]) -> int:
    """
    Count distinct rejected rows from safe row errors.
    """
    rows: set[int] = set()

    for error in row_errors:
        if not isinstance(error, Mapping):
            continue

        row = error.get("row")

        if isinstance(row, int):
            rows.add(row)

    return len(rows)


def _duplicate_handling(
    *,
    row: int,
    duplicate_key: str,
    counts: dict[str, int],
    row_errors: list[dict[str, Any]],
    options: Mapping[str, Any],
    max_errors: int,
) -> bool:
    """
    Handle a duplicate record.

    Returns True when the record may continue processing, which currently is
    always False because duplicates are not inserted by this API.
    """
    counts["duplicated"] += 1

    if options["on_duplicate"] == "skip":
        counts["skipped"] += 1
        return False

    _append_error(
        row_errors,
        _row_error(
            row,
            code="duplicate",
            message="Duplicate record detected.",
            field=duplicate_key,
        ),
        max_errors,
    )

    return False


def _finalize_batch(
    db: Session,
    request: Request,
    response: Response,
    settings: Any,
    actor: User,
    request_id: str,
    *,
    resource_type: str,
    counts: Mapping[str, int],
    row_errors: list[dict[str, Any]],
    options: Mapping[str, Any],
) -> "IngestionBatchResponse":
    """
    Finalize an ingestion batch: raise strict errors, commit valid writes, and
    record safe audit metadata.
    """
    rejected = _rejected_row_count(row_errors)
    duplicated = int(counts.get("duplicated", 0))
    accepted = int(counts.get("accepted", 0))
    skipped = int(counts.get("skipped", 0))

    ok = rejected == 0 and (duplicated == 0 or options["on_duplicate"] == "skip")

    payload = IngestionBatchResponse(
        ok=ok,
        entity_type=resource_type,
        accepted=accepted,
        rejected=rejected,
        duplicated=duplicated,
        skipped=skipped,
        dry_run=bool(options["dry_run"]),
        allow_partial=bool(options["allow_partial"]),
        on_duplicate=str(options["on_duplicate"]),
        source_system=_str_or_none(options.get("source_system")),
        source_batch_id=_str_or_none(options.get("source_batch_id")),
        request_id=request_id,
        errors=row_errors,
        caveats=list(_INGESTION_CAVEATS),
    )

    if options["dry_run"]:
        response.status_code = 200
        return payload

    if row_errors and not options["allow_partial"]:
        raise IngestionValidationError.from_rows(
            accepted=accepted,
            rejected=rejected,
            duplicated=duplicated,
            skipped=skipped,
            row_errors=row_errors,
            message="Ingestion validation failed.",
        )

    if row_errors and options["allow_partial"] and accepted == 0:
        raise IngestionValidationError.from_rows(
            accepted=accepted,
            rejected=rejected,
            duplicated=duplicated,
            skipped=skipped,
            row_errors=row_errors,
            message="Ingestion failed and no valid records were available for partial commit.",
        )

    if accepted > 0:
        try:
            _add_audit_event(
                db,
                action="ingestion_batch",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                actor=actor,
                resource_type="ingestion_batch",
                resource_id=_str_or_none(options.get("source_batch_id")) or request_id,
                ip_hash=_ip_hash(request, settings),
                metadata={
                    "entity_type": resource_type,
                    "accepted": accepted,
                    "rejected": rejected,
                    "duplicated": duplicated,
                    "skipped": skipped,
                    "dry_run": False,
                    "allow_partial": bool(options["allow_partial"]),
                    "on_duplicate": str(options["on_duplicate"]),
                    "source_system": _str_or_none(options.get("source_system")),
                    "source_batch_id": _str_or_none(options.get("source_batch_id")),
                },
            )

            db.commit()
        except SQLAlchemyError as exc:
            db.rollback()
            logger.exception("Ingestion database commit failed.")
            raise InternalError(
                "Ingestion failed during database commit.",
                details={"error_type": type(exc).__name__},
            ) from exc
        except Exception as exc:
            db.rollback()
            logger.exception("Unexpected ingestion commit failure.")
            raise InternalError(
                "Ingestion failed unexpectedly.",
                details={"error_type": type(exc).__name__},
            ) from exc

        response.status_code = 201
    else:
        response.status_code = 200

    return payload


# -----------------------------------------------------------------------------
# Record parsing helper
# -----------------------------------------------------------------------------


def _parse_records(
    record_model: type[BaseModel],
    records: Sequence[Any],
    row_errors: list[dict[str, Any]],
    max_errors: int,
) -> list[tuple[int, BaseModel]]:
    """
    Parse raw records into typed Pydantic models and collect safe row errors.
    """
    parsed: list[tuple[int, BaseModel]] = []

    for row, raw_record in enumerate(records):
        try:
            item = record_model.model_validate(raw_record)
            parsed.append((row, item))
        except PydanticValidationError as exc:
            _pydantic_row_errors(row, exc, row_errors, max_errors)
        except Exception as exc:
            _append_error(
                row_errors,
                _row_error(
                    row,
                    code="parse_error",
                    message="Record could not be parsed.",
                ),
                max_errors,
            )
            logger.debug(
                "Ingestion parse error: row=%s error_type=%s",
                row,
                type(exc).__name__,
            )

    return parsed


# -----------------------------------------------------------------------------
# Request and response models
# -----------------------------------------------------------------------------


class IngestionRowError(BaseModel):
    """
    Safe row-level ingestion error.
    """

    model_config = ConfigDict(extra="ignore")

    row: Optional[int] = None
    field: Optional[str] = None
    code: Optional[str] = None
    message: Optional[str] = None
    _truncated: Optional[bool] = None


class IngestionBatchResponse(BaseModel):
    """
    Safe ingestion batch summary.
    """

    model_config = ConfigDict(extra="ignore")

    ok: bool
    entity_type: str
    accepted: int
    rejected: int
    duplicated: int
    skipped: int
    dry_run: bool
    allow_partial: bool
    on_duplicate: str
    source_system: Optional[str] = None
    source_batch_id: Optional[str] = None
    request_id: Optional[str] = None
    errors: list[IngestionRowError] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)


class IngestionStatusResponse(BaseModel):
    """
    Safe ingestion subsystem status.
    """

    model_config = ConfigDict(extra="ignore")

    enabled: bool
    production_like: bool
    dataset_mode: str
    require_synthetic: bool
    max_batch_size: int
    hard_max_batch_size: int
    max_errors_returned: int
    hard_max_errors_returned: int
    default_allow_partial: bool
    default_duplicate_strategy: str
    future_tolerance_minutes: int
    caveats: list[str] = Field(default_factory=list)


class AccountBatchRequest(BaseModel):
    """
    Batch request for synthetic accounts.
    """

    model_config = ConfigDict(extra="forbid")

    records: list[dict[str, Any]] = Field(default_factory=list)
    options: Optional[IngestionOptions] = None


class TransactionBatchRequest(BaseModel):
    """
    Batch request for synthetic transactions.
    """

    model_config = ConfigDict(extra="forbid")

    records: list[dict[str, Any]] = Field(default_factory=list)
    options: Optional[IngestionOptions] = None


class ComplaintBatchRequest(BaseModel):
    """
    Batch request for synthetic complaints.
    """

    model_config = ConfigDict(extra="forbid")

    records: list[dict[str, Any]] = Field(default_factory=list)
    options: Optional[IngestionOptions] = None


class EntityBatchRequest(BaseModel):
    """
    Batch request for synthetic pseudonymous entities.
    """

    model_config = ConfigDict(extra="forbid")

    records: list[dict[str, Any]] = Field(default_factory=list)
    options: Optional[IngestionOptions] = None


class EntityLinkBatchRequest(BaseModel):
    """
    Batch request for synthetic account-entity links.
    """

    model_config = ConfigDict(extra="forbid")

    records: list[dict[str, Any]] = Field(default_factory=list)
    options: Optional[IngestionOptions] = None


# -----------------------------------------------------------------------------
# Ingestion record models
# -----------------------------------------------------------------------------


def _validate_optional_id(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    normalized = str(value).strip()

    if not normalized:
        return None

    if len(normalized) > 128:
        raise ValueError("id is too long")

    return normalized


def _validate_required_reference(value: str) -> str:
    normalized = str(value).strip()

    if not normalized:
        raise ValueError("reference must not be empty")

    if len(normalized) > 128:
        raise ValueError("reference is too long")

    return normalized


def _validate_optional_reference(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    normalized = str(value).strip()

    if not normalized:
        return None

    if len(normalized) > 128:
        raise ValueError("reference is too long")

    return normalized


def _validate_currency(value: Optional[str], *, required: bool) -> Optional[str]:
    if value is None:
        if required:
            return "INR"
        return None

    normalized = str(value).strip().upper()

    if len(normalized) != 3:
        raise ValueError("currency must be a three-letter code")

    return normalized


def _validate_finite_decimal(value: Optional[Decimal]) -> Optional[Decimal]:
    if value is None:
        return None

    if not value.is_finite():
        raise ValueError("value must be finite")

    return value


class AccountIngestRecord(BaseModel):
    """
    Synthetic account ingestion record.
    """

    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = Field(default=None, max_length=128)
    account_type: AccountType = Field(default=AccountType.OTHER)
    status: AccountStatus = Field(default=AccountStatus.ACTIVE)
    created_at: Optional[datetime] = None
    metadata_json: Optional[dict[str, Any]] = None

    _validate_id = field_validator("id")(_validate_optional_id)

    @field_validator("created_at")
    @classmethod
    def _validate_created_at(cls, value: Optional[datetime]) -> Optional[datetime]:
        return _ensure_utc(value)


class TransactionIngestRecord(BaseModel):
    """
    Synthetic transaction ingestion record.
    """

    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = Field(default=None, max_length=128)
    reference: str
    sender_account_id: str
    receiver_account_id: str
    amount: Decimal = Field(gt=0)
    currency: str = Field(default="INR", min_length=3, max_length=3)
    occurred_at: datetime
    status: TransactionStatus = Field(default=TransactionStatus.COMPLETED)
    channel: Channel = Field(default=Channel.INTERNAL)
    metadata_json: Optional[dict[str, Any]] = None

    _validate_id = field_validator("id")(_validate_optional_id)

    @field_validator("reference")
    @classmethod
    def _validate_reference(cls, value: str) -> str:
        return _validate_required_reference(value)

    @field_validator("sender_account_id", "receiver_account_id")
    @classmethod
    def _validate_account_id(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("account id must not be empty")

        if len(normalized) > 128:
            raise ValueError("account id is too long")

        return normalized

    @field_validator("amount")
    @classmethod
    def _validate_amount(cls, value: Decimal) -> Decimal:
        validated = _validate_finite_decimal(value)

        if validated is None or validated <= 0:
            raise ValueError("amount must be positive")

        return validated

    @field_validator("currency")
    @classmethod
    def _validate_currency(cls, value: str) -> str:
        return _validate_currency(value, required=True) or "INR"

    @field_validator("occurred_at")
    @classmethod
    def _validate_occurred_at(cls, value: datetime) -> datetime:
        normalized = _ensure_utc(value)

        if normalized is None:
            raise ValueError("occurred_at is required")

        return normalized


class ComplaintIngestRecord(BaseModel):
    """
    Synthetic complaint ingestion record.

    `narrative_raw` is accepted and persisted but is never returned in
    ingestion responses or row errors.
    """

    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = Field(default=None, max_length=128)
    reference: str
    reported_at: datetime
    category: str = Field(default="other", max_length=100)
    narrative_raw: str = Field(min_length=1, max_length=_MAX_NARRATIVE_LENGTH)
    transaction_reference: Optional[str] = None
    victim_account_id: Optional[str] = None
    suspected_account_id: Optional[str] = None
    amount: Optional[Decimal] = Field(default=None, gt=0)
    currency: Optional[str] = Field(default=None, min_length=3, max_length=3)
    source: Optional[str] = Field(default=None, max_length=100)
    metadata_json: Optional[dict[str, Any]] = None

    _validate_id = field_validator("id")(_validate_optional_id)

    @field_validator("reference")
    @classmethod
    def _validate_reference(cls, value: str) -> str:
        return _validate_required_reference(value)

    @field_validator("transaction_reference")
    @classmethod
    def _validate_transaction_reference(cls, value: Optional[str]) -> Optional[str]:
        return _validate_optional_reference(value)

    @field_validator("reported_at")
    @classmethod
    def _validate_reported_at(cls, value: datetime) -> datetime:
        normalized = _ensure_utc(value)

        if normalized is None:
            raise ValueError("reported_at is required")

        return normalized

    @field_validator("narrative_raw")
    @classmethod
    def _validate_narrative_raw(cls, value: str) -> str:
        cleaned = _clean_narrative(value)

        if not cleaned.strip():
            raise ValueError("narrative_raw must not be empty")

        return cleaned

    @field_validator("victim_account_id", "suspected_account_id")
    @classmethod
    def _validate_optional_account_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > 128:
            raise ValueError("account id is too long")

        return normalized

    @field_validator("amount")
    @classmethod
    def _validate_amount(cls, value: Optional[Decimal]) -> Optional[Decimal]:
        return _validate_finite_decimal(value)

    @field_validator("currency")
    @classmethod
    def _validate_currency(cls, value: Optional[str]) -> Optional[str]:
        return _validate_currency(value, required=False)

    @field_validator("category", "source")
    @classmethod
    def _validate_short_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > 100:
            raise ValueError("value is too long")

        return normalized


class EntityIngestRecord(BaseModel):
    """
    Synthetic pseudonymous entity ingestion record.

    `identifier_hash` must already be pseudonymous. Raw identifiers must not be
    submitted.
    """

    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = Field(default=None, max_length=128)
    entity_type: EntityType
    identifier_hash: str
    identifier_display: Optional[str] = Field(default=None, max_length=200)
    source: Optional[str] = Field(default=None, max_length=100)
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    metadata_json: Optional[dict[str, Any]] = None

    _validate_id = field_validator("id")(_validate_optional_id)

    @field_validator("identifier_hash")
    @classmethod
    def _validate_identifier_hash(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("identifier_hash must not be empty")

        if not _IDENTIFIER_HASH_RE.match(normalized):
            raise ValueError(
                "identifier_hash must be a pseudonymous hashed value"
            )

        return normalized

    @field_validator("identifier_display")
    @classmethod
    def _validate_identifier_display(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = _clean_text(value, 200)

        if not normalized:
            return None

        return normalized

    @field_validator("source")
    @classmethod
    def _validate_source(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > 100:
            raise ValueError("source is too long")

        return normalized

    @field_validator("first_seen_at", "last_seen_at")
    @classmethod
    def _validate_timestamps(cls, value: Optional[datetime]) -> Optional[datetime]:
        return _ensure_utc(value)


class EntityLinkIngestRecord(BaseModel):
    """
    Synthetic account-entity link ingestion record.
    """

    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = Field(default=None, max_length=128)
    account_id: str
    entity_id: str
    match_method: MatchMethod = Field(default=MatchMethod.EXACT)
    confidence: Optional[Decimal] = Field(default=None, ge=0, le=1)
    verification_state: VerificationState = Field(default=VerificationState.UNVERIFIED)
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    source: Optional[str] = Field(default=None, max_length=100)
    metadata_json: Optional[dict[str, Any]] = None

    _validate_id = field_validator("id")(_validate_optional_id)

    @field_validator("account_id", "entity_id")
    @classmethod
    def _validate_ids(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("identifier must not be empty")

        if len(normalized) > 128:
            raise ValueError("identifier is too long")

        return normalized

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, value: Optional[Decimal]) -> Optional[Decimal]:
        return _validate_finite_decimal(value)

    @field_validator("valid_from", "valid_to")
    @classmethod
    def _validate_timestamps(cls, value: Optional[datetime]) -> Optional[datetime]:
        return _ensure_utc(value)

    @field_validator("source")
    @classmethod
    def _validate_source(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = str(value).strip()

        if not normalized:
            return None

        if len(normalized) > 100:
            raise ValueError("source is too long")

        return normalized


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=IngestionStatusResponse,
    summary="Get ingestion subsystem status",
    description=(
        "Returns safe ingestion status and bounded limits. This endpoint does "
        "not expose secrets, database URLs, tokens, passwords, raw complaint "
        "narratives, or real customer data."
    ),
)
def ingestion_status(
    settings: SettingsDep,
    _: User = Depends(require_permission(INGESTION_PERMISSION)),
) -> IngestionStatusResponse:
    """
    Return safe ingestion subsystem status.
    """
    _ensure_ingestion_enabled(settings)

    duplicate_default = str(
        _setting(settings, "INGESTION_DUPLICATE_STRATEGY", "reject")
        or "reject"
    ).strip().lower()

    if duplicate_default not in {"reject", "skip"}:
        duplicate_default = "reject"

    return IngestionStatusResponse(
        enabled=True,
        production_like=_is_production_like(settings),
        dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")),
        require_synthetic=_as_bool(_setting(settings, "INGESTION_REQUIRE_SYNTHETIC", True), True),
        max_batch_size=_max_batch_size(settings),
        hard_max_batch_size=_HARD_MAX_BATCH_SIZE,
        max_errors_returned=_max_errors_returned(settings),
        hard_max_errors_returned=_HARD_MAX_ERRORS,
        default_allow_partial=_as_bool(_setting(settings, "INGESTION_ALLOW_PARTIAL_BATCH", False), False),
        default_duplicate_strategy=duplicate_default,
        future_tolerance_minutes=max(
            0,
            _as_int(_setting(settings, "INGESTION_FUTURE_TOLERANCE_MINUTES", 5), 5),
        ),
        caveats=list(_INGESTION_CAVEATS),
    )


@router.post(
    "/accounts",
    response_model=IngestionBatchResponse,
    status_code=201,
    summary="Ingest synthetic accounts",
    description=(
        "Validates and persists a bounded batch of synthetic MULEGUARD accounts. "
        "This endpoint is synthetic-first and must not be used for real customer "
        "data."
    ),
)
def ingest_accounts(
    payload: AccountBatchRequest,
    request: Request,
    response: Response,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(INGESTION_PERMISSION)),
) -> IngestionBatchResponse:
    """
    Ingest synthetic accounts.
    """
    _ensure_ingestion_enabled(settings)

    max_batch = _max_batch_size(settings)
    max_errors = _max_errors_returned(settings)

    if len(payload.records) > max_batch:
        raise MuleGuardValidationError(
            "Ingestion batch exceeds configured maximum.",
            details={
                "max_batch_size": max_batch,
                "requested_records": len(payload.records),
            },
        )

    options = _resolve_options(payload.options, settings)
    row_errors: list[dict[str, Any]] = []
    counts = {"accepted": 0, "duplicated": 0, "skipped": 0}

    parsed = _parse_records(AccountIngestRecord, payload.records, row_errors, max_errors)

    seen_ids: set[str] = set()
    candidate_rows: list[tuple[int, AccountIngestRecord]] = []

    for row, record in parsed:
        record_id = _str_or_none(record.id)

        if record_id:
            if record_id in seen_ids:
                _duplicate_handling(
                    row=row,
                    duplicate_key="id",
                    counts=counts,
                    row_errors=row_errors,
                    options=options,
                    max_errors=max_errors,
                )
                continue

            seen_ids.add(record_id)

        created_at = _validate_not_future(
            record.created_at,
            row=row,
            field_name="created_at",
            row_errors=row_errors,
            settings=settings,
            max_errors=max_errors,
        )

        record.created_at = created_at
        candidate_rows.append((row, record))

    existing_ids: set[str] = set()

    if seen_ids:
        rows = db.scalars(select(Account.id).where(Account.id.in_(list(seen_ids)))).all()
        existing_ids = {str(item) for item in rows}

    accepted_rows: list[tuple[int, AccountIngestRecord]] = []

    for row, record in candidate_rows:
        record_id = _str_or_none(record.id)

        if record_id and record_id in existing_ids:
            _duplicate_handling(
                row=row,
                duplicate_key="id",
                counts=counts,
                row_errors=row_errors,
                options=options,
                max_errors=max_errors,
            )
            continue

        accepted_rows.append((row, record))

    now = _now_utc()

    for row, record in accepted_rows:
        account_id = _str_or_none(record.id) or _new_id()

        obj = Account(
            id=account_id,
            account_type=record.account_type,
            status=record.status,
            created_at=record.created_at or now,
            metadata_json=_sanitize_input_mapping(record.metadata_json),
        )

        _set_provenance(
            obj,
            options=options,
            request_id=request_id,
            record_mapping=record.model_dump(mode="json", exclude_none=True),
        )

        if not options["dry_run"]:
            db.add(obj)

        counts["accepted"] += 1

    return _finalize_batch(
        db,
        request,
        response,
        settings,
        actor,
        request_id,
        resource_type="accounts",
        counts=counts,
        row_errors=row_errors,
        options=options,
    )


@router.post(
    "/transactions",
    response_model=IngestionBatchResponse,
    status_code=201,
    summary="Ingest synthetic transactions",
    description=(
        "Validates and persists a bounded batch of synthetic MULEGUARD "
        "transactions. Sender and receiver accounts must already exist. "
        "Completed transfers are fund movement; pending, failed, and reversed "
        "records remain semantically distinct."
    ),
)
def ingest_transactions(
    payload: TransactionBatchRequest,
    request: Request,
    response: Response,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(INGESTION_PERMISSION)),
) -> IngestionBatchResponse:
    """
    Ingest synthetic transactions.
    """
    _ensure_ingestion_enabled(settings)

    max_batch = _max_batch_size(settings)
    max_errors = _max_errors_returned(settings)

    if len(payload.records) > max_batch:
        raise MuleGuardValidationError(
            "Ingestion batch exceeds configured maximum.",
            details={
                "max_batch_size": max_batch,
                "requested_records": len(payload.records),
            },
        )

    options = _resolve_options(payload.options, settings)
    row_errors: list[dict[str, Any]] = []
    counts = {"accepted": 0, "duplicated": 0, "skipped": 0}

    parsed = _parse_records(TransactionIngestRecord, payload.records, row_errors, max_errors)

    seen_ids: set[str] = set()
    seen_references: set[str] = set()
    candidate_rows: list[tuple[int, TransactionIngestRecord]] = []

    for row, record in parsed:
        record_id = _str_or_none(record.id)
        reference = record.reference

        duplicate = False

        if record_id:
            if record_id in seen_ids:
                duplicate = True
                _duplicate_handling(
                    row=row,
                    duplicate_key="id",
                    counts=counts,
                    row_errors=row_errors,
                    options=options,
                    max_errors=max_errors,
                )
            else:
                seen_ids.add(record_id)

        if not duplicate:
            if reference in seen_references:
                _duplicate_handling(
                    row=row,
                    duplicate_key="reference",
                    counts=counts,
                    row_errors=row_errors,
                    options=options,
                    max_errors=max_errors,
                )
                continue

            seen_references.add(reference)

        occurred_at = _validate_not_future(
            record.occurred_at,
            row=row,
            field_name="occurred_at",
            row_errors=row_errors,
            settings=settings,
            max_errors=max_errors,
        )

        record.occurred_at = occurred_at or record.occurred_at
        candidate_rows.append((row, record))

    existing_ids: set[str] = set()
    existing_references: set[str] = set()

    if seen_ids:
        rows = db.scalars(select(Transaction.id).where(Transaction.id.in_(list(seen_ids)))).all()
        existing_ids = {str(item) for item in rows}

    if seen_references:
        rows = db.scalars(
            select(Transaction.reference).where(Transaction.reference.in_(list(seen_references)))
        ).all()
        existing_references = {str(item) for item in rows}

    reference_checked_rows: list[tuple[int, TransactionIngestRecord]] = []

    for row, record in candidate_rows:
        record_id = _str_or_none(record.id)

        if record_id and record_id in existing_ids:
            _duplicate_handling(
                row=row,
                duplicate_key="id",
                counts=counts,
                row_errors=row_errors,
                options=options,
                max_errors=max_errors,
            )
            continue

        if record.reference in existing_references:
            _duplicate_handling(
                row=row,
                duplicate_key="reference",
                counts=counts,
                row_errors=row_errors,
                options=options,
                max_errors=max_errors,
            )
            continue

        reference_checked_rows.append((row, record))

    account_ids: set[str] = set()

    for _, record in reference_checked_rows:
        account_ids.add(record.sender_account_id)
        account_ids.add(record.receiver_account_id)

    existing_accounts: set[str] = set()

    if account_ids:
        rows = db.scalars(select(Account.id).where(Account.id.in_(list(account_ids)))).all()
        existing_accounts = {str(item) for item in rows}

    accepted_rows: list[tuple[int, TransactionIngestRecord]] = []

    for row, record in reference_checked_rows:
        missing: list[str] = []

        if record.sender_account_id not in existing_accounts:
            missing.append("sender_account_id")

        if record.receiver_account_id not in existing_accounts:
            missing.append("receiver_account_id")

        if missing:
            _append_error(
                row_errors,
                _row_error(
                    row,
                    code="reference_missing",
                    message="Referenced account does not exist.",
                    field=", ".join(missing),
                ),
                max_errors,
            )
            continue

        accepted_rows.append((row, record))

    for row, record in accepted_rows:
        transaction_id = _str_or_none(record.id) or _new_id()

        obj = Transaction(
            id=transaction_id,
            sender_account_id=record.sender_account_id,
            receiver_account_id=record.receiver_account_id,
            amount=record.amount,
            currency=record.currency,
            occurred_at=record.occurred_at,
            status=record.status,
            channel=record.channel,
            reference=record.reference,
            metadata_json=_sanitize_input_mapping(record.metadata_json),
        )

        _set_provenance(
            obj,
            options=options,
            request_id=request_id,
            record_mapping=record.model_dump(mode="json", exclude_none=True),
        )

        if not options["dry_run"]:
            db.add(obj)

        counts["accepted"] += 1

    return _finalize_batch(
        db,
        request,
        response,
        settings,
        actor,
        request_id,
        resource_type="transactions",
        counts=counts,
        row_errors=row_errors,
        options=options,
    )


@router.post(
    "/complaints",
    response_model=IngestionBatchResponse,
    status_code=201,
    summary="Ingest synthetic complaints",
    description=(
        "Validates and persists a bounded batch of synthetic MULEGUARD complaints. "
        "Raw complaint narratives are accepted and stored but are never returned "
        "in ingestion responses or row errors."
    ),
)
def ingest_complaints(
    payload: ComplaintBatchRequest,
    request: Request,
    response: Response,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(INGESTION_PERMISSION)),
) -> IngestionBatchResponse:
    """
    Ingest synthetic complaints.
    """
    _ensure_ingestion_enabled(settings)

    max_batch = _max_batch_size(settings)
    max_errors = _max_errors_returned(settings)

    if len(payload.records) > max_batch:
        raise MuleGuardValidationError(
            "Ingestion batch exceeds configured maximum.",
            details={
                "max_batch_size": max_batch,
                "requested_records": len(payload.records),
            },
        )

    options = _resolve_options(payload.options, settings)
    row_errors: list[dict[str, Any]] = []
    counts = {"accepted": 0, "duplicated": 0, "skipped": 0}

    parsed = _parse_records(ComplaintIngestRecord, payload.records, row_errors, max_errors)

    seen_ids: set[str] = set()
    seen_references: set[str] = set()
    candidate_rows: list[tuple[int, ComplaintIngestRecord]] = []

    for row, record in parsed:
        record_id = _str_or_none(record.id)
        reference = record.reference

        duplicate = False

        if record_id:
            if record_id in seen_ids:
                duplicate = True
                _duplicate_handling(
                    row=row,
                    duplicate_key="id",
                    counts=counts,
                    row_errors=row_errors,
                    options=options,
                    max_errors=max_errors,
                )
            else:
                seen_ids.add(record_id)

        if not duplicate:
            if reference in seen_references:
                _duplicate_handling(
                    row=row,
                    duplicate_key="reference",
                    counts=counts,
                    row_errors=row_errors,
                    options=options,
                    max_errors=max_errors,
                )
                continue

            seen_references.add(reference)

        reported_at = _validate_not_future(
            record.reported_at,
            row=row,
            field_name="reported_at",
            row_errors=row_errors,
            settings=settings,
            max_errors=max_errors,
        )

        record.reported_at = reported_at or record.reported_at
        candidate_rows.append((row, record))

    existing_ids: set[str] = set()
    existing_references: set[str] = set()

    if seen_ids:
        rows = db.scalars(select(Complaint.id).where(Complaint.id.in_(list(seen_ids)))).all()
        existing_ids = {str(item) for item in rows}

    if seen_references:
        rows = db.scalars(
            select(Complaint.reference).where(Complaint.reference.in_(list(seen_references)))
        ).all()
        existing_references = {str(item) for item in rows}

    reference_checked_rows: list[tuple[int, ComplaintIngestRecord]] = []

    for row, record in candidate_rows:
        record_id = _str_or_none(record.id)

        if record_id and record_id in existing_ids:
            _duplicate_handling(
                row=row,
                duplicate_key="id",
                counts=counts,
                row_errors=row_errors,
                options=options,
                max_errors=max_errors,
            )
            continue

        if record.reference in existing_references:
            _duplicate_handling(
                row=row,
                duplicate_key="reference",
                counts=counts,
                row_errors=row_errors,
                options=options,
                max_errors=max_errors,
            )
            continue

        reference_checked_rows.append((row, record))

    account_ids: set[str] = set()

    for _, record in reference_checked_rows:
        if record.victim_account_id:
            account_ids.add(record.victim_account_id)

        if record.suspected_account_id:
            account_ids.add(record.suspected_account_id)

    existing_accounts: set[str] = set()

    if account_ids:
        rows = db.scalars(select(Account.id).where(Account.id.in_(list(account_ids)))).all()
        existing_accounts = {str(item) for item in rows}

    accepted_rows: list[tuple[int, ComplaintIngestRecord]] = []

    for row, record in reference_checked_rows:
        missing: list[str] = []

        if record.victim_account_id and record.victim_account_id not in existing_accounts:
            missing.append("victim_account_id")

        if record.suspected_account_id and record.suspected_account_id not in existing_accounts:
            missing.append("suspected_account_id")

        if missing:
            _append_error(
                row_errors,
                _row_error(
                    row,
                    code="reference_missing",
                    message="Referenced account does not exist.",
                    field=", ".join(missing),
                ),
                max_errors,
            )
            continue

        accepted_rows.append((row, record))

    for row, record in accepted_rows:
        complaint_id = _str_or_none(record.id) or _new_id()

        obj = Complaint(
            id=complaint_id,
            reference=record.reference,
            reported_at=record.reported_at,
            category=record.category or "other",
            narrative_raw=record.narrative_raw,
            transaction_reference=record.transaction_reference,
            victim_account_id=record.victim_account_id,
            suspected_account_id=record.suspected_account_id,
            amount=record.amount,
            currency=record.currency,
            source=record.source or _str_or_none(options.get("source_system")) or "synthetic",
            ingested_at=_now_utc(),
            metadata_json=_sanitize_input_mapping(record.metadata_json),
        )

        _set_provenance(
            obj,
            options=options,
            request_id=request_id,
            record_mapping={
                "reference": record.reference,
                "reported_at": record.reported_at.isoformat(),
                "category": record.category,
                "transaction_reference": record.transaction_reference,
                "victim_account_id": record.victim_account_id,
                "suspected_account_id": record.suspected_account_id,
                "amount": str(record.amount) if record.amount is not None else None,
                "currency": record.currency,
                "source": record.source,
                "narrative_length": len(record.narrative_raw),
                "narrative_sha256": hashlib.sha256(record.narrative_raw.encode("utf-8")).hexdigest(),
            },
        )

        if not options["dry_run"]:
            db.add(obj)

        counts["accepted"] += 1

    return _finalize_batch(
        db,
        request,
        response,
        settings,
        actor,
        request_id,
        resource_type="complaints",
        counts=counts,
        row_errors=row_errors,
        options=options,
    )


@router.post(
    "/entities",
    response_model=IngestionBatchResponse,
    status_code=201,
    summary="Ingest synthetic pseudonymous entities",
    description=(
        "Validates and persists a bounded batch of synthetic pseudonymous "
        "entities. Submitted identifier hashes must already be pseudonymous. "
        "Raw identifier hashes are stored but never returned."
    ),
)
def ingest_entities(
    payload: EntityBatchRequest,
    request: Request,
    response: Response,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(INGESTION_PERMISSION)),
) -> IngestionBatchResponse:
    """
    Ingest synthetic entities.
    """
    _ensure_ingestion_enabled(settings)

    max_batch = _max_batch_size(settings)
    max_errors = _max_errors_returned(settings)

    if len(payload.records) > max_batch:
        raise MuleGuardValidationError(
            "Ingestion batch exceeds configured maximum.",
            details={
                "max_batch_size": max_batch,
                "requested_records": len(payload.records),
            },
        )

    options = _resolve_options(payload.options, settings)
    row_errors: list[dict[str, Any]] = []
    counts = {"accepted": 0, "duplicated": 0, "skipped": 0}

    parsed = _parse_records(EntityIngestRecord, payload.records, row_errors, max_errors)

    seen_ids: set[str] = set()
    seen_keys: set[tuple[str, str, str]] = set()
    candidate_rows: list[tuple[int, EntityIngestRecord]] = []

    for row, record in parsed:
        record_id = _str_or_none(record.id)
        source = record.source or _str_or_none(options.get("source_system")) or "synthetic"
        key = (_enum_str(record.entity_type) or "OTHER", record.identifier_hash, source)

        duplicate = False

        if record_id:
            if record_id in seen_ids:
                duplicate = True
                _duplicate_handling(
                    row=row,
                    duplicate_key="id",
                    counts=counts,
                    row_errors=row_errors,
                    options=options,
                    max_errors=max_errors,
                )
            else:
                seen_ids.add(record_id)

        if not duplicate:
            if key in seen_keys:
                _duplicate_handling(
                    row=row,
                    duplicate_key="entity_type,identifier_hash,source",
                    counts=counts,
                    row_errors=row_errors,
                    options=options,
                    max_errors=max_errors,
                )
                continue

            seen_keys.add(key)

        first_seen_at = _validate_not_future(
            record.first_seen_at,
            row=row,
            field_name="first_seen_at",
            row_errors=row_errors,
            settings=settings,
            max_errors=max_errors,
        )
        last_seen_at = _validate_not_future(
            record.last_seen_at,
            row=row,
            field_name="last_seen_at",
            row_errors=row_errors,
            settings=settings,
            max_errors=max_errors,
        )

        if first_seen_at is not None and last_seen_at is not None and first_seen_at > last_seen_at:
            _append_error(
                row_errors,
                _row_error(
                    row,
                    code="invalid_time_range",
                    message="first_seen_at must be earlier than or equal to last_seen_at.",
                    field="first_seen_at,last_seen_at",
                ),
                max_errors,
            )
            continue

        record.first_seen_at = first_seen_at
        record.last_seen_at = last_seen_at
        record.source = source
        candidate_rows.append((row, record))

    existing_ids: set[str] = set()
    existing_keys: set[tuple[str, str, str]] = set()

    if seen_ids:
        rows = db.scalars(select(Entity.id).where(Entity.id.in_(list(seen_ids)))).all()
        existing_ids = {str(item) for item in rows}

    if seen_keys:
        conditions = [
            and_(
                Entity.entity_type == EntityType(key[0]),
                Entity.identifier_hash == key[1],
                Entity.source == key[2],
            )
            for key in seen_keys
        ]

        rows = db.execute(
            select(Entity.entity_type, Entity.identifier_hash, Entity.source).where(or_(*conditions))
        ).all()

        existing_keys = {
            (_enum_str(row[0]) or str(row[0]), str(row[1]), str(row[2]))
            for row in rows
        }

    accepted_rows: list[tuple[int, EntityIngestRecord]] = []

    for row, record in candidate_rows:
        record_id = _str_or_none(record.id)
        source = record.source or "synthetic"
        key = (_enum_str(record.entity_type) or "OTHER", record.identifier_hash, source)

        if record_id and record_id in existing_ids:
            _duplicate_handling(
                row=row,
                duplicate_key="id",
                counts=counts,
                row_errors=row_errors,
                options=options,
                max_errors=max_errors,
            )
            continue

        if key in existing_keys:
            _duplicate_handling(
                row=row,
                duplicate_key="entity_type,identifier_hash,source",
                counts=counts,
                row_errors=row_errors,
                options=options,
                max_errors=max_errors,
            )
            continue

        accepted_rows.append((row, record))

    for row, record in accepted_rows:
        entity_id = _str_or_none(record.id) or _new_id()
        source = record.source or "synthetic"

        obj = Entity(
            id=entity_id,
            entity_type=record.entity_type,
            identifier_hash=record.identifier_hash,
            identifier_display=record.identifier_display,
            source=source,
            first_seen_at=record.first_seen_at,
            last_seen_at=record.last_seen_at,
            metadata_json=_sanitize_input_mapping(record.metadata_json),
        )

        _set_provenance(
            obj,
            options=options,
            request_id=request_id,
            record_mapping={
                "entity_type": _enum_str(record.entity_type),
                "identifier_hash_sha256": hashlib.sha256(record.identifier_hash.encode("utf-8")).hexdigest(),
                "identifier_display": record.identifier_display,
                "source": source,
                "first_seen_at": record.first_seen_at.isoformat() if record.first_seen_at else None,
                "last_seen_at": record.last_seen_at.isoformat() if record.last_seen_at else None,
            },
        )

        if not options["dry_run"]:
            db.add(obj)

        counts["accepted"] += 1

    return _finalize_batch(
        db,
        request,
        response,
        settings,
        actor,
        request_id,
        resource_type="entities",
        counts=counts,
        row_errors=row_errors,
        options=options,
    )


@router.post(
    "/entity-links",
    response_model=IngestionBatchResponse,
    status_code=201,
    summary="Ingest synthetic account-entity links",
    description=(
        "Validates and persists a bounded batch of synthetic time-bound "
        "account-entity links. Links are investigative associations only and "
        "are not proof of common control or wrongdoing."
    ),
)
def ingest_entity_links(
    payload: EntityLinkBatchRequest,
    request: Request,
    response: Response,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(INGESTION_PERMISSION)),
) -> IngestionBatchResponse:
    """
    Ingest synthetic account-entity links.
    """
    _ensure_ingestion_enabled(settings)

    max_batch = _max_batch_size(settings)
    max_errors = _max_errors_returned(settings)

    if len(payload.records) > max_batch:
        raise MuleGuardValidationError(
            "Ingestion batch exceeds configured maximum.",
            details={
                "max_batch_size": max_batch,
                "requested_records": len(payload.records),
            },
        )

    options = _resolve_options(payload.options, settings)
    row_errors: list[dict[str, Any]] = []
    counts = {"accepted": 0, "duplicated": 0, "skipped": 0}

    parsed = _parse_records(EntityLinkIngestRecord, payload.records, row_errors, max_errors)

    seen_ids: set[str] = set()
    seen_keys: set[tuple[str, str, str, str]] = set()
    candidate_rows: list[tuple[int, EntityLinkIngestRecord]] = []

    now = _now_utc()

    for row, record in parsed:
        record_id = _str_or_none(record.id)
        source = record.source or _str_or_none(options.get("source_system")) or "synthetic"
        valid_from = record.valid_from or now
        valid_from = _ensure_utc(valid_from) or now

        valid_from_not_future = _validate_not_future(
            valid_from,
            row=row,
            field_name="valid_from",
            row_errors=row_errors,
            settings=settings,
            max_errors=max_errors,
        )

        valid_from = valid_from_not_future or valid_from

        valid_to = _ensure_utc(record.valid_to)

        if valid_to is not None and valid_to <= valid_from:
            _append_error(
                row_errors,
                _row_error(
                    row,
                    code="invalid_time_range",
                    message="valid_to must be later than valid_from.",
                    field="valid_to",
                ),
                max_errors,
            )
            continue

        key = (
            record.account_id,
            record.entity_id,
            valid_from.isoformat(),
            source,
        )

        duplicate = False

        if record_id:
            if record_id in seen_ids:
                duplicate = True
                _duplicate_handling(
                    row=row,
                    duplicate_key="id",
                    counts=counts,
                    row_errors=row_errors,
                    options=options,
                    max_errors=max_errors,
                )
            else:
                seen_ids.add(record_id)

        if not duplicate:
            if key in seen_keys:
                _duplicate_handling(
                    row=row,
                    duplicate_key="account_id,entity_id,valid_from,source",
                    counts=counts,
                    row_errors=row_errors,
                    options=options,
                    max_errors=max_errors,
                )
                continue

            seen_keys.add(key)

        record.valid_from = valid_from
        record.valid_to = valid_to
        record.source = source
        candidate_rows.append((row, record))

    account_ids: set[str] = set()
    entity_ids: set[str] = set()

    for _, record in candidate_rows:
        account_ids.add(record.account_id)
        entity_ids.add(record.entity_id)

    existing_accounts: set[str] = set()
    existing_entities: set[str] = set()

    if account_ids:
        rows = db.scalars(select(Account.id).where(Account.id.in_(list(account_ids)))).all()
        existing_accounts = {str(item) for item in rows}

    if entity_ids:
        rows = db.scalars(select(Entity.id).where(Entity.id.in_(list(entity_ids)))).all()
        existing_entities = {str(item) for item in rows}

    existing_ids: set[str] = set()
    existing_keys: set[tuple[str, str, str, str]] = set()

    if seen_ids:
        rows = db.scalars(
            select(AccountEntityLink.id).where(AccountEntityLink.id.in_(list(seen_ids)))
        ).all()
        existing_ids = {str(item) for item in rows}

    if seen_keys:
        link_rows = db.scalars(select(AccountEntityLink).limit(len(seen_keys) * 2)).all()

        for link in link_rows:
            link_valid_from = _ensure_utc(getattr(link, "valid_from", None))

            key = (
                str(getattr(link, "account_id", "")),
                str(getattr(link, "entity_id", "")),
                link_valid_from.isoformat() if link_valid_from else "",
                str(getattr(link, "source", "") or ""),
            )

            if key in seen_keys:
                existing_keys.add(key)

    accepted_rows: list[tuple[int, EntityLinkIngestRecord]] = []

    for row, record in candidate_rows:
        missing: list[str] = []

        if record.account_id not in existing_accounts:
            missing.append("account_id")

        if record.entity_id not in existing_entities:
            missing.append("entity_id")

        if missing:
            _append_error(
                row_errors,
                _row_error(
                    row,
                    code="reference_missing",
                    message="Referenced account or entity does not exist.",
                    field=", ".join(missing),
                ),
                max_errors,
            )
            continue

        record_id = _str_or_none(record.id)
        source = record.source or "synthetic"
        valid_from = record.valid_from or now

        key = (
            record.account_id,
            record.entity_id,
            valid_from.isoformat(),
            source,
        )

        if record_id and record_id in existing_ids:
            _duplicate_handling(
                row=row,
                duplicate_key="id",
                counts=counts,
                row_errors=row_errors,
                options=options,
                max_errors=max_errors,
            )
            continue

        if key in existing_keys:
            _duplicate_handling(
                row=row,
                duplicate_key="account_id,entity_id,valid_from,source",
                counts=counts,
                row_errors=row_errors,
                options=options,
                max_errors=max_errors,
            )
            continue

        accepted_rows.append((row, record))

    for row, record in accepted_rows:
        link_id = _str_or_none(record.id) or _new_id()
        source = record.source or "synthetic"

        obj = AccountEntityLink(
            id=link_id,
            account_id=record.account_id,
            entity_id=record.entity_id,
            match_method=record.match_method,
            confidence=record.confidence,
            verification_state=record.verification_state,
            valid_from=record.valid_from or now,
            valid_to=record.valid_to,
            source=source,
            metadata_json=_sanitize_input_mapping(record.metadata_json),
        )

        _set_provenance(
            obj,
            options=options,
            request_id=request_id,
            record_mapping=record.model_dump(mode="json", exclude_none=True),
        )

        if not options["dry_run"]:
            db.add(obj)

        counts["accepted"] += 1

    return _finalize_batch(
        db,
        request,
        response,
        settings,
        actor,
        request_id,
        resource_type="entity_links",
        counts=counts,
        row_errors=row_errors,
        options=options,
    )


__all__ = [
    "router",
]