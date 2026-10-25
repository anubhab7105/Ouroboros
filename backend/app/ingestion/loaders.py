"""
MULEGUARD backend ingestion loaders.

This module provides the canonical loading layer for synthetic MULEGUARD
ingestion workflows.

Primary responsibilities:

- load bounded ingestion records from safe in-memory structures, JSON, NDJSON,
  CSV, and explicitly allowed local files;
- preserve deterministic record ordering where the source supports it;
- enforce strict source bounds for byte size, line size, cell size, record
  count, error reporting, and warning reporting;
- reject or omit leakage-prone top-level fields such as ground-truth labels,
  scenario IDs, fraud-ring IDs, raw identifiers, secrets, tokens, passwords,
  database URLs, and model artifact paths;
- allow controlled synthetic complaint narrative loading only for complaint
  records, while never returning narratives in public summaries, issues,
  warnings, or diagnostics;
- produce safe structured load results with source lineage, checksums, bounded
  issues, and no sensitive values;
- remain import-safe, dependency-light, and usable by API endpoints, services,
  seeders, tests, and offline fixtures.

This module loads records only. It does not persist data, call external systems,
authenticate users, authorize actions, train models, generate reports, or take
adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be ingested.
- Ground-truth labels, injected scenario IDs, and fraud-ring IDs must not be
  accepted, persisted, returned, logged, or exported.
- Raw complaint narratives may be loaded only for controlled synthetic complaint
  ingestion, but are never returned in load summaries, errors, warnings, or
  diagnostics.
- Entity identifiers must be pseudonymously hashed. Raw identifier fields are
  rejected or omitted.
- Secrets, tokens, passwords, database URLs, model artifact paths, and raw
  sensitive identifiers are never logged or returned.
- File loading is disabled by default and, when enabled, is restricted to
  explicitly allowed local directories.
- No network, remote URL, pickle, unsafe YAML, or external-entity XML loading is
  performed.
- Loading is bounded and deterministic.
- Unknown fields are omitted by default to reduce accidental leakage surface.
- Loading never triggers automatic adverse customer action such as freezing,
  blocking, blacklisting, closing, or restricting accounts.
- Ingested records are investigative inputs only. They are not proof of
  wrongdoing.

Explicit non-goals:

- This module does not write to the database.
- This module does not call real banking systems.
- This module does not authenticate or authorize users.
- This module does not generate synthetic data.
- This module does not perform final business-rule validation; use
  `app.ingestion.normalizers` and `app.ingestion.validators` for that.
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

import csv
import hashlib
import io
import json
import logging
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from os import PathLike
from pathlib import Path
from typing import Any, Final, Iterator, Optional

logger = logging.getLogger("muleguard.backend.ingestion.loaders")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

LOADERS_VERSION: Final[str] = "v1"

SOURCE_TYPE_RECORDS: Final[str] = "records"
SOURCE_TYPE_BYTES: Final[str] = "bytes"
SOURCE_TYPE_TEXT: Final[str] = "text"
SOURCE_TYPE_FILE: Final[str] = "file"

CONTENT_TYPE_JSON: Final[str] = "application/json"
CONTENT_TYPE_NDJSON: Final[str] = "application/x-ndjson"
CONTENT_TYPE_CSV: Final[str] = "text/csv"
CONTENT_TYPE_RECORDS: Final[str] = "application/x-records"

SUPPORTED_CONTENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        CONTENT_TYPE_JSON,
        CONTENT_TYPE_NDJSON,
        CONTENT_TYPE_CSV,
        CONTENT_TYPE_RECORDS,
    }
)

SUPPORTED_INGESTION_ENTITY_TYPES: Final[tuple[str, ...]] = (
    "accounts",
    "transactions",
    "complaints",
    "entities",
    "entity_links",
)

ALLOWED_FILE_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".json",
        ".ndjson",
        ".jsonl",
        ".csv",
    }
)

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

DEFAULT_MAX_RECORDS: Final[int] = 10_000
HARD_MAX_RECORDS: Final[int] = 100_000

DEFAULT_MAX_BYTES: Final[int] = 4 * 1024 * 1024
HARD_MAX_BYTES: Final[int] = 50 * 1024 * 1024

DEFAULT_MAX_FILE_BYTES: Final[int] = 10 * 1024 * 1024
HARD_MAX_FILE_BYTES: Final[int] = 100 * 1024 * 1024

DEFAULT_MAX_LINE_BYTES: Final[int] = 1 * 1024 * 1024
HARD_MAX_LINE_BYTES: Final[int] = 10 * 1024 * 1024

DEFAULT_MAX_CELL_BYTES: Final[int] = 256 * 1024
HARD_MAX_CELL_BYTES: Final[int] = 1 * 1024 * 1024

DEFAULT_MAX_ERRORS_RETURNED: Final[int] = 100
HARD_MAX_ERRORS_RETURNED: Final[int] = 500

DEFAULT_MAX_WARNINGS_RETURNED: Final[int] = 50
HARD_MAX_WARNINGS_RETURNED: Final[int] = 200

DEFAULT_MAX_STRING_LENGTH: Final[int] = 512
HARD_MAX_STRING_LENGTH: Final[int] = 4_096

MAX_SOURCE_NAME_LENGTH: Final[int] = 200
MAX_FIELD_NAME_LENGTH: Final[int] = 200

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")

_MORE_SENTINEL: Final[object] = object()


# -----------------------------------------------------------------------------
# Allowed and forbidden field registries
# -----------------------------------------------------------------------------

ALLOWED_FIELDS: Final[Mapping[str, frozenset[str]]] = {
    "accounts": frozenset(
        {
            "id",
            "account_type",
            "status",
            "created_at",
            "metadata_json",
        }
    ),
    "transactions": frozenset(
        {
            "id",
            "reference",
            "sender_account_id",
            "receiver_account_id",
            "amount",
            "currency",
            "occurred_at",
            "status",
            "channel",
            "metadata_json",
        }
    ),
    "complaints": frozenset(
        {
            "id",
            "reference",
            "reported_at",
            "category",
            "narrative_raw",
            "transaction_reference",
            "victim_account_id",
            "suspected_account_id",
            "amount",
            "currency",
            "source",
            "metadata_json",
        }
    ),
    "entities": frozenset(
        {
            "id",
            "entity_type",
            "identifier_hash",
            "identifier_display",
            "source",
            "first_seen_at",
            "last_seen_at",
            "metadata_json",
        }
    ),
    "entity_links": frozenset(
        {
            "id",
            "account_id",
            "entity_id",
            "match_method",
            "confidence",
            "verification_state",
            "valid_from",
            "valid_to",
            "source",
            "metadata_json",
        }
    ),
}

FIELD_ALIASES: Final[Mapping[str, Mapping[str, str]]] = {
    "accounts": {
        "account_id": "id",
        "acct_id": "id",
        "type": "account_type",
        "state": "status",
    },
    "transactions": {
        "transaction_id": "id",
        "txn_id": "id",
        "from_account_id": "sender_account_id",
        "to_account_id": "receiver_account_id",
        "sender": "sender_account_id",
        "receiver": "receiver_account_id",
        "from": "sender_account_id",
        "to": "receiver_account_id",
        "timestamp": "occurred_at",
        "time": "occurred_at",
        "date": "occurred_at",
        "value": "amount",
        "ccy": "currency",
    },
    "complaints": {
        "complaint_id": "id",
        "filed_at": "reported_at",
        "reported_date": "reported_at",
        "txn_reference": "transaction_reference",
        "transaction_ref": "transaction_reference",
        "suspect_account_id": "suspected_account_id",
        "suspect": "suspected_account_id",
        "victim": "victim_account_id",
    },
    "entities": {
        "entity_id": "id",
        "kind": "entity_type",
        "hashed_identifier": "identifier_hash",
        "hash": "identifier_hash",
    },
    "entity_links": {
        "link_id": "id",
        "account": "account_id",
        "entity": "entity_id",
        "from_account_id": "account_id",
        "to_entity_id": "entity_id",
        "start_at": "valid_from",
        "end_at": "valid_to",
        "method": "match_method",
        "state": "verification_state",
    },
}

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
        "narrative",
        "narrative_normalized",
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

FORBIDDEN_KEY_TOKENS: Final[tuple[str, ...]] = (
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
    "pickle",
    "card_number",
    "pan",
    "cvv",
    "upi_id",
    "phone_number",
    "email_address",
    "ifsc",
    "account_number",
    "narrative",
)

_KNOWN_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "batch_too_large",
        "cell_too_long",
        "duplicate_field_alias",
        "duplicate_json_key",
        "empty_record",
        "empty_source",
        "file_loading_disabled",
        "file_loading_production_blocked",
        "file_not_found",
        "file_read_failed",
        "file_stat_failed",
        "file_too_large",
        "forbidden_column",
        "forbidden_field",
        "invalid_csv",
        "invalid_field_name",
        "invalid_json",
        "invalid_json_line",
        "invalid_path",
        "invalid_payload",
        "invalid_utf8",
        "line_too_long",
        "loader_unexpected_failure",
        "malformed_csv_row",
        "max_records_reached",
        "no_allowed_columns",
        "no_allowed_directories",
        "non_finite_json_constant",
        "path_outside_allowed_directory",
        "payload_too_large",
        "record_not_object",
        "record_source_not_iterable",
        "short_csv_row",
        "symlink_rejected",
        "unsupported_content_type",
        "unsupported_entity_type",
        "unsupported_file_extension",
        "unsupported_payload_shape",
        "unsupported_source_type",
        "unknown_field_dropped",
    }
)

_LOADER_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype ingestion loading only. Do not use with real customer data.",
    "Loaded records are investigative inputs only and are not proof of wrongdoing.",
    "Loading must not trigger automatic adverse customer action.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are rejected or omitted.",
    "Raw complaint narratives are loaded only for controlled synthetic complaint ingestion and are never returned in public summaries.",
    "Entity identifiers must be pseudonymously hashed. Raw identifier fields are rejected or omitted.",
    "Unknown fields are omitted by default to reduce accidental leakage surface.",
    "File loading is disabled by default and restricted to allowed local directories when enabled.",
    "No network, remote URL, pickle, unsafe YAML, or external-entity XML loading is performed.",
    "Loading is deterministic and bounded by configured limits.",
    "This module does not persist data or call external systems.",
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


def _normalize_unicode(value: Any) -> str:
    """
    Normalize Unicode text deterministically.

    Enum members are unwrapped to their value first: for a `str`-mixin enum
    `str(Member)` is "ClassName.MEMBER", not "member", so an enum reaching
    here would normalise to a token nothing recognises.
    """
    if isinstance(value, Enum):
        value = value.value

    return unicodedata.normalize("NFKC", str(value if value is not None else ""))


def _clean_text(value: Any, limit: int = DEFAULT_MAX_STRING_LENGTH) -> str:
    """
    Return a safe single-line text value.
    """
    text = _normalize_unicode(value)
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if limit <= 0:
        return ""

    if len(text) > limit:
        return text[:limit]

    return text


def _canonical_field_name(key: Any) -> str:
    """
    Convert a field name to a conservative canonical snake_case form.
    """
    text = _normalize_unicode(key).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = _SEPARATOR_RE.sub("_", text)
    text = _MULTI_UNDERSCORE_RE.sub("_", text)
    return text.strip("_").lower()


def _normalize_entity_type(value: Any) -> str:
    """
    Normalize an ingestion entity type.
    """
    text = _canonical_field_name(value)

    aliases = {
        "account": "accounts",
        "txn": "transactions",
        "transaction": "transactions",
        "complaint": "complaints",
        "entity": "entities",
        "entity_link": "entity_links",
        "account_entity_link": "entity_links",
        "account_entity_links": "entity_links",
    }

    return aliases.get(text, text)


def _normalize_content_type(value: Any) -> Optional[str]:
    """
    Normalize a content-type-like value.
    """
    text = str(value if value is not None else "").strip().lower()

    aliases = {
        "json": CONTENT_TYPE_JSON,
        "application/json": CONTENT_TYPE_JSON,
        "ndjson": CONTENT_TYPE_NDJSON,
        "jsonl": CONTENT_TYPE_NDJSON,
        "application/x-ndjson": CONTENT_TYPE_NDJSON,
        "csv": CONTENT_TYPE_CSV,
        "text/csv": CONTENT_TYPE_CSV,
        "records": CONTENT_TYPE_RECORDS,
        "application/x-records": CONTENT_TYPE_RECORDS,
    }

    return aliases.get(text)


def _infer_content_type_from_name(value: Any) -> Optional[str]:
    """
    Infer a content type from a safe source name or filename.
    """
    name = _safe_source_name(value)

    if not name:
        return None

    suffix = Path(name).suffix.lower()

    if suffix == ".json":
        return CONTENT_TYPE_JSON

    if suffix in {".ndjson", ".jsonl"}:
        return CONTENT_TYPE_NDJSON

    if suffix == ".csv":
        return CONTENT_TYPE_CSV

    return None


def _safe_source_name(value: Any) -> str:
    """
    Return a safe basename-like source label.

    Full paths are never returned.
    """
    text = _normalize_unicode(value).strip()

    if not text:
        return ""

    text = text.replace("\\", "/")
    text = text.rsplit("/", 1)[-1]
    text = _clean_text(text, MAX_SOURCE_NAME_LENGTH)

    return text


def _is_forbidden_key(canonical: str, target: str, entity_type: str) -> bool:
    """
    Return True when a top-level record key is forbidden.

    Complaint `narrative_raw` is intentionally allowed for controlled synthetic
    complaint ingestion. Other raw fields are forbidden.
    """
    if entity_type == "complaints" and (
        canonical == "narrative_raw" or target == "narrative_raw"
    ):
        return False

    if canonical in FORBIDDEN_TOP_LEVEL_KEYS or target in FORBIDDEN_TOP_LEVEL_KEYS:
        return True

    if canonical.startswith("raw_") or target.startswith("raw_"):
        return True

    if (canonical.endswith("_raw") and canonical != "narrative_raw") or (
        target.endswith("_raw") and target != "narrative_raw"
    ):
        return True

    for token in FORBIDDEN_KEY_TOKENS:
        if token in canonical or token in target:
            return True

    return False


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


def _known_code(exc: BaseException, default: str = "invalid_payload") -> str:
    """
    Extract a stable known error code from an internal exception.
    """
    text = str(exc or "").strip().lower().replace(" ", "_")

    if text in _KNOWN_ERROR_CODES:
        return text

    return default


def _hash_bytes(data: bytes) -> str:
    """
    Return a SHA-256 hex digest for source bytes.
    """
    return hashlib.sha256(data).hexdigest()


def _json_default(value: Any) -> Any:
    """
    JSON serializer fallback for checksum computation.
    """
    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Path):
        return str(value)

    return str(value)


def _records_checksum(records: Sequence[Mapping[str, Any]]) -> Optional[str]:
    """
    Return a deterministic SHA-256 checksum for loaded records.

    The checksum is safe to expose. It does not reveal record contents.
    """
    if not records:
        return None

    try:
        canonical = json.dumps(
            list(records),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=_json_default,
        )
        return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()
    except Exception:
        try:
            fallback = "|".join(
                str(record.get("id") or record.get("reference") or index)
                for index, record in enumerate(records)
            )
            return hashlib.sha256(fallback.encode("utf-8", errors="replace")).hexdigest()
        except Exception:
            return None


def _decode_bytes(data: bytes | bytearray | memoryview) -> str:
    """
    Decode UTF-8 strictly.
    """
    try:
        return bytes(data).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid_utf8") from exc


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    """
    Reject duplicate JSON object keys.
    """
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")

        result[key] = value

    return result


def _reject_non_finite_constant(value: str) -> Any:
    """
    Reject NaN and Infinity JSON constants.
    """
    raise ValueError("non_finite_json_constant")


def _strict_json_loads(data: str | bytes | bytearray | memoryview, max_bytes: int) -> Any:
    """
    Parse JSON strictly and within a bounded size.

    Raises ValueError with stable codes for known failures.
    """
    limit = max(1, int(max_bytes))

    if isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)

        if len(raw) > limit:
            raise ValueError("payload_too_large")

        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid_utf8") from exc
    else:
        text = str(data or "")

        if len(text.encode("utf-8", errors="replace")) > limit:
            raise ValueError("payload_too_large")

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except ValueError as exc:
        code = str(exc or "").strip().lower()

        if code in _KNOWN_ERROR_CODES:
            raise

        raise ValueError("invalid_json") from exc
    except Exception as exc:
        raise ValueError("invalid_json") from exc


def _looks_like_json(text: str) -> bool:
    """
    Conservative heuristic for JSON text.
    """
    stripped = text.lstrip()
    return stripped.startswith(("{", "["))


def _looks_like_ndjson(text: str) -> bool:
    """
    Conservative heuristic for NDJSON text.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()][:20]

    if len(lines) <= 1:
        return False

    return all(line.startswith("{") for line in lines)


def _infer_content_type_from_text(text: str) -> str:
    """
    Infer a content type from text content.
    """
    if _looks_like_json(text):
        return CONTENT_TYPE_JSON

    if _looks_like_ndjson(text):
        return CONTENT_TYPE_NDJSON

    return CONTENT_TYPE_CSV


def _safe_detail_value(value: Any, depth: int = 0) -> Any:
    """
    Convert arbitrary detail values into bounded, safe representations.
    """
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
        return _clean_text(value, 300)

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Enum):
        return _safe_detail_value(value.value, depth + 1)

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:20]:
            key = _clean_text(raw_key, 100)

            if not key:
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:20]]

    return f"<{type(value).__name__}>"


def _safe_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return safe issue details.

    Details must never contain raw narratives, secrets, tokens, passwords,
    database URLs, model artifact paths, or sensitive identifiers.
    """
    if not details:
        return {}

    sanitized = _safe_detail_value(details)

    if isinstance(sanitized, dict):
        return sanitized

    if sanitized is None:
        return {}

    return {"value": sanitized}


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoaderOptions:
    """
    Bounded ingestion loading policy.

    Hard caps prevent client-controlled or configuration-controlled unbounded
    loading surfaces.
    """

    max_records: int = DEFAULT_MAX_RECORDS
    max_errors_returned: int = DEFAULT_MAX_ERRORS_RETURNED
    max_warnings_returned: int = DEFAULT_MAX_WARNINGS_RETURNED

    max_bytes: int = DEFAULT_MAX_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_cell_bytes: int = DEFAULT_MAX_CELL_BYTES
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH

    content_type: Optional[str] = None
    source_name: Optional[str] = None
    source_system: Optional[str] = None

    drop_unknown_fields: bool = True
    reject_forbidden_fields: bool = True
    compute_checksum: bool = True

    file_loading_enabled: bool = False
    allow_file_in_production: bool = False
    production_like: bool = False
    allowed_dirs: tuple[str, ...] = dataclass_field(default_factory=tuple)

    def __post_init__(self) -> None:
        """
        Normalize and clamp option values.
        """
        object.__setattr__(
            self,
            "max_records",
            _clamp_int(
                self.max_records,
                1,
                HARD_MAX_RECORDS,
                DEFAULT_MAX_RECORDS,
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
            "max_bytes",
            _clamp_int(
                self.max_bytes,
                1024,
                HARD_MAX_BYTES,
                DEFAULT_MAX_BYTES,
            ),
        )

        object.__setattr__(
            self,
            "max_file_bytes",
            _clamp_int(
                self.max_file_bytes,
                1024,
                HARD_MAX_FILE_BYTES,
                DEFAULT_MAX_FILE_BYTES,
            ),
        )

        object.__setattr__(
            self,
            "max_line_bytes",
            _clamp_int(
                self.max_line_bytes,
                1024,
                HARD_MAX_LINE_BYTES,
                DEFAULT_MAX_LINE_BYTES,
            ),
        )

        object.__setattr__(
            self,
            "max_cell_bytes",
            _clamp_int(
                self.max_cell_bytes,
                1024,
                HARD_MAX_CELL_BYTES,
                DEFAULT_MAX_CELL_BYTES,
            ),
        )

        object.__setattr__(
            self,
            "max_string_length",
            _clamp_int(
                self.max_string_length,
                1,
                HARD_MAX_STRING_LENGTH,
                DEFAULT_MAX_STRING_LENGTH,
            ),
        )

        object.__setattr__(
            self,
            "content_type",
            _normalize_content_type(self.content_type),
        )

        if self.source_name is not None:
            object.__setattr__(
                self,
                "source_name",
                _safe_source_name(self.source_name) or None,
            )

        if self.source_system is not None:
            object.__setattr__(
                self,
                "source_system",
                _clean_text(self.source_system, 100) or None,
            )

        object.__setattr__(
            self,
            "drop_unknown_fields",
            _as_bool(self.drop_unknown_fields, True),
        )

        object.__setattr__(
            self,
            "reject_forbidden_fields",
            _as_bool(self.reject_forbidden_fields, True),
        )

        object.__setattr__(
            self,
            "compute_checksum",
            _as_bool(self.compute_checksum, True),
        )

        object.__setattr__(
            self,
            "file_loading_enabled",
            _as_bool(self.file_loading_enabled, False),
        )

        object.__setattr__(
            self,
            "allow_file_in_production",
            _as_bool(self.allow_file_in_production, False),
        )

        object.__setattr__(
            self,
            "production_like",
            _as_bool(self.production_like, False),
        )

        if not isinstance(self.allowed_dirs, tuple):
            object.__setattr__(
                self,
                "allowed_dirs",
                tuple(
                    _clean_text(item, 512)
                    for item in (self.allowed_dirs or ())
                    if _clean_text(item, 512)
                ),
            )

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "LoaderOptions":
        """
        Build loading options from runtime settings with safe defaults.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        hard_max_records = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_RECORDS", HARD_MAX_RECORDS),
            1,
            HARD_MAX_RECORDS,
            HARD_MAX_RECORDS,
        )

        max_records = _clamp_int(
            _setting(settings, "INGESTION_MAX_RECORDS", DEFAULT_MAX_RECORDS),
            1,
            hard_max_records,
            DEFAULT_MAX_RECORDS,
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

        hard_max_bytes = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_JSON_BYTES", HARD_MAX_BYTES),
            1024,
            HARD_MAX_BYTES,
            HARD_MAX_BYTES,
        )

        max_bytes = _clamp_int(
            _setting(settings, "INGESTION_MAX_JSON_BYTES", DEFAULT_MAX_BYTES),
            1024,
            hard_max_bytes,
            DEFAULT_MAX_BYTES,
        )

        hard_max_file_bytes = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_FILE_BYTES", HARD_MAX_FILE_BYTES),
            1024,
            HARD_MAX_FILE_BYTES,
            HARD_MAX_FILE_BYTES,
        )

        max_file_bytes = _clamp_int(
            _setting(settings, "INGESTION_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES),
            1024,
            hard_max_file_bytes,
            DEFAULT_MAX_FILE_BYTES,
        )

        hard_max_line_bytes = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_LINE_BYTES", HARD_MAX_LINE_BYTES),
            1024,
            HARD_MAX_LINE_BYTES,
            HARD_MAX_LINE_BYTES,
        )

        max_line_bytes = _clamp_int(
            _setting(settings, "INGESTION_MAX_LINE_BYTES", DEFAULT_MAX_LINE_BYTES),
            1024,
            hard_max_line_bytes,
            DEFAULT_MAX_LINE_BYTES,
        )

        hard_max_cell_bytes = _clamp_int(
            _setting(settings, "INGESTION_HARD_MAX_CELL_BYTES", HARD_MAX_CELL_BYTES),
            1024,
            HARD_MAX_CELL_BYTES,
            HARD_MAX_CELL_BYTES,
        )

        max_cell_bytes = _clamp_int(
            _setting(settings, "INGESTION_MAX_CELL_BYTES", DEFAULT_MAX_CELL_BYTES),
            1024,
            hard_max_cell_bytes,
            DEFAULT_MAX_CELL_BYTES,
        )

        allowed_dirs_raw = _csv(
            _setting(
                settings,
                "INGESTION_ALLOWED_LOAD_DIRS",
                "var/ingestion,var/tmp",
            )
        )

        return cls(
            max_records=max_records,
            max_errors_returned=max_errors,
            max_warnings_returned=max(
                1,
                min(
                    max_errors // 2 or DEFAULT_MAX_WARNINGS_RETURNED,
                    HARD_MAX_WARNINGS_RETURNED,
                ),
            ),
            max_bytes=max_bytes,
            max_file_bytes=max_file_bytes,
            max_line_bytes=max_line_bytes,
            max_cell_bytes=max_cell_bytes,
            max_string_length=_clamp_int(
                _setting(settings, "INGESTION_MAX_STRING_LENGTH", DEFAULT_MAX_STRING_LENGTH),
                1,
                HARD_MAX_STRING_LENGTH,
                DEFAULT_MAX_STRING_LENGTH,
            ),
            content_type=_normalize_content_type(
                _setting(settings, "INGESTION_LOAD_CONTENT_TYPE", None)
            ),
            source_name=_safe_source_name(
                _setting(settings, "INGESTION_LOAD_SOURCE_NAME", None)
            )
            or None,
            source_system=_clean_text(
                _setting(settings, "INGESTION_SOURCE_SYSTEM", "api"),
                100,
            )
            or "api",
            drop_unknown_fields=_as_bool(
                _setting(settings, "INGESTION_LOAD_DROP_UNKNOWN_FIELDS", True),
                True,
            ),
            reject_forbidden_fields=_as_bool(
                _setting(settings, "INGESTION_LOAD_REJECT_FORBIDDEN_FIELDS", True),
                True,
            ),
            compute_checksum=_as_bool(
                _setting(settings, "INGESTION_LOAD_COMPUTE_CHECKSUM", True),
                True,
            ),
            file_loading_enabled=_as_bool(
                _setting(settings, "INGESTION_FILE_LOADING_ENABLED", False),
                False,
            ),
            allow_file_in_production=_as_bool(
                _setting(settings, "INGESTION_ALLOW_FILE_IN_PRODUCTION", False),
                False,
            ),
            production_like=_is_production_like_settings(settings),
            allowed_dirs=tuple(allowed_dirs_raw),
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable summary of loading options.

        Full allowed directories are not exposed. Only a count is returned.
        """
        return {
            "max_records": self.max_records,
            "max_errors_returned": self.max_errors_returned,
            "max_warnings_returned": self.max_warnings_returned,
            "max_bytes": self.max_bytes,
            "max_file_bytes": self.max_file_bytes,
            "max_line_bytes": self.max_line_bytes,
            "max_cell_bytes": self.max_cell_bytes,
            "max_string_length": self.max_string_length,
            "content_type": self.content_type,
            "source_name": self.source_name,
            "source_system": self.source_system,
            "drop_unknown_fields": self.drop_unknown_fields,
            "reject_forbidden_fields": self.reject_forbidden_fields,
            "compute_checksum": self.compute_checksum,
            "file_loading_enabled": self.file_loading_enabled,
            "allow_file_in_production": self.allow_file_in_production,
            "production_like": self.production_like,
            "allowed_directory_count": len(self.allowed_dirs),
        }


# -----------------------------------------------------------------------------
# Issue and result models
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class LoadIssue:
    """
    Safe loading issue.

    Issues never contain raw narratives, secrets, tokens, passwords, database
    URLs, model artifact paths, or sensitive identifiers.
    """

    severity: str
    code: str
    message: str
    entity_type: str = ""
    index: Optional[int] = None
    field: Optional[str] = None
    details: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable issue mapping.
        """
        payload: dict[str, Any] = {
            "severity": _clean_text(self.severity, 20),
            "code": _clean_text(self.code, 100),
            "message": _clean_text(self.message, 300),
        }

        if self.entity_type:
            payload["entity_type"] = _clean_text(self.entity_type, 100)

        if self.index is not None:
            payload["index"] = int(self.index)

        if self.field:
            payload["field"] = _clean_text(self.field, 200)

        if self.details:
            payload["details"] = self.details

        return payload


@dataclass(slots=True)
class LoadResult:
    """
    Safe ingestion loading result.

    The `records` list may contain complaint narrative text for downstream
    normalization and validation. Public summaries deliberately exclude records.
    """

    ok: bool = True
    entity_type: str = ""
    source_type: str = ""
    content_type: str = ""
    source_name: Optional[str] = None

    submitted: int = 0
    records: list[dict[str, Any]] = dataclass_field(default_factory=list)
    rejected: list[int] = dataclass_field(default_factory=list)
    issues: list[LoadIssue] = dataclass_field(default_factory=list)
    metadata: dict[str, Any] = dataclass_field(default_factory=dict)

    bytes_processed: int = 0
    checksum: Optional[str] = None
    truncated: bool = False

    max_errors: int = DEFAULT_MAX_ERRORS_RETURNED
    max_warnings: int = DEFAULT_MAX_WARNINGS_RETURNED

    _error_count: int = dataclass_field(default=0, repr=False)
    _warning_count: int = dataclass_field(default=0, repr=False)
    _error_truncated: bool = dataclass_field(default=False, repr=False)
    _warning_truncated: bool = dataclass_field(default=False, repr=False)

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

        entry = LoadIssue(
            severity="error",
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            entity_type=_clean_text(self.entity_type, 100),
            index=int(index) if index is not None else None,
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )

        self.issues.append(entry)
        self._error_count += 1
        self.ok = False

        if self._error_count >= max(1, int(self.max_errors)):
            self._error_truncated = True
            self.issues.append(
                LoadIssue(
                    severity="error",
                    code="error_list_truncated",
                    message="Error list truncated by configured limit.",
                    entity_type=_clean_text(self.entity_type, 100),
                )
            )

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

        entry = LoadIssue(
            severity="warning",
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            entity_type=_clean_text(self.entity_type, 100),
            index=int(index) if index is not None else None,
            field=_clean_text(field, 200) if field else None,
            details=_safe_details(details),
        )

        self.issues.append(entry)
        self._warning_count += 1

        if self._warning_count >= max(1, int(self.max_warnings)):
            self._warning_truncated = True
            self.issues.append(
                LoadIssue(
                    severity="warning",
                    code="warning_list_truncated",
                    message="Warning list truncated by configured limit.",
                    entity_type=_clean_text(self.entity_type, 100),
                )
            )

        return True

    def finalize(self, options: LoaderOptions) -> None:
        """
        Finalize safe metadata and optional checksum.
        """
        if options.compute_checksum and not self.checksum and self.records:
            self.checksum = _records_checksum(self.records)

        source_system = self.metadata.get("source_system") or options.source_system

        self.metadata.update(
            {
                "loader_version": LOADERS_VERSION,
                "entity_type": self.entity_type,
                "source_type": self.source_type,
                "content_type": self.content_type,
                "source_name": self.source_name,
                "source_system": source_system,
                "submitted": self.submitted,
                "loaded_count": len(self.records),
                "rejected_count": len(self.rejected),
                "error_count": self._error_count,
                "warning_count": self._warning_count,
                "error_truncated": self._error_truncated,
                "warning_truncated": self._warning_truncated,
                "truncated": self.truncated,
                "bytes_processed": self.bytes_processed,
                "checksum_algorithm": "sha256" if self.checksum else None,
                "max_records": options.max_records,
                "max_bytes": options.max_bytes,
                "max_line_bytes": options.max_line_bytes,
                "max_cell_bytes": options.max_cell_bytes,
                "drop_unknown_fields": options.drop_unknown_fields,
                "reject_forbidden_fields": options.reject_forbidden_fields,
            }
        )

    def to_response_dict(self) -> dict[str, Any]:
        """
        Return a safe API-facing summary.

        This deliberately does not include loaded records, raw narratives,
        identifier hashes, or sensitive values.
        """
        return {
            "ok": self.ok,
            "entity_type": self.entity_type,
            "source_type": self.source_type,
            "content_type": self.content_type,
            "source_name": self.source_name,
            "counts": {
                "submitted": self.submitted,
                "loaded": len(self.records),
                "rejected": len(self.rejected),
                "errors": self._error_count,
                "warnings": self._warning_count,
            },
            "bytes_processed": self.bytes_processed,
            "checksum": self.checksum,
            "truncated": self.truncated,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
            "caveats": list(_LOADER_CAVEATS),
        }


# -----------------------------------------------------------------------------
# Internal record filtering
# -----------------------------------------------------------------------------


def _filter_record(
    entity_type: str,
    raw_record: Any,
    options: LoaderOptions,
    result: LoadResult,
    index: int,
    line: Optional[int] = None,
) -> Optional[dict[str, Any]]:
    """
    Filter and canonicalize one raw record.

    Returns None when the record should not be passed downstream.
    """
    if not isinstance(raw_record, Mapping):
        result.add_error(
            code="record_not_object",
            message="Record must be a JSON object.",
            index=index,
            details={"line": line} if line is not None else None,
        )
        return None

    aliases = FIELD_ALIASES.get(entity_type, {})
    allowed = ALLOWED_FIELDS.get(entity_type, frozenset())
    out: dict[str, Any] = {}
    forbidden_found = False

    for raw_key, raw_value in raw_record.items():
        key_text = _clean_text(raw_key, MAX_FIELD_NAME_LENGTH)

        if not key_text:
            result.add_warning(
                code="invalid_field_name",
                message="Field name was empty and omitted.",
                index=index,
                details={"line": line} if line is not None else None,
            )
            continue

        canonical = _canonical_field_name(key_text)

        if not canonical:
            result.add_warning(
                code="invalid_field_name",
                message="Field name could not be canonicalized and was omitted.",
                index=index,
                field=key_text,
                details={"line": line} if line is not None else None,
            )
            continue

        target = aliases.get(canonical, canonical)

        if _is_forbidden_key(canonical, target, entity_type):
            forbidden_found = True
            details = {"line": line} if line is not None else None

            if options.reject_forbidden_fields:
                result.add_error(
                    code="forbidden_field",
                    message="Forbidden field omitted.",
                    index=index,
                    field=key_text,
                    details=details,
                )
            else:
                result.add_warning(
                    code="forbidden_field",
                    message="Forbidden field omitted.",
                    index=index,
                    field=key_text,
                    details=details,
                )

            continue

        if target in allowed:
            if target in out:
                result.add_warning(
                    code="duplicate_field_alias",
                    message="Duplicate field alias omitted.",
                    index=index,
                    field=key_text,
                    details={"line": line} if line is not None else None,
                )
                continue

            out[target] = raw_value
            continue

        if options.drop_unknown_fields:
            result.add_warning(
                code="unknown_field_dropped",
                message="Unknown field omitted.",
                index=index,
                field=key_text,
                details={"line": line} if line is not None else None,
            )
            continue

        out[canonical] = raw_value

    if forbidden_found and options.reject_forbidden_fields:
        return None

    if not out:
        result.add_error(
            code="empty_record",
            message="Record normalized to an empty object.",
            index=index,
            details={"line": line} if line is not None else None,
        )
        return None

    return out


def _append_loaded_record(
    entity_type: str,
    raw_record: Any,
    options: LoaderOptions,
    result: LoadResult,
    index: int,
    line: Optional[int] = None,
) -> bool:
    """
    Filter one record and append it to the result when safe.
    """
    record = _filter_record(
        entity_type,
        raw_record,
        options,
        result,
        index,
        line=line,
    )

    if record is None:
        result.rejected.append(index)
        return False

    result.records.append(record)
    return True


def _reject_candidate(
    result: LoadResult,
    index: int,
    code: str,
    message: str,
    *,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Record one rejected candidate.
    """
    result.add_error(
        code=code,
        message=message,
        index=index,
        field=field,
        details=details,
    )
    result.rejected.append(index)


# -----------------------------------------------------------------------------
# Record source helpers
# -----------------------------------------------------------------------------


def _coerce_records_input(source: Any) -> tuple[Any, Optional[Mapping[str, Any]]]:
    """
    Coerce a record source into an iterable of raw records.

    Supports:

    - a single mapping record;
    - a payload wrapper mapping with `records` or `items`;
    - any non-string iterable of records.

    Returns `(records, payload_options)`.
    """
    if isinstance(source, Mapping):
        if "records" in source:
            return source.get("records"), source.get("options")

        if "items" in source:
            return source.get("items"), source.get("options")

        return source, None

    if isinstance(source, (str, bytes, bytearray, memoryview)):
        raise ValueError("record_source_not_iterable")

    if isinstance(source, Iterable):
        return source, None

    raise ValueError("record_source_not_iterable")


def _iter_record_items(source: Any, limit: int) -> Iterator[tuple[int, Any]]:
    """
    Iterate bounded record items.

    Yields `(index, record)` pairs. If more items exist after `limit`, yields
    `(limit, _MORE_SENTINEL)`.
    """
    if isinstance(source, Mapping):
        yield 0, source
        return

    if isinstance(source, (str, bytes, bytearray, memoryview)):
        raise ValueError("record_source_not_iterable")

    try:
        iterator = iter(source)
    except TypeError as exc:
        raise ValueError("record_source_not_iterable") from exc

    safe_limit = max(0, int(limit))

    for index in range(safe_limit):
        try:
            item = next(iterator)
        except StopIteration:
            return

        yield index, item

    try:
        next(iterator)
    except StopIteration:
        return

    yield safe_limit, _MORE_SENTINEL


def _apply_payload_overrides(
    options: LoaderOptions,
    overrides: Optional[Mapping[str, Any]],
) -> LoaderOptions:
    """
    Apply only safe payload-level overrides.

    Clients must not be able to raise hard limits.
    """
    if not isinstance(overrides, Mapping):
        return options

    updates: dict[str, Any] = {}

    if "source_system" in overrides:
        source_system = _clean_text(overrides["source_system"], 100)

        if source_system:
            updates["source_system"] = source_system

    if "content_type" in overrides and options.content_type is None:
        content_type = _normalize_content_type(overrides["content_type"])

        if content_type:
            updates["content_type"] = content_type

    if not updates:
        return options

    return replace(options, **updates)


def _load_from_records_source(
    entity_type: str,
    records: Any,
    options: LoaderOptions,
    result: LoadResult,
    overrides: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Load records from an in-memory or already-parsed record source.
    """
    effective_options = _apply_payload_overrides(options, overrides)

    if not result.source_type:
        result.source_type = SOURCE_TYPE_RECORDS

    if overrides:
        if "source_system" in overrides:
            result.metadata["source_system"] = effective_options.source_system

        if "content_type" in overrides:
            result.content_type = effective_options.content_type or result.content_type

    try:
        item_iterator = _iter_record_items(records, effective_options.max_records)
    except ValueError as exc:
        _reject_candidate(
            result,
            index=0,
            code=_known_code(exc, "record_source_not_iterable"),
            message="Record source is not iterable.",
        )
        return

    for index, raw_record in item_iterator:
        if raw_record is _MORE_SENTINEL:
            result.truncated = True
            result.add_warning(
                code="max_records_reached",
                message="Record limit reached. Remaining records were not loaded.",
                details={"max_records": effective_options.max_records},
            )
            break

        result.submitted += 1
        _append_loaded_record(
            entity_type,
            raw_record,
            effective_options,
            result,
            index,
        )


# -----------------------------------------------------------------------------
# JSON loading
# -----------------------------------------------------------------------------


def _load_from_json_data(
    entity_type: str,
    data: str | bytes | bytearray | memoryview,
    options: LoaderOptions,
    result: LoadResult,
) -> None:
    """
    Load records from a strict JSON payload.
    """
    try:
        parsed = _strict_json_loads(data, options.max_bytes)
    except ValueError as exc:
        _reject_candidate(
            result,
            index=0,
            code=_known_code(exc, "invalid_json"),
            message="JSON payload could not be parsed.",
        )
        return

    try:
        records, overrides = _coerce_records_input(parsed)
    except ValueError as exc:
        _reject_candidate(
            result,
            index=0,
            code=_known_code(exc, "unsupported_payload_shape"),
            message="JSON payload shape is not supported.",
        )
        return

    _load_from_records_source(
        entity_type,
        records,
        options,
        result,
        overrides=overrides,
    )


# -----------------------------------------------------------------------------
# NDJSON loading
# -----------------------------------------------------------------------------


def _load_from_ndjson_text(
    entity_type: str,
    text: str,
    options: LoaderOptions,
    result: LoadResult,
) -> None:
    """
    Load records from newline-delimited JSON text.
    """
    if not text.strip():
        result.add_error(
            code="empty_source",
            message="NDJSON source is empty.",
        )
        return

    record_index = 0

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()

        if not line:
            continue

        if record_index >= options.max_records:
            result.truncated = True
            result.add_warning(
                code="max_records_reached",
                message="Record limit reached. Remaining records were not loaded.",
                details={"max_records": options.max_records, "line": line_no},
            )
            break

        line_bytes = len(line.encode("utf-8", errors="replace"))

        if line_bytes > options.max_line_bytes:
            result.submitted += 1
            _reject_candidate(
                result,
                index=record_index,
                code="line_too_long",
                message="NDJSON line exceeds configured byte limit.",
                details={"line": line_no, "max_line_bytes": options.max_line_bytes},
            )
            record_index += 1
            continue

        try:
            parsed = _strict_json_loads(line, options.max_line_bytes)
        except ValueError as exc:
            result.submitted += 1
            _reject_candidate(
                result,
                index=record_index,
                code=_known_code(exc, "invalid_json_line"),
                message="NDJSON line could not be parsed.",
                details={"line": line_no},
            )
            record_index += 1
            continue

        if not isinstance(parsed, Mapping):
            result.submitted += 1
            _reject_candidate(
                result,
                index=record_index,
                code="record_not_object",
                message="NDJSON line must contain a JSON object.",
                details={"line": line_no},
            )
            record_index += 1
            continue

        result.submitted += 1
        _append_loaded_record(
            entity_type,
            parsed,
            options,
            result,
            record_index,
            line=line_no,
        )
        record_index += 1


# -----------------------------------------------------------------------------
# CSV loading
# -----------------------------------------------------------------------------


def _csv_cell_byte_length(value: Any) -> int:
    """
    Return bounded byte length for a CSV cell.
    """
    text = str(value if value is not None else "")
    return len(text.encode("utf-8", errors="replace"))


def _load_from_csv_text(
    entity_type: str,
    text: str,
    options: LoaderOptions,
    result: LoadResult,
) -> None:
    """
    Load records from CSV text.
    """
    if not text.strip():
        result.add_error(
            code="empty_source",
            message="CSV source is empty.",
        )
        return

    aliases = FIELD_ALIASES.get(entity_type, {})
    allowed = ALLOWED_FIELDS.get(entity_type, frozenset())

    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(reader)
    except StopIteration:
        result.add_error(
            code="empty_source",
            message="CSV source has no header row.",
        )
        return
    except csv.Error as exc:
        _reject_candidate(
            result,
            index=0,
            code="invalid_csv",
            message="CSV header could not be parsed.",
            details={"reason": type(exc).__name__},
        )
        return

    columns: list[Optional[str]] = []
    seen_targets: set[str] = set()
    forbidden_columns: list[str] = []

    for raw_header in header:
        key_text = _clean_text(raw_header, MAX_FIELD_NAME_LENGTH)
        canonical = _canonical_field_name(key_text)
        target = aliases.get(canonical, canonical) if canonical else ""

        if canonical and _is_forbidden_key(canonical, target, entity_type):
            forbidden_columns.append(key_text or canonical)
            columns.append(None)
            continue

        if target in allowed and target not in seen_targets:
            columns.append(target)
            seen_targets.add(target)
            continue

        columns.append(None)

        if key_text:
            result.add_warning(
                code="unknown_field_dropped",
                message="Unknown CSV column omitted.",
                field=key_text,
            )

    if forbidden_columns and options.reject_forbidden_fields:
        result.add_error(
            code="forbidden_column",
            message="CSV contains forbidden columns.",
            details={"columns": forbidden_columns[:20]},
        )
        return

    if forbidden_columns:
        result.add_warning(
            code="forbidden_column",
            message="CSV contains forbidden columns that were omitted.",
            details={"columns": forbidden_columns[:20]},
        )

    if not seen_targets:
        result.add_error(
            code="no_allowed_columns",
            message="CSV contains no allowed columns for this entity type.",
        )
        return

    record_index = 0

    for row_no, row in enumerate(reader, start=2):
        if record_index >= options.max_records:
            result.truncated = True
            result.add_warning(
                code="max_records_reached",
                message="Record limit reached. Remaining records were not loaded.",
                details={"max_records": options.max_records, "line": row_no},
            )
            break

        result.submitted += 1

        if len(row) < len(header):
            result.add_warning(
                code="short_csv_row",
                message="CSV row had fewer fields than the header and was padded.",
                index=record_index,
                details={"line": row_no},
            )
            row = [*row, *[""] * (len(header) - len(row))]

        if len(row) > len(header):
            _reject_candidate(
                result,
                index=record_index,
                code="malformed_csv_row",
                message="CSV row had more fields than the header.",
                details={"line": row_no},
            )
            record_index += 1
            continue

        raw_record: dict[str, Any] = {}
        cell_too_long = False

        for position, value in enumerate(row):
            target = columns[position]

            if target is None:
                continue

            if value is None:
                continue

            if _csv_cell_byte_length(value) > options.max_cell_bytes:
                cell_too_long = True
                break

            text_value = str(value).strip()

            if not text_value:
                continue

            raw_record[target] = text_value

        if cell_too_long:
            _reject_candidate(
                result,
                index=record_index,
                code="cell_too_long",
                message="CSV cell exceeds configured byte limit.",
                details={"line": row_no, "max_cell_bytes": options.max_cell_bytes},
            )
            record_index += 1
            continue

        _append_loaded_record(
            entity_type,
            raw_record,
            options,
            result,
            record_index,
            line=row_no,
        )
        record_index += 1


# -----------------------------------------------------------------------------
# Text and bytes dispatch
# -----------------------------------------------------------------------------


def _dispatch_text_source(
    entity_type: str,
    text: str,
    options: LoaderOptions,
    result: LoadResult,
) -> None:
    """
    Dispatch decoded text to the appropriate parser.
    """
    content_type = result.content_type or options.content_type

    if not content_type:
        content_type = _infer_content_type_from_name(options.source_name)

    if not content_type:
        content_type = _infer_content_type_from_text(text)

    result.content_type = content_type

    if content_type == CONTENT_TYPE_JSON:
        _load_from_json_data(entity_type, text, options, result)
        return

    if content_type == CONTENT_TYPE_NDJSON:
        _load_from_ndjson_text(entity_type, text, options, result)
        return

    if content_type == CONTENT_TYPE_CSV:
        _load_from_csv_text(entity_type, text, options, result)
        return

    result.add_error(
        code="unsupported_content_type",
        message="Unsupported content type for text source.",
        details={"content_type": content_type},
    )


def _load_from_bytes_source(
    entity_type: str,
    data: bytes | bytearray | memoryview,
    options: LoaderOptions,
    result: LoadResult,
    content_type: Optional[str] = None,
) -> None:
    """
    Load records from bounded bytes.
    """
    raw = bytes(data)

    if not result.source_type:
        result.source_type = SOURCE_TYPE_BYTES

    if len(raw) > options.max_bytes:
        result.add_error(
            code="payload_too_large",
            message="Byte source exceeds configured byte limit.",
            details={"max_bytes": options.max_bytes, "actual_bytes": len(raw)},
        )
        return

    if not result.bytes_processed:
        result.bytes_processed = len(raw)

    if options.compute_checksum and not result.checksum:
        result.checksum = _hash_bytes(raw)

    try:
        text = _decode_bytes(raw)
    except ValueError as exc:
        result.add_error(
            code=_known_code(exc, "invalid_utf8"),
            message="Byte source is not valid UTF-8.",
        )
        return

    resolved_content_type = (
        _normalize_content_type(content_type)
        or _normalize_content_type(options.content_type)
        or _infer_content_type_from_name(options.source_name)
    )

    if resolved_content_type:
        result.content_type = resolved_content_type

    _dispatch_text_source(entity_type, text, options, result)


def _load_from_text_source(
    entity_type: str,
    text: str,
    options: LoaderOptions,
    result: LoadResult,
    content_type: Optional[str] = None,
) -> None:
    """
    Load records from bounded text.
    """
    if not result.source_type:
        result.source_type = SOURCE_TYPE_TEXT

    encoded_length = len(text.encode("utf-8", errors="replace"))

    if not result.bytes_processed:
        result.bytes_processed = encoded_length

    if encoded_length > options.max_bytes:
        result.add_error(
            code="payload_too_large",
            message="Text source exceeds configured byte limit.",
            details={"max_bytes": options.max_bytes, "actual_bytes": encoded_length},
        )
        return

    resolved_content_type = (
        _normalize_content_type(content_type)
        or _normalize_content_type(options.content_type)
        or _infer_content_type_from_name(options.source_name)
    )

    if resolved_content_type:
        result.content_type = resolved_content_type

    _dispatch_text_source(entity_type, text, options, result)


# -----------------------------------------------------------------------------
# Filesystem safety helpers
# -----------------------------------------------------------------------------


def _resolve_allowed_dirs(options: LoaderOptions) -> tuple[Path, ...]:
    """
    Resolve allowed local directories.

    Non-existent or non-directory paths are skipped.
    """
    bases: list[Path] = []

    candidates = options.allowed_dirs or ("var/ingestion", "var/tmp")

    for raw in candidates:
        text = _clean_text(raw, 512)

        if not text:
            continue

        try:
            base = Path(text).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            continue

        try:
            if base.is_dir():
                bases.append(base)
        except OSError:
            continue

    return tuple(bases)


def _is_within_directory(base: Path, candidate: Path) -> bool:
    """
    Return True when a resolved candidate path stays inside a resolved base
    directory.
    """
    try:
        candidate.relative_to(base)
        return True
    except ValueError:
        return False


def _read_limited_file(path: Path, max_bytes: int) -> bytes:
    """
    Read a file with a hard byte limit.
    """
    limit = max(1, int(max_bytes))

    with path.open("rb") as handle:
        data = handle.read(limit + 1)

    if len(data) > limit:
        raise ValueError("file_too_large")

    return data


def _load_from_file_source(
    entity_type: str,
    path: Any,
    options: LoaderOptions,
    result: LoadResult,
) -> None:
    """
    Load records from an explicitly allowed local file.

    File loading is disabled by default and blocked in production-like
    environments unless explicitly allowed.
    """
    result.source_type = SOURCE_TYPE_FILE

    if not options.file_loading_enabled:
        result.add_error(
            code="file_loading_disabled",
            message="File loading is disabled by configuration.",
        )
        return

    if options.production_like and not options.allow_file_in_production:
        result.add_error(
            code="file_loading_production_blocked",
            message="File loading is blocked in production-like environments.",
        )
        return

    try:
        original_path = Path(path)
    except Exception:
        result.add_error(
            code="invalid_path",
            message="File path is invalid.",
        )
        return

    try:
        if original_path.is_symlink():
            result.add_error(
                code="symlink_rejected",
                message="Symbolic links are rejected for file loading.",
            )
            return
    except OSError:
        result.add_error(
            code="invalid_path",
            message="File path could not be inspected.",
        )
        return

    try:
        resolved_path = original_path.expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        result.add_error(
            code="invalid_path",
            message="File path could not be resolved.",
        )
        return

    result.source_name = _safe_source_name(resolved_path.name)

    suffix = resolved_path.suffix.lower()

    if suffix not in ALLOWED_FILE_EXTENSIONS:
        result.add_error(
            code="unsupported_file_extension",
            message="File extension is not allowed for ingestion loading.",
            details={"allowed_extensions": sorted(ALLOWED_FILE_EXTENSIONS)},
        )
        return

    try:
        if not resolved_path.is_file():
            result.add_error(
                code="file_not_found",
                message="File does not exist or is not a regular file.",
            )
            return
    except OSError:
        result.add_error(
            code="file_not_found",
            message="File could not be inspected.",
        )
        return

    allowed_bases = _resolve_allowed_dirs(options)

    if not allowed_bases:
        result.add_error(
            code="no_allowed_directories",
            message="No allowed local directories are configured for file loading.",
        )
        return

    if not any(_is_within_directory(base, resolved_path) for base in allowed_bases):
        result.add_error(
            code="path_outside_allowed_directory",
            message="File path is outside allowed local directories.",
        )
        return

    try:
        stat_result = resolved_path.stat()
    except OSError:
        result.add_error(
            code="file_stat_failed",
            message="File metadata could not be read.",
        )
        return

    if int(stat_result.st_size) > options.max_file_bytes:
        result.add_error(
            code="file_too_large",
            message="File exceeds configured byte limit.",
            details={
                "max_file_bytes": options.max_file_bytes,
                "actual_bytes": int(stat_result.st_size),
            },
        )
        return

    try:
        data = _read_limited_file(resolved_path, options.max_file_bytes)
    except ValueError as exc:
        result.add_error(
            code=_known_code(exc, "file_too_large"),
            message="File exceeds configured byte limit.",
        )
        return
    except OSError:
        result.add_error(
            code="file_read_failed",
            message="File could not be read.",
        )
        return

    result.bytes_processed = len(data)

    if options.compute_checksum:
        result.checksum = _hash_bytes(data)

    content_type = (
        _normalize_content_type(options.content_type)
        or _infer_content_type_from_name(resolved_path.name)
        or CONTENT_TYPE_JSON
    )

    result.content_type = content_type

    file_options = replace(options, max_bytes=options.max_file_bytes)

    _load_from_bytes_source(
        entity_type,
        data,
        file_options,
        result,
        content_type=content_type,
    )


# -----------------------------------------------------------------------------
# Core loader
# -----------------------------------------------------------------------------


def _load_core(
    entity_type: str,
    source: Any,
    options: LoaderOptions | None = None,
    forced_content_type: Optional[str] = None,
    source_type: Optional[str] = None,
) -> LoadResult:
    """
    Core bounded loader.
    """
    opts = options or LoaderOptions.from_settings()
    normalized_type = _normalize_entity_type(entity_type)

    result = LoadResult(
        entity_type=normalized_type,
        source_type=source_type or "",
        content_type=_normalize_content_type(forced_content_type)
        or _normalize_content_type(opts.content_type)
        or "",
        source_name=opts.source_name,
        max_errors=opts.max_errors_returned,
        max_warnings=opts.max_warnings_returned,
    )

    if normalized_type not in ALLOWED_FIELDS:
        result.add_error(
            code="unsupported_entity_type",
            message="Unsupported ingestion entity type.",
            details={"allowed_entity_types": list(SUPPORTED_INGESTION_ENTITY_TYPES)},
        )
        result.finalize(opts)
        return result

    try:
        if isinstance(source, PathLike):
            _load_from_file_source(normalized_type, source, opts, result)

        elif isinstance(source, (bytes, bytearray, memoryview)):
            _load_from_bytes_source(
                normalized_type,
                source,
                opts,
                result,
                content_type=forced_content_type,
            )

        elif isinstance(source, str):
            _load_from_text_source(
                normalized_type,
                source,
                opts,
                result,
                content_type=forced_content_type,
            )

        else:
            try:
                records, overrides = _coerce_records_input(source)
            except ValueError as exc:
                result.add_error(
                    code=_known_code(exc, "unsupported_source_type"),
                    message="Unsupported record source type.",
                )
            else:
                _load_from_records_source(
                    normalized_type,
                    records,
                    opts,
                    result,
                    overrides=overrides,
                )

    except Exception as exc:
        result.add_error(
            code="loader_unexpected_failure",
            message="Loading failed unexpectedly.",
            details={"exception_type": type(exc).__name__},
        )
        logger.debug(
            "Ingestion loader unexpected failure: %s",
            type(exc).__name__,
            exc_info=True,
        )

    result.finalize(opts)
    return result


# -----------------------------------------------------------------------------
# Public loading API
# -----------------------------------------------------------------------------


def load_ingestion_records(
    entity_type: str,
    records: Any,
    options: LoaderOptions | None = None,
) -> LoadResult:
    """
    Load bounded ingestion records from in-memory structures.

    Supported inputs:

    - a single mapping record;
    - a payload wrapper mapping with `records` or `items`;
    - any non-string iterable of mappings.
    """
    return _load_core(
        entity_type,
        records,
        options=options,
        source_type=SOURCE_TYPE_RECORDS,
    )


def load_ingestion_json(
    entity_type: str,
    data: str | bytes | bytearray | memoryview,
    options: LoaderOptions | None = None,
) -> LoadResult:
    """
    Load bounded ingestion records from strict JSON.
    """
    return _load_core(
        entity_type,
        data,
        options=options,
        forced_content_type=CONTENT_TYPE_JSON,
    )


def load_ingestion_ndjson(
    entity_type: str,
    data: str | bytes | bytearray | memoryview,
    options: LoaderOptions | None = None,
) -> LoadResult:
    """
    Load bounded ingestion records from NDJSON.
    """
    return _load_core(
        entity_type,
        data,
        options=options,
        forced_content_type=CONTENT_TYPE_NDJSON,
    )


def load_ingestion_csv(
    entity_type: str,
    data: str | bytes | bytearray | memoryview,
    options: LoaderOptions | None = None,
) -> LoadResult:
    """
    Load bounded ingestion records from CSV.
    """
    return _load_core(
        entity_type,
        data,
        options=options,
        forced_content_type=CONTENT_TYPE_CSV,
    )


def load_ingestion_file(
    entity_type: str,
    path: Any,
    options: LoaderOptions | None = None,
) -> LoadResult:
    """
    Load bounded ingestion records from an explicitly allowed local file.

    File loading is disabled by default. When enabled, only allowed local
    directories and safe file extensions are accepted.
    """
    return _load_core(
        entity_type,
        path,
        options=options,
        source_type=SOURCE_TYPE_FILE,
    )


def load_ingestion_source(
    entity_type: str,
    source: Any,
    options: LoaderOptions | None = None,
    content_type: Optional[str] = None,
) -> LoadResult:
    """
    Load bounded ingestion records from a safe source.

    Supported source types:

    - in-memory mappings/iterables/payload wrappers;
    - bytes;
    - text;
    - local path-like objects when file loading is enabled.

    Strings are treated as text, not filesystem paths. Use
    `load_ingestion_file` for explicit file loading.
    """
    return _load_core(
        entity_type,
        source,
        options=options,
        forced_content_type=content_type,
    )


def load_ingestion_payload(
    entity_type: str,
    payload: Any,
    options: LoaderOptions | None = None,
) -> LoadResult:
    """
    Load an ingestion payload.

    This is a convenience alias for `load_ingestion_source`.
    """
    return load_ingestion_source(entity_type, payload, options=options)


def iter_ingestion_batches(
    entity_type: str,
    source: Any,
    *,
    batch_size: Optional[int] = None,
    options: LoaderOptions | None = None,
) -> Iterator[list[dict[str, Any]]]:
    """
    Load records and yield bounded batches.

    This helper still performs a bounded load first. It is intended for
    downstream normalizers and validators that accept batched records.
    """
    result = load_ingestion_source(entity_type, source, options=options)

    if not result.ok and not result.records:
        return

    resolved_batch_size = max(
        1,
        min(
            int(batch_size or (options or LoaderOptions.from_settings()).max_records),
            HARD_MAX_RECORDS,
        ),
    )

    records = result.records

    for start in range(0, len(records), resolved_batch_size):
        yield records[start : start + resolved_batch_size]


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_ingestion_loader_metadata() -> dict[str, Any]:
    """
    Return safe, serializable ingestion-loader metadata.

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
    default_options = LoaderOptions()

    return {
        "package": "muleguard.backend.ingestion.loaders",
        "version": LOADERS_VERSION,
        "supported_entity_types": list(SUPPORTED_INGESTION_ENTITY_TYPES),
        "supported_content_types": sorted(SUPPORTED_CONTENT_TYPES),
        "allowed_file_extensions": sorted(ALLOWED_FILE_EXTENSIONS),
        "default_options": default_options.safe_summary(),
        "hard_limits": {
            "max_records": HARD_MAX_RECORDS,
            "max_errors_returned": HARD_MAX_ERRORS_RETURNED,
            "max_warnings_returned": HARD_MAX_WARNINGS_RETURNED,
            "max_bytes": HARD_MAX_BYTES,
            "max_file_bytes": HARD_MAX_FILE_BYTES,
            "max_line_bytes": HARD_MAX_LINE_BYTES,
            "max_cell_bytes": HARD_MAX_CELL_BYTES,
            "max_string_length": HARD_MAX_STRING_LENGTH,
        },
        "forbidden_top_level_key_count": len(FORBIDDEN_TOP_LEVEL_KEYS),
        "caveats": list(_LOADER_CAVEATS),
        "safety_flags": {
            "synthetic_only_by_default": True,
            "no_real_customer_data_by_default": True,
            "no_ground_truth_labels_accepted": True,
            "no_scenario_ids_accepted": True,
            "no_fraud_ring_ids_accepted": True,
            "no_raw_identifier_fields_accepted": True,
            "no_raw_narrative_in_summaries": True,
            "no_secrets_in_summaries": True,
            "no_network_loading": True,
            "no_pickle_loading": True,
            "no_unsafe_yaml_loading": True,
            "no_external_entity_xml_loading": True,
            "file_loading_disabled_by_default": True,
            "bounded_loading_required": True,
            "deterministic_loading": True,
            "unknown_fields_dropped_by_default": True,
            "no_automatic_adverse_customer_action": True,
            "not_production_ready": True,
        },
    }


__all__ = [
    "CONTENT_TYPE_CSV",
    "CONTENT_TYPE_JSON",
    "CONTENT_TYPE_NDJSON",
    "CONTENT_TYPE_RECORDS",
    "LoadIssue",
    "LoadResult",
    "LoaderOptions",
    "get_ingestion_loader_metadata",
    "iter_ingestion_batches",
    "load_ingestion_csv",
    "load_ingestion_file",
    "load_ingestion_json",
    "load_ingestion_ndjson",
    "load_ingestion_payload",
    "load_ingestion_records",
    "load_ingestion_source",
]