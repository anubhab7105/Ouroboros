"""
MULEGUARD backend API v1 report endpoints.

This module implements the versioned `/api/v1/reports` surface for bounded,
evidence-backed PDF and JSON investigation reports derived from persisted
synthetic MULEGUARD case data.

Implemented endpoints:

- GET  /api/v1/reports/status
- GET  /api/v1/reports/limitations
- GET  /api/v1/reports/cases/{case_id}/preview
- GET  /api/v1/reports/cases/{case_id}/evidence-index
- GET  /api/v1/reports/cases/{case_id}
- POST /api/v1/reports/cases/{case_id}/generate

Design goals:

- generate investigation reports strictly from persisted records;
- never fabricate case content, evidence text, metrics, or narrative quotes;
- keep generation bounded by item counts, section limits, page estimates, and
  wall-clock timeout;
- enforce server-side RBAC through dependency permissions;
- sanitise every emitted string and reject raw complaint narratives, raw
  identifier hashes, secrets, tokens, passwords, database URLs, model artifact
  paths, synthetic ground-truth labels, scenario IDs, and ring IDs;
- include synthetic-data disclaimers, limitations, and investigative-lead
  language in every report;
- use safe, non-traversable filenames and safe download headers;
- record durable audit events for material report generation and download;
- fail closed and honestly when the PDF renderer is unavailable rather than
  emitting a placeholder or empty PDF.

Explicit non-goals:

- This module does not invent evidence, quotations, metrics, or conclusions.
- This module does not return raw complaint narratives.
- This module does not take adverse action against accounts or customers.
- This module does not claim legal admissibility, forensic integrity, or
  regulatory compliance.
- This module does not claim production readiness or real-world fraud-detection
  accuracy.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Reports summarise
synthetic investigative workflow data. Alerts, risk scores, graph relationships,
candidate money trails, entity links, complaint correlations, and case
dispositions are investigative leads or human workflow artefacts only. They are
not proof of wrongdoing and must not trigger automatic adverse customer action.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Final, Optional

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    PageParams,
    Permission,
    RequestIDDep,
    SessionDep,
    SettingsDep,
    apply_pagination,
    pagination_dependency,
    require_permission,
)
from app.exceptions import (
    FeatureFlagDisabledError,
    NotFoundError,
    ReportGenerationError,
    ReportTimeoutError,
    ServiceUnavailableError,
    ValidationError as MuleGuardValidationError,
)
from app.models import (
    Account,
    AccountEntityLink,
    Alert,
    AuditEvent,
    AuditOutcome,
    CaseEvent,
    CaseEvidence,
    Complaint,
    ComplaintCorrelation,
    Entity,
    GraphAnalysisRun,
    InvestigationCase,
    ModelAssessment,
    Transaction,
    User,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.reports")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["reports"])


# -----------------------------------------------------------------------------
# Permission resolution
# -----------------------------------------------------------------------------
# Prefer dedicated report permissions when the project defines them. Fall back
# to investigative read permissions so the module remains usable across
# incremental RBAC evolutions.

_REPORT_READ_NAMES: Final[tuple[str, ...]] = (
    "REPORT_READ",
    "CASE_READ",
    "ALERT_READ",
)

_REPORT_GENERATE_NAMES: Final[tuple[str, ...]] = (
    "REPORT_GENERATE",
    "CASE_UPDATE",
    "CASE_READ",
)

_REPORT_DOWNLOAD_NAMES: Final[tuple[str, ...]] = (
    "REPORT_DOWNLOAD",
    "REPORT_READ",
    "CASE_READ",
)


def _first_permission(names: Sequence[str]) -> Any:
    """
    Return the first available permission attribute from the supplied names.

    The last-resort branch deliberately does not use `iter(Permission)`.
    There are two `Permission` classes in this codebase:
    `app.core.permissions.Permission` is a `str, Enum` and is iterable, while
    `app.api.deps.Permission` -- the one these endpoints import -- is a plain
    class of `Final[str]` constants and is NOT. `iter()` on it raises
    `TypeError: 'type' object is not iterable`.

    Scanning `vars()` works for both shapes and cannot raise.
    """
    for name in names:
        permission = getattr(Permission, name, None)

        if permission is not None:
            return permission

    for attribute, value in vars(Permission).items():
        if not attribute.startswith("_") and isinstance(value, str):
            return value

    return None


REPORT_READ_PERMISSION: Final[Any] = _first_permission(_REPORT_READ_NAMES)
REPORT_GENERATE_PERMISSION: Final[Any] = _first_permission(_REPORT_GENERATE_NAMES)
REPORT_DOWNLOAD_PERMISSION: Final[Any] = _first_permission(_REPORT_DOWNLOAD_NAMES)


# -----------------------------------------------------------------------------
# Constants and policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 4_000
_MAX_CELL_LENGTH: Final[int] = 1_000
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_MAPPING_KEYS: Final[int] = 100
_MAX_JSON_DEPTH: Final[int] = 6

_DEFAULT_MAX_ITEMS_PER_SECTION: Final[int] = 50
_HARD_MAX_ITEMS_PER_SECTION: Final[int] = 500

_DEFAULT_MAX_PAGES: Final[int] = 40
_HARD_MAX_PAGES: Final[int] = 200

_DEFAULT_MAX_GENERATION_SECONDS: Final[int] = 30
_HARD_MAX_GENERATION_SECONDS: Final[int] = 300

_ROWS_PER_PAGE_ESTIMATE: Final[int] = 25

_FILENAME_SAFE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._-]+")
_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

_DEFAULT_FILENAME_PREFIX: Final[str] = "muleguard-case-report"
_DEFAULT_TIMEZONE: Final[str] = "UTC"

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

_DEFAULT_DISCLAIMER: Final[str] = (
    "SYNTHETIC DEMO REPORT. Generated from synthetic prototype data. "
    "Not a real investigation. Not proof of fraud or wrongdoing."
)

_DEFAULT_LIMITATIONS: Final[str] = (
    "This report is generated from synthetic prototype data by MULEGUARD. "
    "Alerts, risk scores, graph relationships, candidate money trails, entity "
    "links, and complaint correlations are investigative leads only and are "
    "not evidence of wrongdoing. Risk scores are investigative priority "
    "scores, not probabilities of guilt and are not calibrated. Candidate "
    "money trails are heuristic flow views, not proof of layering or "
    "integration. Shared entities are association clusters only. Complaint "
    "correlations distinguish exact matches from inferred associations; "
    "inferred correlations are not verified facts. Case dispositions are "
    "investigator-entered workflow assessments and are not automatic "
    "conclusions. This prototype is not production-ready, does not claim "
    "regulatory compliance, does not claim real-world fraud-detection "
    "accuracy, and does not implement automatic adverse customer action."
)

_DEFAULT_FOOTER: Final[str] = (
    "Synthetic prototype only. Investigative leads, not proof of wrongdoing."
)

_REPORT_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Report content is generated exclusively from persisted records.",
    "No evidence text, metric, quotation, or conclusion is fabricated.",
    "Raw complaint narratives are intentionally excluded from reports.",
    "Raw identifier hashes are intentionally excluded from reports.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are excluded.",
    "Risk scores are investigative priority scores, not probabilities of guilt.",
    "Heuristic fallback scores are not calibrated model probabilities.",
    "Graph relationships, shared entities, and candidate money trails are investigative leads only.",
    "Complaint correlations distinguish exact matches from inferred associations.",
    "Case dispositions are investigator-entered workflow assessments, not automatic conclusions.",
    "Report generation is bounded by item, section, page, and time limits.",
    "This report is not legal evidence and does not claim forensic integrity.",
    "This API does not freeze, block, blacklist, close, restrict, or otherwise take adverse action against accounts or customers.",
)


# -----------------------------------------------------------------------------
# Dynamic column helpers
# -----------------------------------------------------------------------------


def _model_column(model: Any, name: str) -> Any | None:
    """
    Return a SQLAlchemy column attribute when present.
    """
    return getattr(model, name, None)


def _first_column(model: Any, *names: str) -> Any | None:
    """
    Return the first existing column attribute among names.
    """
    for name in names:
        column = _model_column(model, name)

        if column is not None:
            return column

    return None


_CASE_EVENT_CREATED_AT = _first_column(CaseEvent, "created_at", "record_created_at")
_CASE_EVENT_SORT = _first_column(CaseEvent, "created_at", "record_created_at", "id")

_EVIDENCE_CREATED_AT = _first_column(
    CaseEvidence,
    "record_created_at",
    "created_at",
    "added_at",
)

_ASSESSMENT_SORT = _first_column(ModelAssessment, "scored_at", "as_of")

_TRANSACTION_SORT = _first_column(Transaction, "occurred_at", "record_created_at", "created_at")

_CORRELATION_SORT = _first_column(
    ComplaintCorrelation,
    "record_created_at",
    "created_at",
)

_GRAPH_RUN_SORT = _first_column(
    GraphAnalysisRun,
    "record_created_at",
    "created_at",
)

_ALERT_SORT = _first_column(Alert, "record_created_at", "created_at", "first_seen_at")


# -----------------------------------------------------------------------------
# Bounded pagination dependency for evidence index
# -----------------------------------------------------------------------------

_EVIDENCE_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(CaseEvidence, "id"),
        "created_at": _EVIDENCE_CREATED_AT,
        "evidence_type": _model_column(CaseEvidence, "evidence_type"),
        "evidence_id": _model_column(CaseEvidence, "evidence_id"),
    }.items()
    if column is not None
}

_EVIDENCE_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _EVIDENCE_COLUMN_MAP
    else ("id" if "id" in _EVIDENCE_COLUMN_MAP else "created_at")
)

evidence_pagination = pagination_dependency(
    sortable_fields=tuple(_EVIDENCE_COLUMN_MAP.keys()),
    default_sort_by=_EVIDENCE_DEFAULT_SORT,
    default_sort_order="desc",
    max_page_size=200,
    hard_max_page_size=200,
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


def _now_utc() -> datetime:
    """
    Return timezone-aware UTC current time.
    """
    return datetime.now(timezone.utc)


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
    text = str(value if value is not None else "")
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if len(text) > limit:
        return text[:limit]

    return text


def _clean_multiline(value: Any, limit: int = _MAX_STRING_LENGTH) -> str:
    """
    Return a safe bounded text value preserving paragraph breaks.
    """
    text = str(value if value is not None else "")
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(" ".join(line.split()) for line in text.split("\n"))
    text = text.strip()

    if len(text) > limit:
        return text[:limit]

    return text


def _get_if_exists(obj: Any, name: str, default: Any = None) -> Any:
    """
    Get an attribute only when it exists on the object.
    """
    return getattr(obj, name, default)


def _str_or_none(value: Any) -> Optional[str]:
    """
    Return a stripped string or None.
    """
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _timestamp_value(obj: Any, *names: str) -> Optional[datetime]:
    """
    Return the first non-null timestamp-like attribute.
    """
    for name in names:
        value = _get_if_exists(obj, name, None)

        if value is not None:
            return value

    return None


def _format_timestamp(value: Any, timezone_label: str) -> str:
    """
    Return a safe ISO-style timestamp string for report rendering.
    """
    if value is None:
        return "not recorded"

    if isinstance(value, datetime):
        text = value.isoformat()
    else:
        text = _clean_text(value, 100)

    if not text:
        return "not recorded"

    if timezone_label and timezone_label != "UTC":
        return f"{text} ({timezone_label})"

    return text


def _format_amount(value: Any, currency: Any) -> str:
    """
    Return a safe monetary string. Never converts between currencies.
    """
    if value is None:
        return "not recorded"

    amount = _clean_text(value, 64)
    currency_text = _clean_text(currency, 8)

    if not amount:
        return "not recorded"

    if currency_text:
        return f"{currency_text} {amount}"

    return amount


def _safe_string_list(value: Any, *, max_items: int = _MAX_LIST_LENGTH) -> list[str]:
    """
    Return a bounded list of safe strings.
    """
    if value is None:
        return []

    if isinstance(value, str):
        candidates: Sequence[Any] = [value]
    elif isinstance(value, Mapping):
        return []
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        candidates = value
    else:
        candidates = [value]

    seen: set[str] = set()
    result: list[str] = []

    for item in candidates:
        text = _clean_text(item, _MAX_CELL_LENGTH)

        if not text or text in seen:
            continue

        seen.add(text)
        result.append(text)

        if len(result) >= max_items:
            break

    return result


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
    Convert an arbitrary JSON-like value into a safe report value.
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

    if isinstance(value, Enum):
        return _sanitize_json_value(
            value.value,
            depth + 1,
            max_sequence_length=max_sequence_length,
            max_mapping_keys=max_mapping_keys,
        )

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
    Return a sanitized JSON object suitable for report rendering.
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


def _response_metadata(value: Any) -> Any:
    """
    Sanitize metadata_json-like values before rendering.
    """
    if isinstance(value, Mapping):
        return _sanitize_json_object(value)

    if value is None:
        return None

    return _sanitize_json_value(value)


def _total_pages(total: int, page_size: int) -> int:
    """
    Compute bounded total page count.
    """
    if total <= 0 or page_size <= 0:
        return 0

    return (total + page_size - 1) // page_size


def _apply(stmt: Any, conditions: list[Any]) -> Any:
    """
    Apply a list of SQLAlchemy conditions to a statement.
    """
    if conditions:
        stmt = stmt.where(and_(*conditions))

    return stmt


def _scalar_count(db: Session, stmt: Any) -> int:
    """
    Execute a count statement and return an int.
    """
    return int(db.scalar(stmt) or 0)


def _order_stmt(stmt: Any, specs: Sequence[tuple[Any, bool]]) -> Any:
    """
    Apply safe ordering specifications, skipping missing columns.
    """
    for column, ascending in specs:
        if column is None:
            continue

        stmt = stmt.order_by(column.asc() if ascending else column.desc())

    return stmt


def _sha256_text(value: str) -> str:
    """
    Return a SHA-256 hex digest for report content integrity.

    This is not a secret and is not used for authentication.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    """
    Return a SHA-256 hex digest for rendered report bytes.
    """
    return hashlib.sha256(value).hexdigest()


# -----------------------------------------------------------------------------
# Client IP / audit helpers
# -----------------------------------------------------------------------------


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
        or "muleguard-reports"
    )

    return hashlib.sha256(f"{salt}:{ip}".encode("utf-8")).hexdigest()


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
    safe_metadata = _sanitize_json_object(
        metadata or {},
        max_sequence_length=50,
        max_mapping_keys=50,
    )

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
# Report policy helpers
# -----------------------------------------------------------------------------


def _ensure_reports_enabled(settings: Any) -> None:
    """
    Fail closed when the report API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "REPORT_API_ENABLED", True), True):
        raise FeatureFlagDisabledError("Report endpoints are disabled by configuration.")

    if not _as_bool(_setting(settings, "REPORT_ENABLED", True), True):
        raise FeatureFlagDisabledError("Report subsystem is disabled by configuration.")


def _report_limit(key: str, default: int, hard: int, settings: Any) -> int:
    """
    Return a bounded report limit.
    """
    configured = max(
        1,
        _as_int(_setting(settings, key, default), default),
    )

    return min(configured, max(configured, hard))


def _max_items_per_section(settings: Any) -> int:
    """
    Return bounded maximum items rendered per report section.
    """
    return _report_limit(
        "REPORT_MAX_ITEMS_PER_SECTION",
        _DEFAULT_MAX_ITEMS_PER_SECTION,
        _HARD_MAX_ITEMS_PER_SECTION,
        settings,
    )


def _max_pages(settings: Any) -> int:
    """
    Return bounded maximum estimated report pages.
    """
    return _report_limit(
        "REPORT_MAX_PAGES",
        _DEFAULT_MAX_PAGES,
        _HARD_MAX_PAGES,
        settings,
    )


def _max_generation_seconds(settings: Any) -> int:
    """
    Return bounded maximum report generation wall-clock seconds.
    """
    return _report_limit(
        "REPORT_MAX_GENERATION_SECONDS",
        _DEFAULT_MAX_GENERATION_SECONDS,
        _HARD_MAX_GENERATION_SECONDS,
        settings,
    )


def _report_timezone_label(settings: Any) -> str:
    """
    Return the configured report timezone label.

    Timestamps are always stored and emitted in UTC; this label is only a
    display annotation and does not convert values.
    """
    return _clean_text(
        _setting(settings, "REPORT_TIMEZONE", _DEFAULT_TIMEZONE) or _DEFAULT_TIMEZONE,
        64,
    )


def _filename_prefix(settings: Any) -> str:
    """
    Return a sanitized report filename prefix.
    """
    raw = _clean_text(
        _setting(settings, "REPORT_FILENAME_PREFIX", _DEFAULT_FILENAME_PREFIX)
        or _DEFAULT_FILENAME_PREFIX,
        64,
    )

    sanitized = _FILENAME_SAFE_RE.sub("-", raw).strip("-._") or _DEFAULT_FILENAME_PREFIX
    return sanitized[:64]


def _safe_filename_component(value: Any, *, limit: int = 64) -> str:
    """
    Return a filename-safe component derived from persisted identifiers.
    """
    text = _clean_text(value, 128)
    sanitized = _FILENAME_SAFE_RE.sub("-", text).strip("-._")

    if not sanitized:
        return "case"

    return sanitized[:limit]


def _build_filename(case_id: Any, generated_at: datetime, content_digest: str, settings: Any) -> str:
    """
    Build a safe, non-traversable report filename.

    Caller-supplied filenames are never accepted.
    """
    timestamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    prefix = _filename_prefix(settings)
    case_component = _safe_filename_component(case_id)
    digest = _clean_text(content_digest, 16) or "0000000000000000"

    return f"{prefix}-{case_component}-{timestamp}-{digest[:12]}.pdf"


def _render_pdf_available() -> bool:
    """
    Return True when the PDF renderer is importable.
    """
    try:
        import reportlab  # noqa: F401

        return True
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Report document model
# -----------------------------------------------------------------------------


@dataclass(slots=True)
class ReportRow:
    """
    Safe single report row.
    """

    label: str
    value: str
    evidence_refs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReportSection:
    """
    Safe bounded report section.
    """

    key: str
    title: str
    rows: list[ReportRow] = field(default_factory=list)
    narrative: Optional[str] = None
    evidence_refs: list[str] = field(default_factory=list)
    item_count: int = 0
    truncated: bool = False
    note: Optional[str] = None


@dataclass(slots=True)
class ReportDocument:
    """
    Safe bounded report document rendered from persisted records only.
    """

    case_id: str
    case_title: str
    generated_at: datetime
    generated_by: str
    timezone_label: str
    sections: list[ReportSection] = field(default_factory=list)
    evidence_index: list[ReportRow] = field(default_factory=list)
    disclaimer: str = ""
    limitations: str = ""
    footer: str = ""
    caveats: list[str] = field(default_factory=list)
    evidence_total: int = 0
    evidence_truncated: bool = False
    estimated_pages: int = 0
    page_limit: int = 0
    generation_seconds: float = 0.0
    item_limit: int = 0


# -----------------------------------------------------------------------------
# Report document builder
# -----------------------------------------------------------------------------


def _get_case_or_404(db: Session, case_id: str) -> InvestigationCase:
    """
    Load a case or raise a safe not-found error.
    """
    case = db.get(InvestigationCase, case_id)

    if case is None:
        raise NotFoundError.resource("case", case_id)

    return case


def _load_case_events(
    db: Session,
    case_id: str,
    *,
    limit: int,
) -> tuple[list[CaseEvent], int]:
    """
    Load bounded case events and total count.
    """
    case_id_column = _model_column(CaseEvent, "case_id")

    if case_id_column is None:
        return [], 0

    conditions = [case_id_column == case_id]

    total = _scalar_count(
        db,
        _apply(select(func.count()).select_from(CaseEvent), conditions),
    )

    stmt = select(CaseEvent)
    stmt = _apply(stmt, conditions)
    stmt = _order_stmt(stmt, [(_CASE_EVENT_SORT, False)])
    stmt = stmt.limit(max(1, int(limit)))

    return list(db.scalars(stmt).all()), total


def _load_case_evidence(
    db: Session,
    case_id: str,
    *,
    limit: int,
) -> tuple[list[CaseEvidence], int]:
    """
    Load bounded active case evidence and total count.
    """
    case_id_column = _model_column(CaseEvidence, "case_id")

    if case_id_column is None:
        return [], 0

    conditions = [case_id_column == case_id]

    active_column = _model_column(CaseEvidence, "is_active")

    if active_column is not None:
        conditions.append(active_column.is_(True))

    total = _scalar_count(
        db,
        _apply(select(func.count()).select_from(CaseEvidence), conditions),
    )

    stmt = select(CaseEvidence)
    stmt = _apply(stmt, conditions)
    stmt = _order_stmt(stmt, [(_EVIDENCE_CREATED_AT, False)])
    stmt = stmt.limit(max(1, int(limit)))

    return list(db.scalars(stmt).all()), total


def _load_latest_assessment(
    db: Session,
    account_id: Optional[str],
    *,
    limit: int = 1,
) -> list[ModelAssessment]:
    """
    Load bounded latest persisted assessments for an account.
    """
    account_column = _model_column(ModelAssessment, "account_id")

    if account_column is None or not account_id:
        return []

    stmt = select(ModelAssessment)
    stmt = _apply(stmt, [account_column == account_id])
    stmt = _order_stmt(stmt, [(_ASSESSMENT_SORT, False)])
    stmt = stmt.limit(max(1, int(limit)))

    return list(db.scalars(stmt).all())


def _load_transaction_timeline(
    db: Session,
    account_id: Optional[str],
    *,
    limit: int,
) -> list[Transaction]:
    """
    Load bounded transactions involving the case account.
    """
    sender_column = _model_column(Transaction, "sender_account_id")
    receiver_column = _model_column(Transaction, "receiver_account_id")

    if not account_id or sender_column is None or receiver_column is None:
        return []

    conditions = [
        or_(
            sender_column == account_id,
            receiver_column == account_id,
        )
    ]

    stmt = select(Transaction)
    stmt = _apply(stmt, conditions)
    stmt = _order_stmt(stmt, [(_TRANSACTION_SORT, False)])
    stmt = stmt.limit(max(1, int(limit)))

    return list(db.scalars(stmt).all())


def _load_complaint_correlations(
    db: Session,
    account_id: Optional[str],
    *,
    limit: int,
) -> list[tuple[ComplaintCorrelation, Complaint]]:
    """
    Load bounded complaint correlations for the case account.

    Raw and normalized narratives are never selected or rendered.
    """
    correlation_account_column = _model_column(ComplaintCorrelation, "account_id")
    complaint_id_column = _model_column(Complaint, "id")

    if not account_id or correlation_account_column is None or complaint_id_column is None:
        return []

    conditions = [correlation_account_column == account_id]

    stmt = (
        select(ComplaintCorrelation, Complaint)
        .join(Complaint, Complaint.id == ComplaintCorrelation.complaint_id)
    )
    stmt = _apply(stmt, conditions)
    stmt = _order_stmt(stmt, [(_CORRELATION_SORT, False)])
    stmt = stmt.limit(max(1, int(limit)))

    return list(db.execute(stmt).all())


def _load_entity_links(
    db: Session,
    account_id: Optional[str],
    *,
    limit: int,
) -> list[tuple[AccountEntityLink, Entity]]:
    """
    Load bounded pseudonymous entity links for the case account.
    """
    link_account_column = _model_column(AccountEntityLink, "account_id")
    entity_id_column = _model_column(Entity, "id")

    if not account_id or link_account_column is None or entity_id_column is None:
        return []

    conditions = [link_account_column == account_id]

    stmt = (
        select(AccountEntityLink, Entity)
        .join(Entity, Entity.id == AccountEntityLink.entity_id)
    )
    stmt = _apply(stmt, conditions)
    stmt = stmt.limit(max(1, int(limit)))

    return list(db.execute(stmt).all())


def _load_graph_runs(
    db: Session,
    account_id: Optional[str],
    *,
    limit: int,
) -> list[GraphAnalysisRun]:
    """
    Load bounded persisted graph analysis runs for the case account.
    """
    root_column = _model_column(GraphAnalysisRun, "root_account_id")

    if not account_id or root_column is None:
        return []

    conditions = [root_column == account_id]

    stmt = select(GraphAnalysisRun)
    stmt = _apply(stmt, conditions)
    stmt = _order_stmt(stmt, [(_GRAPH_RUN_SORT, False)])
    stmt = stmt.limit(max(1, int(limit)))

    return list(db.scalars(stmt).all())


def _load_alert(db: Session, alert_id: Optional[str]) -> Optional[Alert]:
    """
    Load an originating alert when present.
    """
    if not alert_id:
        return None

    return db.get(Alert, alert_id)


def _check_budget(
    started_at: float,
    max_seconds: int,
    *,
    case_id: str,
) -> None:
    """
    Enforce the report generation wall-clock budget.
    """
    elapsed = time.monotonic() - started_at

    if elapsed > max_seconds:
        raise ReportTimeoutError(
            "Report generation exceeded the configured time limit.",
            details={
                "case_id": _clean_text(case_id, 128),
                "max_generation_seconds": int(max_seconds),
                "elapsed_seconds": round(elapsed, 3),
            },
        )


def _estimate_pages(sections: Sequence[ReportSection]) -> int:
    """
    Return a conservative estimated page count for rendered sections.
    """
    rows = sum(len(section.rows) for section in sections)
    extra = sum(1 for section in sections if section.narrative)
    return max(1, (rows + extra) // _ROWS_PER_PAGE_ESTIMATE + 1)


def _build_report_document(
    db: Session,
    settings: Any,
    case: InvestigationCase,
    actor: User,
    *,
    max_items: int,
    page_limit: int,
    max_seconds: int,
    timezone_label: str,
) -> ReportDocument:
    """
    Build a bounded report document from persisted records only.

    Raises ReportTimeoutError when the generation budget is exceeded and
    ReportGenerationError when the case cannot be rendered safely.
    """
    started_at = time.monotonic()

    case_id = str(case.id)
    case_title = _clean_text(_get_if_exists(case, "title", ""), 200) or "Untitled case"
    account_id = _str_or_none(_get_if_exists(case, "account_id", None))
    alert_id = _str_or_none(_get_if_exists(case, "alert_id", None))

    sections: list[ReportSection] = []

    # ------------------------------------------------------------------
    # Case summary
    # ------------------------------------------------------------------
    disposition = _get_if_exists(case, "disposition", None)

    case_section = ReportSection(
        key="case_summary",
        title="Case summary",
        rows=[
            ReportRow("Case ID", _clean_text(case.id, 128)),
            ReportRow("Title", case_title),
            ReportRow(
                "Description",
                _clean_multiline(_get_if_exists(case, "description", None)) or "not recorded",
            ),
            ReportRow("Status", _enum_str(_get_if_exists(case, "status", None)) or "UNKNOWN"),
            ReportRow(
                "Priority",
                _enum_str(_get_if_exists(case, "priority", None)) or "MEDIUM",
            ),
            ReportRow(
                "Assignee",
                _str_or_none(_get_if_exists(case, "assignee_id", None)) or "unassigned",
            ),
            ReportRow(
                "Created by",
                _str_or_none(_get_if_exists(case, "creator_id", None)) or "not recorded",
            ),
            ReportRow("Account ID", account_id or "not recorded"),
            ReportRow("Originating alert ID", alert_id or "not recorded"),
            ReportRow(
                "Disposition",
                _enum_str(disposition)
                if isinstance(disposition, Enum)
                else (_str_or_none(disposition) or "not recorded"),
            ),
            ReportRow(
                "Closed at",
                _format_timestamp(_get_if_exists(case, "closed_at", None), timezone_label),
            ),
            ReportRow(
                "Created at",
                _format_timestamp(
                    _timestamp_value(case, "record_created_at", "created_at"),
                    timezone_label,
                ),
            ),
            ReportRow(
                "Updated at",
                _format_timestamp(
                    _timestamp_value(case, "record_updated_at", "updated_at"),
                    timezone_label,
                ),
            ),
        ],
        note=(
            "Case dispositions are investigator-entered workflow assessments. "
            "They are not automatic conclusions or enforcement actions."
        ),
    )
    sections.append(case_section)

    _check_budget(started_at, max_seconds, case_id=case_id)

    # ------------------------------------------------------------------
    # Account profile
    # ------------------------------------------------------------------
    account_rows: list[ReportRow] = []

    if account_id:
        account = db.get(Account, account_id)

        if account is not None:
            account_rows.extend(
                [
                    ReportRow("Account ID", _clean_text(account.id, 128)),
                    ReportRow(
                        "Account type",
                        _enum_str(_get_if_exists(account, "account_type", None)) or "UNKNOWN",
                    ),
                    ReportRow(
                        "Status",
                        _enum_str(_get_if_exists(account, "status", None)) or "UNKNOWN",
                    ),
                    ReportRow(
                        "Created at",
                        _format_timestamp(
                            _get_if_exists(account, "created_at", None),
                            timezone_label,
                        ),
                    ),
                ]
            )
        else:
            account_rows.append(
                ReportRow("Account ID", f"{account_id} (record not found)")
            )

    sections.append(
        ReportSection(
            key="account_profile",
            title="Account profile",
            rows=account_rows,
            item_count=len(account_rows),
            note=(
                "Account status is observational metadata. It is not an "
                "enforcement action and does not restrict any account."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Originating alert
    # ------------------------------------------------------------------
    alert = _load_alert(db, alert_id)
    alert_rows: list[ReportRow] = []
    alert_refs: list[str] = []

    if alert is not None:
        alert_refs = _safe_string_list(_get_if_exists(alert, "signal_summary_json", None))

        alert_rows.extend(
            [
                ReportRow("Alert ID", _clean_text(alert.id, 128)),
                ReportRow(
                    "Title",
                    _clean_text(_get_if_exists(alert, "title", None), 200) or "untitled",
                ),
                ReportRow(
                    "Priority",
                    _enum_str(_get_if_exists(alert, "priority", None)) or "MEDIUM",
                ),
                ReportRow(
                    "State",
                    _enum_str(_get_if_exists(alert, "state", None)) or "NEW",
                ),
                ReportRow(
                    "Score",
                    _clean_text(_get_if_exists(alert, "score", None), 64) or "not recorded",
                ),
                ReportRow(
                    "Scoring mode",
                    _enum_str(_get_if_exists(alert, "scoring_mode", None)) or "unknown",
                ),
                ReportRow(
                    "Model version",
                    _str_or_none(_get_if_exists(alert, "model_version", None)) or "not recorded",
                ),
                ReportRow(
                    "First seen at",
                    _format_timestamp(
                        _get_if_exists(alert, "first_seen_at", None),
                        timezone_label,
                    ),
                ),
            ]
        )

    sections.append(
        ReportSection(
            key="originating_alert",
            title="Originating alert",
            rows=alert_rows,
            item_count=len(alert_rows),
            evidence_refs=alert_refs,
            note=(
                "Alerts are investigative leads only. Scoring mode and model "
                "version must be interpreted honestly; heuristic fallback "
                "scores are not calibrated model probabilities."
            ),
        )
    )

    _check_budget(started_at, max_seconds, case_id=case_id)

    # ------------------------------------------------------------------
    # Risk assessment
    # ------------------------------------------------------------------
    assessments = _load_latest_assessment(db, account_id, limit=max(1, min(3, max_items)))
    assessment_rows: list[ReportRow] = []
    assessment_refs: list[str] = []

    for assessment in assessments:
        refs = _safe_string_list(_get_if_exists(assessment, "explanation_json", None))
        assessment_refs.extend(refs)

        assessment_rows.append(
            ReportRow(
                f"Assessment {_clean_text(assessment.id, 128)}",
                (
                    f"score={_clean_text(_get_if_exists(assessment, 'score', None), 32) or 'n/a'} "
                    f"band={_enum_str(_get_if_exists(assessment, 'risk_band', None)) or 'UNKNOWN'} "
                    f"mode={_enum_str(_get_if_exists(assessment, 'scoring_mode', None)) or 'unknown'} "
                    f"as_of={_format_timestamp(_get_if_exists(assessment, 'as_of', None), '')}"
                ),
                evidence_refs=refs,
            )
        )

    if not assessment_rows:
        assessment_rows.append(
            ReportRow(
                "Assessment",
                "No persisted assessment was found for the case account at report time.",
            )
        )

    sections.append(
        ReportSection(
            key="risk_assessment",
            title="Risk assessment",
            rows=assessment_rows,
            item_count=len(assessment_rows),
            evidence_refs=_safe_string_list(assessment_refs),
            note=(
                "Risk scores are investigative priority scores, not "
                "probabilities of guilt and not calibrated likelihoods."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Transaction timeline
    # ------------------------------------------------------------------
    transactions = _load_transaction_timeline(db, account_id, limit=max_items)
    transaction_rows: list[ReportRow] = []

    for transaction in transactions:
        status = _enum_str(_get_if_exists(transaction, "status", None)) or "UNKNOWN"
        reference = _clean_text(_get_if_exists(transaction, "reference", None), 128)
        amount = _format_amount(
            _get_if_exists(transaction, "amount", None),
            _get_if_exists(transaction, "currency", None),
        )
        sender = _str_or_none(_get_if_exists(transaction, "sender_account_id", None)) or "n/a"
        receiver = _str_or_none(_get_if_exists(transaction, "receiver_account_id", None)) or "n/a"

        transaction_rows.append(
            ReportRow(
                f"{_clean_text(transaction.id, 128)} · {reference or 'no reference'}",
                (
                    f"status={status} amount={amount} "
                    f"sender={sender} receiver={receiver} "
                    f"occurred_at={_format_timestamp(_get_if_exists(transaction, 'occurred_at', None), '')}"
                ),
                evidence_refs=[_clean_text(transaction.id, 128)],
            )
        )

    if not transaction_rows:
        transaction_rows.append(
            ReportRow("Transactions", "No persisted transactions were found for the case account.")
        )

    sections.append(
        ReportSection(
            key="transaction_timeline",
            title="Transaction timeline",
            rows=transaction_rows,
            item_count=len(transaction_rows),
            truncated=len(transaction_rows) >= max_items,
            evidence_refs=_safe_string_list(
                [row.evidence_refs[0] for row in transaction_rows if row.evidence_refs]
            ),
            note=(
                "Completed transfers are treated as fund movement. Pending, "
                "failed, and reversed records are reported separately and are "
                "not treated as completed transfers. Currency values are not "
                "converted."
            ),
        )
    )

    _check_budget(started_at, max_seconds, case_id=case_id)

    # ------------------------------------------------------------------
    # Candidate graph analysis
    # ------------------------------------------------------------------
    graph_runs = _load_graph_runs(db, account_id, limit=max(1, min(3, max_items)))
    graph_rows: list[ReportRow] = []

    for run in graph_runs:
        capped = bool(_get_if_exists(run, "capped", False))
        node_count = _clean_text(_get_if_exists(run, "node_count", None), 16) or "0"
        edge_count = _clean_text(_get_if_exists(run, "edge_count", None), 16) or "0"

        graph_rows.append(
            ReportRow(
                f"Graph run {_clean_text(run.id, 128)}",
                (
                    f"nodes={node_count} edges={edge_count} "
                    f"capped={'yes' if capped else 'no'} "
                    f"created_at={_format_timestamp(_timestamp_value(run, 'record_created_at', 'created_at'), '')}"
                ),
                evidence_refs=[_clean_text(run.id, 128)],
            )
        )

    if not graph_rows:
        graph_rows.append(
            ReportRow(
                "Graph analysis",
                "No persisted graph analysis run was found for the case account.",
            )
        )

    sections.append(
        ReportSection(
            key="graph_analysis",
            title="Graph analysis",
            rows=graph_rows,
            item_count=len(graph_rows),
            evidence_refs=_safe_string_list(
                [row.evidence_refs[0] for row in graph_rows if row.evidence_refs]
            ),
            note=(
                "Graph relationships and candidate money trails are bounded "
                "investigative leads only. They are not proof of common "
                "control, layering, integration, or wrongdoing."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Entity associations
    # ------------------------------------------------------------------
    entity_links = _load_entity_links(db, account_id, limit=max_items)
    entity_rows: list[ReportRow] = []

    for link, entity in entity_links:
        identifier_display = _clean_text(_get_if_exists(entity, "identifier_display", None), 200)
        entity_type = _enum_str(_get_if_exists(entity, "entity_type", None)) or "UNKNOWN"

        entity_rows.append(
            ReportRow(
                f"Entity {_clean_text(entity.id, 128)} · {entity_type}",
                (
                    f"label={identifier_display or 'not disclosed'} "
                    f"method={_enum_str(_get_if_exists(link, 'match_method', None)) or 'UNKNOWN'} "
                    f"verification={_enum_str(_get_if_exists(link, 'verification_state', None)) or 'UNVERIFIED'} "
                    f"confidence={_clean_text(_get_if_exists(link, 'confidence', None), 32) or 'n/a'} "
                    f"valid_from={_format_timestamp(_get_if_exists(link, 'valid_from', None), '')}"
                ),
                evidence_refs=[_clean_text(entity.id, 128)],
            )
        )

    if not entity_rows:
        entity_rows.append(
            ReportRow("Entity associations", "No persisted entity links were found for the case account.")
        )

    sections.append(
        ReportSection(
            key="entity_associations",
            title="Entity associations",
            rows=entity_rows,
            item_count=len(entity_rows),
            truncated=len(entity_rows) >= max_items,
            evidence_refs=_safe_string_list(
                [row.evidence_refs[0] for row in entity_rows if row.evidence_refs]
            ),
            note=(
                "Shared entities are association clusters only. They may arise "
                "from benign sharing, test data, or synthetic generation "
                "artifacts and are not proof of common control or wrongdoing."
            ),
        )
    )

    _check_budget(started_at, max_seconds, case_id=case_id)

    # ------------------------------------------------------------------
    # Complaint correlations
    # ------------------------------------------------------------------
    correlations = _load_complaint_correlations(db, account_id, limit=max_items)
    correlation_rows: list[ReportRow] = []

    for correlation, complaint in correlations:
        match_method = _enum_str(_get_if_exists(correlation, "match_method", None)) or "UNKNOWN"
        deterministic = bool(_get_if_exists(correlation, "deterministic", False))
        tier = _clean_text(_get_if_exists(correlation, "match_tier", None), 8) or "0"
        reference = _clean_text(_get_if_exists(complaint, "reference", None), 128) or "no reference"

        correlation_rows.append(
            ReportRow(
                f"Correlation {_clean_text(correlation.id, 128)} · complaint {reference}",
                (
                    f"tier={tier} method={match_method} "
                    f"deterministic={'yes' if deterministic else 'no'} "
                    f"category={_clean_text(_get_if_exists(complaint, 'category', None), 100) or 'uncategorised'} "
                    f"reported_at={_format_timestamp(_get_if_exists(complaint, 'reported_at', None), '')} "
                    f"review={_enum_str(_get_if_exists(correlation, 'review_state', None)) or 'UNREVIEWED'}"
                ),
                evidence_refs=[_clean_text(complaint.id, 128)],
            )
        )

    if not correlation_rows:
        correlation_rows.append(
            ReportRow(
                "Complaint correlations",
                "No persisted complaint correlations were found for the case account.",
            )
        )

    sections.append(
        ReportSection(
            key="complaint_correlations",
            title="Complaint correlations",
            rows=correlation_rows,
            item_count=len(correlation_rows),
            truncated=len(correlation_rows) >= max_items,
            evidence_refs=_safe_string_list(
                [row.evidence_refs[0] for row in correlation_rows if row.evidence_refs]
            ),
            note=(
                "Exact matches are distinguished from inferred associations. "
                "Inferred correlations are not verified facts. Raw and "
                "normalized complaint narratives are intentionally excluded "
                "from this report."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Case evidence
    # ------------------------------------------------------------------
    evidences, evidence_total = _load_case_evidence(db, case_id, limit=max_items)
    evidence_rows: list[ReportRow] = []
    evidence_index: list[ReportRow] = []

    for evidence in evidences:
        evidence_type = _enum_str(_get_if_exists(evidence, "evidence_type", None)) or "UNKNOWN"
        evidence_ref = _clean_text(_get_if_exists(evidence, "evidence_id", None), 128) or "n/a"
        evidence_id = _clean_text(evidence.id, 128)

        evidence_rows.append(
            ReportRow(
                f"Evidence {evidence_id}",
                f"type={evidence_type} reference={evidence_ref}",
                evidence_refs=[evidence_ref],
            )
        )

        evidence_index.append(
            ReportRow(
                evidence_id,
                f"{evidence_type} · {evidence_ref}",
                evidence_refs=[evidence_ref],
            )
        )

    if not evidence_rows:
        evidence_rows.append(
            ReportRow("Evidence", "No active case evidence references were attached at report time.")
        )

    sections.append(
        ReportSection(
            key="case_evidence",
            title="Case evidence",
            rows=evidence_rows,
            item_count=len(evidence_rows),
            truncated=len(evidence_rows) >= max_items,
            evidence_refs=_safe_string_list(
                [row.evidence_refs[0] for row in evidence_rows if row.evidence_refs]
            ),
            note=(
                "Evidence references point to validated persisted records. "
                "Graph-path evidence is produced only by the bounded graph "
                "service and is not manually attached."
            ),
        )
    )

    _check_budget(started_at, max_seconds, case_id=case_id)

    # ------------------------------------------------------------------
    # Case notes and event history
    # ------------------------------------------------------------------
    events, event_total = _load_case_events(db, case_id, limit=max_items)
    event_rows: list[ReportRow] = []
    note_rows: list[ReportRow] = []

    for event in events:
        action = _clean_text(_get_if_exists(event, "action", None), 100) or "unknown"
        summary = _clean_multiline(_get_if_exists(event, "summary", None), _MAX_CELL_LENGTH)
        actor_username = _str_or_none(_get_if_exists(event, "actor_username", None)) or "system"

        rendered = ReportRow(
            f"{action} · {actor_username}",
            summary or "no summary recorded",
            evidence_refs=[_clean_text(event.id, 128)],
        )

        event_rows.append(rendered)

        if action.endswith("note_add") or action == "case_note":
            note_rows.append(rendered)

    if not event_rows:
        event_rows.append(ReportRow("Case events", "No persisted case events were found."))

    if not note_rows:
        note_rows.append(ReportRow("Case notes", "No persisted case notes were found."))

    sections.append(
        ReportSection(
            key="case_notes",
            title="Case notes",
            rows=note_rows,
            item_count=len(note_rows),
            truncated=event_total > len(events),
        )
    )

    sections.append(
        ReportSection(
            key="case_history",
            title="Case history",
            rows=event_rows,
            item_count=len(event_rows),
            truncated=event_total > len(events),
            evidence_refs=_safe_string_list(
                [row.evidence_refs[0] for row in event_rows if row.evidence_refs]
            ),
            note=(
                "Case history is append-only. Reopening and corrections append "
                "events rather than deleting prior history."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Finalise
    # ------------------------------------------------------------------
    estimated_pages = _estimate_pages(sections)

    if estimated_pages > page_limit:
        raise ReportGenerationError(
            "Report exceeds the configured page limit. Narrow the case scope or raise the limit.",
            details={
                "case_id": case_id,
                "estimated_pages": estimated_pages,
                "page_limit": page_limit,
            },
        )

    return ReportDocument(
        case_id=case_id,
        case_title=case_title,
        generated_at=_now_utc(),
        generated_by=_clean_text(actor.username, 100) or "system",
        timezone_label=timezone_label,
        sections=sections,
        evidence_index=evidence_index,
        disclaimer=_clean_multiline(
            _setting(settings, "REPORT_DISCLAIMER_TEXT", _DEFAULT_DISCLAIMER)
            or _DEFAULT_DISCLAIMER,
            _MAX_STRING_LENGTH,
        ),
        limitations=_clean_multiline(
            _setting(settings, "REPORT_LIMITATIONS_TEXT", _DEFAULT_LIMITATIONS)
            or _DEFAULT_LIMITATIONS,
            _MAX_STRING_LENGTH,
        ),
        footer=_clean_text(
            _setting(settings, "REPORT_FOOTER_TEXT", _DEFAULT_FOOTER) or _DEFAULT_FOOTER,
            200,
        ),
        caveats=list(_REPORT_CAVEATS),
        evidence_total=evidence_total,
        evidence_truncated=evidence_total > len(evidences),
        estimated_pages=estimated_pages,
        page_limit=page_limit,
        generation_seconds=round(time.monotonic() - started_at, 3),
        item_limit=max_items,
    )


# -----------------------------------------------------------------------------
# PDF renderer
# -----------------------------------------------------------------------------


def _render_pdf(document: ReportDocument) -> bytes:
    """
    Render a report document to PDF bytes using ReportLab.

    Fails honestly with ServiceUnavailableError when the renderer is not
    installed rather than emitting an empty or placeholder document.
    """
    try:
        from io import BytesIO

        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except Exception as exc:
        logger.exception("Report renderer is unavailable.")
        raise ServiceUnavailableError(
            "PDF report generation is unavailable because the renderer dependency is not installed.",
            details={
                "renderer": "reportlab",
                "error_type": type(exc).__name__,
                "setting": "REPORT_ENGINE",
            },
        ) from exc

    try:
        buffer = BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=20 * mm,
            rightMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
            title=f"MULEGUARD Investigation Report - {document.case_id}",
            author="MULEGUARD",
            subject="Synthetic investigation prototype",
            keywords="synthetic,prototype,investigation",
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "MuleGuardTitle",
            parent=styles["Title"],
            fontSize=18,
            leading=22,
            alignment=TA_LEFT,
        )
        subtitle_style = ParagraphStyle(
            "MuleGuardSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#444444"),
        )
        heading_style = ParagraphStyle(
            "MuleGuardHeading",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            spaceBefore=10,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "MuleGuardBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
        )
        note_style = ParagraphStyle(
            "MuleGuardNote",
            parent=styles["Italic"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#555555"),
        )
        disclaimer_style = ParagraphStyle(
            "MuleGuardDisclaimer",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#7A0000"),
        )

        def _footer(canvas: Any, _doc: Any) -> None:
            """
            Draw a synthetic-data watermark and footer on every page.
            """
            canvas.saveState()
            canvas.setFont("Helvetica-Oblique", 7)
            canvas.setFillColor(colors.HexColor("#888888"))
            canvas.drawCentredString(
                A4[0] / 2.0,
                12 * mm,
                document.footer or _DEFAULT_FOOTER,
            )
            canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Page {canvas.getPageNumber()}")
            canvas.restoreState()

        story: list[Any] = []

        story.append(Paragraph("MULEGUARD Investigation Report", title_style))
        story.append(
            Paragraph(
                (
                    f"Case {document.case_id} · Generated "
                    f"{document.generated_at.isoformat()} · "
                    f"Generated by {document.generated_by}"
                ),
                subtitle_style,
            )
        )
        story.append(Paragraph(document.disclaimer, disclaimer_style))
        story.append(Spacer(1, 6 * mm))

        for section in document.sections:
            story.append(Paragraph(section.title, heading_style))

            if section.narrative:
                story.append(Paragraph(section.narrative, body_style))

            if section.rows:
                data: list[list[str]] = [["Item", "Detail"]]

                for row in section.rows:
                    data.append(
                        [
                            _clean_text(row.label, _MAX_CELL_LENGTH),
                            _clean_text(row.value, _MAX_CELL_LENGTH),
                        ]
                    )

                table = Table(data, colWidths=[55 * mm, 115 * mm], repeatRows=1)
                table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEEEEE")),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("LEADING", (0, 0), (-1, -1), 10),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#BBBBBB")),
                            ("LEFTPADDING", (0, 0), (-1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                            ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ]
                    )
                )

                story.append(table)

            if section.truncated:
                story.append(
                    Paragraph(
                        "Section truncated by configured report limits.",
                        note_style,
                    )
                )

            if section.note:
                story.append(Paragraph(section.note, note_style))

            story.append(Spacer(1, 4 * mm))

        if document.evidence_index:
            story.append(Paragraph("Evidence reference index", heading_style))

            evidence_data: list[list[str]] = [["Evidence reference", "Description"]]

            for row in document.evidence_index:
                evidence_data.append(
                    [
                        _clean_text(row.label, _MAX_CELL_LENGTH),
                        _clean_text(row.value, _MAX_CELL_LENGTH),
                    ]
                )

            evidence_table = Table(evidence_data, colWidths=[55 * mm, 115 * mm], repeatRows=1)
            evidence_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEEEEE")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#BBBBBB")),
                    ]
                )
            )

            story.append(evidence_table)
            story.append(Spacer(1, 4 * mm))

        story.append(Paragraph("Limitations", heading_style))
        story.append(Paragraph(document.limitations, body_style))

        if document.evidence_truncated:
            story.append(
                Paragraph(
                    "Evidence references were truncated by configured report limits.",
                    note_style,
                )
            )

        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)

        return buffer.getvalue()

    except Exception as exc:
        logger.exception("Report rendering failed.")
        raise ReportGenerationError(
            "PDF report generation failed.",
            details={
                "case_id": _clean_text(document.case_id, 128),
                "error_type": type(exc).__name__,
            },
        ) from exc


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class ReportSectionSummary(BaseModel):
    """
    Safe report section summary.
    """

    model_config = ConfigDict(from_attributes=False)

    key: str
    title: str
    item_count: int = 0
    truncated: bool = False
    note: Optional[str] = None
    evidence_refs: list[str] = Field(default_factory=list)


class ReportRowModel(BaseModel):
    """
    Safe report row.
    """

    model_config = ConfigDict(from_attributes=False)

    label: str
    value: str
    evidence_refs: list[str] = Field(default_factory=list)


class ReportPreviewResponse(BaseModel):
    """
    JSON preview of a report that would be generated.
    """

    model_config = ConfigDict(from_attributes=False)

    case_id: str
    case_title: str
    generated_at: datetime
    generated_by: str
    timezone_label: str
    sections: list[ReportRowModel] = Field(default_factory=list)
    section_summaries: list[ReportSectionSummary] = Field(default_factory=list)
    evidence_index: list[ReportRowModel] = Field(default_factory=list)
    evidence_total: int = 0
    evidence_truncated: bool = False
    estimated_pages: int = 0
    page_limit: int = 0
    item_limit: int = 0
    generation_seconds: float = 0.0
    disclaimer: str = ""
    limitations: str = ""
    footer: str = ""
    caveats: list[str] = Field(default_factory=list)


class ReportEvidenceIndexResponse(BaseModel):
    """
    Bounded evidence reference index for one case.
    """

    model_config = ConfigDict(from_attributes=False)

    case_id: str
    items: list[ReportRowModel] = Field(default_factory=list)
    page: int = 1
    page_size: int = 50
    total: int = 0
    total_pages: int = 0
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ReportGenerateResponse(BaseModel):
    """
    Metadata for a generated PDF report. Binary content is not returned.
    """

    model_config = ConfigDict(from_attributes=False)

    case_id: str
    case_title: str
    filename: str
    content_type: str = "application/pdf"
    size_bytes: int = 0
    sha256: str = ""
    generated_at: datetime
    generated_by: str
    sections: list[ReportSectionSummary] = Field(default_factory=list)
    evidence_total: int = 0
    evidence_truncated: bool = False
    estimated_pages: int = 0
    page_limit: int = 0
    item_limit: int = 0
    generation_seconds: float = 0.0
    renderer: str = "reportlab"
    caveats: list[str] = Field(default_factory=list)


class ReportLimitationsResponse(BaseModel):
    """
    Safe static limitations and disclaimer text.
    """

    model_config = ConfigDict(from_attributes=False)

    disclaimer: str = ""
    limitations: str = ""
    footer: str = ""
    caveats: list[str] = Field(default_factory=list)


class ReportStatusResponse(BaseModel):
    """
    Safe report subsystem status response.
    """

    model_config = ConfigDict(from_attributes=False)

    enabled: bool
    renderer_available: bool
    renderer: str
    max_items_per_section: int
    max_pages: int
    max_generation_seconds: int
    filename_prefix: str
    timezone_label: str
    include_disclaimer: bool
    include_limitations: bool
    include_evidence_index: bool
    audit_generation: bool
    audit_preview: bool
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Response builders
# -----------------------------------------------------------------------------


def _section_summaries(document: ReportDocument) -> list[ReportSectionSummary]:
    """
    Build safe section summaries.
    """
    return [
        ReportSectionSummary(
            key=section.key,
            title=_clean_text(section.title, 200),
            item_count=int(section.item_count),
            truncated=bool(section.truncated),
            note=_clean_text(section.note, 500) if section.note else None,
            evidence_refs=_safe_string_list(section.evidence_refs),
        )
        for section in document.sections
    ]


def _row_models(rows: Sequence[ReportRow]) -> list[ReportRowModel]:
    """
    Convert internal rows into safe response rows.
    """
    return [
        ReportRowModel(
            label=_clean_text(row.label, _MAX_CELL_LENGTH),
            value=_clean_text(row.value, _MAX_CELL_LENGTH),
            evidence_refs=_safe_string_list(row.evidence_refs),
        )
        for row in rows
    ]


def _preview_response(document: ReportDocument) -> ReportPreviewResponse:
    """
    Build a JSON preview from a report document.
    """
    flattened: list[ReportRow] = []

    for section in document.sections:
        if section.narrative:
            flattened.append(
                ReportRow(
                    label=f"{section.title} · overview",
                    value=_clean_text(section.narrative, _MAX_CELL_LENGTH),
                )
            )

        flattened.extend(section.rows)

    return ReportPreviewResponse(
        case_id=_clean_text(document.case_id, 128),
        case_title=_clean_text(document.case_title, 200),
        generated_at=document.generated_at,
        generated_by=_clean_text(document.generated_by, 100),
        timezone_label=_clean_text(document.timezone_label, 64),
        sections=_row_models(flattened),
        section_summaries=_section_summaries(document),
        evidence_index=_row_models(document.evidence_index),
        evidence_total=int(document.evidence_total),
        evidence_truncated=bool(document.evidence_truncated),
        estimated_pages=int(document.estimated_pages),
        page_limit=int(document.page_limit),
        item_limit=int(document.item_limit),
        generation_seconds=float(document.generation_seconds),
        disclaimer=_clean_multiline(document.disclaimer),
        limitations=_clean_multiline(document.limitations),
        footer=_clean_text(document.footer, 200),
        caveats=list(document.caveats),
    )


def _audit_report_action(
    db: Session,
    request: Request,
    settings: Any,
    actor: User,
    request_id: str,
    *,
    action: str,
    document: ReportDocument,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    extra_metadata: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Record a safe audit event for a material report action.
    """
    metadata: dict[str, Any] = {
        "case_id": _clean_text(document.case_id, 128),
        "estimated_pages": int(document.estimated_pages),
        "page_limit": int(document.page_limit),
        "item_limit": int(document.item_limit),
        "generation_seconds": float(document.generation_seconds),
        "section_count": len(document.sections),
        "evidence_total": int(document.evidence_total),
        "evidence_truncated": bool(document.evidence_truncated),
    }

    if extra_metadata:
        metadata.update(_sanitize_json_object(dict(extra_metadata)))

    _add_audit_event(
        db,
        action=_clean_text(action, 100),
        outcome=outcome,
        request_id=request_id,
        actor=actor,
        resource_type="investigation_case",
        resource_id=_clean_text(document.case_id, 128),
        ip_hash=_ip_hash(request, settings),
        metadata=metadata,
    )


def _prepare_document(
    db: Session,
    settings: Any,
    actor: User,
    case_id: str,
) -> tuple[InvestigationCase, ReportDocument]:
    """
    Load a case and build a bounded report document.
    """
    _ensure_reports_enabled(settings)

    case = _get_case_or_404(db, case_id)

    document = _build_report_document(
        db,
        settings,
        case,
        actor,
        max_items=_max_items_per_section(settings),
        page_limit=_max_pages(settings),
        max_seconds=_max_generation_seconds(settings),
        timezone_label=_report_timezone_label(settings),
    )

    return case, document


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=ReportStatusResponse,
    summary="Get report subsystem status",
    description=(
        "Returns safe report subsystem status, including renderer availability "
        "and bounded generation limits. This endpoint does not expose secrets, "
        "database URLs, tokens, passwords, raw complaint narratives, or real "
        "customer data."
    ),
)
def report_status(
    settings: SettingsDep,
    _: User = Depends(require_permission(REPORT_READ_PERMISSION)),
) -> ReportStatusResponse:
    """
    Return safe report subsystem status.
    """
    _ensure_reports_enabled(settings)

    return ReportStatusResponse(
        enabled=True,
        renderer_available=_render_pdf_available(),
        renderer=_clean_text(
            _setting(settings, "REPORT_ENGINE", "reportlab") or "reportlab",
            50,
        ),
        max_items_per_section=_max_items_per_section(settings),
        max_pages=_max_pages(settings),
        max_generation_seconds=_max_generation_seconds(settings),
        filename_prefix=_filename_prefix(settings),
        timezone_label=_report_timezone_label(settings),
        include_disclaimer=_as_bool(
            _setting(settings, "REPORT_INCLUDE_SYNTHETIC_DISCLAIMER", True),
            True,
        ),
        include_limitations=_as_bool(
            _setting(settings, "REPORT_INCLUDE_LIMITATIONS", True),
            True,
        ),
        include_evidence_index=_as_bool(
            _setting(settings, "REPORT_INCLUDE_EVIDENCE_INDEX", True),
            True,
        ),
        audit_generation=_as_bool(
            _setting(settings, "REPORT_AUDIT_GENERATION", True),
            True,
        ),
        audit_preview=_as_bool(
            _setting(settings, "REPORT_AUDIT_PREVIEW", False),
            False,
        ),
        caveats=list(_REPORT_CAVEATS),
    )


@router.get(
    "/limitations",
    response_model=ReportLimitationsResponse,
    summary="Get report limitations and disclaimer text",
    description=(
        "Returns the configured synthetic-data disclaimer, limitations, and "
        "footer text that MULEGUARD embeds in investigation reports. These "
        "texts describe what reports must not be used for."
    ),
)
def report_limitations(
    settings: SettingsDep,
    _: User = Depends(require_permission(REPORT_READ_PERMISSION)),
) -> ReportLimitationsResponse:
    """
    Return safe report limitations text.
    """
    _ensure_reports_enabled(settings)

    return ReportLimitationsResponse(
        disclaimer=_clean_multiline(
            _setting(settings, "REPORT_DISCLAIMER_TEXT", _DEFAULT_DISCLAIMER)
            or _DEFAULT_DISCLAIMER
        ),
        limitations=_clean_multiline(
            _setting(settings, "REPORT_LIMITATIONS_TEXT", _DEFAULT_LIMITATIONS)
            or _DEFAULT_LIMITATIONS
        ),
        footer=_clean_text(
            _setting(settings, "REPORT_FOOTER_TEXT", _DEFAULT_FOOTER) or _DEFAULT_FOOTER,
            200,
        ),
        caveats=list(_REPORT_CAVEATS),
    )


@router.get(
    "/cases/{case_id}/preview",
    response_model=ReportPreviewResponse,
    summary="Preview a bounded case investigation report",
    description=(
        "Returns a JSON preview of the report that would be generated for one "
        "synthetic MULEGUARD case. The preview is built exclusively from "
        "persisted records and never contains raw complaint narratives."
    ),
)
def preview_case_report(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(REPORT_READ_PERMISSION)),
) -> ReportPreviewResponse:
    """
    Preview one case report.
    """
    _case, document = _prepare_document(db, settings, actor, case_id)

    if _as_bool(_setting(settings, "REPORT_AUDIT_PREVIEW", False), False):
        _audit_report_action(
            db,
            request,
            settings,
            actor,
            request_id,
            action="report_preview",
            document=document,
        )
        db.commit()

    return _preview_response(document)


@router.get(
    "/cases/{case_id}/evidence-index",
    response_model=ReportEvidenceIndexResponse,
    summary="List the bounded evidence reference index for a case",
    description=(
        "Returns a paginated, bounded index of active evidence references for "
        "one synthetic MULEGUARD case. Evidence references point to validated "
        "persisted records and are investigative leads only."
    ),
)
def case_evidence_index(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(evidence_pagination),
    _: User = Depends(require_permission(REPORT_READ_PERMISSION)),
    evidence_type: Annotated[
        Optional[str],
        Query(max_length=100, description="Filter by evidence type."),
    ] = None,
    include_inactive: Annotated[
        bool,
        Query(description="Include deactivated evidence references."),
    ] = False,
) -> ReportEvidenceIndexResponse:
    """
    Return the bounded evidence reference index for one case.
    """
    _ensure_reports_enabled(settings)

    _get_case_or_404(db, case_id)

    case_id_column = _model_column(CaseEvidence, "case_id")

    if case_id_column is None:
        return ReportEvidenceIndexResponse(
            case_id=_clean_text(case_id, 128),
            items=[],
            page=params.page,
            page_size=params.page_size,
            total=0,
            total_pages=0,
            sort_by=params.sort_by,
            sort_order=params.sort_order,
            caveats=[
                *_REPORT_CAVEATS,
                "Case evidence linkage is not available in this schema.",
            ],
        )

    conditions: list[Any] = [case_id_column == case_id]

    if evidence_type:
        type_column = _model_column(CaseEvidence, "evidence_type")

        if type_column is not None:
            conditions.append(type_column == evidence_type.strip())

    active_column = _model_column(CaseEvidence, "is_active")

    if active_column is not None and not include_inactive:
        conditions.append(active_column.is_(True))

    total = _scalar_count(
        db,
        _apply(select(func.count()).select_from(CaseEvidence), conditions),
    )

    stmt = select(CaseEvidence)
    stmt = _apply(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_EVIDENCE_COLUMN_MAP,
        tiebreaker=_model_column(CaseEvidence, "id"),
        default_sort_by=_EVIDENCE_DEFAULT_SORT,
        default_sort_order="desc",
    )

    rows = db.scalars(stmt).all()

    items: list[ReportRowModel] = []

    for evidence in rows:
        evidence_type_value = (
            _enum_str(_get_if_exists(evidence, "evidence_type", None)) or "UNKNOWN"
        )
        reference = (
            _clean_text(_get_if_exists(evidence, "evidence_id", None), 128) or "n/a"
        )

        items.append(
            ReportRowModel(
                label=_clean_text(evidence.id, 128),
                value=f"{evidence_type_value} · {reference}",
                evidence_refs=[reference],
            )
        )

    return ReportEvidenceIndexResponse(
        case_id=_clean_text(case_id, 128),
        items=items,
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_REPORT_CAVEATS),
    )


@router.get(
    "/cases/{case_id}",
    response_model=None,
    summary="Generate and download a case investigation report",
    description=(
        "Generates a bounded PDF investigation report for one synthetic "
        "MULEGUARD case and returns it as a download. The report is built "
        "exclusively from persisted records, includes synthetic-data "
        "disclaimers and limitations, and never contains raw complaint "
        "narratives. The download is audited."
    ),
)
def download_case_report(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(REPORT_DOWNLOAD_PERMISSION)),
) -> Response:
    """
    Generate and download one case report.
    """
    _case, document = _prepare_document(db, settings, actor, case_id)

    pdf_bytes = _render_pdf(document)
    content_digest = _sha256_bytes(pdf_bytes)

    filename = _build_filename(
        document.case_id,
        document.generated_at,
        content_digest,
        settings,
    )

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Security-Policy": "default-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Report-Case-Id": _clean_text(document.case_id, 128),
        "X-Report-Generated-At": document.generated_at.isoformat(),
        "X-Report-SHA256": content_digest,
        "X-Report-Estimated-Pages": str(int(document.estimated_pages)),
        "X-Report-Evidence-Total": str(int(document.evidence_total)),
        "Cache-Control": "no-store",
    }

    if request_id:
        headers["X-Request-ID"] = _clean_text(request_id, 64)

    _audit_report_action(
        db,
        request,
        settings,
        actor,
        request_id,
        action="report_download",
        document=document,
        extra_metadata={
            "filename": filename,
            "size_bytes": len(pdf_bytes),
            "sha256": content_digest,
        },
    )

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to persist report download audit event.")
        raise ReportGenerationError(
            "Report could not be completed because the audit record could not be persisted.",
            details={"case_id": _clean_text(document.case_id, 128)},
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers=headers,
    )


@router.post(
    "/cases/{case_id}/generate",
    response_model=ReportGenerateResponse,
    summary="Generate a case report and return metadata only",
    description=(
        "Generates a bounded PDF investigation report for one synthetic "
        "MULEGUARD case and returns only safe metadata, including filename, "
        "size, SHA-256 digest, section summaries, and bounds. Binary PDF "
        "content is not returned. The generation is audited."
    ),
)
def generate_case_report(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Investigation case identifier."),
    ],
    request: Request,
    response: Response,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    actor: User = Depends(require_permission(REPORT_GENERATE_PERMISSION)),
) -> ReportGenerateResponse:
    """
    Generate one case report and return metadata only.
    """
    _ensure_reports_enabled(settings)

    if not _render_pdf_available():
        raise ServiceUnavailableError(
            "PDF report generation is unavailable because the renderer dependency is not installed.",
            details={
                "renderer": "reportlab",
                "setting": "REPORT_ENGINE",
            },
        )

    _case, document = _prepare_document(db, settings, actor, case_id)

    pdf_bytes = _render_pdf(document)
    content_digest = _sha256_bytes(pdf_bytes)

    filename = _build_filename(
        document.case_id,
        document.generated_at,
        content_digest,
        settings,
    )

    _audit_report_action(
        db,
        request,
        settings,
        actor,
        request_id,
        action="report_generate",
        document=document,
        extra_metadata={
            "filename": filename,
            "size_bytes": len(pdf_bytes),
            "sha256": content_digest,
        },
    )

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to persist report generation audit event.")
        raise ReportGenerationError(
            "Report could not be generated because the audit record could not be persisted.",
            details={"case_id": _clean_text(document.case_id, 128)},
        )

    response.status_code = 201

    return ReportGenerateResponse(
        case_id=_clean_text(document.case_id, 128),
        case_title=_clean_text(document.case_title, 200),
        filename=filename,
        content_type="application/pdf",
        size_bytes=len(pdf_bytes),
        sha256=content_digest,
        generated_at=document.generated_at,
        generated_by=_clean_text(document.generated_by, 100),
        sections=_section_summaries(document),
        evidence_total=int(document.evidence_total),
        evidence_truncated=bool(document.evidence_truncated),
        estimated_pages=int(document.estimated_pages),
        page_limit=int(document.page_limit),
        item_limit=int(document.item_limit),
        generation_seconds=float(document.generation_seconds),
        renderer=_clean_text(
            _setting(settings, "REPORT_ENGINE", "reportlab") or "reportlab",
            50,
        ),
        caveats=list(_REPORT_CAVEATS),
    )


__all__ = [
    "router",
]