"""
MULEGUARD backend API v1 graph endpoints.

This module implements the versioned `/api/v1/graph` read-only investigation
surface for synthetic MULEGUARD graph-style relationship exploration.

Implemented endpoints:

- GET /api/v1/graph/status
- GET /api/v1/graph/subgraph
- GET /api/v1/graph/paths
- GET /api/v1/graph/shared-entities
- GET /api/v1/graph/money-trails

Design goals:

- provide bounded, persisted, evidence-backed graph exploration over synthetic
  MULEGUARD accounts, transactions, entities, complaints, alerts, and
  assessments;
- enforce server-side RBAC through dependency permissions;
- keep graph queries strictly bounded by depth, node count, edge count, path
  count, trail count, date span, and amount filters;
- preserve exact-vs-inferred provenance for entity links and complaint
  correlations;
- avoid exposing raw identifier hashes, raw complaint narratives, synthetic
  ground-truth labels, scenario IDs, ring IDs, passwords, tokens, secrets,
  database URLs, model artifact paths, or real customer data;
- make clear that graph relationships, candidate money trails, shared entities,
  alerts, scores, and complaint correlations are investigative leads only.

Explicit non-goals:

- This module does not create, update, delete, freeze, block, blacklist, close,
  restrict, or otherwise take adverse action against accounts or customers.
- This module does not connect to real banking systems.
- This module does not compute ML scores inline.
- This module does not claim that graph proximity, shared devices, shared
  entities, candidate money trails, or complaint correlations prove common
  control, intent, or wrongdoing.
- This module does not allow manual attachment of graph-path evidence; graph
  evidence must be produced by the bounded graph service.
- This module does not claim production readiness or real-world fraud-detection
  accuracy.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, and case dispositions are investigative leads or human workflow
artefacts only. They are not proof of wrongdoing and must not trigger automatic
adverse customer action.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Final, Literal, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    AmountRangeParams,
    DateRangeParams,
    Permission,
    SessionDep,
    SettingsDep,
    amount_range_dependency,
    date_range_dependency,
    require_permission,
)
from app.exceptions import (
    FeatureFlagDisabledError,
    NotFoundError,
    ValidationError as MuleGuardValidationError,
)
from app.models import (
    Account,
    AccountEntityLink,
    Alert,
    Complaint,
    ComplaintCorrelation,
    Entity,
    EntityType,
    MatchMethod,
    ModelAssessment,
    Transaction,
    User,
    VerificationState,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.graph")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["graph"])


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_MAPPING_KEYS: Final[int] = 100
_MAX_JSON_DEPTH: Final[int] = 6

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

_NODE_ACCOUNT: Final[str] = "account"
_NODE_TRANSACTION: Final[str] = "transaction"
_NODE_ENTITY: Final[str] = "entity"
_NODE_COMPLAINT: Final[str] = "complaint"
_NODE_ALERT: Final[str] = "alert"
_NODE_ASSESSMENT: Final[str] = "assessment"

_EDGE_SENT: Final[str] = "sent"
_EDGE_RECEIVED: Final[str] = "received"
_EDGE_LINKED_TO: Final[str] = "linked_to"
_EDGE_RELATED_TO: Final[str] = "related_to"
_EDGE_CORRELATED_WITH: Final[str] = "correlated_with"
_EDGE_ALERTED_ON: Final[str] = "alerted_on"
_EDGE_ASSESSED_BY: Final[str] = "assessed_by"

_GRAPH_HARD_MAX_NODES: Final[int] = 1_000
_GRAPH_HARD_MAX_EDGES: Final[int] = 2_000
_GRAPH_HARD_MAX_DEPTH: Final[int] = 5
_GRAPH_HARD_MAX_PATHS: Final[int] = 100
_GRAPH_HARD_MAX_TRAILS: Final[int] = 100
_GRAPH_HARD_MAX_SHARED_GROUPS: Final[int] = 100
_GRAPH_HARD_MAX_ACCOUNTS_PER_ENTITY: Final[int] = 100
_GRAPH_HARD_MAX_DATE_SPAN_DAYS: Final[int] = 3_650

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

_GRAPH_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Graph relationships are investigative leads only and are not proof of common control or wrongdoing.",
    "Shared devices, phones, UPI IDs, emails, addresses, IPs, or other entities are associations only.",
    "Candidate money trails are heuristic flow views only and are not proof of layering, integration, or wrongdoing.",
    "Alerts, risk scores, complaint correlations, and entity links are investigative leads only.",
    "Risk scores are investigative priority scores, not probabilities of guilt.",
    "Heuristic fallback scores are not calibrated model probabilities.",
    "Raw identifier hashes are intentionally not returned.",
    "Raw and normalized complaint narratives are intentionally not returned.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    "This API does not freeze, block, blacklist, close, restrict, or otherwise take adverse action against accounts or customers.",
    "Graph queries are bounded by configured depth, node, edge, path, trail, date-span, and amount limits.",
)

_PATH_CAVEATS: Final[tuple[str, ...]] = (
    *_GRAPH_CAVEATS,
    "Returned paths are candidate directed or bidirectional transaction walks only.",
    "Path ordering is heuristic and must not be interpreted as legal, evidentiary, or causal priority.",
    "Mixed-currency path totals are reported per currency and are not converted.",
)

_SHARED_CAVEATS: Final[tuple[str, ...]] = (
    *_GRAPH_CAVEATS,
    "Shared-entity groups are association clusters only.",
    "Shared entities may arise from benign device sharing, NAT, public Wi-Fi, test data, or synthetic generation artifacts.",
)

_TRAIL_CAVEATS: Final[tuple[str, ...]] = (
    *_GRAPH_CAVEATS,
    "Candidate money trails are bounded transaction-flow explorations only.",
    "Trail scoring is heuristic and must not be used for automatic adverse action.",
    "Mixed-currency trail totals are reported per currency and are not converted.",
)


# -----------------------------------------------------------------------------
# Dynamic column helpers
# -----------------------------------------------------------------------------


def _column(model: Any, name: str) -> Any | None:
    """
    Return a SQLAlchemy column attribute when present.
    """
    return getattr(model, name, None)


def _first_column(model: Any, *names: str) -> Any | None:
    """
    Return the first existing column attribute among names.
    """
    for name in names:
        column = _column(model, name)

        if column is not None:
            return column

    return None


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
        text = _clean_text(item, _MAX_STRING_LENGTH)

        if not text:
            continue

        if text in seen:
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
    Convert an arbitrary JSON-like value into a safe response value.
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
    Return a sanitized JSON object suitable for API responses.
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
    Sanitize metadata_json-like values before returning them in API responses.
    """
    if isinstance(value, Mapping):
        return _sanitize_json_object(value)

    if value is None:
        return None

    return _sanitize_json_value(value)


def _is_exact_match(value: Any) -> bool:
    """
    Return True when a match-method-like value indicates exact matching.
    """
    return _enum_str(value) == "EXACT"


def _account_node_id(account_id: Any) -> str:
    """
    Return a stable graph node identifier for an account.
    """
    return f"{_NODE_ACCOUNT}:{_clean_text(account_id, 128)}"


def _transaction_node_id(transaction_id: Any) -> str:
    """
    Return a stable graph node identifier for a transaction.
    """
    return f"{_NODE_TRANSACTION}:{_clean_text(transaction_id, 128)}"


def _entity_node_id(entity_id: Any) -> str:
    """
    Return a stable graph node identifier for an entity.
    """
    return f"{_NODE_ENTITY}:{_clean_text(entity_id, 128)}"


def _complaint_node_id(complaint_id: Any) -> str:
    """
    Return a stable graph node identifier for a complaint.
    """
    return f"{_NODE_COMPLAINT}:{_clean_text(complaint_id, 128)}"


def _alert_node_id(alert_id: Any) -> str:
    """
    Return a stable graph node identifier for an alert.
    """
    return f"{_NODE_ALERT}:{_clean_text(alert_id, 128)}"


def _assessment_node_id(assessment_id: Any) -> str:
    """
    Return a stable graph node identifier for an assessment.
    """
    return f"{_NODE_ASSESSMENT}:{_clean_text(assessment_id, 128)}"


def _stable_hash(values: Sequence[str]) -> str:
    """
    Return a stable short hash for path/trail identifiers.
    """
    payload = "|".join(values).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


def _order_stmt(stmt: Any, specs: Sequence[tuple[Any, bool]]) -> Any:
    """
    Apply safe ordering specifications, skipping missing columns.
    """
    for column, ascending in specs:
        if column is None:
            continue

        stmt = stmt.order_by(column.asc() if ascending else column.desc())

    return stmt


def _apply(stmt: Any, conditions: list[Any]) -> Any:
    """
    Apply a list of SQLAlchemy conditions to a statement.
    """
    if conditions:
        stmt = stmt.where(and_(*conditions))

    return stmt


def _count(db: Session, model: Any, conditions: list[Any]) -> int:
    """
    Return a bounded count for a model under conditions.
    """
    stmt = select(func.count()).select_from(model)
    stmt = _apply(stmt, conditions)
    return int(db.scalar(stmt) or 0)


# -----------------------------------------------------------------------------
# Graph limits and policy helpers
# -----------------------------------------------------------------------------


def _graph_limits(settings: Any) -> dict[str, int]:
    """
    Return bounded graph policy limits.
    """
    max_nodes = max(
        1,
        min(
            _as_int(_setting(settings, "GRAPH_MAX_NODES", 250), 250),
            _GRAPH_HARD_MAX_NODES,
        ),
    )
    max_edges = max(
        1,
        min(
            _as_int(_setting(settings, "GRAPH_MAX_EDGES", 500), 500),
            _GRAPH_HARD_MAX_EDGES,
        ),
    )
    max_depth = max(
        1,
        min(
            _as_int(_setting(settings, "GRAPH_MAX_DEPTH", 3), 3),
            _GRAPH_HARD_MAX_DEPTH,
        ),
    )
    max_paths = max(
        1,
        min(
            _as_int(_setting(settings, "GRAPH_MAX_PATHS", 25), 25),
            _GRAPH_HARD_MAX_PATHS,
        ),
    )
    max_trails = max(
        1,
        min(
            _as_int(_setting(settings, "GRAPH_MAX_TRAILS", 25), 25),
            _GRAPH_HARD_MAX_TRAILS,
        ),
    )
    max_shared_groups = max(
        1,
        min(
            _as_int(_setting(settings, "GRAPH_MAX_SHARED_GROUPS", 25), 25),
            _GRAPH_HARD_MAX_SHARED_GROUPS,
        ),
    )
    max_accounts_per_entity = max(
        1,
        min(
            _as_int(_setting(settings, "GRAPH_MAX_ACCOUNTS_PER_ENTITY", 25), 25),
            _GRAPH_HARD_MAX_ACCOUNTS_PER_ENTITY,
        ),
    )
    max_date_span_days = max(
        1,
        min(
            _as_int(_setting(settings, "GRAPH_MAX_DATE_SPAN_DAYS", 365), 365),
            _GRAPH_HARD_MAX_DATE_SPAN_DAYS,
        ),
    )

    return {
        "max_nodes": max_nodes,
        "hard_max_nodes": _GRAPH_HARD_MAX_NODES,
        "max_edges": max_edges,
        "hard_max_edges": _GRAPH_HARD_MAX_EDGES,
        "max_depth": max_depth,
        "hard_max_depth": _GRAPH_HARD_MAX_DEPTH,
        "max_paths": max_paths,
        "hard_max_paths": _GRAPH_HARD_MAX_PATHS,
        "max_trails": max_trails,
        "hard_max_trails": _GRAPH_HARD_MAX_TRAILS,
        "max_shared_groups": max_shared_groups,
        "hard_max_shared_groups": _GRAPH_HARD_MAX_SHARED_GROUPS,
        "max_accounts_per_entity": max_accounts_per_entity,
        "hard_max_accounts_per_entity": _GRAPH_HARD_MAX_ACCOUNTS_PER_ENTITY,
        "max_date_span_days": max_date_span_days,
        "hard_max_date_span_days": _GRAPH_HARD_MAX_DATE_SPAN_DAYS,
    }


def _clamp_limits(
    settings: Any,
    *,
    max_nodes: Optional[int] = None,
    max_edges: Optional[int] = None,
    depth: Optional[int] = None,
    paths: Optional[int] = None,
    trails: Optional[int] = None,
    groups: Optional[int] = None,
    accounts_per_entity: Optional[int] = None,
) -> dict[str, int]:
    """
    Return configured graph limits clamped by request overrides and hard caps.
    """
    limits = _graph_limits(settings)

    if max_nodes is not None:
        limits["max_nodes"] = max(1, min(int(max_nodes), limits["hard_max_nodes"]))

    if max_edges is not None:
        limits["max_edges"] = max(1, min(int(max_edges), limits["hard_max_edges"]))

    if depth is not None:
        limits["max_depth"] = max(1, min(int(depth), limits["hard_max_depth"]))

    if paths is not None:
        limits["max_paths"] = max(1, min(int(paths), limits["hard_max_paths"]))

    if trails is not None:
        limits["max_trails"] = max(1, min(int(trails), limits["hard_max_trails"]))

    if groups is not None:
        limits["max_shared_groups"] = max(
            1,
            min(int(groups), limits["hard_max_shared_groups"]),
        )

    if accounts_per_entity is not None:
        limits["max_accounts_per_entity"] = max(
            1,
            min(int(accounts_per_entity), limits["hard_max_accounts_per_entity"]),
        )

    return limits


def _ensure_graph_enabled(settings: Any) -> None:
    """
    Fail closed when the graph API surface is disabled by configuration.
    """
    if not _as_bool(_setting(settings, "GRAPH_API_ENABLED", True), True):
        raise FeatureFlagDisabledError("Graph endpoints are disabled by configuration.")

    if not _as_bool(_setting(settings, "GRAPH_ENABLED", True), True):
        raise FeatureFlagDisabledError("Graph subsystem is disabled by configuration.")


def _validate_not_future(value: Optional[datetime], field_name: str) -> None:
    """
    Reject future point-in-time parameters.
    """
    if value is not None and value > _now_utc():
        raise MuleGuardValidationError(
            f"{field_name} must not be in the future.",
            details={field_name: value.isoformat()},
        )


def _validate_date_range(
    start: Optional[datetime],
    end: Optional[datetime],
) -> None:
    """
    Validate optional date-range ordering.
    """
    if start is not None and end is not None and start > end:
        raise MuleGuardValidationError(
            "date_from must be earlier than or equal to date_to.",
            details={
                "date_from": start.isoformat(),
                "date_to": end.isoformat(),
            },
        )


def _validate_span(
    start: Optional[datetime],
    end: Optional[datetime],
    max_span_days: int,
) -> None:
    """
    Enforce maximum date span for graph scans.
    """
    if start is None or end is None:
        return

    span = end - start
    max_delta = timedelta(days=max_span_days)

    if span > max_delta:
        raise MuleGuardValidationError(
            "Graph date span exceeds configured maximum.",
            details={
                "max_span_days": max_span_days,
                "requested_span_days": round(span.total_seconds() / 86400.0, 3),
            },
        )


def _validate_query_windows(
    *,
    date_range: DateRangeParams,
    amount_range: AmountRangeParams,
    as_of: Optional[datetime],
    settings: Any,
) -> tuple[Optional[datetime], Optional[datetime], Optional[datetime]]:
    """
    Validate and normalize graph query windows.
    """
    limits = _graph_limits(settings)

    date_from = _ensure_utc(date_range.date_from)
    date_to = _ensure_utc(date_range.date_to)
    normalized_as_of = _ensure_utc(as_of)

    _validate_not_future(normalized_as_of, "as_of")
    _validate_not_future(date_to, "date_to")
    _validate_date_range(date_from, date_to)
    _validate_span(date_from, date_to, limits["max_date_span_days"])

    if (
        amount_range.amount_min is not None
        and amount_range.amount_max is not None
        and amount_range.amount_min > amount_range.amount_max
    ):
        raise MuleGuardValidationError(
            "amount_min must be less than or equal to amount_max.",
            details={
                "amount_min": str(amount_range.amount_min),
                "amount_max": str(amount_range.amount_max),
            },
        )

    return date_from, date_to, normalized_as_of


# -----------------------------------------------------------------------------
# Lookup helpers
# -----------------------------------------------------------------------------


def _get_account_or_404(db: Session, account_id: str) -> Account:
    """
    Load a synthetic account or raise a safe not-found error.
    """
    account = db.get(Account, account_id)

    if account is None:
        raise NotFoundError.resource("account", account_id)

    return account


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class GraphNode(BaseModel):
    """
    Safe graph node.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    type: str
    label: str
    account_id: Optional[str] = None
    account_type: Optional[str] = None
    entity_type: Optional[str] = None
    source: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    state: Optional[str] = None
    score: Optional[Decimal] = None
    confidence: Optional[Decimal] = None
    match_method: Optional[str] = None
    deterministic: Optional[bool] = None
    review_state: Optional[str] = None
    verification_state: Optional[str] = None
    occurred_at: Optional[datetime] = None
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    reference: Optional[str] = None
    category: Optional[str] = None
    sender_account_id: Optional[str] = None
    receiver_account_id: Optional[str] = None
    narrative_available: Optional[bool] = None
    explanation_available: Optional[bool] = None
    metadata_json: Optional[Any] = None


class GraphEdge(BaseModel):
    """
    Safe graph edge.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    source: str
    target: str
    type: str
    label: Optional[str] = None
    transaction_id: Optional[str] = None
    account_id: Optional[str] = None
    entity_id: Optional[str] = None
    complaint_id: Optional[str] = None
    alert_id: Optional[str] = None
    assessment_id: Optional[str] = None
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    occurred_at: Optional[datetime] = None
    confidence: Optional[Decimal] = None
    match_method: Optional[str] = None
    deterministic: Optional[bool] = None
    review_state: Optional[str] = None
    verification_state: Optional[str] = None
    evidence_refs: list[str] = Field(default_factory=list)
    metadata_json: Optional[Any] = None


class GraphStats(BaseModel):
    """
    Safe graph response statistics.
    """

    model_config = ConfigDict(from_attributes=False)

    node_count: int = 0
    edge_count: int = 0
    truncated: bool = False
    depth_requested: int = 0
    max_nodes: int = 0
    max_edges: int = 0


class GraphResponse(BaseModel):
    """
    Safe bounded graph response.
    """

    model_config = ConfigDict(from_attributes=False)

    generated_at: datetime
    root_node_id: Optional[str] = None
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    stats: GraphStats
    caveats: list[str] = Field(default_factory=list)


class GraphPath(BaseModel):
    """
    Candidate graph path.
    """

    model_config = ConfigDict(from_attributes=False)

    path_id: str
    from_account_id: str
    to_account_id: str
    direction: str
    hop_count: int
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    amount_by_currency: dict[str, Decimal] = Field(default_factory=dict)
    earliest_at: Optional[datetime] = None
    latest_at: Optional[datetime] = None


class GraphPathsResponse(BaseModel):
    """
    Safe bounded graph paths response.
    """

    model_config = ConfigDict(from_attributes=False)

    generated_at: datetime
    from_account_id: str
    to_account_id: str
    direction: str
    max_depth: int
    paths: list[GraphPath] = Field(default_factory=list)
    truncated: bool = False
    caveats: list[str] = Field(default_factory=list)


class SharedEntityGroup(BaseModel):
    """
    Safe shared-entity association group.
    """

    model_config = ConfigDict(from_attributes=False)

    entity: GraphNode
    accounts: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    account_count: int = 0
    match_methods: list[str] = Field(default_factory=list)
    verification_states: list[str] = Field(default_factory=list)
    deterministic: bool = False
    min_confidence: Optional[Decimal] = None
    max_confidence: Optional[Decimal] = None


class SharedEntitiesResponse(BaseModel):
    """
    Safe bounded shared-entities response.
    """

    model_config = ConfigDict(from_attributes=False)

    generated_at: datetime
    root_account_id: str
    min_accounts: int
    max_groups: int
    max_accounts_per_entity: int
    groups: list[SharedEntityGroup] = Field(default_factory=list)
    truncated: bool = False
    caveats: list[str] = Field(default_factory=list)


class MoneyTrail(BaseModel):
    """
    Candidate money trail.
    """

    model_config = ConfigDict(from_attributes=False)

    trail_id: str
    root_account_id: str
    direction: str
    hop_count: int
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    amount_by_currency: dict[str, Decimal] = Field(default_factory=dict)
    earliest_at: Optional[datetime] = None
    latest_at: Optional[datetime] = None


class MoneyTrailsResponse(BaseModel):
    """
    Safe bounded money-trails response.
    """

    model_config = ConfigDict(from_attributes=False)

    generated_at: datetime
    root_account_id: str
    direction: str
    max_hops: int
    trails: list[MoneyTrail] = Field(default_factory=list)
    truncated: bool = False
    caveats: list[str] = Field(default_factory=list)


class GraphStatusResponse(BaseModel):
    """
    Safe graph subsystem status response.
    """

    model_config = ConfigDict(from_attributes=False)

    enabled: bool
    max_nodes: int
    hard_max_nodes: int
    max_edges: int
    hard_max_edges: int
    max_depth: int
    hard_max_depth: int
    max_paths: int
    hard_max_paths: int
    max_trails: int
    hard_max_trails: int
    max_shared_groups: int
    hard_max_shared_groups: int
    max_accounts_per_entity: int
    hard_max_accounts_per_entity: int
    max_date_span_days: int
    hard_max_date_span_days: int
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Node and edge builders
# -----------------------------------------------------------------------------


def _account_node(account: Account) -> GraphNode:
    """
    Build a safe account node.
    """
    return GraphNode(
        id=_account_node_id(account.id),
        type=_NODE_ACCOUNT,
        label=_clean_text(account.id, 128),
        account_id=str(account.id),
        account_type=_enum_str(_get_if_exists(account, "account_type", None)),
        status=_enum_str(_get_if_exists(account, "status", None)),
    )


def _minimal_account_node(account_id: str) -> GraphNode:
    """
    Build a minimal safe account node when the full record is not loaded.
    """
    return GraphNode(
        id=_account_node_id(account_id),
        type=_NODE_ACCOUNT,
        label=_clean_text(account_id, 128),
        account_id=str(account_id),
    )


def _transaction_node(transaction: Transaction) -> GraphNode:
    """
    Build a safe transaction node.
    """
    return GraphNode(
        id=_transaction_node_id(transaction.id),
        type=_NODE_TRANSACTION,
        label=_clean_text(_get_if_exists(transaction, "reference", transaction.id), 128),
        account_id=None,
        occurred_at=_get_if_exists(transaction, "occurred_at", None),
        amount=_get_if_exists(transaction, "amount", None),
        currency=_str_or_none(_get_if_exists(transaction, "currency", None)),
        reference=_str_or_none(_get_if_exists(transaction, "reference", None)),
        status=_enum_str(_get_if_exists(transaction, "status", None)),
        sender_account_id=_str_or_none(_get_if_exists(transaction, "sender_account_id", None)),
        receiver_account_id=_str_or_none(_get_if_exists(transaction, "receiver_account_id", None)),
        metadata_json=_response_metadata(_get_if_exists(transaction, "metadata_json", None)),
    )


def _entity_node(entity: Entity) -> GraphNode:
    """
    Build a safe pseudonymous entity node.

    Raw identifier hashes are intentionally not returned.
    """
    identifier_display = _get_if_exists(entity, "identifier_display", None)
    entity_type = _enum_str(_get_if_exists(entity, "entity_type", None)) or "entity"
    short_id = str(entity.id)[:8]

    label = (
        _clean_text(identifier_display, 200)
        if identifier_display
        else f"{entity_type}-entity-{short_id}"
    )

    return GraphNode(
        id=_entity_node_id(entity.id),
        type=_NODE_ENTITY,
        label=label,
        entity_type=entity_type,
        source=_str_or_none(_get_if_exists(entity, "source", None)) or "synthetic",
        metadata_json=_response_metadata(_get_if_exists(entity, "metadata_json", None)),
    )


def _complaint_node(complaint: Complaint) -> GraphNode:
    """
    Build a safe complaint node.

    Raw and normalized narratives are intentionally not returned.
    """
    return GraphNode(
        id=_complaint_node_id(complaint.id),
        type=_NODE_COMPLAINT,
        label=_clean_text(_get_if_exists(complaint, "reference", complaint.id), 128),
        reference=_str_or_none(_get_if_exists(complaint, "reference", None)),
        category=_str_or_none(_get_if_exists(complaint, "category", None)),
        occurred_at=_get_if_exists(complaint, "reported_at", None),
        amount=_get_if_exists(complaint, "amount", None),
        currency=_str_or_none(_get_if_exists(complaint, "currency", None)),
        source=_str_or_none(_get_if_exists(complaint, "source", None)),
        narrative_available=bool(_get_if_exists(complaint, "narrative_raw", None)),
    )


def _alert_node(alert: Alert) -> GraphNode:
    """
    Build a safe alert node.
    """
    return GraphNode(
        id=_alert_node_id(alert.id),
        type=_NODE_ALERT,
        label=_clean_text(_get_if_exists(alert, "title", alert.id), 200),
        account_id=_str_or_none(_get_if_exists(alert, "account_id", None)),
        priority=_enum_str(_get_if_exists(alert, "priority", None)),
        state=_enum_str(_get_if_exists(alert, "state", None)),
        score=_get_if_exists(alert, "score", None),
        occurred_at=_get_if_exists(alert, "first_seen_at", None),
        metadata_json=_response_metadata(_get_if_exists(alert, "signal_summary_json", None)),
    )


def _assessment_node(assessment: ModelAssessment) -> GraphNode:
    """
    Build a safe persisted assessment node.
    """
    return GraphNode(
        id=_assessment_node_id(assessment.id),
        type=_NODE_ASSESSMENT,
        label=f"assessment-{str(assessment.id)[:8]}",
        account_id=_str_or_none(_get_if_exists(assessment, "account_id", None)),
        score=_get_if_exists(assessment, "score", None),
        occurred_at=_get_if_exists(assessment, "scored_at", None),
        confidence=None,
        match_method=_enum_str(_get_if_exists(assessment, "scoring_mode", None)),
        review_state=_enum_str(_get_if_exists(assessment, "risk_band", None)),
        explanation_available=bool(_get_if_exists(assessment, "explanation_json", None)),
    )


# -----------------------------------------------------------------------------
# Capacity helpers
# -----------------------------------------------------------------------------


def _put_node(
    nodes: dict[str, GraphNode],
    node: GraphNode,
    max_nodes: int,
) -> bool:
    """
    Insert or conservatively upgrade a node if capacity allows.
    """
    existing = nodes.get(node.id)

    if existing is None:
        if len(nodes) >= max_nodes:
            return False

        nodes[node.id] = node
        return True

    if existing.type == _NODE_ACCOUNT and node.type == _NODE_ACCOUNT:
        if node.status and not existing.status:
            nodes[node.id] = node
        elif node.account_type and not existing.account_type:
            nodes[node.id] = node

    return True


def _put_edge(
    edges: dict[str, GraphEdge],
    edge: GraphEdge,
    max_edges: int,
) -> bool:
    """
    Insert an edge if capacity allows.
    """
    if edge.id in edges:
        return True

    if len(edges) >= max_edges:
        return False

    edges[edge.id] = edge
    return True


# -----------------------------------------------------------------------------
# Subgraph collection
# -----------------------------------------------------------------------------


def _collect_subgraph(
    db: Session,
    root_account_id: str,
    *,
    depth: int,
    direction: Literal["outgoing", "incoming", "both"],
    include_transactions: bool,
    include_entities: bool,
    include_complaints: bool,
    include_alerts: bool,
    include_assessments: bool,
    date_from: Optional[datetime],
    date_to: Optional[datetime],
    amount_min: Optional[Decimal],
    amount_max: Optional[Decimal],
    as_of: Optional[datetime],
    limits: dict[str, int],
) -> tuple[dict[str, GraphNode], dict[str, GraphEdge], bool]:
    """
    Collect a bounded synthetic graph subgraph rooted at one account.
    """
    root = _get_account_or_404(db, root_account_id)

    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}
    truncated = False

    _put_node(nodes, _account_node(root), limits["max_nodes"])

    frontier: set[str] = {str(root.id)}
    visited_accounts: set[str] = {str(root.id)}

    for _level in range(max(0, int(depth))):
        if not frontier or truncated:
            break

        account_ids = list(frontier)
        next_accounts: set[str] = set()

        if include_transactions:
            sender_col = _column(Transaction, "sender_account_id")
            receiver_col = _column(Transaction, "receiver_account_id")
            time_col = _column(Transaction, "occurred_at")
            amount_col = _column(Transaction, "amount")
            id_col = _column(Transaction, "id")

            dir_clauses: list[Any] = []

            if direction in ("outgoing", "both") and sender_col is not None:
                dir_clauses.append(sender_col.in_(account_ids))

            if direction in ("incoming", "both") and receiver_col is not None:
                dir_clauses.append(receiver_col.in_(account_ids))

            if dir_clauses:
                conditions: list[Any] = [or_(*dir_clauses)]

                if time_col is not None:
                    if date_from is not None:
                        conditions.append(time_col >= date_from)

                    if date_to is not None:
                        conditions.append(time_col <= date_to)

                    if as_of is not None:
                        conditions.append(time_col <= as_of)

                if amount_col is not None:
                    if amount_min is not None:
                        conditions.append(amount_col >= amount_min)

                    if amount_max is not None:
                        conditions.append(amount_col <= amount_max)

                stmt = select(Transaction).where(and_(*conditions))
                stmt = _order_stmt(stmt, [(time_col, False), (id_col, False)])
                stmt = stmt.limit(limits["max_edges"])

                transactions = db.scalars(stmt).all()

                if len(transactions) >= limits["max_edges"]:
                    truncated = True

                for transaction in transactions:
                    transaction_node = _transaction_node(transaction)

                    if not _put_node(nodes, transaction_node, limits["max_nodes"]):
                        truncated = True
                        break

                    sender_id = _str_or_none(_get_if_exists(transaction, "sender_account_id", None))
                    receiver_id = _str_or_none(_get_if_exists(transaction, "receiver_account_id", None))

                    sender_node_id = _account_node_id(sender_id) if sender_id else None
                    receiver_node_id = _account_node_id(receiver_id) if receiver_id else None

                    if sender_id and sender_node_id:
                        if not _put_node(nodes, _minimal_account_node(sender_id), limits["max_nodes"]):
                            truncated = True
                            break

                    if receiver_id and receiver_node_id:
                        if not _put_node(nodes, _minimal_account_node(receiver_id), limits["max_nodes"]):
                            truncated = True
                            break

                    if sender_node_id and receiver_node_id:
                        sent_edge = GraphEdge(
                            id=f"sent:{transaction_node.id}",
                            source=sender_node_id,
                            target=transaction_node.id,
                            type=_EDGE_SENT,
                            label="sent",
                            transaction_id=str(transaction.id),
                            account_id=sender_id,
                            amount=_get_if_exists(transaction, "amount", None),
                            currency=_str_or_none(_get_if_exists(transaction, "currency", None)),
                            occurred_at=_get_if_exists(transaction, "occurred_at", None),
                            deterministic=True,
                            match_method="transaction_ledger",
                        )

                        received_edge = GraphEdge(
                            id=f"received:{transaction_node.id}",
                            source=transaction_node.id,
                            target=receiver_node_id,
                            type=_EDGE_RECEIVED,
                            label="received",
                            transaction_id=str(transaction.id),
                            account_id=receiver_id,
                            amount=_get_if_exists(transaction, "amount", None),
                            currency=_str_or_none(_get_if_exists(transaction, "currency", None)),
                            occurred_at=_get_if_exists(transaction, "occurred_at", None),
                            deterministic=True,
                            match_method="transaction_ledger",
                        )

                        if not _put_edge(edges, sent_edge, limits["max_edges"]):
                            truncated = True
                            break

                        if not _put_edge(edges, received_edge, limits["max_edges"]):
                            truncated = True
                            break

                    if direction in ("outgoing", "both") and sender_id in frontier and receiver_id:
                        next_accounts.add(receiver_id)

                    if direction in ("incoming", "both") and receiver_id in frontier and sender_id:
                        next_accounts.add(sender_id)

        if include_entities and not truncated:
            link_account_col = _column(AccountEntityLink, "account_id")
            link_entity_col = _column(AccountEntityLink, "entity_id")
            valid_from_col = _column(AccountEntityLink, "valid_from")
            valid_to_col = _column(AccountEntityLink, "valid_to")
            confidence_col = _column(AccountEntityLink, "confidence")
            link_id_col = _column(AccountEntityLink, "id")

            if link_account_col is not None and link_entity_col is not None:
                conditions = [link_account_col.in_(account_ids)]

                if as_of is not None:
                    if valid_from_col is not None:
                        conditions.append(valid_from_col <= as_of)

                    if valid_to_col is not None:
                        conditions.append(or_(valid_to_col.is_(None), valid_to_col >= as_of))

                stmt = (
                    select(AccountEntityLink, Entity)
                    .join(Entity, Entity.id == AccountEntityLink.entity_id)
                    .where(and_(*conditions))
                )
                stmt = _order_stmt(
                    stmt,
                    [
                        (confidence_col, False),
                        (valid_from_col, False),
                        (link_id_col, False),
                    ],
                )
                stmt = stmt.limit(limits["max_edges"])

                rows = db.execute(stmt).all()

                if len(rows) >= limits["max_edges"]:
                    truncated = True

                for link, entity in rows:
                    entity_node = _entity_node(entity)

                    if not _put_node(nodes, entity_node, limits["max_nodes"]):
                        truncated = True
                        break

                    account_id = _str_or_none(_get_if_exists(link, "account_id", None))
                    account_nid = _account_node_id(account_id) if account_id else None

                    if account_id and account_nid:
                        if not _put_node(nodes, _minimal_account_node(account_id), limits["max_nodes"]):
                            truncated = True
                            break

                    if account_nid:
                        edge = GraphEdge(
                            id=f"linked_to:{account_id}:{entity.id}",
                            source=account_nid,
                            target=entity_node.id,
                            type=_EDGE_LINKED_TO,
                            label="linked to",
                            account_id=account_id,
                            entity_id=str(entity.id),
                            confidence=_get_if_exists(link, "confidence", None),
                            match_method=_enum_str(_get_if_exists(link, "match_method", None)),
                            deterministic=_is_exact_match(_get_if_exists(link, "match_method", None)),
                            verification_state=_enum_str(_get_if_exists(link, "verification_state", None)),
                        )

                        if not _put_edge(edges, edge, limits["max_edges"]):
                            truncated = True
                            break

        if include_alerts and not truncated:
            alert_account_col = _column(Alert, "account_id")
            alert_first_seen_col = _column(Alert, "first_seen_at")
            alert_id_col = _column(Alert, "id")

            if alert_account_col is not None:
                conditions = [alert_account_col.in_(account_ids)]

                if as_of is not None and alert_first_seen_col is not None:
                    conditions.append(alert_first_seen_col <= as_of)

                stmt = select(Alert).where(and_(*conditions))
                stmt = _order_stmt(stmt, [(alert_first_seen_col, False), (alert_id_col, False)])
                stmt = stmt.limit(limits["max_edges"])

                alerts = db.scalars(stmt).all()

                if len(alerts) >= limits["max_edges"]:
                    truncated = True

                for alert in alerts:
                    alert_node = _alert_node(alert)

                    if not _put_node(nodes, alert_node, limits["max_nodes"]):
                        truncated = True
                        break

                    account_id = _str_or_none(_get_if_exists(alert, "account_id", None))
                    account_nid = _account_node_id(account_id) if account_id else None

                    if account_id and account_nid:
                        if not _put_node(nodes, _minimal_account_node(account_id), limits["max_nodes"]):
                            truncated = True
                            break

                    if account_nid:
                        edge = GraphEdge(
                            id=f"alerted_on:{alert.id}:{account_id}",
                            source=alert_node.id,
                            target=account_nid,
                            type=_EDGE_ALERTED_ON,
                            label="alerted on",
                            alert_id=str(alert.id),
                            account_id=account_id,
                            amount=_get_if_exists(alert, "score", None),
                            occurred_at=_get_if_exists(alert, "first_seen_at", None),
                            deterministic=True,
                            match_method="alert_account",
                        )

                        if not _put_edge(edges, edge, limits["max_edges"]):
                            truncated = True
                            break

        if include_assessments and not truncated:
            assessment_account_col = _column(ModelAssessment, "account_id")
            assessment_scored_col = _column(ModelAssessment, "scored_at")
            assessment_id_col = _column(ModelAssessment, "id")

            if assessment_account_col is not None:
                conditions = [assessment_account_col.in_(account_ids)]

                if as_of is not None and assessment_scored_col is not None:
                    conditions.append(assessment_scored_col <= as_of)

                stmt = select(ModelAssessment).where(and_(*conditions))
                stmt = _order_stmt(stmt, [(assessment_scored_col, False), (assessment_id_col, False)])
                stmt = stmt.limit(limits["max_edges"])

                assessments = db.scalars(stmt).all()

                if len(assessments) >= limits["max_edges"]:
                    truncated = True

                for assessment in assessments:
                    assessment_node = _assessment_node(assessment)

                    if not _put_node(nodes, assessment_node, limits["max_nodes"]):
                        truncated = True
                        break

                    account_id = _str_or_none(_get_if_exists(assessment, "account_id", None))
                    account_nid = _account_node_id(account_id) if account_id else None

                    if account_id and account_nid:
                        if not _put_node(nodes, _minimal_account_node(account_id), limits["max_nodes"]):
                            truncated = True
                            break

                    if account_nid:
                        edge = GraphEdge(
                            id=f"assessed_by:{assessment.id}:{account_id}",
                            source=assessment_node.id,
                            target=account_nid,
                            type=_EDGE_ASSESSED_BY,
                            label="assessed by",
                            assessment_id=str(assessment.id),
                            account_id=account_id,
                            amount=_get_if_exists(assessment, "score", None),
                            occurred_at=_get_if_exists(assessment, "scored_at", None),
                            deterministic=True,
                            match_method=_enum_str(_get_if_exists(assessment, "scoring_mode", None)),
                        )

                        if not _put_edge(edges, edge, limits["max_edges"]):
                            truncated = True
                            break

        if include_complaints and not truncated:
            victim_col = _column(Complaint, "victim_account_id")
            suspected_col = _column(Complaint, "suspected_account_id")
            reported_col = _column(Complaint, "reported_at")
            complaint_id_col = _column(Complaint, "id")

            clauses: list[Any] = []

            if victim_col is not None:
                clauses.append(victim_col.in_(account_ids))

            if suspected_col is not None:
                clauses.append(suspected_col.in_(account_ids))

            if clauses:
                conditions = [or_(*clauses)]

                if as_of is not None and reported_col is not None:
                    conditions.append(reported_col <= as_of)

                stmt = select(Complaint).where(and_(*conditions))
                stmt = _order_stmt(stmt, [(reported_col, False), (complaint_id_col, False)])
                stmt = stmt.limit(limits["max_edges"])

                complaints = db.scalars(stmt).all()

                if len(complaints) >= limits["max_edges"]:
                    truncated = True

                for complaint in complaints:
                    complaint_node = _complaint_node(complaint)

                    if not _put_node(nodes, complaint_node, limits["max_nodes"]):
                        truncated = True
                        break

                    victim_id = _str_or_none(_get_if_exists(complaint, "victim_account_id", None))
                    suspected_id = _str_or_none(_get_if_exists(complaint, "suspected_account_id", None))

                    for related_account_id in (victim_id, suspected_id):
                        if not related_account_id or related_account_id not in frontier:
                            continue

                        account_nid = _account_node_id(related_account_id)

                        if not _put_node(nodes, _minimal_account_node(related_account_id), limits["max_nodes"]):
                            truncated = True
                            break

                        edge = GraphEdge(
                            id=f"related_to:{complaint.id}:{related_account_id}",
                            source=complaint_node.id,
                            target=account_nid,
                            type=_EDGE_RELATED_TO,
                            label="related to",
                            complaint_id=str(complaint.id),
                            account_id=related_account_id,
                            amount=_get_if_exists(complaint, "amount", None),
                            currency=_str_or_none(_get_if_exists(complaint, "currency", None)),
                            occurred_at=_get_if_exists(complaint, "reported_at", None),
                            deterministic=True,
                            match_method="complaint_field",
                        )

                        if not _put_edge(edges, edge, limits["max_edges"]):
                            truncated = True
                            break

                    if truncated:
                        break

            correlation_account_col = _column(ComplaintCorrelation, "account_id")
            correlation_created_col = _first_column(ComplaintCorrelation, "record_created_at", "created_at")
            correlation_id_col = _column(ComplaintCorrelation, "id")

            if correlation_account_col is not None and not truncated:
                conditions = [correlation_account_col.in_(account_ids)]

                if as_of is not None and correlation_created_col is not None:
                    conditions.append(correlation_created_col <= as_of)

                stmt = (
                    select(ComplaintCorrelation, Complaint)
                    .join(Complaint, Complaint.id == ComplaintCorrelation.complaint_id)
                    .where(and_(*conditions))
                )
                stmt = _order_stmt(
                    stmt,
                    [
                        (correlation_created_col, False),
                        (correlation_id_col, False),
                    ],
                )
                stmt = stmt.limit(limits["max_edges"])

                rows = db.execute(stmt).all()

                if len(rows) >= limits["max_edges"]:
                    truncated = True

                for correlation, complaint in rows:
                    complaint_node = _complaint_node(complaint)

                    if not _put_node(nodes, complaint_node, limits["max_nodes"]):
                        truncated = True
                        break

                    account_id = _str_or_none(_get_if_exists(correlation, "account_id", None))
                    account_nid = _account_node_id(account_id) if account_id else None

                    if account_id and account_nid:
                        if not _put_node(nodes, _minimal_account_node(account_id), limits["max_nodes"]):
                            truncated = True
                            break

                    if account_nid:
                        edge = GraphEdge(
                            id=f"correlated_with:{correlation.id}:{account_id}",
                            source=complaint_node.id,
                            target=account_nid,
                            type=_EDGE_CORRELATED_WITH,
                            label="correlated with",
                            complaint_id=str(complaint.id),
                            account_id=account_id,
                            confidence=_get_if_exists(correlation, "confidence", None),
                            match_method=_enum_str(_get_if_exists(correlation, "match_method", None)),
                            deterministic=bool(_get_if_exists(correlation, "deterministic", False)),
                            review_state=_enum_str(_get_if_exists(correlation, "review_state", None)),
                            evidence_refs=_safe_string_list(
                                _get_if_exists(correlation, "evidence_refs_json", None)
                            ),
                        )

                        if not _put_edge(edges, edge, limits["max_edges"]):
                            truncated = True
                            break

        frontier = {
            account_id
            for account_id in next_accounts
            if account_id not in visited_accounts
        }
        visited_accounts.update(frontier)

        if len(visited_accounts) >= limits["max_nodes"]:
            truncated = True
            break

    return nodes, edges, truncated


# -----------------------------------------------------------------------------
# Graph response builders
# -----------------------------------------------------------------------------


def _graph_stats(
    nodes: Mapping[str, GraphNode],
    edges: Mapping[str, GraphEdge],
    *,
    truncated: bool,
    depth_requested: int,
    limits: dict[str, int],
) -> GraphStats:
    """
    Build safe graph statistics.
    """
    return GraphStats(
        node_count=len(nodes),
        edge_count=len(edges),
        truncated=truncated,
        depth_requested=int(depth_requested),
        max_nodes=int(limits["max_nodes"]),
        max_edges=int(limits["max_edges"]),
    )


def _sorted_nodes(nodes: Mapping[str, GraphNode]) -> list[GraphNode]:
    """
    Return deterministic sorted nodes.
    """
    return sorted(nodes.values(), key=lambda node: (node.type, node.id))


def _sorted_edges(edges: Mapping[str, GraphEdge]) -> list[GraphEdge]:
    """
    Return deterministic sorted edges.
    """
    return sorted(edges.values(), key=lambda edge: (edge.type, edge.id))


# -----------------------------------------------------------------------------
# Transfer adjacency and path/trail search
# -----------------------------------------------------------------------------


def _append_adj(
    adj: dict[str, list[tuple[str, str]]],
    from_id: str,
    to_id: str,
    edge_id: str,
    edges: Mapping[str, GraphEdge],
) -> None:
    """
    Append a directed adjacency entry when the backing edge exists.
    """
    if edge_id not in edges:
        return

    bucket = adj.setdefault(from_id, [])
    item = (to_id, edge_id)

    if item not in bucket:
        bucket.append(item)


def _build_transfer_adjacency(
    nodes: Mapping[str, GraphNode],
    edges: Mapping[str, GraphEdge],
    direction: Literal["outgoing", "incoming", "both"],
) -> dict[str, list[tuple[str, str]]]:
    """
    Build adjacency for transaction walks.
    """
    adj: dict[str, list[tuple[str, str]]] = {}

    for node in nodes.values():
        if node.type != _NODE_TRANSACTION:
            continue

        sender_id = node.sender_account_id
        receiver_id = node.receiver_account_id

        if not sender_id or not receiver_id:
            continue

        sender_node_id = _account_node_id(sender_id)
        receiver_node_id = _account_node_id(receiver_id)
        sent_edge_id = f"sent:{node.id}"
        received_edge_id = f"received:{node.id}"

        if direction in ("outgoing", "both"):
            _append_adj(adj, sender_node_id, node.id, sent_edge_id, edges)
            _append_adj(adj, node.id, receiver_node_id, received_edge_id, edges)

        if direction in ("incoming", "both"):
            _append_adj(adj, receiver_node_id, node.id, received_edge_id, edges)
            _append_adj(adj, node.id, sender_node_id, sent_edge_id, edges)

    return adj


def _amount_totals(nodes: Sequence[GraphNode]) -> dict[str, Decimal]:
    """
    Return per-currency transaction totals for a path or trail.
    """
    totals: dict[str, Decimal] = {}

    for node in nodes:
        if node.type != _NODE_TRANSACTION:
            continue

        if node.amount is None or not node.currency:
            continue

        currency = str(node.currency).upper()
        totals[currency] = totals.get(currency, Decimal("0")) + node.amount

    return totals


def _earliest_latest(nodes: Sequence[GraphNode]) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Return earliest and latest transaction timestamps for a path or trail.
    """
    times = [
        node.occurred_at
        for node in nodes
        if node.type == _NODE_TRANSACTION and node.occurred_at is not None
    ]

    if not times:
        return None, None

    return min(times), max(times)


def _materialize_nodes(
    node_ids: Sequence[str],
    nodes: Mapping[str, GraphNode],
) -> list[GraphNode]:
    """
    Return ordered nodes for a path/trail.
    """
    return [nodes[node_id] for node_id in node_ids if node_id in nodes]


def _materialize_edges(
    edge_ids: Sequence[str],
    edges: Mapping[str, GraphEdge],
) -> list[GraphEdge]:
    """
    Return unique ordered edges for a path/trail.
    """
    result: list[GraphEdge] = []
    seen: set[str] = set()

    for edge_id in edge_ids:
        if edge_id in seen:
            continue

        edge = edges.get(edge_id)

        if edge is None:
            continue

        result.append(edge)
        seen.add(edge_id)

    return result


def _find_paths(
    nodes: Mapping[str, GraphNode],
    edges: Mapping[str, GraphEdge],
    *,
    from_account_id: str,
    to_account_id: str,
    direction: Literal["outgoing", "incoming", "both"],
    max_depth: int,
    max_paths: int,
) -> list[GraphPath]:
    """
    Find bounded candidate paths between two accounts.
    """
    source_node_id = _account_node_id(from_account_id)
    target_node_id = _account_node_id(to_account_id)

    if source_node_id not in nodes or target_node_id not in nodes:
        return []

    adjacency = _build_transfer_adjacency(nodes, edges, direction)
    paths: list[GraphPath] = []

    def record(
        node_ids: Sequence[str],
        edge_ids: Sequence[str],
        hop_count: int,
    ) -> None:
        path_nodes = _materialize_nodes(node_ids, nodes)
        path_edges = _materialize_edges(edge_ids, edges)
        earliest_at, latest_at = _earliest_latest(path_nodes)

        paths.append(
            GraphPath(
                path_id=_stable_hash(list(node_ids)),
                from_account_id=str(from_account_id),
                to_account_id=str(to_account_id),
                direction=direction,
                hop_count=int(hop_count),
                nodes=path_nodes,
                edges=path_edges,
                amount_by_currency=_amount_totals(path_nodes),
                earliest_at=earliest_at,
                latest_at=latest_at,
            )
        )

    def dfs(
        node_id: str,
        node_path: Sequence[str],
        edge_path: Sequence[str],
        edge_set: frozenset[str],
        hop_count: int,
        visited: frozenset[str],
    ) -> None:
        if len(paths) >= max_paths:
            return

        current = nodes.get(node_id)

        if current is None:
            return

        if current.type == _NODE_ACCOUNT and node_id == target_node_id and hop_count > 0:
            record(node_path, edge_path, hop_count)
            return

        if hop_count >= max_depth:
            return

        for next_node_id, edge_id in adjacency.get(node_id, ()):
            if next_node_id in visited:
                continue

            next_node = nodes.get(next_node_id)

            if next_node is None:
                continue

            next_hop_count = hop_count + (1 if next_node.type == _NODE_ACCOUNT else 0)

            if next_hop_count > max_depth:
                continue

            next_edge_path = edge_path
            next_edge_set = edge_set

            if edge_id not in edge_set:
                next_edge_path = tuple(edge_path) + (edge_id,)
                next_edge_set = edge_set | {edge_id}

            dfs(
                next_node_id,
                tuple(node_path) + (next_node_id,),
                next_edge_path,
                next_edge_set,
                next_hop_count,
                visited | {next_node_id},
            )

            if len(paths) >= max_paths:
                return

    dfs(
        source_node_id,
        (source_node_id,),
        (),
        frozenset(),
        0,
        frozenset({source_node_id}),
    )

    paths.sort(key=lambda path: (path.hop_count, path.path_id))
    return paths[:max_paths]


def _find_trails(
    nodes: Mapping[str, GraphNode],
    edges: Mapping[str, GraphEdge],
    *,
    root_account_id: str,
    direction: Literal["outgoing", "incoming"],
    max_hops: int,
    max_trails: int,
) -> list[MoneyTrail]:
    """
    Find bounded candidate money trails from one root account.
    """
    source_node_id = _account_node_id(root_account_id)

    if source_node_id not in nodes:
        return []

    adjacency = _build_transfer_adjacency(nodes, edges, direction)
    trails: list[MoneyTrail] = []

    def record(
        node_ids: Sequence[str],
        edge_ids: Sequence[str],
        hop_count: int,
    ) -> None:
        trail_nodes = _materialize_nodes(node_ids, nodes)
        trail_edges = _materialize_edges(edge_ids, edges)
        earliest_at, latest_at = _earliest_latest(trail_nodes)

        trails.append(
            MoneyTrail(
                trail_id=_stable_hash(list(node_ids)),
                root_account_id=str(root_account_id),
                direction=direction,
                hop_count=int(hop_count),
                nodes=trail_nodes,
                edges=trail_edges,
                amount_by_currency=_amount_totals(trail_nodes),
                earliest_at=earliest_at,
                latest_at=latest_at,
            )
        )

    def dfs(
        node_id: str,
        node_path: Sequence[str],
        edge_path: Sequence[str],
        edge_set: frozenset[str],
        hop_count: int,
        visited: frozenset[str],
    ) -> None:
        if len(trails) >= max_trails:
            return

        current = nodes.get(node_id)

        if current is None:
            return

        if current.type == _NODE_ACCOUNT and hop_count >= max_hops and hop_count > 0:
            record(node_path, edge_path, hop_count)
            return

        can_extend = False

        for next_node_id, edge_id in adjacency.get(node_id, ()):
            if next_node_id in visited:
                continue

            next_node = nodes.get(next_node_id)

            if next_node is None:
                continue

            next_hop_count = hop_count + (1 if next_node.type == _NODE_ACCOUNT else 0)

            if next_hop_count > max_hops:
                continue

            can_extend = True

            next_edge_path = edge_path
            next_edge_set = edge_set

            if edge_id not in edge_set:
                next_edge_path = tuple(edge_path) + (edge_id,)
                next_edge_set = edge_set | {edge_id}

            dfs(
                next_node_id,
                tuple(node_path) + (next_node_id,),
                next_edge_path,
                next_edge_set,
                next_hop_count,
                visited | {next_node_id},
            )

            if len(trails) >= max_trails:
                return

        if not can_extend and current.type == _NODE_ACCOUNT and hop_count > 0:
            record(node_path, edge_path, hop_count)

    dfs(
        source_node_id,
        (source_node_id,),
        (),
        frozenset(),
        0,
        frozenset({source_node_id}),
    )

    trails.sort(key=lambda trail: (-trail.hop_count, trail.trail_id))
    return trails[:max_trails]


# -----------------------------------------------------------------------------
# Shared-entity collection
# -----------------------------------------------------------------------------


def _collect_shared_entities(
    db: Session,
    root_account_id: str,
    *,
    entity_type: Optional[EntityType],
    verification_state: Optional[VerificationState],
    match_method: Optional[MatchMethod],
    min_accounts: int,
    max_groups: int,
    max_accounts_per_entity: int,
    as_of: Optional[datetime],
) -> tuple[list[SharedEntityGroup], bool]:
    """
    Collect bounded shared-entity groups for one root account.
    """
    root = _get_account_or_404(db, root_account_id)
    root_node = _account_node(root)

    link_account_col = _column(AccountEntityLink, "account_id")
    link_entity_col = _column(AccountEntityLink, "entity_id")
    valid_from_col = _column(AccountEntityLink, "valid_from")
    valid_to_col = _column(AccountEntityLink, "valid_to")
    confidence_col = _column(AccountEntityLink, "confidence")
    link_id_col = _column(AccountEntityLink, "id")

    if link_account_col is None or link_entity_col is None:
        return [], False

    root_conditions: list[Any] = [link_account_col == str(root.id)]

    if entity_type is not None:
        root_conditions.append(Entity.entity_type == entity_type)

    if verification_state is not None:
        root_conditions.append(AccountEntityLink.verification_state == verification_state)

    if match_method is not None:
        root_conditions.append(AccountEntityLink.match_method == match_method)

    if as_of is not None:
        if valid_from_col is not None:
            root_conditions.append(valid_from_col <= as_of)

        if valid_to_col is not None:
            root_conditions.append(or_(valid_to_col.is_(None), valid_to_col >= as_of))

    root_stmt = (
        select(AccountEntityLink, Entity)
        .join(Entity, Entity.id == AccountEntityLink.entity_id)
        .where(and_(*root_conditions))
    )
    root_stmt = _order_stmt(
        root_stmt,
        [
            (confidence_col, False),
            (valid_from_col, False),
            (link_id_col, False),
        ],
    )
    root_stmt = root_stmt.limit(max_groups)

    root_rows = db.execute(root_stmt).all()
    truncated = len(root_rows) >= max_groups

    groups: list[SharedEntityGroup] = []

    for root_link, entity in root_rows:
        other_conditions: list[Any] = [
            AccountEntityLink.entity_id == entity.id,
            AccountEntityLink.account_id != str(root.id),
        ]

        if verification_state is not None:
            other_conditions.append(AccountEntityLink.verification_state == verification_state)

        if match_method is not None:
            other_conditions.append(AccountEntityLink.match_method == match_method)

        if as_of is not None:
            if valid_from_col is not None:
                other_conditions.append(valid_from_col <= as_of)

            if valid_to_col is not None:
                other_conditions.append(or_(valid_to_col.is_(None), valid_to_col >= as_of))

        other_stmt = (
            select(AccountEntityLink, Account)
            .join(Account, Account.id == AccountEntityLink.account_id)
            .where(and_(*other_conditions))
        )
        other_stmt = _order_stmt(
            other_stmt,
            [
                (confidence_col, False),
                (valid_from_col, False),
                (link_id_col, False),
            ],
        )
        other_stmt = other_stmt.limit(max_accounts_per_entity)

        other_rows = db.execute(other_stmt).all()

        if len(other_rows) >= max_accounts_per_entity:
            truncated = True

        account_count = 1 + len(other_rows)

        if account_count < min_accounts:
            continue

        entity_node = _entity_node(entity)
        account_nodes: list[GraphNode] = [root_node]
        edges: list[GraphEdge] = []
        match_methods: set[str] = set()
        verification_states: set[str] = set()
        confidences: list[Decimal] = []
        deterministic_values: list[bool] = []

        root_edge = GraphEdge(
            id=f"linked_to:{root.id}:{entity.id}",
            source=root_node.id,
            target=entity_node.id,
            type=_EDGE_LINKED_TO,
            label="linked to",
            account_id=str(root.id),
            entity_id=str(entity.id),
            confidence=_get_if_exists(root_link, "confidence", None),
            match_method=_enum_str(_get_if_exists(root_link, "match_method", None)),
            deterministic=_is_exact_match(_get_if_exists(root_link, "match_method", None)),
            verification_state=_enum_str(_get_if_exists(root_link, "verification_state", None)),
        )

        edges.append(root_edge)

        if root_edge.match_method:
            match_methods.add(root_edge.match_method)

        if root_edge.verification_state:
            verification_states.add(root_edge.verification_state)

        if root_edge.confidence is not None:
            confidences.append(root_edge.confidence)

        deterministic_values.append(bool(root_edge.deterministic))

        for other_link, other_account in other_rows:
            other_node = _account_node(other_account)
            account_nodes.append(other_node)

            other_edge = GraphEdge(
                id=f"linked_to:{other_account.id}:{entity.id}",
                source=other_node.id,
                target=entity_node.id,
                type=_EDGE_LINKED_TO,
                label="linked to",
                account_id=str(other_account.id),
                entity_id=str(entity.id),
                confidence=_get_if_exists(other_link, "confidence", None),
                match_method=_enum_str(_get_if_exists(other_link, "match_method", None)),
                deterministic=_is_exact_match(_get_if_exists(other_link, "match_method", None)),
                verification_state=_enum_str(_get_if_exists(other_link, "verification_state", None)),
            )

            edges.append(other_edge)

            if other_edge.match_method:
                match_methods.add(other_edge.match_method)

            if other_edge.verification_state:
                verification_states.add(other_edge.verification_state)

            if other_edge.confidence is not None:
                confidences.append(other_edge.confidence)

            deterministic_values.append(bool(other_edge.deterministic))

        groups.append(
            SharedEntityGroup(
                entity=entity_node,
                accounts=sorted(account_nodes, key=lambda node: node.id),
                edges=sorted(edges, key=lambda edge: edge.id),
                account_count=account_count,
                match_methods=sorted(match_methods),
                verification_states=sorted(verification_states),
                deterministic=all(deterministic_values) if deterministic_values else False,
                min_confidence=min(confidences) if confidences else None,
                max_confidence=max(confidences) if confidences else None,
            )
        )

        if len(groups) >= max_groups:
            truncated = True
            break

    return groups, truncated


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=GraphStatusResponse,
    summary="Get graph subsystem status",
    description=(
        "Returns safe status and bounded policy limits for the MULEGUARD graph "
        "subsystem. This endpoint does not expose secrets, database URLs, "
        "tokens, passwords, raw complaint narratives, raw identifier hashes, "
        "ground-truth labels, or real customer data."
    ),
)
def graph_status(
    settings: SettingsDep,
    _: User = Depends(require_permission(Permission.GRAPH_READ)),
) -> GraphStatusResponse:
    """
    Return safe graph subsystem status.
    """
    _ensure_graph_enabled(settings)

    limits = _graph_limits(settings)

    return GraphStatusResponse(
        enabled=True,
        max_nodes=limits["max_nodes"],
        hard_max_nodes=limits["hard_max_nodes"],
        max_edges=limits["max_edges"],
        hard_max_edges=limits["hard_max_edges"],
        max_depth=limits["max_depth"],
        hard_max_depth=limits["hard_max_depth"],
        max_paths=limits["max_paths"],
        hard_max_paths=limits["hard_max_paths"],
        max_trails=limits["max_trails"],
        hard_max_trails=limits["hard_max_trails"],
        max_shared_groups=limits["max_shared_groups"],
        hard_max_shared_groups=limits["hard_max_shared_groups"],
        max_accounts_per_entity=limits["max_accounts_per_entity"],
        hard_max_accounts_per_entity=limits["hard_max_accounts_per_entity"],
        max_date_span_days=limits["max_date_span_days"],
        hard_max_date_span_days=limits["hard_max_date_span_days"],
        caveats=list(_GRAPH_CAVEATS),
    )


@router.get(
    "/subgraph",
    response_model=GraphResponse,
    summary="Get a bounded synthetic account subgraph",
    description=(
        "Returns a bounded, safe, evidence-backed graph subgraph rooted at one "
        "synthetic MULEGUARD account. Graph relationships are investigative "
        "leads only and are not proof of common control or wrongdoing."
    ),
)
def get_graph_subgraph(
    db: SessionDep,
    settings: SettingsDep,
    account_id: Annotated[
        str,
        Query(min_length=1, max_length=128, description="Root synthetic account identifier."),
    ],
    _: User = Depends(require_permission(Permission.GRAPH_READ)),
    depth: Annotated[
        int,
        Query(ge=1, le=10, description="Requested traversal depth, clamped by policy."),
    ] = 2,
    direction: Annotated[
        Literal["outgoing", "incoming", "both"],
        Query(description="Transaction traversal direction relative to the root account."),
    ] = "both",
    include_transactions: Annotated[
        bool,
        Query(description="Include transaction nodes and transfer edges."),
    ] = True,
    include_entities: Annotated[
        bool,
        Query(description="Include pseudonymous entity link nodes and edges."),
    ] = True,
    include_complaints: Annotated[
        bool,
        Query(description="Include complaint and complaint-correlation nodes and edges."),
    ] = True,
    include_alerts: Annotated[
        bool,
        Query(description="Include alert nodes and alert-account edges."),
    ] = True,
    include_assessments: Annotated[
        bool,
        Query(description="Include persisted assessment nodes and assessment-account edges."),
    ] = True,
    as_of: Annotated[
        Optional[datetime],
        Query(description="Point-in-time cutoff for temporal graph views."),
    ] = None,
    date_range: DateRangeParams = Depends(date_range_dependency(max_span_days=0)),
    amount_range: AmountRangeParams = Depends(amount_range_dependency(allow_negative=False)),
    max_nodes: Annotated[
        Optional[int],
        Query(ge=1, le=1000, description="Requested maximum node count, clamped by policy."),
    ] = None,
    max_edges: Annotated[
        Optional[int],
        Query(ge=1, le=2000, description="Requested maximum edge count, clamped by policy."),
    ] = None,
) -> GraphResponse:
    """
    Return a bounded account-centred synthetic subgraph.
    """
    _ensure_graph_enabled(settings)

    limits = _clamp_limits(
        settings,
        max_nodes=max_nodes,
        max_edges=max_edges,
        depth=depth,
    )

    date_from, date_to, normalized_as_of = _validate_query_windows(
        date_range=date_range,
        amount_range=amount_range,
        as_of=as_of,
        settings=settings,
    )

    nodes, edges, truncated = _collect_subgraph(
        db,
        account_id,
        depth=limits["max_depth"],
        direction=direction,
        include_transactions=include_transactions,
        include_entities=include_entities,
        include_complaints=include_complaints,
        include_alerts=include_alerts,
        include_assessments=include_assessments,
        date_from=date_from,
        date_to=date_to,
        amount_min=amount_range.amount_min,
        amount_max=amount_range.amount_max,
        as_of=normalized_as_of,
        limits=limits,
    )

    root = _get_account_or_404(db, account_id)

    return GraphResponse(
        generated_at=_now_utc(),
        root_node_id=_account_node_id(root.id),
        nodes=_sorted_nodes(nodes),
        edges=_sorted_edges(edges),
        stats=_graph_stats(
            nodes,
            edges,
            truncated=truncated,
            depth_requested=limits["max_depth"],
            limits=limits,
        ),
        caveats=list(_GRAPH_CAVEATS),
    )


@router.get(
    "/paths",
    response_model=GraphPathsResponse,
    summary="Find bounded candidate transaction paths between two synthetic accounts",
    description=(
        "Returns bounded candidate transaction paths between two synthetic "
        "MULEGUARD accounts. Paths are investigative leads only and are not "
        "proof of common control, layering, integration, or wrongdoing."
    ),
)
def get_graph_paths(
    db: SessionDep,
    settings: SettingsDep,
    from_account_id: Annotated[
        str,
        Query(min_length=1, max_length=128, description="Source synthetic account identifier."),
    ],
    to_account_id: Annotated[
        str,
        Query(min_length=1, max_length=128, description="Target synthetic account identifier."),
    ],
    _: User = Depends(require_permission(Permission.GRAPH_READ)),
    max_depth: Annotated[
        int,
        Query(ge=1, le=10, description="Maximum account-to-account hop count, clamped by policy."),
    ] = 3,
    direction: Annotated[
        Literal["outgoing", "incoming", "both"],
        Query(description="Path traversal direction relative to the source account."),
    ] = "outgoing",
    max_paths: Annotated[
        Optional[int],
        Query(ge=1, le=100, description="Requested maximum path count, clamped by policy."),
    ] = None,
    as_of: Annotated[
        Optional[datetime],
        Query(description="Point-in-time cutoff for temporal path views."),
    ] = None,
    date_range: DateRangeParams = Depends(date_range_dependency(max_span_days=0)),
    amount_range: AmountRangeParams = Depends(amount_range_dependency(allow_negative=False)),
    max_nodes: Annotated[
        Optional[int],
        Query(ge=1, le=1000, description="Requested maximum node count, clamped by policy."),
    ] = None,
    max_edges: Annotated[
        Optional[int],
        Query(ge=1, le=2000, description="Requested maximum edge count, clamped by policy."),
    ] = None,
) -> GraphPathsResponse:
    """
    Return bounded candidate paths between two accounts.
    """
    _ensure_graph_enabled(settings)

    limits = _clamp_limits(
        settings,
        max_nodes=max_nodes,
        max_edges=max_edges,
        depth=max_depth,
        paths=max_paths,
    )

    date_from, date_to, normalized_as_of = _validate_query_windows(
        date_range=date_range,
        amount_range=amount_range,
        as_of=as_of,
        settings=settings,
    )

    _get_account_or_404(db, from_account_id)
    _get_account_or_404(db, to_account_id)

    nodes, edges, truncated = _collect_subgraph(
        db,
        from_account_id,
        depth=limits["max_depth"],
        direction=direction,
        include_transactions=True,
        include_entities=False,
        include_complaints=False,
        include_alerts=False,
        include_assessments=False,
        date_from=date_from,
        date_to=date_to,
        amount_min=amount_range.amount_min,
        amount_max=amount_range.amount_max,
        as_of=normalized_as_of,
        limits=limits,
    )

    paths = _find_paths(
        nodes,
        edges,
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        direction=direction,
        max_depth=limits["max_depth"],
        max_paths=limits["max_paths"],
    )

    if len(paths) >= limits["max_paths"]:
        truncated = True

    return GraphPathsResponse(
        generated_at=_now_utc(),
        from_account_id=str(from_account_id),
        to_account_id=str(to_account_id),
        direction=direction,
        max_depth=limits["max_depth"],
        paths=paths,
        truncated=truncated,
        caveats=list(_PATH_CAVEATS),
    )


@router.get(
    "/shared-entities",
    response_model=SharedEntitiesResponse,
    summary="Find bounded shared-entity groups for a synthetic account",
    description=(
        "Returns bounded shared-entity groups for one synthetic MULEGUARD "
        "account. Shared entities are association clusters only and are not "
        "proof of common control or wrongdoing."
    ),
)
def get_shared_entities(
    db: SessionDep,
    settings: SettingsDep,
    account_id: Annotated[
        str,
        Query(min_length=1, max_length=128, description="Root synthetic account identifier."),
    ],
    _: User = Depends(require_permission(Permission.GRAPH_READ)),
    entity_type: Annotated[
        Optional[EntityType],
        Query(description="Filter by synthetic entity type."),
    ] = None,
    verification_state: Annotated[
        Optional[VerificationState],
        Query(description="Filter by link verification state."),
    ] = None,
    match_method: Annotated[
        Optional[MatchMethod],
        Query(description="Filter by link match method."),
    ] = None,
    min_accounts: Annotated[
        int,
        Query(ge=2, le=100, description="Minimum accounts required to form a shared-entity group."),
    ] = 2,
    max_groups: Annotated[
        Optional[int],
        Query(ge=1, le=100, description="Requested maximum group count, clamped by policy."),
    ] = None,
    max_accounts_per_entity: Annotated[
        Optional[int],
        Query(ge=1, le=100, description="Requested maximum accounts per entity, clamped by policy."),
    ] = None,
    as_of: Annotated[
        Optional[datetime],
        Query(description="Point-in-time cutoff for temporal link views."),
    ] = None,
) -> SharedEntitiesResponse:
    """
    Return bounded shared-entity groups for one account.
    """
    _ensure_graph_enabled(settings)

    limits = _clamp_limits(
        settings,
        groups=max_groups,
        accounts_per_entity=max_accounts_per_entity,
    )

    normalized_as_of = _ensure_utc(as_of)
    _validate_not_future(normalized_as_of, "as_of")

    root = _get_account_or_404(db, account_id)

    groups, truncated = _collect_shared_entities(
        db,
        str(root.id),
        entity_type=entity_type,
        verification_state=verification_state,
        match_method=match_method,
        min_accounts=max(2, int(min_accounts)),
        max_groups=limits["max_shared_groups"],
        max_accounts_per_entity=limits["max_accounts_per_entity"],
        as_of=normalized_as_of,
    )

    return SharedEntitiesResponse(
        generated_at=_now_utc(),
        root_account_id=str(root.id),
        min_accounts=max(2, int(min_accounts)),
        max_groups=limits["max_shared_groups"],
        max_accounts_per_entity=limits["max_accounts_per_entity"],
        groups=groups,
        truncated=truncated,
        caveats=list(_SHARED_CAVEATS),
    )


@router.get(
    "/money-trails",
    response_model=MoneyTrailsResponse,
    summary="Find bounded candidate money trails from a synthetic account",
    description=(
        "Returns bounded candidate money trails from one synthetic MULEGUARD "
        "account. Candidate money trails are heuristic flow views only and are "
        "not proof of layering, integration, or wrongdoing."
    ),
)
def get_money_trails(
    db: SessionDep,
    settings: SettingsDep,
    account_id: Annotated[
        str,
        Query(min_length=1, max_length=128, description="Root synthetic account identifier."),
    ],
    _: User = Depends(require_permission(Permission.GRAPH_READ)),
    direction: Annotated[
        Literal["outgoing", "incoming"],
        Query(description="Trail traversal direction relative to the root account."),
    ] = "outgoing",
    max_hops: Annotated[
        int,
        Query(ge=1, le=10, description="Maximum account-to-account hop count, clamped by policy."),
    ] = 3,
    max_trails: Annotated[
        Optional[int],
        Query(ge=1, le=100, description="Requested maximum trail count, clamped by policy."),
    ] = None,
    as_of: Annotated[
        Optional[datetime],
        Query(description="Point-in-time cutoff for temporal trail views."),
    ] = None,
    date_range: DateRangeParams = Depends(date_range_dependency(max_span_days=0)),
    amount_range: AmountRangeParams = Depends(amount_range_dependency(allow_negative=False)),
    max_nodes: Annotated[
        Optional[int],
        Query(ge=1, le=1000, description="Requested maximum node count, clamped by policy."),
    ] = None,
    max_edges: Annotated[
        Optional[int],
        Query(ge=1, le=2000, description="Requested maximum edge count, clamped by policy."),
    ] = None,
) -> MoneyTrailsResponse:
    """
    Return bounded candidate money trails from one account.
    """
    _ensure_graph_enabled(settings)

    limits = _clamp_limits(
        settings,
        max_nodes=max_nodes,
        max_edges=max_edges,
        depth=max_hops,
        trails=max_trails,
    )

    date_from, date_to, normalized_as_of = _validate_query_windows(
        date_range=date_range,
        amount_range=amount_range,
        as_of=as_of,
        settings=settings,
    )

    root = _get_account_or_404(db, account_id)

    nodes, edges, truncated = _collect_subgraph(
        db,
        str(root.id),
        depth=limits["max_depth"],
        direction=direction,
        include_transactions=True,
        include_entities=False,
        include_complaints=False,
        include_alerts=False,
        include_assessments=False,
        date_from=date_from,
        date_to=date_to,
        amount_min=amount_range.amount_min,
        amount_max=amount_range.amount_max,
        as_of=normalized_as_of,
        limits=limits,
    )

    trails = _find_trails(
        nodes,
        edges,
        root_account_id=str(root.id),
        direction=direction,
        max_hops=limits["max_depth"],
        max_trails=limits["max_trails"],
    )

    if len(trails) >= limits["max_trails"]:
        truncated = True

    return MoneyTrailsResponse(
        generated_at=_now_utc(),
        root_account_id=str(root.id),
        direction=direction,
        max_hops=limits["max_depth"],
        trails=trails,
        truncated=truncated,
        caveats=list(_TRAIL_CAVEATS),
    )


__all__ = [
    "router",
]