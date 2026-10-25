"""
MULEGUARD backend graph limits.

This module provides the canonical bounded limits, constraints, and policy
validation for the synthetic MULEGUARD investigative graph subsystem.

Primary responsibilities:

- define strict, bounded limits for graph construction, traversal, path
  enumeration, community detection, cycle detection, and data export;
- enforce hard maximums to prevent unbounded resource consumption, memory
  exhaustion, and denial-of-service conditions during graph analysis;
- provide centralized, immutable policy objects (`GraphPolicy`) that aggregate
  construction, traversal, and export limits;
- validate limit configurations against hard safety boundaries and report
  bounded, safe validation results;
- preserve privacy by ensuring limit configurations and validation results
  contain no raw feature values, raw identifiers, raw narratives, subject-label
  pairs, secrets, tokens, passwords, database URLs, filesystem paths, or model
  artifact paths;
- remain import-safe, dependency-light, and resilient when optional project
  modules or configuration settings are unavailable.

This module defines and validates limits only. It does not execute graph
algorithms, train models, deploy models, persist durable artifacts, call
external systems, authenticate users, authorize actions, or take adverse action.

Security and product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for graph construction or analysis.
- Graph outputs are investigative leads only. They are not proof of wrongdoing,
  syndicates, cartels, or criminal associations.
- Shared entities, devices, IPs, phones, emails, UPI handles, or addresses are
  association patterns only. They are not proof of common control.
- Only completed transactions are treated as settled fund movement by default.
- Currency amounts are never converted or blended across currencies. Edge
  weights are derived from interaction counts, not monetary values.
- Labels may not be used as graph features or limit criteria.
- Ground-truth style fields such as `ground_truth`, `is_fraud`, `fraud_label`,
  `scenario_id`, and `ring_id` are rejected.
- Raw complaint narratives are forbidden inputs.
- Raw identifiers are forbidden outputs. Node linkage is pseudonymous and salted.
- Graph operations must never trigger automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, denying, terminating,
  suspending, referring to law enforcement, or making credit, employment,
  housing, insurance, benefits, or other consequential decisions.
- Undefined or unavailable limits are reported honestly rather than invented.
- This module does not claim production readiness.
- This module does not claim regulatory compliance.

Explicit non-goals:

- This module does not access databases.
- This module does not call external graph databases or model runtimes.
- This module does not deploy, promote, retire, upload, replace, or serve
  production models or graphs.
- This module does not generate synthetic ingestion records.
- This module does not replace feature schema validation.
- This module does not replace ingestion validation.
- This module is not a durable graph store.
- This module is not an authorization engine.
- This module is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, cycle
candidates, community candidates, filtered graphs, explanations, validation
reports, and case dispositions are investigative leads or human workflow
artefacts only. They are not proof of wrongdoing and must not trigger automatic
adverse customer action.
"""

from __future__ import annotations

import json
import logging
import math
import re
import threading
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field
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


logger = logging.getLogger("muleguard.backend.graph.limits")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

LIMITS_VERSION: Final[str] = "v1"

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.graph.limits.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"

# Graph Construction Limits
DEFAULT_MAX_NODES: Final[int] = 20_000
HARD_MAX_NODES: Final[int] = 100_000

DEFAULT_MAX_EDGES: Final[int] = 100_000
HARD_MAX_EDGES: Final[int] = 1_000_000

DEFAULT_MAX_RECORDS: Final[int] = 100_000
HARD_MAX_RECORDS: Final[int] = 1_000_000

# Traversal and Path Limits
DEFAULT_MAX_DEPTH: Final[int] = 5
HARD_MAX_DEPTH: Final[int] = 20

DEFAULT_MAX_PATHS: Final[int] = 100
HARD_MAX_PATHS: Final[int] = 10_000

DEFAULT_MAX_TRAILS: Final[int] = 50
HARD_MAX_TRAILS: Final[int] = 5_000

DEFAULT_MAX_GROUPS: Final[int] = 100
HARD_MAX_GROUPS: Final[int] = 5_000

DEFAULT_MAX_ACCOUNTS_PER_ENTITY: Final[int] = 100
HARD_MAX_ACCOUNTS_PER_ENTITY: Final[int] = 1_000

# Time and Window Limits
DEFAULT_MAX_DATE_SPAN_DAYS: Final[int] = 365
HARD_MAX_DATE_SPAN_DAYS: Final[int] = 3_650

DEFAULT_MAX_TIME_MS: Final[int] = 30_000
HARD_MAX_TIME_MS: Final[int] = 300_000

# Export and Summary Limits
DEFAULT_MAX_EXPORT_ITEMS: Final[int] = 1_000
HARD_MAX_EXPORT_ITEMS: Final[int] = 10_000

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

_MAX_TEXT_LENGTH: Final[int] = 512

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")

_LIMITS_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic graph limits configuration only. Do not use with real customer data.",
    "Limits are operational safeguards to prevent resource exhaustion and ensure bounded analysis.",
    "Exceeding limits results in truncation or rejection, not automatic adverse customer action.",
    "Graph outputs are investigative leads only and are not proof of wrongdoing.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

_LIMITS_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "bounded_graph_construction_required": True,
        "bounded_traversal_required": True,
        "bounded_export_required": True,
        "no_automatic_adverse_customer_action": True,
        "not_production_ready": True,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class LimitSeverity(str, Enum):
    """
    Limit validation issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class LimitCategory(str, Enum):
    """
    Limit validation category.
    """

    CONSTRUCTION = "construction"
    TRAVERSAL = "traversal"
    EXPORT = "export"
    POLICY = "policy"


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


def _as_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float) -> float:
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default

    if math.isnan(result) or math.isinf(result):
        return default

    return result


def _clamp_int(value: object, minimum: int, maximum: int, default: int) -> int:
    return max(minimum, min(_as_int(value, default), maximum))


def _clamp_float(value: object, minimum: float, maximum: float, default: float) -> float:
    return max(minimum, min(_as_float(value, default), maximum))


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
    # Enum members are unwrapped to their value first. For a `str`-mixin enum,
    # `str(Member)` is "ClassName.MEMBER", not "member" — so an enum passed
    # through here normalised to a token nothing recognised. That is what made
    # money-trail detection see zero money edges: every `GraphEdgeType.SENT`
    # edge normalised to `graph_edge_type_sent`, fell through the known-type
    # set, and became `related_to`.
    if isinstance(value, Enum):
        value = value.value

    return unicodedata.normalize("NFKC", str(value if value is not None else ""))


def _clean_text(value: Any, limit: int = _MAX_TEXT_LENGTH) -> str:
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

            if not key:
                continue

            out[key] = _safe_detail_value(raw_value, depth + 1)

        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_detail_value(item, depth + 1) for item in list(value)[:100]]

    return f"<{type(value).__name__}>"


def _as_mapping(value: Any) -> dict[str, Any]:
    sanitized = _safe_detail_value(value)
    return sanitized if isinstance(sanitized, dict) else {}


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


def _fingerprint_payload(payload: Any) -> str:
    import hashlib

    try:
        return hashlib.sha256(_canonical_json(payload).encode("utf-8", errors="replace")).hexdigest()
    except Exception:
        return hashlib.sha256(str(_safe_detail_value(payload)).encode("utf-8", errors="replace")).hexdigest()


def _normalize_enum(enum_cls: type[Enum], value: Any, default: Any) -> Any:
    """
    Coerce a value to an enum member, falling back to `default`.

    `LimitIssue.__post_init__` has always called this and it was never
    defined, so constructing an issue raised `NameError` — which meant limit
    validation crashed at exactly the moment it found a problem. A valid
    configuration validated fine; an invalid one took the request down instead
    of reporting what was wrong.

    Matches `_normalize_enum_option` in the sibling graph modules: accept a
    member as-is, match a string against member values and names through the
    token normaliser, and fall back rather than raise. Falling back is right
    here because an issue describing a configuration problem must not fail to
    be constructed over its own severity label.
    """
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


# -----------------------------------------------------------------------------
# Issue and Validation Models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LimitIssue:
    """
    Safe limit validation issue.
    """

    severity: LimitSeverity
    category: LimitCategory
    code: str
    message: str
    field: Optional[str] = None
    details: dict[str, Any] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", _normalize_enum(LimitSeverity, self.severity, LimitSeverity.WARNING))
        object.__setattr__(self, "category", _normalize_enum(LimitCategory, self.category, LimitCategory.POLICY))
        object.__setattr__(self, "code", _clean_text(self.code, 100))
        object.__setattr__(self, "message", _clean_text(self.message, 300))
        object.__setattr__(self, "field", _clean_text(self.field, 200) or None)
        object.__setattr__(self, "details", _as_mapping(self.details))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "severity": self.severity.value,
            "category": self.category.value,
            "code": self.code,
            "message": self.message,
        }

        if self.field:
            payload["field"] = self.field

        if self.details:
            payload["details"] = self.details

        return payload


@dataclass(frozen=True, slots=True)
class LimitValidationResult:
    """
    Safe limit validation result.
    """

    ok: bool = True
    issues: tuple[LimitIssue, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ok", _as_bool(self.ok, True))
        object.__setattr__(self, "issues", tuple(self.issues or ()))
        object.__setattr__(self, "metadata", MappingProxyType(_as_mapping(self.metadata)))

        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                _fingerprint_payload(
                    {
                        "version": LIMITS_VERSION,
                        "ok": self.ok,
                        "issue_count": len(self.issues),
                        "metadata": self.metadata,
                    }
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": _safe_detail_value(self.metadata),
            "fingerprint": self.fingerprint,
            "caveats": list(_LIMITS_CAVEATS),
            "safety_flags": dict(_LIMITS_SAFETY_FLAGS),
        }


def _append_issue(
    issues: list[LimitIssue],
    max_issues: int,
    *,
    severity: LimitSeverity,
    category: LimitCategory,
    code: str,
    message: str,
    field: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    limit = max(1, int(max_issues))

    if len(issues) >= limit:
        if issues and issues[-1].code == "issue_list_truncated":
            return

        issues[-1] = LimitIssue(
            severity=LimitSeverity.WARNING,
            category=LimitCategory.POLICY,
            code="issue_list_truncated",
            message="Issue list truncated by configured limit.",
        )
        return

    issues.append(
        LimitIssue(
            severity=severity,
            category=category,
            code=_clean_text(code, 100),
            message=_clean_text(message, 300),
            field=field,
            details=_as_mapping(details),
        )
    )


def _has_error(issues: Sequence[LimitIssue]) -> bool:
    return any(issue.severity == LimitSeverity.ERROR for issue in issues)


def _dedupe_issues(issues: Sequence[LimitIssue]) -> tuple[LimitIssue, ...]:
    seen: set[tuple[str, str, str, Optional[str]]] = set()
    out: list[LimitIssue] = []

    for issue in issues:
        key = (
            issue.severity.value,
            issue.category.value,
            issue.code,
            issue.field,
        )

        if key in seen:
            continue

        seen.add(key)
        out.append(issue)

    return tuple(out)


# -----------------------------------------------------------------------------
# Limit Configuration Models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphConstructionLimits:
    """
    Bounded graph construction limits.
    """

    max_nodes: int = DEFAULT_MAX_NODES
    max_edges: int = DEFAULT_MAX_EDGES
    max_records: int = DEFAULT_MAX_RECORDS
    max_window_days: int = DEFAULT_MAX_DATE_SPAN_DAYS

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_nodes", _clamp_int(self.max_nodes, 1, HARD_MAX_NODES, DEFAULT_MAX_NODES))
        object.__setattr__(self, "max_edges", _clamp_int(self.max_edges, 1, HARD_MAX_EDGES, DEFAULT_MAX_EDGES))
        object.__setattr__(self, "max_records", _clamp_int(self.max_records, 1, HARD_MAX_RECORDS, DEFAULT_MAX_RECORDS))
        object.__setattr__(self, "max_window_days", _clamp_int(self.max_window_days, 1, HARD_MAX_DATE_SPAN_DAYS, DEFAULT_MAX_DATE_SPAN_DAYS))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "GraphConstructionLimits":
        if settings is None:
            try:
                from app.core.config import get_settings
                settings = get_settings()
            except Exception:
                settings = {}

        return cls(
            max_nodes=_as_int(_setting(settings, "GRAPH_MAX_NODES", DEFAULT_MAX_NODES), DEFAULT_MAX_NODES),
            max_edges=_as_int(_setting(settings, "GRAPH_MAX_EDGES", DEFAULT_MAX_EDGES), DEFAULT_MAX_EDGES),
            max_records=_as_int(_setting(settings, "GRAPH_MAX_RECORDS", DEFAULT_MAX_RECORDS), DEFAULT_MAX_RECORDS),
            max_window_days=_as_int(_setting(settings, "GRAPH_MAX_WINDOW_DAYS", DEFAULT_MAX_DATE_SPAN_DAYS), DEFAULT_MAX_DATE_SPAN_DAYS),
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "max_nodes": int(self.max_nodes),
            "max_edges": int(self.max_edges),
            "max_records": int(self.max_records),
            "max_window_days": int(self.max_window_days),
        }


@dataclass(frozen=True, slots=True)
class GraphTraversalLimits:
    """
    Bounded graph traversal and path-finding limits.
    """

    max_depth: int = DEFAULT_MAX_DEPTH
    max_paths: int = DEFAULT_MAX_PATHS
    max_trails: int = DEFAULT_MAX_TRAILS
    max_groups: int = DEFAULT_MAX_GROUPS
    max_accounts_per_entity: int = DEFAULT_MAX_ACCOUNTS_PER_ENTITY
    max_time_ms: int = DEFAULT_MAX_TIME_MS

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_depth", _clamp_int(self.max_depth, 1, HARD_MAX_DEPTH, DEFAULT_MAX_DEPTH))
        object.__setattr__(self, "max_paths", _clamp_int(self.max_paths, 1, HARD_MAX_PATHS, DEFAULT_MAX_PATHS))
        object.__setattr__(self, "max_trails", _clamp_int(self.max_trails, 1, HARD_MAX_TRAILS, DEFAULT_MAX_TRAILS))
        object.__setattr__(self, "max_groups", _clamp_int(self.max_groups, 1, HARD_MAX_GROUPS, DEFAULT_MAX_GROUPS))
        object.__setattr__(self, "max_accounts_per_entity", _clamp_int(self.max_accounts_per_entity, 1, HARD_MAX_ACCOUNTS_PER_ENTITY, DEFAULT_MAX_ACCOUNTS_PER_ENTITY))
        object.__setattr__(self, "max_time_ms", _clamp_int(self.max_time_ms, 100, HARD_MAX_TIME_MS, DEFAULT_MAX_TIME_MS))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "GraphTraversalLimits":
        if settings is None:
            try:
                from app.core.config import get_settings
                settings = get_settings()
            except Exception:
                settings = {}

        return cls(
            max_depth=_as_int(_setting(settings, "GRAPH_MAX_DEPTH", DEFAULT_MAX_DEPTH), DEFAULT_MAX_DEPTH),
            max_paths=_as_int(_setting(settings, "GRAPH_MAX_PATHS", DEFAULT_MAX_PATHS), DEFAULT_MAX_PATHS),
            max_trails=_as_int(_setting(settings, "GRAPH_MAX_TRAILS", DEFAULT_MAX_TRAILS), DEFAULT_MAX_TRAILS),
            max_groups=_as_int(_setting(settings, "GRAPH_MAX_GROUPS", DEFAULT_MAX_GROUPS), DEFAULT_MAX_GROUPS),
            max_accounts_per_entity=_as_int(_setting(settings, "GRAPH_MAX_ACCOUNTS_PER_ENTITY", DEFAULT_MAX_ACCOUNTS_PER_ENTITY), DEFAULT_MAX_ACCOUNTS_PER_ENTITY),
            max_time_ms=_as_int(_setting(settings, "GRAPH_MAX_TIME_MS", DEFAULT_MAX_TIME_MS), DEFAULT_MAX_TIME_MS),
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "max_depth": int(self.max_depth),
            "max_paths": int(self.max_paths),
            "max_trails": int(self.max_trails),
            "max_groups": int(self.max_groups),
            "max_accounts_per_entity": int(self.max_accounts_per_entity),
            "max_time_ms": int(self.max_time_ms),
        }


@dataclass(frozen=True, slots=True)
class GraphExportLimits:
    """
    Bounded graph export limits.
    """

    max_items: int = DEFAULT_MAX_EXPORT_ITEMS

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_items", _clamp_int(self.max_items, 1, HARD_MAX_EXPORT_ITEMS, DEFAULT_MAX_EXPORT_ITEMS))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "GraphExportLimits":
        if settings is None:
            try:
                from app.core.config import get_settings
                settings = get_settings()
            except Exception:
                settings = {}

        return cls(
            max_items=_as_int(_setting(settings, "GRAPH_MAX_EXPORT_ITEMS", DEFAULT_MAX_EXPORT_ITEMS), DEFAULT_MAX_EXPORT_ITEMS),
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "max_items": int(self.max_items),
        }


@dataclass(frozen=True, slots=True)
class GraphPolicy:
    """
    Unified bounded graph policy.
    """

    construction: GraphConstructionLimits = dataclass_field(default_factory=GraphConstructionLimits)
    traversal: GraphTraversalLimits = dataclass_field(default_factory=GraphTraversalLimits)
    export: GraphExportLimits = dataclass_field(default_factory=GraphExportLimits)
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.construction, GraphConstructionLimits):
            object.__setattr__(self, "construction", GraphConstructionLimits(**(self.construction or {})))

        if not isinstance(self.traversal, GraphTraversalLimits):
            object.__setattr__(self, "traversal", GraphTraversalLimits(**(self.traversal or {})))

        if not isinstance(self.export, GraphExportLimits):
            object.__setattr__(self, "export", GraphExportLimits(**(self.export or {})))

        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "dataset_mode", _normalize_token(self.dataset_mode) or "synthetic")
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "GraphPolicy":
        if settings is None:
            try:
                from app.core.config import get_settings
                settings = get_settings()
            except Exception:
                settings = {}

        env = str(_setting(settings, "BACKEND_ENV", "local")).strip().lower()
        production_values = {value.lower() for value in _csv(_setting(settings, "BACKEND_PRODUCTION_LIKE_ENVS", "production,staging,prod,stage"))}

        if not production_values:
            production_values = {"production", "staging", "prod", "stage"}

        return cls(
            construction=GraphConstructionLimits.from_settings(settings),
            traversal=GraphTraversalLimits.from_settings(settings),
            export=GraphExportLimits.from_settings(settings),
            synthetic_required=_as_bool(_setting(settings, "GRAPH_REQUIRE_SYNTHETIC", True), True),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=env in production_values,
            allow_in_production=_as_bool(_setting(settings, "GRAPH_ALLOW_IN_PRODUCTION", False), False),
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "construction": self.construction.safe_summary(),
            "traversal": self.traversal.safe_summary(),
            "export": self.export.safe_summary(),
            "synthetic_required": self.synthetic_required,
            "dataset_mode": self.dataset_mode,
            "production_like": self.production_like,
            "allow_in_production": self.allow_in_production,
        }


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------


def validate_construction_limits(
    limits: GraphConstructionLimits,
    *,
    max_issues: int = DEFAULT_MAX_ISSUES,
) -> LimitValidationResult:
    """
    Validate bounded graph construction limits.
    """
    issues: list[LimitIssue] = []

    if limits.max_nodes < 2:
        _append_issue(
            issues,
            max_issues,
            severity=LimitSeverity.ERROR,
            category=LimitCategory.CONSTRUCTION,
            code="invalid_max_nodes",
            message="max_nodes must be at least 2.",
            field="max_nodes",
        )

    if limits.max_edges < 1:
        _append_issue(
            issues,
            max_issues,
            severity=LimitSeverity.ERROR,
            category=LimitCategory.CONSTRUCTION,
            code="invalid_max_edges",
            message="max_edges must be at least 1.",
            field="max_edges",
        )

    if limits.max_window_days < 1:
        _append_issue(
            issues,
            max_issues,
            severity=LimitSeverity.WARNING,
            category=LimitCategory.CONSTRUCTION,
            code="invalid_max_window_days",
            message="max_window_days is less than 1.",
            field="max_window_days",
        )

    ok = not _has_error(issues)

    return LimitValidationResult(
        ok=ok,
        issues=_dedupe_issues(issues)[:max_issues],
        metadata={
            "limits_version": LIMITS_VERSION,
            "category": LimitCategory.CONSTRUCTION.value,
            "limits": limits.safe_summary(),
            "caveats": list(_LIMITS_CAVEATS),
            "safety_flags": dict(_LIMITS_SAFETY_FLAGS),
        },
    )


def validate_traversal_limits(
    limits: GraphTraversalLimits,
    *,
    max_issues: int = DEFAULT_MAX_ISSUES,
) -> LimitValidationResult:
    """
    Validate bounded graph traversal limits.
    """
    issues: list[LimitIssue] = []

    if limits.max_depth < 1:
        _append_issue(
            issues,
            max_issues,
            severity=LimitSeverity.ERROR,
            category=LimitCategory.TRAVERSAL,
            code="invalid_max_depth",
            message="max_depth must be at least 1.",
            field="max_depth",
        )

    if limits.max_time_ms < 100:
        _append_issue(
            issues,
            max_issues,
            severity=LimitSeverity.WARNING,
            category=LimitCategory.TRAVERSAL,
            code="low_max_time_ms",
            message="max_time_ms is very low and may cause premature truncation.",
            field="max_time_ms",
        )

    ok = not _has_error(issues)

    return LimitValidationResult(
        ok=ok,
        issues=_dedupe_issues(issues)[:max_issues],
        metadata={
            "limits_version": LIMITS_VERSION,
            "category": LimitCategory.TRAVERSAL.value,
            "limits": limits.safe_summary(),
            "caveats": list(_LIMITS_CAVEATS),
            "safety_flags": dict(_LIMITS_SAFETY_FLAGS),
        },
    )


def validate_policy(
    policy: GraphPolicy,
    *,
    max_issues: int = DEFAULT_MAX_ISSUES,
) -> LimitValidationResult:
    """
    Validate the unified graph policy.
    """
    issues: list[LimitIssue] = []

    construction_result = validate_construction_limits(policy.construction, max_issues=max_issues)
    issues.extend(construction_result.issues)

    traversal_result = validate_traversal_limits(policy.traversal, max_issues=max_issues)
    issues.extend(traversal_result.issues)

    if policy.synthetic_required and policy.dataset_mode != "synthetic":
        _append_issue(
            issues,
            max_issues,
            severity=LimitSeverity.ERROR,
            category=LimitCategory.POLICY,
            code="non_synthetic_dataset",
            message="Graph policy requires synthetic dataset mode.",
            field="dataset_mode",
            details={"dataset_mode": policy.dataset_mode},
        )

    if policy.production_like and not policy.allow_in_production:
        _append_issue(
            issues,
            max_issues,
            severity=LimitSeverity.ERROR,
            category=LimitCategory.POLICY,
            code="production_like_blocked",
            message="Graph policy is blocked in production-like environments.",
        )

    ok = not _has_error(issues)

    return LimitValidationResult(
        ok=ok,
        issues=_dedupe_issues(issues)[:max_issues],
        metadata={
            "limits_version": LIMITS_VERSION,
            "category": LimitCategory.POLICY.value,
            "policy": policy.safe_summary(),
            "caveats": list(_LIMITS_CAVEATS),
            "safety_flags": dict(_LIMITS_SAFETY_FLAGS),
        },
    )


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


_default_policy: Optional[GraphPolicy] = None
_default_policy_lock = threading.Lock()


def get_graph_policy(settings: Any | None = None) -> GraphPolicy:
    """
    Return the process-wide graph policy.
    """
    global _default_policy

    with _default_policy_lock:
        if _default_policy is None:
            _default_policy = GraphPolicy.from_settings(settings)

        return _default_policy


def get_limits_metadata() -> dict[str, Any]:
    """
    Return safe, serializable graph limits metadata.
    """
    policy = get_graph_policy()

    return {
        "package": "muleguard.backend.graph.limits",
        "version": LIMITS_VERSION,
        "default_policy": policy.safe_summary(),
        "hard_limits": {
            "max_nodes": HARD_MAX_NODES,
            "max_edges": HARD_MAX_EDGES,
            "max_records": HARD_MAX_RECORDS,
            "max_depth": HARD_MAX_DEPTH,
            "max_paths": HARD_MAX_PATHS,
            "max_trails": HARD_MAX_TRAILS,
            "max_groups": HARD_MAX_GROUPS,
            "max_accounts_per_entity": HARD_MAX_ACCOUNTS_PER_ENTITY,
            "max_date_span_days": HARD_MAX_DATE_SPAN_DAYS,
            "max_time_ms": HARD_MAX_TIME_MS,
            "max_export_items": HARD_MAX_EXPORT_ITEMS,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
        },
        "caveats": list(_LIMITS_CAVEATS),
        "safety_flags": dict(_LIMITS_SAFETY_FLAGS),
    }


__all__ = [
    "GraphConstructionLimits",
    "GraphExportLimits",
    "GraphPolicy",
    "GraphTraversalLimits",
    "LimitCategory",
    "LimitIssue",
    "LimitSeverity",
    "LimitValidationResult",
    "get_graph_policy",
    "get_limits_metadata",
    "validate_construction_limits",
    "validate_policy",
    "validate_traversal_limits",
]