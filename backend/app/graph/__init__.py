"""
MULEGUARD backend graph package.

This module is the public entry point for the MULEGUARD graph-analytics
subsystem.

Its responsibilities are intentionally narrow:

- expose stable graph-layer constants, metadata, and bounded policy defaults;
- declare synthetic-first graph conventions and investigation-only semantics;
- declare supported node types, edge types, traversal directions, path kinds,
  community methods, centrality methods, graph statuses, and bounded limits;
- provide safe helpers for normalization, policy resolution, and metadata
  inspection;
- provide lazy access to graph submodules and selected public symbols;
- avoid eager imports of FastAPI, SQLAlchemy, Pydantic, ingestion, ML, rules,
  reporting, audit, filesystem, network, or training-runtime dependencies
  during package initialization.

This package must not become a place where heavy graph algorithms are executed
at import time.

Graph submodules:

- service:        high-level graph orchestration and run coordination
- builder:        bounded graph construction from synthetic records
- traversal:      bounded directed/undirected traversal
- paths:          bounded candidate path enumeration
- money_trails:   bounded heuristic candidate money-trail detection
- shared_entities: bounded shared-entity cluster detection
- communities:    bounded community and connected-component detection
- centrality:     bounded degree, PageRank, and betweenness measures
- correlation:    bounded complaint correlation association signals
- lineage:        safe provenance and lineage helpers for graph runs
- export:         bounded graph export summaries
- policies:       graph policy resolution helpers
- repositories:   persistence-facing graph-run repositories
- models:         graph DTOs and internal models
- errors:         graph-specific error helpers

Security and product-safety expectations for the graph layer:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for graph construction, traversal, path
  enumeration, community detection, centrality, or correlation.
- Graph relationships, candidate paths, candidate money trails, shared-entity
  clusters, and complaint correlations are investigative leads only.
- They are not proof of common control, fraud, intent, conspiracy, or
  wrongdoing.
- Path, trail, cluster, and centrality ordering is heuristic and must never be
  interpreted as legal, evidentiary, or causal priority.
- Graph scores, centrality measures, intermediary scores, and concentration
  measures are investigative prioritization signals, not probabilities of
  guilt.
- Shared devices, phones, UPI identifiers, email identifiers, address buckets,
  IP buckets, or other entities are association signals only.
- Candidate money trails are heuristic flow views only and are not proof of
  layering, integration, or placement.
- Only completed transactions represent settled fund movement. Pending, failed,
  reversed, cancelled, and disputed states remain semantically distinct.
- Mixed-currency amounts are reported per currency and are never converted or
  aggregated across currencies. No FX assumption is made.
- Raw complaint narratives, raw identifiers, ground-truth labels, injected
  scenario IDs, and fraud-ring IDs are never read, hashed, stored, logged, or
  returned by this package.
- Secrets, tokens, passwords, database URLs, filesystem paths, and model
  artifact paths are never exposed.
- Subject, source, case, and entity linkage is pseudonymous and salted.
- Truncation, emptiness, and unavailability are reported honestly rather than
  silently omitted or invented.
- Graph analytics must never trigger automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, denying,
  terminating, suspending, referring to law enforcement, or making credit,
  employment, housing, insurance, benefits, or other consequential decisions.
- The bundled graph-run registry is process-local, non-durable, and bounded for
  local prototype use only.
- This package does not claim production readiness.
- This package does not claim regulatory compliance.

Explicit non-goals:

- This package does not access databases.
- This package does not call external graph databases or graph engines.
- This package does not persist durable graph snapshots.
- This package does not generate synthetic ingestion records.
- This package does not replace ingestion validation.
- This package does not replace feature schema validation.
- This package does not train, promote, retire, upload, replace, or execute
  models.
- This package is not an authorization engine.
- This package is not a legal or regulatory adjudication system.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Alerts, risk scores,
graph relationships, candidate money trails, entity links, complaint
correlations, anomaly scores, fallback scores, model predictions, rule
evaluations, threshold profiles, evidence bundles, explanations, validation
reports, and case dispositions are investigative leads or human workflow
artefacts only. They are not proof of wrongdoing and must not trigger automatic
adverse customer action.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import importlib
import math
import re
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Optional


logger = logging.getLogger("muleguard.backend.graph")


# -----------------------------------------------------------------------------
# Execution guard
# -----------------------------------------------------------------------------
# This package is intended to be imported as part of the backend application.
# Direct execution is not a supported entrypoint.
if __package__ in {None, ""}:
    raise RuntimeError(
        "Do not execute app/graph/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Stable graph metadata
# -----------------------------------------------------------------------------

GRAPH_PACKAGE_NAME: Final[str] = "muleguard.backend.graph"
GRAPH_LAYER: Final[str] = "graph"
GRAPH_VERSION: Final[str] = "v1"

GRAPH_API_PREFIX: Final[str] = "/api/v1/graph"


# -----------------------------------------------------------------------------
# Boolean parsing literals
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_SALT: Final[str] = "muleguard.graph.default.salt"
_DEFAULT_NAMESPACE: Final[str] = "default"
_DEFAULT_SEED: Final[int] = 42

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


# -----------------------------------------------------------------------------
# Bounded graph limits
# -----------------------------------------------------------------------------

DEFAULT_MAX_NODES: Final[int] = 1_000
HARD_MAX_NODES: Final[int] = 1_000

DEFAULT_MAX_EDGES: Final[int] = 2_000
HARD_MAX_EDGES: Final[int] = 2_000

DEFAULT_MAX_DEPTH: Final[int] = 5
HARD_MAX_DEPTH: Final[int] = 5

DEFAULT_MAX_PATHS: Final[int] = 100
HARD_MAX_PATHS: Final[int] = 100

DEFAULT_MAX_TRAILS: Final[int] = 100
HARD_MAX_TRAILS: Final[int] = 100

DEFAULT_MAX_SHARED_GROUPS: Final[int] = 100
HARD_MAX_SHARED_GROUPS: Final[int] = 100

DEFAULT_MAX_ACCOUNTS_PER_ENTITY: Final[int] = 100
HARD_MAX_ACCOUNTS_PER_ENTITY: Final[int] = 100

DEFAULT_MAX_COMMUNITIES: Final[int] = 100
HARD_MAX_COMMUNITIES: Final[int] = 500

DEFAULT_MAX_COMMUNITY_SIZE: Final[int] = 500
HARD_MAX_COMMUNITY_SIZE: Final[int] = 5_000

DEFAULT_MAX_DATE_SPAN_DAYS: Final[int] = 3_650
HARD_MAX_DATE_SPAN_DAYS: Final[int] = 3_650

DEFAULT_MAX_TIME_MS: Final[int] = 60_000
HARD_MAX_TIME_MS: Final[int] = 300_000

DEFAULT_MAX_ISSUES: Final[int] = 100
HARD_MAX_ISSUES: Final[int] = 500

DEFAULT_MAX_SUMMARY_ITEMS: Final[int] = 50
HARD_MAX_SUMMARY_ITEMS: Final[int] = 500

DEFAULT_MAX_RUNS: Final[int] = 500
HARD_MAX_RUNS: Final[int] = 10_000

DEFAULT_MAX_FEATURES_PER_NODE: Final[int] = 64
HARD_MAX_FEATURES_PER_NODE: Final[int] = 512


# -----------------------------------------------------------------------------
# Node and edge types
# -----------------------------------------------------------------------------

NODE_ACCOUNT: Final[str] = "account"
NODE_TRANSACTION: Final[str] = "transaction"
NODE_ENTITY: Final[str] = "entity"
NODE_COMPLAINT: Final[str] = "complaint"
NODE_ALERT: Final[str] = "alert"
NODE_ASSESSMENT: Final[str] = "assessment"
NODE_CASE: Final[str] = "case"

GRAPH_NODE_TYPES: Final[tuple[str, ...]] = (
    NODE_ACCOUNT,
    NODE_TRANSACTION,
    NODE_ENTITY,
    NODE_COMPLAINT,
    NODE_ALERT,
    NODE_ASSESSMENT,
    NODE_CASE,
)

EDGE_SENT: Final[str] = "sent"
EDGE_RECEIVED: Final[str] = "received"
EDGE_LINKED_TO: Final[str] = "linked_to"
EDGE_RELATED_TO: Final[str] = "related_to"
EDGE_CORRELATED_WITH: Final[str] = "correlated_with"
EDGE_ALERTED_ON: Final[str] = "alerted_on"
EDGE_ASSESSED_BY: Final[str] = "assessed_by"
EDGE_ATTACHED_TO_CASE: Final[str] = "attached_to_case"

GRAPH_EDGE_TYPES: Final[tuple[str, ...]] = (
    EDGE_SENT,
    EDGE_RECEIVED,
    EDGE_LINKED_TO,
    EDGE_RELATED_TO,
    EDGE_CORRELATED_WITH,
    EDGE_ALERTED_ON,
    EDGE_ASSESSED_BY,
    EDGE_ATTACHED_TO_CASE,
)

DIRECTION_OUTGOING: Final[str] = "outgoing"
DIRECTION_INCOMING: Final[str] = "incoming"
DIRECTION_BOTH: Final[str] = "both"

TRAVERSAL_DIRECTIONS: Final[tuple[str, ...]] = (
    DIRECTION_OUTGOING,
    DIRECTION_INCOMING,
    DIRECTION_BOTH,
)

_NODE_TYPE_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "acct": NODE_ACCOUNT,
        "account_node": NODE_ACCOUNT,
        "txn": NODE_TRANSACTION,
        "tx": NODE_TRANSACTION,
        "transaction_node": NODE_TRANSACTION,
        "ent": NODE_ENTITY,
        "entity_node": NODE_ENTITY,
        "cmpl": NODE_COMPLAINT,
        "complaint_node": NODE_COMPLAINT,
        "alert_node": NODE_ALERT,
        "assessment_node": NODE_ASSESSMENT,
        "model_assessment": NODE_ASSESSMENT,
        "model_assessment_node": NODE_ASSESSMENT,
        "investigation_case": NODE_CASE,
        "case_node": NODE_CASE,
    }
)

_EDGE_TYPE_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "transfer_sent": EDGE_SENT,
        "sent_to": EDGE_SENT,
        "outbound": EDGE_SENT,
        "transfer_received": EDGE_RECEIVED,
        "received_from": EDGE_RECEIVED,
        "inbound": EDGE_RECEIVED,
        "link": EDGE_LINKED_TO,
        "linked": EDGE_LINKED_TO,
        "entity_link": EDGE_LINKED_TO,
        "relation": EDGE_RELATED_TO,
        "related": EDGE_RELATED_TO,
        "correlation": EDGE_CORRELATED_WITH,
        "correlated": EDGE_CORRELATED_WITH,
        "complaint_correlation": EDGE_CORRELATED_WITH,
        "alert": EDGE_ALERTED_ON,
        "alerted": EDGE_ALERTED_ON,
        "scored_by": EDGE_ASSESSED_BY,
        "assessed": EDGE_ASSESSED_BY,
        "case_attached": EDGE_ATTACHED_TO_CASE,
        "attached": EDGE_ATTACHED_TO_CASE,
    }
)

_DIRECTION_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "out": DIRECTION_OUTGOING,
        "outbound": DIRECTION_OUTGOING,
        "downstream": DIRECTION_OUTGOING,
        "in": DIRECTION_INCOMING,
        "inbound": DIRECTION_INCOMING,
        "upstream": DIRECTION_INCOMING,
        "bidirectional": DIRECTION_BOTH,
        "both": DIRECTION_BOTH,
        "all": DIRECTION_BOTH,
    }
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class GraphNodeType(str, Enum):
    """
    Bounded graph node type.
    """

    ACCOUNT = NODE_ACCOUNT
    TRANSACTION = NODE_TRANSACTION
    ENTITY = NODE_ENTITY
    COMPLAINT = NODE_COMPLAINT
    ALERT = NODE_ALERT
    ASSESSMENT = NODE_ASSESSMENT
    CASE = NODE_CASE


class GraphEdgeType(str, Enum):
    """
    Bounded graph edge type.

    Edge types are investigative association signals only. They are not proof
    of common control or wrongdoing.
    """

    SENT = EDGE_SENT
    RECEIVED = EDGE_RECEIVED
    LINKED_TO = EDGE_LINKED_TO
    RELATED_TO = EDGE_RELATED_TO
    CORRELATED_WITH = EDGE_CORRELATED_WITH
    ALERTED_ON = EDGE_ALERTED_ON
    ASSESSED_BY = EDGE_ASSESSED_BY
    ATTACHED_TO_CASE = EDGE_ATTACHED_TO_CASE


class TraversalDirection(str, Enum):
    """
    Bounded traversal direction.
    """

    OUTGOING = DIRECTION_OUTGOING
    INCOMING = DIRECTION_INCOMING
    BOTH = DIRECTION_BOTH


class PathKind(str, Enum):
    """
    Bounded candidate path kind.

    All path kinds are heuristic investigative views only.
    """

    DIRECTED = "directed"
    UNDIRECTED = "undirected"
    MONEY_TRAIL = "money_trail"
    SHARED_ENTITY = "shared_entity"
    COMPLAINT_CORRELATION = "complaint_correlation"


class CommunityMethod(str, Enum):
    """
    Bounded community detection method.
    """

    CONNECTED_COMPONENT = "connected_component"
    SHARED_ENTITY_CLUSTER = "shared_entity_cluster"
    LABEL_PROPAGATION = "label_propagation"


class CentralityMethod(str, Enum):
    """
    Bounded centrality method.

    Centrality measures are investigative prioritization signals only.
    """

    DEGREE = "degree"
    IN_DEGREE = "in_degree"
    OUT_DEGREE = "out_degree"
    PAGE_RANK = "page_rank"
    BETWEENNESS = "betweenness"


class GraphStatus(str, Enum):
    """
    Bounded graph or graph-run status.
    """

    AVAILABLE = "available"
    EMPTY = "empty"
    TRUNCATED = "truncated"
    DEGRADED = "degraded"
    BLOCKED = "blocked"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class IssueSeverity(str, Enum):
    """
    Issue severity.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


# -----------------------------------------------------------------------------
# Graph caveats and safety flags
# -----------------------------------------------------------------------------

GRAPH_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic graph analytics only. Do not use with real customer data.",
    "Graph relationships, candidate paths, candidate money trails, shared-entity clusters, and complaint correlations are investigative leads only.",
    "They are not proof of common control, fraud, intent, conspiracy, or wrongdoing.",
    "Path, trail, cluster, and centrality ordering is heuristic and must not be interpreted as legal, evidentiary, or causal priority.",
    "Graph scores, centrality measures, intermediary scores, and concentration measures are investigative prioritization signals, not probabilities of guilt.",
    "Shared devices, phones, UPI identifiers, email identifiers, address buckets, IP buckets, or other entities are association signals only.",
    "Candidate money trails are heuristic flow views only and are not proof of layering, integration, or placement.",
    "Only completed transactions represent settled fund movement. Pending, failed, reversed, cancelled, and disputed states remain distinct.",
    "Mixed-currency amounts are reported per currency and are never converted or aggregated across currencies.",
    "Raw complaint narratives, raw identifiers, ground-truth labels, injected scenario IDs, and fraud-ring IDs are never read or exposed.",
    "Secrets, tokens, passwords, database URLs, filesystem paths, and model artifact paths are never exposed.",
    "Subject, source, case, and entity linkage is pseudonymous and salted.",
    "Truncation, emptiness, and unavailability are reported honestly rather than silently omitted or invented.",
    "Graph analytics must not trigger automatic adverse customer action.",
    "Human review is required before any consequential action.",
    "The bundled graph-run registry is process-local, non-durable, and not production-ready.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)

GRAPH_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "synthetic_only_by_default": True,
        "no_real_customer_data_by_default": True,
        "no_ground_truth_labels_accepted": True,
        "no_scenario_ids_accepted": True,
        "no_fraud_ring_ids_accepted": True,
        "no_raw_narratives_accepted": True,
        "no_raw_identifiers_accepted": True,
        "no_secrets_accepted": True,
        "no_tokens_accepted": True,
        "no_passwords_accepted": True,
        "no_database_urls_accepted": True,
        "no_model_artifact_paths_accepted": True,
        "salted_pseudonymous_reference_hashes": True,
        "bounded_graph_required": True,
        "deterministic_graph_construction": True,
        "graph_outputs_are_investigative_leads_only": True,
        "path_ordering_is_heuristic_only": True,
        "shared_entities_are_association_signals_only": True,
        "money_trails_are_heuristic_views_only": True,
        "completed_transactions_are_settled_movement_only": True,
        "mixed_currency_aggregation_disallowed": True,
        "no_automatic_adverse_customer_action": True,
        "human_review_required_for_consequential_action": True,
        "not_production_ready": True,
        "does_not_claim_regulatory_compliance": True,
    }
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

    if math.isnan(parsed) or math.isinf(parsed):
        return default

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


def _normalize_token(value: Any) -> str:
    """
    Normalize a token-like value into lower snake_case.
    """
    text = _normalize_unicode(value).strip()

    if not text:
        return ""

    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_").lower()


def _clean_text(value: Any, limit: int = 512) -> str:
    """
    Return a safe single-line text value.
    """
    text = _normalize_unicode(value)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if limit <= 0:
        return ""

    if len(text) > limit:
        return text[:limit]

    return text


def _is_placeholder_secret(value: str) -> bool:
    """
    Return True when a value looks like a placeholder secret.
    """
    if not value:
        return True

    lowered = value.strip().lower()

    if not lowered:
        return True

    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _ensure_salt(salt: Any) -> str:
    """
    Ensure the graph salt is non-empty, sufficiently long, and not an obvious
    placeholder.

    The salt is never emitted in public summaries.
    """
    text = str(salt or "").strip()

    if not text or _is_placeholder_secret(text):
        text = _DEFAULT_SALT

    encoded = text.encode("utf-8", errors="replace")

    if len(encoded) < 16:
        return hashlib.sha256(encoded).hexdigest()

    return text


def _json_default(value: Any) -> Any:
    """
    JSON serializer fallback for canonicalization.
    """
    if isinstance(value, datetime):
        normalized = _ensure_utc(value)
        return normalized.isoformat() if normalized else None

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}

    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)

    if isinstance(value, tuple):
        return list(value)

    return str(value)


def _canonical_json(value: Any) -> str:
    """
    Return deterministic canonical JSON.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    )


def _fingerprint_payload(payload: Any) -> str:
    """
    Return a deterministic fingerprint for a safe payload.
    """
    try:
        return hashlib.sha256(_canonical_json(payload).encode("utf-8", errors="replace")).hexdigest()
    except Exception:
        return hashlib.sha256(str(payload).encode("utf-8", errors="replace")).hexdigest()


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


def _is_synthetic_dataset_mode(value: Any) -> bool:
    """
    Return True when a dataset-mode-like value is synthetic-compatible.
    """
    return _normalize_token(value) in {"synthetic", "demo", "test", "fixture", "fixtures"}


# -----------------------------------------------------------------------------
# Normalization helpers
# -----------------------------------------------------------------------------


def normalize_node_type(value: Any, default: str = NODE_ACCOUNT) -> str:
    """
    Normalize a graph node type.
    """
    token = _normalize_token(value)

    if token in GRAPH_NODE_TYPES:
        return token

    alias = _NODE_TYPE_ALIASES.get(token)

    if alias is not None:
        return alias

    return default


def normalize_edge_type(value: Any, default: str = EDGE_RELATED_TO) -> str:
    """
    Normalize a graph edge type.
    """
    token = _normalize_token(value)

    if token in GRAPH_EDGE_TYPES:
        return token

    alias = _EDGE_TYPE_ALIASES.get(token)

    if alias is not None:
        return alias

    return default


def normalize_direction(value: Any, default: str = DIRECTION_BOTH) -> str:
    """
    Normalize a traversal direction.
    """
    token = _normalize_token(value)

    if token in TRAVERSAL_DIRECTIONS:
        return token

    alias = _DIRECTION_ALIASES.get(token)

    if alias is not None:
        return alias

    return default


def normalize_path_kind(value: Any, default: str = PathKind.DIRECTED.value) -> str:
    """
    Normalize a candidate path kind.
    """
    token = _normalize_token(value)
    valid = {member.value for member in PathKind}

    aliases = {
        "trail": PathKind.MONEY_TRAIL.value,
        "money_trail": PathKind.MONEY_TRAIL.value,
        "candidate_trail": PathKind.MONEY_TRAIL.value,
        "shared": PathKind.SHARED_ENTITY.value,
        "shared_entity": PathKind.SHARED_ENTITY.value,
        "entity_cluster": PathKind.SHARED_ENTITY.value,
        "correlation": PathKind.COMPLAINT_CORRELATION.value,
        "complaint_correlation": PathKind.COMPLAINT_CORRELATION.value,
        "undirected": PathKind.UNDIRECTED.value,
        "directed": PathKind.DIRECTED.value,
    }

    if token in valid:
        return token

    alias = aliases.get(token)

    if alias is not None:
        return alias

    return default


def normalize_community_method(value: Any, default: CommunityMethod = CommunityMethod.SHARED_ENTITY_CLUSTER) -> CommunityMethod:
    """
    Normalize a community detection method.
    """
    token = _normalize_token(value)
    valid = {member.value for member in CommunityMethod}

    aliases = {
        "component": CommunityMethod.CONNECTED_COMPONENT.value,
        "connected": CommunityMethod.CONNECTED_COMPONENT.value,
        "connected_component": CommunityMethod.CONNECTED_COMPONENT.value,
        "cluster": CommunityMethod.SHARED_ENTITY_CLUSTER.value,
        "shared": CommunityMethod.SHARED_ENTITY_CLUSTER.value,
        "shared_entity": CommunityMethod.SHARED_ENTITY_CLUSTER.value,
        "shared_entity_cluster": CommunityMethod.SHARED_ENTITY_CLUSTER.value,
        "label": CommunityMethod.LABEL_PROPAGATION.value,
        "label_propagation": CommunityMethod.LABEL_PROPAGATION.value,
    }

    if token in valid:
        return CommunityMethod(token)

    alias = aliases.get(token)

    if alias is not None:
        return CommunityMethod(alias)

    return default


def normalize_centrality_methods(value: Any, default: Optional[Sequence[CentralityMethod]] = None) -> tuple[CentralityMethod, ...]:
    """
    Normalize a set of centrality methods.
    """
    resolved_default = tuple(default or (CentralityMethod.DEGREE, CentralityMethod.PAGE_RANK))

    if value is None:
        return resolved_default

    valid = {member.value for member in CentralityMethod}

    aliases = {
        "in": CentralityMethod.IN_DEGREE.value,
        "out": CentralityMethod.OUT_DEGREE.value,
        "pagerank": CentralityMethod.PAGE_RANK.value,
        "between": CentralityMethod.BETWEENNESS.value,
    }

    raw_items = value if isinstance(value, (list, tuple, set)) else _csv(value)
    out: list[CentralityMethod] = []

    for item in raw_items:
        token = _normalize_token(item)

        if token in valid:
            out.append(CentralityMethod(token))
            continue

        alias = aliases.get(token)

        if alias is not None:
            out.append(CentralityMethod(alias))

    if not out:
        return resolved_default

    seen: dict[str, CentralityMethod] = {}

    for member in out:
        seen.setdefault(member.value, member)

    return tuple(seen.values())


def normalize_graph_status(value: Any, default: GraphStatus = GraphStatus.AVAILABLE) -> GraphStatus:
    """
    Normalize a graph status.
    """
    token = _normalize_token(value)

    for member in GraphStatus:
        if token == member.value:
            return member

    return default


def _unique_preserve_order(items: Sequence[str]) -> tuple[str, ...]:
    """
    Return unique items while preserving first-seen order.
    """
    seen: set[str] = set()
    out: list[str] = []

    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)

    return tuple(out)


# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphPolicy:
    """
    Bounded graph policy.

    Hard caps prevent accidental unbounded graph surfaces.
    """

    enabled: bool = True
    synthetic_required: bool = True
    dataset_mode: str = "synthetic"
    production_like: bool = False
    allow_in_production: bool = False

    salt: str = _DEFAULT_SALT
    namespace: str = _DEFAULT_NAMESPACE
    seed: int = _DEFAULT_SEED

    max_nodes: int = DEFAULT_MAX_NODES
    max_edges: int = DEFAULT_MAX_EDGES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_paths: int = DEFAULT_MAX_PATHS
    max_trails: int = DEFAULT_MAX_TRAILS
    max_shared_groups: int = DEFAULT_MAX_SHARED_GROUPS
    max_accounts_per_entity: int = DEFAULT_MAX_ACCOUNTS_PER_ENTITY
    max_communities: int = DEFAULT_MAX_COMMUNITIES
    max_community_size: int = DEFAULT_MAX_COMMUNITY_SIZE
    max_date_span_days: int = DEFAULT_MAX_DATE_SPAN_DAYS
    max_time_ms: int = DEFAULT_MAX_TIME_MS
    max_issues: int = DEFAULT_MAX_ISSUES
    max_summary_items: int = DEFAULT_MAX_SUMMARY_ITEMS
    max_runs: int = DEFAULT_MAX_RUNS
    max_features_per_node: int = DEFAULT_MAX_FEATURES_PER_NODE

    default_direction: TraversalDirection | str = TraversalDirection.BOTH
    default_path_kind: PathKind | str = PathKind.DIRECTED
    community_method: CommunityMethod | str = CommunityMethod.SHARED_ENTITY_CLUSTER
    centrality_methods: tuple[CentralityMethod, ...] = (
        CentralityMethod.DEGREE,
        CentralityMethod.PAGE_RANK,
    )

    include_transactions: bool = True
    include_entities: bool = True
    include_complaints: bool = True
    include_alerts: bool = True
    include_assessments: bool = True
    include_cases: bool = True
    include_inactive: bool = False

    register_runs: bool = True
    audit_material_runs: bool = True
    expose_node_attributes: bool = False
    allow_mixed_currency_aggregation: bool = False
    allow_cross_currency_conversion: bool = False

    def __post_init__(self) -> None:
        """
        Normalize and clamp policy values.
        """
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(
            self,
            "dataset_mode",
            _normalize_token(self.dataset_mode) or "synthetic",
        )
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))

        object.__setattr__(self, "salt", _ensure_salt(self.salt))
        object.__setattr__(
            self,
            "namespace",
            _normalize_token(self.namespace) or _DEFAULT_NAMESPACE,
        )
        object.__setattr__(self, "seed", int(self.seed))

        object.__setattr__(
            self,
            "max_nodes",
            _clamp_int(self.max_nodes, 1, HARD_MAX_NODES, DEFAULT_MAX_NODES),
        )
        object.__setattr__(
            self,
            "max_edges",
            _clamp_int(self.max_edges, 1, HARD_MAX_EDGES, DEFAULT_MAX_EDGES),
        )
        object.__setattr__(
            self,
            "max_depth",
            _clamp_int(self.max_depth, 1, HARD_MAX_DEPTH, DEFAULT_MAX_DEPTH),
        )
        object.__setattr__(
            self,
            "max_paths",
            _clamp_int(self.max_paths, 1, HARD_MAX_PATHS, DEFAULT_MAX_PATHS),
        )
        object.__setattr__(
            self,
            "max_trails",
            _clamp_int(self.max_trails, 1, HARD_MAX_TRAILS, DEFAULT_MAX_TRAILS),
        )
        object.__setattr__(
            self,
            "max_shared_groups",
            _clamp_int(
                self.max_shared_groups,
                1,
                HARD_MAX_SHARED_GROUPS,
                DEFAULT_MAX_SHARED_GROUPS,
            ),
        )
        object.__setattr__(
            self,
            "max_accounts_per_entity",
            _clamp_int(
                self.max_accounts_per_entity,
                1,
                HARD_MAX_ACCOUNTS_PER_ENTITY,
                DEFAULT_MAX_ACCOUNTS_PER_ENTITY,
            ),
        )
        object.__setattr__(
            self,
            "max_communities",
            _clamp_int(
                self.max_communities,
                1,
                HARD_MAX_COMMUNITIES,
                DEFAULT_MAX_COMMUNITIES,
            ),
        )
        object.__setattr__(
            self,
            "max_community_size",
            _clamp_int(
                self.max_community_size,
                2,
                HARD_MAX_COMMUNITY_SIZE,
                DEFAULT_MAX_COMMUNITY_SIZE,
            ),
        )
        object.__setattr__(
            self,
            "max_date_span_days",
            _clamp_int(
                self.max_date_span_days,
                1,
                HARD_MAX_DATE_SPAN_DAYS,
                DEFAULT_MAX_DATE_SPAN_DAYS,
            ),
        )
        object.__setattr__(
            self,
            "max_time_ms",
            _clamp_int(self.max_time_ms, 100, HARD_MAX_TIME_MS, DEFAULT_MAX_TIME_MS),
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
            "max_runs",
            _clamp_int(self.max_runs, 1, HARD_MAX_RUNS, DEFAULT_MAX_RUNS),
        )
        object.__setattr__(
            self,
            "max_features_per_node",
            _clamp_int(
                self.max_features_per_node,
                1,
                HARD_MAX_FEATURES_PER_NODE,
                DEFAULT_MAX_FEATURES_PER_NODE,
            ),
        )

        object.__setattr__(
            self,
            "default_direction",
            _normalize_enum_option(TraversalDirection, self.default_direction, TraversalDirection.BOTH),
        )
        object.__setattr__(
            self,
            "default_path_kind",
            _normalize_enum_option(PathKind, self.default_path_kind, PathKind.DIRECTED),
        )
        object.__setattr__(
            self,
            "community_method",
            _normalize_enum_option(
                CommunityMethod,
                self.community_method,
                CommunityMethod.SHARED_ENTITY_CLUSTER,
            ),
        )
        object.__setattr__(
            self,
            "centrality_methods",
            normalize_centrality_methods(self.centrality_methods),
        )

        object.__setattr__(self, "include_transactions", _as_bool(self.include_transactions, True))
        object.__setattr__(self, "include_entities", _as_bool(self.include_entities, True))
        object.__setattr__(self, "include_complaints", _as_bool(self.include_complaints, True))
        object.__setattr__(self, "include_alerts", _as_bool(self.include_alerts, True))
        object.__setattr__(self, "include_assessments", _as_bool(self.include_assessments, True))
        object.__setattr__(self, "include_cases", _as_bool(self.include_cases, True))
        object.__setattr__(self, "include_inactive", _as_bool(self.include_inactive, False))

        object.__setattr__(self, "register_runs", _as_bool(self.register_runs, True))
        object.__setattr__(self, "audit_material_runs", _as_bool(self.audit_material_runs, True))
        object.__setattr__(self, "expose_node_attributes", _as_bool(self.expose_node_attributes, False))
        object.__setattr__(
            self,
            "allow_mixed_currency_aggregation",
            _as_bool(self.allow_mixed_currency_aggregation, False),
        )
        object.__setattr__(
            self,
            "allow_cross_currency_conversion",
            _as_bool(self.allow_cross_currency_conversion, False),
        )

        # Node attributes are never exposed by default. Raw and sensitive
        # attributes must never be surfaced through graph summaries.
        if self.expose_node_attributes:
            object.__setattr__(self, "expose_node_attributes", False)

        # Mixed-currency aggregation and cross-currency conversion are always
        # disabled. Amounts are reported per currency only.
        object.__setattr__(self, "allow_mixed_currency_aggregation", False)
        object.__setattr__(self, "allow_cross_currency_conversion", False)

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "GraphPolicy":
        """
        Build a graph policy from runtime settings with safe defaults.
        """
        if settings is None:
            settings = _get_settings()

        salt = str(
            _setting(settings, "GRAPH_SALT", None)
            or _setting(settings, "RULES_EVIDENCE_SALT", None)
            or _setting(settings, "RULES_THRESHOLD_SALT", None)
            or _setting(settings, "RULES_ENGINE_SALT", None)
            or _setting(settings, "RULES_SALT", None)
            or _setting(settings, "ML_VALIDATION_SALT", None)
            or _setting(settings, "ML_EXPLAIN_SALT", None)
            or _setting(settings, "ML_EVALUATE_SALT", None)
            or _setting(settings, "ML_TRAIN_MODEL_SALT", None)
            or _setting(settings, "ML_MODEL_SERVICE_SALT", None)
            or _setting(settings, "ML_ANOMALY_SALT", None)
            or _setting(settings, "ML_SUPERVISED_SALT", None)
            or _setting(settings, "ML_FALLBACK_SALT", None)
            or _setting(settings, "ML_PREPROCESS_SALT", None)
            or _setting(settings, "ML_SPLIT_SALT", None)
            or _setting(settings, "ML_LABEL_SALT", None)
            or _setting(settings, "ML_FEATURE_SALT", None)
            or _setting(settings, "PROVENANCE_SALT", None)
            or _setting(settings, "DEDUPE_SALT", None)
            or _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
            or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
            or _setting(settings, "BACKEND_SECRET_KEY", None)
            or _DEFAULT_SALT
        )

        enabled = _as_bool(_setting(settings, "GRAPH_ENABLED", True), True) and _as_bool(
            _setting(settings, "GRAPH_API_ENABLED", True),
            True,
        )

        production_like = _is_production_like(settings)

        allow_in_production = _as_bool(
            _setting(settings, "GRAPH_ALLOW_IN_PRODUCTION", False),
            False,
        )

        centrality_raw = _setting(settings, "GRAPH_CENTRALITY_METHODS", None)
        centrality_methods = normalize_centrality_methods(
            centrality_raw
            if centrality_raw is not None
            else [CentralityMethod.DEGREE.value, CentralityMethod.PAGE_RANK.value]
        )

        return cls(
            enabled=enabled,
            synthetic_required=_as_bool(_setting(settings, "GRAPH_REQUIRE_SYNTHETIC", True), True),
            dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower(),
            production_like=production_like,
            allow_in_production=allow_in_production,
            salt=salt,
            namespace=str(_setting(settings, "GRAPH_NAMESPACE", _DEFAULT_NAMESPACE)),
            seed=_as_int(_setting(settings, "GRAPH_SEED", _DEFAULT_SEED), _DEFAULT_SEED),
            max_nodes=_as_int(_setting(settings, "GRAPH_MAX_NODES", DEFAULT_MAX_NODES), DEFAULT_MAX_NODES),
            max_edges=_as_int(_setting(settings, "GRAPH_MAX_EDGES", DEFAULT_MAX_EDGES), DEFAULT_MAX_EDGES),
            max_depth=_as_int(_setting(settings, "GRAPH_MAX_DEPTH", DEFAULT_MAX_DEPTH), DEFAULT_MAX_DEPTH),
            max_paths=_as_int(_setting(settings, "GRAPH_MAX_PATHS", DEFAULT_MAX_PATHS), DEFAULT_MAX_PATHS),
            max_trails=_as_int(_setting(settings, "GRAPH_MAX_TRAILS", DEFAULT_MAX_TRAILS), DEFAULT_MAX_TRAILS),
            max_shared_groups=_as_int(
                _setting(settings, "GRAPH_MAX_SHARED_GROUPS", DEFAULT_MAX_SHARED_GROUPS),
                DEFAULT_MAX_SHARED_GROUPS,
            ),
            max_accounts_per_entity=_as_int(
                _setting(settings, "GRAPH_MAX_ACCOUNTS_PER_ENTITY", DEFAULT_MAX_ACCOUNTS_PER_ENTITY),
                DEFAULT_MAX_ACCOUNTS_PER_ENTITY,
            ),
            max_communities=_as_int(
                _setting(settings, "GRAPH_MAX_COMMUNITIES", DEFAULT_MAX_COMMUNITIES),
                DEFAULT_MAX_COMMUNITIES,
            ),
            max_community_size=_as_int(
                _setting(settings, "GRAPH_MAX_COMMUNITY_SIZE", DEFAULT_MAX_COMMUNITY_SIZE),
                DEFAULT_MAX_COMMUNITY_SIZE,
            ),
            max_date_span_days=_as_int(
                _setting(settings, "GRAPH_MAX_DATE_SPAN_DAYS", DEFAULT_MAX_DATE_SPAN_DAYS),
                DEFAULT_MAX_DATE_SPAN_DAYS,
            ),
            max_time_ms=_as_int(_setting(settings, "GRAPH_MAX_TIME_MS", DEFAULT_MAX_TIME_MS), DEFAULT_MAX_TIME_MS),
            max_issues=_as_int(_setting(settings, "GRAPH_MAX_ISSUES", DEFAULT_MAX_ISSUES), DEFAULT_MAX_ISSUES),
            max_summary_items=_as_int(
                _setting(settings, "GRAPH_MAX_SUMMARY_ITEMS", DEFAULT_MAX_SUMMARY_ITEMS),
                DEFAULT_MAX_SUMMARY_ITEMS,
            ),
            max_runs=_as_int(_setting(settings, "GRAPH_MAX_RUNS", DEFAULT_MAX_RUNS), DEFAULT_MAX_RUNS),
            max_features_per_node=_as_int(
                _setting(settings, "GRAPH_MAX_FEATURES_PER_NODE", DEFAULT_MAX_FEATURES_PER_NODE),
                DEFAULT_MAX_FEATURES_PER_NODE,
            ),
            default_direction=str(
                _setting(settings, "GRAPH_DEFAULT_DIRECTION", TraversalDirection.BOTH.value)
            ),
            default_path_kind=str(_setting(settings, "GRAPH_DEFAULT_PATH_KIND", PathKind.DIRECTED.value)),
            community_method=str(
                _setting(
                    settings,
                    "GRAPH_COMMUNITY_METHOD",
                    CommunityMethod.SHARED_ENTITY_CLUSTER.value,
                )
            ),
            centrality_methods=centrality_methods,
            include_transactions=_as_bool(_setting(settings, "GRAPH_INCLUDE_TRANSACTIONS", True), True),
            include_entities=_as_bool(_setting(settings, "GRAPH_INCLUDE_ENTITIES", True), True),
            include_complaints=_as_bool(_setting(settings, "GRAPH_INCLUDE_COMPLAINTS", True), True),
            include_alerts=_as_bool(_setting(settings, "GRAPH_INCLUDE_ALERTS", True), True),
            include_assessments=_as_bool(_setting(settings, "GRAPH_INCLUDE_ASSESSMENTS", True), True),
            include_cases=_as_bool(_setting(settings, "GRAPH_INCLUDE_CASES", True), True),
            include_inactive=_as_bool(_setting(settings, "GRAPH_INCLUDE_INACTIVE", False), False),
            register_runs=_as_bool(_setting(settings, "GRAPH_REGISTER_RUNS", True), True),
            audit_material_runs=_as_bool(_setting(settings, "GRAPH_AUDIT_MATERIAL_RUNS", True), True),
            expose_node_attributes=False,
            allow_mixed_currency_aggregation=False,
            allow_cross_currency_conversion=False,
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable policy summary.

        The salt is never included.
        """
        return {
            "enabled": self.enabled,
            "synthetic_required": self.synthetic_required,
            "dataset_mode": self.dataset_mode,
            "synthetic_dataset_mode": _is_synthetic_dataset_mode(self.dataset_mode),
            "production_like": self.production_like,
            "allow_in_production": self.allow_in_production,
            "namespace": self.namespace,
            "seed": self.seed,
            "salt_configured": bool(self.salt and self.salt != _DEFAULT_SALT),
            "node_types": list(GRAPH_NODE_TYPES),
            "edge_types": list(GRAPH_EDGE_TYPES),
            "directions": list(TRAVERSAL_DIRECTIONS),
            "path_kinds": [member.value for member in PathKind],
            "community_methods": [member.value for member in CommunityMethod],
            "centrality_methods": [member.value for member in self.centrality_methods],
            "default_direction": (
                self.default_direction.value
                if isinstance(self.default_direction, TraversalDirection)
                else str(self.default_direction)
            ),
            "default_path_kind": (
                self.default_path_kind.value
                if isinstance(self.default_path_kind, PathKind)
                else str(self.default_path_kind)
            ),
            "community_method": (
                self.community_method.value
                if isinstance(self.community_method, CommunityMethod)
                else str(self.community_method)
            ),
            "limits": {
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
                "max_depth": self.max_depth,
                "max_paths": self.max_paths,
                "max_trails": self.max_trails,
                "max_shared_groups": self.max_shared_groups,
                "max_accounts_per_entity": self.max_accounts_per_entity,
                "max_communities": self.max_communities,
                "max_community_size": self.max_community_size,
                "max_date_span_days": self.max_date_span_days,
                "max_time_ms": self.max_time_ms,
                "max_issues": self.max_issues,
                "max_summary_items": self.max_summary_items,
                "max_runs": self.max_runs,
                "max_features_per_node": self.max_features_per_node,
            },
            "includes": {
                "transactions": self.include_transactions,
                "entities": self.include_entities,
                "complaints": self.include_complaints,
                "alerts": self.include_alerts,
                "assessments": self.include_assessments,
                "cases": self.include_cases,
                "inactive": self.include_inactive,
            },
            "flags": {
                "register_runs": self.register_runs,
                "audit_material_runs": self.audit_material_runs,
                "expose_node_attributes": self.expose_node_attributes,
                "allow_mixed_currency_aggregation": self.allow_mixed_currency_aggregation,
                "allow_cross_currency_conversion": self.allow_cross_currency_conversion,
            },
        }


def _normalize_enum_option(enum_cls: type[Enum], value: Any, default: Any) -> Any:
    """
    Normalize an enum-like option with a safe fallback.
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
# Policy helpers
# -----------------------------------------------------------------------------


def get_graph_policy(settings: Any | None = None) -> GraphPolicy:
    """
    Return a graph policy resolved from settings.

    This helper is intentionally non-raising. Enforcement belongs in graph
    services, API dependencies, builders, traversal, and deployment controls.
    """
    return GraphPolicy.from_settings(settings)


def resolve_graph_policy(settings: Any | None = None) -> dict[str, Any]:
    """
    Return effective graph policy as a safe dictionary.
    """
    return get_graph_policy(settings).safe_summary()


def get_graph_policy_health(settings: Any | None = None) -> dict[str, Any]:
    """
    Return safe policy-only graph health.

    This helper does not import graph submodules and does not execute graph
    algorithms. It reports policy posture only.
    """
    policy = get_graph_policy(settings)
    issues: list[dict[str, Any]] = []

    if not policy.enabled:
        status = "DISABLED"
        issues.append(
            {
                "severity": IssueSeverity.INFO.value,
                "code": "graph_disabled",
                "message": "Graph analytics are disabled by policy.",
            }
        )
    elif policy.synthetic_required and not _is_synthetic_dataset_mode(policy.dataset_mode):
        status = "BLOCKED"
        issues.append(
            {
                "severity": IssueSeverity.ERROR.value,
                "code": "non_synthetic_dataset",
                "message": "Graph analytics require synthetic dataset mode.",
                "details": {"dataset_mode": policy.dataset_mode},
            }
        )
    elif policy.production_like and not policy.allow_in_production:
        status = "BLOCKED"
        issues.append(
            {
                "severity": IssueSeverity.ERROR.value,
                "code": "production_like_blocked",
                "message": "Graph analytics are blocked in production-like environments.",
            }
        )
    else:
        status = "OK"
        if policy.production_like:
            issues.append(
                {
                    "severity": IssueSeverity.WARNING.value,
                    "code": "graph_allowed_in_production",
                    "message": "Graph analytics are explicitly allowed in a production-like environment and require additional governance review.",
                }
            )

    return {
        "status": status,
        "enabled": policy.enabled,
        "policy": policy.safe_summary(),
        "issues": issues,
        "caveats": list(GRAPH_CAVEATS),
        "safety_flags": dict(GRAPH_SAFETY_FLAGS),
    }


# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------

__all__: Final[tuple[str, ...]] = (
    # Metadata
    "GRAPH_PACKAGE_NAME",
    "GRAPH_LAYER",
    "GRAPH_VERSION",
    "GRAPH_API_PREFIX",
    # Node types
    "NODE_ACCOUNT",
    "NODE_TRANSACTION",
    "NODE_ENTITY",
    "NODE_COMPLAINT",
    "NODE_ALERT",
    "NODE_ASSESSMENT",
    "NODE_CASE",
    "GRAPH_NODE_TYPES",
    "GraphNodeType",
    # Edge types
    "EDGE_SENT",
    "EDGE_RECEIVED",
    "EDGE_LINKED_TO",
    "EDGE_RELATED_TO",
    "EDGE_CORRELATED_WITH",
    "EDGE_ALERTED_ON",
    "EDGE_ASSESSED_BY",
    "EDGE_ATTACHED_TO_CASE",
    "GRAPH_EDGE_TYPES",
    "GraphEdgeType",
    # Directions
    "DIRECTION_OUTGOING",
    "DIRECTION_INCOMING",
    "DIRECTION_BOTH",
    "TRAVERSAL_DIRECTIONS",
    "TraversalDirection",
    # Path kinds
    "PathKind",
    "CommunityMethod",
    "CentralityMethod",
    "GraphStatus",
    "IssueSeverity",
    # Limits
    "DEFAULT_MAX_NODES",
    "HARD_MAX_NODES",
    "DEFAULT_MAX_EDGES",
    "HARD_MAX_EDGES",
    "DEFAULT_MAX_DEPTH",
    "HARD_MAX_DEPTH",
    "DEFAULT_MAX_PATHS",
    "HARD_MAX_PATHS",
    "DEFAULT_MAX_TRAILS",
    "HARD_MAX_TRAILS",
    "DEFAULT_MAX_SHARED_GROUPS",
    "HARD_MAX_SHARED_GROUPS",
    "DEFAULT_MAX_ACCOUNTS_PER_ENTITY",
    "HARD_MAX_ACCOUNTS_PER_ENTITY",
    "DEFAULT_MAX_COMMUNITIES",
    "HARD_MAX_COMMUNITIES",
    "DEFAULT_MAX_COMMUNITY_SIZE",
    "HARD_MAX_COMMUNITY_SIZE",
    "DEFAULT_MAX_DATE_SPAN_DAYS",
    "HARD_MAX_DATE_SPAN_DAYS",
    "DEFAULT_MAX_TIME_MS",
    "HARD_MAX_TIME_MS",
    "DEFAULT_MAX_ISSUES",
    "HARD_MAX_ISSUES",
    "DEFAULT_MAX_SUMMARY_ITEMS",
    "HARD_MAX_SUMMARY_ITEMS",
    "DEFAULT_MAX_RUNS",
    "HARD_MAX_RUNS",
    "DEFAULT_MAX_FEATURES_PER_NODE",
    "HARD_MAX_FEATURES_PER_NODE",
    # Safety
    "GRAPH_CAVEATS",
    "GRAPH_SAFETY_FLAGS",
    # Policy
    "GraphPolicy",
    "get_graph_policy",
    "resolve_graph_policy",
    "get_graph_policy_health",
    # Normalizers
    "normalize_centrality_methods",
    "normalize_community_method",
    "normalize_direction",
    "normalize_edge_type",
    "normalize_graph_status",
    "normalize_node_type",
    "normalize_path_kind",
    # Metadata
    "get_graph_metadata",
    # Lazy submodules
    "service",
    "builder",
    "traversal",
    "paths",
    "money_trails",
    "shared_entities",
    "communities",
    "centrality",
    "correlation",
    "lineage",
    "export",
    "policies",
    "repositories",
    "models",
    "errors",
    # Lazy symbols
    "GraphService",
    "get_graph_service",
    "build_graph",
    "traverse_graph",
    "enumerate_paths",
    "detect_money_trails",
    "detect_shared_entity_clusters",
    "detect_communities",
    "compute_centrality",
    "correlate_complaints",
    "build_graph_lineage",
    "export_graph",
    "load_graph_policy",
    "list_graph_runs",
    "get_graph_run",
)


# -----------------------------------------------------------------------------
# Lazy module and symbol access
# -----------------------------------------------------------------------------
# Keeps `import app.graph` cheap and avoids circular-import pressure during
# package initialization.
#
# Supported patterns:
#
#   from app.graph import service
#   from app.graph import builder
#   from app.graph import get_graph_service
#   from app.graph import GraphService
#
# Missing modules or symbols raise normal ImportError/ModuleNotFoundError or
# AttributeError at the point of use rather than failing the entire package
# import.

_LAZY_MODULES: Final[dict[str, str]] = {
    "service": ".service",
    "builder": ".builder",
    "traversal": ".traversal",
    "paths": ".paths",
    "money_trails": ".money_trails",
    "shared_entities": ".shared_entities",
    "communities": ".communities",
    "centrality": ".centrality",
    "correlation": ".correlation",
    "lineage": ".lineage",
    "export": ".export",
    "policies": ".policies",
    "repositories": ".repositories",
    "models": ".models",
    "errors": ".errors",
}

_LAZY_ATTRS: Final[dict[str, tuple[str, str]]] = {
    "GraphService": (".service", "GraphService"),
    "get_graph_service": (".service", "get_graph_service"),
    "build_graph": (".builder", "build_graph"),
    "traverse_graph": (".traversal", "traverse_graph"),
    "enumerate_paths": (".paths", "enumerate_paths"),
    "detect_money_trails": (".money_trails", "detect_money_trails"),
    "detect_shared_entity_clusters": (".shared_entities", "detect_shared_entity_clusters"),
    "detect_communities": (".communities", "detect_communities"),
    "compute_centrality": (".centrality", "compute_centrality"),
    "correlate_complaints": (".correlation", "correlate_complaints"),
    "build_graph_lineage": (".lineage", "build_graph_lineage"),
    "export_graph": (".export", "export_graph"),
    "load_graph_policy": (".policies", "load_graph_policy"),
    "list_graph_runs": (".repositories", "list_graph_runs"),
    "get_graph_run": (".repositories", "get_graph_run"),
}

_MODULE_CACHE: dict[str, Any] = {}
_ATTR_CACHE: dict[str, Any] = {}


def _is_safe_module_name(name: str) -> bool:
    """
    Return True when a name can safely be treated as a relative submodule name.
    """
    return bool(name) and name.isidentifier() and not name.startswith("_")


def __getattr__(name: str) -> Any:
    """
    Lazily import graph submodules or selected public symbols.

    Explicit lazy modules and symbols are tried first. If the requested name is
    a safe identifier and not already defined, this package also attempts a
    relative submodule import. This allows new graph submodules to become
    available without editing this initializer for every addition.
    """
    if name in _MODULE_CACHE:
        return _MODULE_CACHE[name]

    if name in _ATTR_CACHE:
        return _ATTR_CACHE[name]

    module_name = _LAZY_MODULES.get(name)

    if module_name is not None:
        module = importlib.import_module(module_name, __name__)
        _MODULE_CACHE[name] = module
        globals()[name] = module
        return module

    attr_spec = _LAZY_ATTRS.get(name)

    if attr_spec is not None:
        lazy_module_name, attr_name = attr_spec
        module = importlib.import_module(lazy_module_name, __name__)
        value = getattr(module, attr_name)
        _ATTR_CACHE[name] = value
        globals()[name] = value
        return value

    if _is_safe_module_name(name):
        try:
            module = importlib.import_module(f".{name}", __name__)
        except ModuleNotFoundError:
            pass
        else:
            _MODULE_CACHE[name] = module
            globals()[name] = module
            return module

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )


def __dir__() -> list[str]:
    """
    Return a deterministic directory listing including lazily available modules
    and symbols.
    """
    return sorted(
        {
            *globals().keys(),
            *_LAZY_MODULES.keys(),
            *_LAZY_ATTRS.keys(),
        }
    )


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_graph_metadata() -> dict[str, Any]:
    """
    Return safe, serializable graph-layer metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, raw node attributes, raw identifiers,
    or real customer data.
    """
    policy = get_graph_policy()

    return {
        "package": GRAPH_PACKAGE_NAME,
        "layer": GRAPH_LAYER,
        "version": GRAPH_VERSION,
        "api_prefix": GRAPH_API_PREFIX,
        "node_types": list(GRAPH_NODE_TYPES),
        "edge_types": list(GRAPH_EDGE_TYPES),
        "directions": list(TRAVERSAL_DIRECTIONS),
        "path_kinds": [member.value for member in PathKind],
        "community_methods": [member.value for member in CommunityMethod],
        "centrality_methods": [member.value for member in CentralityMethod],
        "statuses": [member.value for member in GraphStatus],
        "issue_severities": [member.value for member in IssueSeverity],
        "default_policy": policy.safe_summary(),
        "hard_limits": {
            "max_nodes": HARD_MAX_NODES,
            "max_edges": HARD_MAX_EDGES,
            "max_depth": HARD_MAX_DEPTH,
            "max_paths": HARD_MAX_PATHS,
            "max_trails": HARD_MAX_TRAILS,
            "max_shared_groups": HARD_MAX_SHARED_GROUPS,
            "max_accounts_per_entity": HARD_MAX_ACCOUNTS_PER_ENTITY,
            "max_communities": HARD_MAX_COMMUNITIES,
            "max_community_size": HARD_MAX_COMMUNITY_SIZE,
            "max_date_span_days": HARD_MAX_DATE_SPAN_DAYS,
            "max_time_ms": HARD_MAX_TIME_MS,
            "max_issues": HARD_MAX_ISSUES,
            "max_summary_items": HARD_MAX_SUMMARY_ITEMS,
            "max_runs": HARD_MAX_RUNS,
            "max_features_per_node": HARD_MAX_FEATURES_PER_NODE,
        },
        "safety_flags": dict(GRAPH_SAFETY_FLAGS),
        "caveats": list(GRAPH_CAVEATS),
        "lazy_modules": tuple(sorted(_LAZY_MODULES)),
        "lazy_attributes": tuple(sorted(_LAZY_ATTRS)),
        "dynamic_submodule_access": True,
        "policy_health": get_graph_policy_health(),
    }