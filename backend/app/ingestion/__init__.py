"""
MULEGUARD backend ingestion package.

This module is the public entry point for the MULEGUARD ingestion subsystem.

Its responsibilities are intentionally narrow:

- expose stable ingestion-layer constants and metadata;
- declare synthetic-first ingestion conventions;
- declare supported ingestion entity types, duplicate strategies, outcomes,
  batch statuses, and bounded policy defaults;
- provide safe helpers for normalization and policy resolution;
- provide lazy access to ingestion submodules and selected public symbols;
- avoid eager imports of FastAPI, SQLAlchemy, Pydantic, ML, graph, reporting,
  audit, filesystem, or network dependencies during package initialization.

This package must not become a place where heavy runtime logic is executed at
import time.

Ingestion submodules:

- service:      high-level ingestion orchestration
- validators:   record and batch validation helpers
- normalizers:  deterministic record normalization helpers
- loaders:      bounded record loading helpers
- pipeline:     end-to-end ingestion pipeline coordination
- policies:     policy resolution and enforcement helpers
- lineage:      safe provenance and lineage helpers
- quarantine:   rejected-record quarantine helpers
- exporters:    bounded ingestion summary exporters
- repositories: persistence-facing ingestion repositories
- models:       ingestion DTOs and internal models
- errors:       ingestion-specific error helpers

Security and product-safety expectations for the ingestion layer:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be ingested.
- Ground-truth labels, injected scenario IDs, and fraud-ring IDs must not be
  accepted, persisted, returned, logged, or exported through this surface.
- Raw complaint narratives may be persisted only where explicitly required by
  the synthetic complaint workflow, but must never be returned in ingestion
  responses or row errors.
- Ingestion responses must not expose secrets, tokens, passwords, database
  URLs, model artifact paths, or raw sensitive identifiers.
- Batch processing must remain bounded by configured batch size, error-reporting
  limits, narrative limits, JSON depth limits, and future-timestamp tolerance.
- Dry-run behaviour must be honest: validation only, no persistence.
- Partial commits must be opt-in and auditable.
- Duplicate handling must be deterministic and explicit.
- Ingestion must never trigger automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, or restricting accounts.
- Ingested records are investigative inputs only. They are not proof of
  wrongdoing.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final, Optional

# -----------------------------------------------------------------------------
# Execution guard
# -----------------------------------------------------------------------------
# This package is intended to be imported as part of the backend application.
# Direct execution is not a supported entrypoint.
if __package__ in {None, ""}:
    raise RuntimeError(
        "Do not execute app/ingestion/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Stable ingestion metadata
# -----------------------------------------------------------------------------

INGESTION_PACKAGE_NAME: Final[str] = "muleguard.backend.ingestion"
INGESTION_LAYER: Final[str] = "ingestion"
INGESTION_VERSION: Final[str] = "v1"

INGESTION_API_PREFIX: Final[str] = "/api/v1/ingestion"


# -----------------------------------------------------------------------------
# Ingestion modes
# -----------------------------------------------------------------------------

INGESTION_MODE_SYNTHETIC_ONLY: Final[str] = "synthetic_only"
INGESTION_MODE_LOCAL_DEMO: Final[str] = "local_demo"
INGESTION_MODE_TEST_FIXTURES: Final[str] = "test_fixtures"

INGESTION_MODES: Final[tuple[str, ...]] = (
    INGESTION_MODE_SYNTHETIC_ONLY,
    INGESTION_MODE_LOCAL_DEMO,
    INGESTION_MODE_TEST_FIXTURES,
)

_MODE_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "synthetic": INGESTION_MODE_SYNTHETIC_ONLY,
        "fake": INGESTION_MODE_SYNTHETIC_ONLY,
        "mock": INGESTION_MODE_SYNTHETIC_ONLY,
        "demo": INGESTION_MODE_LOCAL_DEMO,
        "local": INGESTION_MODE_LOCAL_DEMO,
        "test": INGESTION_MODE_TEST_FIXTURES,
        "fixture": INGESTION_MODE_TEST_FIXTURES,
        "fixtures": INGESTION_MODE_TEST_FIXTURES,
    }
)


# -----------------------------------------------------------------------------
# Supported ingestion entity types
# -----------------------------------------------------------------------------

INGESTION_ENTITY_ACCOUNTS: Final[str] = "accounts"
INGESTION_ENTITY_TRANSACTIONS: Final[str] = "transactions"
INGESTION_ENTITY_COMPLAINTS: Final[str] = "complaints"
INGESTION_ENTITY_ENTITIES: Final[str] = "entities"
INGESTION_ENTITY_ENTITY_LINKS: Final[str] = "entity_links"

SUPPORTED_INGESTION_ENTITY_TYPES: Final[tuple[str, ...]] = (
    INGESTION_ENTITY_ACCOUNTS,
    INGESTION_ENTITY_TRANSACTIONS,
    INGESTION_ENTITY_COMPLAINTS,
    INGESTION_ENTITY_ENTITIES,
    INGESTION_ENTITY_ENTITY_LINKS,
)

# Entity types whose records normally require caller-stable references for
# deterministic duplicate detection and lineage.
REFERENCE_REQUIRED_INGESTION_ENTITY_TYPES: Final[tuple[str, ...]] = (
    INGESTION_ENTITY_TRANSACTIONS,
    INGESTION_ENTITY_COMPLAINTS,
)


# -----------------------------------------------------------------------------
# Duplicate strategies
# -----------------------------------------------------------------------------

DUPLICATE_STRATEGY_REJECT: Final[str] = "reject"
DUPLICATE_STRATEGY_SKIP: Final[str] = "skip"

DUPLICATE_STRATEGIES: Final[tuple[str, ...]] = (
    DUPLICATE_STRATEGY_REJECT,
    DUPLICATE_STRATEGY_SKIP,
)

_STRATEGY_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "fail": DUPLICATE_STRATEGY_REJECT,
        "error": DUPLICATE_STRATEGY_REJECT,
        "deny": DUPLICATE_STRATEGY_REJECT,
        "drop": DUPLICATE_STRATEGY_SKIP,
        "ignore": DUPLICATE_STRATEGY_SKIP,
        "silent": DUPLICATE_STRATEGY_SKIP,
    }
)


# -----------------------------------------------------------------------------
# Ingestion outcomes
# -----------------------------------------------------------------------------

INGESTION_OUTCOME_ACCEPTED: Final[str] = "accepted"
INGESTION_OUTCOME_REJECTED: Final[str] = "rejected"
INGESTION_OUTCOME_DUPLICATED: Final[str] = "duplicated"
INGESTION_OUTCOME_SKIPPED: Final[str] = "skipped"
INGESTION_OUTCOME_TRUNCATED: Final[str] = "truncated"
INGESTION_OUTCOME_DRY_RUN: Final[str] = "dry_run"

INGESTION_OUTCOMES: Final[tuple[str, ...]] = (
    INGESTION_OUTCOME_ACCEPTED,
    INGESTION_OUTCOME_REJECTED,
    INGESTION_OUTCOME_DUPLICATED,
    INGESTION_OUTCOME_SKIPPED,
    INGESTION_OUTCOME_TRUNCATED,
    INGESTION_OUTCOME_DRY_RUN,
)


# -----------------------------------------------------------------------------
# Batch statuses
# -----------------------------------------------------------------------------

INGESTION_STATUS_PENDING: Final[str] = "pending"
INGESTION_STATUS_RUNNING: Final[str] = "running"
INGESTION_STATUS_COMPLETED: Final[str] = "completed"
INGESTION_STATUS_PARTIAL: Final[str] = "partial"
INGESTION_STATUS_FAILED: Final[str] = "failed"
INGESTION_STATUS_CANCELLED: Final[str] = "cancelled"

INGESTION_STATUSES: Final[tuple[str, ...]] = (
    INGESTION_STATUS_PENDING,
    INGESTION_STATUS_RUNNING,
    INGESTION_STATUS_COMPLETED,
    INGESTION_STATUS_PARTIAL,
    INGESTION_STATUS_FAILED,
    INGESTION_STATUS_CANCELLED,
)

TERMINAL_INGESTION_STATUSES: Final[tuple[str, ...]] = (
    INGESTION_STATUS_COMPLETED,
    INGESTION_STATUS_PARTIAL,
    INGESTION_STATUS_FAILED,
    INGESTION_STATUS_CANCELLED,
)


# -----------------------------------------------------------------------------
# Source and provenance defaults
# -----------------------------------------------------------------------------

DEFAULT_SOURCE_SYSTEM: Final[str] = "api"
DEFAULT_SOURCE_BATCH_PREFIX: Final[str] = "batch"
DEFAULT_INGESTION_ACTOR: Final[str] = "system"


# -----------------------------------------------------------------------------
# Bounded policy defaults
# -----------------------------------------------------------------------------

DEFAULT_MAX_BATCH_SIZE: Final[int] = 1_000
HARD_MAX_BATCH_SIZE: Final[int] = 10_000

DEFAULT_MAX_ERRORS_RETURNED: Final[int] = 100
HARD_MAX_ERRORS_RETURNED: Final[int] = 500

DEFAULT_FUTURE_TOLERANCE_MINUTES: Final[int] = 5

DEFAULT_MAX_NARRATIVE_LENGTH: Final[int] = 20_000
HARD_MAX_NARRATIVE_LENGTH: Final[int] = 100_000

DEFAULT_MAX_JSON_DEPTH: Final[int] = 6
HARD_MAX_JSON_DEPTH: Final[int] = 12

DEFAULT_MAX_LIST_LENGTH: Final[int] = 100
HARD_MAX_LIST_LENGTH: Final[int] = 1_000

DEFAULT_MAX_MAPPING_KEYS: Final[int] = 100
HARD_MAX_MAPPING_KEYS: Final[int] = 1_000


# -----------------------------------------------------------------------------
# Boolean parsing literals
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}


# -----------------------------------------------------------------------------
# Ingestion-layer safety flags
# -----------------------------------------------------------------------------
# These are declarative policy markers. Runtime enforcement must still exist in
# ingestion services, API dependencies, validators, persistence layers,
# middleware, tests, and deployment controls.

_INGESTION_SAFETY_FLAGS_RAW: Final[dict[str, bool]] = {
    "synthetic_only_by_default": True,
    "no_real_customer_data_by_default": True,
    "no_ground_truth_labels_accepted": True,
    "no_scenario_ids_exposed": True,
    "no_fraud_ring_ids_exposed": True,
    "no_raw_narrative_in_ingestion_responses": True,
    "no_secrets_in_logs": True,
    "no_tokens_in_logs": True,
    "no_passwords_in_logs": True,
    "no_database_urls_in_logs": True,
    "no_model_artifact_paths_in_logs": True,
    "bounded_batch_size_required": True,
    "bounded_error_reporting_required": True,
    "bounded_narrative_length_required": True,
    "bounded_json_depth_required": True,
    "dry_run_validation_only": True,
    "partial_commit_opt_in": True,
    "deterministic_duplicate_handling": True,
    "provenance_recorded_when_supported": True,
    "audit_material_batches": True,
    "no_automatic_adverse_customer_action": True,
    "no_fake_functionality": True,
    "not_production_ready": True,
}

INGESTION_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    _INGESTION_SAFETY_FLAGS_RAW
)


# -----------------------------------------------------------------------------
# Standard ingestion caveats
# -----------------------------------------------------------------------------

INGESTION_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype ingestion only. Do not send real customer data.",
    "Ingested records are investigative inputs only and are not proof of wrongdoing.",
    "Ingestion responses do not return raw complaint narratives.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs must not be ingested through this API.",
    "Batch processing is bounded by configured batch size and error-reporting limits.",
    "Dry-run mode validates records without persisting them.",
    "Partial commits are opt-in and auditable.",
    "Duplicate handling is deterministic and configurable.",
    "Provenance metadata is recorded only when supported by the persistence model.",
    "This API does not freeze, block, blacklist, close, restrict, or otherwise take adverse action against accounts or customers.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)


# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------

__all__: Final[tuple[str, ...]] = (
    # Metadata
    "INGESTION_PACKAGE_NAME",
    "INGESTION_LAYER",
    "INGESTION_VERSION",
    "INGESTION_API_PREFIX",
    # Modes
    "INGESTION_MODE_SYNTHETIC_ONLY",
    "INGESTION_MODE_LOCAL_DEMO",
    "INGESTION_MODE_TEST_FIXTURES",
    "INGESTION_MODES",
    # Entity types
    "INGESTION_ENTITY_ACCOUNTS",
    "INGESTION_ENTITY_TRANSACTIONS",
    "INGESTION_ENTITY_COMPLAINTS",
    "INGESTION_ENTITY_ENTITIES",
    "INGESTION_ENTITY_ENTITY_LINKS",
    "SUPPORTED_INGESTION_ENTITY_TYPES",
    "REFERENCE_REQUIRED_INGESTION_ENTITY_TYPES",
    # Duplicate strategies
    "DUPLICATE_STRATEGY_REJECT",
    "DUPLICATE_STRATEGY_SKIP",
    "DUPLICATE_STRATEGIES",
    # Outcomes
    "INGESTION_OUTCOME_ACCEPTED",
    "INGESTION_OUTCOME_REJECTED",
    "INGESTION_OUTCOME_DUPLICATED",
    "INGESTION_OUTCOME_SKIPPED",
    "INGESTION_OUTCOME_TRUNCATED",
    "INGESTION_OUTCOME_DRY_RUN",
    "INGESTION_OUTCOMES",
    # Statuses
    "INGESTION_STATUS_PENDING",
    "INGESTION_STATUS_RUNNING",
    "INGESTION_STATUS_COMPLETED",
    "INGESTION_STATUS_PARTIAL",
    "INGESTION_STATUS_FAILED",
    "INGESTION_STATUS_CANCELLED",
    "INGESTION_STATUSES",
    "TERMINAL_INGESTION_STATUSES",
    # Source/provenance defaults
    "DEFAULT_SOURCE_SYSTEM",
    "DEFAULT_SOURCE_BATCH_PREFIX",
    "DEFAULT_INGESTION_ACTOR",
    # Limits
    "DEFAULT_MAX_BATCH_SIZE",
    "HARD_MAX_BATCH_SIZE",
    "DEFAULT_MAX_ERRORS_RETURNED",
    "HARD_MAX_ERRORS_RETURNED",
    "DEFAULT_FUTURE_TOLERANCE_MINUTES",
    "DEFAULT_MAX_NARRATIVE_LENGTH",
    "HARD_MAX_NARRATIVE_LENGTH",
    "DEFAULT_MAX_JSON_DEPTH",
    "HARD_MAX_JSON_DEPTH",
    "DEFAULT_MAX_LIST_LENGTH",
    "HARD_MAX_LIST_LENGTH",
    "DEFAULT_MAX_MAPPING_KEYS",
    "HARD_MAX_MAPPING_KEYS",
    # Safety
    "INGESTION_SAFETY_FLAGS",
    "INGESTION_CAVEATS",
    # Helpers
    "normalize_ingestion_mode",
    "normalize_entity_type",
    "normalize_duplicate_strategy",
    "is_supported_entity_type",
    "is_ingestion_enabled",
    "is_production_like",
    "requires_synthetic_data",
    "resolve_ingestion_limits",
    "get_ingestion_policy",
    "get_ingestion_metadata",
    # Lazy submodules
    "service",
    "validators",
    "normalizers",
    "loaders",
    "pipeline",
    "policies",
    "lineage",
    "quarantine",
    "exporters",
    "repositories",
    "models",
    "errors",
    # Lazy symbols
    "IngestionService",
    "get_ingestion_service",
    "validate_ingestion_batch",
    "normalize_ingestion_record",
    "load_ingestion_records",
    "run_ingestion_pipeline",
    "resolve_ingestion_policy",
    "build_ingestion_lineage",
    "quarantine_ingestion_record",
    "export_ingestion_summary",
)


# -----------------------------------------------------------------------------
# Lazy module and symbol access
# -----------------------------------------------------------------------------
# Keeps `import app.ingestion` cheap and avoids circular-import pressure during
# package initialization.
#
# Supported patterns:
#
#   from app.ingestion import service
#   from app.ingestion import validators
#   from app.ingestion import get_ingestion_service
#   from app.ingestion import IngestionService
#
# Missing modules or symbols raise normal ImportError/ModuleNotFoundError or
# AttributeError at the point of use rather than failing the entire package
# import.

_LAZY_MODULES: Final[dict[str, str]] = {
    "service": ".service",
    "validators": ".validators",
    "normalizers": ".normalizers",
    "loaders": ".loaders",
    "pipeline": ".pipeline",
    "policies": ".policies",
    "lineage": ".lineage",
    "quarantine": ".quarantine",
    "exporters": ".exporters",
    "repositories": ".repositories",
    "models": ".models",
    "errors": ".errors",
}

_LAZY_ATTRS: Final[dict[str, tuple[str, str]]] = {
    "IngestionService": (".service", "IngestionService"),
    "get_ingestion_service": (".service", "get_ingestion_service"),
    "validate_ingestion_batch": (".validators", "validate_ingestion_batch"),
    "normalize_ingestion_record": (".normalizers", "normalize_ingestion_record"),
    "load_ingestion_records": (".loaders", "load_ingestion_records"),
    "run_ingestion_pipeline": (".pipeline", "run_ingestion_pipeline"),
    "resolve_ingestion_policy": (".policies", "resolve_ingestion_policy"),
    "build_ingestion_lineage": (".lineage", "build_ingestion_lineage"),
    "quarantine_ingestion_record": (".quarantine", "quarantine_ingestion_record"),
    "export_ingestion_summary": (".exporters", "export_ingestion_summary"),
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
    Lazily import ingestion submodules or selected public symbols.

    Explicit lazy modules and symbols are tried first. If the requested name is
    a safe identifier and not already defined, this package also attempts a
    relative submodule import. This allows new ingestion submodules to become
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


# -----------------------------------------------------------------------------
# Normalization helpers
# -----------------------------------------------------------------------------


def normalize_ingestion_mode(
    value: Any,
    *,
    default: str = INGESTION_MODE_SYNTHETIC_ONLY,
) -> str:
    """
    Normalize an ingestion mode-like value.

    Unknown values fall back to the supplied default. Alias handling is
    intentionally conservative and never accepts real-data modes implicitly.
    """
    text = str(value if value is not None else "").strip().lower()
    text = text.replace(" ", "_").replace("-", "_")

    if text in INGESTION_MODES:
        return text

    alias = _MODE_ALIASES.get(text)

    if alias is not None:
        return alias

    return default


def normalize_entity_type(value: Any) -> str:
    """
    Normalize an ingestion entity-type value.

    Returns an empty string for missing values.
    """
    return str(value if value is not None else "").strip().lower().replace(" ", "_").replace("-", "_")


def is_supported_entity_type(value: Any) -> bool:
    """
    Return True when a value maps to a supported ingestion entity type.
    """
    return normalize_entity_type(value) in SUPPORTED_INGESTION_ENTITY_TYPES


def normalize_duplicate_strategy(
    value: Any,
    *,
    default: str = DUPLICATE_STRATEGY_REJECT,
) -> str:
    """
    Normalize a duplicate-handling strategy.

    Unknown values fall back to the supplied default.
    """
    text = str(value if value is not None else "").strip().lower()

    if text in DUPLICATE_STRATEGIES:
        return text

    alias = _STRATEGY_ALIASES.get(text)

    if alias is not None:
        return alias

    return default


# -----------------------------------------------------------------------------
# Policy helpers
# -----------------------------------------------------------------------------


def is_ingestion_enabled(settings: Any) -> bool:
    """
    Return True when ingestion is enabled.

    Both the API surface flag and subsystem flag must be enabled.
    """
    api_enabled = _as_bool(_setting(settings, "INGESTION_API_ENABLED", True), True)
    subsystem_enabled = _as_bool(_setting(settings, "INGESTION_ENABLED", True), True)
    return api_enabled and subsystem_enabled


def is_production_like(settings: Any) -> bool:
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


def requires_synthetic_data(settings: Any) -> bool:
    """
    Return True when ingestion must require synthetic dataset mode.
    """
    return _as_bool(_setting(settings, "INGESTION_REQUIRE_SYNTHETIC", True), True)


def dataset_mode(settings: Any) -> str:
    """
    Return normalized dataset mode.
    """
    return str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower()


def resolve_ingestion_limits(settings: Any) -> dict[str, int]:
    """
    Resolve bounded ingestion limits from settings with safe defaults.

    Returned values are always within hard caps. Configuration cannot create an
    unbounded ingestion surface.
    """
    hard_max_batch_size = max(
        1,
        _as_int(
            _setting(settings, "INGESTION_HARD_MAX_BATCH_SIZE", HARD_MAX_BATCH_SIZE),
            HARD_MAX_BATCH_SIZE,
        ),
    )

    max_batch_size = min(
        hard_max_batch_size,
        max(
            1,
            _as_int(
                _setting(settings, "INGESTION_MAX_BATCH_SIZE", DEFAULT_MAX_BATCH_SIZE),
                DEFAULT_MAX_BATCH_SIZE,
            ),
        ),
    )

    hard_max_errors_returned = max(
        1,
        _as_int(
            _setting(
                settings,
                "INGESTION_HARD_MAX_ERRORS_RETURNED",
                HARD_MAX_ERRORS_RETURNED,
            ),
            HARD_MAX_ERRORS_RETURNED,
        ),
    )

    max_errors_returned = min(
        hard_max_errors_returned,
        max(
            1,
            _as_int(
                _setting(
                    settings,
                    "INGESTION_MAX_ERRORS_RETURNED",
                    DEFAULT_MAX_ERRORS_RETURNED,
                ),
                DEFAULT_MAX_ERRORS_RETURNED,
            ),
        ),
    )

    hard_max_narrative_length = max(
        1,
        _as_int(
            _setting(
                settings,
                "INGESTION_HARD_MAX_NARRATIVE_LENGTH",
                HARD_MAX_NARRATIVE_LENGTH,
            ),
            HARD_MAX_NARRATIVE_LENGTH,
        ),
    )

    max_narrative_length = min(
        hard_max_narrative_length,
        max(
            1,
            _as_int(
                _setting(
                    settings,
                    "INGESTION_MAX_NARRATIVE_LENGTH",
                    DEFAULT_MAX_NARRATIVE_LENGTH,
                ),
                DEFAULT_MAX_NARRATIVE_LENGTH,
            ),
        ),
    )

    hard_max_json_depth = max(
        1,
        _as_int(
            _setting(settings, "INGESTION_HARD_MAX_JSON_DEPTH", HARD_MAX_JSON_DEPTH),
            HARD_MAX_JSON_DEPTH,
        ),
    )

    max_json_depth = min(
        hard_max_json_depth,
        max(
            1,
            _as_int(
                _setting(settings, "INGESTION_MAX_JSON_DEPTH", DEFAULT_MAX_JSON_DEPTH),
                DEFAULT_MAX_JSON_DEPTH,
            ),
        ),
    )

    hard_max_list_length = max(
        1,
        _as_int(
            _setting(settings, "INGESTION_HARD_MAX_LIST_LENGTH", HARD_MAX_LIST_LENGTH),
            HARD_MAX_LIST_LENGTH,
        ),
    )

    max_list_length = min(
        hard_max_list_length,
        max(
            1,
            _as_int(
                _setting(settings, "INGESTION_MAX_LIST_LENGTH", DEFAULT_MAX_LIST_LENGTH),
                DEFAULT_MAX_LIST_LENGTH,
            ),
        ),
    )

    hard_max_mapping_keys = max(
        1,
        _as_int(
            _setting(
                settings,
                "INGESTION_HARD_MAX_MAPPING_KEYS",
                HARD_MAX_MAPPING_KEYS,
            ),
            HARD_MAX_MAPPING_KEYS,
        ),
    )

    max_mapping_keys = min(
        hard_max_mapping_keys,
        max(
            1,
            _as_int(
                _setting(
                    settings,
                    "INGESTION_MAX_MAPPING_KEYS",
                    DEFAULT_MAX_MAPPING_KEYS,
                ),
                DEFAULT_MAX_MAPPING_KEYS,
            ),
        ),
    )

    future_tolerance_minutes = max(
        0,
        _as_int(
            _setting(
                settings,
                "INGESTION_FUTURE_TOLERANCE_MINUTES",
                DEFAULT_FUTURE_TOLERANCE_MINUTES,
            ),
            DEFAULT_FUTURE_TOLERANCE_MINUTES,
        ),
    )

    return {
        "max_batch_size": max_batch_size,
        "hard_max_batch_size": hard_max_batch_size,
        "max_errors_returned": max_errors_returned,
        "hard_max_errors_returned": hard_max_errors_returned,
        "max_narrative_length": max_narrative_length,
        "hard_max_narrative_length": hard_max_narrative_length,
        "max_json_depth": max_json_depth,
        "hard_max_json_depth": hard_max_json_depth,
        "max_list_length": max_list_length,
        "hard_max_list_length": hard_max_list_length,
        "max_mapping_keys": max_mapping_keys,
        "hard_max_mapping_keys": hard_max_mapping_keys,
        "future_tolerance_minutes": future_tolerance_minutes,
    }


def get_ingestion_policy(settings: Any) -> dict[str, Any]:
    """
    Return effective ingestion policy from settings.

    This helper is intentionally non-raising. Enforcement belongs in services,
    API dependencies, and validators.
    """
    limits = resolve_ingestion_limits(settings)

    mode = normalize_ingestion_mode(
        _setting(settings, "INGESTION_MODE", INGESTION_MODE_SYNTHETIC_ONLY),
        default=INGESTION_MODE_SYNTHETIC_ONLY,
    )

    duplicate_strategy = normalize_duplicate_strategy(
        _setting(settings, "INGESTION_DUPLICATE_STRATEGY", DUPLICATE_STRATEGY_REJECT),
        default=DUPLICATE_STRATEGY_REJECT,
    )

    return {
        "enabled": is_ingestion_enabled(settings),
        "production_like": is_production_like(settings),
        "mode": mode,
        "dataset_mode": dataset_mode(settings),
        "synthetic_required": requires_synthetic_data(settings),
        "allow_in_production": _as_bool(
            _setting(settings, "INGESTION_ALLOW_IN_PRODUCTION", False),
            False,
        ),
        "allow_partial": _as_bool(
            _setting(settings, "INGESTION_ALLOW_PARTIAL_BATCH", False),
            False,
        ),
        "transactional_batch": _as_bool(
            _setting(settings, "INGESTION_TRANSACTIONAL_BATCH", True),
            True,
        ),
        "duplicate_strategy": duplicate_strategy,
        "default_source_system": str(
            _setting(settings, "INGESTION_DEFAULT_SOURCE_SYSTEM", DEFAULT_SOURCE_SYSTEM)
            or DEFAULT_SOURCE_SYSTEM
        ).strip(),
        **limits,
    }


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_ingestion_metadata() -> dict[str, Any]:
    """
    Return safe, serializable ingestion-layer metadata.

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
    return {
        "package": INGESTION_PACKAGE_NAME,
        "layer": INGESTION_LAYER,
        "version": INGESTION_VERSION,
        "api_prefix": INGESTION_API_PREFIX,
        "modes": list(INGESTION_MODES),
        "supported_entity_types": list(SUPPORTED_INGESTION_ENTITY_TYPES),
        "reference_required_entity_types": list(
            REFERENCE_REQUIRED_INGESTION_ENTITY_TYPES
        ),
        "duplicate_strategies": list(DUPLICATE_STRATEGIES),
        "outcomes": list(INGESTION_OUTCOMES),
        "statuses": list(INGESTION_STATUSES),
        "terminal_statuses": list(TERMINAL_INGESTION_STATUSES),
        "default_source_system": DEFAULT_SOURCE_SYSTEM,
        "default_source_batch_prefix": DEFAULT_SOURCE_BATCH_PREFIX,
        "default_ingestion_actor": DEFAULT_INGESTION_ACTOR,
        "default_limits": resolve_ingestion_limits(None),
        "safety_flags": dict(INGESTION_SAFETY_FLAGS),
        "caveats": list(INGESTION_CAVEATS),
        "lazy_modules": tuple(sorted(_LAZY_MODULES)),
        "lazy_attributes": tuple(sorted(_LAZY_ATTRS)),
        "dynamic_submodule_access": True,
    }