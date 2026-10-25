"""
MULEGUARD backend ML package.

This module is the public entry point for the MULEGUARD machine-learning
subsystem.

Its responsibilities are intentionally narrow:

- expose stable ML-layer constants and metadata;
- declare synthetic-first ML conventions;
- declare supported ML modes, feature windows, scoring modes, model statuses,
  risk bands, metric identifiers, forbidden feature fields, and bounded policy
  defaults;
- provide safe helpers for normalization, policy resolution, risk-band
  assignment, and metadata inspection;
- provide lazy access to ML submodules and selected public symbols;
- avoid eager imports of FastAPI, SQLAlchemy, Pydantic, ingestion, graph,
  reporting, audit, filesystem, network, or training-runtime dependencies during
  package initialization.

This package must not become a place where heavy runtime logic is executed at
import time.

ML submodules:

- service:         high-level ML orchestration
- features:        bounded synthetic feature construction
- scoring:         risk/priority scoring helpers
- training:        synthetic training orchestration helpers
- evaluation:      synthetic evaluation and metric helpers
- calibration:     optional calibration helpers
- explainability:  bounded explanation/factor attribution helpers
- monitoring:      model health, drift, and operational monitoring helpers
- policies:        ML policy resolution helpers
- artifacts:       safe model artifact metadata helpers
- repositories:    persistence-facing ML repositories
- models:          ML DTOs and internal models
- errors:          ML-specific error helpers

Security and product-safety expectations for the ML layer:

- MULEGUARD is synthetic-first by default.
- Real customer data must not be used for training, evaluation, scoring, or
  explanation in this prototype.
- Ground-truth labels, injected scenario IDs, and fraud-ring IDs must not be
  exposed as features, outputs, metrics, explanations, logs, or artifacts.
- Raw complaint narratives must not be exposed as features, outputs, metrics,
  explanations, logs, or artifacts.
- Model artifact file paths and raw binary artifacts must not be exposed.
- Secrets, tokens, passwords, database URLs, filesystem paths, and real customer
  identifiers must never be logged or returned.
- Risk scores are investigative prioritization scores only. They are not
  probabilities of guilt.
- Heuristic fallback scores are not calibrated model probabilities.
- Undefined metrics must be reported honestly as unavailable, not invented.
- ML outputs are investigative leads only.
- ML outputs must never trigger automatic adverse customer action such as
  freezing, blocking, blacklisting, closing, restricting, or otherwise harming
  accounts or customers.
- Model training, promotion, retirement, upload, replacement, or execution must
  not be implied by this package initializer. Those capabilities must be
  explicitly implemented, authorized, audited, and bounded elsewhere.
"""

from __future__ import annotations

import importlib
import math
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Optional


# -----------------------------------------------------------------------------
# Execution guard
# -----------------------------------------------------------------------------
# This package is intended to be imported as part of the backend application.
# Direct execution is not a supported entrypoint.
if __package__ in {None, ""}:
    raise RuntimeError(
        "Do not execute app/ml/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Stable ML metadata
# -----------------------------------------------------------------------------

ML_PACKAGE_NAME: Final[str] = "muleguard.backend.ml"
ML_LAYER: Final[str] = "ml"
ML_VERSION: Final[str] = "v1"

ML_API_PREFIX: Final[str] = "/api/v1/ml"


# -----------------------------------------------------------------------------
# ML modes
# -----------------------------------------------------------------------------

ML_MODE_SYNTHETIC_ONLY: Final[str] = "synthetic_only"
ML_MODE_LOCAL_DEMO: Final[str] = "local_demo"
ML_MODE_TEST_FIXTURES: Final[str] = "test_fixtures"
ML_MODE_OFFLINE_EVALUATION: Final[str] = "offline_evaluation"

ML_MODES: Final[tuple[str, ...]] = (
    ML_MODE_SYNTHETIC_ONLY,
    ML_MODE_LOCAL_DEMO,
    ML_MODE_TEST_FIXTURES,
    ML_MODE_OFFLINE_EVALUATION,
)

_MODE_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "synthetic": ML_MODE_SYNTHETIC_ONLY,
        "fake": ML_MODE_SYNTHETIC_ONLY,
        "mock": ML_MODE_SYNTHETIC_ONLY,
        "demo": ML_MODE_LOCAL_DEMO,
        "local": ML_MODE_LOCAL_DEMO,
        "test": ML_MODE_TEST_FIXTURES,
        "fixture": ML_MODE_TEST_FIXTURES,
        "fixtures": ML_MODE_TEST_FIXTURES,
        "offline": ML_MODE_OFFLINE_EVALUATION,
        "eval": ML_MODE_OFFLINE_EVALUATION,
        "evaluation": ML_MODE_OFFLINE_EVALUATION,
    }
)


# -----------------------------------------------------------------------------
# Feature windows
# -----------------------------------------------------------------------------

FEATURE_WINDOW_1H: Final[str] = "1h"
FEATURE_WINDOW_24H: Final[str] = "24h"
FEATURE_WINDOW_7D: Final[str] = "7d"
FEATURE_WINDOW_30D: Final[str] = "30d"
FEATURE_WINDOW_90D: Final[str] = "90d"
FEATURE_WINDOW_365D: Final[str] = "365d"

FEATURE_WINDOWS: Final[tuple[str, ...]] = (
    FEATURE_WINDOW_1H,
    FEATURE_WINDOW_24H,
    FEATURE_WINDOW_7D,
    FEATURE_WINDOW_30D,
    FEATURE_WINDOW_90D,
    FEATURE_WINDOW_365D,
)

_WINDOW_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "hour": FEATURE_WINDOW_1H,
        "1_hour": FEATURE_WINDOW_1H,
        "one_hour": FEATURE_WINDOW_1H,
        "day": FEATURE_WINDOW_24H,
        "24_hour": FEATURE_WINDOW_24H,
        "one_day": FEATURE_WINDOW_24H,
        "week": FEATURE_WINDOW_7D,
        "7_day": FEATURE_WINDOW_7D,
        "seven_day": FEATURE_WINDOW_7D,
        "month": FEATURE_WINDOW_30D,
        "30_day": FEATURE_WINDOW_30D,
        "thirty_day": FEATURE_WINDOW_30D,
        "quarter": FEATURE_WINDOW_90D,
        "90_day": FEATURE_WINDOW_90D,
        "ninety_day": FEATURE_WINDOW_90D,
        "year": FEATURE_WINDOW_365D,
        "365_day": FEATURE_WINDOW_365D,
        "one_year": FEATURE_WINDOW_365D,
    }
)


# -----------------------------------------------------------------------------
# Scoring modes
# -----------------------------------------------------------------------------

SCORING_MODE_TRAINED_MODEL: Final[str] = "TRAINED_MODEL"
SCORING_MODE_HEURISTIC_FALLBACK: Final[str] = "HEURISTIC_FALLBACK"
SCORING_MODE_RULES_ONLY: Final[str] = "RULES_ONLY"
SCORING_MODE_HYBRID: Final[str] = "HYBRID"
SCORING_MODE_DISABLED: Final[str] = "DISABLED"
SCORING_MODE_UNKNOWN: Final[str] = "UNKNOWN"

SCORING_MODES: Final[tuple[str, ...]] = (
    SCORING_MODE_TRAINED_MODEL,
    SCORING_MODE_HEURISTIC_FALLBACK,
    SCORING_MODE_RULES_ONLY,
    SCORING_MODE_HYBRID,
    SCORING_MODE_DISABLED,
    SCORING_MODE_UNKNOWN,
)

_SCORING_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "trained": SCORING_MODE_TRAINED_MODEL,
        "model": SCORING_MODE_TRAINED_MODEL,
        "ml": SCORING_MODE_TRAINED_MODEL,
        "heuristic": SCORING_MODE_HEURISTIC_FALLBACK,
        "fallback": SCORING_MODE_HEURISTIC_FALLBACK,
        "rules": SCORING_MODE_RULES_ONLY,
        "rule": SCORING_MODE_RULES_ONLY,
        "hybrid": SCORING_MODE_HYBRID,
        "combined": SCORING_MODE_HYBRID,
        "off": SCORING_MODE_DISABLED,
        "disabled": SCORING_MODE_DISABLED,
        "none": SCORING_MODE_DISABLED,
    }
)


# -----------------------------------------------------------------------------
# Model statuses
# -----------------------------------------------------------------------------

MODEL_STATUS_DRAFT: Final[str] = "DRAFT"
MODEL_STATUS_EVALUATED: Final[str] = "EVALUATED"
MODEL_STATUS_CANDIDATE: Final[str] = "CANDIDATE"
MODEL_STATUS_ACTIVE: Final[str] = "ACTIVE"
MODEL_STATUS_RETIRED: Final[str] = "RETIRED"
MODEL_STATUS_ARCHIVED: Final[str] = "ARCHIVED"

MODEL_STATUSES: Final[tuple[str, ...]] = (
    MODEL_STATUS_DRAFT,
    MODEL_STATUS_EVALUATED,
    MODEL_STATUS_CANDIDATE,
    MODEL_STATUS_ACTIVE,
    MODEL_STATUS_RETIRED,
    MODEL_STATUS_ARCHIVED,
)

_STATUS_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "new": MODEL_STATUS_DRAFT,
        "draft": MODEL_STATUS_DRAFT,
        "evaluated": MODEL_STATUS_EVALUATED,
        "candidate": MODEL_STATUS_CANDIDATE,
        "active": MODEL_STATUS_ACTIVE,
        "live": MODEL_STATUS_ACTIVE,
        "prod": MODEL_STATUS_ACTIVE,
        "production": MODEL_STATUS_ACTIVE,
        "retired": MODEL_STATUS_RETIRED,
        "deprecated": MODEL_STATUS_RETIRED,
        "archived": MODEL_STATUS_ARCHIVED,
    }
)


# -----------------------------------------------------------------------------
# Risk bands
# -----------------------------------------------------------------------------

RISK_BAND_LOW: Final[str] = "LOW"
RISK_BAND_MEDIUM: Final[str] = "MEDIUM"
RISK_BAND_HIGH: Final[str] = "HIGH"
RISK_BAND_CRITICAL: Final[str] = "CRITICAL"
RISK_BAND_UNKNOWN: Final[str] = "UNKNOWN"

RISK_BANDS: Final[tuple[str, ...]] = (
    RISK_BAND_LOW,
    RISK_BAND_MEDIUM,
    RISK_BAND_HIGH,
    RISK_BAND_CRITICAL,
    RISK_BAND_UNKNOWN,
)

DEFAULT_RISK_THRESHOLDS: Final[Mapping[str, float]] = MappingProxyType(
    {
        "critical": 0.90,
        "high": 0.75,
        "medium": 0.50,
        "low": 0.25,
    }
)


# -----------------------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------------------

METRIC_AUC: Final[str] = "auc"
METRIC_ROC_AUC: Final[str] = "roc_auc"
METRIC_PR_AUC: Final[str] = "pr_auc"
METRIC_PRECISION: Final[str] = "precision"
METRIC_RECALL: Final[str] = "recall"
METRIC_F1: Final[str] = "f1"
METRIC_BRIER_SCORE: Final[str] = "brier_score"
METRIC_EXPECTED_CALIBRATION_ERROR: Final[str] = "expected_calibration_error"
METRIC_FALSE_POSITIVE_RATE: Final[str] = "false_positive_rate"
METRIC_TRUE_POSITIVE_RATE: Final[str] = "true_positive_rate"
METRIC_CONFUSION_TP: Final[str] = "confusion_tp"
METRIC_CONFUSION_FP: Final[str] = "confusion_fp"
METRIC_CONFUSION_FN: Final[str] = "confusion_fn"
METRIC_CONFUSION_TN: Final[str] = "confusion_tn"
METRIC_SAMPLE_COUNT: Final[str] = "sample_count"
METRIC_POSITIVE_RATE: Final[str] = "positive_rate"
METRIC_THRESHOLD: Final[str] = "threshold"

DEFAULT_METRICS: Final[tuple[str, ...]] = (
    METRIC_ROC_AUC,
    METRIC_PR_AUC,
    METRIC_PRECISION,
    METRIC_RECALL,
    METRIC_F1,
    METRIC_BRIER_SCORE,
    METRIC_EXPECTED_CALIBRATION_ERROR,
    METRIC_FALSE_POSITIVE_RATE,
    METRIC_TRUE_POSITIVE_RATE,
    METRIC_CONFUSION_TP,
    METRIC_CONFUSION_FP,
    METRIC_CONFUSION_FN,
    METRIC_CONFUSION_TN,
    METRIC_SAMPLE_COUNT,
    METRIC_POSITIVE_RATE,
    METRIC_THRESHOLD,
)

_METRIC_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "area_under_roc_curve": METRIC_ROC_AUC,
        "area_under_precision_recall_curve": METRIC_PR_AUC,
        "average_precision": METRIC_PR_AUC,
        "calibration_error": METRIC_EXPECTED_CALIBRATION_ERROR,
        "ece": METRIC_EXPECTED_CALIBRATION_ERROR,
        "fpr": METRIC_FALSE_POSITIVE_RATE,
        "tpr": METRIC_TRUE_POSITIVE_RATE,
        "true_positive_rate": METRIC_TRUE_POSITIVE_RATE,
        "false_positive_rate": METRIC_FALSE_POSITIVE_RATE,
        "samples": METRIC_SAMPLE_COUNT,
        "n_samples": METRIC_SAMPLE_COUNT,
        "positives": METRIC_POSITIVE_RATE,
        "cutoff": METRIC_THRESHOLD,
    }
)

_KNOWN_METRICS: Final[frozenset[str]] = frozenset(DEFAULT_METRICS)


# -----------------------------------------------------------------------------
# Bounded defaults
# -----------------------------------------------------------------------------

DEFAULT_MAX_FEATURES: Final[int] = 512
HARD_MAX_FEATURES: Final[int] = 4_096

DEFAULT_MAX_BATCH_SIZE: Final[int] = 1_000
HARD_MAX_BATCH_SIZE: Final[int] = 10_000

DEFAULT_MAX_MODEL_VERSIONS: Final[int] = 1_000
HARD_MAX_MODEL_VERSIONS: Final[int] = 100_000

DEFAULT_MAX_EXPLANATION_ITEMS: Final[int] = 50
HARD_MAX_EXPLANATION_ITEMS: Final[int] = 500

DEFAULT_MAX_METRIC_SAMPLES: Final[int] = 100_000
HARD_MAX_METRIC_SAMPLES: Final[int] = 10_000_000


# -----------------------------------------------------------------------------
# Forbidden and sensitive ML field registries
# -----------------------------------------------------------------------------

ML_FEATURE_FORBIDDEN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "fraud_label",
        "ground_truth",
        "ground_truth_label",
        "is_fraud",
        "label",
        "ring_id",
        "scenario_id",
        "truth_label",
    }
)

ML_SENSITIVE_OUTPUT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "artifact_path",
        "database_url",
        "file_path",
        "ground_truth_label",
        "identifier_hash",
        "model_artifact_path",
        "model_path",
        "narrative",
        "narrative_normalized",
        "narrative_raw",
        "password",
        "password_hash",
        "private_key",
        "raw_payload",
        "ring_id",
        "scenario_id",
        "secret",
        "secret_key",
        "token",
    }
)


# -----------------------------------------------------------------------------
# ML-layer safety flags
# -----------------------------------------------------------------------------
# These are declarative policy markers. Runtime enforcement must still exist in
# ML services, API dependencies, feature builders, evaluators, persistence
# layers, middleware, tests, and deployment controls.

_ML_SAFETY_FLAGS_RAW: Final[dict[str, bool]] = {
    "synthetic_only_by_default": True,
    "no_real_customer_data_by_default": True,
    "no_ground_truth_labels_exposed": True,
    "no_scenario_ids_exposed": True,
    "no_fraud_ring_ids_exposed": True,
    "no_model_artifact_paths_exposed": True,
    "no_raw_narrative_in_outputs": True,
    "no_secrets_in_logs": True,
    "no_tokens_in_logs": True,
    "no_passwords_in_logs": True,
    "no_database_urls_in_logs": True,
    "heuristic_fallback_not_calibrated_probability": True,
    "risk_scores_are_investigative_priority_only": True,
    "undefined_metrics_reported_unavailable": True,
    "no_automatic_adverse_customer_action": True,
    "no_training_in_production_by_default": True,
    "no_model_promotion_without_explicit_policy": True,
    "audit_material_ml_actions": True,
    "not_production_ready": True,
}

ML_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(_ML_SAFETY_FLAGS_RAW)


# -----------------------------------------------------------------------------
# Standard ML caveats
# -----------------------------------------------------------------------------

ML_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic ML prototype only. Do not use with real customer data.",
    "Risk scores are investigative priority scores, not probabilities of guilt.",
    "Heuristic fallback scores are not calibrated model probabilities.",
    "Undefined metrics are reported honestly as unavailable, not invented.",
    "Model metadata does not imply production readiness or regulatory compliance.",
    "ML outputs are investigative leads only and must not trigger automatic adverse customer action.",
    "Raw complaint narratives, ground-truth labels, scenario IDs, fraud-ring IDs, secrets, tokens, passwords, database URLs, and model artifact paths are never exposed.",
    "This API does not train, retrain, promote, retire, upload, replace, or execute models unless explicitly implemented, authorized, audited, and bounded elsewhere.",
    "Feature importance and explanation factors are operational attributions only and are not causal proof.",
    "This prototype is not production-ready and does not claim regulatory compliance.",
)


# -----------------------------------------------------------------------------
# Boolean parsing literals
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_PRODUCTION_LIKE_DEFAULTS: Final[tuple[str, ...]] = (
    "production",
    "staging",
    "prod",
    "stage",
)


# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------

__all__: Final[tuple[str, ...]] = (
    # Metadata
    "ML_PACKAGE_NAME",
    "ML_LAYER",
    "ML_VERSION",
    "ML_API_PREFIX",
    # Modes
    "ML_MODE_SYNTHETIC_ONLY",
    "ML_MODE_LOCAL_DEMO",
    "ML_MODE_TEST_FIXTURES",
    "ML_MODE_OFFLINE_EVALUATION",
    "ML_MODES",
    # Feature windows
    "FEATURE_WINDOW_1H",
    "FEATURE_WINDOW_24H",
    "FEATURE_WINDOW_7D",
    "FEATURE_WINDOW_30D",
    "FEATURE_WINDOW_90D",
    "FEATURE_WINDOW_365D",
    "FEATURE_WINDOWS",
    # Scoring modes
    "SCORING_MODE_TRAINED_MODEL",
    "SCORING_MODE_HEURISTIC_FALLBACK",
    "SCORING_MODE_RULES_ONLY",
    "SCORING_MODE_HYBRID",
    "SCORING_MODE_DISABLED",
    "SCORING_MODE_UNKNOWN",
    "SCORING_MODES",
    # Model statuses
    "MODEL_STATUS_DRAFT",
    "MODEL_STATUS_EVALUATED",
    "MODEL_STATUS_CANDIDATE",
    "MODEL_STATUS_ACTIVE",
    "MODEL_STATUS_RETIRED",
    "MODEL_STATUS_ARCHIVED",
    "MODEL_STATUSES",
    # Risk bands
    "RISK_BAND_LOW",
    "RISK_BAND_MEDIUM",
    "RISK_BAND_HIGH",
    "RISK_BAND_CRITICAL",
    "RISK_BAND_UNKNOWN",
    "RISK_BANDS",
    "DEFAULT_RISK_THRESHOLDS",
    # Metrics
    "METRIC_AUC",
    "METRIC_ROC_AUC",
    "METRIC_PR_AUC",
    "METRIC_PRECISION",
    "METRIC_RECALL",
    "METRIC_F1",
    "METRIC_BRIER_SCORE",
    "METRIC_EXPECTED_CALIBRATION_ERROR",
    "METRIC_FALSE_POSITIVE_RATE",
    "METRIC_TRUE_POSITIVE_RATE",
    "METRIC_CONFUSION_TP",
    "METRIC_CONFUSION_FP",
    "METRIC_CONFUSION_FN",
    "METRIC_CONFUSION_TN",
    "METRIC_SAMPLE_COUNT",
    "METRIC_POSITIVE_RATE",
    "METRIC_THRESHOLD",
    "DEFAULT_METRICS",
    # Limits
    "DEFAULT_MAX_FEATURES",
    "HARD_MAX_FEATURES",
    "DEFAULT_MAX_BATCH_SIZE",
    "HARD_MAX_BATCH_SIZE",
    "DEFAULT_MAX_MODEL_VERSIONS",
    "HARD_MAX_MODEL_VERSIONS",
    "DEFAULT_MAX_EXPLANATION_ITEMS",
    "HARD_MAX_EXPLANATION_ITEMS",
    "DEFAULT_MAX_METRIC_SAMPLES",
    "HARD_MAX_METRIC_SAMPLES",
    # Safety
    "ML_FEATURE_FORBIDDEN_FIELDS",
    "ML_SENSITIVE_OUTPUT_FIELDS",
    "ML_SAFETY_FLAGS",
    "ML_CAVEATS",
    # Policy
    "MLPolicy",
    "get_ml_policy",
    "resolve_ml_policy",
    "risk_band",
    # Helpers
    "get_ml_metadata",
    "is_known_metric",
    "normalize_feature_window",
    "normalize_metric_name",
    "normalize_ml_mode",
    "normalize_model_status",
    "normalize_scoring_mode",
    # Lazy submodules
    "service",
    "features",
    "scoring",
    "training",
    "evaluation",
    "calibration",
    "explainability",
    "monitoring",
    "policies",
    "artifacts",
    "repositories",
    "models",
    "errors",
    # Lazy symbols
    "MLService",
    "get_ml_service",
    "build_features",
    "score_account_risk",
    "explain_assessment",
    "train_synthetic_model",
    "evaluate_synthetic_model",
    "calibrate_synthetic_model",
    "monitor_model_health",
    "load_ml_policy",
    "list_model_versions",
    "get_model_metadata",
)


# -----------------------------------------------------------------------------
# Lazy module and symbol access
# -----------------------------------------------------------------------------
# Keeps `import app.ml` cheap and avoids circular-import pressure during
# package initialization.
#
# Supported patterns:
#
#   from app.ml import service
#   from app.ml import features
#   from app.ml import get_ml_service
#   from app.ml import MLService
#
# Missing modules or symbols raise normal ImportError/ModuleNotFoundError or
# AttributeError at the point of use rather than failing the entire package
# import.

_LAZY_MODULES: Final[dict[str, str]] = {
    "service": ".service",
    "features": ".features",
    "scoring": ".scoring",
    "training": ".training",
    "evaluation": ".evaluation",
    "calibration": ".calibration",
    "explainability": ".explainability",
    "monitoring": ".monitoring",
    "policies": ".policies",
    "artifacts": ".artifacts",
    "repositories": ".repositories",
    "models": ".models",
    "errors": ".errors",
}

_LAZY_ATTRS: Final[dict[str, tuple[str, str]]] = {
    "MLService": (".service", "MLService"),
    "get_ml_service": (".service", "get_ml_service"),
    "build_features": (".features", "build_features"),
    "score_account_risk": (".scoring", "score_account_risk"),
    "explain_assessment": (".explainability", "explain_assessment"),
    "train_synthetic_model": (".training", "train_synthetic_model"),
    "evaluate_synthetic_model": (".evaluation", "evaluate_synthetic_model"),
    "calibrate_synthetic_model": (".calibration", "calibrate_synthetic_model"),
    "monitor_model_health": (".monitoring", "monitor_model_health"),
    "load_ml_policy": (".policies", "load_ml_policy"),
    "list_model_versions": (".repositories", "list_model_versions"),
    "get_model_metadata": (".artifacts", "get_model_metadata"),
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
    Lazily import ML submodules or selected public symbols.

    Explicit lazy modules and symbols are tried first. If the requested name is
    a safe identifier and not already defined, this package also attempts a
    relative submodule import. This allows new ML submodules to become available
    without editing this initializer for every addition.
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


def _as_text_sequence(value: Any) -> list[str]:
    """
    Convert a setting-like value into a list of strings.
    """
    if value is None:
        return []

    if isinstance(value, str):
        return _csv(value)

    if isinstance(value, Mapping):
        return []

    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [str(item).strip() for item in value if str(item).strip()]

    text = str(value).strip()
    return [text] if text else []


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


def _normalize_token(value: Any) -> str:
    """
    Normalize a token-like value into lower snake_case.
    """
    text = str(value if value is not None else "").strip().lower()
    text = text.replace(" ", "_").replace("-", "_").replace("/", "_")

    while "__" in text:
        text = text.replace("__", "_")

    return text.strip("_")


def _upper_token(value: Any) -> str:
    """
    Normalize a token-like value into upper snake_case.
    """
    return _normalize_token(value).upper()


def _is_production_like(settings: Any) -> bool:
    """
    Return True when the runtime environment is production-like.
    """
    env = str(_setting(settings, "BACKEND_ENV", "local")).strip().lower()

    configured_values = _csv(
        _setting(
            settings,
            "BACKEND_PRODUCTION_LIKE_ENVS",
            ",".join(_PRODUCTION_LIKE_DEFAULTS),
        )
    )

    production_like_values = {value.lower() for value in configured_values}

    if not production_like_values:
        production_like_values = set(_PRODUCTION_LIKE_DEFAULTS)

    return env in production_like_values


def _is_synthetic_dataset_mode(value: Any) -> bool:
    """
    Return True when a dataset-mode-like value is synthetic-compatible.
    """
    return _normalize_token(value) in {
        "synthetic",
        "demo",
        "test",
        "fixture",
        "fixtures",
    }


def _coerce_score(value: Any) -> Optional[float]:
    """
    Coerce a score-like value into a bounded float in [0, 1].

    Returns None when the value is not a usable numeric score.
    """
    if value is None or isinstance(value, bool):
        return None

    try:
        score = float(value)
    except (TypeError, ValueError):
        return None

    if math.isnan(score) or math.isinf(score):
        return None

    return max(0.0, min(1.0, score))


def _normalized_thresholds(thresholds: Any) -> dict[str, float]:
    """
    Return bounded, monotonic risk thresholds.
    """
    defaults = dict(DEFAULT_RISK_THRESHOLDS)

    if isinstance(thresholds, Mapping):
        for key in defaults:
            if key in thresholds:
                defaults[key] = _clamp_float(thresholds[key], 0.0, 1.0, defaults[key])

    low = defaults["low"]
    medium = max(low, defaults["medium"])
    high = max(medium, defaults["high"])
    critical = max(high, defaults["critical"])

    return {
        "low": low,
        "medium": medium,
        "high": high,
        "critical": critical,
    }


# -----------------------------------------------------------------------------
# Normalization helpers
# -----------------------------------------------------------------------------


def normalize_ml_mode(
    value: Any,
    *,
    default: str = ML_MODE_SYNTHETIC_ONLY,
) -> str:
    """
    Normalize an ML mode-like value.

    Unknown values fall back to the supplied default. Alias handling is
    intentionally conservative and never accepts real-data modes implicitly.
    """
    token = _normalize_token(value)

    if token in ML_MODES:
        return token

    alias = _MODE_ALIASES.get(token)

    if alias is not None:
        return alias

    return default


def normalize_feature_window(
    value: Any,
    *,
    default: str = FEATURE_WINDOW_30D,
) -> str:
    """
    Normalize a feature-window-like value.
    """
    token = _normalize_token(value)

    if token in FEATURE_WINDOWS:
        return token

    alias = _WINDOW_ALIASES.get(token)

    if alias is not None:
        return alias

    return default


def normalize_scoring_mode(
    value: Any,
    *,
    default: str = SCORING_MODE_HEURISTIC_FALLBACK,
) -> str:
    """
    Normalize a scoring-mode-like value.
    """
    lower = _normalize_token(value)
    upper = lower.upper()

    if upper in SCORING_MODES:
        return upper

    alias = _SCORING_ALIASES.get(lower)

    if alias is not None:
        return alias

    return default


def normalize_model_status(
    value: Any,
    *,
    default: str = MODEL_STATUS_DRAFT,
) -> str:
    """
    Normalize a model-status-like value.
    """
    lower = _normalize_token(value)
    upper = lower.upper()

    if upper in MODEL_STATUSES:
        return upper

    alias = _STATUS_ALIASES.get(lower)

    if alias is not None:
        return alias

    return default


def normalize_metric_name(value: Any) -> str:
    """
    Normalize a metric identifier.

    Unknown metrics are preserved in normalized token form so callers can decide
    whether to treat them as unavailable or custom.
    """
    token = _normalize_token(value)
    return _METRIC_ALIASES.get(token, token)


def is_known_metric(value: Any) -> bool:
    """
    Return True when a metric identifier maps to a built-in MULEGUARD metric.
    """
    return normalize_metric_name(value) in _KNOWN_METRICS


def risk_band(
    score: Any,
    thresholds: Any | None = None,
) -> str:
    """
    Map a bounded score to an investigative risk band.

    Risk bands are operational prioritization labels only. They are not
    probabilities of guilt and must not trigger automatic adverse customer
    action.
    """
    resolved = _normalized_thresholds(thresholds or DEFAULT_RISK_THRESHOLDS)
    value = _coerce_score(score)

    if value is None:
        return RISK_BAND_UNKNOWN

    if value >= resolved["critical"]:
        return RISK_BAND_CRITICAL

    if value >= resolved["high"]:
        return RISK_BAND_HIGH

    if value >= resolved["medium"]:
        return RISK_BAND_MEDIUM

    if value >= resolved["low"]:
        return RISK_BAND_LOW

    return RISK_BAND_LOW


# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MLPolicy:
    """
    Bounded ML policy.

    This policy is intentionally conservative. Hard caps prevent accidental
    unbounded ML surfaces.
    """

    enabled: bool = True
    mode: str = ML_MODE_SYNTHETIC_ONLY
    dataset_mode: str = "synthetic"
    synthetic_required: bool = True
    allow_in_production: bool = False
    production_like: bool = False

    scoring_mode: str = SCORING_MODE_HEURISTIC_FALLBACK
    default_feature_window: str = FEATURE_WINDOW_30D
    allowed_feature_windows: tuple[str, ...] = FEATURE_WINDOWS
    metrics: tuple[str, ...] = DEFAULT_METRICS
    thresholds: Mapping[str, float] = field(
        default_factory=lambda: dict(DEFAULT_RISK_THRESHOLDS)
    )

    max_features: int = DEFAULT_MAX_FEATURES
    max_batch_size: int = DEFAULT_MAX_BATCH_SIZE
    max_model_versions: int = DEFAULT_MAX_MODEL_VERSIONS
    max_explanation_items: int = DEFAULT_MAX_EXPLANATION_ITEMS
    max_metric_samples: int = DEFAULT_MAX_METRIC_SAMPLES

    allow_training: bool = False
    allow_evaluation: bool = True
    allow_promotion: bool = False
    allow_retirement: bool = False
    expose_model_artifact_paths: bool = False

    audit_material_actions: bool = True

    def __post_init__(self) -> None:
        """
        Normalize and clamp policy values.
        """
        object.__setattr__(self, "enabled", _as_bool(self.enabled, True))
        object.__setattr__(self, "mode", normalize_ml_mode(self.mode))
        object.__setattr__(
            self,
            "dataset_mode",
            _normalize_token(self.dataset_mode) or "synthetic",
        )
        object.__setattr__(self, "synthetic_required", _as_bool(self.synthetic_required, True))
        object.__setattr__(self, "allow_in_production", _as_bool(self.allow_in_production, False))
        object.__setattr__(self, "production_like", _as_bool(self.production_like, False))

        object.__setattr__(self, "scoring_mode", normalize_scoring_mode(self.scoring_mode))
        object.__setattr__(
            self,
            "default_feature_window",
            normalize_feature_window(self.default_feature_window),
        )

        windows = tuple(
            normalize_feature_window(item)
            for item in _as_text_sequence(self.allowed_feature_windows)
        )
        windows = _unique_preserve_order(windows)

        if not windows:
            windows = FEATURE_WINDOWS

        object.__setattr__(self, "allowed_feature_windows", windows)

        if self.default_feature_window not in windows:
            object.__setattr__(self, "default_feature_window", windows[0])

        metrics = tuple(
            normalize_metric_name(item)
            for item in _as_text_sequence(self.metrics)
            if normalize_metric_name(item)
        )
        metrics = _unique_preserve_order(metrics)

        if not metrics:
            metrics = DEFAULT_METRICS

        object.__setattr__(self, "metrics", metrics)

        object.__setattr__(
            self,
            "thresholds",
            MappingProxyType(_normalized_thresholds(self.thresholds)),
        )

        object.__setattr__(
            self,
            "max_features",
            _clamp_int(self.max_features, 1, HARD_MAX_FEATURES, DEFAULT_MAX_FEATURES),
        )
        object.__setattr__(
            self,
            "max_batch_size",
            _clamp_int(self.max_batch_size, 1, HARD_MAX_BATCH_SIZE, DEFAULT_MAX_BATCH_SIZE),
        )
        object.__setattr__(
            self,
            "max_model_versions",
            _clamp_int(
                self.max_model_versions,
                1,
                HARD_MAX_MODEL_VERSIONS,
                DEFAULT_MAX_MODEL_VERSIONS,
            ),
        )
        object.__setattr__(
            self,
            "max_explanation_items",
            _clamp_int(
                self.max_explanation_items,
                1,
                HARD_MAX_EXPLANATION_ITEMS,
                DEFAULT_MAX_EXPLANATION_ITEMS,
            ),
        )
        object.__setattr__(
            self,
            "max_metric_samples",
            _clamp_int(
                self.max_metric_samples,
                1,
                HARD_MAX_METRIC_SAMPLES,
                DEFAULT_MAX_METRIC_SAMPLES,
            ),
        )

        object.__setattr__(self, "allow_training", _as_bool(self.allow_training, False))
        object.__setattr__(self, "allow_evaluation", _as_bool(self.allow_evaluation, True))
        object.__setattr__(self, "allow_promotion", _as_bool(self.allow_promotion, False))
        object.__setattr__(self, "allow_retirement", _as_bool(self.allow_retirement, False))
        object.__setattr__(self, "audit_material_actions", _as_bool(self.audit_material_actions, True))

        # Model artifact paths are never exposed by the ML layer.
        object.__setattr__(self, "expose_model_artifact_paths", False)

        # Production-like environments must explicitly allow sensitive ML actions.
        if self.production_like and not self.allow_in_production:
            object.__setattr__(self, "allow_training", False)
            object.__setattr__(self, "allow_promotion", False)
            object.__setattr__(self, "allow_retirement", False)

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "MLPolicy":
        """
        Build an ML policy from runtime settings with safe defaults.
        """
        if settings is None:
            settings = _get_settings()

        enabled = _as_bool(_setting(settings, "ML_ENABLED", True), True) and _as_bool(
            _setting(settings, "ML_API_ENABLED", True),
            True,
        )

        mode = normalize_ml_mode(
            _setting(settings, "ML_MODE", ML_MODE_SYNTHETIC_ONLY),
            default=ML_MODE_SYNTHETIC_ONLY,
        )

        dataset_mode = str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower()

        synthetic_required = _as_bool(
            _setting(settings, "ML_REQUIRE_SYNTHETIC", True),
            True,
        )

        allow_in_production = _as_bool(
            _setting(settings, "ML_ALLOW_IN_PRODUCTION", False),
            False,
        )

        production_like = _is_production_like(settings)

        scoring_mode = normalize_scoring_mode(
            _setting(settings, "ML_SCORING_MODE", SCORING_MODE_HEURISTIC_FALLBACK),
            default=SCORING_MODE_HEURISTIC_FALLBACK,
        )

        default_feature_window = normalize_feature_window(
            _setting(settings, "ML_DEFAULT_FEATURE_WINDOW", FEATURE_WINDOW_30D),
            default=FEATURE_WINDOW_30D,
        )

        raw_windows = _setting(settings, "ML_FEATURE_WINDOWS", None)
        allowed_feature_windows = (
            _as_text_sequence(raw_windows)
            if raw_windows is not None
            else list(FEATURE_WINDOWS)
        )

        raw_metrics = _setting(settings, "ML_METRICS", None)
        metrics = (
            _as_text_sequence(raw_metrics)
            if raw_metrics is not None
            else list(DEFAULT_METRICS)
        )

        raw_thresholds = _setting(settings, "ML_RISK_THRESHOLDS", None)
        thresholds = raw_thresholds if isinstance(raw_thresholds, Mapping) else DEFAULT_RISK_THRESHOLDS

        return cls(
            enabled=enabled,
            mode=mode,
            dataset_mode=dataset_mode,
            synthetic_required=synthetic_required,
            allow_in_production=allow_in_production,
            production_like=production_like,
            scoring_mode=scoring_mode,
            default_feature_window=default_feature_window,
            allowed_feature_windows=tuple(allowed_feature_windows),
            metrics=tuple(metrics),
            thresholds=thresholds,
            max_features=_as_int(_setting(settings, "ML_MAX_FEATURES", DEFAULT_MAX_FEATURES), DEFAULT_MAX_FEATURES),
            max_batch_size=_as_int(
                _setting(settings, "ML_MAX_BATCH_SIZE", DEFAULT_MAX_BATCH_SIZE),
                DEFAULT_MAX_BATCH_SIZE,
            ),
            max_model_versions=_as_int(
                _setting(settings, "ML_MAX_MODEL_VERSIONS", DEFAULT_MAX_MODEL_VERSIONS),
                DEFAULT_MAX_MODEL_VERSIONS,
            ),
            max_explanation_items=_as_int(
                _setting(settings, "ML_MAX_EXPLANATION_ITEMS", DEFAULT_MAX_EXPLANATION_ITEMS),
                DEFAULT_MAX_EXPLANATION_ITEMS,
            ),
            max_metric_samples=_as_int(
                _setting(settings, "ML_MAX_METRIC_SAMPLES", DEFAULT_MAX_METRIC_SAMPLES),
                DEFAULT_MAX_METRIC_SAMPLES,
            ),
            allow_training=_as_bool(_setting(settings, "ML_ALLOW_TRAINING", False), False),
            allow_evaluation=_as_bool(_setting(settings, "ML_ALLOW_EVALUATION", True), True),
            allow_promotion=_as_bool(_setting(settings, "ML_ALLOW_PROMOTION", False), False),
            allow_retirement=_as_bool(_setting(settings, "ML_ALLOW_RETIREMENT", False), False),
            audit_material_actions=_as_bool(_setting(settings, "ML_AUDIT_MATERIAL_ACTIONS", True), True),
        )

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, serializable policy summary.

        This never includes secrets, tokens, passwords, database URLs, model
        artifact paths, raw narratives, ground-truth labels, scenario IDs, or
        fraud-ring IDs.
        """
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "dataset_mode": self.dataset_mode,
            "synthetic_required": self.synthetic_required,
            "synthetic_dataset_mode": _is_synthetic_dataset_mode(self.dataset_mode),
            "allow_in_production": self.allow_in_production,
            "production_like": self.production_like,
            "scoring_mode": self.scoring_mode,
            "default_feature_window": self.default_feature_window,
            "allowed_feature_windows": list(self.allowed_feature_windows),
            "metrics": list(self.metrics),
            "thresholds": {
                key: round(float(value), 4)
                for key, value in self.thresholds.items()
            },
            "limits": {
                "max_features": self.max_features,
                "max_batch_size": self.max_batch_size,
                "max_model_versions": self.max_model_versions,
                "max_explanation_items": self.max_explanation_items,
                "max_metric_samples": self.max_metric_samples,
            },
            "capabilities": {
                "allow_training": self.allow_training,
                "allow_evaluation": self.allow_evaluation,
                "allow_promotion": self.allow_promotion,
                "allow_retirement": self.allow_retirement,
                "expose_model_artifact_paths": self.expose_model_artifact_paths,
                "audit_material_actions": self.audit_material_actions,
            },
            "forbidden_feature_fields": sorted(ML_FEATURE_FORBIDDEN_FIELDS),
            "sensitive_output_fields": sorted(ML_SENSITIVE_OUTPUT_FIELDS),
            "safety_flags": dict(ML_SAFETY_FLAGS),
            "caveats": list(ML_CAVEATS),
        }


# -----------------------------------------------------------------------------
# Policy helpers
# -----------------------------------------------------------------------------


def get_ml_policy(settings: Any | None = None) -> MLPolicy:
    """
    Return an ML policy resolved from settings.

    This helper is intentionally non-raising. Enforcement belongs in ML
    services, API dependencies, feature builders, evaluators, and deployment
    controls.
    """
    return MLPolicy.from_settings(settings)


def resolve_ml_policy(settings: Any | None = None) -> dict[str, Any]:
    """
    Return effective ML policy as a safe dictionary.
    """
    return get_ml_policy(settings).safe_summary()


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_ml_metadata() -> dict[str, Any]:
    """
    Return safe, serializable ML-layer metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, ground-truth labels, scenario IDs,
    fraud-ring IDs, model artifact paths, or real customer data.
    """
    default_policy = get_ml_policy()

    return {
        "package": ML_PACKAGE_NAME,
        "layer": ML_LAYER,
        "version": ML_VERSION,
        "api_prefix": ML_API_PREFIX,
        "modes": list(ML_MODES),
        "feature_windows": list(FEATURE_WINDOWS),
        "scoring_modes": list(SCORING_MODES),
        "model_statuses": list(MODEL_STATUSES),
        "risk_bands": list(RISK_BANDS),
        "metrics": list(DEFAULT_METRICS),
        "default_policy": default_policy.safe_summary(),
        "hard_limits": {
            "max_features": HARD_MAX_FEATURES,
            "max_batch_size": HARD_MAX_BATCH_SIZE,
            "max_model_versions": HARD_MAX_MODEL_VERSIONS,
            "max_explanation_items": HARD_MAX_EXPLANATION_ITEMS,
            "max_metric_samples": HARD_MAX_METRIC_SAMPLES,
        },
        "forbidden_feature_fields": sorted(ML_FEATURE_FORBIDDEN_FIELDS),
        "sensitive_output_fields": sorted(ML_SENSITIVE_OUTPUT_FIELDS),
        "safety_flags": dict(ML_SAFETY_FLAGS),
        "caveats": list(ML_CAVEATS),
        "lazy_modules": tuple(sorted(_LAZY_MODULES)),
        "lazy_attributes": tuple(sorted(_LAZY_ATTRS)),
        "dynamic_submodule_access": True,
    }