"""
MULEGUARD backend package.

This module intentionally avoids eager imports of FastAPI, SQLAlchemy, Pandas,
scikit-learn, NetworkX, ReportLab, or other heavyweight dependencies.

Its responsibilities are limited to:

- exposing stable package metadata;
- declaring synthetic-first and safety policy constants;
- providing lazy module access for top-level backend packages/modules;
- offering safe policy-validation helpers for tests and startup checks.

Product safety reminders:

- MULEGUARD is a synthetic-first academic / hackathon-grade prototype.
- It is not production-ready.
- It must not process real customer data by default.
- It must not implement automatic adverse customer action.
- Alerts, scores, graph relationships, candidate money trails, and complaint
  correlations are investigative leads only.
"""

from __future__ import annotations

from collections.abc import Mapping
from importlib import import_module
from types import MappingProxyType
from typing import Any, Final

# -----------------------------------------------------------------------------
# Execution guard
# -----------------------------------------------------------------------------
# This package is intended to be imported as part of the backend application.
# Direct execution of app/__init__.py is not a supported entrypoint.
if __package__ in {None, ""}:
    raise RuntimeError(
        "Do not execute app/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )


# -----------------------------------------------------------------------------
# Stable package metadata
# -----------------------------------------------------------------------------

__version__: Final[str] = "0.1.0"
__version_info__: Final[tuple[int, int, int, str]] = (0, 1, 0, "alpha")

APP_NAME: Final[str] = "MULEGUARD Backend"
APP_DESCRIPTION: Final[str] = (
    "Synthetic-first mule account detection and financial fraud investigation prototype backend"
)
API_PREFIX: Final[str] = "/api/v1"
DATA_CLASSIFICATION: Final[str] = "synthetic"
LICENSE: Final[str] = "MIT"
AUTHOR: Final[str] = "MULEGUARD Contributors"
COPYRIGHT: Final[str] = "Copyright (c) 2026 MULEGUARD Contributors"
PYTHON_REQUIRES: Final[str] = ">=3.11"


# -----------------------------------------------------------------------------
# Product safety and scope boundaries
# -----------------------------------------------------------------------------
# These constants are compile-time declarations of intended policy.
# Runtime enforcement must still be implemented in configuration, services,
# API dependencies, tests, and deployment controls.

SYNTHETIC_FIRST: Final[bool] = True
PRODUCTION_READY: Final[bool] = False
AUTOMATIC_ADVERSE_ACTION_ALLOWED: Final[bool] = False
REAL_CUSTOMER_DATA_ALLOWED: Final[bool] = False

MODEL_PROBABILITY_CLAIM_ALLOWED: Final[bool] = False
CALIBRATION_CLAIM_ALLOWED: Final[bool] = False

GRAPH_UNBOUNDED_QUERY_ALLOWED: Final[bool] = False
USER_UPLOADED_MODEL_DESERIALIZATION_ALLOWED: Final[bool] = False

FAKE_FUNCTIONALITY_ALLOWED: Final[bool] = False
HARDCODED_METRICS_ALLOWED: Final[bool] = False

LABEL_LEAKAGE_ALLOWED: Final[bool] = False
FUTURE_INFORMATION_IN_FEATURES_ALLOWED: Final[bool] = False

AUDIT_BYPASS_ALLOWED: Final[bool] = False
SECRET_IN_SOURCE_CONTROL_ALLOWED: Final[bool] = False


# -----------------------------------------------------------------------------
# Immutable policy mappings
# -----------------------------------------------------------------------------

_SAFETY_FLAGS_RAW: Final[dict[str, bool]] = {
    "synthetic_first": SYNTHETIC_FIRST,
    "production_ready": PRODUCTION_READY,
    "automatic_adverse_action_allowed": AUTOMATIC_ADVERSE_ACTION_ALLOWED,
    "real_customer_data_allowed": REAL_CUSTOMER_DATA_ALLOWED,
    "model_probability_claim_allowed": MODEL_PROBABILITY_CLAIM_ALLOWED,
    "calibration_claim_allowed": CALIBRATION_CLAIM_ALLOWED,
    "graph_unbounded_query_allowed": GRAPH_UNBOUNDED_QUERY_ALLOWED,
    "user_uploaded_model_deserialization_allowed": USER_UPLOADED_MODEL_DESERIALIZATION_ALLOWED,
    "fake_functionality_allowed": FAKE_FUNCTIONALITY_ALLOWED,
    "hardcoded_metrics_allowed": HARDCODED_METRICS_ALLOWED,
    "label_leakage_allowed": LABEL_LEAKAGE_ALLOWED,
    "future_information_in_features_allowed": FUTURE_INFORMATION_IN_FEATURES_ALLOWED,
    "audit_bypass_allowed": AUDIT_BYPASS_ALLOWED,
    "secret_in_source_control_allowed": SECRET_IN_SOURCE_CONTROL_ALLOWED,
}

SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(_SAFETY_FLAGS_RAW)


_PRODUCT_PRINCIPLES_RAW: Final[dict[str, bool]] = {
    "synthetic_first": True,
    "evidence_backed": True,
    "explainable": True,
    "human_in_the_loop": True,
    "auditable": True,
    "reproducible": True,
    "temporally_correct": True,
    "secure_by_default": True,
    "graceful_degradation": True,
    "no_fake_functionality": True,
}

PRODUCT_PRINCIPLES: Final[Mapping[str, bool]] = MappingProxyType(_PRODUCT_PRINCIPLES_RAW)


NON_GOALS: Final[tuple[str, ...]] = (
    "real_bank_integration",
    "real_payment_rail_integration",
    "real_customer_data_processing",
    "live_cybercrime_database_access",
    "deanonymisation",
    "covert_surveillance",
    "automatic_account_freezing",
    "automatic_payment_blocking",
    "automatic_blacklisting",
    "adverse_automated_customer_action",
    "production_regulatory_compliance_claim",
    "real_world_fraud_detection_accuracy_claim",
)


# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------
# Keep this intentionally small. Top-level modules are lazily accessible via
# __getattr__, but they are not exported by star-import to avoid accidental
# heavyweight module loading.

__all__: Final[tuple[str, ...]] = (
    "API_PREFIX",
    "APP_DESCRIPTION",
    "APP_NAME",
    "AUDIT_BYPASS_ALLOWED",
    "AUTHOR",
    "AUTOMATIC_ADVERSE_ACTION_ALLOWED",
    "CALIBRATION_CLAIM_ALLOWED",
    "COPYRIGHT",
    "DATA_CLASSIFICATION",
    "FAKE_FUNCTIONALITY_ALLOWED",
    "FUTURE_INFORMATION_IN_FEATURES_ALLOWED",
    "GRAPH_UNBOUNDED_QUERY_ALLOWED",
    "HARDCODED_METRICS_ALLOWED",
    "LABEL_LEAKAGE_ALLOWED",
    "LICENSE",
    "MODEL_PROBABILITY_CLAIM_ALLOWED",
    "NON_GOALS",
    "PRODUCTION_READY",
    "PRODUCT_PRINCIPLES",
    "PYTHON_REQUIRES",
    "REAL_CUSTOMER_DATA_ALLOWED",
    "SAFETY_FLAGS",
    "SECRET_IN_SOURCE_CONTROL_ALLOWED",
    "SYNTHETIC_FIRST",
    "USER_UPLOADED_MODEL_DESERIALIZATION_ALLOWED",
    "__version__",
    "__version_info__",
    "assert_package_policy",
    "get_app_metadata",
    "validate_package_policy",
)


# -----------------------------------------------------------------------------
# Lazy module access
# -----------------------------------------------------------------------------
# Allows patterns such as:
#
#   from app import models
#   from app import services
#   import app.graph
#
# without forcing every submodule to load during package import.
#
# Only stable top-level backend modules/packages are listed here. If a module
# has not been implemented yet, accessing it will raise the normal ImportError
# at the point of use rather than failing the entire package import.

_LAZY_MODULES: Final[dict[str, str]] = {
    "api": ".api",
    "auth": ".auth",
    "bootstrap": ".bootstrap",
    "core": ".core",
    "correlation": ".correlation",
    "db": ".db",
    "exceptions": ".exceptions",
    "graph": ".graph",
    "ingestion": ".ingestion",
    "lifecycle": ".lifecycle",
    "main": ".main",
    "ml": ".ml",
    "models": ".models",
    "reports": ".reports",
    "rules": ".rules",
    "schemas": ".schemas",
    "services": ".services",
    "utils": ".utils",
}


def __getattr__(name: str) -> Any:
    """
    Lazily import and cache top-level backend modules.

    This keeps `import app` cheap and avoids circular-import pressure during
    package initialization.
    """
    module_name = _LAZY_MODULES.get(name)

    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module = import_module(module_name, __name__)
    globals()[name] = module
    return module


def __dir__() -> list[str]:
    """
    Return a deterministic directory listing including lazily available modules.
    """
    return sorted(
        {
            *globals().keys(),
            *_LAZY_MODULES.keys(),
        }
    )


# -----------------------------------------------------------------------------
# Policy validation helpers
# -----------------------------------------------------------------------------


def validate_package_policy() -> tuple[str, ...]:
    """
    Return a tuple of policy violations detected from package-level constants.

    This does not replace runtime configuration validation. It is a lightweight
    guardrail for tests, startup checks, and developer tooling.
    """
    violations: list[str] = []

    if PRODUCTION_READY:
        violations.append("PRODUCTION_READY must be False for the MULEGUARD prototype.")

    if AUTOMATIC_ADVERSE_ACTION_ALLOWED:
        violations.append(
            "AUTOMATIC_ADVERSE_ACTION_ALLOWED must be False. "
            "MULEGUARD must not implement automatic account freezing, "
            "payment blocking, blacklisting, or other adverse customer action."
        )

    if REAL_CUSTOMER_DATA_ALLOWED:
        violations.append(
            "REAL_CUSTOMER_DATA_ALLOWED must be False by default. MULEGUARD is synthetic-first."
        )

    if MODEL_PROBABILITY_CLAIM_ALLOWED:
        violations.append(
            "MODEL_PROBABILITY_CLAIM_ALLOWED must be False unless calibrated "
            "probability modelling is explicitly implemented, documented, "
            "tested, and approved."
        )

    if CALIBRATION_CLAIM_ALLOWED:
        violations.append(
            "CALIBRATION_CLAIM_ALLOWED must be False unless calibration has "
            "actually been implemented and evaluated."
        )

    if GRAPH_UNBOUNDED_QUERY_ALLOWED:
        violations.append(
            "GRAPH_UNBOUNDED_QUERY_ALLOWED must be False. "
            "Graph queries must remain bounded and evidence-backed."
        )

    if USER_UPLOADED_MODEL_DESERIALIZATION_ALLOWED:
        violations.append(
            "USER_UPLOADED_MODEL_DESERIALIZATION_ALLOWED must be False. "
            "Model artifacts must be loaded only from controlled local paths."
        )

    if FAKE_FUNCTIONALITY_ALLOWED:
        violations.append(
            "FAKE_FUNCTIONALITY_ALLOWED must be False. "
            "UI controls, APIs, charts, exports, and workflows must do what "
            "their labels promise."
        )

    if HARDCODED_METRICS_ALLOWED:
        violations.append(
            "HARDCODED_METRICS_ALLOWED must be False. "
            "Dashboard and model metrics must derive from real persisted data "
            "or be explicitly marked unavailable."
        )

    if LABEL_LEAKAGE_ALLOWED:
        violations.append(
            "LABEL_LEAKAGE_ALLOWED must be False. "
            "Synthetic ground-truth labels and fraud-ring identifiers must "
            "not be used as predictor features."
        )

    if FUTURE_INFORMATION_IN_FEATURES_ALLOWED:
        violations.append(
            "FUTURE_INFORMATION_IN_FEATURES_ALLOWED must be False. "
            "Point-in-time features and assessments must not use future "
            "transactions, complaints, or investigation outcomes."
        )

    if AUDIT_BYPASS_ALLOWED:
        violations.append(
            "AUDIT_BYPASS_ALLOWED must be False. "
            "Material case, evidence, analysis, authentication, and report "
            "actions must leave durable audit records."
        )

    if SECRET_IN_SOURCE_CONTROL_ALLOWED:
        violations.append(
            "SECRET_IN_SOURCE_CONTROL_ALLOWED must be False. "
            "Secrets must be supplied through environment configuration or "
            "a secret manager, never committed to source control."
        )

    return tuple(violations)


def assert_package_policy() -> None:
    """
    Raise RuntimeError if package-level safety constants are violated.

    Intended for tests and controlled startup validation.
    """
    violations = validate_package_policy()

    if violations:
        raise RuntimeError(
            "MULEGUARD package policy validation failed:\n"
            + "\n".join(f"- {violation}" for violation in violations)
        )


def get_app_metadata() -> dict[str, Any]:
    """
    Return safe, serializable application metadata.

    This helper is useful for health endpoints, startup logs, OpenAPI metadata,
    and diagnostic tooling. It must not expose secrets, environment files,
    database URLs, tokens, or real customer data.
    """
    return {
        "name": APP_NAME,
        "description": APP_DESCRIPTION,
        "version": __version__,
        "version_info": __version_info__,
        "api_prefix": API_PREFIX,
        "data_classification": DATA_CLASSIFICATION,
        "python_requires": PYTHON_REQUIRES,
        "license": LICENSE,
        "author": AUTHOR,
        "copyright": COPYRIGHT,
        "production_ready": PRODUCTION_READY,
        "synthetic_first": SYNTHETIC_FIRST,
        "safety_flags": dict(SAFETY_FLAGS),
        "product_principles": dict(PRODUCT_PRINCIPLES),
        "non_goals": NON_GOALS,
        "policy_violations": validate_package_policy(),
        "lazy_modules": tuple(sorted(_LAZY_MODULES)),
    }
