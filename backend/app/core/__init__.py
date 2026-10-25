"""
MULEGUARD backend core package.

This module is the public entry point for the MULEGUARD core subsystem.

Its responsibilities are intentionally narrow:

- expose stable core-layer constants and metadata;
- declare shared runtime conventions such as timezone, currency, locale, and
  synthetic-first data classification;
- provide lazy access to core submodules and selected public symbols;
- provide safe helper metadata for diagnostics and tests;
- avoid eager imports of Pydantic Settings, SQLAlchemy, FastAPI, ML, graph,
  reporting, or audit dependencies during package initialization.

This package must not become a place where heavy runtime logic is executed at
import time.

Core submodules:

- config:      typed environment settings
- security:    hashing, tokens, and cryptographic helpers
- logging:     structured logging configuration
- roles:       role definitions
- permissions: permission checks
- pagination:  pagination helpers
- errors:      error taxonomy helpers
- rate_limit:  login/API throttling helpers
- cache:       optional bounded cache helpers
- enums:       shared enums
- constants:   stable constants

Product-safety expectations for the core layer:

- Core helpers must not fabricate functionality.
- Core helpers must not log secrets, tokens, passwords, database URLs, raw
  complaint narratives, or real customer data.
- Core helpers must remain synthetic-first by default.
- Core helpers must not trigger automatic adverse customer action.
- Alerts, scores, graph relationships, candidate money trails, and complaint
  correlations remain investigative leads only.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from importlib import import_module
from types import MappingProxyType
from typing import Any, Final, Optional

# -----------------------------------------------------------------------------
# Execution guard
# -----------------------------------------------------------------------------
# This package is intended to be imported as part of the backend application.
# Direct execution is not a supported entrypoint.
if __package__ in {None, ""}:
    raise RuntimeError(
        "Do not execute app/core/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Stable core metadata
# -----------------------------------------------------------------------------

CORE_PACKAGE_NAME: Final[str] = "muleguard.backend.core"
CORE_LAYER: Final[str] = "core"

APP_NAME: Final[str] = "MULEGUARD Backend"
API_PREFIX: Final[str] = "/api/v1"
API_VERSION: Final[str] = "v1"

DATA_CLASSIFICATION: Final[str] = "synthetic"
DEFAULT_TIMEZONE: Final[str] = "UTC"
DEFAULT_CURRENCY: Final[str] = "INR"
DEFAULT_LOCALE: Final[str] = "en"

SYNTHETIC_BANNER_TEXT: Final[str] = "SYNTHETIC DEMO DATA"

SAFETY_NOTICE: Final[str] = (
    "MULEGUARD is a synthetic-first investigative prototype. "
    "Alerts, risk scores, graph relationships, candidate money trails, and "
    "complaint correlations are investigative leads only. They are not proof "
    "of wrongdoing and must not trigger automatic adverse customer action."
)


# -----------------------------------------------------------------------------
# Core-layer safety flags
# -----------------------------------------------------------------------------
# These are declarative policy markers. Runtime enforcement must still exist in
# config validation, services, middleware, tests, and deployment controls.

_CORE_SAFETY_FLAGS_RAW: Final[dict[str, bool]] = {
    "synthetic_first_by_default": True,
    "no_real_customer_data_by_default": True,
    "no_secret_logging": True,
    "no_token_logging": True,
    "no_password_logging": True,
    "no_stack_trace_leakage": True,
    "no_fake_functionality": True,
    "no_automatic_adverse_action": True,
    "deny_by_default_authorization": True,
    "utc_timestamps_required": True,
    "decimal_monetary_values_required": True,
    "bounded_pagination_required": True,
    "bounded_graph_queries_required": True,
    "evidence_backed_outputs_required": True,
    "explainable_scores_required": True,
    "audit_material_actions_required": True,
}

CORE_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    _CORE_SAFETY_FLAGS_RAW
)


# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------

__all__: Final[tuple[str, ...]] = (
    "CORE_PACKAGE_NAME",
    "CORE_LAYER",
    "APP_NAME",
    "API_PREFIX",
    "API_VERSION",
    "DATA_CLASSIFICATION",
    "DEFAULT_TIMEZONE",
    "DEFAULT_CURRENCY",
    "DEFAULT_LOCALE",
    "SYNTHETIC_BANNER_TEXT",
    "SAFETY_NOTICE",
    "CORE_SAFETY_FLAGS",
    # Lazy submodules
    "config",
    "security",
    "logging",
    "roles",
    "permissions",
    "pagination",
    "errors",
    "rate_limit",
    "cache",
    "enums",
    "constants",
    # Lazy symbols
    "Settings",
    "get_settings",
    "configure_logging",
    "get_core_metadata",
)


# -----------------------------------------------------------------------------
# Lazy module and symbol access
# -----------------------------------------------------------------------------
# Keeps `import app.core` cheap and avoids circular-import pressure during
# package initialization.
#
# Supported patterns:
#
#   from app.core import config
#   from app.core import get_settings
#   from app.core import configure_logging
#
# Missing modules or symbols raise normal ImportError/AttributeError at the
# point of use rather than failing the entire package import.

_LAZY_MODULES: Final[dict[str, str]] = {
    "config": ".config",
    "security": ".security",
    "logging": ".logging",
    "roles": ".roles",
    "permissions": ".permissions",
    "pagination": ".pagination",
    "errors": ".errors",
    "rate_limit": ".rate_limit",
    "cache": ".cache",
    "enums": ".enums",
    "constants": ".constants",
}

_LAZY_ATTRS: Final[dict[str, tuple[str, str]]] = {
    "Settings": (".config", "Settings"),
    "get_settings": (".config", "get_settings"),
    "configure_logging": (".logging", "configure_logging"),
}

_MODULE_CACHE: dict[str, Any] = {}
_ATTR_CACHE: dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    """
    Lazily import core submodules or selected public symbols.
    """
    if name in _MODULE_CACHE:
        return _MODULE_CACHE[name]

    if name in _ATTR_CACHE:
        return _ATTR_CACHE[name]

    module_name = _LAZY_MODULES.get(name)

    if module_name is not None:
        module = import_module(module_name, __name__)
        _MODULE_CACHE[name] = module
        globals()[name] = module
        return module

    attr_spec = _LAZY_ATTRS.get(name)

    if attr_spec is not None:
        lazy_module_name, attr_name = attr_spec
        module = import_module(lazy_module_name, __name__)
        value = getattr(module, attr_name)
        _ATTR_CACHE[name] = value
        globals()[name] = value
        return value

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


def get_core_metadata() -> dict[str, Any]:
    """
    Return safe, serializable core-layer metadata.

    This is useful for:

    - startup logs;
    - diagnostic endpoints;
    - tests;
    - developer tooling;
    - architecture documentation checks.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, or real customer data.
    """
    return {
        "package": CORE_PACKAGE_NAME,
        "layer": CORE_LAYER,
        "app_name": APP_NAME,
        "api_prefix": API_PREFIX,
        "api_version": API_VERSION,
        "data_classification": DATA_CLASSIFICATION,
        "default_timezone": DEFAULT_TIMEZONE,
        "default_currency": DEFAULT_CURRENCY,
        "default_locale": DEFAULT_LOCALE,
        "synthetic_banner_text": SYNTHETIC_BANNER_TEXT,
        "safety_notice": SAFETY_NOTICE,
        "safety_flags": dict(CORE_SAFETY_FLAGS),
        "lazy_modules": tuple(sorted(_LAZY_MODULES)),
        "lazy_attributes": tuple(sorted(_LAZY_ATTRS)),
    }