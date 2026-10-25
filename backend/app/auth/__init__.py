"""
MULEGUARD backend authentication and authorization package.

This module is the public entry point for the MULEGUARD auth layer.

Its responsibilities are intentionally narrow:

- expose stable auth-layer constants and metadata;
- declare role, token, password-policy, and lockout conventions;
- declare auth-layer safety expectations;
- provide lazy access to auth submodules and selected public symbols;
- provide safe, dependency-light helpers for settings resolution, role
  normalization, password policy, and lockout policy;
- avoid eager imports of FastAPI, SQLAlchemy, Pydantic, JWT, Argon2, bcrypt,
  ML, graph, reporting, or audit dependencies during package initialization.

This package must not become a place where heavy runtime logic is executed at
import time.

Authentication and authorization boundaries:

- The backend is the security boundary. Frontend hiding is not sufficient.
- Authentication verifies local prototype users. Authorization enforces
  server-side role/permission checks through API dependencies and services.
- Inactive users must not authenticate.
- Locked users must not authenticate until the lock expires or is cleared.
- Passwords are stored only as salted hashes. Plaintext passwords are never
  stored, logged, returned, or reflected in error details.
- Failed authentication responses must not enable user enumeration by default.
- Auth metadata must not expose secrets, tokens, raw complaint narratives,
  database URLs, or real customer data.

Product-safety expectations for the auth layer:

- MULEGUARD is a synthetic-first academic / hackathon-grade prototype.
- Auth here protects local demo and test workflows. It is not a production
  identity provider and must not be exposed publicly without hardening.
- Authentication and authorization must never trigger automatic adverse
  customer action such as account freezing, payment blocking, or blacklisting.
- Alerts, scores, graph relationships, candidate money trails, entity links,
  and complaint correlations remain investigative leads only.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
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
        "Do not execute app/auth/__init__.py directly. "
        "Use the FastAPI application entrypoint, for example: "
        "uvicorn app.main:app"
    )

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Stable auth metadata
# -----------------------------------------------------------------------------

AUTH_PACKAGE_NAME: Final[str] = "muleguard.backend.auth"
AUTH_LAYER: Final[str] = "auth"
AUTH_VERSION: Final[str] = "v1"

AUTH_MODE: Final[str] = "jwt_bearer"
TOKEN_TYPE_ACCESS: Final[str] = "access"
TOKEN_TYPE_REFRESH: Final[str] = "refresh"

DEFAULT_ALGORITHM: Final[str] = "HS256"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES: Final[int] = 30
DEFAULT_CLOCK_SKEW_SECONDS: Final[int] = 30


# -----------------------------------------------------------------------------
# Role conventions
# -----------------------------------------------------------------------------
# Canonical role strings. The persistence layer may expose these as a UserRole
# enum. This package intentionally avoids importing app.models at init time to
# keep package import cheap and avoid circular-import pressure.

ROLE_ADMIN: Final[str] = "ADMIN"
ROLE_ANALYST: Final[str] = "ANALYST"
ROLE_SENIOR_INVESTIGATOR: Final[str] = "SENIOR_INVESTIGATOR"
ROLE_AUDITOR: Final[str] = "AUDITOR"

ALL_ROLES: Final[tuple[str, ...]] = (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_SENIOR_INVESTIGATOR,
    ROLE_AUDITOR,
)

READ_ROLES: Final[tuple[str, ...]] = ALL_ROLES

ANALYST_AND_ABOVE: Final[tuple[str, ...]] = (
    ROLE_ANALYST,
    ROLE_SENIOR_INVESTIGATOR,
    ROLE_ADMIN,
)

SENIOR_AND_ADMIN: Final[tuple[str, ...]] = (
    ROLE_SENIOR_INVESTIGATOR,
    ROLE_ADMIN,
)

ADMIN_ONLY: Final[tuple[str, ...]] = (
    ROLE_ADMIN,
)

AUDITOR_AND_ADMIN: Final[tuple[str, ...]] = (
    ROLE_AUDITOR,
    ROLE_ADMIN,
)

ROLE_DISPLAY_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        ROLE_ADMIN: "Administrator",
        ROLE_ANALYST: "Analyst",
        ROLE_SENIOR_INVESTIGATOR: "Senior Investigator",
        ROLE_AUDITOR: "Auditor",
    }
)


# -----------------------------------------------------------------------------
# Password policy defaults
# -----------------------------------------------------------------------------

DEFAULT_PASSWORD_HASH_SCHEME: Final[str] = "argon2id"
FALLBACK_PASSWORD_HASH_SCHEME: Final[str] = "bcrypt"
LAST_RESORT_PASSWORD_HASH_SCHEME: Final[str] = "pbkdf2_sha256"

DEFAULT_PASSWORD_MIN_LENGTH: Final[int] = 12
DEFAULT_PASSWORD_MAX_LENGTH: Final[int] = 128

DEFAULT_PASSWORD_POLICY: Final[Mapping[str, Any]] = MappingProxyType(
    {
        "min_length": DEFAULT_PASSWORD_MIN_LENGTH,
        "max_length": DEFAULT_PASSWORD_MAX_LENGTH,
        "require_lowercase": True,
        "require_uppercase": True,
        "require_digit": True,
        "require_special": True,
        "require_no_spaces": False,
        "reject_placeholder": True,
        "reject_user_identifier": True,
        "reject_repetitive": True,
    }
)


# -----------------------------------------------------------------------------
# Lockout / throttling defaults
# -----------------------------------------------------------------------------

DEFAULT_LOGIN_MAX_ATTEMPTS: Final[int] = 5
DEFAULT_LOGIN_LOCKOUT_MINUTES: Final[int] = 15
DEFAULT_LOGIN_ATTEMPT_WINDOW_MINUTES: Final[int] = 15

DEFAULT_LOCKOUT_POLICY: Final[Mapping[str, Any]] = MappingProxyType(
    {
        "max_attempts": DEFAULT_LOGIN_MAX_ATTEMPTS,
        "lockout_minutes": DEFAULT_LOGIN_LOCKOUT_MINUTES,
        "attempt_window_minutes": DEFAULT_LOGIN_ATTEMPT_WINDOW_MINUTES,
        "reset_on_success": True,
        "reveal_locked_account": False,
        "reveal_inactive_account": False,
    }
)


# -----------------------------------------------------------------------------
# Public / protected path conventions
# -----------------------------------------------------------------------------

LOGIN_PATH: Final[str] = f"/api/{AUTH_VERSION}/auth/login"
CURRENT_USER_PATH: Final[str] = f"/api/{AUTH_VERSION}/auth/me"
PASSWORD_CHANGE_PATH: Final[str] = f"/api/{AUTH_VERSION}/auth/password/change"

PUBLIC_AUTH_PATHS: Final[tuple[str, ...]] = (
    LOGIN_PATH,
)

PROTECTED_AUTH_PATHS: Final[tuple[str, ...]] = (
    CURRENT_USER_PATH,
    PASSWORD_CHANGE_PATH,
)


# -----------------------------------------------------------------------------
# Auth-layer safety flags
# -----------------------------------------------------------------------------
# These are declarative policy markers. Runtime enforcement must still exist in
# auth services, API dependencies, middleware, tests, and deployment controls.

_AUTH_SAFETY_FLAGS_RAW: Final[dict[str, bool]] = {
    "backend_is_security_boundary": True,
    "frontend_hiding_is_not_security_boundary": True,
    "server_side_authorization_required": True,
    "inactive_users_must_not_authenticate": True,
    "locked_users_must_not_authenticate": True,
    "passwords_stored_as_salted_hashes_only": True,
    "no_plaintext_password_storage": True,
    "no_plaintext_password_logging": True,
    "no_token_logging": True,
    "no_secret_logging": True,
    "failed_login_responses_are_generic_by_default": True,
    "login_throttling_required": True,
    "temporary_lockout_supported": True,
    "auth_actions_are_audited": True,
    "auth_does_not_take_adverse_customer_action": True,
    "auth_does_not_freeze_accounts": True,
    "auth_does_not_block_payments": True,
    "auth_does_not_blacklist": True,
    "auth_is_local_prototype_by_default": True,
    "auth_is_not_production_identity_provider": True,
    "no_real_customer_data_by_default": True,
    "no_fake_functionality": True,
}

AUTH_SAFETY_FLAGS: Final[Mapping[str, bool]] = MappingProxyType(
    _AUTH_SAFETY_FLAGS_RAW
)


# -----------------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------------

__all__: Final[tuple[str, ...]] = (
    "AUTH_PACKAGE_NAME",
    "AUTH_LAYER",
    "AUTH_VERSION",
    "AUTH_MODE",
    "TOKEN_TYPE_ACCESS",
    "TOKEN_TYPE_REFRESH",
    "DEFAULT_ALGORITHM",
    "DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES",
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "ROLE_ADMIN",
    "ROLE_ANALYST",
    "ROLE_SENIOR_INVESTIGATOR",
    "ROLE_AUDITOR",
    "ALL_ROLES",
    "READ_ROLES",
    "ANALYST_AND_ABOVE",
    "SENIOR_AND_ADMIN",
    "ADMIN_ONLY",
    "AUDITOR_AND_ADMIN",
    "ROLE_DISPLAY_NAMES",
    "DEFAULT_PASSWORD_HASH_SCHEME",
    "FALLBACK_PASSWORD_HASH_SCHEME",
    "LAST_RESORT_PASSWORD_HASH_SCHEME",
    "DEFAULT_PASSWORD_MIN_LENGTH",
    "DEFAULT_PASSWORD_MAX_LENGTH",
    "DEFAULT_PASSWORD_POLICY",
    "DEFAULT_LOGIN_MAX_ATTEMPTS",
    "DEFAULT_LOGIN_LOCKOUT_MINUTES",
    "DEFAULT_LOGIN_ATTEMPT_WINDOW_MINUTES",
    "DEFAULT_LOCKOUT_POLICY",
    "LOGIN_PATH",
    "CURRENT_USER_PATH",
    "PASSWORD_CHANGE_PATH",
    "PUBLIC_AUTH_PATHS",
    "PROTECTED_AUTH_PATHS",
    "AUTH_SAFETY_FLAGS",
    "normalize_role",
    "coerce_user_role",
    "resolve_allowed_roles",
    "is_auth_enabled",
    "is_production_like",
    "get_password_policy",
    "get_lockout_policy",
    "get_auth_metadata",
    # Lazy submodules
    "passwords",
    "tokens",
    "rbac",
    "throttling",
    "dev_users",
    "service",
)


# -----------------------------------------------------------------------------
# Lazy module access
# -----------------------------------------------------------------------------
# Keeps `import app.auth` cheap and avoids circular-import pressure during
# package initialization.
#
# Supported patterns:
#
#   from app.auth import passwords
#   from app.auth import tokens
#   from app.auth import rbac
#   from app.auth import service
#
# Missing modules raise normal ImportError/ModuleNotFoundError at the point of
# use rather than failing the entire package import.

_LAZY_MODULES: Final[dict[str, str]] = {
    "passwords": ".passwords",
    "tokens": ".tokens",
    "rbac": ".rbac",
    "throttling": ".throttling",
    "dev_users": ".dev_users",
    "service": ".service",
}

_MODULE_CACHE: dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    """
    Lazily import auth submodules by attribute access.
    """
    if name in _LAZY_MODULES:
        cached = _MODULE_CACHE.get(name)

        if cached is not None:
            return cached

        module = import_module(_LAZY_MODULES[name], __name__)
        _MODULE_CACHE[name] = module
        globals()[name] = module
        return module

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )


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
# Small runtime helpers
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}


def _read_setting(settings: Any, name: str, default: Any = None) -> Any:
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
# Role helpers
# -----------------------------------------------------------------------------


def normalize_role(value: Any) -> str:
    """
    Normalize a role-like value to an uppercase role string.

    Accepts enum members, strings, and None. Returns an empty string for None.
    """
    if value is None:
        return ""

    # Prefer enum .value when available without importing app.models.
    enum_value = getattr(value, "value", None)

    if enum_value is not None:
        return str(enum_value).strip().upper().replace(" ", "_").replace("-", "_")

    return str(value).strip().upper().replace(" ", "_").replace("-", "_")


def coerce_user_role(value: Any) -> Any:
    """
    Convert a role-like value to a UserRole enum member when possible.

    Falls back to ANALYST when the value cannot be coerced. This helper imports
    app.models lazily so that package import remains cheap.
    """
    try:
        from app.models import UserRole
    except Exception:
        # If models are unavailable, return the normalized string fallback.
        return normalize_role(value) or ROLE_ANALYST

    normalized = normalize_role(value)

    try:
        return UserRole(normalized)
    except ValueError:
        return UserRole.ANALYST


def resolve_allowed_roles(
    setting_name: str,
    default_roles: Sequence[str],
    settings: Any,
) -> frozenset[str]:
    """
    Resolve a normalized set of allowed roles from configuration or defaults.
    """
    raw = _read_setting(settings, setting_name, None)

    if raw is None:
        return frozenset(normalize_role(item) for item in default_roles if str(item).strip())

    return frozenset(normalize_role(item) for item in _csv(raw) if str(item).strip())


def role_allowed(
    setting_name: str,
    role: Any,
    default_roles: Sequence[str],
    settings: Any,
) -> bool:
    """
    Return True when a role is allowed by setting or default policy.
    """
    normalized_role = normalize_role(role)
    allowed = resolve_allowed_roles(setting_name, default_roles, settings)
    return normalized_role in allowed


def role_display_name(role: Any, settings: Any) -> str:
    """
    Return a safe display name for a role.
    """
    normalized = normalize_role(role)

    configured = _read_setting(settings, f"ROLE_{normalized}_DISPLAY_NAME", None)

    if configured:
        return str(configured).strip()

    return ROLE_DISPLAY_NAMES.get(normalized, normalized.replace("_", " ").title())


# -----------------------------------------------------------------------------
# Auth posture helpers
# -----------------------------------------------------------------------------


def is_auth_enabled(settings: Any) -> bool:
    """
    Return True when authentication is enabled.
    """
    return _as_bool(_read_setting(settings, "AUTH_ENABLED", True), True)


def auth_mode(settings: Any) -> str:
    """
    Return normalized authentication mode.
    """
    return str(
        _read_setting(settings, "AUTH_MODE", AUTH_MODE) or AUTH_MODE
    ).strip().lower()


def is_production_like(settings: Any) -> bool:
    """
    Return True when the runtime environment is production-like.
    """
    env = str(_read_setting(settings, "BACKEND_ENV", "local")).strip().lower()

    configured_values = _csv(
        _read_setting(
            settings,
            "BACKEND_PRODUCTION_LIKE_ENVS",
            "production,staging,prod,stage",
        )
    )

    production_like_values = {value.lower() for value in configured_values}

    if not production_like_values:
        production_like_values = {"production", "staging", "prod", "stage"}

    return env in production_like_values


def get_password_policy(settings: Any) -> dict[str, Any]:
    """
    Return effective password policy from configuration with safe defaults.
    """
    min_length = max(
        1,
        _as_int(
            _read_setting(settings, "AUTH_PASSWORD_MIN_LENGTH", DEFAULT_PASSWORD_MIN_LENGTH),
            DEFAULT_PASSWORD_MIN_LENGTH,
        ),
    )

    max_length = max(
        min_length,
        _as_int(
            _read_setting(settings, "AUTH_PASSWORD_MAX_LENGTH", DEFAULT_PASSWORD_MAX_LENGTH),
            DEFAULT_PASSWORD_MAX_LENGTH,
        ),
    )

    return {
        "hash_scheme": str(
            _read_setting(settings, "AUTH_PASSWORD_HASH_SCHEME", DEFAULT_PASSWORD_HASH_SCHEME)
            or DEFAULT_PASSWORD_HASH_SCHEME
        ),
        "min_length": min_length,
        "max_length": max_length,
        "require_lowercase": _as_bool(
            _read_setting(settings, "AUTH_PASSWORD_REQUIRE_LOWERCASE", True),
            True,
        ),
        "require_uppercase": _as_bool(
            _read_setting(settings, "AUTH_PASSWORD_REQUIRE_UPPERCASE", True),
            True,
        ),
        "require_digit": _as_bool(
            _read_setting(settings, "AUTH_PASSWORD_REQUIRE_DIGIT", True),
            True,
        ),
        "require_special": _as_bool(
            _read_setting(settings, "AUTH_PASSWORD_REQUIRE_SPECIAL", True),
            True,
        ),
        "require_no_spaces": _as_bool(
            _read_setting(settings, "AUTH_PASSWORD_REQUIRE_NO_SPACES", False),
            False,
        ),
        "reject_placeholder": True,
        "reject_user_identifier": True,
        "reject_repetitive": True,
    }


def get_lockout_policy(settings: Any) -> dict[str, Any]:
    """
    Return effective login lockout policy from configuration with safe defaults.
    """
    return {
        "max_attempts": max(
            1,
            _as_int(
                _read_setting(settings, "AUTH_LOGIN_MAX_ATTEMPTS", DEFAULT_LOGIN_MAX_ATTEMPTS),
                DEFAULT_LOGIN_MAX_ATTEMPTS,
            ),
        ),
        "lockout_minutes": max(
            0,
            _as_int(
                _read_setting(settings, "AUTH_LOGIN_LOCKOUT_MINUTES", DEFAULT_LOGIN_LOCKOUT_MINUTES),
                DEFAULT_LOGIN_LOCKOUT_MINUTES,
            ),
        ),
        "attempt_window_minutes": max(
            1,
            _as_int(
                _read_setting(
                    settings,
                    "AUTH_LOGIN_ATTEMPT_WINDOW_MINUTES",
                    DEFAULT_LOGIN_ATTEMPT_WINDOW_MINUTES,
                ),
                DEFAULT_LOGIN_ATTEMPT_WINDOW_MINUTES,
            ),
        ),
        "reset_on_success": _as_bool(
            _read_setting(settings, "AUTH_LOGIN_RESET_ON_SUCCESS", True),
            True,
        ),
        "reveal_locked_account": _as_bool(
            _read_setting(settings, "AUTH_REVEAL_LOCKED_ACCOUNT", False),
            False,
        ),
        "reveal_inactive_account": _as_bool(
            _read_setting(settings, "AUTH_REVEAL_INACTIVE_ACCOUNT", False),
            False,
        ),
    }


# -----------------------------------------------------------------------------
# Metadata helper
# -----------------------------------------------------------------------------


def get_auth_metadata() -> dict[str, Any]:
    """
    Return safe, serializable auth-layer metadata.

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
        "package": AUTH_PACKAGE_NAME,
        "layer": AUTH_LAYER,
        "version": AUTH_VERSION,
        "auth_mode": AUTH_MODE,
        "token_types": {
            "access": TOKEN_TYPE_ACCESS,
            "refresh": TOKEN_TYPE_REFRESH,
        },
        "default_algorithm": DEFAULT_ALGORITHM,
        "default_access_token_expire_minutes": DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES,
        "default_clock_skew_seconds": DEFAULT_CLOCK_SKEW_SECONDS,
        "roles": {
            "all": list(ALL_ROLES),
            "read": list(READ_ROLES),
            "analyst_and_above": list(ANALYST_AND_ABOVE),
            "senior_and_admin": list(SENIOR_AND_ADMIN),
            "admin_only": list(ADMIN_ONLY),
            "auditor_and_admin": list(AUDITOR_AND_ADMIN),
        },
        "role_display_names": dict(ROLE_DISPLAY_NAMES),
        "password_policy_defaults": dict(DEFAULT_PASSWORD_POLICY),
        "password_hash_schemes": {
            "default": DEFAULT_PASSWORD_HASH_SCHEME,
            "fallback": FALLBACK_PASSWORD_HASH_SCHEME,
            "last_resort": LAST_RESORT_PASSWORD_HASH_SCHEME,
        },
        "lockout_defaults": dict(DEFAULT_LOCKOUT_POLICY),
        "paths": {
            "login": LOGIN_PATH,
            "current_user": CURRENT_USER_PATH,
            "password_change": PASSWORD_CHANGE_PATH,
            "public": list(PUBLIC_AUTH_PATHS),
            "protected": list(PROTECTED_AUTH_PATHS),
        },
        "safety_flags": dict(AUTH_SAFETY_FLAGS),
        "lazy_modules": tuple(sorted(_LAZY_MODULES)),
    }