"""
MULEGUARD backend bootstrap orchestration.

This module provides a defensive, idempotent bootstrap helper for local
development, synthetic demo initialization, test environments, and controlled
container startup tasks.

Primary responsibilities:

- validate runtime configuration against MULEGUARD safety policy;
- block dangerous or prohibited feature flags;
- optionally create local/test database schema when explicitly permitted;
- optionally reset the synthetic demo database with destructive confirmation;
- seed local development users from environment-supplied passwords;
- invoke the synthetic demo data seeder when available;
- provide a CLI entrypoint for manual bootstrap operations;
- return structured, safe, JSON-serializable bootstrap results.

Important product-safety rules enforced here:

- MULEGUARD is synthetic-first by default.
- Real customer data is prohibited in bootstrap/demo modes.
- Automatic adverse customer action is prohibited.
- Unbounded whole-bank graph queries are prohibited.
- Ground-truth label leakage is prohibited.
- Future-information leakage in point-in-time features is prohibited.
- User-uploaded model deserialization is prohibited.
- Unsafe pickle/XML/YAML loading is prohibited.
- Production-like environments must not run demo seeding, development user
  seeding, destructive resets, or schema creation through this helper unless
  explicitly overridden by a separate approved deployment process.
- Bootstrap output must not contain passwords, tokens, secrets, database URLs,
  raw complaint narratives, or real customer data.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import logging
import secrets
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Final, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db import Base, engine, session_scope
from app.models import User, UserRole


logger = logging.getLogger("muleguard.backend.bootstrap")


# -----------------------------------------------------------------------------
# Constants and small helpers
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

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

_DEFAULT_RESET_CONFIRM_PHRASE: Final[str] = "RESET_SYNTHETIC_DEMO"

_DANGEROUS_TRUE_FLAGS: Final[tuple[tuple[str, str], ...]] = (
    ("AUTOMATIC_ENFORCEMENT_ENABLED", "Automatic enforcement is prohibited."),
    ("AUTO_FREEZE_ENABLED", "Automatic account freezing is prohibited."),
    ("AUTO_BLOCK_PAYMENT_ENABLED", "Automatic payment blocking is prohibited."),
    ("AUTO_BLACKLIST_ENABLED", "Automatic blacklisting is prohibited."),
    ("ADVERSE_ACTION_AUTOMATION_ENABLED", "Automated adverse customer action is prohibited."),
    ("DEANONYMISATION_ENABLED", "Deanonymisation capabilities are prohibited."),
    ("SURVEILLANCE_ENABLED", "Surveillance capabilities are prohibited."),
    ("COVERT_MONITORING_ENABLED", "Covert monitoring capabilities are prohibited."),
    ("USER_UPLOADED_MODEL_ENABLED", "User-uploaded model deserialization is prohibited."),
    ("PICKLE_UNSAFE_LOAD_ENABLED", "Unsafe pickle loading is prohibited."),
    ("XML_EXTERNAL_ENTITIES_ENABLED", "XML external entity processing is prohibited."),
    ("YAML_UNSAFE_LOAD_ENABLED", "Unsafe YAML loading is prohibited."),
    ("GRAPH_ALLOW_WHOLE_BANK_QUERY", "Unbounded whole-bank graph queries are prohibited."),
    ("FEATURE_ALLOW_LABELS_IN_EXPORT", "Exporting ground-truth labels into feature surfaces is prohibited."),
    ("FEATURE_ALLOW_FUTURE_TRANSACTIONS", "Using future transactions in point-in-time features is prohibited."),
    ("FEATURE_ALLOW_FUTURE_COMPLAINTS", "Using future complaints in point-in-time features is prohibited."),
    ("FEATURE_ALLOW_FUTURE_INVESTIGATION_OUTCOMES", "Using future investigation outcomes in point-in-time features is prohibited."),
    ("PRIVACY_REAL_DATA_PRESENT", "Real customer data is prohibited in synthetic bootstrap mode."),
    ("PRIVACY_CUSTOMER_DATA_PRESENT", "Real customer data is prohibited in synthetic bootstrap mode."),
    ("DATA_CUSTOMER_DATA_PRESENT", "Real customer data is prohibited in synthetic bootstrap mode."),
)

_UNSAFE_FALSE_FLAGS: Final[tuple[tuple[str, str], ...]] = (
    ("ML_DISABLE_UNTRUSTED_PICKLE_UPLOADS", "Untrusted pickle upload protection must remain enabled."),
    ("GRAPH_REQUIRE_ROOT", "Graph queries must require a root account or constrained source/destination."),
    ("FEATURE_STRICT_POINT_IN_TIME", "Strict point-in-time feature computation must remain enabled."),
    ("ML_LABEL_LEAKAGE_CHECK", "ML label leakage checks must remain enabled."),
    ("SEED_LEAKAGE_GUARD", "Synthetic seed leakage guard must remain enabled."),
)

_DEV_USER_SPECS: Final[tuple[tuple[str, UserRole, str, str, str, str, str, str], ...]] = (
    (
        "admin",
        UserRole.ADMIN,
        "DEV_ADMIN_USERNAME",
        "admin",
        "DEV_ADMIN_EMAIL",
        "admin@muleguard.local",
        "DEV_ADMIN_PASSWORD",
        "MULEGUARD Administrator",
    ),
    (
        "analyst",
        UserRole.ANALYST,
        "DEV_ANALYST_USERNAME",
        "analyst",
        "DEV_ANALYST_EMAIL",
        "analyst@muleguard.local",
        "DEV_ANALYST_PASSWORD",
        "MULEGUARD Analyst",
    ),
    (
        "senior_investigator",
        UserRole.SENIOR_INVESTIGATOR,
        "DEV_SENIOR_INVESTIGATOR_USERNAME",
        "senior_investigator",
        "DEV_SENIOR_INVESTIGATOR_EMAIL",
        "senior@muleguard.local",
        "DEV_SENIOR_INVESTIGATOR_PASSWORD",
        "MULEGUARD Senior Investigator",
    ),
    (
        "auditor",
        UserRole.AUDITOR,
        "DEV_AUDITOR_USERNAME",
        "auditor",
        "DEV_AUDITOR_EMAIL",
        "auditor@muleguard.local",
        "DEV_AUDITOR_PASSWORD",
        "MULEGUARD Auditor",
    ),
)


def _utcnow() -> datetime:
    """
    Return timezone-aware UTC current time.
    """
    return datetime.now(timezone.utc)


def _get_setting(settings: Any, name: str, default: Any = None) -> Any:
    """
    Read a setting from either a Pydantic settings object or mapping.
    """
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
        return float(value)  # type: ignore[arg-type]
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


def _contains_placeholder(value: str | None) -> bool:
    """
    Detect obvious template or placeholder secret values.

    This is intentionally conservative and is not a replacement for a full
    secret scanner.
    """
    if not value:
        return True

    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _is_production_like(settings: Any) -> bool:
    """
    Return True when the runtime environment is production-like.
    """
    env = str(_get_setting(settings, "BACKEND_ENV", "local")).strip().lower()

    configured_values = _csv(
        _get_setting(
            settings,
            "BACKEND_PRODUCTION_LIKE_ENVS",
            "production,staging,prod,stage",
        )
    )

    production_like_values = {value.lower() for value in configured_values}

    if not production_like_values:
        production_like_values = {"production", "staging", "prod", "stage"}

    return env in production_like_values


def _is_local(settings: Any) -> bool:
    """
    Return True when the runtime environment is explicitly local.
    """
    return str(_get_setting(settings, "BACKEND_ENV", "local")).strip().lower() == "local"


def _effective_bool(
    settings: Any,
    options: "BootstrapOptions",
    option_name: str,
    setting_name: str,
    default: bool = False,
) -> bool:
    """
    Resolve a boolean setting using CLI option override first, then environment.
    """
    option_value = getattr(options, option_name, None)

    if option_value is not None:
        return bool(option_value)

    return _as_bool(_get_setting(settings, setting_name, default), default)


def _effective_create_schema(settings: Any, options: "BootstrapOptions") -> bool:
    """
    Determine whether bootstrap should create database schema.

    Schema creation is allowed only for local/test use unless explicitly
    overridden by a separate approved deployment process.
    """
    if options.create_schema is not None:
        return bool(options.create_schema)

    if options.validate_only:
        return False

    if options.reset:
        return True

    seed_dev = _effective_bool(
        settings,
        options,
        "seed_dev_users",
        "SEED_DEV_USERS",
        False,
    )

    seed_demo = _effective_bool(
        settings,
        options,
        "seed_demo_data",
        "SEED_DEMO_DATA",
        False,
    )

    if seed_dev or seed_demo:
        return _as_bool(
            _get_setting(settings, "DB_CREATE_ALL_FOR_TESTS", True),
            True,
        )

    return False


def _is_mutating(settings: Any, options: "BootstrapOptions") -> bool:
    """
    Return True when bootstrap would perform any write operation.
    """
    if options.validate_only:
        return False

    return bool(
        options.reset
        or _effective_create_schema(settings, options)
        or _effective_bool(settings, options, "seed_dev_users", "SEED_DEV_USERS", False)
        or _effective_bool(settings, options, "seed_demo_data", "SEED_DEMO_DATA", False)
    )


# -----------------------------------------------------------------------------
# Bootstrap result model
# -----------------------------------------------------------------------------


class StepStatus(str, Enum):
    """
    Status for an individual bootstrap step.
    """

    OK = "ok"
    SKIPPED = "skipped"
    DEGRADED = "degraded"
    FAILED = "failed"


class BootstrapAction(str, Enum):
    """
    Named bootstrap actions.
    """

    VALIDATE = "validate"
    CREATE_SCHEMA = "create_schema"
    RESET_DATABASE = "reset_database"
    SEED_REFERENCE_DATA = "seed_reference_data"
    ENSURE_DEV_USERS = "ensure_dev_users"
    SEED_DEMO_DATA = "seed_demo_data"
    DATABASE_SESSION = "database_session"


@dataclass(slots=True)
class BootstrapStep:
    """
    Safe, structured result from a bootstrap step.
    """

    action: BootstrapAction
    status: StepStatus
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    fatal: bool = False


@dataclass(slots=True)
class BootstrapOptions:
    """
    CLI/runtime options for bootstrap execution.
    """

    dry_run: bool = False
    reset: bool = False
    confirm: Optional[str] = None
    create_schema: Optional[bool] = None
    seed_dev_users: Optional[bool] = None
    seed_demo_data: Optional[bool] = None
    validate_only: bool = False


@dataclass(slots=True)
class BootstrapResult:
    """
    Aggregate bootstrap result.
    """

    started_at: datetime
    dry_run: bool = False
    finished_at: Optional[datetime] = None
    steps: list[BootstrapStep] = field(default_factory=list)

    def add(
        self,
        action: BootstrapAction,
        status: StepStatus,
        message: str,
        *,
        details: Optional[dict[str, Any]] = None,
        fatal: bool = False,
    ) -> BootstrapStep:
        """
        Append a step result and return it.
        """
        step = BootstrapStep(
            action=action,
            status=status,
            message=message,
            details=details or {},
            fatal=fatal,
        )

        self.steps.append(step)
        return step

    @property
    def ok(self) -> bool:
        """
        Return True when no failed step occurred.
        """
        return not any(step.status == StepStatus.FAILED for step in self.steps)

    @property
    def has_fatal(self) -> bool:
        """
        Return True when any step is explicitly fatal.
        """
        return any(step.fatal for step in self.steps)

    def summary_counts(self) -> dict[str, int]:
        """
        Return counts by step status.
        """
        counts = {status.value: 0 for status in StepStatus}

        for step in self.steps:
            counts[step.status.value] += 1

        return counts

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable safe result payload.
        """
        return {
            "ok": self.ok,
            "dry_run": self.dry_run,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "summary": self.summary_counts(),
            "steps": [
                {
                    "action": step.action.value,
                    "status": step.status.value,
                    "message": step.message,
                    "fatal": step.fatal,
                    "details": step.details,
                }
                for step in self.steps
            ],
        }


# -----------------------------------------------------------------------------
# Password hashing helpers
# -----------------------------------------------------------------------------


def _hash_password(password: str, settings: Any) -> str:
    """
    Hash a development password using the strongest available local scheme.

    Preference order:

    1. app.auth.passwords.hash_password, if implemented;
    2. Argon2id via argon2-cffi;
    3. PBKDF2-HMAC-SHA256 fallback for minimal local environments.

    The fallback is intended only for local synthetic development bootstrapping.
    Production authentication must use a maintained, reviewed password hashing
    service.
    """
    try:
        auth_passwords = importlib.import_module("app.auth.passwords")
        hash_fn = getattr(auth_passwords, "hash_password", None)

        if callable(hash_fn):
            return str(hash_fn(password))

    except Exception:
        logger.debug("app.auth.passwords.hash_password unavailable; using local fallback hashing.")

    try:
        from argon2 import PasswordHasher

        time_cost = max(1, _as_int(_get_setting(settings, "AUTH_ARGON2_TIME_COST", 3), 3))
        memory_cost = max(
            1,
            _as_int(_get_setting(settings, "AUTH_ARGON2_MEMORY_COST_KIB", 65536), 65536),
        )
        parallelism = max(
            1,
            _as_int(_get_setting(settings, "AUTH_ARGON2_PARALLELISM", 2), 2),
        )

        hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
        )

        return str(hasher.hash(password))

    except Exception:
        logger.debug("Argon2 password hashing unavailable; using PBKDF2 fallback.")

    iterations = max(
        10_000,
        _as_int(_get_setting(settings, "AUTH_PBKDF2_ITERATIONS", 390_000), 390_000),
    )

    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"


def _validate_dev_password_policy(
    password: str,
    settings: Any,
    username: str,
) -> list[str]:
    """
    Return password policy violations for a development user.

    This is intentionally stricter than a casual demo default. Development
    passwords supplied through environment variables should still meet the
    configured policy.
    """
    errors: list[str] = []

    min_length = max(
        1,
        _as_int(
            _get_setting(
                settings,
                "DEV_USERS_PASSWORD_MIN_LENGTH",
                _get_setting(settings, "AUTH_PASSWORD_MIN_LENGTH", 12),
            ),
            12,
        ),
    )

    max_length = max(
        min_length,
        _as_int(_get_setting(settings, "AUTH_PASSWORD_MAX_LENGTH", 128), 128),
    )

    if len(password) < min_length:
        errors.append(f"password_for_{username}_too_short")

    if len(password) > max_length:
        errors.append(f"password_for_{username}_too_long")

    if _contains_placeholder(password):
        errors.append(f"password_for_{username}_is_placeholder")

    require_lower = _as_bool(_get_setting(settings, "AUTH_PASSWORD_REQUIRE_LOWERCASE", True), True)
    require_upper = _as_bool(_get_setting(settings, "AUTH_PASSWORD_REQUIRE_UPPERCASE", True), True)
    require_digit = _as_bool(_get_setting(settings, "AUTH_PASSWORD_REQUIRE_DIGIT", True), True)
    require_special = _as_bool(_get_setting(settings, "AUTH_PASSWORD_REQUIRE_SPECIAL", True), True)

    if require_lower and not any(character.islower() for character in password):
        errors.append(f"password_for_{username}_missing_lowercase")

    if require_upper and not any(character.isupper() for character in password):
        errors.append(f"password_for_{username}_missing_uppercase")

    if require_digit and not any(character.isdigit() for character in password):
        errors.append(f"password_for_{username}_missing_digit")

    if require_special and not any(not character.isalnum() for character in password):
        errors.append(f"password_for_{username}_missing_special")

    return errors


def _validate_dev_email_domain(email: str, settings: Any, username: str) -> list[str]:
    """
    Ensure development user emails use allowed synthetic local domains.
    """
    errors: list[str] = []

    allowlist_raw = _csv(
        _get_setting(settings, "DEV_USERS_EMAIL_DOMAIN_ALLOWLIST", "muleguard.local")
    )

    if not allowlist_raw:
        return errors

    allowlist = {domain.strip().lower() for domain in allowlist_raw if domain.strip()}

    if not allowlist:
        return errors

    if "@" not in email:
        errors.append(f"email_for_{username}_invalid")
        return errors

    domain = email.rsplit("@", 1)[-1].strip().lower()

    if domain not in allowlist:
        errors.append(f"email_for_{username}_domain_not_allowed")

    return errors


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------


def _validate_settings(
    settings: Any,
    options: BootstrapOptions,
) -> list[BootstrapStep]:
    """
    Validate runtime settings and bootstrap options against MULEGUARD policy.

    Returns a list of safe bootstrap steps. Fatal steps should prevent mutation.
    """
    steps: list[BootstrapStep] = []

    production_like = _is_production_like(settings)
    mutating = _is_mutating(settings, options)

    seed_dev_users = _effective_bool(
        settings,
        options,
        "seed_dev_users",
        "SEED_DEV_USERS",
        False,
    )

    seed_demo_data = _effective_bool(
        settings,
        options,
        "seed_demo_data",
        "SEED_DEMO_DATA",
        False,
    )

    create_schema = _effective_create_schema(settings, options)

    def add_failure(message: str, *, code: str | None = None) -> None:
        details: dict[str, Any] = {}

        if code:
            details["code"] = code

        steps.append(
            BootstrapStep(
                action=BootstrapAction.VALIDATE,
                status=StepStatus.FAILED,
                message=message,
                details=details,
                fatal=True,
            )
        )

    def add_warning(message: str, *, code: str | None = None) -> None:
        details: dict[str, Any] = {}

        if code:
            details["code"] = code

        steps.append(
            BootstrapStep(
                action=BootstrapAction.VALIDATE,
                status=StepStatus.DEGRADED,
                message=message,
                details=details,
                fatal=False,
            )
        )

    # ---------------------------------------------------------------------
    # Production-like mutation blocks
    # ---------------------------------------------------------------------
    if production_like and mutating:
        add_failure(
            "Bootstrap mutation is not allowed in production-like environments.",
            code="BOOTSTRAP_MUTATION_IN_PRODUCTION",
        )

    if production_like and seed_dev_users:
        add_failure(
            "SEED_DEV_USERS=true is not allowed in production-like environments.",
            code="DEV_USERS_ENABLED_IN_PRODUCTION",
        )

    if production_like and seed_demo_data:
        add_failure(
            "SEED_DEMO_DATA=true is not allowed in production-like environments.",
            code="DEMO_SEEDING_ENABLED_IN_PRODUCTION",
        )

    if production_like and create_schema:
        allow_create_all = _as_bool(
            _get_setting(settings, "DB_CREATE_ALL_IN_PRODUCTION", False),
            False,
        )

        if not allow_create_all:
            add_failure(
                "Schema creation through bootstrap is not allowed in production-like environments. Use Alembic migrations.",
                code="CREATE_ALL_IN_PRODUCTION",
            )

    if production_like and options.reset:
        add_failure(
            "Destructive bootstrap reset is not allowed in production-like environments.",
            code="RESET_IN_PRODUCTION",
        )

    # ---------------------------------------------------------------------
    # Secret strength validation
    # ---------------------------------------------------------------------
    env = str(_get_setting(settings, "BACKEND_ENV", "local")).strip().lower()
    secret_key = str(_get_setting(settings, "BACKEND_SECRET_KEY", "") or "")

    if env != "local" and _as_bool(
        _get_setting(settings, "BACKEND_REQUIRE_STRONG_SECRET_IN_NON_LOCAL", True),
        True,
    ):
        if _contains_placeholder(secret_key):
            add_failure(
                "BACKEND_SECRET_KEY must be set to a strong non-placeholder value in non-local environments.",
                code="PLACEHOLDER_SECRET_KEY",
            )

    if env == "local" and _contains_placeholder(secret_key):
        add_warning(
            "BACKEND_SECRET_KEY is missing or uses a placeholder value. This is allowed only for local synthetic development.",
            code="LOCAL_PLACEHOLDER_SECRET_KEY",
        )

    # ---------------------------------------------------------------------
    # Synthetic-first dataset mode checks
    # ---------------------------------------------------------------------
    dataset_mode = str(
        _get_setting(settings, "BACKEND_DATASET_MODE", "synthetic")
    ).strip().lower()

    if dataset_mode != "synthetic" and mutating:
        if production_like:
            add_failure(
                "BACKEND_DATASET_MODE must be 'synthetic' for bootstrap mutation in production-like environments.",
                code="NON_SYNTHETIC_DATASET_MODE",
            )
        else:
            add_warning(
                "BACKEND_DATASET_MODE is not 'synthetic'. MULEGUARD is synthetic-first by default.",
                code="NON_SYNTHETIC_DATASET_MODE_LOCAL",
            )

    # ---------------------------------------------------------------------
    # Hard product-policy prohibitions
    # ---------------------------------------------------------------------
    for flag_name, message in _DANGEROUS_TRUE_FLAGS:
        if _as_bool(_get_setting(settings, flag_name, False), False):
            add_failure(
                f"{flag_name}=true violates MULEGUARD safety policy. {message}",
                code=f"POLICY_FLAG_{flag_name}",
            )

    for flag_name, message in _UNSAFE_FALSE_FLAGS:
        if not _as_bool(_get_setting(settings, flag_name, True), True):
            add_failure(
                f"{flag_name}=false violates MULEGUARD safety policy. {message}",
                code=f"POLICY_FLAG_FALSE_{flag_name}",
            )

    # ---------------------------------------------------------------------
    # Destructive reset validation
    # ---------------------------------------------------------------------
    if options.reset:
        require_confirmation = _as_bool(
            _get_setting(settings, "SEED_RESET_REQUIRES_CONFIRM_PHRASE", True),
            True,
        )

        confirm_phrase = str(
            _get_setting(settings, "DB_RESET_CONFIRM_PHRASE", _DEFAULT_RESET_CONFIRM_PHRASE)
        ).strip()

        allow_demo_only = _as_bool(
            _get_setting(settings, "SEED_RESET_ALLOW_DEMO_ONLY", True),
            True,
        )

        block_production = _as_bool(
            _get_setting(settings, "SEED_RESET_BLOCK_PRODUCTION", True),
            True,
        )

        if block_production and production_like:
            add_failure(
                "Destructive reset is blocked in production-like environments.",
                code="RESET_BLOCKED_PRODUCTION",
            )

        if allow_demo_only and not _is_local(settings):
            add_failure(
                "Destructive reset is allowed only in BACKEND_ENV=local unless explicitly overridden.",
                code="RESET_NOT_LOCAL",
            )

        if require_confirmation and options.confirm != confirm_phrase:
            add_failure(
                "Destructive reset requires the configured confirmation phrase.",
                code="RESET_CONFIRMATION_MISSING",
            )

    # ---------------------------------------------------------------------
    # Local/demo warnings
    # ---------------------------------------------------------------------
    if _is_local(settings):
        if seed_dev_users or seed_demo_data:
            add_warning(
                "Local synthetic/demo bootstrap is enabled. Do not expose this instance publicly without hardening authentication, TLS, rate limits, audit retention, and deployment controls.",
                code="LOCAL_DEMO_BOOTSTRAP_ENABLED",
            )

        if not _as_bool(_get_setting(settings, "BACKEND_SAFE_MODE", True), True):
            add_warning(
                "BACKEND_SAFE_MODE=false weakens default safety behaviour.",
                code="SAFE_MODE_DISABLED",
            )

    if not any(step.status == StepStatus.FAILED for step in steps):
        steps.append(
            BootstrapStep(
                action=BootstrapAction.VALIDATE,
                status=StepStatus.OK,
                message="Bootstrap configuration passed MULEGUARD safety validation.",
                details={
                    "environment": env,
                    "production_like": production_like,
                    "mutating": mutating,
                    "dry_run": options.dry_run,
                    "validate_only": options.validate_only,
                    "reset": options.reset,
                    "create_schema": create_schema,
                    "seed_dev_users": seed_dev_users,
                    "seed_demo_data": seed_demo_data,
                },
                fatal=False,
            )
        )

    return steps


# -----------------------------------------------------------------------------
# Schema and reset helpers
# -----------------------------------------------------------------------------


def _ensure_schema(
    settings: Any,
    options: BootstrapOptions,
    result: BootstrapResult,
) -> None:
    """
    Create database schema from SQLAlchemy metadata for local/test use.

    This is not the deployed schema-management path. Alembic migrations remain
    the production and staging schema-management mechanism.
    """
    create_schema = _effective_create_schema(settings, options)

    if not create_schema:
        result.add(
            BootstrapAction.CREATE_SCHEMA,
            StepStatus.SKIPPED,
            "Schema creation not requested.",
        )
        return

    if options.dry_run:
        result.add(
            BootstrapAction.CREATE_SCHEMA,
            StepStatus.SKIPPED,
            "Dry run: schema creation planned.",
            details={"table_count": len(Base.metadata.tables)},
        )
        return

    if _is_production_like(settings) and not _as_bool(
        _get_setting(settings, "DB_CREATE_ALL_IN_PRODUCTION", False),
        False,
    ):
        result.add(
            BootstrapAction.CREATE_SCHEMA,
            StepStatus.FAILED,
            "Schema creation through bootstrap is not allowed in production-like environments.",
            fatal=True,
        )
        return

    try:
        Base.metadata.create_all(bind=engine)

        result.add(
            BootstrapAction.CREATE_SCHEMA,
            StepStatus.OK,
            "Local/test database schema created from SQLAlchemy metadata.",
            details={
                "table_count": len(Base.metadata.tables),
                "warning": "This path is intended for local/test use, not production migrations.",
            },
        )

    except SQLAlchemyError as exc:
        logger.exception("Bootstrap schema creation failed.")

        result.add(
            BootstrapAction.CREATE_SCHEMA,
            StepStatus.FAILED,
            "Database schema creation failed.",
            details={"error_type": type(exc).__name__},
            fatal=True,
        )

    except Exception as exc:
        logger.exception("Unexpected bootstrap schema creation failure.")

        result.add(
            BootstrapAction.CREATE_SCHEMA,
            StepStatus.FAILED,
            "Unexpected database schema creation failure.",
            details={"error_type": type(exc).__name__},
            fatal=True,
        )


def _reset_database(
    settings: Any,
    options: BootstrapOptions,
    result: BootstrapResult,
) -> None:
    """
    Destructively reset the local synthetic demo database.

    This drops and recreates all tables from SQLAlchemy metadata. It is intended
    only for local synthetic demo environments and requires explicit confirmation
    when configured.
    """
    if not options.reset:
        result.add(
            BootstrapAction.RESET_DATABASE,
            StepStatus.SKIPPED,
            "Database reset not requested.",
        )
        return

    if options.dry_run:
        result.add(
            BootstrapAction.RESET_DATABASE,
            StepStatus.SKIPPED,
            "Dry run: destructive database reset planned.",
            details={"destructive": True},
        )
        return

    if _is_production_like(settings):
        result.add(
            BootstrapAction.RESET_DATABASE,
            StepStatus.FAILED,
            "Destructive reset is not allowed in production-like environments.",
            fatal=True,
        )
        return

    if _as_bool(_get_setting(settings, "SEED_RESET_ALLOW_DEMO_ONLY", True), True) and not _is_local(settings):
        result.add(
            BootstrapAction.RESET_DATABASE,
            StepStatus.FAILED,
            "Destructive reset is allowed only in local synthetic demo environments.",
            fatal=True,
        )
        return

    require_confirmation = _as_bool(
        _get_setting(settings, "SEED_RESET_REQUIRES_CONFIRM_PHRASE", True),
        True,
    )

    confirm_phrase = str(
        _get_setting(settings, "DB_RESET_CONFIRM_PHRASE", _DEFAULT_RESET_CONFIRM_PHRASE)
    ).strip()

    if require_confirmation and options.confirm != confirm_phrase:
        result.add(
            BootstrapAction.RESET_DATABASE,
            StepStatus.FAILED,
            "Destructive reset requires the configured confirmation phrase.",
            details={"confirmation_required": True},
            fatal=True,
        )
        return

    try:
        logger.warning("Performing destructive synthetic demo database reset.")

        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)

        result.add(
            BootstrapAction.RESET_DATABASE,
            StepStatus.OK,
            "Local synthetic demo database reset completed.",
            details={
                "destructive": True,
                "table_count": len(Base.metadata.tables),
            },
        )

    except SQLAlchemyError as exc:
        logger.exception("Bootstrap database reset failed.")

        result.add(
            BootstrapAction.RESET_DATABASE,
            StepStatus.FAILED,
            "Database reset failed.",
            details={"error_type": type(exc).__name__},
            fatal=True,
        )

    except Exception as exc:
        logger.exception("Unexpected bootstrap database reset failure.")

        result.add(
            BootstrapAction.RESET_DATABASE,
            StepStatus.FAILED,
            "Unexpected database reset failure.",
            details={"error_type": type(exc).__name__},
            fatal=True,
        )


# -----------------------------------------------------------------------------
# Reference data
# -----------------------------------------------------------------------------


def _seed_reference_data(
    db: Session,
    settings: Any,
    options: BootstrapOptions,
    result: BootstrapStep | BootstrapResult,
) -> None:
    """
    Seed immutable reference data when required.

    In the current MULEGUARD design, primary reference data such as roles is
    represented by application enums and optional Alembic migration 0002. This
    hook exists for future idempotent reference rows and for explicit bootstrap
    reporting.
    """
    if isinstance(result, BootstrapResult):
        target_result = result
    else:
        target_result = BootstrapResult(started_at=_utcnow())
        target_result.steps.append(result)

    if options.dry_run:
        target_result.add(
            BootstrapAction.SEED_REFERENCE_DATA,
            StepStatus.SKIPPED,
            "Dry run: reference data bootstrap planned.",
        )
        return

    target_result.add(
        BootstrapAction.SEED_REFERENCE_DATA,
        StepStatus.OK,
        "Reference data bootstrap completed. Role/reference semantics are provided by application enums and Alembic migration 0002 where enabled.",
        details={
            "alembic_seed_reference_data": _as_bool(
                _get_setting(settings, "ALEMBIC_SEED_REFERENCE_DATA", True),
                True,
            ),
        },
    )


# -----------------------------------------------------------------------------
# Development user seeding
# -----------------------------------------------------------------------------


def _ensure_dev_users(
    db: Session,
    settings: Any,
    options: BootstrapOptions,
    result: BootstrapResult,
) -> None:
    """
    Create or update local development users from environment configuration.

    Rules:

    - Disabled unless SEED_DEV_USERS=true or CLI override.
    - Blocked in production-like environments.
    - Passwords must be supplied through environment variables.
    - Placeholder passwords are rejected.
    - Password policy is enforced.
    - Emails must use allowed synthetic local domains when configured.
    - No passwords are logged or returned in result details.
    """
    seed_dev_users = _effective_bool(
        settings,
        options,
        "seed_dev_users",
        "SEED_DEV_USERS",
        False,
    )

    if not seed_dev_users:
        result.add(
            BootstrapAction.ENSURE_DEV_USERS,
            StepStatus.SKIPPED,
            "Development user seeding disabled.",
        )
        return

    if _is_production_like(settings):
        result.add(
            BootstrapAction.ENSURE_DEV_USERS,
            StepStatus.FAILED,
            "Development user seeding is not allowed in production-like environments.",
            fatal=True,
        )
        return

    if options.dry_run:
        result.add(
            BootstrapAction.ENSURE_DEV_USERS,
            StepStatus.SKIPPED,
            "Dry run: development user seeding planned.",
            details={
                "usernames": [spec[3] for spec in _DEV_USER_SPECS],
            },
        )
        return

    require_password_from_env = _as_bool(
        _get_setting(settings, "DEV_USERS_REQUIRE_PASSWORD_FROM_ENV", True),
        True,
    )

    force_password_reset = _as_bool(
        _get_setting(settings, "DEV_USERS_FORCE_PASSWORD_RESET", False),
        False,
    ) or _as_bool(
        _get_setting(settings, "DEV_USERS_REQUIRE_PASSWORD_CHANGE", False),
        False,
    )

    created: list[str] = []
    updated: list[str] = []
    skipped: list[str] = []
    conflicts: list[dict[str, str]] = []
    policy_errors: list[str] = []

    for (
        key,
        role,
        username_env,
        default_username,
        email_env,
        default_email,
        password_env,
        full_name,
    ) in _DEV_USER_SPECS:
        username = str(_get_setting(settings, username_env, default_username) or default_username).strip()
        email = str(_get_setting(settings, email_env, default_email) or default_email).strip().lower()
        password = str(_get_setting(settings, password_env, "") or "").strip()

        if not username:
            policy_errors.append(f"missing_username_for_{key}")
            continue

        if not email:
            policy_errors.append(f"missing_email_for_{username}")
            continue

        if not password:
            if require_password_from_env:
                policy_errors.append(f"missing_password_for_{username}")
            else:
                skipped.append(username)
            continue

        errors = _validate_dev_password_policy(password, settings, username)
        errors.extend(_validate_dev_email_domain(email, settings, username))

        if errors:
            policy_errors.extend(errors)
            continue

        password_hash = _hash_password(password, settings)

        existing_by_username: Optional[User] = db.scalar(
            select(User).where(User.username == username)
        )

        existing_by_email: Optional[User] = db.scalar(
            select(User).where(User.email == email)
        )

        if existing_by_email is not None and existing_by_username is not None:
            if existing_by_email.id != existing_by_username.id:
                conflicts.append(
                    {
                        "username": username,
                        "email": email,
                        "reason": "email_belongs_to_different_user",
                    }
                )
                continue

        if existing_by_email is not None and existing_by_username is None:
            conflicts.append(
                {
                    "username": username,
                    "email": email,
                    "reason": "email_belongs_to_existing_user",
                }
            )
            continue

        if existing_by_username is not None:
            existing_by_username.role = role
            existing_by_username.is_active = True
            existing_by_username.password_hash = password_hash
            existing_by_username.must_change_password = force_password_reset

            if existing_by_username.full_name != full_name:
                existing_by_username.full_name = full_name

            if existing_by_username.email != email:
                existing_by_username.email = email

            updated.append(username)
            continue

        stable_id = f"dev-{username}"

        existing_by_id: Optional[User] = db.get(User, stable_id)

        if existing_by_id is not None and existing_by_id.username != username:
            conflicts.append(
                {
                    "username": username,
                    "id": stable_id,
                    "reason": "stable_id_conflict",
                }
            )
            continue

        user = User(
            id=stable_id,
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            password_hash=password_hash,
            is_active=True,
            must_change_password=force_password_reset,
            failed_login_count=0,
        )

        db.add(user)
        created.append(username)

    try:
        db.flush()
    except SQLAlchemyError as exc:
        logger.exception("Development user flush failed.")

        result.add(
            BootstrapAction.ENSURE_DEV_USERS,
            StepStatus.FAILED,
            "Development user seeding failed during database flush.",
            details={
                "error_type": type(exc).__name__,
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "conflicts": conflicts,
                "policy_errors": policy_errors,
            },
            fatal=True,
        )
        return

    status = StepStatus.OK

    if policy_errors or conflicts:
        status = StepStatus.FAILED if policy_errors or conflicts else StepStatus.DEGRADED

    result.add(
        BootstrapAction.ENSURE_DEV_USERS,
        status,
        "Development user seeding completed."
        if status == StepStatus.OK
        else "Development user seeding completed with errors.",
        details={
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "conflicts": conflicts,
            "policy_errors": policy_errors,
            "force_password_reset": force_password_reset,
        },
        fatal=status == StepStatus.FAILED,
    )


# -----------------------------------------------------------------------------
# Synthetic demo data seeding
# -----------------------------------------------------------------------------


def _call_seed_module_callable(
    fn: Any,
    db: Session,
    settings: Any,
) -> tuple[StepStatus, str, dict[str, Any]]:
    """
    Invoke a supported seeding callable from app.ingestion.seed.

    Supports common signatures:

    - seed_all(db, settings)
    - seed_demo_data(db)
    - run(settings)
    - main()
    - main(argv=[])
    """
    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):
        signature = None

    kwargs: dict[str, Any] = {}

    if signature is not None:
        parameters = signature.parameters

        for parameter_name, parameter in parameters.items():
            if parameter_name in {"db", "session"}:
                kwargs[parameter_name] = db
            elif parameter_name in {"settings", "config"}:
                kwargs[parameter_name] = settings
            elif parameter.default is inspect.Parameter.empty:
                if parameter_name in {"argv", "args"}:
                    kwargs[parameter_name] = []
                else:
                    kwargs = {}
                    break

    try:
        outcome = fn(**kwargs)
    except TypeError:
        try:
            outcome = fn()
        except TypeError:
            return (
                StepStatus.DEGRADED,
                "Seed callable signature was not compatible with bootstrap invocation.",
                {},
            )

    if inspect.isawaitable(outcome):
        return (
            StepStatus.DEGRADED,
            "Seed callable returned an awaitable. Bootstrap is synchronous; run async seeding separately.",
            {},
        )

    details: dict[str, Any] = {}

    if isinstance(outcome, Mapping):
        details = {
            str(key): value
            for key, value in list(outcome.items())[:50]
        }

    return (StepStatus.OK, "Synthetic demo data seeding invoked successfully.", details)


def _seed_demo_data(
    db: Session,
    settings: Any,
    options: BootstrapOptions,
    result: BootstrapResult,
) -> None:
    """
    Invoke the synthetic demo data seeder when available.

    This helper does not reimplement the generator. It delegates to
    app.ingestion.seed and reports safe status.
    """
    seed_demo_data = _effective_bool(
        settings,
        options,
        "seed_demo_data",
        "SEED_DEMO_DATA",
        False,
    )

    if not seed_demo_data:
        result.add(
            BootstrapAction.SEED_DEMO_DATA,
            StepStatus.SKIPPED,
            "Synthetic demo data seeding disabled.",
        )
        return

    if _is_production_like(settings):
        result.add(
            BootstrapAction.SEED_DEMO_DATA,
            StepStatus.FAILED,
            "Synthetic demo data seeding is not allowed in production-like environments.",
            fatal=True,
        )
        return

    if options.dry_run:
        result.add(
            BootstrapAction.SEED_DEMO_DATA,
            StepStatus.SKIPPED,
            "Dry run: synthetic demo data seeding planned.",
            details={
                "seed": _get_setting(settings, "SEED_RANDOM_SEED", 42),
                "accounts": _get_setting(settings, "SEED_ACCOUNTS", 1200),
                "transactions": _get_setting(settings, "SEED_TRANSACTIONS", 25000),
                "complaints": _get_setting(settings, "SEED_COMPLAINTS", 150),
            },
        )
        return

    try:
        seed_module = importlib.import_module("app.ingestion.seed")
    except ImportError as exc:
        result.add(
            BootstrapAction.SEED_DEMO_DATA,
            StepStatus.DEGRADED,
            "app.ingestion.seed module not found; synthetic demo seeding skipped.",
            details={
                "error_type": type(exc).__name__,
                "expected_module": "app.ingestion.seed",
            },
            fatal=False,
        )
        return

    candidate_names = (
        "seed_all",
        "seed_demo_data",
        "seed",
        "run",
        "main",
    )

    last_message = "No supported seeding callable was found in app.ingestion.seed."
    last_details: dict[str, Any] = {"candidate_names": list(candidate_names)}

    for candidate_name in candidate_names:
        candidate = getattr(seed_module, candidate_name, None)

        if not callable(candidate):
            continue

        status, message, details = _call_seed_module_callable(candidate, db, settings)

        if status == StepStatus.OK:
            details.setdefault("callable", candidate_name)
            result.add(
                BootstrapAction.SEED_DEMO_DATA,
                status,
                message,
                details=details,
            )
            return

        last_message = message
        last_details = details
        last_details.setdefault("callable", candidate_name)

    result.add(
        BootstrapAction.SEED_DEMO_DATA,
        StepStatus.DEGRADED,
        last_message,
        details=last_details,
        fatal=False,
    )


# -----------------------------------------------------------------------------
# Main bootstrap runner
# -----------------------------------------------------------------------------


def run_bootstrap(
    settings: Settings | Mapping[str, Any] | None = None,
    options: BootstrapOptions | None = None,
) -> BootstrapResult:
    """
    Execute bootstrap validation and optional local initialization steps.

    This function is intentionally safe by default. It performs validation first
    and only mutates state when explicitly requested through options or enabled
    environment settings.
    """
    resolved_settings: Any = settings if settings is not None else get_settings()
    resolved_options = options or BootstrapOptions()

    result = BootstrapResult(
        started_at=_utcnow(),
        dry_run=resolved_options.dry_run,
    )

    validation_steps = _validate_settings(resolved_settings, resolved_options)

    for step in validation_steps:
        result.steps.append(step)

    if any(step.fatal or step.status == StepStatus.FAILED for step in validation_steps):
        result.finished_at = _utcnow()
        return result

    if resolved_options.validate_only:
        result.add(
            BootstrapAction.VALIDATE,
            StepStatus.OK,
            "Bootstrap validation-only mode completed.",
        )
        result.finished_at = _utcnow()
        return result

    seed_dev_users = _effective_bool(
        resolved_settings,
        resolved_options,
        "seed_dev_users",
        "SEED_DEV_USERS",
        False,
    )

    seed_demo_data = _effective_bool(
        resolved_settings,
        resolved_options,
        "seed_demo_data",
        "SEED_DEMO_DATA",
        False,
    )

    create_schema = _effective_create_schema(resolved_settings, resolved_options)

    if resolved_options.dry_run:
        if resolved_options.reset:
            result.add(
                BootstrapAction.RESET_DATABASE,
                StepStatus.SKIPPED,
                "Dry run: destructive database reset planned.",
                details={"destructive": True},
            )

        if create_schema and not resolved_options.reset:
            result.add(
                BootstrapAction.CREATE_SCHEMA,
                StepStatus.SKIPPED,
                "Dry run: schema creation planned.",
            )

        result.add(
            BootstrapAction.SEED_REFERENCE_DATA,
            StepStatus.SKIPPED,
            "Dry run: reference data bootstrap planned.",
        )

        if seed_dev_users:
            result.add(
                BootstrapAction.ENSURE_DEV_USERS,
                StepStatus.SKIPPED,
                "Dry run: development user seeding planned.",
            )

        if seed_demo_data:
            result.add(
                BootstrapAction.SEED_DEMO_DATA,
                StepStatus.SKIPPED,
                "Dry run: synthetic demo data seeding planned.",
            )

        result.finished_at = _utcnow()
        return result

    # ---------------------------------------------------------------------
    # Destructive reset, if requested
    # ---------------------------------------------------------------------
    if resolved_options.reset:
        _reset_database(resolved_settings, resolved_options, result)

        if any(step.fatal or step.status == StepStatus.FAILED for step in result.steps):
            result.finished_at = _utcnow()
            return result

    # ---------------------------------------------------------------------
    # Schema creation, if requested and not already handled by reset
    # ---------------------------------------------------------------------
    if create_schema and not resolved_options.reset:
        _ensure_schema(resolved_settings, resolved_options, result)

        if any(step.fatal or step.status == StepStatus.FAILED for step in result.steps):
            result.finished_at = _utcnow()
            return result

    # ---------------------------------------------------------------------
    # Data bootstrap steps
    # ---------------------------------------------------------------------
    try:
        with session_scope() as db:
            _seed_reference_data(db, resolved_settings, resolved_options, result)
            _ensure_dev_users(db, resolved_settings, resolved_options, result)
            _seed_demo_data(db, resolved_settings, resolved_options, result)

    except SQLAlchemyError as exc:
        logger.exception("Bootstrap database session failed.")

        result.add(
            BootstrapAction.DATABASE_SESSION,
            StepStatus.FAILED,
            "Bootstrap database session failed.",
            details={"error_type": type(exc).__name__},
            fatal=True,
        )

    except Exception as exc:
        logger.exception("Unexpected bootstrap failure.")

        result.add(
            BootstrapAction.DATABASE_SESSION,
            StepStatus.FAILED,
            "Unexpected bootstrap failure.",
            details={"error_type": type(exc).__name__},
            fatal=True,
        )

    result.finished_at = _utcnow()
    return result


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    """
    Build the bootstrap CLI argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="python -m app.bootstrap",
        description=(
            "MULEGUARD backend bootstrap helper. "
            "Validates safety policy and optionally initializes local synthetic demo state."
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and report planned actions without mutating state.",
    )

    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Run validation only and skip all bootstrap actions.",
    )

    parser.add_argument(
        "--reset",
        action="store_true",
        help="Destructively reset the local synthetic demo database.",
    )

    parser.add_argument(
        "--confirm",
        default=None,
        help="Confirmation phrase required for destructive reset.",
    )

    parser.add_argument(
        "--create-schema",
        dest="create_schema",
        action="store_true",
        default=None,
        help="Create local/test database schema from SQLAlchemy metadata.",
    )

    parser.add_argument(
        "--no-create-schema",
        dest="create_schema",
        action="store_false",
        help="Disable schema creation even if environment settings would enable it.",
    )

    parser.add_argument(
        "--seed-dev-users",
        dest="seed_dev_users",
        action="store_true",
        default=None,
        help="Seed local development users from environment configuration.",
    )

    parser.add_argument(
        "--no-seed-dev-users",
        dest="seed_dev_users",
        action="store_false",
        help="Disable development user seeding.",
    )

    parser.add_argument(
        "--seed-demo-data",
        dest="seed_demo_data",
        action="store_true",
        default=None,
        help="Invoke synthetic demo data seeding.",
    )

    parser.add_argument(
        "--no-seed-demo-data",
        dest="seed_demo_data",
        action="store_false",
        help="Disable synthetic demo data seeding.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging.",
    )

    return parser


def _configure_logging(verbose: bool = False) -> None:
    """
    Configure CLI logging safely.

    Do not enable debug logging for password hashing or database internals in
    shared environments.
    """
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stderr,
    )

    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("app.db").setLevel(logging.INFO)


def _print_human(result: BootstrapResult) -> None:
    """
    Print a human-readable bootstrap summary.
    """
    for step in result.steps:
        status = step.status.value.upper()
        action = step.action.value
        print(f"[{status}] {action}: {step.message}", file=sys.stderr)

        if step.details:
            print(
                json.dumps(step.details, indent=2, sort_keys=True, default=str),
                file=sys.stderr,
            )

    if result.ok:
        print("Bootstrap completed successfully.", file=sys.stderr)
    else:
        print("Bootstrap failed. See steps above.", file=sys.stderr)


def main(argv: Optional[list[str]] = None) -> int:
    """
    CLI entrypoint for bootstrap operations.
    """
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    _configure_logging(verbose=bool(args.verbose))

    options = BootstrapOptions(
        dry_run=bool(args.dry_run),
        validate_only=bool(args.validate_only),
        reset=bool(args.reset),
        confirm=args.confirm,
        create_schema=args.create_schema,
        seed_dev_users=args.seed_dev_users,
        seed_demo_data=args.seed_demo_data,
    )

    result = run_bootstrap(options=options)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True, default=str))
    else:
        _print_human(result)

    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BootstrapAction",
    "BootstrapOptions",
    "BootstrapResult",
    "BootstrapStep",
    "StepStatus",
    "main",
    "run_bootstrap",
]