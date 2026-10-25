"""
MULEGUARD backend local development user seeding.

This module provisions local prototype users for synthetic MULEGUARD demo and
test workflows. It is invoked by the Docker entrypoint, the bootstrap helper,
and directly as a CLI module:

    python -m app.auth.dev_users

Security and product-safety rules enforced here:

- Development users are local-only. Seeding is blocked in production-like
  environments.
- Passwords must be supplied through environment configuration. No hardcoded
  passwords are used.
- Placeholder passwords are rejected.
- Configured password policy is enforced for every development user.
- Development user emails must use allowed synthetic local domains when
  configured.
- Seeding is idempotent. Re-running updates existing users without duplicating
  them.
- Username/email conflicts are detected and reported rather than silently
  overwritten.
- No passwords, tokens, secrets, database URLs, raw complaint narratives, or
  real customer data are logged or returned.
- Development users are prototype operators, not real customers. Seeding never
  triggers automatic adverse customer action.

Explicit non-goals:

- This module does not manage real bank customers.
- This module does not connect to real identity providers.
- This module does not implement hard deletion because audit and case history
  integrity require soft state changes.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Development users
created here are local demo operators only.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Final, Optional

from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password, validate_password_policy
from app.db import session_scope
from app.models import AuditEvent, AuditOutcome, User, UserRole

logger = logging.getLogger("muleguard.backend.auth.dev_users")


# -----------------------------------------------------------------------------
# Constants
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

_SENSITIVE_AUDIT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "current_password",
        "new_password",
        "narrative",
        "password",
        "raw_payload",
        "refresh_token",
        "secret",
        "token",
    }
)

_DEFAULT_EMAIL_DOMAIN_ALLOWLIST: Final[tuple[str, ...]] = ("muleguard.local",)


class SeedOutcome(str, Enum):
    """
    Outcome label for a development-user seeding operation.
    """

    CREATED = "created"
    UPDATED = "updated"
    SKIPPED = "skipped"
    CONFLICT = "conflict"
    POLICY_ERROR = "policy_error"
    DISABLED = "disabled"
    BLOCKED = "blocked"


@dataclass(slots=True)
class DevUserSpec:
    """
    Declarative specification for one local development user.
    """

    key: str
    role: UserRole
    username_setting: str
    default_username: str
    email_setting: str
    default_email: str
    password_setting: str
    full_name: str


@dataclass(slots=True)
class SeedResult:
    """
    Structured result from development-user seeding.

    This object never contains passwords or raw secrets.
    """

    enabled: bool = True
    blocked: bool = False
    dry_run: bool = False
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    conflicts: list[dict[str, str]] = field(default_factory=list)
    policy_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """
        Return True when seeding completed without blocking errors.
        """
        if self.blocked:
            return False

        if self.policy_errors:
            return False

        if self.conflicts:
            return False

        return True

    def to_dict(self) -> dict[str, Any]:
        """
        Return a safe JSON-serializable summary.
        """
        return {
            "ok": self.ok,
            "enabled": self.enabled,
            "blocked": self.blocked,
            "dry_run": self.dry_run,
            "created": list(self.created),
            "updated": list(self.updated),
            "skipped": list(self.skipped),
            "conflicts": list(self.conflicts),
            "policy_errors": list(self.policy_errors),
            "warnings": list(self.warnings),
        }


# -----------------------------------------------------------------------------
# Development user specifications
# -----------------------------------------------------------------------------

_DEV_USER_SPECS: Final[tuple[DevUserSpec, ...]] = (
    DevUserSpec(
        key="admin",
        role=UserRole.ADMIN,
        username_setting="DEV_ADMIN_USERNAME",
        default_username="admin",
        email_setting="DEV_ADMIN_EMAIL",
        default_email="admin@muleguard.local",
        password_setting="DEV_ADMIN_PASSWORD",
        full_name="MULEGUARD Administrator",
    ),
    DevUserSpec(
        key="analyst",
        role=UserRole.ANALYST,
        username_setting="DEV_ANALYST_USERNAME",
        default_username="analyst",
        email_setting="DEV_ANALYST_EMAIL",
        default_email="analyst@muleguard.local",
        password_setting="DEV_ANALYST_PASSWORD",
        full_name="MULEGUARD Analyst",
    ),
    DevUserSpec(
        key="senior_investigator",
        role=UserRole.SENIOR_INVESTIGATOR,
        username_setting="DEV_SENIOR_INVESTIGATOR_USERNAME",
        default_username="senior_investigator",
        email_setting="DEV_SENIOR_INVESTIGATOR_EMAIL",
        default_email="senior@muleguard.local",
        password_setting="DEV_SENIOR_INVESTIGATOR_PASSWORD",
        full_name="MULEGUARD Senior Investigator",
    ),
    DevUserSpec(
        key="auditor",
        role=UserRole.AUDITOR,
        username_setting="DEV_AUDITOR_USERNAME",
        default_username="auditor",
        email_setting="DEV_AUDITOR_EMAIL",
        default_email="auditor@muleguard.local",
        password_setting="DEV_AUDITOR_PASSWORD",
        full_name="MULEGUARD Auditor",
    ),
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


def _contains_placeholder(value: str) -> bool:
    """
    Detect obvious template or placeholder secret values.
    """
    if not value:
        return True

    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


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


def _safe_metadata(metadata: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return sanitized audit metadata.
    """
    if not metadata:
        return {}

    safe: dict[str, Any] = {}

    for raw_key, raw_value in list(metadata.items())[:50]:
        key = str(raw_key).strip()

        if not key or key.lower() in _SENSITIVE_AUDIT_KEYS:
            continue

        if raw_value is None:
            safe[key] = None
            continue

        if isinstance(raw_value, bool):
            safe[key] = raw_value
            continue

        if isinstance(raw_value, int):
            safe[key] = raw_value
            continue

        if isinstance(raw_value, float):
            safe[key] = raw_value
            continue

        if isinstance(raw_value, str):
            safe[key] = raw_value[:512]
            continue

        safe[key] = str(raw_value)[:512]

    return safe


def _add_audit_event(
    db: Session,
    *,
    action: str,
    outcome: AuditOutcome,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Add a safe audit event to the current session.

    The caller is responsible for committing the transaction.
    """
    event = AuditEvent(
        actor_id=None,
        actor_username="system",
        actor_role="SYSTEM",
        action=str(action)[:100],
        resource_type=str(resource_type)[:100] if resource_type is not None else None,
        resource_id=str(resource_id)[:128] if resource_id is not None else None,
        outcome=outcome,
        request_id=None,
        ip_hash=None,
        metadata_json=_safe_metadata(metadata),
    )

    db.add(event)


# -----------------------------------------------------------------------------
# Validation helpers
# -----------------------------------------------------------------------------


def _validate_email_domain(email: str, settings: Any) -> list[str]:
    """
    Ensure development user emails use allowed synthetic local domains.

    By default, no domain restriction is enforced unless configured.
    """
    allowlist_raw = _csv(
        _setting(
            settings,
            "DEV_USERS_EMAIL_DOMAIN_ALLOWLIST",
            ",".join(_DEFAULT_EMAIL_DOMAIN_ALLOWLIST),
        )
    )

    if not allowlist_raw:
        return []

    allowed = {domain.strip().lower() for domain in allowlist_raw if domain.strip()}

    if not allowed:
        return []

    if "@" not in email:
        return ["invalid_email"]

    domain = email.rsplit("@", 1)[-1].strip().lower()

    if domain not in allowed:
        return ["email_domain_not_allowed"]

    return []


def _validate_dev_password(password: str, settings: Any) -> list[str]:
    """
    Validate a development password against configured policy.
    """
    errors: list[str] = []

    if not password:
        return ["missing_password"]

    if _contains_placeholder(password):
        errors.append("placeholder_value")

    errors.extend(validate_password_policy(password, None, settings))

    seen: set[str] = set()
    unique_errors: list[str] = []

    for error in errors:
        if error not in seen:
            seen.add(error)
            unique_errors.append(error)

    return unique_errors


# -----------------------------------------------------------------------------
# Seeding logic
# -----------------------------------------------------------------------------


def _resolve_spec_values(
    spec: DevUserSpec,
    settings: Any,
) -> tuple[str, str, str]:
    """
    Resolve username, email, and password for one development user spec.
    """
    username = str(
        _setting(settings, spec.username_setting, spec.default_username)
        or spec.default_username
    ).strip()

    email = str(
        _setting(settings, spec.email_setting, spec.default_email)
        or spec.default_email
    ).strip().lower()

    password = str(_setting(settings, spec.password_setting, "") or "").strip()

    return username, email, password


def _stable_user_id(username: str) -> str:
    """
    Return a stable identifier for a development user.
    """
    return f"dev-{username}"


def ensure_dev_users(
    db: Session,
    settings: Any,
    *,
    dry_run: bool = False,
) -> SeedResult:
    """
    Create or update local development users from environment configuration.

    This function is idempotent and safe to re-run. It never logs or returns
    passwords.
    """
    result = SeedResult(dry_run=dry_run)

    # ---------------------------------------------------------------------
    # Production-like block
    # ---------------------------------------------------------------------
    if _is_production_like(settings):
        result.enabled = False
        result.blocked = True
        result.warnings.append(
            "Development user seeding is not allowed in production-like environments."
        )
        return result

    # ---------------------------------------------------------------------
    # Enablement check
    # ---------------------------------------------------------------------
    enabled = _as_bool(_setting(settings, "SEED_DEV_USERS", True), True)

    if not enabled:
        result.enabled = False
        result.warnings.append("Development user seeding is disabled by SEED_DEV_USERS=false.")
        return result

    require_password_from_env = _as_bool(
        _setting(settings, "DEV_USERS_REQUIRE_PASSWORD_FROM_ENV", True),
        True,
    )

    force_password_reset = _as_bool(
        _setting(settings, "DEV_USERS_FORCE_PASSWORD_RESET", False),
        False,
    ) or _as_bool(
        _setting(settings, "DEV_USERS_REQUIRE_PASSWORD_CHANGE", False),
        False,
    )

    # ---------------------------------------------------------------------
    # Seed each development user
    # ---------------------------------------------------------------------
    for spec in _DEV_USER_SPECS:
        username, email, password = _resolve_spec_values(spec, settings)

        if not username:
            result.policy_errors.append(f"missing_username_for_{spec.key}")
            continue

        if not email:
            result.policy_errors.append(f"missing_email_for_{username}")
            continue

        if not password:
            if require_password_from_env:
                result.policy_errors.append(f"missing_password_for_{username}")
            else:
                result.skipped.append(username)
            continue

        # Password policy validation.
        password_errors = _validate_dev_password(password, settings)

        # Email domain validation.
        email_errors = _validate_email_domain(email, settings)

        combined_errors = password_errors + [
            f"{error}_for_{username}" for error in email_errors
        ]

        if combined_errors:
            result.policy_errors.extend(combined_errors)
            continue

        if dry_run:
            result.created.append(f"{username} (dry-run)")
            continue

        password_hash = hash_password(password, settings)

        existing_by_username: Optional[User] = db.scalar(
            select(User).where(User.username == username)
        )

        existing_by_email: Optional[User] = db.scalar(
            select(User).where(User.email == email)
        )

        # Detect cross-conflicts before writing.
        if existing_by_email is not None and existing_by_username is not None:
            if existing_by_email.id != existing_by_username.id:
                result.conflicts.append(
                    {
                        "username": username,
                        "email": email,
                        "reason": "email_belongs_to_different_user",
                    }
                )
                continue

        if existing_by_email is not None and existing_by_username is None:
            result.conflicts.append(
                {
                    "username": username,
                    "email": email,
                    "reason": "email_belongs_to_existing_user",
                }
            )
            continue

        stable_id = _stable_user_id(username)
        existing_by_id: Optional[User] = db.get(User, stable_id)

        if existing_by_id is not None and existing_by_id.username != username:
            result.conflicts.append(
                {
                    "username": username,
                    "id": stable_id,
                    "reason": "stable_id_conflict",
                }
            )
            continue

        # Update existing user.
        if existing_by_username is not None:
            existing_by_username.role = spec.role
            existing_by_username.is_active = True
            existing_by_username.password_hash = password_hash
            existing_by_username.must_change_password = force_password_reset

            if existing_by_username.full_name != spec.full_name:
                existing_by_username.full_name = spec.full_name

            if existing_by_username.email != email:
                existing_by_username.email = email

            result.updated.append(username)
            continue

        # Create new user.
        user = User(
            id=stable_id,
            username=username,
            email=email,
            full_name=spec.full_name,
            role=spec.role,
            password_hash=password_hash,
            is_active=True,
            must_change_password=force_password_reset,
            failed_login_count=0,
        )

        db.add(user)
        result.created.append(username)

    # ---------------------------------------------------------------------
    # Flush and audit
    # ---------------------------------------------------------------------
    if not dry_run:
        try:
            db.flush()
        except SQLAlchemyError as exc:
            logger.exception("Development user flush failed.")
            result.policy_errors.append(
                f"database_flush_failed:{type(exc).__name__}"
            )
            return result

        _add_audit_event(
            db,
            action="dev_users_seed",
            outcome=AuditOutcome.SUCCESS if result.ok else AuditOutcome.FAILURE,
            resource_type="dev_users",
            resource_id=None,
            metadata={
                "created_count": len(result.created),
                "updated_count": len(result.updated),
                "skipped_count": len(result.skipped),
                "conflict_count": len(result.conflicts),
                "policy_error_count": len(result.policy_errors),
                "dry_run": False,
            },
        )

    return result


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def _print_result(result: SeedResult, *, as_json: bool) -> None:
    """
    Print a safe seeding summary to stdout.
    """
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return

    for warning in result.warnings:
        print(f"[WARN] {warning}", file=sys.stderr)

    for username in result.created:
        print(f"[CREATED] {username}", file=sys.stderr)

    for username in result.updated:
        print(f"[UPDATED] {username}", file=sys.stderr)

    for username in result.skipped:
        print(f"[SKIPPED] {username}", file=sys.stderr)

    for conflict in result.conflicts:
        print(
            f"[CONFLICT] {conflict.get('username')} "
            f"({conflict.get('reason')})",
            file=sys.stderr,
        )

    for error in result.policy_errors:
        print(f"[POLICY_ERROR] {error}", file=sys.stderr)

    if result.ok:
        print("Development user seeding completed successfully.", file=sys.stderr)
    else:
        print("Development user seeding failed. See details above.", file=sys.stderr)


def main(argv: Optional[list[str]] = None) -> int:
    """
    CLI entrypoint for development user seeding.
    """
    parser = argparse.ArgumentParser(
        prog="python -m app.auth.dev_users",
        description=(
            "Seed local MULEGUARD development users from environment "
            "configuration. This is a local-only synthetic prototype action."
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration and report planned actions without writing.",
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

    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stderr,
    )

    try:
        from app.core.config import get_settings

        settings = get_settings()
    except Exception:
        settings = {}

    try:
        with session_scope() as db:
            result = ensure_dev_users(db, settings, dry_run=bool(args.dry_run))

            if not args.dry_run:
                db.commit()

    except Exception as exc:
        logger.exception("Development user seeding failed unexpectedly.")
        result = SeedResult(enabled=True, blocked=True)
        result.policy_errors.append(f"unexpected_error:{type(exc).__name__}")

    _print_result(result, as_json=bool(args.json))

    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DevUserSpec",
    "SeedOutcome",
    "SeedResult",
    "ensure_dev_users",
    "main",
]