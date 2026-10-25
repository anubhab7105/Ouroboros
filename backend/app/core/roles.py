"""
MULEGUARD backend core role model.

This module centralizes the canonical role definitions, hierarchy, display
metadata, and normalization helpers for the synthetic MULEGUARD prototype.

Primary responsibilities:

- define the canonical role identifiers and stable display metadata;
- provide a lightweight role hierarchy for seniority checks;
- normalize role-like values from environment settings, API payloads, tokens,
  and persistence layers;
- expose safe helpers for role validation, membership, and comparison;
- provide settings-aware display-name resolution;
- remain import-safe and avoid circular dependencies.

Relationship to other modules:

- `app.core.roles` defines role identity and hierarchy.
- `app.auth.rbac` defines permission grants and deny-by-default authorization.
- `app.models.UserRole` persists the same role identifiers as a database enum.

This module intentionally avoids importing SQLAlchemy models at package level.
It exposes helpers that lazily convert to `UserRole` when needed.

Security and product-safety rules enforced here:

- Roles are server-side concepts. Client-supplied role claims must be verified
  against the persisted user record by authentication/authorization layers.
- Unknown roles are rejected by validation helpers.
- Role metadata never contains secrets, tokens, passwords, database URLs, raw
  complaint narratives, or real customer data.
- Roles never trigger automatic adverse customer action.

Explicit non-goals:

- This module does not authenticate users.
- This module does not authorize permissions. Use `app.auth.rbac` for that.
- This module does not persist or mutate role assignments.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Roles here describe local
operator capabilities only and must not be interpreted as real-world legal,
regulatory, or enforcement authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, Optional

from app.exceptions import ValidationError


# -----------------------------------------------------------------------------
# Canonical role identifiers
# -----------------------------------------------------------------------------

ROLE_ADMIN: Final[str] = "ADMIN"
ROLE_ANALYST: Final[str] = "ANALYST"
ROLE_SENIOR_INVESTIGATOR: Final[str] = "SENIOR_INVESTIGATOR"
ROLE_AUDITOR: Final[str] = "AUDITOR"

ALL_ROLES: Final[tuple[str, ...]] = (
    ROLE_ADMIN,
    ROLE_SENIOR_INVESTIGATOR,
    ROLE_ANALYST,
    ROLE_AUDITOR,
)

# Investigative roles that can read most surfaces.
READ_ROLES: Final[tuple[str, ...]] = (
    ROLE_ADMIN,
    ROLE_SENIOR_INVESTIGATOR,
    ROLE_ANALYST,
    ROLE_AUDITOR,
)

# Roles that can perform day-to-day triage and investigation mutations.
ANALYST_AND_ABOVE: Final[tuple[str, ...]] = (
    ROLE_ANALYST,
    ROLE_SENIOR_INVESTIGATOR,
    ROLE_ADMIN,
)

# Roles that can assign, escalate, close, or reopen workflows.
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

# Roles that are considered "operators" for investigation workflows.
OPERATOR_ROLES: Final[tuple[str, ...]] = (
    ROLE_ANALYST,
    ROLE_SENIOR_INVESTIGATOR,
    ROLE_ADMIN,
)


# -----------------------------------------------------------------------------
# Role hierarchy
# -----------------------------------------------------------------------------
# Higher rank means broader investigative authority. AUDITOR is intentionally
# placed outside the operator chain because auditors read but do not mutate.

_ROLE_RANK: Final[Mapping[str, int]] = {
    ROLE_AUDITOR: 0,
    ROLE_ANALYST: 1,
    ROLE_SENIOR_INVESTIGATOR: 2,
    ROLE_ADMIN: 3,
}

_ROLE_DESCRIPTIONS: Final[Mapping[str, str]] = {
    ROLE_ADMIN: (
        "Administrator with full access to configuration, user management, "
        "ingestion, model training, and audit export."
    ),
    ROLE_SENIOR_INVESTIGATOR: (
        "Senior investigator who can triage alerts, manage cases, assign and "
        "escalate work, and review sensitive complaint data."
    ),
    ROLE_ANALYST: (
        "Analyst who can review alerts, investigate cases, attach evidence, and "
        "generate reports."
    ),
    ROLE_AUDITOR: (
        "Auditor with read-only access to cases, alerts, and audit history, but "
        "no mutation rights."
    ),
}

_ROLE_DISPLAY_NAMES: Final[Mapping[str, str]] = {
    ROLE_ADMIN: "Administrator",
    ROLE_SENIOR_INVESTIGATOR: "Senior Investigator",
    ROLE_ANALYST: "Analyst",
    ROLE_AUDITOR: "Auditor",
}


@dataclass(frozen=True, slots=True)
class RoleInfo:
    """
    Safe metadata describing one MULEGUARD role.
    """

    name: str
    display_name: str
    description: str
    rank: int
    is_operator: bool
    is_admin: bool
    is_auditor: bool

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable representation.
        """
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "rank": self.rank,
            "is_operator": self.is_operator,
            "is_admin": self.is_admin,
            "is_auditor": self.is_auditor,
        }


def _build_role_info(name: str) -> RoleInfo:
    """
    Build RoleInfo for a canonical role.
    """
    return RoleInfo(
        name=name,
        display_name=_ROLE_DISPLAY_NAMES[name],
        description=_ROLE_DESCRIPTIONS[name],
        rank=_ROLE_RANK[name],
        is_operator=name in OPERATOR_ROLES,
        is_admin=name == ROLE_ADMIN,
        is_auditor=name == ROLE_AUDITOR,
    )


ROLE_REGISTRY: Final[Mapping[str, RoleInfo]] = {
    name: _build_role_info(name) for name in ALL_ROLES
}


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}


def _setting(settings: Any, name: str, default: Any = None) -> Any:
    """
    Read a setting from either a typed settings object or mapping.
    """
    if settings is None:
        return default

    if isinstance(settings, Mapping):
        return settings.get(name, default)

    return getattr(settings, name, default)


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
# Normalization and validation
# -----------------------------------------------------------------------------


def normalize_role(value: Any) -> str:
    """
    Normalize a role-like value to an uppercase canonical role string.

    Accepts enum members, strings, and None. Returns an empty string for None
    or unparseable values.
    """
    if value is None:
        return ""

    enum_value = getattr(value, "value", None)

    if enum_value is not None:
        return str(enum_value).strip().upper().replace(" ", "_").replace("-", "_")

    return str(value).strip().upper().replace(" ", "_").replace("-", "_")


def is_known_role(value: Any) -> bool:
    """
    Return True when a value maps to a known MULEGUARD role.
    """
    return normalize_role(value) in ROLE_REGISTRY


def validate_role(value: Any) -> str:
    """
    Validate and normalize a role value.

    Raises ValidationError for unknown or missing roles.
    """
    normalized = normalize_role(value)

    if not normalized:
        raise ValidationError(
            "Role is required.",
            details={"reason": "missing_role"},
        )

    if normalized not in ROLE_REGISTRY:
        raise ValidationError(
            "Role is not recognized.",
            details={
                "reason": "unknown_role",
                "allowed_roles": list(ALL_ROLES),
            },
        )

    return normalized


def roles_from_setting(value: Any) -> tuple[str, ...]:
    """
    Parse a role-list setting into normalized, de-duplicated role names.
    """
    items = _csv(value)
    seen: set[str] = set()
    result: list[str] = []

    for item in items:
        role = normalize_role(item)

        if not role or role in seen:
            continue

        seen.add(role)
        result.append(role)

    return tuple(result)


def coerce_user_role(value: Any) -> Any:
    """
    Convert a role-like value to a persisted UserRole enum member when possible.

    Falls back to ANALYST when the value cannot be coerced. This helper imports
    `app.models.UserRole` lazily to avoid circular dependencies.
    """
    try:
        from app.models import UserRole
    except Exception:
        return normalize_role(value) or ROLE_ANALYST

    normalized = normalize_role(value)

    try:
        return UserRole(normalized)
    except ValueError:
        return UserRole.ANALYST


# -----------------------------------------------------------------------------
# Hierarchy helpers
# -----------------------------------------------------------------------------


def role_rank(value: Any) -> int:
    """
    Return the numeric rank for a role.

    Unknown roles return -1 so they sort below every known role.
    """
    normalized = normalize_role(value)
    return _ROLE_RANK.get(normalized, -1)


def role_at_least(user_role: Any, minimum_role: Any) -> bool:
    """
    Return True when `user_role` has at least the authority of `minimum_role`.

    Unknown roles never satisfy a minimum-role requirement.
    """
    user_rank = role_rank(user_role)
    minimum_rank = role_rank(minimum_role)

    if user_rank < 0 or minimum_rank < 0:
        return False

    return user_rank >= minimum_rank


def is_operator_role(value: Any) -> bool:
    """
    Return True when a role can perform investigative mutations.
    """
    normalized = normalize_role(value)
    return normalized in OPERATOR_ROLES


def is_admin_role(value: Any) -> bool:
    """
    Return True when a role is ADMIN.
    """
    return normalize_role(value) == ROLE_ADMIN


def is_auditor_role(value: Any) -> bool:
    """
    Return True when a role is AUDITOR.
    """
    return normalize_role(value) == ROLE_AUDITOR


# -----------------------------------------------------------------------------
# Metadata helpers
# -----------------------------------------------------------------------------


def get_role_info(value: Any) -> RoleInfo:
    """
    Return RoleInfo for a role value.

    Raises ValidationError for unknown roles.
    """
    normalized = validate_role(value)
    return ROLE_REGISTRY[normalized]


def list_roles() -> tuple[str, ...]:
    """
    Return all known role identifiers.
    """
    return ALL_ROLES


def role_display_name(value: Any, settings: Any | None = None) -> str:
    """
    Return a safe display name for a role.

    Display names can be overridden by configuration through:

        ROLE_<NAME>_DISPLAY_NAME
    """
    normalized = normalize_role(value)

    if not normalized:
        return ""

    if settings is not None:
        configured = _setting(settings, f"ROLE_{normalized}_DISPLAY_NAME", None)

        if configured:
            return str(configured).strip()

    return _ROLE_DISPLAY_NAMES.get(normalized, normalized.replace("_", " ").title())


def get_roles_metadata() -> list[dict[str, Any]]:
    """
    Return safe, serializable metadata for all known roles.
    """
    return [ROLE_REGISTRY[name].to_dict() for name in ALL_ROLES]


__all__ = [
    "ADMIN_ONLY",
    "ALL_ROLES",
    "ANALYST_AND_ABOVE",
    "AUDITOR_AND_ADMIN",
    "OPERATOR_ROLES",
    "READ_ROLES",
    "ROLE_ADMIN",
    "ROLE_ANALYST",
    "ROLE_AUDITOR",
    "ROLE_SENIOR_INVESTIGATOR",
    "ROLE_REGISTRY",
    "RoleInfo",
    "SENIOR_AND_ADMIN",
    "coerce_user_role",
    "get_role_info",
    "get_roles_metadata",
    "is_admin_role",
    "is_auditor_role",
    "is_known_role",
    "is_operator_role",
    "list_roles",
    "normalize_role",
    "role_at_least",
    "role_display_name",
    "role_rank",
    "roles_from_setting",
    "validate_role",
]