"""
MULEGUARD backend role-based access control (RBAC).

This module centralizes role and permission resolution for the synthetic
MULEGUARD prototype. It is used by API dependencies and services to enforce
server-side authorization consistently.

Primary responsibilities:

- define the canonical role set and a lightweight role hierarchy;
- define stable permission identifiers and their default role grants;
- resolve effective allowed roles per permission from configuration overrides;
- enforce deny-by-default authorization decisions;
- provide safe helper functions for role and permission checks;
- expose structured decision results for auditing and diagnostics;
- never expose secrets, tokens, passwords, database URLs, raw complaint
  narratives, or real customer data.

Security and product-safety rules enforced here:

- The backend is the security boundary. Frontend hiding is not sufficient.
- Authorization is deny-by-default. Unknown permissions or roles deny access.
- RBAC does not trigger automatic adverse customer action.
- Superuser bypass is disabled unless explicitly enabled by configuration.
- Decisions are deterministic and inspectable for audit tooling.
- Role checks are based on the authenticated user's current persisted role, not
  on client-supplied claims.

Explicit non-goals:

- This module does not authenticate users.
- This module does not manage user records or persist role assignments.
- This module does not implement attribute-based or policy-engine authorization
  beyond the documented role/permission model.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. RBAC here protects local
demo and test workflows only. Alerts, scores, graph relationships, candidate
money trails, entity links, complaint correlations, and case dispositions remain
investigative leads or human workflow artefacts only.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final, Optional

from app.auth import (
    ADMIN_ONLY,
    ALL_ROLES,
    ANALYST_AND_ABOVE,
    AUDITOR_AND_ADMIN,
    READ_ROLES,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_SENIOR_INVESTIGATOR,
    SENIOR_AND_ADMIN,
)
from app.exceptions import ConfigurationError, PermissionDeniedError

logger = logging.getLogger("muleguard.backend.auth.rbac")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}


class Permission(str, Enum):
    """
    Stable permission identifiers used across the MULEGUARD backend.

    These map to environment settings such as:

        ANALYSIS_RUN_ROLES=ANALYST,SENIOR_INVESTIGATOR,ADMIN
        CASE_CREATE_ROLES=ANALYST,SENIOR_INVESTIGATOR,ADMIN
        AUDIT_READ_ROLES=AUDITOR,ADMIN

    Permission names are treated as public contract. Prefer adding new
    permissions over changing the meaning of existing ones.
    """

    # User and configuration management
    USER_MANAGE = "user_management"
    CONFIG_READ = "config_read"
    CONFIG_WRITE = "config_write"

    # Read surfaces
    DASHBOARD_READ = "dashboard_read"
    ACCOUNT_READ = "account_read"
    TRANSACTION_READ = "transaction_read"
    SEARCH = "search"

    # Analysis and ingestion
    ANALYSIS_RUN = "analysis_run"
    INGESTION_WRITE = "ingestion_write"
    SEED_RESET = "seed_reset"

    # Alerts
    ALERT_READ = "alert_read"
    ALERT_TRIAGE = "alert_triage"
    ALERT_ASSIGN = "alert_assign"
    ALERT_ESCALATE = "alert_escalate"
    ALERT_CASE_CREATE = "alert_case_create"

    # Graph and entities
    GRAPH_READ = "graph_read"
    GRAPH_EXPORT = "graph_export"

    # Complaints
    COMPLAINT_READ = "complaint_read"
    COMPLAINT_REVIEW = "complaint_review"
    COMPLAINT_NARRATIVE_READ = "complaint_narrative_read"

    # Cases
    CASE_READ = "case_read"
    CASE_CREATE = "case_create"
    CASE_UPDATE = "case_update"
    CASE_ASSIGN = "case_assign"
    CASE_CLOSE = "case_close"
    CASE_REOPEN = "case_reopen"
    CASE_NOTE_ADD = "case_note_add"
    CASE_EVIDENCE_ADD = "case_evidence_add"
    CASE_EVIDENCE_REMOVE = "case_evidence_remove"
    CASE_EXPORT = "case_export"

    # Reports
    REPORT_READ = "report_read"
    REPORT_GENERATE = "report_generate"
    REPORT_DOWNLOAD = "report_download"

    # Audit
    AUDIT_READ = "audit_read"
    AUDIT_EXPORT = "audit_export"

    # Model monitoring
    MODEL_MONITOR_READ = "model_monitor_read"
    MODEL_TRAIN = "model_train"
    MODEL_EVALUATE = "model_evaluate"


class DecisionOutcome(str, Enum):
    """
    Outcome label for an RBAC decision.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    DISABLED = "disabled"


# -----------------------------------------------------------------------------
# Default permission-to-role grants
# -----------------------------------------------------------------------------
# These defaults reflect the MULEGUARD product-safety model:
#
# - broad read access for all investigative roles;
# - mutation and workflow actions restricted to analysts and above;
# - assignment, closure, and reopening restricted to senior/admin;
# - audit access restricted to auditor/admin;
# - administrative functions restricted to admin only.

_DEFAULT_PERMISSION_ROLES: Final[Mapping[str, tuple[str, ...]]] = {
    Permission.USER_MANAGE.value: ADMIN_ONLY,
    Permission.CONFIG_READ.value: ADMIN_ONLY,
    Permission.CONFIG_WRITE.value: ADMIN_ONLY,
    Permission.DASHBOARD_READ.value: READ_ROLES,
    Permission.ACCOUNT_READ.value: READ_ROLES,
    Permission.TRANSACTION_READ.value: READ_ROLES,
    Permission.SEARCH.value: READ_ROLES,
    Permission.ANALYSIS_RUN.value: ANALYST_AND_ABOVE,
    Permission.INGESTION_WRITE.value: ADMIN_ONLY,
    Permission.SEED_RESET.value: ADMIN_ONLY,
    Permission.ALERT_READ.value: READ_ROLES,
    Permission.ALERT_TRIAGE.value: ANALYST_AND_ABOVE,
    Permission.ALERT_ASSIGN.value: SENIOR_AND_ADMIN,
    Permission.ALERT_ESCALATE.value: SENIOR_AND_ADMIN,
    Permission.ALERT_CASE_CREATE.value: ANALYST_AND_ABOVE,
    Permission.GRAPH_READ.value: READ_ROLES,
    Permission.GRAPH_EXPORT.value: ANALYST_AND_ABOVE,
    Permission.COMPLAINT_READ.value: READ_ROLES,
    Permission.COMPLAINT_REVIEW.value: SENIOR_AND_ADMIN,
    Permission.COMPLAINT_NARRATIVE_READ.value: SENIOR_AND_ADMIN,
    Permission.CASE_READ.value: READ_ROLES,
    Permission.CASE_CREATE.value: ANALYST_AND_ABOVE,
    Permission.CASE_UPDATE.value: ANALYST_AND_ABOVE,
    Permission.CASE_ASSIGN.value: SENIOR_AND_ADMIN,
    Permission.CASE_CLOSE.value: SENIOR_AND_ADMIN,
    Permission.CASE_REOPEN.value: SENIOR_AND_ADMIN,
    Permission.CASE_NOTE_ADD.value: ANALYST_AND_ABOVE,
    Permission.CASE_EVIDENCE_ADD.value: ANALYST_AND_ABOVE,
    Permission.CASE_EVIDENCE_REMOVE.value: SENIOR_AND_ADMIN,
    Permission.CASE_EXPORT.value: READ_ROLES,
    Permission.REPORT_READ.value: READ_ROLES,
    Permission.REPORT_GENERATE.value: ANALYST_AND_ABOVE,
    Permission.REPORT_DOWNLOAD.value: READ_ROLES,
    Permission.AUDIT_READ.value: AUDITOR_AND_ADMIN,
    Permission.AUDIT_EXPORT.value: ADMIN_ONLY,
    Permission.MODEL_MONITOR_READ.value: READ_ROLES,
    Permission.MODEL_TRAIN.value: ADMIN_ONLY,
    Permission.MODEL_EVALUATE.value: ADMIN_ONLY,
}


# -----------------------------------------------------------------------------
# Role hierarchy
# -----------------------------------------------------------------------------
# Higher rank means broader investigative authority. AUDITOR is intentionally
# placed outside the analyst chain because auditors read but do not mutate.

_ROLE_RANK: Final[Mapping[str, int]] = {
    ROLE_AUDITOR: 0,
    ROLE_ANALYST: 1,
    ROLE_SENIOR_INVESTIGATOR: 2,
    ROLE_ADMIN: 3,
}


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


def _normalize_role(value: Any) -> str:
    """
    Normalize a role-like value to an uppercase role string.
    """
    enum_value = getattr(value, "value", None)

    if enum_value is not None:
        return str(enum_value).strip().upper().replace(" ", "_").replace("-", "_")

    return str(value).strip().upper().replace(" ", "_").replace("-", "_")


def _normalize_permission(permission: Any) -> str:
    """
    Normalize a permission-like value to its stable string identifier.
    """
    enum_value = getattr(permission, "value", None)

    if enum_value is not None:
        return str(enum_value)

    return str(permission).strip()


def _get_user_role(user: Any) -> str:
    """
    Extract a normalized role string from a user-like object.
    """
    if user is None:
        return ""

    role = getattr(user, "role", None)
    return _normalize_role(role)


def _is_active_user(user: Any) -> bool:
    """
    Return True when a user-like object is active.
    """
    if user is None:
        return False

    return bool(getattr(user, "is_active", False))


# -----------------------------------------------------------------------------
# Decision model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Decision:
    """
    Safe, structured RBAC decision result.

    This object is suitable for diagnostics and audit metadata. It never
    contains secrets, tokens, or raw sensitive narratives.
    """

    outcome: DecisionOutcome
    permission: str
    user_role: str
    allowed_roles: tuple[str, ...] = field(default_factory=tuple)
    reason: Optional[str] = None
    rbac_enabled: bool = True
    superuser_bypass: bool = False

    @property
    def allowed(self) -> bool:
        """
        Return True when access is allowed.
        """
        return self.outcome == DecisionOutcome.ALLOWED

    def to_metadata(self) -> dict[str, Any]:
        """
        Return a safe metadata mapping for audit events.
        """
        return {
            "outcome": self.outcome.value,
            "permission": self.permission,
            "user_role": self.user_role,
            "allowed_roles": list(self.allowed_roles),
            "reason": self.reason,
            "rbac_enabled": self.rbac_enabled,
            "superuser_bypass": self.superuser_bypass,
        }


# -----------------------------------------------------------------------------
# Configuration resolution
# -----------------------------------------------------------------------------


def _permission_setting_names(permission: str) -> tuple[str, ...]:
    """
    Return possible environment setting names for a permission.
    """
    normalized = permission.strip().upper().replace("-", "_").replace(".", "_")

    return (
        f"{normalized}_ROLES",
        f"PERMISSION_{normalized}",
        f"RBAC_{normalized}_ROLES",
    )


def _rbac_enabled(settings: Any) -> bool:
    """
    Return True when RBAC enforcement is enabled.
    """
    return _as_bool(_setting(settings, "RBAC_ENABLED", True), True)


def _superuser_bypass_enabled(settings: Any) -> bool:
    """
    Return True when superuser bypass is explicitly enabled.

    Superuser bypass is disabled by default and should remain disabled in
    production-like environments.
    """
    return _as_bool(_setting(settings, "RBAC_SUPERUSER_BYPASS", False), False)


def _deny_unknown_roles(settings: Any) -> bool:
    """
    Return True when unknown roles should be denied explicitly.
    """
    return _as_bool(_setting(settings, "RBAC_DENY_UNKNOWN_ROLE", True), True)


def get_allowed_roles(permission: Any, settings: Any) -> tuple[str, ...]:
    """
    Resolve the effective allowed roles for a permission.

    Resolution order:

    1. explicit environment setting, e.g. CASE_CREATE_ROLES;
    2. PERMISSION_CASE_CREATE;
    3. RBAC_CASE_CREATE_ROLES;
    4. built-in default grant.

    When no roles resolve, an empty tuple is returned and access will be denied.
    """
    permission_name = _normalize_permission(permission)
    defaults = _DEFAULT_PERMISSION_ROLES.get(permission_name, ())

    for setting_name in _permission_setting_names(permission_name):
        raw_value = _setting(settings, setting_name, None)

        if raw_value is not None:
            roles = tuple(
                _normalize_role(item)
                for item in _csv(raw_value)
                if str(item).strip()
            )

            return roles

    return tuple(_normalize_role(item) for item in defaults)


# -----------------------------------------------------------------------------
# Role helpers
# -----------------------------------------------------------------------------


def is_known_role(role: Any) -> bool:
    """
    Return True when a role value maps to a known MULEGUARD role.
    """
    normalized = _normalize_role(role)
    return normalized in _ROLE_RANK


def role_rank(role: Any) -> int:
    """
    Return the numeric rank for a role.

    Unknown roles return -1 so they sort below every known role.
    """
    normalized = _normalize_role(role)
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


def has_role(user: Any, role: Any) -> bool:
    """
    Return True when a user has exactly the specified role.
    """
    return _get_user_role(user) == _normalize_role(role)


def has_any_role(user: Any, roles: Sequence[Any]) -> bool:
    """
    Return True when a user has any of the specified roles.
    """
    user_role = _get_user_role(user)
    normalized_roles = {_normalize_role(role) for role in roles}
    return user_role in normalized_roles


# -----------------------------------------------------------------------------
# Authorization decisions
# -----------------------------------------------------------------------------


def decide(
    user: Any,
    permission: Any,
    settings: Any,
) -> Decision:
    """
    Compute a safe RBAC decision for a user and permission.

    This function never raises. Callers that need enforcement should use
    `ensure()` instead.
    """
    permission_name = _normalize_permission(permission)
    user_role = _get_user_role(user)

    # Inactive users are always denied.
    if not _is_active_user(user):
        return Decision(
            outcome=DecisionOutcome.DENIED,
            permission=permission_name,
            user_role=user_role,
            allowed_roles=(),
            reason="inactive_user",
            rbac_enabled=_rbac_enabled(settings),
            superuser_bypass=False,
        )

    # When RBAC is disabled, authenticated active users are allowed.
    # This is intentionally unsafe for production-like use.
    if not _rbac_enabled(settings):
        return Decision(
            outcome=DecisionOutcome.ALLOWED,
            permission=permission_name,
            user_role=user_role,
            allowed_roles=(),
            reason="rbac_disabled",
            rbac_enabled=False,
            superuser_bypass=False,
        )

    allowed_roles = get_allowed_roles(permission_name, settings)

    # Superuser bypass, disabled by default.
    if _superuser_bypass_enabled(settings) and user_role == ROLE_ADMIN:
        return Decision(
            outcome=DecisionOutcome.ALLOWED,
            permission=permission_name,
            user_role=user_role,
            allowed_roles=allowed_roles,
            reason="superuser_bypass",
            rbac_enabled=True,
            superuser_bypass=True,
        )

    # Deny unknown roles by default.
    if _deny_unknown_roles(settings) and not is_known_role(user_role):
        return Decision(
            outcome=DecisionOutcome.DENIED,
            permission=permission_name,
            user_role=user_role,
            allowed_roles=allowed_roles,
            reason="unknown_role",
            rbac_enabled=True,
            superuser_bypass=False,
        )

    if not allowed_roles:
        return Decision(
            outcome=DecisionOutcome.DENIED,
            permission=permission_name,
            user_role=user_role,
            allowed_roles=(),
            reason="no_roles_configured",
            rbac_enabled=True,
            superuser_bypass=False,
        )

    if user_role in allowed_roles:
        return Decision(
            outcome=DecisionOutcome.ALLOWED,
            permission=permission_name,
            user_role=user_role,
            allowed_roles=allowed_roles,
            reason="role_granted",
            rbac_enabled=True,
            superuser_bypass=False,
        )

    return Decision(
        outcome=DecisionOutcome.DENIED,
        permission=permission_name,
        user_role=user_role,
        allowed_roles=allowed_roles,
        reason="role_not_granted",
        rbac_enabled=True,
        superuser_bypass=False,
    )


def can(user: Any, permission: Any, settings: Any) -> bool:
    """
    Return True when a user is allowed to perform a permission.

    Deny-by-default. Unknown permissions or roles deny access.
    """
    return decide(user, permission, settings).allowed


def ensure(user: Any, permission: Any, settings: Any) -> Decision:
    """
    Enforce a permission check, raising PermissionDeniedError when denied.

    Returns the Decision when allowed so callers can attach it to audit events.
    """
    decision = decide(user, permission, settings)

    if decision.outcome == DecisionOutcome.ALLOWED:
        return decision

    raise PermissionDeniedError(
        "Insufficient permissions for this action.",
        details={
            "permission": decision.permission,
            "reason": decision.reason,
        },
    )


def ensure_any(
    user: Any,
    permissions: Sequence[Any],
    settings: Any,
) -> Decision:
    """
    Enforce that a user satisfies at least one of several permissions.

    Raises PermissionDeniedError when none are satisfied.
    """
    if not permissions:
        raise ConfigurationError("ensure_any() requires at least one permission.")

    decisions: list[Decision] = []

    for permission in permissions:
        decision = decide(user, permission, settings)

        if decision.allowed:
            return decision

        decisions.append(decision)

    raise PermissionDeniedError(
        "Insufficient permissions for this action.",
        details={
            "permissions": [decision.permission for decision in decisions],
            "reason": "no_permission_granted",
        },
    )


def ensure_role(user: Any, role: Any, settings: Any) -> Decision:
    """
    Enforce that a user has exactly the specified role.
    """
    if not _is_active_user(user):
        raise PermissionDeniedError(
            "Inactive users cannot perform this action.",
            details={"reason": "inactive_user"},
        )

    if has_role(user, role):
        return Decision(
            outcome=DecisionOutcome.ALLOWED,
            permission=f"role:{_normalize_role(role)}",
            user_role=_get_user_role(user),
            allowed_roles=(_normalize_role(role),),
            reason="role_granted",
            rbac_enabled=_rbac_enabled(settings),
            superuser_bypass=False,
        )

    raise PermissionDeniedError(
        "Insufficient role for this action.",
        details={
            "required_role": _normalize_role(role),
            "user_role": _get_user_role(user),
        },
    )


def ensure_role_at_least(user: Any, minimum_role: Any, settings: Any) -> Decision:
    """
    Enforce that a user has at least the authority of the specified role.
    """
    if not _is_active_user(user):
        raise PermissionDeniedError(
            "Inactive users cannot perform this action.",
            details={"reason": "inactive_user"},
        )

    if role_at_least(_get_user_role(user), minimum_role):
        return Decision(
            outcome=DecisionOutcome.ALLOWED,
            permission=f"role_at_least:{_normalize_role(minimum_role)}",
            user_role=_get_user_role(user),
            allowed_roles=(_normalize_role(minimum_role),),
            reason="role_granted",
            rbac_enabled=_rbac_enabled(settings),
            superuser_bypass=False,
        )

    raise PermissionDeniedError(
        "Insufficient role level for this action.",
        details={
            "minimum_role": _normalize_role(minimum_role),
            "user_role": _get_user_role(user),
        },
    )


# -----------------------------------------------------------------------------
# Capability helpers
# -----------------------------------------------------------------------------


def permitted_permissions(user: Any, settings: Any) -> tuple[str, ...]:
    """
    Return the tuple of permission identifiers a user is allowed to perform.

    This is useful for building safe capability metadata and for diagnostics.
    """
    allowed: list[str] = []

    for permission in Permission:
        if can(user, permission, settings):
            allowed.append(permission.value)

    return tuple(allowed)


def roles_for_permission(permission: Any, settings: Any) -> tuple[str, ...]:
    """
    Return the effective allowed roles for a permission.
    """
    return get_allowed_roles(permission, settings)


def all_permissions() -> tuple[str, ...]:
    """
    Return all known permission identifiers.
    """
    return tuple(permission.value for permission in Permission)


def all_roles() -> tuple[str, ...]:
    """
    Return all known role identifiers.
    """
    return ALL_ROLES


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "Decision",
    "DecisionOutcome",
    "Permission",
    "all_permissions",
    "all_roles",
    "can",
    "decide",
    "ensure",
    "ensure_any",
    "ensure_role",
    "ensure_role_at_least",
    "get_allowed_roles",
    "has_any_role",
    "has_role",
    "is_known_role",
    "permitted_permissions",
    "role_at_least",
    "role_rank",
    "roles_for_permission",
]