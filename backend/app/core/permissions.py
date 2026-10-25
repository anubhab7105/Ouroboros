"""
MULEGUARD backend core permission model.

This module centralizes permission identifiers, default role grants, permission
metadata, and safe resolution helpers for the synthetic MULEGUARD prototype.

Primary responsibilities:

- define stable permission identifiers;
- describe each permission with category, sensitivity, and default role grants;
- resolve effective allowed roles for a permission from configuration overrides;
- provide role-to-permission and permission-to-role lookups;
- expose safe metadata for documentation, diagnostics, and tests;
- remain import-safe and avoid circular dependencies.

Relationship to other modules:

- `app.core.roles` defines role identity and hierarchy.
- `app.core.permissions` defines permission identity and metadata.
- `app.auth.rbac` enforces deny-by-default authorization decisions.

This module does not perform authorization decisions by itself. It provides the
policy data and helpers that enforcement layers consume.

Security and product-safety rules enforced here:

- Permissions are server-side concepts. Client-supplied claims must be verified
  against the persisted user record by authentication/authorization layers.
- Unknown permissions are rejected by validation helpers.
- Default grants follow least-privilege principles.
- Permission metadata never contains secrets, tokens, passwords, database URLs,
  raw complaint narratives, or real customer data.
- Permissions never trigger automatic adverse customer action.

Explicit non-goals:

- This module does not authenticate users.
- This module does not enforce authorization. Use `app.auth.rbac` for that.
- This module does not persist or mutate role assignments.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Permissions here describe
local operator capabilities only and must not be interpreted as real-world legal,
regulatory, or enforcement authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final, Optional

from app.core.roles import (
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
    normalize_role,
)
from app.exceptions import ValidationError


# -----------------------------------------------------------------------------
# Permission identifiers
# -----------------------------------------------------------------------------


class Permission(str, Enum):
    """
    Stable permission identifiers used across the MULEGUARD backend.

    Permission values are treated as public contract. Prefer adding new
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


class PermissionCategory(str, Enum):
    """
    Logical grouping for permissions.
    """

    ADMIN = "admin"
    READ = "read"
    ANALYSIS = "analysis"
    INGESTION = "ingestion"
    ALERT = "alert"
    GRAPH = "graph"
    COMPLAINT = "complaint"
    CASE = "case"
    REPORT = "report"
    AUDIT = "audit"
    MODEL = "model"


class PermissionSensitivity(str, Enum):
    """
    Sensitivity label used for documentation and audit posture.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# -----------------------------------------------------------------------------
# Permission metadata model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PermissionInfo:
    """
    Safe metadata describing one MULEGUARD permission.
    """

    name: str
    description: str
    category: PermissionCategory
    sensitivity: PermissionSensitivity
    default_roles: tuple[str, ...]
    mutation: bool = False
    auditable: bool = False
    requires_senior: bool = False
    requires_admin: bool = False

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable representation.
        """
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "sensitivity": self.sensitivity.value,
            "default_roles": list(self.default_roles),
            "mutation": self.mutation,
            "auditable": self.auditable,
            "requires_senior": self.requires_senior,
            "requires_admin": self.requires_admin,
        }


def _info(
    permission: Permission,
    *,
    description: str,
    category: PermissionCategory,
    sensitivity: PermissionSensitivity,
    default_roles: Sequence[str],
    mutation: bool = False,
    auditable: bool = False,
) -> PermissionInfo:
    """
    Build a PermissionInfo with derived senior/admin flags.
    """
    roles = tuple(default_roles)

    requires_admin = roles == ADMIN_ONLY
    requires_senior = (not requires_admin) and (
        set(roles) == set(SENIOR_AND_ADMIN)
        or set(roles) == set(AUDITOR_AND_ADMIN)
    )

    return PermissionInfo(
        name=permission.value,
        description=description,
        category=category,
        sensitivity=sensitivity,
        default_roles=roles,
        mutation=mutation,
        auditable=auditable,
        requires_senior=requires_senior,
        requires_admin=requires_admin,
    )


# -----------------------------------------------------------------------------
# Permission registry
# -----------------------------------------------------------------------------

PERMISSION_REGISTRY: Final[Mapping[str, PermissionInfo]] = {
    # User and configuration management
    Permission.USER_MANAGE.value: _info(
        Permission.USER_MANAGE,
        description="Manage local prototype users, roles, activation, and password resets.",
        category=PermissionCategory.ADMIN,
        sensitivity=PermissionSensitivity.HIGH,
        default_roles=ADMIN_ONLY,
        mutation=True,
        auditable=True,
    ),
    Permission.CONFIG_READ.value: _info(
        Permission.CONFIG_READ,
        description="Read safe runtime configuration metadata.",
        category=PermissionCategory.ADMIN,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ADMIN_ONLY,
    ),
    Permission.CONFIG_WRITE.value: _info(
        Permission.CONFIG_WRITE,
        description="Write runtime configuration. Not exposed by default in this prototype.",
        category=PermissionCategory.ADMIN,
        sensitivity=PermissionSensitivity.HIGH,
        default_roles=ADMIN_ONLY,
        mutation=True,
        auditable=True,
    ),

    # Read surfaces
    Permission.DASHBOARD_READ.value: _info(
        Permission.DASHBOARD_READ,
        description="Read operational dashboard aggregates.",
        category=PermissionCategory.READ,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),
    Permission.ACCOUNT_READ.value: _info(
        Permission.ACCOUNT_READ,
        description="Read synthetic account profiles and assessments.",
        category=PermissionCategory.READ,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),
    Permission.TRANSACTION_READ.value: _info(
        Permission.TRANSACTION_READ,
        description="Read synthetic transaction evidence.",
        category=PermissionCategory.READ,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),
    Permission.SEARCH.value: _info(
        Permission.SEARCH,
        description="Perform bounded investigative search.",
        category=PermissionCategory.READ,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),

    # Analysis and ingestion
    Permission.ANALYSIS_RUN.value: _info(
        Permission.ANALYSIS_RUN,
        description="Run bounded synthetic analysis batches.",
        category=PermissionCategory.ANALYSIS,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ANALYST_AND_ABOVE,
        mutation=True,
        auditable=True,
    ),
    Permission.INGESTION_WRITE.value: _info(
        Permission.INGESTION_WRITE,
        description="Ingest synthetic accounts, transactions, complaints, entities, and links.",
        category=PermissionCategory.INGESTION,
        sensitivity=PermissionSensitivity.HIGH,
        default_roles=ADMIN_ONLY,
        mutation=True,
        auditable=True,
    ),
    Permission.SEED_RESET.value: _info(
        Permission.SEED_RESET,
        description="Reset local synthetic demo data. Destructive and local-only.",
        category=PermissionCategory.INGESTION,
        sensitivity=PermissionSensitivity.HIGH,
        default_roles=ADMIN_ONLY,
        mutation=True,
        auditable=True,
    ),

    # Alerts
    Permission.ALERT_READ.value: _info(
        Permission.ALERT_READ,
        description="Read investigative alerts.",
        category=PermissionCategory.ALERT,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),
    Permission.ALERT_TRIAGE.value: _info(
        Permission.ALERT_TRIAGE,
        description="Acknowledge and triage alerts.",
        category=PermissionCategory.ALERT,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ANALYST_AND_ABOVE,
        mutation=True,
        auditable=True,
    ),
    Permission.ALERT_ASSIGN.value: _info(
        Permission.ALERT_ASSIGN,
        description="Assign alerts to investigators.",
        category=PermissionCategory.ALERT,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=SENIOR_AND_ADMIN,
        mutation=True,
        auditable=True,
    ),
    Permission.ALERT_ESCALATE.value: _info(
        Permission.ALERT_ESCALATE,
        description="Escalate alerts for senior review.",
        category=PermissionCategory.ALERT,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=SENIOR_AND_ADMIN,
        mutation=True,
        auditable=True,
    ),
    Permission.ALERT_CASE_CREATE.value: _info(
        Permission.ALERT_CASE_CREATE,
        description="Create an investigation case from an alert.",
        category=PermissionCategory.ALERT,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ANALYST_AND_ABOVE,
        mutation=True,
        auditable=True,
    ),

    # Graph and entities
    Permission.GRAPH_READ.value: _info(
        Permission.GRAPH_READ,
        description="Read bounded graph and entity association views.",
        category=PermissionCategory.GRAPH,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),
    Permission.GRAPH_EXPORT.value: _info(
        Permission.GRAPH_EXPORT,
        description="Export bounded graph views.",
        category=PermissionCategory.GRAPH,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ANALYST_AND_ABOVE,
        mutation=False,
        auditable=True,
    ),

    # Complaints
    Permission.COMPLAINT_READ.value: _info(
        Permission.COMPLAINT_READ,
        description="Read complaint metadata and correlations without narratives.",
        category=PermissionCategory.COMPLAINT,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),
    Permission.COMPLAINT_REVIEW.value: _info(
        Permission.COMPLAINT_REVIEW,
        description="Review complaint correlations and update review state.",
        category=PermissionCategory.COMPLAINT,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=SENIOR_AND_ADMIN,
        mutation=True,
        auditable=True,
    ),
    Permission.COMPLAINT_NARRATIVE_READ.value: _info(
        Permission.COMPLAINT_NARRATIVE_READ,
        description="Read complaint narratives where explicitly permitted.",
        category=PermissionCategory.COMPLAINT,
        sensitivity=PermissionSensitivity.HIGH,
        default_roles=SENIOR_AND_ADMIN,
    ),

    # Cases
    Permission.CASE_READ.value: _info(
        Permission.CASE_READ,
        description="Read investigation cases, evidence, notes, and events.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),
    Permission.CASE_CREATE.value: _info(
        Permission.CASE_CREATE,
        description="Create investigation cases.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ANALYST_AND_ABOVE,
        mutation=True,
        auditable=True,
    ),
    Permission.CASE_UPDATE.value: _info(
        Permission.CASE_UPDATE,
        description="Update non-material case attributes and start review.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ANALYST_AND_ABOVE,
        mutation=True,
        auditable=True,
    ),
    Permission.CASE_ASSIGN.value: _info(
        Permission.CASE_ASSIGN,
        description="Assign cases to investigators.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=SENIOR_AND_ADMIN,
        mutation=True,
        auditable=True,
    ),
    Permission.CASE_CLOSE.value: _info(
        Permission.CASE_CLOSE,
        description="Close cases with an investigator-entered disposition.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=SENIOR_AND_ADMIN,
        mutation=True,
        auditable=True,
    ),
    Permission.CASE_REOPEN.value: _info(
        Permission.CASE_REOPEN,
        description="Reopen closed cases.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=SENIOR_AND_ADMIN,
        mutation=True,
        auditable=True,
    ),
    Permission.CASE_NOTE_ADD.value: _info(
        Permission.CASE_NOTE_ADD,
        description="Append notes to a case.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ANALYST_AND_ABOVE,
        mutation=True,
        auditable=True,
    ),
    Permission.CASE_EVIDENCE_ADD.value: _info(
        Permission.CASE_EVIDENCE_ADD,
        description="Attach validated evidence to a case.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ANALYST_AND_ABOVE,
        mutation=True,
        auditable=True,
    ),
    Permission.CASE_EVIDENCE_REMOVE.value: _info(
        Permission.CASE_EVIDENCE_REMOVE,
        description="Deactivate case evidence references.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.HIGH,
        default_roles=SENIOR_AND_ADMIN,
        mutation=True,
        auditable=True,
    ),
    Permission.CASE_EXPORT.value: _info(
        Permission.CASE_EXPORT,
        description="Export bounded case bundles.",
        category=PermissionCategory.CASE,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=READ_ROLES,
        auditable=True,
    ),

    # Reports
    Permission.REPORT_READ.value: _info(
        Permission.REPORT_READ,
        description="Read report previews and limitations.",
        category=PermissionCategory.REPORT,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),
    Permission.REPORT_GENERATE.value: _info(
        Permission.REPORT_GENERATE,
        description="Generate investigation reports.",
        category=PermissionCategory.REPORT,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=ANALYST_AND_ABOVE,
        mutation=True,
        auditable=True,
    ),
    Permission.REPORT_DOWNLOAD.value: _info(
        Permission.REPORT_DOWNLOAD,
        description="Download generated investigation reports.",
        category=PermissionCategory.REPORT,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=READ_ROLES,
        auditable=True,
    ),

    # Audit
    Permission.AUDIT_READ.value: _info(
        Permission.AUDIT_READ,
        description="Read audit history.",
        category=PermissionCategory.AUDIT,
        sensitivity=PermissionSensitivity.MEDIUM,
        default_roles=AUDITOR_AND_ADMIN,
    ),
    Permission.AUDIT_EXPORT.value: _info(
        Permission.AUDIT_EXPORT,
        description="Export bounded audit history.",
        category=PermissionCategory.AUDIT,
        sensitivity=PermissionSensitivity.HIGH,
        default_roles=ADMIN_ONLY,
        auditable=True,
    ),

    # Model monitoring
    Permission.MODEL_MONITOR_READ.value: _info(
        Permission.MODEL_MONITOR_READ,
        description="Read model metrics and limitations.",
        category=PermissionCategory.MODEL,
        sensitivity=PermissionSensitivity.LOW,
        default_roles=READ_ROLES,
    ),
    Permission.MODEL_TRAIN.value: _info(
        Permission.MODEL_TRAIN,
        description="Train synthetic models. Not exposed as an API action by default.",
        category=PermissionCategory.MODEL,
        sensitivity=PermissionSensitivity.HIGH,
        default_roles=ADMIN_ONLY,
        mutation=True,
        auditable=True,
    ),
    Permission.MODEL_EVALUATE.value: _info(
        Permission.MODEL_EVALUATE,
        description="Evaluate synthetic models. Not exposed as an API action by default.",
        category=PermissionCategory.MODEL,
        sensitivity=PermissionSensitivity.HIGH,
        default_roles=ADMIN_ONLY,
        mutation=True,
        auditable=True,
    ),
}


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


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


def normalize_permission(value: Any) -> str:
    """
    Normalize a permission-like value to its stable string identifier.
    """
    enum_value = getattr(value, "value", None)

    if enum_value is not None:
        return str(enum_value)

    return str(value or "").strip()


def is_known_permission(value: Any) -> bool:
    """
    Return True when a value maps to a known permission.
    """
    return normalize_permission(value) in PERMISSION_REGISTRY


def validate_permission(value: Any) -> str:
    """
    Validate and normalize a permission value.

    Raises ValidationError for unknown or missing permissions.
    """
    normalized = normalize_permission(value)

    if not normalized:
        raise ValidationError(
            "Permission is required.",
            details={"reason": "missing_permission"},
        )

    if normalized not in PERMISSION_REGISTRY:
        raise ValidationError(
            "Permission is not recognized.",
            details={
                "reason": "unknown_permission",
                "allowed_permissions": sorted(PERMISSION_REGISTRY.keys()),
            },
        )

    return normalized


def get_permission_info(value: Any) -> PermissionInfo:
    """
    Return PermissionInfo for a permission value.

    Raises ValidationError for unknown permissions.
    """
    normalized = validate_permission(value)
    return PERMISSION_REGISTRY[normalized]


# -----------------------------------------------------------------------------
# Role resolution
# -----------------------------------------------------------------------------


def _permission_setting_names(permission_value: str) -> tuple[str, ...]:
    """
    Return possible environment setting names for a permission.
    """
    normalized = permission_value.strip().upper().replace("-", "_").replace(".", "_")

    return (
        f"{normalized}_ROLES",
        f"PERMISSION_{normalized}",
        f"RBAC_{normalized}_ROLES",
    )


def default_roles_for_permission(value: Any) -> tuple[str, ...]:
    """
    Return the built-in default roles for a permission.
    """
    info = get_permission_info(value)
    return info.default_roles


def resolve_roles_for_permission(
    value: Any,
    settings: Any | None = None,
) -> tuple[str, ...]:
    """
    Resolve effective allowed roles for a permission.

    Resolution order:

    1. explicit environment setting, e.g. CASE_CREATE_ROLES;
    2. PERMISSION_CASE_CREATE;
    3. RBAC_CASE_CREATE_ROLES;
    4. built-in default grant.

    When no roles resolve, an empty tuple is returned and enforcement layers
    should deny access.
    """
    info = get_permission_info(value)

    if settings is None:
        return info.default_roles

    for setting_name in _permission_setting_names(info.name):
        raw_value = _setting(settings, setting_name, None)

        if raw_value is not None:
            roles = tuple(
                normalize_role(item)
                for item in _csv(raw_value)
                if str(item).strip()
            )

            return roles

    return info.default_roles


# -----------------------------------------------------------------------------
# Lookup helpers
# -----------------------------------------------------------------------------


def list_permissions(
    *,
    category: Optional[PermissionCategory] = None,
    mutation: Optional[bool] = None,
    auditable: Optional[bool] = None,
) -> tuple[str, ...]:
    """
    Return known permission identifiers, optionally filtered.
    """
    results: list[str] = []

    for name, info in PERMISSION_REGISTRY.items():
        if category is not None and info.category != category:
            continue

        if mutation is not None and info.mutation != mutation:
            continue

        if auditable is not None and info.auditable != auditable:
            continue

        results.append(name)

    return tuple(sorted(results))


def permissions_for_role(
    role: Any,
    *,
    settings: Any | None = None,
    use_overrides: bool = False,
) -> tuple[str, ...]:
    """
    Return permissions granted to a role.

    When `use_overrides` is False, only built-in default grants are considered.
    When True, configuration overrides are resolved for every permission.
    """
    normalized_role = normalize_role(role)

    if not normalized_role:
        return ()

    granted: list[str] = []

    for name, info in PERMISSION_REGISTRY.items():
        if use_overrides:
            allowed_roles = resolve_roles_for_permission(name, settings)
        else:
            allowed_roles = info.default_roles

        if normalized_role in allowed_roles:
            granted.append(name)

    return tuple(sorted(granted))


def role_has_permission(
    role: Any,
    permission: Any,
    *,
    settings: Any | None = None,
    use_overrides: bool = False,
) -> bool:
    """
    Return True when a role is granted a permission.

    This is a policy lookup helper, not an authorization decision.
    """
    normalized_role = normalize_role(role)
    info = get_permission_info(permission)

    if use_overrides:
        allowed_roles = resolve_roles_for_permission(info.name, settings)
    else:
        allowed_roles = info.default_roles

    return normalized_role in allowed_roles


def permission_matrix(
    *,
    settings: Any | None = None,
    use_overrides: bool = False,
) -> dict[str, list[str]]:
    """
    Return a mapping of role -> granted permissions.
    """
    matrix: dict[str, list[str]] = {role: [] for role in ALL_ROLES}

    for name, info in PERMISSION_REGISTRY.items():
        if use_overrides:
            allowed_roles = resolve_roles_for_permission(name, settings)
        else:
            allowed_roles = info.default_roles

        for role in allowed_roles:
            if role in matrix:
                matrix[role].append(name)

    for role in matrix:
        matrix[role] = sorted(matrix[role])

    return matrix


def diff_role_permissions(
    higher_role: Any,
    lower_role: Any,
    *,
    settings: Any | None = None,
    use_overrides: bool = False,
) -> dict[str, tuple[str, ...]]:
    """
    Return permissions that differ between two roles.

    Useful for documentation and access reviews.
    """
    higher = set(
        permissions_for_role(higher_role, settings=settings, use_overrides=use_overrides)
    )
    lower = set(
        permissions_for_role(lower_role, settings=settings, use_overrides=use_overrides)
    )

    return {
        "only_in_higher": tuple(sorted(higher - lower)),
        "only_in_lower": tuple(sorted(lower - higher)),
        "shared": tuple(sorted(higher & lower)),
    }


# -----------------------------------------------------------------------------
# Metadata helpers
# -----------------------------------------------------------------------------


def get_permissions_metadata() -> list[dict[str, Any]]:
    """
    Return safe, serializable metadata for all known permissions.
    """
    return [info.to_dict() for info in PERMISSION_REGISTRY.values()]


def get_permission_categories() -> tuple[str, ...]:
    """
    Return all permission category identifiers.
    """
    return tuple(sorted(category.value for category in PermissionCategory))


def get_permission_sensitivity_levels() -> tuple[str, ...]:
    """
    Return all permission sensitivity identifiers.
    """
    return tuple(sorted(level.value for level in PermissionSensitivity))


__all__ = [
    "Permission",
    "PermissionCategory",
    "PermissionInfo",
    "PermissionSensitivity",
    "PERMISSION_REGISTRY",
    "default_roles_for_permission",
    "diff_role_permissions",
    "get_permission_categories",
    "get_permission_info",
    "get_permission_sensitivity_levels",
    "get_permissions_metadata",
    "is_known_permission",
    "list_permissions",
    "normalize_permission",
    "permission_matrix",
    "permissions_for_role",
    "resolve_roles_for_permission",
    "role_has_permission",
    "validate_permission",
]