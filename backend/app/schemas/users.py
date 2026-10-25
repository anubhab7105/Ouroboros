"""
MULEGUARD user schemas.

`password_hash`, `last_login_ip_hash`, `failed_login_count` and `locked_until`
are absent from every response model here by design. None of them is useful to
a client, and the first two are security-relevant.

`is_locked` is exposed as a derived boolean instead of the lockout timestamp,
which is what an administrator actually needs to know.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Optional

from pydantic import EmailStr, Field, SecretStr, field_validator

from app.schemas.common import IdentifierField, MuleGuardModel, ResponseModel
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "UserCreateRequest",
    "UserListResponse",
    "UserResponse",
    "UserRoleUpdateRequest",
    "UserUpdateRequest",
    "AdminPasswordResetRequest",
]

_ROLES = ("ADMIN", "ANALYST", "SENIOR_INVESTIGATOR", "AUDITOR")

RoleField = Annotated[str, Field(pattern=f"^({'|'.join(_ROLES)})$")]


class UserResponse(ResponseModel):
    """
    A user, as returned to a client.
    """

    id: str = Field(description="User identifier.")
    username: str = Field(description="Login username.")
    email: str = Field(description="Email address.")
    full_name: Optional[str] = Field(default=None)
    role: str = Field(description="Assigned role.")
    is_active: bool = Field(description="Inactive users cannot authenticate.")
    must_change_password: bool = Field(default=False)
    is_locked: bool = Field(
        default=False,
        description=(
            "True while the account is temporarily locked after repeated "
            "failed logins. Exposed instead of the lockout timestamp."
        ),
    )
    last_login_at: Optional[datetime] = Field(default=None)
    created_at: Optional[datetime] = Field(default=None)


class UserListResponse(PaginatedResponse[UserResponse]):
    """
    A page of users.
    """


class UserCreateRequest(MuleGuardModel):
    """
    A new user account.
    """

    username: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9._-]+$",
        description="Unique username. Letters, digits, dot, underscore, dash.",
    )
    email: EmailStr = Field(description="Unique email address.")
    password: SecretStr = Field(
        min_length=1,
        max_length=256,
        description=(
            "Initial password. Validated against the configured policy, which "
            "returns specific reasons on failure."
        ),
    )
    full_name: Optional[str] = Field(default=None, max_length=200)
    role: RoleField = Field(default="ANALYST", description="Role for RBAC.")
    must_change_password: bool = Field(
        default=True,
        description=(
            "Defaults to true: an account created by an administrator should "
            "not keep a password that administrator knows."
        ),
    )

    @field_validator("username")
    @classmethod
    def _normalise(cls, value: str) -> str:
        return value.strip().lower()


class UserUpdateRequest(MuleGuardModel):
    """
    Editable user fields.

    Role changes go through `UserRoleUpdateRequest` so a privilege change is a
    distinct, separately audited action rather than a field in a general edit.
    """

    email: Optional[EmailStr] = Field(default=None)
    full_name: Optional[str] = Field(default=None, max_length=200)
    is_active: Optional[bool] = Field(default=None)


class UserRoleUpdateRequest(MuleGuardModel):
    """
    A role change.
    """

    role: RoleField = Field(description="The new role.")
    reason: str = Field(
        min_length=3,
        max_length=500,
        description=(
            "Why the role is changing. Required because a privilege change "
            "must be explicable in the audit trail."
        ),
    )


class AdminPasswordResetRequest(MuleGuardModel):
    """
    An administrative password reset.

    Does not require the current password, because the point is that the owner
    has lost it. `must_change_password` therefore defaults to true: the
    administrator who sets it must not keep a usable credential.
    """

    new_password: SecretStr = Field(min_length=1, max_length=256)
    must_change_password: bool = Field(default=True)
    reason: str = Field(min_length=3, max_length=500, description="Reason, for the audit trail.")
