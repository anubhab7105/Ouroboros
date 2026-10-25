"""
MULEGUARD authentication schemas.

Request and response shapes for login, token issuance, and password change.

Rules enforced here:

- A password field is never echoed in any response. There is no response model
  in this module that contains one.
- Login failures do not distinguish "no such user" from "wrong password". The
  endpoint returns one message, because distinguishing them lets an attacker
  enumerate valid usernames.
- The access token response states its lifetime so a client can refresh before
  expiry rather than discovering it through a 401 mid-action.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Final, Optional

from pydantic import Field, SecretStr, field_validator

from app.schemas.common import MuleGuardModel, ResponseModel

__all__ = [
    "LoginRequest",
    "PasswordChangeRequest",
    "TokenResponse",
    "TokenPayloadSchema",
    "WhoAmIResponse",
]

# Deliberately permissive on input: policy is enforced by
# app.auth.passwords.validate_password_policy, which returns specific reasons.
# A regex here would reject with a useless message.
_PasswordField = Annotated[SecretStr, Field(min_length=1, max_length=256)]


class LoginRequest(MuleGuardModel):
    """
    Credentials for a login attempt.
    """

    username: str = Field(min_length=1, max_length=64, description="Login username.")
    password: _PasswordField = Field(description="Password. Never logged or echoed.")

    @field_validator("username")
    @classmethod
    def _normalise_username(cls, value: str) -> str:
        """
        Lower-case the username so login is case-insensitive.
        """
        return value.strip().lower()


class TokenResponse(ResponseModel):
    """
    An issued access token.
    """

    access_token: str = Field(description="Bearer token for the Authorization header.")
    token_type: str = Field(default="bearer", description="Always 'bearer'.")
    expires_in: int = Field(
        description="Lifetime in seconds, so a client can refresh before expiry."
    )
    expires_at: datetime = Field(description="Absolute expiry instant, UTC.")
    username: str = Field(description="Authenticated username.")
    role: str = Field(description="Role used for server-side authorisation.")
    must_change_password: bool = Field(
        default=False,
        description=(
            "True when the account must set a new password before doing "
            "anything else."
        ),
    )


class TokenPayloadSchema(ResponseModel):
    """
    Decoded token claims.

    Exposed for diagnostics. Authorisation decisions are made server-side from
    the database record, never from these claims alone: a token is only proof
    of authentication, and the role may have changed since it was issued.
    """

    subject: str = Field(description="User identifier the token was issued for.")
    username: Optional[str] = Field(default=None)
    role: Optional[str] = Field(default=None)
    issued_at: Optional[datetime] = Field(default=None)
    expires_at: Optional[datetime] = Field(default=None)
    token_id: Optional[str] = Field(default=None)


class WhoAmIResponse(ResponseModel):
    """
    The authenticated caller's identity and effective permissions.
    """

    id: str = Field(description="User identifier.")
    username: str = Field(description="Username.")
    email: str = Field(description="Email address.")
    full_name: Optional[str] = Field(default=None)
    role: str = Field(description="Assigned role.")
    permissions: list[str] = Field(
        default_factory=list,
        description=(
            "Effective permissions. The frontend uses these to hide controls; "
            "the backend enforces them independently on every request."
        ),
    )
    is_active: bool = Field(default=True)
    must_change_password: bool = Field(default=False)
    last_login_at: Optional[datetime] = Field(default=None)


class PasswordChangeRequest(MuleGuardModel):
    """
    A password change.

    The current password is required even for an authenticated session, so a
    stolen token cannot be used to lock the owner out of their own account.
    """

    current_password: _PasswordField = Field(description="The existing password.")
    new_password: _PasswordField = Field(description="The replacement password.")

    @field_validator("new_password")
    @classmethod
    def _not_same(cls, value: SecretStr, info: Any) -> SecretStr:
        """
        Reject a no-op change.
        """
        current = (info.data or {}).get("current_password")

        if (
            isinstance(current, SecretStr)
            and current.get_secret_value() == value.get_secret_value()
        ):
            raise ValueError("The new password must differ from the current one.")

        return value
