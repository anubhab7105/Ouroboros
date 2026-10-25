"""
MULEGUARD backend user-management endpoints.

This module implements the versioned `/api/v1/users` administrative surface for
local MULEGUARD prototype users.

Implemented endpoints:

- GET    /api/v1/users
- POST   /api/v1/users
- GET    /api/v1/users/{user_id}
- PATCH  /api/v1/users/{user_id}
- POST   /api/v1/users/{user_id}/deactivate
- POST   /api/v1/users/{user_id}/reactivate
- POST   /api/v1/users/{user_id}/unlock
- POST   /api/v1/users/{user_id}/reset-password

Design goals:

- provide real, auditable administrative user management for the synthetic
  prototype;
- enforce server-side RBAC;
- prevent accidental removal of the last active administrator;
- prevent administrators from deactivating their own account;
- avoid user enumeration where practical;
- never return or log password hashes, plaintext passwords, tokens, secrets,
  database URLs, raw complaint narratives, or real customer data;
- support Argon2id password hashing where available, with bcrypt and
  PBKDF2-HMAC-SHA256 fallbacks;
- remain honest about unsupported features.

Explicit non-goals:

- This module does not manage real bank customers.
- This module does not connect to real identity providers.
- This module does not implement hard deletion because audit and case history
  integrity require soft state changes.
- This module does not implement fake logout, fake revocation, or fake
  self-service flows that are not backed by persisted state.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. These users are local
prototype operators, not real customers. Deactivation, role changes, and
password resets are administrative controls for the prototype only and must not
be interpreted as automatic adverse action against any real person or account.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import logging
import re
import secrets
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Annotated, Any, Final, Optional

from fastapi import APIRouter, Depends, Path, Query, Request
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    CurrentUser,
    PageParams,
    Permission,
    RequestIDDep,
    SearchParams,
    SessionDep,
    SettingsDep,
    apply_pagination,
    pagination_dependency,
    require_permission,
    search_dependency,
)
from app.exceptions import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError as MuleGuardValidationError,
)
from app.models import AuditEvent, AuditOutcome, User, UserRole


logger = logging.getLogger("muleguard.backend.api.v1.endpoints.users")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["users"])


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_USERNAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9._-]{3,64}$")

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
        "password_hash",
        "raw_payload",
        "refresh_token",
        "secret",
        "token",
    }
)

_COLUMN_MAP: Final[dict[str, Any]] = {
    "created_at": User.record_created_at,
    "updated_at": User.record_updated_at,
    "username": User.username,
    "email": User.email,
    "role": User.role,
    "is_active": User.is_active,
    "last_login_at": User.last_login_at,
}

_SORTABLE_FIELDS: Final[tuple[str, ...]] = tuple(_COLUMN_MAP.keys())


# -----------------------------------------------------------------------------
# Dependency aliases
# -----------------------------------------------------------------------------

user_pagination = pagination_dependency(
    sortable_fields=_SORTABLE_FIELDS,
    default_sort_by="created_at",
    default_sort_order="desc",
)

user_search = search_dependency(
    max_length=200,
    alias="q",
)

AdminUserDep = Annotated[User, Depends(require_permission(Permission.USER_MANAGE))]
UserPaginationDep = Annotated[PageParams, Depends(user_pagination)]
UserSearchDep = Annotated[SearchParams, Depends(user_search)]


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


def _normalize_role(value: Any) -> str:
    """
    Normalize a role-like value to an uppercase role string.
    """
    if isinstance(value, UserRole):
        return value.value

    return str(value).strip().upper().replace(" ", "_").replace("-", "_")


def _now_utc() -> datetime:
    """
    Return timezone-aware UTC current time.
    """
    return datetime.now(timezone.utc)


def _safe_secret(value: SecretStr | str | None) -> str:
    """
    Extract a secret string without relying on object repr.
    """
    if value is None:
        return ""

    if isinstance(value, SecretStr):
        return value.get_secret_value()

    return str(value)


def _contains_placeholder(value: str) -> bool:
    """
    Detect obvious template or placeholder secret values.
    """
    if not value:
        return True

    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _client_ip(request: Request, settings: Any) -> str:
    """
    Return a best-effort client IP.

    Proxy headers are trusted only when BACKEND_TRUST_PROXY_HEADERS=true.
    """
    trust_proxy = _as_bool(
        _setting(settings, "BACKEND_TRUST_PROXY_HEADERS", False),
        False,
    )

    if trust_proxy:
        forwarded_for = request.headers.get("X-Forwarded-For")

        if forwarded_for:
            first = forwarded_for.split(",", 1)[0].strip()

            if first:
                return first

        real_ip = request.headers.get("X-Real-IP")

        if real_ip:
            return real_ip.strip()

    if request.client and request.client.host:
        return request.client.host

    return ""


def _hash_salt(settings: Any) -> str:
    """
    Return a salt for non-secret hashing such as IP hashes.

    This is not used for password hashing.
    """
    return str(
        _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
        or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
        or _setting(settings, "BACKEND_SECRET_KEY", None)
        or "muleguard-users"
    )


def _hash_value(value: str, salt: str) -> str:
    """
    Return a stable SHA-256 hash for safe audit storage.
    """
    payload = f"{salt}:{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ip_hash(request: Request, settings: Any) -> Optional[str]:
    """
    Return a hashed client IP for audit storage, or None when disabled.
    """
    mode = str(
        _setting(settings, "PRIVACY_IP_LOG_MODE", "hashed")
    ).strip().lower()

    if mode in {"none", "off", "disabled"}:
        return None

    ip = _client_ip(request, settings)

    if not ip:
        return None

    return _hash_value(ip, _hash_salt(settings))


def _safe_metadata(metadata: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Return sanitized audit metadata.

    This intentionally avoids storing passwords, tokens, secrets, raw
    narratives, or unbounded object representations.
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
    request_id: Optional[str] = None,
    actor: Optional[User] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_hash: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> AuditEvent:
    """
    Add a safe audit event to the current session.

    The caller is responsible for committing the transaction.
    """
    event = AuditEvent(
        actor_id=str(actor.id) if actor is not None else None,
        actor_username=str(actor.username) if actor is not None else None,
        actor_role=_normalize_role(actor.role) if actor is not None else None,
        action=str(action)[:100],
        resource_type=str(resource_type)[:100] if resource_type is not None else None,
        resource_id=str(resource_id)[:128] if resource_id is not None else None,
        outcome=outcome,
        request_id=str(request_id)[:64] if request_id is not None else None,
        ip_hash=ip_hash,
        metadata_json=_safe_metadata(metadata),
    )

    db.add(event)
    return event


# -----------------------------------------------------------------------------
# Password hashing helpers
# -----------------------------------------------------------------------------


def _argon2_hasher(settings: Any) -> Any:
    """
    Construct an Argon2 hasher using configured parameters.
    """
    from argon2 import PasswordHasher

    time_cost = max(1, _as_int(_setting(settings, "AUTH_ARGON2_TIME_COST", 3), 3))
    memory_cost = max(
        1,
        _as_int(_setting(settings, "AUTH_ARGON2_MEMORY_COST_KIB", 65536), 65536),
    )
    parallelism = max(
        1,
        _as_int(_setting(settings, "AUTH_ARGON2_PARALLELISM", 2), 2),
    )

    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )


def _try_external_password_hash(password: str, settings: Any) -> Optional[str]:
    """
    Delegate password hashing to app.auth.passwords if implemented.
    """
    try:
        module = importlib.import_module("app.auth.passwords")
    except Exception:
        return None

    fn = getattr(module, "hash_password", None)

    if not callable(fn):
        return None

    attempts = (
        {"password": password, "settings": settings},
        {"password": password},
    )

    for kwargs in attempts:
        try:
            result = fn(**kwargs)
            return str(result)
        except TypeError:
            continue
        except Exception:
            logger.debug("External password hasher failed.", exc_info=True)
            return None

    try:
        result = fn(password, settings)
        return str(result)
    except TypeError:
        try:
            result = fn(password)
            return str(result)
        except Exception:
            logger.debug("External password hasher positional fallback failed.", exc_info=True)
            return None
    except Exception:
        logger.debug("External password hasher failed.", exc_info=True)
        return None


def _hash_password(password: str, settings: Any) -> str:
    """
    Hash a password using the strongest locally available scheme.

    Preference order:

    1. app.auth.passwords.hash_password, if implemented;
    2. Argon2id;
    3. bcrypt;
    4. PBKDF2-HMAC-SHA256.
    """
    if not password:
        raise ValueError("Password must not be empty.")

    external = _try_external_password_hash(password, settings)

    if external:
        return external

    try:
        hasher = _argon2_hasher(settings)
        return str(hasher.hash(password))
    except Exception:
        logger.debug("Argon2 password hashing unavailable; trying bcrypt.", exc_info=True)

    try:
        import bcrypt

        rounds = min(
            31,
            max(
                4,
                _as_int(_setting(settings, "AUTH_BCRYPT_ROUNDS", 12), 12),
            ),
        )

        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password.encode("utf-8")[:72], salt)
        return hashed.decode("utf-8")

    except Exception:
        logger.debug("bcrypt password hashing unavailable; using PBKDF2.", exc_info=True)

    iterations = min(
        10_000_000,
        max(
            10_000,
            _as_int(_setting(settings, "AUTH_PBKDF2_ITERATIONS", 390_000), 390_000),
        ),
    )

    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )

    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"


def _password_policy_errors(
    password: str,
    user: Optional[User],
    settings: Any,
) -> list[str]:
    """
    Return safe password policy violation labels.

    The labels are intentionally non-sensitive and do not echo the password.
    """
    errors: list[str] = []

    min_length = max(
        1,
        _as_int(_setting(settings, "AUTH_PASSWORD_MIN_LENGTH", 12), 12),
    )
    max_length = max(
        min_length,
        _as_int(_setting(settings, "AUTH_PASSWORD_MAX_LENGTH", 128), 128),
    )

    if len(password) < min_length:
        errors.append("too_short")

    if len(password) > max_length:
        errors.append("too_long")

    if _contains_placeholder(password):
        errors.append("placeholder_value")

    if _as_bool(_setting(settings, "AUTH_PASSWORD_REQUIRE_LOWERCASE", True), True):
        if not any(character.islower() for character in password):
            errors.append("missing_lowercase")

    if _as_bool(_setting(settings, "AUTH_PASSWORD_REQUIRE_UPPERCASE", True), True):
        if not any(character.isupper() for character in password):
            errors.append("missing_uppercase")

    if _as_bool(_setting(settings, "AUTH_PASSWORD_REQUIRE_DIGIT", True), True):
        if not any(character.isdigit() for character in password):
            errors.append("missing_digit")

    if _as_bool(_setting(settings, "AUTH_PASSWORD_REQUIRE_SPECIAL", True), True):
        if not any(
            not character.isalnum() and not character.isspace()
            for character in password
        ):
            errors.append("missing_special")

    if _as_bool(_setting(settings, "AUTH_PASSWORD_REQUIRE_NO_SPACES", False), False):
        if any(character.isspace() for character in password):
            errors.append("contains_space")

    if len(set(password)) <= 1:
        errors.append("too_repetitive")

    lowered_password = password.lower()
    forbidden_tokens: list[str] = []

    if user is not None:
        username = str(getattr(user, "username", "") or "").strip()

        if len(username) >= 3:
            forbidden_tokens.append(username.lower())

        email = str(getattr(user, "email", "") or "").strip()

        if "@" in email:
            local_part = email.split("@", 1)[0].strip()

            if len(local_part) >= 3:
                forbidden_tokens.append(local_part.lower())

    for token in forbidden_tokens:
        if token and token in lowered_password:
            errors.append("contains_user_identifier")
            break

    # Optional external policy hook.
    try:
        module = importlib.import_module("app.auth.passwords")
        fn = getattr(module, "validate_password_policy", None)

        if callable(fn):
            result: Any = None

            attempts = (
                {"password": password, "user": user, "settings": settings},
                {"password": password, "user": user},
                {"password": password},
            )

            for kwargs in attempts:
                try:
                    result = fn(**kwargs)
                    break
                except TypeError:
                    continue

            if result is None:
                try:
                    result = fn(password, user, settings)
                except TypeError:
                    try:
                        result = fn(password, user)
                    except TypeError:
                        try:
                            result = fn(password)
                        except Exception:
                            result = None

            if isinstance(result, Mapping):
                raw_errors = result.get("errors") or result.get("violations") or []

                if isinstance(raw_errors, (list, tuple, set)):
                    errors.extend(str(item) for item in raw_errors)
            elif isinstance(result, (list, tuple, set)):
                errors.extend(str(item) for item in result)
            elif isinstance(result, bool):
                if not result:
                    errors.append("external_policy_violation")

    except Exception:
        logger.debug("External password policy validator unavailable.", exc_info=True)

    seen: set[str] = set()
    unique_errors: list[str] = []

    for error in errors:
        if error not in seen:
            seen.add(error)
            unique_errors.append(error)

    return unique_errors


# -----------------------------------------------------------------------------
# Email/domain helpers
# -----------------------------------------------------------------------------


def _ensure_email_domain_allowed(email: str, settings: Any) -> None:
    """
    Enforce optional email domain allowlist for local prototype users.

    By default, no domain restriction is enforced. Deployments may set:

        USER_EMAIL_DOMAIN_ALLOWLIST=muleguard.local,example.test
    """
    allowlist_raw = _csv(_setting(settings, "USER_EMAIL_DOMAIN_ALLOWLIST", ""))

    if not allowlist_raw:
        return

    allowed = {domain.strip().lower() for domain in allowlist_raw if domain.strip()}

    if not allowed:
        return

    if "@" not in email:
        raise MuleGuardValidationError(
            "Email address is invalid.",
            details={"fields": [{"field": "email", "type": "invalid_email"}]},
        )

    domain = email.rsplit("@", 1)[-1].strip().lower()

    if domain not in allowed:
        raise MuleGuardValidationError(
            "Email domain is not allowed for local prototype users.",
            details={"fields": [{"field": "email", "type": "domain_not_allowed"}]},
        )


# -----------------------------------------------------------------------------
# Uniqueness helpers
# -----------------------------------------------------------------------------


def _ensure_username_available(
    db: Session,
    username: str,
    *,
    exclude_user_id: Optional[str] = None,
) -> None:
    stmt = select(User.id).where(User.username == username).limit(1)

    if exclude_user_id is not None:
        stmt = stmt.where(User.id != exclude_user_id)

    if db.scalar(stmt) is not None:
        raise ConflictError(
            "Username already exists.",
            details={"fields": [{"field": "username", "type": "unique_violation"}]},
        )


def _ensure_email_available(
    db: Session,
    email: str,
    *,
    exclude_user_id: Optional[str] = None,
) -> None:
    stmt = select(User.id).where(User.email == email).limit(1)

    if exclude_user_id is not None:
        stmt = stmt.where(User.id != exclude_user_id)

    if db.scalar(stmt) is not None:
        raise ConflictError(
            "Email already registered.",
            details={"fields": [{"field": "email", "type": "unique_violation"}]},
        )


# -----------------------------------------------------------------------------
# Administrator safety helpers
# -----------------------------------------------------------------------------


def _is_active_admin(user: User) -> bool:
    """
    Return True when the user is an active administrator.
    """
    return _normalize_role(user.role) == UserRole.ADMIN.value and bool(user.is_active)


def _count_active_admins(db: Session, *, exclude_user_id: Optional[str] = None) -> int:
    """
    Count active administrator users.

    This is used to prevent accidental removal of the last active administrator.
    """
    stmt = (
        select(func.count())
        .select_from(User)
        .where(User.role == UserRole.ADMIN, User.is_active.is_(True))
    )

    if exclude_user_id is not None:
        stmt = stmt.where(User.id != exclude_user_id)

    return int(db.scalar(stmt) or 0)


def _admin_retention_violation(
    db: Session,
    target: User,
    *,
    new_role: Optional[UserRole],
    new_is_active: Optional[bool],
    actor: User,
) -> Optional[str]:
    """
    Return a safe violation label when an operation would remove administrative
    capacity unsafely.

    Returns None when the operation is safe.
    """
    if not _is_active_admin(target):
        return None

    prospective_role = (
        _normalize_role(new_role)
        if new_role is not None
        else _normalize_role(target.role)
    )

    prospective_active = (
        bool(new_is_active)
        if new_is_active is not None
        else bool(target.is_active)
    )

    if prospective_role == UserRole.ADMIN.value and prospective_active:
        return None

    if actor.id == target.id:
        return "self_admin_removal"

    if _count_active_admins(db) <= 1:
        return "last_active_admin"

    return None


def _audit_denied_and_raise(
    db: Session,
    request: Request,
    settings: Any,
    request_id: str,
    actor: User,
    target: User,
    action: str,
    reason: str,
) -> None:
    """
    Persist a denied administrative action and raise the appropriate error.

    The audit event is committed before raising so that denied privileged
    actions remain durable even though the request fails.
    """
    _add_audit_event(
        db,
        action=action,
        outcome=AuditOutcome.DENIED,
        request_id=request_id,
        actor=actor,
        resource_type="user",
        resource_id=str(target.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "reason": reason,
            "target_role": _normalize_role(target.role),
            "target_is_active": bool(target.is_active),
        },
    )

    db.commit()

    if reason == "last_active_admin":
        raise ConflictError(
            "Cannot remove the last active administrator.",
            details={"reason": reason},
        )

    raise PermissionDeniedError(
        "This administrative action is prohibited to protect MULEGUARD operator access.",
        details={"reason": reason},
    )


# -----------------------------------------------------------------------------
# Response helpers
# -----------------------------------------------------------------------------


def _role_display_name(role: str, settings: Any) -> str:
    """
    Return a safe display name for a role.
    """
    normalized = _normalize_role(role)
    setting_name = f"ROLE_{normalized}_DISPLAY_NAME"
    configured = _setting(settings, setting_name, None)

    if configured:
        return str(configured).strip()

    return normalized.replace("_", " ").title()


def _user_response(user: User, settings: Any) -> "UserResponse":
    """
    Build a safe response payload from a persisted user.

    This must not include password hashes or other secrets.
    """
    role = _normalize_role(user.role)

    return UserResponse(
        id=str(user.id),
        username=str(user.username),
        email=str(user.email),
        full_name=str(user.full_name) if getattr(user, "full_name", None) else None,
        role=role,
        role_display_name=_role_display_name(role, settings),
        is_active=bool(getattr(user, "is_active", False)),
        must_change_password=bool(getattr(user, "must_change_password", False)),
        failed_login_count=int(getattr(user, "failed_login_count", 0) or 0),
        locked_until=getattr(user, "locked_until", None),
        last_login_at=getattr(user, "last_login_at", None),
        created_at=getattr(user, "record_created_at", None),
        updated_at=getattr(user, "record_updated_at", None),
    )


def _get_user_or_404(db: Session, user_id: str) -> User:
    """
    Load a user or raise a safe not-found error.
    """
    user = db.get(User, user_id)

    if user is None:
        raise NotFoundError.resource("user", user_id)

    return user


# -----------------------------------------------------------------------------
# Pydantic schemas
# -----------------------------------------------------------------------------


class UserResponse(BaseModel):
    """
    Safe user profile response.

    This response must not include password hashes, tokens, secrets, or raw
    sensitive narratives.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    role_display_name: str
    is_active: bool
    must_change_password: bool
    failed_login_count: int
    locked_until: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class UserListResponse(BaseModel):
    """
    Paginated user list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[UserResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"


class CreateUserRequest(BaseModel):
    """
    Administrative request to create a local prototype user.
    """

    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        min_length=3,
        max_length=64,
        description="Unique local username.",
        examples=["analyst"],
    )
    email: EmailStr = Field(
        description="Unique local email address.",
        examples=["analyst@muleguard.local"],
    )
    password: SecretStr = Field(
        description="Initial local password. Never use real credentials.",
    )
    full_name: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Optional display name.",
    )
    role: UserRole = Field(
        default=UserRole.ANALYST,
        description="Initial role for the local prototype user.",
    )
    must_change_password: Optional[bool] = Field(
        default=None,
        description=(
            "Whether the user must change the password on next login. "
            "Defaults to configured policy."
        ),
    )

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        normalized = str(value).strip().lower()

        if not normalized:
            raise ValueError("username must not be empty")

        if not _USERNAME_RE.match(normalized):
            raise ValueError(
                "username may contain lowercase letters, digits, dot, underscore, and hyphen"
            )

        return normalized

    @field_validator("password")
    @classmethod
    def _validate_password(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()

        if not secret:
            raise ValueError("password must not be empty")

        if len(secret) > 1024:
            raise ValueError("password is too long")

        return value


class UpdateUserRequest(BaseModel):
    """
    Administrative request to update a local prototype user.

    Password changes are intentionally handled through the dedicated
    reset-password endpoint.
    """

    model_config = ConfigDict(extra="forbid")

    email: Optional[EmailStr] = Field(
        default=None,
        description="Updated local email address.",
    )
    full_name: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Updated display name. Use null to clear.",
    )
    role: Optional[UserRole] = Field(
        default=None,
        description="Updated role.",
    )
    is_active: Optional[bool] = Field(
        default=None,
        description="Updated active status.",
    )
    must_change_password: Optional[bool] = Field(
        default=None,
        description="Whether the user must change password on next login.",
    )

    @model_validator(mode="after")
    def _validate_update_payload(self) -> "UpdateUserRequest":
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")

        for name in ("email", "role", "is_active", "must_change_password"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} must not be null.")

        return self


class ResetPasswordRequest(BaseModel):
    """
    Administrative password reset request.
    """

    model_config = ConfigDict(extra="forbid")

    new_password: SecretStr = Field(
        description="New local password satisfying configured policy.",
    )
    force_change: Optional[bool] = Field(
        default=None,
        description=(
            "Whether the user must change the password on next login. "
            "Defaults to configured policy."
        ),
    )

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()

        if not secret:
            raise ValueError("new_password must not be empty")

        if len(secret) > 1024:
            raise ValueError("new_password is too long")

        return value


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "",
    response_model=UserListResponse,
    summary="List local prototype users",
    description=(
        "Returns a paginated list of local MULEGUARD prototype users. "
        "This endpoint is administrative and must not be used to manage real "
        "bank customers."
    ),
)
def list_users(
    db: SessionDep,
    settings: SettingsDep,
    params: UserPaginationDep,
    search: UserSearchDep,
    admin_user: AdminUserDep,
    role: Annotated[
        Optional[UserRole],
        Query(description="Filter by role."),
    ] = None,
    is_active: Annotated[
        Optional[bool],
        Query(description="Filter by active status."),
    ] = None,
) -> UserListResponse:
    """
    List users with bounded pagination, stable ordering, and safe filters.
    """
    conditions: list[Any] = []

    if role is not None:
        conditions.append(User.role == role)

    if is_active is not None:
        conditions.append(User.is_active == is_active)

    if search.q:
        pattern = f"%{search.q.lower()}%"
        conditions.append(
            or_(
                func.lower(User.username).like(pattern),
                func.lower(User.email).like(pattern),
                func.lower(User.full_name).like(pattern),
            )
        )

    whereclause = and_(*conditions) if conditions else None

    count_stmt = select(func.count()).select_from(User)

    if whereclause is not None:
        count_stmt = count_stmt.where(whereclause)

    total = int(db.scalar(count_stmt) or 0)

    stmt = select(User)

    if whereclause is not None:
        stmt = stmt.where(whereclause)

    stmt = apply_pagination(
        stmt,
        params,
        column_map=_COLUMN_MAP,
        tiebreaker=User.id,
        default_sort_by="created_at",
        default_sort_order="desc",
    )

    users = db.scalars(stmt).all()

    total_pages = (
        (total + params.page_size - 1) // params.page_size
        if total > 0
        else 0
    )

    return UserListResponse(
        items=[_user_response(user, settings) for user in users],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=total_pages,
        sort_by=params.sort_by,
        sort_order=params.sort_order,
    )


@router.post(
    "",
    response_model=UserResponse,
    status_code=201,
    summary="Create a local prototype user",
    description=(
        "Creates a local MULEGUARD prototype user. "
        "This endpoint is administrative and must not be used to create real "
        "customer accounts."
    ),
)
def create_user(
    payload: CreateUserRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    admin_user: AdminUserDep,
    request_id: RequestIDDep,
) -> UserResponse:
    """
    Create a new local prototype user.
    """
    username = payload.username.strip().lower()
    email = str(payload.email).strip().lower()
    password = _safe_secret(payload.password)

    if not _USERNAME_RE.match(username):
        raise MuleGuardValidationError(
            "Username is invalid.",
            details={
                "fields": [
                    {
                        "field": "username",
                        "type": "invalid_username",
                        "message": "Username format is invalid.",
                    }
                ]
            },
        )

    policy_errors = _password_policy_errors(password, None, settings)

    if policy_errors:
        raise MuleGuardValidationError(
            "Password does not satisfy configured policy.",
            details={
                "fields": [
                    {
                        "field": "password",
                        "type": "policy_violation",
                        "message": ", ".join(policy_errors),
                    }
                ]
            },
        )

    _ensure_email_domain_allowed(email, settings)
    _ensure_username_available(db, username)
    _ensure_email_available(db, email)

    must_change_password = (
        payload.must_change_password
        if payload.must_change_password is not None
        else _as_bool(
            _setting(settings, "USER_FORCE_PASSWORD_CHANGE_FOR_CREATED_USERS", True),
            True,
        )
    )

    full_name = payload.full_name.strip() if payload.full_name else None

    user = User(
        username=username,
        email=email,
        full_name=full_name,
        role=payload.role,
        password_hash=_hash_password(password, settings),
        is_active=True,
        must_change_password=must_change_password,
        failed_login_count=0,
    )

    db.add(user)
    db.flush()

    _add_audit_event(
        db,
        action="user_create",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=admin_user,
        resource_type="user",
        resource_id=str(user.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "role": _normalize_role(user.role),
            "is_active": bool(user.is_active),
            "must_change_password": bool(user.must_change_password),
        },
    )

    db.commit()
    db.refresh(user)

    return _user_response(user, settings)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get a local prototype user",
    description=(
        "Returns safe profile metadata for one local MULEGUARD prototype user. "
        "Password hashes are never returned."
    ),
)
def get_user(
    user_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="User identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    admin_user: AdminUserDep,
) -> UserResponse:
    """
    Retrieve one user by ID.
    """
    user = _get_user_or_404(db, user_id)
    return _user_response(user, settings)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update a local prototype user",
    description=(
        "Updates safe administrative attributes for a local MULEGUARD prototype "
        "user. Password changes must use the dedicated reset-password endpoint."
    ),
)
def update_user(
    user_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="User identifier."),
    ],
    payload: UpdateUserRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    admin_user: AdminUserDep,
    request_id: RequestIDDep,
) -> UserResponse:
    """
    Update a user.
    """
    user = _get_user_or_404(db, user_id)

    changes = payload.model_dump(exclude_unset=True)

    if not changes:
        raise MuleGuardValidationError(
            "At least one field must be provided.",
            details={
                "fields": [
                    {
                        "field": "body",
                        "type": "missing",
                        "message": "At least one field must be provided.",
                    }
                ]
            },
        )

    new_email: Optional[str] = None

    if "email" in changes:
        new_email = str(changes["email"]).strip().lower()

        if new_email != user.email:
            _ensure_email_available(db, new_email, exclude_user_id=str(user.id))

    new_role: Optional[UserRole] = changes.get("role")
    new_is_active: Optional[bool] = changes.get("is_active")

    if new_is_active is False and admin_user.id == user.id:
        _audit_denied_and_raise(
            db=db,
            request=request,
            settings=settings,
            request_id=request_id,
            actor=admin_user,
            target=user,
            action="user_update_denied",
            reason="self_deactivation",
        )

    violation = _admin_retention_violation(
        db,
        user,
        new_role=new_role,
        new_is_active=new_is_active,
        actor=admin_user,
    )

    if violation:
        _audit_denied_and_raise(
            db=db,
            request=request,
            settings=settings,
            request_id=request_id,
            actor=admin_user,
            target=user,
            action="user_update_denied",
            reason=violation,
        )

    if new_email is not None:
        user.email = new_email

    if "full_name" in changes:
        raw_full_name = changes["full_name"]
        user.full_name = str(raw_full_name).strip() if raw_full_name is not None else None

    if new_role is not None:
        user.role = new_role

    if new_is_active is not None:
        was_active = bool(user.is_active)
        user.is_active = bool(new_is_active)

        if bool(new_is_active) and not was_active:
            user.failed_login_count = 0
            user.locked_until = None

    if "must_change_password" in changes:
        user.must_change_password = bool(changes["must_change_password"])

    _add_audit_event(
        db,
        action="user_update",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=admin_user,
        resource_type="user",
        resource_id=str(user.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "changed_fields": sorted(changes.keys()),
            "role": _normalize_role(user.role),
            "is_active": bool(user.is_active),
            "must_change_password": bool(user.must_change_password),
        },
    )

    db.commit()
    db.refresh(user)

    return _user_response(user, settings)


@router.post(
    "/{user_id}/deactivate",
    response_model=UserResponse,
    summary="Deactivate a local prototype user",
    description=(
        "Marks a local MULEGUARD prototype user as inactive. "
        "Inactive users must not be able to authenticate. "
        "This is an administrative prototype control, not an adverse action "
        "against a real customer."
    ),
)
def deactivate_user(
    user_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="User identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    admin_user: AdminUserDep,
    request_id: RequestIDDep,
) -> UserResponse:
    """
    Deactivate a user.
    """
    user = _get_user_or_404(db, user_id)

    if admin_user.id == user.id:
        _audit_denied_and_raise(
            db=db,
            request=request,
            settings=settings,
            request_id=request_id,
            actor=admin_user,
            target=user,
            action="user_deactivate_denied",
            reason="self_deactivation",
        )

    if not user.is_active:
        return _user_response(user, settings)

    violation = _admin_retention_violation(
        db,
        user,
        new_role=None,
        new_is_active=False,
        actor=admin_user,
    )

    if violation:
        _audit_denied_and_raise(
            db=db,
            request=request,
            settings=settings,
            request_id=request_id,
            actor=admin_user,
            target=user,
            action="user_deactivate_denied",
            reason=violation,
        )

    user.is_active = False

    _add_audit_event(
        db,
        action="user_deactivate",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=admin_user,
        resource_type="user",
        resource_id=str(user.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "role": _normalize_role(user.role),
            "is_active": False,
        },
    )

    db.commit()
    db.refresh(user)

    return _user_response(user, settings)


@router.post(
    "/{user_id}/reactivate",
    response_model=UserResponse,
    summary="Reactivate a local prototype user",
    description=(
        "Marks a local MULEGUARD prototype user as active and clears temporary "
        "login lockout state."
    ),
)
def reactivate_user(
    user_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="User identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    admin_user: AdminUserDep,
    request_id: RequestIDDep,
) -> UserResponse:
    """
    Reactivate a user.
    """
    user = _get_user_or_404(db, user_id)

    if user.is_active:
        return _user_response(user, settings)

    user.is_active = True
    user.failed_login_count = 0
    user.locked_until = None

    _add_audit_event(
        db,
        action="user_reactivate",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=admin_user,
        resource_type="user",
        resource_id=str(user.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "role": _normalize_role(user.role),
            "is_active": True,
        },
    )

    db.commit()
    db.refresh(user)

    return _user_response(user, settings)


@router.post(
    "/{user_id}/unlock",
    response_model=UserResponse,
    summary="Unlock a local prototype user",
    description=(
        "Clears failed-login counters and temporary lockout for a local "
        "MULEGUARD prototype user without changing active status."
    ),
)
def unlock_user(
    user_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="User identifier."),
    ],
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    admin_user: AdminUserDep,
    request_id: RequestIDDep,
) -> UserResponse:
    """
    Unlock a user.
    """
    user = _get_user_or_404(db, user_id)

    user.failed_login_count = 0
    user.locked_until = None

    _add_audit_event(
        db,
        action="user_unlock",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=admin_user,
        resource_type="user",
        resource_id=str(user.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "role": _normalize_role(user.role),
            "is_active": bool(user.is_active),
        },
    )

    db.commit()
    db.refresh(user)

    return _user_response(user, settings)


@router.post(
    "/{user_id}/reset-password",
    response_model=UserResponse,
    summary="Reset a local prototype user password",
    description=(
        "Administratively resets the password for a local MULEGUARD prototype "
        "user. This endpoint does not return the password and does not log it."
    ),
)
def reset_password(
    user_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="User identifier."),
    ],
    payload: ResetPasswordRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    admin_user: AdminUserDep,
    request_id: RequestIDDep,
) -> UserResponse:
    """
    Reset a user's password.
    """
    user = _get_user_or_404(db, user_id)

    password = _safe_secret(payload.new_password)

    policy_errors = _password_policy_errors(password, user, settings)

    if policy_errors:
        raise MuleGuardValidationError(
            "New password does not satisfy configured policy.",
            details={
                "fields": [
                    {
                        "field": "new_password",
                        "type": "policy_violation",
                        "message": ", ".join(policy_errors),
                    }
                ]
            },
        )

    user.password_hash = _hash_password(password, settings)
    user.must_change_password = (
        payload.force_change
        if payload.force_change is not None
        else _as_bool(
            _setting(settings, "USER_FORCE_PASSWORD_CHANGE_AFTER_RESET", True),
            True,
        )
    )

    user.failed_login_count = 0
    user.locked_until = None

    _add_audit_event(
        db,
        action="user_password_reset",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=admin_user,
        resource_type="user",
        resource_id=str(user.id),
        ip_hash=_ip_hash(request, settings),
        metadata={
            "role": _normalize_role(user.role),
            "is_active": bool(user.is_active),
            "must_change_password": bool(user.must_change_password),
        },
    )

    db.commit()
    db.refresh(user)

    return _user_response(user, settings)


__all__ = [
    "router",
]