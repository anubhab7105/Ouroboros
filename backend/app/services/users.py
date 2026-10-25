"""
MULEGUARD user service.

Creates and maintains local prototype user accounts.

Password handling is delegated entirely to `app.auth.passwords`, which uses a
slow KDF. Nothing in this module ever stores, logs, returns, or compares a
plaintext password, and `password_hash` is never included in any payload this
module produces.

Account lockout is a read-and-clear operation rather than a scheduled job:
`locked_until` is compared on each authentication attempt, so a lock expires
without anything having to run.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any, Final, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.exceptions import ConflictError, NotFoundError, ValidationError
from app.models import User, UserRole
from app.utils.dates import ensure_utc, utcnow
from app.utils.hashing import hash_identifier
from app.utils.text import clean_text

logger = logging.getLogger("muleguard.backend.services.users")

__all__ = [
    "USERS_SERVICE_VERSION",
    "clear_lockout",
    "create_user",
    "deactivate_user",
    "get_user_by_username",
    "get_users_service_metadata",
    "is_locked",
    "list_users",
    "public_user_payload",
    "record_failed_login",
    "record_successful_login",
    "set_password",
    "set_role",
]

USERS_SERVICE_VERSION: Final[str] = "v1"

_MAX_FAILED_ATTEMPTS: Final[int] = 5
_LOCKOUT_MINUTES: Final[int] = 15
_MAX_USERS_PAGE: Final[int] = 200


def _hash_password(raw: str) -> str:
    """
    Hash a password with the configured KDF.
    """
    from app.auth.passwords import hash_password, validate_password_policy

    problems = validate_password_policy(raw)

    if problems:
        raise ValidationError(
            "Password does not meet the configured policy.",
            details={"problems": list(problems)[:10]},
        )

    return hash_password(raw)


def create_user(
    db: Session,
    *,
    username: str,
    email: str,
    password: str,
    role: UserRole = UserRole.ANALYST,
    full_name: Optional[str] = None,
    is_active: bool = True,
    must_change_password: bool = False,
) -> User:
    """
    Create a user account.

    Raises ConflictError when the username or email already exists, checked
    before insert so the caller gets a readable message rather than an
    integrity error.
    """
    cleaned_username = clean_text(username, 64).lower()
    cleaned_email = clean_text(email, 320).lower()

    if not cleaned_username:
        raise ValidationError("Username is required.")

    if not cleaned_email or "@" not in cleaned_email:
        raise ValidationError("A valid email address is required.")

    clash = db.execute(
        select(User)
        .where(
            or_(User.username == cleaned_username, User.email == cleaned_email)
        )
        .limit(1)
    ).scalars().first()

    if clash is not None:
        field = "username" if clash.username == cleaned_username else "email"
        raise ConflictError(
            f"A user with this {field} already exists.",
            details={"field": field},
        )

    user = User(
        username=cleaned_username,
        email=cleaned_email,
        full_name=clean_text(full_name or "", 200) or None,
        role=role if isinstance(role, UserRole) else UserRole.ANALYST,
        password_hash=_hash_password(password),
        is_active=bool(is_active),
        must_change_password=bool(must_change_password),
        failed_login_count=0,
    )
    db.add(user)
    db.flush()

    logger.info(
        "Created user %s with role %s", cleaned_username, user.role.value
    )
    return user


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """
    Look up a user by username, case-insensitively.
    """
    cleaned = clean_text(username, 64).lower()

    if not cleaned:
        return None

    return db.execute(
        select(User).where(func.lower(User.username) == cleaned).limit(1)
    ).scalars().first()


def set_password(
    db: Session,
    *,
    user_id: str,
    new_password: str,
    must_change: bool = False,
) -> User:
    """
    Replace a user's password hash.

    Resets the failed-attempt counter and clears any lockout: a successful
    password change is evidence the legitimate owner has control.
    """
    user = db.get(User, str(user_id))

    if user is None:
        raise NotFoundError("User not found.", details={"user_id": str(user_id)[:64]})

    user.password_hash = _hash_password(new_password)
    user.must_change_password = bool(must_change)
    user.failed_login_count = 0
    user.locked_until = None
    db.flush()
    return user


def set_role(db: Session, *, user_id: str, role: UserRole) -> User:
    """
    Change a user's role.
    """
    user = db.get(User, str(user_id))

    if user is None:
        raise NotFoundError("User not found.", details={"user_id": str(user_id)[:64]})

    user.role = role if isinstance(role, UserRole) else UserRole.ANALYST
    db.flush()
    return user


def deactivate_user(db: Session, *, user_id: str) -> User:
    """
    Deactivate a user.

    Deactivation rather than deletion: audit events and case history reference
    the user, and removing the row would leave that history unattributed.
    """
    user = db.get(User, str(user_id))

    if user is None:
        raise NotFoundError("User not found.", details={"user_id": str(user_id)[:64]})

    user.is_active = False
    db.flush()
    return user


def is_locked(user: User, *, as_of: Optional[datetime] = None) -> bool:
    """
    Return True when a user is currently locked out.
    """
    locked_until = ensure_utc(user.locked_until)

    if locked_until is None:
        return False

    return locked_until > (ensure_utc(as_of) or utcnow())


def record_failed_login(
    db: Session,
    *,
    user: User,
    max_attempts: int = _MAX_FAILED_ATTEMPTS,
    lockout_minutes: int = _LOCKOUT_MINUTES,
) -> User:
    """
    Increment the failed-attempt counter and lock the account at the threshold.
    """
    user.failed_login_count = int(user.failed_login_count or 0) + 1

    if user.failed_login_count >= max(1, int(max_attempts)):
        user.locked_until = utcnow() + timedelta(minutes=max(1, int(lockout_minutes)))
        logger.warning(
            "User %s locked until %s after %d failed attempts",
            user.username,
            user.locked_until.isoformat(),
            user.failed_login_count,
        )

    db.flush()
    return user


def record_successful_login(
    db: Session,
    *,
    user: User,
    ip_address: Optional[str] = None,
    salt: Optional[str] = None,
) -> User:
    """
    Record a successful login and clear the failure state.

    The source IP is stored hashed, never raw.
    """
    user.last_login_at = utcnow()
    user.failed_login_count = 0
    user.locked_until = None

    if ip_address:
        user.last_login_ip_hash = hash_identifier(ip_address, salt=salt, kind="ip")

    db.flush()
    return user


def clear_lockout(db: Session, *, user_id: str) -> User:
    """
    Clear a lockout administratively.
    """
    user = db.get(User, str(user_id))

    if user is None:
        raise NotFoundError("User not found.", details={"user_id": str(user_id)[:64]})

    user.locked_until = None
    user.failed_login_count = 0
    db.flush()
    return user


def list_users(
    db: Session,
    *,
    roles: Optional[Sequence[UserRole]] = None,
    active_only: bool = False,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[User], int]:
    """
    Return a page of users and the total matching count.
    """
    conditions: list[Any] = []

    if roles:
        conditions.append(User.role.in_(list(roles)))

    if active_only:
        conditions.append(User.is_active.is_(True))

    if search:
        pattern = f"%{clean_text(search, 100).lower()}%"
        conditions.append(
            or_(
                func.lower(User.username).like(pattern),
                func.lower(User.email).like(pattern),
                func.lower(User.full_name).like(pattern),
            )
        )

    count_stmt = select(func.count()).select_from(User)
    page_stmt = select(User)

    for condition in conditions:
        count_stmt = count_stmt.where(condition)
        page_stmt = page_stmt.where(condition)

    total = int(db.execute(count_stmt).scalar() or 0)
    page_stmt = (
        page_stmt.order_by(User.username)
        .offset(max(0, int(offset)))
        .limit(max(1, min(int(limit), _MAX_USERS_PAGE)))
    )
    return list(db.execute(page_stmt).scalars()), total


def public_user_payload(user: User) -> dict[str, Any]:
    """
    Return the safe representation of a user.

    `password_hash`, `last_login_ip_hash`, and the lockout timestamp are
    deliberately excluded: none of them belongs in a response.
    """
    return {
        "id": str(user.id),
        "username": str(user.username),
        "email": str(user.email),
        "full_name": user.full_name,
        "role": user.role.value,
        "is_active": bool(user.is_active),
        "must_change_password": bool(user.must_change_password),
        "last_login_at": (
            ensure_utc(user.last_login_at).isoformat() if user.last_login_at else None
        ),
        "is_locked": is_locked(user),
    }


def get_users_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the user service.
    """
    return {
        "service": "muleguard.backend.services.users",
        "version": USERS_SERVICE_VERSION,
        "roles": [item.value for item in UserRole],
        "lockout": {
            "max_failed_attempts": _MAX_FAILED_ATTEMPTS,
            "lockout_minutes": _LOCKOUT_MINUTES,
            "expiry": "checked on each attempt; no scheduled job required",
        },
        "guarantees": [
            "Passwords are hashed by app.auth.passwords with a slow KDF.",
            "No plaintext password is ever stored, logged, or returned.",
            "password_hash is never included in a response payload.",
            "Users are deactivated rather than deleted, so audit history stays "
            "attributed.",
            "Login source IPs are stored hashed.",
        ],
    }
