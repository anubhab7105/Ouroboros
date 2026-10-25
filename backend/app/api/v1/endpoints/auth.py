"""
MULEGUARD backend authentication endpoints.

This module implements the versioned `/api/v1/auth` authentication surface.

Implemented endpoints:

- POST /api/v1/auth/login
- GET  /api/v1/auth/me
- POST /api/v1/auth/password/change

Design goals:

- issue local JWT bearer tokens for the synthetic prototype;
- enforce server-side authentication and authorization;
- avoid user enumeration where practical;
- apply login throttling and temporary lockout;
- store only safe audit metadata;
- never log or return passwords, tokens, secrets, database URLs, raw complaint
  narratives, or real customer data;
- support Argon2id password hashing where available, with bcrypt and
  PBKDF2-HMAC-SHA256 fallbacks;
- remain honest about unsupported features.

Explicit non-goals:

- This module does not implement refresh tokens because no persistent token
  revocation store is part of the current prototype schema.
- This module does not implement logout as a fake success response. Stateless
  JWT logout requires a reviewed revocation backend first.
- This module does not connect to real identity providers, banks, payment rails,
  or customer systems.
- This module does not enable automatic adverse customer action.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Authentication here is
for local demo and test workflows only. Production-like deployments must replace
or harden this authentication layer before exposure.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import logging
import secrets
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Final, NoReturn, Optional

import jwt
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    CurrentUser,
    RequestIDDep,
    SessionDep,
    SettingsDep,
    rate_limited,
)
from app.exceptions import (
    ConfigurationError,
    InvalidCredentialsError,
    UnsupportedActionError,
    UserInactiveError,
    UserLockedError,
    ValidationError as MuleGuardValidationError,
)
from app.models import AuditEvent, AuditOutcome, User, UserRole

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.auth")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["auth"])


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

_ALL_ROLES: Final[tuple[str, ...]] = (
    UserRole.ADMIN.value,
    UserRole.ANALYST.value,
    UserRole.SENIOR_INVESTIGATOR.value,
    UserRole.AUDITOR.value,
)

_READ_ROLES: Final[tuple[str, ...]] = _ALL_ROLES

_ANALYST_AND_ABOVE: Final[tuple[str, ...]] = (
    UserRole.ANALYST.value,
    UserRole.SENIOR_INVESTIGATOR.value,
    UserRole.ADMIN.value,
)

_SENIOR_AND_ADMIN: Final[tuple[str, ...]] = (
    UserRole.SENIOR_INVESTIGATOR.value,
    UserRole.ADMIN.value,
)

_ADMIN_ONLY: Final[tuple[str, ...]] = (
    UserRole.ADMIN.value,
)

_AUDITOR_AND_ADMIN: Final[tuple[str, ...]] = (
    UserRole.AUDITOR.value,
    UserRole.ADMIN.value,
)

# Fixed low-cost dummy hash used to reduce trivial timing differences when a
# user is not found. This is not a security control by itself.
_DUMMY_SALT: Final[bytes] = b"muleguard-auth-dummy"
_DUMMY_ITERATIONS: Final[int] = 10_000
_DUMMY_DERIVED: Final[bytes] = hashlib.pbkdf2_hmac(
    "sha256",
    b"invalid-password",
    _DUMMY_SALT,
    _DUMMY_ITERATIONS,
    dklen=32,
)
_DUMMY_PASSWORD_HASH: Final[str] = (
    f"pbkdf2_sha256${_DUMMY_ITERATIONS}${_DUMMY_SALT.hex()}${_DUMMY_DERIVED.hex()}"
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


def _auth_enabled(settings: Any) -> bool:
    """
    Return True when authentication is enabled.
    """
    return _as_bool(_setting(settings, "AUTH_ENABLED", True), True)


def _auth_mode(settings: Any) -> str:
    """
    Return normalized authentication mode.
    """
    return str(_setting(settings, "AUTH_MODE", "jwt_bearer") or "jwt_bearer").strip().lower()


# -----------------------------------------------------------------------------
# Hashing helpers
# -----------------------------------------------------------------------------


def _hash_salt(settings: Any) -> str:
    """
    Return a salt for non-secret hashing such as IP hashes.

    This is not used for password hashing.
    """
    return str(
        _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
        or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
        or _setting(settings, "BACKEND_SECRET_KEY", None)
        or "muleguard-auth"
    )


def _hash_value(value: str, salt: str) -> str:
    """
    Return a stable SHA-256 hash for safe audit storage.
    """
    payload = f"{salt}:{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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

        try:
            result = fn(password, settings)
            return str(result)
        except TypeError:
            result = fn(password)
            return str(result)

    except Exception:
        logger.debug("External password hashing helper unavailable.", exc_info=True)

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


def _try_external_password_verify(
    password: str,
    password_hash: str,
    settings: Any,
) -> Optional[tuple[bool, Optional[str]]]:
    """
    Delegate password verification to app.auth.passwords if implemented.

    Supported return shapes:

    - bool
    - (bool, Optional[str])
    - mapping with ok/new_hash
    """
    try:
        module = importlib.import_module("app.auth.passwords")
        fn = getattr(module, "verify_password", None)

        if not callable(fn):
            return None

        attempts = (
            {"password": password, "password_hash": password_hash, "settings": settings},
            {"password": password, "password_hash": password_hash},
        )

        result: Any = None
        last_error: Optional[Exception] = None

        for kwargs in attempts:
            try:
                result = fn(**kwargs)
                break
            except TypeError as exc:
                last_error = exc
                continue

        if result is None:
            try:
                result = fn(password, password_hash, settings)
            except TypeError:
                try:
                    result = fn(password, password_hash)
                except TypeError as exc:
                    if last_error is None:
                        last_error = exc
                    logger.debug(
                        "External password verify signature incompatible: %s",
                        type(last_error).__name__ if last_error else "unknown",
                    )
                    return None

        if isinstance(result, Mapping):
            ok = bool(result.get("ok") or result.get("valid") or result.get("success"))
            new_hash = result.get("new_hash") or result.get("rehash")
            return ok, str(new_hash) if isinstance(new_hash, str) and new_hash else None

        if isinstance(result, tuple):
            ok = bool(result[0]) if result else False
            new_hash = result[1] if len(result) > 1 else None
            return ok, str(new_hash) if isinstance(new_hash, str) and new_hash else None

        return bool(result), None

    except Exception:
        logger.debug("External password verification helper unavailable.", exc_info=True)
        return None


def _verify_password(
    password: str,
    password_hash: str,
    settings: Any,
) -> tuple[bool, Optional[str]]:
    """
    Verify a password and optionally return a rehashed value.

    Returns:

        (ok, new_hash_or_none)

    The new hash is returned only when verification succeeds and the stored hash
    should be upgraded to current parameters.
    """
    if not password or not password_hash:
        return False, None

    external = _try_external_password_verify(password, password_hash, settings)

    if external is not None:
        return external

    lowered_hash = password_hash.lower()

    # ------------------------------------------------------------------
    # Argon2
    # ------------------------------------------------------------------
    if lowered_hash.startswith("$argon2"):
        try:
            from argon2 import exceptions as argon2_exceptions

            hasher = _argon2_hasher(settings)

            try:
                hasher.verify(password_hash, password)
            except argon2_exceptions.VerifyMismatchError:
                return False, None
            except Exception:
                return False, None

            new_hash: Optional[str] = None

            try:
                if hasattr(hasher, "check_needs_rehash") and hasher.check_needs_rehash(
                    password_hash
                ):
                    new_hash = str(hasher.hash(password))
            except Exception:
                new_hash = None

            return True, new_hash

        except Exception:
            logger.debug("Argon2 verification failed structurally.", exc_info=True)
            return False, None

    # ------------------------------------------------------------------
    # bcrypt
    # ------------------------------------------------------------------
    if password_hash.startswith(("$2b$", "$2a$", "$2y$", "$2x$")):
        try:
            import bcrypt

            ok = bcrypt.checkpw(
                password.encode("utf-8")[:72],
                password_hash.encode("utf-8"),
            )

            return bool(ok), None

        except Exception:
            logger.debug("bcrypt verification failed structurally.", exc_info=True)
            return False, None

    # ------------------------------------------------------------------
    # PBKDF2-HMAC-SHA256
    # ------------------------------------------------------------------
    if password_hash.startswith("pbkdf2_sha256$"):
        try:
            parts = password_hash.split("$")

            if len(parts) != 4:
                return False, None

            _, iterations_raw, salt_hex, hash_hex = parts
            iterations = int(iterations_raw)

            if iterations < 1 or iterations > 10_000_000:
                return False, None

            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)

            if not salt or not expected:
                return False, None

            derived = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                iterations,
                dklen=len(expected),
            )

            ok = hmac.compare_digest(derived, expected)

            new_hash: Optional[str] = None
            min_iterations = max(
                10_000,
                _as_int(_setting(settings, "AUTH_PBKDF2_ITERATIONS", 390_000), 390_000),
            )

            if ok and iterations < min_iterations:
                try:
                    new_hash = _hash_password(password, settings)
                except Exception:
                    new_hash = None

            return ok, new_hash

        except Exception:
            logger.debug("PBKDF2 verification failed structurally.", exc_info=True)
            return False, None

    return False, None


# -----------------------------------------------------------------------------
# Token helpers
# -----------------------------------------------------------------------------


def _jwt_audience(settings: Any) -> Any:
    """
    Return a PyJWT-compatible audience value.
    """
    raw = _setting(settings, "AUTH_AUDIENCE", None)

    if raw is None:
        return None

    if isinstance(raw, (list, tuple, set)):
        values = [str(item).strip() for item in raw if str(item).strip()]
        return values or None

    values = [part.strip() for part in str(raw).split(",") if part.strip()]

    if not values:
        return None

    if len(values) == 1:
        return values[0]

    return values


def _try_external_token_issue(
    user: User,
    settings: Any,
    now: datetime,
) -> Optional[tuple[str, int]]:
    """
    Delegate token issuance to app.auth.tokens if implemented.
    """
    try:
        module = importlib.import_module("app.auth.tokens")
        fn = getattr(module, "issue_access_token", None)

        if not callable(fn):
            return None

        attempts = (
            {"user": user, "settings": settings, "now": now},
            {"user": user, "settings": settings},
            {"user": user},
        )

        result: Any = None

        for kwargs in attempts:
            try:
                result = fn(**kwargs)
                break
            except TypeError:
                continue

        if result is None:
            try:
                result = fn(user, settings, now)
            except TypeError:
                try:
                    result = fn(user, settings)
                except TypeError:
                    result = fn(user)

        default_expire_minutes = max(
            1,
            _as_int(_setting(settings, "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES", 30), 30),
        )

        if isinstance(result, Mapping):
            token = result.get("access_token") or result.get("token")
            expires_in = result.get("expires_in")

            if not token:
                return None

            return str(token), int(expires_in or default_expire_minutes * 60)

        if isinstance(result, tuple):
            if not result:
                return None

            token = str(result[0])
            expires_in = result[1] if len(result) > 1 else default_expire_minutes * 60

            if not token:
                return None

            return token, int(expires_in)

        # An object carrying the token in an attribute -- which is what
        # `app.auth.tokens.issue_access_token` actually returns: an
        # `IssuedToken`, a frozen dataclass. A dataclass is neither a Mapping
        # nor a tuple, so it used to fall through to the `str(result)` branch
        # below and the "token" became the dataclass REPR:
        #
        #   IssuedToken(access_token='eyJhbGciOi...', token_type='bearer', ...)
        #
        # Login still returned 200 with that string in `access_token`, and
        # every authenticated request then sent it as the bearer credential,
        # where PyJWT rejected it as malformed -- a 200 login followed by
        # MULEGUARD_TOKEN_INVALID on everything else, with nothing in either
        # message pointing at the cause. It also leaked the real JWT inside a
        # repr, so anything that logged the "token" logged the credential.
        attribute_token = getattr(result, "access_token", None) or getattr(
            result, "token", None
        )

        if attribute_token:
            attribute_expires_in = getattr(result, "expires_in", None)

            return (
                str(attribute_token),
                int(attribute_expires_in or default_expire_minutes * 60),
            )

        # Only a plain string is accepted from here. Never stringify an
        # arbitrary object into a credential position: if a future issuer
        # returns an unrecognised shape, fall back to local issuance instead of
        # minting a token-shaped lie.
        if isinstance(result, str) and result.strip():
            return result.strip(), default_expire_minutes * 60

        logger.debug(
            "External token issuer returned an unsupported result type: %s",
            type(result).__name__,
        )
        return None

    except Exception:
        logger.debug("External token issuer unavailable.", exc_info=True)
        return None


def _issue_access_token(
    user: User,
    settings: Any,
    now: datetime,
) -> tuple[str, int]:
    """
    Issue a local HS256 access token for the synthetic prototype.

    If app.auth.tokens provides a stronger issuer, that implementation is used
    first. Otherwise this endpoint supports HS256 only and fails closed for
    asymmetric algorithms until a reviewed token service exists.
    """
    mode = _auth_mode(settings)

    if mode != "jwt_bearer":
        raise ConfigurationError(
            "Only AUTH_MODE=jwt_bearer is supported by /api/v1/auth/login."
        )

    delegated = _try_external_token_issue(user, settings, now)

    if delegated is not None:
        return delegated

    secret = str(_setting(settings, "BACKEND_SECRET_KEY", "") or "").strip()

    if not secret:
        raise ConfigurationError("BACKEND_SECRET_KEY is not configured.")

    algorithm = str(_setting(settings, "AUTH_ALGORITHM", "HS256") or "HS256").strip()

    if algorithm.upper() != "HS256":
        raise ConfigurationError(
            "Local authentication supports HS256 unless app.auth.tokens provides "
            "asymmetric token issuance."
        )

    expire_minutes = max(
        1,
        _as_int(_setting(settings, "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES", 30), 30),
    )
    expires_in = expire_minutes * 60

    now_ts = int(now.timestamp())
    clock_skew = max(0, _as_int(_setting(settings, "AUTH_CLOCK_SKEW_SECONDS", 30), 30))

    claims: dict[str, Any] = {
        "sub": str(user.id),
        "iat": now_ts,
        "nbf": now_ts - clock_skew,
        "exp": now_ts + expires_in,
        "typ": "access",
        "ver": "v1",
    }

    issuer = _setting(settings, "AUTH_ISSUER", None)

    if issuer:
        claims["iss"] = str(issuer)

    audience = _jwt_audience(settings)

    if audience:
        claims["aud"] = audience

    if _as_bool(_setting(settings, "AUTH_JTI_CLAIM_ENABLED", True), True):
        claims["jti"] = secrets.token_urlsafe(24)

    if _as_bool(_setting(settings, "AUTH_INCLUDE_ROLES_IN_TOKEN", False), False):
        claims["roles"] = [_normalize_role(user.role)]

    try:
        token = jwt.encode(claims, secret, algorithm=algorithm)
    except Exception as exc:
        logger.exception("Unable to issue access token.")
        raise ConfigurationError("Unable to issue access token.") from exc

    return str(token), expires_in


# -----------------------------------------------------------------------------
# Audit helpers
# -----------------------------------------------------------------------------


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
# Password policy
# -----------------------------------------------------------------------------


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

    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique_errors: list[str] = []

    for error in errors:
        if error not in seen:
            seen.add(error)
            unique_errors.append(error)

    return unique_errors


# -----------------------------------------------------------------------------
# Capabilities and response models
# -----------------------------------------------------------------------------


def _role_allowed(
    setting_name: str,
    role: str,
    default_roles: tuple[str, ...],
    settings: Any,
) -> bool:
    """
    Return True when a role is allowed by setting or default policy.
    """
    raw = _setting(settings, setting_name, None)

    if raw is None:
        allowed = {item.strip().upper() for item in default_roles if item.strip()}
    else:
        allowed = {item.strip().upper() for item in _csv(raw) if item.strip()}

    return role.strip().upper() in allowed


def _capabilities_for_user(user: User, settings: Any) -> dict[str, bool]:
    """
    Return safe high-level capabilities for the current user.

    These are convenience booleans for UI gating. They are not a substitute for
    server-side permission dependencies on protected endpoints.
    """
    role = _normalize_role(user.role)
    active = bool(getattr(user, "is_active", False))

    if not active:
        return {
            "read_dashboard": False,
            "run_analysis": False,
            "triage_alerts": False,
            "assign_alerts": False,
            "escalate_alerts": False,
            "create_case": False,
            "assign_case": False,
            "close_case": False,
            "reopen_case": False,
            "add_case_note": False,
            "add_case_evidence": False,
            "remove_case_evidence": False,
            "read_audit": False,
            "export_audit": False,
            "manage_users": False,
            "read_config": False,
            "write_config": False,
            "run_ingestion": False,
            "train_model": False,
            "evaluate_model": False,
            "generate_report": False,
            "download_report": False,
            "read_complaint_narrative": False,
        }

    return {
        "read_dashboard": _role_allowed(
            "DASHBOARD_READ_ROLES",
            role,
            _READ_ROLES,
            settings,
        ),
        "run_analysis": _role_allowed(
            "ANALYSIS_RUN_ROLES",
            role,
            _ANALYST_AND_ABOVE,
            settings,
        ),
        "triage_alerts": _role_allowed(
            "ALERT_TRIAGE_ROLES",
            role,
            _ANALYST_AND_ABOVE,
            settings,
        ),
        "assign_alerts": _role_allowed(
            "ALERT_ASSIGN_ROLES",
            role,
            _SENIOR_AND_ADMIN,
            settings,
        ),
        "escalate_alerts": _role_allowed(
            "ALERT_ESCALATION_ROLES",
            role,
            _SENIOR_AND_ADMIN,
            settings,
        ),
        "create_case": _role_allowed(
            "CASE_CREATE_ROLES",
            role,
            _ANALYST_AND_ABOVE,
            settings,
        ),
        "assign_case": _role_allowed(
            "CASE_ASSIGN_ROLES",
            role,
            _SENIOR_AND_ADMIN,
            settings,
        ),
        "close_case": _role_allowed(
            "CASE_CLOSE_ROLES",
            role,
            _SENIOR_AND_ADMIN,
            settings,
        ),
        "reopen_case": _role_allowed(
            "CASE_REOPEN_ROLES",
            role,
            _SENIOR_AND_ADMIN,
            settings,
        ),
        "add_case_note": _role_allowed(
            "CASE_NOTE_ROLES",
            role,
            _ANALYST_AND_ABOVE,
            settings,
        ),
        "add_case_evidence": _role_allowed(
            "CASE_EVIDENCE_ADD_ROLES",
            role,
            _ANALYST_AND_ABOVE,
            settings,
        ),
        "remove_case_evidence": _role_allowed(
            "CASE_EVIDENCE_REMOVE_ROLES",
            role,
            _SENIOR_AND_ADMIN,
            settings,
        ),
        "read_audit": _role_allowed(
            "AUDIT_READ_ROLES",
            role,
            _AUDITOR_AND_ADMIN,
            settings,
        ),
        "export_audit": _role_allowed(
            "AUDIT_EXPORT_ROLES",
            role,
            _ADMIN_ONLY,
            settings,
        ),
        "manage_users": _role_allowed(
            "USER_MANAGEMENT_ROLES",
            role,
            _ADMIN_ONLY,
            settings,
        ),
        "read_config": _role_allowed(
            "CONFIG_READ_ROLES",
            role,
            _ADMIN_ONLY,
            settings,
        ),
        "write_config": _role_allowed(
            "CONFIG_WRITE_ROLES",
            role,
            _ADMIN_ONLY,
            settings,
        ),
        "run_ingestion": _role_allowed(
            "INGESTION_RUN_ROLES",
            role,
            _ADMIN_ONLY,
            settings,
        ),
        "train_model": _role_allowed(
            "MODEL_TRAIN_ROLES",
            role,
            _ADMIN_ONLY,
            settings,
        ),
        "evaluate_model": _role_allowed(
            "MODEL_EVALUATE_ROLES",
            role,
            _ADMIN_ONLY,
            settings,
        ),
        "generate_report": _role_allowed(
            "REPORT_GENERATE_ROLES",
            role,
            _ANALYST_AND_ABOVE,
            settings,
        ),
        "download_report": _role_allowed(
            "REPORT_DOWNLOAD_ROLES",
            role,
            _READ_ROLES,
            settings,
        ),
        "read_complaint_narrative": _role_allowed(
            "COMPLAINT_NARRATIVE_ACCESS_ROLES",
            role,
            _SENIOR_AND_ADMIN,
            settings,
        ),
    }


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


# -----------------------------------------------------------------------------
# Pydantic schemas
# -----------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """
    Local authentication request.

    The identifier may be a username or email address. Passwords are accepted
    as SecretStr to reduce accidental logging.
    """

    model_config = ConfigDict(extra="forbid")

    identifier: str = Field(
        description="Username or email address for a local synthetic user.",
        examples=["admin", "analyst@muleguard.local"],
    )
    password: SecretStr = Field(
        description="Local development password. Never use real credentials.",
    )

    @field_validator("identifier")
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("identifier must not be empty")

        if len(normalized) > 320:
            raise ValueError("identifier is too long")

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


class ChangePasswordRequest(BaseModel):
    """
    Password change request for the authenticated local user.
    """

    model_config = ConfigDict(extra="forbid")

    current_password: SecretStr = Field(
        description="Current local password.",
    )
    new_password: SecretStr = Field(
        description="New local password satisfying configured policy.",
    )

    @field_validator("current_password")
    @classmethod
    def _validate_current_password(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()

        if not secret:
            raise ValueError("current_password must not be empty")

        if len(secret) > 1024:
            raise ValueError("current_password is too long")

        return value

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()

        if not secret:
            raise ValueError("new_password must not be empty")

        if len(secret) > 1024:
            raise ValueError("new_password is too long")

        return value


class AuthUserResponse(BaseModel):
    """
    Safe authenticated user profile.

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
    last_login_at: Optional[datetime] = None
    capabilities: dict[str, bool]


class LoginResponse(BaseModel):
    """
    Successful local login response.
    """

    model_config = ConfigDict(from_attributes=False)

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    issued_at: datetime
    user: AuthUserResponse


# -----------------------------------------------------------------------------
# Response helpers
# -----------------------------------------------------------------------------


def _user_response(user: User, settings: Any) -> AuthUserResponse:
    """
    Build a safe response payload from a persisted or transient user.
    """
    role = _normalize_role(user.role)

    return AuthUserResponse(
        id=str(user.id),
        username=str(user.username),
        email=str(user.email),
        full_name=str(user.full_name) if getattr(user, "full_name", None) else None,
        role=role,
        role_display_name=_role_display_name(role, settings),
        is_active=bool(getattr(user, "is_active", False)),
        must_change_password=bool(getattr(user, "must_change_password", False)),
        last_login_at=getattr(user, "last_login_at", None),
        capabilities=_capabilities_for_user(user, settings),
    )


def _finish_login_failure(
    db: Session,
    request: Request,
    settings: Any,
    request_id: str,
    user: Optional[User],
    reason: str,
) -> NoReturn:
    """
    Persist a safe failed-login audit event and raise a non-enumerating error.

    Some deployments may choose to reveal locked/inactive state explicitly.
    Defaults remain conservative.
    """
    ip_hash = _ip_hash(request, settings)

    outcome = (
        AuditOutcome.DENIED
        if reason in {"locked", "inactive", "ambiguous_or_missing_identifier"}
        else AuditOutcome.FAILURE
    )

    _add_audit_event(
        db,
        action="failed_login",
        outcome=outcome,
        request_id=request_id,
        actor=user,
        resource_type="user",
        resource_id=str(user.id) if user is not None else None,
        ip_hash=ip_hash,
        metadata={
            "reason": reason,
            "auth_mode": _auth_mode(settings),
        },
    )

    db.commit()

    if (
        reason == "locked"
        and _as_bool(_setting(settings, "AUTH_REVEAL_LOCKED_ACCOUNT", False), False)
    ):
        raise UserLockedError()

    if (
        reason == "inactive"
        and _as_bool(_setting(settings, "AUTH_REVEAL_INACTIVE_ACCOUNT", False), False)
    ):
        raise UserInactiveError()

    raise InvalidCredentialsError()


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate a local synthetic user",
    description=(
        "Issues a local JWT bearer token for MULEGUARD synthetic prototype users. "
        "This endpoint is intended for local demo and test workflows. "
        "It does not connect to real identity providers, banks, or customer systems. "
        "Failed authentication responses are intentionally generic to reduce user enumeration."
    ),
)
def login(
    payload: LoginRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
    _: None = Depends(rate_limited(key_prefix="login", by="ip")),
) -> LoginResponse:
    """
    Authenticate and issue an access token.
    """
    if not _auth_enabled(settings):
        raise ConfigurationError(
            "Authentication is disabled. Enable AUTH_ENABLED=true to use /auth/login."
        )

    mode = _auth_mode(settings)

    if mode != "jwt_bearer":
        raise ConfigurationError(
            "Only AUTH_MODE=jwt_bearer is supported by /api/v1/auth/login."
        )

    if _is_production_like(settings) and _as_bool(
        _setting(settings, "AUTH_DEMO_MODE", False),
        False,
    ):
        raise ConfigurationError(
            "AUTH_DEMO_MODE=true is not allowed in production-like environments."
        )

    now = _now_utc()
    identifier = payload.identifier.strip()
    password = _safe_secret(payload.password)

    if not identifier or not password:
        _verify_password(password, _DUMMY_PASSWORD_HASH, settings)
        _finish_login_failure(
            db=db,
            request=request,
            settings=settings,
            request_id=request_id,
            user=None,
            reason="invalid_credentials",
        )

    email_identifier = identifier.lower()

    statement = (
        select(User)
        .where(
            or_(
                User.username == identifier,
                User.email == email_identifier,
            )
        )
        .limit(2)
    )

    users = list(db.scalars(statement).all())

    if len(users) != 1:
        # Reduce trivial timing differences and avoid revealing whether the
        # identifier exists or is ambiguous.
        _verify_password(password, _DUMMY_PASSWORD_HASH, settings)
        _finish_login_failure(
            db=db,
            request=request,
            settings=settings,
            request_id=request_id,
            user=None,
            reason="ambiguous_or_missing_identifier",
        )

    user = users[0]

    # Clear expired lockout before evaluating the attempt.
    if user.locked_until is not None and user.locked_until <= now:
        user.locked_until = None
        user.failed_login_count = 0

    if user.locked_until is not None and user.locked_until > now:
        _verify_password(password, _DUMMY_PASSWORD_HASH, settings)
        _finish_login_failure(
            db=db,
            request=request,
            settings=settings,
            request_id=request_id,
            user=user,
            reason="locked",
        )

    if not user.is_active:
        _verify_password(password, _DUMMY_PASSWORD_HASH, settings)
        _finish_login_failure(
            db=db,
            request=request,
            settings=settings,
            request_id=request_id,
            user=user,
            reason="inactive",
        )

    ok, rehashed_password = _verify_password(
        password,
        str(user.password_hash or ""),
        settings,
    )

    if not ok:
        max_attempts = max(
            1,
            _as_int(_setting(settings, "AUTH_LOGIN_MAX_ATTEMPTS", 5), 5),
        )
        lockout_minutes = max(
            0,
            _as_int(_setting(settings, "AUTH_LOGIN_LOCKOUT_MINUTES", 15), 15),
        )

        user.failed_login_count = int(user.failed_login_count or 0) + 1

        if lockout_minutes > 0 and user.failed_login_count >= max_attempts:
            user.locked_until = now + timedelta(minutes=lockout_minutes)

        _finish_login_failure(
            db=db,
            request=request,
            settings=settings,
            request_id=request_id,
            user=user,
            reason="invalid_credentials",
        )

    # Successful authentication.
    if rehashed_password:
        user.password_hash = rehashed_password

    if _as_bool(_setting(settings, "AUTH_LOGIN_RESET_ON_SUCCESS", True), True):
        user.failed_login_count = 0
        user.locked_until = None

    ip_hash = _ip_hash(request, settings)

    user.last_login_at = now
    user.last_login_ip_hash = ip_hash

    access_token, expires_in = _issue_access_token(user, settings, now)

    _add_audit_event(
        db,
        action="login",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=user,
        resource_type="user",
        resource_id=str(user.id),
        ip_hash=ip_hash,
        metadata={
            "auth_mode": mode,
            "token_type": "access",
            "expires_in": expires_in,
        },
    )

    db.commit()

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        issued_at=now,
        user=_user_response(user, settings),
    )


@router.get(
    "/me",
    response_model=AuthUserResponse,
    summary="Return the authenticated local user",
    description=(
        "Returns safe profile and high-level capability metadata for the "
        "authenticated user. Protected endpoints still enforce server-side "
        "permissions independently."
    ),
)
def read_current_user(
    current_user: CurrentUser,
    settings: SettingsDep,
) -> AuthUserResponse:
    """
    Return the current authenticated user.
    """
    return _user_response(current_user, settings)


@router.post(
    "/password/change",
    response_model=AuthUserResponse,
    summary="Change the authenticated user's local password",
    description=(
        "Changes the password for the authenticated local synthetic user. "
        "This endpoint requires the current password and enforces configured "
        "password policy. It does not support real customer accounts."
    ),
)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    current_user: CurrentUser,
    request_id: RequestIDDep,
    _: None = Depends(rate_limited(key_prefix="password_change", by="user_and_ip")),
) -> AuthUserResponse:
    """
    Change the current user's password.
    """
    if not _auth_enabled(settings):
        raise ConfigurationError(
            "Authentication is disabled. Enable AUTH_ENABLED=true to change passwords."
        )

    if str(getattr(current_user, "id", "")) == "local-bypass":
        raise UnsupportedActionError(
            "Password change is not available for local bypass users."
        )

    current_password = _safe_secret(payload.current_password)
    new_password = _safe_secret(payload.new_password)

    if not current_password or not new_password:
        raise MuleGuardValidationError(
            "Current and new passwords are required.",
            details={
                "fields": [
                    {"field": "current_password", "type": "missing", "message": "Required."},
                    {"field": "new_password", "type": "missing", "message": "Required."},
                ]
            },
        )

    if current_password == new_password:
        raise MuleGuardValidationError(
            "New password must differ from the current password.",
            details={
                "fields": [
                    {
                        "field": "new_password",
                        "type": "policy_violation",
                        "message": "new_password_must_differ",
                    }
                ]
            },
        )

    ok, _ = _verify_password(
        current_password,
        str(current_user.password_hash or ""),
        settings,
    )

    if not ok:
        ip_hash = _ip_hash(request, settings)

        _add_audit_event(
            db,
            action="password_change_denied",
            outcome=AuditOutcome.DENIED,
            request_id=request_id,
            actor=current_user,
            resource_type="user",
            resource_id=str(current_user.id),
            ip_hash=ip_hash,
            metadata={
                "reason": "invalid_current_password",
                "auth_mode": _auth_mode(settings),
            },
        )

        db.commit()

        raise InvalidCredentialsError("Current password is incorrect.")

    policy_errors = _password_policy_errors(new_password, current_user, settings)

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

    current_user.password_hash = _hash_password(new_password, settings)
    current_user.must_change_password = False

    ip_hash = _ip_hash(request, settings)

    _add_audit_event(
        db,
        action="password_change",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        actor=current_user,
        resource_type="user",
        resource_id=str(current_user.id),
        ip_hash=ip_hash,
        metadata={
            "auth_mode": _auth_mode(settings),
            "hash_scheme": str(
                _setting(settings, "AUTH_PASSWORD_HASH_SCHEME", "argon2id")
            ),
        },
    )

    db.commit()

    return _user_response(current_user, settings)


# -----------------------------------------------------------------------------
# Explicit unsupported endpoints
# -----------------------------------------------------------------------------
# These endpoints are intentionally not implemented as fake successes.
#
# Logout and refresh require a reviewed token revocation or session store.
# Adding endpoints that merely return 200 without revoking access would violate
# the MULEGUARD no-fake-functionality rule.
#
# If a future implementation adds persistent revocation, replace these notes
# with real endpoints and tests.


__all__ = [
    "router",
]