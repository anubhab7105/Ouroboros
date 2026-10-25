"""
MULEGUARD backend authentication service.

This module centralizes authentication orchestration for the synthetic MULEGUARD
prototype. It is designed to be called from API endpoints and background tasks so
that authentication, lockout, auditing, and token issuance behave consistently.

Primary responsibilities:

- resolve local prototype users by username or email;
- verify passwords using the strongest available local hashing scheme;
- enforce inactive and temporary-lockout rules;
- apply login throttling with bounded, auditable counters;
- issue local JWT bearer tokens for the synthetic prototype;
- record safe audit events for material authentication outcomes;
- support authenticated password changes with policy enforcement;
- build safe capability metadata for the current user.

Security and product-safety rules enforced or supported here:

- The backend is the security boundary. Frontend hiding is not sufficient.
- Passwords are stored only as salted hashes. Plaintext passwords are never
  stored, logged, returned, or reflected in error details.
- Failed authentication responses are generic by default to reduce user
  enumeration.
- Inactive users must not authenticate.
- Locked users must not authenticate until the lock expires or is cleared.
- Authentication never triggers automatic adverse customer action.
- Audit metadata is sanitized before persistence.
- Secrets, tokens, raw complaint narratives, database URLs, and real customer
  data are never logged or returned.

Explicit non-goals:

- This module does not connect to real identity providers, banks, payment rails,
  or customer systems.
- This module does not implement refresh-token rotation because no persistent
  revocation store is part of the current prototype schema.
- This module does not implement logout as a fake success response. Stateless
  JWT logout requires a reviewed revocation backend first.
- This module does not take adverse action against accounts or customers.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Authentication here
protects local demo and test workflows only. Alerts, scores, graph
relationships, candidate money trails, entity links, complaint correlations, and
case dispositions remain investigative leads or human workflow artefacts only.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import logging
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Final, Optional

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.exceptions import (
    AuthenticationError,
    ConfigurationError,
    InvalidCredentialsError,
    UnsupportedActionError,
    UserInactiveError,
    UserLockedError,
    ValidationError as MuleGuardValidationError,
)
from app.models import AuditEvent, AuditOutcome, User, UserRole

logger = logging.getLogger("muleguard.backend.auth.service")


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
# Result dataclasses
# -----------------------------------------------------------------------------


class AuthFailureReason(str, Enum):
    """
    Stable failure reasons for authentication attempts.

    These are internal diagnostics only. Client-facing errors remain generic by
    default to reduce user enumeration.
    """

    INVALID_CREDENTIALS = "invalid_credentials"
    AMBIGUOUS_OR_MISSING_IDENTIFIER = "ambiguous_or_missing_identifier"
    USER_INACTIVE = "inactive"
    USER_LOCKED = "locked"


@dataclass(slots=True)
class AuthResult:
    """
    Safe authentication result.

    This object never contains passwords or raw secrets. It may contain an
    issued access token, which must be treated as sensitive by callers.
    """

    ok: bool
    user: Optional[User] = None
    access_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    issued_at: Optional[datetime] = None
    failure_reason: Optional[AuthFailureReason] = None
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PasswordChangeResult:
    """
    Safe password change result.
    """

    ok: bool
    changed: bool = False
    failure_reason: Optional[str] = None
    policy_errors: list[str] = field(default_factory=list)


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


def _hash_salt(settings: Any) -> str:
    """
    Return a salt for non-secret hashing such as IP hashes.

    This is not used for password hashing.
    """
    return str(
        _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
        or _setting(settings, "PRIVACY_IP_HASH_SALT", None)
        or _setting(settings, "BACKEND_SECRET_KEY", None)
        or "muleguard-auth-service"
    )


def _hash_value(value: str, salt: str) -> str:
    """
    Return a stable SHA-256 hash for safe audit storage.
    """
    payload = f"{salt}:{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ip_hash(request: Any, settings: Any) -> Optional[str]:
    """
    Return a hashed client IP for audit storage, or None when disabled.
    """
    mode = str(_setting(settings, "PRIVACY_IP_LOG_MODE", "hashed")).strip().lower()

    if mode in {"none", "off", "disabled"}:
        return None

    ip = _client_ip(request, settings)

    if not ip:
        return None

    return _hash_value(ip, _hash_salt(settings))


def _client_ip(request: Any, settings: Any) -> str:
    """
    Return a best-effort client IP.

    Proxy headers are trusted only when BACKEND_TRUST_PROXY_HEADERS=true.
    """
    if request is None:
        return ""

    trust_proxy = _as_bool(
        _setting(settings, "BACKEND_TRUST_PROXY_HEADERS", False),
        False,
    )

    headers = getattr(request, "headers", None)

    if trust_proxy and headers is not None:
        forwarded_for = headers.get("X-Forwarded-For")

        if forwarded_for:
            first = forwarded_for.split(",", 1)[0].strip()

            if first:
                return first

        real_ip = headers.get("X-Real-IP")

        if real_ip:
            return real_ip.strip()

    client = getattr(request, "client", None)
    client_host = getattr(client, "host", None)

    if client_host:
        return client_host

    return ""


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
) -> None:
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
            return str(fn(**kwargs))
        except TypeError:
            continue
        except Exception:
            logger.debug("External password hasher failed.", exc_info=True)
            return None

    try:
        return str(fn(password, settings))
    except TypeError:
        try:
            return str(fn(password))
        except Exception:
            logger.debug("External password hasher positional fallback failed.", exc_info=True)
            return None
    except Exception:
        logger.debug("External password hasher failed.", exc_info=True)
        return None


def hash_password(password: str, settings: Any) -> str:
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
            max(4, _as_int(_setting(settings, "AUTH_BCRYPT_ROUNDS", 12), 12)),
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
    except Exception:
        return None

    fn = getattr(module, "verify_password", None)

    if not callable(fn):
        return None

    result: Any = None

    attempts = (
        {"password": password, "password_hash": password_hash, "settings": settings},
        {"password": password, "password_hash": password_hash},
    )

    for kwargs in attempts:
        try:
            result = fn(**kwargs)
            break
        except TypeError:
            continue
        except Exception:
            logger.debug("External password verify failed.", exc_info=True)
            return None

    if result is None:
        try:
            result = fn(password, password_hash, settings)
        except TypeError:
            try:
                result = fn(password, password_hash)
            except TypeError:
                return None
            except Exception:
                logger.debug("External password verify failed.", exc_info=True)
                return None
        except Exception:
            logger.debug("External password verify failed.", exc_info=True)
            return None

    if isinstance(result, Mapping):
        ok = bool(result.get("ok") or result.get("valid") or result.get("success"))
        new_hash = result.get("new_hash") or result.get("rehash")
        return ok, str(new_hash) if isinstance(new_hash, str) and new_hash else None

    if isinstance(result, tuple):
        if not result:
            return False, None

        ok = bool(result[0])
        new_hash = result[1] if len(result) > 1 else None
        return ok, str(new_hash) if isinstance(new_hash, str) and new_hash else None

    return bool(result), None


def verify_password(
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

    # Argon2
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

    # bcrypt
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

    # PBKDF2-HMAC-SHA256
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
                    new_hash = hash_password(password, settings)
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
    except Exception:
        return None

    fn = getattr(module, "issue_access_token", None)

    if not callable(fn):
        return None

    result: Any = None

    attempts = (
        {"user": user, "settings": settings, "now": now},
        {"user": user, "settings": settings},
        {"user": user},
    )

    for kwargs in attempts:
        try:
            result = fn(**kwargs)
            break
        except TypeError:
            continue
        except Exception:
            logger.debug("External token issuer failed.", exc_info=True)
            return None

    if result is None:
        try:
            result = fn(user, settings, now)
        except TypeError:
            try:
                result = fn(user, settings)
            except TypeError:
                try:
                    result = fn(user)
                except Exception:
                    logger.debug("External token issuer failed.", exc_info=True)
                    return None
            except Exception:
                logger.debug("External token issuer failed.", exc_info=True)
                return None
        except Exception:
            logger.debug("External token issuer failed.", exc_info=True)
            return None

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

    token = str(result)

    if not token:
        return None

    return token, default_expire_minutes * 60


def issue_access_token(
    user: User,
    settings: Any,
    now: datetime,
) -> tuple[str, int]:
    """
    Issue a local HS256 access token for the synthetic prototype.

    If app.auth.tokens provides a stronger issuer, that implementation is used
    first. Otherwise this service supports HS256 only and fails closed for
    asymmetric algorithms until a reviewed token service exists.
    """
    mode = str(_setting(settings, "AUTH_MODE", "jwt_bearer") or "jwt_bearer").strip().lower()

    if mode != "jwt_bearer":
        raise ConfigurationError(
            "Only AUTH_MODE=jwt_bearer is supported by the bundled auth service."
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

    import jwt

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
# Password policy
# -----------------------------------------------------------------------------


def password_policy_errors(
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
# Auth service
# -----------------------------------------------------------------------------


class AuthService:
    """
    Central authentication orchestration for the MULEGUARD synthetic prototype.

    This service is intentionally synchronous and database-session driven. It
    does not manage background tasks, refresh-token rotation, or distributed
    session storage.
    """

    def __init__(self, settings: Any | None = None) -> None:
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        self.settings = settings

    # ---------------------------------------------------------------------
    # Configuration guards
    # ---------------------------------------------------------------------

    def _auth_enabled(self) -> bool:
        return _as_bool(_setting(self.settings, "AUTH_ENABLED", True), True)

    def _auth_mode(self) -> str:
        return str(
            _setting(self.settings, "AUTH_MODE", "jwt_bearer") or "jwt_bearer"
        ).strip().lower()

    def _ensure_auth_supported(self) -> None:
        if not self._auth_enabled():
            raise ConfigurationError(
                "Authentication is disabled. Enable AUTH_ENABLED=true to authenticate."
            )

        if self._auth_mode() != "jwt_bearer":
            raise ConfigurationError(
                "Only AUTH_MODE=jwt_bearer is supported by the bundled auth service."
            )

        if _is_production_like(self.settings) and _as_bool(
            _setting(self.settings, "AUTH_DEMO_MODE", False),
            False,
        ):
            raise ConfigurationError(
                "AUTH_DEMO_MODE=true is not allowed in production-like environments."
            )

    # ---------------------------------------------------------------------
    # User lookup
    # ---------------------------------------------------------------------

    def find_user_by_identifier(
        self,
        db: Session,
        identifier: str,
    ) -> tuple[Optional[User], AuthFailureReason]:
        """
        Resolve a user by username or email.

        Returns `(user, failure_reason)`. `user` is None when no unique match is
        found. Ambiguous matches are treated as failures to reduce enumeration.
        """
        normalized = str(identifier or "").strip()

        if not normalized:
            return None, AuthFailureReason.AMBIGUOUS_OR_MISSING_IDENTIFIER

        email_identifier = normalized.lower()

        statement = (
            select(User)
            .where(
                or_(
                    User.username == normalized,
                    User.email == email_identifier,
                )
            )
            .limit(2)
        )

        users = list(db.scalars(statement).all())

        if len(users) != 1:
            return None, AuthFailureReason.AMBIGUOUS_OR_MISSING_IDENTIFIER

        return users[0], AuthFailureReason.INVALID_CREDENTIALS

    # ---------------------------------------------------------------------
    # Lockout helpers
    # ---------------------------------------------------------------------

    def _clear_expired_lockout(self, user: User, now: datetime) -> None:
        if user.locked_until is not None and user.locked_until <= now:
            user.locked_until = None
            user.failed_login_count = 0

    def _is_locked(self, user: User, now: datetime) -> bool:
        return user.locked_until is not None and user.locked_until > now

    def _register_failed_attempt(
        self,
        user: User,
        now: datetime,
    ) -> None:
        max_attempts = max(
            1,
            _as_int(_setting(self.settings, "AUTH_LOGIN_MAX_ATTEMPTS", 5), 5),
        )
        lockout_minutes = max(
            0,
            _as_int(_setting(self.settings, "AUTH_LOGIN_LOCKOUT_MINUTES", 15), 15),
        )

        user.failed_login_count = int(user.failed_login_count or 0) + 1

        if lockout_minutes > 0 and user.failed_login_count >= max_attempts:
            user.locked_until = now + timedelta(minutes=lockout_minutes)

    def _reset_failed_attempts(self, user: User) -> None:
        if _as_bool(_setting(self.settings, "AUTH_LOGIN_RESET_ON_SUCCESS", True), True):
            user.failed_login_count = 0
            user.locked_until = None

    # ---------------------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------------------

    def authenticate(
        self,
        db: Session,
        identifier: str,
        password: str,
        *,
        request: Any = None,
        request_id: Optional[str] = None,
    ) -> AuthResult:
        """
        Authenticate a local prototype user and issue an access token.

        This method commits successful authentication state and failed-login
        audit records. It raises safe API exceptions for configuration errors
        and returns AuthResult for credential/lockout failures so callers can
        control HTTP mapping.
        """
        self._ensure_auth_supported()

        now = _now_utc()
        ip_hash = _ip_hash(request, self.settings)

        user, failure_reason = self.find_user_by_identifier(db, identifier)

        if user is None:
            # Reduce trivial timing differences.
            verify_password(password, _DUMMY_PASSWORD_HASH, self.settings)

            self._record_failed_login(
                db,
                request_id=request_id,
                actor=None,
                ip_hash=ip_hash,
                reason=failure_reason.value,
            )
            db.commit()

            return AuthResult(ok=False, failure_reason=failure_reason)

        self._clear_expired_lockout(user, now)

        if self._is_locked(user, now):
            verify_password(password, _DUMMY_PASSWORD_HASH, self.settings)

            self._record_failed_login(
                db,
                request_id=request_id,
                actor=user,
                ip_hash=ip_hash,
                reason=AuthFailureReason.USER_LOCKED.value,
            )
            db.commit()

            return AuthResult(ok=False, failure_reason=AuthFailureReason.USER_LOCKED)

        if not user.is_active:
            verify_password(password, _DUMMY_PASSWORD_HASH, self.settings)

            self._record_failed_login(
                db,
                request_id=request_id,
                actor=user,
                ip_hash=ip_hash,
                reason=AuthFailureReason.USER_INACTIVE.value,
            )
            db.commit()

            return AuthResult(ok=False, failure_reason=AuthFailureReason.USER_INACTIVE)

        ok, rehashed_password = verify_password(
            password,
            str(user.password_hash or ""),
            self.settings,
        )

        if not ok:
            self._register_failed_attempt(user, now)

            self._record_failed_login(
                db,
                request_id=request_id,
                actor=user,
                ip_hash=ip_hash,
                reason=AuthFailureReason.INVALID_CREDENTIALS.value,
            )
            db.commit()

            return AuthResult(ok=False, failure_reason=AuthFailureReason.INVALID_CREDENTIALS)

        # Successful authentication.
        if rehashed_password:
            user.password_hash = rehashed_password

        self._reset_failed_attempts(user)

        user.last_login_at = now
        user.last_login_ip_hash = ip_hash

        access_token, expires_in = issue_access_token(user, self.settings, now)

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
                "auth_mode": self._auth_mode(),
                "token_type": "access",
                "expires_in": expires_in,
            },
        )

        db.commit()

        return AuthResult(
            ok=True,
            user=user,
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            issued_at=now,
        )

    def _record_failed_login(
        self,
        db: Session,
        *,
        request_id: Optional[str],
        actor: Optional[User],
        ip_hash: Optional[str],
        reason: str,
    ) -> None:
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
            actor=actor,
            resource_type="user",
            resource_id=str(actor.id) if actor is not None else None,
            ip_hash=ip_hash,
            metadata={
                "reason": reason,
                "auth_mode": self._auth_mode(),
            },
        )

    # ---------------------------------------------------------------------
    # Password change
    # ---------------------------------------------------------------------

    def change_password(
        self,
        db: Session,
        user: User,
        current_password: str,
        new_password: str,
        *,
        request: Any = None,
        request_id: Optional[str] = None,
    ) -> PasswordChangeResult:
        """
        Change the password for an authenticated local user.

        This method enforces the current password, configured policy, and records
        a safe audit event. It never logs or returns passwords.
        """
        self._ensure_auth_supported()

        if str(getattr(user, "id", "")) == "local-bypass":
            raise UnsupportedActionError(
                "Password change is not available for local bypass users."
            )

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
            return PasswordChangeResult(
                ok=False,
                changed=False,
                failure_reason="new_password_must_differ",
                policy_errors=["new_password_must_differ"],
            )

        ok, _ = verify_password(
            current_password,
            str(user.password_hash or ""),
            self.settings,
        )

        if not ok:
            ip_hash = _ip_hash(request, self.settings)

            _add_audit_event(
                db,
                action="password_change_denied",
                outcome=AuditOutcome.DENIED,
                request_id=request_id,
                actor=user,
                resource_type="user",
                resource_id=str(user.id),
                ip_hash=ip_hash,
                metadata={
                    "reason": "invalid_current_password",
                    "auth_mode": self._auth_mode(),
                },
            )

            db.commit()

            raise InvalidCredentialsError("Current password is incorrect.")

        policy_errors = password_policy_errors(new_password, user, self.settings)

        if policy_errors:
            return PasswordChangeResult(
                ok=False,
                changed=False,
                failure_reason="policy_violation",
                policy_errors=policy_errors,
            )

        user.password_hash = hash_password(new_password, self.settings)
        user.must_change_password = False

        ip_hash = _ip_hash(request, self.settings)

        _add_audit_event(
            db,
            action="password_change",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            actor=user,
            resource_type="user",
            resource_id=str(user.id),
            ip_hash=ip_hash,
            metadata={
                "auth_mode": self._auth_mode(),
                "hash_scheme": str(
                    _setting(self.settings, "AUTH_PASSWORD_HASH_SCHEME", "argon2id")
                ),
            },
        )

        db.commit()

        return PasswordChangeResult(ok=True, changed=True)

    # ---------------------------------------------------------------------
    # Capabilities
    # ---------------------------------------------------------------------

    def _role_allowed(
        self,
        setting_name: str,
        role: str,
        default_roles: Sequence[str],
    ) -> bool:
        raw = _setting(self.settings, setting_name, None)
        normalized_role = _normalize_role(role)

        if raw is None:
            allowed = {item.strip().upper() for item in default_roles if str(item).strip()}
        else:
            allowed = {item.strip().upper() for item in _csv(raw) if str(item).strip()}

        return normalized_role in allowed

    def capabilities_for_user(self, user: User) -> dict[str, bool]:
        """
        Return safe high-level capabilities for the current user.

        These are convenience booleans for UI gating. They are not a substitute
        for server-side permission dependencies on protected endpoints.
        """
        role = _normalize_role(user.role)
        active = bool(getattr(user, "is_active", False))

        if not active:
            return {key: False for key in self._capability_keys()}

        all_roles = ("ADMIN", "ANALYST", "SENIOR_INVESTIGATOR", "AUDITOR")
        analyst_and_above = ("ANALYST", "SENIOR_INVESTIGATOR", "ADMIN")
        senior_and_admin = ("SENIOR_INVESTIGATOR", "ADMIN")
        admin_only = ("ADMIN",)
        auditor_and_admin = ("AUDITOR", "ADMIN")

        return {
            "read_dashboard": self._role_allowed("DASHBOARD_READ_ROLES", role, all_roles),
            "run_analysis": self._role_allowed("ANALYSIS_RUN_ROLES", role, analyst_and_above),
            "triage_alerts": self._role_allowed("ALERT_TRIAGE_ROLES", role, analyst_and_above),
            "assign_alerts": self._role_allowed("ALERT_ASSIGN_ROLES", role, senior_and_admin),
            "escalate_alerts": self._role_allowed("ALERT_ESCALATION_ROLES", role, senior_and_admin),
            "create_case": self._role_allowed("CASE_CREATE_ROLES", role, analyst_and_above),
            "assign_case": self._role_allowed("CASE_ASSIGN_ROLES", role, senior_and_admin),
            "close_case": self._role_allowed("CASE_CLOSE_ROLES", role, senior_and_admin),
            "reopen_case": self._role_allowed("CASE_REOPEN_ROLES", role, senior_and_admin),
            "add_case_note": self._role_allowed("CASE_NOTE_ROLES", role, analyst_and_above),
            "add_case_evidence": self._role_allowed("CASE_EVIDENCE_ADD_ROLES", role, analyst_and_above),
            "remove_case_evidence": self._role_allowed("CASE_EVIDENCE_REMOVE_ROLES", role, senior_and_admin),
            "read_audit": self._role_allowed("AUDIT_READ_ROLES", role, auditor_and_admin),
            "export_audit": self._role_allowed("AUDIT_EXPORT_ROLES", role, admin_only),
            "manage_users": self._role_allowed("USER_MANAGEMENT_ROLES", role, admin_only),
            "read_config": self._role_allowed("CONFIG_READ_ROLES", role, admin_only),
            "write_config": self._role_allowed("CONFIG_WRITE_ROLES", role, admin_only),
            "run_ingestion": self._role_allowed("INGESTION_RUN_ROLES", role, admin_only),
            "train_model": self._role_allowed("MODEL_TRAIN_ROLES", role, admin_only),
            "evaluate_model": self._role_allowed("MODEL_EVALUATE_ROLES", role, admin_only),
            "generate_report": self._role_allowed("REPORT_GENERATE_ROLES", role, analyst_and_above),
            "download_report": self._role_allowed("REPORT_DOWNLOAD_ROLES", role, all_roles),
            "read_complaint_narrative": self._role_allowed(
                "COMPLAINT_NARRATIVE_ACCESS_ROLES",
                role,
                senior_and_admin,
            ),
        }

    def _capability_keys(self) -> tuple[str, ...]:
        return (
            "read_dashboard",
            "run_analysis",
            "triage_alerts",
            "assign_alerts",
            "escalate_alerts",
            "create_case",
            "assign_case",
            "close_case",
            "reopen_case",
            "add_case_note",
            "add_case_evidence",
            "remove_case_evidence",
            "read_audit",
            "export_audit",
            "manage_users",
            "read_config",
            "write_config",
            "run_ingestion",
            "train_model",
            "evaluate_model",
            "generate_report",
            "download_report",
            "read_complaint_narrative",
        )


# -----------------------------------------------------------------------------
# Convenience factory
# -----------------------------------------------------------------------------

_default_service: Optional[AuthService] = None


def get_auth_service(settings: Any | None = None) -> AuthService:
    """
    Return a process-wide auth service.

    If settings are provided, a new service is created and becomes the default.
    This is useful for tests or applications that construct settings explicitly.
    """
    global _default_service

    if _default_service is None or settings is not None:
        _default_service = AuthService(settings=settings)

    return _default_service


__all__ = [
    "AuthFailureReason",
    "AuthResult",
    "AuthService",
    "PasswordChangeResult",
    "get_auth_service",
    "hash_password",
    "issue_access_token",
    "password_policy_errors",
    "verify_password",
]