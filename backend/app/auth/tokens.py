"""
MULEGUARD backend token issuance and validation.

This module is the canonical bearer-token layer for the synthetic MULEGUARD
prototype. It is imported by `app.auth.service` and the `/api/v1/auth`
endpoints through lazy delegation.

Primary responsibilities:

- issue local HS256 JWT bearer access tokens for synthetic prototype users;
- validate bearer tokens with strict signature, expiry, and claim checks;
- normalize audience and issuer handling;
- provide an optional, bounded, in-memory revocation store for local/demo use;
- expose safe helpers for building Authorization headers and inspecting claims;
- never log, return, or reflect tokens, passwords, secrets, database URLs, raw
  complaint narratives, or real customer data.

Security and product-safety rules enforced here:

- The backend is the security boundary. Token validation must happen server-side.
- Asymmetric or external token issuance is delegated to `app.auth.tokens`
  overrides only when explicitly implemented; otherwise HS256 is enforced.
- Expired tokens produce a distinct, non-enumerating error.
- Invalid tokens produce a generic error that does not reveal which claim
  failed.
- Optional revocation is best-effort and process-local. It is clearly labelled
  as non-durable and must not be presented as a production session store.
- Tokens never trigger automatic adverse customer action.

Explicit non-goals:

- This module does not manage users, passwords, sessions, or permissions.
- This module does not implement durable refresh-token rotation.
- This module does not connect to external JWKS endpoints unless a caller
  explicitly supplies one.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Bearer tokens here
protect local demo and test workflows only.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.exceptions import (
    ConfigurationError,
    TokenExpiredError,
    TokenInvalidError,
    UnsupportedActionError,
)

logger = logging.getLogger("muleguard.backend.auth.tokens")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

DEFAULT_ALGORITHM: Final[str] = "HS256"
SUPPORTED_ALGORITHMS: Final[tuple[str, ...]] = ("HS256",)

TOKEN_TYPE_ACCESS: Final[str] = "access"
TOKEN_TYPE_REFRESH: Final[str] = "refresh"

DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES: Final[int] = 30
DEFAULT_CLOCK_SKEW_SECONDS: Final[int] = 30
DEFAULT_MAX_TOKEN_LENGTH: Final[int] = 8192

# Bounded in-memory revocation store limits.
_REVOCATION_STORE_MAX_ENTRIES: Final[int] = 10_000
_REVOCATION_STORE_PRUNE_INTERVAL_SECONDS: Final[float] = 60.0


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


def _now_utc() -> datetime:
    """
    Return timezone-aware UTC current time.
    """
    return datetime.now(timezone.utc)


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


def _normalize_role(value: Any) -> str:
    """
    Normalize a role-like value to an uppercase role string.
    """
    enum_value = getattr(value, "value", None)

    if enum_value is not None:
        return str(enum_value).strip().upper()

    return str(value).strip().upper().replace(" ", "_").replace("-", "_")


# -----------------------------------------------------------------------------
# Token payload model
# -----------------------------------------------------------------------------


class TokenPayload(BaseModel):
    """
    Minimal JWT claims accepted by MULEGUARD.

    Roles are optional in the token. The database remains the authoritative
    source for current role and active status.
    """

    model_config = ConfigDict(extra="ignore")

    sub: str = Field(min_length=1, max_length=128)
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    iss: Optional[str] = None
    aud: Optional[Any] = None
    jti: Optional[str] = None
    typ: Optional[str] = None
    ver: Optional[str] = None
    roles: Optional[list[str]] = None


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """
    Safe issued-token result.

    The `access_token` field must be treated as sensitive by callers.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int = DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    jti: Optional[str] = None


# -----------------------------------------------------------------------------
# Revocation store
# -----------------------------------------------------------------------------


class _RevocationStore:
    """
    Bounded, process-local, in-memory token revocation store.

    This is intentionally non-durable and local to the current process. It is
    suitable for local demo and CI use only. Production deployments should
    replace it with a reviewed shared revocation backend.

    Entries are keyed by `jti` and expire automatically.
    """

    def __init__(self, max_entries: int = _REVOCATION_STORE_MAX_ENTRIES) -> None:
        self.max_entries = max(100, int(max_entries))
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._last_prune = time.monotonic()

    def _prune_expired(self, now: float) -> None:
        stale: list[str] = []

        for jti, expires_at in self._entries.items():
            if expires_at <= now:
                stale.append(jti)

        for jti in stale:
            self._entries.pop(jti, None)

    def revoke(self, jti: str, exp_ts: float) -> None:
        """
        Record a revoked token `jti` until its original expiry time.
        """
        if not jti:
            return

        now = time.monotonic()

        with self._lock:
            if now - self._last_prune >= _REVOCATION_STORE_PRUNE_INTERVAL_SECONDS:
                self._prune_expired(now)
                self._last_prune = now

            self._entries[jti] = float(exp_ts)
            self._entries.move_to_end(jti)

            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def is_revoked(self, jti: str) -> bool:
        """
        Return True when a token `jti` has been revoked and not yet expired.
        """
        if not jti:
            return False

        now = time.monotonic()

        with self._lock:
            expires_at = self._entries.get(jti)

            if expires_at is None:
                return False

            if expires_at <= now:
                self._entries.pop(jti, None)
                return False

            return True


_REVOCATION_STORE: Final[_RevocationStore] = _RevocationStore()


def _revocation_enabled(settings: Any) -> bool:
    """
    Return True when optional in-memory token revocation is enabled.
    """
    return _as_bool(_setting(settings, "AUTH_TOKEN_REVOCATION_ENABLED", False), False)


def revoke_token(jti: str, exp_ts: Optional[float], settings: Any) -> bool:
    """
    Revoke a token by `jti` in the process-local store.

    Returns True when revocation was recorded. This is best-effort and
    non-durable. It must not be presented as a production session store.
    """
    if not _revocation_enabled(settings):
        return False

    if not jti:
        return False

    expires_at = float(exp_ts) if exp_ts is not None else (time.time() + 3600.0)
    _REVOCATION_STORE.revoke(jti, expires_at)
    return True


def is_token_revoked(jti: Optional[str], settings: Any) -> bool:
    """
    Return True when a token `jti` is revoked and revocation is enabled.
    """
    if not _revocation_enabled(settings):
        return False

    if not jti:
        return False

    return _REVOCATION_STORE.is_revoked(str(jti))


# -----------------------------------------------------------------------------
# Token issuance
# -----------------------------------------------------------------------------


def build_access_token_claims(
    user: Any,
    settings: Any,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """
    Build safe access-token claims for a local prototype user.

    The returned claims do not include secrets or sensitive personal data beyond
    a stable subject identifier and optional role labels.
    """
    now = now or _now_utc()

    expire_minutes = max(
        1,
        _as_int(
            _setting(settings, "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES", DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES),
            DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES,
        ),
    )
    expires_in = expire_minutes * 60

    now_ts = int(now.timestamp())
    clock_skew = max(
        0,
        _as_int(_setting(settings, "AUTH_CLOCK_SKEW_SECONDS", DEFAULT_CLOCK_SKEW_SECONDS), DEFAULT_CLOCK_SKEW_SECONDS),
    )

    claims: dict[str, Any] = {
        "sub": str(getattr(user, "id", "")),
        "iat": now_ts,
        "nbf": now_ts - clock_skew,
        "exp": now_ts + expires_in,
        "typ": TOKEN_TYPE_ACCESS,
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
        role = getattr(user, "role", None)

        if role is not None:
            claims["roles"] = [_normalize_role(role)]

    return claims


def issue_access_token(
    user: Any,
    settings: Any,
    now: Optional[datetime] = None,
) -> IssuedToken:
    """
    Issue a local HS256 access token for a synthetic prototype user.

    Raises ConfigurationError when the secret or algorithm is not configured
    safely.
    """
    import jwt

    secret = str(_setting(settings, "BACKEND_SECRET_KEY", "") or "").strip()

    if not secret:
        raise ConfigurationError("BACKEND_SECRET_KEY is not configured.")

    algorithm = str(_setting(settings, "AUTH_ALGORITHM", DEFAULT_ALGORITHM) or DEFAULT_ALGORITHM).strip()

    if algorithm.upper() not in SUPPORTED_ALGORITHMS:
        raise ConfigurationError(
            "Local token issuance supports HS256 only unless an external token "
            "service is implemented."
        )

    claims = build_access_token_claims(user, settings, now=now)

    try:
        token = jwt.encode(claims, secret, algorithm=algorithm)
    except Exception as exc:
        logger.exception("Unable to issue access token.")
        raise ConfigurationError("Unable to issue access token.") from exc

    expire_minutes = max(
        1,
        _as_int(
            _setting(settings, "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES", DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES),
            DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES,
        ),
    )

    issued_at = now or _now_utc()

    return IssuedToken(
        access_token=str(token),
        token_type="bearer",
        expires_in=expire_minutes * 60,
        issued_at=issued_at,
        expires_at=claims.get("exp") and datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
        jti=claims.get("jti"),
    )


# -----------------------------------------------------------------------------
# Token decoding / validation
# -----------------------------------------------------------------------------


def decode_access_token(token: str, settings: Any) -> TokenPayload:
    """
    Decode and validate a MULEGUARD access token.

    Raises:
        TokenExpiredError: when the token is expired.
        TokenInvalidError: when the token is malformed, has a bad signature, or
            fails claim validation.
        ConfigurationError: when the secret is not configured.

    This implementation intentionally keeps token validation simple and local
    for the synthetic prototype. Production deployments should replace or extend
    this with reviewed JWT/JWKS/OIDC validation.
    """
    import jwt

    if not token:
        raise TokenInvalidError("Authentication token is required.")

    max_length = max(
        1024,
        _as_int(_setting(settings, "AUTH_MAX_TOKEN_LENGTH", DEFAULT_MAX_TOKEN_LENGTH), DEFAULT_MAX_TOKEN_LENGTH),
    )

    if len(token) > max_length:
        raise TokenInvalidError("Authentication token is too long.")

    secret = str(_setting(settings, "BACKEND_SECRET_KEY", "") or "").strip()

    if not secret:
        raise ConfigurationError("BACKEND_SECRET_KEY is not configured.")

    algorithm = str(_setting(settings, "AUTH_ALGORITHM", DEFAULT_ALGORITHM) or DEFAULT_ALGORITHM).strip()

    if algorithm.upper() not in SUPPORTED_ALGORITHMS:
        raise ConfigurationError(
            "Local token validation supports HS256 only unless an external token "
            "service is implemented."
        )

    issuer = _setting(settings, "AUTH_ISSUER", None)
    audience = _jwt_audience(settings)
    clock_skew = max(
        0,
        _as_int(_setting(settings, "AUTH_CLOCK_SKEW_SECONDS", DEFAULT_CLOCK_SKEW_SECONDS), DEFAULT_CLOCK_SKEW_SECONDS),
    )

    decode_kwargs: dict[str, Any] = {
        "algorithms": [algorithm],
        "options": {
            "verify_signature": True,
            "verify_exp": True,
            "require": ["exp"],
        },
        "leeway": clock_skew,
    }

    if issuer:
        decode_kwargs["issuer"] = str(issuer)

    if audience:
        decode_kwargs["audience"] = audience

    try:
        claims = jwt.decode(token, secret, **decode_kwargs)
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError() from exc
    except jwt.InvalidTokenError as exc:
        logger.debug("Token decode failed: %s", type(exc).__name__)
        raise TokenInvalidError() from exc
    except Exception as exc:
        logger.debug("Unexpected token decode failure: %s", type(exc).__name__)
        raise TokenInvalidError() from exc

    try:
        payload = TokenPayload.model_validate(claims)
    except Exception as exc:
        logger.debug("Token claim validation failed: %s", type(exc).__name__)
        raise TokenInvalidError() from exc

    if not payload.sub:
        raise TokenInvalidError()

    return payload


def validate_access_token(token: str, settings: Any) -> TokenPayload:
    """
    Decode and validate a token, also enforcing optional revocation.

    Returns the TokenPayload when valid.
    """
    payload = decode_access_token(token, settings)

    if _revocation_enabled(settings) and payload.jti and is_token_revoked(payload.jti, settings):
        raise TokenInvalidError("Authentication token has been revoked.")

    return payload


# -----------------------------------------------------------------------------
# Authorization header helpers
# -----------------------------------------------------------------------------


def build_authorization_header(token: str, scheme: str = "Bearer") -> str:
    """
    Build an Authorization header value from a bearer token.
    """
    return f"{scheme} {token}"


def parse_authorization_header(
    header_value: Optional[str],
    settings: Any,
) -> Optional[str]:
    """
    Extract a bearer token from an Authorization header value.

    Returns None when the header is missing, malformed, or uses an unsupported
    scheme. This does not validate the token itself.
    """
    if not header_value:
        return None

    scheme = str(_setting(settings, "AUTH_TOKEN_SCHEME", "Bearer") or "Bearer").strip()
    prefix = f"{scheme} "

    if header_value.lower().startswith(prefix.lower()):
        token = header_value[len(prefix):].strip()

        if token:
            return token

    return None


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "IssuedToken",
    "TokenPayload",
    "build_access_token_claims",
    "build_authorization_header",
    "decode_access_token",
    "is_token_revoked",
    "issue_access_token",
    "parse_authorization_header",
    "revoke_token",
    "validate_access_token",
]