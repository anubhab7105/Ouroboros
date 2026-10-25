"""
MULEGUARD backend password hashing and verification.

This module is the canonical password security layer for the synthetic
MULEGUARD prototype. It is imported by `app.auth.service` and the `/api/v1/auth`
endpoints through lazy delegation.

Primary responsibilities:

- hash passwords using the strongest locally available scheme;
- verify passwords against stored hashes with constant-time comparison;
- detect the stored hash scheme and support transparent rehashing to current
  parameters;
- enforce a configurable password policy;
- provide a dummy verification path to reduce trivial timing differences when a
  user is not found;
- never log, return, or reflect plaintext passwords, tokens, secrets, or raw
  complaint narratives.

Supported schemes, in preference order:

1. Argon2id (`argon2-cffi`) — preferred;
2. bcrypt — fallback when Argon2 is unavailable;
3. PBKDF2-HMAC-SHA256 — last-resort local fallback.

Stored hash formats:

- Argon2id / bcrypt use their native PHC string formats.
- PBKDF2 uses: `pbkdf2_sha256$<iterations>$<salt_hex>$<derived_hex>`.

Security and product-safety rules enforced here:

- Passwords are stored only as salted hashes.
- Plaintext passwords are never stored, logged, returned, or reflected in
  errors or metadata.
- Verification is constant-time for the comparison step.
- Failed verification never leaks whether a user exists by itself.
- Rehashing happens only after successful verification.
- The module never triggers automatic adverse customer action.
- The module never exposes secrets, tokens, database URLs, or real customer data.

Explicit non-goals:

- This module does not manage user records, sessions, or tokens.
- This module does not connect to external KMS/HSM services.
- This module does not implement password history or breach-database checks
  unless explicitly wired by a caller.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Password security here
protects local demo and test workflows only.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, Optional

logger = logging.getLogger("muleguard.backend.auth.passwords")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_PBKDF2_PREFIX: Final[str] = "pbkdf2_sha256$"
_ARGON2_PREFIX: Final[str] = "$argon2"
_BCRYPT_PREFIXES: Final[tuple[str, ...]] = ("$2b$", "$2a$", "$2y$", "$2x$")

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

# Bounded parameter limits to avoid accidental DoS through configuration.
_ARGON2_MIN_TIME_COST: Final[int] = 1
_ARGON2_MAX_TIME_COST: Final[int] = 32
_ARGON2_MIN_MEMORY_KIB: Final[int] = 1024
_ARGON2_MAX_MEMORY_KIB: Final[int] = 2 * 1024 * 1024  # 2 GiB
_ARGON2_MIN_PARALLELISM: Final[int] = 1
_ARGON2_MAX_PARALLELISM: Final[int] = 64

_BCRYPT_MIN_ROUNDS: Final[int] = 4
_BCRYPT_MAX_ROUNDS: Final[int] = 31

_PBKDF2_MIN_ITERATIONS: Final[int] = 10_000
_PBKDF2_MAX_ITERATIONS: Final[int] = 10_000_000

# Dummy hash used to reduce trivial timing differences when a user is missing.
_DUMMY_SALT: Final[bytes] = b"muleguard-passwords-dummy"
_DUMMY_ITERATIONS: Final[int] = 10_000
_DUMMY_DERIVED: Final[bytes] = hashlib.pbkdf2_hmac(
    "sha256",
    b"invalid-password",
    _DUMMY_SALT,
    _DUMMY_ITERATIONS,
    dklen=32,
)
_DUMMY_PASSWORD_HASH: Final[str] = (
    f"{_PBKDF2_PREFIX}{_DUMMY_ITERATIONS}${_DUMMY_SALT.hex()}${_DUMMY_DERIVED.hex()}"
)

# bcrypt truncates passwords to 72 bytes. We enforce this explicitly.
_BCRYPT_MAX_BYTES: Final[int] = 72

# Maximum accepted password length to bound hashing cost.
_MAX_PASSWORD_LENGTH: Final[int] = 1024


class PasswordScheme(str, Enum):
    """
    Supported password hashing schemes.
    """

    ARGON2ID = "argon2id"
    BCRYPT = "bcrypt"
    PBKDF2_SHA256 = "pbkdf2_sha256"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """
    Safe password verification result.
    """

    ok: bool
    new_hash: Optional[str] = None
    scheme: PasswordScheme = PasswordScheme.UNKNOWN


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


def _clamp(value: int, minimum: int, maximum: int) -> int:
    """
    Clamp an integer into [minimum, maximum].
    """
    return max(minimum, min(value, maximum))


def _contains_placeholder(value: str) -> bool:
    """
    Detect obvious template or placeholder values.
    """
    if not value:
        return True

    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _configured_scheme(settings: Any) -> PasswordScheme:
    """
    Resolve the configured preferred scheme.
    """
    raw = str(
        _setting(settings, "AUTH_PASSWORD_HASH_SCHEME", PasswordScheme.ARGON2ID.value)
        or PasswordScheme.ARGON2ID.value
    ).strip().lower()

    if raw in {"argon2", "argon2id"}:
        return PasswordScheme.ARGON2ID

    if raw in {"bcrypt"}:
        return PasswordScheme.BCRYPT

    if raw in {"pbkdf2", "pbkdf2_sha256", "pbkdf2-sha256"}:
        return PasswordScheme.PBKDF2_SHA256

    return PasswordScheme.ARGON2ID


def identify_scheme(password_hash: str) -> PasswordScheme:
    """
    Identify the scheme of a stored hash.
    """
    if not password_hash:
        return PasswordScheme.UNKNOWN

    if password_hash.startswith(_ARGON2_PREFIX):
        return PasswordScheme.ARGON2ID

    if password_hash.startswith(_BCRYPT_PREFIXES):
        return PasswordScheme.BCRYPT

    if password_hash.startswith(_PBKDF2_PREFIX):
        return PasswordScheme.PBKDF2_SHA256

    return PasswordScheme.UNKNOWN


# -----------------------------------------------------------------------------
# Argon2
# -----------------------------------------------------------------------------


def _argon2_available() -> bool:
    """
    Return True when argon2-cffi is importable.
    """
    try:
        import argon2  # noqa: F401

        return True
    except Exception:
        return False


def _argon2_hasher(settings: Any) -> Any:
    """
    Construct an Argon2 hasher using bounded configured parameters.
    """
    from argon2 import PasswordHasher

    time_cost = _clamp(
        _as_int(_setting(settings, "AUTH_ARGON2_TIME_COST", 3), 3),
        _ARGON2_MIN_TIME_COST,
        _ARGON2_MAX_TIME_COST,
    )
    memory_cost = _clamp(
        _as_int(_setting(settings, "AUTH_ARGON2_MEMORY_COST_KIB", 65536), 65536),
        _ARGON2_MIN_MEMORY_KIB,
        _ARGON2_MAX_MEMORY_KIB,
    )
    parallelism = _clamp(
        _as_int(_setting(settings, "AUTH_ARGON2_PARALLELISM", 2), 2),
        _ARGON2_MIN_PARALLELISM,
        _ARGON2_MAX_PARALLELISM,
    )

    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )


def _hash_argon2(password: str, settings: Any) -> str:
    """
    Hash a password with Argon2id.
    """
    hasher = _argon2_hasher(settings)
    return str(hasher.hash(password))


def _verify_argon2(
    password: str,
    password_hash: str,
    settings: Any,
) -> VerifyResult:
    """
    Verify a password against an Argon2 hash and detect rehash needs.
    """
    try:
        from argon2 import exceptions as argon2_exceptions

        hasher = _argon2_hasher(settings)

        try:
            hasher.verify(password_hash, password)
        except argon2_exceptions.VerifyMismatchError:
            return VerifyResult(ok=False, scheme=PasswordScheme.ARGON2ID)
        except Exception:
            return VerifyResult(ok=False, scheme=PasswordScheme.ARGON2ID)

        new_hash: Optional[str] = None

        try:
            if hasattr(hasher, "check_needs_rehash") and hasher.check_needs_rehash(
                password_hash
            ):
                new_hash = str(hasher.hash(password))
        except Exception:
            new_hash = None

        return VerifyResult(
            ok=True,
            new_hash=new_hash,
            scheme=PasswordScheme.ARGON2ID,
        )

    except Exception:
        logger.debug("Argon2 verification failed structurally.", exc_info=True)
        return VerifyResult(ok=False, scheme=PasswordScheme.ARGON2ID)


# -----------------------------------------------------------------------------
# bcrypt
# -----------------------------------------------------------------------------


def _bcrypt_available() -> bool:
    """
    Return True when bcrypt is importable.
    """
    try:
        import bcrypt  # noqa: F401

        return True
    except Exception:
        return False


def _hash_bcrypt(password: str, settings: Any) -> str:
    """
    Hash a password with bcrypt, truncating to the 72-byte limit.
    """
    import bcrypt

    rounds = _clamp(
        _as_int(_setting(settings, "AUTH_BCRYPT_ROUNDS", 12), 12),
        _BCRYPT_MIN_ROUNDS,
        _BCRYPT_MAX_ROUNDS,
    )

    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password.encode("utf-8")[:_BCRYPT_MAX_BYTES], salt)
    return hashed.decode("utf-8")


def _verify_bcrypt(password: str, password_hash: str) -> VerifyResult:
    """
    Verify a password against a bcrypt hash.
    """
    try:
        import bcrypt

        ok = bcrypt.checkpw(
            password.encode("utf-8")[:_BCRYPT_MAX_BYTES],
            password_hash.encode("utf-8"),
        )

        return VerifyResult(ok=bool(ok), scheme=PasswordScheme.BCRYPT)

    except Exception:
        logger.debug("bcrypt verification failed structurally.", exc_info=True)
        return VerifyResult(ok=False, scheme=PasswordScheme.BCRYPT)


# -----------------------------------------------------------------------------
# PBKDF2-HMAC-SHA256
# -----------------------------------------------------------------------------


def _hash_pbkdf2(password: str, settings: Any) -> str:
    """
    Hash a password with PBKDF2-HMAC-SHA256.
    """
    iterations = _clamp(
        _as_int(_setting(settings, "AUTH_PBKDF2_ITERATIONS", 390_000), 390_000),
        _PBKDF2_MIN_ITERATIONS,
        _PBKDF2_MAX_ITERATIONS,
    )

    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )

    return f"{_PBKDF2_PREFIX}{iterations}${salt.hex()}${derived.hex()}"


def _verify_pbkdf2(
    password: str,
    password_hash: str,
    settings: Any,
) -> VerifyResult:
    """
    Verify a password against a PBKDF2 hash and detect rehash needs.
    """
    try:
        parts = password_hash.split("$")

        if len(parts) != 4:
            return VerifyResult(ok=False, scheme=PasswordScheme.PBKDF2_SHA256)

        _, iterations_raw, salt_hex, hash_hex = parts
        iterations = int(iterations_raw)

        if not _PBKDF2_MIN_ITERATIONS <= iterations <= _PBKDF2_MAX_ITERATIONS:
            return VerifyResult(ok=False, scheme=PasswordScheme.PBKDF2_SHA256)

        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)

        if not salt or not expected:
            return VerifyResult(ok=False, scheme=PasswordScheme.PBKDF2_SHA256)

        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=len(expected),
        )

        ok = hmac.compare_digest(derived, expected)

        new_hash: Optional[str] = None
        min_iterations = _clamp(
            _as_int(_setting(settings, "AUTH_PBKDF2_ITERATIONS", 390_000), 390_000),
            _PBKDF2_MIN_ITERATIONS,
            _PBKDF2_MAX_ITERATIONS,
        )

        if ok and iterations < min_iterations:
            try:
                new_hash = _hash_pbkdf2(password, settings)
            except Exception:
                new_hash = None

        return VerifyResult(
            ok=bool(ok),
            new_hash=new_hash,
            scheme=PasswordScheme.PBKDF2_SHA256,
        )

    except Exception:
        logger.debug("PBKDF2 verification failed structurally.", exc_info=True)
        return VerifyResult(ok=False, scheme=PasswordScheme.PBKDF2_SHA256)


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def hash_password(password: str, settings: Any) -> str:
    """
    Hash a password using the configured scheme with safe fallbacks.

    Preference order:

    1. configured scheme, when its dependency is available;
    2. Argon2id, when available;
    3. bcrypt, when available;
    4. PBKDF2-HMAC-SHA256.

    Raises ValueError for empty or oversized passwords.
    """
    if not password:
        raise ValueError("Password must not be empty.")

    if len(password) > _MAX_PASSWORD_LENGTH:
        raise ValueError("Password is too long.")

    preferred = _configured_scheme(settings)

    if preferred == PasswordScheme.ARGON2ID and _argon2_available():
        try:
            return _hash_argon2(password, settings)
        except Exception:
            logger.debug("Argon2 hashing failed; falling back.", exc_info=True)

    if preferred == PasswordScheme.BCRYPT and _bcrypt_available():
        try:
            return _hash_bcrypt(password, settings)
        except Exception:
            logger.debug("bcrypt hashing failed; falling back.", exc_info=True)

    if preferred == PasswordScheme.PBKDF2_SHA256:
        return _hash_pbkdf2(password, settings)

    # Fallback chain independent of configured preference.
    if _argon2_available():
        try:
            return _hash_argon2(password, settings)
        except Exception:
            logger.debug("Argon2 hashing fallback failed.", exc_info=True)

    if _bcrypt_available():
        try:
            return _hash_bcrypt(password, settings)
        except Exception:
            logger.debug("bcrypt hashing fallback failed.", exc_info=True)

    return _hash_pbkdf2(password, settings)


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
    should be upgraded to current parameters or scheme.
    """
    if not password or not password_hash:
        return False, None

    if len(password) > _MAX_PASSWORD_LENGTH:
        return False, None

    scheme = identify_scheme(password_hash)

    if scheme == PasswordScheme.ARGON2ID:
        result = _verify_argon2(password, password_hash, settings)

    elif scheme == PasswordScheme.BCRYPT:
        result = _verify_bcrypt(password, password_hash)

        # Transparently upgrade bcrypt to Argon2 when available and configured.
        if result.ok and _should_upgrade_to_argon2(settings):
            try:
                result = VerifyResult(
                    ok=True,
                    new_hash=_hash_argon2(password, settings),
                    scheme=scheme,
                )
            except Exception:
                logger.debug("bcrypt-to-argon2 upgrade failed.", exc_info=True)

    elif scheme == PasswordScheme.PBKDF2_SHA256:
        result = _verify_pbkdf2(password, password_hash, settings)

        # Transparently upgrade PBKDF2 to Argon2 when available and configured.
        if result.ok and _should_upgrade_to_argon2(settings):
            try:
                result = VerifyResult(
                    ok=True,
                    new_hash=_hash_argon2(password, settings),
                    scheme=scheme,
                )
            except Exception:
                logger.debug("pbkdf2-to-argon2 upgrade failed.", exc_info=True)

    else:
        return False, None

    return result.ok, result.new_hash


def _should_upgrade_to_argon2(settings: Any) -> bool:
    """
    Return True when legacy hashes should be upgraded to Argon2 on verify.
    """
    if not _as_bool(_setting(settings, "AUTH_PASSWORD_UPGRADE_TO_ARGON2", True), True):
        return False

    if _configured_scheme(settings) != PasswordScheme.ARGON2ID:
        return False

    return _argon2_available()


def needs_rehash(password_hash: str, settings: Any) -> bool:
    """
    Return True when a stored hash should be rehashed on next successful verify.

    This is a lightweight heuristic and does not verify the password.
    """
    scheme = identify_scheme(password_hash)
    preferred = _configured_scheme(settings)

    if scheme == PasswordScheme.UNKNOWN:
        return True

    if scheme != preferred:
        return True

    if scheme == PasswordScheme.ARGON2ID:
        try:
            hasher = _argon2_hasher(settings)

            if hasattr(hasher, "check_needs_rehash"):
                return bool(hasher.check_needs_rehash(password_hash))
        except Exception:
            return True

    if scheme == PasswordScheme.PBKDF2_SHA256:
        try:
            parts = password_hash.split("$")

            if len(parts) != 4:
                return True

            iterations = int(parts[1])
            min_iterations = _clamp(
                _as_int(_setting(settings, "AUTH_PBKDF2_ITERATIONS", 390_000), 390_000),
                _PBKDF2_MIN_ITERATIONS,
                _PBKDF2_MAX_ITERATIONS,
            )

            return iterations < min_iterations
        except Exception:
            return True

    return False


def dummy_verify(password: str) -> bool:
    """
    Perform a constant-ish dummy verification to reduce trivial timing
    differences when a user is not found.

    This always returns False. It exists solely to spend comparable hashing
    time before returning a generic authentication failure.
    """
    if not password:
        return False

    # Run PBKDF2 against the dummy hash to burn comparable CPU time.
    verify_result = _verify_pbkdf2(password, _DUMMY_PASSWORD_HASH, None)
    return bool(verify_result.ok) and False


# -----------------------------------------------------------------------------
# Password policy
# -----------------------------------------------------------------------------


def validate_password_policy(
    password: str,
    user: Optional[Any] = None,
    settings: Any = None,
) -> list[str]:
    """
    Return safe password policy violation labels.

    The labels are intentionally non-sensitive and do not echo the password.
    An empty list means the password satisfies the configured policy.
    """
    errors: list[str] = []

    if password is None:
        return ["missing_password"]

    if len(password) > _MAX_PASSWORD_LENGTH:
        return ["too_long"]

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

    if password and len(set(password)) <= 1:
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

    seen: set[str] = set()
    unique_errors: list[str] = []

    for error in errors:
        if error not in seen:
            seen.add(error)
            unique_errors.append(error)

    return unique_errors


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "PasswordScheme",
    "VerifyResult",
    "dummy_verify",
    "hash_password",
    "identify_scheme",
    "needs_rehash",
    "validate_password_policy",
    "verify_password",
]