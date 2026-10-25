"""
MULEGUARD backend core security primitives.

This module provides the low-level security helpers used across configuration,
authentication, ingestion, reporting, graph, and audit subsystems.

Primary responsibilities:

- generate cryptographically strong secrets;
- perform constant-time comparisons;
- provide domain-separated hashing and HMAC helpers for pseudonymous identifiers,
  audit references, and payload fingerprints;
- validate secret strength without echoing secret values;
- delegate password hashing/verification to the canonical `app.auth.passwords`
  module;
- delegate bearer-token issuance/validation to the canonical `app.auth.tokens`
  module;
- provide safe filename and filesystem-path helpers that prevent traversal and
  symlink escape;
- provide a conservative outbound-URL policy helper for optional integrations;
- provide strict, bounded JSON parsing helpers.

Security and product-safety rules enforced here:

- Secrets, tokens, passwords, and raw identifiers are never logged.
- Passwords are never stored or returned in plaintext.
- Comparisons that protect secrets use constant-time primitives.
- Identifier hashing uses domain separation and a caller-supplied salt.
- Payload fingerprints are deterministic and contain no reversible secret.
- Filesystem paths are resolved and checked to stay inside an allowed base
  directory.
- Outbound network access is disabled by default. The URL policy helper is a
  defence-in-depth layer, not a complete SSRF protection.
- JSON parsing rejects non-finite constants and duplicate keys.
- No pickle, unsafe YAML, or external-entity XML loading is performed.
- Security helpers never trigger automatic adverse customer action.

Explicit non-goals:

- This module does not implement a production identity provider.
- This module does not replace network egress policy, TLS verification, DNS
  pinning, or a secret manager.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Security primitives here
protect local demo and test workflows only.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Optional
from urllib.parse import urlsplit

from app.exceptions import ConfigurationError, ValidationError

if TYPE_CHECKING:
    from app.auth.tokens import IssuedToken, TokenPayload
    from app.core.config import Settings

logger = logging.getLogger("muleguard.backend.core.security")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MIN_SECRET_BYTES: Final[int] = 16
_MAX_SECRET_BYTES: Final[int] = 256

_MIN_SALT_LENGTH: Final[int] = 16
_MAX_FINGERPRINT_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_JSON_BYTES: Final[int] = 4 * 1024 * 1024

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

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_FILENAME_UNSAFE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._-]+")
_FILENAME_EXT_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9]{1,10}$")
_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]+$")

_WINDOWS_RESERVED_NAMES: Final[frozenset[str]] = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)

_BLOCKED_HOSTNAMES: Final[frozenset[str]] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "169.254.169.254",
        "fd00:ec2::254",
    }
)


# -----------------------------------------------------------------------------
# Decision models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OutboundUrlDecision:
    """
    Safe outbound-URL policy decision.

    This never contains credentials or query strings.
    """

    allowed: bool
    reason: str
    scheme: str = ""
    hostname: str = ""


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


def _resolve_settings(settings: Any | None) -> Any:
    """
    Resolve settings lazily to avoid import cycles.
    """
    if settings is not None:
        return settings

    try:
        from app.core.config import get_settings

        return get_settings()
    except Exception:
        return {}


def _to_bytes(value: str | bytes) -> bytes:
    """
    Normalize a string or bytes value to bytes without raising on Unicode.
    """
    if isinstance(value, bytes):
        return value

    return str(value).encode("utf-8", errors="replace")


# -----------------------------------------------------------------------------
# Secret generation and comparison
# -----------------------------------------------------------------------------


def generate_secret(length_bytes: int = 32) -> str:
    """
    Generate a cryptographically strong hex secret.

    The length is bounded to prevent accidental DoS through configuration.
    """
    length = max(_MIN_SECRET_BYTES, min(int(length_bytes), _MAX_SECRET_BYTES))
    return secrets.token_hex(length)


def generate_urlsafe_secret(length_bytes: int = 32) -> str:
    """
    Generate a cryptographically strong URL-safe secret.
    """
    length = max(_MIN_SECRET_BYTES, min(int(length_bytes), _MAX_SECRET_BYTES))
    return secrets.token_urlsafe(length)


def constant_time_equals(left: Any, right: Any) -> bool:
    """
    Compare two values in constant time where possible.

    Returns False for missing or non-comparable values. Never raises for
    ordinary string/bytes inputs.
    """
    if left is None or right is None:
        return False

    try:
        return hmac.compare_digest(_to_bytes(left), _to_bytes(right))
    except Exception:
        return False


def is_hex_digest(value: Any, *, expected_length: int = 64) -> bool:
    """
    Return True when a value is a hex digest of the expected length.
    """
    if not isinstance(value, str):
        return False

    if len(value) != expected_length:
        return False

    return _HEX_RE.match(value) is not None


# -----------------------------------------------------------------------------
# Hashing and fingerprints
# -----------------------------------------------------------------------------


def sha256_hex(value: str | bytes) -> str:
    """
    Return a SHA-256 hex digest of a value.

    This is appropriate for integrity metadata, not password storage.
    """
    return hashlib.sha256(_to_bytes(value)).hexdigest()


def hmac_sha256_hex(value: str | bytes, key: str | bytes) -> str:
    """
    Return a keyed HMAC-SHA256 hex digest.
    """
    return hmac.new(
        _to_bytes(key),
        _to_bytes(value),
        hashlib.sha256,
    ).hexdigest()


def hash_identifier(
    value: str | bytes,
    salt: str | bytes,
    *,
    domain: str = "muleguard.identifier",
) -> str:
    """
    Produce a domain-separated pseudonymous identifier hash.

    This is used for synthetic entity identifiers and audit references. It is
    not a password hash and must not be used for password storage.

    Raises ValueError when the salt is missing or too short.
    """
    salt_bytes = _to_bytes(salt)

    if len(salt_bytes) < _MIN_SALT_LENGTH:
        raise ValueError("Identifier hashing requires a salt of at least 16 bytes.")

    domain_bytes = _to_bytes(domain)
    value_bytes = _to_bytes(value)

    material = b"\x00".join((domain_bytes, salt_bytes, value_bytes))

    return hmac.new(salt_bytes, material, hashlib.sha256).hexdigest()


def _canonical_json(payload: Any) -> str:
    """
    Produce deterministic canonical JSON for fingerprinting.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )


def fingerprint_payload(payload: Any) -> str:
    """
    Return a deterministic SHA-256 fingerprint of a JSON-like payload.

    This is useful for ingestion lineage and evidence integrity. It is not
    reversible and must not be treated as authentication.
    """
    try:
        canonical = _canonical_json(payload)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            "Payload cannot be fingerprinted.",
            details={"reason": "non_canonicalizable_payload"},
        ) from exc

    encoded = canonical.encode("utf-8", errors="replace")

    if len(encoded) > _MAX_FINGERPRINT_BYTES:
        raise ValidationError(
            "Payload is too large to fingerprint.",
            details={
                "max_bytes": _MAX_FINGERPRINT_BYTES,
                "actual_bytes": len(encoded),
            },
        )

    return hashlib.sha256(encoded).hexdigest()


def hash_for_audit(
    value: str | bytes,
    salt: str | bytes,
    *,
    domain: str = "muleguard.audit",
) -> str:
    """
    Return a salted, domain-separated audit hash.

    Use this instead of logging raw IPs, tokens, or identifiers.
    """
    return hash_identifier(value, salt, domain=domain)


def hash_token_for_audit(token: str | None, settings: Any | None = None) -> Optional[str]:
    """
    Return a salted audit hash for a bearer token, or None when no salt exists.

    The raw token is never returned or logged.
    """
    if not token:
        return None

    resolved = _resolve_settings(settings)

    salt = str(
        _setting(resolved, "AUTH_RATE_LIMIT_KEY_SALT", None)
        or _setting(resolved, "PRIVACY_IP_HASH_SALT", None)
        or _setting(resolved, "BACKEND_SECRET_KEY", None)
        or ""
    ).strip()

    if not salt:
        return None

    try:
        return hash_identifier(token, salt, domain="muleguard.token")
    except ValueError:
        return None


# -----------------------------------------------------------------------------
# Secret strength validation
# -----------------------------------------------------------------------------


def is_placeholder_secret(value: str | None) -> bool:
    """
    Return True when a value is missing or looks like a template placeholder.
    """
    if not value:
        return True

    lowered = value.strip().lower()

    if not lowered:
        return True

    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def secret_policy_errors(value: str | None, *, min_length: int = 32) -> list[str]:
    """
    Return safe secret-policy violation labels.

    Never echoes the secret value.
    """
    errors: list[str] = []

    if not value:
        return ["missing_secret"]

    if is_placeholder_secret(value):
        errors.append("placeholder_secret")

    if len(value) < max(16, int(min_length)):
        errors.append("secret_too_short")

    if len(value) > 4096:
        errors.append("secret_too_long")

    if len(set(value)) <= 1:
        errors.append("secret_too_repetitive")

    if any(character.isspace() for character in value):
        errors.append("secret_contains_whitespace")

    return errors


def validate_secret(
    value: str | None,
    *,
    min_length: int = 32,
) -> None:
    """
    Raise ValidationError when a secret fails policy.

    Error details contain only safe violation labels.
    """
    errors = secret_policy_errors(value, min_length=min_length)

    if errors:
        raise ValidationError(
            "Secret does not satisfy configured policy.",
            details={"errors": errors},
        )


# -----------------------------------------------------------------------------
# Password delegation
# -----------------------------------------------------------------------------


def hash_password(password: str, settings: Settings | Any | None = None) -> str:
    """
    Hash a password using the canonical MULEGUARD password module.

    Delegates to `app.auth.passwords.hash_password`.
    """
    try:
        from app.auth.passwords import hash_password as _hash_password
    except Exception as exc:
        raise ConfigurationError(
            "Password hashing module is unavailable."
        ) from exc

    return _hash_password(password, _resolve_settings(settings))


def verify_password(
    password: str,
    password_hash: str,
    settings: Settings | Any | None = None,
) -> tuple[bool, Optional[str]]:
    """
    Verify a password using the canonical MULEGUARD password module.

    Returns `(ok, new_hash_or_none)` for transparent rehashing.
    """
    try:
        from app.auth.passwords import verify_password as _verify_password
    except Exception as exc:
        raise ConfigurationError(
            "Password verification module is unavailable."
        ) from exc

    return _verify_password(password, password_hash, _resolve_settings(settings))


def needs_rehash(
    password_hash: str,
    settings: Settings | Any | None = None,
) -> bool:
    """
    Return True when a stored password hash should be upgraded.
    """
    try:
        from app.auth.passwords import needs_rehash as _needs_rehash
    except Exception as exc:
        raise ConfigurationError(
            "Password rehash detection module is unavailable."
        ) from exc

    return _needs_rehash(password_hash, _resolve_settings(settings))


def validate_password_policy(
    password: str,
    user: Any = None,
    settings: Settings | Any | None = None,
) -> list[str]:
    """
    Return safe password-policy violation labels.

    Delegates to the canonical password policy validator.
    """
    try:
        from app.auth.passwords import validate_password_policy as _validate_policy
    except Exception as exc:
        raise ConfigurationError(
            "Password policy module is unavailable."
        ) from exc

    return _validate_policy(password, user, _resolve_settings(settings))


# -----------------------------------------------------------------------------
# Token delegation
# -----------------------------------------------------------------------------


def issue_access_token(
    user: Any,
    settings: Settings | Any | None = None,
    now: datetime | None = None,
) -> IssuedToken:
    """
    Issue a local access token using the canonical token module.
    """
    try:
        from app.auth.tokens import issue_access_token as _issue_access_token
    except Exception as exc:
        raise ConfigurationError(
            "Token issuance module is unavailable."
        ) from exc

    return _issue_access_token(user, _resolve_settings(settings), now=now)


def decode_access_token(
    token: str,
    settings: Settings | Any | None = None,
) -> TokenPayload:
    """
    Decode and validate a local access token.
    """
    try:
        from app.auth.tokens import decode_access_token as _decode_access_token
    except Exception as exc:
        raise ConfigurationError(
            "Token validation module is unavailable."
        ) from exc

    return _decode_access_token(token, _resolve_settings(settings))


def validate_access_token(
    token: str,
    settings: Settings | Any | None = None,
) -> TokenPayload:
    """
    Validate a local access token, including optional revocation.
    """
    try:
        from app.auth.tokens import validate_access_token as _validate_access_token
    except Exception as exc:
        raise ConfigurationError(
            "Token validation module is unavailable."
        ) from exc

    return _validate_access_token(token, _resolve_settings(settings))


# -----------------------------------------------------------------------------
# Filename and filesystem safety
# -----------------------------------------------------------------------------


def _sanitize_filename_component(value: Any, *, fallback: str = "file") -> str:
    """
    Sanitize a single filename component.
    """
    text = str(value if value is not None else "")

    # Normalise Unicode and remove path separators and control characters.
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\\", "/")
    text = text.rsplit("/", 1)[-1]
    text = _CONTROL_CHAR_RE.sub("", text)
    text = text.replace("\x00", "")
    text = text.replace(":", "")

    text = _FILENAME_UNSAFE_RE.sub("-", text)
    text = re.sub(r"-{2,}", "-", text)
    text = text.strip(" .-_")

    if not text or text in {".", ".."}:
        text = fallback

    return text


def safe_filename(
    value: Any,
    *,
    fallback: str = "file",
    max_length: int = 120,
) -> str:
    """
    Return a safe, non-traversable filename.

    This helper:
      - removes path separators and control characters;
      - normalises Unicode;
      - strips Windows drive/ADS constructs;
      - avoids reserved Windows device names;
      - bounds length;
      - preserves a safe short extension when possible.

    Caller-supplied filenames must never be trusted for filesystem writes.
    """
    limit = max(16, min(int(max_length), 255))
    safe_fallback = _sanitize_filename_component(fallback, fallback="file")[:40]

    name = _sanitize_filename_component(value, fallback=safe_fallback)

    # Separate a short, safe extension from the stem.
    stem = name
    extension = ""

    if "." in name:
        candidate_stem, _, candidate_ext = name.rpartition(".")

        if (
            candidate_stem
            and _FILENAME_EXT_RE.match(candidate_ext)
            and 1 <= len(candidate_ext) <= 10
        ):
            stem = candidate_stem
            extension = candidate_ext.lower()

    stem = re.sub(r"[ .]+$", "", stem).strip("._-") or safe_fallback

    if stem.upper() in _WINDOWS_RESERVED_NAMES:
        stem = f"{stem}_"

    if extension:
        candidate = f"{stem}.{extension}"
    else:
        candidate = stem

    if len(candidate) > limit:
        if extension and len(extension) + 1 < limit:
            allowed_stem_length = limit - len(extension) - 1
            stem = stem[:allowed_stem_length].rstrip(" .-_") or safe_fallback
            candidate = f"{stem}.{extension}"
        else:
            candidate = candidate[:limit].rstrip(" .-_") or safe_fallback

    return candidate or safe_fallback


def is_within_directory(base_dir: str | Path, candidate: str | Path) -> bool:
    """
    Return True when a resolved candidate path stays inside a resolved base
    directory.

    This check is symlink-aware because both paths are resolved.
    """
    try:
        base = Path(base_dir).resolve()
        target = Path(candidate).resolve()
        target.relative_to(base)
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def resolve_safe_output_path(
    base_dir: str | Path,
    filename: Any,
    *,
    create_parents: bool = False,
) -> Path:
    """
    Resolve a safe output path inside an allowed base directory.

    Raises ValidationError when the resolved path would escape the base
    directory or refers to an existing directory.

    This prevents path traversal and symlink-based escape.
    """
    base = Path(base_dir).resolve()
    safe_name = safe_filename(filename)
    candidate = (base / safe_name).resolve()

    if not is_within_directory(base, candidate):
        raise ValidationError(
            "Output path is outside the allowed directory.",
            details={"reason": "path_escape"},
        )

    if candidate.exists() and candidate.is_dir():
        raise ValidationError(
            "Output path refers to a directory.",
            details={"reason": "output_is_directory"},
        )

    if create_parents:
        try:
            base.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ValidationError(
                "Unable to create output directory.",
                details={"reason": "directory_creation_failed"},
            ) from exc

    return candidate


# -----------------------------------------------------------------------------
# Strict JSON parsing
# -----------------------------------------------------------------------------


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    """
    Reject duplicate JSON keys.

    Duplicate keys can hide conflicting values in ingestion payloads.
    """
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")

        result[key] = value

    return result


def _reject_non_finite_constant(value: str) -> Any:
    """
    Reject NaN and Infinity constants in JSON.
    """
    raise ValueError(f"Non-finite JSON constant: {value}")


def safe_json_loads(
    raw: str | bytes,
    *,
    max_bytes: int = _MAX_JSON_BYTES,
) -> Any:
    """
    Parse JSON strictly and within a bounded size.

    Rejects:
      - oversized payloads;
      - invalid UTF-8;
      - malformed JSON;
      - duplicate object keys;
      - NaN and Infinity constants.

    Raises ValidationError with a safe message on failure.
    """
    limit = max(1024, min(int(max_bytes), _MAX_JSON_BYTES))

    if isinstance(raw, bytes):
        if len(raw) > limit:
            raise ValidationError(
                "JSON payload is too large.",
                details={"max_bytes": limit},
            )

        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValidationError(
                "JSON payload is not valid UTF-8.",
                details={"reason": "invalid_utf8"},
            ) from exc
    else:
        text = str(raw or "")

        if len(text.encode("utf-8", errors="replace")) > limit:
            raise ValidationError(
                "JSON payload is too large.",
                details={"max_bytes": limit},
            )

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValidationError(
            "Invalid JSON payload.",
            details={"reason": "invalid_json"},
        ) from exc


# -----------------------------------------------------------------------------
# Outbound URL policy
# -----------------------------------------------------------------------------


def _hostname_is_public(hostname: str) -> bool:
    """
    Return True when a hostname is not a literal private/loopback/link-local
    address and is not a known metadata hostname.

    This does not perform DNS resolution. Production deployments must enforce
    egress policy at the network layer and re-validate resolved addresses.
    """
    normalized = hostname.strip().lower().rstrip(".")

    if not normalized:
        return False

    if normalized in _BLOCKED_HOSTNAMES:
        return False

    # Block decimal/hex/octal IPv4-looking hosts and IPv6 literals.
    try:
        address = ipaddress.ip_address(normalized)
        return bool(address.is_global)
    except ValueError:
        pass

    # Block obvious single-label internal hosts.
    if "." not in normalized and ":" not in normalized:
        return False

    return True


def validate_outbound_url(
    url: str,
    settings: Settings | Any | None = None,
    *,
    allowed_hosts: Sequence[str] | None = None,
) -> OutboundUrlDecision:
    """
    Apply a conservative outbound-URL policy.

    Outbound network access is disabled by default. When enabled, this helper
    rejects:
      - non-HTTP(S) schemes;
      - embedded credentials;
      - private/loopback/link-local/metadata addresses;
      - disallowed ports;
      - plaintext HTTP in production-like environments unless explicitly allowed;
      - hosts outside an explicit allowlist when one is supplied.

    This is defence-in-depth only. It does not resolve DNS, follow redirects,
    or replace a network egress allowlist.
    """
    resolved = _resolve_settings(settings)

    if not _as_bool(_setting(resolved, "OUTBOUND_NETWORK_ENABLED", False), False):
        return OutboundUrlDecision(
            allowed=False,
            reason="outbound_network_disabled",
        )

    try:
        parsed = urlsplit(str(url or "").strip())
    except ValueError:
        return OutboundUrlDecision(
            allowed=False,
            reason="malformed_url",
        )

    scheme = (parsed.scheme or "").strip().lower()
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")

    if scheme not in {"http", "https"}:
        return OutboundUrlDecision(
            allowed=False,
            reason="unsupported_scheme",
            scheme=scheme,
            hostname=hostname,
        )

    if parsed.username or parsed.password:
        return OutboundUrlDecision(
            allowed=False,
            reason="url_credentials_prohibited",
            scheme=scheme,
            hostname=hostname,
        )

    if not hostname:
        return OutboundUrlDecision(
            allowed=False,
            reason="missing_hostname",
            scheme=scheme,
        )

    env = str(_setting(resolved, "BACKEND_ENV", "local")).strip().lower()
    production_like = env in {"production", "staging", "prod", "stage"}

    allow_insecure_http = _as_bool(
        _setting(resolved, "OUTBOUND_ALLOW_INSECURE_HTTP", False),
        False,
    )

    if scheme == "http" and (production_like or not allow_insecure_http):
        return OutboundUrlDecision(
            allowed=False,
            reason="insecure_http_prohibited",
            scheme=scheme,
            hostname=hostname,
        )

    try:
        port = parsed.port
    except ValueError:
        return OutboundUrlDecision(
            allowed=False,
            reason="invalid_port",
            scheme=scheme,
            hostname=hostname,
        )

    configured_ports = _csv(_setting(resolved, "OUTBOUND_ALLOWED_PORTS", "80,443"))
    allowed_ports: set[int] = set()

    for item in configured_ports:
        try:
            value = int(item)

            if 1 <= value <= 65535:
                allowed_ports.add(value)
        except ValueError:
            continue

    if not allowed_ports:
        allowed_ports = {80, 443}

    effective_port = port or (443 if scheme == "https" else 80)

    if effective_port not in allowed_ports:
        return OutboundUrlDecision(
            allowed=False,
            reason="port_not_allowed",
            scheme=scheme,
            hostname=hostname,
        )

    if not _hostname_is_public(hostname):
        return OutboundUrlDecision(
            allowed=False,
            reason="private_or_metadata_host",
            scheme=scheme,
            hostname=hostname,
        )

    allowlist_source = allowed_hosts

    if allowlist_source is None:
        allowlist_source = _csv(_setting(resolved, "OUTBOUND_ALLOWED_HOSTS", ""))

    allowlist = {
        str(host).strip().lower().rstrip(".")
        for host in allowlist_source
        if str(host).strip()
    }

    if allowlist and hostname not in allowlist:
        return OutboundUrlDecision(
            allowed=False,
            reason="host_not_allowed",
            scheme=scheme,
            hostname=hostname,
        )

    return OutboundUrlDecision(
        allowed=True,
        reason="allowed",
        scheme=scheme,
        hostname=hostname,
    )


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "OutboundUrlDecision",
    "constant_time_equals",
    "decode_access_token",
    "fingerprint_payload",
    "generate_secret",
    "generate_urlsafe_secret",
    "hash_for_audit",
    "hash_identifier",
    "hash_password",
    "hash_token_for_audit",
    "hmac_sha256_hex",
    "is_hex_digest",
    "is_placeholder_secret",
    "is_within_directory",
    "needs_rehash",
    "resolve_safe_output_path",
    "safe_filename",
    "safe_json_loads",
    "secret_policy_errors",
    "sha256_hex",
    "validate_access_token",
    "validate_outbound_url",
    "validate_password_policy",
    "validate_secret",
    "verify_password",
]