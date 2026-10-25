"""
MULEGUARD hashing and pseudonymisation utilities.

MULEGUARD stores pseudonymous identifier hashes rather than raw identifiers for
devices, phones, UPI IDs, emails, addresses, and IPs. This module is the only
place those hashes are produced.

Design rules:

- Identifier hashes are salted with a deployment secret. Without a salt, a
  SHA-256 of a phone number is trivially reversible by brute force, so an
  unsalted identifier hash would be pseudonymisation in name only.
- The salt is namespaced per identifier kind, so the same raw value used as a
  phone and as a UPI handle does not produce the same hash.
- `fingerprint` is for reproducibility (dataset and config digests) and is
  deliberately *not* salted, so the same dataset fingerprints identically
  across deployments.
- Nothing here is a password hash. Passwords go through `app.auth.passwords`,
  which uses a slow KDF.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping, Sequence
from typing import Any, Final, Optional

from app.utils.json import canonical_json

__all__ = [
    "DEFAULT_HASH_ALGORITHM",
    "HASH_PREFIX_LENGTH",
    "checksum_file",
    "constant_time_equals",
    "dataset_fingerprint",
    "fingerprint",
    "hash_identifier",
    "hash_many",
    "is_hex_digest",
    "sha256_hex",
    "short_hash",
    "stable_bucket",
]

DEFAULT_HASH_ALGORITHM: Final[str] = "sha256"
HASH_PREFIX_LENGTH: Final[int] = 16

# Matches the String(128) identifier_hash / source_payload_hash columns.
_MAX_DIGEST_LENGTH: Final[int] = 128

_FALLBACK_SALT: Final[str] = "muleguard-synthetic-dev-salt"


def sha256_hex(value: Any) -> str:
    """
    Return the hex SHA-256 digest of a value's UTF-8 text form.
    """
    if isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
    else:
        payload = str(value if value is not None else "").encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def hash_identifier(
    value: Any,
    *,
    salt: Optional[str] = None,
    kind: str = "generic",
    algorithm: str = DEFAULT_HASH_ALGORITHM,
) -> str:
    """
    Produce a salted, namespaced, one-way identifier hash.

    `kind` namespaces the digest (`device`, `phone`, `upi_id`, `email`,
    `ip`, ...) so that the same raw string under two kinds does not collide.

    An empty value returns an empty string rather than the hash of "", which
    would otherwise make every missing identifier look like the same entity.
    """
    text = str(value if value is not None else "").strip().lower()

    if not text:
        return ""

    effective_salt = (salt or _FALLBACK_SALT).strip() or _FALLBACK_SALT
    namespace = str(kind or "generic").strip().lower()
    message = f"{namespace}:{text}".encode("utf-8")

    try:
        digest = hmac.new(
            effective_salt.encode("utf-8"),
            message,
            getattr(hashlib, algorithm),
        ).hexdigest()
    except (AttributeError, TypeError, ValueError):
        digest = hmac.new(
            effective_salt.encode("utf-8"),
            message,
            hashlib.sha256,
        ).hexdigest()

    return digest[:_MAX_DIGEST_LENGTH]


def hash_many(
    values: Sequence[Any],
    *,
    salt: Optional[str] = None,
    kind: str = "generic",
) -> list[str]:
    """
    Hash a sequence of identifiers, preserving order and dropping blanks.
    """
    out: list[str] = []

    for value in values:
        digest = hash_identifier(value, salt=salt, kind=kind)

        if digest:
            out.append(digest)

    return out


def fingerprint(payload: Any, *, length: int = 64) -> str:
    """
    Return a deterministic, unsalted digest of a structured payload.

    Used for dataset fingerprints, configuration snapshots, and idempotency
    digests, where two deployments must agree on the value.
    """
    canonical = canonical_json(payload)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    if length <= 0:
        return digest

    return digest[: min(length, _MAX_DIGEST_LENGTH)]


def dataset_fingerprint(
    *,
    account_count: int = 0,
    transaction_count: int = 0,
    complaint_count: int = 0,
    entity_count: int = 0,
    link_count: int = 0,
    extra: Optional[Mapping[str, Any]] = None,
) -> str:
    """
    Fingerprint a dataset by its shape, for reproducibility metadata.

    This records *what was analysed*, not the content of the records, so it is
    safe to store and display.
    """
    return fingerprint(
        {
            "version": "v1",
            "accounts": int(account_count),
            "transactions": int(transaction_count),
            "complaints": int(complaint_count),
            "entities": int(entity_count),
            "entity_links": int(link_count),
            "extra": dict(extra or {}),
        }
    )


def short_hash(payload: Any, length: int = HASH_PREFIX_LENGTH) -> str:
    """
    Return a short digest suitable for a filename or a display label.
    """
    return fingerprint(payload, length=max(4, length))


def stable_bucket(value: Any, buckets: int) -> int:
    """
    Map a value deterministically into `[0, buckets)`.

    Used for reproducible dataset splits: the same subject always lands in the
    same bucket regardless of iteration order or process restarts.
    """
    if buckets <= 0:
        return 0

    digest = sha256_hex(value)
    return int(digest[:8], 16) % buckets


def is_hex_digest(value: Any, *, min_length: int = 32) -> bool:
    """
    Return True when a value looks like a hex digest of sufficient length.
    """
    if not isinstance(value, str):
        return False

    text = value.strip()

    if len(text) < min_length or len(text) > _MAX_DIGEST_LENGTH:
        return False

    return all(char in "0123456789abcdefABCDEF" for char in text)


def constant_time_equals(left: Any, right: Any) -> bool:
    """
    Compare two values without leaking their difference through timing.
    """
    return hmac.compare_digest(
        str(left if left is not None else "").encode("utf-8"),
        str(right if right is not None else "").encode("utf-8"),
    )


def checksum_file(path: Any, *, algorithm: str = DEFAULT_HASH_ALGORITHM) -> Optional[str]:
    """
    Return the hex digest of a file's contents, or None when unreadable.

    Used to verify a model artifact against `ModelVersion.artifact_checksum`
    before it is loaded.
    """
    try:
        hasher = hashlib.new(algorithm)
    except (ValueError, TypeError):
        hasher = hashlib.sha256()

    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError:
        return None

    return hasher.hexdigest()
