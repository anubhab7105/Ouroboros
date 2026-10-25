"""
MULEGUARD backend core caching.

This module provides reusable, bounded, safe caching primitives for the
MULEGUARD backend.

Primary responsibilities:

- provide a bounded, thread-safe, process-local cache with TTL and LRU eviction;
- provide deterministic, salted, namespace/version-aware cache keys;
- provide safe key canonicalization that avoids leaking secrets into cache key
  material;
- provide stampede protection through per-key locking in `get_or_set`;
- provide async-safe helper functions for asynchronous factories;
- provide cache decorators for synchronous and asynchronous functions;
- provide a null cache for disabled configurations;
- provide safe diagnostics and statistics.

Relationship to other modules:

- Services may use this module for expensive derived views such as dashboard
  aggregates, bounded graph summaries, model metadata, or report previews.
- API dependencies and endpoints should not cache authenticated secrets, raw
  complaint narratives, tokens, passwords, or real customer data.
- Production multi-instance deployments should replace the local memory backend
  with a reviewed shared cache backend.

Security and product-safety rules enforced here:

- Cache keys are canonicalized and hashed. Long or unsafe key material is not
  stored verbatim.
- Sensitive mapping keys are redacted during key canonicalization.
- Cache entries expire by TTL and are bounded by max-entry LRU eviction.
- Disabled caches execute factories directly and never store values.
- Cache values are stored by reference in-process. Callers remain responsible
  for not caching sensitive payloads.
- Caching never triggers automatic adverse customer action.
- Caching does not claim production readiness.

Explicit non-goals:

- This module does not implement a distributed cache.
- This module does not persist cache entries.
- This module does not serialize values to disk.
- This module does not cache request bodies, response bodies, tokens, secrets,
  passwords, raw complaint narratives, or real customer data.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import hmac
import inspect
import json
import logging
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Final, Optional, Protocol, runtime_checkable

from app.exceptions import ConfigurationError

logger = logging.getLogger("muleguard.backend.core.cache")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

DEFAULT_NAMESPACE: Final[str] = "muleguard"
DEFAULT_KEY_VERSION: Final[str] = "v1"
DEFAULT_TTL_SECONDS: Final[int] = 300
DEFAULT_MAX_TTL_SECONDS: Final[int] = 3600
DEFAULT_MAX_ENTRIES: Final[int] = 2048
DEFAULT_PRUNE_INTERVAL_SECONDS: Final[float] = 60.0
DEFAULT_MAX_KEY_LOCKS: Final[int] = 1024
DEFAULT_MAX_ASYNC_LOCKS: Final[int] = 1024

_MAX_KEY_PART_LENGTH: Final[int] = 1000
_MAX_CANONICAL_DEPTH: Final[int] = 5
_MAX_CANONICAL_SEQUENCE_LENGTH: Final[int] = 50
_MAX_CANONICAL_MAPPING_KEYS: Final[int] = 50

_SAFE_NAMESPACE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._:-]+")
_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

_SENSITIVE_KEY_TOKENS: Final[tuple[str, ...]] = (
    "access_key",
    "access_token",
    "account_number",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "card_number",
    "credential",
    "customer_data",
    "customer_id",
    "cvv",
    "device_id",
    "email_address",
    "ground_truth",
    "hash",
    "id_token",
    "identifier_hash",
    "ifsc",
    "ip_address",
    "narrative",
    "otp",
    "pan",
    "passphrase",
    "password",
    "passwd",
    "payload_hash",
    "phone_number",
    "pin",
    "private_key",
    "raw_",
    "real_data",
    "refresh_token",
    "ring",
    "scenario",
    "secret",
    "secret_key",
    "session",
    "token",
    "upi_id",
)

_MISSING: Final[object] = object()


# -----------------------------------------------------------------------------
# Public sentinel
# -----------------------------------------------------------------------------

MISSING: Final[Any] = _MISSING


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


def _as_float(value: object, default: float) -> float:
    """
    Safely convert a setting to float.
    """
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _clean_text(value: Any, limit: int = 200) -> str:
    """
    Return a safe single-line text value.
    """
    text = str(value if value is not None else "")
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())

    if len(text) > limit:
        return text[:limit]

    return text


def _is_sensitive_key(key: str) -> bool:
    """
    Return True when a mapping key appears sensitive or leakage-prone.
    """
    lowered = key.strip().lower()
    return any(token in lowered for token in _SENSITIVE_KEY_TOKENS)


def _sanitize_namespace(value: Any) -> str:
    """
    Normalize a cache namespace.
    """
    text = _clean_text(value, 128) or DEFAULT_NAMESPACE
    sanitized = _SAFE_NAMESPACE_RE.sub("-", text).strip("-._:")

    return sanitized or DEFAULT_NAMESPACE


def _canonical_key_value(value: Any, depth: int = 0) -> str:
    """
    Convert an arbitrary value into a bounded canonical key fragment.

    This intentionally avoids calling `repr()` on arbitrary objects because
    object representations may leak sensitive internal state.
    """
    if depth > _MAX_CANONICAL_DEPTH:
        return "<depth>"

    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, int):
        return str(value)

    if isinstance(value, float):
        return repr(value)

    if isinstance(value, str):
        text = value[:_MAX_KEY_PART_LENGTH]
        return json.dumps(text, ensure_ascii=False)

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, Enum):
        return _canonical_key_value(value.value, depth + 1)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.urlsafe_b64encode(bytes(value)).decode("ascii")

    if isinstance(value, Mapping):
        items: list[str] = []

        for raw_key, raw_value in list(value.items())[:_MAX_CANONICAL_MAPPING_KEYS]:
            key_text = str(raw_key)

            if _is_sensitive_key(key_text):
                items.append(f"{json.dumps(key_text, ensure_ascii=False)}:<redacted>")
                continue

            items.append(
                f"{json.dumps(key_text, ensure_ascii=False)}:{_canonical_key_value(raw_value, depth + 1)}"
            )

        return "{" + ",".join(items) + "}"

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        limited = list(value)[:_MAX_CANONICAL_SEQUENCE_LENGTH]
        items = [_canonical_key_value(item, depth + 1) for item in limited]

        if len(value) > _MAX_CANONICAL_SEQUENCE_LENGTH:
            items.append("<truncated>")

        return "[" + ",".join(items) + "]"

    if isinstance(value, (set, frozenset)):
        limited = list(value)[:_MAX_CANONICAL_SEQUENCE_LENGTH]

        try:
            ordered = sorted(
                _canonical_key_value(item, depth + 1) for item in limited
            )
        except Exception:
            ordered = [_canonical_key_value(item, depth + 1) for item in limited]

        if len(value) > _MAX_CANONICAL_SEQUENCE_LENGTH:
            ordered.append("<truncated>")

        return "{" + ",".join(ordered) + "}"

    return f"<{type(value).__name__}>"


# -----------------------------------------------------------------------------
# Cache key building
# -----------------------------------------------------------------------------


def build_cache_key(
    namespace: str,
    parts: Sequence[Any],
    *,
    version: str = DEFAULT_KEY_VERSION,
    salt: str = "",
) -> str:
    """
    Build a deterministic, bounded, salted cache key.

    The returned key is safe to use as an in-memory dictionary key. Raw key
    material is not stored verbatim unless it is short and already canonical.
    """
    safe_namespace = _sanitize_namespace(namespace)
    safe_version = _clean_text(version, 32) or DEFAULT_KEY_VERSION

    canonical_parts = [
        _canonical_key_value(part, depth=0)
        for part in parts
        if part is not None
    ]

    material = "\x00".join(
        [
            safe_namespace,
            safe_version,
            *canonical_parts,
        ]
    )

    if salt:
        digest = hmac.new(
            salt.encode("utf-8", errors="replace"),
            material.encode("utf-8", errors="replace"),
            hashlib.sha256,
        ).hexdigest()
    else:
        digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()

    return f"{safe_namespace}:{safe_version}:{digest[:48]}"


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CacheConfig:
    """
    Bounded cache configuration.
    """

    enabled: bool = True
    namespace: str = DEFAULT_NAMESPACE
    key_version: str = DEFAULT_KEY_VERSION
    key_salt: str = ""
    max_entries: int = DEFAULT_MAX_ENTRIES
    default_ttl_seconds: float = DEFAULT_TTL_SECONDS
    max_ttl_seconds: float = DEFAULT_MAX_TTL_SECONDS
    prune_interval_seconds: float = DEFAULT_PRUNE_INTERVAL_SECONDS
    max_key_locks: int = DEFAULT_MAX_KEY_LOCKS

    def __post_init__(self) -> None:
        object.__setattr__(self, "namespace", _sanitize_namespace(self.namespace))
        object.__setattr__(
            self,
            "key_version",
            _clean_text(self.key_version, 32) or DEFAULT_KEY_VERSION,
        )

        max_entries = max(16, int(self.max_entries))
        default_ttl = max(0.0, float(self.default_ttl_seconds))
        max_ttl = max(default_ttl, float(self.max_ttl_seconds))

        object.__setattr__(self, "max_entries", max_entries)
        object.__setattr__(self, "default_ttl_seconds", default_ttl)
        object.__setattr__(self, "max_ttl_seconds", max_ttl)
        object.__setattr__(
            self,
            "prune_interval_seconds",
            max(1.0, float(self.prune_interval_seconds)),
        )
        object.__setattr__(self, "max_key_locks", max(16, int(self.max_key_locks)))

    @classmethod
    def from_settings(cls, settings: Any | None = None) -> "CacheConfig":
        """
        Build cache configuration from runtime settings.
        """
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        enabled = _as_bool(_setting(settings, "CACHE_ENABLED", True), True)

        key_salt = str(
            _setting(settings, "CACHE_KEY_SALT", None)
            or _setting(settings, "BACKEND_SECRET_KEY", None)
            or ""
        )

        return cls(
            enabled=enabled,
            namespace=str(_setting(settings, "CACHE_NAMESPACE", DEFAULT_NAMESPACE)),
            key_version=str(_setting(settings, "CACHE_KEY_VERSION", DEFAULT_KEY_VERSION)),
            key_salt=key_salt,
            max_entries=_as_int(_setting(settings, "CACHE_MAX_ENTRIES", DEFAULT_MAX_ENTRIES), DEFAULT_MAX_ENTRIES),
            default_ttl_seconds=_as_float(
                _setting(settings, "CACHE_DEFAULT_TTL_SECONDS", DEFAULT_TTL_SECONDS),
                float(DEFAULT_TTL_SECONDS),
            ),
            max_ttl_seconds=_as_float(
                _setting(settings, "CACHE_MAX_TTL_SECONDS", DEFAULT_MAX_TTL_SECONDS),
                float(DEFAULT_MAX_TTL_SECONDS),
            ),
            prune_interval_seconds=_as_float(
                _setting(settings, "CACHE_PRUNE_INTERVAL_SECONDS", DEFAULT_PRUNE_INTERVAL_SECONDS),
                DEFAULT_PRUNE_INTERVAL_SECONDS,
            ),
            max_key_locks=_as_int(
                _setting(settings, "CACHE_MAX_KEY_LOCKS", DEFAULT_MAX_KEY_LOCKS),
                DEFAULT_MAX_KEY_LOCKS,
            ),
        )


# -----------------------------------------------------------------------------
# Stats and entries
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CacheStats:
    """
    Safe cache statistics.
    """

    hits: int = 0
    misses: int = 0
    sets: int = 0
    deletes: int = 0
    expired: int = 0
    evictions: int = 0
    size: int = 0
    max_entries: int = 0
    enabled: bool = True
    backend: str = "memory"

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable mapping.
        """
        return {
            "hits": self.hits,
            "misses": self.misses,
            "sets": self.sets,
            "deletes": self.deletes,
            "expired": self.expired,
            "evictions": self.evictions,
            "size": self.size,
            "max_entries": self.max_entries,
            "enabled": self.enabled,
            "backend": self.backend,
        }


class CacheEntry:
    """
    Mutable cache entry.
    """

    __slots__ = ("value", "created_at", "expires_at", "hits", "last_access")

    def __init__(self, value: Any, created_at: float, expires_at: float) -> None:
        self.value = value
        self.created_at = float(created_at)
        self.expires_at = float(expires_at)
        self.hits = 0
        self.last_access = float(created_at)

    def is_expired(self, now: float) -> bool:
        """
        Return True when the entry is expired.
        """
        return now >= self.expires_at


# -----------------------------------------------------------------------------
# Cache protocol and base classes
# -----------------------------------------------------------------------------


@runtime_checkable
class CacheBackend(Protocol):
    """
    Protocol for cache backends.
    """

    enabled: bool

    def make_key(self, *parts: Any, subnamespace: Optional[str] = None) -> str:
        """
        Build a namespaced cache key.
        """
        raise NotImplementedError

    def get(self, key: str, default: Any = None) -> Any:
        """
        Return a cached value or default.
        """
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """
        Store a value with bounded TTL.
        """
        raise NotImplementedError

    def delete(self, key: str) -> bool:
        """
        Delete one key.
        """
        raise NotImplementedError

    def clear(self, prefix: Optional[str] = None) -> int:
        """
        Clear all keys or keys matching a prefix.
        """
        raise NotImplementedError

    def get_or_set(
        self,
        key: str,
        factory: Callable[[], Any],
        *,
        ttl: Optional[float] = None,
        force_refresh: bool = False,
    ) -> Any:
        """
        Return a cached value or compute and store it.
        """
        raise NotImplementedError

    def stats(self) -> CacheStats:
        """
        Return safe cache statistics.
        """
        raise NotImplementedError


class BaseCache:
    """
    Common cache behaviour shared by concrete backends.
    """

    enabled: bool = True

    def make_key(self, *parts: Any, subnamespace: Optional[str] = None) -> str:
        """
        Build a namespaced cache key.
        """
        raise NotImplementedError

    def get(self, key: str, default: Any = None) -> Any:
        """
        Return a cached value or default.
        """
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """
        Store a value.
        """
        raise NotImplementedError

    def delete(self, key: str) -> bool:
        """
        Delete one key.
        """
        raise NotImplementedError

    def clear(self, prefix: Optional[str] = None) -> int:
        """
        Clear keys.
        """
        raise NotImplementedError

    def get_or_set(
        self,
        key: str,
        factory: Callable[[], Any],
        *,
        ttl: Optional[float] = None,
        force_refresh: bool = False,
    ) -> Any:
        """
        Return a cached value or compute and store it.
        """
        raise NotImplementedError

    def stats(self) -> CacheStats:
        """
        Return safe cache statistics.
        """
        raise NotImplementedError


class NullCache(BaseCache):
    """
    Disabled cache implementation.

    This cache stores nothing and always executes factories directly.
    """

    enabled: bool = False

    def __init__(self, config: Optional[CacheConfig] = None) -> None:
        self.config = config or CacheConfig(enabled=False)

    def make_key(self, *parts: Any, subnamespace: Optional[str] = None) -> str:
        namespace = self.config.namespace

        if subnamespace:
            namespace = f"{namespace}.{_sanitize_namespace(subnamespace)}"

        return build_cache_key(
            namespace,
            list(parts),
            version=self.config.key_version,
            salt=self.config.key_salt,
        )

    def get(self, key: str, default: Any = None) -> Any:
        return default

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        return False

    def delete(self, key: str) -> bool:
        return False

    def clear(self, prefix: Optional[str] = None) -> int:
        return 0

    def get_or_set(
        self,
        key: str,
        factory: Callable[[], Any],
        *,
        ttl: Optional[float] = None,
        force_refresh: bool = False,
    ) -> Any:
        result = factory()

        if inspect.isawaitable(result):
            close = getattr(result, "close", None)

            if callable(close):
                try:
                    close()
                except Exception:
                    pass

            raise ConfigurationError(
                "Use async_get_or_set for asynchronous cache factories."
            )

        return result

    def stats(self) -> CacheStats:
        return CacheStats(enabled=False, backend="null", max_entries=0)


class MemoryCache(BaseCache):
    """
    Bounded, thread-safe, process-local memory cache.

    This backend uses TTL expiration and LRU eviction. It is intended for local
    prototype, demo, and CI use. It is not durable and is not shared across
    processes or hosts.
    """

    enabled: bool = True

    def __init__(self, config: Optional[CacheConfig] = None) -> None:
        self.config = config or CacheConfig()
        self.enabled = bool(self.config.enabled)

        self._data: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._key_locks: OrderedDict[str, threading.Lock] = OrderedDict()

        self._hits = 0
        self._misses = 0
        self._sets = 0
        self._deletes = 0
        self._expired = 0
        self._evictions = 0
        self._last_prune = 0.0

    # ---------------------------------------------------------------------
    # Key helpers
    # ---------------------------------------------------------------------

    def make_key(self, *parts: Any, subnamespace: Optional[str] = None) -> str:
        """
        Build a namespaced cache key using this cache's configuration.
        """
        namespace = self.config.namespace

        if subnamespace:
            namespace = f"{namespace}.{_sanitize_namespace(subnamespace)}"

        return build_cache_key(
            namespace,
            list(parts),
            version=self.config.key_version,
            salt=self.config.key_salt,
        )

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------

    def _resolve_ttl(self, ttl: Optional[float]) -> float:
        """
        Resolve and clamp TTL.
        """
        if ttl is None:
            resolved = float(self.config.default_ttl_seconds)
        else:
            resolved = float(ttl)

        if resolved <= 0:
            return 0.0

        return min(resolved, float(self.config.max_ttl_seconds))

    def _maybe_prune(self, now: float) -> None:
        """
        Lazily prune expired entries and enforce the bounded entry limit.
        """
        due = now - self._last_prune >= self.config.prune_interval_seconds
        over_capacity = len(self._data) > self.config.max_entries

        if not due and not over_capacity:
            return

        expired_keys: list[str] = []

        for key, entry in self._data.items():
            if entry.is_expired(now):
                expired_keys.append(key)

        for key in expired_keys:
            self._data.pop(key, None)
            self._expired += 1

        while len(self._data) > self.config.max_entries:
            self._data.popitem(last=False)
            self._evictions += 1

        self._last_prune = now

    def _get_internal(self, key: str, default: Any = _MISSING) -> Any:
        """
        Internal get supporting sentinel behaviour.
        """
        if not self.enabled:
            return None if default is _MISSING else default

        now = time.monotonic()

        with self._lock:
            self._maybe_prune(now)

            entry = self._data.get(key)

            if entry is None:
                self._misses += 1
                return None if default is _MISSING else default

            if entry.is_expired(now):
                self._data.pop(key, None)
                self._expired += 1
                self._misses += 1
                return None if default is _MISSING else default

            self._data.move_to_end(key)
            entry.hits += 1
            entry.last_access = now
            self._hits += 1
            return entry.value

    def _get_key_lock(self, key: str) -> threading.Lock:
        """
        Return a bounded per-key lock for stampede protection.
        """
        with self._lock:
            existing = self._key_locks.get(key)

            if existing is not None:
                self._key_locks.move_to_end(key)
                return existing

            while len(self._key_locks) >= self.config.max_key_locks:
                self._key_locks.popitem(last=False)

            lock = threading.Lock()
            self._key_locks[key] = lock
            return lock

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """
        Return a cached value or default.
        """
        return self._get_internal(key, default)

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """
        Store a value with bounded TTL.
        """
        if not self.enabled:
            return False

        resolved_ttl = self._resolve_ttl(ttl)

        if resolved_ttl <= 0:
            return False

        now = time.monotonic()
        expires_at = now + resolved_ttl

        with self._lock:
            self._maybe_prune(now)

            if key in self._data:
                self._data[key] = CacheEntry(value, now, expires_at)
                self._data.move_to_end(key)
            else:
                while len(self._data) >= self.config.max_entries:
                    self._data.popitem(last=False)
                    self._evictions += 1

                self._data[key] = CacheEntry(value, now, expires_at)

            self._sets += 1
            return True

    def delete(self, key: str) -> bool:
        """
        Delete one key.
        """
        with self._lock:
            entry = self._data.pop(key, None)

            if entry is not None:
                self._deletes += 1
                return True

            return False

    def clear(self, prefix: Optional[str] = None) -> int:
        """
        Clear all keys or keys matching a prefix.
        """
        with self._lock:
            if prefix is None:
                count = len(self._data)
                self._data.clear()
                self._deletes += count
                return count

            matching = [key for key in self._data if key.startswith(prefix)]

            for key in matching:
                self._data.pop(key, None)

            self._deletes += len(matching)
            return len(matching)

    def get_or_set(
        self,
        key: str,
        factory: Callable[[], Any],
        *,
        ttl: Optional[float] = None,
        force_refresh: bool = False,
    ) -> Any:
        """
        Return a cached value or compute and store it.

        Per-key locking prevents multiple threads from recomputing the same
        expensive value simultaneously.
        """
        if not self.enabled:
            result = factory()

            if inspect.isawaitable(result):
                close = getattr(result, "close", None)

                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

                raise ConfigurationError(
                    "Use async_get_or_set for asynchronous cache factories."
                )

            return result

        if not force_refresh:
            cached_value = self._get_internal(key, _MISSING)

            if cached_value is not _MISSING:
                return cached_value

        lock = self._get_key_lock(key)

        with lock:
            if not force_refresh:
                cached_value = self._get_internal(key, _MISSING)

                if cached_value is not _MISSING:
                    return cached_value

            result = factory()

            if inspect.isawaitable(result):
                close = getattr(result, "close", None)

                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

                raise ConfigurationError(
                    "Use async_get_or_set for asynchronous cache factories."
                )

            self.set(key, result, ttl=ttl)
            return result

    def stats(self) -> CacheStats:
        """
        Return safe cache statistics.
        """
        with self._lock:
            return CacheStats(
                hits=self._hits,
                misses=self._misses,
                sets=self._sets,
                deletes=self._deletes,
                expired=self._expired,
                evictions=self._evictions,
                size=len(self._data),
                max_entries=self.config.max_entries,
                enabled=self.enabled,
                backend="memory",
            )


# -----------------------------------------------------------------------------
# Async helper locks
# -----------------------------------------------------------------------------

_ASYNC_LOCKS: dict[str, asyncio.Lock] = {}
_ASYNC_LOCK_GUARD = threading.Lock()


def _get_async_lock(key: str) -> asyncio.Lock:
    """
    Return a bounded per-key asyncio lock.
    """
    with _ASYNC_LOCK_GUARD:
        existing = _ASYNC_LOCKS.get(key)

        if existing is not None:
            return existing

        while len(_ASYNC_LOCKS) >= DEFAULT_MAX_ASYNC_LOCKS:
            oldest_key = next(iter(_ASYNC_LOCKS), None)

            if oldest_key is None:
                break

            _ASYNC_LOCKS.pop(oldest_key, None)

        lock = asyncio.Lock()
        _ASYNC_LOCKS[key] = lock
        return lock


async def async_get_or_set(
    cache: CacheBackend,
    key: str,
    factory: Callable[[], Any],
    *,
    ttl: Optional[float] = None,
    force_refresh: bool = False,
) -> Any:
    """
    Async-safe cache lookup with optional asynchronous factory support.

    The cache backend itself remains synchronous because the bundled backend is
    process-local. The async lock prevents concurrent coroutine stampedes for
    the same key.
    """
    if not getattr(cache, "enabled", False):
        result = factory()

        if inspect.isawaitable(result):
            return await result

        return result

    if not force_refresh:
        cached_value = cache.get(key, _MISSING)

        if cached_value is not _MISSING:
            return cached_value

    lock = _get_async_lock(key)

    async with lock:
        if not force_refresh:
            cached_value = cache.get(key, _MISSING)

            if cached_value is not _MISSING:
                return cached_value

        result = factory()

        if inspect.isawaitable(result):
            result = await result

        cache.set(key, result, ttl=ttl)
        return result


# -----------------------------------------------------------------------------
# Decorator key helpers
# -----------------------------------------------------------------------------


def _default_decorator_key_parts(
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> list[Any]:
    """
    Build safe default key parts for a cached function.

    Complex objects are reduced to their type names. Callers should provide an
    explicit key builder when function identity depends on object fields.
    """
    parts: list[Any] = [
        getattr(fn, "__module__", "<module>"),
        getattr(fn, "__qualname__", getattr(fn, "__name__", "<callable>")),
    ]

    for arg in args:
        parts.append(_canonical_key_value(arg, depth=0))

    if kwargs:
        for key in sorted(kwargs):
            parts.append(f"{key}={_canonical_key_value(kwargs[key], depth=0)}")

    return parts


def _resolve_decorator_key(
    cache: CacheBackend,
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    key_builder: Optional[Callable[..., Any]],
    subnamespace: Optional[str],
) -> str:
    """
    Resolve a cache key for decorated calls.
    """
    if key_builder is not None:
        custom_key = key_builder(*args, **kwargs)
        return cache.make_key(
            getattr(fn, "__qualname__", getattr(fn, "__name__", "<callable>")),
            custom_key,
            subnamespace=subnamespace,
        )

    parts = _default_decorator_key_parts(fn, args, kwargs)
    return cache.make_key(*parts, subnamespace=subnamespace)


# -----------------------------------------------------------------------------
# Decorators
# -----------------------------------------------------------------------------


def cached(
    cache: Optional[CacheBackend] = None,
    *,
    ttl: Optional[float] = None,
    key_builder: Optional[Callable[..., Any]] = None,
    subnamespace: Optional[str] = None,
    enabled: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorate a synchronous function with caching.

    Provide `key_builder` when the function's cache identity depends on object
    fields, query parameters, or other non-primitive inputs.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            active_cache = cache if cache is not None else get_cache()

            if not enabled or not getattr(active_cache, "enabled", False):
                return fn(*args, **kwargs)

            key = _resolve_decorator_key(
                active_cache,
                fn,
                args,
                kwargs,
                key_builder,
                subnamespace,
            )

            return active_cache.get_or_set(
                key,
                lambda: fn(*args, **kwargs),
                ttl=ttl,
            )

        return wrapper

    return decorator


def cached_async(
    cache: Optional[CacheBackend] = None,
    *,
    ttl: Optional[float] = None,
    key_builder: Optional[Callable[..., Any]] = None,
    subnamespace: Optional[str] = None,
    enabled: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorate an asynchronous function with caching.

    Provide `key_builder` when the function's cache identity depends on object
    fields, query parameters, or other non-primitive inputs.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            active_cache = cache if cache is not None else get_cache()

            if not enabled or not getattr(active_cache, "enabled", False):
                return await fn(*args, **kwargs)

            key = _resolve_decorator_key(
                active_cache,
                fn,
                args,
                kwargs,
                key_builder,
                subnamespace,
            )

            async def factory() -> Any:
                return await fn(*args, **kwargs)

            return await async_get_or_set(
                active_cache,
                key,
                factory,
                ttl=ttl,
            )

        return wrapper

    return decorator


# -----------------------------------------------------------------------------
# Default cache accessor
# -----------------------------------------------------------------------------

_default_cache: Optional[BaseCache] = None
_default_cache_lock = threading.Lock()


def get_cache(settings: Any | None = None) -> BaseCache:
    """
    Return a process-wide cache instance.

    If settings are provided, a new cache is created and becomes the default.
    This is useful for tests or applications that construct settings explicitly.
    """
    global _default_cache

    with _default_cache_lock:
        if _default_cache is None or settings is not None:
            config = CacheConfig.from_settings(settings)

            if config.enabled:
                _default_cache = MemoryCache(config)
            else:
                _default_cache = NullCache(config)

        return _default_cache


def clear_default_cache() -> None:
    """
    Clear the process-wide default cache. Intended for tests.
    """
    global _default_cache

    with _default_cache_lock:
        if _default_cache is not None:
            _default_cache.clear()

        _default_cache = None


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "BaseCache",
    "CacheBackend",
    "CacheConfig",
    "CacheEntry",
    "CacheStats",
    "MISSING",
    "MemoryCache",
    "NullCache",
    "async_get_or_set",
    "build_cache_key",
    "cached",
    "cached_async",
    "clear_default_cache",
    "get_cache",
]