"""
MULEGUARD backend core rate limiting.

This module provides reusable, bounded, thread-safe rate-limiting primitives
for the MULEGUARD backend.

Primary responsibilities:

- parse rate-limit rules from strings, mappings, integers, or explicit objects;
- support bounded sliding-window, fixed-window, and token-bucket algorithms;
- provide a process-local in-memory store suitable for local prototype and CI
  use;
- derive salted, non-reversible rate-limit keys so raw IPs, user IDs, and
  route identifiers are not stored directly;
- produce safe rate-limit decisions and response headers;
- expose diagnostics without leaking internal limiter state or sensitive data;
- fail closed when configuration is invalid.

Relationship to other modules:

- `app.api.deps` may use these primitives for API dependency-level limiting.
- `app.auth.throttling` may use these primitives for login throttling.
- Endpoint and service layers should treat rate limiting as an operational
  control, not as investigative evidence or adverse customer action.

Security and product-safety rules enforced here:

- Rate-limit keys are salted and hashed.
- Raw IPs, user IDs, passwords, tokens, secrets, database URLs, and request
  bodies are never logged or returned.
- Stores are bounded to prevent unbounded memory growth.
- Local in-memory limiting is clearly documented as non-distributed.
- Rate limiting never freezes, blocks, blacklists, closes, restricts, or
  otherwise takes adverse action against accounts or customers.
- Rate limiting does not claim production readiness.

Explicit non-goals:

- This module does not authenticate or authorize users.
- This module does not replace a distributed limiter such as Redis or a gateway
  rate limiter in multi-instance deployments.
- This module does not make investigative decisions.
- This module does not persist rate-limit state.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import re
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Final, Optional, Protocol, runtime_checkable

from app.exceptions import ConfigurationError, RateLimitError

logger = logging.getLogger("muleguard.backend.core.rate_limit")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_WINDOW_SECONDS: Final[dict[str, int]] = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
}

DEFAULT_RATE_LIMIT: Final[str] = "300/minute"
DEFAULT_MAX_KEYS: Final[int] = 10_000
DEFAULT_PRUNE_INTERVAL_SECONDS: Final[float] = 60.0
DEFAULT_MIN_PRUNE_STALE_SECONDS: Final[int] = 120

_RATE_LIMIT_SLASH_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(\d+)\s*/\s*(second|minute|hour|day)\s*$",
    re.IGNORECASE,
)

_RATE_LIMIT_WORD_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(\d+)\s+(?:per\s+)?(second|minute|hour|day)\s*$",
    re.IGNORECASE,
)

_ANONYMOUS_SUBJECT: Final[str] = "anonymous"


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class RateLimitAlgorithm(str, Enum):
    """
    Supported rate-limit algorithms.
    """

    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    TOKEN_BUCKET = "token_bucket"


class RateLimitScope(str, Enum):
    """
    Common rate-limit scopes.

    Additional string scopes are allowed by the limiter. These values are
    provided for stable defaults and diagnostics.
    """

    GLOBAL = "global"
    API = "api"
    LOGIN = "login"
    PASSWORD_CHANGE = "password_change"
    ANALYSIS = "analysis"
    GRAPH = "graph"
    REPORT = "report"
    EXPORT = "export"
    INGESTION = "ingestion"
    AUDIT = "audit"
    SEARCH = "search"


class RateLimitDecisionReason(str, Enum):
    """
    Stable reason labels for rate-limit decisions.
    """

    ALLOWED = "allowed"
    DISABLED = "disabled"
    RATE_LIMITED = "rate_limited"
    MISCONFIGURED = "misconfigured"


# -----------------------------------------------------------------------------
# Rule and decision models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """
    Parsed rate-limit rule.

    For sliding-window and fixed-window rules, `limit` requests are allowed per
    `window_seconds`.

    For token-bucket rules, `limit / window_seconds` defines the sustained refill
    rate and `burst` defines bucket capacity. When `burst` is omitted, it
    defaults to `limit`.
    """

    limit: int
    window_seconds: int
    name: str = "custom"
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW
    burst: Optional[int] = None

    def __post_init__(self) -> None:
        limit = int(self.limit)
        window_seconds = int(self.window_seconds)

        if limit <= 0:
            raise ValueError("Rate limit must be greater than zero.")

        if window_seconds <= 0:
            raise ValueError("Rate-limit window must be greater than zero.")

        if window_seconds > 365 * 24 * 3600:
            raise ValueError("Rate-limit window is too large.")

        object.__setattr__(self, "limit", limit)
        object.__setattr__(self, "window_seconds", window_seconds)

        if self.burst is not None:
            burst = int(self.burst)

            if burst <= 0:
                raise ValueError("Rate-limit burst must be greater than zero.")

            object.__setattr__(self, "burst", burst)

        if not str(self.name).strip():
            object.__setattr__(self, "name", f"{limit}/{window_seconds}s")

        if not isinstance(self.algorithm, RateLimitAlgorithm):
            object.__setattr__(
                self,
                "algorithm",
                RateLimitAlgorithm(str(self.algorithm).strip().lower()),
            )

    @property
    def rate_per_second(self) -> float:
        """
        Return the sustained rate in requests per second.
        """
        return float(self.limit) / float(self.window_seconds)

    @property
    def token_bucket_capacity(self) -> int:
        """
        Return token-bucket capacity.
        """
        if self.burst is not None:
            return int(self.burst)

        return int(self.limit)


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """
    Safe rate-limit decision.

    This object never contains raw IPs, user identifiers, passwords, tokens,
    secrets, or request bodies.
    """

    allowed: bool
    reason: RateLimitDecisionReason
    limit: int = 0
    remaining: int = 0
    reset_seconds: int = 0
    retry_after_seconds: int = 0
    key_id: str = ""
    rule_name: str = ""
    scope: str = ""
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW

    def to_headers(self) -> dict[str, str]:
        """
        Return safe rate-limit response headers.
        """
        headers = {
            "RateLimit-Limit": str(max(0, int(self.limit))),
            "RateLimit-Remaining": str(max(0, int(self.remaining))),
            "RateLimit-Reset": str(max(1, int(self.reset_seconds))),
        }

        if self.rule_name:
            policy_window = max(1, int(self.reset_seconds))
            headers["RateLimit-Policy"] = f"{self.limit};w={policy_window}"

        if not self.allowed:
            headers["Retry-After"] = str(max(1, int(self.retry_after_seconds)))

        return headers

    def to_details(self) -> dict[str, Any]:
        """
        Return safe details for errors or diagnostics.
        """
        return {
            "allowed": self.allowed,
            "reason": self.reason.value,
            "scope": self.scope,
            "rule": self.rule_name,
            "algorithm": self.algorithm.value,
            "limit": self.limit,
            "remaining": self.remaining,
            "reset_seconds": self.reset_seconds,
            "retry_after_seconds": self.retry_after_seconds,
        }


# -----------------------------------------------------------------------------
# Store protocol
# -----------------------------------------------------------------------------


@runtime_checkable
class RateLimitStore(Protocol):
    """
    Protocol for rate-limit stores.

    A production deployment may implement this protocol with Redis, Memcached,
    or another shared store. The bundled implementation is process-local.
    """

    def consume(
        self,
        key_id: str,
        rule: RateLimitRule,
        now: float,
    ) -> RateLimitDecision:
        """
        Consume one unit against a key/rule pair.
        """
        raise NotImplementedError

    def clear(self) -> None:
        """
        Clear all stored buckets.
        """
        raise NotImplementedError

    def stats(self) -> dict[str, Any]:
        """
        Return safe store statistics.
        """
        raise NotImplementedError


# -----------------------------------------------------------------------------
# Internal bucket model
# -----------------------------------------------------------------------------


class _Bucket:
    """
    Mutable rate-limit bucket state.
    """

    __slots__ = (
        "algorithm",
        "window_seconds",
        "last_access",
        "timestamps",
        "tokens",
        "last_refill",
        "window_start",
        "count",
    )

    def __init__(
        self,
        *,
        algorithm: RateLimitAlgorithm,
        window_seconds: int,
        now: float,
        token_capacity: float = 0.0,
    ) -> None:
        self.algorithm = algorithm
        self.window_seconds = int(window_seconds)
        self.last_access = float(now)

        self.timestamps: Optional[deque[float]] = (
            deque()
            if algorithm == RateLimitAlgorithm.SLIDING_WINDOW
            else None
        )

        self.tokens: float = float(token_capacity)
        self.last_refill: float = float(now)

        self.window_start: float = (
            math.floor(now / window_seconds) * window_seconds
            if algorithm == RateLimitAlgorithm.FIXED_WINDOW
            else 0.0
        )
        self.count: int = 0


# -----------------------------------------------------------------------------
# In-memory store
# -----------------------------------------------------------------------------


class MemoryRateLimitStore:
    """
    Bounded, thread-safe, process-local rate-limit store.

    This store supports sliding-window log, fixed-window, and token-bucket
    algorithms. It is intended for local prototype, demo, and CI use. It is not
    durable and is not shared across processes or hosts.
    """

    def __init__(
        self,
        *,
        max_keys: int = DEFAULT_MAX_KEYS,
        prune_interval_seconds: float = DEFAULT_PRUNE_INTERVAL_SECONDS,
    ) -> None:
        self.max_keys = max(100, int(max_keys))
        self.prune_interval_seconds = max(1.0, float(prune_interval_seconds))

        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._last_prune = 0.0

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def consume(
        self,
        key_id: str,
        rule: RateLimitRule,
        now: float,
    ) -> RateLimitDecision:
        """
        Consume one unit against a key/rule pair.
        """
        if not key_id:
            raise ValueError("Rate-limit key must not be empty.")

        now = float(now)

        with self._lock:
            self._maybe_prune(now, rule.window_seconds)

            bucket = self._buckets.get(key_id)

            if bucket is None:
                bucket = self._create_bucket(key_id, rule, now)
            else:
                self._buckets.move_to_end(key_id)
                bucket.last_access = now

            if rule.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                return self._consume_token_bucket(bucket, rule, now)

            if rule.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
                return self._consume_fixed_window(bucket, rule, now)

            return self._consume_sliding_window(bucket, rule, now)

    def clear(self) -> None:
        """
        Clear all buckets.
        """
        with self._lock:
            self._buckets.clear()

    def stats(self) -> dict[str, Any]:
        """
        Return safe store statistics.
        """
        with self._lock:
            algorithm_counts: dict[str, int] = {}

            for bucket in self._buckets.values():
                key = bucket.algorithm.value
                algorithm_counts[key] = algorithm_counts.get(key, 0) + 1

            return {
                "backend": "memory",
                "max_keys": self.max_keys,
                "active_keys": len(self._buckets),
                "algorithms": algorithm_counts,
                "distributed": False,
                "durable": False,
            }

    # ---------------------------------------------------------------------
    # Bucket lifecycle
    # ---------------------------------------------------------------------

    def _create_bucket(
        self,
        key_id: str,
        rule: RateLimitRule,
        now: float,
    ) -> _Bucket:
        """
        Create and register a new bucket.
        """
        while len(self._buckets) >= self.max_keys:
            self._buckets.popitem(last=False)

        bucket = _Bucket(
            algorithm=rule.algorithm,
            window_seconds=rule.window_seconds,
            now=now,
            token_capacity=float(rule.token_bucket_capacity),
        )

        self._buckets[key_id] = bucket
        return bucket

    def _maybe_prune(self, now: float, window_seconds: int) -> None:
        """
        Prune stale buckets periodically.
        """
        if self._last_prune and now - self._last_prune < self.prune_interval_seconds:
            return

        self._last_prune = now

        stale_cutoff = max(
            DEFAULT_MIN_PRUNE_STALE_SECONDS,
            int(window_seconds) * 2,
        )

        stale_keys: list[str] = []

        for key_id, bucket in self._buckets.items():
            if now - bucket.last_access > stale_cutoff:
                stale_keys.append(key_id)

        for key_id in stale_keys:
            self._buckets.pop(key_id, None)

    # ---------------------------------------------------------------------
    # Algorithm implementations
    # ---------------------------------------------------------------------

    def _consume_sliding_window(
        self,
        bucket: _Bucket,
        rule: RateLimitRule,
        now: float,
    ) -> RateLimitDecision:
        """
        Sliding-window log algorithm.

        This is accurate and bounded, but stores one timestamp per request in
        the current window.
        """
        timestamps = bucket.timestamps

        if timestamps is None:
            timestamps = deque()
            bucket.timestamps = timestamps

        window_seconds = float(rule.window_seconds)
        cutoff = now - window_seconds

        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        if len(timestamps) >= rule.limit:
            oldest = timestamps[0]
            retry_after = max(1, math.ceil(oldest + window_seconds - now))

            return RateLimitDecision(
                allowed=False,
                reason=RateLimitDecisionReason.RATE_LIMITED,
                limit=rule.limit,
                remaining=0,
                reset_seconds=retry_after,
                retry_after_seconds=retry_after,
                rule_name=rule.name,
                algorithm=rule.algorithm,
            )

        timestamps.append(now)
        remaining = max(0, rule.limit - len(timestamps))

        if timestamps:
            reset_seconds = max(1, math.ceil(timestamps[0] + window_seconds - now))
        else:
            reset_seconds = rule.window_seconds

        return RateLimitDecision(
            allowed=True,
            reason=RateLimitDecisionReason.ALLOWED,
            limit=rule.limit,
            remaining=remaining,
            reset_seconds=reset_seconds,
            retry_after_seconds=0,
            rule_name=rule.name,
            algorithm=rule.algorithm,
        )

    def _consume_fixed_window(
        self,
        bucket: _Bucket,
        rule: RateLimitRule,
        now: float,
    ) -> RateLimitDecision:
        """
        Fixed-window algorithm.

        This is memory efficient but can allow short bursts at window boundaries.
        """
        window_seconds = float(rule.window_seconds)
        window_start = math.floor(now / window_seconds) * window_seconds

        if bucket.window_start != window_start:
            bucket.window_start = window_start
            bucket.count = 0

        if bucket.count >= rule.limit:
            retry_after = max(1, math.ceil(window_start + window_seconds - now))

            return RateLimitDecision(
                allowed=False,
                reason=RateLimitDecisionReason.RATE_LIMITED,
                limit=rule.limit,
                remaining=0,
                reset_seconds=retry_after,
                retry_after_seconds=retry_after,
                rule_name=rule.name,
                algorithm=rule.algorithm,
            )

        bucket.count += 1
        remaining = max(0, rule.limit - bucket.count)
        reset_seconds = max(1, math.ceil(window_start + window_seconds - now))

        return RateLimitDecision(
            allowed=True,
            reason=RateLimitDecisionReason.ALLOWED,
            limit=rule.limit,
            remaining=remaining,
            reset_seconds=reset_seconds,
            retry_after_seconds=0,
            rule_name=rule.name,
            algorithm=rule.algorithm,
        )

    def _consume_token_bucket(
        self,
        bucket: _Bucket,
        rule: RateLimitRule,
        now: float,
    ) -> RateLimitDecision:
        """
        Token-bucket algorithm.

        This permits configured bursts while enforcing a sustained average rate.
        """
        capacity = float(rule.token_bucket_capacity)
        rate = rule.rate_per_second

        elapsed = max(0.0, now - bucket.last_refill)
        tokens = min(capacity, bucket.tokens + elapsed * rate)

        if tokens >= 1.0:
            tokens -= 1.0
            bucket.tokens = tokens
            bucket.last_refill = now

            remaining = int(tokens)

            if tokens >= 1.0:
                reset_seconds = 0
            else:
                reset_seconds = max(1, math.ceil((1.0 - tokens) / rate))

            return RateLimitDecision(
                allowed=True,
                reason=RateLimitDecisionReason.ALLOWED,
                limit=rule.limit,
                remaining=remaining,
                reset_seconds=reset_seconds,
                retry_after_seconds=0,
                rule_name=rule.name,
                algorithm=rule.algorithm,
            )

        bucket.tokens = tokens
        bucket.last_refill = now

        retry_after = max(1, math.ceil((1.0 - tokens) / rate))

        return RateLimitDecision(
            allowed=False,
            reason=RateLimitDecisionReason.RATE_LIMITED,
            limit=rule.limit,
            remaining=0,
            reset_seconds=retry_after,
            retry_after_seconds=retry_after,
            rule_name=rule.name,
            algorithm=rule.algorithm,
        )


# -----------------------------------------------------------------------------
# Rule parsing
# -----------------------------------------------------------------------------


def _default_rule() -> RateLimitRule:
    """
    Return the built-in default global rule.
    """
    return RateLimitRule(
        limit=300,
        window_seconds=60,
        name=DEFAULT_RATE_LIMIT,
        algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
    )


def _normalize_algorithm(value: Any) -> RateLimitAlgorithm:
    """
    Normalize an algorithm-like value.
    """
    if isinstance(value, RateLimitAlgorithm):
        return value

    text = str(value or RateLimitAlgorithm.SLIDING_WINDOW.value).strip().lower()

    try:
        return RateLimitAlgorithm(text)
    except ValueError as exc:
        raise ConfigurationError(
            "Unsupported rate-limit algorithm.",
            details={
                "allowed_algorithms": [item.value for item in RateLimitAlgorithm],
            },
        ) from exc


def parse_rate_limit(
    value: Any,
    *,
    default: Optional[RateLimitRule] = None,
    default_algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW,
) -> RateLimitRule:
    """
    Parse a rate-limit rule from common representations.

    Supported string forms:

    - `5/minute`
    - `100/hour`
    - `10 per minute`
    - `10 minute`

    Supported mapping keys:

    - `limit`
    - `window_seconds` or `window` or `unit`
    - `burst`
    - `algorithm`
    - `name`

    Raises ConfigurationError when no valid rule can be parsed and no default is
    supplied.
    """
    if isinstance(value, RateLimitRule):
        return value

    fallback = default or _default_rule()

    if value is None:
        return fallback

    if isinstance(value, int):
        if value <= 0:
            return fallback

        return RateLimitRule(
            limit=value,
            window_seconds=60,
            name=f"{value}/minute",
            algorithm=default_algorithm,
        )

    if isinstance(value, Mapping):
        try:
            limit = int(value.get("limit", 0))
        except (TypeError, ValueError):
            return fallback

        if limit <= 0:
            return fallback

        window_seconds: Optional[int] = None

        raw_window_seconds = value.get("window_seconds", None)

        if raw_window_seconds is not None:
            try:
                window_seconds = int(raw_window_seconds)
            except (TypeError, ValueError):
                window_seconds = None

        if window_seconds is None:
            unit = str(value.get("unit", "minute")).strip().lower()
            window_seconds = _WINDOW_SECONDS.get(unit, 60)

        burst_value = value.get("burst", None)
        burst: Optional[int] = None

        if burst_value is not None:
            try:
                burst = int(burst_value)
            except (TypeError, ValueError):
                burst = None

        algorithm = _normalize_algorithm(value.get("algorithm", default_algorithm))
        name = str(value.get("name", "") or "").strip()

        if not name:
            name = f"{limit}/{window_seconds}s"

        try:
            return RateLimitRule(
                limit=limit,
                window_seconds=window_seconds,
                name=name,
                algorithm=algorithm,
                burst=burst,
            )
        except ValueError:
            return fallback

    text = str(value).strip()

    if not text:
        return fallback

    match = _RATE_LIMIT_SLASH_RE.match(text) or _RATE_LIMIT_WORD_RE.match(text)

    if not match:
        if default is not None:
            return fallback

        raise ConfigurationError(
            "Invalid rate-limit rule.",
            details={"expected_examples": ["5/minute", "300/hour", "10 per second"]},
        )

    limit = int(match.group(1))
    unit = match.group(2).lower()
    window_seconds = _WINDOW_SECONDS.get(unit, 60)

    try:
        return RateLimitRule(
            limit=limit,
            window_seconds=window_seconds,
            name=text,
            algorithm=default_algorithm,
        )
    except ValueError:
        return fallback


# -----------------------------------------------------------------------------
# Key derivation
# -----------------------------------------------------------------------------


def _key_salt(settings: Any) -> str:
    """
    Resolve the key-hashing salt from settings.
    """
    if settings is None:
        return "muleguard-rate-limit"

    if isinstance(settings, Mapping):
        salt = (
            settings.get("RATE_LIMIT_KEY_SALT")
            or settings.get("AUTH_RATE_LIMIT_KEY_SALT")
            or settings.get("BACKEND_SECRET_KEY")
            or "muleguard-rate-limit"
        )
    else:
        salt = (
            getattr(settings, "RATE_LIMIT_KEY_SALT", None)
            or getattr(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
            or getattr(settings, "BACKEND_SECRET_KEY", None)
            or "muleguard-rate-limit"
        )

    return str(salt)


def build_rate_limit_key(
    parts: Sequence[str],
    salt: str,
) -> str:
    """
    Build a salted, non-reversible rate-limit key.

    Raw identifiers are not stored directly in limiter maps.
    """
    cleaned = [str(part).strip() for part in parts if str(part).strip()]

    if not cleaned:
        cleaned = [_ANONYMOUS_SUBJECT]

    joined = "\x00".join(cleaned)

    digest = hmac.new(
        salt.encode("utf-8", errors="replace"),
        joined.encode("utf-8", errors="replace"),
        hashlib.sha256,
    )

    return digest.hexdigest()


# -----------------------------------------------------------------------------
# Settings helpers
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


def _scope_setting_names(scope: str) -> tuple[str, ...]:
    """
    Return setting names checked for a scope-specific rule.
    """
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", scope).strip("_").upper()

    if not normalized:
        normalized = "GLOBAL"

    return (
        f"RATE_LIMIT_{normalized}",
        f"AUTH_RATE_LIMIT_{normalized}",
    )


# -----------------------------------------------------------------------------
# Limiter
# -----------------------------------------------------------------------------


class RateLimiter:
    """
    High-level rate limiter.

    This limiter resolves rules from settings, derives salted keys, delegates to
    a bounded store, and produces safe decisions.
    """

    def __init__(
        self,
        settings: Any | None = None,
        *,
        store: RateLimitStore | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        self.settings = settings
        self.store: RateLimitStore = store or MemoryRateLimitStore()
        self._clock = clock
        self._salt = _key_salt(settings)
        self._lock = threading.Lock()
        self._default_rule_cache: Optional[RateLimitRule] = None

    # ---------------------------------------------------------------------
    # Configuration
    # ---------------------------------------------------------------------

    def enabled(self) -> bool:
        """
        Return True when rate limiting is enabled.
        """
        return _as_bool(
            _setting(self.settings, "RATE_LIMIT_ENABLED", True),
            True,
        ) and _as_bool(
            _setting(self.settings, "AUTH_RATE_LIMIT_ENABLED", True),
            True,
        )

    def default_algorithm(self) -> RateLimitAlgorithm:
        """
        Return the configured default algorithm.
        """
        raw = _setting(
            self.settings,
            "RATE_LIMIT_ALGORITHM",
            RateLimitAlgorithm.SLIDING_WINDOW.value,
        )

        try:
            return _normalize_algorithm(raw)
        except ConfigurationError:
            return RateLimitAlgorithm.SLIDING_WINDOW

    def default_rule(self) -> RateLimitRule:
        """
        Return the default global rule.
        """
        with self._lock:
            if self._default_rule_cache is not None:
                return self._default_rule_cache

            raw = (
                _setting(self.settings, "RATE_LIMIT_DEFAULT", None)
                or _setting(self.settings, "AUTH_RATE_LIMIT_GLOBAL", None)
                or DEFAULT_RATE_LIMIT
            )

            rule = parse_rate_limit(
                raw,
                default=_default_rule(),
                default_algorithm=self.default_algorithm(),
            )

            self._default_rule_cache = rule
            return rule

    def resolve_rule(
        self,
        scope: str,
        rule: Optional[RateLimitRule] = None,
    ) -> RateLimitRule:
        """
        Resolve the effective rule for a scope.
        """
        if rule is not None:
            return rule

        for setting_name in _scope_setting_names(scope):
            raw = _setting(self.settings, setting_name, None)

            if raw is not None:
                return parse_rate_limit(
                    raw,
                    default=self.default_rule(),
                    default_algorithm=self.default_algorithm(),
                )

        return self.default_rule()

    # ---------------------------------------------------------------------
    # Checks
    # ---------------------------------------------------------------------

    def check(
        self,
        scope: str,
        *,
        subject: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        rule: Optional[RateLimitRule] = None,
        extra_key_parts: Optional[Sequence[str]] = None,
    ) -> RateLimitDecision:
        """
        Check and consume one rate-limit unit for a scope.
        """
        scope_value = (
            scope.value
            if isinstance(scope, RateLimitScope)
            else str(scope or RateLimitScope.GLOBAL.value).strip().lower()
        )

        if not self.enabled():
            return RateLimitDecision(
                allowed=True,
                reason=RateLimitDecisionReason.DISABLED,
                scope=scope_value,
            )

        resolved_rule = self.resolve_rule(scope_value, rule=rule)

        parts: list[str] = [
            scope_value,
            str(subject or _ANONYMOUS_SUBJECT),
            str(action or "-"),
            str(resource or "-"),
            resolved_rule.name,
            resolved_rule.algorithm.value,
        ]

        if extra_key_parts:
            parts.extend(str(part) for part in extra_key_parts if str(part).strip())

        key_id = build_rate_limit_key(parts, self._salt)
        now = float(self._clock())

        decision = self.store.consume(key_id, resolved_rule, now)

        return replace(
            decision,
            key_id=key_id,
            scope=scope_value,
        )

    def raise_if_denied(self, decision: RateLimitDecision) -> None:
        """
        Raise a safe RateLimitError when a decision denies the request.
        """
        if decision.allowed:
            return

        error = RateLimitError(
            message="Too many requests.",
            retry_after_seconds=max(1, int(decision.retry_after_seconds)),
            details=decision.to_details(),
        )

        error.headers.update(decision.to_headers())
        raise error

    def check_or_raise(
        self,
        scope: str,
        *,
        subject: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        rule: Optional[RateLimitRule] = None,
        extra_key_parts: Optional[Sequence[str]] = None,
    ) -> RateLimitDecision:
        """
        Check a rate limit and raise when denied.
        """
        decision = self.check(
            scope,
            subject=subject,
            action=action,
            resource=resource,
            rule=rule,
            extra_key_parts=extra_key_parts,
        )

        self.raise_if_denied(decision)
        return decision

    # ---------------------------------------------------------------------
    # Diagnostics
    # ---------------------------------------------------------------------

    def policy_snapshot(self) -> dict[str, Any]:
        """
        Return a safe snapshot of limiter policy and store state.
        """
        default_rule = self.default_rule()

        return {
            "enabled": self.enabled(),
            "default_rule": {
                "name": default_rule.name,
                "limit": default_rule.limit,
                "window_seconds": default_rule.window_seconds,
                "algorithm": default_rule.algorithm.value,
                "burst": default_rule.burst,
            },
            "store": self.store.stats(),
        }

    def clear(self) -> None:
        """
        Clear the underlying store. Intended for tests.
        """
        self.store.clear()

        with self._lock:
            self._default_rule_cache = None


# -----------------------------------------------------------------------------
# Convenience helpers
# -----------------------------------------------------------------------------


def rate_limit_error_from_decision(decision: RateLimitDecision) -> RateLimitError:
    """
    Build a safe RateLimitError from a decision.
    """
    error = RateLimitError(
        message="Too many requests.",
        retry_after_seconds=max(1, int(decision.retry_after_seconds)),
        details=decision.to_details(),
    )

    error.headers.update(decision.to_headers())
    return error


def decision_headers(decision: RateLimitDecision) -> dict[str, str]:
    """
    Return safe response headers for a decision.
    """
    return decision.to_headers()


def parse_rule_setting(
    settings: Any,
    setting_name: str,
    *,
    default: Optional[RateLimitRule] = None,
) -> RateLimitRule:
    """
    Parse one rate-limit setting by name.
    """
    raw = _setting(settings, setting_name, None)

    algorithm = RateLimitAlgorithm.SLIDING_WINDOW

    raw_algorithm = _setting(settings, "RATE_LIMIT_ALGORITHM", None)

    if raw_algorithm is not None:
        try:
            algorithm = _normalize_algorithm(raw_algorithm)
        except ConfigurationError:
            algorithm = RateLimitAlgorithm.SLIDING_WINDOW

    return parse_rate_limit(
        raw,
        default=default or _default_rule(),
        default_algorithm=algorithm,
    )


# -----------------------------------------------------------------------------
# Default limiter accessor
# -----------------------------------------------------------------------------

_default_limiter: Optional[RateLimiter] = None
_default_limiter_lock = threading.Lock()


def get_rate_limiter(settings: Any | None = None) -> RateLimiter:
    """
    Return a process-wide rate limiter.

    If settings are provided, a new limiter is created and becomes the default.
    This is useful for tests or applications that construct settings explicitly.
    """
    global _default_limiter

    with _default_limiter_lock:
        if _default_limiter is None or settings is not None:
            _default_limiter = RateLimiter(settings=settings)

        return _default_limiter


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "DEFAULT_RATE_LIMIT",
    "MemoryRateLimitStore",
    "RateLimitAlgorithm",
    "RateLimitDecision",
    "RateLimitDecisionReason",
    "RateLimitRule",
    "RateLimitScope",
    "RateLimitStore",
    "RateLimiter",
    "build_rate_limit_key",
    "decision_headers",
    "get_rate_limiter",
    "parse_rate_limit",
    "parse_rule_setting",
    "rate_limit_error_from_decision",
]