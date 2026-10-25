"""
MULEGUARD backend authentication throttling and lockout.

This module centralizes request-rate throttling and login lockout for the
synthetic MULEGUARD prototype. It is used by `app.auth.service` and the
`/api/v1/auth` endpoints to keep authentication brute-force resistant without
introducing external dependencies.

Primary responsibilities:

- enforce bounded, sliding-window request-rate limits keyed by user, IP, route,
  or combinations thereof;
- enforce login attempt limits and temporary lockout using the persisted
  `User.failed_login_count` and `User.locked_until` fields;
- parse and validate rate-limit expressions such as `5/minute`;
- hash throttling keys so raw IPs and user identifiers are not stored directly
  in limiter maps;
- provide thread-safe, bounded, in-memory stores suitable for local prototype
  and CI use;
- expose structured decisions for diagnostics and audit metadata.

Security and product-safety rules enforced here:

- Throttling is a defensive control. It does not authenticate or authorize.
- Keys are salted and hashed. Raw IPs and user IDs are not stored in limiter
  maps.
- Failed authentication state is durable through the database where available,
  and best-effort in memory otherwise.
- Throttling never triggers automatic adverse customer action.
- Lockout is temporary and reversible. It does not deactivate or blacklist a
  user.
- Decisions are deterministic and inspectable.
- This module never logs tokens, passwords, secrets, database URLs, raw
  complaint narratives, or real customer data.

Explicit non-goals:

- This module is not a distributed rate limiter. Production deployments should
  replace the in-memory store with Redis or a gateway limiter.
- This module does not manage users, passwords, tokens, or permissions.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Throttling here protects
local demo and test workflows only.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import threading
import time
from collections import OrderedDict, defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Final, Optional

logger = logging.getLogger("muleguard.backend.auth.throttling")


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
DEFAULT_LOGIN_RATE_LIMIT: Final[str] = "5/minute"

DEFAULT_MAX_ATTEMPTS: Final[int] = 5
DEFAULT_LOCKOUT_MINUTES: Final[int] = 15
DEFAULT_ATTEMPT_WINDOW_MINUTES: Final[int] = 15

_LIMITER_MAX_KEYS: Final[int] = 10_000
_LIMITER_PRUNE_INTERVAL_SECONDS: Final[float] = 60.0

import re

_RATE_LIMIT_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(\d+)\s*/\s*(second|minute|hour|day)\s*$",
    re.IGNORECASE,
)


class ThrottleScope(str, Enum):
    """
    Throttling scope labels.
    """

    LOGIN = "login"
    PASSWORD_CHANGE = "password_change"
    GLOBAL = "global"
    ANALYSIS = "analysis"
    GRAPH = "graph"
    REPORT = "report"
    INGESTION = "ingestion"
    GENERIC = "generic"


class ThrottleOutcome(str, Enum):
    """
    Outcome label for a throttle decision.
    """

    ALLOWED = "allowed"
    THROTTLED = "throttled"
    LOCKED = "locked"
    DISABLED = "disabled"


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


def _hash_key(parts: Sequence[str], salt: str) -> str:
    """
    Produce a stable, non-reversible throttling key.

    Raw IPs and user identifiers are not stored directly in limiter maps.
    """
    joined = "\x00".join(str(part) for part in parts)
    digest = hmac.new(
        salt.encode("utf-8"),
        joined.encode("utf-8"),
        hashlib.sha256,
    )
    return digest.hexdigest()


def _key_salt(settings: Any) -> str:
    """
    Return the salt used for throttling key derivation.
    """
    return str(
        _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
        or _setting(settings, "BACKEND_SECRET_KEY", None)
        or "muleguard-throttling"
    )


# -----------------------------------------------------------------------------
# Rate-limit rule model
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """
    Parsed rate-limit rule.
    """

    limit: int
    window_seconds: int
    name: str = "custom"


def parse_rate_limit(value: Any, default: Optional[RateLimitRule] = None) -> RateLimitRule:
    """
    Parse a rate-limit string such as `5/minute` or `300/minute`.

    Returns the supplied default when the value is missing or malformed.
    """
    fallback = default or RateLimitRule(
        limit=300,
        window_seconds=60,
        name=DEFAULT_RATE_LIMIT,
    )

    if isinstance(value, RateLimitRule):
        return value

    if value is None:
        return fallback

    match = _RATE_LIMIT_RE.match(str(value))

    if not match:
        return fallback

    limit = max(1, int(match.group(1)))
    unit = match.group(2).lower()
    window_seconds = _WINDOW_SECONDS.get(unit, fallback.window_seconds)

    return RateLimitRule(
        limit=limit,
        window_seconds=max(1, int(window_seconds)),
        name=str(value).strip(),
    )


# -----------------------------------------------------------------------------
# Throttle decision
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ThrottleDecision:
    """
    Safe throttle decision result.
    """

    outcome: ThrottleOutcome
    scope: str
    remaining: int = 0
    limit: int = 0
    window_seconds: int = 0
    retry_after_seconds: int = 0
    reason: Optional[str] = None

    @property
    def allowed(self) -> bool:
        """
        Return True when the action is allowed.
        """
        return self.outcome in {ThrottleOutcome.ALLOWED, ThrottleOutcome.DISABLED}

    def to_metadata(self) -> dict[str, Any]:
        """
        Return a safe metadata mapping for audit events.
        """
        return {
            "outcome": self.outcome.value,
            "scope": self.scope,
            "remaining": self.remaining,
            "limit": self.limit,
            "window_seconds": self.window_seconds,
            "retry_after_seconds": self.retry_after_seconds,
            "reason": self.reason,
        }


# -----------------------------------------------------------------------------
# Sliding-window in-memory limiter
# -----------------------------------------------------------------------------


class SlidingWindowLimiter:
    """
    Thread-safe, bounded, sliding-window rate limiter.

    This is intentionally process-local and non-durable. It is suitable for
    local prototype and CI use. Production deployments should replace it with a
    shared store such as Redis or a gateway limiter.
    """

    def __init__(
        self,
        *,
        max_keys: int = _LIMITER_MAX_KEYS,
        prune_interval_seconds: float = _LIMITER_PRUNE_INTERVAL_SECONDS,
    ) -> None:
        self.max_keys = max(100, int(max_keys))
        self.prune_interval_seconds = max(1.0, float(prune_interval_seconds))
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()
        self._last_prune = time.monotonic()

    def _prune_expired(self, now: float, max_window_seconds: int) -> None:
        cutoff = now - max(60, int(max_window_seconds) * 2)
        stale: list[str] = []

        for key, bucket in self._buckets.items():
            if not bucket or bucket[-1] <= cutoff:
                stale.append(key)

        for key in stale:
            self._buckets.pop(key, None)

    def check(self, key: str, rule: RateLimitRule) -> tuple[bool, int, int]:
        """
        Check and consume one request against a bucket.

        Returns:

            (allowed, remaining, retry_after_seconds)
        """
        now = time.monotonic()
        cutoff = now - rule.window_seconds

        with self._lock:
            if now - self._last_prune >= self.prune_interval_seconds:
                self._prune_expired(now, rule.window_seconds)
                self._last_prune = now

            bucket = self._buckets.get(key)

            if bucket is None:
                bucket = deque()
                self._buckets[key] = bucket
            else:
                self._buckets.move_to_end(key)

            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= rule.limit:
                oldest = bucket[0] if bucket else now
                retry_after = max(1, int(math.ceil(oldest + rule.window_seconds - now)))
                return False, 0, retry_after

            bucket.append(now)
            remaining = max(0, rule.limit - len(bucket))
            return True, remaining, max(1, int(math.ceil(rule.window_seconds)))

    def peek(self, key: str, rule: RateLimitRule) -> tuple[int, int]:
        """
        Inspect a bucket without consuming a request.

        Returns:

            (used, remaining)
        """
        now = time.monotonic()
        cutoff = now - rule.window_seconds

        with self._lock:
            bucket = self._buckets.get(key)

            if bucket is None:
                return 0, rule.limit

            active = [ts for ts in bucket if ts > cutoff]
            used = len(active)
            remaining = max(0, rule.limit - used)
            return used, remaining


# Shared limiter instance used by the default throttler.
_DEFAULT_LIMITER: Final[SlidingWindowLimiter] = SlidingWindowLimiter()


# -----------------------------------------------------------------------------
# Login throttler
# -----------------------------------------------------------------------------


class LoginThrottler:
    """
    Combines request-rate throttling with persisted login lockout.

    Request-rate limiting uses the process-local `SlidingWindowLimiter`. Login
    lockout uses the persisted `User.failed_login_count` and `User.locked_until`
    fields when a user object is supplied.
    """

    def __init__(
        self,
        settings: Any | None = None,
        *,
        limiter: SlidingWindowLimiter | None = None,
    ) -> None:
        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        self.settings = settings
        self.limiter = limiter or _DEFAULT_LIMITER

    # ---------------------------------------------------------------------
    # Configuration helpers
    # ---------------------------------------------------------------------

    def _enabled(self) -> bool:
        # Either switch turns throttling off; both default to on. `or` here
        # made `AUTH_RATE_LIMIT_ENABLED=false` ineffective, because
        # `RATE_LIMIT_ENABLED` is undeclared and so always read as its `True`
        # default. Matches `RateLimitSettings.enabled()`.
        return (
            _as_bool(_setting(self.settings, "AUTH_RATE_LIMIT_ENABLED", True), True)
            and _as_bool(_setting(self.settings, "RATE_LIMIT_ENABLED", True), True)
        )

    def _max_attempts(self) -> int:
        return max(
            1,
            _as_int(
                _setting(self.settings, "AUTH_LOGIN_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS),
                DEFAULT_MAX_ATTEMPTS,
            ),
        )

    def _lockout_minutes(self) -> int:
        return max(
            0,
            _as_int(
                _setting(self.settings, "AUTH_LOGIN_LOCKOUT_MINUTES", DEFAULT_LOCKOUT_MINUTES),
                DEFAULT_LOCKOUT_MINUTES,
            ),
        )

    def _attempt_window_minutes(self) -> int:
        return max(
            1,
            _as_int(
                _setting(
                    self.settings,
                    "AUTH_LOGIN_ATTEMPT_WINDOW_MINUTES",
                    DEFAULT_ATTEMPT_WINDOW_MINUTES,
                ),
                DEFAULT_ATTEMPT_WINDOW_MINUTES,
            ),
        )

    def _reset_on_success(self) -> bool:
        return _as_bool(_setting(self.settings, "AUTH_LOGIN_RESET_ON_SUCCESS", True), True)

    def _login_rule(self) -> RateLimitRule:
        configured = _setting(self.settings, "AUTH_RATE_LIMIT_LOGIN", DEFAULT_LOGIN_RATE_LIMIT)
        return parse_rate_limit(configured, parse_rate_limit(DEFAULT_LOGIN_RATE_LIMIT))

    def _generic_rule(self, scope: ThrottleScope) -> RateLimitRule:
        setting_name = f"AUTH_RATE_LIMIT_{scope.value.upper()}"
        configured = _setting(self.settings, setting_name, None)

        if configured is not None:
            return parse_rate_limit(configured)

        global_configured = _setting(self.settings, "AUTH_RATE_LIMIT_GLOBAL", DEFAULT_RATE_LIMIT)
        return parse_rate_limit(global_configured, parse_rate_limit(DEFAULT_RATE_LIMIT))

    # ---------------------------------------------------------------------
    # Key builders
    # ---------------------------------------------------------------------

    def _build_key(
        self,
        *,
        scope: str,
        method: str,
        path: str,
        user_id: Optional[str] = None,
        ip: Optional[str] = None,
        by: str = "user_and_ip",
    ) -> str:
        parts: list[str] = [scope, method.upper(), path]

        if by in {"user", "user_and_ip"} and user_id:
            parts.append(f"user:{user_id}")

        if by in {"ip", "user_and_ip"} and ip:
            parts.append(f"ip:{ip}")

        return _hash_key(parts, _key_salt(self.settings))

    # ---------------------------------------------------------------------
    # Request-rate checks
    # ---------------------------------------------------------------------

    def check_rate(
        self,
        *,
        scope: ThrottleScope,
        method: str,
        path: str,
        user_id: Optional[str] = None,
        ip: Optional[str] = None,
        by: str = "user_and_ip",
        rule: Optional[RateLimitRule] = None,
    ) -> ThrottleDecision:
        """
        Check and consume one request against the rate limiter.

        Returns a ThrottleDecision describing whether the request is allowed.
        """
        if not self._enabled():
            return ThrottleDecision(
                outcome=ThrottleOutcome.DISABLED,
                scope=scope.value,
                reason="rate_limiting_disabled",
            )

        effective_rule = rule or self._generic_rule(scope)
        key = self._build_key(
            scope=scope.value,
            method=method,
            path=path,
            user_id=user_id,
            ip=ip,
            by=by,
        )

        allowed, remaining, retry_after = self.limiter.check(key, effective_rule)

        if allowed:
            return ThrottleDecision(
                outcome=ThrottleOutcome.ALLOWED,
                scope=scope.value,
                remaining=remaining,
                limit=effective_rule.limit,
                window_seconds=effective_rule.window_seconds,
                retry_after_seconds=retry_after,
            )

        return ThrottleDecision(
            outcome=ThrottleOutcome.THROTTLED,
            scope=scope.value,
            remaining=0,
            limit=effective_rule.limit,
            window_seconds=effective_rule.window_seconds,
            retry_after_seconds=retry_after,
            reason="rate_limit_exceeded",
        )

    def check_login_rate(
        self,
        *,
        method: str,
        path: str,
        ip: Optional[str] = None,
        by: str = "ip",
    ) -> ThrottleDecision:
        """
        Check the login-specific request-rate limit.
        """
        return self.check_rate(
            scope=ThrottleScope.LOGIN,
            method=method,
            path=path,
            user_id=None,
            ip=ip,
            by=by,
            rule=self._login_rule(),
        )

    # ---------------------------------------------------------------------
    # Persisted login lockout
    # ---------------------------------------------------------------------

    def is_user_locked(self, user: Any) -> bool:
        """
        Return True when a user is currently locked out.
        """
        if user is None:
            return False

        locked_until = getattr(user, "locked_until", None)

        if locked_until is None:
            return False

        now = _now_utc()

        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        return locked_until > now

    def check_login_allowed(self, user: Any) -> ThrottleDecision:
        """
        Check whether a user is allowed to attempt login based on lockout state.

        This does not consume an attempt. Call `record_login_failure` after an
        unsuccessful attempt and `record_login_success` after a successful one.
        """
        if not self._enabled():
            return ThrottleDecision(
                outcome=ThrottleOutcome.DISABLED,
                scope=ThrottleScope.LOGIN.value,
                reason="rate_limiting_disabled",
            )

        if self.is_user_locked(user):
            locked_until = getattr(user, "locked_until", None)
            retry_after = 0

            if locked_until is not None:
                if locked_until.tzinfo is None:
                    locked_until = locked_until.replace(tzinfo=timezone.utc)

                retry_after = max(0, int((locked_until - _now_utc()).total_seconds()))

            return ThrottleDecision(
                outcome=ThrottleOutcome.LOCKED,
                scope=ThrottleScope.LOGIN.value,
                retry_after_seconds=retry_after,
                reason="user_locked",
            )

        return ThrottleDecision(
            outcome=ThrottleOutcome.ALLOWED,
            scope=ThrottleScope.LOGIN.value,
            remaining=self._max_attempts() - int(getattr(user, "failed_login_count", 0) or 0),
            limit=self._max_attempts(),
            window_seconds=self._attempt_window_minutes() * 60,
        )

    def record_login_failure(self, user: Any) -> None:
        """
        Record a failed login attempt and apply lockout when thresholds are met.
        """
        if user is None:
            return

        max_attempts = self._max_attempts()
        lockout_minutes = self._lockout_minutes()

        user.failed_login_count = int(getattr(user, "failed_login_count", 0) or 0) + 1

        if lockout_minutes > 0 and user.failed_login_count >= max_attempts:
            user.locked_until = _now_utc() + timedelta(minutes=lockout_minutes)

    def record_login_success(self, user: Any) -> None:
        """
        Clear failed-attempt counters and lockout after a successful login.
        """
        if user is None:
            return

        if self._reset_on_success():
            user.failed_login_count = 0
            user.locked_until = None

    def clear_expired_lockout(self, user: Any) -> None:
        """
        Clear a lockout that has already expired.
        """
        if user is None:
            return

        locked_until = getattr(user, "locked_until", None)

        if locked_until is None:
            return

        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        if locked_until <= _now_utc():
            user.locked_until = None
            user.failed_login_count = 0

    def unlock_user(self, user: Any) -> None:
        """
        Forcibly clear lockout and failed-attempt counters.

        This is an administrative action and must be authorized by callers.
        """
        if user is None:
            return

        user.failed_login_count = 0
        user.locked_until = None


# -----------------------------------------------------------------------------
# Convenience factory
# -----------------------------------------------------------------------------

_default_throttler: Optional[LoginThrottler] = None


def get_login_throttler(settings: Any | None = None) -> LoginThrottler:
    """
    Return a process-wide login throttler.

    If settings are provided, a new throttler is created and becomes the default.
    """
    global _default_throttler

    if _default_throttler is None or settings is not None:
        _default_throttler = LoginThrottler(settings=settings)

    return _default_throttler


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "LoginThrottler",
    "RateLimitRule",
    "SlidingWindowLimiter",
    "ThrottleDecision",
    "ThrottleOutcome",
    "ThrottleScope",
    "get_login_throttler",
    "parse_rate_limit",
]