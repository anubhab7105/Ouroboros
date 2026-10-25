"""
MULEGUARD performance middleware.

This module provides a pure ASGI middleware that safely measures request
latency, adds a bounded response-time header, records low-cardinality local
performance metrics, and emits safe structured logs for slow or failed
requests.

Primary responsibilities:

- measure end-to-end HTTP request latency using monotonic clocks;
- optionally add an X-Response-Time header to HTTP responses;
- classify route labels using FastAPI/Starlette route templates where
  available, with safe fallback path normalization;
- record bounded in-memory performance metrics for local diagnostics;
- log slow requests and server-side failures without leaking sensitive data;
- skip infrastructure paths such as health, metrics, docs, and OPTIONS where
  appropriate;
- preserve streaming ASGI behaviour by modifying only http.response.start.

Important boundaries:

- This middleware is not an authentication or authorization boundary.
- This middleware does not make detection, risk, graph, complaint, case, or
  investigative decisions.
- This middleware must not log request bodies, response bodies, query strings,
  cookies, authorization headers, tokens, passwords, raw complaint narratives,
  database URLs, or real customer data.
- Performance telemetry is operational diagnostics only. It is not
  investigative evidence.
- MULEGUARD remains a synthetic-first investigative prototype. Alerts, scores,
  graph relationships, candidate money trails, and complaint correlations are
  investigative leads only.
"""

from __future__ import annotations

import logging
import math
import re
import threading
import time
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final, Optional

from starlette.types import ASGIApp, Message, Receive, Scope, Send


logger = logging.getLogger("muleguard.backend.api.middleware.performance")


# -----------------------------------------------------------------------------
# Optional package constants
# -----------------------------------------------------------------------------
# These are imported lazily/defensively so the module remains importable in
# isolated tests even if the wider middleware package is not fully wired yet.

try:  # pragma: no cover - exercised indirectly through package import
    from app.api.middleware import (
        HEALTH_PATHS as PACKAGE_HEALTH_PATHS,
        METRICS_PATHS as PACKAGE_METRICS_PATHS,
        RESPONSE_TIME_HEADER as PACKAGE_RESPONSE_TIME_HEADER,
    )

    DEFAULT_RESPONSE_TIME_HEADER: Final[str] = PACKAGE_RESPONSE_TIME_HEADER
    DEFAULT_HEALTH_PATHS: Final[tuple[str, ...]] = PACKAGE_HEALTH_PATHS
    DEFAULT_METRICS_PATHS: Final[tuple[str, ...]] = PACKAGE_METRICS_PATHS
except Exception:  # pragma: no cover - fallback for isolated module import
    DEFAULT_RESPONSE_TIME_HEADER = "X-Response-Time"
    DEFAULT_HEALTH_PATHS = ("/health", "/api/v1/health/ready")
    DEFAULT_METRICS_PATHS = ("/metrics",)


try:  # pragma: no cover - exercised indirectly through package import
    from app.api.middleware.request_id import (
        get_current_request_id as _get_current_request_id,
    )
except Exception:  # pragma: no cover - fallback for isolated module import
    _get_current_request_id = None


# -----------------------------------------------------------------------------
# Validation and sanitization limits
# -----------------------------------------------------------------------------

MAX_HEADER_VALUE_LENGTH: Final[int] = 8192
MAX_REQUEST_ID_LENGTH: Final[int] = 128
MAX_PATH_LABEL_LENGTH: Final[int] = 200
MAX_PATH_SEGMENTS: Final[int] = 12

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_HEADER_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_REQUEST_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9._:-]{1,%d}$" % MAX_REQUEST_ID_LENGTH
)

_UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_NUMERIC_ID_RE: Final[re.Pattern[str]] = re.compile(r"^\d+$")
_HEX_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{16,128}$", re.IGNORECASE)
_RESOURCE_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Z][A-Z0-9]{1,15}(?:[-_:][A-Z0-9._-]+)+$",
    re.IGNORECASE,
)


# -----------------------------------------------------------------------------
# Default skip policy
# -----------------------------------------------------------------------------

DEFAULT_SKIP_PATHS: Final[tuple[str, ...]] = tuple(
    dict.fromkeys((*DEFAULT_HEALTH_PATHS, *DEFAULT_METRICS_PATHS))
)

DEFAULT_SKIP_PREFIXES: Final[tuple[str, ...]] = (
    "/health/",
    "/metrics/",
    "/docs/",
    "/redoc/",
    "/static/",
)

DEFAULT_SKIP_METHODS: Final[tuple[str, ...]] = ("OPTIONS",)


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


def _effective(
    settings: Any,
    overrides: Mapping[str, Any],
    name: str,
    default: Any = None,
) -> Any:
    """
    Resolve a setting using explicit middleware overrides first.

    Precedence:

    1. constructor/overrides mapping;
    2. runtime settings object;
    3. supplied default.
    """
    if name in overrides:
        return overrides[name]

    return _setting(settings, name, default)


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


def _normalize_frozenset(values: Any) -> frozenset[str]:
    """
    Normalize values into an uppercase frozenset.
    """
    if values is None:
        return frozenset()

    if isinstance(values, str):
        iterable: Iterable[Any] = [values]
    elif isinstance(values, Iterable) and not isinstance(values, (bytes, bytearray)):
        iterable = values
    else:
        iterable = [values]

    return frozenset(
        str(item).strip().upper()
        for item in iterable
        if str(item).strip()
    )


def _normalize_path(path: Any) -> str:
    """
    Normalize a request path for safe prefix comparisons.
    """
    if path is None:
        return "/"

    value = str(path).strip()

    if not value:
        return "/"

    if not value.startswith("/"):
        value = f"/{value}"

    while "//" in value:
        value = value.replace("//", "/")

    if len(value) > 1 and value.endswith("/"):
        value = value.rstrip("/")

    return value or "/"


def _is_valid_header_name(name: str) -> bool:
    """
    Return True when a header name is safe to emit.
    """
    return bool(_HEADER_NAME_RE.match(name))


def _normalize_header_value(value: Any) -> Optional[str]:
    """
    Return a safe single-line HTTP header value.
    """
    if value is None:
        return None

    text_value = str(value)

    if not text_value.strip():
        return None

    text_value = _CONTROL_CHAR_RE.sub(" ", text_value)
    text_value = text_value.replace("\r", " ").replace("\n", " ")
    text_value = " ".join(text_value.split())

    if not text_value:
        return None

    if len(text_value) > MAX_HEADER_VALUE_LENGTH:
        return text_value[:MAX_HEADER_VALUE_LENGTH]

    return text_value


def _get_header(scope: Scope, name: str) -> Optional[str]:
    """
    Return the first matching request header value from the ASGI scope.
    """
    target = name.lower().encode("latin-1", errors="ignore")

    for raw_key, raw_value in scope.get("headers") or []:
        try:
            key = raw_key.lower()
        except Exception:
            continue

        if key == target:
            try:
                return raw_value.decode("latin-1", errors="ignore").strip()
            except Exception:
                return None

    return None


def _get_state_value(scope: Scope, key: str) -> Any:
    """
    Read a value from ASGI scope state, supporting dict-like and object-like
    state containers.
    """
    state = scope.get("state")

    if state is None:
        return None

    if isinstance(state, Mapping):
        return state.get(key)

    return getattr(state, key, None)


def _is_valid_request_id(value: Any) -> bool:
    """
    Return True when a request ID is safe to log or reflect.
    """
    if not value:
        return False

    text_value = str(value).strip()

    if not text_value:
        return False

    if len(text_value) > MAX_REQUEST_ID_LENGTH:
        return False

    return _REQUEST_ID_RE.fullmatch(text_value) is not None


def _safe_request_id(scope: Scope) -> Optional[str]:
    """
    Return a safe request/correlation ID for logs and diagnostics.

    Preference order:

    1. active contextvar from RequestIdMiddleware;
    2. scope["request_id"];
    3. request.state.request_id;
    4. X-Request-ID header.

    Invalid, oversized, or control-character-bearing values are ignored.
    """
    if _get_current_request_id is not None:
        try:
            value = _get_current_request_id()

            if _is_valid_request_id(value):
                return str(value).strip()
        except Exception:
            pass

    for candidate in (
        scope.get("request_id"),
        _get_state_value(scope, "request_id"),
        _get_state_value(scope, "muleguard_request_id"),
        _get_header(scope, "X-Request-ID"),
    ):
        if _is_valid_request_id(candidate):
            return str(candidate).strip()

    return None


def _upsert_header(
    headers: Sequence[tuple[bytes, bytes]],
    name: str,
    value: str,
) -> list[tuple[bytes, bytes]]:
    """
    Replace or append a response header safely.
    """
    encoded_name = name.lower().encode("latin-1", errors="ignore")
    encoded_value = value.encode("latin-1", errors="ignore")

    updated = [
        (key, existing_value)
        for key, existing_value in headers
        if key.lower() != encoded_name
    ]

    updated.append((encoded_name, encoded_value))
    return updated


# -----------------------------------------------------------------------------
# Route label normalization
# -----------------------------------------------------------------------------


def _collapse_segment(segment: str) -> str:
    """
    Collapse likely identifier path segments into stable labels.

    This reduces metric cardinality and avoids logging raw synthetic IDs in
    high-volume performance telemetry.
    """
    segment = segment.strip()

    if not segment:
        return ""

    if _UUID_RE.fullmatch(segment):
        return ":uuid"

    if _NUMERIC_ID_RE.fullmatch(segment):
        return ":id"

    if _HEX_ID_RE.fullmatch(segment):
        return ":hash"

    if _RESOURCE_ID_RE.fullmatch(segment):
        return ":resource_id"

    return segment


def _normalize_path_label(path: Any) -> str:
    """
    Return a bounded, low-cardinality path label for fallback logging/metrics.
    """
    normalized = _normalize_path(path)
    parts = [part for part in normalized.split("/") if part]

    collapsed: list[str] = []

    for part in parts:
        collapsed_part = _collapse_segment(part)

        if collapsed_part:
            collapsed.append(collapsed_part)

        if len(collapsed) >= MAX_PATH_SEGMENTS:
            collapsed.append("...")
            break

    label = "/" + "/".join(collapsed) if collapsed else "/"

    if len(label) > MAX_PATH_LABEL_LENGTH:
        label = label[:MAX_PATH_LABEL_LENGTH]

    return label


def _extract_route_label(scope: Scope, path: Any) -> str:
    """
    Return a stable route label.

    Preference order:

    1. Starlette/FastAPI route.path_format, when available;
    2. normalized and collapsed fallback path label.

    Route templates are preferred because they avoid high cardinality from
    path parameters such as account IDs, transaction IDs, case IDs, and
    complaint IDs.
    """
    route = scope.get("route")
    path_format = getattr(route, "path_format", None)

    if isinstance(path_format, str) and path_format.strip().startswith("/"):
        label = path_format.strip()

        if len(label) > MAX_PATH_LABEL_LENGTH:
            label = label[:MAX_PATH_LABEL_LENGTH]

        return label or "/"

    return _normalize_path_label(path)


# -----------------------------------------------------------------------------
# Skip policy
# -----------------------------------------------------------------------------


def _should_skip(
    path: Any,
    method: Any,
    settings: Any,
    overrides: Mapping[str, Any],
) -> bool:
    """
    Return True when performance instrumentation should skip this request.

    Skipping is intended for infrastructure noise reduction only. It must not
    be used to bypass authentication or authorization.
    """
    normalized_path = _normalize_path(path)
    upper_method = str(method or "").strip().upper()

    skip_methods = _normalize_frozenset(
        _effective(
            settings,
            overrides,
            "PERFORMANCE_SKIP_METHODS",
            DEFAULT_SKIP_METHODS,
        )
    )

    if upper_method and upper_method in skip_methods:
        return True

    skip_paths_raw = _effective(
        settings,
        overrides,
        "PERFORMANCE_SKIP_PATHS",
        DEFAULT_SKIP_PATHS,
    )

    skip_paths = {
        _normalize_path(candidate)
        for candidate in _csv(skip_paths_raw)
    }

    if normalized_path in skip_paths:
        return True

    skip_prefixes = _csv(
        _effective(
            settings,
            overrides,
            "PERFORMANCE_SKIP_PREFIXES",
            DEFAULT_SKIP_PREFIXES,
        )
    )

    return any(
        normalized_path.startswith(prefix)
        for prefix in skip_prefixes
        if prefix
    )


# -----------------------------------------------------------------------------
# Status classification
# -----------------------------------------------------------------------------


def _status_class(status: Optional[int], error_type: Optional[str]) -> str:
    """
    Return a bounded status class label for metrics.
    """
    if error_type:
        return "error"

    if status is None:
        return "unknown"

    if 200 <= status < 300:
        return "2xx"

    if 300 <= status < 400:
        return "3xx"

    if 400 <= status < 500:
        return "4xx"

    if 500 <= status < 600:
        return "5xx"

    return "other"


# -----------------------------------------------------------------------------
# Percentile helper
# -----------------------------------------------------------------------------


def _percentile(values: Sequence[float], q: float) -> Optional[float]:
    """
    Return a nearest-rank percentile from a sorted sequence.
    """
    if not values:
        return None

    q = min(1.0, max(0.0, float(q)))
    idx = int(math.ceil(q * len(values))) - 1
    idx = max(0, min(len(values) - 1, idx))

    return round(float(values[idx]), 3)


# -----------------------------------------------------------------------------
# Bounded local metrics
# -----------------------------------------------------------------------------


class RouteMetrics:
    """
    Bounded per-route performance metrics.

    Latency samples are kept in a fixed-size deque to provide approximate
    recent percentiles without unbounded memory growth.
    """

    __slots__ = (
        "count",
        "error_count",
        "slow_count",
        "status_counts",
        "latencies",
        "max_samples",
    )

    def __init__(self, max_samples: int) -> None:
        self.count = 0
        self.error_count = 0
        self.slow_count = 0
        self.status_counts: defaultdict[str, int] = defaultdict(int)
        self.max_samples = max(1, int(max_samples))
        self.latencies: deque[float] = deque(maxlen=self.max_samples)

    def record(
        self,
        status_class: str,
        latency_ms: float,
        *,
        error: bool,
        slow: bool,
    ) -> None:
        """
        Record one request outcome.
        """
        self.count += 1

        if error:
            self.error_count += 1

        if slow:
            self.slow_count += 1

        self.status_counts[str(status_class)] += 1
        self.latencies.append(round(float(latency_ms), 3))

    def snapshot(self) -> dict[str, Any]:
        """
        Return a safe, serializable snapshot for this route.
        """
        sorted_latencies = sorted(self.latencies)

        average_ms = (
            round(sum(sorted_latencies) / len(sorted_latencies), 3)
            if sorted_latencies
            else None
        )

        return {
            "count": self.count,
            "error_count": self.error_count,
            "slow_count": self.slow_count,
            "status_counts": dict(self.status_counts),
            "latency_ms": {
                "avg": average_ms,
                "p50": _percentile(sorted_latencies, 0.50),
                "p95": _percentile(sorted_latencies, 0.95),
                "p99": _percentile(sorted_latencies, 0.99),
                "max": round(sorted_latencies[-1], 3) if sorted_latencies else None,
                "samples_retained": len(sorted_latencies),
                "max_samples": self.max_samples,
            },
        }


class PerformanceMetrics:
    """
    Thread-safe, bounded, local performance metrics registry.

    This is intentionally not a full APM system. It provides enough structured
    telemetry for local development, CI smoke checks, and demo diagnostics
    without introducing external agents or unbounded cardinality.
    """

    OVERFLOW_ROUTE: Final[str] = "_other"

    def __init__(
        self,
        *,
        max_routes: int = 256,
        max_latency_samples: int = 256,
    ) -> None:
        self._lock = threading.Lock()
        self.max_routes = max(1, int(max_routes))
        self.max_latency_samples = max(1, int(max_latency_samples))
        self.routes: dict[str, RouteMetrics] = {}
        self.totals: defaultdict[str, int] = defaultdict(int)

    def record(
        self,
        route: str,
        status_class: str,
        latency_ms: float,
        *,
        error: bool,
        slow: bool,
    ) -> None:
        """
        Record one request outcome into bounded route metrics.
        """
        with self._lock:
            if route not in self.routes and len(self.routes) >= self.max_routes:
                route = self.OVERFLOW_ROUTE

            metrics = self.routes.get(route)

            if metrics is None:
                metrics = RouteMetrics(max_samples=self.max_latency_samples)
                self.routes[route] = metrics

            self.totals["requests"] += 1

            if error:
                self.totals["errors"] += 1

            if slow:
                self.totals["slow"] += 1

            metrics.record(
                status_class=status_class,
                latency_ms=latency_ms,
                error=error,
                slow=slow,
            )

    def snapshot(self) -> dict[str, Any]:
        """
        Return a safe, serializable metrics snapshot.
        """
        with self._lock:
            route_snapshots = [
                {
                    "route": route,
                    **metrics.snapshot(),
                }
                for route, metrics in self.routes.items()
            ]

        route_snapshots.sort(key=lambda item: item.get("count", 0), reverse=True)

        return {
            "enabled": True,
            "max_routes": self.max_routes,
            "max_latency_samples_per_route": self.max_latency_samples,
            "overflow_route": self.OVERFLOW_ROUTE,
            "totals": dict(self.totals),
            "routes": route_snapshots,
        }


# -----------------------------------------------------------------------------
# Middleware
# -----------------------------------------------------------------------------


class PerformanceMiddleware:
    """
    Pure ASGI middleware for safe MULEGUARD performance instrumentation.

    Example:

        app.add_middleware(PerformanceMiddleware)

    Optional explicit overrides:

        app.add_middleware(
            PerformanceMiddleware,
            settings=settings,
            PERFORMANCE_SLOW_REQUEST_THRESHOLD_MS=1500,
            PERFORMANCE_LOG_ALL_REQUESTS=False,
        )

    Behaviour:

    - Non-HTTP scopes pass through unchanged.
    - If disabled, the middleware passes through unchanged.
    - Skipped paths/methods pass through unchanged.
    - For HTTP responses, it modifies only `http.response.start`.
    - It does not log request bodies, response bodies, query strings, cookies,
      authorization headers, tokens, passwords, raw narratives, or real
      customer data.
    - Metrics are bounded and local to the process.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Any | None = None,
        enabled: bool | None = None,
        slow_request_threshold_ms: int | None = None,
        include_response_time_header: bool | None = None,
        **overrides: Any,
    ) -> None:
        self.app = app

        self._settings = settings
        self._overrides: dict[str, Any] = dict(overrides)

        self._enabled = enabled
        self._slow_request_threshold_ms = slow_request_threshold_ms
        self._include_response_time_header = include_response_time_header

        self._settings_lock = threading.Lock()
        self._resolved_settings: Any | None = None

        self._metrics_lock = threading.Lock()
        self._metrics: Optional[PerformanceMetrics] = None

    # -------------------------------------------------------------------------
    # Settings resolution
    # -------------------------------------------------------------------------

    def _resolve_settings(self, scope: Scope) -> Any:
        """
        Resolve runtime settings for this request.

        Preference order:

        1. settings supplied to the middleware constructor;
        2. `scope["app"].state.settings`, when available;
        3. `app.core.config.get_settings()`;
        4. empty mapping fallback.
        """
        if self._settings is not None:
            return self._settings

        with self._settings_lock:
            if self._resolved_settings is not None:
                return self._resolved_settings

            resolved: Any = None

            app = scope.get("app")
            state = getattr(app, "state", None)
            state_settings = getattr(state, "settings", None)

            if state_settings is not None:
                resolved = state_settings
            else:
                try:
                    from app.core.config import get_settings

                    resolved = get_settings()
                except Exception:
                    logger.debug(
                        "Performance middleware could not resolve application settings; "
                        "using empty settings fallback.",
                        exc_info=True,
                    )
                    resolved = None

            if resolved is not None:
                self._resolved_settings = resolved

            return resolved if resolved is not None else (self._resolved_settings or {})

    # -------------------------------------------------------------------------
    # Metrics helpers
    # -------------------------------------------------------------------------

    def _metrics_enabled(self, settings: Any) -> bool:
        """
        Return True when bounded local metrics should be recorded.
        """
        return _as_bool(
            _effective(
                settings,
                self._overrides,
                "PERFORMANCE_METRICS_ENABLED",
                True,
            ),
            True,
        )

    def _get_metrics(self, settings: Any) -> Optional[PerformanceMetrics]:
        """
        Return the bounded metrics registry, creating it lazily when enabled.
        """
        if not self._metrics_enabled(settings):
            return None

        with self._metrics_lock:
            if self._metrics is None:
                max_routes = max(
                    1,
                    _as_int(
                        _effective(
                            settings,
                            self._overrides,
                            "PERFORMANCE_METRICS_MAX_ROUTES",
                            256,
                        ),
                        256,
                    ),
                )

                max_latency_samples = max(
                    1,
                    _as_int(
                        _effective(
                            settings,
                            self._overrides,
                            "PERFORMANCE_METRICS_LATENCY_SAMPLES_PER_ROUTE",
                            256,
                        ),
                        256,
                    ),
                )

                self._metrics = PerformanceMetrics(
                    max_routes=max_routes,
                    max_latency_samples=max_latency_samples,
                )

            return self._metrics

    def metrics_snapshot(self) -> dict[str, Any]:
        """
        Return a safe snapshot of this middleware's local metrics.
        """
        if self._metrics is None:
            return {
                "enabled": False,
                "reason": "performance_metrics_disabled_or_not_initialized",
            }

        return self._metrics.snapshot()

    # -------------------------------------------------------------------------
    # ASGI entrypoint
    # -------------------------------------------------------------------------

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """
        ASGI entrypoint.
        """
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        settings = self._resolve_settings(scope)

        enabled = self._enabled

        if enabled is None:
            enabled = _as_bool(
                _effective(
                    settings,
                    self._overrides,
                    "PERFORMANCE_MIDDLEWARE_ENABLED",
                    True,
                ),
                True,
            )

        if not enabled:
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path") or "/")
        method = str(scope.get("method") or "")

        if _should_skip(path, method, settings, self._overrides):
            await self.app(scope, receive, send)
            return

        threshold = self._slow_request_threshold_ms

        if threshold is None:
            threshold = _as_int(
                _effective(
                    settings,
                    self._overrides,
                    "PERFORMANCE_SLOW_REQUEST_THRESHOLD_MS",
                    2000,
                ),
                2000,
            )

        threshold = max(0, int(threshold))

        include_header = self._include_response_time_header

        if include_header is None:
            include_header = _as_bool(
                _effective(
                    settings,
                    self._overrides,
                    "PERFORMANCE_INCLUDE_RESPONSE_TIME_HEADER",
                    True,
                ),
                True,
            )

        header_name = str(
            _effective(
                settings,
                self._overrides,
                "PERFORMANCE_RESPONSE_TIME_HEADER",
                DEFAULT_RESPONSE_TIME_HEADER,
            )
            or DEFAULT_RESPONSE_TIME_HEADER
        ).strip()

        if not _is_valid_header_name(header_name):
            header_name = DEFAULT_RESPONSE_TIME_HEADER

        log_slow = _as_bool(
            _effective(
                settings,
                self._overrides,
                "PERFORMANCE_LOG_SLOW_REQUESTS",
                True,
            ),
            True,
        )

        log_errors = _as_bool(
            _effective(
                settings,
                self._overrides,
                "PERFORMANCE_LOG_ERRORS",
                True,
            ),
            True,
        )

        log_all = _as_bool(
            _effective(
                settings,
                self._overrides,
                "PERFORMANCE_LOG_ALL_REQUESTS",
                False,
            ),
            False,
        )

        metrics = self._get_metrics(settings)

        if metrics is not None:
            app = scope.get("app")
            state = getattr(app, "state", None)

            if state is not None:
                try:
                    setattr(state, "performance_metrics", metrics)
                except Exception:
                    logger.debug(
                        "Unable to attach performance metrics to app.state.",
                        exc_info=True,
                    )

        request_id = _safe_request_id(scope)
        started_at_ns = time.perf_counter_ns()

        status: Optional[int] = None
        route_label: Optional[str] = None
        error_type: Optional[str] = None

        async def send_wrapper(message: Message) -> None:
            """
            Inject response-time header and capture status/route safely.
            """
            nonlocal status
            nonlocal route_label

            if message.get("type") == "http.response.start":
                status = int(message.get("status") or 0)
                route_label = _extract_route_label(scope, path)

                if include_header:
                    latency_ms = (time.perf_counter_ns() - started_at_ns) / 1_000_000.0
                    headers = _upsert_header(
                        list(message.get("headers") or []),
                        header_name,
                        f"{latency_ms:.3f}",
                    )

                    message = {
                        **message,
                        "headers": headers,
                    }

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)

        except Exception as exc:
            error_type = type(exc).__name__

            if status is None:
                status = 500

            if route_label is None:
                route_label = _extract_route_label(scope, path)

            raise

        finally:
            latency_ms = (time.perf_counter_ns() - started_at_ns) / 1_000_000.0

            if route_label is None:
                route_label = _extract_route_label(scope, path)

            slow = threshold > 0 and latency_ms >= float(threshold)
            is_error = error_type is not None or (status is not None and status >= 500)
            status_class = _status_class(status, error_type)

            if metrics is not None:
                metrics.record(
                    route=route_label,
                    status_class=status_class,
                    latency_ms=latency_ms,
                    error=is_error,
                    slow=slow,
                )

            should_log = (
                log_all
                or (log_slow and slow)
                or (log_errors and is_error)
            )

            if should_log:
                log_message = (
                    "performance method=%s route=%s status=%s latency_ms=%.3f "
                    "request_id=%s slow=%s error_type=%s"
                )

                log_args = (
                    method,
                    route_label,
                    status if status is not None else "-",
                    latency_ms,
                    request_id or "-",
                    slow,
                    error_type or "-",
                )

                if is_error:
                    logger.error(log_message, *log_args)
                elif slow:
                    logger.warning(log_message, *log_args)
                else:
                    logger.info(log_message, *log_args)


# -----------------------------------------------------------------------------
# Convenience factory and snapshot helper
# -----------------------------------------------------------------------------


def create_performance_middleware(
    app: ASGIApp,
    **kwargs: Any,
) -> PerformanceMiddleware:
    """
    Convenience factory for explicit middleware installation.

    Example:

        app.add_middleware(create_performance_middleware)
    """
    return PerformanceMiddleware(app, **kwargs)


def get_performance_metrics_snapshot(app: Any) -> dict[str, Any]:
    """
    Return a safe performance metrics snapshot from an application instance.

    This helper expects the middleware to have attached its metrics registry to:

        app.state.performance_metrics

    If metrics are not installed or not yet initialized, it returns a safe
    disabled payload.
    """
    state = getattr(app, "state", None)
    metrics = getattr(state, "performance_metrics", None)

    if metrics is not None and hasattr(metrics, "snapshot"):
        try:
            return metrics.snapshot()
        except Exception:
            logger.warning(
                "Failed to generate performance metrics snapshot.",
                exc_info=True,
            )
            return {
                "enabled": False,
                "reason": "snapshot_failed",
            }

    return {
        "enabled": False,
        "reason": "performance_metrics_not_installed",
    }


__all__ = [
    "PerformanceMetrics",
    "PerformanceMiddleware",
    "RouteMetrics",
    "create_performance_middleware",
    "get_performance_metrics_snapshot",
]