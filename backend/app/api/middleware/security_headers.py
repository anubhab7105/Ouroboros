"""
MULEGUARD security headers middleware.

This module provides a pure ASGI middleware that adds conservative,
privacy-preserving HTTP security headers to MULEGUARD API responses.

Primary responsibilities:

- add safe default security headers to HTTP responses;
- remove or suppress server-version disclosure headers where practical;
- support HSTS only when the request is recognised as secure;
- support optional Content-Security-Policy without breaking local docs by
  default;
- support Permissions-Policy, COOP, CORP, and optional COEP;
- apply safe cache-control behaviour to authentication and error responses;
- avoid leaking secrets, stack traces, tokens, passwords, raw complaint
  narratives, database URLs, or real customer data;
- remain compatible with streaming ASGI responses by modifying only
  `http.response.start`.

Important boundaries:

- This middleware is not an authentication or authorization boundary.
- This middleware does not replace TLS, secure cookie configuration, CORS
  policy, input validation, rate limiting, RBAC, audit logging, or deployment
  hardening.
- Security headers reduce certain browser-side risks, but they do not make
  MULEGUARD production-ready.
- MULEGUARD remains a synthetic-first investigative prototype. Alerts, scores,
  graph relationships, candidate money trails, and complaint correlations are
  investigative leads only.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final, Optional

from starlette.types import ASGIApp, Message, Receive, Scope, Send


logger = logging.getLogger("muleguard.backend.api.middleware.security_headers")


# -----------------------------------------------------------------------------
# Validation and sanitization limits
# -----------------------------------------------------------------------------

MAX_HEADER_VALUE_LENGTH: Final[int] = 8192

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_HEADER_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")


# -----------------------------------------------------------------------------
# Default header values
# -----------------------------------------------------------------------------

DEFAULT_X_CONTENT_TYPE_OPTIONS: Final[str] = "nosniff"
DEFAULT_X_FRAME_OPTIONS: Final[str] = "DENY"
DEFAULT_REFERRER_POLICY: Final[str] = "no-referrer"
DEFAULT_X_DNS_PREFETCH_CONTROL: Final[str] = "off"
DEFAULT_X_PERMITTED_CROSS_DOMAIN_POLICIES: Final[str] = "none"

DEFAULT_PERMISSIONS_POLICY: Final[str] = (
    "camera=(), microphone=(), geolocation=(), interest-cohort=()"
)

DEFAULT_COOP: Final[str] = "same-origin"
DEFAULT_COEP: Final[str] = "require-corp"
DEFAULT_CORP: Final[str] = "same-origin"

DEFAULT_HSTS_MAX_AGE: Final[int] = 31_536_000
HSTS_PRELOAD_MIN_MAX_AGE: Final[int] = 31_536_000


# -----------------------------------------------------------------------------
# CSP defaults
# -----------------------------------------------------------------------------
# CSP is disabled by default because overly strict policies can break local
# OpenAPI docs, Swagger UI, ReDoc, and frontend development proxies.
#
# When enabled, the default policy is intentionally conservative for API JSON
# responses. Docs paths are exempt by default unless explicitly configured
# otherwise.

_DEFAULT_API_CSP_DIRECTIVES: Final[dict[str, list[str]]] = {
    "default-src": ["'none'"],
    "base-uri": ["'none'"],
    "frame-ancestors": ["'none'"],
    "form-action": ["'self'"],
    "object-src": ["'none'"],
    "script-src": ["'self'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:"],
    "font-src": ["'self'"],
    "connect-src": ["'self'"],
    "media-src": ["'none'"],
    "worker-src": ["'self'"],
    "manifest-src": ["'self'"],
}

_DEFAULT_DOCS_CSP_DIRECTIVES: Final[dict[str, list[str]]] = {
    "default-src": ["'self'"],
    "base-uri": ["'self'"],
    "frame-ancestors": ["'none'"],
    "form-action": ["'self'"],
    "object-src": ["'none'"],
    "script-src": ["'self'", "'unsafe-inline'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:"],
    "font-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
    "media-src": ["'none'"],
    "worker-src": ["'self'"],
    "manifest-src": ["'self'"],
}

_CSP_SETTING_TO_DIRECTIVE: Final[dict[str, str]] = {
    "CSP_DEFAULT_SRC": "default-src",
    "CSP_SCRIPT_SRC": "script-src",
    "CSP_STYLE_SRC": "style-src",
    "CSP_IMG_SRC": "img-src",
    "CSP_FONT_SRC": "font-src",
    "CSP_CONNECT_SRC": "connect-src",
    "CSP_MEDIA_SRC": "media-src",
    "CSP_OBJECT_SRC": "object-src",
    "CSP_FRAME_SRC": "frame-src",
    "CSP_FRAME_ANCESTORS": "frame-ancestors",
    "CSP_BASE_URI": "base-uri",
    "CSP_FORM_ACTION": "form-action",
    "CSP_MANIFEST_SRC": "manifest-src",
    "CSP_WORKER_SRC": "worker-src",
    "CSP_SANDBOX": "sandbox",
    "CSP_UPGRADE_INSECURE_REQUESTS": "upgrade-insecure-requests",
    "CSP_BLOCK_ALL_MIXED_CONTENT": "block-all-mixed-content",
}


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


def _normalize_header_value(value: Any) -> Optional[str]:
    """
    Return a safe single-line HTTP header value.

    This removes control characters, collapses whitespace, and bounds length.
    It is intentionally conservative because header values may originate from
    environment configuration.
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


def _is_valid_header_name(name: str) -> bool:
    """
    Return True when a header name is safe to emit.
    """
    return bool(_HEADER_NAME_RE.match(name))


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


def _drop_headers(
    headers: Sequence[tuple[bytes, bytes]],
    names: set[bytes],
) -> list[tuple[bytes, bytes]]:
    """
    Remove headers by lowercase byte name.
    """
    if not names:
        return list(headers)

    return [
        (key, value)
        for key, value in headers
        if key.lower() not in names
    ]


def _merge_headers(
    headers: Sequence[tuple[bytes, bytes]],
    additions: Mapping[str, str],
) -> list[tuple[bytes, bytes]]:
    """
    Replace or append response headers safely.

    Existing case-insensitive duplicates for names being added are removed
    before appending the canonical sanitized value.
    """
    if not additions:
        return list(headers)

    encoded_additions: dict[bytes, bytes] = {}

    for raw_name, raw_value in additions.items():
        name = str(raw_name).strip()

        if not _is_valid_header_name(name):
            continue

        value = _normalize_header_value(raw_value)

        if value is None:
            continue

        encoded_additions[name.lower().encode("latin-1", errors="ignore")] = (
            value.encode("latin-1", errors="ignore")
        )

    if not encoded_additions:
        return list(headers)

    filtered = [
        (key, value)
        for key, value in headers
        if key.lower() not in encoded_additions
    ]

    filtered.extend(encoded_additions.items())
    return filtered


# -----------------------------------------------------------------------------
# Path classification helpers
# -----------------------------------------------------------------------------


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


def _is_api_path(path: str) -> bool:
    normalized = _normalize_path(path).lower()
    return normalized.startswith("/api")


def _is_auth_path(path: str) -> bool:
    normalized = _normalize_path(path).lower()
    return normalized.startswith("/api/v1/auth") or normalized.startswith("/auth")


def _is_health_path(path: str) -> bool:
    normalized = _normalize_path(path).lower()
    return (
        normalized == "/health"
        or normalized.startswith("/health/")
        or normalized == "/api/v1/health/ready"
        or normalized.startswith("/api/v1/health/")
    )


def _is_docs_path(path: str) -> bool:
    normalized = _normalize_path(path).lower()

    return (
        normalized.startswith("/docs")
        or normalized.startswith("/redoc")
        or normalized.startswith("/swagger")
        or normalized.startswith("/static/swagger")
        or normalized.startswith("/api/v1/docs")
        or normalized.startswith("/api/v1/redoc")
    )


# -----------------------------------------------------------------------------
# Transport security helpers
# -----------------------------------------------------------------------------


def _is_secure_scope(
    scope: Scope,
    settings: Any,
    overrides: Mapping[str, Any],
) -> bool:
    """
    Return True when the request should be treated as TLS-secured.

    Proxy headers are trusted only when `BACKEND_TRUST_PROXY_HEADERS=true`.
    """
    if str(scope.get("scheme", "")).lower() == "https":
        return True

    trust_proxy = _as_bool(
        _effective(
            settings,
            overrides,
            "BACKEND_TRUST_PROXY_HEADERS",
            False,
        ),
        False,
    )

    if not trust_proxy:
        return False

    forwarded_proto = _get_header(scope, "X-Forwarded-Proto")

    if forwarded_proto and forwarded_proto.lower() == "https":
        return True

    forwarded = _get_header(scope, "Forwarded")

    if forwarded and "proto=https" in forwarded.lower():
        return True

    return False


# -----------------------------------------------------------------------------
# CSP helpers
# -----------------------------------------------------------------------------


def _parse_csp_values(value: Any) -> list[str]:
    """
    Parse a CSP directive value into source expressions.

    Supported forms:

    - `" 'self' 'unsafe-inline' "`
    - `["'self'", "'unsafe-inline'"]`
    - `""` meaning omit directive
    """
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    text_value = str(value).strip()

    if not text_value:
        return []

    return [token for token in text_value.split() if token]


def _default_csp_directives(is_docs: bool, relaxed_docs: bool) -> dict[str, list[str]]:
    """
    Return baseline CSP directives for API or docs responses.
    """
    if is_docs and relaxed_docs:
        directives = {
            key: list(value)
            for key, value in _DEFAULT_DOCS_CSP_DIRECTIVES.items()
        }
    else:
        directives = {
            key: list(value)
            for key, value in _DEFAULT_API_CSP_DIRECTIVES.items()
        }

    return directives


def _build_csp_headers(
    scope: Scope,
    settings: Any,
    overrides: Mapping[str, Any],
    path: str,
) -> dict[str, str]:
    """
    Build Content-Security-Policy headers when enabled.

    CSP is disabled by default. Docs paths are exempt by default to avoid
    breaking local Swagger UI/ReDoc during development.
    """
    csp_enabled = _as_bool(
        _effective(settings, overrides, "CSP_ENABLED", False),
        False,
    )

    if not csp_enabled:
        return {}

    is_docs = _is_docs_path(path)
    docs_exempt = _as_bool(
        _effective(settings, overrides, "CSP_DOCS_EXEMPT", True),
        True,
    )

    if is_docs and docs_exempt:
        return {}

    relaxed_docs = _as_bool(
        _effective(settings, overrides, "CSP_DOCS_RELAXED", True),
        True,
    )

    directives = _default_csp_directives(
        is_docs=is_docs,
        relaxed_docs=relaxed_docs,
    )

    if is_docs and relaxed_docs:
        allow_unsafe_eval = _as_bool(
            _effective(settings, overrides, "CSP_DOCS_ALLOW_UNSAFE_EVAL", False),
            False,
        )

        if allow_unsafe_eval:
            script_src = directives.setdefault("script-src", ["'self'"])

            if "'unsafe-eval'" not in script_src:
                script_src.append("'unsafe-eval'")

    for setting_name, directive_name in _CSP_SETTING_TO_DIRECTIVE.items():
        raw_value = _effective(settings, overrides, setting_name, None)

        if raw_value is None:
            continue

        values = _parse_csp_values(raw_value)

        if values:
            directives[directive_name] = values
        else:
            directives.pop(directive_name, None)

    parts: list[str] = []

    for directive_name, values in directives.items():
        if not values:
            continue

        parts.append(f"{directive_name} {' '.join(values)}")

    report_uri = str(
        _effective(settings, overrides, "CSP_REPORT_URI", "") or ""
    ).strip()

    if report_uri:
        parts.append(f"report-uri {report_uri}")

    if not parts:
        return {}

    value = "; ".join(parts)
    report_only = _as_bool(
        _effective(settings, overrides, "CSP_REPORT_ONLY", False),
        False,
    )

    header_name = (
        "Content-Security-Policy-Report-Only"
        if report_only
        else "Content-Security-Policy"
    )

    return {header_name: value}


# -----------------------------------------------------------------------------
# HSTS helper
# -----------------------------------------------------------------------------


def _build_hsts_header(
    scope: Scope,
    settings: Any,
    overrides: Mapping[str, Any],
) -> Optional[str]:
    """
    Build a Strict-Transport-Security header value when appropriate.

    HSTS is emitted only when the request is recognised as secure.
    """
    hsts_enabled = _as_bool(
        _effective(settings, overrides, "HSTS_ENABLED", False),
        False,
    )

    if not hsts_enabled:
        return None

    if not _is_secure_scope(scope, settings, overrides):
        return None

    max_age = _as_int(
        _effective(settings, overrides, "HSTS_MAX_AGE", DEFAULT_HSTS_MAX_AGE),
        DEFAULT_HSTS_MAX_AGE,
    )

    if max_age <= 0:
        return None

    parts = [f"max-age={max_age}"]

    include_subdomains = _as_bool(
        _effective(settings, overrides, "HSTS_INCLUDE_SUBDOMAINS", True),
        True,
    )

    if include_subdomains:
        parts.append("includeSubDomains")

    preload = _as_bool(
        _effective(settings, overrides, "HSTS_PRELOAD", False),
        False,
    )

    if preload and max_age >= HSTS_PRELOAD_MIN_MAX_AGE:
        parts.append("preload")

    return "; ".join(parts)


# -----------------------------------------------------------------------------
# Permissions-Policy helper
# -----------------------------------------------------------------------------


def _build_permissions_policy(
    settings: Any,
    overrides: Mapping[str, Any],
) -> Optional[str]:
    """
    Build a Permissions-Policy header value.
    """
    raw_value = _effective(
        settings,
        overrides,
        "PERMISSIONS_POLICY",
        DEFAULT_PERMISSIONS_POLICY,
    )

    if raw_value is None:
        return None

    if isinstance(raw_value, (list, tuple, set)):
        value = ", ".join(str(item).strip() for item in raw_value if str(item).strip())
    else:
        value = str(raw_value).strip()

    return value or None


# -----------------------------------------------------------------------------
# Cache-control helper
# -----------------------------------------------------------------------------


def _build_cache_control_header(
    settings: Any,
    overrides: Mapping[str, Any],
    path: str,
    status: int,
) -> Optional[str]:
    """
    Build conservative Cache-Control behaviour for sensitive or error responses.

    This intentionally avoids broad cache-control changes for normal successful
    API responses unless explicitly configured.
    """
    no_store_auth = _as_bool(
        _effective(settings, overrides, "SECURE_HEADERS_NO_STORE_FOR_AUTH", True),
        True,
    )

    no_store_errors = _as_bool(
        _effective(settings, overrides, "SECURE_HEADERS_NO_STORE_FOR_ERRORS", True),
        True,
    )

    no_store_api = _as_bool(
        _effective(settings, overrides, "SECURE_HEADERS_NO_STORE_FOR_API", False),
        False,
    )

    if no_store_auth and _is_auth_path(path):
        return "no-store"

    if no_store_errors and status >= 400 and (
        _is_api_path(path) or _is_auth_path(path) or _is_health_path(path)
    ):
        return "no-store"

    if no_store_api and _is_api_path(path):
        return "no-store"

    return None


# -----------------------------------------------------------------------------
# Header builder
# -----------------------------------------------------------------------------


def _build_response_headers(
    scope: Scope,
    settings: Any,
    overrides: Mapping[str, Any],
    status: int,
    path: str,
) -> dict[str, str]:
    """
    Build the full set of security headers for an HTTP response.

    Only known, safe header names are emitted. Values are sanitized during
    merge.
    """
    headers: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Core anti-sniffing / anti-framing / referrer controls
    # ------------------------------------------------------------------
    x_content_type_options = _normalize_header_value(
        _effective(
            settings,
            overrides,
            "X_CONTENT_TYPE_OPTIONS",
            DEFAULT_X_CONTENT_TYPE_OPTIONS,
        )
    )

    if x_content_type_options:
        headers["X-Content-Type-Options"] = x_content_type_options

    x_frame_options = _normalize_header_value(
        _effective(
            settings,
            overrides,
            "X_FRAME_OPTIONS",
            DEFAULT_X_FRAME_OPTIONS,
        )
    )

    if x_frame_options:
        headers["X-Frame-Options"] = x_frame_options

    referrer_policy = _normalize_header_value(
        _effective(
            settings,
            overrides,
            "REFERRER_POLICY",
            DEFAULT_REFERRER_POLICY,
        )
    )

    if referrer_policy:
        headers["Referrer-Policy"] = referrer_policy

    x_dns_prefetch_control = _normalize_header_value(
        _effective(
            settings,
            overrides,
            "X_DNS_PREFETCH_CONTROL",
            DEFAULT_X_DNS_PREFETCH_CONTROL,
        )
    )

    if x_dns_prefetch_control:
        headers["X-DNS-Prefetch-Control"] = x_dns_prefetch_control

    x_permitted_cross_domain_policies = _normalize_header_value(
        _effective(
            settings,
            overrides,
            "X_PERMITTED_CROSS_DOMAIN_POLICIES",
            DEFAULT_X_PERMITTED_CROSS_DOMAIN_POLICIES,
        )
    )

    if x_permitted_cross_domain_policies:
        headers["X-Permitted-Cross-Domain-Policies"] = (
            x_permitted_cross_domain_policies
        )

    # ------------------------------------------------------------------
    # Permissions-Policy
    # ------------------------------------------------------------------
    permissions_policy = _build_permissions_policy(settings, overrides)

    if permissions_policy:
        headers["Permissions-Policy"] = permissions_policy

    # ------------------------------------------------------------------
    # Cross-origin isolation controls
    # ------------------------------------------------------------------
    coop_enabled = _as_bool(
        _effective(settings, overrides, "COOP_ENABLED", True),
        True,
    )

    if coop_enabled:
        coop_value = _normalize_header_value(
            _effective(settings, overrides, "COOP", DEFAULT_COOP)
        )

        if coop_value:
            headers["Cross-Origin-Opener-Policy"] = coop_value

    coep_enabled = _as_bool(
        _effective(settings, overrides, "COEP_ENABLED", False),
        False,
    )

    if coep_enabled:
        coep_value = _normalize_header_value(
            _effective(settings, overrides, "COEP", DEFAULT_COEP)
        )

        if coep_value:
            headers["Cross-Origin-Embedder-Policy"] = coep_value

    corp_enabled = _as_bool(
        _effective(settings, overrides, "CORP_ENABLED", True),
        True,
    )

    if corp_enabled:
        corp_value = _normalize_header_value(
            _effective(settings, overrides, "CORP", DEFAULT_CORP)
        )

        if corp_value:
            headers["Cross-Origin-Resource-Policy"] = corp_value

    # ------------------------------------------------------------------
    # HSTS
    # ------------------------------------------------------------------
    hsts_value = _build_hsts_header(scope, settings, overrides)

    if hsts_value:
        headers["Strict-Transport-Security"] = hsts_value

    # ------------------------------------------------------------------
    # CSP
    # ------------------------------------------------------------------
    headers.update(_build_csp_headers(scope, settings, overrides, path))

    # ------------------------------------------------------------------
    # Cache-Control for sensitive/error responses
    # ------------------------------------------------------------------
    cache_control_value = _build_cache_control_header(
        settings=settings,
        overrides=overrides,
        path=path,
        status=status,
    )

    if cache_control_value:
        headers["Cache-Control"] = cache_control_value

    # ------------------------------------------------------------------
    # Optional Vary header
    # ------------------------------------------------------------------
    vary_value = _normalize_header_value(
        _effective(settings, overrides, "VARY_HEADER", "")
    )

    if vary_value:
        headers["Vary"] = vary_value

    return headers


# -----------------------------------------------------------------------------
# Middleware
# -----------------------------------------------------------------------------


class SecurityHeadersMiddleware:
    """
    Pure ASGI middleware that adds MULEGUARD security headers.

    Example:

        app.add_middleware(SecurityHeadersMiddleware)

    Optional explicit overrides:

        app.add_middleware(
            SecurityHeadersMiddleware,
            settings=settings,
            CSP_ENABLED=True,
            CSP_REPORT_ONLY=True,
        )

    Behaviour:

    - Non-HTTP scopes pass through unchanged.
    - If disabled, the middleware passes through unchanged.
    - For HTTP responses, it modifies only `http.response.start`.
    - It removes `Server` and `X-Powered-By` response headers by default.
    - It applies security headers to successful and error responses by default.
    - It does not log request bodies, query strings, headers, tokens, or
      sensitive narratives.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Any | None = None,
        enabled: bool | None = None,
        apply_to_errors: bool | None = None,
        remove_server: bool | None = None,
        remove_x_powered_by: bool | None = None,
        **overrides: Any,
    ) -> None:
        self.app = app
        self._settings = settings
        self._overrides: dict[str, Any] = dict(overrides)

        self._enabled = enabled
        self._apply_to_errors = apply_to_errors
        self._remove_server = remove_server
        self._remove_x_powered_by = remove_x_powered_by

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

        app = scope.get("app")
        state = getattr(app, "state", None)
        state_settings = getattr(state, "settings", None)

        if state_settings is not None:
            return state_settings

        try:
            from app.core.config import get_settings

            return get_settings()
        except Exception:
            logger.debug(
                "Security headers middleware could not resolve application settings; "
                "using empty settings fallback.",
                exc_info=True,
            )
            return {}

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
                    "SECURE_HEADERS_ENABLED",
                    True,
                ),
                True,
            )

        if not enabled:
            await self.app(scope, receive, send)
            return

        apply_to_errors = self._apply_to_errors

        if apply_to_errors is None:
            apply_to_errors = _as_bool(
                _effective(
                    settings,
                    self._overrides,
                    "SECURE_HEADERS_APPLY_TO_ERRORS",
                    True,
                ),
                True,
            )

        remove_server = self._remove_server

        if remove_server is None:
            remove_server = _as_bool(
                _effective(
                    settings,
                    self._overrides,
                    "SECURE_HEADERS_REMOVE_SERVER",
                    True,
                ),
                True,
            )

        remove_x_powered_by = self._remove_x_powered_by

        if remove_x_powered_by is None:
            remove_x_powered_by = _as_bool(
                _effective(
                    settings,
                    self._overrides,
                    "SECURE_HEADERS_REMOVE_X_POWERED_BY",
                    True,
                ),
                True,
            )

        path = str(scope.get("path") or "/")

        async def send_wrapper(message: Message) -> None:
            """
            Modify HTTP response start headers safely.
            """
            if message.get("type") == "http.response.start":
                status = int(message.get("status") or 0)
                headers = list(message.get("headers") or [])

                drop_names: set[bytes] = set()

                if remove_server:
                    drop_names.add(b"server")

                if remove_x_powered_by:
                    drop_names.add(b"x-powered-by")

                if drop_names:
                    headers = _drop_headers(headers, drop_names)

                if apply_to_errors or status < 400:
                    additions = _build_response_headers(
                        scope=scope,
                        settings=settings,
                        overrides=self._overrides,
                        status=status,
                        path=path,
                    )

                    if additions:
                        headers = _merge_headers(headers, additions)

                message = {
                    **message,
                    "headers": headers,
                }

            await send(message)

        await self.app(scope, receive, send_wrapper)


# -----------------------------------------------------------------------------
# Convenience factory
# -----------------------------------------------------------------------------


def create_security_headers_middleware(
    app: ASGIApp,
    **kwargs: Any,
) -> SecurityHeadersMiddleware:
    """
    Convenience factory for explicit middleware installation.

    Example:

        app.add_middleware(create_security_headers_middleware)
    """
    return SecurityHeadersMiddleware(app, **kwargs)


__all__ = [
    "SecurityHeadersMiddleware",
    "create_security_headers_middleware",
]