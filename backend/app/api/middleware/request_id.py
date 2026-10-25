"""
MULEGUARD request/correlation ID middleware.

This module provides a pure ASGI middleware that:

- accepts an optional inbound X-Request-ID header;
- validates inbound identifiers conservatively;
- generates a safe UUID4 request ID when none is supplied or when the supplied
  value is invalid;
- accepts or derives an X-Correlation-ID;
- stores safe identifiers on:
  - the ASGI scope;
  - request.state where supported by Starlette/FastAPI;
  - context-local variables for structured logging and downstream services;
- injects the canonical request/correlation IDs into HTTP response headers;
- avoids logging or reflecting sensitive, oversized, control-character-bearing,
  or malformed identifier values.

Security and product-safety rules:

- Middleware is not the authentication or authorization boundary.
- Request IDs are diagnostic/correlation identifiers only. They are not
  investigative evidence and must not be treated as proof of anything.
- Inbound identifiers are validated and bounded.
- Response headers contain only safe identifier values.
- Logs must not include secrets, tokens, passwords, raw complaint narratives,
  database URLs, or real customer data.
- The middleware must not fabricate business behaviour or security decisions.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Mapping
from contextvars import ContextVar, Token
from typing import Any, Final, Optional

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# -----------------------------------------------------------------------------
# Header constants
# -----------------------------------------------------------------------------
# Imported lazily from the middleware package when possible, but duplicated as
# local fallback constants to keep this module independently importable and
# resistant to partial package-initialisation ordering.

DEFAULT_REQUEST_ID_HEADER: Final[str] = "X-Request-ID"
DEFAULT_CORRELATION_ID_HEADER: Final[str] = "X-Correlation-ID"

try:  # pragma: no cover - exercised indirectly through package import
    from app.api.middleware import (
        CORRELATION_ID_HEADER as PACKAGE_CORRELATION_ID_HEADER,
        REQUEST_ID_HEADER as PACKAGE_REQUEST_ID_HEADER,
    )

    DEFAULT_REQUEST_ID_HEADER = PACKAGE_REQUEST_ID_HEADER
    DEFAULT_CORRELATION_ID_HEADER = PACKAGE_CORRELATION_ID_HEADER
except Exception:  # pragma: no cover - fallback for isolated module import
    pass


logger = logging.getLogger("muleguard.backend.api.middleware.request_id")


# -----------------------------------------------------------------------------
# Validation constants
# -----------------------------------------------------------------------------

MAX_ID_LENGTH: Final[int] = 128

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

# Conservative identifier pattern:
#   - ASCII letters, digits, dot, underscore, hyphen, colon
#   - no spaces
#   - no control characters
#   - bounded length
_REQUEST_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9._:-]{1,%d}$" % MAX_ID_LENGTH
)

# Conservative HTTP header-name pattern for configurable header names.
_HEADER_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9-]{1,128}$")

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")


# -----------------------------------------------------------------------------
# Context variables
# -----------------------------------------------------------------------------

_REQUEST_ID_CTX: Final[ContextVar[Optional[str]]] = ContextVar(
    "muleguard_request_id",
    default=None,
)

_CORRELATION_ID_CTX: Final[ContextVar[Optional[str]]] = ContextVar(
    "muleguard_correlation_id",
    default=None,
)


# -----------------------------------------------------------------------------
# Small helpers
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


def _is_valid_request_id(value: str | None) -> bool:
    """
    Return True when a request/correlation ID is safe to accept or reflect.
    """
    if not value:
        return False

    if len(value) > MAX_ID_LENGTH:
        return False

    return _REQUEST_ID_RE.match(value) is not None


def _is_valid_header_name(value: str | None) -> bool:
    """
    Return True when a configurable header name is safe to use.
    """
    if not value:
        return False

    return _HEADER_NAME_RE.match(value) is not None


def _generate_request_id() -> str:
    """
    Generate a stable, non-sensitive request ID.
    """
    return str(uuid.uuid4())


def _decode_header_value(raw: bytes) -> str:
    """
    Decode a raw ASGI header value safely.

    HTTP headers are byte strings. Latin-1 is used because it is lossless for
    byte values and avoids UnicodeDecodeError on malformed inbound headers.
    Control characters are stripped before validation.
    """
    try:
        value = raw.decode("latin-1", errors="ignore")
    except Exception:
        return ""

    value = _CONTROL_CHAR_RE.sub("", value)
    return value.strip()


def _first_valid_header(scope: Scope, header_name: str) -> Optional[str]:
    """
    Return the first valid value for a header name from the ASGI scope.

    Invalid, oversized, empty, or control-character-bearing values are ignored.
    """
    target = header_name.lower().encode("latin-1", errors="ignore")

    headers = scope.get("headers") or []

    for raw_key, raw_value in headers:
        try:
            key = raw_key.lower()
        except Exception:
            continue

        if key != target:
            continue

        value = _decode_header_value(raw_value)

        if _is_valid_request_id(value):
            return value

    return None


def _set_scope_state(
    scope: Scope,
    request_id: str,
    correlation_id: str,
) -> None:
    """
    Store safe identifiers on the ASGI scope and request.state.

    Starlette/FastAPI exposes request.state through scope["state"]. This helper
    supports both dict-like state and object-like state for robustness.
    """
    scope["request_id"] = request_id
    scope["correlation_id"] = correlation_id

    state = scope.get("state")

    if state is None:
        state = {}
        scope["state"] = state

    if isinstance(state, dict):
        state["request_id"] = request_id
        state["correlation_id"] = correlation_id
        state["muleguard_request_id"] = request_id
        state["muleguard_correlation_id"] = correlation_id
        return

    try:
        setattr(state, "request_id", request_id)
        setattr(state, "correlation_id", correlation_id)
        setattr(state, "muleguard_request_id", request_id)
        setattr(state, "muleguard_correlation_id", correlation_id)
    except Exception:
        # Last-resort replacement. This should rarely happen because Starlette
        # uses a dict for scope["state"] before wrapping it in State.
        scope["state"] = {
            "request_id": request_id,
            "correlation_id": correlation_id,
            "muleguard_request_id": request_id,
            "muleguard_correlation_id": correlation_id,
        }


def _upsert_header(
    headers: list[tuple[bytes, bytes]],
    name: str,
    value: str,
) -> list[tuple[bytes, bytes]]:
    """
    Replace or append a response header safely.

    Existing case-insensitive duplicates are removed before appending the
    canonical value.
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
# Public context helpers
# -----------------------------------------------------------------------------


def get_current_request_id() -> Optional[str]:
    """
    Return the active request ID from context-local storage, if present.
    """
    return _REQUEST_ID_CTX.get()


def get_current_correlation_id() -> Optional[str]:
    """
    Return the active correlation ID from context-local storage, if present.
    """
    return _CORRELATION_ID_CTX.get()


def get_request_context() -> dict[str, Optional[str]]:
    """
    Return a safe request-context mapping for logging or diagnostics.

    This must not include secrets, tokens, passwords, raw narratives, database
    URLs, or real customer data.
    """
    return {
        "request_id": get_current_request_id(),
        "correlation_id": get_current_correlation_id(),
    }


# -----------------------------------------------------------------------------
# Logging filter
# -----------------------------------------------------------------------------


class RequestIdLogFilter(logging.Filter):
    """
    Logging filter that enriches log records with active request/correlation IDs.

    Example:

        handler.addFilter(RequestIdLogFilter())
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s "
            "request_id=%(request_id)s correlation_id=%(correlation_id)s "
            "%(message)s"
        )
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_current_request_id() or "-"
        record.correlation_id = get_current_correlation_id() or "-"
        return True


# -----------------------------------------------------------------------------
# Middleware
# -----------------------------------------------------------------------------


class RequestIdMiddleware:
    """
    Pure ASGI middleware for safe request and correlation ID propagation.

    Behaviour:

    - If enabled=false, the middleware passes through without modifying scope
      or response headers.
    - If the request is not an HTTP request, it passes through unchanged.
    - If a valid inbound X-Request-ID exists and validate_inbound=true, it is
      reused.
    - If no valid inbound ID exists and generate_if_missing=true, a UUID4 is
      generated.
    - If no valid ID exists and generate_if_missing=false, the request proceeds
      without middleware-injected identifiers.
    - X-Correlation-ID is reused when valid; otherwise it is set to the request
      ID.
    - Identifiers are stored on scope, request.state, and contextvars.
    - HTTP responses receive canonical X-Request-ID and X-Correlation-ID headers.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Any | None = None,
        header_name: str | None = None,
        correlation_header_name: str | None = None,
        enabled: bool | None = None,
        generate_if_missing: bool | None = None,
        validate_inbound: bool | None = None,
    ) -> None:
        self.app = app

        if settings is None:
            try:
                from app.core.config import get_settings

                settings = get_settings()
            except Exception:
                settings = {}

        self.settings = settings

        resolved_header_name = str(
            header_name
            or _setting(settings, "REQUEST_ID_HEADER", DEFAULT_REQUEST_ID_HEADER)
            or DEFAULT_REQUEST_ID_HEADER
        ).strip()

        if not _is_valid_header_name(resolved_header_name):
            resolved_header_name = DEFAULT_REQUEST_ID_HEADER

        resolved_correlation_header_name = str(
            correlation_header_name
            or _setting(
                settings,
                "CORRELATION_ID_HEADER",
                DEFAULT_CORRELATION_ID_HEADER,
            )
            or DEFAULT_CORRELATION_ID_HEADER
        ).strip()

        if not _is_valid_header_name(resolved_correlation_header_name):
            resolved_correlation_header_name = DEFAULT_CORRELATION_ID_HEADER

        self.header_name = resolved_header_name
        self.correlation_header_name = resolved_correlation_header_name

        self.enabled = _as_bool(
            enabled
            if enabled is not None
            else _setting(settings, "REQUEST_ID_MIDDLEWARE_ENABLED", True),
            True,
        )

        self.generate_if_missing = _as_bool(
            generate_if_missing
            if generate_if_missing is not None
            else _setting(settings, "REQUEST_ID_GENERATE_IF_MISSING", True),
            True,
        )

        self.validate_inbound = _as_bool(
            validate_inbound
            if validate_inbound is not None
            else _setting(settings, "REQUEST_ID_VALIDATE_INBOUND", True),
            True,
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """
        ASGI entrypoint.
        """
        if not self.enabled:
            await self.app(scope, receive, send)
            return

        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        inbound_request_id: Optional[str] = None

        if self.validate_inbound:
            inbound_request_id = _first_valid_header(scope, self.header_name)

        request_id = inbound_request_id

        if not request_id and self.generate_if_missing:
            request_id = _generate_request_id()

        if not request_id:
            # No trusted inbound ID and generation disabled. Proceed without
            # middleware-managed identifiers. Downstream dependencies may still
            # generate a request ID if needed.
            await self.app(scope, receive, send)
            return

        inbound_correlation_id: Optional[str] = None

        if self.validate_inbound:
            inbound_correlation_id = _first_valid_header(
                scope,
                self.correlation_header_name,
            )

        correlation_id = inbound_correlation_id or request_id

        _set_scope_state(
            scope,
            request_id=request_id,
            correlation_id=correlation_id,
        )

        request_id_token: Token[Optional[str]] = _REQUEST_ID_CTX.set(request_id)
        correlation_id_token: Token[Optional[str]] = _CORRELATION_ID_CTX.set(
            correlation_id
        )

        async def send_wrapper(message: Message) -> None:
            """
            Inject canonical identifiers into HTTP response start messages.
            """
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])

                headers = _upsert_header(
                    headers,
                    self.header_name,
                    request_id,
                )

                headers = _upsert_header(
                    headers,
                    self.correlation_header_name,
                    correlation_id,
                )

                message = {
                    **message,
                    "headers": headers,
                }

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            _REQUEST_ID_CTX.reset(request_id_token)
            _CORRELATION_ID_CTX.reset(correlation_id_token)


# -----------------------------------------------------------------------------
# Convenience factory
# -----------------------------------------------------------------------------


def create_request_id_middleware(
    app: ASGIApp,
    **kwargs: Any,
) -> RequestIdMiddleware:
    """
    Convenience factory for explicit middleware installation.

    Example:

        app.add_middleware(create_request_id_middleware)
    """
    return RequestIdMiddleware(app, **kwargs)


__all__ = [
    "DEFAULT_CORRELATION_ID_HEADER",
    "DEFAULT_REQUEST_ID_HEADER",
    "MAX_ID_LENGTH",
    "RequestIdLogFilter",
    "RequestIdMiddleware",
    "create_request_id_middleware",
    "get_current_correlation_id",
    "get_current_request_id",
    "get_request_context",
]