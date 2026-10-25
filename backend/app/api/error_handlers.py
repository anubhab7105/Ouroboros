"""
MULEGUARD backend API error handlers.

This module is responsible for converting backend exceptions into stable,
safe, JSON-serializable API error responses.

Primary responsibilities:

- translate MULEGUARD domain exceptions into consistent error envelopes;
- translate FastAPI/Pydantic validation errors into safe field-level feedback;
- translate Starlette/FastAPI HTTP exceptions into stable error codes;
- translate low-level SQLAlchemy failures into non-leaking service errors;
- catch unexpected exceptions without exposing stack traces, secrets, tokens,
  database URLs, raw complaint narratives, or real customer data;
- preserve request/correlation IDs where available;
- emit safe structured logs for observability;
- support explicit retryable semantics for rate limits, timeouts, and transient
  infrastructure failures.

Product-safety rules enforced here:

- Error responses must not expose secrets, credentials, tokens, database URLs,
  stack traces, raw payloads, or real customer data.
- Client/input failures must be distinguishable from unexpected server failures.
- Validation errors must remain useful without echoing sensitive values.
- Graph, ML, case, report, ingestion, and audit failures must not imply proof of
  wrongdoing or automatic enforcement.
- The backend remains the security boundary.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from typing import Any, Final, Optional
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response

from app.api import REQUEST_ID_HEADER
from app.core.config import get_settings
from app.exceptions import (
    ClientError,
    ErrorCode,
    ErrorCategory,
    MuleGuardError,
    ValidationError as MuleGuardValidationError,
    build_error_payload,
    generic_internal_payload,
)

logger = logging.getLogger("muleguard.backend.api.error_handlers")


# -----------------------------------------------------------------------------
# Safe detail limits
# -----------------------------------------------------------------------------

MAX_DETAIL_STRING_LENGTH: Final[int] = 512
MAX_DETAIL_SEQUENCE_LENGTH: Final[int] = 50
MAX_DETAIL_MAPPING_KEYS: Final[int] = 50
MAX_DETAIL_DEPTH: Final[int] = 8


# -----------------------------------------------------------------------------
# Boolean parsing
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}


# -----------------------------------------------------------------------------
# Sensitive-key detection
# -----------------------------------------------------------------------------

SENSITIVE_DETAIL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "apikey",
        "auth_header",
        "authorization",
        "bearer",
        "body",
        "card_number",
        "cookie",
        "credential",
        "credentials",
        "cvv",
        "id_token",
        "narrative",
        "otp",
        "pan",
        "pass",
        "passwd",
        "password",
        "pin",
        "private_key",
        "raw_payload",
        "refresh_token",
        "secret",
        "secret_key",
        "session",
        "token",
    }
)

SENSITIVE_KEY_TOKENS: Final[tuple[str, ...]] = (
    "access_key",
    "api_key",
    "apikey",
    "authorization",
    "card_number",
    "credential",
    "narrative",
    "passphrase",
    "password",
    "passwd",
    "private_key",
    "raw_payload",
    "refresh_token",
    "secret",
    "secret_key",
    "token",
)


# -----------------------------------------------------------------------------
# Safe response headers
# -----------------------------------------------------------------------------

SAFE_RESPONSE_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "allow",
        "retry-after",
        "www-authenticate",
        "x-request-id",
    }
)


# -----------------------------------------------------------------------------
# Regex helpers
# -----------------------------------------------------------------------------

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_REQUEST_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _setting(settings: Any, name: str, default: Any = None) -> Any:
    """
    Read a setting from either a Pydantic settings object or mapping.
    """
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


def _csv(value: object) -> list[str]:
    """
    Parse comma-separated settings into a clean list.
    """
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return [part.strip() for part in str(value).split(",") if part.strip()]


def _is_production_like(settings: Any) -> bool:
    """
    Return True when the runtime environment is production-like.
    """
    env = str(_setting(settings, "BACKEND_ENV", "local")).strip().lower()

    configured_values = _csv(
        _setting(
            settings,
            "BACKEND_PRODUCTION_LIKE_ENVS",
            "production,staging,prod,stage",
        )
    )

    production_like_values = {value.lower() for value in configured_values}

    if not production_like_values:
        production_like_values = {"production", "staging", "prod", "stage"}

    return env in production_like_values


def _should_include_details(settings: Any) -> bool:
    """
    Return True when sanitized error details may be included in responses.
    """
    if _is_production_like(settings):
        return _as_bool(
            _setting(settings, "ERROR_INCLUDE_DETAILS_IN_PRODUCTION", False),
            False,
        )

    return _as_bool(
        _setting(settings, "ERROR_INCLUDE_DETAILS_IN_LOCAL", True),
        True,
    )


def _should_include_validation_details(settings: Any) -> bool:
    """
    Return True when sanitized validation field details may be included.

    Validation details are usually safe and necessary for client usability, so
    this defaults to True even in production-like environments. It can still be
    disabled explicitly.
    """
    if _is_production_like(settings):
        return _as_bool(
            _setting(settings, "ERROR_INCLUDE_VALIDATION_DETAILS_IN_PRODUCTION", True),
            True,
        )

    return _as_bool(
        _setting(settings, "ERROR_INCLUDE_VALIDATION_DETAILS_IN_LOCAL", True),
        True,
    )


def _should_include_validation_messages(settings: Any) -> bool:
    """
    Return True when human-readable validation messages may be included.

    Messages are sanitized and truncated, but this can be disabled if a
    deployment prefers only field/type information.
    """
    if _is_production_like(settings):
        return _as_bool(
            _setting(settings, "ERROR_INCLUDE_VALIDATION_MESSAGES_IN_PRODUCTION", True),
            True,
        )

    return _as_bool(
        _setting(settings, "ERROR_INCLUDE_VALIDATION_MESSAGES_IN_LOCAL", True),
        True,
    )


def _get_request_id(request: Request) -> Optional[str]:
    """
    Return a safe request/correlation ID when available.
    """
    request_id = getattr(request.state, "request_id", None)

    if not request_id:
        request_id = request.headers.get(REQUEST_ID_HEADER)

    if not request_id:
        return None

    normalized = str(request_id).strip()

    if not normalized:
        return None

    if _REQUEST_ID_RE.match(normalized):
        return normalized

    return None


# -----------------------------------------------------------------------------
# Sanitization helpers
# -----------------------------------------------------------------------------


def _truncate_string(value: str) -> str:
    """
    Remove control characters and truncate long strings safely.
    """
    cleaned = _CONTROL_CHAR_RE.sub("", value)

    if len(cleaned) <= MAX_DETAIL_STRING_LENGTH:
        return cleaned

    return cleaned[:MAX_DETAIL_STRING_LENGTH] + "...[truncated]"


def _is_sensitive_key(key: str) -> bool:
    """
    Return True when a detail key appears sensitive and should be omitted.
    """
    lowered = key.strip().lower()

    if lowered in SENSITIVE_DETAIL_KEYS:
        return True

    return any(token in lowered for token in SENSITIVE_KEY_TOKENS)


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    """
    Convert an arbitrary value into a JSON-safe, non-sensitive detail value.

    This intentionally avoids calling `repr()` on arbitrary objects because
    object representations may leak secrets or internal state.
    """
    if depth > MAX_DETAIL_DEPTH:
        return "[truncated-depth]"

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, str):
        return _truncate_string(value)

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, (datetime, date, time)):
        return value.isoformat()

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, Enum):
        return _sanitize_value(value.value, depth + 1)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        return _sanitize_mapping(value, depth + 1)

    if isinstance(value, (list, tuple, set, frozenset)):
        original_length = len(value)
        limited = list(value)[:MAX_DETAIL_SEQUENCE_LENGTH]
        sanitized = [_sanitize_value(item, depth + 1) for item in limited]

        if original_length > MAX_DETAIL_SEQUENCE_LENGTH:
            sanitized.append(f"<+{original_length - MAX_DETAIL_SEQUENCE_LENGTH} more>")

        return sanitized

    return f"<{type(value).__name__}>"


def _sanitize_mapping(mapping: Mapping[Any, Any], depth: int = 0) -> dict[str, Any]:
    """
    Return a sanitized, JSON-safe mapping suitable for error details.
    """
    if depth > MAX_DETAIL_DEPTH:
        return {"_truncated": True}

    sanitized: dict[str, Any] = {}

    for raw_key, raw_value in mapping.items():
        key = raw_key if isinstance(raw_key, str) else str(raw_key)

        if _is_sensitive_key(key):
            continue

        if len(sanitized) >= MAX_DETAIL_MAPPING_KEYS:
            sanitized["_truncated_keys"] = True
            break

        sanitized[key] = _sanitize_value(raw_value, depth + 1)

    return sanitized


def _safe_headers(headers: Optional[Mapping[str, str]]) -> dict[str, str]:
    """
    Filter response headers to a safe allowlist.
    """
    if not headers:
        return {}

    safe: dict[str, str] = {}

    for raw_key, raw_value in headers.items():
        key = str(raw_key).strip()

        if not key:
            continue

        if key.lower() not in SAFE_RESPONSE_HEADERS:
            continue

        value = str(raw_value).strip()

        if not value:
            continue

        safe[key] = _truncate_string(value)

    return safe


def _safe_loc(loc: Any) -> str:
    """
    Convert a Pydantic/FastAPI error location into a safe dotted path.

    Sensitive path segments such as `password` or `token` are redacted.
    """
    if not loc:
        return "body"

    parts: list[str] = []

    if isinstance(loc, Sequence) and not isinstance(loc, (str, bytes, bytearray)):
        iterable = loc
    else:
        iterable = [loc]

    for item in iterable:
        if isinstance(item, int):
            parts.append(str(item))
            continue

        text_value = str(item).strip()

        if not text_value:
            continue

        if _is_sensitive_key(text_value):
            parts.append("***")
        else:
            parts.append(_truncate_string(text_value))

    return ".".join(parts) or "body"


def _validation_fields_from_errors(
    errors: Sequence[Mapping[str, Any]],
    *,
    include_messages: bool,
) -> list[dict[str, Any]]:
    """
    Build sanitized validation field details from Pydantic/FastAPI errors.
    """
    fields: list[dict[str, Any]] = []
    limited_errors = list(errors)[:MAX_DETAIL_SEQUENCE_LENGTH]

    for raw_error in limited_errors:
        field = _safe_loc(raw_error.get("loc"))
        error_type = str(raw_error.get("type") or "value_error").strip()
        message = str(raw_error.get("msg") or "Invalid or missing value.").strip()

        if not include_messages:
            message = "Invalid or missing value."

        fields.append(
            {
                "field": field,
                "type": _truncate_string(error_type),
                "message": _truncate_string(message),
            }
        )

    if len(errors) > MAX_DETAIL_SEQUENCE_LENGTH:
        fields.append({"_truncated": True})

    return fields


# -----------------------------------------------------------------------------
# Response helpers
# -----------------------------------------------------------------------------


def _make_response(
    payload: dict[str, Any],
    status_code: int,
    headers: Optional[Mapping[str, str]] = None,
) -> JSONResponse:
    """
    Build a safe JSON error response.
    """
    safe_headers = _safe_headers(headers)

    request_id = payload.get("request_id")

    if request_id:
        safe_headers.setdefault(REQUEST_ID_HEADER, str(request_id))

    return JSONResponse(
        status_code=int(status_code),
        content=payload,
        headers=safe_headers,
    )


def _request_log_context(request: Request) -> dict[str, Any]:
    """
    Return safe request context for logging.

    Do not include query strings, bodies, headers, cookies, tokens, passwords,
    raw narratives, or real customer data.
    """
    user = getattr(request.state, "user", None)
    user_id = getattr(request.state, "user_id", None) or getattr(user, "id", None)
    role = getattr(request.state, "user_role", None)

    if role is None:
        user_role = getattr(user, "role", None)
        role = getattr(user_role, "value", user_role)

    return {
        "method": request.method.upper(),
        "path": request.url.path,
        "user_id": str(user_id) if user_id else None,
        "role": str(role) if role else None,
    }


def _log_client_error(
    request: Request,
    payload: dict[str, Any],
    status_code: int,
) -> None:
    """
    Log a safe client/input/policy error.
    """
    context = _request_log_context(request)

    category = str(payload.get("category") or "")
    code = str(payload.get("code") or "")
    request_id = payload.get("request_id")

    warning_categories = {
        ErrorCategory.AUTHENTICATION,
        ErrorCategory.AUTHORIZATION,
        ErrorCategory.POLICY,
        ErrorCategory.EVIDENCE,
        ErrorCategory.AUDIT,
    }

    level = logging.WARNING if category in warning_categories else logging.INFO

    logger.log(
        level,
        "API client error method=%s path=%s status=%s code=%s category=%s request_id=%s user_id=%s role=%s",
        context["method"],
        context["path"],
        status_code,
        code,
        category,
        request_id,
        context["user_id"],
        context["role"],
    )


def _log_server_error(
    request: Request,
    payload: dict[str, Any],
    status_code: int,
    *,
    exc_info: bool = False,
) -> None:
    """
    Log a safe server/infrastructure error.
    """
    context = _request_log_context(request)

    logger.error(
        "API server error method=%s path=%s status=%s code=%s category=%s request_id=%s user_id=%s role=%s",
        context["method"],
        context["path"],
        status_code,
        payload.get("code"),
        payload.get("category"),
        payload.get("request_id"),
        context["user_id"],
        context["role"],
        exc_info=exc_info,
    )


# -----------------------------------------------------------------------------
# MULEGUARD domain exception handler
# -----------------------------------------------------------------------------


async def muleguard_error_handler(
    request: Request,
    exc: MuleGuardError,
) -> Response:
    """
    Convert MULEGUARD domain exceptions into stable API error responses.
    """
    settings = get_settings()
    request_id = _get_request_id(request)

    payload = build_error_payload(exc, request_id=request_id)

    if not _should_include_details(settings):
        payload.pop("details", None)

    status_code = int(exc.status_code)
    headers = _safe_headers(exc.http_headers())

    if status_code == 401:
        if not any(key.lower() == "www-authenticate" for key in headers):
            headers["WWW-Authenticate"] = "Bearer"

    response = _make_response(payload, status_code, headers)

    if 400 <= status_code < 500:
        _log_client_error(request, payload, status_code)
    else:
        _log_server_error(request, payload, status_code, exc_info=status_code >= 500)

    return response


# -----------------------------------------------------------------------------
# FastAPI request validation handler
# -----------------------------------------------------------------------------


async def request_validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> Response:
    """
    Convert FastAPI request validation errors into safe field-level feedback.
    """
    settings = get_settings()
    request_id = _get_request_id(request)

    include_messages = _should_include_validation_messages(settings)
    fields = _validation_fields_from_errors(
        exc.errors(),
        include_messages=include_messages,
    )

    mapped_exc = MuleGuardValidationError(
        message="Request validation failed.",
        details={"fields": fields},
    )

    payload = build_error_payload(mapped_exc, request_id=request_id)

    if not _should_include_validation_details(settings):
        payload.pop("details", None)

    response = _make_response(payload, 422)
    _log_client_error(request, payload, 422)

    return response


# -----------------------------------------------------------------------------
# Pydantic validation handler
# -----------------------------------------------------------------------------


async def pydantic_validation_error_handler(
    request: Request,
    exc: PydanticValidationError,
) -> Response:
    """
    Convert raw Pydantic validation errors into safe field-level feedback.

    This is useful when services or schemas raise Pydantic validation errors
    outside the normal FastAPI request-parsing path.
    """
    settings = get_settings()
    request_id = _get_request_id(request)

    include_messages = _should_include_validation_messages(settings)
    fields = _validation_fields_from_errors(
        exc.errors(),
        include_messages=include_messages,
    )

    mapped_exc = MuleGuardValidationError(
        message="Request validation failed.",
        details={"fields": fields},
    )

    payload = build_error_payload(mapped_exc, request_id=request_id)

    if not _should_include_validation_details(settings):
        payload.pop("details", None)

    response = _make_response(payload, 422)
    _log_client_error(request, payload, 422)

    return response


# -----------------------------------------------------------------------------
# HTTP exception handler
# -----------------------------------------------------------------------------


_HTTP_STATUS_MAP: Final[dict[int, tuple[str, str, str]]] = {
    400: (
        ErrorCode.INVALID_REQUEST,
        ErrorCategory.CLIENT,
        "Invalid request.",
    ),
    401: (
        ErrorCode.AUTHENTICATION_REQUIRED,
        ErrorCategory.AUTHENTICATION,
        "Authentication required.",
    ),
    403: (
        ErrorCode.PERMISSION_DENIED,
        ErrorCategory.AUTHORIZATION,
        "Insufficient permissions for this action.",
    ),
    404: (
        ErrorCode.NOT_FOUND,
        ErrorCategory.CLIENT,
        "Resource not found.",
    ),
    405: (
        ErrorCode.METHOD_NOT_ALLOWED,
        ErrorCategory.CLIENT,
        "Method not allowed.",
    ),
    408: (
        ErrorCode.REQUEST_TIMEOUT,
        ErrorCategory.CLIENT,
        "Request timed out.",
    ),
    409: (
        ErrorCode.CONFLICT,
        ErrorCategory.CLIENT,
        "Resource conflict.",
    ),
    410: (
        ErrorCode.GONE,
        ErrorCategory.CLIENT,
        "Resource is no longer available.",
    ),
    413: (
        ErrorCode.PAYLOAD_TOO_LARGE,
        ErrorCategory.CLIENT,
        "Request payload is too large.",
    ),
    415: (
        ErrorCode.UNSUPPORTED_MEDIA_TYPE,
        ErrorCategory.CLIENT,
        "Unsupported media type.",
    ),
    422: (
        ErrorCode.VALIDATION_ERROR,
        ErrorCategory.VALIDATION,
        "Request validation failed.",
    ),
    429: (
        ErrorCode.RATE_LIMITED,
        ErrorCategory.CLIENT,
        "Too many requests.",
    ),
    500: (
        ErrorCode.INTERNAL_ERROR,
        ErrorCategory.INTERNAL,
        "Internal server error.",
    ),
    501: (
        ErrorCode.UNSUPPORTED_ACTION,
        ErrorCategory.INTERNAL,
        "Requested action is not supported.",
    ),
    503: (
        ErrorCode.SERVICE_UNAVAILABLE,
        ErrorCategory.INTERNAL,
        "Service temporarily unavailable.",
    ),
    504: (
        ErrorCode.OPERATION_TIMEOUT,
        ErrorCategory.INTERNAL,
        "Operation timed out.",
    ),
}


def _http_status_mapping(status_code: int) -> tuple[str, str, str]:
    """
    Return a safe code/category/message tuple for an HTTP status code.
    """
    mapped = _HTTP_STATUS_MAP.get(status_code)

    if mapped is not None:
        return mapped

    if 400 <= status_code < 500:
        return (
            ErrorCode.INVALID_REQUEST,
            ErrorCategory.CLIENT,
            "Invalid request.",
        )

    return (
        ErrorCode.INTERNAL_ERROR,
        ErrorCategory.INTERNAL,
        "Internal server error.",
    )


async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
) -> Response:
    """
    Convert Starlette/FastAPI HTTP exceptions into stable MULEGUARD error
    responses without leaking raw exception details.
    """
    settings = get_settings()
    request_id = _get_request_id(request)
    status_code = int(getattr(exc, "status_code", 500))

    code, category, message = _http_status_mapping(status_code)

    payload: dict[str, Any] = {
        "code": code,
        "message": message,
        "category": category,
        "retryable": status_code in {408, 429, 503, 504},
    }

    if request_id:
        payload["request_id"] = request_id

    headers = _safe_headers(getattr(exc, "headers", None))

    if status_code == 401:
        if not any(key.lower() == "www-authenticate" for key in headers):
            headers["WWW-Authenticate"] = "Bearer"

    if status_code == 429:
        if not any(key.lower() == "retry-after" for key in headers):
            headers["Retry-After"] = "60"

    response = _make_response(payload, status_code, headers)

    if 400 <= status_code < 500:
        _log_client_error(request, payload, status_code)
    else:
        _log_server_error(request, payload, status_code, exc_info=status_code >= 500)

    return response


# -----------------------------------------------------------------------------
# SQLAlchemy fallback handlers
# -----------------------------------------------------------------------------


async def integrity_error_handler(
    request: Request,
    exc: IntegrityError,
) -> Response:
    """
    Convert database integrity errors into safe conflict responses.

    Constraint names and raw database messages are intentionally not exposed.
    """
    request_id = _get_request_id(request)

    payload: dict[str, Any] = {
        "code": ErrorCode.CONFLICT,
        "message": "Resource conflict.",
        "category": ErrorCategory.CLIENT,
        "retryable": False,
    }

    if request_id:
        payload["request_id"] = request_id

    context = _request_log_context(request)

    logger.warning(
        "Database integrity error method=%s path=%s request_id=%s error_type=%s",
        context["method"],
        context["path"],
        request_id,
        type(exc).__name__,
    )

    return _make_response(payload, 409)


async def operational_error_handler(
    request: Request,
    exc: OperationalError,
) -> Response:
    """
    Convert database operational errors into safe unavailable responses.
    """
    request_id = _get_request_id(request)

    payload: dict[str, Any] = {
        "code": ErrorCode.DATABASE_UNAVAILABLE,
        "message": "Database is temporarily unavailable.",
        "category": ErrorCategory.DATABASE,
        "retryable": True,
    }

    if request_id:
        payload["request_id"] = request_id

    _log_server_error(request, payload, 503, exc_info=True)

    return _make_response(payload, 503)


async def sqlalchemy_error_handler(
    request: Request,
    exc: SQLAlchemyError,
) -> Response:
    """
    Convert remaining SQLAlchemy errors into safe internal database errors.
    """
    request_id = _get_request_id(request)

    payload: dict[str, Any] = {
        "code": ErrorCode.DATABASE_ERROR,
        "message": "Database error.",
        "category": ErrorCategory.DATABASE,
        "retryable": False,
    }

    if request_id:
        payload["request_id"] = request_id

    _log_server_error(request, payload, 500, exc_info=True)

    return _make_response(payload, 500)


# -----------------------------------------------------------------------------
# Unexpected exception handler
# -----------------------------------------------------------------------------


async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
) -> Response:
    """
    Catch unexpected exceptions and return a safe generic internal error.

    Stack traces are logged internally but never returned to clients.
    """
    request_id = _get_request_id(request)
    payload = generic_internal_payload(request_id=request_id)

    _log_server_error(request, payload, 500, exc_info=True)

    return _make_response(payload, 500)


# -----------------------------------------------------------------------------
# Registration
# -----------------------------------------------------------------------------


def register_exception_handlers(app: FastAPI) -> None:
    """
    Register MULEGUARD exception handlers on the FastAPI application.

    This function is idempotent.
    """
    if getattr(app.state, "_muleguard_error_handlers_registered", False):
        return

    app.add_exception_handler(MuleGuardError, muleguard_error_handler)
    app.add_exception_handler(RequestValidationError, request_validation_error_handler)
    app.add_exception_handler(PydanticValidationError, pydantic_validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(IntegrityError, integrity_error_handler)
    app.add_exception_handler(OperationalError, operational_error_handler)
    app.add_exception_handler(SQLAlchemyError, sqlalchemy_error_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    app.state._muleguard_error_handlers_registered = True


__all__ = [
    "register_exception_handlers",
]