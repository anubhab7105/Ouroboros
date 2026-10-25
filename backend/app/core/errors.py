"""
MULEGUARD backend core error utilities.

This module provides framework-agnostic error handling primitives used by
services, ingestion pipelines, ML orchestration, graph analytics, reporting,
audit workflows, and API adapters.

Primary responsibilities:

- build safe, stable error payloads from arbitrary exceptions;
- translate common low-level exceptions into MULEGUARD domain exceptions;
- classify errors as client/server, retryable, transient, or policy-related;
- provide safe structured error context for logs and audits;
- provide bounded batch-error collection for ingestion and validation flows;
- sanitize error details so secrets, tokens, passwords, database URLs, raw
  complaint narratives, and real customer data are never exposed;
- keep error behaviour deterministic, inspectable, and honest.

Relationship to other modules:

- `app.exceptions` owns the canonical MULEGUARD exception taxonomy.
- `app.api.error_handlers` owns FastAPI/HTTP exception mapping.
- `app.core.errors` owns reusable non-HTTP error utilities and translation
  helpers.

Security and product-safety rules enforced here:

- Error payloads must not expose secrets, credentials, tokens, database URLs,
  stack traces, raw complaint narratives, model artifact paths, or real customer
  data.
- Unexpected server failures are mapped to a generic internal error unless a
  safer specific mapping exists.
- Client/input failures remain distinguishable from server/infrastructure
  failures.
- Batch error collectors are bounded and sanitize row-level details.
- Error handling never triggers automatic adverse customer action.

Explicit non-goals:

- This module does not define the canonical exception classes.
- This module does not replace API-level exception handlers.
- This module does not ship logs or errors to external systems.
- This module does not claim production readiness.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from typing import Any, Final, Optional
from uuid import UUID

from app.exceptions import (
    AuthenticationError,
    ClientError,
    ConflictError,
    DatabaseError,
    DatabaseOperationError,
    DatabaseTimeoutError,
    DatabaseUnavailableError,
    ErrorCategory,
    ErrorCode,
    GoneError,
    InternalError,
    InvalidRequestError,
    MethodNotAllowedError,
    MuleGuardError,
    NotFoundError,
    OperationTimeoutError,
    PayloadTooLargeError,
    PermissionDeniedError,
    RateLimitError,
    RequestTimeoutError,
    ServerError,
    ServiceUnavailableError,
    UnsupportedActionError,
    UnsupportedMediaTypeError,
    ValidationError as MuleGuardValidationError,
    build_error_payload,
    generic_internal_payload,
    is_client_error,
    is_retryable_error,
    is_server_error,
)

# Optional integrations are imported defensively so core error helpers remain
# usable in minimal environments and tests.
try:  # pragma: no cover - exercised indirectly in normal backend use
    from pydantic import ValidationError as PydanticValidationError
except Exception:  # pragma: no cover - fallback for minimal environments
    PydanticValidationError = None  # type: ignore[assignment]

try:  # pragma: no cover - exercised indirectly in normal backend use
    from fastapi.exceptions import RequestValidationError
except Exception:  # pragma: no cover - fallback for minimal environments
    RequestValidationError = None  # type: ignore[assignment]

try:  # pragma: no cover - exercised indirectly in normal backend use
    from starlette.exceptions import HTTPException as StarletteHTTPException
except Exception:  # pragma: no cover - fallback for minimal environments
    StarletteHTTPException = None  # type: ignore[assignment]

try:  # pragma: no cover - exercised indirectly in normal backend use
    from sqlalchemy.exc import (
        DBAPIError,
        IntegrityError,
        OperationalError,
        SQLAlchemyError,
    )
except Exception:  # pragma: no cover - fallback for minimal environments
    DBAPIError = None  # type: ignore[assignment]
    IntegrityError = None  # type: ignore[assignment]
    OperationalError = None  # type: ignore[assignment]
    SQLAlchemyError = None  # type: ignore[assignment]


logger = logging.getLogger("muleguard.backend.core.errors")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

MAX_DETAIL_STRING_LENGTH: Final[int] = 512
MAX_DETAIL_SEQUENCE_LENGTH: Final[int] = 50
MAX_DETAIL_MAPPING_KEYS: Final[int] = 50
MAX_DETAIL_DEPTH: Final[int] = 8
MAX_BATCH_ERRORS: Final[int] = 100

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

_SENSITIVE_DETAIL_KEYS: Final[frozenset[str]] = frozenset(
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
        "narrative_raw",
        "narrative_normalized",
        "otp",
        "pan",
        "pass",
        "passwd",
        "password",
        "password_hash",
        "payload_hash",
        "pin",
        "private_key",
        "raw_payload",
        "refresh_token",
        "secret",
        "secret_key",
        "session",
        "source_payload_hash",
        "token",
    }
)

_SENSITIVE_KEY_TOKENS: Final[tuple[str, ...]] = (
    "access_key",
    "account_number",
    "api_key",
    "apikey",
    "authorization",
    "card_number",
    "credential",
    "customer_data",
    "customer_id",
    "device_id",
    "email_address",
    "fraud",
    "ground_truth",
    "hash",
    "ifsc",
    "identifier_hash",
    "ip_address",
    "label",
    "narrative",
    "passphrase",
    "password",
    "passwd",
    "payload_hash",
    "phone_number",
    "private_key",
    "raw_",
    "real_data",
    "refresh_token",
    "ring",
    "scenario",
    "secret",
    "secret_key",
    "token",
    "upi_id",
)

_SQL_STATEMENT_TIMEOUT_CODES: Final[frozenset[str]] = frozenset(
    {
        "57014",  # query_canceled
        "57P01",  # admin_shutdown
        "57P02",  # crash_shutdown
        "57P03",  # cannot_connect_now
    }
)

_SQL_LOCK_TIMEOUT_CODES: Final[frozenset[str]] = frozenset(
    {
        "55P03",  # lock_not_available
    }
)

_SQL_CONNECTION_ERROR_PREFIXES: Final[tuple[str, ...]] = ("08",)
_SQL_SERIALIZATION_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "40001",  # serialization_failure
        "40P01",  # deadlock_detected
    }
)


# -----------------------------------------------------------------------------
# Optional exception-class tuples
# -----------------------------------------------------------------------------

_PYDANTIC_VALIDATION_EXCEPTIONS: Final[tuple[type[Exception], ...]] = tuple(
    exception_class
    for exception_class in (PydanticValidationError, RequestValidationError)
    if exception_class is not None
)

_HTTP_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    (StarletteHTTPException,) if StarletteHTTPException is not None else ()
)

_SQLALCHEMY_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    (SQLAlchemyError,) if SQLAlchemyError is not None else ()
)

_SQLALCHEMY_INTEGRITY_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    (IntegrityError,) if IntegrityError is not None else ()
)

_SQLALCHEMY_OPERATIONAL_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    (OperationalError,) if OperationalError is not None else ()
)

_SQLALCHEMY_DBAPI_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    (DBAPIError,) if DBAPIError is not None else ()
)


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class ErrorSeverity(str, Enum):
    """
    Operational severity for error logging and monitoring.
    """

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class FailureClass(str, Enum):
    """
    Coarse failure classification.
    """

    CLIENT = "client"
    SERVER = "server"
    DATABASE = "database"
    POLICY = "policy"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"


# -----------------------------------------------------------------------------
# Dataclasses
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ErrorContext:
    """
    Safe structured context for an error.

    This object must not contain secrets, tokens, passwords, raw complaint
    narratives, or real customer data.
    """

    operation: str = ""
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    actor_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def merge(self, **kwargs: Any) -> "ErrorContext":
        """
        Return a new ErrorContext merged with safe supplied overrides.
        """
        current_metadata = dict(self.metadata or {})
        incoming_metadata = kwargs.pop("metadata", None)

        if isinstance(incoming_metadata, Mapping):
            current_metadata.update(incoming_metadata)

        return ErrorContext(
            operation=_clean_text(kwargs.get("operation", self.operation), 200),
            request_id=_clean_text(kwargs.get("request_id", self.request_id), 128) or None,
            correlation_id=(
                _clean_text(kwargs.get("correlation_id", self.correlation_id), 128) or None
            ),
            actor_id=_clean_text(kwargs.get("actor_id", self.actor_id), 128) or None,
            resource_type=(
                _clean_text(kwargs.get("resource_type", self.resource_type), 100) or None
            ),
            resource_id=(
                _clean_text(kwargs.get("resource_id", self.resource_id), 128) or None
            ),
            metadata=current_metadata,
        )

    def to_safe_dict(self) -> dict[str, Any]:
        """
        Return a sanitized mapping suitable for logs, audits, or diagnostics.
        """
        payload: dict[str, Any] = {
            "operation": _clean_text(self.operation, 200),
        }

        if self.request_id:
            payload["request_id"] = _clean_text(self.request_id, 128)

        if self.correlation_id:
            payload["correlation_id"] = _clean_text(self.correlation_id, 128)

        if self.actor_id:
            payload["actor_id"] = _clean_text(self.actor_id, 128)

        if self.resource_type:
            payload["resource_type"] = _clean_text(self.resource_type, 100)

        if self.resource_id:
            payload["resource_id"] = _clean_text(self.resource_id, 128)

        if self.metadata:
            payload["metadata"] = sanitize_mapping(self.metadata)

        return payload


@dataclass(frozen=True, slots=True)
class ErrorClassification:
    """
    Safe classification for an exception.
    """

    code: str
    message: str
    category: str
    status_code: int
    retryable: bool
    transient: bool
    failure_class: FailureClass
    severity: ErrorSeverity
    exception_type: str


@dataclass(frozen=True, slots=True)
class BatchRowError:
    """
    Safe row-level batch error.
    """

    row: Optional[int] = None
    field: Optional[str] = None
    code: Optional[str] = None
    message: Optional[str] = None
    details: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable mapping.
        """
        payload: dict[str, Any] = {}

        if self.row is not None:
            payload["row"] = int(self.row)

        if self.field:
            payload["field"] = _clean_text(self.field, 200)

        if self.code:
            payload["code"] = _clean_text(self.code, 100)

        if self.message:
            payload["message"] = _clean_text(self.message, 300)

        if self.details:
            payload["details"] = sanitize_mapping(self.details)

        return payload


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------


def _clean_text(value: Any, limit: int = MAX_DETAIL_STRING_LENGTH) -> str:
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
    Return True when a detail key appears sensitive or leakage-prone.
    """
    lowered = key.strip().lower()

    if lowered in _SENSITIVE_DETAIL_KEYS:
        return True

    return any(token in lowered for token in _SENSITIVE_KEY_TOKENS)


def sanitize_value(value: Any, depth: int = 0) -> Any:
    """
    Convert an arbitrary value into a JSON-safe, non-sensitive detail value.
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
        return _clean_text(value, MAX_DETAIL_STRING_LENGTH)

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, (datetime, date, time)):
        return value.isoformat()

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, Enum):
        return sanitize_value(value.value, depth + 1)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        return sanitize_mapping(value, depth + 1)

    if isinstance(value, (list, tuple, set, frozenset)):
        original_length = len(value)
        limited = list(value)[:MAX_DETAIL_SEQUENCE_LENGTH]
        sanitized = [sanitize_value(item, depth + 1) for item in limited]

        if original_length > MAX_DETAIL_SEQUENCE_LENGTH:
            sanitized.append({"_truncated": True})

        return sanitized

    return f"<{type(value).__name__}>"


def sanitize_mapping(mapping: Mapping[Any, Any], depth: int = 0) -> dict[str, Any]:
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

        sanitized[key] = sanitize_value(raw_value, depth + 1)

    return sanitized


def _failure_class_from_category(category: str) -> FailureClass:
    """
    Map an error category to a coarse failure class.
    """
    if category == ErrorCategory.CLIENT:
        return FailureClass.CLIENT

    if category == ErrorCategory.VALIDATION:
        return FailureClass.VALIDATION

    if category == ErrorCategory.AUTHENTICATION:
        return FailureClass.AUTHENTICATION

    if category == ErrorCategory.AUTHORIZATION:
        return FailureClass.AUTHORIZATION

    if category == ErrorCategory.POLICY:
        return FailureClass.POLICY

    if category == ErrorCategory.DATABASE:
        return FailureClass.DATABASE

    if category in {ErrorCategory.INTERNAL, ErrorCategory.CONFIGURATION}:
        return FailureClass.SERVER

    return FailureClass.UNKNOWN


def _severity_from_status_and_class(status_code: int, failure_class: FailureClass) -> ErrorSeverity:
    """
    Derive safe logging severity from status and failure class.
    """
    if failure_class in {FailureClass.AUTHENTICATION, FailureClass.AUTHORIZATION, FailureClass.POLICY}:
        return ErrorSeverity.WARNING

    if 400 <= status_code < 500:
        return ErrorSeverity.INFO

    if status_code >= 500:
        return ErrorSeverity.ERROR

    return ErrorSeverity.INFO


def _http_status_mapping(status_code: int) -> tuple[type[MuleGuardError], str, str]:
    """
    Return a safe MULEGUARD exception class, code, and message for an HTTP
    status code.
    """
    if status_code == 400:
        return InvalidRequestError, ErrorCode.INVALID_REQUEST, "Invalid request."

    if status_code == 401:
        return AuthenticationError, ErrorCode.AUTHENTICATION_REQUIRED, "Authentication required."

    if status_code == 403:
        return PermissionDeniedError, ErrorCode.PERMISSION_DENIED, "Insufficient permissions for this action."

    if status_code == 404:
        return NotFoundError, ErrorCode.NOT_FOUND, "Resource not found."

    if status_code == 405:
        return MethodNotAllowedError, ErrorCode.METHOD_NOT_ALLOWED, "Method not allowed."

    if status_code == 408:
        return RequestTimeoutError, ErrorCode.REQUEST_TIMEOUT, "Request timed out."

    if status_code == 409:
        return ConflictError, ErrorCode.CONFLICT, "Resource conflict."

    if status_code == 410:
        return GoneError, ErrorCode.GONE, "Resource is no longer available."

    if status_code == 413:
        return PayloadTooLargeError, ErrorCode.PAYLOAD_TOO_LARGE, "Request payload is too large."

    if status_code == 415:
        return UnsupportedMediaTypeError, ErrorCode.UNSUPPORTED_MEDIA_TYPE, "Unsupported media type."

    if status_code == 422:
        return MuleGuardValidationError, ErrorCode.VALIDATION_ERROR, "Request validation failed."

    if status_code == 429:
        return RateLimitError, ErrorCode.RATE_LIMITED, "Too many requests."

    if status_code == 501:
        return UnsupportedActionError, ErrorCode.UNSUPPORTED_ACTION, "Requested action is not supported."

    if status_code == 503:
        return ServiceUnavailableError, ErrorCode.SERVICE_UNAVAILABLE, "Service temporarily unavailable."

    if status_code == 504:
        return OperationTimeoutError, ErrorCode.OPERATION_TIMEOUT, "Operation timed out."

    if 400 <= status_code < 500:
        return InvalidRequestError, ErrorCode.INVALID_REQUEST, "Invalid request."

    return InternalError, ErrorCode.INTERNAL_ERROR, "Internal server error."


def _pydantic_fields_from_errors(errors: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """
    Build sanitized validation field details from Pydantic/FastAPI errors.
    """
    fields: list[dict[str, Any]] = []
    limited_errors = list(errors)[:MAX_BATCH_ERRORS]

    for raw_error in limited_errors:
        loc = raw_error.get("loc") or ()
        field_parts: list[str] = []

        if isinstance(loc, Sequence) and not isinstance(loc, (str, bytes, bytearray)):
            iterable = loc
        else:
            iterable = (loc,)

        for part in iterable:
            text = str(part).strip()

            if not text or text == "body":
                continue

            if _is_sensitive_key(text):
                field_parts.append("***")
            else:
                field_parts.append(_clean_text(text, 200))

        field_name = ".".join(field_parts) or "body"

        error_type = _clean_text(raw_error.get("type") or "value_error", 100)
        message = _clean_text(raw_error.get("msg") or "Invalid or missing value.", 300)

        if _is_sensitive_key(field_name):
            message = "Invalid or missing value."

        fields.append(
            {
                "field": field_name,
                "type": error_type,
                "message": message,
            }
        )

    if len(errors) > MAX_BATCH_ERRORS:
        fields.append({"_truncated": True})

    return fields


def _sql_state(exc: BaseException) -> Optional[str]:
    """
    Return a SQLSTATE/pgcode when available.
    """
    for source in (exc, getattr(exc, "orig", None)):
        if source is None:
            continue

        for attribute in ("pgcode", "sqlstate"):
            code = getattr(source, attribute, None)

            if code:
                return str(code)

    return None


# -----------------------------------------------------------------------------
# Context helpers
# -----------------------------------------------------------------------------


def context_from_request(request: Any) -> ErrorContext:
    """
    Build a safe ErrorContext from a request-like object.

    This helper does not read query strings, headers, cookies, or bodies.
    """
    state = getattr(request, "state", None)

    request_id = getattr(state, "request_id", None)
    correlation_id = getattr(state, "correlation_id", None)
    user_id = getattr(state, "user_id", None)

    if request_id is None:
        headers = getattr(request, "headers", None)

        if headers is not None:
            request_id = headers.get("X-Request-ID")

    if correlation_id is None and headers is not None:
        correlation_id = headers.get("X-Correlation-ID")

    url = getattr(request, "url", None)
    path = getattr(url, "path", None)
    method = str(getattr(request, "method", "") or "").upper()

    operation = ""

    if method and path:
        operation = f"{method} {path}"
    elif path:
        operation = str(path)

    return ErrorContext(
        operation=_clean_text(operation, 200),
        request_id=_clean_text(request_id, 128) or None,
        correlation_id=_clean_text(correlation_id, 128) or None,
        actor_id=_clean_text(user_id, 128) or None,
    )


# -----------------------------------------------------------------------------
# Payload builders
# -----------------------------------------------------------------------------


def safe_error_payload(
    exc: BaseException,
    context: Optional[ErrorContext] = None,
) -> dict[str, Any]:
    """
    Build a stable, safe JSON error payload from an exception.

    This does not include stack traces, exception class names, secrets, tokens,
    passwords, database URLs, or raw sensitive narratives.
    """
    request_id = context.request_id if context is not None else None

    if isinstance(exc, MuleGuardError):
        payload = build_error_payload(exc, request_id=request_id)
    else:
        payload = generic_internal_payload(request_id=request_id)

    return payload


def safe_error_message(exc: BaseException) -> str:
    """
    Return a safe public message for an exception.
    """
    if isinstance(exc, MuleGuardError):
        return exc.message

    return "Internal server error."


# -----------------------------------------------------------------------------
# Exception translation
# -----------------------------------------------------------------------------


def translate_exception(exc: BaseException) -> MuleGuardError:
    """
    Translate common low-level exceptions into MULEGUARD domain exceptions.

    This function never logs or returns secrets, raw payloads, or stack traces.
    The original exception is preserved as `__cause__` for internal debugging.
    """
    if isinstance(exc, MuleGuardError):
        return exc

    translated: MuleGuardError

    # ------------------------------------------------------------------
    # Pydantic/FastAPI validation errors
    # ------------------------------------------------------------------
    if _PYDANTIC_VALIDATION_EXCEPTIONS and isinstance(exc, _PYDANTIC_VALIDATION_EXCEPTIONS):
        errors = getattr(exc, "errors", None)

        if callable(errors):
            fields = _pydantic_fields_from_errors(errors())
        else:
            fields = []

        translated = MuleGuardValidationError(
            message="Request validation failed.",
            details={"fields": fields},
        )
        translated.__cause__ = exc
        return translated

    # ------------------------------------------------------------------
    # HTTP exceptions
    # ------------------------------------------------------------------
    if _HTTP_EXCEPTIONS and isinstance(exc, _HTTP_EXCEPTIONS):
        status_code = int(getattr(exc, "status_code", 500))
        exception_class, code, message = _http_status_mapping(status_code)

        if exception_class is RateLimitError:
            translated = RateLimitError(message=message, code=code)
        else:
            translated = exception_class(message=message, code=code)

        translated.__cause__ = exc
        return translated

    # ------------------------------------------------------------------
    # SQLAlchemy errors
    # ------------------------------------------------------------------
    if _SQLALCHEMY_EXCEPTIONS and isinstance(exc, _SQLALCHEMY_EXCEPTIONS):
        state = _sql_state(exc)

        if state in _SQL_STATEMENT_TIMEOUT_CODES or state in _SQL_LOCK_TIMEOUT_CODES:
            translated = DatabaseTimeoutError(
                message="Database operation timed out.",
                code=ErrorCode.DATABASE_TIMEOUT,
            )
        elif (
            state is not None
            and state.startswith(_SQL_CONNECTION_ERROR_PREFIXES)
        ):
            translated = DatabaseUnavailableError(
                message="Database is temporarily unavailable.",
                code=ErrorCode.DATABASE_UNAVAILABLE,
            )
        elif _SQLALCHEMY_INTEGRITY_EXCEPTIONS and isinstance(
            exc,
            _SQLALCHEMY_INTEGRITY_EXCEPTIONS,
        ):
            translated = ConflictError(
                message="Resource conflict.",
                code=ErrorCode.CONFLICT,
            )
        elif _SQLALCHEMY_OPERATIONAL_EXCEPTIONS and isinstance(
            exc,
            _SQLALCHEMY_OPERATIONAL_EXCEPTIONS,
        ):
            translated = DatabaseUnavailableError(
                message="Database is temporarily unavailable.",
                code=ErrorCode.DATABASE_UNAVAILABLE,
            )
        else:
            translated = DatabaseError(
                message="Database error.",
                code=ErrorCode.DATABASE_ERROR,
            )

        translated.__cause__ = exc
        return translated

    # ------------------------------------------------------------------
    # Built-in timeout errors
    # ------------------------------------------------------------------
    if isinstance(exc, TimeoutError):
        translated = OperationTimeoutError(
            message="Operation timed out.",
            code=ErrorCode.OPERATION_TIMEOUT,
        )
        translated.__cause__ = exc
        return translated

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------
    translated = InternalError(
        message="Internal server error.",
        code=ErrorCode.INTERNAL_ERROR,
    )
    translated.__cause__ = exc
    return translated


# -----------------------------------------------------------------------------
# Classification
# -----------------------------------------------------------------------------


def classify_exception(exc: BaseException) -> ErrorClassification:
    """
    Classify an exception into safe operational metadata.
    """
    domain_exc = exc if isinstance(exc, MuleGuardError) else translate_exception(exc)

    if not isinstance(domain_exc, MuleGuardError):
        domain_exc = InternalError()

    category = domain_exc.category
    status_code = int(domain_exc.status_code)
    retryable = bool(domain_exc.retryable)
    transient = is_transient_error(domain_exc)
    failure_class = _failure_class_from_category(category)
    severity = _severity_from_status_and_class(status_code, failure_class)

    return ErrorClassification(
        code=domain_exc.code,
        message=domain_exc.message,
        category=category,
        status_code=status_code,
        retryable=retryable,
        transient=transient,
        failure_class=failure_class,
        severity=severity,
        exception_type=type(exc).__name__,
    )


def is_client_error_exc(exc: BaseException) -> bool:
    """
    Return True when an exception represents a client/input/policy failure.
    """
    if isinstance(exc, MuleGuardError):
        return is_client_error(exc)

    return 400 <= classify_exception(exc).status_code < 500


def is_server_error_exc(exc: BaseException) -> bool:
    """
    Return True when an exception represents a backend/infrastructure failure.
    """
    if isinstance(exc, MuleGuardError):
        return is_server_error(exc)

    return classify_exception(exc).status_code >= 500


def is_retryable(exc: BaseException) -> bool:
    """
    Return True when an exception is explicitly retryable.
    """
    if isinstance(exc, MuleGuardError):
        return is_retryable_error(exc)

    classification = classify_exception(exc)
    return classification.retryable or classification.transient


def is_transient_error(exc: BaseException) -> bool:
    """
    Return True when an error appears transient and may succeed on retry.
    """
    if isinstance(exc, MuleGuardError):
        if exc.retryable:
            return True

        if exc.category == ErrorCategory.DATABASE:
            cause = exc.__cause__

            if cause is not None:
                return is_transient_database_error(cause)

        return False

    if _SQLALCHEMY_EXCEPTIONS and isinstance(exc, _SQLALCHEMY_EXCEPTIONS):
        return is_transient_database_error(exc)

    if isinstance(exc, TimeoutError):
        return True

    if isinstance(exc, ConnectionError):
        return True

    return False


def is_transient_database_error(exc: BaseException) -> bool:
    """
    Best-effort detection of transient database errors.
    """
    if not _SQLALCHEMY_EXCEPTIONS or not isinstance(exc, _SQLALCHEMY_EXCEPTIONS):
        return False

    state = _sql_state(exc)

    if state is None:
        if _SQLALCHEMY_OPERATIONAL_EXCEPTIONS and isinstance(
            exc,
            _SQLALCHEMY_OPERATIONAL_EXCEPTIONS,
        ):
            return True

        return False

    if state in _SQL_SERIALIZATION_ERROR_CODES:
        return True

    if state in _SQL_STATEMENT_TIMEOUT_CODES:
        return True

    if state in _SQL_LOCK_TIMEOUT_CODES:
        return True

    return state.startswith(_SQL_CONNECTION_ERROR_PREFIXES)


# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------


def log_exception(
    log: logging.Logger,
    exc: BaseException,
    context: Optional[ErrorContext] = None,
    *,
    exc_info: bool = False,
) -> None:
    """
    Log an exception safely.

    Client errors are logged at warning/info level without stack traces by
    default. Server errors are logged at error level and may include stack
    traces when `exc_info=True`.
    """
    classification = classify_exception(exc)

    message = (
        "operation=%s code=%s category=%s status=%s failure_class=%s "
        "retryable=%s transient=%s request_id=%s actor_id=%s resource_type=%s "
        "resource_id=%s exception_type=%s"
    )

    args = (
        _clean_text(context.operation if context else "", 200) or "-",
        classification.code,
        classification.category,
        classification.status_code,
        classification.failure_class.value,
        classification.retryable,
        classification.transient,
        _clean_text(context.request_id if context else None, 128) or "-",
        _clean_text(context.actor_id if context else None, 128) or "-",
        _clean_text(context.resource_type if context else None, 100) or "-",
        _clean_text(context.resource_id if context else None, 128) or "-",
        classification.exception_type,
    )

    if classification.severity == ErrorSeverity.ERROR:
        log.error(message, *args, exc_info=exc_info)
    elif classification.severity == ErrorSeverity.WARNING:
        log.warning(message, *args)
    elif classification.severity == ErrorSeverity.INFO:
        log.info(message, *args)
    else:
        log.debug(message, *args)


# -----------------------------------------------------------------------------
# Batch error collection
# -----------------------------------------------------------------------------


class BatchErrorCollector:
    """
    Bounded collector for row-level and operation-level errors.

    This is useful for ingestion, bulk updates, validation passes, and batch
    analysis preflight. It intentionally does not store raw payloads, secrets,
    tokens, passwords, or full sensitive narratives.
    """

    def __init__(self, *, max_errors: int = MAX_BATCH_ERRORS) -> None:
        self.max_errors = max(1, int(max_errors))
        self._errors: list[dict[str, Any]] = []
        self._rows: set[int] = set()
        self._truncated = False

    @property
    def errors(self) -> list[dict[str, Any]]:
        """
        Return a copy of collected errors.
        """
        return list(self._errors)

    @property
    def has_errors(self) -> bool:
        """
        Return True when any error has been collected.
        """
        return bool(self._errors) or self._truncated

    @property
    def truncated(self) -> bool:
        """
        Return True when errors were dropped because of the bounded limit.
        """
        return self._truncated

    @property
    def rejected_row_count(self) -> int:
        """
        Return the number of distinct rejected rows.
        """
        return len(self._rows)

    def _append(self, error: Mapping[str, Any]) -> None:
        """
        Append a sanitized error when capacity allows.
        """
        if len(self._errors) >= self.max_errors:
            if not self._truncated:
                self._errors.append({"_truncated": True})
                self._truncated = True
            return

        self._errors.append(sanitize_mapping(error))

    def add(
        self,
        message: str,
        *,
        row: Optional[int] = None,
        field: Optional[str] = None,
        code: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Add one safe error entry.
        """
        entry: dict[str, Any] = {
            "message": _clean_text(message, 300),
        }

        if row is not None:
            entry["row"] = int(row)
            self._rows.add(int(row))

        if field:
            entry["field"] = _clean_text(field, 200)

        if code:
            entry["code"] = _clean_text(code, 100)

        if details:
            entry["details"] = sanitize_mapping(details)

        self._append(entry)

    def add_row_error(
        self,
        row: int,
        code: str,
        message: str,
        *,
        field: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Add one row-level error.
        """
        self.add(
            message,
            row=row,
            field=field,
            code=code,
            details=details,
        )

    def add_from_exception(
        self,
        exc: BaseException,
        *,
        row: Optional[int] = None,
    ) -> None:
        """
        Add errors from an exception.

        Pydantic-style validation errors are expanded into field errors. Other
        exceptions are translated and recorded as one safe error entry.
        """
        if _PYDANTIC_VALIDATION_EXCEPTIONS and isinstance(exc, _PYDANTIC_VALIDATION_EXCEPTIONS):
            errors = getattr(exc, "errors", None)

            if callable(errors):
                for field_error in errors():
                    loc = field_error.get("loc") or ()
                    field_parts: list[str] = []

                    if isinstance(loc, Sequence) and not isinstance(loc, (str, bytes, bytearray)):
                        iterable = loc
                    else:
                        iterable = (loc,)

                    for part in iterable:
                        text = str(part).strip()

                        if not text or text == "body":
                            continue

                        if _is_sensitive_key(text):
                            field_parts.append("***")
                        else:
                            field_parts.append(_clean_text(text, 200))

                    field_name = ".".join(field_parts) or None
                    message = _clean_text(
                        field_error.get("msg") or "Invalid or missing value.",
                        300,
                    )

                    if field_name and _is_sensitive_key(field_name):
                        message = "Invalid or missing value."

                    self.add(
                        message,
                        row=row,
                        field=field_name,
                        code=_clean_text(field_error.get("type") or "value_error", 100),
                    )

                return

        domain_exc = translate_exception(exc)

        self.add(
            domain_exc.message,
            row=row,
            code=domain_exc.code,
            details=domain_exc.details,
        )

    def to_details(self) -> dict[str, Any]:
        """
        Return safe collector details.
        """
        return {
            "errors": list(self._errors),
            "rejected_rows": self.rejected_row_count,
            "truncated": self._truncated,
        }

    def raise_if_errors(
        self,
        message: str = "Batch validation failed.",
    ) -> None:
        """
        Raise a MULEGUARD validation error when any errors were collected.
        """
        if not self.has_errors:
            return

        raise MuleGuardValidationError(
            message=message,
            details=self.to_details(),
        )


# -----------------------------------------------------------------------------
# Convenience helpers
# -----------------------------------------------------------------------------


def field_error(
    field_name: str,
    error_type: str,
    message: str,
) -> dict[str, str]:
    """
    Build one safe field-error mapping.
    """
    return {
        "field": _clean_text(field_name, 200),
        "type": _clean_text(error_type, 100),
        "message": _clean_text(message, 300),
    }


def validation_error_from_fields(
    fields: Sequence[Mapping[str, Any]],
    message: str = "Request validation failed.",
) -> MuleGuardValidationError:
    """
    Build a MULEGUARD validation error from safe field errors.
    """
    return MuleGuardValidationError.from_field_errors(fields, message=message)


def database_unavailable_error(
    message: str = "Database is temporarily unavailable.",
) -> DatabaseUnavailableError:
    """
    Build a safe database-unavailable error.
    """
    return DatabaseUnavailableError(message=message)


def database_timeout_error(
    message: str = "Database operation timed out.",
) -> DatabaseTimeoutError:
    """
    Build a safe database-timeout error.
    """
    return DatabaseTimeoutError(message=message)


def database_operation_error(
    message: str = "Database operation failed.",
) -> DatabaseOperationError:
    """
    Build a safe database-operation error.
    """
    return DatabaseOperationError(message=message)


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "BatchErrorCollector",
    "BatchRowError",
    "ErrorClassification",
    "ErrorContext",
    "ErrorSeverity",
    "FailureClass",
    "classify_exception",
    "context_from_request",
    "database_operation_error",
    "database_timeout_error",
    "database_unavailable_error",
    "field_error",
    "is_client_error_exc",
    "is_retryable",
    "is_server_error_exc",
    "is_transient_database_error",
    "is_transient_error",
    "log_exception",
    "safe_error_message",
    "safe_error_payload",
    "sanitize_mapping",
    "sanitize_value",
    "translate_exception",
    "validation_error_from_fields",
]