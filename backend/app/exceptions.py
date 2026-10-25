"""
MULEGUARD backend exception taxonomy.

This module defines the canonical error vocabulary used by services, API
handlers, middleware, ingestion pipelines, ML services, graph services, case
workflows, report generation, and audit systems.

Design goals:

- Provide stable, machine-readable error codes.
- Provide human-readable but non-sensitive error messages.
- Map domain failures to appropriate HTTP status codes.
- Preserve safe structured details without leaking secrets, tokens, passwords,
  raw complaint narratives, database URLs, stack traces, or real customer data.
- Support a consistent API error payload:

    {
      "code": "MULEGUARD_VALIDATION_ERROR",
      "message": "Request validation failed.",
      "category": "validation",
      "retryable": false,
      "details": {},
      "request_id": "..."
    }

- Make unexpected server failures distinguishable from client/input errors.
- Encode MULEGUARD safety boundaries as explicit exceptions where useful:
  synthetic-first data, no automatic adverse action, bounded graph queries,
  leakage control, temporal correctness, evidence integrity, and auditability.

Important:

- This module is intentionally dependency-light and uses only the Python
  standard library.
- Exception handlers in `app/api/error_handlers.py` should convert these
  exceptions into FastAPI/JSON responses.
- Never place passwords, bearer tokens, secrets, raw complaint narratives,
  database credentials, or real customer data in `details`.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from typing import Any, Final, Optional, Self
from uuid import UUID


# -----------------------------------------------------------------------------
# Safe detail sanitization limits
# -----------------------------------------------------------------------------

MAX_DETAIL_STRING_LENGTH: Final[int] = 512
MAX_DETAIL_SEQUENCE_LENGTH: Final[int] = 50
MAX_DETAIL_MAPPING_KEYS: Final[int] = 50
MAX_DETAIL_DEPTH: Final[int] = 8


# -----------------------------------------------------------------------------
# Sensitive key detection
# -----------------------------------------------------------------------------
# These lists are intentionally conservative. The goal is to prevent accidental
# leakage of credentials, tokens, raw narratives, payment secrets, and request
# payloads into API error details or logs.

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


def _is_sensitive_key(key: str) -> bool:
    """
    Return True when a detail key appears sensitive and should be omitted.
    """
    lowered = key.strip().lower()

    if lowered in SENSITIVE_DETAIL_KEYS:
        return True

    return any(token in lowered for token in SENSITIVE_KEY_TOKENS)


def _truncate_string(value: str) -> str:
    """
    Truncate long strings safely.
    """
    if len(value) <= MAX_DETAIL_STRING_LENGTH:
        return value

    return value[:MAX_DETAIL_STRING_LENGTH] + "...[truncated]"


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    """
    Convert an arbitrary value into a JSON-safe, non-sensitive detail value.

    This function intentionally avoids calling `repr()` on arbitrary objects
    because object representations may leak secrets or internal state.
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

    # Unknown object types are reduced to their class name only.
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


# -----------------------------------------------------------------------------
# Error categories
# -----------------------------------------------------------------------------


class ErrorCategory:
    """
    Stable high-level error categories.

    Categories are useful for dashboards, alerting, and client-side handling.
    They are not a substitute for precise error codes.
    """

    INTERNAL: Final[str] = "internal"
    CONFIGURATION: Final[str] = "configuration"
    DATABASE: Final[str] = "database"
    CLIENT: Final[str] = "client"
    VALIDATION: Final[str] = "validation"
    AUTHENTICATION: Final[str] = "authentication"
    AUTHORIZATION: Final[str] = "authorization"
    POLICY: Final[str] = "policy"
    INGESTION: Final[str] = "ingestion"
    FEATURE: Final[str] = "feature"
    RULE: Final[str] = "rule"
    RISK: Final[str] = "risk"
    GRAPH: Final[str] = "graph"
    ML: Final[str] = "ml"
    COMPLAINT: Final[str] = "complaint"
    CASE: Final[str] = "case"
    EVIDENCE: Final[str] = "evidence"
    REPORT: Final[str] = "report"
    AUDIT: Final[str] = "audit"
    ANALYSIS: Final[str] = "analysis"


# -----------------------------------------------------------------------------
# Error codes
# -----------------------------------------------------------------------------


class ErrorCode:
    """
    Stable machine-readable error codes.

    Naming convention:

        MULEGUARD_<AREA>_<CONDITION>

    Codes should be treated as public API contract. Prefer adding new codes
    over changing the meaning of existing codes.
    """

    INTERNAL_ERROR: Final[str] = "MULEGUARD_INTERNAL_ERROR"
    CONFIGURATION_ERROR: Final[str] = "MULEGUARD_CONFIGURATION_ERROR"
    SERVICE_UNAVAILABLE: Final[str] = "MULEGUARD_SERVICE_UNAVAILABLE"
    OPERATION_TIMEOUT: Final[str] = "MULEGUARD_OPERATION_TIMEOUT"
    UNSUPPORTED_ACTION: Final[str] = "MULEGUARD_UNSUPPORTED_ACTION"
    MAINTENANCE_MODE: Final[str] = "MULEGUARD_MAINTENANCE_MODE"

    DATABASE_ERROR: Final[str] = "MULEGUARD_DATABASE_ERROR"
    DATABASE_UNAVAILABLE: Final[str] = "MULEGUARD_DATABASE_UNAVAILABLE"
    DATABASE_TIMEOUT: Final[str] = "MULEGUARD_DATABASE_TIMEOUT"
    DATABASE_OPERATION_ERROR: Final[str] = "MULEGUARD_DATABASE_OPERATION_ERROR"

    INVALID_REQUEST: Final[str] = "MULEGUARD_INVALID_REQUEST"
    VALIDATION_ERROR: Final[str] = "MULEGUARD_VALIDATION_ERROR"
    PAYLOAD_TOO_LARGE: Final[str] = "MULEGUARD_PAYLOAD_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE: Final[str] = "MULEGUARD_UNSUPPORTED_MEDIA_TYPE"
    METHOD_NOT_ALLOWED: Final[str] = "MULEGUARD_METHOD_NOT_ALLOWED"
    REQUEST_TIMEOUT: Final[str] = "MULEGUARD_REQUEST_TIMEOUT"
    RATE_LIMITED: Final[str] = "MULEGUARD_RATE_LIMITED"
    CONFLICT: Final[str] = "MULEGUARD_CONFLICT"
    NOT_FOUND: Final[str] = "MULEGUARD_NOT_FOUND"
    GONE: Final[str] = "MULEGUARD_GONE"

    AUTHENTICATION_REQUIRED: Final[str] = "MULEGUARD_AUTHENTICATION_REQUIRED"
    INVALID_CREDENTIALS: Final[str] = "MULEGUARD_INVALID_CREDENTIALS"
    TOKEN_EXPIRED: Final[str] = "MULEGUARD_TOKEN_EXPIRED"
    TOKEN_INVALID: Final[str] = "MULEGUARD_TOKEN_INVALID"
    USER_INACTIVE: Final[str] = "MULEGUARD_USER_INACTIVE"
    USER_LOCKED: Final[str] = "MULEGUARD_USER_LOCKED"
    PERMISSION_DENIED: Final[str] = "MULEGUARD_PERMISSION_DENIED"

    POLICY_VIOLATION: Final[str] = "MULEGUARD_POLICY_VIOLATION"
    SYNTHETIC_DATA_REQUIRED: Final[str] = "MULEGUARD_SYNTHETIC_DATA_REQUIRED"
    REAL_DATA_PROHIBITED: Final[str] = "MULEGUARD_REAL_DATA_PROHIBITED"
    ADVERSE_ACTION_PROHIBITED: Final[str] = "MULEGUARD_ADVERSE_ACTION_PROHIBITED"
    AUTOMATIC_ENFORCEMENT_PROHIBITED: Final[str] = "MULEGUARD_AUTOMATIC_ENFORCEMENT_PROHIBITED"
    UNBOUNDED_GRAPH_QUERY_PROHIBITED: Final[str] = "MULEGUARD_UNBOUNDED_GRAPH_QUERY_PROHIBITED"
    LABEL_LEAKAGE_DETECTED: Final[str] = "MULEGUARD_LABEL_LEAKAGE_DETECTED"
    TEMPORAL_CORRECTNESS_VIOLATION: Final[str] = "MULEGUARD_TEMPORAL_CORRECTNESS_VIOLATION"
    FAKE_FUNCTIONALITY_PROHIBITED: Final[str] = "MULEGUARD_FAKE_FUNCTIONALITY_PROHIBITED"
    FEATURE_FLAG_DISABLED: Final[str] = "MULEGUARD_FEATURE_FLAG_DISABLED"

    INGESTION_ERROR: Final[str] = "MULEGUARD_INGESTION_ERROR"
    INGESTION_VALIDATION_ERROR: Final[str] = "MULEGUARD_INGESTION_VALIDATION_ERROR"
    INGESTION_DUPLICATE: Final[str] = "MULEGUARD_INGESTION_DUPLICATE"
    INGESTION_REFERENTIAL_INTEGRITY: Final[str] = "MULEGUARD_INGESTION_REFERENTIAL_INTEGRITY"
    INGESTION_BATCH_LIMIT: Final[str] = "MULEGUARD_INGESTION_BATCH_LIMIT"

    FEATURE_COMPUTATION_ERROR: Final[str] = "MULEGUARD_FEATURE_COMPUTATION_ERROR"
    FEATURE_SCHEMA_ERROR: Final[str] = "MULEGUARD_FEATURE_SCHEMA_ERROR"
    RULE_CONFIGURATION_ERROR: Final[str] = "MULEGUARD_RULE_CONFIGURATION_ERROR"
    RISK_FUSION_ERROR: Final[str] = "MULEGUARD_RISK_FUSION_ERROR"

    GRAPH_ERROR: Final[str] = "MULEGUARD_GRAPH_ERROR"
    GRAPH_PARAMETER_ERROR: Final[str] = "MULEGUARD_GRAPH_PARAMETER_ERROR"
    GRAPH_LIMIT_EXCEEDED: Final[str] = "MULEGUARD_GRAPH_LIMIT_EXCEEDED"
    GRAPH_TIMEOUT: Final[str] = "MULEGUARD_GRAPH_TIMEOUT"
    GRAPH_CONSTRUCTION_ERROR: Final[str] = "MULEGUARD_GRAPH_CONSTRUCTION_ERROR"
    MONEY_TRAIL_CONSTRAINT_ERROR: Final[str] = "MULEGUARD_MONEY_TRAIL_CONSTRAINT_ERROR"
    CYCLE_NOT_ALLOWED: Final[str] = "MULEGUARD_CYCLE_NOT_ALLOWED"

    ML_ERROR: Final[str] = "MULEGUARD_ML_ERROR"
    MODEL_NOT_AVAILABLE: Final[str] = "MULEGUARD_MODEL_NOT_AVAILABLE"
    MODEL_ARTIFACT_MISSING: Final[str] = "MULEGUARD_MODEL_ARTIFACT_MISSING"
    MODEL_ARTIFACT_CORRUPT: Final[str] = "MULEGUARD_MODEL_ARTIFACT_CORRUPT"
    MODEL_FEATURE_SCHEMA_MISMATCH: Final[str] = "MULEGUARD_MODEL_FEATURE_SCHEMA_MISMATCH"
    MODEL_INFERENCE_ERROR: Final[str] = "MULEGUARD_MODEL_INFERENCE_ERROR"
    MODEL_EVALUATION_ERROR: Final[str] = "MULEGUARD_MODEL_EVALUATION_ERROR"
    EXPLAINABILITY_ERROR: Final[str] = "MULEGUARD_EXPLAINABILITY_ERROR"

    COMPLAINT_ERROR: Final[str] = "MULEGUARD_COMPLAINT_ERROR"
    COMPLAINT_REFERENCE_COLLISION: Final[str] = "MULEGUARD_COMPLAINT_REFERENCE_COLLISION"
    COMPLAINT_NORMALIZATION_AMBIGUITY: Final[str] = "MULEGUARD_COMPLAINT_NORMALIZATION_AMBIGUITY"

    CASE_ERROR: Final[str] = "MULEGUARD_CASE_ERROR"
    CASE_INVALID_TRANSITION: Final[str] = "MULEGUARD_CASE_INVALID_TRANSITION"
    CASE_CLOSED: Final[str] = "MULEGUARD_CASE_CLOSED"
    EVIDENCE_ERROR: Final[str] = "MULEGUARD_EVIDENCE_ERROR"
    EVIDENCE_VALIDATION_ERROR: Final[str] = "MULEGUARD_EVIDENCE_VALIDATION_ERROR"
    EVIDENCE_NOT_FOUND: Final[str] = "MULEGUARD_EVIDENCE_NOT_FOUND"
    EVIDENCE_EXTERNAL_URL_PROHIBITED: Final[str] = "MULEGUARD_EVIDENCE_EXTERNAL_URL_PROHIBITED"

    REPORT_ERROR: Final[str] = "MULEGUARD_REPORT_ERROR"
    REPORT_GENERATION_ERROR: Final[str] = "MULEGUARD_REPORT_GENERATION_ERROR"
    REPORT_TIMEOUT: Final[str] = "MULEGUARD_REPORT_TIMEOUT"
    REPORT_NOT_FOUND: Final[str] = "MULEGUARD_REPORT_NOT_FOUND"
    REPORT_EXPIRED: Final[str] = "MULEGUARD_REPORT_EXPIRED"

    AUDIT_ERROR: Final[str] = "MULEGUARD_AUDIT_ERROR"
    AUDIT_INTEGRITY_ERROR: Final[str] = "MULEGUARD_AUDIT_INTEGRITY_ERROR"

    ANALYSIS_RUN_ERROR: Final[str] = "MULEGUARD_ANALYSIS_RUN_ERROR"
    ANALYSIS_RUN_CONFLICT: Final[str] = "MULEGUARD_ANALYSIS_RUN_CONFLICT"
    IDEMPOTENCY_CONFLICT: Final[str] = "MULEGUARD_IDEMPOTENCY_CONFLICT"


# -----------------------------------------------------------------------------
# Base exception
# -----------------------------------------------------------------------------


class MuleGuardError(Exception):
    """
    Base class for all MULEGUARD domain and API exceptions.

    Subclasses should define:

    - `default_code`
    - `default_message`
    - `status_code`
    - `category`
    - `retryable` when appropriate

    Instances may carry sanitized structured `details` and optional HTTP
    `headers`.
    """

    default_code: str = ErrorCode.INTERNAL_ERROR
    default_message: str = "Internal server error."
    status_code: int = 500
    category: str = ErrorCategory.INTERNAL
    retryable: bool = False

    def __init__(
        self,
        message: Optional[str] = None,
        *,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        category: Optional[str] = None,
        details: Optional[Mapping[Any, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        retryable: Optional[bool] = None,
    ) -> None:
        cls = type(self)

        self.code: str = code or cls.default_code
        self.message: str = message or cls.default_message
        self.status_code: int = status_code if status_code is not None else cls.status_code
        self.category: str = category or cls.category
        self.retryable: bool = cls.retryable if retryable is None else bool(retryable)
        self.details: dict[str, Any] = _sanitize_mapping(details) if isinstance(details, Mapping) else {}
        self.headers: dict[str, str] = dict(headers) if isinstance(headers, Mapping) else {}

        if not isinstance(self.status_code, int) or not (100 <= self.status_code <= 599):
            raise ValueError("HTTP status_code must be an integer between 100 and 599.")

        super().__init__(self.message)

    def add_detail(self, key: str, value: Any) -> Self:
        """
        Add a sanitized detail field and return self for chaining.
        """
        if _is_sensitive_key(key):
            return self

        self.details[key] = _sanitize_value(value, depth=0)
        return self

    def set_header(self, key: str, value: str) -> Self:
        """
        Set an HTTP response header hint.
        """
        self.headers[key] = value
        return self

    def http_headers(self) -> dict[str, str]:
        """
        Return a copy of headers that handlers may include in responses.
        """
        return dict(self.headers)

    def to_payload(self, request_id: Optional[str] = None) -> dict[str, Any]:
        """
        Return a stable JSON-serializable error payload.

        The payload intentionally avoids stack traces, exception class names,
        database URLs, secrets, tokens, and raw sensitive narratives.
        """
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "category": self.category,
            "retryable": self.retryable,
        }

        if self.details:
            payload["details"] = self.details

        if request_id:
            payload["request_id"] = str(request_id)

        return payload

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"code={self.code!r}, "
            f"status_code={self.status_code!r}, "
            f"category={self.category!r})"
        )


# -----------------------------------------------------------------------------
# Broad client/server bases
# -----------------------------------------------------------------------------


class ClientError(MuleGuardError):
    """
    Base class for errors caused by request input, policy, or client state.
    """

    status_code = 400
    category = ErrorCategory.CLIENT


class ServerError(MuleGuardError):
    """
    Base class for unexpected backend, infrastructure, or invariant failures.
    """

    status_code = 500
    category = ErrorCategory.INTERNAL


# -----------------------------------------------------------------------------
# Generic HTTP-like errors
# -----------------------------------------------------------------------------


class InvalidRequestError(ClientError):
    default_code = ErrorCode.INVALID_REQUEST
    default_message = "Invalid request."
    status_code = 400
    category = ErrorCategory.CLIENT


class ValidationError(ClientError):
    default_code = ErrorCode.VALIDATION_ERROR
    default_message = "Request validation failed."
    status_code = 422
    category = ErrorCategory.VALIDATION

    @classmethod
    def from_field_errors(
        cls,
        field_errors: Sequence[Mapping[str, Any]],
        *,
        message: Optional[str] = None,
    ) -> Self:
        """
        Build a validation error from structured field errors.

        Expected input items may contain keys such as:

        - field
        - location
        - type
        - msg
        - message
        - code

        Only allowlisted keys are preserved.
        """
        errors: list[dict[str, Any]] = []
        limited = list(field_errors)[:MAX_DETAIL_SEQUENCE_LENGTH]

        allowed_keys = ("field", "location", "type", "msg", "message", "code")

        for raw_error in limited:
            safe_error: dict[str, Any] = {}

            for key in allowed_keys:
                if key in raw_error:
                    safe_error[key] = raw_error[key]

            if safe_error:
                errors.append(safe_error)

        if len(field_errors) > MAX_DETAIL_SEQUENCE_LENGTH:
            errors.append({"_truncated": True})

        return cls(
            message=message or cls.default_message,
            details={"fields": errors},
        )


class PayloadTooLargeError(ClientError):
    default_code = ErrorCode.PAYLOAD_TOO_LARGE
    default_message = "Request payload is too large."
    status_code = 413
    category = ErrorCategory.CLIENT


class UnsupportedMediaTypeError(ClientError):
    default_code = ErrorCode.UNSUPPORTED_MEDIA_TYPE
    default_message = "Unsupported media type."
    status_code = 415
    category = ErrorCategory.CLIENT


class MethodNotAllowedError(ClientError):
    default_code = ErrorCode.METHOD_NOT_ALLOWED
    default_message = "Method not allowed."
    status_code = 405
    category = ErrorCategory.CLIENT


class RequestTimeoutError(ClientError):
    default_code = ErrorCode.REQUEST_TIMEOUT
    default_message = "Request timed out."
    status_code = 408
    category = ErrorCategory.CLIENT
    retryable = True


class ConflictError(ClientError):
    default_code = ErrorCode.CONFLICT
    default_message = "Resource conflict."
    status_code = 409
    category = ErrorCategory.CLIENT


class NotFoundError(ClientError):
    default_code = ErrorCode.NOT_FOUND
    default_message = "Resource not found."
    status_code = 404
    category = ErrorCategory.CLIENT

    @classmethod
    def resource(
        cls,
        resource_type: str,
        resource_id: Optional[str] = None,
        *,
        message: Optional[str] = None,
    ) -> Self:
        """
        Build a not-found error for a specific resource type and optional ID.
        """
        details: dict[str, Any] = {"resource_type": str(resource_type)}

        if resource_id is not None:
            details["resource_id"] = str(resource_id)

        return cls(
            message=message or f"{resource_type} not found.",
            details=details,
        )


class GoneError(ClientError):
    default_code = ErrorCode.GONE
    default_message = "Resource is no longer available."
    status_code = 410
    category = ErrorCategory.CLIENT


class RateLimitError(ClientError):
    default_code = ErrorCode.RATE_LIMITED
    default_message = "Too many requests."
    status_code = 429
    category = ErrorCategory.CLIENT
    retryable = True

    def __init__(
        self,
        message: Optional[str] = None,
        *,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        category: Optional[str] = None,
        details: Optional[Mapping[Any, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        retryable: Optional[bool] = None,
        retry_after_seconds: int = 60,
    ) -> None:
        retry_after = max(0, int(retry_after_seconds))

        merged_headers: dict[str, str] = {"Retry-After": str(retry_after)}
        if isinstance(headers, Mapping):
            merged_headers.update({str(k): str(v) for k, v in headers.items()})

        merged_details: dict[Any, Any] = dict(details) if isinstance(details, Mapping) else {}
        merged_details.setdefault("retry_after_seconds", retry_after)

        super().__init__(
            message=message,
            code=code,
            status_code=status_code,
            category=category,
            details=merged_details,
            headers=merged_headers,
            retryable=retryable,
        )


class IdempotencyConflictError(ConflictError):
    default_code = ErrorCode.IDEMPOTENCY_CONFLICT
    default_message = "Idempotency key conflict."
    category = ErrorCategory.CLIENT


# -----------------------------------------------------------------------------
# Authentication and authorization
# -----------------------------------------------------------------------------


class AuthenticationError(ClientError):
    default_code = ErrorCode.AUTHENTICATION_REQUIRED
    default_message = "Authentication required."
    status_code = 401
    category = ErrorCategory.AUTHENTICATION

    def __init__(
        self,
        message: Optional[str] = None,
        *,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        category: Optional[str] = None,
        details: Optional[Mapping[Any, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        retryable: Optional[bool] = None,
    ) -> None:
        merged_headers: dict[str, str] = {"WWW-Authenticate": "Bearer"}
        if isinstance(headers, Mapping):
            merged_headers.update({str(k): str(v) for k, v in headers.items()})

        super().__init__(
            message=message,
            code=code,
            status_code=status_code,
            category=category,
            details=details,
            headers=merged_headers,
            retryable=retryable,
        )


class InvalidCredentialsError(AuthenticationError):
    """
    Generic invalid-credentials error.

    The message must not reveal whether a username or password individually
    failed when doing so is unnecessary.
    """

    default_code = ErrorCode.INVALID_CREDENTIALS
    default_message = "Invalid username or password."


class TokenExpiredError(AuthenticationError):
    default_code = ErrorCode.TOKEN_EXPIRED
    default_message = "Authentication token has expired."


class TokenInvalidError(AuthenticationError):
    default_code = ErrorCode.TOKEN_INVALID
    default_message = "Authentication token is invalid."


class UserInactiveError(AuthenticationError):
    default_code = ErrorCode.USER_INACTIVE
    default_message = "User account is inactive."
    status_code = 403
    category = ErrorCategory.AUTHORIZATION


class UserLockedError(ClientError):
    default_code = ErrorCode.USER_LOCKED
    default_message = "User account is temporarily locked."
    status_code = 423
    category = ErrorCategory.AUTHENTICATION
    retryable = True


class PermissionDeniedError(ClientError):
    default_code = ErrorCode.PERMISSION_DENIED
    default_message = "Insufficient permissions for this action."
    status_code = 403
    category = ErrorCategory.AUTHORIZATION


# -----------------------------------------------------------------------------
# Infrastructure and service errors
# -----------------------------------------------------------------------------


class InternalError(ServerError):
    default_code = ErrorCode.INTERNAL_ERROR
    default_message = "Internal server error."
    status_code = 500
    category = ErrorCategory.INTERNAL


class ConfigurationError(ServerError):
    default_code = ErrorCode.CONFIGURATION_ERROR
    default_message = "Server configuration error."
    status_code = 500
    category = ErrorCategory.CONFIGURATION


class ServiceUnavailableError(ServerError):
    default_code = ErrorCode.SERVICE_UNAVAILABLE
    default_message = "Service temporarily unavailable."
    status_code = 503
    category = ErrorCategory.INTERNAL
    retryable = True


class OperationTimeoutError(ServerError):
    default_code = ErrorCode.OPERATION_TIMEOUT
    default_message = "Operation timed out."
    status_code = 504
    category = ErrorCategory.INTERNAL
    retryable = True


class UnsupportedActionError(ServerError):
    default_code = ErrorCode.UNSUPPORTED_ACTION
    default_message = "Requested action is not supported."
    status_code = 501
    category = ErrorCategory.INTERNAL


class MaintenanceModeError(ServiceUnavailableError):
    default_code = ErrorCode.MAINTENANCE_MODE
    default_message = "Service is temporarily unavailable for maintenance."


class DatabaseError(ServerError):
    default_code = ErrorCode.DATABASE_ERROR
    default_message = "Database error."
    status_code = 500
    category = ErrorCategory.DATABASE


class DatabaseUnavailableError(DatabaseError, ServiceUnavailableError):
    default_code = ErrorCode.DATABASE_UNAVAILABLE
    default_message = "Database is temporarily unavailable."
    status_code = 503
    category = ErrorCategory.DATABASE
    retryable = True


class DatabaseTimeoutError(DatabaseError, OperationTimeoutError):
    default_code = ErrorCode.DATABASE_TIMEOUT
    default_message = "Database operation timed out."
    status_code = 504
    category = ErrorCategory.DATABASE
    retryable = True


class DatabaseOperationError(DatabaseError, InternalError):
    default_code = ErrorCode.DATABASE_OPERATION_ERROR
    default_message = "Database operation failed."
    status_code = 500
    category = ErrorCategory.DATABASE


# -----------------------------------------------------------------------------
# MULEGUARD safety and product-policy errors
# -----------------------------------------------------------------------------


class PolicyViolationError(ClientError):
    default_code = ErrorCode.POLICY_VIOLATION
    default_message = "Request violates MULEGUARD safety policy."
    status_code = 422
    category = ErrorCategory.POLICY


class SyntheticDataRequiredError(PolicyViolationError):
    default_code = ErrorCode.SYNTHETIC_DATA_REQUIRED
    default_message = "MULEGUARD requires synthetic data for this operation."


class RealDataProhibitedError(PolicyViolationError):
    default_code = ErrorCode.REAL_DATA_PROHIBITED
    default_message = "Real customer data is prohibited in this prototype mode."


class AdverseActionProhibitedError(PermissionDeniedError):
    default_code = ErrorCode.ADVERSE_ACTION_PROHIBITED
    default_message = (
        "Automatic adverse customer action is prohibited. "
        "MULEGUARD supports human investigation only."
    )


class AutomaticEnforcementProhibitedError(AdverseActionProhibitedError):
    default_code = ErrorCode.AUTOMATIC_ENFORCEMENT_PROHIBITED
    default_message = (
        "Automatic account freezing, payment blocking, blacklisting, "
        "or other enforcement action is prohibited."
    )


class UnboundedGraphQueryProhibitedError(PolicyViolationError):
    default_code = ErrorCode.UNBOUNDED_GRAPH_QUERY_PROHIBITED
    default_message = "Unbounded whole-bank graph queries are prohibited."


class LabelLeakageDetectedError(ServerError):
    default_code = ErrorCode.LABEL_LEAKAGE_DETECTED
    default_message = "Ground-truth label leakage was detected and blocked."
    status_code = 500
    category = ErrorCategory.ML


class TemporalCorrectnessViolationError(ServerError):
    default_code = ErrorCode.TEMPORAL_CORRECTNESS_VIOLATION
    default_message = "Point-in-time temporal correctness violation was detected."
    status_code = 500
    category = ErrorCategory.FEATURE


class FakeFunctionalityProhibitedError(ServerError):
    default_code = ErrorCode.FAKE_FUNCTIONALITY_PROHIBITED
    default_message = "Requested behaviour would violate the no-fake-functionality rule."
    status_code = 500
    category = ErrorCategory.INTERNAL


class FeatureFlagDisabledError(ClientError):
    default_code = ErrorCode.FEATURE_FLAG_DISABLED
    default_message = "Requested feature is disabled by configuration."
    status_code = 403
    category = ErrorCategory.POLICY


# -----------------------------------------------------------------------------
# Ingestion errors
# -----------------------------------------------------------------------------


class IngestionError(ClientError):
    default_code = ErrorCode.INGESTION_ERROR
    default_message = "Ingestion failed."
    status_code = 422
    category = ErrorCategory.INGESTION


class IngestionValidationError(IngestionError):
    default_code = ErrorCode.INGESTION_VALIDATION_ERROR
    default_message = "Ingestion payload validation failed."

    @classmethod
    def from_rows(
        cls,
        *,
        accepted: int = 0,
        rejected: int = 0,
        duplicated: int = 0,
        skipped: int = 0,
        row_errors: Optional[Sequence[Mapping[str, Any]]] = None,
        message: Optional[str] = None,
    ) -> Self:
        """
        Build an ingestion validation error with safe row-level summaries.

        Row errors should contain only non-sensitive fields such as row index,
        field name, code, and safe message.
        """
        details: dict[str, Any] = {
            "counts": {
                "accepted": int(accepted),
                "rejected": int(rejected),
                "duplicated": int(duplicated),
                "skipped": int(skipped),
            }
        }

        errors: list[dict[str, Any]] = []
        allowed_keys = ("row", "index", "field", "code", "message", "reason")

        if row_errors:
            limited = list(row_errors)[:MAX_DETAIL_SEQUENCE_LENGTH]

            for raw_error in limited:
                safe_error: dict[str, Any] = {}

                for key in allowed_keys:
                    if key in raw_error:
                        safe_error[key] = raw_error[key]

                if safe_error:
                    errors.append(safe_error)

            if len(row_errors) > MAX_DETAIL_SEQUENCE_LENGTH:
                errors.append({"_truncated": True})

        details["row_errors"] = errors

        return cls(
            message=message or cls.default_message,
            details=details,
        )


class IngestionDuplicateError(ConflictError):
    default_code = ErrorCode.INGESTION_DUPLICATE
    default_message = "Duplicate ingestion record detected."
    category = ErrorCategory.INGESTION


class IngestionReferentialIntegrityError(IngestionValidationError):
    default_code = ErrorCode.INGESTION_REFERENTIAL_INTEGRITY
    default_message = "Ingestion payload references missing or invalid records."


class IngestionBatchLimitError(PayloadTooLargeError):
    default_code = ErrorCode.INGESTION_BATCH_LIMIT
    default_message = "Ingestion batch exceeds configured limits."
    category = ErrorCategory.INGESTION


# -----------------------------------------------------------------------------
# Feature, rule, and risk errors
# -----------------------------------------------------------------------------


class FeatureComputationError(ServerError):
    default_code = ErrorCode.FEATURE_COMPUTATION_ERROR
    default_message = "Behavioural feature computation failed."
    status_code = 500
    category = ErrorCategory.FEATURE


class FeatureSchemaError(ServerError):
    default_code = ErrorCode.FEATURE_SCHEMA_ERROR
    default_message = "Feature schema validation failed."
    status_code = 500
    category = ErrorCategory.FEATURE


class RuleConfigurationError(ServerError):
    default_code = ErrorCode.RULE_CONFIGURATION_ERROR
    default_message = "Rule configuration is invalid."
    status_code = 500
    category = ErrorCategory.RULE


class RiskFusionError(ServerError):
    default_code = ErrorCode.RISK_FUSION_ERROR
    default_message = "Risk fusion failed."
    status_code = 500
    category = ErrorCategory.RISK


# -----------------------------------------------------------------------------
# Graph errors
# -----------------------------------------------------------------------------


class GraphError(ClientError):
    default_code = ErrorCode.GRAPH_ERROR
    default_message = "Graph query failed."
    status_code = 422
    category = ErrorCategory.GRAPH


class GraphParameterError(GraphError):
    default_code = ErrorCode.GRAPH_PARAMETER_ERROR
    default_message = "Invalid graph query parameter."


class GraphLimitExceededError(GraphError):
    default_code = ErrorCode.GRAPH_LIMIT_EXCEEDED
    default_message = "Graph query exceeded configured limits."

    @classmethod
    def limit(
        cls,
        limit_name: str,
        limit_value: Any,
        requested_value: Optional[Any] = None,
        *,
        message: Optional[str] = None,
    ) -> Self:
        """
        Build a graph limit error with safe limit metadata.
        """
        details: dict[str, Any] = {
            "limit_name": str(limit_name),
            "limit_value": limit_value,
        }

        if requested_value is not None:
            details["requested_value"] = requested_value

        return cls(
            message=message or cls.default_message,
            details=details,
        )


class GraphTimeoutError(GraphError, OperationTimeoutError):
    default_code = ErrorCode.GRAPH_TIMEOUT
    default_message = "Graph query timed out."
    status_code = 504
    category = ErrorCategory.GRAPH
    retryable = True


class GraphConstructionError(ServerError):
    default_code = ErrorCode.GRAPH_CONSTRUCTION_ERROR
    default_message = "Graph construction failed."
    status_code = 500
    category = ErrorCategory.GRAPH


class MoneyTrailConstraintError(GraphError):
    default_code = ErrorCode.MONEY_TRAIL_CONSTRAINT_ERROR
    default_message = "Candidate money trail violates temporal or amount constraints."


class CycleNotAllowedError(GraphError):
    default_code = ErrorCode.CYCLE_NOT_ALLOWED
    default_message = "Cycle prevention policy rejects this candidate path."


# -----------------------------------------------------------------------------
# ML errors
# -----------------------------------------------------------------------------


class MLError(ServerError):
    default_code = ErrorCode.ML_ERROR
    default_message = "Machine-learning operation failed."
    status_code = 500
    category = ErrorCategory.ML


class ModelNotAvailableError(ServiceUnavailableError):
    default_code = ErrorCode.MODEL_NOT_AVAILABLE
    default_message = "Trained model is not available."
    status_code = 503
    category = ErrorCategory.ML
    retryable = True


class ModelArtifactMissingError(ModelNotAvailableError):
    default_code = ErrorCode.MODEL_ARTIFACT_MISSING
    default_message = "Trained model artifact is missing."


class ModelArtifactCorruptError(MLError):
    default_code = ErrorCode.MODEL_ARTIFACT_CORRUPT
    default_message = "Trained model artifact is corrupt or unreadable."


class ModelFeatureSchemaMismatchError(MLError):
    default_code = ErrorCode.MODEL_FEATURE_SCHEMA_MISMATCH
    default_message = "Model feature schema mismatch detected."


class ModelInferenceError(MLError):
    default_code = ErrorCode.MODEL_INFERENCE_ERROR
    default_message = "Model inference failed."


class ModelEvaluationError(MLError):
    default_code = ErrorCode.MODEL_EVALUATION_ERROR
    default_message = "Model evaluation failed."


class ExplainabilityError(MLError):
    default_code = ErrorCode.EXPLAINABILITY_ERROR
    default_message = "Model explanation generation failed."


# -----------------------------------------------------------------------------
# Complaint correlation errors
# -----------------------------------------------------------------------------


class ComplaintError(ClientError):
    default_code = ErrorCode.COMPLAINT_ERROR
    default_message = "Complaint correlation operation failed."
    status_code = 422
    category = ErrorCategory.COMPLAINT


class ComplaintReferenceCollisionError(ConflictError):
    default_code = ErrorCode.COMPLAINT_REFERENCE_COLLISION
    default_message = "Complaint reference normalization collision detected."
    category = ErrorCategory.COMPLAINT


class ComplaintNormalizationAmbiguityError(ComplaintError):
    default_code = ErrorCode.COMPLAINT_NORMALIZATION_AMBIGUITY
    default_message = "Complaint identifier normalization is ambiguous."


# -----------------------------------------------------------------------------
# Case, evidence, and workflow errors
# -----------------------------------------------------------------------------


class CaseError(ClientError):
    default_code = ErrorCode.CASE_ERROR
    default_message = "Case operation failed."
    status_code = 422
    category = ErrorCategory.CASE


class InvalidCaseTransitionError(ConflictError):
    default_code = ErrorCode.CASE_INVALID_TRANSITION
    default_message = "Invalid case state transition."
    category = ErrorCategory.CASE

    @classmethod
    def transition(
        cls,
        from_status: str,
        to_status: str,
        allowed_statuses: Optional[Sequence[str]] = None,
        *,
        message: Optional[str] = None,
    ) -> Self:
        """
        Build an invalid case transition error.
        """
        details: dict[str, Any] = {
            "from_status": str(from_status),
            "to_status": str(to_status),
        }

        if allowed_statuses is not None:
            limited = [str(status) for status in list(allowed_statuses)[:MAX_DETAIL_SEQUENCE_LENGTH]]
            details["allowed_statuses"] = limited

            if len(allowed_statuses) > MAX_DETAIL_SEQUENCE_LENGTH:
                details["allowed_statuses_truncated"] = True

        return cls(
            message=message or cls.default_message,
            details=details,
        )


class CaseClosedError(ConflictError):
    default_code = ErrorCode.CASE_CLOSED
    default_message = "Case is closed and cannot be modified in this way."
    category = ErrorCategory.CASE


class EvidenceError(ClientError):
    default_code = ErrorCode.EVIDENCE_ERROR
    default_message = "Evidence operation failed."
    status_code = 422
    category = ErrorCategory.EVIDENCE


class EvidenceValidationError(EvidenceError):
    default_code = ErrorCode.EVIDENCE_VALIDATION_ERROR
    default_message = "Evidence validation failed."


class EvidenceNotFoundError(NotFoundError):
    default_code = ErrorCode.EVIDENCE_NOT_FOUND
    default_message = "Referenced evidence record was not found."
    category = ErrorCategory.EVIDENCE


class EvidenceExternalUrlProhibitedError(EvidenceValidationError):
    default_code = ErrorCode.EVIDENCE_EXTERNAL_URL_PROHIBITED
    default_message = "External URLs are not accepted as evidence in MULEGUARD."


# -----------------------------------------------------------------------------
# Report errors
# -----------------------------------------------------------------------------


class ReportError(ServerError):
    default_code = ErrorCode.REPORT_ERROR
    default_message = "Report operation failed."
    status_code = 500
    category = ErrorCategory.REPORT


class ReportGenerationError(ReportError):
    default_code = ErrorCode.REPORT_GENERATION_ERROR
    default_message = "PDF report generation failed."


class ReportTimeoutError(ReportError, OperationTimeoutError):
    default_code = ErrorCode.REPORT_TIMEOUT
    default_message = "PDF report generation timed out."
    status_code = 504
    category = ErrorCategory.REPORT
    retryable = True


class ReportNotFoundError(NotFoundError):
    default_code = ErrorCode.REPORT_NOT_FOUND
    default_message = "Report or case was not found."
    category = ErrorCategory.REPORT


class ReportExpiredError(GoneError):
    default_code = ErrorCode.REPORT_EXPIRED
    default_message = "Generated report is no longer available."
    category = ErrorCategory.REPORT


# -----------------------------------------------------------------------------
# Audit errors
# -----------------------------------------------------------------------------


class AuditError(ServerError):
    default_code = ErrorCode.AUDIT_ERROR
    default_message = "Audit operation failed."
    status_code = 500
    category = ErrorCategory.AUDIT


class AuditIntegrityError(AuditError):
    default_code = ErrorCode.AUDIT_INTEGRITY_ERROR
    default_message = "Audit integrity violation detected."


# -----------------------------------------------------------------------------
# Analysis run errors
# -----------------------------------------------------------------------------


class AnalysisRunError(ServerError):
    default_code = ErrorCode.ANALYSIS_RUN_ERROR
    default_message = "Analysis run failed."
    status_code = 500
    category = ErrorCategory.ANALYSIS


class AnalysisRunConflictError(ConflictError):
    default_code = ErrorCode.ANALYSIS_RUN_CONFLICT
    default_message = "Analysis run conflict detected."
    category = ErrorCategory.ANALYSIS


# -----------------------------------------------------------------------------
# Helper functions for API error handlers
# -----------------------------------------------------------------------------


def build_error_payload(
    exc: MuleGuardError,
    request_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Build a stable JSON payload from a MULEGUARD exception.
    """
    return exc.to_payload(request_id=request_id)


def generic_internal_payload(request_id: Optional[str] = None) -> dict[str, Any]:
    """
    Build a safe generic internal-error payload for unexpected exceptions.

    This must not include exception type names, stack traces, database URLs,
    secrets, tokens, or raw sensitive narratives.
    """
    payload: dict[str, Any] = {
        "code": ErrorCode.INTERNAL_ERROR,
        "message": "Internal server error.",
        "category": ErrorCategory.INTERNAL,
        "retryable": False,
    }

    if request_id:
        payload["request_id"] = str(request_id)

    return payload


def is_client_error(exc: BaseException) -> bool:
    """
    Return True when the exception represents a client/input/policy error.
    """
    return isinstance(exc, ClientError)


def is_server_error(exc: BaseException) -> bool:
    """
    Return True when the exception represents a backend/infrastructure error.
    """
    return isinstance(exc, ServerError)


def is_retryable_error(exc: BaseException) -> bool:
    """
    Return True when the exception is explicitly retryable.
    """
    return isinstance(exc, MuleGuardError) and exc.retryable


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "AnalysisRunConflictError",
    "AnalysisRunError",
    "AuditError",
    "AuditIntegrityError",
    "AuthenticationError",
    "AutomaticEnforcementProhibitedError",
    "AdverseActionProhibitedError",
    "CaseClosedError",
    "CaseError",
    "ClientError",
    "ComplaintError",
    "ComplaintNormalizationAmbiguityError",
    "ComplaintReferenceCollisionError",
    "ConfigurationError",
    "ConflictError",
    "CycleNotAllowedError",
    "DatabaseError",
    "DatabaseOperationError",
    "DatabaseTimeoutError",
    "DatabaseUnavailableError",
    "ErrorCode",
    "ErrorCategory",
    "EvidenceError",
    "EvidenceExternalUrlProhibitedError",
    "EvidenceNotFoundError",
    "EvidenceValidationError",
    "ExplainabilityError",
    "FakeFunctionalityProhibitedError",
    "FeatureComputationError",
    "FeatureFlagDisabledError",
    "FeatureSchemaError",
    "GoneError",
    "GraphConstructionError",
    "GraphError",
    "GraphLimitExceededError",
    "GraphParameterError",
    "GraphTimeoutError",
    "IdempotencyConflictError",
    "IngestionBatchLimitError",
    "IngestionDuplicateError",
    "IngestionError",
    "IngestionReferentialIntegrityError",
    "IngestionValidationError",
    "InternalError",
    "InvalidCaseTransitionError",
    "InvalidCredentialsError",
    "InvalidRequestError",
    "MaintenanceModeError",
    "MethodNotAllowedError",
    "MLError",
    "ModelArtifactCorruptError",
    "ModelArtifactMissingError",
    "ModelEvaluationError",
    "ModelFeatureSchemaMismatchError",
    "ModelInferenceError",
    "ModelNotAvailableError",
    "MoneyTrailConstraintError",
    "MuleGuardError",
    "NotFoundError",
    "OperationTimeoutError",
    "PayloadTooLargeError",
    "PermissionDeniedError",
    "PolicyViolationError",
    "RateLimitError",
    "RealDataProhibitedError",
    "ReportError",
    "ReportExpiredError",
    "ReportGenerationError",
    "ReportNotFoundError",
    "ReportTimeoutError",
    "RequestTimeoutError",
    "RiskFusionError",
    "RuleConfigurationError",
    "ServerError",
    "ServiceUnavailableError",
    "SyntheticDataRequiredError",
    "TemporalCorrectnessViolationError",
    "TokenExpiredError",
    "TokenInvalidError",
    "UnsupportedActionError",
    "UnsupportedMediaTypeError",
    "UnboundedGraphQueryProhibitedError",
    "UserInactiveError",
    "UserLockedError",
    "ValidationError",
    "build_error_payload",
    "generic_internal_payload",
    "is_client_error",
    "is_retryable_error",
    "is_server_error",
]