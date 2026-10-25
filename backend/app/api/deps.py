"""
MULEGUARD backend API dependencies.

This module provides the reusable FastAPI dependency layer for the MULEGUARD
backend.

Primary responsibilities:

- typed database session injection;
- bearer-token authentication;
- server-side role and permission enforcement;
- safe pagination, sorting, filtering, and search parameters;
- bounded graph and money-trail query parameter validation;
- idempotency-key handling;
- local in-memory rate limiting for demo and CI use;
- synthetic-first and production-safety guards;
- feature-flag guards;
- request/correlation context helpers.

Security and product-safety rules enforced or supported here:

- The backend is the security boundary. Frontend hiding is not sufficient.
- Protected endpoints must authenticate and authorize server-side.
- Inactive users must not authenticate.
- Role checks are deny-by-default.
- List endpoints must use bounded pagination and stable ordering.
- Graph endpoints must remain bounded and constrained.
- Whole-bank graph access is prohibited by default.
- Synthetic-first mode is required for demo/ingestion/bootstrap operations
  unless explicitly overridden.
- Production-like environments must not run local demo-only operations.
- Error messages must not leak secrets, tokens, passwords, database URLs,
  stack traces, raw complaint narratives, or real customer data.
- Alerts, scores, graph relationships, candidate money trails, and complaint
  correlations are investigative leads only.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import re
import threading
import time
import uuid
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Final, Literal, Optional, TypeVar, cast

import jwt
from fastapi import Depends, Header, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError
from sqlalchemy import Select, asc, desc
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db import get_db
from app.exceptions import (
    AuthenticationError,
    ConfigurationError,
    FeatureFlagDisabledError,
    GraphLimitExceededError,
    PermissionDeniedError,
    RateLimitError,
    SyntheticDataRequiredError,
    TokenExpiredError,
    TokenInvalidError,
    UnboundedGraphQueryProhibitedError,
    UserInactiveError,
    ValidationError,
)
from app.models import User, UserRole

logger = logging.getLogger("muleguard.backend.api.deps")

T = TypeVar("T")


# -----------------------------------------------------------------------------
# Small runtime helpers
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_REQUEST_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SORT_FIELD_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_IDEMPOTENCY_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
_RATE_LIMIT_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(\d+)\s*/\s*(second|minute|hour|day)\s*$",
    re.IGNORECASE,
)

_WINDOW_SECONDS: Final[dict[str, int]] = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
}


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


def _csv(value: object) -> list[str]:
    """
    Parse comma-separated settings into a clean list.
    """
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return [part.strip() for part in str(value).split(",") if part.strip()]


def _normalize_role(value: Any) -> str:
    """
    Normalize a role-like value to an uppercase role string.
    """
    if isinstance(value, UserRole):
        return value.value

    return str(value).strip().upper().replace(" ", "_").replace("-", "_")


def _coerce_user_role(value: Any) -> UserRole:
    """
    Convert a role-like value to UserRole, falling back safely to ANALYST.
    """
    normalized = _normalize_role(value)

    try:
        return UserRole(normalized)
    except ValueError:
        return UserRole.ANALYST


def _normalize_roles(values: Any) -> tuple[str, ...]:
    """
    Normalize an iterable, string, enum, or single role value to a tuple of
    uppercase role strings.
    """
    if values is None:
        return ()

    if isinstance(values, (str, UserRole)):
        iterable: Iterable[Any] = [values]
    else:
        iterable = values

    normalized: set[str] = set()

    for value in iterable:
        if value is None:
            continue

        role = _normalize_role(value)

        if role:
            normalized.add(role)

    return tuple(sorted(normalized))


def _roles_from_setting_value(value: Any) -> tuple[str, ...]:
    """
    Interpret a role-list setting value.

    Supported forms:

    - "ADMIN,ANALYST"
    - ["ADMIN", "ANALYST"]
    - UserRole.ADMIN
    - None
    """
    if value is None:
        return ()

    if isinstance(value, str):
        return _normalize_roles(_csv(value))

    if isinstance(value, UserRole):
        return (value.value,)

    return _normalize_roles(value)


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    """
    Normalize datetimes to timezone-aware UTC.

    Naive datetimes are assumed to already be UTC.
    """
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


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


def _is_local(settings: Any) -> bool:
    """
    Return True when the runtime environment is explicitly local.
    """
    return str(_setting(settings, "BACKEND_ENV", "local")).strip().lower() == "local"


def _hash_key(parts: Iterable[str], salt: str) -> str:
    """
    Produce a stable, non-reversible key for rate limiting.

    Raw IPs and user identifiers are not stored directly in the limiter map.
    """
    joined = "\x00".join(str(part) for part in parts)
    digest = hmac.new(
        salt.encode("utf-8"),
        joined.encode("utf-8"),
        hashlib.sha256,
    )
    return digest.hexdigest()


# -----------------------------------------------------------------------------
# Core typed dependencies
# -----------------------------------------------------------------------------


def get_api_settings() -> Settings:
    """
    Return runtime settings for API dependencies.

    This wrapper exists so tests can override `get_api_settings` independently
    from application startup settings.
    """
    return get_settings()


SettingsDep = Annotated[Settings, Depends(get_api_settings)]
SessionDep = Annotated[Session, Depends(get_db)]


def get_request_id(
    request: Request,
    x_request_id: Annotated[
        Optional[str],
        Header(alias="X-Request-ID"),
    ] = None,
) -> str:
    """
    Return a safe request/correlation ID.

    Preference order:

    1. request.state.request_id set by middleware;
    2. X-Request-ID header;
    3. generated UUID4.
    """
    request_id = getattr(request.state, "request_id", None) or x_request_id

    if request_id:
        request_id = str(request_id).strip()

        if _REQUEST_ID_RE.match(request_id):
            return request_id

    generated = str(uuid.uuid4())
    request.state.request_id = generated
    return generated


RequestIDDep = Annotated[str, Depends(get_request_id)]


# -----------------------------------------------------------------------------
# Authentication token helpers
# -----------------------------------------------------------------------------


class TokenPayload(BaseModel):
    """
    Minimal JWT claims accepted by MULEGUARD.

    Roles are optional in the token. The database remains the authoritative
    source for current role and active status.
    """

    model_config = ConfigDict(extra="ignore")

    sub: str = Field(min_length=1, max_length=128)
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    iss: Optional[str] = None
    aud: Optional[Any] = None
    jti: Optional[str] = None
    typ: Optional[str] = None
    roles: Optional[list[str]] = None


def _authorization_scheme(settings: Any) -> str:
    """
    Return the configured bearer scheme.
    """
    scheme = str(_setting(settings, "AUTH_TOKEN_SCHEME", "Bearer") or "Bearer").strip()
    return scheme or "Bearer"


def _extract_bearer_token(
    request: Request,
    authorization: Optional[str],
    settings: Any,
) -> Optional[str]:
    """
    Extract a bearer token from Authorization header or optional cookie.

    Returns None when no token is present.
    """
    header_value = authorization or request.headers.get("Authorization")

    if header_value:
        scheme = _authorization_scheme(settings)
        prefix = f"{scheme} "

        if header_value.lower().startswith(prefix.lower()):
            token = header_value[len(prefix):].strip()

            if token:
                return token

    if _as_bool(_setting(settings, "AUTH_USE_COOKIES", False), False):
        cookie_name = str(_setting(settings, "AUTH_COOKIE_NAME", "muleguard_auth"))
        cookie_value = request.cookies.get(cookie_name)

        if cookie_value:
            token = str(cookie_value).strip()

            if token:
                return token

    return None


def get_bearer_token(
    request: Request,
    authorization: Annotated[
        Optional[str],
        Header(alias="Authorization"),
    ] = None,
    settings: SettingsDep = ...,
) -> str:
    """
    FastAPI dependency that extracts a bearer token.

    When authentication is disabled, this returns an empty string so that
    `get_current_user` can apply local bypass or configuration errors in a
    single place.
    """
    token = _extract_bearer_token(request, authorization, settings)

    if token:
        return token

    if not _as_bool(_setting(settings, "AUTH_ENABLED", True), True):
        return ""

    raise AuthenticationError("Authentication token is required.")


BearerTokenDep = Annotated[str, Depends(get_bearer_token)]


def decode_access_token(token: str, settings: Any) -> TokenPayload:
    """
    Decode and validate a MULEGUARD access token.

    The implementation intentionally keeps token validation simple and local for
    the synthetic prototype. Production deployments should replace or extend
    this with reviewed JWT/JWKS/OIDC validation.
    """
    secret = str(_setting(settings, "BACKEND_SECRET_KEY", "") or "").strip()

    if not secret:
        raise ConfigurationError("BACKEND_SECRET_KEY is not configured.")

    algorithm = str(_setting(settings, "AUTH_ALGORITHM", "HS256") or "HS256").strip()
    issuer = _setting(settings, "AUTH_ISSUER", None)
    audience_raw = _setting(settings, "AUTH_AUDIENCE", None)
    clock_skew = max(0, _as_int(_setting(settings, "AUTH_CLOCK_SKEW_SECONDS", 30), 30))

    audience: Any = None

    if isinstance(audience_raw, str):
        audience_parts = [part.strip() for part in audience_raw.split(",") if part.strip()]

        if len(audience_parts) == 1:
            audience = audience_parts[0]
        elif len(audience_parts) > 1:
            audience = audience_parts
    elif isinstance(audience_raw, (list, tuple, set)):
        audience = [str(item).strip() for item in audience_raw if str(item).strip()]

    decode_kwargs: dict[str, Any] = {
        "algorithms": [algorithm],
        "options": {
            "verify_signature": True,
            "verify_exp": True,
            "require": ["exp"],
        },
        "leeway": clock_skew,
    }

    if issuer:
        decode_kwargs["issuer"] = str(issuer)

    if audience:
        decode_kwargs["audience"] = audience

    try:
        claims = jwt.decode(token, secret, **decode_kwargs)
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError() from exc
    except jwt.InvalidTokenError as exc:
        raise TokenInvalidError() from exc
    except Exception as exc:
        logger.debug("Unexpected token decode failure: %s", type(exc).__name__)
        raise TokenInvalidError() from exc

    try:
        payload = TokenPayload.model_validate(claims)
    except PydanticValidationError as exc:
        logger.debug("Token claim validation failed: %s", exc.errors(include_url=False))
        raise TokenInvalidError() from exc

    if not payload.sub:
        raise TokenInvalidError()

    return payload


def _load_user_from_token(token: str, db: Session, settings: Any) -> User:
    """
    Load and validate the user referenced by a token.

    The database is authoritative for active status and role.
    """
    payload = decode_access_token(token, settings)
    user = db.get(User, payload.sub)

    if user is None:
        # Do not reveal whether the token subject exists.
        raise AuthenticationError("Invalid authentication token.")

    if not user.is_active:
        raise UserInactiveError()

    return user


def _bind_request_user_context(
    request: Request,
    db: Session,
    user: User,
    request_id: str,
) -> None:
    """
    Attach safe user context to request state and SQLAlchemy session info.

    This does not persist audit records by itself.
    """
    request.state.user = user
    request.state.user_id = user.id
    request.state.user_role = (
        user.role.value if isinstance(user.role, UserRole) else str(user.role)
    )

    try:
        from app.db import bind_audit_context

        bind_audit_context(
            db,
            actor_id=str(user.id),
            actor_role=str(request.state.user_role),
            request_id=request_id,
        )
    except Exception:
        # Audit context binding is best-effort and must not break authentication.
        logger.debug("Unable to bind audit context.", exc_info=True)


def _local_bypass_user(settings: Any) -> User:
    """
    Create a transient local bypass user for explicitly unsafe local testing.

    This is allowed only when:

    - AUTH_ENABLED=false;
    - BACKEND_ENV=local;
    - AUTH_ALLOW_UNAUTHENTICATED_LOCAL=true.

    It is not intended for Docker demo exposure, staging, or production.
    """
    role_value = _setting(settings, "AUTH_DISABLED_ROLE", UserRole.ANALYST.value)
    role = _coerce_user_role(role_value)

    return User(
        id="local-bypass",
        username="local",
        email="local@muleguard.local",
        full_name="Local bypass user",
        role=role,
        password_hash="",
        is_active=True,
        must_change_password=False,
        failed_login_count=0,
    )


async def get_current_user(
    request: Request,
    token: BearerTokenDep,
    db: SessionDep,
    settings: SettingsDep,
    request_id: RequestIDDep,
) -> User:
    """
    FastAPI dependency that returns the authenticated user.

    Behaviour:

    - If AUTH_ENABLED=true, requires a valid bearer token and active user.
    - If AUTH_ENABLED=false and local unsafe bypass is explicitly enabled,
      returns a transient local user.
    - Otherwise raises ConfigurationError.
    """
    auth_enabled = _as_bool(_setting(settings, "AUTH_ENABLED", True), True)

    if not auth_enabled:
        allow_local_bypass = (
            _is_local(settings)
            and _as_bool(_setting(settings, "AUTH_ALLOW_UNAUTHENTICATED_LOCAL", False), False)
        )

        if allow_local_bypass:
            user = _local_bypass_user(settings)
            _bind_request_user_context(request, db, user, request_id)
            return user

        raise ConfigurationError(
            "Protected API endpoints require AUTH_ENABLED=true. "
            "For local tests, either enable authentication or explicitly set "
            "AUTH_ALLOW_UNAUTHENTICATED_LOCAL=true in BACKEND_ENV=local."
        )

    if not token:
        raise AuthenticationError("Authentication token is required.")

    user = _load_user_from_token(token, db, settings)
    _bind_request_user_context(request, db, user, request_id)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def get_optional_current_user(
    request: Request,
    authorization: Annotated[
        Optional[str],
        Header(alias="Authorization"),
    ] = None,
    db: SessionDep = ...,
    settings: SettingsDep = ...,
    request_id: RequestIDDep = ...,
) -> Optional[User]:
    """
    Return the authenticated user when present and valid, otherwise None.

    This is useful for endpoints that behave differently for authenticated users
    but do not require authentication. It must not be used as a security
    boundary for protected actions.
    """
    auth_enabled = _as_bool(_setting(settings, "AUTH_ENABLED", True), True)

    if not auth_enabled:
        allow_local_bypass = (
            _is_local(settings)
            and _as_bool(_setting(settings, "AUTH_ALLOW_UNAUTHENTICATED_LOCAL", False), False)
        )

        if allow_local_bypass:
            user = _local_bypass_user(settings)
            _bind_request_user_context(request, db, user, request_id)
            return user

        return None

    token = _extract_bearer_token(request, authorization, settings)

    if not token:
        return None

    try:
        user = _load_user_from_token(token, db, settings)
    except Exception:
        # Optional authentication must not fail the request.
        logger.debug("Optional authentication failed.", exc_info=True)
        return None

    _bind_request_user_context(request, db, user, request_id)
    return user


OptionalUser = Annotated[Optional[User], Depends(get_optional_current_user)]


# -----------------------------------------------------------------------------
# RBAC: roles and permissions
# -----------------------------------------------------------------------------


class Permission:
    """
    Stable permission identifiers used by API dependencies.

    These map to environment settings such as:

        ANALYSIS_RUN_ROLES=ANALYST,SENIOR_INVESTIGATOR,ADMIN
        CASE_CREATE_ROLES=ANALYST,SENIOR_INVESTIGATOR,ADMIN
        AUDIT_READ_ROLES=AUDITOR,ADMIN
    """

    USER_MANAGE: Final[str] = "user_management"
    CONFIG_READ: Final[str] = "config_read"
    CONFIG_WRITE: Final[str] = "config_write"

    DASHBOARD_READ: Final[str] = "dashboard_read"
    ACCOUNT_READ: Final[str] = "account_read"
    TRANSACTION_READ: Final[str] = "transaction_read"
    SEARCH: Final[str] = "search"

    ANALYSIS_RUN: Final[str] = "analysis_run"
    INGESTION_WRITE: Final[str] = "ingestion_write"
    SEED_RESET: Final[str] = "seed_reset"

    ALERT_READ: Final[str] = "alert_read"
    ALERT_TRIAGE: Final[str] = "alert_triage"
    ALERT_ASSIGN: Final[str] = "alert_assign"
    ALERT_ESCALATE: Final[str] = "alert_escalate"
    ALERT_CASE_CREATE: Final[str] = "alert_case_create"

    GRAPH_READ: Final[str] = "graph_read"
    GRAPH_EXPORT: Final[str] = "graph_export"

    COMPLAINT_READ: Final[str] = "complaint_read"
    COMPLAINT_REVIEW: Final[str] = "complaint_review"
    COMPLAINT_NARRATIVE_READ: Final[str] = "complaint_narrative_read"

    CASE_READ: Final[str] = "case_read"
    CASE_CREATE: Final[str] = "case_create"
    CASE_UPDATE: Final[str] = "case_update"
    CASE_ASSIGN: Final[str] = "case_assign"
    CASE_CLOSE: Final[str] = "case_close"
    CASE_REOPEN: Final[str] = "case_reopen"
    CASE_NOTE_ADD: Final[str] = "case_note_add"
    CASE_EVIDENCE_ADD: Final[str] = "case_evidence_add"
    CASE_EVIDENCE_REMOVE: Final[str] = "case_evidence_remove"
    CASE_EXPORT: Final[str] = "case_export"

    REPORT_READ: Final[str] = "report_read"
    REPORT_GENERATE: Final[str] = "report_generate"
    REPORT_DOWNLOAD: Final[str] = "report_download"

    AUDIT_READ: Final[str] = "audit_read"
    AUDIT_EXPORT: Final[str] = "audit_export"

    MODEL_MONITOR_READ: Final[str] = "model_monitor_read"
    MODEL_TRAIN: Final[str] = "model_train"
    MODEL_EVALUATE: Final[str] = "model_evaluate"


_ALL_ROLES: Final[tuple[str, ...]] = (
    UserRole.ADMIN.value,
    UserRole.ANALYST.value,
    UserRole.SENIOR_INVESTIGATOR.value,
    UserRole.AUDITOR.value,
)

_ADMIN_AND_SENIOR: Final[tuple[str, ...]] = (
    UserRole.ADMIN.value,
    UserRole.SENIOR_INVESTIGATOR.value,
)

_ADMIN_ONLY: Final[tuple[str, ...]] = (
    UserRole.ADMIN.value,
)

_READ_ROLES: Final[tuple[str, ...]] = _ALL_ROLES

_DEFAULT_PERMISSION_ROLES: Final[dict[str, tuple[str, ...]]] = {
    Permission.USER_MANAGE: _ADMIN_ONLY,
    Permission.CONFIG_READ: _ADMIN_ONLY,
    Permission.CONFIG_WRITE: _ADMIN_ONLY,
    Permission.DASHBOARD_READ: _READ_ROLES,
    Permission.ACCOUNT_READ: _READ_ROLES,
    Permission.TRANSACTION_READ: _READ_ROLES,
    Permission.SEARCH: _READ_ROLES,
    Permission.ANALYSIS_RUN: (
        UserRole.ANALYST.value,
        UserRole.SENIOR_INVESTIGATOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.INGESTION_WRITE: _ADMIN_ONLY,
    Permission.SEED_RESET: _ADMIN_ONLY,
    Permission.ALERT_READ: _READ_ROLES,
    Permission.ALERT_TRIAGE: (
        UserRole.ANALYST.value,
        UserRole.SENIOR_INVESTIGATOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.ALERT_ASSIGN: _ADMIN_AND_SENIOR,
    Permission.ALERT_ESCALATE: _ADMIN_AND_SENIOR,
    Permission.ALERT_CASE_CREATE: (
        UserRole.ANALYST.value,
        UserRole.SENIOR_INVESTIGATOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.GRAPH_READ: _READ_ROLES,
    Permission.GRAPH_EXPORT: (
        UserRole.ANALYST.value,
        UserRole.SENIOR_INVESTIGATOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.COMPLAINT_READ: _READ_ROLES,
    Permission.COMPLAINT_REVIEW: _ADMIN_AND_SENIOR,
    Permission.COMPLAINT_NARRATIVE_READ: _ADMIN_AND_SENIOR,
    Permission.CASE_READ: _READ_ROLES,
    Permission.CASE_CREATE: (
        UserRole.ANALYST.value,
        UserRole.SENIOR_INVESTIGATOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.CASE_UPDATE: (
        UserRole.ANALYST.value,
        UserRole.SENIOR_INVESTIGATOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.CASE_ASSIGN: _ADMIN_AND_SENIOR,
    Permission.CASE_CLOSE: _ADMIN_AND_SENIOR,
    Permission.CASE_REOPEN: _ADMIN_AND_SENIOR,
    Permission.CASE_NOTE_ADD: (
        UserRole.ANALYST.value,
        UserRole.SENIOR_INVESTIGATOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.CASE_EVIDENCE_ADD: (
        UserRole.ANALYST.value,
        UserRole.SENIOR_INVESTIGATOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.CASE_EVIDENCE_REMOVE: _ADMIN_AND_SENIOR,
    Permission.CASE_EXPORT: _READ_ROLES,
    Permission.REPORT_READ: _READ_ROLES,
    Permission.REPORT_GENERATE: (
        UserRole.ANALYST.value,
        UserRole.SENIOR_INVESTIGATOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.REPORT_DOWNLOAD: _READ_ROLES,
    Permission.AUDIT_READ: (
        UserRole.AUDITOR.value,
        UserRole.ADMIN.value,
    ),
    Permission.AUDIT_EXPORT: _ADMIN_ONLY,
    Permission.MODEL_MONITOR_READ: _READ_ROLES,
    Permission.MODEL_TRAIN: _ADMIN_ONLY,
    Permission.MODEL_EVALUATE: _ADMIN_ONLY,
}


def _permission_setting_names(permission: str) -> tuple[str, ...]:
    """
    Return possible environment setting names for a permission.
    """
    normalized = permission.strip().upper().replace("-", "_").replace(".", "_")
    return (
        f"{normalized}_ROLES",
        f"PERMISSION_{normalized}",
        f"RBAC_{normalized}_ROLES",
    )


def require_roles(*roles: str | UserRole) -> Callable[..., User]:
    """
    Dependency factory requiring one of the specified roles.

    Example:

        @router.get("/audit")
        def read_audit(user: User = Depends(require_roles(UserRole.AUDITOR, UserRole.ADMIN))):
            ...
    """
    allowed = _normalize_roles(roles)

    if not allowed:
        raise ConfigurationError("require_roles() requires at least one role.")

    async def dependency(current_user: CurrentUser) -> User:
        user_role = (
            current_user.role.value
            if isinstance(current_user.role, UserRole)
            else _normalize_role(current_user.role)
        )

        if user_role not in allowed:
            raise PermissionDeniedError()

        return current_user

    return dependency


def require_permission(
    permission: str,
    *,
    default_roles: Sequence[str | UserRole] | None = None,
) -> Callable[..., User]:
    """
    Dependency factory enforcing a named permission.

    Resolution order:

    1. explicit environment setting, e.g. CASE_CREATE_ROLES;
    2. PERMISSION_CASE_CREATE;
    3. RBAC_CASE_CREATE_ROLES;
    4. built-in default_roles;
    5. built-in _DEFAULT_PERMISSION_ROLES.

    If no roles resolve, access is denied.
    """
    permission_name = permission.strip()

    if not permission_name:
        raise ConfigurationError("require_permission() requires a permission name.")

    fallback_defaults = _normalize_roles(default_roles) if default_roles is not None else ()
    builtin_defaults = _DEFAULT_PERMISSION_ROLES.get(permission_name, ())

    async def dependency(
        current_user: CurrentUser,
        settings: SettingsDep,
    ) -> User:
        if not _as_bool(_setting(settings, "RBAC_ENABLED", True), True):
            # RBAC disabled is unsafe for production-like use, but may be useful
            # in tightly controlled local tests. Authentication is still
            # enforced by CurrentUser.
            return current_user

        configured_roles: tuple[str, ...] = ()

        for setting_name in _permission_setting_names(permission_name):
            raw_value = _setting(settings, setting_name, None)

            if raw_value is not None:
                configured_roles = _roles_from_setting_value(raw_value)
                break

        allowed = configured_roles or fallback_defaults or builtin_defaults

        if not allowed:
            logger.warning(
                "No roles configured for permission %s; denying access.",
                permission_name,
            )
            raise PermissionDeniedError()

        user_role = (
            current_user.role.value
            if isinstance(current_user.role, UserRole)
            else _normalize_role(current_user.role)
        )

        if user_role not in allowed:
            raise PermissionDeniedError()

        return current_user

    return dependency


# -----------------------------------------------------------------------------
# Pagination, sorting, filtering, and search
# -----------------------------------------------------------------------------

SortOrder = Literal["asc", "desc"]


@dataclass(frozen=True, slots=True)
class PageParams:
    """
    Bounded pagination parameters.
    """

    page: int
    page_size: int
    sort_by: Optional[str]
    sort_order: SortOrder

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        return self.page_size

    def as_dict(self) -> dict[str, Any]:
        return {
            "page": self.page,
            "page_size": self.page_size,
            "sort_by": self.sort_by,
            "sort_order": self.sort_order,
            "offset": self.offset,
            "limit": self.limit,
        }


def pagination_dependency(
    *,
    sortable_fields: Sequence[str] | None = None,
    default_sort_by: str | None = "created_at",
    default_sort_order: SortOrder = "desc",
    max_page_size: int | None = None,
    hard_max_page_size: int = 500,
) -> Callable[..., PageParams]:
    """
    Create a bounded pagination dependency.

    Parameters
    ----------
    sortable_fields:
        Optional allowlist of sortable field names. If provided, unknown sort
        fields are rejected.
    default_sort_by:
        Default sort field when the client omits `sort_by`.
    default_sort_order:
        Default sort direction.
    max_page_size:
        Optional override for maximum page size. Otherwise uses
        PAGINATION_MAX_PAGE_SIZE.
    hard_max_page_size:
        Absolute upper bound to prevent accidental huge pages.
    """
    allowed_sort_fields = set(sortable_fields) if sortable_fields is not None else None

    def dependency(
        page: Annotated[int, Query(ge=1, description="1-based page number")] = 1,
        page_size: Annotated[
            Optional[int],
            Query(ge=1, description="Page size"),
        ] = None,
        sort_by: Annotated[
            Optional[str],
            Query(description="Sort field"),
        ] = None,
        sort_order: Annotated[
            str,
            Query(pattern="^(asc|desc)$", description="Sort direction"),
        ] = default_sort_order,
        settings: SettingsDep = ...,
    ) -> PageParams:
        configured_max = _as_int(
            _setting(settings, "PAGINATION_MAX_PAGE_SIZE", 200),
            200,
        )
        configured_default = _as_int(
            _setting(settings, "PAGINATION_DEFAULT_PAGE_SIZE", 50),
            50,
        )

        effective_max = max_page_size if max_page_size is not None else configured_max
        effective_max = max(1, min(int(effective_max), int(hard_max_page_size)))

        if page_size is None:
            page_size = configured_default

        page_size = max(1, min(int(page_size), effective_max))

        normalized_sort_by: Optional[str] = None

        if sort_by is not None:
            candidate = str(sort_by).strip()

            if candidate:
                if not _SORT_FIELD_RE.match(candidate):
                    raise ValidationError(
                        "Invalid sort field.",
                        details={"sort_by": candidate[:128]},
                    )

                if allowed_sort_fields is not None and candidate not in allowed_sort_fields:
                    raise ValidationError(
                        "Sort field is not allowed.",
                        details={"sort_by": candidate},
                    )

                normalized_sort_by = candidate

        if normalized_sort_by is None:
            normalized_sort_by = default_sort_by

        normalized_order = cast(SortOrder, str(sort_order).strip().lower())

        return PageParams(
            page=int(page),
            page_size=int(page_size),
            sort_by=normalized_sort_by,
            sort_order=normalized_order,
        )

    return dependency


def apply_pagination(
    query: Select[Any],
    params: PageParams,
    *,
    column_map: Mapping[str, Any] | None = None,
    tiebreaker: Any | None = None,
    default_sort_by: str | None = None,
    default_sort_order: SortOrder = "desc",
) -> Select[Any]:
    """
    Apply bounded pagination and stable ordering to a SQLAlchemy Select.

    The caller should provide a `column_map` mapping allowed sort field names
    to SQLAlchemy columns and a `tiebreaker` column, usually the primary key,
    to guarantee deterministic ordering.
    """
    order_clauses: list[Any] = []

    sort_field = params.sort_by or default_sort_by
    sort_direction = params.sort_order or default_sort_order

    if column_map and sort_field:
        sort_column = column_map.get(sort_field)

        if sort_column is None:
            raise ValidationError(
                "Sort field is not available for this query.",
                details={"sort_by": sort_field},
            )

        order_clauses.append(asc(sort_column) if sort_direction == "asc" else desc(sort_column))

    if tiebreaker is not None:
        # Stable tie-breaker. Use descending primary key by default to make
        # newest-first listings deterministic when primary sort values tie.
        order_clauses.append(desc(tiebreaker))

    if order_clauses:
        query = query.order_by(*order_clauses)

    return query.offset(params.offset).limit(params.limit)


@dataclass(frozen=True, slots=True)
class DateRangeParams:
    """
    Bounded date-range filter parameters.
    """

    date_from: Optional[datetime]
    date_to: Optional[datetime]

    def as_dict(self) -> dict[str, Any]:
        return {
            "date_from": self.date_from.isoformat() if self.date_from else None,
            "date_to": self.date_to.isoformat() if self.date_to else None,
        }


def date_range_dependency(
    *,
    max_span_days: int | None = None,
    from_alias: str = "date_from",
    to_alias: str = "date_to",
) -> Callable[..., DateRangeParams]:
    """
    Create a date-range dependency with optional maximum span enforcement.
    """

    def dependency(
        date_from: Optional[datetime] = Query(
            default=None,
            alias=from_alias,
            description="Start timestamp, inclusive",
        ),
        date_to: Optional[datetime] = Query(
            default=None,
            alias=to_alias,
            description="End timestamp, inclusive",
        ),
        settings: SettingsDep = ...,
    ) -> DateRangeParams:
        start = _ensure_utc(date_from)
        end = _ensure_utc(date_to)

        if start is not None and end is not None and start > end:
            raise ValidationError(
                "date_from must be earlier than or equal to date_to.",
                details={
                    from_alias: start.isoformat(),
                    to_alias: end.isoformat(),
                },
            )

        effective_max_span = max_span_days

        if effective_max_span is None:
            effective_max_span = _as_int(
                _setting(settings, "GRAPH_MAX_DATE_SPAN_DAYS", 90),
                90,
            )

        if (
            effective_max_span is not None
            and effective_max_span > 0
            and start is not None
            and end is not None
        ):
            span = end - start
            max_delta = timedelta(days=int(effective_max_span))

            if span > max_delta:
                raise GraphLimitExceededError.limit(
                    "date_span_days",
                    int(effective_max_span),
                    int(span.total_seconds() // 86400),
                    message="Requested date range exceeds configured maximum span.",
                )

        return DateRangeParams(date_from=start, date_to=end)

    return dependency


@dataclass(frozen=True, slots=True)
class AmountRangeParams:
    """
    Bounded amount-range filter parameters.
    """

    amount_min: Optional[Decimal]
    amount_max: Optional[Decimal]

    def as_dict(self) -> dict[str, Any]:
        return {
            "amount_min": str(self.amount_min) if self.amount_min is not None else None,
            "amount_max": str(self.amount_max) if self.amount_max is not None else None,
        }


def amount_range_dependency(
    *,
    min_alias: str = "amount_min",
    max_alias: str = "amount_max",
    allow_negative: bool = False,
) -> Callable[..., AmountRangeParams]:
    """
    Create an amount-range dependency.

    Monetary amounts in MULEGUARD are normally non-negative for completed
    transfers. Negative values are rejected unless explicitly allowed.
    """

    def dependency(
        amount_min: Annotated[
            Optional[Decimal],
            Query(alias=min_alias, description="Minimum amount"),
        ] = None,
        amount_max: Annotated[
            Optional[Decimal],
            Query(alias=max_alias, description="Maximum amount"),
        ] = None,
    ) -> AmountRangeParams:
        try:
            minimum = Decimal(amount_min) if amount_min is not None else None
            maximum = Decimal(amount_max) if amount_max is not None else None
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValidationError("Invalid amount filter value.") from exc

        for label, value in ((min_alias, minimum), (max_alias, maximum)):
            if value is None:
                continue

            if not value.is_finite():
                raise ValidationError(
                    "Amount filters must be finite decimal values.",
                    details={label: str(value)},
                )

            if not allow_negative and value < 0:
                raise ValidationError(
                    "Amount filters must be non-negative.",
                    details={label: str(value)},
                )

        if minimum is not None and maximum is not None and minimum > maximum:
            raise ValidationError(
                "amount_min must be less than or equal to amount_max.",
                details={
                    min_alias: str(minimum),
                    max_alias: str(maximum),
                },
            )

        return AmountRangeParams(amount_min=minimum, amount_max=maximum)

    return dependency


@dataclass(frozen=True, slots=True)
class SearchParams:
    """
    Bounded free-text search parameters.
    """

    q: Optional[str]

    def as_dict(self) -> dict[str, Any]:
        return {"q": self.q}


def search_dependency(
    *,
    max_length: int | None = None,
    alias: str = "q",
) -> Callable[..., SearchParams]:
    """
    Create a bounded search query dependency.
    """

    def dependency(
        q: Optional[str] = Query(
            default=None,
            alias=alias,
            description="Free-text search query",
        ),
        settings: SettingsDep = ...,
    ) -> SearchParams:
        effective_max = max_length

        if effective_max is None:
            effective_max = _as_int(
                _setting(settings, "SEARCH_MAX_QUERY_LENGTH", 200),
                200,
            )

        effective_max = max(1, min(int(effective_max), 1000))

        if q is None:
            return SearchParams(q=None)

        normalized = str(q).strip()

        if not normalized:
            return SearchParams(q=None)

        if len(normalized) > effective_max:
            raise ValidationError(
                "Search query is too long.",
                details={"max_length": effective_max, "actual_length": len(normalized)},
            )

        return SearchParams(q=normalized)

    return dependency


# -----------------------------------------------------------------------------
# Idempotency
# -----------------------------------------------------------------------------


def get_idempotency_key(
    idempotency_key: Annotated[
        Optional[str],
        Header(alias="Idempotency-Key"),
    ] = None,
    settings: SettingsDep = ...,
) -> Optional[str]:
    """
    Validate and return an optional idempotency key.

    If ANALYSIS_REQUIRE_IDEMPOTENCY_KEY or a generic required flag is enabled,
    missing keys raise ValidationError.
    """
    require_key = _as_bool(
        _setting(settings, "ANALYSIS_REQUIRE_IDEMPOTENCY_KEY", False),
        False,
    ) or _as_bool(
        _setting(settings, "REQUIRE_IDEMPOTENCY_KEY", False),
        False,
    )

    if idempotency_key is None:
        if require_key:
            raise ValidationError(
                "Idempotency-Key header is required for this operation.",
                details={"header": "Idempotency-Key"},
            )

        return None

    normalized = str(idempotency_key).strip()

    if not normalized:
        if require_key:
            raise ValidationError(
                "Idempotency-Key header is required for this operation.",
                details={"header": "Idempotency-Key"},
            )

        return None

    if not _IDEMPOTENCY_KEY_RE.match(normalized):
        raise ValidationError(
            "Invalid Idempotency-Key value.",
            details={"header": "Idempotency-Key"},
        )

    return normalized


IdempotencyKeyDep = Annotated[Optional[str], Depends(get_idempotency_key)]


# -----------------------------------------------------------------------------
# Rate limiting
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """
    Parsed rate-limit rule.
    """

    limit: int
    window_seconds: int
    name: str = "custom"


def parse_rate_limit(value: str | RateLimitRule | None, default: RateLimitRule) -> RateLimitRule:
    """
    Parse a rate-limit string such as `5/minute` or `300/minute`.
    """
    if isinstance(value, RateLimitRule):
        return value

    if not value:
        return default

    match = _RATE_LIMIT_RE.match(str(value))

    if not match:
        return default

    limit = max(1, int(match.group(1)))
    unit = match.group(2).lower()
    window_seconds = _WINDOW_SECONDS.get(unit, default.window_seconds)

    return RateLimitRule(
        limit=limit,
        window_seconds=max(1, int(window_seconds)),
        name=str(value).strip(),
    )


class MemoryRateLimiter:
    """
    Small thread-safe in-memory rate limiter for local prototype and CI use.

    This is intentionally not distributed. Production deployments should replace
    it with Redis, a gateway limiter, or another shared store.
    """

    def __init__(
        self,
        *,
        max_keys: int = 10_000,
        prune_interval_seconds: float = 60.0,
    ) -> None:
        self.max_keys = max(100, int(max_keys))
        self.prune_interval_seconds = max(1.0, float(prune_interval_seconds))
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()
        self._last_prune = time.monotonic()

    def _prune_expired(self, now: float, max_window_seconds: int) -> None:
        cutoff = now - max(60, int(max_window_seconds) * 2)
        stale_keys: list[str] = []

        for key, bucket in self._buckets.items():
            if not bucket or bucket[-1] <= cutoff:
                stale_keys.append(key)

        for key in stale_keys:
            self._buckets.pop(key, None)

    def check(self, key: str, rule: RateLimitRule) -> tuple[bool, int, int]:
        """
        Check and consume one request against a rate-limit bucket.

        Returns:
            allowed, remaining, retry_after_seconds
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
            reset_after = max(1, int(math.ceil(rule.window_seconds)))
            return True, remaining, reset_after


_RATE_LIMITER: Final[MemoryRateLimiter] = MemoryRateLimiter()


def _client_ip(request: Request, settings: Any) -> str:
    """
    Return a best-effort client IP for rate-limit keying.

    Proxy headers are trusted only when BACKEND_TRUST_PROXY_HEADERS=true.
    """
    trust_proxy = _as_bool(
        _setting(settings, "BACKEND_TRUST_PROXY_HEADERS", False),
        False,
    )

    if trust_proxy:
        forwarded_for = request.headers.get("X-Forwarded-For")

        if forwarded_for:
            first = forwarded_for.split(",", 1)[0].strip()

            if first:
                return first

        real_ip = request.headers.get("X-Real-IP")

        if real_ip:
            return real_ip.strip() or "unknown"

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


def _rate_limit_setting_name(prefix: str) -> str:
    """
    Convert a rate-limit prefix into an environment setting name.
    """
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", prefix).strip("_").upper()
    return f"AUTH_RATE_LIMIT_{normalized}" if normalized else "AUTH_RATE_LIMIT_GLOBAL"


def rate_limited(
    *,
    rule: str | RateLimitRule | None = None,
    key_prefix: str = "",
    by: Literal["user", "ip", "user_and_ip"] = "user_and_ip",
) -> Callable[..., None]:
    """
    Create a rate-limit dependency.

    Examples:

        @router.post("/auth/login")
        def login(_: None = Depends(rate_limited(rule="5/minute", key_prefix="login"))):
            ...

        @router.post("/analysis/run")
        def run_analysis(
            user: CurrentUser,
            _: None = Depends(rate_limited(rule="5/minute", key_prefix="analysis")),
        ):
            ...
    """
    default_rule = RateLimitRule(limit=300, window_seconds=60, name="300/minute")

    def dependency(
        request: Request,
        response: Response,
        settings: SettingsDep,
    ) -> None:
        # Either switch turns rate limiting off, and both default to on.
        #
        # This was previously `or`, which made `AUTH_RATE_LIMIT_ENABLED=false`
        # a dead flag: `RATE_LIMIT_ENABLED` is not a declared setting, so
        # `_setting` always returned its `True` default and the `or` was
        # always satisfied. An operator could not switch limiting off at all.
        # `RateLimitSettings.enabled()` in `app/core/rate_limit.py` already
        # uses `and`; this is the same rule, so the two cannot disagree.
        enabled = _as_bool(
            _setting(settings, "AUTH_RATE_LIMIT_ENABLED", True),
            True,
        ) and _as_bool(
            _setting(settings, "RATE_LIMIT_ENABLED", True),
            True,
        )

        if not enabled:
            return

        resolved_rule = rule

        if resolved_rule is None:
            setting_name = _rate_limit_setting_name(key_prefix or "global")
            configured = _setting(settings, setting_name, None)

            if configured is None and key_prefix:
                configured = _setting(settings, "AUTH_RATE_LIMIT_GLOBAL", None)

            resolved_rule = configured or "300/minute"

        parsed_rule = parse_rate_limit(resolved_rule, default_rule)

        user_id = getattr(request.state, "user_id", None)
        ip = _client_ip(request, settings)

        salt = str(
            _setting(settings, "AUTH_RATE_LIMIT_KEY_SALT", None)
            or _setting(settings, "BACKEND_SECRET_KEY", None)
            or "muleguard-rate-limit"
        )

        parts: list[str] = [
            key_prefix or "global",
            request.method.upper(),
            request.url.path,
        ]

        if by in {"user", "user_and_ip"} and user_id:
            parts.append(f"user:{user_id}")

        if by in {"ip", "user_and_ip"}:
            parts.append(f"ip:{ip}")

        key = _hash_key(parts, salt)
        allowed, remaining, reset_after = _RATE_LIMITER.check(key, parsed_rule)

        add_headers = _as_bool(
            _setting(settings, "RATE_LIMIT_ADD_HEADERS", True),
            True,
        )

        if add_headers:
            response.headers.setdefault("RateLimit-Limit", str(parsed_rule.limit))
            response.headers.setdefault("RateLimit-Remaining", str(remaining))
            response.headers.setdefault("RateLimit-Reset", str(reset_after))

        if not allowed:
            raise RateLimitError(
                retry_after_seconds=reset_after,
                details={
                    "scope": key_prefix or "global",
                    "limit": parsed_rule.limit,
                    "window_seconds": parsed_rule.window_seconds,
                },
            )

    return dependency


# -----------------------------------------------------------------------------
# Graph and money-trail bounded query parameters
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphQueryParams:
    """
    Bounded graph query parameters.

    These parameters are intentionally constrained. Graph results are
    investigative leads only and must not be treated as proof of wrongdoing.
    """

    root_account_id: Optional[str]
    source_account_id: Optional[str]
    destination_account_id: Optional[str]
    hops: int
    max_nodes: int
    max_edges: int
    max_paths: int
    date_from: Optional[datetime]
    date_to: Optional[datetime]
    min_amount: Optional[Decimal]
    max_amount: Optional[Decimal]
    include_failed: bool
    include_pending: bool
    include_reversed: bool
    max_time_gap_hours: Optional[int] = None
    cycle_prevention: bool = True
    temporal_strict: bool = True
    same_timestamp_policy: str = "reject"

    def as_dict(self) -> dict[str, Any]:
        return {
            "root_account_id": self.root_account_id,
            "source_account_id": self.source_account_id,
            "destination_account_id": self.destination_account_id,
            "hops": self.hops,
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
            "max_paths": self.max_paths,
            "date_from": self.date_from.isoformat() if self.date_from else None,
            "date_to": self.date_to.isoformat() if self.date_to else None,
            "min_amount": str(self.min_amount) if self.min_amount is not None else None,
            "max_amount": str(self.max_amount) if self.max_amount is not None else None,
            "include_failed": self.include_failed,
            "include_pending": self.include_pending,
            "include_reversed": self.include_reversed,
            "max_time_gap_hours": self.max_time_gap_hours,
            "cycle_prevention": self.cycle_prevention,
            "temporal_strict": self.temporal_strict,
            "same_timestamp_policy": self.same_timestamp_policy,
        }


def _validate_decimal_range(
    min_amount: Optional[Decimal],
    max_amount: Optional[Decimal],
    *,
    allow_negative: bool = False,
) -> tuple[Optional[Decimal], Optional[Decimal]]:
    try:
        minimum = Decimal(min_amount) if min_amount is not None else None
        maximum = Decimal(max_amount) if max_amount is not None else None
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValidationError("Invalid amount filter value.") from exc

    for label, value in (("min_amount", minimum), ("max_amount", maximum)):
        if value is None:
            continue

        if not value.is_finite():
            raise ValidationError(
                "Amount filters must be finite decimal values.",
                details={label: str(value)},
            )

        if not allow_negative and value < 0:
            raise ValidationError(
                "Amount filters must be non-negative.",
                details={label: str(value)},
            )

    if minimum is not None and maximum is not None and minimum > maximum:
        raise ValidationError(
            "min_amount must be less than or equal to max_amount.",
            details={
                "min_amount": str(minimum),
                "max_amount": str(maximum),
            },
        )

    return minimum, maximum


def _resolve_include_flag(
    requested: Optional[bool],
    setting_name: str,
    settings: Any,
    *,
    label: str,
) -> bool:
    allowed = _as_bool(_setting(settings, setting_name, False), False)

    if requested is None:
        return allowed

    requested_bool = bool(requested)

    if requested_bool and not allowed:
        raise ValidationError(
            f"Including {label} transactions is disabled by configuration.",
            details={
                "setting": setting_name,
                "requested": requested_bool,
                "allowed": allowed,
            },
        )

    return requested_bool


def graph_query_dependency(
    *,
    require_root: bool | None = None,
    default_hops: int = 2,
    default_max_nodes: int = 300,
    default_max_edges: int = 1000,
    default_max_paths: int = 20,
) -> Callable[..., GraphQueryParams]:
    """
    Create a bounded graph-query dependency.

    Whole-bank graph access is prohibited by default. Callers must provide a
    root account, or an explicitly allowed constrained source/destination query.
    """

    def dependency(
        root_account_id: Annotated[
            Optional[str],
            Query(max_length=128, description="Root account for bounded neighbourhood query"),
        ] = None,
        source_account_id: Annotated[
            Optional[str],
            Query(max_length=128, description="Optional source account for constrained query"),
        ] = None,
        destination_account_id: Annotated[
            Optional[str],
            Query(max_length=128, description="Optional destination account for constrained query"),
        ] = None,
        hops: Annotated[
            Optional[int],
            Query(ge=1, description="Neighbourhood hop limit"),
        ] = None,
        max_nodes: Annotated[
            Optional[int],
            Query(ge=1, description="Maximum returned nodes"),
        ] = None,
        max_edges: Annotated[
            Optional[int],
            Query(ge=1, description="Maximum returned edges"),
        ] = None,
        max_paths: Annotated[
            Optional[int],
            Query(ge=1, description="Maximum returned paths"),
        ] = None,
        date_from: Annotated[
            Optional[datetime],
            Query(description="Start timestamp, inclusive"),
        ] = None,
        date_to: Annotated[
            Optional[datetime],
            Query(description="End timestamp, inclusive"),
        ] = None,
        min_amount: Annotated[
            Optional[Decimal],
            Query(description="Minimum transaction amount"),
        ] = None,
        max_amount: Annotated[
            Optional[Decimal],
            Query(description="Maximum transaction amount"),
        ] = None,
        include_failed: Annotated[
            Optional[bool],
            Query(description="Include failed transactions if allowed"),
        ] = None,
        include_pending: Annotated[
            Optional[bool],
            Query(description="Include pending transactions if allowed"),
        ] = None,
        include_reversed: Annotated[
            Optional[bool],
            Query(description="Include reversed transactions if allowed"),
        ] = None,
        settings: SettingsDep = ...,
    ) -> GraphQueryParams:
        if not _as_bool(_setting(settings, "GRAPH_ENABLED", True), True):
            raise FeatureFlagDisabledError("Graph analytics are disabled.")

        allow_whole_bank = _as_bool(
            _setting(settings, "GRAPH_ALLOW_WHOLE_BANK_QUERY", False),
            False,
        )
        effective_require_root = require_root

        if effective_require_root is None:
            effective_require_root = _as_bool(
                _setting(settings, "GRAPH_REQUIRE_ROOT", True),
                True,
            )

        root = str(root_account_id).strip() if root_account_id else None
        source = str(source_account_id).strip() if source_account_id else None
        destination = str(destination_account_id).strip() if destination_account_id else None

        has_constrained_query = bool(root or source or destination)

        if not has_constrained_query and not allow_whole_bank:
            raise UnboundedGraphQueryProhibitedError(
                "Graph queries must provide root_account_id or a constrained "
                "source/destination account."
            )

        if effective_require_root and not root:
            raise UnboundedGraphQueryProhibitedError(
                "This graph endpoint requires root_account_id."
            )

        max_hops = max(1, _as_int(_setting(settings, "GRAPH_MAX_HOPS", 3), 3))
        effective_hops = hops if hops is not None else default_hops
        effective_hops = max(1, min(int(effective_hops), max_hops))

        if hops is not None and int(hops) > max_hops:
            raise GraphLimitExceededError.limit("hops", max_hops, int(hops))

        configured_max_nodes = max(1, _as_int(_setting(settings, "GRAPH_MAX_NODES", 500), 500))
        effective_max_nodes = max_nodes if max_nodes is not None else default_max_nodes
        effective_max_nodes = max(1, min(int(effective_max_nodes), configured_max_nodes))

        if max_nodes is not None and int(max_nodes) > configured_max_nodes:
            raise GraphLimitExceededError.limit("max_nodes", configured_max_nodes, int(max_nodes))

        configured_max_edges = max(1, _as_int(_setting(settings, "GRAPH_MAX_EDGES", 1500), 1500))
        effective_max_edges = max_edges if max_edges is not None else default_max_edges
        effective_max_edges = max(1, min(int(effective_max_edges), configured_max_edges))

        if max_edges is not None and int(max_edges) > configured_max_edges:
            raise GraphLimitExceededError.limit("max_edges", configured_max_edges, int(max_edges))

        configured_max_paths = max(1, _as_int(_setting(settings, "GRAPH_MAX_PATHS", 20), 20))
        effective_max_paths = max_paths if max_paths is not None else default_max_paths
        effective_max_paths = max(1, min(int(effective_max_paths), configured_max_paths))

        if max_paths is not None and int(max_paths) > configured_max_paths:
            raise GraphLimitExceededError.limit("max_paths", configured_max_paths, int(max_paths))

        start = _ensure_utc(date_from)
        end = _ensure_utc(date_to)

        if start is not None and end is not None and start > end:
            raise ValidationError(
                "date_from must be earlier than or equal to date_to.",
                details={
                    "date_from": start.isoformat(),
                    "date_to": end.isoformat(),
                },
            )

        max_date_span_days = max(
            1,
            _as_int(_setting(settings, "GRAPH_MAX_DATE_SPAN_DAYS", 90), 90),
        )

        if start is not None and end is not None:
            span = end - start
            max_delta = timedelta(days=max_date_span_days)

            if span > max_delta:
                raise GraphLimitExceededError.limit(
                    "date_span_days",
                    max_date_span_days,
                    int(span.total_seconds() // 86400),
                    message="Graph query date span exceeds configured maximum.",
                )

        minimum, maximum = _validate_decimal_range(min_amount, max_amount)

        effective_include_failed = _resolve_include_flag(
            include_failed,
            "GRAPH_INCLUDE_FAILED_TRANSACTIONS",
            settings,
            label="failed",
        )
        effective_include_pending = _resolve_include_flag(
            include_pending,
            "GRAPH_INCLUDE_PENDING_TRANSACTIONS",
            settings,
            label="pending",
        )
        effective_include_reversed = _resolve_include_flag(
            include_reversed,
            "GRAPH_INCLUDE_REVERSED_TRANSACTIONS",
            settings,
            label="reversed",
        )

        return GraphQueryParams(
            root_account_id=root,
            source_account_id=source,
            destination_account_id=destination,
            hops=effective_hops,
            max_nodes=effective_max_nodes,
            max_edges=effective_max_edges,
            max_paths=effective_max_paths,
            date_from=start,
            date_to=end,
            min_amount=minimum,
            max_amount=maximum,
            include_failed=effective_include_failed,
            include_pending=effective_include_pending,
            include_reversed=effective_include_reversed,
            cycle_prevention=_as_bool(
                _setting(settings, "GRAPH_PATH_ALLOW_CYCLES", False),
                False,
            )
            is False,
            temporal_strict=_as_bool(
                _setting(settings, "GRAPH_STRICT_TIME_ORDER", True),
                True,
            ),
            same_timestamp_policy=str(
                _setting(settings, "GRAPH_SAME_TIMESTAMP_POLICY", "reject")
            ).strip().lower()
            or "reject",
        )

    return dependency


def money_trail_query_dependency(
    *,
    default_hops: int = 3,
    default_max_paths: int = 20,
) -> Callable[..., GraphQueryParams]:
    """
    Create a bounded candidate money-trail query dependency.

    Money trails are candidate flow paths constrained by direction, time,
    amount, and hop limits. They are not exact tracing of specific currency
    units and are not proof of wrongdoing.
    """

    def dependency(
        source_account_id: Annotated[
            Optional[str],
            Query(max_length=128, description="Required source account"),
        ] = None,
        destination_account_id: Annotated[
            Optional[str],
            Query(max_length=128, description="Optional destination account"),
        ] = None,
        hops: Annotated[
            Optional[int],
            Query(ge=1, description="Maximum path hops"),
        ] = None,
        max_paths: Annotated[
            Optional[int],
            Query(ge=1, description="Maximum returned paths"),
        ] = None,
        date_from: Annotated[
            Optional[datetime],
            Query(description="Start timestamp, inclusive"),
        ] = None,
        date_to: Annotated[
            Optional[datetime],
            Query(description="End timestamp, inclusive"),
        ] = None,
        min_amount: Annotated[
            Optional[Decimal],
            Query(description="Minimum transfer amount"),
        ] = None,
        max_amount: Annotated[
            Optional[Decimal],
            Query(description="Maximum transfer amount"),
        ] = None,
        max_time_gap_hours: Annotated[
            Optional[int],
            Query(ge=0, description="Maximum gap between consecutive transfers"),
        ] = None,
        settings: SettingsDep = ...,
    ) -> GraphQueryParams:
        if not _as_bool(_setting(settings, "MONEY_TRAIL_ENABLED", True), True):
            raise FeatureFlagDisabledError("Candidate money-trail search is disabled.")

        if not _as_bool(_setting(settings, "GRAPH_ENABLED", True), True):
            raise FeatureFlagDisabledError("Graph analytics are disabled.")

        source = str(source_account_id).strip() if source_account_id else None
        destination = str(destination_account_id).strip() if destination_account_id else None

        require_source = _as_bool(
            _setting(settings, "MONEY_TRAIL_REQUIRE_SOURCE", True),
            True,
        )

        if require_source and not source:
            raise ValidationError(
                "source_account_id is required for candidate money-trail search.",
                details={"source_account_id": None},
            )

        max_hops = max(
            1,
            _as_int(
                _setting(settings, "MONEY_TRAIL_MAX_HOPS", _setting(settings, "GRAPH_PATH_MAX_HOPS", 4)),
                4,
            ),
        )
        effective_hops = hops if hops is not None else default_hops
        effective_hops = max(1, min(int(effective_hops), max_hops))

        if hops is not None and int(hops) > max_hops:
            raise GraphLimitExceededError.limit("hops", max_hops, int(hops))

        configured_max_paths = max(
            1,
            _as_int(
                _setting(
                    settings,
                    "MONEY_TRAIL_MAX_PATHS",
                    _setting(settings, "GRAPH_PATH_MAX_RESULTS", 20),
                ),
                20,
            ),
        )
        effective_max_paths = max_paths if max_paths is not None else default_max_paths
        effective_max_paths = max(1, min(int(effective_max_paths), configured_max_paths))

        if max_paths is not None and int(max_paths) > configured_max_paths:
            raise GraphLimitExceededError.limit(
                "max_paths",
                configured_max_paths,
                int(max_paths),
            )

        start = _ensure_utc(date_from)
        end = _ensure_utc(date_to)

        if start is not None and end is not None and start > end:
            raise ValidationError(
                "date_from must be earlier than or equal to date_to.",
                details={
                    "date_from": start.isoformat(),
                    "date_to": end.isoformat(),
                },
            )

        max_date_span_days = max(
            1,
            _as_int(_setting(settings, "GRAPH_MAX_DATE_SPAN_DAYS", 90), 90),
        )

        if start is not None and end is not None:
            span = end - start
            max_delta = timedelta(days=max_date_span_days)

            if span > max_delta:
                raise GraphLimitExceededError.limit(
                    "date_span_days",
                    max_date_span_days,
                    int(span.total_seconds() // 86400),
                    message="Money-trail query date span exceeds configured maximum.",
                )

        minimum, maximum = _validate_decimal_range(min_amount, max_amount)

        max_gap_setting = max(
            0,
            _as_int(
                _setting(settings, "MONEY_TRAIL_MAX_TIME_GAP_HOURS", 72),
                72,
            ),
        )
        effective_max_gap = max_time_gap_hours if max_time_gap_hours is not None else max_gap_setting
        effective_max_gap = max(0, min(int(effective_max_gap), max_gap_setting))

        if max_time_gap_hours is not None and int(max_time_gap_hours) > max_gap_setting:
            raise GraphLimitExceededError.limit(
                "max_time_gap_hours",
                max_gap_setting,
                int(max_time_gap_hours),
            )

        cycle_prevention = _as_bool(
            _setting(settings, "MONEY_TRAIL_CYCLE_PREVENTION", True),
            True,
        )
        temporal_strict = _as_bool(
            _setting(settings, "MONEY_TRAIL_TEMPORAL_ORDER_STRICT", True),
            True,
        )
        same_timestamp_policy = str(
            _setting(settings, "MONEY_TRAIL_SAME_TIMESTAMP_POLICY", "reject")
        ).strip().lower() or "reject"

        return GraphQueryParams(
            root_account_id=None,
            source_account_id=source,
            destination_account_id=destination,
            hops=effective_hops,
            max_nodes=max(
                1,
                _as_int(_setting(settings, "GRAPH_MAX_NODES", 500), 500),
            ),
            max_edges=max(
                1,
                _as_int(_setting(settings, "GRAPH_MAX_EDGES", 1500), 1500),
            ),
            max_paths=effective_max_paths,
            date_from=start,
            date_to=end,
            min_amount=minimum,
            max_amount=maximum,
            include_failed=False,
            include_pending=False,
            include_reversed=False,
            max_time_gap_hours=effective_max_gap,
            cycle_prevention=cycle_prevention,
            temporal_strict=temporal_strict,
            same_timestamp_policy=same_timestamp_policy,
        )

    return dependency


# -----------------------------------------------------------------------------
# Safety and feature-flag dependencies
# -----------------------------------------------------------------------------


def require_synthetic_mode(*, allow_non_synthetic: bool = False) -> Callable[..., str]:
    """
    Dependency requiring synthetic dataset mode.

    This protects the synthetic-first principle for demo, seeding, ingestion,
    and analysis operations unless a deployment explicitly allows another mode.
    """

    async def dependency(settings: SettingsDep) -> str:
        mode = str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")).strip().lower()

        if mode != "synthetic" and not allow_non_synthetic:
            raise SyntheticDataRequiredError(
                "This operation requires BACKEND_DATASET_MODE=synthetic."
            )

        return mode

    return dependency


def require_not_production() -> Callable[..., None]:
    """
    Dependency blocking local/demo-only operations in production-like environments.
    """

    async def dependency(settings: SettingsDep) -> None:
        if _is_production_like(settings):
            raise ConfigurationError(
                "This operation is restricted to local synthetic demo environments."
            )

    return dependency


def require_feature_flag(
    flag_name: str,
    *,
    default: bool = False,
) -> Callable[..., bool]:
    """
    Dependency requiring a named feature flag to be enabled.
    """
    normalized_flag = str(flag_name).strip()

    if not normalized_flag:
        raise ConfigurationError("require_feature_flag() requires a flag name.")

    async def dependency(settings: SettingsDep) -> bool:
        enabled = _as_bool(_setting(settings, normalized_flag, default), default)

        if not enabled:
            raise FeatureFlagDisabledError(
                f"Feature flag {normalized_flag} is disabled.",
                details={"flag": normalized_flag},
            )

        return True

    return dependency


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "AmountRangeParams",
    "BearerTokenDep",
    "CurrentUser",
    "DateRangeParams",
    "GraphQueryParams",
    "IdempotencyKeyDep",
    "OptionalUser",
    "PageParams",
    "Permission",
    "RateLimitRule",
    "RequestIDDep",
    "SearchParams",
    "SessionDep",
    "SettingsDep",
    "TokenPayload",
    "apply_pagination",
    "amount_range_dependency",
    "date_range_dependency",
    "decode_access_token",
    "get_api_settings",
    "get_bearer_token",
    "get_current_user",
    "get_idempotency_key",
    "get_optional_current_user",
    "get_request_id",
    "graph_query_dependency",
    "money_trail_query_dependency",
    "pagination_dependency",
    "parse_rate_limit",
    "rate_limited",
    "require_feature_flag",
    "require_not_production",
    "require_permission",
    "require_roles",
    "require_synthetic_mode",
    "search_dependency",
]