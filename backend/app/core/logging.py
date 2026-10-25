"""
MULEGUARD backend structured logging.

This module configures safe, structured logging for the MULEGUARD backend.

Primary responsibilities:

- configure root and component loggers from typed runtime settings;
- support human-readable console output and machine-readable JSON output;
- redact secrets, tokens, passwords, database URLs, raw complaint narratives,
  and leakage-prone metadata before they reach any log handler;
- enrich log records with active request and correlation IDs when available;
- keep log volume bounded and avoid echoing request/response bodies by default;
- remain import-safe and dependency-light.

Security and product-safety rules enforced here:

- Passwords, bearer tokens, API keys, secrets, and credentials are never logged.
- Raw complaint narratives are never logged; only safe length/digest metadata is
  permitted when explicitly attached by callers.
- Database URLs are redacted to hide credentials.
- Request/response bodies are not logged by default.
- Log output is bounded and sanitized.
- Logging never triggers automatic adverse customer action.

Explicit non-goals:

- This module does not ship logs to external aggregators.
- This module does not implement distributed tracing.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Logs describe synthetic
investigative workflows only and must not be interpreted as proof of wrongdoing.
"""

from __future__ import annotations

import json
import logging
import logging.config
import re
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Final, Optional

logger = logging.getLogger("muleguard.backend.core.logging")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_DEFAULT_LEVEL: Final[str] = "INFO"
_DEFAULT_FORMAT: Final[str] = "console"

_CONSOLE_FORMAT: Final[str] = (
    "%(asctime)s [%(levelname)s] %(name)s "
    "request_id=%(request_id)s correlation_id=%(correlation_id)s %(message)s"
)

_CONSOLE_DATE_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S%z"

_MAX_VALUE_LENGTH: Final[int] = 512
_MAX_NARRATIVE_LOG_CHARS: Final[int] = 200

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

# Sensitive key names that must never be logged verbatim.
_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
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
        "identifier_hash",
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

# URL credential redaction pattern: scheme://user:password@host
_URL_CREDENTIAL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://(?P<user>[^:/@]+):(?P<password>[^@]+)@"
)

_BEARER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(bearer\s+)[a-z0-9._~+/=-]+"
)

_REDACTED: Final[str] = "***REDACTED***"


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


def _parse_level(value: Any) -> int:
    """
    Parse a logging level from a setting value.
    """
    text = str(value or _DEFAULT_LEVEL).strip().upper()

    level = logging.getLevelName(text)

    if isinstance(level, int):
        return level

    return logging.INFO


def _clean_text(value: Any, limit: int = _MAX_VALUE_LENGTH) -> str:
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
    Return True when a key appears sensitive or leakage-prone.
    """
    lowered = key.strip().lower()

    if lowered in _SENSITIVE_KEYS:
        return True

    return any(token in lowered for token in _SENSITIVE_KEY_TOKENS)


def _redact_url_credentials(value: str) -> str:
    """
    Redact credentials embedded in URLs such as database connection strings.
    """
    return _URL_CREDENTIAL_RE.sub(
        lambda match: f"{match.group('scheme')}://{match.group('user')}:{_REDACTED}@",
        value,
    )


def _redact_bearer_tokens(value: str) -> str:
    """
    Redact bearer token values from text.
    """
    return _BEARER_RE.sub(r"\1" + _REDACTED, value)


def _redact_text(value: str) -> str:
    """
    Apply all text-level redactions.
    """
    value = _redact_url_credentials(value)
    value = _redact_bearer_tokens(value)
    return value


def _redact_value(value: Any, depth: int = 0) -> Any:
    """
    Recursively redact sensitive values from arbitrary structures.
    """
    if depth > 6:
        return "[truncated-depth]"

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return value

    if isinstance(value, str):
        return _clean_text(_redact_text(value))

    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}

        for raw_key, raw_value in list(value.items())[:100]:
            key = str(raw_key)

            if _is_sensitive_key(key):
                redacted[key] = _REDACTED
            else:
                redacted[key] = _redact_value(raw_value, depth + 1)

        return redacted

    if isinstance(value, (list, tuple, set)):
        return [_redact_value(item, depth + 1) for item in list(value)[:100]]

    return _clean_text(_redact_text(str(value)))


# -----------------------------------------------------------------------------
# Request context enrichment
# -----------------------------------------------------------------------------


def _get_request_context() -> dict[str, Optional[str]]:
    """
    Return active request/correlation IDs when available.

    This helper defensively imports the request-ID middleware context and falls
    back to "-" values so logging remains safe when no request context exists.
    """
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None

    try:
        from app.api.middleware.request_id import (
            get_current_correlation_id,
            get_current_request_id,
        )

        request_id = get_current_request_id()
        correlation_id = get_current_correlation_id()
    except Exception:
        request_id = None
        correlation_id = None

    return {
        "request_id": request_id or "-",
        "correlation_id": correlation_id or "-",
    }


class RequestContextFilter(logging.Filter):
    """
    Enriches log records with safe request and correlation IDs.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        context = _get_request_context()

        if not hasattr(record, "request_id"):
            record.request_id = context["request_id"]

        if not hasattr(record, "correlation_id"):
            record.correlation_id = context["correlation_id"]

        return True


# -----------------------------------------------------------------------------
# Redaction filter
# -----------------------------------------------------------------------------


class RedactingFilter(logging.Filter):
    """
    Scrubs sensitive data from log records before they reach handlers.

    This filter redacts:

    - the formatted message string;
    - record arguments when they are mappings;
    - common attribute names that may carry secrets.

    It is intentionally conservative and may over-redact in ambiguous cases.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # Redact the primary message text.
            if isinstance(record.msg, str):
                record.msg = _redact_text(record.msg)

            # Redact mapping-style arguments.
            if record.args:
                if isinstance(record.args, Mapping):
                    record.args = _redact_value(record.args)
                elif isinstance(record.args, tuple):
                    record.args = tuple(_redact_value(item) for item in record.args)

            # Redact sensitive attributes if present.
            for attr in ("password", "token", "secret", "authorization", "narrative"):
                if hasattr(record, attr):
                    setattr(record, attr, _REDACTED)

        except Exception:
            # Never allow redaction to break logging entirely.
            pass

        return True


# -----------------------------------------------------------------------------
# Formatters
# -----------------------------------------------------------------------------


class SafeConsoleFormatter(logging.Formatter):
    """
    Human-readable console formatter with safe defaults.
    """

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "request_id"):
            record.request_id = "-"

        if not hasattr(record, "correlation_id"):
            record.correlation_id = "-"

        try:
            return super().format(record)
        except Exception:
            return _clean_text(record.getMessage())


class JsonFormatter(logging.Formatter):
    """
    Machine-readable JSON formatter with safe field extraction.
    """

    _RESERVED_ATTRS: Final[frozenset[str]] = frozenset(
        {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "taskName",
            "message",
            "asctime",
        }
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": _clean_text(_redact_text(record.getMessage())),
        }

        request_id = getattr(record, "request_id", None)
        correlation_id = getattr(record, "correlation_id", None)

        if request_id:
            payload["request_id"] = str(request_id)

        if correlation_id:
            payload["correlation_id"] = str(correlation_id)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # Include safe extra fields attached by callers.
        for key, value in record.__dict__.items():
            if key in self._RESERVED_ATTRS:
                continue

            if key.startswith("_"):
                continue

            if _is_sensitive_key(key):
                payload[key] = _REDACTED
            else:
                payload[key] = _redact_value(value)

        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except Exception:
            return json.dumps(
                {
                    "timestamp": payload.get("timestamp"),
                    "level": payload.get("level"),
                    "logger": payload.get("logger"),
                    "message": _clean_text(payload.get("message", "")),
                },
                ensure_ascii=False,
            )


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------


def configure_logging(settings: Any | None = None) -> None:
    """
    Configure MULEGUARD logging from typed runtime settings.

    This function is idempotent enough for application startup and tests. It
    replaces handlers on managed loggers to avoid duplicate output.
    """
    level = _parse_level(_setting(settings, "BACKEND_LOG_LEVEL", _DEFAULT_LEVEL))
    log_format = str(
        _setting(settings, "BACKEND_LOG_FORMAT", _DEFAULT_FORMAT) or _DEFAULT_FORMAT
    ).strip().lower()
    use_json = _as_bool(_setting(settings, "BACKEND_LOG_JSON", False), False)
    use_json = use_json or log_format == "json"

    max_narrative_chars = max(
        0,
        _as_int(
            _setting(settings, "BACKEND_MAX_NARRATIVE_LOG_CHARS", _MAX_NARRATIVE_LOG_CHARS),
            _MAX_NARRATIVE_LOG_CHARS,
        ),
    )

    formatter: logging.Formatter

    if use_json:
        formatter = JsonFormatter()
    else:
        formatter = SafeConsoleFormatter(
            fmt=_CONSOLE_FORMAT,
            datefmt=_CONSOLE_DATE_FORMAT,
        )

    stream_handler = logging.StreamHandler(stream=sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(RedactingFilter())
    stream_handler.addFilter(RequestContextFilter())

    handlers: list[logging.Handler] = [stream_handler]

    # Optional file handler.
    log_to_file = _as_bool(_setting(settings, "BACKEND_LOG_TO_FILE", False), False)

    if log_to_file:
        log_file = str(_setting(settings, "BACKEND_LOG_FILE", "var/logs/backend.log"))

        try:
            import os

            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)

            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.addFilter(RedactingFilter())
            file_handler.addFilter(RequestContextFilter())
            handlers.append(file_handler)

        except Exception:
            logger.warning("Unable to configure file logging for %s.", log_file)

    # Configure root logger.
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to keep configuration idempotent.
    for existing_handler in list(root_logger.handlers):
        root_logger.removeHandler(existing_handler)

    for handler in handlers:
        root_logger.addHandler(handler)

    # Component loggers.
    logging.getLogger("muleguard").setLevel(level)
    logging.getLogger("uvicorn").setLevel(level)
    logging.getLogger("uvicorn.error").setLevel(level)
    logging.getLogger("uvicorn.access").setLevel(level)
    logging.getLogger("fastapi").setLevel(level)

    # SQLAlchemy echo is controlled by DB_ECHO, not logging config.
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO
        if _as_bool(_setting(settings, "BACKEND_LOG_SQL", False), False)
        else logging.WARNING
    )

    # Store narrative cap for use by redaction helpers elsewhere.
    global _MAX_NARRATIVE_LOG_CHARS_RUNTIME
    _MAX_NARRATIVE_LOG_CHARS_RUNTIME = max_narrative_chars

    logger.debug(
        "Logging configured: level=%s format=%s json=%s file=%s",
        logging.getLevelName(level),
        log_format,
        use_json,
        log_to_file,
    )


# Runtime narrative cap populated by configure_logging.
_MAX_NARRATIVE_LOG_CHARS_RUNTIME: int = _MAX_NARRATIVE_LOG_CHARS


def get_max_narrative_log_chars() -> int:
    """
    Return the configured maximum narrative log characters.
    """
    return _MAX_NARRATIVE_LOG_CHARS_RUNTIME


# -----------------------------------------------------------------------------
# Safe logging helpers
# -----------------------------------------------------------------------------


def get_logger(name: str) -> logging.Logger:
    """
    Return a namespaced logger under the MULEGUARD hierarchy.
    """
    if name.startswith("muleguard"):
        return logging.getLogger(name)

    return logging.getLogger(f"muleguard.backend.{name}")


def safe_log_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """
    Return a redacted copy of metadata suitable for logging.
    """
    result = _redact_value(metadata)

    if isinstance(result, Mapping):
        return dict(result)

    return {"value": result}


def narrative_log_summary(narrative: Optional[str]) -> dict[str, Any]:
    """
    Return safe narrative metadata for logging.

    The full narrative is never logged. Only length and a truncated, redacted
    excerpt are provided when explicitly requested by callers.
    """
    if not narrative:
        return {
            "narrative_length": 0,
            "narrative_excerpt": "",
        }

    max_chars = get_max_narrative_log_chars()
    excerpt = _clean_text(_redact_text(narrative), max_chars)

    return {
        "narrative_length": len(narrative),
        "narrative_excerpt": excerpt,
    }


__all__ = [
    "JsonFormatter",
    "RedactingFilter",
    "RequestContextFilter",
    "SafeConsoleFormatter",
    "configure_logging",
    "get_logger",
    "get_max_narrative_log_chars",
    "narrative_log_summary",
    "safe_log_metadata",
]