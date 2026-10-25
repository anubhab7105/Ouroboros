"""
MULEGUARD backend lifecycle orchestration.

This module provides a reusable, defensive startup/shutdown manager for the
FastAPI application.

Responsibilities:

- validate runtime safety policy before the application serves traffic;
- enforce synthetic-first and production-safety boundaries;
- block dangerous feature flags that would violate MULEGUARD principles;
- verify database connectivity without leaking connection secrets;
- preflight optional ML artifact availability and expose explicit fallback mode;
- ensure required runtime directories exist where practical;
- maintain safe lifecycle state for health/readiness endpoints;
- dispose database resources cleanly during shutdown;
- provide a FastAPI-compatible lifespan context manager.

Design rules:

- The database remains the source of truth.
- Missing optional ML artifacts must produce explicit fallback behaviour, not
  fabricated model claims.
- Production-like environments must not enable demo seeding, development users,
  placeholder secrets, remote debugging, or public docs unless explicitly
  overridden by a safe deployment process.
- Automatic adverse customer action is prohibited.
- Unbounded graph queries are prohibited.
- Label leakage and future-information leakage are prohibited.
- Error payloads and logs must not expose secrets, tokens, passwords, raw
  complaint narratives, database URLs, or real customer data.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import logging
import os
import time
from collections.abc import Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Final, Optional

from fastapi import FastAPI

from app.core.config import Settings, get_settings
from app.db import check_database_health, dispose_engine

logger = logging.getLogger("muleguard.backend.lifecycle")


# -----------------------------------------------------------------------------
# Constants and small helpers
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_PLACEHOLDER_MARKERS: Final[tuple[str, ...]] = (
    "change_me",
    "changeme",
    "placeholder",
    "replace_me",
    "replace-me",
    "your_",
    "example_",
    "todo",
    "fixme",
)

_SAFE_DB_HEALTH_KEYS: Final[tuple[str, ...]] = (
    "ok",
    "dialect",
    "driver",
    "latency_ms",
    "error_code",
)


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


def _contains_placeholder(value: str | None) -> bool:
    """
    Detect obvious template or placeholder secret values.

    This is intentionally conservative and is not a replacement for a full
    secret scanner.
    """
    if not value:
        return True

    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _read_signal(obj: Any, name: str, default: Any = None) -> Any:
    """
    Read a field from either a mapping or an object.
    """
    if isinstance(obj, Mapping):
        return obj.get(name, default)

    return getattr(obj, name, default)


def _utcnow() -> datetime:
    """
    Return timezone-aware UTC current time.
    """
    return datetime.now(timezone.utc)


# -----------------------------------------------------------------------------
# Lifecycle enums and result model
# -----------------------------------------------------------------------------


class LifecyclePhase(str, Enum):
    """
    High-level application lifecycle phase.
    """

    PENDING = "pending"
    STARTING = "starting"
    STARTED = "started"
    DEGRADED = "degraded"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class CheckStatus(str, Enum):
    """
    Status for an individual lifecycle check.
    """

    OK = "ok"
    SKIPPED = "skipped"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


@dataclass(slots=True)
class CheckResult:
    """
    Safe, structured result from a lifecycle check.

    Details must not contain secrets, tokens, passwords, raw narratives,
    database URLs, or real customer data.
    """

    name: str
    status: CheckStatus
    message: str
    duration_ms: float | None = None
    details: dict[str, Any] = field(default_factory=dict)
    fatal: bool = False

    @property
    def is_failure(self) -> bool:
        """
        Return True when the check represents a failure or unavailable state.
        """
        return self.status in {CheckStatus.FAILED, CheckStatus.UNAVAILABLE}


# -----------------------------------------------------------------------------
# Lifecycle manager
# -----------------------------------------------------------------------------


class LifecycleManager:
    """
    Central startup/shutdown orchestrator for the MULEGUARD backend.

    This class is intentionally conservative. It validates safety policy,
    performs lightweight dependency preflight, and records safe diagnostic state
    for health/readiness endpoints.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings: Settings | Mapping[str, Any] = settings or get_settings()

        self.phase: LifecyclePhase = LifecyclePhase.PENDING
        self.started_at: Optional[datetime] = None
        self.stopped_at: Optional[datetime] = None

        self.results: list[CheckResult] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []

        self.db_health: dict[str, Any] | None = None
        self.ml_scoring_mode: str = str(
            self._setting("ML_ACTIVE_SCORING_MODE", "auto")
        )
        self.model_version: str | None = (
            str(self._setting("ML_ACTIVE_MODEL_VERSION"))
            if self._setting("ML_ACTIVE_MODEL_VERSION") is not None
            else None
        )

    # -------------------------------------------------------------------------
    # Setting helpers
    # -------------------------------------------------------------------------

    def _setting(self, name: str, default: Any = None) -> Any:
        """
        Read a setting from either a Pydantic settings object or mapping.
        """
        if isinstance(self.settings, Mapping):
            return self.settings.get(name, default)

        return getattr(self.settings, name, default)

    def _flag_true(self, name: str, default: bool = False) -> bool:
        """
        Return True when a boolean-like setting is enabled.
        """
        return _as_bool(self._setting(name, default), default)

    def _flag_false(self, name: str, default: bool = True) -> bool:
        """
        Return True when a boolean-like safeguard setting is disabled.
        """
        return not _as_bool(self._setting(name, default), default)

    def _is_production_like(self) -> bool:
        """
        Return True when the runtime environment is production-like.
        """
        env = str(self._setting("BACKEND_ENV", "local")).strip().lower()

        configured_values = _csv(
            self._setting(
                "BACKEND_PRODUCTION_LIKE_ENVS",
                "production,staging,prod,stage",
            )
        )

        production_like_values = {value.lower() for value in configured_values}

        if not production_like_values:
            production_like_values = {"production", "staging", "prod", "stage"}

        return env in production_like_values

    # -------------------------------------------------------------------------
    # Configuration and policy validation
    # -------------------------------------------------------------------------

    def validate_configuration(self) -> list[CheckResult]:
        """
        Validate runtime configuration against MULEGUARD safety policy.

        Returns a list of safe CheckResult objects. Fatal failures should prevent
        application startup. Non-fatal failures produce degraded mode.
        """
        results: list[CheckResult] = []

        env = str(self._setting("BACKEND_ENV", "local")).strip().lower()
        production_like = self._is_production_like()

        def add_failure(message: str, *, code: str | None = None) -> None:
            details: dict[str, Any] = {}
            if code:
                details["code"] = code

            results.append(
                CheckResult(
                    name="configuration",
                    status=CheckStatus.FAILED,
                    message=message,
                    details=details,
                    fatal=True,
                )
            )

        def add_warning(message: str, *, code: str | None = None) -> None:
            details: dict[str, Any] = {}
            if code:
                details["code"] = code

            results.append(
                CheckResult(
                    name="configuration",
                    status=CheckStatus.DEGRADED,
                    message=message,
                    details=details,
                    fatal=False,
                )
            )

        # ---------------------------------------------------------------------
        # Production-like hard blocks
        # ---------------------------------------------------------------------
        if production_like:
            if self._flag_true("BACKEND_DEBUG"):
                add_failure(
                    "BACKEND_DEBUG=true is not allowed in production-like environments.",
                    code="DEBUG_ENABLED_IN_PRODUCTION",
                )

            if self._flag_true("SEED_DEV_USERS") and self._flag_true(
                "BACKEND_BLOCK_DEV_USERS_IN_PRODUCTION", True
            ):
                add_failure(
                    "SEED_DEV_USERS=true is not allowed in production-like environments.",
                    code="DEV_USERS_ENABLED_IN_PRODUCTION",
                )

            if self._flag_true("SEED_DEMO_DATA") and self._flag_true(
                "BACKEND_BLOCK_SEEDING_IN_PRODUCTION", True
            ):
                add_failure(
                    "SEED_DEMO_DATA=true is not allowed in production-like environments.",
                    code="DEMO_SEEDING_ENABLED_IN_PRODUCTION",
                )

            if self._flag_true("AUTH_DEMO_MODE") and self._flag_true(
                "BACKEND_BLOCK_DEMO_FEATURES_IN_PRODUCTION", True
            ):
                add_failure(
                    "AUTH_DEMO_MODE=true is not allowed in production-like environments.",
                    code="AUTH_DEMO_MODE_ENABLED_IN_PRODUCTION",
                )

            if self._flag_true("BACKEND_OPENAPI_ENABLED") and self._flag_true(
                "BACKEND_BLOCK_OPENAPI_IN_PRODUCTION", True
            ):
                add_failure(
                    "BACKEND_OPENAPI_ENABLED=true is not allowed in production-like environments.",
                    code="OPENAPI_ENABLED_IN_PRODUCTION",
                )

            if self._flag_true("BACKEND_DOCS_ENABLED") and self._flag_true(
                "BACKEND_BLOCK_OPENAPI_IN_PRODUCTION", True
            ):
                add_failure(
                    "BACKEND_DOCS_ENABLED=true is not allowed in production-like environments.",
                    code="DOCS_ENABLED_IN_PRODUCTION",
                )

            if self._flag_true("REMOTE_DEBUGGING_ENABLED") or self._flag_true(
                "DEBUGPY_ENABLED"
            ):
                add_failure(
                    "Remote debugging is not allowed in production-like environments.",
                    code="REMOTE_DEBUGGING_ENABLED",
                )

            if self._flag_true("OUTBOUND_NETWORK_ENABLED"):
                add_failure(
                    "OUTBOUND_NETWORK_ENABLED=true is not allowed in production-like environments by default.",
                    code="OUTBOUND_NETWORK_ENABLED_IN_PRODUCTION",
                )

            if self._flag_true("FILE_UPLOAD_ENABLED"):
                add_failure(
                    "FILE_UPLOAD_ENABLED=true requires explicit security review and is not allowed in production-like environments by default.",
                    code="FILE_UPLOAD_ENABLED_IN_PRODUCTION",
                )

        # ---------------------------------------------------------------------
        # Secret strength validation
        # ---------------------------------------------------------------------
        secret_key = str(self._setting("BACKEND_SECRET_KEY", "") or "")

        if env != "local" and self._flag_true(
            "BACKEND_REQUIRE_STRONG_SECRET_IN_NON_LOCAL", True
        ):
            if _contains_placeholder(secret_key):
                add_failure(
                    "BACKEND_SECRET_KEY must be set to a strong non-placeholder value in non-local environments.",
                    code="PLACEHOLDER_SECRET_KEY",
                )

        if env == "local" and _contains_placeholder(secret_key):
            add_warning(
                "BACKEND_SECRET_KEY is missing or uses a placeholder value. This is allowed only for local synthetic development.",
                code="LOCAL_PLACEHOLDER_SECRET_KEY",
            )

        # ---------------------------------------------------------------------
        # Local/demo warnings
        # ---------------------------------------------------------------------
        if env == "local":
            if self._flag_true("SEED_DEMO_DATA") or self._flag_true("SEED_DEV_USERS"):
                add_warning(
                    "Local synthetic/demo mode is enabled. Do not expose this instance publicly without hardening authentication, TLS, rate limits, audit retention, and deployment controls.",
                    code="LOCAL_DEMO_MODE_ENABLED",
                )

            if not self._flag_true("BACKEND_SAFE_MODE", True):
                add_warning(
                    "BACKEND_SAFE_MODE=false weakens default safety behaviour.",
                    code="SAFE_MODE_DISABLED",
                )

        # ---------------------------------------------------------------------
        # Synthetic-first policy checks
        # ---------------------------------------------------------------------
        dataset_mode = str(self._setting("BACKEND_DATASET_MODE", "synthetic")).strip().lower()

        if dataset_mode != "synthetic":
            if production_like:
                add_failure(
                    "BACKEND_DATASET_MODE must be 'synthetic' in production-like environments unless a separate approved real-data deployment policy exists.",
                    code="NON_SYNTHETIC_DATASET_MODE",
                )
            else:
                add_warning(
                    "BACKEND_DATASET_MODE is not 'synthetic'. MULEGUARD is synthetic-first by default.",
                    code="NON_SYNTHETIC_DATASET_MODE_LOCAL",
                )

        # ---------------------------------------------------------------------
        # Hard product-policy prohibitions
        # ---------------------------------------------------------------------
        always_fatal_true_flags: tuple[tuple[str, str], ...] = (
            ("AUTOMATIC_ENFORCEMENT_ENABLED", "Automatic enforcement is prohibited."),
            ("AUTO_FREEZE_ENABLED", "Automatic account freezing is prohibited."),
            ("AUTO_BLOCK_PAYMENT_ENABLED", "Automatic payment blocking is prohibited."),
            ("AUTO_BLACKLIST_ENABLED", "Automatic blacklisting is prohibited."),
            ("ADVERSE_ACTION_AUTOMATION_ENABLED", "Automated adverse customer action is prohibited."),
            ("DEANONYMISATION_ENABLED", "Deanonymisation capabilities are prohibited."),
            ("SURVEILLANCE_ENABLED", "Surveillance capabilities are prohibited."),
            ("COVERT_MONITORING_ENABLED", "Covert monitoring capabilities are prohibited."),
            ("USER_UPLOADED_MODEL_ENABLED", "User-uploaded model deserialization is prohibited."),
            ("PICKLE_UNSAFE_LOAD_ENABLED", "Unsafe pickle loading is prohibited."),
            ("XML_EXTERNAL_ENTITIES_ENABLED", "XML external entity processing is prohibited."),
            ("YAML_UNSAFE_LOAD_ENABLED", "Unsafe YAML loading is prohibited."),
            ("GRAPH_ALLOW_WHOLE_BANK_QUERY", "Unbounded whole-bank graph queries are prohibited."),
            ("FEATURE_ALLOW_LABELS_IN_EXPORT", "Exporting ground-truth labels into feature surfaces is prohibited."),
            ("FEATURE_ALLOW_FUTURE_TRANSACTIONS", "Using future transactions in point-in-time features is prohibited."),
            ("FEATURE_ALLOW_FUTURE_COMPLAINTS", "Using future complaints in point-in-time features is prohibited."),
            ("FEATURE_ALLOW_FUTURE_INVESTIGATION_OUTCOMES", "Using future investigation outcomes in point-in-time features is prohibited."),
        )

        for flag_name, message in always_fatal_true_flags:
            if self._flag_true(flag_name):
                add_failure(
                    f"{flag_name}=true violates MULEGUARD safety policy. {message}",
                    code=f"POLICY_FLAG_{flag_name}",
                )

        # Safeguards that must remain enabled.
        unsafe_false_flags: tuple[tuple[str, str], ...] = (
            ("ML_DISABLE_UNTRUSTED_PICKLE_UPLOADS", "Untrusted pickle upload protection must remain enabled."),
            ("GRAPH_REQUIRE_ROOT", "Graph queries must require a root account or constrained source/destination."),
            ("FEATURE_STRICT_POINT_IN_TIME", "Strict point-in-time feature computation must remain enabled."),
            ("ML_LABEL_LEAKAGE_CHECK", "ML label leakage checks must remain enabled."),
            ("SEED_LEAKAGE_GUARD", "Synthetic seed leakage guard must remain enabled."),
        )

        for flag_name, message in unsafe_false_flags:
            if self._flag_false(flag_name, True):
                add_failure(
                    f"{flag_name}=false violates MULEGUARD safety policy. {message}",
                    code=f"POLICY_FLAG_FALSE_{flag_name}",
                )

        # ---------------------------------------------------------------------
        # Optional/local-only risky flags
        # ---------------------------------------------------------------------
        if self._flag_true("OUTBOUND_NETWORK_ENABLED") and not production_like:
            add_warning(
                "OUTBOUND_NETWORK_ENABLED=true is disabled by default for the synthetic local prototype. Ensure SSRF protections, allowlists, timeouts, and audit controls are implemented before enabling.",
                code="OUTBOUND_NETWORK_ENABLED_LOCAL",
            )

        if self._flag_true("FILE_UPLOAD_ENABLED") and not production_like:
            add_warning(
                "FILE_UPLOAD_ENABLED=true requires strict upload validation, size limits, magic validation, quarantine, path-traversal protection, and audit controls.",
                code="FILE_UPLOAD_ENABLED_LOCAL",
            )

        if self._flag_true("SHAP_ENABLED"):
            add_warning(
                "SHAP_ENABLED=true is optional. Core functionality must not fail if SHAP is unavailable, and explanations must remain non-causal.",
                code="SHAP_ENABLED",
            )

        if self._flag_true("ML_CALIBRATION_ENABLED"):
            add_warning(
                "ML_CALIBRATION_ENABLED=true must be accompanied by documented calibration evaluation before probability claims are made.",
                code="ML_CALIBRATION_ENABLED",
            )

        if not results:
            results.append(
                CheckResult(
                    name="configuration",
                    status=CheckStatus.OK,
                    message="Runtime configuration passed MULEGUARD safety validation.",
                )
            )

        return results

    # -------------------------------------------------------------------------
    # Runtime directory check
    # -------------------------------------------------------------------------

    async def _ensure_runtime_directories(self) -> CheckResult:
        """
        Best-effort creation of safe runtime directories.

        This does not create arbitrary paths. It only uses configured local
        runtime directories such as var/, reports/, and ML artifact directories.
        """
        started_at = time.perf_counter()

        candidate_paths: list[str] = [
            str(self._setting("VAR_DIR", "var") or ""),
            str(self._setting("LOG_DIR", "var/logs") or ""),
            str(self._setting("TMP_DIR", "var/tmp") or ""),
            str(self._setting("CACHE_DIR", "var/cache") or ""),
            str(self._setting("REPORT_OUTPUT_DIR", "var/reports") or ""),
            str(self._setting("ML_ARTIFACT_DIR", "app/ml/artifacts") or ""),
        ]

        created: list[str] = []
        failed: list[dict[str, str]] = []

        def _create_directories() -> tuple[list[str], list[dict[str, str]]]:
            local_created: list[str] = []
            local_failed: list[dict[str, str]] = []

            for raw_path in candidate_paths:
                path = raw_path.strip()

                if not path:
                    continue

                try:
                    os.makedirs(path, exist_ok=True)
                    local_created.append(os.path.basename(path) or path)
                except OSError as exc:
                    local_failed.append(
                        {
                            "path_basename": os.path.basename(path) or "<unknown>",
                            "error_type": type(exc).__name__,
                        }
                    )

            return local_created, local_failed

        created, failed = await asyncio.to_thread(_create_directories)

        duration_ms = round((time.perf_counter() - started_at) * 1000, 3)

        if failed:
            return CheckResult(
                name="runtime_directories",
                status=CheckStatus.DEGRADED,
                message="Some runtime directories could not be created.",
                duration_ms=duration_ms,
                details={
                    "created": created,
                    "failed": failed,
                },
                fatal=False,
            )

        return CheckResult(
            name="runtime_directories",
            status=CheckStatus.OK,
            message="Runtime directories are available.",
            duration_ms=duration_ms,
            details={"created": created},
            fatal=False,
        )

    # -------------------------------------------------------------------------
    # Database check
    # -------------------------------------------------------------------------

    async def _check_database(self) -> CheckResult:
        """
        Perform a lightweight database connectivity check.

        This does not run migrations. Migrations remain the documented schema
        management path.
        """
        started_at = time.perf_counter()

        timeout_seconds = max(
            0.1,
            _as_float(self._setting("DB_CONNECT_TIMEOUT_SECONDS", 5.0), 5.0),
        )

        health = await asyncio.to_thread(
            check_database_health,
            timeout_seconds=timeout_seconds,
        )

        duration_ms = round((time.perf_counter() - started_at) * 1000, 3)

        safe_details = {
            key: health[key]
            for key in _SAFE_DB_HEALTH_KEYS
            if key in health
        }

        self.db_health = safe_details

        if health.get("ok") is True:
            return CheckResult(
                name="database",
                status=CheckStatus.OK,
                message="Database connectivity check passed.",
                duration_ms=duration_ms,
                details=safe_details,
                fatal=False,
            )

        fail_on_unavailable = _as_bool(
            self._setting("HEALTH_FAIL_ON_DB_UNAVAILABLE", True),
            True,
        )

        status = (
            CheckStatus.UNAVAILABLE
            if health.get("error_code") == "DATABASE_UNAVAILABLE"
            else CheckStatus.FAILED
        )

        return CheckResult(
            name="database",
            status=status,
            message="Database connectivity check failed.",
            duration_ms=duration_ms,
            details=safe_details,
            fatal=fail_on_unavailable,
        )

    # -------------------------------------------------------------------------
    # ML preflight
    # -------------------------------------------------------------------------

    async def _preflight_ml(self) -> CheckResult:
        """
        Preflight optional ML artifact availability.

        The application must gracefully degrade when no trained artifact exists.
        It must not fabricate model probabilities or crash solely because
        optional ML artifacts are unavailable, unless ML_REQUIRE_TRAINED_MODEL
        is true.
        """
        started_at = time.perf_counter()

        fallback_label = str(
            self._setting("ML_FALLBACK_MODE_LABEL", "heuristic_fallback")
        )

        if not _as_bool(self._setting("ML_ENABLED", True), True):
            self.ml_scoring_mode = "ml_disabled"
            self.model_version = None

            return CheckResult(
                name="ml_preflight",
                status=CheckStatus.SKIPPED,
                message="ML subsystem disabled by configuration.",
                duration_ms=round((time.perf_counter() - started_at) * 1000, 3),
                details={
                    "scoring_mode": self.ml_scoring_mode,
                    "model_version": None,
                },
                fatal=False,
            )

        require_trained_model = _as_bool(
            self._setting("ML_REQUIRE_TRAINED_MODEL", False),
            False,
        )

        module_name = "app.ml.model_service"

        if importlib.util.find_spec(module_name) is None:
            if require_trained_model:
                return CheckResult(
                    name="ml_preflight",
                    status=CheckStatus.FAILED,
                    message="ML model service module not found and trained model is required.",
                    duration_ms=round((time.perf_counter() - started_at) * 1000, 3),
                    details={"module": module_name},
                    fatal=True,
                )

            self.ml_scoring_mode = fallback_label
            self.model_version = None

            return CheckResult(
                name="ml_preflight",
                status=CheckStatus.DEGRADED,
                message="ML model service unavailable; using explicit fallback mode.",
                duration_ms=round((time.perf_counter() - started_at) * 1000, 3),
                details={
                    "scoring_mode": self.ml_scoring_mode,
                    "model_version": None,
                    "module": module_name,
                },
                fatal=False,
            )

        try:
            module = await asyncio.to_thread(importlib.import_module, module_name)
            factory = getattr(module, "get_model_service", None)

            if not callable(factory):
                raise AttributeError("app.ml.model_service.get_model_service is missing.")

            service = await asyncio.to_thread(factory)
            preflight = getattr(service, "preflight", None)

            result: Any = None
            if callable(preflight):
                result = await asyncio.to_thread(preflight)

            scoring_mode = (
                _read_signal(result, "scoring_mode")
                or _read_signal(service, "scoring_mode")
                or self._setting("ML_ACTIVE_SCORING_MODE", "auto")
            )

            model_version = (
                _read_signal(result, "model_version")
                or _read_signal(service, "model_version")
                or self._setting("ML_ACTIVE_MODEL_VERSION", None)
            )

            self.ml_scoring_mode = str(scoring_mode)
            self.model_version = str(model_version) if model_version is not None else None

            is_fallback = self.ml_scoring_mode.lower() in {
                fallback_label.lower(),
                "heuristic_fallback",
                "rules_only",
                "ml_disabled",
                "unknown",
            }

            status = CheckStatus.DEGRADED if is_fallback else CheckStatus.OK

            message = (
                "ML preflight completed using explicit fallback mode."
                if is_fallback
                else "ML preflight completed using trained model mode."
            )

            return CheckResult(
                name="ml_preflight",
                status=status,
                message=message,
                duration_ms=round((time.perf_counter() - started_at) * 1000, 3),
                details={
                    "scoring_mode": self.ml_scoring_mode,
                    "model_version": self.model_version,
                },
                fatal=False,
            )

        except Exception as exc:
            if require_trained_model:
                return CheckResult(
                    name="ml_preflight",
                    status=CheckStatus.FAILED,
                    message="ML preflight failed and trained model is required.",
                    duration_ms=round((time.perf_counter() - started_at) * 1000, 3),
                    details={"error_type": type(exc).__name__},
                    fatal=True,
                )

            self.ml_scoring_mode = fallback_label
            self.model_version = None

            return CheckResult(
                name="ml_preflight",
                status=CheckStatus.DEGRADED,
                message="ML preflight failed; using explicit fallback mode.",
                duration_ms=round((time.perf_counter() - started_at) * 1000, 3),
                details={
                    "scoring_mode": self.ml_scoring_mode,
                    "model_version": None,
                    "error_type": type(exc).__name__,
                },
                fatal=False,
            )

    # -------------------------------------------------------------------------
    # Check runner
    # -------------------------------------------------------------------------

    async def _run_check(
        self,
        name: str,
        func: Callable[[], Awaitable[CheckResult]],
    ) -> CheckResult:
        """
        Run an async lifecycle check and record its safe result.
        """
        started_at = time.perf_counter()

        try:
            result = await func()
        except Exception as exc:
            logger.exception("Lifecycle check failed unexpectedly: %s", name)

            result = CheckResult(
                name=name,
                status=CheckStatus.FAILED,
                message=f"{name} failed unexpectedly.",
                duration_ms=round((time.perf_counter() - started_at) * 1000, 3),
                details={"error_type": type(exc).__name__},
                fatal=True,
            )

        if result.duration_ms is None:
            result.duration_ms = round((time.perf_counter() - started_at) * 1000, 3)

        self.results.append(result)
        return result

    # -------------------------------------------------------------------------
    # Start/stop
    # -------------------------------------------------------------------------

    async def start(self, app: FastAPI) -> None:
        """
        Execute startup checks and transition the application to started or
        degraded state.

        Raises RuntimeError when fatal configuration or dependency failures are
        detected.
        """
        if self.phase in {LifecyclePhase.STARTED, LifecyclePhase.DEGRADED}:
            return

        self.phase = LifecyclePhase.STARTING
        app.state.lifecycle = self
        app.state.lifecycle_phase = self.phase.value

        self.started_at = _utcnow()
        self.stopped_at = None
        self.results.clear()
        self.warnings.clear()
        self.errors.clear()

        logger.info("MULEGUARD lifecycle startup begins.")

        # ---------------------------------------------------------------------
        # Configuration validation
        # ---------------------------------------------------------------------
        config_results = self.validate_configuration()
        self.results.extend(config_results)

        fatal_config_failures = [
            result for result in config_results if result.is_failure and result.fatal
        ]

        if fatal_config_failures:
            self.phase = LifecyclePhase.FAILED
            app.state.lifecycle_phase = self.phase.value

            self.errors = [result.message for result in fatal_config_failures]

            raise RuntimeError(
                "MULEGUARD lifecycle configuration validation failed: "
                + "; ".join(self.errors)
            )

        self.warnings = [
            result.message
            for result in config_results
            if result.status == CheckStatus.DEGRADED
        ]

        # ---------------------------------------------------------------------
        # Runtime checks
        # ---------------------------------------------------------------------
        await self._run_check("runtime_directories", self._ensure_runtime_directories)
        db_result = await self._run_check("database", self._check_database)
        ml_result = await self._run_check("ml_preflight", self._preflight_ml)

        # ---------------------------------------------------------------------
        # Publish safe state to app
        # ---------------------------------------------------------------------
        app.state.active_scoring_mode = self.ml_scoring_mode
        app.state.active_model_version = self.model_version

        # ---------------------------------------------------------------------
        # Determine final phase
        # ---------------------------------------------------------------------
        failures = [result for result in self.results if result.is_failure]
        degraded = [
            result
            for result in self.results
            if result.status == CheckStatus.DEGRADED
        ]

        if failures:
            # Non-fatal failures still produce degraded mode. Fatal failures
            # should already have raised during configuration or check execution.
            self.phase = LifecyclePhase.DEGRADED
        elif degraded:
            self.phase = LifecyclePhase.DEGRADED
        else:
            self.phase = LifecyclePhase.STARTED

        app.state.lifecycle_phase = self.phase.value

        self.errors = [result.message for result in failures]
        self.warnings.extend(
            result.message
            for result in degraded
            if result.message not in self.warnings
        )

        logger.info(
            "MULEGUARD lifecycle startup complete: phase=%s database=%s ml_scoring_mode=%s warnings=%s errors=%s",
            self.phase.value,
            db_result.status.value,
            ml_result.details.get("scoring_mode", self.ml_scoring_mode),
            len(self.warnings),
            len(self.errors),
        )

    async def stop(self, app: FastAPI) -> None:
        """
        Execute shutdown tasks and transition the application to stopped state.
        """
        if self.phase == LifecyclePhase.STOPPED:
            return

        previous_phase = self.phase
        self.phase = LifecyclePhase.STOPPING
        app.state.lifecycle_phase = self.phase.value

        logger.info(
            "MULEGUARD lifecycle shutdown begins: previous_phase=%s",
            previous_phase.value,
        )

        try:
            await asyncio.to_thread(dispose_engine)
            logger.info("Database engine disposed during lifecycle shutdown.")
        except Exception:
            logger.warning(
                "Failed to dispose database engine cleanly during lifecycle shutdown.",
                exc_info=True,
            )

        self.stopped_at = _utcnow()
        self.phase = LifecyclePhase.STOPPED
        app.state.lifecycle_phase = self.phase.value

        logger.info("MULEGUARD lifecycle shutdown complete.")

    @asynccontextmanager
    async def lifespan(self, app: FastAPI):
        """
        FastAPI-compatible lifespan context manager.
        """
        await self.start(app)

        try:
            yield
        finally:
            await self.stop(app)

    # -------------------------------------------------------------------------
    # Diagnostics and payloads
    # -------------------------------------------------------------------------

    def _uptime_seconds(self) -> float | None:
        """
        Return safe uptime in seconds, if startup time is known.
        """
        if self.started_at is None:
            return None

        return round((_utcnow() - self.started_at).total_seconds(), 3)

    def _safe_check_summary(self) -> list[dict[str, Any]]:
        """
        Return a safe summary of lifecycle checks.
        """
        return [
            {
                "name": result.name,
                "status": result.status.value,
                "message": result.message,
                "duration_ms": result.duration_ms,
                "fatal": result.fatal,
            }
            for result in self.results
        ]

    def _overall_status(self) -> str:
        """
        Return a coarse overall status string.
        """
        if self.phase == LifecyclePhase.STARTED:
            return "ok"

        if self.phase == LifecyclePhase.DEGRADED:
            return "degraded"

        if self.phase in {LifecyclePhase.STOPPING, LifecyclePhase.STOPPED}:
            return "stopped"

        if self.phase == LifecyclePhase.FAILED:
            return "failed"

        return "starting"

    def health_payload(self) -> dict[str, Any]:
        """
        Return a safe health payload for liveness-style diagnostics.

        This payload must not expose secrets, database URLs, tokens, raw
        narratives, or real customer data.
        """
        return {
            "status": self._overall_status(),
            "phase": self.phase.value,
            "uptime_seconds": self._uptime_seconds(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "stopped_at": self.stopped_at.isoformat() if self.stopped_at else None,
            "environment": str(self._setting("BACKEND_ENV", "local")),
            "data_classification": str(
                self._setting("BACKEND_DATASET_MODE", "synthetic")
            ),
            "production_ready": False,
            "checks": self._safe_check_summary(),
            "database": self.db_health,
            "ml": {
                "enabled": _as_bool(self._setting("ML_ENABLED", True), True),
                "scoring_mode": self.ml_scoring_mode,
                "model_version": self.model_version,
                "require_trained_model": _as_bool(
                    self._setting("ML_REQUIRE_TRAINED_MODEL", False),
                    False,
                ),
            },
            "warnings": self.warnings,
            "errors": self.errors,
        }

    def readiness_payload(self) -> dict[str, Any]:
        """
        Return a safe readiness payload.

        The application is considered ready when:

        - lifecycle phase is started or degraded;
        - database check is OK.

        ML fallback mode is allowed and should be surfaced explicitly rather
        than treated as a crash or fake model claim.
        """
        db_ok = any(
            result.name == "database" and result.status == CheckStatus.OK
            for result in self.results
        )

        ready = self.phase in {
            LifecyclePhase.STARTED,
            LifecyclePhase.DEGRADED,
        } and db_ok

        return {
            "ready": ready,
            "status": "ready" if ready else "not_ready",
            "phase": self.phase.value,
            "database_ok": db_ok,
            "ml_scoring_mode": self.ml_scoring_mode,
            "active_model_version": self.model_version,
            "warnings": self.warnings,
            "errors": self.errors,
        }


# -----------------------------------------------------------------------------
# Module-level convenience API
# -----------------------------------------------------------------------------

_default_manager: LifecycleManager | None = None


def get_lifecycle_manager(settings: Settings | None = None) -> LifecycleManager:
    """
    Return a process-wide lifecycle manager.

    If settings are provided, a new manager is created and becomes the default.
    This is useful for tests or applications that construct settings explicitly.
    """
    global _default_manager

    if _default_manager is None or settings is not None:
        _default_manager = LifecycleManager(settings=settings)

    return _default_manager


def create_lifespan(settings: Settings | None = None) -> Callable[[FastAPI], Any]:
    """
    Create a FastAPI lifespan callable bound to a dedicated LifecycleManager.

    Usage in app/main.py:

        from app.lifecycle import create_lifespan

        app = FastAPI(
            ...,
            lifespan=create_lifespan(),
        )
    """
    manager = LifecycleManager(settings=settings)

    async def _lifespan(app: FastAPI):
        async with manager.lifespan(app):
            yield

    return _lifespan


async def lifespan(app: FastAPI):
    """
    Default module-level FastAPI lifespan.

    This uses app.state.settings when available, otherwise falls back to
    get_settings().
    """
    settings = getattr(app.state, "settings", None)

    manager = get_lifecycle_manager(
        settings if isinstance(settings, Settings) else None
    )

    async with manager.lifespan(app):
        yield


__all__ = [
    "CheckResult",
    "CheckStatus",
    "LifecycleManager",
    "LifecyclePhase",
    "create_lifespan",
    "get_lifecycle_manager",
    "lifespan",
]