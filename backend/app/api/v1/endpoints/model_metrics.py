"""
MULEGUARD backend API v1 model metrics endpoints.

This module implements the versioned `/api/v1/model-metrics` read-only model
observability surface for synthetic MULEGUARD machine-learning metadata and
evaluations.

Implemented endpoints:

- GET /api/v1/model-metrics/status
- GET /api/v1/model-metrics/current
- GET /api/v1/model-metrics/limitations
- GET /api/v1/model-metrics/feature-schema
- GET /api/v1/model-metrics/versions
- GET /api/v1/model-metrics/versions/{version_id}
- GET /api/v1/model-metrics/versions/{version_id}/evaluations
- GET /api/v1/model-metrics/evaluations/{evaluation_id}
- GET /api/v1/model-metrics/compare

Design goals:

- expose only real, persisted model metadata and computed evaluation metrics;
- never fabricate metrics, probabilities, calibration, or accuracy claims;
- report undefined metrics honestly as unavailable rather than inventing them;
- distinguish trained-model mode from heuristic/rules-only fallback explicitly;
- preserve leakage control by never exposing synthetic ground-truth labels,
  scenario IDs, fraud-ring IDs, raw complaint narratives, secrets, tokens,
  passwords, database URLs, or model artifact file paths;
- keep all listings bounded and stably ordered;
- enforce server-side RBAC through dependency permissions;
- fail closed and honestly when ML metadata or optional modules are missing.

Explicit non-goals:

- This module does not train, retrain, promote, retire, upload, replace, or
  execute models.
- This module does not compute ML scores inline.
- This module does not load model artifacts or deserialize pickles.
- This module does not expose automatic adverse customer action.
- This module does not claim production readiness, regulatory compliance, or
  real-world fraud-detection accuracy.
- This module does not claim calibration unless calibration has actually been
  implemented and evaluated, which MULEGUARD does not currently do.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Model scores are
investigative priority scores, not probabilities of guilt. Heuristic fallback
scores are not calibrated model probabilities. Alerts, graph relationships,
entity links, complaint correlations, and case dispositions remain
investigative leads or human workflow artefacts only.
"""

from __future__ import annotations

import importlib
import logging
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Final, Optional

from fastapi import APIRouter, Depends, Path, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    PageParams,
    Permission,
    SessionDep,
    SettingsDep,
    apply_pagination,
    pagination_dependency,
    require_permission,
)
from app.exceptions import (
    FeatureFlagDisabledError,
    NotFoundError,
    ValidationError as MuleGuardValidationError,
)
from app.models import (
    ModelEvaluation,
    ModelType,
    ModelVersion,
    ScoringMode,
    SplitStrategy,
    User,
)

logger = logging.getLogger("muleguard.backend.api.v1.endpoints.model_metrics")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(tags=["model_metrics"])


# -----------------------------------------------------------------------------
# Permission resolution
# -----------------------------------------------------------------------------
# Prefer a dedicated model-monitor permission when the project defines one.
# Fall back to audit/read permissions so the module remains usable across
# incremental RBAC evolutions.

_MODEL_READ_PERMISSION_NAMES: Final[tuple[str, ...]] = (
    "MODEL_MONITOR_READ",
    "MODEL_READ",
    "AUDIT_READ",
    "DASHBOARD_READ",
)

def _first_permission(names: tuple[str, ...]) -> Any:
    """
    Return the first available permission attribute from the supplied names.

    Avoids `iter(Permission)`: `app.api.deps.Permission`, which this module
    imports, is a plain class of `Final[str]` constants rather than an Enum, so
    `iter()` on it raises `TypeError: 'type' object is not iterable`. In the
    previous form that call sat in the `default` argument of `next()` and was
    evaluated eagerly, so importing this module always raised TypeError and
    /api/v1/model/* silently did not exist.
    """
    for name in names:
        permission = getattr(Permission, name, None)

        if permission is not None:
            return permission

    for attribute, value in vars(Permission).items():
        if not attribute.startswith("_") and isinstance(value, str):
            return value

    return None


MODEL_READ_PERMISSION: Final[Any] = _first_permission(_MODEL_READ_PERMISSION_NAMES)


# -----------------------------------------------------------------------------
# Constants and small policy limits
# -----------------------------------------------------------------------------

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}

_MAX_STRING_LENGTH: Final[int] = 512
_MAX_LIST_LENGTH: Final[int] = 100
_MAX_MAPPING_KEYS: Final[int] = 100
_MAX_JSON_DEPTH: Final[int] = 6
_MAX_COMPARE_VERSIONS: Final[int] = 3

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

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
    "artifact_path",
    "file_path",
    "filesystem",
)

# Metric keys that are safe to surface as first-class fields when present.
_KNOWN_METRIC_KEYS: Final[tuple[str, ...]] = (
    "precision",
    "recall",
    "f1",
    "f1_score",
    "pr_auc",
    "roc_auc",
    "auc_roc",
    "auc_pr",
    "average_precision",
    "precision_at_k",
    "recall_at_k",
    "top_k_yield",
    "false_positive_rate",
    "false_negative_rate",
    "accuracy",
    "balanced_accuracy",
    "log_loss",
    "brier_score",
    "expected_calibration_error",
    "latency_ms_per_account",
    "latency_ms",
    "latency_batch_size",
    "positive_rate",
    "support",
    "sample_count",
    "positive_count",
    "negative_count",
    "threshold",
)

# Metric keys that must never be reported unless actually computed.
# When absent, they are surfaced explicitly as unavailable.
_METRIC_UNAVAILABLE_KEYS: Final[tuple[str, ...]] = (
    "expected_calibration_error",
    "brier_score",
    "log_loss",
)

_MODEL_METRICS_CAVEATS: Final[tuple[str, ...]] = (
    "Synthetic prototype data only. Not real customer or bank data.",
    "Model metrics are real computed outputs from synthetic evaluation data.",
    "Undefined metrics are reported honestly as unavailable, not invented.",
    "Risk scores are investigative priority scores, not probabilities of guilt.",
    "Heuristic fallback scores are not calibrated model probabilities.",
    "Calibration metrics are unavailable unless calibration has been implemented and evaluated.",
    "Model metadata must not be interpreted as production readiness or regulatory compliance.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not exposed by this endpoint.",
    "Model artifact file paths and raw binary artifacts are never exposed.",
    "Alerts, graph relationships, entity links, complaint correlations, and case dispositions are investigative leads only.",
    "This API does not train, retrain, promote, retire, upload, replace, or execute models.",
    "This API does not freeze, block, blacklist, close, restrict, or otherwise take adverse action against accounts or customers.",
)

_FALLBACK_CAVEATS: Final[tuple[str, ...]] = (
    *_MODEL_METRICS_CAVEATS,
    "When no trained model is available, MULEGUARD reports an explicit fallback scoring mode.",
    "Fallback mode is not a trained model and must not be described as model probability.",
)


# -----------------------------------------------------------------------------
# Dynamic column helpers
# -----------------------------------------------------------------------------


def _model_column(model: Any, name: str) -> Any | None:
    """
    Return a SQLAlchemy column attribute when present.
    """
    return getattr(model, name, None)


def _first_column(model: Any, *names: str) -> Any | None:
    """
    Return the first existing column attribute among names.
    """
    for name in names:
        column = _model_column(model, name)

        if column is not None:
            return column

    return None


_MODEL_VERSION_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(ModelVersion, "id"),
        "version": _model_column(ModelVersion, "version"),
        "created_at": _first_column(ModelVersion, "record_created_at", "created_at"),
        "updated_at": _first_column(ModelVersion, "record_updated_at", "updated_at"),
        "model_type": _model_column(ModelVersion, "model_type"),
        "is_active": _model_column(ModelVersion, "is_active"),
        "feature_schema_version": _model_column(ModelVersion, "feature_schema_version"),
        "training_started_at": _model_column(ModelVersion, "training_started_at"),
        "training_finished_at": _model_column(ModelVersion, "training_finished_at"),
    }.items()
    if column is not None
}

_MODEL_VERSION_TIEBREAKER = _model_column(ModelVersion, "id")

_MODEL_VERSION_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _MODEL_VERSION_COLUMN_MAP
    else ("id" if "id" in _MODEL_VERSION_COLUMN_MAP else "created_at")
)

_MODEL_EVALUATION_COLUMN_MAP: Final[dict[str, Any]] = {
    key: column
    for key, column in {
        "id": _model_column(ModelEvaluation, "id"),
        "created_at": _first_column(ModelEvaluation, "record_created_at", "created_at"),
        "model_version_id": _model_column(ModelEvaluation, "model_version_id"),
        "split_strategy": _model_column(ModelEvaluation, "split_strategy"),
        "sample_count": _model_column(ModelEvaluation, "sample_count"),
        "top_k": _model_column(ModelEvaluation, "top_k"),
    }.items()
    if column is not None
}

_MODEL_EVALUATION_TIEBREAKER = _model_column(ModelEvaluation, "id")

_MODEL_EVALUATION_DEFAULT_SORT: Final[str] = (
    "created_at"
    if "created_at" in _MODEL_EVALUATION_COLUMN_MAP
    else ("id" if "id" in _MODEL_EVALUATION_COLUMN_MAP else "created_at")
)


# -----------------------------------------------------------------------------
# Reusable bounded dependencies
# -----------------------------------------------------------------------------

version_pagination = pagination_dependency(
    sortable_fields=tuple(_MODEL_VERSION_COLUMN_MAP.keys()),
    default_sort_by=_MODEL_VERSION_DEFAULT_SORT,
    default_sort_order="desc",
)

evaluation_pagination = pagination_dependency(
    sortable_fields=tuple(_MODEL_EVALUATION_COLUMN_MAP.keys()),
    default_sort_by=_MODEL_EVALUATION_DEFAULT_SORT,
    default_sort_order="desc",
)


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


def _enum_str(value: Any) -> Optional[str]:
    """
    Return a stable string for enum-like values.
    """
    if value is None:
        return None

    return str(getattr(value, "value", value))


def _clean_text(value: Any, limit: int = _MAX_STRING_LENGTH) -> str:
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


def _clean_multiline(value: Any, limit: int = _MAX_STRING_LENGTH) -> str:
    """
    Return a safe bounded text value preserving paragraph breaks.
    """
    text = str(value if value is not None else "")
    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(" ".join(line.split()) for line in text.split("\n"))
    text = text.strip()

    if len(text) > limit:
        return text[:limit]

    return text


def _get_if_exists(obj: Any, name: str, default: Any = None) -> Any:
    """
    Get an attribute only when it exists on the object.
    """
    return getattr(obj, name, default)


def _str_or_none(value: Any) -> Optional[str]:
    """
    Return a stripped string or None.
    """
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _is_finite_number(value: Any) -> bool:
    """
    Return True when a value is a finite int/float/Decimal.
    """
    if isinstance(value, bool):
        return False

    if isinstance(value, (int, float)):
        return float(value) == float(value) and float(value) not in {float("inf"), float("-inf")}

    if isinstance(value, Decimal):
        return value.is_finite()

    return False


def _is_sensitive_key(key: str) -> bool:
    """
    Return True when a metadata key appears sensitive or leakage-prone.
    """
    lowered = key.strip().lower()

    if lowered in _SENSITIVE_KEYS:
        return True

    return any(token in lowered for token in _SENSITIVE_KEY_TOKENS)


def _sanitize_json_value(
    value: Any,
    depth: int = 0,
    *,
    max_sequence_length: int = _MAX_LIST_LENGTH,
    max_mapping_keys: int = _MAX_MAPPING_KEYS,
) -> Any:
    """
    Convert an arbitrary JSON-like value into a safe response value.
    """
    if depth > _MAX_JSON_DEPTH:
        return "[truncated-depth]"

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return value

    if isinstance(value, str):
        return _clean_text(value, _MAX_STRING_LENGTH)

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Enum):
        return _sanitize_json_value(
            value.value,
            depth + 1,
            max_sequence_length=max_sequence_length,
            max_mapping_keys=max_mapping_keys,
        )

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<binary:{len(value)} bytes>"

    if isinstance(value, Mapping):
        return _sanitize_json_object(
            value,
            depth + 1,
            max_sequence_length=max_sequence_length,
            max_mapping_keys=max_mapping_keys,
        )

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        original_length = len(value)
        limited = list(value)[:max_sequence_length]
        items = [
            _sanitize_json_value(
                item,
                depth + 1,
                max_sequence_length=max_sequence_length,
                max_mapping_keys=max_mapping_keys,
            )
            for item in limited
        ]

        if original_length > max_sequence_length:
            items.append({"_truncated": True})

        return items

    return f"<{type(value).__name__}>"


def _sanitize_json_object(
    value: Mapping[Any, Any],
    depth: int = 0,
    *,
    max_sequence_length: int = _MAX_LIST_LENGTH,
    max_mapping_keys: int = _MAX_MAPPING_KEYS,
) -> dict[str, Any]:
    """
    Return a sanitized JSON object suitable for API responses.
    """
    if depth > _MAX_JSON_DEPTH:
        return {"_truncated": True}

    sanitized: dict[str, Any] = {}

    for raw_key, raw_value in list(value.items())[:max_mapping_keys]:
        key = str(raw_key)

        if _is_sensitive_key(key):
            continue

        sanitized[key] = _sanitize_json_value(
            raw_value,
            depth + 1,
            max_sequence_length=max_sequence_length,
            max_mapping_keys=max_mapping_keys,
        )

        if len(sanitized) >= max_mapping_keys:
            sanitized["_truncated_keys"] = True
            break

    return sanitized


def _response_metadata(value: Any) -> Any:
    """
    Sanitize metadata_json-like values before returning them in API responses.
    """
    if isinstance(value, Mapping):
        return _sanitize_json_object(value)

    if value is None:
        return None

    return _sanitize_json_value(value)


def _safe_string_list(value: Any, *, max_items: int = _MAX_LIST_LENGTH) -> list[str]:
    """
    Return a bounded list of safe strings.
    """
    if value is None:
        return []

    if isinstance(value, str):
        candidates: Sequence[Any] = [value]
    elif isinstance(value, Mapping):
        return []
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        candidates = value
    else:
        candidates = [value]

    seen: set[str] = set()
    result: list[str] = []

    for item in candidates:
        text = _clean_text(item, _MAX_STRING_LENGTH)

        if not text or text in seen:
            continue

        seen.add(text)
        result.append(text)

        if len(result) >= max_items:
            break

    return result


def _total_pages(total: int, page_size: int) -> int:
    """
    Compute bounded total page count.
    """
    if total <= 0 or page_size <= 0:
        return 0

    return (total + page_size - 1) // page_size


def _apply(stmt: Any, conditions: list[Any]) -> Any:
    """
    Apply a list of SQLAlchemy conditions to a statement.
    """
    if conditions:
        stmt = stmt.where(and_(*conditions))

    return stmt


def _scalar_count(db: Session, stmt: Any) -> int:
    """
    Execute a count statement and return an int.
    """
    return int(db.scalar(stmt) or 0)


def _order_stmt(stmt: Any, specs: Sequence[tuple[Any, bool]]) -> Any:
    """
    Apply safe ordering specifications, skipping missing columns.
    """
    for column, ascending in specs:
        if column is None:
            continue

        stmt = stmt.order_by(column.asc() if ascending else column.desc())

    return stmt


# -----------------------------------------------------------------------------
# ML policy and service helpers
# -----------------------------------------------------------------------------


def _ensure_model_metrics_enabled(settings: Any) -> None:
    """
    Fail closed when the model metrics API surface is disabled.
    """
    if not _as_bool(_setting(settings, "MODEL_METRICS_API_ENABLED", True), True):
        raise FeatureFlagDisabledError(
            "Model metrics endpoints are disabled by configuration."
        )

    if not _as_bool(_setting(settings, "ML_ENABLED", True), True):
        raise FeatureFlagDisabledError("ML subsystem is disabled by configuration.")


def _active_scoring_mode(app_state: Any, settings: Any) -> str:
    """
    Resolve the active scoring mode honestly.

    Preference order:

    1. app.state.active_scoring_mode set by lifecycle preflight;
    2. ML_ACTIVE_SCORING_MODE setting;
    3. explicit fallback label when ML is disabled.
    """
    state_mode = getattr(app_state, "active_scoring_mode", None)

    if state_mode:
        return str(state_mode).strip().lower()

    if not _as_bool(_setting(settings, "ML_ENABLED", True), True):
        return "ml_disabled"

    configured = str(
        _setting(settings, "ML_ACTIVE_SCORING_MODE", "auto") or "auto"
    ).strip().lower()

    return configured or "auto"


def _active_model_version(app_state: Any, settings: Any) -> Optional[str]:
    """
    Resolve the active model version label honestly.
    """
    state_version = getattr(app_state, "active_model_version", None)

    if state_version:
        return str(state_version)

    configured = _setting(settings, "ML_ACTIVE_MODEL_VERSION", None)

    if configured:
        return str(configured)

    return None


def _model_service_preflight(settings: Any) -> dict[str, Any]:
    """
    Query app.ml.model_service.preflight() when available.

    Returns a safe status dict. Never loads or deserializes artifacts.
    """
    if not _as_bool(_setting(settings, "ML_ENABLED", True), True):
        return {
            "available": False,
            "reason": "ml_disabled",
        }

    try:
        module = importlib.import_module("app.ml.model_service")
        factory = getattr(module, "get_model_service", None)

        if not callable(factory):
            return {
                "available": False,
                "reason": "model_service_factory_missing",
            }

        service = factory()
        preflight = getattr(service, "preflight", None)

        if not callable(preflight):
            return {
                "available": True,
                "reason": "preflight_missing",
                "scoring_mode": _str_or_none(getattr(service, "scoring_mode", None)),
                "model_version": _str_or_none(getattr(service, "model_version", None)),
            }

        result = preflight()

        if isinstance(result, Mapping):
            return {
                "available": True,
                "reason": "ok",
                "scoring_mode": _str_or_none(result.get("scoring_mode")),
                "model_version": _str_or_none(result.get("model_version")),
                "artifact_available": result.get("artifact_available"),
                "feature_schema_version": _str_or_none(result.get("feature_schema_version")),
                "fallback_label": _str_or_none(result.get("fallback_label")),
            }

        return {
            "available": True,
            "reason": "ok",
            "scoring_mode": _str_or_none(getattr(result, "scoring_mode", None)),
            "model_version": _str_or_none(getattr(result, "model_version", None)),
            "artifact_available": getattr(result, "artifact_available", None),
            "feature_schema_version": _str_or_none(getattr(result, "feature_schema_version", None)),
            "fallback_label": _str_or_none(getattr(result, "fallback_label", None)),
        }

    except Exception as exc:
        logger.debug("Model service preflight unavailable: %s", type(exc).__name__)
        return {
            "available": False,
            "reason": "model_service_unavailable",
            "error_type": type(exc).__name__,
        }


def _feature_schema_metadata(settings: Any) -> dict[str, Any]:
    """
    Return safe feature-schema metadata from app.ml.feature_schema when
    available.

    This never exposes forbidden feature fields or raw labels.
    """
    fallback_label = str(
        _setting(settings, "ML_FALLBACK_MODE_LABEL", "heuristic_fallback")
        or "heuristic_fallback"
    )

    schema_version = str(
        _setting(settings, "ML_FEATURE_SCHEMA_VERSION", "v1") or "v1"
    )

    forbidden_fields = _safe_string_list(
        _setting(
            settings,
            "ML_FORBIDDEN_FEATURE_FIELDS",
            "fraud_label,scenario_id,ground_truth_label,ring_id,label,is_fraud",
        )
    )

    try:
        module = importlib.import_module("app.ml.feature_schema")

        metadata = {}

        schema_attr = getattr(module, "FEATURE_SCHEMA", None)
        version_attr = getattr(module, "FEATURE_SCHEMA_VERSION", None)
        fields_attr = getattr(module, "FEATURE_FIELDS", None)
        windows_attr = getattr(module, "FEATURE_WINDOWS", None)

        if version_attr:
            metadata["feature_schema_version"] = str(version_attr)
        else:
            metadata["feature_schema_version"] = schema_version

        if isinstance(schema_attr, Mapping):
            metadata["schema"] = _sanitize_json_object(schema_attr)

        if fields_attr is not None:
            metadata["feature_fields"] = _safe_string_list(fields_attr, max_items=500)

        if windows_attr is not None:
            metadata["feature_windows"] = _safe_string_list(windows_attr, max_items=50)

        metadata["available"] = True
        metadata["forbidden_fields"] = forbidden_fields
        metadata["fallback_label"] = fallback_label
        return metadata

    except Exception as exc:
        logger.debug("Feature schema module unavailable: %s", type(exc).__name__)
        return {
            "available": False,
            "reason": "feature_schema_module_unavailable",
            "error_type": type(exc).__name__,
            "feature_schema_version": schema_version,
            "forbidden_fields": forbidden_fields,
            "fallback_label": fallback_label,
        }


def _model_card_limitations(settings: Any) -> dict[str, Any]:
    """
    Return safe model-card limitations metadata.
    """
    return {
        "calibration_claim_allowed": False,
        "probability_claim_allowed": False,
        "production_ready": False,
        "synthetic_only": True,
        "model_card_path_configured": bool(
            _setting(settings, "MODEL_CARD_PATH", None)
        ),
        "limitations_summary": (
            "Model metrics are computed on synthetic data and do not "
            "establish real-world accuracy. Scores are investigative priority "
            "signals, not calibrated probabilities. Heuristic fallback is not "
            "a trained model. No regulatory, production, or legal-admissibility "
            "claims are made."
        ),
    }


# -----------------------------------------------------------------------------
# Metric extraction helpers
# -----------------------------------------------------------------------------


def _metrics_payload(metrics_json: Any) -> dict[str, Any]:
    """
    Return sanitized metrics mapping.
    """
    if not isinstance(metrics_json, Mapping):
        return {}

    return _sanitize_json_object(metrics_json)


def _extract_known_metrics(metrics: Mapping[str, Any]) -> dict[str, Any]:
    """
    Extract first-class known metric values when present.

    Only finite numeric values are surfaced. Missing values remain absent.
    """
    extracted: dict[str, Any] = {}

    for key in _KNOWN_METRIC_KEYS:
        if key not in metrics:
            continue

        value = metrics[key]

        if _is_finite_number(value):
            extracted[key] = value
        elif isinstance(value, str) and value.strip():
            extracted[key] = _clean_text(value, 64)
        elif isinstance(value, Mapping):
            extracted[key] = _sanitize_json_object(value)

    return extracted


def _undefined_metrics_payload(evaluation: Any) -> list[str]:
    """
    Return explicitly undefined metric names from an evaluation.
    """
    raw = _get_if_exists(evaluation, "undefined_metrics_json", None)

    if raw is None:
        return []

    if isinstance(raw, Mapping):
        keys = list(raw.keys())
        return _safe_string_list(keys, max_items=50)

    return _safe_string_list(raw, max_items=50)


def _evaluation_metrics_summary(evaluation: Any) -> dict[str, Any]:
    """
    Build an honest metrics summary for one evaluation.
    """
    metrics = _metrics_payload(_get_if_exists(evaluation, "metrics_json", None))
    known = _extract_known_metrics(metrics)
    undefined = _undefined_metrics_payload(evaluation)

    # Ensure calibration-related metrics are reported as unavailable unless
    # explicitly present and finite.
    for key in _METRIC_UNAVAILABLE_KEYS:
        if key not in known:
            undefined.append(key)

    undefined = sorted({item for item in undefined if item})

    return {
        "available_metrics": known,
        "raw_metrics": metrics,
        "undefined_metrics": undefined,
        "threshold": _get_if_exists(evaluation, "threshold", None),
        "top_k": _get_if_exists(evaluation, "top_k", None),
        "latency_ms_per_account": _get_if_exists(
            evaluation,
            "latency_ms_per_account",
            None,
        ),
        "latency_batch_size": _get_if_exists(
            evaluation,
            "latency_batch_size",
            None,
        ),
    }


# -----------------------------------------------------------------------------
# Response models
# -----------------------------------------------------------------------------


class ModelMetricsStatusResponse(BaseModel):
    """
    Safe ML metrics subsystem status.
    """

    model_config = ConfigDict(from_attributes=False)

    enabled: bool
    scoring_mode: str
    active_model_version: Optional[str] = None
    fallback_label: str
    require_trained_model: bool
    dataset_mode: str
    feature_schema_version: str
    artifact_status: dict[str, Any] = Field(default_factory=dict)
    feature_schema_available: bool = False
    caveats: list[str] = Field(default_factory=list)


class ModelVersionResponse(BaseModel):
    """
    Safe model version metadata.

    Artifact file paths are intentionally not exposed.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    version: str
    feature_schema_version: str
    model_type: str
    training_seed: Optional[int] = None
    training_started_at: Optional[datetime] = None
    training_finished_at: Optional[datetime] = None
    dataset_fingerprint: Optional[str] = None
    generator_config_json: Optional[Any] = None
    split_strategy: str
    hyperparameters_json: Optional[Any] = None
    artifact_checksum: Optional[str] = None
    checksum_algorithm: Optional[str] = None
    artifact_available: bool = False
    metrics_json: Optional[Any] = None
    limitations_json: Optional[Any] = None
    is_active: bool = False
    notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ModelVersionListResponse(BaseModel):
    """
    Paginated model version list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[ModelVersionResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ModelEvaluationResponse(BaseModel):
    """
    Safe model evaluation response.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    model_version_id: str
    dataset_fingerprint: Optional[str] = None
    split_strategy: str
    sample_count: int = 0
    class_distribution_json: Optional[Any] = None
    metrics_summary: dict[str, Any] = Field(default_factory=dict)
    limitations: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ModelEvaluationListResponse(BaseModel):
    """
    Paginated evaluation list response.
    """

    model_config = ConfigDict(from_attributes=False)

    items: list[ModelEvaluationResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    sort_by: Optional[str] = None
    sort_order: str = "desc"
    caveats: list[str] = Field(default_factory=list)


class ModelCurrentResponse(BaseModel):
    """
    Safe current ML posture response.
    """

    model_config = ConfigDict(from_attributes=False)

    scoring_mode: str
    active_model_version: Optional[str] = None
    fallback_label: str
    require_trained_model: bool
    feature_schema_version: str
    active_version: Optional[ModelVersionResponse] = None
    latest_evaluations: list[ModelEvaluationResponse] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)


class ModelLimitationsResponse(BaseModel):
    """
    Safe model limitations and calibration posture.
    """

    model_config = ConfigDict(from_attributes=False)

    scoring_mode: str
    calibration_claim_allowed: bool = False
    probability_claim_allowed: bool = False
    synthetic_only: bool = True
    production_ready: bool = False
    limitations_summary: str = ""
    caveats: list[str] = Field(default_factory=list)


class FeatureSchemaResponse(BaseModel):
    """
    Safe feature-schema metadata response.
    """

    model_config = ConfigDict(from_attributes=False)

    available: bool
    feature_schema_version: str
    feature_fields: list[str] = Field(default_factory=list)
    feature_windows: list[str] = Field(default_factory=list)
    forbidden_fields: list[str] = Field(default_factory=list)
    fallback_label: str
    schema: Optional[Any] = None
    caveats: list[str] = Field(default_factory=list)


class ModelComparisonResponse(BaseModel):
    """
    Safe bounded comparison of model versions and latest evaluations.
    """

    model_config = ConfigDict(from_attributes=False)

    versions: list[ModelVersionResponse] = Field(default_factory=list)
    latest_evaluations: list[ModelEvaluationResponse] = Field(default_factory=list)
    metric_keys: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Response builders
# -----------------------------------------------------------------------------


def _version_response(version: Any) -> ModelVersionResponse:
    """
    Build a safe model-version response.
    """
    return ModelVersionResponse(
        id=str(_get_if_exists(version, "id", "")),
        version=_clean_text(_get_if_exists(version, "version", ""), 64),
        feature_schema_version=_clean_text(
            _get_if_exists(version, "feature_schema_version", "v1"),
            32,
        ),
        model_type=_enum_str(_get_if_exists(version, "model_type", None)) or "UNKNOWN",
        training_seed=_get_if_exists(version, "training_seed", None),
        training_started_at=_get_if_exists(version, "training_started_at", None),
        training_finished_at=_get_if_exists(version, "training_finished_at", None),
        dataset_fingerprint=_str_or_none(_get_if_exists(version, "dataset_fingerprint", None)),
        generator_config_json=_response_metadata(
            _get_if_exists(version, "generator_config_json", None)
        ),
        split_strategy=_enum_str(_get_if_exists(version, "split_strategy", None)) or "UNKNOWN",
        hyperparameters_json=_response_metadata(
            _get_if_exists(version, "hyperparameters_json", None)
        ),
        artifact_checksum=_str_or_none(_get_if_exists(version, "artifact_checksum", None)),
        checksum_algorithm=_str_or_none(
            _get_if_exists(version, "checksum_algorithm", None)
        ),
        artifact_available=bool(_get_if_exists(version, "artifact_checksum", None)),
        metrics_json=_response_metadata(_get_if_exists(version, "metrics_json", None)),
        limitations_json=_response_metadata(
            _get_if_exists(version, "limitations_json", None)
        ),
        is_active=bool(_get_if_exists(version, "is_active", False)),
        notes=_clean_multiline(_get_if_exists(version, "notes", None)),
        created_at=_get_if_exists(version, "record_created_at", None),
        updated_at=_get_if_exists(version, "record_updated_at", None),
    )


def _evaluation_response(evaluation: Any) -> ModelEvaluationResponse:
    """
    Build a safe evaluation response.
    """
    return ModelEvaluationResponse(
        id=str(_get_if_exists(evaluation, "id", "")),
        model_version_id=str(_get_if_exists(evaluation, "model_version_id", "")),
        dataset_fingerprint=_str_or_none(
            _get_if_exists(evaluation, "dataset_fingerprint", None)
        ),
        split_strategy=_enum_str(_get_if_exists(evaluation, "split_strategy", None))
        or "UNKNOWN",
        sample_count=int(_get_if_exists(evaluation, "sample_count", 0) or 0),
        class_distribution_json=_response_metadata(
            _get_if_exists(evaluation, "class_distribution_json", None)
        ),
        metrics_summary=_evaluation_metrics_summary(evaluation),
        limitations=_clean_multiline(_get_if_exists(evaluation, "limitations", None)),
        created_at=_get_if_exists(evaluation, "record_created_at", None),
        updated_at=_get_if_exists(evaluation, "record_updated_at", None),
    )


# -----------------------------------------------------------------------------
# Lookup helpers
# -----------------------------------------------------------------------------


def _get_model_version_or_404(db: Session, version_id: str) -> Any:
    """
    Load a model version or raise a safe not-found error.
    """
    version = db.get(ModelVersion, version_id)

    if version is None:
        raise NotFoundError.resource("model_version", version_id)

    return version


def _get_model_evaluation_or_404(db: Session, evaluation_id: str) -> Any:
    """
    Load a model evaluation or raise a safe not-found error.
    """
    evaluation = db.get(ModelEvaluation, evaluation_id)

    if evaluation is None:
        raise NotFoundError.resource("model_evaluation", evaluation_id)

    return evaluation


def _load_latest_evaluations_for_version(
    db: Session,
    version_id: str,
    *,
    limit: int = 5,
) -> list[Any]:
    """
    Load bounded latest evaluations for one model version.
    """
    version_column = _model_column(ModelEvaluation, "model_version_id")

    if version_column is None:
        return []

    stmt = select(ModelEvaluation)
    stmt = _apply(stmt, [version_column == version_id])
    stmt = _order_stmt(
        stmt,
        [
            (_first_column(ModelEvaluation, "record_created_at", "created_at"), False),
            (_model_column(ModelEvaluation, "id"), False),
        ],
    )
    stmt = stmt.limit(max(1, int(limit)))

    return list(db.scalars(stmt).all())


def _active_model_version_row(db: Session) -> Optional[Any]:
    """
    Return the active model version row when one is marked active.
    """
    active_column = _model_column(ModelVersion, "is_active")

    if active_column is None:
        return None

    stmt = select(ModelVersion)
    stmt = _apply(stmt, [active_column.is_(True)])
    stmt = _order_stmt(
        stmt,
        [
            (_first_column(ModelVersion, "record_updated_at", "updated_at"), False),
            (_model_column(ModelVersion, "id"), False),
        ],
    )
    stmt = stmt.limit(1)

    return db.scalar(stmt)


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=ModelMetricsStatusResponse,
    summary="Get ML metrics subsystem status",
    description=(
        "Returns safe ML metrics status including active scoring mode, active "
        "model version, fallback label, feature schema availability, and "
        "artifact preflight status. This endpoint never loads or deserializes "
        "model artifacts and never exposes secrets or model artifact file paths."
    ),
)
def model_metrics_status(
    request: Any,
    settings: SettingsDep,
    _: User = Depends(require_permission(MODEL_READ_PERMISSION)),
) -> ModelMetricsStatusResponse:
    """
    Return safe ML metrics subsystem status.
    """
    _ensure_model_metrics_enabled(settings)

    app_state = getattr(request, "app", None)
    app_state = getattr(app_state, "state", None)

    scoring_mode = _active_scoring_mode(app_state, settings)
    active_version = _active_model_version(app_state, settings)
    fallback_label = str(
        _setting(settings, "ML_FALLBACK_MODE_LABEL", "heuristic_fallback")
        or "heuristic_fallback"
    )

    preflight = _model_service_preflight(settings)
    feature_schema = _feature_schema_metadata(settings)

    return ModelMetricsStatusResponse(
        enabled=True,
        scoring_mode=scoring_mode,
        active_model_version=active_version,
        fallback_label=fallback_label,
        require_trained_model=_as_bool(
            _setting(settings, "ML_REQUIRE_TRAINED_MODEL", False),
            False,
        ),
        dataset_mode=str(_setting(settings, "BACKEND_DATASET_MODE", "synthetic")),
        feature_schema_version=str(
            feature_schema.get("feature_schema_version")
            or _setting(settings, "ML_FEATURE_SCHEMA_VERSION", "v1")
        ),
        artifact_status=preflight,
        feature_schema_available=bool(feature_schema.get("available", False)),
        caveats=list(_FALLBACK_CAVEATS),
    )


@router.get(
    "/current",
    response_model=ModelCurrentResponse,
    summary="Get current active model posture",
    description=(
        "Returns the active model version and latest evaluations for the "
        "current scoring mode. If no trained model is active, this endpoint "
        "reports explicit fallback posture instead of fabricating metrics."
    ),
)
def current_model(
    request: Any,
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(MODEL_READ_PERMISSION)),
) -> ModelCurrentResponse:
    """
    Return current active model posture.
    """
    _ensure_model_metrics_enabled(settings)

    app_state = getattr(request, "app", None)
    app_state = getattr(app_state, "state", None)

    scoring_mode = _active_scoring_mode(app_state, settings)
    active_version_label = _active_model_version(app_state, settings)
    fallback_label = str(
        _setting(settings, "ML_FALLBACK_MODE_LABEL", "heuristic_fallback")
        or "heuristic_fallback"
    )

    active_version_row = _active_model_version_row(db)

    if active_version_row is None and active_version_label:
        # Try resolving by version label when active flag is not set.
        version_column = _model_column(ModelVersion, "version")

        if version_column is not None:
            active_version_row = db.scalar(
                select(ModelVersion)
                .where(version_column == active_version_label)
                .limit(1)
            )

    active_version_response = (
        _version_response(active_version_row)
        if active_version_row is not None
        else None
    )

    latest_evaluations: list[ModelEvaluationResponse] = []

    if active_version_row is not None:
        evaluations = _load_latest_evaluations_for_version(
            db,
            str(active_version_row.id),
            limit=5,
        )

        latest_evaluations = [_evaluation_response(item) for item in evaluations]

    return ModelCurrentResponse(
        scoring_mode=scoring_mode,
        active_model_version=active_version_label,
        fallback_label=fallback_label,
        require_trained_model=_as_bool(
            _setting(settings, "ML_REQUIRE_TRAINED_MODEL", False),
            False,
        ),
        feature_schema_version=str(
            _setting(settings, "ML_FEATURE_SCHEMA_VERSION", "v1") or "v1"
        ),
        active_version=active_version_response,
        latest_evaluations=latest_evaluations,
        caveats=list(_FALLBACK_CAVEATS),
    )


@router.get(
    "/limitations",
    response_model=ModelLimitationsResponse,
    summary="Get ML limitations and calibration posture",
    description=(
        "Returns safe ML limitations and calibration posture. Calibration and "
        "probability claims are prohibited unless explicitly implemented and "
        "evaluated. MULEGUARD currently makes neither claim."
    ),
)
def model_limitations(
    request: Any,
    settings: SettingsDep,
    _: User = Depends(require_permission(MODEL_READ_PERMISSION)),
) -> ModelLimitationsResponse:
    """
    Return ML limitations and calibration posture.
    """
    _ensure_model_metrics_enabled(settings)

    app_state = getattr(request, "app", None)
    app_state = getattr(app_state, "state", None)

    scoring_mode = _active_scoring_mode(app_state, settings)
    limitations = _model_card_limitations(settings)

    return ModelLimitationsResponse(
        scoring_mode=scoring_mode,
        calibration_claim_allowed=bool(
            limitations.get("calibration_claim_allowed", False)
        ),
        probability_claim_allowed=bool(
            limitations.get("probability_claim_allowed", False)
        ),
        synthetic_only=bool(limitations.get("synthetic_only", True)),
        production_ready=bool(limitations.get("production_ready", False)),
        limitations_summary=_clean_multiline(
            limitations.get("limitations_summary", "")
        ),
        caveats=list(_MODEL_METRICS_CAVEATS),
    )


@router.get(
    "/feature-schema",
    response_model=FeatureSchemaResponse,
    summary="Get safe feature-schema metadata",
    description=(
        "Returns safe feature-schema metadata, including feature field names, "
        "windows, and forbidden leakage-prone fields. This endpoint never "
        "exposes raw labels, scenario IDs, ring IDs, or real customer data."
    ),
)
def feature_schema(
    settings: SettingsDep,
    _: User = Depends(require_permission(MODEL_READ_PERMISSION)),
) -> FeatureSchemaResponse:
    """
    Return safe feature-schema metadata.
    """
    _ensure_model_metrics_enabled(settings)

    metadata = _feature_schema_metadata(settings)

    return FeatureSchemaResponse(
        available=bool(metadata.get("available", False)),
        feature_schema_version=str(
            metadata.get("feature_schema_version")
            or _setting(settings, "ML_FEATURE_SCHEMA_VERSION", "v1")
        ),
        feature_fields=_safe_string_list(metadata.get("feature_fields", [])),
        feature_windows=_safe_string_list(metadata.get("feature_windows", [])),
        forbidden_fields=_safe_string_list(metadata.get("forbidden_fields", [])),
        fallback_label=str(
            metadata.get("fallback_label")
            or _setting(settings, "ML_FALLBACK_MODE_LABEL", "heuristic_fallback")
        ),
        schema=metadata.get("schema"),
        caveats=list(_MODEL_METRICS_CAVEATS),
    )


@router.get(
    "/versions",
    response_model=ModelVersionListResponse,
    summary="List persisted model versions",
    description=(
        "Returns a paginated, filtered, and stably ordered list of persisted "
        "MULEGUARD model versions. Model artifact file paths are never exposed."
    ),
)
def list_model_versions(
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(version_pagination),
    _: User = Depends(require_permission(MODEL_READ_PERMISSION)),
    model_type: Annotated[
        Optional[ModelType],
        Query(description="Filter by model family."),
    ] = None,
    is_active: Annotated[
        Optional[bool],
        Query(description="Filter by active flag."),
    ] = None,
    feature_schema_version: Annotated[
        Optional[str],
        Query(max_length=32, description="Filter by feature schema version."),
    ] = None,
    dataset_fingerprint: Annotated[
        Optional[str],
        Query(max_length=128, description="Filter by dataset fingerprint."),
    ] = None,
    version: Annotated[
        Optional[str],
        Query(max_length=64, description="Exact version label filter."),
    ] = None,
) -> ModelVersionListResponse:
    """
    List persisted model versions.
    """
    _ensure_model_metrics_enabled(settings)

    conditions: list[Any] = []

    model_type_column = _model_column(ModelVersion, "model_type")
    active_column = _model_column(ModelVersion, "is_active")
    schema_version_column = _model_column(ModelVersion, "feature_schema_version")
    fingerprint_column = _model_column(ModelVersion, "dataset_fingerprint")
    version_column = _model_column(ModelVersion, "version")

    if model_type is not None and model_type_column is not None:
        conditions.append(model_type_column == model_type)

    if is_active is not None and active_column is not None:
        conditions.append(active_column.is_(is_active))

    if feature_schema_version and schema_version_column is not None:
        conditions.append(schema_version_column == feature_schema_version.strip())

    if dataset_fingerprint and fingerprint_column is not None:
        conditions.append(fingerprint_column == dataset_fingerprint.strip())

    if version and version_column is not None:
        conditions.append(version_column == version.strip())

    total = _scalar_count(
        db,
        _apply(select(func.count()).select_from(ModelVersion), conditions),
    )

    stmt = select(ModelVersion)
    stmt = _apply(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_MODEL_VERSION_COLUMN_MAP,
        tiebreaker=_MODEL_VERSION_TIEBREAKER,
        default_sort_by=_MODEL_VERSION_DEFAULT_SORT,
        default_sort_order="desc",
    )

    rows = db.scalars(stmt).all()

    return ModelVersionListResponse(
        items=[_version_response(row) for row in rows],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_MODEL_METRICS_CAVEATS),
    )


@router.get(
    "/versions/{version_id}",
    response_model=ModelVersionResponse,
    summary="Get one persisted model version",
    description=(
        "Returns safe metadata for one persisted MULEGUARD model version. "
        "Artifact file paths are never exposed."
    ),
)
def get_model_version(
    version_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Model version identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(MODEL_READ_PERMISSION)),
) -> ModelVersionResponse:
    """
    Retrieve one model version.
    """
    _ensure_model_metrics_enabled(settings)

    version = _get_model_version_or_404(db, version_id)
    return _version_response(version)


@router.get(
    "/versions/{version_id}/evaluations",
    response_model=ModelEvaluationListResponse,
    summary="List evaluations for one model version",
    description=(
        "Returns a paginated list of persisted evaluations for one model "
        "version. Metrics are reported honestly; undefined metrics are listed "
        "explicitly rather than invented."
    ),
)
def list_model_version_evaluations(
    version_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Model version identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    params: PageParams = Depends(evaluation_pagination),
    _: User = Depends(require_permission(MODEL_READ_PERMISSION)),
    split_strategy: Annotated[
        Optional[SplitStrategy],
        Query(description="Filter by evaluation split strategy."),
    ] = None,
) -> ModelEvaluationListResponse:
    """
    List evaluations for one model version.
    """
    _ensure_model_metrics_enabled(settings)

    _get_model_version_or_404(db, version_id)

    version_column = _model_column(ModelEvaluation, "model_version_id")

    if version_column is None:
        return ModelEvaluationListResponse(
            items=[],
            page=params.page,
            page_size=params.page_size,
            total=0,
            total_pages=0,
            sort_by=params.sort_by,
            sort_order=params.sort_order,
            caveats=[
                *_MODEL_METRICS_CAVEATS,
                "Evaluation linkage to model versions is not available in this schema.",
            ],
        )

    conditions: list[Any] = [version_column == version_id]

    split_column = _model_column(ModelEvaluation, "split_strategy")

    if split_strategy is not None and split_column is not None:
        conditions.append(split_column == split_strategy)

    total = _scalar_count(
        db,
        _apply(select(func.count()).select_from(ModelEvaluation), conditions),
    )

    stmt = select(ModelEvaluation)
    stmt = _apply(stmt, conditions)
    stmt = apply_pagination(
        stmt,
        params,
        column_map=_MODEL_EVALUATION_COLUMN_MAP,
        tiebreaker=_MODEL_EVALUATION_TIEBREAKER,
        default_sort_by=_MODEL_EVALUATION_DEFAULT_SORT,
        default_sort_order="desc",
    )

    rows = db.scalars(stmt).all()

    return ModelEvaluationListResponse(
        items=[_evaluation_response(row) for row in rows],
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=_total_pages(total, params.page_size),
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        caveats=list(_MODEL_METRICS_CAVEATS),
    )


@router.get(
    "/evaluations/{evaluation_id}",
    response_model=ModelEvaluationResponse,
    summary="Get one persisted model evaluation",
    description=(
        "Returns safe metadata and honest metric availability for one persisted "
        "model evaluation."
    ),
)
def get_model_evaluation(
    evaluation_id: Annotated[
        str,
        Path(min_length=1, max_length=128, description="Model evaluation identifier."),
    ],
    db: SessionDep,
    settings: SettingsDep,
    _: User = Depends(require_permission(MODEL_READ_PERMISSION)),
) -> ModelEvaluationResponse:
    """
    Retrieve one model evaluation.
    """
    _ensure_model_metrics_enabled(settings)

    evaluation = _get_model_evaluation_or_404(db, evaluation_id)
    return _evaluation_response(evaluation)


@router.get(
    "/compare",
    response_model=ModelComparisonResponse,
    summary="Compare bounded model versions and latest evaluations",
    description=(
        "Returns a bounded side-by-side view of two or three model versions "
        "and their latest evaluations. Comparisons are read-only and do not "
        "promote or retire models."
    ),
)
def compare_model_versions(
    db: SessionDep,
    settings: SettingsDep,
    version_ids: Annotated[
        list[str],
        Query(
            alias="version_id",
            description="Two or three model version identifiers to compare.",
        ),
    ],
    _: User = Depends(require_permission(MODEL_READ_PERMISSION)),
) -> ModelComparisonResponse:
    """
    Compare bounded model versions.
    """
    _ensure_model_metrics_enabled(settings)

    unique_ids = []

    for value in version_ids:
        text = str(value).strip()

        if text and text not in unique_ids:
            unique_ids.append(text)

    if len(unique_ids) < 2:
        raise MuleGuardValidationError(
            "At least two distinct version_id values are required for comparison.",
            details={"provided": len(unique_ids)},
        )

    if len(unique_ids) > _MAX_COMPARE_VERSIONS:
        raise MuleGuardValidationError(
            f"Comparison supports at most {_MAX_COMPARE_VERSIONS} model versions.",
            details={
                "provided": len(unique_ids),
                "max_versions": _MAX_COMPARE_VERSIONS,
            },
        )

    versions: list[Any] = []

    for version_id in unique_ids:
        versions.append(_get_model_version_or_404(db, version_id))

    version_responses = [_version_response(version) for version in versions]

    evaluations: list[ModelEvaluationResponse] = []
    metric_keys: set[str] = set()

    for version in versions:
        latest = _load_latest_evaluations_for_version(
            db,
            str(version.id),
            limit=1,
        )

        for evaluation in latest:
            response = _evaluation_response(evaluation)
            evaluations.append(response)

            available_metrics = response.metrics_summary.get("available_metrics", {})

            if isinstance(available_metrics, Mapping):
                metric_keys.update(
                    key
                    for key, value in available_metrics.items()
                    if _is_finite_number(value)
                )

    return ModelComparisonResponse(
        versions=version_responses,
        latest_evaluations=evaluations,
        metric_keys=sorted(metric_keys),
        caveats=list(_MODEL_METRICS_CAVEATS),
    )


__all__ = [
    "router",
]