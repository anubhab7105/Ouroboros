"""
MULEGUARD model metrics service.

Reads model versions and their evaluations for the model-monitoring page, and
reports the active scoring mode.

The governing rule: **a metric that was not computed is reported as
unavailable, never as a number.** A fabricated AUC is worse than a blank field,
because a reader will act on it. `ModelEvaluation.undefined_metrics_json`
exists to record *why* a metric is absent, and this service surfaces that
rather than defaulting to zero.

The second rule: **a model is not described as validated unless it has an
evaluation.** A promoted model version with no evaluation row is reported with
`has_evaluation: false`, so the monitoring page can say so plainly.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any, Final, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    ModelAssessment,
    ModelEvaluation,
    ModelType,
    ModelVersion,
    ScoringMode,
    SplitStrategy,
)
from app.utils.dates import ensure_utc, utcnow
from app.utils.decimals import to_float
from app.utils.json import sanitize_json

logger = logging.getLogger("muleguard.backend.services.model_metrics")

__all__ = [
    "MODEL_METRICS_SERVICE_VERSION",
    "HEADLINE_METRICS",
    "active_model_version",
    "active_scoring_mode",
    "evaluation_payload",
    "get_model_metrics_service_metadata",
    "latest_evaluation",
    "list_model_versions",
    "model_version_payload",
    "scoring_mode_distribution",
]

MODEL_METRICS_SERVICE_VERSION: Final[str] = "v1"

# Metrics the monitoring page shows when they exist. Ordered as an analyst
# reads them: ranking quality first, then operating-point behaviour.
HEADLINE_METRICS: Final[tuple[str, ...]] = (
    "roc_auc",
    "average_precision",
    "precision_at_k",
    "recall_at_k",
    "precision",
    "recall",
    "f1",
    "brier_score",
    "false_positive_rate",
)


def active_model_version(db: Session) -> Optional[ModelVersion]:
    """
    Return the promoted model version, if any.
    """
    return db.execute(
        select(ModelVersion)
        .where(ModelVersion.is_active.is_(True))
        .order_by(ModelVersion.record_created_at.desc())
        .limit(1)
    ).scalars().first()


def active_scoring_mode(db: Session) -> dict[str, Any]:
    """
    Report which scoring mode the platform is actually running in.

    Derived from the most recent assessments rather than from configuration:
    what the system did is more informative than what it intended to do.
    """
    recent = db.execute(
        select(ModelAssessment.scoring_mode, func.count())
        .group_by(ModelAssessment.scoring_mode)
        .order_by(func.count().desc())
    ).all()

    distribution = {
        str(getattr(mode, "value", mode)): int(count) for mode, count in recent
    }
    dominant = max(distribution.items(), key=lambda kv: kv[1])[0] if distribution else None
    active = active_model_version(db)

    explanations = {
        ScoringMode.TRAINED_MODEL.value: (
            "A validated supervised model is active and contributing to scores."
        ),
        ScoringMode.HEURISTIC_FALLBACK.value: (
            "No trained model is promoted, so scores use the transparent "
            "heuristic scorer. Its weights are hand-set, not learned."
        ),
        ScoringMode.RULES_ONLY.value: (
            "Scores come from rule evaluation alone. Only typologies encoded in "
            "the rule pack can be detected."
        ),
        ScoringMode.ML_DISABLED.value: (
            "Machine-learning scoring is disabled in configuration."
        ),
        ScoringMode.UNKNOWN.value: "No assessments have been produced yet.",
    }

    return {
        "mode": dominant or ScoringMode.UNKNOWN.value,
        "explanation": explanations.get(
            dominant or ScoringMode.UNKNOWN.value, "Scoring mode is unknown."
        ),
        "distribution": distribution,
        "active_model_version": str(active.version) if active is not None else None,
        "active_model_version_id": str(active.id) if active is not None else None,
        "has_active_trained_model": bool(
            active is not None
            and active.model_type
            not in {ModelType.RULES_ONLY, ModelType.HEURISTIC_FALLBACK, ModelType.UNKNOWN}
        ),
    }


def latest_evaluation(db: Session, model_version_id: str) -> Optional[ModelEvaluation]:
    """
    Return the most recent evaluation for a model version.
    """
    return db.execute(
        select(ModelEvaluation)
        .where(ModelEvaluation.model_version_id == str(model_version_id))
        .order_by(ModelEvaluation.record_created_at.desc())
        .limit(1)
    ).scalars().first()


def evaluation_payload(evaluation: Optional[ModelEvaluation]) -> dict[str, Any]:
    """
    Return a safe evaluation payload.

    Metrics absent from `metrics_json` are listed under
    `unavailable_metrics` with the recorded reason, never emitted as 0.
    """
    if evaluation is None:
        return {
            "available": False,
            "reason": (
                "This model version has no evaluation record, so its "
                "performance is unknown. It must not be described as validated."
            ),
            "metrics": {},
            "unavailable_metrics": {
                name: "no evaluation record exists" for name in HEADLINE_METRICS
            },
        }

    raw = evaluation.metrics_json if isinstance(evaluation.metrics_json, Mapping) else {}
    undefined = (
        evaluation.undefined_metrics_json
        if isinstance(evaluation.undefined_metrics_json, Mapping)
        else {}
    )

    metrics: dict[str, Any] = {}
    unavailable: dict[str, str] = {}

    for name in HEADLINE_METRICS:
        if name in raw and raw[name] is not None:
            value = to_float(raw[name])

            if value is not None:
                metrics[name] = value
                continue

        unavailable[name] = str(
            undefined.get(name)
            or "not computed for this evaluation"
        )

    # Metrics present but outside the headline list are still shown.
    for name, value in raw.items():
        if name in metrics or name in unavailable:
            continue

        numeric = to_float(value)

        if numeric is not None:
            metrics[str(name)] = numeric

    return {
        "available": True,
        "evaluation_id": str(evaluation.id),
        "sample_count": int(evaluation.sample_count or 0),
        "split_strategy": str(
            getattr(evaluation.split_strategy, "value", evaluation.split_strategy)
        ),
        "dataset_fingerprint": evaluation.dataset_fingerprint,
        "threshold": to_float(evaluation.threshold),
        "top_k": evaluation.top_k,
        "metrics": metrics,
        "unavailable_metrics": unavailable,
        "class_distribution": sanitize_json(
            evaluation.class_distribution_json or {}, max_items=20
        ),
        "latency": {
            "ms_per_account": to_float(evaluation.latency_ms_per_account),
            "batch_size": evaluation.latency_batch_size,
        },
        "limitations": evaluation.limitations,
        "evaluated_at": (
            ensure_utc(evaluation.record_created_at).isoformat()
            if evaluation.record_created_at
            else None
        ),
    }


def model_version_payload(
    db: Session,
    version: ModelVersion,
    *,
    include_evaluation: bool = True,
) -> dict[str, Any]:
    """
    Return a safe payload for one model version.

    `artifact_path` is deliberately excluded: a filesystem path in an API
    response is an information leak and of no use to the UI.
    """
    evaluation = latest_evaluation(db, str(version.id)) if include_evaluation else None

    assessment_count = int(
        db.execute(
            select(func.count())
            .select_from(ModelAssessment)
            .where(ModelAssessment.model_version_id == str(version.id))
        ).scalar()
        or 0
    )

    return {
        "id": str(version.id),
        "version": str(version.version),
        "model_type": str(getattr(version.model_type, "value", version.model_type)),
        "feature_schema_version": str(version.feature_schema_version),
        "split_strategy": str(
            getattr(version.split_strategy, "value", version.split_strategy)
        ),
        "is_active": bool(version.is_active),
        "training_seed": version.training_seed,
        "trained_at": (
            ensure_utc(version.training_finished_at).isoformat()
            if version.training_finished_at
            else None
        ),
        "dataset_fingerprint": version.dataset_fingerprint,
        "has_artifact": bool(version.artifact_path),
        "artifact_checksum": version.artifact_checksum,
        "checksum_algorithm": version.checksum_algorithm,
        "assessments_produced": assessment_count,
        "has_evaluation": evaluation is not None,
        "evaluation": evaluation_payload(evaluation) if include_evaluation else None,
        "limitations": sanitize_json(version.limitations_json or {}, max_items=30),
        "notes": version.notes,
    }


def list_model_versions(
    db: Session,
    *,
    active_only: bool = False,
    limit: int = 50,
    offset: int = 0,
    include_evaluation: bool = True,
) -> tuple[list[dict[str, Any]], int]:
    """
    Return a page of model versions with their latest evaluations.
    """
    count_stmt = select(func.count()).select_from(ModelVersion)
    page_stmt = select(ModelVersion)

    if active_only:
        count_stmt = count_stmt.where(ModelVersion.is_active.is_(True))
        page_stmt = page_stmt.where(ModelVersion.is_active.is_(True))

    total = int(db.execute(count_stmt).scalar() or 0)
    page_stmt = (
        page_stmt.order_by(
            ModelVersion.is_active.desc(), ModelVersion.record_created_at.desc()
        )
        .offset(max(0, int(offset)))
        .limit(max(1, min(int(limit), 200)))
    )

    return (
        [
            model_version_payload(db, version, include_evaluation=include_evaluation)
            for version in db.execute(page_stmt).scalars()
        ],
        total,
    )


def scoring_mode_distribution(
    db: Session,
    *,
    since: Optional[Any] = None,
) -> dict[str, int]:
    """
    Return assessment counts by scoring mode.
    """
    stmt = select(ModelAssessment.scoring_mode, func.count()).group_by(
        ModelAssessment.scoring_mode
    )

    lower = ensure_utc(since)

    if lower is not None:
        stmt = stmt.where(ModelAssessment.scored_at >= lower)

    rows = db.execute(stmt).all()
    counts = {mode.value: 0 for mode in ScoringMode}

    for mode, count in rows:
        counts[str(getattr(mode, "value", mode))] = int(count)

    return counts


def get_model_metrics_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the model metrics service.
    """
    return {
        "service": "muleguard.backend.services.model_metrics",
        "version": MODEL_METRICS_SERVICE_VERSION,
        "headline_metrics": list(HEADLINE_METRICS),
        "model_types": [item.value for item in ModelType],
        "scoring_modes": [item.value for item in ScoringMode],
        "split_strategies": [item.value for item in SplitStrategy],
        "guarantees": [
            "A metric that was not computed is reported as unavailable with a "
            "reason, never as zero.",
            "A model version without an evaluation is reported with "
            "has_evaluation: false and is not described as validated.",
            "Artifact filesystem paths are never included in a payload.",
            "The active scoring mode is derived from what the system actually "
            "did, not from configuration.",
        ],
    }
