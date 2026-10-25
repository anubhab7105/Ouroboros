"""
MULEGUARD model metrics schemas.

`metrics` holds only values that were actually computed. Anything absent
appears in `unavailable_metrics` with the reason. A metric is never defaulted
to zero, because a reader will act on a zero and cannot act on a blank.

`has_evaluation` is separate from `is_active`. A promoted model with no
evaluation record is reported as active but unvalidated, which is a state an
operator needs to see rather than one to paper over.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Optional

from pydantic import Field

from app.schemas.common import MuleGuardModel, ResponseModel
from app.schemas.pagination import PaginatedResponse

__all__ = [
    "EvaluationResponse",
    "FeatureSchemaSummary",
    "ModelVersionListResponse",
    "ModelVersionResponse",
    "ScoringModeResponse",
]

_SCORING_MODES = (
    "TRAINED_MODEL",
    "HEURISTIC_FALLBACK",
    "RULES_ONLY",
    "ML_DISABLED",
    "UNKNOWN",
)

ScoringModeField = Annotated[str, Field(pattern=f"^({'|'.join(_SCORING_MODES)})$")]


class EvaluationResponse(ResponseModel):
    """
    A model evaluation.
    """

    available: bool = Field(
        description=(
            "False when no evaluation record exists. The model's performance "
            "is then unknown and it must not be described as validated."
        )
    )
    reason: Optional[str] = Field(
        default=None, description="Why no evaluation is available, when it is not."
    )
    evaluation_id: Optional[str] = Field(default=None)
    sample_count: int = Field(default=0)
    split_strategy: Optional[str] = Field(
        default=None,
        description=(
            "How the evaluation partition was chosen. A chronological or "
            "scenario-aware split is the only honest one here; a random split "
            "over transaction data leaks across time."
        ),
    )
    dataset_fingerprint: Optional[str] = Field(default=None)
    threshold: Optional[float] = Field(default=None)
    top_k: Optional[int] = Field(default=None)

    metrics: dict[str, float] = Field(
        default_factory=dict, description="Metrics that were actually computed."
    )
    unavailable_metrics: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Metric name to the reason it is absent. Never defaulted to zero: "
            "a blank is honest, a zero is misleading."
        ),
    )
    class_distribution: dict[str, Any] = Field(default_factory=dict)
    latency_ms_per_account: Optional[float] = Field(default=None)
    latency_batch_size: Optional[int] = Field(default=None)
    limitations: Optional[str] = Field(default=None)
    evaluated_at: Optional[datetime] = Field(default=None)


class ModelVersionResponse(ResponseModel):
    """
    A model version with its latest evaluation.
    """

    id: str = Field(description="Model version identifier.")
    version: str = Field(description="Human-readable version.")
    model_type: str = Field(description="Model family or scoring baseline.")
    feature_schema_version: str = Field(description="Feature schema it expects.")
    split_strategy: str = Field(default="UNKNOWN")
    is_active: bool = Field(description="Whether it is the promoted model.")
    has_evaluation: bool = Field(
        default=False,
        description=(
            "Separate from is_active: a promoted model with no evaluation is "
            "active but unvalidated."
        ),
    )
    trained_at: Optional[datetime] = Field(default=None)
    training_seed: Optional[int] = Field(
        default=None, description="Seed used, so training can be reproduced."
    )
    dataset_fingerprint: Optional[str] = Field(default=None)
    has_artifact: bool = Field(
        default=False,
        description=(
            "Whether a model artifact is on disk. The path itself is never "
            "returned."
        ),
    )
    artifact_checksum: Optional[str] = Field(
        default=None,
        description="Checksum verified before the artifact is loaded.",
    )
    assessments_produced: int = Field(default=0)
    evaluation: Optional[EvaluationResponse] = Field(default=None)
    limitations: dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = Field(default=None)


class ModelVersionListResponse(PaginatedResponse[ModelVersionResponse]):
    """
    A page of model versions.
    """


class ScoringModeResponse(ResponseModel):
    """
    The scoring mode the platform is actually running in.
    """

    mode: str = Field(
        description=(
            "Derived from recent assessments, not from configuration: what the "
            "system did is more informative than what it intended."
        )
    )
    explanation: str = Field(description="What the mode means for a reader.")
    distribution: dict[str, int] = Field(
        default_factory=dict, description="Assessment counts per mode."
    )
    active_model_version: Optional[str] = Field(default=None)
    active_model_version_id: Optional[str] = Field(default=None)
    has_active_trained_model: bool = Field(
        default=False,
        description=(
            "False when the active version is a rules-only or heuristic "
            "baseline rather than a trained classifier."
        ),
    )
    caveats: list[str] = Field(
        default_factory=lambda: [
            "Where a trained model contributed, it was trained on synthetic "
            "labels; its measured performance describes that distribution only.",
            "Risk-fusion component weights are a configured product decision, "
            "not a learned optimum.",
        ]
    )


class FeatureSchemaSummary(ResponseModel):
    """
    A summary of the active feature schema.
    """

    version: str = Field(description="Schema version.")
    feature_count: int = Field(description="Features defined.")
    categories: dict[str, int] = Field(
        default_factory=dict, description="Feature count per category."
    )
    windows: list[str] = Field(default_factory=list)
    required_features: list[str] = Field(default_factory=list)
    forbidden_features: list[str] = Field(
        default_factory=list,
        description=(
            "Names rejected as predictors because they would leak the label."
        ),
    )
