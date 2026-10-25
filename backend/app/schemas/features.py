"""
MULEGUARD feature schemas.

A feature snapshot is **point-in-time**. `as_of` is the instant the features
describe, and every value in it was computed from data available strictly
before that instant. `computed_at` is when the computation actually ran, which
is usually later. Both are exposed because confusing them is how a feature set
ends up leaking the future into a model.

No response here can contain a ground-truth label, a scenario id, or a
fraud-ring id. Those live in a separate table and must never reach a predictor;
`FORBIDDEN_FEATURE_NAMES` is the list the validator rejects.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Final, Optional

from pydantic import Field, field_validator

from app.schemas.common import IdentifierField, MuleGuardModel, ResponseModel

__all__ = [
    "FORBIDDEN_FEATURE_NAMES",
    "FeatureCatalogEntry",
    "FeatureCatalogResponse",
    "FeatureSnapshotResponse",
    "FeatureSnapshotQueryParams",
]

# Names that would leak the label into the predictors. Rejected on the way out
# as well as on the way in: a snapshot containing one is a pipeline bug, and
# returning it would let a client train on it.
FORBIDDEN_FEATURE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "ground_truth_label",
        "label",
        "is_mule",
        "is_fraud",
        "scenario_id",
        "scenario_type",
        "ring_id",
        "fraud_ring_id",
        "disposition",
        "case_outcome",
    }
)


class FeatureCatalogEntry(ResponseModel):
    """
    One feature's definition.
    """

    name: str = Field(description="Canonical feature name.")
    label: str = Field(description="Human-readable label.")
    description: str = Field(description="What the feature measures.")
    dtype: str = Field(description="Value type.")
    category: str = Field(description="Feature family.")
    window: str = Field(description="Time window it is computed over.")
    source: str = Field(description="Which records it derives from.")
    unit: Optional[str] = Field(default=None)
    required: bool = Field(default=False)
    explainable: bool = Field(
        default=True,
        description="Whether the feature can be shown to an analyst as a reason.",
    )


class FeatureCatalogResponse(ResponseModel):
    """
    The feature catalogue.
    """

    version: str = Field(description="Catalogue version.")
    feature_count: int = Field(description="Number of features defined.")
    features: list[FeatureCatalogEntry] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    windows: list[str] = Field(default_factory=list)
    notes: list[str] = Field(
        default_factory=lambda: [
            "Features are computed point-in-time: each value reflects only "
            "what was knowable before the stated as_of instant.",
            "Ground-truth labels, scenario ids and fraud-ring ids are isolated "
            "and never appear as features.",
        ]
    )


class FeatureSnapshotResponse(ResponseModel):
    """
    One account's feature snapshot.
    """

    id: str = Field(description="Snapshot identifier.")
    account_id: str = Field(description="Account the features describe.")
    as_of: datetime = Field(
        description=(
            "The instant the features describe. Every value was computed from "
            "data strictly before it."
        )
    )
    computed_at: Optional[datetime] = Field(
        default=None,
        description=(
            "When the computation ran, which is usually later than as_of. "
            "Distinct from as_of so the two are never conflated."
        ),
    )
    feature_version: str = Field(description="Feature schema version.")
    window: Optional[str] = Field(default=None, description="Primary window label.")
    dataset_fingerprint: Optional[str] = Field(
        default=None, description="Dataset shape digest, for reproducibility."
    )
    values: dict[str, Any] = Field(
        default_factory=dict, description="Computed feature values."
    )
    value_count: int = Field(default=0)
    caveats: list[str] = Field(default_factory=list)

    @field_validator("values")
    @classmethod
    def _no_label_leakage(cls, value: dict[str, Any]) -> dict[str, Any]:
        """
        Refuse to serialise a snapshot containing a label-like feature.

        A snapshot holding one is a pipeline defect. Failing loudly here is far
        better than returning it and letting a client train on it.
        """
        leaked = sorted(
            name
            for name in value
            if str(name).strip().lower() in FORBIDDEN_FEATURE_NAMES
        )

        if leaked:
            raise ValueError(
                "feature snapshot contains label-like fields that must never "
                f"be used as predictors: {leaked}"
            )

        return value


class FeatureSnapshotQueryParams(MuleGuardModel):
    """
    Feature snapshot lookup.
    """

    account_id: IdentifierField = Field(description="Account to look up.")
    as_of: Optional[datetime] = Field(
        default=None,
        description=(
            "Return the latest snapshot at or before this instant. Defaults to "
            "the most recent snapshot."
        ),
    )
    feature_version: Optional[str] = Field(
        default=None, max_length=32, description="Restrict to one schema version."
    )
    include_values: bool = Field(
        default=True,
        description="Set false for metadata only, which is much cheaper.",
    )
