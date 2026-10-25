"""
MULEGUARD ingestion schemas.

Batch responses distinguish four outcomes per row, which matters because a
caller needs to know whether to retry, fix, or ignore:

- **accepted** — written.
- **duplicate** — already present. Not an error; a re-sent batch is expected to
  be mostly duplicates, and reporting them as failures would make an idempotent
  retry look broken.
- **rejected** — failed validation, returned with an index and a reason so the
  source file can be corrected.
- **batch rejected** — a referential problem that invalidates the whole batch,
  raised as an error rather than returned per-row.

Row errors carry the **index**, not the row contents. Echoing a rejected row
back would reflect unvalidated input into a response.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Optional

from pydantic import Field, field_validator

from app.schemas.common import (
    AmountField,
    IdentifierField,
    MuleGuardModel,
    ResponseModel,
)

__all__ = [
    "AccountIngestRecord",
    "BatchIngestResponse",
    "ComplaintIngestRecord",
    "EntityIngestRecord",
    "EntityLinkIngestRecord",
    "GenerateDataRequest",
    "GenerateDataResponse",
    "IngestRequest",
    "RowErrorResponse",
    "TransactionIngestRecord",
]

_MAX_BATCH = 10_000

CurrencyField = Annotated[str, Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")]


class AccountIngestRecord(MuleGuardModel):
    """
    One account to import.
    """

    id: IdentifierField = Field(description="Account identifier.")
    account_type: str = Field(default="OTHER", max_length=32)
    status: str = Field(default="ACTIVE", max_length=32)
    created_at: datetime = Field(description="Account opening timestamp, UTC.")
    metadata: Optional[dict[str, Any]] = Field(
        default=None, description="Non-sensitive synthetic attributes only."
    )


class TransactionIngestRecord(MuleGuardModel):
    """
    One transaction to import.
    """

    id: Optional[IdentifierField] = Field(default=None)
    reference: str = Field(
        min_length=1, max_length=128, description="Unique source reference."
    )
    sender_account_id: IdentifierField
    receiver_account_id: IdentifierField
    amount: AmountField = Field(description="Must be positive.")
    currency: CurrencyField = Field(default="INR")
    occurred_at: datetime
    status: str = Field(default="COMPLETED", max_length=32)
    channel: str = Field(default="INTERNAL", max_length=32)
    metadata: Optional[dict[str, Any]] = Field(default=None)

    @field_validator("receiver_account_id")
    @classmethod
    def _distinct_endpoints(cls, value: str, info) -> str:
        """
        Reject a self-transfer.
        """
        sender = (info.data or {}).get("sender_account_id")

        if sender and value == sender:
            raise ValueError("sender and receiver must differ")

        return value


class ComplaintIngestRecord(MuleGuardModel):
    """
    One complaint to import.
    """

    id: Optional[IdentifierField] = Field(default=None)
    reference: str = Field(min_length=1, max_length=128)
    reported_at: datetime
    category: str = Field(default="other", max_length=100)
    narrative_raw: str = Field(
        min_length=1,
        max_length=100_000,
        description="Stored verbatim as a source fact; never rewritten.",
    )
    transaction_reference: Optional[str] = Field(default=None, max_length=128)
    victim_account_id: Optional[IdentifierField] = Field(default=None)
    suspected_account_id: Optional[IdentifierField] = Field(default=None)
    amount: Optional[Decimal] = Field(default=None, gt=0)
    currency: Optional[CurrencyField] = Field(default=None)
    source: Optional[str] = Field(default=None, max_length=100)
    metadata: Optional[dict[str, Any]] = Field(default=None)


class EntityIngestRecord(MuleGuardModel):
    """
    One entity to import.

    `identifier_hash` must already be hashed. A raw device id, phone number or
    email address is never accepted.
    """

    id: Optional[IdentifierField] = Field(default=None)
    entity_type: str = Field(max_length=32)
    identifier_hash: str = Field(
        min_length=8,
        max_length=128,
        description=(
            "Pre-hashed identifier. Raw identifiers are rejected: MULEGUARD "
            "stores pseudonymous values only."
        ),
    )
    identifier_display: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Masked display label, never the real value.",
    )
    source: str = Field(default="synthetic", max_length=100)
    first_seen_at: Optional[datetime] = Field(default=None)
    last_seen_at: Optional[datetime] = Field(default=None)
    metadata: Optional[dict[str, Any]] = Field(default=None)


class EntityLinkIngestRecord(MuleGuardModel):
    """
    One account-entity link to import.
    """

    id: Optional[IdentifierField] = Field(default=None)
    account_id: IdentifierField
    entity_id: IdentifierField
    match_method: str = Field(default="EXACT", max_length=32)
    confidence: Optional[Decimal] = Field(default=None, ge=0, le=1)
    verification_state: str = Field(default="UNVERIFIED", max_length=32)
    valid_from: Optional[datetime] = Field(default=None)
    valid_to: Optional[datetime] = Field(default=None)
    source: str = Field(default="synthetic", max_length=100)
    metadata: Optional[dict[str, Any]] = Field(default=None)

    @field_validator("valid_to")
    @classmethod
    def _ordered(cls, value: Optional[datetime], info) -> Optional[datetime]:
        """
        Reject an inverted validity window.
        """
        start = (info.data or {}).get("valid_from")

        if value is not None and start is not None and value <= start:
            raise ValueError("valid_to must be after valid_from")

        return value


class IngestRequest(MuleGuardModel):
    """
    A batch import request.
    """

    records: list[dict[str, Any]] = Field(
        min_length=1,
        max_length=_MAX_BATCH,
        description=f"Records to import. At most {_MAX_BATCH} per batch.",
    )
    source_system: str = Field(
        default="import", max_length=100, description="Logical source name."
    )
    batch_id: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Caller-supplied batch identifier, recorded for lineage.",
    )


class RowErrorResponse(ResponseModel):
    """
    One rejected row.

    Carries the index and the reason, not the row contents: echoing back
    unvalidated input would reflect it into a response.
    """

    index: int = Field(ge=0, description="Zero-based position in the submitted batch.")
    reason: str = Field(description="Why the row was rejected.")
    field: Optional[str] = Field(default=None, description="Offending field, if known.")
    record_id: Optional[str] = Field(
        default=None, description="Record identifier, where one was parseable."
    )


class BatchIngestResponse(ResponseModel):
    """
    The outcome of a batch import.
    """

    entity_type: str = Field(description="What was imported.")
    received: int = Field(default=0, description="Rows submitted.")
    accepted: int = Field(default=0, description="Rows written.")
    duplicates: int = Field(
        default=0,
        description=(
            "Rows already present. Not an error: a re-sent batch is expected "
            "to be mostly duplicates."
        ),
    )
    rejected: int = Field(default=0, description="Rows that failed validation.")
    errors: list[RowErrorResponse] = Field(
        default_factory=list, description="A bounded sample of the rejections."
    )
    errors_truncated: bool = Field(
        default=False, description="True when more rows failed than are listed."
    )
    batch_id: Optional[str] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)


class GenerateDataRequest(MuleGuardModel):
    """
    A synthetic dataset generation request.
    """

    account_count: int = Field(default=500, ge=1, le=20_000)
    transaction_count: int = Field(default=5_000, ge=1, le=500_000)
    complaint_count: int = Field(default=100, ge=0, le=20_000)
    mule_ratio: float = Field(
        default=0.05,
        ge=0.0,
        le=0.5,
        description=(
            "Proportion of accounts given a mule typology. Kept low because a "
            "realistic base rate is what makes evaluation meaningful."
        ),
    )
    seed: int = Field(
        default=42,
        ge=0,
        description="Random seed. The same seed reproduces the same dataset.",
    )
    include_hard_negatives: bool = Field(
        default=True,
        description=(
            "Include legitimate accounts that superficially resemble mules "
            "(busy merchants, shared family devices). Without them a detector "
            "scores well and is useless."
        ),
    )
    persist: bool = Field(
        default=True, description="Write to the database rather than returning only."
    )


class GenerateDataResponse(ResponseModel):
    """
    The outcome of generation.
    """

    seed: int = Field(description="Seed used, so the dataset can be reproduced.")
    dataset_fingerprint: Optional[str] = Field(default=None)
    accounts: int = Field(default=0)
    transactions: int = Field(default=0)
    complaints: int = Field(default=0)
    entities: int = Field(default=0)
    entity_links: int = Field(default=0)
    ground_truth_labels: int = Field(
        default=0,
        description=(
            "Labels written to the isolated ground-truth table. They are never "
            "used as predictor features."
        ),
    )
    scenario_counts: dict[str, int] = Field(
        default_factory=dict, description="Accounts per injected typology."
    )
    duration_seconds: Optional[float] = Field(default=None)
    caveats: list[str] = Field(
        default_factory=lambda: [
            "Generated data is synthetic and is not calibrated against "
            "real-world fraud base rates.",
        ]
    )
