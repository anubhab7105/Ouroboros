"""
MULEGUARD report schemas.

`limitations` is required on every report response, not optional. A report that
lists accounts under headings like "high risk" will be read by someone who did
not run the analysis and may be attached to a referral; the limitations are
what stop a prioritisation signal from being read as a finding of fact.

`evidence_index` is also always present. Every claim in a report traces to a
persisted record, and the index is how a reader works backwards from a
conclusion to its sources.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Optional

from pydantic import Field

from app.schemas.common import IdentifierField, MuleGuardModel, ResponseModel

__all__ = [
    "EvidenceIndexEntryResponse",
    "ReportGenerateRequest",
    "ReportLimitationsResponse",
    "ReportPreviewResponse",
    "ReportSectionResponse",
]

_FORMATS = ("pdf", "json")

ReportFormatField = Annotated[str, Field(pattern=f"^({'|'.join(_FORMATS)})$")]


class ReportGenerateRequest(MuleGuardModel):
    """
    A report generation request.
    """

    format: ReportFormatField = Field(
        default="pdf",
        description=(
            "pdf for distribution, json for a machine-readable copy. JSON "
            "remains available when the PDF engine is not installed."
        ),
    )
    include_internal_notes: bool = Field(
        default=False,
        description=(
            "Internal notes are written for colleagues. Defaults to excluded "
            "so a report is safe to share without re-reading every note."
        ),
    )
    include_transactions: bool = Field(
        default=True, description="Include the transaction timeline section."
    )
    include_evidence_index: bool = Field(default=True)


class ReportSectionResponse(ResponseModel):
    """
    One rendered section.
    """

    title: str = Field(description="Section heading.")
    kind: str = Field(description="table, key_value or narrative.")
    summary: Optional[str] = Field(default=None)
    columns: list[str] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = Field(default=0)
    truncated_rows: int = Field(
        default=0,
        description=(
            "Rows omitted for length. Stated rather than hidden: a silently "
            "shortened table misrepresents the data."
        ),
    )
    evidence_refs: list[str] = Field(
        default_factory=list, description="Records this section was built from."
    )
    notes: list[str] = Field(default_factory=list)


class EvidenceIndexEntryResponse(ResponseModel):
    """
    One cited record.
    """

    reference: str = Field(description="Canonical TYPE:id reference.")
    evidence_type: str = Field(description="Record type.")
    evidence_id: str = Field(description="Record identifier.")
    label: str = Field(description="Human-readable type label.")
    cited_in: list[str] = Field(
        default_factory=list, description="Sections citing this record."
    )
    resolved: Optional[bool] = Field(
        default=None,
        description=(
            "Whether the record still exists. Reported rather than dropped, "
            "because a reader who cannot find a cited record should know the "
            "system cannot either."
        ),
    )


class ReportLimitationsResponse(ResponseModel):
    """
    The canonical limitations text.

    Served so the frontend displays exactly the wording the PDF carries, rather
    than keeping its own copy and drifting from it.
    """

    version: str = Field(description="Limitations text version.")
    score_semantics: str = Field(description="What the score is, and is not.")
    core: list[str] = Field(default_factory=list)
    data: list[str] = Field(default_factory=list)
    model: list[str] = Field(default_factory=list)
    graph: list[str] = Field(default_factory=list)
    prohibited_uses: list[str] = Field(
        default_factory=list,
        description="Uses the platform's output must not be put to.",
    )


class ReportPreviewResponse(ResponseModel):
    """
    A report's content before rendering.

    Lets a client show what the report will contain, and serves as the JSON
    export format.
    """

    title: str = Field(description="Report title.")
    subtitle: Optional[str] = Field(default=None)
    subject_type: str = Field(description="case or account.")
    subject_id: str = Field(description="Subject identifier.")
    generated_at: datetime = Field(description="When it was assembled, UTC.")
    generated_by: Optional[str] = Field(default=None)

    sections: list[ReportSectionResponse] = Field(default_factory=list)
    limitations: list[str] = Field(
        description=(
            "Required, not optional. The interpretation limits travel with the "
            "findings."
        )
    )
    evidence_index: list[EvidenceIndexEntryResponse] = Field(default_factory=list)
    unresolved_evidence_count: int = Field(
        default=0,
        description="Cited records that no longer resolve.",
    )

    content_fingerprint: Optional[str] = Field(
        default=None,
        description=(
            "Digest of the report's content, printed in the PDF footer so two "
            "copies can be compared."
        ),
    )
    estimated_pages: Optional[int] = Field(default=None)
    pdf_available: bool = Field(
        default=True,
        description="False when the PDF engine is not installed; JSON still works.",
    )
