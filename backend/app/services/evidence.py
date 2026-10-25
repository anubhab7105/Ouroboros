"""
MULEGUARD evidence service.

Attaches evidence to cases and alerts, and resolves evidence references back to
the records they point at.

The central rule: **evidence must reference a record that exists.** Every
reference is validated against its table before it is stored. A reference to a
missing or mistyped record is worse than no reference, because a report would
cite it and an analyst would be unable to check it.

What is deliberately not supported: arbitrary URLs and free-text locations.
`EvidenceType` is a closed set mapped to real tables, so evidence cannot point
outside the system. That blocks both a server-side request forgery vector and
the quieter failure where evidence points at a document nobody can find later.

Removal is soft. `CaseEvidence` keeps `is_active`, `removed_by`, `removed_at`
and `removal_reason`, so a report generated last month can still be
reconstructed after an analyst detaches a record.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any, Final, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.exceptions import EvidenceValidationError
from app.models import (
    Account,
    Alert,
    AlertEvidence,
    CaseEvidence,
    Complaint,
    ComplaintCorrelation,
    EvidenceType,
    GraphAnalysisRun,
    ModelAssessment,
    Transaction,
    AccountEntityLink,
)
from app.utils.dates import utcnow
from app.utils.ids import is_safe_identifier, parse_evidence_ref
from app.utils.json import sanitize_json
from app.utils.text import clean_text

logger = logging.getLogger("muleguard.backend.services.evidence")

__all__ = [
    "EVIDENCE_SERVICE_VERSION",
    "EVIDENCE_MODELS",
    "add_case_evidence",
    "evidence_exists",
    "get_evidence_service_metadata",
    "list_case_evidence",
    "remove_case_evidence",
    "resolve_evidence_reference",
    "validate_evidence_reference",
]

EVIDENCE_SERVICE_VERSION: Final[str] = "v1"

# The closed mapping from evidence type to the table it must resolve against.
EVIDENCE_MODELS: Final[dict[EvidenceType, Any]] = {
    EvidenceType.ACCOUNT: Account,
    EvidenceType.TRANSACTION: Transaction,
    EvidenceType.COMPLAINT: Complaint,
    EvidenceType.ALERT: Alert,
    EvidenceType.GRAPH_PATH: GraphAnalysisRun,
    EvidenceType.MODEL_ASSESSMENT: ModelAssessment,
    EvidenceType.ENTITY_LINK: AccountEntityLink,
}

_MAX_EVIDENCE_PER_CASE: Final[int] = 500


def _coerce_type(value: Any) -> Optional[EvidenceType]:
    """
    Coerce a value into an EvidenceType, or None.
    """
    if isinstance(value, EvidenceType):
        return value

    token = str(getattr(value, "value", value) or "").strip().upper()
    return EvidenceType[token] if token in EvidenceType.__members__ else None


def evidence_exists(db: Session, evidence_type: Any, evidence_id: str) -> bool:
    """
    Return True when an evidence reference resolves to a real record.
    """
    kind = _coerce_type(evidence_type)

    if kind is None:
        return False

    model = EVIDENCE_MODELS.get(kind)

    if model is None:
        return False

    identifier = str(evidence_id or "").strip()

    if not identifier or not is_safe_identifier(identifier, max_length=128):
        return False

    return db.get(model, identifier) is not None


def validate_evidence_reference(
    db: Session,
    evidence_type: Any,
    evidence_id: str,
) -> tuple[EvidenceType, str]:
    """
    Validate a reference and return its normalised form.

    Raises EvidenceValidationError with a specific reason, so an analyst sees
    which part of the reference was wrong.
    """
    kind = _coerce_type(evidence_type)

    if kind is None:
        raise EvidenceValidationError(
            "Unsupported evidence type.",
            details={
                "provided": str(evidence_type),
                "supported": [item.value for item in EvidenceType],
            },
        )

    identifier = str(evidence_id or "").strip()

    if not identifier:
        raise EvidenceValidationError(
            "Evidence identifier is required.",
            details={"evidence_type": kind.value},
        )

    if not is_safe_identifier(identifier, max_length=128):
        # Rejects whitespace, quoting, path separators and overlong values.
        raise EvidenceValidationError(
            "Evidence identifier is not a valid record identifier.",
            details={"evidence_type": kind.value},
        )

    if not evidence_exists(db, kind, identifier):
        raise EvidenceValidationError(
            "Evidence does not reference an existing record. Evidence must "
            "point at a record that can be inspected.",
            details={"evidence_type": kind.value, "evidence_id": identifier[:128]},
        )

    return kind, identifier


def resolve_evidence_reference(db: Session, reference: str) -> Optional[Any]:
    """
    Resolve a `TYPE:id` reference string to its record, or None.
    """
    kind_token, identifier = parse_evidence_ref(reference)

    if kind_token is None or identifier is None:
        return None

    kind = _coerce_type(kind_token)

    if kind is None:
        return None

    model = EVIDENCE_MODELS.get(kind)

    if model is None:
        return None

    return db.get(model, identifier)


def add_case_evidence(
    db: Session,
    *,
    case_id: str,
    evidence_type: Any,
    evidence_id: str,
    added_by: Optional[str] = None,
    snapshot: Optional[Mapping[str, Any]] = None,
    provenance: Optional[Mapping[str, Any]] = None,
) -> CaseEvidence:
    """
    Attach validated evidence to a case.

    Re-attaching an item that was soft-removed reactivates the original row
    rather than inserting a second one, keeping the removal history intact.
    """
    kind, identifier = validate_evidence_reference(db, evidence_type, evidence_id)

    existing = db.execute(
        select(CaseEvidence)
        .where(CaseEvidence.case_id == str(case_id))
        .where(CaseEvidence.evidence_type == kind)
        .where(CaseEvidence.evidence_id == identifier)
        .limit(1)
    ).scalars().first()

    if existing is not None:
        if not existing.is_active:
            existing.is_active = True
            existing.removed_at = None
            existing.removed_by = None
            existing.removal_reason = None
            db.flush()

        return existing

    active_count = int(
        db.execute(
            select(func.count())
            .select_from(CaseEvidence)
            .where(CaseEvidence.case_id == str(case_id))
            .where(CaseEvidence.is_active.is_(True))
        ).scalar()
        or 0
    )

    if active_count >= _MAX_EVIDENCE_PER_CASE:
        raise EvidenceValidationError(
            "This case has reached the maximum number of attached evidence "
            "items.",
            details={"limit": _MAX_EVIDENCE_PER_CASE},
        )

    record = CaseEvidence(
        case_id=str(case_id),
        evidence_type=kind,
        evidence_id=identifier,
        evidence_snapshot_json=(
            sanitize_json(dict(snapshot), max_items=40) if snapshot else None
        ),
        provenance_json=sanitize_json(
            {
                "attached_by_service": "muleguard.backend.services.evidence",
                "service_version": EVIDENCE_SERVICE_VERSION,
                **dict(provenance or {}),
            },
            max_items=30,
        ),
        added_by=added_by,
        is_active=True,
    )
    db.add(record)
    db.flush()
    return record


def remove_case_evidence(
    db: Session,
    *,
    case_id: str,
    evidence_record_id: str,
    removed_by: Optional[str] = None,
    reason: Optional[str] = None,
) -> Optional[CaseEvidence]:
    """
    Soft-remove a case evidence attachment.

    The row is kept so a previously generated report remains reconstructible.
    """
    record = db.get(CaseEvidence, str(evidence_record_id))

    if record is None or str(record.case_id) != str(case_id):
        return None

    if not record.is_active:
        return record

    record.is_active = False
    record.removed_at = utcnow()
    record.removed_by = removed_by
    record.removal_reason = clean_text(reason or "", 1_000) or None
    db.flush()
    return record


def list_case_evidence(
    db: Session,
    case_id: str,
    *,
    evidence_types: Optional[Sequence[EvidenceType]] = None,
    include_removed: bool = False,
    limit: int = 200,
    offset: int = 0,
) -> list[CaseEvidence]:
    """
    Return a case's evidence attachments.
    """
    stmt = select(CaseEvidence).where(CaseEvidence.case_id == str(case_id))

    if not include_removed:
        stmt = stmt.where(CaseEvidence.is_active.is_(True))

    if evidence_types:
        stmt = stmt.where(CaseEvidence.evidence_type.in_(list(evidence_types)))

    stmt = (
        stmt.order_by(CaseEvidence.record_created_at.asc())
        .offset(max(0, int(offset)))
        .limit(max(1, min(int(limit), _MAX_EVIDENCE_PER_CASE)))
    )
    return list(db.execute(stmt).scalars())


def get_evidence_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the evidence service.
    """
    return {
        "service": "muleguard.backend.services.evidence",
        "version": EVIDENCE_SERVICE_VERSION,
        "supported_types": {
            kind.value: getattr(model, "__tablename__", str(model))
            for kind, model in EVIDENCE_MODELS.items()
        },
        "limits": {"max_active_evidence_per_case": _MAX_EVIDENCE_PER_CASE},
        "guarantees": [
            "Every reference is validated against its table before storage.",
            "Arbitrary URLs and free-text locations are not accepted; evidence "
            "cannot point outside the system.",
            "Identifiers are checked for shape before any lookup.",
            "Removal is soft, so an earlier report stays reconstructible.",
            "Re-attaching a removed item reactivates it rather than duplicating it.",
        ],
    }
