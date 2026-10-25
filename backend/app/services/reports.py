"""
MULEGUARD report data service.

Gathers everything a case or account report needs and returns it as a
structured document model. Rendering is `app.reports`' job; this module only
decides what goes in and what must not.

Two rules govern the contents:

- **Every claim is traceable.** Each section carries the evidence references it
  was built from, so a reader can verify any statement against a persisted
  record. A figure with no resolvable source is omitted rather than printed
  unattributed.
- **Limitations travel with the findings.** `build_limitations` is not
  optional decoration. A report that lists high-risk accounts without saying
  what the score means, that it was computed on synthetic data, and that it is
  not a finding of guilt, is a document that will be misread.

Internal notes are excluded unless explicitly requested, because they are
written for colleagues rather than for whoever eventually receives the report.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final, Optional

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.exceptions import NotFoundError
from app.models import (
    Account,
    Alert,
    Complaint,
    ComplaintCorrelation,
    GraphAnalysisRun,
    InvestigationCase,
    ModelAssessment,
    RiskIndicator,
    RuleHit,
    Transaction,
    TransactionStatus,
    User,
)
from app.services.case_events import list_case_events
from app.services.evidence import list_case_evidence
from app.services.notes import list_case_notes
from app.utils.dates import ensure_utc, utcnow
from app.utils.decimals import to_float
from app.utils.hashing import fingerprint
from app.utils.ids import evidence_ref
from app.utils.json import sanitize_json
from app.utils.text import clean_text, truncate

logger = logging.getLogger("muleguard.backend.services.reports")

__all__ = [
    "REPORTS_SERVICE_VERSION",
    "ReportDocument",
    "ReportSection",
    "build_account_report",
    "build_case_report",
    "build_limitations",
    "get_reports_service_metadata",
]

REPORTS_SERVICE_VERSION: Final[str] = "v1"

_MAX_ROWS_PER_SECTION: Final[int] = 100
_MAX_TRANSACTIONS: Final[int] = 200


class ReportSection:
    """
    One section of a report.
    """

    __slots__ = ("columns", "evidence_refs", "kind", "notes", "rows", "summary", "title")

    def __init__(
        self,
        *,
        title: str,
        kind: str = "table",
        summary: Optional[str] = None,
        columns: Optional[Sequence[str]] = None,
        rows: Optional[Sequence[Mapping[str, Any]]] = None,
        evidence_refs: Optional[Sequence[str]] = None,
        notes: Optional[Sequence[str]] = None,
    ) -> None:
        self.title = str(title)
        self.kind = str(kind)
        self.summary = summary
        self.columns = list(columns or [])
        self.rows = [dict(row) for row in (rows or [])][:_MAX_ROWS_PER_SECTION]
        self.evidence_refs = [str(r) for r in (evidence_refs or []) if r][:200]
        self.notes = [str(n) for n in (notes or [])]

    @property
    def row_count(self) -> int:
        """
        Number of rows in the section.
        """
        return len(self.rows)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation.
        """
        return {
            "title": self.title,
            "kind": self.kind,
            "summary": self.summary,
            "columns": self.columns,
            "rows": sanitize_json(self.rows, max_items=_MAX_ROWS_PER_SECTION),
            "row_count": self.row_count,
            "evidence_refs": self.evidence_refs,
            "notes": self.notes,
        }


class ReportDocument:
    """
    A complete report, ready for rendering.
    """

    __slots__ = (
        "generated_at",
        "generated_by",
        "limitations",
        "metadata",
        "sections",
        "subject_id",
        "subject_type",
        "subtitle",
        "title",
    )

    def __init__(
        self,
        *,
        title: str,
        subject_type: str,
        subject_id: str,
        subtitle: Optional[str] = None,
        sections: Optional[Sequence[ReportSection]] = None,
        limitations: Optional[Sequence[str]] = None,
        generated_by: Optional[str] = None,
        generated_at: Optional[datetime] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.title = str(title)
        self.subtitle = subtitle
        self.subject_type = str(subject_type)
        self.subject_id = str(subject_id)
        self.sections = list(sections or [])
        self.limitations = list(limitations or [])
        self.generated_by = generated_by
        self.generated_at = ensure_utc(generated_at) or utcnow()
        self.metadata = dict(metadata or {})

    @property
    def evidence_refs(self) -> list[str]:
        """
        Every distinct evidence reference cited anywhere in the report.
        """
        seen: list[str] = []
        known: set[str] = set()

        for section in self.sections:
            for reference in section.evidence_refs:
                if reference not in known:
                    known.add(reference)
                    seen.append(reference)

        return seen

    def content_fingerprint(self) -> str:
        """
        Return a digest of the report's content.

        Printed in the footer so two copies of a report can be compared, and a
        later regeneration can be shown to differ.
        """
        return fingerprint(
            {
                "title": self.title,
                "subject": [self.subject_type, self.subject_id],
                "sections": [
                    [s.title, s.row_count, s.evidence_refs] for s in self.sections
                ],
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation.
        """
        return {
            "title": self.title,
            "subtitle": self.subtitle,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "sections": [section.to_dict() for section in self.sections],
            "limitations": self.limitations,
            "evidence_index": self.evidence_refs,
            "content_fingerprint": self.content_fingerprint(),
            "metadata": sanitize_json(self.metadata, max_items=40),
            "report_service_version": REPORTS_SERVICE_VERSION,
        }


def build_limitations(
    *,
    scoring_mode: Optional[str] = None,
    has_trained_model: bool = False,
    graph_capped: bool = False,
    synthetic: bool = True,
    include_correlation_note: bool = False,
) -> list[str]:
    """
    Build the limitations text that accompanies every report.

    Tailored to what the report actually contains: a report with no graph
    section does not need a traversal caveat, and claiming limitations that do
    not apply trains readers to skip the section.
    """
    limitations: list[str] = [
        "Risk scores in this report are investigative priority signals. They "
        "rank accounts for analyst attention and are not probabilities of "
        "criminal guilt.",
        "Alerts, correlations, graph relationships and candidate money trails "
        "are investigative leads. None of them establishes that an account "
        "holder participated in wrongdoing.",
        "This report does not authorise any automatic action against an "
        "account. Account restrictions require a separate human decision under "
        "the applicable policy and legal process.",
    ]

    if synthetic:
        limitations.append(
            "The data underlying this report is synthetic. Figures are not "
            "calibrated against real-world fraud base rates and must not be "
            "used to estimate real exposure."
        )

    if scoring_mode == "HEURISTIC_FALLBACK":
        limitations.append(
            "Scores were produced by a transparent heuristic scorer, not a "
            "trained model. Its weights were chosen for explainability and are "
            "not learned from outcomes."
        )
    elif scoring_mode == "RULES_ONLY":
        limitations.append(
            "Scores were produced by rule evaluation alone. Only typologies "
            "encoded in the rule pack could be detected; a novel pattern would "
            "not appear."
        )
    elif scoring_mode == "TRAINED_MODEL" and not has_trained_model:
        limitations.append(
            "A trained model contributed to these scores but no evaluation "
            "record was found for it, so its measured performance is unknown."
        )

    if graph_capped:
        limitations.append(
            "Graph traversal was truncated by configured limits. The absence of "
            "a path in this report does not mean no path exists."
        )

    if include_correlation_note:
        limitations.append(
            "Complaint correlations are tiered. Tier 1 and 2 matches are "
            "deterministic reference matches; tiers 3 to 5 are inferred and "
            "carry a confidence value. An inferred correlation must not be "
            "quoted as an established link."
        )

    limitations.append(
        "Shared devices, addresses, phone numbers and payment handles are "
        "associations only. They occur legitimately between family members and "
        "within small businesses."
    )
    return limitations


def _account_row(account: Account) -> dict[str, Any]:
    return {
        "account_id": str(account.id),
        "account_type": str(getattr(account.account_type, "value", account.account_type)),
        "status": str(getattr(account.status, "value", account.status)),
        "created_at": (ensure_utc(account.created_at) or utcnow()).isoformat(),
    }


def _transaction_row(txn: Transaction) -> dict[str, Any]:
    return {
        "transaction_id": str(txn.id),
        "reference": str(txn.reference),
        "occurred_at": (ensure_utc(txn.occurred_at) or utcnow()).isoformat(),
        "sender_account_id": str(txn.sender_account_id),
        "receiver_account_id": str(txn.receiver_account_id),
        "amount": to_float(txn.amount),
        "currency": str(txn.currency),
        "channel": str(getattr(txn.channel, "value", txn.channel)),
        "status": str(getattr(txn.status, "value", txn.status)),
    }


def build_case_report(
    db: Session,
    *,
    case_id: str,
    generated_by: Optional[str] = None,
    include_internal_notes: bool = False,
    include_transactions: bool = True,
) -> ReportDocument:
    """
    Assemble the evidence-based report for one investigation case.
    """
    case = db.get(InvestigationCase, str(case_id))

    if case is None:
        raise NotFoundError("Case not found.", details={"case_id": str(case_id)[:64]})

    sections: list[ReportSection] = []
    graph_capped = False
    scoring_mode: Optional[str] = None

    assignee = db.get(User, str(case.assignee_id)) if case.assignee_id else None
    creator = db.get(User, str(case.creator_id)) if case.creator_id else None

    # ------------------------------------------------------------- summary
    sections.append(
        ReportSection(
            title="Case summary",
            kind="key_value",
            rows=[
                {
                    "case_id": str(case.id),
                    "title": str(case.title),
                    "status": case.status.value,
                    "priority": case.priority.value,
                    "disposition": case.disposition.value if case.disposition else None,
                    "assignee": assignee.username if assignee is not None else None,
                    "created_by": creator.username if creator is not None else None,
                    "opened_at": (
                        ensure_utc(case.record_created_at) or utcnow()
                    ).isoformat(),
                    "closed_at": (
                        ensure_utc(case.closed_at).isoformat() if case.closed_at else None
                    ),
                    "primary_account_id": case.account_id,
                }
            ],
            summary=clean_text(case.description or "", 4_000) or None,
            evidence_refs=[evidence_ref("ACCOUNT", case.account_id)]
            if case.account_id
            else [],
        )
    )

    # ------------------------------------------------------- risk assessment
    if case.account_id:
        assessment = db.execute(
            select(ModelAssessment)
            .where(ModelAssessment.account_id == str(case.account_id))
            .order_by(ModelAssessment.as_of.desc())
            .limit(1)
        ).scalars().first()

        if assessment is not None:
            scoring_mode = assessment.scoring_mode.value
            indicators = list(
                db.execute(
                    select(RiskIndicator)
                    .where(RiskIndicator.assessment_id == str(assessment.id))
                    .order_by(RiskIndicator.severity.desc())
                    .limit(_MAX_ROWS_PER_SECTION)
                ).scalars()
            )

            sections.append(
                ReportSection(
                    title="Risk assessment",
                    kind="key_value",
                    rows=[
                        {
                            "assessment_id": str(assessment.id),
                            "as_of": (
                                ensure_utc(assessment.as_of) or utcnow()
                            ).isoformat(),
                            "score": to_float(assessment.score),
                            "score_type": str(assessment.score_type),
                            "risk_band": assessment.risk_band.value,
                            "scoring_mode": assessment.scoring_mode.value,
                            "score_version": assessment.score_version,
                        }
                    ],
                    summary=(
                        str(
                            (assessment.explanation_json or {}).get("summary")
                            if isinstance(assessment.explanation_json, Mapping)
                            else ""
                        )
                        or None
                    ),
                    evidence_refs=[
                        evidence_ref("MODEL_ASSESSMENT", str(assessment.id))
                    ],
                )
            )

            if indicators:
                sections.append(
                    ReportSection(
                        title="Risk indicators",
                        columns=["code", "type", "severity", "measured_value", "explanation"],
                        rows=[
                            {
                                "code": str(indicator.code),
                                "type": indicator.indicator_type.value,
                                "severity": indicator.severity.value,
                                "measured_value": to_float(indicator.measured_value),
                                "explanation": truncate(
                                    clean_text(indicator.explanation or "", 600), 600
                                ),
                            }
                            for indicator in indicators
                        ],
                        evidence_refs=[
                            reference
                            for indicator in indicators
                            for reference in (indicator.evidence_refs_json or [])
                        ],
                        notes=[
                            "Indicators describe observable behaviour, not intent."
                        ],
                    )
                )

            rule_hits = list(
                db.execute(
                    select(RuleHit)
                    .where(RuleHit.assessment_id == str(assessment.id))
                    .where(RuleHit.triggered.is_(True))
                    .order_by(RuleHit.severity.desc())
                    .limit(_MAX_ROWS_PER_SECTION)
                ).scalars()
            )

            if rule_hits:
                sections.append(
                    ReportSection(
                        title="Triggered detection rules",
                        columns=["rule_code", "severity", "measured_value", "threshold", "explanation"],
                        rows=[
                            {
                                "rule_code": str(hit.rule_code),
                                "severity": hit.severity.value,
                                "measured_value": to_float(hit.measured_value),
                                "threshold": to_float(hit.threshold),
                                "explanation": truncate(
                                    clean_text(hit.explanation or "", 600), 600
                                ),
                            }
                            for hit in rule_hits
                        ],
                    )
                )

    # ------------------------------------------------------- transaction trail
    if include_transactions and case.account_id:
        transactions = list(
            db.execute(
                select(Transaction)
                .where(
                    or_(
                        Transaction.sender_account_id == str(case.account_id),
                        Transaction.receiver_account_id == str(case.account_id),
                    )
                )
                .where(Transaction.status == TransactionStatus.COMPLETED)
                .order_by(Transaction.occurred_at.desc())
                .limit(_MAX_TRANSACTIONS)
            ).scalars()
        )

        if transactions:
            sections.append(
                ReportSection(
                    title="Transaction timeline",
                    columns=[
                        "occurred_at",
                        "reference",
                        "sender_account_id",
                        "receiver_account_id",
                        "amount",
                        "currency",
                        "channel",
                    ],
                    rows=[_transaction_row(txn) for txn in transactions],
                    evidence_refs=[
                        evidence_ref("TRANSACTION", str(txn.id)) for txn in transactions
                    ],
                    notes=[
                        "Only COMPLETED transfers are listed; failed and "
                        "reversed transactions are excluded because they are "
                        "not fund movement.",
                    ],
                )
            )

    # ---------------------------------------------------- complaint linkage
    if case.account_id:
        correlations = list(
            db.execute(
                select(ComplaintCorrelation, Complaint)
                .join(Complaint, Complaint.id == ComplaintCorrelation.complaint_id)
                .where(ComplaintCorrelation.account_id == str(case.account_id))
                .order_by(ComplaintCorrelation.match_tier.asc())
                .limit(_MAX_ROWS_PER_SECTION)
            ).all()
        )

        if correlations:
            sections.append(
                ReportSection(
                    title="Correlated cybercrime complaints",
                    columns=[
                        "complaint_reference",
                        "reported_at",
                        "category",
                        "match_tier",
                        "match_method",
                        "deterministic",
                        "confidence",
                        "review_state",
                    ],
                    rows=[
                        {
                            "complaint_reference": str(complaint.reference),
                            "reported_at": (
                                ensure_utc(complaint.reported_at) or utcnow()
                            ).isoformat(),
                            "category": str(complaint.category),
                            "match_tier": int(correlation.match_tier),
                            "match_method": correlation.match_method.value,
                            "deterministic": bool(correlation.deterministic),
                            "confidence": to_float(correlation.confidence),
                            "review_state": correlation.review_state.value,
                        }
                        for correlation, complaint in correlations
                    ],
                    evidence_refs=[
                        evidence_ref("COMPLAINT", str(complaint.id))
                        for _correlation, complaint in correlations
                    ],
                    notes=[
                        "Tier 1 and 2 are deterministic reference matches. "
                        "Tiers 3 to 5 are inferred and carry a confidence value.",
                    ],
                )
            )

    # ------------------------------------------------------- graph analysis
    graph_runs = list(
        db.execute(
            select(GraphAnalysisRun)
            .where(GraphAnalysisRun.root_account_id == str(case.account_id or ""))
            .order_by(GraphAnalysisRun.record_created_at.desc())
            .limit(5)
        ).scalars()
    ) if case.account_id else []

    if graph_runs:
        graph_capped = any(bool(run.capped) for run in graph_runs)
        sections.append(
            ReportSection(
                title="Network analysis",
                columns=["analysed_at", "node_count", "edge_count", "capped"],
                rows=[
                    {
                        "analysed_at": (
                            ensure_utc(run.record_created_at) or utcnow()
                        ).isoformat(),
                        "node_count": int(run.node_count),
                        "edge_count": int(run.edge_count),
                        "capped": bool(run.capped),
                        "intermediary_score": (
                            (run.metrics_json or {}).get("intermediary_score")
                            if isinstance(run.metrics_json, Mapping)
                            else None
                        ),
                        "cycle_count": (
                            (run.metrics_json or {}).get("cycle_count")
                            if isinstance(run.metrics_json, Mapping)
                            else None
                        ),
                    }
                    for run in graph_runs
                ],
                evidence_refs=[
                    evidence_ref("GRAPH_PATH", str(run.id)) for run in graph_runs
                ],
            )
        )

    # --------------------------------------------------------- case evidence
    evidence_items = list_case_evidence(db, str(case.id), limit=_MAX_ROWS_PER_SECTION)

    if evidence_items:
        sections.append(
            ReportSection(
                title="Attached evidence",
                columns=["evidence_type", "evidence_id", "attached_at"],
                rows=[
                    {
                        "evidence_type": item.evidence_type.value,
                        "evidence_id": str(item.evidence_id),
                        "attached_at": (
                            ensure_utc(item.record_created_at) or utcnow()
                        ).isoformat(),
                    }
                    for item in evidence_items
                ],
                evidence_refs=[
                    evidence_ref(item.evidence_type, str(item.evidence_id))
                    for item in evidence_items
                ],
            )
        )

    # ------------------------------------------------------------- notes
    notes = list_case_notes(
        db,
        str(case.id),
        include_internal=include_internal_notes,
        limit=_MAX_ROWS_PER_SECTION,
    )

    if notes:
        sections.append(
            ReportSection(
                title="Investigator notes",
                kind="narrative",
                columns=["recorded_at", "body"],
                rows=[
                    {
                        "recorded_at": (
                            ensure_utc(note.record_created_at) or utcnow()
                        ).isoformat(),
                        "body": clean_text(note.body, 4_000),
                        "internal": bool(note.is_internal),
                    }
                    for note in notes
                ],
                notes=(
                    []
                    if include_internal_notes
                    else ["Internal-only notes are excluded from this report."]
                ),
            )
        )

    # ------------------------------------------------------------ history
    events = list_case_events(db, str(case.id), limit=_MAX_ROWS_PER_SECTION)

    if events:
        sections.append(
            ReportSection(
                title="Case history",
                columns=["occurred_at", "action", "actor", "summary"],
                rows=[
                    {
                        "occurred_at": (
                            ensure_utc(event.created_at) or utcnow()
                        ).isoformat(),
                        "action": str(event.action),
                        "actor": event.actor_username or "system",
                        "summary": truncate(clean_text(event.summary or "", 400), 400),
                    }
                    for event in events
                ],
                notes=["Case history is append-only."],
            )
        )

    return ReportDocument(
        title=f"Investigation report: {case.title}",
        subtitle=f"Case {case.id} - {case.status.value}",
        subject_type="case",
        subject_id=str(case.id),
        sections=sections,
        limitations=build_limitations(
            scoring_mode=scoring_mode,
            graph_capped=graph_capped,
            include_correlation_note=any(
                section.title == "Correlated cybercrime complaints"
                for section in sections
            ),
        ),
        generated_by=generated_by,
        metadata={
            "case_status": case.status.value,
            "section_count": len(sections),
            "includes_internal_notes": include_internal_notes,
        },
    )


def build_account_report(
    db: Session,
    *,
    account_id: str,
    generated_by: Optional[str] = None,
) -> ReportDocument:
    """
    Assemble a report for one account, independent of any case.
    """
    account = db.get(Account, str(account_id))

    if account is None:
        raise NotFoundError(
            "Account not found.", details={"account_id": str(account_id)[:64]}
        )

    sections: list[ReportSection] = [
        ReportSection(
            title="Account overview",
            kind="key_value",
            rows=[_account_row(account)],
            evidence_refs=[evidence_ref("ACCOUNT", str(account.id))],
        )
    ]

    assessments = list(
        db.execute(
            select(ModelAssessment)
            .where(ModelAssessment.account_id == str(account.id))
            .order_by(ModelAssessment.as_of.desc())
            .limit(10)
        ).scalars()
    )
    scoring_mode = assessments[0].scoring_mode.value if assessments else None

    if assessments:
        sections.append(
            ReportSection(
                title="Score history",
                columns=["as_of", "score", "risk_band", "scoring_mode"],
                rows=[
                    {
                        "as_of": (ensure_utc(a.as_of) or utcnow()).isoformat(),
                        "score": to_float(a.score),
                        "risk_band": a.risk_band.value,
                        "scoring_mode": a.scoring_mode.value,
                    }
                    for a in assessments
                ],
                evidence_refs=[
                    evidence_ref("MODEL_ASSESSMENT", str(a.id)) for a in assessments
                ],
            )
        )

    alerts = list(
        db.execute(
            select(Alert)
            .where(Alert.account_id == str(account.id))
            .order_by(Alert.record_created_at.desc())
            .limit(25)
        ).scalars()
    )

    if alerts:
        sections.append(
            ReportSection(
                title="Alerts raised",
                columns=["raised_at", "title", "priority", "state", "score"],
                rows=[
                    {
                        "raised_at": (
                            ensure_utc(alert.record_created_at) or utcnow()
                        ).isoformat(),
                        "title": str(alert.title),
                        "priority": alert.priority.value,
                        "state": alert.state.value,
                        "score": to_float(alert.score),
                    }
                    for alert in alerts
                ],
                evidence_refs=[evidence_ref("ALERT", str(alert.id)) for alert in alerts],
            )
        )

    return ReportDocument(
        title=f"Account risk report: {account.id}",
        subject_type="account",
        subject_id=str(account.id),
        sections=sections,
        limitations=build_limitations(scoring_mode=scoring_mode),
        generated_by=generated_by,
        metadata={"section_count": len(sections)},
    )


def get_reports_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the report service.
    """
    return {
        "service": "muleguard.backend.services.reports",
        "version": REPORTS_SERVICE_VERSION,
        "subjects": ["case", "account"],
        "limits": {
            "max_rows_per_section": _MAX_ROWS_PER_SECTION,
            "max_transactions": _MAX_TRANSACTIONS,
        },
        "guarantees": [
            "Every section carries the evidence references it was built from.",
            "Limitations are tailored to the report's actual contents and are "
            "always included.",
            "Internal notes are excluded unless explicitly requested.",
            "Only COMPLETED transfers appear in a transaction timeline.",
            "A content fingerprint lets two copies of a report be compared.",
        ],
    }
