"""
MULEGUARD complaint correlation service.

Links cybercrime complaints to the transactions, accounts, and entities they
describe, and persists each link as a `ComplaintCorrelation` row.

Correlations are tiered, and the tier is the most important thing a reader
needs. Tier 1 is an identity; tier 5 is a guess. Keeping them in one table
with an explicit `match_tier` and `deterministic` flag means an analyst can
always tell which they are looking at, and a report can quote a tier-1 match as
fact while presenting a tier-4 match as a lead.

| Tier | Method | Deterministic | What it means |
|------|--------|---------------|---------------|
| 1 | `EXACT` | yes | The complaint's transaction reference equals a transaction reference. |
| 2 | `NORMALIZED` | yes | The references match after case and separator normalisation. |
| 3 | `ENTITY_TEMPORAL` | no | The complaint's account shares a device, phone, or UPI handle with a counterparty, within the complaint's time window. |
| 4 | `GRAPH_TEMPORAL` | no | A transfer of the complained amount left the victim's account close to the reported time. |
| 5 | `NARRATIVE_EXTRACTION` | no | A reference-shaped token extracted from the narrative text matched a transaction. |

Confidence is only recorded for the inferred tiers. A deterministic match does
not get a confidence of 1.0, because that would invite averaging it with an
inferred score as though they were the same kind of quantity.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Final, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Account,
    AccountEntityLink,
    Complaint,
    ComplaintCorrelation,
    ComplaintReviewState,
    MatchMethod,
    Transaction,
    TransactionStatus,
)
from app.utils.dates import ensure_utc, utcnow
from app.utils.decimals import quantize_confidence, to_float
from app.utils.ids import evidence_ref
from app.utils.json import sanitize_json
from app.utils.text import normalize_reference

logger = logging.getLogger("muleguard.backend.services.complaint_correlation")

__all__ = [
    "CORRELATION_SERVICE_VERSION",
    "CorrelationSummary",
    "correlate_complaint",
    "correlate_complaints",
    "get_correlation_service_metadata",
]

CORRELATION_SERVICE_VERSION: Final[str] = "v1"

# Tier -> (method, deterministic, base confidence)
_TIERS: Final[dict[int, tuple[MatchMethod, bool, Optional[float]]]] = {
    1: (MatchMethod.EXACT, True, None),
    2: (MatchMethod.NORMALIZED, True, None),
    3: (MatchMethod.ENTITY_TEMPORAL, False, 0.55),
    4: (MatchMethod.GRAPH_TEMPORAL, False, 0.45),
    5: (MatchMethod.NARRATIVE_EXTRACTION, False, 0.35),
}

# Amount tolerance for a tier-4 temporal/amount match.
_AMOUNT_TOLERANCE: Final[Decimal] = Decimal("0.01")
_AMOUNT_RELATIVE_TOLERANCE: Final[float] = 0.02

_TEMPORAL_WINDOW_HOURS: Final[int] = 72
_ENTITY_WINDOW_DAYS: Final[int] = 30

_MAX_CANDIDATES_PER_TIER: Final[int] = 25
_MAX_NARRATIVE_TOKENS: Final[int] = 20

# Reference-shaped tokens in free text: at least 6 chars, letters and digits,
# containing at least one digit. Deliberately conservative — a looser pattern
# matches ordinary words and floods tier 5 with noise.
_REFERENCE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?=[A-Za-z0-9/-]{6,40}\b)(?=[A-Za-z0-9/-]*\d)[A-Za-z0-9][A-Za-z0-9/-]{5,39}\b"
)


class CorrelationSummary:
    """
    Aggregate outcome of a correlation pass.
    """

    __slots__ = ("by_tier", "complaints_processed", "created", "skipped_existing")

    def __init__(self) -> None:
        self.complaints_processed = 0
        self.created = 0
        self.skipped_existing = 0
        self.by_tier: dict[int, int] = {}

    def record(self, tier: int) -> None:
        """
        Count one created correlation at the given tier.
        """
        self.created += 1
        self.by_tier[tier] = self.by_tier.get(tier, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe summary for the analysis run report.
        """
        return {
            "complaints_processed": self.complaints_processed,
            "correlations_created": self.created,
            "already_present": self.skipped_existing,
            "by_tier": {str(k): v for k, v in sorted(self.by_tier.items())},
            "tier_legend": {
                "1": "exact reference match (deterministic)",
                "2": "normalised reference match (deterministic)",
                "3": "shared entity within the complaint window (inferred)",
                "4": "amount and time proximity (inferred)",
                "5": "reference extracted from narrative text (inferred)",
            },
        }

    def __repr__(self) -> str:
        return f"CorrelationSummary(created={self.created}, by_tier={self.by_tier})"


def _existing_keys(db: Session, complaint_id: str) -> set[tuple[int, Optional[str], Optional[str], Optional[str]]]:
    """
    Return the correlation signatures already stored for a complaint.
    """
    rows = db.execute(
        select(ComplaintCorrelation).where(
            ComplaintCorrelation.complaint_id == str(complaint_id)
        )
    ).scalars()

    return {
        (
            int(row.match_tier),
            str(row.account_id) if row.account_id else None,
            str(row.transaction_id) if row.transaction_id else None,
            str(row.entity_id) if row.entity_id else None,
        )
        for row in rows
    }


def _amounts_match(left: Any, right: Any) -> bool:
    """
    Return True when two amounts agree within tolerance.

    A relative tolerance is applied as well as an absolute one, because a
    complainant reporting "about 50,000" against a transfer of 49,750 is
    describing the same event.
    """
    first = to_float(left)
    second = to_float(right)

    if first is None or second is None:
        return False

    if abs(first - second) <= float(_AMOUNT_TOLERANCE):
        return True

    larger = max(abs(first), abs(second))

    if larger <= 0:
        return False

    return abs(first - second) / larger <= _AMOUNT_RELATIVE_TOLERANCE


def _narrative_tokens(text: Any) -> list[str]:
    """
    Extract reference-shaped tokens from a complaint narrative.
    """
    if not text:
        return []

    found: list[str] = []
    seen: set[str] = set()

    for match in _REFERENCE_TOKEN_RE.finditer(str(text)):
        token = normalize_reference(match.group(0))

        if not token or token in seen or len(token) < 6:
            continue

        seen.add(token)
        found.append(token)

        if len(found) >= _MAX_NARRATIVE_TOKENS:
            break

    return found


def _add_correlation(
    db: Session,
    *,
    complaint: Complaint,
    tier: int,
    account_id: Optional[str] = None,
    transaction_id: Optional[str] = None,
    entity_id: Optional[str] = None,
    confidence: Optional[float] = None,
    evidence: Optional[Sequence[str]] = None,
    normalized_values: Optional[Mapping[str, Any]] = None,
    provenance: Optional[Mapping[str, Any]] = None,
    seen: Optional[set[tuple[int, Optional[str], Optional[str], Optional[str]]]] = None,
    summary: Optional[CorrelationSummary] = None,
) -> Optional[ComplaintCorrelation]:
    """
    Persist one correlation, skipping an exact duplicate signature.
    """
    method, deterministic, base_confidence = _TIERS[tier]
    key = (tier, account_id, transaction_id, entity_id)

    if seen is not None and key in seen:
        if summary is not None:
            summary.skipped_existing += 1
        return None

    if seen is not None:
        seen.add(key)

    effective_confidence = (
        None if deterministic else (confidence if confidence is not None else base_confidence)
    )

    record = ComplaintCorrelation(
        complaint_id=str(complaint.id),
        account_id=account_id,
        transaction_id=transaction_id,
        entity_id=entity_id,
        match_tier=int(tier),
        match_method=method,
        # Deterministic matches carry no confidence on purpose: a 1.0 would
        # invite averaging an identity with an estimate.
        confidence=quantize_confidence(effective_confidence) if effective_confidence is not None else None,
        deterministic=bool(deterministic),
        review_state=ComplaintReviewState.UNREVIEWED,
        evidence_refs_json=list(evidence or [])[:20],
        provenance_json=sanitize_json(
            {
                "service": "muleguard.backend.services.complaint_correlation",
                "service_version": CORRELATION_SERVICE_VERSION,
                "tier": tier,
                "method": method.value,
                "deterministic": deterministic,
                **dict(provenance or {}),
            },
            max_items=30,
        ),
        normalized_values_json=sanitize_json(dict(normalized_values or {}), max_items=30),
    )
    db.add(record)

    if summary is not None:
        summary.record(tier)

    return record


def correlate_complaint(
    db: Session,
    complaint: Complaint,
    *,
    as_of: Optional[datetime] = None,
    summary: Optional[CorrelationSummary] = None,
) -> list[ComplaintCorrelation]:
    """
    Correlate one complaint against transactions, accounts, and entities.

    Returns the correlations created. Tiers are evaluated strongest first, and
    a deterministic hit on a transaction stops the weaker inferred tiers for
    that same transaction — once the reference is an identity, an amount
    coincidence adds nothing.
    """
    observation_time = ensure_utc(as_of) or utcnow()
    reported_at = ensure_utc(complaint.reported_at) or observation_time
    seen = _existing_keys(db, str(complaint.id))
    created: list[ComplaintCorrelation] = []
    matched_transaction_ids: set[str] = set()

    if summary is not None:
        summary.complaints_processed += 1

    # ------------------------------------------------- tier 1: exact reference
    raw_reference = str(complaint.transaction_reference or "").strip()

    if raw_reference:
        exact = db.execute(
            select(Transaction)
            .where(Transaction.reference == raw_reference)
            .where(Transaction.occurred_at <= observation_time)
            .limit(_MAX_CANDIDATES_PER_TIER)
        ).scalars().all()

        for txn in exact:
            record = _add_correlation(
                db,
                complaint=complaint,
                tier=1,
                account_id=str(txn.receiver_account_id),
                transaction_id=str(txn.id),
                evidence=[
                    evidence_ref("COMPLAINT", str(complaint.id)),
                    evidence_ref("TRANSACTION", str(txn.id)),
                ],
                normalized_values={"transaction_reference": raw_reference},
                provenance={"matched_on": "transaction_reference"},
                seen=seen,
                summary=summary,
            )

            if record is not None:
                created.append(record)
                matched_transaction_ids.add(str(txn.id))

        # --------------------------------------- tier 2: normalised reference
        normalised = normalize_reference(raw_reference)

        if normalised and not matched_transaction_ids:
            # Normalising in SQL is not portable, so candidates are fetched by
            # a bounded prefix and compared in Python.
            prefix = re.sub(r"[^A-Za-z0-9]", "", raw_reference)[:4]
            candidates = db.execute(
                select(Transaction)
                .where(Transaction.occurred_at <= observation_time)
                .where(Transaction.reference.ilike(f"%{prefix}%"))
                .limit(500)
            ).scalars().all() if prefix else []

            for txn in candidates:
                if str(txn.id) in matched_transaction_ids:
                    continue

                if normalize_reference(txn.reference) != normalised:
                    continue

                record = _add_correlation(
                    db,
                    complaint=complaint,
                    tier=2,
                    account_id=str(txn.receiver_account_id),
                    transaction_id=str(txn.id),
                    evidence=[
                        evidence_ref("COMPLAINT", str(complaint.id)),
                        evidence_ref("TRANSACTION", str(txn.id)),
                    ],
                    normalized_values={
                        "complaint_reference_normalized": normalised,
                        "transaction_reference_normalized": normalize_reference(txn.reference),
                    },
                    provenance={"matched_on": "normalized_transaction_reference"},
                    seen=seen,
                    summary=summary,
                )

                if record is not None:
                    created.append(record)
                    matched_transaction_ids.add(str(txn.id))

                if len(matched_transaction_ids) >= _MAX_CANDIDATES_PER_TIER:
                    break

    # ------------------------------ tier 4: amount and time proximity
    victim_id = str(complaint.victim_account_id or "").strip()
    complaint_amount = complaint.amount

    if victim_id and complaint_amount is not None and not matched_transaction_ids:
        window_start = reported_at - timedelta(hours=_TEMPORAL_WINDOW_HOURS)
        window_end = min(reported_at + timedelta(hours=_TEMPORAL_WINDOW_HOURS), observation_time)

        nearby = db.execute(
            select(Transaction)
            .where(Transaction.sender_account_id == victim_id)
            .where(Transaction.status == TransactionStatus.COMPLETED)
            .where(Transaction.occurred_at >= window_start)
            .where(Transaction.occurred_at <= window_end)
            .order_by(Transaction.occurred_at)
            .limit(_MAX_CANDIDATES_PER_TIER * 4)
        ).scalars().all()

        for txn in nearby:
            if str(txn.id) in matched_transaction_ids:
                continue

            if not _amounts_match(txn.amount, complaint_amount):
                continue

            occurred = ensure_utc(txn.occurred_at) or reported_at
            hours_apart = abs((reported_at - occurred).total_seconds()) / 3600.0
            # Closer in time is stronger, decaying across the window.
            proximity = max(0.0, 1.0 - (hours_apart / float(_TEMPORAL_WINDOW_HOURS)))
            confidence = 0.30 + 0.35 * proximity

            record = _add_correlation(
                db,
                complaint=complaint,
                tier=4,
                account_id=str(txn.receiver_account_id),
                transaction_id=str(txn.id),
                confidence=confidence,
                evidence=[
                    evidence_ref("COMPLAINT", str(complaint.id)),
                    evidence_ref("TRANSACTION", str(txn.id)),
                    evidence_ref("ACCOUNT", victim_id),
                ],
                normalized_values={
                    "complaint_amount": to_float(complaint_amount),
                    "transaction_amount": to_float(txn.amount),
                    "hours_between": round(hours_apart, 2),
                },
                provenance={
                    "matched_on": "amount_and_time_proximity",
                    "window_hours": _TEMPORAL_WINDOW_HOURS,
                },
                seen=seen,
                summary=summary,
            )

            if record is not None:
                created.append(record)
                matched_transaction_ids.add(str(txn.id))

            if len(created) >= _MAX_CANDIDATES_PER_TIER:
                break

    # ------------------------------ tier 3: shared entity within the window
    subject_ids = [
        identifier
        for identifier in (
            str(complaint.victim_account_id or "").strip(),
            str(complaint.suspected_account_id or "").strip(),
        )
        if identifier
    ]

    if subject_ids:
        entity_window_start = reported_at - timedelta(days=_ENTITY_WINDOW_DAYS)

        subject_links = db.execute(
            select(AccountEntityLink)
            .where(AccountEntityLink.account_id.in_(subject_ids))
            .where(AccountEntityLink.valid_from <= observation_time)
            .limit(200)
        ).scalars().all()

        entity_ids = sorted({str(link.entity_id) for link in subject_links})

        if entity_ids:
            sibling_links = db.execute(
                select(AccountEntityLink)
                .where(AccountEntityLink.entity_id.in_(entity_ids))
                .where(AccountEntityLink.account_id.notin_(subject_ids))
                .where(AccountEntityLink.valid_from <= observation_time)
                .limit(200)
            ).scalars().all()

            for link in sibling_links:
                valid_from = ensure_utc(link.valid_from)
                valid_to = ensure_utc(link.valid_to)

                # The association must overlap the complaint's window.
                if valid_to is not None and valid_to < entity_window_start:
                    continue

                if valid_from is not None and valid_from > observation_time:
                    continue

                link_confidence = to_float(link.confidence)
                confidence = 0.40 + 0.25 * (link_confidence if link_confidence is not None else 0.5)

                record = _add_correlation(
                    db,
                    complaint=complaint,
                    tier=3,
                    account_id=str(link.account_id),
                    entity_id=str(link.entity_id),
                    confidence=confidence,
                    evidence=[
                        evidence_ref("COMPLAINT", str(complaint.id)),
                        evidence_ref("ENTITY_LINK", str(link.id)),
                        evidence_ref("ACCOUNT", str(link.account_id)),
                    ],
                    normalized_values={
                        "shared_entity_id": str(link.entity_id),
                        "link_match_method": str(
                            getattr(link.match_method, "value", link.match_method)
                        ),
                        "link_verification_state": str(
                            getattr(link.verification_state, "value", link.verification_state)
                        ),
                    },
                    provenance={
                        "matched_on": "shared_entity_within_window",
                        "window_days": _ENTITY_WINDOW_DAYS,
                        "limits": [
                            "A shared device, phone, or handle is an association "
                            "only. Families and small businesses share them "
                            "legitimately."
                        ],
                    },
                    seen=seen,
                    summary=summary,
                )

                if record is not None:
                    created.append(record)

    # ------------------------------- tier 5: reference from narrative text
    if not matched_transaction_ids:
        tokens = _narrative_tokens(complaint.narrative_raw)

        for token in tokens:
            prefix = token[:4]
            candidates = db.execute(
                select(Transaction)
                .where(Transaction.occurred_at <= observation_time)
                .where(Transaction.reference.ilike(f"%{prefix}%"))
                .limit(200)
            ).scalars().all()

            for txn in candidates:
                if str(txn.id) in matched_transaction_ids:
                    continue

                if normalize_reference(txn.reference) != token:
                    continue

                record = _add_correlation(
                    db,
                    complaint=complaint,
                    tier=5,
                    account_id=str(txn.receiver_account_id),
                    transaction_id=str(txn.id),
                    confidence=0.35,
                    evidence=[
                        evidence_ref("COMPLAINT", str(complaint.id)),
                        evidence_ref("TRANSACTION", str(txn.id)),
                    ],
                    normalized_values={"extracted_token": token},
                    provenance={
                        "matched_on": "narrative_extracted_reference",
                        "limits": [
                            "Extracted from free text. The complainant may have "
                            "mistyped or quoted an unrelated reference."
                        ],
                    },
                    seen=seen,
                    summary=summary,
                )

                if record is not None:
                    created.append(record)
                    matched_transaction_ids.add(str(txn.id))
                    break

            if len(matched_transaction_ids) >= 5:
                break

    if created:
        db.flush()

    return created


def correlate_complaints(
    db: Session,
    *,
    complaint_ids: Optional[Sequence[str]] = None,
    account_ids: Optional[Sequence[str]] = None,
    as_of: Optional[datetime] = None,
    max_complaints: int = 2_000,
) -> CorrelationSummary:
    """
    Correlate a bounded set of complaints.

    With `account_ids`, only complaints naming one of those accounts are
    processed, which is what an analysis run scoped to a subset needs.
    """
    observation_time = ensure_utc(as_of) or utcnow()
    summary = CorrelationSummary()

    stmt = select(Complaint).where(Complaint.reported_at <= observation_time)

    if complaint_ids:
        stmt = stmt.where(Complaint.id.in_([str(c) for c in complaint_ids]))

    if account_ids:
        scoped = [str(a) for a in account_ids]
        stmt = stmt.where(
            Complaint.victim_account_id.in_(scoped)
            | Complaint.suspected_account_id.in_(scoped)
        )

    stmt = stmt.order_by(Complaint.reported_at.desc()).limit(max(1, int(max_complaints)))
    complaints = list(db.execute(stmt).scalars())

    for complaint in complaints:
        try:
            correlate_complaint(db, complaint, as_of=observation_time, summary=summary)
        except Exception:
            # One malformed complaint must not abandon the whole pass.
            logger.exception(
                "Correlation failed for complaint %s; continuing.", complaint.id
            )

    logger.info(
        "Correlated %d complaint(s): %d correlation(s) created %s",
        summary.complaints_processed,
        summary.created,
        summary.by_tier,
    )
    return summary


def get_correlation_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the correlation service.
    """
    return {
        "service": "muleguard.backend.services.complaint_correlation",
        "version": CORRELATION_SERVICE_VERSION,
        "tiers": {
            str(tier): {
                "method": method.value,
                "deterministic": deterministic,
                "base_confidence": base,
            }
            for tier, (method, deterministic, base) in sorted(_TIERS.items())
        },
        "windows": {
            "temporal_window_hours": _TEMPORAL_WINDOW_HOURS,
            "entity_window_days": _ENTITY_WINDOW_DAYS,
        },
        "amount_tolerance": {
            "absolute": str(_AMOUNT_TOLERANCE),
            "relative": _AMOUNT_RELATIVE_TOLERANCE,
        },
        "notes": [
            "Deterministic tiers carry no confidence value on purpose; an "
            "identity is not an estimate and must not be averaged with one.",
            "Every correlation starts UNREVIEWED and requires analyst review.",
            "A correlation is a lead. It does not establish that an account "
            "holder was involved in wrongdoing.",
        ],
    }
