"""
MULEGUARD alert service.

Turns a scored assessment into a triage-queue entry, applying the
deduplication policy from `config/alert_deduplication.default.json`.

Why deduplication is the whole point of this module: a batch run scores the
same accounts every night. Without it, a persistent typology would raise the
same alert nightly and bury the queue within a week. With it, a persistent
pattern produces one alert per account per typology per window, and an analyst
who acknowledged it does not see it reset.

The hard part is not suppressing duplicates but *not* suppressing genuinely new
information. Four break-out conditions force a fresh alert even when a matching
one is open: a band escalation, a large score jump, a newly triggered typology,
and new complaint corroboration. Each is a change an analyst must see as its
own queue entry rather than as a quiet field update.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any, Final, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Alert,
    AlertEvidence,
    AlertState,
    EvidenceType,
    ModelAssessment,
    Priority,
    RiskBand,
    ScoringMode,
)
from app.services.policy import get_alert_dedup_policy, get_scoring_policy
from app.services.risk import FusedRisk, priority_for_band, should_raise_alert
from app.utils.dates import ensure_utc, utcnow
from app.utils.decimals import quantize_score, to_float
from app.utils.ids import dedup_key as build_dedup_key
from app.utils.json import sanitize_json
from app.utils.text import clean_text, truncate

logger = logging.getLogger("muleguard.backend.services.alerts")

__all__ = [
    "ALERTS_SERVICE_VERSION",
    "AlertOutcome",
    "attach_alert_evidence",
    "build_alert_dedup_key",
    "get_alerts_service_metadata",
    "raise_alert_for_assessment",
]

ALERTS_SERVICE_VERSION: Final[str] = "v1"

_BAND_RANK: Final[dict[str, int]] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_MAX_TITLE_LENGTH: Final[int] = 200
_MAX_SUMMARY_LENGTH: Final[int] = 1_000
_DEFAULT_SCORE_JUMP: Final[float] = 15.0
_DEFAULT_WINDOW_DAYS: Final[int] = 7


class AlertOutcome:
    """
    What `raise_alert_for_assessment` did, and why.
    """

    __slots__ = ("alert", "created", "reason", "suppressed")

    def __init__(
        self,
        *,
        alert: Optional[Alert],
        created: bool,
        reason: str,
        suppressed: bool = False,
    ) -> None:
        self.alert = alert
        self.created = created
        self.reason = reason
        self.suppressed = suppressed

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe summary for the run report.
        """
        return {
            "alert_id": str(self.alert.id) if self.alert is not None else None,
            "created": self.created,
            "suppressed": self.suppressed,
            "reason": self.reason,
        }

    def __repr__(self) -> str:
        return (
            f"AlertOutcome(created={self.created}, suppressed={self.suppressed}, "
            f"reason={self.reason!r})"
        )


def _typology_group(triggered_rules: Sequence[Mapping[str, Any]]) -> str:
    """
    Build the typology component of the dedup key.

    Grouping by typology rather than by rule code means adding a new rule to an
    existing typology does not re-alert every account that already matched it.
    """
    typologies = sorted(
        {
            str((rule.get("metadata") or {}).get("typology") or rule.get("rule_id") or "")
            .strip()
            .lower()
            for rule in triggered_rules
        }
        - {""}
    )
    return ",".join(typologies[:8]) if typologies else "unclassified"


def build_alert_dedup_key(
    *,
    account_id: str,
    triggered_rules: Sequence[Mapping[str, Any]],
    window_start: datetime,
) -> str:
    """
    Build the alert deduplication key.

    Stored in the unique `Alert.dedup_key` column, so the database itself
    prevents two open alerts with the same signature under a race.
    """
    return build_dedup_key(
        str(account_id),
        _typology_group(triggered_rules),
        ensure_utc(window_start).strftime("%Y-%m-%d") if window_start else "-",
    )


def _break_out_reason(
    existing: Alert,
    *,
    risk: FusedRisk,
    typologies: str,
    correlation_count: int,
    score_jump_threshold: float,
) -> Optional[str]:
    """
    Return why a new alert must be raised despite an open match, or None.
    """
    existing_band = str(
        getattr(existing.priority, "value", existing.priority) or "LOW"
    ).upper()
    new_band = risk.band.value

    if _BAND_RANK.get(new_band, 0) > _BAND_RANK.get(existing_band, 0):
        return f"band escalated from {existing_band} to {new_band}"

    previous_score = to_float(existing.score)

    if previous_score is not None and risk.score - previous_score >= score_jump_threshold:
        return (
            f"score rose by {risk.score - previous_score:.1f} points "
            f"(threshold {score_jump_threshold:.1f})"
        )

    summary = existing.signal_summary_json

    if isinstance(summary, Mapping):
        previous_typologies = {
            t.strip()
            for t in str(summary.get("typologies") or "").split(",")
            if t.strip()
        }
        new_typologies = {t.strip() for t in typologies.split(",") if t.strip()}
        added = new_typologies - previous_typologies

        if added:
            return f"new typology detected: {', '.join(sorted(added))}"

        previous_correlations = int(summary.get("complaint_correlation_count") or 0)

        if correlation_count > previous_correlations:
            return (
                "new complaint corroboration "
                f"({previous_correlations} -> {correlation_count})"
            )

    return None


def raise_alert_for_assessment(
    db: Session,
    *,
    assessment: ModelAssessment,
    risk: FusedRisk,
    triggered_rules: Optional[Sequence[Mapping[str, Any]]] = None,
    effects: Optional[Sequence[str]] = None,
    correlation_count: int = 0,
    evidence_refs: Optional[Sequence[tuple[EvidenceType, str]]] = None,
    as_of: Optional[datetime] = None,
    actor_id: Optional[str] = None,
    dedup_policy: Optional[Mapping[str, Any]] = None,
    scoring_policy: Optional[Mapping[str, Any]] = None,
) -> AlertOutcome:
    """
    Create or update the alert for one scored assessment.

    Returns an `AlertOutcome` describing what happened, so the analysis run can
    report created, updated, and suppressed counts honestly.
    """
    rules = list(triggered_rules or [])
    policy = dedup_policy or get_alert_dedup_policy()
    scoring = scoring_policy or get_scoring_policy()

    wanted, reason = should_raise_alert(risk, effects=effects, policy=scoring)

    if not wanted:
        return AlertOutcome(alert=None, created=False, reason=reason)

    observation_time = ensure_utc(as_of) or ensure_utc(assessment.as_of) or utcnow()
    window_days = int(
        (policy.get("window") or {}).get("length_days") or _DEFAULT_WINDOW_DAYS
    )
    window_start = observation_time - timedelta(days=max(1, window_days))
    typologies = _typology_group(rules)
    dedup_enabled = bool(policy.get("enabled", True))

    key = build_alert_dedup_key(
        account_id=str(assessment.account_id),
        triggered_rules=rules,
        window_start=window_start,
    )

    signal_summary = {
        "typologies": typologies,
        "triggered_rule_count": len(rules),
        "complaint_correlation_count": int(correlation_count),
        "score": round(risk.score, 2),
        "band": risk.band.value,
        "scoring_mode": risk.scoring_mode.value,
        "components": {
            component.name: component.value
            for component in risk.components
            if component.available
        },
        "alert_reason": reason,
    }
    rule_codes = [str(rule.get("rule_id") or "") for rule in rules if rule.get("rule_id")]
    priority_value = priority_for_band(risk.band, policy=scoring)
    priority = Priority(priority_value) if priority_value in Priority.__members__ else Priority.MEDIUM

    existing: Optional[Alert] = None

    if dedup_enabled:
        existing = db.execute(
            select(Alert).where(Alert.dedup_key == key).limit(1)
        ).scalars().first()

    if existing is not None:
        terminal = existing.state == AlertState.CLOSED

        if terminal:
            reopen = policy.get("reopen_policy") or {}
            horizon_days = int(reopen.get("closed_alert_within_days") or 14)
            closed_at = ensure_utc(existing.closed_at)

            if closed_at is not None and observation_time - closed_at <= timedelta(
                days=max(1, horizon_days)
            ):
                # Raise a linked new alert rather than reopening: the original
                # disposition and its audit trail must stay intact.
                return _create_alert(
                    db,
                    assessment=assessment,
                    risk=risk,
                    priority=priority,
                    dedup_key=f"{key}|r{int(observation_time.timestamp())}",
                    window_start=window_start,
                    window_end=observation_time,
                    signal_summary=signal_summary
                    | {"recurrence_of_alert_id": str(existing.id)},
                    rule_codes=rule_codes,
                    evidence_refs=evidence_refs,
                    actor_id=actor_id,
                    reason=(
                        "recurrence of a recently closed alert; linked rather "
                        "than reopened to preserve the original disposition"
                    ),
                )

        break_out = _break_out_reason(
            existing,
            risk=risk,
            typologies=typologies,
            correlation_count=correlation_count,
            score_jump_threshold=_DEFAULT_SCORE_JUMP,
        )

        if break_out is not None:
            return _create_alert(
                db,
                assessment=assessment,
                risk=risk,
                priority=priority,
                dedup_key=f"{key}|b{int(observation_time.timestamp())}",
                window_start=window_start,
                window_end=observation_time,
                signal_summary=signal_summary
                | {"break_out_from_alert_id": str(existing.id), "break_out_reason": break_out},
                rule_codes=rule_codes,
                evidence_refs=evidence_refs,
                actor_id=actor_id,
                reason=f"new alert raised because {break_out}",
            )

        # Ordinary recurrence: refresh the facts, preserve the triage state.
        existing.last_seen_at = observation_time
        existing.score = quantize_score(risk.score)
        existing.priority = priority
        existing.scoring_mode = risk.scoring_mode
        existing.score_version = risk.score_version
        existing.signal_summary_json = sanitize_json(signal_summary, max_items=60)
        existing.rule_codes_json = rule_codes[:40]
        existing.dedup_window_end = observation_time
        existing.updated_by = actor_id
        db.flush()

        return AlertOutcome(
            alert=existing,
            created=False,
            reason="existing open alert updated; triage state preserved",
        )

    return _create_alert(
        db,
        assessment=assessment,
        risk=risk,
        priority=priority,
        dedup_key=key,
        window_start=window_start,
        window_end=observation_time,
        signal_summary=signal_summary,
        rule_codes=rule_codes,
        evidence_refs=evidence_refs,
        actor_id=actor_id,
        reason=reason,
    )


def _create_alert(
    db: Session,
    *,
    assessment: ModelAssessment,
    risk: FusedRisk,
    priority: Priority,
    dedup_key: str,
    window_start: datetime,
    window_end: datetime,
    signal_summary: Mapping[str, Any],
    rule_codes: Sequence[str],
    evidence_refs: Optional[Sequence[tuple[EvidenceType, str]]],
    actor_id: Optional[str],
    reason: str,
) -> AlertOutcome:
    """
    Insert a new alert and attach its evidence.
    """
    top_rules = [
        str(rule) for rule in list(rule_codes)[:3]
    ]
    title = truncate(
        f"{risk.band.value} risk on account {assessment.account_id}"
        + (f" ({', '.join(top_rules)})" if top_rules else ""),
        _MAX_TITLE_LENGTH,
    )
    summary_text = clean_text(
        str(risk.explanation.get("summary") or "") or
        f"Investigative priority {risk.score:.1f}/100.",
        _MAX_SUMMARY_LENGTH,
    )

    alert = Alert(
        account_id=str(assessment.account_id),
        assessment_id=str(assessment.id),
        title=title,
        summary=summary_text,
        priority=priority,
        state=AlertState.NEW,
        score=quantize_score(risk.score),
        score_version=risk.score_version,
        scoring_mode=risk.scoring_mode,
        model_version=None,
        signal_summary_json=sanitize_json(dict(signal_summary), max_items=60),
        rule_codes_json=list(rule_codes)[:40],
        dedup_key=dedup_key[:255],
        dedup_window_start=window_start,
        dedup_window_end=window_end,
        first_seen_at=window_end,
        last_seen_at=window_end,
        created_by=actor_id,
        updated_by=actor_id,
    )
    db.add(alert)
    db.flush()

    refs = list(evidence_refs or [])

    # Always cite the assessment and the account; an alert with no resolvable
    # evidence is not actionable.
    refs.insert(0, (EvidenceType.MODEL_ASSESSMENT, str(assessment.id)))
    refs.insert(1, (EvidenceType.ACCOUNT, str(assessment.account_id)))

    attach_alert_evidence(db, alert=alert, references=refs, actor_id=actor_id)

    logger.info(
        "Raised alert %s for account %s band=%s score=%.1f (%s)",
        alert.id,
        assessment.account_id,
        risk.band.value,
        risk.score,
        reason,
    )
    return AlertOutcome(alert=alert, created=True, reason=reason)


def attach_alert_evidence(
    db: Session,
    *,
    alert: Alert,
    references: Sequence[tuple[EvidenceType, str]],
    actor_id: Optional[str] = None,
    snapshots: Optional[Mapping[str, Mapping[str, Any]]] = None,
    max_items: int = 50,
) -> list[AlertEvidence]:
    """
    Attach evidence references to an alert, skipping duplicates.

    `(alert_id, evidence_type, evidence_id)` is unique, so re-attaching the
    same reference on a later run is a no-op rather than an error.
    """
    if not references:
        return []

    existing = {
        (row.evidence_type, str(row.evidence_id))
        for row in db.execute(
            select(AlertEvidence).where(AlertEvidence.alert_id == str(alert.id))
        ).scalars()
    }

    created: list[AlertEvidence] = []
    seen: set[tuple[Any, str]] = set()

    for evidence_type, evidence_id in references:
        identifier = str(evidence_id or "").strip()

        if not identifier:
            continue

        kind = (
            evidence_type
            if isinstance(evidence_type, EvidenceType)
            else EvidenceType(str(evidence_type))
        )
        key = (kind, identifier)

        if key in existing or key in seen:
            continue

        seen.add(key)

        if len(created) >= max_items:
            break

        snapshot = (snapshots or {}).get(identifier)
        record = AlertEvidence(
            alert_id=str(alert.id),
            evidence_type=kind,
            evidence_id=identifier[:128],
            evidence_snapshot_json=(
                sanitize_json(dict(snapshot), max_items=30) if snapshot else None
            ),
            provenance_json={
                "attached_by": "muleguard.backend.services.alerts",
                "service_version": ALERTS_SERVICE_VERSION,
            },
            created_by=actor_id,
        )
        db.add(record)
        created.append(record)

    if created:
        db.flush()

    return created


def get_alerts_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the alert service.
    """
    try:
        policy = get_alert_dedup_policy()
        window_days = (policy.get("window") or {}).get("length_days")
        enabled = bool(policy.get("enabled", True))
        suppression = bool((policy.get("suppression") or {}).get("enabled", False))
    except Exception:
        window_days = None
        enabled = True
        suppression = False

    return {
        "service": "muleguard.backend.services.alerts",
        "version": ALERTS_SERVICE_VERSION,
        "deduplication_enabled": enabled,
        "window_days": window_days,
        "suppression_enabled": suppression,
        "states": [item.value for item in AlertState],
        "break_out_conditions": [
            "band escalation",
            "score jump of 15 points or more",
            "a newly triggered typology",
            "new complaint corroboration",
        ],
        "guarantees": [
            "Triage state is never reset by a later run.",
            "first_seen_at is preserved so queue age reflects how long a pattern has persisted.",
            "A recently closed alert recurs as a new linked alert, never by reopening.",
            "An escalate_to_human effect always alerts regardless of score.",
            "Suppression never applies to escalate_to_human alerts.",
        ],
    }
