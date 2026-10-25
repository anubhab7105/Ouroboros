"""
MULEGUARD analysis orchestration service.

This module is the one hard dependency the API layer has on a service:
`app/api/v1/endpoints/analysis.py` resolves `app.services.analysis` and calls
`execute_analysis_run(db, run, settings)`. Without it, `POST /analysis/runs`
returns 503 and nothing ever populates assessments, alerts, correlations, or
graph runs.

It is also the seam that connects the analytical packages — `app.ml`,
`app.rules`, `app.graph`, `app.correlation` — to the database. Before this
existed, those packages were imported by nothing.

Pipeline, in order:

    select accounts
      -> build point-in-time dataset          (services.features)
      -> compute 94-feature vectors           (app.ml.features)
      -> persist FeatureSnapshot rows
      -> evaluate the detection rule pack     (app.rules.engine)
      -> score: trained model, else heuristic (app.ml / app.ml.fallback)
      -> fuse into a 0-100 priority score     (services.risk)
      -> persist ModelAssessment / RuleHit / RiskIndicator
      -> correlate complaints                 (services.complaint_correlation)
      -> bounded graph neighbourhood          (services.graph)
      -> raise or update alerts               (services.alerts)
      -> finalize the run

Contract requirements imposed by the endpoint, all honoured here:

- The run's status **must** end terminal. The endpoint checks, and marks the
  run failed itself if the service left it running.
- A failure **must** set `error_code` and `error_message`; the endpoint
  re-raises from them.
- The endpoint owns the transaction: it calls `db.flush()` afterwards and
  commits. This service flushes but never commits, so the whole run stays one
  atomic unit.

Error handling philosophy: one bad account must not abandon a 5,000-account
run. Per-account failures are counted and summarised, and the run ends
`PARTIAL`. Only a failure that makes the whole run meaningless — no policy, no
features — ends it `FAILED`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.exceptions import FeatureComputationError, MuleGuardError
from app.models import (
    Account,
    AnalysisRun,
    AnalysisRunStatus,
    IndicatorType,
    ModelAssessment,
    ModelVersion,
    RiskIndicator,
    RuleHit,
    ScoringMode,
    Severity,
)
from app.services import features as features_service
from app.services import graph as graph_service
from app.services.alerts import raise_alert_for_assessment
from app.services.audit import record_system_event
from app.services.complaint_correlation import correlate_complaints
from app.services.policy import PolicyBundle, get_policy_bundle
from app.services.risk import (
    FusedRisk,
    fuse_risk,
    severity_for_rule_severity,
)
from app.utils.dates import ensure_utc, utcnow
from app.utils.decimals import quantize_score, to_decimal, to_float
from app.utils.hashing import hash_identifier
from app.utils.ids import evidence_ref
from app.utils.json import sanitize_json
from app.utils.text import clean_text, truncate

logger = logging.getLogger("muleguard.backend.services.analysis")

__all__ = [
    "ANALYSIS_SERVICE_VERSION",
    "AnalysisRunOutcome",
    "execute_analysis_run",
    "get_analysis_service_metadata",
    "run_analysis",
]

ANALYSIS_SERVICE_VERSION: Final[str] = "v1"

_GRAPH_VERSION: Final[str] = graph_service.GRAPH_SERVICE_VERSION
_FEATURE_VERSION: Final[str] = features_service.DEFAULT_FEATURE_VERSION

# Graph analysis is comparatively expensive, so it runs only for accounts that
# scored into a band worth investigating.
_GRAPH_MIN_SCORE: Final[float] = 40.0
_MAX_GRAPH_RUNS: Final[int] = 200

_MAX_ACCOUNTS_HARD_CAP: Final[int] = 10_000
_MAX_INDICATORS_PER_ASSESSMENT: Final[int] = 25
_MAX_ERROR_SAMPLES: Final[int] = 25


class AnalysisRunOutcome:
    """
    Aggregate counters and diagnostics for one run.
    """

    __slots__ = (
        "alerts_created",
        "alerts_updated",
        "assessments",
        "correlation_summary",
        "errors",
        "graph_runs",
        "indicators",
        "processed",
        "rule_hits",
        "scoring_modes",
        "selected",
        "stage_timings",
    )

    def __init__(self) -> None:
        self.selected = 0
        self.processed = 0
        self.assessments = 0
        self.rule_hits = 0
        self.indicators = 0
        self.alerts_created = 0
        self.alerts_updated = 0
        self.graph_runs = 0
        self.errors: list[dict[str, Any]] = []
        self.scoring_modes: dict[str, int] = {}
        self.correlation_summary: dict[str, Any] = {}
        self.stage_timings: dict[str, float] = {}

    def note_error(self, *, account_id: Optional[str], stage: str, exc: BaseException) -> None:
        """
        Record a per-account failure without aborting the run.
        """
        if len(self.errors) < _MAX_ERROR_SAMPLES:
            self.errors.append(
                {
                    "account_id": account_id,
                    "stage": stage,
                    "error_type": type(exc).__name__,
                    # Message only, never a traceback: these land in a JSON
                    # column that analysts can read.
                    "message": truncate(clean_text(str(exc), 400), 400),
                }
            )

    def note_mode(self, mode: ScoringMode) -> None:
        """
        Count how many accounts were scored in each mode.
        """
        self.scoring_modes[mode.value] = self.scoring_modes.get(mode.value, 0) + 1

    @property
    def error_count(self) -> int:
        """
        Number of per-account failures recorded.
        """
        return len(self.errors)

    def counts(self) -> dict[str, Any]:
        """
        Return the per-stage counters for `counts_json`.
        """
        return {
            "accounts_selected": self.selected,
            "accounts_processed": self.processed,
            "assessments_written": self.assessments,
            "rule_hits_written": self.rule_hits,
            "indicators_written": self.indicators,
            "alerts_created": self.alerts_created,
            "alerts_updated": self.alerts_updated,
            "graph_runs_written": self.graph_runs,
            "account_errors": self.error_count,
            "scoring_modes": dict(self.scoring_modes),
            "stage_seconds": {k: round(v, 3) for k, v in self.stage_timings.items()},
        }


def _parameters(run: AnalysisRun) -> dict[str, Any]:
    """
    Read the run request parameters defensively.
    """
    raw = getattr(run, "parameters_json", None)
    return dict(raw) if isinstance(raw, Mapping) else {}


def _requested_account_ids(parameters: Mapping[str, Any]) -> Optional[list[str]]:
    """
    Extract an explicit account selection, if the request carried one.
    """
    for key in ("account_ids", "accounts", "account_id_list"):
        value = parameters.get(key)

        if isinstance(value, (list, tuple)):
            cleaned = [str(item).strip() for item in value if str(item).strip()]

            if cleaned:
                return cleaned[:_MAX_ACCOUNTS_HARD_CAP]

    single = parameters.get("account_id")

    if single and str(single).strip():
        return [str(single).strip()]

    return None


def _resolve_as_of(parameters: Mapping[str, Any], run: AnalysisRun) -> datetime:
    """
    Resolve the point-in-time instant for the run.
    """
    for key in ("as_of", "asOf", "observation_time"):
        candidate = parameters.get(key)

        if candidate:
            parsed = ensure_utc(
                candidate if isinstance(candidate, datetime) else _parse_iso(candidate)
            )

            if parsed is not None:
                return parsed

    return ensure_utc(getattr(run, "started_at", None)) or utcnow()


def _parse_iso(value: Any) -> Optional[datetime]:
    from app.utils.dates import parse_datetime

    return parse_datetime(value)


def _select_account_ids(
    db: Session,
    *,
    parameters: Mapping[str, Any],
    as_of: datetime,
) -> list[str]:
    """
    Resolve which accounts this run covers.
    """
    explicit = _requested_account_ids(parameters)

    if explicit:
        found = list(
            db.execute(
                select(Account.id).where(Account.id.in_(explicit))
            ).scalars()
        )
        return [str(item) for item in found]

    limit = parameters.get("max_accounts") or parameters.get("limit")

    try:
        cap = int(limit) if limit else _MAX_ACCOUNTS_HARD_CAP
    except (TypeError, ValueError):
        cap = _MAX_ACCOUNTS_HARD_CAP

    cap = max(1, min(cap, _MAX_ACCOUNTS_HARD_CAP))

    stmt = (
        select(Account.id)
        .where(Account.created_at < as_of)
        .order_by(Account.id)
        .limit(cap)
    )
    return [str(item) for item in db.execute(stmt).scalars()]


def _register_rule_pack(bundle: PolicyBundle) -> tuple[int, list[str]]:
    """
    Load the configured rule pack into the engine registry.

    Returns `(active_rule_count, notes)`. Builtin packs do not auto-register,
    so without this the engine evaluates nothing and every account scores zero.
    """
    notes: list[str] = []

    try:
        from app.rules.definitions import import_rule_pack, register_rule_pack
    except Exception as exc:
        notes.append(f"rule definitions unavailable: {type(exc).__name__}")
        return 0, notes

    payload = {k: v for k, v in bundle.rules.items() if not k.startswith("_")}

    try:
        pack = import_rule_pack(payload, strict=False)
    except Exception as exc:
        notes.append(f"rule pack import failed: {type(exc).__name__}")
        return 0, notes

    try:
        report = register_rule_pack(pack, replace=True, validate=True)
        registered = len(getattr(pack, "rules", ()) or ())
        status = getattr(report, "status", None)

        if status is not None:
            notes.append(f"rule pack registration status: {getattr(status, 'value', status)}")

        return registered, notes
    except Exception as exc:
        notes.append(f"rule pack registration failed: {type(exc).__name__}")
        return 0, notes


def _evaluate_rules(
    records: Sequence[Mapping[str, Any]],
    *,
    settings: Any,
) -> tuple[dict[int, Any], list[str]]:
    """
    Evaluate the rule engine over feature records.

    Returns `(index -> RuleRecordResult, notes)`. Results are keyed by the
    record index the engine echoes back, which is the only reliable join: the
    subject hash is pseudonymous and the engine may reorder.
    """
    notes: list[str] = []

    if not records:
        return {}, notes

    try:
        from app.rules.engine import (
            RuleEngineOptions,
            RuleEvaluationRequest,
            evaluate_rules,
        )
    except Exception as exc:
        notes.append(f"rule engine unavailable: {type(exc).__name__}")
        return {}, notes

    try:
        options = RuleEngineOptions.from_settings(settings)
    except Exception:
        options = RuleEngineOptions()

    try:
        request = RuleEvaluationRequest(records=list(records))
        result = evaluate_rules(request, options)
    except Exception as exc:
        logger.exception("Rule evaluation failed.")
        notes.append(f"rule evaluation failed: {type(exc).__name__}")
        return {}, notes

    out: dict[int, Any] = {}

    for record_result in list(getattr(result, "records", ()) or ()):
        index = getattr(record_result, "index", None)

        if index is None:
            continue

        out[int(index)] = record_result

    if not getattr(result, "ok", True):
        notes.append("rule engine reported a degraded evaluation")

    return out, notes


def _fallback_score(record: Mapping[str, Any], *, settings: Any) -> Optional[float]:
    """
    Score one feature record with the transparent heuristic scorer.

    Scored one record at a time on purpose: the batch result carries only a
    pseudonymous subject hash, so per-record scoring is the only way to keep
    the account association exact.
    """
    try:
        from app.ml.fallback import FallbackOptions, score_fallback_record
    except Exception:
        return None

    try:
        options = FallbackOptions.from_settings(settings)
    except Exception:
        try:
            from app.ml.fallback import FallbackOptions as _Options

            options = _Options()
        except Exception:
            return None

    try:
        scored = score_fallback_record(record, options)
    except Exception:
        logger.debug("Heuristic scoring failed for one record.", exc_info=True)
        return None

    return to_float(getattr(scored, "score", None))


def _active_model(db: Session) -> Optional[ModelVersion]:
    """
    Return the active trained model version, if one is promoted.
    """
    try:
        return db.execute(
            select(ModelVersion)
            .where(ModelVersion.is_active.is_(True))
            .order_by(ModelVersion.record_created_at.desc())
            .limit(1)
        ).scalars().first()
    except Exception:
        logger.debug("Could not read the active model version.", exc_info=True)
        return None


def _rule_payloads(record_result: Any) -> list[dict[str, Any]]:
    """
    Flatten a rule result into plain dicts for persistence and alerting.
    """
    payloads: list[dict[str, Any]] = []

    for match in list(getattr(record_result, "matched_rules", ()) or ()):
        reasons = list(getattr(match, "reasons", ()) or ())
        action_reason = next(
            (r for r in reasons if isinstance(r, Mapping) and r.get("type") == "action"),
            {},
        )
        metadata = getattr(match, "metadata", {}) or {}

        payloads.append(
            {
                "rule_id": str(getattr(match, "rule_id", "") or ""),
                "severity": str(
                    getattr(getattr(match, "severity", ""), "value", getattr(match, "severity", ""))
                ),
                "score_contribution": to_float(getattr(match, "score_contribution", None)) or 0.0,
                "effects": [str(e) for e in (getattr(match, "effects", ()) or ())],
                "reason_code": str(action_reason.get("reason_code") or ""),
                "reason_message": str(action_reason.get("reason_message") or ""),
                "metadata": dict(metadata) if isinstance(metadata, Mapping) else {},
                "reasons": [r for r in reasons if isinstance(r, Mapping)][:6],
            }
        )

    return payloads


def _persist_assessment(
    db: Session,
    *,
    account_id: str,
    run: AnalysisRun,
    risk: FusedRisk,
    rules: Sequence[Mapping[str, Any]],
    feature_snapshot_id: Optional[str],
    model_version_id: Optional[str],
    as_of: datetime,
    dataset_fingerprint: Optional[str],
    outcome: AnalysisRunOutcome,
) -> ModelAssessment:
    """
    Persist the assessment plus its rule hits and risk indicators.
    """
    assessment = ModelAssessment(
        account_id=account_id,
        feature_snapshot_id=feature_snapshot_id,
        analysis_run_id=str(run.id),
        model_version_id=model_version_id,
        as_of=as_of,
        scored_at=utcnow(),
        scoring_mode=risk.scoring_mode,
        score=quantize_score(risk.score),
        score_type="investigative_priority_score",
        score_version=risk.score_version,
        risk_band=risk.band,
        components_json=risk.components_json(),
        explanation_json=risk.explanation_json(),
        caveats_json=risk.caveats_json(),
        dataset_fingerprint=dataset_fingerprint,
    )
    db.add(assessment)
    db.flush()
    outcome.assessments += 1

    # ------------------------------------------------------------ rule hits
    rule_hit_ids: dict[str, str] = {}

    for rule in rules:
        rule_id = str(rule.get("rule_id") or "")

        if not rule_id:
            continue

        severity = severity_for_rule_severity(rule.get("severity"))
        reasons = rule.get("reasons") or []
        measured: Optional[Any] = None
        threshold: Optional[Any] = None

        for reason in reasons:
            if not isinstance(reason, Mapping):
                continue

            if measured is None and reason.get("observed") is not None:
                measured = reason.get("observed")

            if threshold is None and reason.get("expected") is not None:
                threshold = reason.get("expected")

        hit = RuleHit(
            account_id=account_id,
            assessment_id=str(assessment.id),
            rule_code=rule_id[:100],
            rule_version=str(rule.get("metadata", {}).get("version") or "v1")[:32],
            triggered=True,
            measured_value=to_decimal(measured),
            threshold=to_decimal(threshold),
            severity=severity,
            explanation=clean_text(rule.get("reason_message") or "", 2_000) or None,
            evidence_refs_json=[
                evidence_ref("ACCOUNT", account_id),
                evidence_ref("MODEL_ASSESSMENT", str(assessment.id)),
            ],
            config_json=sanitize_json(
                {
                    "rule_id": rule_id,
                    "severity": rule.get("severity"),
                    "effects": rule.get("effects"),
                    "score_contribution": rule.get("score_contribution"),
                    "typology": (rule.get("metadata") or {}).get("typology"),
                },
                max_items=20,
            ),
            evaluated_at=utcnow(),
        )
        db.add(hit)
        db.flush()
        rule_hit_ids[rule_id] = str(hit.id)
        outcome.rule_hits += 1

    # ------------------------------------------------------------ indicators
    written = 0

    for rule in rules:
        if written >= _MAX_INDICATORS_PER_ASSESSMENT:
            break

        rule_id = str(rule.get("rule_id") or "")

        if not rule_id:
            continue

        db.add(
            RiskIndicator(
                assessment_id=str(assessment.id),
                indicator_type=IndicatorType.RULE,
                code=rule_id[:100],
                title=truncate(
                    clean_text(rule.get("reason_code") or rule_id, 200), 200
                ),
                severity=severity_for_rule_severity(rule.get("severity")),
                measured_value=to_decimal(rule.get("score_contribution")),
                threshold=None,
                explanation=clean_text(rule.get("reason_message") or "", 2_000) or None,
                evidence_refs_json=[
                    evidence_ref("ACCOUNT", account_id),
                    evidence_ref("MODEL_ASSESSMENT", str(assessment.id)),
                ],
                config_json=sanitize_json(
                    {"typology": (rule.get("metadata") or {}).get("typology")},
                    max_items=10,
                ),
                rule_hit_id=rule_hit_ids.get(rule_id),
            )
        )
        written += 1
        outcome.indicators += 1

    # One fused-risk indicator so the explanation panel always has the
    # component breakdown even when no rule fired.
    if written < _MAX_INDICATORS_PER_ASSESSMENT:
        db.add(
            RiskIndicator(
                assessment_id=str(assessment.id),
                indicator_type=IndicatorType.FUSED_RISK,
                code="fused_risk_score",
                title=f"Fused investigative priority {risk.score:.1f}/100",
                severity=(
                    Severity.CRITICAL
                    if risk.score >= 85
                    else Severity.HIGH
                    if risk.score >= 65
                    else Severity.MEDIUM
                    if risk.score >= 40
                    else Severity.LOW
                ),
                measured_value=to_decimal(risk.score),
                threshold=None,
                explanation=clean_text(
                    str(risk.explanation.get("summary") or ""), 2_000
                )
                or None,
                evidence_refs_json=[evidence_ref("MODEL_ASSESSMENT", str(assessment.id))],
                config_json=sanitize_json(
                    {"effective_weights": risk.effective_weights}, max_items=20
                ),
                rule_hit_id=None,
            )
        )
        outcome.indicators += 1

    db.flush()
    return assessment


def execute_analysis_run(
    db: Session,
    run: AnalysisRun,
    settings: Any = None,
) -> AnalysisRun:
    """
    Execute one analysis run to completion.

    This is the callable the analysis endpoint resolves. It always leaves the
    run in a terminal status, and never commits — the endpoint owns the
    transaction so the whole run is atomic.
    """
    started = time.perf_counter()
    outcome = AnalysisRunOutcome()
    parameters = _parameters(run)
    as_of = _resolve_as_of(parameters, run)

    run.status = AnalysisRunStatus.RUNNING
    run.started_at = run.started_at or utcnow()
    run.run_type = str(parameters.get("run_type") or run.run_type or "batch")
    db.flush()

    notes: list[str] = []

    try:
        bundle = get_policy_bundle()
    except Exception as exc:
        # No policy means no detection. This is fatal for the run.
        return _fail(
            db,
            run,
            outcome,
            code="policy_unavailable",
            message=f"Detection policy could not be loaded: {exc}",
        )

    rule_count, rule_notes = _register_rule_pack(bundle)
    notes.extend(rule_notes)

    if rule_count == 0:
        notes.append(
            "No rules were registered; rule-based detection is inactive for "
            "this run and scores rely on the remaining components."
        )

    # ------------------------------------------------------- account selection
    stage = time.perf_counter()

    try:
        account_ids = _select_account_ids(db, parameters=parameters, as_of=as_of)
    except Exception as exc:
        return _fail(
            db,
            run,
            outcome,
            code="account_selection_failed",
            message=f"Account selection failed: {exc}",
        )

    outcome.selected = len(account_ids)
    outcome.stage_timings["select_accounts"] = time.perf_counter() - stage

    if not account_ids:
        run.account_count = 0
        run.processed_count = 0
        run.assessment_count = 0
        run.alert_count = 0
        run.error_count = 0
        run.status = AnalysisRunStatus.SUCCEEDED
        run.finished_at = utcnow()
        run.scoring_mode = ScoringMode.UNKNOWN
        run.counts_json = outcome.counts()
        run.summary_json = {
            "summary": "No accounts matched the run selection.",
            "notes": notes,
        }
        run.config_json = bundle.safe_summary()
        db.flush()
        return run

    # ------------------------------------------------------------- features
    stage = time.perf_counter()

    try:
        build_result, dataset = features_service.compute_features(
            db, as_of=as_of, account_ids=account_ids, settings=settings
        )
    except FeatureComputationError as exc:
        return _fail(
            db,
            run,
            outcome,
            code="feature_computation_failed",
            message=str(exc),
        )
    except Exception as exc:
        return _fail(
            db,
            run,
            outcome,
            code="feature_computation_error",
            message=f"Unexpected failure building features: {exc}",
        )

    outcome.stage_timings["build_features"] = time.perf_counter() - stage
    fingerprint = dataset.fingerprint()

    stage = time.perf_counter()

    try:
        snapshots = features_service.persist_feature_snapshots(
            db,
            result=build_result,
            bundle=dataset,
            as_of=as_of,
            feature_version=_FEATURE_VERSION,
        )
    except Exception as exc:
        logger.exception("Persisting feature snapshots failed.")
        snapshots = {}
        notes.append(f"feature snapshots not persisted: {type(exc).__name__}")

    outcome.stage_timings["persist_features"] = time.perf_counter() - stage

    # --------------------------------------------- build the rule input records
    vectors = list(getattr(build_result, "vectors", []) or [])
    records: list[dict[str, Any]] = []
    index_to_account: dict[int, str] = {}
    account_features: dict[str, dict[str, Any]] = {}
    salt = str(getattr(settings, "SECRET_KEY", "") or "") or None

    for vector in vectors:
        account_id = features_service._vector_account_id(vector)  # noqa: SLF001

        if not account_id:
            continue

        values = features_service._vector_features(vector)  # noqa: SLF001

        if not values:
            continue

        index = len(records)
        index_to_account[index] = account_id
        account_features[account_id] = values
        records.append(
            {
                "index": index,
                "subject_ref_hash": hash_identifier(
                    account_id, salt=salt, kind="account"
                ),
                **values,
            }
        )

    # ------------------------------------------------------------ rule engine
    stage = time.perf_counter()
    rule_results, eval_notes = _evaluate_rules(records, settings=settings)
    notes.extend(eval_notes)
    outcome.stage_timings["evaluate_rules"] = time.perf_counter() - stage

    # -------------------------------------------------- complaint correlation
    stage = time.perf_counter()
    correlation_counts: dict[str, int] = {}

    try:
        correlation_summary = correlate_complaints(
            db, account_ids=account_ids, as_of=as_of
        )
        outcome.correlation_summary = correlation_summary.to_dict()

        from app.models import ComplaintCorrelation

        for account_id, count in db.execute(
            select(
                ComplaintCorrelation.account_id,
                ComplaintCorrelation.id,
            ).where(ComplaintCorrelation.account_id.in_(account_ids))
        ).all():
            if account_id:
                correlation_counts[str(account_id)] = (
                    correlation_counts.get(str(account_id), 0) + 1
                )
    except Exception as exc:
        logger.exception("Complaint correlation stage failed.")
        notes.append(f"complaint correlation skipped: {type(exc).__name__}")

    outcome.stage_timings["correlate_complaints"] = time.perf_counter() - stage

    # ------------------------------------------------------------- scoring
    active_model = _active_model(db)
    model_version_id = str(active_model.id) if active_model is not None else None
    model_version_label = str(active_model.version) if active_model is not None else None
    stage = time.perf_counter()

    scored: list[tuple[ModelAssessment, FusedRisk, list[dict[str, Any]]]] = []

    for index, record in enumerate(records):
        account_id = index_to_account.get(index)

        if not account_id:
            continue

        try:
            record_result = rule_results.get(index)
            rules = _rule_payloads(record_result) if record_result is not None else []
            rule_score = (
                to_float(getattr(record_result, "score", None))
                if record_result is not None
                else None
            )
            effects = (
                [str(e) for e in (getattr(record_result, "effects", ()) or ())]
                if record_result is not None
                else []
            )

            feature_values = account_features.get(account_id, {})
            fallback = _fallback_score(record, settings=settings)

            risk = fuse_risk(
                features=feature_values,
                rule_score=rule_score,
                model_score=None,
                model_available=False,
                fallback_score=fallback,
                correlation_count=correlation_counts.get(account_id, 0),
                triggered_rules=rules,
                policy=bundle.scoring,
            )
            outcome.note_mode(risk.scoring_mode)

            snapshot = snapshots.get(account_id)
            assessment = _persist_assessment(
                db,
                account_id=account_id,
                run=run,
                risk=risk,
                rules=rules,
                feature_snapshot_id=str(snapshot.id) if snapshot is not None else None,
                model_version_id=model_version_id,
                as_of=as_of,
                dataset_fingerprint=fingerprint,
                outcome=outcome,
            )
            scored.append((assessment, risk, rules))
            outcome.processed += 1
        except Exception as exc:
            # One account must not abandon the run.
            logger.exception("Scoring failed for account %s.", account_id)
            outcome.note_error(account_id=account_id, stage="scoring", exc=exc)

    outcome.stage_timings["score_accounts"] = time.perf_counter() - stage

    # -------------------------------------------------------------- alerting
    stage = time.perf_counter()

    for assessment, risk, rules in scored:
        try:
            effects = [
                effect
                for rule in rules
                for effect in (rule.get("effects") or [])
            ]
            alert_outcome = raise_alert_for_assessment(
                db,
                assessment=assessment,
                risk=risk,
                triggered_rules=rules,
                effects=effects,
                correlation_count=correlation_counts.get(str(assessment.account_id), 0),
                as_of=as_of,
                actor_id=getattr(run, "requested_by", None),
                dedup_policy=bundle.alert_dedup,
                scoring_policy=bundle.scoring,
            )

            if alert_outcome.alert is not None:
                if alert_outcome.created:
                    outcome.alerts_created += 1
                else:
                    outcome.alerts_updated += 1
        except Exception as exc:
            logger.exception("Alerting failed for account %s.", assessment.account_id)
            outcome.note_error(
                account_id=str(assessment.account_id), stage="alerting", exc=exc
            )

    outcome.stage_timings["raise_alerts"] = time.perf_counter() - stage

    # --------------------------------------------------------- graph analysis
    stage = time.perf_counter()
    graph_candidates = sorted(
        (item for item in scored if item[1].score >= _GRAPH_MIN_SCORE),
        key=lambda item: -item[1].score,
    )[:_MAX_GRAPH_RUNS]

    for assessment, _risk, _rules in graph_candidates:
        try:
            neighbourhood = graph_service.build_neighbourhood(
                db, str(assessment.account_id), as_of=as_of
            )
            graph_service.persist_graph_run(
                db,
                result=neighbourhood,
                analysis_run_id=str(run.id),
                created_by=getattr(run, "requested_by", None),
            )
            outcome.graph_runs += 1
        except Exception as exc:
            logger.exception(
                "Graph analysis failed for account %s.", assessment.account_id
            )
            outcome.note_error(
                account_id=str(assessment.account_id), stage="graph", exc=exc
            )

    outcome.stage_timings["graph_analysis"] = time.perf_counter() - stage

    # -------------------------------------------------------------- finalize
    dominant_mode = ScoringMode.UNKNOWN

    if outcome.scoring_modes:
        dominant_mode = ScoringMode(
            max(outcome.scoring_modes.items(), key=lambda kv: kv[1])[0]
        )

    run.account_count = outcome.selected
    run.processed_count = outcome.processed
    run.assessment_count = outcome.assessments
    run.alert_count = outcome.alerts_created
    run.error_count = outcome.error_count
    run.scoring_mode = dominant_mode
    run.score_version = bundle.score_version
    run.feature_version = _FEATURE_VERSION
    run.rules_version = bundle.rules_version
    run.graph_version = _GRAPH_VERSION
    run.complaint_version = "v1"
    run.dataset_fingerprint = fingerprint
    run.model_version_id = model_version_id
    run.model_version = model_version_label
    run.config_json = bundle.safe_summary()
    run.counts_json = outcome.counts()
    run.error_summary_json = (
        {"errors": outcome.errors, "truncated": outcome.error_count >= _MAX_ERROR_SAMPLES}
        if outcome.errors
        else None
    )
    run.summary_json = sanitize_json(
        {
            "summary": (
                f"Scored {outcome.processed} of {outcome.selected} account(s); "
                f"{outcome.alerts_created} alert(s) raised, "
                f"{outcome.alerts_updated} updated."
            ),
            "counts": outcome.counts(),
            "correlation": outcome.correlation_summary,
            "registered_rule_count": rule_count,
            "notes": notes,
            "interpretation": [
                "Scores rank accounts for analyst attention and are not "
                "probabilities of guilt.",
                "Alerts are investigative leads and trigger no automatic action.",
                "Candidate money trails show that value could have moved along "
                "a path, not that specific funds did.",
            ],
        },
        max_items=80,
    )

    # PARTIAL is the honest status when some accounts failed: the run produced
    # usable output but is not a complete answer.
    if outcome.processed == 0 and outcome.selected > 0:
        run.status = AnalysisRunStatus.FAILED

        # Distinguish "every account failed" from "there was nothing to score".
        #
        # These look identical in the counters -- processed == 0 either way --
        # but they have opposite causes and opposite fixes, and the old message
        # sent you to `error_summary_json` for per-account failures that, in
        # the second case, do not exist. A run over 507 accounts with 0
        # transactions in the lookback window reported
        #
        #     "No account could be scored. See error_summary_json for the
        #      per-account failures."    (errors=0)
        #
        # which points at an empty list and says nothing about the window that
        # excluded the data. Naming the empty dataset and the horizon turns a
        # dead end into something actionable.
        dataset_counts = dataset.counts() if dataset is not None else {}
        scoreable = sum(
            int(dataset_counts.get(key, 0) or 0)
            for key in ("transactions", "complaints", "balances")
        )

        if outcome.errors == 0 and scoreable == 0:
            run.error_code = "no_scoreable_data_in_window"
            run.error_message = (
                "No account could be scored because the point-in-time dataset "
                "was empty: no transactions, complaints or balances fall "
                f"within the lookback window ending {as_of.isoformat()}. "
                "The accounts exist, but their activity is outside the window. "
                "Check the age of the ingested data against the analysis "
                "lookback, or pass an earlier as_of."
            )
        else:
            run.error_code = "no_accounts_scored"
            run.error_message = (
                "No account could be scored. See error_summary_json for the "
                "per-account failures."
            )
    elif outcome.errors:
        run.status = AnalysisRunStatus.PARTIAL
    else:
        run.status = AnalysisRunStatus.SUCCEEDED

    run.finished_at = utcnow()
    db.flush()

    record_system_event(
        db,
        action="analysis_run_complete",
        resource_type="analysis_run",
        resource_id=str(run.id),
        metadata={
            "status": run.status.value,
            "counts": outcome.counts(),
            "duration_seconds": round(time.perf_counter() - started, 3),
        },
    )

    logger.info(
        "Analysis run %s finished status=%s processed=%d/%d alerts=%d errors=%d in %.2fs",
        run.id,
        run.status.value,
        outcome.processed,
        outcome.selected,
        outcome.alerts_created,
        outcome.error_count,
        time.perf_counter() - started,
    )
    return run


def _fail(
    db: Session,
    run: AnalysisRun,
    outcome: AnalysisRunOutcome,
    *,
    code: str,
    message: str,
) -> AnalysisRun:
    """
    Mark a run failed with a sanitized reason.

    The endpoint reads `error_code` and `error_message` to build its response,
    so both must be set before returning.
    """
    run.status = AnalysisRunStatus.FAILED
    run.finished_at = utcnow()
    run.error_code = clean_text(code, 100)
    run.error_message = truncate(clean_text(message, 2_000), 2_000)
    run.account_count = outcome.selected
    run.processed_count = outcome.processed
    run.assessment_count = outcome.assessments
    run.alert_count = outcome.alerts_created
    run.error_count = max(1, outcome.error_count)
    run.counts_json = outcome.counts()
    run.summary_json = {"summary": run.error_message, "failed_stage": code}
    db.flush()

    record_system_event(
        db,
        action="analysis_run_failed",
        resource_type="analysis_run",
        resource_id=str(run.id),
        metadata={"error_code": code, "message": run.error_message},
    )
    logger.error("Analysis run %s failed: %s - %s", run.id, code, run.error_message)
    return run


# The endpoint probes for several names; `run_analysis` is one of them.
run_analysis = execute_analysis_run


def get_analysis_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the analysis service.
    """
    return {
        "service": "muleguard.backend.services.analysis",
        "version": ANALYSIS_SERVICE_VERSION,
        "entrypoint": "execute_analysis_run(db, run, settings)",
        "aliases": ["run_analysis"],
        "feature_version": _FEATURE_VERSION,
        "graph_version": _GRAPH_VERSION,
        "pipeline": [
            "select_accounts",
            "build_point_in_time_dataset",
            "compute_feature_vectors",
            "persist_feature_snapshots",
            "evaluate_rule_pack",
            "score_model_or_heuristic_fallback",
            "fuse_risk",
            "persist_assessments_rule_hits_indicators",
            "correlate_complaints",
            "build_graph_neighbourhoods",
            "raise_or_update_alerts",
            "finalize_run",
        ],
        "limits": {
            "max_accounts": _MAX_ACCOUNTS_HARD_CAP,
            "graph_min_score": _GRAPH_MIN_SCORE,
            "max_graph_runs": _MAX_GRAPH_RUNS,
            "max_indicators_per_assessment": _MAX_INDICATORS_PER_ASSESSMENT,
        },
        "guarantees": [
            "The run always ends in a terminal status.",
            "A failure sets error_code and error_message.",
            "The service never commits; the caller owns the transaction.",
            "A per-account failure is counted and the run ends PARTIAL rather "
            "than abandoning the remaining accounts.",
            "Ground-truth labels are never read.",
        ],
    }
