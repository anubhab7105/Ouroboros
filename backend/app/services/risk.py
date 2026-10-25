"""
MULEGUARD risk fusion service.

Combines the rule, model, anomaly, graph, and complaint signals into the single
0–100 investigative priority score stored on `ModelAssessment`, and maps it to
a risk band.

What the score is and is not:

- It is a *relative priority* for analyst attention.
- It is not a probability of guilt, a calibrated fraud likelihood, or an
  enforcement trigger. Nothing in MULEGUARD may act on it automatically.

Two design decisions matter:

1. **Missing components are renormalised away, not treated as zero.** If the
   trained model is unavailable, scoring with `model = 0.0` would drag every
   account's score down and make a high-risk account look safe. Instead the
   remaining weights are renormalised and the assessment records a caveat plus
   a degraded `scoring_mode`.

2. **Weights are a product decision, not a learned optimum.** They are
   deliberately in configuration (`config/scoring.default.json`) and the model
   is weighted *below* the rules, so an explainable signal always dominates an
   opaque one.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any, Final, Optional

from app.models import RiskBand, ScoringMode, Severity
from app.services.policy import get_scoring_policy
from app.utils.decimals import clamp, clamp_confidence, to_float
from app.utils.json import sanitize_json

logger = logging.getLogger("muleguard.backend.services.risk")

__all__ = [
    "RISK_SERVICE_VERSION",
    "ComponentSignal",
    "FusedRisk",
    "band_for_score",
    "fuse_risk",
    "get_risk_service_metadata",
    "priority_for_band",
    "severity_for_rule_severity",
    "should_raise_alert",
]

RISK_SERVICE_VERSION: Final[str] = "v1"

_BAND_ORDER: Final[tuple[str, ...]] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Graph features that contribute to the graph component, with their weights
# within that component. These are the position signals that distinguish a
# layering hop from an endpoint.
_GRAPH_SIGNALS: Final[tuple[tuple[str, float], ...]] = (
    ("graph_intermediary_score_30d", 0.30),
    ("graph_betweenness_norm_30d", 0.25),
    ("graph_page_rank_norm_30d", 0.15),
    ("graph_cycle_indicator_30d", 0.20),
    ("graph_shared_entity_cluster_size_30d", 0.10),
)

# Complaint features that contribute to the complaint component.
_COMPLAINT_SIGNALS: Final[tuple[tuple[str, float], ...]] = (
    ("complaint_suspect_count_30d", 0.40),
    ("complaint_count_30d", 0.25),
    ("complaint_linked_txn_ratio_30d", 0.20),
    ("complaint_neighbour", 0.15),
)

_ANOMALY_FEATURE: Final[str] = "composite_anomaly_score_30d"


class ComponentSignal:
    """
    One normalised 0..1 component entering the fusion.

    `available=False` means "no information", which is handled by
    renormalisation rather than by substituting zero.
    """

    __slots__ = ("available", "detail", "name", "source", "value")

    def __init__(
        self,
        name: str,
        value: Optional[float],
        *,
        source: str = "",
        available: bool = True,
        detail: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.name = str(name)
        self.value = None if value is None else clamp_confidence(value)
        self.source = str(source or "")
        self.available = bool(available and self.value is not None)
        self.detail = dict(detail or {})

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation for `components_json`.
        """
        return {
            "name": self.name,
            "value": self.value,
            "available": self.available,
            "source": self.source,
            "detail": sanitize_json(self.detail, max_items=30),
        }

    def __repr__(self) -> str:
        return f"ComponentSignal({self.name!r}, {self.value!r}, available={self.available})"


class FusedRisk:
    """
    The result of fusing all available components for one account.
    """

    __slots__ = (
        "band",
        "caveats",
        "components",
        "effective_weights",
        "explanation",
        "score",
        "score_version",
        "scoring_mode",
    )

    def __init__(
        self,
        *,
        score: float,
        band: RiskBand,
        scoring_mode: ScoringMode,
        score_version: str,
        components: Sequence[ComponentSignal],
        effective_weights: Mapping[str, float],
        caveats: Sequence[str],
        explanation: Mapping[str, Any],
    ) -> None:
        self.score = float(score)
        self.band = band
        self.scoring_mode = scoring_mode
        self.score_version = str(score_version)
        self.components = list(components)
        self.effective_weights = dict(effective_weights)
        self.caveats = list(caveats)
        self.explanation = dict(explanation)

    def components_json(self) -> dict[str, Any]:
        """
        Return the `ModelAssessment.components_json` payload.
        """
        return {
            "score_version": self.score_version,
            "scoring_mode": self.scoring_mode.value,
            "components": [component.to_dict() for component in self.components],
            "effective_weights": self.effective_weights,
            "fusion_method": "weighted_sum_of_normalised_components",
        }

    def caveats_json(self) -> dict[str, Any]:
        """
        Return the `ModelAssessment.caveats_json` payload.
        """
        return {
            "caveats": self.caveats,
            "unavailable_components": [
                component.name for component in self.components if not component.available
            ],
        }

    def explanation_json(self) -> dict[str, Any]:
        """
        Return the `ModelAssessment.explanation_json` payload.
        """
        return sanitize_json(self.explanation, max_items=100)


def _feature(features: Mapping[str, Any], name: str) -> Optional[float]:
    """
    Read a numeric feature, treating a boolean flag as 1.0 / 0.0.
    """
    if name not in features:
        return None

    raw = features.get(name)

    if isinstance(raw, bool):
        return 1.0 if raw else 0.0

    return to_float(raw)


def _normalise_count(value: Optional[float], soft_cap: float) -> Optional[float]:
    """
    Map a non-negative count onto 0..1 with a soft cap.

    A linear scale would let one extreme account dominate; a soft cap means the
    difference between 1 and 3 complaints matters more than between 20 and 30,
    which matches how an investigator reads them.
    """
    if value is None:
        return None

    if soft_cap <= 0:
        return None

    return clamp(float(value) / soft_cap, 0.0, 1.0)


def _graph_component(features: Mapping[str, Any]) -> ComponentSignal:
    """
    Build the graph-position component from catalog features.
    """
    total = 0.0
    weight_used = 0.0
    detail: dict[str, Any] = {}

    for name, weight in _GRAPH_SIGNALS:
        value = _feature(features, name)

        if value is None:
            continue

        if name == "graph_shared_entity_cluster_size_30d":
            value = _normalise_count(value, 20.0) or 0.0

        value = clamp(value, 0.0, 1.0)
        total += value * weight
        weight_used += weight
        detail[name] = value

    if weight_used <= 0:
        return ComponentSignal(
            "graph", None, source="graph_features", available=False
        )

    return ComponentSignal(
        "graph",
        total / weight_used,
        source="graph_features",
        detail=detail,
    )


def _complaint_component(
    features: Mapping[str, Any],
    *,
    correlation_count: int = 0,
) -> ComponentSignal:
    """
    Build the complaint-corroboration component.
    """
    total = 0.0
    weight_used = 0.0
    detail: dict[str, Any] = {}

    for name, weight in _COMPLAINT_SIGNALS:
        if name == "complaint_neighbour":
            value = _feature(features, "graph_neighbor_complaint_ratio_30d")
        else:
            value = _feature(features, name)

        if value is None:
            continue

        if name in {"complaint_suspect_count_30d", "complaint_count_30d"}:
            value = _normalise_count(value, 5.0) or 0.0

        value = clamp(value, 0.0, 1.0)
        total += value * weight
        weight_used += weight
        detail[name] = value

    if correlation_count > 0:
        detail["persisted_correlation_count"] = int(correlation_count)
        boost = _normalise_count(float(correlation_count), 5.0) or 0.0
        total += boost * 0.2
        weight_used += 0.2

    if weight_used <= 0:
        return ComponentSignal(
            "complaint", None, source="complaint_features", available=False
        )

    return ComponentSignal(
        "complaint",
        total / weight_used,
        source="complaint_features",
        detail=detail,
    )


def fuse_risk(
    *,
    features: Optional[Mapping[str, Any]] = None,
    rule_score: Optional[float] = None,
    model_score: Optional[float] = None,
    model_available: bool = False,
    fallback_score: Optional[float] = None,
    correlation_count: int = 0,
    triggered_rules: Optional[Sequence[Mapping[str, Any]]] = None,
    policy: Optional[Mapping[str, Any]] = None,
) -> FusedRisk:
    """
    Fuse all available signals into one investigative priority score.

    `rule_score`, `model_score`, and `fallback_score` are each 0..1.
    `features` supplies the anomaly, graph, and complaint components.
    """
    feature_map: Mapping[str, Any] = features or {}
    scoring = policy or get_scoring_policy()
    fusion = scoring.get("fusion") or {}
    declared = fusion.get("components") or {}

    weights: dict[str, float] = {}

    for name, spec in declared.items():
        if isinstance(spec, Mapping):
            weight = to_float(spec.get("weight"))

            if weight is not None and weight >= 0:
                weights[str(name)] = float(weight)

    if not weights:
        weights = {
            "rules": 0.40,
            "model": 0.25,
            "anomaly": 0.15,
            "graph": 0.12,
            "complaint": 0.08,
        }

    # ---------------------------------------------------------- components
    components: list[ComponentSignal] = []

    components.append(
        ComponentSignal(
            "rules",
            rule_score,
            source="app.rules.engine",
            available=rule_score is not None,
            detail={"triggered_rule_count": len(triggered_rules or [])},
        )
    )

    # The supervised model and the heuristic fallback occupy the same slot:
    # they are alternative estimators of the same quantity, never additive.
    if model_available and model_score is not None:
        components.append(
            ComponentSignal(
                "model",
                model_score,
                source="trained_supervised_model",
                detail={"estimator": "supervised"},
            )
        )
        scoring_mode = ScoringMode.TRAINED_MODEL
    elif fallback_score is not None:
        components.append(
            ComponentSignal(
                "model",
                fallback_score,
                source="app.ml.fallback heuristic scorer",
                detail={"estimator": "heuristic_fallback"},
            )
        )
        scoring_mode = ScoringMode.HEURISTIC_FALLBACK
    else:
        components.append(
            ComponentSignal(
                "model", None, source="unavailable", available=False
            )
        )
        scoring_mode = ScoringMode.RULES_ONLY

    anomaly_value = _feature(feature_map, _ANOMALY_FEATURE)
    components.append(
        ComponentSignal(
            "anomaly",
            anomaly_value,
            source=_ANOMALY_FEATURE,
            available=anomaly_value is not None,
        )
    )
    components.append(_graph_component(feature_map))
    components.append(
        _complaint_component(feature_map, correlation_count=correlation_count)
    )

    # ------------------------------------------------------------- fusion
    available = [c for c in components if c.available and c.value is not None]
    available_weight = sum(weights.get(c.name, 0.0) for c in available)

    caveats: list[str] = []

    if not available or available_weight <= 0:
        # Nothing to go on. Report 0 with an explicit caveat rather than
        # inventing a number.
        caveats.append(
            "No scoring component was available; the score is not meaningful "
            "and the account should be treated as unscored."
        )
        return FusedRisk(
            score=0.0,
            band=RiskBand.LOW,
            scoring_mode=ScoringMode.ML_DISABLED,
            score_version=str(scoring.get("score_version") or "v1"),
            components=components,
            effective_weights={},
            caveats=caveats,
            explanation={
                "summary": "No scoring component was available.",
                "components": [],
            },
        )

    effective: dict[str, float] = {
        c.name: weights.get(c.name, 0.0) / available_weight for c in available
    }
    normalised = sum((c.value or 0.0) * effective[c.name] for c in available)
    score = clamp(normalised * 100.0, 0.0, 100.0)

    unavailable = [c.name for c in components if not c.available]

    if unavailable:
        caveats.append(
            "Component weights were renormalised because these components were "
            f"unavailable: {', '.join(sorted(unavailable))}. A missing component "
            "lowers confidence in the score; it does not lower the risk."
        )

    if scoring_mode is ScoringMode.HEURISTIC_FALLBACK:
        caveats.append(
            "Scored with the transparent heuristic scorer because no validated "
            "trained model is active. Weights are hand-set, not learned."
        )
    elif scoring_mode is ScoringMode.RULES_ONLY:
        caveats.append(
            "Scored from rule evaluation alone. Only typologies encoded in the "
            "rule pack can be detected."
        )

    caveats.extend(str(c) for c in (scoring.get("caveats") or [])[:6])

    band = band_for_score(score, policy=scoring)

    explanation = {
        "summary": (
            f"Investigative priority {score:.1f}/100 ({band.value}) from "
            f"{len(available)} of {len(components)} components."
        ),
        "score": round(score, 2),
        "band": band.value,
        "scoring_mode": scoring_mode.value,
        "components": [
            {
                "name": c.name,
                "normalised_value": c.value,
                "effective_weight": round(effective.get(c.name, 0.0), 4),
                "contribution_points": round(
                    (c.value or 0.0) * effective.get(c.name, 0.0) * 100.0, 2
                ),
                "source": c.source,
            }
            for c in available
        ],
        "unavailable_components": sorted(unavailable),
        "triggered_rules": [
            {
                "rule_id": str(rule.get("rule_id") or ""),
                "severity": str(rule.get("severity") or ""),
                "reason_code": str(rule.get("reason_code") or ""),
                "reason_message": str(rule.get("reason_message") or ""),
            }
            for rule in list(triggered_rules or [])[:25]
        ],
        "interpretation": (
            "This score ranks accounts for analyst attention. It is not a "
            "probability of guilt and must not drive an automatic action."
        ),
    }

    return FusedRisk(
        score=score,
        band=band,
        scoring_mode=scoring_mode,
        score_version=str(scoring.get("score_version") or "v1"),
        components=components,
        effective_weights={k: round(v, 4) for k, v in effective.items()},
        caveats=caveats,
        explanation=explanation,
    )


def band_for_score(
    score: Any,
    *,
    policy: Optional[Mapping[str, Any]] = None,
) -> RiskBand:
    """
    Map a 0..100 score onto a configured risk band.
    """
    value = to_float(score)

    if value is None:
        return RiskBand.LOW

    scoring = policy or get_scoring_policy()
    thresholds = (scoring.get("bands") or {}).get("thresholds") or []

    best: Optional[RiskBand] = None
    best_min = -1.0

    for entry in thresholds:
        if not isinstance(entry, Mapping):
            continue

        low = to_float(entry.get("min"))
        high = to_float(entry.get("max"))
        name = str(entry.get("band") or "").strip().upper()

        if low is None or high is None or name not in _BAND_ORDER:
            continue

        if low <= value <= high and low > best_min:
            best = RiskBand(name)
            best_min = low

    if best is not None:
        return best

    # Fallback cut-points matching scoring.default.json.
    if value >= 85:
        return RiskBand.CRITICAL

    if value >= 65:
        return RiskBand.HIGH

    if value >= 40:
        return RiskBand.MEDIUM

    return RiskBand.LOW


def priority_for_band(band: RiskBand, *, policy: Optional[Mapping[str, Any]] = None) -> str:
    """
    Map a risk band onto an alert priority value.
    """
    scoring = policy or get_scoring_policy()
    mapping = (scoring.get("alerting") or {}).get("priority_mapping") or {}
    resolved = str(mapping.get(band.value, band.value)).strip().upper()
    return resolved if resolved in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else band.value


def should_raise_alert(
    risk: FusedRisk,
    *,
    effects: Optional[Sequence[str]] = None,
    policy: Optional[Mapping[str, Any]] = None,
) -> tuple[bool, str]:
    """
    Decide whether a fused result warrants an alert.

    Returns `(should_alert, reason)`.

    An `escalate_to_human` rule effect always alerts, regardless of score, so
    that a complaint-named suspect is never missed because the other signals
    happened to be quiet.
    """
    scoring = policy or get_scoring_policy()
    alerting = scoring.get("alerting") or {}
    always = {
        str(e).strip().lower()
        for e in (alerting.get("always_alert_on_effects") or [])
    }
    present = {str(e).strip().lower() for e in (effects or [])}

    overlap = always & present

    if overlap:
        return True, f"rule effect {sorted(overlap)[0]!r} always raises an alert"

    minimum = to_float(alerting.get("min_score_for_alert"))

    if minimum is None:
        minimum = 65.0

    if risk.score >= minimum:
        return True, f"score {risk.score:.1f} >= threshold {minimum:.1f}"

    min_band = str(alerting.get("min_band_for_alert") or "HIGH").strip().upper()

    if min_band in _BAND_ORDER and risk.band.value in _BAND_ORDER:
        if _BAND_ORDER.index(risk.band.value) >= _BAND_ORDER.index(min_band):
            return True, f"band {risk.band.value} at or above {min_band}"

    return False, f"score {risk.score:.1f} below threshold {minimum:.1f}"


def severity_for_rule_severity(
    value: Any,
    *,
    policy: Optional[Mapping[str, Any]] = None,
) -> Severity:
    """
    Map a rule-engine severity token onto the persisted `Severity` enum.
    """
    scoring = policy or get_scoring_policy()
    mapping = scoring.get("rule_severity_to_indicator_severity") or {}
    token = str(getattr(value, "value", value) or "").strip().lower()
    resolved = str(mapping.get(token, "")).strip().upper()

    if resolved in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return Severity(resolved)

    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.LOW,
    }.get(token, Severity.LOW)


def get_risk_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the risk fusion service.
    """
    try:
        scoring = get_scoring_policy()
        weights = {
            name: (spec or {}).get("weight")
            for name, spec in ((scoring.get("fusion") or {}).get("components") or {}).items()
            if isinstance(spec, Mapping)
        }
        score_version = scoring.get("score_version")
        prohibited = list(scoring.get("prohibited_uses") or [])
    except Exception:
        weights = {}
        score_version = None
        prohibited = []

    return {
        "service": "muleguard.backend.services.risk",
        "version": RISK_SERVICE_VERSION,
        "score_version": score_version,
        "score_type": "investigative_priority_score",
        "scale": {"min": 0, "max": 100},
        "component_weights": weights,
        "missing_component_policy": "renormalise_available_weights",
        "prohibited_uses": prohibited,
        "notes": [
            "A missing component lowers confidence, never risk.",
            "The model component is weighted below the rule component so an "
            "explainable signal always dominates an opaque one.",
            "An escalate_to_human rule effect raises an alert regardless of score.",
        ],
    }
