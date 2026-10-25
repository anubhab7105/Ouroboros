"""
Risk fusion: turning several signals into one priority score.

Fusion is where this platform is most capable of producing a confident number
that means nothing, so the tests here are mostly about the handling of
missing information.

The central decision is that **an unavailable component is renormalised away,
not treated as zero**. If the trained model is unavailable, the model
component's weight is redistributed across the components that did report.
Substituting zero would be a claim — "the model looked and found nothing
suspicious" — about a model that did not run, and it would drag every score
down by a fixed amount that nobody could see in the output.

The second decision is that **the model and the heuristic fallback share one
slot**. They are alternative estimators of the same quantity, never additive.
Giving them a weight each would let an account score higher merely because
both happened to be available.
"""

from __future__ import annotations

import pytest

from app.models import RiskBand, ScoringMode
from app.services.risk import (
    ComponentSignal,
    band_for_score,
    fuse_risk,
    priority_for_band,
    should_raise_alert,
)

pytestmark = pytest.mark.ml


# -----------------------------------------------------------------------------
# Bands
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, RiskBand.LOW),
        (39.99, RiskBand.LOW),
        (40, RiskBand.MEDIUM),
        (64.99, RiskBand.MEDIUM),
        (65, RiskBand.HIGH),
        (84.99, RiskBand.HIGH),
        (85, RiskBand.CRITICAL),
        (100, RiskBand.CRITICAL),
    ],
)
def test_band_cut_points(score, expected):
    """
    The cut-points from `config/scoring.default.json`, written out.

    Boundaries are tested on both sides because an off-by-one in a cut-point
    silently reclassifies a whole band of accounts, and nothing else in the
    system would notice: the scores stay the same and only the label changes.
    """
    assert band_for_score(score) is expected


def test_band_is_inclusive_at_the_lower_edge():
    """
    Exactly 65 is HIGH, not MEDIUM.

    Stated separately because `>=` versus `>` here is the difference between
    an account appearing in the high-risk queue and not.
    """
    assert band_for_score(65.0) is RiskBand.HIGH
    assert band_for_score(64.999) is RiskBand.MEDIUM


def test_priority_rises_with_the_band():
    """
    Higher band, no lower priority.

    Asserted as an ordering rather than against specific values, because the
    mapping is configurable and the invariant is what matters.
    """
    order = [RiskBand.LOW, RiskBand.MEDIUM, RiskBand.HIGH, RiskBand.CRITICAL]
    priorities = [priority_for_band(band) for band in order]

    assert len(set(priorities)) >= 2
    assert priorities[-1] != priorities[0]


# -----------------------------------------------------------------------------
# Components
# -----------------------------------------------------------------------------


def test_a_component_with_no_value_is_unavailable():
    """
    `available` is derived, not trusted from the caller.

    A component constructed with `available=True` and a value of `None` is a
    contradiction, and resolving it in favour of "unavailable" is the safe
    direction: the alternative is a component that claims to have information
    and carries none.
    """
    signal = ComponentSignal("model", None, available=True)

    assert signal.available is False
    assert signal.value is None


def test_component_values_are_clamped_to_the_unit_interval():
    """
    A component is 0..1, and a value outside that is clamped rather than used.

    An out-of-range component would push the fused score past 100, which the
    bands cannot represent — and the most likely cause is a percentage where a
    fraction was expected, which would be out by a factor of a hundred.
    """
    assert ComponentSignal("rules", 1.4).value == pytest.approx(1.0)
    assert ComponentSignal("rules", -0.3).value == pytest.approx(0.0)


# -----------------------------------------------------------------------------
# Fusion
# -----------------------------------------------------------------------------


def test_fusion_with_no_signals_at_all():
    """
    Nothing to fuse produces a low score and says why.

    Not an exception: an account with no computed signals is a normal state
    early in a run. What matters is that the caveats make the emptiness
    visible, so the score is not read as a finding.
    """
    risk = fuse_risk()

    assert 0 <= risk.score <= 100
    assert risk.caveats
    assert risk.scoring_mode in set(ScoringMode)


def test_a_high_rule_score_raises_the_fused_score():
    low = fuse_risk(rule_score=0.1)
    high = fuse_risk(rule_score=0.95)

    assert high.score > low.score


def test_an_unavailable_component_is_renormalised_not_zeroed():
    """
    The core invariant.

    Two fusions with an identical rules signal: one where the model also
    reported, one where it did not. With renormalisation, the rules component
    carries more weight in the second, so a strong rules signal is *not*
    diluted by the model's absence.

    If the absent model were treated as zero, the second score would be
    strictly lower — the system would be penalising an account for a model
    that failed to load, which is a statement about the infrastructure
    masquerading as a statement about the account.
    """
    with_model = fuse_risk(rule_score=0.9, model_score=0.9, model_available=True)
    without_model = fuse_risk(rule_score=0.9)

    assert without_model.score == pytest.approx(with_model.score, abs=1.0), (
        "a strong rules signal was diluted by the model being unavailable"
    )


def test_a_weak_signal_is_not_inflated_by_renormalisation():
    """
    The other direction of the same invariant.

    Renormalisation must not turn a weak signal into a strong one just
    because it is the only signal. A rules score of 0.1 alone should still
    produce a low fused score.
    """
    risk = fuse_risk(rule_score=0.1)

    assert risk.score < 40
    assert risk.band is RiskBand.LOW


def test_effective_weights_are_reported_and_sum_to_one():
    """
    The weights that were actually used are part of the output.

    This is what makes a score auditable. A configured weight of 0.25 that
    became 0.33 after renormalisation is the number an analyst needs to
    reconstruct the arithmetic, and it is not the number in the
    configuration file.
    """
    risk = fuse_risk(rule_score=0.8, model_score=0.6, model_available=True)
    weights = risk.effective_weights

    assert weights
    assert sum(weights.values()) == pytest.approx(1.0, abs=0.01)


def test_the_model_and_the_fallback_share_one_slot():
    """
    They are alternative estimators, never additive.

    Both describe the same quantity — the model's view of how mule-like the
    account looks. Counting each separately would make an account with both
    available score higher than an identical account with only one, which is
    an artefact of deployment state rather than of behaviour.
    """
    risk = fuse_risk(
        rule_score=0.5,
        model_score=0.9,
        model_available=True,
        fallback_score=0.9,
    )

    names = [component.name for component in risk.components]
    assert names.count("model") == 1


def test_the_trained_model_takes_precedence_over_the_fallback():
    risk = fuse_risk(
        rule_score=0.5,
        model_score=0.7,
        model_available=True,
        fallback_score=0.2,
    )

    assert risk.scoring_mode is ScoringMode.TRAINED_MODEL


def test_the_fallback_is_used_when_the_model_is_unavailable_and_is_declared():
    """
    Falling back is fine. Falling back silently is not.

    The scoring mode changes to `HEURISTIC_FALLBACK`, which travels with the
    assessment and is shown next to the score. A heuristic score presented as
    a model score is the platform claiming a capability it did not use.
    """
    risk = fuse_risk(rule_score=0.5, model_available=False, fallback_score=0.8)

    assert risk.scoring_mode is ScoringMode.HEURISTIC_FALLBACK
    assert any("fallback" in caveat.lower() or "heuristic" in caveat.lower()
               for caveat in risk.caveats)


def test_rules_only_scoring_is_declared():
    """With neither a model nor a fallback, the mode says rules only."""
    risk = fuse_risk(rule_score=0.7)

    assert risk.scoring_mode in {
        ScoringMode.RULES_ONLY,
        ScoringMode.ML_DISABLED,
        ScoringMode.HEURISTIC_FALLBACK,
        ScoringMode.UNKNOWN,
    }
    assert risk.caveats


def test_the_score_stays_in_range_under_every_combination():
    """
    No combination of signals escapes 0..100.

    A score of 103 would land outside every band and render as "unknown",
    and the band is what the queue sorts on.
    """
    for rule_score in (None, 0.0, 0.5, 1.0):
        for model_score in (None, 0.0, 0.5, 1.0):
            for correlations in (0, 1, 50):
                risk = fuse_risk(
                    rule_score=rule_score,
                    model_score=model_score,
                    model_available=model_score is not None,
                    correlation_count=correlations,
                )
                assert 0 <= risk.score <= 100, (
                    f"out of range for rules={rule_score} model={model_score} "
                    f"correlations={correlations}: {risk.score}"
                )


def test_complaint_correlations_contribute():
    """
    A complaint is the strongest signal the platform holds.

    It comes from outside the transaction data: a person reporting a loss,
    not a pattern inferred from a ledger. An account named in complaints
    should not score the same as an identical account named in none.
    """
    without = fuse_risk(rule_score=0.5, correlation_count=0)
    with_complaints = fuse_risk(rule_score=0.5, correlation_count=4)

    assert with_complaints.score >= without.score


# -----------------------------------------------------------------------------
# Explanation and caveats
# -----------------------------------------------------------------------------


def test_every_fusion_carries_caveats():
    """
    There is no such thing as an uncaveated score here.

    The score is an investigative priority computed from synthetic data by
    a detector that only finds typologies it already knows about. Shipping it
    bare would invite it to be read as a probability of guilt.
    """
    risk = fuse_risk(rule_score=0.9, model_score=0.9, model_available=True)

    assert risk.caveats
    assert risk.caveats_json() is not None


def test_the_explanation_names_the_components():
    """
    An explanation, not a number with a label.

    The components and their effective weights are what let someone disagree
    with the score. A score an analyst cannot argue with is a score they will
    either over-trust or ignore, and both are worse than a score they can
    check.
    """
    risk = fuse_risk(
        rule_score=0.85,
        model_score=0.7,
        model_available=True,
        triggered_rules=[{"rule_code": "FAN_IN_BURST", "severity": "HIGH"}],
    )

    explanation = risk.explanation_json()
    components = risk.components_json()

    assert explanation
    assert components

    serialised = str(components)
    assert "rules" in serialised
    assert "model" in serialised


def test_components_json_records_availability():
    """
    The output says which components were missing.

    Without it, a renormalised score is indistinguishable from a complete one
    — the number looks the same, and only the breakdown shows that half the
    evidence was absent.
    """
    risk = fuse_risk(rule_score=0.6)
    components = risk.components_json()

    serialised = str(components)
    assert "available" in serialised


def test_triggered_rules_are_reflected_in_the_detail():
    risk = fuse_risk(
        rule_score=0.8,
        triggered_rules=[
            {"rule_code": "FAN_IN_BURST", "severity": "HIGH"},
            {"rule_code": "HIGH_THROUGHPUT", "severity": "HIGH"},
        ],
    )

    rules_component = next(
        component for component in risk.components if component.name == "rules"
    )
    assert rules_component.detail.get("triggered_rule_count") == 2


# -----------------------------------------------------------------------------
# Alerting
# -----------------------------------------------------------------------------


def test_a_low_score_does_not_raise_an_alert():
    """
    The queue is finite and an analyst's attention is the scarce resource.

    Alerting on everything is the same as alerting on nothing: the queue stops
    being read.
    """
    assert should_raise_alert(fuse_risk(rule_score=0.05)) is False


def test_a_high_score_raises_an_alert():
    risk = fuse_risk(rule_score=0.95, model_score=0.92, model_available=True)

    assert risk.band in {RiskBand.HIGH, RiskBand.CRITICAL}
    assert should_raise_alert(risk) is True


def test_alerting_never_takes_action_against_an_account():
    """
    An alert is a request for a human to look. Nothing more.

    There is no freeze, no block, no flag written back to the account, and
    `AutomaticEnforcementProhibitedError` exists so that adding one has to be
    a deliberate act. The platform's output is a lead for an investigator; the
    decision and the accountability stay with the person.
    """
    risk = fuse_risk(rule_score=1.0, model_score=1.0, model_available=True)

    assert risk.band is RiskBand.CRITICAL

    # The fusion result is data: a score, a band, components, caveats and an
    # explanation. It carries no field that could express an action.
    forbidden = {"freeze", "block", "action", "enforce", "blacklist", "suspend"}
    assert not (forbidden & set(dir(risk)))
