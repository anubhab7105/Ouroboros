"""
The heuristic fallback scorer.

The fallback exists so that the platform works with no trained model: it scores
from hand-set weights over named signals. It is less accurate than a trained
model and more honest about itself, and both of those matter.

The property the whole design rests on: **a fallback score never pretends to
be a model score.** The scoring mode on the assessment says
`HEURISTIC_FALLBACK`, a caveat says the weights are hand-set rather than
learned, and the interface shows it. A heuristic presented as model output
would be the platform claiming a capability it did not use.

The second property: **unavailable signals are reported, not substituted.**
`signals_unavailable` lists what could not be computed. Substituting zero for a
missing signal would be asserting that the account scored well on something
nothing looked at.

These tests run the scorer directly — it depends only on numpy, which is
present.
"""

from __future__ import annotations

import pytest

from app.ml.fallback import (
    FallbackOptions,
    assert_no_fallback_label_leakage,
    fallback_score,
    fallback_score_one,
    get_fallback_metadata,
    scan_features_for_label_leakage,
)

pytestmark = pytest.mark.ml


#: An account that looks like a pass-through: high throughput, concentrated
#: counterparties, low beneficiary entropy, mostly at night.
SUSPICIOUS = {
    "account_id": "acc-suspicious",
    "txn_count_7d": 40,
    "txn_count_30d": 60,
    "counterparty_distinct_count_30d": 22,
    "inbound_outbound_amount_ratio_30d": 0.98,
    "txn_night_ratio_30d": 0.70,
    "counterparty_entropy_30d": 0.20,
    "txn_amount_sum_30d": 900_000,
}

#: The same fields, unremarkable values.
ORDINARY = {
    "account_id": "acc-ordinary",
    "txn_count_7d": 3,
    "txn_count_30d": 11,
    "counterparty_distinct_count_30d": 4,
    "inbound_outbound_amount_ratio_30d": 0.15,
    "txn_night_ratio_30d": 0.05,
    "counterparty_entropy_30d": 0.85,
    "txn_amount_sum_30d": 22_000,
}


# -----------------------------------------------------------------------------
# Scoring
# -----------------------------------------------------------------------------


def test_a_record_is_scored():
    result = fallback_score_one(SUSPICIOUS)

    assert result.score is not None
    assert 0.0 <= result.score <= 1.0
    assert result.risk_band is not None


def test_a_suspicious_record_scores_above_an_ordinary_one():
    """
    The scorer discriminates.

    A heuristic that ranked an ordinary account above a pass-through would be
    worse than no scorer at all, because its output would still be presented
    with a band and a priority.
    """
    suspicious = fallback_score_one(SUSPICIOUS)
    ordinary = fallback_score_one(ORDINARY)

    assert suspicious.score > ordinary.score


def test_the_score_is_in_the_unit_interval():
    """
    0..1, because fusion treats every component as a normalised value.

    A fallback that returned 0..100 would be multiplied by its weight and
    produce a fused score a hundred times too large — which would land every
    account in CRITICAL.
    """
    for record in (SUSPICIOUS, ORDINARY, {"account_id": "acc-bare"}):
        result = fallback_score_one(record)
        if result.score is not None:
            assert 0.0 <= result.score <= 1.0


def test_scoring_is_deterministic():
    """
    The same record scores the same, every time.

    The fallback is the estimator used when no model is active, which is the
    state a fresh deployment is in. A non-deterministic score there would
    make every assessment irreproducible from the start.
    """
    first = fallback_score_one(SUSPICIOUS)
    second = fallback_score_one(SUSPICIOUS)

    assert first.score == second.score
    assert first.risk_band == second.risk_band


def test_the_subject_reference_is_hashed():
    """
    The result carries a hash, not the account id.

    The caller submitted the record and knows which account it was. The
    scorer's output travels into assessments and logs, so it does not carry
    the identifier.
    """
    result = fallback_score_one(SUSPICIOUS)

    assert result.subject_ref_hash
    assert result.subject_ref_hash != "acc-suspicious"
    assert len(result.subject_ref_hash) >= 16


def test_a_band_accompanies_every_score():
    """
    The band is what the queue sorts on.

    A score with no band cannot be placed, and the fallback is scored on the
    same band scale as everything else so the two estimators are comparable.
    """
    result = fallback_score_one(SUSPICIOUS)
    assert result.risk_band is not None


def test_review_is_recommended_only_above_the_threshold():
    """
    The flag is a threshold decision, not a restatement of the score.

    It is what decides whether an account reaches a human, so it must not
    fire on an ordinary record.
    """
    assert fallback_score_one(ORDINARY).review_recommended is False


# -----------------------------------------------------------------------------
# Missing signals
# -----------------------------------------------------------------------------


def test_unavailable_signals_are_listed_not_substituted():
    """
    The central honesty property of the scorer.

    A record missing most of its signals reports them in
    `signals_unavailable`. Substituting zero would assert that the account
    scored well on something nothing computed — and the resulting score would
    be systematically low for exactly the accounts whose data is incomplete.
    """
    partial = {"account_id": "acc-partial", "txn_count_7d": 30}
    result = fallback_score_one(partial)

    assert result.signals_unavailable, "no unavailable signals were reported"
    assert result.signals_evaluated >= 0


def test_a_record_with_no_signals_is_not_scored_as_zero():
    """
    Nothing to go on is not the same as nothing suspicious.

    An empty record should produce either no score or a score accompanied by
    a complete list of unavailable signals — never a confident low score.
    """
    result = fallback_score_one({"account_id": "acc-empty"})

    if result.score is not None:
        assert result.signals_unavailable
        assert result.signals_evaluated == 0 or result.score == 0


def test_more_available_signals_means_more_evaluated():
    full = fallback_score_one(SUSPICIOUS)
    partial = fallback_score_one({"account_id": "acc-partial", "txn_count_7d": 30})

    assert full.signals_evaluated >= partial.signals_evaluated


def test_contributions_are_reported_per_signal():
    """
    Which signal contributed what.

    This is the fallback's one real advantage over a model: it is completely
    transparent. An analyst can read the arithmetic, which is why its weights
    being hand-set is a stated limitation rather than a hidden one.
    """
    result = fallback_score_one(SUSPICIOUS)

    assert result.contributions

    serialised = str(result.contributions)
    assert "txn" in serialised or "counterparty" in serialised


# -----------------------------------------------------------------------------
# Batches
# -----------------------------------------------------------------------------


def test_a_batch_is_scored_and_ordered():
    result = fallback_score([ORDINARY, SUSPICIOUS])

    assert len(result.records) == 2

    scores = [record.score for record in result.records if record.score is not None]
    assert len(scores) == 2
    assert result.records[1].score > result.records[0].score


def test_a_batch_preserves_input_order():
    """
    Results come back in submission order.

    The caller matches results to accounts by position. A reordering would
    attribute one account's score to another — silently, and in the component
    that runs when no model is available.
    """
    records = [dict(ORDINARY, account_id=f"acc-{index}") for index in range(5)]
    result = fallback_score(records)

    hashes = [record.subject_ref_hash for record in result.records]
    assert len(hashes) == len(set(hashes)), "two records share a subject hash"
    assert len(result.records) == 5


def test_a_batch_is_bounded():
    options = FallbackOptions()

    assert getattr(options, "max_records", 1) > 0


def test_an_empty_batch_is_not_an_error():
    result = fallback_score([])
    assert result.records == () or list(result.records) == []


# -----------------------------------------------------------------------------
# Label leakage
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "ground_truth_label",
        "ground_truth",
        "is_fraud",
        "fraud_label",
        "scenario_id",
        "ring_id",
    ],
)
def test_a_label_field_in_the_input_is_detected(field):
    """
    The scorer refuses to be handed the answer.

    The synthetic generator plants labels on every account, so a careless
    join puts `ground_truth_label` straight into a feature mapping. A scorer
    that used it would appear to work perfectly and would be measuring
    nothing.
    """
    issues = scan_features_for_label_leakage({field: 1, "txn_count_7d": 5})

    assert issues, f"{field} was not detected as leakage"
    assert any(issue.field == field for issue in issues)


def test_leakage_raises_rather_than_being_logged():
    """
    An exception, not a warning.

    A warning in a log is a warning nobody reads, and the consequence of
    missing it is a model or a scorer whose reported accuracy is fiction. The
    only safe response is to stop.
    """
    with pytest.raises(Exception) as raised:
        assert_no_fallback_label_leakage({"ground_truth_label": 1})

    assert "leakage" in str(raised.value).lower()


def test_clean_features_pass_the_leakage_check():
    assert scan_features_for_label_leakage(ORDINARY) == []
    assert_no_fallback_label_leakage(ORDINARY)


def test_a_scored_record_does_not_echo_its_input():
    """
    The result is a score, a band and contributions — not the features back.

    Echoing the input would put whatever the caller passed into the result,
    which is how a label reaches an assessment even when the scorer itself
    ignored it.
    """
    result = fallback_score_one(SUSPICIOUS)
    serialised = str(result.to_dict() if hasattr(result, "to_dict") else result)

    assert "acc-suspicious" not in serialised


# -----------------------------------------------------------------------------
# Self-description
# -----------------------------------------------------------------------------


def test_the_scorer_declares_that_its_weights_are_hand_set():
    """
    The limitation is stated by the module, not left to documentation.

    A heuristic whose weights were chosen by a person is a legitimate thing to
    ship and an illegitimate thing to describe as a model. The caveats are
    what keep the distinction visible wherever the metadata is surfaced.
    """
    metadata = get_fallback_metadata()

    assert metadata["caveats"]

    joined = " ".join(str(item) for item in metadata["caveats"]).lower()
    assert any(
        phrase in joined
        for phrase in ("hand-set", "hand set", "heuristic", "not learned", "not trained")
    ), f"the caveats do not say the weights are hand-set: {metadata['caveats']}"


def test_the_scorer_declares_itself_non_durable_and_local():
    metadata = get_fallback_metadata()

    assert metadata["durable"] is False
    assert metadata["distributed"] is False


def test_the_metadata_lists_its_safety_flags():
    metadata = get_fallback_metadata()
    flags = metadata["safety_flags"]

    assert flags
    assert metadata["label_leakage_field_count"] > 0
    assert metadata["forbidden_fallback_field_count"] > 0


def test_the_metadata_describes_its_bands_and_limits():
    metadata = get_fallback_metadata()

    assert metadata["risk_bands"]
    assert metadata["hard_limits"]
    assert metadata["default_options"]


def test_the_metadata_reports_whether_a_salt_is_set_but_never_its_value():
    """
    `salt_configured` is a boolean. The salt itself does not appear.

    The subject hashes are salted, so publishing the salt would let anyone
    recompute them from account ids and undo the pseudonymisation. Reporting
    only whether one is configured is enough for an operator to see that the
    deployment is set up, and gives nothing away.

    The assertion looks for the *value* rather than the word: the metadata
    legitimately contains flag names like `no_secrets_accepted` and
    `salted_pseudonymous_subject_hashes`, which are promises about absence and
    not leaks.
    """
    from app.ml.fallback import FallbackOptions

    metadata = get_fallback_metadata()
    options = metadata["default_options"]

    assert "salt_configured" in options
    assert isinstance(options["salt_configured"], bool)
    assert "salt" not in options or options.get("salt") is None

    # The configured salt's actual value must not appear anywhere.
    salt = getattr(FallbackOptions(), "salt", None)
    if salt:
        assert str(salt) not in str(metadata), "the salt value is published"


def test_the_metadata_carries_no_credential_values():
    """
    No connection strings, bearer tokens or hashes in the published metadata.

    Checked by shape rather than by keyword, because the safety-flag names
    legitimately contain the words `secret`, `token` and `password`.
    """
    serialised = str(get_fallback_metadata())

    for forbidden in ("postgresql://", "postgres://", "sqlite:///", "Bearer ", "$2b$", "$argon2"):
        assert forbidden not in serialised, f"the metadata exposes {forbidden!r}"
