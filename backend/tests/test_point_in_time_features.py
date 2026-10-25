"""
Point-in-time correctness.

Every feature vector is computed *as of* an instant, and sees only data
strictly before it. That single rule is what makes a backfilled assessment
defensible, and breaking it is the most consequential silent failure in the
platform.

Why it matters concretely. Suppose an account is assessed as of 1 October and
the assessment is used to justify an investigation. If the features were
computed over everything available at the time of *computation* — say
20 November — then the score reflects seven weeks of activity the investigator
could not have seen, including activity that may have happened *because* of the
investigation. The score is then unreproducible and indefensible: nobody can
say what it was based on, and re-running it gives a different answer.

The two timestamps that keep this straight:

- **`as_of`** — the instant assessed. Features see only data before it.
- **`scored_at`** — when the computation ran, usually later.

`TemporalCorrectnessViolationError` exists for the case where the rule is
broken. These tests exercise the real builder, which depends only on numpy.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.ml.features import build_feature_vectors

pytestmark = pytest.mark.features


#: Three instants: before the early activity, between the two bursts, and
#: after everything.
EARLY = datetime(2025, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
MIDDLE = datetime(2025, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
LATE = datetime(2025, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def _iso(moment):
    return moment.isoformat()


def _account(account_id, created_at=None):
    return {
        "id": account_id,
        "account_type": "INDIVIDUAL",
        "status": "ACTIVE",
        "created_at": _iso(created_at or (EARLY - timedelta(days=365))),
    }


def _transfer(index, sender, receiver, when, amount=24_000):
    return {
        "id": f"t-{index}",
        "reference": f"T-{index}",
        "sender_account_id": sender,
        "receiver_account_id": receiver,
        "amount": amount,
        "currency": "INR",
        "status": "COMPLETED",
        "channel": "UPI",
        "occurred_at": _iso(when),
    }


def _two_bursts():
    """
    Three transfers just before MIDDLE, nine just before LATE.

    Built so that an `as_of` of MIDDLE must see three and an `as_of` of LATE
    must see twelve — and so that a builder ignoring `as_of` returns twelve
    for both, which is the failure this module exists to catch.
    """
    accounts = [_account("acc-0")] + [_account(f"acc-{i}") for i in range(1, 13)]

    transactions = [
        _transfer(index, f"acc-{index + 1}", "acc-0", MIDDLE - timedelta(hours=index + 1))
        for index in range(3)
    ]
    transactions += [
        _transfer(
            10 + index,
            f"acc-{index + 4}",
            "acc-0",
            LATE - timedelta(hours=index + 1),
        )
        for index in range(9)
    ]

    return {"accounts": accounts, "transactions": transactions}


def _features_at(dataset, moment, account_id="acc-0"):
    result = build_feature_vectors(dataset, [account_id], observation_time=moment)
    assert result.vectors, (
        f"no vector at {moment.isoformat()}: {[i.code for i in result.issues]}"
    )
    return result.vectors[0].features


# -----------------------------------------------------------------------------
# The core rule
# -----------------------------------------------------------------------------


def test_a_vector_sees_only_activity_before_its_as_of():
    """
    The central test of the whole module.

    Three transfers precede MIDDLE and twelve precede LATE. If the builder
    ignored `as_of` it would return twelve for both — which is exactly what a
    naive implementation does, because the dataset it is handed contains
    everything.
    """
    dataset = _two_bursts()

    at_middle = _features_at(dataset, MIDDLE)
    at_late = _features_at(dataset, LATE)

    assert at_middle["txn_count_30d"] == 3, (
        f"as_of MIDDLE saw {at_middle['txn_count_30d']} transfers, expected 3 — "
        "later activity leaked into a point-in-time vector"
    )
    assert at_late["txn_count_30d"] == 9


def test_a_vector_before_any_activity_sees_nothing():
    """
    Zero, from a complete vector — not a failure and not nulls everywhere.

    An account assessed before it did anything is a real case: it is what the
    new-account rules are about.
    """
    features = _features_at(_two_bursts(), EARLY)

    assert features["txn_count_7d"] == 0
    assert features["txn_count_30d"] == 0
    assert features["counterparty_distinct_count_30d"] == 0


def test_moving_as_of_forward_never_loses_history():
    """
    Later vectors see at least the long-window activity of earlier ones.

    Checked on the 90-day window, which is wide enough to contain both
    bursts. A later `as_of` seeing *fewer* transfers in a window that covers
    the same period would mean the cutoff is being applied as a floor rather
    than a ceiling.
    """
    dataset = _two_bursts()

    middle = _features_at(dataset, MIDDLE)
    late = _features_at(dataset, LATE)

    middle_90 = middle.get("txn_count_90d")
    late_90 = late.get("txn_count_90d")

    if middle_90 is not None and late_90 is not None:
        assert late_90 >= middle_90


def test_distinct_counterparties_respect_the_cutoff():
    """
    The fan-in signal is point-in-time too.

    Three payers before MIDDLE, nine more after. A collection account's
    distinctness is the whole signal, so a cutoff applied to the count but not
    to the distinct set would be the subtlest possible version of this bug.
    """
    dataset = _two_bursts()

    assert _features_at(dataset, MIDDLE)["counterparty_distinct_count_30d"] == 3
    assert _features_at(dataset, LATE)["counterparty_distinct_count_30d"] == 9


def test_amount_totals_respect_the_cutoff():
    from decimal import Decimal

    dataset = _two_bursts()

    middle = _features_at(dataset, MIDDLE)
    late = _features_at(dataset, LATE)

    assert Decimal(str(middle["txn_amount_sum_30d"])) == Decimal("72000")
    assert Decimal(str(late["txn_amount_sum_30d"])) == Decimal("216000")


def test_a_transfer_exactly_at_the_cutoff_is_excluded():
    """
    The window is strictly before `as_of`.

    "Strictly" is the part that matters. A transfer at exactly the assessment
    instant is activity that had not finished happening when the assessment
    was taken, and including it makes the boundary depend on clock resolution.
    """
    boundary = MIDDLE
    dataset = {
        "accounts": [_account("acc-0"), _account("acc-1")],
        "transactions": [_transfer(1, "acc-1", "acc-0", boundary)],
    }

    at_boundary = _features_at(dataset, boundary)
    just_after = _features_at(dataset, boundary + timedelta(seconds=1))

    assert at_boundary["txn_count_30d"] == 0, (
        "a transfer at exactly as_of was included"
    )
    assert just_after["txn_count_30d"] == 1


def test_account_age_is_computed_at_the_cutoff_not_now():
    """
    Age is as of the assessment instant.

    An account 30 days old on 1 October is 80 days old on 20 November. A
    vector dated to October that reported 80 would be feeding the
    new-account rules a figure from the future — and the rule most sensitive
    to age is the one about accounts that transact soon after opening.
    """
    opened = MIDDLE - timedelta(days=30)

    dataset = {
        "accounts": [_account("acc-0", created_at=opened), _account("acc-1")],
        "transactions": [
            _transfer(1, "acc-1", "acc-0", MIDDLE - timedelta(days=1))
        ],
    }

    at_middle = _features_at(dataset, MIDDLE)
    at_late = _features_at(dataset, LATE)

    assert at_middle["account_age_days"] == 30
    assert at_late["account_age_days"] > 30


def test_an_account_not_yet_opened_at_the_cutoff_is_handled():
    """
    An account created after `as_of` did not exist then.

    Reporting a negative age would be a nonsense value that would still pass
    through every arithmetic rule. Either the account is rejected or the age
    is non-negative; both are defensible, a negative is not.
    """
    dataset = {
        "accounts": [_account("acc-0", created_at=LATE)],
        "transactions": [],
    }

    result = build_feature_vectors(dataset, ["acc-0"], observation_time=MIDDLE)

    if result.vectors:
        age = result.vectors[0].features["account_age_days"]
        assert age is None or age >= 0, f"account age at as_of was {age}"
    else:
        assert result.rejected_accounts or result.issues


# -----------------------------------------------------------------------------
# Reproducibility
# -----------------------------------------------------------------------------


def test_the_same_as_of_gives_the_same_vector_whenever_it_is_computed():
    """
    The property the whole contract exists to deliver.

    A vector for 1 October must be identical whether it is computed on
    1 October or in six months. Without this, an assessment cannot be
    reproduced and therefore cannot be defended — and re-running an
    investigation's scoring would quietly give a different answer.
    """
    dataset = _two_bursts()

    first = _features_at(dataset, MIDDLE)
    second = _features_at(dataset, MIDDLE)

    assert first == second


def test_adding_later_data_does_not_change_an_earlier_vector():
    """
    The strongest form of the same property.

    This is what "point-in-time" actually buys: the October vector is
    unaffected by November's activity. A re-run next year over a dataset that
    has grown by a million rows must produce the same October figures, or
    every historical assessment silently changes.
    """
    before = _features_at(_two_bursts(), MIDDLE)

    grown = _two_bursts()
    grown["accounts"].extend(_account(f"acc-new-{index}") for index in range(5))
    grown["transactions"].extend(
        _transfer(
            500 + index,
            f"acc-new-{index}",
            "acc-0",
            LATE + timedelta(days=index + 1),
        )
        for index in range(5)
    )

    after = _features_at(grown, MIDDLE)

    assert after == before, (
        "adding activity after as_of changed a point-in-time vector"
    )


def test_two_different_as_of_instants_give_different_vectors():
    """
    The cutoff is actually doing something.

    Without this, the reproducibility tests above would pass for a builder
    that ignored `as_of` entirely and returned the same vector always.
    """
    dataset = _two_bursts()

    assert _features_at(dataset, MIDDLE) != _features_at(dataset, LATE)


def test_the_observation_time_is_recorded_on_the_result():
    """
    The result says which instant it was computed for.

    A vector whose `as_of` is not recorded cannot be filed as a snapshot, and
    the `as_of` / `scored_at` distinction on the assessment depends on this
    value being carried through rather than re-derived.
    """
    result = build_feature_vectors(_two_bursts(), ["acc-0"], observation_time=MIDDLE)

    assert result.observation_time is not None
    assert result.observation_time == MIDDLE


def test_a_naive_observation_time_is_treated_as_utc():
    """
    Timestamps are UTC end to end.

    A naive datetime interpreted as local time would shift the cutoff by the
    server's offset, which would be a point-in-time violation that only
    appears outside UTC — the hardest kind to notice and the easiest to ship.
    """
    naive = MIDDLE.replace(tzinfo=None)

    aware_result = build_feature_vectors(
        _two_bursts(), ["acc-0"], observation_time=MIDDLE
    )
    naive_result = build_feature_vectors(
        _two_bursts(), ["acc-0"], observation_time=naive
    )

    assert naive_result.vectors
    assert naive_result.vectors[0].features == aware_result.vectors[0].features


# -----------------------------------------------------------------------------
# The model-side contract
# -----------------------------------------------------------------------------


def test_the_snapshot_and_assessment_tables_both_record_as_of():
    """
    The contract is in the schema, not only in the builder.

    `FeatureSnapshot.as_of` is the instant the features describe.
    `ModelAssessment` carries both `as_of` and `scored_at`, so an assessment
    re-run today over last month's data is correctly dated to last month.
    Collapsing them into one column would make every backfilled assessment
    look as though it had seen data it could not have.
    """
    from app.models import FeatureSnapshot, ModelAssessment

    assert "as_of" in FeatureSnapshot.__table__.columns

    assessment_columns = ModelAssessment.__table__.columns
    assert "as_of" in assessment_columns
    assert "scored_at" in assessment_columns


def test_a_temporal_violation_has_its_own_exception():
    """
    The failure is named, so it can be raised rather than logged.

    A point-in-time violation is not a validation error and not a bad
    request: it is the platform having computed something it cannot defend.
    `TemporalCorrectnessViolationError` is a server error for that reason.
    """
    from app.exceptions import TemporalCorrectnessViolationError

    error = TemporalCorrectnessViolationError()

    assert error.status_code >= 500
    assert "temporal" in error.message.lower() or "point-in-time" in error.message.lower()


def test_label_leakage_and_temporal_leakage_are_separate_failures():
    """
    Two different exceptions, because they are two different mistakes.

    Label leakage is training on the answer. Temporal leakage is training on
    the future. Both produce excellent metrics and a useless model, and
    conflating them in one error would make the cause unclear exactly when it
    needs to be clear.
    """
    from app.exceptions import (
        LabelLeakageDetectedError,
        TemporalCorrectnessViolationError,
    )

    assert LabelLeakageDetectedError is not TemporalCorrectnessViolationError
    assert LabelLeakageDetectedError().status_code >= 500
    assert TemporalCorrectnessViolationError().status_code >= 500


def test_the_feature_catalogue_declares_every_window():
    """
    A feature named `_30d` says 30 days in its metadata.

    The name is a convention; the metadata is the contract. If they disagree,
    every explanation that quotes a window is wrong — and the window is the
    part an analyst is most likely to repeat out loud.
    """
    from app.ml.feature_schema import get_feature_spec, list_feature_names

    for name in list_feature_names():
        if not name.endswith(("_7d", "_30d", "_90d")):
            continue

        spec = get_feature_spec(name)
        assert spec is not None, name
        assert getattr(spec, "window", None) is not None, (
            f"{name} is windowed by name but declares no window"
        )
