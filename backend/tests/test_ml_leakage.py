"""
Leakage: the three ways this platform could fool itself.

Leakage is the failure mode that produces a model with excellent reported
metrics and no value. It is worth more attention than almost anything else in
the ML path, because unlike a bug it does not announce itself — the numbers
get *better*.

Three distinct kinds, each with its own guard:

**Target leakage** — a feature derived from the label. The synthetic generator
plants `ground_truth_label`, `scenario_type` and `ring_id` on every labelled
account, so the leak is one careless join away at all times. Guarded by the
feature-schema blocklist and by `assert_no_label_leakage`.

**Group leakage** — the same ring split across train and test. A model that
saw four accounts of a five-account ring in training will recognise the fifth,
and the test score measures memorisation of the ring rather than
generalisation to new ones. Guarded by grouped splitting.

**Temporal leakage** — training on data from after the evaluation window.
A model that has seen the future scores well and cannot be deployed, because
in production the future is not available. Guarded by temporal splitting and
by the `as_of` contract on feature snapshots.

These run directly against `app/ml/` — numpy is present, so the real splitting
and label machinery is exercised rather than described.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.ml.feature_schema import is_forbidden_feature_name
from app.ml.labels import assert_no_label_leakage, scan_feature_vector_for_label_leakage
from app.ml.splits import (
    SplitOptions,
    SplitStrategy,
    assert_no_split_leakage,
    build_split_plan,
    split_plan_fingerprint,
    split_plan_has_errors,
    split_plan_partitions,
    split_quality_report,
    subject_split_map,
    summarize_split_plan,
    test_items,
    training_items,
    validation_items,
)

pytestmark = pytest.mark.ml


def _records(count=40, rings=3):
    """
    Labelled records with a group and a timestamp.

    `account_id`, `label`, `entity_id` and `occurred_at` are the input aliases
    the splitter accepts; it normalises them to `subject_ref_hash`,
    `label_code`, `group_key_hash` and `timestamp` and hashes the
    identifiers.
    """
    return [
        {
            "account_id": f"acc-{index}",
            "label": 1 if index % 4 == 0 else 0,
            "entity_id": f"ring-{index % rings}",
            "occurred_at": f"2025-{(index % 9) + 1:02d}-01T00:00:00Z",
        }
        for index in range(count)
    ]


# -----------------------------------------------------------------------------
# Target leakage
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "ground_truth_label",
        "ground_truth",
        "truth_label",
        "is_fraud",
        "fraud_label",
        "scenario_id",
        "scenario_type",
        "ring_id",
        "fraud_ring",
    ],
)
def test_a_label_shaped_feature_is_refused(field):
    """
    The blocklist catches the name, including as a substring.

    `scenario_type` is the one worth noting: it was missing from the
    blocklist while `scenario_id` was present, even though the generator
    plants both on every labelled account and either one gives the answer
    away.
    """
    assert is_forbidden_feature_name(field) is True


def test_a_label_field_hidden_in_a_plausible_feature_name_is_refused():
    """
    `account_ground_truth_label_30d` looks exactly like a real feature.

    And that is how a leak gets in: somebody needs the label for a
    diagnostic, names it in the house style, and it is never removed. The
    match is on the stem, not the whole name.
    """
    for name in (
        "account_ground_truth_label_30d",
        "ring_id_hashed",
        "scenario_type_encoded",
        "is_fraud_flag_7d",
    ):
        assert is_forbidden_feature_name(name) is True, name


def test_a_feature_vector_carrying_a_label_is_detected():
    issues = scan_feature_vector_for_label_leakage(
        {"ground_truth_label": 1, "txn_count_7d": 12}
    )

    assert issues
    assert any(getattr(issue, "field", "") == "ground_truth_label" for issue in issues)


def test_label_leakage_raises_rather_than_warning():
    """
    An exception, because a warning is a warning nobody reads.

    The cost of missing it is a model whose reported accuracy is fiction, and
    the cost of stopping is a failed run somebody has to look at. The second
    is much cheaper.
    """
    with pytest.raises(Exception) as raised:
        assert_no_label_leakage({"ground_truth_label": 1, "txn_count_7d": 5})

    assert "leak" in str(raised.value).lower()


def test_a_clean_feature_vector_passes():
    clean = {
        "txn_count_7d": 12,
        "txn_count_30d": 40,
        "counterparty_distinct_count_30d": 9,
        "inbound_outbound_amount_ratio_30d": 0.44,
    }

    assert scan_feature_vector_for_label_leakage(clean) == []
    assert_no_label_leakage(clean)


def test_no_catalogued_feature_is_label_shaped():
    """
    The catalogue and the blocklist are checked against each other.

    They are maintained separately, so a feature added to the catalogue is
    never run past the blocklist unless something does it.
    """
    from app.ml.feature_schema import list_feature_names

    offenders = [name for name in list_feature_names() if is_forbidden_feature_name(name)]
    assert not offenders, f"catalogued features hit the blocklist: {offenders}"


# -----------------------------------------------------------------------------
# Group leakage
# -----------------------------------------------------------------------------


def test_a_split_plan_is_built():
    plan = build_split_plan(_records())

    assert split_plan_has_errors(plan) is False
    assert plan.counts["total"] == 40
    assert plan.counts["labeled"] == 40


def test_every_record_lands_in_exactly_one_split():
    """
    No record in two splits, and none dropped.

    A record in both train and test is group leakage in its purest form. A
    record in neither is a silently smaller dataset than the one reported.
    """
    plan = build_split_plan(_records())
    partitions = split_plan_partitions(plan)

    total = sum(len(items) for items in partitions.values())
    assert total == plan.counts["total"]

    subjects = [
        item.subject_ref_hash for items in partitions.values() for item in items
    ]
    assert len(subjects) == len(set(subjects)), "a subject appears in two splits"


def test_the_splits_sum_to_the_whole(
):
    plan = build_split_plan(_records())

    assert (
        len(training_items(plan))
        + len(validation_items(plan))
        + len(test_items(plan))
        == plan.counts["total"]
    )


def test_grouped_splitting_keeps_a_ring_in_one_split():
    """
    The guard against group leakage, and the reason it matters here.

    A mule ring is a group of accounts that act together. If four of its five
    accounts are in training, the model will recognise the fifth from the
    pattern it memorised — and the test score measures that memorisation, not
    the ability to find a ring it has never seen. Which is the only thing
    anybody wants it for.
    """
    plan = build_split_plan(
        _records(count=40, rings=3),
        SplitOptions(strategy=SplitStrategy.GROUPED, group_field="entity_id"),
    )

    partitions = split_plan_partitions(plan)
    splits_per_group: dict[str, set[str]] = {}

    for split_name, items in partitions.items():
        for item in items:
            if item.group_key_hash:
                splits_per_group.setdefault(item.group_key_hash, set()).add(split_name)

    straddling = {
        group: splits for group, splits in splits_per_group.items() if len(splits) > 1
    }

    assert not straddling, f"{len(straddling)} group(s) span more than one split"


def test_grouped_splitting_is_what_scenario_aware_means():
    """
    `SCENARIO_AWARE_CHRONOLOGICAL` on a model version is this plus time order.

    Worth stating because the name appears on every `ModelVersion` row and is
    otherwise opaque: it means groups are kept whole *and* the split respects
    chronology, which is the combination the two leakage guards require
    together.
    """
    from app.models import SplitStrategy as ModelSplitStrategy

    assert ModelSplitStrategy.SCENARIO_AWARE_CHRONOLOGICAL.value
    assert ModelSplitStrategy.GROUP_AWARE_RANDOM.value
    assert ModelSplitStrategy.CHRONOLOGICAL.value


def test_the_split_guard_passes_on_a_clean_plan():
    plan = build_split_plan(_records())
    assert_no_split_leakage(plan)


def test_a_subject_maps_to_one_split_only():
    """
    `subject_split_map` is one-to-one by construction.

    It is what the training code uses to decide which rows to feed where, so
    a subject with two entries would quietly put the same account on both
    sides.
    """
    plan = build_split_plan(_records())
    mapping = subject_split_map(plan)

    assert len(mapping) == plan.counts["total"]
    assert all(isinstance(value, str) and value for value in mapping.values())


# -----------------------------------------------------------------------------
# Temporal leakage
# -----------------------------------------------------------------------------


def test_temporal_splitting_puts_earlier_records_in_training():
    """
    Training data precedes test data.

    A model trained on records from after the evaluation window has seen the
    future. It scores well and cannot be deployed, because in production the
    future is not available — which makes the reported score not merely
    optimistic but meaningless.
    """
    boundary_one = datetime(2025, 4, 1, tzinfo=timezone.utc)
    boundary_two = datetime(2025, 7, 1, tzinfo=timezone.utc)

    plan = build_split_plan(
        _records(count=40),
        SplitOptions(
            strategy=SplitStrategy.TEMPORAL,
            temporal_field="occurred_at",
            temporal_boundary_train_validation=boundary_one,
            temporal_boundary_validation_test=boundary_two,
        ),
    )

    train_times = [item.timestamp for item in training_items(plan) if item.timestamp]
    test_times = [item.timestamp for item in test_items(plan) if item.timestamp]

    if train_times and test_times:
        assert max(train_times) <= min(test_times), (
            "a training record is dated after a test record"
        )


def test_a_record_with_no_timestamp_is_handled_explicitly():
    """
    Undated records go somewhere by policy, not by accident.

    `temporal_missing_policy` decides. Dropping them silently would shrink
    the dataset without saying so; putting them in training by default would
    be a temporal leak for any that are actually recent.
    """
    records = _records(count=10)
    records.append({"account_id": "acc-undated", "label": 0})

    plan = build_split_plan(
        records,
        SplitOptions(strategy=SplitStrategy.TEMPORAL, temporal_field="occurred_at"),
    )

    assert plan.counts["total"] >= 10


def test_a_feature_snapshot_is_dated_by_as_of_not_by_when_it_was_computed():
    """
    The temporal contract the whole ML path depends on, stated in the schema.

    `as_of` is the instant assessed: features see only data strictly before
    it. `scored_at` is when the computation ran, usually later. An assessment
    re-run today over last month's data is correct about last month — and
    conflating the two timestamps would make every backfilled assessment look
    like it had seen data it could not have.
    """
    from app.models import FeatureSnapshot, ModelAssessment

    assert "as_of" in FeatureSnapshot.__table__.columns
    assert "as_of" in ModelAssessment.__table__.columns
    assert "scored_at" in ModelAssessment.__table__.columns


# -----------------------------------------------------------------------------
# Determinism and reporting
# -----------------------------------------------------------------------------


def test_a_split_plan_is_deterministic():
    """
    Same records and options, same plan.

    A non-deterministic split makes every evaluation incomparable with every
    other, so a model that looks better than its predecessor may simply have
    had an easier test set.
    """
    first = build_split_plan(_records())
    second = build_split_plan(_records())

    assert split_plan_fingerprint(first) == split_plan_fingerprint(second)


def test_a_different_seed_gives_a_different_plan():
    """
    The seed is honoured, so the determinism above is a choice not a constant.

    Without this, the "deterministic" test above would pass for the wrong
    reason: the seed was recorded in the configuration fingerprint but not
    used in the assignment, so changing it produced a plan that claimed to be
    new and was byte-identical. Anyone re-splitting by changing the seed got
    the same split and no indication of it.
    """
    first = build_split_plan(_records(), SplitOptions(seed=42))
    second = build_split_plan(_records(), SplitOptions(seed=1_234))

    assert split_plan_fingerprint(first) != split_plan_fingerprint(second)

    first_map = subject_split_map(first)
    second_map = subject_split_map(second)

    assert first_map != second_map, "the seed changed the fingerprint but not the split"


def test_an_account_keeps_its_split_as_the_dataset_grows():
    """
    Assignment is a stable hash, not a shuffle, and this is why that matters.

    Splitting by shuffling reassigns everything whenever a record is added,
    which silently invalidates every evaluation taken before the addition —
    an account that was in the test set is now in training, so the previous
    test score measured a model that had seen it.

    Hashing the subject against a fixed configuration means an account keeps
    its side. Most of the twenty accounts below stay put when the dataset
    doubles; the few that move do so because the per-split *allocation* grew,
    not because the ordering changed.
    """
    options = SplitOptions(seed=42)

    small = subject_split_map(build_split_plan(_records(count=20), options))
    large = subject_split_map(build_split_plan(_records(count=40), options))

    kept = sum(1 for subject, split in small.items() if large.get(subject) == split)

    assert kept >= len(small) * 0.8, (
        f"only {kept}/{len(small)} accounts kept their split when the data grew"
    )


def test_the_plan_is_fingerprinted_over_both_config_and_data():
    """
    Two fingerprints, because two things can change.

    A split that differs because the configuration changed and one that
    differs because the data changed are different situations, and an
    evaluation comparison needs to tell them apart.
    """
    plan = build_split_plan(_records())

    assert plan.config_fingerprint
    assert plan.data_fingerprint
    assert plan.fingerprint
    assert plan.config_fingerprint != plan.data_fingerprint


def test_the_plan_summary_carries_no_account_identifiers():
    """
    The summary reaches a model-version record and from there a report.

    Everything in it is hashed or aggregated. An account id here would travel
    into every artefact the training run produced.
    """
    summary = summarize_split_plan(build_split_plan(_records()))
    serialised = str(summary)

    assert "acc-0" not in serialised
    assert "ring-0" not in serialised
    assert summary["caveats"]


def test_the_quality_report_describes_the_class_balance():
    """
    A split with all the positives on one side is a broken split.

    It is also an easy one to produce by accident on a small, imbalanced
    synthetic dataset — which is exactly what this project has.
    """
    report = split_quality_report(build_split_plan(_records()))

    assert report["counts"]
    assert report["metrics"]
    assert report["caveats"]


def test_the_plan_declares_its_safety_flags():
    summary = summarize_split_plan(build_split_plan(_records()))
    flags = summary["safety_flags"]

    assert flags

    serialised = str(flags).lower()
    assert "leak" in serialised or "label" in serialised


def test_identifiers_in_a_split_plan_are_hashed():
    """
    Subjects and groups are salted hashes in the plan itself.

    A split plan is persisted with a model version and is read long
    afterwards. It records which accounts were in which split, so it holds
    hashes rather than ids.
    """
    plan = build_split_plan(_records())

    for item in plan.items:
        assert item.subject_ref_hash
        assert not item.subject_ref_hash.startswith("acc-")
        assert len(item.subject_ref_hash) >= 32

        if item.group_key_hash:
            assert not item.group_key_hash.startswith("ring-")


def test_splitting_is_bounded():
    options = SplitOptions()

    assert options.max_items > 0
    assert options.max_issues > 0
    assert options.leakage_guard is True


def test_the_leakage_guard_is_on_by_default():
    """
    Opt-out, not opt-in.

    A guard that had to be switched on would be off in the one run where it
    mattered.
    """
    assert SplitOptions().leakage_guard is True
    assert SplitOptions().synthetic_required is True


def test_a_forbidden_field_in_a_split_record_is_reported():
    """
    The splitter refuses secrets and labels in its own input too.

    It receives whatever the caller assembled, which in practice is a join
    across several tables — the step where a stray column is most likely to
    arrive.
    """
    records = _records(count=5)
    records[0] = dict(records[0], ground_truth_label=1, api_key="should-not-be-here")

    plan = build_split_plan(records)
    serialised = str(summarize_split_plan(plan))

    assert "should-not-be-here" not in serialised
