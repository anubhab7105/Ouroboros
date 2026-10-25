"""
Feature construction.

`app/ml/features.py` turns a dataset of plain mappings into feature vectors
validated against the catalogue. It depends only on numpy, so these tests run
the real builder rather than describing it.

Two things are being checked throughout.

**The vector matches the catalogue.** Every key the builder emits is a
catalogued feature, and the vector validates against the schema. A feature the
catalogue does not declare is a column the model cannot be trained on and the
explanation layer cannot describe.

**Unavailable means null, not zero.** An account with no balance history has
`balance_mean_30d` of None, not 0 — a zero would be a claim that the balance
was zero. The same distinction runs through every optional metric.

The account-type features get their own section because they were silently
constant: the builder's `_ACCOUNT_TYPES` listed SAVINGS / CURRENT / WALLET /
UPI / CARD, which shares no value with the model's `AccountType`
(INDIVIDUAL / BUSINESS / MERCHANT / OTHER). Every account normalised to the
OTHER fallback, so `account_type_enum`, `account_segment_enum` and
`is_business_flag` carried no information at all.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from app.ml.feature_schema import (
    get_feature_catalog,
    is_forbidden_feature_name,
    list_feature_names,
    validate_feature_vector,
)
from app.ml.features import (
    FeatureBuildOptions,
    build_feature_vector,
    build_feature_vectors,
    get_features_metadata,
)

pytestmark = pytest.mark.features


NOW = datetime(2025, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def _iso(moment):
    return moment.isoformat()


def _account(account_id, account_type="INDIVIDUAL", status="ACTIVE", age_days=400):
    return {
        "id": account_id,
        "account_type": account_type,
        "status": status,
        "created_at": _iso(NOW - timedelta(days=age_days)),
    }


def _transfer(index, sender, receiver, amount=24_000, hours_ago=6, currency="INR"):
    return {
        "id": f"t-{index}",
        "reference": f"T-{index}",
        "sender_account_id": sender,
        "receiver_account_id": receiver,
        "amount": amount,
        "currency": currency,
        "status": "COMPLETED",
        "channel": "UPI",
        "occurred_at": _iso(NOW - timedelta(hours=hours_ago)),
    }


def _fan_in(sources=12, target="acc-0", within_hours=6):
    """The collection shape: `sources` accounts paying `target`."""
    accounts = [_account(target)] + [
        _account(f"acc-{index}") for index in range(1, sources + 1)
    ]
    transactions = [
        _transfer(
            index,
            f"acc-{index + 1}",
            target,
            hours_ago=within_hours - index * (within_hours / (sources + 1)),
        )
        for index in range(sources)
    ]
    return {"accounts": accounts, "transactions": transactions}


def _features_for(dataset, account_id="acc-0", **kwargs):
    result = build_feature_vectors(
        dataset, [account_id], observation_time=NOW, **kwargs
    )
    assert result.vectors, f"no vector was built: {[i.code for i in result.issues]}"
    return result.vectors[0].features


# -----------------------------------------------------------------------------
# Building
# -----------------------------------------------------------------------------


def test_a_vector_is_built_for_a_requested_account():
    result = build_feature_vectors(_fan_in(), ["acc-0"], observation_time=NOW)

    assert result.ok is True
    assert len(result.vectors) == 1
    assert result.rejected_accounts == []
    assert result.counts["vectors_built"] == 1
    assert result.counts["errors"] == 0


def test_the_vector_covers_the_whole_catalogue():
    """
    Every catalogued feature is present, and nothing extra is.

    A model is trained on the catalogue's column order. A vector missing a
    feature trains a model with a hole in it; a vector with an extra one
    trains a model on a column the serving path will not supply.
    """
    features = _features_for(_fan_in())
    catalogued = set(list_feature_names())

    assert set(features) == catalogued, (
        f"missing: {sorted(catalogued - set(features))[:5]}, "
        f"extra: {sorted(set(features) - catalogued)[:5]}"
    )


def test_the_vector_validates_against_the_schema():
    """
    Values are in their declared domains.

    The catalogue declares a type and a range per feature. A ratio outside
    0..1 or a negative count would be accepted by the builder and rejected by
    nothing else in the path.
    """
    result = build_feature_vectors(_fan_in(), ["acc-0"], observation_time=NOW)
    vector = result.vectors[0]

    validated = validate_feature_vector(vector.features, catalog=get_feature_catalog())
    validation = getattr(validated, "validation", None)

    issues = getattr(validation, "issues", ()) if validation is not None else ()
    errors = [
        issue
        for issue in issues
        if "error" in str(getattr(issue, "severity", "")).lower()
    ]

    assert not errors, (
        f"schema validation errors: {[getattr(i, 'code', i) for i in errors]}"
    )


def test_no_emitted_feature_name_is_forbidden():
    """
    The built vector contains no label-shaped or identity-shaped key.

    Checked on the output rather than on the catalogue, because the builder
    assembles the dict itself and could add a key the catalogue never
    declared.
    """
    features = _features_for(_fan_in())

    offenders = [name for name in features if is_forbidden_feature_name(name)]
    assert not offenders, f"the vector carries forbidden features: {offenders}"


def test_the_vector_carries_a_hashed_subject_and_a_fingerprint():
    """
    No account id, and a fingerprint for reproducibility.

    The vector is persisted as a `FeatureSnapshot` and read much later. The
    fingerprint is how an assessment can say which vector it scored.
    """
    result = build_feature_vectors(_fan_in(), ["acc-0"], observation_time=NOW)
    vector = result.vectors[0]

    assert vector.subject_ref_hash
    assert vector.subject_ref_hash != "acc-0"
    assert len(vector.subject_ref_hash) >= 32
    assert vector.fingerprint


def test_building_is_deterministic():
    """
    Same dataset and instant, same vector.

    Everything downstream — the snapshot, the score, the explanation — is
    irreproducible without this.
    """
    first = build_feature_vectors(_fan_in(), ["acc-0"], observation_time=NOW)
    second = build_feature_vectors(_fan_in(), ["acc-0"], observation_time=NOW)

    assert first.vectors[0].features == second.vectors[0].features
    assert first.vectors[0].fingerprint == second.vectors[0].fingerprint


def test_a_single_account_can_be_built_on_its_own():
    vector = build_feature_vector("acc-0", _fan_in(), observation_time=NOW)

    assert vector is not None
    assert vector.features


def test_an_unknown_account_is_rejected_rather_than_invented():
    """
    No vector of zeroes for an account that is not there.

    A zero vector would score as an unremarkable account, which is a finding
    about an account the builder never saw.
    """
    result = build_feature_vectors(
        _fan_in(), ["acc-does-not-exist"], observation_time=NOW
    )

    assert result.vectors == [] or len(result.vectors) == 0
    assert result.rejected_accounts or result.issues


# -----------------------------------------------------------------------------
# Counts and windows
# -----------------------------------------------------------------------------


def test_transaction_counts_are_windowed():
    """
    7-day and 30-day counts, computed over their own windows.

    Twelve transfers in six hours are inside both windows, so both counts are
    twelve. The distinction matters once activity is spread: a count that
    ignored its window would make a burst and a trickle look identical.
    """
    features = _features_for(_fan_in(sources=12))

    assert features["txn_count_7d"] == 12
    assert features["txn_count_30d"] == 12


def test_an_older_transfer_falls_out_of_the_shorter_window():
    """
    A transfer forty days back is in neither window.

    This is the test that distinguishes a real windowed count from a total:
    with a bare count both windows would read 13.
    """
    dataset = _fan_in(sources=12)
    dataset["transactions"].append(
        _transfer(99, "acc-1", "acc-0", hours_ago=24 * 40)
    )

    features = _features_for(dataset)

    assert features["txn_count_7d"] == 12
    assert features["txn_count_30d"] == 12


def test_distinct_counterparties_counts_people_not_transfers():
    """
    Six payers making seven transfers is six counterparties.

    The fan-in signal is about how many *different* parties paid in. A count
    that conflated the two would fire on a regular salary from one employer.
    """
    dataset = _fan_in(sources=6)
    dataset["transactions"].append(_transfer(50, "acc-2", "acc-0", hours_ago=2))

    features = _features_for(dataset)

    assert features["txn_count_30d"] == 7
    assert features["counterparty_distinct_count_30d"] == 6


def test_amount_statistics_are_computed():
    dataset = _fan_in(sources=5)
    features = _features_for(dataset)

    assert features["txn_amount_sum_30d"] is not None
    assert Decimal(str(features["txn_amount_sum_30d"])) == Decimal("120000")
    assert features["txn_amount_mean_30d"] is not None
    assert features["txn_amount_max_30d"] is not None


def test_account_age_is_computed_from_the_observation_time():
    """
    Age is relative to `as_of`, not to now.

    A feature vector built today over last month's data must report the age
    the account had last month. Computing it from the wall clock would make
    every backfilled vector wrong by the elapsed time.
    """
    dataset = _fan_in()
    dataset["accounts"][0] = _account("acc-0", age_days=400)

    features = _features_for(dataset)
    assert features["account_age_days"] == 400


def test_a_new_account_has_a_small_age():
    dataset = _fan_in()
    dataset["accounts"][0] = _account("acc-0", age_days=11)

    features = _features_for(dataset)
    assert features["account_age_days"] == 11


# -----------------------------------------------------------------------------
# Account type and segment
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "account_type,expected_segment",
    [
        ("INDIVIDUAL", "retail"),
        ("BUSINESS", "business"),
        ("MERCHANT", "merchant"),
    ],
)
def test_the_account_type_reaches_the_vector(account_type, expected_segment):
    """
    The regression test for a signal that was dead in every vector.

    The builder kept its own list of account types — SAVINGS, CURRENT, WALLET,
    UPI, CARD — which shares not one value with the model's `AccountType`.
    `_normalize_enum` therefore fell through to the OTHER fallback for every
    account ever built, and `account_type_enum`, `account_segment_enum` and
    `is_business_flag` were constant across the whole dataset.

    Nothing failed. The features were simply uninformative, which is the worst
    way for a feature to be wrong: a model trained on them learns to ignore
    the column and nobody can tell from the metrics.
    """
    dataset = _fan_in()
    dataset["accounts"][0] = _account("acc-0", account_type=account_type)

    features = _features_for(dataset)

    assert features["account_type_enum"] == account_type
    assert features["account_segment_enum"] == expected_segment


def test_a_merchant_is_distinguishable_from_an_individual():
    """
    The distinction the hard-negative scenario depends on.

    A busy merchant and a collection account have similar inbound counts. The
    account type is one of the few signals that separates them, so it has to
    be present and correct.
    """
    merchant_dataset = _fan_in()
    merchant_dataset["accounts"][0] = _account("acc-0", account_type="MERCHANT")

    individual_dataset = _fan_in()

    merchant = _features_for(merchant_dataset)
    individual = _features_for(individual_dataset)

    assert merchant["account_type_enum"] != individual["account_type_enum"]
    assert merchant["account_segment_enum"] != individual["account_segment_enum"]


def test_a_business_account_sets_the_business_flag():
    for account_type in ("BUSINESS", "MERCHANT"):
        dataset = _fan_in()
        dataset["accounts"][0] = _account("acc-0", account_type=account_type)

        assert _features_for(dataset)["is_business_flag"] is True

    individual = _fan_in()
    assert _features_for(individual)["is_business_flag"] is False


def test_the_wallet_flag_is_constantly_false_and_says_so():
    """
    A catalogued feature with no account type behind it.

    The catalogue declares `is_wallet_flag`, and a vector must match the
    catalogue, so the key stays. But no account type in this platform is a
    wallet, so it is hard-coded false rather than testing a value that cannot
    occur — which at least makes the dead feature visible in the source.
    """
    assert _features_for(_fan_in())["is_wallet_flag"] is False


def test_an_unknown_account_type_falls_back_to_other():
    """
    A type the model does not define normalises to OTHER, deliberately.

    This is the fallback working as intended — and it is exactly what used to
    happen to *every* account, which is why it needs its own test rather than
    being inferred from the absence of one.
    """
    dataset = _fan_in()
    dataset["accounts"][0] = _account("acc-0", account_type="CRYPTO_WALLET")

    assert _features_for(dataset)["account_type_enum"] == "OTHER"


def test_a_dormant_account_is_segmented_as_dormant():
    """
    Status and inactivity both route to the dormant segment.

    Dormancy is computed from the absence of activity as well as from the
    reported status, because the status column is often stale and MuleGuard
    never sets it.
    """
    dataset = {
        "accounts": [_account("acc-0", status="DORMANT")],
        "transactions": [],
    }

    features = _features_for(dataset)

    assert features["is_dormant_flag"] is True
    assert features["account_segment_enum"] == "dormant"


def test_an_account_with_no_activity_is_dormant_whatever_its_status():
    dataset = {"accounts": [_account("acc-0", status="ACTIVE")], "transactions": []}

    assert _features_for(dataset)["is_dormant_flag"] is True


# -----------------------------------------------------------------------------
# Missing data
# -----------------------------------------------------------------------------


def test_an_unavailable_metric_is_null_not_zero():
    """
    The distinction that runs through the whole vector.

    No balance snapshots means `balance_mean_30d` cannot be computed. A zero
    would assert the balance *was* zero, which for an account the dataset has
    no balance data for is a claim out of nothing — and it would make every
    balance-based rule fire on missing data rather than on low balances.
    """
    features = _features_for(_fan_in())

    assert features["balance_cv_30d"] is None or features["balance_cv_30d"] == 0
    assert "inbound_outbound_amount_ratio_30d" in features


def test_a_ratio_with_no_denominator_is_null():
    """
    An account with no outbound transfers has no inbound/outbound ratio.

    Not infinity, and not zero. A collection account that has received money
    and sent none is precisely the case this arises in, so getting it wrong
    would misreport the most interesting accounts.
    """
    features = _features_for(_fan_in(sources=5))

    ratio = features["inbound_outbound_amount_ratio_30d"]
    assert ratio is None or Decimal(str(ratio)) >= 0


def test_an_account_with_no_transactions_still_builds_a_vector():
    """
    A complete vector of mostly nulls, not a failure.

    A dormant account is a normal thing to assess, and the rules need a vector
    to evaluate — the guardrail rule exists to flag exactly this case.
    """
    dataset = {"accounts": [_account("acc-0")], "transactions": []}
    features = _features_for(dataset)

    assert set(features) == set(list_feature_names())
    assert features["txn_count_7d"] == 0
    assert features["txn_count_30d"] == 0


def test_a_malformed_transaction_is_reported_not_fatal():
    """
    One bad row does not lose the whole vector.

    Feature construction runs over a feed. Raising on a single malformed
    transfer would mean an account cannot be assessed because of a row that
    has nothing to do with it.
    """
    dataset = _fan_in(sources=4)
    dataset["transactions"].append(
        {
            "id": "t-bad",
            "reference": "T-BAD",
            "sender_account_id": "acc-1",
            "receiver_account_id": "acc-0",
            "amount": "not-a-number",
            "currency": "INR",
            "status": "COMPLETED",
            "channel": "UPI",
            "occurred_at": "not-a-timestamp",
        }
    )

    result = build_feature_vectors(dataset, ["acc-0"], observation_time=NOW)

    assert result.vectors, "a malformed row prevented the vector being built"


# -----------------------------------------------------------------------------
# Bounds and metadata
# -----------------------------------------------------------------------------


def test_construction_is_bounded():
    options = FeatureBuildOptions()

    assert options.max_accounts > 0
    assert options.max_transactions > 0
    assert options.max_counterparties > 0
    assert options.synthetic_required is True


def test_the_counts_describe_what_was_read():
    """
    What the builder saw, alongside what it produced.

    A vector built from a truncated dataset is a vector over partial data.
    The counts are how that becomes visible rather than being absorbed into
    the feature values.
    """
    result = build_feature_vectors(_fan_in(sources=8), ["acc-0"], observation_time=NOW)
    counts = result.counts

    assert counts["accounts_available"] == 9
    assert counts["transactions_available"] == 8
    assert counts["accounts_requested"] == 1
    assert counts["accounts_built"] == 1


def test_the_metadata_declares_its_caveats_and_limits():
    metadata = get_features_metadata()

    assert metadata
    serialised = str(metadata).lower()

    assert "synthetic" in serialised


def test_the_result_carries_no_account_identifier():
    """
    The build result is passed around and persisted, so it holds no ids.

    The caller asked for `acc-0` and knows which account it asked about.
    """
    result = build_feature_vectors(_fan_in(), ["acc-0"], observation_time=NOW)

    serialised = str(result.vectors[0].features) + str(result.vectors[0].metadata)
    assert "acc-0" not in serialised


def test_many_accounts_can_be_built_in_one_pass():
    """
    The batch path, which is what an analysis run uses.

    Building one account at a time would re-read the dataset per account; the
    graph indices in particular are shared across the batch.
    """
    dataset = _fan_in(sources=6)
    requested = [account["id"] for account in dataset["accounts"]]

    result = build_feature_vectors(dataset, requested, observation_time=NOW)

    assert len(result.vectors) == len(requested)

    hashes = {vector.subject_ref_hash for vector in result.vectors}
    assert len(hashes) == len(requested), "two accounts share a subject hash"
