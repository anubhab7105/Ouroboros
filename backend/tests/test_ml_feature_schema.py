"""
The feature catalogue and its guard rails.

The catalogue is the list of things the model is allowed to know about an
account. Most of what matters about it is negative: which names are refused,
and why.

Two kinds of name are forbidden, for different reasons.

**Label-shaped names** — `ground_truth`, `scenario_id`, `ring_id`, `is_fraud`
— are target leakage. A model trained on a feature derived from the label it
is predicting scores perfectly in evaluation and uselessly in production. The
synthetic generator plants `scenario_type` and `ring_id` on every account, so
the leak is one careless join away at all times, and the names are blocked at
the schema rather than caught by reviewers.

**Identity-shaped names** — `phone_number`, `upi_id`, `device_id`,
`account_number`, `narrative` — are privacy leakage. A feature vector is
copied into snapshots, model artefacts, explanations and reports, so anything
in it spreads. Identifiers belong in the entity tables as hashes, where the
access rules apply.
"""

from __future__ import annotations

import pytest

from app.ml.feature_schema import (
    FEATURE_SCHEMA_VERSION,
    get_feature_catalog,
    get_feature_spec,
    is_forbidden_feature_name,
    list_feature_names,
)

pytestmark = pytest.mark.ml


# -----------------------------------------------------------------------------
# The catalogue
# -----------------------------------------------------------------------------


def test_the_catalogue_is_not_empty():
    names = list_feature_names()

    assert names
    assert len(names) == len(set(names)), "a feature name appears twice"


def test_the_schema_is_versioned():
    """
    A feature vector without a schema version is uninterpretable later.

    A snapshot taken six months ago under a different catalogue cannot be fed
    to today's model, and the version is what lets that be detected rather
    than producing a confident wrong answer from misaligned columns.
    """
    assert FEATURE_SCHEMA_VERSION


def test_every_feature_has_a_specification():
    """
    Each name resolves to a spec with a description.

    An undescribed feature cannot be explained to an analyst, and a score
    whose top contributing factor cannot be put into words is not an
    explainable score.
    """
    for name in list_feature_names():
        spec = get_feature_spec(name)

        assert spec is not None, f"{name} has no specification"
        assert getattr(spec, "description", None), f"{name} has no description"


def test_the_catalogue_is_stable_across_calls():
    """
    Same catalogue twice.

    It is cached, and a catalogue that rebuilt differently on each call would
    make feature ordering non-deterministic — which silently misaligns a model
    trained in one process and served in another.
    """
    assert list_feature_names() == list_feature_names()
    assert get_feature_catalog() is get_feature_catalog()


# -----------------------------------------------------------------------------
# Label leakage
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "ground_truth",
        "ground_truth_label",
        "truth_label",
        "fraud_label",
        "is_fraud",
        "scenario_id",
        "scenario_type",
        "ring_id",
        "fraud_ring",
        "account_ground_truth_label_30d",
        "ring_id_hashed",
    ],
)
def test_label_shaped_names_are_forbidden(name):
    """
    Substring matching, so a name that merely contains the token is refused.

    `account_ground_truth_label_30d` looks like a legitimate windowed feature
    and is the exact shape a leak takes in practice: someone needed the label
    for a diagnostic, named it like a feature, and it was never removed.
    """
    assert is_forbidden_feature_name(name) is True


def test_no_catalogued_feature_is_label_shaped():
    """
    The catalogue and the blocklist agree.

    Checked rather than assumed, because the two are maintained separately —
    a feature added to the catalogue is not run past the blocklist unless
    something does it.
    """
    offenders = [name for name in list_feature_names() if is_forbidden_feature_name(name)]

    assert not offenders, f"catalogued features hit the leakage blocklist: {offenders}"


# -----------------------------------------------------------------------------
# Privacy leakage
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "phone_number",
        "email_address",
        "upi_id",
        "device_id",
        "ip_address",
        "account_number",
        "card_number",
        "pan",
        "cvv",
        "identifier_raw",
        "raw_identifier",
        "narrative",
        "narrative_raw",
        "complaint_narrative_text",
    ],
)
def test_identity_shaped_names_are_forbidden(name):
    """
    Raw identifiers and complaint text never enter a feature vector.

    A feature vector travels: into snapshots, into model artefacts, into
    explanations, and from there into reports that leave the building. A
    victim's narrative in a feature vector is a victim's narrative in a PDF.
    """
    assert is_forbidden_feature_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "secret",
        "api_key",
        "access_token",
        "authorization",
        "connection_string",
        "database_url",
        "private_key",
        "cookie",
        "session_token",
    ],
)
def test_credential_shaped_names_are_forbidden(name):
    assert is_forbidden_feature_name(name) is True


def test_pickle_is_forbidden_as_a_feature_name():
    """
    An odd-looking entry with a specific history.

    A feature named `pickle` is a feature holding serialised Python, and a
    model artefact that unpickles its own feature values is remote code
    execution with extra steps.
    """
    assert is_forbidden_feature_name("pickle") is True
    assert is_forbidden_feature_name("pickled_state") is True


# -----------------------------------------------------------------------------
# What is allowed
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "txn_count_7d",
        "txn_count_30d",
        "txn_amount_sum_30d",
        "counterparty_distinct_count_30d",
        "counterparty_entropy_30d",
        "inbound_outbound_amount_ratio_30d",
        "txn_night_ratio_30d",
        "is_dormant_flag",
    ],
)
def test_behavioural_features_are_allowed(name):
    """
    The features the detector is actually meant to use.

    All behavioural: counts, amounts, ratios, concentration, timing. Nothing
    about who the person is — which is both the privacy position and the
    reason the platform can claim to detect a *pattern* rather than to profile
    an account holder.
    """
    assert is_forbidden_feature_name(name) is False


def test_a_forbidden_check_is_case_and_separator_insensitive():
    """
    `GroundTruth`, `ground-truth` and `GROUND_TRUTH` are all the same name.

    A blocklist that only matches one spelling is a blocklist with a
    documented bypass.
    """
    for spelling in ("GroundTruth", "GROUND_TRUTH", "ground-truth", "Ground Truth"):
        assert is_forbidden_feature_name(spelling) is True, spelling


def test_an_empty_or_nonsense_name_is_refused():
    """
    Not a leak, but not a feature either.

    An empty name would produce a column nothing can refer to.
    """
    assert get_feature_spec("") is None
    assert get_feature_spec("definitely_not_a_real_feature") is None


# -----------------------------------------------------------------------------
# Specs
# -----------------------------------------------------------------------------


def test_windowed_features_declare_their_window():
    """
    A feature named `_30d` says 30 days in its metadata too.

    The name is a convention and the metadata is the contract. If they
    disagree, every explanation that quotes the window is wrong.
    """
    for name in list_feature_names():
        if not name.endswith(("_7d", "_30d", "_90d")):
            continue

        spec = get_feature_spec(name)
        window = getattr(spec, "window", None)

        assert window is not None, f"{name} is windowed by name but declares no window"


def test_derived_features_declare_their_dependencies():
    """
    A ratio says which features it came from.

    `txn_count_velocity_ratio_7d_30d` is meaningless without knowing it is
    7-day over 30-day, and an explanation that cites it has to be able to show
    both sides.
    """
    spec = get_feature_spec("txn_count_velocity_ratio_7d_30d")

    if spec is None:
        pytest.skip("this derived feature is not in the catalogue")

    dependencies = getattr(spec, "dependencies", ()) or ()
    assert set(dependencies) >= {"txn_count_7d", "txn_count_30d"}


def test_feature_names_are_lowercase_with_underscores():
    """
    One naming convention, enforced.

    Feature names become dictionary keys, JSON keys, column headers and
    explanation text. A mixed convention means a lookup that works in one
    place and quietly misses in another.
    """
    offenders = [
        name
        for name in list_feature_names()
        if name != name.lower() or " " in name or "-" in name
    ]

    assert not offenders, f"features not in lower_snake_case: {offenders[:10]}"
