"""
Model monitoring: versions, evaluations and the claims the platform may make.

This endpoint group is where the platform describes its own ML capability, and
the most important thing it does is refuse to overstate it. Two fields on
`/model/limitations` carry that refusal:

- `probability_claim_allowed` — whether a score may be described as a
  probability of anything. It is false. The score is an investigative
  priority on a 0..100 scale, and calling it "an 87% chance this is a mule
  account" would be a statement nobody can support.
- `calibration_claim_allowed` — whether the model is calibrated, meaning its
  scores correspond to observed frequencies. Also false: calibration would
  have to be measured against real outcomes, and the labels here are the
  generator's intent.

`production_ready` is false and `synthetic_only` is true for the same reason.
These are not placeholders awaiting a flip; they are the honest description of
a prototype trained on synthetic labels.

The metric fields matter too: an evaluation reports a class distribution and a
sample count alongside its metrics, because an AUC over 40 accounts with three
positives is a number with enormous error bars and no confidence interval of
its own.
"""

from __future__ import annotations

import pytest

from app.api.v1.endpoints.model_metrics import (
    FeatureSchemaResponse,
    ModelEvaluationResponse,
    ModelVersionResponse as EndpointModelVersionResponse,
)
from app.models import ModelType, SplitStrategy
from app.schemas.model_metrics import ModelVersionResponse as SharedModelVersionResponse

from tests.utils import assert_error, assert_ok, assert_paginated, ids_of

pytestmark = [pytest.mark.ml, pytest.mark.api]


MODEL = "/api/v1/model"


# -----------------------------------------------------------------------------
# Status
# -----------------------------------------------------------------------------


def test_status_reports_the_active_estimator(analyst_client):
    """
    Which estimator is in use, and whether an artefact backs it.

    `scoring_mode` is the field everything else hangs off: it says whether
    scores are coming from a trained model or from the hand-weighted
    fallback, and the interface shows that next to every score.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/status"))

    assert body["enabled"] is True
    assert body["scoring_mode"]
    assert body["fallback_label"]
    assert body["dataset_mode"] == "synthetic"
    assert body["feature_schema_version"]
    assert body["caveats"]


def test_status_reports_no_active_version_when_none_is_trained(analyst_client):
    """
    Null, not a placeholder string.

    A fresh deployment has no trained model. Reporting `"none"` or `"v0"`
    would make the interface display a version that does not exist.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/status"))

    assert body["active_model_version"] is None
    assert isinstance(body["artifact_status"], dict)


def test_status_says_whether_the_artifact_is_actually_present(
    analyst_client, make, db
):
    """
    A `ModelVersion` row is not a model.

    The row says a model was trained; `artifact_status` says whether the file
    it produced is on disk and readable. A deployment restored without its
    artefacts has rows and no models, and this is the only field that shows
    it.
    """
    make.model_version(version="v-test-1", is_active=True)
    db.commit()

    body = assert_ok(analyst_client.get(f"{MODEL}/status"))
    assert isinstance(body["artifact_status"], dict)


def test_status_is_readable_by_every_role(role_clients):
    """
    `MODEL_MONITOR_READ` is granted to all four roles.

    An analyst needs to know whether the scores they are acting on came from
    a model, and an auditor needs to be able to check what the platform
    claimed about itself.
    """
    for role, client in role_clients.items():
        assert client.get(f"{MODEL}/status").status_code == 200, role


# -----------------------------------------------------------------------------
# Limitations
# -----------------------------------------------------------------------------


def test_the_score_may_not_be_described_as_a_probability(analyst_client):
    """
    `probability_claim_allowed` is false.

    The single most important field in this endpoint group. A score of 87 is
    an investigative priority, not "an 87% chance this is a mule account" —
    there is no calibration behind it and the labels it was trained against
    are a generator's intent. Letting the number be read as a probability is
    how a lead becomes an accusation.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/limitations"))

    assert body["probability_claim_allowed"] is False


def test_the_model_may_not_be_described_as_calibrated(analyst_client):
    """
    `calibration_claim_allowed` is false.

    Calibration means the scores match observed frequencies, which would have
    to be measured against real outcomes. There are none here.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/limitations"))

    assert body["calibration_claim_allowed"] is False


def test_the_platform_declares_itself_synthetic_only_and_not_production_ready(
    analyst_client,
):
    """
    Both flags, and neither is a placeholder.

    `/health` says `production_ready: False` as a `Literal`. This says the
    same about the ML path specifically, and for a separate reason: the model
    is trained on generated labels, so its metrics measure agreement with the
    generator rather than accuracy against fraud.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/limitations"))

    assert body["synthetic_only"] is True
    assert body["production_ready"] is False
    assert body["limitations_summary"]
    assert body["caveats"]


def test_the_limitations_summary_says_what_the_labels_are(analyst_client):
    """
    The summary names the actual limitation rather than gesturing at one.

    "Trained on synthetic labels" is the fact that makes every metric below a
    measurement of agreement with the generator. A summary that said only
    "use with care" would be worse than nothing.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/limitations"))
    text = (body["limitations_summary"] + " " + " ".join(body["caveats"])).lower()

    assert "synthetic" in text
    assert any(
        phrase in text
        for phrase in ("label", "not proof", "priority", "not a probability", "lead")
    )


# -----------------------------------------------------------------------------
# The feature schema
# -----------------------------------------------------------------------------


def test_model_metrics_protected_fields_keep_their_json_aliases():
    endpoint_version = EndpointModelVersionResponse(
        id="version-id",
        version="v1",
        feature_schema_version="v1",
        family="RANDOM_FOREST",
        split_strategy="temporal",
    )
    evaluation = ModelEvaluationResponse(
        id="evaluation-id",
        version_id="version-id",
        split_strategy="temporal",
    )
    shared_version = SharedModelVersionResponse(
        id="version-id",
        version="v1",
        feature_schema_version="v1",
        family="RANDOM_FOREST",
    )

    assert endpoint_version.family == "RANDOM_FOREST"
    assert endpoint_version.model_dump(by_alias=True)["model_type"] == "RANDOM_FOREST"
    assert evaluation.version_id == "version-id"
    assert evaluation.model_dump(by_alias=True)["model_version_id"] == "version-id"
    assert shared_version.family == "RANDOM_FOREST"
    assert shared_version.model_dump(by_alias=True)["model_type"] == "RANDOM_FOREST"


def test_feature_schema_python_attribute_preserves_json_alias():
    response = FeatureSchemaResponse(
        available=True,
        feature_schema_version="v1",
        fallback_label="heuristic_fallback",
        feature_schema={"fields": ["amount"]},
    )

    assert response.feature_schema == {"fields": ["amount"]}
    payload = response.model_dump(by_alias=True)
    assert payload["schema"] == {"fields": ["amount"]}
    assert "feature_schema" not in payload


def test_the_feature_schema_is_published(analyst_client):
    """
    The field list, the windows, and the forbidden names.

    Published so that a client can tell whether a model is compatible with the
    features it would be served, and so the leakage blocklist is inspectable
    rather than buried.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/feature-schema"))

    assert body["available"] is True
    assert body["feature_schema_version"]
    assert "schema" in body
    assert "feature_schema" not in body
    assert body["feature_fields"]
    assert body["feature_windows"]
    assert body["forbidden_fields"]
    assert body["caveats"]


def test_the_published_forbidden_fields_include_the_label_names(analyst_client):
    """
    The blocklist is visible, so somebody can check it.

    A leakage guard nobody can inspect is a guard nobody can verify. These
    are the names that would give the answer away: the generator plants them
    on every labelled account.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/feature-schema"))
    forbidden = {name.lower() for name in body["forbidden_fields"]}

    for name in ("ground_truth", "is_fraud", "scenario", "ring_id"):
        assert any(name in entry for entry in forbidden), (
            f"{name!r} is not in the published forbidden list"
        )


def test_no_published_feature_field_is_itself_forbidden(analyst_client):
    """
    The two published lists do not overlap.

    They are built from the same catalogue but by different code, so this is
    a real consistency check rather than a tautology.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/feature-schema"))

    fields = {name.lower() for name in body["feature_fields"]}
    forbidden = {name.lower() for name in body["forbidden_fields"]}

    assert not (fields & forbidden), f"overlap: {sorted(fields & forbidden)}"


def test_the_published_windows_match_the_field_suffixes(analyst_client):
    body = assert_ok(analyst_client.get(f"{MODEL}/feature-schema"))

    assert body["feature_windows"]
    assert any(
        str(window).lower().endswith(("d", "day", "days"))
        for window in body["feature_windows"]
    )


# -----------------------------------------------------------------------------
# Versions
# -----------------------------------------------------------------------------


def test_list_model_versions(analyst_client, make, db):
    version = make.model_version(version="v-2026-01")
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(f"{MODEL}/versions")))

    assert version.id in ids_of(body["items"])
    assert body["caveats"]


def test_an_empty_version_list_is_not_an_error(analyst_client):
    body = assert_paginated(assert_ok(analyst_client.get(f"{MODEL}/versions")))

    assert body["items"] == []
    assert body["total"] == 0


def test_filter_versions_by_model_type(analyst_client, make, db):
    forest = make.model_version(model_type=ModelType.RANDOM_FOREST)
    make.model_version(model_type=ModelType.LOGISTIC_REGRESSION)
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{MODEL}/versions", params={"model_type": "RANDOM_FOREST"})
    )
    assert ids_of(body["items"]) == [forest.id]


def test_filter_versions_by_active_flag(analyst_client, make, db):
    active = make.model_version(version="v-active", is_active=True)
    make.model_version(version="v-retired", is_active=False)
    db.commit()

    body = assert_ok(analyst_client.get(f"{MODEL}/versions", params={"is_active": True}))
    assert ids_of(body["items"]) == [active.id]


def test_filter_versions_by_feature_schema_version(analyst_client, make, db):
    """
    The filter that answers "which models can still be served".

    A model trained against an older feature schema cannot be fed today's
    vectors — the columns differ. This is how that set is found.
    """
    current = make.model_version(version="v-current", feature_schema_version="v1")
    make.model_version(version="v-old", feature_schema_version="v0")
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{MODEL}/versions", params={"feature_schema_version": "v1"})
    )
    assert ids_of(body["items"]) == [current.id]


def test_a_version_records_its_full_provenance(analyst_client, make, db):
    """
    Seed, dataset fingerprint, split strategy, hyperparameters, checksum.

    This is what makes a model reproducible. Without the seed and the dataset
    fingerprint, "retrain and compare" is not a thing anyone can do, and a
    difference between two versions cannot be attributed to the change that
    was intended.
    """
    version = make.model_version(
        version="v-provenance",
        training_seed=20_260_120,
        dataset_fingerprint="a" * 64,
        split_strategy=SplitStrategy.SCENARIO_AWARE_CHRONOLOGICAL,
        hyperparameters_json={"max_depth": 6, "learning_rate": 0.08},
        artifact_checksum="b" * 64,
    )
    db.commit()

    body = assert_ok(analyst_client.get(f"{MODEL}/versions/{version.id}"))

    assert body["training_seed"] == 20_260_120
    assert body["dataset_fingerprint"] == "a" * 64
    assert body["split_strategy"] == "SCENARIO_AWARE_CHRONOLOGICAL"
    assert body["hyperparameters_json"]
    assert body["artifact_checksum"]
    assert body["checksum_algorithm"]


def test_the_split_strategy_is_recorded_on_every_version(analyst_client, make, db):
    """
    How the data was split is part of what the model is.

    A model split randomly over a dataset containing rings has group leakage
    and a flattering test score. Recording the strategy is what lets a reader
    discount the metrics of a version split the wrong way.
    """
    version = make.model_version(split_strategy=SplitStrategy.GROUP_AWARE_RANDOM)
    db.commit()

    body = assert_ok(analyst_client.get(f"{MODEL}/versions/{version.id}"))
    assert body["split_strategy"] == "GROUP_AWARE_RANDOM"


def test_artifact_availability_is_distinguished_from_the_row(analyst_client, make, db):
    """
    `artifact_available` is false when the file is not there.

    A row with no artefact is a model that cannot be served. Reporting it as
    available would make the interface offer a version that fails at scoring
    time.
    """
    version = make.model_version(version="v-no-artifact", artifact_path=None)
    db.commit()

    body = assert_ok(analyst_client.get(f"{MODEL}/versions/{version.id}"))
    assert body["artifact_available"] is False


def test_a_version_does_not_expose_its_artifact_path(analyst_client, make, db):
    """
    A filesystem path is not published.

    `artifact_path` is a server-side location. Publishing it discloses the
    deployment's layout, and `_FORBIDDEN_FEATURE_FIELDS` lists
    `artifact_path` for the same reason.
    """
    version = make.model_version(
        version="v-path", artifact_path="/srv/muleguard/models/v-path/model.joblib"
    )
    db.commit()

    response = analyst_client.get(f"{MODEL}/versions/{version.id}")
    assert_ok(response)

    assert "/srv/muleguard" not in response.text
    assert "artifact_path" not in response.json()


def test_unknown_version_is_404(analyst_client):
    assert_error(analyst_client.get(f"{MODEL}/versions/not-a-real-version"), 404)


# -----------------------------------------------------------------------------
# Current
# -----------------------------------------------------------------------------


def test_current_reports_the_active_version_and_its_evaluations(
    analyst_client, make, db
):
    version = make.model_version(version="v-active", is_active=True)
    db.commit()

    body = assert_ok(analyst_client.get(f"{MODEL}/current"))

    assert body["scoring_mode"]
    assert body["fallback_label"]
    assert body["feature_schema_version"]
    assert isinstance(body["latest_evaluations"], list)
    assert body["caveats"]


def test_current_reports_nulls_when_nothing_is_trained(analyst_client):
    """
    No active version, and the fallback named.

    This is the state of a fresh deployment, and the one the interface has to
    render without pretending a model exists.
    """
    body = assert_ok(analyst_client.get(f"{MODEL}/current"))

    assert body["active_model_version"] is None
    assert body["active_version"] is None
    assert body["latest_evaluations"] == []
    assert body["fallback_label"]


# -----------------------------------------------------------------------------
# Evaluations
# -----------------------------------------------------------------------------


def test_an_evaluation_reports_its_sample_count_and_class_distribution(
    analyst_client, make, db
):
    """
    The two numbers that make a metric interpretable.

    An AUC of 0.94 over 40 accounts with 3 positives is almost meaningless,
    and an AUC of 0.94 over 50,000 with 1,200 is a real result. Publishing
    the metric without the sample size and the balance invites the first to be
    read as the second.
    """
    from app.models import ModelEvaluation

    version = make.model_version(version="v-evaluated")
    db.flush()

    evaluation = ModelEvaluation(
        model_version_id=version.id,
        split_strategy=SplitStrategy.SCENARIO_AWARE_CHRONOLOGICAL,
        sample_count=1_200,
        class_distribution_json={"positive": 96, "negative": 1_104},
        metrics_json={"roc_auc": 0.91, "precision_at_50": 0.62, "recall_at_50": 0.48},
        limitations="Metrics measure agreement with generator intent, not real fraud.",
    )
    db.add(evaluation)
    db.commit()

    body = assert_ok(analyst_client.get(f"{MODEL}/evaluations/{evaluation.id}"))

    assert body["sample_count"] == 1_200
    assert body["class_distribution_json"]
    assert body["metrics_summary"]
    assert body["split_strategy"] == "SCENARIO_AWARE_CHRONOLOGICAL"


def test_an_evaluation_states_its_own_limitations(analyst_client, make, db):
    """
    Carried on the row, not inferred from the endpoint.

    An evaluation is the thing most likely to be quoted in isolation — "the
    model scores 0.91" — so the qualification is stored with the number
    rather than attached by whichever endpoint serves it.
    """
    from app.models import ModelEvaluation

    version = make.model_version()
    db.flush()

    evaluation = ModelEvaluation(
        model_version_id=version.id,
        sample_count=400,
        metrics_json={"roc_auc": 0.88},
        limitations="Synthetic labels; no real-world validation.",
    )
    db.add(evaluation)
    db.commit()

    body = assert_ok(analyst_client.get(f"{MODEL}/evaluations/{evaluation.id}"))

    assert body["limitations"]
    assert "synthetic" in body["limitations"].lower()


def test_evaluations_are_listed_per_version(analyst_client, make, db):
    from app.models import ModelEvaluation

    first = make.model_version(version="v-one")
    second = make.model_version(version="v-two")
    db.flush()

    db.add(ModelEvaluation(model_version_id=first.id, sample_count=100))
    db.add(ModelEvaluation(model_version_id=second.id, sample_count=200))
    db.commit()

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{MODEL}/versions/{first.id}/evaluations"))
    )

    assert body["total"] == 1
    assert body["items"][0]["model_version_id"] == first.id


def test_evaluations_can_be_filtered_by_split_strategy(analyst_client, make, db):
    """
    Comparing a chronological evaluation with a random one is not comparable.

    The filter exists so somebody can compare like with like, which is the
    only way a version-to-version difference means anything.
    """
    from app.models import ModelEvaluation

    version = make.model_version()
    db.flush()

    db.add(
        ModelEvaluation(
            model_version_id=version.id,
            split_strategy=SplitStrategy.CHRONOLOGICAL,
            sample_count=100,
        )
    )
    db.add(
        ModelEvaluation(
            model_version_id=version.id,
            split_strategy=SplitStrategy.RANDOM,
            sample_count=100,
        )
    )
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{MODEL}/versions/{version.id}/evaluations",
            params={"split_strategy": "CHRONOLOGICAL"},
        )
    )

    assert body["total"] == 1


def test_an_evaluation_with_no_metrics_is_not_reported_as_zeroes(
    analyst_client, make, db
):
    """
    An evaluation that failed to compute metrics has none, not zeroes.

    A ROC-AUC of 0.0 is the worst possible model; an absent one is an
    evaluation that did not finish. Showing the first for the second would
    have somebody withdrawing a working model.
    """
    from app.models import ModelEvaluation

    version = make.model_version()
    db.flush()

    evaluation = ModelEvaluation(
        model_version_id=version.id, sample_count=0, metrics_json=None
    )
    db.add(evaluation)
    db.commit()

    body = assert_ok(analyst_client.get(f"{MODEL}/evaluations/{evaluation.id}"))

    assert body["metrics_summary"] in ({}, None) or not body["metrics_summary"].get(
        "roc_auc"
    )


def test_unknown_evaluation_is_404(analyst_client):
    assert_error(analyst_client.get(f"{MODEL}/evaluations/not-real"), 404)


# -----------------------------------------------------------------------------
# Comparison
# -----------------------------------------------------------------------------


def test_two_versions_can_be_compared(analyst_client, make, db):
    first = make.model_version(version="v-a")
    second = make.model_version(version="v-b")
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{MODEL}/compare", params=[("version_id", first.id), ("version_id", second.id)]
        )
    )

    assert len(body["versions"]) == 2
    assert isinstance(body["metric_keys"], list)
    assert body["caveats"]


def test_comparison_requires_at_least_two_versions(analyst_client, make, db):
    """
    Comparing one version with nothing is not a comparison.

    It would render as a table with one column, which reads as a result
    rather than as a mistake.
    """
    version = make.model_version()
    db.commit()

    assert_error(
        analyst_client.get(f"{MODEL}/compare", params={"version_id": version.id}), 422
    )


def test_comparison_is_bounded_to_three_versions(analyst_client, make, db):
    """
    Two or three, because the response embeds each version in full.

    An unbounded comparison is an unbounded response, and a table of twenty
    models is not something anybody reads.
    """
    versions = [make.model_version(version=f"v-{index}") for index in range(5)]
    db.commit()

    response = analyst_client.get(
        f"{MODEL}/compare",
        params=[("version_id", version.id) for version in versions],
    )

    assert response.status_code == 422


def test_comparing_an_unknown_version_is_404(analyst_client, make, db):
    version = make.model_version()
    db.commit()

    assert_error(
        analyst_client.get(
            f"{MODEL}/compare",
            params=[("version_id", version.id), ("version_id", "v-does-not-exist")],
        ),
        404,
    )


def test_a_comparison_carries_the_same_caveats_as_a_single_version(
    analyst_client, make, db
):
    """
    Comparison is where a metric is most likely to be over-read.

    "Version B is better" is the conclusion the table invites, and it is only
    supportable if both were evaluated the same way over comparable data —
    which the caveats and the split strategies are there to let somebody
    check.
    """
    first = make.model_version(version="v-a")
    second = make.model_version(version="v-b")
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{MODEL}/compare", params=[("version_id", first.id), ("version_id", second.id)]
        )
    )

    assert body["caveats"]
    joined = " ".join(body["caveats"]).lower()
    assert "synthetic" in joined or "label" in joined


# -----------------------------------------------------------------------------
# What model monitoring must not expose
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["status", "current", "limitations", "feature-schema", "versions"]
)
def test_no_model_surface_leaks_a_path_or_a_secret(analyst_client, make, db, path):
    make.model_version(
        version="v-leaky",
        artifact_path="/srv/muleguard/models/v-leaky/model.joblib",
        is_active=True,
    )
    db.commit()

    raw = analyst_client.get(f"{MODEL}/{path}").text.lower()

    for forbidden in (
        "/srv/muleguard",
        ".joblib",
        "secret_key",
        "postgresql://",
        "password_hash",
    ):
        assert forbidden not in raw, f"/{path} exposes {forbidden!r}"


def test_the_generator_config_does_not_expose_scenario_labels(
    analyst_client, make, db
):
    """
    A model version records how its data was generated, not what was planted.

    `generator_config_json` is provenance — the parameters of the run. If it
    carried the scenario assignments it would be the answer sheet, published
    through a read endpoint that every role can reach.
    """
    make.model_version(
        version="v-gen",
        generator_config_json={
            "seed": 20_260_120,
            "account_count": 5_000,
            "typologies": ["fan_in", "pass_through"],
        },
    )
    db.commit()

    raw = analyst_client.get(f"{MODEL}/versions").text.lower()

    assert "ground_truth" not in raw
    assert "ring_id" not in raw
