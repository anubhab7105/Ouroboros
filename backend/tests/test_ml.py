"""
The bounded supervised layer: training, evaluation, prediction.

This module is the one place in the platform that fits a model. Everything
about it is deliberately small — logistic and softmax regression, hand-rolled,
no scikit-learn in the request path — because a fraud platform that cannot
explain a score cannot defend one.

Four properties are worth more than the rest, and each is here because
breaking it produces a plausible-looking system that is wrong:

**A design matrix is never silently zero.** The natural way to hand in
features is a numeric matrix with the column names supplied separately. If
those rows reach the vectorizer as nameless sequences and come out as zeros,
training still "succeeds": the loss curve descends, the status reads
EVALUATED, and ROC-AUC is 0.50 because the model saw nothing. There is no
exception to catch. So rows that carry no recognizable column are reported,
and vector rows are paired with the declared names positionally.

**Unavailable metrics are unavailable, not zero.** Evaluating on a split the
dataset does not have returns `ok=False` and an issue, not a report full of
zeros. A zero precision and an uncomputed precision mean opposite things to an
investigator deciding whether to trust a score.

**Training is deterministic, and the fingerprint proves it.** The same dataset
and options must produce the same weights *and* the same fingerprint, because
the fingerprint is how two models are told apart and how a retrain is shown to
be a no-op. Hashing a wall-clock duration would make every identical model
look new.

**Labels never become features.** The synthetic generator stamps
`ground_truth_label`, `scenario_type` and `ring_id` on every labelled account,
so target leakage is always one careless join away. By default a row carrying
such a field is refused outright rather than quietly stripped.

`app/ml/supervised.py` depends only on the standard library, so these tests
exercise the real trainer rather than a description of it.
"""

from __future__ import annotations

import dataclasses
import math
import random

import pytest

from app.ml.supervised import (
    CalibrationMethod,
    ModelFamily,
    ModelStatus,
    SplitName,
    SupervisedOptions,
    SupervisedTrainer,
    TaskType,
    build_training_dataset,
    evaluate_supervised_model,
    get_registered_model,
    list_registered_models,
    predict_supervised_model,
    register_model,
    train_supervised_model,
)

pytestmark = pytest.mark.ml


# -----------------------------------------------------------------------------
# Synthetic inputs
#
# Separable on purpose. A test that asserts "the model learned something" needs
# data where failing to learn is unambiguous, so the two classes sit four
# standard deviations apart on two of the three columns and the third column is
# pure noise that the model should weight near zero.
# -----------------------------------------------------------------------------


def separable_rows(
    count: int = 240,
    *,
    seed: int = 5,
    split: bool = True,
) -> tuple[list[dict[str, float]], list[int], list[str] | None]:
    """
    Build separable binary rows, their labels, and an explicit split column.
    """
    generator = random.Random(seed)
    rows: list[dict[str, float]] = []
    labels: list[int] = []
    splits: list[str] = []

    train_end = (count * 2) // 3
    validation_end = (count * 5) // 6

    for index in range(count):
        positive = index % 2 == 0

        rows.append(
            {
                "amount_zscore": generator.gauss(2.0 if positive else -2.0, 0.6),
                "inflow_count_7d": generator.gauss(1.5 if positive else -1.5, 0.6),
                "unrelated_noise": generator.gauss(0.0, 1.0),
            }
        )
        labels.append(1 if positive else 0)

        if index < train_end:
            splits.append(SplitName.TRAIN.value)
        elif index < validation_end:
            splits.append(SplitName.VALIDATION.value)
        else:
            splits.append(SplitName.TEST.value)

    return rows, labels, (splits if split else None)


def separable_vectors(
    count: int = 240,
    *,
    seed: int = 5,
) -> tuple[list[list[float]], list[int], list[str], tuple[str, ...]]:
    """
    Build the same data as a bare numeric matrix with names held separately.
    """
    rows, labels, splits = separable_rows(count, seed=seed)
    names = ("amount_zscore", "inflow_count_7d", "unrelated_noise")
    matrix = [[row[name] for name in names] for row in rows]
    return matrix, labels, list(splits or ()), names


def three_class_rows(
    count: int = 300,
    *,
    seed: int = 3,
) -> tuple[list[dict[str, float]], list[int], list[str]]:
    """
    Build three well-separated clusters for the multiclass path.
    """
    generator = random.Random(seed)
    centers = {0: (-2.0, 0.0), 1: (2.0, 2.0), 2: (0.0, -2.5)}
    rows: list[dict[str, float]] = []
    labels: list[int] = []
    splits: list[str] = []

    train_end = (count * 7) // 10
    validation_end = (count * 17) // 20

    for index in range(count):
        label = index % 3
        center_x, center_y = centers[label]

        rows.append(
            {
                "cluster_x": generator.gauss(center_x, 0.5),
                "cluster_y": generator.gauss(center_y, 0.5),
            }
        )
        labels.append(label)

        if index < train_end:
            splits.append(SplitName.TRAIN.value)
        elif index < validation_end:
            splits.append(SplitName.VALIDATION.value)
        else:
            splits.append(SplitName.TEST.value)

    return rows, labels, splits


def issue_codes(dataset) -> set[str]:
    """
    Collect issue codes from a dataset's public metadata.
    """
    return {str(issue.get("code")) for issue in dataset.metadata.get("issues") or ()}


# -----------------------------------------------------------------------------
# Dataset construction
# -----------------------------------------------------------------------------


class TestDatasetConstruction:
    """Turning caller input into a design matrix."""

    def test_mapping_rows_build_named_columns(self):
        rows, labels, splits = separable_rows(60)

        dataset = build_training_dataset(rows, labels, splits=splits)

        assert dataset.feature_names == (
            "amount_zscore",
            "inflow_count_7d",
            "unrelated_noise",
        )
        assert len(dataset.x) == 60
        assert len(dataset.y) == 60
        assert all(len(row) == 3 for row in dataset.x)

    def test_vector_rows_are_paired_with_declared_names(self):
        """
        A numeric matrix plus a name list is the ordinary shape of a feature
        set. Pairing them positionally must give the same matrix as the
        equivalent mappings — not a matrix of zeros.
        """
        matrix, labels, splits, names = separable_vectors(60)
        rows, _, _ = separable_rows(60)

        from_vectors = build_training_dataset(
            matrix,
            labels,
            splits=splits,
            feature_names=names,
        )
        from_mappings = build_training_dataset(rows, labels, splits=splits)

        assert from_vectors.feature_names == from_mappings.feature_names
        assert from_vectors.x == from_mappings.x

    def test_vector_rows_without_names_get_positional_names(self):
        dataset = build_training_dataset(
            [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]],
            [1, 0],
        )

        assert dataset.feature_names == (
            "feature_0000",
            "feature_0001",
            "feature_0002",
        )
        assert dataset.x == ((1.0, 2.0, 3.0), (4.0, 5.0, 6.0))

    def test_positional_names_keep_column_order_past_ten_columns(self):
        """
        Column order is recovered by sorting the resolved names, and
        "feature_10" sorts before "feature_2". Zero padding is what keeps the
        twelfth column twelfth.
        """
        width = 12
        row = [float(index) for index in range(width)]

        dataset = build_training_dataset([row, row], [1, 0])

        assert len(dataset.feature_names) == width
        assert dataset.x[0] == tuple(row)

    def test_ragged_vector_rows_are_reported(self):
        dataset = build_training_dataset(
            [[1.0, 2.0, 3.0], [4.0, 5.0]],
            [1, 0],
        )

        assert "ragged_vector_rows" in issue_codes(dataset)

    def test_undeclared_trailing_columns_are_reported(self):
        dataset = build_training_dataset(
            [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]],
            [1, 0],
            feature_names=("first", "second"),
        )

        assert "vector_columns_undeclared" in issue_codes(dataset)
        assert dataset.feature_names == ("first", "second")

    def test_rows_matching_no_resolved_column_are_reported(self):
        """
        The silent failure this guards: a row whose columns share no name with
        the resolved set vectorizes to zeros, which is indistinguishable
        downstream from an account that genuinely scored zero everywhere.
        """
        dataset = build_training_dataset(
            [{"wrong_name": 1.0}, {"wrong_name": 2.0}],
            [1, 0],
            feature_names=("expected_name",),
        )

        assert "rows_without_resolved_features" in issue_codes(dataset)

    def test_label_like_fields_reject_the_whole_row_by_default(self):
        """
        Fail closed. A row carrying `ground_truth_label` is refused rather than
        stripped, because stripping leaves no trace that the caller's pipeline
        is joining the label onto the features.
        """
        rows, labels, splits = separable_rows(60)
        tainted = [
            dict(row, ground_truth_label=label) for row, label in zip(rows, labels)
        ]

        dataset = build_training_dataset(tainted, labels, splits=splits)

        assert dataset.counts["processed"] == 0
        assert "forbidden_feature" in issue_codes(dataset)

    def test_dropping_forbidden_fields_is_opt_in_and_still_reported(self):
        rows, labels, splits = separable_rows(60)
        tainted = [
            dict(row, ground_truth_label=label) for row, label in zip(rows, labels)
        ]
        options = dataclasses.replace(SupervisedOptions(), drop_forbidden_fields=True)

        dataset = build_training_dataset(
            tainted,
            labels,
            splits=splits,
            options=options,
        )

        assert dataset.counts["processed"] == 60
        assert "ground_truth_label" not in dataset.feature_names
        assert "forbidden_feature_dropped" in issue_codes(dataset)

    def test_sample_limit_truncates_and_says_so(self):
        rows, labels, splits = separable_rows(240)
        options = dataclasses.replace(SupervisedOptions(), max_samples=50)

        dataset = build_training_dataset(
            rows,
            labels,
            splits=splits,
            options=options,
        )

        assert dataset.counts["submitted"] == 240
        assert dataset.counts["processed"] == 50
        assert "dataset_sample_truncated" in issue_codes(dataset)

    def test_explicit_splits_are_honoured(self):
        rows, labels, splits = separable_rows(240)

        dataset = build_training_dataset(rows, labels, splits=splits)

        assert dataset.counts["train"] == 160
        assert dataset.counts["validation"] == 40
        assert dataset.counts["test"] == 40


# -----------------------------------------------------------------------------
# Training
# -----------------------------------------------------------------------------


class TestTraining:
    """Fitting a model, and refusing to."""

    def test_binary_logistic_learns_separable_data(self):
        rows, labels, splits = separable_rows()

        model = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        weights = model.parameters.weights[0]
        names = model.parameters.feature_names
        by_name = dict(zip(names, weights))

        assert model.parameters.task == TaskType.BINARY
        assert by_name["amount_zscore"] > 1.0
        assert by_name["inflow_count_7d"] > 1.0
        assert abs(by_name["unrelated_noise"]) < 0.5

    def test_vector_input_trains_identically_to_mapping_input(self):
        """
        The regression this pins: vector rows used to vectorize to zeros, so
        the model trained to all-zero weights and chance accuracy while
        reporting a clean descent and an EVALUATED status.
        """
        rows, labels, splits = separable_rows()
        matrix, _, _, names = separable_vectors()

        from_mappings = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )
        from_vectors = train_supervised_model(
            matrix,
            labels,
            splits=splits,
            feature_names=names,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        assert from_vectors.parameters.weights == from_mappings.parameters.weights
        assert not all(
            value == 0.0
            for row in from_vectors.parameters.weights
            for value in row
        )

    def test_binary_data_resolves_to_logistic_regression(self):
        rows, labels, splits = separable_rows()

        model = train_supervised_model(rows, labels, splits=splits)

        assert model.family == ModelFamily.LOGISTIC_REGRESSION
        assert model.parameters.task == TaskType.BINARY

    def test_multiclass_data_resolves_to_softmax_regression(self):
        rows, labels, splits = three_class_rows()

        model = train_supervised_model(rows, labels, splits=splits)

        assert model.family == ModelFamily.SOFTMAX_REGRESSION
        assert model.parameters.task == TaskType.MULTICLASS
        assert len(model.parameters.weights) == 3
        assert len(model.parameters.intercept) == 3

    def test_single_class_data_resolves_to_the_prior(self):
        """
        One class carries no decision boundary. The prior is the honest answer:
        it predicts the base rate and says so, rather than fitting a boundary
        to noise.
        """
        rows, _, splits = separable_rows()
        labels = [1] * len(rows)

        model = train_supervised_model(rows, labels, splits=splits)

        assert model.family == ModelFamily.BASELINE_PRIOR

    def test_the_prior_has_no_feature_weights_and_encodes_the_base_rate(self):
        """
        The prior is the floor every other family has to beat. It reads the
        base rate off the training split and nothing else, so its intercept is
        the log-odds of that rate and its feature weights are exactly zero.
        """
        rows, _, splits = separable_rows(240)
        labels = [1 if index % 4 == 0 else 0 for index in range(240)]

        model = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.BASELINE_PRIOR,
        )
        train_labels = [
            label
            for label, split in zip(labels, splits or ())
            if split == SplitName.TRAIN.value
        ]
        rate = sum(train_labels) / len(train_labels)

        assert all(
            value == 0.0 for row in model.parameters.weights for value in row
        )
        assert pytest.approx(model.parameters.intercept[0], abs=1e-4) == math.log(
            rate / (1.0 - rate)
        )

    def test_training_records_its_loss_history(self):
        rows, labels, splits = separable_rows()

        model = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )
        history = model.parameters.metadata.get("history") or model.training_history

        assert history
        losses = [float(entry["train_loss"]) for entry in history]
        assert losses[-1] < losses[0]

    def test_identical_inputs_produce_an_identical_fingerprint(self):
        """
        The fingerprint identifies the model and seeds its id, so a retrain
        that changed nothing must be recognizable as such. Wall-clock values
        are reported but never hashed.
        """
        rows, labels, splits = separable_rows()

        first = train_supervised_model(rows, labels, splits=splits)
        second = train_supervised_model(rows, labels, splits=splits)

        assert first.parameters.weights == second.parameters.weights
        assert first.fingerprint == second.fingerprint
        assert first.model_id == second.model_id
        assert first.parameters.metadata.get("training_elapsed_ms") is not None

    def test_different_data_produces_a_different_fingerprint(self):
        rows_a, labels_a, splits_a = separable_rows(seed=5)
        rows_b, labels_b, splits_b = separable_rows(seed=99)

        first = train_supervised_model(rows_a, labels_a, splits=splits_a)
        second = train_supervised_model(rows_b, labels_b, splits=splits_b)

        assert first.fingerprint != second.fingerprint

    def test_disabled_training_returns_a_draft_with_a_reason(self):
        rows, labels, splits = separable_rows(60)
        options = dataclasses.replace(SupervisedOptions(), enabled=False)
        dataset = build_training_dataset(rows, labels, splits=splits)

        model = SupervisedTrainer(options).train(dataset)

        assert model.status == ModelStatus.DRAFT
        assert model.parameters.weights == ()
        assert [issue.code for issue in model.issues] == ["supervised_disabled"]

    def test_non_synthetic_data_is_refused(self):
        """
        This layer is a prototype trained on generated data. Pointing it at a
        live dataset is refused rather than permitted with a warning.
        """
        rows, labels, splits = separable_rows(60)
        options = dataclasses.replace(SupervisedOptions(), dataset_mode="live")
        dataset = build_training_dataset(rows, labels, splits=splits)

        model = SupervisedTrainer(options).train(dataset)

        assert model.status == ModelStatus.DRAFT
        assert "non_synthetic_dataset" in [issue.code for issue in model.issues]

    def test_empty_dataset_is_refused(self):
        options = SupervisedOptions()
        dataset = build_training_dataset([], [], options=options)

        model = SupervisedTrainer(options).train(dataset)

        assert model.status == ModelStatus.DRAFT
        assert "empty_training_dataset" in [issue.code for issue in model.issues]


# -----------------------------------------------------------------------------
# Evaluation
# -----------------------------------------------------------------------------


class TestEvaluation:
    """Measuring a model, and declining to."""

    def test_binary_metrics_are_computed_on_the_held_out_split(self):
        rows, labels, splits = separable_rows()
        dataset = build_training_dataset(rows, labels, splits=splits)
        model = SupervisedTrainer(SupervisedOptions()).train(
            dataset,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        report = evaluate_supervised_model(model, dataset, split=SplitName.TEST.value)

        assert report.ok is True
        assert report.split_used == SplitName.TEST.value
        assert report.counts["evaluated"] == 40
        assert report.counts["skipped"] == 0
        assert report.metrics["roc_auc"] > 0.95
        assert report.metrics["accuracy"] > 0.9
        assert report.metrics["log_loss"] < 0.5

    def test_a_missing_split_is_unavailable_not_zero(self):
        """
        A dataset with no test rows has no test metrics. Reporting zeros would
        read as a model that failed, which is a different claim from a model
        that was not measured.
        """
        rows, labels, _ = separable_rows(split=False)
        dataset = build_training_dataset(rows, labels)
        model = SupervisedTrainer(SupervisedOptions()).train(
            dataset,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        report = evaluate_supervised_model(model, dataset, split=SplitName.TEST.value)

        assert report.ok is False
        assert report.metrics == {}
        assert "evaluation_split_unavailable" in [
            issue.code for issue in report.issues
        ]

    def test_multiclass_metrics_map_every_class(self):
        """
        Model metadata is normalized into a JSON-safe form, which turns the
        integer class codes of the class mapping into strings. A consumer
        looking the mapping up by integer then matches nothing and every
        multiclass evaluation reports no mapped classes.
        """
        rows, labels, splits = three_class_rows()
        dataset = build_training_dataset(rows, labels, splits=splits)
        model = SupervisedTrainer(SupervisedOptions()).train(dataset)

        report = evaluate_supervised_model(model, dataset, split=SplitName.TEST.value)

        assert report.ok is True
        assert report.counts["skipped"] == 0
        assert report.metrics["accuracy"] > 0.9
        assert report.metrics["macro_f1"] > 0.9
        assert len(report.class_metrics) == 3

    def test_confusion_matrix_is_square_over_the_model_classes(self):
        rows, labels, splits = three_class_rows()
        dataset = build_training_dataset(rows, labels, splits=splits)
        model = SupervisedTrainer(SupervisedOptions()).train(dataset)

        report = evaluate_supervised_model(model, dataset, split=SplitName.TEST.value)
        matrix = report.confusion["matrix"]

        assert len(matrix) == 3
        assert all(len(row) == 3 for row in matrix)
        assert sum(sum(row) for row in matrix) == report.counts["evaluated"]
        assert report.confusion["normalization"] == "counts"

    def test_calibration_is_fitted_on_validation_data(self):
        """
        Calibration fitted on the training split would be fitted on data the
        weights already saw, and the reliability curve would flatter itself.
        """
        rows, labels, splits = separable_rows()
        dataset = build_training_dataset(rows, labels, splits=splits)
        model = SupervisedTrainer(SupervisedOptions()).train(
            dataset,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        report = evaluate_supervised_model(model, dataset, split=SplitName.TEST.value)

        assert report.calibration["fitted_on_validation"] is True
        assert report.calibration["method"] == CalibrationMethod.PLATT.value
        assert report.calibration["loss_after"] <= report.calibration["loss_before"]

    def test_evaluation_of_identical_models_is_reproducible(self):
        rows, labels, splits = separable_rows()
        dataset = build_training_dataset(rows, labels, splits=splits)
        trainer = SupervisedTrainer(SupervisedOptions())

        first = evaluate_supervised_model(
            trainer.train(dataset, model_family=ModelFamily.LOGISTIC_REGRESSION),
            dataset,
            split=SplitName.TEST.value,
        )
        second = evaluate_supervised_model(
            trainer.train(dataset, model_family=ModelFamily.LOGISTIC_REGRESSION),
            dataset,
            split=SplitName.TEST.value,
        )

        assert first.fingerprint == second.fingerprint


# -----------------------------------------------------------------------------
# Prediction
# -----------------------------------------------------------------------------


class TestPrediction:
    """Scoring new rows."""

    def test_scores_separate_the_two_classes(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        batch = predict_supervised_model(model, rows[:20])
        positives = [
            prediction.score
            for prediction, label in zip(batch.predictions, labels[:20])
            if label == 1
        ]
        negatives = [
            prediction.score
            for prediction, label in zip(batch.predictions, labels[:20])
            if label == 0
        ]

        assert min(positives) > max(negatives)

    def test_every_score_is_a_probability_with_a_band(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        batch = predict_supervised_model(model, rows[:20])

        assert batch.ok is True
        assert len(batch.predictions) == 20

        for prediction in batch.predictions:
            assert 0.0 <= prediction.score <= 1.0
            assert prediction.risk_band in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
            assert prediction.label_code in {0, 1}
            assert pytest.approx(sum(prediction.probabilities.values()), abs=1e-4) == 1.0

    def test_contributions_name_the_features_that_moved_the_score(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        batch = predict_supervised_model(model, rows[:1], include_contributions=True)
        contributions = batch.predictions[0].contributions
        names = [entry["feature"] for entry in contributions]

        assert set(names) <= set(model.parameters.feature_names)
        assert names[0] in {"amount_zscore", "inflow_count_7d"}
        assert all(
            entry["interpretation"] == "operational attribution only, not causal proof"
            for entry in contributions
        )

    def test_contributions_are_ordered_by_magnitude(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        batch = predict_supervised_model(model, rows[:1])
        magnitudes = [entry["magnitude"] for entry in batch.predictions[0].contributions]

        assert magnitudes == sorted(magnitudes, reverse=True)

    def test_vector_rows_predict_the_same_as_mapping_rows(self):
        rows, labels, splits = separable_rows()
        matrix, _, _, _ = separable_vectors()
        model = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        from_mappings = predict_supervised_model(model, rows[:10])
        from_vectors = predict_supervised_model(model, matrix[:10])

        assert [p.score for p in from_vectors.predictions] == [
            p.score for p in from_mappings.predictions
        ]

    def test_multiclass_prediction_attributes_to_the_predicted_class(self):
        rows, labels, splits = three_class_rows()
        model = train_supervised_model(rows, labels, splits=splits)

        batch = predict_supervised_model(model, rows[:6])

        assert all(
            prediction.label_code in {0, 1, 2} for prediction in batch.predictions
        )
        assert all(prediction.contributions for prediction in batch.predictions)

    def test_prediction_limit_truncates_and_says_so(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(
            rows,
            labels,
            splits=splits,
            model_family=ModelFamily.LOGISTIC_REGRESSION,
        )

        batch = predict_supervised_model(model, rows, max_predictions=5)

        assert len(batch.predictions) == 5
        assert "prediction_sample_truncated" in [
            issue.code for issue in batch.issues
        ]


# -----------------------------------------------------------------------------
# What leaves the module
# -----------------------------------------------------------------------------


class TestPublicSurface:
    """The boundary between internal parameters and what callers see."""

    def test_public_model_omits_coefficients_by_default(self):
        """
        Coefficients over named behavioural features are a map of how to evade
        the detector. They stay behind an explicit flag.
        """
        rows, labels, splits = separable_rows()
        model = train_supervised_model(rows, labels, splits=splits)

        public = model.to_public_dict()

        assert public["parameters"]["coefficients_omitted"] is True
        assert "weights" not in public["parameters"]
        assert "intercept" not in public["parameters"]

    def test_internal_model_keeps_coefficients(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(rows, labels, splits=splits)

        internal = model.to_internal_dict()

        assert internal["parameters"]["weights"]

    def test_public_model_carries_its_caveats(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(rows, labels, splits=splits)

        public = model.to_public_dict()
        caveats = " ".join(public["caveats"]).lower()

        assert "synthetic" in caveats
        assert "not production-ready" in caveats
        assert "adverse" in caveats

    def test_prediction_batch_carries_its_caveats(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(rows, labels, splits=splits)

        batch = predict_supervised_model(model, rows[:3])
        caveats = " ".join(batch.metadata["caveats"]).lower()

        assert "prioritization" in caveats
        assert "not probabilities of guilt" in caveats

    def test_registry_round_trips_a_model(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(rows, labels, splits=splits)

        model_id = register_model(model)
        recovered = get_registered_model(model_id)

        assert model_id == model.model_id
        assert recovered is not None
        assert recovered.fingerprint == model.fingerprint

    def test_registry_listing_omits_coefficients(self):
        rows, labels, splits = separable_rows()
        model = train_supervised_model(rows, labels, splits=splits)
        register_model(model)

        listing = list_registered_models()
        entry = next(row for row in listing if row["model_id"] == model.model_id)

        assert "weights" not in entry
        assert "intercept" not in entry
        assert entry["feature_count"] == 3
