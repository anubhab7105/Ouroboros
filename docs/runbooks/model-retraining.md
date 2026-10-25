# Retraining the model

Read `docs/model-card.md` before acting on any number this produces. The short
version: the generator plants the typologies the rules look for, so a metric
from this pipeline measures agreement between the generator and the model. It
is a real check that training works end to end and no evidence at all about
detection quality on a real portfolio.

```bash
scripts/train_model.sh                        # 1000 accounts, grouped split
scripts/train_model.sh --accounts 5000 --split temporal
```

## What happens

1. `generate_data.py --with-labels` writes a dataset plus `labels.json`.
2. `evaluate_model.py` trains a bounded logistic model and evaluates it.
3. The metrics print, followed by what they do not mean.

Ground truth lives in its own file, not on the records. That is the whole
design: a label on an account record is one careless join away from being a
feature, and a model trained on a feature derived from its own label scores
perfectly in evaluation and uselessly in production.

## Choose the split deliberately

The default is `grouped`, and the default is the point.

| Split | Keeps apart | Use it when |
|---|---|---|
| `grouped` | A fraud ring stays whole | Default. Measures generalising to a new ring |
| `temporal` | Train is never later than test | Checking deployability |
| `random` | Nothing | Only to see how much the other two were protecting you |

A random split puts four accounts of a five-account ring in training and the
fifth in test, then reports how well the model memorised that ring. Run it
once, alongside `grouped`, and the gap between the two numbers is the size of
the leakage you would otherwise have shipped.

## The three leaks, and what guards each

**Target leakage** — a feature derived from the label. Guarded structurally
rather than by a split: the ingestion field blocklist, the feature-schema name
blocklist, and `assert_no_label_leakage`, which `evaluate_model.py` calls
before it will report anything. `tests/test_ml_leakage.py` is the module that
fails if any of them stops working.

If you are adding a feature and reaching for the scenario id or the ring id,
that is the signal to stop, not an obstacle to route around.

**Group leakage** — handled by `--split grouped`.

**Temporal leakage** — handled by `--split temporal`, and by the `as_of`
contract on feature snapshots. A snapshot contains only data from strictly
before its cutoff, and the boundary is strict rather than inclusive on
purpose: a transfer at exactly the cutoff is information from the instant
being predicted.

## Reading the metrics

ROC-AUC near 0.50 means the model learned nothing from the features it was
given. That is the expected result from `evaluate_model.py` as it stands,
because it uses only the account record's own fields — type and status — which
carry almost no signal about whether an account is a mule. The real feature
set is built from transaction history by `app/ml/features.py`.

Treat an AUC near 1.00 with more suspicion than one near 0.50. On this data it
usually means leakage rather than skill, and the first thing to check is which
split you ran.

Calibration matters as much as discrimination here. The score is shown to an
investigator as a priority ordering, so a model that ranks well and is wildly
overconfident produces a queue in roughly the right order with numbers nobody
should trust. The report includes Brier score and expected calibration error
for that reason.

## Determinism

Same seed, same dataset, same weights, same fingerprint. The model's
fingerprint is a hash of its parameters and options with wall-clock values
excluded, so retraining on the same input produces the same fingerprint and
the same model id — which is how you tell that a retrain changed nothing.

If the fingerprint changed and you expected it not to, something in the input
or the options did.

## When no model is registered

The platform does not fail. `app/ml/fallback.py` scores from hand-set weights
over named signals, and every assessment says `scoring_mode:
HEURISTIC_FALLBACK` with a caveat stating that the weights are hand-set rather
than learned.

That is less accurate and more honest, and the mode travels in the response so
an interface cannot present a heuristic as model output. Deploying without a
trained model is a supported state, not a broken one.

## What this pipeline cannot tell you

Whether detection works. For that you need labelled real data, a baseline to
compare against, and a measurement of what the current process catches without
the model — none of which this repository has or claims to have.

`docs/model-card.md` lists the specific things that would need to be true
before a number from here belonged in a sentence beginning "the model is".
