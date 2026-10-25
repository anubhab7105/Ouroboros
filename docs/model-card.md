# Model card

For the scoring in MULEGUARD, following the model-card format in spirit: what
it is, what it was measured on, and what it must not be used for.

The short version, because it is the only part that matters if you read
nothing else:

> **No number produced by this system is evidence about detection quality on
> real data.** Every metric here was computed on data a generator produced,
> and the generator plants the typologies the rules look for. A score from
> this pipeline measures agreement between the generator and the model.

## What it is

Two things, and which one ran is reported with every score.

### A trained supervised model

Binary logistic regression (softmax for multiclass), hand-written in
`app/ml/supervised.py`. No scikit-learn in the request path.

- Deterministic: same seed, same data, same weights, same fingerprint.
- Bounded: sample, feature, class, iteration and time limits.
- Calibrated on the validation split via Platt scaling, never on training
  data.
- Coefficients not exposed through the API — weights over named behavioural
  features are a map of how to evade the detector.

Hand-written because the model has to be explainable to an investigator and
reproducible months later, and because a dependency that deserialises an
artefact is arbitrary code execution. A linear model's contribution per
feature is a multiplication, which is the only kind of explanation that
survives contact with somebody asking "why this account?".

### A heuristic fallback

`app/ml/fallback.py`. Hand-set weights over named signals, used when no model
is registered.

It is less accurate and more honest about itself. Every assessment it produces
says `scoring_mode: HEURISTIC_FALLBACK`, carries a caveat stating that the
weights are hand-set rather than learned, and lists `signals_unavailable`.

Running with no trained model is a supported state, not a broken one. The mode
travels in the response so an interface cannot present a heuristic as model
output.

## Intended use

**Prioritising a queue for human review.** The score orders accounts so that
an analyst looks at the twenty most unusual rather than twenty at random. That
is the whole claim.

### Out of scope, explicitly

- Deciding whether an account holder committed a crime.
- Any automatic action. There is no capability and no `AccountStatus` value to
  write. ADR 0004.
- Evidence in a proceeding. A contribution is an operational attribution, not
  a causal account.
- Any use on real customer data in this configuration.

## Inputs

Behavioural aggregates from transaction history, computed as of a point in
time:

- velocity and burstiness over windows (1h, 24h, 7d, 30d)
- counterparty concentration and beneficiary entropy
- inflow and outflow value, and the ratio between them
- pass-through residual — how much of what arrives stays
- account age and dormancy
- graph degree and component size, bounded
- complaint correlation counts, by tier
- categorical: account type, status, channel mix

### What is deliberately not an input

Nothing that identifies a person: no names, no phone numbers, no addresses, no
device ids. Entity associations enter as counts and degrees over hashed
identifiers, never as the identifiers.

Nothing derived from the label: `ground_truth_label`, `scenario_type`,
`ring_id`. Guarded by the ingestion field blocklist, the feature-schema name
blocklist, and `assert_no_label_leakage`.

Nothing from after the `as_of` cutoff. The boundary is **strict**: a transfer
at exactly the cutoff is information from the instant being predicted.

## Point-in-time discipline

A feature snapshot contains only data from strictly before its cutoff, and the
snapshot is **stored** rather than recomputed.

Both halves matter. Strictness is what stops the model seeing the future;
storage is what lets a score be reproduced months later, when the underlying
transfers have been joined by thousands more.

`FEATURE_ALLOW_FUTURE_TRANSACTIONS`, `FEATURE_ALLOW_FUTURE_COMPLAINTS` and
`FEATURE_ALLOW_FUTURE_INVESTIGATION_OUTCOMES` are all false, and each names a
specific way a model can be made to look good by seeing the future. The last
is the subtlest: training on whether a case was eventually confirmed leaks the
outcome of the process the model is supposed to inform.

## Evaluation data

Synthetic, from `app/ingestion/generator.py`. A portfolio in which about 95% of
accounts and the large majority of transfers are ordinary, with four typologies
planted: fan-in collection, pass-through, layering chain, dormant
reactivation. Hard negatives are planted too — a merchant settling to a
processor, a payroll run — which look like typologies on three or four signals
and are not.

### Why metrics from it mean so little

The generator plants the typologies the rules look for. Measuring the model
against them is measuring whether two components agree about what the author
of both thought a mule account looks like.

That is a real and useful check: it verifies the pipeline end to end, catches
leakage, and shows that training converges. It is not a measurement of
detection quality, and the difference is not a technicality — the real
question is whether these features separate mule accounts from unusual-but-
legitimate ones in a portfolio nobody designed, and nothing here can answer
it.

## Metrics

Reported by `scripts/evaluate_model.py`: accuracy, precision, recall, F1
(macro, micro, weighted), ROC-AUC, PR-AUC, log loss, Brier score, expected
calibration error, and a confusion matrix.

Three notes on reading them.

**Calibration matters as much as discrimination.** The score is shown to an
investigator as a priority ordering, so a model that ranks well and is wildly
overconfident produces a queue in roughly the right order with numbers nobody
should trust. Brier score and ECE are in the report for that reason.

**An AUC near 1.00 deserves more suspicion than one near 0.50.** On this data
it usually means leakage. Check which split ran.

**An unavailable metric is reported as unavailable, never as zero.** Evaluating
on a split the dataset does not have returns `ok: false` with an issue, not a
report full of zeros. A zero precision and an uncomputed precision mean
opposite things to somebody deciding whether to trust a score.

### Splits

| Strategy | Keeps apart | Default? |
|---|---|---|
| `grouped` | A fraud ring stays whole | **yes** |
| `temporal` | Train is never later than test | no |
| `random` | Nothing | no |

`grouped` is the default because a random split puts four accounts of a
five-account ring in training and the fifth in test, then reports how well the
model memorised that ring. Run `random` once alongside `grouped`: the gap
between the two numbers is the size of the leakage you would otherwise have
shipped.

## Limitations

### Of the model

- **Linear.** No interaction terms unless engineered. A pattern that is only
  visible in a combination of signals is invisible to it.
- **No sequence modelling.** Order within a window is lost; a chronology that
  matters is flattened into an aggregate.
- **No concept drift handling.** Typologies change; the model does not notice.
- **Calibrated on synthetic data,** so the calibration is against a base rate
  the generator chose.

### Of the evaluation

- Synthetic data, planted typologies, no real-world baseline.
- No comparison against what the current process catches without the model,
  which is the comparison that would actually justify deploying it.
- No measurement of analyst effort per true positive, which is what determines
  whether a queue is usable.
- Hard negatives are the ones we thought of.

### Of the features

- Aggregates miss patterns that need sequence.
- Graph features are bounded, so a wide or deep structure is partially seen —
  and **a truncated traversal establishes nothing**.
- Complaint correlations depend on complaints being filed, which is a biased
  process: the accounts that get reported are the ones whose victims noticed
  and knew where to complain.

## Fairness

**Not assessed, and the honest reason is that it cannot be from here.**

There is no protected-attribute data in the system — no names, no addresses,
no demographics — so a disparate-impact analysis is not possible, by design.

That is a privacy-protective choice with a real cost: the absence of the data
means the absence of the measurement, not the absence of the problem. Several
features are plausible proxies. Account age penalises recently-opened
accounts, which correlates with recent arrival in a country or in formal
banking. Channel mix differs by region and by income. Dormancy patterns differ
for seasonal and migrant workers.

A deployment on real data would need a fairness assessment, which would need
demographic data held under a lawful basis for exactly that purpose, which is
a programme rather than a configuration change. This document cannot discharge
that obligation and does not pretend to.

## Reproducing a score

Four things identify a score, and all four are stored with it:

```
model version   + dataset fingerprint
feature schema  + as_of
```

A model's fingerprint is a hash of its parameters and options with wall-clock
values excluded, so retraining on the same input gives the same fingerprint
and the same model id — which is how you tell a retrain changed nothing.

The feature snapshot is stored, so the inputs are recoverable rather than
recomputable.

## Before any number from here is used as evidence

What would have to be true. Most of it is not code.

1. Labelled real data, held under a lawful basis, with a retention schedule.
2. A baseline: what the current process catches without this.
3. Evaluation on real data with grouped and temporal splits.
4. A fairness assessment against protected attributes.
5. Measured analyst effort per true positive.
6. Monitoring for drift, with a review cadence and somebody who owns it.
7. An appeals process for an account holder affected by a decision informed by
   a score.

Until then, the score is a way of ordering a queue, and that is all it is.
