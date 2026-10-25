# Scenario fixtures

One file per typology. Each describes a shape of activity the platform is
meant to notice, in a form a test can build and a person can read.

## Why these are files and not code

The typologies are the product's substance, and they are argued about. Writing
them as data means the definition of "fan-in" is in one place, with its
parameters visible, rather than distributed across whichever tests happened to
need it. When someone disagrees that twelve senders in six hours is a
collection pattern, this is the file to disagree with.

`tests/factories.py` holds builders with the same names and the same defaults.
The builders are what the tests actually call; these files are the written
record of what the builders mean, plus the expectation of what should be
detected. `test_rules.py` reads them to check that the two have not drifted.

## Shape

```json
{
  "id": "fan_in",
  "label": "…",
  "description": "…",
  "parameters": { … },
  "expected": {
    "rule_codes": ["…"],
    "min_risk_band": "HIGH",
    "ground_truth_label": true
  },
  "confounders": ["…"],
  "notes": "…"
}
```

`parameters` are the knobs the builder takes. `expected` is what detection
should produce — and it is deliberately loose: a `min_risk_band` rather than a
score, because a test that pins an exact score fails every time a weight is
tuned, which trains people to update the expected value without reading it.

`confounders` is the field that matters most. Every one of these shapes has an
innocent twin, and the list names it. A detector that cannot tell a collection
account from a popular merchant is measuring popularity.

## `hard_negative.json` is not a bug

It describes activity that trips naive versions of these rules and is not
laundering. It carries `"ground_truth_label": false` and an empty
`rule_codes`. A suite made only of positives cannot measure a false-positive
rate, and the false-positive rate is what decides whether an analyst trusts
the queue.

## What the labels mean

`ground_truth_label` is the generator's intent, not a finding about the world.
Every metric computed against these labels measures agreement with what the
generator planted. That is a real and useful measurement — it is how a
regression in the detector is caught — and it is not an accuracy figure for
real fraud. The reports say so wherever such a number appears, and so does
this file.
