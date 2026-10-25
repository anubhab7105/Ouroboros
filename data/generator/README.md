# The synthetic generator

The code is `backend/app/ingestion/generator.py`. This file is about what it
produces and why it is shaped the way it is; the module's own docstring covers
the API.

Run it through the script rather than importing it:

```bash
python scripts/generate_data.py --accounts 500 --transactions 20000 --seed 42 \
                                --out data/generated/run-42
```

## What it generates

A portfolio, not a list of suspicious things. Roughly 95% of the accounts and
the overwhelming majority of the transfers are ordinary, because a generator
that emits mostly typologies produces a dataset on which anything scores well
and nothing is learned.

Accounts are drawn from behavioural profiles — retail, business, wallet,
dormant, source, mule, funnel, beneficiary — and the profile shapes the
activity rather than labelling the account. The profile is generator-internal
and is never written to the account record.

Four typologies are planted:

**Fan-in collection.** Many unrelated senders paying one account inside a
short window. The parameters that matter are the sender count and the window,
not the amounts; a collection account taking ₹2,000 from forty people is the
same shape as one taking ₹200,000 from four.

**Pass-through.** Money in and almost all of it straight back out, with a
small remainder kept. The remainder is the signature. An ordinary account that
forwards a payment keeps a round number or nothing at all; a pass-through
keeps a commission, and the hold time is minutes rather than days.

**Layering chain.** A to B to C to D, each hop shedding a little. Generated to
a configured depth so the bounded traversal in `app/services/graph.py` has
something to find and something to be cut off by.

**Dormant reactivation.** An account quiet for months, then a sudden inbound.
This one is independent of amount and of counterparty count, which is why it
earns a rule of its own rather than a threshold on an existing one.

## Three things it does deliberately

**It plants ground truth and refuses to let you use it.**
`ground_truth_label`, `scenario_type` and `ring_id` are attached to every
generated account, because without them you cannot measure precision and
recall at all. They are also the single largest leakage risk in the
repository: a model trained on a feature derived from them scores perfectly in
evaluation and uselessly in production.

So they are blocked at four layers rather than one — the ingestion field
blocklist, the feature-schema name blocklist, `assert_no_label_leakage`, and
the API response models, none of which will carry them. `tests/test_ml_leakage.py`
is the module that fails if any of those stops working. If you are adding a
feature and find yourself reaching for the scenario id, that is the signal to
stop rather than the obstacle to route around.

**It generates hard negatives on purpose.** A merchant settling to a
processor, a payroll run, a business with genuinely many counterparties. These
look like typologies on three or four signals and are not. A generator without
them produces a dataset where the easy rule works, and the first contact with
a real portfolio is where you discover what it was actually measuring.

**It produces the vocabulary the database accepts, because it imports it.**
The generator used to declare its own `AccountType`, `AccountStatus`,
`TransactionStatus`, `Channel`, `EntityType`, `MatchMethod` and
`VerificationState`, and all seven had drifted from the enums the columns are
declared over. Generated accounts came out as `SAVINGS`, which the account-type
column cannot hold, so the generate-then-ingest path — the whole demo — could
not complete. It now imports them from `app/core/vocabularies.py`, which is
the one place they are defined.

## Determinism

Same seed, same dataset. The generator is seeded explicitly and uses no
unseeded randomness, no wall-clock in record content, and no dict iteration
order for anything that reaches output.

That is what makes a generated dataset citable: `--seed 42` at generator
version `v1` identifies a specific set of records, so a metric from last week
can be reproduced rather than approximated. It is also why `data/generated/` is
gitignored — a committed dataset is a large file that says less than the two
values that produced it.

Timestamps are relative to the generation time, so a dataset regenerated
tomorrow has the same shape at a different offset. If you need absolute
reproducibility including timestamps, pass `--as-of`.

## What it will not generate

- Real or re-identifiable data. Identifiers are hashed; the raw values exist
  only inside the generator and are never emitted.
- Names, addresses or phone numbers that resolve to a real person. The
  identifier pool is synthetic strings, which is also why there is no `NAME`
  entity type to generate into.
- A dataset that proves the platform works. The typologies are the ones the
  rules look for, which makes the output useful for a demo and useless as
  evidence of detection quality. Measuring that needs data this generator did
  not produce, and `docs/model-card.md` says so in more detail.
