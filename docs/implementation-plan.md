# Implementation plan

What was built, in what order, and — more usefully — what is left and what
should be approached carefully.

## Status

| Area | State |
|---|---|
| Database schema, 23 tables, migrations | Complete |
| Ingestion: normalize, validate, dedupe, provenance | Complete |
| Synthetic generator | Complete |
| Feature engineering, point-in-time | Complete |
| Rules engine and typology rules | Complete |
| Supervised model and heuristic fallback | Complete |
| Risk fusion | Complete |
| Bounded graph traversal and money trails | Complete |
| Complaint correlation, five tiers | Complete |
| Alerts and triage | Complete |
| Case workflow and state machine | Complete |
| Audit trail | Complete |
| PDF reports | Complete |
| Dashboard | Complete |
| Permission matrix, four roles | Complete |
| API, 15 endpoint modules | Complete |
| Frontend | Complete |
| Test suite, 39 modules | Written; **not executed as a suite** |
| Documentation, ADRs, runbooks | Complete |

### The one thing to fix first

`pytest`, `fastapi`, `sqlalchemy` and `httpx` could not be installed in the
environment where this was written — no package index was reachable — so the
suite has never run.

301 assertions from the pure modules were executed directly and all pass, and
two static checkers run clean over 157 files. The rest has been verified by
reading, which found and fixed several real defects, and reading is not
running.

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

Expect failures, and expect most of them to be in the tests rather than the
application. An assertion written against code without being run has a typo in
it roughly as often as not. `docs/testing.md` says which failures would be
worth taking seriously.

## How it was built

Roughly in this order, and the order mattered twice.

1. **Schema and migrations first.** Everything else is a projection of the
   data model, and getting the enums and the nullability right early avoided
   a class of rework.
2. **Ingestion before detection.** A detection pipeline with no data is
   untestable, and the validation rules turned out to encode most of the
   domain decisions.
3. **The generator before the model.** The hard negatives in the generator
   shaped the rules more than the typologies did.
4. **Rules before the model.** The rules are explainable and the model is a
   refinement; building them in the other order produces a system nobody can
   defend.
5. **The case state machine before the case endpoints.** Writing the machine
   as a pure function, with an exhaustive test, meant the endpoints had
   something to enforce rather than something to approximate.
6. **The API, then the frontend.**
7. **Tests throughout, documentation last** — which is the wrong order for
   documentation and is why several documents found bugs.

### What writing the documentation found

Worth recording, because it is the argument for writing it at all.

Documenting the configuration surface found fourteen security-header settings
that the middleware read and the settings model did not declare. Since the
model ignores unknown variables, every one of them was inert: HSTS could be
switched on without a max-age, and CSP with nowhere to send reports.

Documenting the data dictionary found that four layers each carried their own
copy of the ingested-record vocabularies — the ORM, the ingestion normalizer,
the ingestion validator, the generator and the feature builder — and that the
copies had drifted apart on every single field. Account type was the clearest:
the database accepted `INDIVIDUAL`, `BUSINESS`, `MERCHANT`, `OTHER`, while
ingestion accepted `SAVINGS`, `CURRENT`, `WALLET`, `UPI`, `CARD`, `OTHER`.
They shared one value. A correct record failed validation, an accepted record
failed on insert, the generator's output could not be loaded at all, and the
account-type feature was constant in every vector the model ever saw.

Documenting the case workflow found that the endpoint module carried a second
transition table that disagreed with the published state machine: no `TRIAGED`
row at all, so a triaged case could not move anywhere, and a phantom
`UNDER_REVIEW` status — an *alert* state — being written into a column that
cannot hold it. Starting an investigation, the central action of the product,
could not complete.

None of those three raised an error naming the cause.

## What is left

### Should be done next

**Run the suite.** Above.

**Wire `/metrics` or remove the setting.** `PROMETHEUS_ENABLED` exists and the
exposition is partial. A setting that half works is worse than one that does
not exist.

**Generate the frontend API client.** The types in `frontend/src/types/` are
hand-written, so they can drift from the response models and a mismatch shows
up as `undefined` in a table cell. The OpenAPI document is there; generating
from it would make the drift impossible.

**Reconcile `app/schemas/`.** It exists, it is not what the API returns, and
the endpoint modules declare their own models. Either make it the authority or
delete it — right now it is a second answer to "what does this endpoint
return", and the fact that its case vocabularies were *correct* while the
endpoint's were wrong is exactly how that costs somebody an afternoon.

**Decide what `app/graph/` is for.** A parallel analytics layer the endpoints
do not use. It has real capabilities the service layer lacks — community
detection, global metrics — and either they should be reachable or the layer
should go.

### Worth doing

- **Bulk alert actions.** A hundred false positives are a hundred clicks.
- **Saved views.** Every analyst rebuilds the same filter.
- **Field-level access logging on narratives.** A senior reading two hundred
  narratives looks exactly like one reading two.
- **A shared rate limiter.** The current one is in-process, so limits are per
  worker and nothing is shared across instances.
- **Case-to-case linking.** A network investigated as several cases has no
  representation of being one thing.
- **Ingestion drift detection.** A feed that slowly changes shape is not
  noticed.

### Deliberately not planned

| Not planned | Why |
|---|---|
| Automatic enforcement | ADR 0004. No capability, no enum value, five settings refused at startup |
| Real-time streaming | ADR 0001. The next step would be a background worker sharing this codebase |
| A graph database | ADR 0002 |
| Unbounded traversal | ADR 0007 |
| Real data support | ADR 0003, `docs/compliance-note.md` |
| Model artefact upload | Arbitrary code execution |

## Where the hard parts turned out to be

Not where expected, which is the only reason this section is worth writing.

**Point-in-time correctness** was the most error-prone thing in the codebase.
Not conceptually hard — only data from before the cutoff — but the boundary
has to be strict rather than inclusive, the strictness has to agree between
the feature builder and the service that publishes the caveat, and the
snapshot has to be stored rather than recomputed. Three places to get it
right, and a mistake in any of them shows up as better numbers.

**The distinction between unavailable and zero** touched almost every layer. A
nullable score, a nullable count, a per-component availability flag, a
truncation flag, a `signals_unavailable` list, a `no_assessment` status, a
rule engine that reports `no_rules_available` rather than scoring everything
zero. It is a single idea and it has to be carried through the whole stack,
including the frontend, which is the easiest place to render a null as zero and
undo all of it.

**Parallel vocabularies** were the most expensive defect class and the least
dramatic. Four copies of one enum, drifting, with no error that named the
cause. The fix — one dependency-light module that everything imports — is
obvious in retrospect and was not obvious while writing five layers that each
needed the same list.

**Keeping the test fixtures honest** was harder than writing them. A fixture
sitting exactly on a threshold fails when somebody tunes the threshold by one,
and the failure is about the fixture. The convention that emerged: put
parameters well past the threshold so the shape is unambiguous, and when a
test genuinely wants the borderline case, build it inline and say why.

**The hard negatives** did more for the rules than the typologies did. A
merchant settling to a payment processor matches three of the four signals the
collection rule looks at, and keeping it in the sample data permanently is
what stops the rules drifting toward measuring activity.

## What would make this production-ready

Not a list of features. Roughly, in order:

1. Run and fix the test suite.
2. A penetration test, and a review by somebody who did not write it.
3. Audit trail integrity that does not depend on nobody having database
   access.
4. Token revocation.
5. Evaluation on real labelled data, with grouped and temporal splits, against
   a measured baseline of what the current process catches.
6. A fairness assessment, which needs demographic data held under a lawful
   basis for exactly that purpose.
7. A retention schedule, an erasure path, and an answer to the tension between
   those and an append-only audit trail.
8. An owner.

Items 5 through 8 are not engineering work, and they are the ones that decide
whether any of this should be deployed. `docs/compliance-note.md` and
`docs/model-card.md` are the two documents that say so in detail.
