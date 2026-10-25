# Testing

39 test modules under `backend/tests/`, plus fixtures, factories and
scenarios. This document covers how the suite is organised, the conventions
that make it readable, and — in the last section — exactly how much of it has
been executed and how much has not.

```bash
cd backend
pytest                          # everything
pytest -m api                   # one marker
pytest tests/test_cases.py -x   # one module, stop at the first failure
pytest --cov=app --cov-report=term-missing
```

16 markers are declared in `pyproject.toml` and `--strict-markers` is on, so a
typo in a marker is an error rather than a silently-ignored filter.

## What is tested where

| Module | Subject |
|---|---|
| `test_health`, `test_openapi` | Liveness, readiness, schema generation |
| `test_auth`, `test_users`, `test_permissions` | Authentication and the permission matrix |
| `test_rate_limit`, `test_security_headers` | Middleware |
| `test_ingestion`, `test_ingestion_validation`, `test_import_transactionality` | The front door |
| `test_accounts`, `test_transactions`, `test_entities` | Record reads |
| `test_features`, `test_point_in_time_features` | Feature building and the `as_of` boundary |
| `test_rules`, `test_risk`, `test_analysis`, `test_analysis_idempotency` | Detection |
| `test_alerts`, `test_graph`, `test_graph_metrics`, `test_money_trails` | Triage and traversal |
| `test_complaints`, `test_complaint_correlation` | Correlation tiers |
| `test_cases`, `test_case_transitions`, `test_evidence`, `test_case_events` | Workflow |
| `test_audit`, `test_reports`, `test_dashboard` | Record and output |
| `test_model_metrics`, `test_ml`, `test_ml_feature_schema`, `test_ml_leakage`, `test_ml_fallback` | ML |
| `test_api_flow`, `test_e2e_workflow` | Cross-cutting contracts, and one journey end to end |

## Conventions

### A test name is a sentence

`test_a_quiet_record_matches_nothing`, not `test_rules_2`. The name is what a
reader sees in a failure report, and it should say what is now untrue.

### A docstring says why the test exists

Not what it does — the code says that. The docstring says what breaks in the
product if this assertion stops holding:

```python
def test_a_deterministic_link_carries_no_confidence(...):
    """
    An EXACT link stores `confidence` as NULL.

    Not 1.0. The distinction is not pedantry: a confidence of 1.000 sits in
    the same column as 0.94 and invites a reader to compare them, when one is
    a probability and the other is an identity.
    """
```

A test whose docstring is "tests the thing" is a test nobody will know how to
fix when it fails.

### The permission matrix is written out by hand

`test_permissions.py` does not derive its table from `app/core/permissions.py`.
That is the entire point: a table generated from the registry agrees with the
registry by construction and could never catch a change to it. The hand-written
table is a second, independent statement of who may do what, and a
disagreement between the two is the signal worth having.

### Band cut points are duplicated on purpose

`tests/factories.py` has its own `band_for()` carrying the cut points from
`config/scoring.default.json`. Moving a cut point in the config therefore
fails a test rather than silently reclassifying every account in the system.

### The state machine is tested exhaustively

`test_case_transitions.py` enumerates **every ordered pair** of case statuses,
not just the legal transitions, and asserts that each illegal one is refused.
A state machine is the one place where exhaustive testing is both cheap and
genuinely worthwhile.

### Rejection fixtures explain themselves

Every case in `tests/fixtures/*.invalid.json` carries a `why`. A rejection
fixture whose cases are not explained is one nobody dares change, because the
next person cannot tell a deliberate case from a typo — and the cheapest way
to make a failing test pass is to delete the case that was protecting
something.

## Fixtures

`conftest.py` provides:

| Fixture | What |
|---|---|
| `db` | A session inside a transaction that is rolled back |
| `users` | One user per role |
| `client` | Unauthenticated |
| `admin_client`, `senior_client`, `analyst_client`, `auditor_client` | Authenticated wrappers, each with `.raw` for a deliberately malformed request |
| `role_clients` | All four, for matrix tests |
| `client_factory` | Builds an app with different settings, for middleware tests |
| `override_settings` | Overrides the settings dependency |
| `make` | The `Factory`, below |
| `load_fixture`, `load_scenario` | JSON fixtures |

Two details that are load-bearing:

**Environment variables are set at module scope, before importing `app`.**
`app/db.py` builds its engine at import time from a cached settings object, so
an override applied later does not reach the engine.

**`BACKEND_ALLOWED_HOSTS` includes `testserver`.** `TrustedHostMiddleware`
would otherwise reject every request from the test client with a 400 and an
unhelpful body — which is exactly what it does in production for an
unconfigured host, and is worth knowing for that reason too.

### The factory builds typologies, not rows

```python
collector, senders, transfers = make.fan_in(sources=12)
source, middle, destination, transfers = make.pass_through(retained_fraction=0.02)
account = make.dormant_account(dormant_days=200)
account, assessment, indicators = make.scored_account(score=78)
```

`fan_in(sources=12, within_hours=6)` puts the parameters well past the
thresholds so the shape is unambiguous rather than borderline. A test that
wants the borderline case builds it from `make.transaction` directly and says
why — a fixture sitting exactly on a threshold fails when somebody tunes the
threshold by one, and the failure is about the fixture rather than the code.

`make.hard_negative()` builds the record that should **not** alert.

## Scenarios

`tests/fixtures/scenarios/` holds nine JSON scenarios, each with `parameters`,
`expected`, `confounders` and `notes`. They describe a detection situation
independently of the code, so a test can assert the outcome and a reader can
disagree with the scenario rather than with the assertion.

`confounders` is the useful field: what else is true in this scenario that
should not change the answer.

## Running

```bash
pytest -m "not slow"
pytest -m api
pytest -m ml
pytest --cov=app --cov-report=html
```

Each test runs inside a transaction that is rolled back, so order does not
matter and a failure leaves nothing behind.

---

## How much of this has actually been run

The section to read before quoting a number from this document.

**The suite has not been executed as a suite.** `pytest`, `fastapi`,
`sqlalchemy` and `httpx` could not be installed in the environment where this
code was written and verified — no package index was reachable — so no
`pytest` run has happened.

That is a real limitation and it would be dishonest to present the test count
as a pass count.

### What was verified, and how

**301 assertions were executed directly**, by importing the modules under test
and running the test functions without pytest. These are the tests whose
subjects are pure — the state machine, the rule engine, the feature builder,
the graph metrics, the supervised trainer, the leakage guards, the feature
schema:

| Module | Executed | Failures |
|---|---|---|
| `test_case_transitions` | 52 | 0 |
| `test_ml_feature_schema` | 54 | 0 |
| `test_ml` | 42 | 0 |
| `test_graph_metrics` | 34 | 0 |
| `test_ml_leakage` | 33 | 0 |
| `test_features` | 32 | 0 |
| `test_ml_fallback` | 30 | 0 |
| `test_point_in_time_features` | 16 | 0 |

**Every module imports cleanly**, and every `from app...` import resolves.

**Two static checkers were run over the whole tree**, both clean:

- import-order and enum-member checking across 157 files: names used during
  module execution but bound later, references to enum members that do not
  exist, and a class attribute shadowing a name the same class body calls;
- test-suite checking across 42 files: that imports resolve, markers are among
  the 16 declared, fixtures exist, helper calls match their signatures, and
  there are no duplicate test names.

**The data path was verified end to end** outside pytest: the generator
produces records, the generated records validate against the published JSON
Schemas, and the schemas match the vocabulary module the validator reads.

### What has not been run

The remaining modules need `client`, `db` and `make` fixtures, which need
FastAPI and SQLAlchemy. Their assertions have been checked by reading against
the endpoint code — several defects were found and fixed that way — but
**they have not been executed**, and a test that has never run is a test that
might not run.

In particular, these are unverified by execution:

- every HTTP-level assertion: status codes, the pagination envelope, the error
  envelope, permission enforcement through the dependency chain;
- the database-level assertions: foreign keys, transactionality, the
  append-only properties;
- the end-to-end journey in `test_e2e_workflow.py`.

### What to do about it

Run the suite. On a machine with a package index:

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

Expect failures, and expect most of them to be in the tests rather than in the
application — an assertion written against code without being run is an
assertion with a typo in it roughly as often as not. The ones worth reading
carefully are any failure in `test_permissions.py`, `test_e2e_workflow.py` or
`test_api_flow.py`, because those three encode contracts rather than details.
