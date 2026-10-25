# Architecture

One FastAPI process, one PostgreSQL database, one React application. The
interesting decisions are not in the shape — a modular monolith is the
unsurprising choice at this size — but in what the layers refuse to do to each
other.

Diagram: `docs/diagrams/architecture.mmd`.

## The layers, and which way they point

```
app/api/v1/endpoints/     HTTP. Auth, validation, response models.
        ↓
app/services/             Orchestration and domain rules.
        ↓
app/models.py             SQLAlchemy models. 23 tables.
app/ml/                   Features, model, fallback.
app/ingestion/            Normalize, validate, dedupe, provenance.
app/core/                 Config, permissions, vocabularies, constants.
```

Dependencies point one way. A service never imports an endpoint, and
`app/core/` imports nothing from above it. That is a convention plus a static
check rather than a network boundary, but it is what makes the invariants
checkable: "the graph layer never performs an unbounded query" is a property
you can verify by reading one package.

### The endpoints are the API contract

This is the thing most likely to surprise someone reading the code.

`app/schemas/` exists and is **not** what the API returns. Every module under
`app/api/v1/endpoints/` declares its own request and response models inline
and imports nothing from `app/schemas/`. If you want to know what an endpoint
returns, read the endpoint.

That is a wart rather than a design. The response models drifted into the
endpoint modules as the shapes stabilised, and `app/schemas/` was left behind.
It still agrees with the real contract on the parts that matter — the case
status and disposition vocabularies there are correct, and were the reference
used to fix the endpoint module when it had drifted — but it is not the
authority.

### `app/graph/` is a parallel layer the API does not use

Another one worth knowing before you go looking.

`app/graph/` (builder, metrics, trails, neighborhood, cycles, communities,
limits) is an offline analytics layer. The live `/api/v1/graph` endpoints are
served by `app/services/graph.py`, which does its own bounded BFS over
`Transaction` rows.

Two layers doing similar things is not good, and the reason they both exist is
real: the service layer answers "what is connected to this account, now,
within a budget" inside a request transaction, and `app/graph/` answers
"compute a metric over a whole component", which is not a request-shaped
question. `app/graph/limits.py` is shared.

## A request, end to end

### Reading

```
GET /api/v1/accounts/ACC-1/assessment
  → deps: resolve settings, open a session, parse the request id
  → deps: decode the bearer token, load the user
  → deps: require_permission(ACCOUNT_READ)
  → endpoint: query, build the response model
  → middleware: security headers, request id, cache control
```

Permissions are named, never roles. `require_permission(Permission.CASE_CLOSE)`
survives a change to which roles may close a case; `if role == "SENIOR"` does
not, and the change gets missed in one endpoint out of twelve.

### Writing

Same, plus: the mutation, an audit row, and one commit. The audit row is
written in the same transaction as the change it describes, so there is no
state in which a case moved and nothing recorded it.

### An analysis run

Synchronous. `POST /api/v1/analysis/runs` performs the work and returns a
terminal status, which is why the demo seed script can run it and then show a
populated dashboard.

```
resolve as_of (default now)
for each selected account:
    build a feature snapshot — only data strictly before as_of
    evaluate rules
    score: trained model, or the heuristic fallback
    gather graph signals (bounded)
    gather complaint correlations
    fuse → score, band, components, caveats, evidence refs
    persist assessment + indicators + rule hits
    raise or update an alert if warranted
commit
```

Diagram: `docs/diagrams/detection-pipeline.mmd`.

## The four invariants the layers exist to protect

These are the design. Everything above is arrangement.

### Unavailable is not zero

A signal that could not be computed is reported as unavailable. Substituting
zero would assert that the account scored well on something nothing looked at,
and that assertion is invisible downstream: a zero and a real zero are the
same number.

So a score can be null, a metric can say unavailable, and a rule pack that
failed to register reports `no_rules_available` rather than scoring every
account zero and calling it a clean run.

### Identity is not inference

A deterministic match — a complaint naming a transaction reference, an
identifier that came from the account record itself — carries no confidence
score and no review state. An inferred one carries both and waits for a
person.

Not `1.0` for the deterministic case. A certainty and a probability in the
same column invite a reader to compare them, so the column holds NULL and the
interface renders the absence as the word "identity".

### A truncated traversal establishes nothing

Every traversal is bounded by hops, nodes and time, and the result says
whether it was cut off. If it was, "no path found" means "no path found within
the budget" — and an investigator who reads an exhausted search as an
exhaustive one has drawn a conclusion the data does not support.

ADR 0007 has the reasoning.

### Nothing takes adverse action

No endpoint changes an account's status as a consequence of a score.
`AccountStatus` has no suspended, blocked or restricted value, so there is
nowhere to record an enforcement decision. The absence of the capability is
the control; a flag would not be.

ADR 0004. `tests/test_e2e_workflow.py::TestNoAdverseAction` runs an
investigation to closure and asserts the account is untouched.

## One vocabulary, one place

`app/core/vocabularies.py` defines the enumerations that describe ingested
records: account type and status, transaction status, channel, entity type,
match method, verification state, case status, disposition. `app/models.py`
imports them and declares the columns over them; the ingestion normalizer, the
ingestion validator, the synthetic generator and the ML feature builder import
the same module.

It is worth a paragraph because the alternative was tried. Each of those
layers used to carry its own hand-written copy, and the copies had drifted on
every single field. Account type is the clearest: the database accepted
`INDIVIDUAL`, `BUSINESS`, `MERCHANT`, `OTHER`, while ingestion accepted
`SAVINGS`, `CURRENT`, `WALLET`, `UPI`, `CARD`, `OTHER`. They shared one value.
A correct record failed validation, an accepted record failed on insert, the
generator's output could not be loaded at all, and the account-type feature
was constant in every vector the model ever saw. None of it raised an error
that named the cause.

The module imports nothing beyond the standard library, which is what lets the
ML and ingestion layers run offline — against fixtures, in a script — without
SQLAlchemy installed.

## Contracts a client can rely on

**Pagination** is flat and identical on every list endpoint: `items`, `page`,
`page_size`, `total`, `total_pages`, `sort_by`, `sort_order`, `caveats`. Not a
nested `meta`, not a bare array.

**Errors** are flat: `code`, `message`, `category`, `retryable`, optional
`details` and `request_id`. FastAPI's own `{"detail": ...}` is replaced, so a
client writes one error reader rather than two.

**Caveats** travel in the payload. The platform's position is that its output
is a lead rather than a finding, and a caveat that lives only in documentation
is a caveat nobody reads.

**Request ids** come back on every response, echoing the caller's when one was
sent. It is the thread between a user's screenshot, an access log line and an
audit row.

## The frontend

React, TypeScript, Vite, TanStack Query. Types in `src/types/` mirror the
response models by hand; there is no generated client, which means they can
drift and a mismatch shows up as `undefined` in a table cell.

Two things it does deliberately:

- **It renders the caveats.** Every scored view shows them. The server sends
  them and the client is not permitted to be the place they get dropped.
- **It does not pre-empt a refusal.** The case transition table is duplicated
  client-side to decide which buttons to offer, and that table can drift from
  the server. So every action is still attempted and a 403 or 409 is shown as
  what it is, rather than the client deciding in advance that it would fail.

## Where things are

| Path | What |
|---|---|
| `backend/app/api/v1/endpoints/` | 15 modules. The API contract |
| `backend/app/services/` | Orchestration, case state machine, correlation |
| `backend/app/ml/` | Features, supervised model, fallback, leakage guards |
| `backend/app/ingestion/` | Normalize, validate, dedupe, generator, seed |
| `backend/app/graph/` | Offline graph analytics (not used by the endpoints) |
| `backend/app/core/` | Config, permissions, vocabularies, constants |
| `backend/app/reports/` | ReportLab PDF assembly |
| `backend/migrations/` | Alembic revisions |
| `backend/tests/` | 39 modules, plus fixtures and factories |
| `frontend/src/features/` | One directory per domain area |
| `data/` | Samples, schemas, generator notes |
| `scripts/` | Six Python tools, seven shell/PowerShell pairs |
| `docs/adr/accepted/` | Eight decisions, with their costs |
