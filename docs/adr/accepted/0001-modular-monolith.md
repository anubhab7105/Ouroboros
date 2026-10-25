# ADR 0001: A modular monolith, not services

- **Status:** accepted
- **Date:** 2026-02-09
- **Deciders:** MULEGUARD contributors

## Context

MULEGUARD does six things that have to agree with each other: ingest records,
compute features, run rules, fuse a risk score, traverse a graph, and manage
cases. An analysis run touches all six within one request, and every one of
them reads from and writes to the same relational data.

It is deployed by one person onto one machine, for a demonstration or a pilot.
Nobody is on call for it.

The hardest constraint is a correctness one. A feature snapshot must contain
only data from before its `as_of` cutoff, and the assessment, its indicators,
its rule hits and the alert it raises must either all persist or none of them
do. A half-written assessment is worse than no assessment: it looks like a
score somebody can act on.

## Decision

> We will build one FastAPI process with explicit internal module boundaries,
> sharing one database and one transaction per request.

`app/api/` depends on `app/services/`, which depends on `app/models/` and
`app/ml/`. Dependencies point one way. A service never imports an endpoint.

## Alternatives considered

### Services per domain

Ingestion, detection, graph and cases as four deployables.

The point-in-time guarantee is what rules this out. A feature snapshot built
by a detection service from data owned by an ingestion service is a snapshot
of whatever that service had replicated at the time, and the `as_of` contract
becomes a statement about replication lag rather than about the data. The
honest version of that requires distributed transactions or event sourcing,
and both are a larger engineering commitment than the detection logic they
would be supporting.

Operationally it is also wrong for the target: four processes, a message
broker and four sets of migrations, deployed by one person for a pilot.

### A single module with no internal boundaries

Faster to write and genuinely tempting at this size. Rejected because the
boundaries are what make the invariants checkable. "The graph layer never
performs an unbounded query" is a property somebody can verify by reading one
package; without the package it is a property somebody has to verify by
reading everything.

### A framework with a built-in admin, such as Django

Would have supplied user management and an admin interface. Rejected because
the data model is relationship-heavy and the queries are analytical — bounded
graph traversal, windowed aggregates, point-in-time snapshots — and the ORM
conveniences that make a CRUD admin pleasant are not the ones that make those
queries legible.

## Consequences

### What this makes easy

- One transaction per request, so an assessment and its alert commit together.
- One migration history.
- A feature snapshot and the transfers it was computed from in one query plan.
- Running the whole system on a laptop, which is most of what the test suite
  depends on.

### What this makes hard

- Scaling one part independently. A heavy analysis run competes with API
  requests for the same process, and `uvicorn --workers` is the only answer.
- Enforcing the module boundaries. They are a convention plus a static check,
  not a network boundary, and a shortcut import compiles.
- Deploying a change to one area without redeploying everything.

### What would make us revisit this

- A single analysis run taking longer than the request timeout, consistently.
  The first move would be a background worker sharing this codebase and
  database, not a service.
- More than one team deploying independently.

## Notes

`app/graph/` is a second, parallel analytics layer that the live endpoints do
not use — `app/services/graph.py` serves them. That is a wart, documented in
`docs/architecture.md` rather than hidden.
