# ADR 0002: PostgreSQL is the source of truth; no graph database

- **Status:** accepted
- **Date:** 2026-02-09
- **Deciders:** MULEGUARD contributors

## Context

The platform is about relationships — accounts connected by transfers, by
shared device hashes, by complaints naming both ends — and the obvious
reaction is to reach for a graph database.

But look at what the queries actually are. Every traversal starts from one
account, is bounded to a handful of hops, is restricted to completed transfers
inside a date window, and returns at most a few hundred nodes. That is a
recursive query over an indexed edge table, not a graph analytics workload.

Meanwhile the rest of the system is unambiguously relational: 23 tables,
foreign keys that must hold, monetary amounts that must be exact, an
append-only audit table, and point-in-time snapshots that have to be
transactionally consistent with the rows they summarise.

## Decision

> We will keep every record in PostgreSQL, and traverse the graph with bounded
> queries against the same database.

SQLite is supported for development and for the test suite. Schema definitions
avoid native enum types (`native_enum=False`) so the same models work on both.

## Alternatives considered

### Neo4j, or another graph database, alongside PostgreSQL

The appealing option, and the one most likely to be chosen by reflex.

Two systems means synchronising them, and the synchronisation is where the
correctness goes. A traversal that reads a graph store lagging behind the
transaction table returns a path through a transfer that was reversed, and
nothing in the result says so. Keeping them consistent means either writing
both in one distributed transaction or accepting a window in which an
investigator is shown a relationship that no longer exists.

The workload also does not need it. A graph database earns its place on
unbounded traversal, global community detection or shortest paths over
millions of edges. Every traversal here is deliberately bounded (ADR 0007),
because an unbounded one is both a performance problem and an investigative
one — a path of fifteen hops through a payments network connects almost any
two accounts and means nothing.

### PostgreSQL with the `ltree` or `pgRouting` extension

Rejected for the deployment target. An extension is a thing the person
deploying this has to install and the managed database may not offer, and
recursive CTEs cover the bounded case without one.

### A document store

Rejected immediately. The foreign keys are the product: a transfer naming an
account that does not exist has to fail, and the audit trail has to be
append-only and ordered.

## Consequences

### What this makes easy

- One backup, one restore, one migration history, one consistency story.
- A traversal and the transfers it walked read in the same transaction.
- `docker compose up` with one data service.
- Exact money. `NUMERIC`, never a float.

### What this makes hard

- Deep or global graph analytics. Community detection across the whole
  portfolio is not a query here; `app/graph/` exists as an offline analytics
  layer for that reason.
- Traversal performance at a scale where a recursive CTE stops being fast.
  Mitigated by the bounds, and the bounds are reported rather than hidden.

### What would make us revisit this

- An investigative need for genuinely unbounded traversal that the bounded
  version cannot serve.
- Edge counts where bounded traversal exceeds its time budget on ordinary
  queries rather than on pathological ones.

## Notes

The traversal lives in `app/services/graph.py` and is tested in
`backend/tests/test_graph.py` and `test_money_trails.py`. Monetary columns are
`NUMERIC` and are never summed across currencies, because there is no exchange
rate in this system and a cross-currency total is a number with no meaning
that still sorts.
