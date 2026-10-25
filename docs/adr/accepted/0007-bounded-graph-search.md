# ADR 0007: Every traversal is bounded, and a truncated result says so

- **Status:** accepted
- **Date:** 2026-02-12
- **Deciders:** MULEGUARD contributors

## Context

A transaction graph is dense and a payments network is small-world. Follow
transfers far enough from any account and you reach a large fraction of the
portfolio, through a chain of entirely ordinary payments.

That creates two problems at once, and the second is the serious one.

The performance problem is familiar: an unbounded traversal from a busy
account can walk most of the edge table, and a dense seed turns one API
request into a database outage.

The investigative problem is that a long path is not evidence. "These two
accounts are connected" is true of almost any pair at six hops, so a traversal
with no limit produces an answer that is simultaneously correct and
meaningless — and it is presented to an investigator in the same interface as
a two-hop connection that means a great deal.

## Decision

> Every traversal carries a hop limit, a node budget and a time budget, and
> every result states whether it was truncated and which budget was hit.

The defaults are deliberately small: a handful of hops, a few hundred nodes.
They are configurable upward, within hard caps, and the response always
reports the limits that applied.

## Alternatives considered

### Unbounded traversal with a query timeout

Rejected because a timeout produces a partial result indistinguishable from a
complete one. The investigator sees a subgraph; nothing in it says that the
search stopped early, and a missing path reads as "no connection".

### Precompute components offline

Useful, and not a substitute. A precomputed component is as of its last run,
and an investigator working a live alert needs the graph as of now. It also
answers a different question: "what is connected to this" rather than "how".

### Bound it, but do not report the truncation

The tempting shortcut, and the one that does the damage. **A truncated
traversal establishes nothing.** If the search was cut off, "no path found"
means "no path found within the budget", and an investigator who reads an
exhausted search as an exhaustive one has drawn a conclusion the data does not
support — and will write it in a case note.

So the flag is not a diagnostic. It changes what the result means, and it is
part of the response contract.

## Consequences

### What this makes easy

- Predictable latency, bounded by configuration rather than by data.
- An honest "we did not look further" instead of a false negative.
- Traversal inside the request transaction, consistent with everything else
  the endpoint read.

### What this makes hard

- Finding a genuinely long chain. A six-hop layering scheme will be truncated
  at a four-hop default, and the investigator has to raise the limit
  deliberately — which is the right shape for that decision.
- Any global graph measure. Centrality over the whole portfolio is not
  something a bounded traversal can compute; `app/graph/` exists for offline
  work of that kind.

### What would make us revisit this

An investigative workflow that genuinely needs unbounded traversal, with
somebody accountable for interpreting the result. Even then the bound would
move rather than disappear.

## Notes

Implemented in `app/services/graph.py`; the limit resolution is in
`app/graph/limits.py`. Tested in `backend/tests/test_graph.py` and
`test_money_trails.py`, which assert specifically that a cut-off traversal
reports `truncated: true` rather than returning a quietly short answer.

The related invariant: a money trail is a **shape**, not a tracing of funds.
Money is fungible, so "this rupee went there" is not a claim the data supports;
what the trail shows is a sequence of transfers consistent with a pattern.
