# ADR NNNN: <short title, a decision not a topic>

- **Status:** proposed | accepted | superseded by [ADR NNNN](accepted/NNNN-....md)
- **Date:** YYYY-MM-DD
- **Deciders:** <who>

## Context

What is true that forces a decision. Constraints, not preferences: what the
system has to do, what it runs on, who maintains it, what it must not do.

Write this so that somebody who disagrees with the decision can still agree
with this section. If the context only supports one conclusion, it is probably
the decision smuggled in early.

## Decision

One or two sentences, in the active voice, saying what was chosen.

> We will ...

## Alternatives considered

The ones that were real, with the reason each was not chosen. An ADR listing
only strawmen is an ADR nobody will trust when they come to revisit it.

### <alternative>

What it would have looked like, and why not. "Too complex" is not a reason;
"it needs an operator to run a message broker, and this is a prototype a
single person deploys" is.

## Consequences

### What this makes easy

### What this makes hard

The part most often left out, and the part a future reader needs. A decision
with no costs was not a decision.

### What would make us revisit this

A concrete trigger, not "if requirements change". For example: "if a single
analysis run exceeds ten minutes", or "if more than one team deploys this
independently".

## Notes

Anything that does not fit above. Links to the code that implements it, to the
tests that pin it, or to the discussion.
