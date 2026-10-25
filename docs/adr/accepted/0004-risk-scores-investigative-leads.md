# ADR 0004: A risk score is a lead, and the system never acts on one

- **Status:** accepted
- **Date:** 2026-02-10
- **Deciders:** MULEGUARD contributors

## Context

The platform produces a number between 0 and 100 for an account, with a band
attached. A number like that invites two things: being treated as a
probability that the holder is a criminal, and being wired to an automatic
action.

Both are wrong, and the second is how a detection system causes real harm. A
mule account freeze is a person losing access to their money — often someone
recruited, coerced, or entirely innocent — and the score is computed from
behavioural aggregates and inferred associations, several of which are
genuinely weak on their own. A shared IP address is a carrier NAT. A fan-in
pattern is also what a small business receiving customer payments looks like.

The risk is not hypothetical. A system that can freeze accounts will be asked
to, and the request will be reasonable each time.

## Decision

> We will treat every score, alert, graph relationship, money trail,
> correlation and case disposition as an investigative lead for a person to
> act on, and the platform will take no adverse action on an account under any
> circumstance.

Concretely:

- No endpoint changes an account's status as a consequence of a score.
- `AccountStatus` has no suspended, blocked or restricted value. There is
  nowhere to record an enforcement decision, so one cannot be recorded.
- Every scored response carries caveats, and they travel to the client rather
  than living in documentation.
- The explanation says "contribution", never "cause".
- Closing a case states explicitly that it does not restrict any account.

## Alternatives considered

### Automatic action above a threshold, with human review afterwards

The industry pattern, and the one this explicitly refuses. Review after the
fact is review of a decision already taken, and the person whose account was
frozen has already been harmed. At this system's accuracy, that is not a
trade worth making.

### A configurable action hook, off by default

Rejected. An off-by-default hook is an on-by-default hook in six months. The
absence of the capability is the control; a flag is not.

### Hide the numeric score and show only a band

Considered, and partly adopted: the interface leads with the band. The score
is still available, because an investigator comparing two accounts needs the
ordering, and bands of twenty points hide it.

## Consequences

### What this makes easy

- A defensible answer to "what happens to the account?" — nothing, until a
  person decides.
- Caveats that cannot be stripped by a client, because they are in the payload.
- An audit trail of human decisions rather than automated ones.

### What this makes hard

- Volume. Every action needs a person, and the queue is the bottleneck.
- Integration with a system that expects a verdict. It will get a score and a
  band, and the decision stays here.

### What would make us revisit this

Nothing in this codebase. A system that takes adverse action needs an accuracy
profile, an appeals process and a regulatory basis that are all outside the
scope of a prototype.

## Notes

Tested in `backend/tests/test_e2e_workflow.py::TestNoAdverseAction`, which
runs an investigation from alert to closure and asserts that the account's
status is unchanged at the end. The caveat text is asserted rather than
assumed, so removing it fails a test.
