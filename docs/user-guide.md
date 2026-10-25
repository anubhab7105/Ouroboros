# User guide

For an analyst or investigator using MULEGUARD. It assumes somebody has set it
up and seeded it; `docs/demo-walkthrough.md` is the version that starts from
nothing.

## What the system is telling you

Before anything else, because it changes how you read every screen.

**A score is a priority, not a verdict.** It orders accounts so you look at
the unusual ones first. It is not a probability that the holder committed a
crime, and the number was computed from behavioural aggregates and inferred
associations, several of which are weak on their own.

**Nothing happens to an account because of a score.** The platform cannot
freeze, block or restrict anything. Every consequence comes from a person
deciding something outside it.

**A caveat on a screen is part of the data.** The caveats are sent with every
scored response rather than written in a manual, because a number quoted
without its qualification is how a lead becomes a finding in somebody else's
filing cabinet. They are worth reading once properly.

## Signing in

Your role decides what you can do.

| Role | You can |
|---|---|
| Analyst | Read everything, triage alerts, work cases, add notes and evidence |
| Senior investigator | The above, plus assign, close, reopen, and review inferred correlations |
| Auditor | Read everything including the audit log. Change nothing |
| Admin | Users, configuration, ingestion, exports |

If you are an analyst and a button is missing or returns a refusal, that is
usually the separation of duties rather than a fault. **An analyst cannot
assign or close a case** — the person doing the work is not the person signing
it off.

Sessions are short and there is no refresh. Everything breaking at once
usually means the token expired; sign in again.

## The dashboard

Five queues, and the order is deliberate:

**Unassigned alerts.** Nobody owns these and they do not age out on their own.

**Assigned to me.** Yours, not yet closed.

**Escalated cases.** Waiting on a senior investigator.

**Cases under investigation.** In progress, with an owner.

**Triaged cases.** Assigned to somebody who has not started. A case sitting
here for a week is the one worth asking about.

**Unreviewed complaint links.** Inferred correlations waiting for somebody to
accept or reject. This is the queue most often ignored and the one where
ignoring it costs most: an unreviewed inference is shown alongside confirmed
ones.

## Working an alert

An alert is a request for you to look. That is the whole of what it is.

### Read the indicators before the score

The score tells you where in the queue this sits. The indicators tell you
why, and they are what you will reason about:

- `FAN_IN_BURST` — many unrelated senders in a short window
- `HIGH_THROUGHPUT` — large volume relative to the account's history
- `PASS_THROUGH` — money in and almost all of it out again, quickly
- `DORMANT_REACTIVATION` — quiet for months, then sudden activity
- `CYCLE_MEMBER` — part of a loop of transfers
- `SHARED_ENTITY` — a device or address hash in common with another account
- `COMPLAINT_CORRELATION` — a complaint relates to this account

### Check what the account's ordinary behaviour is

The account summary counts **completed transfers only**, with pending, failed
and reversed shown separately. That difference matters: an aggregate including
pending transfers describes money that has not moved.

Per-currency totals are never added together. There is no exchange rate here,
so a combined total would be a number with no meaning.

### Look for the innocent explanation first

The patterns that trigger alerts are also the patterns of legitimate business.
A merchant settling to a payment processor has high throughput, many
counterparties and a thin retained balance — three of the four signals the
collection rule looks at.

The sample data contains exactly this account on purpose
(`ACC-S-HARD-NEGATIVE`), and it should not alert. If something like it does,
that is worth reporting: it means the rules are measuring activity rather than
typology.

### Actions

| Action | Who | Effect |
|---|---|---|
| Acknowledge | Analyst | You have seen it |
| Assign | Senior | Gives it an owner |
| Escalate | Senior | For senior review |
| Close | Analyst | With a reason |
| Open a case | Analyst | Starts an investigation, carrying the evidence |

Every action tells you whether anything **changed**. Acknowledging an
already-acknowledged alert reports "nothing changed" rather than a success,
because knowing the difference matters when two people are working the same
queue.

## Working a case

### The states, and what each one means

```
NEW → TRIAGED → UNDER_INVESTIGATION → ESCALATED → CLOSED
                                   ↖──────────────↙
```

- **NEW** — opened, nobody owns it.
- **TRIAGED** — assigned. Assigning a new case triages it.
- **UNDER_INVESTIGATION** — being worked. **Needs an owner**: a case here that
  nobody owns counts as active everywhere and has nobody accountable for it.
- **ESCALATED** — with a senior. **Needs a reason**, because a case arriving
  at a reviewer with a changed status and nothing to act on makes their first
  task reconstructing why it was sent.
- **CLOSED** — concluded, with a disposition. **Not terminal**: new
  information arrives and a case reopens.

A closed case reopens to UNDER_INVESTIGATION, never to NEW. The work already
recorded is part of the case, and sending it back to the top of the funnel
would discard it.

### Evidence

Attach what the conclusion rests on: transfers, accounts, complaints, graph
paths, assessments. A snapshot of each is stored, because the underlying
record may change and the evidence is what you saw.

**Evidence is withdrawn, never deleted**, and withdrawing it requires a
reason. The withdrawn item stays visible with its reason — a case's history is
the point, and an item that silently vanished is the one somebody will ask
about.

### Notes

Append-only. Write what you concluded and what you ruled out; the second is
what the next person needs and the first is what they will read anyway.

### Closing

Needs a **reason** and a **disposition**:

| Disposition | Use it when |
|---|---|
| `CONFIRMED_FRAUD` | You concluded the activity was fraudulent |
| `FALSE_POSITIVE` | There was an innocent explanation |
| `INCONCLUSIVE` | Neither confirmed nor cleared |
| `REFERRED` | Passed to another team or authority |

**`INCONCLUSIVE` is a real answer.** Use it rather than forcing one of the
other two. Every later measurement of how well detection works reads this
field, and a confirmed-fraud marked on insufficient evidence is worse than an
honest shrug — it teaches the system the wrong lesson, permanently, because
the disposition cannot be reconstructed later from your closure note.

`FALSE_POSITIVE` is the most valuable one to record precisely. It is the
feedback that improves the rules, and it is the one people skip because
closing a case that went nowhere feels like admitting wasted time.

Closing does not restrict the account. The response says so, every time.

## Graph

Shows accounts connected by transfers and by shared pseudonymous identifiers.

### Read the `truncated` flag

Every traversal is bounded by hops, nodes and time. If the result says it was
truncated, **the absence of a path means nothing**: "no path found" is "no path
found within the budget", and the subgraph you are looking at is partial.

Raise the limits deliberately if you need to look further. Do not read an
exhausted search as an exhaustive one — that is the single easiest way to
write something in a case note that the data does not support.

### A money trail is a shape, not a tracing of funds

Money is fungible. "This rupee went there" is not a claim the data supports.
What a trail shows is a sequence of transfers consistent with a pattern, and
that is worth a great deal less in a sentence beginning "the funds were".

### A shared identifier is weaker than it looks

A shared device hash in an overlapping window is strong. A shared IP is often
nothing at all: a carrier NAT puts thousands of unrelated people behind one
address.

The interface shows the match method and the validity window for this reason.
`EXACT` is an observation; `NARRATIVE_EXTRACTION` is a guess.

## Complaints

A complaint is evidence that somebody reported something. It is not evidence
that the thing happened.

### The tiers, and why two of them look different

| Tier | Matched on | Confidence | Review |
|---|---|---|---|
| 1 | Exact transaction reference | — | — |
| 2 | Account the complainant named | — | — |
| 3 | Identifier found in the narrative | yes | yes |
| 4 | Amount and timing | yes | yes |
| 5 | Entity or graph association | yes | yes |

Tiers 1 and 2 are **identities** — the complainant named the thing — so they
carry no confidence score and need no review. The interface shows the word
"identity" where a confidence would be, rather than 1.000, because a certainty
and a probability shown side by side invite a comparison that does not mean
anything.

Tiers 3 to 5 are inferred, scored, and waiting on you.

### Reviewing

Senior and above. Accept or reject, with a note.

A rejected correlation is **kept**, not deleted. The fact that somebody looked
and said no is worth more than a clean list, and it stops the same inference
being raised again next week.

## When something says "unavailable"

It means nothing looked, and that is different from a zero.

A null score, a metric marked unavailable, a `signals_unavailable` list — all
of these are the system declining to assert something. A zero in place of an
unavailable value would be a claim that the account scored well on something
nothing measured, and you would have no way to tell.

If a whole screen is unavailable, the most common causes are: no analysis has
run on these accounts yet; no model is trained (the heuristic fallback is in
use, and the scoring mode says so); or a rule pack failed to register.

## Reports

Generate a PDF for a case. It contains the case, its evidence index, the
assessment it came from, and the limitations — the same limitations text the
interface shows, from the same source.

Generation is audited: who, when, which case, and a digest of the document.
The digest is how you tell whether the copy in somebody's hand is the one that
was generated.
