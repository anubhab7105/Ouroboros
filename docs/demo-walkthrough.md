# Demo walkthrough

Twenty minutes, from a clean checkout to an investigation closed with a
disposition and a PDF. Written to be followed in front of somebody.

## Setup

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'   # into BACKEND_SECRET_KEY
docker compose up --build -d

export MULEGUARD_DEV_PASSWORD='Demo-Passw0rd!2026'
export MULEGUARD_ADMIN_PASSWORD="$MULEGUARD_DEV_PASSWORD"

scripts/wait_for_backend.sh
docker compose exec backend python scripts/create_dev_users.py
scripts/seed_demo.sh
scripts/smoke_test.sh
```

`smoke_test.sh` should report eleven passes. **A skipped check is not a passed
one** — if the authenticated half skipped, `MULEGUARD_ADMIN_PASSWORD` is not
set.

Then open http://localhost:5173 and sign in as **`analyst`**, not `admin`. The
demonstration is better when the separation of duties is visible.

## 1. The banner (30 seconds)

Point at it before anything else.

> **SYNTHETIC DEMO DATA**

It is in every health response, every scored response, every generated report
and the interface. It is the first thing anybody asks about, and answering it
up front means the rest of the conversation is about the detection rather than
about the data.

## 2. The dashboard (2 minutes)

Five queues. Walk them in the order they are shown, because the order is the
argument:

- **Unassigned alerts** — nobody owns these, and they do not age out.
- **Assigned to me** — mine, still open.
- **Escalated** — waiting on a senior.
- **Under investigation** — in progress, with an owner.
- **Triaged** — assigned, not started. *The queue that quietly grows.*
- **Unreviewed complaint links** — inferred, waiting on a judgement.

Worth saying out loud: nothing on this screen has done anything to anybody.
Every one of these is a request for a person to look.

## 3. The collection account (4 minutes)

Open the top alert. It should be `ACC-S-COLLECTOR`.

**Read the indicators, not the score.** The score says where in the queue this
sits; the indicators say why:

- `FAN_IN_BURST` — twelve senders in six hours
- `HIGH_THROUGHPUT` — volume against an eleven-day-old account
- `SHARED_ENTITY` — a device hash in common with another account

Then the account summary, and the detail that is easy to miss: the monetary
figures count **completed transfers only**, with pending, failed and reversed
shown separately. The sample contains one of each, deliberately. An aggregate
that included the pending transfer would describe money that has not moved.

The USD transfer is there for the same reason. Per-currency totals are never
added together — there is no exchange rate in this system, and a combined
total would be a number with no meaning that still sorts.

## 4. The hard negative (3 minutes)

This is the most interesting screen in the demonstration, and it is the one
with nothing on it.

Search for `ACC-S-HARD-NEGATIVE`. A merchant settling to a payment processor:
high throughput, many counterparties, a thin retained balance. **Three of the
four signals the collection rule looks at.**

It has not alerted.

That is the point. A detection system is easy to make sensitive and hard to
make useful, and the difference shows up as legitimate businesses in the
triage queue. If this account ever starts alerting, the rules have begun
measuring activity rather than typology — which is why it is in the sample
data permanently rather than as a one-off test.

## 5. The graph (3 minutes)

From the collector, open the graph view.

Two accounts share a device hash in an overlapping window — the collector and
the pass-through account. One edge, and it is what turns two unrelated-looking
accounts into a connected component.

Then the two things to say about what is on screen:

**Check the `truncated` flag.** Every traversal is bounded by hops, nodes and
time. If it says truncated, the absence of a path means *nothing* — "no path
found" is "no path found within the budget". Reading an exhausted search as an
exhaustive one is the easiest way to write something in a case note that the
data does not support.

**A money trail is a shape, not a tracing of funds.** Money is fungible. What
the trail shows is a sequence of transfers consistent with a pattern, and that
is worth considerably less than a sentence beginning "the funds were".

Open the shared-identifier panel and show the IP link: three accounts, one of
them the hard negative, and that one **rejected on review**. A carrier NAT
puts thousands of unrelated people behind one address. The rejection is kept
rather than deleted, because the fact that somebody looked and said no stops
the same inference being raised next week.

## 6. The complaints (3 minutes)

Four complaints, one per correlation tier.

`CMP-S-0001` names a transaction reference. Show where a confidence score
would be and is not — the interface says **"identity"**.

That is a deliberate choice worth dwelling on for a moment. A certainty shown
as `1.000` sits in the same column as `0.74` and invites a reader to compare
them, when one is an identity and the other is a probability. So the column is
empty and the word says why.

`CMP-S-0003` is the opposite: matched on amount and timing, carrying a
confidence and sitting in the review queue.

`CMP-S-0004` is the one that should match nothing. "Someone has been using my
details, I'm not sure which transactions." A correlation engine that finds a
confident match there is matching noise, and the review queue is where that
becomes somebody's wasted afternoon.

## 7. The investigation (5 minutes)

Back on the collector's alert: **Open a case**.

The alert's evidence comes across — the response reports
`copied_evidence_count`.

Now the sequence, and let the refusals happen:

**Try to start it.** It fails: a case needs an owner before it can be under
investigation, because a case nobody owns counts as active everywhere and has
nobody accountable for it.

**Try to assign it as the analyst.** 403. Assignment is senior-and-above —
the person doing the work is not the person signing it off.

Sign in as `senior`, assign it to the analyst. The status becomes **TRIAGED**,
not under investigation: assignment and starting work are different acts.

Back as the analyst: **Start**. Now UNDER_INVESTIGATION.

Add a note — "twelve senders in six hours, none previously linked" — and
attach the inbound transfer as evidence.

**Escalate**, and notice it asks for a reason. An escalation arriving at a
senior reviewer with a changed status and nothing to act on makes their first
task reconstructing why it was sent.

As `senior`: **Close**. It asks for a reason *and* a disposition, and will not
accept the close without both.

Pause on the disposition list. `CONFIRMED_FRAUD`, `FALSE_POSITIVE`,
`INCONCLUSIVE`, `REFERRED`. **`INCONCLUSIVE` is a real answer** — every later
measurement of how well detection works reads this field, and a
confirmed-fraud marked on insufficient evidence teaches the system the wrong
lesson permanently, because the disposition cannot be reconstructed later from
the closure note.

Pick `CONFIRMED_FRAUD`, and read the response caveat aloud:

> Closing a case does not close, freeze, block, blacklist, or restrict any
> account.

Then show the account: status unchanged. The platform has no capability to
change it, and no `AccountStatus` value to write one into.

## 8. The report and the trail (2 minutes)

Generate the PDF. The response returns metadata rather than bytes — filename,
size, SHA-256, section summaries — because generation is the audited event and
is recorded even if the download never happens. The digest is how you tell
whether the copy in somebody's hand is the one that was generated.

The report carries the same limitations text the interface shows, from the
same source.

Then, as `admin`, open the audit trail filtered to the case: assign, start,
escalate, close, report generated. Each with an actor, a timestamp and a
request id.

The no-op is worth pointing out if you have it: starting an already-started
case writes **no** audit row, because a record of an event that did not happen
is worse than no record.

## What to say at the end

Four things, in this order:

**It prioritises; it does not decide.** Every consequence in this
demonstration came from a person.

**It says what it does not know.** An unavailable signal is reported as
unavailable rather than as zero, because a zero is a claim that the account
scored well on something nothing looked at. A truncated traversal says so. A
missing assessment is `no_assessment`, not a score of nothing.

**The hard negative is the test that matters.** Sensitivity is easy. The
account that looks guilty on three signals and is not is what a usable queue
depends on.

**The numbers mean less than they look like.** This is synthetic data and the
generator plants the typologies the rules look for, so a metric from it
measures agreement between two things the same author wrote.
`docs/model-card.md` lists what would have to be true before a number from
here belonged in a sentence beginning "the model is".

## If something goes wrong

Do not reset. An empty dashboard with a working case view is a better
demonstration than a restart.

The commonest mid-demonstration failure is an expired token, which looks like
everything breaking at once. Sign in again.

`docs/runbooks/troubleshooting.md` has the rest, and
`docs/runbooks/demo-reset.md` has a pre-flight list for next time.
