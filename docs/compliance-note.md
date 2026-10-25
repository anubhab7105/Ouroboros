# Compliance note

This document exists to be read before somebody loads real data, and to say
plainly that they should not.

It is not legal advice. It is an engineering statement about what this
codebase does and does not do, written so that the gap between the two is
visible to whoever has to make the decision.

## What MULEGUARD is

A synthetic-first prototype for detecting patterns consistent with mule-account
activity, and for managing the human investigation that follows. It is a
demonstration of a workflow and a set of detection ideas.

## What it is not

**It is not a compliance system.** It implements no regulatory obligation,
satisfies no reporting requirement, and produces no filing. It is not an AML
transaction-monitoring system in the regulatory sense, and nothing it outputs
discharges a duty.

**It is not production-ready**, and says so in every health response, every
scored response, every generated report and its own package metadata.

**It is not a system of record.** The audit trail is append-only by convention
— because no code deletes — and not by database enforcement. Anyone with
database access can alter a row and nothing would detect it. A tamper-evident
chain is not implemented.

## The data it is designed for

Synthetic data. Invented, not anonymised, not masked, not sampled from
anything real.

`INGESTION_REQUIRE_SYNTHETIC` defaults to true and ingestion refuses a batch
that does not declare itself synthetic. `ANALYSIS_REQUIRE_SYNTHETIC_DATA` and
`BACKEND_BLOCK_REAL_DATA_IF_SYNTHETIC_ONLY` are the same decision at other
layers.

That is a control rather than advice (ADR 0003), because "use synthetic data
only" in a README is a sentence somebody will not read before loading a CSV
they already have — and having real data to try it on is exactly what makes a
detection prototype interesting.

## If you are considering real data

The honest answer is: do not, with this codebase as it stands. What follows is
what would have to be true, so the decision can be made with the list in view.

Most of it is not code.

### Lawful basis and purpose

- A lawful basis for processing transaction data, complaint narratives and
  device and contact identifiers, for this purpose.
- A purpose limitation that this use fits inside. Fraud prevention is often a
  legitimate purpose; "we wanted to try a tool" is not.
- A record of processing activities that includes it.
- A data protection impact assessment. For automated analysis of financial
  behaviour feeding decisions about individuals, this is the expected
  position in most jurisdictions, and the United Kingdom and European Union
  are explicit about it.

### Data subject rights

None of these are implemented:

- **Access.** No endpoint assembles everything held about one person. The
  identifier hashing that protects privacy also means there is no way to find
  every record relating to an individual from their phone number.
- **Rectification.** Records are corrected by re-ingestion, and the original
  stays in the audit trail.
- **Erasure.** There is no deletion path. Nothing here erases a person's data,
  and the append-only tables are designed not to.
- **Objection, and rights around automated decision-making.** No mechanism,
  because the platform takes no automated decisions — which helps, and does
  not discharge the obligation if a human decision is substantially informed
  by a score.
- **Explanation.** Feature contributions exist and are labelled as operational
  attributions, not causal accounts. Whether that meets a regulator's standard
  for explaining a decision is not a question this document can answer.

The erasure gap is the sharpest. An append-only audit trail and a right to
erasure are in genuine tension, and resolving it is a design decision with
legal input, not a patch.

### Retention

There is no retention schedule. `RETENTION_AUDIT_DAYS` is a number with no
enforcement behind it: nothing deletes, nothing archives, nothing expires.

### Security

`docs/security.md` lists what is implemented and what is not. The gaps that
matter here: no encryption at rest configured by this repository, no key
management beyond an environment variable, no penetration test, no dependency
or secret scanning in CI, tokens that cannot be revoked.

### Fairness

Not assessed, and `docs/model-card.md` explains why it cannot be from here:
there is no protected-attribute data in the system, by design, so a
disparate-impact analysis is not possible.

That is privacy-protective with a real cost. The absence of the data means the
absence of the measurement, not the absence of the problem — and several
features are plausible proxies. Account age penalises recently-opened
accounts, which correlates with recent arrival in a country or in formal
banking. Channel mix differs by region and income. Dormancy patterns differ
for seasonal and migrant workers.

A deployment affecting people needs that assessment, which needs demographic
data held under a lawful basis for exactly that purpose.

### Model governance

- No model risk management framework.
- No validation by anyone independent of the people who built it.
- No monitoring for drift, no review cadence, no owner.
- No measured baseline: nobody knows what the current process catches without
  this, which is the comparison that would justify using it.

### Harm to individuals

The most important part, and the one least likely to be covered by a
checklist.

A mule account is frequently held by somebody who was recruited, coerced,
deceived or is simply unconnected — a student who answered an advertisement, a
person whose details were stolen, a small business with an unusual week. An
intervention against that account is a person losing access to their money.

The platform therefore takes **no** adverse action: no endpoint changes an
account's status as a consequence of a score, and `AccountStatus` has no
suspended, blocked or restricted value to write (ADR 0004).

That protects against the platform causing harm directly. It does not protect
against a score being exported into a system that does act, which is the
likeliest path to harm in practice and is outside this codebase's control.

If a score from here informs a decision about a person, somebody needs to own:

- an appeals process the affected person can actually use;
- a record of what the decision was based on, which the stored assessment and
  its feature snapshot support;
- a measured false-positive rate on the population being decided about, which
  nothing here provides.

## Complaint narratives

The most sensitive field in the schema: a person's own account of being
defrauded, often including what they were told, what they lost and how they
feel about it.

Protections in place:

- returned on the detail view only, to senior roles and above;
- never in a list view, an error body, an export or a log line;
- truncated if one somehow reaches a log;
- normalised for correlation without the normalised form being returned.

A deployment holding real narratives needs more than this: access logging at
the field level, a retention schedule specific to them, and a judgement about
whether narrative-based correlation is proportionate at all.

## Identifiers

Device ids, phone numbers, email addresses, IPs and postal addresses are
stored as salted hashes. The raw values are never stored.

Be clear about the limit of that protection. A hash of a phone number is still
personal data under most regimes — it identifies an individual indirectly, and
anyone with a list of candidate numbers and the salt can confirm a match. The
hashing reduces exposure; it does not take the data out of scope.

## The one-sentence version

**Do not put real customer data in this.** It is a prototype for
demonstrating an approach, the protections it has are the protections of a
careful prototype, and the obligations that come with real financial-crime
data are met by a programme — with an owner, a lawful basis, a retention
schedule, an appeals process and independent validation — rather than by a
configuration flag.

If you are reading this because somebody asked you to deploy it against real
data, this document is the thing to send back.
