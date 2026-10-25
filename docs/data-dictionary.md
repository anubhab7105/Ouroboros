# Data dictionary

23 tables. The authority is `backend/app/models.py`; this is the reading of it
that explains why the columns are shaped the way they are.

Conventions throughout:

- Ids are strings, prefixed by kind. Not sequential integers: an id that
  appears in a URL, a log line and a report should not also tell the reader
  how many records exist.
- Money is `NUMERIC`, never a float, and **never summed across currencies**.
  There is no exchange rate here, so a cross-currency total is a number with
  no meaning that still sorts.
- Timestamps are `TIMESTAMP WITH TIME ZONE`, UTC end to end.
- Enum columns are declared over Python enums with `native_enum=False`, so the
  same models work on PostgreSQL and SQLite.
- A nullable column usually means **not computed** or **not applicable**, and
  that is distinct from zero. Where it means something specific, it is noted.

## The vocabularies

All defined in `app/core/vocabularies.py`, which is the single place they
exist. Four layers import it — the ORM, the ingestion normalizer, the
ingestion validator, the generator and the ML feature builder — because each
used to carry its own copy and the copies had drifted apart on every field.

| Enum | Values | Note |
|---|---|---|
| `AccountType` | INDIVIDUAL, BUSINESS, MERCHANT, OTHER | Classifies the **holder**, not the product. There is no SAVINGS |
| `AccountStatus` | ACTIVE, DORMANT, CLOSED, REVIEW_REQUIRED | No suspended or blocked value: MULEGUARD does not take those actions |
| `TransactionStatus` | PENDING, COMPLETED, FAILED, REVERSED | Only COMPLETED is settled fund movement |
| `Channel` | UPI, IMPS, NEFT, RTGS, CARD, INTERNAL | |
| `EntityType` | DEVICE, PHONE_HASH, UPI_ID, EMAIL_HASH, ADDRESS_HASH, IP_HASH, OTHER | The `_HASH` suffixes are the design |
| `MatchMethod` | EXACT, NORMALIZED, ENTITY_TEMPORAL, GRAPH_TEMPORAL, NARRATIVE_EXTRACTION, MANUAL, UNKNOWN | Roughly decreasing strength |
| `VerificationState` | UNVERIFIED, VERIFIED, REJECTED, NEEDS_REVIEW | |
| `CaseStatus` | NEW, TRIAGED, UNDER_INVESTIGATION, ESCALATED, CLOSED | |
| `Disposition` | CONFIRMED_FRAUD, FALSE_POSITIVE, INCONCLUSIVE, REFERRED | INCONCLUSIVE is a real answer |
| `RiskBand` | LOW, MEDIUM, HIGH, CRITICAL | Cut points in `config/scoring.default.json` |
| `AlertState` | NEW, ACKNOWLEDGED, UNDER_REVIEW, ESCALATED, CLOSED | `UNDER_REVIEW` is an *alert* state, not a case status |
| `ScoringMode` | TRAINED_MODEL, HEURISTIC_FALLBACK, RULES_ONLY, ML_DISABLED, UNKNOWN | Travels with every assessment |

`AccountStatus` deserves its paragraph. There is no `SUSPENDED`, `BLOCKED` or
`RESTRICTED` value, and that is not an omission. The platform takes no adverse
action on an account, so it has nowhere to record an enforcement decision —
and folding somebody else's decision to freeze an account into
`REVIEW_REQUIRED` would file it as one of ours. ADR 0004.

## Core records

### `accounts` (14 columns)

One synthetic bank account.

| Column | Notes |
|---|---|
| `id` | String, caller-supplied on ingestion |
| `account_type`, `status` | Enums above |
| `created_at` | When the account was **opened**, not when the row was written |
| `metadata_json` | Sanitised on ingestion. Secrets, raw identifiers and label-shaped keys are dropped |
| `record_created_at`, `record_updated_at` | Row lifecycle, from the timestamp mixin |

`created_at` and `record_created_at` are different and both matter. Account age
feeds the new-account-with-high-throughput signal, and that signal is about the
account, not the row.

### `transactions` (13 columns)

One transfer between two accounts.

| Column | Notes |
|---|---|
| `reference` | Unique. The transfer's identity in the outside world, and what makes a tier-1 complaint correlation possible |
| `sender_account_id`, `receiver_account_id` | Both foreign keys, both enforced |
| `amount` | `NUMERIC`. Positive: direction is carried by the two account columns, not by the sign |
| `currency` | Three-letter code |
| `occurred_at` | When the transfer happened. Every window, rate and velocity feature is defined relative to it |
| `status`, `channel` | Enums above |

A self-transfer — sender equal to receiver — is accepted and stored, and
excluded from counterparty counts. An account is not its own counterparty, and
counting it would inflate the fan-out of anybody who moves money between their
own accounts.

### `complaints` (17 columns)

One fraud or cybercrime complaint.

| Column | Notes |
|---|---|
| `reference` | Unique |
| `reported_at` | When it was **filed**. The correlation window is anchored on it |
| `category` | Free-text `String(100)`, not an enum: taxonomies differ between sources and forcing one loses the distinction the source drew |
| `narrative_raw` | The complainant's own words |
| `transaction_reference` | What they named, if they named one |
| `victim_account_id`, `suspected_account_id` | Nullable foreign keys |
| `amount`, `currency` | Nullable |

`narrative_raw` is the only free-text field a person wrote. It is normalised
for correlation and **never returned** in a list view, an error, a log line or
an export. It exists on the detail view and nowhere else.

A complaint is evidence that somebody reported something. It is not evidence
that the thing occurred, and nothing treats a named account as guilty because
a complaint named it.

### `entities` (10 columns)

One pseudonymous shared identifier.

| Column | Notes |
|---|---|
| `entity_type` | Enum. `_HASH` suffixes where the raw value is personal data |
| `identifier_hash` | Salted hash, 32–128 lowercase hex. The raw value is never stored |
| `identifier_display` | Masked, non-reversible, for an interface to show |
| `first_seen_at`, `last_seen_at` | Observation window |

The salt is configuration, never in the repository. A value that is not a hash
is refused on ingestion, because accepting one would put a raw phone number in
the column every downstream consumer treats as safe.

### `account_entity_links` (12 columns)

One account-to-identifier association, valid over a time range.

| Column | Notes |
|---|---|
| `match_method` | How it was established |
| `confidence` | **NULL for a deterministic method.** Nullable, `NUMERIC`, in [0, 1] |
| `verification_state` | Whether a person has confirmed an inferred link |
| `valid_from`, `valid_to` | `valid_to` null means open-ended |

The validity range is the point of the table. Two accounts that used the same
device two years apart are not connected; two that used it the same week may
be. A link with no bounds collapses that distinction and inflates every graph
it appears in.

`confidence` is NULL rather than 1.0 for `EXACT`. A certainty and a
probability in the same column invite a reader to compare them, and the
interface renders the absence as the word "identity".

## Detection

### `feature_snapshots` (10 columns)

The feature vector used for one assessment, with its cutoff.

| Column | Notes |
|---|---|
| `as_of` | The point-in-time cutoff |
| `features_json` | The vector |
| `schema_version` | Which catalogue it was built against |

The snapshot contains only data from **strictly before** `as_of`. The boundary
is strict rather than inclusive because a transfer at exactly the cutoff is
information from the instant being predicted, and including it is temporal
leakage that makes evaluation look better.

Stored rather than recomputed, because reproducing a score months later means
reproducing its inputs.

### `model_assessments` (22 columns)

One account's score at one point in time.

| Column | Notes |
|---|---|
| `score` | 0–100. Nullable: an unavailable score is not a zero |
| `score_type`, `score_version` | What kind of number this is |
| `risk_band` | Derived from the score and the configured cut points |
| `scoring_mode` | TRAINED_MODEL or HEURISTIC_FALLBACK. Travels with the score |
| `as_of`, `scored_at` | The cutoff, and when the computation ran |
| `components_json` | Per-component values **and whether each was available** |
| `explanation_json` | Contributions, labelled as operational attribution, not causal proof |
| `caveats_json` | The limits on reading this score |
| `evidence_refs` | What the score was computed from |
| `dataset_fingerprint`, `model_version_id` | Reproducibility |

`components_json` carrying availability per component is what makes
"unavailable is not zero" real in storage rather than only in the API.

### `rule_hits` (16 columns) and `risk_indicators` (14 columns)

A rule hit records which rule matched, with what inputs and what effect.
A risk indicator is the human-readable finding shown in the interface — code,
title, severity, and the evidence behind it.

Both are stored per assessment rather than recomputed, for the same reason as
the snapshot.

### `analysis_runs` (33 columns)

One execution over a set of accounts. Status, counts, timings, the `as_of`
used, the parameters, and per-stage timings.

Wide because the run is the audit record of the computation: which accounts,
which model, which cutoff, how long each stage took, what was truncated or
skipped.

### `model_versions` (20 columns), `model_evaluations` (16 columns)

A registered model and its evaluation. Metrics, split strategy, dataset
fingerprint, and the limitations text that travels with the version.

Coefficients are not exposed through the API by default. Weights over named
behavioural features are a map of how to evade the detector.

### `graph_analysis_runs` (14 columns)

A graph computation, its bounds, and whether it was truncated. A truncated
traversal establishes nothing, so recording the bounds is what makes the
result interpretable later.

## Workflow

### `alerts` (32 columns)

A request for a person to look. That is the whole of what it is.

| Column | Notes |
|---|---|
| `state` | AlertState |
| `score` | Nullable: an alert can be raised by a rule effect without a fused score |
| `priority` | Independent of the score |
| `dedup_key`, `first_seen_at`, `last_seen_at` | One alert per account per window per typology group, updated rather than duplicated |
| `assigned_to`, `acknowledged_by`, `closed_by` | Who did what |

Deduplication is why the table is wide. Without it, an account scored nightly
produces thirty alerts a month and the queue becomes unusable.

### `alert_evidence` (9 columns), `case_evidence` (14 columns)

Typed references to records: account, transaction, complaint, alert, graph
path, model assessment, entity link. A snapshot of the referenced record is
stored alongside, because the record may change and the evidence is what was
seen.

`case_evidence` has `is_active`, `removed_by`, `removed_at` and
`removal_reason`. Evidence is **withdrawn, never deleted**, and the reason is
required — a case's history is the point, and an item that silently vanished
is the one somebody will ask about.

### `investigation_cases` (24 columns)

| Column | Notes |
|---|---|
| `status` | CaseStatus |
| `disposition` | **Required to close.** Nullable only because an open case has none |
| `assignee_id` | Required to start |
| `closed_at`, `closed_by` | |
| `alert_id`, `account_id` | What it came from |

The disposition is the single most consequential field in the schema. Every
later measurement of detection quality reads it, and it cannot be
reconstructed from the closure note. A case closed without one is
indistinguishable from a case nobody concluded, which is why the state machine
refuses.

### `case_events` (12 columns), `case_notes` (8 columns)

Append-only. An event is a workflow action with its actor and metadata; a note
is an investigator's prose. Neither is editable, because a case history that
can be rewritten is not a history.

### `complaint_correlations` (23 columns)

The join between a complaint and what it may relate to.

| Column | Notes |
|---|---|
| `match_tier` | 1–5 |
| `match_method` | How |
| `confidence` | **NULL for tiers 1–2** |
| `review_state` | **NULL for tiers 1–2** |
| `reviewed_by`, `reviewed_at`, `review_note` | |

Tiers 1–2 are deterministic — an exact transaction reference, or an account the
complainant named. They are identities, so they carry no confidence and need
no review. Tiers 3–5 are inferred and carry both.

A rejected correlation is kept, not deleted. The fact that somebody looked and
said no is worth more than a clean table, and it stops the same inference
being re-raised next week.

### `audit_events` (15 columns)

Append-only. Actor, action, resource, outcome, request id, hashed IP, and
sanitised metadata.

| Column | Notes |
|---|---|
| `actor_id`, `actor_username`, `actor_role` | The username and role are **denormalised on purpose** |
| `action`, `outcome` | |
| `resource_type`, `resource_id` | |
| `request_id` | Ties a log line to an audit row to a user's screenshot |
| `ip_hash` | Hashed, not stored raw |
| `metadata_json` | Sanitised: no narratives, no secrets, no raw identifiers |

The denormalisation is deliberate. A user may be renamed, have their role
changed or be deactivated, and the audit row has to say who did the thing at
the time — resolving through a foreign key would rewrite history every time a
user record changed.

There is no endpoint that edits or deletes an audit row.

### `users` (18 columns)

Local accounts. Username, email, role, password hash, active flag,
`must_change_password`, failed login count, lockout state.

Passwords are hashed with a configured algorithm and never logged. The hash is
not returned by any endpoint.

### `ground_truth_labels` (9 columns)

The one table that exists to be kept away from everything else.

It holds the generator's labels for evaluation. Nothing in the feature pipeline
reads it; the ingestion API refuses every field in it; the feature-schema
blocklist refuses names shaped like it; and `assert_no_label_leakage` checks a
vector before training.

Four guards for one table, because a model trained on a feature derived from
its own label scores perfectly in evaluation and uselessly in production — and
the failure makes the numbers *better*, which is why it needs guarding rather
than noticing.

## Relationships worth knowing

```
accounts ──< transactions >── accounts          (sender, receiver)
accounts ──< account_entity_links >── entities  (time-bounded)
accounts ──< model_assessments ──< risk_indicators
                              └──< rule_hits
model_assessments ──< alerts ──< alert_evidence
alerts ──< investigation_cases ──< case_evidence
                              ├──< case_events
                              └──< case_notes
complaints ──< complaint_correlations >── accounts / transactions / entities
```

Every workflow mutation also writes an `audit_events` row, in the same
transaction, so there is no state in which something happened and nothing
recorded it.
