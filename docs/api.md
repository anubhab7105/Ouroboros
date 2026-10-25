# API

Base path `/api/v1`. Interactive schema at `/docs` when
`BACKEND_DOCS_ENABLED` is true; the raw document is at
`/api/v1/openapi.json`.

The endpoint modules are the contract. `app/schemas/` exists and is not what
the API returns — see `docs/architecture.md`.

## Authentication

```http
POST /api/v1/auth/login
Content-Type: application/json

{"identifier": "analyst", "password": "..."}
```

`identifier`, not `username`: it accepts either the username or the email.

```json
{"access_token": "...", "token_type": "bearer", "expires_in": 3600, "user": {...}}
```

Send it on everything else:

```http
Authorization: Bearer <access_token>
```

Tokens are short-lived and there is no refresh endpoint. Log in again. There
is also no revocation list, so rotating `BACKEND_SECRET_KEY` is the only way
to invalidate a token before it expires — worth knowing before rotating it at
a busy moment.

Public paths: `/health`, `/api/v1/health`, `/api/v1/health/live`,
`/api/v1/health/ready`, `/api/v1/health/status`, `/api/v1/openapi.json`.
Everything else under `/api/v1` is 401 without a token.

## Three shapes to learn once

### Pagination

Identical on every list endpoint. Flat, not nested under `meta`:

```json
{
  "items": [...],
  "page": 1,
  "page_size": 50,
  "total": 1284,
  "total_pages": 26,
  "sort_by": "created_at",
  "sort_order": "desc",
  "caveats": ["..."]
}
```

- `page` is 1-based. `page=0` is a 422, not an empty page.
- `page_size` is clamped rather than refused, so a large value still works.
- `sort_by` and `sort_order` come back, because a client rendering the current
  sort cannot infer it when the server fell back to a default.
- An unknown `sort_by` is a 422. Ignoring it would return rows in some other
  order while the client believed its sort worked.
- A page past the end is empty, not an error.

### Errors

```json
{
  "code": "MULEGUARD_NOT_FOUND",
  "message": "Resource not found.",
  "category": "client",
  "retryable": false,
  "details": {"...": "..."},
  "request_id": "req-..."
}
```

Flat, for every failure — including the ones FastAPI would answer in its own
`{"detail": [...]}` format. Codes are namespaced with `MULEGUARD_` so they can
be looked up and translated without colliding with every other API the client
talks to.

`retryable` is first-class because it is the first thing a client needs to
know and is not derivable from the status code.

### Caveats

Scored and derived responses carry a `caveats` array. They are in the payload
rather than the documentation because the platform's whole position is that
its output is an investigative lead rather than a finding, and a caveat a
client can drop is a caveat that will be dropped.

## Request correlation

Send `X-Request-ID` and it comes back. Send nothing and one is generated.
Either way it is in the response header and in the body of an error, because
the error body is what a user screenshots.

Values are validated against a character set rather than reflected — the id
reaches logs and audit rows, so an unvalidated one is a log-injection
parameter. A rejected value is replaced, not dropped.

## Endpoints

### Health

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | Root-level liveness. Public |
| GET | `/api/v1/health/live` | Liveness |
| GET | `/api/v1/health/ready` | **Includes the database check** |
| GET | `/api/v1/health` | Per-subsystem detail |

`ready` answers 200 with `ready: false` while a dependency check is failing,
so the status code alone is not the signal. A process that is listening is not
a backend that can serve a request.

### Ingestion — admin only

| Method | Path |
|---|---|
| GET | `/api/v1/ingestion/status` |
| POST | `/api/v1/ingestion/accounts` |
| POST | `/api/v1/ingestion/entities` |
| POST | `/api/v1/ingestion/transactions` |
| POST | `/api/v1/ingestion/entity-links` |
| POST | `/api/v1/ingestion/complaints` |

```json
{
  "records": [ {...}, {...} ],
  "options": {
    "source_system": "my-loader",
    "source_batch_id": "batch-001",
    "dry_run": false,
    "allow_partial": false,
    "on_duplicate": "skip"
  }
}
```

Response: four disjoint counts that together account for every submitted
record.

```json
{"ok": true, "entity_type": "accounts", "accepted": 7, "rejected": 0,
 "duplicated": 0, "skipped": 0, "errors": [], "caveats": [...]}
```

A caller can check `accepted + rejected + duplicated + skipped == submitted`
and know nothing was silently dropped, which is the one thing a bulk import
has to be able to establish.

**A partial load returns 201 with `ok: false`.** Check `ok`, not the status
code. `errors` carries one entry per rejected row with its index, so you can
fix the file rather than bisect it.

**Load in order.** Accounts, entities, transactions, entity links,
complaints. Foreign keys are checked rather than records created implicitly:
an account conjured from a transfer has no opening date, type or status and
would score as a brand-new account forever.

Schemas for each record type are in `data/schemas/`, generated from the same
module the validator reads.

### Accounts

| Method | Path |
|---|---|
| GET | `/api/v1/accounts` |
| GET | `/api/v1/accounts/{id}` |
| GET | `/api/v1/accounts/{id}/summary` |
| GET | `/api/v1/accounts/{id}/transactions` |
| GET | `/api/v1/accounts/{id}/assessment` |
| GET | `/api/v1/accounts/{id}/assessments` |
| GET | `/api/v1/accounts/{id}/alerts` |
| GET | `/api/v1/accounts/{id}/entities` |
| GET | `/api/v1/accounts/{id}/complaint-correlations` |

`/assessment` reports the absence of one explicitly rather than returning
null:

```json
{"available": false, "status": "no_assessment", "message": "...",
 "assessment": null, "indicators": []}
```

An account nothing has looked at is `no_assessment`, which is a different
statement from a score of zero in the LOW band — and a client rendering a null
as zero would make the second claim.

`/summary` counts **completed transfers only**, and returns the pending,
failed and reversed counts separately. That difference is the point: an
aggregate including pending transfers describes money that has not moved.
Per-currency totals are never summed, because there is no exchange rate here
and a cross-currency total is a number with no meaning that still sorts.

### Transactions, entities, complaints

| Method | Path |
|---|---|
| GET | `/api/v1/transactions`, `/{id}`, `/{id}/alerts`, `/{id}/evidence`, `/{id}/complaint-correlations` |
| GET | `/api/v1/entities`, `/{id}`, `/{id}/accounts`, `/{id}/alerts`, `/{id}/complaint-correlations` |
| PATCH | `/api/v1/entities/{id}/links/{link_id}/verification-state` |
| GET | `/api/v1/complaints`, `/stats`, `/{id}`, `/{id}/correlations`, `/{id}/accounts`, `/{id}/transactions`, `/{id}/entities`, `/{id}/alerts`, `/{id}/history`, `/{id}/export` |
| POST | `/api/v1/complaints/{id}/correlations/{cid}/review-state` |

Complaint narratives are never returned in a list view, an error, a log line
or an export. They exist for correlation and are read on the detail view only.

A correlation's `match_tier` decides its shape: tiers 1–2 are deterministic
and carry no confidence and no review state; tiers 3–5 carry both. Reviewing
is senior-and-above.

### Analysis

| Method | Path |
|---|---|
| GET | `/api/v1/analysis/status` |
| GET | `/api/v1/analysis/runs` |
| POST | `/api/v1/analysis/runs` |
| GET | `/api/v1/analysis/runs/{id}` |
| GET | `/api/v1/analysis/runs/{id}/results` |
| GET | `/api/v1/analysis/runs/{id}/history` |
| POST | `/api/v1/analysis/runs/{id}/cancel` |

```json
{"account_ids": ["ACC-1"], "as_of": "2026-04-13T00:00:00Z"}
```

Synchronous: the response has a terminal status. `{}` scores every account
passing the default filter.

`as_of` is a point-in-time cutoff, and the boundary is strict. A feature
snapshot contains only data from **before** the cutoff, not at it — a transfer
at exactly the cutoff is information from the instant being predicted.

Supports `Idempotency-Key`. The same key with a different payload is a
conflict rather than a silent replay.

### Alerts

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/alerts`, `/{id}`, `/{id}/evidence`, `/{id}/history` | read |
| POST | `/api/v1/alerts/{id}/evidence` | analyst+ |
| POST | `/api/v1/alerts/{id}/acknowledge` | analyst+ |
| POST | `/api/v1/alerts/{id}/escalate` | senior+ |
| POST | `/api/v1/alerts/{id}/assign` | senior+ |
| POST | `/api/v1/alerts/{id}/close` | analyst+ |
| POST | `/api/v1/alerts/{id}/reopen` | analyst+ |
| POST | `/api/v1/alerts/{id}/case` | analyst+ |

Workflow actions return `changed`, `previous_state` and `new_state`. An action
that was a no-op says so rather than reporting success, and `audited` says
whether a record was written — a no-op writes none, because an audit row for
an event that did not happen is worse than no row.

`score` is nullable: an alert can be raised by a rule effect without a fused
score. `evidence_count`, `case_count` and `active_case_count` are nullable
too, and null means "not computed for this view" rather than zero.

`/case` copies the alert's evidence into the new case, reports
`copied_evidence_count` and `total_evidence_count`, and sets
`evidence_truncated` when the bounded copy did not take everything.

### Cases

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/cases`, `/{id}` | read |
| POST | `/api/v1/cases` | analyst+ |
| PATCH | `/api/v1/cases/{id}` | analyst+ |
| POST | `/api/v1/cases/{id}/assign` | senior+ |
| POST | `/api/v1/cases/{id}/start` | analyst+ |
| POST | `/api/v1/cases/{id}/escalate` | analyst+ |
| POST | `/api/v1/cases/{id}/close` | senior+ |
| POST | `/api/v1/cases/{id}/reopen` | senior+ |
| GET/POST | `/api/v1/cases/{id}/notes` | read / analyst+ |
| GET/POST | `/api/v1/cases/{id}/evidence` | read / analyst+ |
| POST | `/api/v1/cases/{id}/evidence/{eid}/remove` | senior+ |
| GET | `/api/v1/cases/{id}/events`, `/audit`, `/export` | read |

The state machine is in `app/services/case_state_machine.py` and the endpoints
enforce it, including what each transition requires:

| From → To | Action | Requires |
|---|---|---|
| NEW → TRIAGED | triage | — (assignment does this) |
| NEW / TRIAGED → UNDER_INVESTIGATION | start | **an assignee** |
| TRIAGED / UNDER_INVESTIGATION → ESCALATED | escalate | **a reason** |
| ESCALATED → UNDER_INVESTIGATION | de_escalate | **a reason** |
| any open → CLOSED | close | **a reason and a disposition** |
| CLOSED → UNDER_INVESTIGATION | reopen | **a reason** |

Dispositions are `CONFIRMED_FRAUD`, `FALSE_POSITIVE`, `INCONCLUSIVE`,
`REFERRED` — the whole vocabulary, because the column is declared over it.

A disposition is required to close. It is the field every later measurement of
detection quality reads and it cannot be reconstructed afterwards from the
closure note, so a case closed without one is indistinguishable from a case
nobody concluded.

Evidence is **withdrawn, never deleted**, and removal requires a reason. The
withdrawn item stays retrievable with its reason, because a case's history is
the point.

### Graph

| Method | Path |
|---|---|
| GET | `/api/v1/graph/status` |
| GET | `/api/v1/graph/subgraph` |
| GET | `/api/v1/graph/paths` |
| GET | `/api/v1/graph/shared-entities` |
| GET | `/api/v1/graph/money-trails` |

Every response carries `truncated` and the limits that applied. **A truncated
traversal establishes nothing**: if the search was cut off, "no path found"
means "no path found within the budget".

A money trail is a **shape**, not a tracing of funds. Money is fungible, so
"this rupee went there" is not a claim the data supports; what the trail shows
is a sequence of transfers consistent with a pattern.

### Reports

| Method | Path |
|---|---|
| GET | `/api/v1/reports/status`, `/limitations` |
| GET | `/api/v1/reports/cases/{id}/preview`, `/evidence-index` |
| POST | `/api/v1/reports/cases/{id}/generate` |
| GET | `/api/v1/reports/cases/{id}` |

`/generate` returns metadata — filename, size, SHA-256, section summaries,
bounds — not bytes. Generation is the audited event and is recorded even if
the download never happens. The bytes come from the `GET`.

`/limitations` returns the disclaimer text as data, so the interface and the
PDF render the same words from one source.

### Model

| Method | Path |
|---|---|
| GET | `/api/v1/model/status`, `/current`, `/limitations`, `/feature-schema` |
| GET | `/api/v1/model/versions`, `/{id}`, `/{id}/evaluations` |
| GET | `/api/v1/model/evaluations/{id}` |
| GET | `/api/v1/model/compare` |

`/current` reports the scoring mode, which is `HEURISTIC_FALLBACK` when no
model is registered. That is a supported state, not a broken one, and the mode
travels in every assessment so an interface cannot present a heuristic as
model output.

Coefficients are not exposed by default. Weights over named behavioural
features are a map of how to evade the detector.

### Dashboard, audit, users

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/dashboard/status`, `/overview`, `/metrics`, `/queues`, `/trends` | read |
| GET | `/api/v1/audit`, `/status`, `/stats`, `/{id}` | auditor or admin |
| GET | `/api/v1/audit/export` | admin |
| GET/POST | `/api/v1/users`, `/{id}` | admin |
| PATCH | `/api/v1/users/{id}` | admin |
| POST | `/api/v1/users/{id}/deactivate`, `/reactivate`, `/unlock`, `/reset-password` | admin |

The audit log is append-only. There is no endpoint that edits or deletes a row,
by design.

## Permissions

| Set | Roles |
|---|---|
| read | analyst, senior, auditor, admin |
| analyst and above | analyst, senior, admin |
| senior and admin | senior, admin |
| auditor and admin | auditor, admin (audit read) |
| admin only | admin |

The two that surprise people are deliberate: an **analyst cannot assign or
close** a case, and an **auditor cannot change anything at all**. The auditor
is the only role with no mutation permission, which is what makes it useful
for reviewing an investigation without being able to alter it.

Endpoints gate on named permissions, not roles. `app/core/permissions.py` is
the registry; `tests/test_permissions.py` checks it against a hand-written
table rather than one derived from the registry, because a generated table
agrees with the registry by construction and could never catch a change to it.

## Rate limiting

On by default for authentication, configurable for the rest. A 429 carries the
error envelope and says nothing about the keying scheme — telling a caller how
the limit is keyed tells them how to spread around it.
