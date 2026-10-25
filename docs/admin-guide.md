# Admin guide

For whoever runs MULEGUARD. Assumes it is deployed; `docs/deployment.md`
covers getting there.

## Users

`POST /api/v1/users`, admin only.

```json
{"username": "a.patel", "email": "a.patel@example.internal",
 "full_name": "A. Patel", "role": "ANALYST", "password": "..."}
```

Roles are `ANALYST`, `SENIOR_INVESTIGATOR`, `AUDITOR`, `ADMIN`.

### Give people the role that matches what they do

The temptation is to make everyone a senior investigator because assignment is
inconvenient. That removes the separation of duties, which is the thing the
roles are for: the person doing the work should not be the person signing it
off.

**Make sure at least one auditor exists, and that it is not an
administrator.** The auditor is the only role with no mutation permission at
all. An auditor who can also alter the record they are reviewing is not a
reviewer, and a deployment where the reviewer has an admin account has that
control on paper only.

### Lifecycle

| Action | Endpoint |
|---|---|
| Deactivate | `POST /api/v1/users/{id}/deactivate` |
| Reactivate | `POST /api/v1/users/{id}/reactivate` |
| Unlock after failed logins | `POST /api/v1/users/{id}/unlock` |
| Reset a password | `POST /api/v1/users/{id}/reset-password` |

Deactivate rather than delete. A deleted user leaves audit rows pointing at
nothing, and the audit trail has to say who did what — which is why the
username and role are copied onto each row rather than resolved through a
foreign key.

Five failed logins locks an account for fifteen minutes. Unlock is for when
somebody is actually locked out rather than being brute-forced.

### The development users

`scripts/create_dev_users.py` creates `admin`, `senior`, `analyst` and
`auditor` with a password from the environment. It is for laptops. It refuses
to run when `BACKEND_ENV` looks deployed, and if you find those four accounts
on a deployed instance, somebody overrode that.

## Ingestion

Admin only. See `docs/api.md` for the shapes and `data/schemas/` for the
schemas.

### Load order

```
accounts → entities → transactions → entity-links → complaints
```

Foreign keys are checked rather than records created implicitly. Loading
transfers first produces a wall of rejections that reads exactly like bad
data. `scripts/import_json.py` does the ordering.

### Check `ok`, not the status code

A partial load returns **201 with `ok: false`**. The four counts are disjoint
and sum to the number submitted:

```
accepted + rejected + duplicated + skipped == submitted
```

Check that arithmetic. It is the one thing a bulk import has to be able to
establish, and a caller watching only the HTTP status treats a half-loaded
batch as a success.

`errors` carries one entry per rejected row with its **index**, so you can fix
the file rather than bisect it.

### Dry run first, on anything large

```bash
python scripts/import_json.py --dir data/imports --dry-run
```

The API does the validation, so a dry run exercises the real rules rather than
a local approximation.

### The rejections that confuse people

| Value | Why it is refused |
|---|---|
| `account_type: "SAVINGS"` | Classifies the **holder** — INDIVIDUAL, BUSINESS, MERCHANT, OTHER. A product has no honest mapping onto a holder type |
| `status: "FROZEN"` | Not a status. The platform does not freeze accounts, so there is nowhere to record one |
| `confidence: 88` | A fraction, not a percentage. `0.88`. A value above 1 is refused rather than divided by a hundred |
| `ground_truth_label: ...` | Refused outright. A label on a record is one careless join from being a feature |
| An unknown account id | Foreign key. An account conjured from a transfer has no opening date, type or status |

Informal wording **is** accepted where the meaning is unambiguous:
`HEURISTIC` → `NORMALIZED`, `WIRE` → `NEFT`, `SUCCESS` → `COMPLETED`,
`PENDING` → `NEEDS_REVIEW` for a verification state. The alias table is in
`app/ingestion/normalizers.py`.

### Validate before loading

```bash
python scripts/check_schemas.py --data file.json \
                               --schema data/schemas/account.schema.json
```

## Analysis

`POST /api/v1/analysis/runs`. Analyst and above.

```json
{}                                        # everything, up to ANALYSIS_MAX_ACCOUNTS
{"account_ids": ["ACC-1", "ACC-2"]}       # specific accounts
{"as_of": "2026-04-13T00:00:00Z"}         # a point in time
```

Synchronous, and it holds a worker for its duration.
`ANALYSIS_MAX_ACCOUNTS` (default 1000) is the bound; raising it past
`ANALYSIS_HARD_MAX_ACCOUNTS` has no effect rather than an unbounded one.

Supports `Idempotency-Key`. The same key with a **different** payload is a
conflict rather than a silent replay, which is what you want when a retry was
not actually a retry.

Read the response rather than the database: it reports `account_count`,
`assessment_count`, per-stage timings and anything truncated or skipped. A run
over zero accounts is a filter problem, not a scoring problem.

## The audit trail

`GET /api/v1/audit` for auditors and admins; `GET /api/v1/audit/export` for
admins, bounded, and the export is itself audited.

Append-only: no endpoint edits or deletes a row, and refused actions are
recorded as well as permitted ones (`AUDIT_LOG_DENIED=true`) — a log of only
what succeeded cannot show that somebody tried.

### What it does not guarantee

Append-only **by convention**, because no code deletes. Not by database
enforcement. Anyone with database access can alter a row and nothing would
detect it; there is no tamper-evident chain.

If the audit trail needs to be evidence rather than a record, that gap is the
first thing to close.

## Model management

| Endpoint | Shows |
|---|---|
| `/api/v1/model/current` | Active version and **scoring mode** |
| `/api/v1/model/limitations` | What it cannot do |
| `/api/v1/model/versions` | Registered versions |
| `/api/v1/model/compare` | Two versions side by side |

`scoring_mode: HEURISTIC_FALLBACK` means no trained model is registered. That
is a **supported state**, not a fault: the platform scores with hand-set
weights and says so in every assessment, so an interface cannot present a
heuristic as model output.

Retraining: `docs/runbooks/model-retraining.md`. Read the model card before
acting on any number it produces.

## Routine checks

### Daily, if anybody is using it

```bash
scripts/smoke_test.sh
```

Then look at the dashboard queues for the things that only a person notices:

- **Unassigned alerts growing.** Nobody is triaging, and alerts do not age out.
- **Cases sitting in TRIAGED.** Assigned to somebody who has not started.
- **Unreviewed complaint correlations.** Inferred links being shown alongside
  confirmed ones because nobody has judged them.

### Weekly

- Closed cases by disposition. A sudden shift in the `FALSE_POSITIVE` share
  usually means the rules or the data changed, not that the fraud did.
- **Closed with `INCONCLUSIVE` as a share of the total.** Rising means
  investigators cannot reach a conclusion with what they are given; near zero
  means they are forcing a conclusion, which is worse.
- Analysis run durations, for the first sign of the synchronous run becoming a
  problem.

### On every upgrade

```bash
cd backend && alembic check          # a model change with no migration
cd .. && python scripts/check_schemas.py   # published schemas vs the vocabulary
```

The second one matters more than it looks. The vocabularies that describe
ingestible records are derived from one module because they used to exist in
four hand-maintained copies that had drifted apart on every field — and the
symptom was not an error but a correct record being rejected while an accepted
one failed on insert.

## Configuration changes

`docs/configuration.md` is the reference. Three to be careful with:

**`INGESTION_REQUIRE_SYNTHETIC`.** Turning it off is the single most
consequential change available. `docs/compliance-note.md` first.

**`BACKEND_SECRET_KEY`.** Rotating it invalidates every issued token, because
there is no revocation list. Everyone signs in again.

**`VITE_API_BASE_URL`.** A frontend **build** argument, not a runtime
variable. Changing it needs a rebuild; the symptom of forgetting is a frontend
that loads with every panel in its error state while the backend is healthy.

## What you cannot turn on

```
AUTOMATIC_ENFORCEMENT_ENABLED   AUTO_FREEZE_ENABLED
AUTO_BLOCK_PAYMENT_ENABLED      AUTO_BLACKLIST_ENABLED
ADVERSE_ACTION_AUTOMATION_ENABLED
```

All false, and startup refuses if any is set true. There is no code path
behind them and no `AccountStatus` value to write, so turning one on would not
make the platform freeze an account — it would stop the platform starting.

The absence of the capability is the control (ADR 0004). The settings exist so
the refusal is explicit and testable rather than implied by silence.

If somebody needs a score to trigger an action, that integration lives outside
this system, and whoever builds it owns the appeals process, the measured
false-positive rate on the affected population, and the record of what each
decision was based on.
