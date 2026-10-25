# Security

What this protects, how, and — the longer section — what it does not protect.

A prototype that lists only its controls is making a claim. The controls below
are real and tested; the gaps at the end are the reason this is not a system
for real data.

## Authentication

Signed bearer tokens from a local user table. HS256, 30-minute expiry, issuer
and audience claims, 30 seconds of clock skew allowed.

`BACKEND_SECRET_KEY` ships as a placeholder so a local checkout runs, and
startup **refuses** while it is still the placeholder in any non-local
environment. There is no revocation list
(`AUTH_TOKEN_REVOCATION_ENABLED=false`), so rotating the key is the only way
to invalidate a token early — short expiry is the mitigation.

Passwords are Argon2id by default (`argon2id`, time cost 3, 64 MiB, two
lanes), with bcrypt and PBKDF2 available for an existing store and automatic
upgrade to Argon2 on next login. Minimum 12 characters, with character-class
requirements.

### Login responses do not confirm which usernames exist

`AUTH_REVEAL_LOCKED_ACCOUNT` and `AUTH_REVEAL_INACTIVE_ACCOUNT` are both
false. A failed login says the credentials were wrong and nothing else — "that
account is locked" tells an attacker they found a real username, which is
exactly what they were testing for.

Five failed attempts locks for fifteen minutes, counted in a fifteen-minute
window and reset on success. The login endpoint is rate-limited to five a
minute independently of the lockout, because a lockout keyed to an account
does nothing against spraying one password across many accounts.

## Authorization

Deny by default (`RBAC_DENY_BY_DEFAULT=true`), no superuser bypass
(`RBAC_SUPERUSER_BYPASS=false`), unknown roles denied.

Endpoints declare a **named permission**, never a role:

```python
actor: User = Depends(require_permission(Permission.CASE_CLOSE))
```

That survives a change to which roles may close a case; `if role == "SENIOR"`
does not, and the change gets missed in one endpoint out of twelve.

Four roles, and two of the boundaries are the point of having them:

- An **analyst cannot assign or close** a case. Separation of duties: the
  person doing the work is not the person signing it off.
- An **auditor cannot change anything at all** — the only role with no
  mutation permission. An auditor who can also alter the record they are
  reviewing is not a reviewer, which is the whole reason the role exists.

`tests/test_permissions.py` checks the matrix against a **hand-written** table
rather than one derived from the registry. A generated table agrees with the
registry by construction and could never catch a change to it.

## Data protection

### Identifiers are hashed, and raw ones are refused

Device ids, phone numbers, email addresses, IPs and postal addresses reach the
entity table as salted hashes. The raw values are never stored, which is why
the enum values carry `_HASH` suffixes.

Ingestion refuses a value in `identifier_hash` that is not 32–128 lowercase
hex characters. Accepting one would put a raw phone number in the column every
downstream consumer treats as safe.

`identifier_display` holds a masked, non-reversible label for an interface to
show: `+91-****-****1234`.

### Client addresses are hashed before they are logged

`PRIVACY_IP_LOG_MODE=hashed`, with `PRIVACY_IP_HASH_SALT` configurable. An
audit row records `ip_hash`, not an address.

### Complaint narratives are the most restricted field in the schema

A complainant's own words, describing being defrauded. They are:

- returned on the complaint detail view only, and only to
  `COMPLAINT_NARRATIVE_ACCESS_ROLES` (senior and above);
- **never** in a list view, an error body, an export, or a log line;
- truncated to `BACKEND_MAX_NARRATIVE_LOG_CHARS` if one somehow reaches a log;
- normalised for correlation without the normalised form being returned.

### The field blocklist

Ingestion refuses, rather than ignores, fields that would be dangerous to
store:

| Refused | Why |
|---|---|
| `ground_truth_label`, `scenario_id`, `ring_id`, `scenario_type` | Target leakage. One careless join from being a feature |
| Raw identifiers — `phone_number`, `upi_id`, `device_id`, `account_number` | Identity leakage. Identifiers belong in the entity table as hashes |
| Secrets, tokens, passwords, database URLs | Nothing good follows from accepting one |
| Model artefact paths | Path traversal into a loader |

Refused rather than dropped, because a dropped field leaves no trace that
somebody's pipeline is joining a label onto the records.

The generator's behavioural `profile` is subject to the same reasoning. It is
the generator's ground truth under a gentler name, and it is deliberately not
written onto the record — it travels in `SyntheticDataset.labels`, which is
not ingestible.

### Errors carry no internals

The error envelope has a code, a message, a category and a retryable flag. No
tracebacks, no exception class names, no SQL, no database URLs, no file paths,
no narratives. Validation details are sanitised and can be switched off
entirely.

A 500 carries a generic message and a request id. The request id is how the
actual error is found in the log, which is where it belongs.

## Transport and headers

The application does not terminate TLS. Put it behind something that does.

Headers applied by `SecurityHeadersMiddleware`:

| Header | Default |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | camera, microphone, geolocation denied |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Strict-Transport-Security` | off by default; on, with max-age, when enabled |
| `Content-Security-Policy` | off by default |
| `Cache-Control: no-store` | on auth and error responses always; on API responses when enabled |

Every setting the middleware reads is declared in the settings model. That is
worth stating because it was not always true: fourteen of them were read by
the middleware and absent from the model, and since the model ignores unknown
variables, setting any of them did nothing — HSTS could be switched on without
a max-age, and CSP with nowhere to send reports.
`tests/test_api_flow.py` now reads the names out of the middleware and asserts
each one is declared.

CORS allows credentials and an explicit origin list. Not `*` — `*` with
credentials is refused by browsers anyway, and the configuration should say
what it means.

`TrustedHostMiddleware` rejects an unexpected `Host`. Behind a proxy, list the
forwarded host and set `BACKEND_TRUST_PROXY_HEADERS`.

## Request correlation

Every response carries `X-Request-ID`, echoing the caller's when one was sent.
It appears in the error body too, because that is what a user screenshots.

Inbound values are **validated against a character set rather than reflected**
(`REQUEST_ID_VALIDATE_INBOUND=true`). The id reaches log lines, audit rows and
report filenames, so an unvalidated one is a log-injection parameter. A
rejected value is replaced, not dropped.

## Audit

Append-only. There is no endpoint that edits or deletes a row.

Each row: actor id, username, role, action, outcome, resource type and id,
request id, hashed IP, sanitised metadata, timestamp. Written in the **same
transaction** as the change it describes, so there is no state in which
something happened and nothing recorded it.

`AUDIT_LOG_DENIED=true` records refused actions as well as permitted ones. A
log of only what succeeded cannot show that somebody tried.

The username and role are **denormalised on purpose**. A user may be renamed,
have their role changed or be deactivated, and the row has to say who did the
thing at the time — resolving through a foreign key would rewrite history
every time a user record changed.

Reading the log is `AUDITOR` or `ADMIN`; exporting is `ADMIN`. Export is
bounded and the export itself is audited.

## ML-specific

Deserialising a model artefact is arbitrary code execution. So:

- `USER_UPLOADED_MODEL_ENABLED=false` and `PICKLE_UNSAFE_LOAD_ENABLED=false`,
  both refused if set true;
- `ML_ARTIFACT_TRUSTED_PATH_ONLY=true` restricts loading to a configured
  directory;
- the supervised implementation is hand-written logistic and softmax
  regression, with no artefact format that executes on load.

Coefficients are not exposed by the API. Weights over named behavioural
features are a map of how to evade the detector.

`ML_LABEL_LEAKAGE_CHECK=true` enables `assert_no_label_leakage`, which the
evaluation path calls before reporting anything.

## What does not take adverse action

No endpoint changes an account's status as a consequence of a score.
`AccountStatus` has no suspended, blocked or restricted value, so there is
nowhere to record an enforcement decision.

Five settings state it (`AUTOMATIC_ENFORCEMENT_ENABLED`, `AUTO_FREEZE_ENABLED`,
`AUTO_BLOCK_PAYMENT_ENABLED`, `AUTO_BLACKLIST_ENABLED`,
`ADVERSE_ACTION_AUTOMATION_ENABLED`), all false and all refused if set true.
There is no code path behind them: the absence of the capability is the
control, and the settings are the statement. ADR 0004.

`tests/test_e2e_workflow.py::TestNoAdverseAction` runs an investigation from
alert to closure and asserts the account is untouched at the end.

---

## What this does not protect against

The section that matters. Everything above is real; none of it adds up to a
system fit for real financial-crime data.

### Not done at all

- **No penetration test.** Nothing here has had one.
- **No threat model beyond a starting point.** `docs/threat-model.md` is a
  first pass, not a conclusion.
- **No encryption at rest.** That is the database's and the disk's job, and
  this repository does not configure it.
- **No key management.** `BACKEND_SECRET_KEY` is an environment variable. No
  KMS, no rotation schedule, no envelope encryption.
- **No secret scanning in CI.** Run one.
- **No dependency scanning in CI.** Run `pip-audit` and `npm audit`, and know
  that a clean result is a statement about known issues on one day.
- **No SBOM.**
- **No mTLS, no network policy, no WAF.**

### Known weaknesses in what is here

**Tokens cannot be revoked.** A stolen token is valid until it expires.
Thirty minutes is the mitigation and it is not a strong one.

**No refresh flow.** Sessions end abruptly, which pushes operators toward
longer expiry, which weakens the mitigation above.

**Rate limiting is in-process.** Limits are per worker, so the effective limit
is multiplied by `BACKEND_WORKERS`, and nothing is shared across instances.

**No CSRF protection**, because authentication is a bearer token and cookie
auth is off. Turning `AUTH_USE_COOKIES` on would need CSRF protection added.

**Audit integrity is by convention.** Append-only because no code deletes, not
because the database enforces it. Anyone with database access can edit a row,
and nothing would detect it. A tamper-evident chain is not implemented.

**The frontend types are hand-written.** No generated client, so the types can
drift from the API; a mismatch shows up as `undefined` in a table cell rather
than as an error.

**Hard caps are in code.** The limits that bound traversal, export and
analysis are clamped in Python, not enforced by the database. A direct
database query is unbounded.

### Reporting a vulnerability

See `CONTRIBUTING.md`. Do not open a public issue for anything exploitable.

### The honest summary

The controls here are the ones a careful prototype should have, and several of
them — the permission matrix, the field blocklist, the narrative restriction,
the absence of any enforcement capability — are better than a prototype
usually gets.

They are not a security posture for a system holding real transaction and
complaint data. That needs the list above closed, an owner, and a programme
rather than a document. `docs/compliance-note.md` is the companion piece and
is blunter.
