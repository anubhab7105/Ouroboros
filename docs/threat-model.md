# Threat model

A first pass, not a conclusion. Nothing here has had a penetration test or an
independent review, and a threat model written by the people who wrote the
system has a predictable blind spot.

It is worth having anyway, because the interesting threats to this system are
not the ones a scanner finds.

## What is worth attacking

Four things, in descending order of how much damage their loss does.

**The complaint narratives.** A person's own account of being defrauded,
describing what they were told, what they lost, and often how they feel about
it. The most sensitive field in the schema, and the one whose exposure is
least recoverable.

**The transaction graph.** Who pays whom. Commercially sensitive, and for a
person under investigation, a map of their financial life.

**The detection logic and the model weights.** Not confidential in the usual
sense — they are a map of how to evade the detector. A mule network that knows
the fan-in threshold operates below it.

**The audit trail.** Its value is entirely in being trustworthy. An audit
trail somebody has edited is worse than no audit trail, because it is still
believed.

## Who might attack it

### An outsider with network access

Conventional. Covered conventionally: bearer tokens, deny-by-default
authorization, rate limiting, security headers, no tracebacks in responses,
TLS terminated in front.

The specific weakness: tokens **cannot be revoked**
(`AUTH_TOKEN_REVOCATION_ENABLED=false`), so a stolen token is valid until it
expires. Thirty minutes is the mitigation and it is not a strong one.

### A legitimate user exceeding their role

The one most likely to actually happen, and the reason the permission matrix
is as granular as it is.

An analyst cannot assign or close a case. An auditor cannot change anything.
Endpoints gate on named permissions rather than roles, deny-by-default is on,
there is no superuser bypass, and refused actions are audited.

What remains: a user with a legitimate role browsing data they have no
business need for. Role-based access is not need-to-know, and nothing here
implements need-to-know. An analyst can read every account. That is a
deliberate trade — an investigation platform where you cannot see the
counterparty is not usable — and it means the control on curiosity is the
audit trail rather than the authorization layer.

### An insider with database access

Largely unmitigated, and worth stating plainly.

The audit trail is append-only because no code deletes, not because the
database enforces it. Anyone with database access can edit or delete a row and
nothing would detect it. There is no tamper-evident chain, no write-once
storage, no external log shipping of audit rows.

If the audit trail needs to be evidence rather than a record, that is the
first gap to close, and the fix is architectural rather than a setting.

### Somebody probing the detector

The attacker this system is actually about, and the one a generic threat model
omits.

A mule network wants to know where the thresholds are. Three things make that
harder:

- **Coefficients are not exposed.** `/api/v1/model/current` reports the
  version and the scoring mode, not the weights.
- **Rule thresholds are configuration, not API.** They are not returned by any
  endpoint.
- **Nothing is automated.** A score produces a queue entry for a person, so
  probing the system does not produce a measurable automated response to
  calibrate against.

What does not help: the scoring is deliberately explainable. Feature
contributions are returned so an investigator can defend a decision, and a
contribution list is informative to a determined adversary too. That is a
genuine tension and the choice here is explainability, because a score nobody
can defend is a score nobody should act on.

### Somebody feeding the system bad data

Ingestion is admin-only, which bounds this considerably. Beyond that: foreign
keys enforced, enum vocabularies derived from one module, amounts and
confidences range-checked, timestamps bounded by a clock-skew tolerance,
batches transactional, duplicates detected by natural key.

The field blocklist refuses — rather than ignores — ground-truth labels,
scenario ids, ring ids, raw identifiers, secrets and model artefact paths. A
dropped field leaves no trace that somebody's pipeline is joining a label onto
the records.

What remains: an admin can load plausible-looking records that are wrong. No
statistical validation of a batch, no drift detection on ingestion. A feed
that slowly changes shape would not be noticed.

### Somebody uploading a model

Deserialising a model artefact is arbitrary code execution, so:

`USER_UPLOADED_MODEL_ENABLED=false` and `PICKLE_UNSAFE_LOAD_ENABLED=false`,
both **refused if set true**. `ML_ARTIFACT_TRUSTED_PATH_ONLY=true` restricts
loading to a configured directory. The supervised implementation is
hand-written with no artefact format that executes on load.

## Specific attacks

### Credential stuffing

Five failures locks for fifteen minutes; login is rate-limited to five a
minute independently, because a per-account lockout does nothing against one
password sprayed across many accounts. Failed logins do not reveal whether an
account exists or is locked.

The limiter is **in-process**: per worker, nothing shared across instances. A
deployment that matters needs a shared limiter in front.

### Enumeration

Ids are prefixed strings rather than sequential integers, so an id does not
tell you how many records exist or let you walk them. A 404 for a record that
exists but is out of scope and one that does not exist are the same response.

### Narrative exfiltration

The most valuable data and the most restricted path. Narratives appear on the
complaint detail view only, to senior roles and above
(`COMPLAINT_NARRATIVE_ACCESS_ROLES`), never in a list view, an error, an
export or a log line.

What is missing: field-level access logging. A senior reading two hundred
narratives in an afternoon looks exactly like one reading two.

### Log injection

Request ids are validated, not reflected. Log output is structured. Narratives
are truncated if one reaches a line.

### Timing attacks on login

Password comparison is constant-time via the hashing library. The user lookup
is not, so a username that exists may be distinguishable from one that does
not by timing. Unmitigated, and the exposure is which usernames exist.

### Denial of service

Everything expensive is bounded: traversal by hops, nodes and time; analysis
by account count; exports and reports by item and page counts; request bodies
by size. Each bound has a hard cap above it, so raising a limit past the cap
has no effect rather than an unbounded one.

The remaining exposure is the synchronous analysis run holding a worker. A
determined caller with analyst credentials could occupy all of them.

## What this system does not do, which removes whole categories

Worth listing, because the absence of a feature is the strongest control
available.

- **No adverse action.** Nothing freezes, blocks or restricts an account.
  There is no code path and no `AccountStatus` value to write, so there is no
  "trick the system into freezing an account" attack.
- **No outbound network calls.** `OUTBOUND_NETWORK_ENABLED=false`. No
  webhooks, no third-party enrichment, no SSRF surface.
- **No file uploads.** `FILE_UPLOAD_ENABLED=false`.
- **No deanonymisation.** `DEANONYMISATION_ENABLED=false`. There is no path
  from a hash back to an identifier.
- **No real data.** `INGESTION_REQUIRE_SYNTHETIC=true`. The most effective
  control in the system is that there is nothing valuable in it.

## Residual risk, ranked

1. **Audit trail integrity against database access.** No enforcement, no
   tamper evidence.
2. **No need-to-know.** Any authenticated reader sees every account.
3. **Tokens cannot be revoked.** Thirty minutes of exposure after a theft.
4. **Rate limiting is in-process.** Per worker, nothing shared.
5. **No field-level access logging on narratives.** Bulk reading is
   indistinguishable from normal use.
6. **No ingestion drift detection.** A feed that changes shape goes unnoticed.
7. **Timing on user lookup.** Username existence may be observable.

## What would change this document

A penetration test, and a review by somebody who did not write the system.
Both would likely find things this document does not mention, and the value of
a threat model written in-house is mostly in the questions it makes askable.
