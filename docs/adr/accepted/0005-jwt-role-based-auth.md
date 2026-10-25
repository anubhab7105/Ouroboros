# ADR 0005: Bearer tokens and four roles, with the auditor as a read-only role

- **Status:** accepted
- **Date:** 2026-02-11
- **Deciders:** MULEGUARD contributors

## Context

The platform needs to know who is acting, because the audit trail is only
worth having if it names a person, and because the whole workflow is built on
the idea that a human decision is recorded.

It is deployed standalone. There is no corporate identity provider to defer
to, and requiring one would make the demonstration case impossible.

The role structure matters more than the token format. An investigation
platform where everyone can do everything has no separation of duties, and a
reviewer who can also alter what they review is not a reviewer.

## Decision

> We will issue short-lived signed bearer tokens from a local user table, and
> gate every endpoint on a named permission resolved through four roles.

The roles, and what each is for:

| Role | Can |
|---|---|
| `ANALYST` | Read everything; triage alerts; work cases; add notes and evidence |
| `SENIOR_INVESTIGATOR` | Everything an analyst can, plus assign, close, reopen, and review inferred correlations |
| `AUDITOR` | Read everything, including the audit log. Change nothing |
| `ADMIN` | Users, configuration, ingestion, audit export, model training |

Permissions are named (`case_close`, `alert_assign`, `audit_read`) and each
has a default role set. Endpoints declare a permission, never a role.

## Alternatives considered

### Sessions and cookies

Fine for a browser-only client, awkward for the scripted use this has plenty
of (`scripts/import_json.py`, `smoke_test.sh`, a CI job). A bearer token works
the same from a browser, a shell and a test.

### OAuth or OIDC against an external provider

The right answer for a deployment inside an organisation, and the wrong one
for a prototype somebody runs on a laptop. The user table is small and
replaceable; the permission matrix is the part worth getting right, and it
does not change if the tokens later come from elsewhere.

### Three roles, with the auditor folded into admin

Rejected, and this is the decision inside the decision. An auditor who is also
an administrator can alter the record they are reviewing, which removes the
reason to have the role. `AUDITOR` holds no mutation permission at all — it is
the only role of the four that cannot change anything, and that is what makes
it useful.

The admin *can* read the audit log, because somebody has to when there is no
auditor, and a log nobody can read during an incident is not a control either.

### Roles checked at the endpoint

Rejected in favour of named permissions. `require_permission(Permission.CASE_CLOSE)`
survives a change to which roles may close a case; `if role == "SENIOR"` does
not, and the change gets missed in one endpoint out of twelve.

## Consequences

### What this makes easy

- One mechanism for browser, script and test.
- A permission matrix that can be stated as a table and tested as one.
- Changing who may do what in a single registry.

### What this makes hard

- Revoking a token before it expires. Short lifetimes rather than a blocklist;
  a longer-lived deployment would need the blocklist.
- Rotating the signing key without invalidating every live token.
- No single sign-on.

### What would make us revisit this

Deployment inside an organisation with an identity provider. The permission
matrix stays; only the token issuance changes.

## Notes

The matrix lives in `app/core/permissions.py` and is tested in
`backend/tests/test_permissions.py` against a **hand-written** table rather
than one derived from the registry. That is the point of it: a table generated
from the registry agrees with the registry by construction and can never catch
a change to it.

`BACKEND_SECRET_KEY` has no default. The application refuses to start without
one rather than falling back to a development value, because a development
signing key that reaches a deployment is a forgeable token.
