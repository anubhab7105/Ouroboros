# Pre-deployment security checklist

For putting this somewhere other than a laptop. It is not a sign-off for
handling real data — see `docs/compliance-note.md`, which is blunt about what
would have to be true first.

Work through it in order. The first section is the one that has actually gone
wrong.

## Secrets

- [ ] `BACKEND_SECRET_KEY` is set, and is not the value from `.env.example`.
      There is no default and the application refuses to start without one,
      which is the control working.
- [ ] It came from a generator, not a keyboard:
      `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`
- [ ] It is not in the repository, in a Dockerfile, in a compose file, in CI
      logs or in a shell history. `git log -p -- '*.env'` is worth one minute.
- [ ] `DATABASE_URL`'s password is not in anything that gets logged. The
      scripts here print host and database name only, for this reason.
- [ ] Database credentials are not the Docker Compose defaults.
- [ ] Rotating `BACKEND_SECRET_KEY` invalidates every issued token. Know that
      before you rotate it at a busy moment.

## Accounts

- [ ] `scripts/create_dev_users.py` has **not** been run. It creates accounts
      named `admin`, `senior`, `analyst` and `auditor` sharing one password
      from an environment variable. It refuses when `BACKEND_ENV` looks
      deployed; confirm that refusal rather than trusting it.
- [ ] Real accounts were created through `POST /api/v1/users`.
- [ ] No account has a password anybody typed twice.
- [ ] At least one `AUDITOR` exists and is held by somebody who is not an
      administrator. An auditor who can also alter the record is not a
      reviewer, which is the entire reason the role has no mutation
      permission.
- [ ] Analysts are analysts. Giving everyone `SENIOR_INVESTIGATOR` because
      assignment is inconvenient removes the separation of duties.

## Transport and headers

- [ ] TLS terminates in front of this. The application does not terminate TLS.
- [ ] `HSTS_ENABLED=true`, and `HSTS_MAX_AGE` is set deliberately. Both are
      settings; both are read.
- [ ] `BACKEND_ALLOWED_HOSTS` lists exactly the hostnames in use. Behind a
      proxy, include the host the proxy forwards, or every request is a 400
      with an unhelpful body.
- [ ] `BACKEND_CORS_ORIGINS` lists the frontend's origin and nothing else. Not
      `*`, and `null` is not an origin.
- [ ] `SECURE_HEADERS_NO_STORE_FOR_API=true` if responses may pass through a
      shared cache. Successful API responses carry no `Cache-Control` by
      default, which is a deliberate choice rather than an omission — these
      responses describe one analyst's view of an investigation.

## Data

- [ ] `INGESTION_REQUIRE_SYNTHETIC=true`. If it is false, stop and read
      `docs/compliance-note.md`.
- [ ] No real data has been loaded. Check rather than assume: a demonstration
      database that somebody tried a real export against is the likeliest way
      this goes wrong.
- [ ] `data/generated/` and `data/imports/` are empty or hold only synthetic
      files. Both are gitignored; gitignored is not the same as absent.
- [ ] The field blocklist is intact. `tests/test_ingestion_validation.py`
      covers it.

## Exposure

- [ ] `BACKEND_DOCS_ENABLED=false` unless the interactive docs are wanted. The
      schema is a complete map of the API, which is fine internally and is
      information you may not want to publish.
- [ ] `/metrics` is not publicly reachable.
- [ ] The database is not reachable from outside the deployment network.
- [ ] Debug is off. `BACKEND_DEBUG=false`, and confirm an error response
      carries no traceback: the envelope is designed to carry none.

## Operational

- [ ] Migrations have run: `alembic current` equals head.
- [ ] A backup exists, and the Alembic revision is recorded with it. See
      `backup-restore.md`.
- [ ] `scripts/smoke_test.sh` passes with **no skips**. A skipped
      authenticated check is not a passed one.
- [ ] The rate limiter is on. `AUTH_RATE_LIMIT_ENABLED=true` in particular:
      the login endpoint is the one worth protecting.
- [ ] Logs go somewhere that is read, and are not world-readable. They contain
      request ids, usernames and action names — not narratives, not secrets,
      not raw identifiers, which is by design and worth verifying once.
- [ ] Somebody owns this. An investigation platform with no owner accumulates
      cases nobody closes.

## What this checklist does not cover

- **A penetration test.** Nothing here has had one.
- **Threat modelling.** `docs/threat-model.md` is a starting point, not a
  conclusion.
- **Dependency vulnerabilities.** Run `pip-audit` and `npm audit`, and know
  that a clean result is a statement about known issues on one day.
- **The claim that this is fit for handling real financial crime data.** It is
  not, and no configuration makes it so. The model card and the compliance
  note say what would have to change, and most of it is not code.
