# Troubleshooting

Symptoms in the order they are likely to be hit, each with the cause that
actually produces it rather than the cause that sounds plausible.

## The backend will not start

### `BACKEND_SECRET_KEY` errors, or a startup validation failure

There is no default. The application refuses to start rather than falling back
to a development value, because a development signing key that reaches a
deployment is a forgeable token.

```bash
cp backend/.env.example backend/.env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'   # paste into .env
```

### `ModuleNotFoundError: No module named 'fastapi'`

The requirements are not installed, or you are in the wrong virtualenv.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
```

### `could not connect to server` on startup

`DATABASE_URL` points somewhere that is not listening. With Docker, the
hostname is the service name (`db`), not `localhost` — a container reaching
`localhost` reaches itself.

```bash
docker compose ps
docker compose logs db | tail -40
```

## It starts, but `/health/ready` says `ready: false`

The process is up and a dependency check is failing. `/api/v1/health` lists
the individual checks and which one failed; read that before guessing.

Almost always one of two things:

**Migrations have not run.** `alembic upgrade head` from `backend/`.
`scripts/run_backend_dev.sh` does this for you; a container started by hand
does not.

**The database is reachable but the schema is older than the code.** Same
fix. The symptom is distinctive: liveness passes, readiness fails, and a query
against a changed table errors with a missing column.

## Every request returns 400 with no obvious reason

`TrustedHostMiddleware` is rejecting the `Host` header. `BACKEND_ALLOWED_HOSTS`
has to include the hostname you are using, and `localhost` and `127.0.0.1` are
different entries.

This one is worth knowing because the response says nothing useful. It happens
most often behind a reverse proxy that forwards the original host.

## Every request returns 401

Three distinct causes, and the error code distinguishes them:

- No `Authorization` header. Log in and send `Bearer <token>`.
- Expired token. They are short-lived by design; log in again.
- A signing key that changed since the token was issued — restarting with a
  new `BACKEND_SECRET_KEY` invalidates every live token.

## A request returns 403 and the user looks right

Read the permission, not the role. Endpoints gate on a named permission
(`case_close`, `alert_assign`), and the role-to-permission mapping is in
`app/core/permissions.py`.

The two that catch people out, because both are deliberate:

- An **analyst cannot assign or close** a case. That is the separation of
  duties, not a bug. Use the senior investigator.
- An **auditor cannot change anything at all**. It is the only role with no
  mutation permission, which is what makes it useful for review.

## Ingestion rejects everything with foreign-key errors

Load order. The endpoints check foreign keys instead of creating records
implicitly:

```
accounts → entities → transactions → entity-links → complaints
```

`scripts/import_json.py` does this. Loading transfers first produces a wall of
rejections that reads exactly like bad data.

## Ingestion rejects a record and the value looks fine

Check it against the vocabulary rather than against intuition:

```bash
python scripts/check_schemas.py --data your-file.json \
                               --schema data/schemas/account.schema.json
```

The commonest surprises:

- `account_type` classifies the **holder** — `INDIVIDUAL`, `BUSINESS`,
  `MERCHANT`, `OTHER`. `SAVINGS` is a product and is refused rather than
  mapped, because there is no honest mapping from one to the other.
- `confidence` is a fraction. `0.88`, not `88`. A value above 1 is refused
  rather than divided by a hundred.
- An enforcement state such as `FROZEN` is not a status. MULEGUARD does not
  freeze accounts, so there is no value to store.

Informal wording **is** accepted where the meaning is unambiguous:
`HEURISTIC` becomes `NORMALIZED`, `WIRE` becomes `NEFT`, `SUCCESS` becomes
`COMPLETED`. The alias table is in `app/ingestion/normalizers.py`.

## An analysis run completes but nothing is scored

Check the run's response rather than the database. It reports
`account_count` and `assessment_count`, and a run over zero accounts is a
filter problem, not a scoring problem.

If accounts were scored but no alerts were raised, that may well be correct: an
alert needs a score at or above the threshold (65 by default, the HIGH band) or
a rule effect that always escalates. Ordinary accounts not alerting is the
system working.

## The dashboard is empty after seeding

Seeding loads records; it does not score them. `scripts/seed_demo.sh` runs an
analysis pass afterwards — unless you passed `--no-analyse`, in which case
nothing is scored and the empty dashboard is correct.

## A money trail or subgraph looks suspiciously short

Check `truncated` in the response. Every traversal is bounded by hops, nodes
and time, and a truncated traversal **establishes nothing**: "no path found"
means "no path found within the budget".

Raise the limits deliberately if you need to look further. Do not read an
exhausted search as an exhaustive one.

## A score is null, or a metric says unavailable

That is the design, and it is not the same as zero. An unavailable signal is
reported as unavailable because substituting zero would assert that the
account scored well on something nothing looked at.

Common reasons: no trained model (the heuristic fallback is used, and the
scoring mode says so); no feature snapshot for that `as_of`; a rule pack that
failed to register, which reports `no_rules_available` rather than scoring
every account zero.

## The frontend loads but every panel shows an error

The API base URL. `frontend/.env` sets `VITE_API_BASE_URL`, and it is baked in
at build time — changing it needs a rebuild, not a page refresh.

Check the browser console for CORS errors, which mean `BACKEND_CORS_ORIGINS`
does not include the frontend's origin.

## Tests fail with `No module named 'pytest'`

Install the dev requirements. If a test fails with a `Host` 400, the test
client's `testserver` host is missing from `BACKEND_ALLOWED_HOSTS` — the
conftest sets it, so this only happens in a hand-rolled fixture.

## Nothing above matches

```bash
scripts/smoke_test.sh                 # eleven checks, in order of likelihood
docker compose logs -f backend        # or the process output
curl -s localhost:8000/api/v1/health | jq   # per-subsystem detail
```

Include the `X-Request-ID` from the failing response when reporting it. Every
response carries one and it is the thread between a screenshot, a log line and
an audit row.
