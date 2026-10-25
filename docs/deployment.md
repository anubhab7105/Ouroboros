# Deployment

Three ways to run this, in increasing order of commitment. None of them is a
deployment for real data — `docs/compliance-note.md` is blunt about that.

## Docker Compose

The fastest path to something working.

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'   # BACKEND_SECRET_KEY
docker compose up --build
```

- backend: http://localhost:8000 (docs at `/docs`)
- frontend: http://localhost:5173
- PostgreSQL 16 on 5432

`docker-compose.override.yml` adds reload and bind mounts for development, and
is picked up automatically. Leave it out for anything else:

```bash
docker compose -f docker-compose.yml up -d
```

Migrations run in the backend container's entrypoint, so the first start takes
longer than the rest.

### Seeding

```bash
export MULEGUARD_DEV_PASSWORD=choose-something
export MULEGUARD_ADMIN_PASSWORD=$MULEGUARD_DEV_PASSWORD

docker compose exec backend python scripts/create_dev_users.py
scripts/seed_demo.sh
```

## Without Docker

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
cp backend/.env.example backend/.env           # set BACKEND_SECRET_KEY
scripts/run_backend_dev.sh                     # migrates, then serves

cd frontend && npm ci && cp .env.example .env
cd .. && scripts/run_frontend_dev.sh
```

SQLite works for development: `DATABASE_URL=sqlite:///./muleguard.db`. It is
refused in production (`DB_ALLOW_SQLITE_IN_PRODUCTION=false`), because
concurrent writes and this workload do not mix.

## A real deployment

Work `docs/runbooks/pre-deployment-security-checklist.md` first. What follows
assumes you have.

### Set `BACKEND_ENV`

Setting it to `production` or `staging` changes what is **allowed**, not just
what is logged. Startup refuses `BACKEND_DEBUG=true`, `SEED_DEV_USERS=true`,
`SEED_DEMO_DATA=true`, `AUTH_DEMO_MODE=true`, remote debugging, and a
`BACKEND_SECRET_KEY` still at its placeholder.

That refusal is the point: the configuration mistakes most likely to matter
are caught loudly at startup rather than quietly at first use.

### Build

```bash
docker build -t muleguard-backend:$(git rev-parse --short HEAD) backend/
docker build -t muleguard-frontend:$(git rev-parse --short HEAD) frontend/ \
  --build-arg VITE_API_BASE_URL=https://api.muleguard.example
```

`VITE_API_BASE_URL` is a **build argument**, not a runtime variable. The
frontend is static files and the URL is compiled in. Changing it means
rebuilding, and the symptom of forgetting is a frontend that loads with every
panel in its error state while the backend is healthy.

Tag with a commit, not `latest`. `latest` is how you end up unable to say what
is running.

### Database

PostgreSQL 14 or newer. Managed is fine and preferable.

```bash
DATABASE_URL=postgresql+psycopg2://... alembic -c backend/alembic.ini upgrade head
```

Run migrations as a separate step from starting the application, not from
every replica's entrypoint — concurrent migrations on one database is a race
nobody enjoys debugging.

The application user does not need `CREATE`; the migration user does. Two
roles is worth the small inconvenience.

### Serving

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Behind something that terminates TLS. The application does not.

Rate limiting is **in-process**, so limits are per worker: four workers means
roughly four times the configured limit, and nothing is shared across
instances. Size the limits accordingly, or put a shared limiter in front.

### Reverse proxy

```nginx
location / {
    proxy_pass http://backend:8000;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Request-ID      $request_id;
}
```

Two things to get right, both of which produce confusing failures:

- `BACKEND_ALLOWED_HOSTS` must include the host the proxy forwards, or every
  request is a 400 with an unhelpful body.
- `BACKEND_TRUST_PROXY_HEADERS=true` and `BACKEND_FORWARDED_ALLOW_IPS` set to
  the proxy, or client addresses are the proxy's. Do not trust the headers
  without restricting who may set them.

Forwarding `X-Request-ID` ties the proxy's log line to the application's and
to the audit row. Worth doing.

### Verifying

```bash
scripts/smoke_test.sh --base-url https://api.muleguard.example
```

Eleven checks. **A skipped check is not a passed one** — set
`MULEGUARD_ADMIN_PASSWORD` so the authenticated half runs.

It checks, among other things, that the deployment still declares itself
synthetic and not production-ready. If that check fails, something has been
configured to look like a production system, which is the one claim this
prototype must never make.

## Operational notes

### Health

| Endpoint | Use it for |
|---|---|
| `/health` | Liveness. Process is up |
| `/api/v1/health/ready` | Readiness. **Includes the database check** |
| `/api/v1/health` | Per-subsystem detail |

Use `ready` as the readiness probe, and read the body rather than the status:
it answers 200 with `ready: false` while a dependency is failing. A process
that is listening is not a backend that can serve a request.

### Logging

`BACKEND_LOG_FORMAT=json` for anything that ships logs.

Leave `BACKEND_LOG_REQUEST_BODY` and `BACKEND_LOG_RESPONSE_BODY` false. A
request body here can contain a complaint narrative and a response body can
contain a page of them.

Logs carry request ids, usernames and action names. Not narratives, not
secrets, not raw identifiers, and client addresses are hashed. Worth verifying
once rather than assuming.

### Metrics

`PROMETHEUS_ENABLED=true` exposes `/metrics`. Do not expose it publicly.

### Backups

`docs/runbooks/backup-restore.md`. The part people skip: record the Alembic
revision with the dump. A dump without its revision is a dump somebody will
have to bisect migrations against.

### Scaling

Stateless apart from the in-process rate limiter, so horizontal scaling works
with the caveat above.

The thing that will hurt first is a large analysis run: it is synchronous, and
a run over thousands of accounts holds a worker for its duration.
`ANALYSIS_MAX_ACCOUNTS` (default 1000) is the bound; the next move would be a
background worker sharing this codebase, not a service (ADR 0001).

## What is not provided

- **No Kubernetes manifests or Helm chart.** The container is ordinary; write
  what your cluster expects.
- **No CI/CD pipeline.** `.github/workflows/` runs tests and linting, not
  deployment.
- **No infrastructure as code.**
- **No horizontal pod autoscaling guidance**, because nothing here has been
  load-tested and a number would be invented.
- **No multi-tenancy.** One deployment is one organisation's data.
- **No blue/green or canary.** Migrations are forward-compatible within a
  release but no compatibility window is guaranteed across them, so the safe
  pattern is: migrate, then deploy, with a short overlap.
