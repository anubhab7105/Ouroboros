# Deploy MULEGUARD with Vercel, Render, and Supabase

This guide deploys the existing Vite/React frontend to Vercel, the FastAPI API to Render, and PostgreSQL to Supabase. It does not deploy every script separately: only the frontend and backend are long-running services. Alembic migrations and any optional data-generation/seed scripts are one-off operations.

> **Scope and safety:** MULEGUARD is a synthetic-first academic/hackathon prototype, not production-ready software. Do not connect real banking systems or load real customer data. This guide is for a controlled synthetic-data demo.

## Deployment order

1. Create the Supabase Postgres database.
2. Deploy the FastAPI backend to Render and connect it to Supabase.
3. Configure and deploy the Vite frontend to Vercel using the Render API URL.
4. Check health, CORS, authentication/bootstrap, and application routes.

Deploy the database first so the backend can run migrations against it.

## 1. Create the Supabase database

1. Create a Supabase project and choose a region close to your Render service.
2. Open **Connect** in the Supabase dashboard.
3. Choose **Session pooler** and copy its connection string. Render's network is IPv4-only and Supabase's direct database endpoint is IPv6 by default; the Supabase session pooler is available over IPv4. Use the session pooler on port `5432`, not the transaction pooler on port `6543`, for this long-running SQLAlchemy/FastAPI service.
4. Keep the database password private. If it contains URL-reserved characters, use the correctly URL-encoded password in the connection string.
5. Do not create the application tables manually. The backend uses Alembic migrations.

Official reference: [Supabase — Connect to Postgres](https://supabase.com/docs/guides/database/connecting-to-postgres).

## 2. Deploy the backend to Render

Create a **Web Service** in Render and connect `anubhab7105/Ouroboros`.

Use these settings:

| Render setting | Value |
|---|---|
| Branch | `main` after this guide/configuration PR is merged |
| Runtime | Python |
| Root Directory | `backend` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| Health Check Path | `/health` |

### Database migration command

If the selected Render service plan supports a **Pre-Deploy Command**, set it to:

```bash
alembic upgrade head
```

Keep the Start Command as the Uvicorn command above. This runs migrations before the new service version starts.

Render's Free web services do not support Pre-Deploy Commands. For a single-instance prototype/demo on Free, use this temporary Start Command instead:

```bash
alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

This runs an idempotent Alembic upgrade at each start. Keep the service to one instance with this setup; for a multi-instance or production-like deployment, move migrations to a separate pre-deploy step instead.

### Required Render environment variables

Add these under **Environment** in the Render service. Do not commit real values to Git.

| Variable | Value |
|---|---|
| `BACKEND_ENV` | `production` |
| `BACKEND_DEBUG` | `false` |
| `BACKEND_SECRET_KEY` | A newly generated, strong random secret; never a placeholder |
| `DATABASE_URL` | Supabase **Session pooler** connection string |
| `BACKEND_PUBLIC_URL` | `https://YOUR-RENDER-SERVICE.onrender.com` |
| `BACKEND_ALLOWED_HOSTS` | `YOUR-RENDER-SERVICE.onrender.com` |
| `BACKEND_CORS_ORIGINS` | `https://YOUR-VERCEL-PROJECT.vercel.app` |
| `BACKEND_OPENAPI_ENABLED` | `false` |
| `BACKEND_DOCS_ENABLED` | `false` |
| `AUTH_DEMO_MODE` | `false` |
| `SEED_DEV_USERS` | `false` |
| `SEED_DEMO_DATA` | `false` |
| `DB_ALLOW_SQLITE_IN_PRODUCTION` | `false` |
| `ML_REQUIRE_TRAINED_MODEL` | `false` |

Replace the example hosts with the real hostnames after you create each service. Add any custom frontend domain to `BACKEND_CORS_ORIGINS` as another comma-separated origin, without a trailing slash. Keep `BACKEND_ALLOWED_HOSTS` restricted to the backend hostname(s).

Generate a secret locally, for example:

```bash
python -c "import secrets; print(secrets.token_hex(64))"
```

Copy the result directly into Render's secret environment variable; do not commit it or send it in a chat. The backend checks that production-like environments do not use placeholder secrets and refuses demo seeding / public OpenAPI settings unless explicitly configured otherwise.

### Render networking note

Use Supabase's session-pooler URI copied from **Connect**. Do not compose the pooler hostname or username by guessing them, because Supabase uses a project-specific pooler host and username.

## 3. Deploy the frontend to Vercel

Create a Vercel project and import the same GitHub repository.

Set the Vercel **Root Directory** to `frontend`. Once the PR containing `frontend/vercel.json` is merged, that file supplies the Vite SPA rewrite so direct navigation to routes such as `/alerts` or `/cases/123` serves the frontend app.

Use the following build settings:

| Vercel setting | Value |
|---|---|
| Framework Preset | Vite |
| Root Directory | `frontend` |
| Install Command | `npm ci` |
| Build Command | `npm run build` |
| Output Directory | `dist` |

Add these environment variables for **Production** (and for Preview only if you have a separate preview API/database):

| Variable | Value |
|---|---|
| `VITE_API_BASE_URL` | `https://YOUR-RENDER-SERVICE.onrender.com/api/v1` |
| `VITE_ENVIRONMENT` | `production` |
| `VITE_ENVIRONMENT_LABEL` | `HOSTED SYNTHETIC DEMO` |
| `VITE_SHOW_SYNTHETIC_BANNER` | `true` |
| `VITE_SHOW_SCORE_DISCLAIMER` | `true` |
| `VITE_SHOW_LIMITATIONS` | `true` |

The API base URL is compiled into the static bundle at build time. After changing it, trigger a new Vercel deployment. Include `/api/v1` and do not add a trailing slash. Never put `DATABASE_URL`, a database password, or any backend secret in Vercel variables: all `VITE_*` values are visible to browser users.

Official reference: [Vercel — Vite](https://vercel.com/docs/frameworks/frontend/vite).

## 4. Verify the deployment

After both services are deployed:

1. Open `https://YOUR-RENDER-SERVICE.onrender.com/health`. It should return JSON with `status: "ok"`.
2. Check Render logs for a successful database connectivity check and confirm that the Alembic migration command completed.
3. Open the Vercel URL. In browser developer tools, check Network for requests going to `https://YOUR-RENDER-SERVICE.onrender.com/api/v1/...` and verify there are no CORS or mixed-content errors.
4. Directly open a nested frontend route (for example `/alerts`) and refresh it. It should load the SPA rather than return a Vercel 404.
5. Test login and one read-only API flow, then exercise write operations only with synthetic test data.

If the frontend renders but API panels fail, check `VITE_API_BASE_URL` first, then `BACKEND_CORS_ORIGINS`, `BACKEND_ALLOWED_HOSTS`, `DATABASE_URL`, and Render logs.

## 5. Important first-admin blocker

**Infrastructure deployment is not the same as a usable sign-in.** Users are not created automatically. The existing `scripts/create_dev_users.py` intentionally refuses production-like environments, and `POST /api/v1/users` requires an administrator. The repository does not currently provide a documented production-safe first-admin bootstrap flow.

Do not work around this by changing `BACKEND_ENV` to `local`, enabling demo authentication, or seeding the known development users on a public deployment. Before expecting sign-in to work, add and review a controlled one-time administrator bootstrap process (or another approved initial account-provisioning path). Until then, the health/API connectivity can be tested, but the hosted app should not be considered a complete usable deployment.

## Free-tier limitations

- Render Free web services spin down after 15 minutes without inbound traffic, so the first request after idle can take about a minute.
- Supabase Free projects may be paused after seven days with low activity; restore them in the Supabase dashboard if that happens.
- Supabase Free does not provide downloadable database backups. Treat this setup as a disposable synthetic demo, not as durable storage for important data.

References: [Render Free](https://render.com/docs/free) and [Supabase project pausing](https://supabase.com/docs/guides/platform/free-project-pausing).

## Official platform references

- [Vercel Vite deployment](https://vercel.com/docs/frameworks/frontend/vite)
- [Render FastAPI deployment](https://render.com/docs/deploy-fastapi)
- [Supabase Postgres connection methods](https://supabase.com/docs/guides/database/connecting-to-postgres)
