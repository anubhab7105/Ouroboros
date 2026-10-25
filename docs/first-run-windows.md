# First run on Windows

A manual for getting MuleGuard running on a laptop for the first time, from a
fresh clone or a fresh copy of the folder, with nothing installed but Python
and Node.

It is written for Windows PowerShell, because that is what the project ships
helper scripts for. Every step also gives the raw command underneath, so the
same sequence works in `cmd`, in Git Bash, or on Linux with `scripts/*.sh`
instead of `scripts/*.ps1`.

Read the two boxes in [Before you start](#before-you-start) first. They are the
two things that will otherwise waste your evening.

---

## Contents

1. [What you are about to run](#1-what-you-are-about-to-run)
2. [Before you start](#before-you-start)
3. [Prerequisites](#2-prerequisites)
4. [Install the backend](#3-install-the-backend)
5. [Configure the backend](#4-configure-the-backend)
6. [Create the database](#5-create-the-database)
7. [Create the login accounts](#6-create-the-login-accounts)
8. [Start the backend](#7-start-the-backend)
9. [Load data](#8-load-data)
10. [Score the data](#9-score-the-data)
11. [Install and start the frontend](#10-install-and-start-the-frontend)
12. [Log in and look around](#11-log-in-and-look-around)
13. [Verify the install](#12-verify-the-install)
14. [Run the tests](#13-run-the-tests)
15. [Resetting](#14-resetting)
16. [Troubleshooting](#15-troubleshooting)
17. [What is switched off by default](#16-what-is-switched-off-by-default)

---

## 1. What you are about to run

Three processes, two of which you start:

| Part | What it is | Where it listens |
|---|---|---|
| Backend | FastAPI app, 15 endpoint modules, 23 tables | `http://localhost:8000` |
| Frontend | Vite dev server, React 18 + TypeScript | `http://localhost:5173` |
| Database | SQLite file on disk for local dev; PostgreSQL in deployment | `backend/var/muleguard.db` |

The frontend's dev server proxies `/api` through to the backend, so the browser
only ever talks to port 5173. You do not need to configure CORS for local work.

You do **not** need Docker or PostgreSQL for a first run. Both are supported —
see `docs/deployment.md` — but SQLite is the shortest path to a working screen,
and every migration in this project runs on both.

---

## Before you start

> **The login accounts are not created automatically.**
> Running the backend gives you an API with no users in it, and every
> authenticated endpoint will return 401. [Step 6](#6-create-the-login-accounts)
> creates them. It is one command and it is easy to skip past.

> **Use `npm install`, not `npm ci`, the first time.**
> `frontend/package-lock.json` is not in the repository yet, and `npm ci`
> requires a lockfile. `scripts/run_frontend_dev.ps1` tells you to use `npm ci`;
> that advice is correct from the second run onward. See
> [step 10](#10-install-and-start-the-frontend).

---

## 2. Prerequisites

| Tool | Version | Check | Where |
|---|---|---|---|
| Python | 3.11 or 3.12 | `python --version` | python.org |
| Node.js | 20.11.0 or later (pinned in `frontend/.nvmrc`) | `node --version` | nodejs.org |
| npm | ships with Node | `npm --version` | — |

`.python-version` pins 3.11.9 for CI reproducibility, but 3.12 works and is
fine to use. The backend imports the standard library plus FastAPI, SQLAlchemy
and three small libraries — there is no numpy/scipy/scikit-learn stack to
match an interpreter version against, so the usual reason to care about the
exact minor version does not apply here.

If you have several Pythons installed, confirm which one PowerShell resolves:

```powershell
(Get-Command python).Source
```

Nothing else is required. In particular:

- **No PostgreSQL.** `psycopg2-binary` is in `requirements.txt` and installs
  from a wheel on Windows without needing a Postgres install or build tools. It
  just sits unused while you are on SQLite.
- **No C compiler.** The only binary dependencies are `argon2-cffi`, `bcrypt`
  and `psycopg2-binary`, all of which ship Windows wheels.
- **No OpenSSL.** Where the docs say `openssl rand -hex 64`, there is a Python
  equivalent below.
- **No numpy, pandas, scipy, scikit-learn or networkx.** They used to be listed
  in `requirements.txt` and nothing imports any of them — `app/ml/` is
  pure-Python by design and `app/graph/` implements its own bounded traversal.
  They are commented out, with the reasoning, in `backend/requirements.txt`.
  This takes roughly 400 MB and several minutes off the install, and removes the
  most fragile corner of the Python packaging ecosystem from your first run.

---

## 3. Install the backend

Open PowerShell at the project root.

```powershell
cd $HOME\Desktop\MuleGuard

python -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r backend\requirements.txt -r backend\requirements-dev.txt
```

If `Activate.ps1` is blocked by execution policy:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

That lasts for the current window only and does not change a machine-wide
setting.

Install the dev requirements too, even though you are not developing: `pytest`
and `httpx` live there, and the dev file starts with `-r requirements.txt`, so
a single command covers both.

Confirm it took:

```powershell
python -c "import fastapi, sqlalchemy, alembic, reportlab, jsonschema, jwt, argon2; print('ok')"
python -m pip --version
```

The second line matters more than it looks. **If `pip install` fails for any
reason, pip installs nothing at all** — it resolves the entire requirement set
before writing a single file. A venv that looks active can therefore be
completely empty, and the next command you run will silently fall through to
some other Python on your PATH, typically a per-user install under
`%APPDATA%\Roaming\Python\`. The traceback then points at files in a directory
you did not expect, which is confusing in a way that costs an hour.

Two habits avoid it entirely:

- Check that the install actually succeeded before moving on.
- Invoke tools as `python -m <tool>` rather than by bare name. `python -m
  alembic`, `python -m uvicorn`, `python -m pytest` and `python -m pip` all
  resolve through the active interpreter, so they cannot be satisfied by a
  stray `alembic.exe` earlier on PATH. The bare names work once the venv is
  correctly populated; `python -m` works or fails honestly.

---

## 4. Configure the backend

```powershell
Copy-Item backend\.env.example backend\.env
```

`backend/.env.example` is long — around 3,200 lines — because every setting the
backend reads is declared there with a comment explaining it. You do not need to
read it. Five values need changing for a first run, and **the backend will
refuse to create your login accounts until the password ones are set**, because
the password validator explicitly rejects placeholder strings.

Open `backend\.env` and set these:

### 4.1 Point the database at SQLite

Find `DATABASE_URL` (around line 412) and replace the PostgreSQL line with:

```ini
DATABASE_URL=sqlite+pysqlite:///./var/muleguard.db
```

The path is relative to `backend/`, which is where you will run `alembic` and
`uvicorn` from. SQLite is allowed because `BACKEND_ENV=local`;
`app/db.py` refuses SQLite outright in production-like environments, which is
deliberate.

### 4.2 Set a real secret key

Generate one:

```powershell
python -c "import secrets; print(secrets.token_hex(64))"
```

Paste the output:

```ini
BACKEND_SECRET_KEY=<the 128 hex characters you just generated>
```

With `BACKEND_ENV=local` a placeholder key only produces a startup warning
rather than a failure, but it is also the JWT signing key, so leaving it means
any token minted now stays valid against the default. Set it.

### 4.3 Set the four development passwords

```ini
DEV_ADMIN_PASSWORD=<your choice>
DEV_ANALYST_PASSWORD=<your choice>
DEV_SENIOR_INVESTIGATOR_PASSWORD=<your choice>
DEV_AUDITOR_PASSWORD=<your choice>
```

The policy in `app/auth/passwords.py` is enforced on these, so each one must
have **at least 12 characters, one uppercase, one lowercase, one digit, and one
non-alphanumeric character**, and must not contain any of `change_me`,
`changeme`, `placeholder`, `replace_me`, `replace-me`, `your_`, `example_`,
`todo`, or `fixme` in any casing. `MuleGuard!Dev2026` passes. `ChangeMe123!`
does not — the substring check catches it.

You can use the same password for all four. They are four accounts so you can
see the permission matrix behave differently, not because the passwords need to
differ.

### 4.4 Create the runtime directories

The backend writes the SQLite file, logs and generated PDF reports under
`backend/var/`, and does not create those directories itself:

```powershell
New-Item -ItemType Directory -Force backend\var, backend\var\logs, backend\var\reports | Out-Null
```

### 4.5 Leave everything else alone

The remaining `CHANGE_ME` values in `.env` are for features that are off by
default: `CRYPTO_MASTER_KEY` is read only when field encryption is enabled,
`POSTGRES_PASSWORD` only by `docker-compose`, and the various `*_HASH_SALT`
values fall back to safe derived defaults in local mode. You can set them later;
`docs/configuration.md` lists what each one does.

---

## 5. Create the database

```powershell
cd backend
python -m alembic upgrade head
```

You should see three revisions apply: `0001_initial_schema`,
`0002_seed_roles_and_reference_data`, `0003_add_investigation_indexes`. That
creates 23 tables and seeds the role rows and reference data.

Migrations take the database URL from `DATABASE_URL` in the environment first
and from application settings second, so `alembic.ini` does not need editing.
On SQLite, `migrations/env.py` turns on batch mode automatically, because SQLite
cannot `ALTER COLUMN`.

Confirm:

```powershell
python -c "import sqlite3; c=sqlite3.connect('var/muleguard.db'); print(len(c.execute(\"select name from sqlite_master where type='table'\").fetchall()), 'tables')"
```

---

## 6. Create the login accounts

This is the step that is easy to miss. Nothing in application startup creates
users — `app/bootstrap.py` can do it, but it is not wired into the lifecycle, by
design, so that starting the server never silently mints accounts with known
usernames.

Run the script, from the project root, with the venv active:

```powershell
cd ..
$env:MULEGUARD_DEV_PASSWORD = '<the ' + 'password you chose in 4.3>'
python scripts\create_dev_users.py
```

Four accounts are created:

| Username | Email | Role | What it can do |
|---|---|---|---|
| `admin` | admin@muleguard.local | ADMIN | User management, configuration, ingestion, audit export, model training |
| `senior` | senior@muleguard.local | SENIOR_INVESTIGATOR | Assignment, case closure, reopening, review of inferred correlations |
| `analyst` | analyst@muleguard.local | ANALYST | Triage and case work. **Cannot assign or close** — that is the control |
| `auditor` | auditor@muleguard.local | AUDITOR | Reads everything, changes nothing |

Notes on this script:

- It reads the password from the environment only. There is no default, and it
  never prints a password.
- `MULEGUARD_DEV_PASSWORD` sets all four. For different passwords per role, use
  `MULEGUARD_ADMIN_PASSWORD`, `MULEGUARD_SENIOR_PASSWORD`,
  `MULEGUARD_ANALYST_PASSWORD`, `MULEGUARD_AUDITOR_PASSWORD` instead.
- It refuses to run when `BACKEND_ENV` is any of `production`, `prod`,
  `staging`, `stage`, `uat`, `preprod`.
- `python scripts\create_dev_users.py --list` prints what it would create
  without touching the database.
- `--reset-passwords` also resets an account that already exists. Without it,
  existing accounts are left alone.

Keep `MULEGUARD_ADMIN_PASSWORD` set in this shell — the data-loading scripts in
step 8 need it, because ingestion is admin-only:

```powershell
$env:MULEGUARD_ADMIN_PASSWORD = '<the ' + 'admin password>'
```

---

## 7. Start the backend

The helper script runs migrations first, every time, then serves with reload:

```powershell
.\scripts\run_backend_dev.ps1
```

Equivalent raw command:

```powershell
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The script takes `-Port`, `-BindHost`, `-NoMigrate` and `-NoReload`. It warns if
you bind to `0.0.0.0`, which would expose a development server with known
usernames to your whole network.

Leave this window running. Open a second PowerShell window for everything that
follows, and activate the venv again in it:

```powershell
cd $HOME\Desktop\MuleGuard
.\.venv\Scripts\Activate.ps1
```

### Check it came up

```powershell
curl.exe http://localhost:8000/health
```

Four health endpoints exist, and they answer different questions:

| URL | Answers |
|---|---|
| `/health` | Is the process alive |
| `/api/v1/health/live` | Same, inside the versioned API |
| `/api/v1/health/ready` | Is the database reachable and are migrations current |
| `/api/v1/health/status` | Component-by-component detail, including ML scoring mode |

`/api/v1/health/ready` is the one that tells you whether step 5 worked.

### The interactive API docs

Open <http://localhost:8000/docs>. Swagger UI lists every endpoint with its
request and response models — the response models are declared inline in the
endpoint modules, so what you see there is the actual contract, not a
hand-maintained description. The OpenAPI document itself is at
`/api/v1/openapi.json`.

To call an authenticated endpoint from Swagger UI: `POST /api/v1/auth/login`
with

```json
{ "identifier": "admin", "password": "<your admin password>" }
```

then paste the returned `access_token` into **Authorize**. `identifier` accepts
either the username or the email address.

---

## 8. Load data

An empty install is a working install with nothing on any screen. There are two
ways to put data in, and they are genuinely different, not two spellings of the
same thing.

### Route A — seed straight into the database (fastest)

```powershell
cd backend
python -m app.ingestion.seed
cd ..
```

This generates a synthetic dataset and writes it directly to the database in
dependency-safe order. It is deterministic for a given seed and salt, and
idempotent — running it twice does not double the data.

Useful flags:

```powershell
python -m app.ingestion.seed --dry-run              # report the plan, write nothing
python -m app.ingestion.seed --accounts 500 --transactions 20000
python -m app.ingestion.seed --seed 42              # override the deterministic seed
python -m app.ingestion.seed --json                 # machine-readable summary
python -m app.ingestion.seed --force                # seed even if synthetic accounts exist
```

Ground-truth labels — which accounts are mules, which ring they belong to — are
deliberately **not** written to the database. They are returned on the
generator's `SyntheticDataset.labels` and excluded from its `to_dict()`, so that
a label can never reach a screen an investigator is reading. If you want them for
evaluating a model, use `scripts/generate_data.py`, which writes `labels.json`
alongside the data files.

### Route B — import through the API (exercises the real validation)

```powershell
.\scripts\seed_demo.ps1
```

This generates files, then loads them through `POST /api/v1/ingestion/*`, which
means every record goes through the same normalizers, validators and dedupe
logic a real import would. It needs the backend running and
`MULEGUARD_ADMIN_PASSWORD` set.

```powershell
.\scripts\seed_demo.ps1 -Generate 500          # generate 500 accounts first
.\scripts\seed_demo.ps1 -From data\samples     # load the committed sample files
.\scripts\seed_demo.ps1 -NoAnalyse             # skip the scoring pass
```

Underneath it is `scripts/import_json.py`, which you can also drive directly:

```powershell
python scripts\import_json.py --dir data\samples --dry-run
python scripts\import_json.py --dir data\samples --on-duplicate skip
python scripts\import_json.py --dir data\samples --stop-on-error
```

`--dry-run` is worth knowing about: the API does the validation, so it exercises
the real rules rather than a local approximation of them. `data/samples/` also
contains deliberately invalid files (`invalid-accounts.sample.json`,
`invalid-transactions.sample.json`) if you want to see rejection behaviour and
the error envelope.

### Generating a dataset without loading it

```powershell
python scripts\generate_data.py --accounts 250 --transactions 8000 --out data\generated\run-1
```

Defaults are 250 accounts, 8,000 transactions, 120 complaints, 400 entities and
600 entity links. Output goes to `data/generated/`, which is git-ignored — a
dataset is reproducible from its seed and generator version, so the two values
that produced it are worth more than the file.

---

## 9. Score the data

**Loading data does not score it.** Rules, risk scores, alerts and complaint
correlations are produced by an analysis run, and until one has happened the
dashboard, the alert queue and every risk badge are legitimately empty.

`scripts\seed_demo.ps1` triggers a run for you unless you pass `-NoAnalyse`. To
do it by hand:

```powershell
$body = @{ identifier = 'admin'; password = $env:MULEGUARD_ADMIN_PASSWORD } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/api/v1/auth/login' `
    -ContentType 'application/json' -Body $body

Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/api/v1/analysis/runs' `
    -Headers @{ Authorization = "Bearer $($login.access_token)" } `
    -ContentType 'application/json' -Body '{}'
```

Or from the UI, once you are logged in as admin: **Ingestion → run analysis**.

Analysis runs are idempotent per dataset version, so triggering one twice does
not double-count alerts.

---

## 10. Install and start the frontend

In the second PowerShell window:

```powershell
cd frontend
npm install
```

**`npm install`, not `npm ci`.** `package-lock.json` is not in the repository
yet, and `npm ci` fails without one. The install will create it — commit that
file, and from then on `npm ci` is the right command, because it installs
exactly the lockfile.

The dependency set is pinned to exact versions in `package.json`, so
`npm install` resolves to one tree: React 18.3.1, TanStack Query 5.51.1,
Cytoscape 3.30.1 for the graph canvas, Recharts 2.12.7 for the dashboard
charts, Tailwind 3.4.4, Vite 5.3.3, TypeScript 5.5.3.

Then:

```powershell
Copy-Item .env.example .env
cd ..
.\scripts\run_frontend_dev.ps1
```

Or raw:

```powershell
cd frontend
npm run dev
```

Open <http://localhost:5173>.

The default `frontend/.env` sets `VITE_API_BASE_URL=/api/v1` and relies on the
Vite dev proxy, which forwards `/api` to `VITE_DEV_API_TARGET`
(`http://localhost:8000`). That is why there is no CORS step. If you move the
backend to another port, change `VITE_DEV_API_TARGET`, not
`VITE_API_BASE_URL`.

`run_frontend_dev.ps1` checks the backend first and warns rather than refusing —
a frontend with no backend still renders, with every panel in its error state,
and that is occasionally the thing you want to look at.

Other scripts worth knowing:

```powershell
npm run typecheck    # tsc --noEmit
npm run lint         # eslint, zero warnings tolerated
npm test             # vitest, run once
npm run build        # typecheck then production build
```

---

## 11. Log in and look around

Log in as `analyst` first. The analyst view is the product's actual subject —
someone triaging leads — and the permission gaps are visible from it.

A path through the six capability areas, in the order they build on each other:

1. **Dashboard.** Risk band distribution, open cases by state, alert trend,
   complaint summary. If this is empty, you have not run step 9.
2. **Transactions.** Filter, sort, open one. The detail drawer shows the rule
   hits and the evidence behind them. Amounts are per-currency and never summed
   across currencies — that is deliberate, not an oversight.
3. **Accounts.** Open a high-risk one. The risk panel shows the score, its band,
   the contributing features and the limitations that apply to it. The score is
   an investigative priority, not a probability of guilt, and the panel says so.
4. **Alerts.** Triage queue. Open an alert, read its evidence, then
   **create a case from it**.
5. **Cases.** Your new case is in `NEW`. As `analyst`, try to assign it or close
   it — you will get a clear permission-denied state rather than a broken
   screen. Log in as `senior` to assign, start, escalate and close it. Closing
   requires a disposition; starting requires an assignee; escalating requires a
   reason. The state machine is in `app/services/case_state_machine.py` and the
   UI mirrors it rather than re-implementing it.
6. **Graph.** Pick a seed account and expand its neighbourhood. Run a money
   trail search. Note the traversal caveats: every bounded result says so, and a
   truncated traversal establishes nothing — it does not mean no path exists.
7. **Complaints.** Open one with correlations. Tiers 1 and 2 are deterministic
   matches and carry no confidence score, because a deterministic match is not
   an inference. Tiers 3 to 5 are inferred, carry a confidence score, and are
   flagged for review by a senior investigator.
8. **Reports.** Generate a case PDF. The filename and content digest are
   recorded in the audit trail.
9. **Model monitoring.** Metrics, feature schema, scoring mode, and an explicit
   limitations panel. These are synthetic-data evaluation metrics, not
   real-world fraud-detection claims.
10. **Audit.** Log in as `auditor`. Everything is readable; nothing is
    mutable. The auditor role holds no mutation permission at all, which is
    the point of having it.

`docs/demo-walkthrough.md` is a longer narrated version of this with specific
things to notice. `docs/user-guide.md` covers the screens one at a time.

---

## 12. Verify the install

```powershell
.\scripts\smoke_test.ps1
```

Eleven checks, ordered so the most likely problem is found first. It exits
non-zero if any fail, so it also works as a deployment gate. Authenticated
checks need `MULEGUARD_ADMIN_PASSWORD`; without it the public checks still run
and the rest report as **skipped** rather than passed, because a smoke test that
silently skips most of itself is worse than no smoke test.

Also worth running once:

```powershell
python scripts\check_schemas.py
```

That asserts the six JSON Schemas under `data/schemas/` still agree with
`backend/app/core/vocabularies.py`, which is the single definition of every
persisted vocabulary. If someone adds an account status in one place and not the
other, this is what catches it.

---

## 13. Run the tests

```powershell
cd backend
pytest
```

**Expect this to need some work.** Be aware of where the project actually
stands:

- Every test module is written and syntax-checked. Six modules that need no
  database and no fixtures have been executed and pass — 244 assertions, zero
  failures: `test_ml`, `test_case_transitions`, `test_ml_feature_schema`,
  `test_ml_fallback`, `test_graph_metrics`, `test_features`.
- The integration modules — anything using the `db`, `analyst_client` or `make`
  fixtures — have **never been executed**, because `pytest`, `fastapi` and
  `sqlalchemy` could not be installed in the environment they were written in.
  They are a specification of expected behaviour that has not yet been run
  against the implementation.

So the first `pytest` on your laptop is the first real signal on roughly
two-thirds of the suite. Some of it will fail on fixture details rather than on
product logic. `docs/testing.md` states this plainly and lists which modules are
in which category.

Useful subsets:

```powershell
pytest tests\test_ml.py -v                  # known-good, fast
pytest -k "case_transitions"                # the state machine
pytest --timeout 60                         # pytest-timeout is installed
pytest --cov=app --cov-report=term-missing  # coverage
```

Frontend:

```powershell
cd frontend
npm test
npm run typecheck
```

---

## 14. Resetting

Back to an empty but migrated database:

```powershell
.\scripts\reset_demo.ps1            # prompts before destroying anything
.\scripts\reset_demo.ps1 -Yes       # skip the prompt
.\scripts\reset_demo.ps1 -Yes -Reseed   # reset, then seed again
```

There is no selective reset, deliberately: a half-reset database is worse than
either state, because the accounts that survive are referenced by transactions
that did not. The script also refuses to run when `BACKEND_ENV` looks deployed,
and it checks the environment *name* rather than a flag, because a flag is the
thing somebody passes by accident.

The underlying module path, which requires an explicit confirmation phrase:

```powershell
cd backend
python -m app.ingestion.seed --reset --confirm "<phrase the command prints>"
```

The bluntest reset, which is fine on SQLite:

```powershell
cd backend
Remove-Item var\muleguard.db
python -m alembic upgrade head
cd ..
python scripts\create_dev_users.py      # users live in the database too
```

Remember the last line. Deleting the database deletes the accounts.

---

## 15. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No matching distribution found for types-PyJWT` | The stub package stops at 1.7.1; the pin asked for ≥2.8 | Fixed — the `types-*` block is commented out of `requirements-dev.txt`. Pull the current file |
| `pip install` failed, then every later command tracebacks through `%APPDATA%\Roaming\Python\` | pip installs nothing when resolution fails, so tools resolved to a per-user install outside the venv | Re-run the install, confirm it succeeded, and use `python -m <tool>` |
| `python-dotenv could not parse statement starting at line 769` | `CSV_QUOTECHAR="` and `CSV_ESCAPECHAR=\` were unquoted, so the parser gave up and dropped the rest of the file | Fixed in `.env.example`. Re-copy it over your `.env`, or quote those three values by hand |
| `SettingsError: error parsing value for field "BACKEND_ALLOWED_HOSTS"` | pydantic-settings tried `json.loads` on a comma-separated list before the CSV validator could run | Fixed — `enable_decoding=False` in `app/core/config.py`. It applies to all 48 list settings, not just the one named |
| `401` on every authenticated endpoint | No users exist | [Step 6](#6-create-the-login-accounts) |
| `create_dev_users.py` exits with a policy error | Password fails the policy, or contains a placeholder substring | ≥12 chars, upper + lower + digit + symbol, no `change_me` / `your_` / `todo` / `example_` |
| `npm ci` → "can only install with an existing package-lock.json" | No lockfile yet | `npm install` once, then commit the lockfile |
| `unable to open database file` | `backend/var/` does not exist | [Step 4.4](#44-create-the-runtime-directories) |
| `SQLite is not permitted in production-like environments` | `BACKEND_ENV` is set to production/staging | Set `BACKEND_ENV=local` |
| Dashboard renders but every panel is empty | Data loaded, never scored | [Step 9](#9-score-the-data) |
| Dashboard empty and so is every table | No data | [Step 8](#8-load-data) |
| `/api/v1/health/ready` fails, `/health` passes | Database unreachable or migrations behind | `cd backend; python -m alembic upgrade head` |
| `Activate.ps1 cannot be loaded` | Execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` |
| Frontend loads, every panel in its error state | Backend not running, or on a different port | Start it; or fix `VITE_DEV_API_TARGET` in `frontend/.env` |
| `ModuleNotFoundError: app` | Running from the wrong directory | `python -m alembic`, `python -m uvicorn` and `python -m app.*` all run from `backend/` |
| `alembic: command not found` | venv not active, or the install never completed | `.\.venv\Scripts\Activate.ps1`, then re-run the install and check it succeeded |
| Analyst cannot assign or close a case | Working as intended | That is the permission matrix. Use `senior` |
| A graph result looks incomplete | Traversal hit a bound | Read the caveat on the response. A truncated traversal establishes nothing |

For anything not here, `backend/var/logs/backend.log` has the detail once you
set `BACKEND_LOG_TO_FILE=true`. Logs mask PII by default
(`BACKEND_LOG_MASK_PII=true`) and never include complaint narratives in full.

---

## 16. What is switched off by default

Worth knowing so you do not go looking for a bug:

- **ML scoring falls back to rules** until a model artifact exists under
  `backend/app/ml/artifacts/`. Train one with `.\scripts\train_model.ps1`. The
  fallback is explicit, reported on `/api/v1/health/status` and shown in the
  model-monitoring screen — an unavailable model is never silently treated as a
  score of zero.
- **Field-level encryption** is off. `CRYPTO_MASTER_KEY` is only read when it is
  on.
- **Rate limiting** is on but generous in local mode. The auth endpoints are
  throttled separately.
- **The docs endpoints** (`/docs`, `/redoc`, `/api/v1/openapi.json`) are enabled
  in local mode and blocked in production-like environments by
  `BACKEND_BLOCK_OPENAPI_IN_PRODUCTION`.
- **No adverse action, anywhere.** There is no account freeze, no payment block,
  no blacklist. Scores, alerts, graph relationships and complaint correlations
  are investigative leads. This is a design invariant, not a missing feature —
  `docs/compliance-note.md` and `docs/adr/accepted/0004-risk-scores-investigative-leads.md`
  explain why.
- **All data is synthetic.** `BACKEND_DATASET_MODE=synthetic` and the UI carries
  a persistent banner saying so.

---

## Where to go next

| You want | Read |
|---|---|
| A narrated tour with things to notice | `docs/demo-walkthrough.md` |
| What each screen does | `docs/user-guide.md` |
| What every setting means | `docs/configuration.md` |
| What each table and column holds | `docs/data-dictionary.md` |
| The endpoint contract | `docs/api.md`, or `/docs` while running |
| How the pieces fit together | `docs/architecture.md` + `docs/diagrams/` |
| PostgreSQL, Docker, reverse proxy | `docs/deployment.md` |
| Why a decision was made that way | `docs/adr/accepted/` |
| What the model does and does not claim | `docs/model-card.md` |
| Which requirement is satisfied where | `docs/requirements-traceability.md` |
| What is tested and what is not | `docs/testing.md` |
