# Configuration

Everything is environment variables, read into a Pydantic settings model at
`backend/app/core/config.py`. That model declares roughly 350 settings;
`backend/.env.example` is the annotated list. This document covers the ones
whose wrong value causes a confusing failure, the ones where the default is a
decision rather than a convenience, and the handful that cannot be turned on
at all.

```bash
cp backend/.env.example backend/.env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'   # BACKEND_SECRET_KEY
```

**The model ignores unknown variables.** A typo in a name is silently dropped
rather than reported, so a setting that appears to have no effect is most often
a setting the model does not declare. Check the name against
`app/core/config.py` before assuming the value is wrong.

## `BACKEND_ENV` changes what is allowed

Not just what is logged. When `BACKEND_ENV` is one of
`BACKEND_PRODUCTION_LIKE_ENVS` — `production`, `staging` and similar — startup
**refuses** rather than warns:

| Setting | Refused in a production-like environment |
|---|---|
| `BACKEND_DEBUG=true` | Tracebacks in responses |
| `SEED_DEV_USERS=true` | Accounts with known usernames |
| `SEED_DEMO_DATA=true` | Synthetic records |
| `AUTH_DEMO_MODE=true` | Relaxed authentication |
| `REMOTE_DEBUGGING_ENABLED=true` | A debugger port |
| `BACKEND_SECRET_KEY` left at its placeholder | Guarded by `BACKEND_REQUIRE_STRONG_SECRET_IN_NON_LOCAL` |

The refusal is loud and at startup rather than quiet and at first use. It is
also what `scripts/reset_demo.sh` and `scripts/create_dev_users.py` check
before doing anything destructive — an environment name is what a deployment
already knows about itself, whereas a flag is the thing somebody passes by
accident at the end of a long day.

## `BACKEND_SECRET_KEY`

The model's default is the placeholder string
`CHANGE_ME_GENERATE_WITH_openssl_rand_hex_64`, so a local checkout starts
without configuration. In any non-local environment,
`BACKEND_REQUIRE_STRONG_SECRET_IN_NON_LOCAL` (default true) makes startup
refuse while it is still the placeholder.

Rotating it invalidates every issued token:
`AUTH_TOKEN_REVOCATION_ENABLED` is false, so there is no blocklist and
rotation is the only way to invalidate a token early. Worth knowing before
rotating it at a busy moment.

## `DATABASE_URL`

```
postgresql+psycopg2://user:password@host:5432/muleguard    # deployment
sqlite:///./muleguard.db                                    # local
```

In Docker the host is the service name (`db`), not `localhost` — a container
reaching `localhost` reaches itself, and the error is a connection refusal
that looks like the database being down.

The engine is built at import time from a cached settings object, which is why
the test suite sets its environment before importing `app`. A late override
does not reach the engine.

SQLite is allowed locally (`BACKEND_ALLOW_SQLITE_FOR_LOCAL_DEV`) and refused
in production (`DB_ALLOW_SQLITE_IN_PRODUCTION=false`).

## `BACKEND_ALLOWED_HOSTS` — the unhelpful 400

`TrustedHostMiddleware` rejects a request whose `Host` header is not listed,
and the response body says nothing useful. `localhost` and `127.0.0.1` are
different entries, and behind a reverse proxy the forwarded host has to be
listed too (with `BACKEND_TRUST_PROXY_HEADERS=true`).

If every request is a 400 with an opaque body, check this first.

## Capabilities that cannot be turned on

These exist as settings, default to false, and are refused if set true. They
are declared rather than absent so that the refusal is explicit and testable:

```
AUTOMATIC_ENFORCEMENT_ENABLED=false
AUTO_FREEZE_ENABLED=false
AUTO_BLOCK_PAYMENT_ENABLED=false
AUTO_BLACKLIST_ENABLED=false
ADVERSE_ACTION_AUTOMATION_ENABLED=false
DEANONYMISATION_ENABLED=false
SURVEILLANCE_ENABLED=false
COVERT_MONITORING_ENABLED=false
USER_UPLOADED_MODEL_ENABLED=false
PICKLE_UNSAFE_LOAD_ENABLED=false
```

The first five are ADR 0004 expressed as configuration. There is also no code
path behind them and no `AccountStatus` value to write, so turning one on
would not make the platform freeze an account — it would make startup refuse.
The absence of the capability is the control; the setting is the statement.

`USER_UPLOADED_MODEL_ENABLED` and `PICKLE_UNSAFE_LOAD_ENABLED` are the ML
equivalent: deserialising a user-supplied model artefact is arbitrary code
execution, and `ML_ARTIFACT_TRUSTED_PATH_ONLY` restricts loading to a
configured directory.

## Where a default is a decision

### `INGESTION_REQUIRE_SYNTHETIC` — `true`

Ingestion refuses a batch that does not declare itself synthetic. The single
most consequential change available here; `docs/compliance-note.md` is blunt
about what would have to be true first. Related:
`ANALYSIS_REQUIRE_SYNTHETIC_DATA`, `BACKEND_BLOCK_REAL_DATA_IF_SYNTHETIC_ONLY`.

### `SECURE_HEADERS_NO_STORE_FOR_API` — `false`

Successful API responses carry no `Cache-Control`; error and authentication
responses always do (`..._FOR_ERRORS`, `..._FOR_AUTH`, both true).

A decision rather than an omission: these responses describe one analyst's
view of an investigation, so a deployment putting them behind a shared cache
should have had to choose that. Turn it on if anything caches.

### The CSP directive settings — `None`, not empty

`CSP_DEFAULT_SRC` and its sixteen siblings default to **unset**. Unset means
"keep the built-in directive"; an **empty string means remove that directive**.
Setting one to empty strips it from the policy, which is the opposite of what
somebody filling in a blank intends.

CSP is off by default (`CSP_ENABLED=false`), and docs paths are exempt when it
is on (`CSP_DOCS_EXEMPT=true`) so Swagger UI keeps working.

### `FEATURE_STRICT_POINT_IN_TIME` — `true`

A feature snapshot contains only data from strictly **before** its `as_of`
cutoff. The companion flags — `FEATURE_ALLOW_FUTURE_TRANSACTIONS`,
`FEATURE_ALLOW_FUTURE_COMPLAINTS`,
`FEATURE_ALLOW_FUTURE_INVESTIGATION_OUTCOMES` — are all false, and each one
names a specific way a model can be made to look good by seeing the future.

### `ML_REQUIRE_TRAINED_MODEL` — `false`

Without a trained model the platform scores with the heuristic fallback and
says so in every assessment (`scoring_mode: HEURISTIC_FALLBACK`). That is a
supported state, not a broken one. Set it true if you would rather fail than
fall back.

### `CASE_DISPOSITIONS`

Must be members of `Disposition` — `CONFIRMED_FRAUD`, `FALSE_POSITIVE`,
`INCONCLUSIVE`, `REFERRED`. The column is declared over that enum, so a label
outside it cannot be stored and configuring one only produces a failure at
closure time.

### `PRIVACY_IP_LOG_MODE` — `hashed`

Client addresses are hashed before they reach a log line or an audit row.
`PRIVACY_IP_HASH_SALT` should be set in any shared deployment; without it the
hash is still not the address, but it is the same hash everywhere.

## Reference, by area

Defaults are the model's. Hard caps exist alongside most limits: the
configured value is clamped to the hard cap, so raising a limit past it has no
effect rather than an unbounded one.

### Application

| Variable | Default |
|---|---|
| `BACKEND_ENV` | `local` |
| `BACKEND_DEBUG` | `false` |
| `BACKEND_SAFE_MODE` | `true` |
| `BACKEND_STRICT_CONFIG` | `true` |
| `BACKEND_SECRET_KEY` | placeholder; refused non-local |
| `BACKEND_API_PREFIX` | `/api/v1` |
| `BACKEND_ALLOWED_HOSTS` | `localhost,127.0.0.1` |
| `BACKEND_CORS_ORIGINS` | dev origins |
| `BACKEND_TRUST_PROXY_HEADERS` | `false` |
| `BACKEND_MAX_REQUEST_BODY_MB` | 10 |
| `BACKEND_REQUEST_TIMEOUT_SECONDS` | 60 |
| `BACKEND_DOCS_ENABLED` | `true` |
| `BACKEND_OPENAPI_ENABLED` | `true` |

### Database

| Variable | Default |
|---|---|
| `DATABASE_URL` | PostgreSQL placeholder |
| `DB_ECHO` | `false` |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | 10 / 20 |
| `DB_POOL_PRE_PING` | `true` |
| `DB_STATEMENT_TIMEOUT_MS` | 15000 |
| `DB_ALLOW_SQLITE_IN_PRODUCTION` | `false` |
| `SQLITE_JOURNAL_MODE` | `WAL` |
| `HEALTH_FAIL_ON_DB_UNAVAILABLE` | `true` |

### Authentication

| Variable | Default |
|---|---|
| `AUTH_ENABLED` | `true` |
| `AUTH_MODE` | `jwt_bearer` |
| `AUTH_ALGORITHM` | `HS256` |
| `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` | 30 |
| `AUTH_TOKEN_REVOCATION_ENABLED` | `false` |
| `AUTH_PASSWORD_HASH_SCHEME` | `argon2id` |
| `AUTH_PASSWORD_MIN_LENGTH` | 12 |
| `AUTH_LOGIN_MAX_ATTEMPTS` | 5 |
| `AUTH_LOGIN_LOCKOUT_MINUTES` | 15 |
| `AUTH_REVEAL_LOCKED_ACCOUNT` | `false` |
| `AUTH_RATE_LIMIT_ENABLED` | `true` |
| `AUTH_RATE_LIMIT_LOGIN` | `5/minute` |

`AUTH_REVEAL_LOCKED_ACCOUNT` and `AUTH_REVEAL_INACTIVE_ACCOUNT` are false so
that a failed login does not confirm which usernames exist.

### Authorization

`RBAC_DENY_BY_DEFAULT=true` and `RBAC_SUPERUSER_BYPASS=false`. Role
membership per permission is configurable through the `*_ROLES` settings —
`CASE_CLOSE_ROLES`, `AUDIT_READ_ROLES`, `COMPLAINT_NARRATIVE_ACCESS_ROLES` and
around thirty more. The defaults are the matrix in `docs/api.md`.

`COMPLAINT_NARRATIVE_ACCESS_ROLES` is senior-and-above: a complainant's own
words are the most sensitive field in the schema.

### Ingestion

| Variable | Default |
|---|---|
| `INGESTION_REQUIRE_SYNTHETIC` | `true` |
| `INGESTION_MAX_BATCH_SIZE` | 1000 (hard cap 10000) |
| `INGESTION_ALLOW_PARTIAL_BATCH` | `false` |
| `INGESTION_DUPLICATE_STRATEGY` | `reject` |
| `INGESTION_FUTURE_TOLERANCE_MINUTES` | 5 |
| `INGESTION_TRANSACTIONAL_BATCH` | `true` |
| `INGESTION_MAX_ERRORS_RETURNED` | 100 |

`/api/v1/ingestion/status` reports these, so a loader can discover the limit
rather than learn it by exceeding it.

### Detection

| Variable | Default |
|---|---|
| `RULES_CONFIG_PATH` | `config/rules.default.json` |
| `FEATURE_VERSION` | `v1` |
| `FEATURE_WINDOWS` | `1h, 24h, 7d, …` |
| `RISK_WEIGHT_SUPERVISED` | 0.35 |
| `RISK_WEIGHT_ANOMALY` | 0.25 |
| `RISK_WEIGHT_GRAPH` | 0.20 |
| `RISK_WEIGHT_RULES` | 0.20 |
| `ALERT_DEDUPLICATION_WINDOW_HOURS` | 24 |
| `ANALYSIS_MAX_ACCOUNTS` | 1000 (hard cap 50000) |
| `ANALYSIS_ALLOW_ALL_ACCOUNTS` | `false` |

Band cut points and the alert threshold live in the scoring configuration
rather than in environment variables: LOW 0–39.99, MEDIUM 40–64.99, HIGH
65–84.99, CRITICAL 85–100. `tests/factories.py` duplicates them deliberately,
so moving a cut point fails a test rather than silently reclassifying every
account.

The four risk weights sum to 1.0. A component that was unavailable is excluded
and the remainder renormalised — it does not contribute a zero, because a zero
would assert that the account scored well on something nothing looked at.

### Graph

| Variable | Default | Hard cap |
|---|---|---|
| `GRAPH_MAX_HOPS` / `GRAPH_MAX_DEPTH` | 3 | 5 |
| `GRAPH_MAX_NODES` | 500 | 1000 |
| `GRAPH_MAX_EDGES` | 1500 | 2000 |
| `GRAPH_MAX_PATHS` | 20 | 100 |
| `GRAPH_MAX_TRAILS` | 25 | 100 |
| `GRAPH_TIMEOUT_SECONDS` | 15 | — |
| `GRAPH_MAX_DATE_SPAN_DAYS` | 90 | 3650 |
| `GRAPH_REQUIRE_ROOT` | `true` | |
| `GRAPH_ALLOW_WHOLE_BANK_QUERY` | `false` | |

`GRAPH_REQUIRE_ROOT` and `GRAPH_ALLOW_WHOLE_BANK_QUERY` are ADR 0007 as
configuration: a traversal starts from an account, and there is no "show me
everything". A traversal that hits any limit reports `truncated` and which one
— the bound is part of the contract, not a diagnostic.

### Cases, reports, dashboard

| Variable | Default |
|---|---|
| `CASE_DISPOSITIONS` | the four enum values |
| `CASE_DETAIL_MAX_ITEMS` | 50 (hard cap 200) |
| `CASE_EXPORT_MAX_ITEMS` | 200 (hard cap 1000) |
| `REPORT_ENGINE` | `reportlab` |
| `REPORT_MAX_PAGES` | 40 (hard cap 200) |
| `REPORT_MAX_GENERATION_SECONDS` | 30 |
| `REPORT_INCLUDE_LIMITATIONS` | `true` |
| `REPORT_AUDIT_GENERATION` | `true` |
| `DASHBOARD_DEFAULT_WINDOW_DAYS` | 30 |
| `PAGINATION_DEFAULT_PAGE_SIZE` | 50 |
| `PAGINATION_MAX_PAGE_SIZE` | 200 |

### Audit and privacy

| Variable | Default |
|---|---|
| `AUDIT_ENABLED` | `true` |
| `AUDIT_LOG_DENIED` | `true` |
| `AUDIT_REDACTION_ENABLED` | `true` |
| `AUDIT_EXPORT_MAX_ROWS` | 10000 (hard cap 100000) |
| `RETENTION_AUDIT_DAYS` | 3650 |
| `PRIVACY_MODE` | `synthetic_prototype` |
| `PRIVACY_IP_LOG_MODE` | `hashed` |
| `BACKEND_LOG_MASK_PII` | `true` |
| `BACKEND_MAX_NARRATIVE_LOG_CHARS` | 200 |

`AUDIT_LOG_DENIED` records refused actions as well as permitted ones. A log of
only what succeeded cannot show that somebody tried.

### Logging and observability

| Variable | Default |
|---|---|
| `BACKEND_LOG_LEVEL` | `INFO` |
| `BACKEND_LOG_FORMAT` | `console` (`json` for shipping) |
| `BACKEND_LOG_REQUEST_BODY` | `false` |
| `BACKEND_LOG_RESPONSE_BODY` | `false` |
| `BACKEND_LOG_SQL` | `false` |
| `PROMETHEUS_ENABLED` | `false` |
| `OTEL_ENABLED` | `false` |
| `PERFORMANCE_SLOW_REQUEST_THRESHOLD_MS` | 2000 |
| `REQUEST_ID_HEADER` | `X-Request-ID` |
| `REQUEST_ID_VALIDATE_INBOUND` | `true` |

The body-logging settings are false and should stay false: a request body here
can contain a complaint narrative, and a response body can contain a page of
them.

`REQUEST_ID_VALIDATE_INBOUND` matters more than it looks. The id reaches logs,
audit rows and report filenames, so an unvalidated one is a log-injection
parameter.

## Frontend

`frontend/.env`, and **baked in at build time**:

| Variable | Default |
|---|---|
| `VITE_API_BASE_URL` | `http://localhost:8000` |
| `VITE_APP_NAME` | `MULEGUARD` |

Changing `VITE_API_BASE_URL` needs a rebuild, not a restart. The symptom of
forgetting is a frontend that loads with every panel in its error state while
the backend is healthy.

## Scripts

Read from the environment, never passed as arguments — an argument ends up in
a shell history file and in `ps` output.

| Variable | Used by |
|---|---|
| `MULEGUARD_BASE_URL` | all |
| `MULEGUARD_ADMIN_USER` | `import_json.py`, `seed_demo`, `smoke_test` |
| `MULEGUARD_ADMIN_PASSWORD` | the same |
| `MULEGUARD_DEV_PASSWORD` | `create_dev_users.py` |

The backend's own `DEV_*_PASSWORD` settings are separate and empty by default;
`DEV_USERS_REQUIRE_PASSWORD_FROM_ENV` is true, so seeding a user with no
password configured fails rather than inventing one.

## Precedence

Process environment, then `backend/.env`, then the model default. The
environment wins, which is what makes
`DATABASE_URL=... alembic upgrade head` work against a copy.
