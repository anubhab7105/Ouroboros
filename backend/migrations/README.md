# MULEGUARD database migrations

Alembic migrations are the only supported way to create or change the MULEGUARD
schema. `app.db.init_db()` exists for tests and throwaway local databases; it
calls `create_all` and knows nothing about upgrade paths, so it must never be
used against a database that holds data you care about.

## Revisions

| Revision | What it does |
|---|---|
| `0001_initial_schema` | Creates all 23 tables, their constraints and their declared indexes. |
| `0002_seed_roles_and_reference_data` | Seeds the two baseline `model_versions` rows (`rules-only-v1`, `heuristic-fallback-v1`). Creates no users. |
| `0003_add_investigation_indexes` | Adds 13 composite indexes for the query shapes the investigation UI issues. |

## Running them

The database URL is **not** read from `alembic.ini` — the value there is a
deliberately unusable placeholder so no credential is ever committed. `env.py`
resolves it in this order:

1. `alembic -x url=...`
2. the `DATABASE_URL` environment variable
3. application settings (`app.core.config.get_settings`)
4. `alembic.ini`, only if it is not the placeholder

```bash
cd backend

# usual path: DATABASE_URL already set (docker compose does this for you)
alembic upgrade head

# explicit one-off
alembic -x url="postgresql+psycopg://muleguard:muleguard@localhost:5432/muleguard" upgrade head

# where are we?
alembic current
alembic history --verbose

# roll back one revision
alembic downgrade -1

# review the DDL without touching a database
alembic upgrade head --sql > upgrade.sql
```

In Docker, `docker-entrypoint.sh` runs `alembic upgrade head` before starting
the API, so a fresh `docker compose up` arrives at `head` on its own.

## Creating a new revision

```bash
cd backend
alembic revision --autogenerate -m "short description"
```

Then **read the generated file before committing it.** Autogenerate is a
starting point, not an oracle. In this schema it specifically gets these wrong:

- **Enum changes.** Enums are `native_enum=False`, so they are VARCHAR plus a
  CHECK constraint. Adding a member changes the CHECK, and autogenerate often
  misses it. Write the constraint change by hand.
- **Index renames.** It emits a drop plus a create, which on a large table means
  a window with no index. Use `op.execute("ALTER INDEX ... RENAME TO ...")` on
  PostgreSQL instead.
- **Server defaults.** Most MULEGUARD defaults are Python-side
  (`default=utcnow`), not server-side, so they do not appear in the database at
  all. Autogenerate sometimes proposes adding a server default that was never
  there.
- **Column drops on SQLite.** SQLite cannot `DROP COLUMN`. `env.py` sets
  `render_as_batch=True` for SQLite so batch mode rewrites the table; verify any
  destructive change against both backends.

### Rules for every revision

1. **`downgrade` must work.** If a change genuinely cannot be reverted, raise
   `NotImplementedError` with the reason rather than leaving `pass` — an
   operator should find out before a rollback, not during one.
2. **No imports from `app.*` in a revision.** A migration has to keep working
   after the models move on. `0002` declares its own `sa.table()` for exactly
   this reason. `env.py` is the one exception: it imports the models so
   autogenerate can see the metadata.
3. **Separate data from schema.** A migration that both alters a table and
   backfills it is hard to roll back safely. Add the column in one revision,
   backfill in the next.
4. **Keep names stable.** Constraint names come from the naming convention in
   `app.db.NAMING_CONVENTION`. Changing that convention renames every
   constraint in the database.
5. **Declare new indexes on the models too.** Otherwise the next autogenerate
   sees them in the database but not in the metadata and proposes dropping
   them. Every index in `0003` is also declared in
   `app.models.__table_args__` for this reason.

## Verifying the schema matches the models

`scripts/check_schemas.py --migrations` compares every table and column in
`app/models.py` against the `op.create_table` calls in `0001`, without needing
a database or SQLAlchemy installed. CI runs it, and it is the check that
catches a model edit that nobody migrated.

## Things that are not in the database

- **Users and passwords.** Created by `scripts/create_dev_users.py` or by an
  administrator. A migration that invents credentials is how a prototype ends
  up shipping with a live admin account.
- **Detection rules.** `backend/config/rules.default.json`, loaded at analysis
  time, so a rule change is a reviewable diff rather than an `UPDATE`.
- **Scoring weights and thresholds.** `backend/config/scoring.default.json`.
- **Model artifacts.** On disk under `app/ml/artifacts/`, referenced by
  `model_versions.artifact_path` with a checksum. Only the metadata is stored
  in the database.
