# ADR 0006: Alembic migrations, and no `create_all` outside tests

- **Status:** accepted
- **Date:** 2026-02-11
- **Deciders:** MULEGUARD contributors

## Context

SQLAlchemy can create a schema from the models with one call. It is the
obvious thing to do in a prototype, and it works right up until the first
time somebody has data they want to keep.

This schema has 23 tables, foreign keys in both directions between accounts
and transfers, enum-typed columns, and partial indexes. It will change: the
feature set is not final and the correlation tiers have already moved once.

## Decision

> We will version every schema change as an Alembic revision, and use
> `create_all` only in the test suite.

Development, demonstration and deployment all run `alembic upgrade head`.
`scripts/run_backend_dev.sh` runs it before serving, every time.

## Alternatives considered

### `Base.metadata.create_all()` everywhere

What a prototype usually does. It cannot alter an existing table, so the
upgrade path is "drop the database", and the first person with a week of demo
data loaded discovers that at the wrong moment.

It also hides divergence. A column added to a model and never applied to a
long-running development database produces an error in a query rather than at
startup, and the error names the column rather than the cause.

### Autogenerate and never review

Alembic's autogenerate is used here, and its output is reviewed rather than
committed as produced. It reliably misses a server default change, an index
rename and a constraint rename, and it occasionally proposes dropping a table
it cannot see — which, applied in order, is a data loss bug with a clean diff.

### A migration tool outside Python, such as Flyway or Sqitch

Rejected on dependency count. Alembic reads the same model metadata, so a
mismatch between models and migrations is detectable (`alembic check`) rather
than a thing somebody notices later.

## Consequences

### What this makes easy

- Upgrading a database that has data in it.
- Reviewing a schema change as a diff.
- `alembic check` in CI catching a model change with no migration.
- Downgrade paths, which `scripts/reset_demo.sh` uses.

### What this makes hard

- Every model change needs a migration, including during exploratory work.
  That is the cost, and it is paid once per change rather than once at the end.
- Keeping SQLite and PostgreSQL both working. Mitigated by avoiding native
  enum types, which is why `enum_column()` passes `native_enum=False`.

### What would make us revisit this

Nothing foreseeable. The alternative is worse at every scale above one
person's laptop.

## Notes

`backend/migrations/` holds the revisions. The test suite builds its schema
with `init_db()` against in-memory SQLite, which is the one place `create_all`
is legitimate: a test database is created and destroyed within the test and
has no upgrade path to preserve.
