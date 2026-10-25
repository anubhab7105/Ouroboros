# Upgrading

Pulling new code and bringing a database with data in it along with it.

```bash
git pull
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
cd backend && alembic upgrade head && cd ..
scripts/smoke_test.sh
```

For a demonstration database with nothing worth keeping,
`scripts/reset_demo.sh --yes --reseed` is faster and has fewer ways to go
wrong.

## Before you upgrade anything with data in it

Take the backup, and record the revision with it:

```bash
cd backend && alembic current        # write this down
pg_dump --format=custom --file=pre-upgrade.dump "$DATABASE_URL"
```

A dump without its revision is a dump somebody will have to bisect migrations
against later.

## Test the migration against a copy first

This is the step that gets skipped, and the one that matters. A migration that
works on an empty schema can fail on data — a `NOT NULL` column with no
default, a unique constraint that the existing rows violate, a type change
that cannot cast.

```bash
createdb muleguard_upgrade_test
pg_restore --no-owner --dbname=muleguard_upgrade_test pre-upgrade.dump

DATABASE_URL=postgresql://.../muleguard_upgrade_test \
  alembic -c backend/alembic.ini upgrade head
```

If that passes on a copy of production data, the real one almost certainly
will. If it fails, you have found out at no cost.

## Read the migration before applying it

```bash
cd backend
alembic history --verbose -r current:head      # what is about to run
alembic upgrade head --sql                     # the SQL, without running it
```

Three things to look for, each of which has happened:

**A dropped column or table.** Alembic's autogenerate occasionally proposes
dropping something it cannot see — a table created outside the models, a
column added by hand. Applied in order, that is data loss with a clean diff.

**A `NOT NULL` addition with no server default.** Fails on any existing row.
The fix is three migrations: add nullable, backfill, then enforce.

**A long-held lock.** A table rewrite on a large table blocks writes for its
duration. On the scale this runs at, unlikely; worth a glance anyway.

## After upgrading

```bash
cd backend && alembic current             # should equal head
cd .. && scripts/smoke_test.sh
```

Then check the two things an upgrade is most likely to have broken:

```bash
# The schema matches the models. Catches a model change with no migration.
cd backend && alembic check
```

```bash
# The schemas on disk match the vocabulary module. Catches a new enum value
# that ingestion now accepts and the documented schema does not mention.
python scripts/check_schemas.py
```

That second one is worth running on every upgrade. The vocabularies that
describe ingestible records are derived from one module precisely because they
used to exist in four hand-maintained copies that had drifted apart on every
field, and this is the check that keeps the generated schemas honest.

## Rolling back

### Code only

If the migration has not run, `git checkout` the previous revision and
restart. Nothing else to do.

### Code and schema

```bash
cd backend
alembic downgrade -1          # one revision
alembic downgrade <revision>  # to a specific one
```

Downgrades are written for every revision here, and they are tested only by
`reset_demo.sh` going all the way to base. A downgrade that has to preserve
data is the one to distrust: a column being dropped takes its data with it,
and no downgrade can bring it back.

If the downgrade fails, restore the dump into a new database and point at it.
That is why the dump was taken.

### What cannot be rolled back

A migration that dropped a column, and anything that was written after the
upgrade. Rolling the schema back does not un-write rows the new code added in
a shape the old code cannot read.

## Upgrading the frontend

```bash
cd frontend && npm ci && npm run build
```

`npm ci` rather than `npm install`: it installs exactly the lockfile, which is
the point of having one.

`VITE_API_BASE_URL` is baked in at build time. Changing it means a rebuild,
not a restart — the symptom of forgetting is a frontend that loads with every
panel in its error state while the backend is healthy.

## Dependency upgrades

Pinned in `requirements.txt` and `package-lock.json`. Upgrade deliberately,
one group at a time, and run the suite between groups. The ones worth extra
care:

- **SQLAlchemy.** The models use 2.0 typed `Mapped[]` declarations.
- **Pydantic.** v2. Field validators and `ConfigDict` are v2 spellings.
- **FastAPI.** Dependency resolution and response-model behaviour are what the
  endpoint contracts rest on.

After any of those three, run the full suite rather than the smoke test. The
smoke test checks that the system works; the suite checks that it still works
the way the contracts say.
