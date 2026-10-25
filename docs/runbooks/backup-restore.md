# Backup and restore

One database holds everything: records, assessments, cases, evidence and the
audit trail. There is no second store to reconcile, which makes this short.

Generated datasets are not backed up. They are reproducible from a seed and a
generator version, and `data/generated/` is gitignored for that reason.

## What is actually at risk

Be clear about what a backup here is protecting, because most of the database
is replaceable:

| Data | Replaceable? |
|---|---|
| Ingested records | Yes, from the source files |
| Assessments, alerts | Yes — re-run the analysis |
| **Cases, notes, evidence, dispositions** | **No. Human work.** |
| **Audit trail** | **No. Append-only by design.** |
| Users | Recreatable, but credentials are not |

The two in bold are the reason to take a backup. An analysis run can be
repeated; an investigator's reasoning and the record of who did what cannot.

## Backing up

### PostgreSQL

```bash
pg_dump --format=custom --no-owner --no-privileges \
        --file="muleguard-$(date +%Y%m%d-%H%M).dump" \
        "$DATABASE_URL"
```

Custom format rather than plain SQL: it compresses, it restores selectively,
and `pg_restore --list` shows what is in it without restoring anything.

In Docker:

```bash
docker compose exec -T db pg_dump -U muleguard --format=custom muleguard \
  > "muleguard-$(date +%Y%m%d-%H%M).dump"
```

### SQLite (development)

```bash
sqlite3 backend/muleguard.db ".backup 'muleguard-$(date +%Y%m%d).db'"
```

Use `.backup`, not `cp`. Copying a SQLite file while a connection is open can
capture a torn write; `.backup` takes a consistent snapshot.

### What to record alongside the dump

A dump restored into the wrong schema version fails in a way that is hard to
read. Record:

```bash
cd backend && alembic current        # the revision the dump was taken at
```

Keep that revision with the dump. It is the single most useful thing in the
file, and the one most often missing.

## Restoring

### Into an empty database

```bash
createdb muleguard_restored
pg_restore --no-owner --no-privileges --dbname=muleguard_restored backup.dump
```

Then bring the schema to the revision the application expects:

```bash
cd backend && alembic upgrade head
```

If the dump predates the current code, this applies the intervening
migrations. That is the normal path and it is why the revision is worth
recording.

### Over an existing database

Do not. Restore into a new database and point `DATABASE_URL` at it once you
have checked the contents. A restore over a live database is irreversible, and
the moment you discover the dump was the wrong one is after it has overwritten
the only copy.

### Verifying a restore

Row counts tell you the restore ran. These tell you it restored the right
thing:

```sql
-- The audit trail should be continuous and end when you expect.
SELECT min(created_at), max(created_at), count(*) FROM audit_events;

-- Closed cases should have a disposition. None should be null: the state
-- machine requires one, so a null here means a row predating that rule or a
-- restore that lost a column.
SELECT status, disposition, count(*)
FROM investigation_cases GROUP BY status, disposition;

-- Evidence should still point at records that exist.
SELECT count(*) FROM case_evidence ce
LEFT JOIN accounts a ON a.id = ce.evidence_id
WHERE ce.evidence_type = 'ACCOUNT' AND a.id IS NULL;
```

Then:

```bash
scripts/smoke_test.sh
```

## What a backup does not protect against

**A bad migration.** The dump is at a revision; restoring it and running the
same migration reproduces the damage. Test a migration against a copy first —
`docs/runbooks/upgrading.md` covers this.

**An operator mistake replicated before anyone noticed.** Keep more than one
generation. A single nightly dump overwritten each night protects against disk
failure and nothing else.

**Secrets.** `BACKEND_SECRET_KEY` is not in the database. Restoring the
database without it leaves every stored password hash valid and every issued
token worthless, which is survivable, but the key belongs in whatever holds
your other secrets.

## Retention

This is a prototype holding synthetic data, so there is no retention schedule
here and none is implied. A deployment holding anything else needs one before
it needs a backup policy — see `docs/compliance-note.md`.
