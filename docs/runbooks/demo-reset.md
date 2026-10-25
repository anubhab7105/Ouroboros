# Resetting the demo

Put the system back to a known state, usually before showing it to somebody.

```bash
export MULEGUARD_DEV_PASSWORD=choose-something
export MULEGUARD_ADMIN_PASSWORD=$MULEGUARD_DEV_PASSWORD

scripts/reset_demo.sh --yes --reseed
```

That drops every row, migrates back up, recreates the four users and loads the
samples with an analysis pass. Two to three minutes on the sample data.

## What it does, in order

1. Reads `BACKEND_ENV` and refuses if it looks deployed.
2. `alembic downgrade base` — drops everything.
3. `alembic upgrade head` — rebuilds the schema at the current revision.
4. `create_dev_users.py` — the four roles.
5. `seed_demo.sh` — loads records in dependency order, then runs an analysis
   pass so the dashboard has something on it.

## Why it is all-or-nothing

There is no selective reset, and that is deliberate. A half-reset database is
worse than either state: the accounts that survive are referenced by transfers
that did not, so the foreign keys hold while the data means nothing, and the
first symptom is a graph view with edges to accounts that are gone.

## Why it checks the environment rather than taking a flag

`reset_demo` refuses when `BACKEND_ENV` is `production`, `staging`, `uat` or
similar. A flag is the thing somebody passes by accident at the end of a long
day; an environment name is what the deployment already knows about itself.

Without `--yes` it also asks you to type the environment name back, which is a
second chance to notice you are pointed at the wrong database. The target host
and database name are printed first — not the URL, because a connection URL
usually has a password in it and this output ends up in logs.

## A bigger dataset

The samples are seven accounts: enough for every rule to have something to
find, and small enough to read end to end. For something that looks like a
portfolio:

```bash
scripts/reset_demo.sh --yes
python scripts/create_dev_users.py
scripts/seed_demo.sh --generate 500
```

500 accounts and 20,000 transfers takes a couple of minutes to generate and
load, and the analysis pass afterwards is the longer part.

## Before a demonstration

A list worth having, because every item on it has gone wrong at least once:

```bash
scripts/smoke_test.sh            # eleven checks; skipped is not passed
```

- The synthetic banner is visible. It should be, and it is the first thing a
  viewer asks about.
- The alert queue is not empty. If it is, the analysis pass did not run, or
  nothing scored above the alert threshold.
- The hard negative (`ACC-S-HARD-NEGATIVE`) has **not** alerted. It is a
  merchant settling to a processor and it looks like a collection account on
  three of four signals. If it alerted, the rules are measuring activity
  rather than typology, and that is the most interesting thing you could show
  somebody by accident.
- Log in as the analyst, not the admin. The demonstration is better when the
  separation of duties is visible: watch the analyst fail to close a case.

## If something is wrong mid-demonstration

Do not reset. Open a case and talk through it — the workflow is the product,
and an empty dashboard with a working case view is a better demonstration than
a restart.

The most common mid-demo problem is an expired token, which looks like
everything breaking at once. Log in again.
