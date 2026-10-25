# scripts/

Six Python tools and seven shell/PowerShell pairs. Everything here is meant to
be run from the repository root:

```bash
python scripts/check_schemas.py
scripts/seed_demo.sh
```

```powershell
python scripts/check_schemas.py
./scripts/seed_demo.ps1
```

The `.sh` and `.ps1` files in each pair do the same thing, including the same
exit codes and the same messages. Where they differ, the `.sh` version is the
one the Makefile calls and the one CI runs.

## Getting a working system

From a clean checkout, in order:

```bash
cp backend/.env.example backend/.env       # then set BACKEND_SECRET_KEY
export MULEGUARD_DEV_PASSWORD='choose-something'
export MULEGUARD_ADMIN_PASSWORD="$MULEGUARD_DEV_PASSWORD"

scripts/run_backend_dev.sh &               # migrates, then serves
scripts/wait_for_backend.sh
python scripts/create_dev_users.py         # four users, one per role
scripts/seed_demo.sh                       # load samples, then analyse
scripts/smoke_test.sh                      # confirm it works
scripts/run_frontend_dev.sh
```

`make demo` does the middle four.

## The tools

| Script | What it does |
|---|---|
| `generate_data.py` | Write a synthetic dataset as ingestible batch files |
| `import_json.py` | Load batch files into a running backend, in dependency order |
| `check_schemas.py` | Generate or verify `data/schemas/`; validate a data file |
| `evaluate_model.py` | Train and evaluate on a generated dataset, with the caveats |
| `create_dev_users.py` | Create the four local users, one per role |
| `generate_project_tree.py` | Print the repository tree; `--check` for CI |

| Pair | What it does |
|---|---|
| `run_backend_dev` | Migrate, then serve with reload |
| `run_frontend_dev` | Serve the frontend; warns if no backend is reachable |
| `wait_for_backend` | Block until `/health/ready` reports ready |
| `seed_demo` | Load a dataset and run an analysis pass |
| `reset_demo` | Drop every row, migrate back up, optionally reseed |
| `train_model` | Generate a labelled dataset, train, evaluate |
| `smoke_test` | Eleven checks against a deployed backend |

## Conventions these follow

**Credentials come from the environment.** No script takes a password as an
argument, because an argument ends up in a shell history file and in the
output of `ps`. `MULEGUARD_ADMIN_PASSWORD` and `MULEGUARD_DEV_PASSWORD` are
read from the environment or the script stops and says so.

**Nothing prints a secret.** `reset_demo` prints the database host and name but
not the URL, because a connection URL usually has a password in it and this
output ends up in CI logs.

**Destructive things check the environment, not a flag.** `reset_demo` and
`create_dev_users` refuse when `BACKEND_ENV` is `production`, `staging` or
similar. A flag is the thing somebody passes by accident at two in the
morning; an environment name is what the deployment already knows about
itself.

**Order is enforced rather than documented.** `import_json.py` loads accounts,
then entities, then transactions, then entity links, then complaints, because
the ingestion API checks foreign keys instead of creating records implicitly.
Loading in the wrong order produces a wall of rejections that reads like bad
data.

**A partial success is reported as a failure.** Every ingestion endpoint
returns four disjoint counts summing to the number of records submitted, and
HTTP 201 with `ok: false` for a partial load. `import_json.py` checks the
arithmetic and exits non-zero if anything was refused, because a caller
checking only the status code treats a half-loaded batch as a success.

**Skipped is not passed.** `smoke_test` prints `SKIP` for the authenticated
checks when no password is available, and says how many it skipped. A smoke
test that quietly runs four of eleven checks and reports success is worse than
no smoke test.

## Two scripts worth reading before running

**`evaluate_model.py`** prints the metrics and then prints what they do not
mean. The generator plants the typologies the rules look for, so a score from
this pipeline measures agreement between the generator and the model — a real
check that training works end to end, and no evidence about detection quality
on a real portfolio. The default split is `grouped` rather than `random`
because a random split puts four accounts of a five-account ring in training
and the fifth in test, and then reports how well the model memorised that ring.

**`reset_demo.sh`** drops every row and there is no selective version. A
half-reset database is worse than either state: the accounts that survive are
referenced by transactions that did not.

## Dependencies

`import_json.py` and `generate_project_tree.py` use only the standard library,
so they run against a deployed backend from a machine with nothing installed.

`check_schemas.py` imports `app.core.vocabularies`, which also imports only
the standard library — that is deliberate, and `--data` validation uses
`jsonschema` when it is installed and falls back to a structural check when it
is not, saying which it did.

The rest need the backend requirements:

```bash
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
```
