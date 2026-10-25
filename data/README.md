# data/

Everything MULEGUARD reads from or writes to disk, and nothing it needs to
run. The application works with an empty `data/` directory; what is here is
sample input, the schemas that describe it, and two directories for files you
or the generator produce.

```
data/
├── samples/      checked in, small, hand-written, explained
├── schemas/      JSON Schema for every ingestible record type
├── generator/    notes on the synthetic generator (the code is in the backend)
├── generated/    generator output (gitignored)
└── imports/      files you are about to load (gitignored)
```

## Everything here is synthetic

Not anonymised, not masked, not a sample of something real — invented. The
accounts do not exist, the complaints were written for this repository, and
the identifier hashes are sha256 of fixed strings chosen to be obviously fake.

That is a product constraint rather than a convenience. `REQUIRE_SYNTHETIC`
defaults to true and ingestion refuses a batch that does not declare itself
synthetic. `docs/compliance-note.md` has the reasoning; the short version is
that a prototype holding real transaction and complaint data is a different
kind of object with different obligations, and nothing in this repository is
built to carry them.

## The samples

Seven files. The four `*.sample.json` record files load through the ingestion
API and produce a database where every detection rule has something to find.
The two `invalid-*.sample.json` files are the other half: records that must be
refused, each with the reason written down.

| File | Records | What it is for |
|---|---|---|
| `accounts.sample.json` | 7 | One account per shape, including a hard negative |
| `entities.sample.json` | 2 | The shared device and IP the links need |
| `transactions.sample.json` | 21 | A fan-in, a pass-through, a dormant wake, and ordinary traffic |
| `complaints.sample.json` | 4 | One per correlation tier, including one that should match nothing |
| `entity-links.sample.json` | 5 | Two deterministic, three inferred, one rejected on review |
| `invalid-accounts.sample.json` | 6 cases | Rejections, with reasons |
| `invalid-transactions.sample.json` | 7 cases | Rejections, with reasons |

### Load order matters

The ingestion endpoints enforce referential integrity rather than creating
records implicitly, so:

```
accounts → entities → transactions → entity-links → complaints
```

`scripts/seed_demo.sh` (or `.ps1`) does this in order. By hand:

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"admin","password":"<your dev password>"}' | jq -r .access_token)

for pair in accounts:accounts entities:entities transactions:transactions \
            entity-links:entity-links complaints:complaints; do
  file="${pair%%:*}"; path="${pair##*:}"
  curl -s -X POST "localhost:8000/api/v1/ingestion/$path" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d @"data/samples/${file}.sample.json" | jq '{accepted, rejected, duplicated}'
done
```

A transfer naming an unknown account is refused rather than creating one. That
is deliberate: an account conjured from a transfer has no opening date, type or
status, and would score as a brand-new account forever — which is itself one of
the strongest signals in the model.

### The hard negative is the most useful record here

`ACC-S-HARD-NEGATIVE` is a merchant settling to a payment processor. It has
high throughput, many counterparties and a thin retained balance: three of the
four things the collection rule looks at. **It should not alert.**

If it does, the rules are measuring activity rather than typology, and the
consequence is not an abstract one — the triage queue fills with legitimate
businesses and the analysts who work it stop trusting the queue. A detection
prototype with no hard negatives in its sample data will pass all of its own
tests and fail on contact with a real portfolio.

### Why the rejection fixtures carry prose

Each case in `invalid-*.sample.json` has a `why`. A rejection fixture whose
cases are not explained is a fixture nobody dares to change, because the next
person cannot tell a deliberate case from a typo, and the cheapest way to make
a failing test pass is to delete the case that was protecting something.

Two of them guard against a specific regression. `SAVINGS` as an account type
and `FROZEN` as a status were both once accepted by the ingestion layer and
refused by the database — see `data/schemas/README.md` for how four
hand-maintained copies of one vocabulary drifted apart.

## generated/ and imports/

Both gitignored except for their `.gitkeep`.

`generated/` is where `scripts/generate_data.py` writes. Output is
reproducible from a seed, so it is regenerated rather than committed, and a
dataset that matters is identified by its seed and the generator version
rather than by a file somebody kept.

`imports/` is a working directory for files you are about to load. Nothing
reads it automatically; it exists so that a file you are halfway through
fixing is not sitting in `samples/` next to the checked-in ones.

## Two files not in the original project tree

`data/schemas/entity.schema.json` and `data/samples/entities.sample.json`.

Entities are one of the five ingestible record types and the entity-link
sample refers to two of them, so without these the documented load order could
not be followed and the graph view would have nothing to draw. The alternative
was a README snippet containing JSON, which is a worse place for data that
needs to be validated.
