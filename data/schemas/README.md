# Ingestion schemas

JSON Schema (draft 2020-12) for the five record types the ingestion API
accepts, plus the response every batch endpoint returns.

| File | Describes | Endpoint |
|---|---|---|
| `account.schema.json` | One bank account | `POST /api/v1/ingestion/accounts` |
| `transaction.schema.json` | One transfer between two accounts | `POST /api/v1/ingestion/transactions` |
| `complaint.schema.json` | One fraud or cybercrime complaint | `POST /api/v1/ingestion/complaints` |
| `entity.schema.json` | One pseudonymous shared identifier | `POST /api/v1/ingestion/entities` |
| `entity-link.schema.json` | One account-to-identifier association | `POST /api/v1/ingestion/entity-links` |
| `batch-response.schema.json` | What all five return | — |

Each schema describes **one record**. The endpoints take a batch:

```json
{
  "records": [ { … }, { … } ],
  "options": { "source_system": "my-loader", "allow_partial": false }
}
```

## These are generated, not hand-written

`scripts/check_schemas.py --write` writes them from
`backend/app/core/vocabularies.py`, which is the single definition of what the
database columns accept. Without `--write` the same script re-derives them and
fails if the files on disk have drifted, which is what CI runs.

That is not ceremony. Every one of these vocabularies previously existed in
four hand-maintained copies — the ORM columns, the ingestion normalizer, the
ingestion validator, the synthetic generator — and the copies had drifted
apart on every single field. Account type is the clearest case: the database
accepted `INDIVIDUAL`, `BUSINESS`, `MERCHANT`, `OTHER`, while ingestion
accepted `SAVINGS`, `CURRENT`, `WALLET`, `UPI`, `CARD`, `OTHER`. They shared
one value. A correct record failed validation, an accepted record failed on
insert, and the account-type feature was constant in every vector the model
ever saw. None of it raised an error naming the cause.

So if you are adding a value, add it to `vocabularies.py` and regenerate.
Editing a schema by hand puts a sixth copy in play.

## Validating a file before you load it

```bash
python scripts/check_schemas.py --data data/samples/accounts.sample.json \
                               --schema data/schemas/account.schema.json
```

`jsonschema` is in `requirements-dev.txt`. The checker reports every failing
record with its index, which is what you need to fix a file rather than
bisect it.

## What the schemas will not tell you

They are structural. Three classes of rule are enforced by the API and cannot
be expressed here:

**Referential integrity.** A transfer's two account ids are foreign keys, and
a complaint's `transaction_reference` is matched against transfers already
loaded. A file that validates can still be rejected for naming an account
that does not exist. Load in order: accounts, then entities, then
transactions, then entity links, then complaints.

**Cross-field rules.** `valid_to` must not precede `valid_from`. A timestamp
must not be in the future beyond the configured clock-skew tolerance. An
`amount` requires a `currency` when present.

**Field rejection.** Ground-truth labels, scenario ids, ring ids, secrets,
tokens and raw identifiers are dropped or refused regardless of what the
schema says, because `additionalProperties: false` here is a convenience and
the server's blocklist is the actual control. See `docs/security.md`.

## Two things in the schemas worth reading twice

**`confidence` is a fraction, not a percentage.** `0.88`, not `88`. A value
above 1 is refused rather than divided by a hundred, because a source that
genuinely means a confidence above one exists and silently rescaling its data
would be worse than refusing it.

**A deterministic link has no `confidence` at all.** Not `1.0`. A certainty
and a probability in the same column invite a reader to compare them, and the
interface renders the absence as the word "identity" for the same reason.
