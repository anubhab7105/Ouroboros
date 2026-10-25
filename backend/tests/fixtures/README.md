# Ingestion fixtures

JSON payloads for the ingestion tests. They exist so that the shape of an
acceptable record is written down somewhere a person can read, rather than
living only inside assertions.

## Two file shapes

**`*.valid.json`** is postable as it stands:

```json
{ "records": [ { … }, { … } ] }
```

A test posts the whole object to the matching `/api/v1/ingestion/*` endpoint
and expects `accepted` to equal the number of records.

**`*.invalid.json`** is a list of cases, each with the reason it must be
rejected:

```json
{ "cases": [ { "name": "…", "why": "…", "record": { … } } ] }
```

A test posts each `record` on its own and expects it to be rejected. The
`why` field is the point of these files: a rejection that happens for a
different reason than the one stated is not the test passing, so the tests
assert on the error's `field` where the record has one bad field.

## Identifiers

Accounts carry explicit `id` values of the form `ACC-V-01`. Ingestion accepts
a caller-supplied id, and fixing them here is what lets the transaction and
entity-link fixtures refer to accounts by name instead of threading generated
ids through the test.

The prefix says which file owns the id: `ACC-V-*` from `accounts.valid.json`,
`ENT-V-*` from `entity_links` and `entities`. Tests that need both load the
accounts first; the ordering is a foreign-key requirement, not a convention.

## These are not real records

Every value here is invented. The hashes are not hashes of anything, the
phone numbers are from the reserved ranges, and the narratives are written
to read like complaints without describing any actual incident. Nothing in
this directory should ever be replaced with production data — the repository
is public, and `BACKEND_DATASET_MODE` defaults to `synthetic` precisely so
that a deployment holding real records has to say so deliberately.

## Amounts

Amounts are JSON numbers, which the API parses into `Decimal`. They are
written with at most two decimal places so that no fixture depends on how a
float literal happens to round. Currency is always a three-letter code; the
API rejects anything else, and the aggregates never sum across currencies,
so a fixture mixing them is testing that separation rather than being
careless.
