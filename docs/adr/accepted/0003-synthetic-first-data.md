# ADR 0003: Synthetic data by default, enforced rather than advised

- **Status:** accepted
- **Date:** 2026-02-10
- **Deciders:** MULEGUARD contributors

## Context

MULEGUARD processes exactly the data that is most sensitive to hold: bank
transfers, device and phone identifiers, and the free-text narratives of
cybercrime complaints written by people describing being defrauded.

It is a prototype. It has no data retention schedule, no subject-access
process, no breach procedure, no key management, and no authority to hold any
of this about a real person.

A README line saying "use synthetic data only" is not a control. It is a
sentence that somebody will not read before loading a CSV they already have,
because having real data to try it on is exactly what makes a detection
prototype interesting.

## Decision

> We will default `INGESTION_REQUIRE_SYNTHETIC` to true, refuse ingestion of batches
> that do not declare themselves synthetic, and make the platform say so in
> every response.

The declaration is in the batch options. The refusal is at the API boundary.
The statement travels in the health payload (`data_classification: synthetic`,
`production_ready: false`), in the response caveats, and in the interface
banner.

## Alternatives considered

### Document it and trust the operator

The usual approach, and the reason this ADR exists. The failure mode is not
malice; it is somebody evaluating the tool the way one evaluates a tool.

### A startup flag with no runtime enforcement

Better, and still wrong, because the flag would be set once by whoever stood
the system up and never seen again by whoever loaded the data.

### Refuse any data that fails a PII heuristic

Considered seriously. Rejected because a heuristic that is strict enough to
catch real data refuses plenty of synthetic data too, and the resulting
experience teaches people to work around the check. The declaration is
explicit and auditable instead; the field blocklist does the narrower,
reliable job of refusing raw identifiers outright.

## Consequences

### What this makes easy

- An unambiguous answer to "is there real data in this?" — no, and the
  system will not accept any.
- Honest demonstrations. Nobody has to wonder whether a screenshot leaks
  something.
- Reproducible evaluation, because the generator is seeded.

### What this makes hard

- Evaluating detection quality, which is the real cost. Metrics computed on
  generated data measure agreement between the generator and the rules,
  because the generator plants the typologies the rules look for. The model
  card says this rather than reporting a number as though it meant more.
- A pilot on real data. That is a deliberate obstacle: it requires turning
  the flag off knowingly, and the obligations that come with real data are not
  met by this codebase.

### What would make us revisit this

A deployment with a lawful basis, a retention schedule, key management and a
breach procedure in place — at which point the flag is the smallest part of
what needs to change.

## Notes

Enforced in `app/ingestion/validators.py` and the ingestion endpoints. The
field blocklist that refuses ground-truth labels, scenario ids, ring ids, raw
identifiers and secrets is in `app/ingestion/normalizers.py` and tested in
`backend/tests/test_ingestion_validation.py`. See also `docs/compliance-note.md`.
