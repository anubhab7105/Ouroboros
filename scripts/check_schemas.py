#!/usr/bin/env python3
"""
Generate the ingestion JSON Schemas, or check that they have not drifted.

The schemas in `data/schemas/` describe what the ingestion API accepts, and
what it accepts is decided by one module: `backend/app/core/vocabularies.py`.
Writing them by hand would put a second copy of every vocabulary in play, and
this repository has already been through what happens then — the ORM columns,
the ingestion normalizer, the ingestion validator and the synthetic generator
each carried a copy, and all four had drifted apart. A correct record failed
validation while an accepted one failed on insert.

So the schemas are generated. CI runs this without `--write`, which regenerates
into memory and diffs against the files, and fails if they disagree.

    python scripts/check_schemas.py                 # check, exit 1 on drift
    python scripts/check_schemas.py --write         # regenerate the files
    python scripts/check_schemas.py --data FILE --schema FILE   # validate data

The third form validates a data file against one schema. It needs the
`jsonschema` package (in `requirements-dev.txt`); without it, the script falls
back to a structural check covering required fields, unknown fields and enum
membership, and says which one it did.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "data" / "schemas"
BACKEND = REPO_ROOT / "backend"

ID_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
HASH_PATTERN = "^[0-9a-f]{32,128}$"
CURRENCY_PATTERN = "^[A-Z]{3}$"

#: Which schema describes which record type, and the key under `records`.
RECORD_SCHEMAS = {
    "account": "accounts",
    "transaction": "transactions",
    "complaint": "complaints",
    "entity": "entities",
    "entity-link": "entity_links",
}


def load_vocabularies() -> Any:
    """
    Import the vocabulary module from the backend package.

    `app.core.vocabularies` imports nothing beyond the standard library, which
    is the whole reason this script can run without SQLAlchemy, FastAPI or a
    database. If that stops being true, this import is where it shows up.
    """
    sys.path.insert(0, str(BACKEND))

    try:
        from app.core import vocabularies
    except ImportError as exc:  # pragma: no cover - environment problem
        raise SystemExit(
            f"Could not import app.core.vocabularies from {BACKEND}: {exc}\n"
            "Run this from the repository root."
        ) from exc

    return vocabularies


def build_schemas(vocab: Any) -> dict[str, dict[str, Any]]:
    """
    Build every schema from the vocabulary module.

    Kept as one function returning the whole set so that a reader can see the
    five record shapes side by side, which is how the differences between them
    become obvious.
    """
    values = vocab.enum_values

    metadata = {
        "type": "object",
        "description": (
            "Free-form synthetic context. Sanitised on ingestion: keys that "
            "look like secrets, tokens, raw identifiers, ground-truth labels, "
            "scenario ids or ring ids are dropped rather than stored."
        ),
    }

    def optional_string(**extra: Any) -> dict[str, Any]:
        """
        An optional string field, which may also be explicitly null.

        The API treats an explicit null as an absent value, because a caller
        building records programmatically emits `"field": null` rather than
        omitting the key, and refusing that would make every generated file
        unloadable for a reason that has nothing to do with its content.
        """
        return {"type": ["string", "null"], **extra}

    #: A decimal carried as a number or a string.
    #:
    #: A string is the better form and the one the samples use: JSON numbers
    #: are IEEE 754 doubles, so 24000.00 survives a round trip but a value with
    #: more precision than a double can hold does not, and a monetary amount
    #: that changes in the last place on its way through a parser is worse than
    #: one that was refused. The validator parses both via `Decimal(str(...))`.
    def decimal_field(**extra: Any) -> dict[str, Any]:
        return {"type": ["number", "string", "null"], **extra}

    def envelope(title: str, description: str, required: list[str], properties: dict) -> dict:
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://muleguard.local/schemas/{title}.schema.json",
            "title": title,
            "description": description,
            "type": "object",
            "additionalProperties": False,
            "required": required,
            "properties": properties,
        }

    schemas: dict[str, dict[str, Any]] = {}

    schemas["account"] = envelope(
        "account",
        (
            "One synthetic bank account as the ingestion API accepts it.\n\n"
            "account_type classifies the HOLDER, not the banking product. A savings "
            "account and a current account held by the same person are both "
            "INDIVIDUAL. There is deliberately no product value: the column cannot "
            "hold one, and mapping a product onto a holder type would record a "
            "claim the source never made.\n\n"
            "status is observational. REVIEW_REQUIRED means somebody should look; "
            "there is no suspended, blocked or restricted value, because MULEGUARD "
            "does not take those actions."
        ),
        ["id", "account_type", "status"],
        {
            "id": {"type": "string", "pattern": ID_PATTERN, "maxLength": 64},
            "account_type": {"type": "string", "enum": list(values(vocab.AccountType))},
            "status": {"type": "string", "enum": list(values(vocab.AccountStatus))},
            "created_at": optional_string(
                format="date-time",
                description=(
                    "When the account was opened. Account age feeds the "
                    "new-account-with-high-throughput signal, so a missing or "
                    "wrong value weakens detection rather than breaking it."
                ),
            ),
            "metadata_json": metadata,
        },
    )

    schemas["transaction"] = envelope(
        "transaction",
        (
            "One synthetic transfer between two accounts already present in the "
            "system.\n\n"
            "Both account columns are foreign keys: a transfer naming an unknown "
            "account is refused rather than creating one, because an account "
            "conjured from a transfer has no opening date, type or status and "
            "would score as a brand-new account forever.\n\n"
            "Only COMPLETED is settled fund movement. Every monetary aggregate in "
            "the platform counts COMPLETED alone, and amounts are never summed "
            "across currencies."
        ),
        ["reference", "sender_account_id", "receiver_account_id", "amount", "occurred_at"],
        {
            "id": {"type": "string", "pattern": ID_PATTERN, "maxLength": 64},
            "reference": {
                "type": "string",
                "maxLength": 128,
                "minLength": 1,
                "description": (
                    "The transfer's identity in the outside world, and unique. It "
                    "is how a complaint naming a transaction is matched to one, "
                    "which is the whole of tier-1 correlation."
                ),
            },
            "sender_account_id": {"type": "string", "pattern": ID_PATTERN, "maxLength": 64},
            "receiver_account_id": {"type": "string", "pattern": ID_PATTERN, "maxLength": 64},
            "amount": decimal_field(
                description=(
                    "Positive. Direction is carried by the sender and receiver "
                    "columns, not by the sign, and a negative amount would be "
                    "counted as a negative inflow. Accepted as a string so a "
                    "caller can avoid float rounding; stored as a decimal."
                ),
            ),
            "currency": optional_string(pattern=CURRENCY_PATTERN, default="INR"),
            "occurred_at": {
                "type": "string",
                "format": "date-time",
                "description": (
                    "Required. Every window, rate and velocity feature is defined "
                    "relative to it, and a transfer with no time cannot be placed "
                    "in a window at all."
                ),
            },
            "status": {
                "type": "string",
                "enum": list(values(vocab.TransactionStatus)),
                "default": "COMPLETED",
            },
            "channel": {
                "type": "string",
                "enum": list(values(vocab.Channel)),
                "default": "INTERNAL",
            },
            "metadata_json": metadata,
        },
    )

    schemas["complaint"] = envelope(
        "complaint",
        (
            "One synthetic cybercrime or fraud complaint.\n\n"
            "A complaint is a citizen's account of what happened. It is evidence "
            "that somebody reported something, not evidence that it occurred, and "
            "nothing in the platform treats a named account as guilty because a "
            "complaint named it.\n\n"
            "narrative_raw is the one field that holds free text written by a "
            "person. It is normalised for correlation and is never returned in a "
            "list view, an error, a log line or an export."
        ),
        ["reference", "reported_at", "narrative_raw"],
        {
            "id": {"type": "string", "pattern": ID_PATTERN, "maxLength": 64},
            "reference": {"type": "string", "maxLength": 128, "minLength": 1},
            "reported_at": {
                "type": "string",
                "format": "date-time",
                "description": (
                    "When the complaint was filed. The correlation window is "
                    "anchored on it, so a wrong value silently changes which "
                    "transfers are considered."
                ),
            },
            "category": optional_string(
                maxLength=100,
                description=(
                    "A free-text label rather than an enum, because complaint "
                    "taxonomies differ between sources and forcing one would lose "
                    "the distinction the source drew."
                ),
            ),
            "narrative_raw": {"type": "string", "minLength": 1, "maxLength": 20000},
            "transaction_reference": optional_string(
                maxLength=128,
                description=(
                    "The transfer the complainant named, if they named one. This "
                    "is what makes a tier-1 correlation: an exact reference match "
                    "needs no confidence score and no review, because it is an "
                    "identity rather than an inference."
                ),
            ),
            "victim_account_id": optional_string(pattern=ID_PATTERN, maxLength=64),
            "suspected_account_id": optional_string(
                pattern=ID_PATTERN,
                maxLength=64,
                description=(
                    "The account the complainant suspects. A suspicion, recorded "
                    "as one. It raises an alert for a person to look at and takes "
                    "no action against the account."
                ),
            ),
            "amount": decimal_field(),
            "currency": optional_string(pattern=CURRENCY_PATTERN),
            "source": optional_string(maxLength=100),
            "metadata_json": metadata,
        },
    )

    schemas["entity"] = envelope(
        "entity",
        (
            "One pseudonymous shared identifier.\n\n"
            "Identifiers reach this table as salted hashes and the raw values are "
            "never stored. The `_HASH` suffixes in entity_type are that design, "
            "not a naming habit. identifier_display holds a masked form for an "
            "interface to show, which is why it may exist alongside the hash."
        ),
        ["id", "entity_type", "identifier_hash"],
        {
            "id": {"type": "string", "pattern": ID_PATTERN, "maxLength": 64},
            "entity_type": {"type": "string", "enum": list(values(vocab.EntityType))},
            "identifier_hash": {
                "type": "string",
                "pattern": HASH_PATTERN,
                "description": (
                    "Lowercase hex, 32 to 128 characters. A value that is not a "
                    "hash is refused: accepting one would put a raw phone number "
                    "into the column every downstream consumer treats as safe."
                ),
            },
            "identifier_display": optional_string(
                maxLength=100,
                description=(
                    "A masked, non-reversible label for display, such as "
                    "'+91-****-****1234'. Optional, and never reconstructible."
                ),
            ),
            "source": optional_string(maxLength=100),
            "first_seen_at": optional_string(format="date-time"),
            "last_seen_at": optional_string(format="date-time"),
            "metadata_json": metadata,
        },
    )

    schemas["entity-link"] = envelope(
        "entity-link",
        (
            "One association between an account and a pseudonymous shared "
            "identifier, valid over a time range.\n\n"
            "The time range is the point. Two accounts that used the same device "
            "two years apart are not connected; two that used it the same week may "
            "be. A link with no bounds collapses that distinction and inflates "
            "every graph it appears in.\n\n"
            "confidence is absent for a deterministic method and present for an "
            "inferred one. Not 1.0 for the deterministic case: a certainty and a "
            "probability in the same column invite a reader to compare them."
        ),
        ["account_id", "entity_id", "match_method"],
        {
            "id": {"type": "string", "pattern": ID_PATTERN, "maxLength": 64},
            "account_id": {"type": "string", "pattern": ID_PATTERN, "maxLength": 64},
            "entity_id": {"type": "string", "pattern": ID_PATTERN, "maxLength": 64},
            "match_method": {
                "type": "string",
                "enum": list(values(vocab.MatchMethod)),
                "description": (
                    "How the association was established. EXACT is an observation; "
                    "NARRATIVE_EXTRACTION is a guess. Which one it is decides "
                    "whether the link needs a person to confirm it."
                ),
            },
            "confidence": decimal_field(
                minimum=0,
                maximum=1,
                description=(
                    "A fraction in [0, 1], not a percentage. 88 meaning 88% is the "
                    "commonest error in this field, and it is refused rather than "
                    "divided by a hundred, because guessing would be wrong for a "
                    "source that really does mean a confidence above one."
                ),
            ),
            "verification_state": {
                "type": "string",
                "enum": list(values(vocab.VerificationState)),
                "default": "UNVERIFIED",
            },
            "valid_from": optional_string(format="date-time"),
            "valid_to": optional_string(
                format="date-time",
                description=(
                    "Open-ended when absent. Must not precede valid_from: a link "
                    "that stopped being true before it started would silently "
                    "match nothing in every window query."
                ),
            ),
            "source": optional_string(maxLength=100),
            "metadata_json": metadata,
        },
    )

    schemas["batch-response"] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://muleguard.local/schemas/batch-response.schema.json",
        "title": "batch-response",
        "description": (
            "What every ingestion endpoint returns.\n\n"
            "The four counts are disjoint and together account for every submitted "
            "record: accepted + rejected + duplicated + skipped == submitted. A "
            "loader can check that arithmetic and know nothing was silently "
            "dropped, which is the one thing a bulk import has to be able to "
            "establish.\n\n"
            "`errors` carries one entry per rejected row, with its index, so a "
            "caller can fix the file rather than bisect it. Narratives, secrets "
            "and raw identifiers never appear in it."
        ),
        "type": "object",
        "required": ["ok", "entity_type", "accepted", "rejected", "duplicated", "skipped"],
        "properties": {
            "ok": {
                "type": "boolean",
                "description": (
                    "False when anything was rejected, even if the batch was "
                    "partially applied. A caller that checks only the HTTP status "
                    "would otherwise treat a half-loaded batch as a success."
                ),
            },
            "entity_type": {
                "type": "string",
                "enum": sorted(RECORD_SCHEMAS.values()),
            },
            "accepted": {"type": "integer", "minimum": 0},
            "rejected": {"type": "integer", "minimum": 0},
            "duplicated": {
                "type": "integer",
                "minimum": 0,
                "description": (
                    "Records whose natural key already existed. Counted apart from "
                    "rejected, because a re-run of the same file is a normal "
                    "event and should not read as a failure."
                ),
            },
            "skipped": {"type": "integer", "minimum": 0},
            "dry_run": {"type": "boolean"},
            "allow_partial": {"type": "boolean"},
            "on_duplicate": {"type": "string", "enum": ["reject", "skip"]},
            "source_system": {"type": ["string", "null"]},
            "source_batch_id": {"type": ["string", "null"]},
            "request_id": {"type": ["string", "null"]},
            "errors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["index", "code", "message"],
                    "properties": {
                        "index": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Position in the submitted array, zero-based.",
                        },
                        "code": {"type": "string"},
                        "message": {"type": "string"},
                        "field": {"type": ["string", "null"]},
                    },
                },
            },
            "caveats": {"type": "array", "items": {"type": "string"}},
        },
    }

    return schemas


def serialize(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2) + "\n"


def write_schemas(schemas: dict[str, dict[str, Any]]) -> int:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    written = 0

    for name, schema in schemas.items():
        path = SCHEMA_DIR / f"{name}.schema.json"
        text = serialize(schema)

        if path.exists() and path.read_text(encoding="utf-8") == text:
            continue

        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(REPO_ROOT)}")
        written += 1

    if not written:
        print("schemas already up to date")

    return 0


def check_schemas(schemas: dict[str, dict[str, Any]]) -> int:
    problems = 0

    for name, schema in schemas.items():
        path = SCHEMA_DIR / f"{name}.schema.json"
        expected = serialize(schema)

        if not path.exists():
            print(f"MISSING {path.relative_to(REPO_ROOT)}")
            problems += 1
            continue

        actual = path.read_text(encoding="utf-8")

        if actual == expected:
            continue

        problems += 1
        print(f"DRIFTED {path.relative_to(REPO_ROOT)}")
        diff = difflib.unified_diff(
            actual.splitlines(keepends=True),
            expected.splitlines(keepends=True),
            fromfile="on disk",
            tofile="generated",
            n=2,
        )
        sys.stdout.writelines(list(diff)[:40])

    if problems:
        print(
            f"\n{problems} schema file(s) differ from the vocabulary module.\n"
            "Run: python scripts/check_schemas.py --write"
        )
        return 1

    print(f"OK: {len(schemas)} schema file(s) match app/core/vocabularies.py")
    return 0


def validate_data(data_path: Path, schema_path: Path) -> int:
    """
    Validate a data file against one schema.

    Accepts either a bare array of records or the batch envelope the ingestion
    endpoints take, because both are things people have on disk.
    """
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    document = json.loads(data_path.read_text(encoding="utf-8"))

    if isinstance(document, dict) and "records" in document:
        records = document["records"]
    elif isinstance(document, dict) and "cases" in document:
        records = [case.get("record", {}) for case in document["cases"]]
    elif isinstance(document, list):
        records = document
    else:
        records = [document]

    try:
        import jsonschema
    except ImportError:
        print("jsonschema not installed; falling back to a structural check")
        return _structural_check(records, schema)

    validator = jsonschema.Draft202012Validator(schema)
    failures = 0

    for index, record in enumerate(records):
        for error in sorted(validator.iter_errors(record), key=lambda e: list(e.path)):
            failures += 1
            where = "/".join(str(part) for part in error.path) or "(record)"
            print(f"record {index}: {where}: {error.message}")

    if failures:
        print(f"\n{failures} validation failure(s) across {len(records)} record(s)")
        return 1

    print(f"OK: {len(records)} record(s) validate against {schema_path.name}")
    return 0


def _structural_check(records: list[Any], schema: dict[str, Any]) -> int:
    """
    Required fields, unknown fields and enum membership, without jsonschema.

    Deliberately not a reimplementation of JSON Schema. It covers the three
    kinds of mistake that actually happen in a hand-edited data file, and says
    so rather than implying full validation.
    """
    required = schema.get("required", [])
    properties = schema.get("properties", {})
    failures = 0

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            print(f"record {index}: not an object")
            failures += 1
            continue

        for field in required:
            if field not in record:
                print(f"record {index}: missing required field {field!r}")
                failures += 1

        for field, value in record.items():
            spec = properties.get(field)

            if spec is None:
                print(f"record {index}: unknown field {field!r}")
                failures += 1
                continue

            allowed = spec.get("enum")

            if allowed is not None and value not in allowed:
                print(
                    f"record {index}: {field}={value!r} is not one of "
                    f"{', '.join(map(str, allowed))}"
                )
                failures += 1

    if failures:
        print(f"\n{failures} structural failure(s) across {len(records)} record(s)")
        return 1

    print(
        f"OK: {len(records)} record(s) pass the structural check "
        "(required fields, unknown fields, enum membership)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate or check the ingestion JSON Schemas.",
        epilog="Run from the repository root.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate the schema files instead of checking them",
    )
    parser.add_argument(
        "--data",
        type=Path,
        help="validate this data file instead of checking the schemas",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        help="the schema to validate --data against",
    )
    args = parser.parse_args()

    if args.data or args.schema:
        if not (args.data and args.schema):
            parser.error("--data and --schema go together")
        if not args.data.exists():
            parser.error(f"no such file: {args.data}")
        if not args.schema.exists():
            parser.error(f"no such file: {args.schema}")

        return validate_data(args.data, args.schema)

    schemas = build_schemas(load_vocabularies())

    return write_schemas(schemas) if args.write else check_schemas(schemas)


if __name__ == "__main__":
    raise SystemExit(main())
