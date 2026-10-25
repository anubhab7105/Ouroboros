#!/usr/bin/env python3
"""
Generate a synthetic MULEGUARD dataset and write it as ingestible batch files.

    python scripts/generate_data.py --accounts 500 --transactions 20000 \
                                    --seed 42 --out data/generated/run-42

Writes five files, named so that loading them in alphabetical order would be
wrong, and prints the order to use. Referential integrity is enforced by the
ingestion API rather than assumed, so accounts and entities have to exist
before anything refers to them:

    accounts → entities → transactions → entity-links → complaints

What the output is good for
---------------------------

Filling a demo database with a portfolio in which every detection rule has
something to find and several things it should ignore. Roughly 95% of what it
generates is ordinary activity, because a dataset consisting mostly of
typologies is one on which anything scores well.

What it is not good for: measuring whether detection works. The planted
typologies are the ones the rules look for, so a metric computed on this data
measures agreement between the generator and the rules, not detection quality.
`docs/model-card.md` is blunter about it.

Ground truth
------------

The generator plants `ground_truth_label`, `scenario_type` and `ring_id` on
every account it generates, because precision and recall cannot be computed
without them. The ingestion API refuses those fields, so by default they are
stripped from what this script writes.

`--with-labels` keeps them in a separate `labels.json` rather than on the
records, which is the only shape in which they are safe to have on disk: a
label sitting on an account record is one careless join away from being a
feature, and a model trained on a feature derived from its own label scores
perfectly in evaluation and uselessly in production.

Determinism
-----------

Same seed, same dataset, including timestamps: the generator's activity window
is a fixed pair of dates rather than an offset from now. `--from-date` and
`--to-date` move the window if you want the data to look recent, and the
manifest records whichever window was used so a dataset can be reproduced
rather than approximated.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND = REPO_ROOT / "backend"

#: The order the ingestion API will accept these in.
LOAD_ORDER = [
    ("accounts", "accounts.json"),
    ("entities", "entities.json"),
    ("transactions", "transactions.json"),
    ("entity-links", "entity-links.json"),
    ("complaints", "complaints.json"),
]

#: Fields the ingestion API refuses. Stripped here so the output is loadable.
#:
#: The generator does not put these on its records -- ground truth travels in
#: `dataset.labels` instead -- so this is a belt-and-braces strip rather than
#: the mechanism. It stays because a future change to the generator that
#: started emitting one of them would otherwise produce files that fail to
#: load, with the cause three modules away.
LABEL_FIELDS = (
    "ground_truth_label",
    "ground_truth",
    "scenario_type",
    "scenario_id",
    "ring_id",
    "profile",
)


def load_generator() -> Any:
    sys.path.insert(0, str(BACKEND))

    try:
        from app.ingestion import generator
    except ImportError as exc:
        raise SystemExit(
            f"Could not import app.ingestion.generator from {BACKEND}: {exc}\n"
            "Install the backend requirements first:\n"
            "  pip install -r backend/requirements.txt"
        ) from exc

    return generator


def split_labels(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Separate label fields from records, returning (clean records, labels).

    The labels keep the account id so they can be joined back for evaluation,
    and nothing else, so that a labels file cannot accidentally become a
    feature source.
    """
    clean: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []

    for record in records:
        label = {
            field: record[field] for field in LABEL_FIELDS if field in record
        }

        if label:
            label["account_id"] = record.get("id")
            labels.append(label)

        clean.append({k: v for k, v in record.items() if k not in LABEL_FIELDS})

    return clean, labels


def write_batch(
    path: Path,
    records: list[dict[str, Any]],
    *,
    source_batch_id: str,
) -> None:
    payload = {
        "records": records,
        "options": {
            "source_system": "generator",
            "source_batch_id": source_batch_id,
        },
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic dataset as ingestible batch files.",
    )
    parser.add_argument("--accounts", type=int, default=250)
    parser.add_argument("--transactions", type=int, default=8000)
    parser.add_argument("--complaints", type=int, default=120)
    parser.add_argument("--entities", type=int, default=400)
    parser.add_argument("--entity-links", type=int, default=600)
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help=(
            "Same seed, same dataset. A generated dataset is identified by its "
            "seed and the generator version rather than by a committed file."
        ),
    )
    parser.add_argument(
        "--from-date",
        type=str,
        default=None,
        help=(
            "ISO-8601 start of the generated activity window. Defaults to the "
            "generator's own window, which is fixed, so the same seed produces "
            "exactly the same timestamps."
        ),
    )
    parser.add_argument(
        "--to-date",
        type=str,
        default=None,
        help="ISO-8601 end of the generated activity window.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "data" / "generated" / "latest",
        help="output directory (created if absent)",
    )
    parser.add_argument(
        "--with-labels",
        action="store_true",
        help="also write labels.json for offline evaluation",
    )
    args = parser.parse_args()

    generator = load_generator()

    def parse_date(raw: str | None, flag: str) -> datetime | None:
        if not raw:
            return None

        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            parser.error(f"{flag} is not an ISO-8601 timestamp: {raw!r}")

        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    window = {}
    date_start = parse_date(args.from_date, "--from-date")
    date_end = parse_date(args.to_date, "--to-date")

    if date_start:
        window["date_start"] = date_start
    if date_end:
        window["date_end"] = date_end

    if date_start and date_end and date_end <= date_start:
        parser.error("--to-date must be after --from-date")

    policy = generator.GenerationPolicy(
        accounts=args.accounts,
        transactions=args.transactions,
        complaints=args.complaints,
        entities=args.entities,
        entity_links=args.entity_links,
        seed=args.seed,
        **window,
    )

    print(
        f"generating: {args.accounts} accounts, {args.transactions} transactions, "
        f"{args.complaints} complaints, seed {args.seed}"
    )

    dataset = generator.generate_synthetic_dataset(policy=policy)

    args.out.mkdir(parents=True, exist_ok=True)

    collections = {
        "accounts": list(dataset.accounts),
        "entities": list(dataset.entities),
        "transactions": list(dataset.transactions),
        "entity-links": list(dataset.entity_links),
        "complaints": list(dataset.complaints),
    }

    # Ground truth comes from the dataset's own label collection, which the
    # generator keeps apart from the records precisely so that this script has
    # to ask for it.
    all_labels: list[dict[str, Any]] = list(getattr(dataset, "labels", []) or [])

    for name, filename in LOAD_ORDER:
        records = collections[name]
        records, stripped = split_labels(records)

        if stripped:
            # A record carried a label field. Not expected, and worth saying
            # out loud rather than quietly fixing.
            print(
                f"  note: stripped label fields from {len(stripped)} "
                f"{name} record(s)"
            )

        write_batch(
            args.out / filename,
            records,
            source_batch_id=f"generated-{name}-seed{args.seed}",
        )
        print(f"  {filename:22} {len(records):>7} records")

    if args.with_labels and all_labels:
        (args.out / "labels.json").write_text(
            json.dumps(
                {
                    "description": (
                        "Ground truth. NOT ingestible, and not to be joined "
                        "onto a feature row: a model trained on these has "
                        "learned what the generator was told to build rather "
                        "than how to recognise it."
                    ),
                    "labels": all_labels,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        positives = sum(1 for row in all_labels if row.get("is_mule"))
        print(
            f"  {'labels.json':22} {len(all_labels):>7} labels "
            f"({positives} positive, not ingestible)"
        )
    elif all_labels:
        print(
            f"  withheld {len(all_labels)} ground-truth labels "
            "(pass --with-labels to write labels.json)"
        )

    manifest = {
        "generator_version": getattr(generator, "GENERATOR_VERSION", "v1"),
        "seed": args.seed,
        "date_start": policy.date_start.isoformat(),
        "date_end": policy.date_end.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {name: len(records) for name, records in collections.items()},
        "load_order": [name for name, _ in LOAD_ORDER],
        "caveats": [
            "Synthetic data only. Not real customer or bank data.",
            "Planted typologies are the ones the rules look for, so metrics "
            "computed on this dataset measure agreement rather than detection "
            "quality.",
            "Reproduce with the same seed, window and generator version rather "
            "than by keeping these files.",
        ],
    }
    (args.out / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"\nwrote {args.out}")
    print("load in this order:")
    for name, filename in LOAD_ORDER:
        print(f"  POST /api/v1/ingestion/{name}  <  {filename}")
    print("\nor: scripts/seed_demo.sh --from " + str(args.out))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
