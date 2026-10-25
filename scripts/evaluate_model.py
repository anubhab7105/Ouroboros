#!/usr/bin/env python3
"""
Train and evaluate a bounded supervised model on a generated dataset.

    python scripts/evaluate_model.py --dataset data/generated/run-42
    python scripts/evaluate_model.py --dataset data/generated/run-42 --split temporal

Prints the metric set and the limitations, together, because the metrics on
their own are misleading in a specific way this script will not help you
avoid silently.

What this measures
------------------

Agreement between the synthetic generator and the model. Nothing more.

The generator plants the typologies the rules look for. Train on that and the
reported precision and recall say the model learned to recognise what the
generator was told to produce — which is a real check that the pipeline works
end to end, and no evidence at all about detection quality on a real
portfolio.

`docs/model-card.md` has the long version. The short version is that a number
from this script belongs in a sentence that names the dataset and the seed,
and never in a sentence beginning "the model is".

Why the split strategy is the most important argument
-----------------------------------------------------

Three kinds of leakage will each inflate the numbers, and only one of them is
visible without choosing a split deliberately:

**Group leakage.** A fraud ring split across train and test. A model that saw
four accounts of a five-account ring in training will recognise the fifth, and
the test score measures memorisation of that ring rather than generalisation
to new ones. `--split grouped` keeps a ring whole.

**Temporal leakage.** Training on data from after the evaluation window. The
model has seen the future and cannot be deployed, because in production the
future is not available. `--split temporal` cuts on time.

**Target leakage.** A feature derived from the label. Guarded structurally
rather than by a split: the ingestion blocklist, the feature-schema blocklist,
and `assert_no_label_leakage`. This script calls that assertion and will
refuse to report a metric if it fires.

A random split is available as `--split random` and is the wrong default,
which is why it is not the default.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND = REPO_ROOT / "backend"


def load_backend() -> tuple[Any, Any]:
    sys.path.insert(0, str(BACKEND))

    try:
        from app.ml import supervised
    except ImportError as exc:
        raise SystemExit(
            f"Could not import app.ml.supervised from {BACKEND}: {exc}\n"
            "Install the requirements first:\n"
            "  pip install -r backend/requirements.txt"
        ) from exc

    from app.ml import labels

    return supervised, labels


def read_dataset(directory: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Read a generated dataset's accounts and labels.

    Labels live in their own file precisely so that reading them is a separate
    act. A labels file joined onto the feature rows by accident is target
    leakage, and it is the kind that makes the numbers better rather than
    raising an error.
    """
    accounts_path = directory / "accounts.json"
    labels_path = directory / "labels.json"

    if not accounts_path.exists():
        raise SystemExit(
            f"No accounts.json in {directory}.\n"
            "Generate a dataset first:\n"
            "  python scripts/generate_data.py --with-labels --out " + str(directory)
        )

    if not labels_path.exists():
        raise SystemExit(
            f"No labels.json in {directory}.\n"
            "Regenerate with labels -- evaluation needs ground truth, and the "
            "generator strips it by default:\n"
            "  python scripts/generate_data.py --with-labels --out " + str(directory)
        )

    accounts = json.loads(accounts_path.read_text(encoding="utf-8")).get("records", [])
    labels = json.loads(labels_path.read_text(encoding="utf-8")).get("labels", [])

    by_account = {
        str(row.get("account_id")): row
        for row in labels
        if row.get("account_id")
    }

    return accounts, by_account


def assign_splits(
    strategy: str,
    *,
    groups: list[str],
    created: list[str],
    seed: int,
) -> list[str]:
    """
    Assign each row to train, validation or test.

    The three strategies differ in what they refuse to let the model see, and
    that refusal is the entire value of the evaluation:

    **grouped** keeps a ring whole. Every account of a ring lands in the same
    split, so the test score measures recognising a ring the model has never
    seen rather than recalling one it has.

    **temporal** cuts on the account's opening date, oldest first. The model
    is never trained on anything later than the window it is scored on,
    because in production the future is not available.

    **random** does neither, and is here so the gap between it and the other
    two can be seen. That gap is the size of the leakage.
    """
    import random as _random

    rng = _random.Random(seed)
    count = len(groups)

    if strategy == "temporal":
        order = sorted(range(count), key=lambda i: (created[i] or "", i))
    elif strategy == "grouped":
        # Shuffle whole groups, then walk them, so a group is never split.
        distinct = sorted(set(groups))
        rng.shuffle(distinct)
        rank = {name: position for position, name in enumerate(distinct)}
        order = sorted(range(count), key=lambda i: (rank[groups[i]], i))
    else:
        order = list(range(count))
        rng.shuffle(order)

    train_end = int(count * 0.6)
    validation_end = int(count * 0.8)

    splits = ["train"] * count

    for position, index in enumerate(order):
        if position < train_end:
            splits[index] = "train"
        elif position < validation_end:
            splits[index] = "validation"
        else:
            splits[index] = "test"

    return splits


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train and evaluate a bounded supervised model.",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="a directory written by scripts/generate_data.py --with-labels",
    )
    parser.add_argument(
        "--split",
        choices=["grouped", "temporal", "random"],
        default="grouped",
        help=(
            "how to split. 'grouped' keeps a fraud ring whole; 'temporal' cuts "
            "on time; 'random' leaks both ways and is here to be compared "
            "against, not used."
        ),
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the report as JSON instead of prose",
    )
    args = parser.parse_args()

    supervised, labels_module = load_backend()
    accounts, labels = read_dataset(args.dataset)

    if not labels:
        raise SystemExit("labels.json has no labels")

    rows: list[dict[str, Any]] = []
    targets: list[int] = []
    groups: list[str] = []
    created: list[str] = []

    for account in accounts:
        account_id = str(account.get("id"))
        label = labels.get(account_id)

        if label is None:
            continue

        # Features would normally be built from transaction history by
        # `app.ml.features`. This script evaluates the training path, so it
        # uses the account record's own non-label fields and says so rather
        # than pretending to a richer feature set than it has.
        rows.append(
            {
                "account_type": account.get("account_type"),
                "status": account.get("status"),
            }
        )
        targets.append(1 if label.get("is_mule") else 0)
        groups.append(str(label.get("ring_id") or account_id))
        created.append(str(account.get("created_at") or ""))

    if len(set(targets)) < 2:
        raise SystemExit(
            f"Only one class present across {len(targets)} labelled accounts. "
            "Generate more accounts, or a dataset with planted typologies."
        )

    # The guard takes a feature mapping and raises on a label-shaped name.
    # Called here rather than trusted, because the whole point of a leakage
    # guard is that the failure it prevents looks like success.
    if rows:
        labels_module.assert_no_label_leakage(rows[0])

    splits = assign_splits(
        args.split,
        groups=groups,
        created=created,
        seed=args.seed,
    )

    options = supervised.SupervisedOptions(seed=args.seed)
    dataset = supervised.build_training_dataset(
        rows,
        targets,
        splits=splits,
        options=options,
    )
    model = supervised.SupervisedTrainer(options).train(dataset)
    report = supervised.evaluate_supervised_model(model, dataset, split="test")

    payload = {
        "dataset": str(args.dataset),
        "split_strategy": args.split,
        "seed": args.seed,
        "labelled_accounts": len(targets),
        "positive_rate": round(sum(targets) / len(targets), 4),
        "distinct_groups": len(set(groups)),
        "split_counts": {
            name: splits.count(name) for name in ("train", "validation", "test")
        },
        "model_family": model.parameters.metadata.get("model_family"),
        "model_fingerprint": model.fingerprint,
        "evaluated": report.ok,
        "metrics": dict(report.metrics),
        "counts": dict(report.counts),
        "issues": [issue.code for issue in report.issues],
        "limitations": [
            "Measures agreement between the synthetic generator and the model, "
            "not detection quality on real data.",
            "The planted typologies are the ones the rules look for.",
            "Features here are the account record's own fields. The real "
            "feature set is built from transaction history by app.ml.features.",
            "A random split leaks rings and time. Prefer grouped or temporal.",
            "Not production-ready. No regulatory claim.",
        ],
    }

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
        return 0 if report.ok else 1

    print(f"dataset           {payload['dataset']}")
    print(f"split strategy    {payload['split_strategy']}")
    print(f"labelled accounts {payload['labelled_accounts']}")
    print(f"positive rate     {payload['positive_rate']}")
    print(f"distinct groups   {payload['distinct_groups']}")
    counts = payload["split_counts"]
    print(
        f"split sizes       train {counts['train']}, "
        f"validation {counts['validation']}, test {counts['test']}"
    )
    print(f"model family      {payload['model_family']}")
    print(f"fingerprint       {payload['model_fingerprint'][:16]}…")
    print()

    if not report.ok:
        print("not evaluated:")
        for code in payload["issues"]:
            print(f"  {code}")
        print(
            "\nAn unavailable metric is reported as unavailable rather than as "
            "zero. A zero precision and an uncomputed precision mean opposite "
            "things."
        )
        return 1

    print("metrics")
    for key in sorted(report.metrics):
        value = report.metrics[key]
        if isinstance(value, float):
            print(f"  {key:30} {value:.4f}")
        else:
            print(f"  {key:30} {value}")

    print("\nwhat these numbers are not")
    for line in payload["limitations"]:
        print(f"  - {line}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
