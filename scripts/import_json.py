#!/usr/bin/env python3
"""
Load JSON batch files into a running MULEGUARD backend, in the right order.

    python scripts/import_json.py --dir data/samples
    python scripts/import_json.py --dir data/generated/run-42 --base-url http://localhost:8000
    python scripts/import_json.py --dir data/samples --dry-run

Why a script rather than five curl calls
----------------------------------------

Three reasons, and the third is the one that matters.

**Order.** The ingestion endpoints enforce referential integrity instead of
creating records implicitly, so accounts and entities have to exist before
transactions and links refer to them. Get it wrong and you get a wall of
foreign-key rejections that look like bad data.

**Authentication.** Ingestion is admin-only. The script logs in once and
reuses the token.

**Reading the result.** Every endpoint returns four disjoint counts whose sum
must equal the number of records submitted. A partial load — some accepted,
some rejected — returns HTTP 201 with `ok: false`, so a caller checking only
the status code treats a half-loaded batch as a success. This script checks
the arithmetic, prints the rejected rows with their indices, and exits
non-zero if anything was refused.

Credentials
-----------

Read from the environment, never from the command line, so they do not end up
in a shell history file:

    MULEGUARD_ADMIN_USER      default: admin
    MULEGUARD_ADMIN_PASSWORD  required
    MULEGUARD_BASE_URL        default: http://localhost:8000

Uses only the standard library, so it runs with no dependencies installed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "http://localhost:8000"

#: (filename stem, endpoint path). The order is the dependency order.
LOAD_ORDER: list[tuple[str, str]] = [
    ("accounts", "accounts"),
    ("entities", "entities"),
    ("transactions", "transactions"),
    ("entity-links", "entity-links"),
    ("complaints", "complaints"),
]

#: Filenames to try for each stem, so one script reads both directories.
NAME_PATTERNS = ["{stem}.json", "{stem}.sample.json"]


def post(
    url: str,
    payload: dict[str, Any],
    *,
    token: str | None = None,
    timeout: float = 120.0,
) -> tuple[int, dict[str, Any]]:
    """
    POST JSON and return (status, decoded body).

    An HTTP error is returned rather than raised, because a 4xx from this API
    carries the error envelope and that envelope is the useful part.
    """
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")

    if token:
        request.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        raw = error.read()

        try:
            return error.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return error.code, {"message": raw.decode("utf-8", "replace")[:500]}
    except urllib.error.URLError as error:
        raise SystemExit(
            f"Could not reach {url}: {error.reason}\n"
            "Is the backend running? Try: scripts/run_backend_dev.sh"
        ) from error


def log_in(base_url: str) -> str:
    user = os.environ.get("MULEGUARD_ADMIN_USER", "admin")
    password = os.environ.get("MULEGUARD_ADMIN_PASSWORD")

    if not password:
        raise SystemExit(
            "MULEGUARD_ADMIN_PASSWORD is not set.\n"
            "Ingestion is admin-only. Set it in your shell rather than passing "
            "it as an argument, so it stays out of your shell history:\n"
            "  export MULEGUARD_ADMIN_PASSWORD='...'"
        )

    status, body = post(
        f"{base_url}/api/v1/auth/login",
        {"identifier": user, "password": password},
    )

    if status != 200 or "access_token" not in body:
        message = body.get("message") or body.get("code") or "unknown error"
        hint = ""

        # A 401 here has two quite different causes and the API deliberately
        # will not say which: "Invalid username or password" is the correct
        # response whether the password is wrong or the account does not
        # exist, because distinguishing them tells an attacker which usernames
        # are real.
        #
        # That is right for the API and unhelpful at a terminal, where the
        # overwhelmingly common cause is an empty users table -- the accounts
        # live in the database, so `reset_demo` drops them along with
        # everything else. Naming both possibilities costs nothing here and
        # reveals nothing to anyone who is not already running the script.
        if status == 401:
            hint = (
                "\n\nEither the password is wrong, or the user does not exist. "
                "The API cannot tell you which, by design.\n"
                "Development accounts live in the database, so a reset removes "
                "them. If you have just run reset_demo:\n"
                "  python scripts/create_dev_users.py"
            )

        raise SystemExit(f"Login failed for {user!r}: {status} {message}{hint}")

    return str(body["access_token"])


def find_file(directory: Path, stem: str) -> Path | None:
    for pattern in NAME_PATTERNS:
        candidate = directory / pattern.format(stem=stem)

        if candidate.exists():
            return candidate

    return None


def report(name: str, status: int, body: dict[str, Any], submitted: int) -> bool:
    """
    Print one batch's outcome and return True when everything was accepted.
    """
    accepted = int(body.get("accepted", 0))
    rejected = int(body.get("rejected", 0))
    duplicated = int(body.get("duplicated", 0))
    skipped = int(body.get("skipped", 0))

    if status >= 400:
        print(
            f"  {name:16} HTTP {status}: "
            f"{body.get('code', '')} {body.get('message', '')}"
        )

        details = body.get("details") or {}
        for field, problem in list(details.items())[:5]:
            print(f"      {field}: {problem}")

        return False

    print(
        f"  {name:16} accepted {accepted:>6}  rejected {rejected:>5}  "
        f"duplicated {duplicated:>5}  skipped {skipped:>5}"
    )

    # `skipped` is a SUB-COUNT of `duplicated`, not a fourth disjoint bucket.
    # `_duplicate_handling` in the ingestion endpoint increments `duplicated`
    # for every duplicate and then additionally increments `skipped` when
    # on_duplicate=skip. So the partition of submitted rows is:
    #
    #     submitted == accepted + rejected + duplicated
    #
    # with `skipped` describing what was DONE with the duplicates. Summing all
    # four double-counted every skipped duplicate: a clean re-run of an
    # already-loaded file reported "14 accounted for, 7 submitted" and then
    # declared the batch failed, which aborted the caller before the analysis
    # pass. The arithmetic was wrong, not the ingestion.
    accounted = accepted + rejected + duplicated

    if accounted != submitted:
        print(
            f"      counts do not add up: {accounted} accounted for, "
            f"{submitted} submitted"
        )
        return False

    if skipped > duplicated:
        print(
            f"      more rows skipped ({skipped}) than duplicates found "
            f"({duplicated}); the server's counters disagree with each other"
        )
        return False

    for error in (body.get("errors") or [])[:10]:
        where = f" ({error['field']})" if error.get("field") else ""
        print(f"      record {error.get('index')}{where}: {error.get('message')}")

    remaining = len(body.get("errors") or []) - 10
    if remaining > 0:
        print(f"      ... and {remaining} more")

    return rejected == 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Load JSON batch files into a running backend, in order.",
    )
    parser.add_argument(
        "--dir",
        type=Path,
        required=True,
        help="directory holding the batch files",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("MULEGUARD_BASE_URL", DEFAULT_BASE_URL),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "validate without writing. The API does the validation, so this "
            "exercises the real rules rather than a local approximation."
        ),
    )
    parser.add_argument(
        "--on-duplicate",
        choices=["reject", "skip"],
        default="skip",
        help=(
            "what to do with a record that already exists. 'skip' by default, "
            "so re-running the same file is a no-op rather than an error."
        ),
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="stop at the first batch with rejections instead of continuing",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1000,
        help=(
            "records per request (default 1000). The server refuses a batch "
            "over INGESTION_MAX_BATCH_SIZE, which defaults to 1000 in code "
            "and 5000 in .env.example, so the default here is safe against "
            "both."
        ),
    )
    args = parser.parse_args()

    if not args.dir.is_dir():
        raise SystemExit(f"Not a directory: {args.dir}")

    base_url = args.base_url.rstrip("/")
    token = log_in(base_url)

    print(f"loading {args.dir} into {base_url}")

    if args.dry_run:
        print("dry run: nothing will be written\n")

    all_clean = True
    loaded_any = False

    for stem, endpoint in LOAD_ORDER:
        path = find_file(args.dir, stem)

        if path is None:
            print(f"  {stem:16} (no file, skipped)")
            continue

        document = json.loads(path.read_text(encoding="utf-8"))

        if isinstance(document, list):
            document = {"records": document}

        records = document.get("records") or []

        if not records:
            print(f"  {stem:16} (no records, skipped)")
            continue

        options = dict(document.get("options") or {})
        options["dry_run"] = args.dry_run
        options["on_duplicate"] = args.on_duplicate
        options.setdefault("source_system", "import_json")

        # Posted in chunks, because the API bounds a single batch.
        #
        # INGESTION_MAX_BATCH_SIZE defaults to 1000 in code and is set to 5000
        # in .env.example, and a batch over the limit is refused outright:
        #
        #     Ingestion batch exceeds configured maximum.
        #
        # A generated dataset passes that easily -- `seed_demo -Generate 500`
        # produces 20,000 transactions -- so posting a file as one request
        # worked for the committed samples and failed for anything realistic.
        # Chunking here rather than raising the server's limit keeps the bound
        # doing its job: it exists so one request cannot pin the database for
        # an unbounded stretch.
        #
        # Each chunk is its own transaction, so an interrupted load can leave
        # part of a file applied. That is why `--on-duplicate skip` is the
        # default: re-running the same file finishes the job instead of
        # colliding with what already landed.
        totals = {"accepted": 0, "rejected": 0, "duplicated": 0, "skipped": 0}
        errors: list[dict[str, Any]] = []
        status = 200
        body: dict[str, Any] = {}
        chunks = [
            records[index : index + args.chunk_size]
            for index in range(0, len(records), args.chunk_size)
        ]

        for number, chunk in enumerate(chunks, start=1):
            if len(chunks) > 1:
                print(
                    f"  {stem:16} chunk {number}/{len(chunks)} "
                    f"({len(chunk)} records)...",
                    end="\r",
                )

            status, body = post(
                f"{base_url}/api/v1/ingestion/{endpoint}",
                {"records": chunk, "options": options},
                token=token,
            )

            if status >= 400:
                break

            for key in totals:
                totals[key] += int(body.get(key, 0))

            errors.extend(body.get("errors") or [])

        if len(chunks) > 1:
            print(" " * 60, end="\r")

        if status < 400:
            body = {**body, **totals, "errors": errors}

        clean = report(stem, status, body, len(records))
        all_clean = all_clean and clean
        loaded_any = True

        if not clean and args.stop_on_error:
            print("\nstopping at the first failure (--stop-on-error)")
            return 1

    if not loaded_any:
        print(f"\nNothing to load. Expected files named like: {NAME_PATTERNS[0]}")
        return 1

    if all_clean:
        # Re-running an already-loaded directory is a normal thing to do and
        # lands here with every record counted as a duplicate, so the summary
        # says "no records refused" rather than "accepted". Nothing was
        # written, and nothing was wrong.
        print(
            "\nno records refused" + (" (dry run)" if args.dry_run else "")
        )
        return 0

    print(
        "\nsome records were refused. The indices above are positions in the "
        "submitted array, so you can fix the file rather than bisect it."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
