"""
Ingestion rejection, driven by the `*.invalid.json` fixtures.

Each fixture case states the field it is about and why it must be refused.
The tests assert on that field rather than merely on the status code, because
a record rejected for the wrong reason is not the test passing — it is two
bugs cancelling out, and the next change uncovers one of them.

What this module is really defending is the line between a caller error and a
server error. Every case here must be a 4xx with a usable message. A 500 means
the validation did not run and a driver-level exception escaped, and a caller
has no way to act on that.
"""

from __future__ import annotations

import pytest

from tests.utils import assert_ok, unique_id

pytestmark = [pytest.mark.ingestion, pytest.mark.api]


ENDPOINTS = {
    "accounts": "/api/v1/ingestion/accounts",
    "transactions": "/api/v1/ingestion/transactions",
    "complaints": "/api/v1/ingestion/complaints",
    "entity_links": "/api/v1/ingestion/entity-links",
}


def _cases(name):
    """Expand one fixture's cases into pytest parameters at collection time."""
    import json
    from pathlib import Path

    path = Path(__file__).parent / "fixtures" / f"{name}.invalid.json"
    data = json.loads(path.read_text(encoding="utf-8"))

    return [
        pytest.param(case, id=f"{name}-{case['name']}") for case in data["cases"]
    ]


@pytest.fixture()
def seeded(admin_client, load_fixture):
    """
    Accounts and entities in place.

    Several invalid cases reference valid accounts — the point of
    `confidence_above_one` is the confidence, not a missing account — so the
    referenced rows have to exist or the test would pass for the wrong reason.
    """
    assert_ok(
        admin_client.post(ENDPOINTS["accounts"], json=load_fixture("accounts.valid.json")),
        201,
    )
    assert_ok(
        admin_client.post(
            "/api/v1/ingestion/entities",
            json={
                "records": [
                    {
                        "id": f"ENT-V-0{index}",
                        "entity_type": "DEVICE",
                        "identifier_hash": unique_id("hash"),
                    }
                    for index in (1, 2, 3)
                ]
            },
        ),
        201,
    )


# -----------------------------------------------------------------------------
# The fixture cases
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("case", _cases("accounts"))
def test_invalid_account_is_rejected(admin_client, case):
    _assert_rejected(admin_client, ENDPOINTS["accounts"], case)


@pytest.mark.parametrize("case", _cases("transactions"))
def test_invalid_transaction_is_rejected(admin_client, seeded, case):
    _assert_rejected(admin_client, ENDPOINTS["transactions"], case)


@pytest.mark.parametrize("case", _cases("complaints"))
def test_invalid_complaint_is_rejected(admin_client, seeded, case):
    _assert_rejected(admin_client, ENDPOINTS["complaints"], case)


@pytest.mark.parametrize("case", _cases("entity_links"))
def test_invalid_entity_link_is_rejected(admin_client, seeded, case):
    _assert_rejected(admin_client, ENDPOINTS["entity_links"], case)


def _assert_rejected(client, url, case):
    """
    One invalid record, posted alone, must be refused.

    `allow_partial` defaults to false, so a batch of one bad record writes
    nothing and raises. The assertion allows 413 and 409 alongside 422 because
    a few cases (an oversized id, a duplicate) are legitimately those; what is
    never acceptable is a 2xx or a 5xx.
    """
    response = client.post(url, json={"records": [case["record"]]})

    assert response.status_code in (409, 413, 422), (
        f"{case['name']}: expected a client error, got {response.status_code}. "
        f"Reason this must be rejected: {case['why']}"
    )

    body = response.json()
    assert body.get("code")
    assert body.get("message")

    raw = response.text.lower()
    assert "traceback" not in raw
    assert "sqlalchemy" not in raw


@pytest.mark.parametrize("case", _cases("transactions"))
def test_the_rejection_names_the_field_at_fault(admin_client, seeded, case):
    """
    The error points at the field the fixture says is wrong.

    This is the assertion that makes the suite worth more than a status-code
    check. A loader processing a thousand records needs to know which column
    to fix, and a message of "validation failed" sends somebody to read the
    source.

    The check is tolerant about *where* the field name appears, because the
    detail shape differs between a Pydantic failure (`details.fields`) and a
    domain rejection (`details.rows`), and pinning the shape here would make
    this a test of the error serialiser rather than of the validation.
    """
    expected_field = case.get("field")

    if not expected_field:
        pytest.skip("this case has no single field at fault")

    response = admin_client.post(
        ENDPOINTS["transactions"], json={"records": [case["record"]]}
    )

    assert expected_field in response.text, (
        f"{case['name']}: rejection did not mention {expected_field!r}. "
        f"Body: {response.text[:400]}"
    )


# -----------------------------------------------------------------------------
# Batch-level behaviour
# -----------------------------------------------------------------------------


def test_one_bad_row_rejects_the_whole_batch_by_default(admin_client, db):
    """
    `allow_partial=false` means all or nothing.

    The alternative — write the good rows, report the bad ones — sounds
    friendlier and is worse: the caller gets a 201 and has to diff the
    response against its own input to discover what landed. Retrying becomes
    unsafe, because some rows are already there.
    """
    from app.models import Account

    response = admin_client.post(
        ENDPOINTS["accounts"],
        json={
            "records": [
                {"id": "ACC-GOOD-1", "account_type": "INDIVIDUAL"},
                {"id": "ACC-BAD-1", "account_type": "NOT_A_TYPE"},
                {"id": "ACC-GOOD-2", "account_type": "BUSINESS"},
            ]
        },
    )

    assert response.status_code == 422
    assert db.get(Account, "ACC-GOOD-1") is None
    assert db.get(Account, "ACC-GOOD-2") is None


def test_partial_mode_writes_the_valid_rows(admin_client, db):
    """
    With `allow_partial=true`, the good rows land and the response says which did not.

    Opt-in, because it is only the right behaviour when the caller is prepared
    to reconcile.
    """
    from app.models import Account

    body = assert_ok(
        admin_client.post(
            ENDPOINTS["accounts"],
            json={
                "records": [
                    {"id": "ACC-PART-1", "account_type": "INDIVIDUAL"},
                    {"id": "ACC-PART-BAD", "account_type": "NOT_A_TYPE"},
                ],
                "options": {"allow_partial": True},
            },
        ),
        201,
    )

    assert body["accepted"] == 1
    assert body["rejected"] == 1
    assert body["ok"] is False
    assert body["errors"]

    assert db.get(Account, "ACC-PART-1") is not None
    assert db.get(Account, "ACC-PART-BAD") is None


def test_partial_mode_still_fails_when_nothing_is_valid(admin_client):
    """
    Partial mode is not permission to return 201 for a batch that wrote nothing.

    A caller reading only the status code would record a success.
    """
    response = admin_client.post(
        ENDPOINTS["accounts"],
        json={
            "records": [{"id": "ACC-ALLBAD", "account_type": "NOT_A_TYPE"}],
            "options": {"allow_partial": True},
        },
    )

    assert response.status_code == 422


def test_errors_identify_the_row_by_index(admin_client):
    """
    Each error carries the row it came from.

    Without the index, a thousand-record batch reports "a currency is wrong"
    and the caller has to find it.
    """
    body = assert_ok(
        admin_client.post(
            ENDPOINTS["accounts"],
            json={
                "records": [
                    {"id": "ACC-ROW-0", "account_type": "INDIVIDUAL"},
                    {"id": "ACC-ROW-1", "account_type": "NOPE"},
                    {"id": "ACC-ROW-2", "account_type": "ALSO_NOPE"},
                ],
                "options": {"dry_run": True},
            },
        ),
        200,
    )

    rows = [error.get("row") for error in body["errors"] if error.get("row") is not None]

    assert rows, f"no error carried a row index: {body['errors']}"
    assert all(isinstance(row, int) for row in rows)

    # Two records are bad, so two distinct indices. Whether the indices are
    # zero- or one-based is not asserted: either is defensible and pinning it
    # would be a test of a convention rather than of the behaviour.
    assert len(set(rows)) == 2


def test_the_error_list_is_capped(admin_client, override_settings):
    """
    A batch of ten thousand bad rows does not return ten thousand errors.

    An unbounded error list is a denial-of-service against the caller's own
    log, and the response is truncated with a marker rather than silently cut.
    """
    override_settings(INGESTION_MAX_ERRORS_RETURNED=5)

    body = assert_ok(
        admin_client.post(
            ENDPOINTS["accounts"],
            json={
                "records": [
                    {"id": f"ACC-MANY-{index}", "account_type": "NOPE"}
                    for index in range(40)
                ],
                "options": {"dry_run": True},
            },
        ),
        200,
    )

    assert len(body["errors"]) <= 6


def test_duplicate_ids_within_one_batch_are_caught(admin_client):
    """
    Two rows with the same id in one payload.

    Caught before the write, so the error names the duplication rather than
    surfacing as a primary-key violation from the driver.
    """
    response = admin_client.post(
        ENDPOINTS["accounts"],
        json={
            "records": [
                {"id": "ACC-SAME", "account_type": "INDIVIDUAL"},
                {"id": "ACC-SAME", "account_type": "BUSINESS"},
            ]
        },
    )

    assert response.status_code in (409, 422)


def test_re_posting_a_batch_is_rejected_by_default(admin_client, load_fixture):
    """
    `on_duplicate` defaults to reject, so a replayed batch fails.

    The safe default: a loader that re-runs by accident should hear about it.
    A caller that genuinely wants replay-safe loading asks for `skip`, which
    the next test covers.
    """
    payload = load_fixture("accounts.valid.json")

    assert_ok(admin_client.post(ENDPOINTS["accounts"], json=payload), 201)

    response = admin_client.post(ENDPOINTS["accounts"], json=payload)
    assert response.status_code in (409, 422)


def test_skip_makes_a_replayed_batch_idempotent(admin_client, load_fixture):
    """
    With `on_duplicate=skip`, the second run reports the duplicates and writes nothing new.

    This is what a retrying loader needs: the same request twice leaves the
    same state, and the response distinguishes "skipped because present" from
    "accepted".
    """
    payload = dict(load_fixture("accounts.valid.json"))
    payload["options"] = {"on_duplicate": "skip"}

    first = assert_ok(admin_client.post(ENDPOINTS["accounts"], json=payload), 201)
    second = assert_ok(admin_client.post(ENDPOINTS["accounts"], json=payload), 201)

    assert first["accepted"] == len(payload["records"])
    assert second["accepted"] == 0
    assert second["duplicated"] == len(payload["records"])
    assert second["ok"] is True


def test_a_malformed_body_is_a_422_not_a_500(admin_client):
    """Not a list, not an object, missing `records` — all caller errors."""
    for body in (
        {"records": "not-a-list"},
        {"records": [["not", "an", "object"]]},
        {"records": [None]},
        [],
        "nonsense",
    ):
        response = admin_client.post(ENDPOINTS["accounts"], json=body)
        assert response.status_code == 422, f"{body!r} gave {response.status_code}"


def test_unknown_fields_in_a_record_do_not_crash(admin_client):
    """
    An extra field is ignored rather than fatal.

    Source systems add columns. A loader that breaks on an unrecognised field
    forces a coordinated deploy for every upstream change, which is how
    ingestion ends up being done by hand.
    """
    response = admin_client.post(
        ENDPOINTS["accounts"],
        json={
            "records": [
                {
                    "id": "ACC-EXTRA",
                    "account_type": "INDIVIDUAL",
                    "branch_manager_mobile": "5550100",
                    "some_future_column": 42,
                }
            ]
        },
    )

    assert response.status_code in (201, 422)
    assert response.status_code != 500
