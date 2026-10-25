"""
Ingestion atomicity.

`INGESTION_TRANSACTIONAL_BATCH` defaults to true, which means a batch is one
unit: it all lands or none of it does. The tests here are about the *second*
half of that promise — the failure paths — because the success path is already
covered and because a partially-applied batch is the single worst outcome
ingestion can produce.

It is worse than a clean failure for a specific reason. A failed batch can be
retried. A half-applied one cannot: the caller does not know which rows
landed, so a retry either duplicates or, with `on_duplicate=reject`, fails on
rows that succeeded the first time. Recovery then means reconciling by hand
against a dataset nobody can describe.
"""

from __future__ import annotations

import pytest

from app.models import Account, Complaint, Entity, Transaction

from tests.utils import assert_ok, unique_id

pytestmark = [pytest.mark.ingestion, pytest.mark.integration]


ACCOUNTS = "/api/v1/ingestion/accounts"
TRANSACTIONS = "/api/v1/ingestion/transactions"
COMPLAINTS = "/api/v1/ingestion/complaints"
ENTITIES = "/api/v1/ingestion/entities"
LINKS = "/api/v1/ingestion/entity-links"


def _transaction(reference, sender, receiver, **overrides):
    record = {
        "reference": reference,
        "sender_account_id": sender,
        "receiver_account_id": receiver,
        "amount": 10_000,
        "currency": "INR",
        "occurred_at": "2025-11-13T07:12:00Z",
    }
    record.update(overrides)
    return record


@pytest.fixture()
def accounts(admin_client, load_fixture):
    assert_ok(admin_client.post(ACCOUNTS, json=load_fixture("accounts.valid.json")), 201)


# -----------------------------------------------------------------------------
# Rollback
# -----------------------------------------------------------------------------


def test_a_failed_account_batch_writes_nothing(admin_client, db):
    """Twenty good rows and one bad one leave twenty-one rows unwritten."""
    records = [
        {"id": f"ACC-ATOMIC-{index}", "account_type": "INDIVIDUAL"} for index in range(20)
    ]
    records.append({"id": "ACC-ATOMIC-BAD", "account_type": "NOT_A_TYPE"})

    response = admin_client.post(ACCOUNTS, json={"records": records})
    assert response.status_code == 422

    for index in range(20):
        assert db.get(Account, f"ACC-ATOMIC-{index}") is None


def test_a_failed_transaction_batch_writes_nothing(admin_client, db, accounts):
    """
    The bad row is last, so the good ones were already staged.

    Ordering matters here. A validation pass that ran entirely before any
    write would make this test pass trivially; putting the failure at the end
    is what makes it a test of the rollback rather than of the validation
    order.
    """
    records = [
        _transaction(f"TXN-ATOMIC-{index}", "ACC-V-01", "ACC-V-02") for index in range(10)
    ]
    records.append(
        _transaction("TXN-ATOMIC-BAD", "ACC-V-01", "ACC-V-02", currency="RUPEES")
    )

    response = admin_client.post(TRANSACTIONS, json={"records": records})
    assert response.status_code == 422

    written = (
        db.query(Transaction)
        .filter(Transaction.reference.like("TXN-ATOMIC-%"))
        .count()
    )
    assert written == 0


def test_a_referential_failure_rolls_back_the_earlier_rows(admin_client, db, accounts):
    """
    A missing counterparty discovered mid-batch rolls back what came before.

    This is the realistic failure: a transaction feed that arrives slightly
    ahead of the account feed. It has to fail cleanly, because it will happen
    on a schedule.
    """
    records = [
        _transaction("TXN-REF-1", "ACC-V-01", "ACC-V-02"),
        _transaction("TXN-REF-2", "ACC-V-02", "ACC-V-03"),
        _transaction("TXN-REF-3", "ACC-V-03", "ACC-NOT-INGESTED-YET"),
    ]

    response = admin_client.post(TRANSACTIONS, json={"records": records})
    assert response.status_code == 422

    assert db.query(Transaction).filter(Transaction.reference == "TXN-REF-1").count() == 0
    assert db.query(Transaction).filter(Transaction.reference == "TXN-REF-2").count() == 0


def test_a_duplicate_late_in_a_batch_rolls_back_the_rest(admin_client, db, accounts):
    """
    Re-posting one already-present reference fails the whole batch.

    With `on_duplicate=reject` this is the behaviour that makes a retry safe:
    the second attempt changes nothing, so the state after it is the state
    before.
    """
    assert_ok(
        admin_client.post(
            TRANSACTIONS,
            json={"records": [_transaction("TXN-DUP-SEED", "ACC-V-01", "ACC-V-02")]},
        ),
        201,
    )

    records = [
        _transaction("TXN-DUP-NEW-1", "ACC-V-01", "ACC-V-02"),
        _transaction("TXN-DUP-NEW-2", "ACC-V-02", "ACC-V-03"),
        _transaction("TXN-DUP-SEED", "ACC-V-01", "ACC-V-02"),
    ]

    response = admin_client.post(TRANSACTIONS, json={"records": records})
    assert response.status_code in (409, 422)

    assert db.query(Transaction).filter(Transaction.reference == "TXN-DUP-NEW-1").count() == 0
    assert db.query(Transaction).filter(Transaction.reference == "TXN-DUP-NEW-2").count() == 0


def test_a_failed_complaint_batch_writes_nothing(admin_client, db, accounts):
    records = [
        {
            "reference": f"CMP-ATOMIC-{index}",
            "reported_at": "2025-11-14T05:40:00Z",
            "narrative_raw": "Complainant reports an unrecognised debit.",
        }
        for index in range(6)
    ]
    records.append(
        {
            "reference": "CMP-ATOMIC-BAD",
            "reported_at": "2025-11-14T05:40:00Z",
            "narrative_raw": "",
        }
    )

    response = admin_client.post(COMPLAINTS, json={"records": records})
    assert response.status_code == 422

    assert (
        db.query(Complaint).filter(Complaint.reference.like("CMP-ATOMIC-%")).count() == 0
    )


def test_a_failed_entity_batch_writes_nothing(admin_client, db):
    records = [
        {
            "id": f"ENT-ATOMIC-{index}",
            "entity_type": "DEVICE",
            "identifier_hash": unique_id("hash"),
        }
        for index in range(5)
    ]
    records.append(
        {
            "id": "ENT-ATOMIC-BAD",
            "entity_type": "NOT_A_TYPE",
            "identifier_hash": unique_id("hash"),
        }
    )

    response = admin_client.post(ENTITIES, json={"records": records})
    assert response.status_code == 422

    for index in range(5):
        assert db.get(Entity, f"ENT-ATOMIC-{index}") is None


def test_a_failed_link_batch_writes_nothing(admin_client, db, accounts):
    from app.models import AccountEntityLink

    assert_ok(
        admin_client.post(
            ENTITIES,
            json={
                "records": [
                    {
                        "id": "ENT-LINK-1",
                        "entity_type": "DEVICE",
                        "identifier_hash": unique_id("hash"),
                    }
                ]
            },
        ),
        201,
    )

    records = [
        {"account_id": "ACC-V-01", "entity_id": "ENT-LINK-1", "match_method": "EXACT"},
        {"account_id": "ACC-V-02", "entity_id": "ENT-LINK-1", "match_method": "EXACT"},
        # Confidence out of range, so the batch fails after two good rows.
        {
            "account_id": "ACC-V-03",
            "entity_id": "ENT-LINK-1",
            "match_method": "NORMALIZED",
            "confidence": 1.9,
        },
    ]

    response = admin_client.post(LINKS, json={"records": records})
    assert response.status_code == 422

    assert (
        db.query(AccountEntityLink)
        .filter(AccountEntityLink.entity_id == "ENT-LINK-1")
        .count()
        == 0
    )


# -----------------------------------------------------------------------------
# What survives a failure
# -----------------------------------------------------------------------------


def test_a_prior_successful_batch_survives_a_later_failure(admin_client, db):
    """
    Atomicity is per batch, not per session.

    A batch that succeeded is committed and stays committed. If a later
    failure rolled it back, there would be no safe point to resume a load
    from.
    """
    assert_ok(
        admin_client.post(
            ACCOUNTS,
            json={"records": [{"id": "ACC-SURVIVOR", "account_type": "INDIVIDUAL"}]},
        ),
        201,
    )

    admin_client.post(
        ACCOUNTS,
        json={"records": [{"id": "ACC-DOOMED", "account_type": "NOT_A_TYPE"}]},
    )

    assert db.get(Account, "ACC-SURVIVOR") is not None
    assert db.get(Account, "ACC-DOOMED") is None


def test_a_dry_run_leaves_no_trace_even_when_it_passes(admin_client, db):
    """
    A dry run that validates cleanly still writes nothing.

    The obvious half of dry-run behaviour, and the half most likely to break:
    a refactor that moves the `dry_run` check after `db.add` leaves a dry run
    that writes everything and reports that it did not.
    """
    assert_ok(
        admin_client.post(
            ACCOUNTS,
            json={
                "records": [
                    {"id": f"ACC-DRY-{index}", "account_type": "INDIVIDUAL"}
                    for index in range(5)
                ],
                "options": {"dry_run": True},
            },
        ),
        200,
    )

    for index in range(5):
        assert db.get(Account, f"ACC-DRY-{index}") is None


def test_partial_mode_commits_exactly_the_accepted_rows(admin_client, db):
    """
    In partial mode the count in the response matches what is in the database.

    The response is the only record the caller has of what happened, so a
    count that overstates or understates it is worse than no count.
    """
    records = [
        {"id": "ACC-COUNT-1", "account_type": "INDIVIDUAL"},
        {"id": "ACC-COUNT-BAD-1", "account_type": "NOPE"},
        {"id": "ACC-COUNT-2", "account_type": "BUSINESS"},
        {"id": "ACC-COUNT-BAD-2", "account_type": "ALSO_NOPE"},
        {"id": "ACC-COUNT-3", "account_type": "MERCHANT"},
    ]

    body = assert_ok(
        admin_client.post(
            ACCOUNTS,
            json={"records": records, "options": {"allow_partial": True}},
        ),
        201,
    )

    present = sum(
        1
        for index in (1, 2, 3)
        if db.get(Account, f"ACC-COUNT-{index}") is not None
    )

    assert body["accepted"] == 3
    assert body["rejected"] == 2
    assert present == body["accepted"]


def test_an_audit_event_is_written_for_a_successful_batch(admin_client, db):
    """
    Ingestion is auditable, and the audit record is part of the same transaction.

    If the audit write were separate, a committed batch could have no record
    of who loaded it — which for the one endpoint that can introduce bulk data
    is the record that matters most.
    """
    from app.models import AuditEvent

    before = db.query(AuditEvent).filter(AuditEvent.action == "ingestion_batch").count()

    assert_ok(
        admin_client.post(
            ACCOUNTS,
            json={"records": [{"id": "ACC-AUDITED", "account_type": "INDIVIDUAL"}]},
        ),
        201,
    )

    after = db.query(AuditEvent).filter(AuditEvent.action == "ingestion_batch").count()
    assert after == before + 1


def test_no_audit_event_is_written_for_a_dry_run(admin_client, db):
    """A dry run changed nothing, so there is nothing to record."""
    from app.models import AuditEvent

    before = db.query(AuditEvent).filter(AuditEvent.action == "ingestion_batch").count()

    assert_ok(
        admin_client.post(
            ACCOUNTS,
            json={
                "records": [{"id": "ACC-DRY-AUDIT", "account_type": "INDIVIDUAL"}],
                "options": {"dry_run": True},
            },
        ),
        200,
    )

    after = db.query(AuditEvent).filter(AuditEvent.action == "ingestion_batch").count()
    assert after == before
