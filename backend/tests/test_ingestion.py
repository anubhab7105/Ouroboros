"""
Ingestion: the happy paths and the options that govern them.

Ingestion is admin-only and synthetic-only, and both of those are deliberate.
It is the one endpoint group that writes bulk data, so getting its defaults
wrong is how a prototype ends up holding real customer records.

Three defaults are load-bearing, and each gets a test:

- `allow_partial` is **false**: a batch with any bad row writes nothing. The
  alternative leaves the caller guessing which rows landed.
- `on_duplicate` is **reject**: re-posting a batch fails rather than quietly
  doing nothing. A caller that wants idempotent replay asks for `skip`.
- `dry_run` validates and returns **200**, not 201, because nothing was
  created.
"""

from __future__ import annotations

import pytest

from app.models import Account, Complaint, Entity, Transaction

from tests.utils import assert_ok, unique_id

pytestmark = [pytest.mark.ingestion, pytest.mark.api]


ACCOUNTS = "/api/v1/ingestion/accounts"
TRANSACTIONS = "/api/v1/ingestion/transactions"
COMPLAINTS = "/api/v1/ingestion/complaints"
ENTITIES = "/api/v1/ingestion/entities"
LINKS = "/api/v1/ingestion/entity-links"


def _entities_payload():
    return {
        "records": [
            {
                "id": f"ENT-V-0{index}",
                "entity_type": "DEVICE",
                "identifier_hash": unique_id("devicehash"),
            }
            for index in (1, 2, 3)
        ]
    }


# -----------------------------------------------------------------------------
# Status
# -----------------------------------------------------------------------------


def test_status_reports_the_limits_it_will_enforce(admin_client):
    """
    A caller can discover the batch ceiling before hitting it.

    Without this, the only way to learn the limit is to exceed it, which for a
    bulk loader means a failed run.
    """
    body = assert_ok(admin_client.get("/api/v1/ingestion/status"))

    assert body["enabled"] is True
    assert body["max_batch_size"] > 0
    assert body["hard_max_batch_size"] >= body["max_batch_size"]
    assert body["default_duplicate_strategy"] in {"reject", "skip"}
    assert isinstance(body["default_allow_partial"], bool)
    assert body["future_tolerance_minutes"] >= 0
    assert body["caveats"]


def test_status_says_the_data_must_be_synthetic(admin_client):
    """
    `require_synthetic` is on by default and the status says so.

    The flag is what stands between a prototype and a system holding real
    account records. It is reported rather than merely enforced, so that
    somebody configuring a deployment can see which mode they are in.
    """
    body = assert_ok(admin_client.get("/api/v1/ingestion/status"))

    assert body["require_synthetic"] is True
    assert body["dataset_mode"] == "synthetic"
    assert body["production_like"] is False


# -----------------------------------------------------------------------------
# Accounts
# -----------------------------------------------------------------------------


def test_ingest_accounts_from_the_fixture(admin_client, db, load_fixture):
    payload = load_fixture("accounts.valid.json")
    body = assert_ok(admin_client.post(ACCOUNTS, json=payload), 201)

    assert body["ok"] is True
    assert body["accepted"] == len(payload["records"])
    assert body["rejected"] == 0
    assert body["errors"] == []
    assert body["entity_type"] == "accounts"

    assert db.get(Account, "ACC-V-01") is not None
    assert db.get(Account, "ACC-V-07") is not None


def test_caller_supplied_ids_are_honoured(admin_client, db):
    """
    The id in the record is the id in the database.

    This is what lets the transaction and entity-link fixtures refer to
    accounts by name. If ingestion generated its own ids, every multi-entity
    load would need the caller to thread generated ids through, which is both
    tedious and the kind of code that silently links the wrong rows.
    """
    assert_ok(
        admin_client.post(
            ACCOUNTS,
            json={"records": [{"id": "ACC-EXPLICIT", "account_type": "INDIVIDUAL"}]},
        ),
        201,
    )

    assert db.get(Account, "ACC-EXPLICIT") is not None


def test_an_omitted_id_is_generated(admin_client, db):
    body = assert_ok(
        admin_client.post(ACCOUNTS, json={"records": [{"account_type": "BUSINESS"}]}),
        201,
    )

    assert body["accepted"] == 1


def test_provenance_is_recorded(admin_client, db):
    """
    `source_system` and `source_batch_id` are stored with the records.

    Six months later the question "where did this account come from" has to
    have an answer, and the answer cannot be "the ingestion endpoint".
    """
    assert_ok(
        admin_client.post(
            ACCOUNTS,
            json={
                "records": [{"id": "ACC-PROV", "account_type": "INDIVIDUAL"}],
                "options": {
                    "source_system": "test-loader",
                    "source_batch_id": "batch-42",
                },
            },
        ),
        201,
    )

    account = db.get(Account, "ACC-PROV")
    assert account is not None

    metadata = account.metadata_json or {}
    serialised = str(metadata)

    assert "test-loader" in serialised or "batch-42" in serialised


# -----------------------------------------------------------------------------
# Transactions
# -----------------------------------------------------------------------------


def test_ingest_transactions_after_their_accounts(admin_client, db, load_fixture):
    assert_ok(admin_client.post(ACCOUNTS, json=load_fixture("accounts.valid.json")), 201)

    payload = load_fixture("transactions.valid.json")
    body = assert_ok(admin_client.post(TRANSACTIONS, json=payload), 201)

    assert body["accepted"] == len(payload["records"])
    assert body["rejected"] == 0

    stored = db.query(Transaction).filter(Transaction.reference == "TXN-V-0001").one()
    assert stored.sender_account_id == "ACC-V-01"
    assert stored.receiver_account_id == "ACC-V-02"
    assert str(stored.amount) == "48500.00"


def test_transaction_amounts_keep_their_precision(admin_client, db, load_fixture):
    """
    `1250.50` arrives as `1250.50`, not `1250.5000000000002`.

    The column is `Numeric` and the request model is `Decimal`, so this works
    — but it works because of those two choices, and a well-meant change to
    `float` anywhere in the path would break it in a way no other test would
    notice.
    """
    assert_ok(admin_client.post(ACCOUNTS, json=load_fixture("accounts.valid.json")), 201)
    assert_ok(
        admin_client.post(TRANSACTIONS, json=load_fixture("transactions.valid.json")), 201
    )

    stored = db.query(Transaction).filter(Transaction.reference == "TXN-V-0006").one()
    assert str(stored.amount) == "1250.50"


def test_a_transaction_referencing_an_unknown_account_is_rejected(admin_client):
    """
    Referential integrity is checked before the write, not by the database.

    A foreign-key violation surfacing from the driver would be a 500. This is
    a caller error and must read as one.
    """
    response = admin_client.post(
        TRANSACTIONS,
        json={
            "records": [
                {
                    "reference": unique_id("TXN"),
                    "sender_account_id": "ACC-NOT-REAL",
                    "receiver_account_id": "ACC-ALSO-NOT-REAL",
                    "amount": 1000,
                    "currency": "INR",
                    "occurred_at": "2025-11-13T07:12:00Z",
                }
            ]
        },
    )

    assert response.status_code == 422
    assert "traceback" not in response.text.lower()


# -----------------------------------------------------------------------------
# Complaints, entities, links
# -----------------------------------------------------------------------------


def test_ingest_complaints(admin_client, db, load_fixture):
    assert_ok(admin_client.post(ACCOUNTS, json=load_fixture("accounts.valid.json")), 201)

    payload = load_fixture("complaints.valid.json")
    body = assert_ok(admin_client.post(COMPLAINTS, json=payload), 201)

    assert body["accepted"] == len(payload["records"])

    stored = db.query(Complaint).filter(Complaint.reference == "CMP-V-0001").one()
    assert stored.suspected_account_id == "ACC-V-02"
    assert stored.narrative_raw


def test_a_complaint_with_no_links_is_accepted(admin_client, load_fixture):
    """
    A complaint that names nothing is a normal complaint.

    Most are. Requiring an account or a transaction reference would reject the
    majority of real filings, and the correlation tiers exist precisely
    because the common case is a narrative and a date.
    """
    body = assert_ok(
        admin_client.post(
            COMPLAINTS,
            json={
                "records": [
                    {
                        "reference": unique_id("CMP"),
                        "reported_at": "2025-11-15T11:00:00Z",
                        "narrative_raw": "Complainant reports an unrecognised debit.",
                    }
                ]
            },
        ),
        201,
    )

    assert body["accepted"] == 1


def test_ingest_entities_and_links(admin_client, db, load_fixture):
    assert_ok(admin_client.post(ACCOUNTS, json=load_fixture("accounts.valid.json")), 201)
    assert_ok(admin_client.post(ENTITIES, json=_entities_payload()), 201)

    payload = load_fixture("entity_links.valid.json")
    body = assert_ok(admin_client.post(LINKS, json=payload), 201)

    assert body["accepted"] == len(payload["records"])
    assert db.get(Entity, "ENT-V-01") is not None


def test_a_deterministic_link_carries_no_confidence(admin_client, db, load_fixture):
    """
    An EXACT link stores `confidence` as NULL.

    Not 1.0. The distinction is not pedantry: a confidence of 1.000 sits in
    the same column as 0.94 and invites a reader to compare them, when one is
    a probability and the other is an identity. The interface renders the
    absence as the word "identity" for the same reason.
    """
    from app.models import AccountEntityLink

    assert_ok(admin_client.post(ACCOUNTS, json=load_fixture("accounts.valid.json")), 201)
    assert_ok(admin_client.post(ENTITIES, json=_entities_payload()), 201)
    assert_ok(admin_client.post(LINKS, json=load_fixture("entity_links.valid.json")), 201)

    exact = (
        db.query(AccountEntityLink)
        .filter(
            AccountEntityLink.account_id == "ACC-V-01",
            AccountEntityLink.entity_id == "ENT-V-01",
        )
        .one()
    )
    assert exact.confidence is None

    inferred = (
        db.query(AccountEntityLink)
        .filter(
            AccountEntityLink.account_id == "ACC-V-04",
            AccountEntityLink.entity_id == "ENT-V-01",
        )
        .one()
    )
    assert inferred.confidence is not None


def test_a_source_systems_own_wording_is_mapped_not_refused(
    admin_client,
    db,
    load_fixture,
):
    """
    `HEURISTIC` and `PENDING` are not our words, and both are accepted.

    A feed will describe its own data in its own vocabulary, and refusing a
    record whose meaning is unambiguous would push the mapping work onto
    whoever runs the loader. The alias table does it once, in one place, and
    what lands in the column is always a value the column declares.

    The line it will not cross is inventing a fact: a name with no honest
    destination is refused with the allowed list instead of being filed under
    the nearest-looking value. `tests/fixtures/entity_links.invalid.json`
    holds those cases.
    """
    from app.models import AccountEntityLink, MatchMethod, VerificationState

    assert_ok(admin_client.post(ACCOUNTS, json=load_fixture("accounts.valid.json")), 201)
    assert_ok(admin_client.post(ENTITIES, json=_entities_payload()), 201)
    assert_ok(admin_client.post(LINKS, json=load_fixture("entity_links.valid.json")), 201)

    aliased = (
        db.query(AccountEntityLink)
        .filter(
            AccountEntityLink.account_id == "ACC-V-04",
            AccountEntityLink.entity_id == "ENT-V-02",
        )
        .one()
    )

    assert aliased.match_method == MatchMethod.NORMALIZED
    assert aliased.verification_state == VerificationState.NEEDS_REVIEW


def test_the_accepted_vocabulary_is_the_one_the_columns_declare(admin_client):
    """
    Ingestion accepts exactly what the database can store.

    This held in neither direction before: the validator accepted SAVINGS,
    CURRENT, WALLET, UPI and CARD as account types, none of which the column
    can hold, and refused INDIVIDUAL, BUSINESS and MERCHANT, which are the
    only values it can. A correct record failed validation; an accepted one
    failed on insert. The same had happened to statuses, transaction states,
    channels, entity types, match methods and verification states.

    Both sides now derive from `app.core.vocabularies`, so the comparison
    below cannot fail by drift — only by someone reintroducing a second list.
    """
    from app.core.vocabularies import (
        AccountStatus,
        AccountType,
        Channel,
        EntityType,
        MatchMethod,
        TransactionStatus,
        VerificationState,
        enum_values,
    )
    from app.ingestion import normalizers, validators

    expected = {
        "ACCOUNT_TYPES": enum_values(AccountType),
        "ACCOUNT_STATUSES": enum_values(AccountStatus),
        "TRANSACTION_STATUSES": enum_values(TransactionStatus),
        "CHANNELS": enum_values(Channel),
        "ENTITY_TYPES": enum_values(EntityType),
        "MATCH_METHODS": enum_values(MatchMethod),
        "VERIFICATION_STATES": enum_values(VerificationState),
    }

    for name, values in expected.items():
        assert getattr(normalizers, name) == frozenset(values), name
        assert getattr(validators, name) == frozenset(values), name


def test_an_alias_never_points_outside_the_vocabulary(admin_client):
    """
    Every alias resolves to a value the column accepts.

    An alias pointing at a word that is no longer a member would be worse
    than no alias at all: the record passes normalization, looks canonical,
    and fails at the database with a message about an enum rather than about
    the mapping that produced it.
    """
    from app.core.vocabularies import (
        AccountStatus,
        AccountType,
        Channel,
        EntityType,
        MatchMethod,
        TransactionStatus,
        VerificationState,
        enum_values,
    )
    from app.ingestion import normalizers as n

    pairs = [
        (n._ACCOUNT_TYPE_ALIASES, enum_values(AccountType)),
        (n._ACCOUNT_STATUS_ALIASES, enum_values(AccountStatus)),
        (n._TRANSACTION_STATUS_ALIASES, enum_values(TransactionStatus)),
        (n._CHANNEL_ALIASES, enum_values(Channel)),
        (n._ENTITY_TYPE_ALIASES, enum_values(EntityType)),
        (n._MATCH_METHOD_ALIASES, enum_values(MatchMethod)),
        (n._VERIFICATION_STATE_ALIASES, enum_values(VerificationState)),
    ]

    for aliases, allowed in pairs:
        for source, target in aliases.items():
            assert target in allowed, f"{source} -> {target}"
            assert source not in allowed, f"{source} is a member, not an alias"


# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------


def test_dry_run_validates_without_writing(admin_client, db):
    """
    200, not 201, and nothing in the database.

    The status code is the part worth pinning: 201 means "created", and a dry
    run creates nothing. A loader that checks for 201 would treat a validation
    pass as a completed load.
    """
    body = assert_ok(
        admin_client.post(
            ACCOUNTS,
            json={
                "records": [{"id": "ACC-DRYRUN", "account_type": "INDIVIDUAL"}],
                "options": {"dry_run": True},
            },
        ),
        200,
    )

    assert body["dry_run"] is True
    assert body["accepted"] == 1
    assert db.get(Account, "ACC-DRYRUN") is None


def test_dry_run_still_reports_errors(admin_client):
    """A dry run that finds problems reports them without failing the request."""
    body = assert_ok(
        admin_client.post(
            ACCOUNTS,
            json={
                "records": [
                    {"id": "ACC-OK", "account_type": "INDIVIDUAL"},
                    {"id": "ACC-BAD", "account_type": "SAVINGS"},
                ],
                "options": {"dry_run": True},
            },
        ),
        200,
    )

    assert body["rejected"] >= 1
    assert body["errors"]
    assert body["ok"] is False


def test_an_empty_batch_is_accepted_and_does_nothing(admin_client):
    """
    Zero records is not an error.

    A scheduled loader with nothing to send should not have to special-case
    the empty case, and an empty batch failing is how a nightly job starts
    paging someone at 3am for no reason.
    """
    body = assert_ok(admin_client.post(ACCOUNTS, json={"records": []}), 201)

    assert body["accepted"] == 0
    assert body["rejected"] == 0
    assert body["ok"] is True


def test_a_batch_over_the_limit_is_refused(admin_client, override_settings):
    """
    Over the ceiling the request is refused, not truncated.

    Truncation would be worse than failure: the caller gets a success for a
    partial load and has no way to know which records were dropped.
    """
    override_settings(INGESTION_MAX_BATCH_SIZE=5)

    response = admin_client.post(
        ACCOUNTS,
        json={"records": [{"account_type": "INDIVIDUAL"} for _ in range(20)]},
    )

    assert response.status_code in (413, 422)


def test_the_response_echoes_the_options_in_force(admin_client):
    """
    A caller can see which defaults applied.

    `allow_partial` and `on_duplicate` are configurable and have different
    defaults in different deployments, so a response that did not state them
    would leave the caller unable to interpret its own result.
    """
    body = assert_ok(admin_client.post(ACCOUNTS, json={"records": []}), 201)

    assert body["allow_partial"] is False
    assert body["on_duplicate"] == "reject"
    assert body["dry_run"] is False
    assert body["request_id"]


def test_every_batch_response_carries_caveats(admin_client):
    """
    Ingested data is synthetic, and the response says so every time.

    Not once in the documentation. The caveats travel with the result because
    that is where someone reads them.
    """
    body = assert_ok(admin_client.post(ACCOUNTS, json={"records": []}), 201)

    assert body["caveats"]
    assert any("synthetic" in caveat.lower() for caveat in body["caveats"])
