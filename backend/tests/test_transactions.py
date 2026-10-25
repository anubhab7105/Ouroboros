"""
Transaction reads.

The transaction list is the one place in the API where a client can ask for a
lot of rows cheaply, so most of this module is about the filters and the
bounds. The rest is about two representational points.

**The global list has no `direction`.** Direction is relative to an account,
and the global list is not scoped to one. It appears on
`/accounts/{id}/transactions`, and on the global list only when `account_id`
is supplied. A `direction` field on an unscoped row would have to be relative
to something, and whatever that something was would be wrong half the time.

**There is no `is_fund_movement` field.** Whether a transfer moved money is
`status == "COMPLETED"`, derived by the reader. Materialising it as a column
would create a second source of truth that can disagree with the status.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.models import Channel, TransactionStatus

from tests.utils import (
    assert_error,
    assert_ok,
    assert_paginated,
    days_ago,
    hours_ago,
    ids_of,
)

pytestmark = pytest.mark.api


TRANSACTIONS = "/api/v1/transactions"


# -----------------------------------------------------------------------------
# The list
# -----------------------------------------------------------------------------


def test_list_transactions(analyst_client, make, db):
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver, amount=12_345)
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(TRANSACTIONS)))

    assert transfer.id in ids_of(body["items"])

    row = next(item for item in body["items"] if item["id"] == transfer.id)
    assert row["sender_account_id"] == sender.id
    assert row["receiver_account_id"] == receiver.id
    assert Decimal(str(row["amount"])) == Decimal("12345")


def test_the_global_list_has_no_direction_field(analyst_client, make, db):
    """
    Direction is relative to an account; the global list is not scoped to one.

    A reader that wanted it computes it from the sender and receiver against
    whichever account it cares about — which is what the frontend's
    `directionFor` helper does.
    """
    sender, receiver = make.accounts(2)
    make.transaction(sender, receiver)
    db.commit()

    row = assert_ok(analyst_client.get(TRANSACTIONS))["items"][0]

    assert "direction" not in row
    assert "counterparty_account_id" not in row
    assert "sender_account_id" in row
    assert "receiver_account_id" in row


def test_there_is_no_is_fund_movement_field(analyst_client, make, db):
    """
    Derived from `status`, not stored.

    `COMPLETED` moved money; everything else did not. A separate boolean would
    be a second source of truth, and the two would diverge the first time a
    status was corrected without the flag being recomputed.
    """
    sender, receiver = make.accounts(2)
    make.transaction(sender, receiver)
    db.commit()

    row = assert_ok(analyst_client.get(TRANSACTIONS))["items"][0]

    assert "is_fund_movement" not in row
    assert row["status"] == "COMPLETED"


def test_filter_by_sender_and_receiver(analyst_client, make, db):
    a, b, c = make.accounts(3)

    a_to_b = make.transaction(a, b)
    make.transaction(b, c)
    db.commit()

    by_sender = assert_ok(analyst_client.get(TRANSACTIONS, params={"sender_account_id": a.id}))
    assert ids_of(by_sender["items"]) == [a_to_b.id]

    by_receiver = assert_ok(
        analyst_client.get(TRANSACTIONS, params={"receiver_account_id": b.id})
    )
    assert ids_of(by_receiver["items"]) == [a_to_b.id]


def test_account_id_matches_either_side(analyst_client, make, db):
    """
    `account_id` is the convenience filter: anything involving this account.

    Without it a client asking "what did this account do" has to make two
    requests and merge them, which is both slower and a place to get the
    de-duplication wrong for a self-transfer.
    """
    account, other = make.accounts(2)

    inbound = make.transaction(other, account)
    outbound = make.transaction(account, other)
    db.commit()

    body = assert_ok(analyst_client.get(TRANSACTIONS, params={"account_id": account.id}))

    assert set(ids_of(body["items"])) == {inbound.id, outbound.id}


def test_direction_requires_account_id(analyst_client, make, db):
    """
    `direction` without `account_id` is meaningless and is ignored.

    Documented as ignored rather than rejected, which is the gentler choice
    for a client that sends a default. What must not happen is it being
    honoured against some implicit account.
    """
    sender, receiver = make.accounts(2)
    make.transaction(sender, receiver)
    db.commit()

    body = assert_ok(analyst_client.get(TRANSACTIONS, params={"direction": "inbound"}))
    assert len(body["items"]) == 1


def test_direction_with_account_id_filters(analyst_client, make, db):
    account, other = make.accounts(2)

    inbound = make.transaction(other, account)
    make.transaction(account, other)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            TRANSACTIONS, params={"account_id": account.id, "direction": "inbound"}
        )
    )

    assert ids_of(body["items"]) == [inbound.id]


def test_filter_by_status(analyst_client, make, db):
    sender, receiver = make.accounts(2)

    make.transaction(sender, receiver)
    pending = make.transaction(sender, receiver, status=TransactionStatus.PENDING)
    db.commit()

    body = assert_ok(analyst_client.get(TRANSACTIONS, params={"status": "PENDING"}))
    assert ids_of(body["items"]) == [pending.id]


def test_filter_by_channel(analyst_client, make, db):
    sender, receiver = make.accounts(2)

    upi = make.transaction(sender, receiver, channel=Channel.UPI)
    make.transaction(sender, receiver, channel=Channel.NEFT)
    db.commit()

    body = assert_ok(analyst_client.get(TRANSACTIONS, params={"channel": "UPI"}))
    assert ids_of(body["items"]) == [upi.id]


def test_filter_by_currency(analyst_client, make, db):
    sender, receiver = make.accounts(2)

    make.transaction(sender, receiver, currency="INR")
    dollars = make.transaction(sender, receiver, currency="USD")
    db.commit()

    body = assert_ok(analyst_client.get(TRANSACTIONS, params={"currency": "USD"}))
    assert ids_of(body["items"]) == [dollars.id]


def test_filter_by_exact_reference(analyst_client, make, db):
    sender, receiver = make.accounts(2)

    target = make.transaction(sender, receiver, reference="TXN-FIND-ME")
    make.transaction(sender, receiver, reference="TXN-SOMETHING-ELSE")
    db.commit()

    body = assert_ok(analyst_client.get(TRANSACTIONS, params={"reference": "TXN-FIND-ME"}))
    assert ids_of(body["items"]) == [target.id]


def test_filter_by_date_range(analyst_client, make, db):
    sender, receiver = make.accounts(2)

    old = make.transaction(sender, receiver, occurred_at=days_ago(60))
    recent = make.transaction(sender, receiver, occurred_at=hours_ago(2))
    db.commit()

    body = assert_ok(
        analyst_client.get(TRANSACTIONS, params={"date_from": days_ago(7).isoformat()})
    )

    returned = set(ids_of(body["items"]))
    assert recent.id in returned
    assert old.id not in returned


def test_filter_by_amount_range(analyst_client, make, db):
    sender, receiver = make.accounts(2)

    small = make.transaction(sender, receiver, amount=500)
    large = make.transaction(sender, receiver, amount=250_000)
    db.commit()

    body = assert_ok(analyst_client.get(TRANSACTIONS, params={"amount_min": 1_000}))

    returned = set(ids_of(body["items"]))
    assert large.id in returned
    assert small.id not in returned


def test_a_negative_amount_filter_is_rejected(analyst_client):
    """
    Amounts are unsigned; direction lives in the sender and receiver columns.

    A negative bound would match nothing, which looks like "no results" rather
    than "your query was wrong".
    """
    assert_error(analyst_client.get(TRANSACTIONS, params={"amount_min": -100}), 422)


def test_a_reversed_date_range_is_rejected(analyst_client):
    """
    `date_from` after `date_to` is an empty window.

    Honouring it returns nothing, which an analyst reads as "no activity in
    that period" — a false negative produced by a typo.
    """
    assert_error(
        analyst_client.get(
            TRANSACTIONS,
            params={
                "date_from": days_ago(1).isoformat(),
                "date_to": days_ago(30).isoformat(),
            },
        ),
        422,
    )


def test_the_list_carries_caveats(analyst_client, make, db):
    sender, receiver = make.accounts(2)
    make.transaction(sender, receiver)
    db.commit()

    body = assert_ok(analyst_client.get(TRANSACTIONS))
    assert body["caveats"]


# -----------------------------------------------------------------------------
# Sorting and paging
# -----------------------------------------------------------------------------


def test_default_sort_is_most_recent_first(analyst_client, make, db):
    sender, receiver = make.accounts(2)

    older = make.transaction(sender, receiver, occurred_at=days_ago(5))
    newer = make.transaction(sender, receiver, occurred_at=hours_ago(1))
    db.commit()

    body = assert_ok(analyst_client.get(TRANSACTIONS))
    order = ids_of(body["items"])

    assert body["sort_by"] == "occurred_at"
    assert body["sort_order"] == "desc"
    assert order.index(newer.id) < order.index(older.id)


def test_sort_by_amount(analyst_client, make, db):
    sender, receiver = make.accounts(2)

    small = make.transaction(sender, receiver, amount=100)
    large = make.transaction(sender, receiver, amount=900_000)
    db.commit()

    body = assert_ok(
        analyst_client.get(TRANSACTIONS, params={"sort_by": "amount", "sort_order": "desc"})
    )
    order = ids_of(body["items"])

    assert order.index(large.id) < order.index(small.id)


def test_sort_by_an_unknown_field_is_rejected(analyst_client):
    assert_error(analyst_client.get(TRANSACTIONS, params={"sort_by": "sender_account_id"}), 422)


def test_paging_does_not_repeat_or_skip(analyst_client, make, db):
    """
    Every row appears exactly once across the pages.

    The sort is on `occurred_at`, and the factory gives every transfer the
    same default timestamp, so ties are the common case. A sort with no
    tiebreaker produces a non-deterministic order, and the symptom is exactly
    this: a row on page one that reappears on page two while another is never
    returned at all.
    """
    sender, receiver = make.accounts(2)
    created = [make.transaction(sender, receiver, amount=1_000 + index) for index in range(25)]
    db.commit()

    seen: list[str] = []
    for page in range(1, 4):
        body = assert_ok(
            analyst_client.get(TRANSACTIONS, params={"page": page, "page_size": 10})
        )
        seen.extend(ids_of(body["items"]))

    assert len(seen) == len(set(seen)), "a row was returned on more than one page"
    assert set(seen) == {transfer.id for transfer in created}


# -----------------------------------------------------------------------------
# One transaction
# -----------------------------------------------------------------------------


def test_get_one_transaction(analyst_client, make, db):
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver, amount=99_000)
    db.commit()

    body = assert_ok(analyst_client.get(f"{TRANSACTIONS}/{transfer.id}"))

    assert body["transaction"]["id"] == transfer.id
    assert Decimal(str(body["transaction"]["amount"])) == Decimal("99000")
    assert body["caveats"]


def test_detail_includes_both_account_summaries_by_default(analyst_client, make, db):
    """
    `include_accounts` defaults to true on the detail endpoint.

    A transaction with two opaque ids is not useful on its own: the next thing
    anyone wants is what kind of accounts those are. The list endpoint
    defaults the other way, because there it is a join per row.
    """
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver)
    db.commit()

    body = assert_ok(analyst_client.get(f"{TRANSACTIONS}/{transfer.id}"))

    assert body["sender_account"]["id"] == sender.id
    assert body["receiver_account"]["id"] == receiver.id


def test_account_summaries_can_be_omitted(analyst_client, make, db):
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{TRANSACTIONS}/{transfer.id}", params={"include_accounts": False}
        )
    )

    assert body["sender_account"] is None
    assert body["receiver_account"] is None


def test_the_embedded_account_summary_is_bounded(analyst_client, make, db):
    """
    The nested account is a summary, not the whole account.

    No assessment, no counts, no metadata. Embedding the full account would
    make a transaction read pull its own risk history, and the detail page
    would grow a second meaning.
    """
    sender, receiver = make.accounts(2)
    make.assessment(sender, score=90)
    transfer = make.transaction(sender, receiver)
    db.commit()

    body = assert_ok(analyst_client.get(f"{TRANSACTIONS}/{transfer.id}"))
    summary = body["sender_account"]

    assert set(summary) <= {
        "id",
        "account_type",
        "status",
        "created_at",
        "record_created_at",
        "record_updated_at",
    }
    assert "latest_assessment" not in summary


def test_unknown_transaction_is_404(analyst_client):
    assert_error(analyst_client.get(f"{TRANSACTIONS}/not-a-real-transaction"), 404)


def test_a_self_transfer_reports_the_same_account_on_both_sides(analyst_client, make, db):
    account = make.account()
    transfer = make.transaction(account, account, amount=7_000)
    db.commit()

    body = assert_ok(analyst_client.get(f"{TRANSACTIONS}/{transfer.id}"))

    assert body["transaction"]["sender_account_id"] == account.id
    assert body["transaction"]["receiver_account_id"] == account.id
    assert body["sender_account"]["id"] == body["receiver_account"]["id"]


# -----------------------------------------------------------------------------
# Nested collections
# -----------------------------------------------------------------------------


def test_transaction_alerts_are_scoped(analyst_client, make, db):
    """
    Alerts are raised against accounts, so a transaction's alerts are its parties'.

    An empty list is the common and correct answer: a transfer between two
    unremarkable accounts has none.
    """
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver)
    make.alert(sender)
    db.commit()

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{TRANSACTIONS}/{transfer.id}/alerts"))
    )
    assert isinstance(body["items"], list)


def test_transaction_correlations_distinguish_identity_from_inference(
    analyst_client, make, db
):
    """
    A tier-2 match on the transaction reference carries no confidence.

    The complaint quoted the reference and the reference exists. That is an
    identity, and presenting it as a probability of 1.0 would put it on the
    same scale as a tier-4 amount-and-time guess.
    """
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver, reference="TXN-QUOTED")

    complaint = make.complaint(transaction_reference="TXN-QUOTED")
    make.correlation(complaint, transaction=transfer, match_tier=2)
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{TRANSACTIONS}/{transfer.id}/complaint-correlations")
    )

    assert len(body["items"]) == 1
    row = body["items"][0]

    assert row["deterministic"] is True
    assert row["confidence"] is None
    assert row["match_tier"] == 2


def test_an_inferred_correlation_carries_a_confidence_and_a_review_state(
    analyst_client, make, db
):
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver)

    complaint = make.complaint()
    make.correlation(complaint, transaction=transfer, match_tier=4, confidence=0.61)
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{TRANSACTIONS}/{transfer.id}/complaint-correlations")
    )
    row = body["items"][0]

    assert row["deterministic"] is False
    assert row["confidence"] is not None
    assert row["review_state"] == "UNREVIEWED"


def test_correlations_can_be_filtered_by_determinism(analyst_client, make, db):
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver)

    complaint = make.complaint()
    make.correlation(complaint, transaction=transfer, match_tier=2)
    make.correlation(complaint, transaction=transfer, match_tier=4)
    db.commit()

    deterministic = assert_ok(
        analyst_client.get(
            f"{TRANSACTIONS}/{transfer.id}/complaint-correlations",
            params={"deterministic": True},
        )
    )
    inferred = assert_ok(
        analyst_client.get(
            f"{TRANSACTIONS}/{transfer.id}/complaint-correlations",
            params={"deterministic": False},
        )
    )

    assert len(deterministic["items"]) == 1
    assert len(inferred["items"]) == 1


def test_a_correlation_does_not_include_the_narrative(analyst_client, make, db):
    """
    The correlation says whether a narrative exists, not what it says.

    A complaint narrative is a victim's account of what happened to them and
    reading it is gated to senior roles. A flag is enough for a list; the text
    requires going to the complaint itself, where the permission applies.
    """
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver)

    complaint = make.complaint(
        narrative_raw="Victim describes a distressing sequence of events."
    )
    make.correlation(complaint, transaction=transfer, match_tier=2)
    db.commit()

    response = analyst_client.get(
        f"{TRANSACTIONS}/{transfer.id}/complaint-correlations"
    )
    body = assert_ok(response)
    row = body["items"][0]

    assert row["complaint_narrative_available"] is True
    assert "narrative_raw" not in row
    assert "distressing" not in response.text


def test_the_evidence_bundle_is_self_contained(analyst_client, make, db):
    """
    The evidence bundle holds the transaction and its two parties, nothing else.

    It is what gets attached to a case, so it must be a snapshot that still
    makes sense when read later — but bounded, because evidence that pulls in
    a whole neighbourhood is evidence nobody can review.
    """
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver)
    db.commit()

    body = assert_ok(analyst_client.get(f"{TRANSACTIONS}/{transfer.id}/evidence"))

    assert body["transaction"]["id"] == transfer.id
    assert body["sender_account"]["id"] == sender.id
    assert body["receiver_account"]["id"] == receiver.id
    assert body["caveats"]
