"""
Account reads: the list, the record, and the windowed summary.

Three things in this group are easy to get subtly wrong and are each pinned
here.

**The account list does not carry alert or case counts.** It returns the
record and, on request, a summary of the latest assessment. Counts come from
`/accounts/{id}/summary`, one account at a time. A list view that promised a
count column would have to fabricate it.

**An unassessed account is not a low-risk account.** The assessment endpoint
answers with `status: "no_assessment"` rather than a zero score, because the
two mean opposite things: one says the platform looked and found little, the
other says nothing has looked.

**Monetary totals are per currency and never summed across them.** The summary
takes a currency and reports on that currency alone. Adding rupees to dollars
produces a number that is wrong in a way nobody notices.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.models import AccountStatus, AccountType, TransactionStatus

from tests.utils import (
    assert_error,
    assert_ok,
    assert_paginated,
    days_ago,
    hours_ago,
    ids_of,
)

pytestmark = pytest.mark.api


ACCOUNTS = "/api/v1/accounts"


# -----------------------------------------------------------------------------
# The list
# -----------------------------------------------------------------------------


def test_list_accounts(analyst_client, make, db):
    accounts = make.accounts(3)
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(ACCOUNTS)))

    returned = set(ids_of(body["items"]))
    assert {account.id for account in accounts} <= returned


def test_an_empty_list_is_not_an_error(analyst_client):
    """
    No accounts yet is a normal state.

    A 404 for an empty collection is a classic and annoying mistake: the
    client has to special-case the first run.
    """
    body = assert_paginated(assert_ok(analyst_client.get(ACCOUNTS)))

    assert body["items"] == []
    assert body["total"] == 0
    assert body["total_pages"] in (0, 1)


def test_the_envelope_is_flat(analyst_client, make, db):
    """
    Pagination fields sit beside `items`, not inside a `meta` object.

    The whole API uses one envelope shape. A client writes one reader for it,
    and the frontend's `pageInfo()` depends on exactly these keys.
    """
    make.account()
    db.commit()

    body = assert_ok(analyst_client.get(ACCOUNTS))

    for key in ("items", "page", "page_size", "total", "total_pages", "sort_order"):
        assert key in body, f"envelope is missing {key}"

    assert "meta" not in body
    assert "pagination" not in body


def test_filter_by_account_type(analyst_client, make, db):
    make.account(account_type=AccountType.MERCHANT)
    make.account(account_type=AccountType.INDIVIDUAL)
    db.commit()

    body = assert_ok(analyst_client.get(ACCOUNTS, params={"account_type": "MERCHANT"}))

    assert body["items"]
    assert all(row["account_type"] == "MERCHANT" for row in body["items"])


def test_filter_by_status(analyst_client, make, db):
    make.account(status=AccountStatus.DORMANT)
    make.account(status=AccountStatus.ACTIVE)
    db.commit()

    body = assert_ok(analyst_client.get(ACCOUNTS, params={"status": "DORMANT"}))

    assert body["items"]
    assert all(row["status"] == "DORMANT" for row in body["items"])


def test_filter_by_creation_window(analyst_client, make, db):
    old = make.account(created_at=days_ago(900))
    recent = make.account(created_at=days_ago(3))
    db.commit()

    body = assert_ok(
        analyst_client.get(ACCOUNTS, params={"created_from": days_ago(30).isoformat()})
    )

    returned = set(ids_of(body["items"]))
    assert recent.id in returned
    assert old.id not in returned


def test_an_unknown_filter_value_is_rejected(analyst_client):
    """
    A typo in an enum filter fails rather than silently returning everything.

    Returning the unfiltered list would be the worst outcome: the caller reads
    the result as "all accounts of this type" and the type never existed.
    """
    assert_error(analyst_client.get(ACCOUNTS, params={"status": "FROZEN"}), 422)
    assert_error(analyst_client.get(ACCOUNTS, params={"account_type": "SAVINGS"}), 422)


def test_latest_assessment_is_opt_in(analyst_client, make, db):
    """
    The assessment summary is attached only when asked for.

    It is an extra query per page. A list view that does not show risk should
    not pay for it, and a client that wants it says so.
    """
    account, assessment, _ = make.scored_account(score=71)
    db.commit()

    without = assert_ok(analyst_client.get(ACCOUNTS))
    row = next(item for item in without["items"] if item["id"] == account.id)
    assert row.get("latest_assessment") is None

    with_assessment = assert_ok(
        analyst_client.get(ACCOUNTS, params={"include_latest_assessment": True})
    )
    row = next(item for item in with_assessment["items"] if item["id"] == account.id)

    assert row["latest_assessment"] is not None
    assert row["latest_assessment"]["risk_band"] == "HIGH"
    assert Decimal(str(row["latest_assessment"]["score"])) == Decimal("71")


def test_an_unassessed_account_has_a_null_assessment_not_a_zero(analyst_client, make, db):
    """
    Absent, not zero.

    A zero would sort alongside genuinely low-scoring accounts and render as a
    LOW badge, which says "we looked and found little" about an account
    nothing has looked at.
    """
    account = make.account()
    db.commit()

    body = assert_ok(
        analyst_client.get(ACCOUNTS, params={"include_latest_assessment": True})
    )
    row = next(item for item in body["items"] if item["id"] == account.id)

    assert row["latest_assessment"] is None


def test_the_list_carries_no_alert_or_case_counts(analyst_client, make, db):
    """
    Fields the list endpoint deliberately does not have.

    Asserted as absences because the frontend's `Account` type was once
    written with them, and the result was a column that rendered `undefined`
    for every row. The counts exist on the per-account summary.
    """
    account, _, _ = make.scored_account()
    make.alert(account)
    db.commit()

    body = assert_ok(analyst_client.get(ACCOUNTS))
    row = next(item for item in body["items"] if item["id"] == account.id)

    assert "open_alert_count" not in row
    assert "case_count" not in row
    assert "alert_count" not in row


# -----------------------------------------------------------------------------
# Pagination and sorting
# -----------------------------------------------------------------------------


def test_pagination_pages_do_not_overlap(analyst_client, make, db):
    make.accounts(12)
    db.commit()

    first = assert_ok(analyst_client.get(ACCOUNTS, params={"page_size": 5, "page": 1}))
    second = assert_ok(analyst_client.get(ACCOUNTS, params={"page_size": 5, "page": 2}))

    assert len(first["items"]) == 5
    assert len(second["items"]) == 5
    assert not (set(ids_of(first["items"])) & set(ids_of(second["items"])))


def test_a_page_past_the_end_is_empty_not_an_error(analyst_client, make, db):
    make.accounts(3)
    db.commit()

    body = assert_ok(analyst_client.get(ACCOUNTS, params={"page": 99, "page_size": 10}))

    assert body["items"] == []
    assert body["total"] == 3


def test_page_size_is_capped(analyst_client, make, db):
    """
    An absurd page size is clamped or refused, never honoured.

    `page_size=100000` on a table with a million rows is a denial of service
    with a polite HTTP interface.
    """
    make.accounts(3)
    db.commit()

    response = analyst_client.get(ACCOUNTS, params={"page_size": 100_000})

    if response.status_code == 200:
        assert response.json()["page_size"] <= 500
    else:
        assert response.status_code == 422


@pytest.mark.parametrize("params", [{"page": 0}, {"page": -1}, {"page_size": 0}])
def test_invalid_pagination_is_rejected(analyst_client, params):
    assert_error(analyst_client.get(ACCOUNTS, params=params), 422)


def test_sorting_by_an_allowed_field(analyst_client, make, db):
    oldest = make.account(created_at=days_ago(500))
    newest = make.account(created_at=days_ago(1))
    db.commit()

    ascending = assert_ok(
        analyst_client.get(ACCOUNTS, params={"sort_by": "created_at", "sort_order": "asc"})
    )
    order = ids_of(ascending["items"])

    assert order.index(oldest.id) < order.index(newest.id)
    assert ascending["sort_by"] == "created_at"
    assert ascending["sort_order"] == "asc"


def test_sorting_by_an_unknown_field_is_rejected(analyst_client):
    """
    The sort field is an allowlist, not a column name passed through.

    Accepting arbitrary field names is how an ORM-level sort becomes an
    information leak — or, with string interpolation anywhere in the path, an
    injection. The allowlist is the defence, and this is the test of it.
    """
    assert_error(analyst_client.get(ACCOUNTS, params={"sort_by": "password_hash"}), 422)
    assert_error(analyst_client.get(ACCOUNTS, params={"sort_by": "id; DROP TABLE"}), 422)


def test_the_default_sort_is_stated(analyst_client, make, db):
    make.account()
    db.commit()

    body = assert_ok(analyst_client.get(ACCOUNTS))

    assert body["sort_by"] == "created_at"
    assert body["sort_order"] == "desc"


# -----------------------------------------------------------------------------
# One account
# -----------------------------------------------------------------------------


def test_get_one_account(analyst_client, make, db):
    account = make.account(account_type=AccountType.BUSINESS)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}"))

    assert body["id"] == account.id
    assert body["account_type"] == "BUSINESS"
    assert body["created_at"]


def test_unknown_account_is_404(analyst_client):
    assert_error(analyst_client.get(f"{ACCOUNTS}/not-a-real-account"), 404)


def test_account_status_is_observational(analyst_client, make, db):
    """
    `status` is reported, not acted on.

    MuleGuard never sets it and takes no action on it — no freeze, no block,
    no flag written back. The platform supports human investigation; automatic
    adverse action against a customer is prohibited, and there is an exception
    class for it.
    """
    account = make.account(status=AccountStatus.REVIEW_REQUIRED)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}"))
    assert body["status"] == "REVIEW_REQUIRED"


# -----------------------------------------------------------------------------
# The summary
# -----------------------------------------------------------------------------


def test_summary_counts_completed_transfers_only(analyst_client, make, db):
    """
    Pending, failed and reversed are excluded from the money and counted beside it.

    The counts are what make the exclusion auditable. Without them an analyst
    comparing the summary against the ledger sees a discrepancy and cannot
    tell whether it is a filter or a bug.
    """
    account = make.account()
    others = make.accounts(3)

    make.transaction(others[0], account, amount=10_000)
    make.transaction(others[1], account, amount=20_000)
    make.transaction(others[2], account, amount=50_000, status=TransactionStatus.PENDING)
    make.transaction(others[0], account, amount=70_000, status=TransactionStatus.FAILED)
    make.transaction(others[1], account, amount=90_000, status=TransactionStatus.REVERSED)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/summary"))

    assert body["incoming_completed_count"] == 2
    assert Decimal(str(body["incoming_completed_amount"])) == Decimal("30000")

    assert body["pending_count"] == 1
    assert body["failed_count"] == 1
    assert body["reversed_count"] == 1


def test_summary_separates_inbound_from_outbound(analyst_client, make, db):
    account = make.account()
    other = make.account()

    make.transaction(other, account, amount=80_000)
    make.transaction(account, other, amount=30_000)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/summary"))

    assert Decimal(str(body["incoming_completed_amount"])) == Decimal("80000")
    assert Decimal(str(body["outgoing_completed_amount"])) == Decimal("30000")
    assert Decimal(str(body["net_completed_amount"])) == Decimal("50000")


def test_summary_counts_self_transfers_separately(analyst_client, make, db):
    """
    A transfer to oneself moves no money between parties.

    Counted on its own line because including it in both the inbound and the
    outbound totals would inflate both and leave the net correct, which is the
    hardest kind of error to spot.
    """
    account = make.account()
    make.transaction(account, account, amount=7_000)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/summary"))
    assert body["self_transfer_count"] == 1


def test_summary_counts_distinct_counterparties(analyst_client, make, db):
    """
    Distinct senders, not transfer count.

    The fan-in signal is about how many *different* people paid in. Ten
    transfers from one person is a different thing from one transfer each from
    ten people, and a count that conflated them would fire on a regular
    salary.
    """
    collector, senders, _ = make.fan_in(sources=6)

    # One sender pays twice: six senders, seven transfers.
    make.transaction(senders[0], collector, amount=24_000, occurred_at=hours_ago(1))
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{collector.id}/summary"))

    assert body["incoming_completed_count"] == 7
    assert body["distinct_incoming_counterparties"] == 6


def test_summary_reports_one_currency_at_a_time(analyst_client, make, db):
    """
    Totals are per currency. They are never added together.

    The summary takes a `currency` and reports on that currency alone. A
    single "total" across currencies is a number with no meaning that looks
    exactly like a number with meaning.
    """
    account = make.account()
    other = make.account()

    make.transaction(other, account, amount=50_000, currency="INR")
    make.transaction(other, account, amount=300, currency="USD")
    db.commit()

    rupees = assert_ok(
        analyst_client.get(f"{ACCOUNTS}/{account.id}/summary", params={"currency": "INR"})
    )
    dollars = assert_ok(
        analyst_client.get(f"{ACCOUNTS}/{account.id}/summary", params={"currency": "USD"})
    )

    assert rupees["currency"] == "INR"
    assert Decimal(str(rupees["incoming_completed_amount"])) == Decimal("50000")

    assert dollars["currency"] == "USD"
    assert Decimal(str(dollars["incoming_completed_amount"])) == Decimal("300")

    # 50_300 would be the bug.
    assert Decimal(str(rupees["incoming_completed_amount"])) != Decimal("50300")


def test_summary_states_its_window(analyst_client, make, db):
    """
    The window is part of the answer.

    Every figure in the summary is "over this period". A summary that did not
    say which period would be uninterpretable, and the window says whether it
    was defaulted or requested.
    """
    account = make.account()
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/summary"))

    window = body["window"]
    assert isinstance(window, dict)
    assert window


def test_summary_carries_caveats(analyst_client, make, db):
    account = make.account()
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/summary"))
    assert body["caveats"]


def test_summary_of_an_account_with_no_activity(analyst_client, make, db):
    """Zeroes, not an error, and not a 404."""
    account = make.account()
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/summary"))

    assert body["incoming_completed_count"] == 0
    assert Decimal(str(body["incoming_completed_amount"])) == Decimal("0")
    assert body["latest_assessment"] is None


def test_summary_includes_the_counts_the_list_omits(analyst_client, make, db):
    """Open alerts, correlations and active links: here, one account at a time."""
    account, assessment, _ = make.scored_account()
    make.alert(account, assessment=assessment)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/summary"))

    assert body["open_alert_count"] >= 1
    assert "complaint_correlation_count" in body
    assert "active_entity_link_count" in body


def test_summary_of_an_unknown_account_is_404(analyst_client):
    assert_error(analyst_client.get(f"{ACCOUNTS}/nope/summary"), 404)


# -----------------------------------------------------------------------------
# Assessment history
# -----------------------------------------------------------------------------


def test_assessment_history_is_paginated(analyst_client, make, db):
    account = make.account()
    for index in range(5):
        make.assessment(account, score=40 + index * 10, as_of=days_ago(index + 1))
    db.commit()

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/assessments"))
    )

    assert body["total"] == 5


def test_assessment_history_can_be_filtered_by_band(analyst_client, make, db):
    account = make.account()
    make.assessment(account, score=20, as_of=days_ago(3))
    make.assessment(account, score=90, as_of=days_ago(1))
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{ACCOUNTS}/{account.id}/assessments", params={"risk_band": "CRITICAL"}
        )
    )

    assert len(body["items"]) == 1
    assert body["items"][0]["risk_band"] == "CRITICAL"


def test_history_distinguishes_as_of_from_scored_at(analyst_client, make, db):
    """
    Two timestamps, two meanings.

    `as_of` is the instant assessed — the features saw only data strictly
    before it. `scored_at` is when scoring ran, which is usually later and can
    be much later when an assessment is re-run over historical data.
    Collapsing them would misdate every backfilled finding.
    """
    account = make.account()
    make.assessment(account, as_of=days_ago(30))
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/assessments"))
    row = body["items"][0]

    assert row["as_of"]
    assert row["scored_at"]
    assert row["as_of"] != row["scored_at"]


def test_assessment_summary_says_whether_an_explanation_exists(analyst_client, make, db):
    """
    `explanation_available` is a flag, not an empty string.

    An assessment with no written explanation is a real state — rules-only
    scoring produces one — and the list has to distinguish it from an
    explanation that failed to load.
    """
    account = make.account()
    make.assessment(account, with_explanation=False, as_of=days_ago(2))
    make.assessment(account, with_explanation=True, as_of=days_ago(1))
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/assessments"))
    flags = {row["explanation_available"] for row in body["items"]}

    assert flags == {True, False}


# -----------------------------------------------------------------------------
# Nested collections
# -----------------------------------------------------------------------------


def test_account_transactions_are_scoped_to_the_account(analyst_client, make, db):
    account = make.account()
    other = make.account()
    unrelated_a = make.account()
    unrelated_b = make.account()

    mine = make.transaction(other, account, amount=1_000)
    make.transaction(unrelated_a, unrelated_b, amount=2_000)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/transactions"))

    assert ids_of(body["items"]) == [mine.id]


def test_account_transactions_carry_a_direction(analyst_client, make, db):
    """
    Direction is relative to the requested account and the API computes it.

    The transaction row itself has only a sender and a receiver; which of
    those is "inbound" depends on whose page you are on. Having the server
    say so means the client does not re-derive it and get it backwards.
    """
    account = make.account()
    other = make.account()

    make.transaction(other, account, amount=1_000)
    make.transaction(account, other, amount=2_000)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/transactions"))
    directions = {row["direction"] for row in body["items"]}

    assert directions == {"incoming", "outgoing"}

    for row in body["items"]:
        assert row["counterparty_account_id"] == other.id


def test_account_transactions_can_be_filtered_by_direction(analyst_client, make, db):
    account = make.account()
    other = make.account()

    make.transaction(other, account, amount=1_000)
    make.transaction(account, other, amount=2_000)
    db.commit()

    inbound = assert_ok(
        analyst_client.get(
            f"{ACCOUNTS}/{account.id}/transactions", params={"direction": "incoming"}
        )
    )

    assert len(inbound["items"]) == 1
    assert inbound["items"][0]["direction"] == "incoming"


def test_account_alerts_are_scoped_to_the_account(analyst_client, make, db):
    account = make.account()
    other = make.account()

    mine = make.alert(account)
    make.alert(other)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/alerts"))
    assert ids_of(body["items"]) == [mine.id]


def test_account_entity_links_report_identity_without_a_confidence(
    analyst_client, make, db
):
    """
    A deterministic link's confidence is null in the response too.

    Pinned at the API boundary as well as in the database, because the
    interface decides what to render from this field: null means "identity",
    a number means "inferred, with this much confidence".
    """
    account = make.account()
    entity = make.entity()
    make.entity_link(account, entity)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ACCOUNTS}/{account.id}/entities"))
    row = body["items"][0]

    assert row["match_method"] == "EXACT"
    assert row["confidence"] is None


def test_entity_links_respect_a_point_in_time(analyst_client, make, db):
    """
    `as_of` returns the links that were valid then.

    Links are time-bounded rather than deleted, because a link that was true
    last year is still a fact about last year. A query dated before a link
    started, or after it ended, must not see it — otherwise a point-in-time
    investigation is contaminated by what was learned later.
    """
    account = make.account()
    entity = make.entity()

    make.entity_link(
        account, entity, valid_from=days_ago(400), valid_to=days_ago(200)
    )
    db.commit()

    during = assert_ok(
        analyst_client.get(
            f"{ACCOUNTS}/{account.id}/entities",
            params={"as_of": days_ago(300).isoformat()},
        )
    )
    after = assert_ok(
        analyst_client.get(
            f"{ACCOUNTS}/{account.id}/entities",
            params={"as_of": days_ago(10).isoformat()},
        )
    )

    assert len(during["items"]) == 1
    assert after["items"] == []
