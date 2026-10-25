"""
Complaint reads.

A complaint is a person's account of a loss they suffered. That shapes
everything here, and two properties follow from it.

**The narrative does not travel.** Responses carry
`narrative_available: bool`, never the text. Reading a narrative is gated
behind `COMPLAINT_NARRATIVE_READ`, which is senior-only, because it is the
most sensitive text in the system: it describes something that happened to a
named person, often while they were being deceived. A list endpoint has no
business including it, and a correlation row certainly does not.

**An absence of correlations is not evidence.** Most complaints correlate to
nothing, because the account the money went to is usually at another bank or
is named only in prose. An empty list means the platform found no link, which
is different from there being none.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from tests.utils import (
    assert_error,
    assert_ok,
    assert_paginated,
    days_ago,
    ids_of,
)

pytestmark = [pytest.mark.complaints, pytest.mark.api]


COMPLAINTS = "/api/v1/complaints"

NARRATIVE = (
    "Complainant states that funds were debited after an unsolicited call "
    "from a person claiming to be bank staff."
)


# -----------------------------------------------------------------------------
# The list
# -----------------------------------------------------------------------------


def test_list_complaints(analyst_client, make, db):
    complaint = make.complaint()
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(COMPLAINTS)))

    assert complaint.id in ids_of(body["items"])
    assert body["caveats"]


def test_the_narrative_is_never_in_the_list(analyst_client, make, db):
    """
    A flag, not the text.

    The narrative is a victim's description of what happened to them. It is
    the single most sensitive field in the dataset, and a list endpoint that
    included it would put it in front of every role that can read complaints,
    in bulk, with no record of who read what.
    """
    make.complaint(narrative_raw=NARRATIVE)
    db.commit()

    response = analyst_client.get(COMPLAINTS)
    body = assert_ok(response)

    row = body["items"][0]
    assert row["narrative_available"] is True
    assert "narrative_raw" not in row
    assert "narrative" not in row

    assert "unsolicited call" not in response.text


def test_narrative_available_is_false_when_there_is_no_narrative(
    analyst_client, make, db
):
    """
    The flag distinguishes "withheld" from "absent".

    A complaint can arrive with no usable narrative — a bare referral, a
    truncated feed. An investigator needs to know which of the two they are
    looking at before deciding whether it is worth requesting access.
    """
    make.complaint(narrative_raw="   ")
    db.commit()

    body = assert_ok(analyst_client.get(COMPLAINTS))
    assert body["items"][0]["narrative_available"] is False


def test_filter_by_category(analyst_client, make, db):
    upi = make.complaint(category="UPI_FRAUD")
    make.complaint(category="INVESTMENT_FRAUD")
    db.commit()

    body = assert_ok(analyst_client.get(COMPLAINTS, params={"category": "UPI_FRAUD"}))
    assert ids_of(body["items"]) == [upi.id]


def test_filter_by_suspected_account(analyst_client, make, db):
    suspect, other = make.accounts(2)

    named = make.complaint(suspected_account=suspect)
    make.complaint(suspected_account=other)
    db.commit()

    body = assert_ok(
        analyst_client.get(COMPLAINTS, params={"suspected_account_id": suspect.id})
    )
    assert ids_of(body["items"]) == [named.id]


def test_filter_by_victim_account(analyst_client, make, db):
    victim = make.account()

    theirs = make.complaint(victim_account=victim)
    make.complaint()
    db.commit()

    body = assert_ok(
        analyst_client.get(COMPLAINTS, params={"victim_account_id": victim.id})
    )
    assert ids_of(body["items"]) == [theirs.id]


def test_filter_by_transaction_reference(analyst_client, make, db):
    quoted = make.complaint(transaction_reference="TXN-QUOTED-BY-VICTIM")
    make.complaint()
    db.commit()

    body = assert_ok(
        analyst_client.get(
            COMPLAINTS, params={"transaction_reference": "TXN-QUOTED-BY-VICTIM"}
        )
    )
    assert ids_of(body["items"]) == [quoted.id]


def test_filter_by_reported_window(analyst_client, make, db):
    old = make.complaint(reported_at=days_ago(300))
    recent = make.complaint(reported_at=days_ago(2))
    db.commit()

    body = assert_ok(
        analyst_client.get(COMPLAINTS, params={"date_from": days_ago(30).isoformat()})
    )

    returned = set(ids_of(body["items"]))
    assert recent.id in returned
    assert old.id not in returned


def test_filter_by_amount_range(analyst_client, make, db):
    small = make.complaint(amount=500)
    large = make.complaint(amount=800_000)
    db.commit()

    body = assert_ok(analyst_client.get(COMPLAINTS, params={"amount_min": 100_000}))

    returned = set(ids_of(body["items"]))
    assert large.id in returned
    assert small.id not in returned


def test_a_complaint_can_have_no_amount(analyst_client, make, db):
    """
    Amount is nullable, and null is common.

    Many complaints are filed before the loss is quantified, or describe an
    attempt that failed. A zero would make them look like no-loss incidents
    and would drag every average down.
    """
    make.complaint(amount=None)
    db.commit()

    body = assert_ok(analyst_client.get(COMPLAINTS))
    assert body["items"][0]["amount"] is None


def test_correlation_counts_are_opt_in(analyst_client, make, db):
    account, complaints, _ = make.complaint_linked_account(complaints=2)
    db.commit()

    without = assert_ok(analyst_client.get(COMPLAINTS))
    assert all(row.get("correlation_count") is None for row in without["items"])

    with_counts = assert_ok(
        analyst_client.get(COMPLAINTS, params={"include_correlation_count": True})
    )
    assert any(row["correlation_count"] == 1 for row in with_counts["items"])


def test_a_null_correlation_count_means_not_computed(analyst_client, make, db):
    """
    Null, not zero.

    A table column reading `row.correlation_count > 0` would compare against
    `null` and answer "no correlations" for every complaint on a page that did
    not request counts — which is precisely the "nothing found" reading that
    must never be produced by accident.
    """
    make.complaint()
    db.commit()

    body = assert_ok(analyst_client.get(COMPLAINTS))
    assert body["items"][0]["correlation_count"] is None


# -----------------------------------------------------------------------------
# One complaint
# -----------------------------------------------------------------------------


def test_get_one_complaint(analyst_client, make, db):
    complaint = make.complaint(amount=48_500, currency="INR")
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}"))

    assert body["id"] == complaint.id
    assert body["reference"] == complaint.reference
    assert Decimal(str(body["amount"])) == Decimal("48500")
    assert body["currency"] == "INR"


def test_the_detail_view_also_withholds_the_narrative(analyst_client, make, db):
    """
    Even one at a time, an analyst does not get the text.

    The permission is `COMPLAINT_NARRATIVE_READ`, which is senior-only. The
    detail endpoint is not a way around it.
    """
    complaint = make.complaint(narrative_raw=NARRATIVE)
    db.commit()

    response = analyst_client.get(f"{COMPLAINTS}/{complaint.id}")
    assert_ok(response)

    assert "unsolicited call" not in response.text
    assert response.json()["narrative_available"] is True


def test_unknown_complaint_is_404(analyst_client):
    assert_error(analyst_client.get(f"{COMPLAINTS}/not-a-real-complaint"), 404)


# -----------------------------------------------------------------------------
# Linked records
# -----------------------------------------------------------------------------


def test_linked_accounts_carry_their_match_quality(analyst_client, make, db):
    """
    Each linked account reports *how* it was linked.

    An account listed under a complaint without its tier reads as "the
    complaint named this account". At tier 1 that is true; at tier 4 it means
    "an amount and a time were close". The row carries the tier, the method,
    the confidence and the review state so the two cannot be confused.
    """
    suspect = make.account()
    complaint = make.complaint(suspected_account=suspect)
    make.correlation(complaint, account=suspect, match_tier=1)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/accounts"))

    assert len(body["items"]) == 1
    row = body["items"][0]

    assert row["id"] == suspect.id
    assert row["match_tier"] == 1
    assert row["deterministic"] is True
    assert row["confidence"] is None
    assert row["correlation_id"]


def test_linked_accounts_can_be_filtered_to_deterministic_only(
    analyst_client, make, db
):
    """
    "Show me only the accounts this complaint actually named."

    The filter exists so an investigator can separate what the victim said
    from what the platform inferred — which is the first thing anyone wants
    when deciding where to look.
    """
    named, guessed = make.accounts(2)
    complaint = make.complaint(suspected_account=named)

    make.correlation(complaint, account=named, match_tier=1)
    make.correlation(complaint, account=guessed, match_tier=4, confidence=0.55)
    db.commit()

    deterministic = assert_ok(
        analyst_client.get(
            f"{COMPLAINTS}/{complaint.id}/accounts", params={"deterministic": True}
        )
    )

    assert ids_of(deterministic["items"]) == [named.id]


def test_linked_transactions_carry_their_match_quality(analyst_client, make, db):
    sender, receiver = make.accounts(2)
    transfer = make.transaction(sender, receiver, reference="TXN-NAMED")

    complaint = make.complaint(transaction_reference="TXN-NAMED")
    make.correlation(complaint, transaction=transfer, match_tier=2)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/transactions"))

    assert len(body["items"]) == 1
    row = body["items"][0]

    assert row["id"] == transfer.id
    assert row["match_tier"] == 2
    assert row["deterministic"] is True
    assert row["reference"] == "TXN-NAMED"


def test_a_complaint_with_no_links_returns_empty_lists(analyst_client, make, db):
    """
    The normal case, and not a 404.

    Most complaints correlate to nothing: the beneficiary is at another bank,
    or is named only in prose. An empty list is the honest answer, and the
    caveats say what it does and does not mean.
    """
    complaint = make.complaint()
    db.commit()

    for path in ("accounts", "transactions", "entities", "correlations"):
        body = assert_paginated(
            assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/{path}"))
        )
        assert body["items"] == []
        assert body["total"] == 0
        assert body["caveats"]


def test_complaint_alerts_are_listed(analyst_client, make, db):
    suspect = make.account()
    complaint = make.complaint(suspected_account=suspect)
    make.correlation(complaint, account=suspect, match_tier=1)
    make.alert(suspect)
    db.commit()

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/alerts"))
    )
    assert isinstance(body["items"], list)


# -----------------------------------------------------------------------------
# Statistics
# -----------------------------------------------------------------------------


def test_stats_separate_deterministic_from_inferred(analyst_client, make, db):
    """
    Two counts, never one total.

    "412 correlations this month" is a number that means nothing on its own:
    412 identity matches is a working pipeline, and 412 tier-4 guesses is a
    noise generator. The split is the whole content of the measurement.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)

    make.correlation(complaint, account=account, match_tier=1)
    make.correlation(complaint, account=account, match_tier=4, confidence=0.6)
    make.correlation(complaint, account=account, match_tier=5, confidence=0.4)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/stats"))

    assert body["deterministic_count"] == 1
    assert body["inferred_count"] == 2
    assert body["total_correlations"] == 3


def test_stats_break_down_by_tier(analyst_client, make, db):
    """
    Per-tier counts, because the tiers are not interchangeable.

    A rise in tier-5 narrative extractions and a rise in tier-1 identity
    matches mean opposite things about the data feed.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)

    make.correlation(complaint, account=account, match_tier=1)
    make.correlation(complaint, account=account, match_tier=3, confidence=0.7)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/stats"))
    tiers = body["by_match_tier"]

    assert tiers
    assert sum(int(count) for count in tiers.values()) == 2


def test_stats_break_down_by_review_state(analyst_client, make, db):
    """
    How much inferred work is still unreviewed.

    This is the operational number: unreviewed inferences are leads nobody has
    accepted or rejected, and a growing pile of them means the correlation
    rules are never getting the feedback that would improve them.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)

    make.correlation(complaint, account=account, match_tier=4, confidence=0.6)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/stats"))

    assert body["by_review_state"]
    assert "UNREVIEWED" in body["by_review_state"]


def test_stats_state_their_period(analyst_client, make, db):
    """
    Every figure is "over this window", and the window is in the response.

    A statistic with no period is uninterpretable, and the one most likely to
    be screenshotted into a slide.
    """
    make.complaint()
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/stats"))

    assert body["period"]
    assert body["caveats"]


def test_stats_top_limit_is_bounded(analyst_client, make, db):
    make.complaint()
    db.commit()

    assert_error(analyst_client.get(f"{COMPLAINTS}/stats", params={"top_limit": 0}), 422)
    assert_error(
        analyst_client.get(f"{COMPLAINTS}/stats", params={"top_limit": 10_000}), 422
    )


def test_stats_on_an_empty_dataset_are_zeroes(analyst_client):
    """Zeroes, not an error. A new deployment has no complaints."""
    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/stats"))

    assert body["total_complaints"] == 0
    assert body["total_correlations"] == 0
    assert body["deterministic_count"] == 0
    assert body["inferred_count"] == 0


# -----------------------------------------------------------------------------
# Export
# -----------------------------------------------------------------------------


def test_the_export_bundle_says_whether_it_truncated(analyst_client, make, db):
    """
    A bundle that was capped says so and states the cap.

    An export is what gets attached to something that leaves the platform. A
    silently truncated one is a partial record presented as complete, which is
    the worst possible failure mode for a document somebody relies on.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)
    make.correlation(complaint, account=account, match_tier=1)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/export"))

    assert body["complaint"]["id"] == complaint.id
    assert body["correlation_total"] == 1
    assert body["correlation_truncated"] is False
    assert body["max_items"] > 0
    assert body["caveats"]


def test_the_export_does_not_carry_the_narrative_for_an_analyst(
    analyst_client, make, db
):
    """
    Export is not a privilege escalation.

    An endpoint that assembles a bundle is exactly where a sensitive field
    gets included by accident, because the code is about completeness.
    """
    complaint = make.complaint(narrative_raw=NARRATIVE)
    db.commit()

    response = analyst_client.get(f"{COMPLAINTS}/{complaint.id}/export")
    assert_ok(response)

    assert "unsolicited call" not in response.text


# -----------------------------------------------------------------------------
# History
# -----------------------------------------------------------------------------


def test_complaint_history_is_available(analyst_client, make, db):
    complaint = make.complaint()
    db.commit()

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/history"))
    )
    assert isinstance(body["items"], list)


def test_history_records_a_review_decision(senior_client, make, db):
    """
    Accepting or rejecting an inference is recorded against the complaint.

    The review is a human judgement that later work relies on, so who made it
    and when has to be recoverable.
    """
    account = make.account()
    complaint = make.complaint()
    correlation = make.correlation(complaint, account=account, match_tier=4, confidence=0.6)
    db.commit()

    assert_ok(
        senior_client.post(
            f"{COMPLAINTS}/{complaint.id}/correlations/{correlation.id}/review-state",
            json={"review_state": "REJECTED", "note": "Amount proximity is coincidental."},
        )
    )

    body = assert_paginated(
        assert_ok(senior_client.get(f"{COMPLAINTS}/{complaint.id}/history"))
    )

    assert body["total"] >= 1

    actions = {row["action"] for row in body["items"]}
    assert any("review" in action.lower() for action in actions), actions
