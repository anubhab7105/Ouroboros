"""
Complaint correlation: the five tiers and the review that governs them.

This is the part of the platform where a presentation mistake does the most
damage, because the output is "this account is connected to a reported crime"
and the strength of that claim varies by a factor nobody can see in the
number.

The tiers:

1. The complaint names the account directly.
2. The complaint quotes a transaction reference that exists.
3. A shared identifier within the complaint window.
4. Amount and time proximity.
5. A reference extracted from the narrative text.

**Tiers 1 and 2 are deterministic.** The reference either matches or it does
not. They carry no confidence, because certainty about an exact match is not
the same kind of thing as a probability — putting it in the same column as
0.94 invites a comparison that means nothing. They need no review, because
there is nothing for a human to decide.

**Tiers 3 to 5 are inferences.** They carry a confidence and a review state,
and they start `UNREVIEWED`. Until somebody accepts one it is a lead, and the
interface says so.

The single most consequential error this module guards against is an inferred
link rendered as certain. That is how an investigation ends up aimed at the
wrong person.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.models import ComplaintReviewState, MatchMethod

from tests.utils import assert_error, assert_ok, assert_paginated, ids_of

pytestmark = pytest.mark.complaints


COMPLAINTS = "/api/v1/complaints"

DETERMINISTIC_TIERS = [1, 2]
INFERRED_TIERS = [3, 4, 5]


def _review_url(complaint_id, correlation_id):
    return f"{COMPLAINTS}/{complaint_id}/correlations/{correlation_id}/review-state"


# -----------------------------------------------------------------------------
# The tier contract
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("tier", DETERMINISTIC_TIERS)
def test_a_deterministic_tier_carries_no_confidence(analyst_client, make, db, tier):
    """
    Null confidence, and `deterministic: true`.

    Not 1.0. A confidence of 1.000 sits in the same column as 0.94 and reads
    as "we are very sure", when the actual statement is "the reference
    matched". The interface renders the null as the word "identity" for
    exactly this reason.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)
    make.correlation(complaint, account=account, match_tier=tier)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/correlations"))
    row = body["items"][0]

    assert row["match_tier"] == tier
    assert row["deterministic"] is True
    assert row["confidence"] is None


@pytest.mark.parametrize("tier", INFERRED_TIERS)
def test_an_inferred_tier_carries_a_confidence_below_one(analyst_client, make, db, tier):
    """
    A confidence, and it is strictly less than 1.

    An inference that reported 1.0 would be indistinguishable from an identity
    match in every sort, filter and chart.
    """
    account = make.account()
    complaint = make.complaint()
    make.correlation(complaint, account=account, match_tier=tier, confidence=0.72)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/correlations"))
    row = body["items"][0]

    assert row["match_tier"] == tier
    assert row["deterministic"] is False
    assert row["confidence"] is not None
    assert Decimal(str(row["confidence"])) < Decimal("1")


@pytest.mark.parametrize("tier", INFERRED_TIERS)
def test_an_inferred_correlation_starts_unreviewed(analyst_client, make, db, tier):
    """
    Nobody has accepted it yet, and the row says so.

    `UNREVIEWED` is what keeps an inference out of reports and out of
    conclusions until a person has agreed with it.
    """
    account = make.account()
    complaint = make.complaint()
    make.correlation(complaint, account=account, match_tier=tier, confidence=0.6)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/correlations"))
    assert body["items"][0]["review_state"] == "UNREVIEWED"


def test_tier_one_and_two_do_not_need_review(analyst_client, make, db):
    """
    An identity match arrives already accepted.

    Asking a human to confirm that a quoted reference exists is work with no
    decision in it, and a queue full of such items is a queue nobody reads.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)
    make.correlation(complaint, account=account, match_tier=1)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/correlations"))
    assert body["items"][0]["review_state"] != "UNREVIEWED"


def test_the_tier_is_always_in_range(analyst_client, make, db):
    """
    One to five, and the filter enforces it.

    A tier outside the range would be an unclassified correlation, and the
    interface would have no rule for how to present it.
    """
    assert_error(
        analyst_client.get(f"{COMPLAINTS}/x/correlations", params={"match_tier": 0}), 422
    )
    assert_error(
        analyst_client.get(f"{COMPLAINTS}/x/correlations", params={"match_tier": 6}), 422
    )


# -----------------------------------------------------------------------------
# Filtering
# -----------------------------------------------------------------------------


def test_filter_correlations_by_tier(analyst_client, make, db):
    account = make.account()
    complaint = make.complaint(suspected_account=account)

    named = make.correlation(complaint, account=account, match_tier=1)
    make.correlation(complaint, account=account, match_tier=4, confidence=0.5)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{COMPLAINTS}/{complaint.id}/correlations", params={"match_tier": 1}
        )
    )
    assert ids_of(body["items"]) == [named.id]


def test_filter_correlations_by_determinism(analyst_client, make, db):
    """
    The filter an investigator reaches for first.

    "What did the victim actually tell us" versus "what did we guess" is the
    first question when deciding where to spend an hour.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)

    named = make.correlation(complaint, account=account, match_tier=1)
    inferred = make.correlation(complaint, account=account, match_tier=3, confidence=0.6)
    db.commit()

    deterministic = assert_ok(
        analyst_client.get(
            f"{COMPLAINTS}/{complaint.id}/correlations", params={"deterministic": True}
        )
    )
    guessed = assert_ok(
        analyst_client.get(
            f"{COMPLAINTS}/{complaint.id}/correlations", params={"deterministic": False}
        )
    )

    assert ids_of(deterministic["items"]) == [named.id]
    assert ids_of(guessed["items"]) == [inferred.id]


def test_filter_correlations_by_review_state(analyst_client, make, db):
    account = make.account()
    complaint = make.complaint()

    unreviewed = make.correlation(
        complaint, account=account, match_tier=4, confidence=0.6
    )
    make.correlation(
        complaint,
        account=account,
        match_tier=4,
        confidence=0.6,
        review_state=ComplaintReviewState.REJECTED,
    )
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{COMPLAINTS}/{complaint.id}/correlations",
            params={"review_state": "UNREVIEWED"},
        )
    )
    assert ids_of(body["items"]) == [unreviewed.id]


def test_filter_correlations_by_match_method(analyst_client, make, db):
    account = make.account()
    complaint = make.complaint()

    narrative = make.correlation(
        complaint,
        account=account,
        match_tier=5,
        match_method=MatchMethod.NARRATIVE_EXTRACTION,
        confidence=0.4,
    )
    make.correlation(
        complaint,
        account=account,
        match_tier=3,
        match_method=MatchMethod.ENTITY_TEMPORAL,
        confidence=0.6,
    )
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{COMPLAINTS}/{complaint.id}/correlations",
            params={"match_method": "NARRATIVE_EXTRACTION"},
        )
    )
    assert ids_of(body["items"]) == [narrative.id]


def test_correlations_are_scoped_to_their_complaint(analyst_client, make, db):
    account = make.account()
    first, second = make.complaint(), make.complaint()

    mine = make.correlation(first, account=account, match_tier=1)
    make.correlation(second, account=account, match_tier=1)
    db.commit()

    body = assert_ok(analyst_client.get(f"{COMPLAINTS}/{first.id}/correlations"))
    assert ids_of(body["items"]) == [mine.id]


def test_a_correlation_names_exactly_one_target(analyst_client, make, db):
    """
    An account, a transaction or an identifier — not several at once.

    A correlation that pointed at two things would be two findings sharing one
    review state, and accepting it would accept both.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)
    make.correlation(complaint, account=account, match_tier=1)
    db.commit()

    row = assert_ok(
        analyst_client.get(f"{COMPLAINTS}/{complaint.id}/correlations")
    )["items"][0]

    targets = [row["account_id"], row["transaction_id"], row["entity_id"]]
    assert sum(1 for target in targets if target) == 1


# -----------------------------------------------------------------------------
# Review
# -----------------------------------------------------------------------------


def test_a_senior_investigator_can_accept_an_inference(senior_client, make, db):
    account = make.account()
    complaint = make.complaint()
    correlation = make.correlation(
        complaint, account=account, match_tier=3, confidence=0.68
    )
    db.commit()

    body = assert_ok(
        senior_client.post(
            _review_url(complaint.id, correlation.id),
            json={
                "review_state": "ACCEPTED",
                "note": "Device is shared with two accounts already in the case.",
            },
        )
    )

    assert body["changed"] is True
    assert body["previous_state"] == "UNREVIEWED"
    assert body["new_state"] == "ACCEPTED"
    assert body["audited"] is True
    assert body["correlation"]["review_state"] == "ACCEPTED"


def test_a_rejection_is_recorded_as_a_decision(senior_client, make, db):
    """
    Rejecting is as valuable as accepting, and is recorded the same way.

    A rejection with a stated reason is the only feedback the correlation
    rules ever get. Without it, a tier that produces nothing but noise keeps
    producing it forever.
    """
    account = make.account()
    complaint = make.complaint()
    correlation = make.correlation(
        complaint, account=account, match_tier=4, confidence=0.52
    )
    db.commit()

    body = assert_ok(
        senior_client.post(
            _review_url(complaint.id, correlation.id),
            json={
                "review_state": "REJECTED",
                "note": "Amount and timing are coincidental; unrelated payer.",
            },
        )
    )

    assert body["new_state"] == "REJECTED"
    assert body["changed"] is True


def test_needs_more_info_is_a_valid_outcome(senior_client, make, db):
    """
    "Cannot decide on what we hold" is a real answer.

    Forcing a reviewer to choose accept or reject produces guesses, and a
    guessed acceptance is worse than an unreviewed lead because later work
    relies on it.
    """
    account = make.account()
    complaint = make.complaint()
    correlation = make.correlation(
        complaint, account=account, match_tier=5, confidence=0.33
    )
    db.commit()

    body = assert_ok(
        senior_client.post(
            _review_url(complaint.id, correlation.id),
            json={"review_state": "NEEDS_MORE_INFO"},
        )
    )
    assert body["new_state"] == "NEEDS_MORE_INFO"


def test_reviewing_twice_to_the_same_state_reports_no_change(senior_client, make, db):
    account = make.account()
    complaint = make.complaint()
    correlation = make.correlation(
        complaint, account=account, match_tier=3, confidence=0.6
    )
    db.commit()

    url = _review_url(complaint.id, correlation.id)

    assert_ok(senior_client.post(url, json={"review_state": "ACCEPTED"}))
    second = assert_ok(senior_client.post(url, json={"review_state": "ACCEPTED"}))

    assert second["changed"] is False
    assert second["previous_state"] == second["new_state"] == "ACCEPTED"


def test_a_decision_can_be_changed(senior_client, make, db):
    """
    Review is revisable.

    A reviewer who accepted a link and then found the contradicting
    transaction has to be able to say so, and the change has to be recorded
    rather than overwritten silently.
    """
    account = make.account()
    complaint = make.complaint()
    correlation = make.correlation(
        complaint, account=account, match_tier=3, confidence=0.6
    )
    db.commit()

    url = _review_url(complaint.id, correlation.id)

    assert_ok(senior_client.post(url, json={"review_state": "ACCEPTED"}))
    body = assert_ok(
        senior_client.post(
            url,
            json={
                "review_state": "REJECTED",
                "note": "The shared number was reissued; the accounts are unrelated.",
            },
        )
    )

    assert body["previous_state"] == "ACCEPTED"
    assert body["new_state"] == "REJECTED"
    assert body["changed"] is True


def test_an_analyst_cannot_review(analyst_client, make, db):
    """
    Review is senior-only, enforced on the server.

    Accepting an inference licenses later work to rely on it, including a
    report that may leave the organisation. The frontend gates the control for
    the same reason, but this is the gate that counts.
    """
    account = make.account()
    complaint = make.complaint()
    correlation = make.correlation(
        complaint, account=account, match_tier=3, confidence=0.6
    )
    db.commit()

    assert_error(
        analyst_client.post(
            _review_url(complaint.id, correlation.id),
            json={"review_state": "ACCEPTED"},
        ),
        403,
    )


def test_an_auditor_cannot_review(auditor_client, make, db):
    account = make.account()
    complaint = make.complaint()
    correlation = make.correlation(
        complaint, account=account, match_tier=3, confidence=0.6
    )
    db.commit()

    assert_error(
        auditor_client.post(
            _review_url(complaint.id, correlation.id),
            json={"review_state": "REJECTED"},
        ),
        403,
    )


def test_an_unknown_review_state_is_rejected(senior_client, make, db):
    account = make.account()
    complaint = make.complaint()
    correlation = make.correlation(
        complaint, account=account, match_tier=3, confidence=0.6
    )
    db.commit()

    assert_error(
        senior_client.post(
            _review_url(complaint.id, correlation.id),
            json={"review_state": "PROBABLY_RIGHT"},
        ),
        422,
    )


def test_a_correlation_from_another_complaint_is_404(senior_client, make, db):
    """
    The complaint id in the path is checked against the correlation.

    Otherwise it is decoration, and any correlation could be reviewed by
    guessing its id under any complaint — a broken-object-level-authorisation
    shape even within one permission scope.
    """
    account = make.account()
    first, second = make.complaint(), make.complaint()
    correlation = make.correlation(first, account=account, match_tier=3, confidence=0.6)
    db.commit()

    assert_error(
        senior_client.post(
            _review_url(second.id, correlation.id),
            json={"review_state": "ACCEPTED"},
        ),
        404,
    )


def test_review_does_not_disclose_the_narrative(senior_client, make, db):
    """
    Even a senior reviewer's action response does not echo the text.

    The narrative is read through the endpoint that is gated for it, with the
    access recorded. A review response is not that endpoint.
    """
    account = make.account()
    complaint = make.complaint(
        narrative_raw="Victim describes being coached through a transfer by phone."
    )
    correlation = make.correlation(complaint, account=account, match_tier=5, confidence=0.4)
    db.commit()

    response = senior_client.post(
        _review_url(complaint.id, correlation.id),
        json={"review_state": "NEEDS_MORE_INFO"},
    )
    assert_ok(response)

    assert "coached" not in response.text
    assert response.json()["complaint"]["narrative_available"] is True


# -----------------------------------------------------------------------------
# Evidence and caveats
# -----------------------------------------------------------------------------


def test_a_correlation_carries_evidence_references(analyst_client, make, db):
    """
    What the correlation was based on, as references rather than values.

    A reference an investigator can look up is checkable. A copied value is
    not: it cannot be re-derived, and it duplicates data that may since have
    been corrected.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)
    make.correlation(
        complaint,
        account=account,
        match_tier=1,
        evidence_refs_json=[f"complaint:{complaint.reference}", f"account:{account.id}"],
    )
    db.commit()

    row = assert_ok(
        analyst_client.get(f"{COMPLAINTS}/{complaint.id}/correlations")
    )["items"][0]

    assert row["evidence_refs"]
    assert any("complaint:" in ref for ref in row["evidence_refs"])


def test_correlation_lists_carry_caveats(analyst_client, make, db):
    """
    Every page says what a correlation is.

    These are the responses most likely to be read as "this account did it",
    so the qualification travels with them.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)
    make.correlation(complaint, account=account, match_tier=1)
    db.commit()

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{COMPLAINTS}/{complaint.id}/correlations"))
    )
    assert body["caveats"]


def test_a_tier_three_correlation_is_described_as_a_shared_identifier(
    analyst_client, make, db
):
    """
    The weakest link type the platform draws between a complaint and an account.

    Shared devices, recycled phone numbers and public terminals all produce
    this signal. It is a reason to look, and the response's match method says
    which kind of coincidence is on the table.
    """
    account = make.account()
    entity = make.entity()
    make.entity_link(account, entity)

    complaint = make.complaint()
    make.correlation(
        complaint,
        entity=entity,
        match_tier=3,
        match_method=MatchMethod.ENTITY_TEMPORAL,
        confidence=0.58,
    )
    db.commit()

    row = assert_ok(
        analyst_client.get(f"{COMPLAINTS}/{complaint.id}/correlations")
    )["items"][0]

    assert row["match_method"] == "ENTITY_TEMPORAL"
    assert row["entity_id"] == entity.id
    assert row["deterministic"] is False
