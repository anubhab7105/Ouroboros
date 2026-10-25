"""
Entities: pseudonymous identifiers and the accounts linked to them.

This is the part of the platform most capable of causing harm when presented
badly, because a shared identifier is a strong-looking signal with a long list
of innocent explanations: families share handsets, telecoms reissue phone
numbers, cyber cafes and branch tablets open accounts for strangers, and
carrier-grade NAT puts thousands of unrelated subscribers behind one address.

So three properties are pinned hard here.

**The raw identifier hash is never returned.** `identifier_display` is a label
— the stored display form if there is one, otherwise a derived
`device-entity-ab12cd34`. The hash itself stays in the database.

**Links are time-bounded, never deleted.** A link that was true last year is a
fact about last year, and a point-in-time query must see the world as it stood
rather than as it is now.

**Verification is a human decision with a reviewer attached.** Changing a
link's verification state is a senior action, and the record says who decided
and when.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.models import (
    AccountStatus,
    AccountType,
    EntityType,
    MatchMethod,
    VerificationState,
)

from tests.utils import (
    assert_error,
    assert_ok,
    assert_paginated,
    days_ago,
    ids_of,
    unique_id,
)

pytestmark = [pytest.mark.graph, pytest.mark.api]


ENTITIES = "/api/v1/entities"


# -----------------------------------------------------------------------------
# The list
# -----------------------------------------------------------------------------


def test_list_entities(analyst_client, make, db):
    entity = make.entity(entity_type=EntityType.DEVICE)
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(ENTITIES)))

    assert entity.id in ids_of(body["items"])
    assert body["caveats"]


def test_the_identifier_hash_is_never_returned(analyst_client, make, db):
    """
    The response carries a label, not the stored hash.

    The hash is the thing that lets two datasets be joined on a person. It is
    stored so that matching can happen server-side and it does not leave.
    """
    secret_hash = unique_id("verysecrethash")
    make.entity(identifier_hash=secret_hash)
    db.commit()

    response = analyst_client.get(ENTITIES)
    assert_ok(response)

    assert secret_hash not in response.text
    assert "identifier_hash" not in response.text


def test_an_entity_without_a_display_form_gets_a_derived_label(analyst_client, make, db):
    """
    Most identifiers are held only as hashes, and the label is derived.

    `device-entity-ab12cd34`: enough to refer to the thing in conversation and
    in a case note, without disclosing it. The alternative — an empty string —
    would render as a blank row in every table that lists entities.
    """
    entity = make.entity(entity_type=EntityType.PHONE_HASH, identifier_display=None)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ENTITIES}/{entity.id}"))
    label = body["entity"]["identifier_display"]

    assert label
    assert "phone_hash" in label.lower()
    assert entity.id[:8] in label


def test_a_stored_display_form_is_used_when_present(analyst_client, make, db):
    """
    A UPI handle is already public-facing, so it can be shown as it is.

    The distinction is the point: a handle a victim quoted in a complaint is
    useful to display, and a device fingerprint is not.
    """
    entity = make.entity(
        entity_type=EntityType.UPI_ID, identifier_display="suspect@examplebank"
    )
    db.commit()

    body = assert_ok(analyst_client.get(f"{ENTITIES}/{entity.id}"))
    assert body["entity"]["identifier_display"] == "suspect@examplebank"


def test_filter_by_entity_type(analyst_client, make, db):
    device = make.entity(entity_type=EntityType.DEVICE)
    make.entity(entity_type=EntityType.IP_HASH)
    db.commit()

    body = assert_ok(analyst_client.get(ENTITIES, params={"entity_type": "DEVICE"}))

    assert ids_of(body["items"]) == [device.id]


def test_an_unknown_entity_type_is_rejected(analyst_client):
    assert_error(analyst_client.get(ENTITIES, params={"entity_type": "FINGERPRINT"}), 422)


def test_link_counts_are_opt_in(analyst_client, make, db):
    """
    Counting links is a join per row, so the list does not do it unasked.

    When asked, the counts separate verified from inferred, because an entity
    with four verified links and one with four guesses are not the same
    finding.
    """
    shared, accounts, _ = make.shared_identifier_cluster(members=3)
    db.commit()

    without = assert_ok(analyst_client.get(ENTITIES))
    row = next(item for item in without["items"] if item["id"] == shared.id)
    assert row.get("account_link_count") is None

    with_counts = assert_ok(analyst_client.get(ENTITIES, params={"include_link_counts": True}))
    row = next(item for item in with_counts["items"] if item["id"] == shared.id)

    assert row["account_link_count"] == 3
    assert row["active_account_link_count"] == 3


def test_a_null_link_count_means_not_computed_not_zero(analyst_client, make, db):
    """
    Absent is not zero.

    A table column that read `row.account_link_count > 0` would be comparing
    against `null` and quietly answering "no links" for every entity on a page
    that did not request counts.
    """
    make.shared_identifier_cluster(members=2)
    db.commit()

    body = assert_ok(analyst_client.get(ENTITIES))

    for row in body["items"]:
        assert row.get("account_link_count") is None


# -----------------------------------------------------------------------------
# One entity
# -----------------------------------------------------------------------------


def test_entity_detail_separates_verified_from_inferred_links(analyst_client, make, db):
    """
    Four counts, not one.

    "Linked to five accounts" is the kind of summary that gets read aloud in a
    meeting. Whether those five are exact matches or normalisation guesses
    changes what it means entirely, so the detail reports both.
    """
    entity = make.entity()
    accounts = make.accounts(4)

    make.entity_link(accounts[0], entity, verification_state=VerificationState.VERIFIED)
    make.entity_link(accounts[1], entity, verification_state=VerificationState.VERIFIED)
    make.entity_link(
        accounts[2],
        entity,
        match_method=MatchMethod.NORMALIZED,
        confidence=0.8,
    )
    make.entity_link(
        accounts[3],
        entity,
        match_method=MatchMethod.ENTITY_TEMPORAL,
        confidence=0.55,
    )
    db.commit()

    body = assert_ok(analyst_client.get(f"{ENTITIES}/{entity.id}"))

    assert body["account_link_count"] == 4
    assert body["verified_account_link_count"] == 2
    assert body["inferred_account_link_count"] == 2
    assert body["caveats"]


def test_entity_detail_link_counts_respect_a_point_in_time(analyst_client, make, db):
    """
    `as_of` counts the links that were open then.

    An entity shared by four accounts today and by one a year ago is two
    different findings, and an investigation dated to last year must see last
    year's.
    """
    entity = make.entity()
    accounts = make.accounts(2)

    make.entity_link(accounts[0], entity, valid_from=days_ago(500))
    make.entity_link(accounts[1], entity, valid_from=days_ago(10))
    db.commit()

    now = assert_ok(analyst_client.get(f"{ENTITIES}/{entity.id}"))
    then = assert_ok(
        analyst_client.get(
            f"{ENTITIES}/{entity.id}", params={"as_of": days_ago(100).isoformat()}
        )
    )

    assert now["active_account_link_count"] == 2
    assert then["active_account_link_count"] == 1


def test_unknown_entity_is_404(analyst_client):
    assert_error(analyst_client.get(f"{ENTITIES}/not-a-real-entity"), 404)


# -----------------------------------------------------------------------------
# Linked accounts
# -----------------------------------------------------------------------------


def test_entity_accounts_lists_the_cluster(analyst_client, make, db):
    shared, accounts, _ = make.shared_identifier_cluster(members=4)
    db.commit()

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{ENTITIES}/{shared.id}/accounts"))
    )

    assert body["total"] == 4
    linked = {row["account_id"] for row in body["items"]}
    assert linked == {account.id for account in accounts}


def test_each_link_embeds_a_bounded_account_summary(analyst_client, make, db):
    """
    Enough to recognise the account, not its risk history.

    A cluster view that embedded each account's assessment would turn "these
    accounts share a device" into "these high-risk accounts share a device",
    which is the conclusion the analyst is supposed to be reaching, not the
    premise.
    """
    shared, accounts, _ = make.shared_identifier_cluster(members=2)
    make.assessment(accounts[0], score=95)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ENTITIES}/{shared.id}/accounts"))
    summary = body["items"][0]["account"]

    assert summary["id"]
    assert summary["account_type"]
    assert "latest_assessment" not in summary
    assert "score" not in summary


def test_filter_linked_accounts_by_type(analyst_client, make, db):
    entity = make.entity()
    merchant = make.account(account_type=AccountType.MERCHANT)
    individual = make.account(account_type=AccountType.INDIVIDUAL)

    make.entity_link(merchant, entity)
    make.entity_link(individual, entity)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{ENTITIES}/{entity.id}/accounts", params={"account_type": "MERCHANT"}
        )
    )

    assert len(body["items"]) == 1
    assert body["items"][0]["account_id"] == merchant.id


def test_filter_linked_accounts_by_status(analyst_client, make, db):
    entity = make.entity()
    dormant = make.account(status=AccountStatus.DORMANT)
    active = make.account(status=AccountStatus.ACTIVE)

    make.entity_link(dormant, entity)
    make.entity_link(active, entity)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{ENTITIES}/{entity.id}/accounts", params={"account_status": "DORMANT"}
        )
    )

    assert len(body["items"]) == 1
    assert body["items"][0]["account_id"] == dormant.id


def test_filter_links_by_match_method(analyst_client, make, db):
    entity = make.entity()
    exact_account, inferred_account = make.accounts(2)

    make.entity_link(exact_account, entity, match_method=MatchMethod.EXACT)
    make.entity_link(
        inferred_account, entity, match_method=MatchMethod.NORMALIZED, confidence=0.7
    )
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{ENTITIES}/{entity.id}/accounts", params={"match_method": "NORMALIZED"}
        )
    )

    assert len(body["items"]) == 1
    assert body["items"][0]["account_id"] == inferred_account.id


def test_a_closed_link_is_retained_and_dated(analyst_client, make, db):
    """
    Links end; they are not removed.

    `valid_to` is when the link stopped being true. Deleting it instead would
    make a past investigation unreproducible — the case notes would reference
    a connection with no record of it.
    """
    entity = make.entity()
    account = make.account()

    make.entity_link(
        account, entity, valid_from=days_ago(400), valid_to=days_ago(100)
    )
    db.commit()

    body = assert_ok(analyst_client.get(f"{ENTITIES}/{entity.id}/accounts"))

    assert body["total"] == 1
    assert body["items"][0]["valid_to"] is not None


def test_active_only_excludes_closed_links(analyst_client, make, db):
    entity = make.entity()
    current, past = make.accounts(2)

    make.entity_link(current, entity)
    make.entity_link(past, entity, valid_from=days_ago(400), valid_to=days_ago(100))
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{ENTITIES}/{entity.id}/accounts", params={"active_only": True}
        )
    )

    assert len(body["items"]) == 1
    assert body["items"][0]["account_id"] == current.id


def test_as_of_returns_the_links_that_were_open_then(analyst_client, make, db):
    """
    The world as it stood, not as it is.

    A link that opened after the date must not appear: a point-in-time
    investigation contaminated by later knowledge produces conclusions that
    cannot be reproduced and cannot be defended.
    """
    entity = make.entity()
    old, new = make.accounts(2)

    make.entity_link(old, entity, valid_from=days_ago(500), valid_to=days_ago(200))
    make.entity_link(new, entity, valid_from=days_ago(30))
    db.commit()

    then = assert_ok(
        analyst_client.get(
            f"{ENTITIES}/{entity.id}/accounts",
            params={"as_of": days_ago(300).isoformat(), "active_only": True},
        )
    )

    assert len(then["items"]) == 1
    assert then["items"][0]["account_id"] == old.id


# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------


def test_a_senior_investigator_can_change_a_verification_state(
    senior_client, make, db
):
    entity = make.entity()
    account = make.account()
    link = make.entity_link(
        account,
        entity,
        match_method=MatchMethod.NORMALIZED,
        confidence=0.7,
        verification_state=VerificationState.NEEDS_REVIEW,
    )
    db.commit()

    body = assert_ok(
        senior_client.patch(
            f"{ENTITIES}/{entity.id}/links/{link.id}/verification-state",
            json={"verification_state": "VERIFIED", "note": "Confirmed against the ledger."},
        )
    )

    assert body


def test_an_analyst_cannot_change_a_verification_state(analyst_client, make, db):
    """
    Verification is a senior decision, enforced on the server.

    Accepting a link means later work can rely on it, including a report that
    leaves the building. That is not a judgement to make without the authority
    to make it, and the frontend gates the control for the same reason — but
    the gate that matters is this one.
    """
    entity = make.entity()
    account = make.account()
    link = make.entity_link(account, entity, match_method=MatchMethod.NORMALIZED, confidence=0.6)
    db.commit()

    assert_error(
        analyst_client.patch(
            f"{ENTITIES}/{entity.id}/links/{link.id}/verification-state",
            json={"verification_state": "VERIFIED"},
        ),
        403,
    )


def test_an_auditor_cannot_change_a_verification_state(auditor_client, make, db):
    entity = make.entity()
    account = make.account()
    link = make.entity_link(account, entity, match_method=MatchMethod.NORMALIZED, confidence=0.6)
    db.commit()

    assert_error(
        auditor_client.patch(
            f"{ENTITIES}/{entity.id}/links/{link.id}/verification-state",
            json={"verification_state": "REJECTED"},
        ),
        403,
    )


def test_an_unknown_verification_state_is_rejected(senior_client, make, db):
    entity = make.entity()
    account = make.account()
    link = make.entity_link(account, entity)
    db.commit()

    assert_error(
        senior_client.patch(
            f"{ENTITIES}/{entity.id}/links/{link.id}/verification-state",
            json={"verification_state": "PROBABLY_FINE"},
        ),
        422,
    )


def test_a_link_belonging_to_another_entity_is_404(senior_client, make, db):
    """
    The link id is checked against the entity in the path.

    Otherwise the entity id is decoration and a caller could edit any link by
    guessing its id — the classic broken-object-level-authorisation shape,
    even though both ids belong to the same permission scope.
    """
    first, second = make.entity(), make.entity()
    account = make.account()

    link_on_first = make.entity_link(account, first)
    db.commit()

    assert_error(
        senior_client.patch(
            f"{ENTITIES}/{second.id}/links/{link_on_first.id}/verification-state",
            json={"verification_state": "VERIFIED"},
        ),
        404,
    )


def test_verification_records_the_reviewer(senior_client, make, db, users):
    """
    Who decided, and when.

    A verification state with no attribution is an assertion from nobody. The
    whole value of a human review is that a person is accountable for it.
    """
    from app.models import AccountEntityLink

    entity = make.entity()
    account = make.account()
    link = make.entity_link(
        account, entity, match_method=MatchMethod.NORMALIZED, confidence=0.7
    )
    db.commit()

    assert_ok(
        senior_client.patch(
            f"{ENTITIES}/{entity.id}/links/{link.id}/verification-state",
            json={"verification_state": "VERIFIED", "note": "Checked."},
        )
    )

    db.expire_all()
    stored = db.get(AccountEntityLink, link.id)

    assert stored is not None
    assert stored.verification_state == VerificationState.VERIFIED


# -----------------------------------------------------------------------------
# Nested collections
# -----------------------------------------------------------------------------


def test_entity_correlations_are_inferred_and_say_so(analyst_client, make, db):
    """
    A complaint linked through a shared identifier is a tier-3 inference.

    It is the weakest kind of link the platform draws between a complaint and
    an account, and it carries a confidence and an unreviewed state to match.
    """
    entity = make.entity()
    account = make.account()
    make.entity_link(account, entity)

    complaint = make.complaint()
    make.correlation(complaint, entity=entity, match_tier=3, confidence=0.58)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ENTITIES}/{entity.id}/complaint-correlations"))

    assert len(body["items"]) == 1
    row = body["items"][0]

    assert row["match_tier"] == 3
    assert row["deterministic"] is False
    assert Decimal(str(row["confidence"])) < Decimal("1")
    assert row["review_state"] == "UNREVIEWED"


def test_entity_alerts_can_be_empty(analyst_client, make, db):
    """
    An identifier with no alerts is the normal case, and an empty list says so.

    Not a 404: the entity exists and has no alerts, which is different from
    the entity not existing.
    """
    entity = make.entity()
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(f"{ENTITIES}/{entity.id}/alerts")))
    assert body["items"] == []
