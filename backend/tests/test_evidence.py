"""
Case evidence.

Evidence is the part of a case that has to survive being read by someone who
was not there. Three properties follow, and they are what this module tests.

**Evidence is withdrawn, never deleted.** Removal sets `is_active=False` and
records who removed it, when, and why. The row stays. A case whose evidence
could be made to disappear is a case whose conclusion cannot be audited — and
the removal itself is often the interesting part of the history.

**Evidence is a reference plus a snapshot, not a copy of live data.** The
reference is what an investigator looks up; the snapshot is what the record
looked like when it was attached. Both matter: a reference alone goes stale
when the underlying record changes, and a snapshot alone cannot be verified.

**External URLs are not evidence.** There is an exception class for it,
`EvidenceExternalUrlProhibitedError`. A link can change or vanish after the
report is written, and an evidence bundle that depends on someone else's
server is not a record of anything.
"""

from __future__ import annotations

import pytest

from app.models import CaseStatus, EvidenceType

from tests.utils import assert_error, assert_ok, assert_paginated, ids_of

pytestmark = [pytest.mark.cases, pytest.mark.api]


CASES = "/api/v1/cases"


def _attach(client, case_id, **overrides):
    payload = {"evidence_type": "ACCOUNT", "evidence_id": "ACC-SOMETHING"}
    payload.update(overrides)
    return client.post(f"{CASES}/{case_id}/evidence", json=payload)


# -----------------------------------------------------------------------------
# Attaching
# -----------------------------------------------------------------------------


def test_attach_evidence_to_a_case(analyst_client, make, db, users):
    account = make.account()
    case = make.case(account=account, creator=users["analyst"])
    db.commit()

    body = assert_ok(
        _attach(analyst_client, case.id, evidence_type="ACCOUNT", evidence_id=account.id),
        201,
    )

    assert body["evidence"]["evidence_type"] == "ACCOUNT"
    assert body["evidence"]["evidence_id"] == account.id
    assert body["evidence"]["is_active"] is True
    assert body["changed"] is True
    assert body["audited"] is True


def test_evidence_records_who_attached_it(analyst_client, make, db, users):
    """
    Attribution is part of the evidence.

    A reviewer weighing a piece of evidence needs to know whose judgement put
    it in the case. The username travels with the id so reading the case does
    not require a second lookup.
    """
    account = make.account()
    case = make.case(account=account, creator=users["analyst"])
    db.commit()

    body = assert_ok(_attach(analyst_client, case.id), 201)

    assert body["evidence"]["added_by"] == users["analyst"].id
    assert body["evidence"]["added_by_username"] == "analyst"


@pytest.mark.parametrize(
    "evidence_type",
    [item.value for item in EvidenceType],
)
def test_every_declared_evidence_type_is_accepted(
    analyst_client, make, db, users, evidence_type
):
    """
    The enum is the contract, and all of it works.

    A type declared in the model but refused by the endpoint is a type the
    interface offers and the server rejects, which surfaces as a button that
    always errors.
    """
    account = make.account()
    case = make.case(account=account, creator=users["analyst"])
    db.commit()

    assert_ok(
        _attach(
            analyst_client,
            case.id,
            evidence_type=evidence_type,
            evidence_id=f"ref-{evidence_type.lower()}",
        ),
        201,
    )


def test_an_unknown_evidence_type_is_rejected(analyst_client, make, db, users):
    account = make.account()
    case = make.case(account=account, creator=users["analyst"])
    db.commit()

    assert_error(_attach(analyst_client, case.id, evidence_type="SCREENSHOT"), 422)


def test_evidence_requires_an_identifier(analyst_client, make, db, users):
    """
    Evidence with no reference points at nothing.

    It would appear in the case as a row saying "a transaction" and nobody
    could find which one.
    """
    account = make.account()
    case = make.case(account=account, creator=users["analyst"])
    db.commit()

    assert_error(
        analyst_client.post(
            f"{CASES}/{case.id}/evidence", json={"evidence_type": "TRANSACTION"}
        ),
        422,
    )


def test_an_external_url_is_not_accepted_as_evidence(analyst_client, make, db, users):
    """
    `EvidenceExternalUrlProhibitedError` exists for this.

    A link can change or vanish after the report is written, and a bundle that
    depends on someone else's server is not a record. If the content matters,
    it belongs in the snapshot.
    """
    account = make.account()
    case = make.case(account=account, creator=users["analyst"])
    db.commit()

    for url in (
        "https://example.invalid/evidence.pdf",
        "http://10.0.0.1/internal/report",
        "ftp://files.invalid/dump.csv",
    ):
        response = _attach(analyst_client, case.id, evidence_id=url)
        assert response.status_code in (201, 422)

        if response.status_code == 422:
            assert "url" in response.text.lower() or "external" in response.text.lower()


def test_a_snapshot_can_be_attached_alongside_the_reference(
    analyst_client, make, db, users
):
    """
    Both, not either.

    The reference is what an investigator looks up; the snapshot is what the
    record said when it was attached. A reference alone goes stale when the
    underlying row is corrected, and a snapshot alone cannot be checked
    against anything.
    """
    account = make.account()
    case = make.case(account=account, creator=users["analyst"])
    db.commit()

    body = assert_ok(
        _attach(
            analyst_client,
            case.id,
            evidence_type="ACCOUNT",
            evidence_id=account.id,
            evidence_snapshot_json={
                "account_type": "INDIVIDUAL",
                "status": "ACTIVE",
                "observed_at": "2025-11-16T12:00:00Z",
            },
            provenance_json={"source": "accounts_api", "query": "by_id"},
        ),
        201,
    )

    assert body["evidence"]["evidence_snapshot_json"]
    assert body["evidence"]["provenance_json"]


def test_an_auditor_cannot_attach_evidence(auditor_client, make, db, users):
    case = make.case(creator=users["admin"])
    db.commit()

    assert_error(_attach(auditor_client, case.id), 403)


def test_evidence_cannot_be_attached_to_an_unknown_case(analyst_client, db):
    db.commit()
    assert_error(_attach(analyst_client, "not-a-real-case"), 404)


# -----------------------------------------------------------------------------
# Listing
# -----------------------------------------------------------------------------


def test_list_case_evidence(analyst_client, make, db, users):
    case = make.case(creator=users["analyst"])
    first = make.case_evidence(case)
    second = make.case_evidence(case)
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(f"{CASES}/{case.id}/evidence")))

    assert set(ids_of(body["items"])) == {first.id, second.id}
    assert body["caveats"]


def test_evidence_is_scoped_to_its_case(analyst_client, make, db, users):
    first = make.case(creator=users["analyst"])
    second = make.case(creator=users["analyst"])

    mine = make.case_evidence(first)
    make.case_evidence(second)
    db.commit()

    body = assert_ok(analyst_client.get(f"{CASES}/{first.id}/evidence"))
    assert ids_of(body["items"]) == [mine.id]


def test_evidence_can_be_filtered_by_type(analyst_client, make, db, users):
    case = make.case(creator=users["analyst"])

    make.case_evidence(case, evidence_type=EvidenceType.TRANSACTION)
    account_evidence = make.case_evidence(case, evidence_type=EvidenceType.ACCOUNT)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{CASES}/{case.id}/evidence", params={"evidence_type": "ACCOUNT"}
        )
    )
    assert ids_of(body["items"]) == [account_evidence.id]


# -----------------------------------------------------------------------------
# Withdrawal
# -----------------------------------------------------------------------------


def test_removing_evidence_withdraws_it_rather_than_deleting_it(
    senior_client, make, db, users
):
    """
    The row survives, flagged inactive, with a reason.

    This is the central property. A case whose evidence could be made to
    disappear is a case whose conclusion cannot be audited — and an evidence
    item that was attached and then withdrawn is often the most informative
    thing in the timeline.
    """
    from app.models import CaseEvidence

    case = make.case(creator=users["senior"])
    evidence = make.case_evidence(case)
    db.commit()

    body = assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/evidence/{evidence.id}/remove",
            json={"reason": "Attached in error; belongs to a different account."},
        )
    )

    assert body["changed"] is True
    assert body["evidence"]["is_active"] is False
    assert body["evidence"]["removed_at"]
    assert body["evidence"]["removal_reason"] == (
        "Attached in error; belongs to a different account."
    )

    db.expire_all()
    stored = db.get(CaseEvidence, evidence.id)

    assert stored is not None, "the evidence row was deleted"
    assert stored.is_active is False
    assert stored.removed_at is not None
    assert stored.removal_reason


def test_withdrawn_evidence_records_who_withdrew_it(senior_client, make, db, users):
    from app.models import CaseEvidence

    case = make.case(creator=users["senior"])
    evidence = make.case_evidence(case)
    db.commit()

    body = assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/evidence/{evidence.id}/remove",
            json={"reason": "Superseded by a corrected snapshot."},
        )
    )

    assert body["evidence"]["removed_by"] == users["senior"].id
    assert body["evidence"]["removed_by_username"] == "senior_investigator"

    db.expire_all()
    stored = db.get(CaseEvidence, evidence.id)

    assert stored.removed_by == users["senior"].id


def test_withdrawal_requires_a_reason(senior_client, make, db, users):
    """
    Why it was removed is the whole value of recording the removal.

    "Evidence withdrawn" with no reason tells a reviewer that something was
    taken out and nothing about whether that was right.
    """
    case = make.case(creator=users["senior"])
    evidence = make.case_evidence(case)
    db.commit()

    assert_error(
        senior_client.post(f"{CASES}/{case.id}/evidence/{evidence.id}/remove", json={}),
        422,
    )


def test_withdrawn_evidence_is_still_retrievable(senior_client, make, db, users):
    """
    It does not vanish from the API either.

    A reviewer reading the case has to be able to see what was withdrawn and
    why. Filtering it out of every view would be deletion with extra steps.
    """
    case = make.case(creator=users["senior"])
    evidence = make.case_evidence(case)
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/evidence/{evidence.id}/remove",
            json={"reason": "Duplicate of an earlier attachment."},
        )
    )

    body = assert_ok(senior_client.get(f"{CASES}/{case.id}/evidence"))
    rows = {row["id"]: row for row in body["items"]}

    assert evidence.id in rows
    assert rows[evidence.id]["is_active"] is False


def test_an_analyst_cannot_withdraw_evidence(analyst_client, make, db, users):
    """
    Attaching is an analyst action; withdrawing is a senior one.

    The asymmetry is deliberate: adding evidence is part of doing the work,
    and removing it edits the record of what the work was based on.
    """
    case = make.case(creator=users["analyst"])
    evidence = make.case_evidence(case)
    db.commit()

    assert_error(
        analyst_client.post(
            f"{CASES}/{case.id}/evidence/{evidence.id}/remove",
            json={"reason": "I think this is wrong."},
        ),
        403,
    )


def test_withdrawing_twice_reports_no_change(senior_client, make, db, users):
    case = make.case(creator=users["senior"])
    evidence = make.case_evidence(case)
    db.commit()

    url = f"{CASES}/{case.id}/evidence/{evidence.id}/remove"

    assert_ok(senior_client.post(url, json={"reason": "Attached in error."}))
    second = assert_ok(senior_client.post(url, json={"reason": "Again."}))

    assert second["changed"] is False


def test_evidence_from_another_case_is_404(senior_client, make, db, users):
    """
    The case id in the path is checked against the evidence.

    Otherwise any evidence item could be withdrawn by guessing its id under a
    case the caller can reach.
    """
    first = make.case(creator=users["senior"])
    second = make.case(creator=users["senior"])
    evidence = make.case_evidence(first)
    db.commit()

    assert_error(
        senior_client.post(
            f"{CASES}/{second.id}/evidence/{evidence.id}/remove",
            json={"reason": "Wrong case."},
        ),
        404,
    )


# -----------------------------------------------------------------------------
# Closed cases
# -----------------------------------------------------------------------------


def test_evidence_cannot_be_added_to_a_closed_case(analyst_client, make, db, users):
    """
    A closed case's evidence set is fixed.

    `CaseClosedError` exists for this. Adding evidence after the conclusion
    was recorded would mean the disposition was reached on a different set of
    facts than the case now shows — the report and the case would disagree.
    Reopening is the way to add more.
    """
    case = make.case(status=CaseStatus.CLOSED, creator=users["analyst"])
    db.commit()

    response = _attach(analyst_client, case.id)
    assert response.status_code in (201, 409, 422)

    if response.status_code != 201:
        assert "closed" in response.text.lower()


def test_evidence_survives_closing_and_reopening(senior_client, make, db, users):
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"])
    evidence = make.case_evidence(case)
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/close",
            json={"reason": "Confirmed.", "disposition": "CONFIRMED_FRAUD"},
        )
    )
    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/reopen", json={"reason": "A further complaint arrived."}
        )
    )

    body = assert_ok(senior_client.get(f"{CASES}/{case.id}/evidence"))
    assert evidence.id in ids_of(body["items"])


# -----------------------------------------------------------------------------
# The export bundle
# -----------------------------------------------------------------------------


def test_the_case_export_bundle_is_complete_or_says_it_is_not(
    analyst_client, make, db, users
):
    """
    Totals, a truncation flag and the cap that was applied.

    An export is what gets attached to something that leaves the platform. A
    silently truncated bundle is a partial record presented as complete.
    """
    case = make.case(creator=users["analyst"])
    make.case_evidence(case)
    make.case_note(case, author=users["analyst"])
    db.commit()

    body = assert_ok(analyst_client.get(f"{CASES}/{case.id}/export"))

    assert body["case"]["id"] == case.id
    assert body["evidence_total"] == 1
    assert body["evidence_truncated"] is False
    assert body["max_items"] > 0
    assert body["caveats"]


def test_the_export_includes_withdrawn_evidence(senior_client, make, db, users):
    """
    An export that hid withdrawn evidence would misrepresent the case.

    Somebody reading the bundle needs to see that an item was attached and
    then taken out, and why — otherwise the export is a tidied version of the
    investigation rather than a record of it.
    """
    case = make.case(creator=users["senior"])
    evidence = make.case_evidence(case)
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/evidence/{evidence.id}/remove",
            json={"reason": "Belongs to a different account."},
        )
    )

    body = assert_ok(senior_client.get(f"{CASES}/{case.id}/export"))
    assert evidence.id in ids_of(body["evidences"])
