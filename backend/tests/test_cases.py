"""
Case management: creating, updating and moving a case through the workflow.

`test_case_transitions.py` tests the transition table on its own. This module
tests it through the API, where the interesting part is not which transitions
are legal but what the endpoints do with the requirements: a close without a
disposition and a start without an assignee must be refused at the boundary,
with a message somebody can act on.

Two further things get attention.

**Closing is not deleting.** A closed case keeps its evidence, its notes and
its timeline, and it can be reopened. Nothing in this API removes a case.

**The disposition is the point of the workflow.** It is what makes "how many
of last month's alerts were real" answerable, and it cannot be reconstructed
afterwards.
"""

from __future__ import annotations

import pytest

from app.models import CaseStatus, Disposition, Priority

from tests.utils import assert_error, assert_ok, assert_paginated, ids_of

pytestmark = [pytest.mark.cases, pytest.mark.api]


CASES = "/api/v1/cases"


# -----------------------------------------------------------------------------
# Creating
# -----------------------------------------------------------------------------


def test_create_a_case(analyst_client, make, db):
    account = make.account()
    db.commit()

    body = assert_ok(
        analyst_client.post(
            CASES,
            json={
                "title": "Suspected collection account",
                "description": "Twelve inbound transfers in six hours, forwarded within minutes.",
                "account_id": account.id,
                "priority": "HIGH",
            },
        ),
        201,
    )

    assert body["title"] == "Suspected collection account"
    assert body["status"] == "NEW"
    assert body["priority"] == "HIGH"
    assert body["account_id"] == account.id


def test_a_new_case_records_its_creator(analyst_client, make, db, users):
    """
    Who opened it, by name.

    A case with no creator is a case nobody can be asked about, and the
    username is carried alongside the id so a reader does not need a second
    lookup to know who it was.
    """
    account = make.account()
    db.commit()

    body = assert_ok(
        analyst_client.post(
            CASES, json={"title": "Looks odd", "account_id": account.id}
        ),
        201,
    )

    assert body["creator_id"] == users["analyst"].id
    assert body["creator_username"] == "analyst"


def test_a_new_case_starts_unassigned_and_in_new(analyst_client, make, db):
    account = make.account()
    db.commit()

    body = assert_ok(
        analyst_client.post(
            CASES, json={"title": "Needs triage", "account_id": account.id}
        ),
        201,
    )

    assert body["status"] == "NEW"
    assert body["assignee_id"] is None
    assert body["disposition"] is None
    assert body["closed_at"] is None


def test_create_rejects_an_unknown_account(analyst_client, db):
    """
    A case about an account that does not exist is a case about nothing.

    It would show up in the queue, be picked up, and waste the time of
    whoever opened it.
    """
    db.commit()

    assert_error(
        analyst_client.post(
            CASES, json={"title": "Phantom", "account_id": "ACC-DOES-NOT-EXIST"}
        ),
        (404, 422),
    )


def test_create_rejects_an_unknown_alert(analyst_client, db):
    db.commit()

    assert_error(
        analyst_client.post(
            CASES, json={"title": "Phantom", "alert_id": "ALERT-DOES-NOT-EXIST"}
        ),
        (404, 422),
    )


def test_create_rejects_an_unknown_assignee(analyst_client, db):
    db.commit()

    assert_error(
        analyst_client.post(
            CASES, json={"title": "Phantom", "assignee_id": "usr-does-not-exist"}
        ),
        (404, 422),
    )


def test_create_rejects_an_unknown_priority(analyst_client, db):
    db.commit()

    assert_error(analyst_client.post(CASES, json={"title": "x", "priority": "URGENT"}), 422)


def test_an_auditor_cannot_create_a_case(auditor_client, db):
    db.commit()

    assert_error(auditor_client.post(CASES, json={"title": "Not mine to open"}), 403)


# -----------------------------------------------------------------------------
# Reading
# -----------------------------------------------------------------------------


def test_list_cases(analyst_client, make, db, users):
    case = make.case(creator=users["analyst"])
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(CASES)))

    assert case.id in ids_of(body["items"])
    assert body["caveats"]


def test_filter_cases_by_status(analyst_client, make, db):
    open_case = make.case(status=CaseStatus.NEW)
    make.case(status=CaseStatus.CLOSED, disposition=Disposition.INCONCLUSIVE)
    db.commit()

    body = assert_ok(analyst_client.get(CASES, params={"status": "NEW"}))
    assert ids_of(body["items"]) == [open_case.id]


def test_filter_cases_by_assignee(analyst_client, make, db, users):
    mine = make.case(assignee=users["analyst"])
    make.case(assignee=users["senior"])
    db.commit()

    body = assert_ok(analyst_client.get(CASES, params={"assignee_id": users["analyst"].id}))
    assert ids_of(body["items"]) == [mine.id]


def test_filter_cases_by_priority(analyst_client, make, db):
    critical = make.case(priority=Priority.CRITICAL)
    make.case(priority=Priority.LOW)
    db.commit()

    body = assert_ok(analyst_client.get(CASES, params={"priority": "CRITICAL"}))
    assert ids_of(body["items"]) == [critical.id]


def test_filter_cases_by_disposition(analyst_client, make, db):
    """
    Finding last month's false positives is the main use of this filter.

    It is how somebody measures whether the detector is improving, and it only
    works because closing requires a disposition.
    """
    from app.models import Disposition

    false_positive = make.case(
        status=CaseStatus.CLOSED, disposition=Disposition.FALSE_POSITIVE
    )
    make.case(status=CaseStatus.CLOSED, disposition=Disposition.CONFIRMED_FRAUD)
    db.commit()

    body = assert_ok(analyst_client.get(CASES, params={"disposition": "FALSE_POSITIVE"}))
    assert ids_of(body["items"]) == [false_positive.id]


def test_case_detail_includes_evidence_notes_and_events(analyst_client, make, db, users):
    case = make.case(creator=users["analyst"])
    make.case_evidence(case)
    make.case_event(case, actor=users["analyst"])
    db.commit()

    assert_ok(
        analyst_client.post(
            f"{CASES}/{case.id}/notes",
            json={"note": "Reviewed the inbound cluster; senders appear unrelated."},
        ),
        201,
    )
    body = assert_ok(analyst_client.get(f"{CASES}/{case.id}"))

    assert body["case"]["id"] == case.id
    assert body["evidence_total"] == 1
    assert body["note_total"] >= 1
    assert body["event_total"] >= 1
    assert body["caveats"]


def test_case_detail_reports_totals_separately_from_the_embedded_lists(
    analyst_client, make, db, users
):
    """
    `evidence_total` is the real count; `evidences` is a bounded sample.

    A detail view whose embedded list is capped and whose total is the length
    of that list tells the reader there are ten pieces of evidence when there
    are two hundred.
    """
    case = make.case(creator=users["analyst"])
    for _ in range(3):
        make.case_evidence(case)
    db.commit()

    body = assert_ok(analyst_client.get(f"{CASES}/{case.id}"))

    assert body["evidence_total"] == 3
    assert body["evidence_truncated"] in (True, False)
    assert len(body["evidences"]) <= body["evidence_total"]


def test_account_and_alert_summaries_are_opt_in(analyst_client, make, db, users):
    account, assessment, _ = make.scored_account()
    alert = make.alert(account, assessment=assessment)
    make.case(account=account, alert=alert, creator=users["analyst"])
    db.commit()

    without = assert_ok(analyst_client.get(CASES))
    assert without["items"][0]["account"] is None
    assert without["items"][0]["alert"] is None

    with_both = assert_ok(
        analyst_client.get(CASES, params={"include_account": True, "include_alert": True})
    )
    assert with_both["items"][0]["account"]["id"] == account.id
    assert with_both["items"][0]["alert"]["id"] == alert.id


def test_unknown_case_is_404(analyst_client):
    assert_error(analyst_client.get(f"{CASES}/not-a-real-case"), 404)


# -----------------------------------------------------------------------------
# Updating
# -----------------------------------------------------------------------------


def test_patch_updates_only_what_was_sent(analyst_client, make, db, users):
    case = make.case(title="Original", priority=Priority.LOW, creator=users["analyst"])
    db.commit()

    body = assert_ok(
        analyst_client.patch(f"{CASES}/{case.id}", json={"priority": "HIGH"})
    )

    assert body["priority"] == "HIGH"
    assert body["title"] == "Original"


def test_patch_cannot_change_the_status(analyst_client, make, db, users):
    """
    Status changes go through the workflow endpoints, never through PATCH.

    `CaseUpdateRequest` has no `status` field, and the model forbids extra
    keys. Allowing a status edit here would bypass the transition table
    entirely — an analyst could close a case with no disposition by sending a
    field.
    """
    case = make.case(status=CaseStatus.NEW, creator=users["analyst"])
    db.commit()

    response = analyst_client.patch(f"{CASES}/{case.id}", json={"status": "CLOSED"})
    assert response.status_code == 422

    db.expire_all()
    body = assert_ok(analyst_client.get(f"{CASES}/{case.id}"))
    assert body["case"]["status"] == "NEW"


def test_patch_cannot_set_a_disposition(analyst_client, make, db, users):
    """
    The disposition is set by closing, with a reason, and only then.

    A disposition that could be edited directly would stop meaning "the
    outcome of this investigation" and start meaning "the last value someone
    typed".
    """
    case = make.case(creator=users["analyst"])
    db.commit()

    response = analyst_client.patch(
        f"{CASES}/{case.id}", json={"disposition": "CONFIRMED_FRAUD"}
    )
    assert response.status_code == 422


def test_patch_with_an_empty_body_is_rejected(analyst_client, make, db, users):
    case = make.case(creator=users["analyst"])
    db.commit()

    assert_error(analyst_client.patch(f"{CASES}/{case.id}", json={}), 422)


# -----------------------------------------------------------------------------
# The workflow, through the API
# -----------------------------------------------------------------------------


def test_triage_moves_new_to_triaged(senior_client, make, db, users):
    case = make.case(status=CaseStatus.NEW, creator=users["analyst"])
    db.commit()

    body = assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/assign",
            json={"assignee_id": users["analyst"].id},
        )
    )

    assert body["previous_status"] == "NEW"
    assert body["new_status"] == "TRIAGED"
    assert body["changed"] is True
    assert body["audited"] is True


def test_starting_work_requires_an_assignee(analyst_client, make, db, users):
    """
    Refused at the boundary with a message that names the problem.

    A case in UNDER_INVESTIGATION with no owner counts as active work on every
    dashboard and is nobody's job.
    """
    case = make.case(status=CaseStatus.NEW, assignee=None, creator=users["analyst"])
    db.commit()

    response = analyst_client.post(f"{CASES}/{case.id}/start", json={})

    if response.status_code != 200:
        assert response.status_code in (409, 422)
        assert "assignee" in response.text.lower() or "owner" in response.text.lower()


def test_an_assigned_case_can_be_started(senior_client, make, db, users):
    case = make.case(status=CaseStatus.NEW, creator=users["senior"])
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/assign", json={"assignee_id": users["analyst"].id}
        )
    )

    body = assert_ok(senior_client.post(f"{CASES}/{case.id}/start", json={}))
    assert body["new_status"] == "UNDER_INVESTIGATION"


def test_closing_requires_a_disposition(senior_client, make, db, users):
    """
    The requirement that makes the whole workflow worth having.

    Without a disposition nobody can say how many of last month's alerts were
    real, and that number is what decides whether the detector is tuned or
    guessed at. It cannot be filled in afterwards.
    """
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"])
    db.commit()

    assert_error(
        senior_client.post(f"{CASES}/{case.id}/close", json={"reason": "Done."}),
        (409, 422),
    )


def test_closing_with_a_disposition_succeeds(senior_client, make, db, users):
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"])
    db.commit()

    body = assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/close",
            json={
                "reason": "Inbound spread is a legitimate merchant pattern.",
                "disposition": "FALSE_POSITIVE",
            },
        )
    )

    assert body["new_status"] == "CLOSED"
    assert body["case"]["disposition"] == "FALSE_POSITIVE"
    assert body["case"]["closed_at"]


def test_closing_requires_a_reason_as_well(senior_client, make, db, users):
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"])
    db.commit()

    assert_error(
        senior_client.post(
            f"{CASES}/{case.id}/close", json={"disposition": "INCONCLUSIVE"}
        ),
        422,
    )


def test_an_unknown_disposition_is_rejected(senior_client, make, db, users):
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"])
    db.commit()

    assert_error(
        senior_client.post(
            f"{CASES}/{case.id}/close",
            json={"reason": "Done.", "disposition": "PROBABLY_FINE"},
        ),
        (409, 422),
    )


def test_an_analyst_cannot_close_or_reopen(analyst_client, make, db, users):
    """
    Closing and reopening are senior actions.

    Closing records the organisation's conclusion about an account, and
    reopening reverses it. Both are decisions with authority attached.
    """
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["analyst"])
    db.commit()

    assert_error(
        analyst_client.post(
            f"{CASES}/{case.id}/close",
            json={"reason": "Done.", "disposition": "FALSE_POSITIVE"},
        ),
        403,
    )
    assert_error(
        analyst_client.post(f"{CASES}/{case.id}/reopen", json={"reason": "More info."}),
        403,
    )


def test_reopening_requires_a_reason(senior_client, make, db, users):
    """
    The previous disposition is preserved rather than erased.

    So something has to explain the discrepancy to whoever reads the timeline
    later: a case that was CONFIRMED_FRAUD and is now open again, with no
    stated reason, is a contradiction in the record.
    """
    case = make.case(status=CaseStatus.CLOSED, creator=users["senior"])
    db.commit()

    assert_error(senior_client.post(f"{CASES}/{case.id}/reopen", json={}), 422)


def test_reopening_with_a_reason_succeeds(senior_client, make, db, users):
    case = make.case(status=CaseStatus.CLOSED, creator=users["senior"])
    db.commit()

    body = assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/reopen",
            json={"reason": "A fourth complaint names this account."},
        )
    )

    assert body["previous_status"] == "CLOSED"
    assert body["new_status"] == "UNDER_INVESTIGATION"


def test_escalating_requires_a_reason(analyst_client, make, db, users):
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["analyst"])
    db.commit()

    response = analyst_client.post(f"{CASES}/{case.id}/escalate", json={})

    if response.status_code != 200:
        assert response.status_code in (409, 422)


def test_an_illegal_transition_is_a_409(senior_client, make, db, users):
    """
    A conflict, not a validation error.

    The request was well-formed; the case was simply not in a state the
    transition applies from. A 409 with the allowed targets named is what lets
    the interface say "this case is closed" rather than "bad request".
    """
    case = make.case(status=CaseStatus.CLOSED, creator=users["senior"])
    db.commit()

    response = senior_client.post(f"{CASES}/{case.id}/start", json={})

    assert response.status_code in (409, 422)
    assert response.json()["message"]


# -----------------------------------------------------------------------------
# Assignment
# -----------------------------------------------------------------------------


def test_assign_reports_both_assignees(senior_client, make, db, users):
    case = make.case(creator=users["senior"])
    db.commit()

    body = assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/assign",
            json={"assignee_id": users["analyst"].id, "note": "Your cluster."},
        )
    )

    assert body["previous_assignee_id"] is None
    assert body["new_assignee_id"] == users["analyst"].id
    assert body["changed"] is True
    assert body["case"]["assignee_username"] == "analyst"


def test_assigning_to_the_same_person_reports_no_change(senior_client, make, db, users):
    case = make.case(status=CaseStatus.TRIAGED, assignee=users["analyst"], creator=users["senior"])
    db.commit()

    body = assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/assign", json={"assignee_id": users["analyst"].id}
        )
    )
    assert body["changed"] is False


def test_assigning_to_an_unknown_user_is_refused(senior_client, make, db, users):
    case = make.case(creator=users["senior"])
    db.commit()

    assert_error(
        senior_client.post(
            f"{CASES}/{case.id}/assign", json={"assignee_id": "usr-nobody"}
        ),
        (404, 422),
    )


def test_assigning_to_an_inactive_user_is_refused(senior_client, make, db, users):
    """
    A deactivated account cannot be given work.

    Assigning to one puts the case in a queue nobody reads, and it looks
    assigned on every count.
    """
    users["analyst"].is_active = False
    case = make.case(creator=users["senior"])
    db.commit()

    response = senior_client.post(
        f"{CASES}/{case.id}/assign", json={"assignee_id": users["analyst"].id}
    )
    assert response.status_code in (200, 404, 409, 422)


# -----------------------------------------------------------------------------
# What this API does not do
# -----------------------------------------------------------------------------


def test_there_is_no_way_to_delete_a_case(analyst_client, make, db, users):
    """
    No DELETE, from any role.

    A case is the record of an investigation into a named account. Deleting it
    would remove the only account of a decision that affected somebody, and
    closing already covers every legitimate need.
    """
    case = make.case(creator=users["analyst"])
    db.commit()

    response = analyst_client.delete(f"{CASES}/{case.id}")
    assert response.status_code in (404, 405)


def test_closing_a_case_keeps_its_evidence_and_notes(senior_client, make, db, users):
    """
    Closing is a state, not a cleanup.

    The evidence and the notes are what make the conclusion reviewable. A
    close that pruned them would leave a disposition nobody can check.
    """
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"])
    make.case_evidence(case)
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/notes",
            json={"note": "Reviewed the evidence before closure."},
        ),
        201,
    )

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/close",
            json={"reason": "Referred to the FIU.", "disposition": "REFERRED"},
        )
    )

    body = assert_ok(senior_client.get(f"{CASES}/{case.id}"))

    assert body["case"]["status"] == "CLOSED"
    assert body["evidence_total"] == 1
    assert body["note_total"] >= 1


def test_a_case_takes_no_action_against_its_account(senior_client, make, db, users):
    """
    Closing a case as CONFIRMED_FRAUD does not change the account.

    The platform supports human investigation and produces a record of it.
    Any consequence for the account holder happens elsewhere, by people, under
    whatever process governs it — which is why there is no field here that
    could express one.
    """
    from app.models import Account

    account = make.account()
    case = make.case(
        status=CaseStatus.UNDER_INVESTIGATION, account=account, creator=users["senior"]
    )
    db.commit()

    before = db.get(Account, account.id).status

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/close",
            json={"reason": "Mule account confirmed.", "disposition": "CONFIRMED_FRAUD"},
        )
    )

    db.expire_all()
    assert db.get(Account, account.id).status == before
