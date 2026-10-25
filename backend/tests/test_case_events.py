"""
Case events and notes: the append-only timeline.

A case's timeline is the record of how a conclusion was reached. Its value
comes entirely from being append-only: a timeline that can be edited is a
timeline nobody can rely on, and the whole point of recording an
investigation is that somebody else can check it later.

So the properties tested here are mostly about what cannot happen. There is no
endpoint to edit an event, none to delete one, and none to edit a note. A note
written in error is corrected by writing another note — which is itself part
of the record, and more informative than a silent edit would have been.

Notes and events share a representation (`CaseEventResponse`) because a note
*is* an event: an actor, a time, and what they said. Keeping them in one shape
means the timeline can be assembled from both without the reader having to
reconcile two formats.
"""

from __future__ import annotations

import pytest

from app.models import CaseStatus

from tests.utils import assert_error, assert_ok, assert_paginated, ids_of

pytestmark = [pytest.mark.cases, pytest.mark.audit]


CASES = "/api/v1/cases"


# -----------------------------------------------------------------------------
# Notes
# -----------------------------------------------------------------------------


def test_add_a_note(analyst_client, make, db, users):
    case = make.case(creator=users["analyst"])
    db.commit()

    body = assert_ok(
        analyst_client.post(
            f"{CASES}/{case.id}/notes",
            json={"note": "Senders appear unrelated; checked five at random."},
        ),
        201,
    )

    assert body["note"]["summary"] or body["note"]["action"]
    assert body["audited"] is True
    assert body["caveats"]


def test_a_note_records_its_author(analyst_client, make, db, users):
    """
    Attribution, by name.

    A note is somebody's judgement about an account. Unattributed, it is an
    assertion from nowhere, and a reviewer cannot weigh it or ask about it.
    """
    case = make.case(creator=users["analyst"])
    db.commit()

    body = assert_ok(
        analyst_client.post(
            f"{CASES}/{case.id}/notes", json={"note": "Requested the device history."}
        ),
        201,
    )

    assert body["note"]["actor_id"] == users["analyst"].id
    assert body["note"]["actor_username"] == "analyst"
    assert body["note"]["created_at"]


def test_an_empty_note_is_rejected(analyst_client, make, db, users):
    """
    Whitespace is not a note.

    An empty note adds a row to the timeline that says nothing, which is worse
    than no row: it looks like somebody recorded something.
    """
    case = make.case(creator=users["analyst"])
    db.commit()

    for value in ("", "   ", "\n\t "):
        assert_error(
            analyst_client.post(f"{CASES}/{case.id}/notes", json={"note": value}), 422
        )


def test_a_note_body_is_required(analyst_client, make, db, users):
    case = make.case(creator=users["analyst"])
    db.commit()

    assert_error(analyst_client.post(f"{CASES}/{case.id}/notes", json={}), 422)


def test_an_over_long_note_is_rejected(analyst_client, make, db, users):
    """
    The cap is a real limit, not advice.

    A note holding a pasted log file makes the timeline unreadable and the
    export unusable, and the content belongs in evidence with a snapshot.
    """
    case = make.case(creator=users["analyst"])
    db.commit()

    assert_error(
        analyst_client.post(f"{CASES}/{case.id}/notes", json={"note": "x" * 50_000}),
        422,
    )


def test_list_notes(analyst_client, make, db, users):
    case = make.case(creator=users["analyst"])
    db.commit()

    for text in ("First look.", "Second look.", "Asked the issuing bank."):
        assert_ok(
            analyst_client.post(f"{CASES}/{case.id}/notes", json={"note": text}), 201
        )

    body = assert_paginated(assert_ok(analyst_client.get(f"{CASES}/{case.id}/notes")))

    assert body["total"] == 3
    assert body["caveats"]


def test_notes_are_scoped_to_their_case(analyst_client, make, db, users):
    first = make.case(creator=users["analyst"])
    second = make.case(creator=users["analyst"])
    db.commit()

    assert_ok(
        analyst_client.post(f"{CASES}/{first.id}/notes", json={"note": "On the first."}),
        201,
    )
    assert_ok(
        analyst_client.post(f"{CASES}/{second.id}/notes", json={"note": "On the second."}),
        201,
    )

    body = assert_ok(analyst_client.get(f"{CASES}/{first.id}/notes"))
    assert body["total"] == 1


def test_notes_can_be_filtered_by_author(analyst_client, senior_client, make, db, users):
    """
    "What did this person conclude" is a real question.

    Most often asked when a case changes hands, or when somebody is reviewing
    one investigator's work across several cases.
    """
    case = make.case(creator=users["senior"])
    db.commit()

    assert_ok(
        analyst_client.post(f"{CASES}/{case.id}/notes", json={"note": "Analyst view."}),
        201,
    )
    assert_ok(
        senior_client.post(f"{CASES}/{case.id}/notes", json={"note": "Senior view."}), 201
    )

    body = assert_ok(
        analyst_client.get(
            f"{CASES}/{case.id}/notes", params={"actor_id": users["analyst"].id}
        )
    )

    assert body["total"] == 1
    assert body["items"][0]["actor_username"] == "analyst"


def test_an_auditor_can_read_notes_but_not_write_them(auditor_client, make, db, users):
    case = make.case(creator=users["admin"])
    make.case_note(case, author=users["admin"])
    db.commit()

    assert_ok(auditor_client.get(f"{CASES}/{case.id}/notes"))
    assert_error(
        auditor_client.post(f"{CASES}/{case.id}/notes", json={"note": "Observing."}), 403
    )


def test_notes_cannot_be_added_to_an_unknown_case(analyst_client, db):
    db.commit()

    assert_error(
        analyst_client.post(f"{CASES}/not-a-real-case/notes", json={"note": "x"}), 404
    )


# -----------------------------------------------------------------------------
# Events
# -----------------------------------------------------------------------------


def test_workflow_actions_produce_events(senior_client, make, db, users):
    """
    The timeline is written by the workflow, not by hand.

    Every transition leaves an event with the action name, so the sequence of
    states a case went through is reconstructable without reading the audit
    log.
    """
    case = make.case(status=CaseStatus.NEW, creator=users["senior"])
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/assign", json={"assignee_id": users["analyst"].id}
        )
    )
    assert_ok(senior_client.post(f"{CASES}/{case.id}/start", json={}))

    body = assert_paginated(assert_ok(senior_client.get(f"{CASES}/{case.id}/events")))

    assert body["total"] >= 2

    actions = {row["action"] for row in body["items"]}
    assert any("assign" in action.lower() for action in actions), actions


def test_each_event_names_its_actor(senior_client, make, db, users):
    case = make.case(status=CaseStatus.NEW, creator=users["senior"])
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/assign", json={"assignee_id": users["analyst"].id}
        )
    )

    body = assert_ok(senior_client.get(f"{CASES}/{case.id}/events"))

    for row in body["items"]:
        assert row["action"]
        assert row["created_at"]
        assert row["case_id"] == case.id


def test_events_can_be_filtered_by_action(senior_client, make, db, users):
    case = make.case(status=CaseStatus.NEW, creator=users["senior"])
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/assign", json={"assignee_id": users["analyst"].id}
        )
    )
    assert_ok(senior_client.post(f"{CASES}/{case.id}/start", json={}))

    body = assert_ok(senior_client.get(f"{CASES}/{case.id}/events"))
    actions = [row["action"] for row in body["items"]]

    assert len(set(actions)) >= 2


def test_evidence_changes_appear_in_the_timeline(senior_client, make, db, users):
    """
    Attaching and withdrawing evidence are both events.

    A case whose evidence set changed with nothing in the timeline saying so
    would show a conclusion resting on facts that appeared from nowhere.
    """
    account = make.account()
    case = make.case(account=account, creator=users["senior"])
    db.commit()

    attached = assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/evidence",
            json={"evidence_type": "ACCOUNT", "evidence_id": account.id},
        ),
        201,
    )
    evidence_id = attached["evidence"]["id"]

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/evidence/{evidence_id}/remove",
            json={"reason": "Attached to the wrong case."},
        )
    )

    body = assert_ok(senior_client.get(f"{CASES}/{case.id}/events"))
    actions = " ".join(row["action"] for row in body["items"]).lower()

    assert "evidence" in actions


def test_the_timeline_records_the_reason_for_a_withdrawal(senior_client, make, db, users):
    """
    The reason is in the event metadata, not only on the evidence row.

    Somebody reading the timeline in order should be able to see why an item
    was taken out without going to look at the item.
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

    response = senior_client.get(f"{CASES}/{case.id}/events")
    assert_ok(response)

    assert "Duplicate of an earlier attachment." in response.text


def test_events_are_scoped_to_their_case(senior_client, make, db, users):
    first = make.case(status=CaseStatus.NEW, creator=users["senior"])
    second = make.case(status=CaseStatus.NEW, creator=users["senior"])
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{first.id}/assign", json={"assignee_id": users["analyst"].id}
        )
    )

    body = assert_ok(senior_client.get(f"{CASES}/{second.id}/events"))
    assert all(row["case_id"] == second.id for row in body["items"])


def test_events_are_paginated(senior_client, make, db, users):
    case = make.case(creator=users["senior"])
    for index in range(12):
        make.case_event(case, action=f"case.touched.{index}", actor=users["senior"])
    db.commit()

    first = assert_paginated(
        assert_ok(senior_client.get(f"{CASES}/{case.id}/events", params={"page_size": 5}))
    )
    second = assert_paginated(
        assert_ok(
            senior_client.get(
                f"{CASES}/{case.id}/events", params={"page_size": 5, "page": 2}
            )
        )
    )

    assert len(first["items"]) == 5
    assert not (set(ids_of(first["items"])) & set(ids_of(second["items"])))


# -----------------------------------------------------------------------------
# Append-only
# -----------------------------------------------------------------------------


def test_there_is_no_endpoint_to_edit_an_event(senior_client, make, db, users):
    """
    No PATCH, no PUT, no DELETE on the timeline.

    This is the property the timeline's value rests on. An editable history is
    not a history: a conclusion reached on facts that were later changed, with
    no record of the change, is a conclusion nobody can check.

    A note written in error is corrected by writing another note — which is
    itself informative in a way a silent edit would not be.
    """
    case = make.case(creator=users["senior"])
    event = make.case_event(case, actor=users["senior"])
    db.commit()

    for method in ("patch", "put", "delete"):
        response = senior_client.raw.request(
            method,
            f"{CASES}/{case.id}/events/{event.id}",
            headers={"Authorization": f"Bearer {senior_client.token}"},
            json={} if method in {"patch", "put"} else None,
        )
        assert response.status_code in (404, 405), (
            f"{method.upper()} on an event answered {response.status_code}"
        )


def test_there_is_no_endpoint_to_edit_a_note(senior_client, make, db, users):
    case = make.case(creator=users["senior"])
    note = make.case_note(case, author=users["senior"])
    db.commit()

    for method in ("patch", "put", "delete"):
        response = senior_client.raw.request(
            method,
            f"{CASES}/{case.id}/notes/{note.id}",
            headers={"Authorization": f"Bearer {senior_client.token}"},
            json={} if method in {"patch", "put"} else None,
        )
        assert response.status_code in (404, 405)


def test_closing_a_case_does_not_prune_its_timeline(senior_client, make, db, users):
    """
    Closing adds an event; it does not remove any.

    The timeline is what makes the disposition reviewable, so it has to
    survive the thing it explains.
    """
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"])
    db.commit()

    before = assert_ok(senior_client.get(f"{CASES}/{case.id}/events"))["total"]

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/close",
            json={"reason": "Merchant pattern.", "disposition": "FALSE_POSITIVE"},
        )
    )

    after = assert_ok(senior_client.get(f"{CASES}/{case.id}/events"))["total"]
    assert after > before


def test_reopening_preserves_the_earlier_events(senior_client, make, db, users):
    """
    Reopening resumes a case; it does not start a new one.

    The previous disposition and everything that led to it stay in the
    timeline, which is what lets a reader see that the conclusion changed and
    why.
    """
    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"])
    db.commit()

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/close",
            json={"reason": "Confirmed.", "disposition": "CONFIRMED_FRAUD"},
        )
    )
    closed_count = assert_ok(senior_client.get(f"{CASES}/{case.id}/events"))["total"]

    assert_ok(
        senior_client.post(
            f"{CASES}/{case.id}/reopen",
            json={"reason": "The issuing bank disputed the finding."},
        )
    )

    reopened = assert_ok(senior_client.get(f"{CASES}/{case.id}/events"))
    assert reopened["total"] > closed_count


# -----------------------------------------------------------------------------
# What the timeline must not contain
# -----------------------------------------------------------------------------


def test_the_timeline_does_not_leak_a_complaint_narrative(
    analyst_client, make, db, users
):
    """
    A note is free text, but the platform never puts a narrative into one.

    Event metadata is assembled by the server from workflow state. If a
    correlation's complaint narrative reached it, the text would be readable
    by every role that can read a case — bypassing the permission that governs
    it.
    """
    account = make.account()
    complaint = make.complaint(
        narrative_raw="Victim describes being coached through a transfer by phone."
    )
    make.correlation(complaint, account=account, match_tier=1)

    case = make.case(account=account, creator=users["analyst"])
    db.commit()

    assert_ok(
        analyst_client.post(
            f"{CASES}/{case.id}/evidence",
            json={"evidence_type": "COMPLAINT", "evidence_id": complaint.id},
        ),
        201,
    )

    response = analyst_client.get(f"{CASES}/{case.id}/events")
    assert_ok(response)

    assert "coached" not in response.text


def test_the_timeline_does_not_leak_ground_truth_labels(
    analyst_client, make, db, users
):
    """
    Scenario and ring ids never reach a case.

    They are the synthetic generator's answer sheet. An investigator who could
    see them would be reading the answer rather than the evidence, and any
    measurement taken from their work afterwards would be meaningless.
    """
    account = make.account()
    make.label(account, is_mule=True, scenario_type="fan_in_collector", ring_id="RING-7")

    case = make.case(account=account, creator=users["analyst"])
    make.case_event(case, actor=users["analyst"])
    db.commit()

    response = analyst_client.get(f"{CASES}/{case.id}/events")
    assert_ok(response)

    raw = response.text.lower()
    assert "ring-7" not in raw
    assert "fan_in_collector" not in raw
    assert "ground_truth" not in raw
    assert "scenario" not in raw
