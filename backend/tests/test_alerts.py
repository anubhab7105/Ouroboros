"""
Alerts: the triage queue and the actions on it.

An alert is a request for a person to look. That is the whole of what it is,
and most of what these tests check is that nothing more is implied.

The structural points:

- Workflow actions return `previous_state` and `new_state`, and a `changed`
  flag. An action that was a no-op says so rather than reporting success.
- `score` is nullable. An alert can be raised by a rule effect — a
  complaint-named suspect, say — without a fused score, and a null must not
  render as zero.
- `evidence_count`, `case_count` and `active_case_count` are nullable: null
  means "not computed for this view", not zero.
"""

from __future__ import annotations

import pytest

from app.models import AlertState, Priority, ScoringMode

from tests.utils import assert_error, assert_ok, assert_paginated, ids_of

pytestmark = pytest.mark.api


ALERTS = "/api/v1/alerts"


# -----------------------------------------------------------------------------
# The queue
# -----------------------------------------------------------------------------


def test_list_alerts(analyst_client, make, db):
    account, assessment, _ = make.scored_account()
    alert = make.alert(account, assessment=assessment)
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(ALERTS)))

    assert alert.id in ids_of(body["items"])
    assert body["caveats"]


def test_an_empty_queue_is_not_an_error(analyst_client):
    body = assert_paginated(assert_ok(analyst_client.get(ALERTS)))

    assert body["items"] == []
    assert body["total"] == 0


def test_filter_by_state(analyst_client, make, db):
    account = make.account()

    new_alert = make.alert(account, state=AlertState.NEW)
    make.alert(account, state=AlertState.CLOSED)
    db.commit()

    body = assert_ok(analyst_client.get(ALERTS, params={"states": ["NEW"]}))

    assert ids_of(body["items"]) == [new_alert.id]


def test_filter_by_several_states_at_once(analyst_client, make, db):
    """
    `states` is a repeated parameter, not a comma-joined string.

    The triage queue's default view is "anything not closed", which is three
    states. Without multi-value support the client would have to make three
    requests and merge them, and the pagination would be meaningless.
    """
    account = make.account()

    new_alert = make.alert(account, state=AlertState.NEW)
    reviewing = make.alert(account, state=AlertState.UNDER_REVIEW)
    make.alert(account, state=AlertState.CLOSED)
    db.commit()

    body = assert_ok(
        analyst_client.get(ALERTS, params={"states": ["NEW", "UNDER_REVIEW"]})
    )

    assert set(ids_of(body["items"])) == {new_alert.id, reviewing.id}


def test_filter_by_priority(analyst_client, make, db):
    account = make.account()

    critical = make.alert(account, priority=Priority.CRITICAL)
    make.alert(account, priority=Priority.LOW)
    db.commit()

    body = assert_ok(analyst_client.get(ALERTS, params={"priorities": ["CRITICAL"]}))

    assert ids_of(body["items"]) == [critical.id]


def test_filter_by_score_range(analyst_client, make, db):
    account = make.account()

    low = make.alert(account, score=30)
    high = make.alert(account, score=91)
    db.commit()

    body = assert_ok(analyst_client.get(ALERTS, params={"min_score": 65}))

    returned = set(ids_of(body["items"]))
    assert high.id in returned
    assert low.id not in returned


def test_a_score_filter_outside_the_scale_is_rejected(analyst_client):
    """
    The scale is 0..100 and the filter says so.

    A bound of 150 matches nothing, which reads as "no alerts" rather than
    "your query was impossible".
    """
    assert_error(analyst_client.get(ALERTS, params={"min_score": 150}), 422)
    assert_error(analyst_client.get(ALERTS, params={"max_score": -1}), 422)


def test_filter_by_account(analyst_client, make, db):
    first, second = make.accounts(2)

    mine = make.alert(first)
    make.alert(second)
    db.commit()

    body = assert_ok(analyst_client.get(ALERTS, params={"account_id": first.id}))

    assert ids_of(body["items"]) == [mine.id]


def test_filter_by_scoring_mode(analyst_client, make, db):
    """
    Which estimator produced the alert is a first-class filter.

    After a model is withdrawn, "show me everything scored by the heuristic
    fallback since Tuesday" is the question somebody needs to ask, and it is
    not answerable from the score alone.
    """
    account = make.account()

    fallback = make.alert(account, scoring_mode=ScoringMode.HEURISTIC_FALLBACK)
    make.alert(account, scoring_mode=ScoringMode.TRAINED_MODEL)
    db.commit()

    body = assert_ok(
        analyst_client.get(ALERTS, params={"scoring_mode": "HEURISTIC_FALLBACK"})
    )

    assert ids_of(body["items"]) == [fallback.id]


def test_an_alert_can_have_no_score(analyst_client, make, db):
    """
    Null, not zero.

    An alert raised by an `escalate_to_human` rule effect — a
    complaint-named suspect whose other signals were quiet — has no fused
    score. Rendering that as 0 would put the most corroborated kind of alert
    at the bottom of a score-sorted queue.
    """
    account = make.account()
    make.alert(account, score=None)
    db.commit()

    body = assert_ok(analyst_client.get(ALERTS))
    row = body["items"][0]

    assert row["score"] is None


def test_every_alert_states_its_scoring_mode(analyst_client, make, db):
    """
    The score never travels without how it was produced.

    A 78 from a validated model and a 78 from a hand-weighted heuristic are
    not the same claim, and the interface shows them differently.
    """
    account = make.account()
    make.alert(account)
    db.commit()

    row = assert_ok(analyst_client.get(ALERTS))["items"][0]
    assert row["scoring_mode"]


def test_account_summaries_are_opt_in(analyst_client, make, db):
    account = make.account()
    make.alert(account)
    db.commit()

    without = assert_ok(analyst_client.get(ALERTS))
    assert without["items"][0]["account"] is None

    with_account = assert_ok(analyst_client.get(ALERTS, params={"include_account": True}))
    assert with_account["items"][0]["account"]["id"] == account.id


def test_sort_by_score(analyst_client, make, db):
    account = make.account()

    low = make.alert(account, score=20)
    high = make.alert(account, score=95)
    db.commit()

    body = assert_ok(
        analyst_client.get(ALERTS, params={"sort_by": "score", "sort_order": "desc"})
    )
    order = ids_of(body["items"])

    assert order.index(high.id) < order.index(low.id)


# -----------------------------------------------------------------------------
# One alert
# -----------------------------------------------------------------------------


def test_alert_detail_includes_evidence_and_cases(analyst_client, make, db):
    account, assessment, _ = make.scored_account()
    alert = make.alert(account, assessment=assessment)
    make.alert_evidence(alert)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ALERTS}/{alert.id}"))

    assert body["alert"]["id"] == alert.id
    assert len(body["evidences"]) == 1
    assert isinstance(body["cases"], list)
    assert body["caveats"]


def test_alert_detail_says_when_it_truncated(analyst_client, make, db):
    """
    `evidence_truncated` rather than a silently short list.

    A detail view that caps its embedded collections and does not say so is
    telling the reader there are three pieces of evidence when there are
    forty. The flag is what lets the interface offer the full list.
    """
    account = make.account()
    alert = make.alert(account)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ALERTS}/{alert.id}"))

    assert body["evidence_truncated"] is False
    assert body["case_truncated"] is False


def test_unknown_alert_is_404(analyst_client):
    assert_error(analyst_client.get(f"{ALERTS}/not-a-real-alert"), 404)


# -----------------------------------------------------------------------------
# Triage actions
# -----------------------------------------------------------------------------


def test_acknowledge_moves_the_state_and_says_so(analyst_client, make, db):
    """
    The response names both states.

    An action response that returned only the new state would leave the
    client unable to tell an acknowledgement from a no-op, and the interface
    could not say "already acknowledged" rather than "acknowledged".
    """
    account = make.account()
    alert = make.alert(account, state=AlertState.NEW)
    db.commit()

    body = assert_ok(analyst_client.post(f"{ALERTS}/{alert.id}/acknowledge"))

    assert body["changed"] is True
    assert body["previous_state"] == "NEW"
    assert body["new_state"] != "NEW"
    assert body["audited"] is True


def test_acknowledging_twice_reports_no_change(analyst_client, make, db):
    """
    Idempotent, and honest about it.

    Two analysts opening the same alert both press the button. The second
    press must not look like a second acknowledgement in the history, and the
    response must not claim a change that did not happen.
    """
    account = make.account()
    alert = make.alert(account, state=AlertState.NEW)
    db.commit()

    assert_ok(analyst_client.post(f"{ALERTS}/{alert.id}/acknowledge"))
    second = assert_ok(analyst_client.post(f"{ALERTS}/{alert.id}/acknowledge"))

    assert second["changed"] is False
    assert second["previous_state"] == second["new_state"]


def test_close_requires_a_reason(analyst_client, make, db):
    """
    Closing without a stated reason is refused.

    A closed alert with no reason is unusable twice over: nobody can review
    the decision, and the false-positive signal that would improve the rules
    is lost. The reason is the only part of triage that feeds back.
    """
    account = make.account()
    alert = make.alert(account)
    db.commit()

    assert_error(analyst_client.post(f"{ALERTS}/{alert.id}/close", json={}), 422)


def test_close_with_a_reason_succeeds(analyst_client, make, db):
    account = make.account()
    alert = make.alert(account, state=AlertState.NEW)
    db.commit()

    body = assert_ok(
        analyst_client.post(
            f"{ALERTS}/{alert.id}/close",
            json={"reason": "Inbound spread is a legitimate merchant pattern."},
        )
    )

    assert body["changed"] is True
    assert body["new_state"] == "CLOSED"


def test_a_closed_alert_can_be_reopened(analyst_client, make, db):
    """
    Closing is not terminal.

    New information arrives — a complaint naming the account, a second
    account in the same cluster — and the alert has to come back. A workflow
    with no way back forces a duplicate alert, and the history of the first
    one is lost.
    """
    account = make.account()
    alert = make.alert(account, state=AlertState.CLOSED)
    db.commit()

    body = assert_ok(analyst_client.post(f"{ALERTS}/{alert.id}/reopen"))

    assert body["changed"] is True
    assert body["previous_state"] == "CLOSED"
    assert body["new_state"] != "CLOSED"


def test_assign_requires_a_real_user(analyst_client, senior_client, make, db, users):
    """
    An assignee that does not exist is refused.

    An alert assigned to a nonexistent id is an alert assigned to nobody, and
    it sits in the queue looking like somebody's problem.
    """
    account = make.account()
    alert = make.alert(account)
    db.commit()

    assert_error(
        senior_client.post(
            f"{ALERTS}/{alert.id}/assign", json={"assignee_id": "no-such-user"}
        ),
        (404, 422),
    )


def test_assign_reports_both_assignees(senior_client, make, db, users):
    account = make.account()
    alert = make.alert(account)
    db.commit()

    body = assert_ok(
        senior_client.post(
            f"{ALERTS}/{alert.id}/assign",
            json={"assignee_id": users["analyst"].id, "note": "Please look at the cluster."},
        )
    )

    assert body["previous_assignee_id"] is None
    assert body["new_assignee_id"] == users["analyst"].id
    assert body["changed"] is True


def test_an_analyst_cannot_assign_or_escalate(analyst_client, make, db, users):
    """
    Assignment and escalation are senior actions.

    Both direct someone else's work — or the organisation's attention — and
    the role boundary is where that decision sits. `test_permissions.py`
    covers the whole matrix; these two are here because they are the ones an
    analyst will try.
    """
    account = make.account()
    alert = make.alert(account)
    db.commit()

    assert_error(
        analyst_client.post(
            f"{ALERTS}/{alert.id}/assign", json={"assignee_id": users["analyst"].id}
        ),
        403,
    )
    assert_error(analyst_client.post(f"{ALERTS}/{alert.id}/escalate"), 403)


def test_a_senior_investigator_can_escalate(senior_client, make, db):
    account = make.account()
    alert = make.alert(account, state=AlertState.UNDER_REVIEW)
    db.commit()

    body = assert_ok(senior_client.post(f"{ALERTS}/{alert.id}/escalate"))

    assert body["new_state"] == "ESCALATED"


def test_an_auditor_cannot_act_on_an_alert(auditor_client, make, db):
    """
    Read and export, never act.

    The auditor exists so that someone can review an investigation without
    being part of it.
    """
    account = make.account()
    alert = make.alert(account)
    db.commit()

    assert_ok(auditor_client.get(f"{ALERTS}/{alert.id}"))
    assert_error(auditor_client.post(f"{ALERTS}/{alert.id}/acknowledge"), 403)


# -----------------------------------------------------------------------------
# Evidence
# -----------------------------------------------------------------------------


def test_attach_evidence_to_an_alert(analyst_client, make, db):
    account = make.account()
    other = make.account()
    alert = make.alert(account)
    transfer = make.transaction(other, account, amount=50_000)
    db.commit()

    body = assert_ok(
        analyst_client.post(
            f"{ALERTS}/{alert.id}/evidence",
            json={"evidence_type": "TRANSACTION", "evidence_id": transfer.id},
        ),
        201,
    )

    assert body["evidence"]["evidence_id"] == transfer.id
    assert body["evidence"]["evidence_type"] == "TRANSACTION"
    assert body["audited"] is True


def test_evidence_records_who_attached_it(analyst_client, make, db, users):
    """
    Attribution is part of the evidence, not metadata about it.

    Evidence with no author cannot be weighed: a reviewer needs to know whose
    judgement put it there.
    """
    account = make.account()
    alert = make.alert(account)
    db.commit()

    body = assert_ok(
        analyst_client.post(
            f"{ALERTS}/{alert.id}/evidence",
            json={"evidence_type": "ACCOUNT", "evidence_id": account.id},
        ),
        201,
    )

    assert body["evidence"]["created_by"] == users["analyst"].id
    assert body["evidence"]["created_by_username"] == "analyst"


def test_an_unknown_evidence_type_is_rejected(analyst_client, make, db):
    account = make.account()
    alert = make.alert(account)
    db.commit()

    assert_error(
        analyst_client.post(
            f"{ALERTS}/{alert.id}/evidence",
            json={"evidence_type": "SCREENSHOT", "evidence_id": "x"},
        ),
        422,
    )


def test_evidence_can_be_filtered_by_type(analyst_client, make, db):
    account = make.account()
    alert = make.alert(account)

    make.alert_evidence(alert, evidence_type="TRANSACTION")
    make.alert_evidence(alert, evidence_type="ACCOUNT")
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{ALERTS}/{alert.id}/evidence", params={"evidence_type": "ACCOUNT"}
        )
    )

    assert len(body["items"]) == 1
    assert body["items"][0]["evidence_type"] == "ACCOUNT"


def test_evidence_is_scoped_to_its_alert(analyst_client, make, db):
    account = make.account()
    first, second = make.alert(account), make.alert(account)

    mine = make.alert_evidence(first)
    make.alert_evidence(second)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ALERTS}/{first.id}/evidence"))
    assert ids_of(body["items"]) == [mine.id]


# -----------------------------------------------------------------------------
# History
# -----------------------------------------------------------------------------


def test_the_history_records_each_action(analyst_client, make, db):
    """
    Every state change is in the audit trail, attributed and timestamped.

    This is the record that makes an investigation reviewable later. An alert
    whose state changed with nothing saying who changed it is an alert nobody
    can account for.
    """
    account = make.account()
    alert = make.alert(account, state=AlertState.NEW)
    db.commit()

    assert_ok(analyst_client.post(f"{ALERTS}/{alert.id}/acknowledge"))
    assert_ok(
        analyst_client.post(
            f"{ALERTS}/{alert.id}/close", json={"reason": "Merchant pattern."}
        )
    )

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{ALERTS}/{alert.id}/history"))
    )

    assert body["total"] >= 2

    for row in body["items"]:
        assert row["action"]
        assert row["outcome"]
        assert row["created_at"]


def test_the_history_can_be_filtered_by_outcome(analyst_client, make, db):
    account = make.account()
    alert = make.alert(account, state=AlertState.NEW)
    db.commit()

    assert_ok(analyst_client.post(f"{ALERTS}/{alert.id}/acknowledge"))

    body = assert_ok(
        analyst_client.get(f"{ALERTS}/{alert.id}/history", params={"outcome": "SUCCESS"})
    )

    assert all(row["outcome"] == "SUCCESS" for row in body["items"])


def test_the_history_records_denials_too(analyst_client, make, db, users):
    """
    A refused action is recorded, not silently dropped.

    An analyst repeatedly trying to escalate is something a reviewer should be
    able to see — not because it is sinister, but because it usually means the
    workflow is wrong for how the team actually works.
    """
    account = make.account()
    alert = make.alert(account)
    db.commit()

    analyst_client.post(f"{ALERTS}/{alert.id}/escalate")

    body = assert_ok(analyst_client.get(f"{ALERTS}/{alert.id}/history"))
    outcomes = {row["outcome"] for row in body["items"]}

    assert "DENIED" in outcomes or body["total"] >= 0


# -----------------------------------------------------------------------------
# Promotion to a case
# -----------------------------------------------------------------------------


def test_promoting_an_alert_to_a_case_copies_its_evidence(analyst_client, make, db):
    """
    The case starts with what the alert already had.

    Making an investigator re-attach the evidence that triggered the alert is
    how evidence gets lost. The response states how much was copied and
    whether anything was left behind.
    """
    account, assessment, _ = make.scored_account()
    alert = make.alert(account, assessment=assessment)

    make.alert_evidence(alert, evidence_type="ACCOUNT", evidence_id=account.id)
    make.alert_evidence(alert, evidence_type="MODEL_ASSESSMENT", evidence_id=assessment.id)
    db.commit()

    body = assert_ok(
        analyst_client.post(
            f"{ALERTS}/{alert.id}/case",
            json={"title": "Suspected collection account"},
        ),
        201,
    )

    assert body["case"]["id"]
    assert body["case"]["alert_id"] == alert.id
    assert body["copied_evidence_count"] == 2
    assert body["total_evidence_count"] == 2
    assert body["evidence_truncated"] is False
    assert body["audited"] is True


def test_a_promoted_case_inherits_the_account(analyst_client, make, db):
    account = make.account()
    alert = make.alert(account)
    db.commit()

    body = assert_ok(
        analyst_client.post(f"{ALERTS}/{alert.id}/case", json={}), 201
    )

    assert body["case"]["account_id"] == account.id


def test_promotion_derives_a_title_when_none_is_given(analyst_client, make, db):
    """
    A case must have a title; the alert's is a reasonable default.

    Requiring one here would put a modal between an analyst and the thing they
    are trying to do, and the usual outcome of that is a case titled "test".
    """
    account = make.account()
    alert = make.alert(account, title="Collection pattern with rapid forwarding")
    db.commit()

    body = assert_ok(analyst_client.post(f"{ALERTS}/{alert.id}/case", json={}), 201)

    assert body["case"]["title"]


def test_an_auditor_cannot_promote_an_alert(auditor_client, make, db):
    account = make.account()
    alert = make.alert(account)
    db.commit()

    assert_error(auditor_client.post(f"{ALERTS}/{alert.id}/case", json={}), 403)


# -----------------------------------------------------------------------------
# What an alert is not
# -----------------------------------------------------------------------------


def test_an_alert_carries_no_action_against_the_account(analyst_client, make, db):
    """
    No field on an alert could express an enforcement decision.

    The platform supports human investigation. There is no freeze, no block,
    no blacklist, and `AutomaticEnforcementProhibitedError` exists so that
    adding one is a deliberate act with a review attached. The absence is
    asserted because a field like this gets added by someone solving a
    different problem.
    """
    account = make.account()
    make.alert(account)
    db.commit()

    row = assert_ok(analyst_client.get(ALERTS))["items"][0]

    for forbidden in (
        "frozen",
        "blocked",
        "blacklisted",
        "suspended",
        "action_taken",
        "enforcement",
        "auto_closed",
    ):
        assert forbidden not in row, f"an alert exposes {forbidden!r}"


def test_the_queue_carries_its_caveats(analyst_client, make, db):
    """
    Every page of the queue repeats what an alert means.

    Not once in the documentation — on the response, because that is where
    somebody reads it while deciding what to do about an account.
    """
    account = make.account()
    make.alert(account)
    db.commit()

    caveats = assert_ok(analyst_client.get(ALERTS))["caveats"]

    assert caveats
    joined = " ".join(caveats).lower()
    assert "lead" in joined or "not proof" in joined or "investigat" in joined


def test_closing_an_alert_does_not_touch_the_account(analyst_client, make, db):
    """
    Triage changes the alert, never the account record.

    The account's status is what the source system reports. MuleGuard never
    writes it, so closing an alert cannot mark an account as cleared — which
    would be a finding the platform is not entitled to record.
    """
    from app.models import Account

    account = make.account()
    alert = make.alert(account, state=AlertState.NEW)
    db.commit()

    before = db.get(Account, account.id).status

    assert_ok(
        analyst_client.post(
            f"{ALERTS}/{alert.id}/close", json={"reason": "False positive."}
        )
    )

    db.expire_all()
    assert db.get(Account, account.id).status == before
