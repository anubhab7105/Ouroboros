"""
One investigation, start to finish, through the API.

Every other module tests a step. This one tests that the steps join up, which
is a different property and the one that actually fails in practice: each
endpoint passes its own tests while the handoff between two of them loses an
id, drops a permission, or leaves a record in a state the next step refuses.

The journey, as an investigator would run it:

    ingest      an admin loads accounts and transfers
    analyse     an analyst triggers a run; it scores accounts and raises alerts
    triage      the analyst reads the queue and acknowledges an alert
    assign      a senior gives it an owner
    open        a case is opened from the alert, carrying its evidence across
    work        assign, start, note, attach more evidence
    escalate    with a reason, to a senior
    close       with a reason and a disposition
    report      the case exports, including after closure
    audit       the whole thing is on the record

Two properties are only visible from here.

**Ids survive the handoffs.** The account the run scored is the account the
alert names, is the account the case names, is the account the report covers.
A journey that quietly changes subject halfway is the failure mode no
single-endpoint test can see.

**Nothing in it takes adverse action.** Scoring, alerting, escalating and
closing are all human workflow, and the account's own status is untouched at
the end. This is the platform's central claim, and the end of the journey is
where it would have been broken.

The role split is not decoration: an analyst cannot assign or close, so the
journey needs two people. That is the control being tested.
"""

from __future__ import annotations

import pytest

from app.models import AlertState, CaseStatus

from tests.utils import (
    assert_error,
    assert_has_caveats,
    assert_ok,
    assert_paginated,
    find_by,
)

pytestmark = pytest.mark.e2e


API = "/api/v1"


# -----------------------------------------------------------------------------
# Helpers
#
# Each one is a step of the journey, so a test can start partway along without
# repeating the whole thing, and a failure names the step that broke.
# -----------------------------------------------------------------------------


def run_analysis(client, *, account_ids: list[str]) -> dict:
    """Trigger one synchronous analysis run over named accounts."""
    body = assert_ok(
        client.post(
            f"{API}/analysis/runs",
            json={"account_ids": account_ids},
        ),
        (200, 201),
    )

    assert body["status"] in {"SUCCEEDED", "COMPLETED", "PARTIAL"}, body["status"]
    return body


def open_case_from_alert(client, alert_id: str, **payload) -> dict:
    """Open an investigation case from an alert, carrying its evidence."""
    return assert_ok(
        client.post(f"{API}/alerts/{alert_id}/case", json=payload or {}),
        (200, 201),
    )


def close_case(client, case_id: str, *, disposition: str, reason: str) -> dict:
    return assert_ok(
        client.post(
            f"{API}/cases/{case_id}/close",
            json={"reason": reason, "disposition": disposition},
        )
    )


# -----------------------------------------------------------------------------
# The journey
# -----------------------------------------------------------------------------


class TestFullInvestigation:
    """Collection pattern found, investigated, concluded."""

    def test_the_whole_journey(
        self,
        admin_client,
        analyst_client,
        senior_client,
        make,
        db,
        load_fixture,
    ):
        # --- ingest ------------------------------------------------------
        accounts = load_fixture("accounts.valid.json")
        ingested = assert_ok(
            admin_client.post(f"{API}/ingestion/accounts", json=accounts),
            (200, 201),
        )

        assert ingested["accepted"] >= 1
        assert ingested["rejected"] == 0

        # The transfers that make the shape. Built directly rather than
        # ingested, because the point here is the handoff from analysis
        # onwards and the fan-in builder states the pattern in one line.
        collector, senders, transfers = make.fan_in(sources=12)
        db.commit()

        # --- analyse -----------------------------------------------------
        run = run_analysis(analyst_client, account_ids=[collector.id])

        assert run["account_count"] == 1
        assert run["assessment_count"] >= 1
        assert_has_caveats(run)

        results = assert_ok(
            analyst_client.get(f"{API}/analysis/runs/{run['id']}/results")
        )

        assert results["assessments"], "a completed run produced no assessments"
        assert results["run"]["id"] == run["id"]
        assert collector.id in {
            row["account_id"] for row in results["assessments"]
        }

        # --- triage ------------------------------------------------------
        queue = assert_paginated(
            assert_ok(
                analyst_client.get(
                    f"{API}/alerts",
                    params={"account_id": collector.id},
                )
            )
        )

        assert queue["items"], "a scored collection account raised no alert"
        alert = queue["items"][0]
        alert_id = alert["id"]

        assert alert["account_id"] == collector.id
        assert alert["state"] == AlertState.NEW.value

        acknowledged = assert_ok(
            analyst_client.post(f"{API}/alerts/{alert_id}/acknowledge", json={})
        )

        assert acknowledged["changed"] is True
        assert acknowledged["previous_state"] == AlertState.NEW.value

        # --- assign ------------------------------------------------------
        # An analyst may not assign. That is the control, not an obstacle.
        assert_error(
            analyst_client.post(
                f"{API}/alerts/{alert_id}/assign",
                json={"assignee_id": "usr_analyst"},
            ),
            403,
        )

        assigned = assert_ok(
            senior_client.post(
                f"{API}/alerts/{alert_id}/assign",
                json={"assignee_id": "usr_analyst"},
            )
        )

        assert assigned["changed"] is True

        # --- open a case -------------------------------------------------
        opened = open_case_from_alert(
            analyst_client,
            alert_id,
            title="Collection account with rapid forwarding",
        )
        case_id = opened["case"]["id"]

        assert opened["case"]["account_id"] == collector.id
        assert opened["case"]["alert_id"] == alert_id
        assert opened["case"]["status"] == CaseStatus.NEW.value
        assert opened["audited"] is True

        # The alert moves out of the queue: somebody has opened a case on it.
        assert opened["alert"]["state"] == AlertState.UNDER_REVIEW.value

        # --- work it -----------------------------------------------------
        # Assigning a new case triages it. Starting is a separate act, and it
        # needs an owner, so the order here is the order the API enforces.
        assert_error(
            analyst_client.post(f"{API}/cases/{case_id}/start", json=None),
            409,
        )

        case_assigned = assert_ok(
            senior_client.post(
                f"{API}/cases/{case_id}/assign",
                json={"assignee_id": "usr_analyst"},
            )
        )

        assert case_assigned["case"]["status"] == CaseStatus.TRIAGED.value

        started = assert_ok(analyst_client.post(f"{API}/cases/{case_id}/start"))

        assert started["changed"] is True
        assert started["new_status"] == CaseStatus.UNDER_INVESTIGATION.value

        assert_ok(
            analyst_client.post(
                f"{API}/cases/{case_id}/notes",
                json={"note": "Twelve senders in six hours, none previously linked."},
            ),
            (200, 201),
        )

        evidence = assert_ok(
            analyst_client.post(
                f"{API}/cases/{case_id}/evidence",
                json={
                    "evidence_type": "TRANSACTION",
                    "evidence_id": transfers[0].id,
                },
            ),
            (200, 201),
        )

        assert evidence["audited"] is True

        listed_evidence = assert_paginated(
            assert_ok(analyst_client.get(f"{API}/cases/{case_id}/evidence"))
        )

        assert transfers[0].id in {
            row["evidence_id"] for row in listed_evidence["items"]
        }

        # --- escalate ----------------------------------------------------
        escalated = assert_ok(
            analyst_client.post(
                f"{API}/cases/{case_id}/escalate",
                json={"reason": "Two senders appear in an unrelated complaint."},
            )
        )

        assert escalated["new_status"] == CaseStatus.ESCALATED.value

        # --- close -------------------------------------------------------
        # An analyst may not close, and a close needs a disposition.
        assert_error(
            analyst_client.post(
                f"{API}/cases/{case_id}/close",
                json={"reason": "Done.", "disposition": "CONFIRMED_FRAUD"},
            ),
            403,
        )
        assert_error(
            senior_client.post(
                f"{API}/cases/{case_id}/close",
                json={"reason": "Done looking at this."},
            ),
            422,
        )

        closed = close_case(
            senior_client,
            case_id,
            disposition="CONFIRMED_FRAUD",
            reason="Collection pattern confirmed across twelve unrelated senders.",
        )

        assert closed["new_status"] == CaseStatus.CLOSED.value
        assert closed["case"]["disposition"] == "CONFIRMED_FRAUD"

        # --- report ------------------------------------------------------
        report = assert_ok(
            analyst_client.post(f"{API}/reports/cases/{case_id}/generate"),
            (200, 201),
        )

        assert report["case_id"] == case_id
        assert report["size_bytes"] > 0
        assert report["sha256"]
        assert report["filename"].endswith(".pdf")
        assert_has_caveats(report)

        export = assert_ok(analyst_client.get(f"{API}/cases/{case_id}/export"))

        assert export["case"]["id"] == case_id
        assert export["case"]["account_id"] == collector.id
        assert export["evidences"]

        # --- audit -------------------------------------------------------
        trail = assert_paginated(
            assert_ok(
                admin_client.get(
                    f"{API}/audit",
                    params={"resource_id": case_id, "page_size": 100},
                )
            )
        )
        actions = {row["action"] for row in trail["items"]}

        for expected in ("case_assign", "case_start", "case_escalate", "case_close"):
            assert expected in actions, f"{expected} left no audit record"

        # --- and nothing was done to the account -------------------------
        db.refresh(collector)
        account = assert_ok(analyst_client.get(f"{API}/accounts/{collector.id}"))

        assert account["status"] == "ACTIVE"
        assert len(senders) == 12


# -----------------------------------------------------------------------------
# Journey-level properties
#
# Each of these starts partway along rather than repeating the whole journey.
# -----------------------------------------------------------------------------


class TestEvidenceCarriesAcross:
    """What the alert collected, the case inherits."""

    def test_alert_evidence_is_copied_into_the_case(
        self,
        analyst_client,
        make,
        db,
    ):
        account, assessment, _ = make.scored_account()
        alert = make.alert(account, assessment=assessment)
        make.alert_evidence(alert, evidence_type="ACCOUNT", evidence_id=account.id)
        make.alert_evidence(alert, evidence_type="MODEL_ASSESSMENT", evidence_id=assessment.id)
        db.commit()

        opened = open_case_from_alert(analyst_client, alert.id)

        assert opened["copied_evidence_count"] == 2
        assert opened["total_evidence_count"] == 2

        case_evidence = assert_paginated(
            assert_ok(
                analyst_client.get(f"{API}/cases/{opened['case']['id']}/evidence")
            )
        )

        assert {row["evidence_id"] for row in case_evidence["items"]} == {
            account.id,
            assessment.id,
        }

    def test_the_copy_is_reported_when_it_was_truncated(
        self,
        analyst_client,
        make,
        db,
        monkeypatch,
    ):
        """
        A bounded copy that silently stopped would leave a case that looks
        complete and is not.

        The bound is a module constant rather than a setting, so it is patched
        here instead of configured. Five items against a limit of two is the
        same arithmetic as a hundred and one against a hundred, and does not
        need a hundred fixtures to demonstrate.
        """
        from app.api.v1.endpoints import alerts as alerts_endpoint

        account = make.account()
        alert = make.alert(account)

        for index in range(5):
            make.alert_evidence(alert, evidence_id=f"evi_{index}")

        db.commit()

        monkeypatch.setattr(alerts_endpoint, "_MAX_BUNDLE_ITEMS", 2)

        opened = open_case_from_alert(analyst_client, alert.id)

        assert opened["evidence_truncated"] is True
        assert opened["copied_evidence_count"] == 2
        assert opened["total_evidence_count"] == 5


class TestClosureIsNotDeletion:
    """A concluded case stays readable."""

    def test_a_closed_case_still_exports(self, senior_client, make, db, users):
        case = make.case(
            status=CaseStatus.UNDER_INVESTIGATION,
            assignee=users["analyst"],
        )
        db.commit()
        assert_ok(
            senior_client.post(
                f"{API}/cases/{case.id}/notes",
                json={"note": "Reviewed the evidence before closure."},
            ),
            (200, 201),
        )

        close_case(
            senior_client,
            case.id,
            disposition="INCONCLUSIVE",
            reason="No further activity after the initial burst.",
        )

        export = assert_ok(senior_client.get(f"{API}/cases/{case.id}/export"))

        assert export["case"]["status"] == CaseStatus.CLOSED.value
        assert export["case"]["disposition"] == "INCONCLUSIVE"
        assert export["notes"], "closure dropped the case notes"

    def test_reopening_records_why_and_keeps_the_history(
        self,
        senior_client,
        make,
        db,
        users,
    ):
        case = make.case(
            status=CaseStatus.UNDER_INVESTIGATION,
            assignee=users["analyst"],
        )
        db.commit()

        close_case(
            senior_client,
            case.id,
            disposition="FALSE_POSITIVE",
            reason="Sender cluster explained by a payroll run.",
        )

        reopened = assert_ok(
            senior_client.post(
                f"{API}/cases/{case.id}/reopen",
                json={"reason": "A third complaint names the same account."},
            )
        )

        assert reopened["previous_status"] == CaseStatus.CLOSED.value
        assert reopened["new_status"] == CaseStatus.UNDER_INVESTIGATION.value

        events = assert_paginated(
            assert_ok(senior_client.get(f"{API}/cases/{case.id}/events"))
        )
        actions = [row["action"] for row in events["items"]]

        assert "case_close" in actions, "closure was erased by reopening"
        assert "case_reopen" in actions

    def test_a_reopen_without_a_reason_is_refused(
        self,
        senior_client,
        make,
        db,
        users,
    ):
        from app.models import Disposition

        case = make.case(
            status=CaseStatus.CLOSED,
            disposition=Disposition.INCONCLUSIVE,
            assignee=users["analyst"],
        )
        db.commit()

        assert_error(
            senior_client.post(f"{API}/cases/{case.id}/reopen", json={}),
            422,
        )


class TestTheRecordIsComplete:
    """Every material action is on the audit trail."""

    def test_each_mutation_leaves_exactly_one_record(
        self,
        senior_client,
        admin_client,
        make,
        db,
        users,
    ):
        case = make.case(status=CaseStatus.TRIAGED, assignee=users["analyst"])
        db.commit()

        assert_ok(senior_client.post(f"{API}/cases/{case.id}/start"))
        close_case(
            senior_client,
            case.id,
            disposition="REFERRED",
            reason="Passed to the fraud desk with the sender list.",
        )

        trail = assert_paginated(
            assert_ok(
                admin_client.get(
                    f"{API}/audit",
                    params={"resource_id": case.id, "page_size": 100},
                )
            )
        )
        actions = [row["action"] for row in trail["items"]]

        assert actions.count("case_start") == 1
        assert actions.count("case_close") == 1

    def test_a_no_op_action_is_not_audited(
        self,
        senior_client,
        admin_client,
        make,
        db,
        users,
    ):
        """
        Starting an already-started case changes nothing, and an audit row
        saying otherwise would be a record of an event that did not happen.
        """
        case = make.case(
            status=CaseStatus.UNDER_INVESTIGATION,
            assignee=users["analyst"],
        )
        db.commit()

        response = assert_ok(senior_client.post(f"{API}/cases/{case.id}/start"))

        assert response["changed"] is False
        assert response["audited"] is False

        trail = assert_paginated(
            assert_ok(
                admin_client.get(
                    f"{API}/audit",
                    params={"resource_id": case.id, "page_size": 100},
                )
            )
        )

        assert "case_start" not in {row["action"] for row in trail["items"]}

    def test_the_actor_is_recorded_not_just_the_action(
        self,
        senior_client,
        admin_client,
        make,
        db,
        users,
    ):
        case = make.case(status=CaseStatus.UNDER_INVESTIGATION, assignee=users["analyst"])
        db.commit()

        close_case(
            senior_client,
            case.id,
            disposition="CONFIRMED_FRAUD",
            reason="Confirmed against the complaint narrative.",
        )

        trail = assert_paginated(
            assert_ok(
                admin_client.get(
                    f"{API}/audit",
                    params={"resource_id": case.id, "page_size": 100},
                )
            )
        )
        row = find_by(trail["items"], action="case_close")

        assert row is not None
        assert row["actor_id"] == str(users["senior"].id)


class TestNoAdverseAction:
    """
    The end of the journey is where the central claim would break.

    A platform that scores an account, raises an alert, opens a case and
    concludes it has every opportunity to change something about that account
    along the way. It does not, and that is asserted rather than assumed.
    """

    def test_concluding_an_investigation_leaves_the_account_alone(
        self,
        senior_client,
        make,
        db,
        users,
    ):
        account, assessment, _ = make.scored_account(score=96)
        alert = make.alert(account, assessment=assessment)
        case = make.case(
            account=account,
            alert=alert,
            status=CaseStatus.UNDER_INVESTIGATION,
            assignee=users["analyst"],
        )
        db.commit()

        before = account.status

        close_case(
            senior_client,
            case.id,
            disposition="CONFIRMED_FRAUD",
            reason="Confirmed collection account.",
        )
        db.refresh(account)

        assert account.status == before

    def test_the_closure_response_says_so(self, senior_client, make, db, users):
        case = make.case(status=CaseStatus.UNDER_INVESTIGATION, assignee=users["analyst"])
        db.commit()

        closed = close_case(
            senior_client,
            case.id,
            disposition="CONFIRMED_FRAUD",
            reason="Confirmed collection account.",
        )
        caveats = " ".join(assert_has_caveats(closed)).lower()

        assert "does not close, freeze, block, blacklist, or restrict" in caveats
        assert "investigator-entered" in caveats

    def test_a_critical_score_is_still_only_a_lead(self, analyst_client, make, db):
        """
        The highest band the platform can produce, read back with its own
        stored caveats and its indicators. Nothing in it is a conclusion.
        """
        account, assessment, indicators = make.scored_account(score=99, indicators=3)
        db.commit()

        body = assert_ok(analyst_client.get(f"{API}/accounts/{account.id}/assessment"))

        assert body["available"] is True
        assert body["status"] == "available"
        assert body["assessment"]["account_id"] == account.id
        assert body["assessment"]["risk_band"] == "CRITICAL"
        assert body["assessment"]["score_type"]
        assert body["assessment"]["caveats_json"]
        assert len(body["indicators"]) == len(indicators)

    def test_an_unscored_account_reports_that_rather_than_a_zero(
        self,
        analyst_client,
        make,
        db,
    ):
        """
        The distinction the whole response shape exists for. An account
        nothing has looked at is `no_assessment`, not a score of zero in the
        LOW band, which is what a client would render from a null.
        """
        account = make.account()
        db.commit()

        body = assert_ok(analyst_client.get(f"{API}/accounts/{account.id}/assessment"))

        assert body["available"] is False
        assert body["status"] == "no_assessment"
        assert body["assessment"] is None
        assert body["message"]
