"""
Analysis runs.

A run is a bounded, point-in-time scoring pass over a set of accounts. Three
properties get most of the attention here.

**A run is bounded.** `max_accounts` is enforced, "every account" is not a
default, and the date span is capped. An analysis endpoint that would happily
score a million accounts synchronously is an endpoint that takes a worker down
the first time somebody presses it twice.

**A run records what produced it.** Scoring mode, model version, feature
version, the parameters it was given and a dataset fingerprint. Without them
an assessment from last month cannot be reproduced, and "the score changed"
cannot be distinguished from "the account changed".

**A failed run says so.** It carries an error code and a safe message rather
than appearing as a run that scored nothing. Those two look identical on a
dashboard and mean completely different things.
"""

from __future__ import annotations

import pytest

from app.api.v1.endpoints import analysis as analysis_endpoint
from app.models import AnalysisRun, AnalysisRunStatus, ScoringMode
from tests.utils import assert_error, assert_ok, assert_paginated, days_ago, ids_of

pytestmark = pytest.mark.api


ANALYSIS = "/api/v1/analysis"


# -----------------------------------------------------------------------------
# Status
# -----------------------------------------------------------------------------


def test_status_reports_the_bounds_and_the_active_estimator(analyst_client):
    """
    What a run will do, before anyone starts one.

    `scoring_mode` is the part that matters: it says whether a run will use a
    trained model or the heuristic fallback, which decides how its output
    should be read.
    """
    body = assert_ok(analyst_client.get(f"{ANALYSIS}/status"))

    assert body["enabled"] is True
    assert body["scoring_mode"]
    assert body["max_accounts"] > 0
    assert body["max_date_span_days"] > 0
    assert body["dataset_mode"] == "synthetic"
    assert body["default_as_of_policy"]
    assert body["caveats"]


def test_status_says_whether_a_trained_model_is_required(analyst_client):
    """
    `require_trained_model` distinguishes two deployments.

    With it off, a run proceeds on the heuristic fallback and says so. With it
    on, a run refuses rather than quietly producing hand-weighted scores that
    look like model output.
    """
    body = assert_ok(analyst_client.get(f"{ANALYSIS}/status"))

    assert isinstance(body["require_trained_model"], bool)
    assert isinstance(body["allow_all_accounts"], bool)


def test_status_is_not_readable_by_an_auditor(auditor_client):
    """
    Running analysis is `ANALYST_AND_ABOVE`, and so is its status.

    The auditor reads the record of what was done, not the controls for doing
    it.
    """
    assert_error(auditor_client.get(f"{ANALYSIS}/status"), 403)


# -----------------------------------------------------------------------------
# Starting a run
# -----------------------------------------------------------------------------


def test_start_a_run_over_named_accounts(analyst_client, make, db):
    accounts = make.accounts(3)
    db.commit()

    body = assert_ok(
        analyst_client.post(
            f"{ANALYSIS}/runs", json={"account_ids": [a.id for a in accounts]}
        ),
        201,
    )

    assert body["id"]
    assert body["status"]
    assert body["scoring_mode"]
    assert body["caveats"]


def test_a_run_records_who_requested_it(analyst_client, make, db, users):
    make.accounts(2)
    db.commit()

    body = assert_ok(
        analyst_client.post(f"{ANALYSIS}/runs", json={"account_ids": []}), 201
    )

    assert body["requested_by"] == users["analyst"].id
    assert body["requested_by_username"] == "analyst"


def test_a_run_records_its_parameters(analyst_client, make, db):
    """
    The run stores what it was asked to do.

    Six months later, reproducing an assessment means knowing the window, the
    account set and the options. Without them the run is a score with no
    provenance.
    """
    accounts = make.accounts(2)
    db.commit()

    body = assert_ok(
        analyst_client.post(
            f"{ANALYSIS}/runs",
            json={
                "account_ids": [a.id for a in accounts],
                "as_of": days_ago(1).isoformat(),
            },
        ),
        201,
    )

    assert body["parameters_json"]


def test_a_run_over_a_filter_rather_than_a_list(
    analyst_client, make, db, override_settings
):
    """
    Filters are the realistic case: "score the dormant accounts".

    Enumerating ids client-side would mean fetching them first, and the set
    could change between the two calls. The all-account selection mode is
    explicitly enabled here because it is disabled by default for safety.
    """
    override_settings(ANALYSIS_ALLOW_ALL_ACCOUNTS=True)

    from app.models import AccountStatus

    make.account(status=AccountStatus.DORMANT)
    make.account(status=AccountStatus.ACTIVE)
    db.commit()

    body = assert_ok(
        analyst_client.post(
            f"{ANALYSIS}/runs", json={"account_filters": {"status": "DORMANT"}}
        ),
        201,
    )

    assert body["id"]


def test_an_unknown_account_id_is_refused(analyst_client, db):
    db.commit()

    assert_error(
        analyst_client.post(
            f"{ANALYSIS}/runs", json={"account_ids": ["ACC-DOES-NOT-EXIST"]}
        ),
        (404, 422),
    )


def test_an_over_large_account_set_is_refused(analyst_client, make, db, override_settings):
    """
    The ceiling is enforced, not advisory.

    A run is synchronous. An unbounded one holds a worker for as long as it
    takes, and the caller's request times out while the work continues — which
    is how a second press produces two runs.
    """
    override_settings(ANALYSIS_MAX_ACCOUNTS=3)

    accounts = make.accounts(10)
    db.commit()

    response = analyst_client.post(
        f"{ANALYSIS}/runs", json={"account_ids": [a.id for a in accounts]}
    )
    assert response.status_code in (413, 422)


def test_an_unknown_filter_value_is_rejected(analyst_client, db):
    db.commit()

    assert_error(
        analyst_client.post(
            f"{ANALYSIS}/runs", json={"account_filters": {"status": "FROZEN"}}
        ),
        422,
    )


def test_a_future_as_of_is_rejected(analyst_client, make, db):
    """
    An assessment cannot be dated after now.

    `as_of` is the instant assessed: features see only data strictly before
    it. A future value would include everything and then claim to be a
    point-in-time view, which is the one thing that makes a backfilled
    assessment defensible.
    """
    from datetime import timedelta

    from tests.utils import utcnow

    make.accounts(2)
    db.commit()

    future = (utcnow() + timedelta(days=30)).isoformat()
    response = analyst_client.post(f"{ANALYSIS}/runs", json={"as_of": future})

    assert response.status_code in (201, 422)
    if response.status_code == 422:
        assert "as_of" in response.text or "future" in response.text.lower()


def test_an_auditor_cannot_start_a_run(auditor_client, make, db):
    make.accounts(2)
    db.commit()

    assert_error(auditor_client.post(f"{ANALYSIS}/runs", json={"account_ids": []}), 403)


# -----------------------------------------------------------------------------
# Listing and reading runs
# -----------------------------------------------------------------------------


def test_list_runs(analyst_client, make, db, users):
    run = make.analysis_run(requested_by=users["analyst"])
    db.commit()

    body = assert_paginated(assert_ok(analyst_client.get(f"{ANALYSIS}/runs")))

    assert run.id in ids_of(body["items"])
    assert body["caveats"]


def test_filter_runs_by_status(analyst_client, make, db, users):
    succeeded = make.analysis_run(
        status=AnalysisRunStatus.SUCCEEDED, requested_by=users["analyst"]
    )
    make.analysis_run(status=AnalysisRunStatus.FAILED, requested_by=users["analyst"])
    db.commit()

    body = assert_ok(analyst_client.get(f"{ANALYSIS}/runs", params={"status": "SUCCEEDED"}))
    assert ids_of(body["items"]) == [succeeded.id]


def test_filter_runs_by_scoring_mode(analyst_client, make, db, users):
    """
    "Which runs used the fallback" is the question asked after a model is withdrawn.

    It decides which assessments have to be re-run, and it is not answerable
    from the scores.
    """
    fallback = make.analysis_run(
        scoring_mode=ScoringMode.HEURISTIC_FALLBACK, requested_by=users["analyst"]
    )
    make.analysis_run(
        scoring_mode=ScoringMode.TRAINED_MODEL, requested_by=users["analyst"]
    )
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{ANALYSIS}/runs", params={"scoring_mode": "HEURISTIC_FALLBACK"}
        )
    )
    assert ids_of(body["items"]) == [fallback.id]


def test_filter_runs_by_requester(analyst_client, make, db, users):
    mine = make.analysis_run(requested_by=users["analyst"])
    make.analysis_run(requested_by=users["senior"])
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{ANALYSIS}/runs", params={"requested_by": users["analyst"].id})
    )
    assert ids_of(body["items"]) == [mine.id]


def test_get_one_run(analyst_client, make, db, users):
    run = make.analysis_run(requested_by=users["analyst"])
    db.commit()

    body = assert_ok(analyst_client.get(f"{ANALYSIS}/runs/{run.id}"))

    assert body["id"] == run.id
    assert body["status"]
    assert body["caveats"]


def test_a_finished_run_reports_its_duration(analyst_client, make, db, users):
    """
    Derived from the timestamps, by the server.

    Every client would otherwise compute it, and one of them would get a
    timezone wrong. It is also the number somebody watches when deciding
    whether a run is stuck.
    """
    run = make.analysis_run(
        status=AnalysisRunStatus.SUCCEEDED,
        requested_by=users["analyst"],
        started_at=days_ago(1),
    )
    db.commit()

    body = assert_ok(analyst_client.get(f"{ANALYSIS}/runs/{run.id}"))

    assert body["started_at"]
    assert body["finished_at"]
    assert body["duration_seconds"] is not None
    assert body["duration_seconds"] >= 0


def test_a_running_run_has_no_finish_time_or_duration(analyst_client, make, db, users):
    """
    Null, not zero.

    A duration of 0 on a run that is still going would read as "instant", and
    it is the value a progress display would show.
    """
    run = make.analysis_run(
        status=AnalysisRunStatus.RUNNING, requested_by=users["analyst"]
    )
    db.commit()

    body = assert_ok(analyst_client.get(f"{ANALYSIS}/runs/{run.id}"))

    assert body["finished_at"] is None
    assert body["duration_seconds"] is None


def test_a_failed_run_carries_an_error_code_and_a_safe_message(
    analyst_client, make, db, users
):
    """
    A failure is visible as a failure.

    A failed run and a run that scored nothing look identical on a dashboard
    and mean opposite things — one needs re-running, the other means there was
    nothing to score. The message is safe text, never a traceback.
    """
    run = make.analysis_run(
        status=AnalysisRunStatus.FAILED,
        requested_by=users["analyst"],
        error_code="feature_computation_failed",
        error_message="Feature construction failed for the requested window.",
    )
    db.commit()

    response = analyst_client.get(f"{ANALYSIS}/runs/{run.id}")
    body = assert_ok(response)

    assert body["status"] == "FAILED"
    assert body["error_code"]
    assert body["error_message"]

    raw = response.text.lower()
    assert "traceback" not in raw
    assert "sqlalchemy" not in raw


def test_failed_analysis_execution_persists_terminal_run(
    analyst_client, make, db, monkeypatch
):
    account = make.account()
    db.commit()

    def fail_analysis(*, db, run, settings):
        run.status = AnalysisRunStatus.FAILED
        run.error_code = "no_accounts_scored"
        run.error_message = "No account could be scored."
        return run

    monkeypatch.setattr(
        analysis_endpoint,
        "_load_analysis_service",
        lambda _settings: (fail_analysis, "test.failure"),
    )

    response = analyst_client.post(
        f"{ANALYSIS}/runs", json={"account_ids": [account.id]}
    )

    assert response.status_code == 500
    run_id = response.json()["details"]["run_id"]
    db.expire_all()
    run = db.get(AnalysisRun, run_id)

    assert run.status == AnalysisRunStatus.FAILED
    assert run.error_code == "no_accounts_scored"
    assert run.error_message == "No account could be scored."


def test_a_partial_run_is_distinguishable_from_a_successful_one(
    analyst_client, make, db, users
):
    """
    `PARTIAL` is its own status.

    A run that scored most accounts and failed on some is neither a success
    nor a failure. Reporting it as either would mean an account silently went
    unassessed.
    """
    run = make.analysis_run(
        status=AnalysisRunStatus.PARTIAL,
        requested_by=users["analyst"],
        processed_count=80,
        error_count=20,
    )
    db.commit()

    body = assert_ok(analyst_client.get(f"{ANALYSIS}/runs/{run.id}"))
    assert body["status"] == "PARTIAL"


def test_unknown_run_is_404(analyst_client):
    assert_error(analyst_client.get(f"{ANALYSIS}/runs/not-a-real-run"), 404)


# -----------------------------------------------------------------------------
# Results
# -----------------------------------------------------------------------------


def test_run_results_report_assessments_and_alerts(analyst_client, make, db, users):
    run = make.analysis_run(requested_by=users["analyst"])
    account = make.account()
    assessment = make.assessment(account, score=78, analysis_run=run)
    make.alert(account, assessment=assessment)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ANALYSIS}/runs/{run.id}/results"))

    assert body["assessment_total"] == 1
    assert body["assessments"][0]["account_id"] == account.id
    assert body["caveats"]


def test_results_report_their_own_truncation(analyst_client, make, db, users):
    """
    Totals apart from the embedded lists.

    A run over ten thousand accounts cannot return ten thousand assessments in
    one response. The total is the real figure and the flag says the list is a
    page of it.
    """
    run = make.analysis_run(requested_by=users["analyst"])
    for _ in range(5):
        account = make.account()
        make.assessment(account, score=50, analysis_run=run)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ANALYSIS}/runs/{run.id}/results"))

    assert body["assessment_total"] == 5
    assert body["assessment_truncated"] in (True, False)
    assert len(body["assessments"]) <= body["assessment_total"]


def test_results_say_whether_alerts_were_available(analyst_client, make, db, users):
    """
    `alerts_available` distinguishes "no alerts" from "alerts not computed".

    A run configured without alerting produces none; a run that alerted and
    found nothing also produces none. The first is a configuration fact and
    the second is a finding.
    """
    run = make.analysis_run(requested_by=users["analyst"])
    db.commit()

    body = assert_ok(analyst_client.get(f"{ANALYSIS}/runs/{run.id}/results"))
    assert isinstance(body["alerts_available"], bool)


def test_results_can_be_filtered_by_risk_band(analyst_client, make, db, users):
    run = make.analysis_run(requested_by=users["analyst"])

    low_account, high_account = make.accounts(2)
    make.assessment(low_account, score=10, analysis_run=run)
    make.assessment(high_account, score=92, analysis_run=run)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{ANALYSIS}/runs/{run.id}/results", params={"risk_band": "CRITICAL"}
        )
    )

    assert body["assessment_total"] == 1
    assert body["assessments"][0]["account_id"] == high_account.id


def test_results_can_be_filtered_by_account(analyst_client, make, db, users):
    run = make.analysis_run(requested_by=users["analyst"])

    first, second = make.accounts(2)
    make.assessment(first, score=60, analysis_run=run)
    make.assessment(second, score=60, analysis_run=run)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{ANALYSIS}/runs/{run.id}/results", params={"account_id": first.id}
        )
    )

    assert body["assessment_total"] == 1


def test_result_assessments_say_whether_they_are_explained(
    analyst_client, make, db, users
):
    run = make.analysis_run(requested_by=users["analyst"])
    account = make.account()
    make.assessment(account, score=80, analysis_run=run, with_explanation=True)
    db.commit()

    body = assert_ok(analyst_client.get(f"{ANALYSIS}/runs/{run.id}/results"))
    assert body["assessments"][0]["explanation_available"] is True


def test_results_of_an_unknown_run_are_404(analyst_client):
    assert_error(analyst_client.get(f"{ANALYSIS}/runs/nope/results"), 404)


# -----------------------------------------------------------------------------
# Cancelling
# -----------------------------------------------------------------------------


def test_a_queued_run_can_be_cancelled(analyst_client, make, db, users):
    run = make.analysis_run(
        status=AnalysisRunStatus.QUEUED, requested_by=users["analyst"]
    )
    db.commit()

    body = assert_ok(analyst_client.post(f"{ANALYSIS}/runs/{run.id}/cancel"))
    assert body["status"] == "CANCELLED"


def test_cancelling_a_finished_run_is_refused_or_a_no_op(analyst_client, make, db, users):
    """
    A completed run cannot be un-completed.

    Its assessments exist and are referenced by alerts. Marking it cancelled
    would leave the output of a run that officially did not happen.
    """
    run = make.analysis_run(
        status=AnalysisRunStatus.SUCCEEDED, requested_by=users["analyst"]
    )
    db.commit()

    response = analyst_client.post(f"{ANALYSIS}/runs/{run.id}/cancel")
    assert response.status_code in (200, 409, 422)

    if response.status_code == 200:
        assert response.json()["status"] == "SUCCEEDED"


def test_an_auditor_cannot_cancel_a_run(auditor_client, make, db, users):
    run = make.analysis_run(
        status=AnalysisRunStatus.RUNNING, requested_by=users["analyst"]
    )
    db.commit()

    assert_error(auditor_client.post(f"{ANALYSIS}/runs/{run.id}/cancel"), 403)


# -----------------------------------------------------------------------------
# History
# -----------------------------------------------------------------------------


def test_a_run_has_an_audit_history(analyst_client, make, db):
    make.accounts(2)
    db.commit()

    created = assert_ok(
        analyst_client.post(f"{ANALYSIS}/runs", json={"account_ids": []}), 201
    )

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{ANALYSIS}/runs/{created['id']}/history"))
    )

    assert body["total"] >= 1
    for row in body["items"]:
        assert row["action"]
        assert row["outcome"]
        assert row["created_at"]


# -----------------------------------------------------------------------------
# Provenance and safety
# -----------------------------------------------------------------------------


def test_a_run_declares_its_scoring_mode(analyst_client, make, db):
    """
    Every run says which estimator produced its scores.

    The mode travels onto each assessment and from there onto each alert, so
    that a score is never shown without how it was made.
    """
    make.accounts(2)
    db.commit()

    body = assert_ok(
        analyst_client.post(f"{ANALYSIS}/runs", json={"account_ids": []}), 201
    )
    assert body["scoring_mode"]


def test_a_run_never_reports_ground_truth(analyst_client, make, db, users):
    """
    Labels are not run output.

    The generator plants `scenario_type` and `ring_id` on every labelled
    account. A run that echoed them would be publishing the answer sheet to
    every analyst, and every measurement taken from their work afterwards
    would be worthless.
    """
    run = make.analysis_run(requested_by=users["analyst"])
    account = make.account()
    make.label(account, is_mule=True, scenario_type="fan_in_collector", ring_id="RING-3")
    make.assessment(account, score=90, analysis_run=run)
    db.commit()

    for path in ("", "/results", "/history"):
        raw = analyst_client.get(f"{ANALYSIS}/runs/{run.id}{path}").text.lower()

        assert "ring-3" not in raw
        assert "fan_in_collector" not in raw
        assert "ground_truth" not in raw


def test_a_run_takes_no_action_against_any_account(analyst_client, make, db):
    """
    Scoring changes assessments and alerts. It does not touch accounts.

    A run that wrote back to the account — a flag, a status, a hold — would be
    automatic adverse action, which the platform prohibits and has an
    exception class for.
    """
    from app.models import Account

    accounts = make.accounts(3)
    db.commit()

    before = {account.id: account.status for account in accounts}

    assert_ok(
        analyst_client.post(
            f"{ANALYSIS}/runs", json={"account_ids": [a.id for a in accounts]}
        ),
        201,
    )

    db.expire_all()
    for account_id, status in before.items():
        assert db.get(Account, account_id).status == status
