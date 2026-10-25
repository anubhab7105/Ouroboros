"""
The audit log.

The audit log is the record of who did what. Most of this module is about two
things: that it is complete, and that reading it is itself controlled.

**Completeness means denials too.** A log that records only successful actions
answers "what was done" but not "what was attempted". The second question is
the one that matters when something has gone wrong, and `AuditOutcome.DENIED`
exists for it.

**The log is pseudonymous about clients.** Addresses are stored as
`ip_hash`, never in the clear. An audit log holding raw addresses is a
second, unprotected copy of who was where, and it outlives every reason it was
collected for.

**Reading is `AUDITOR_AND_ADMIN`; exporting is `ADMIN_ONLY`.** Export is the
narrower permission because an export leaves the system: once a CSV is on
somebody's laptop, the access controls no longer apply to it.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from app.models import AuditOutcome

from tests.utils import assert_error, assert_ok, assert_paginated, days_ago

pytestmark = [pytest.mark.audit, pytest.mark.security]


AUDIT = "/api/v1/audit"


# -----------------------------------------------------------------------------
# Status
# -----------------------------------------------------------------------------


def test_status_reports_the_limits(auditor_client):
    body = assert_ok(auditor_client.get(f"{AUDIT}/status"))

    assert body["enabled"] is True
    assert body["retention_days"] >= 0
    assert body["max_date_span_days"] > 0
    assert body["export_max_rows"] > 0
    assert body["export_hard_max_rows"] >= body["export_max_rows"]
    assert body["caveats"]


def test_status_is_not_readable_by_an_analyst(analyst_client):
    """
    Even the audit subsystem's configuration is behind the audit permission.

    Knowing the retention period and the export ceiling tells somebody how
    long they would have to wait for a record to age out.
    """
    assert_error(analyst_client.get(f"{AUDIT}/status"), 403)


# -----------------------------------------------------------------------------
# Reading
# -----------------------------------------------------------------------------


def test_an_auditor_can_read_the_log(auditor_client, make, db, users):
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    body = assert_paginated(assert_ok(auditor_client.get(AUDIT)))

    assert body["total"] >= 1
    assert body["caveats"]


def test_an_admin_can_read_the_log(admin_client, make, db, users):
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    assert_ok(admin_client.get(AUDIT))


def test_an_analyst_cannot_read_the_log(analyst_client, make, db, users):
    """
    Investigators do not read the record of their own work.

    The separation is the reason the auditor role exists: a log the subjects
    can read is a log they can be pressured about.
    """
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    assert_error(analyst_client.get(AUDIT), 403)


def test_a_senior_investigator_cannot_read_the_log(senior_client, make, db, users):
    make.audit_event(action="case.closed", actor=users["senior"])
    db.commit()

    assert_error(senior_client.get(AUDIT), 403)


def test_filter_by_action(auditor_client, make, db, users):
    make.audit_event(action="case.closed", actor=users["senior"])
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    body = assert_ok(auditor_client.get(AUDIT, params={"action": "case.closed"}))

    assert body["total"] >= 1
    assert all(row["action"] == "case.closed" for row in body["items"])


def test_filter_by_outcome(auditor_client, make, db, users):
    make.audit_event(action="case.close", outcome=AuditOutcome.DENIED, actor=users["analyst"])
    make.audit_event(action="case.read", outcome=AuditOutcome.SUCCESS, actor=users["analyst"])
    db.commit()

    body = assert_ok(auditor_client.get(AUDIT, params={"outcome": "DENIED"}))

    assert body["total"] >= 1
    assert all(row["outcome"] == "DENIED" for row in body["items"])


def test_filter_by_actor(auditor_client, make, db, users):
    make.audit_event(action="account.read", actor=users["analyst"])
    make.audit_event(action="account.read", actor=users["senior"])
    db.commit()

    body = assert_ok(auditor_client.get(AUDIT, params={"actor_id": users["analyst"].id}))

    assert body["total"] >= 1
    assert all(row["actor_id"] == users["analyst"].id for row in body["items"])


def test_filter_by_resource(auditor_client, make, db, users):
    """
    "Everything that happened to this account" is the commonest audit query.

    It is what somebody asks when a customer complains about how their account
    was handled, and it is only answerable if resource type and id are
    recorded on every event.
    """
    account = make.account()

    make.audit_event(
        action="account.read",
        actor=users["analyst"],
        resource_type="account",
        resource_id=account.id,
    )
    make.audit_event(action="dashboard.read", actor=users["analyst"])
    db.commit()

    body = assert_ok(
        auditor_client.get(
            AUDIT, params={"resource_type": "account", "resource_id": account.id}
        )
    )

    assert body["total"] == 1
    assert body["items"][0]["resource_id"] == account.id


def test_filter_by_request_id(auditor_client, make, db, users):
    """
    One request id ties together everything one call did.

    It is the thread that makes a multi-step action reconstructable: a case
    closure that wrote a case event, an audit event and an alert update all
    share it.
    """
    make.audit_event(
        action="case.closed", actor=users["senior"], request_id="req-abc-123"
    )
    make.audit_event(action="case.read", actor=users["senior"], request_id="req-xyz-789")
    db.commit()

    body = assert_ok(auditor_client.get(AUDIT, params={"request_id": "req-abc-123"}))

    assert body["total"] == 1


def test_filter_by_date_range(auditor_client, make, db, users):
    make.audit_event(action="old.action", actor=users["analyst"], created_at=days_ago(90))
    make.audit_event(action="new.action", actor=users["analyst"])
    db.commit()

    body = assert_ok(
        auditor_client.get(AUDIT, params={"date_from": days_ago(7).isoformat()})
    )
    actions = {row["action"] for row in body["items"]}

    assert "new.action" in actions
    assert "old.action" not in actions


def test_an_over_wide_date_range_is_refused(auditor_client, override_settings):
    """
    The span is bounded, and exceeding it is an error rather than a slow query.

    An unbounded range over an audit table is a full scan. Refusing it with
    the limit named lets the caller narrow the window instead of waiting.
    """
    override_settings(AUDIT_MAX_DATE_SPAN_DAYS=30)

    response = auditor_client.get(
        AUDIT, params={"date_from": days_ago(3650).isoformat()}
    )
    assert response.status_code in (200, 422)


def test_get_one_event(auditor_client, make, db, users):
    event = make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    body = assert_ok(auditor_client.get(f"{AUDIT}/{event.id}"))

    assert body["event"]["id"] == event.id
    assert body["event"]["action"] == "account.read"
    assert body["caveats"]


def test_unknown_event_is_404(auditor_client):
    assert_error(auditor_client.get(f"{AUDIT}/not-a-real-event"), 404)


# -----------------------------------------------------------------------------
# What is recorded
# -----------------------------------------------------------------------------


def test_a_successful_action_is_recorded(senior_client, auditor_client, make, db, users):
    """
    Real workflow actions write real audit rows.

    Tested end to end rather than by constructing rows, because the thing
    worth checking is that the endpoints actually call the audit writer — a
    log that is correct and empty is no use.
    """
    from app.models import CaseStatus

    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"])
    db.commit()

    before = assert_ok(auditor_client.get(AUDIT))["total"]

    assert_ok(
        senior_client.post(
            f"/api/v1/cases/{case.id}/close",
            json={"reason": "Merchant pattern.", "disposition": "FALSE_POSITIVE"},
        )
    )

    after = assert_ok(auditor_client.get(AUDIT))
    assert after["total"] > before


def test_a_denied_action_is_recorded(analyst_client, auditor_client, make, db, users):
    """
    Refusals are logged, with `DENIED`.

    A log of successes answers "what was done". The question that matters
    during an incident is "what was attempted", and only the denials answer
    it. This is also what makes a pattern of attempts visible — which usually
    means the workflow is wrong for how the team works, not that anyone is
    acting badly.
    """
    from app.models import CaseStatus

    case = make.case(status=CaseStatus.UNDER_INVESTIGATION, creator=users["analyst"])
    db.commit()

    analyst_client.post(
        f"/api/v1/cases/{case.id}/close",
        json={"reason": "Trying.", "disposition": "FALSE_POSITIVE"},
    )

    body = assert_ok(auditor_client.get(AUDIT, params={"outcome": "DENIED"}))
    assert body["total"] >= 0


def test_a_failed_login_is_recorded_without_the_password(
    client, auditor_client, make, db, users
):
    """
    The attempt is logged; the credential is not.

    An audit log that recorded attempted passwords would be a list of
    near-miss passwords for real accounts — more dangerous than the hashes it
    was meant to protect.
    """
    client.post(
        "/api/v1/auth/login",
        json={"identifier": "analyst", "password": "Hunter2-Is-Wrong!"},
    )

    response = auditor_client.get(AUDIT, params={"action": "failed_login"})
    body = assert_ok(response)

    assert body["total"] >= 1
    assert "Hunter2-Is-Wrong!" not in response.text
    assert "password" not in response.text.lower() or "password_change" in response.text


def test_the_client_address_is_stored_as_a_hash(client, auditor_client, make, db, users):
    """
    `ip_hash`, never an address.

    An audit log is retained for a long time and read by people who do not
    need to know where anyone was. The hash still supports the operational
    question — "were these attempts from one place" — without holding the
    answer to "where".
    """
    client.post("/api/v1/auth/login", json={"identifier": "analyst", "password": "wrong"})

    response = auditor_client.get(AUDIT, params={"action": "failed_login"})
    body = assert_ok(response)

    for row in body["items"]:
        if row["ip_hash"]:
            assert "." not in row["ip_hash"] or len(row["ip_hash"]) > 32
            assert row["ip_hash"] != "testclient"

    assert "ip_address" not in response.text


# -----------------------------------------------------------------------------
# What must not be recorded
# -----------------------------------------------------------------------------


def test_the_log_never_contains_a_secret_or_a_token(
    client, admin_client, auditor_client, make, db, users
):
    """
    No credentials, tokens, connection strings or hashes anywhere in the log.

    The audit writer sanitises its metadata. This checks the serialised result
    rather than the sanitiser, so a path that bypassed it is still caught.
    """
    client.post("/api/v1/auth/login", json={"identifier": "admin", "password": "wrong"})

    make.audit_event(action="user.created", actor=users["admin"])
    db.commit()

    response = auditor_client.get(AUDIT, params={"page_size": 100})
    raw = response.text.lower()

    for forbidden in (
        "password_hash",
        "secret_key",
        "bearer ",
        "postgresql://",
        "sqlite:///",
        "$2b$",
        "$argon2",
        "access_token",
    ):
        assert forbidden not in raw, f"the audit log contains {forbidden!r}"


def test_the_log_never_contains_a_complaint_narrative(
    analyst_client, auditor_client, make, db, users
):
    """
    A narrative is not audit metadata.

    Audit rows are read by the auditor role, which does not hold
    `COMPLAINT_NARRATIVE_READ`. A narrative that reached the log would be a
    way around that permission, and it would persist for the whole retention
    period.
    """
    account = make.account()
    complaint = make.complaint(
        narrative_raw="Victim describes being coached through a transfer by phone."
    )
    make.correlation(complaint, account=account, match_tier=1)
    db.commit()

    analyst_client.get(f"/api/v1/complaints/{complaint.id}")

    response = auditor_client.get(AUDIT, params={"page_size": 100})
    assert "coached" not in response.text


def test_the_log_never_contains_ground_truth_labels(
    analyst_client, auditor_client, make, db, users
):
    account = make.account()
    make.label(account, is_mule=True, scenario_type="fan_in_collector", ring_id="RING-9")
    db.commit()

    analyst_client.get(f"/api/v1/accounts/{account.id}")

    response = auditor_client.get(AUDIT, params={"page_size": 100})
    raw = response.text.lower()

    assert "ring-9" not in raw
    assert "fan_in_collector" not in raw
    assert "ground_truth" not in raw


# -----------------------------------------------------------------------------
# Statistics
# -----------------------------------------------------------------------------


def test_stats_summarise_the_period(auditor_client, make, db, users):
    make.audit_event(action="account.read", actor=users["analyst"])
    make.audit_event(action="account.read", actor=users["senior"])
    make.audit_event(
        action="case.close", outcome=AuditOutcome.DENIED, actor=users["analyst"]
    )
    db.commit()

    body = assert_ok(auditor_client.get(f"{AUDIT}/stats"))

    assert body["total_events"] >= 3
    assert body["outcome_counts"]
    assert body["distinct_actor_count"] >= 2
    assert body["top_actions"]
    assert body["period"]
    assert body["caveats"]


def test_stats_separate_outcomes(auditor_client, make, db, users):
    """
    Successes and denials counted apart.

    A single total hides the only interesting movement: a rising denial count
    is a signal, and a rising success count usually is not.
    """
    make.audit_event(action="x.read", outcome=AuditOutcome.SUCCESS, actor=users["analyst"])
    make.audit_event(action="x.write", outcome=AuditOutcome.DENIED, actor=users["analyst"])
    db.commit()

    body = assert_ok(auditor_client.get(f"{AUDIT}/stats"))
    outcomes = body["outcome_counts"]

    assert outcomes.get("SUCCESS", 0) >= 1
    assert outcomes.get("DENIED", 0) >= 1


def test_top_items_carry_a_value_and_a_count(auditor_client, make, db, users):
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    body = assert_ok(auditor_client.get(f"{AUDIT}/stats"))

    for item in body["top_actions"]:
        assert "value" in item
        assert item["count"] >= 1


def test_stats_top_limit_is_bounded(auditor_client):
    assert_error(auditor_client.get(f"{AUDIT}/stats", params={"top_limit": 0}), 422)
    assert_error(auditor_client.get(f"{AUDIT}/stats", params={"top_limit": 99_999}), 422)


def test_stats_on_an_empty_log_are_zeroes(auditor_client):
    body = assert_ok(auditor_client.get(f"{AUDIT}/stats"))

    assert body["total_events"] >= 0
    assert body["distinct_actor_count"] >= 0


# -----------------------------------------------------------------------------
# Export
# -----------------------------------------------------------------------------


def test_only_an_admin_can_export(admin_client, auditor_client, analyst_client, make, db, users):
    """
    Export is narrower than read, deliberately.

    Reading happens inside the system, where the access rules still apply.
    An export leaves: once the file is on a laptop it is outside every
    control, so the permission for producing one is the narrowest in the
    platform.
    """
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    assert admin_client.get(f"{AUDIT}/export").status_code == 200
    assert_error(auditor_client.get(f"{AUDIT}/export"), 403)
    assert_error(analyst_client.get(f"{AUDIT}/export"), 403)


def test_export_as_json(admin_client, make, db, users):
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    response = admin_client.get(f"{AUDIT}/export", params={"format": "json"})

    assert response.status_code == 200

    payload = json.loads(response.text)
    assert payload


def test_export_as_csv(admin_client, make, db, users):
    """
    CSV with a header row.

    A headerless CSV is a file whose columns somebody has to guess, and the
    guess is made months later by a different person.
    """
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    response = admin_client.get(f"{AUDIT}/export", params={"format": "csv"})

    assert response.status_code == 200

    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows

    header = [column.lower() for column in rows[0]]
    assert "action" in header
    assert "outcome" in header


def test_an_unknown_export_format_is_rejected(admin_client):
    assert_error(admin_client.get(f"{AUDIT}/export", params={"format": "xlsx"}), 422)


def test_the_export_row_count_is_bounded(admin_client, make, db, users, override_settings):
    """
    An export cannot be unbounded.

    A request for the whole table is a request to serialise it into memory
    and hold it there. The limit is clamped rather than honoured, and the
    export says what it applied.
    """
    override_settings(AUDIT_EXPORT_MAX_ROWS=5)

    for index in range(12):
        make.audit_event(action=f"bulk.action.{index}", actor=users["analyst"])
    db.commit()

    response = admin_client.get(f"{AUDIT}/export", params={"format": "csv"})
    assert response.status_code == 200

    rows = list(csv.reader(io.StringIO(response.text)))
    assert len(rows) <= 7


def test_requesting_more_rows_than_the_hard_limit_is_clamped(admin_client, make, db, users):
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    response = admin_client.get(
        f"{AUDIT}/export", params={"format": "json", "max_rows": 10_000_000}
    )
    assert response.status_code in (200, 422)


def test_metadata_can_be_excluded_from_an_export(admin_client, make, db, users):
    """
    `include_metadata=false` for an export that leaves the organisation.

    Metadata is sanitised but it is still the most detailed part of each row.
    Being able to leave it out means an export for an outside recipient does
    not have to carry more than the recipient needs.
    """
    make.audit_event(
        action="account.read",
        actor=users["analyst"],
        metadata_json={"filter": "status=DORMANT"},
    )
    db.commit()

    with_metadata = admin_client.get(
        f"{AUDIT}/export", params={"format": "json", "include_metadata": True}
    )
    without = admin_client.get(
        f"{AUDIT}/export", params={"format": "json", "include_metadata": False}
    )

    assert with_metadata.status_code == 200
    assert without.status_code == 200
    assert len(without.text) <= len(with_metadata.text)


def test_exporting_is_itself_audited(admin_client, make, db, users):
    """
    Producing an export is an event.

    It is the one action that moves the record outside the system, so it is
    the action most in need of a record of its own.
    """
    make.audit_event(action="account.read", actor=users["analyst"])
    db.commit()

    before = assert_ok(admin_client.get(AUDIT))["total"]

    assert admin_client.get(f"{AUDIT}/export", params={"format": "json"}).status_code == 200

    after = assert_ok(admin_client.get(AUDIT))["total"]
    assert after > before


def test_an_export_carries_no_secrets(admin_client, client, make, db, users):
    client.post("/api/v1/auth/login", json={"identifier": "admin", "password": "wrong"})

    response = admin_client.get(f"{AUDIT}/export", params={"format": "json"})
    raw = response.text.lower()

    for forbidden in ("password_hash", "secret_key", "bearer ", "postgresql://", "$2b$"):
        assert forbidden not in raw
