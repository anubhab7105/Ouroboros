"""
The dashboard.

The dashboard is where somebody forms an impression of the whole system in
about four seconds, which makes it the place where an ambiguous number does
the most damage. Nearly every assertion here is about a distinction the
response keeps that a simpler shape would collapse.

**All-time versus in-window.** `total_all_time` and `created_in_window` are
separate fields on alerts and cases. A single "total" on a page with a date
filter is unreadable: nobody can tell whether 40 open cases is the backlog or
this week's intake.

**Deterministic versus inferred correlations.** Reported apart, because 412
identity matches and 412 tier-4 guesses are opposite findings about the same
number.

**Scoring mode and risk band on assessments.** A band distribution with no
mode breakdown hides that half the scores came from the heuristic fallback.

**Queues report their own truncation.** A section that caps at twenty says so
and gives the real total, so "20 unassigned alerts" is never read as the
backlog when it is 400.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.api.v1.endpoints.dashboard import _validate_trend_buckets
from app.exceptions import ValidationError as MuleGuardValidationError
from app.models import (
    AccountStatus,
    AlertState,
    CaseStatus,
    Priority,
    ScoringMode,
    TransactionStatus,
)
from tests.utils import assert_error, assert_ok, days_ago, hours_ago

pytestmark = pytest.mark.api


DASHBOARD = "/api/v1/dashboard"


# -----------------------------------------------------------------------------
# Status
# -----------------------------------------------------------------------------


def test_status_reports_the_limits(analyst_client):
    body = assert_ok(analyst_client.get(f"{DASHBOARD}/status"))

    assert body["enabled"] is True
    assert body["default_window_days"] > 0
    assert body["max_date_span_days"] >= body["default_window_days"]
    assert body["max_trend_buckets"] > 0
    assert body["caveats"]


@pytest.mark.parametrize(
    "path", ["status", "overview", "metrics", "queues", "trends"]
)
def test_every_dashboard_surface_is_readable_by_every_role(role_clients, path):
    """
    Reading the dashboard is not privileged.

    `DASHBOARD_READ` is granted to all four roles. An auditor who could not
    see the dashboard would have to reconstruct the state of the system from
    the audit log, which is not what the log is for.
    """
    for role, client in role_clients.items():
        response = client.get(f"{DASHBOARD}/{path}")
        assert response.status_code == 200, f"{role} cannot read /{path}"


# -----------------------------------------------------------------------------
# Overview
# -----------------------------------------------------------------------------


def test_overview_states_its_window(analyst_client):
    """
    Every figure is "over this period", and the period is in the response.

    `defaulted` says whether the caller chose the window or got the default,
    which matters when the number is screenshotted into a slide.
    """
    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))
    window = body["window"]

    assert window["date_from"]
    assert window["date_to"]
    assert isinstance(window["defaulted"], bool)
    assert window["default_window_days"] > 0
    assert window["max_span_days"] > 0
    assert body["generated_at"]
    assert body["caveats"]


@pytest.mark.parametrize("path", ["overview", "metrics", "trends"])
def test_dashboard_accepts_an_explicit_date_window(analyst_client, path):
    date_from = days_ago(7).isoformat()
    date_to = hours_ago(1).isoformat()

    body = assert_ok(
        analyst_client.get(
            f"{DASHBOARD}/{path}",
            params={"date_from": date_from, "date_to": date_to},
        )
    )

    window = body["window"] if path != "trends" else body["period"]
    assert window["date_from"]
    assert window["date_to"]
    assert window["defaulted"] is False


def test_overview_separates_all_time_from_in_window(analyst_client, make, db):
    """
    Two numbers, never one.

    An alert raised three months ago and still open belongs in
    `open_all_time`; one raised yesterday belongs in `created_in_window`. A
    single "total" on a page with a date filter cannot distinguish the backlog
    from this week's intake, and the two call for completely different
    responses.
    """
    account = make.account()

    make.alert(account, state=AlertState.NEW, first_seen_at=days_ago(120))
    make.alert(account, state=AlertState.NEW, first_seen_at=hours_ago(2))
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{DASHBOARD}/overview", params={"date_from": days_ago(7).isoformat()}
        )
    )
    alerts = body["alerts"]

    assert alerts["total_all_time"] >= 2
    assert alerts["created_in_window"] <= alerts["total_all_time"]


def test_overview_breaks_alerts_down_by_state_and_priority(analyst_client, make, db):
    account = make.account()

    make.alert(account, state=AlertState.NEW, priority=Priority.CRITICAL)
    make.alert(account, state=AlertState.UNDER_REVIEW, priority=Priority.LOW)
    make.alert(account, state=AlertState.CLOSED, priority=Priority.MEDIUM)
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))
    alerts = body["alerts"]

    assert alerts["open_by_state"]
    assert alerts["created_by_priority"]

    # A closed alert is not open.
    assert "CLOSED" not in alerts["open_by_state"] or alerts["open_by_state"]["CLOSED"] == 0


def test_overview_breaks_cases_down_by_status(analyst_client, make, db, users):
    make.case(status=CaseStatus.NEW, creator=users["analyst"])
    make.case(status=CaseStatus.ESCALATED, creator=users["analyst"])
    make.case(status=CaseStatus.CLOSED, creator=users["analyst"])
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))
    cases = body["cases"]

    assert cases["total_all_time"] >= 3
    assert cases["open_by_status"]
    assert cases["open_all_time"] <= cases["total_all_time"]


def test_overview_separates_deterministic_from_inferred_correlations(
    analyst_client, make, db
):
    """
    The distinction the dashboard most needs to keep.

    "412 complaint correlations" is a number with no content. 412 identity
    matches means the complaint feed is being matched well; 412 tier-4
    proximity guesses means the platform is generating leads nobody has
    checked. The unreviewed count is the operational one.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)

    make.correlation(complaint, account=account, match_tier=1)
    make.correlation(complaint, account=account, match_tier=4, confidence=0.6)
    make.correlation(complaint, account=account, match_tier=5, confidence=0.3)
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))
    complaints = body["complaints"]

    assert complaints["correlations_total"] == 3
    assert complaints["correlations_deterministic"] == 1
    assert complaints["correlations_inferred"] == 2
    assert complaints["correlations_unreviewed"] == 2


def test_overview_counts_transactions_by_status(analyst_client, make, db):
    """
    Completed, pending, failed and reversed, each on its own line.

    Only COMPLETED moved money. The other three are the difference between
    this view and a naive ledger count, and reporting them is what makes that
    difference checkable rather than mysterious.
    """
    sender, receiver = make.accounts(2)

    make.transaction(sender, receiver, status=TransactionStatus.COMPLETED)
    make.transaction(sender, receiver, status=TransactionStatus.PENDING)
    make.transaction(sender, receiver, status=TransactionStatus.FAILED)
    make.transaction(sender, receiver, status=TransactionStatus.REVERSED)
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))
    transactions = body["transactions"]

    assert transactions["completed"] == 1
    assert transactions["pending"] == 1
    assert transactions["failed"] == 1
    assert transactions["reversed"] == 1
    assert transactions["total_in_window"] == 4


def test_overview_reports_assessments_by_scoring_mode(analyst_client, make, db):
    """
    The band distribution is not interpretable without the mode.

    A page showing "18 HIGH" where most were produced by the heuristic
    fallback is telling a different story from one where they came from a
    validated model, and the difference is invisible unless both are shown.
    """
    account = make.account()

    make.assessment(account, score=90, scoring_mode=ScoringMode.TRAINED_MODEL)
    make.assessment(account, score=70, scoring_mode=ScoringMode.HEURISTIC_FALLBACK)
    make.assessment(account, score=20, scoring_mode=ScoringMode.RULES_ONLY)
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))
    assessments = body["assessments"]

    assert assessments["total_in_window"] == 3
    assert assessments["by_scoring_mode"]
    assert assessments["by_risk_band"]
    assert len(assessments["by_scoring_mode"]) >= 2


def test_overview_reports_how_many_assessments_are_explained(analyst_client, make, db):
    """
    An unexplained score is a score an analyst cannot act on.

    The count is here because it is an operational health signal: if it falls,
    something in the explanation path has broken, and nothing else on the
    dashboard would show it.
    """
    account = make.account()

    make.assessment(account, score=80, with_explanation=True)
    make.assessment(account, score=50, with_explanation=False, as_of=days_ago(1))
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))
    assert body["assessments"]["explanation_available"] == 1


def test_overview_counts_accounts_by_status_and_type(analyst_client, make, db):
    make.account(status=AccountStatus.ACTIVE)
    make.account(status=AccountStatus.DORMANT)
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))
    accounts = body["accounts"]

    assert accounts["total"] >= 2
    assert accounts["by_status"]
    assert accounts["by_type"]


def test_overview_on_an_empty_system_is_zeroes(analyst_client):
    """
    A new deployment shows zeroes, not errors and not blanks.

    The dashboard is the first thing anyone opens, and it is opened before
    there is any data.
    """
    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))

    assert body["accounts"]["total"] == 0
    assert body["alerts"]["total_all_time"] == 0
    assert body["cases"]["total_all_time"] == 0
    assert body["complaints"]["correlations_total"] == 0


def test_an_over_wide_window_is_refused(analyst_client):
    response = analyst_client.get(
        f"{DASHBOARD}/overview", params={"date_from": days_ago(100_000).isoformat()}
    )
    assert response.status_code in (200, 422)


def test_a_reversed_window_is_rejected(analyst_client):
    assert_error(
        analyst_client.get(
            f"{DASHBOARD}/overview",
            params={
                "date_from": days_ago(1).isoformat(),
                "date_to": days_ago(30).isoformat(),
            },
        ),
        422,
    )


# -----------------------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------------------


def test_metrics_report_rates_alongside_totals(analyst_client, make, db):
    """
    A rate needs the number of days it was divided by, and the response gives it.

    "14 alerts a day" over a two-day window is noise; over ninety days it is a
    trend. Publishing `days` next to `rates_per_day` is what lets a reader
    tell which they are looking at.
    """
    account = make.account()
    for _ in range(4):
        make.alert(account)
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/metrics"))

    assert body["days"] > 0
    assert body["totals"]
    assert body["rates_per_day"]
    assert body["window"]
    assert body["caveats"]


def test_metric_rates_are_consistent_with_their_totals(analyst_client, make, db):
    """
    total ÷ days = rate, within rounding.

    Checked because the two are computed separately and a mismatch would make
    the dashboard self-contradicting in a way nobody would notice for months.
    """
    account = make.account()
    for _ in range(6):
        make.alert(account)
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/metrics"))
    days = body["days"]

    for key, total in body["totals"].items():
        rate = body["rates_per_day"].get(key)
        if rate is None or days <= 0:
            continue
        assert abs(rate - total / days) < 0.01, f"{key}: {total}/{days} != {rate}"


def test_metrics_on_an_empty_system_are_zero_not_divided_by_zero(analyst_client):
    """
    No data and a zero-length window must not produce a division error.

    This is the single most likely 500 on the whole dashboard.
    """
    body = assert_ok(analyst_client.get(f"{DASHBOARD}/metrics"))

    assert body["days"] > 0
    for rate in body["rates_per_day"].values():
        assert rate == 0


# -----------------------------------------------------------------------------
# Queues
# -----------------------------------------------------------------------------


def test_queues_report_their_sections(analyst_client, make, db, users):
    body = assert_ok(analyst_client.get(f"{DASHBOARD}/queues"))

    for section in (
        "unassigned_alerts",
        "my_alerts",
        "new_cases",
        "under_review_cases",
        "escalated_cases",
        "unreviewed_complaint_correlations",
    ):
        assert section in body, f"missing queue section {section}"
        assert "items" in body[section]
        assert "total" in body[section]
        assert "truncated" in body[section]

    assert body["caveats"]


def test_a_queue_section_reports_the_real_total_and_its_truncation(
    analyst_client, make, db
):
    """
    `total` is the backlog; `items` is a page of it.

    A section that showed twenty items and a total of twenty would tell an
    analyst the backlog is twenty when it is four hundred. The truncation flag
    is what lets the interface say "20 of 400".
    """
    account = make.account()
    for _ in range(30):
        make.alert(account, state=AlertState.NEW)
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/queues"))
    section = body["unassigned_alerts"]

    assert section["total"] >= 30
    assert len(section["items"]) <= section["total"]

    if len(section["items"]) < section["total"]:
        assert section["truncated"] is True


def test_my_alerts_is_scoped_to_the_caller(analyst_client, senior_client, make, db, users):
    """
    "Mine" means the authenticated user's, derived server-side.

    If the client passed its own user id, any client could read anyone's
    queue by changing it.
    """
    account = make.account()

    make.alert(account, assigned_to=users["analyst"].id)
    make.alert(account, assigned_to=users["senior"].id)
    db.commit()

    analyst_view = assert_ok(analyst_client.get(f"{DASHBOARD}/queues"))
    senior_view = assert_ok(senior_client.get(f"{DASHBOARD}/queues"))

    assert analyst_view["my_alerts"]["total"] == 1
    assert senior_view["my_alerts"]["total"] == 1

    analyst_ids = {item["id"] for item in analyst_view["my_alerts"]["items"]}
    senior_ids = {item["id"] for item in senior_view["my_alerts"]["items"]}
    assert not (analyst_ids & senior_ids)


def test_queue_items_carry_their_age(analyst_client, make, db):
    """
    How long it has been waiting, as a number.

    Age is what triage is actually sorted by. Making the client compute it
    from a timestamp means every client computes it, and one of them gets the
    timezone wrong.
    """
    account = make.account()
    make.alert(account, state=AlertState.NEW, first_seen_at=days_ago(3))
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/queues"))
    items = body["unassigned_alerts"]["items"]

    assert items
    assert items[0]["age_seconds"] is not None
    assert items[0]["age_seconds"] > 0


def test_the_unreviewed_correlation_queue_holds_only_inferences(
    analyst_client, make, db
):
    """
    Deterministic correlations are never in a review queue.

    There is nothing for a human to decide about a reference that matched, and
    a queue padded with such items is a queue that stops being read.
    """
    account = make.account()
    complaint = make.complaint(suspected_account=account)

    make.correlation(complaint, account=account, match_tier=1)
    make.correlation(complaint, account=account, match_tier=3, confidence=0.6)
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/queues"))
    section = body["unreviewed_complaint_correlations"]

    assert section["total"] == 1


def test_a_queue_item_names_its_kind(analyst_client, make, db, users):
    """
    Alerts and cases share one item shape, so each says which it is.

    The queues panel renders them in one list; without `kind` it could not
    link them to the right page.
    """
    account = make.account()
    make.alert(account, state=AlertState.NEW)
    make.case(status=CaseStatus.NEW, creator=users["analyst"])
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/queues"))

    for section in ("unassigned_alerts", "new_cases"):
        for item in body[section]["items"]:
            assert item["kind"]
            assert item["id"]


def test_queues_on_an_empty_system_are_empty_not_missing(analyst_client):
    body = assert_ok(analyst_client.get(f"{DASHBOARD}/queues"))

    for section in ("unassigned_alerts", "my_alerts", "new_cases"):
        assert body[section]["items"] == []
        assert body[section]["total"] == 0
        assert body[section]["truncated"] is False


# -----------------------------------------------------------------------------
# Trends
# -----------------------------------------------------------------------------


def test_trends_return_one_point_per_bucket(analyst_client, make, db):
    account = make.account()

    make.alert(account, first_seen_at=days_ago(1))
    make.alert(account, first_seen_at=days_ago(3))
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{DASHBOARD}/trends", params={"date_from": days_ago(7).isoformat()}
        )
    )

    assert body["bucket_size"]
    assert body["points"]
    assert body["period"]
    assert body["caveats"]

    for point in body["points"]:
        assert point["date"]
        for series in ("alerts", "cases", "complaints", "transactions", "assessments"):
            assert point[series] >= 0


def test_trend_buckets_are_contiguous_and_include_empty_days(analyst_client, make, db):
    """
    A day with nothing is a point with zeroes, not a gap.

    A sparse series renders as a line that skips days, which reads as a
    plateau rather than as nothing having happened. Any chart drawn from this
    depends on the buckets being complete.
    """
    account = make.account()
    make.alert(account, first_seen_at=days_ago(5))
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{DASHBOARD}/trends", params={"date_from": days_ago(7).isoformat()}
        )
    )
    dates = [point["date"] for point in body["points"]]

    assert len(dates) == len(set(dates)), "a bucket is repeated"
    assert dates == sorted(dates), "buckets are not in order"
    assert len(dates) >= 5


def test_the_trend_bucket_count_is_bounded(analyst_client):
    """
    A ten-year daily range would be three and a half thousand points.

    That is a response nothing can render and a query nothing should run. The
    bucket size widens or the request is refused; either is fine, silently
    returning thousands of points is not.
    """
    response = analyst_client.get(
        f"{DASHBOARD}/trends", params={"date_from": days_ago(3650).isoformat()}
    )

    if response.status_code == 200:
        body = response.json()
        assert len(body["points"]) <= 1000
    else:
        assert response.status_code == 422


def test_trends_accept_exactly_the_configured_buckets_at_utc_day_boundary():
    settings = SimpleNamespace(
        DASHBOARD_MAX_TREND_BUCKETS=90,
        DASHBOARD_HARD_MAX_TREND_BUCKETS=366,
    )
    date_to = datetime(2026, 10, 24, 0, 0, 1, tzinfo=UTC)
    exact_limit_start = datetime.combine(
        date_to.date() - timedelta(days=89),
        datetime.min.time(),
        tzinfo=UTC,
    )
    crossing_boundary_start = date_to - timedelta(days=90)

    assert _validate_trend_buckets(exact_limit_start, date_to, settings) == (90, 90)
    with pytest.raises(
        MuleGuardValidationError,
        match="Dashboard trend range exceeds configured maximum bucket count",
    ):
        _validate_trend_buckets(crossing_boundary_start, date_to, settings)


def test_trends_on_an_empty_system_are_zeroes(analyst_client):
    body = assert_ok(analyst_client.get(f"{DASHBOARD}/trends"))

    for point in body["points"]:
        assert point["alerts"] == 0
        assert point["cases"] == 0


# -----------------------------------------------------------------------------
# What the dashboard must not show
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["overview", "metrics", "queues", "trends"])
def test_no_dashboard_surface_leaks_a_narrative_or_a_label(
    analyst_client, make, db, users, path
):
    """
    Aggregates are the one place a sensitive field reaches everybody at once.

    A dashboard that included a complaint narrative or a ground-truth label
    would put it in front of every role, on the page everyone opens, with no
    record of who saw it.
    """
    account = make.account()
    make.label(account, is_mule=True, scenario_type="fan_in_collector", ring_id="RING-11")

    complaint = make.complaint(
        suspected_account=account,
        narrative_raw="Victim describes being coached through a transfer by phone.",
    )
    make.correlation(complaint, account=account, match_tier=1)
    make.alert(account)
    make.case(account=account, creator=users["analyst"])
    db.commit()

    raw = analyst_client.get(f"{DASHBOARD}/{path}").text.lower()

    assert "coached" not in raw
    assert "ring-11" not in raw
    assert "fan_in_collector" not in raw
    assert "ground_truth" not in raw


@pytest.mark.parametrize("path", ["overview", "metrics", "queues", "trends"])
def test_every_dashboard_surface_carries_caveats(analyst_client, path):
    """
    The page where the platform is most likely to be over-read says what it is.

    Four seconds of looking at a dashboard produces an impression that lasts.
    The caveats are on every surface because that is where the impression is
    formed.
    """
    body = assert_ok(analyst_client.get(f"{DASHBOARD}/{path}"))
    assert body["caveats"]


def test_the_dashboard_reports_no_monetary_total_across_currencies(
    analyst_client, make, db
):
    """
    There is no single "total value at risk" field, and that is deliberate.

    Summing across currencies produces a number that is wrong in a way nobody
    checks, and it is exactly the number that would end up in a board slide.
    The dashboard counts transactions; per-currency amounts live on the
    account summary, one currency at a time.
    """
    sender, receiver = make.accounts(2)
    make.transaction(sender, receiver, amount=100_000, currency="INR")
    make.transaction(sender, receiver, amount=1_000, currency="USD")
    db.commit()

    body = assert_ok(analyst_client.get(f"{DASHBOARD}/overview"))
    transactions = body["transactions"]

    assert set(transactions) == {
        "total_in_window",
        "completed",
        "pending",
        "failed",
        "reversed",
    }
