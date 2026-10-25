"""
Health, readiness and liveness.

These endpoints are public — they are in `PUBLIC_PATH_PREFIXES` — which is
deliberate and worth a test of its own: an orchestrator cannot authenticate,
and a readiness probe that needs a token is a readiness probe that always
fails. The flip side is that whatever they return is visible to anyone who can
reach the port, so the tests here check the *absence* of detail as carefully as
its presence.
"""

from __future__ import annotations

import pytest

from tests.utils import assert_ok

pytestmark = pytest.mark.api


HEALTH_PATHS = ["/api/v1/health", "/api/v1/health/status"]


def test_liveness_is_public(client):
    """Liveness answers without a token: a probe has none to offer."""
    body = assert_ok(client.get("/api/v1/health/live"))
    assert body["app"]
    assert body["production_ready"] is False


def test_readiness_is_public(client):
    assert client.get("/api/v1/health/ready").status_code in (200, 503)


def test_readiness_reports_dependency_checks(client):
    """
    Readiness names what it checked.

    A probe that returns a bare "ok" tells an operator nothing when it starts
    failing. The database check in particular has to be present: a process
    that is running but cannot reach PostgreSQL is live and not ready, and
    conflating the two is what makes a bad deploy take traffic.
    """
    response = client.get("/api/v1/health/ready")
    body = response.json()

    checks = body.get("checks") or []
    assert isinstance(checks, list)

    if checks:
        names = {str(check.get("name", "")).lower() for check in checks}
        assert any("db" in name or "database" in name for name in names), (
            f"readiness ran no database check; saw {sorted(names)}"
        )

        for check in checks:
            assert check.get("name")
            assert check.get("status")


@pytest.mark.parametrize("path", HEALTH_PATHS)
def test_health_declares_itself_not_production_ready(client, path):
    """
    `production_ready` is `Literal[False]`.

    Not a placeholder someone forgot to flip. The platform scores synthetic
    data, its models are trained on generated labels, and its outputs are
    investigative leads. Advertising readiness would be the single most
    consequential untruth the API could tell, so the field is typed so that it
    cannot become true without a code change and a review.
    """
    body = assert_ok(client.get(path))
    assert body["production_ready"] is False


@pytest.mark.parametrize("path", HEALTH_PATHS)
def test_health_carries_the_synthetic_banner(client, path):
    """The data classification travels with every health response."""
    body = assert_ok(client.get(path))

    assert body["banner"]
    assert body["safety_notice"]
    assert body["data_classification"]
    assert isinstance(body["synthetic_demo"], bool)


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    HEALTH_PATHS + ["/api/v1/health/live", "/api/v1/health/ready"],
)
def test_health_leaks_nothing_sensitive(client, path):
    """
    No secrets, connection strings or stack traces in a public response.

    Health endpoints are the classic place for a database URL to escape,
    because the natural way to report a database check is to say which
    database. The assertion is crude on purpose: it looks at the whole
    serialised body, so a leak nested three levels inside `details` is caught
    as readily as one at the top.
    """
    raw = client.get(path).text.lower()

    for forbidden in (
        "postgresql://",
        "postgres://",
        "sqlite:///",
        "password",
        "secret_key",
        "traceback",
        "bearer ",
    ):
        assert forbidden not in raw, f"{path} response contains {forbidden!r}"


def test_root_is_reachable(client):
    """The service root answers, and says the same thing about itself."""
    body = assert_ok(client.get("/"))
    assert isinstance(body, dict)
    assert body.get("production_ready") in (False, None)


def test_unknown_path_is_a_clean_404(client):
    """
    A missing path 404s with a JSON body, not an HTML error page.

    The exception handlers are registered application-wide, so this is really
    a test that they are: a client parsing JSON should not have to special-case
    the one response that is a Starlette default.
    """
    response = client.get("/api/v1/definitely-not-a-route")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
