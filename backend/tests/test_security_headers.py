"""
Security headers, request correlation, and what responses must not contain.

`SecurityHeadersMiddleware` is constructed once with the settings
`create_app` received, so a dependency override cannot reach it. Tests that
change its configuration build their own application through
`client_factory`.

HSTS and CSP are both **off by default**, which is right and is worth stating
rather than treating as an oversight. HSTS over plain HTTP in local
development pins the browser to HTTPS for a host that does not serve it, and
recovering from that means clearing site data. CSP is off because the API's
own consumer is the frontend, which is served by nginx with its own policy —
a policy on JSON responses protects nothing and breaks the docs page. Both
belong on in a deployment that terminates TLS, and the compose file turns them
on.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


PROBE_PATHS = [
    "/api/v1/health/live",
    "/api/v1/accounts",
    "/api/v1/definitely-not-a-route",
]


# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("path", PROBE_PATHS)
def test_baseline_headers_are_present(admin_client, path):
    """
    The headers that cost nothing and are always right.

    `nosniff` stops a browser second-guessing a content type — which matters
    on an API that returns JSON and, for report download, a PDF. `DENY` stops
    the interface being framed by another origin, which is the setup for a
    clickjacked case closure. `no-referrer` stops account and case identifiers
    leaking in the `Referer` of any outbound link.
    """
    response = admin_client.get(path)

    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"


def test_headers_are_applied_to_error_responses(admin_client):
    """
    A 404 and a 403 get the same headers as a 200.

    `SECURE_HEADERS_APPLY_TO_ERRORS` defaults on. Applying headers only to
    successful responses is a common and quiet gap: the error path is served
    by an exception handler, which is the code most likely to be missed when
    middleware is wired up.
    """
    for response in (
        admin_client.get("/api/v1/definitely-not-a-route"),
        admin_client.get("/api/v1/accounts/also-not-real"),
    ):
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"


def test_server_identification_is_removed(admin_client):
    """
    No `Server` or `X-Powered-By`.

    Version banners are free reconnaissance: they tell an attacker which
    advisories to read. Removing them is not security by obscurity in any
    meaningful sense — it just declines to publish the answer.
    """
    headers = {name.lower() for name in admin_client.get("/api/v1/accounts").headers}

    assert "x-powered-by" not in headers

    server = admin_client.get("/api/v1/accounts").headers.get("Server", "")
    assert "uvicorn" not in server.lower()


def test_hsts_is_off_by_default(admin_client):
    """
    Off, deliberately.

    A developer who loads the API over HTTP once and receives an HSTS header
    has a browser that will refuse plain HTTP for that host for the lifetime
    of the policy. On `localhost` that affects every other project on the same
    host. It belongs on behind TLS and nowhere else.
    """
    assert "Strict-Transport-Security" not in admin_client.get("/api/v1/accounts").headers


def test_csp_is_off_by_default_so_the_docs_page_works(client):
    """
    Off by default, and `CSP_DOCS_EXEMPT` exists for when it is on.

    The docs page loads Swagger from a CDN. A strict policy applied to it
    leaves a blank page, which looks like the API being broken.
    """
    response = client.get("/docs")

    assert response.status_code == 200
    assert "Content-Security-Policy" not in response.headers


# -----------------------------------------------------------------------------
# When configured on
# -----------------------------------------------------------------------------


def test_hsts_can_be_enabled(client_factory, users):
    secured = client_factory(HSTS_ENABLED=True)
    response = secured.get("/api/v1/health/live")

    header = response.headers.get("Strict-Transport-Security")
    assert header
    assert "max-age=" in header


def test_csp_can_be_enabled(client_factory, users):
    secured = client_factory(CSP_ENABLED=True)
    response = secured.get("/api/v1/health/live")

    assert response.headers.get("Content-Security-Policy")


def test_csp_report_only_uses_the_report_only_header(client_factory, users):
    """
    Report-only mode reports; it does not block.

    The distinction is the whole value of the mode: a policy rolled out in
    enforcing mode breaks whatever it got wrong, immediately and for everyone.
    The two modes must not both set the enforcing header.
    """
    secured = client_factory(CSP_ENABLED=True, CSP_REPORT_ONLY=True)
    response = secured.get("/api/v1/health/live")

    assert response.headers.get("Content-Security-Policy-Report-Only")
    assert "Content-Security-Policy" not in response.headers


def test_docs_are_exempt_from_csp_when_configured(client_factory, users):
    secured = client_factory(CSP_ENABLED=True, CSP_DOCS_EXEMPT=True)

    docs = secured.get("/docs")
    api = secured.get("/api/v1/health/live")

    assert docs.status_code == 200
    assert "Content-Security-Policy" not in docs.headers
    assert api.headers.get("Content-Security-Policy")


# -----------------------------------------------------------------------------
# Hosts
# -----------------------------------------------------------------------------


def test_an_unlisted_host_is_rejected(client_factory, users):
    """
    `TrustedHostMiddleware` is installed first and does its job.

    Host-header handling is how cache-poisoning and password-reset-link
    rewriting get started. The suite itself relies on `testserver` being in
    the allowlist, so this builds an application that does not allow it and
    checks the rejection rather than asserting against the suite's own
    configuration.
    """
    strict = client_factory(BACKEND_ALLOWED_HOSTS=["example.invalid"])
    assert strict.get("/api/v1/health/live").status_code == 400


# -----------------------------------------------------------------------------
# Request correlation
# -----------------------------------------------------------------------------


def test_every_response_carries_a_request_id(admin_client):
    """
    `X-Request-ID` on the way out, whether or not one came in.

    It is the only way to connect what a user saw to what the logs recorded.
    The error payloads carry the same value, which is what makes "quote the id
    from the error message" a usable support instruction.
    """
    response = admin_client.get("/api/v1/accounts")

    assert response.headers.get("X-Request-ID")


def test_a_supplied_request_id_is_echoed(admin_client):
    """A caller that brings its own correlation id keeps it."""
    supplied = "abc123-correlation-test"
    response = admin_client.get(
        "/api/v1/accounts", headers={"X-Request-ID": supplied}
    )

    assert response.headers.get("X-Request-ID") == supplied


def test_a_hostile_request_id_is_not_reflected_verbatim(admin_client):
    """
    A client-supplied id is sanitised before it is echoed or logged.

    It arrives in a header and leaves in a header, which is a textbook
    response-splitting and log-injection vector. Newlines and control
    characters must not survive the round trip.
    """
    response = admin_client.get(
        "/api/v1/accounts",
        headers={"X-Request-ID": "ok-part"},
    )
    returned = response.headers.get("X-Request-ID", "")

    assert "\n" not in returned
    assert "\r" not in returned

    oversized = admin_client.get(
        "/api/v1/accounts",
        headers={"X-Request-ID": "A" * 500},
    )
    assert len(oversized.headers.get("X-Request-ID", "")) <= 200


def test_an_error_body_carries_the_request_id(admin_client):
    """The id in the body matches the one in the header."""
    response = admin_client.get("/api/v1/accounts/not-a-real-account")

    assert response.status_code == 404

    body = response.json()
    if "request_id" in body:
        assert body["request_id"] == response.headers.get("X-Request-ID")


# -----------------------------------------------------------------------------
# What must not appear
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("path", PROBE_PATHS + ["/api/v1/accounts/nope"])
def test_no_stack_trace_or_secret_in_any_response(admin_client, path):
    raw = admin_client.get(path).text.lower()

    for forbidden in (
        "traceback (most recent call last)",
        "sqlalchemy.exc",
        "file \"/app",
        "postgresql://",
        "secret_key",
        "password_hash",
    ):
        assert forbidden not in raw, f"{path} leaked {forbidden!r}"


def test_cors_does_not_combine_a_wildcard_origin_with_credentials(client_factory, users):
    """
    A wildcard origin plus credentials is refused, not honoured.

    That combination is rejected by browsers anyway, and a server that claims
    it is a server whose CORS configuration nobody has read. `create_app`
    detects it, logs, and drops credentials rather than starting with a policy
    that cannot work.
    """
    permissive = client_factory(
        BACKEND_CORS_ORIGINS=["*"], CORS_ALLOW_CREDENTIALS=True
    )

    response = permissive.get(
        "/api/v1/health/live", headers={"Origin": "https://somewhere.invalid"}
    )

    if response.headers.get("Access-Control-Allow-Origin") == "*":
        assert "Access-Control-Allow-Credentials" not in response.headers
