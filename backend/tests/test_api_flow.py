"""
The contract every endpoint shares.

The other modules test what each endpoint *does*. This one tests what they all
do the same way, because a client is written once against the shape of the API
and then reused everywhere. An endpoint that answers with a different envelope,
paginates by a different rule, or reports an error in its own format costs more
than a wrong value: it costs a special case in the client that nobody
remembers is there.

Four shared contracts, each checked across the real route list rather than
against one example:

**One pagination envelope.** `items`, `page`, `page_size`, `total`,
`total_pages`, `sort_by`, `sort_order`, `caveats` — at the top level, on every
list endpoint. Not a nested `meta`, not a bare array.

**One error envelope.** `code`, `message`, `category`, `retryable`, and
optionally `details` and `request_id`. Flat, for every failure, including the
ones FastAPI would otherwise answer in its own `{"detail": ...}` format.

**One authentication rule.** Everything under `/api/v1` needs a bearer token
except the paths that declare themselves public. A protected endpoint that
answers an anonymous caller is a hole; a public one that demands a token is a
client that cannot log in.

**Request ids come back.** Every response carries `X-Request-ID`, echoing the
caller's when one was sent. This is the thread between a user's screenshot, an
access log line and an audit row, and it only works if it is on every
response.

The route list is read from the live application, so an endpoint added without
these properties fails here rather than being discovered by whoever writes the
client.
"""

from __future__ import annotations

import pytest

from tests.utils import assert_error, assert_ok, assert_paginated

pytestmark = pytest.mark.api


API = "/api/v1"


# -----------------------------------------------------------------------------
# The route inventory
#
# Collected from the application rather than hand-listed, so that these tests
# apply to endpoints written after them.
# -----------------------------------------------------------------------------


def api_routes(app) -> list[tuple[str, str]]:
    """Every (method, path) under the v1 prefix, ignoring HEAD and OPTIONS."""
    found: list[tuple[str, str]] = []

    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", None)

        if not path.startswith(API) or not methods:
            continue

        for method in sorted(methods):
            if method in {"HEAD", "OPTIONS"}:
                continue
            found.append((method, path))

    return sorted(found)


def parameterless_get_routes(app) -> list[str]:
    """GET routes with no path parameters: callable without fixture data."""
    return [
        path
        for method, path in api_routes(app)
        if method == "GET" and "{" not in path
    ]


#: Collection endpoints: the ones that must carry the pagination envelope.
#: Listed explicitly, because "a GET that returns many things" cannot be
#: inferred from the path, and a wrong guess would make this test vacuous.
LIST_ENDPOINTS = [
    f"{API}/accounts",
    f"{API}/transactions",
    f"{API}/alerts",
    f"{API}/cases",
    f"{API}/complaints",
    f"{API}/entities",
    f"{API}/analysis/runs",
    f"{API}/model/versions",
]

#: Endpoints reachable without a token. Everything else under /api/v1 is not.
#:
#: The health probes are public because a load balancer and a container
#: orchestrator call them with no credentials, and their payloads are
#: deliberately free of configuration values. `/health/status` is an alias of
#: `/health` for operational tooling that expects that path.
PUBLIC_ENDPOINTS = [
    "/health",
    f"{API}/health",
    f"{API}/health/live",
    f"{API}/health/ready",
    f"{API}/health/status",
    f"{API}/openapi.json",
]


# -----------------------------------------------------------------------------
# Pagination
# -----------------------------------------------------------------------------


def test_model_metrics_router_is_loaded_and_mounted(app):
    """
    Model metrics are an optional feature surface, but when enabled in CI the
    module must load and its routes must be mounted instead of silently 404ing.
    """
    import importlib

    module = importlib.import_module("app.api.v1.endpoints.model_metrics")
    assert getattr(module, "router", None) is not None

    paths = {getattr(route, "path", "") for route in app.routes}
    if "/api/v1/model/versions" not in paths:
        from app.api.v1.router import get_api_v1_inclusion_state

        pytest.fail(
            "Model metrics module imported but its routes were not mounted; "
            f"API v1 inclusion state: {get_api_v1_inclusion_state()!r}"
        )


class TestPaginationContract:
    """One envelope, on every list endpoint."""

    @pytest.mark.parametrize("path", LIST_ENDPOINTS)
    def test_envelope_is_present_and_flat(self, analyst_client, path):
        response = analyst_client.get(path)
        if path == f"{API}/model/versions" and response.status_code == 404:
            from app.api.v1.router import get_api_v1_inclusion_state

            pytest.fail(
                "Model router is missing; API v1 inclusion state: "
                f"{get_api_v1_inclusion_state()!r}"
            )
        body = assert_paginated(assert_ok(response))

        assert "meta" not in body, "pagination is flat, not nested under meta"
        assert isinstance(body["caveats"], list)

    @pytest.mark.parametrize("path", LIST_ENDPOINTS)
    def test_sort_fields_are_reported_back(self, analyst_client, path):
        """
        A client that lets the user sort has to render the current sort, and
        guessing it from the request would be wrong the moment the server
        falls back to a default.
        """
        body = assert_ok(analyst_client.get(path))

        assert "sort_by" in body
        assert body.get("sort_order") in {"asc", "desc"}

    @pytest.mark.parametrize("path", LIST_ENDPOINTS)
    def test_an_empty_collection_is_not_an_error(self, analyst_client, path):
        body = assert_paginated(assert_ok(analyst_client.get(path)))

        assert body["items"] == []
        assert body["total"] == 0

    @pytest.mark.parametrize("path", LIST_ENDPOINTS)
    def test_page_size_is_bounded(self, analyst_client, path):
        """
        An unbounded page size is a denial-of-service parameter. The server
        clamps rather than refuses, so the request still works.
        """
        body = assert_ok(analyst_client.get(path, params={"page_size": 100_000}))

        assert body["page_size"] <= 500

    @pytest.mark.parametrize("path", LIST_ENDPOINTS)
    def test_a_page_beyond_the_end_is_empty_not_an_error(self, analyst_client, path):
        body = assert_paginated(
            assert_ok(analyst_client.get(path, params={"page": 9_999}))
        )

        assert body["items"] == []
        assert body["page"] == 9_999

    @pytest.mark.parametrize("path", LIST_ENDPOINTS)
    def test_a_zero_page_is_refused(self, analyst_client, path):
        assert_error(analyst_client.get(path, params={"page": 0}), 422)

    @pytest.mark.parametrize("path", LIST_ENDPOINTS)
    def test_an_unknown_sort_field_is_refused_not_ignored(self, analyst_client, path):
        """
        Silently ignoring an unknown sort field returns rows in some other
        order and lets the client believe its sort worked.
        """
        assert_error(
            analyst_client.get(path, params={"sort_by": "no_such_column"}),
            422,
        )


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------


class TestErrorContract:
    """One error shape, whatever went wrong."""

    def test_validation_failure_uses_the_envelope(self, analyst_client):
        """
        FastAPI's own 422 body is `{"detail": [...]}`. The application
        replaces it, so a client has one error reader rather than two.
        """
        body = assert_error(
            analyst_client.get(f"{API}/accounts", params={"page": -1}),
            422,
        )

        assert "detail" not in body
        assert body["category"]
        assert body["retryable"] is False

    def test_not_found_uses_the_envelope(self, analyst_client):
        body = assert_error(analyst_client.get(f"{API}/accounts/ACC-missing"), 404)

        assert body["code"]
        assert body["retryable"] is False

    def test_unauthenticated_uses_the_envelope(self, client):
        body = assert_error(client.get(f"{API}/accounts"), 401)

        assert body["code"]

    def test_forbidden_uses_the_envelope(self, auditor_client):
        """The auditor can read everything and change nothing."""
        body = assert_error(
            auditor_client.post(f"{API}/cases", json={"title": "Nope"}),
            403,
        )

        assert body["code"]

    def test_unknown_path_under_the_api_prefix_uses_the_envelope(self, analyst_client):
        body = assert_error(analyst_client.get(f"{API}/no-such-collection"), 404)

        assert body["code"]

    def test_wrong_method_uses_the_envelope(self, analyst_client):
        body = assert_error(analyst_client.delete(f"{API}/accounts"), 405)

        assert body["code"]

    def test_error_codes_are_namespaced(self, analyst_client):
        """
        A prefixed code can be looked up and translated. A bare
        "not_found" collides with every other API the client talks to.
        """
        body = assert_error(analyst_client.get(f"{API}/accounts/ACC-missing"), 404)

        assert body["code"].startswith("MULEGUARD_")

    def test_a_retryable_flag_is_always_present(self, analyst_client):
        """
        Whether to retry is the first thing a client needs to know, and it is
        not derivable from the status code alone.
        """
        for response in (
            analyst_client.get(f"{API}/accounts/ACC-missing"),
            analyst_client.get(f"{API}/accounts", params={"page": 0}),
        ):
            body = assert_error(response, (404, 422))
            assert isinstance(body["retryable"], bool)


# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------


class TestAuthenticationContract:
    """Who may reach what, before any permission check runs."""

    @pytest.mark.parametrize("path", PUBLIC_ENDPOINTS)
    def test_public_paths_need_no_token(self, client, path):
        assert_ok(client.get(path), (200, 503))

    def test_every_other_v1_get_requires_a_token(self, client, app):
        """
        Collected from the live route list, so an endpoint added without
        authentication fails here.
        """
        unprotected: list[str] = []

        for path in parameterless_get_routes(app):
            if path in PUBLIC_ENDPOINTS:
                continue

            if client.get(path).status_code != 401:
                unprotected.append(path)

        assert unprotected == []

    def test_a_malformed_authorization_header_is_refused(self, client):
        response = client.get(
            f"{API}/accounts",
            headers={"Authorization": "Bearer not-a-token"},
        )

        assert_error(response, 401)

    def test_a_non_bearer_scheme_is_refused(self, client):
        response = client.get(
            f"{API}/accounts",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )

        assert_error(response, 401)

    def test_the_token_identifies_the_caller(self, analyst_client, users):
        body = assert_ok(analyst_client.get(f"{API}/auth/me"))

        assert body["username"] == users["analyst"].username
        assert body["role"] == "ANALYST"


# -----------------------------------------------------------------------------
# Request correlation
# -----------------------------------------------------------------------------


class TestRequestCorrelation:
    """The id that ties a complaint to a log line."""

    def test_a_request_id_is_returned(self, analyst_client):
        response = analyst_client.raw.get(f"{API}/accounts")

        assert response.headers.get("X-Request-ID")

    def test_a_supplied_request_id_is_echoed(self, analyst_client):
        supplied = "req-flow-0001"

        response = analyst_client.raw.get(
            f"{API}/accounts",
            headers={"X-Request-ID": supplied},
        )

        assert response.headers.get("X-Request-ID") == supplied

    def test_an_error_carries_the_request_id(self, analyst_client):
        """
        The error body is what a user screenshots, so the id has to be in the
        body and not only in a header they will never see.
        """
        supplied = "req-flow-0002"

        response = analyst_client.get(
            f"{API}/accounts/ACC-missing",
            headers={"X-Request-ID": supplied},
        )
        body = assert_error(response, 404)

        assert body.get("request_id") == supplied

    def test_a_hostile_request_id_is_not_echoed(self, analyst_client):
        """
        The id reaches logs and audit rows, so it is validated against a
        character set rather than reflected. An unvalidated value is a
        log-injection parameter, and it is also what a report filename and an
        audit row are built from.
        """
        hostile = "bad id; X-Injected: yes"

        response = analyst_client.raw.get(
            f"{API}/accounts",
            headers={"X-Request-ID": hostile},
        )
        returned = response.headers.get("X-Request-ID") or ""

        assert returned != hostile
        assert returned, "a rejected id is replaced, not dropped"
        assert " " not in returned
        assert ":" not in returned

    def test_each_request_gets_its_own_id(self, analyst_client):
        first = analyst_client.raw.get(f"{API}/accounts")
        second = analyst_client.raw.get(f"{API}/accounts")

        assert first.headers["X-Request-ID"] != second.headers["X-Request-ID"]


# -----------------------------------------------------------------------------
# Caveats
# -----------------------------------------------------------------------------


class TestCaveatContract:
    """
    The platform's position travels with its data.

    Every response that carries a score, a correlation, a path or a trail also
    carries the limits on reading it. These are the responses most likely to be
    quoted in a decision, and a caveat that lives only in the documentation is
    a caveat nobody reads.
    """

    @pytest.mark.parametrize(
        "path",
        [
            f"{API}/accounts",
            f"{API}/alerts",
            f"{API}/complaints",
            f"{API}/graph/status",
            f"{API}/model/current",
            f"{API}/model/limitations",
            f"{API}/dashboard/overview",
            f"{API}/reports/limitations",
        ],
    )
    def test_interpretation_limits_are_published(self, analyst_client, path):
        body = assert_ok(analyst_client.get(path))

        assert isinstance(body.get("caveats"), list)
        assert body["caveats"], f"{path} published no caveats"

    def test_the_model_endpoint_says_what_it_cannot_do(self, analyst_client):
        body = assert_ok(analyst_client.get(f"{API}/model/limitations"))
        text = " ".join(str(item) for item in body["caveats"]).lower()

        assert "synthetic" in text


# -----------------------------------------------------------------------------
# Headers
# -----------------------------------------------------------------------------


class TestResponseHeaders:
    """What every response says about itself."""

    def test_json_responses_declare_their_type(self, analyst_client):
        response = analyst_client.raw.get(f"{API}/accounts")

        assert response.headers["content-type"].startswith("application/json")

    def test_authentication_responses_are_never_cached(self, client, users):
        """
        A cached login response is a token sitting in a cache.
        """
        from tests.conftest import TEST_PASSWORD

        response = client.post(
            f"{API}/auth/login",
            json={
                "identifier": users["analyst"].username,
                "password": TEST_PASSWORD,
            },
        )

        assert "no-store" in response.headers.get("Cache-Control", "")

    def test_error_responses_are_never_cached(self, analyst_client):
        """
        A cached 404 outlives the record being created, and a cached 403
        outlives the permission being granted.
        """
        response = analyst_client.raw.get(f"{API}/accounts/ACC-missing")

        assert "no-store" in response.headers.get("Cache-Control", "")

    def test_caching_successful_api_responses_is_a_deliberate_setting(self):
        """
        Successful API responses carry no `Cache-Control` by default, which is
        a decision rather than an omission: `SECURE_HEADERS_NO_STORE_FOR_API`
        exists to turn it on. The setting is asserted here so that the default
        cannot quietly change meaning — a deployment serving investigation
        data through a shared cache should have had to choose that.
        """
        from app.core.config import Settings

        fields = Settings.model_fields

        assert fields["SECURE_HEADERS_NO_STORE_FOR_API"].default is False
        assert fields["SECURE_HEADERS_NO_STORE_FOR_ERRORS"].default is True
        assert fields["SECURE_HEADERS_NO_STORE_FOR_AUTH"].default is True

    def test_every_security_header_setting_is_declared(self):
        """
        The settings model ignores unknown environment variables, so a header
        setting the middleware reads but the model does not declare is a knob
        that looks configurable and does nothing. HSTS could be switched on
        without a max-age, and CSP with nowhere to send reports.

        Read out of the middleware rather than listed here, so a new setting
        has to be declared to pass.
        """
        from app.api.middleware import security_headers as mw
        from app.core.config import Settings

        names = set(mw._CSP_SETTING_TO_DIRECTIVE)
        names.update(
            {
                "COEP",
                "COEP_ENABLED",
                "COOP",
                "COOP_ENABLED",
                "CORP",
                "CORP_ENABLED",
                "CSP_DOCS_ALLOW_UNSAFE_EVAL",
                "CSP_DOCS_EXEMPT",
                "CSP_DOCS_RELAXED",
                "CSP_ENABLED",
                "CSP_REPORT_ONLY",
                "CSP_REPORT_URI",
                "HSTS_ENABLED",
                "HSTS_INCLUDE_SUBDOMAINS",
                "HSTS_MAX_AGE",
                "HSTS_PRELOAD",
                "PERMISSIONS_POLICY",
                "SECURE_HEADERS_NO_STORE_FOR_API",
                "SECURE_HEADERS_NO_STORE_FOR_AUTH",
                "SECURE_HEADERS_NO_STORE_FOR_ERRORS",
                "VARY_HEADER",
            }
        )

        undeclared = sorted(name for name in names if name not in Settings.model_fields)

        assert undeclared == []

    def test_csp_directive_settings_default_to_unset(self):
        """
        None means "keep the baseline directive"; an empty string means
        "remove it". Declaring these as empty strings would strip every
        directive from the policy as soon as CSP was enabled, which is the
        opposite of what setting them is for.
        """
        from app.api.middleware import security_headers as mw
        from app.core.config import Settings

        for name in mw._CSP_SETTING_TO_DIRECTIVE:
            assert Settings.model_fields[name].default is None, name

    def test_the_api_version_is_discoverable(self, client):
        body = assert_ok(client.get(f"{API}/health"))

        assert body.get("version") or body.get("api_version")
