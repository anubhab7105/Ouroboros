"""
The OpenAPI document.

Two things are being checked. First, that the schema generates at all: it is
the cheapest possible test and it catches a whole class of mistake —
a response model that cannot be serialised, two routes with the same
`operation_id`, a forward reference that never resolved — which otherwise
surfaces as a 500 the first time someone opens the docs.

Second, that the document tells the truth about authentication. A generated
client reads the security scheme, so a protected endpoint documented as public
produces a client that omits the header and fails at runtime for a reason that
looks like a server bug.
"""

from __future__ import annotations

import pytest

from tests.utils import assert_ok

pytestmark = pytest.mark.api


def test_openapi_schema_generates(client):
    schema = assert_ok(client.get("/openapi.json"))

    assert schema["openapi"].startswith("3.")
    assert schema["info"]["title"]
    assert schema["paths"]


def test_every_v1_path_is_documented(app, client):
    """
    Every mounted route appears in the schema.

    A route excluded with `include_in_schema=False` is a deliberate decision
    (the root and `/health` are both excluded), so the comparison runs the
    other way round: everything the application mounted under `/api/v1` and
    did not exclude must be in the document.
    """
    schema = assert_ok(client.get("/openapi.json"))
    documented = set(schema["paths"])

    mounted = {
        route.path
        for route in app.routes
        if getattr(route, "include_in_schema", False)
        and str(getattr(route, "path", "")).startswith("/api/v1")
    }

    missing = sorted(mounted - documented)
    assert not missing, f"mounted but undocumented: {missing}"


def test_bearer_security_scheme_is_declared(client):
    """
    The document declares how to authenticate.

    `_install_openapi_bearer_security` adds this. Without it the generated
    clients have no way to send a token and the docs page has no
    "Authorize" button, which makes the API look unusable even though it
    works.
    """
    schema = assert_ok(client.get("/openapi.json"))
    schemes = schema.get("components", {}).get("securitySchemes", {})

    assert schemes, "no security schemes declared"

    bearer = [
        scheme
        for scheme in schemes.values()
        if str(scheme.get("scheme", "")).lower() == "bearer"
    ]
    assert bearer, f"no bearer scheme among {list(schemes)}"


def test_login_is_not_marked_as_requiring_auth(client):
    """
    Login is reachable without a token, and says so.

    Documenting the one endpoint that issues tokens as requiring a token is a
    small mistake with a confusing symptom: a generated client that cannot
    start.
    """
    schema = assert_ok(client.get("/openapi.json"))
    login = schema["paths"]["/api/v1/auth/login"]["post"]

    assert login.get("security", []) in ([], None) or login["security"] == []


@pytest.mark.parametrize(
    "path,method",
    [
        ("/api/v1/accounts", "get"),
        ("/api/v1/alerts", "get"),
        ("/api/v1/cases", "get"),
        ("/api/v1/users", "get"),
        ("/api/v1/audit", "get"),
    ],
)
def test_protected_paths_declare_security(client, path, method):
    """A protected route carries a security requirement in the document."""
    schema = assert_ok(client.get("/openapi.json"))

    operation = schema["paths"][path][method]
    security = operation.get("security")

    assert security, f"{method.upper()} {path} documented as public"


def test_docs_page_renders(client):
    """
    The interactive docs load.

    Worth asserting separately from the schema: the page is served with its own
    CSP, and a policy that blocks the Swagger bundle leaves a document that is
    valid and a page that is blank.
    """
    response = client.get("/docs")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_schema_does_not_expose_internal_settings(client):
    """
    No configuration object leaks into a schema component.

    The settings model has a hundred-odd fields including a secret key. It is
    not a request or response model anywhere, and the way it would end up in
    the document is by being annotated on an endpoint by accident.
    """
    schema = assert_ok(client.get("/openapi.json"))
    components = schema.get("components", {}).get("schemas", {})

    assert "Settings" not in components

    raw = str(components).lower()
    assert "secret_key" not in raw
    assert "database_url" not in raw
