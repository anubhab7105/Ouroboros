"""
Shared fixtures for the MULEGUARD backend test suite.

Two things here are load-bearing and worth reading before changing:

**The environment is set before `app` is imported.** `app.db` builds its engine
and session factory at import time from `get_settings()`, and `get_settings()`
is `lru_cache`d. Setting `DATABASE_URL` after the first import would leave the
tests pointed at the configured PostgreSQL instance, which in CI does not
exist and locally would be someone's real database. So the environment is
assembled at module scope, before any `app.*` import, and the cache is cleared
for good measure.

**The database is one in-memory SQLite connection, shared.** With
`StaticPool`, every session in the process sees the same database, which is
what lets a fixture insert an account and the API then read it back through a
different session. Each test runs inside a transaction that is rolled back
afterwards, so tests do not see each other's rows.

SQLite is not PostgreSQL, and two differences matter: it has no server-side
statement timeout, and its `JSON` type does not support containment operators.
Anything that depends on either is marked and skipped rather than asserted
loosely.
"""

from __future__ import annotations

import os
from typing import Any, Iterator

import pytest

# -----------------------------------------------------------------------------
# Environment, before any application import
# -----------------------------------------------------------------------------

#: A real 64-byte secret, so the strong-secret validation passes rather than
#: being switched off. It is a test constant and protects nothing.
_TEST_KEY = "0123456789abcdef" * 8

_TEST_ENV: dict[str, str] = {
    "BACKEND_ENV": "local",
    "BACKEND_DEBUG": "false",
    "BACKEND_SECRET_KEY": _TEST_KEY,
    "BACKEND_DATASET_MODE": "synthetic",
    "BACKEND_VALIDATE_ENV_ON_STARTUP": "false",
    # `TrustedHostMiddleware` is installed first and rejects an unlisted Host
    # with a 400 before any route is reached. Starlette's TestClient sends
    # `Host: testserver`, which is not in the application's default allowlist,
    # so without this every request in the suite would fail identically and
    # for a reason unrelated to what was being tested.
    "BACKEND_ALLOWED_HOSTS": "testserver,localhost,127.0.0.1",
    # One shared in-memory database for the whole process.
    "DATABASE_URL": "sqlite+pysqlite:///:memory:",
    "DB_ECHO": "false",
    "DB_AUTO_COMMIT_ON_REQUEST_SUCCESS": "false",
    # Users are created by the fixtures below rather than by bootstrap, so the
    # dev-user seeding path stays out of the way.
    "SEED_DEV_USERS": "false",
    "DEV_USERS_REQUIRE_PASSWORD_FROM_ENV": "false",
    # Rate limiting is off by default: a suite that shares a limiter bucket
    # fails in whichever test happens to run sixth. `rate_limited_client`
    # turns it back on for the tests that are about the limiter itself.
    "AUTH_RATE_LIMIT_ENABLED": "false",
    "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    # Lockout is exercised explicitly in test_auth; a low threshold here would
    # lock the shared fixtures out partway through an unrelated module.
    "AUTH_LOGIN_MAX_ATTEMPTS": "5",
    "AUTH_LOGIN_LOCKOUT_MINUTES": "15",
}

for _key, _value in _TEST_ENV.items():
    os.environ.setdefault(_key, _value)

# The router registry is evaluated at import time; keep model monitoring mounted in tests.
os.environ["ML_ENABLED"] = "true"

# `setdefault` leaves an inherited value in place, which is right for most
# settings but wrong for the database: a DATABASE_URL in the developer's shell
# would point the suite at a real database. This one is forced.
os.environ["DATABASE_URL"] = _TEST_ENV["DATABASE_URL"]

from app.core.config import get_settings  # noqa: E402

get_settings.cache_clear()

from sqlalchemy.orm import Session  # noqa: E402

from sqlalchemy.orm import Session as _SQLAlchemySession

_original_session_commit = _SQLAlchemySession.commit

def _session_commit_without_outer_transaction(self: Any) -> None:
    # In tests the session is bound to an outer transaction that must remain
    # open so it can be rolled back. Committing would persist data across
    # tests, so flush instead.
    self.flush()

_SQLAlchemySession.commit = _session_commit_without_outer_transaction  # type: ignore[assignment]
from app.core.security import hash_password  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import User, UserRole  # noqa: E402
from app import db as app_db  # noqa: E402

from tests import factories  # noqa: E402
from tests.utils import assert_ok  # noqa: E402

#: Passwords for the fixture users. Long enough for the password policy
#: (12 characters, mixed case, digit, symbol) so that the policy stays on.
TEST_PASSWORD = "Test-" + "Passw0rd!2026"


# -----------------------------------------------------------------------------
# Schema
# -----------------------------------------------------------------------------


@pytest.fixture(scope="session")
def engine() -> Iterator[Any]:
    """
    The process-wide engine, with the schema created once.

    Created from `app.db`'s own engine rather than a second one, so that the
    API's sessions and the tests' sessions are unquestionably the same
    database.
    """
    app_db.init_db()
    engine = app_db.get_engine()
    engine.dispose = lambda: None
    yield engine


@pytest.fixture()
def db(engine: Any) -> Iterator[Session]:
    """
    A session wrapped in a transaction that is rolled back.

    The session is bound to an explicit connection and the outer transaction
    is rolled back at the end, so a test's rows never reach the next test even
    though they share one in-memory database. A nested savepoint lets code
    under test call `commit()` without ending the outer transaction.
    """
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")

    try:
        yield session
    finally:
        transaction.rollback()
        session.close()
        connection.close()


# -----------------------------------------------------------------------------
# Users
# -----------------------------------------------------------------------------


def _make_user(session: Session, username: str, role: UserRole) -> User:
    settings = get_settings()

    user = User(
        id=f"usr_{username}",
        username=username,
        email=f"{username}@muleguard.local",
        full_name=username.replace("_", " ").title(),
        role=role,
        password_hash=hash_password(TEST_PASSWORD, settings),
        is_active=True,
        must_change_password=False,
        failed_login_count=0,
    )

    session.add(user)
    session.flush()
    return user


@pytest.fixture()
def users(db: Session) -> dict[str, User]:
    """
    One user per role.

    All four exist in every test that asks for them, because almost every
    permission assertion is "this role may, that role may not", and writing
    that needs both sides present.
    """
    created = {
        "admin": _make_user(db, "admin", UserRole.ADMIN),
        "senior": _make_user(db, "senior_investigator", UserRole.SENIOR_INVESTIGATOR),
        "analyst": _make_user(db, "analyst", UserRole.ANALYST),
        "auditor": _make_user(db, "auditor", UserRole.AUDITOR),
    }

    db.commit()
    return created


# -----------------------------------------------------------------------------
# Application and clients
# -----------------------------------------------------------------------------


@pytest.fixture()
def app(db: Session) -> Iterator[Any]:
    """
    The FastAPI application, with `get_db` overridden to the test session.

    Overriding the dependency rather than letting the app open its own session
    is what makes a test's uncommitted fixture data visible to the API, and
    what keeps the API's writes inside the transaction this test rolls back.
    """
    application = create_app()

    def override_get_db() -> Iterator[Session]:
        yield db

    application.dependency_overrides[app_db.get_db] = override_get_db

    try:
        yield application
    finally:
        application.dependency_overrides.clear()


@pytest.fixture()
def client(app: Any) -> Iterator[Any]:
    """An unauthenticated client."""
    from fastapi.testclient import TestClient

    import app.main as app_main

    async def _noop_shutdown(logger: Any) -> None:
        return None

    app_main._shutdown_database = _noop_shutdown

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def _login(test_client: Any, username: str) -> str:
    """Sign in and return the bearer token."""
    body = assert_ok(
        test_client.post(
            "/api/v1/auth/login",
            json={"identifier": username, "password": TEST_PASSWORD},
        )
    )
    return str(body["access_token"])


class AuthedClient:
    """
    A thin wrapper that attaches a bearer token to every request.

    Not a subclass of TestClient: wrapping keeps the token handling in one
    place and leaves the underlying client available as `.raw` for the few
    tests that need to send a deliberately malformed request.
    """

    def __init__(self, test_client: Any, token: str, username: str) -> None:
        self.raw = test_client
        self.token = token
        self.username = username
        self._headers = {"Authorization": f"Bearer {token}"}

    def _merge(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        headers = dict(self._headers)
        headers.update(kwargs.pop("headers", None) or {})
        kwargs["headers"] = headers
        return kwargs

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.raw.get(url, **self._merge(kwargs))

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.raw.post(url, **self._merge(kwargs))

    def patch(self, url: str, **kwargs: Any) -> Any:
        return self.raw.patch(url, **self._merge(kwargs))

    def put(self, url: str, **kwargs: Any) -> Any:
        return self.raw.put(url, **self._merge(kwargs))

    def delete(self, url: str, **kwargs: Any) -> Any:
        return self.raw.delete(url, **self._merge(kwargs))


@pytest.fixture()
def admin_client(client: Any, users: dict[str, User]) -> AuthedClient:
    return AuthedClient(client, _login(client, "admin"), "admin")


@pytest.fixture()
def senior_client(client: Any, users: dict[str, User]) -> AuthedClient:
    return AuthedClient(client, _login(client, "senior_investigator"), "senior_investigator")


@pytest.fixture()
def analyst_client(client: Any, users: dict[str, User]) -> AuthedClient:
    return AuthedClient(client, _login(client, "analyst"), "analyst")


@pytest.fixture()
def auditor_client(client: Any, users: dict[str, User]) -> AuthedClient:
    return AuthedClient(client, _login(client, "auditor"), "auditor")


@pytest.fixture()
def role_clients(
    admin_client: AuthedClient,
    senior_client: AuthedClient,
    analyst_client: AuthedClient,
    auditor_client: AuthedClient,
) -> dict[str, AuthedClient]:
    """All four roles, for a table-driven permission assertion."""
    return {
        "ADMIN": admin_client,
        "SENIOR_INVESTIGATOR": senior_client,
        "ANALYST": analyst_client,
        "AUDITOR": auditor_client,
    }


# -----------------------------------------------------------------------------
# Data
# -----------------------------------------------------------------------------


@pytest.fixture()
def client_factory(db: Session) -> Iterator[Any]:
    """
    Build a client on an application constructed with different settings.

    `override_settings` reaches the endpoints, which read settings through a
    dependency, but it cannot reach the middleware: `SecurityHeadersMiddleware`
    and `TrustedHostMiddleware` are constructed once with the settings that
    `create_app` was given, and a dependency override comes too late to change
    them. Anything that tests middleware behaviour has to build its own
    application, which is what this does.

    Every client it builds is closed when the test ends.
    """
    from fastapi.testclient import TestClient

    opened: list[Any] = []

    def build(**changes: Any) -> Any:
        settings = get_settings().model_copy(update=changes) if changes else get_settings()
        application = create_app(settings=settings)

        def override_get_db() -> Iterator[Session]:
            yield db

        application.dependency_overrides[app_db.get_db] = override_get_db

        from app.api.deps import get_api_settings

        application.dependency_overrides[get_api_settings] = lambda: settings

        import app.main as app_main

        async def _noop_shutdown(logger: Any) -> None:
            return None

        app_main._shutdown_database = _noop_shutdown

        test_client = TestClient(application, raise_server_exceptions=False)
        test_client.__enter__()
        opened.append(test_client)
        return test_client

    try:
        yield build
    finally:
        for test_client in opened:
            test_client.__exit__(None, None, None)


@pytest.fixture()
def override_settings(app: Any) -> Any:
    """
    Change settings for one test.

    `get_settings()` is `lru_cache`d, so mutating the environment mid-test
    changes nothing. The endpoints reach settings through the
    `get_api_settings` dependency, which is overridable, so that is the seam
    this uses. A copy of the real settings with fields replaced keeps every
    other value exactly as the rest of the suite sees it.

    Used by the tests that are *about* a setting — rate limiting, lockout,
    pagination ceilings — which have to switch it on against a suite that
    deliberately runs with it off.
    """
    from app.api.deps import get_api_settings

    def apply(**changes: Any) -> Any:
        updated = get_settings().model_copy(update=changes)
        app.dependency_overrides[get_api_settings] = lambda: updated
        return updated

    return apply


@pytest.fixture()
def make(db: Session) -> factories.Factory:
    """
    The data factory, bound to this test's session.

    Every scenario in the suite is built through this rather than through raw
    model construction, so a column rename is one edit in `factories.py`
    instead of forty edits across the tests.
    """
    return factories.Factory(db)


@pytest.fixture()
def api_prefix() -> str:
    return "/api/v1"


# -----------------------------------------------------------------------------
# Fixture files
# -----------------------------------------------------------------------------


@pytest.fixture(scope="session")
def fixtures_dir() -> Any:
    """The `tests/fixtures/` directory, resolved from this file's location."""
    from pathlib import Path

    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def load_fixture(fixtures_dir: Any) -> Any:
    """
    Read a JSON fixture by name, e.g. `load_fixture("accounts.valid.json")`.

    Session-scoped and returns the parsed object. Tests must not mutate what
    comes back — a test that needs a changed record copies it first — because
    everything in the session shares the same dict.
    """
    import json

    cache: dict[str, Any] = {}

    def read(name: str) -> Any:
        if name not in cache:
            cache[name] = json.loads((fixtures_dir / name).read_text(encoding="utf-8"))
        return cache[name]

    return read


@pytest.fixture(scope="session")
def load_scenario(fixtures_dir: Any) -> Any:
    """
    Read a scenario by id, e.g. `load_scenario("fan_in")`.

    The scenario files are the written record of what each typology means;
    `tests/factories.py` holds builders with the same names and parameters.
    `test_rules.py` compares the two so they cannot drift apart silently.
    """
    import json

    def read(scenario_id: str) -> Any:
        path = fixtures_dir / "scenarios" / f"{scenario_id}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    return read
