"""
Rate limiting.

The suite runs with the limiter off — a shared bucket would otherwise make
whichever test happens to run sixth fail — so this module switches it back on
for itself.

Each test gets its own bucket by setting a unique `AUTH_RATE_LIMIT_KEY_SALT`.
The salt is part of the limiter's key, so a fresh salt is a fresh bucket. That
is cleaner than reaching into the module-level limiter and clearing it:
`_RATE_LIMITER` is private, it is shared with anything else running in the
process, and a test that reaches into it leaves the next one depending on
having done so.
"""

from __future__ import annotations

import pytest

from tests.utils import unique_id

pytestmark = [pytest.mark.security, pytest.mark.api]


LOGIN = "/api/v1/auth/login"


@pytest.fixture()
def limited(override_settings):
    """
    Turn the limiter on with a bucket nobody else is using.

    Returns a callable so a test can set its own limit.
    """

    def configure(**rules):
        return override_settings(
            AUTH_RATE_LIMIT_ENABLED=True,
            AUTH_RATE_LIMIT_KEY_SALT=unique_id("salt"),
            **rules,
        )

    return configure


def test_login_is_limited(client, users, limited):
    """
    The limit applies, and the request that exceeds it gets a 429.

    Login is the endpoint that most needs this: it is public, it is the one
    place a password can be guessed, and the lockout on the user record does
    nothing about an attacker spraying one password across many usernames.
    """
    limited(AUTH_RATE_LIMIT_LOGIN="3/minute")

    statuses = [
        client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"}).status_code
        for _ in range(5)
    ]

    assert statuses[:3] == [401, 401, 401]
    assert 429 in statuses[3:]


def test_a_rate_limited_response_says_when_to_retry(client, users, limited):
    """
    `Retry-After` is present on the 429.

    Without it a client has to guess, and a client that guesses wrong retries
    immediately — which is indistinguishable from the attack the limit exists
    to slow down.
    """
    limited(AUTH_RATE_LIMIT_LOGIN="2/minute")

    for _ in range(2):
        client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"})

    response = client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"})

    assert response.status_code == 429
    assert "retry-after" in {name.lower() for name in response.headers}
    assert int(response.headers["retry-after"]) >= 1


def test_rate_limit_headers_are_advisory_and_present(client, users, limited):
    """
    `RateLimit-Limit` and `RateLimit-Remaining` on a successful response.

    These let a well-behaved client pace itself instead of discovering the
    limit by hitting it.
    """
    limited(AUTH_RATE_LIMIT_LOGIN="10/minute")

    response = client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"})
    headers = {name.lower() for name in response.headers}

    assert "ratelimit-limit" in headers
    assert "ratelimit-remaining" in headers


def test_the_limit_counts_failures_not_successes_only(client, users, limited):
    """
    A successful login consumes the budget too.

    Counting only failures would let an attacker who has one valid credential
    use it as a free oracle for everything else; and more prosaically, a
    runaway client that happens to be authenticating correctly is still a
    runaway client.
    """
    limited(AUTH_RATE_LIMIT_LOGIN="2/minute")

    from tests.conftest import TEST_PASSWORD

    first = client.post(LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD})
    second = client.post(LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD})
    third = client.post(LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD})

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429


def test_the_limiter_is_off_by_configuration(client, users, override_settings):
    """
    `AUTH_RATE_LIMIT_ENABLED=false` actually turns it off.

    Worth its own test. The two switches were previously combined with `or`
    against an undeclared `RATE_LIMIT_ENABLED`, which defaults to true — so
    the declared flag had no effect at all and limiting could not be disabled.
    Both now use `and`, and this asserts the result rather than the reasoning.
    """
    override_settings(
        AUTH_RATE_LIMIT_ENABLED=False,
        AUTH_RATE_LIMIT_LOGIN="1/minute",
        AUTH_RATE_LIMIT_KEY_SALT=unique_id("salt"),
    )

    statuses = [
        client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"}).status_code
        for _ in range(4)
    ]

    assert 429 not in statuses


def test_a_429_body_does_not_leak_the_keying_scheme(client, users, limited):
    """
    The error says the scope and the limit, not the key.

    The key is a hash of a salt, the client address and the path. Including it
    would publish the salt's effect and tell an attacker how to land in a
    different bucket.
    """
    limited(AUTH_RATE_LIMIT_LOGIN="1/minute")

    client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"})
    response = client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"})

    assert response.status_code == 429

    body = response.json()
    assert body["code"]

    raw = response.text.lower()
    assert "salt" not in raw
    assert "secret" not in raw


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/health/live",
        "/api/v1/health/ready",
    ],
)
def test_health_probes_are_not_rate_limited(client, limited, path):
    """
    A probe runs every few seconds forever.

    Rate limiting it would mean the orchestrator eventually gets a 429 and
    restarts a healthy container. These endpoints carry no limiter dependency,
    and this is the test that notices if one is added.
    """
    limited(AUTH_RATE_LIMIT_GLOBAL="2/minute")

    statuses = [client.get(path).status_code for _ in range(6)]
    assert 429 not in statuses
