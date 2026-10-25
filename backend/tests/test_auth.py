"""
Authentication: login, the token, `/auth/me`, and password change.

The interesting assertions here are about what the API refuses to say. A login
endpoint that distinguishes "no such user" from "wrong password" hands an
attacker a user enumeration oracle, and one that distinguishes "locked" from
"wrong password" tells them when to stop guessing. Both are off by default,
and the tests pin that default rather than the convenience of a clearer
message.
"""

from __future__ import annotations

import pytest

from app.models import User

from tests.conftest import TEST_PASSWORD
from tests.utils import assert_error, assert_ok

pytestmark = pytest.mark.security


LOGIN = "/api/v1/auth/login"
ME = "/api/v1/auth/me"
CHANGE = "/api/v1/auth/password/change"


# -----------------------------------------------------------------------------
# Login
# -----------------------------------------------------------------------------


def test_login_returns_a_usable_token(client, users):
    body = assert_ok(
        client.post(LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD})
    )

    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["expires_in"] > 0
    assert body["issued_at"]
    assert body["user"]["username"] == "analyst"

    authorised = client.get(ME, headers={"Authorization": f"Bearer {body['access_token']}"})
    assert authorised.status_code == 200


def test_login_response_carries_issued_at_for_clock_independent_expiry(client, users):
    """
    `issued_at` and `expires_in` travel together.

    A client that computes expiry as "now plus `expires_in`" is reading its own
    clock, which may be minutes off the server's. With both fields present it
    can anchor on the server's instant instead. The frontend's `storeSession`
    does exactly that, and this is the server-side half of that contract.
    """
    body = assert_ok(
        client.post(LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD})
    )

    assert "issued_at" in body
    assert "expires_in" in body


def test_login_accepts_email_as_the_identifier(client, users):
    """`identifier` is a username or an email, not a username only."""
    body = assert_ok(
        client.post(
            LOGIN,
            json={"identifier": "analyst@muleguard.local", "password": TEST_PASSWORD},
        )
    )
    assert body["user"]["username"] == "analyst"


def test_login_rejects_a_wrong_password(client, users):
    assert_error(
        client.post(LOGIN, json={"identifier": "analyst", "password": "wrong-password"}),
        401,
    )


def test_login_does_not_reveal_whether_the_user_exists(client, users):
    """
    An unknown user and a wrong password are indistinguishable.

    Same status, same code, same message. Any difference between these two
    responses is a user-enumeration oracle: an attacker who can tell a real
    username from an invented one has halved the problem before guessing a
    single password.
    """
    unknown = client.post(
        LOGIN, json={"identifier": "no-such-person", "password": TEST_PASSWORD}
    )
    wrong = client.post(
        LOGIN, json={"identifier": "analyst", "password": "definitely-not-it"}
    )

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["code"] == wrong.json()["code"]
    assert unknown.json()["message"] == wrong.json()["message"]


def test_login_rejects_an_empty_password(client, users):
    response = client.post(LOGIN, json={"identifier": "analyst", "password": ""})
    assert response.status_code in (401, 422)


def test_login_requires_both_fields(client, users):
    assert_error(client.post(LOGIN, json={"identifier": "analyst"}), 422)
    assert_error(client.post(LOGIN, json={"password": TEST_PASSWORD}), 422)


def test_login_response_never_contains_the_hash(client, users):
    """The password hash is not a field of any response model. Verified, not assumed."""
    raw = client.post(
        LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD}
    ).text

    assert "password_hash" not in raw
    assert TEST_PASSWORD not in raw


def test_inactive_user_cannot_sign_in(client, db, users):
    users["analyst"].is_active = False
    db.commit()

    response = client.post(
        LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD}
    )
    assert response.status_code in (401, 403)


# -----------------------------------------------------------------------------
# Lockout
# -----------------------------------------------------------------------------


def test_repeated_failures_lock_the_account(client, db, users):
    """
    Five failures set `locked_until`.

    Asserted against the stored row rather than the response, because the
    response deliberately does not say. Lockout is enforced on the user record
    and is independent of rate limiting — the suite runs with the limiter off,
    and lockout must still work.
    """
    for _ in range(5):
        client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"})

    db.expire_all()
    analyst = db.get(User, users["analyst"].id)

    assert analyst is not None
    assert analyst.failed_login_count >= 5
    assert analyst.locked_until is not None


def test_a_locked_account_still_answers_401_by_default(client, db, users):
    """
    Lockout is not disclosed.

    `AUTH_REVEAL_LOCKED_ACCOUNT` defaults to false, so a locked account and a
    wrong password look identical. That is the conservative default: telling an
    attacker they have triggered a lockout tells them the username was real.

    A deployment that prefers the clearer message can turn the setting on; this
    test pins what happens when nobody has thought about it.
    """
    for _ in range(6):
        client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"})

    # Correct password, locked account.
    response = client.post(
        LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD}
    )

    assert response.status_code == 401
    assert "lock" not in response.json()["message"].lower()


def test_lockout_can_be_disclosed_when_configured(client, db, users, override_settings):
    """With the setting on, a locked account says so with a 423."""
    override_settings(AUTH_REVEAL_LOCKED_ACCOUNT=True)

    for _ in range(6):
        client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"})

    response = client.post(
        LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD}
    )
    assert response.status_code == 423


def test_a_successful_login_clears_the_failure_count(client, db, users):
    for _ in range(2):
        client.post(LOGIN, json={"identifier": "analyst", "password": "wrong"})

    assert_ok(client.post(LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD}))

    db.expire_all()
    analyst = db.get(User, users["analyst"].id)

    assert analyst is not None
    assert analyst.failed_login_count == 0
    assert analyst.locked_until is None


# -----------------------------------------------------------------------------
# /auth/me
# -----------------------------------------------------------------------------


def test_me_requires_a_token(client, users):
    assert_error(client.get(ME), 401)


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer",
        "Bearer ",
        "Basic dXNlcjpwYXNz",
        "Bearer not-a-jwt",
        "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
    ],
)
def test_me_rejects_malformed_and_unsigned_tokens(client, users, header):
    """
    Including `alg: none`.

    The last case is a token with a valid JWT shape, an algorithm of "none"
    and an empty signature, claiming to be the admin. A library configured to
    accept the token's own algorithm choice would honour it. This is the single
    most-exploited JWT mistake, so it gets an explicit case rather than being
    folded into "malformed".
    """
    response = client.get(ME, headers={"Authorization": header} if header else {})
    assert response.status_code == 401


def test_me_returns_capability_flags(analyst_client):
    """
    `/auth/me` carries the capability map the interface gates on.

    The flags are booleans, computed from the role on the server. The frontend
    uses them to decide which controls to render; the endpoints enforce the
    same rules independently, which is why the map is described as a
    convenience and not as the authorisation boundary.
    """
    body = assert_ok(analyst_client.get(ME))

    capabilities = body["capabilities"]
    assert isinstance(capabilities, dict)
    assert capabilities
    assert all(isinstance(value, bool) for value in capabilities.values())

    assert capabilities["read_dashboard"] is True
    assert capabilities["manage_users"] is False


def test_capability_map_has_the_same_keys_for_every_role(role_clients):
    """
    Every role gets every key.

    A role whose map omits a flag instead of setting it false makes the
    frontend's `can()` depend on `undefined`, which is falsy and therefore
    works by accident until someone writes `!capabilities.x`. Same keys, every
    time.
    """
    maps = {
        role: assert_ok(client.get(ME))["capabilities"]
        for role, client in role_clients.items()
    }

    reference = set(next(iter(maps.values())))
    for role, capabilities in maps.items():
        assert set(capabilities) == reference, f"{role} has a different capability set"


def test_admin_has_user_management_and_an_analyst_does_not(role_clients):
    admin = assert_ok(role_clients["ADMIN"].get(ME))["capabilities"]
    analyst = assert_ok(role_clients["ANALYST"].get(ME))["capabilities"]

    assert admin["manage_users"] is True
    assert analyst["manage_users"] is False


def test_auditor_can_read_but_not_run(role_clients):
    """
    The auditor is read-and-export, not write.

    The role exists so that someone can review what investigators did without
    being able to do it themselves; a capability map that let an auditor run
    an analysis would defeat the separation.
    """
    auditor = assert_ok(role_clients["AUDITOR"].get(ME))["capabilities"]

    assert auditor["read_dashboard"] is True
    assert auditor["read_audit"] is True
    assert auditor["run_analysis"] is False
    assert auditor["create_case"] is False
    assert auditor["manage_users"] is False


# -----------------------------------------------------------------------------
# Password change
# -----------------------------------------------------------------------------


def test_password_change_requires_the_current_password(analyst_client):
    assert_error(
        analyst_client.post(
            CHANGE,
            json={"current_password": "not-the-password", "new_password": "An0ther-Good-One!"},
        ),
        401,
    )


def test_password_change_enforces_the_policy(analyst_client):
    """A new password below the configured minimum length is refused."""
    response = analyst_client.post(
        CHANGE,
        json={"current_password": TEST_PASSWORD, "new_password": "short"},
    )
    assert response.status_code == 422


def test_password_change_refuses_the_same_password(analyst_client):
    response = analyst_client.post(
        CHANGE,
        json={"current_password": TEST_PASSWORD, "new_password": TEST_PASSWORD},
    )
    assert response.status_code == 422


def test_password_change_succeeds_and_the_old_password_stops_working(
    client, analyst_client, users
):
    new_password = "Quite-Different-9!"

    assert_ok(
        analyst_client.post(
            CHANGE,
            json={"current_password": TEST_PASSWORD, "new_password": new_password},
        )
    )

    assert_error(
        client.post(LOGIN, json={"identifier": "analyst", "password": TEST_PASSWORD}),
        401,
    )
    assert_ok(client.post(LOGIN, json={"identifier": "analyst", "password": new_password}))


def test_password_change_requires_authentication(client, users):
    assert_error(
        client.post(
            CHANGE,
            json={"current_password": TEST_PASSWORD, "new_password": "An0ther-Good-One!"},
        ),
        401,
    )
