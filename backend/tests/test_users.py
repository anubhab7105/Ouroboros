"""
User administration.

Every endpoint here is admin-only, which `test_permissions.py` covers as a
table. What this module tests is the behaviour an administrator actually needs
to be protected from: locking themselves out, removing the last account that
can let anyone back in, and creating a duplicate that makes the login
identifier ambiguous.
"""

from __future__ import annotations

import pytest

from app.models import User, UserRole

from tests.conftest import TEST_PASSWORD
from tests.utils import assert_error, assert_ok, assert_paginated, ids_of, unique_id

pytestmark = pytest.mark.api


USERS = "/api/v1/users"

GOOD_PASSWORD = "Fresh-" + "Passw0rd!77"


def _new_user_payload(**overrides):
    username = overrides.pop("username", unique_id("newuser").lower().replace("-", "")[:40])
    payload = {
        "username": username,
        "email": f"{username}@muleguard.test",
        "password": GOOD_PASSWORD,
        "full_name": "New User",
        "role": "ANALYST",
    }
    payload.update(overrides)
    return payload


# -----------------------------------------------------------------------------
# Reading
# -----------------------------------------------------------------------------


def test_list_users(admin_client, users):
    body = assert_paginated(assert_ok(admin_client.get(USERS)))

    usernames = {row["username"] for row in body["items"]}
    assert {"admin", "analyst", "senior_investigator", "auditor"} <= usernames


def test_user_list_never_includes_the_hash(admin_client, users):
    """
    `UserResponse` has no `password_hash` field, and this proves it.

    The model is written by hand rather than generated from the ORM, so the
    omission is deliberate — but "deliberate" is a property of the code as it
    stands today, and the whole point of the assertion is to notice when
    someone adds `model_config = ConfigDict(from_attributes=True)` and a
    `**row.__dict__`.
    """
    raw = admin_client.get(USERS).text

    assert "password_hash" not in raw
    assert TEST_PASSWORD not in raw
    assert "$2b$" not in raw
    assert "$argon2" not in raw


def test_filter_users_by_role(admin_client, users):
    body = assert_ok(admin_client.get(USERS, params={"role": "AUDITOR"}))

    assert body["items"]
    assert all(row["role"] == "AUDITOR" for row in body["items"])


def test_filter_users_by_active_flag(admin_client, db, users):
    users["auditor"].is_active = False
    db.commit()

    inactive = assert_ok(admin_client.get(USERS, params={"is_active": False}))
    assert "auditor" in {row["username"] for row in inactive["items"]}

    active = assert_ok(admin_client.get(USERS, params={"is_active": True}))
    assert "auditor" not in {row["username"] for row in active["items"]}


def test_get_one_user(admin_client, users):
    body = assert_ok(admin_client.get(f"{USERS}/{users['analyst'].id}"))

    assert body["username"] == "analyst"
    assert body["role"] == "ANALYST"
    assert body["role_display_name"]


def test_get_unknown_user_is_404(admin_client, users):
    assert_error(admin_client.get(f"{USERS}/does-not-exist"), 404)


# -----------------------------------------------------------------------------
# Creating
# -----------------------------------------------------------------------------


def test_create_user(admin_client, users):
    payload = _new_user_payload()
    body = assert_ok(admin_client.post(USERS, json=payload), 201)

    assert body["username"] == payload["username"]
    assert body["role"] == "ANALYST"
    assert body["is_active"] is True
    assert "password" not in body


def test_created_user_can_sign_in(admin_client, client, users):
    payload = _new_user_payload()
    created = assert_ok(admin_client.post(USERS, json=payload), 201)

    login = client.post(
        "/api/v1/auth/login",
        json={"identifier": payload["username"], "password": payload["password"]},
    )

    # A user created with `must_change_password` must still be able to sign in;
    # the flag changes what the interface does next, not whether the
    # credentials work.
    assert login.status_code == 200
    assert login.json()["user"]["id"] == created["id"]


def test_create_rejects_a_duplicate_username(admin_client, users):
    assert_error(admin_client.post(USERS, json=_new_user_payload(username="analyst")), 409)


def test_create_rejects_a_duplicate_email(admin_client, users):
    """
    Email uniqueness matters as much as username uniqueness.

    `/auth/login` accepts either as the identifier, so two users sharing an
    email make one of them unreachable — and which one wins depends on row
    order, which is the worst kind of bug to debug.
    """
    assert_error(
        admin_client.post(USERS, json=_new_user_payload(email="analyst@muleguard.local")),
        409,
    )


def test_create_enforces_the_password_policy(admin_client, users):
    assert_error(admin_client.post(USERS, json=_new_user_payload(password="short")), 422)


def test_create_rejects_an_invalid_email(admin_client, users):
    assert_error(admin_client.post(USERS, json=_new_user_payload(email="not-an-email")), 422)


def test_create_rejects_an_unknown_role(admin_client, users):
    assert_error(admin_client.post(USERS, json=_new_user_payload(role="SUPERUSER")), 422)


# -----------------------------------------------------------------------------
# Updating
# -----------------------------------------------------------------------------


def test_patch_updates_only_what_was_sent(admin_client, users):
    before = assert_ok(admin_client.get(f"{USERS}/{users['analyst'].id}"))

    after = assert_ok(
        admin_client.patch(f"{USERS}/{users['analyst'].id}", json={"full_name": "Renamed"})
    )

    assert after["full_name"] == "Renamed"
    assert after["email"] == before["email"]
    assert after["role"] == before["role"]


def test_patch_with_an_empty_body_is_rejected(admin_client, users):
    """
    An empty PATCH is a client bug, not a no-op.

    Returning 200 for it hides a form that failed to collect anything, and the
    user sees a success message for a change that did not happen.
    """
    assert_error(admin_client.patch(f"{USERS}/{users['analyst'].id}", json={}), 422)


def test_patch_can_change_a_role(admin_client, users):
    body = assert_ok(
        admin_client.patch(
            f"{USERS}/{users['analyst'].id}", json={"role": "SENIOR_INVESTIGATOR"}
        )
    )
    assert body["role"] == "SENIOR_INVESTIGATOR"


def test_admin_cannot_deactivate_themselves_via_patch(admin_client, users):
    """
    The lockout guard, through the update path.

    Both routes to deactivation are guarded, because closing one and leaving
    the other open is the same bug with a longer reproduction.
    """
    response = admin_client.patch(
        f"{USERS}/{users['admin'].id}", json={"is_active": False}
    )
    assert response.status_code in (403, 409)


# -----------------------------------------------------------------------------
# Lifecycle
# -----------------------------------------------------------------------------


def test_deactivate_and_reactivate(admin_client, users):
    deactivated = assert_ok(admin_client.post(f"{USERS}/{users['analyst'].id}/deactivate"))
    assert deactivated["is_active"] is False

    reactivated = assert_ok(admin_client.post(f"{USERS}/{users['analyst'].id}/reactivate"))
    assert reactivated["is_active"] is True


def test_admin_cannot_deactivate_themselves(admin_client, users):
    response = admin_client.post(f"{USERS}/{users['admin'].id}/deactivate")
    assert response.status_code in (403, 409)


def test_cannot_remove_the_last_active_admin(admin_client, db, users, make):
    """
    The guard that stops the platform becoming unadministrable.

    A second admin is created and the original demotes it, which is allowed;
    then the original tries to demote *itself*, leaving nobody. There is no
    recovery from that state short of a database edit, so it is refused with a
    409 and an audit record.
    """
    second = make.user(username="admin_two", role=UserRole.ADMIN)
    db.commit()

    assert_ok(admin_client.patch(f"{USERS}/{second.id}", json={"role": "ANALYST"}))

    response = admin_client.patch(f"{USERS}/{users['admin'].id}", json={"role": "ANALYST"})
    assert response.status_code in (403, 409)


def test_unlock_clears_a_lockout(admin_client, client, db, users):
    for _ in range(6):
        client.post(
            "/api/v1/auth/login", json={"identifier": "analyst", "password": "wrong"}
        )

    db.expire_all()
    assert db.get(User, users["analyst"].id).locked_until is not None

    body = assert_ok(admin_client.post(f"{USERS}/{users['analyst'].id}/unlock"))

    assert body["locked_until"] is None
    assert body["failed_login_count"] == 0

    assert_ok(
        client.post(
            "/api/v1/auth/login",
            json={"identifier": "analyst", "password": TEST_PASSWORD},
        )
    )


def test_reset_password(admin_client, client, users):
    assert_ok(
        admin_client.post(
            f"{USERS}/{users['analyst'].id}/reset-password",
            json={"new_password": GOOD_PASSWORD, "force_change": True},
        )
    )

    assert_error(
        client.post(
            "/api/v1/auth/login",
            json={"identifier": "analyst", "password": TEST_PASSWORD},
        ),
        401,
    )

    body = assert_ok(
        client.post(
            "/api/v1/auth/login",
            json={"identifier": "analyst", "password": GOOD_PASSWORD},
        )
    )
    assert body["user"]["must_change_password"] is True


def test_reset_password_enforces_the_policy(admin_client, users):
    assert_error(
        admin_client.post(
            f"{USERS}/{users['analyst'].id}/reset-password",
            json={"new_password": "weak"},
        ),
        422,
    )


def test_reset_password_response_does_not_echo_the_password(admin_client, users):
    response = admin_client.post(
        f"{USERS}/{users['analyst'].id}/reset-password",
        json={"new_password": GOOD_PASSWORD},
    )

    assert GOOD_PASSWORD not in response.text


# -----------------------------------------------------------------------------
# Pagination
# -----------------------------------------------------------------------------


def test_user_list_paginates(admin_client, db, make, users):
    for index in range(8):
        make.user(username=f"bulk_{index}")
    db.commit()

    first = assert_paginated(assert_ok(admin_client.get(USERS, params={"page_size": 5})))
    second = assert_paginated(
        assert_ok(admin_client.get(USERS, params={"page_size": 5, "page": 2}))
    )

    assert len(first["items"]) == 5
    assert first["total"] >= 12
    assert first["total_pages"] >= 3

    assert not (set(ids_of(first["items"])) & set(ids_of(second["items"])))
