#!/usr/bin/env python3
"""
Create the four local development users, one per role.

    python scripts/create_dev_users.py
    python scripts/create_dev_users.py --reset-passwords

Creates `admin`, `senior`, `analyst` and `auditor`. Existing users are left
alone unless `--reset-passwords` is passed, so running this twice is safe.

Why four and not one
--------------------

Because the permission matrix is the product, not an afterthought, and a
single admin account hides every mistake in it. An analyst cannot assign a
case or close one; an auditor can read everything and change nothing. Those
are the controls, and the only way to see them working — or to notice when a
new endpoint was added without one — is to have all four accounts and use
them.

The auditor in particular: it exists so somebody can review an investigation
without being able to alter it. A deployment where the reviewer has an admin
account has that control on paper only.

Passwords
---------

Read from the environment. There is no default, and no password is printed:

    MULEGUARD_DEV_PASSWORD      one password for all four (dev only)
    MULEGUARD_ADMIN_PASSWORD    per-role override
    MULEGUARD_SENIOR_PASSWORD
    MULEGUARD_ANALYST_PASSWORD
    MULEGUARD_AUDITOR_PASSWORD

One shared password across four accounts is acceptable on a laptop and
nowhere else. It is also why this script refuses to run when the environment
looks like a deployed one: see `_refuse_in_production`.

This writes directly to the database rather than going through the API,
because creating the first admin through an admin-only endpoint is a
chicken-and-egg problem. It is the one tool in `scripts/` that does.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND = REPO_ROOT / "backend"

#: username -> (role name, what the account is for)
DEV_USERS = {
    "admin": (
        "ADMIN",
        "User management, configuration, ingestion, audit export, model training.",
    ),
    "senior": (
        "SENIOR_INVESTIGATOR",
        "Assignment, case closure, reopening, review of inferred correlations.",
    ),
    "analyst": (
        "ANALYST",
        "Triage and case work. Cannot assign or close -- that is the control.",
    ),
    "auditor": (
        "AUDITOR",
        "Reads everything, changes nothing. Reviews without being able to alter.",
    ),
}

#: Environment names this script will not run against.
PRODUCTION_LIKE = {"production", "prod", "staging", "stage", "uat", "preprod"}


def _refuse_in_production(settings: object) -> None:
    """
    Stop before creating a known-username account in a deployed environment.

    Four accounts called admin, senior, analyst and auditor, sharing one
    password from an environment variable, is a reasonable thing on a laptop
    and an open door anywhere else. The check is on the environment name
    rather than on a flag, because a flag is the thing somebody passes by
    accident at two in the morning.
    """
    environment = str(getattr(settings, "BACKEND_ENV", "local") or "local").lower()

    if environment in PRODUCTION_LIKE:
        raise SystemExit(
            f"Refusing to run: BACKEND_ENV is {environment!r}.\n"
            "This script creates accounts with known usernames and a password "
            "from the environment. Create real accounts through "
            "POST /api/v1/users instead."
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create the four local development users, one per role.",
    )
    parser.add_argument(
        "--reset-passwords",
        action="store_true",
        help="also reset the password of a user that already exists",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print what would be created and exit",
    )
    args = parser.parse_args()

    if args.list:
        print("development users:\n")
        for username, (role, purpose) in DEV_USERS.items():
            print(f"  {username:10} {role:20} {purpose}")
        return 0

    sys.path.insert(0, str(BACKEND))

    try:
        from app.auth.passwords import hash_password
        from app.core.config import get_settings
        from app.db import session_scope
        from app.models import User, UserRole
    except ImportError as exc:
        raise SystemExit(
            f"Could not import the backend from {BACKEND}: {exc}\n"
            "Install the requirements first:\n"
            "  pip install -r backend/requirements.txt"
        ) from exc

    settings = get_settings()
    _refuse_in_production(settings)

    shared = os.environ.get("MULEGUARD_DEV_PASSWORD")
    created: list[str] = []
    updated: list[str] = []
    unchanged: list[str] = []
    missing_password: list[str] = []

    with session_scope() as session:
        for username, (role_name, purpose) in DEV_USERS.items():
            password = os.environ.get(
                f"MULEGUARD_{username.upper()}_PASSWORD",
                shared,
            )

            existing = (
                session.query(User).filter(User.username == username).one_or_none()
            )

            if existing is not None:
                if not args.reset_passwords:
                    unchanged.append(username)
                    continue

                if not password:
                    missing_password.append(username)
                    continue

                existing.password_hash = hash_password(password, settings)
                existing.must_change_password = False
                existing.failed_login_count = 0
                existing.is_active = True
                updated.append(username)
                continue

            if not password:
                missing_password.append(username)
                continue

            role = getattr(UserRole, role_name, None)

            if role is None:
                raise SystemExit(
                    f"UserRole has no member {role_name!r}. The role names in "
                    "this script have drifted from app/models.py."
                )

            session.add(
                User(
                    id=f"usr_dev_{username}",
                    username=username,
                    email=f"{username}@muleguard.local",
                    full_name=username.replace("_", " ").title(),
                    role=role,
                    password_hash=hash_password(password, settings),
                    is_active=True,
                    must_change_password=False,
                    failed_login_count=0,
                )
            )
            created.append(username)

    for label, names in (
        ("created", created),
        ("password reset", updated),
        ("already existed", unchanged),
    ):
        if names:
            print(f"{label}: {', '.join(sorted(names))}")

    if missing_password:
        print(
            "\nno password available for: "
            + ", ".join(sorted(missing_password))
            + "\nSet MULEGUARD_DEV_PASSWORD, or a per-role variable such as "
            "MULEGUARD_ANALYST_PASSWORD."
        )
        return 1

    if unchanged and not args.reset_passwords:
        print(
            "\nExisting users were left alone. Pass --reset-passwords to "
            "change their passwords."
        )

    print("\nNo passwords are printed by this script, by design.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
