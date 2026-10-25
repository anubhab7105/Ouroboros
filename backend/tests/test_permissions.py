"""
The permission matrix.

One table, every protected endpoint, every role. This is the module that fails
when a new endpoint is added without a permission, or when a permission's
default roles change without anyone meaning to.

The table is written out by hand rather than derived from
`app/core/permissions.py`. That is the whole point: a table generated from the
registry would agree with the registry by construction and could never catch a
change to it. These rows are a second, independent statement of who may do
what, and a disagreement between the two is exactly the signal worth having.

Roles, from the registry:

- `READ_ROLES`         — all four. Reading is not privileged.
- `ANALYST_AND_ABOVE`  — analyst, senior, admin. Triage and case work.
- `SENIOR_AND_ADMIN`   — assignment, closing, reopening, review of inferences.
- `AUDITOR_AND_ADMIN`  — reading the audit log.
- `ADMIN_ONLY`         — users, config, ingestion, training, audit export.

The auditor is deliberately not an operator: it can read everything and act on
nothing, so that someone can review an investigation without being able to
change it. The admin is in `AUDITOR_AND_ADMIN` because somebody has to be able
to read the log when there is no auditor, not because administration and audit
should be one person — a deployment that cares about that separation gives the
admin account to nobody and uses named roles.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


ALL = ("ADMIN", "SENIOR_INVESTIGATOR", "ANALYST", "AUDITOR")
ANALYST_AND_ABOVE = ("ADMIN", "SENIOR_INVESTIGATOR", "ANALYST")
SENIOR_AND_ADMIN = ("ADMIN", "SENIOR_INVESTIGATOR")
AUDITOR_AND_ADMIN = ("ADMIN", "AUDITOR")
ADMIN_ONLY = ("ADMIN",)


#: (method, path, roles allowed).
#:
#: Paths use ids that do not exist. That is intentional and is what makes the
#: table cheap: the permission dependency runs before the handler, so an
#: allowed role gets 404 or 422 and a denied role gets 403. The assertion is
#: "was this a permission failure", never "did this succeed", which keeps the
#: table free of fixture setup for sixty-odd endpoints.
MATRIX: list[tuple[str, str, tuple[str, ...]]] = [
    # ----------------------------------------------------------------- reads
    ("GET", "/api/v1/dashboard/overview", ALL),
    ("GET", "/api/v1/dashboard/metrics", ALL),
    ("GET", "/api/v1/dashboard/queues", ALL),
    ("GET", "/api/v1/dashboard/trends", ALL),
    ("GET", "/api/v1/accounts", ALL),
    ("GET", "/api/v1/accounts/nope", ALL),
    ("GET", "/api/v1/accounts/nope/summary", ALL),
    ("GET", "/api/v1/accounts/nope/transactions", ALL),
    ("GET", "/api/v1/accounts/nope/assessment", ALL),
    ("GET", "/api/v1/accounts/nope/alerts", ALL),
    ("GET", "/api/v1/accounts/nope/entities", ALL),
    ("GET", "/api/v1/transactions", ALL),
    ("GET", "/api/v1/transactions/nope", ALL),
    ("GET", "/api/v1/alerts", ALL),
    ("GET", "/api/v1/alerts/nope", ALL),
    ("GET", "/api/v1/alerts/nope/evidence", ALL),
    ("GET", "/api/v1/alerts/nope/history", ALL),
    ("GET", "/api/v1/cases", ALL),
    ("GET", "/api/v1/cases/nope", ALL),
    ("GET", "/api/v1/cases/nope/notes", ALL),
    ("GET", "/api/v1/cases/nope/evidence", ALL),
    ("GET", "/api/v1/cases/nope/events", ALL),
    ("GET", "/api/v1/cases/nope/export", ALL),
    ("GET", "/api/v1/complaints", ALL),
    ("GET", "/api/v1/complaints/stats", ALL),
    ("GET", "/api/v1/complaints/nope", ALL),
    ("GET", "/api/v1/complaints/nope/correlations", ALL),
    ("GET", "/api/v1/entities", ALL),
    ("GET", "/api/v1/entities/nope", ALL),
    ("GET", "/api/v1/graph/status", ALL),
    ("GET", "/api/v1/graph/subgraph", ALL),
    ("GET", "/api/v1/graph/paths", ALL),
    ("GET", "/api/v1/graph/shared-entities", ALL),
    ("GET", "/api/v1/graph/money-trails", ALL),
    ("GET", "/api/v1/model/current", ALL),
    ("GET", "/api/v1/model/limitations", ALL),
    ("GET", "/api/v1/model/feature-schema", ALL),
    ("GET", "/api/v1/model/versions", ALL),
    ("GET", "/api/v1/reports/limitations", ALL),
    ("GET", "/api/v1/reports/cases/nope/preview", ALL),
    ("GET", "/api/v1/reports/cases/nope/evidence-index", ALL),
    # ------------------------------------------------------- analysis (write)
    ("GET", "/api/v1/analysis/status", ANALYST_AND_ABOVE),
    ("GET", "/api/v1/analysis/runs", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/analysis/runs", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/analysis/runs/nope/cancel", ANALYST_AND_ABOVE),
    # --------------------------------------------------------- alert workflow
    ("POST", "/api/v1/alerts/nope/acknowledge", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/alerts/nope/close", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/alerts/nope/reopen", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/alerts/nope/evidence", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/alerts/nope/case", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/alerts/nope/assign", SENIOR_AND_ADMIN),
    ("POST", "/api/v1/alerts/nope/escalate", SENIOR_AND_ADMIN),
    # ---------------------------------------------------------- case workflow
    ("POST", "/api/v1/cases", ANALYST_AND_ABOVE),
    ("PATCH", "/api/v1/cases/nope", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/cases/nope/start", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/cases/nope/escalate", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/cases/nope/notes", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/cases/nope/evidence", ANALYST_AND_ABOVE),
    ("POST", "/api/v1/cases/nope/assign", SENIOR_AND_ADMIN),
    ("POST", "/api/v1/cases/nope/close", SENIOR_AND_ADMIN),
    ("POST", "/api/v1/cases/nope/reopen", SENIOR_AND_ADMIN),
    ("POST", "/api/v1/cases/nope/evidence/nope/remove", SENIOR_AND_ADMIN),
    # --------------------------------------------------------------- reports
    ("POST", "/api/v1/reports/cases/nope/generate", ANALYST_AND_ABOVE),
    # ----------------------------------------------------- senior-only review
    (
        "POST",
        "/api/v1/complaints/nope/correlations/nope/review-state",
        SENIOR_AND_ADMIN,
    ),
    (
        "PATCH",
        "/api/v1/entities/nope/links/nope/verification-state",
        SENIOR_AND_ADMIN,
    ),
    # ----------------------------------------------------------------- audit
    ("GET", "/api/v1/audit", AUDITOR_AND_ADMIN),
    ("GET", "/api/v1/audit/stats", AUDITOR_AND_ADMIN),
    ("GET", "/api/v1/audit/nope", AUDITOR_AND_ADMIN),
    ("GET", "/api/v1/cases/nope/audit", AUDITOR_AND_ADMIN),
    ("GET", "/api/v1/audit/export", ADMIN_ONLY),
    # ------------------------------------------------------------ admin only
    ("GET", "/api/v1/users", ADMIN_ONLY),
    ("POST", "/api/v1/users", ADMIN_ONLY),
    ("GET", "/api/v1/users/nope", ADMIN_ONLY),
    ("PATCH", "/api/v1/users/nope", ADMIN_ONLY),
    ("POST", "/api/v1/users/nope/deactivate", ADMIN_ONLY),
    ("POST", "/api/v1/users/nope/reactivate", ADMIN_ONLY),
    ("POST", "/api/v1/users/nope/unlock", ADMIN_ONLY),
    ("POST", "/api/v1/users/nope/reset-password", ADMIN_ONLY),
    ("GET", "/api/v1/ingestion/status", ADMIN_ONLY),
    ("POST", "/api/v1/ingestion/accounts", ADMIN_ONLY),
    ("POST", "/api/v1/ingestion/transactions", ADMIN_ONLY),
    ("POST", "/api/v1/ingestion/complaints", ADMIN_ONLY),
    ("POST", "/api/v1/ingestion/entities", ADMIN_ONLY),
    ("POST", "/api/v1/ingestion/entity-links", ADMIN_ONLY),
]


def _ids():
    return [
        f"{role}-{method}-{path}"
        for method, path, allowed in MATRIX
        for role in ALL
    ]


def _cases():
    return [
        (method, path, role, role in allowed)
        for method, path, allowed in MATRIX
        for role in ALL
    ]


@pytest.mark.parametrize("method,path,role,allowed", _cases(), ids=_ids())
def test_permission_matrix(role_clients, method, path, role, allowed):
    """
    A denied role gets 403; an allowed role gets anything but 403.

    The negative form of the allowed case is deliberate. These paths point at
    ids that do not exist, so an allowed role's request fails — with 404
    because the resource is missing, or 422 because a required body was not
    sent. Both are fine. What must not happen is a 403, because that would
    mean the role was refused.
    """
    client = role_clients[role]
    response = client.raw.request(
        method,
        path,
        headers={"Authorization": f"Bearer {client.token}"},
        json={} if method in {"POST", "PATCH", "PUT"} else None,
    )

    if allowed:
        assert response.status_code != 403, (
            f"{role} should be allowed {method} {path}, got 403: {response.text[:200]}"
        )
    else:
        assert response.status_code == 403, (
            f"{role} should be denied {method} {path}, got {response.status_code}"
        )


@pytest.mark.parametrize(
    "method,path",
    sorted({(method, path) for method, path, _ in MATRIX}),
)
def test_every_protected_endpoint_requires_a_token(client, users, method, path):
    """
    No endpoint in the matrix answers without authentication.

    Run separately from the matrix because the failure mode is different: a
    missing permission dependency is a privilege bug, while a missing
    authentication dependency is an open door. This catches the second even
    when the first is correct.
    """
    response = client.request(
        method, path, json={} if method in {"POST", "PATCH", "PUT"} else None
    )

    assert response.status_code == 401, (
        f"{method} {path} answered {response.status_code} without a token"
    )


def test_an_inactive_user_is_refused_everywhere(client, db, users):
    """
    Deactivation takes effect on the next request, not at the next login.

    A token issued before deactivation is still cryptographically valid, so
    the check has to be on the user record at request time. If it were not,
    deactivating a compromised account would leave it working until the token
    expired — which is the one moment the deactivation needed to work.
    """
    login = client.post(
        "/api/v1/auth/login",
        json={"identifier": "analyst", "password": "Test-Passw0rd!2026"},
    )
    token = login.json()["access_token"]

    assert client.get(
        "/api/v1/accounts", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 200

    users["analyst"].is_active = False
    db.commit()

    response = client.get(
        "/api/v1/accounts", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code in (401, 403)


def test_denial_explains_itself_without_naming_internals(role_clients):
    """
    A 403 says what was needed, not how it was decided.

    The message has to be actionable — "you need a senior role for this" lets
    someone ask the right person — without leaking the permission registry,
    the setting that overrode it, or the names of other roles. The body is
    checked for absences as well as presences.
    """
    response = role_clients["ANALYST"].get("/api/v1/users")

    assert response.status_code == 403

    body = response.json()
    assert body["code"]
    assert body["message"]

    raw = response.text.lower()
    assert "traceback" not in raw
    assert "settings" not in raw
    assert "secret" not in raw
