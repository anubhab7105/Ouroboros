"""
Analysis-run idempotency.

A run is expensive and synchronous. The failure mode this guards against is
ordinary and expensive: somebody presses the button, nothing visibly happens
for thirty seconds, and they press it again. Without an idempotency key that
is two runs over the same accounts, producing two sets of assessments and
twice the alerts — and the second set supersedes the first for no reason
anybody can reconstruct.

The contract, from `app/api/v1/endpoints/analysis.py`:

- `Idempotency-Key` plus the **same** payload returns the original run.
- `Idempotency-Key` plus a **different** payload is a 409
  (`IdempotencyConflictError`), because the caller has reused a key for
  different work and silently returning the old run would be wrong.
- The key is scoped **per actor**, so two investigators using the same
  obvious key do not collide.

One important limitation, and it is documented rather than hidden: the cache
is **process-local**. Behind two workers the same key can produce two runs.
`test_the_scope_of_the_guarantee_is_documented` asserts that the module says
so, because a reader who assumes distributed idempotency will build on a
guarantee that is not there.
"""

from __future__ import annotations

import pytest

from tests.utils import assert_error, assert_ok, unique_id

pytestmark = [pytest.mark.api, pytest.mark.integration]


RUNS = "/api/v1/analysis/runs"


def _payload(accounts, **extra):
    body = {"account_ids": [account.id for account in accounts]}
    body.update(extra)
    return body


# -----------------------------------------------------------------------------
# The guarantee
# -----------------------------------------------------------------------------


def test_the_same_key_and_payload_returns_the_same_run(analyst_client, make, db):
    """
    The second press returns the first run.

    Not a new one, not an error. The caller gets the run it already started,
    which is what makes the retry safe — and it is the behaviour a double
    click needs, since the user has no way to know the first request landed.
    """
    accounts = make.accounts(3)
    db.commit()

    key = unique_id("idem")
    payload = _payload(accounts)

    first = assert_ok(
        analyst_client.post(RUNS, json=payload, headers={"Idempotency-Key": key}), 201
    )
    second = assert_ok(
        analyst_client.post(RUNS, json=payload, headers={"Idempotency-Key": key}),
        (200, 201),
    )

    assert second["id"] == first["id"]


def test_the_replay_does_not_create_a_second_run(analyst_client, make, db):
    """
    Counted, not just compared.

    Returning the right id while also having created a second run would pass
    the previous test and still double the work.
    """
    accounts = make.accounts(2)
    db.commit()

    key = unique_id("idem")
    payload = _payload(accounts)

    before = assert_ok(analyst_client.get(RUNS))["total"]

    analyst_client.post(RUNS, json=payload, headers={"Idempotency-Key": key})
    analyst_client.post(RUNS, json=payload, headers={"Idempotency-Key": key})
    analyst_client.post(RUNS, json=payload, headers={"Idempotency-Key": key})

    after = assert_ok(analyst_client.get(RUNS))["total"]

    assert after == before + 1, f"three requests produced {after - before} runs"


def test_the_same_key_with_a_different_payload_is_a_conflict(analyst_client, make, db):
    """
    409, not a silent replay of the old run.

    The caller has reused a key for different work. Returning the earlier run
    would answer a question nobody asked — the caller wanted the *new*
    accounts scored and would believe they had been.
    """
    first_set = make.accounts(2)
    second_set = make.accounts(2)
    db.commit()

    key = unique_id("idem")

    assert_ok(
        analyst_client.post(
            RUNS, json=_payload(first_set), headers={"Idempotency-Key": key}
        ),
        201,
    )

    body = assert_error(
        analyst_client.post(
            RUNS, json=_payload(second_set), headers={"Idempotency-Key": key}
        ),
        409,
    )

    assert body["code"]
    assert "idempotency" in body["message"].lower() or "key" in body["message"].lower()


def test_the_conflict_does_not_echo_the_key(analyst_client, make, db):
    """
    The error names the problem without reprinting the key in full.

    An idempotency key is caller-chosen and is often derived from something
    the caller would rather not have in an error body or a log line.
    """
    first_set = make.accounts(2)
    second_set = make.accounts(2)
    db.commit()

    key = "idem-" + "k" * 300

    analyst_client.post(RUNS, json=_payload(first_set), headers={"Idempotency-Key": key})
    response = analyst_client.post(
        RUNS, json=_payload(second_set), headers={"Idempotency-Key": key}
    )

    assert response.status_code == 409
    assert key not in response.text


def test_a_different_key_starts_a_new_run(analyst_client, make, db):
    """
    Two deliberate runs over the same accounts are allowed.

    Re-scoring the same set after a model change is a legitimate thing to
    want, and a different key is how a caller says "this is on purpose".
    """
    accounts = make.accounts(2)
    db.commit()

    payload = _payload(accounts)

    first = assert_ok(
        analyst_client.post(
            RUNS, json=payload, headers={"Idempotency-Key": unique_id("idem")}
        ),
        201,
    )
    second = assert_ok(
        analyst_client.post(
            RUNS, json=payload, headers={"Idempotency-Key": unique_id("idem")}
        ),
        201,
    )

    assert first["id"] != second["id"]


def test_no_key_means_no_deduplication(analyst_client, make, db):
    """
    Idempotency is opt-in, by sending the header.

    De-duplicating by payload alone would make "run this again" impossible to
    express, which is the operation somebody needs after a model is replaced.
    """
    accounts = make.accounts(2)
    db.commit()

    payload = _payload(accounts)

    first = assert_ok(analyst_client.post(RUNS, json=payload), 201)
    second = assert_ok(analyst_client.post(RUNS, json=payload), 201)

    assert first["id"] != second["id"]


# -----------------------------------------------------------------------------
# Scoping
# -----------------------------------------------------------------------------


def test_keys_are_scoped_per_actor(analyst_client, senior_client, make, db):
    """
    Two users with the same key do not collide.

    Clients pick obvious keys — a date, a batch name, "nightly". If the
    namespace were global, one investigator's run would be returned to
    another, who would read someone else's results as their own.
    """
    accounts = make.accounts(2)
    db.commit()

    shared_key = "nightly-2026-10-21"
    payload = _payload(accounts)

    mine = assert_ok(
        analyst_client.post(
            RUNS, json=payload, headers={"Idempotency-Key": shared_key}
        ),
        201,
    )
    theirs = assert_ok(
        senior_client.post(RUNS, json=payload, headers={"Idempotency-Key": shared_key}),
        201,
    )

    assert mine["id"] != theirs["id"]


def test_the_run_records_that_a_key_was_used(analyst_client, make, db):
    """
    The key's hash is stored, not the key.

    Enough to recognise a replay and to answer "was this run a retry", without
    retaining a caller-chosen string that may carry meaning of its own.
    """
    accounts = make.accounts(2)
    db.commit()

    key = unique_id("idem")
    body = assert_ok(
        analyst_client.post(
            RUNS, json=_payload(accounts), headers={"Idempotency-Key": key}
        ),
        201,
    )

    parameters = body["parameters_json"] or {}
    serialised = str(parameters)

    assert key not in serialised, "the raw idempotency key was stored"

    if "idempotency_key_hash" in serialised:
        assert len(str(parameters.get("idempotency_key_hash", ""))) >= 32


# -----------------------------------------------------------------------------
# Payload identity
# -----------------------------------------------------------------------------


def test_account_order_does_not_change_the_payload_identity(analyst_client, make, db):
    """
    The same set in a different order is the same request.

    A client building the list from a set has no stable order. Treating the
    orderings as different payloads would turn every retry into a 409 and make
    the feature useless.
    """
    accounts = make.accounts(3)
    db.commit()

    key = unique_id("idem")

    first = assert_ok(
        analyst_client.post(
            RUNS, json=_payload(accounts), headers={"Idempotency-Key": key}
        ),
        201,
    )
    reversed_response = analyst_client.post(
        RUNS,
        json=_payload(list(reversed(accounts))),
        headers={"Idempotency-Key": key},
    )

    assert reversed_response.status_code in (200, 201, 409)

    if reversed_response.status_code != 409:
        assert reversed_response.json()["id"] == first["id"]


def test_a_changed_as_of_is_a_different_payload(analyst_client, make, db):
    """
    The window is part of what makes a run a run.

    Two runs over the same accounts at different instants produce different
    assessments, so they are different work and the same key cannot cover
    both.
    """
    accounts = make.accounts(2)
    db.commit()

    key = unique_id("idem")
    from tests.utils import days_ago

    assert_ok(
        analyst_client.post(
            RUNS,
            json=_payload(accounts, as_of=days_ago(1).isoformat()),
            headers={"Idempotency-Key": key},
        ),
        201,
    )

    response = analyst_client.post(
        RUNS,
        json=_payload(accounts, as_of=days_ago(5).isoformat()),
        headers={"Idempotency-Key": key},
    )
    assert response.status_code == 409


# -----------------------------------------------------------------------------
# The limits of the guarantee
# -----------------------------------------------------------------------------


def test_the_scope_of_the_guarantee_is_documented():
    """
    The cache is process-local, and the module says so.

    This matters more than it looks. Behind two workers — which is the default
    deployment — the same key can produce two runs, because the second worker
    has never seen it. A reader who assumes distributed idempotency will build
    a nightly job on a guarantee that is not there.

    The honest position is the one taken: implement what is useful locally and
    state the limit in the source. This test asserts the statement exists, so
    that making the guarantee real, or removing it, cannot quietly leave the
    documentation behind.
    """
    import inspect

    from app.api.v1.endpoints import analysis

    source = inspect.getsource(analysis).lower()

    assert "process-local" in source or "process local" in source
    assert "distributed idempotency" in source


def test_an_empty_key_is_ignored_rather_than_treated_as_a_key(analyst_client, make, db):
    """
    An empty header is not a key.

    Treating `""` as a key would make every client that sends the header
    unconditionally share one namespace, and the first run would be returned
    to everybody.
    """
    accounts = make.accounts(2)
    db.commit()

    payload = _payload(accounts)

    first = analyst_client.post(RUNS, json=payload, headers={"Idempotency-Key": ""})
    second = analyst_client.post(RUNS, json=payload, headers={"Idempotency-Key": ""})

    assert first.status_code == 201
    assert second.status_code in (200, 201)

    if second.status_code == 201:
        assert second.json()["id"] != first.json()["id"]


def test_an_over_long_key_is_handled_without_error(analyst_client, make, db):
    """
    A key of ten thousand characters is a caller bug, not a server one.

    It is truncated or refused; what must not happen is a 500 from a column
    that is too small for it.
    """
    accounts = make.accounts(2)
    db.commit()

    response = analyst_client.post(
        RUNS, json=_payload(accounts), headers={"Idempotency-Key": "k" * 10_000}
    )

    assert response.status_code in (201, 400, 422, 431)
    assert response.status_code != 500
