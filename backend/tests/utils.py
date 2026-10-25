"""
Test helpers that carry no fixtures.

Everything here is a plain function so it can be used from a fixture, from a
test, or from another helper without pytest being involved.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Iterable, Mapping, Optional


# -----------------------------------------------------------------------------
# Time
# -----------------------------------------------------------------------------


def utcnow() -> datetime:
    """
    Timezone-aware now, in UTC.

    The application is UTC end to end and several comparisons are strict, so a
    naive datetime in a test is a bug waiting to surface as a timezone error on
    somebody else's machine.
    """
    return datetime.now(timezone.utc)


def days_ago(days: float) -> datetime:
    return utcnow() - timedelta(days=days)


def hours_ago(hours: float) -> datetime:
    return utcnow() - timedelta(hours=hours)


def minutes_ago(minutes: float) -> datetime:
    return utcnow() - timedelta(minutes=minutes)


def iso(value: datetime) -> str:
    """Serialise for a query parameter or a JSON body."""
    return value.astimezone(timezone.utc).isoformat()


# -----------------------------------------------------------------------------
# Identifiers
# -----------------------------------------------------------------------------


def unique_id(prefix: str) -> str:
    """
    A collision-free identifier.

    Tests share one database within a module, and several of them insert
    accounts with overlapping intent ("a dormant account"). Deriving ids from
    a uuid rather than a counter means a test can be run alone, re-run, or run
    in a different order without tripping a unique constraint.
    """
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def money(value: str | int | float) -> Decimal:
    """
    A Decimal amount.

    Always via `str`: `Decimal(0.1)` is 0.1000000000000000055511151231257827,
    and a test that compares sums would then fail for reasons that have
    nothing to do with the code under test.
    """
    return Decimal(str(value))


# -----------------------------------------------------------------------------
# Response assertions
# -----------------------------------------------------------------------------


def _status_matches(actual: int, expected: int | tuple[int, ...]) -> bool:
    if isinstance(expected, int):
        return actual == expected
    return actual in expected


def assert_ok(
    response: Any,
    expected: int | tuple[int, ...] = 200,
) -> Any:
    """
    Assert the status code and return the decoded body.

    `expected` is positional, because at the call site
    `assert_ok(client.post(...), 201)` reads better than a keyword, and these
    two helpers appear several hundred times across the suite.

    A tuple is accepted for the handful of cases where more than one status is
    legitimately correct — a path that is either a 404 or a 422 depending on
    which validation runs first, say. Prefer a single status wherever the
    answer is actually determined.

    On failure the response body is included in the message. A bare
    `assert response.status_code == 200` tells you nothing about *why* the
    server refused, and the body almost always says exactly why.
    """
    assert _status_matches(response.status_code, expected), (
        f"expected {expected}, got {response.status_code}: {response.text[:2000]}"
    )

    if response.status_code == 204 or not response.content:
        return None

    return response.json()


def assert_error(
    response: Any,
    expected: int | tuple[int, ...],
) -> Mapping[str, Any]:
    """
    Assert a failure status and return the error body.

    Also checks the error envelope, which is flat: `code`, `message`,
    `category`, `retryable`, and optionally `details` and `request_id`. A
    client writes one reader for it, so an endpoint that answered with some
    other shape would be a contract break the status code alone would not
    catch.
    """
    assert _status_matches(response.status_code, expected), (
        f"expected {expected}, got {response.status_code}: {response.text[:2000]}"
    )

    body = response.json()

    assert isinstance(body, Mapping), f"error body is not an object: {body!r}"
    assert body.get("code"), f"error body has no code: {body!r}"
    assert body.get("message"), f"error body has no message: {body!r}"

    return body


def assert_paginated(body: Mapping[str, Any]) -> Mapping[str, Any]:
    """
    Assert the flat pagination envelope and return the body unchanged.

    Every list endpoint returns `items` alongside `page`, `page_size`, `total`
    and `total_pages` at the top level. This checks the shape itself, so a
    change to the envelope fails in one obvious place rather than as a
    `KeyError` in forty tests.

    The body is returned rather than the items so that a call can wrap a
    response inline — `assert_paginated(assert_ok(client.get(...)))` — and the
    caller still reads `["items"]` and `["total"]` from it.
    """
    for key in ("items", "page", "page_size", "total", "total_pages"):
        assert key in body, f"missing pagination key {key!r}: {sorted(body)}"

    assert isinstance(body["items"], list)
    assert body["page"] >= 1
    assert body["page_size"] >= 1
    assert body["total"] >= 0
    assert body["total_pages"] >= 0

    # The envelope must be internally consistent: a page cannot hold more rows
    # than its own page size, and a non-empty result cannot claim zero pages.
    assert len(body["items"]) <= body["page_size"]
    if body["total"] > 0:
        assert body["total_pages"] >= 1

    return body


def ids_of(items: Iterable[Mapping[str, Any]], key: str = "id") -> list[str]:
    return [str(item[key]) for item in items]


def find_by(items: Iterable[Mapping[str, Any]], **match: Any) -> Optional[Mapping[str, Any]]:
    """The first item whose fields all match, or None."""
    for item in items:
        if all(item.get(field) == value for field, value in match.items()):
            return item
    return None


def assert_has_caveats(body: Mapping[str, Any]) -> list[str]:
    """
    Assert that a response carries its interpretation limits.

    This matters more than it looks. The platform's whole position is that its
    output is an investigative lead rather than a finding, and the caveat list
    is how that travels with the data. A response that drops it is a response
    somebody will quote without the qualification.
    """
    caveats = body.get("caveats")
    assert isinstance(caveats, list), f"expected a caveats list, got {caveats!r}"
    return [str(item) for item in caveats]
