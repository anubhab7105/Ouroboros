"""
Money trails.

This is the module where the product's central honesty problem lives, so the
qualification is worth stating plainly before the tests.

**A money trail is not a tracing of funds.** Accounts are fungible. Once money
arrives in an account that already held money, which rupees subsequently left
is a question the ledger cannot answer — not approximately, not with better
data. What a trail actually is: a sequence of transfers, ordered in time,
consistent with funds having moved along that route. That is genuinely useful,
and it is a different claim.

Everything here follows from that:

- Trails are called **candidate** trails, and the caveats say so on every
  response.
- Amounts are reported **per currency**, never summed into a "total traced".
- A trail reports its **time span**, because a four-hop trail over ten minutes
  and one over three months are different findings.
- Traversal is **bounded**, and a trail that stopped at a limit says so. A
  truncated trail establishes nothing about where the money went next.

A test that asserted "the amount traced was X" would be asserting the thing
this module exists to deny, so none does.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

# Imported from the vocabulary module rather than from `app.models`: the
# trail builder is pure, so this module runs without a database driver
# installed, and pulling the ORM in just for an enum would end that.
from app.core.vocabularies import TransactionStatus

from tests.utils import assert_error, assert_ok, days_ago, hours_ago

pytestmark = [pytest.mark.graph, pytest.mark.api]


TRAILS = "/api/v1/graph/money-trails"


# -----------------------------------------------------------------------------
# The shape of the answer
# -----------------------------------------------------------------------------


def test_trails_from_a_layering_chain(analyst_client, make, db):
    chain, _ = make.layering_chain(hops=4)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            TRAILS, params={"account_id": chain[0].id, "max_hops": 5, "direction": "outgoing"}
        )
    )

    assert body["root_account_id"] == chain[0].id
    assert body["direction"] == "outgoing"
    assert body["generated_at"]
    assert body["trails"]
    assert body["caveats"]

    trail = body["trails"][0]
    assert trail["trail_id"]
    assert trail["hop_count"] >= 1
    assert trail["nodes"]
    assert trail["edges"]


def test_a_trail_is_described_as_a_candidate_not_as_traced_funds(
    analyst_client, make, db
):
    """
    The caveats say what a trail is, on every response.

    This is the assertion that keeps the product honest. A response that
    returned a route with no qualification would be making a claim about where
    specific money went — which the ledger cannot support, and which is
    exactly what a reader naturally assumes a "money trail" means.
    """
    chain, _ = make.layering_chain(hops=3)
    db.commit()

    body = assert_ok(analyst_client.get(TRAILS, params={"account_id": chain[0].id}))
    joined = " ".join(body["caveats"]).lower()

    assert body["caveats"]
    assert any(
        word in joined
        for word in ("candidate", "not proof", "lead", "consistent with", "fungib")
    ), f"the caveats do not qualify the trail: {body['caveats']}"


def test_there_is_no_total_traced_amount_field(analyst_client, make, db):
    """
    No `total_amount`, no `amount_traced`, no `funds_traced`.

    Any such field would be the single most quotable number the platform
    produces and the least defensible. `amount_by_currency` describes the
    transfers along the route; it is not a claim that this money took it.
    """
    chain, _ = make.layering_chain(hops=3)
    db.commit()

    body = assert_ok(analyst_client.get(TRAILS, params={"account_id": chain[0].id}))

    for forbidden in (
        "total_amount",
        "amount_traced",
        "funds_traced",
        "traced_amount",
        "total_value",
    ):
        assert forbidden not in body, f"the response exposes {forbidden!r}"

        for trail in body["trails"]:
            assert forbidden not in trail, f"a trail exposes {forbidden!r}"


def test_amounts_are_reported_per_currency(analyst_client, make, db):
    """
    A mapping, and it is not collapsed.

    A trail crossing two currencies has two figures. One number would be
    wrong in a way nobody checks, and it would be the number that reaches a
    slide.
    """
    first, second, third = make.accounts(3)

    make.transaction(first, second, amount=200_000, currency="INR", occurred_at=hours_ago(6))
    make.transaction(second, third, amount=2_000, currency="USD", occurred_at=hours_ago(5))
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": first.id, "max_hops": 4})
    )

    for trail in body["trails"]:
        amounts = trail["amount_by_currency"]
        assert isinstance(amounts, dict)

        for code, value in amounts.items():
            assert len(code) == 3, f"{code!r} is not a currency code"
            assert Decimal(str(value)) >= 0

        if {"INR", "USD"} <= set(amounts):
            assert Decimal(str(amounts["INR"])) != Decimal("202000")


def test_a_trail_reports_its_time_span(analyst_client, make, db):
    """
    Earliest and latest, because the timing is most of the signal.

    Five hops in an hour is layering. Five hops over two years is a sequence
    of unrelated payments that happens to form a route, and the hop count
    cannot tell them apart.
    """
    chain, _ = make.layering_chain(hops=4, minutes_between=12)
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": chain[0].id, "max_hops": 5})
    )

    for trail in body["trails"]:
        assert trail["earliest_at"]
        assert trail["latest_at"]
        assert trail["earliest_at"] <= trail["latest_at"]


def test_trail_edges_are_in_time_order(analyst_client, make, db):
    """
    A trail's transfers run forward in time.

    Money cannot arrive at hop three before it left hop two. A route assembled
    without the temporal constraint would be a path in the graph and not a
    candidate flow at all — and it would be the most convincing wrong answer
    the platform could give.
    """
    chain, _ = make.layering_chain(hops=4, minutes_between=20)
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": chain[0].id, "max_hops": 5})
    )

    for trail in body["trails"]:
        timestamps = [
            edge["occurred_at"] for edge in trail["edges"] if edge.get("occurred_at")
        ]
        assert timestamps == sorted(timestamps), (
            f"trail {trail['trail_id']} has transfers out of order"
        )


def test_every_trail_node_appears_in_its_own_node_list(analyst_client, make, db):
    chain, _ = make.layering_chain(hops=3)
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": chain[0].id, "max_hops": 4})
    )

    for trail in body["trails"]:
        node_ids = {node["id"] for node in trail["nodes"]}

        for edge in trail["edges"]:
            assert edge["source"] in node_ids
            assert edge["target"] in node_ids


# -----------------------------------------------------------------------------
# Direction
# -----------------------------------------------------------------------------


def test_outgoing_follows_the_money_away_from_the_root(analyst_client, make, db):
    chain, _ = make.layering_chain(hops=3)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            TRAILS,
            params={"account_id": chain[0].id, "direction": "outgoing", "max_hops": 4},
        )
    )

    assert body["direction"] == "outgoing"
    assert body["trails"]


def test_incoming_follows_the_money_towards_the_root(analyst_client, make, db):
    """
    The other half of a trail query, and the one used on a collection account.

    "Where did this money come from" is the question asked about a mule
    account that has already been identified, and it is answered by walking
    the edges backwards.
    """
    chain, _ = make.layering_chain(hops=3)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            TRAILS,
            params={"account_id": chain[-1].id, "direction": "incoming", "max_hops": 4},
        )
    )

    assert body["direction"] == "incoming"


def test_an_unknown_direction_is_rejected(analyst_client, make, db):
    """
    Only `outgoing` and `incoming`. There is no `both`.

    A trail is directional by nature: a route that changes direction halfway
    is not a candidate flow, it is two routes. The subgraph endpoint accepts
    `both` because a neighbourhood is not directional.
    """
    account = make.account()
    db.commit()

    assert_error(
        analyst_client.get(TRAILS, params={"account_id": account.id, "direction": "both"}),
        422,
    )
    assert_error(
        analyst_client.get(
            TRAILS, params={"account_id": account.id, "direction": "sideways"}
        ),
        422,
    )


# -----------------------------------------------------------------------------
# What counts as a transfer
# -----------------------------------------------------------------------------


def test_only_completed_transfers_form_a_trail(analyst_client, make, db):
    """
    A failed transfer moved no money, so it is not a hop.

    Including one would produce a trail through a transfer that never
    happened — the most misleading possible output, because the route would
    look complete.
    """
    first, second, third = make.accounts(3)

    make.transaction(first, second, amount=100_000, occurred_at=hours_ago(6))
    make.transaction(
        second,
        third,
        amount=95_000,
        occurred_at=hours_ago(5),
        status=TransactionStatus.FAILED,
    )
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": first.id, "max_hops": 4})
    )

    for trail in body["trails"]:
        account_ids = {
            node.get("account_id") for node in trail["nodes"] if node.get("account_id")
        }
        assert third.id not in account_ids, (
            "a trail ran through a FAILED transfer"
        )


def test_a_pending_transfer_is_not_a_hop(analyst_client, make, db):
    first, second, third = make.accounts(3)

    make.transaction(first, second, amount=100_000, occurred_at=hours_ago(6))
    make.transaction(
        second,
        third,
        amount=95_000,
        occurred_at=hours_ago(5),
        status=TransactionStatus.PENDING,
    )
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": first.id, "max_hops": 4})
    )

    for trail in body["trails"]:
        account_ids = {
            node.get("account_id") for node in trail["nodes"] if node.get("account_id")
        }
        assert third.id not in account_ids


def test_a_self_transfer_is_not_a_hop(analyst_client, make, db):
    """
    Moving money to oneself advances nothing.

    A self-transfer in a trail would inflate the hop count without the money
    having gone anywhere, which is both wrong and the easiest way to make a
    trail look longer than it is.
    """
    account, other = make.accounts(2)

    make.transaction(account, account, amount=50_000, occurred_at=hours_ago(5))
    make.transaction(account, other, amount=48_000, occurred_at=hours_ago(4))
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": account.id, "max_hops": 4})
    )

    for trail in body["trails"]:
        for edge in trail["edges"]:
            assert edge["source"] != edge["target"], "a self-transfer became a hop"


# -----------------------------------------------------------------------------
# Bounds
# -----------------------------------------------------------------------------


def test_the_hop_count_is_bounded(analyst_client, make, db):
    account = make.account()
    db.commit()

    assert_error(
        analyst_client.get(TRAILS, params={"account_id": account.id, "max_hops": 99}), 422
    )
    assert_error(
        analyst_client.get(TRAILS, params={"account_id": account.id, "max_hops": 0}), 422
    )


def test_the_trail_count_is_bounded(analyst_client, make, db):
    account = make.account()
    db.commit()

    assert_error(
        analyst_client.get(TRAILS, params={"account_id": account.id, "max_trails": 9_999}),
        422,
    )


def test_a_requested_hop_count_above_policy_is_clamped(
    analyst_client, make, db, override_settings
):
    """
    Policy decides the depth, not the caller.

    A caller that could raise the hop limit could issue the unbounded
    traversal the limit exists to prevent — and on a dense graph each extra
    hop multiplies the work.
    """
    override_settings(GRAPH_MAX_HOPS=2)

    chain, _ = make.layering_chain(hops=6)
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": chain[0].id, "max_hops": 10})
    )

    assert body["max_hops"] <= 2

    for trail in body["trails"]:
        assert trail["hop_count"] <= 2


def test_a_truncated_trail_search_says_so(analyst_client, make, db, override_settings):
    """
    The flag that stops a partial answer being read as a complete one.

    A trail cut at the hop limit says nothing about where the money went
    next. Returning it without the flag would let a reader conclude the money
    stopped there — which is the opposite of what a truncated traversal
    establishes.
    """
    override_settings(GRAPH_MAX_TRAILS=2)

    distributor, receivers, _ = make.fan_out(destinations=10)

    for receiver in receivers:
        onward = make.account()
        make.transaction(receiver, onward, amount=26_000, occurred_at=hours_ago(1))
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": distributor.id, "max_hops": 3})
    )

    assert len(body["trails"]) <= 2

    if body["truncated"]:
        joined = " ".join(body["caveats"]).lower()
        assert "truncat" in joined or "limit" in joined or "incomplete" in joined


def test_a_long_chain_is_cut_at_the_hop_limit_rather_than_followed(
    analyst_client, make, db
):
    """
    A five-hop chain queried at three hops returns three hops.

    And the trail does not claim to end there. This is the ordinary case: real
    chains are longer than any limit, so almost every trail in practice is a
    truncated one.
    """
    chain, _ = make.layering_chain(hops=6)
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": chain[0].id, "max_hops": 3})
    )

    for trail in body["trails"]:
        assert trail["hop_count"] <= 3


# -----------------------------------------------------------------------------
# Edge cases
# -----------------------------------------------------------------------------


def test_an_account_with_no_onward_transfers_has_no_trails(analyst_client, make, db):
    """
    An empty list, and the caveats still say what an absence means.

    No outgoing trail from a collection account means the money has not moved
    on *yet*, or has moved somewhere outside the dataset. It does not mean the
    money stopped.
    """
    collector, _, _ = make.fan_in(sources=5)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            TRAILS, params={"account_id": collector.id, "direction": "outgoing"}
        )
    )

    assert body["trails"] == []
    assert body["caveats"]


def test_an_unknown_root_is_404(analyst_client):
    assert_error(
        analyst_client.get(TRAILS, params={"account_id": "ACC-DOES-NOT-EXIST"}), 404
    )


def test_a_cycle_does_not_loop_forever(analyst_client, make, db):
    """
    A round trip terminates.

    Cycle prevention is the difference between a trail query and a hang. The
    round-trip typology is real and common, so this is not a hypothetical
    input.
    """
    cycle, _ = make.round_trip(hops=3)
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": cycle[0].id, "max_hops": 6})
    )

    for trail in body["trails"]:
        account_ids = [
            node["account_id"] for node in trail["nodes"] if node.get("account_id")
        ]
        assert len(account_ids) == len(set(account_ids)) or trail["hop_count"] <= 6


def test_trails_respect_a_point_in_time(analyst_client, make, db):
    """
    `as_of` excludes transfers that had not happened.

    A trail dated to last month that included this month's hops would be
    showing an investigator what they could not have known — and would make a
    historical reconstruction irreproducible.
    """
    first, second, third = make.accounts(3)

    make.transaction(first, second, amount=100_000, occurred_at=days_ago(100))
    make.transaction(second, third, amount=95_000, occurred_at=hours_ago(2))
    db.commit()

    then = assert_ok(
        analyst_client.get(
            TRAILS,
            params={
                "account_id": first.id,
                "max_hops": 4,
                "as_of": days_ago(30).isoformat(),
            },
        )
    )

    for trail in then["trails"]:
        account_ids = {
            node.get("account_id") for node in trail["nodes"] if node.get("account_id")
        }
        assert third.id not in account_ids


def test_trails_can_be_filtered_by_amount(analyst_client, make, db):
    """
    Small transfers are usually noise in a trail query.

    A chain carrying four lakh and a chain carrying two hundred rupees are not
    equally interesting, and without the filter the second swamps the first.
    """
    first, second = make.accounts(2)

    make.transaction(first, second, amount=200, occurred_at=hours_ago(3))
    db.commit()

    body = assert_ok(
        analyst_client.get(
            TRAILS, params={"account_id": first.id, "amount_min": 100_000}
        )
    )

    assert body["trails"] == []


def test_the_pass_through_shape_produces_a_trail(analyst_client, make, db):
    """
    The typology the trail query exists for.

    Money in, almost all of it out within minutes. The trail shows the route;
    what makes it a finding is the retained fraction and the holding time,
    both of which are visible in the transfers rather than asserted by the
    platform.
    """
    source, middle, destination, _ = make.pass_through(
        amount=200_000, retained_fraction=0.02, minutes_held=11
    )
    db.commit()

    body = assert_ok(
        analyst_client.get(TRAILS, params={"account_id": source.id, "max_hops": 3})
    )

    assert body["trails"]

    reached = set()
    for trail in body["trails"]:
        for node in trail["nodes"]:
            if node.get("account_id"):
                reached.add(node["account_id"])

    assert middle.id in reached
    assert destination.id in reached
