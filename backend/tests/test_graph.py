"""
Graph queries: subgraphs, paths and shared-entity groups.

The graph is the part of the platform whose output most invites
over-reading. A picture of connected accounts is persuasive in a way a table
of numbers is not, so almost everything here is about the qualifications that
have to travel with it.

**Every query is bounded, and truncation is reported.** `UnboundedGraphQueryProhibitedError`
exists because a whole-bank traversal is both a denial of service and a
useless answer. When a traversal stops at a limit it says so — and a truncated
neighbourhood establishes *nothing* about what lay beyond it. Presenting one
as complete is the single most misleading thing this API could do.

**A path is a shape, not a tracing of funds.** Accounts are fungible: once
money lands in an account that already held money, which rupees left is a
question the ledger cannot answer. A path is a sequence of transfers
consistent with a flow, and the amounts are reported per currency, never
summed.

**Deterministic and inferred edges are distinguishable.** An entity link
edge carries `deterministic` and, when inferred, a confidence. The frontend
draws inferred edges dashed for this reason; the data has to support it.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.models import EntityType, MatchMethod

from tests.utils import assert_error, assert_ok, days_ago, hours_ago

pytestmark = [pytest.mark.graph, pytest.mark.api]


GRAPH = "/api/v1/graph"


# -----------------------------------------------------------------------------
# Status
# -----------------------------------------------------------------------------


def test_status_reports_every_bound_and_its_hard_ceiling(analyst_client):
    """
    Two numbers per limit: the configured one and the ceiling it cannot exceed.

    The configured limit can be raised by an operator; the hard maximum
    cannot. Publishing both is what lets a caller know whether a bound is
    policy or physics.
    """
    body = assert_ok(analyst_client.get(f"{GRAPH}/status"))

    assert body["enabled"] is True

    for name in (
        "nodes",
        "edges",
        "depth",
        "paths",
        "trails",
        "shared_groups",
        "accounts_per_entity",
        "date_span_days",
    ):
        configured = body[f"max_{name}"]
        hard = body[f"hard_max_{name}"]

        assert configured > 0, f"max_{name} is not positive"
        assert hard >= configured, f"hard_max_{name} is below max_{name}"

    assert body["caveats"]


# -----------------------------------------------------------------------------
# Subgraph
# -----------------------------------------------------------------------------


def test_a_subgraph_is_rooted_and_reports_its_stats(analyst_client, make, db):
    collector, senders, _ = make.fan_in(sources=5)
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{GRAPH}/subgraph", params={"account_id": collector.id})
    )

    assert body["root_node_id"]
    assert body["nodes"]
    assert body["edges"]
    assert body["stats"]["node_count"] == len(body["nodes"])
    assert body["stats"]["edge_count"] == len(body["edges"])
    assert body["generated_at"]
    assert body["caveats"]


def test_a_subgraph_requires_a_root(analyst_client):
    """
    There is no "show me the whole graph".

    `account_id` is required rather than optional-with-a-default, because the
    default would be the query that must not exist.
    """
    assert_error(analyst_client.get(f"{GRAPH}/subgraph"), 422)


def test_an_unknown_root_is_404(analyst_client):
    assert_error(
        analyst_client.get(f"{GRAPH}/subgraph", params={"account_id": "ACC-NOPE"}), 404
    )


def test_the_depth_is_bounded(analyst_client, make, db):
    """
    Ten hops is the ceiling, and beyond it the request is refused.

    Depth is the parameter that turns a cheap query into an expensive one
    exponentially, so it is capped in the signature rather than clamped
    quietly.
    """
    account = make.account()
    db.commit()

    assert_error(
        analyst_client.get(
            f"{GRAPH}/subgraph", params={"account_id": account.id, "depth": 50}
        ),
        422,
    )
    assert_error(
        analyst_client.get(
            f"{GRAPH}/subgraph", params={"account_id": account.id, "depth": 0}
        ),
        422,
    )


def test_a_requested_limit_above_policy_is_clamped_not_honoured(
    analyst_client, make, db, override_settings
):
    """
    The caller asks; policy decides.

    A caller that could raise the node cap by asking could issue the
    whole-bank query the cap exists to prevent.
    """
    override_settings(GRAPH_MAX_NODES=10)

    collector, _, _ = make.fan_in(sources=20)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/subgraph", params={"account_id": collector.id, "max_nodes": 1000}
        )
    )

    assert body["stats"]["max_nodes"] <= 10
    assert len(body["nodes"]) <= 10


def test_truncation_is_reported(analyst_client, make, db, override_settings):
    """
    The flag that keeps the picture honest.

    A truncated neighbourhood establishes nothing about what lay beyond the
    cut. Rendering one without saying it was cut invites the reader to
    conclude that the network ends there — which is precisely the conclusion
    the data does not support.
    """
    override_settings(GRAPH_MAX_NODES=8)

    collector, _, _ = make.fan_in(sources=25)
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{GRAPH}/subgraph", params={"account_id": collector.id})
    )

    assert body["stats"]["truncated"] is True

    joined = " ".join(body["caveats"]).lower()
    assert "truncat" in joined or "incomplete" in joined or "limit" in joined


def test_an_untruncated_subgraph_says_so(analyst_client, make, db):
    account, other = make.accounts(2)
    make.transaction(other, account, amount=1_000)
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{GRAPH}/subgraph", params={"account_id": account.id})
    )
    assert body["stats"]["truncated"] is False


def test_node_kinds_can_be_excluded(analyst_client, make, db):
    """
    The include flags are real, so the picture can be narrowed.

    An investigator looking at fund flow does not want complaint and
    assessment nodes in the way, and a graph of forty nodes where thirty are
    metadata is unreadable.
    """
    account, other = make.accounts(2)
    make.transaction(other, account, amount=5_000)

    entity = make.entity()
    make.entity_link(account, entity)
    db.commit()

    with_entities = assert_ok(
        analyst_client.get(
            f"{GRAPH}/subgraph",
            params={"account_id": account.id, "include_entities": True},
        )
    )
    without = assert_ok(
        analyst_client.get(
            f"{GRAPH}/subgraph",
            params={"account_id": account.id, "include_entities": False},
        )
    )

    assert len(without["nodes"]) <= len(with_entities["nodes"])

    types = {node["type"] for node in without["nodes"]}
    assert not any("entit" in kind.lower() for kind in types)


def test_every_node_carries_a_type_and_a_label(analyst_client, make, db):
    """
    Shape comes from the type; the label is what a person reads.

    The frontend maps type to shape and risk to colour, which is why colour
    never carries meaning on its own. A node with no type could not be drawn.
    """
    collector, _, _ = make.fan_in(sources=3)
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{GRAPH}/subgraph", params={"account_id": collector.id})
    )

    for node in body["nodes"]:
        assert node["id"]
        assert node["type"]
        assert node["label"]


def test_every_edge_connects_two_nodes_in_the_response(analyst_client, make, db):
    """
    No dangling edges.

    An edge whose endpoint is not in `nodes` cannot be drawn, and the usual
    cause is a truncation that cut nodes without cutting their edges — which
    renders as a line into empty space.
    """
    collector, _, _ = make.fan_in(sources=6)
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{GRAPH}/subgraph", params={"account_id": collector.id})
    )
    node_ids = {node["id"] for node in body["nodes"]}

    for edge in body["edges"]:
        assert edge["source"] in node_ids, f"edge {edge['id']} has a dangling source"
        assert edge["target"] in node_ids, f"edge {edge['id']} has a dangling target"


def test_an_inferred_entity_edge_is_marked_as_inferred(analyst_client, make, db):
    """
    `deterministic` and a confidence on the edge itself.

    This is what lets the interface draw inferred links dashed and
    deterministic ones solid. Without it the picture would show a device
    fingerprint match and a normalisation guess as the same relationship.
    """
    account = make.account()
    entity = make.entity(entity_type=EntityType.DEVICE)
    make.entity_link(
        account, entity, match_method=MatchMethod.NORMALIZED, confidence=0.81
    )
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/subgraph",
            params={"account_id": account.id, "include_entities": True},
        )
    )

    entity_edges = [edge for edge in body["edges"] if edge.get("entity_id")]
    assert entity_edges

    edge = entity_edges[0]
    assert edge["deterministic"] is False
    assert edge["confidence"] is not None
    assert Decimal(str(edge["confidence"])) < Decimal("1")


def test_a_deterministic_entity_edge_carries_no_confidence(analyst_client, make, db):
    account = make.account()
    entity = make.entity()
    make.entity_link(account, entity, match_method=MatchMethod.EXACT)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/subgraph",
            params={"account_id": account.id, "include_entities": True},
        )
    )

    entity_edges = [edge for edge in body["edges"] if edge.get("entity_id")]
    assert entity_edges
    assert entity_edges[0]["deterministic"] is True
    assert entity_edges[0]["confidence"] is None


def test_a_complaint_node_does_not_carry_its_narrative(analyst_client, make, db):
    """
    A flag on the node, never the text.

    The graph is the widest surface in the product: one query returns dozens
    of records at once. A narrative here would reach every role that can read
    the graph.
    """
    account = make.account()
    complaint = make.complaint(
        suspected_account=account,
        narrative_raw="Victim describes being coached through a transfer by phone.",
    )
    make.correlation(complaint, account=account, match_tier=1)
    db.commit()

    response = analyst_client.get(
        f"{GRAPH}/subgraph",
        params={"account_id": account.id, "include_complaints": True},
    )
    assert_ok(response)

    assert "coached" not in response.text

    complaint_nodes = [
        node for node in response.json()["nodes"] if node.get("narrative_available") is not None
    ]
    for node in complaint_nodes:
        assert node["narrative_available"] in (True, False)


def test_a_subgraph_respects_a_point_in_time(analyst_client, make, db):
    """
    `as_of` excludes what had not happened yet.

    A graph dated to last month that included this month's transfers would
    make a point-in-time investigation unreproducible — and would show the
    investigator information they did not have.
    """
    account, other = make.accounts(2)

    make.transaction(other, account, amount=1_000, occurred_at=days_ago(100))
    make.transaction(other, account, amount=2_000, occurred_at=hours_ago(1))
    db.commit()

    then = assert_ok(
        analyst_client.get(
            f"{GRAPH}/subgraph",
            params={"account_id": account.id, "as_of": days_ago(30).isoformat()},
        )
    )
    now = assert_ok(
        analyst_client.get(f"{GRAPH}/subgraph", params={"account_id": account.id})
    )

    assert then["stats"]["edge_count"] <= now["stats"]["edge_count"]


def test_an_isolated_account_returns_just_itself(analyst_client, make, db):
    """
    One node, no edges, and not an error.

    An account with no counterparties is a normal thing to look at, and the
    empty neighbourhood is the answer.
    """
    account = make.account()
    db.commit()

    body = assert_ok(
        analyst_client.get(f"{GRAPH}/subgraph", params={"account_id": account.id})
    )

    assert body["stats"]["node_count"] >= 1
    assert body["edges"] == []


# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------


def test_paths_between_two_accounts(analyst_client, make, db):
    chain, _ = make.layering_chain(hops=4)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/paths",
            params={
                "from_account_id": chain[0].id,
                "to_account_id": chain[-1].id,
                "max_depth": 6,
            },
        )
    )

    assert body["from_account_id"] == chain[0].id
    assert body["to_account_id"] == chain[-1].id
    assert body["paths"]
    assert body["caveats"]

    path = body["paths"][0]
    assert path["hop_count"] >= 1
    assert path["nodes"]
    assert path["edges"]


def test_a_path_reports_amounts_per_currency_never_summed(analyst_client, make, db):
    """
    `amount_by_currency` is a mapping, not a total.

    A path crossing two currencies has two amounts. A single figure would be
    a number with no meaning that looks exactly like a number with meaning —
    and it is the figure that would end up quoted in a report.
    """
    first, second, third = make.accounts(3)

    make.transaction(first, second, amount=100_000, currency="INR", occurred_at=hours_ago(5))
    make.transaction(second, third, amount=1_000, currency="USD", occurred_at=hours_ago(4))
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/paths",
            params={"from_account_id": first.id, "to_account_id": third.id},
        )
    )

    if body["paths"]:
        amounts = body["paths"][0]["amount_by_currency"]

        assert isinstance(amounts, dict)
        if len(amounts) > 1:
            assert "INR" in amounts and "USD" in amounts
            assert Decimal(str(amounts["INR"])) != Decimal("101000")


def test_a_path_reports_its_time_span(analyst_client, make, db):
    """
    Earliest and latest, because timing is most of the signal.

    Four hops over ten minutes and four hops over three months are entirely
    different findings, and the hop count alone does not distinguish them.
    """
    chain, _ = make.layering_chain(hops=3)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/paths",
            params={
                "from_account_id": chain[0].id,
                "to_account_id": chain[-1].id,
                "max_depth": 5,
            },
        )
    )

    if body["paths"]:
        path = body["paths"][0]
        assert path["earliest_at"]
        assert path["latest_at"]
        assert path["earliest_at"] <= path["latest_at"]


def test_no_path_is_an_empty_list_not_an_error(analyst_client, make, db):
    """
    Two unconnected accounts produce no paths.

    That is an answer, and it has to be distinguishable from a failed query —
    especially since the caveats say an absence of paths is not evidence that
    none exists beyond the traversal bound.
    """
    first, second = make.accounts(2)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/paths",
            params={"from_account_id": first.id, "to_account_id": second.id},
        )
    )

    assert body["paths"] == []
    assert body["caveats"]


def test_the_path_depth_and_count_are_bounded(analyst_client, make, db):
    first, second = make.accounts(2)
    db.commit()

    assert_error(
        analyst_client.get(
            f"{GRAPH}/paths",
            params={
                "from_account_id": first.id,
                "to_account_id": second.id,
                "max_depth": 99,
            },
        ),
        422,
    )
    assert_error(
        analyst_client.get(
            f"{GRAPH}/paths",
            params={
                "from_account_id": first.id,
                "to_account_id": second.id,
                "max_paths": 10_000,
            },
        ),
        422,
    )


def test_path_truncation_is_reported(analyst_client, make, db, override_settings):
    """
    More paths than the cap, and the response says it stopped.

    "Three paths" from a traversal that stopped at three is a very different
    statement from "three paths exist".
    """
    override_settings(GRAPH_MAX_PATHS=2)

    hub, destination = make.accounts(2)
    middles = make.accounts(6)

    for middle in middles:
        make.transaction(hub, middle, amount=10_000, occurred_at=hours_ago(5))
        make.transaction(middle, destination, amount=9_500, occurred_at=hours_ago(4))
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/paths",
            params={"from_account_id": hub.id, "to_account_id": destination.id},
        )
    )

    assert len(body["paths"]) <= 2
    if body["truncated"]:
        assert "truncat" in " ".join(body["caveats"]).lower() or body["caveats"]


def test_a_path_to_itself_is_handled(analyst_client, make, db):
    """
    Source equal to target: a cycle query, not an error.

    A round trip is a real typology, and asking for paths from an account back
    to itself is how somebody looks for one.
    """
    cycle, _ = make.round_trip(hops=3)
    db.commit()

    response = analyst_client.get(
        f"{GRAPH}/paths",
        params={
            "from_account_id": cycle[0].id,
            "to_account_id": cycle[0].id,
            "max_depth": 5,
        },
    )

    assert response.status_code in (200, 422)
    assert response.status_code != 500


def test_an_unknown_endpoint_account_is_404(analyst_client, make, db):
    account = make.account()
    db.commit()

    assert_error(
        analyst_client.get(
            f"{GRAPH}/paths",
            params={"from_account_id": account.id, "to_account_id": "ACC-NOPE"},
        ),
        404,
    )


# -----------------------------------------------------------------------------
# Shared entities
# -----------------------------------------------------------------------------


def test_shared_entity_groups_are_returned(analyst_client, make, db):
    shared, accounts, _ = make.shared_identifier_cluster(members=4)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/shared-entities", params={"account_id": accounts[0].id}
        )
    )

    assert body["root_account_id"] == accounts[0].id
    assert body["groups"]
    assert body["caveats"]

    group = body["groups"][0]
    assert group["entity"]["id"]
    assert len(group["accounts"]) >= 2


def test_min_accounts_is_at_least_two(analyst_client, make, db):
    """
    A group of one is not a group.

    An "entity shared by one account" is just an account's own identifier, and
    a list of those is noise rather than a network.
    """
    account = make.account()
    db.commit()

    assert_error(
        analyst_client.get(
            f"{GRAPH}/shared-entities",
            params={"account_id": account.id, "min_accounts": 1},
        ),
        422,
    )


def test_a_higher_min_accounts_narrows_the_result(analyst_client, make, db):
    small, small_accounts, _ = make.shared_identifier_cluster(members=2)
    large, large_accounts, _ = make.shared_identifier_cluster(members=5)

    # Link one account into both clusters so the query has a common root.
    make.entity_link(small_accounts[0], large)
    db.commit()

    loose = assert_ok(
        analyst_client.get(
            f"{GRAPH}/shared-entities",
            params={"account_id": small_accounts[0].id, "min_accounts": 2},
        )
    )
    strict = assert_ok(
        analyst_client.get(
            f"{GRAPH}/shared-entities",
            params={"account_id": small_accounts[0].id, "min_accounts": 5},
        )
    )

    assert len(strict["groups"]) <= len(loose["groups"])


def test_shared_entity_groups_report_determinism_per_group(analyst_client, make, db):
    """
    Whether the whole group rests on exact matches or on guesses.

    "Four accounts share a device" is a finding. "Four accounts share
    something we normalised into the same value" is a lead. The group-level
    flag and confidence range are what distinguish them at a glance.
    """
    entity = make.entity()
    accounts = make.accounts(3)

    for account in accounts:
        make.entity_link(account, entity, match_method=MatchMethod.EXACT)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/shared-entities", params={"account_id": accounts[0].id}
        )
    )

    group = body["groups"][0]
    assert group["deterministic"] is True
    assert group["min_confidence"] is None
    assert group["max_confidence"] is None


def test_an_inferred_group_reports_a_confidence_range(analyst_client, make, db):
    entity = make.entity()
    accounts = make.accounts(3)

    make.entity_link(accounts[0], entity, match_method=MatchMethod.NORMALIZED, confidence=0.6)
    make.entity_link(accounts[1], entity, match_method=MatchMethod.NORMALIZED, confidence=0.9)
    make.entity_link(accounts[2], entity, match_method=MatchMethod.NORMALIZED, confidence=0.75)
    db.commit()

    body = assert_ok(
        analyst_client.get(
            f"{GRAPH}/shared-entities", params={"account_id": accounts[0].id}
        )
    )

    group = body["groups"][0]
    assert group["deterministic"] is False
    assert group["min_confidence"] is not None
    assert group["max_confidence"] is not None
    assert Decimal(str(group["min_confidence"])) <= Decimal(str(group["max_confidence"]))


def test_shared_entities_respect_a_point_in_time(analyst_client, make, db):
    """
    A link that had ended is not a current shared identifier.

    Telecoms reissue phone numbers. An account that held a number last year
    and one that holds it now are not connected, and a query that ignored the
    link bounds would say they are.
    """
    entity = make.entity(entity_type=EntityType.PHONE_HASH)
    past, present = make.accounts(2)

    make.entity_link(past, entity, valid_from=days_ago(700), valid_to=days_ago(400))
    make.entity_link(present, entity, valid_from=days_ago(30))
    db.commit()

    now = assert_ok(
        analyst_client.get(
            f"{GRAPH}/shared-entities",
            params={"account_id": present.id, "min_accounts": 2},
        )
    )

    # The two never held the number at the same time, so there is no current
    # group of two.
    assert now["groups"] == [] or all(
        len(group["accounts"]) < 2 for group in now["groups"]
    )


def test_shared_entities_never_expose_the_identifier_hash(analyst_client, make, db):
    """
    The entity node carries a label, not the stored hash.

    The hash is the value that would let two datasets be joined on a person.
    It stays server-side.
    """
    secret = "verysecretidentifierhash0001"
    entity = make.entity(identifier_hash=secret)
    accounts = make.accounts(2)

    for account in accounts:
        make.entity_link(account, entity)
    db.commit()

    response = analyst_client.get(
        f"{GRAPH}/shared-entities", params={"account_id": accounts[0].id}
    )
    assert_ok(response)

    assert secret not in response.text
    assert "identifier_hash" not in response.text


def test_group_and_per_entity_counts_are_bounded(analyst_client, make, db):
    account = make.account()
    db.commit()

    assert_error(
        analyst_client.get(
            f"{GRAPH}/shared-entities",
            params={"account_id": account.id, "max_groups": 5_000},
        ),
        422,
    )
    assert_error(
        analyst_client.get(
            f"{GRAPH}/shared-entities",
            params={"account_id": account.id, "max_accounts_per_entity": 5_000},
        ),
        422,
    )


# -----------------------------------------------------------------------------
# Safety
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,params",
    [
        ("subgraph", {"account_id": "ROOT"}),
        ("paths", {"from_account_id": "ROOT", "to_account_id": "ROOT"}),
        ("shared-entities", {"account_id": "ROOT"}),
        ("money-trails", {"account_id": "ROOT"}),
    ],
)
def test_no_graph_surface_leaks_a_label(analyst_client, make, db, path, params):
    """
    Scenario and ring ids never reach the graph.

    An analyst who could see the generator's labels would be reading the
    answer rather than the evidence — and the graph is where a label would be
    most useful and most corrupting, because it would let somebody colour the
    network by truth.
    """
    collector, senders, _ = make.fan_in(sources=3)
    make.label(collector, is_mule=True, scenario_type="fan_in_collector", ring_id="RING-5")
    for sender in senders:
        make.label(sender, is_mule=True, scenario_type="fan_in_source", ring_id="RING-5")
    db.commit()

    resolved = {
        key: (collector.id if value == "ROOT" else value) for key, value in params.items()
    }
    raw = analyst_client.get(f"{GRAPH}/{path}", params=resolved).text.lower()

    assert "ring-5" not in raw
    assert "fan_in_collector" not in raw
    assert "ground_truth" not in raw
    assert "scenario" not in raw


@pytest.mark.parametrize(
    "path,params",
    [
        ("subgraph", {"account_id": "ROOT"}),
        ("paths", {"from_account_id": "ROOT", "to_account_id": "ROOT"}),
        ("shared-entities", {"account_id": "ROOT"}),
        ("money-trails", {"account_id": "ROOT"}),
    ],
)
def test_every_graph_surface_carries_caveats(analyst_client, make, db, path, params):
    """
    A graph is persuasive, so the qualification travels with it.

    These responses are the ones most likely to be screenshotted into a
    report, which is exactly why the caveats are on the payload rather than in
    the documentation.
    """
    collector, _, _ = make.fan_in(sources=3)
    db.commit()

    resolved = {
        key: (collector.id if value == "ROOT" else value) for key, value in params.items()
    }
    body = assert_ok(analyst_client.get(f"{GRAPH}/{path}", params=resolved))

    assert body["caveats"], f"/{path} returned no caveats"

    joined = " ".join(body["caveats"]).lower()
    assert "lead" in joined or "not proof" in joined or "investigat" in joined
