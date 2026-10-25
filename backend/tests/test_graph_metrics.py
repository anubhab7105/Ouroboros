"""
Graph metrics, tested directly against `app/graph/`.

These run without a database or a client: the graph modules take a dataset of
plain mappings, build a view, and compute over it. That makes them cheap to
test thoroughly, which is worth doing because a metric that is quietly wrong
is almost impossible to notice downstream — a centrality figure looks equally
plausible whatever it says.

Note on the architecture: `app/graph/` is a self-contained analytics layer,
and the live `/api/v1/graph` endpoints use `app/services/graph.py`, which does
its own bounded traversal over `Transaction` rows. The two are separate
implementations. `test_graph.py` covers the API; this module covers the
analytics package, including the enum-normalisation bug that made every
`GraphEdgeType.SENT` edge normalise to `related_to` and left money-trail
detection seeing zero money edges.
"""

from __future__ import annotations

import pytest

from app.graph.builder import build_graph
from app.graph.limits import (
    GraphConstructionLimits,
    GraphTraversalLimits,
    get_graph_policy,
    validate_construction_limits,
    validate_traversal_limits,
)
from app.graph.metrics import compute_graph_metrics, summarize_graph_metrics
from app.graph.neighborhood import extract_neighborhood
from app.graph.trails import detect_money_trails

pytestmark = pytest.mark.graph


def _accounts(count, prefix="acc"):
    return [
        {"id": f"{prefix}-{index}", "account_type": "INDIVIDUAL", "status": "ACTIVE"}
        for index in range(count)
    ]


def _chain(length, prefix="acc", amount=100_000, decay=2_000):
    """A linear chain of `length` transfers: prefix-0 → prefix-1 → …"""
    return [
        {
            "id": f"t-{prefix}-{index}",
            "reference": f"T-{prefix.upper()}-{index}",
            "sender_account_id": f"{prefix}-{index}",
            "receiver_account_id": f"{prefix}-{index + 1}",
            "amount": amount - index * decay,
            "currency": "INR",
            "status": "COMPLETED",
            "channel": "IMPS",
            "occurred_at": f"2025-11-13T{index:02d}:00:00Z",
        }
        for index in range(length)
    ]


def _view(accounts, transactions):
    return build_graph({"accounts": accounts, "transactions": transactions})


# -----------------------------------------------------------------------------
# Building
# -----------------------------------------------------------------------------


def test_a_graph_builds_from_a_plain_dataset():
    view = _view(_accounts(6), _chain(5))

    assert str(view.status).endswith("AVAILABLE")
    assert view.nodes
    assert view.edges
    assert view.counts["nodes"] == len(view.nodes)
    assert view.counts["edges"] == len(view.edges)


def test_the_graph_is_bipartite_over_accounts_and_transactions():
    """
    A transfer is a node, not just an edge.

    Modelling it as a node is what lets a transfer carry its own amount,
    time and status, and what lets a complaint correlate to the transfer
    rather than to one of the accounts.
    """
    view = _view(_accounts(6), _chain(5))

    assert view.node_type_counts["account"] == 6
    assert view.node_type_counts["transaction"] == 5
    assert view.edge_type_counts["sent"] == 5
    assert view.edge_type_counts["received"] == 5


def test_node_identifiers_are_hashed_not_the_account_ids():
    """
    The view carries salted hashes, never the account ids.

    A graph view is passed between analytics components and can end up in
    metrics output. The caller submitted the ids and does not need them back.
    """
    view = _view(_accounts(3), _chain(2))

    node_ids = {node.node_id for node in view.nodes}

    assert "acc-0" not in node_ids
    for node_id in node_ids:
        assert len(node_id) >= 32


def test_the_build_is_deterministic_and_fingerprinted():
    """
    Same input, same fingerprint.

    The fingerprint is how a metrics result can say which graph it was
    computed over. Non-determinism here would make every downstream figure
    irreproducible.
    """
    first = _view(_accounts(6), _chain(5))
    second = _view(_accounts(6), _chain(5))

    assert first.fingerprint
    assert first.fingerprint == second.fingerprint


def test_an_empty_dataset_builds_an_empty_graph():
    view = build_graph({"accounts": [], "transactions": []})

    assert view.nodes == ()
    assert view.edges == ()


def test_construction_is_bounded_by_policy():
    """
    More nodes than the limit does not simply build them all.

    `UnboundedGraphQueryProhibitedError` exists because a whole-bank graph is
    both unaffordable and useless. The builder reports the limits it applied.
    """
    view = _view(_accounts(6), _chain(5))

    assert view.counts["node_limit"] > 0
    assert view.counts["edge_limit"] > 0
    assert view.counts["nodes"] <= view.counts["node_limit"]
    assert view.counts["edges"] <= view.counts["edge_limit"]


# -----------------------------------------------------------------------------
# Edge-type normalisation
# -----------------------------------------------------------------------------


def test_edge_types_survive_normalisation():
    """
    The enum regression test.

    `GraphEdgeType` is a `str`-mixin enum, so `str(GraphEdgeType.SENT)` is
    `"GraphEdgeType.SENT"`, not `"sent"`. The token normaliser stringified its
    input, so every edge the builder produced normalised to `graph_edge_type_
    sent`, fell through the known-type set and became `related_to`.

    Nothing raised. Money-trail detection simply reported zero money edges on
    every graph the builder had produced — the whole feature silently did
    nothing. `_normalize_unicode` now unwraps an Enum to its value.
    """
    from app.graph.trails import _MONEY_FLOW_EDGE_TYPES, _normalize_edge_type

    view = _view(_accounts(4), _chain(3))

    for edge in view.edges:
        normalised = _normalize_edge_type(edge.edge_type)

        assert normalised != "related_to", (
            f"{edge.edge_type!r} normalised to the fallback type"
        )
        assert normalised in _MONEY_FLOW_EDGE_TYPES


def test_money_edges_are_found_in_a_built_graph():
    """
    The observable consequence of the fix.

    Before it, `money_edges` was 0 for any graph `build_graph` produced and
    trail detection returned `EMPTY` every time.
    """
    view = _view(_accounts(6), _chain(5))
    result = detect_money_trails(view)

    assert result.counts["money_edges"] > 0
    assert result.trails


# -----------------------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------------------


def test_metrics_compute_over_a_chain():
    view = _view(_accounts(6), _chain(5))
    result = compute_graph_metrics(view)

    assert result.ok is True
    assert result.basic_metrics["available"] is True
    assert result.basic_metrics["node_count"] == len(view.nodes)
    assert result.basic_metrics["edge_count"] == len(view.edges)


def test_the_metrics_fingerprint_identifies_the_normalised_graph():
    """
    `graph_fingerprint` is the metrics layer's own hash, not the builder's.

    Worth stating because the name invites the opposite assumption. The
    builder fingerprints the dataset it was given; the metrics layer
    re-normalises that view into its own adjacency representation and
    fingerprints *that*. The two hashes legitimately differ.

    What has to hold is that it is stable and deterministic — otherwise a
    metrics result could not be matched back to the graph it describes, which
    is the only thing the field is for.
    """
    view = _view(_accounts(6), _chain(5))

    first = compute_graph_metrics(view)
    second = compute_graph_metrics(_view(_accounts(6), _chain(5)))

    assert first.graph_fingerprint
    assert first.graph_fingerprint == second.graph_fingerprint

    # A different graph gets a different fingerprint.
    other = compute_graph_metrics(_view(_accounts(4), _chain(3)))
    assert other.graph_fingerprint != first.graph_fingerprint


def test_a_chain_is_one_connected_component():
    """
    A property with a known answer, which is why it is worth asserting.

    Most graph metrics are hard to check by inspection. Component count on a
    linear chain is not: it is one, and a result that said otherwise would
    mean the adjacency is being built wrong.
    """
    view = _view(_accounts(6), _chain(5))
    result = compute_graph_metrics(view)

    components = result.component_metrics

    assert components["component_count"] == 1
    assert components["largest_component_size"] == len(view.nodes)
    assert components["largest_component_share"] == pytest.approx(1.0)
    assert components["singleton_count"] == 0


def test_two_disjoint_chains_are_two_components():
    accounts = _accounts(4, "left") + _accounts(4, "right")
    transactions = _chain(3, "left") + _chain(3, "right")

    result = compute_graph_metrics(_view(accounts, transactions))

    assert result.component_metrics["component_count"] == 2


def test_an_isolated_account_is_a_singleton():
    """
    An account with no transfers is its own component.

    Counted rather than dropped, because "how many accounts have no activity
    at all" is a data-quality question with an operational answer.
    """
    accounts = _accounts(4) + [
        {"id": "acc-lonely", "account_type": "INDIVIDUAL", "status": "ACTIVE"}
    ]
    result = compute_graph_metrics(_view(accounts, _chain(3)))

    assert result.component_metrics["singleton_count"] >= 1
    assert result.basic_metrics["isolated_node_count"] >= 1


def test_degree_statistics_are_internally_consistent():
    """
    min ≤ mean ≤ max, and the count matches the node count.

    Cheap, and it catches the commonest statistics bug: computing a summary
    over the wrong collection.
    """
    view = _view(_accounts(8), _chain(7))
    result = compute_graph_metrics(view)

    degree = result.degree_metrics["degree"]

    assert degree["available"] is True
    assert degree["count"] == len(view.nodes)
    assert degree["min"] <= degree["mean"] <= degree["max"]
    assert degree["median"] >= degree["min"]


def test_in_and_out_degree_are_reported_separately():
    """
    Direction matters in this domain more than anywhere else.

    A collector has high in-degree and low out-degree; a distributor is the
    reverse. A single undirected degree would make the two look identical,
    which is the distinction the whole detector rests on.
    """
    result = compute_graph_metrics(_view(_accounts(6), _chain(5)))

    assert "in_degree" in result.degree_metrics
    assert "out_degree" in result.degree_metrics
    assert result.degree_metrics["in_degree"]["available"] is True


def test_a_fan_in_shape_has_a_high_in_degree_node():
    """
    Twelve senders paying one account.

    The collector's transaction nodes all point at it, so its in-degree is
    the highest in the graph. If this did not hold, the shape the product is
    named for would not be visible in the metrics.
    """
    accounts = _accounts(13)
    transactions = [
        {
            "id": f"t-in-{index}",
            "reference": f"T-IN-{index}",
            "sender_account_id": f"acc-{index + 1}",
            "receiver_account_id": "acc-0",
            "amount": 24_000,
            "currency": "INR",
            "status": "COMPLETED",
            "channel": "UPI",
            "occurred_at": f"2025-11-13T{index:02d}:00:00Z",
        }
        for index in range(12)
    ]

    result = compute_graph_metrics(_view(accounts, transactions))
    in_degree = result.degree_metrics["in_degree"]

    assert in_degree["max"] >= 12


def test_density_is_between_zero_and_one():
    result = compute_graph_metrics(_view(_accounts(8), _chain(7)))

    for key in ("directed_density", "undirected_density"):
        value = result.basic_metrics[key]
        assert 0.0 <= value <= 1.0, f"{key} is {value}"


def test_reciprocity_is_zero_on_a_one_way_chain():
    """
    No transfer in a chain has a matching reverse transfer.

    Reciprocity is a useful signal — mutual flow between two accounts is a
    different pattern from a chain — and a non-zero value here would mean it
    is being counted wrong.
    """
    result = compute_graph_metrics(_view(_accounts(6), _chain(5)))

    assert result.basic_metrics["reciprocity"] == pytest.approx(0.0)
    assert result.basic_metrics["reciprocal_pair_count"] == 0


def test_a_round_trip_produces_a_cycle_in_the_graph():
    """
    The money comes back, and the component is still one.

    A cycle is a strong signal and an easy one to produce innocently
    (settlement between related businesses), which is why the metrics report
    the structure and leave the interpretation to the rules.
    """
    accounts = _accounts(3)
    transactions = [
        {
            "id": f"t-cycle-{index}",
            "reference": f"T-CYCLE-{index}",
            "sender_account_id": f"acc-{index}",
            "receiver_account_id": f"acc-{(index + 1) % 3}",
            "amount": 150_000,
            "currency": "INR",
            "status": "COMPLETED",
            "channel": "IMPS",
            "occurred_at": f"2025-11-1{index + 3}T04:00:00Z",
        }
        for index in range(3)
    ]

    result = compute_graph_metrics(_view(accounts, transactions))

    assert result.component_metrics["component_count"] == 1
    assert result.basic_metrics["self_edge_count"] == 0


def test_metrics_on_an_empty_graph_are_unavailable_not_zero():
    """
    Nothing to measure is reported as unavailable.

    A density of 0.0 on an empty graph would be a number where there is no
    number, and it would plot as a point on a trend chart.
    """
    result = compute_graph_metrics(build_graph({"accounts": [], "transactions": []}))

    assert result.ok is True
    assert str(result.status).endswith("EMPTY") or result.basic_metrics.get(
        "available"
    ) in (False, None)


def test_metrics_are_deterministic():
    first = compute_graph_metrics(_view(_accounts(8), _chain(7)))
    second = compute_graph_metrics(_view(_accounts(8), _chain(7)))

    assert first.basic_metrics == second.basic_metrics
    assert first.component_metrics == second.component_metrics


def test_the_metrics_summary_is_serialisable_and_carries_no_identifiers():
    """
    The summary is what reaches a report, so it holds no account ids.

    It is a digest of structure: counts, distributions and a fingerprint.
    Nothing in it identifies a party.
    """
    view = _view(_accounts(6), _chain(5))
    summary = summarize_graph_metrics(compute_graph_metrics(view))

    assert summary

    serialised = str(summary)
    assert "acc-0" not in serialised
    assert "T-ACC-0" not in serialised


def test_metrics_are_bounded_by_their_options():
    from app.graph.metrics import GraphMetricsOptions

    options = GraphMetricsOptions()

    assert options.max_nodes > 0
    assert options.max_edges > 0
    assert options.max_neighbors > 0


# -----------------------------------------------------------------------------
# Neighbourhood extraction
# -----------------------------------------------------------------------------


def test_a_neighbourhood_is_extracted_around_a_seed():
    view = _view(_accounts(8), _chain(7))
    seed = next(node.node_id for node in view.nodes if str(node.node_type).endswith("ACCOUNT"))

    result = extract_neighborhood(view, [seed])

    assert result.ok is True
    assert result.seeds_found >= 1
    assert result.nodes


def test_neighbourhood_nodes_carry_their_distance():
    """
    Distance from the seed is what makes a neighbourhood readable.

    It is how the interface decides what to place near the centre, and how an
    analyst knows whether a node is a direct counterparty or three hops out.
    """
    view = _view(_accounts(8), _chain(7))
    seed = next(node.node_id for node in view.nodes if str(node.node_type).endswith("ACCOUNT"))

    result = extract_neighborhood(view, [seed])

    for node in result.nodes:
        assert node.distance is not None
        assert node.distance >= 0

    assert any(node.distance == 0 for node in result.nodes), "the seed is not at distance 0"


def test_a_missing_seed_is_reported_rather_than_ignored():
    """
    A seed that is not in the graph is counted as missing.

    Silently returning an empty neighbourhood would look like "this account
    has no connections" when the truth is "this account was not in the graph
    you built".
    """
    view = _view(_accounts(4), _chain(3))
    result = extract_neighborhood(view, ["not-a-node-id"])

    assert result.seeds_missing >= 1
    assert result.issues or result.seeds_found == 0


def test_neighbourhood_extraction_is_bounded():
    from app.graph.neighborhood import NeighborhoodOptions

    options = NeighborhoodOptions()

    assert options.max_nodes > 0
    assert options.max_edges > 0
    assert options.max_seeds > 0


# -----------------------------------------------------------------------------
# Policy and limits
# -----------------------------------------------------------------------------


def test_the_default_policy_is_synthetic_only():
    """
    The graph layer refuses to run on non-synthetic data by default.

    It is the component that would most obviously be repurposed against real
    records, because the analytics are generic. The default closes that.
    """
    policy = get_graph_policy()

    assert policy.synthetic_required is True
    assert policy.dataset_mode == "synthetic"
    assert policy.allow_in_production is False


def test_construction_limits_are_validated():
    valid = validate_construction_limits(
        GraphConstructionLimits(max_nodes=500, max_edges=1500, max_records=5000)
    )
    assert valid.ok is True
    assert valid.issues == ()


def test_an_out_of_range_limit_is_clamped_rather_than_accepted():
    """
    The limits type corrects itself in `__post_init__`.

    A deliberate choice, and the right one: these values come from
    environment variables, and a typo in `GRAPH_MAX_NODES` should clamp to
    something workable rather than refuse to start the service. Zero and
    negative values land on the floor of 1, and absurdly large ones on the
    hard ceiling.
    """
    clamped = GraphConstructionLimits(max_nodes=0, max_edges=-1, max_records=5000)

    assert clamped.max_nodes >= 1
    assert clamped.max_edges >= 1

    enormous = GraphConstructionLimits(max_nodes=10**9, max_edges=10**9)

    assert enormous.max_nodes < 10**9, "the hard ceiling was not applied"
    assert enormous.max_edges < 10**9


def test_a_clamped_but_unusable_limit_is_still_reported():
    """
    Clamping keeps the service up; validation still says it is wrong.

    A node limit of 1 is legal as a number and useless as a graph — a graph
    needs at least two nodes to have an edge. So the value is clamped *and*
    the validator raises an error about it, which is the combination that
    lets a misconfiguration be visible without being fatal.
    """
    result = validate_construction_limits(
        GraphConstructionLimits(max_nodes=0, max_edges=1500, max_records=5000)
    )

    assert result.ok is False
    assert result.issues

    codes = {issue.code for issue in result.issues}
    assert "invalid_max_nodes" in codes

    # The issue carries a usable severity and the field at fault — the
    # severity in particular is what previously raised `NameError` on
    # construction, so every failed validation crashed.
    issue = next(item for item in result.issues if item.code == "invalid_max_nodes")
    assert issue.severity is not None
    assert issue.field == "max_nodes"
    assert issue.message


def test_traversal_limits_are_validated():
    valid = validate_traversal_limits(
        GraphTraversalLimits(max_depth=3, max_paths=20, max_trails=25)
    )
    assert valid.ok is True
    assert valid.issues == ()


def test_traversal_limits_are_clamped_to_at_least_one_hop():
    """
    A depth of zero would traverse nothing.

    Clamped to 1 rather than refused, for the same reason as the construction
    limits: a bad environment variable should degrade the query, not stop the
    service.
    """
    clamped = GraphTraversalLimits(max_depth=0, max_paths=20, max_trails=25)

    assert clamped.max_depth >= 1
    assert clamped.max_paths >= 1
    assert clamped.max_trails >= 1
    assert clamped.max_time_ms > 0


def test_a_graph_view_reports_its_issues_rather_than_raising():
    """
    Problems come back as data.

    A graph built from a feed with bad rows should still produce a view, with
    the problems listed. Raising would mean one malformed transaction takes
    out the whole neighbourhood an analyst was looking at.
    """
    view = build_graph(
        {
            "accounts": _accounts(3),
            "transactions": [
                {
                    "id": "t-bad",
                    "reference": "T-BAD",
                    "sender_account_id": "acc-0",
                    "receiver_account_id": "acc-does-not-exist",
                    "amount": 1_000,
                    "currency": "INR",
                    "status": "COMPLETED",
                    "channel": "IMPS",
                    "occurred_at": "2025-11-13T01:00:00Z",
                }
            ],
        }
    )

    assert view is not None
    assert isinstance(view.issues, tuple)
