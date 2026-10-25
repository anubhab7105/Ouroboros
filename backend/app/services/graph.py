"""
MULEGUARD graph analysis service.

Builds bounded fund-flow neighbourhoods around an account, computes position
metrics, finds candidate money trails and cycles, and persists the result as a
`GraphAnalysisRun` row.

Every traversal here is bounded before it starts — maximum hops, nodes, edges,
paths, and a date span. That is a correctness requirement, not an optimisation:
an unbounded traversal on a dense transfer graph does not return slowly, it
does not return. The persisted row records which limits were hit via `capped`,
so a reader can tell a complete answer from a truncated one.

This service implements its own bounded traversal rather than delegating to the
`app.graph` engine package. The traversal is small, the correctness conditions
are local, and keeping it here means the persisted `GraphAnalysisRun` payload
is produced by code with the database in front of it. `app.graph` remains the
richer analysis toolkit for interactive queries.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Final, Optional

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import GraphAnalysisRun, Transaction, TransactionStatus
from app.utils.dates import ensure_utc, utcnow
from app.utils.decimals import safe_div, to_float
from app.utils.json import sanitize_json

logger = logging.getLogger("muleguard.backend.services.graph")

__all__ = [
    "GRAPH_SERVICE_VERSION",
    "GraphLimits",
    "NeighbourhoodResult",
    "build_neighbourhood",
    "get_graph_service_metadata",
    "persist_graph_run",
]

GRAPH_SERVICE_VERSION: Final[str] = "v1"


class GraphLimits:
    """
    Hard bounds applied to every traversal.
    """

    __slots__ = (
        "max_edges",
        "max_hops",
        "max_nodes",
        "max_path_length",
        "max_paths",
        "span_days",
    )

    def __init__(
        self,
        *,
        max_hops: int = 3,
        max_nodes: int = 300,
        max_edges: int = 1_200,
        max_paths: int = 50,
        max_path_length: int = 6,
        span_days: int = 90,
    ) -> None:
        self.max_hops = max(1, min(int(max_hops), 6))
        self.max_nodes = max(2, min(int(max_nodes), 5_000))
        self.max_edges = max(1, min(int(max_edges), 20_000))
        self.max_paths = max(1, min(int(max_paths), 500))
        self.max_path_length = max(2, min(int(max_path_length), 10))
        self.span_days = max(1, min(int(span_days), 365))

    def to_dict(self) -> dict[str, Any]:
        """
        Return the limits as recorded on the persisted run.
        """
        return {
            "max_hops": self.max_hops,
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
            "max_paths": self.max_paths,
            "max_path_length": self.max_path_length,
            "span_days": self.span_days,
        }


class NeighbourhoodResult:
    """
    A bounded neighbourhood with its metrics and candidate trails.
    """

    __slots__ = (
        "capped",
        "cycles",
        "edges",
        "limits",
        "metrics",
        "nodes",
        "root_account_id",
        "trails",
        "window_end",
        "window_start",
    )

    def __init__(
        self,
        *,
        root_account_id: str,
        nodes: dict[str, dict[str, Any]],
        edges: list[dict[str, Any]],
        metrics: dict[str, Any],
        trails: list[dict[str, Any]],
        cycles: list[dict[str, Any]],
        capped: dict[str, bool],
        limits: GraphLimits,
        window_start: datetime,
        window_end: datetime,
    ) -> None:
        self.root_account_id = root_account_id
        self.nodes = nodes
        self.edges = edges
        self.metrics = metrics
        self.trails = trails
        self.cycles = cycles
        self.capped = capped
        self.limits = limits
        self.window_start = window_start
        self.window_end = window_end

    @property
    def was_capped(self) -> bool:
        """
        True when any limit truncated the result.
        """
        return any(self.capped.values())

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation.
        """
        return {
            "root_account_id": self.root_account_id,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "metrics": self.metrics,
            "trail_count": len(self.trails),
            "cycle_count": len(self.cycles),
            "capped": {k: v for k, v in self.capped.items() if v},
            "limits": self.limits.to_dict(),
            "window": {
                "start": self.window_start.isoformat(),
                "end": self.window_end.isoformat(),
            },
        }


def build_neighbourhood(
    db: Session,
    root_account_id: str,
    *,
    as_of: Optional[datetime] = None,
    limits: Optional[GraphLimits] = None,
) -> NeighbourhoodResult:
    """
    Expand a bounded fund-flow neighbourhood around one account.

    Only COMPLETED transfers inside the date span are edges: a failed or
    reversed transaction is not fund movement and must not appear as a hop in a
    money trail.
    """
    bounds = limits or GraphLimits()
    window_end = ensure_utc(as_of) or utcnow()
    window_start = window_end - timedelta(days=bounds.span_days)
    root = str(root_account_id).strip()

    nodes: dict[str, dict[str, Any]] = {
        root: {"id": root, "hop": 0, "in_amount": 0.0, "out_amount": 0.0}
    }
    edges: list[dict[str, Any]] = []
    edge_keys: set[tuple[str, str]] = set()
    adjacency: dict[str, set[str]] = defaultdict(set)
    reverse: dict[str, set[str]] = defaultdict(set)
    capped = {"nodes": False, "edges": False, "hops": False, "paths": False}

    frontier: deque[tuple[str, int]] = deque([(root, 0)])
    visited: set[str] = {root}

    while frontier:
        account_id, hop = frontier.popleft()

        if hop >= bounds.max_hops:
            capped["hops"] = True
            continue

        if len(nodes) >= bounds.max_nodes:
            capped["nodes"] = True
            break

        remaining_edges = bounds.max_edges - len(edges)

        if remaining_edges <= 0:
            capped["edges"] = True
            break

        stmt = (
            select(Transaction)
            .where(Transaction.status == TransactionStatus.COMPLETED)
            .where(Transaction.occurred_at >= window_start)
            .where(Transaction.occurred_at <= window_end)
            .where(
                or_(
                    Transaction.sender_account_id == account_id,
                    Transaction.receiver_account_id == account_id,
                )
            )
            .order_by(Transaction.occurred_at)
            .limit(min(remaining_edges + 1, 2_000))
        )
        rows = list(db.execute(stmt).scalars())

        if len(rows) > remaining_edges:
            capped["edges"] = True
            rows = rows[:remaining_edges]

        for txn in rows:
            sender = str(txn.sender_account_id)
            receiver = str(txn.receiver_account_id)
            amount = to_float(txn.amount) or 0.0
            key = (sender, receiver)

            if key not in edge_keys:
                edge_keys.add(key)
                edges.append(
                    {
                        "from": sender,
                        "to": receiver,
                        "amount": amount,
                        "currency": str(txn.currency or ""),
                        "count": 1,
                        "first_at": (ensure_utc(txn.occurred_at) or window_end).isoformat(),
                        "last_at": (ensure_utc(txn.occurred_at) or window_end).isoformat(),
                        "channel": str(getattr(txn.channel, "value", txn.channel) or ""),
                        "transaction_ids": [str(txn.id)],
                    }
                )
            else:
                for edge in edges:
                    if edge["from"] == sender and edge["to"] == receiver:
                        edge["amount"] += amount
                        edge["count"] += 1
                        occurred = (ensure_utc(txn.occurred_at) or window_end).isoformat()
                        edge["last_at"] = max(edge["last_at"], occurred)
                        edge["first_at"] = min(edge["first_at"], occurred)

                        if len(edge["transaction_ids"]) < 20:
                            edge["transaction_ids"].append(str(txn.id))
                        break

            adjacency[sender].add(receiver)
            reverse[receiver].add(sender)

            nodes.setdefault(sender, {"id": sender, "hop": hop + 1, "in_amount": 0.0, "out_amount": 0.0})
            nodes.setdefault(receiver, {"id": receiver, "hop": hop + 1, "in_amount": 0.0, "out_amount": 0.0})
            nodes[sender]["out_amount"] += amount
            nodes[receiver]["in_amount"] += amount

            for neighbour in (sender, receiver):
                if neighbour in visited:
                    continue

                if len(nodes) >= bounds.max_nodes:
                    capped["nodes"] = True
                    break

                visited.add(neighbour)
                frontier.append((neighbour, hop + 1))

    metrics = _metrics(root, nodes, edges, adjacency, reverse)
    trails, trail_capped = _trails(root, adjacency, edges, bounds)
    cycles = _cycles(root, adjacency, bounds)
    capped["paths"] = trail_capped

    return NeighbourhoodResult(
        root_account_id=root,
        nodes=nodes,
        edges=edges,
        metrics=metrics,
        trails=trails,
        cycles=cycles,
        capped=capped,
        limits=bounds,
        window_start=window_start,
        window_end=window_end,
    )


def _metrics(
    root: str,
    nodes: Mapping[str, Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    adjacency: Mapping[str, set[str]],
    reverse: Mapping[str, set[str]],
) -> dict[str, Any]:
    """
    Compute position metrics for the root account.

    `intermediary_score` is the signal that distinguishes a layering hop from an
    endpoint: an account with both inbound and outbound flow, where the two
    nearly balance, is passing funds through rather than receiving or spending
    them.
    """
    in_degree = len(reverse.get(root, set()))
    out_degree = len(adjacency.get(root, set()))
    root_node = nodes.get(root, {})
    in_amount = float(root_node.get("in_amount") or 0.0)
    out_amount = float(root_node.get("out_amount") or 0.0)

    balance_ratio = safe_div(min(in_amount, out_amount), max(in_amount, out_amount), 0.0) or 0.0
    degree_balance = safe_div(min(in_degree, out_degree), max(in_degree, out_degree), 0.0) or 0.0

    # Both directions present AND flows balanced => pass-through shaped.
    intermediary = 0.0

    if in_degree > 0 and out_degree > 0:
        intermediary = round(0.5 * balance_ratio + 0.5 * degree_balance, 6)

    total_in = sum(float(n.get("in_amount") or 0.0) for n in nodes.values())
    total_out = sum(float(n.get("out_amount") or 0.0) for n in nodes.values())

    return {
        "in_degree": in_degree,
        "out_degree": out_degree,
        "degree": in_degree + out_degree,
        "inbound_amount": round(in_amount, 2),
        "outbound_amount": round(out_amount, 2),
        "flow_balance_ratio": round(balance_ratio, 6),
        "intermediary_score": intermediary,
        "neighbourhood_nodes": len(nodes),
        "neighbourhood_edges": len(edges),
        "neighbourhood_inbound_amount": round(total_in, 2),
        "neighbourhood_outbound_amount": round(total_out, 2),
        "outbound_amount_share": round(
            safe_div(out_amount, in_amount + out_amount, 0.0) or 0.0, 6
        ),
    }


def _trails(
    root: str,
    adjacency: Mapping[str, set[str]],
    edges: Sequence[Mapping[str, Any]],
    bounds: GraphLimits,
) -> tuple[list[dict[str, Any]], bool]:
    """
    Enumerate candidate downstream money trails from the root.

    Depth-first with an explicit visited set per path, so a cycle cannot cause
    infinite recursion, and bounded by `max_paths` and `max_path_length`.
    """
    amount_by_edge = {(e["from"], e["to"]): float(e.get("amount") or 0.0) for e in edges}
    trails: list[dict[str, Any]] = []
    capped = False

    stack: list[tuple[list[str], set[str]]] = [([root], {root})]

    while stack:
        path, on_path = stack.pop()

        if len(trails) >= bounds.max_paths:
            capped = True
            break

        current = path[-1]
        successors = sorted(adjacency.get(current, set()))

        if not successors or len(path) >= bounds.max_path_length:
            if len(path) >= 3:
                # A trail needs at least one intermediary to be interesting.
                hop_amounts = [
                    amount_by_edge.get((path[i], path[i + 1]), 0.0)
                    for i in range(len(path) - 1)
                ]
                trails.append(
                    {
                        "path": list(path),
                        "hops": len(path) - 1,
                        "min_hop_amount": round(min(hop_amounts), 2) if hop_amounts else 0.0,
                        "max_hop_amount": round(max(hop_amounts), 2) if hop_amounts else 0.0,
                        # How much of what entered the first hop survives to
                        # the last: a high ratio over several hops is layering.
                        "throughput_ratio": round(
                            safe_div(min(hop_amounts), max(hop_amounts), 0.0) or 0.0, 6
                        )
                        if hop_amounts
                        else 0.0,
                    }
                )
            continue

        for successor in successors:
            if successor in on_path:
                continue

            stack.append(([*path, successor], on_path | {successor}))

    trails.sort(key=lambda t: (-t["hops"], -t["throughput_ratio"]))
    return trails[: bounds.max_paths], capped


def _cycles(
    root: str,
    adjacency: Mapping[str, set[str]],
    bounds: GraphLimits,
) -> list[dict[str, Any]]:
    """
    Find cycles that return to the root within the hop budget.

    Only cycles through the root are reported: a cycle elsewhere in the
    neighbourhood is not evidence about this account.
    """
    found: list[dict[str, Any]] = []
    seen_signatures: set[tuple[str, ...]] = set()
    stack: list[tuple[list[str], set[str]]] = [([root], {root})]

    while stack and len(found) < bounds.max_paths:
        path, on_path = stack.pop()
        current = path[-1]

        if len(path) > bounds.max_path_length:
            continue

        for successor in sorted(adjacency.get(current, set())):
            if successor == root and len(path) >= 3:
                cycle = [*path, root]
                rotated = tuple(cycle[:-1])
                signature = min(
                    tuple(rotated[i:] + rotated[:i]) for i in range(len(rotated))
                )

                if signature in seen_signatures:
                    continue

                seen_signatures.add(signature)
                found.append({"path": cycle, "length": len(cycle) - 1})
                continue

            if successor in on_path:
                continue

            stack.append(([*path, successor], on_path | {successor}))

    return found


def persist_graph_run(
    db: Session,
    *,
    result: NeighbourhoodResult,
    analysis_run_id: Optional[str] = None,
    created_by: Optional[str] = None,
) -> GraphAnalysisRun:
    """
    Persist a neighbourhood as a `GraphAnalysisRun` row.
    """
    record = GraphAnalysisRun(
        analysis_run_id=analysis_run_id,
        root_account_id=result.root_account_id,
        parameters_json=sanitize_json(
            {
                "limits": result.limits.to_dict(),
                "window": {
                    "start": result.window_start.isoformat(),
                    "end": result.window_end.isoformat(),
                },
                "edge_filter": "status == COMPLETED",
                "service_version": GRAPH_SERVICE_VERSION,
            },
            max_items=40,
        ),
        node_count=len(result.nodes),
        edge_count=len(result.edges),
        metrics_json=sanitize_json(
            result.metrics | {"cycle_count": len(result.cycles)}, max_items=40
        ),
        paths_json=sanitize_json(
            [
                *(
                    {"kind": "trail", **trail}
                    for trail in result.trails[:25]
                ),
                *(
                    {"kind": "cycle", **cycle}
                    for cycle in result.cycles[:25]
                ),
            ],
            max_items=60,
        ),
        capped=result.was_capped,
        limitations_json={
            "capped": {k: v for k, v in result.capped.items() if v},
            "limits": result.limits.to_dict(),
            "interpretation": [
                "Paths are candidate fund flows, not proven transfers of the "
                "same funds. Money is fungible; a path shows that value could "
                "have moved along it.",
                "Only COMPLETED transfers are edges. Failed and reversed "
                "transactions are excluded.",
                "A capped result is incomplete: absence of a path does not mean "
                "no path exists.",
                "Graph position is an investigative lead, not proof of "
                "involvement.",
            ],
        },
        created_by=created_by,
    )
    db.add(record)
    db.flush()
    return record


def get_graph_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the graph service.
    """
    defaults = GraphLimits()
    return {
        "service": "muleguard.backend.services.graph",
        "version": GRAPH_SERVICE_VERSION,
        "default_limits": defaults.to_dict(),
        "edge_definition": "COMPLETED transactions only, within the date span",
        "guarantees": [
            "Every traversal is bounded before it starts.",
            "Cycle and trail enumeration carry a per-path visited set, so a "
            "cyclic graph cannot cause unbounded recursion.",
            "Truncation is recorded in `capped` rather than hidden.",
            "Only cycles through the root account are reported.",
        ],
    }
