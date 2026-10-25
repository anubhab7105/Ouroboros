"""
MULEGUARD API schema package.

Pydantic request and response contracts for the versioned API.

Conventions every module here follows, set in `common` and `pagination`:

- **Requests forbid unknown fields.** A misspelled filter is rejected rather
  than ignored, because silently dropping it returns unfiltered results that
  the caller believes were filtered.
- **Responses ignore unknown fields,** so adding a field to a service result
  never breaks serialisation.
- **Page size is capped server-side.** A request for 100,000 rows gets 200.
- **Decimals serialise as JSON numbers,** so a client does arithmetic without
  parsing strings.
- **Datetimes are timezone-aware UTC** in both directions; a naive value is
  interpreted as UTC, never as server-local time.

Two rules are about honesty rather than mechanics, and they are the reason
several response models look more verbose than they need to:

1. **Interpretation limits travel with the data.** Any response conveying a
   risk judgement carries `caveats`, and every report carries `limitations`.
   A score detached from the knowledge that the model was unavailable, the
   weights were renormalised, and the data is synthetic is a number a reader
   will over-trust.
2. **Absent is not zero.** A metric that was not computed is reported as
   unavailable with a reason. A truncated result says it was truncated. A
   capped traversal says so, because "no path found" and "we stopped looking"
   are different answers.
"""

from __future__ import annotations

from typing import Any, Final

from app.schemas import (
    accounts,
    alerts,
    analysis,
    audit,
    auth,
    cases,
    common,
    complaints,
    dashboard,
    entities,
    features,
    graph,
    ingestion,
    model_metrics,
    pagination,
    reports,
    transactions,
    users,
)

SCHEMAS_VERSION: Final[str] = "v1"

__all__ = [
    "SCHEMAS_VERSION",
    "accounts",
    "alerts",
    "analysis",
    "audit",
    "auth",
    "cases",
    "common",
    "complaints",
    "dashboard",
    "entities",
    "features",
    "get_schemas_metadata",
    "graph",
    "ingestion",
    "model_metrics",
    "pagination",
    "reports",
    "transactions",
    "users",
]


def get_schemas_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the schema package.
    """
    return {
        "package": "muleguard.backend.schemas",
        "version": SCHEMAS_VERSION,
        "modules": [
            "accounts",
            "alerts",
            "analysis",
            "audit",
            "auth",
            "cases",
            "common",
            "complaints",
            "dashboard",
            "entities",
            "features",
            "graph",
            "ingestion",
            "model_metrics",
            "pagination",
            "reports",
            "transactions",
            "users",
        ],
        "pagination": {
            "default_page_size": pagination.DEFAULT_PAGE_SIZE,
            "max_page_size": pagination.MAX_PAGE_SIZE,
        },
        "conventions": [
            "Requests forbid unknown fields; responses ignore them.",
            "Page size is capped server-side.",
            "Decimals serialise as JSON numbers.",
            "Datetimes are timezone-aware UTC; naive values are read as UTC.",
            "Responses conveying a risk judgement carry caveats.",
            "An uncomputed metric is reported as unavailable, never as zero.",
            "A truncated or capped result always says so.",
        ],
        "forbidden_feature_names": sorted(features.FORBIDDEN_FEATURE_NAMES),
    }
