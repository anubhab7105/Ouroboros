"""
MULEGUARD report limitations text.

The canonical wording that accompanies every exported report, kept in one place
so the PDF renderer, the API's limitations endpoint, and the frontend all quote
the same text.

This is not boilerplate. A report that lists accounts under headings like
"high risk" and "suspicious network" will be read by someone who did not run
the analysis, and may be attached to a referral. The limitations section is what
stops a prioritisation signal from being read as a finding of fact.

The rules this text enforces:

- A score ranks attention, it is not a probability of guilt.
- Synthetic data is not calibrated to real base rates.
- A path shows that value *could* have moved, not that specific funds did.
- A shared device is an association, not shared control.
- A truncated traversal means absence of evidence, not evidence of absence.
- Nothing here authorises an automatic action against an account.
"""

from __future__ import annotations

from typing import Any, Final

__all__ = [
    "CORE_LIMITATIONS",
    "DATA_LIMITATIONS",
    "GRAPH_LIMITATIONS",
    "LIMITATIONS_VERSION",
    "MODEL_LIMITATIONS",
    "PROHIBITED_USES",
    "SCORE_SEMANTICS",
    "compose_limitations",
    "get_limitations_metadata",
]

LIMITATIONS_VERSION: Final[str] = "v1"

SCORE_SEMANTICS: Final[str] = (
    "The investigative priority score is a relative ranking signal used to "
    "decide which accounts an analyst should examine first. It is not a "
    "probability that a crime occurred, not a measure of an account holder's "
    "character or creditworthiness, and not a decision."
)

CORE_LIMITATIONS: Final[tuple[str, ...]] = (
    "Risk scores rank accounts for analyst attention. They are not "
    "probabilities of criminal guilt.",
    "Alerts, correlations, graph relationships and candidate money trails are "
    "investigative leads. None of them establishes that an account holder "
    "participated in wrongdoing.",
    "A low score is not a clearance. A typology absent from the rule set and "
    "from the training data will not be detected.",
    "Findings require human investigation before any action is taken. This "
    "report authorises nothing on its own.",
)

DATA_LIMITATIONS: Final[tuple[str, ...]] = (
    "The underlying dataset is synthetic. Figures are not calibrated against "
    "real-world fraud base rates and must not be used to estimate real "
    "financial exposure.",
    "Only transactions in a COMPLETED state are treated as fund movement. "
    "Failed and reversed transactions are excluded by design.",
    "Features are computed point-in-time: each reflects only what was "
    "knowable at the stated observation instant.",
    "Where data was missing, the affected component was excluded from the "
    "score and the assessment records a caveat. A missing component lowers "
    "confidence in the score, not the underlying risk.",
)

MODEL_LIMITATIONS: Final[tuple[str, ...]] = (
    "Where a trained model contributed, it was trained on synthetic labels. "
    "Its measured performance describes that synthetic distribution only.",
    "Where the transparent heuristic scorer was used, its weights were chosen "
    "for explainability and are not learned from outcomes.",
    "Component weights in risk fusion are a configured product decision, not "
    "a learned optimum, and should be re-tuned against labelled outcomes "
    "before any production use.",
    "A metric that was not computed is reported as unavailable. An absent "
    "metric is never shown as zero.",
)

GRAPH_LIMITATIONS: Final[tuple[str, ...]] = (
    "A candidate money trail shows that value could have moved along a path. "
    "Money is fungible, so it does not establish that specific funds did.",
    "Graph traversal is bounded by configured limits on hops, nodes, edges and "
    "date span. Where a result was truncated the report says so, and the "
    "absence of a path does not mean no path exists.",
    "Shared devices, addresses, phone numbers and payment handles are "
    "associations only. They occur legitimately between family members and "
    "within small businesses.",
    "Network address associations are especially weak: carrier NAT and public "
    "Wi-Fi place unrelated accounts behind a single address.",
)

PROHIBITED_USES: Final[tuple[str, ...]] = (
    "Automatically freezing, blocking, restricting or closing an account.",
    "Taking adverse action against a customer without human investigation and "
    "a recorded disposition.",
    "Presenting a score to a customer, a court or a regulator as a probability "
    "of guilt.",
    "Using a score as a credit, employment, insurance or eligibility signal.",
    "Sharing findings with a third party without this limitations text "
    "attached.",
)


def compose_limitations(
    *,
    synthetic: bool = True,
    include_model: bool = True,
    include_graph: bool = True,
    graph_capped: bool = False,
    scoring_mode: str | None = None,
    extra: tuple[str, ...] = (),
) -> list[str]:
    """
    Compose the limitations list for one report.

    Tailored to the report's contents: claiming limitations that do not apply
    trains readers to skip the section, which defeats its purpose.
    """
    out: list[str] = list(CORE_LIMITATIONS)

    if synthetic:
        out.extend(DATA_LIMITATIONS)
    else:
        out.extend(DATA_LIMITATIONS[1:])

    if include_model:
        out.extend(MODEL_LIMITATIONS)

    if scoring_mode == "RULES_ONLY":
        out.append(
            "This report's scores came from rule evaluation alone; no model "
            "component contributed."
        )
    elif scoring_mode == "HEURISTIC_FALLBACK":
        out.append(
            "This report's scores used the transparent heuristic scorer "
            "because no validated trained model was active."
        )

    if include_graph:
        out.extend(GRAPH_LIMITATIONS)

    if graph_capped:
        out.append(
            "At least one graph result in this report was truncated by a "
            "configured limit and is therefore incomplete."
        )

    out.extend(str(item) for item in extra if str(item).strip())

    # Preserve order while removing duplicates.
    seen: set[str] = set()
    unique: list[str] = []

    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)

    return unique


def get_limitations_metadata() -> dict[str, Any]:
    """
    Return the full limitations catalogue.

    Served by the API's limitations endpoint so the frontend displays exactly
    the same wording as the PDF, rather than keeping its own copy.
    """
    return {
        "module": "muleguard.backend.reports.limitations",
        "version": LIMITATIONS_VERSION,
        "score_semantics": SCORE_SEMANTICS,
        "core": list(CORE_LIMITATIONS),
        "data": list(DATA_LIMITATIONS),
        "model": list(MODEL_LIMITATIONS),
        "graph": list(GRAPH_LIMITATIONS),
        "prohibited_uses": list(PROHIBITED_USES),
    }
