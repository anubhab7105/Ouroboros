"""
MULEGUARD report evidence index.

Builds the index of every record a report cites, grouped by type, so a reader
can take any claim in the document and look up the record behind it.

Why this exists as its own section rather than inline citations: a reader
checking a report works backwards from a conclusion to its sources. Inline
references alone force them to scan the whole document to collect what they
need to pull. The index is also the manifest for an evidence export.

Each entry records whether the reference actually resolves. An unresolvable
reference is reported as such rather than dropped: silently omitting it would
hide a data problem, and a reader who cannot find a cited record deserves to
know that the system cannot either.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final, Optional

from app.reports.layout import ROW_LIMITS
from app.utils.ids import parse_evidence_ref

__all__ = [
    "EVIDENCE_TYPE_LABELS",
    "EvidenceIndexEntry",
    "build_evidence_index",
    "get_evidence_index_metadata",
    "summarize_evidence_index",
]

# Human-readable labels, and the plural form used as a group heading.
EVIDENCE_TYPE_LABELS: Final[dict[str, tuple[str, str]]] = {
    "ACCOUNT": ("Account", "Accounts"),
    "TRANSACTION": ("Transaction", "Transactions"),
    "COMPLAINT": ("Complaint", "Complaints"),
    "ALERT": ("Alert", "Alerts"),
    "GRAPH_PATH": ("Network analysis", "Network analyses"),
    "MODEL_ASSESSMENT": ("Risk assessment", "Risk assessments"),
    "ENTITY_LINK": ("Entity link", "Entity links"),
}

# Order groups the way an investigator reads them: the subject first, then the
# movement, then the corroboration, then the derived analysis.
_GROUP_ORDER: Final[tuple[str, ...]] = (
    "ACCOUNT",
    "TRANSACTION",
    "COMPLAINT",
    "ENTITY_LINK",
    "ALERT",
    "MODEL_ASSESSMENT",
    "GRAPH_PATH",
)

_MAX_ENTRIES: Final[int] = ROW_LIMITS["max_evidence_index_entries"]


class EvidenceIndexEntry:
    """
    One cited record in the evidence index.
    """

    __slots__ = ("cited_in", "evidence_id", "evidence_type", "reference", "resolved")

    def __init__(
        self,
        *,
        evidence_type: str,
        evidence_id: str,
        reference: str,
        cited_in: Optional[Sequence[str]] = None,
        resolved: Optional[bool] = None,
    ) -> None:
        self.evidence_type = str(evidence_type)
        self.evidence_id = str(evidence_id)
        self.reference = str(reference)
        self.cited_in = list(cited_in or [])
        self.resolved = resolved

    @property
    def label(self) -> str:
        """
        Human-readable type label.
        """
        return EVIDENCE_TYPE_LABELS.get(self.evidence_type, (self.evidence_type, self.evidence_type))[0]

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation.
        """
        return {
            "evidence_type": self.evidence_type,
            "evidence_id": self.evidence_id,
            "reference": self.reference,
            "label": self.label,
            "cited_in": self.cited_in,
            "resolved": self.resolved,
        }

    def __repr__(self) -> str:
        return f"EvidenceIndexEntry({self.reference!r}, resolved={self.resolved})"


def build_evidence_index(
    sections: Iterable[Any],
    *,
    resolver: Optional[Any] = None,
    max_entries: int = _MAX_ENTRIES,
) -> list[EvidenceIndexEntry]:
    """
    Build the evidence index from a report's sections.

    `sections` accepts `ReportSection` objects or mappings with `title` and
    `evidence_refs`. `resolver`, when given, is called as
    `resolver(evidence_type, evidence_id) -> bool` to mark whether each
    reference resolves to a real record.
    """
    by_reference: dict[str, EvidenceIndexEntry] = {}

    for section in sections:
        if isinstance(section, Mapping):
            title = str(section.get("title") or "")
            references = section.get("evidence_refs") or []
        else:
            title = str(getattr(section, "title", "") or "")
            references = getattr(section, "evidence_refs", []) or []

        for raw in references:
            reference = str(raw or "").strip()

            if not reference:
                continue

            evidence_type, evidence_id = parse_evidence_ref(reference)

            if evidence_type is None or evidence_id is None:
                # Malformed references are skipped rather than indexed: there
                # is nothing a reader could look up.
                continue

            entry = by_reference.get(reference)

            if entry is None:
                if len(by_reference) >= max_entries:
                    continue

                entry = EvidenceIndexEntry(
                    evidence_type=evidence_type,
                    evidence_id=evidence_id,
                    reference=reference,
                )
                by_reference[reference] = entry

            if title and title not in entry.cited_in:
                entry.cited_in.append(title)

    entries = list(by_reference.values())

    if resolver is not None:
        for entry in entries:
            try:
                entry.resolved = bool(resolver(entry.evidence_type, entry.evidence_id))
            except Exception:
                # A resolver failure must not break report generation; unknown
                # is more honest than assuming resolved.
                entry.resolved = None

    def sort_key(item: EvidenceIndexEntry) -> tuple[int, str]:
        order = (
            _GROUP_ORDER.index(item.evidence_type)
            if item.evidence_type in _GROUP_ORDER
            else len(_GROUP_ORDER)
        )
        return order, item.evidence_id

    entries.sort(key=sort_key)
    return entries


def summarize_evidence_index(
    entries: Sequence[EvidenceIndexEntry],
) -> dict[str, Any]:
    """
    Summarise an evidence index for the report footer and the API.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    unresolved = 0
    unknown = 0

    for entry in entries:
        plural = EVIDENCE_TYPE_LABELS.get(
            entry.evidence_type, (entry.evidence_type, entry.evidence_type)
        )[1]
        groups.setdefault(plural, []).append(entry.to_dict())

        if entry.resolved is False:
            unresolved += 1
        elif entry.resolved is None:
            unknown += 1

    return {
        "total_entries": len(entries),
        "groups": groups,
        "counts_by_type": {
            label: len(items) for label, items in sorted(groups.items())
        },
        "unresolved_count": unresolved,
        "unverified_count": unknown,
        "integrity_note": (
            "Every cited record resolved."
            if unresolved == 0 and unknown == 0
            else (
                f"{unresolved} cited record(s) could not be resolved and "
                f"{unknown} could not be checked. A reader should treat the "
                "affected claims as unverified."
            )
        ),
        "truncated": len(entries) >= _MAX_ENTRIES,
    }


def get_evidence_index_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the evidence index.
    """
    return {
        "module": "muleguard.backend.reports.evidence_index",
        "supported_types": sorted(EVIDENCE_TYPE_LABELS),
        "group_order": list(_GROUP_ORDER),
        "max_entries": _MAX_ENTRIES,
        "notes": [
            "References are grouped so a reader can work backwards from a "
            "claim to the record behind it.",
            "An unresolvable reference is reported, not dropped: hiding it "
            "would conceal a data problem.",
            "Malformed references are skipped because there is nothing to "
            "look up.",
        ],
    }
