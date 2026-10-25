"""
MULEGUARD report section preparation.

Turns a `ReportDocument` from `app.services.reports` into render-ready blocks:
bounded tables, wrapped cell text, formatted numbers, and the standard header,
limitations and footer blocks.

This sits between data gathering and PDF rendering so that the bounds and the
formatting rules are testable without ReportLab installed, and so an HTML or
Markdown exporter could reuse them unchanged.

What it guarantees to the renderer:

- No table exceeds the configured row and column limits.
- No cell exceeds the character limit, so a long narrative cannot push a table
  off the page.
- Amounts, scores and timestamps are formatted once, consistently.
- Every table that was truncated says so in its own caption; a silently
  shortened table would misrepresent the data.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final, Optional

from app.reports.layout import BAND_COLORS, ROW_LIMITS, SEVERITY_COLORS
from app.utils.dates import ensure_utc, parse_datetime
from app.utils.decimals import to_float
from app.utils.text import clean_text, title_case, truncate

__all__ = [
    "PreparedSection",
    "PreparedTable",
    "band_color",
    "format_amount",
    "format_cell",
    "format_score",
    "format_timestamp",
    "prepare_document",
    "prepare_section",
    "severity_color",
]

_MAX_ROWS: Final[int] = ROW_LIMITS["max_rows_per_table"]
_MAX_COLS: Final[int] = ROW_LIMITS["max_columns_per_table"]
_MAX_CELL: Final[int] = ROW_LIMITS["max_cell_chars"]
_MAX_SECTIONS: Final[int] = ROW_LIMITS["max_sections"]

# Column name fragments that select a formatter.
_AMOUNT_HINTS: Final[tuple[str, ...]] = ("amount", "value", "balance", "sum")
_SCORE_HINTS: Final[tuple[str, ...]] = ("score", "confidence", "ratio", "share")
_TIME_HINTS: Final[tuple[str, ...]] = ("_at", "timestamp", "as_of", "occurred", "date")


def format_timestamp(value: Any, *, with_time: bool = True) -> str:
    """
    Format a timestamp for display.

    Rendered as `YYYY-MM-DD HH:MM UTC`: unambiguous for an international
    reader, and the timezone is stated because a bare timestamp in a financial
    report is a reconciliation hazard.
    """
    moment = (
        ensure_utc(value) if isinstance(value, datetime) else ensure_utc(parse_datetime(value))
    )

    if moment is None:
        return ""

    return moment.strftime("%Y-%m-%d %H:%M UTC" if with_time else "%Y-%m-%d")


def format_amount(value: Any, currency: Optional[str] = None) -> str:
    """
    Format a monetary amount with thousands separators and two decimals.
    """
    numeric = to_float(value)

    if numeric is None:
        return ""

    rendered = f"{numeric:,.2f}"
    return f"{rendered} {currency.upper()}" if currency else rendered


def format_score(value: Any, *, scale: int = 100) -> str:
    """
    Format a score or a 0..1 ratio.
    """
    numeric = to_float(value)

    if numeric is None:
        return ""

    if scale == 100 and numeric > 1.0:
        return f"{numeric:.1f}"

    return f"{numeric:.3f}".rstrip("0").rstrip(".")


def band_color(band: Any) -> str:
    """
    Return the hex colour for a risk band.
    """
    token = str(getattr(band, "value", band) or "").strip().upper()
    return BAND_COLORS.get(token, BAND_COLORS["UNKNOWN"])


def severity_color(severity: Any) -> str:
    """
    Return the hex colour for a severity.
    """
    token = str(getattr(severity, "value", severity) or "").strip().upper()
    return SEVERITY_COLORS.get(token, SEVERITY_COLORS["LOW"])


def format_cell(column: str, value: Any) -> str:
    """
    Format one cell, choosing a formatter from the column name.
    """
    if value is None:
        return ""

    if isinstance(value, bool):
        return "yes" if value else "no"

    name = str(column).lower()

    if any(hint in name for hint in _TIME_HINTS):
        rendered = format_timestamp(value)

        if rendered:
            return rendered

    if any(hint in name for hint in _AMOUNT_HINTS):
        rendered = format_amount(value)

        if rendered:
            return rendered

    if any(hint in name for hint in _SCORE_HINTS):
        rendered = format_score(value)

        if rendered:
            return rendered

    if isinstance(value, (list, tuple)):
        return truncate(", ".join(str(item) for item in value), _MAX_CELL)

    if isinstance(value, Mapping):
        return truncate(
            ", ".join(f"{k}={v}" for k, v in list(value.items())[:6]), _MAX_CELL
        )

    return truncate(clean_text(value, _MAX_CELL), _MAX_CELL)


class PreparedTable:
    """
    A bounded, formatted table ready to render.
    """

    __slots__ = ("caption", "columns", "headers", "rows", "truncated_columns", "truncated_rows")

    def __init__(
        self,
        *,
        columns: Sequence[str],
        rows: Sequence[Sequence[str]],
        headers: Sequence[str],
        truncated_rows: int = 0,
        truncated_columns: int = 0,
        caption: Optional[str] = None,
    ) -> None:
        self.columns = list(columns)
        self.headers = list(headers)
        self.rows = [list(row) for row in rows]
        self.truncated_rows = int(truncated_rows)
        self.truncated_columns = int(truncated_columns)
        self.caption = caption

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation.
        """
        return {
            "columns": self.columns,
            "headers": self.headers,
            "rows": self.rows,
            "truncated_rows": self.truncated_rows,
            "truncated_columns": self.truncated_columns,
            "caption": self.caption,
        }


class PreparedSection:
    """
    A render-ready section.
    """

    __slots__ = ("evidence_count", "kind", "notes", "summary", "table", "title")

    def __init__(
        self,
        *,
        title: str,
        kind: str,
        summary: Optional[str] = None,
        table: Optional[PreparedTable] = None,
        notes: Optional[Sequence[str]] = None,
        evidence_count: int = 0,
    ) -> None:
        self.title = str(title)
        self.kind = str(kind)
        self.summary = summary
        self.table = table
        self.notes = list(notes or [])
        self.evidence_count = int(evidence_count)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation.
        """
        return {
            "title": self.title,
            "kind": self.kind,
            "summary": self.summary,
            "table": self.table.to_dict() if self.table is not None else None,
            "notes": self.notes,
            "evidence_count": self.evidence_count,
        }


def _resolve_columns(section: Any, rows: Sequence[Mapping[str, Any]]) -> list[str]:
    """
    Determine a section's column order.

    Explicit columns win. Otherwise the union of the row keys is used, in
    first-seen order so the natural field order survives.
    """
    declared = list(getattr(section, "columns", None) or [])

    if isinstance(section, Mapping):
        declared = list(section.get("columns") or [])

    if declared:
        return declared

    seen: list[str] = []

    for row in rows:
        for key in row:
            if key not in seen:
                seen.append(str(key))

    return seen


def prepare_section(section: Any) -> PreparedSection:
    """
    Prepare one section for rendering.
    """
    if isinstance(section, Mapping):
        title = str(section.get("title") or "")
        kind = str(section.get("kind") or "table")
        summary = section.get("summary")
        rows = list(section.get("rows") or [])
        notes = list(section.get("notes") or [])
        evidence = list(section.get("evidence_refs") or [])
    else:
        title = str(getattr(section, "title", "") or "")
        kind = str(getattr(section, "kind", "table") or "table")
        summary = getattr(section, "summary", None)
        rows = list(getattr(section, "rows", []) or [])
        notes = list(getattr(section, "notes", []) or [])
        evidence = list(getattr(section, "evidence_refs", []) or [])

    mapping_rows = [row for row in rows if isinstance(row, Mapping)]
    columns = _resolve_columns(section, mapping_rows)

    truncated_columns = max(0, len(columns) - _MAX_COLS)
    columns = columns[:_MAX_COLS]

    truncated_rows = max(0, len(mapping_rows) - _MAX_ROWS)
    visible_rows = mapping_rows[:_MAX_ROWS]

    table: Optional[PreparedTable] = None

    if columns and visible_rows:
        caption_parts: list[str] = []

        if truncated_rows:
            caption_parts.append(
                f"{truncated_rows} further row(s) omitted for length"
            )

        if truncated_columns:
            caption_parts.append(
                f"{truncated_columns} further column(s) omitted for width"
            )

        table = PreparedTable(
            columns=columns,
            headers=[title_case(column) for column in columns],
            rows=[
                [format_cell(column, row.get(column)) for column in columns]
                for row in visible_rows
            ],
            truncated_rows=truncated_rows,
            truncated_columns=truncated_columns,
            caption="; ".join(caption_parts) or None,
        )

    return PreparedSection(
        title=title,
        kind=kind,
        summary=clean_text(summary or "", 2_000) or None,
        table=table,
        notes=notes,
        evidence_count=len(evidence),
    )


def prepare_document(document: Any) -> dict[str, Any]:
    """
    Prepare a whole report document for rendering.

    Returns the header fields, the prepared sections, the limitations, and the
    footer data the renderer needs.
    """
    if isinstance(document, Mapping):
        payload = dict(document)
        raw_sections = list(payload.get("sections") or [])
    else:
        payload = document.to_dict() if hasattr(document, "to_dict") else {}
        raw_sections = list(getattr(document, "sections", []) or [])

    truncated_sections = max(0, len(raw_sections) - _MAX_SECTIONS)
    prepared = [prepare_section(section) for section in raw_sections[:_MAX_SECTIONS]]

    return {
        "header": {
            "title": str(payload.get("title") or ""),
            "subtitle": payload.get("subtitle"),
            "subject_type": payload.get("subject_type"),
            "subject_id": payload.get("subject_id"),
            "generated_at": format_timestamp(payload.get("generated_at")),
            "generated_by": payload.get("generated_by") or "system",
        },
        "sections": [section.to_dict() for section in prepared],
        "limitations": [str(item) for item in (payload.get("limitations") or [])],
        "evidence_index": list(payload.get("evidence_index") or []),
        "footer": {
            "content_fingerprint": payload.get("content_fingerprint"),
            "section_count": len(prepared),
            "truncated_sections": truncated_sections,
        },
        "notes": (
            [
                f"{truncated_sections} further section(s) omitted; the report "
                "exceeded the configured section limit."
            ]
            if truncated_sections
            else []
        ),
    }
