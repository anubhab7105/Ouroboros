"""
MULEGUARD PDF renderer.

Renders a prepared report document to PDF bytes with ReportLab.

ReportLab is imported lazily inside `render_pdf`. The rest of this module —
and everything that imports it — therefore works without ReportLab installed,
which matters because report *data* assembly is used by tests and scripts that
have no need for a PDF engine. When ReportLab is genuinely missing, the caller
gets `ReportGenerationError` with a clear reason rather than an ImportError
from somewhere deep in a request.

Rendering choices:

- Only ReportLab's built-in fonts are used, so no font file ships with the
  image and rendering cannot fail on a missing font.
- Every page carries the subject, the page number, and the content fingerprint
  in the footer. A loose page from a printed report stays traceable.
- The limitations section is rendered on the **first** page, not as an appendix.
  A reader who stops after page one must still see what the scores mean.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Mapping, Sequence
from typing import Any, Final, Optional

from app.exceptions import ReportGenerationError, ServiceUnavailableError
from app.reports.layout import (
    BASE_FONT,
    BOLD_FONT,
    COLORS,
    FONT_SIZES,
    MARGINS,
    MONO_FONT,
    ROW_LIMITS,
    SPACING,
)
from app.reports.sections import prepare_document

logger = logging.getLogger("muleguard.backend.reports.pdf")

__all__ = [
    "PDF_RENDERER_VERSION",
    "estimate_pages",
    "get_pdf_metadata",
    "is_pdf_available",
    "render_pdf",
]

PDF_RENDERER_VERSION: Final[str] = "v1"

_MAX_PAGES: Final[int] = ROW_LIMITS["max_pages_estimate"]


def is_pdf_available() -> bool:
    """
    Return True when ReportLab can be imported.
    """
    try:
        import reportlab  # noqa: F401

        return True
    except Exception:
        return False


def estimate_pages(prepared: Mapping[str, Any]) -> int:
    """
    Roughly estimate the page count of a prepared document.

    Used to refuse an unreasonably large render before spending the time on
    it. Deliberately approximate: it only has to catch the pathological case.
    """
    # ~46 table rows fit on an A4 page at the configured table font size.
    rows_per_page = 46.0
    total_rows = 0.0

    for section in prepared.get("sections") or []:
        table = section.get("table") if isinstance(section, Mapping) else None
        total_rows += 3.0  # heading + spacing

        if isinstance(table, Mapping):
            total_rows += 1.0 + len(table.get("rows") or [])

    # Limitations and the evidence index add their own pages.
    total_rows += len(prepared.get("limitations") or []) * 1.6
    total_rows += len(prepared.get("evidence_index") or []) * 0.5

    return max(1, int(total_rows / rows_per_page) + 1)


def render_pdf(
    document: Any,
    *,
    include_evidence_index: bool = True,
    max_pages: int = _MAX_PAGES,
) -> bytes:
    """
    Render a report document to PDF bytes.

    `document` is a `ReportDocument` from `app.services.reports` or an
    equivalent mapping.

    Raises ServiceUnavailableError when ReportLab is not installed, and
    ReportGenerationError when the document is too large or rendering fails.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except Exception as exc:
        raise ServiceUnavailableError(
            "PDF rendering is unavailable because ReportLab is not installed. "
            "Install backend requirements, or request the report as JSON.",
            details={"missing_dependency": "reportlab"},
        ) from exc

    prepared = prepare_document(document)
    estimated = estimate_pages(prepared)

    if estimated > max_pages:
        raise ReportGenerationError(
            "The report is too large to render. Narrow the date range or the "
            "number of sections.",
            details={"estimated_pages": estimated, "max_pages": max_pages},
        )

    header = prepared["header"]
    footer = prepared["footer"]
    subject_label = f"{header.get('subject_type') or 'report'} {header.get('subject_id') or ''}".strip()
    fingerprint = str(footer.get("content_fingerprint") or "")[:16]

    buffer = io.BytesIO()
    base = getSampleStyleSheet()

    def style(
        name: str,
        size: float,
        *,
        font: str = BASE_FONT,
        color: str = COLORS["ink"],
        space_after: float = 0.0,
        leading: Optional[float] = None,
    ) -> Any:
        return ParagraphStyle(
            name=name,
            parent=base["Normal"],
            fontName=font,
            fontSize=size,
            leading=leading or size * SPACING["leading_ratio"],
            textColor=colors.HexColor(color),
            spaceAfter=space_after,
            alignment=TA_LEFT,
        )

    title_style = style("mgTitle", FONT_SIZES["title"], font=BOLD_FONT, space_after=SPACING["after_title"])
    subtitle_style = style("mgSubtitle", FONT_SIZES["subtitle"], color=COLORS["muted"], space_after=SPACING["after_subtitle"])
    section_style = style("mgSection", FONT_SIZES["section"], font=BOLD_FONT, space_after=SPACING["after_section"])
    body_style = style("mgBody", FONT_SIZES["body"], space_after=SPACING["after_paragraph"])
    caption_style = style("mgCaption", FONT_SIZES["caption"], color=COLORS["faint"], space_after=4.0)
    note_style = style("mgNote", FONT_SIZES["caption"], color=COLORS["muted"], space_after=3.0)
    mono_style = style("mgMono", FONT_SIZES["mono"], font=MONO_FONT, color=COLORS["muted"])
    cell_style = style("mgCell", FONT_SIZES["table"], leading=FONT_SIZES["table"] * 1.25)
    cell_header_style = style(
        "mgCellHeader", FONT_SIZES["table_header"], font=BOLD_FONT,
        leading=FONT_SIZES["table_header"] * 1.25,
    )

    def draw_chrome(canvas: Any, doc: Any) -> None:
        """
        Draw the footer rule, subject, page number and fingerprint.
        """
        canvas.saveState()
        width, _height = A4
        y = MARGINS["footer"] * mm

        canvas.setStrokeColor(colors.HexColor(COLORS["rule"]))
        canvas.setLineWidth(0.4)
        canvas.line(
            MARGINS["left"] * mm,
            y + 4 * mm,
            width - MARGINS["right"] * mm,
            y + 4 * mm,
        )

        canvas.setFont(BASE_FONT, FONT_SIZES["footer"])
        canvas.setFillColor(colors.HexColor(COLORS["faint"]))
        canvas.drawString(
            MARGINS["left"] * mm,
            y,
            f"MULEGUARD - {subject_label} - investigative leads only, not a finding of guilt",
        )
        canvas.drawRightString(
            width - MARGINS["right"] * mm,
            y,
            f"page {canvas.getPageNumber()}" + (f" - {fingerprint}" if fingerprint else ""),
        )
        canvas.restoreState()

    story: list[Any] = [
        Paragraph(_escape(header.get("title") or "MULEGUARD report"), title_style)
    ]

    if header.get("subtitle"):
        story.append(Paragraph(_escape(header["subtitle"]), subtitle_style))

    story.append(
        Paragraph(
            _escape(
                f"Generated {header.get('generated_at') or ''} by "
                f"{header.get('generated_by') or 'system'}"
            ),
            caption_style,
        )
    )

    # Limitations go on page one, before the findings: a reader who stops
    # after the first page must still know what the numbers mean.
    limitations = prepared.get("limitations") or []

    if limitations:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("How to read this report", section_style))

        for item in limitations[:14]:
            story.append(Paragraph(f"&bull; {_escape(item)}", note_style))

        story.append(Spacer(1, 3 * mm))

    for section in prepared.get("sections") or []:
        if not isinstance(section, Mapping):
            continue

        block: list[Any] = [
            Spacer(1, SPACING["before_section"]),
            Paragraph(_escape(section.get("title") or ""), section_style),
        ]

        if section.get("summary"):
            block.append(Paragraph(_escape(section["summary"]), body_style))

        table_data = section.get("table")

        if isinstance(table_data, Mapping) and table_data.get("rows"):
            headers = [
                Paragraph(_escape(h), cell_header_style)
                for h in table_data.get("headers") or []
            ]
            body_rows = [
                [Paragraph(_escape(cell), cell_style) for cell in row]
                for row in table_data.get("rows") or []
            ]
            table = Table(
                [headers, *body_rows],
                repeatRows=1,
                hAlign="LEFT",
            )
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(COLORS["panel_alt"])),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor(COLORS["rule"])),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 3),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.HexColor(COLORS["white"]), colors.HexColor(COLORS["panel"])],
                        ),
                    ]
                )
            )
            block.append(table)

            if table_data.get("caption"):
                block.append(Paragraph(_escape(table_data["caption"]), caption_style))

        for note in section.get("notes") or []:
            block.append(Paragraph(_escape(note), note_style))

        # Keep a short section together with its heading; let a long table
        # flow across pages rather than leaving a mostly blank page before it.
        if len(body_rows_len(section)) > 18:
            story.extend(block)
        else:
            story.append(KeepTogether(block))

        story.append(Spacer(1, SPACING["after_table"]))

    evidence_index = prepared.get("evidence_index") or []

    if include_evidence_index and evidence_index:
        story.append(PageBreak())
        story.append(Paragraph("Evidence index", section_style))
        story.append(
            Paragraph(
                "Every record cited in this report. Each reference can be "
                "looked up in the platform to verify the claim it supports.",
                body_style,
            )
        )

        for reference in evidence_index[: ROW_LIMITS["max_evidence_index_entries"]]:
            story.append(Paragraph(_escape(str(reference)), mono_style))

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=MARGINS["top"] * mm,
        bottomMargin=MARGINS["bottom"] * mm,
        leftMargin=MARGINS["left"] * mm,
        rightMargin=MARGINS["right"] * mm,
        title=str(header.get("title") or "MULEGUARD report"),
        author="MULEGUARD",
        subject="Investigative lead report",
        creator=f"MULEGUARD report renderer {PDF_RENDERER_VERSION}",
    )

    try:
        doc.build(story, onFirstPage=draw_chrome, onLaterPages=draw_chrome)
    except Exception as exc:
        logger.exception("PDF rendering failed.")
        raise ReportGenerationError(
            "The report could not be rendered.",
            details={"error_type": type(exc).__name__},
        ) from exc

    return buffer.getvalue()


def body_rows_len(section: Mapping[str, Any]) -> Sequence[Any]:
    """
    Return a section's table rows, or an empty sequence.
    """
    table = section.get("table")

    if isinstance(table, Mapping):
        return table.get("rows") or []

    return []


def _escape(value: Any) -> str:
    """
    Escape text for ReportLab's mini-HTML paragraph markup.

    Report content includes analyst-written notes and complaint narratives, so
    an unescaped `&` or `<` would either corrupt the layout or inject markup.
    """
    text = str(value if value is not None else "")
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def get_pdf_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the PDF renderer.
    """
    return {
        "module": "muleguard.backend.reports.pdf",
        "version": PDF_RENDERER_VERSION,
        "available": is_pdf_available(),
        "engine": "reportlab",
        "max_pages": _MAX_PAGES,
        "notes": [
            "ReportLab is imported lazily, so report data assembly works "
            "without it installed.",
            "Only built-in fonts are used; rendering cannot fail on a missing "
            "font file.",
            "Limitations are rendered on the first page, not as an appendix.",
            "Every page footer carries the subject, page number and content "
            "fingerprint.",
            "All text is escaped before entering ReportLab's paragraph markup.",
        ],
    }
