"""
MULEGUARD report layout constants.

Page geometry, typography, and the palette used by the PDF renderer. Kept
separate from the rendering code so the look can be adjusted without touching
layout logic, and so the same constants drive both the PDF and any future HTML
export.

Choices worth noting:

- **A4, not Letter.** The deployment context is Indian financial crime
  investigation, where A4 is standard. Letter would print with wrong margins.
- **Risk band colours are not a traffic light.** CRITICAL is deep red and LOW
  is slate grey rather than green: a low score is "not prioritised", not
  "cleared", and green would say the wrong thing.
- **Band colours are paired with a text label everywhere.** Roughly one in
  twelve men has a colour vision deficiency, so colour alone must never carry
  the meaning.
"""

from __future__ import annotations

from typing import Any, Final

__all__ = [
    "BAND_COLORS",
    "BASE_FONT",
    "BOLD_FONT",
    "COLORS",
    "FONT_SIZES",
    "MARGINS",
    "MONO_FONT",
    "PAGE_SIZE_NAME",
    "ROW_LIMITS",
    "SEVERITY_COLORS",
    "SPACING",
    "TABLE_STYLE_TOKENS",
    "get_layout_metadata",
]

PAGE_SIZE_NAME: Final[str] = "A4"

# Millimetres. ReportLab works in points; the renderer converts.
MARGINS: Final[dict[str, float]] = {
    "top": 18.0,
    "bottom": 20.0,
    "left": 16.0,
    "right": 16.0,
    # Extra room at the bottom for the footer rule, page number and fingerprint.
    "footer": 12.0,
    "header": 10.0,
}

# Helvetica is one of ReportLab's 14 built-in fonts, so no font file has to
# ship with the image and rendering cannot fail on a missing font.
BASE_FONT: Final[str] = "Helvetica"
BOLD_FONT: Final[str] = "Helvetica-Bold"
MONO_FONT: Final[str] = "Courier"

FONT_SIZES: Final[dict[str, float]] = {
    "title": 18.0,
    "subtitle": 11.0,
    "section": 12.5,
    "body": 9.0,
    "table": 7.8,
    "table_header": 8.0,
    "caption": 7.2,
    "footer": 7.0,
    "mono": 7.5,
}

SPACING: Final[dict[str, float]] = {
    "after_title": 4.0,
    "after_subtitle": 10.0,
    "before_section": 11.0,
    "after_section": 5.0,
    "after_table": 8.0,
    "after_paragraph": 5.0,
    "leading_ratio": 1.35,
}

# Neutral, print-safe palette. Hex strings; the renderer converts to colours.
COLORS: Final[dict[str, str]] = {
    "ink": "#1A1D21",
    "muted": "#5B6470",
    "faint": "#8B95A1",
    "rule": "#C9D1DA",
    "panel": "#F2F5F8",
    "panel_alt": "#E7ECF1",
    "accent": "#1F4E79",
    "warning_bg": "#FDF3E3",
    "warning_border": "#D9A33C",
    "white": "#FFFFFF",
}

# Deliberately not a red/amber/green scale: see the module docstring.
BAND_COLORS: Final[dict[str, str]] = {
    "CRITICAL": "#8C1D18",
    "HIGH": "#B3541E",
    "MEDIUM": "#8A6D1F",
    "LOW": "#5B6470",
    "UNKNOWN": "#8B95A1",
}

SEVERITY_COLORS: Final[dict[str, str]] = {
    "CRITICAL": "#8C1D18",
    "HIGH": "#B3541E",
    "MEDIUM": "#8A6D1F",
    "LOW": "#5B6470",
}

# Bounds so one enormous section cannot produce a thousand-page document.
ROW_LIMITS: Final[dict[str, int]] = {
    "max_rows_per_table": 60,
    "max_columns_per_table": 8,
    "max_cell_chars": 160,
    "max_sections": 20,
    "max_pages_estimate": 60,
    "max_evidence_index_entries": 300,
}

TABLE_STYLE_TOKENS: Final[dict[str, Any]] = {
    "header_background": COLORS["panel_alt"],
    "header_text": COLORS["ink"],
    "row_background": COLORS["white"],
    "row_background_alt": COLORS["panel"],
    "grid_color": COLORS["rule"],
    "grid_width": 0.4,
    "cell_padding": 3.0,
    "valign": "TOP",
}


def get_layout_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the report layout.
    """
    return {
        "module": "muleguard.backend.reports.layout",
        "page_size": PAGE_SIZE_NAME,
        "margins_mm": dict(MARGINS),
        "fonts": {"base": BASE_FONT, "bold": BOLD_FONT, "mono": MONO_FONT},
        "font_sizes": dict(FONT_SIZES),
        "row_limits": dict(ROW_LIMITS),
        "accessibility_notes": [
            "Risk bands are always rendered with a text label, never colour alone.",
            "The band scale avoids red/amber/green: a low score is not a clearance.",
            "Only ReportLab built-in fonts are used, so rendering cannot fail on "
            "a missing font file.",
        ],
    }
