"""
MULEGUARD report rendering package.

Turns the structured report documents built by `app.services.reports` into
exportable artifacts.

Layering, and why it is split this way:

    services.reports   decides WHAT goes in a report (queries, evidence refs)
    reports.sections   decides HOW it is shaped (bounds, formatting)
    reports.layout     decides how it LOOKS (geometry, type, palette)
    reports.pdf        renders it (ReportLab)

Only `reports.pdf` touches ReportLab, and it imports it lazily. Everything
else in this package works without a PDF engine installed, so report data
assembly stays testable and usable from scripts.

`reports.limitations` holds the canonical wording that accompanies every
export, in one place so the PDF, the API's limitations endpoint and the
frontend all quote identical text. `reports.evidence_index` builds the manifest
of cited records that makes a claim checkable.
"""

from __future__ import annotations

from typing import Any, Final

from app.reports import evidence_index, filenames, layout, limitations, sections

REPORTS_PACKAGE_VERSION: Final[str] = "v1"

__all__ = [
    "REPORTS_PACKAGE_VERSION",
    "evidence_index",
    "filenames",
    "get_reports_metadata",
    "is_pdf_available",
    "layout",
    "limitations",
    "render_pdf",
    "sections",
]


def is_pdf_available() -> bool:
    """
    Return True when PDF rendering is possible in this deployment.
    """
    from app.reports.pdf import is_pdf_available as _available

    return _available()


def render_pdf(document: Any, **kwargs: Any) -> bytes:
    """
    Render a report document to PDF bytes.

    Imported lazily so that `import app.reports` does not require ReportLab.
    """
    from app.reports.pdf import render_pdf as _render

    return _render(document, **kwargs)


def get_reports_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the report package.
    """
    from app.reports.pdf import get_pdf_metadata

    return {
        "package": "muleguard.backend.reports",
        "version": REPORTS_PACKAGE_VERSION,
        "layout": layout.get_layout_metadata(),
        "limitations": {
            "version": limitations.LIMITATIONS_VERSION,
            "core_count": len(limitations.CORE_LIMITATIONS),
            "prohibited_uses": list(limitations.PROHIBITED_USES),
        },
        "evidence_index": evidence_index.get_evidence_index_metadata(),
        "filenames": filenames.get_filenames_metadata(),
        "pdf": get_pdf_metadata(),
        "boundaries": [
            "Only reports.pdf imports ReportLab, and it does so lazily.",
            "Report data assembly works without a PDF engine installed.",
            "Limitations wording is defined once and shared by the PDF, the "
            "API and the frontend.",
        ],
    }
