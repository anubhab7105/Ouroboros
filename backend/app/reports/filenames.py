"""
MULEGUARD report filename construction.

Thin, report-specific layer over `app.utils.filenames`. Report names derive
from user-influenced values — case titles, account identifiers — so they go
through the same sanitisation as any other generated filename, plus the naming
convention report consumers expect.

The convention is `muleguard-<subject>-<slug>-<timestamp>.<ext>`, with the
timestamp last so files sort chronologically within a subject. An investigator
browsing a downloads folder wants that order, not alphabetical by title.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final, Optional

from app.utils.filenames import (
    ALLOWED_EXTENSIONS,
    build_report_filename,
    content_type_for,
    safe_filename,
    timestamp_token,
)
from app.utils.text import slugify

__all__ = [
    "REPORT_EXTENSIONS",
    "attachment_disposition",
    "case_report_filename",
    "account_report_filename",
    "evidence_bundle_filename",
    "get_filenames_metadata",
    "report_content_type",
]

# Report formats MULEGUARD will emit. Narrower than the general allow-list:
# a report is a document, not an archive or a spreadsheet.
REPORT_EXTENSIONS: Final[frozenset[str]] = frozenset({"pdf", "json", "md"})

_DEFAULT_EXTENSION: Final[str] = "pdf"


def _checked_extension(extension: Optional[str]) -> str:
    """
    Resolve a report extension, falling back to PDF.
    """
    token = str(extension or "").strip().lower().lstrip(".")

    if token in REPORT_EXTENSIONS:
        return token

    return _DEFAULT_EXTENSION


def case_report_filename(
    *,
    case_id: Any,
    title: Any = None,
    generated_at: Optional[datetime] = None,
    extension: str = _DEFAULT_EXTENSION,
) -> str:
    """
    Build the filename for a case investigation report.
    """
    return build_report_filename(
        case_id=case_id,
        title=title,
        generated_at=generated_at,
        extension=_checked_extension(extension),
    )


def account_report_filename(
    *,
    account_id: Any,
    generated_at: Optional[datetime] = None,
    extension: str = _DEFAULT_EXTENSION,
) -> str:
    """
    Build the filename for an account risk report.
    """
    return build_report_filename(
        account_id=account_id,
        title="risk-report",
        generated_at=generated_at,
        extension=_checked_extension(extension),
    )


def evidence_bundle_filename(
    *,
    subject_type: str,
    subject_id: Any,
    generated_at: Optional[datetime] = None,
) -> str:
    """
    Build the filename for an exported evidence bundle.
    """
    return safe_filename(
        "-".join(
            [
                "muleguard",
                slugify(subject_type, limit=24, default="subject"),
                slugify(subject_id, limit=32, default="unknown"),
                "evidence",
                timestamp_token(generated_at),
            ]
        ),
        extension="json",
    )


def report_content_type(filename: Any) -> str:
    """
    Return the HTTP content type for a report filename.
    """
    return content_type_for(filename, default="application/pdf")


def attachment_disposition(filename: Any) -> str:
    """
    Build a `Content-Disposition` header value for a download.

    The filename is re-sanitised here even though it was sanitised on
    construction: this value goes into a response header, and a stray newline
    or quote in a header is a response-splitting vector.
    """
    cleaned = safe_filename(filename, extension=_DEFAULT_EXTENSION)
    return f'attachment; filename="{cleaned}"'


def get_filenames_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing report filename handling.
    """
    return {
        "module": "muleguard.backend.reports.filenames",
        "report_extensions": sorted(REPORT_EXTENSIONS),
        "default_extension": _DEFAULT_EXTENSION,
        "general_allow_list": sorted(ALLOWED_EXTENSIONS),
        "convention": "muleguard-<subject>-<slug>-<timestamp>.<ext>",
        "notes": [
            "The timestamp is last so files sort chronologically within a subject.",
            "Filenames are sanitised on construction and again before entering a "
            "response header.",
            "Extensions come from an allow-list; a caller cannot choose an "
            "executable extension.",
        ],
    }
