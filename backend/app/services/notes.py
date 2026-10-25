"""
MULEGUARD case note service.

Investigator notes on a case. Notes are attributed, timestamped, and preserved:
an edit appends a revision to the note's metadata rather than silently
overwriting the body, so the reasoning recorded at the time of a decision stays
readable afterwards.

Notes are the one place in MULEGUARD where an analyst types free text that ends
up in a report, so the body is normalised (paragraph structure preserved) and
passed through redaction before storage. A pasted token or password must not
become a durable record.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import CaseNote, User
from app.utils.dates import ensure_utc, utcnow
from app.utils.json import sanitize_json
from app.utils.text import normalize_whitespace_text, redact

logger = logging.getLogger("muleguard.backend.services.notes")

__all__ = [
    "NOTES_SERVICE_VERSION",
    "add_case_note",
    "count_case_notes",
    "get_case_notes_service_metadata",
    "list_case_notes",
    "update_case_note",
]

NOTES_SERVICE_VERSION: Final[str] = "v1"

_MAX_BODY_LENGTH: Final[int] = 10_000
_MAX_NOTES: Final[int] = 500
_MAX_REVISIONS: Final[int] = 20


def _prepare_body(body: Any) -> str:
    """
    Normalise and redact a note body.

    Paragraph breaks are preserved because losing them changes how a human
    reads the note; everything else is collapsed.
    """
    normalised = normalize_whitespace_text(body, _MAX_BODY_LENGTH)
    return redact(normalised, _MAX_BODY_LENGTH)


def add_case_note(
    db: Session,
    *,
    case_id: str,
    body: str,
    author: Optional[User] = None,
    author_id: Optional[str] = None,
    is_internal: bool = True,
    metadata: Optional[Mapping[str, Any]] = None,
) -> CaseNote:
    """
    Add a note to a case.

    Raises ValueError when the body is empty after normalisation, which also
    satisfies the `ck_case_notes_body_not_empty` CHECK constraint before the
    database has to.
    """
    prepared = _prepare_body(body)

    if not prepared.strip():
        raise ValueError("A case note cannot be empty.")

    resolved_author = author_id or (
        str(getattr(author, "id", "") or "") or None if author is not None else None
    )

    note = CaseNote(
        case_id=str(case_id),
        author_id=resolved_author,
        body=prepared,
        is_internal=bool(is_internal),
        metadata_json=sanitize_json(
            {
                "service_version": NOTES_SERVICE_VERSION,
                **dict(metadata or {}),
            },
            max_items=20,
        ),
    )
    db.add(note)
    db.flush()
    return note


def update_case_note(
    db: Session,
    *,
    note_id: str,
    body: str,
    editor_id: Optional[str] = None,
    reason: Optional[str] = None,
) -> Optional[CaseNote]:
    """
    Replace a note's body, appending the previous text as a revision.

    The prior body is kept in metadata, so the reasoning recorded at the time
    of a decision is still readable after a correction.
    """
    note = db.get(CaseNote, str(note_id))

    if note is None:
        return None

    prepared = _prepare_body(body)

    if not prepared.strip():
        raise ValueError("A case note cannot be empty.")

    if prepared == note.body:
        return note

    metadata = dict(note.metadata_json or {})
    revisions = list(metadata.get("revisions") or [])
    revisions.append(
        {
            "previous_body": note.body[:4_000],
            "edited_by": editor_id,
            "edited_at": utcnow().isoformat(),
            "reason": redact(reason or "", 500) or None,
        }
    )
    metadata["revisions"] = revisions[-_MAX_REVISIONS:]
    metadata["revision_count"] = len(revisions)

    note.body = prepared
    note.metadata_json = sanitize_json(metadata, max_items=30)
    db.flush()
    return note


def list_case_notes(
    db: Session,
    case_id: str,
    *,
    include_internal: bool = True,
    author_id: Optional[str] = None,
    since: Optional[datetime] = None,
    ascending: bool = True,
    limit: int = 200,
    offset: int = 0,
) -> list[CaseNote]:
    """
    Return a case's notes.

    `include_internal=False` is what report generation passes: an internal note
    is written for colleagues and must not land in an externally shared report.
    """
    stmt = select(CaseNote).where(CaseNote.case_id == str(case_id))

    if not include_internal:
        stmt = stmt.where(CaseNote.is_internal.is_(False))

    if author_id:
        stmt = stmt.where(CaseNote.author_id == str(author_id))

    lower = ensure_utc(since)

    if lower is not None:
        stmt = stmt.where(CaseNote.record_created_at >= lower)

    order = (
        CaseNote.record_created_at.asc()
        if ascending
        else CaseNote.record_created_at.desc()
    )
    stmt = (
        stmt.order_by(order)
        .offset(max(0, int(offset)))
        .limit(max(1, min(int(limit), _MAX_NOTES)))
    )
    return list(db.execute(stmt).scalars())


def count_case_notes(db: Session, case_id: str, *, include_internal: bool = True) -> int:
    """
    Count a case's notes.
    """
    stmt = select(func.count()).select_from(CaseNote).where(
        CaseNote.case_id == str(case_id)
    )

    if not include_internal:
        stmt = stmt.where(CaseNote.is_internal.is_(False))

    return int(db.execute(stmt).scalar() or 0)


def get_case_notes_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the note service.
    """
    return {
        "service": "muleguard.backend.services.notes",
        "version": NOTES_SERVICE_VERSION,
        "limits": {
            "max_body_length": _MAX_BODY_LENGTH,
            "max_revisions_kept": _MAX_REVISIONS,
        },
        "guarantees": [
            "Note bodies are redacted before storage, so a pasted credential "
            "does not become a durable record.",
            "An edit appends a revision rather than overwriting history.",
            "Paragraph structure is preserved; other whitespace is collapsed.",
            "Internal notes can be excluded from externally shared reports.",
        ],
    }
