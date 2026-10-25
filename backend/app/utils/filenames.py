"""
MULEGUARD filename and output-path utilities.

Report downloads and data exports write files whose names derive from
user-influenced values (case titles, account identifiers). This module makes
those names safe.

Design rules:

- A generated filename never contains a path separator, a drive letter, a
  leading dot, or a reserved Windows device name. The project is developed on
  Windows and deployed on Linux, so both sets of rules apply at once.
- `safe_output_path` confines a write to a configured base directory and
  rejects traversal, which is the control that stops `../../etc/passwd`.
- Extensions come from an allow-list; a caller cannot choose `.py` or `.sh`.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path, PurePath
from typing import Any, Final, Optional

from app.utils.dates import ensure_utc, utcnow
from app.utils.text import slugify

__all__ = [
    "ALLOWED_EXTENSIONS",
    "MAX_FILENAME_LENGTH",
    "build_export_filename",
    "build_report_filename",
    "content_type_for",
    "is_within_directory",
    "safe_filename",
    "safe_output_path",
    "timestamp_token",
]

MAX_FILENAME_LENGTH: Final[int] = 180

ALLOWED_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {"pdf", "json", "csv", "ndjson", "txt", "md", "zip", "xlsx"}
)

_CONTENT_TYPES: Final[dict[str, str]] = {
    "pdf": "application/pdf",
    "json": "application/json",
    "ndjson": "application/x-ndjson",
    "csv": "text/csv",
    "txt": "text/plain; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "zip": "application/zip",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

# Windows reserved device names; a file called `con.pdf` is unopenable there.
_RESERVED_NAMES: Final[frozenset[str]] = frozenset(
    {
        "con", "prn", "aux", "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)

_UNSAFE_CHARS: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._-]+")
_MULTI_DASH: Final[re.Pattern[str]] = re.compile(r"-{2,}")
_MULTI_DOT: Final[re.Pattern[str]] = re.compile(r"\.{2,}")


def timestamp_token(value: Optional[datetime] = None) -> str:
    """
    Return a sortable `YYYYMMDDTHHMMSSZ` token for a filename.
    """
    moment = ensure_utc(value) or utcnow()
    return moment.strftime("%Y%m%dT%H%M%SZ")


def safe_filename(
    name: Any,
    *,
    extension: Optional[str] = None,
    default: str = "muleguard-output",
    max_length: int = MAX_FILENAME_LENGTH,
) -> str:
    """
    Produce a filename that is safe on Windows, macOS, and Linux.

    Strips directory components, collapses unsafe characters, refuses reserved
    device names, and forces the extension to the allow-list.
    """
    raw = str(name or "").strip()

    # Discard any directory component the caller may have passed in.
    raw = PurePath(raw.replace("\\", "/")).name

    stem, _, raw_ext = raw.rpartition(".")

    if not stem:
        stem, raw_ext = raw, ""

    chosen_ext = (extension or raw_ext or "").strip().lower().lstrip(".")

    if chosen_ext not in ALLOWED_EXTENSIONS:
        chosen_ext = "txt" if extension is None else str(extension).strip().lower().lstrip(".")

    if chosen_ext not in ALLOWED_EXTENSIONS:
        chosen_ext = "txt"

    cleaned = _UNSAFE_CHARS.sub("-", stem)
    cleaned = _MULTI_DASH.sub("-", cleaned)
    cleaned = _MULTI_DOT.sub(".", cleaned)
    cleaned = cleaned.strip(".-_")

    if not cleaned or cleaned.lower() in _RESERVED_NAMES:
        cleaned = slugify(default, default="muleguard-output")

    budget = max(8, max_length - len(chosen_ext) - 1)
    cleaned = cleaned[:budget].strip(".-_") or "muleguard-output"

    return f"{cleaned}.{chosen_ext}"


def build_report_filename(
    *,
    case_id: Any = None,
    account_id: Any = None,
    alert_id: Any = None,
    title: Any = None,
    generated_at: Optional[datetime] = None,
    extension: str = "pdf",
) -> str:
    """
    Build a descriptive, sortable report filename.

    The timestamp comes last so that files sort chronologically within a
    subject, which is what an investigator browsing a download folder wants.
    """
    parts: list[str] = ["muleguard"]

    if case_id:
        parts.append(f"case-{slugify(case_id, limit=32, default='case')}")
    elif alert_id:
        parts.append(f"alert-{slugify(alert_id, limit=32, default='alert')}")
    elif account_id:
        parts.append(f"account-{slugify(account_id, limit=32, default='account')}")

    if title:
        parts.append(slugify(title, limit=48, default="report"))

    parts.append(timestamp_token(generated_at))
    return safe_filename("-".join(parts), extension=extension)


def build_export_filename(
    kind: Any,
    *,
    generated_at: Optional[datetime] = None,
    extension: str = "json",
) -> str:
    """
    Build a filename for a data export such as an evidence bundle.
    """
    return safe_filename(
        f"muleguard-{slugify(kind, limit=48, default='export')}-{timestamp_token(generated_at)}",
        extension=extension,
    )


def content_type_for(filename: Any, default: str = "application/octet-stream") -> str:
    """
    Return the response content type for a generated filename.
    """
    extension = str(filename or "").rpartition(".")[2].lower()
    return _CONTENT_TYPES.get(extension, default)


def is_within_directory(base: Any, candidate: Any) -> bool:
    """
    Return True when `candidate` resolves inside `base`.

    Both paths are fully resolved first, so symlinks and `..` segments cannot
    escape the base directory.
    """
    try:
        base_resolved = Path(base).resolve()
        candidate_resolved = Path(candidate).resolve()
    except (OSError, RuntimeError, ValueError):
        return False

    try:
        candidate_resolved.relative_to(base_resolved)
    except ValueError:
        return False

    return True


def safe_output_path(
    base_dir: Any,
    filename: Any,
    *,
    extension: Optional[str] = None,
    create_parents: bool = False,
) -> Path:
    """
    Resolve a write target inside `base_dir`, or raise ValueError.

    This is the single control preventing a user-influenced filename from
    escaping the configured output directory.
    """
    base = Path(base_dir)
    cleaned = safe_filename(filename, extension=extension)
    target = base / cleaned

    if not is_within_directory(base, target):
        raise ValueError(
            f"refusing to write outside the configured output directory: {cleaned!r}"
        )

    if create_parents:
        try:
            base.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ValueError(f"cannot create output directory {base}: {exc}") from exc

    return target


def _ensure_relative(value: Any) -> str:
    """
    Reject absolute paths and drive-qualified Windows paths.
    """
    text = str(value or "").replace("\\", "/")

    if not text or text.startswith("/") or os.path.isabs(text) or ":" in text.split("/")[0]:
        raise ValueError(f"expected a relative path, got {value!r}")

    return text
