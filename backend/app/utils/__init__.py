"""
MULEGUARD shared utility package.

These are small, dependency-free helpers used across the ingestion, feature,
rules, correlation, service, and report layers. Keeping them here means one
definition of "what is a UTC timestamp", "how is money rounded", and "what is
safe to log" rather than one per module.

Boundaries:

- No SQLAlchemy, FastAPI, or Pydantic imports. These helpers must be usable
  from scripts and tests without starting the application.
- No business rules. Thresholds, rule definitions, and scoring weights live in
  `app.rules` and `backend/config/`, not here.
- No I/O except the explicit file helpers in `filenames` and `hashing`.

Submodules:

- `dates`      timezone-aware UTC handling and analysis windows
- `decimals`   money, confidence, and score quantisation plus statistics
- `json`       bounded, credential-free JSON serialisation
- `ids`        identifier generation, validation, and evidence references
- `hashing`    salted pseudonymisation and reproducibility fingerprints
- `filenames`  safe output filenames and confined write paths
- `text`       normalisation, redaction, and similarity
"""

from __future__ import annotations

from typing import Any, Final

from app.utils import dates, decimals, filenames, hashing, ids, json, text

UTILS_VERSION: Final[str] = "v1"

__all__ = [
    "UTILS_VERSION",
    "dates",
    "decimals",
    "filenames",
    "get_utils_metadata",
    "hashing",
    "ids",
    "json",
    "text",
]


def get_utils_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the utility surface.

    Exposed through the diagnostics endpoints so a deployment can confirm which
    helper version is active without reading the source.
    """
    return {
        "package": "muleguard.backend.utils",
        "version": UTILS_VERSION,
        "submodules": [
            "dates",
            "decimals",
            "filenames",
            "hashing",
            "ids",
            "json",
            "text",
        ],
        "money_quantum": str(decimals.MONEY_QUANTUM),
        "confidence_quantum": str(decimals.CONFIDENCE_QUANTUM),
        "score_quantum": str(decimals.SCORE_QUANTUM),
        "hash_algorithm": hashing.DEFAULT_HASH_ALGORITHM,
        "identifier_max_length": ids.ID_MAX_LENGTH,
        "allowed_export_extensions": sorted(filenames.ALLOWED_EXTENSIONS),
        "json_limits": {
            "max_depth": json.DEFAULT_MAX_DEPTH,
            "max_items": json.DEFAULT_MAX_ITEMS,
            "max_string": json.DEFAULT_MAX_STRING,
        },
        "notes": [
            "Identifier hashes are salted and namespaced per identifier kind.",
            "Dataset fingerprints are unsalted so they reproduce across deployments.",
            "Analysis windows are half-open [start, end) to avoid double counting.",
        ],
    }
