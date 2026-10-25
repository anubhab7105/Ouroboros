"""seed roles and reference data

Seeds the non-secret reference rows the application expects to exist on a fresh
database.

What is seeded, and why:

- Two baseline `model_versions` rows: `rules-only-v1` and
  `heuristic-fallback-v1`. Every `ModelAssessment` records the scoring mode that
  produced it, and the analysis service runs in `RULES_ONLY` or
  `HEURISTIC_FALLBACK` mode until a supervised model is trained and promoted.
  Having these rows present from the start means an assessment produced before
  any training still has a real, inspectable version to point at, and the model
  monitoring page has something to show instead of an empty state.

What is deliberately NOT seeded:

- **Users.** A migration must not invent credentials. Creating a user requires
  hashing a password, which means importing application code into a migration
  and baking a default password into version control — the single most common
  way a prototype ships with a live admin account. Users are created explicitly
  by `scripts/create_dev_users.py` (local development) or by an administrator.
- **Roles.** Roles are a `UserRole` enum rendered as a VARCHAR plus a CHECK
  constraint, not a lookup table, so there is nothing to insert. The revision
  keeps its historical name for traceability.
- **Rules.** The detection rule pack lives in `backend/config/rules.default.json`
  and is loaded at analysis time. Keeping rules in configuration rather than in
  rows means a rule change is a reviewable diff, not an UPDATE statement.

Revision ID: 0002_seed_roles_and_reference_data
Revises: 0001_initial_schema
Create Date: 2026-10-20
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

# Revision identifiers used by Alembic.
revision = "0002_seed_roles_and_reference_data"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


# Stable identifiers so the rows are idempotent across environments and can be
# referenced by seed scripts and tests.
RULES_ONLY_VERSION_ID = "mdl_baseline_rules_only_v1"
FALLBACK_VERSION_ID = "mdl_baseline_heuristic_fallback_v1"

_SEEDED_IDS = (RULES_ONLY_VERSION_ID, FALLBACK_VERSION_ID)


def _model_versions_table() -> sa.Table:
    """
    Minimal table definition for the bulk insert.

    Declared locally rather than imported from `app.models` on purpose: a
    migration must keep working even after the models move on, so it never
    depends on the current shape of application code.
    """
    return sa.table(
        "model_versions",
        sa.column("id", sa.String),
        sa.column("version", sa.String),
        sa.column("feature_schema_version", sa.String),
        sa.column("model_type", sa.String),
        sa.column("split_strategy", sa.String),
        sa.column("checksum_algorithm", sa.String),
        sa.column("is_active", sa.Boolean),
        sa.column("metrics_json", sa.JSON),
        sa.column("limitations_json", sa.JSON),
        sa.column("notes", sa.Text),
        sa.column("record_created_at", sa.DateTime(timezone=True)),
        sa.column("record_updated_at", sa.DateTime(timezone=True)),
    )


def upgrade() -> None:
    """
    Insert the baseline scoring-mode rows if they are not already present.
    """
    bind = op.get_bind()

    # Alembic's default `alembic_version.version_num` column is VARCHAR(32),
    # which is too narrow for some revision ids (and any future longer ones).
    # Widen it before recording this revision so the upgrade itself can succeed.
    if bind.dialect.name != "sqlite":
        op.alter_column(
            "alembic_version",
            "version_num",
            type_=sa.String(128),
            existing_type=sa.String(32),
        )

    now = datetime.now(timezone.utc)
    table = _model_versions_table()
    existing = set(
        bind.execute(
            sa.text(
                "SELECT id FROM model_versions WHERE id IN (:a, :b)"
            ),
            {"a": RULES_ONLY_VERSION_ID, "b": FALLBACK_VERSION_ID},
        )
        .scalars()
        .all()
    )

    rows = []

    if RULES_ONLY_VERSION_ID not in existing:
        rows.append(
            {
                "id": RULES_ONLY_VERSION_ID,
                "version": "rules-only-v1",
                "feature_schema_version": "v1",
                "model_type": "RULES_ONLY",
                "split_strategy": "UNKNOWN",
                "checksum_algorithm": "sha256",
                "is_active": False,
                # No metrics: this baseline is not a trained classifier, and
                # fabricating an AUC for it would be worse than an empty value.
                "metrics_json": None,
                "limitations_json": {
                    "scoring_mode": "RULES_ONLY",
                    "limits": [
                        "Deterministic rule evaluation only. No learned model is involved.",
                        "Detects only the typologies encoded in the rule pack.",
                        "Produces no calibrated probability, so scores are ordinal priorities only.",
                    ],
                },
                "notes": (
                    "Baseline reference version for assessments produced by rule "
                    "evaluation alone. Present so every assessment can reference a "
                    "real version before a supervised model is trained."
                ),
                "record_created_at": now,
                "record_updated_at": now,
            }
        )

    if FALLBACK_VERSION_ID not in existing:
        rows.append(
            {
                "id": FALLBACK_VERSION_ID,
                "version": "heuristic-fallback-v1",
                "feature_schema_version": "v1",
                "model_type": "HEURISTIC_FALLBACK",
                "split_strategy": "UNKNOWN",
                "checksum_algorithm": "sha256",
                "is_active": False,
                "metrics_json": None,
                "limitations_json": {
                    "scoring_mode": "HEURISTIC_FALLBACK",
                    "limits": [
                        "Transparent weighted heuristic over catalog features; weights are hand-set, not learned.",
                        "Weights were chosen for explainability, not optimised against outcomes.",
                        "Not calibrated against real-world fraud base rates.",
                    ],
                },
                "notes": (
                    "Baseline reference version for assessments produced by the "
                    "transparent heuristic scorer when no trained model is active."
                ),
                "record_created_at": now,
                "record_updated_at": now,
            }
        )

    if rows:
        op.bulk_insert(table, rows)


def downgrade() -> None:
    """
    Remove the seeded baseline rows.

    Assessments referencing them are left intact: `ModelAssessment.model_version_id`
    is `ON DELETE SET NULL`, so history survives the rollback with the link
    cleared rather than the row disappearing.
    """
    bind = op.get_bind()
    bind.execute(
        sa.text("DELETE FROM model_versions WHERE id IN (:a, :b)"),
        {"a": RULES_ONLY_VERSION_ID, "b": FALLBACK_VERSION_ID},
    )
