"""add investigation indexes

Adds composite indexes for the query shapes the investigation UI actually
issues. `0001` created the indexes declared on the models; these are the ones
identified from the endpoint query patterns afterwards.

Each index below exists for a specific query, noted inline. They are also
declared in `app.models.__table_args__`, so `alembic revision --autogenerate`
sees metadata and database agreeing and will not try to drop them.

Why composite rather than more single-column indexes: every one of these
queries filters on one column and orders by another. A single-column index on
the filter still leaves the database sorting the matched rows; a composite
index on (filter, sort) lets it walk the index in order and stop early at the
page limit. On the transaction table, which is the largest, that is the
difference between a bounded index scan and a sort of the whole partition.

Revision ID: 0003_add_investigation_indexes
Revises: 0002_seed_roles_and_reference_data
Create Date: 2026-10-20
"""

from __future__ import annotations

from alembic import op

# Revision identifiers used by Alembic.
revision = "0003_add_investigation_indexes"
down_revision = "0002_seed_roles_and_reference_data"
branch_labels = None
depends_on = None


# (index name, table, columns, query it serves)
_INDEXES: tuple[tuple[str, str, list[str], str], ...] = (
    (
        "ix_transactions_sender_receiver_occurred",
        "transactions",
        ["sender_account_id", "receiver_account_id", "occurred_at"],
        "Money-trail traversal: expanding a hop filters on both endpoints and "
        "bounds the date span. The hottest query in the graph endpoints.",
    ),
    (
        "ix_model_assessments_run_score",
        "model_assessments",
        ["analysis_run_id", "score"],
        "GET /analysis/runs/{id}/results ranks a run's assessments by score.",
    ),
    (
        "ix_model_assessments_account_version_asof",
        "model_assessments",
        ["account_id", "score_version", "as_of"],
        "Account score history filtered to one score version.",
    ),
    (
        "ix_feature_snapshots_account_version_asof",
        "feature_snapshots",
        ["account_id", "feature_version", "as_of"],
        "Point-in-time feature lookup for one account at one schema version; "
        "also the read behind reproducing a past assessment.",
    ),
    (
        "ix_alerts_assignee_state",
        "alerts",
        ["assigned_to", "state"],
        "'My queue': alerts assigned to the current user, filtered by state.",
    ),
    (
        "ix_alerts_priority_score",
        "alerts",
        ["priority", "score"],
        "Default triage queue ordering: priority band then score within it.",
    ),
    (
        "ix_rule_hits_assessment_triggered",
        "rule_hits",
        ["assessment_id", "triggered"],
        "Assessment detail loads only the rules that actually fired.",
    ),
    (
        "ix_risk_indicators_assessment_severity",
        "risk_indicators",
        ["assessment_id", "severity"],
        "Assessment explanation panel orders indicators by severity.",
    ),
    (
        "ix_complaint_correlations_complaint_account",
        "complaint_correlations",
        ["complaint_id", "account_id"],
        "Resolving which accounts a given complaint touches.",
    ),
    (
        "ix_complaint_correlations_account_tier",
        "complaint_correlations",
        ["account_id", "match_tier"],
        "Account detail shows correlations strongest tier first.",
    ),
    (
        "ix_case_evidence_type_id_active",
        "case_evidence",
        ["evidence_type", "evidence_id", "is_active"],
        "Reverse evidence lookup: 'which open cases cite this record?'",
    ),
    (
        "ix_cases_status_assignee_updated",
        "investigation_cases",
        ["status", "assignee_id", "record_updated_at"],
        "Case board columns, per assignee, most recently touched first.",
    ),
    (
        "ix_audit_events_actor_username_created",
        "audit_events",
        ["actor_username", "created_at"],
        "Auditor view: one actor's activity over a period. Uses the "
        "denormalised username so it still resolves after a user row is removed.",
    ),
)


def upgrade() -> None:
    """
    Create the investigation query indexes.
    """
    for name, table, columns, _reason in _INDEXES:
        op.create_index(name, table, columns)


def downgrade() -> None:
    """
    Drop the investigation query indexes in reverse order.
    """
    for name, table, _columns, _reason in reversed(_INDEXES):
        op.drop_index(name, table_name=table)
