"""initial schema

Creates the full MULEGUARD schema: users, the synthetic financial domain
(accounts, transactions, complaints, entities and their time-bound links), the
detection pipeline (feature snapshots, model versions, analysis runs,
assessments, rule hits, risk indicators), the investigation workflow (alerts,
cases, evidence, events, notes), the audit log, complaint correlations, bounded
graph analysis runs, and the isolated synthetic ground-truth store.

Notes on choices made here:

- Enums are created with ``native_enum=False``, so they are rendered as VARCHAR
  plus a CHECK constraint. That keeps one set of model definitions working on
  both PostgreSQL and SQLite, and avoids the PostgreSQL ``ALTER TYPE`` dance
  every time an enum gains a member.
- JSON columns use the portable ``JSON().with_variant(JSONB, "postgresql")``
  type, matching ``app.models.JSONType``: JSONB on PostgreSQL for indexing and
  containment queries, plain JSON on SQLite for local development.
- Tables are created in foreign-key dependency order and dropped in exactly
  the reverse, so ``downgrade`` is clean on databases that enforce FKs.
- ``ground_truth_labels`` is a separate table on purpose. Synthetic labels,
  scenario IDs and fraud-ring IDs must never sit alongside predictor features
  where a careless join could leak them into training.

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-10-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# Revision identifiers used by Alembic.
revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None

# Mirrors app.models.JSONType so the migration and the models agree.
JSONType = sa.JSON().with_variant(JSONB, "postgresql")


def upgrade() -> None:
    """
    Create every MULEGUARD table, constraint and index.
    """

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable user identifier.'),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True, comment='Unique login username.'),
        sa.Column("email", sa.String(length=320), nullable=False, unique=True, comment='Unique email address.'),
        sa.Column("full_name", sa.String(length=200), nullable=True, comment='Optional display name.'),
        sa.Column("role", sa.Enum('ADMIN', 'ANALYST', 'SENIOR_INVESTIGATOR', 'AUDITOR', name='user_role', native_enum=False), nullable=False, comment='Role used for server-side RBAC.'),
        sa.Column("password_hash", sa.String(length=255), nullable=False, comment='Salted password hash. Never store plaintext passwords.'),
        sa.Column("is_active", sa.Boolean(), nullable=False, comment='Inactive users must not authenticate.'),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, comment='Force password change on next login where implemented.'),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, comment='Failed login counter for throttling/lockout.'),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True, comment='Temporary account lockout expiry, if used.'),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True, comment='Last successful login timestamp in UTC.'),
        sa.Column("last_login_ip_hash", sa.String(length=128), nullable=True, comment='Hashed source IP for security auditing, not raw IP.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('length(username) > 0', name='ck_users_username_not_empty'),
        sa.CheckConstraint('length(email) > 0', name='ck_users_email_not_empty'),
    )
    op.create_index(
        "ix_users_username",
        "users",
        ["username"],
    )
    op.create_index(
        "ix_users_email",
        "users",
        ["email"],
    )
    op.create_index(
        "ix_users_role",
        "users",
        ["role"],
    )
    op.create_index(
        "ix_users_is_active",
        "users",
        ["is_active"],
    )
    op.create_index(
        "ix_users_role_active",
        "users",
        ["role", "is_active"],
    )

    op.create_table(
        "accounts",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable synthetic account identifier.'),
        sa.Column("account_type", sa.Enum('INDIVIDUAL', 'BUSINESS', 'MERCHANT', 'OTHER', name='account_type', native_enum=False), nullable=False, comment='Synthetic account type.'),
        sa.Column("status", sa.Enum('ACTIVE', 'DORMANT', 'CLOSED', 'REVIEW_REQUIRED', name='account_status', native_enum=False), nullable=False, comment='Synthetic lifecycle status; not an enforcement action.'),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, comment='Account creation timestamp in the synthetic domain.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Non-sensitive synthetic attributes only.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('length(id) > 0', name='ck_accounts_id_not_empty'),
    )
    op.create_index(
        "ix_accounts_account_type",
        "accounts",
        ["account_type"],
    )
    op.create_index(
        "ix_accounts_status",
        "accounts",
        ["status"],
    )
    op.create_index(
        "ix_accounts_created_at",
        "accounts",
        ["created_at"],
    )
    op.create_index(
        "ix_accounts_type_status_created",
        "accounts",
        ["account_type", "status", "created_at"],
    )

    op.create_table(
        "transactions",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable transaction identifier.'),
        sa.Column("sender_account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, comment='Sending synthetic account.'),
        sa.Column("receiver_account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, comment='Receiving synthetic account.'),
        sa.Column("amount", sa.Numeric(precision=18, scale=2), nullable=False, comment='Transfer amount. Must be positive for completed transfers.'),
        sa.Column("currency", sa.String(length=3), nullable=False, comment='ISO-style currency code, normalised uppercase.'),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, comment='Transaction timestamp in UTC.'),
        sa.Column("status", sa.Enum('PENDING', 'COMPLETED', 'FAILED', 'REVERSED', name='transaction_status', native_enum=False), nullable=False, comment='Transaction lifecycle status.'),
        sa.Column("channel", sa.Enum('UPI', 'IMPS', 'NEFT', 'RTGS', 'CARD', 'INTERNAL', name='channel', native_enum=False), nullable=False, comment='Synthetic payment channel.'),
        sa.Column("reference", sa.String(length=128), nullable=False, unique=True, comment='Unique transaction reference for complaint and evidence matching.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Non-sensitive synthetic transaction metadata only.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_system", sa.String(length=100), nullable=True),
        sa.Column("source_batch_id", sa.String(length=100), nullable=True),
        sa.Column("ingestion_run_id", sa.String(length=64), nullable=True),
        sa.Column("source_payload_hash", sa.String(length=128), nullable=True),
        sa.CheckConstraint('amount > 0', name='ck_transactions_amount_positive'),
        sa.CheckConstraint('length(currency) = 3', name='ck_transactions_currency_length'),
        sa.CheckConstraint('currency = upper(currency)', name='ck_transactions_currency_uppercase'),
    )
    op.create_index(
        "ix_transactions_sender_account_id",
        "transactions",
        ["sender_account_id"],
    )
    op.create_index(
        "ix_transactions_receiver_account_id",
        "transactions",
        ["receiver_account_id"],
    )
    op.create_index(
        "ix_transactions_occurred_at",
        "transactions",
        ["occurred_at"],
    )
    op.create_index(
        "ix_transactions_status",
        "transactions",
        ["status"],
    )
    op.create_index(
        "ix_transactions_channel",
        "transactions",
        ["channel"],
    )
    op.create_index(
        "ix_transactions_reference",
        "transactions",
        ["reference"],
    )
    op.create_index(
        "ix_transactions_source_batch_id",
        "transactions",
        ["source_batch_id"],
    )
    op.create_index(
        "ix_transactions_ingestion_run_id",
        "transactions",
        ["ingestion_run_id"],
    )
    op.create_index(
        "ix_transactions_sender_occurred",
        "transactions",
        ["sender_account_id", "occurred_at"],
    )
    op.create_index(
        "ix_transactions_receiver_occurred",
        "transactions",
        ["receiver_account_id", "occurred_at"],
    )
    op.create_index(
        "ix_transactions_status_occurred",
        "transactions",
        ["status", "occurred_at"],
    )
    op.create_index(
        "ix_transactions_channel_occurred",
        "transactions",
        ["channel", "occurred_at"],
    )
    op.create_index(
        "ix_transactions_amount",
        "transactions",
        ["amount"],
    )

    op.create_table(
        "complaints",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable complaint identifier.'),
        sa.Column("reference", sa.String(length=128), nullable=False, unique=True, comment='Complaint reference from source system.'),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False, comment='Complaint report timestamp in UTC.'),
        sa.Column("category", sa.String(length=100), nullable=False, comment='Synthetic complaint category or type.'),
        sa.Column("narrative_raw", sa.Text(), nullable=False, comment='Original synthetic narrative text. Must not be silently altered.'),
        sa.Column("narrative_normalized", sa.Text(), nullable=True, comment='Derived normalised narrative, stored separately from raw facts.'),
        sa.Column("transaction_reference", sa.String(length=128), nullable=True, comment='Transaction reference supplied by complaint source, if any.'),
        sa.Column("victim_account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True, comment='Known victim synthetic account, if supplied.'),
        sa.Column("suspected_account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True, comment='Suspected synthetic account, if supplied.'),
        sa.Column("amount", sa.Numeric(precision=18, scale=2), nullable=True, comment='Reported complaint amount, if supplied.'),
        sa.Column("currency", sa.String(length=3), nullable=True, comment='Reported complaint currency, if supplied.'),
        sa.Column("source", sa.String(length=100), nullable=True, comment='Complaint source system or channel.'),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, comment='Complaint ingestion timestamp in UTC.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Non-sensitive synthetic complaint metadata.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_system", sa.String(length=100), nullable=True),
        sa.Column("source_batch_id", sa.String(length=100), nullable=True),
        sa.Column("ingestion_run_id", sa.String(length=64), nullable=True),
        sa.Column("source_payload_hash", sa.String(length=128), nullable=True),
        sa.CheckConstraint('amount IS NULL OR amount > 0', name='ck_complaints_amount_positive_when_present'),
        sa.CheckConstraint('currency IS NULL OR (length(currency) = 3 AND currency = upper(currency))', name='ck_complaints_currency_format_when_present'),
    )
    op.create_index(
        "ix_complaints_reference",
        "complaints",
        ["reference"],
    )
    op.create_index(
        "ix_complaints_reported_at",
        "complaints",
        ["reported_at"],
    )
    op.create_index(
        "ix_complaints_category",
        "complaints",
        ["category"],
    )
    op.create_index(
        "ix_complaints_transaction_reference",
        "complaints",
        ["transaction_reference"],
    )
    op.create_index(
        "ix_complaints_victim_account_id",
        "complaints",
        ["victim_account_id"],
    )
    op.create_index(
        "ix_complaints_suspected_account_id",
        "complaints",
        ["suspected_account_id"],
    )
    op.create_index(
        "ix_complaints_source",
        "complaints",
        ["source"],
    )
    op.create_index(
        "ix_complaints_ingested_at",
        "complaints",
        ["ingested_at"],
    )
    op.create_index(
        "ix_complaints_source_batch_id",
        "complaints",
        ["source_batch_id"],
    )
    op.create_index(
        "ix_complaints_ingestion_run_id",
        "complaints",
        ["ingestion_run_id"],
    )
    op.create_index(
        "ix_complaints_reported_category",
        "complaints",
        ["reported_at", "category"],
    )
    op.create_index(
        "ix_complaints_victim_reported",
        "complaints",
        ["victim_account_id", "reported_at"],
    )
    op.create_index(
        "ix_complaints_suspected_reported",
        "complaints",
        ["suspected_account_id", "reported_at"],
    )

    op.create_table(
        "entities",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable entity identifier.'),
        sa.Column("entity_type", sa.Enum('DEVICE', 'PHONE_HASH', 'UPI_ID', 'EMAIL_HASH', 'ADDRESS_HASH', 'IP_HASH', 'OTHER', name='entity_type', native_enum=False), nullable=False, comment='Synthetic entity type.'),
        sa.Column("identifier_hash", sa.String(length=128), nullable=False, comment='Pseudonymous hash of synthetic identifier.'),
        sa.Column("identifier_display", sa.String(length=200), nullable=True, comment='Masked or synthetic display label, never real sensitive identifier.'),
        sa.Column("source", sa.String(length=100), nullable=False, comment='Entity provenance source.'),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True, comment='Earliest observed timestamp for this entity, if known.'),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True, comment='Latest observed timestamp for this entity, if known.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Non-sensitive synthetic entity metadata.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_system", sa.String(length=100), nullable=True),
        sa.Column("source_batch_id", sa.String(length=100), nullable=True),
        sa.Column("ingestion_run_id", sa.String(length=64), nullable=True),
        sa.Column("source_payload_hash", sa.String(length=128), nullable=True),
        sa.UniqueConstraint('entity_type', 'identifier_hash', 'source', name='uq_entities_type_hash_source'),
        sa.CheckConstraint('length(identifier_hash) > 0', name='ck_entities_identifier_hash_not_empty'),
    )
    op.create_index(
        "ix_entities_entity_type",
        "entities",
        ["entity_type"],
    )
    op.create_index(
        "ix_entities_identifier_hash",
        "entities",
        ["identifier_hash"],
    )
    op.create_index(
        "ix_entities_source",
        "entities",
        ["source"],
    )
    op.create_index(
        "ix_entities_source_batch_id",
        "entities",
        ["source_batch_id"],
    )
    op.create_index(
        "ix_entities_ingestion_run_id",
        "entities",
        ["ingestion_run_id"],
    )
    op.create_index(
        "ix_entities_type_first_seen",
        "entities",
        ["entity_type", "first_seen_at"],
    )

    op.create_table(
        "account_entity_links",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable link identifier.'),
        sa.Column("account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, comment='Linked synthetic account.'),
        sa.Column("entity_id", sa.String(length=64), sa.ForeignKey("entities.id", ondelete="RESTRICT"), nullable=False, comment='Linked synthetic entity.'),
        sa.Column("match_method", sa.Enum('EXACT', 'NORMALIZED', 'ENTITY_TEMPORAL', 'GRAPH_TEMPORAL', 'NARRATIVE_EXTRACTION', 'MANUAL', 'UNKNOWN', name='match_method', native_enum=False), nullable=False, comment='How the account-entity relationship was established.'),
        sa.Column("confidence", sa.Numeric(precision=5, scale=4), nullable=True, comment='Confidence in inferred relationship, between 0 and 1.'),
        sa.Column("verification_state", sa.Enum('UNVERIFIED', 'VERIFIED', 'REJECTED', 'NEEDS_REVIEW', name='verification_state', native_enum=False), nullable=False, comment='Verification state for the relationship.'),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False, comment='Relationship validity start in UTC.'),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True, comment='Relationship validity end in UTC, if known.'),
        sa.Column("source", sa.String(length=100), nullable=False, comment='Link provenance source.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Non-sensitive synthetic link metadata.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_system", sa.String(length=100), nullable=True),
        sa.Column("source_batch_id", sa.String(length=100), nullable=True),
        sa.Column("ingestion_run_id", sa.String(length=64), nullable=True),
        sa.Column("source_payload_hash", sa.String(length=128), nullable=True),
        sa.UniqueConstraint('account_id', 'entity_id', 'valid_from', 'source', name='uq_account_entity_links_account_entity_valid_source'),
        sa.CheckConstraint('confidence IS NULL OR (confidence >= 0 AND confidence <= 1)', name='ck_account_entity_links_confidence_range'),
        sa.CheckConstraint('valid_to IS NULL OR valid_to > valid_from', name='ck_account_entity_links_valid_range'),
    )
    op.create_index(
        "ix_account_entity_links_account_id",
        "account_entity_links",
        ["account_id"],
    )
    op.create_index(
        "ix_account_entity_links_entity_id",
        "account_entity_links",
        ["entity_id"],
    )
    op.create_index(
        "ix_account_entity_links_match_method",
        "account_entity_links",
        ["match_method"],
    )
    op.create_index(
        "ix_account_entity_links_verification_state",
        "account_entity_links",
        ["verification_state"],
    )
    op.create_index(
        "ix_account_entity_links_valid_from",
        "account_entity_links",
        ["valid_from"],
    )
    op.create_index(
        "ix_account_entity_links_valid_to",
        "account_entity_links",
        ["valid_to"],
    )
    op.create_index(
        "ix_account_entity_links_source",
        "account_entity_links",
        ["source"],
    )
    op.create_index(
        "ix_account_entity_links_source_batch_id",
        "account_entity_links",
        ["source_batch_id"],
    )
    op.create_index(
        "ix_account_entity_links_ingestion_run_id",
        "account_entity_links",
        ["ingestion_run_id"],
    )
    op.create_index(
        "ix_account_entity_links_account_valid",
        "account_entity_links",
        ["account_id", "valid_from"],
    )
    op.create_index(
        "ix_account_entity_links_entity_valid",
        "account_entity_links",
        ["entity_id", "valid_from"],
    )
    op.create_index(
        "ix_account_entity_links_method_state",
        "account_entity_links",
        ["match_method", "verification_state"],
    )

    op.create_table(
        "feature_snapshots",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable feature snapshot identifier.'),
        sa.Column("account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, comment='Account for which features were computed.'),
        sa.Column("as_of", sa.DateTime(timezone=True), nullable=False, comment='Point-in-time assessment timestamp in UTC.'),
        sa.Column("feature_version", sa.String(length=32), nullable=False, comment='Feature schema/version used for computation.'),
        sa.Column("window", sa.String(length=32), nullable=True, comment='Optional primary window label, e.g. 24h, 7d, 30d.'),
        sa.Column("values_json", JSONType, nullable=False, comment='Computed feature values. Must not contain leaked labels.'),
        sa.Column("dataset_fingerprint", sa.String(length=128), nullable=True, comment='Dataset fingerprint for reproducibility.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Non-sensitive computation metadata.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('account_id', 'as_of', 'feature_version', name='uq_feature_snapshots_account_asof_version'),
    )
    op.create_index(
        "ix_feature_snapshots_account_id",
        "feature_snapshots",
        ["account_id"],
    )
    op.create_index(
        "ix_feature_snapshots_as_of",
        "feature_snapshots",
        ["as_of"],
    )
    op.create_index(
        "ix_feature_snapshots_feature_version",
        "feature_snapshots",
        ["feature_version"],
    )
    op.create_index(
        "ix_feature_snapshots_dataset_fingerprint",
        "feature_snapshots",
        ["dataset_fingerprint"],
    )
    op.create_index(
        "ix_feature_snapshots_account_asof",
        "feature_snapshots",
        ["account_id", "as_of"],
    )
    op.create_index(
        "ix_feature_snapshots_version_asof",
        "feature_snapshots",
        ["feature_version", "as_of"],
    )

    op.create_table(
        "model_versions",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable model version identifier.'),
        sa.Column("version", sa.String(length=64), nullable=False, unique=True, comment='Human-readable model version.'),
        sa.Column("feature_schema_version", sa.String(length=32), nullable=False, comment='Feature schema version expected by the model.'),
        sa.Column("model_type", sa.Enum('HIST_GRADIENT_BOOSTING', 'RANDOM_FOREST', 'LOGISTIC_REGRESSION', 'ISOLATION_FOREST', 'RULES_ONLY', 'HEURISTIC_FALLBACK', 'UNKNOWN', name='model_type', native_enum=False), nullable=False, comment='Model family or scoring baseline type.'),
        sa.Column("training_seed", sa.Integer(), nullable=True, comment='Random seed used for reproducible training.'),
        sa.Column("training_started_at", sa.DateTime(timezone=True), nullable=True, comment='Training start timestamp in UTC.'),
        sa.Column("training_finished_at", sa.DateTime(timezone=True), nullable=True, comment='Training finish timestamp in UTC.'),
        sa.Column("dataset_fingerprint", sa.String(length=128), nullable=True, comment='Dataset fingerprint used for training.'),
        sa.Column("generator_config_json", JSONType, nullable=True, comment='Synthetic generator configuration fingerprint, not secrets.'),
        sa.Column("split_strategy", sa.Enum('CHRONOLOGICAL', 'SCENARIO_AWARE_CHRONOLOGICAL', 'GROUP_AWARE_RANDOM', 'RANDOM', 'UNKNOWN', name='split_strategy', native_enum=False), nullable=False, comment='Train/validation/test split strategy.'),
        sa.Column("hyperparameters_json", JSONType, nullable=True, comment='Model hyperparameters.'),
        sa.Column("artifact_path", sa.String(length=512), nullable=True, comment='Controlled local artifact path. Must not be user-upload derived.'),
        sa.Column("artifact_checksum", sa.String(length=128), nullable=True, comment='Checksum of trusted local artifact.'),
        sa.Column("checksum_algorithm", sa.String(length=32), nullable=False, comment='Checksum algorithm.'),
        sa.Column("metrics_json", JSONType, nullable=True, comment='Headline metrics actually computed for this model version.'),
        sa.Column("limitations_json", JSONType, nullable=True, comment='Known limitations and prohibited interpretations.'),
        sa.Column("is_active", sa.Boolean(), nullable=False, comment='Whether this version is the active inference model.'),
        sa.Column("notes", sa.Text(), nullable=True, comment='Model card or operational notes.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('length(version) > 0', name='ck_model_versions_version_not_empty'),
    )
    op.create_index(
        "ix_model_versions_version",
        "model_versions",
        ["version"],
    )
    op.create_index(
        "ix_model_versions_feature_schema_version",
        "model_versions",
        ["feature_schema_version"],
    )
    op.create_index(
        "ix_model_versions_model_type",
        "model_versions",
        ["model_type"],
    )
    op.create_index(
        "ix_model_versions_dataset_fingerprint",
        "model_versions",
        ["dataset_fingerprint"],
    )
    op.create_index(
        "ix_model_versions_split_strategy",
        "model_versions",
        ["split_strategy"],
    )
    op.create_index(
        "ix_model_versions_is_active",
        "model_versions",
        ["is_active"],
    )
    op.create_index(
        "ix_model_versions_active_type",
        "model_versions",
        ["is_active", "model_type"],
    )

    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable analysis run identifier.'),
        sa.Column("status", sa.Enum('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'PARTIAL', name='analysis_run_status', native_enum=False), nullable=False, comment='Current run state.'),
        sa.Column("run_type", sa.String(length=50), nullable=False, comment='Run type, e.g. batch, targeted, replay.'),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True, comment='Run start timestamp in UTC.'),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True, comment='Run finish timestamp in UTC.'),
        sa.Column("processed_count", sa.Integer(), nullable=False, comment='Number of accounts processed.'),
        sa.Column("error_count", sa.Integer(), nullable=False, comment='Number of processing errors.'),
        sa.Column("model_version_id", sa.String(length=64), sa.ForeignKey("model_versions.id", ondelete="SET NULL"), nullable=True, comment='Model version used during the run.'),
        sa.Column("scoring_mode", sa.Enum('TRAINED_MODEL', 'HEURISTIC_FALLBACK', 'RULES_ONLY', 'ML_DISABLED', 'UNKNOWN', name='scoring_mode', native_enum=False), nullable=False, comment='Active scoring mode for the run.'),
        sa.Column("score_version", sa.String(length=32), nullable=True, comment='Risk fusion score version.'),
        sa.Column("feature_version", sa.String(length=32), nullable=True, comment='Feature schema version used.'),
        sa.Column("rules_version", sa.String(length=32), nullable=True, comment='Rule engine version used.'),
        sa.Column("graph_version", sa.String(length=32), nullable=True, comment='Graph analytics version used.'),
        sa.Column("complaint_version", sa.String(length=32), nullable=True, comment='Complaint correlation version used.'),
        sa.Column("dataset_fingerprint", sa.String(length=128), nullable=True, comment='Dataset fingerprint for reproducibility.'),
        sa.Column("config_json", JSONType, nullable=True, comment='Safe run configuration snapshot.'),
        sa.Column("counts_json", JSONType, nullable=True, comment='Run counts by stage or outcome.'),
        sa.Column("error_summary_json", JSONType, nullable=True, comment='Sanitized error summary.'),
        sa.Column("requested_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User who requested the run.'),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True, unique=True, comment='Optional idempotency key for repeated run requests.'),
        sa.Column("account_count", sa.Integer(), nullable=False, comment='Number of accounts selected for the run.'),
        sa.Column("assessment_count", sa.Integer(), nullable=False, comment='Number of assessments written by the run.'),
        sa.Column("alert_count", sa.Integer(), nullable=False, comment='Number of alerts raised by the run.'),
        sa.Column("model_version", sa.String(length=64), nullable=True, comment='Denormalised model version label for history resilience.'),
        sa.Column("parameters_json", JSONType, nullable=True, comment='Run request parameters as submitted. Secrets must be excluded.'),
        sa.Column("summary_json", JSONType, nullable=True, comment='Analyst-facing run summary.'),
        sa.Column("error_code", sa.String(length=100), nullable=True, comment='Stable error code when the run failed.'),
        sa.Column("error_message", sa.Text(), nullable=True, comment='Sanitized failure message. Must not contain secrets.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('processed_count >= 0', name='ck_analysis_runs_processed_nonnegative'),
        sa.CheckConstraint('error_count >= 0', name='ck_analysis_runs_error_nonnegative'),
    )
    op.create_index(
        "ix_analysis_runs_status",
        "analysis_runs",
        ["status"],
    )
    op.create_index(
        "ix_analysis_runs_run_type",
        "analysis_runs",
        ["run_type"],
    )
    op.create_index(
        "ix_analysis_runs_started_at",
        "analysis_runs",
        ["started_at"],
    )
    op.create_index(
        "ix_analysis_runs_finished_at",
        "analysis_runs",
        ["finished_at"],
    )
    op.create_index(
        "ix_analysis_runs_model_version_id",
        "analysis_runs",
        ["model_version_id"],
    )
    op.create_index(
        "ix_analysis_runs_scoring_mode",
        "analysis_runs",
        ["scoring_mode"],
    )
    op.create_index(
        "ix_analysis_runs_dataset_fingerprint",
        "analysis_runs",
        ["dataset_fingerprint"],
    )
    op.create_index(
        "ix_analysis_runs_requested_by",
        "analysis_runs",
        ["requested_by"],
    )
    op.create_index(
        "ix_analysis_runs_idempotency_key",
        "analysis_runs",
        ["idempotency_key"],
    )
    op.create_index(
        "ix_analysis_runs_status_started",
        "analysis_runs",
        ["status", "started_at"],
    )
    op.create_index(
        "ix_analysis_runs_requested_started",
        "analysis_runs",
        ["requested_by", "started_at"],
    )

    op.create_table(
        "model_evaluations",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable evaluation identifier.'),
        sa.Column("model_version_id", sa.String(length=64), sa.ForeignKey("model_versions.id", ondelete="RESTRICT"), nullable=False, comment='Evaluated model version.'),
        sa.Column("analysis_run_id", sa.String(length=64), sa.ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, comment='Analysis run associated with evaluation, if any.'),
        sa.Column("dataset_fingerprint", sa.String(length=128), nullable=True, comment='Dataset fingerprint used for evaluation.'),
        sa.Column("split_strategy", sa.Enum('CHRONOLOGICAL', 'SCENARIO_AWARE_CHRONOLOGICAL', 'GROUP_AWARE_RANDOM', 'RANDOM', 'UNKNOWN', name='split_strategy', native_enum=False), nullable=False, comment='Evaluation split strategy.'),
        sa.Column("sample_count", sa.Integer(), nullable=False, comment='Number of evaluation samples.'),
        sa.Column("class_distribution_json", JSONType, nullable=True, comment='Class distribution in evaluation partition.'),
        sa.Column("metrics_json", JSONType, nullable=True, comment='Computed metrics. Null/absent values mean not computed.'),
        sa.Column("threshold", sa.Numeric(precision=7, scale=4), nullable=True, comment='Decision threshold used for confusion matrix, if any.'),
        sa.Column("top_k", sa.Integer(), nullable=True, comment='K used for Precision@K / top-K review yield.'),
        sa.Column("latency_ms_per_account", sa.Numeric(precision=10, scale=3), nullable=True, comment='Measured latency per account at stated batch size.'),
        sa.Column("latency_batch_size", sa.Integer(), nullable=True, comment='Batch size used for latency measurement.'),
        sa.Column("undefined_metrics_json", JSONType, nullable=True, comment='Metrics intentionally not computed and why.'),
        sa.Column("limitations", sa.Text(), nullable=True, comment='Evaluation limitations and interpretation warnings.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('model_version_id', 'dataset_fingerprint', 'split_strategy', 'analysis_run_id', name='uq_model_evaluations_version_dataset_split_run'),
        sa.CheckConstraint('sample_count >= 0', name='ck_model_evaluations_sample_count_nonnegative'),
        sa.CheckConstraint('threshold IS NULL OR (threshold >= 0 AND threshold <= 1)', name='ck_model_evaluations_threshold_range'),
    )
    op.create_index(
        "ix_model_evaluations_model_version_id",
        "model_evaluations",
        ["model_version_id"],
    )
    op.create_index(
        "ix_model_evaluations_analysis_run_id",
        "model_evaluations",
        ["analysis_run_id"],
    )
    op.create_index(
        "ix_model_evaluations_dataset_fingerprint",
        "model_evaluations",
        ["dataset_fingerprint"],
    )
    op.create_index(
        "ix_model_evaluations_split_strategy",
        "model_evaluations",
        ["split_strategy"],
    )
    op.create_index(
        "ix_model_evaluations_model_created",
        "model_evaluations",
        ["model_version_id", "record_created_at"],
    )

    op.create_table(
        "model_assessments",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable assessment identifier.'),
        sa.Column("account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, comment='Assessed synthetic account.'),
        sa.Column("feature_snapshot_id", sa.String(length=64), sa.ForeignKey("feature_snapshots.id", ondelete="RESTRICT"), nullable=True, comment='Feature snapshot used for assessment.'),
        sa.Column("analysis_run_id", sa.String(length=64), sa.ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, comment='Analysis run that produced the assessment.'),
        sa.Column("model_version_id", sa.String(length=64), sa.ForeignKey("model_versions.id", ondelete="SET NULL"), nullable=True, comment='Model version used, if trained model scoring was active.'),
        sa.Column("as_of", sa.DateTime(timezone=True), nullable=False, comment='Point-in-time assessment timestamp in UTC.'),
        sa.Column("scored_at", sa.DateTime(timezone=True), nullable=False, comment='Actual scoring timestamp in UTC.'),
        sa.Column("scoring_mode", sa.Enum('TRAINED_MODEL', 'HEURISTIC_FALLBACK', 'RULES_ONLY', 'ML_DISABLED', 'UNKNOWN', name='scoring_mode', native_enum=False), nullable=False, comment='Trained model, heuristic fallback, rules-only, or disabled.'),
        sa.Column("score", sa.Numeric(precision=7, scale=2), nullable=False, comment='Investigative priority score, typically 0-100.'),
        sa.Column("score_type", sa.String(length=64), nullable=False, comment='Score semantics label.'),
        sa.Column("score_version", sa.String(length=32), nullable=True, comment='Risk fusion score version.'),
        sa.Column("risk_band", sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='risk_band', native_enum=False), nullable=False, comment='Configured risk band label.'),
        sa.Column("components_json", JSONType, nullable=True, comment='Component signals used in fusion.'),
        sa.Column("explanation_json", JSONType, nullable=True, comment='Structured explanation payload.'),
        sa.Column("caveats_json", JSONType, nullable=True, comment='Missing-data and interpretation caveats.'),
        sa.Column("dataset_fingerprint", sa.String(length=128), nullable=True, comment='Dataset fingerprint for reproducibility.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('score >= 0 AND score <= 100', name='ck_model_assessments_score_range'),
    )
    op.create_index(
        "ix_model_assessments_account_id",
        "model_assessments",
        ["account_id"],
    )
    op.create_index(
        "ix_model_assessments_feature_snapshot_id",
        "model_assessments",
        ["feature_snapshot_id"],
    )
    op.create_index(
        "ix_model_assessments_analysis_run_id",
        "model_assessments",
        ["analysis_run_id"],
    )
    op.create_index(
        "ix_model_assessments_model_version_id",
        "model_assessments",
        ["model_version_id"],
    )
    op.create_index(
        "ix_model_assessments_as_of",
        "model_assessments",
        ["as_of"],
    )
    op.create_index(
        "ix_model_assessments_scored_at",
        "model_assessments",
        ["scored_at"],
    )
    op.create_index(
        "ix_model_assessments_scoring_mode",
        "model_assessments",
        ["scoring_mode"],
    )
    op.create_index(
        "ix_model_assessments_score",
        "model_assessments",
        ["score"],
    )
    op.create_index(
        "ix_model_assessments_risk_band",
        "model_assessments",
        ["risk_band"],
    )
    op.create_index(
        "ix_model_assessments_dataset_fingerprint",
        "model_assessments",
        ["dataset_fingerprint"],
    )
    op.create_index(
        "ix_model_assessments_account_scored",
        "model_assessments",
        ["account_id", "scored_at"],
    )
    op.create_index(
        "ix_model_assessments_account_asof",
        "model_assessments",
        ["account_id", "as_of"],
    )
    op.create_index(
        "ix_model_assessments_band_score",
        "model_assessments",
        ["risk_band", "score"],
    )
    op.create_index(
        "ix_model_assessments_mode_scored",
        "model_assessments",
        ["scoring_mode", "scored_at"],
    )

    op.create_table(
        "rule_hits",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable rule hit identifier.'),
        sa.Column("account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, comment='Account evaluated by the rule.'),
        sa.Column("assessment_id", sa.String(length=64), sa.ForeignKey("model_assessments.id", ondelete="SET NULL"), nullable=True, comment='Assessment associated with this rule hit, if any.'),
        sa.Column("rule_code", sa.String(length=100), nullable=False, comment='Stable rule code.'),
        sa.Column("rule_version", sa.String(length=32), nullable=False, comment='Rule implementation/version.'),
        sa.Column("triggered", sa.Boolean(), nullable=False, comment='Whether the rule triggered.'),
        sa.Column("measured_value", sa.Numeric(precision=18, scale=6), nullable=True, comment='Measured value used by the rule.'),
        sa.Column("threshold", sa.Numeric(precision=18, scale=6), nullable=True, comment='Configured threshold used by the rule.'),
        sa.Column("severity", sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='severity', native_enum=False), nullable=False, comment='Rule severity.'),
        sa.Column("explanation", sa.Text(), nullable=True, comment='Human-readable explanation for analysts.'),
        sa.Column("evidence_refs_json", JSONType, nullable=True, comment='Evidence references that actually triggered the rule.'),
        sa.Column("config_json", JSONType, nullable=True, comment='Safe rule configuration snapshot.'),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False, comment='Rule evaluation timestamp in UTC.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('length(rule_code) > 0', name='ck_rule_hits_code_not_empty'),
    )
    op.create_index(
        "ix_rule_hits_account_id",
        "rule_hits",
        ["account_id"],
    )
    op.create_index(
        "ix_rule_hits_assessment_id",
        "rule_hits",
        ["assessment_id"],
    )
    op.create_index(
        "ix_rule_hits_rule_code",
        "rule_hits",
        ["rule_code"],
    )
    op.create_index(
        "ix_rule_hits_rule_version",
        "rule_hits",
        ["rule_version"],
    )
    op.create_index(
        "ix_rule_hits_triggered",
        "rule_hits",
        ["triggered"],
    )
    op.create_index(
        "ix_rule_hits_severity",
        "rule_hits",
        ["severity"],
    )
    op.create_index(
        "ix_rule_hits_evaluated_at",
        "rule_hits",
        ["evaluated_at"],
    )
    op.create_index(
        "ix_rule_hits_account_rule_evaluated",
        "rule_hits",
        ["account_id", "rule_code", "evaluated_at"],
    )
    op.create_index(
        "ix_rule_hits_triggered_severity",
        "rule_hits",
        ["triggered", "severity"],
    )

    op.create_table(
        "risk_indicators",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable indicator identifier.'),
        sa.Column("assessment_id", sa.String(length=64), sa.ForeignKey("model_assessments.id", ondelete="RESTRICT"), nullable=False, comment='Assessment to which this indicator belongs.'),
        sa.Column("indicator_type", sa.Enum('RULE', 'MODEL', 'ANOMALY', 'GRAPH', 'COMPLAINT', 'FEATURE', 'FUSED_RISK', name='indicator_type', native_enum=False), nullable=False, comment='Source type of the indicator.'),
        sa.Column("code", sa.String(length=100), nullable=False, comment='Stable indicator code.'),
        sa.Column("title", sa.String(length=200), nullable=False, comment='Human-readable indicator title.'),
        sa.Column("severity", sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='severity', native_enum=False), nullable=False, comment='Indicator severity.'),
        sa.Column("measured_value", sa.Numeric(precision=18, scale=6), nullable=True, comment='Measured value behind the indicator.'),
        sa.Column("threshold", sa.Numeric(precision=18, scale=6), nullable=True, comment='Threshold or comparison value, if applicable.'),
        sa.Column("explanation", sa.Text(), nullable=True, comment='Analyst-facing explanation.'),
        sa.Column("evidence_refs_json", JSONType, nullable=True, comment='Evidence references supporting the indicator.'),
        sa.Column("config_json", JSONType, nullable=True, comment='Safe indicator configuration metadata.'),
        sa.Column("rule_hit_id", sa.String(length=64), sa.ForeignKey("rule_hits.id", ondelete="SET NULL"), nullable=True, comment='Associated rule hit, if this indicator came from a rule.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('length(code) > 0', name='ck_risk_indicators_code_not_empty'),
    )
    op.create_index(
        "ix_risk_indicators_assessment_id",
        "risk_indicators",
        ["assessment_id"],
    )
    op.create_index(
        "ix_risk_indicators_indicator_type",
        "risk_indicators",
        ["indicator_type"],
    )
    op.create_index(
        "ix_risk_indicators_code",
        "risk_indicators",
        ["code"],
    )
    op.create_index(
        "ix_risk_indicators_severity",
        "risk_indicators",
        ["severity"],
    )
    op.create_index(
        "ix_risk_indicators_rule_hit_id",
        "risk_indicators",
        ["rule_hit_id"],
    )
    op.create_index(
        "ix_risk_indicators_assessment_type",
        "risk_indicators",
        ["assessment_id", "indicator_type"],
    )
    op.create_index(
        "ix_risk_indicators_code_severity",
        "risk_indicators",
        ["code", "severity"],
    )

    op.create_table(
        "alerts",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable alert identifier.'),
        sa.Column("account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, comment='Alerted synthetic account.'),
        sa.Column("assessment_id", sa.String(length=64), sa.ForeignKey("model_assessments.id", ondelete="SET NULL"), nullable=True, comment='Assessment that raised the alert, if any.'),
        sa.Column("title", sa.String(length=200), nullable=False, comment='Alert title.'),
        sa.Column("summary", sa.Text(), nullable=True, comment='Alert summary for queue display.'),
        sa.Column("priority", sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='priority', native_enum=False), nullable=False, comment='Alert priority band.'),
        sa.Column("state", sa.Enum('NEW', 'ACKNOWLEDGED', 'UNDER_REVIEW', 'ESCALATED', 'CLOSED', name='alert_state', native_enum=False), nullable=False, comment='Alert triage state.'),
        sa.Column("score", sa.Numeric(precision=7, scale=2), nullable=True, comment='Investigative priority score associated with the alert.'),
        sa.Column("score_version", sa.String(length=32), nullable=True, comment='Risk score version.'),
        sa.Column("scoring_mode", sa.Enum('TRAINED_MODEL', 'HEURISTIC_FALLBACK', 'RULES_ONLY', 'ML_DISABLED', 'UNKNOWN', name='scoring_mode', native_enum=False), nullable=False, comment='Scoring mode that produced the alert.'),
        sa.Column("model_version", sa.String(length=64), nullable=True, comment='Model version label, if trained model scoring was used.'),
        sa.Column("signal_summary_json", JSONType, nullable=True, comment='Safe summary of rule/model/graph/complaint signals.'),
        sa.Column("rule_codes_json", JSONType, nullable=True, comment='Triggered rule codes contributing to the alert.'),
        sa.Column("dedup_key", sa.String(length=255), nullable=True, unique=True, comment='Idempotency/deduplication key for open alert prevention.'),
        sa.Column("dedup_window_start", sa.DateTime(timezone=True), nullable=True, comment='Detection window start used for deduplication.'),
        sa.Column("dedup_window_end", sa.DateTime(timezone=True), nullable=True, comment='Detection window end used for deduplication.'),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, comment='First time this alert signature was seen.'),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, comment='Most recent time this alert signature was seen.'),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True, comment='Acknowledgement timestamp.'),
        sa.Column("acknowledged_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User who acknowledged the alert.'),
        sa.Column("assigned_to", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User assigned to triage the alert.'),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True, comment='Alert closure timestamp, if closed without case.'),
        sa.Column("created_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User or system that created the alert.'),
        sa.Column("updated_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User that last materially updated the alert.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('score IS NULL OR (score >= 0 AND score <= 100)', name='ck_alerts_score_range'),
    )
    op.create_index(
        "ix_alerts_account_id",
        "alerts",
        ["account_id"],
    )
    op.create_index(
        "ix_alerts_assessment_id",
        "alerts",
        ["assessment_id"],
    )
    op.create_index(
        "ix_alerts_priority",
        "alerts",
        ["priority"],
    )
    op.create_index(
        "ix_alerts_state",
        "alerts",
        ["state"],
    )
    op.create_index(
        "ix_alerts_score",
        "alerts",
        ["score"],
    )
    op.create_index(
        "ix_alerts_scoring_mode",
        "alerts",
        ["scoring_mode"],
    )
    op.create_index(
        "ix_alerts_dedup_key",
        "alerts",
        ["dedup_key"],
    )
    op.create_index(
        "ix_alerts_first_seen_at",
        "alerts",
        ["first_seen_at"],
    )
    op.create_index(
        "ix_alerts_last_seen_at",
        "alerts",
        ["last_seen_at"],
    )
    op.create_index(
        "ix_alerts_acknowledged_by",
        "alerts",
        ["acknowledged_by"],
    )
    op.create_index(
        "ix_alerts_assigned_to",
        "alerts",
        ["assigned_to"],
    )
    op.create_index(
        "ix_alerts_state_priority_created",
        "alerts",
        ["state", "priority", "record_created_at"],
    )
    op.create_index(
        "ix_alerts_account_state",
        "alerts",
        ["account_id", "state"],
    )
    op.create_index(
        "ix_alerts_mode_state",
        "alerts",
        ["scoring_mode", "state"],
    )

    op.create_table(
        "alert_evidence",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable alert evidence identifier.'),
        sa.Column("alert_id", sa.String(length=64), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=False, comment='Alert to which evidence is attached.'),
        sa.Column("evidence_type", sa.Enum('ACCOUNT', 'TRANSACTION', 'COMPLAINT', 'ALERT', 'GRAPH_PATH', 'MODEL_ASSESSMENT', 'ENTITY_LINK', name='evidence_type', native_enum=False), nullable=False, comment='Validated evidence type.'),
        sa.Column("evidence_id", sa.String(length=128), nullable=False, comment='Identifier of the referenced evidence record.'),
        sa.Column("evidence_snapshot_json", JSONType, nullable=True, comment='Safe structured snapshot of what was shown at alert time.'),
        sa.Column("provenance_json", JSONType, nullable=True, comment='Provenance metadata for the evidence reference.'),
        sa.Column("created_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User or system that attached the evidence.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('alert_id', 'evidence_type', 'evidence_id', name='uq_alert_evidence_alert_type_id'),
        sa.CheckConstraint('length(evidence_id) > 0', name='ck_alert_evidence_id_not_empty'),
    )
    op.create_index(
        "ix_alert_evidence_alert_id",
        "alert_evidence",
        ["alert_id"],
    )
    op.create_index(
        "ix_alert_evidence_evidence_type",
        "alert_evidence",
        ["evidence_type"],
    )
    op.create_index(
        "ix_alert_evidence_evidence_id",
        "alert_evidence",
        ["evidence_id"],
    )
    op.create_index(
        "ix_alert_evidence_type_id",
        "alert_evidence",
        ["evidence_type", "evidence_id"],
    )

    op.create_table(
        "investigation_cases",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable case identifier.'),
        sa.Column("title", sa.String(length=200), nullable=False, comment='Case title.'),
        sa.Column("description", sa.Text(), nullable=True, comment='Case description.'),
        sa.Column("status", sa.Enum('NEW', 'TRIAGED', 'UNDER_INVESTIGATION', 'ESCALATED', 'CLOSED', name='case_status', native_enum=False), nullable=False, comment='Case workflow state.'),
        sa.Column("priority", sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='priority', native_enum=False), nullable=False, comment='Case priority.'),
        sa.Column("assignee_id", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='Assigned investigator user.'),
        sa.Column("creator_id", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User who created the case.'),
        sa.Column("alert_id", sa.String(length=64), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, comment='Alert from which the case was created, if any.'),
        sa.Column("account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True, comment='Primary account under investigation, if any.'),
        sa.Column("disposition", sa.Enum('CONFIRMED_FRAUD', 'FALSE_POSITIVE', 'INCONCLUSIVE', 'REFERRED', name='disposition', native_enum=False), nullable=True, comment='Investigator-entered closure disposition.'),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True, comment='Case closure timestamp.'),
        sa.Column("closed_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User who closed the case.'),
        sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True, comment='Most recent reopen timestamp.'),
        sa.Column("reopened_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User who reopened the case.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Non-sensitive case metadata.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status <> 'CLOSED' OR disposition IS NOT NULL", name='ck_cases_closed_requires_disposition'),
    )
    op.create_index(
        "ix_investigation_cases_status",
        "investigation_cases",
        ["status"],
    )
    op.create_index(
        "ix_investigation_cases_priority",
        "investigation_cases",
        ["priority"],
    )
    op.create_index(
        "ix_investigation_cases_assignee_id",
        "investigation_cases",
        ["assignee_id"],
    )
    op.create_index(
        "ix_investigation_cases_creator_id",
        "investigation_cases",
        ["creator_id"],
    )
    op.create_index(
        "ix_investigation_cases_alert_id",
        "investigation_cases",
        ["alert_id"],
    )
    op.create_index(
        "ix_investigation_cases_account_id",
        "investigation_cases",
        ["account_id"],
    )
    op.create_index(
        "ix_investigation_cases_disposition",
        "investigation_cases",
        ["disposition"],
    )
    op.create_index(
        "ix_cases_status_priority_updated",
        "investigation_cases",
        ["status", "priority", "record_updated_at"],
    )
    op.create_index(
        "ix_cases_assignee_status",
        "investigation_cases",
        ["assignee_id", "status"],
    )
    op.create_index(
        "ix_cases_account_status",
        "investigation_cases",
        ["account_id", "status"],
    )

    op.create_table(
        "case_evidence",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable case evidence identifier.'),
        sa.Column("case_id", sa.String(length=64), sa.ForeignKey("investigation_cases.id", ondelete="RESTRICT"), nullable=False, comment='Case to which evidence is attached.'),
        sa.Column("evidence_type", sa.Enum('ACCOUNT', 'TRANSACTION', 'COMPLAINT', 'ALERT', 'GRAPH_PATH', 'MODEL_ASSESSMENT', 'ENTITY_LINK', name='evidence_type', native_enum=False), nullable=False, comment='Validated evidence type.'),
        sa.Column("evidence_id", sa.String(length=128), nullable=False, comment='Identifier of the referenced evidence record.'),
        sa.Column("evidence_snapshot_json", JSONType, nullable=True, comment='Safe structured snapshot of evidence at attachment time.'),
        sa.Column("provenance_json", JSONType, nullable=True, comment='Provenance metadata for the evidence reference.'),
        sa.Column("added_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User who added the evidence.'),
        sa.Column("removed_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User who removed the evidence, if soft-removed.'),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True, comment='Removal timestamp, if soft-removed.'),
        sa.Column("removal_reason", sa.Text(), nullable=True, comment='Reason for evidence removal.'),
        sa.Column("is_active", sa.Boolean(), nullable=False, comment='Whether the evidence attachment is currently active.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('length(evidence_id) > 0', name='ck_case_evidence_id_not_empty'),
    )
    op.create_index(
        "ix_case_evidence_case_id",
        "case_evidence",
        ["case_id"],
    )
    op.create_index(
        "ix_case_evidence_evidence_type",
        "case_evidence",
        ["evidence_type"],
    )
    op.create_index(
        "ix_case_evidence_evidence_id",
        "case_evidence",
        ["evidence_id"],
    )
    op.create_index(
        "ix_case_evidence_added_by",
        "case_evidence",
        ["added_by"],
    )
    op.create_index(
        "ix_case_evidence_is_active",
        "case_evidence",
        ["is_active"],
    )
    op.create_index(
        "ix_case_evidence_case_active",
        "case_evidence",
        ["case_id", "is_active"],
    )
    op.create_index(
        "ix_case_evidence_type_id",
        "case_evidence",
        ["evidence_type", "evidence_id"],
    )

    op.create_table(
        "case_events",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable case event identifier.'),
        sa.Column("case_id", sa.String(length=64), sa.ForeignKey("investigation_cases.id", ondelete="RESTRICT"), nullable=False, comment='Case to which the event belongs.'),
        sa.Column("actor_id", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User actor, if known.'),
        sa.Column("actor_username", sa.String(length=64), nullable=True, comment='Denormalised actor username for system/history resilience.'),
        sa.Column("action", sa.String(length=100), nullable=False, comment='Case action, e.g. created, assigned, status_change.'),
        sa.Column("resource_type", sa.String(length=100), nullable=True, comment='Resource type affected by the event.'),
        sa.Column("resource_id", sa.String(length=128), nullable=True, comment='Resource identifier affected by the event.'),
        sa.Column("summary", sa.Text(), nullable=True, comment='Safe human-readable event summary.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Sanitized event metadata.'),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, comment='Event timestamp in UTC.'),
        sa.CheckConstraint('length(action) > 0', name='ck_case_events_action_not_empty'),
    )
    op.create_index(
        "ix_case_events_case_id",
        "case_events",
        ["case_id"],
    )
    op.create_index(
        "ix_case_events_actor_id",
        "case_events",
        ["actor_id"],
    )
    op.create_index(
        "ix_case_events_action",
        "case_events",
        ["action"],
    )
    op.create_index(
        "ix_case_events_resource_id",
        "case_events",
        ["resource_id"],
    )
    op.create_index(
        "ix_case_events_created_at",
        "case_events",
        ["created_at"],
    )
    op.create_index(
        "ix_case_events_case_created",
        "case_events",
        ["case_id", "created_at"],
    )
    op.create_index(
        "ix_case_events_action_created",
        "case_events",
        ["action", "created_at"],
    )

    op.create_table(
        "case_notes",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable note identifier.'),
        sa.Column("case_id", sa.String(length=64), sa.ForeignKey("investigation_cases.id", ondelete="RESTRICT"), nullable=False, comment='Case to which the note belongs.'),
        sa.Column("author_id", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='Note author user.'),
        sa.Column("body", sa.Text(), nullable=False, comment='Note body. Must not contain secrets or real customer data.'),
        sa.Column("is_internal", sa.Boolean(), nullable=False, comment='Whether the note is internal-only.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Non-sensitive note metadata.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('length(body) > 0', name='ck_case_notes_body_not_empty'),
    )
    op.create_index(
        "ix_case_notes_case_id",
        "case_notes",
        ["case_id"],
    )
    op.create_index(
        "ix_case_notes_author_id",
        "case_notes",
        ["author_id"],
    )
    op.create_index(
        "ix_case_notes_case_created",
        "case_notes",
        ["case_id", "record_created_at"],
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable audit event identifier.'),
        sa.Column("actor_id", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='Authenticated user actor, if known.'),
        sa.Column("actor_username", sa.String(length=64), nullable=True, comment='Denormalised actor username.'),
        sa.Column("actor_role", sa.String(length=50), nullable=True, comment='Actor role at time of action.'),
        sa.Column("action", sa.String(length=100), nullable=False, comment='Audited action name.'),
        sa.Column("resource_type", sa.String(length=100), nullable=True, comment='Target resource type.'),
        sa.Column("resource_id", sa.String(length=128), nullable=True, comment='Target resource identifier.'),
        sa.Column("outcome", sa.Enum('SUCCESS', 'FAILURE', 'DENIED', 'WARNING', name='audit_outcome', native_enum=False), nullable=False, comment='Action outcome.'),
        sa.Column("request_id", sa.String(length=64), nullable=True, comment='Request/correlation identifier.'),
        sa.Column("correlation_id", sa.String(length=64), nullable=True, comment='Optional external correlation identifier.'),
        sa.Column("ip_hash", sa.String(length=128), nullable=True, comment='Hashed source IP, not raw IP.'),
        sa.Column("user_agent_hash", sa.String(length=128), nullable=True, comment='Hashed user agent, not raw user agent.'),
        sa.Column("metadata_json", JSONType, nullable=True, comment='Sanitized metadata only.'),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, comment='Audit event timestamp in UTC.'),
        sa.CheckConstraint('length(action) > 0', name='ck_audit_events_action_not_empty'),
    )
    op.create_index(
        "ix_audit_events_actor_id",
        "audit_events",
        ["actor_id"],
    )
    op.create_index(
        "ix_audit_events_actor_username",
        "audit_events",
        ["actor_username"],
    )
    op.create_index(
        "ix_audit_events_action",
        "audit_events",
        ["action"],
    )
    op.create_index(
        "ix_audit_events_resource_type",
        "audit_events",
        ["resource_type"],
    )
    op.create_index(
        "ix_audit_events_resource_id",
        "audit_events",
        ["resource_id"],
    )
    op.create_index(
        "ix_audit_events_outcome",
        "audit_events",
        ["outcome"],
    )
    op.create_index(
        "ix_audit_events_request_id",
        "audit_events",
        ["request_id"],
    )
    op.create_index(
        "ix_audit_events_created_at",
        "audit_events",
        ["created_at"],
    )
    op.create_index(
        "ix_audit_events_actor_created",
        "audit_events",
        ["actor_id", "created_at"],
    )
    op.create_index(
        "ix_audit_events_action_created",
        "audit_events",
        ["action", "created_at"],
    )
    op.create_index(
        "ix_audit_events_resource_created",
        "audit_events",
        ["resource_type", "resource_id", "created_at"],
    )
    op.create_index(
        "ix_audit_events_outcome_created",
        "audit_events",
        ["outcome", "created_at"],
    )

    op.create_table(
        "complaint_correlations",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable correlation identifier.'),
        sa.Column("complaint_id", sa.String(length=64), sa.ForeignKey("complaints.id", ondelete="RESTRICT"), nullable=False, comment='Complaint being correlated.'),
        sa.Column("account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True, comment='Associated account, if matched.'),
        sa.Column("transaction_id", sa.String(length=64), sa.ForeignKey("transactions.id", ondelete="SET NULL"), nullable=True, comment='Associated transaction, if matched.'),
        sa.Column("entity_id", sa.String(length=64), sa.ForeignKey("entities.id", ondelete="SET NULL"), nullable=True, comment='Associated entity, if matched.'),
        sa.Column("match_tier", sa.Integer(), nullable=False, comment='Correlation tier: 1 exact, 2 normalised, 3 entity, 4 temporal, 5 narrative.'),
        sa.Column("match_method", sa.Enum('EXACT', 'NORMALIZED', 'ENTITY_TEMPORAL', 'GRAPH_TEMPORAL', 'NARRATIVE_EXTRACTION', 'MANUAL', 'UNKNOWN', name='match_method', native_enum=False), nullable=False, comment='Method used to establish the correlation.'),
        sa.Column("confidence", sa.Numeric(precision=5, scale=4), nullable=True, comment='Confidence for inferred correlations, between 0 and 1.'),
        sa.Column("deterministic", sa.Boolean(), nullable=False, comment='Whether the match is deterministic rather than inferred.'),
        sa.Column("review_state", sa.Enum('UNREVIEWED', 'REVIEWED', 'ACCEPTED', 'REJECTED', 'NEEDS_MORE_INFO', name='complaint_review_state', native_enum=False), nullable=False, comment='Analyst review state for the correlation.'),
        sa.Column("evidence_refs_json", JSONType, nullable=True, comment='Evidence references supporting the correlation.'),
        sa.Column("provenance_json", JSONType, nullable=True, comment='Match provenance and source metadata.'),
        sa.Column("normalized_values_json", JSONType, nullable=True, comment='Normalised values used for matching, separate from raw facts.'),
        sa.Column("created_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User or system that created the correlation.'),
        sa.Column("reviewed_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='Reviewer user.'),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True, comment='Review timestamp.'),
        sa.Column("notes", sa.Text(), nullable=True, comment='Reviewer notes, without leaking secrets.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('match_tier BETWEEN 1 AND 5', name='ck_complaint_correlations_tier_range'),
        sa.CheckConstraint('confidence IS NULL OR (confidence >= 0 AND confidence <= 1)', name='ck_complaint_correlations_confidence_range'),
    )
    op.create_index(
        "ix_complaint_correlations_complaint_id",
        "complaint_correlations",
        ["complaint_id"],
    )
    op.create_index(
        "ix_complaint_correlations_account_id",
        "complaint_correlations",
        ["account_id"],
    )
    op.create_index(
        "ix_complaint_correlations_transaction_id",
        "complaint_correlations",
        ["transaction_id"],
    )
    op.create_index(
        "ix_complaint_correlations_entity_id",
        "complaint_correlations",
        ["entity_id"],
    )
    op.create_index(
        "ix_complaint_correlations_match_tier",
        "complaint_correlations",
        ["match_tier"],
    )
    op.create_index(
        "ix_complaint_correlations_match_method",
        "complaint_correlations",
        ["match_method"],
    )
    op.create_index(
        "ix_complaint_correlations_deterministic",
        "complaint_correlations",
        ["deterministic"],
    )
    op.create_index(
        "ix_complaint_correlations_review_state",
        "complaint_correlations",
        ["review_state"],
    )
    op.create_index(
        "ix_complaint_correlations_complaint_tier",
        "complaint_correlations",
        ["complaint_id", "match_tier"],
    )
    op.create_index(
        "ix_complaint_correlations_account_review",
        "complaint_correlations",
        ["account_id", "review_state"],
    )
    op.create_index(
        "ix_complaint_correlations_transaction_review",
        "complaint_correlations",
        ["transaction_id", "review_state"],
    )
    op.create_index(
        "ix_complaint_correlations_method_deterministic",
        "complaint_correlations",
        ["match_method", "deterministic"],
    )

    op.create_table(
        "graph_analysis_runs",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable graph analysis identifier.'),
        sa.Column("analysis_run_id", sa.String(length=64), sa.ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, comment='Parent batch analysis run, if part of a larger run.'),
        sa.Column("root_account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, comment='Root account for bounded graph query.'),
        sa.Column("parameters_json", JSONType, nullable=True, comment='Safe graph query parameters, including limits.'),
        sa.Column("node_count", sa.Integer(), nullable=False, comment='Number of nodes returned.'),
        sa.Column("edge_count", sa.Integer(), nullable=False, comment='Number of edges returned.'),
        sa.Column("metrics_json", JSONType, nullable=True, comment='Graph metrics summary.'),
        sa.Column("paths_json", JSONType, nullable=True, comment='Bounded candidate path results with transaction evidence.'),
        sa.Column("capped", sa.Boolean(), nullable=False, comment='Whether result limits truncated the output.'),
        sa.Column("limitations_json", JSONType, nullable=True, comment='Interpretation limitations for graph output.'),
        sa.Column("created_by", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, comment='User who initiated the graph analysis.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('node_count >= 0', name='ck_graph_analysis_runs_node_count_nonnegative'),
        sa.CheckConstraint('edge_count >= 0', name='ck_graph_analysis_runs_edge_count_nonnegative'),
    )
    op.create_index(
        "ix_graph_analysis_runs_analysis_run_id",
        "graph_analysis_runs",
        ["analysis_run_id"],
    )
    op.create_index(
        "ix_graph_analysis_runs_root_account_id",
        "graph_analysis_runs",
        ["root_account_id"],
    )
    op.create_index(
        "ix_graph_analysis_runs_root_created",
        "graph_analysis_runs",
        ["root_account_id", "record_created_at"],
    )

    op.create_table(
        "ground_truth_labels",
        sa.Column("id", sa.String(length=64), nullable=False, primary_key=True, comment='Stable ground-truth identifier.'),
        sa.Column("account_id", sa.String(length=64), sa.ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, unique=True, comment='Synthetic account label target.'),
        sa.Column("ground_truth_label", sa.Boolean(), nullable=False, comment='Injected synthetic label. Never use as predictor feature.'),
        sa.Column("scenario_id", sa.String(length=100), nullable=True, comment='Injected scenario identifier, isolated from model inputs.'),
        sa.Column("ring_id", sa.String(length=100), nullable=True, comment='Synthetic fraud-ring identifier, isolated from model inputs.'),
        sa.Column("scenario_type", sa.String(length=100), nullable=True, comment='Scenario family, e.g. rapid_pass_through, fan_in, hard_negative.'),
        sa.Column("label_source", sa.String(length=100), nullable=False, comment='How the synthetic label was produced.'),
        sa.Column("notes", sa.Text(), nullable=True, comment='Non-sensitive generator notes.'),
        sa.Column("record_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('length(label_source) > 0', name='ck_ground_truth_labels_source_not_empty'),
    )
    op.create_index(
        "ix_ground_truth_labels_account_id",
        "ground_truth_labels",
        ["account_id"],
    )
    op.create_index(
        "ix_ground_truth_labels_scenario_id",
        "ground_truth_labels",
        ["scenario_id"],
    )
    op.create_index(
        "ix_ground_truth_labels_ring_id",
        "ground_truth_labels",
        ["ring_id"],
    )
    op.create_index(
        "ix_ground_truth_labels_scenario_type",
        "ground_truth_labels",
        ["scenario_type"],
    )


def downgrade() -> None:
    """
    Drop every MULEGUARD table in reverse dependency order.

    Indexes and constraints are dropped implicitly with their tables.
    """

    op.drop_table("ground_truth_labels")
    op.drop_table("graph_analysis_runs")
    op.drop_table("complaint_correlations")
    op.drop_table("audit_events")
    op.drop_table("case_notes")
    op.drop_table("case_events")
    op.drop_table("case_evidence")
    op.drop_table("investigation_cases")
    op.drop_table("alert_evidence")
    op.drop_table("alerts")
    op.drop_table("risk_indicators")
    op.drop_table("rule_hits")
    op.drop_table("model_assessments")
    op.drop_table("model_evaluations")
    op.drop_table("analysis_runs")
    op.drop_table("model_versions")
    op.drop_table("feature_snapshots")
    op.drop_table("account_entity_links")
    op.drop_table("entities")
    op.drop_table("complaints")
    op.drop_table("transactions")
    op.drop_table("accounts")
    op.drop_table("users")
