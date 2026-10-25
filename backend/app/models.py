"""
MULEGUARD backend domain models.

This module defines the persisted source of truth for the MULEGUARD synthetic
financial-crime investigation prototype.

Design rules:

- PostgreSQL is the intended deployment source of truth.
- SQLite is supported for local development and tests where configured.
- Alembic migrations are the deployed schema-management path.
- Monetary values use Decimal / SQL NUMERIC.
- Timestamps are timezone-aware and UTC-normalised by application services.
- Alerts, scores, graph relationships, candidate money trails, and complaint
  correlations are investigative leads, not proof of wrongdoing.
- Synthetic ground-truth labels are isolated in a dedicated table and must not
  be used as model predictor features.
- Evidence references must point to validated persisted records where possible.
- No real bank credentials, card numbers, PINs, OTPs, or online-banking secrets
  are stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum as PyEnum
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.vocabularies import (
    AccountStatus,
    AccountType,
    CaseStatus,
    Channel,
    Disposition,
    EntityType,
    MatchMethod,
    TransactionStatus,
    VerificationState,
)
from app.db import Base


# -----------------------------------------------------------------------------
# Shared runtime helpers
# -----------------------------------------------------------------------------

JSONType = JSON().with_variant(JSONB, "postgresql")


def utcnow() -> datetime:
    """
    Return a timezone-aware UTC timestamp.
    """
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    """
    Generate a stable string UUID for runtime-created records.

    Synthetic seed data should provide deterministic IDs where reproducibility
    is required. This default is mainly for API-created cases, alerts, audit
    events, and other runtime records.
    """
    return str(uuid.uuid4())


def enum_column(enum_cls: type[PyEnum], *, name: Optional[str] = None) -> SAEnum:
    """
    Build a portable SQLAlchemy Enum column type.

    Uses native_enum=False so the same model definitions work reasonably across
    PostgreSQL and SQLite. Values are stored as their string enum values.
    """
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        values_callable=lambda e: [item.value for item in e],
    )


# -----------------------------------------------------------------------------
# Reusable mixins
# -----------------------------------------------------------------------------


class RecordTimestampMixin:
    """
    Record-level audit timestamps.

    These are distinct from domain timestamps such as Transaction.occurred_at
    or Account.created_at.
    """

    record_created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="Record creation timestamp in UTC.",
    )
    record_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
        comment="Record last-update timestamp in UTC.",
    )


class ProvenanceMixin:
    """
    Lightweight data-lineage fields for imported or generated records.

    These fields support reproducibility and investigation provenance without
    storing raw sensitive payloads by default.
    """

    source_system: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Logical source system or generator name.",
    )
    source_batch_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Batch identifier for bulk ingestion or generation.",
    )
    ingestion_run_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="Ingestion run identifier where available.",
    )
    source_payload_hash: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Hash of original source payload for lineage, not raw payload.",
    )


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


# The vocabularies that describe ingested records live in
# `app.core.vocabularies` and are re-exported here.
#
# The ingestion normalizer, the ingestion validator, the synthetic generator
# and the ML feature builder all need the same sets, and each used to carry
# its own copy. The copies had drifted from these columns on every field, so
# ingestion rejected values the database accepts and accepted values it does
# not. One dependency-light definition, imported by everything including this
# module, removes the possibility.
#
# Re-exporting keeps `from app.models import AccountType` working, which is
# how the rest of the application refers to them.


class ComplaintReviewState(str, PyEnum):
    UNREVIEWED = "UNREVIEWED"
    REVIEWED = "REVIEWED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    NEEDS_MORE_INFO = "NEEDS_MORE_INFO"


class Severity(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Priority(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskBand(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScoringMode(str, PyEnum):
    TRAINED_MODEL = "TRAINED_MODEL"
    HEURISTIC_FALLBACK = "HEURISTIC_FALLBACK"
    RULES_ONLY = "RULES_ONLY"
    ML_DISABLED = "ML_DISABLED"
    UNKNOWN = "UNKNOWN"


class IndicatorType(str, PyEnum):
    RULE = "RULE"
    MODEL = "MODEL"
    ANOMALY = "ANOMALY"
    GRAPH = "GRAPH"
    COMPLAINT = "COMPLAINT"
    FEATURE = "FEATURE"
    FUSED_RISK = "FUSED_RISK"


class AlertState(str, PyEnum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    UNDER_REVIEW = "UNDER_REVIEW"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"


class EvidenceType(str, PyEnum):
    ACCOUNT = "ACCOUNT"
    TRANSACTION = "TRANSACTION"
    COMPLAINT = "COMPLAINT"
    ALERT = "ALERT"
    GRAPH_PATH = "GRAPH_PATH"
    MODEL_ASSESSMENT = "MODEL_ASSESSMENT"
    ENTITY_LINK = "ENTITY_LINK"


class UserRole(str, PyEnum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    SENIOR_INVESTIGATOR = "SENIOR_INVESTIGATOR"
    AUDITOR = "AUDITOR"


class AuditOutcome(str, PyEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    WARNING = "WARNING"


class AnalysisRunStatus(str, PyEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIAL = "PARTIAL"


class ModelType(str, PyEnum):
    HIST_GRADIENT_BOOSTING = "HIST_GRADIENT_BOOSTING"
    RANDOM_FOREST = "RANDOM_FOREST"
    LOGISTIC_REGRESSION = "LOGISTIC_REGRESSION"
    ISOLATION_FOREST = "ISOLATION_FOREST"
    RULES_ONLY = "RULES_ONLY"
    HEURISTIC_FALLBACK = "HEURISTIC_FALLBACK"
    UNKNOWN = "UNKNOWN"


class SplitStrategy(str, PyEnum):
    CHRONOLOGICAL = "CHRONOLOGICAL"
    SCENARIO_AWARE_CHRONOLOGICAL = "SCENARIO_AWARE_CHRONOLOGICAL"
    GROUP_AWARE_RANDOM = "GROUP_AWARE_RANDOM"
    RANDOM = "RANDOM"
    UNKNOWN = "UNKNOWN"


# -----------------------------------------------------------------------------
# Users and authentication
# -----------------------------------------------------------------------------


class User(Base, RecordTimestampMixin):
    """
    Local prototype user account.

    Passwords must be stored as salted hashes. Inactive users must not be able
    to authenticate. Role checks are enforced in backend dependencies/services,
    not merely in the frontend.
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable user identifier.",
    )
    username: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique login username.",
    )
    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique email address.",
    )
    full_name: Mapped[Optional[str]] = mapped_column(
        String(200),
        nullable=True,
        comment="Optional display name.",
    )
    role: Mapped[UserRole] = mapped_column(
        enum_column(UserRole),
        nullable=False,
        default=UserRole.ANALYST,
        index=True,
        comment="Role used for server-side RBAC.",
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Salted password hash. Never store plaintext passwords.",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Inactive users must not authenticate.",
    )
    must_change_password: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Force password change on next login where implemented.",
    )
    failed_login_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Failed login counter for throttling/lockout.",
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Temporary account lockout expiry, if used.",
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last successful login timestamp in UTC.",
    )
    last_login_ip_hash: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Hashed source IP for security auditing, not raw IP.",
    )

    # Relationships
    assigned_cases: Mapped[list["InvestigationCase"]] = relationship(
        "InvestigationCase",
        foreign_keys="InvestigationCase.assignee_id",
        back_populates="assignee",
    )
    created_cases: Mapped[list["InvestigationCase"]] = relationship(
        "InvestigationCase",
        foreign_keys="InvestigationCase.creator_id",
        back_populates="creator",
    )
    acknowledged_alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        foreign_keys="Alert.acknowledged_by",
        back_populates="acknowledged_by_user",
    )
    assigned_alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        foreign_keys="Alert.assigned_to",
        back_populates="assigned_to_user",
    )
    requested_analysis_runs: Mapped[list["AnalysisRun"]] = relationship(
        "AnalysisRun",
        foreign_keys="AnalysisRun.requested_by",
        back_populates="requested_by_user",
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(
        "AuditEvent",
        back_populates="actor",
    )

    __table_args__ = (
        Index("ix_users_role_active", "role", "is_active"),
        CheckConstraint(
            "length(username) > 0",
            name="ck_users_username_not_empty",
        ),
        CheckConstraint(
            "length(email) > 0",
            name="ck_users_email_not_empty",
        ),
    )


# -----------------------------------------------------------------------------
# Core financial-domain records
# -----------------------------------------------------------------------------


class Account(Base, RecordTimestampMixin):
    """
    Synthetic bank account.

    Account status is observational only. It must not be interpreted as an
    automatic enforcement control.
    """

    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable synthetic account identifier.",
    )
    account_type: Mapped[AccountType] = mapped_column(
        enum_column(AccountType),
        nullable=False,
        default=AccountType.OTHER,
        index=True,
        comment="Synthetic account type.",
    )
    status: Mapped[AccountStatus] = mapped_column(
        enum_column(AccountStatus),
        nullable=False,
        default=AccountStatus.ACTIVE,
        index=True,
        comment="Synthetic lifecycle status; not an enforcement action.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
        comment="Account creation timestamp in the synthetic domain.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Non-sensitive synthetic attributes only.",
    )

    # Relationships
    sender_transactions: Mapped[list["Transaction"]] = relationship(
        "Transaction",
        foreign_keys="Transaction.sender_account_id",
        back_populates="sender_account",
    )
    receiver_transactions: Mapped[list["Transaction"]] = relationship(
        "Transaction",
        foreign_keys="Transaction.receiver_account_id",
        back_populates="receiver_account",
    )
    entity_links: Mapped[list["AccountEntityLink"]] = relationship(
        "AccountEntityLink",
        back_populates="account",
    )
    feature_snapshots: Mapped[list["FeatureSnapshot"]] = relationship(
        "FeatureSnapshot",
        back_populates="account",
    )
    assessments: Mapped[list["ModelAssessment"]] = relationship(
        "ModelAssessment",
        back_populates="account",
    )
    rule_hits: Mapped[list["RuleHit"]] = relationship(
        "RuleHit",
        back_populates="account",
    )
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="account",
    )
    complaint_correlations: Mapped[list["ComplaintCorrelation"]] = relationship(
        "ComplaintCorrelation",
        back_populates="account",
    )
    ground_truth_label: Mapped[Optional["GroundTruthLabel"]] = relationship(
        "GroundTruthLabel",
        back_populates="account",
        uselist=False,
    )

    __table_args__ = (
        Index("ix_accounts_type_status_created", "account_type", "status", "created_at"),
        CheckConstraint(
            "length(id) > 0",
            name="ck_accounts_id_not_empty",
        ),
    )


class Transaction(Base, RecordTimestampMixin, ProvenanceMixin):
    """
    Synthetic transfer record.

    Only qualifying completed statuses should be treated as completed fund
    movement in graph and feature logic. Failed or reversed transactions must
    not be silently counted as successful transfers.
    """

    __tablename__ = "transactions"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable transaction identifier.",
    )
    sender_account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Sending synthetic account.",
    )
    receiver_account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Receiving synthetic account.",
    )
    amount: Mapped[Decimal] = mapped_column(
        Numeric(18, 2),
        nullable=False,
        comment="Transfer amount. Must be positive for completed transfers.",
    )
    currency: Mapped[str] = mapped_column(
        String(3),
        nullable=False,
        default="INR",
        comment="ISO-style currency code, normalised uppercase.",
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Transaction timestamp in UTC.",
    )
    status: Mapped[TransactionStatus] = mapped_column(
        enum_column(TransactionStatus),
        nullable=False,
        default=TransactionStatus.COMPLETED,
        index=True,
        comment="Transaction lifecycle status.",
    )
    channel: Mapped[Channel] = mapped_column(
        enum_column(Channel),
        nullable=False,
        default=Channel.INTERNAL,
        index=True,
        comment="Synthetic payment channel.",
    )
    reference: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique transaction reference for complaint and evidence matching.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Non-sensitive synthetic transaction metadata only.",
    )

    # Relationships
    sender_account: Mapped["Account"] = relationship(
        "Account",
        foreign_keys="Transaction.sender_account_id",
        back_populates="sender_transactions",
    )
    receiver_account: Mapped["Account"] = relationship(
        "Account",
        foreign_keys="Transaction.receiver_account_id",
        back_populates="receiver_transactions",
    )
    complaint_correlations: Mapped[list["ComplaintCorrelation"]] = relationship(
        "ComplaintCorrelation",
        back_populates="transaction",
    )

    __table_args__ = (
        CheckConstraint("amount > 0", name="ck_transactions_amount_positive"),
        CheckConstraint(
            "length(currency) = 3",
            name="ck_transactions_currency_length",
        ),
        CheckConstraint(
            "currency = upper(currency)",
            name="ck_transactions_currency_uppercase",
        ),
        Index("ix_transactions_sender_occurred", "sender_account_id", "occurred_at"),
        Index("ix_transactions_receiver_occurred", "receiver_account_id", "occurred_at"),
        Index("ix_transactions_status_occurred", "status", "occurred_at"),
        Index("ix_transactions_channel_occurred", "channel", "occurred_at"),
        Index("ix_transactions_amount", "amount"),
        # Added in migration 0003 for investigation query shapes.
        Index(
            "ix_transactions_sender_receiver_occurred",
            "sender_account_id",
            "receiver_account_id",
            "occurred_at",
        ),
    )


class Complaint(Base, RecordTimestampMixin, ProvenanceMixin):
    """
    Synthetic complaint record.

    Raw complaint facts must be preserved. Derived or normalised values must be
    stored separately and must not overwrite source facts.
    """

    __tablename__ = "complaints"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable complaint identifier.",
    )
    reference: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
        index=True,
        comment="Complaint reference from source system.",
    )
    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Complaint report timestamp in UTC.",
    )
    category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="other",
        index=True,
        comment="Synthetic complaint category or type.",
    )
    narrative_raw: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Original synthetic narrative text. Must not be silently altered.",
    )
    narrative_normalized: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Derived normalised narrative, stored separately from raw facts.",
    )
    transaction_reference: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Transaction reference supplied by complaint source, if any.",
    )
    victim_account_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Known victim synthetic account, if supplied.",
    )
    suspected_account_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Suspected synthetic account, if supplied.",
    )
    amount: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(18, 2),
        nullable=True,
        comment="Reported complaint amount, if supplied.",
    )
    currency: Mapped[Optional[str]] = mapped_column(
        String(3),
        nullable=True,
        default="INR",
        comment="Reported complaint currency, if supplied.",
    )
    source: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Complaint source system or channel.",
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
        comment="Complaint ingestion timestamp in UTC.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Non-sensitive synthetic complaint metadata.",
    )

    # Relationships
    victim_account: Mapped[Optional["Account"]] = relationship(
        "Account",
        foreign_keys="Complaint.victim_account_id",
    )
    suspected_account: Mapped[Optional["Account"]] = relationship(
        "Account",
        foreign_keys="Complaint.suspected_account_id",
    )
    correlations: Mapped[list["ComplaintCorrelation"]] = relationship(
        "ComplaintCorrelation",
        back_populates="complaint",
    )

    __table_args__ = (
        CheckConstraint(
            "amount IS NULL OR amount > 0",
            name="ck_complaints_amount_positive_when_present",
        ),
        CheckConstraint(
            "currency IS NULL OR (length(currency) = 3 AND currency = upper(currency))",
            name="ck_complaints_currency_format_when_present",
        ),
        Index("ix_complaints_reported_category", "reported_at", "category"),
        Index("ix_complaints_transaction_reference", "transaction_reference"),
        Index("ix_complaints_victim_reported", "victim_account_id", "reported_at"),
        Index("ix_complaints_suspected_reported", "suspected_account_id", "reported_at"),
    )


# -----------------------------------------------------------------------------
# Entities and account-entity relationships
# -----------------------------------------------------------------------------


class Entity(Base, RecordTimestampMixin, ProvenanceMixin):
    """
    Synthetic pseudonymous entity.

    Shared devices, phones, UPI IDs, addresses, or IPs are investigative
    associations only. They are not conclusive proof of shared control or
    wrongdoing.
    """

    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable entity identifier.",
    )
    entity_type: Mapped[EntityType] = mapped_column(
        enum_column(EntityType),
        nullable=False,
        index=True,
        comment="Synthetic entity type.",
    )
    identifier_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
        comment="Pseudonymous hash of synthetic identifier.",
    )
    identifier_display: Mapped[Optional[str]] = mapped_column(
        String(200),
        nullable=True,
        comment="Masked or synthetic display label, never real sensitive identifier.",
    )
    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="synthetic",
        index=True,
        comment="Entity provenance source.",
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Earliest observed timestamp for this entity, if known.",
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Latest observed timestamp for this entity, if known.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Non-sensitive synthetic entity metadata.",
    )

    # Relationships
    account_links: Mapped[list["AccountEntityLink"]] = relationship(
        "AccountEntityLink",
        back_populates="entity",
    )
    complaint_correlations: Mapped[list["ComplaintCorrelation"]] = relationship(
        "ComplaintCorrelation",
        back_populates="entity",
    )

    __table_args__ = (
        UniqueConstraint(
            "entity_type",
            "identifier_hash",
            "source",
            name="uq_entities_type_hash_source",
        ),
        Index("ix_entities_type_first_seen", "entity_type", "first_seen_at"),
        CheckConstraint(
            "length(identifier_hash) > 0",
            name="ck_entities_identifier_hash_not_empty",
        ),
    )


class AccountEntityLink(Base, RecordTimestampMixin, ProvenanceMixin):
    """
    Time-bound relationship between an account and a pseudonymous entity.

    Match method, confidence, verification state, and validity window must be
    visible to analysts. Inferred links must not be presented as verified fact.
    """

    __tablename__ = "account_entity_links"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable link identifier.",
    )
    account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Linked synthetic account.",
    )
    entity_id: Mapped[str] = mapped_column(
        ForeignKey("entities.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Linked synthetic entity.",
    )
    match_method: Mapped[MatchMethod] = mapped_column(
        enum_column(MatchMethod),
        nullable=False,
        default=MatchMethod.EXACT,
        index=True,
        comment="How the account-entity relationship was established.",
    )
    confidence: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(5, 4),
        nullable=True,
        comment="Confidence in inferred relationship, between 0 and 1.",
    )
    verification_state: Mapped[VerificationState] = mapped_column(
        enum_column(VerificationState),
        nullable=False,
        default=VerificationState.UNVERIFIED,
        index=True,
        comment="Verification state for the relationship.",
    )
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
        comment="Relationship validity start in UTC.",
    )
    valid_to: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Relationship validity end in UTC, if known.",
    )
    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="synthetic",
        index=True,
        comment="Link provenance source.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Non-sensitive synthetic link metadata.",
    )

    # Relationships
    account: Mapped["Account"] = relationship(
        "Account",
        back_populates="entity_links",
    )
    entity: Mapped["Entity"] = relationship(
        "Entity",
        back_populates="account_links",
    )

    __table_args__ = (
        UniqueConstraint(
            "account_id",
            "entity_id",
            "valid_from",
            "source",
            name="uq_account_entity_links_account_entity_valid_source",
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_account_entity_links_confidence_range",
        ),
        CheckConstraint(
            "valid_to IS NULL OR valid_to > valid_from",
            name="ck_account_entity_links_valid_range",
        ),
        Index("ix_account_entity_links_account_valid", "account_id", "valid_from"),
        Index("ix_account_entity_links_entity_valid", "entity_id", "valid_from"),
        Index("ix_account_entity_links_method_state", "match_method", "verification_state"),
    )


# -----------------------------------------------------------------------------
# Feature, model, assessment, rule, and indicator records
# -----------------------------------------------------------------------------


class FeatureSnapshot(Base, RecordTimestampMixin):
    """
    Point-in-time behavioural feature snapshot.

    Feature computation must only use information available at `as_of`.
    Synthetic ground-truth labels, fraud-ring IDs, and future investigation
    outcomes must never be included as predictor features.
    """

    __tablename__ = "feature_snapshots"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable feature snapshot identifier.",
    )
    account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Account for which features were computed.",
    )
    as_of: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Point-in-time assessment timestamp in UTC.",
    )
    feature_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="v1",
        index=True,
        comment="Feature schema/version used for computation.",
    )
    window: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment="Optional primary window label, e.g. 24h, 7d, 30d.",
    )
    values_json: Mapped[dict[str, Any]] = mapped_column(
        JSONType,
        nullable=False,
        comment="Computed feature values. Must not contain leaked labels.",
    )
    dataset_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Dataset fingerprint for reproducibility.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Non-sensitive computation metadata.",
    )

    # Relationships
    account: Mapped["Account"] = relationship(
        "Account",
        back_populates="feature_snapshots",
    )
    assessments: Mapped[list["ModelAssessment"]] = relationship(
        "ModelAssessment",
        back_populates="feature_snapshot",
    )

    __table_args__ = (
        UniqueConstraint(
            "account_id",
            "as_of",
            "feature_version",
            name="uq_feature_snapshots_account_asof_version",
        ),
        Index("ix_feature_snapshots_account_asof", "account_id", "as_of"),
        Index("ix_feature_snapshots_version_asof", "feature_version", "as_of"),
        # Added in migration 0003 for investigation query shapes.
        Index(
            "ix_feature_snapshots_account_version_asof",
            "account_id",
            "feature_version",
            "as_of",
        ),
    )


class ModelVersion(Base, RecordTimestampMixin):
    """
    Metadata for a trained or fallback model version.

    Model artifacts must be loaded only from controlled local paths. Arbitrary
    user-uploaded model deserialization is not allowed.
    """

    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable model version identifier.",
    )
    version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        comment="Human-readable model version.",
    )
    feature_schema_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="v1",
        index=True,
        comment="Feature schema version expected by the model.",
    )
    model_type: Mapped[ModelType] = mapped_column(
        enum_column(ModelType),
        nullable=False,
        default=ModelType.UNKNOWN,
        index=True,
        comment="Model family or scoring baseline type.",
    )
    training_seed: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Random seed used for reproducible training.",
    )
    training_started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Training start timestamp in UTC.",
    )
    training_finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Training finish timestamp in UTC.",
    )
    dataset_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Dataset fingerprint used for training.",
    )
    generator_config_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Synthetic generator configuration fingerprint, not secrets.",
    )
    split_strategy: Mapped[SplitStrategy] = mapped_column(
        enum_column(SplitStrategy),
        nullable=False,
        default=SplitStrategy.UNKNOWN,
        index=True,
        comment="Train/validation/test split strategy.",
    )
    hyperparameters_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Model hyperparameters.",
    )
    artifact_path: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
        comment="Controlled local artifact path. Must not be user-upload derived.",
    )
    artifact_checksum: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Checksum of trusted local artifact.",
    )
    checksum_algorithm: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="sha256",
        comment="Checksum algorithm.",
    )
    metrics_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Headline metrics actually computed for this model version.",
    )
    limitations_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Known limitations and prohibited interpretations.",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Whether this version is the active inference model.",
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Model card or operational notes.",
    )

    # Relationships
    assessments: Mapped[list["ModelAssessment"]] = relationship(
        "ModelAssessment",
        back_populates="model_version",
    )
    evaluations: Mapped[list["ModelEvaluation"]] = relationship(
        "ModelEvaluation",
        back_populates="model_version",
    )

    __table_args__ = (
        Index("ix_model_versions_active_type", "is_active", "model_type"),
        CheckConstraint(
            "length(version) > 0",
            name="ck_model_versions_version_not_empty",
        ),
    )


class AnalysisRun(Base, RecordTimestampMixin):
    """
    Batch analysis run state.

    Repeated runs should be idempotent where practical and should retain score
    history rather than silently overwriting prior assessments.
    """

    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable analysis run identifier.",
    )
    status: Mapped[AnalysisRunStatus] = mapped_column(
        enum_column(AnalysisRunStatus),
        nullable=False,
        default=AnalysisRunStatus.QUEUED,
        index=True,
        comment="Current run state.",
    )
    run_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="batch",
        index=True,
        comment="Run type, e.g. batch, targeted, replay.",
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Run start timestamp in UTC.",
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Run finish timestamp in UTC.",
    )
    processed_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of accounts processed.",
    )
    error_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of processing errors.",
    )
    model_version_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("model_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Model version used during the run.",
    )
    scoring_mode: Mapped[ScoringMode] = mapped_column(
        enum_column(ScoringMode),
        nullable=False,
        default=ScoringMode.UNKNOWN,
        index=True,
        comment="Active scoring mode for the run.",
    )
    score_version: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment="Risk fusion score version.",
    )
    feature_version: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment="Feature schema version used.",
    )
    rules_version: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment="Rule engine version used.",
    )
    graph_version: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment="Graph analytics version used.",
    )
    complaint_version: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment="Complaint correlation version used.",
    )
    dataset_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Dataset fingerprint for reproducibility.",
    )
    config_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Safe run configuration snapshot.",
    )
    counts_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Run counts by stage or outcome.",
    )
    error_summary_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Sanitized error summary.",
    )
    requested_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who requested the run.",
    )
    idempotency_key: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        unique=True,
        index=True,
        comment="Optional idempotency key for repeated run requests.",
    )

    # ---------------------------------------------------------------------
    # Request/outcome surface exposed by the analysis API.
    #
    # These are deliberately distinct from the stage-accounting columns
    # above:
    #
    #   account_count       accounts SELECTED for the run
    #   processed_count     accounts successfully processed
    #   error_count         per-account processing failures
    #   assessment_count    ModelAssessment rows written by the run
    #   alert_count         Alert rows raised by the run
    #   parameters_json     the run request exactly as submitted
    #   config_json         the resolved effective configuration snapshot
    #   counts_json         detailed per-stage counters
    #   summary_json        analyst-facing run summary
    #   error_summary_json  sanitized aggregate error summary
    # ---------------------------------------------------------------------
    account_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of accounts selected for the run.",
    )
    assessment_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of assessments written by the run.",
    )
    alert_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of alerts raised by the run.",
    )
    model_version: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        comment="Denormalised model version label for history resilience.",
    )
    parameters_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Run request parameters as submitted. Secrets must be excluded.",
    )
    summary_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Analyst-facing run summary.",
    )
    error_code: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Stable error code when the run failed.",
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Sanitized failure message. Must not contain secrets.",
    )

    # Relationships
    #
    # NOTE: the ORM relationship is `model_version_ref`, because
    # `model_version` is the denormalised string label column above (the same
    # convention Alert.model_version follows).
    model_version_ref: Mapped[Optional["ModelVersion"]] = relationship(
        "ModelVersion",
    )
    requested_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="AnalysisRun.requested_by",
        back_populates="requested_analysis_runs",
    )
    assessments: Mapped[list["ModelAssessment"]] = relationship(
        "ModelAssessment",
        back_populates="analysis_run",
    )
    evaluations: Mapped[list["ModelEvaluation"]] = relationship(
        "ModelEvaluation",
        back_populates="analysis_run",
    )
    graph_runs: Mapped[list["GraphAnalysisRun"]] = relationship(
        "GraphAnalysisRun",
        back_populates="analysis_run",
    )

    __table_args__ = (
        Index("ix_analysis_runs_status_started", "status", "started_at"),
        Index("ix_analysis_runs_requested_started", "requested_by", "started_at"),
        CheckConstraint(
            "processed_count >= 0",
            name="ck_analysis_runs_processed_nonnegative",
        ),
        CheckConstraint(
            "error_count >= 0",
            name="ck_analysis_runs_error_nonnegative",
        ),
    )


class ModelEvaluation(Base, RecordTimestampMixin):
    """
    Evaluation record for a model version.

    Metrics must be real computed outputs. Undefined metrics must be reported
    honestly as unavailable rather than fabricated.
    """

    __tablename__ = "model_evaluations"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable evaluation identifier.",
    )
    model_version_id: Mapped[str] = mapped_column(
        ForeignKey("model_versions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Evaluated model version.",
    )
    analysis_run_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Analysis run associated with evaluation, if any.",
    )
    dataset_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Dataset fingerprint used for evaluation.",
    )
    split_strategy: Mapped[SplitStrategy] = mapped_column(
        enum_column(SplitStrategy),
        nullable=False,
        default=SplitStrategy.UNKNOWN,
        index=True,
        comment="Evaluation split strategy.",
    )
    sample_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of evaluation samples.",
    )
    class_distribution_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Class distribution in evaluation partition.",
    )
    metrics_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Computed metrics. Null/absent values mean not computed.",
    )
    threshold: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(7, 4),
        nullable=True,
        comment="Decision threshold used for confusion matrix, if any.",
    )
    top_k: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="K used for Precision@K / top-K review yield.",
    )
    latency_ms_per_account: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(10, 3),
        nullable=True,
        comment="Measured latency per account at stated batch size.",
    )
    latency_batch_size: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Batch size used for latency measurement.",
    )
    undefined_metrics_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Metrics intentionally not computed and why.",
    )
    limitations: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Evaluation limitations and interpretation warnings.",
    )

    # Relationships
    model_version: Mapped["ModelVersion"] = relationship(
        "ModelVersion",
        back_populates="evaluations",
    )
    analysis_run: Mapped[Optional["AnalysisRun"]] = relationship(
        "AnalysisRun",
        back_populates="evaluations",
    )

    __table_args__ = (
        UniqueConstraint(
            "model_version_id",
            "dataset_fingerprint",
            "split_strategy",
            "analysis_run_id",
            name="uq_model_evaluations_version_dataset_split_run",
        ),
        Index("ix_model_evaluations_model_created", "model_version_id", "record_created_at"),
        CheckConstraint(
            "sample_count >= 0",
            name="ck_model_evaluations_sample_count_nonnegative",
        ),
        CheckConstraint(
            "threshold IS NULL OR (threshold >= 0 AND threshold <= 1)",
            name="ck_model_evaluations_threshold_range",
        ),
    )


class ModelAssessment(Base, RecordTimestampMixin):
    """
    Persisted risk assessment for an account at a point in time.

    The score is an investigative priority score, not a probability of guilt.
    Every assessment must record scoring mode, model version where applicable,
    score version, component signals, and evidence references.
    """

    __tablename__ = "model_assessments"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable assessment identifier.",
    )
    account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Assessed synthetic account.",
    )
    feature_snapshot_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("feature_snapshots.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
        comment="Feature snapshot used for assessment.",
    )
    analysis_run_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Analysis run that produced the assessment.",
    )
    model_version_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("model_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Model version used, if trained model scoring was active.",
    )
    as_of: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Point-in-time assessment timestamp in UTC.",
    )
    scored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
        comment="Actual scoring timestamp in UTC.",
    )
    scoring_mode: Mapped[ScoringMode] = mapped_column(
        enum_column(ScoringMode),
        nullable=False,
        default=ScoringMode.UNKNOWN,
        index=True,
        comment="Trained model, heuristic fallback, rules-only, or disabled.",
    )
    score: Mapped[Decimal] = mapped_column(
        Numeric(7, 2),
        nullable=False,
        index=True,
        comment="Investigative priority score, typically 0-100.",
    )
    score_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="investigative_priority_score",
        comment="Score semantics label.",
    )
    score_version: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment="Risk fusion score version.",
    )
    risk_band: Mapped[RiskBand] = mapped_column(
        enum_column(RiskBand),
        nullable=False,
        default=RiskBand.LOW,
        index=True,
        comment="Configured risk band label.",
    )
    components_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Component signals used in fusion.",
    )
    explanation_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Structured explanation payload.",
    )
    caveats_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Missing-data and interpretation caveats.",
    )
    dataset_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Dataset fingerprint for reproducibility.",
    )

    # Relationships
    account: Mapped["Account"] = relationship(
        "Account",
        back_populates="assessments",
    )
    feature_snapshot: Mapped[Optional["FeatureSnapshot"]] = relationship(
        "FeatureSnapshot",
        back_populates="assessments",
    )
    analysis_run: Mapped[Optional["AnalysisRun"]] = relationship(
        "AnalysisRun",
        back_populates="assessments",
    )
    model_version: Mapped[Optional["ModelVersion"]] = relationship(
        "ModelVersion",
        back_populates="assessments",
    )
    indicators: Mapped[list["RiskIndicator"]] = relationship(
        "RiskIndicator",
        back_populates="assessment",
    )
    rule_hits: Mapped[list["RuleHit"]] = relationship(
        "RuleHit",
        back_populates="assessment",
    )

    __table_args__ = (
        CheckConstraint(
            "score >= 0 AND score <= 100",
            name="ck_model_assessments_score_range",
        ),
        Index("ix_model_assessments_account_scored", "account_id", "scored_at"),
        Index("ix_model_assessments_account_asof", "account_id", "as_of"),
        Index("ix_model_assessments_band_score", "risk_band", "score"),
        Index("ix_model_assessments_mode_scored", "scoring_mode", "scored_at"),
        # Added in migration 0003 for investigation query shapes.
        Index("ix_model_assessments_run_score", "analysis_run_id", "score"),
        Index(
            "ix_model_assessments_account_version_asof",
            "account_id",
            "score_version",
            "as_of",
        ),
    )


class RuleHit(Base, RecordTimestampMixin):
    """
    Persisted rule evaluation result.

    Each rule hit must include measured value, threshold, severity, explanation,
    evidence references, and rule/configuration version metadata.
    """

    __tablename__ = "rule_hits"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable rule hit identifier.",
    )
    account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Account evaluated by the rule.",
    )
    assessment_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("model_assessments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Assessment associated with this rule hit, if any.",
    )
    rule_code: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Stable rule code.",
    )
    rule_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="v1",
        index=True,
        comment="Rule implementation/version.",
    )
    triggered: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Whether the rule triggered.",
    )
    measured_value: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(18, 6),
        nullable=True,
        comment="Measured value used by the rule.",
    )
    threshold: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(18, 6),
        nullable=True,
        comment="Configured threshold used by the rule.",
    )
    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity),
        nullable=False,
        default=Severity.LOW,
        index=True,
        comment="Rule severity.",
    )
    explanation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable explanation for analysts.",
    )
    evidence_refs_json: Mapped[Optional[list[str]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Evidence references that actually triggered the rule.",
    )
    config_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Safe rule configuration snapshot.",
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
        comment="Rule evaluation timestamp in UTC.",
    )

    # Relationships
    account: Mapped["Account"] = relationship(
        "Account",
        back_populates="rule_hits",
    )
    assessment: Mapped[Optional["ModelAssessment"]] = relationship(
        "ModelAssessment",
        back_populates="rule_hits",
    )
    indicators: Mapped[list["RiskIndicator"]] = relationship(
        "RiskIndicator",
        back_populates="rule_hit",
    )

    __table_args__ = (
        Index("ix_rule_hits_account_rule_evaluated", "account_id", "rule_code", "evaluated_at"),
        Index("ix_rule_hits_triggered_severity", "triggered", "severity"),
        # Added in migration 0003 for investigation query shapes.
        Index("ix_rule_hits_assessment_triggered", "assessment_id", "triggered"),
        CheckConstraint(
            "length(rule_code) > 0",
            name="ck_rule_hits_code_not_empty",
        ),
    )


class RiskIndicator(Base, RecordTimestampMixin):
    """
    Individual evidence-backed risk indicator for an assessment.

    Indicators may originate from rules, model signals, anomaly scores, graph
    analysis, complaint correlations, or fused risk components. They must not be
    described as proof of wrongdoing.
    """

    __tablename__ = "risk_indicators"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable indicator identifier.",
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("model_assessments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Assessment to which this indicator belongs.",
    )
    indicator_type: Mapped[IndicatorType] = mapped_column(
        enum_column(IndicatorType),
        nullable=False,
        index=True,
        comment="Source type of the indicator.",
    )
    code: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Stable indicator code.",
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="Human-readable indicator title.",
    )
    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity),
        nullable=False,
        default=Severity.LOW,
        index=True,
        comment="Indicator severity.",
    )
    measured_value: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(18, 6),
        nullable=True,
        comment="Measured value behind the indicator.",
    )
    threshold: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(18, 6),
        nullable=True,
        comment="Threshold or comparison value, if applicable.",
    )
    explanation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Analyst-facing explanation.",
    )
    evidence_refs_json: Mapped[Optional[list[str]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Evidence references supporting the indicator.",
    )
    config_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Safe indicator configuration metadata.",
    )
    rule_hit_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("rule_hits.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Associated rule hit, if this indicator came from a rule.",
    )

    # Relationships
    assessment: Mapped["ModelAssessment"] = relationship(
        "ModelAssessment",
        back_populates="indicators",
    )
    rule_hit: Mapped[Optional["RuleHit"]] = relationship(
        "RuleHit",
        back_populates="indicators",
    )

    __table_args__ = (
        Index("ix_risk_indicators_assessment_type", "assessment_id", "indicator_type"),
        Index("ix_risk_indicators_code_severity", "code", "severity"),
        # Added in migration 0003 for investigation query shapes.
        Index(
            "ix_risk_indicators_assessment_severity",
            "assessment_id",
            "severity",
        ),
        CheckConstraint(
            "length(code) > 0",
            name="ck_risk_indicators_code_not_empty",
        ),
    )


# -----------------------------------------------------------------------------
# Alerts and alert evidence
# -----------------------------------------------------------------------------


class Alert(Base, RecordTimestampMixin):
    """
    Ranked investigative alert.

    Alerts must be evidence-backed and must avoid duplicate open alerts for the
    same account and detection window where deduplication is enabled.
    """

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable alert identifier.",
    )
    account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Alerted synthetic account.",
    )
    assessment_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("model_assessments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Assessment that raised the alert, if any.",
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="Alert title.",
    )
    summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Alert summary for queue display.",
    )
    priority: Mapped[Priority] = mapped_column(
        enum_column(Priority),
        nullable=False,
        default=Priority.MEDIUM,
        index=True,
        comment="Alert priority band.",
    )
    state: Mapped[AlertState] = mapped_column(
        enum_column(AlertState),
        nullable=False,
        default=AlertState.NEW,
        index=True,
        comment="Alert triage state.",
    )
    score: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(7, 2),
        nullable=True,
        index=True,
        comment="Investigative priority score associated with the alert.",
    )
    score_version: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment="Risk score version.",
    )
    scoring_mode: Mapped[ScoringMode] = mapped_column(
        enum_column(ScoringMode),
        nullable=False,
        default=ScoringMode.UNKNOWN,
        index=True,
        comment="Scoring mode that produced the alert.",
    )
    model_version: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        comment="Model version label, if trained model scoring was used.",
    )
    signal_summary_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Safe summary of rule/model/graph/complaint signals.",
    )
    rule_codes_json: Mapped[Optional[list[str]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Triggered rule codes contributing to the alert.",
    )
    dedup_key: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        index=True,
        comment="Idempotency/deduplication key for open alert prevention.",
    )
    dedup_window_start: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Detection window start used for deduplication.",
    )
    dedup_window_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Detection window end used for deduplication.",
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
        comment="First time this alert signature was seen.",
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        index=True,
        comment="Most recent time this alert signature was seen.",
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Acknowledgement timestamp.",
    )
    acknowledged_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who acknowledged the alert.",
    )
    assigned_to: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User assigned to triage the alert.",
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Alert closure timestamp, if closed without case.",
    )
    created_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User or system that created the alert.",
    )
    updated_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User that last materially updated the alert.",
    )

    # Relationships
    account: Mapped["Account"] = relationship(
        "Account",
        back_populates="alerts",
    )
    assessment: Mapped[Optional["ModelAssessment"]] = relationship(
        "ModelAssessment",
    )
    evidences: Mapped[list["AlertEvidence"]] = relationship(
        "AlertEvidence",
        back_populates="alert",
    )
    acknowledged_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="Alert.acknowledged_by",
        back_populates="acknowledged_alerts",
    )
    assigned_to_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="Alert.assigned_to",
        back_populates="assigned_alerts",
    )
    created_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="Alert.created_by",
    )
    updated_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="Alert.updated_by",
    )
    cases: Mapped[list["InvestigationCase"]] = relationship(
        "InvestigationCase",
        back_populates="alert",
    )

    __table_args__ = (
        CheckConstraint(
            "score IS NULL OR (score >= 0 AND score <= 100)",
            name="ck_alerts_score_range",
        ),
        Index("ix_alerts_state_priority_created", "state", "priority", "record_created_at"),
        Index("ix_alerts_account_state", "account_id", "state"),
        Index("ix_alerts_score_desc", "score"),
        Index("ix_alerts_mode_state", "scoring_mode", "state"),
        # Added in migration 0003 for investigation query shapes.
        Index("ix_alerts_assignee_state", "assigned_to", "state"),
        Index("ix_alerts_priority_score", "priority", "score"),
    )


class AlertEvidence(Base, RecordTimestampMixin):
    """
    Evidence reference attached to an alert.

    Evidence must reference a validated record type and identifier. It must not
    accept arbitrary URLs or unchecked SQL-like identifiers.
    """

    __tablename__ = "alert_evidence"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable alert evidence identifier.",
    )
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Alert to which evidence is attached.",
    )
    evidence_type: Mapped[EvidenceType] = mapped_column(
        enum_column(EvidenceType),
        nullable=False,
        index=True,
        comment="Validated evidence type.",
    )
    evidence_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
        comment="Identifier of the referenced evidence record.",
    )
    evidence_snapshot_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Safe structured snapshot of what was shown at alert time.",
    )
    provenance_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Provenance metadata for the evidence reference.",
    )
    created_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User or system that attached the evidence.",
    )

    # Relationships
    alert: Mapped["Alert"] = relationship(
        "Alert",
        back_populates="evidences",
    )
    created_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="AlertEvidence.created_by",
    )

    __table_args__ = (
        UniqueConstraint(
            "alert_id",
            "evidence_type",
            "evidence_id",
            name="uq_alert_evidence_alert_type_id",
        ),
        Index("ix_alert_evidence_type_id", "evidence_type", "evidence_id"),
        CheckConstraint(
            "length(evidence_id) > 0",
            name="ck_alert_evidence_id_not_empty",
        ),
    )


# -----------------------------------------------------------------------------
# Investigation cases, evidence, events, and notes
# -----------------------------------------------------------------------------


class InvestigationCase(Base, RecordTimestampMixin):
    """
    Analyst-owned investigation case.

    Case decisions are human-entered assessments in this synthetic prototype.
    Closure dispositions do not establish real-world guilt or regulatory
    outcomes.
    """

    __tablename__ = "investigation_cases"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable case identifier.",
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="Case title.",
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Case description.",
    )
    status: Mapped[CaseStatus] = mapped_column(
        enum_column(CaseStatus),
        nullable=False,
        default=CaseStatus.NEW,
        index=True,
        comment="Case workflow state.",
    )
    priority: Mapped[Priority] = mapped_column(
        enum_column(Priority),
        nullable=False,
        default=Priority.MEDIUM,
        index=True,
        comment="Case priority.",
    )
    assignee_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Assigned investigator user.",
    )
    creator_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who created the case.",
    )
    alert_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Alert from which the case was created, if any.",
    )
    account_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Primary account under investigation, if any.",
    )
    disposition: Mapped[Optional[Disposition]] = mapped_column(
        enum_column(Disposition),
        nullable=True,
        index=True,
        comment="Investigator-entered closure disposition.",
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Case closure timestamp.",
    )
    closed_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who closed the case.",
    )
    reopened_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Most recent reopen timestamp.",
    )
    reopened_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who reopened the case.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Non-sensitive case metadata.",
    )

    # Relationships
    assignee: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="InvestigationCase.assignee_id",
        back_populates="assigned_cases",
    )
    creator: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="InvestigationCase.creator_id",
        back_populates="created_cases",
    )
    alert: Mapped[Optional["Alert"]] = relationship(
        "Alert",
        back_populates="cases",
    )
    account: Mapped[Optional["Account"]] = relationship(
        "Account",
    )
    evidences: Mapped[list["CaseEvidence"]] = relationship(
        "CaseEvidence",
        back_populates="case",
    )
    events: Mapped[list["CaseEvent"]] = relationship(
        "CaseEvent",
        back_populates="case",
    )
    notes: Mapped[list["CaseNote"]] = relationship(
        "CaseNote",
        back_populates="case",
    )
    closed_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="InvestigationCase.closed_by",
    )
    reopened_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="InvestigationCase.reopened_by",
    )

    __table_args__ = (
        CheckConstraint(
            "status <> 'CLOSED' OR disposition IS NOT NULL",
            name="ck_cases_closed_requires_disposition",
        ),
        Index("ix_cases_status_priority_updated", "status", "priority", "record_updated_at"),
        Index("ix_cases_assignee_status", "assignee_id", "status"),
        Index("ix_cases_account_status", "account_id", "status"),
        Index("ix_cases_alert", "alert_id"),
        # Added in migration 0003 for investigation query shapes.
        Index(
            "ix_cases_status_assignee_updated",
            "status",
            "assignee_id",
            "record_updated_at",
        ),
    )


class CaseEvidence(Base, RecordTimestampMixin):
    """
    Evidence attached to an investigation case.

    Evidence must point to a real record or validated structured snapshot.
    Removal should be soft/auditable where case history integrity is required.
    """

    __tablename__ = "case_evidence"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable case evidence identifier.",
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_cases.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Case to which evidence is attached.",
    )
    evidence_type: Mapped[EvidenceType] = mapped_column(
        enum_column(EvidenceType),
        nullable=False,
        index=True,
        comment="Validated evidence type.",
    )
    evidence_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
        comment="Identifier of the referenced evidence record.",
    )
    evidence_snapshot_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Safe structured snapshot of evidence at attachment time.",
    )
    provenance_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Provenance metadata for the evidence reference.",
    )
    added_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who added the evidence.",
    )
    removed_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who removed the evidence, if soft-removed.",
    )
    removed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Removal timestamp, if soft-removed.",
    )
    removal_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Reason for evidence removal.",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Whether the evidence attachment is currently active.",
    )

    # Relationships
    case: Mapped["InvestigationCase"] = relationship(
        "InvestigationCase",
        back_populates="evidences",
    )
    added_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="CaseEvidence.added_by",
    )
    removed_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="CaseEvidence.removed_by",
    )

    __table_args__ = (
        Index("ix_case_evidence_case_active", "case_id", "is_active"),
        Index("ix_case_evidence_type_id", "evidence_type", "evidence_id"),
        # Added in migration 0003 for investigation query shapes.
        Index(
            "ix_case_evidence_type_id_active",
            "evidence_type",
            "evidence_id",
            "is_active",
        ),
        CheckConstraint(
            "length(evidence_id) > 0",
            name="ck_case_evidence_id_not_empty",
        ),
    )


class CaseEvent(Base):
    """
    Append-only case event history.

    Material case actions should leave durable audit records. Reopening or
    correcting a case appends a new event rather than deleting history.
    """

    __tablename__ = "case_events"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable case event identifier.",
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_cases.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Case to which the event belongs.",
    )
    actor_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User actor, if known.",
    )
    actor_username: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        comment="Denormalised actor username for system/history resilience.",
    )
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Case action, e.g. created, assigned, status_change.",
    )
    resource_type: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Resource type affected by the event.",
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Resource identifier affected by the event.",
    )
    summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Safe human-readable event summary.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Sanitized event metadata.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
        comment="Event timestamp in UTC.",
    )

    # Relationships
    case: Mapped["InvestigationCase"] = relationship(
        "InvestigationCase",
        back_populates="events",
    )
    actor: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="CaseEvent.actor_id",
    )

    __table_args__ = (
        Index("ix_case_events_case_created", "case_id", "created_at"),
        Index("ix_case_events_action_created", "action", "created_at"),
        CheckConstraint(
            "length(action) > 0",
            name="ck_case_events_action_not_empty",
        ),
    )


class CaseNote(Base, RecordTimestampMixin):
    """
    Timestamped investigator note.

    Notes should be attributed and preserved. If edit history is required,
    implement append-only note revisions rather than silent overwrite.
    """

    __tablename__ = "case_notes"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable note identifier.",
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("investigation_cases.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Case to which the note belongs.",
    )
    author_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Note author user.",
    )
    body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Note body. Must not contain secrets or real customer data.",
    )
    is_internal: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether the note is internal-only.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Non-sensitive note metadata.",
    )

    # Relationships
    case: Mapped["InvestigationCase"] = relationship(
        "InvestigationCase",
        back_populates="notes",
    )
    author: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="CaseNote.author_id",
    )

    __table_args__ = (
        Index("ix_case_notes_case_created", "case_id", "record_created_at"),
        CheckConstraint(
            "length(body) > 0",
            name="ck_case_notes_body_not_empty",
        ),
    )


# -----------------------------------------------------------------------------
# Audit logging
# -----------------------------------------------------------------------------


class AuditEvent(Base):
    """
    Durable audit record for material actions.

    Audit records must not store passwords, bearer tokens, secrets, or
    unnecessary full sensitive complaint narratives.
    """

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable audit event identifier.",
    )
    actor_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Authenticated user actor, if known.",
    )
    actor_username: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="Denormalised actor username.",
    )
    actor_role: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="Actor role at time of action.",
    )
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Audited action name.",
    )
    resource_type: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Target resource type.",
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Target resource identifier.",
    )
    outcome: Mapped[AuditOutcome] = mapped_column(
        enum_column(AuditOutcome),
        nullable=False,
        default=AuditOutcome.SUCCESS,
        index=True,
        comment="Action outcome.",
    )
    request_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="Request/correlation identifier.",
    )
    correlation_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        comment="Optional external correlation identifier.",
    )
    ip_hash: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Hashed source IP, not raw IP.",
    )
    user_agent_hash: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Hashed user agent, not raw user agent.",
    )
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Sanitized metadata only.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
        comment="Audit event timestamp in UTC.",
    )

    # Relationships
    actor: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="audit_events",
    )

    __table_args__ = (
        Index("ix_audit_events_actor_created", "actor_id", "created_at"),
        Index("ix_audit_events_action_created", "action", "created_at"),
        Index("ix_audit_events_resource_created", "resource_type", "resource_id", "created_at"),
        Index("ix_audit_events_outcome_created", "outcome", "created_at"),
        # Added in migration 0003 for investigation query shapes.
        Index(
            "ix_audit_events_actor_username_created",
            "actor_username",
            "created_at",
        ),
        CheckConstraint(
            "length(action) > 0",
            name="ck_audit_events_action_not_empty",
        ),
    )


# -----------------------------------------------------------------------------
# Complaint correlation
# -----------------------------------------------------------------------------


class ComplaintCorrelation(Base, RecordTimestampMixin):
    """
    Transparent complaint-to-record correlation.

    Exact matches must be separated from inferred associations. Match tier,
    method, confidence, provenance, and review state must be visible.
    """

    __tablename__ = "complaint_correlations"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable correlation identifier.",
    )
    complaint_id: Mapped[str] = mapped_column(
        ForeignKey("complaints.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Complaint being correlated.",
    )
    account_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Associated account, if matched.",
    )
    transaction_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("transactions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Associated transaction, if matched.",
    )
    entity_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("entities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Associated entity, if matched.",
    )
    match_tier: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
        comment="Correlation tier: 1 exact, 2 normalised, 3 entity, 4 temporal, 5 narrative.",
    )
    match_method: Mapped[MatchMethod] = mapped_column(
        enum_column(MatchMethod),
        nullable=False,
        index=True,
        comment="Method used to establish the correlation.",
    )
    confidence: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(5, 4),
        nullable=True,
        comment="Confidence for inferred correlations, between 0 and 1.",
    )
    deterministic: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Whether the match is deterministic rather than inferred.",
    )
    review_state: Mapped[ComplaintReviewState] = mapped_column(
        enum_column(ComplaintReviewState),
        nullable=False,
        default=ComplaintReviewState.UNREVIEWED,
        index=True,
        comment="Analyst review state for the correlation.",
    )
    evidence_refs_json: Mapped[Optional[list[str]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Evidence references supporting the correlation.",
    )
    provenance_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Match provenance and source metadata.",
    )
    normalized_values_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Normalised values used for matching, separate from raw facts.",
    )
    created_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User or system that created the correlation.",
    )
    reviewed_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="Reviewer user.",
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Review timestamp.",
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Reviewer notes, without leaking secrets.",
    )

    # Relationships
    complaint: Mapped["Complaint"] = relationship(
        "Complaint",
        back_populates="correlations",
    )
    account: Mapped[Optional["Account"]] = relationship(
        "Account",
        back_populates="complaint_correlations",
    )
    transaction: Mapped[Optional["Transaction"]] = relationship(
        "Transaction",
        back_populates="complaint_correlations",
    )
    entity: Mapped[Optional["Entity"]] = relationship(
        "Entity",
        back_populates="complaint_correlations",
    )
    created_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="ComplaintCorrelation.created_by",
    )
    reviewed_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="ComplaintCorrelation.reviewed_by",
    )

    __table_args__ = (
        CheckConstraint(
            "match_tier BETWEEN 1 AND 5",
            name="ck_complaint_correlations_tier_range",
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_complaint_correlations_confidence_range",
        ),
        Index("ix_complaint_correlations_complaint_tier", "complaint_id", "match_tier"),
        Index("ix_complaint_correlations_account_review", "account_id", "review_state"),
        Index("ix_complaint_correlations_transaction_review", "transaction_id", "review_state"),
        Index("ix_complaint_correlations_method_deterministic", "match_method", "deterministic"),
        # Added in migration 0003 for investigation query shapes.
        Index(
            "ix_complaint_correlations_complaint_account",
            "complaint_id",
            "account_id",
        ),
        Index("ix_complaint_correlations_account_tier", "account_id", "match_tier"),
    )


# -----------------------------------------------------------------------------
# Graph analysis runs
# -----------------------------------------------------------------------------


class GraphAnalysisRun(Base, RecordTimestampMixin):
    """
    Bounded graph analysis result.

    Graph queries must require a root account or constrained source/destination
    and must enforce server-side limits on hops, nodes, edges, paths, and date
    span. Results are investigative leads only.
    """

    __tablename__ = "graph_analysis_runs"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable graph analysis identifier.",
    )
    analysis_run_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Parent batch analysis run, if part of a larger run.",
    )
    root_account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Root account for bounded graph query.",
    )
    parameters_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Safe graph query parameters, including limits.",
    )
    node_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of nodes returned.",
    )
    edge_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of edges returned.",
    )
    metrics_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Graph metrics summary.",
    )
    paths_json: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Bounded candidate path results with transaction evidence.",
    )
    capped: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether result limits truncated the output.",
    )
    limitations_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
        comment="Interpretation limitations for graph output.",
    )
    created_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who initiated the graph analysis.",
    )

    # Relationships
    analysis_run: Mapped[Optional["AnalysisRun"]] = relationship(
        "AnalysisRun",
        back_populates="graph_runs",
    )
    root_account: Mapped["Account"] = relationship(
        "Account",
    )
    created_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys="GraphAnalysisRun.created_by",
    )

    __table_args__ = (
        Index("ix_graph_analysis_runs_root_created", "root_account_id", "record_created_at"),
        Index("ix_graph_analysis_runs_analysis", "analysis_run_id"),
        CheckConstraint(
            "node_count >= 0",
            name="ck_graph_analysis_runs_node_count_nonnegative",
        ),
        CheckConstraint(
            "edge_count >= 0",
            name="ck_graph_analysis_runs_edge_count_nonnegative",
        ),
    )


# -----------------------------------------------------------------------------
# Isolated synthetic ground truth
# -----------------------------------------------------------------------------


class GroundTruthLabel(Base, RecordTimestampMixin):
    """
    Isolated synthetic ground-truth label store.

    CRITICAL:
        These labels are for synthetic evaluation and demo scenario validation
        only. They must never be used as model predictor features, must not be
        exposed in normal analyst UI, and must not leak fraud-ring IDs or
        scenario IDs into feature pipelines.
    """

    __tablename__ = "ground_truth_labels"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=new_uuid,
        comment="Stable ground-truth identifier.",
    )
    account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
        index=True,
        comment="Synthetic account label target.",
    )
    ground_truth_label: Mapped[bool] = mapped_column(
        "ground_truth_label",
        Boolean,
        nullable=False,
        comment="Injected synthetic label. Never use as predictor feature.",
    )
    scenario_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Injected scenario identifier, isolated from model inputs.",
    )
    ring_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Synthetic fraud-ring identifier, isolated from model inputs.",
    )
    scenario_type: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Scenario family, e.g. rapid_pass_through, fan_in, hard_negative.",
    )
    label_source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="injected_synthetic_scenario",
        comment="How the synthetic label was produced.",
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Non-sensitive generator notes.",
    )

    # Relationships
    account: Mapped["Account"] = relationship(
        "Account",
        back_populates="ground_truth_label",
    )

    __table_args__ = (
        Index("ix_ground_truth_labels_scenario_type", "scenario_type"),
        Index("ix_ground_truth_labels_ring", "ring_id"),
        CheckConstraint(
            "length(label_source) > 0",
            name="ck_ground_truth_labels_source_not_empty",
        ),
    )


# -----------------------------------------------------------------------------
# Public model surface
# -----------------------------------------------------------------------------

__all__ = [
    "Account",
    "AccountEntityLink",
    "AccountStatus",
    "AccountType",
    "Alert",
    "AlertEvidence",
    "AlertState",
    "AnalysisRun",
    "AnalysisRunStatus",
    "AuditEvent",
    "AuditOutcome",
    "CaseEvent",
    "CaseEvidence",
    "CaseNote",
    "CaseStatus",
    "Channel",
    "Complaint",
    "ComplaintCorrelation",
    "ComplaintReviewState",
    "Disposition",
    "Entity",
    "EntityType",
    "EvidenceType",
    "FeatureSnapshot",
    "GraphAnalysisRun",
    "GroundTruthLabel",
    "IndicatorType",
    "InvestigationCase",
    "MatchMethod",
    "ModelAssessment",
    "ModelEvaluation",
    "ModelType",
    "ModelVersion",
    "Priority",
    "ProvenanceMixin",
    "RecordTimestampMixin",
    "RiskBand",
    "RiskIndicator",
    "RuleHit",
    "ScoringMode",
    "Severity",
    "SplitStrategy",
    "Transaction",
    "TransactionStatus",
    "User",
    "UserRole",
    "VerificationState",
]