"""
MULEGUARD backend core enums.

This module provides canonical, dependency-light, string-based enumerations for
the synthetic MULEGUARD prototype.

Primary responsibilities:

- define stable enum identifiers used across configuration, APIs, services,
  persistence mirrors, reports, graph views, audit metadata, and tests;
- normalize role-like, state-like, channel-like, and workflow-like values from
  environment variables, JSON payloads, query parameters, tokens, logs, and
  database rows;
- support safe aliases without accepting arbitrary client-controlled semantics;
- expose display labels, descriptions, terminal-state metadata, and bounded
  workflow transition rules;
- keep enum behaviour deterministic, inspectable, and non-leaking;
- avoid importing FastAPI, SQLAlchemy, Pydantic, ML, graph, reporting, or audit
  runtime dependencies at package level.

Relationship to other modules:

- `app.core.roles` owns role identity and hierarchy.
- `app.core.permissions` owns permission identity and metadata.
- `app.auth.rbac` owns deny-by-default authorization decisions.
- `app.models` may define persistence-level enums with synchronized values.

Security and product-safety rules enforced here:

- Enum helpers never log or return secrets, tokens, passwords, database URLs,
  raw complaint narratives, synthetic ground-truth labels, scenario IDs, fraud
  ring IDs, model artifact paths, or real customer data.
- State transitions are workflow metadata only. They do not authorize adverse
  customer action.
- Account statuses, alert states, case statuses, dispositions, evidence types,
  risk bands, and scoring modes are investigative or operational labels only.
- Heuristic fallback scoring is never represented as calibrated model
  probability.
- Completed transactions are the only status treated as settled fund movement;
  pending, failed, reversed, cancelled, and disputed states remain distinct.

Explicit non-goals:

- This module does not authenticate users.
- This module does not enforce authorization.
- This module does not persist state.
- This module does not execute workflows.
- This module does not claim production readiness.

Product-safety notice:

MULEGUARD is a synthetic-first investigative prototype. Enums in this module
describe local prototype workflow and data semantics only. Alerts, scores,
graph relationships, candidate money trails, entity links, complaint
correlations, and case dispositions remain investigative leads or human
workflow artefacts only.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Final, Optional, TypeVar

from app.exceptions import ValidationError


EnumT = TypeVar("EnumT", bound=Enum)


# -----------------------------------------------------------------------------
# Tokenization constants
# -----------------------------------------------------------------------------

_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")
_MULTI_UNDERSCORE_RE: Final[re.Pattern[str]] = re.compile(r"_+")

_WORD_DISPLAY: Final[dict[str, str]] = {
    "API": "API",
    "AUDIT": "Audit",
    "CI": "CI",
    "CSV": "CSV",
    "FP": "False Positive",
    "HTTP": "HTTP",
    "HTTPS": "HTTPS",
    "ID": "ID",
    "IMPS": "IMPS",
    "IP": "IP",
    "JSON": "JSON",
    "NEFT": "NEFT",
    "NDJSON": "NDJSON",
    "PDF": "PDF",
    "RTGS": "RTGS",
    "SLA": "SLA",
    "UI": "UI",
    "UPI": "UPI",
}


# -----------------------------------------------------------------------------
# Base enum
# -----------------------------------------------------------------------------


class CoreEnum(str, Enum):
    """
    Base string enum with safe normalization, labeling, and transition helpers.

    Concrete enums should keep values stable and public-facing. Aliases may be
    added for ergonomic input handling, but unknown values must remain rejected
    by strict helpers.
    """

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def normalize(
        cls,
        value: Any,
        *,
        default: Any = None,
        allow_aliases: bool = True,
    ) -> Optional[str]:
        """
        Normalize a value to this enum's canonical string value.

        Returns None when the value is unrecognized and no valid default is
        supplied.
        """
        return normalize_enum(
            cls,
            value,
            default=default,
            allow_aliases=allow_aliases,
        )

    @classmethod
    def coerce(
        cls,
        value: Any,
        *,
        default: Any = None,
        allow_aliases: bool = True,
    ) -> Optional["CoreEnum"]:
        """
        Coerce a value to an enum member.

        Returns None when the value is unrecognized and no valid default is
        supplied.
        """
        return coerce_enum(
            cls,
            value,
            default=default,
            allow_aliases=allow_aliases,
        )

    @classmethod
    def require(
        cls,
        value: Any,
        *,
        field_name: str = "value",
        allow_aliases: bool = True,
    ) -> "CoreEnum":
        """
        Coerce a value to an enum member or raise a safe validation error.
        """
        return require_enum(
            cls,
            value,
            field_name=field_name,
            allow_aliases=allow_aliases,
        )

    @classmethod
    def values(cls) -> tuple[str, ...]:
        """
        Return canonical enum values in declaration order.
        """
        return enum_values(cls)

    @classmethod
    def names(cls) -> tuple[str, ...]:
        """
        Return enum member names in declaration order.
        """
        return enum_names(cls)

    @classmethod
    def choices(cls) -> list[dict[str, str]]:
        """
        Return safe value/label choices for UI or documentation use.
        """
        return enum_choices(cls)

    @classmethod
    def metadata(cls) -> dict[str, Any]:
        """
        Return safe metadata for this enum.
        """
        return enum_metadata(cls)

    @property
    def label(self) -> str:
        """
        Return a human-readable label for this member.
        """
        return enum_label(type(self), self.name)

    @property
    def description(self) -> str:
        """
        Return a safe description for this member, when configured.
        """
        return enum_description(type(self), self.name)

    @property
    def is_terminal(self) -> bool:
        """
        Return True when this member is considered terminal workflow metadata.

        Terminal does not mean irreversible. Reopen transitions may still be
        explicitly allowed by transition rules.
        """
        return is_terminal(type(self), self.value)

    @property
    def allowed_transitions(self) -> tuple[str, ...]:
        """
        Return canonical values this member may transition to.
        """
        return allowed_transitions(type(self), self.value)

    def can_transition_to(self, target: Any) -> bool:
        """
        Return True when transition from this member to target is allowed.
        """
        return allowed_transition(type(self), self.value, target)

    def validate_transition_to(
        self,
        target: Any,
        *,
        field_name: str = "transition",
    ) -> None:
        """
        Validate transition from this member to target.

        Raises ValidationError when the transition is not allowed.
        """
        validate_transition(
            type(self),
            self.value,
            target,
            field_name=field_name,
        )


# -----------------------------------------------------------------------------
# Environment and data classification enums
# -----------------------------------------------------------------------------


class Environment(CoreEnum):
    """
    Runtime environment labels.
    """

    LOCAL = "local"
    TEST = "test"
    CI = "ci"
    STAGING = "staging"
    PRODUCTION = "production"


class DatasetMode(CoreEnum):
    """
    Dataset classification modes.

    MULEGUARD is synthetic-first. Non-synthetic modes are only accepted where
    explicitly supported by deployment policy.
    """

    SYNTHETIC = "synthetic"
    DEMO = "demo"
    TEST = "test"
    EMPTY = "empty"


class DataSensitivity(CoreEnum):
    """
    Broad data sensitivity labels.
    """

    SYNTHETIC = "synthetic"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    PUBLIC = "public"


# -----------------------------------------------------------------------------
# Query and time enums
# -----------------------------------------------------------------------------


class SortDirection(CoreEnum):
    """
    Sort direction labels.
    """

    ASC = "asc"
    DESC = "desc"


class TimeGranularity(CoreEnum):
    """
    Calendar or operational time granularity.
    """

    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    QUARTER = "quarter"
    YEAR = "year"


class FeatureWindow(CoreEnum):
    """
    Stable feature-window labels used by synthetic feature engineering.
    """

    ONE_HOUR = "1h"
    ONE_DAY = "24h"
    SEVEN_DAY = "7d"
    THIRTY_DAY = "30d"
    NINETY_DAY = "90d"
    ONE_YEAR = "365d"


# -----------------------------------------------------------------------------
# Matching, verification, and review enums
# -----------------------------------------------------------------------------


class MatchMethod(CoreEnum):
    """
    How an association or correlation was produced.

    Exact methods are deterministic. Heuristic methods are inferred leads only.
    """

    EXACT = "EXACT"
    HASHED = "HASHED"
    DEVICE = "DEVICE"
    IP = "IP"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    UPI = "UPI"
    ADDRESS = "ADDRESS"
    NAME = "NAME"
    ACCOUNT = "ACCOUNT"
    TRANSACTION = "TRANSACTION"
    COMPLAINT = "COMPLAINT"
    GRAPH = "GRAPH"
    HEURISTIC = "HEURISTIC"
    MANUAL = "MANUAL"
    UNKNOWN = "UNKNOWN"


class VerificationState(CoreEnum):
    """
    Verification state for entity links or associations.
    """

    UNVERIFIED = "UNVERIFIED"
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    STALE = "STALE"


class ReviewState(CoreEnum):
    """
    Human review state for investigative correlations.
    """

    UNREVIEWED = "UNREVIEWED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    ESCALATED = "ESCALATED"
    SUPERSEDED = "SUPERSEDED"


# -----------------------------------------------------------------------------
# Account, channel, and transaction enums
# -----------------------------------------------------------------------------


class AccountStatus(CoreEnum):
    """
    Observational synthetic account status.

    Status labels do not authorize freezing, blocking, blacklisting, closing,
    restricting, or any other adverse customer action.
    """

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    DORMANT = "DORMANT"
    PENDING = "PENDING"
    SUSPENDED = "SUSPENDED"
    RESTRICTED = "RESTRICTED"
    CLOSED = "CLOSED"


class AccountType(CoreEnum):
    """
    Synthetic account type labels.
    """

    SAVINGS = "SAVINGS"
    CURRENT = "CURRENT"
    WALLET = "WALLET"
    UPI = "UPI"
    CARD = "CARD"
    OTHER = "OTHER"


class Channel(CoreEnum):
    """
    Payment or transfer channel labels.
    """

    UPI = "UPI"
    NEFT = "NEFT"
    RTGS = "RTGS"
    IMPS = "IMPS"
    CARD = "CARD"
    WALLET = "WALLET"
    CASH = "CASH"
    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"
    UNKNOWN = "UNKNOWN"


class TransactionStatus(CoreEnum):
    """
    Transaction lifecycle status.

    Only COMPLETED is treated as settled fund movement. Pending, failed,
    reversed, cancelled, and disputed records remain semantically distinct.
    """

    COMPLETED = "COMPLETED"
    PENDING = "PENDING"
    FAILED = "FAILED"
    REVERSED = "REVERSED"
    CANCELLED = "CANCELLED"
    DISPUTED = "DISPUTED"
    UNKNOWN = "UNKNOWN"


# -----------------------------------------------------------------------------
# Priority, severity, alert, case, and disposition enums
# -----------------------------------------------------------------------------


class Priority(CoreEnum):
    """
    Operational priority labels.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Severity(CoreEnum):
    """
    Severity labels for alerts, findings, or log events.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertState(CoreEnum):
    """
    Human triage state for investigative alerts.

    Alerts are investigative leads only. Alert state changes do not trigger
    automatic adverse customer action.
    """

    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    UNDER_REVIEW = "UNDER_REVIEW"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DUPLICATE = "DUPLICATE"
    CLOSED = "CLOSED"


class CaseStatus(CoreEnum):
    """
    Investigation case workflow status.

    The members mirror `app.models.CaseStatus`, which is what the case table's
    status column is declared over. They were once a different set — with an
    `UNDER_REVIEW` borrowed from the alert states and no `TRIAGED` — and the
    divergence was invisible because nothing imports this module: code reached
    for a member by name, got `None` back, and stored or compared a value the
    column cannot hold. Two vocabularies for one column is a trap, so this one
    follows the persisted one.

    Case status is workflow metadata only and is not proof of wrongdoing.
    """

    NEW = "NEW"
    TRIAGED = "TRIAGED"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"


class CaseDisposition(CoreEnum):
    """
    Investigator-entered case disposition.

    The members mirror `app.models.Disposition`, for the same reason the case
    statuses do: the column is declared over that enum, so a label outside it
    has nowhere to be stored.

    Dispositions are workflow assessments, not automatic enforcement actions.
    """

    CONFIRMED_FRAUD = "CONFIRMED_FRAUD"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    REFERRED = "REFERRED"


# -----------------------------------------------------------------------------
# Evidence, audit, model, and ingestion enums
# -----------------------------------------------------------------------------


class EvidenceType(CoreEnum):
    """
    Types of persisted evidence references that may be attached to cases.

    Evidence references point to synthetic records and are investigative leads
    only.
    """

    ALERT = "ALERT"
    TRANSACTION = "TRANSACTION"
    ACCOUNT = "ACCOUNT"
    ENTITY = "ENTITY"
    COMPLAINT = "COMPLAINT"
    COMPLAINT_CORRELATION = "COMPLAINT_CORRELATION"
    GRAPH_PATH = "GRAPH_PATH"
    MONEY_TRAIL = "MONEY_TRAIL"
    MODEL_ASSESSMENT = "MODEL_ASSESSMENT"
    CASE_NOTE = "CASE_NOTE"
    AUDIT_EVENT = "AUDIT_EVENT"
    DOCUMENT = "DOCUMENT"
    EXTERNAL_REF = "EXTERNAL_REF"


class AuditOutcome(CoreEnum):
    """
    Outcome label for audited system or workflow actions.
    """

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    ERROR = "ERROR"


class ScoringMode(CoreEnum):
    """
    How a risk or priority score was produced.

    Heuristic fallback is not a trained model and must not be described as a
    calibrated probability.
    """

    TRAINED_MODEL = "TRAINED_MODEL"
    HEURISTIC_FALLBACK = "HEURISTIC_FALLBACK"
    RULES_ONLY = "RULES_ONLY"
    HYBRID = "HYBRID"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


class RiskBand(CoreEnum):
    """
    Investigative prioritization band.

    Risk bands are not probabilities of guilt.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class ModelStatus(CoreEnum):
    """
    Lifecycle status for synthetic model metadata.

    Model status does not imply production readiness or regulatory approval.
    """

    DRAFT = "DRAFT"
    EVALUATED = "EVALUATED"
    CANDIDATE = "CANDIDATE"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    ARCHIVED = "ARCHIVED"


class IngestionOutcome(CoreEnum):
    """
    Row-level ingestion outcome labels.
    """

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    DUPLICATED = "DUPLICATED"
    SKIPPED = "SKIPPED"
    TRUNCATED = "TRUNCATED"


# -----------------------------------------------------------------------------
# Graph and export enums
# -----------------------------------------------------------------------------


class GraphNodeType(CoreEnum):
    """
    Graph node type labels used by bounded synthetic graph views.
    """

    ACCOUNT = "account"
    TRANSACTION = "transaction"
    ENTITY = "entity"
    COMPLAINT = "complaint"
    ALERT = "alert"
    ASSESSMENT = "assessment"
    CASE = "case"


class GraphEdgeType(CoreEnum):
    """
    Graph edge type labels used by bounded synthetic graph views.

    Edges are investigative associations only.
    """

    SENT = "sent"
    RECEIVED = "received"
    LINKED_TO = "linked_to"
    RELATED_TO = "related_to"
    CORRELATED_WITH = "correlated_with"
    ALERTED_ON = "alerted_on"
    ASSESSED_BY = "assessed_by"
    ATTACHED_TO_CASE = "attached_to_case"


class TraversalDirection(CoreEnum):
    """
    Direction for graph traversal or money-trail exploration.
    """

    OUTGOING = "outgoing"
    INCOMING = "incoming"
    BOTH = "both"


class ExportFormat(CoreEnum):
    """
    Bounded export format labels.
    """

    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    NDJSON = "ndjson"


class ReportFormat(CoreEnum):
    """
    Investigation report format labels.
    """

    PDF = "pdf"
    JSON = "json"


# -----------------------------------------------------------------------------
# Canonical enum registry
# -----------------------------------------------------------------------------

_CORE_ENUM_CLASSES: Final[tuple[type[CoreEnum], ...]] = (
    Environment,
    DatasetMode,
    DataSensitivity,
    SortDirection,
    TimeGranularity,
    FeatureWindow,
    MatchMethod,
    VerificationState,
    ReviewState,
    AccountStatus,
    AccountType,
    Channel,
    TransactionStatus,
    Priority,
    Severity,
    AlertState,
    CaseStatus,
    CaseDisposition,
    EvidenceType,
    AuditOutcome,
    ScoringMode,
    RiskBand,
    ModelStatus,
    IngestionOutcome,
    GraphNodeType,
    GraphEdgeType,
    TraversalDirection,
    ExportFormat,
    ReportFormat,
)


# -----------------------------------------------------------------------------
# Aliases
# -----------------------------------------------------------------------------
# Alias keys are normalized uppercase tokens. Alias targets should be member
# names, but value strings are also accepted by lookup helpers.

_ALIASES: Final[dict[type[Enum], dict[str, str]]] = {
    Environment: {
        "DEV": "LOCAL",
        "DEVELOPMENT": "LOCAL",
        "PROD": "PRODUCTION",
        "STAGE": "STAGING",
    },
    DatasetMode: {
        "FAKE": "SYNTHETIC",
        "MOCK": "SYNTHETIC",
        "SYNTH": "SYNTHETIC",
    },
    DataSensitivity: {
        "DEMO": "SYNTHETIC",
        "SYNTHETIC_DEMO": "SYNTHETIC",
    },
    SortDirection: {
        "ASCENDING": "ASC",
        "DESCENDING": "DESC",
        "DOWN": "DESC",
        "UP": "ASC",
    },
    TimeGranularity: {
        "1D": "DAY",
        "7D": "WEEK",
        "30D": "MONTH",
        "365D": "YEAR",
        "DAILY": "DAY",
        "HOURLY": "HOUR",
        "MONTHLY": "MONTH",
        "QUARTERLY": "QUARTER",
        "WEEKLY": "WEEK",
        "YEARLY": "YEAR",
    },
    FeatureWindow: {
        "1H": "ONE_HOUR",
        "24H": "ONE_DAY",
        "7D": "SEVEN_DAY",
        "30D": "THIRTY_DAY",
        "90D": "NINETY_DAY",
        "365D": "ONE_YEAR",
        "DAY": "ONE_DAY",
        "HOUR": "ONE_HOUR",
        "MONTH": "THIRTY_DAY",
        "QUARTER": "NINETY_DAY",
        "WEEK": "SEVEN_DAY",
        "YEAR": "ONE_YEAR",
    },
    MatchMethod: {
        "ACCOUNT_LINK": "ACCOUNT",
        "DEVICE_ID": "DEVICE",
        "EXACT_MATCH": "EXACT",
        "FUZZY": "HEURISTIC",
        "HASHED_IDENTIFIER": "HASHED",
        "INFERRED": "HEURISTIC",
        "IP_ADDRESS": "IP",
        "PHONE_NUMBER": "PHONE",
        "TRANSACTION_LINK": "TRANSACTION",
        "UPI_ID": "UPI",
    },
    VerificationState: {
        "NOT_VERIFIED": "UNVERIFIED",
        "UNVERIFIED": "UNVERIFIED",
    },
    ReviewState: {
        "APPROVED": "CONFIRMED",
        "DISMISSED": "REJECTED",
        "ESCALATE": "ESCALATED",
        "NEEDS_MORE_EVIDENCE": "NEEDS_MORE_EVIDENCE",
        "UNREVIEWED": "UNREVIEWED",
    },
    AccountStatus: {
        "DISABLED": "INACTIVE",
        "ENABLED": "ACTIVE",
        "FROZEN": "SUSPENDED",
        "OPEN": "ACTIVE",
    },
    AccountType: {
        "CASA": "CURRENT",
        "WALLET_ACCOUNT": "WALLET",
    },
    Channel: {
        "CARD_PAYMENT": "CARD",
        "CASH_DEPOSIT": "CASH",
        "CASH_WITHDRAWAL": "CASH",
        "EXTERNAL_TRANSFER": "EXTERNAL",
        "INTERNAL_TRANSFER": "INTERNAL",
        "WALLET_TRANSFER": "WALLET",
    },
    TransactionStatus: {
        "CANCELED": "CANCELLED",
        "CHARGEBACK": "DISPUTED",
        "FAILURE": "FAILED",
        "PROCESSING": "PENDING",
        "REFUND": "REVERSED",
        "SETTLED": "COMPLETED",
        "SUCCESS": "COMPLETED",
    },
    Priority: {
        "P0": "CRITICAL",
        "P1": "HIGH",
        "P2": "MEDIUM",
        "P3": "LOW",
        "URGENT": "CRITICAL",
    },
    Severity: {
        "CRIT": "CRITICAL",
        "INFORMATIONAL": "INFO",
    },
    AlertState: {
        "ACK": "ACKNOWLEDGED",
        "CLOSE": "CLOSED",
        "DUPLICATE_ALERT": "DUPLICATE",
        "FALSE_POSITIVE_ALERT": "FALSE_POSITIVE",
        "FP": "FALSE_POSITIVE",
        "INVESTIGATING": "UNDER_REVIEW",
        "IN_REVIEW": "UNDER_REVIEW",
        "RESOLVE": "RESOLVED",
    },
    CaseStatus: {
        "INVESTIGATING": "UNDER_INVESTIGATION",
        "IN_REVIEW": "UNDER_INVESTIGATION",
        "UNDER_REVIEW": "UNDER_INVESTIGATION",
        "OPEN": "NEW",
        "REOPENED": "UNDER_INVESTIGATION",
        "RE_OPENED": "UNDER_INVESTIGATION",
        "REOPEN": "UNDER_INVESTIGATION",
        "TRIAGE": "TRIAGED",
    },
    CaseDisposition: {
        "CONFIRMED": "CONFIRMED_FRAUD",
        "FALSE_POSITIVE_CASE": "FALSE_POSITIVE",
        "FP": "FALSE_POSITIVE",
        "FRAUD": "CONFIRMED_FRAUD",
        "INCONCLUSIVE_RESULT": "INCONCLUSIVE",
        "INSUFFICIENT": "INCONCLUSIVE",
        "INSUFFICIENT_EVIDENCE": "INCONCLUSIVE",
        "REFERRED_FOR_FURTHER_REVIEW": "REFERRED",
    },
    EvidenceType: {
        "ASSESSMENT": "MODEL_ASSESSMENT",
        "CORRELATION": "COMPLAINT_CORRELATION",
        "EXTERNAL": "EXTERNAL_REF",
        "MODEL": "MODEL_ASSESSMENT",
        "NOTE": "CASE_NOTE",
        "PATH": "GRAPH_PATH",
        "TRAIL": "MONEY_TRAIL",
        "TXN": "TRANSACTION",
    },
    AuditOutcome: {
        "FAIL": "FAILURE",
        "FORBIDDEN": "DENIED",
        "OK": "SUCCESS",
        "UNAUTHORIZED": "DENIED",
    },
    ScoringMode: {
        "FALLBACK": "HEURISTIC_FALLBACK",
        "HEURISTIC": "HEURISTIC_FALLBACK",
        "ML": "TRAINED_MODEL",
        "MODEL": "TRAINED_MODEL",
        "RULES": "RULES_ONLY",
    },
    RiskBand: {
        "NONE": "LOW",
    },
    ModelStatus: {
        "LIVE": "ACTIVE",
        "PROD": "ACTIVE",
        "PRODUCTION": "ACTIVE",
    },
    IngestionOutcome: {
        "ACCEPT": "ACCEPTED",
        "DUPLICATE": "DUPLICATED",
        "REJECT": "REJECTED",
        "SKIP": "SKIPPED",
        "TRUNCATE": "TRUNCATED",
    },
    GraphNodeType: {
        "MODEL_ASSESSMENT": "ASSESSMENT",
        "TXN": "TRANSACTION",
    },
    GraphEdgeType: {
        "ATTACHED": "ATTACHED_TO_CASE",
        "CORRELATED": "CORRELATED_WITH",
        "LINKED": "LINKED_TO",
        "RELATED": "RELATED_TO",
    },
    TraversalDirection: {
        "BIDIRECTIONAL": "BOTH",
        "INBOUND": "INCOMING",
    },
    ExportFormat: {
        "JSONL": "NDJSON",
    },
    ReportFormat: {
        "APPLICATION_PDF": "PDF",
        "APPLICATION_JSON": "JSON",
    },
}


# -----------------------------------------------------------------------------
# Display and description metadata
# -----------------------------------------------------------------------------

_DISPLAY_NAMES: Final[dict[type[Enum], dict[str, str]]] = {
    CaseDisposition: {
        "NO_FURTHER_ACTION": "No further action",
        "REFERRED_FOR_FURTHER_REVIEW": "Referred for further review",
        "INSUFFICIENT_EVIDENCE": "Insufficient evidence",
        "FALSE_POSITIVE": "False positive",
    },
    ScoringMode: {
        "HEURISTIC_FALLBACK": "Heuristic fallback",
        "TRAINED_MODEL": "Trained model",
        "RULES_ONLY": "Rules only",
    },
}

_MEMBER_DESCRIPTIONS: Final[dict[type[Enum], dict[str, str]]] = {
    DatasetMode: {
        "SYNTHETIC": "Generated synthetic prototype data.",
        "DEMO": "Curated synthetic demo dataset.",
        "TEST": "Deterministic test fixture data.",
        "EMPTY": "No dataset records are present.",
    },
    DataSensitivity: {
        "SYNTHETIC": "Synthetic prototype data only.",
        "INTERNAL": "Internal operational metadata.",
        "RESTRICTED": "Restricted investigative metadata.",
        "PUBLIC": "Safe public-facing metadata.",
    },
    MatchMethod: {
        "EXACT": "Deterministic exact identifier or field match.",
        "HEURISTIC": "Inferred association produced by bounded heuristics.",
        "MANUAL": "Human-attached association, subject to review.",
    },
    VerificationState: {
        "UNVERIFIED": "Association has not been verified.",
        "PENDING": "Verification is queued or awaiting reviewer action.",
        "VERIFIED": "Verification succeeded under configured policy.",
        "REJECTED": "Verification failed or association was dismissed.",
        "STALE": "Association is outdated and requires refresh.",
    },
    ReviewState: {
        "UNREVIEWED": "No human reviewer decision has been recorded.",
        "CONFIRMED": "Reviewer confirmed the association as useful.",
        "REJECTED": "Reviewer rejected the association.",
        "NEEDS_MORE_EVIDENCE": "Reviewer requires additional evidence.",
        "ESCALATED": "Reviewer escalated for senior review.",
        "SUPERSEDED": "Reviewer decision was replaced by a later decision.",
    },
    AccountStatus: {
        "ACTIVE": "Observational active synthetic account state.",
        "INACTIVE": "Observational inactive synthetic account state.",
        "DORMANT": "Observational low-activity synthetic account state.",
        "PENDING": "Observational pending synthetic account state.",
        "SUSPENDED": "Observational suspended synthetic account state.",
        "RESTRICTED": "Observational restricted synthetic account state.",
        "CLOSED": "Observational closed synthetic account state.",
    },
    TransactionStatus: {
        "COMPLETED": "Settled fund movement.",
        "PENDING": "Not yet settled and must not be treated as completed.",
        "FAILED": "Unsuccessful transfer attempt.",
        "REVERSED": "Reversal or refund-like movement.",
        "CANCELLED": "Cancelled before completion.",
        "DISPUTED": "Disputed or chargeback-like state.",
    },
    AlertState: {
        "NEW": "Alert has not been acknowledged.",
        "ACKNOWLEDGED": "Alert has been acknowledged by a reviewer.",
        "UNDER_REVIEW": "Alert is being investigated.",
        "ESCALATED": "Alert requires senior review.",
        "RESOLVED": "Alert workflow is resolved.",
        "FALSE_POSITIVE": "Alert was assessed as false positive.",
        "DUPLICATE": "Alert was assessed as duplicate.",
        "CLOSED": "Alert workflow is closed.",
    },
    CaseStatus: {
        "NEW": "Case has not been reviewed.",
        "UNDER_REVIEW": "Case is under investigation.",
        "ESCALATED": "Case requires senior review.",
        "RESOLVED": "Case workflow is resolved.",
        "CLOSED": "Case is closed.",
        "REOPENED": "Closed case was reopened by authorized workflow.",
        "DUPLICATE": "Case was assessed as duplicate.",
    },
    CaseDisposition: {
        "NO_FURTHER_ACTION": "Investigator recorded no further action.",
        "MONITORING": "Investigator recorded monitoring outcome.",
        "REFERRED_FOR_FURTHER_REVIEW": "Investigator referred for further review.",
        "INSUFFICIENT_EVIDENCE": "Evidence was insufficient for a stronger outcome.",
        "DUPLICATE": "Case was assessed as duplicate.",
        "FALSE_POSITIVE": "Case was assessed as false positive.",
    },
    EvidenceType: {
        "GRAPH_PATH": "Bounded graph path produced by graph service.",
        "MONEY_TRAIL": "Bounded candidate money trail produced by graph service.",
        "COMPLAINT_CORRELATION": "Persisted complaint correlation reference.",
        "MODEL_ASSESSMENT": "Persisted model or heuristic assessment reference.",
    },
    AuditOutcome: {
        "SUCCESS": "Action completed successfully.",
        "FAILURE": "Action failed for non-policy reasons.",
        "DENIED": "Action was denied by policy, permission, lockout, or validation.",
        "ERROR": "Action encountered an unexpected error.",
    },
    ScoringMode: {
        "TRAINED_MODEL": "Score produced by persisted trained model metadata.",
        "HEURISTIC_FALLBACK": "Score produced by deterministic heuristics.",
        "RULES_ONLY": "Score produced only by rule signals.",
        "HYBRID": "Score combined multiple configured signal sources.",
        "DISABLED": "Scoring is disabled.",
        "UNKNOWN": "Scoring mode could not be determined.",
    },
    RiskBand: {
        "LOW": "Lower investigative prioritization.",
        "MEDIUM": "Moderate investigative prioritization.",
        "HIGH": "Higher investigative prioritization.",
        "CRITICAL": "Highest investigative prioritization.",
        "UNKNOWN": "Risk band unavailable or not computed.",
    },
    ModelStatus: {
        "DRAFT": "Model metadata is not finalized.",
        "EVALUATED": "Model has evaluation metadata.",
        "CANDIDATE": "Model is candidate for activation.",
        "ACTIVE": "Model is marked active in synthetic metadata.",
        "RETIRED": "Model is retired.",
        "ARCHIVED": "Model metadata is archived.",
    },
}


# -----------------------------------------------------------------------------
# Safety notes
# -----------------------------------------------------------------------------

_ENUM_NOTES: Final[dict[type[Enum], str]] = {
    DatasetMode: (
        "MULEGUARD is synthetic-first. Dataset mode labels do not authorize "
        "processing of real customer data."
    ),
    DataSensitivity: (
        "Sensitivity labels are operational metadata only and do not override "
        "server-side access controls."
    ),
    MatchMethod: (
        "Heuristic and manual matches are investigative leads only and are not "
        "verified facts."
    ),
    VerificationState: (
        "Verification state describes association confidence only. It is not "
        "proof of common control or wrongdoing."
    ),
    ReviewState: (
        "Review state is human workflow metadata only. It does not trigger "
        "automatic adverse customer action."
    ),
    AccountStatus: (
        "Account status is observational synthetic metadata. It does not "
        "authorize freezing, blocking, blacklisting, closing, or restricting."
    ),
    TransactionStatus: (
        "Only completed transfers represent settled fund movement. Other states "
        "must remain distinct."
    ),
    AlertState: (
        "Alert state is human triage metadata. Alerts are investigative leads "
        "only."
    ),
    CaseStatus: (
        "Case status is workflow metadata only and is not proof of wrongdoing."
    ),
    CaseDisposition: (
        "Case disposition is an investigator-entered workflow assessment, not "
        "automatic enforcement."
    ),
    EvidenceType: (
        "Evidence references point to persisted synthetic records and are "
        "investigative leads only."
    ),
    AuditOutcome: (
        "Audit outcomes describe system or workflow results and do not imply "
        "customer fault."
    ),
    ScoringMode: (
        "Scoring mode describes score provenance. Heuristic fallback is not a "
        "calibrated model probability."
    ),
    RiskBand: (
        "Risk bands are investigative prioritization labels, not probabilities "
        "of guilt."
    ),
    ModelStatus: (
        "Model status is synthetic lifecycle metadata and does not imply "
        "production readiness or regulatory approval."
    ),
    GraphNodeType: (
        "Graph nodes are synthetic investigative views only."
    ),
    GraphEdgeType: (
        "Graph edges are investigative associations only and are not proof of "
        "common control or wrongdoing."
    ),
    TraversalDirection: (
        "Traversal direction controls bounded exploration only. It does not "
        "imply causality or intent."
    ),
    ExportFormat: (
        "Exports are bounded investigative artefacts only and must not include "
        "raw sensitive narratives unless explicitly permitted by policy."
    ),
    ReportFormat: (
        "Reports are synthetic investigative summaries only and must include "
        "limitations and non-proof language."
    ),
}


# -----------------------------------------------------------------------------
# Terminal and transition metadata
# -----------------------------------------------------------------------------

_TERMINAL_STATES: Final[dict[type[Enum], frozenset[str]]] = {
    AlertState: frozenset(
        {
            "RESOLVED",
            "FALSE_POSITIVE",
            "DUPLICATE",
            "CLOSED",
        }
    ),
    CaseStatus: frozenset(
        {
            "RESOLVED",
            "CLOSED",
            "DUPLICATE",
        }
    ),
    ReviewState: frozenset(
        {
            "CONFIRMED",
            "REJECTED",
            "SUPERSEDED",
        }
    ),
    TransactionStatus: frozenset(
        {
            "COMPLETED",
            "FAILED",
            "REVERSED",
            "CANCELLED",
        }
    ),
    ModelStatus: frozenset(
        {
            "RETIRED",
            "ARCHIVED",
        }
    ),
    IngestionOutcome: frozenset(
        {
            "ACCEPTED",
            "REJECTED",
            "DUPLICATED",
            "SKIPPED",
            "TRUNCATED",
        }
    ),
}

_TRANSITIONS: Final[dict[type[Enum], dict[str, tuple[str, ...]]]] = {
    AlertState: {
        "NEW": (
            "ACKNOWLEDGED",
            "UNDER_REVIEW",
            "ESCALATED",
            "RESOLVED",
            "FALSE_POSITIVE",
            "DUPLICATE",
            "CLOSED",
        ),
        "ACKNOWLEDGED": (
            "UNDER_REVIEW",
            "ESCALATED",
            "RESOLVED",
            "FALSE_POSITIVE",
            "DUPLICATE",
            "CLOSED",
        ),
        "UNDER_REVIEW": (
            "ESCALATED",
            "RESOLVED",
            "FALSE_POSITIVE",
            "DUPLICATE",
            "CLOSED",
        ),
        "ESCALATED": (
            "UNDER_REVIEW",
            "RESOLVED",
            "FALSE_POSITIVE",
            "DUPLICATE",
            "CLOSED",
        ),
        "RESOLVED": (
            "UNDER_REVIEW",
            "ESCALATED",
            "CLOSED",
        ),
        "FALSE_POSITIVE": (
            "UNDER_REVIEW",
            "ESCALATED",
            "CLOSED",
        ),
        "DUPLICATE": (
            "UNDER_REVIEW",
            "ESCALATED",
            "CLOSED",
        ),
        "CLOSED": (
            "UNDER_REVIEW",
            "ESCALATED",
        ),
    },
    CaseStatus: {
        "NEW": (
            "UNDER_REVIEW",
            "ESCALATED",
            "RESOLVED",
            "CLOSED",
            "DUPLICATE",
        ),
        "UNDER_REVIEW": (
            "ESCALATED",
            "RESOLVED",
            "CLOSED",
            "DUPLICATE",
        ),
        "ESCALATED": (
            "UNDER_REVIEW",
            "RESOLVED",
            "CLOSED",
            "DUPLICATE",
        ),
        "RESOLVED": (
            "REOPENED",
            "CLOSED",
        ),
        "CLOSED": (
            "REOPENED",
        ),
        "REOPENED": (
            "UNDER_REVIEW",
            "ESCALATED",
            "RESOLVED",
            "CLOSED",
            "DUPLICATE",
        ),
        "DUPLICATE": (
            "CLOSED",
            "REOPENED",
        ),
    },
    ReviewState: {
        "UNREVIEWED": (
            "CONFIRMED",
            "REJECTED",
            "NEEDS_MORE_EVIDENCE",
            "ESCALATED",
            "SUPERSEDED",
        ),
        "NEEDS_MORE_EVIDENCE": (
            "CONFIRMED",
            "REJECTED",
            "ESCALATED",
            "SUPERSEDED",
        ),
        "ESCALATED": (
            "CONFIRMED",
            "REJECTED",
            "SUPERSEDED",
        ),
        "CONFIRMED": (
            "SUPERSEDED",
        ),
        "REJECTED": (
            "SUPERSEDED",
        ),
    },
    TransactionStatus: {
        "PENDING": (
            "COMPLETED",
            "FAILED",
            "CANCELLED",
        ),
        "COMPLETED": (
            "REVERSED",
            "DISPUTED",
        ),
        "FAILED": (
            "PENDING",
            "CANCELLED",
        ),
        "REVERSED": (
            "DISPUTED",
        ),
        "CANCELLED": (
            "PENDING",
        ),
        "DISPUTED": (
            "REVERSED",
            "COMPLETED",
        ),
    },
    ModelStatus: {
        "DRAFT": (
            "EVALUATED",
            "CANDIDATE",
            "RETIRED",
            "ARCHIVED",
        ),
        "EVALUATED": (
            "CANDIDATE",
            "ACTIVE",
            "RETIRED",
            "ARCHIVED",
        ),
        "CANDIDATE": (
            "ACTIVE",
            "EVALUATED",
            "RETIRED",
            "ARCHIVED",
        ),
        "ACTIVE": (
            "RETIRED",
            "CANDIDATE",
        ),
        "RETIRED": (
            "ARCHIVED",
            "CANDIDATE",
        ),
        "ARCHIVED": (
            "CANDIDATE",
        ),
    },
}


# -----------------------------------------------------------------------------
# Internal caches
# -----------------------------------------------------------------------------

_TERMINAL_CACHE: dict[type[Enum], frozenset[str]] = {}
_TRANSITION_CACHE: dict[type[Enum], dict[str, tuple[str, ...]]] = {}


# -----------------------------------------------------------------------------
# Token and lookup helpers
# -----------------------------------------------------------------------------


def _prettify(name: str) -> str:
    """
    Convert an enum member name into a human-readable label.
    """
    parts = [part for part in str(name).split("_") if part]

    if not parts:
        return ""

    words = [
        _WORD_DISPLAY.get(part.upper(), part.title())
        for part in parts
    ]

    return " ".join(words)


def _token(value: Any) -> str:
    """
    Normalize any value into a conservative uppercase token.

    This helper is intentionally lossy and bounded. It must not be used for
    secrets or sensitive identifiers.
    """
    if isinstance(value, Enum):
        raw = value.value
    else:
        raw = value

    text = str(raw if raw is not None else "").strip()

    if not text:
        return ""

    text = _CONTROL_CHAR_RE.sub(" ", text)
    text = text.lower()
    text = _SEPARATOR_RE.sub("_", text)
    text = _MULTI_UNDERSCORE_RE.sub("_", text)
    text = text.strip("_")

    return text.upper()


def _lookup(
    enum_cls: type[Enum],
    token: str,
    *,
    allow_aliases: bool = True,
) -> Optional[Enum]:
    """
    Look up an enum member by canonical value, member name, or alias.
    """
    if not token:
        return None

    for member in enum_cls:
        if str(member.value).strip().upper() == token:
            return member

    try:
        return enum_cls[token]
    except KeyError:
        pass

    if allow_aliases:
        alias_target = _ALIASES.get(enum_cls, {}).get(token)

        if alias_target:
            try:
                return enum_cls[alias_target]
            except KeyError:
                for member in enum_cls:
                    if str(member.value).strip().upper() == str(alias_target).strip().upper():
                        return member

    return None


# -----------------------------------------------------------------------------
# Public coercion helpers
# -----------------------------------------------------------------------------


def coerce_enum(
    enum_cls: type[EnumT],
    value: Any,
    *,
    default: Any = None,
    allow_aliases: bool = True,
) -> Optional[EnumT]:
    """
    Coerce a value to an enum member.

    Returns None when the value is unrecognized and no valid default is
    supplied.
    """
    member = _lookup(enum_cls, _token(value), allow_aliases=allow_aliases)

    if member is not None:
        return member  # type: ignore[return-value]

    if default is not None:
        default_member = _lookup(
            enum_cls,
            _token(default),
            allow_aliases=allow_aliases,
        )

        if default_member is not None:
            return default_member  # type: ignore[return-value]

    return None


def normalize_enum(
    enum_cls: type[Enum],
    value: Any,
    *,
    default: Any = None,
    allow_aliases: bool = True,
) -> Optional[str]:
    """
    Normalize a value to an enum's canonical string value.

    Returns None when the value is unrecognized and no valid default is
    supplied.
    """
    member = coerce_enum(
        enum_cls,
        value,
        default=None,
        allow_aliases=allow_aliases,
    )

    if member is not None:
        return str(member.value)

    if default is not None:
        default_member = coerce_enum(
            enum_cls,
            default,
            default=None,
            allow_aliases=allow_aliases,
        )

        if default_member is not None:
            return str(default_member.value)

    return None


def require_enum(
    enum_cls: type[EnumT],
    value: Any,
    *,
    field_name: str = "value",
    allow_aliases: bool = True,
) -> EnumT:
    """
    Coerce a value to an enum member or raise a safe validation error.
    """
    member = coerce_enum(
        enum_cls,
        value,
        default=None,
        allow_aliases=allow_aliases,
    )

    if member is None:
        raise ValidationError(
            "Invalid value.",
            details={
                "field": str(field_name),
                "allowed_values": list(enum_values(enum_cls)),
            },
        )

    return member


def safe_enum_value(value: Any) -> Optional[str]:
    """
    Return a safe string value for an enum-like object.

    This does not validate against a specific enum class.
    """
    if value is None:
        return None

    if isinstance(value, Enum):
        return str(value.value)

    text = str(value).strip()
    return text or None


# -----------------------------------------------------------------------------
# Enumeration introspection helpers
# -----------------------------------------------------------------------------


def enum_values(enum_cls: type[Enum]) -> tuple[str, ...]:
    """
    Return canonical enum values in declaration order.
    """
    return tuple(str(member.value) for member in enum_cls)


def enum_names(enum_cls: type[Enum]) -> tuple[str, ...]:
    """
    Return enum member names in declaration order.
    """
    return tuple(str(member.name) for member in enum_cls)


def enum_members(enum_cls: type[Enum]) -> tuple[Enum, ...]:
    """
    Return enum members in declaration order.
    """
    return tuple(enum_cls)


def enum_label(enum_cls: type[Enum], name: Any) -> str:
    """
    Return a human-readable label for an enum member name.
    """
    member_name = str(name)
    return _DISPLAY_NAMES.get(enum_cls, {}).get(
        member_name,
        _prettify(member_name),
    )


def enum_description(enum_cls: type[Enum], name: Any) -> str:
    """
    Return a safe description for an enum member name, when configured.
    """
    return _MEMBER_DESCRIPTIONS.get(enum_cls, {}).get(str(name), "")


def enum_choices(enum_cls: type[Enum]) -> list[dict[str, str]]:
    """
    Return safe value/label choices for UI or documentation use.
    """
    return [
        {
            "value": str(member.value),
            "label": enum_label(enum_cls, member.name),
        }
        for member in enum_cls
    ]


def enum_note(enum_cls: type[Enum]) -> str:
    """
    Return a product-safety note for an enum class, when configured.
    """
    return _ENUM_NOTES.get(enum_cls, "")


# -----------------------------------------------------------------------------
# Terminal and transition helpers
# -----------------------------------------------------------------------------


def _terminal_token_set(enum_cls: type[Enum]) -> frozenset[str]:
    """
    Return normalized terminal tokens for an enum class.
    """
    cached = _TERMINAL_CACHE.get(enum_cls)

    if cached is not None:
        return cached

    terminal_names = {
        str(item).strip().upper()
        for item in _TERMINAL_STATES.get(enum_cls, frozenset())
        if str(item).strip()
    }

    tokens: set[str] = set()

    for member in enum_cls:
        member_token = _token(member.value)

        if str(member.name).upper() in terminal_names or member_token in terminal_names:
            tokens.add(member_token)

    normalized = frozenset(tokens)
    _TERMINAL_CACHE[enum_cls] = normalized
    return normalized


def is_terminal(enum_cls: type[Enum], value: Any) -> bool:
    """
    Return True when a value is terminal workflow metadata.

    Terminal does not necessarily mean irreversible. Explicit reopen transitions
    may still be allowed.
    """
    token = _token(value)
    return bool(token and token in _terminal_token_set(enum_cls))


def _transition_map(enum_cls: type[Enum]) -> dict[str, tuple[str, ...]]:
    """
    Return normalized transition map for an enum class.
    """
    cached = _TRANSITION_CACHE.get(enum_cls)

    if cached is not None:
        return cached

    normalized: dict[str, tuple[str, ...]] = {}

    for from_key, to_values in _TRANSITIONS.get(enum_cls, {}).items():
        from_token = _token(from_key)
        resolved: list[str] = []

        for to_value in to_values:
            to_member = _lookup(
                enum_cls,
                _token(to_value),
                allow_aliases=True,
            )

            resolved.append(
                str(to_member.value)
                if to_member is not None
                else str(to_value)
            )

        normalized[from_token] = tuple(resolved)

    _TRANSITION_CACHE[enum_cls] = normalized
    return normalized


def allowed_transitions(enum_cls: type[Enum], current: Any) -> tuple[str, ...]:
    """
    Return canonical values that the current state may transition to.
    """
    return _transition_map(enum_cls).get(_token(current), ())


def allowed_transition(
    enum_cls: type[Enum],
    from_value: Any,
    to_value: Any,
) -> bool:
    """
    Return True when transition from one state to another is allowed.

    Same-state transitions are allowed as no-op idempotent updates.
    """
    from_token = _token(from_value)
    to_token = _token(to_value)

    if not from_token or not to_token:
        return False

    if from_token == to_token:
        return True

    return any(
        to_token == _token(allowed)
        for allowed in allowed_transitions(enum_cls, from_value)
    )


def validate_transition(
    enum_cls: type[Enum],
    from_value: Any,
    to_value: Any,
    *,
    field_name: str = "transition",
) -> None:
    """
    Validate a state transition and raise a safe error when disallowed.
    """
    from_member = coerce_enum(enum_cls, from_value)
    to_member = coerce_enum(enum_cls, to_value)

    if from_member is None or to_member is None:
        raise ValidationError(
            "Invalid state transition value.",
            details={
                "field": str(field_name),
                "allowed_values": list(enum_values(enum_cls)),
            },
        )

    if not allowed_transition(enum_cls, from_member.value, to_member.value):
        raise ValidationError(
            "State transition is not allowed.",
            details={
                "field": str(field_name),
                "from": str(from_member.value),
                "to": str(to_member.value),
                "allowed_transitions": list(
                    allowed_transitions(enum_cls, from_member.value)
                ),
            },
        )


# -----------------------------------------------------------------------------
# Metadata helpers
# -----------------------------------------------------------------------------


def enum_metadata(enum_cls: type[Enum]) -> dict[str, Any]:
    """
    Return safe, serializable metadata for one enum class.
    """
    terminal_tokens = _terminal_token_set(enum_cls)
    transitions = _transition_map(enum_cls)
    members: list[dict[str, Any]] = []

    for member in enum_cls:
        token = _token(member.value)

        members.append(
            {
                "name": str(member.name),
                "value": str(member.value),
                "label": enum_label(enum_cls, member.name),
                "description": enum_description(enum_cls, member.name),
                "terminal": token in terminal_tokens,
                "allowed_transitions": list(transitions.get(token, ())),
            }
        )

    return {
        "name": enum_cls.__name__,
        "note": enum_note(enum_cls),
        "members": members,
    }


def all_core_enums_metadata() -> dict[str, dict[str, Any]]:
    """
    Return safe metadata for all registered core enums.
    """
    return {
        enum_cls.__name__: enum_metadata(enum_cls)
        for enum_cls in _CORE_ENUM_CLASSES
    }


def core_enum_classes() -> tuple[type[CoreEnum], ...]:
    """
    Return all registered core enum classes.
    """
    return _CORE_ENUM_CLASSES


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "AccountStatus",
    "AccountType",
    "AlertState",
    "AuditOutcome",
    "CaseDisposition",
    "CaseStatus",
    "Channel",
    "CoreEnum",
    "DataSensitivity",
    "DatasetMode",
    "Environment",
    "EvidenceType",
    "ExportFormat",
    "FeatureWindow",
    "GraphEdgeType",
    "GraphNodeType",
    "IngestionOutcome",
    "MatchMethod",
    "ModelStatus",
    "Priority",
    "ReportFormat",
    "ReviewState",
    "RiskBand",
    "ScoringMode",
    "Severity",
    "SortDirection",
    "TimeGranularity",
    "TransactionStatus",
    "TraversalDirection",
    "VerificationState",
    "all_core_enums_metadata",
    "allowed_transition",
    "allowed_transitions",
    "coerce_enum",
    "core_enum_classes",
    "enum_choices",
    "enum_description",
    "enum_label",
    "enum_members",
    "enum_metadata",
    "enum_names",
    "enum_note",
    "enum_values",
    "is_terminal",
    "normalize_enum",
    "require_enum",
    "safe_enum_value",
    "validate_transition",
]