"""
MULEGUARD ingestion service.

Persists validated synthetic records, batch by batch, with referential checks
and deduplication.

Transactionality is the point of this module. A batch is applied as one unit:
either every accepted row lands or none does. A half-applied batch is worse
than a rejected one, because transactions referencing accounts that never
arrived produce a graph with phantom endpoints, and nobody can tell which half
is missing.

Rows are validated in three passes before anything is written:

1. **Shape** — required fields, types, ranges, currency format.
2. **Referential integrity** — every account a transaction names must exist,
   either already in the database or earlier in the same batch.
3. **Deduplication** — a natural key already present is reported as a duplicate
   rather than inserted again. References are unique in the schema, so
   inserting blind would abort the whole transaction on one repeat.

Rejected rows are returned with their index and reason so a caller can fix the
source file, rather than being silently dropped.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any, Final, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.exceptions import (
    IngestionBatchLimitError,
    IngestionReferentialIntegrityError,
    IngestionValidationError,
)
from app.models import (
    Account,
    AccountEntityLink,
    AccountStatus,
    AccountType,
    Channel,
    Complaint,
    Entity,
    EntityType,
    MatchMethod,
    Transaction,
    TransactionStatus,
    VerificationState,
)
from app.utils.dates import ensure_utc, parse_datetime, utcnow
from app.utils.decimals import quantize_confidence, quantize_money, to_decimal
from app.utils.ids import coerce_id, is_safe_identifier
from app.utils.json import sanitize_json
from app.utils.text import clean_text, normalize_whitespace_text

logger = logging.getLogger("muleguard.backend.services.ingestion")

__all__ = [
    "INGESTION_SERVICE_VERSION",
    "MAX_BATCH_SIZE",
    "BatchResult",
    "RowError",
    "get_ingestion_service_metadata",
    "ingest_accounts",
    "ingest_complaints",
    "ingest_entities",
    "ingest_entity_links",
    "ingest_transactions",
]

INGESTION_SERVICE_VERSION: Final[str] = "v1"
MAX_BATCH_SIZE: Final[int] = 10_000

_MAX_REPORTED_ERRORS: Final[int] = 100


class RowError:
    """
    One rejected row, with enough context to fix the source.
    """

    __slots__ = ("field", "index", "reason", "record_id")

    def __init__(
        self,
        index: int,
        reason: str,
        *,
        field: Optional[str] = None,
        record_id: Optional[str] = None,
    ) -> None:
        self.index = int(index)
        self.reason = str(reason)
        self.field = field
        self.record_id = record_id

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe representation.
        """
        return {
            "index": self.index,
            "reason": self.reason,
            "field": self.field,
            "record_id": self.record_id,
        }


class BatchResult:
    """
    Outcome of one ingestion batch.
    """

    __slots__ = ("accepted", "duplicates", "entity_type", "errors", "received")

    def __init__(self, entity_type: str) -> None:
        self.entity_type = entity_type
        self.received = 0
        self.accepted = 0
        self.duplicates = 0
        self.errors: list[RowError] = []

    def reject(
        self,
        index: int,
        reason: str,
        *,
        field: Optional[str] = None,
        record_id: Optional[str] = None,
    ) -> None:
        """
        Record a rejected row.
        """
        if len(self.errors) < _MAX_REPORTED_ERRORS:
            self.errors.append(
                RowError(index, reason, field=field, record_id=record_id)
            )

    @property
    def rejected(self) -> int:
        """
        Number of rows rejected.
        """
        return self.received - self.accepted - self.duplicates

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe summary.
        """
        return {
            "entity_type": self.entity_type,
            "received": self.received,
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "errors": [error.to_dict() for error in self.errors],
            "errors_truncated": self.rejected > len(self.errors),
        }

    def __repr__(self) -> str:
        return (
            f"BatchResult({self.entity_type}, received={self.received}, "
            f"accepted={self.accepted}, duplicates={self.duplicates}, "
            f"rejected={self.rejected})"
        )


def _check_batch_size(records: Sequence[Any], entity_type: str) -> None:
    """
    Reject an oversized batch before any work is done.
    """
    if len(records) > MAX_BATCH_SIZE:
        raise IngestionBatchLimitError(
            "Ingestion batch exceeds the configured maximum size.",
            details={
                "entity_type": entity_type,
                "received": len(records),
                "max_batch_size": MAX_BATCH_SIZE,
            },
        )


def _enum_or_none(enum_cls: Any, value: Any) -> Any:
    """
    Coerce a value into an enum member, or None when it does not match.
    """
    if value is None:
        return None

    if isinstance(value, enum_cls):
        return value

    token = str(getattr(value, "value", value)).strip().upper()
    return enum_cls[token] if token in enum_cls.__members__ else None


def _currency(value: Any) -> Optional[str]:
    """
    Normalise a currency code to the schema's 3-letter uppercase form.
    """
    token = clean_text(value or "", 8).upper()
    return token if len(token) == 3 and token.isalpha() else None


def ingest_accounts(
    db: Session,
    records: Sequence[Mapping[str, Any]],
    *,
    source_system: str = "import",
    batch_id: Optional[str] = None,
) -> BatchResult:
    """
    Persist account records.
    """
    _check_batch_size(records, "account")
    result = BatchResult("account")
    result.received = len(records)

    incoming_ids = [
        coerce_id(record.get("id")) for record in records if isinstance(record, Mapping)
    ]
    existing = {
        str(item)
        for item in db.execute(
            select(Account.id).where(
                Account.id.in_([i for i in incoming_ids if i])
            )
        ).scalars()
    }
    seen: set[str] = set()

    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            result.reject(index, "record is not an object")
            continue

        account_id = coerce_id(record.get("id"))

        if not account_id:
            result.reject(index, "missing or unsafe account id", field="id")
            continue

        if account_id in existing or account_id in seen:
            result.duplicates += 1
            continue

        created_at = ensure_utc(
            record.get("created_at")
            if isinstance(record.get("created_at"), datetime)
            else parse_datetime(record.get("created_at"))
        )

        if created_at is None:
            result.reject(index, "missing or unparseable created_at", field="created_at", record_id=account_id)
            continue

        if created_at > utcnow():
            result.reject(index, "created_at is in the future", field="created_at", record_id=account_id)
            continue

        account_type = _enum_or_none(AccountType, record.get("account_type"))
        status = _enum_or_none(AccountStatus, record.get("status"))

        db.add(
            Account(
                id=account_id,
                account_type=account_type or AccountType.OTHER,
                status=status or AccountStatus.ACTIVE,
                created_at=created_at,
                metadata_json=sanitize_json(
                    record.get("metadata_json") or record.get("metadata") or {},
                    max_items=40,
                ),
            )
        )
        seen.add(account_id)
        result.accepted += 1

    db.flush()
    return result


def ingest_transactions(
    db: Session,
    records: Sequence[Mapping[str, Any]],
    *,
    source_system: str = "import",
    batch_id: Optional[str] = None,
) -> BatchResult:
    """
    Persist transaction records.

    Both endpoint accounts must already exist, or the whole batch is rejected:
    a transfer whose counterparty is absent would create a graph edge to a
    phantom node, which is worse than refusing the row.
    """
    _check_batch_size(records, "transaction")
    result = BatchResult("transaction")
    result.received = len(records)

    referenced: set[str] = set()
    references: list[str] = []

    for record in records:
        if not isinstance(record, Mapping):
            continue

        for key in ("sender_account_id", "receiver_account_id"):
            identifier = coerce_id(record.get(key))

            if identifier:
                referenced.add(identifier)

        reference = clean_text(record.get("reference") or "", 128)

        if reference:
            references.append(reference)

    known_accounts = {
        str(item)
        for item in db.execute(
            select(Account.id).where(Account.id.in_(sorted(referenced)))
        ).scalars()
    }
    missing = sorted(referenced - known_accounts)

    if missing:
        raise IngestionReferentialIntegrityError(
            "Transaction batch references accounts that do not exist. Import "
            "the accounts first.",
            details={"missing_account_ids": missing[:50], "missing_count": len(missing)},
        )

    existing_refs = {
        str(item)
        for item in db.execute(
            select(Transaction.reference).where(Transaction.reference.in_(references))
        ).scalars()
    }
    seen_refs: set[str] = set()

    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            result.reject(index, "record is not an object")
            continue

        reference = clean_text(record.get("reference") or "", 128)

        if not reference:
            result.reject(index, "missing transaction reference", field="reference")
            continue

        if reference in existing_refs or reference in seen_refs:
            result.duplicates += 1
            continue

        sender = coerce_id(record.get("sender_account_id"))
        receiver = coerce_id(record.get("receiver_account_id"))

        if not sender or not receiver:
            result.reject(index, "missing sender or receiver account", record_id=reference)
            continue

        if sender == receiver:
            result.reject(
                index,
                "sender and receiver are the same account",
                record_id=reference,
            )
            continue

        amount = quantize_money(record.get("amount"))

        if amount is None or amount <= 0:
            result.reject(
                index, "amount must be a positive number", field="amount", record_id=reference
            )
            continue

        currency = _currency(record.get("currency") or "INR")

        if currency is None:
            result.reject(
                index,
                "currency must be a 3-letter code",
                field="currency",
                record_id=reference,
            )
            continue

        occurred_at = ensure_utc(
            record.get("occurred_at")
            if isinstance(record.get("occurred_at"), datetime)
            else parse_datetime(record.get("occurred_at"))
        )

        if occurred_at is None:
            result.reject(
                index, "missing or unparseable occurred_at", field="occurred_at", record_id=reference
            )
            continue

        if occurred_at > utcnow():
            result.reject(
                index, "occurred_at is in the future", field="occurred_at", record_id=reference
            )
            continue

        db.add(
            Transaction(
                id=coerce_id(record.get("id")) or None,
                sender_account_id=sender,
                receiver_account_id=receiver,
                amount=amount,
                currency=currency,
                occurred_at=occurred_at,
                status=_enum_or_none(TransactionStatus, record.get("status"))
                or TransactionStatus.COMPLETED,
                channel=_enum_or_none(Channel, record.get("channel")) or Channel.INTERNAL,
                reference=reference,
                metadata_json=sanitize_json(
                    record.get("metadata_json") or record.get("metadata") or {},
                    max_items=40,
                ),
                source_system=source_system[:100],
                source_batch_id=(batch_id or "")[:100] or None,
            )
        )
        seen_refs.add(reference)
        result.accepted += 1

    db.flush()
    return result


def ingest_complaints(
    db: Session,
    records: Sequence[Mapping[str, Any]],
    *,
    source_system: str = "import",
    batch_id: Optional[str] = None,
) -> BatchResult:
    """
    Persist complaint records.

    The raw narrative is stored verbatim. It is a source fact and must not be
    rewritten; only whitespace is normalised, and the normalised form goes in
    its own column.
    """
    _check_batch_size(records, "complaint")
    result = BatchResult("complaint")
    result.received = len(records)

    references = [
        clean_text(record.get("reference") or "", 128)
        for record in records
        if isinstance(record, Mapping)
    ]
    existing = {
        str(item)
        for item in db.execute(
            select(Complaint.reference).where(
                Complaint.reference.in_([r for r in references if r])
            )
        ).scalars()
    }
    seen: set[str] = set()

    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            result.reject(index, "record is not an object")
            continue

        reference = clean_text(record.get("reference") or "", 128)

        if not reference:
            result.reject(index, "missing complaint reference", field="reference")
            continue

        if reference in existing or reference in seen:
            result.duplicates += 1
            continue

        reported_at = ensure_utc(
            record.get("reported_at")
            if isinstance(record.get("reported_at"), datetime)
            else parse_datetime(record.get("reported_at"))
        )

        if reported_at is None:
            result.reject(
                index, "missing or unparseable reported_at", field="reported_at", record_id=reference
            )
            continue

        narrative = str(record.get("narrative_raw") or record.get("narrative") or "")

        if not narrative.strip():
            result.reject(
                index, "missing narrative_raw", field="narrative_raw", record_id=reference
            )
            continue

        for key in ("victim_account_id", "suspected_account_id"):
            identifier = record.get(key)

            if identifier and not is_safe_identifier(str(identifier)):
                result.reject(index, f"unsafe {key}", field=key, record_id=reference)
                break
        else:
            amount = quantize_money(record.get("amount")) if record.get("amount") is not None else None

            if amount is not None and amount <= 0:
                result.reject(
                    index, "amount must be positive when present", field="amount", record_id=reference
                )
                continue

            db.add(
                Complaint(
                    id=coerce_id(record.get("id")) or None,
                    reference=reference,
                    reported_at=reported_at,
                    category=clean_text(record.get("category") or "other", 100) or "other",
                    # Verbatim: the raw narrative is a source fact.
                    narrative_raw=narrative[:100_000],
                    narrative_normalized=normalize_whitespace_text(narrative, 20_000) or None,
                    transaction_reference=clean_text(
                        record.get("transaction_reference") or "", 128
                    )
                    or None,
                    victim_account_id=coerce_id(record.get("victim_account_id")),
                    suspected_account_id=coerce_id(record.get("suspected_account_id")),
                    amount=amount,
                    currency=_currency(record.get("currency")),
                    source=clean_text(record.get("source") or source_system, 100) or None,
                    ingested_at=utcnow(),
                    metadata_json=sanitize_json(
                        record.get("metadata_json") or record.get("metadata") or {},
                        max_items=40,
                    ),
                    source_system=source_system[:100],
                    source_batch_id=(batch_id or "")[:100] or None,
                )
            )
            seen.add(reference)
            result.accepted += 1

    db.flush()
    return result


def ingest_entities(
    db: Session,
    records: Sequence[Mapping[str, Any]],
    *,
    source_system: str = "import",
    batch_id: Optional[str] = None,
) -> BatchResult:
    """
    Persist pseudonymous entity records.

    `identifier_hash` is required and must already be hashed. This service
    never accepts a raw device id, phone number, or email address.
    """
    _check_batch_size(records, "entity")
    result = BatchResult("entity")
    result.received = len(records)
    seen: set[tuple[str, str, str]] = set()

    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            result.reject(index, "record is not an object")
            continue

        entity_type = _enum_or_none(EntityType, record.get("entity_type"))

        if entity_type is None:
            result.reject(
                index,
                f"entity_type must be one of {[e.value for e in EntityType]}",
                field="entity_type",
            )
            continue

        identifier_hash = clean_text(record.get("identifier_hash") or "", 128)

        if not identifier_hash:
            result.reject(
                index,
                "identifier_hash is required; raw identifiers are never accepted",
                field="identifier_hash",
            )
            continue

        source = clean_text(record.get("source") or "synthetic", 100) or "synthetic"
        key = (entity_type.value, identifier_hash, source)

        if key in seen:
            result.duplicates += 1
            continue

        clash = db.execute(
            select(Entity.id)
            .where(Entity.entity_type == entity_type)
            .where(Entity.identifier_hash == identifier_hash)
            .where(Entity.source == source)
            .limit(1)
        ).scalars().first()

        if clash is not None:
            result.duplicates += 1
            continue

        db.add(
            Entity(
                id=coerce_id(record.get("id")) or None,
                entity_type=entity_type,
                identifier_hash=identifier_hash,
                identifier_display=clean_text(record.get("identifier_display") or "", 200) or None,
                source=source,
                first_seen_at=ensure_utc(parse_datetime(record.get("first_seen_at"))),
                last_seen_at=ensure_utc(parse_datetime(record.get("last_seen_at"))),
                metadata_json=sanitize_json(
                    record.get("metadata_json") or record.get("metadata") or {},
                    max_items=30,
                ),
                source_system=source_system[:100],
                source_batch_id=(batch_id or "")[:100] or None,
            )
        )
        seen.add(key)
        result.accepted += 1

    db.flush()
    return result


def ingest_entity_links(
    db: Session,
    records: Sequence[Mapping[str, Any]],
    *,
    source_system: str = "import",
    batch_id: Optional[str] = None,
) -> BatchResult:
    """
    Persist account-entity links.

    Both endpoints must exist. A link to a missing account or entity would make
    a shared-entity cluster report an account that is not in the system.
    """
    _check_batch_size(records, "entity_link")
    result = BatchResult("entity_link")
    result.received = len(records)

    account_ids = {
        coerce_id(record.get("account_id"))
        for record in records
        if isinstance(record, Mapping)
    } - {None}
    entity_ids = {
        coerce_id(record.get("entity_id"))
        for record in records
        if isinstance(record, Mapping)
    } - {None}

    known_accounts = {
        str(i)
        for i in db.execute(
            select(Account.id).where(Account.id.in_(sorted(account_ids)))
        ).scalars()
    }
    known_entities = {
        str(i)
        for i in db.execute(
            select(Entity.id).where(Entity.id.in_(sorted(entity_ids)))
        ).scalars()
    }

    missing_accounts = sorted(set(account_ids) - known_accounts)
    missing_entities = sorted(set(entity_ids) - known_entities)

    if missing_accounts or missing_entities:
        raise IngestionReferentialIntegrityError(
            "Entity-link batch references records that do not exist.",
            details={
                "missing_account_ids": missing_accounts[:25],
                "missing_entity_ids": missing_entities[:25],
            },
        )

    seen: set[tuple[str, str, str, str]] = set()

    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            result.reject(index, "record is not an object")
            continue

        account_id = coerce_id(record.get("account_id"))
        entity_id = coerce_id(record.get("entity_id"))

        if not account_id or not entity_id:
            result.reject(index, "missing account_id or entity_id")
            continue

        valid_from = ensure_utc(parse_datetime(record.get("valid_from"))) or utcnow()
        valid_to = ensure_utc(parse_datetime(record.get("valid_to")))

        if valid_to is not None and valid_to <= valid_from:
            result.reject(
                index, "valid_to must be after valid_from", field="valid_to"
            )
            continue

        source = clean_text(record.get("source") or "synthetic", 100) or "synthetic"
        key = (account_id, entity_id, valid_from.isoformat(), source)

        if key in seen:
            result.duplicates += 1
            continue

        clash = db.execute(
            select(AccountEntityLink.id)
            .where(AccountEntityLink.account_id == account_id)
            .where(AccountEntityLink.entity_id == entity_id)
            .where(AccountEntityLink.valid_from == valid_from)
            .where(AccountEntityLink.source == source)
            .limit(1)
        ).scalars().first()

        if clash is not None:
            result.duplicates += 1
            continue

        confidence = record.get("confidence")
        quantized = quantize_confidence(confidence) if confidence is not None else None

        db.add(
            AccountEntityLink(
                id=coerce_id(record.get("id")) or None,
                account_id=account_id,
                entity_id=entity_id,
                match_method=_enum_or_none(MatchMethod, record.get("match_method"))
                or MatchMethod.EXACT,
                confidence=quantized,
                verification_state=_enum_or_none(
                    VerificationState, record.get("verification_state")
                )
                or VerificationState.UNVERIFIED,
                valid_from=valid_from,
                valid_to=valid_to,
                source=source,
                metadata_json=sanitize_json(
                    record.get("metadata_json") or record.get("metadata") or {},
                    max_items=30,
                ),
                source_system=source_system[:100],
                source_batch_id=(batch_id or "")[:100] or None,
            )
        )
        seen.add(key)
        result.accepted += 1

    db.flush()
    return result


def get_ingestion_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the ingestion service.
    """
    return {
        "service": "muleguard.backend.services.ingestion",
        "version": INGESTION_SERVICE_VERSION,
        "max_batch_size": MAX_BATCH_SIZE,
        "entity_types": [
            "account",
            "transaction",
            "complaint",
            "entity",
            "entity_link",
        ],
        "validation_passes": ["shape", "referential_integrity", "deduplication"],
        "guarantees": [
            "A batch is applied as one unit; the caller's transaction is never "
            "left half-applied.",
            "A transaction referencing a missing account rejects the batch "
            "rather than creating a phantom graph node.",
            "Duplicates are reported, not inserted, so one repeated reference "
            "cannot abort the whole batch.",
            "Rejected rows are returned with an index and a reason.",
            "Raw complaint narratives are stored verbatim as source facts.",
            "Raw device, phone, and email identifiers are never accepted; only "
            "pre-hashed identifier values are.",
        ],
    }
