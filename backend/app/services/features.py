"""
MULEGUARD feature service.

Bridges the database to the feature builder in `app.ml.features` and persists
the results as `FeatureSnapshot` rows.

This module is where point-in-time correctness is enforced. Every query here
has an upper bound of `as_of`, so a feature vector can only ever see what was
knowable at that instant. Without that, a model trained on these features
would learn from the future and score beautifully in evaluation while
detecting nothing in production.

Two integration details are load-bearing and were established by reading
`app.ml.features` directly:

1. **Records must be mappings, not ORM objects.** The builder's
   `_record_to_mapping` only applies its alias table to a `Mapping`. Given a
   non-mapping it reads the *canonical* attribute names, so a `Transaction`
   row yields `sender = None` (the column is `sender_account_id`) and the
   transaction is silently discarded.

2. **Enum columns must be passed as `.value`.** The builder normalises through
   `str(value)`, and `str(TransactionStatus.COMPLETED)` is
   `"TransactionStatus.COMPLETED"`, which normalises to
   `"TRANSACTION_STATUS_COMPLETED"` and fails the status check — again
   discarding every transaction.

Both failure modes are silent: they produce an empty feature set rather than an
error. `build_dataset` therefore emits plain primitives, and
`compute_features` asserts that a non-empty input produced a non-empty result.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any, Final, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.exceptions import FeatureComputationError
from app.models import (
    Account,
    AccountEntityLink,
    Complaint,
    Entity,
    FeatureSnapshot,
    Transaction,
    TransactionStatus,
)
from app.services.policy import get_windows_policy
from app.utils.dates import ensure_utc, utcnow
from app.utils.decimals import to_float
from app.utils.hashing import dataset_fingerprint
from app.utils.json import sanitize_json

logger = logging.getLogger("muleguard.backend.services.features")

__all__ = [
    "DEFAULT_FEATURE_VERSION",
    "FEATURES_SERVICE_VERSION",
    "DatasetBundle",
    "build_dataset",
    "compute_features",
    "feature_values_for_account",
    "get_features_service_metadata",
    "latest_snapshot_for_account",
    "persist_feature_snapshots",
]

FEATURES_SERVICE_VERSION: Final[str] = "v1"
DEFAULT_FEATURE_VERSION: Final[str] = "v1"

# Bounds on how much history one run may read. These exist so a run on a large
# database cannot turn into a full table scan.
_DEFAULT_MAX_ACCOUNTS: Final[int] = 5_000
_DEFAULT_MAX_TRANSACTIONS: Final[int] = 200_000
_DEFAULT_MAX_COMPLAINTS: Final[int] = 20_000
_DEFAULT_MAX_ENTITIES: Final[int] = 50_000
_DEFAULT_MAX_LINKS: Final[int] = 100_000
_DEFAULT_LOOKBACK_DAYS: Final[int] = 180


def _enum_value(value: Any) -> Optional[str]:
    """
    Return an enum's `.value`, or the cleaned string form.

    Never returns `str(enum_member)`: see the module docstring.
    """
    if value is None:
        return None

    inner = getattr(value, "value", value)
    text = str(inner).strip()
    return text or None


def _money(value: Any) -> Optional[float]:
    """
    Convert a NUMERIC column to a float for the feature builder.
    """
    if isinstance(value, Decimal):
        return float(value)

    return to_float(value)


class DatasetBundle:
    """
    The bounded, point-in-time dataset handed to the feature builder.

    Exposes the collection names the builder looks for (`accounts`,
    `transactions`, `complaints`, `entities`, `entity_links`, `balances`) both
    as attributes and as mapping keys, because the builder accepts either.
    """

    __slots__ = (
        "accounts",
        "as_of",
        "balances",
        "complaints",
        "entities",
        "entity_links",
        "transactions",
        "truncated",
    )

    def __init__(
        self,
        *,
        as_of: datetime,
        accounts: list[dict[str, Any]],
        transactions: list[dict[str, Any]],
        complaints: list[dict[str, Any]],
        entities: list[dict[str, Any]],
        entity_links: list[dict[str, Any]],
        balances: Optional[list[dict[str, Any]]] = None,
        truncated: Optional[dict[str, bool]] = None,
    ) -> None:
        self.as_of = as_of
        self.accounts = accounts
        self.transactions = transactions
        self.complaints = complaints
        self.entities = entities
        self.entity_links = entity_links
        self.balances = balances or []
        self.truncated = truncated or {}

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Mapping-style access, so the builder can treat this as a mapping.
        """
        return getattr(self, key, default)

    def keys(self) -> list[str]:
        """
        Return the collection names available on this bundle.
        """
        return [
            "accounts",
            "transactions",
            "complaints",
            "entities",
            "entity_links",
            "balances",
        ]

    def counts(self) -> dict[str, int]:
        """
        Return row counts per collection.
        """
        return {
            "accounts": len(self.accounts),
            "transactions": len(self.transactions),
            "complaints": len(self.complaints),
            "entities": len(self.entities),
            "entity_links": len(self.entity_links),
            "balances": len(self.balances),
        }

    def fingerprint(self) -> str:
        """
        Return a reproducibility fingerprint for this dataset's shape.
        """
        return dataset_fingerprint(
            account_count=len(self.accounts),
            transaction_count=len(self.transactions),
            complaint_count=len(self.complaints),
            entity_count=len(self.entities),
            link_count=len(self.entity_links),
            extra={"as_of": self.as_of.isoformat()},
        )


def build_dataset(
    db: Session,
    *,
    as_of: Optional[datetime] = None,
    account_ids: Optional[Sequence[str]] = None,
    lookback_days: int = _DEFAULT_LOOKBACK_DAYS,
    max_accounts: int = _DEFAULT_MAX_ACCOUNTS,
    max_transactions: int = _DEFAULT_MAX_TRANSACTIONS,
    max_complaints: int = _DEFAULT_MAX_COMPLAINTS,
    max_entities: int = _DEFAULT_MAX_ENTITIES,
    max_links: int = _DEFAULT_MAX_LINKS,
) -> DatasetBundle:
    """
    Read a bounded, point-in-time dataset from the database.

    Everything is filtered to strictly before `as_of`. Transactions are further
    restricted to COMPLETED, because a failed or reversed transfer is not fund
    movement and must not be counted as one.

    When `account_ids` is given, transactions are restricted to those touching
    one of the named accounts, plus their direct counterparties — the graph
    features need one hop of context to be meaningful.
    """
    observation_time = ensure_utc(as_of) or utcnow()
    horizon = observation_time - _lookback_delta(lookback_days)

    selected_ids: Optional[set[str]] = None

    if account_ids is not None:
        selected_ids = {str(a).strip() for a in account_ids if str(a).strip()}

    # ---------------------------------------------------------------- accounts
    account_stmt = select(Account).where(Account.created_at < observation_time)

    if selected_ids:
        account_stmt = account_stmt.where(Account.id.in_(sorted(selected_ids)))

    account_stmt = account_stmt.order_by(Account.id).limit(max_accounts + 1)
    account_rows = list(db.execute(account_stmt).scalars())
    truncated = {"accounts": len(account_rows) > max_accounts}
    account_rows = account_rows[:max_accounts]

    accounts = [
        {
            "id": str(row.id),
            "account_type": _enum_value(row.account_type),
            "status": _enum_value(row.status),
            "created_at": ensure_utc(row.created_at),
            "metadata_json": row.metadata_json if isinstance(row.metadata_json, Mapping) else None,
        }
        for row in account_rows
    ]

    in_scope_ids = {entry["id"] for entry in accounts}

    # ------------------------------------------------------------ transactions
    txn_stmt = (
        select(Transaction)
        .where(Transaction.occurred_at < observation_time)
        .where(Transaction.occurred_at >= horizon)
        .where(Transaction.status == TransactionStatus.COMPLETED)
    )

    if selected_ids:
        # One hop of context: transfers where either endpoint is in scope.
        txn_stmt = txn_stmt.where(
            Transaction.sender_account_id.in_(sorted(in_scope_ids))
            | Transaction.receiver_account_id.in_(sorted(in_scope_ids))
        )

    txn_stmt = txn_stmt.order_by(
        Transaction.occurred_at, Transaction.id
    ).limit(max_transactions + 1)
    txn_rows = list(db.execute(txn_stmt).scalars())
    truncated["transactions"] = len(txn_rows) > max_transactions
    txn_rows = txn_rows[:max_transactions]

    transactions = [
        {
            "id": str(row.id),
            "reference": str(row.reference) if row.reference else None,
            # Alias keys: the builder maps these onto sender/receiver.
            "sender_account_id": str(row.sender_account_id),
            "receiver_account_id": str(row.receiver_account_id),
            "amount": _money(row.amount),
            "currency": str(row.currency) if row.currency else None,
            "occurred_at": ensure_utc(row.occurred_at),
            # .value, not the member: a member would normalise to
            # "TRANSACTION_STATUS_COMPLETED" and be discarded.
            "status": _enum_value(row.status),
            "channel": _enum_value(row.channel),
        }
        for row in txn_rows
    ]

    # Counterparties pulled in by the one-hop expansion need account rows too,
    # or the builder cannot resolve the other end of an edge.
    if selected_ids:
        referenced = {entry["sender_account_id"] for entry in transactions} | {
            entry["receiver_account_id"] for entry in transactions
        }
        missing = sorted(referenced - in_scope_ids)

        if missing:
            extra_rows = list(
                db.execute(
                    select(Account)
                    .where(Account.id.in_(missing[:max_accounts]))
                    .where(Account.created_at < observation_time)
                ).scalars()
            )
            accounts.extend(
                {
                    "id": str(row.id),
                    "account_type": _enum_value(row.account_type),
                    "status": _enum_value(row.status),
                    "created_at": ensure_utc(row.created_at),
                    "metadata_json": (
                        row.metadata_json if isinstance(row.metadata_json, Mapping) else None
                    ),
                }
                for row in extra_rows
            )
            in_scope_ids |= {str(row.id) for row in extra_rows}

    # -------------------------------------------------------------- complaints
    complaint_stmt = (
        select(Complaint)
        .where(Complaint.reported_at < observation_time)
        .where(Complaint.reported_at >= horizon)
    )

    if selected_ids:
        complaint_stmt = complaint_stmt.where(
            Complaint.victim_account_id.in_(sorted(in_scope_ids))
            | Complaint.suspected_account_id.in_(sorted(in_scope_ids))
        )

    complaint_stmt = complaint_stmt.order_by(
        Complaint.reported_at, Complaint.id
    ).limit(max_complaints + 1)
    complaint_rows = list(db.execute(complaint_stmt).scalars())
    truncated["complaints"] = len(complaint_rows) > max_complaints
    complaint_rows = complaint_rows[:max_complaints]

    complaints = [
        {
            "id": str(row.id),
            "reported_at": ensure_utc(row.reported_at),
            "category": str(row.category) if row.category else None,
            "transaction_reference": (
                str(row.transaction_reference) if row.transaction_reference else None
            ),
            # Alias keys: the builder maps these onto victim/suspect.
            "victim_account_id": (
                str(row.victim_account_id) if row.victim_account_id else None
            ),
            "suspected_account_id": (
                str(row.suspected_account_id) if row.suspected_account_id else None
            ),
            "amount": _money(row.amount),
            "currency": str(row.currency) if row.currency else None,
        }
        for row in complaint_rows
    ]

    # ------------------------------------------------------- entities + links
    link_stmt = select(AccountEntityLink).where(
        AccountEntityLink.valid_from < observation_time
    )

    if selected_ids:
        link_stmt = link_stmt.where(
            AccountEntityLink.account_id.in_(sorted(in_scope_ids))
        )

    link_stmt = link_stmt.order_by(
        AccountEntityLink.valid_from, AccountEntityLink.id
    ).limit(max_links + 1)
    link_rows = list(db.execute(link_stmt).scalars())
    truncated["entity_links"] = len(link_rows) > max_links
    link_rows = link_rows[:max_links]

    entity_links = [
        {
            "id": str(row.id),
            "account_id": str(row.account_id),
            "entity_id": str(row.entity_id),
            "match_method": _enum_value(row.match_method),
            "verification_state": _enum_value(row.verification_state),
            "confidence": _money(row.confidence),
            "valid_from": ensure_utc(row.valid_from),
            "valid_to": ensure_utc(row.valid_to),
        }
        for row in link_rows
    ]

    # Shared-entity features need every account attached to a linked entity,
    # not only the accounts in scope, or the cluster size is always 1.
    entity_ids = sorted({entry["entity_id"] for entry in entity_links})

    if entity_ids:
        sibling_rows = list(
            db.execute(
                select(AccountEntityLink)
                .where(AccountEntityLink.entity_id.in_(entity_ids))
                .where(AccountEntityLink.valid_from < observation_time)
                .limit(max_links)
            ).scalars()
        )
        known = {(e["account_id"], e["entity_id"], e["valid_from"]) for e in entity_links}

        for row in sibling_rows:
            key = (str(row.account_id), str(row.entity_id), ensure_utc(row.valid_from))

            if key in known:
                continue

            entity_links.append(
                {
                    "id": str(row.id),
                    "account_id": str(row.account_id),
                    "entity_id": str(row.entity_id),
                    "match_method": _enum_value(row.match_method),
                    "verification_state": _enum_value(row.verification_state),
                    "confidence": _money(row.confidence),
                    "valid_from": ensure_utc(row.valid_from),
                    "valid_to": ensure_utc(row.valid_to),
                }
            )

    entity_stmt = select(Entity)

    if entity_ids:
        entity_stmt = entity_stmt.where(Entity.id.in_(entity_ids))

    entity_stmt = entity_stmt.order_by(Entity.id).limit(max_entities + 1)
    entity_rows = list(db.execute(entity_stmt).scalars())
    truncated["entities"] = len(entity_rows) > max_entities
    entity_rows = entity_rows[:max_entities]

    entities = [
        {
            "id": str(row.id),
            "entity_type": _enum_value(row.entity_type),
        }
        for row in entity_rows
    ]

    bundle = DatasetBundle(
        as_of=observation_time,
        accounts=accounts,
        transactions=transactions,
        complaints=complaints,
        entities=entities,
        entity_links=entity_links,
        truncated=truncated,
    )

    logger.info(
        "Built point-in-time dataset as_of=%s counts=%s truncated=%s",
        observation_time.isoformat(),
        bundle.counts(),
        {k: v for k, v in truncated.items() if v},
    )
    return bundle


def _lookback_delta(days: int) -> Any:
    """
    Return the lookback window, bounded by the windows policy.
    """
    from datetime import timedelta

    try:
        limits = get_windows_policy().get("limits") or {}
        cap = int(limits.get("max_lookback_days") or 730)
    except Exception:
        cap = 730

    return timedelta(days=max(1, min(int(days), cap)))


def compute_features(
    db: Session,
    *,
    as_of: Optional[datetime] = None,
    account_ids: Optional[Sequence[str]] = None,
    settings: Any = None,
    dataset: Optional[DatasetBundle] = None,
) -> tuple[Any, DatasetBundle]:
    """
    Build feature vectors for the requested accounts.

    Returns `(FeatureBuildResult, DatasetBundle)`.

    Raises FeatureComputationError when the ML feature package is unavailable,
    or when a non-empty dataset produced no vectors — the latter is almost
    always an integration mismatch rather than a legitimately empty result, and
    silently returning nothing would hide it.
    """
    observation_time = ensure_utc(as_of) or utcnow()
    bundle = dataset or build_dataset(
        db, as_of=observation_time, account_ids=account_ids
    )

    try:
        from app.ml.features import FeatureBuildOptions, build_feature_vectors
    except Exception as exc:  # pragma: no cover - depends on optional ML deps
        raise FeatureComputationError(
            "Feature construction is unavailable because the ML feature "
            "package could not be imported.",
            details={"error_type": type(exc).__name__},
        ) from exc

    try:
        options = FeatureBuildOptions.from_settings(settings)
    except Exception:
        options = FeatureBuildOptions()

    target_ids = (
        [str(a) for a in account_ids]
        if account_ids is not None
        else [entry["id"] for entry in bundle.accounts]
    )

    result = build_feature_vectors(
        bundle,
        target_ids,
        options=options,
        observation_time=observation_time,
    )

    vectors = list(getattr(result, "vectors", []) or [])

    if bundle.accounts and bundle.transactions and not vectors:
        # Both known silent-failure modes (ORM objects instead of mappings,
        # enum members instead of .value) land exactly here.
        raise FeatureComputationError(
            "Feature construction returned no vectors for a non-empty "
            "dataset. This indicates a dataset/builder contract mismatch "
            "rather than an empty result.",
            details={
                "counts": bundle.counts(),
                "requested_accounts": len(target_ids),
                "issues": [
                    getattr(issue, "code", str(issue))
                    for issue in list(getattr(result, "issues", []) or [])[:10]
                ],
            },
        )

    logger.info(
        "Computed %d feature vector(s) as_of=%s",
        len(vectors),
        observation_time.isoformat(),
    )
    return result, bundle


def persist_feature_snapshots(
    db: Session,
    *,
    result: Any,
    bundle: DatasetBundle,
    as_of: Optional[datetime] = None,
    feature_version: str = DEFAULT_FEATURE_VERSION,
    window_label: Optional[str] = None,
) -> dict[str, FeatureSnapshot]:
    """
    Persist feature vectors as `FeatureSnapshot` rows.

    Returns a mapping of account_id to the persisted snapshot.

    `(account_id, as_of, feature_version)` is unique, so a re-run for the same
    instant updates the existing row rather than inserting a duplicate. That
    keeps a replay idempotent while preserving history across different
    `as_of` values.
    """
    observation_time = ensure_utc(as_of) or ensure_utc(bundle.as_of) or utcnow()
    fingerprint = bundle.fingerprint()
    vectors = list(getattr(result, "vectors", []) or [])

    if not vectors:
        return {}

    account_ids = [
        _vector_account_id(vector) for vector in vectors
    ]
    known = {
        str(row.account_id): row
        for row in db.execute(
            select(FeatureSnapshot)
            .where(FeatureSnapshot.as_of == observation_time)
            .where(FeatureSnapshot.feature_version == feature_version)
            .where(
                FeatureSnapshot.account_id.in_(
                    [a for a in account_ids if a]
                )
            )
        ).scalars()
    }

    out: dict[str, FeatureSnapshot] = {}
    primary_window = window_label or str(
        (get_windows_policy().get("primary_window") or "30d")
    )

    for vector in vectors:
        account_id = _vector_account_id(vector)

        if not account_id:
            continue

        values = _vector_features(vector)

        if not values:
            continue

        metadata = {
            "feature_service_version": FEATURES_SERVICE_VERSION,
            "dataset_counts": bundle.counts(),
            "dataset_truncated": {k: v for k, v in bundle.truncated.items() if v},
            "vector_metadata": sanitize_json(
                getattr(vector, "metadata", None) or {}, max_items=50
            ),
        }

        existing = known.get(account_id)

        if existing is not None:
            existing.values_json = sanitize_json(values, max_items=500)
            existing.dataset_fingerprint = fingerprint
            existing.window = primary_window
            existing.metadata_json = metadata
            out[account_id] = existing
            continue

        snapshot = FeatureSnapshot(
            account_id=account_id,
            as_of=observation_time,
            feature_version=feature_version,
            window=primary_window,
            values_json=sanitize_json(values, max_items=500),
            dataset_fingerprint=fingerprint,
            metadata_json=metadata,
        )
        db.add(snapshot)
        out[account_id] = snapshot

    db.flush()
    logger.info("Persisted %d feature snapshot(s)", len(out))
    return out


def _vector_account_id(vector: Any) -> Optional[str]:
    """
    Extract the account identifier a feature vector belongs to.

    The builder may carry it as metadata rather than as the pseudonymous
    `subject_ref_hash`, which is a hash and cannot be used as a foreign key.
    """
    # The explicit field first. `app/ml/features.py` sets it from the real
    # account id; everything below is a fallback for vectors built elsewhere
    # (tests, tooling, older callers) that only carry it as metadata.
    explicit = getattr(vector, "subject_id", None)

    if explicit:
        return str(explicit)

    metadata = getattr(vector, "metadata", None) or {}

    for key in ("account_id", "subject_id", "subject"):
        candidate = metadata.get(key) if isinstance(metadata, Mapping) else None

        if candidate:
            return str(candidate)

    features = _vector_features(vector)

    for key in ("account_id", "subject_id"):
        if features.get(key):
            return str(features[key])

    direct = getattr(vector, "account_id", None)
    return str(direct) if direct else None


def _vector_features(vector: Any) -> dict[str, Any]:
    """
    Extract the feature mapping from a feature vector.
    """
    features = getattr(vector, "features", None)

    if isinstance(features, Mapping):
        return dict(features)

    if isinstance(vector, Mapping):
        inner = vector.get("features")
        return dict(inner) if isinstance(inner, Mapping) else dict(vector)

    return {}


def latest_snapshot_for_account(
    db: Session,
    account_id: str,
    *,
    feature_version: Optional[str] = None,
    as_of: Optional[datetime] = None,
) -> Optional[FeatureSnapshot]:
    """
    Return the most recent feature snapshot at or before `as_of`.
    """
    stmt = select(FeatureSnapshot).where(FeatureSnapshot.account_id == str(account_id))

    if feature_version:
        stmt = stmt.where(FeatureSnapshot.feature_version == str(feature_version))

    bound = ensure_utc(as_of)

    if bound is not None:
        stmt = stmt.where(FeatureSnapshot.as_of <= bound)

    stmt = stmt.order_by(FeatureSnapshot.as_of.desc()).limit(1)
    return db.execute(stmt).scalars().first()


def feature_values_for_account(
    db: Session,
    account_id: str,
    *,
    feature_version: Optional[str] = None,
    as_of: Optional[datetime] = None,
) -> dict[str, Any]:
    """
    Return the stored feature values for an account, or an empty mapping.
    """
    snapshot = latest_snapshot_for_account(
        db, account_id, feature_version=feature_version, as_of=as_of
    )

    if snapshot is None or not isinstance(snapshot.values_json, Mapping):
        return {}

    return dict(snapshot.values_json)


def get_features_service_metadata() -> dict[str, Any]:
    """
    Return safe metadata describing the feature service.
    """
    return {
        "service": "muleguard.backend.services.features",
        "version": FEATURES_SERVICE_VERSION,
        "feature_version": DEFAULT_FEATURE_VERSION,
        "limits": {
            "max_accounts": _DEFAULT_MAX_ACCOUNTS,
            "max_transactions": _DEFAULT_MAX_TRANSACTIONS,
            "max_complaints": _DEFAULT_MAX_COMPLAINTS,
            "max_entities": _DEFAULT_MAX_ENTITIES,
            "max_links": _DEFAULT_MAX_LINKS,
            "default_lookback_days": _DEFAULT_LOOKBACK_DAYS,
        },
        "point_in_time_guarantees": [
            "Every query is bounded strictly before as_of.",
            "Only COMPLETED transactions count as fund movement.",
            "Entity links are filtered by valid_from < as_of.",
            "Ground-truth labels are never read by this service.",
        ],
        "notes": [
            "Records are emitted as primitive mappings with enum .value strings, "
            "which the feature builder's alias table requires.",
            "A non-empty dataset that yields no vectors raises rather than "
            "returning an empty result.",
        ],
    }
