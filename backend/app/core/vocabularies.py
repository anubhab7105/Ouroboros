"""
MULEGUARD backend persisted vocabularies.

This module owns the enumerations that describe ingested records: what kind of
account an account is, what state a transfer reached, which rail it used, what
kind of pseudonymous entity an entity is, and how and how firmly an
account-entity link was established.

Why these live here rather than in `app/models.py`
--------------------------------------------------

They are the vocabulary of the data, and four layers need them:

- `app.models` declares the columns over them, so they are what the database
  will accept;
- `app.ingestion.normalizers` and `app.ingestion.validators` decide what the
  API will accept, which has to be the same set;
- `app.ingestion.generator` produces synthetic records, which have to be
  ingestible;
- `app.ml.feature_schema` and `app.ml.features` one-hot encode them, which
  requires knowing every value a column can hold.

Each of those layers previously carried its own hand-written copy, and the
copies had drifted apart on every single field. The account type is the
clearest illustration: the database accepted INDIVIDUAL, BUSINESS, MERCHANT
and OTHER; ingestion accepted SAVINGS, CURRENT, WALLET, UPI, CARD and OTHER;
the generator emitted the second set; and the feature builder one-hot encoded
the second set too. The three disagreeing layers shared exactly one value with
the database, so a correct record was rejected by validation, a generated
record was rejected by the database, and the account-type feature was constant
in every vector ever built. None of it raised an error that named the cause.

Keeping the definitions in one dependency-light module fixes that by
construction. There is one place to add a value, and nothing to keep in step.

This module deliberately imports nothing beyond the standard library. The ML
and ingestion layers are usable offline — against fixtures, in a script, in a
notebook — without SQLAlchemy installed, and they would lose that if the
vocabulary arrived through the ORM.

Product-safety notice
---------------------

These are observational labels. An account status of REVIEW_REQUIRED means
somebody should look at the account; it does not freeze, block, blacklist,
close or restrict anything, and there is deliberately no value here for an
enforcement action MULEGUARD does not take.
"""

from __future__ import annotations

from enum import Enum as PyEnum
from typing import Final


__all__ = [
    "VOCABULARIES_VERSION",
    "AccountStatus",
    "AccountType",
    "CaseStatus",
    "Channel",
    "Disposition",
    "EntityType",
    "MatchMethod",
    "TransactionStatus",
    "VerificationState",
    "enum_values",
]


VOCABULARIES_VERSION: Final[str] = "v1"


class AccountType(str, PyEnum):
    """
    What kind of party holds the account.

    This classifies the *holder*, not the banking product. A savings account
    and a current account held by the same person are both INDIVIDUAL, and
    there is no value here for a product type: mapping one onto the other
    would record a claim about the account holder that the source never made.
    """

    INDIVIDUAL = "INDIVIDUAL"
    BUSINESS = "BUSINESS"
    MERCHANT = "MERCHANT"
    OTHER = "OTHER"


class AccountStatus(str, PyEnum):
    """
    The account's observed state.

    REVIEW_REQUIRED is the strongest value, and it means exactly that
    somebody should look. There is no suspended, blocked or restricted value,
    because MULEGUARD does not take those actions and has no business
    recording somebody else's decision to take one as its own.
    """

    ACTIVE = "ACTIVE"
    DORMANT = "DORMANT"
    CLOSED = "CLOSED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class TransactionStatus(str, PyEnum):
    """
    How far a transfer got.

    Only COMPLETED is settled fund movement, and every monetary aggregate in
    the platform counts COMPLETED alone. The distinction matters more than it
    looks: a pass-through pattern measured over pending and failed transfers
    would describe money that never moved.
    """

    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REVERSED = "REVERSED"


class Channel(str, PyEnum):
    """
    The rail the transfer used.
    """

    UPI = "UPI"
    IMPS = "IMPS"
    NEFT = "NEFT"
    RTGS = "RTGS"
    CARD = "CARD"
    INTERNAL = "INTERNAL"


class EntityType(str, PyEnum):
    """
    What kind of shared identifier an entity represents.

    The `_HASH` suffixes are the design, not a naming habit: a phone number, an
    email address, a postal address and an IP reach the entity table as salted
    hashes and the raw values are never stored. DEVICE and UPI_ID are already
    opaque tokens rather than personal data, which is why they carry no
    suffix. There is no NAME or card-number type, because there is nowhere
    safe to put one.
    """

    DEVICE = "DEVICE"
    PHONE_HASH = "PHONE_HASH"
    UPI_ID = "UPI_ID"
    EMAIL_HASH = "EMAIL_HASH"
    ADDRESS_HASH = "ADDRESS_HASH"
    IP_HASH = "IP_HASH"
    OTHER = "OTHER"


class MatchMethod(str, PyEnum):
    """
    How an association was established.

    The ordering from EXACT down to UNKNOWN is roughly decreasing strength,
    and the distinction between the deterministic methods and the inferred
    ones is what the review workflow turns on: an exact match on a shared
    device hash is an observation, while a narrative extraction is a guess
    that a person should confirm.
    """

    EXACT = "EXACT"
    NORMALIZED = "NORMALIZED"
    ENTITY_TEMPORAL = "ENTITY_TEMPORAL"
    GRAPH_TEMPORAL = "GRAPH_TEMPORAL"
    NARRATIVE_EXTRACTION = "NARRATIVE_EXTRACTION"
    MANUAL = "MANUAL"
    UNKNOWN = "UNKNOWN"


class VerificationState(str, PyEnum):
    """
    Whether a person has confirmed an inferred association.

    NEEDS_REVIEW is not a weaker UNVERIFIED: it means the link is waiting on
    somebody, which includes a link whose earlier verification has lapsed.
    Collapsing the two would lose the fact that it was once verified.
    """

    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class CaseStatus(str, PyEnum):
    """
    Where an investigation case has got to.

    TRIAGED earns its place between NEW and UNDER_INVESTIGATION: a case with
    an owner who has not started is not the same as one being worked, and
    collapsing the two hides the queue that actually needs attention.

    CLOSED is not terminal — new information arrives and a case reopens to
    UNDER_INVESTIGATION. What it does not do is reopen to NEW, which would
    discard the work already recorded against it.

    `app.services.case_state_machine` owns which moves between these are
    legal and what each one requires; this is only the set of states.
    """

    NEW = "NEW"
    TRIAGED = "TRIAGED"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"


class Disposition(str, PyEnum):
    """
    How an investigation concluded.

    Required to close a case, and the single most consequential field in the
    workflow: every later measurement of how well detection is working reads
    it, and it cannot be reconstructed afterwards from the closure note. A
    case closed without one is indistinguishable from a case nobody concluded.

    INCONCLUSIVE is a real answer and belongs here. Without it, a reviewer
    with genuinely insufficient evidence has to pick between confirming fraud
    and clearing the account, and both are wrong.
    """

    CONFIRMED_FRAUD = "CONFIRMED_FRAUD"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    REFERRED = "REFERRED"


def enum_values(enum_cls: type[PyEnum]) -> tuple[str, ...]:
    """
    Return one enumeration's values in declaration order.

    Declaration order rather than sorted, because the one-hot encoders in
    `app.ml` use the position of a value as its column index, and a feature
    vector whose columns silently reorder is a model that reads the wrong
    number out of every row.
    """
    return tuple(str(member.value) for member in enum_cls)
