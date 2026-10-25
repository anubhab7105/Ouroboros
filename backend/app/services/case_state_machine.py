"""
MULEGUARD case state machine.

Defines the legal transitions of an investigation case and the preconditions
each one carries. The transition table lives here, separate from the case
service, so the workflow can be read, tested, and documented on its own.

The states:

    NEW -> TRIAGED -> UNDER_INVESTIGATION -> CLOSED
                   \\-> ESCALATED ----------/
    CLOSED -> UNDER_INVESTIGATION (reopen)

Rules that matter:

- **Closing requires a disposition.** Enforced here and by the
  `ck_cases_closed_requires_disposition` CHECK constraint. Two layers on
  purpose: the database guarantees no closed case ever lacks one, and this
  layer produces a readable error instead of an integrity violation.
- **Reopening is a transition, not an edit.** A reopened case returns to
  UNDER_INVESTIGATION and keeps its prior disposition in history. Erasing the
  earlier decision would destroy the audit trail that makes a case defensible.
- **Every transition appends a CaseEvent.** Case history is append-only.
- **Nothing here is automatic.** Transitions are analyst decisions. The
  detection pipeline raises alerts; it never advances a case.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final, Optional

# The vocabulary comes from `app.core.vocabularies`, which imports nothing
# beyond the standard library, so the state machine and its exhaustive
# test run without a database driver installed.
from app.core.vocabularies import CaseStatus, Disposition

__all__ = [
    "CASE_STATE_MACHINE_VERSION",
    "TERMINAL_STATES",
    "TransitionRule",
    "allowed_transitions",
    "describe_state_machine",
    "is_terminal",
    "requires_disposition",
    "transition_action",
    "validate_transition",
]

CASE_STATE_MACHINE_VERSION: Final[str] = "v1"

TERMINAL_STATES: Final[frozenset[CaseStatus]] = frozenset({CaseStatus.CLOSED})


class TransitionRule:
    """
    One legal transition and what it requires.
    """

    __slots__ = (
        "action",
        "clears_disposition",
        "description",
        "requires_assignee",
        "requires_disposition",
        "requires_reason",
        "source",
        "target",
    )

    def __init__(
        self,
        *,
        source: CaseStatus,
        target: CaseStatus,
        action: str,
        description: str,
        requires_disposition: bool = False,
        requires_assignee: bool = False,
        requires_reason: bool = False,
        clears_disposition: bool = False,
    ) -> None:
        self.source = source
        self.target = target
        self.action = action
        self.description = description
        self.requires_disposition = requires_disposition
        self.requires_assignee = requires_assignee
        self.requires_reason = requires_reason
        self.clears_disposition = clears_disposition

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-safe description of this transition.
        """
        return {
            "from": self.source.value,
            "to": self.target.value,
            "action": self.action,
            "description": self.description,
            "requires_disposition": self.requires_disposition,
            "requires_assignee": self.requires_assignee,
            "requires_reason": self.requires_reason,
        }

    def __repr__(self) -> str:
        return f"TransitionRule({self.source.value} -> {self.target.value}, {self.action!r})"


_TRANSITIONS: Final[tuple[TransitionRule, ...]] = (
    TransitionRule(
        source=CaseStatus.NEW,
        target=CaseStatus.TRIAGED,
        action="triage",
        description="An analyst reviewed the case and confirmed it is worth investigating.",
    ),
    TransitionRule(
        source=CaseStatus.NEW,
        target=CaseStatus.CLOSED,
        action="close",
        description="Closed at triage without investigation, typically a false positive.",
        requires_disposition=True,
    ),
    TransitionRule(
        source=CaseStatus.NEW,
        target=CaseStatus.UNDER_INVESTIGATION,
        action="start",
        description="Investigation started directly, skipping a separate triage step.",
        requires_assignee=True,
    ),
    TransitionRule(
        source=CaseStatus.TRIAGED,
        target=CaseStatus.UNDER_INVESTIGATION,
        action="start",
        description="Investigation started. An owner must be assigned first.",
        requires_assignee=True,
    ),
    TransitionRule(
        source=CaseStatus.TRIAGED,
        target=CaseStatus.CLOSED,
        action="close",
        description="Closed after triage without full investigation.",
        requires_disposition=True,
    ),
    TransitionRule(
        source=CaseStatus.TRIAGED,
        target=CaseStatus.ESCALATED,
        action="escalate",
        description="Escalated from triage because it needs senior or external handling.",
        requires_reason=True,
    ),
    TransitionRule(
        source=CaseStatus.UNDER_INVESTIGATION,
        target=CaseStatus.ESCALATED,
        action="escalate",
        description="Escalated during investigation to a senior investigator or an external body.",
        requires_reason=True,
    ),
    TransitionRule(
        source=CaseStatus.UNDER_INVESTIGATION,
        target=CaseStatus.CLOSED,
        action="close",
        description="Investigation concluded with a recorded disposition.",
        requires_disposition=True,
    ),
    TransitionRule(
        source=CaseStatus.ESCALATED,
        target=CaseStatus.UNDER_INVESTIGATION,
        action="de_escalate",
        description="Returned to normal investigation after escalation review.",
        requires_reason=True,
    ),
    TransitionRule(
        source=CaseStatus.ESCALATED,
        target=CaseStatus.CLOSED,
        action="close",
        description="Closed following escalation, with a recorded disposition.",
        requires_disposition=True,
    ),
    TransitionRule(
        source=CaseStatus.CLOSED,
        target=CaseStatus.UNDER_INVESTIGATION,
        action="reopen",
        description=(
            "Reopened because new information arrived. The previous disposition "
            "is preserved in case history rather than erased."
        ),
        requires_reason=True,
        clears_disposition=True,
    ),
)

_BY_PAIR: Final[dict[tuple[CaseStatus, CaseStatus], TransitionRule]] = {
    (rule.source, rule.target): rule for rule in _TRANSITIONS
}


def _coerce_status(value: Any) -> Optional[CaseStatus]:
    """
    Coerce a value into a CaseStatus, or None.
    """
    if isinstance(value, CaseStatus):
        return value

    token = str(getattr(value, "value", value) or "").strip().upper()

    return CaseStatus[token] if token in CaseStatus.__members__ else None


def _coerce_disposition(value: Any) -> Optional[Disposition]:
    """
    Coerce a value into a Disposition, or None.
    """
    if isinstance(value, Disposition):
        return value

    token = str(getattr(value, "value", value) or "").strip().upper()

    return Disposition[token] if token in Disposition.__members__ else None


def is_terminal(status: Any) -> bool:
    """
    Return True when a status is terminal.
    """
    resolved = _coerce_status(status)
    return resolved is not None and resolved in TERMINAL_STATES


def allowed_transitions(status: Any) -> list[TransitionRule]:
    """
    Return the transitions available from a status.
    """
    resolved = _coerce_status(status)

    if resolved is None:
        return []

    return [rule for rule in _TRANSITIONS if rule.source is resolved]


def transition_action(source: Any, target: Any) -> Optional[str]:
    """
    Return the action name for a transition, or None when it is illegal.
    """
    from_status = _coerce_status(source)
    to_status = _coerce_status(target)

    if from_status is None or to_status is None:
        return None

    rule = _BY_PAIR.get((from_status, to_status))
    return rule.action if rule is not None else None


def requires_disposition(source: Any, target: Any) -> bool:
    """
    Return True when a transition needs a disposition.
    """
    from_status = _coerce_status(source)
    to_status = _coerce_status(target)

    if from_status is None or to_status is None:
        return False

    rule = _BY_PAIR.get((from_status, to_status))
    return bool(rule is not None and rule.requires_disposition)


def validate_transition(
    *,
    current: Any,
    target: Any,
    disposition: Any = None,
    assignee_id: Optional[str] = None,
    reason: Optional[str] = None,
) -> TransitionRule:
    """
    Validate a requested transition and return its rule.

    Raises ValueError with an analyst-readable message when the transition is
    illegal or its preconditions are unmet. The case service translates that
    into an `InvalidCaseTransitionError`.
    """
    from_status = _coerce_status(current)
    to_status = _coerce_status(target)

    if from_status is None:
        raise ValueError(f"Unknown current case status: {current!r}")

    if to_status is None:
        raise ValueError(f"Unknown target case status: {target!r}")

    if from_status is to_status:
        raise ValueError(
            f"Case is already {from_status.value}; no transition is needed."
        )

    rule = _BY_PAIR.get((from_status, to_status))

    if rule is None:
        options = sorted(r.target.value for r in allowed_transitions(from_status))
        raise ValueError(
            f"Cannot move a case from {from_status.value} to {to_status.value}. "
            f"Allowed from {from_status.value}: {', '.join(options) or 'none'}."
        )

    if rule.requires_disposition:
        resolved = _coerce_disposition(disposition)

        if resolved is None:
            raise ValueError(
                "Closing a case requires a disposition "
                f"({', '.join(item.value for item in Disposition)}). A closed "
                "case without one would also violate the database constraint."
            )

    if rule.requires_assignee and not str(assignee_id or "").strip():
        raise ValueError(
            "Starting an investigation requires an assigned owner, so the case "
            "does not sit in progress with nobody accountable for it."
        )

    if rule.requires_reason and not str(reason or "").strip():
        raise ValueError(
            f"The '{rule.action}' transition requires a reason, which is "
            "recorded in case history."
        )

    return rule


def describe_state_machine() -> dict[str, Any]:
    """
    Return the full transition table.

    Served to the frontend so the UI can offer exactly the legal transitions
    rather than hard-coding its own copy of the workflow and drifting from it.
    """
    return {
        "version": CASE_STATE_MACHINE_VERSION,
        "states": [item.value for item in CaseStatus],
        "terminal_states": sorted(item.value for item in TERMINAL_STATES),
        "dispositions": [item.value for item in Disposition],
        "transitions": [rule.to_dict() for rule in _TRANSITIONS],
        "by_state": {
            status.value: [rule.to_dict() for rule in allowed_transitions(status)]
            for status in CaseStatus
        },
        "rules": [
            "Closing a case requires a disposition.",
            "Starting an investigation requires an assignee.",
            "Escalating, de-escalating, and reopening require a reason.",
            "Reopening preserves the previous disposition in case history.",
            "Every transition appends an append-only CaseEvent.",
            "No transition is ever performed automatically by the detection "
            "pipeline; all are analyst decisions.",
        ],
    }
