"""
The case state machine, tested directly.

`app/services/case_state_machine.py` holds the transition table. It is tested
on its own, without a database or a client, because it is a pure function of
(current state, target state, what was supplied) and because a state machine
is the one place where an exhaustive test is both cheap and genuinely
worthwhile.

The transition table, written out so a reader does not have to go and look:

    NEW                  → TRIAGED             (triage)
    NEW                  → UNDER_INVESTIGATION (start,    needs an assignee)
    NEW                  → CLOSED              (close,    needs a disposition)
    TRIAGED              → UNDER_INVESTIGATION (start,    needs an assignee)
    TRIAGED              → ESCALATED           (escalate, needs a reason)
    TRIAGED              → CLOSED              (close,    needs a disposition)
    UNDER_INVESTIGATION  → ESCALATED           (escalate, needs a reason)
    UNDER_INVESTIGATION  → CLOSED              (close,    needs a disposition)
    ESCALATED            → UNDER_INVESTIGATION (de_escalate, needs a reason)
    ESCALATED            → CLOSED              (close,    needs a disposition)
    CLOSED               → UNDER_INVESTIGATION (reopen)

Three things that table encodes are worth stating in words.

**Starting work needs an assignee.** A case in UNDER_INVESTIGATION that nobody
owns is the state a case goes to die in: it looks active in every count and
nobody is looking at it.

**Closing needs a disposition.** A closed case with no stated outcome is the
single most expensive omission in the workflow. The disposition —
`CONFIRMED_FRAUD`, `FALSE_POSITIVE`, `INCONCLUSIVE`, `REFERRED` — is what
every quality measurement afterwards depends on, and it cannot be
reconstructed later.

**CLOSED is not terminal.** It reopens to UNDER_INVESTIGATION, because new
information arrives. What it does *not* do is reopen to NEW: the work already
done is part of the case's history, and sending it back to the top of the
funnel would discard that.
"""

from __future__ import annotations

import pytest

# Imported from the vocabulary module rather than from `app.models`: the
# state machine is a pure function of (current, target, what was supplied),
# so this module runs without a database driver installed.
from app.core.vocabularies import CaseStatus
from app.services.case_state_machine import (
    allowed_transitions,
    describe_state_machine,
    is_terminal,
    requires_disposition,
    transition_action,
    validate_transition,
)

pytestmark = pytest.mark.cases


#: Every legal transition: (source, target, action).
LEGAL = [
    (CaseStatus.NEW, CaseStatus.TRIAGED, "triage"),
    (CaseStatus.NEW, CaseStatus.UNDER_INVESTIGATION, "start"),
    (CaseStatus.NEW, CaseStatus.CLOSED, "close"),
    (CaseStatus.TRIAGED, CaseStatus.UNDER_INVESTIGATION, "start"),
    (CaseStatus.TRIAGED, CaseStatus.ESCALATED, "escalate"),
    (CaseStatus.TRIAGED, CaseStatus.CLOSED, "close"),
    (CaseStatus.UNDER_INVESTIGATION, CaseStatus.ESCALATED, "escalate"),
    (CaseStatus.UNDER_INVESTIGATION, CaseStatus.CLOSED, "close"),
    (CaseStatus.ESCALATED, CaseStatus.UNDER_INVESTIGATION, "de_escalate"),
    (CaseStatus.ESCALATED, CaseStatus.CLOSED, "close"),
    (CaseStatus.CLOSED, CaseStatus.UNDER_INVESTIGATION, "reopen"),
]

LEGAL_PAIRS = {(source, target) for source, target, _ in LEGAL}

ALL_PAIRS = [
    (source, target)
    for source in CaseStatus
    for target in CaseStatus
    if source is not target
]


def _targets(status) -> set:
    """
    The statuses reachable from `status`.

    `allowed_transitions` returns `TransitionRule` objects, not statuses,
    so the target has to be read off each rule. Comparing a `CaseStatus`
    against the rules directly is always false, which would make every
    assertion below pass or fail for the wrong reason.
    """
    return {rule.target for rule in allowed_transitions(status)}


def _ok(current, target, **kwargs) -> bool:
    """
    Whether a transition is permitted.

    `validate_transition` returns the matching `TransitionRule` and raises
    `ValueError` with an analyst-readable message when the transition is
    illegal or a precondition is unmet — the case service turns that into an
    `InvalidCaseTransitionError`. Collapsing it to a boolean keeps the tests
    below readable; `test_a_refusal_explains_itself` checks the message.
    """
    try:
        validate_transition(current=current, target=target, **kwargs)
    except ValueError:
        return False

    return True


# -----------------------------------------------------------------------------
# The table
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("source,target,action", LEGAL, ids=lambda value: str(value))
def test_each_legal_transition_names_its_action(source, target, action):
    """
    The action name is part of the contract.

    It is what the audit trail records and what the interface's button says.
    A transition whose action is `None` produces an event nobody can read.
    """
    assert transition_action(source, target) == action


@pytest.mark.parametrize("source,target", ALL_PAIRS)
def test_only_the_declared_transitions_are_permitted(source, target):
    """
    Exhaustive over every ordered pair of states.

    Twenty of the twenty-five possible pairs must be refused, and this is the
    cheapest possible way to be sure none of them has been quietly allowed.
    `allowed_transitions` is the authority; it is compared against the table
    written out at the top of this module, which is an independent statement
    of the same thing.
    """
    permitted = target in _targets(source)
    expected = (source, target) in LEGAL_PAIRS

    assert permitted is expected, (
        f"{source.value} → {target.value}: "
        f"{'allowed' if permitted else 'refused'}, expected the opposite"
    )


def test_no_state_transitions_to_itself():
    """
    A transition to the current state is a no-op, not a transition.

    Allowing it would put a second "escalated" event in the history of a case
    that was already escalated, which is how a timeline stops being readable.
    """
    for status in CaseStatus:
        assert status not in _targets(status)


def test_every_state_can_be_closed():
    """
    There is always a way out.

    A state with no transition to CLOSED is a state a case can get stuck in,
    and the only remedy is a database edit.
    """
    for status in CaseStatus:
        if status is CaseStatus.CLOSED:
            continue
        assert CaseStatus.CLOSED in _targets(status), status


def test_closed_is_the_only_terminal_state():
    assert is_terminal(CaseStatus.CLOSED) is True

    for status in CaseStatus:
        if status is CaseStatus.CLOSED:
            continue
        assert is_terminal(status) is False, status


def test_closed_reopens_to_under_investigation_not_to_new():
    """
    Reopening resumes, it does not restart.

    The evidence, the notes and the timeline are all still there. Sending the
    case back to NEW would present work already done as work not yet begun,
    and whoever picked it up would start again.
    """
    targets = _targets(CaseStatus.CLOSED)

    assert targets == {CaseStatus.UNDER_INVESTIGATION}
    assert CaseStatus.NEW not in targets
    assert transition_action(CaseStatus.CLOSED, CaseStatus.UNDER_INVESTIGATION) == "reopen"


def test_escalated_can_be_de_escalated():
    """
    Escalation is reversible, and reversing it is its own action.

    A senior investigator who looks and decides it was not warranted needs to
    hand it back. Recording that as `de_escalate` rather than as a plain
    status change is what makes the round trip legible afterwards.
    """
    assert transition_action(CaseStatus.ESCALATED, CaseStatus.UNDER_INVESTIGATION) == (
        "de_escalate"
    )


# -----------------------------------------------------------------------------
# What each transition requires
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        CaseStatus.NEW,
        CaseStatus.TRIAGED,
        CaseStatus.UNDER_INVESTIGATION,
        CaseStatus.ESCALATED,
    ],
)
def test_closing_always_requires_a_disposition(source):
    """
    From every state, closing needs an outcome.

    This is the requirement that makes the workflow worth having. Without a
    disposition nobody can answer "how many of last month's alerts were real",
    which is the question that decides whether the detector is tuned or
    guessed at — and it cannot be answered retrospectively.
    """
    assert requires_disposition(source, CaseStatus.CLOSED) is True

    assert _ok(source, CaseStatus.CLOSED, disposition=None) is False
    assert _ok(source, CaseStatus.CLOSED, disposition="FALSE_POSITIVE") is True


def test_starting_work_requires_an_assignee():
    """
    No unowned investigations.

    A case in UNDER_INVESTIGATION with no assignee counts as active work on
    every dashboard and is nobody's job. The assignee is the whole difference
    between a case being investigated and a case being open.
    """
    assert _ok(CaseStatus.NEW, CaseStatus.UNDER_INVESTIGATION, assignee_id=None) is False
    assert (
        _ok(CaseStatus.NEW, CaseStatus.UNDER_INVESTIGATION, assignee_id="usr_analyst")
        is True
    )

    assert (
        _ok(CaseStatus.TRIAGED, CaseStatus.UNDER_INVESTIGATION, assignee_id=None) is False
    )


def test_escalating_requires_a_reason():
    """
    Escalation spends someone else's attention, so it has to be justified.

    An escalation with no stated reason arrives on a senior investigator's
    queue as a case and a shrug.
    """
    assert _ok(CaseStatus.TRIAGED, CaseStatus.ESCALATED, reason=None) is False
    assert (
        _ok(
            CaseStatus.TRIAGED,
            CaseStatus.ESCALATED,
            reason="Three complaints name this account directly.",
        )
        is True
    )


def test_de_escalating_requires_a_reason():
    assert (
        _ok(CaseStatus.ESCALATED, CaseStatus.UNDER_INVESTIGATION, reason=None) is False
    )
    assert (
        _ok(
            CaseStatus.ESCALATED,
            CaseStatus.UNDER_INVESTIGATION,
            reason="Inbound spread is a merchant pattern; returning for routine review.",
        )
        is True
    )


def test_triage_requires_nothing_extra():
    """
    The cheap transition is cheap.

    Moving a case from NEW to TRIAGED is somebody saying "I have looked at
    this enough to know it belongs in the queue". Demanding a reason for that
    would mean nobody triages anything.
    """
    assert _ok(CaseStatus.NEW, CaseStatus.TRIAGED) is True


def test_reopening_requires_a_reason_but_not_a_disposition():
    """
    Reopening clears the outcome rather than asking for a new one.

    Requiring a disposition to reopen would be asking for the conclusion
    before the work. A reason *is* required: the previous disposition is
    preserved in history rather than erased, so something has to explain the
    discrepancy to whoever reads the timeline afterwards.
    """
    assert requires_disposition(CaseStatus.CLOSED, CaseStatus.UNDER_INVESTIGATION) is False

    assert _ok(CaseStatus.CLOSED, CaseStatus.UNDER_INVESTIGATION) is False
    assert (
        _ok(
            CaseStatus.CLOSED,
            CaseStatus.UNDER_INVESTIGATION,
            reason="A fourth complaint names this account.",
        )
        is True
    )


def test_a_refusal_explains_itself():
    """
    The message says what was wrong, in words an analyst can act on.

    It becomes the body of an `InvalidCaseTransitionError`, which is what
    somebody reads when a button does not work. "Invalid transition" sends
    them to ask an engineer.
    """
    with pytest.raises(ValueError) as closing_without_disposition:
        validate_transition(
            current=CaseStatus.UNDER_INVESTIGATION,
            target=CaseStatus.CLOSED,
            disposition=None,
        )

    assert "disposition" in str(closing_without_disposition.value).lower()

    with pytest.raises(ValueError) as starting_without_assignee:
        validate_transition(
            current=CaseStatus.NEW,
            target=CaseStatus.UNDER_INVESTIGATION,
            assignee_id=None,
        )

    # "assigned owner", not "assignee": the message is for an investigator,
    # not for whoever named the column.
    assert "assigned" in str(starting_without_assignee.value).lower()

    with pytest.raises(ValueError) as escalating_without_reason:
        validate_transition(
            current=CaseStatus.TRIAGED,
            target=CaseStatus.ESCALATED,
            reason=None,
        )

    assert "reason" in str(escalating_without_reason.value).lower()


def test_transitioning_to_the_current_state_is_refused_as_unnecessary():
    """
    "Already triaged" rather than "invalid transition".

    The two are different for the person reading the message: one says they
    have nothing to do, the other says something is broken.
    """
    with pytest.raises(ValueError) as same_state:
        validate_transition(current=CaseStatus.TRIAGED, target=CaseStatus.TRIAGED)

    assert "already" in str(same_state.value).lower()


def test_an_unknown_status_is_refused_by_name():
    with pytest.raises(ValueError) as unknown:
        validate_transition(current="NOT_A_STATUS", target=CaseStatus.CLOSED)

    assert "status" in str(unknown.value).lower()


def test_an_illegal_transition_is_refused_whatever_is_supplied():
    """
    Supplying every field does not unlock a transition that does not exist.

    The requirements are additional conditions on a legal transition, never a
    way to make an illegal one legal.
    """
    assert (
        _ok(
            CaseStatus.CLOSED,
            CaseStatus.TRIAGED,
            disposition="FALSE_POSITIVE",
            assignee_id="usr_analyst",
            reason="trying everything",
        )
        is False
    )


# -----------------------------------------------------------------------------
# Self-description
# -----------------------------------------------------------------------------


def test_the_state_machine_can_describe_itself():
    """
    The table is introspectable.

    The interface uses it to decide which buttons to offer, which is the only
    way the available actions stay in step with the server's rules. A
    hard-coded button list drifts, and the symptom is a button that always
    errors.
    """
    description = describe_state_machine()

    assert description

    serialised = str(description)
    for status in CaseStatus:
        assert status.value in serialised, f"{status.value} is not described"


def test_the_description_states_the_requirements():
    """
    Not just which transitions exist, but what each one needs.

    The interface needs this to know whether to open a dialog asking for a
    disposition, rather than letting someone press Close and receive a 422.
    """
    serialised = str(describe_state_machine())

    assert "disposition" in serialised
    assert "assignee" in serialised or "assignee_id" in serialised
    assert "reason" in serialised


def test_the_described_transitions_match_the_table():
    """
    The self-description and `allowed_transitions` agree.

    Two code paths read the same table; if they disagree, the interface offers
    actions the server refuses.
    """
    description = describe_state_machine()
    serialised = str(description)

    for source, target, action in LEGAL:
        assert action in serialised, f"{action} is missing from the description"
        assert target in _targets(source)
