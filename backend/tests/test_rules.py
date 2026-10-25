"""
The rule engine and the built-in rule packs.

Rules are the explainable backbone of the score — they carry the largest
single fusion weight precisely because an analyst can always read why one
fired. So the tests here are as much about the *reasons* as about the
decisions.

Three properties get the most attention.

**A record with no usable signals is reported as unavailable, not as
low-risk.** The engine returns `score=None` and a band of `unavailable`.
Scoring it zero would be a claim about an account nothing could be computed
for, and it would sort alongside genuinely quiet accounts.

**Label-shaped fields are rejected as rule inputs.** A rule conditioned on
`ground_truth` or `scenario_id` would be reading the generator's answer sheet.

**Rules never express an adverse action.** A rule's effect is at most
`escalate_to_human`. There is no freeze, block or blacklist effect to reach
for, and `AutomaticEnforcementProhibitedError` exists so that adding one has
to be deliberate.
"""

from __future__ import annotations

import pytest

from app.rules import definitions as rule_definitions
from app.rules import engine as rule_engine

pytestmark = pytest.mark.rules


# A record that trips essentially everything, and its quiet twin.
#
# The feature names are the rule conditions' own, read from the exported
# definitions. `account_id` is the subject key: the engine looks for one of
# `subject_ref_hash`, `subject_hash`, `subject`, `account_id`, `acct_id` or
# `id`, hashes it with a salt, and returns only the hash. A record with none
# of those keys gets no subject hash at all.
LOUD = {
    "account_id": "acc-loud",
    "txn_count_24h": 40,
    "velocity_burstiness": 4.0,
    "counterparty_concentration": 0.95,
    "beneficiary_entropy": 0.1,
    "device_cluster_degree": 12,
    "ip_subnet_share": 0.95,
    "complaint_correlation_count": 5,
    "historical_case_link_degree": 3,
}

QUIET = {
    "account_id": "acc-quiet",
    "txn_count_24h": 3,
    "velocity_burstiness": 0.2,
    "counterparty_concentration": 0.1,
    "beneficiary_entropy": 0.9,
    "device_cluster_degree": 1,
    "ip_subnet_share": 0.05,
    "complaint_correlation_count": 0,
    "historical_case_link_degree": 0,
}


@pytest.fixture(autouse=True)
def registered_packs():
    """
    The built-in packs, registered into a clean registry for each test.

    The registry is process-local and shared, so a test that registered on top
    of a previous test's state would be measuring the leftovers. Cleared
    before and after.
    """
    registry = rule_engine.get_rule_registry()
    registry.clear()

    report = rule_definitions.register_builtin_rule_packs(registry=registry)

    yield report

    registry.clear()


def _evaluate(records, **kwargs):
    request = rule_engine.RuleEvaluationRequest(records=list(records), **kwargs)
    return rule_engine.evaluate_rules(request)


# -----------------------------------------------------------------------------
# Registration
# -----------------------------------------------------------------------------


def test_the_builtin_packs_register_cleanly(registered_packs):
    payload = registered_packs.to_dict()

    assert payload["ok"] is True
    assert payload["registered_count"] >= 1
    assert payload["failed_count"] == 0
    assert payload["rule_ids"]


def test_registration_is_fingerprinted(registered_packs):
    """
    A deterministic fingerprint over the registered definitions.

    It is what lets an assessment record *which* rules produced it. Without
    it, a score from last month cannot be reproduced after a rule has been
    tuned, and "the rules changed" is indistinguishable from "the account
    changed".
    """
    payload = registered_packs.to_dict()

    assert payload["fingerprint"]
    assert len(payload["fingerprint"]) >= 32


def test_registration_reports_its_caveats(registered_packs):
    caveats = registered_packs.to_dict()["caveats"]

    assert caveats
    joined = " ".join(caveats).lower()

    assert "synthetic" in joined
    assert "not proof" in joined or "proof of wrongdoing" in joined


def test_the_registry_declares_itself_non_durable(registered_packs):
    """
    Process-local and in-memory, and it says so.

    A rule registry that looks durable and is not is how a rule someone
    carefully tuned disappears at the next restart, with nobody noticing until
    detection quietly gets worse.
    """
    metadata = registered_packs.to_dict()["metadata"]

    assert metadata["registry_durable"] is False
    assert metadata["registry_distributed"] is False


def test_every_builtin_rule_has_a_description_and_a_severity():
    """
    No anonymous rules.

    A rule that fires without being able to say what it is cannot appear in an
    explanation, and an unexplained contribution to a score is worse than no
    contribution.
    """
    for rule_id in rule_definitions.list_builtin_rule_ids():
        rule = rule_definitions.get_builtin_rule_definition(rule_id)

        assert rule is not None
        assert getattr(rule, "name", None), f"{rule_id} has no name"
        assert getattr(rule, "description", None), f"{rule_id} has no description"
        assert getattr(rule, "severity", None) is not None


def test_rule_ids_are_versioned():
    """
    Every id ends in a version.

    Retuning a threshold under the same id makes two incompatible rules
    indistinguishable in an audit trail.
    """
    for rule_id in rule_definitions.list_builtin_rule_ids():
        assert rule_id.rsplit(".", 1)[-1].startswith("v"), rule_id


# -----------------------------------------------------------------------------
# Evaluation
# -----------------------------------------------------------------------------


def test_a_loud_record_matches_several_rules():
    result = _evaluate([LOUD])

    assert result.ok is True
    assert len(result.records) == 1

    record = result.records[0]
    assert record.matched_rules
    assert record.score is not None
    assert record.review_recommended is True


def test_a_quiet_record_matches_nothing():
    """
    The false-positive side.

    A record with ordinary values on every signal should match no rule. A rule
    pack that fires on this is measuring activity rather than typology, and
    the queue fills with accounts that have done nothing unusual.
    """
    result = _evaluate([QUIET])

    record = result.records[0]
    assert list(record.matched_rules) == []
    assert record.review_recommended is False
    assert record.score == 0.0


def test_an_evaluated_record_that_matches_nothing_scores_zero():
    """
    Nothing fired is a finding, not a failure to assess.

    The noisy-OR of an empty match set is exactly 0.0, so a record that was
    checked against the pack and matched nothing gets a zero and a minimal
    band. That is the honest answer: the account was assessed and nothing
    stood out.

    The engine previously returned `score=None` and a band of `unavailable`
    whenever nothing matched, which reported every ordinary account as
    unassessable — the mirror image of rendering "not assessed" as a zero, and
    it would bury the genuinely unassessable records among thousands of
    unremarkable ones.
    """
    result = _evaluate([QUIET])
    record = result.records[0]

    assert record.score == 0.0
    assert "unavail" not in str(record.risk_band).lower()
    assert record.review_recommended is False


def test_a_record_with_no_usable_features_is_dropped_and_reported():
    """
    No features at all is a data problem, and it is raised as one.

    The record is not returned with an invented score. It is excluded and the
    result carries `empty_feature_row`, so the caller learns that an account
    it submitted was not assessed rather than reading a zero as a clean bill
    of health.
    """
    result = _evaluate([{"account_id": "acc-empty"}])

    assert result.records == ()
    assert result.counts["submitted"] == 1
    assert result.counts["scored"] == 0

    codes = {issue.code for issue in result.issues}
    assert "empty_feature_row" in codes


def test_no_rules_available_is_reported_rather_than_scored():
    """
    An empty registry produces an issue, not a page of zeroes.

    This is the state `score=None` is now reserved for. A deployment whose
    rule pack failed to register must not quietly score every account zero and
    call it a clean run.
    """
    registry = rule_engine.get_rule_registry()
    registry.clear()

    result = _evaluate([QUIET])

    codes = {issue.code for issue in result.issues}
    assert "no_rules_available" in codes
    assert result.records == ()


def test_the_guardrail_rule_fires_on_missing_core_signals():
    """
    Missing inputs produce a finding of their own.

    The guardrail is an INFO-severity rule whose entire job is to say "this
    account could not be assessed properly". It is how a silent ingestion gap
    becomes visible rather than becoming a page of low scores.
    """
    result = _evaluate([{"account_id": "acc-partial", "velocity_burstiness": 1.0}])

    matched = [match.rule_id for match in result.records[0].matched_rules]
    assert any("guardrail" in rule_id for rule_id in matched), matched


def test_evaluation_is_deterministic():
    """
    The same record twice gives the same score.

    Non-determinism here would make an assessment irreproducible, which makes
    it indefensible: an analyst cannot stand behind a number that comes out
    differently when it is recomputed.
    """
    first = _evaluate([LOUD])
    second = _evaluate([LOUD])

    assert first.records[0].score == second.records[0].score
    assert first.fingerprint == second.fingerprint


def test_a_higher_signal_never_lowers_the_score():
    """
    Monotonicity on one signal, holding the rest fixed.

    Not a mathematical necessity of the design, but a property an analyst will
    assume, and a violation of it is the fastest way to lose their trust in
    the score. Here the quiet record scores zero and the same record with a
    complaint spike scores above it.
    """
    low = dict(QUIET, complaint_correlation_count=0)
    high = dict(QUIET, complaint_correlation_count=9)

    result = _evaluate([low, high])

    assert result.records[0].score == 0.0
    assert result.records[1].score > result.records[0].score


def test_counts_account_for_every_submitted_record():
    """
    Submitted equals processed, and a dropped record is visible in the counts.

    A record silently dropped mid-batch would be an account that was never
    assessed and that nothing said was not assessed. Here the third record has
    no usable features, so it is excluded from `records` — but `submitted` and
    `processed` still count it, and `scored` does not, which is how the caller
    reconciles what it sent against what came back.
    """
    result = _evaluate([LOUD, QUIET, {"account_id": "acc-empty"}])
    counts = result.counts

    # `submitted` is what the caller sent, `processed` what survived input
    # cleaning, `scored` what produced a score. The third record has no usable
    # features, so it is dropped: the difference between `submitted` and
    # `processed` is exactly the dropped count, which is what lets a caller
    # reconcile its input against the result instead of guessing.
    assert counts["submitted"] == 3
    assert counts["processed"] == 2
    assert counts["scored"] == 2
    assert counts["submitted"] - counts["processed"] == 1
    assert len(result.records) == 2


def test_record_order_is_preserved_by_index():
    """
    Each result carries the index of the record it came from.

    The caller matches results back to accounts by position, so a reordering
    would attribute one account's score to another — the worst possible
    failure in this system and a completely silent one.
    """
    result = _evaluate([QUIET, LOUD])

    assert [record.index for record in result.records] == [0, 1]
    assert result.records[1].matched_rules


# -----------------------------------------------------------------------------
# Reasons
# -----------------------------------------------------------------------------


def test_a_match_carries_reasons():
    """
    Why it fired, in words.

    This is what reaches the analyst as the explanation of a score. A match
    with no reason is a number with a label.
    """
    result = _evaluate([LOUD], include_reasons=True)
    record = result.records[0]

    assert record.reasons or any(match.reasons for match in record.matched_rules)


def test_reasons_do_not_leak_raw_values():
    """
    Bucketed, not verbatim.

    A reason string that quoted the exact amount or counterparty would put
    transaction detail into explanations, assessments, alerts and from there
    into exported reports. The engine's own safety flags promise this; the
    test checks it.
    """
    result = _evaluate([LOUD], include_reasons=True)

    serialised = str(result.to_dict()).lower()

    assert "acc-loud" not in serialised, "the subject reference leaked into the output"


def test_the_subject_reference_is_hashed_in_results():
    """
    Results carry a salted hash, not the account id.

    Rule evaluation output is passed around and logged. The caller already
    knows which account it submitted, by index, so the identifier does not
    need to travel with the result.
    """
    result = _evaluate([LOUD])
    record = result.records[0]

    assert record.subject_ref_hash
    assert record.subject_ref_hash != "acc-loud"
    assert len(record.subject_ref_hash) >= 16


def test_each_match_reports_its_score_contribution():
    """
    How much this rule added.

    An aggregate score with no per-rule contribution cannot be argued with:
    an analyst who thinks one rule is wrong has no way to see what the score
    would be without it.
    """
    result = _evaluate([LOUD])

    for match in result.records[0].matched_rules:
        assert match.score_contribution is not None
        assert match.severity is not None


# -----------------------------------------------------------------------------
# Safety
# -----------------------------------------------------------------------------


def _condition_fields(node) -> set[str]:
    """
    The field names a condition tree reads.

    Walked rather than string-matched, because an exported definition also
    carries the caveat text — which itself lists `ground_truth`, `is_fraud`
    and the rest as examples of fields that are refused. Searching the whole
    export for those words finds the caveat and reports it as a violation.
    """
    if not isinstance(node, dict):
        return set()

    found: set[str] = set()

    field = node.get("field")
    if isinstance(field, str) and field:
        found.add(field.lower())

    for child in node.get("children") or ():
        found |= _condition_fields(child)

    return found


def _fields_of(rule) -> set[str]:
    exported = rule_definitions.export_rule_definition(rule)
    tree = exported.get("condition") or exported.get("conditions")

    if isinstance(tree, list):
        found: set[str] = set()
        for entry in tree:
            found |= _condition_fields(entry)
        return found

    return _condition_fields(tree)


def test_no_builtin_rule_expresses_an_adverse_action():
    """
    The strongest effect available is escalation to a human.

    MuleGuard produces leads. The decision, and the accountability for it,
    stay with a person — so there is no rule effect that freezes an account,
    blocks a payment or adds anyone to a list.
    """
    forbidden = {"freeze", "block", "blacklist", "suspend", "close", "deny", "reject"}

    for rule_id in rule_definitions.list_builtin_rule_ids():
        rule = rule_definitions.get_builtin_rule_definition(rule_id)
        action = rule_definitions.export_rule_definition(rule).get("action") or {}
        effect = str(action.get("effect", "")).lower()

        assert effect not in forbidden, f"{rule_id} has effect {effect!r}"

        for word in forbidden:
            assert word not in effect, f"{rule_id} has effect {effect!r}"


def test_the_engine_declares_no_automatic_adverse_action(registered_packs):
    flags = registered_packs.to_dict()["safety_flags"]

    assert flags["no_automatic_adverse_customer_action"] is True
    assert flags["human_review_required_for_consequential_action"] is True
    assert flags["scores_are_investigative_priority_only"] is True


def test_label_shaped_fields_are_refused_as_rule_inputs(registered_packs):
    """
    The leakage guarantee, as the engine states it.

    A rule conditioned on `ground_truth` or `scenario_id` would be reading the
    synthetic generator's answer sheet — and since those columns exist on
    every labelled account, the leak is always one careless rule away.
    """
    flags = registered_packs.to_dict()["safety_flags"]

    assert flags["no_labels_as_rule_features"] is True
    assert flags["no_ground_truth_fields_accepted"] is True
    assert flags["no_scenario_ids_accepted"] is True
    assert flags["no_fraud_ring_ids_accepted"] is True


def test_no_builtin_rule_conditions_on_a_label_field():
    """
    Checked against the definitions, not only against the declared flag.

    A safety flag is a promise. This reads the exported conditions and looks
    for the forbidden field names itself, so the promise and the rules cannot
    disagree.
    """
    forbidden = (
        "ground_truth",
        "is_fraud",
        "fraud_label",
        "truth_label",
        "scenario",
        "ring_id",
    )

    for rule_id in rule_definitions.list_builtin_rule_ids():
        rule = rule_definitions.get_builtin_rule_definition(rule_id)
        fields = _fields_of(rule)

        assert fields, f"{rule_id} reads no fields at all"

        for field in fields:
            for token in forbidden:
                assert token not in field, (
                    f"{rule_id} conditions on {field!r}, which contains {token!r}"
                )


def test_narratives_and_raw_identifiers_are_refused(registered_packs):
    flags = registered_packs.to_dict()["safety_flags"]

    assert flags["no_raw_narratives_accepted"] is True
    assert flags["no_raw_identifiers_accepted"] is True
    assert flags["no_secrets_accepted"] is True


def test_evaluation_is_bounded(registered_packs):
    """
    A batch cannot be unbounded.

    Rule evaluation runs inside a request. An unbounded batch is a request
    that never returns, which takes a worker with it.
    """
    flags = registered_packs.to_dict()["safety_flags"]
    assert flags["bounded_rule_evaluation_required"] is True

    options = rule_engine.RuleEngineOptions()
    assert options.max_records > 0
    assert options.max_rules_evaluated > 0
    assert options.max_time_ms > 0


def test_a_batch_over_the_record_limit_is_bounded():
    """
    More records than the limit does not simply process them all.

    Either refused or truncated with the truncation reported; what must not
    happen is a quiet full run that ignores the limit.
    """
    options = rule_engine.RuleEngineOptions(max_records=5)
    request = rule_engine.RuleEvaluationRequest(
        records=[dict(QUIET, account_id=f"acc-{index}") for index in range(40)]
    )

    result = rule_engine.evaluate_rules(request, options)

    assert len(result.records) <= 5 or result.issues


# -----------------------------------------------------------------------------
# The scenario fixtures
# -----------------------------------------------------------------------------


SCENARIO_IDS = [
    "fan_in",
    "fan_out",
    "rapid_pass_through",
    "multi_hop_layering",
    "round_trip_cycle",
    "dormant_to_active",
    "complaint_linked",
    "shared_entity_network",
    "hard_negative",
]


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_every_scenario_fixture_is_well_formed(load_scenario, scenario_id):
    """
    The scenario files are the written record of what each typology means.

    They are read by tests and by people, so the shape is checked: an
    expectation without a label, or a positive scenario with no expected
    rules, is a file that has stopped describing anything.
    """
    scenario = load_scenario(scenario_id)

    assert scenario["id"] == scenario_id
    assert scenario["label"]
    assert scenario["description"]
    assert scenario["parameters"]
    assert scenario["confounders"], "every typology has an innocent twin; name it"

    expected = scenario["expected"]
    assert "ground_truth_label" in expected
    assert isinstance(expected["rule_codes"], list)


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_scenario_parameters_match_the_factory_builders(load_scenario, scenario_id, make):
    """
    The files and `tests/factories.py` agree.

    The builders are what the tests call; the files are what a person reads.
    If they drift, the documentation describes a typology the suite does not
    actually build, which is worse than having no documentation.
    """
    scenario = load_scenario(scenario_id)
    builder_name = {
        "fan_in": "fan_in",
        "fan_out": "fan_out",
        "rapid_pass_through": "pass_through",
        "multi_hop_layering": "layering_chain",
        "round_trip_cycle": "round_trip",
        "dormant_to_active": "dormant_reactivation",
        "complaint_linked": "complaint_linked_account",
        "shared_entity_network": "shared_identifier_cluster",
        "hard_negative": "hard_negative",
    }[scenario_id]

    builder = getattr(make, builder_name, None)
    assert builder is not None, f"factories.py has no {builder_name!r} builder"

    import inspect

    accepted = set(inspect.signature(builder).parameters)
    declared = set(scenario["parameters"])

    # Not every documented parameter has to be a builder argument — some
    # describe the shape rather than configure it — but a builder argument
    # named in the file must actually exist, or the file is describing a knob
    # nobody can turn.
    unknown = {
        name
        for name in declared
        if name in {"sources", "destinations", "hops", "members", "burst", "counterparties"}
        and name not in accepted
    }
    assert not unknown, f"{scenario_id} documents parameters {builder.__name__} lacks: {unknown}"


def test_the_hard_negative_expects_no_rule_hits(load_scenario):
    """
    The one scenario that is in the suite to be got right rather than detected.

    It is a busy merchant: many payers, spread over months, money retained. It
    trips a naive fan-in count and is entirely legitimate. If a change makes
    it produce an alert, the change raised the false-positive rate — whatever
    it did for recall.
    """
    scenario = load_scenario("hard_negative")

    assert scenario["expected"]["ground_truth_label"] is False
    assert scenario["expected"]["rule_codes"] == []
    assert scenario["expected"]["max_risk_band"] == "MEDIUM"


def test_scenario_labels_are_the_generators_intent_not_ground_truth(load_scenario):
    """
    What `ground_truth_label` actually means, written down in the file.

    Every metric computed against these labels measures agreement with what
    the generator planted. That is a real and useful measurement — it catches
    regressions — and it is not an accuracy figure for real fraud. The README
    says so, and so does this assertion.
    """
    import json
    from pathlib import Path

    readme = (
        Path(__file__).parent / "fixtures" / "scenarios" / "README.md"
    ).read_text(encoding="utf-8").lower()

    assert "generator's intent" in readme
    assert "not an accuracy figure" in readme or "not a finding about the world" in readme

    # And the labels themselves are present, so the claim is about something.
    assert load_scenario("fan_in")["expected"]["ground_truth_label"] is True
