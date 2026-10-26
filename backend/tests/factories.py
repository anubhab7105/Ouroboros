"""
Data builders for the test suite.

Tests construct scenarios through `Factory` rather than through the models
directly. Three reasons, in order of how much they matter:

1. **A column rename is one edit.** Forty tests that each spell out
   `Transaction(sender_account_id=..., receiver_account_id=..., ...)` make the
   schema expensive to change, which in practice means the schema stops
   changing.

2. **Defaults are the boring case.** Almost every test cares about one or two
   fields and wants the rest to be unremarkable. A factory that fills in a
   plausible rest lets the test say only what it means: `make.transaction(a, b,
   amount=99_000)` reads as "a transfer just under a lakh", which is the point
   being tested.

3. **The typologies are shared vocabulary.** `make.fan_in(...)` builds the same
   shape in the rules tests, the graph tests and the dashboard tests, so a
   disagreement between them is a real disagreement rather than two different
   hand-built fixtures.

Every builder flushes but does not commit: the caller's transaction owns the
rows, and `conftest.db` rolls it back. Builders return the ORM objects so a
test can read generated ids straight back.

**Amounts are always `Decimal`.** `money()` goes through `str` so that
`0.1 + 0.2` never enters the picture; a float literal in a monetary column is
a bug the suite should not be able to express.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Optional, Sequence

from sqlalchemy.orm import Session

from app.models import (
    Account,
    AccountEntityLink,
    AccountStatus,
    AccountType,
    Alert,
    AlertEvidence,
    AlertState,
    AnalysisRun,
    AnalysisRunStatus,
    AuditEvent,
    AuditOutcome,
    CaseEvent,
    CaseEvidence,
    CaseNote,
    CaseStatus,
    Channel,
    Complaint,
    ComplaintCorrelation,
    ComplaintReviewState,
    Disposition,
    Entity,
    EntityType,
    EvidenceType,
    FeatureSnapshot,
    GraphAnalysisRun,
    GroundTruthLabel,
    IndicatorType,
    InvestigationCase,
    MatchMethod,
    ModelAssessment,
    ModelType,
    ModelVersion,
    Priority,
    RiskBand,
    RiskIndicator,
    RuleHit,
    ScoringMode,
    Severity,
    SplitStrategy,
    TransactionStatus,
    Transaction,
    User,
    UserRole,
    VerificationState,
)

from tests.utils import money, unique_id, utcnow


class Factory:
    """
    Scenario builders bound to one session.

    Instantiated by the `make` fixture. Holds a monotonically increasing
    counter so that references and identifiers are unique within a test
    without the caller having to supply them.
    """

    def __init__(self, session: Session) -> None:
        self.session = session
        self._counter = 0

    # ---------------------------------------------------------------- helpers

    def _next(self) -> int:
        self._counter += 1
        return self._counter

    def _add(self, instance: Any) -> Any:
        self.session.add(instance)
        self.session.flush()
        return instance

    # ----------------------------------------------------------------- people

    def user(
        self,
        *,
        username: Optional[str] = None,
        role: UserRole = UserRole.ANALYST,
        is_active: bool = True,
        password_hash: str = "not-a-real-hash",
        **kwargs: Any,
    ) -> User:
        """
        A user row.

        The password hash is a placeholder: a test that needs to *sign in* as
        this user must go through the `conftest` role fixtures, which hash a
        real password. Everything else — assignment, attribution, audit — only
        needs the row to exist.
        """
        name = username or f"user_{self._next()}"
        return self._add(
            User(
                username=name,
                email=kwargs.pop("email", f"{name}@muleguard.test"),
                full_name=kwargs.pop("full_name", name.replace("_", " ").title()),
                role=role,
                password_hash=password_hash,
                is_active=is_active,
                **kwargs,
            )
        )

    # --------------------------------------------------------------- accounts

    def account(
        self,
        *,
        account_type: AccountType = AccountType.INDIVIDUAL,
        status: AccountStatus = AccountStatus.ACTIVE,
        created_at: Optional[datetime] = None,
        **kwargs: Any,
    ) -> Account:
        """
        An account.

        `created_at` defaults to a year ago rather than now, because an account
        opened this instant trips every recency rule in the engine and would
        make unrelated tests depend on the dormancy thresholds.
        """
        return self._add(
            Account(
                account_type=account_type,
                status=status,
                created_at=created_at or (utcnow() - timedelta(days=365)),
                **kwargs,
            )
        )

    def accounts(self, count: int, **kwargs: Any) -> list[Account]:
        """`count` accounts with the same options."""
        return [self.account(**kwargs) for _ in range(count)]

    def dormant_account(self, *, dormant_days: int = 200, **kwargs: Any) -> Account:
        """An account that has been quiet for a long time."""
        return self.account(
            status=AccountStatus.DORMANT,
            created_at=utcnow() - timedelta(days=dormant_days + 365),
            **kwargs,
        )

    # ----------------------------------------------------------- transactions

    def transaction(
        self,
        sender: Account | str,
        receiver: Account | str,
        *,
        amount: Decimal | int | float | str = 10_000,
        occurred_at: Optional[datetime] = None,
        status: TransactionStatus = TransactionStatus.COMPLETED,
        channel: Channel = Channel.IMPS,
        currency: str = "INR",
        reference: Optional[str] = None,
        **kwargs: Any,
    ) -> Transaction:
        """
        One transfer.

        Defaults to COMPLETED because that is the only status the monetary
        aggregates count; a test about pending or reversed behaviour says so
        explicitly, which is the right way round.
        """
        return self._add(
            Transaction(
                sender_account_id=_id_of(sender),
                receiver_account_id=_id_of(receiver),
                amount=money(amount),
                currency=currency,
                occurred_at=occurred_at or utcnow() - timedelta(hours=1),
                status=status,
                channel=channel,
                reference=reference or unique_id("TXNREF"),
                **kwargs,
            )
        )

    def transfers(
        self,
        pairs: Sequence[tuple[Account | str, Account | str]],
        **kwargs: Any,
    ) -> list[Transaction]:
        """One transfer per (sender, receiver) pair."""
        return [self.transaction(sender, receiver, **kwargs) for sender, receiver in pairs]

    # ---------------------------------------------------------- the typologies
    #
    # These are the shapes the detector is meant to find. Keeping them here
    # rather than in each test module means a rules test and a graph test are
    # looking at the same thing, and that the definition of "fan-in" lives in
    # one place where it can be argued with.

    def fan_in(
        self,
        *,
        sources: int = 12,
        amount: Decimal | int = 24_000,
        within_hours: int = 6,
        collector: Optional[Account] = None,
    ) -> tuple[Account, list[Account], list[Transaction]]:
        """
        Many accounts paying one, in a short window.

        The collection pattern: a mule account receiving from a spread of
        unrelated victims or sub-mules. `sources` well above the fan-in
        threshold and `within_hours` well below the window, so the shape is
        unambiguous rather than borderline — a test that wants the borderline
        case should build it from `transaction` directly and say why.
        """
        target = collector or self.account()
        senders = self.accounts(sources)
        base = utcnow() - timedelta(hours=within_hours)

        transactions = [
            self.transaction(
                sender,
                target,
                amount=amount,
                occurred_at=base + timedelta(minutes=index * 7),
            )
            for index, sender in enumerate(senders)
        ]

        return target, senders, transactions

    def fan_out(
        self,
        *,
        destinations: int = 10,
        amount: Decimal | int = 28_000,
        within_hours: int = 4,
        distributor: Optional[Account] = None,
    ) -> tuple[Account, list[Account], list[Transaction]]:
        """One account paying many, in a short window: the dispersal half."""
        source = distributor or self.account()
        receivers = self.accounts(destinations)
        base = utcnow() - timedelta(hours=within_hours)

        transactions = [
            self.transaction(
                source,
                receiver,
                amount=amount,
                occurred_at=base + timedelta(minutes=index * 9),
            )
            for index, receiver in enumerate(receivers)
        ]

        return source, receivers, transactions

    def pass_through(
        self,
        *,
        amount: Decimal | int = 200_000,
        retained_fraction: float = 0.02,
        minutes_held: int = 11,
    ) -> tuple[Account, Account, Account, list[Transaction]]:
        """
        Money in and almost all of it straight back out.

        `retained_fraction` is what the middle account keeps. The default 2% is
        the signature: a real account that happens to forward a payment keeps
        a round remainder or none at all, whereas a pass-through keeps a
        commission.

        Returns (source, middle, destination, transactions).
        """
        source = self.account()
        middle = self.account()
        destination = self.account()

        incoming_at = utcnow() - timedelta(hours=2)
        inbound = self.transaction(source, middle, amount=amount, occurred_at=incoming_at)

        forwarded = money(amount) * (Decimal("1") - money(retained_fraction))
        outbound = self.transaction(
            middle,
            destination,
            amount=forwarded.quantize(Decimal("0.01")),
            occurred_at=incoming_at + timedelta(minutes=minutes_held),
        )

        return source, middle, destination, [inbound, outbound]

    def layering_chain(
        self,
        *,
        hops: int = 5,
        amount: Decimal | int = 480_000,
        throughput: float = 0.97,
        minutes_between: int = 14,
    ) -> tuple[list[Account], list[Transaction]]:
        """
        A chain of hops, each forwarding most of what it received.

        This is the shape that makes a money trail worth tracing, and the one
        that most needs care in presentation: the chain is a *sequence of
        transfers consistent with* layering, not a tracing of specific funds.
        Accounts are fungible; once money lands, which rupees left is a
        question the ledger cannot answer.
        """
        chain = self.accounts(hops + 1)
        transactions: list[Transaction] = []

        current = money(amount)
        moment = utcnow() - timedelta(hours=hops + 2)

        for index in range(hops):
            transactions.append(
                self.transaction(
                    chain[index],
                    chain[index + 1],
                    amount=current.quantize(Decimal("0.01")),
                    occurred_at=moment,
                )
            )
            current = current * money(throughput)
            moment = moment + timedelta(minutes=minutes_between)

        return chain, transactions

    def round_trip(
        self,
        *,
        hops: int = 3,
        amount: Decimal | int = 150_000,
    ) -> tuple[list[Account], list[Transaction]]:
        """
        A cycle: the money comes back to where it started.

        Returned accounts are the cycle in order; the final transfer closes it.
        A cycle is a strong signal and also an easy one to produce innocently
        (settlement between related businesses), so the tests that use this
        check the explanation as much as the detection.
        """
        cycle = self.accounts(hops)
        transactions: list[Transaction] = []
        moment = utcnow() - timedelta(days=1)

        for index in range(hops):
            transactions.append(
                self.transaction(
                    cycle[index],
                    cycle[(index + 1) % hops],
                    amount=amount,
                    occurred_at=moment + timedelta(hours=index * 3),
                )
            )

        return cycle, transactions

    def dormant_reactivation(
        self,
        *,
        dormant_days: int = 240,
        burst: int = 9,
        amount: Decimal | int = 45_000,
    ) -> tuple[Account, list[Transaction]]:
        """
        A long-quiet account that suddenly moves money.

        One old transaction establishes that the account was used before, then
        nothing for `dormant_days`, then a burst. Without the old transaction
        this is indistinguishable from a new account, which is a different
        thing entirely.
        """
        account = self.dormant_account(dormant_days=dormant_days)
        counterparties = self.accounts(burst + 1)

        history = [
            self.transaction(
                counterparties[0],
                account,
                amount=5_000,
                occurred_at=utcnow() - timedelta(days=dormant_days + 30),
            )
        ]

        base = utcnow() - timedelta(hours=5)
        for index in range(burst):
            history.append(
                self.transaction(
                    counterparties[index + 1],
                    account,
                    amount=amount,
                    occurred_at=base + timedelta(minutes=index * 11),
                )
            )

        return account, history

    def hard_negative(
        self,
        *,
        counterparties: int = 14,
        amount: Decimal | int = 22_000,
    ) -> tuple[Account, list[Transaction]]:
        """
        An account that looks like a collector and is not one.

        A small merchant: many inbound payments from many payers, which trips
        a naive fan-in count — but spread evenly over months rather than
        clustered in hours, and with the money staying put rather than being
        forwarded. Any rule that fires on this is measuring popularity, not
        laundering, and the suite should catch that.
        """
        merchant = self.account(account_type=AccountType.MERCHANT)
        payers = self.accounts(counterparties)
        transactions: list[Transaction] = []

        for index, payer in enumerate(payers):
            transactions.append(
                self.transaction(
                    payer,
                    merchant,
                    amount=amount,
                    occurred_at=utcnow() - timedelta(days=index * 6 + 2),
                    channel=Channel.CARD,
                )
            )

        return merchant, transactions

    # --------------------------------------------------------------- entities

    def entity(
        self,
        *,
        entity_type: EntityType = EntityType.DEVICE,
        identifier_hash: Optional[str] = None,
        identifier_display: Optional[str] = None,
        **kwargs: Any,
    ) -> Entity:
        """
        A pseudonymous identifier.

        `identifier_hash` is the stored form; `identifier_display` is optional
        and usually absent, because most identifiers are never held in the
        clear. Tests that assert on display text must set it explicitly rather
        than assume it is there.
        """
        return self._add(
            Entity(
                entity_type=entity_type,
                identifier_hash=identifier_hash or unique_id("hash"),
                identifier_display=identifier_display,
                **kwargs,
            )
        )

    def entity_link(
        self,
        account: Account | str,
        entity: Entity | str,
        *,
        match_method: MatchMethod = MatchMethod.EXACT,
        confidence: Optional[Decimal | float] = None,
        verification_state: VerificationState = VerificationState.UNVERIFIED,
        valid_from: Optional[datetime] = None,
        valid_to: Optional[datetime] = None,
        **kwargs: Any,
    ) -> AccountEntityLink:
        """
        Link an account to an identifier.

        `confidence` stays None for a deterministic method. A deterministic
        link with a confidence of 1.0 is the mistake this signature is shaped
        to prevent: certainty about an exact match is not the same kind of
        thing as a probability, and showing it as 1.000 invites the reader to
        compare it with 0.94.
        """
        return self._add(
            AccountEntityLink(
                account_id=_id_of(account),
                entity_id=_id_of(entity),
                match_method=match_method,
                confidence=money(confidence) if confidence is not None else None,
                verification_state=verification_state,
                valid_from=valid_from or (utcnow() - timedelta(days=90)),
                valid_to=valid_to,
                **kwargs,
            )
        )

    def shared_identifier_cluster(
        self,
        *,
        members: int = 4,
        entity_type: EntityType = EntityType.DEVICE,
    ) -> tuple[Entity, list[Account], list[AccountEntityLink]]:
        """
        Several accounts sharing one identifier.

        A real signal and a weak one: shared devices, recycled phone numbers
        and family handsets produce exactly this. The tests assert that the
        platform says so rather than treating co-occurrence as common control.
        """
        shared = self.entity(entity_type=entity_type)
        accounts = self.accounts(members)
        links = [self.entity_link(account, shared) for account in accounts]
        return shared, accounts, links

    # ------------------------------------------------------------- complaints

    def complaint(
        self,
        *,
        reference: Optional[str] = None,
        reported_at: Optional[datetime] = None,
        narrative_raw: str = "Victim reports funds debited after an unsolicited call.",
        category: str = "UPI_FRAUD",
        transaction_reference: Optional[str] = None,
        victim_account: Optional[Account | str] = None,
        suspected_account: Optional[Account | str] = None,
        amount: Optional[Decimal | int] = None,
        currency: Optional[str] = "INR",
        **kwargs: Any,
    ) -> Complaint:
        """A cybercrime complaint."""
        return self._add(
            Complaint(
                reference=reference or unique_id("CMP"),
                reported_at=reported_at or (utcnow() - timedelta(days=2)),
                category=category,
                narrative_raw=narrative_raw,
                transaction_reference=transaction_reference,
                victim_account_id=_id_of(victim_account) if victim_account else None,
                suspected_account_id=_id_of(suspected_account) if suspected_account else None,
                amount=money(amount) if amount is not None else None,
                currency=currency,
                **kwargs,
            )
        )

    def correlation(
        self,
        complaint: Complaint | str,
        *,
        account: Optional[Account | str] = None,
        transaction: Optional[Transaction | str] = None,
        entity: Optional[Entity | str] = None,
        match_tier: int = 1,
        match_method: MatchMethod = MatchMethod.EXACT,
        confidence: Optional[Decimal | float] = None,
        deterministic: Optional[bool] = None,
        review_state: Optional[ComplaintReviewState] = None,
        **kwargs: Any,
    ) -> ComplaintCorrelation:
        """
        A correlation between a complaint and something in the ledger.

        `deterministic` and `review_state` are derived from the tier when not
        given, because the relationship between them is the contract: tiers 1
        and 2 are identity matches, which carry no confidence and need no
        review; tiers 3 to 5 are inferences, which carry both. Letting a test
        set them independently would let it assert a combination the API never
        produces.
        """
        is_deterministic = deterministic if deterministic is not None else match_tier <= 2

        if is_deterministic:
            resolved_confidence = None
            resolved_state = review_state or ComplaintReviewState.ACCEPTED
        else:
            resolved_confidence = money(confidence if confidence is not None else 0.72)
            resolved_state = review_state or ComplaintReviewState.UNREVIEWED

        return self._add(
            ComplaintCorrelation(
                complaint_id=_id_of(complaint),
                account_id=_id_of(account) if account else None,
                transaction_id=_id_of(transaction) if transaction else None,
                entity_id=_id_of(entity) if entity else None,
                match_tier=match_tier,
                match_method=match_method,
                confidence=resolved_confidence,
                deterministic=is_deterministic,
                review_state=resolved_state,
                **kwargs,
            )
        )

    def complaint_linked_account(
        self,
        *,
        complaints: int = 3,
    ) -> tuple[Account, list[Complaint], list[ComplaintCorrelation]]:
        """An account named as the suspect in several complaints."""
        account = self.account()
        raised: list[Complaint] = []
        correlations: list[ComplaintCorrelation] = []

        for index in range(complaints):
            lodged = self.complaint(
                suspected_account=account,
                reported_at=utcnow() - timedelta(days=index + 1),
                amount=50_000 + index * 10_000,
            )
            raised.append(lodged)
            correlations.append(
                self.correlation(lodged, account=account, match_tier=1)
            )

        return account, raised, correlations

    # -------------------------------------------------------- model artefacts

    def model_version(
        self,
        *,
        version: Optional[str] = None,
        model_type: ModelType = ModelType.HIST_GRADIENT_BOOSTING,
        is_active: bool = True,
        **kwargs: Any,
    ) -> ModelVersion:
        return self._add(
            ModelVersion(
                version=version or f"test-{self._next():03d}",
                model_type=model_type,
                split_strategy=kwargs.pop(
                    "split_strategy", SplitStrategy.SCENARIO_AWARE_CHRONOLOGICAL
                ),
                is_active=is_active,
                **kwargs,
            )
        )

    def analysis_run(
        self,
        *,
        status: AnalysisRunStatus = AnalysisRunStatus.SUCCEEDED,
        run_type: str = "full",
        scoring_mode: ScoringMode = ScoringMode.HEURISTIC_FALLBACK,
        requested_by: Optional[User | str] = None,
        **kwargs: Any,
    ) -> AnalysisRun:
        started = kwargs.pop("started_at", utcnow() - timedelta(minutes=10))
        finished = kwargs.pop(
            "finished_at",
            utcnow() - timedelta(minutes=8) if status != AnalysisRunStatus.RUNNING else None,
        )

        return self._add(
            AnalysisRun(
                status=status,
                run_type=run_type,
                scoring_mode=scoring_mode,
                started_at=started,
                finished_at=finished,
                requested_by=_id_of(requested_by) if requested_by else None,
                **kwargs,
            )
        )

    def feature_snapshot(
        self,
        account: Account | str,
        *,
        as_of: Optional[datetime] = None,
        values: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> FeatureSnapshot:
        return self._add(
            FeatureSnapshot(
                account_id=_id_of(account),
                as_of=as_of or utcnow(),
                values_json=values
                if values is not None
                else {
                    "inbound_count_7d": 11,
                    "outbound_count_7d": 9,
                    "throughput_ratio_7d": 0.96,
                    "distinct_senders_7d": 11,
                },
                **kwargs,
            )
        )

    def assessment(
        self,
        account: Account | str,
        *,
        score: Decimal | int | float = 72,
        risk_band: Optional[RiskBand] = None,
        as_of: Optional[datetime] = None,
        scoring_mode: ScoringMode = ScoringMode.HEURISTIC_FALLBACK,
        analysis_run: Optional[AnalysisRun | str] = None,
        model_version: Optional[ModelVersion | str] = None,
        feature_snapshot: Optional[FeatureSnapshot | str] = None,
        with_explanation: bool = True,
        **kwargs: Any,
    ) -> ModelAssessment:
        """
        A persisted assessment.

        The band is derived from the score by default, using the cut-points in
        `config/scoring.default.json`. A test may override it to assert that
        the API reports the *stored* band rather than recomputing one, which
        matters: an assessment written under an older configuration keeps the
        band it was given.
        """
        return self._add(
            ModelAssessment(
                account_id=_id_of(account),
                as_of=as_of or utcnow(),
                score=money(score),
                risk_band=risk_band or band_for(score),
                scoring_mode=scoring_mode,
                analysis_run_id=_id_of(analysis_run) if analysis_run else None,
                model_version_id=_id_of(model_version) if model_version else None,
                feature_snapshot_id=_id_of(feature_snapshot) if feature_snapshot else None,
                explanation_json=(
                    {
                        "summary": "Inbound concentration with near-complete forwarding.",
                        "top_factors": [
                            {"code": "FAN_IN_BURST", "direction": "increases"},
                            {"code": "HIGH_THROUGHPUT", "direction": "increases"},
                        ],
                    }
                    if with_explanation
                    else None
                ),
                components_json=kwargs.pop(
                    "components_json",
                    {
                        "components": [
                            {
                                "name": "rules",
                                "normalised_value": 0.81,
                                "effective_weight": 0.45,
                                "available": True,
                            },
                            {
                                "name": "model",
                                "normalised_value": 0.64,
                                "effective_weight": 0.35,
                                "available": True,
                            },
                            {
                                "name": "graph",
                                "normalised_value": 0.52,
                                "effective_weight": 0.20,
                                "available": True,
                            },
                        ]
                    },
                ),
                **kwargs,
            )
        )

    def rule_hit(
        self,
        account: Account | str,
        *,
        rule_code: str = "FAN_IN_BURST",
        triggered: bool = True,
        measured_value: Optional[Decimal | float] = 12,
        threshold: Optional[Decimal | float] = 8,
        severity: Severity = Severity.HIGH,
        assessment: Optional[ModelAssessment | str] = None,
        **kwargs: Any,
    ) -> RuleHit:
        """
        One rule evaluation.

        `triggered=False` rows are written deliberately in several tests: a
        rule that was evaluated and came back under threshold is evidence
        about the account, and the API is expected to return it rather than
        silently drop it.
        """
        return self._add(
            RuleHit(
                account_id=_id_of(account),
                assessment_id=_id_of(assessment) if assessment else None,
                rule_code=rule_code,
                triggered=triggered,
                measured_value=money(measured_value) if measured_value is not None else None,
                threshold=money(threshold) if threshold is not None else None,
                severity=severity,
                explanation=kwargs.pop(
                    "explanation",
                    f"{rule_code}: measured {measured_value} against threshold {threshold}.",
                ),
                **kwargs,
            )
        )

    def indicator(
        self,
        assessment: ModelAssessment | str,
        *,
        code: str = "FAN_IN_BURST",
        title: str = "Inbound burst from many senders",
        indicator_type: IndicatorType = IndicatorType.RULE,
        severity: Severity = Severity.HIGH,
        rule_hit: Optional[RuleHit | str] = None,
        **kwargs: Any,
    ) -> RiskIndicator:
        return self._add(
            RiskIndicator(
                assessment_id=_id_of(assessment),
                indicator_type=indicator_type,
                code=code,
                title=title,
                severity=severity,
                rule_hit_id=_id_of(rule_hit) if rule_hit else None,
                **kwargs,
            )
        )

    def scored_account(
        self,
        *,
        score: Decimal | int | float = 78,
        indicators: int = 2,
    ) -> tuple[Account, ModelAssessment, list[RiskIndicator]]:
        """An account with an assessment and indicators: the common read shape."""
        account = self.account()
        snapshot = self.feature_snapshot(account)
        scored = self.assessment(
            account,
            score=score,
            feature_snapshot=snapshot,
            caveats_json={
                "data_classification": "synthetic",
                "score_semantics": "Investigative priority score, not probability of guilt.",
                "automatic_adverse_action": False,
            },
        )

        codes = ["FAN_IN_BURST", "HIGH_THROUGHPUT", "DORMANT_REACTIVATION", "CYCLE_MEMBER"]
        produced = [
            self.indicator(
                scored,
                code=codes[index % len(codes)],
                title=f"Indicator {codes[index % len(codes)]}",
            )
            for index in range(indicators)
        ]

        return account, scored, produced

    # ----------------------------------------------------------------- alerts

    def alert(
        self,
        account: Account | str,
        *,
        title: str = "Collection pattern with rapid forwarding",
        priority: Priority = Priority.HIGH,
        state: AlertState = AlertState.NEW,
        score: Optional[Decimal | int] = 78,
        assessment: Optional[ModelAssessment | str] = None,
        **kwargs: Any,
    ) -> Alert:
        return self._add(
            Alert(
                account_id=_id_of(account),
                assessment_id=_id_of(assessment) if assessment else None,
                title=title,
                priority=priority,
                state=state,
                score=money(score) if score is not None else None,
                scoring_mode=kwargs.pop("scoring_mode", ScoringMode.HEURISTIC_FALLBACK),
                **kwargs,
            )
        )

    def alert_evidence(
        self,
        alert: Alert | str,
        *,
        evidence_type: EvidenceType = EvidenceType.TRANSACTION,
        evidence_id: Optional[str] = None,
        **kwargs: Any,
    ) -> AlertEvidence:
        return self._add(
            AlertEvidence(
                alert_id=_id_of(alert),
                evidence_type=evidence_type,
                evidence_id=evidence_id or unique_id("evi"),
                **kwargs,
            )
        )

    # ------------------------------------------------------------------ cases

    def case(
        self,
        *,
        title: str = "Suspected collection account",
        status: CaseStatus = CaseStatus.NEW,
        priority: Priority = Priority.MEDIUM,
        assignee: Optional[User | str] = None,
        creator: Optional[User | str] = None,
        alert: Optional[Alert | str] = None,
        account: Optional[Account | str] = None,
        **kwargs: Any,
    ) -> InvestigationCase:
        if status == CaseStatus.CLOSED and "disposition" not in kwargs:
            kwargs["disposition"] = Disposition.INCONCLUSIVE

        return self._add(
            InvestigationCase(
                title=title,
                status=status,
                priority=priority,
                assignee_id=_id_of(assignee) if assignee else None,
                creator_id=_id_of(creator) if creator else None,
                alert_id=_id_of(alert) if alert else None,
                account_id=_id_of(account) if account else None,
                **kwargs,
            )
        )

    def case_evidence(
        self,
        case: InvestigationCase | str,
        *,
        evidence_type: EvidenceType = EvidenceType.ACCOUNT,
        evidence_id: Optional[str] = None,
        is_active: bool = True,
        **kwargs: Any,
    ) -> CaseEvidence:
        """
        Evidence attached to a case.

        `is_active=False` with a `removed_at` is how removal is recorded:
        evidence is withdrawn, never deleted, so that a case's history stays
        auditable. Tests assert that a withdrawn item is still retrievable
        with its reason.
        """
        return self._add(
            CaseEvidence(
                case_id=_id_of(case),
                evidence_type=evidence_type,
                evidence_id=evidence_id or unique_id("evi"),
                is_active=is_active,
                **kwargs,
            )
        )

    def case_note(
        self,
        case: InvestigationCase | str,
        *,
        body: str = "Reviewed the inbound cluster; senders appear unrelated.",
        author: Optional[User | str] = None,
        is_internal: bool = False,
        **kwargs: Any,
    ) -> CaseNote:
        return self._add(
            CaseNote(
                case_id=_id_of(case),
                body=body,
                author_id=_id_of(author) if author else None,
                is_internal=is_internal,
                **kwargs,
            )
        )

    def case_event(
        self,
        case: InvestigationCase | str,
        *,
        action: str = "case.created",
        actor: Optional[User | str] = None,
        **kwargs: Any,
    ) -> CaseEvent:
        return self._add(
            CaseEvent(
                case_id=_id_of(case),
                action=action,
                actor_id=_id_of(actor) if actor else None,
                actor_username=kwargs.pop(
                    "actor_username",
                    actor.username if isinstance(actor, User) else None,
                ),
                **kwargs,
            )
        )

    # ------------------------------------------------------------------ audit

    def audit_event(
        self,
        *,
        action: str = "account.read",
        actor: Optional[User | str] = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        **kwargs: Any,
    ) -> AuditEvent:
        return self._add(
            AuditEvent(
                action=action,
                actor_id=_id_of(actor) if actor else None,
                actor_username=kwargs.pop(
                    "actor_username",
                    actor.username if isinstance(actor, User) else None,
                ),
                outcome=outcome,
                **kwargs,
            )
        )

    # ------------------------------------------------------------------ graph

    def graph_run(
        self,
        root: Account | str,
        *,
        node_count: int = 18,
        edge_count: int = 24,
        capped: bool = False,
        **kwargs: Any,
    ) -> GraphAnalysisRun:
        """
        A stored graph traversal.

        `capped=True` is the interesting case and is tested explicitly: a
        traversal stopped at a limit establishes nothing about what lay beyond
        it, and the API is required to say so rather than present a truncated
        neighbourhood as complete.
        """
        return self._add(
            GraphAnalysisRun(
                root_account_id=_id_of(root),
                node_count=node_count,
                edge_count=edge_count,
                capped=capped,
                **kwargs,
            )
        )

    # ------------------------------------------------------------ ground truth

    def label(
        self,
        account: Account | str,
        *,
        is_mule: bool = True,
        scenario_type: Optional[str] = "fan_in_collector",
        **kwargs: Any,
    ) -> GroundTruthLabel:
        """
        A synthetic-data label.

        Only ever present for generated data. Every metric computed against
        these labels measures agreement with the generator's intent, not with
        reality, and the reports say so.
        """
        return self._add(
            GroundTruthLabel(
                account_id=_id_of(account),
                ground_truth_label=is_mule,
                scenario_type=scenario_type,
                **kwargs,
            )
        )


# ---------------------------------------------------------------- module level


def _id_of(value: Any) -> str:
    """
    Accept either a model instance or an id string.

    Lets a test pass whichever it has to hand without a `.id` at every call
    site, which is the difference between a readable scenario and a wall of
    attribute access.
    """
    if value is None:
        raise ValueError("expected a model instance or an id, got None")
    return value if isinstance(value, str) else str(value.id)


def band_for(score: Decimal | int | float) -> RiskBand:
    """
    The band for a score, per `config/scoring.default.json`.

    Duplicated here on purpose: a test that imported the scorer's own banding
    would agree with it by construction and could never catch a cut-point
    being moved. These numbers are written out so that changing the
    configuration without intending to shows up as a failing test.
    """
    value = float(score)
    if value >= 85:
        return RiskBand.CRITICAL
    if value >= 65:
        return RiskBand.HIGH
    if value >= 40:
        return RiskBand.MEDIUM
    return RiskBand.LOW
