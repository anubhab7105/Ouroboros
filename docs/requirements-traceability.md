# Requirements traceability

The six requirement areas, mapped to what implements them, what tests them,
and — in the last column of each section — what is not covered.

The uncovered column is the useful one. A traceability matrix with no gaps is
a traceability matrix that was written to have no gaps.

**Verification status:** the test suite has not been executed as a suite;
`pytest` could not be installed where this was written. 301 assertions from
the pure modules were executed directly, all passing. `docs/testing.md` has
the breakdown. Where a row below cites a test, that test exists and has been
checked by reading; where it has also been *run*, the row says so.

---

## 1. Transaction analysis

> Analyse transactional behaviour to identify patterns consistent with mule
> activity.

| Requirement | Implementation | Tests |
|---|---|---|
| Ingest transfers with referential integrity | `app/ingestion/validators.py`, `app/api/v1/endpoints/ingestion.py` | `test_ingestion`, `test_ingestion_validation`, `test_import_transactionality` |
| Windowed aggregates (1h, 24h, 7d, 30d) | `app/ml/features.py` | `test_features` ✓ run |
| Velocity and burstiness | `app/ml/features.py` | `test_features` ✓ run |
| Counterparty concentration, beneficiary entropy | `app/ml/features.py` | `test_features` ✓ run |
| Pass-through residual | `app/ml/features.py`, `app/rules/definitions.py` | `test_features` ✓ run, `test_rules` |
| Dormancy and reactivation | `app/ml/features.py` | `test_features` ✓ run |
| Completed transfers only in monetary aggregates | `app/api/v1/endpoints/accounts.py` | `test_accounts` |
| Per-currency totals, never summed | `app/api/v1/endpoints/accounts.py` | `test_accounts` |
| Self-transfers excluded from counterparty counts | `app/ml/features.py` | `test_features` ✓ run |
| Point-in-time correctness | `app/ml/features.py`, `FeatureSnapshot` | `test_point_in_time_features` ✓ run |

**Not covered.** No sequence modelling: order within a window is lost, so a
chronology that matters is flattened into an aggregate. No cross-account
timing correlation beyond what the graph layer sees. No seasonality: a
business with a quarterly cycle looks anomalous every quarter.

---

## 2. Mule account detection

> Generate explainable risk scores for suspected mule accounts.

| Requirement | Implementation | Tests |
|---|---|---|
| Typology rules | `app/rules/definitions.py`, `app/rules/engine.py` | `test_rules` |
| Rule hits recorded with inputs and effects | `RuleHit` | `test_rules`, `test_analysis` |
| Supervised model | `app/ml/supervised.py` | `test_ml` ✓ run |
| Heuristic fallback when no model | `app/ml/fallback.py` | `test_ml_fallback` ✓ run |
| Scoring mode reported with every score | `ModelAssessment.scoring_mode` | `test_ml_fallback` ✓ run, `test_risk` |
| Risk fusion across components | `app/services/risk.py` | `test_risk` |
| Unavailable component is not a zero | `app/services/risk.py`, `components_json` | `test_risk`, `test_ml_fallback` ✓ run |
| Banding (LOW/MEDIUM/HIGH/CRITICAL) | `config/scoring.default.json` | `test_risk`, `tests/factories.py` |
| Explanation as contributions | `app/ml/explainability.py` | `test_ml` ✓ run |
| Feature-name blocklist | `app/ml/feature_schema.py` | `test_ml_feature_schema` ✓ run |
| Label-leakage guards | `app/ml/labels.py`, `app/ml/splits.py` | `test_ml_leakage` ✓ run |
| Deterministic training | `app/ml/supervised.py` | `test_ml` ✓ run |
| Alert deduplication by window | `app/services/alerts.py` | `test_alerts` |
| No adverse action | absence of capability; five refused settings | `test_e2e_workflow::TestNoAdverseAction` |

**Not covered.** The model is linear: a pattern visible only in a combination
of signals is invisible to it. No concept-drift detection. No measured
detection quality — the generator plants the typologies the rules look for, so
every metric measures agreement rather than performance
(`docs/model-card.md`). No fairness assessment, and the system holds no
protected-attribute data to make one possible.

---

## 3. Money trail analysis

> Trace fund flows across accounts to reveal layering and dispersal.

| Requirement | Implementation | Tests |
|---|---|---|
| Multi-hop traversal from a seed account | `app/services/graph.py` | `test_graph`, `test_money_trails` |
| Bounded by hops, nodes, edges, time | `app/graph/limits.py` | `test_graph`, `test_money_trails` |
| Truncation reported with which limit was hit | `app/services/graph.py` | `test_money_trails` |
| Candidate trails, ranked | `app/services/graph.py` | `test_money_trails` |
| Completed transfers only | `app/services/graph.py` | `test_money_trails` |
| Date-window restriction | `app/services/graph.py` | `test_graph` |
| Cycle detection | `app/graph/cycles.py` | `test_graph_metrics` ✓ run |
| Graph metrics (degree, component size) | `app/graph/metrics.py` | `test_graph_metrics` ✓ run |
| A trail is a shape, not a tracing of funds | response caveats | `test_money_trails` |

**Not covered.** No global graph analytics — centrality or community detection
over the whole portfolio is not a bounded query, and `app/graph/` exists for
offline work of that kind without being wired to an endpoint. No trail scoring
beyond structural ranking. No cross-institution view, which is where real mule
networks live.

---

## 4. Complaint correlation

> Correlate cybercrime complaints with accounts and transactions.

| Requirement | Implementation | Tests |
|---|---|---|
| Tier 1 — exact transaction reference | `app/correlation/exact_reference.py` | `test_complaint_correlation` |
| Tier 2 — named suspect account | `app/correlation/identifier_match.py` | `test_complaint_correlation` |
| Tier 3 — identifier extracted from the narrative | `app/correlation/narrative_extraction.py` | `test_complaint_correlation` |
| Tier 4 — temporal and amount proximity | `app/correlation/temporal_association.py` | `test_complaint_correlation` |
| Tier 5 — entity or graph association | `app/correlation/entity_association.py` | `test_complaint_correlation` |
| Deterministic tiers carry no confidence | `ComplaintCorrelation` | `test_complaint_correlation` |
| Deterministic tiers need no review | same | `test_complaint_correlation` |
| Inferred tiers carry confidence and review state | same | `test_complaint_correlation` |
| Review workflow, senior and above | `app/api/v1/endpoints/complaints.py` | `test_permissions`, `test_complaints` |
| A rejected correlation is kept | `review_state = REJECTED` | `test_complaint_correlation` |
| Narratives never in list views, errors, logs or exports | `app/api/v1/endpoints/complaints.py` | `test_complaints` |

**Not covered.** Narrative extraction is pattern-based, not semantic: a
complaint describing an account without quoting an identifier will not match
above tier 4. No multilingual handling, which for Indian complaint data is a
real limitation. No deduplication of complaints describing one incident.

---

## 5. Graph-based investigation

> Identify suspicious networks through relationships among connected entities.

| Requirement | Implementation | Tests |
|---|---|---|
| Pseudonymous entities, hashed identifiers | `Entity`, `app/ingestion/normalizers.py` | `test_entities`, `test_ingestion_validation` |
| Time-bounded account-entity links | `AccountEntityLink.valid_from/valid_to` | `test_entities` |
| Deterministic links carry no confidence | `AccountEntityLink.confidence` nullable | `test_ingestion` |
| Match method distinguishes observation from inference | `MatchMethod` | `test_entities`, `test_ingestion` |
| Verification workflow for inferred links | `app/api/v1/endpoints/entities.py` | `test_entities`, `test_permissions` |
| Shared-entity discovery | `app/services/graph.py` | `test_graph` |
| Subgraph around an account | `app/services/graph.py` | `test_graph` |
| Bounded, with truncation reported | `app/graph/limits.py` | `test_graph` |
| A masked display label, non-reversible | `Entity.identifier_display` | `test_entities` |

**Not covered.** No entity resolution: two hashes of the same phone number
written differently are two entities. No link-strength scoring beyond the
method and the window — a shared IP and a shared device hash are distinguished
by type, not by a weight. No temporal graph evolution view.

---

## 6. Investigation dashboard

> Support investigations through an integrated dashboard.

| Requirement | Implementation | Tests |
|---|---|---|
| Alert queue with filters | `app/api/v1/endpoints/alerts.py`, `frontend/src/features/alerts/` | `test_alerts` |
| Triage actions, reporting whether anything changed | same | `test_alerts` |
| Case workflow, 11 transitions | `app/services/case_state_machine.py` | `test_case_transitions` ✓ run (exhaustive) |
| Start requires an assignee | same | `test_case_transitions` ✓ run |
| Close requires a disposition | same | `test_case_transitions` ✓ run, `test_cases` |
| Escalate, de-escalate, reopen require a reason | same | `test_case_transitions` ✓ run |
| Evidence withdrawn, never deleted, with a reason | `CaseEvidence` | `test_evidence` |
| Append-only notes and events | `CaseNote`, `CaseEvent` | `test_case_events` |
| Audit row per mutation, in the same transaction | `app/services/audit.py` | `test_audit` |
| No audit row for a no-op | endpoint handlers | `test_e2e_workflow` |
| Work queues | `app/api/v1/endpoints/dashboard.py` | `test_dashboard` |
| Metrics and trends | same | `test_dashboard` |
| PDF case report with limitations | `app/reports/` | `test_reports` |
| Report generation audited with a digest | `app/api/v1/endpoints/reports.py` | `test_reports` |
| Caveats travel in every scored response | all scored endpoints | `test_api_flow::TestCaveatContract` |

**Not covered.** No bulk actions, so a hundred false positives are a hundred
clicks. No saved views or filters. No assignment workload balancing. No
notifications: the queues grow silently and somebody has to look. No
case-to-case linking, so a network investigated as several cases has no
representation of being one thing.

---

## Cross-cutting

| Requirement | Implementation | Tests |
|---|---|---|
| Role-based access, four roles | `app/core/permissions.py` | `test_permissions` (hand-written matrix) |
| Named permissions, not role checks | `require_permission` | `test_permissions` |
| One pagination envelope | `app/api/deps.py` | `test_api_flow::TestPaginationContract` |
| One error envelope | `app/api/error_handlers.py` | `test_api_flow::TestErrorContract` |
| Request id on every response, echoed | `app/api/middleware/request_id.py` | `test_api_flow::TestRequestCorrelation` |
| Security headers | `app/api/middleware/security_headers.py` | `test_security_headers`, `test_api_flow` |
| Every header setting is declared | `app/core/config.py` | `test_api_flow` |
| Rate limiting | `app/auth/throttling.py` | `test_rate_limit` |
| One vocabulary, derived in one place | `app/core/vocabularies.py` | `test_ingestion` |
| Published schemas match the vocabulary | `scripts/check_schemas.py` | run directly ✓ |
| Synthetic-only enforcement | `app/ingestion/validators.py` | `test_ingestion_validation` |
| OpenAPI generates | `app/main.py` | `test_openapi` |

---

## Requirements deliberately not implemented

Not gaps. Decisions, each with a reason.

| Not implemented | Why |
|---|---|
| Automatic account freezing or blocking | ADR 0004. No capability, no enum value, five refused settings |
| Real-time streaming detection | Batch analysis, synchronously. ADR 0001 |
| A graph database | ADR 0002. Every traversal is bounded, which is a recursive query |
| Unbounded traversal | ADR 0007. A long path connects almost any two accounts and means nothing |
| Cross-institution data sharing | Out of scope, and a regulatory question before a technical one |
| Real data handling | ADR 0003, `docs/compliance-note.md` |
| Data subject access or erasure | Not implemented. Append-only tables and a right to erasure are in genuine tension |
| Model artefact upload | Arbitrary code execution. Refused if enabled |
| A fairness assessment | Not possible: the system holds no protected-attribute data, by design |

The last two rows of that table are the ones to read together with
`docs/model-card.md` and `docs/compliance-note.md`. They are the limits that
matter, and neither is closed by writing more code.
