---
name: Feature request
about: Propose a new capability for MULEGUARD that improves ingestion, detection, ML, graph analytics, complaints, cases, reports, UI, security, observability, or developer experience.
title: "[FEATURE]: "
labels: ["enhancement", "triage"]
assignees: []
---

<!--
=============================================================================
MULEGUARD Feature Request
=============================================================================

MULEGUARD is a synthetic-first, evidence-backed, human-in-the-loop financial
fraud investigation prototype.

Please do not include:
- real customer data;
- real account numbers;
- real card numbers;
- real phone numbers;
- real email addresses;
- passwords;
- bearer tokens;
- API keys;
- private keys;
- production secrets;
- real complaint narratives.

If this request involves a security vulnerability, do not open a public issue.
Report it privately to the project security contact.

Before submitting, read:
- README.md
- CONTRIBUTING.md
- docs/architecture.md
- docs/api.md
- docs/model-card.md
- docs/security.md
- docs/testing.md
=============================================================================
-->

## 1. Feature summary

<!--
Provide a concise description of the requested feature.
-->



## 2. Problem statement

<!--
What problem does this feature solve?
Why is the current behaviour insufficient?
-->



## 3. User / persona impact

<!--
Who benefits from this feature?
-->

- [ ] Fraud analyst
- [ ] Senior investigator
- [ ] Auditor
- [ ] Administrator
- [ ] ML / detection engineer
- [ ] Data engineer
- [ ] DevOps / deployment engineer
- [ ] Test engineer
- [ ] Technical writer
- [ ] Hackathon / academic reviewer
- [ ] Other:

Primary user story:

```text
As a <role>,
I want <capability>,
so that <outcome>.
```

## 4. MULEGUARD principle alignment

<!--
Explain how this feature preserves MULEGUARD's core principles.
-->

- [ ] Synthetic-first by default
- [ ] Evidence-backed
- [ ] Explainable
- [ ] Human-in-the-loop
- [ ] Auditable
- [ ] Reproducible
- [ ] Temporally correct
- [ ] Secure by default
- [ ] Graceful degradation
- [ ] No fake functionality
- [ ] Does not introduce automatic adverse customer action
- [ ] Does not claim real-world fraud-detection accuracy
- [ ] Does not claim regulatory compliance

If any principle is weakened or requires an exception, explain:

```text
None / explain
```

## 5. Scope classification

<!--
Help maintainers understand how large this request is.
-->

- [ ] Small — localized change, low integration risk
- [ ] Medium — multiple modules or API/UI changes
- [ ] Large — cross-cutting architectural change
- [ ] Breaking change
- [ ] Requires ADR
- [ ] Requires new dependency
- [ ] Requires database migration
- [ ] Requires ML artifact/training/evaluation changes
- [ ] Requires security review
- [ ] Requires performance review

## 6. Affected areas

<!--
Select all areas that may be affected.
-->

- [ ] Backend API
- [ ] Database / migrations
- [ ] Authentication / authorisation
- [ ] Synthetic data generation
- [ ] Ingestion / validation
- [ ] Feature engineering
- [ ] Rule engine
- [ ] Risk fusion / scoring
- [ ] Alerts / alert deduplication
- [ ] Graph analytics
- [ ] Money-trail search
- [ ] Complaint correlation
- [ ] ML training / inference / evaluation
- [ ] Model monitoring
- [ ] Case management
- [ ] Evidence / notes / events
- [ ] Audit logging
- [ ] PDF reports
- [ ] Dashboard
- [ ] Frontend UI
- [ ] Graph UI
- [ ] Model monitoring UI
- [ ] Docker / deployment
- [ ] CI
- [ ] Scripts
- [ ] Documentation
- [ ] Data schemas / samples
- [ ] Other:

## 7. Proposed solution

<!--
Describe the proposed feature in enough detail to evaluate it.
Include major workflows, inputs, outputs, and expected behaviour.
-->



## 8. Detailed behaviour

<!--
Describe the behaviour in operational terms.
Avoid vague language such as "smart", "AI-powered", or "advanced" unless the
mechanism is specified.
-->

### 8.1 Trigger / entry point

```text
Example: analyst opens account profile and selects "Run targeted analysis".
```

### 8.2 Inputs

| Input | Source | Required | Validation | Notes |
| ----- | ------ | -------: | ---------- | ----- |
|       |        |          |            |       |

### 8.3 Processing

```text
Describe the service, rule, model, graph, correlation, or workflow logic.
```

### 8.4 Outputs

| Output | Destination | Persistence | Visibility | Notes |
| ------ | ----------- | ----------- | ---------- | ----- |
|        |             |             |            |       |

### 8.5 Failure behaviour

```text
Describe what happens on invalid input, missing data, timeout, permission denial,
dependency failure, or partial completion.
```

## 9. API design

<!--
Complete this section if backend API changes are expected.
-->

- [ ] No API changes
- [ ] New endpoint
- [ ] Modified endpoint
- [ ] Deprecated endpoint
- [ ] New request/response schema
- [ ] New permission dependency
- [ ] New pagination/filtering behaviour
- [ ] New audit event

Proposed endpoints:

| Method | Path | Purpose | Permission | Idempotent? | Notes |
| ------ | ---- | ------- | ---------- | ----------- | ----- |
|        |      |         |            |             |       |

Example request:

```json
{}
```

Example response:

```json
{}
```

Error responses:

| Status | Code | Meaning |
| -----: | ---- | ------- |
|    400 |      |         |
|    401 |      |         |
|    403 |      |         |
|    404 |      |         |
|    422 |      |         |
|    429 |      |         |
|    500 |      |         |

API design checks:

- [ ] Uses `/api/v1`
- [ ] Typed Pydantic request/response models
- [ ] Raw ORM objects are not returned
- [ ] Invalid input returns useful 4xx responses
- [ ] Permission checks are enforced server-side
- [ ] List endpoints are paginated and stably ordered
- [ ] Expensive operations are bounded
- [ ] Error responses do not leak stack traces or secrets
- [ ] OpenAPI documentation will be updated
- [ ] `docs/api.md` will be updated

## 10. Database / persistence design

<!--
Complete this section if persisted state changes are expected.
-->

- [ ] No schema change
- [ ] New table
- [ ] New column
- [ ] New index
- [ ] New constraint
- [ ] New relationship
- [ ] New enum/status value
- [ ] New migration required
- [ ] Backfill required
- [ ] Data retention policy change

Proposed entities/fields:

| Entity | Field | Type | Nullable | Default | Index | Purpose |
| ------ | ----- | ---- | -------: | ------- | ----- | ------- |
|        |       |      |          |         |       |         |

Migration considerations:

- [ ] Works from empty database
- [ ] Downgrade path considered
- [ ] Destructive change avoided or explicitly justified
- [ ] UTC timestamps used
- [ ] Monetary amounts use Decimal/NUMERIC where applicable
- [ ] Constraints prevent invalid evidence references
- [ ] Indexes support expected query paths
- [ ] `docs/data-dictionary.md` will be updated

## 11. Synthetic data / ingestion impact

<!--
Complete this section if the feature affects generated or imported data.
-->

- [ ] No synthetic data impact
- [ ] New generator option
- [ ] New synthetic scenario
- [ ] New entity type
- [ ] New relationship type
- [ ] New complaint field
- [ ] New ingestion validation rule
- [ ] New JSON schema/sample update
- [ ] New CSV import behaviour, if supported

Leakage and safety checks:

- [ ] Synthetic ground-truth labels remain isolated from model inputs
- [ ] Fraud-ring IDs do not leak into predictor features
- [ ] Generated data remains clearly synthetic
- [ ] Deterministic seeding remains preserved
- [ ] Invalid/duplicate records are rejected predictably
- [ ] Batch import reports accepted/rejected/duplicated/skipped counts
- [ ] Row-level errors do not leak secrets
- [ ] `data/schemas/` and `data/samples/` will be updated if contracts change

## 12. Feature engineering impact

<!--
Complete this section if behavioural features change.
-->

- [ ] No feature changes
- [ ] New feature
- [ ] Modified feature definition
- [ ] New time window
- [ ] New missing-value policy
- [ ] New graph-derived feature
- [ ] New feature snapshot
- [ ] Feature schema version bump required

Temporal correctness checks:

- [ ] Features use only information available at `as_of`
- [ ] Future transactions are not used for past assessments
- [ ] Future complaints are not used as predictors
- [ ] Future investigation outcomes are not used as predictors
- [ ] Ground-truth labels are not used as predictors
- [ ] Boundary conditions are specified
- [ ] Zero/missing denominators are handled explicitly
- [ ] Feature names, units, windows, and definitions will be documented

## 13. Rule engine impact

<!--
Complete this section if detection rules or thresholds change.
-->

- [ ] No rule changes
- [ ] New rule
- [ ] Modified rule
- [ ] New threshold
- [ ] New evidence type
- [ ] New severity mapping
- [ ] Rule version bump required

Rule design checks:

- [ ] Rule is separate and testable
- [ ] Thresholds are configurable
- [ ] Rule result includes:
  - rule code;
  - human-readable title;
  - triggered status;
  - measured value;
  - threshold;
  - severity/priority;
  - explanation;
  - evidence references;
  - rule version/configuration metadata
- [ ] Evidence references point to real persisted records
- [ ] Positive, negative, and boundary tests are planned
- [ ] Demo thresholds are not described as universal banking thresholds
- [ ] Rule cannot declare guilt on its own

## 14. Graph analytics / money-trail impact

<!--
Complete this section if graph behaviour changes.
-->

- [ ] No graph changes
- [ ] New graph metric
- [ ] New neighbourhood expansion rule
- [ ] New community detection behaviour
- [ ] New cycle detection behaviour
- [ ] New money-trail search option
- [ ] New graph serialization format
- [ ] New graph UI interaction

Safety and correctness checks:

- [ ] Graph queries remain bounded
- [ ] Root account or constrained source/destination is required
- [ ] Hop limits are enforced
- [ ] Node/edge limits are enforced
- [ ] Path result limits are enforced
- [ ] Date-span limits are enforced
- [ ] Multiple transactions between same account pair are preserved
- [ ] Edge evidence preserves transaction ID, amount, currency, status, timestamp
- [ ] Only qualifying completed statuses represent completed money movement
- [ ] Candidate money trails respect direction
- [ ] Candidate money trails respect chronological ordering
- [ ] Cycle prevention behaviour is explicit
- [ ] Same-timestamp policy is documented
- [ ] Results are labelled candidate flow paths, not exact currency-unit tracing
- [ ] Graph proximity is not treated as proof of wrongdoing
- [ ] Performance impact is assessed

## 15. Complaint correlation impact

<!--
Complete this section if complaint matching changes.
-->

- [ ] No complaint correlation changes
- [ ] New match tier
- [ ] New normalisation rule
- [ ] New entity association method
- [ ] New temporal association method
- [ ] New narrative extraction behaviour
- [ ] New review-state workflow

Matching integrity checks:

- [ ] Exact matches remain separated from inferred associations
- [ ] Match tier is visible
- [ ] Match method is visible
- [ ] Confidence/provenance is visible
- [ ] Raw complaint facts are preserved
- [ ] Normalised values are stored separately from source values
- [ ] Missing references are handled gracefully
- [ ] Duplicate complaints are handled predictably
- [ ] Ambiguous entity matches are labelled as inferred
- [ ] Narrative extraction, if used, preserves evidence span and method
- [ ] Fuzzy text matches are not treated as verified evidence

## 16. ML / model impact

<!--
Complete this section if ML training, inference, evaluation, artifacts, or explanations change.
-->

- [ ] No ML changes
- [ ] New model type
- [ ] Modified training pipeline
- [ ] Modified feature schema
- [ ] Modified split strategy
- [ ] Modified evaluation metrics
- [ ] Modified artifact format
- [ ] Modified model service
- [ ] Modified fallback behaviour
- [ ] Modified explainability output
- [ ] Model card update required
- [ ] New dependency required

ML safety checks:

- [ ] Training remains reproducible with fixed seed
- [ ] Feature schema is consistent between training and inference
- [ ] Preprocessing is fitted only on training data
- [ ] Leakage controls are preserved
- [ ] Ground-truth labels are not predictor features
- [ ] Fraud-ring IDs are not predictor features
- [ ] Future investigation outcomes are not predictor features
- [ ] Missing artifact fallback remains explicit
- [ ] Corrupt/incompatible artifact handling remains safe
- [ ] Arbitrary user-uploaded model deserialization is not introduced
- [ ] Metrics are real computed outputs
- [ ] Undefined metrics are reported honestly
- [ ] Scores are labelled appropriately
- [ ] Heuristic fallback is not presented as model probability
- [ ] Calibration is not claimed unless implemented and documented
- [ ] Explanations cite real feature values, rules, graph evidence, and complaint matches
- [ ] SHAP or other optional explainability remains non-blocking if unavailable

## 17. Risk fusion / alert impact

<!--
Complete this section if scoring, prioritisation, or alerts change.
-->

- [ ] No risk/alert changes
- [ ] New signal source
- [ ] Modified score formula
- [ ] Modified weights
- [ ] Modified normalization
- [ ] Modified risk bands
- [ ] New alert type
- [ ] Modified alert deduplication
- [ ] Modified alert triage workflow
- [ ] Score version bump required

Risk/alert checks:

- [ ] Score formula and version are documented
- [ ] Weights and normalization live in configuration
- [ ] Missing signals are handled explicitly
- [ ] Shared-entity links do not automatically escalate all connected accounts to maximum risk
- [ ] Neighbour-alert signal is capped and limited
- [ ] Alerts remain evidence-backed
- [ ] Duplicate open alerts are avoided across repeated runs
- [ ] Score history is retained where required
- [ ] Scoring mode is visible
- [ ] Model version is visible
- [ ] Alert triage actions are audited where material
- [ ] UI/API language avoids "confirmed mule" or guilt claims

## 18. Case management / evidence / audit / report impact

<!--
Complete this section if investigation workflow changes.
-->

- [ ] No case/evidence/audit/report changes
- [ ] New case state
- [ ] New case transition
- [ ] New case role permission
- [ ] New evidence type
- [ ] New note behaviour
- [ ] New audit action
- [ ] New report section
- [ ] New report format
- [ ] New report download behaviour

Workflow integrity checks:

- [ ] Case state transitions are centrally validated
- [ ] Illegal transitions are rejected
- [ ] Evidence references point to validated existing records
- [ ] Arbitrary URLs or unchecked identifiers are not accepted as evidence
- [ ] Case history remains append-only
- [ ] Reopen appends an event rather than erasing history
- [ ] Notes are timestamped and attributed
- [ ] Material actions are auditable
- [ ] Audit records do not leak passwords, tokens, or unnecessary personal data
- [ ] PDF report is generated from persisted data
- [ ] Report includes synthetic-data disclaimer
- [ ] Report includes limitations
- [ ] Report includes evidence references
- [ ] Report download checks authorisation
- [ ] Missing/expired case errors are handled safely
- [ ] Report filenames are sanitized
- [ ] Path traversal is prevented

## 19. Frontend / UI impact

<!--
Complete this section if UI changes are expected.
-->

- [ ] No UI changes
- [ ] New page
- [ ] New panel
- [ ] New table/filter/sort/pagination behaviour
- [ ] New form/modal/drawer
- [ ] New chart
- [ ] New graph interaction
- [ ] New download/export action
- [ ] New role-gated control
- [ ] New accessibility improvement

UI quality checks:

- [ ] API request/response shapes are typed
- [ ] Raw `fetch` calls are not scattered through components
- [ ] Reusable components are used where appropriate
- [ ] Loading states are implemented
- [ ] Empty states are implemented
- [ ] Error states are implemented
- [ ] Permission-denied states are implemented
- [ ] Forms validate and show server errors
- [ ] Filters either work or are clearly disabled with explanation
- [ ] Charts derive from backend data
- [ ] No hardcoded fake metrics or chart series are introduced
- [ ] Synthetic-data banner remains visible in demo mode
- [ ] Risk scores are labelled as priority scores, not probabilities
- [ ] Exact complaint matches are visually distinct from inferred associations
- [ ] High-risk states use text as well as colour
- [ ] Graph views include legend and edge-direction indication
- [ ] Cytoscape resources are cleaned up
- [ ] Keyboard focus and accessible labels are considered
- [ ] Responsive behaviour is considered
- [ ] TypeScript checks and production build are planned

## 20. Security and privacy impact

<!--
Complete this section carefully.
Do not disclose exploitable vulnerability details publicly.
-->

- [ ] No security impact expected
- [ ] New authentication behaviour
- [ ] New authorisation rule
- [ ] New role or permission
- [ ] New secret/environment variable
- [ ] New input validation
- [ ] New file upload/download
- [ ] New report generation
- [ ] New graph query surface
- [ ] New ML artifact loading
- [ ] New external dependency
- [ ] New logging behaviour
- [ ] New audit behaviour
- [ ] Security review required

Security checks:

- [ ] No real customer data is introduced
- [ ] No secrets are introduced
- [ ] SQL remains parameterised
- [ ] Input validation is enforced
- [ ] Pagination/filter/graph/path limits are enforced
- [ ] Authentication and role checks are enforced server-side
- [ ] Frontend hiding is not treated as the security boundary
- [ ] Sensitive values are not logged
- [ ] Audit redaction is preserved
- [ ] Path traversal protections are preserved
- [ ] CORS remains restricted/configurable
- [ ] Secure headers remain configured where practical
- [ ] Upload/request size limits are enforced
- [ ] Model artifacts are loaded only from controlled local paths
- [ ] User-uploaded model deserialization is not allowed
- [ ] Automatic adverse customer action is not introduced

## 21. Observability impact

<!--
Complete this section if logging, metrics, tracing, or run state changes.
-->

- [ ] No observability changes
- [ ] New structured log event
- [ ] New request/correlation ID behaviour
- [ ] New analysis run state
- [ ] New performance metric
- [ ] New health/readiness check
- [ ] New error taxonomy
- [ ] New audit event

Observability checks:

- [ ] Logs remain structured
- [ ] Passwords/tokens/secrets are not logged
- [ ] Full sensitive complaint narratives are not logged unnecessarily
- [ ] Analysis runs expose started/finished time, processed count, error count, model version, and scoring mode where relevant
- [ ] Expensive operations have timeouts/limits
- [ ] Errors are distinguishable as validation vs unexpected server failures
- [ ] Client error responses do not expose stack traces

## 22. Performance impact

<!--
Complete this section if the feature may affect local performance.
-->

- [ ] No expected performance impact
- [ ] New database query
- [ ] New batch computation
- [ ] New graph computation
- [ ] New ML inference
- [ ] New report generation
- [ ] New frontend rendering load
- [ ] New caching behaviour

Performance checks:

- [ ] List endpoints remain paginated
- [ ] Database indexes are considered
- [ ] Graph operations remain bounded
- [ ] Expensive computations are not repeated per dashboard row unnecessarily
- [ ] Caching keys include dataset/version/time-window context if used
- [ ] Cache invalidation is documented
- [ ] Browser graph rendering remains bounded
- [ ] Large datasets remain optional, not default startup behaviour

## 23. Dependencies

<!--
Complete this section if new packages or services are required.
-->

- [ ] No new dependencies
- [ ] New Python dependency
- [ ] New npm dependency
- [ ] New Docker image dependency
- [ ] New external service
- [ ] New infrastructure component

If new dependencies are required:

| Dependency | Ecosystem | Purpose | License | Security impact | Why existing dependencies are insufficient |
| ---------- | --------- | ------- | ------- | --------------- | ------------------------------------------ |
|            |           |         |         |                 |                                            |

Guardrails:

- [ ] Dependency is widely maintained
- [ ] Dependency is necessary, not decorative
- [ ] Dependency does not introduce Kafka/Kubernetes/microservice complexity unless justified
- [ ] Dependency does not introduce deep learning/GNN/LLM dependency unless explicitly approved
- [ ] Lockfiles/requirements will be updated
- [ ] CI dependency installation remains deterministic

## 24. Environment configuration impact

<!--
Complete this section if new settings are required.
-->

- [ ] No environment changes
- [ ] New backend variable
- [ ] New frontend variable
- [ ] New Docker Compose variable
- [ ] New secret requirement
- [ ] New feature flag
- [ ] `.env.example` update required

Proposed variables:

| Variable | Default | Required in production? | Purpose | Security-sensitive? |
| -------- | ------- | ----------------------: | ------- | ------------------: |
|          |         |                         |         |                     |

Configuration checks:

- [ ] Safe local defaults are provided
- [ ] Production-like environments fail safely if required secrets are missing
- [ ] Demo-only features are disabled by default for production-like environments
- [ ] `.env.example` contains placeholders only
- [ ] `docs/configuration.md` or equivalent docs will be updated

## 25. Alternatives considered

<!--
Describe other possible designs and why the proposed one is preferable.
-->

| Alternative | Pros | Cons | Reason not chosen |
| ----------- | ---- | ---- | ----------------- |
|             |      |      |                   |

## 26. Out of scope

<!--
Explicitly list what this feature request does not include.
-->

- [ ] Real bank integration
- [ ] Real payment rail integration
- [ ] Real customer data
- [ ] Live cybercrime database integration
- [ ] Deanonymisation
- [ ] Covert surveillance
- [ ] Automatic account freezing
- [ ] Automatic payment blocking
- [ ] Blacklisting
- [ ] Adverse automated customer action
- [ ] Production regulatory compliance
- [ ] Real-world fraud-detection accuracy claim
- [ ] Microservice split
- [ ] Kafka/Kubernetes/feature store/GNN/LLM dependency
- [ ] Other:

## 27. Risks and mitigations

<!--
Identify risks introduced by the feature.
-->

| Risk | Likelihood | Impact | Mitigation |
| ---- | ---------: | -----: | ---------- |
|      |            |        |            |

Potential risk categories:

- [ ] Misleading investigative evidence
- [ ] Label leakage
- [ ] Future-information leakage
- [ ] Unbounded graph query
- [ ] Browser freeze from large graph
- [ ] Privilege escalation
- [ ] Audit bypass
- [ ] Evidence integrity failure
- [ ] Report fabrication
- [ ] Secret exposure
- [ ] Performance degradation
- [ ] Dependency supply-chain risk
- [ ] Accessibility regression
- [ ] Documentation drift

## 28. Rollout plan

<!--
Describe how this feature should be introduced safely.
-->

- [ ] Behind feature flag
- [ ] Local demo only
- [ ] Admin-only initially
- [ ] Analyst-only initially
- [ ] Requires migration
- [ ] Requires model retraining
- [ ] Requires synthetic dataset regeneration
- [ ] Requires documentation update
- [ ] Requires demo walkthrough update
- [ ] Requires CI update
- [ ] Requires Docker Compose update

Suggested rollout steps:

```text
1.
2.
3.
```

## 29. Testing plan

<!--
List tests required before this feature can be accepted.
-->

- [ ] Unit test
- [ ] API test
- [ ] Integration workflow test
- [ ] End-to-end workflow test
- [ ] Graph test
- [ ] ML leakage test
- [ ] ML fallback test
- [ ] ML artifact corruption/mismatch test
- [ ] Case transition test
- [ ] Evidence validation test
- [ ] Audit test
- [ ] Report test
- [ ] Frontend typecheck
- [ ] Frontend production build
- [ ] Component test
- [ ] Accessibility test
- [ ] Docker smoke test
- [ ] CI test

Required scenarios:

| Scenario                          | Expected result |
| --------------------------------- | --------------- |
| Happy path                        |                 |
| Invalid input                     |                 |
| Missing data                      |                 |
| Permission denied                 |                 |
| Unauthenticated access            |                 |
| Not found                         |                 |
| Boundary condition                |                 |
| Deterministic rerun               |                 |
| Idempotent rerun where applicable |                 |
| Failure/degradation               |                 |

## 30. Acceptance criteria

<!--
Define objective criteria for this feature to be considered complete.
-->

- [ ]
- [ ]
- [ ]
- [ ]

Example format:

```text
- Given a seeded synthetic account with scenario SCN-RAPID-PASS-THROUGH-001,
  when analysis is run,
  then the account receives an evidence-backed indicator referencing the
  triggering transactions.
```

## 31. Documentation impact

<!--
List documentation that must be updated.
-->

- [ ] `README.md`
- [ ] `docs/api.md`
- [ ] `docs/architecture.md`
- [ ] `docs/data-dictionary.md`
- [ ] `docs/model-card.md`
- [ ] `docs/security.md`
- [ ] `docs/threat-model.md`
- [ ] `docs/testing.md`
- [ ] `docs/deployment.md`
- [ ] `docs/configuration.md`
- [ ] `docs/demo-walkthrough.md`
- [ ] `docs/requirements-traceability.md`
- [ ] `docs/user-guide.md`
- [ ] `docs/admin-guide.md`
- [ ] `docs/runbooks/*`
- [ ] `CHANGELOG.md`
- [ ] ADR required
- [ ] No documentation impact expected

## 32. Requirements traceability

<!--
If this feature maps to a project requirement, reference it.
-->

| Requirement / problem statement item | How this feature satisfies it |
| ------------------------------------ | ----------------------------- |
|                                      |                               |

## 33. Example workflow

<!--
Provide a concrete synthetic example.
Do not use real customer data.
-->

```text
1. Seed synthetic dataset with SEED_RANDOM_SEED=42.
2. Log in as analyst.
3. Run analysis.
4. Open alert for synthetic scenario ...
5. Inspect evidence ...
6. Create case ...
7. Generate report ...
```

## 34. Open questions

<!--
List decisions that still need maintainer input.
-->

- [ ]
- [ ]
- [ ]

## 35. Additional context

<!--
Add links, references, mockups, or prior discussion.
Do not include secrets or real data.
-->