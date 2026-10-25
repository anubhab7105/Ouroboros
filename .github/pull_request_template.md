<!--
=============================================================================
MULEGUARD Pull Request Template
=============================================================================

Suggested PR title format:

    type(scope): short summary

Examples:

    feat(graph): add bounded temporal money-trail search
    fix(ingestion): reject duplicate transaction references
    security(auth): enforce login throttling
    docs(model-card): clarify synthetic evaluation limitations
    test(cases): cover illegal state transitions

Delete sections that are not relevant, but do not remove mandatory checklist
items. If a check could not be run, state exactly why.
=============================================================================
-->

## 1. Summary

<!--
Provide a concise summary of the change.
Explain what problem this solves and why the change is safe for MULEGUARD.
-->

## 2. Related issue

Fixes #

<!--
If there is no issue, explain why the change is being made.
For major changes, an issue should usually exist first.
-->

## 3. Change type

- [ ] Feature
- [ ] Bug fix
- [ ] Security fix or hardening
- [ ] Performance improvement
- [ ] Refactor
- [ ] Test improvement
- [ ] Documentation
- [ ] Build / CI / Docker
- [ ] Synthetic data generator change
- [ ] ML / evaluation / explanation change
- [ ] Breaking change
- [ ] Dependency change
- [ ] Other:

## 4. Affected areas

- [ ] Backend API
- [ ] Database / migrations
- [ ] Synthetic data / ingestion
- [ ] Feature engineering
- [ ] Rule engine
- [ ] Risk fusion / alerts
- [ ] Graph analytics / money trails
- [ ] Complaint correlation
- [ ] ML training / inference / evaluation
- [ ] Case management
- [ ] Evidence / notes / events
- [ ] Audit
- [ ] PDF reports
- [ ] Authentication / authorisation
- [ ] Frontend UI
- [ ] Graph UI
- [ ] Dashboard / charts
- [ ] Model monitoring
- [ ] Docker / deployment
- [ ] CI
- [ ] Scripts
- [ ] Documentation
- [ ] Other:

## 5. Problem and solution

### Problem

<!--
What issue, bug, gap, or requirement is being addressed?
-->

### Solution

<!--
How does this PR solve the problem?
Mention important design decisions and alternatives considered.
-->

## 6. Implementation details

<!--
Describe the main files/modules changed and why.
If the change touches business logic, explain the source of truth for the rule,
threshold, score, state machine, or validation behaviour.
-->

## 7. MULEGUARD safety and product principles

- [ ] This PR does not introduce real customer data.
- [ ] This PR does not connect to real banking systems or payment rails.
- [ ] This PR does not implement automatic account freezing, payment blocking, blacklisting, or adverse customer action.
- [ ] Alerts, scores, graph relationships, and complaint associations remain investigative leads only.
- [ ] Synthetic data remains clearly synthetic.
- [ ] No fake functionality has been introduced.
- [ ] Buttons, filters, forms, charts, exports, and state transitions either work or are clearly disabled with explanation.
- [ ] No hardcoded metrics or fake chart series were added when real backend data is available.
- [ ] If metrics are unavailable, the UI/API says so instead of fabricating values.

## 8. Verification

<!--
List the exact commands you ran and their actual results.
Do not claim a check passed if it was not run.
-->

| Check               | Command                             | Result | Notes |
| ------------------- | ----------------------------------- | ------ | ----- |
| Backend tests       | `pytest backend/tests`              |        |       |
| Backend lint        | `ruff check backend`                |        |       |
| Backend typecheck   | `mypy backend/app`                  |        |       |
| Frontend typecheck  | `npm run typecheck`                 |        |       |
| Frontend build      | `npm run build`                     |        |       |
| Frontend lint       | `npm run lint`                      |        |       |
| Docker build        | `docker compose build`              |        |       |
| Docker startup      | `docker compose up`                 |        |       |
| Seed synthetic data | `make seed`                         |        |       |
| Run analysis        | `POST /api/v1/analysis/run`         |        |       |
| Smoke check         | `curl http://localhost:8000/health` |        |       |
| Other               |                                     |        |       |

If a check was blocked by the environment, explain:

```text
None / explain here
```

## 9. Automated tests

### Tests added or updated

<!--
List tests added or updated.
For each meaningful behaviour change, there should be a test.
-->

### Tests not added

<!--
If no tests were added, explain why.
-->

### Mandatory test coverage considered

- [ ] Positive case
- [ ] Negative case
- [ ] Boundary case
- [ ] Invalid input
- [ ] Not found
- [ ] Unauthenticated access
- [ ] Authenticated but forbidden access
- [ ] Pagination where relevant
- [ ] Deterministic fixture data
- [ ] No dependence on live external APIs

## 10. Backend API changes

If API endpoints were added, changed, or removed:

| Endpoint | Method | Change | Permission | OpenAPI updated | Tests updated |
| -------- | ------ | ------ | ---------- | --------------- | ------------- |
|          |        |        |            |                 |               |

- [ ] Request/response schemas are typed.
- [ ] Raw ORM objects are not returned directly.
- [ ] Invalid input returns useful 4xx responses.
- [ ] Permission checks are enforced server-side.
- [ ] Pagination and stable ordering are used where relevant.
- [ ] Error responses do not leak stack traces or sensitive data.
- [ ] Audit events are emitted where material actions occur.

If no API changes:

```text
N/A
```

## 11. Database and migration changes

- [ ] No schema change
- [ ] Schema change included
- [ ] Alembic migration included
- [ ] Migration works from empty database
- [ ] Downgrade considered
- [ ] Indexes considered for query paths
- [ ] Data dictionary updated

Migration notes:

```text
None / explain
```

## 12. Synthetic data and ingestion changes

If synthetic generation or ingestion changed:

- [ ] Generator remains deterministic for a fixed seed.
- [ ] Synthetic ground-truth labels remain isolated from model inputs.
- [ ] No fraud-ring ID or label leaks into predictor features.
- [ ] Ingestion validation remains strict.
- [ ] Duplicate handling remains predictable.
- [ ] Accepted/rejected/duplicated/skipped counts remain accurate.
- [ ] Row-level errors do not leak secrets.
- [ ] JSON schemas and samples updated if contracts changed.

Notes:

```text
None / explain
```

## 13. Feature engineering changes

If behavioural features changed:

- [ ] Features remain point-in-time correct.
- [ ] Future transactions/complaints/outcomes are not used for past assessments.
- [ ] Window semantics are explicit.
- [ ] Missing-value policy is documented.
- [ ] Feature schema version updated if required.
- [ ] Feature documentation/data dictionary updated.
- [ ] Boundary conditions tested.

Notes:

```text
None / explain
```

## 14. Rule engine changes

If rules or thresholds changed:

| Rule code | Change | Threshold change | Evidence updated | Tests updated |
| --------- | ------ | ---------------- | ---------------- | ------------- |
|           |        |                  |                  |               |

- [ ] Rules remain modular and testable.
- [ ] Rule results include measured value, threshold, explanation, and evidence.
- [ ] Evidence references point to real persisted records.
- [ ] Positive/negative/boundary tests exist for changed rules.
- [ ] Demo thresholds are not described as universal banking thresholds.

Notes:

```text
None / explain
```

## 15. Graph and money-trail changes

If graph analytics, neighbourhood expansion, or money trails changed:

- [ ] Graph queries remain bounded.
- [ ] Root account or constrained query is required.
- [ ] Hop, node, edge, path, and date-span limits remain enforced.
- [ ] Candidate money trails respect direction and chronological order.
- [ ] Cycle prevention behaviour remains correct.
- [ ] Path evidence includes ordered transaction references.
- [ ] Results are described as candidate flow paths, not exact currency-unit tracing.
- [ ] Graph proximity is not presented as proof of wrongdoing.

Notes:

```text
None / explain
```

## 16. Complaint correlation changes

If complaint matching changed:

- [ ] Exact matches remain separated from inferred associations.
- [ ] Match tier/method/provenance remains visible.
- [ ] Raw complaint facts remain preserved.
- [ ] Normalised values remain separate from raw values.
- [ ] Missing references are handled gracefully.
- [ ] Ambiguous matches are clearly labelled as inferred.
- [ ] Tests cover duplicate/missing/ambiguous cases.

Notes:

```text
None / explain
```

## 17. ML and model transparency changes

If ML training, inference, evaluation, artifacts, or explanations changed:

- [ ] Training remains reproducible with fixed seed.
- [ ] Feature schema consistency between training and inference is preserved.
- [ ] Preprocessing is fitted only on training data.
- [ ] Leakage controls remain intact.
- [ ] Ground-truth labels/scenario IDs are not predictor features.
- [ ] Missing artifact fallback remains explicit.
- [ ] Corrupt/incompatible artifact handling remains safe.
- [ ] Arbitrary user-uploaded model deserialization is not introduced.
- [ ] Metrics are real computed outputs.
- [ ] Undefined metrics are reported honestly.
- [ ] Model card updated if model behaviour/metrics changed.
- [ ] Explanations cite real features/rules/evidence.

Scoring mode impact:

```text
trained_model / heuristic_fallback / N/A
```

Notes:

```text
None / explain
```

## 18. Risk fusion and alert changes

If risk scoring, alerts, deduplication, or analysis runs changed:

- [ ] Score formula/version documented if changed.
- [ ] Weights/normalization remain configurable.
- [ ] Missing signals are handled explicitly.
- [ ] Shared-entity links do not automatically escalate all connected accounts to maximum risk.
- [ ] Alerts remain evidence-backed.
- [ ] Duplicate open alert prevention remains intact.
- [ ] Scoring mode and model version remain visible.
- [ ] Alert triage actions remain audited where material.

Notes:

```text
None / explain
```

## 19. Case management, evidence, audit, and report changes

If cases, evidence, notes, events, audit, or PDF reports changed:

- [ ] Case state transitions remain centrally validated.
- [ ] Illegal transitions are rejected.
- [ ] Evidence references point to validated existing records.
- [ ] Arbitrary URLs or unchecked identifiers are not accepted as evidence.
- [ ] Case history remains append-only.
- [ ] Notes remain timestamped and attributed.
- [ ] Material actions remain auditable.
- [ ] PDF report remains generated from persisted data.
- [ ] Report includes synthetic-data disclaimer and limitations.
- [ ] Report download checks authorisation and missing-case handling.

Notes:

```text
None / explain
```

## 20. Frontend and UI changes

If UI changed:

- [ ] TypeScript checks pass.
- [ ] Production build passes.
- [ ] API shapes are typed.
- [ ] No raw `fetch` calls scattered through components.
- [ ] Reusable components used where appropriate.
- [ ] Loading states implemented.
- [ ] Empty states implemented.
- [ ] Error states implemented.
- [ ] Permission-denied states implemented.
- [ ] Forms validate and show server errors.
- [ ] Filters either work or are clearly disabled with explanation.
- [ ] Charts derive from backend data.
- [ ] Synthetic-data banner remains visible in demo mode.
- [ ] Risk scores are labelled as priority scores, not probabilities.
- [ ] Exact complaint matches are visually distinct from inferred associations.
- [ ] High-risk states use text as well as colour.
- [ ] Graph views include legend and edge-direction indication.
- [ ] Cytoscape resources are cleaned up.
- [ ] No hardcoded fake data was added.

Screenshots or recordings:

```text
Add screenshots or recordings here, or write N/A
```

## 21. Security and privacy

- [ ] No secrets were added.
- [ ] No real credentials were added.
- [ ] No real customer data was added.
- [ ] Input validation remains enforced.
- [ ] SQL remains parameterised.
- [ ] Pagination/filter/graph/path limits remain enforced.
- [ ] Authentication and role checks remain server-side.
- [ ] Sensitive values are not logged.
- [ ] Audit redaction remains intact.
- [ ] Path traversal protections remain intact.
- [ ] CORS remains restricted/configurable.
- [ ] Secure headers remain configured where practical.
- [ ] Development users remain clearly non-production.

Security review required?

- [ ] Yes
- [ ] No

If yes, explain:

```text
None / explain
```

## 22. Observability and performance

- [ ] Logging remains structured and safe.
- [ ] Request IDs/correlation IDs preserved where applicable.
- [ ] Analysis run observability preserved.
- [ ] No unbounded queries introduced.
- [ ] No expensive graph operations introduced without limits.
- [ ] Caching, if added, includes invalidation and dataset/version sensitivity.
- [ ] Dashboard/report performance remains acceptable for local demo data.

Notes:

```text
None / explain
```

## 23. Documentation and changelog

- [ ] `README.md` updated if setup/usage changed.
- [ ] `docs/api.md` updated if API changed.
- [ ] `docs/data-dictionary.md` updated if entities/fields changed.
- [ ] `docs/model-card.md` updated if ML behaviour/metrics changed.
- [ ] `docs/security.md` updated if security behaviour changed.
- [ ] `docs/testing.md` updated if test strategy changed.
- [ ] `docs/deployment.md` updated if Docker/env changed.
- [ ] `docs/demo-walkthrough.md` updated if demo flow changed.
- [ ] `docs/requirements-traceability.md` updated if requirement coverage changed.
- [ ] `CHANGELOG.md` updated under `[Unreleased]`.

Notes:

```text
None / explain
```

## 24. Dependency changes

If dependencies were added, removed, upgraded, or pinned:

| Dependency | Version/change | Reason | Security impact | License checked |
| ---------- | -------------- | ------ | --------------- | --------------- |
|            |                |        |                 |                 |

- [ ] No unnecessary dependencies added.
- [ ] Lockfiles/requirements updated.
- [ ] Dependency justification provided.
- [ ] Security impact considered.

If no dependency changes:

```text
N/A
```

## 25. Environment configuration changes

If environment variables changed:

| Variable | Added/changed/removed | Purpose | `.env.example` updated |
| -------- | --------------------- | ------- | ---------------------- |
|          |                       |         |                        |

- [ ] `.env.example` updated.
- [ ] No real secrets included.
- [ ] Safe defaults preserved.
- [ ] Production-like behaviour fails safely if required secrets are missing.

## 26. Breaking changes and migration notes

- [ ] No breaking changes
- [ ] Breaking changes included

Breaking change details:

```text
None / explain
```

Migration steps:

```text
None / explain
```

## 27. Known limitations and unverified areas

<!--
Be honest.
List anything that is incomplete, environment-blocked, or not fully verified.
-->

```text
None / explain
```

## 28. AI-assisted contribution disclosure

If AI assistance was used in a material way:

- [ ] AI assistance was used.
- [ ] AI assistance was reviewed and verified by the contributor.
- [ ] No secrets or real data were provided to the AI tool.

Explain which parts were AI-assisted:

```text
None / explain
```

## 29. Reviewer focus areas

<!--
Tell reviewers where to look carefully.
Examples: temporal correctness, leakage prevention, RBAC, graph limits, PDF data integrity.
-->

```text
None / explain
```

## 30. Final contributor checklist

Before requesting review, confirm:

- [ ] I read `CONTRIBUTING.md`.
- [ ] I inspected existing code before changing it.
- [ ] I preserved useful working code.
- [ ] The application remains runnable.
- [ ] I did not introduce fake functionality.
- [ ] I did not introduce fake metrics or hardcoded chart data.
- [ ] I did not introduce real customer data.
- [ ] I did not introduce secrets.
- [ ] I did not introduce automatic adverse customer actions.
- [ ] I did not introduce unsupported production claims.
- [ ] I added or updated tests where behaviour changed.
- [ ] I added or updated documentation where behaviour changed.
- [ ] I updated `CHANGELOG.md` under `[Unreleased]`.
- [ ] I ran relevant local checks.
- [ ] I reported blocked or unrun checks honestly.
- [ ] I am ready for review.