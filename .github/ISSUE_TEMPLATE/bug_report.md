---
name: Bug report
about: Report a defect in MULEGUARD affecting ingestion, detection, ML, graph analytics, complaints, cases, reports, UI, security, or deployment.
title: "[BUG]: "
labels: ["bug", "triage"]
assignees: []
---

<!--
=============================================================================
MULEGUARD Bug Report
=============================================================================

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

MULEGUARD is a synthetic-first prototype. If you are testing with synthetic
data, include the synthetic scenario ID or generated record ID instead.

If this is a security vulnerability, do not open a public issue.
Use GitHub's private vulnerability reporting feature when available; see [SECURITY.md](../../SECURITY.md). Do not include exploit details in this public issue.
=============================================================================
-->

## 1. Bug summary

<!--
Provide a concise description of the bug.
-->



## 2. Expected behaviour

<!--
Describe what should happen according to the product requirements or documented behaviour.
-->



## 3. Actual behaviour

<!--
Describe what actually happens.
-->



## 4. Severity

<!--
Choose the closest severity.
-->

- [ ] Critical — blocks core workflow, causes data loss, security exposure, or incorrect persistent evidence
- [ ] High — major feature broken, misleading investigation result, or significant user-facing failure
- [ ] Medium — feature partially broken, workaround exists, or minor incorrect behaviour
- [ ] Low — cosmetic, documentation, minor UI, or non-blocking issue

## 5. Impact area

<!--
Select all affected areas.
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
- [ ] Docker / deployment
- [ ] CI
- [ ] Documentation
- [ ] Other:

## 6. Component and version

<!--
Provide as much detail as possible.
-->

| Field                  | Value                                        |
| ---------------------- | -------------------------------------------- |
| Git commit / branch    |                                              |
| Backend version        |                                              |
| Frontend version       |                                              |
| API version            |                                              |
| Database               | PostgreSQL / SQLite                          |
| Python version         |                                              |
| Node.js version        |                                              |
| Docker Compose version |                                              |
| Operating system       |                                              |
| Browser                |                                              |
| Environment            | local / docker / CI / other                  |
| `BACKEND_ENV`          | local / staging / production                 |
| Active scoring mode    | trained_model / heuristic_fallback / unknown |
| Model version          |                                              |
| Rules version          |                                              |
| Feature schema version |                                              |
| Risk score version     |                                              |

## 7. Reproduction steps

<!--
Provide exact steps to reproduce the bug.
-->

1.
2.
3.
4.

## 8. Minimal reproduction data

<!--
Use synthetic data only.
If possible, provide a deterministic seed, scenario ID, or small JSON payload.
Do not paste real customer data or secrets.
-->

```json
{}
```

Synthetic scenario ID, if applicable:

```text
SCN-...
```

Seed, if applicable:

```text
SEED_RANDOM_SEED=...
```

## 9. Relevant logs or API responses

<!--
Paste sanitized logs, request/response bodies, or stack traces.
Remove secrets, tokens, passwords, and sensitive narrative text.
-->

```text

```

## 10. Screenshots or recordings

<!--
If the bug is UI-related, attach screenshots or recordings.
-->



## 11. Environment configuration

<!--
Share relevant non-secret configuration values.
Do not include .env contents with secrets.
-->

```dotenv
BACKEND_ENV=
BACKEND_DEBUG=
DATABASE_URL=redacted
AUTH_ENABLED=
ML_ACTIVE_SCORING_MODE=
SEED_DEMO_DATA=
VITE_API_BASE_URL=
```

## 12. Commands used

<!--
List commands used to start, seed, migrate, test, or reproduce.
-->

```bash

```

## 13. Database state

<!--
If the bug depends on persisted records, describe the relevant records using
synthetic IDs only.
-->

| Entity      | ID / reference | Notes |
| ----------- | -------------- | ----- |
| Account     |                |       |
| Transaction |                |       |
| Complaint   |                |       |
| Alert       |                |       |
| Case        |                |       |
| Assessment  |                |       |
| Evidence    |                |       |
| Audit event |                |       |

## 14. Detection / ML correctness checklist

<!--
Complete this section if the bug affects features, rules, scoring, alerts, or model behaviour.
-->

- [ ] The bug involves point-in-time feature computation.
- [ ] The bug may involve future-information leakage.
- [ ] The bug may involve synthetic ground-truth leakage.
- [ ] The bug may involve fraud-ring ID leakage.
- [ ] The bug affects rule thresholds.
- [ ] The bug affects evidence references.
- [ ] The bug affects alert deduplication.
- [ ] The bug affects risk score fusion.
- [ ] The bug affects scoring mode reporting.
- [ ] The bug affects model artifact loading.
- [ ] The bug affects evaluation metrics.
- [ ] The bug affects explainability output.

Details:

```text
None / explain
```

## 15. Graph / money-trail checklist

<!--
Complete this section if the bug affects graph analytics or candidate paths.
-->

- [ ] The bug involves graph construction.
- [ ] The bug may violate transaction direction.
- [ ] The bug may violate chronological ordering.
- [ ] The bug may exceed hop limits.
- [ ] The bug may exceed node/edge/path limits.
- [ ] The bug may incorrectly include failed/reversed transactions.
- [ ] The bug may lose transaction evidence.
- [ ] The bug may report a path as exact tracing instead of candidate flow path.
- [ ] The bug may allow unbounded graph access.

Details:

```text
None / explain
```

## 16. Complaint correlation checklist

<!--
Complete this section if the bug affects complaint matching.
-->

- [ ] The bug involves exact reference matching.
- [ ] The bug involves normalised identifier matching.
- [ ] The bug involves entity association.
- [ ] The bug involves temporal graph association.
- [ ] The bug may blur exact matches and inferred associations.
- [ ] The bug may overwrite raw complaint facts.
- [ ] The bug may mishandle missing references.
- [ ] The bug may mishandle duplicate complaints.
- [ ] The bug may create ambiguous matches.

Details:

```text
None / explain
```

## 17. Case / evidence / audit / report checklist

<!--
Complete this section if the bug affects investigation workflow.
-->

- [ ] The bug involves invalid case state transition.
- [ ] The bug involves evidence validation.
- [ ] The bug involves case history deletion or overwrite.
- [ ] The bug involves missing audit events.
- [ ] The bug involves incorrect report generation.
- [ ] The bug involves report authorisation.
- [ ] The bug involves missing-case handling.
- [ ] The bug involves unsafe filenames or path traversal.
- [ ] The bug involves fabricated report content.

Details:

```text
None / explain
```

## 18. Security relevance

<!--
Do not disclose exploitable vulnerability details publicly.
If this is a security issue, close this draft and report privately.
-->

- [ ] This bug may expose secrets.
- [ ] This bug may bypass authentication.
- [ ] This bug may bypass role-based authorisation.
- [ ] This bug may allow SQL injection or unsafe query construction.
- [ ] This bug may allow path traversal.
- [ ] This bug may allow unsafe file download.
- [ ] This bug may allow unsafe model artifact loading.
- [ ] This bug may log sensitive information.
- [ ] This bug may corrupt audit history.
- [ ] This bug may allow unbounded resource consumption.
- [ ] This bug may affect data integrity.
- [ ] This bug may produce misleading investigative evidence.

If any box is checked, provide sanitized details:

```text
None / explain
```

## 19. Workaround

<!--
Is there a known temporary workaround?
-->

```text
None / explain
```

## 20. Possible root cause

<!--
If known, list suspected files, modules, endpoints, services, or database tables.
-->

```text
None / explain
```

## 21. Suggested fix

<!--
If known, describe the likely fix and required tests.
-->

```text
None / explain
```

## 22. Required regression tests

<!--
List tests that should be added or updated once fixed.
-->

- [ ] Unit test
- [ ] API test
- [ ] Integration workflow test
- [ ] Graph test
- [ ] ML leakage/fallback test
- [ ] Case transition test
- [ ] Evidence validation test
- [ ] Audit test
- [ ] Report test
- [ ] Frontend typecheck/build
- [ ] Docker smoke test

Test details:

```text
None / explain
```

## 23. Documentation impact

<!--
Will fixing this require documentation changes?
-->

- [ ] `README.md`
- [ ] `docs/api.md`
- [ ] `docs/data-dictionary.md`
- [ ] `docs/model-card.md`
- [ ] `docs/security.md`
- [ ] `docs/testing.md`
- [ ] `docs/deployment.md`
- [ ] `docs/demo-walkthrough.md`
- [ ] `docs/requirements-traceability.md`
- [ ] `CHANGELOG.md`
- [ ] ADR required
- [ ] No documentation impact expected

## 24. Acceptance criteria

<!--
Define what must be true for this bug to be considered fixed.
-->

- [ ]
- [ ]
- [ ]

## 25. Additional context

<!--
Add any other context, links, or references.
-->