# Contributing to MULEGUARD

Thank you for considering a contribution to **MULEGUARD — Intelligent Mule Account Detection and Financial Fraud Investigation Platform**.

MULEGUARD is a synthetic-first, evidence-backed, human-in-the-loop financial-fraud investigation prototype. Contributions must preserve these principles:

- **Synthetic-first:** use synthetic data unless the project owner explicitly provides an approved dataset.
- **Evidence-backed:** alerts, scores, graph paths, and complaint correlations must reference real persisted evidence.
- **Explainable:** model version, scoring mode, feature values, rule hits, and caveats must be visible.
- **Human-in-the-loop:** investigators decide outcomes; the system prioritises work and does not adjudicate guilt.
- **Auditable:** material case, evidence, analysis, authentication, and report actions must leave durable audit records.
- **Reproducible:** generators, training, evaluation, demos, and tests must support fixed seeds.
- **Temporally correct:** point-in-time features and assessments must not use future information.
- **Secure by default:** validate inputs, bound graph searches, parameterise SQL, protect secrets, and enforce roles server-side.
- **Graceful degradation:** missing ML artifacts or optional dependencies must produce explicit fallback behaviour, not crashes or fake claims.
- **No fake functionality:** buttons, filters, charts, exports, and state transitions must do what their labels promise.

By contributing, you agree that your contribution will be licensed under the project’s license and that you have the right to submit it.

---

## 1. Security issues

Do **not** open a public issue for a security vulnerability.

Report vulnerabilities privately to:

```text
security@muleguard.local
```

Include:

- affected component;
- reproduction steps;
- impact;
- suggested fix, if available;
- whether the issue involves secrets, authentication, authorisation, injection, path traversal, model deserialisation, or audit bypass.

Do not include real credentials, real customer data, or production secrets in vulnerability reports.

---

## 2. Code of conduct

All contributors are expected to communicate respectfully, assume good intent, and focus on the technical work. Harassment, abusive language, and unsafe behaviour are not acceptable.

---

## 3. Contribution scope

### 3.1 In-scope contributions

The following are welcome:

- bug fixes;
- backend API improvements;
- frontend usability improvements;
- synthetic data generator improvements;
- ingestion validation improvements;
- feature-engineering improvements;
- rule-engine improvements;
- graph analytics and money-trail search improvements;
- complaint correlation improvements;
- ML transparency, evaluation, fallback, and leakage-control improvements;
- case management, evidence, notes, audit, and report improvements;
- security hardening;
- observability and performance improvements;
- test coverage improvements;
- documentation improvements;
- Docker and developer-experience improvements;
- accessibility improvements;
- deterministic demo scenario improvements.

### 3.2 Out-of-scope contributions

Do not contribute:

- real bank integrations;
- real payment-rail integrations;
- real customer data;
- real cybercrime-database integrations;
- deanonymisation tooling;
- covert-surveillance capabilities;
- automatic account freezing;
- automatic payment blocking;
- automatic blacklisting;
- adverse automated customer actions;
- production regulatory-compliance claims;
- real-world fraud-detection accuracy claims;
- unbounded whole-bank graph endpoints;
- arbitrary user-uploaded model artifact loading;
- Kafka, Kubernetes, microservice fleets, complex feature stores, deep learning, graph neural networks, or LLM dependencies unless a measured need has been discussed and approved;
- hardcoded metrics, fake chart series, or fake UI behaviour.

If a contribution appears advanced but weakens safety, explainability, auditability, or reproducibility, it will be rejected.

---

## 4. Before you start

### 4.1 Discuss major changes

Open an issue first for:

- new API endpoints;
- database schema changes;
- ML model type changes;
- risk fusion formula changes;
- rule threshold philosophy changes;
- graph search semantics changes;
- complaint matching tier changes;
- case state machine changes;
- authentication/authorisation changes;
- report structure changes;
- deployment architecture changes;
- new dependencies;
- breaking changes.

Small bug fixes, documentation fixes, and test improvements may proceed directly.

### 4.2 Required reading

Before contributing, read:

```text
README.md
docs/architecture.md
docs/api.md
docs/data-dictionary.md
docs/model-card.md
docs/security.md
docs/testing.md
docs/deployment.md
docs/demo-walkthrough.md
docs/requirements-traceability.md
```

If your change makes any of these documents inaccurate, you must update them in the same pull request.

---

## 5. Local development setup

### 5.1 Prerequisites

Install:

- Python 3.11 or newer;
- Node.js 20 LTS or newer;
- Docker and Docker Compose;
- GNU Make or equivalent script runner;
- Git.

### 5.2 Clone and enter the repository

```bash
git clone https://github.com/YOUR_ORG/muleguard.git
cd muleguard
```

### 5.3 Create environment file

Unix/macOS:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Update all `CHANGE_ME` values.

Never commit real secrets.

### 5.4 Backend setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements-dev.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend/requirements-dev.txt
```

### 5.5 Frontend setup

```bash
cd frontend
npm ci
cd ..
```

### 5.6 Database migrations

```bash
make migrate
```

or from `backend/`:

```bash
alembic upgrade head
```

### 5.7 Seed synthetic demo data

```bash
make seed
```

### 5.8 Run backend and frontend locally

```bash
make dev-backend
```

in one terminal, and:

```bash
make dev-frontend
```

in another.

### 5.9 Docker path

To run the full local stack:

```bash
docker compose up --build
```

To stop and remove local demo volumes:

```bash
make docker-reset
```

This is destructive and resets the synthetic demo database.

---

## 6. Development workflow

Use small vertical slices. Keep the application runnable at each stage.

Recommended flow:

1. Pick or create an issue.
2. Create a feature branch.
3. Inspect existing code before changing it.
4. Implement the smallest useful vertical slice.
5. Add or update tests.
6. Add or update documentation.
7. Add a changelog entry under `[Unreleased]`.
8. Run relevant checks.
9. Run the full local verification suite.
10. Open a pull request.
11. Respond to review feedback.
12. Wait for CI and maintainer approval.

Do not stop at advice, diagrams, TODOs, mockups, pseudocode, or file trees when the issue asks for implementation. Implement, test, and report honestly.

---

## 7. Branching model

Use descriptive branch names.

Recommended patterns:

```text
feat/<scope>/<short-description>
fix/<scope>/<short-description>
docs/<scope>/<short-description>
test/<scope>/<short-description>
refactor/<scope>/<short-description>
security/<scope>/<short-description>
chore/<scope>/<short-description>
```

Examples:

```text
feat/graph/temporal-money-trail-limits
fix/ingestion/duplicate-transaction-reference
docs/model-card/update-metrics-section
test/cases/illegal-state-transition
security/auth/login-throttling
```

Branch from the default branch unless instructed otherwise.

---

## 8. Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/).

Format:

```text
<type>(<scope>): <summary>

<optional body>

<optional footer>
```

Allowed types:

| Type       | Purpose                              |
| ---------- | ------------------------------------ |
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `docs`     | Documentation only                   |
| `test`     | Adding or fixing tests               |
| `refactor` | Code change without behaviour change |
| `perf`     | Performance improvement              |
| `style`    | Formatting only, no logic change     |
| `build`    | Build system or dependency change    |
| `ci`       | CI configuration change              |
| `security` | Security hardening or fix            |
| `chore`    | Maintenance task                     |

Recommended scopes:

```text
backend
frontend
api
db
migrations
ingestion
features
rules
ml
graph
complaints
cases
alerts
audit
reports
auth
security
docker
ci
docs
scripts
data
config
ui
dashboard
transactions
accounts
model-monitoring
```

Example:

```text
feat(graph): add bounded temporal money-trail search

- enforce max hops and chronological ordering
- prevent cycles inside candidate paths
- return ordered transaction evidence
- add tests for impossible time ordering
```

Breaking changes must include:

```text
BREAKING CHANGE: alert evidence response now uses `evidence_refs` instead of `evidence_ids`
```

---

## 9. Pull request rules

A pull request must:

- solve one clearly described problem;
- remain small enough to review safely;
- keep the application runnable;
- include tests for behaviour changes;
- include documentation updates where relevant;
- include a changelog entry under `[Unreleased]`;
- pass local checks;
- pass CI checks;
- contain no secrets, real customer data, or production credentials;
- contain no fake metrics, hardcoded dashboard values, or placeholder behaviour presented as working functionality;
- describe exactly what was verified and what was not verified.

If a check cannot be run because of an environment limitation, state that explicitly in the pull request. Do not claim an unrun test passed.

---

## 10. Definition of Done

A contribution is done only when all applicable items are complete.

### 10.1 General

- [ ] The change matches the issue description.
- [ ] Existing useful code was preserved and not blindly overwritten.
- [ ] The application starts.
- [ ] No new empty placeholder modules were added.
- [ ] Every added file has a clear purpose.
- [ ] No TODO-only implementation was left where working behaviour is required.
- [ ] `CHANGELOG.md` was updated under `[Unreleased]`.
- [ ] Documentation matches the implementation.
- [ ] No secrets were added to source control.
- [ ] No real customer data was added.
- [ ] Synthetic data remains clearly synthetic.

### 10.2 Backend

- [ ] API routes use typed Pydantic request/response models.
- [ ] Raw ORM objects are not returned directly from API endpoints.
- [ ] Validation and orchestration live in routes; domain logic lives in services.
- [ ] Invalid input returns a useful 4xx response.
- [ ] Not-found cases return correct status codes.
- [ ] Authentication and role permissions are enforced server-side.
- [ ] Pagination is bounded and stable.
- [ ] List endpoints use stable ordering.
- [ ] Writes are transactional where appropriate.
- [ ] Error responses do not expose stack traces.
- [ ] Sensitive fields are not logged.
- [ ] Audit events are emitted for material actions where required.

### 10.3 Database

- [ ] SQLAlchemy models use clear relationships and constraints.
- [ ] UTC timestamps are used.
- [ Monetary amounts use `Decimal`/SQL `NUMERIC`.
- [ ] Indexes support common query paths.
- [ ] Alembic migration is included for schema changes.
- [ ] Migration works from an empty database.
- [ ] Migration includes a safe downgrade where practical.
- [ ] `create_all()` is not the deployed schema path.
- [ ] Data dictionary is updated.
- [ ] Destructive migrations require explicit confirmation.

### 10.4 Synthetic data and ingestion

- [ ] Generator remains deterministic for a fixed seed.
- [ ] Synthetic labels are isolated from model inputs.
- [ ] No fraud-ring ID or ground-truth label leaks into features.
- [ ] Generated records are clearly synthetic.
- [ ] Ingestion validates required fields, types, references, timestamps, currency, status, and amounts.
- [ ] Duplicate references are handled predictably.
- [ ] Batch response includes accepted/rejected/duplicated/skipped counts.
- [ ] Row-level errors are useful and do not leak secrets.
- [ ] Failed batches do not leave unpredictable partial data unless partial acceptance is explicitly reported.
- [ ] JSON schemas and sample payloads are updated when ingestion contracts change.

### 10.5 Feature engineering

- [ ] Features are point-in-time correct.
- [ ] Future transactions, complaints, or investigation outcomes are not used for past assessments.
- [ ] Windows and `as_of` semantics are explicit.
- [ ] Missing-value behaviour is documented.
- [ ] Feature names are stable.
- [ ] Boundary conditions are tested.
- [ ] Feature schema version is updated when feature meaning changes.
- [ ] Data dictionary or feature documentation is updated.

### 10.6 Rules

- [ ] Rules are separate testable functions or structured definitions.
- [ ] Rule thresholds are configurable.
- [ ] Rule results include rule code, title, triggered status, measured value, threshold, severity, explanation, evidence, and version metadata.
- [ ] Evidence references point to real persisted records.
- [ ] Each rule has positive, negative, and boundary tests.
- [ ] Demo thresholds are not described as universal banking thresholds.

### 10.7 Graph

- [ ] Graph construction preserves multiple transactions between the same account pair.
- [ ] Edge evidence preserves transaction ID, amount, currency, status, and timestamp.
- [ ] Only appropriate completed statuses represent completed money movement.
- [ ] Graph queries are bounded.
- [ ] Root account or constrained source/destination is required.
- [ ] Hops, nodes, edges, paths, date span, and result counts are limited server-side.
- [ ] Candidate money trails respect direction and chronological order.
- [ ] Cycle prevention rules are implemented and tested.
- [ ] Path evidence includes ordered transaction references.
- [ ] Results are described as candidate flow paths, not exact currency-unit tracing.
- [ ] UI graph views include loading, empty, error, capped-result, and legend states.

### 10.8 Complaint correlation

- [ ] Exact matches are separated from inferred associations.
- [ ] Match tier, method, confidence/provenance, and review state are visible.
- [ ] Raw complaint facts are preserved.
- [ ] Normalised values are stored separately from raw values.
- [ ] Missing references are handled gracefully.
- [ ] Duplicate complaints are handled predictably.
- [ ] Ambiguous entity matches are labelled as inferred.
- [ ] Tests cover exact-vs-inferred ordering.

### 10.9 Machine learning

- [ ] Training is reproducible with a fixed seed.
- [ ] Feature schema is consistent between training and inference.
- [ ] Preprocessing is fitted only on training data.
- [ ] Split strategy reduces leakage across linked accounts/scenarios where practical.
- [ ] Ground-truth labels and scenario IDs are not predictor features.
- [ ] Missing artifact behavior falls back explicitly and visibly.
- [ ] Corrupt or incompatible artifacts are handled safely.
- [ ] Arbitrary user-uploaded model deserialization is not allowed.
- [ ] Metrics are real computed outputs.
- [ ] Undefined metrics are reported honestly.
- [ ] Model card is updated.
- [ ] Model version and scoring mode are stored with assessments.
- [ ] Explanations cite real feature values, rule hits, and evidence references.
- [ ] Scores are not described as calibrated fraud probabilities unless calibration has actually been implemented and documented.

### 10.10 Risk fusion and alerts

- [ ] Score formula and version are documented.
- [ ] Weights and normalization live in configuration.
- [ ] Missing signals are handled explicitly.
- [ ] Shared-entity links do not automatically escalate every connected account to maximum risk.
- [ ] Alerts are evidence-backed.
- [ ] Duplicate open alerts are avoided across repeated runs.
- [ ] Alert triage actions are audited where material.
- [ ] UI and API expose scoring mode and model version.

### 10.11 Cases, evidence, audit, and reports

- [ ] Case state transitions are centrally defined and validated.
- [ ] Illegal transitions are rejected.
- [ ] Evidence references validated existing records.
- [ ] Arbitrary URLs or unchecked identifiers are not accepted as evidence.
- [ ] Case history is append-only.
- [ ] Reopen appends an event rather than erasing history.
- [ ] Notes are timestamped and attributed.
- [ ] Audit events record actor, action, target, timestamp, and safe metadata.
- [ ] PDF report is generated from persisted case data.
- [ ] Report includes limitations and synthetic-data disclaimer.
- [ ] Report download checks authorisation and missing-case handling.
- [ ] Report filenames are safe.

### 10.12 Frontend

- [ ] TypeScript checks pass.
- [ ] Production build passes.
- [ ] API shapes are typed.
- [ ] Raw `fetch` calls are not scattered through components.
- [ ] Reusable components are used instead of duplicated UI logic.
- [ ] Loading states are implemented.
- [ ] Empty states are implemented.
- [ ] Error states are implemented.
- [ ] Permission-denied states are implemented.
- [ ] Forms validate and show server errors.
- [ ] Filters either work or are clearly disabled with explanation.
- [ ] Charts derive from backend data.
- [ ] No hardcoded fake metric series are used.
- [ ] Synthetic-data banner is visible in demo mode.
- [ ] Risk scores are labelled as priority scores, not guilt probabilities.
- [ ] Exact complaint matches are visually distinct from inferred associations.
- [ ] High-risk states use text as well as colour.
- [ ] Graph views include legend and edge-direction indication.
- [ ] Cytoscape resources are cleaned up.
- [ ] React keys are correct.
- [ ] Exceptions are not swallowed silently.

### 10.13 Security

- [ ] Input validation is enforced.
- [ ] Pagination/filter/graph/path limits are enforced.
- [ ] SQL is parameterised through SQLAlchemy.
- [ ] Secrets are supplied through environment configuration.
- [ ] `.env`, local databases, generated private artifacts, and model binaries remain out of Git.
- [ ] Authentication and role checks are enforced server-side.
- [ ] Tests verify both allowed and denied access.
- [ ] Sensitive values are not logged.
- [ ] Audit redaction is preserved.
- [ ] Path traversal protections remain intact.
- [ ] CORS remains configurable and restricted.
- [ ] Secure headers remain configured where practical.
- [ ] Development users are clearly non-production.

### 10.14 Docker and deployment

- [ ] Docker Compose builds successfully where Docker is available.
- [ ] Service health/readiness behavior is preserved.
- [ ] Environment configuration remains documented.
- [ ] `.env.example` is updated for new variables.
- [ ] Reset behavior remains explicitly destructive.
- [ ] Deployment documentation is updated.

### 10.15 CI and tests

- [ ] Backend tests pass locally where dependencies are available.
- [ ] Frontend typecheck passes.
- [ ] Frontend production build passes.
- [ ] New behaviour has tests.
- [ ] Tests are deterministic.
- [ ] Tests do not write to the developer demo database.
- [ ] Tests do not depend on live external APIs.
- [ ] CI configuration remains secret-free.
- [ ] Exact commands and outcomes are reported in the PR.

---

## 11. Coding standards

### 11.1 Python backend

- Target Python 3.11+.
- Use type hints.
- Use Pydantic for request/response models.
- Use SQLAlchemy 2.x patterns.
- Keep API handlers thin.
- Put business logic in services.
- Use repository-style data access where it improves clarity, but do not add abstraction layers without benefit.
- Use UTC timestamps.
- Use `Decimal` for money.
- Use explicit enums/status values.
- Avoid raw SQL built from request values.
- Avoid returning ORM objects directly.
- Avoid unbounded queries.
- Avoid duplicate business rules scattered across endpoints.
- Prefer one source of truth for each rule.
- Log structured messages, not secrets.

### 11.2 FastAPI rules

- Use `/api/v1` versioned routing.
- Publish OpenAPI documentation.
- Use typed request/response models.
- Use appropriate HTTP status codes.
- Return stable error structures.
- Reject invalid parameters with 4xx responses.
- Do not expose stack traces to clients.
- Add permission dependencies explicitly.
- Add pagination to list endpoints.
- Add stable ordering to list endpoints.

### 11.3 SQLAlchemy and Alembic

- Define clear constraints and indexes.
- Use migrations for schema evolution.
- Review autogenerated migrations manually.
- Include safe downgrade paths where practical.
- Avoid destructive data changes without explicit local-demo flags.
- Document new fields in the data dictionary.
- Do not store real credentials, card numbers, PINs, OTPs, or online-banking secrets.

### 11.4 React/TypeScript frontend

- Use TypeScript strict mode.
- Avoid `any` unless strongly justified.
- Use functional components and hooks.
- Use React Router for navigation.
- Use TanStack Query or the project’s typed API client for server state.
- Use reusable components.
- Keep page components focused.
- Split feature logic by purpose.
- Type all API request/response shapes.
- Centralise API base URL and error handling.
- Avoid raw fetch calls inside components.
- Clean up graph, timer, and event resources.
- Use correct React keys.
- Show loading, empty, error, and permission states.
- Make forms validate and display server-side errors.
- Do not hardcode chart data when backend data is available.

### 11.5 Styling and UX

- Maintain a professional analyst-focused interface.
- Keep spacing, typography, badges, and status language consistent.
- Do not copy a specific banking brand.
- Avoid excessive gradients, animated decoration, fake terminal panels, or effects that harm investigation usability.
- Use clear risk-state semantics.
- Use explicit currency formatting.
- Use consistent timestamp formatting with timezone label.
- Label score type clearly.
- Ensure high-risk indicators have text as well as colour.
- Provide accessible labels and keyboard-focus behaviour.
- Provide useful empty states with a path to seed/load demo data.

### 11.6 ML code

- Use fixed random seeds.
- Keep feature schema explicit and versioned.
- Keep ground-truth labels isolated.
- Do not leak labels, scenario IDs, or investigation outcomes into predictors.
- Fit preprocessing only on training data.
- Use reproducible splits.
- Evaluate on held-out data.
- Store model metadata.
- Load artifacts only from controlled local paths.
- Handle missing/corrupt/incompatible artifacts gracefully.
- Mark fallback scoring mode explicitly.
- Do not present heuristic scores as model probabilities.

### 11.7 Graph code

- Preserve transaction-level evidence.
- Keep graph construction derived from database records or controlled snapshots.
- Keep database as source of truth.
- Bound all graph queries.
- Require constrained queries.
- Enforce temporal ordering in money trails.
- Prevent cycles inside candidate paths where configured.
- Document metric limitations.
- Do not imply that graph proximity proves wrongdoing.

### 11.8 Rules code

- Keep rules modular and testable.
- Keep thresholds configurable.
- Keep rule versions explicit.
- Return structured evidence.
- Do not embed large unexplained conditional trees in API routes.
- Do not use synthetic demo thresholds as universal banking thresholds.

### 11.9 Complaint correlation code

- Preserve raw source values.
- Store normalized values separately.
- Keep match tier/method/provenance explicit.
- Avoid ambiguous normalization collisions.
- Clearly separate deterministic exact matches from inferred associations.
- Handle missing values gracefully.

### 11.10 Case management code

- Validate all state transitions centrally.
- Preserve append-only event history.
- Validate evidence references.
- Enforce permissions server-side.
- Record material actions in audit.
- Do not erase prior case history.
- Do not allow arbitrary identifiers as evidence.

### 11.11 Reports code

- Generate reports from persisted data.
- Do not fabricate evidence-like text.
- Include synthetic-data disclaimer.
- Include limitations.
- Include evidence references.
- Use safe filenames.
- Use safe download headers.
- Test PDF output.

### 11.12 Security code

- Validate all identifiers, pagination, filters, graph hops, and path limits.
- Use ORM parameterization.
- Enforce request/body/upload limits.
- Avoid path traversal.
- Sanitize error messages.
- Keep secrets out of source control.
- Do not log passwords, bearer tokens, or full sensitive narratives unnecessarily.
- Use dependency scanning or lockfile/CI checks where possible.
- Keep demo data synthetic by default.

---

## 12. Testing requirements

All contributions must include or update tests where behaviour changes.

### 12.1 Backend unit tests

Add tests for:

- feature computation;
- every rule;
- score normalization;
- risk band assignment;
- identifier normalization;
- complaint matching;
- temporal path constraints;
- allowed case transitions;
- report generation;
- deterministic generation.

### 12.2 API tests

Add tests for:

- happy path;
- invalid input;
- not found;
- pagination;
- unauthenticated access;
- authenticated but forbidden access;
- role permission checks;
- stable ordering where relevant.

Use a temporary test database and deterministic fixtures.

Tests must not write to the developer demo database.

### 12.3 Integration workflow test

For end-to-end changes, verify the full journey:

1. seed synthetic data;
2. verify accounts and transactions exist;
3. run analysis;
4. verify expected injected scenario produces evidence-backed indicators;
5. query flagged account and explanation;
6. query graph neighbourhood and known candidate money trail;
7. query complaint correlations;
8. create case from alert;
9. attach evidence and add note;
10. update case through a legal transition;
11. download and validate report;
12. verify audit events were recorded.

### 12.4 Graph tests

Test:

- correct direction;
- timestamp ordering;
- maximum hops;
- no path for impossible time ordering;
- cycle prevention;
- same-timestamp policy;
- maximum result limits.

### 12.5 ML tests

Test:

- feature schema consistency;
- deterministic output under fixed seed where expected;
- no label leakage;
- missing model fallback;
- corrupt/mismatched artifact handling;
- rare or single-class label metric behavior.

### 12.6 Frontend checks

Run:

```bash
npm run typecheck
npm run build
```

If component or end-to-end tests are supported by the repository setup, add them for key journeys.

Verify that no frontend page depends on hardcoded sample data once the API is available.

### 12.7 Test honesty

Do not state “all tests pass” unless you actually ran the relevant suite successfully.

If a check is blocked by environment limitations, list:

- the exact command;
- the failure/blocker;
- the likely impact;
- what remains unverified.

---

## 13. Documentation requirements

Update documentation in the same pull request when behaviour changes.

| Change type                 | Required documentation updates                          |
| --------------------------- | ------------------------------------------------------- |
| API change                  | `docs/api.md`, OpenAPI, endpoint tests                  |
| Database change             | `docs/data-dictionary.md`, migration                    |
| Feature change              | feature docs, data dictionary, model card if ML-visible |
| Rule change                 | rule docs, threshold docs, tests                        |
| Graph change                | graph docs, API docs, UI guidance if relevant           |
| Complaint matching change   | correlation docs, tests                                 |
| Case workflow change        | case docs, state machine docs, tests                    |
| Report change               | report docs, PDF tests                                  |
| ML change                   | `docs/model-card.md`, evaluation docs                   |
| Security change             | `docs/security.md`, threat model/checklist              |
| Deployment change           | `docs/deployment.md`, `.env.example`, Docker docs       |
| Demo change                 | `docs/demo-walkthrough.md`                              |
| Requirement coverage change | `docs/requirements-traceability.md`                     |
| Major decision              | new ADR in `docs/adr/accepted/`                         |

Documentation must describe what the code actually does, not aspirational behaviour.

---

## 14. Architecture decision records

Create an ADR for material decisions, including:

- new architectural pattern;
- new datastore;
- new authentication/session mechanism;
- new ML model family;
- new graph search semantics;
- new scoring formula;
- new report generation engine;
- new deployment model;
- breaking API changes;
- new trust boundary.

Use the ADR template in:

```text
docs/adr/template.md
```

Store accepted ADRs in:

```text
docs/adr/accepted/
```

---

## 15. Changelog policy

Add entries under `[Unreleased]` in:

```text
CHANGELOG.md
```

Use the appropriate section:

- `Added`
- `Changed`
- `Deprecated`
- `Removed`
- `Fixed`
- `Security`

Security entries must include enough information for users to understand impact without exposing vulnerability details prematurely where appropriate.

---

## 16. Dependency policy

Before adding a dependency:

1. Check whether existing dependencies can solve the problem.
2. Prefer maintained, widely used libraries.
3. Avoid dependencies that are not used.
4. Avoid heavy dependencies for marginal benefit.
5. Pin or bound versions thoughtfully.
6. Update lockfiles/requirements.
7. Explain the reason in the pull request.
8. Update security documentation if the dependency introduces a new trust boundary.

Do not add dependencies merely to make the project appear advanced.

---

## 17. Performance guidance

Contributions should not materially degrade local usability.

Prefer:

- pagination;
- database indexes;
- bounded graph searches;
- bounded caches with invalidation;
- computing expensive graph metrics once per analysis run rather than per dashboard row;
- avoiding repeated full-table scans;
- avoiding unbounded JSON blobs where normalized rows are better;
- avoiding browser-freezing graph layouts.

If you add caching, document:

- cache key;
- invalidation rule;
- dataset/version sensitivity;
- TTL;
- failure behavior.

---

## 18. Observability guidance

When adding services or workflows, preserve:

- structured logging;
- request IDs where feasible;
- analysis run state;
- started/finished timestamps;
- processed/error counts;
- active model version;
- active scoring mode;
- safe error summaries.

Do not log:

- passwords;
- bearer tokens;
- secrets;
- full sensitive complaint narratives unnecessarily;
- real personal data.

---

## 19. Synthetic data guidance

When changing synthetic data:

- keep generation deterministic;
- document seed behavior;
- preserve quick-start and large-dataset profiles;
- keep labels isolated;
- preserve hard negatives;
- preserve injected scenario coverage;
- avoid generating data that looks like real customer data;
- avoid real names, real account numbers, real phone numbers, or real identifiers;
- keep synthetic disclaimers visible.

If adding a new scenario:

- add deterministic fixture support;
- add tests;
- update demo walkthrough if demo-visible;
- update traceability if requirement-visible;
- ensure labels do not leak into features.

---

## 20. Model and explanation guidance

When changing model behaviour:

- update model card;
- update evaluation output;
- preserve fallback behaviour;
- preserve feature schema validation;
- preserve leakage tests;
- preserve scoring mode transparency;
- preserve explanation structure;
- preserve model version metadata;
- preserve artifact checksum/trust policy.

Do not:

- claim calibrated probability unless calibration is implemented and documented;
- claim real-world fraud detection performance;
- describe suspicious accounts as guilty;
- present graph proximity as proof;
- present complaint association as proof;
- present shared entity as conclusive control evidence.

---

## 21. UI contribution guidance

When changing UI:

- preserve analyst efficiency;
- preserve information hierarchy;
- preserve loading/empty/error/permission states;
- preserve synthetic-data banner;
- preserve disclosure language;
- preserve accessible labels;
- preserve keyboard focus;
- preserve responsive behaviour;
- preserve evidence drill-through;
- preserve exact-vs-inferred visual separation;
- preserve graph legend and direction cues.

If adding a new UI control:

- wire it to real state or backend behaviour;
- disable it with explanation if unsupported;
- add validation;
- add server-error feedback;
- add tests or checks where supported.

---

## 22. Docker contribution guidance

When changing Docker:

- keep images lean;
- keep secrets out of images;
- keep `.dockerignore` effective;
- preserve health checks;
- preserve service readiness;
- preserve migration-on-start behavior;
- preserve named volumes for local persistence;
- document destructive reset;
- update deployment docs.

Do not add Redis, workers, Kubernetes, or extra infrastructure unless required by an approved asynchronous workflow.

---

## 23. CI contribution guidance

When changing CI:

- keep workflows deterministic;
- keep workflows secret-free;
- cache dependencies where useful;
- avoid live external APIs;
- run backend tests;
- run frontend typecheck;
- run frontend production build;
- run lint/format checks where configured;
- fail clearly;
- avoid flaky network dependencies.

---

## 24. Pull request template

Use this structure in pull request descriptions:

```markdown
## Summary

Describe the problem and the implemented solution.

## Related issue

Fixes #<issue-number>

## What changed

- backend:
- frontend:
- database:
- ML:
- graph:
- docs:
- tests:

## Verification

Commands run and actual results:

```bash
make test
npm run typecheck
npm run build
```

## Screenshots / recordings

If UI changed, add screenshots or recordings.

## Risk and limitations

Describe edge cases, known limitations, and unverified areas.

## Checklist

- [ ] Tests added/updated
- [ ] Docs updated
- [ ] Changelog updated
- [ ] No secrets introduced
- [ ] No fake functionality introduced
- [ ] No real customer data introduced
- [ ] CI relevant checks run locally
```

---

## 25. Review process

Maintainers will review for:

- correctness;
- safety;
- explainability;
- auditability;
- reproducibility;
- test coverage;
- documentation accuracy;
- performance impact;
- security impact;
- alignment with MULEGUARD principles.

Reviewers may request:

- smaller pull requests;
- additional tests;
- documentation updates;
- safer wording;
- bounded queries;
- explicit fallback behaviour;
- removal of fake/hardcoded data;
- evidence-link verification;
- migration fixes;
- changelog fixes.

Be patient and professional. Review is collaborative quality control, not personal evaluation.

---

## 26. Merge criteria

A pull request may be merged when:

- it satisfies the Definition of Done;
- it has passed required automated checks;
- it has been reviewed and approved;
- it contains no secrets or unsafe data;
- it does not introduce false functionality;
- it does not introduce unsupported production claims;
- it updates documentation and changelog;
- it preserves synthetic-first and human-in-the-loop principles.

Maintainers may reject contributions that are technically correct but unsafe, misleading, or misaligned with the project’s ethical scope.

---

## 27. Release process

Maintainers will:

1. consolidate accepted changes under `[Unreleased]`;
2. determine the next semantic version;
3. move changelog entries to the new version section;
4. tag the release;
5. update release notes;
6. verify setup instructions;
7. confirm documentation links and references.

Release notes must distinguish:

- verified changes;
- environment-blocked verification;
- known limitations;
- breaking changes;
- migration steps.

---

## 28. AI-assisted contributions

AI-assisted contributions are allowed only if:

- the contributor reviews the output;
- the contributor verifies correctness;
- tests are added or updated;
- documentation is updated;
- no secrets, real data, or unsafe capabilities are introduced;
- the contributor can explain and maintain the change;
- the pull request honestly states which parts were AI-assisted where material.

Do not submit unreviewed AI-generated code as verified work.

---

## 29. Useful commands

Common commands:

```bash
# Install backend development dependencies
pip install -r backend/requirements-dev.txt

# Run migrations
make migrate

# Seed synthetic demo data
make seed

# Run backend tests
make test-backend

# Run frontend typecheck
make typecheck-frontend

# Build frontend
make build-frontend

# Run all available checks
make test

# Start Docker stack
docker compose up --build

# Reset local synthetic demo database
make docker-reset
```

If a Make target is unavailable, run the underlying command directly and document it.

---

## 30. Contributor checklist

Before opening a pull request, confirm:

- [ ] I read this guide.
- [ ] I discussed major changes in an issue.
- [ ] My branch is focused and up to date.
- [ ] My change keeps the application runnable.
- [ ] I preserved existing useful code.
- [ ] I added or updated tests.
- [ ] I added or updated documentation.
- [ ] I updated `CHANGELOG.md`.
- [ ] I did not introduce secrets.
- [ ] I did not introduce real customer data.
- [ ] I did not introduce fake functionality.
- [ ] I did not introduce unsupported production claims.
- [ ] I did not introduce automatic adverse customer actions.
- [ ] I ran relevant local checks.
- [ ] I reported unrun or blocked checks honestly.

---

Thank you for helping make MULEGUARD safer, clearer, more reproducible, and more useful for responsible financial-crime investigation research.