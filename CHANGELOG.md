# Changelog

All notable changes to **MULEGUARD — Intelligent Mule Account Detection and Financial Fraud Investigation Platform** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Prototype notice:** MULEGUARD is an academic / hackathon-grade synthetic prototype. It is not production-ready, does not connect to real banking systems, and does not make or support automatic adverse customer actions.

---

## Versioning policy

- **MAJOR** version changes indicate incompatible API, database schema, model artifact, or configuration changes.
- **MINOR** version changes indicate backward-compatible feature additions.
- **PATCH** version changes indicate backward-compatible bug fixes, documentation fixes, or test fixes.
- Pre-release versions may use suffixes such as `-alpha`, `-beta`, or `-rc`.
- User-visible changes must be recorded under `[Unreleased]` before release.
- Security-relevant changes must always appear under the `Security` section.
- Breaking changes must be clearly described under `Changed`, `Removed`, or `Deprecated`.

---

## [Unreleased]

### Added

- Nothing unreleased yet.

### Changed

- Nothing changed yet.

### Deprecated

- Nothing deprecated yet.

### Removed

- Nothing removed yet.

### Fixed

- Nothing fixed yet.

### Security

- No pending security changes.

---

## [0.1.0] - 2026-06-15

### Summary

Initial synthetic-first MULEGUARD prototype.

This release introduces the end-to-end investigative workflow:

1. Generate deterministic synthetic banking data.
2. Ingest and validate accounts, transactions, complaints, and entity relationships.
3. Compute point-in-time behavioural features.
4. Run configurable rule-based detection.
5. Run graph analytics and bounded money-trail search.
6. Correlate complaints with transaction and entity evidence.
7. Produce explainable risk priority scores.
8. Create and manage investigation cases.
9. Maintain audit history.
10. Generate PDF investigation reports.
11. Monitor model status, scoring mode, and evaluation transparency.

This version is intended for local development, demonstration, education, and hackathon use.

### Compatibility

| Component | Supported version |
|---|---:|
| Python | 3.11+ |
| Node.js | 20 LTS+ |
| PostgreSQL | 15+ |
| SQLite | Local development and tests only |
| Docker Compose | v2+ |
| API prefix | `/api/v1` |
| Feature schema version | `v1` |
| Rules version | `v1` |
| Risk score version | `v1` |
| Case state machine version | `v1` |
| Complaint correlation version | `v1` |
| Graph search version | `v1` |
| Model artifact manifest version | `v1` |

### Added

#### Repository and project foundation

- Initial repository structure for backend, frontend, data schemas, docs, scripts, Docker, and CI.
- Root `README.md` with setup, demo, testing, and safety guidance.
- Root `Makefile` with common development, migration, seeding, training, testing, and Docker commands.
- `.env.example` with safe placeholder values and production warning guidance.
- `.gitignore` entries for secrets, local databases, generated data, model binaries, caches, and build output.
- `.dockerignore` files for smaller and safer Docker build contexts.
- `.editorconfig` for consistent formatting across Python, TypeScript, YAML, JSON, shell, PowerShell, Makefiles, and Dockerfiles.
- `.gitattributes` for safe line-ending normalization and binary/generated-file handling.
- `.python-version` pinned to Python 3.11.
- `PROJECT_TREE.txt` generation support.
- `LICENSE`, `CONTRIBUTING.md`, and issue/pull-request templates.
- Architecture decision records covering the modular monolith, PostgreSQL source of truth, synthetic-first data, and human-in-the-loop risk scoring.

#### Backend application

- FastAPI application factory with versioned API router under `/api/v1`.
- Health and readiness endpoints.
- Structured application logging.
- Request ID correlation support.
- Secure error response structure with safe `code`, `message`, and optional `details` fields.
- Server-side request validation using Pydantic schemas.
- Thin API handlers with domain logic delegated to services.
- Typed request/response models for all public endpoints.
- OpenAPI documentation for all API routes.
- Configuration through environment variables with safe local defaults.
- Graceful startup behavior when ML artifacts are unavailable.
- Explicit fallback scoring mode when trained models are not present.

#### Database and migrations

- SQLAlchemy 2.x domain models.
- Alembic migration setup.
- Initial migration from empty database.
- UTC timestamps across persisted entities.
- Indexed fields for transaction time, sender, receiver, status, reference, account, alert, case, complaint, and audit queries.
- Decimal/numeric monetary storage.
- JSON metadata fields constrained to non-sensitive synthetic attributes.
- Separate persisted structures for:
  - accounts;
  - transactions;
  - complaints;
  - entities;
  - account-entity links;
  - feature snapshots;
  - model assessments;
  - risk indicators;
  - rule hits;
  - alerts;
  - alert evidence;
  - investigation cases;
  - case evidence;
  - case events;
  - case notes;
  - audit events;
  - model versions;
  - model evaluations;
  - complaint correlations;
  - analysis runs.

#### Synthetic data generation

- Deterministic synthetic dataset generator.
- Seed-based reproducibility for accounts, transactions, complaints, entity links, labels, and timestamps.
- Synthetic-first default dataset.
- Quick-start dataset profile for local development.
- Optional larger dataset profile for performance experiments.
- Synthetic ground-truth labels isolated from model features.
- Injected suspicious scenarios, including:
  - rapid pass-through;
  - fan-in;
  - fan-out;
  - multi-hop layering;
  - circular movement / round-tripping;
  - dormant-to-active behaviour;
  - high transaction velocity;
  - complaint-linked transactions;
  - shared synthetic entity relationships;
  - hard negatives that resemble suspicious rules but are legitimate.
- Clear synthetic watermarking and demo-data labels.
- Seeding commands through Python modules and scripts.
- Reset behavior requiring explicit destructive confirmation or local demo flag.

#### Ingestion and validation

- JSON bulk ingestion endpoints for:
  - accounts;
  - transactions;
  - complaints;
  - entity links.
- Validation for required fields, types, timestamps, currencies, statuses, amounts, references, and provenance.
- Positive amount validation for completed transfers.
- Duplicate transaction and complaint reference detection.
- Referential integrity checks for transaction counterparties and entity links.
- Batch result reporting with accepted, rejected, duplicated, and skipped counts.
- Row-level validation summaries without leaking secrets.
- Configurable maximum batch and request sizes.
- Transactional batch behavior with clearly reported partial acceptance only when explicitly enabled.
- JSON schemas in `data/schemas/` aligned with ingestion validation.
- Sample valid and invalid payloads in `data/samples/`.
- Automated schema/sample validation tests.

#### Feature engineering

- Point-in-time behavioural feature engine.
- Explicit `as_of` timestamps for assessments.
- Configurable windows:
  - 1 hour;
  - 24 hours;
  - 7 days;
  - 30 days.
- Transaction behaviour features:
  - incoming/outgoing counts;
  - incoming/outgoing amounts;
  - average and median amounts;
  - amount dispersion;
  - distinct counterparties;
  - failed/reversed counts and ratios;
  - velocity;
  - inter-transaction time statistics;
  - incoming-to-outgoing value ratio;
  - pass-through ratio;
  - baseline amount deviation;
  - sudden activity after inactivity;
  - recipient diversity change;
  - recent-vs-historical activity change.
- Graph-derived features with bounded neighbourhood expansion.
- Stable feature names.
- Documented missing-value policy.
- Feature snapshot persistence.
- Feature schema versioning.
- Leakage protection preventing synthetic ground-truth fields from entering model inputs.
- Unit tests for boundary conditions, zero-volume accounts, single transactions, duplicates, missing values, and window edges.

#### Rule engine

- Modular rule engine with separately testable rule implementations.
- Configurable thresholds.
- Rule versioning.
- Structured rule results containing:
  - rule code;
  - human-readable title;
  - triggered status;
  - measured value;
  - configured threshold;
  - severity/priority;
  - explanation;
  - evidence references;
  - rule version/configuration metadata.
- Initial rules:
  - rapid pass-through;
  - high velocity;
  - fan-in;
  - fan-out;
  - dormant-to-active;
  - unusual amount / behavioural deviation;
  - layered path;
  - circular movement;
  - complaint reference association;
  - suspicious-neighbour association.
- Positive, negative, and boundary tests for each rule.
- Rule hits persisted with evidence references.
- Rule explanations exposed through account and alert APIs.

#### Graph analytics

- NetworkX directed multigraph construction preserving multiple transactions between the same account pair.
- Edge preservation of:
  - transaction ID;
  - amount;
  - currency;
  - status;
  - timestamp.
- Completed-status filtering for money-movement graph edges.
- Bounded neighbourhood queries.
- Required root account or constrained query source/destination.
- Server-side limits for:
  - hops;
  - nodes;
  - edges;
  - paths;
  - date span;
  - result count.
- Directed degree and weighted volume metrics.
- Local neighbourhood expansion.
- Connected component analysis under documented direction semantics.
- Community detection where size and dependency constraints permit.
- Cycle candidate detection.
- High-degree and intermediary candidate indicators.
- Complaint-linked neighbourhood analysis.
- Candidate time-ordered money-trail search.
- Path constraints:
  - direction;
  - chronological ordering;
  - maximum hops;
  - time range;
  - optional amount bounds;
  - cycle prevention;
  - maximum returned paths.
- Path evidence including ordered transaction IDs, timestamps, and amounts.
- Explicit labelling of candidate flow paths rather than exact currency-unit tracing.
- Graph query safety tests for impossible time ordering, hop limits, cycle prevention, and bounded results.

#### Complaint correlation

- Complaint correlation engine with explicit match tiers.
- Tier 1 exact transaction/reference matching.
- Tier 2 normalized identifier matching.
- Tier 3 account/entity association matching.
- Tier 4 bounded temporal graph association.
- Optional Tier 5 deterministic narrative extraction, disabled by default.
- Match provenance, method, confidence, and review state.
- Separation of original complaint facts from system-generated correlations.
- Preservation of raw complaint values.
- Normalized values stored separately from source values.
- Graceful handling of missing transaction references, missing identifiers, duplicate complaints, and ambiguous entity associations.
- Exact matches visually and structurally separated from inferred associations.
- Complaint correlation API with filtering and pagination.
- Tests for exact-vs-inferred ordering, duplicate complaints, missing references, normalization collisions, and ambiguous entity matches.

#### Machine learning

- Supervised tabular baseline classifier.
- Unsupervised Isolation Forest anomaly detector.
- Transparent rules-only baseline.
- Reproducible training command.
- Deterministic seed support.
- Feature and label integrity validation.
- Chronological or scenario-aware split strategy.
- Leakage controls preventing fraud-ring identifiers and ground-truth labels from entering predictors.
- Preprocessing fitted only on training partition.
- Held-out evaluation.
- Model artifact persistence in controlled local artifact directory.
- Model metadata including:
  - version identifier;
  - feature schema/version;
  - training timestamp;
  - random seed;
  - dataset fingerprint;
  - split strategy;
  - model type;
  - hyperparameters;
  - metrics;
  - limitations;
  - artifact checksum.
- Model service that validates artifact feature schema/version.
- Explicit fallback scoring mode when no trained artifact exists.
- Safe handling of missing, corrupt, or incompatible artifacts.
- No user-uploaded model deserialization.
- Evaluation metrics:
  - precision;
  - recall;
  - F1;
  - PR-AUC where supported;
  - ROC-AUC as supplementary metric;
  - Precision@K / top-K review yield;
  - confusion matrix;
  - false-positive rate;
  - latency estimate at stated dataset size.
- Honest reporting of undefined metrics for single-class or too-small evaluation partitions.
- Model monitoring API exposing real computed metrics or explicit `not_evaluated` state.
- Optional SHAP integration disabled by default and never required for core functionality.
- Deterministic rule/feature-based explanations when model explanations are unavailable.

#### Risk fusion and prioritisation

- Transparent investigative priority score.
- Versioned risk fusion configuration.
- Weighted combination of:
  - supervised model signal;
  - anomaly signal;
  - graph signal;
  - rule signal.
- Configurable weights and normalization.
- Documented handling of missing signals.
- Risk bands such as `LOW`, `MEDIUM`, `HIGH`, and optional `CRITICAL`.
- Explicit labelling that scores are investigative priority scores, not probabilities of guilt.
- Prevention of automatic maximum escalation from a single shared-entity link.
- Caps on neighbour-alert and shared-entity signals.
- Persisted score components.
- Persisted rule hits, model version, score version, timestamp, and evidence references.
- Alert deduplication across repeated analysis runs.
- Score history retained instead of silent overwrite.
- Analysis run state tracking including started/finished time, processed count, error count, model version, and scoring mode.

#### Alerts

- Alert creation from rule, model, graph, and fused-risk signals.
- Alert deduplication by account, detection window, and signal family.
- Evidence-backed alert detail.
- Priority and state metadata.
- Acknowledgement/triage updates with permission checks.
- Audit events for material alert triage actions.
- Alert APIs with filtering, pagination, and stable ordering.
- Alert evidence relationships persisted and queryable.
- Duplicate open alert prevention during repeated analysis runs.

#### Case management

- Investigation case creation.
- Case creation from alert.
- Case title, status, priority, assignee, creator, timestamps, notes, and closure disposition.
- Case state machine:
  - `NEW`
  - `TRIAGED`
  - `UNDER_INVESTIGATION`
  - `ESCALATED`
  - `CLOSED`
- Validated state transitions.
- Reopen behavior with append-only audit event.
- Closure dispositions:
  - `CONFIRMED_FRAUD`
  - `FALSE_POSITIVE`
  - `INCONCLUSIVE`
  - `REFERRED`
- Case assignment and reassignment with role checks.
- Timestamped investigator notes.
- Evidence attachment for:
  - accounts;
  - transactions;
  - complaints;
  - alerts;
  - graph paths;
  - model assessments;
  - entity links.
- Evidence validation against existing records.
- No arbitrary URL evidence.
- No unchecked SQL-like identifier evidence.
- Evidence provenance snapshot support.
- Case event history with actor, action, timestamp, resource, and safe change summary.
- Append-only case history.
- Case search, filtering, and pagination.
- Case report generation entry point.

#### Audit

- Durable audit events for:
  - login/authentication events where practical;
  - case creation;
  - case updates;
  - case assignment;
  - evidence addition/removal;
  - disposition changes;
  - analysis runs;
  - report generation;
  - privileged configuration changes.
- Audit redaction for sensitive fields.
- No logging of passwords, bearer tokens, or full sensitive narratives.
- Read-only audit history endpoint for authorized roles.
- Audit pagination and filtering.
- Audit tests for material investigation actions.

#### PDF reports

- ReportLab-based PDF generation.
- Reports generated from persisted case, account, transaction, complaint, assessment, evidence, note, and event data.
- Report contents:
  - report title;
  - case ID;
  - generation timestamp;
  - generated-by user;
  - synthetic-data disclaimer;
  - case state, priority, assignment, and disposition;
  - executive summary derived from saved evidence and notes;
  - accounts and entities in scope;
  - transaction timeline;
  - candidate money-trail paths and constraints;
  - complaint correlation table with match tier/provenance;
  - risk assessment and contributing indicators;
  - evidence reference index;
  - investigator notes;
  - case event history;
  - limitations statement.
- Safe filename generation.
- Safe download headers.
- Authorization checks for report generation and download.
- Missing/expired case handling.
- PDF tests verifying non-empty output, PDF signature, and case identifier presence where feasible.

#### Frontend application

- React + TypeScript frontend.
- Vite build configuration.
- Tailwind-based analyst workstation styling.
- React Router page navigation.
- Typed API client.
- Centralized API base URL and error handling.
- TanStack Query-based server state.
- Reusable UI components for:
  - tables;
  - badges;
  - cards;
  - loading states;
  - empty states;
  - error states;
  - permission-denied states;
  - modals;
  - drawers;
  - forms;
  - pagination;
  - charts.
- Global layout with navigation, environment label, synthetic-data banner, current user, and role.
- Responsive desktop-first analyst layout.
- Accessible labels and keyboard-focus support.
- Consistent severity/status badges with text and colour.
- Currency formatting with explicit currency code.
- UTC timestamp formatting with timezone label.
- Risk score disclosure: priority score, not probability.

#### Frontend pages

- Executive dashboard backed by API data.
- Transaction monitoring table with filters, search, sorting, pagination, and transaction detail drawer.
- Account risk explorer with search, filters, sorting, pagination, and score disclosure.
- Account investigation profile with:
  - synthetic account overview;
  - score history;
  - incoming/outgoing summaries;
  - transaction timeline;
  - risk indicator cards;
  - model version and scoring mode;
  - graph summary;
  - related complaints;
  - connected cases/evidence.
- Graph investigation page using Cytoscape.js.
- Complaint correlation page separating exact matches from inferred associations.
- Alert queue with sorting, filtering, triage, evidence inspection, and case creation.
- Case management pages with case list, case detail, evidence, notes, events, transitions, assignment, and report download.
- Reports page with report availability and download state.
- Model monitoring / technical transparency page.
- Ingestion/admin page for synthetic data generation and JSON import where role permits.
- System pages for not-found, forbidden, and service-status states.

#### Authentication and authorization

- Role-based authentication layer.
- Roles:
  - `ADMIN`
  - `ANALYST`
  - `SENIOR_INVESTIGATOR`
  - `AUDITOR`
- Server-side role checks for protected actions.
- Password hashing using maintained hashing scheme.
- Token/session handling suitable for local SPA deployment.
- Inactive users blocked from authentication.
- Login throttling for local demo use.
- Development users seeded only when explicitly enabled.
- Development credentials marked as local-only and non-production.
- Passwords supplied through environment configuration, not hardcoded production defaults.
- Frontend role hiding for convenience only; backend remains the security boundary.
- Authentication and permission tests for allowed and denied access.

#### Observability and performance

- Health endpoint.
- Dependency/readiness endpoint where useful.
- Structured logging.
- Request ID propagation.
- Stable API error structure.
- Pagination for list endpoints.
- Stable ordering for deterministic API responses.
- Bounded graph operations.
- Timeouts/limits for expensive graph and report operations.
- Analysis run observability.
- Optional bounded caching with invalidation keys including dataset/version context.
- Database indexes for high-frequency query paths.
- Avoidance of whole-bank graph endpoints.
- No unbounded list endpoints.

#### Testing

- Pytest backend test suite.
- FastAPI TestClient API tests.
- Deterministic fixtures.
- Disposable test database support.
- Unit tests for:
  - features;
  - rules;
  - score normalization;
  - risk bands;
  - identifier normalization;
  - complaint matching;
  - temporal path constraints;
  - case transitions;
  - report generation.
- API tests for:
  - success;
  - invalid input;
  - not found;
  - pagination;
  - authentication;
  - authorization;
  - permission denied.
- Integration workflow test covering:
  1. seed synthetic data;
  2. verify accounts/transactions;
  3. run analysis;
  4. verify evidence-backed indicators;
  5. inspect flagged account explanations;
  6. query graph neighbourhood and money trail;
  7. query complaint correlations;
  8. create case from alert;
  9. attach evidence and add note;
  10. perform legal case transition;
  11. download and validate report;
  12. verify audit events.
- Graph tests for direction, temporal ordering, hop limits, cycle prevention, impossible paths, and result limits.
- ML tests for feature schema consistency, deterministic behavior, leakage protection, fallback behavior, corrupt artifact handling, and rare/single-class metric handling.
- Frontend TypeScript checks and production build.

#### Documentation

- `README.md` with setup, demo, testing, and limitation guidance.
- `docs/architecture.md` with backend/frontend/database boundaries and Mermaid diagrams.
- `docs/api.md` synchronized with OpenAPI conventions.
- `docs/data-dictionary.md` describing entities, fields, units, nullability, relationships, and indexes.
- `docs/model-card.md` describing intended use, prohibited use, synthetic training data, features, split strategy, leakage controls, metrics, calibration status, and limitations.
- `docs/security.md` with threat model, role matrix, secret management, audit logging, input validation, graph limits, and pre-deployment checklist.
- `docs/testing.md` describing test layers, fixtures, commands, and end-to-end reproduction.
- `docs/deployment.md` describing Docker, ports, environment values, migrations, persistence, reset, and troubleshooting.
- `docs/demo-walkthrough.md` describing deterministic synthetic demo steps.
- `docs/requirements-traceability.md` mapping requirements to modules, routes, endpoints, and tests.
- `docs/implementation-plan.md` with build checklist.
- Runbooks for backup/restore, demo reset, model retraining, troubleshooting, upgrading, and security checklist.
- Architecture decision records for major material decisions.

#### Deployment and CI

- Docker Compose stack with:
  - frontend;
  - backend;
  - PostgreSQL.
- Backend Dockerfile.
- Frontend multi-stage Dockerfile.
- Nginx configuration for SPA routing and `/api` proxying.
- Secure reverse-proxy headers where practical.
- Docker health checks and service readiness handling.
- Named volumes for local synthetic database persistence.
- Documented destructive demo reset command.
- Environment-based configuration without source-code edits.
- Backend entrypoint running migrations before serving.
- Optional development override compose file.
- GitHub Actions CI workflow.
- CI checks for:
  - Python dependency installation;
  - backend lint/type/test where configured;
  - frontend install;
  - TypeScript checking;
  - production frontend build;
  - configuration/schema validation where useful.
- Dependency caching in CI where supported.
- No secrets in CI.
- No live external API dependencies in tests.

### Changed

- Initial release; no prior behavior changed.

### Deprecated

- None.

### Removed

- None.

### Fixed

- Not applicable for initial release.

### Security

- Secrets are excluded from version control.
- `.env.example` contains placeholders only.
- Application fails safely when required non-local secrets are missing.
- Passwords are stored using salted hashing.
- Authentication tokens/sessions are handled server-side.
- Inactive users cannot authenticate.
- Role checks are enforced in backend dependencies/services.
- Frontend hiding is convenience only and not the security boundary.
- SQLAlchemy parameterization is used; request values are not concatenated into SQL.
- Request bodies, uploads, pagination, filters, graph hops, and path limits are validated.
- Graph endpoints are bounded and require constrained queries.
- Whole-bank graph access is not exposed by default.
- Report filenames and downloads are sanitized.
- Path traversal protections are applied to report/file outputs.
- Audit logs redact sensitive fields.
- Passwords, tokens, and secrets are not logged.
- Model artifacts are loaded only from controlled local artifact paths.
- User-uploaded model deserialization is not allowed.
- Complaint narratives are handled as synthetic text and are redacted in logs where appropriate.
- Evidence attachments must reference validated existing records.
- CORS origins are configurable.
- Secure headers are applied in the frontend reverse proxy where practical.
- Development accounts are explicitly marked as non-production.
- No automatic account freezing, payment blocking, blacklisting, or adverse customer action is implemented.

### Migration notes

- This is the first public schema version.
- Initialize the database with:

```bash
make migrate