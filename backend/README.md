# MULEGUARD Backend

**FastAPI backend for the MULEGUARD — Intelligent Mule Account Detection and Financial Fraud Investigation Platform**

> **Prototype notice:** This backend is part of a synthetic-first academic / hackathon-grade prototype. It is **not production-ready**, does not connect to real banking systems, does not process real customer data, and must not be used to make automatic adverse customer decisions.

> **Safety notice:** Alerts, risk scores, graph relationships, candidate money trails, and complaint correlations are **investigative leads only**. They are not proof of wrongdoing. This backend does not implement automatic account freezing, payment blocking, blacklisting, or any other adverse action.

---

## 1. Purpose

The MULEGUARD backend provides the operational core of the platform. It is responsible for:

- persistent domain storage;
- synthetic data generation;
- bulk ingestion and validation;
- account, transaction, complaint, and entity queries;
- point-in-time behavioural feature computation;
- rule-based detection;
- graph analytics and bounded money-trail search;
- complaint correlation;
- supervised and unsupervised ML scoring;
- risk fusion and alert generation;
- investigation case management;
- evidence validation and case history;
- audit logging;
- PDF report generation;
- role-based authentication and authorisation;
- model monitoring and evaluation transparency.

The backend is the **security boundary**. The frontend may hide controls for usability, but all protected actions must be enforced here.

---

## 2. Architecture summary

MULEGUARD uses a modular monolith backend.

```text
React / TypeScript frontend
        |
        | HTTP /api/v1
        v
FastAPI backend
        |
        | SQLAlchemy 2.x
        v
PostgreSQL / SQLite
        |
        v
Domain services:
  - ingestion
  - features
  - rules
  - graph
  - complaints
  - ML
  - risk
  - alerts
  - cases
  - audit
  - reports
```

Design principles:

- **Database is the source of truth.**
- **APIs are typed and versioned.**
- **Routes are thin; services contain domain logic.**
- **All alerts and indicators must reference persisted evidence.**
- **All graph queries are bounded.**
- **All ML assessments record model version and scoring mode.**
- **All material case actions are auditable.**
- **All reports are generated from persisted data.**
- **Missing ML artifacts trigger explicit fallback, not fabricated model claims.**

---

## 3. Backend module map

```text
backend/
├── app/
│   ├── main.py                  # FastAPI application factory and startup wiring
│   ├── db.py                    # SQLAlchemy engine/session management
│   ├── models.py                # SQLAlchemy domain models
│   ├── exceptions.py            # Domain and API exceptions
│   ├── lifecycle.py             # Startup/shutdown hooks
│   ├── bootstrap.py             # Optional local bootstrap helpers
│   │
│   ├── api/
│   │   ├── deps.py              # Auth, pagination, DB session, role dependencies
│   │   ├── error_handlers.py    # Stable API error responses
│   │   ├── middleware/          # Request ID, security headers, performance
│   │   └── v1/
│   │       ├── router.py        # Versioned API router
│   │       └── endpoints/       # Route handlers
│   │
│   ├── core/
│   │   ├── config.py            # Typed environment settings
│   │   ├── security.py          # Hashing, tokens, cryptographic helpers
│   │   ├── logging.py           # Structured logging
│   │   ├── roles.py             # Role definitions
│   │   ├── permissions.py       # Permission checks
│   │   ├── pagination.py        # Pagination helpers
│   │   ├── errors.py            # Error taxonomy
│   │   ├── rate_limit.py        # Login/API throttling helpers
│   │   ├── cache.py             # Optional bounded cache helpers
│   │   ├── enums.py             # Shared enums
│   │   └── constants.py         # Stable constants
│   │
│   ├── auth/
│   │   ├── service.py           # Authentication service
│   │   ├── passwords.py         # Password hashing policy
│   │   ├── tokens.py            # Token issuing/validation
│   │   ├── rbac.py              # Role-based access control
│   │   ├── throttling.py        # Login throttling
│   │   └── dev_users.py         # Local development user seeding
│   │
│   ├── ingestion/
│   │   ├── generator.py         # Deterministic synthetic generator
│   │   ├── seed.py              # CLI/module seeder
│   │   ├── validators.py        # Payload validation
│   │   ├── normalizers.py       # Identifier/reference normalisation
│   │   ├── loaders.py           # Bulk loading helpers
│   │   ├── dedupe.py            # Duplicate handling
│   │   └── provenance.py        # Source lineage
│   │
│   ├── ml/
│   │   ├── feature_schema.py    # Stable feature schema
│   │   ├── features.py          # ML-facing feature assembly
│   │   ├── labels.py            # Synthetic label isolation helpers
│   │   ├── splits.py            # Reproducible split strategy
│   │   ├── preprocessing.py     # Training-only preprocessing
│   │   ├── supervised.py        # Supervised classifier
│   │   ├── anomaly.py           # Isolation Forest anomaly model
│   │   ├── fallback.py          # Heuristic fallback scorer
│   │   ├── model_service.py     # Artifact loading/validation/inference
│   │   ├── train_model.py       # Training entrypoint
│   │   ├── evaluate.py          # Evaluation entrypoint
│   │   ├── explainability.py    # Deterministic explanations
│   │   ├── validation.py        # Leakage/schema checks
│   │   └── artifacts/           # Controlled local model artifact directory
│   │
│   ├── rules/
│   │   ├── engine.py            # Rule execution engine
│   │   ├── definitions.py       # Structured rule definitions
│   │   ├── thresholds.py        # Configurable thresholds
│   │   └── evidence.py          # Rule evidence builders
│   │
│   ├── graph/
│   │   ├── builder.py           # NetworkX MultiDiGraph construction
│   │   ├── metrics.py           # Degree, weighted volume, neighbourhood metrics
│   │   ├── neighborhood.py      # Bounded expansion
│   │   ├── trails.py            # Temporal money-trail search
│   │   ├── cycles.py            # Cycle candidates
│   │   ├── communities.py       # Optional community detection
│   │   ├── filters.py           # Status/time/amount filters
│   │   ├── limits.py            # Server-side query limits
│   │   └── serialization.py     # API-safe graph payloads
│   │
│   ├── correlation/
│   │   ├── normalizers.py       # Complaint/reference normalisation
│   │   ├── exact_reference.py   # Tier 1 exact matching
│   │   ├── identifier_match.py  # Tier 2 normalised identifier matching
│   │   ├── entity_association.py# Tier 3 entity/account association
│   │   ├── temporal_association.py # Tier 4 temporal graph association
│   │   ├── narrative_extraction.py # Optional Tier 5 deterministic extraction
│   │   ├── confidence.py        # Match confidence/provenance
│   │   └── service.py           # Correlation orchestration
│   │
│   ├── services/
│   │   ├── accounts.py
│   │   ├── transactions.py
│   │   ├── complaints.py
│   │   ├── entities.py
│   │   ├── entity_links.py
│   │   ├── features.py
│   │   ├── alerts.py
│   │   ├── analysis.py
│   │   ├── risk.py
│   │   ├── graph.py
│   │   ├── complaint_correlation.py
│   │   ├── cases.py
│   │   ├── case_state_machine.py
│   │   ├── evidence.py
│   │   ├── case_events.py
│   │   ├── notes.py
│   │   ├── audit.py
│   │   ├── dashboard.py
│   │   ├── reports.py
│   │   ├── ingestion.py
│   │   ├── users.py
│   │   └── model_metrics.py
│   │
│   ├── reports/
│   │   ├── pdf.py               # ReportLab PDF renderer
│   │   ├── sections.py          # Report section builders
│   │   ├── layout.py            # Page/table layout helpers
│   │   ├── filenames.py         # Safe filename generation
│   │   ├── evidence_index.py    # Evidence reference index
│   │   └── limitations.py       # Limitations/disclaimer text
│   │
│   ├── schemas/
│   │   ├── auth.py
│   │   ├── common.py
│   │   ├── pagination.py
│   │   ├── users.py
│   │   ├── accounts.py
│   │   ├── transactions.py
│   │   ├── complaints.py
│   │   ├── entities.py
│   │   ├── ingestion.py
│   │   ├── features.py
│   │   ├── alerts.py
│   │   ├── analysis.py
│   │   ├── graph.py
│   │   ├── cases.py
│   │   ├── audit.py
│   │   ├── dashboard.py
│   │   ├── model_metrics.py
│   │   └── reports.py
│   │
│   └── utils/
│       ├── dates.py
│       ├── decimals.py
│       ├── json.py
│       ├── ids.py
│       ├── filenames.py
│       ├── hashing.py
│       └── text.py
│
├── config/
│   ├── rules.default.json
│   ├── scoring.default.json
│   ├── windows.default.json
│   └── alert_deduplication.default.json
│
├── migrations/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│
├── tests/
│   ├── conftest.py
│   ├── factories.py
│   ├── fixtures/
│   └── test_*.py
│
├── alembic.ini
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── Dockerfile
├── docker-entrypoint.sh
└── README.md
```

---

## 4. Prerequisites

Required:

- Python 3.11 or newer;
- PostgreSQL 15+ for Docker deployment;
- SQLite may be used for local development and tests where supported;
- Docker and Docker Compose for containerised deployment;
- Git.

Optional but recommended:

- GNU Make;
- `ruff`;
- `mypy`;
- `pytest`;
- `pip-audit`.

---

## 5. Local development quick start

From the repository root:

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment.

Unix/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install backend dependencies:

```bash
pip install -r requirements-dev.txt
```

Create a local environment file:

Unix/macOS:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and replace all `CHANGE_ME` values.

At minimum, configure:

```dotenv
BACKEND_SECRET_KEY=generate_a_strong_secret
DATABASE_URL=postgresql+psycopg2://muleguard:your_password@localhost:5432/muleguard
POSTGRES_PASSWORD=your_password
DEV_ADMIN_PASSWORD=your_local_dev_password
DEV_ANALYST_PASSWORD=your_local_dev_password
DEV_SENIOR_INVESTIGATOR_PASSWORD=your_local_dev_password
DEV_AUDITOR_PASSWORD=your_local_dev_password
```

Generate a strong secret:

```bash
python -c "import secrets; print(secrets.token_hex(64))"
```

Apply database migrations:

```bash
alembic upgrade head
```

Seed deterministic synthetic demo data:

```bash
python -m app.ingestion.seed
```

Start the backend:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Default local endpoints:

```text
Backend:     http://localhost:8000
Health:      http://localhost:8000/health
OpenAPI:     http://localhost:8000/docs
Redoc:       http://localhost:8000/redoc
API prefix:  /api/v1
```

---

## 6. Using root Makefile targets

If the root `Makefile` is present, these commands are usually easier:

```bash
make install-backend
make migrate
make seed
make dev-backend
make test-backend
```

Docker-based backend development:

```bash
docker compose up --build backend
```

---

## 7. Configuration

Backend configuration is loaded from environment variables through typed settings in:

```text
app/core/config.py
```

The safe template is:

```text
backend/.env.example
```

Important configuration groups:

| Group          | Examples                                                                |
| -------------- | ----------------------------------------------------------------------- |
| Runtime        | `BACKEND_ENV`, `BACKEND_DEBUG`, `BACKEND_LOG_LEVEL`                     |
| API            | `BACKEND_API_PREFIX`, `BACKEND_OPENAPI_ENABLED`, `BACKEND_DOCS_ENABLED` |
| Security       | `BACKEND_SECRET_KEY`, `BACKEND_CORS_ORIGINS`, `BACKEND_ALLOWED_HOSTS`   |
| Database       | `DATABASE_URL`, `POSTGRES_*`, `DB_POOL_*`                               |
| Auth           | `AUTH_ENABLED`, `AUTH_MODE`, `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES`         |
| RBAC           | `RBAC_ENABLED`, role permission variables                               |
| Synthetic data | `SEED_RANDOM_SEED`, `SEED_ACCOUNTS`, `SEED_TRANSACTIONS`                |
| Ingestion      | `INGESTION_MAX_BATCH_SIZE`, `INGESTION_TRANSACTIONAL_BATCH`             |
| Features       | `FEATURE_WINDOWS`, `FEATURE_STRICT_POINT_IN_TIME`                       |
| Rules          | `RULES_ENABLED`, `RULES_CONFIG_PATH`, rule thresholds                   |
| Graph          | `GRAPH_MAX_HOPS`, `GRAPH_MAX_NODES`, `MONEY_TRAIL_MAX_PATHS`            |
| ML             | `ML_ARTIFACT_DIR`, `ML_ACTIVE_SCORING_MODE`, `ML_REQUIRE_TRAINED_MODEL` |
| Risk           | `RISK_WEIGHT_*`, `RISK_BAND_*`, `RISK_SCORE_VERSION`                    |
| Alerts         | `ALERT_DEDUPLICATION_ENABLED`, `ALERT_DEDUPLICATION_WINDOW_HOURS`       |
| Cases          | `CASE_DEFAULT_STATUS`, `CASE_DISPOSITION_OPTIONS`                       |
| Audit          | `AUDIT_ENABLED`, `AUDIT_REDACTION_PATTERNS`                             |
| Reports        | `REPORT_ENABLED`, `REPORT_OUTPUT_DIR`, `REPORT_FILENAME_PREFIX`         |

Production-like settings must disable demo-only behaviour:

```dotenv
BACKEND_ENV=production
BACKEND_DEBUG=false
SEED_DEV_USERS=false
SEED_DEMO_DATA=false
BACKEND_OPENAPI_ENABLED=false
BACKEND_DOCS_ENABLED=false
AUTH_COOKIE_SECURE=true
BACKEND_REQUIRE_STRONG_SECRET_IN_NON_LOCAL=true
```

The backend should fail safely if required secrets are missing or still contain placeholder values in non-local environments.

---

## 8. Database and migrations

The backend uses:

- SQLAlchemy 2.x models;
- Alembic migrations;
- UTC timestamps;
- `Decimal` / SQL `NUMERIC` for monetary amounts;
- indexed query paths for transactions, alerts, cases, complaints, and audit history.

Apply migrations:

```bash
alembic upgrade head
```

Create a new migration after changing models:

```bash
alembic revision --autogenerate -m "describe change"
```

Always review autogenerated migrations manually before applying them.

Important rules:

- `create_all()` is not the deployed schema path.
- Destructive migrations require explicit confirmation.
- Monetary amounts must not be stored as floats.
- Failed or reversed transactions must not be treated as completed fund movement.
- Synthetic ground-truth labels must remain isolated from model features.

---

## 9. Domain entities

The backend persists, at minimum:

| Entity                 | Purpose                                                                  |
| ---------------------- | ------------------------------------------------------------------------ |
| `Account`              | Synthetic bank account identity and lifecycle metadata                   |
| `Transaction`          | Completed/pending/failed/reversed transfer records with evidence lineage |
| `Complaint`            | Synthetic complaint facts, references, and source metadata               |
| `Entity`               | Devices, phone hashes, UPI IDs, and other synthetic identifiers          |
| `AccountEntityLink`    | Time-bound account-to-entity relationships                               |
| `FeatureSnapshot`      | Point-in-time behavioural feature records                                |
| `ModelAssessment`      | Score, model version, scoring mode, and assessment metadata              |
| `RiskIndicator`        | Evidence-backed indicator for an account assessment                      |
| `RuleHit`              | Triggered rule, measured value, threshold, and evidence                  |
| `Alert`                | Ranked investigative alert                                               |
| `AlertEvidence`        | Evidence references attached to an alert                                 |
| `InvestigationCase`    | Analyst-owned investigation case                                         |
| `CaseEvidence`         | Validated evidence attached to a case                                    |
| `CaseEvent`            | Append-only case history                                                 |
| `CaseNote`             | Timestamped investigator note                                            |
| `AuditEvent`           | Durable audit record                                                     |
| `ModelVersion`         | Model artifact metadata                                                  |
| `ModelEvaluation`      | Evaluation metrics and limitations                                       |
| `ComplaintCorrelation` | Match tier, method, confidence, and provenance                           |
| `AnalysisRun`          | Batch analysis state and counts                                          |
| `GroundTruthLabel`     | Isolated synthetic label store, never used as a predictor                |

---

## 10. Synthetic data generation

MULEGUARD is synthetic-first.

The generator creates deterministic:

- legitimate accounts;
- legitimate transactions;
- suspicious injected scenarios;
- complaints;
- entity relationships;
- isolated synthetic ground-truth labels.

Run the seeder:

```bash
python -m app.ingestion.seed
```

Example options, depending on implementation:

```bash
python -m app.ingestion.seed --reset --confirm-local-demo
```

or from repository root:

```bash
make seed
make seed-reset CONFIRM=1
```

Default quick-start synthetic dataset:

```dotenv
SEED_RANDOM_SEED=42
SEED_ACCOUNTS=1200
SEED_TRANSACTIONS=25000
SEED_COMPLAINTS=150
SEED_ENTITY_LINKS=400
SEED_FRAUD_SCENARIOS=12
```

Larger optional dataset:

```dotenv
SEED_LARGE_DATASET=true
SEED_LARGE_ACCOUNTS=10000
SEED_LARGE_TRANSACTIONS=100000
```

Injected scenarios include:

```text
SCN-RAPID-PASS-THROUGH-001
SCN-FAN-IN-001
SCN-FAN-OUT-001
SCN-LAYERING-001
SCN-CYCLE-001
SCN-DORMANT-ACTIVE-001
SCN-HIGH-VELOCITY-001
SCN-COMPLAINT-LINKED-001
SCN-SHARED-ENTITY-001
SCN-HARD-NEGATIVE-001
```

These are synthetic demo scenarios only. They are not real incidents.

Leakage controls:

- ground-truth labels are stored separately;
- fraud-ring IDs are not model features;
- scenario IDs are not model features;
- future complaints are not used for past assessments;
- future investigation outcomes are not used as predictors.

---

## 11. Ingestion and validation

Supported bulk ingestion:

```text
POST /api/v1/ingestion/accounts
POST /api/v1/ingestion/transactions
POST /api/v1/ingestion/complaints
POST /api/v1/ingestion/entity-links
```

Validation covers:

- required fields;
- field types;
- positive completed transfer amounts;
- supported currency values;
- supported status values;
- supported channel values;
- valid timestamp format and timezone handling;
- referenced account existence;
- duplicate transaction references;
- duplicate complaint references;
- maximum batch size;
- maximum request size;
- malformed/unexpected fields;
- source provenance.

Batch responses should include:

```json
{
  "accepted": 0,
  "rejected": 0,
  "duplicated": 0,
  "skipped": 0,
  "errors": []
}
```

Row-level errors must be useful but must not leak secrets or unnecessary sensitive narrative content.

Transactional behaviour:

- failed batches should not leave unpredictable partial records unless partial acceptance is explicitly enabled and reported;
- duplicate handling must be deterministic;
- unknown fields should be rejected by default.

---

## 12. Feature engine

The feature engine computes point-in-time behavioural features using an explicit `as_of` timestamp.

Default windows:

```text
1h
24h
7d
30d
```

Feature categories:

- incoming/outgoing transaction counts;
- incoming/outgoing amounts;
- average and median transaction values;
- dispersion / standard deviation;
- distinct incoming counterparties;
- distinct outgoing recipients;
- failed/reversed counts and ratios;
- transaction velocity;
- inter-transaction time statistics;
- incoming-to-outgoing value ratio;
- pass-through ratio;
- amount deviation from account baseline;
- sudden activity after inactivity;
- recipient diversity change;
- recent-versus-historical activity change;
- bounded graph-derived features.

Temporal correctness rules:

- only transactions with `occurred_at <= as_of` may be used;
- only complaints reported by `as_of` may be used;
- only entity relationships valid at `as_of` may be used;
- future investigation outcomes must never be used;
- synthetic ground-truth labels must never be used as predictors.

Feature snapshots may be persisted for reproducibility and explanation.

---

## 13. Rule engine

Rules are implemented as structured, testable definitions, not unexplained conditional logic inside API routes.

Initial rules:

| Rule code                          | Meaning                                                       |
| ---------------------------------- | ------------------------------------------------------------- |
| `RAPID_PASS_THROUGH`               | Substantial incoming funds moved onward within a short period |
| `HIGH_VELOCITY`                    | Unusually many transfers in a defined window                  |
| `FAN_IN`                           | Several independent sources send money to one account         |
| `FAN_OUT`                          | One account distributes to many recipients                    |
| `DORMANT_TO_ACTIVE`                | Sudden meaningful activity after quiet history                |
| `AMOUNT_DEVIATION`                 | Activity departs from the account’s own baseline              |
| `LAYERED_PATH`                     | Plausible time-ordered multi-hop transfer path                |
| `CIRCULAR_MOVEMENT`                | Temporal cycle candidate                                      |
| `COMPLAINT_REFERENCE_ASSOCIATION`  | Complaint reference matches transaction/account               |
| `SUSPICIOUS_NEIGHBOUR_ASSOCIATION` | Limited signal from relationship to flagged account           |

Each rule result includes:

```json
{
  "rule_code": "RAPID_PASS_THROUGH",
  "title": "Rapid pass-through movement",
  "triggered": true,
  "measured_value": 0.91,
  "threshold": 0.80,
  "severity": "HIGH",
  "explanation": "89.1% of incoming volume was transferred onward within 60 minutes.",
  "evidence_references": ["TXN-..."],
  "rule_version": "v1"
}
```

Important constraints:

- thresholds are configurable;
- demo thresholds are not universal banking thresholds;
- a rule hit is an investigative indicator, not proof;
- suspicious-neighbour association must never create a verdict by itself;
- shared-entity links must be capped and must not automatically escalate every connected account to maximum risk.

---

## 14. Graph analytics

The graph engine builds a NetworkX `MultiDiGraph` from persisted transactions.

Graph properties:

- multiple transactions between the same account pair are preserved;
- each edge preserves transaction ID, amount, currency, status, and timestamp;
- only qualifying completed statuses represent completed money movement;
- graph construction is derived from the database or a bounded cached snapshot;
- the database remains the source of truth.

Supported operations:

- bounded neighbourhood expansion;
- directed in/out degree;
- weighted incoming/outgoing volume;
- connected component summaries under documented direction semantics;
- cycle candidates;
- high-degree and intermediary candidates;
- complaint-linked neighbourhoods;
- candidate time-ordered money trails.

Graph safety limits:

```dotenv
GRAPH_MAX_HOPS=3
GRAPH_MAX_NODES=500
GRAPH_MAX_EDGES=1500
GRAPH_MAX_PATHS=20
GRAPH_MAX_DATE_SPAN_DAYS=90
GRAPH_TIMEOUT_SECONDS=15
```

Money-trail rules:

- source account is required;
- destination is optional;
- transaction direction must be respected;
- timestamps must be chronologically ordered;
- cycles within a candidate path are prevented by default;
- same-timestamp behaviour is configurable and documented;
- results are candidate flow paths, not exact tracing of specific currency units.

Endpoint examples:

```text
GET /api/v1/graph?root_account_id=...&hops=2
GET /api/v1/graph/money-trails?source_account_id=...&max_hops=3
GET /api/v1/graph/accounts/{account_id}/metrics
```

Graph proximity is never proof of wrongdoing.

---

## 15. Complaint correlation

Complaint correlation uses explicit match tiers.

| Tier | Type                                        | Confidence style                              |
| ---- | ------------------------------------------- | --------------------------------------------- |
| 1    | Exact transaction/complaint reference match | Deterministic exact match                     |
| 2    | Normalised identifier match                 | High-confidence normalised match              |
| 3    | Account/entity association                  | Inferred association                          |
| 4    | Temporal graph association                  | Potential association                         |
| 5    | Optional narrative extraction               | Deterministic extraction, disabled by default |

Rules:

- raw complaint facts are preserved;
- normalised values are stored separately;
- exact matches are separated from inferred associations;
- ambiguous normalisation collisions are rejected or flagged;
- missing references are handled gracefully;
- duplicate complaints are handled predictably;
- narrative extraction, if enabled, preserves evidence span and method;
- fuzzy text matches are not treated as verified evidence.

Endpoint examples:

```text
GET /api/v1/complaints
GET /api/v1/complaints/{complaint_id}
GET /api/v1/complaints/correlations
```

---

## 16. Machine-learning pipeline

The ML subsystem includes:

- transparent rules-only baseline;
- supervised tabular classifier;
- unsupervised Isolation Forest anomaly detector;
- explicit heuristic fallback when no trained artifact exists.

Training command:

```bash
python -m app.ml.train_model --seed 42
```

Training pipeline behaviour:

1. retrieve or generate labelled synthetic accounts and features;
2. validate feature and label integrity;
3. create a reproducible split;
4. fit preprocessing only on the training partition;
5. fit the supervised model;
6. train the anomaly detector;
7. evaluate on held-out data;
8. save artifacts plus metadata;
9. print a readable metric report;
10. fail clearly on invalid or empty training data.

Default model choices:

```dotenv
ML_MODEL_TYPE=hist_gradient_boosting
ML_ANOMALY_MODEL_TYPE=isolation_forest
ML_TRAINING_SEED=42
ML_SPLIT_STRATEGY=scenario_aware_chronological
```

Split strategy:

- prefer chronological or scenario-aware split;
- reduce leakage across linked accounts and injected fraud rings;
- if strict temporal split is not possible, document the alternative and its limitations.

Leakage controls:

- synthetic labels are isolated;
- fraud-ring IDs are excluded;
- scenario IDs are excluded;
- future complaints are excluded;
- future investigation outcomes are excluded;
- preprocessing is fitted only on training data.

Artifact safety:

```dotenv
ML_ARTIFACT_DIR=app/ml/artifacts
ML_ARTIFACT_TRUSTED_PATH_ONLY=true
ML_DISABLE_UNTRUSTED_PICKLE_UPLOADS=true
ML_ARTIFACT_CHECKSUM_REQUIRED=true
```

The backend must not load arbitrary model artifacts from user uploads.

Fallback behaviour:

If no trained artifact exists:

```text
scoring_mode = heuristic_fallback
```

If a trained artifact exists and loads successfully:

```text
scoring_mode = trained_model
```

Fallback must be visible in API responses and UI. It must not pretend that a heuristic score is a model probability.

Evaluation metrics may include:

- precision;
- recall;
- F1;
- PR-AUC where supported;
- ROC-AUC as supplementary metric;
- Precision@K / top-K review yield;
- confusion matrix;
- false-positive rate;
- latency per batch/account at stated dataset size.

Undefined metrics must be reported honestly as unavailable.

---

## 17. Explainability

Every assessed account should return a structured explanation object containing:

- score;
- score type;
- risk band;
- scoring mode;
- model version, if available;
- assessment timestamp;
- `as_of` timestamp;
- top contributing features;
- triggered rule indicators;
- graph-derived evidence;
- complaint matches;
- evidence reference IDs;
- caveats;
- missing-data notes.

Explanation rules:

- explanations must cite real persisted feature values, rule hits, graph evidence, or complaint correlations;
- SHAP, if enabled, is explanatory only and not causal;
- if SHAP is unavailable, deterministic feature/rule explanations must be used and labelled accurately;
- scores are investigative priority scores, not probabilities of guilt.

---

## 18. Risk fusion and prioritisation

Risk fusion combines signals transparently.

Default conceptual formula:

```text
priority_score =
  100 * weighted_combination(
    supervised_signal,
    anomaly_signal,
    graph_signal,
    rule_signal
  )
```

Default weights:

```dotenv
RISK_WEIGHT_SUPERVISED=0.35
RISK_WEIGHT_ANOMALY=0.25
RISK_WEIGHT_GRAPH=0.20
RISK_WEIGHT_RULES=0.20
```

Important controls:

```dotenv
RISK_SHARED_ENTITY_CAP=0.15
RISK_NEIGHBOUR_ALERT_CAP=0.20
RISK_COMPLAINT_EXACT_CAP=0.30
RISK_RULE_MAX_CONTRIB=0.40
```

Risk bands:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

The score is labelled:

```text
Investigative priority score
```

It is not:

- a probability of fraud;
- a calibrated likelihood;
- proof of guilt;
- an automatic enforcement decision.

Repeated analysis runs should retain score history and avoid creating duplicate open alerts for the same account and detection window.

---

## 19. Alerts

Alert creation sources:

- triggered rules;
- model assessments;
- graph-derived indicators;
- complaint correlations;
- fused risk score.

Alert deduplication:

```dotenv
ALERT_DEDUPLICATION_ENABLED=true
ALERT_DEDUPLICATION_STRATEGY=account_window_signal
ALERT_DEDUPLICATION_WINDOW_HOURS=24
```

Alert detail must include:

- account ID;
- assessment ID where available;
- priority/state;
- triggered indicators;
- evidence references;
- scoring mode;
- model version;
- rule versions;
- created/updated timestamps.

Alert triage actions must be permission-checked and audited where material.

Endpoint examples:

```text
GET /api/v1/alerts
GET /api/v1/alerts/{alert_id}
PATCH /api/v1/alerts/{alert_id}
```

---

## 20. Case management

Case management is investigator-owned.

Default states:

```text
NEW
TRIAGED
UNDER_INVESTIGATION
ESCALATED
CLOSED
```

Allowed transitions are centrally defined and validated in:

```text
app/services/case_state_machine.py
```

Closure dispositions:

```text
CONFIRMED_FRAUD
FALSE_POSITIVE
INCONCLUSIVE
REFERRED
```

These dispositions are investigator-entered assessments in the synthetic prototype. They are not automatic conclusions.

Case actions:

- create case;
- create case from alert;
- assign/reassign;
- attach evidence;
- remove evidence where permitted;
- add notes;
- update priority/status;
- close case;
- reopen case;
- inspect event history;
- generate report.

Evidence integrity rules:

- evidence must reference an existing validated record;
- arbitrary URLs are not accepted;
- unchecked SQL-like identifiers are not accepted;
- evidence snapshots may store provenance;
- case history is append-only;
- reopening appends an event rather than deleting history.

Endpoint examples:

```text
GET /api/v1/cases
POST /api/v1/cases
GET /api/v1/cases/{case_id}
PATCH /api/v1/cases/{case_id}
POST /api/v1/cases/from-alert/{alert_id}
POST /api/v1/cases/{case_id}/evidence
POST /api/v1/cases/{case_id}/notes
GET /api/v1/cases/{case_id}/events
```

---

## 21. Audit logging

Audit records capture:

- actor;
- action;
- target resource;
- timestamp;
- safe metadata;
- outcome where useful.

Material audited actions include:

- login/logout where practical;
- failed login;
- denied access;
- case creation/update;
- case assignment;
- evidence addition/removal;
- note addition;
- disposition change;
- analysis run;
- ingestion batch;
- model training/evaluation/loading;
- report generation;
- privileged configuration changes.

Audit redaction rules:

- never log passwords;
- never log bearer tokens;
- never log secrets;
- do not log full sensitive complaint narratives unnecessarily;
- sanitise metadata before persistence.

Endpoint example:

```text
GET /api/v1/audit
```

Access is restricted to permitted roles such as `AUDITOR` and `ADMIN`.

---

## 22. PDF report generation

Reports are generated using ReportLab from persisted case, account, transaction, complaint, assessment, evidence, note, and event data.

Command/API:

```text
GET /api/v1/reports/cases/{case_id}/report
```

Report contents include:

- title;
- case ID;
- generation timestamp;
- generated-by user;
- synthetic-data disclaimer;
- case state, priority, assignment, disposition;
- executive summary derived from saved evidence and notes;
- accounts and entities in scope;
- transaction timeline;
- candidate money-trail paths and constraints;
- complaint correlation table;
- risk assessment and contributing indicators;
- evidence reference index;
- investigator notes;
- case event history;
- limitations.

Report safety rules:

- no fabricated evidence text;
- no real customer data;
- synthetic disclaimer included;
- limitations included;
- safe filenames;
- safe download headers;
- authorisation checked;
- missing/expired case handled cleanly.

---

## 23. Authentication and authorisation

The backend implements role-based authentication for the local prototype.

Roles:

| Role                  | Purpose                                                                             |
| --------------------- | ----------------------------------------------------------------------------------- |
| `ADMIN`               | Manage users/configuration and permitted administrative functions                   |
| `ANALYST`             | Run analysis, inspect alerts, investigate accounts, manage cases within permissions |
| `SENIOR_INVESTIGATOR` | Analyst access plus case assignment/review and approved dispositions                |
| `AUDITOR`             | Read permitted records and audit history without mutation permissions               |

Authentication defaults:

```dotenv
AUTH_ENABLED=true
AUTH_MODE=jwt_bearer
AUTH_PASSWORD_HASH_SCHEME=argon2id
AUTH_ACCESS_TOKEN_EXPIRE_MINUTES=30
AUTH_RATE_LIMIT_ENABLED=true
```

Password policy:

- salted hashing;
- Argon2id preferred where available;
- bcrypt acceptable if configured securely;
- inactive users cannot authenticate;
- development users are local-only and must be disabled in production-like environments.

Development users may be seeded when:

```dotenv
SEED_DEV_USERS=true
```

Example development usernames:

```text
admin
analyst
senior_investigator
auditor
```

Development passwords must come from environment variables or forced reset. Do not publish known shared passwords as production defaults.

Authorisation rules:

- backend dependencies enforce roles;
- frontend hiding is not the security boundary;
- write actions are permission-checked;
- audit reads are restricted;
- report generation/download is permission-checked;
- ingestion/seed/reset are admin-only by default;
- case assignment/close/reopen require senior/admin permissions.

---

## 24. API overview

Base path:

```text
/api/v1
```

OpenAPI:

```text
http://localhost:8000/docs
```

Key endpoint groups:

| Area          | Examples                                                        |
| ------------- | --------------------------------------------------------------- |
| Health        | `GET /health`, `GET /api/v1/health/ready`                       |
| Auth          | `POST /api/v1/auth/login`, `GET /api/v1/auth/me`                |
| Dashboard     | `GET /api/v1/dashboard/summary`                                 |
| Accounts      | `GET /api/v1/accounts`, `GET /api/v1/accounts/{id}`             |
| Transactions  | `GET /api/v1/transactions`, `GET /api/v1/transactions/{id}`     |
| Analysis      | `POST /api/v1/analysis/run`, `GET /api/v1/analysis/status`      |
| Alerts        | `GET /api/v1/alerts`, `PATCH /api/v1/alerts/{id}`               |
| Graph         | `GET /api/v1/graph`, `GET /api/v1/graph/money-trails`           |
| Complaints    | `GET /api/v1/complaints`, `GET /api/v1/complaints/correlations` |
| Ingestion     | `POST /api/v1/ingestion/*`                                      |
| Cases         | `GET/POST/PATCH /api/v1/cases...`                               |
| Audit         | `GET /api/v1/audit`                                             |
| Reports       | `GET /api/v1/reports/cases/{case_id}/report`                    |
| Model metrics | `GET /api/v1/model/metrics`                                     |

API conventions:

- typed Pydantic request/response models;
- no raw ORM objects returned directly;
- stable error structure;
- pagination for list endpoints;
- stable ordering;
- 4xx for invalid input;
- 401 for unauthenticated;
- 403 for forbidden;
- 404 for missing resources;
- no stack traces in client responses.

---

## 25. Error handling

The backend should return a stable error structure:

```json
{
  "code": "MULEGUARD_VALIDATION_ERROR",
  "message": "Request validation failed.",
  "details": [],
  "request_id": "..."
}
```

Rules:

- distinguish validation errors from unexpected server failures;
- sanitise client-facing error messages;
- do not expose secrets, tokens, stack traces, or raw database errors;
- include request ID where feasible;
- audit unexpected errors where appropriate.

---

## 26. Observability

Structured logging should include safe fields such as:

- request ID;
- method;
- path;
- status;
- latency;
- user ID;
- role;
- resource ID;
- action;
- outcome;
- error code.

Do not log:

- passwords;
- bearer tokens;
- secrets;
- full sensitive complaint narratives unnecessarily.

Health endpoints:

```text
GET /health
GET /api/v1/health/ready
```

Analysis run observability:

- started time;
- finished time;
- processed count;
- error count;
- active model version;
- active scoring mode;
- run state.

---

## 27. Performance guidance

The backend is intended for local synthetic datasets first.

Performance rules:

- list endpoints must be paginated;
- database indexes must support common query paths;
- graph queries must be bounded;
- expensive graph metrics should not be recomputed per dashboard row;
- caches, if enabled, must include dataset/version/time-window context;
- report generation must have timeouts;
- ML inference must handle missing artifacts gracefully;
- large datasets must be optional, not default startup behaviour.

---

## 28. Testing

Run backend tests:

```bash
pytest -q
```

Run with coverage:

```bash
pytest --cov=app --cov-report=term-missing
```

Run lint:

```bash
ruff check app tests
ruff format --check app tests
```

Run typecheck:

```bash
mypy app
```

Test categories:

- unit tests;
- API tests;
- integration workflow tests;
- graph tests;
- ML tests;
- case transition tests;
- evidence validation tests;
- audit tests;
- report tests;
- auth/permission tests.

Important test expectations:

- deterministic fixtures;
- disposable test database;
- no writes to developer demo database;
- no dependence on live external APIs;
- positive/negative/boundary tests for rules;
- point-in-time correctness tests;
- leakage tests;
- fallback tests;
- corrupt artifact tests;
- bounded graph tests;
- illegal case transition tests;
- report authorisation tests.

End-to-end workflow test should cover:

1. seed synthetic data;
2. verify accounts and transactions exist;
3. run analysis;
4. verify expected injected scenario produces evidence-backed indicators;
5. query flagged account and explanation;
6. query graph neighbourhood and known candidate money trail;
7. query complaint correlations;
8. create case from alert;
9. attach evidence and add note;
10. update case through legal transition;
11. download and validate report;
12. verify audit events.

---

## 29. Docker

The backend Dockerfile expects the build context:

```text
muleguard/backend
```

Build:

```bash
DOCKER_BUILDKIT=1 docker build -f backend/Dockerfile -t muleguard/backend:latest backend
```

Run:

```bash
docker run --rm -p 8000:8000 --env-file backend/.env muleguard/backend:latest
```

With migrations on startup:

```bash
docker run --rm \
  -p 8000:8000 \
  -e ALEMBIC_UPGRADE_ON_START=true \
  --env-file backend/.env \
  muleguard/backend:latest
```

With local synthetic demo seeding:

```bash
docker run --rm \
  -p 8000:8000 \
  -e ALEMBIC_UPGRADE_ON_START=true \
  -e SEED_DEV_USERS=true \
  -e SEED_DEMO_DATA=true \
  --env-file backend/.env \
  muleguard/backend:latest
```

The container:

- runs as a non-root user;
- does not copy `.env` into the image;
- creates writable runtime directories;
- optionally runs Alembic migrations;
- optionally seeds local development users and synthetic demo data;
- refuses demo seeding in production-like environments;
- refuses placeholder secrets in production-like environments;
- exposes a healthcheck without requiring `curl`.

---

## 30. Security checklist for backend changes

Before merging backend changes, confirm:

- [ ] No real customer data is introduced.
- [ ] No secrets are hardcoded.
- [ ] `.env` remains out of version control.
- [ ] SQL is parameterised through SQLAlchemy.
- [ ] All request inputs are validated.
- [ ] Pagination is bounded and stable.
- [ ] Graph queries are bounded.
- [ ] Report filenames are sanitized.
- [ ] Path traversal is prevented.
- [ ] Role checks are enforced server-side.
- [ ] Audit events are emitted for material actions.
- [ ] Sensitive fields are not logged.
- [ ] Model artifacts are loaded only from controlled paths.
- [ ] User-uploaded model deserialization is not allowed.
- [ ] Missing ML artifacts produce explicit fallback.
- [ ] No automatic adverse customer action is introduced.
- [ ] No unsupported production/regulatory claims are introduced.

---

## 31. Known backend limitations

- The backend is a synthetic prototype, not a production banking system.
- Model metrics are computed on synthetic data and do not establish real-world accuracy.
- Risk scores are investigative priority scores, not calibrated probabilities.
- Graph relationships are investigative leads, not proof of common control or wrongdoing.
- Candidate money trails are flow hypotheses, not exact currency tracing.
- Complaint correlations may be inferred and require review.
- Rule thresholds are demo defaults, not universal banking thresholds.
- Authentication is demo-grade unless hardened for deployment.
- PDF reports are investigation support, not legal evidence.
- Long-running analysis is synchronous by default unless a background worker is explicitly implemented.
- Large graph operations are intentionally bounded to protect local performance.

---

## 32. Documentation links

Relevant project documentation:

```text
../README.md
../docs/architecture.md
../docs/api.md
../docs/data-dictionary.md
../docs/model-card.md
../docs/security.md
../docs/testing.md
../docs/deployment.md
../docs/demo-walkthrough.md
../docs/requirements-traceability.md
```

---

## 33. Final reminder

This backend is part of a responsible-by-design synthetic prototype.

It prioritises investigative work. It does not adjudicate guilt. It does not automate enforcement. It does not claim regulatory compliance. It does not use real customer data by default.

All alerts, scores, graph paths, and complaint correlations must remain evidence-backed, explainable, auditable, and human-reviewed.