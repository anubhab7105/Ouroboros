---
title: MULEGUARD ML Artifacts Directory
module: muleguard.backend.app.ml.artifacts
status: inert-placeholder
purpose: directory-layout preservation and artifact-boundary policy
persistent_storage_allowed: false
production_artifact_storage_allowed: false
real_customer_data_allowed: false
raw_narratives_allowed: false
raw_identifiers_allowed: false
labels_as_features_allowed: false
secrets_allowed: false
model_binaries_allowed: false
datasets_allowed: false
pickles_allowed: false
notebooks_allowed: false
exports_allowed: false
logs_allowed: false
caches_allowed: false
runtime_state_allowed: false
synthetic_first: true
not_production_ready: true
does_not_claim_regulatory_compliance: true
sentinel: muleguard.ml.artifacts.readme:v1:inert-boundary-policy
---

# MULEGUARD ML Artifacts Directory

> **Important:** This directory is an **inert placeholder**. It exists only to
> preserve repository layout and to document the MULEGUARD ML artifact boundary.
>
> It **must not** be used to store model binaries, training datasets,
> evaluation fixtures, caches, logs, exports, pickles, notebooks, credentials,
> configuration secrets, raw customer data, raw narratives, raw identifiers,
> subject-label pairs, ground-truth labels, scenario IDs, fraud-ring IDs,
> production artifacts, or runtime state.

MULEGUARD is a **synthetic-first investigative prototype**. ML artifacts in this
project are **process-local, bounded, non-durable, and operational only**. They
are not evidence, not adjudication, not production model assets, and not
regulatory records.

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Non-Goals](#2-non-goals)
3. [Repository Policy](#3-repository-policy)
4. [Prohibited Contents](#4-prohibited-contents)
5. [Allowed Contents](#5-allowed-contents)
6. [Runtime Artifact Model](#6-runtime-artifact-model)
7. [Module Integration Boundary](#7-module-integration-boundary)
8. [Privacy and Data Classification](#8-privacy-and-data-classification)
9. [Leakage Controls](#9-leakage-controls)
10. [Safety and Product Guardrails](#10-safety-and-product-guardrails)
11. [Artifact Metadata Contract](#11-artifact-metadata-contract)
12. [Future Durable Registry Contract](#12-future-durable-registry-contract)
13. [CI and Repository Guardrails](#13-ci-and-repository-guardrails)
14. [Threat Model Summary](#14-threat-model-summary)
15. [Operational Invariants](#15-operational-invariants)
16. [Troubleshooting](#16-troubleshooting)
17. [Versioning and Change Control](#17-versioning-and-change-control)
18. [Sentinel](#18-sentinel)

---

## 1. Purpose

This directory serves three narrow purposes:

1. **Preserve repository layout**

   The `app/ml/artifacts/` path documents where ML-related artifact concerns are
   conceptually isolated inside the MULEGUARD backend package.

2. **Enforce a hard artifact boundary**

   This directory is a policy surface. It declares that MULEGUARD does **not**
   persist ML artifacts in source control or in this repository path.

3. **Provide developer-facing safety documentation**

   Contributors, reviewers, CI systems, and security auditors can rely on this
   file as the canonical statement that this directory must remain inert.

This README is not an artifact store. It is a **boundary declaration**.

---

## 2. Non-Goals

This directory explicitly does **not**:

- store trained models;
- store model weights;
- store serialized estimators;
- store pickles;
- store joblib artifacts;
- store ONNX artifacts;
- store TorchScript artifacts;
- store TensorFlow SavedModels;
- store scikit-learn pipelines;
- store preprocessing transformers;
- store feature stores;
- store datasets;
- store synthetic datasets;
- store evaluation fixtures;
- store ground-truth files;
- store label files;
- store subject-label pairs;
- store raw identifiers;
- store raw complaint narratives;
- store free-text inputs;
- store PII;
- store secrets;
- store tokens;
- store passwords;
- store API keys;
- store private keys;
- store authorization headers;
- store cookies;
- store session identifiers;
- store database URLs;
- store connection strings;
- store filesystem paths to runtime artifacts;
- store environment files;
- store logs;
- store caches;
- store notebooks;
- store exports;
- store reports containing raw values;
- store production deployment bundles;
- store model registries;
- store experiment trackers;
- store durable audit trails;
- store regulatory evidence packages;
- store customer data of any kind.

If a future implementation requires durable artifact storage, it must be handled
through a separate, explicitly approved, access-controlled, non-repository
artifact registry. That registry must not be implemented by committing artifacts
into this directory.

---

## 3. Repository Policy

### 3.1 Mandatory rules

The following rules are mandatory for all contributors and automated tooling:

| Rule        | Requirement                                                                                                               |
| ----------- | ------------------------------------------------------------------------------------------------------------------------- |
| `R-ART-001` | No binary model artifacts may be committed here.                                                                          |
| `R-ART-002` | No datasets may be committed here.                                                                                        |
| `R-ART-003` | No labels or subject-label pairs may be committed here.                                                                   |
| `R-ART-004` | No raw narratives may be committed here.                                                                                  |
| `R-ART-005` | No raw identifiers may be committed here.                                                                                 |
| `R-ART-006` | No secrets, tokens, passwords, keys, or credentials may be committed here.                                                |
| `R-ART-007` | No filesystem paths to local model artifacts may be committed here.                                                       |
| `R-ART-008` | No production artifacts may be committed here.                                                                            |
| `R-ART-009` | No runtime state may be committed here.                                                                                   |
| `R-ART-010` | Only inert documentation and policy placeholders may exist here.                                                          |
| `R-ART-011` | ML artifact summaries must remain process-local unless a separate durable registry is explicitly introduced and governed. |
| `R-ART-012` | All artifact metadata must be privacy-preserving and leakage-resistant.                                                   |
| `R-ART-013` | All artifact outputs must include synthetic-first caveats.                                                                |
| `R-ART-014` | All artifact outputs must prohibit automatic adverse customer action.                                                     |
| `R-ART-015` | This directory must not be treated as a model registry.                                                                   |

### 3.2 Recommended directory state

The recommended state of this directory is:

```text
muleguard/backend/app/ml/artifacts/
├── .gitkeep
└── README.md
```

No other files should be present unless this policy is formally revised and a
separate governed artifact mechanism is introduced.

---

## 4. Prohibited Contents

The following classes of content are prohibited in this directory.

### 4.1 Model artifacts

Prohibited examples:

```text
model.pkl
model.joblib
model.onnx
model.pt
model.h5
saved_model/
pipeline.pkl
preprocessor.pkl
vectorizer.pkl
encoder.json
scaler.npy
```

Reason:

- model binaries are not source-controlled assets in MULEGUARD;
- they may encode sensitive patterns from training data;
- they may create false impressions of production readiness;
- they may bypass governed model registries;
- they may leak information through memorization or inversion.

### 4.2 Datasets and fixtures

Prohibited examples:

```text
train.csv
validation.csv
test.csv
labels.json
synthetic_records.json
ground_truth.csv
fraud_labels.parquet
scenario_ids.json
ring_ids.json
```

Reason:

- datasets may contain real or realistic sensitive data;
- labels may create leakage pathways;
- fixtures may be mistaken for production evidence;
- synthetic labels are evaluation-only and must not persist as repository assets.

### 4.3 Subject-label pairs

Prohibited examples:

```text
subject_hash,label
abc123,2
def456,3
```

or any JSON/CSV/Parquet/Log artifact containing:

```text
subject_ref_hash + label_code
account_id + is_fraud
customer_id + fraud_label
subject + ground_truth
```

Reason:

- subject-label pairs are highly sensitive;
- they can enable re-identification;
- they can leak target information into unintended surfaces;
- they violate the MULEGUARD privacy boundary.

### 4.4 Raw narratives and free text

Prohibited examples:

```text
customer complained that...
the user said...
narrative_raw
narrative_normalized
complaint_text
```

Reason:

- raw narratives are forbidden ML inputs in MULEGUARD;
- they may contain PII, secrets, allegations, or sensitive context;
- they must never be read, hashed, stored, logged, or returned by ML artifact
  surfaces.

### 4.5 Raw identifiers

Prohibited examples:

```text
account_id
customer_id
upi_id
phone_number
email_address
ip_address
device_id
ifsc
pan
aadhaar
card_number
```

Reason:

- raw identifiers are forbidden in public outputs;
- subject linkage must be pseudonymous and salted;
- raw identifiers increase re-identification risk.

### 4.6 Secrets and credentials

Prohibited examples:

```text
BACKEND_SECRET_KEY=...
DATABASE_URL=...
AWS_SECRET_ACCESS_KEY=...
PRIVATE_KEY=...
API_KEY=...
PASSWORD=...
TOKEN=...
COOKIE=...
SESSION=...
```

Reason:

- secrets must never be committed;
- this directory is not a configuration store;
- secret material may accidentally be exposed through repository history.

### 4.7 Filesystem paths and runtime pointers

Prohibited examples:

```text
/tmp/muleguard/model.pkl
/var/lib/muleguard/artifacts/model.bin
s3://muleguard-prod/models/latest
/home/user/muleguard/checkpoints
```

Reason:

- paths may leak environment structure;
- paths may point to non-reproducible runtime state;
- paths may encourage unsafe local artifact execution.

### 4.8 Logs, caches, and exports

Prohibited examples:

```text
ml_debug.log
feature_cache.bin
evaluation_export.json
explanation_dump.csv
training_trace.json
```

Reason:

- logs and exports may contain raw values;
- caches may persist sensitive intermediate state;
- exports may be mistaken for governed reports.

---

## 5. Allowed Contents

Only the following are allowed:

| Allowed item                  | Purpose                                |
| ----------------------------- | -------------------------------------- |
| `.gitkeep`                    | Preserve empty directory in Git.       |
| `README.md`                   | Document artifact boundary and policy. |
| Future inert policy documents | Clarify non-storage boundaries.        |

Nothing else is allowed under the current MULEGUARD prototype policy.

If a future change introduces governed artifact manifests, those manifests must:

- contain no raw values;
- contain no subject-label pairs;
- contain no secrets;
- contain no filesystem paths to private artifacts;
- contain no production deployment pointers;
- contain only safe metadata, fingerprints, summaries, and governance flags;
- be reviewed under a separate artifact governance policy.

---

## 6. Runtime Artifact Model

MULEGUARD ML artifacts are designed to be **process-local** and **bounded**.

### 6.1 Process-local meaning

“Process-local” means:

- artifacts live only in memory for the lifetime of the Python process;
- they are not written to disk by default;
- they are not committed to Git;
- they are not shared across workers unless an explicit governed registry is
  introduced;
- they disappear on restart;
- they are suitable for local prototypes, tests, fixtures, and developer
  tooling only.

### 6.2 Bounded meaning

“Bounded” means:

- record counts are capped;
- feature counts are capped;
- issue lists are capped;
- summary items are capped;
- contribution lists are capped;
- catalog entries are capped;
- audit events are capped;
- latency budgets are enforced where applicable;
- truncation is reported honestly.

### 6.3 Non-durable meaning

“Non-durable” means:

- no promise of persistence;
- no disaster recovery;
- no replication;
- no retention policy;
- no legal hold;
- no regulatory archive;
- no production model serving lineage.

### 6.4 Operational-only meaning

“Operational-only” means:

- artifacts support investigation prioritization;
- artifacts do not adjudicate guilt;
- artifacts do not justify automatic action;
- artifacts must not freeze, block, blacklist, close, restrict, or harm accounts
  or customers.

---

## 7. Module Integration Boundary

This directory is adjacent to, but separate from, the MULEGUARD ML orchestration
modules.

### 7.1 `app.ml.model_service`

The model service may maintain a process-local model catalog. That catalog is
not persisted here.

Allowed:

- in-memory model entries;
- safe metadata;
- fingerprints;
- governance summaries;
- lifecycle status metadata.

Not allowed:

- serialized model files in this directory;
- durable registry exports in this directory;
- production serving pointers.

### 7.2 `app.ml.train_model`

The training harness may register process-local training job results.

Allowed:

- safe job summaries;
- phase records;
- artifact summaries;
- metrics summaries;
- governance summaries.

Not allowed:

- training datasets;
- label files;
- model binaries;
- checkpoint files;
- local artifact paths.

### 7.3 `app.ml.evaluate`

The evaluation harness may produce evaluation reports.

Allowed:

- aggregate metrics;
- threshold curves;
- slice summaries;
- stability summaries;
- safe artifact metadata.

Not allowed:

- raw predictions with subject-label pairs;
- raw feature values;
- exported evaluation datasets;
- ground-truth files.

### 7.4 `app.ml.explainability`

The explainability harness may produce operational attributions.

Allowed:

- feature contribution summaries;
- global importance summaries;
- local explanation summaries;
- method metadata;
- stability/confidence metadata.

Not allowed:

- raw feature values;
- raw narratives;
- raw identifiers;
- explanation exports containing sensitive payloads.

### 7.5 `app.ml.validation`

The validation harness may produce validation reports.

Allowed:

- schema summaries;
- aggregate feature statistics;
- privacy posture summaries;
- leakage posture summaries;
- duplicate rates;
- drift diagnostics.

Not allowed:

- raw records;
- raw PII scan hits;
- raw target-copy payloads;
- raw validation datasets.

---

## 8. Privacy and Data Classification

MULEGUARD applies a strict privacy boundary to ML artifact surfaces.

### 8.1 Prohibited data classes

The following data classes must never appear in this directory:

| Class                   | Examples                                                    |
| ----------------------- | ----------------------------------------------------------- |
| Direct identifiers      | account ID, customer ID, phone number, email, IP, device ID |
| Financial identifiers   | card number, UPI ID, IFSC, bank account number              |
| Government identifiers  | PAN, Aadhaar, passport, driver license                      |
| Authentication material | password, PIN, OTP, token, cookie, session, private key     |
| Free-text narratives    | complaint text, user statement, chat transcript             |
| Subject-label pairs     | pseudonymous subject plus synthetic label                   |
| Ground-truth labels     | fraud label, is_fraud, truth label                          |
| Scenario metadata       | scenario ID, fraud ring ID                                  |
| Runtime secrets         | database URL, API key, secret key                           |
| Artifact pointers       | local model path, object storage key                        |

### 8.2 Allowed pseudonymization

Where subject linkage is required internally, MULEGUARD uses salted one-way
pseudonymous hashes.

Allowed conceptual form:

```text
subject_ref_hash = HMAC-SHA256(salt, namespace_domain || raw_subject_value)
```

Requirements:

- salt must be configured securely outside source control;
- raw subject values must not be stored;
- hashes must not be reversible;
- public summaries must not expose subject-label pairs;
- hashes must be namespace-scoped where practical.

### 8.3 Raw value exclusion

Public artifact summaries must exclude:

- raw feature values;
- raw labels;
- raw narratives;
- raw identifiers;
- raw secrets;
- raw payload hashes that could enable correlation attacks when combined with
  labels;
- raw model parameters unless explicitly governed and privacy-reviewed.

---

## 9. Leakages Controls

This directory is part of the MULEGUARD leakage-resistance boundary.

### 9.1 Labels are not features

Labels must never be used as features.

Prohibited feature-like fields include:

```text
label
label_code
target
y
ground_truth
ground_truth_label
truth_label
fraud_label
is_fraud
synthetic_label
scenario_id
ring_id
fraud_ring_id
```

### 9.2 Ground-truth style fields are rejected

ML artifact surfaces must reject or omit:

- ground-truth labels;
- fraud labels;
- scenario IDs;
- fraud-ring IDs;
- injected target proxies;
- leakage-prone identifiers.

### 9.3 Target-copy detection

Validation and explainability surfaces may detect features that appear to copy
the target. Such detections must be reported as aggregate leakage risk only.

Allowed:

```json
{
  "feature": "some_feature",
  "code_match_rate": 1.0,
  "binary_match_rate": 1.0,
  "raw_values_retained": false
}
```

Not allowed:

```json
{
  "feature": "some_feature",
  "example_values": [1, 0, 1],
  "labels": [1, 0, 1]
}
```

### 9.4 Narrative exclusion

Raw complaint narratives are forbidden inputs. Artifact surfaces must never:

- read narratives;
- hash narratives for linkage;
- store narrative snippets;
- log narrative tokens;
- return narrative-derived free text.

---

## 10. Safety and Product Guardrails

MULEGUARD is an investigative prototype, not an adjudication system.

### 10.1 Scores are not guilt probabilities

All scores must be interpreted as investigative prioritization signals only:

- model probability;
- anomaly score;
- fallback score;
- hybrid score;
- risk band;
- explanation contribution;
- validation warning;
- evaluation metric.

None of these are probabilities of guilt.

### 10.2 Contributions are not causal proof

Feature contributions and importance rankings are operational attributions only.

They may indicate:

- model sensitivity;
- permutation importance;
- local surrogate behavior;
- coefficient direction;
- anomaly deviation.

They do not prove:

- fraud;
- intent;
- wrongdoing;
- causality;
- criminal association.

### 10.3 No automatic adverse action

Artifact outputs must never directly trigger:

- account freeze;
- account closure;
- blacklisting;
- blocking;
- restriction;
- denial of service;
- law-enforcement referral;
- customer harm;
- automated punishment.

Human review is mandatory for any consequential action.

### 10.4 Synthetic-first default

Default operation is synthetic-only.

Real customer data must not be used for:

- training;
- evaluation;
- explanation;
- validation;
- inference;
- artifact generation;
- debugging;
- fixtures;
- examples.

---

## 11. Artifact Metadata Contract

Although this directory does not store artifacts, MULEGUARD modules may expose
safe artifact metadata in process-local responses.

### 11.1 Minimal safe metadata shape

A safe metadata object should resemble:

```json
{
  "artifact_kind": "model_summary",
  "artifact_id": "opaque-process-local-id",
  "fingerprint": "sha256-or-hmac-derived-safe-fingerprint",
  "status": "CANDIDATE",
  "synthetic_only": true,
  "raw_values_retained": false,
  "subject_label_pairs_retained": false,
  "narratives_retained": false,
  "identifiers_retained": false,
  "secrets_retained": false",
  "model_artifact_paths_retained": false,
  "caveats": [
    "Investigative prioritization only.",
    "Not proof of wrongdoing.",
    "No automatic adverse customer action."
  ],
  "safety_flags": {
    "synthetic_only_by_default": true,
    "no_labels_as_features": true,
    "no_raw_values_in_public_summaries": true,
    "not_production_ready": true
  }
}
```

### 11.2 Required fields

Safe artifact metadata should include:

| Field                           | Purpose                                    |
| ------------------------------- | ------------------------------------------ |
| `artifact_kind`                 | Operational classification.                |
| `artifact_id`                   | Process-local identifier, not a file path. |
| `fingerprint`                   | Deterministic safe identity.               |
| `status`                        | Lifecycle or validation status.            |
| `synthetic_only`                | Privacy boundary flag.                     |
| `raw_values_retained`           | Must be `false`.                           |
| `subject_label_pairs_retained`  | Must be `false`.                           |
| `narratives_retained`           | Must be `false`.                           |
| `identifiers_retained`          | Must be `false`.                           |
| `secrets_retained`              | Must be `false`.                           |
| `model_artifact_paths_retained` | Must be `false`.                           |
| `caveats`                       | Product-safety language.                   |
| `safety_flags`                  | Machine-readable guardrails.               |

### 11.3 Forbidden fields

Safe artifact metadata must not include:

```text
raw_features
raw_values
raw_payload
raw_narrative
narrative_raw
ground_truth
fraud_label
is_fraud
scenario_id
ring_id
subject_label_pairs
account_id
customer_id
phone_number
email_address
ip_address
upi_id
pan
ifsc
card_number
password
token
secret
api_key
private_key
database_url
model_path
artifact_path
checkpoint_path
```

---

## 12. Future Durable Registry Contract

If MULEGUARD later introduces a durable artifact registry, it must be designed
outside this directory and must satisfy the following contract.

### 12.1 Registry placement

A durable registry must not live in:

```text
muleguard/backend/app/ml/artifacts/
```

It should instead be implemented through a governed service such as:

- enterprise model registry;
- access-controlled object store;
- MLflow-compatible registry with authentication and audit;
- internal artifact service;
- separately documented infrastructure component.

### 12.2 Required governance controls

A future durable registry must enforce:

| Control                | Requirement                                                  |
| ---------------------- | ------------------------------------------------------------ |
| Authentication         | Strong identity verification.                                |
| Authorization          | Role-based access control.                                   |
| Auditability           | Immutable access and mutation logs.                          |
| Lineage                | Training run, dataset version, code version, config version. |
| Privacy review         | No raw PII or subject-label pairs in public metadata.        |
| Leakage review         | No labels-as-features pathway.                               |
| Retention policy       | Explicit retention and deletion rules.                       |
| Access revocation      | Ability to revoke access quickly.                            |
| Environment separation | Dev/staging/prod isolation.                                  |
| Approval workflow      | Human approval for promotion.                                |
| Rollback capability    | Safe retirement and rollback.                                |
| Monitoring             | Drift, performance, and safety monitoring.                   |
| Incident response      | Artifact quarantine and audit trail.                         |
| Regulatory review      | Separate compliance assessment.                              |

### 12.3 Still not allowed in durable registry metadata

Even in a future durable registry, metadata must not expose:

- raw customer data;
- raw narratives;
- raw identifiers;
- subject-label pairs;
- secrets;
- private keys;
- database URLs;
- unauthorized production endpoints.

---

## 13. CI and Repository Guardrails

Automated checks should treat this directory as a protected policy surface.

### 13.1 Recommended CI assertions

CI should fail if any file other than allowed inert files is added.

Conceptual check:

```text
Allowed:
  .gitkeep
  README.md

Forbidden:
  any other file
```

### 13.2 Content scanning

CI should scan this directory for prohibited patterns.

Examples of patterns to reject:

```text
BEGIN PRIVATE KEY
BEGIN RSA PRIVATE KEY
-----BEGIN OPENSSH PRIVATE KEY-----
AWS_SECRET_ACCESS_KEY
DATABASE_URL
POSTGRES://
MYSQL://
MONGODB://
REDIS://
AMQP://
password=
passwd=
secret=
token=
api_key=
apikey=
authorization:
bearer
cookie:
session=
csrf
xsrf
pickle
joblib
\.pkl$
\.joblib$
\.onnx$
\.pt$
\.pth$
\.h5$
\.parquet$
\.csv$
\.tsv$
\.xlsx$
ground_truth
fraud_label
is_fraud
scenario_id
ring_id
subject_label
narrative_raw
account_id
customer_id
upi_id
phone_number
email_address
ip_address
ifsc
pan
aadhaar
card_number
```

### 13.3 Binary file rejection

CI should reject binary files in this directory.

Examples:

```text
*.pkl
*.joblib
*.bin
*.pt
*.pth
*.onnx
*.h5
*.parquet
*.zip
*.tar
*.gz
*.bz2
*.xz
*.7z
```

### 13.4 Large file rejection

CI should reject large files in this directory.

Recommended limit:

```text
max_file_bytes = 0 for non-allowed files
max_file_bytes = modest documentation limit for README.md
```

### 13.5 Path traversal rejection

CI should reject filenames containing:

```text
../
~/
绝对路径
C:\
/tmp/
/var/
/home/
```

### 13.6 Secret entropy rejection

CI should reject high-entropy strings that resemble credentials, even if not
matched by keyword rules.

---

## 14. Threat Model Summary

This directory is protected against several classes of risk.

### 14.1 Accidental sensitive data commit

Threat:

- developer commits a CSV, pickle, log, notebook, or export containing sensitive
  data.

Control:

- inert directory policy;
- CI file-type restrictions;
- content scanning;
- review checklist.

### 14.2 Model memorization leakage

Threat:

- committed model artifact memorizes training data and exposes it through
  inference or inspection.

Control:

- no model binaries committed;
- process-local artifacts only;
- privacy-preserving summaries only.

### 14.3 Label leakage

Threat:

- labels or subject-label pairs enter feature pipelines.

Control:

- forbidden label-like feature fields;
- target-copy detection;
- validation leakage summary;
- no label files in repository.

### 14.4 False production readiness

Threat:

- committed artifacts imply production-grade model management.

Control:

- explicit non-production-ready notices;
- no deployment bundles;
- no registry semantics in this directory.

### 14.5 Unauthorized adverse action

Threat:

- teams treat scores or artifacts as automated enforcement triggers.

Control:

- product-safety caveats;
- human-review requirement;
- no automatic adverse action language.

### 14.6 Secret exposure

Threat:

- credentials committed accidentally.

Control:

- secret scanning;
- prohibited content list;
- inert directory policy.

---

## 15. Operational Invariants

The following invariants are intended to remain true for this directory.

| Invariant     | Statement                                                         |
| ------------- | ----------------------------------------------------------------- |
| `INV-ART-001` | This directory contains no model binaries.                        |
| `INV-ART-002` | This directory contains no datasets.                              |
| `INV-ART-003` | This directory contains no labels.                                |
| `INV-ART-004` | This directory contains no subject-label pairs.                   |
| `INV-ART-005` | This directory contains no raw narratives.                        |
| `INV-ART-006` | This directory contains no raw identifiers.                       |
| `INV-ART-007` | This directory contains no secrets.                               |
| `INV-ART-008` | This directory contains no production artifacts.                  |
| `INV-ART-009` | This directory contains no runtime state.                         |
| `INV-ART-010` | This directory contains only inert documentation.                 |
| `INV-ART-011` | ML artifacts are process-local unless a governed registry exists. |
| `INV-ART-012` | Artifact summaries exclude raw values.                            |
| `INV-ART-013` | Artifact metadata includes synthetic-first caveats.               |
| `INV-ART-014` | Artifact outputs prohibit automatic adverse action.               |
| `INV-ART-015` | This directory is not a model registry.                           |
| `INV-ART-016` | This directory is not an experiment tracker.                      |
| `INV-ART-017` | This directory is not a data lake.                                |
| `INV-ART-018` | This directory is not a feature store.                            |
| `INV-ART-019` | This directory is not a log sink.                                 |
| `INV-ART-020` | This directory is not a cache directory.                          |

---

## 16. Troubleshooting

### 16.1 “I need to save a trained model.”

Do not save it here.

For local prototyping:

- keep the model in process memory;
- use the process-local model catalog;
- export only safe metadata if needed;
- do not commit binaries.

For durable needs:

- introduce a separate governed artifact registry;
- update architecture docs;
- add security review;
- add retention and access controls.

### 16.2 “I need a synthetic dataset fixture.”

Do not place it here.

Preferred approaches:

- generate fixtures programmatically;
- store tiny non-sensitive schema examples in tests;
- use factory functions;
- use deterministic seeds;
- avoid realistic PII-like values.

### 16.3 “I need an evaluation report.”

Do not export raw reports here.

Use process-local evaluation results and safe summaries. If a durable report is
required, place it in a governed reporting system with access control and
privacy review.

### 16.4 “I need to debug a model.”

Use bounded logs that exclude raw values. Do not write debug artifacts into this
directory.

Allowed debug metadata:

- feature names;
- dtypes;
- counts;
- missing rates;
- fingerprints;
- issue codes;
- safe summaries.

Not allowed:

- raw rows;
- raw labels;
- raw narratives;
- raw identifiers;
- raw secrets.

### 16.5 “CI blocked my file.”

That is expected. This directory is intentionally restrictive. Move the asset to
an appropriate governed location or remove it.

---

## 17. Versioning and Change Control

This policy document is versioned.

Current sentinel:

```text
muleguard.ml.artifacts.readme:v1:inert-boundary-policy
```

Any change to this file should include:

1. clear rationale;
2. security review;
3. privacy review;
4. ML governance review;
5. product-safety review;
6. updated sentinel version if policy semantics change.

Examples of changes requiring review:

- allowing new file types;
- allowing manifests;
- allowing durable registry pointers;
- allowing exported summaries;
- allowing test fixtures;
- changing privacy posture;
- changing leakage posture;
- changing production-readiness claims.

---

## 18. Sentinel

End of policy document.

```text
sentinel:muleguard.ml.artifacts.readme:v1:inert-boundary-policy
```