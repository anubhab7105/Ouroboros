"""
MULEGUARD backend core constants.

This module is the canonical source for stable, dependency-light literals used
across the MULEGUARD backend.

Primary responsibilities:

- define safe project, API, product-safety, and synthetic-data constants;
- define stable HTTP header, query-parameter, path-parameter, media-type, and
  response-field names;
- define bounded operational limits for pagination, ingestion, graph, reports,
  exports, search, JSON depth, and request size;
- define conservative regular expressions for identifiers, cursors, request IDs,
  idempotency keys, filenames, hashes, and currencies;
- define sensitive-key and forbidden-response-key registries used by sanitizers;
- define audit action, audit resource, and audit outcome literals;
- define grouped caveat tuples for dashboard, graph, ingestion, reports, model
  metrics, and auth surfaces;
- provide a safe metadata helper for diagnostics and documentation checks.

Relationship to other modules:

- `app.core.config` owns runtime environment settings.
- `app.core.enums` owns validated enum state machines and transition rules.
- `app.core.roles` owns role identity and hierarchy.
- `app.core.permissions` owns permission identity and metadata.
- `app.auth.rbac` owns deny-by-default authorization decisions.
- `app.exceptions` owns the canonical error taxonomy.
- This module owns stable literals only. It must not execute runtime policy,
  load environment variables, access databases, or perform I/O.

Security and product-safety rules enforced here:

- Constants must not contain secrets, tokens, passwords, database URLs, model
  artifact paths, raw complaint narratives, synthetic ground-truth labels,
  scenario IDs, fraud-ring IDs, or real customer data.
- MULEGUARD is synthetic-first by default.
- Alerts, risk scores, graph relationships, candidate money trails, entity
  links, complaint correlations, and case dispositions are investigative leads
  or human workflow artefacts only.
- They are not proof of wrongdoing and must not trigger automatic adverse
  customer action.
- Risk scores are investigative priority scores, not probabilities of guilt.
- Heuristic fallback scores are not calibrated model probabilities.
- Only completed transactions represent settled fund movement.
- Undefined capabilities must be reported honestly as unavailable.
- This prototype is not production-ready and does not claim regulatory
  compliance or real-world fraud-detection accuracy.

Explicit non-goals:

- This module does not authenticate or authorize users.
- This module does not persist state.
- This module does not load configuration.
- This module does not execute workflows.
- This module does not replace enums, settings, or exception classes.
- This module does not claim production readiness.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Final, Mapping, Pattern

# -----------------------------------------------------------------------------
# Interpreter guard
# -----------------------------------------------------------------------------

if sys.version_info < (3, 11):
    raise RuntimeError(
        "MULEGUARD backend requires Python 3.11 or newer. "
        f"Current Python version: {sys.version.split()[0]}"
    )


# -----------------------------------------------------------------------------
# Package and contract metadata
# -----------------------------------------------------------------------------

CORE_CONSTANTS_PACKAGE_NAME: Final[str] = "muleguard.backend.core.constants"
CORE_LAYER: Final[str] = "core"
CONSTANTS_CONTRACT_VERSION: Final[str] = "v1"


# -----------------------------------------------------------------------------
# Project and API metadata
# -----------------------------------------------------------------------------

PROJECT_NAME: Final[str] = "MULEGUARD"
PRODUCT_NAME: Final[str] = "MULEGUARD"
PRODUCT_SUBTITLE: Final[str] = (
    "Synthetic money-laundering and fraud investigation prototype"
)
PRODUCT_DESCRIPTION: Final[str] = (
    "MULEGUARD is a synthetic-first investigative prototype for bounded "
    "analysis of synthetic accounts, transactions, complaints, pseudonymous "
    "entities, alerts, cases, graph relationships, candidate money trails, and "
    "model-assessment metadata. It produces investigative leads only."
)

API_TITLE: Final[str] = "MULEGUARD API"
API_VERSION: Final[str] = "v1"
API_PREFIX: Final[str] = "/api/v1"
OPENAPI_PATH: Final[str] = f"{API_PREFIX}/openapi.json"
HEALTH_PATH: Final[str] = f"{API_PREFIX}/health"
READY_PATH: Final[str] = f"{API_PREFIX}/ready"
METADATA_PATH: Final[str] = f"{API_PREFIX}/metadata"
DOCS_PATH: Final[str] = "/docs"
REDOC_PATH: Final[str] = "/redoc"


# -----------------------------------------------------------------------------
# Synthetic-data and product-safety literals
# -----------------------------------------------------------------------------

DATA_CLASSIFICATION: Final[str] = "synthetic"
DATASET_MODE_SYNTHETIC: Final[str] = "synthetic"
DATASET_MODE_DEMO: Final[str] = "demo"
DATASET_MODE_TEST: Final[str] = "test"
DATASET_MODE_EMPTY: Final[str] = "empty"

SYNTHETIC_BANNER_TEXT: Final[str] = "SYNTHETIC DEMO DATA"

SYNTHETIC_ONLY_TEXT: Final[str] = (
    "Synthetic prototype data only. Not real customer or bank data."
)
EVIDENCE_BACKED_TEXT: Final[str] = (
    "Outputs are generated only from persisted records."
)
INVESTIGATIVE_LEAD_TEXT: Final[str] = (
    "Alerts, risk scores, graph relationships, candidate money trails, entity "
    "links, complaint correlations, and case dispositions are investigative "
    "leads or human workflow artefacts only."
)
NOT_PROOF_TEXT: Final[str] = "They are not proof of wrongdoing."
NO_ADVERSE_ACTION_TEXT: Final[str] = (
    "They must not trigger automatic adverse customer action."
)
SCORE_TEXT: Final[str] = (
    "Risk scores are investigative priority scores, not probabilities of guilt."
)
FALLBACK_SCORE_TEXT: Final[str] = (
    "Heuristic fallback scores are not calibrated model probabilities."
)
GRAPH_TEXT: Final[str] = (
    "Graph relationships and shared entities are association signals only."
)
MONEY_TRAIL_TEXT: Final[str] = (
    "Candidate money trails are heuristic flow views only."
)
COMPLAINT_CORRELATION_TEXT: Final[str] = (
    "Complaint correlations distinguish exact matches from inferred associations."
)
CASE_DISPOSITION_TEXT: Final[str] = (
    "Case dispositions are investigator-entered workflow assessments, not "
    "automatic conclusions."
)
TRANSACTION_STATUS_TEXT: Final[str] = (
    "Only completed transfers represent settled fund movement."
)
RAW_NARRATIVE_TEXT: Final[str] = (
    "Raw complaint narratives are intentionally excluded from operational and "
    "investigative summaries."
)
GROUND_TRUTH_TEXT: Final[str] = (
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are not "
    "exposed by this API."
)
SECRET_LEAKAGE_TEXT: Final[str] = (
    "Secrets, tokens, passwords, database URLs, model artifact paths, and real "
    "customer data are never exposed."
)
BOUNDED_QUERY_TEXT: Final[str] = (
    "Queries and exports are bounded by configured limits."
)
HONEST_UNAVAILABLE_TEXT: Final[str] = (
    "Undefined capabilities are reported honestly as unavailable."
)
NOT_PRODUCTION_READY_TEXT: Final[str] = (
    "This prototype is not production-ready and does not claim regulatory "
    "compliance or real-world fraud-detection accuracy."
)
NO_AUTOMATIC_ENFORCEMENT_TEXT: Final[str] = (
    "This API does not freeze, block, blacklist, close, restrict, or otherwise "
    "take adverse action against accounts or customers."
)

PRODUCT_SAFETY_NOTICES: Final[tuple[str, ...]] = (
    SYNTHETIC_ONLY_TEXT,
    EVIDENCE_BACKED_TEXT,
    INVESTIGATIVE_LEAD_TEXT,
    NOT_PROOF_TEXT,
    NO_ADVERSE_ACTION_TEXT,
    SCORE_TEXT,
    FALLBACK_SCORE_TEXT,
    GRAPH_TEXT,
    MONEY_TRAIL_TEXT,
    COMPLAINT_CORRELATION_TEXT,
    CASE_DISPOSITION_TEXT,
    TRANSACTION_STATUS_TEXT,
    RAW_NARRATIVE_TEXT,
    GROUND_TRUTH_TEXT,
    SECRET_LEAKAGE_TEXT,
    BOUNDED_QUERY_TEXT,
    HONEST_UNAVAILABLE_TEXT,
    NOT_PRODUCTION_READY_TEXT,
    NO_AUTOMATIC_ENFORCEMENT_TEXT,
)


# -----------------------------------------------------------------------------
# Grouped caveat tuples
# -----------------------------------------------------------------------------

BASE_CAVEATS: Final[tuple[str, ...]] = (
    SYNTHETIC_ONLY_TEXT,
    EVIDENCE_BACKED_TEXT,
    INVESTIGATIVE_LEAD_TEXT,
    NOT_PROOF_TEXT,
    NO_ADVERSE_ACTION_TEXT,
    SCORE_TEXT,
    FALLBACK_SCORE_TEXT,
    RAW_NARRATIVE_TEXT,
    GROUND_TRUTH_TEXT,
    SECRET_LEAKAGE_TEXT,
    BOUNDED_QUERY_TEXT,
    HONEST_UNAVAILABLE_TEXT,
    NOT_PRODUCTION_READY_TEXT,
    NO_AUTOMATIC_ENFORCEMENT_TEXT,
)

READ_ONLY_CAVEATS: Final[tuple[str, ...]] = (
    *BASE_CAVEATS,
    "This endpoint is read-only.",
    "This endpoint does not create, update, delete, freeze, block, blacklist, "
    "close, restrict, or otherwise take adverse action against accounts or "
    "customers.",
)

DASHBOARD_CAVEATS: Final[tuple[str, ...]] = (
    *BASE_CAVEATS,
    "Dashboard aggregates are operational and investigative signals only.",
    "Work queues are bounded triage views, not exhaustive case management.",
    "Queue ordering is heuristic and must not be interpreted as legal or "
    "evidentiary priority.",
    "Metrics rates are simple operational rates, not calibrated statistical "
    "measures.",
    "Backlog counts are current-state counts and are not scoped to the "
    "activity window unless stated.",
)

GRAPH_CAVEATS: Final[tuple[str, ...]] = (
    *BASE_CAVEATS,
    GRAPH_TEXT,
    MONEY_TRAIL_TEXT,
    "Shared devices, phones, UPI IDs, emails, addresses, IPs, or other entities "
    "are associations only.",
    "Returned paths are candidate directed or bidirectional transaction walks "
    "only.",
    "Path ordering is heuristic and must not be interpreted as legal, "
    "evidentiary, or causal priority.",
    "Mixed-currency path totals are reported per currency and are not converted.",
)

INGESTION_CAVEATS: Final[tuple[str, ...]] = (
    *BASE_CAVEATS,
    "Synthetic prototype ingestion only. Do not send real customer data.",
    "Ingestion responses do not return raw complaint narratives.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs must not be "
    "ingested through this API.",
    "Ingested records are investigative inputs only and do not trigger "
    "automatic adverse customer action.",
    "Batch processing is bounded by configured batch size and error-reporting "
    "limits.",
    "Dry-run mode validates records without persisting them.",
    "Duplicate handling is deterministic and configurable.",
)

REPORT_CAVEATS: Final[tuple[str, ...]] = (
    *BASE_CAVEATS,
    "Report content is generated exclusively from persisted records.",
    "No evidence text, metric, quotation, or conclusion is fabricated.",
    "Raw complaint narratives are intentionally excluded from reports.",
    "Ground-truth labels, injected scenario IDs, and fraud-ring IDs are excluded.",
    "Report generation is bounded by item, section, page, and time limits.",
    "This report is not legal evidence and does not claim forensic integrity.",
)

MODEL_METRICS_CAVEATS: Final[tuple[str, ...]] = (
    *BASE_CAVEATS,
    "Model metrics are real computed outputs from synthetic evaluation data.",
    "Undefined metrics are reported honestly as unavailable, not invented.",
    "Calibration metrics are unavailable unless calibration has been "
    "implemented and evaluated.",
    "Model metadata must not be interpreted as production readiness or "
    "regulatory compliance.",
    "Model artifact file paths and raw binary artifacts are never exposed.",
    "This API does not train, retrain, promote, retire, upload, replace, or "
    "execute models.",
)

AUTH_CAVEATS: Final[tuple[str, ...]] = (
    *BASE_CAVEATS,
    "Authentication here protects local demo and test workflows only.",
    "The backend is the security boundary. Frontend hiding is not sufficient.",
    "Passwords are stored only as salted hashes.",
    "Failed authentication responses are generic by default to reduce user "
    "enumeration.",
    "Inactive users must not authenticate.",
    "Locked users must not authenticate until the lock expires or is cleared.",
    "Authentication never triggers automatic adverse customer action.",
)

EXPORT_CAVEATS: Final[tuple[str, ...]] = (
    *BASE_CAVEATS,
    "Exports are bounded investigative artefacts only.",
    "Raw complaint narratives are excluded unless an explicitly permitted "
    "narrative endpoint is used.",
    "Export ordering is heuristic and must not be interpreted as legal or "
    "evidentiary priority.",
)


# -----------------------------------------------------------------------------
# Boolean and null parsing literals
# -----------------------------------------------------------------------------

TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "y", "on", "t"}
)
FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "n", "off", "f", ""}
)
NULL_VALUES: Final[frozenset[str]] = frozenset(
    {"", "null", "none", "nil", "nan", "undefined"}
)


# -----------------------------------------------------------------------------
# Environment classification literals
# -----------------------------------------------------------------------------

ENV_LOCAL: Final[str] = "local"
ENV_TEST: Final[str] = "test"
ENV_CI: Final[str] = "ci"
ENV_STAGING: Final[str] = "staging"
ENV_PRODUCTION: Final[str] = "production"

PRODUCTION_LIKE_ENVS: Final[frozenset[str]] = frozenset(
    {"production", "staging", "prod", "stage"}
)
NON_PRODUCTION_ENVS: Final[frozenset[str]] = frozenset(
    {"local", "test", "ci", "development", "dev"}
)

PLACEHOLDER_MARKERS: Final[frozenset[str]] = frozenset(
    {
        "change_me",
        "changeme",
        "placeholder",
        "replace_me",
        "replace-me",
        "your_",
        "example_",
        "todo",
        "fixme",
    }
)


# -----------------------------------------------------------------------------
# HTTP header literals
# -----------------------------------------------------------------------------

HEADER_REQUEST_ID: Final[str] = "X-Request-ID"
HEADER_CORRELATION_ID: Final[str] = "X-Correlation-ID"
HEADER_IDEMPOTENCY_KEY: Final[str] = "Idempotency-Key"
HEADER_RESPONSE_TIME: Final[str] = "X-Response-Time"
HEADER_CONTENT_TYPE: Final[str] = "Content-Type"
HEADER_CONTENT_LENGTH: Final[str] = "Content-Length"
HEADER_CONTENT_DISPOSITION: Final[str] = "Content-Disposition"
HEADER_ACCEPT: Final[str] = "Accept"
HEADER_AUTHORIZATION: Final[str] = "Authorization"
HEADER_WWW_AUTHENTICATE: Final[str] = "WWW-Authenticate"
HEADER_RETRY_AFTER: Final[str] = "Retry-After"
HEADER_X_CONTENT_TYPE_OPTIONS: Final[str] = "X-Content-Type-Options"
HEADER_X_FRAME_OPTIONS: Final[str] = "X-Frame-Options"
HEADER_REFERRER_POLICY: Final[str] = "Referrer-Policy"
HEADER_CONTENT_SECURITY_POLICY: Final[str] = "Content-Security-Policy"
HEADER_STRICT_TRANSPORT_SECURITY: Final[str] = "Strict-Transport-Security"

HEADER_RATELIMIT_LIMIT: Final[str] = "RateLimit-Limit"
HEADER_RATELIMIT_REMAINING: Final[str] = "RateLimit-Remaining"
HEADER_RATELIMIT_RESET: Final[str] = "RateLimit-Reset"
HEADER_RATELIMIT_POLICY: Final[str] = "RateLimit-Policy"

HEADER_REPORT_CASE_ID: Final[str] = "X-Report-Case-Id"
HEADER_REPORT_GENERATED_AT: Final[str] = "X-Report-Generated-At"
HEADER_REPORT_SHA256: Final[str] = "X-Report-SHA256"
HEADER_REPORT_ESTIMATED_PAGES: Final[str] = "X-Report-Estimated-Pages"
HEADER_REPORT_EVIDENCE_TOTAL: Final[str] = "X-Report-Evidence-Total"

SENSITIVE_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "apikey",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)

DEFAULT_SECURE_HEADERS: Final[Mapping[str, str]] = MappingProxyType(
    {
        HEADER_X_CONTENT_TYPE_OPTIONS: "nosniff",
        HEADER_X_FRAME_OPTIONS: "DENY",
        HEADER_REFERRER_POLICY: "no-referrer",
        HEADER_CONTENT_SECURITY_POLICY: "default-src 'none'",
    }
)


# -----------------------------------------------------------------------------
# Query and path parameter literals
# -----------------------------------------------------------------------------

QUERY_PAGE: Final[str] = "page"
QUERY_PAGE_SIZE: Final[str] = "page_size"
QUERY_SORT_BY: Final[str] = "sort_by"
QUERY_SORT_ORDER: Final[str] = "sort_order"
QUERY_CURSOR: Final[str] = "cursor"
QUERY_LIMIT: Final[str] = "limit"
QUERY_TOP_LIMIT: Final[str] = "top_limit"
QUERY_OFFSET: Final[str] = "offset"

QUERY_DATE_FROM: Final[str] = "date_from"
QUERY_DATE_TO: Final[str] = "date_to"
QUERY_AS_OF: Final[str] = "as_of"

QUERY_AMOUNT_MIN: Final[str] = "amount_min"
QUERY_AMOUNT_MAX: Final[str] = "amount_max"
QUERY_CURRENCY: Final[str] = "currency"

QUERY_DIRECTION: Final[str] = "direction"
QUERY_DEPTH: Final[str] = "depth"
QUERY_MAX_DEPTH: Final[str] = "max_depth"
QUERY_MAX_HOPS: Final[str] = "max_hops"
QUERY_MAX_NODES: Final[str] = "max_nodes"
QUERY_MAX_EDGES: Final[str] = "max_edges"
QUERY_MAX_PATHS: Final[str] = "max_paths"
QUERY_MAX_TRAILS: Final[str] = "max_trails"
QUERY_MAX_GROUPS: Final[str] = "max_groups"
QUERY_MAX_ACCOUNTS_PER_ENTITY: Final[str] = "max_accounts_per_entity"

QUERY_INCLUDE_TRANSACTIONS: Final[str] = "include_transactions"
QUERY_INCLUDE_ENTITIES: Final[str] = "include_entities"
QUERY_INCLUDE_COMPLAINTS: Final[str] = "include_complaints"
QUERY_INCLUDE_ALERTS: Final[str] = "include_alerts"
QUERY_INCLUDE_ASSESSMENTS: Final[str] = "include_assessments"
QUERY_INCLUDE_INACTIVE: Final[str] = "include_inactive"

QUERY_ENTITY_TYPE: Final[str] = "entity_type"
QUERY_VERIFICATION_STATE: Final[str] = "verification_state"
QUERY_MATCH_METHOD: Final[str] = "match_method"
QUERY_REVIEW_STATE: Final[str] = "review_state"
QUERY_MIN_ACCOUNTS: Final[str] = "min_accounts"

QUERY_ACCOUNT_ID: Final[str] = "account_id"
QUERY_ALERT_ID: Final[str] = "alert_id"
QUERY_CASE_ID: Final[str] = "case_id"
QUERY_COMPLAINT_ID: Final[str] = "complaint_id"
QUERY_TRANSACTION_ID: Final[str] = "transaction_id"
QUERY_ENTITY_ID: Final[str] = "entity_id"
QUERY_ASSESSMENT_ID: Final[str] = "assessment_id"
QUERY_VERSION_ID: Final[str] = "version_id"
QUERY_EVALUATION_ID: Final[str] = "evaluation_id"

PATH_ACCOUNT_ID: Final[str] = "account_id"
PATH_ALERT_ID: Final[str] = "alert_id"
PATH_CASE_ID: Final[str] = "case_id"
PATH_COMPLAINT_ID: Final[str] = "complaint_id"
PATH_TRANSACTION_ID: Final[str] = "transaction_id"
PATH_ENTITY_ID: Final[str] = "entity_id"
PATH_ASSESSMENT_ID: Final[str] = "assessment_id"
PATH_VERSION_ID: Final[str] = "version_id"
PATH_EVALUATION_ID: Final[str] = "evaluation_id"
PATH_USER_ID: Final[str] = "user_id"


# -----------------------------------------------------------------------------
# Media types, extensions, and filename literals
# -----------------------------------------------------------------------------

MEDIA_TYPE_JSON: Final[str] = "application/json"
MEDIA_TYPE_JSON_UTF8: Final[str] = "application/json; charset=utf-8"
MEDIA_TYPE_CSV: Final[str] = "text/csv"
MEDIA_TYPE_CSV_UTF8: Final[str] = "text/csv; charset=utf-8"
MEDIA_TYPE_NDJSON: Final[str] = "application/x-ndjson"
MEDIA_TYPE_PDF: Final[str] = "application/pdf"
MEDIA_TYPE_OCTET_STREAM: Final[str] = "application/octet-stream"
MEDIA_TYPE_URLENCODED: Final[str] = "application/x-www-form-urlencoded"
MEDIA_TYPE_MULTIPART: Final[str] = "multipart/form-data"
MEDIA_TYPE_TEXT: Final[str] = "text/plain"

EXT_JSON: Final[str] = ".json"
EXT_CSV: Final[str] = ".csv"
EXT_NDJSON: Final[str] = ".ndjson"
EXT_PDF: Final[str] = ".pdf"
EXT_TXT: Final[str] = ".txt"

FILENAME_ATTACHMENT: Final[str] = "attachment"
FILENAME_INLINE: Final[str] = "inline"


# -----------------------------------------------------------------------------
# Time, date, and timezone literals
# -----------------------------------------------------------------------------

TIMEZONE_UTC: Final[str] = "UTC"
DATE_FORMAT: Final[str] = "%Y-%m-%d"
DATETIME_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S%z"
COMPACT_DATETIME_FORMAT: Final[str] = "%Y%m%dT%H%M%SZ"
LOG_TIMESTAMP_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S%z"

EPOCH_UTC: Final[datetime] = datetime(1970, 1, 1, tzinfo=timezone.utc)


# -----------------------------------------------------------------------------
# Monetary and numeric literals
# -----------------------------------------------------------------------------

DEFAULT_CURRENCY: Final[str] = "INR"
CURRENCY_PATTERN: Final[str] = r"^[A-Z]{3}$"

MONEY_DECIMAL_PLACES: Final[int] = 2
MAX_AMOUNT_INTEGER_DIGITS: Final[int] = 30
MAX_AMOUNT_DECIMAL_DIGITS: Final[int] = 2

ZERO_DECIMAL: Final[str] = "0"
ONE_DECIMAL: Final[str] = "1"


# -----------------------------------------------------------------------------
# Bounded operational limits
# -----------------------------------------------------------------------------

MAX_STRING_LENGTH: Final[int] = 512
MAX_TEXT_LENGTH: Final[int] = 4_000
MAX_CELL_LENGTH: Final[int] = 1_000
MAX_NARRATIVE_LENGTH: Final[int] = 20_000
MAX_LIST_LENGTH: Final[int] = 100
MAX_MAPPING_KEYS: Final[int] = 100
MAX_JSON_DEPTH: Final[int] = 6

MAX_REQUEST_BODY_MB: Final[int] = 10
MAX_REQUEST_BODY_BYTES: Final[int] = MAX_REQUEST_BODY_MB * 1024 * 1024

DEFAULT_PAGE_SIZE: Final[int] = 50
MAX_PAGE_SIZE: Final[int] = 200
HARD_MAX_PAGE_SIZE: Final[int] = 500
MAX_OFFSET: Final[int] = 1_000_000
MAX_SORT_FIELDS: Final[int] = 8

DEFAULT_TOP_LIMIT: Final[int] = 10
HARD_TOP_LIMIT: Final[int] = 50

DEFAULT_WINDOW_DAYS: Final[int] = 30
MAX_WINDOW_DAYS: Final[int] = 3_650
DEFAULT_TREND_BUCKETS: Final[int] = 90
HARD_TREND_BUCKETS: Final[int] = 366

DEFAULT_MAX_BATCH_SIZE: Final[int] = 1_000
HARD_MAX_BATCH_SIZE: Final[int] = 10_000
DEFAULT_MAX_ERRORS_RETURNED: Final[int] = 100
HARD_MAX_ERRORS_RETURNED: Final[int] = 500
FUTURE_TOLERANCE_MINUTES: Final[int] = 5

GRAPH_HARD_MAX_NODES: Final[int] = 1_000
GRAPH_HARD_MAX_EDGES: Final[int] = 2_000
GRAPH_HARD_MAX_DEPTH: Final[int] = 5
GRAPH_HARD_MAX_PATHS: Final[int] = 100
GRAPH_HARD_MAX_TRAILS: Final[int] = 100
GRAPH_HARD_MAX_SHARED_GROUPS: Final[int] = 100
GRAPH_HARD_MAX_ACCOUNTS_PER_ENTITY: Final[int] = 100
GRAPH_HARD_MAX_DATE_SPAN_DAYS: Final[int] = 3_650
GRAPH_HARD_TIMEOUT_SECONDS: Final[int] = 60

REPORT_HARD_MAX_ITEMS_PER_SECTION: Final[int] = 500
REPORT_HARD_MAX_PAGES: Final[int] = 200
REPORT_HARD_MAX_GENERATION_SECONDS: Final[int] = 300

EXPORT_DEFAULT_MAX_ITEMS: Final[int] = 200
EXPORT_HARD_MAX_ITEMS: Final[int] = 10_000

SEARCH_MAX_QUERY_LENGTH: Final[int] = 200

AUDIT_HARD_MAX_EXPORT_ROWS: Final[int] = 100_000

CASE_HARD_MAX_DETAIL_ITEMS: Final[int] = 200
CASE_HARD_MAX_EXPORT_ITEMS: Final[int] = 1_000

COMPLAINT_HARD_MAX_EXPORT_ITEMS: Final[int] = 1_000


# -----------------------------------------------------------------------------
# Regular expression patterns and compiled matchers
# -----------------------------------------------------------------------------

CONTROL_CHAR_PATTERN: Final[str] = r"[\x00-\x1f\x7f]"
IDENTIFIER_PATTERN: Final[str] = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
UUID_PATTERN: Final[str] = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
SHA256_HEX_PATTERN: Final[str] = r"^[0-9a-fA-F]{64}$"
BASE64_URL_PATTERN: Final[str] = r"^[A-Za-z0-9_-]+={0,2}$"
REQUEST_ID_PATTERN: Final[str] = r"^[A-Za-z0-9._:-]{1,128}$"
IDEMPOTENCY_KEY_PATTERN: Final[str] = r"^[A-Za-z0-9._:-]{1,128}$"
CURSOR_PATTERN: Final[str] = r"^[A-Za-z0-9._:-]{1,4096}$"
SAFE_FILENAME_PATTERN: Final[str] = r"[^A-Za-z0-9._-]+"

CONTROL_CHAR_RE: Final[Pattern[str]] = re.compile(CONTROL_CHAR_PATTERN)
CURRENCY_RE: Final[Pattern[str]] = re.compile(CURRENCY_PATTERN)
IDENTIFIER_RE: Final[Pattern[str]] = re.compile(IDENTIFIER_PATTERN)
UUID_RE: Final[Pattern[str]] = re.compile(UUID_PATTERN)
SHA256_HEX_RE: Final[Pattern[str]] = re.compile(SHA256_HEX_PATTERN)
BASE64_URL_RE: Final[Pattern[str]] = re.compile(BASE64_URL_PATTERN)
REQUEST_ID_RE: Final[Pattern[str]] = re.compile(REQUEST_ID_PATTERN)
IDEMPOTENCY_KEY_RE: Final[Pattern[str]] = re.compile(IDEMPOTENCY_KEY_PATTERN)
CURSOR_RE: Final[Pattern[str]] = re.compile(CURSOR_PATTERN)
SAFE_FILENAME_RE: Final[Pattern[str]] = re.compile(SAFE_FILENAME_PATTERN)

WINDOWS_RESERVED_NAMES: Final[frozenset[str]] = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)


# -----------------------------------------------------------------------------
# Sensitive-key and forbidden-response registries
# -----------------------------------------------------------------------------

SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "apikey",
        "artifact_path",
        "auth_header",
        "authorization",
        "bearer",
        "body",
        "card_number",
        "connection_string",
        "cookie",
        "credential",
        "credentials",
        "cvv",
        "database_url",
        "dsn",
        "file_path",
        "id_token",
        "identifier_hash",
        "model_artifact_path",
        "model_path",
        "narrative",
        "narrative_raw",
        "narrative_normalized",
        "otp",
        "pan",
        "pass",
        "passwd",
        "password",
        "password_hash",
        "payload_hash",
        "pickle",
        "pin",
        "private_key",
        "raw_payload",
        "refresh_token",
        "secret",
        "secret_key",
        "session",
        "source_payload_hash",
        "token",
    }
)

SENSITIVE_KEY_TOKENS: Final[tuple[str, ...]] = (
    "access_key",
    "account_number",
    "api_key",
    "apikey",
    "artifact_path",
    "authorization",
    "card_number",
    "connection_string",
    "credential",
    "customer_data",
    "customer_id",
    "database_url",
    "device_id",
    "dsn",
    "email_address",
    "file_path",
    "filesystem",
    "fraud",
    "ground_truth",
    "hash",
    "identifier_hash",
    "ifsc",
    "ip_address",
    "label",
    "model_artifact_path",
    "model_path",
    "narrative",
    "passphrase",
    "password",
    "passwd",
    "payload_hash",
    "phone_number",
    "pickle",
    "private_key",
    "raw_",
    "real_data",
    "refresh_token",
    "ring",
    "scenario",
    "secret",
    "secret_key",
    "token",
    "upi_id",
)

FORBIDDEN_RESPONSE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_token",
        "artifact_path",
        "authorization",
        "cookie",
        "database_url",
        "dsn",
        "file_path",
        "fraud_label",
        "ground_truth_label",
        "identifier_hash",
        "model_artifact_path",
        "model_path",
        "narrative_normalized",
        "narrative_raw",
        "password",
        "password_hash",
        "refresh_token",
        "ring_id",
        "scenario_id",
        "secret",
        "secret_key",
        "token",
    }
)

ML_FORBIDDEN_FEATURE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "fraud_label",
        "ground_truth_label",
        "is_fraud",
        "label",
        "ring_id",
        "scenario_id",
    }
)


# -----------------------------------------------------------------------------
# Redaction and truncation literals
# -----------------------------------------------------------------------------

REDACTED: Final[str] = "***REDACTED***"
TRUNCATED_MARKER: Final[str] = "[truncated]"
TRUNCATED_DEPTH: Final[str] = "[truncated-depth]"
BINARY_PLACEHOLDER: Final[str] = "<binary>"


# -----------------------------------------------------------------------------
# Authentication and token literals
# -----------------------------------------------------------------------------

AUTH_MODE_JWT_BEARER: Final[str] = "jwt_bearer"
TOKEN_TYPE_ACCESS: Final[str] = "access"
TOKEN_TYPE_REFRESH: Final[str] = "refresh"
TOKEN_SCHEME_BEARER: Final[str] = "Bearer"

JWT_ALGORITHM_HS256: Final[str] = "HS256"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES: Final[int] = 30
DEFAULT_CLOCK_SKEW_SECONDS: Final[int] = 30
DEFAULT_MAX_TOKEN_LENGTH: Final[int] = 8_192

PASSWORD_HASH_ARGON2ID: Final[str] = "argon2id"
PASSWORD_HASH_BCRYPT: Final[str] = "bcrypt"
PASSWORD_HASH_PBKDF2_SHA256: Final[str] = "pbkdf2_sha256"

DEFAULT_PASSWORD_MIN_LENGTH: Final[int] = 12
DEFAULT_PASSWORD_MAX_LENGTH: Final[int] = 128

DEFAULT_LOGIN_MAX_ATTEMPTS: Final[int] = 5
DEFAULT_LOGIN_LOCKOUT_MINUTES: Final[int] = 15
DEFAULT_LOGIN_ATTEMPT_WINDOW_MINUTES: Final[int] = 15

PASSWORD_POLICY_DEFAULTS: Final[Mapping[str, Any]] = MappingProxyType(
    {
        "hash_scheme": PASSWORD_HASH_ARGON2ID,
        "min_length": DEFAULT_PASSWORD_MIN_LENGTH,
        "max_length": DEFAULT_PASSWORD_MAX_LENGTH,
        "require_lowercase": True,
        "require_uppercase": True,
        "require_digit": True,
        "require_special": True,
        "require_no_spaces": False,
        "reject_placeholder": True,
        "reject_user_identifier": True,
        "reject_repetitive": True,
    }
)

LOCKOUT_POLICY_DEFAULTS: Final[Mapping[str, Any]] = MappingProxyType(
    {
        "max_attempts": DEFAULT_LOGIN_MAX_ATTEMPTS,
        "lockout_minutes": DEFAULT_LOGIN_LOCKOUT_MINUTES,
        "attempt_window_minutes": DEFAULT_LOGIN_ATTEMPT_WINDOW_MINUTES,
        "reset_on_success": True,
        "reveal_locked_account": False,
        "reveal_inactive_account": False,
    }
)


# -----------------------------------------------------------------------------
# Rate-limit literals
# -----------------------------------------------------------------------------

RATE_LIMIT_ALGORITHM_SLIDING_WINDOW: Final[str] = "sliding_window"
RATE_LIMIT_ALGORITHM_FIXED_WINDOW: Final[str] = "fixed_window"
RATE_LIMIT_ALGORITHM_TOKEN_BUCKET: Final[str] = "token_bucket"

RATE_LIMIT_DEFAULT: Final[str] = "300/minute"
RATE_LIMIT_LOGIN: Final[str] = "5/minute"
RATE_LIMIT_ANALYSIS: Final[str] = "5/minute"
RATE_LIMIT_GRAPH: Final[str] = "60/minute"
RATE_LIMIT_REPORT: Final[str] = "10/minute"
RATE_LIMIT_INGESTION: Final[str] = "10/minute"
RATE_LIMIT_AUDIT: Final[str] = "30/minute"
RATE_LIMIT_SEARCH: Final[str] = "120/minute"

RATE_LIMIT_DEFAULTS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "global": RATE_LIMIT_DEFAULT,
        "login": RATE_LIMIT_LOGIN,
        "analysis": RATE_LIMIT_ANALYSIS,
        "graph": RATE_LIMIT_GRAPH,
        "report": RATE_LIMIT_REPORT,
        "ingestion": RATE_LIMIT_INGESTION,
        "audit": RATE_LIMIT_AUDIT,
        "search": RATE_LIMIT_SEARCH,
    }
)


# -----------------------------------------------------------------------------
# Sort, direction, granularity, and format literals
# -----------------------------------------------------------------------------

SORT_ASC: Final[str] = "asc"
SORT_DESC: Final[str] = "desc"

DIRECTION_OUTGOING: Final[str] = "outgoing"
DIRECTION_INCOMING: Final[str] = "incoming"
DIRECTION_BOTH: Final[str] = "both"

GRANULARITY_MINUTE: Final[str] = "minute"
GRANULARITY_HOUR: Final[str] = "hour"
GRANULARITY_DAY: Final[str] = "day"
GRANULARITY_WEEK: Final[str] = "week"
GRANULARITY_MONTH: Final[str] = "month"
GRANULARITY_QUARTER: Final[str] = "quarter"
GRANULARITY_YEAR: Final[str] = "year"

FORMAT_JSON: Final[str] = "json"
FORMAT_CSV: Final[str] = "csv"
FORMAT_PDF: Final[str] = "pdf"
FORMAT_NDJSON: Final[str] = "ndjson"

EXPORT_FORMATS: Final[tuple[str, ...]] = (
    FORMAT_JSON,
    FORMAT_CSV,
    FORMAT_PDF,
    FORMAT_NDJSON,
)

REPORT_FORMATS: Final[tuple[str, ...]] = (
    FORMAT_PDF,
    FORMAT_JSON,
)


# -----------------------------------------------------------------------------
# Response envelope field literals
# -----------------------------------------------------------------------------

FIELD_OK: Final[str] = "ok"
FIELD_DATA: Final[str] = "data"
FIELD_ERROR: Final[str] = "error"
FIELD_META: Final[str] = "meta"
FIELD_CAVEATS: Final[str] = "caveats"
FIELD_GENERATED_AT: Final[str] = "generated_at"
FIELD_REQUEST_ID: Final[str] = "request_id"
FIELD_ITEMS: Final[str] = "items"
FIELD_TOTAL: Final[str] = "total"
FIELD_PAGE: Final[str] = "page"
FIELD_PAGE_SIZE: Final[str] = "page_size"
FIELD_TOTAL_PAGES: Final[str] = "total_pages"
FIELD_SORT_BY: Final[str] = "sort_by"
FIELD_SORT_ORDER: Final[str] = "sort_order"
FIELD_NEXT_CURSOR: Final[str] = "next_cursor"
FIELD_PREVIOUS_CURSOR: Final[str] = "previous_cursor"
FIELD_ERRORS: Final[str] = "errors"
FIELD_ACCEPTED: Final[str] = "accepted"
FIELD_REJECTED: Final[str] = "rejected"
FIELD_DUPLICATED: Final[str] = "duplicated"
FIELD_SKIPPED: Final[str] = "skipped"
FIELD_TRUNCATED: Final[str] = "truncated"
FIELD_LIMIT: Final[str] = "limit"
FIELD_REMAINING: Final[str] = "remaining"
FIELD_RESET_SECONDS: Final[str] = "reset_seconds"
FIELD_RETRY_AFTER_SECONDS: Final[str] = "retry_after_seconds"


# -----------------------------------------------------------------------------
# Audit literals
# -----------------------------------------------------------------------------

AUDIT_OUTCOME_SUCCESS: Final[str] = "SUCCESS"
AUDIT_OUTCOME_FAILURE: Final[str] = "FAILURE"
AUDIT_OUTCOME_DENIED: Final[str] = "DENIED"
AUDIT_OUTCOME_ERROR: Final[str] = "ERROR"

AUDIT_RESOURCE_SYSTEM: Final[str] = "system"
AUDIT_RESOURCE_USER: Final[str] = "user"
AUDIT_RESOURCE_ACCOUNT: Final[str] = "account"
AUDIT_RESOURCE_TRANSACTION: Final[str] = "transaction"
AUDIT_RESOURCE_COMPLAINT: Final[str] = "complaint"
AUDIT_RESOURCE_COMPLAINT_CORRELATION: Final[str] = "complaint_correlation"
AUDIT_RESOURCE_ENTITY: Final[str] = "entity"
AUDIT_RESOURCE_ENTITY_LINK: Final[str] = "entity_link"
AUDIT_RESOURCE_ALERT: Final[str] = "alert"
AUDIT_RESOURCE_CASE: Final[str] = "case"
AUDIT_RESOURCE_CASE_EVIDENCE: Final[str] = "case_evidence"
AUDIT_RESOURCE_CASE_NOTE: Final[str] = "case_note"
AUDIT_RESOURCE_MODEL_ASSESSMENT: Final[str] = "model_assessment"
AUDIT_RESOURCE_MODEL_VERSION: Final[str] = "model_version"
AUDIT_RESOURCE_MODEL_EVALUATION: Final[str] = "model_evaluation"
AUDIT_RESOURCE_GRAPH_RUN: Final[str] = "graph_run"
AUDIT_RESOURCE_REPORT: Final[str] = "report"
AUDIT_RESOURCE_AUDIT_EVENT: Final[str] = "audit_event"
AUDIT_RESOURCE_INGESTION_BATCH: Final[str] = "ingestion_batch"
AUDIT_RESOURCE_DEV_USERS: Final[str] = "dev_users"
AUDIT_RESOURCE_CONFIG: Final[str] = "config"

AUDIT_ACTION_LOGIN: Final[str] = "login"
AUDIT_ACTION_FAILED_LOGIN: Final[str] = "failed_login"
AUDIT_ACTION_PASSWORD_CHANGE: Final[str] = "password_change"
AUDIT_ACTION_PASSWORD_CHANGE_DENIED: Final[str] = "password_change_denied"
AUDIT_ACTION_USER_CREATE: Final[str] = "user_create"
AUDIT_ACTION_USER_UPDATE: Final[str] = "user_update"
AUDIT_ACTION_USER_ACTIVATE: Final[str] = "user_activate"
AUDIT_ACTION_USER_DEACTIVATE: Final[str] = "user_deactivate"
AUDIT_ACTION_USER_ROLE_CHANGE: Final[str] = "user_role_change"
AUDIT_ACTION_USER_UNLOCK: Final[str] = "user_unlock"

AUDIT_ACTION_INGESTION_BATCH: Final[str] = "ingestion_batch"
AUDIT_ACTION_SEED_RESET: Final[str] = "seed_reset"
AUDIT_ACTION_DEV_USERS_SEED: Final[str] = "dev_users_seed"

AUDIT_ACTION_ANALYSIS_RUN: Final[str] = "analysis_run"
AUDIT_ACTION_ALERT_READ: Final[str] = "alert_read"
AUDIT_ACTION_ALERT_TRIAGE: Final[str] = "alert_triage"
AUDIT_ACTION_ALERT_ASSIGN: Final[str] = "alert_assign"
AUDIT_ACTION_ALERT_ESCALATE: Final[str] = "alert_escalate"
AUDIT_ACTION_ALERT_CASE_CREATE: Final[str] = "alert_case_create"

AUDIT_ACTION_CASE_CREATE: Final[str] = "case_create"
AUDIT_ACTION_CASE_UPDATE: Final[str] = "case_update"
AUDIT_ACTION_CASE_ASSIGN: Final[str] = "case_assign"
AUDIT_ACTION_CASE_CLOSE: Final[str] = "case_close"
AUDIT_ACTION_CASE_REOPEN: Final[str] = "case_reopen"
AUDIT_ACTION_CASE_NOTE_ADD: Final[str] = "case_note_add"
AUDIT_ACTION_CASE_EVIDENCE_ADD: Final[str] = "case_evidence_add"
AUDIT_ACTION_CASE_EVIDENCE_REMOVE: Final[str] = "case_evidence_remove"
AUDIT_ACTION_CASE_EXPORT: Final[str] = "case_export"

AUDIT_ACTION_COMPLAINT_REVIEW: Final[str] = "complaint_review"
AUDIT_ACTION_COMPLAINT_NARRATIVE_READ: Final[str] = "complaint_narrative_read"

AUDIT_ACTION_GRAPH_READ: Final[str] = "graph_read"
AUDIT_ACTION_GRAPH_EXPORT: Final[str] = "graph_export"

AUDIT_ACTION_REPORT_PREVIEW: Final[str] = "report_preview"
AUDIT_ACTION_REPORT_GENERATE: Final[str] = "report_generate"
AUDIT_ACTION_REPORT_DOWNLOAD: Final[str] = "report_download"

AUDIT_ACTION_AUDIT_READ: Final[str] = "audit_read"
AUDIT_ACTION_AUDIT_EXPORT: Final[str] = "audit_export"

AUDIT_ACTION_MODEL_TRAIN: Final[str] = "model_train"
AUDIT_ACTION_MODEL_EVALUATE: Final[str] = "model_evaluate"
AUDIT_ACTION_MODEL_PROMOTE: Final[str] = "model_promote"
AUDIT_ACTION_MODEL_RETIRE: Final[str] = "model_retire"

AUDIT_ACTION_CONFIG_READ: Final[str] = "config_read"
AUDIT_ACTION_CONFIG_WRITE: Final[str] = "config_write"


# -----------------------------------------------------------------------------
# Ingestion literals
# -----------------------------------------------------------------------------

INGESTION_ENTITY_ACCOUNTS: Final[str] = "accounts"
INGESTION_ENTITY_TRANSACTIONS: Final[str] = "transactions"
INGESTION_ENTITY_COMPLAINTS: Final[str] = "complaints"
INGESTION_ENTITY_ENTITIES: Final[str] = "entities"
INGESTION_ENTITY_ENTITY_LINKS: Final[str] = "entity_links"

INGESTION_ENTITY_TYPES: Final[tuple[str, ...]] = (
    INGESTION_ENTITY_ACCOUNTS,
    INGESTION_ENTITY_TRANSACTIONS,
    INGESTION_ENTITY_COMPLAINTS,
    INGESTION_ENTITY_ENTITIES,
    INGESTION_ENTITY_ENTITY_LINKS,
)

DUPLICATE_STRATEGY_REJECT: Final[str] = "reject"
DUPLICATE_STRATEGY_SKIP: Final[str] = "skip"
DUPLICATE_STRATEGIES: Final[tuple[str, ...]] = (
    DUPLICATE_STRATEGY_REJECT,
    DUPLICATE_STRATEGY_SKIP,
)

ROW_ERROR_DUPLICATE: Final[str] = "duplicate"
ROW_ERROR_REFERENCE_MISSING: Final[str] = "reference_missing"
ROW_ERROR_FUTURE_TIMESTAMP: Final[str] = "future_timestamp"
ROW_ERROR_INVALID_TIME_RANGE: Final[str] = "invalid_time_range"
ROW_ERROR_PARSE_ERROR: Final[str] = "parse_error"
ROW_ERROR_POLICY_VIOLATION: Final[str] = "policy_violation"
ROW_ERROR_NEW_PASSWORD_MUST_DIFFER: Final[str] = "new_password_must_differ"

INGESTION_ROW_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        ROW_ERROR_DUPLICATE,
        ROW_ERROR_REFERENCE_MISSING,
        ROW_ERROR_FUTURE_TIMESTAMP,
        ROW_ERROR_INVALID_TIME_RANGE,
        ROW_ERROR_PARSE_ERROR,
        ROW_ERROR_POLICY_VIOLATION,
        ROW_ERROR_NEW_PASSWORD_MUST_DIFFER,
    }
)


# -----------------------------------------------------------------------------
# Domain state literals
# -----------------------------------------------------------------------------
# These literals mirror canonical enum values for serialization, configuration,
# and low-level helpers. `app.core.enums` remains the authoritative validation
# and transition layer.

ACCOUNT_STATUS_ACTIVE: Final[str] = "ACTIVE"
ACCOUNT_STATUS_INACTIVE: Final[str] = "INACTIVE"
ACCOUNT_STATUS_DORMANT: Final[str] = "DORMANT"
ACCOUNT_STATUS_PENDING: Final[str] = "PENDING"
ACCOUNT_STATUS_SUSPENDED: Final[str] = "SUSPENDED"
ACCOUNT_STATUS_RESTRICTED: Final[str] = "RESTRICTED"
ACCOUNT_STATUS_CLOSED: Final[str] = "CLOSED"

ACCOUNT_STATUSES: Final[tuple[str, ...]] = (
    ACCOUNT_STATUS_ACTIVE,
    ACCOUNT_STATUS_INACTIVE,
    ACCOUNT_STATUS_DORMANT,
    ACCOUNT_STATUS_PENDING,
    ACCOUNT_STATUS_SUSPENDED,
    ACCOUNT_STATUS_RESTRICTED,
    ACCOUNT_STATUS_CLOSED,
)

ACCOUNT_TYPE_SAVINGS: Final[str] = "SAVINGS"
ACCOUNT_TYPE_CURRENT: Final[str] = "CURRENT"
ACCOUNT_TYPE_WALLET: Final[str] = "WALLET"
ACCOUNT_TYPE_UPI: Final[str] = "UPI"
ACCOUNT_TYPE_CARD: Final[str] = "CARD"
ACCOUNT_TYPE_OTHER: Final[str] = "OTHER"

ACCOUNT_TYPES: Final[tuple[str, ...]] = (
    ACCOUNT_TYPE_SAVINGS,
    ACCOUNT_TYPE_CURRENT,
    ACCOUNT_TYPE_WALLET,
    ACCOUNT_TYPE_UPI,
    ACCOUNT_TYPE_CARD,
    ACCOUNT_TYPE_OTHER,
)

CHANNEL_UPI: Final[str] = "UPI"
CHANNEL_NEFT: Final[str] = "NEFT"
CHANNEL_RTGS: Final[str] = "RTGS"
CHANNEL_IMPS: Final[str] = "IMPS"
CHANNEL_CARD: Final[str] = "CARD"
CHANNEL_WALLET: Final[str] = "WALLET"
CHANNEL_CASH: Final[str] = "CASH"
CHANNEL_INTERNAL: Final[str] = "INTERNAL"
CHANNEL_EXTERNAL: Final[str] = "EXTERNAL"
CHANNEL_UNKNOWN: Final[str] = "UNKNOWN"

CHANNELS: Final[tuple[str, ...]] = (
    CHANNEL_UPI,
    CHANNEL_NEFT,
    CHANNEL_RTGS,
    CHANNEL_IMPS,
    CHANNEL_CARD,
    CHANNEL_WALLET,
    CHANNEL_CASH,
    CHANNEL_INTERNAL,
    CHANNEL_EXTERNAL,
    CHANNEL_UNKNOWN,
)

TRANSACTION_STATUS_COMPLETED: Final[str] = "COMPLETED"
TRANSACTION_STATUS_PENDING: Final[str] = "PENDING"
TRANSACTION_STATUS_FAILED: Final[str] = "FAILED"
TRANSACTION_STATUS_REVERSED: Final[str] = "REVERSED"
TRANSACTION_STATUS_CANCELLED: Final[str] = "CANCELLED"
TRANSACTION_STATUS_DISPUTED: Final[str] = "DISPUTED"
TRANSACTION_STATUS_UNKNOWN: Final[str] = "UNKNOWN"

TRANSACTION_STATUSES: Final[tuple[str, ...]] = (
    TRANSACTION_STATUS_COMPLETED,
    TRANSACTION_STATUS_PENDING,
    TRANSACTION_STATUS_FAILED,
    TRANSACTION_STATUS_REVERSED,
    TRANSACTION_STATUS_CANCELLED,
    TRANSACTION_STATUS_DISPUTED,
    TRANSACTION_STATUS_UNKNOWN,
)

PRIORITY_LOW: Final[str] = "LOW"
PRIORITY_MEDIUM: Final[str] = "MEDIUM"
PRIORITY_HIGH: Final[str] = "HIGH"
PRIORITY_CRITICAL: Final[str] = "CRITICAL"
PRIORITY_UNKNOWN: Final[str] = "UNKNOWN"

PRIORITIES: Final[tuple[str, ...]] = (
    PRIORITY_LOW,
    PRIORITY_MEDIUM,
    PRIORITY_HIGH,
    PRIORITY_CRITICAL,
    PRIORITY_UNKNOWN,
)

SEVERITY_INFO: Final[str] = "INFO"
SEVERITY_LOW: Final[str] = "LOW"
SEVERITY_MEDIUM: Final[str] = "MEDIUM"
SEVERITY_HIGH: Final[str] = "HIGH"
SEVERITY_CRITICAL: Final[str] = "CRITICAL"

SEVERITIES: Final[tuple[str, ...]] = (
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

ALERT_STATE_NEW: Final[str] = "NEW"
ALERT_STATE_ACKNOWLEDGED: Final[str] = "ACKNOWLEDGED"
ALERT_STATE_UNDER_REVIEW: Final[str] = "UNDER_REVIEW"
ALERT_STATE_ESCALATED: Final[str] = "ESCALATED"
ALERT_STATE_RESOLVED: Final[str] = "RESOLVED"
ALERT_STATE_FALSE_POSITIVE: Final[str] = "FALSE_POSITIVE"
ALERT_STATE_DUPLICATE: Final[str] = "DUPLICATE"
ALERT_STATE_CLOSED: Final[str] = "CLOSED"

ALERT_STATES: Final[tuple[str, ...]] = (
    ALERT_STATE_NEW,
    ALERT_STATE_ACKNOWLEDGED,
    ALERT_STATE_UNDER_REVIEW,
    ALERT_STATE_ESCALATED,
    ALERT_STATE_RESOLVED,
    ALERT_STATE_FALSE_POSITIVE,
    ALERT_STATE_DUPLICATE,
    ALERT_STATE_CLOSED,
)

# These mirror `app.models.CaseStatus` and `app.models.Disposition`, which the
# case table's columns are declared over. An earlier set listed statuses the
# column cannot hold (`UNDER_REVIEW`, borrowed from the alert states, plus
# `RESOLVED`, `REOPENED` and `DUPLICATE`) and omitted `TRIAGED`; the
# disposition labels overlapped the persisted ones in one value out of six.
CASE_STATUS_NEW: Final[str] = "NEW"
CASE_STATUS_TRIAGED: Final[str] = "TRIAGED"
CASE_STATUS_UNDER_INVESTIGATION: Final[str] = "UNDER_INVESTIGATION"
CASE_STATUS_ESCALATED: Final[str] = "ESCALATED"
CASE_STATUS_CLOSED: Final[str] = "CLOSED"

CASE_STATUSES: Final[tuple[str, ...]] = (
    CASE_STATUS_NEW,
    CASE_STATUS_TRIAGED,
    CASE_STATUS_UNDER_INVESTIGATION,
    CASE_STATUS_ESCALATED,
    CASE_STATUS_CLOSED,
)

CASE_DISPOSITION_CONFIRMED_FRAUD: Final[str] = "CONFIRMED_FRAUD"
CASE_DISPOSITION_FALSE_POSITIVE: Final[str] = "FALSE_POSITIVE"
CASE_DISPOSITION_INCONCLUSIVE: Final[str] = "INCONCLUSIVE"
CASE_DISPOSITION_REFERRED: Final[str] = "REFERRED"

CASE_DISPOSITIONS: Final[tuple[str, ...]] = (
    CASE_DISPOSITION_CONFIRMED_FRAUD,
    CASE_DISPOSITION_FALSE_POSITIVE,
    CASE_DISPOSITION_INCONCLUSIVE,
    CASE_DISPOSITION_REFERRED,
)

MATCH_METHOD_EXACT: Final[str] = "EXACT"
MATCH_METHOD_HASHED: Final[str] = "HASHED"
MATCH_METHOD_DEVICE: Final[str] = "DEVICE"
MATCH_METHOD_IP: Final[str] = "IP"
MATCH_METHOD_PHONE: Final[str] = "PHONE"
MATCH_METHOD_EMAIL: Final[str] = "EMAIL"
MATCH_METHOD_UPI: Final[str] = "UPI"
MATCH_METHOD_ADDRESS: Final[str] = "ADDRESS"
MATCH_METHOD_NAME: Final[str] = "NAME"
MATCH_METHOD_ACCOUNT: Final[str] = "ACCOUNT"
MATCH_METHOD_TRANSACTION: Final[str] = "TRANSACTION"
MATCH_METHOD_COMPLAINT: Final[str] = "COMPLAINT"
MATCH_METHOD_GRAPH: Final[str] = "GRAPH"
MATCH_METHOD_HEURISTIC: Final[str] = "HEURISTIC"
MATCH_METHOD_MANUAL: Final[str] = "MANUAL"
MATCH_METHOD_UNKNOWN: Final[str] = "UNKNOWN"

MATCH_METHODS: Final[tuple[str, ...]] = (
    MATCH_METHOD_EXACT,
    MATCH_METHOD_HASHED,
    MATCH_METHOD_DEVICE,
    MATCH_METHOD_IP,
    MATCH_METHOD_PHONE,
    MATCH_METHOD_EMAIL,
    MATCH_METHOD_UPI,
    MATCH_METHOD_ADDRESS,
    MATCH_METHOD_NAME,
    MATCH_METHOD_ACCOUNT,
    MATCH_METHOD_TRANSACTION,
    MATCH_METHOD_COMPLAINT,
    MATCH_METHOD_GRAPH,
    MATCH_METHOD_HEURISTIC,
    MATCH_METHOD_MANUAL,
    MATCH_METHOD_UNKNOWN,
)

VERIFICATION_STATE_UNVERIFIED: Final[str] = "UNVERIFIED"
VERIFICATION_STATE_PENDING: Final[str] = "PENDING"
VERIFICATION_STATE_VERIFIED: Final[str] = "VERIFIED"
VERIFICATION_STATE_REJECTED: Final[str] = "REJECTED"
VERIFICATION_STATE_STALE: Final[str] = "STALE"

VERIFICATION_STATES: Final[tuple[str, ...]] = (
    VERIFICATION_STATE_UNVERIFIED,
    VERIFICATION_STATE_PENDING,
    VERIFICATION_STATE_VERIFIED,
    VERIFICATION_STATE_REJECTED,
    VERIFICATION_STATE_STALE,
)

REVIEW_STATE_UNREVIEWED: Final[str] = "UNREVIEWED"
REVIEW_STATE_CONFIRMED: Final[str] = "CONFIRMED"
REVIEW_STATE_REJECTED: Final[str] = "REJECTED"
REVIEW_STATE_NEEDS_MORE_EVIDENCE: Final[str] = "NEEDS_MORE_EVIDENCE"
REVIEW_STATE_ESCALATED: Final[str] = "ESCALATED"
REVIEW_STATE_SUPERSEDED: Final[str] = "SUPERSEDED"

REVIEW_STATES: Final[tuple[str, ...]] = (
    REVIEW_STATE_UNREVIEWED,
    REVIEW_STATE_CONFIRMED,
    REVIEW_STATE_REJECTED,
    REVIEW_STATE_NEEDS_MORE_EVIDENCE,
    REVIEW_STATE_ESCALATED,
    REVIEW_STATE_SUPERSEDED,
)

EVIDENCE_TYPE_ALERT: Final[str] = "ALERT"
EVIDENCE_TYPE_TRANSACTION: Final[str] = "TRANSACTION"
EVIDENCE_TYPE_ACCOUNT: Final[str] = "ACCOUNT"
EVIDENCE_TYPE_ENTITY: Final[str] = "ENTITY"
EVIDENCE_TYPE_COMPLAINT: Final[str] = "COMPLAINT"
EVIDENCE_TYPE_COMPLAINT_CORRELATION: Final[str] = "COMPLAINT_CORRELATION"
EVIDENCE_TYPE_GRAPH_PATH: Final[str] = "GRAPH_PATH"
EVIDENCE_TYPE_MONEY_TRAIL: Final[str] = "MONEY_TRAIL"
EVIDENCE_TYPE_MODEL_ASSESSMENT: Final[str] = "MODEL_ASSESSMENT"
EVIDENCE_TYPE_CASE_NOTE: Final[str] = "CASE_NOTE"
EVIDENCE_TYPE_AUDIT_EVENT: Final[str] = "AUDIT_EVENT"
EVIDENCE_TYPE_DOCUMENT: Final[str] = "DOCUMENT"
EVIDENCE_TYPE_EXTERNAL_REF: Final[str] = "EXTERNAL_REF"

EVIDENCE_TYPES: Final[tuple[str, ...]] = (
    EVIDENCE_TYPE_ALERT,
    EVIDENCE_TYPE_TRANSACTION,
    EVIDENCE_TYPE_ACCOUNT,
    EVIDENCE_TYPE_ENTITY,
    EVIDENCE_TYPE_COMPLAINT,
    EVIDENCE_TYPE_COMPLAINT_CORRELATION,
    EVIDENCE_TYPE_GRAPH_PATH,
    EVIDENCE_TYPE_MONEY_TRAIL,
    EVIDENCE_TYPE_MODEL_ASSESSMENT,
    EVIDENCE_TYPE_CASE_NOTE,
    EVIDENCE_TYPE_AUDIT_EVENT,
    EVIDENCE_TYPE_DOCUMENT,
    EVIDENCE_TYPE_EXTERNAL_REF,
)

SCORING_MODE_TRAINED_MODEL: Final[str] = "TRAINED_MODEL"
SCORING_MODE_HEURISTIC_FALLBACK: Final[str] = "HEURISTIC_FALLBACK"
SCORING_MODE_RULES_ONLY: Final[str] = "RULES_ONLY"
SCORING_MODE_HYBRID: Final[str] = "HYBRID"
SCORING_MODE_DISABLED: Final[str] = "DISABLED"
SCORING_MODE_UNKNOWN: Final[str] = "UNKNOWN"

SCORING_MODES: Final[tuple[str, ...]] = (
    SCORING_MODE_TRAINED_MODEL,
    SCORING_MODE_HEURISTIC_FALLBACK,
    SCORING_MODE_RULES_ONLY,
    SCORING_MODE_HYBRID,
    SCORING_MODE_DISABLED,
    SCORING_MODE_UNKNOWN,
)

RISK_BAND_LOW: Final[str] = "LOW"
RISK_BAND_MEDIUM: Final[str] = "MEDIUM"
RISK_BAND_HIGH: Final[str] = "HIGH"
RISK_BAND_CRITICAL: Final[str] = "CRITICAL"
RISK_BAND_UNKNOWN: Final[str] = "UNKNOWN"

RISK_BANDS: Final[tuple[str, ...]] = (
    RISK_BAND_LOW,
    RISK_BAND_MEDIUM,
    RISK_BAND_HIGH,
    RISK_BAND_CRITICAL,
    RISK_BAND_UNKNOWN,
)

MODEL_STATUS_DRAFT: Final[str] = "DRAFT"
MODEL_STATUS_EVALUATED: Final[str] = "EVALUATED"
MODEL_STATUS_CANDIDATE: Final[str] = "CANDIDATE"
MODEL_STATUS_ACTIVE: Final[str] = "ACTIVE"
MODEL_STATUS_RETIRED: Final[str] = "RETIRED"
MODEL_STATUS_ARCHIVED: Final[str] = "ARCHIVED"

MODEL_STATUSES: Final[tuple[str, ...]] = (
    MODEL_STATUS_DRAFT,
    MODEL_STATUS_EVALUATED,
    MODEL_STATUS_CANDIDATE,
    MODEL_STATUS_ACTIVE,
    MODEL_STATUS_RETIRED,
    MODEL_STATUS_ARCHIVED,
)

INGESTION_OUTCOME_ACCEPTED: Final[str] = "ACCEPTED"
INGESTION_OUTCOME_REJECTED: Final[str] = "REJECTED"
INGESTION_OUTCOME_DUPLICATED: Final[str] = "DUPLICATED"
INGESTION_OUTCOME_SKIPPED: Final[str] = "SKIPPED"
INGESTION_OUTCOME_TRUNCATED: Final[str] = "TRUNCATED"

INGESTION_OUTCOMES: Final[tuple[str, ...]] = (
    INGESTION_OUTCOME_ACCEPTED,
    INGESTION_OUTCOME_REJECTED,
    INGESTION_OUTCOME_DUPLICATED,
    INGESTION_OUTCOME_SKIPPED,
    INGESTION_OUTCOME_TRUNCATED,
)


# -----------------------------------------------------------------------------
# Graph literals
# -----------------------------------------------------------------------------

GRAPH_NODE_ACCOUNT: Final[str] = "account"
GRAPH_NODE_TRANSACTION: Final[str] = "transaction"
GRAPH_NODE_ENTITY: Final[str] = "entity"
GRAPH_NODE_COMPLAINT: Final[str] = "complaint"
GRAPH_NODE_ALERT: Final[str] = "alert"
GRAPH_NODE_ASSESSMENT: Final[str] = "assessment"
GRAPH_NODE_CASE: Final[str] = "case"

GRAPH_NODE_TYPES: Final[tuple[str, ...]] = (
    GRAPH_NODE_ACCOUNT,
    GRAPH_NODE_TRANSACTION,
    GRAPH_NODE_ENTITY,
    GRAPH_NODE_COMPLAINT,
    GRAPH_NODE_ALERT,
    GRAPH_NODE_ASSESSMENT,
    GRAPH_NODE_CASE,
)

GRAPH_EDGE_SENT: Final[str] = "sent"
GRAPH_EDGE_RECEIVED: Final[str] = "received"
GRAPH_EDGE_LINKED_TO: Final[str] = "linked_to"
GRAPH_EDGE_RELATED_TO: Final[str] = "related_to"
GRAPH_EDGE_CORRELATED_WITH: Final[str] = "correlated_with"
GRAPH_EDGE_ALERTED_ON: Final[str] = "alerted_on"
GRAPH_EDGE_ASSESSED_BY: Final[str] = "assessed_by"
GRAPH_EDGE_ATTACHED_TO_CASE: Final[str] = "attached_to_case"

GRAPH_EDGE_TYPES: Final[tuple[str, ...]] = (
    GRAPH_EDGE_SENT,
    GRAPH_EDGE_RECEIVED,
    GRAPH_EDGE_LINKED_TO,
    GRAPH_EDGE_RELATED_TO,
    GRAPH_EDGE_CORRELATED_WITH,
    GRAPH_EDGE_ALERTED_ON,
    GRAPH_EDGE_ASSESSED_BY,
    GRAPH_EDGE_ATTACHED_TO_CASE,
)


# -----------------------------------------------------------------------------
# Entity literals
# -----------------------------------------------------------------------------

ENTITY_TYPE_DEVICE: Final[str] = "DEVICE"
ENTITY_TYPE_PHONE: Final[str] = "PHONE"
ENTITY_TYPE_EMAIL: Final[str] = "EMAIL"
ENTITY_TYPE_UPI: Final[str] = "UPI"
ENTITY_TYPE_IP: Final[str] = "IP"
ENTITY_TYPE_ADDRESS: Final[str] = "ADDRESS"
ENTITY_TYPE_NAME: Final[str] = "NAME"
ENTITY_TYPE_ACCOUNT: Final[str] = "ACCOUNT"
ENTITY_TYPE_CARD: Final[str] = "CARD"
ENTITY_TYPE_WALLET: Final[str] = "WALLET"
ENTITY_TYPE_OTHER: Final[str] = "OTHER"
ENTITY_TYPE_UNKNOWN: Final[str] = "UNKNOWN"

ENTITY_TYPES: Final[tuple[str, ...]] = (
    ENTITY_TYPE_DEVICE,
    ENTITY_TYPE_PHONE,
    ENTITY_TYPE_EMAIL,
    ENTITY_TYPE_UPI,
    ENTITY_TYPE_IP,
    ENTITY_TYPE_ADDRESS,
    ENTITY_TYPE_NAME,
    ENTITY_TYPE_ACCOUNT,
    ENTITY_TYPE_CARD,
    ENTITY_TYPE_WALLET,
    ENTITY_TYPE_OTHER,
    ENTITY_TYPE_UNKNOWN,
)


# -----------------------------------------------------------------------------
# Complaint literals
# -----------------------------------------------------------------------------

COMPLAINT_CATEGORY_OTHER: Final[str] = "other"
COMPLAINT_CATEGORY_UNCATEGORISED: Final[str] = "uncategorised"
COMPLAINT_SOURCE_SYNTHETIC: Final[str] = "synthetic"
COMPLAINT_SOURCE_API: Final[str] = "api"
COMPLAINT_SOURCE_SEED: Final[str] = "seed"

COMPLAINT_SOURCES: Final[tuple[str, ...]] = (
    COMPLAINT_SOURCE_SYNTHETIC,
    COMPLAINT_SOURCE_API,
    COMPLAINT_SOURCE_SEED,
)


# -----------------------------------------------------------------------------
# Report literals
# -----------------------------------------------------------------------------

REPORT_FILENAME_PREFIX: Final[str] = "muleguard-case-report"
REPORT_ENGINE_REPORTLAB: Final[str] = "reportlab"

REPORT_DEFAULT_DISCLAIMER: Final[str] = (
    "SYNTHETIC DEMO REPORT. Generated from synthetic prototype data. "
    "Not a real investigation. Not proof of fraud or wrongdoing."
)

REPORT_DEFAULT_LIMITATIONS: Final[str] = (
    "This report is generated from synthetic prototype data by MULEGUARD. "
    "Alerts, risk scores, graph relationships, candidate money trails, entity "
    "links, and complaint correlations are investigative leads only and are "
    "not evidence of wrongdoing. Risk scores are investigative priority "
    "scores, not probabilities of guilt and are not calibrated. Candidate "
    "money trails are heuristic flow views, not proof of layering or "
    "integration. Shared entities are association clusters only. Complaint "
    "correlations distinguish exact matches from inferred associations; "
    "inferred correlations are not verified facts. Case dispositions are "
    "investigator-entered workflow assessments and are not automatic "
    "conclusions. This prototype is not production-ready, does not claim "
    "regulatory compliance, does not claim real-world fraud-detection "
    "accuracy, and does not implement automatic adverse customer action."
)

REPORT_DEFAULT_FOOTER: Final[str] = (
    "Synthetic prototype only. Investigative leads, not proof of wrongdoing."
)


# -----------------------------------------------------------------------------
# Cursor literals
# -----------------------------------------------------------------------------

CURSOR_VERSION: Final[str] = "v1"
CURSOR_SEPARATOR: Final[str] = "."
CURSOR_SIGNATURE_LENGTH: Final[int] = 64


# -----------------------------------------------------------------------------
# Idempotency and request-context literals
# -----------------------------------------------------------------------------

ANONYMOUS_SUBJECT: Final[str] = "anonymous"
SYSTEM_ACTOR: Final[str] = "system"
UNKNOWN_ACTOR: Final[str] = "unknown"
UNKNOWN_ROLE: Final[str] = "UNKNOWN"


# -----------------------------------------------------------------------------
# Safe metadata helper
# -----------------------------------------------------------------------------


def get_constants_metadata() -> dict[str, Any]:
    """
    Return safe, serializable constants-layer metadata.

    This is useful for:

    - startup diagnostics;
    - architecture documentation checks;
    - tests;
    - developer tooling.

    It must not expose secrets, environment files, database URLs, tokens,
    passwords, raw complaint narratives, or real customer data.
    """
    return {
        "package": CORE_CONSTANTS_PACKAGE_NAME,
        "layer": CORE_LAYER,
        "contract_version": CONSTANTS_CONTRACT_VERSION,
        "project_name": PROJECT_NAME,
        "product_name": PRODUCT_NAME,
        "api_title": API_TITLE,
        "api_version": API_VERSION,
        "api_prefix": API_PREFIX,
        "data_classification": DATA_CLASSIFICATION,
        "synthetic_banner_text": SYNTHETIC_BANNER_TEXT,
        "product_safety_notice_count": len(PRODUCT_SAFETY_NOTICES),
        "base_caveat_count": len(BASE_CAVEATS),
        "sensitive_key_count": len(SENSITIVE_KEYS),
        "sensitive_key_token_count": len(SENSITIVE_KEY_TOKENS),
        "forbidden_response_key_count": len(FORBIDDEN_RESPONSE_KEYS),
        "audit_action_count": len(
            [
                name
                for name in globals()
                if name.startswith("AUDIT_ACTION_")
            ]
        ),
        "audit_resource_count": len(
            [
                name
                for name in globals()
                if name.startswith("AUDIT_RESOURCE_")
            ]
        ),
        "limits": {
            "max_string_length": MAX_STRING_LENGTH,
            "max_text_length": MAX_TEXT_LENGTH,
            "max_narrative_length": MAX_NARRATIVE_LENGTH,
            "max_list_length": MAX_LIST_LENGTH,
            "max_mapping_keys": MAX_MAPPING_KEYS,
            "max_json_depth": MAX_JSON_DEPTH,
            "max_request_body_mb": MAX_REQUEST_BODY_MB,
            "default_page_size": DEFAULT_PAGE_SIZE,
            "max_page_size": MAX_PAGE_SIZE,
            "hard_max_page_size": HARD_MAX_PAGE_SIZE,
            "default_top_limit": DEFAULT_TOP_LIMIT,
            "hard_top_limit": HARD_TOP_LIMIT,
            "default_window_days": DEFAULT_WINDOW_DAYS,
            "max_window_days": MAX_WINDOW_DAYS,
            "default_trend_buckets": DEFAULT_TREND_BUCKETS,
            "hard_trend_buckets": HARD_TREND_BUCKETS,
            "default_max_batch_size": DEFAULT_MAX_BATCH_SIZE,
            "hard_max_batch_size": HARD_MAX_BATCH_SIZE,
            "default_max_errors_returned": DEFAULT_MAX_ERRORS_RETURNED,
            "hard_max_errors_returned": HARD_MAX_ERRORS_RETURNED,
            "graph_hard_max_nodes": GRAPH_HARD_MAX_NODES,
            "graph_hard_max_edges": GRAPH_HARD_MAX_EDGES,
            "graph_hard_max_depth": GRAPH_HARD_MAX_DEPTH,
            "graph_hard_max_paths": GRAPH_HARD_MAX_PATHS,
            "graph_hard_max_trails": GRAPH_HARD_MAX_TRAILS,
            "report_hard_max_pages": REPORT_HARD_MAX_PAGES,
            "report_hard_max_items_per_section": REPORT_HARD_MAX_ITEMS_PER_SECTION,
            "report_hard_max_generation_seconds": REPORT_HARD_MAX_GENERATION_SECONDS,
            "export_hard_max_items": EXPORT_HARD_MAX_ITEMS,
            "search_max_query_length": SEARCH_MAX_QUERY_LENGTH,
        },
        "safety_flags": {
            "synthetic_first_by_default": True,
            "no_real_customer_data_by_default": True,
            "no_secret_logging": True,
            "no_token_logging": True,
            "no_password_logging": True,
            "no_stack_trace_leakage": True,
            "no_fake_functionality": True,
            "no_automatic_adverse_action": True,
            "deny_by_default_authorization": True,
            "utc_timestamps_required": True,
            "decimal_monetary_values_required": True,
            "bounded_pagination_required": True,
            "bounded_graph_queries_required": True,
            "evidence_backed_outputs_required": True,
            "explainable_scores_required": True,
            "audit_material_actions_required": True,
        },
    }


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------
# Dynamic __all__ avoids drift when constants are added or removed. It exports
# public immutable literals and locally defined helper functions only.

__all__: Final[tuple[str, ...]] = tuple(
    sorted(
        name
        for name, value in globals().items()
        if not name.startswith("_")
        and (
            isinstance(
                value,
                (
                    str,
                    int,
                    float,
                    tuple,
                    frozenset,
                    MappingProxyType,
                    datetime,
                    re.Pattern,
                ),
            )
            or (
                callable(value)
                and getattr(value, "__module__", None) == __name__
            )
        )
    )
)