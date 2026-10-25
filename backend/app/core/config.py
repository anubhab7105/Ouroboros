"""
MULEGUARD backend typed environment configuration.

This module defines the single source of truth for runtime settings. It loads
values from process environment variables and an optional local `.env` file,
normalizes types, and exposes safe helper methods used across the backend.

Design goals:

- provide typed, validated settings with safe local defaults;
- support comma-separated environment values for list fields;
- distinguish local, staging, and production-like environments;
- expose role-permission lists for RBAC;
- expose bounded limits for pagination, graph, ingestion, reports, and exports;
- never expose secrets through string representations;
- remain import-safe and dependency-light at package level.

Security and product-safety rules enforced or supported here:

- Placeholder secrets are detected and must be rejected in non-local
  environments by callers.
- Production-like environments are detected from BACKEND_ENV.
- Synthetic-first dataset mode is the default.
- Automatic adverse customer action is prohibited by default flags.
- Unbounded whole-bank graph queries are prohibited by default.
- Secrets, tokens, and passwords are never serialized by `repr` overrides.

Explicit non-goals:

- This module does not connect to secret managers.
- This module does not write environment files.
- This module does not claim production readiness.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Final, Optional

from pydantic import BeforeValidator, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: The `backend/` directory, i.e. the parent of the `app` package. Used to
#: anchor relative filesystem settings so they do not depend on the working
#: directory of whatever happened to start the process.
BACKEND_DIR: Final[Path] = Path(__file__).resolve().parents[2]

#: Matches `sqlite:///...`, `sqlite+pysqlite:///...` and friends, capturing the
#: scheme and the path separately.
_SQLITE_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<scheme>sqlite(?:\+[a-z0-9_]+)?):///(?P<path>.*)$",
    re.IGNORECASE,
)


def _anchor_sqlite_path(url: str) -> str:
    """
    Rewrite a relative SQLite URL so it points at `backend/<path>` regardless of
    the current working directory.

    A relative SQLite URL is resolved by the driver against the process's
    working directory, and the parts of this project do not share one:
    `alembic` and `uvicorn` run from `backend/`, while `scripts/*.py` run from
    the project root. `sqlite:///./var/muleguard.db` therefore means
    `backend/var/muleguard.db` to the server and `var/muleguard.db` to the
    scripts -- two different files.

    The failure mode is quiet and expensive. `scripts/create_dev_users.py`
    would create a second database, write the four accounts into it, report
    success, and leave every login against the real database returning 401.
    Nothing in either process is wrong on its own; only the pair is.

    Absolute paths, in-memory databases and non-SQLite URLs are returned
    unchanged.
    """
    match = _SQLITE_URL_RE.match(url)

    if match is None:
        return url

    raw_path = match.group("path")

    # `sqlite://`, `sqlite:///:memory:` and shared-cache memory URLs.
    if not raw_path or raw_path.startswith(":memory:") or "mode=memory" in raw_path:
        return url

    # Keep any query string (`?check_same_thread=...`) out of the path.
    path_part, separator, query = raw_path.partition("?")

    # POSIX absolute (`sqlite:////var/db`) or Windows absolute (`C:/...`).
    if path_part.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", path_part):
        return url

    resolved = (BACKEND_DIR / path_part.lstrip("./")).resolve()

    # Forward slashes work on every platform SQLAlchemy supports, and avoid a
    # backslash being read as an escape anywhere downstream.
    return f"{match.group('scheme')}:///{resolved.as_posix()}{separator}{query}"


# -----------------------------------------------------------------------------
# Value normalization helpers
# -----------------------------------------------------------------------------


def _split_csv(value: Any) -> list[str]:
    """
    Normalize a comma-separated environment value into a clean string list.
    """
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    text = str(value).strip()

    if not text:
        return []

    return [part.strip() for part in text.split(",") if part.strip()]


CsvList = Annotated[list[str], BeforeValidator(_split_csv)]


def _as_bool(value: Any) -> bool:
    """
    Normalize common truthy/falsy environment representations to bool.
    """
    if isinstance(value, bool):
        return value

    if value is None:
        return False

    if isinstance(value, int):
        return bool(value)

    text = str(value).strip().lower()

    if text in {"1", "true", "yes", "y", "on", "t"}:
        return True

    if text in {"0", "false", "no", "n", "off", "f", ""}:
        return False

    return False


_PLACEHOLDER_MARKERS: Final[tuple[str, ...]] = (
    "change_me",
    "changeme",
    "placeholder",
    "replace_me",
    "replace-me",
    "your_",
    "example_",
    "todo",
    "fixme",
)


# -----------------------------------------------------------------------------
# Settings
# -----------------------------------------------------------------------------


class Settings(BaseSettings):
    """
    Typed MULEGUARD backend settings.

    Field names map directly to environment variable names. Extra environment
    variables are ignored to keep startup resilient.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        # Every list-valued setting in this class is a `CsvList`, read from a
        # comma-separated environment value -- `a,b,c`, which is how these are
        # written in .env and in every deployment manifest.
        #
        # pydantic-settings decides a field is "complex" from its annotation,
        # sees `list[str]`, and tries `json.loads` on the raw string inside the
        # settings SOURCE, before any validator runs. `localhost,127.0.0.1` is
        # not JSON, so it raises
        #
        #   SettingsError: error parsing value for field
        #   "BACKEND_ALLOWED_HOSTS" from source "DotEnvSettingsSource"
        #
        # and the `BeforeValidator` attached to CsvList never gets a chance,
        # because validation is a later stage than source decoding. The first
        # CsvList field in the file is the one named in the error; there are 48
        # of them, so fixing them one at a time is not a fix.
        #
        # `enable_decoding=False` turns off that JSON step and hands the raw
        # string to validation, which is where `_split_csv` already handles
        # strings, lists, tuples, sets and None. Safe here because no setting
        # in this class is a dict or a nested model -- nothing needs JSON.
        # Added in pydantic-settings 2.3; requirements pin >=2.4.
        enable_decoding=False,
    )

    # ------------------------------------------------------------------
    # Application runtime
    # ------------------------------------------------------------------
    BACKEND_APP_NAME: str = "MULEGUARD"
    BACKEND_APP_MODULE: str = "app.main:app"
    BACKEND_ENV: str = "local"
    BACKEND_DEBUG: bool = False
    BACKEND_SAFE_MODE: bool = True
    BACKEND_STRICT_CONFIG: bool = True
    BACKEND_TIMEZONE: str = "UTC"
    BACKEND_DEFAULT_LOCALE: str = "en"
    BACKEND_DEFAULT_CURRENCY: str = "INR"
    BACKEND_DATASET_MODE: str = "synthetic"
    BACKEND_SYNTHETIC_BANNER_TEXT: str = "SYNTHETIC DEMO DATA"
    BACKEND_API_PREFIX: str = "/api/v1"
    BACKEND_PUBLIC_URL: str = "http://localhost:8000"
    BACKEND_INTERNAL_URL: str = "http://backend:8000"
    BACKEND_ROOT_PATH: str = ""
    BACKEND_ALLOWED_HOSTS: CsvList = Field(default_factory=lambda: ["localhost", "127.0.0.1", "backend"])
    BACKEND_TRUST_PROXY_HEADERS: bool = False
    BACKEND_FORWARDED_ALLOW_IPS: str = ""
    BACKEND_REQUEST_TIMEOUT_SECONDS: int = 60
    BACKEND_MAX_REQUEST_BODY_MB: int = 10
    BACKEND_WORKERS: int = 1
    BACKEND_KEEP_ALIVE_TIMEOUT_SECONDS: int = 5
    BACKEND_GRACEFUL_TIMEOUT_SECONDS: int = 20
    BACKEND_LIFESPAN_STARTUP_TIMEOUT_SECONDS: int = 120
    BACKEND_LIFESPAN_SHUTDOWN_TIMEOUT_SECONDS: int = 30
    BACKEND_VALIDATE_ENV_ON_STARTUP: bool = True
    BACKEND_BLOCK_REAL_DATA_IF_SYNTHETIC_ONLY: bool = True
    BACKEND_BLOCK_DEMO_FEATURES_IN_PRODUCTION: bool = True
    BACKEND_BLOCK_SEEDING_IN_PRODUCTION: bool = True
    BACKEND_BLOCK_OPENAPI_IN_PRODUCTION: bool = True
    BACKEND_BLOCK_DEV_USERS_IN_PRODUCTION: bool = True
    BACKEND_REQUIRE_STRONG_SECRET_IN_NON_LOCAL: bool = True
    BACKEND_PRODUCTION_LIKE_ENVS: CsvList = Field(
        default_factory=lambda: ["production", "staging", "prod", "stage"]
    )

    # ------------------------------------------------------------------
    # Build / service metadata
    # ------------------------------------------------------------------
    SERVICE_NAME: str = "muleguard-backend"
    SERVICE_VERSION: str = "0.1.0"
    BUILD_VERSION: str = "0.1.0"
    BUILD_COMMIT: str = "unknown"
    BUILD_TIME: str = "unknown"
    BUILD_BRANCH: str = "unknown"

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------
    VAR_DIR: str = "var"
    LOG_DIR: str = "var/logs"
    TMP_DIR: str = "var/tmp"
    CACHE_DIR: str = "var/cache"
    REPORT_OUTPUT_DIR: str = "var/reports"
    ML_ARTIFACT_DIR: str = "app/ml/artifacts"
    CONFIG_DIR: str = "config"
    MIGRATION_DIR: str = "migrations"

    # ------------------------------------------------------------------
    # Logging and observability
    # ------------------------------------------------------------------
    BACKEND_LOG_LEVEL: str = "INFO"
    BACKEND_LOG_FORMAT: str = "console"
    BACKEND_LOG_JSON: bool = False
    BACKEND_LOG_TO_FILE: bool = False
    BACKEND_LOG_FILE: str = "var/logs/backend.log"
    BACKEND_LOG_REQUEST_BODY: bool = False
    BACKEND_LOG_RESPONSE_BODY: bool = False
    BACKEND_LOG_SQL: bool = False
    BACKEND_LOG_MASK_PII: bool = True
    BACKEND_MAX_NARRATIVE_LOG_CHARS: int = 200
    OTEL_ENABLED: bool = False
    PROMETHEUS_ENABLED: bool = False

    # ------------------------------------------------------------------
    # Server / ASGI
    # ------------------------------------------------------------------
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    SERVER_PORT: int = 8000
    API_DOCS_ENABLED: bool = True
    BACKEND_DOCS_ENABLED: bool = True
    BACKEND_OPENAPI_ENABLED: bool = True
    OPENAPI_TITLE: str = "MULEGUARD API"
    OPENAPI_VERSION: str = "v1"
    OPENAPI_PATH: str = "/api/v1/openapi.json"

    # ------------------------------------------------------------------
    # Security headers / CORS
    # ------------------------------------------------------------------
    SECURE_HEADERS_ENABLED: bool = True
    SECURE_HEADERS_APPLY_TO_ERRORS: bool = True
    SECURE_HEADERS_REMOVE_SERVER: bool = True
    SECURE_HEADERS_REMOVE_X_POWERED_BY: bool = True
    X_CONTENT_TYPE_OPTIONS: str = "nosniff"
    X_FRAME_OPTIONS: str = "DENY"
    REFERRER_POLICY: str = "no-referrer"
    # The security-headers middleware reads each of the settings below by
    # name. They are declared here because this model is configured with
    # `extra="ignore"`: a name the middleware reads but the model does not
    # declare is silently dropped from the environment, so the knob looks
    # configurable and does nothing. HSTS could be switched on without being
    # given a max-age, and CSP could be switched on with nowhere to send
    # reports. The defaults match the middleware's own.
    HSTS_ENABLED: bool = False
    HSTS_MAX_AGE: int = 31_536_000
    HSTS_INCLUDE_SUBDOMAINS: bool = True
    HSTS_PRELOAD: bool = False
    CSP_ENABLED: bool = False
    CSP_DOCS_EXEMPT: bool = True
    CSP_DOCS_RELAXED: bool = True
    CSP_DOCS_ALLOW_UNSAFE_EVAL: bool = False
    CSP_REPORT_ONLY: bool = False
    CSP_REPORT_URI: str = ""
    # The per-directive settings default to None, not "". The middleware
    # treats None as "keep the baseline directive" and an empty string as
    # "remove this directive", so declaring these as empty strings would strip
    # every directive from the policy the moment CSP was switched on.
    CSP_DEFAULT_SRC: Optional[str] = None
    CSP_SCRIPT_SRC: Optional[str] = None
    CSP_STYLE_SRC: Optional[str] = None
    CSP_IMG_SRC: Optional[str] = None
    CSP_FONT_SRC: Optional[str] = None
    CSP_CONNECT_SRC: Optional[str] = None
    CSP_MEDIA_SRC: Optional[str] = None
    CSP_OBJECT_SRC: Optional[str] = None
    CSP_FRAME_SRC: Optional[str] = None
    CSP_FRAME_ANCESTORS: Optional[str] = None
    CSP_BASE_URI: Optional[str] = None
    CSP_FORM_ACTION: Optional[str] = None
    CSP_MANIFEST_SRC: Optional[str] = None
    CSP_WORKER_SRC: Optional[str] = None
    CSP_SANDBOX: Optional[str] = None
    CSP_UPGRADE_INSECURE_REQUESTS: Optional[str] = None
    CSP_BLOCK_ALL_MIXED_CONTENT: Optional[str] = None
    PERMISSIONS_POLICY: str = (
        "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    )
    COOP_ENABLED: bool = True
    COOP: str = "same-origin"
    COEP_ENABLED: bool = False
    COEP: str = "require-corp"
    CORP_ENABLED: bool = True
    CORP: str = "same-origin"
    VARY_HEADER: str = ""
    # Successful API responses carry no Cache-Control unless this is turned
    # on. Errors and authentication responses always do.
    SECURE_HEADERS_NO_STORE_FOR_API: bool = False
    SECURE_HEADERS_NO_STORE_FOR_AUTH: bool = True
    SECURE_HEADERS_NO_STORE_FOR_ERRORS: bool = True
    CORS_ENABLED: bool = True
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: CsvList = Field(
        default_factory=lambda: ["GET", "POST", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    )
    CORS_ALLOW_HEADERS: CsvList = Field(
        default_factory=lambda: [
            "Authorization",
            "Content-Type",
            "X-Request-ID",
            "X-Correlation-ID",
            "Idempotency-Key",
            "X-CSRF-Token",
        ]
    )
    CORS_EXPOSE_HEADERS: CsvList = Field(
        default_factory=lambda: ["X-Request-ID", "X-Correlation-ID", "X-Response-Time"]
    )
    CORS_MAX_AGE_SECONDS: int = 600
    BACKEND_CORS_ORIGINS: CsvList = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://localhost:4173",
            "http://localhost:8080",
        ]
    )

    # ------------------------------------------------------------------
    # Secrets
    # ------------------------------------------------------------------
    BACKEND_SECRET_KEY: str = "CHANGE_ME_GENERATE_WITH_openssl_rand_hex_64"

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    # Defaults to SQLite under `backend/var/`, so the application starts on a
    # machine with no database server. PostgreSQL is the source of truth for
    # anything deployed, and `app/db.py` refuses SQLite when BACKEND_ENV is
    # production-like, so the safe default cannot quietly reach production.
    #
    # A PostgreSQL default here was worse than it looks: an unset or truncated
    # .env produced `connection to server at "localhost", port 5432 failed:
    # Connection refused`, which describes the symptom and gives no hint that
    # the cause is a missing setting rather than a missing server.
    DATABASE_URL: str = "sqlite+pysqlite:///./var/muleguard.db"
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT_SECONDS: float = 30.0
    DB_POOL_RECYCLE_SECONDS: int = 1800
    DB_POOL_PRE_PING: bool = True
    DB_CONNECT_TIMEOUT_SECONDS: float = 10.0
    DB_STATEMENT_TIMEOUT_MS: int = 15000
    DB_LOCK_TIMEOUT_SECONDS: int = 10
    DB_APPLICATION_NAME: str = "muleguard-backend"
    DB_DEFAULT_TIMEZONE: str = "UTC"
    DB_AUTO_COMMIT_ON_REQUEST_SUCCESS: bool = False
    DB_ALLOW_SQLITE_IN_PRODUCTION: bool = False
    BACKEND_ALLOW_SQLITE_FOR_LOCAL_DEV: bool = True
    SQLITE_FOREIGN_KEYS: bool = True
    SQLITE_BUSY_TIMEOUT: int = 5000
    SQLITE_JOURNAL_MODE: str = "WAL"
    SQLITE_SYNCHRONOUS: str = "NORMAL"
    SQLITE_TEMP_STORE: str = "MEMORY"
    SQLITE_CACHE_SIZE_MB: int = 64
    POSTGRES_SSL_MODE: str = ""
    STARTUP_CHECK_DB: bool = True
    HEALTH_FAIL_ON_DB_UNAVAILABLE: bool = True

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    AUTH_ENABLED: bool = True
    AUTH_MODE: str = "jwt_bearer"
    AUTH_ALGORITHM: str = "HS256"
    AUTH_ISSUER: Optional[str] = "muleguard.local"
    AUTH_AUDIENCE: Optional[str] = "muleguard-client"
    AUTH_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    AUTH_CLOCK_SKEW_SECONDS: int = 30
    AUTH_JTI_CLAIM_ENABLED: bool = True
    AUTH_INCLUDE_ROLES_IN_TOKEN: bool = False
    AUTH_USE_COOKIES: bool = False
    AUTH_COOKIE_NAME: str = "muleguard_auth"
    AUTH_ALLOW_UNAUTHENTICATED_LOCAL: bool = False
    AUTH_DISABLED_ROLE: str = "ANALYST"
    AUTH_DEMO_MODE: bool = False
    AUTH_TOKEN_SCHEME: str = "Bearer"
    AUTH_TOKEN_REVOCATION_ENABLED: bool = False
    AUTH_MAX_TOKEN_LENGTH: int = 8192

    # Password hashing
    AUTH_PASSWORD_HASH_SCHEME: str = "argon2id"
    AUTH_PASSWORD_MIN_LENGTH: int = 12
    AUTH_PASSWORD_MAX_LENGTH: int = 128
    AUTH_PASSWORD_REQUIRE_LOWERCASE: bool = True
    AUTH_PASSWORD_REQUIRE_UPPERCASE: bool = True
    AUTH_PASSWORD_REQUIRE_DIGIT: bool = True
    AUTH_PASSWORD_REQUIRE_SPECIAL: bool = True
    AUTH_PASSWORD_REQUIRE_NO_SPACES: bool = False
    AUTH_ARGON2_TIME_COST: int = 3
    AUTH_ARGON2_MEMORY_COST_KIB: int = 65536
    AUTH_ARGON2_PARALLELISM: int = 2
    AUTH_BCRYPT_ROUNDS: int = 12
    AUTH_PBKDF2_ITERATIONS: int = 390_000
    AUTH_PASSWORD_UPGRADE_TO_ARGON2: bool = True

    # Login throttling / lockout
    AUTH_RATE_LIMIT_ENABLED: bool = True
    AUTH_LOGIN_MAX_ATTEMPTS: int = 5
    AUTH_LOGIN_LOCKOUT_MINUTES: int = 15
    AUTH_LOGIN_ATTEMPT_WINDOW_MINUTES: int = 15
    AUTH_LOGIN_RESET_ON_SUCCESS: bool = True
    AUTH_REVEAL_LOCKED_ACCOUNT: bool = False
    AUTH_REVEAL_INACTIVE_ACCOUNT: bool = False
    AUTH_RATE_LIMIT_LOGIN: str = "5/minute"
    AUTH_RATE_LIMIT_GLOBAL: str = "300/minute"
    AUTH_RATE_LIMIT_ANALYSIS: str = "5/minute"
    AUTH_RATE_LIMIT_GRAPH: str = "60/minute"
    AUTH_RATE_LIMIT_REPORT: str = "10/minute"
    AUTH_RATE_LIMIT_INGESTION: str = "10/minute"
    AUTH_RATE_LIMIT_KEY_SALT: Optional[str] = None

    # ------------------------------------------------------------------
    # RBAC
    # ------------------------------------------------------------------
    RBAC_ENABLED: bool = True
    RBAC_DENY_BY_DEFAULT: bool = True
    RBAC_SUPERUSER_BYPASS: bool = False
    RBAC_DENY_UNKNOWN_ROLE: bool = True

    USER_MANAGEMENT_ROLES: CsvList = Field(default_factory=lambda: ["ADMIN"])
    ANALYSIS_RUN_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    INGESTION_RUN_ROLES: CsvList = Field(default_factory=lambda: ["ADMIN"])
    SEED_RESET_ROLES: CsvList = Field(default_factory=lambda: ["ADMIN"])
    CASE_READ_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    CASE_CREATE_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    CASE_UPDATE_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    CASE_ASSIGN_ROLES: CsvList = Field(
        default_factory=lambda: ["SENIOR_INVESTIGATOR", "ADMIN"]
    )
    CASE_CLOSE_ROLES: CsvList = Field(
        default_factory=lambda: ["SENIOR_INVESTIGATOR", "ADMIN"]
    )
    CASE_REOPEN_ROLES: CsvList = Field(
        default_factory=lambda: ["SENIOR_INVESTIGATOR", "ADMIN"]
    )
    CASE_NOTE_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    CASE_EVIDENCE_ADD_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    CASE_EVIDENCE_REMOVE_ROLES: CsvList = Field(
        default_factory=lambda: ["SENIOR_INVESTIGATOR", "ADMIN"]
    )
    CASE_ASSIGNABLE_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    ALERT_READ_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    ALERT_TRIAGE_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    ALERT_ASSIGN_ROLES: CsvList = Field(
        default_factory=lambda: ["SENIOR_INVESTIGATOR", "ADMIN"]
    )
    ALERT_ESCALATION_ROLES: CsvList = Field(
        default_factory=lambda: ["SENIOR_INVESTIGATOR", "ADMIN"]
    )
    ALERT_CASE_CREATE_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    REPORT_READ_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    REPORT_GENERATE_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    REPORT_DOWNLOAD_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    AUDIT_READ_ROLES: CsvList = Field(default_factory=lambda: ["AUDITOR", "ADMIN"])
    AUDIT_EXPORT_ROLES: CsvList = Field(default_factory=lambda: ["ADMIN"])
    GRAPH_READ_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    GRAPH_EXPORT_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN"]
    )
    COMPLAINT_READ_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    COMPLAINT_REVIEW_ROLES: CsvList = Field(
        default_factory=lambda: ["SENIOR_INVESTIGATOR", "ADMIN"]
    )
    COMPLAINT_NARRATIVE_ACCESS_ROLES: CsvList = Field(
        default_factory=lambda: ["SENIOR_INVESTIGATOR", "ADMIN"]
    )
    MODEL_MONITOR_READ_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    MODEL_TRAIN_ROLES: CsvList = Field(default_factory=lambda: ["ADMIN"])
    MODEL_EVALUATE_ROLES: CsvList = Field(default_factory=lambda: ["ADMIN"])
    DASHBOARD_READ_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    ACCOUNT_READ_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    TRANSACTION_READ_ROLES: CsvList = Field(
        default_factory=lambda: ["ANALYST", "SENIOR_INVESTIGATOR", "ADMIN", "AUDITOR"]
    )
    CONFIG_READ_ROLES: CsvList = Field(default_factory=lambda: ["ADMIN"])
    CONFIG_WRITE_ROLES: CsvList = Field(default_factory=lambda: ["ADMIN"])

    # ------------------------------------------------------------------
    # Development users / seeding
    # ------------------------------------------------------------------
    SEED_DEV_USERS: bool = True
    DEV_USERS_REQUIRE_PASSWORD_FROM_ENV: bool = True
    DEV_USERS_FORCE_PASSWORD_RESET: bool = False
    DEV_USERS_REQUIRE_PASSWORD_CHANGE: bool = False
    DEV_USERS_EMAIL_DOMAIN_ALLOWLIST: CsvList = Field(
        default_factory=lambda: ["muleguard.local"]
    )
    DEV_ADMIN_USERNAME: str = "admin"
    DEV_ADMIN_EMAIL: str = "admin@muleguard.local"
    DEV_ADMIN_PASSWORD: str = ""
    DEV_ANALYST_USERNAME: str = "analyst"
    DEV_ANALYST_EMAIL: str = "analyst@muleguard.local"
    DEV_ANALYST_PASSWORD: str = ""
    DEV_SENIOR_INVESTIGATOR_USERNAME: str = "senior_investigator"
    DEV_SENIOR_INVESTIGATOR_EMAIL: str = "senior@muleguard.local"
    DEV_SENIOR_INVESTIGATOR_PASSWORD: str = ""
    DEV_AUDITOR_USERNAME: str = "auditor"
    DEV_AUDITOR_EMAIL: str = "auditor@muleguard.local"
    DEV_AUDITOR_PASSWORD: str = ""

    SEED_DEMO_DATA: bool = True
    SEED_RANDOM_SEED: int = 42
    SEED_ACCOUNTS: int = 1200
    SEED_TRANSACTIONS: int = 25000
    SEED_COMPLAINTS: int = 150
    SEED_ENTITY_LINKS: int = 400
    SEED_FRAUD_SCENARIOS: int = 12
    SEED_LARGE_DATASET: bool = False
    SEED_RESET_REQUIRES_CONFIRM_PHRASE: bool = True
    SEED_RESET_ALLOW_DEMO_ONLY: bool = True
    SEED_RESET_BLOCK_PRODUCTION: bool = True
    DB_RESET_CONFIRM_PHRASE: str = "RESET_SYNTHETIC_DEMO"

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    INGESTION_ENABLED: bool = True
    INGESTION_API_ENABLED: bool = True
    INGESTION_REQUIRE_SYNTHETIC: bool = True
    INGESTION_ALLOW_IN_PRODUCTION: bool = False
    INGESTION_MAX_BATCH_SIZE: int = 1000
    INGESTION_HARD_MAX_BATCH_SIZE: int = 10_000
    INGESTION_MAX_ERRORS_RETURNED: int = 100
    INGESTION_HARD_MAX_ERRORS_RETURNED: int = 500
    INGESTION_ALLOW_PARTIAL_BATCH: bool = False
    INGESTION_DUPLICATE_STRATEGY: str = "reject"
    INGESTION_FUTURE_TOLERANCE_MINUTES: int = 5
    INGESTION_TRANSACTIONAL_BATCH: bool = True

    # ------------------------------------------------------------------
    # Feature engine
    # ------------------------------------------------------------------
    FEATURE_ENGINE_ENABLED: bool = True
    FEATURE_VERSION: str = "v1"
    FEATURE_STRICT_POINT_IN_TIME: bool = True
    FEATURE_WINDOWS: CsvList = Field(default_factory=lambda: ["1h", "24h", "7d", "30d"])
    FEATURE_ALLOW_LABELS_IN_EXPORT: bool = False
    FEATURE_ALLOW_FUTURE_TRANSACTIONS: bool = False
    FEATURE_ALLOW_FUTURE_COMPLAINTS: bool = False
    FEATURE_ALLOW_FUTURE_INVESTIGATION_OUTCOMES: bool = False

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------
    RULES_ENABLED: bool = True
    RULES_VERSION: str = "v1"
    RULES_CONFIG_PATH: str = "config/rules.default.json"

    # ------------------------------------------------------------------
    # Graph
    # ------------------------------------------------------------------
    GRAPH_ENABLED: bool = True
    GRAPH_REQUIRE_ROOT: bool = True
    GRAPH_ALLOW_WHOLE_BANK_QUERY: bool = False
    GRAPH_MAX_HOPS: int = 3
    GRAPH_MAX_NODES: int = 500
    GRAPH_MAX_EDGES: int = 1500
    GRAPH_MAX_PATHS: int = 20
    GRAPH_MAX_DATE_SPAN_DAYS: int = 90
    GRAPH_TIMEOUT_SECONDS: int = 15
    GRAPH_MAX_DEPTH: int = 3
    GRAPH_MAX_TRAILS: int = 25
    GRAPH_MAX_SHARED_GROUPS: int = 25
    GRAPH_MAX_ACCOUNTS_PER_ENTITY: int = 25
    GRAPH_HARD_MAX_NODES: int = 1000
    GRAPH_HARD_MAX_EDGES: int = 2000
    GRAPH_HARD_MAX_DEPTH: int = 5
    GRAPH_HARD_MAX_PATHS: int = 100
    GRAPH_HARD_MAX_TRAILS: int = 100
    GRAPH_HARD_MAX_SHARED_GROUPS: int = 100
    GRAPH_HARD_MAX_ACCOUNTS_PER_ENTITY: int = 100
    GRAPH_HARD_MAX_DATE_SPAN_DAYS: int = 3650
    MONEY_TRAIL_ENABLED: bool = True
    ENTITIES_API_ENABLED: bool = True

    # ------------------------------------------------------------------
    # Complaints
    # ------------------------------------------------------------------
    COMPLAINT_ENGINE_ENABLED: bool = True
    COMPLAINTS_API_ENABLED: bool = True
    COMPLAINT_STATS_ENABLED: bool = True
    COMPLAINT_REVIEW_ENABLED: bool = True
    COMPLAINT_MAX_DATE_SPAN_DAYS: int = 3650
    COMPLAINT_STATS_DEFAULT_DAYS: int = 30
    COMPLAINT_EXPORT_MAX_ITEMS: int = 200
    COMPLAINT_EXPORT_HARD_MAX_ITEMS: int = 1000

    # ------------------------------------------------------------------
    # ML
    # ------------------------------------------------------------------
    ML_ENABLED: bool = True
    ML_VERSION: str = "v1"
    ML_ACTIVE_SCORING_MODE: str = "auto"
    ML_FALLBACK_MODE_LABEL: str = "heuristic_fallback"
    ML_REQUIRE_TRAINED_MODEL: bool = False
    ML_ACTIVE_MODEL_VERSION: Optional[str] = None
    ML_FEATURE_SCHEMA_VERSION: str = "v1"
    ML_FORBIDDEN_FEATURE_FIELDS: CsvList = Field(
        default_factory=lambda: [
            "fraud_label",
            "scenario_id",
            "ground_truth_label",
            "ring_id",
            "label",
            "is_fraud",
        ]
    )
    ML_ARTIFACT_TRUSTED_PATH_ONLY: bool = True
    ML_DISABLE_UNTRUSTED_PICKLE_UPLOADS: bool = True
    ML_LABEL_LEAKAGE_CHECK: bool = True
    ML_WARN_ON_MISSING_ML_ARTIFACT: bool = True

    # ------------------------------------------------------------------
    # Risk fusion
    # ------------------------------------------------------------------
    RISK_FUSION_ENABLED: bool = True
    RISK_SCORE_VERSION: str = "v1"
    RISK_WEIGHT_SUPERVISED: float = 0.35
    RISK_WEIGHT_ANOMALY: float = 0.25
    RISK_WEIGHT_GRAPH: float = 0.20
    RISK_WEIGHT_RULES: float = 0.20

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    ALERT_ENGINE_ENABLED: bool = True
    ALERTS_API_ENABLED: bool = True
    ALERT_DEDUPLICATION_ENABLED: bool = True
    ALERT_DEDUPLICATION_WINDOW_HOURS: int = 24
    ALERT_MAX_DATE_SPAN_DAYS: int = 3650

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    ANALYSIS_ENABLED: bool = True
    ANALYSIS_MAX_ACCOUNTS: int = 1000
    ANALYSIS_HARD_MAX_ACCOUNTS: int = 50_000
    ANALYSIS_ALLOW_ALL_ACCOUNTS: bool = False
    ANALYSIS_MAX_DATE_SPAN_DAYS: int = 3650
    ANALYSIS_REQUIRE_SYNTHETIC_DATA: bool = True
    ANALYSIS_SERVICE_MODULE: Optional[str] = None
    ANALYSIS_REQUIRE_IDEMPOTENCY_KEY: bool = False

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------
    CASE_ENGINE_ENABLED: bool = True
    CASES_API_ENABLED: bool = True
    CASE_DEFAULT_STATUS: str = "NEW"
    # These must be members of `app.models.Disposition`, because the case
    # table's disposition column is declared over that enum. A label outside
    # it cannot be stored, so configuring one would only produce a failure at
    # closure time.
    CASE_DISPOSITIONS: CsvList = Field(
        default_factory=lambda: [
            "CONFIRMED_FRAUD",
            "FALSE_POSITIVE",
            "INCONCLUSIVE",
            "REFERRED",
        ]
    )
    CASE_MAX_DATE_SPAN_DAYS: int = 3650
    CASE_DETAIL_MAX_ITEMS: int = 50
    CASE_DETAIL_HARD_MAX_ITEMS: int = 200
    CASE_EXPORT_MAX_ITEMS: int = 200
    CASE_EXPORT_HARD_MAX_ITEMS: int = 1000

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    AUDIT_ENABLED: bool = True
    AUDIT_API_ENABLED: bool = True
    AUDIT_EXPORT_ENABLED: bool = True
    AUDIT_REDACTION_ENABLED: bool = True
    PRIVACY_AUDIT_REDACTION_ENABLED: bool = True
    AUDIT_LOG_DENIED: bool = True
    RETENTION_AUDIT_DAYS: int = 3650
    AUDIT_MAX_DATE_SPAN_DAYS: int = 365
    AUDIT_EXPORT_MAX_ROWS: int = 10_000
    AUDIT_EXPORT_HARD_MAX_ROWS: int = 100_000
    AUDIT_STATS_DEFAULT_DAYS: int = 30

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    REPORT_ENABLED: bool = True
    REPORT_API_ENABLED: bool = True
    REPORT_ENGINE: str = "reportlab"
    REPORT_TIMEZONE: str = "UTC"
    REPORT_MAX_GENERATION_SECONDS: int = 30
    REPORT_MAX_PAGES: int = 40
    REPORT_HARD_MAX_PAGES: int = 200
    REPORT_MAX_ITEMS_PER_SECTION: int = 50
    REPORT_HARD_MAX_ITEMS_PER_SECTION: int = 500
    REPORT_FILENAME_PREFIX: str = "muleguard-case-report"
    REPORT_INCLUDE_SYNTHETIC_DISCLAIMER: bool = True
    REPORT_INCLUDE_LIMITATIONS: bool = True
    REPORT_INCLUDE_EVIDENCE_INDEX: bool = True
    REPORT_AUDIT_GENERATION: bool = True
    REPORT_AUDIT_PREVIEW: bool = False
    REPORT_DISCLAIMER_TEXT: str = (
        "SYNTHETIC DEMO REPORT. Generated from synthetic prototype data. "
        "Not a real investigation. Not proof of fraud or wrongdoing."
    )
    REPORT_LIMITATIONS_TEXT: str = (
        "This report is generated from synthetic prototype data by MULEGUARD. "
        "Alerts, risk scores, graph relationships, candidate money trails, "
        "entity links, and complaint correlations are investigative leads only "
        "and are not evidence of wrongdoing."
    )
    REPORT_FOOTER_TEXT: str = (
        "Synthetic prototype only. Investigative leads, not proof of wrongdoing."
    )

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    DASHBOARD_ENABLED: bool = True
    DASHBOARD_API_ENABLED: bool = True
    DASHBOARD_DEFAULT_WINDOW_DAYS: int = 30
    DASHBOARD_MAX_DATE_SPAN_DAYS: int = 365
    DASHBOARD_HARD_MAX_DATE_SPAN_DAYS: int = 3650
    DASHBOARD_MAX_TREND_BUCKETS: int = 90
    DASHBOARD_HARD_MAX_TREND_BUCKETS: int = 366
    DASHBOARD_TOP_LIMIT_DEFAULT: int = 10
    DASHBOARD_TOP_LIMIT_MAX: int = 50

    # ------------------------------------------------------------------
    # Accounts / transactions API
    # ------------------------------------------------------------------
    ACCOUNTS_API_ENABLED: bool = True
    TRANSACTIONS_API_ENABLED: bool = True
    ACCOUNT_SUMMARY_MAX_DATE_SPAN_DAYS: int = 90
    TRANSACTION_MAX_DATE_SPAN_DAYS: int = 3650

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------
    PAGINATION_DEFAULT_PAGE_SIZE: int = 50
    PAGINATION_MAX_PAGE_SIZE: int = 200

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------
    SEARCH_MAX_QUERY_LENGTH: int = 200

    # ------------------------------------------------------------------
    # Privacy / PII
    # ------------------------------------------------------------------
    PRIVACY_MODE: str = "synthetic_prototype"
    PRIVACY_REAL_DATA_PRESENT: bool = False
    PRIVACY_CUSTOMER_DATA_PRESENT: bool = False
    PRIVACY_IP_LOG_MODE: str = "hashed"
    PRIVACY_IP_HASH_SALT: Optional[str] = None

    # ------------------------------------------------------------------
    # Performance middleware
    # ------------------------------------------------------------------
    PERFORMANCE_MIDDLEWARE_ENABLED: bool = True
    PERFORMANCE_SLOW_REQUEST_THRESHOLD_MS: int = 2000
    PERFORMANCE_INCLUDE_RESPONSE_TIME_HEADER: bool = True
    PERFORMANCE_RESPONSE_TIME_HEADER: str = "X-Response-Time"
    PERFORMANCE_LOG_SLOW_REQUESTS: bool = True
    PERFORMANCE_LOG_ERRORS: bool = True
    PERFORMANCE_LOG_ALL_REQUESTS: bool = False
    PERFORMANCE_METRICS_ENABLED: bool = True
    PERFORMANCE_METRICS_MAX_ROUTES: int = 256
    PERFORMANCE_METRICS_LATENCY_SAMPLES_PER_ROUTE: int = 256

    # ------------------------------------------------------------------
    # Request ID middleware
    # ------------------------------------------------------------------
    REQUEST_ID_MIDDLEWARE_ENABLED: bool = True
    REQUEST_ID_HEADER: str = "X-Request-ID"
    CORRELATION_ID_HEADER: str = "X-Correlation-ID"
    REQUEST_ID_GENERATE_IF_MISSING: bool = True
    REQUEST_ID_VALIDATE_INBOUND: bool = True

    # ------------------------------------------------------------------
    # Runtime config endpoint
    # ------------------------------------------------------------------
    RUNTIME_CONFIG_ENDPOINT_ENABLED: bool = True

    # ------------------------------------------------------------------
    # API v1 router behaviour
    # ------------------------------------------------------------------
    API_V1_STRICT_REQUIRED_ENDPOINTS: Optional[bool] = None
    API_V1_METADATA_ENDPOINT_ENABLED: Optional[bool] = None

    # ------------------------------------------------------------------
    # Dangerous feature flags that must remain false
    # ------------------------------------------------------------------
    AUTOMATIC_ENFORCEMENT_ENABLED: bool = False
    AUTO_FREEZE_ENABLED: bool = False
    AUTO_BLOCK_PAYMENT_ENABLED: bool = False
    AUTO_BLACKLIST_ENABLED: bool = False
    ADVERSE_ACTION_AUTOMATION_ENABLED: bool = False
    DEANONYMISATION_ENABLED: bool = False
    SURVEILLANCE_ENABLED: bool = False
    COVERT_MONITORING_ENABLED: bool = False
    USER_UPLOADED_MODEL_ENABLED: bool = False
    PICKLE_UNSAFE_LOAD_ENABLED: bool = False
    XML_EXTERNAL_ENTITIES_ENABLED: bool = False
    YAML_UNSAFE_LOAD_ENABLED: bool = False
    REMOTE_DEBUGGING_ENABLED: bool = False
    DEBUGPY_ENABLED: bool = False
    OUTBOUND_NETWORK_ENABLED: bool = False
    FILE_UPLOAD_ENABLED: bool = False

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("BACKEND_ENV", mode="before")
    @classmethod
    def _normalize_env(cls, value: Any) -> str:
        return str(value or "local").strip().lower()

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def _normalize_database_url(cls, value: Any) -> str:
        text = str(value or "").strip()

        if not text:
            return "sqlite+pysqlite:///./var/muleguard.db"

        return _anchor_sqlite_path(text)

    @field_validator("BACKEND_DATASET_MODE", mode="before")
    @classmethod
    def _normalize_dataset_mode(cls, value: Any) -> str:
        return str(value or "synthetic").strip().lower()

    @field_validator("AUTH_MODE", mode="before")
    @classmethod
    def _normalize_auth_mode(cls, value: Any) -> str:
        return str(value or "jwt_bearer").strip().lower()

    @field_validator("AUTH_ALGORITHM", mode="before")
    @classmethod
    def _normalize_auth_algorithm(cls, value: Any) -> str:
        return str(value or "HS256").strip().upper()

    @field_validator("INGESTION_DUPLICATE_STRATEGY", mode="before")
    @classmethod
    def _normalize_duplicate_strategy(cls, value: Any) -> str:
        text = str(value or "reject").strip().lower()
        return text if text in {"reject", "skip"} else "reject"

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def is_production_like(self) -> bool:
        """
        Return True when the runtime environment is production-like.
        """
        env = self.BACKEND_ENV.strip().lower()
        production_like_values = {
            value.strip().lower() for value in self.BACKEND_PRODUCTION_LIKE_ENVS if value.strip()
        }

        if not production_like_values:
            production_like_values = {"production", "staging", "prod", "stage"}

        return env in production_like_values

    def is_local(self) -> bool:
        """
        Return True when the runtime environment is explicitly local.
        """
        return self.BACKEND_ENV.strip().lower() == "local"

    def has_placeholder_secret(self) -> bool:
        """
        Return True when BACKEND_SECRET_KEY is missing or uses a placeholder.
        """
        secret = (self.BACKEND_SECRET_KEY or "").strip()

        if not secret:
            return True

        lowered = secret.lower()
        return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)

    def is_synthetic_mode(self) -> bool:
        """
        Return True when the dataset mode is synthetic.
        """
        return self.BACKEND_DATASET_MODE.strip().lower() == "synthetic"

    def get_role_list(self, setting_name: str) -> list[str]:
        """
        Return a normalized uppercase role list for a settings field name.
        """
        value = getattr(self, setting_name, None)

        if value is None:
            return []

        if isinstance(value, str):
            items = _split_csv(value)
        elif isinstance(value, (list, tuple, set)):
            items = [str(item) for item in value]
        else:
            items = [str(value)]

        return [item.strip().upper() for item in items if item.strip()]

    def safe_summary(self) -> dict[str, Any]:
        """
        Return a safe, non-sensitive summary for diagnostics.

        This must not expose secrets, tokens, passwords, or database URLs.
        """
        return {
            "app_name": self.BACKEND_APP_NAME,
            "environment": self.BACKEND_ENV,
            "dataset_mode": self.BACKEND_DATASET_MODE,
            "synthetic_mode": self.is_synthetic_mode(),
            "production_like": self.is_production_like(),
            "debug": self.BACKEND_DEBUG,
            "auth_enabled": self.AUTH_ENABLED,
            "auth_mode": self.AUTH_MODE,
            "rbac_enabled": self.RBAC_ENABLED,
            "ml_enabled": self.ML_ENABLED,
            "graph_enabled": self.GRAPH_ENABLED,
            "report_enabled": self.REPORT_ENABLED,
            "audit_enabled": self.AUDIT_ENABLED,
            "has_placeholder_secret": self.has_placeholder_secret(),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        """
        Avoid leaking secrets in repr.
        """
        return (
            f"<Settings env={self.BACKEND_ENV!r} "
            f"dataset_mode={self.BACKEND_DATASET_MODE!r} "
            f"auth_enabled={self.AUTH_ENABLED!r} "
            f"production_like={self.is_production_like()!r}>"
        )


# -----------------------------------------------------------------------------
# Settings access
# -----------------------------------------------------------------------------


#: A test-supplied Settings instance that `get_settings()` returns in
#: preference to the cached one. Held in a slot rather than by rebinding
#: `get_settings`, because every module that did
#: `from app.core.config import get_settings` holds its own reference to the
#: original function and would never see a rebinding.
_override: Optional[Settings] = None


@lru_cache(maxsize=1)
def _cached_settings() -> Settings:
    return Settings()


def get_settings() -> Settings:
    """
    Return a cached Settings instance.

    Use `clear_settings_cache()` in tests that need to reload environment
    variables, or `override_settings_for_testing()` to inject an instance.
    """
    if _override is not None:
        return _override

    return _cached_settings()


# `get_settings.cache_clear()` is called in several places, including the test
# suite's conftest. Keep it working now that the cache sits one level down.
get_settings.cache_clear = _cached_settings.cache_clear  # type: ignore[attr-defined]


def get_settings_fresh() -> Settings:
    """
    Return a new Settings instance without using the cache.
    """
    return Settings()


def clear_settings_cache() -> None:
    """
    Clear the cached Settings instance and any test override.
    """
    global _override

    _override = None
    _cached_settings.cache_clear()


def override_settings_for_testing(settings: Optional[Settings]) -> None:
    """
    Make `get_settings()` return `settings` until the override is cleared.

    Testing helper only; production code relies on environment configuration.
    Pass `None`, or call `clear_settings_cache()`, to remove the override.
    """
    global _override

    _override = settings
    _cached_settings.cache_clear()


__all__ = [
    "Settings",
    "clear_settings_cache",
    "get_settings",
    "get_settings_fresh",
    "override_settings_for_testing",
]