"""
MULEGUARD backend database foundation.

This module owns:

- SQLAlchemy declarative base;
- database engine creation;
- session factory creation;
- FastAPI database session dependency;
- transactional session scope helper;
- safe database health checks;
- SQLite and PostgreSQL runtime tuning;
- test/bootstrap helpers for disposable schemas;
- audit context binding helpers;
- redacted database URL logging.

Design rules:

- PostgreSQL is the intended deployment source of truth.
- SQLite is supported only for local development and tests unless explicitly
  reconfigured.
- Migrations, not create_all(), are the deployed schema-management path.
- Monetary values must use Decimal/NUMERIC in models.
- Timestamps should be timezone-aware and UTC-normalised in models/services.
- No request-derived raw SQL is constructed here.
- Database errors returned to callers must not leak secrets, connection strings,
  or sensitive parameter values.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Final

from sqlalchemy import MetaData, create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from app.core.config import Settings, get_settings

logger = logging.getLogger("muleguard.backend.db")


# -----------------------------------------------------------------------------
# SQLAlchemy metadata and declarative base
# -----------------------------------------------------------------------------
# Deterministic constraint/index naming is important for Alembic autogenerate
# and for reproducible migrations across PostgreSQL and SQLite.

NAMING_CONVENTION: Final[dict[str, str]] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """
    Project-wide SQLAlchemy declarative base.

    All persisted domain models should inherit from this class.

    Example:

        from app.db import Base

        class Account(Base):
            __tablename__ = "accounts"
            ...
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# -----------------------------------------------------------------------------
# Small typed-setting helpers
# -----------------------------------------------------------------------------
# These helpers tolerate both properly typed Pydantic settings and partially
# populated mapping-like objects during early bootstrap or tests.

_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on", "t"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off", "f", ""}


def _as_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, int):
        return bool(value)

    text_value = str(value).strip().lower()

    if text_value in _TRUE_VALUES:
        return True

    if text_value in _FALSE_VALUES:
        return False

    return default


def _as_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _csv(value: object) -> list[str]:
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]

    return [part.strip() for part in str(value).split(",") if part.strip()]


def _setting(settings: Settings | Any, name: str, default: Any = None) -> Any:
    """
    Read a setting from either a Pydantic settings object or mapping.
    """
    if isinstance(settings, dict):
        return settings.get(name, default)

    return getattr(settings, name, default)


# -----------------------------------------------------------------------------
# Database URL helpers
# -----------------------------------------------------------------------------


def _redact_database_url(url: str | None) -> str:
    """
    Return a log-safe representation of a database URL.

    This intentionally hides passwords. It is not a parser for every exotic
    driver URL format, but it is sufficient for common PostgreSQL and SQLite
    URLs used by MULEGUARD.
    """
    if not url:
        return "<unset>"

    try:
        if "://" not in url:
            return "<redacted>"

        scheme, remainder = url.split("://", 1)

        if "@" not in remainder:
            return url

        userinfo, host_part = remainder.rsplit("@", 1)

        if ":" in userinfo:
            username = userinfo.split(":", 1)[0]
            return f"{scheme}://{username}:***@{host_part}"

        return f"{scheme}://{userinfo}@{host_part}"

    except Exception:
        return "<redacted>"


def _is_sqlite_url(url: str) -> bool:
    return url.startswith("sqlite")


def _is_postgres_url(url: str) -> bool:
    return url.startswith(("postgresql", "postgres"))


def _is_memory_sqlite_url(url: str) -> bool:
    return ":memory:" in url or "mode=memory" in url


def _ensure_sqlite_parent_dir(url: str) -> None:
    """
    Create the directory holding a file-backed SQLite database, if missing.

    SQLite will create `muleguard.db` on first connect but not the `var/`
    directory above it, and the resulting `unable to open database file` names
    the file rather than the directory, which sends people looking for a
    permissions problem that is not there.

    Failures here are logged and swallowed: if the directory cannot be created,
    the connection attempt that follows produces the real, specific error, and
    that is a better message than anything this function could raise.
    """
    try:
        _, _, remainder = url.partition(":///")
        path_part, _, _ = remainder.partition("?")

        if not path_part:
            return

        parent = Path(path_part).expanduser().parent

        if parent and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
            logger.info("Created SQLite database directory: %s", parent)
    except OSError:
        logger.warning(
            "Could not create the SQLite database directory; "
            "letting the connection attempt report the specific error.",
            exc_info=True,
        )


def _is_production_like_settings(settings: Settings | Any) -> bool:
    env = str(_setting(settings, "BACKEND_ENV", "local")).strip().lower()

    configured_values = _csv(
        _setting(
            settings,
            "BACKEND_PRODUCTION_LIKE_ENVS",
            "production,staging,prod,stage",
        )
    )

    production_like_values = {value.lower() for value in configured_values}

    if not production_like_values:
        production_like_values = {"production", "staging", "prod", "stage"}

    return env in production_like_values


# -----------------------------------------------------------------------------
# SQLite connection tuning
# -----------------------------------------------------------------------------


def _configure_sqlite_engine(
    target_engine: Engine,
    *,
    settings: Settings | Any,
    database_url: str,
) -> None:
    """
    Attach SQLite PRAGMA settings to new DBAPI connections.

    SQLite defaults vary by platform and driver. MULEGUARD relies on:

    - foreign key enforcement;
    - busy timeout for concurrent local access;
    - predictable journal mode;
    - bounded cache behaviour for local demos.
    """
    is_memory = _is_memory_sqlite_url(database_url)

    foreign_keys_enabled = _as_bool(
        _setting(settings, "SQLITE_FOREIGN_KEYS", True),
        True,
    )

    busy_timeout_ms = max(
        0,
        _as_int(_setting(settings, "SQLITE_BUSY_TIMEOUT", 5000), 5000),
    )

    default_journal_mode = "MEMORY" if is_memory else "WAL"
    journal_mode = str(
        _setting(settings, "SQLITE_JOURNAL_MODE", default_journal_mode)
    ).strip().upper()

    allowed_journal_modes = {
        "DELETE",
        "TRUNCATE",
        "PERSIST",
        "MEMORY",
        "WAL",
        "OFF",
    }

    if journal_mode not in allowed_journal_modes:
        logger.warning(
            "Unsupported SQLITE_JOURNAL_MODE=%s; falling back to %s",
            journal_mode,
            default_journal_mode,
        )
        journal_mode = default_journal_mode

    synchronous = str(
        _setting(settings, "SQLITE_SYNCHRONOUS", "NORMAL")
    ).strip().upper()

    allowed_synchronous = {"OFF", "NORMAL", "FULL", "EXTRA"}

    if synchronous not in allowed_synchronous:
        logger.warning(
            "Unsupported SQLITE_SYNCHRONOUS=%s; falling back to NORMAL",
            synchronous,
        )
        synchronous = "NORMAL"

    temp_store = str(
        _setting(settings, "SQLITE_TEMP_STORE", "MEMORY")
    ).strip().upper()

    allowed_temp_store = {"DEFAULT", "FILE", "MEMORY"}

    if temp_store not in allowed_temp_store:
        logger.warning(
            "Unsupported SQLITE_TEMP_STORE=%s; falling back to MEMORY",
            temp_store,
        )
        temp_store = "MEMORY"

    cache_size_mb = max(
        0,
        _as_int(_setting(settings, "SQLITE_CACHE_SIZE_MB", 64), 64),
    )

    @event.listens_for(target_engine, "connect")
    def _set_sqlite_pragmas(
        dbapi_connection: Any,
        _connection_record: Any,
    ) -> None:
        cursor = dbapi_connection.cursor()

        try:
            # SQLite cannot parameterize a PRAGMA: the name and the value have
            # to be literal SQL text, so the value is interpolated like every
            # other pragma below. `%s` was doubly wrong here -- sqlite3 uses
            # qmark paramstyle, not printf -- and the resulting
            # `near "%": syntax error` fired on the "connect" event, which is
            # why it surfaced as a connection failure rather than a statement
            # failure, and why alembic was unaffected: `migrations/env.py`
            # builds its own engine with `engine_from_config` and never
            # installs this listener.
            #
            # Interpolation is safe because the value is derived from a bool,
            # not from input. The explicit literal keeps it that way.
            cursor.execute(
                "PRAGMA foreign_keys=ON"
                if foreign_keys_enabled
                else "PRAGMA foreign_keys=OFF"
            )
            cursor.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            cursor.execute(f"PRAGMA journal_mode={journal_mode}")
            cursor.execute(f"PRAGMA synchronous={synchronous}")
            cursor.execute(f"PRAGMA temp_store={temp_store}")

            if cache_size_mb > 0:
                # Negative cache_size values are interpreted as kibibytes.
                cursor.execute(f"PRAGMA cache_size=-{int(cache_size_mb * 1024)}")

        finally:
            cursor.close()


# -----------------------------------------------------------------------------
# Engine factory
# -----------------------------------------------------------------------------


def create_engine_from_settings(settings: Settings | None = None) -> Engine:
    """
    Create a SQLAlchemy engine from typed runtime settings.

    This function is intentionally explicit and defensive. It supports:

    - PostgreSQL with connection pooling, statement timeout, lock timeout,
      UTC session timezone, and optional SSL mode;
    - SQLite for local development/tests with foreign keys, busy timeout,
      WAL/MEMORY journal mode, and bounded cache settings;
    - redacted startup logging;
    - production-like guards against accidental SQLite use.
    """
    settings = settings or get_settings()

    database_url = str(_setting(settings, "DATABASE_URL", "") or "").strip()

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is not configured. "
            "Set it through environment configuration or backend/.env."
        )

    production_like = _is_production_like_settings(settings)

    # ---------------------------------------------------------------------
    # SQLite safety guard
    # ---------------------------------------------------------------------
    if _is_sqlite_url(database_url):
        allow_sqlite_local = _as_bool(
            _setting(settings, "BACKEND_ALLOW_SQLITE_FOR_LOCAL_DEV", True),
            True,
        )

        allow_sqlite_production = _as_bool(
            _setting(settings, "DB_ALLOW_SQLITE_IN_PRODUCTION", False),
            False,
        )

        if production_like and not allow_sqlite_production:
            raise RuntimeError(
                "SQLite is not permitted in production-like environments. "
                "Use PostgreSQL as the MULEGUARD source of truth."
            )

        if not production_like and not allow_sqlite_local:
            raise RuntimeError(
                "SQLite usage is disabled by BACKEND_ALLOW_SQLITE_FOR_LOCAL_DEV=false."
            )

    # ---------------------------------------------------------------------
    # Echo / SQL logging
    # ---------------------------------------------------------------------
    # SQLAlchemy echo can log bound parameters. That is useful for local
    # debugging but unsafe for sensitive complaint narratives or ingestion
    # payloads. Force it off in production-like environments.
    echo_sql = _as_bool(_setting(settings, "DB_ECHO", False), False)

    if echo_sql and production_like:
        logger.warning(
            "DB_ECHO=true is unsafe in production-like environments because it "
            "may log bound parameters. Disabling echo SQL logging."
        )
        echo_sql = False

    engine_kwargs: dict[str, Any] = {
        "future": True,
        "echo": echo_sql,
    }

    connect_args: dict[str, Any] = {}

    # ---------------------------------------------------------------------
    # SQLite-specific configuration
    # ---------------------------------------------------------------------
    if _is_sqlite_url(database_url):
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = _as_float(
            _setting(settings, "DB_CONNECT_TIMEOUT_SECONDS", 5.0),
            5.0,
        )

        if _is_memory_sqlite_url(database_url):
            # In-memory SQLite databases are connection-local unless a
            # StaticPool shares a single connection across sessions.
            engine_kwargs["poolclass"] = StaticPool
        else:
            # File-backed SQLite in local FastAPI threads is safest without
            # cross-thread pool reuse for the prototype.
            engine_kwargs["poolclass"] = NullPool

            # SQLite creates the database file but not the directory above it.
            # Without this, a perfectly correct configuration fails with
            # `unable to open database file`, which reads as a permissions or
            # corruption problem rather than a missing folder.
            _ensure_sqlite_parent_dir(database_url)

    # ---------------------------------------------------------------------
    # PostgreSQL / generic server database configuration
    # ---------------------------------------------------------------------
    else:
        engine_kwargs.update(
            {
                "pool_size": _as_int(
                    _setting(settings, "DB_POOL_SIZE", 10),
                    10,
                ),
                "max_overflow": _as_int(
                    _setting(settings, "DB_MAX_OVERFLOW", 20),
                    20,
                ),
                "pool_timeout": _as_float(
                    _setting(settings, "DB_POOL_TIMEOUT_SECONDS", 30.0),
                    30.0,
                ),
                "pool_recycle": _as_int(
                    _setting(settings, "DB_POOL_RECYCLE_SECONDS", 1800),
                    1800,
                ),
                "pool_pre_ping": _as_bool(
                    _setting(settings, "DB_POOL_PRE_PING", True),
                    True,
                ),
            }
        )

        if _is_postgres_url(database_url):
            connect_args["connect_timeout"] = _as_int(
                _setting(settings, "DB_CONNECT_TIMEOUT_SECONDS", 10),
                10,
            )

            connect_args["application_name"] = str(
                _setting(settings, "DB_APPLICATION_NAME", "muleguard-backend")
            )

            postgres_options: list[str] = []

            statement_timeout_ms = _as_int(
                _setting(settings, "DB_STATEMENT_TIMEOUT_MS", 15000),
                15000,
            )

            if statement_timeout_ms > 0:
                postgres_options.append(
                    f"-c statement_timeout={int(statement_timeout_ms)}"
                )

            lock_timeout_seconds = _as_int(
                _setting(settings, "DB_LOCK_TIMEOUT_SECONDS", 10),
                10,
            )

            if lock_timeout_seconds > 0:
                postgres_options.append(
                    f"-c lock_timeout={int(lock_timeout_seconds * 1000)}"
                )

            default_timezone = str(
                _setting(settings, "DB_DEFAULT_TIMEZONE", "UTC")
            ).strip().upper()

            if default_timezone == "UTC":
                postgres_options.append("-c timezone=UTC")

            if postgres_options:
                connect_args["options"] = " ".join(postgres_options)

            ssl_mode = str(
                _setting(settings, "POSTGRES_SSL_MODE", "") or ""
            ).strip()

            if ssl_mode:
                connect_args["sslmode"] = ssl_mode

            ssl_root_cert = str(
                _setting(settings, "POSTGRES_SSL_ROOT_CERT", "") or ""
            ).strip()

            if ssl_root_cert:
                connect_args["sslrootcert"] = ssl_root_cert

            ssl_cert = str(
                _setting(settings, "POSTGRES_SSL_CERT", "") or ""
            ).strip()

            if ssl_cert:
                connect_args["sslcert"] = ssl_cert

            ssl_key = str(
                _setting(settings, "POSTGRES_SSL_KEY", "") or ""
            ).strip()

            if ssl_key:
                connect_args["sslkey"] = ssl_key

    engine_kwargs["connect_args"] = connect_args

    engine_instance = create_engine(database_url, **engine_kwargs)

    if _is_sqlite_url(database_url):
        _configure_sqlite_engine(
            engine_instance,
            settings=settings,
            database_url=database_url,
        )

    logger.info(
        "Database engine initialised: dialect=%s driver=%s url=%s",
        engine_instance.dialect.name,
        engine_instance.dialect.driver,
        _redact_database_url(database_url),
    )

    return engine_instance


# -----------------------------------------------------------------------------
# Module-level engine and session factory
# -----------------------------------------------------------------------------
# These are created at import time so that FastAPI dependencies, services, and
# scripts can use a single shared engine. Tests may rebuild or dispose them
# through the helpers below.

engine: Engine = create_engine_from_settings()

SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    class_=Session,
)


def get_engine() -> Engine:
    """
    Return the active SQLAlchemy engine.
    """
    return engine


def get_session_factory() -> sessionmaker[Session]:
    """
    Return the active SQLAlchemy session factory.
    """
    return SessionLocal


# -----------------------------------------------------------------------------
# FastAPI dependency
# -----------------------------------------------------------------------------


def get_db() -> Iterator[Session]:
    """
    FastAPI dependency that yields a SQLAlchemy session.

    Transaction policy:

    - By default, this dependency does **not** automatically commit.
    - Write services should explicitly call `session.commit()` or use
      `session_scope()` for atomic operations.
    - If `DB_AUTO_COMMIT_ON_REQUEST_SUCCESS=true` is configured, successful
      request completion will commit the session. This is convenient for
      simple local prototypes but should be used deliberately.

    On exception, the session is rolled back and closed.
    """
    session = SessionLocal()

    auto_commit = _as_bool(
        _setting(get_settings(), "DB_AUTO_COMMIT_ON_REQUEST_SUCCESS", False),
        False,
    )

    try:
        yield session

        if auto_commit:
            session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


# -----------------------------------------------------------------------------
# Transactional helpers
# -----------------------------------------------------------------------------


@contextmanager
def session_scope(*, commit: bool = True) -> Iterator[Session]:
    """
    Provide an atomic session scope for scripts, services, and tests.

    Usage:

        with session_scope() as db:
            db.add(obj)

    If an exception occurs, the transaction is rolled back.
    """
    session = SessionLocal()

    try:
        yield session

        if commit:
            session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


def is_transient_database_error(exc: BaseException) -> bool:
    """
    Best-effort detection of transient PostgreSQL-style errors.

    This helper exists for future retry wrappers. It must not be used to hide
    real bugs or data-integrity failures.
    """
    original = getattr(exc, "orig", None)

    if original is None:
        return False

    pgcode = getattr(original, "pgcode", None)

    if pgcode is None:
        return False

    # Common transient codes:
    #   40001: serialization_failure
    #   40P01: deadlock_detected
    #   08006: connection_failure
    #   08001: sqlclient_unable_to_establish_sqlconnection
    transient_codes = {"40001", "40P01", "08006", "08001"}

    return str(pgcode) in transient_codes


# -----------------------------------------------------------------------------
# Audit context helpers
# -----------------------------------------------------------------------------


def bind_audit_context(
    session: Session,
    *,
    actor_id: str | None = None,
    actor_role: str | None = None,
    request_id: str | None = None,
    action: str | None = None,
    dataset_fingerprint: str | None = None,
) -> None:
    """
    Attach safe audit metadata to the current SQLAlchemy session.

    This does not persist audit records by itself. It allows services and event
    listeners to access request/actor context without threading it through
    every function signature.

    Do not place passwords, tokens, secrets, or full sensitive narratives in
    session info.
    """
    if actor_id:
        session.info["actor_id"] = str(actor_id)

    if actor_role:
        session.info["actor_role"] = str(actor_role)

    if request_id:
        session.info["request_id"] = str(request_id)

    if action:
        session.info["audit_action"] = str(action)

    if dataset_fingerprint:
        session.info["dataset_fingerprint"] = str(dataset_fingerprint)


def get_audit_context(session: Session) -> dict[str, str]:
    """
    Return a safe copy of audit context stored on the session.
    """
    allowed_keys = (
        "actor_id",
        "actor_role",
        "request_id",
        "audit_action",
        "dataset_fingerprint",
    )

    return {
        key: str(session.info[key])
        for key in allowed_keys
        if key in session.info and session.info[key] is not None
    }


# -----------------------------------------------------------------------------
# Health check
# -----------------------------------------------------------------------------


def check_database_health(*, timeout_seconds: float = 3.0) -> dict[str, Any]:
    """
    Return a safe database health summary.

    This endpoint-facing helper must not expose:

    - connection strings;
    - passwords;
    - database host details beyond dialect name;
    - raw driver exceptions.
    """
    started_at = time.perf_counter()

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        latency_ms = round((time.perf_counter() - started_at) * 1000, 3)

        return {
            "ok": True,
            "dialect": engine.dialect.name,
            "driver": engine.dialect.driver,
            "latency_ms": latency_ms,
            "timeout_seconds": timeout_seconds,
        }

    except SQLAlchemyError as exc:
        latency_ms = round((time.perf_counter() - started_at) * 1000, 3)

        logger.warning(
            "Database health check failed: dialect=%s latency_ms=%s error_type=%s",
            engine.dialect.name,
            latency_ms,
            exc.__class__.__name__,
        )

        return {
            "ok": False,
            "dialect": engine.dialect.name,
            "driver": engine.dialect.driver,
            "latency_ms": latency_ms,
            "timeout_seconds": timeout_seconds,
            "error_code": "DATABASE_UNAVAILABLE",
        }

    except Exception:
        latency_ms = round((time.perf_counter() - started_at) * 1000, 3)

        logger.exception(
            "Unexpected database health check failure: dialect=%s latency_ms=%s",
            engine.dialect.name,
            latency_ms,
        )

        return {
            "ok": False,
            "dialect": engine.dialect.name,
            "driver": engine.dialect.driver,
            "latency_ms": latency_ms,
            "timeout_seconds": timeout_seconds,
            "error_code": "DATABASE_HEALTH_CHECK_ERROR",
        }


# -----------------------------------------------------------------------------
# Lifecycle helpers
# -----------------------------------------------------------------------------


def dispose_engine() -> None:
    """
    Dispose the active engine connection pool.

    Used during application shutdown and test teardown.
    """
    try:
        engine.dispose()
        logger.info("Database engine disposed.")
    except Exception:
        logger.exception("Failed to dispose database engine cleanly.")


def rebuild_engine_for_tests(settings: Settings | None = None) -> Engine:
    """
    Rebuild the module-level engine and session factory.

    This is intended for tests that need to point the application at a
    disposable database. It is not intended for normal runtime use.

    Important:

    - Modules that captured the old `engine` object directly may still refer to
      the previous engine.
    - Prefer importing `app.db` and calling `get_engine()` after rebuilding.
    """
    global engine, SessionLocal

    old_engine = engine

    engine = create_engine_from_settings(settings)

    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        class_=Session,
    )

    try:
        old_engine.dispose()
    except Exception:
        logger.warning("Failed to dispose previous test engine cleanly.")

    return engine


# -----------------------------------------------------------------------------
# Disposable schema helpers for tests and local bootstrap
# -----------------------------------------------------------------------------


def _guard_schema_creation() -> None:
    settings = get_settings()

    if _is_production_like_settings(settings):
        allow_create_all = _as_bool(
            _setting(settings, "DB_CREATE_ALL_IN_PRODUCTION", False),
            False,
        )

        if not allow_create_all:
            raise RuntimeError(
                "Base.metadata.create_all() is not permitted in production-like "
                "environments. Use Alembic migrations as the schema-management path."
            )


def init_db(*, drop_first: bool = False) -> None:
    """
    Create tables from SQLAlchemy metadata.

    This is intended for:

    - disposable test databases;
    - quick local experiments;
    - CI fixtures where migrations are intentionally bypassed.

    Deployed environments should use Alembic migrations.
    """
    _guard_schema_creation()

    # Import models so that all mapper registrations and table definitions are
    # attached to Base.metadata before create_all() runs.
    try:
        import app.models  # noqa: F401
    except Exception as exc:
        logger.warning(
            "Could not import app.models before database initialisation: %s",
            exc.__class__.__name__,
        )

    if drop_first:
        Base.metadata.drop_all(bind=engine)

    Base.metadata.create_all(bind=engine)

    logger.info(
        "Database schema initialised using create_all() for non-production use. "
        "table_count=%s",
        len(Base.metadata.tables),
    )


def drop_db() -> None:
    """
    Drop all tables from SQLAlchemy metadata.

    This is destructive and intended only for disposable test databases or
    explicitly local synthetic experiments.
    """
    _guard_schema_creation()

    try:
        import app.models  # noqa: F401
    except Exception as exc:
        logger.warning(
            "Could not import app.models before database drop: %s",
            exc.__class__.__name__,
        )

    Base.metadata.drop_all(bind=engine)

    logger.info(
        "Database schema dropped using drop_all() for non-production use. "
        "table_count=%s",
        len(Base.metadata.tables),
    )


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------

__all__ = [
    "Base",
    "NAMING_CONVENTION",
    "SessionLocal",
    "bind_audit_context",
    "check_database_health",
    "create_engine_from_settings",
    "dispose_engine",
    "drop_db",
    "engine",
    "get_audit_context",
    "get_db",
    "get_engine",
    "get_session_factory",
    "init_db",
    "is_transient_database_error",
    "rebuild_engine_for_tests",
    "session_scope",
]