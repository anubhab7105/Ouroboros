"""
Alembic environment for MULEGUARD.

The database URL comes from application settings rather than `alembic.ini`, so
there is exactly one place a connection string is configured and no credential
is ever committed. The placeholder `sqlalchemy.url` in `alembic.ini` is
deliberately unusable and is overridden here at runtime.

Behaviour worth knowing:

- `target_metadata` is `app.db.Base.metadata` with `app.models` imported, so
  `alembic revision --autogenerate` sees the real schema.
- The naming convention from `app.db` is attached to that metadata, which is
  what lets autogenerate emit stable constraint names instead of database
  defaults.
- On SQLite, `render_as_batch=True` is enabled because SQLite cannot
  `ALTER TABLE DROP COLUMN`; batch mode rewrites the table instead. Without
  this, any future column-drop migration would fail on a developer's local
  SQLite database while passing on PostgreSQL.
- `compare_type` and `compare_server_default` are on so a changed column type
  is caught rather than silently ignored.
"""

from __future__ import annotations

import logging
import os
import sys
from logging.config import fileConfig
from pathlib import Path
from typing import Any

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure `backend/` is importable when alembic runs from that directory.
_BACKEND_ROOT = Path(__file__).resolve().parents[1]

if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.db import Base  # noqa: E402  (import after sys.path setup)
from app import models as _models  # noqa: E402,F401  (registers all tables)

config = context.config

if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except (KeyError, ValueError):
        # A malformed logging section must not block a migration.
        logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("muleguard.migrations")

target_metadata = Base.metadata


def _resolve_database_url() -> str:
    """
    Resolve the migration database URL.

    Precedence:
      1. `-x url=...` passed on the alembic command line
      2. the `DATABASE_URL` environment variable
      3. application settings (`app.core.config.get_settings`)
      4. the `alembic.ini` value, only if it is not the placeholder
    """
    overrides: dict[str, str] = context.get_x_argument(as_dictionary=True) or {}
    candidate = overrides.get("url") or overrides.get("database_url")

    if candidate:
        return str(candidate).strip()

    env_url = os.environ.get("DATABASE_URL", "").strip()

    if env_url:
        return env_url

    try:
        from app.core.config import get_settings

        settings_url = str(getattr(get_settings(), "DATABASE_URL", "") or "").strip()

        if settings_url:
            return settings_url
    except Exception:  # pragma: no cover - settings must not break migrations
        logger.warning("Could not load application settings for the database URL.")

    ini_url = str(config.get_main_option("sqlalchemy.url") or "").strip()

    if ini_url and not ini_url.startswith("driver://"):
        return ini_url

    raise RuntimeError(
        "No database URL configured for migrations. Set DATABASE_URL in the "
        "environment, or pass it explicitly: "
        'alembic -x url="postgresql+psycopg://user:pass@host/db" upgrade head'
    )


def _is_sqlite(url: str) -> bool:
    return url.strip().lower().startswith("sqlite")


def _include_object(
    obj: Any,
    name: str | None,
    type_: str,
    reflected: bool,
    compare_to: Any,
) -> bool:
    """
    Decide whether an object participates in autogenerate.

    Alembic's own version table is excluded so it never appears in a diff.
    """
    if type_ == "table" and name == config.get_main_option(
        "version_table", "alembic_version"
    ):
        return False

    return True


def run_migrations_offline() -> None:
    """
    Emit SQL to stdout without connecting to a database.

    Used to hand a reviewable DDL script to a DBA:
        alembic upgrade head --sql > upgrade.sql
    """
    url = _resolve_database_url()

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=_include_object,
        render_as_batch=_is_sqlite(url),
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations against a live connection.
    """
    url = _resolve_database_url()
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = url

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_object=_include_object,
            render_as_batch=_is_sqlite(url),
            transaction_per_migration=True,
        )

        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
