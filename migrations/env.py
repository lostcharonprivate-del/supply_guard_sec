"""Alembic environment.

Reads the database URL from the application settings rather than alembic.ini,
so migrations and the running service can never disagree about which database
they are pointed at.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

import sqlalchemy as sa
from alembic import context
from sqlalchemy import pool
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from supplyguard.config import get_settings
from supplyguard.db.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", get_settings().database_url)
target_metadata = Base.metadata


def render_item(type_: str, obj: object, autogen_context) -> str | bool:
    """Render the JSONB variant without an unqualified `Text()` reference.

    The models use `JSON().with_variant(JSONB(), "postgresql")` so the schema
    works on both Postgres and SQLite. Left to itself, autogenerate emits
    `postgresql.JSONB(astext_type=Text())` while importing neither `Text` nor
    anything that defines it, and the migration fails at import time.
    `astext_type` defaults to Text anyway, so it is simply dropped.
    """
    if type_ == "type" and isinstance(obj, postgresql.JSONB):
        autogen_context.imports.add("from sqlalchemy.dialects import postgresql")
        return "postgresql.JSONB()"
    if type_ == "type" and isinstance(obj, sa.JSON):
        variant = obj._variant_mapping.get("postgresql") if hasattr(obj, "_variant_mapping") else None
        if variant is not None:
            autogen_context.imports.add("from sqlalchemy.dialects import postgresql")
            return 'sa.JSON().with_variant(postgresql.JSONB(), "postgresql")'
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_async_migrations())
