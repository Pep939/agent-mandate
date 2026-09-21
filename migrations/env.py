"""Alembic environment for the Mandate ledger (ADR-0008)."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from mandate.adapters.postgres.db import metadata

config = context.config
target_metadata = metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        msg = "sqlalchemy.url or MANDATE_DB_URL is required"
        raise RuntimeError(msg)
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("MANDATE_DB_URL")
    if not url:
        msg = "set sqlalchemy.url in alembic.ini or MANDATE_DB_URL in the environment"
        raise RuntimeError(msg)
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url
    connectable = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
