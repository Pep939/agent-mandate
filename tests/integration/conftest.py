"""Fixtures for Postgres integration tests.

All tests in this package are gated on the MANDATE_TEST_DB_URL environment
variable (ADR-0008): the CI unit suite never needs a database, and a local
run with the variable set exercises the real backend.

  docker run -d --name mandate-pg -e POSTGRES_DB=mandate \
    -e POSTGRES_USER=mandate -e POSTGRES_PASSWORD=dev -p 5432:5432 postgres:16
  export MANDATE_TEST_DB_URL=postgresql+psycopg://mandate:dev@127.0.0.1:5432/mandate
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine

from mandate.adapters.postgres.db import create_schema, drop_schema
from mandate.adapters.postgres.store import PostgresLedgerStore


@pytest.fixture
def db_url() -> str:
    url = os.environ.get("MANDATE_TEST_DB_URL")
    if url is None:
        pytest.skip("MANDATE_TEST_DB_URL not set (Postgres integration tests are gated)")
    return url


@pytest.fixture
def store(db_url: str) -> Iterator[PostgresLedgerStore]:
    """A PostgresLedgerStore with a fresh schema (tables + append-only trigger)."""
    engine = create_engine(db_url)
    drop_schema(engine)
    create_schema(engine)
    engine.dispose()
    s = PostgresLedgerStore(db_url)
    yield s
    drop_schema(s.engine)
    s.close()
