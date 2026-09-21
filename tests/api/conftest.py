"""Fixtures for the console tests (ADR-0011).

`app_state` builds a seeded runtime state with explicit (test-only) secrets;
`client` wraps it in a logged-in TestClient. Secrets here are test fixtures,
never committed defaults in src/ (invariant 12).
"""

from __future__ import annotations

import pytest

from mandate.api.app import build_state, create_app
from mandate.ledger.store import InMemoryLedgerStore
from tests.api.support import make_logged_in_client

PASSWORD = "op-test-password"
SESSION_SECRET = "op-test-session-secret"


@pytest.fixture
def app_state():
    return build_state(
        store=InMemoryLedgerStore(), password=PASSWORD, session_secret=SESSION_SECRET, seed=True
    )


@pytest.fixture
def client(app_state):
    app = create_app(state=app_state, seed=False)
    return make_logged_in_client(app, PASSWORD)


@pytest.fixture
def fresh_client():
    """A logged-in client factory for tests that need a custom (unseeded or
    specially-seeded) state. Returns a callable: fresh_client(state) -> client."""

    def _make(state):
        app = create_app(state=state, seed=False)
        return make_logged_in_client(app, PASSWORD)

    return _make
