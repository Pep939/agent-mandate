"""Live-server fixtures for the Phase 5 agent tests.

A real uvicorn server on an ephemeral 127.0.0.1 port shares one `AppState`
with the test process. That is what makes the tests end-to-end (real HTTP,
real sessions, real threads) while still letting tests register custom
mandates and inspect the exact runtime the agents talk to. Secrets are
test fixtures only (invariant 12).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
import uvicorn

from mandate.api import boundary
from mandate.api.app import build_state, create_app
from mandate.api.state import AppState
from mandate.ledger.store import InMemoryLedgerStore

PASSWORD = "op-adv-password"
SESSION_SECRET = "op-adv-session-secret"


@dataclass
class LiveServer:
    base_url: str
    state: AppState
    password: str

    def register_deal(self, **record_kwargs: object) -> str:
        """Register a DRAFT deal under a custom gateway-signed mandate."""
        now = boundary.now_iso()
        record = boundary.make_signed_record(self.state, now=now, **record_kwargs)
        deal_id = boundary.new_ulid()
        boundary.register_deal(self.state, deal_id, record, now)
        return deal_id


@pytest.fixture
def live_server() -> Iterator[LiveServer]:
    state = build_state(
        store=InMemoryLedgerStore(),
        password=PASSWORD,
        session_secret=SESSION_SECRET,
        seed=False,
    )
    app = create_app(state=state, seed=False)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            msg = "uvicorn did not start within 10s"
            raise RuntimeError(msg)
        time.sleep(0.01)
    sock = server.servers[0].sockets[0]
    yield LiveServer(
        base_url=f"http://127.0.0.1:{sock.getsockname()[1]}",
        state=state,
        password=PASSWORD,
    )
    server.should_exit = True
    thread.join(timeout=5)
