"""Run the wire gateway against Postgres (C1).

Loads the process-lifetime key material (identity + chain key) and the peer
registry from files, opens the Postgres store, and serves the gateway over
HTTP. The process is restart-safe: deals, events, and the deal → mandate
registry live in Postgres, and `build_gateway_state` rebuilds the in-memory
registry from the store, so after a restart the chain still verifies and
pre-existing deals stay actionable.

Usage:
    uv run scripts/dev_gateway_keys.py
    export MANDATE_DB_URL=postgresql+psycopg://mandate:dev@127.0.0.1:5432/mandate
    export MANDATE_IDENTITY_FILE=.dev/keys/gateway/<identity>.ed25519.json
    export MANDATE_CHAIN_KEY_FILE=.dev/keys/gateway/<chain>.ed25519.json
    export MANDATE_PEERS_FILE=.dev/keys/gateway/peers.json
    uv run scripts/run_gateway.py

Environment:
    MANDATE_DB_URL                   Postgres DSN (required)
    MANDATE_IDENTITY_FILE            identity key file (required)
    MANDATE_CHAIN_KEY_FILE           chain key file (required)
    MANDATE_PEERS_FILE               peer registry JSON (required)
    MANDATE_HOST / MANDATE_PORT      bind address (default 127.0.0.1:8100)
    MANDATE_ENVELOPE_MAX_AGE_SECONDS first-seen freshness window in seconds
                                     (default 300; 0/off disables)
    MANDATE_LOG_LEVEL                logging level (default INFO)
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import uvicorn

from mandate.adapters.postgres.store import PostgresLedgerStore
from mandate.adapters.postgres.wire_dedup import PostgresWireDedup
from mandate.transport.envelope import EnvelopeError
from mandate.transport.gateway import (
    build_gateway_state,
    configure_gateway_logging,
    create_gateway_app,
    load_chain_signer,
    load_identity,
    load_peers,
    max_age_from_env,
    require_env,
)


def main() -> int:
    configure_gateway_logging(os.environ.get("MANDATE_LOG_LEVEL", "INFO"))
    log = logging.getLogger("mandate.run_gateway")
    try:
        db_url = require_env("MANDATE_DB_URL")
        identity = load_identity(Path(require_env("MANDATE_IDENTITY_FILE")))
        signer = load_chain_signer(Path(require_env("MANDATE_CHAIN_KEY_FILE")))
        peers = load_peers(Path(require_env("MANDATE_PEERS_FILE")))
        max_age = max_age_from_env(os.environ.get("MANDATE_ENVELOPE_MAX_AGE_SECONDS", "300"))
    except (ValueError, EnvelopeError) as exc:
        raise SystemExit(f"gateway configuration error: {exc}") from exc

    store = PostgresLedgerStore(db_url)
    state = build_gateway_state(
        identity=identity,
        signer=signer,
        store=store,
        dedup=PostgresWireDedup(store.engine),
        peers=peers,
        max_age_seconds=max_age,
    )
    host = os.environ.get("MANDATE_HOST", "127.0.0.1")
    port = int(os.environ.get("MANDATE_PORT", "8100"))
    log.info(
        "gateway starting",
        extra={
            "log": {
                "event": "gateway_starting",
                "identity_id": state.identity.identity_id,
                "chain_key_id": state.signer.key_id,
                "peers": sorted(state.peers),
                "host": host,
                "port": port,
                "max_age_seconds": state.max_age_seconds,
                "deals_known": len(state.deal_ids),
            }
        },
    )
    uvicorn.run(create_gateway_app(state), host=host, port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
