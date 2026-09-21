"""The console application factory (ADR-0011).

`create_app` builds a FastAPI app over a runtime `AppState`. A single HTTP
middleware guarantees every request has a (at least anonymous) server-side
session so the login form always carries a CSRF token. Secrets are supplied by
the caller (env or generated at startup) — never a committed default
(invariant 12). Run the local server with `uv run python -m mandate.api.app`.
"""

from __future__ import annotations

import os
import secrets as _secrets
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import Response

from mandate.api import boundary, security
from mandate.api.routes import auth, deals, operations
from mandate.api.state import AppState
from mandate.crypto.signing import GatewaySigner, generate_keypair
from mandate.ledger.store import InMemoryLedgerStore, LedgerStore
from mandate.screen.config import screen_from_env
from mandate.screen.protocol import ContentScreen


def build_state(
    *,
    store: LedgerStore,
    password: str,
    session_secret: str,
    operator_id: str = "operator",
    seed: bool = True,
    screen: ContentScreen | None = None,
) -> AppState:
    """Assemble runtime state. `password`/`session_secret` are required — the
    caller decides whether they come from env or are freshly generated.

    `screen` is the content screen (ADR-0016); when omitted it is read from
    the environment (`MANDATE_CONTENT_SCREEN`), which is off by default."""
    private_key, public_key = generate_keypair()
    signer = GatewaySigner(
        key_id=boundary.new_ulid(), private_key=private_key, public_key=public_key
    )
    state = AppState(
        store=store,
        signer=signer,
        operator_id=operator_id,
        operator_password=password,
        session_secret=session_secret,
        screen=screen if screen is not None else screen_from_env(),
    )
    if seed:
        boundary.seed_demo(state)
    return state


def create_app(
    state: AppState | None = None,
    *,
    store: LedgerStore | None = None,
    password: str | None = None,
    session_secret: str | None = None,
    seed: bool = True,
) -> FastAPI:
    """Build the app. If `state` is omitted it is built from `store`/`password`/
    `session_secret` (all required in that case)."""
    if state is None:
        if store is None or password is None or session_secret is None:
            msg = "pass a ready AppState or all of store/password/session_secret"
            raise ValueError(msg)
        state = build_state(
            store=store, password=password, session_secret=session_secret, seed=seed
        )

    app = FastAPI(title="Agent Mandate console", debug=False)
    app.state.mandate = state

    @app.middleware("http")
    async def session_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        token = request.cookies.get(security.COOKIE_NAME)
        if token is None or token not in state.sessions:
            token = security.new_anonymous_session(state)
        request.state.mandate_token = token
        response = await call_next(request)
        # Re-read: a route may have rotated the session (login does, to defeat
        # session fixation). Setting the cookie from the token captured above
        # would leave the browser holding a token that no longer exists.
        current = getattr(request.state, "mandate_token", token)
        security.set_session_cookie(response, current)
        return response

    app.include_router(auth.router)
    app.include_router(deals.router)
    app.include_router(operations.router)
    return app


def _load_secret(env_var: str, dev_file: Path) -> str:
    """Resolve one secret: env var, then a 0600 .dev file, then generate
    (invariant 12: never a committed default)."""
    from_env = os.environ.get(env_var)
    if from_env:
        return from_env
    if dev_file.is_file():
        return dev_file.read_text(encoding="utf-8").strip()
    return _secrets.token_urlsafe(32)


def _secrets_from_env() -> tuple[str, str]:
    dev_dir = Path(".dev")
    password = _load_secret("MANDATE_OPERATOR_PASSWORD", dev_dir / "operator_password")
    session_secret = _load_secret("MANDATE_SESSION_SECRET", dev_dir / "session_secret")
    had_password = (
        "MANDATE_OPERATOR_PASSWORD" in os.environ or (dev_dir / "operator_password").is_file()
    )
    if not had_password:
        print(
            "no operator password set (env or .dev/); generated one for this run only — "
            f"log in with: {password}\n"
            "persist it with: uv run scripts/dev_secrets.py",
            file=sys.stderr,
        )
    return password, session_secret


def main() -> None:
    import uvicorn

    password, session_secret = _secrets_from_env()
    app = create_app(
        state=build_state(
            store=InMemoryLedgerStore(), password=password, session_secret=session_secret, seed=True
        )
    )
    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
