"""Operator authentication, server-side sessions, and CSRF (ADR-0011).

Single-operator local console. The operator password and the session signing
secret are runtime-only (invariant 12): they live on AppState and are used only
in constant-time comparisons here — never rendered, logged, or placed in a
response body.
"""

from __future__ import annotations

import hmac
import secrets

from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.requests import Request
from starlette.responses import Response

from mandate.api.state import AppState, Session

COOKIE_NAME = "mandate_session"
SESSION_MAX_AGE = 8 * 3600  # seconds; carried as the cookie max-age (ADR-0011)


def _serializer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt="mandate-csrf")


def check_password(state: AppState, submitted: str) -> bool:
    """Constant-time compare against the operator secret (ADR-0011).

    No user store, no per-user hashing — a single local operator.
    """
    return hmac.compare_digest(submitted, state.operator_password)


def _new_csrf(state: AppState, session_token: str) -> str:
    """A signed, per-session synchronizer token (opaque and session-bound)."""
    return _serializer(state.session_secret).dumps(session_token)


def new_anonymous_session(state: AppState) -> str:
    token = secrets.token_urlsafe(32)
    state.sessions[token] = Session(csrf_token=_new_csrf(state, token), authenticated=False)
    return token


def session_token_for(request: Request) -> str | None:
    """The active session token for this request.

    The session middleware records it on `request.state` before the route runs
    (so the login form has a token even on the very first request, before any
    cookie round-trip); the cookie is the fallback for direct access.
    """
    token = getattr(request.state, "mandate_token", None)
    if token is None:
        token = request.cookies.get(COOKIE_NAME)
    return token


def get_session(state: AppState, request: Request) -> Session | None:
    token = session_token_for(request)
    if token is None:
        return None
    return state.sessions.get(token)


def is_authenticated(state: AppState, request: Request) -> bool:
    session = get_session(state, request)
    return session is not None and session.authenticated


def csrf_token_for(state: AppState, request: Request) -> str:
    session = get_session(state, request)
    return session.csrf_token if session is not None else ""


def verify_csrf(state: AppState, request: Request, submitted: str) -> bool:
    """Validate the per-session synchronizer token (constant-time).

    The token must both match the session's stored token and be a currently
    valid signature under the session secret — a token from another session or
    a tampered token fails.
    """
    session = get_session(state, request)
    if session is None or not submitted:
        return False
    if not hmac.compare_digest(submitted, session.csrf_token):
        return False
    try:
        _serializer(state.session_secret).loads(submitted, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return False
    return True


def authenticate_session(state: AppState, request: Request) -> bool:
    """Flip the current (anonymous) session to authenticated. Returns whether a
    session existed to flip."""
    session = get_session(state, request)
    if session is None:
        return False
    session.authenticated = True
    return True


def destroy_session(state: AppState, request: Request) -> bool:
    token = request.cookies.get(COOKIE_NAME)
    if token is None:
        return False
    state.sessions.pop(token, None)
    return True


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_MAX_AGE,
    )
