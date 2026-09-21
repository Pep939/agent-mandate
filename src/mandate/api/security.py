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


def _new_csrf(state: AppState) -> str:
    """A signed, timestamped synchronizer token over fresh random bytes.

    The payload must NOT be the session token. `itsdangerous` signs but does not
    encrypt, so anything put in here is recoverable by base64-decoding the first
    segment — and this token is rendered into a hidden field on every page. It
    used to carry the session token, which made `httponly` on the session cookie
    decorative: read the page source, recover the cookie, own the session. The
    binding to a session comes from the server-side `Session.csrf_token`
    comparison in `verify_csrf`, not from the payload.
    """
    return _serializer(state.session_secret).dumps(secrets.token_urlsafe(32))


def new_anonymous_session(state: AppState) -> str:
    token = secrets.token_urlsafe(32)
    state.sessions[token] = Session(csrf_token=_new_csrf(state), authenticated=False)
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
    """Promote the current session to authenticated **under a fresh token**.

    The privilege change mints a new session token and a new CSRF token and
    discards the old entry — it never flips `authenticated` in place. Cookies
    are not port-scoped, so any other page served from 127.0.0.1 (routine on a
    developer machine) can plant a `mandate_session` cookie of its choosing;
    upgrading that same token in place would hand the attacker the operator's
    authenticated session. Rotating on login is what makes the planted token
    worthless.

    The middleware re-reads `request.state.mandate_token` when it sets the
    response cookie, so updating it here is what gets the new token to the
    browser. Returns whether a session existed to promote.
    """
    old_token = session_token_for(request)
    if old_token is None or old_token not in state.sessions:
        return False
    new_token = secrets.token_urlsafe(32)
    state.sessions[new_token] = Session(csrf_token=_new_csrf(state), authenticated=True)
    state.sessions.pop(old_token, None)
    request.state.mandate_token = new_token
    return True


def destroy_session(state: AppState, request: Request) -> bool:
    token = session_token_for(request)
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
