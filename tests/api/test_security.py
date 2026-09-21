"""Authentication, CSRF, and secret handling (ADR-0011)."""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from mandate.api.app import build_state, create_app
from mandate.api.security import COOKIE_NAME
from mandate.ledger.store import InMemoryLedgerStore
from tests.api.conftest import PASSWORD, SESSION_SECRET
from tests.api.support import csrf_token, first_deal_id, login

# A distinct secret that must never surface in any response body (invariant 12).
_CANARY_SECRET = "canary-secret-value-0f3a9c"


def _client() -> TestClient:
    app = create_app(
        state=build_state(
            store=InMemoryLedgerStore(),
            password=PASSWORD,
            session_secret=_CANARY_SECRET,
            seed=True,
        )
    )
    return TestClient(app, base_url="http://test")


def test_unauthenticated_get_redirects_to_login():
    with _client() as c:
        response = c.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/login"


def test_unauthenticated_post_is_rejected_not_redirected():
    with _client() as c:
        response = c.post("/deals", follow_redirects=False)  # not a real route, but unauth
    assert response.status_code in (403, 404)


def test_login_form_carries_csrf_token_on_first_request():
    with _client() as c:
        html = c.get("/login").text
    assert csrf_token(html)  # non-empty even before any cookie round-trip


def test_login_with_wrong_password_is_rejected():
    with _client() as c:
        html = c.get("/login").text
        response = c.post(
            "/login",
            data={"password": "wrong", "csrf_token": csrf_token(html)},
            follow_redirects=False,
        )
    assert response.status_code == 401
    # still not authenticated
    follow = c.get("/", follow_redirects=False)
    assert follow.status_code == 307


def test_login_succeeds_with_correct_password():
    with _client() as c:
        login(c, PASSWORD)
        assert c.get("/").status_code == 200


def test_csrf_mismatch_rejects_state_change():
    with _client() as c:
        login(c, PASSWORD)
        deal_id = first_deal_id(c.get("/").text)
        # POST a proposal with a bogus csrf token
        response = c.post(
            f"/deals/{deal_id}/propose",
            data={"action": "request_quote", "csrf_token": "forged-token"},
            follow_redirects=False,
        )
    assert response.status_code == 400


def test_session_cookie_is_httponly_and_samesite_strict():
    with _client() as c:
        c.get("/login")
    cookie = c.cookies.get("mandate_session")
    assert cookie is not None
    # inspect the Set-Cookie attributes from the raw login page response
    raw = c.get("/login")
    set_cookie = raw.headers.get("set-cookie", "")
    assert "httponly" in set_cookie.lower()
    assert "samesite=strict" in set_cookie.lower()


def test_secrets_never_leak_into_response_bodies():
    """The operator password and the session secret must not appear in any
    page or redirect body (invariant 12)."""
    with _client() as c:
        pages = [
            c.get("/login").text,
        ]
        login(c, PASSWORD)
        deal_id = first_deal_id(c.get("/").text)
        pages += [
            c.get("/").text,
            c.get(f"/deals/{deal_id}").text,
            c.get(f"/deals/{deal_id}/propose").text,
            c.get(f"/deals/{deal_id}/timeline").text,
        ]
        # a real decision body too
        token = csrf_token(c.get(f"/deals/{deal_id}/propose").text)
        pages.append(
            c.post(
                f"/deals/{deal_id}/propose",
                data={"action": "request_quote", "csrf_token": token},
            ).text
        )
    for page in pages:
        assert _CANARY_SECRET not in page, "session secret leaked into a page"
        assert SESSION_SECRET not in page
        assert PASSWORD not in page


def test_login_rotates_the_session_token_and_the_csrf_token():
    """Session fixation: a token planted before login must not survive it.

    Cookies are not port-scoped, so any page on 127.0.0.1 can set
    `mandate_session`. If login upgraded that token in place, the planter would
    own the operator's authenticated session.
    """
    app = create_app(
        state=build_state(
            store=InMemoryLedgerStore(),
            password=PASSWORD,
            session_secret=SESSION_SECRET,
            seed=True,
        )
    )
    state = app.state.mandate
    with TestClient(app, base_url="http://test") as c:
        html = c.get("/login").text
        planted = c.cookies[COOKIE_NAME]
        planted_csrf = state.sessions[planted].csrf_token

        response = c.post(
            "/login",
            data={"password": PASSWORD, "csrf_token": csrf_token(html)},
            follow_redirects=False,
        )
        assert response.status_code == 303

        after = c.cookies[COOKIE_NAME]

    assert after != planted, "login must mint a new session token"
    assert planted not in state.sessions, "the pre-login session must be discarded"
    assert state.sessions[after].authenticated is True
    assert state.sessions[after].csrf_token != planted_csrf, "the CSRF token must rotate too"


def test_a_session_token_planted_before_login_is_not_authenticated_afterwards():
    app = create_app(
        state=build_state(
            store=InMemoryLedgerStore(),
            password=PASSWORD,
            session_secret=SESSION_SECRET,
            seed=True,
        )
    )
    state = app.state.mandate
    with TestClient(app, base_url="http://test") as c:
        html = c.get("/login").text
        planted = c.cookies[COOKIE_NAME]
        c.post(
            "/login",
            data={"password": PASSWORD, "csrf_token": csrf_token(html)},
            follow_redirects=False,
        )

    # The attacker still holds `planted`; it must grant nothing.
    assert state.sessions.get(planted) is None
    with TestClient(app, base_url="http://test") as attacker:
        attacker.cookies.set(COOKIE_NAME, planted)
        response = attacker.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/login"


def test_csrf_token_does_not_encode_the_session_token():
    """`itsdangerous` signs, it does not encrypt.

    The CSRF token is rendered into a hidden field on every page. If its payload
    were the session token, anyone who saw page source, a screenshot or a proxy
    log would recover the session cookie and `httponly` would mean nothing.
    """
    app = create_app(
        state=build_state(
            store=InMemoryLedgerStore(),
            password=PASSWORD,
            session_secret=SESSION_SECRET,
            seed=True,
        )
    )
    with TestClient(app, base_url="http://test") as c:
        html = c.get("/login").text
        token = csrf_token(html)
        session_cookie = c.cookies[COOKIE_NAME]

    payload = token.split(".")[0]
    decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    assert session_cookie.encode() not in decoded
    assert session_cookie not in token
