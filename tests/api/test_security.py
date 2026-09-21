"""Authentication, CSRF, and secret handling (ADR-0011)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from mandate.api.app import build_state, create_app
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
