"""Dependency injection, auth/CSRF guards, and template rendering (ADR-0011).

`get_state` hands routes the runtime state; `require_auth` enforces login;
`require_csrf` enforces the per-session synchronizer token on state-changing
requests; `render` injects the CSRF token into every template with autoescape
on (invariant 11).
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from mandate.api import security
from mandate.api.state import AppState, Session

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


def get_state(request: Request) -> AppState:
    state = request.app.state.mandate
    assert isinstance(state, AppState)
    return state


def require_auth(request: Request, state: AppState = Depends(get_state)) -> Session:
    """Return the authenticated session, or redirect/reject.

    GET requests redirect to /login (307); state-changing requests are rejected
    (403). (ADR-0011)
    """
    session = security.get_session(state, request)
    if session is not None and session.authenticated:
        return session
    if request.method in ("GET", "HEAD"):
        raise HTTPException(
            status_code=307, headers={"Location": "/login"}, detail="login required"
        )
    raise HTTPException(status_code=403, detail="login required")


async def require_csrf(
    request: Request,
    state: AppState = Depends(get_state),
    _session: Session = Depends(require_auth),
) -> None:
    form = await request.form()
    submitted = str(form.get("csrf_token", ""))
    if not security.verify_csrf(state, request, submitted):
        raise HTTPException(status_code=400, detail="csrf token mismatch")


def render(request: Request, name: str, **context: object) -> HTMLResponse:
    state: AppState = request.app.state.mandate
    context = {
        **context,
        "csrf_token": security.csrf_token_for(state, request),
        "authenticated": security.is_authenticated(state, request),
    }
    return _templates.TemplateResponse(request, name, context)


def parse_minor(raw: str | None) -> int | None:
    """Parse a whole-dollar amount from the form into integer minor units.

    Decimal (never float) to keep money exact (invariant: integer minor units).
    Empty → None.
    """
    if raw is None or raw.strip() == "":
        return None
    text = raw.strip().replace("$", "").replace(",", "").replace(" ", "")
    try:
        dollars = Decimal(text)
    except InvalidOperation:
        raise ValueError("amount must be a whole-dollar number") from None
    if dollars != dollars.to_integral_value():
        raise ValueError("amount must be whole currency units")
    if dollars < 0:
        raise ValueError("amount must be non-negative")
    return int(dollars * 100)
