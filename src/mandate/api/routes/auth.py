"""Login / logout (ADR-0011).

The operator password is compared in constant time (security.check_password).
On success the anonymous session is flipped to authenticated in place; on
failure the login form re-renders with a 401 and the session stays anonymous.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from mandate.api import security
from mandate.api.deps import get_state, render, require_auth
from mandate.api.state import AppState, Session

router = APIRouter()


@router.get("/login")
async def login_get(request: Request, state: AppState = Depends(get_state)) -> Response:
    return render(request, "login.html", error=None)


@router.post("/login")
async def login_post(request: Request, state: AppState = Depends(get_state)) -> Response:
    form = await request.form()
    if not security.verify_csrf(state, request, str(form.get("csrf_token", ""))):
        raise HTTPException(status_code=400, detail="csrf token mismatch")
    if not security.check_password(state, str(form.get("password", ""))):
        response = render(request, "login.html", error="Wrong password.")
        response.status_code = 401
        return response
    if not security.authenticate_session(state, request):
        raise HTTPException(status_code=500, detail="no session to authenticate")
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
async def logout(
    request: Request,
    state: AppState = Depends(get_state),
    _session: Session = Depends(require_auth),
) -> Response:
    security.destroy_session(state, request)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(security.COOKIE_NAME)
    return response
