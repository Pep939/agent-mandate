"""Helpers to drive the console through a TestClient (ADR-0011 tests)."""

from __future__ import annotations

import re

from fastapi import FastAPI
from fastapi.testclient import TestClient

_CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
_DEAL_RE = re.compile(r"/deals/([A-Z0-9]{26})")
_APPROVAL_RE = re.compile(r"/approvals/([A-Z0-9]{26})/decision")


def csrf_token(html: str) -> str:
    match = _CSRF_RE.search(html)
    assert match is not None, "no csrf token in response"
    return match.group(1)


def first_deal_id(html: str) -> str:
    match = _DEAL_RE.search(html)
    assert match is not None, "no deal id in response"
    return match.group(1)


def first_approval_id(html: str) -> str:
    match = _APPROVAL_RE.search(html)
    assert match is not None, "no approval id in response"
    return match.group(1)


def login(client: TestClient, password: str) -> None:
    html = client.get("/login").text
    response = client.post(
        "/login",
        data={"password": password, "csrf_token": csrf_token(html)},
        follow_redirects=False,
    )
    assert response.status_code == 303, f"login failed: {response.status_code}"


def make_logged_in_client(app: FastAPI, password: str) -> TestClient:
    client = TestClient(app, base_url="http://test")
    with client:
        login(client, password)
        return client
