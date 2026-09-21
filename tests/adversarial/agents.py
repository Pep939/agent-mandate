"""Simulated agents that drive the live console over real HTTP (Phase 5).

Two roles, one surface:
- the *provider* proposes actions under its signed mandate (POST /propose);
- the *customer* is the counterparty and records boundary events
  (POST /boundary).

Either authenticated session can also act as the principal's delegate:
decide a pending approval or revoke the mandate. Agents scrape their
per-session CSRF token from rendered pages — they never read state or
secrets directly (that is what makes the tests end-to-end).
"""

from __future__ import annotations

import html as html_module
import re
from dataclasses import dataclass

import httpx

from mandate.api import boundary
from mandate.api.phrasing import OUTCOME_LABELS, REASON_SENTENCES
from mandate.domain.authority import ActionToken
from mandate.domain.decisions import Outcome, ReasonCode

_CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
_RESULT_RE = re.compile(
    r'<p style="font-size:1.2rem"><strong>(?P<outcome>[^<]+)</strong></p>\s*'
    r"<p>(?P<sentence>.*?)</p>",
    re.DOTALL,
)
_STATE_RE = re.compile(r'Current deal state: <span class="badge">([^<]+)</span>')
_DEAL_STATE_RE = re.compile(r"State: <span class=\"badge\">([^<]+)</span>")
_COMMITTED_RE = re.compile(r"Committed \(minor\): (\d+)")
_MANDATE_RE = re.compile(r"Mandate: ([^\n<]+)")
_APPROVAL_RE = re.compile(r"/approvals/([A-Z0-9]{26})/decision")


def mandate_kwargs(**overrides: object) -> dict[str, object]:
    """Full `make_signed_record` kwargs with permissive demo defaults, so
    misbehavior tests override only the field under attack."""
    defaults: dict[str, object] = {
        "agent_id": boundary.new_ulid(),
        "principal_id": boundary.new_ulid(),
        "purpose": "simulated mandate",
        "allowed_actions": [a.value for a in ActionToken],
        "spend_cap_currency": "USD",
        "spend_cap_minor": 1_000_000,
        "max_negotiation_rounds": 10,
        "expires_at": "2027-01-01T00:00:00+00:00",
        "requires_human_approval_for": ["capture_payment"],
    }
    defaults.update(overrides)
    return defaults


@dataclass(frozen=True)
class Decision:
    """One rendered console decision (propose or boundary)."""

    outcome: str  # console label: Allowed / Denied / Needs a person's approval / ...
    sentence: str  # reason sentence (propose) or commit detail (boundary)
    state: str  # deal state after the request
    html: str  # raw page, for deeper assertions

    @property
    def reason_code(self) -> ReasonCode | None:
        """The exact machine reason behind a policy decision, recovered from
        its plain-language sentence (None for boundary commits and gate
        blocks, which are not policy decisions)."""
        for code, sentence in REASON_SENTENCES.items():
            if sentence == self.sentence:
                return code
        return None

    @property
    def outcome_enum(self) -> Outcome | None:
        for outcome, label in OUTCOME_LABELS.items():
            if label == self.outcome:
                return outcome
        return None


@dataclass(frozen=True)
class DealView:
    """What the deal detail page shows at one instant."""

    deal_id: str
    state: str
    mandate_state: str
    committed_minor: int
    approval_ids: tuple[str, ...]
    html: str


class Agent:
    """One authenticated console session with a stable identity."""

    def __init__(self, base_url: str, password: str, name: str) -> None:
        self.name = name
        self.client = httpx.Client(base_url=base_url, follow_redirects=False, timeout=10)
        self._csrf: str | None = None
        self._login(password)

    def _login(self, password: str) -> None:
        token = _csrf(self.client.get("/login").text)
        response = self.client.post("/login", data={"password": password, "csrf_token": token})
        if response.status_code != 303:
            msg = f"{self.name}: login failed with {response.status_code}"
            raise AssertionError(msg)
        # the session token is regenerated on login, so scrape the live one
        self._csrf = _csrf(self.client.get("/").text)

    def _token(self) -> str:
        assert self._csrf is not None
        return self._csrf

    def view(self, deal_id: str) -> DealView:
        html = self.client.get(f"/deals/{deal_id}").text
        approval_ids = tuple(dict.fromkeys(_APPROVAL_RE.findall(html)))
        return DealView(
            deal_id=deal_id,
            state=_group(_DEAL_STATE_RE, html, self.name, "state"),
            mandate_state=_group(_MANDATE_RE, html, self.name, "mandate state"),
            committed_minor=int(_group(_COMMITTED_RE, html, self.name, "committed")),
            approval_ids=approval_ids,
            html=html,
        )

    def propose(self, deal_id: str, action: str, amount_dollars: str | None = None) -> Decision:
        data: dict[str, str] = {"action": action, "csrf_token": self._token()}
        if amount_dollars is not None:
            data["amount_dollars"] = amount_dollars
        response = self.client.post(f"/deals/{deal_id}/propose", data=data)
        if response.status_code >= 400:
            msg = f"{self.name}: propose {action!r} -> {response.status_code} {response.text[:200]}"
            raise AssertionError(msg)
        return _decision(response.text, self.name)

    def boundary(self, deal_id: str, event: str) -> Decision:
        response = self.client.post(
            f"/deals/{deal_id}/boundary", data={"event": event, "csrf_token": self._token()}
        )
        if response.status_code >= 400:
            msg = f"{self.name}: boundary {event!r} -> {response.status_code} {response.text[:200]}"
            raise AssertionError(msg)
        return _decision(response.text, self.name)

    def grant(self, deal_id: str, approval_id: str) -> int:
        return self._decide(deal_id, approval_id, "granted")

    def deny(self, deal_id: str, approval_id: str, reason: str = "Denied by operator") -> int:
        response = self.client.post(
            f"/deals/{deal_id}/approvals/{approval_id}/decision",
            data={
                "operation": "denied",
                "deny_reason": reason,
                "csrf_token": self._token(),
            },
        )
        if response.status_code not in (303,):
            msg = f"{self.name}: deny {approval_id} -> {response.status_code} {response.text[:200]}"
            raise AssertionError(msg)
        return response.status_code

    def _decide(self, deal_id: str, approval_id: str, operation: str) -> int:
        response = self.client.post(
            f"/deals/{deal_id}/approvals/{approval_id}/decision",
            data={"operation": operation, "csrf_token": self._token()},
        )
        if response.status_code != 303:
            msg = (
                f"{self.name}: {operation} {approval_id} -> "
                f"{response.status_code} {response.text[:200]}"
            )
            raise AssertionError(msg)
        return response.status_code

    def revoke(self, deal_id: str) -> int:
        response = self.client.post(f"/deals/{deal_id}/revoke", data={"csrf_token": self._token()})
        if response.status_code != 303:
            msg = f"{self.name}: revoke -> {response.status_code} {response.text[:200]}"
            raise AssertionError(msg)
        return response.status_code

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> Agent:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def run_to_acceptance_window(provider: Agent, customer: Agent, deal_id: str) -> None:
    """Default-mandate lifecycle: DRAFT to ACCEPTANCE_WINDOW, two agents."""
    d = provider.propose(deal_id, "request_quote")
    assert d.state == "QUOTE_REQUESTED", (d.outcome, d.sentence)
    d = customer.boundary(deal_id, "quote_received")
    assert d.state == "QUOTE_RECEIVED", (d.outcome, d.sentence)
    d = provider.propose(deal_id, "accept_agreement", "500")
    assert d.state == "AGREED", (d.outcome, d.sentence)
    d = provider.propose(deal_id, "start_work")
    assert d.state == "IN_PROGRESS", (d.outcome, d.sentence)
    d = customer.boundary(deal_id, "completion_claimed")
    assert d.state == "COMPLETED", (d.outcome, d.sentence)
    d = customer.boundary(deal_id, "acceptance_window_opened")
    assert d.state == "ACCEPTANCE_WINDOW", (d.outcome, d.sentence)


def run_to_open_capture_approval(provider: Agent, customer: Agent, deal_id: str) -> str:
    """Full lifecycle up to a pending capture_payment approval; returns its id."""
    run_to_acceptance_window(provider, customer, deal_id)
    d = customer.boundary(deal_id, "accepted")
    assert d.state == "ACCEPTED", (d.outcome, d.sentence)
    d = provider.propose(deal_id, "initiate_payment")
    assert d.state == "PAYMENT_PENDING", (d.outcome, d.sentence)
    d = provider.propose(deal_id, "capture_payment")
    assert d.outcome == "Needs a person's approval", (d.outcome, d.sentence)
    (approval_id,) = customer.view(deal_id).approval_ids
    return approval_id


def _csrf(html: str) -> str:
    match = _CSRF_RE.search(html)
    assert match is not None, "no csrf token in response"
    return match.group(1)


def _group(regex: re.Pattern[str], html: str, agent: str, what: str) -> str:
    match = regex.search(html)
    assert match is not None, f"{agent}: no {what!r} in page"
    return match.group(1).strip()


def _decision(html: str, agent: str) -> Decision:
    match = _RESULT_RE.search(html)
    assert match is not None, f"{agent}: no rendered decision in page"
    state_match = _STATE_RE.search(html)
    assert state_match is not None, f"{agent}: no deal state in page"
    # autoescape renders "person's" as "person&#39;s" — unescape before
    # comparing against the console's own labels and sentences
    return Decision(
        outcome=html_module.unescape(match.group("outcome").strip()),
        sentence=html_module.unescape(match.group("sentence").strip()),
        state=state_match.group(1).strip(),
        html=html,
    )
