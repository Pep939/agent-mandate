"""Run two simulated agents against a live console and narrate the outcome.

Spins up the real FastAPI console (uvicorn, in-process, ephemeral port) with
an in-memory ledger, then drives it over real HTTP:

  1. the *provider* proposes a quote request under its signed mandate — allowed;
  2. the *customer* (counterparty) records the incoming quote — boundary event;
  3. the provider proposes a $2,500 agreement against a $1,000 spend cap —
     escalated to a person, not authorized;
  4. the principal grants the approval over HTTP — the deal is agreed;
  5. the provider misbehaves: a stale action, then one more proposal after the
     principal revokes the mandate — both denied;
  6. the whole event chain is independently verified and printed.

Secrets are generated at startup (invariant 12) — nothing here is a
committed default.

Usage:
  uv run scripts/sim_agents.py

Exit codes: 0 = the expected demo played out, 1 = something unexpected.
"""

from __future__ import annotations

import html as html_module
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass

import httpx
import uvicorn

from mandate.api import boundary
from mandate.api.app import build_state, create_app
from mandate.domain.authority import ActionToken
from mandate.ledger.chain import verify_chain
from mandate.ledger.store import InMemoryLedgerStore

_CSRE_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
_RESULT_RE = re.compile(
    r'<p style="font-size:1.2rem"><strong>(?P<outcome>[^<]+)</strong></p>\s*'
    r"<p>(?P<sentence>.*?)</p>",
    re.DOTALL,
)
_STATE_RE = re.compile(r'Current deal state: <span class="badge">([^<]+)</span>')


@dataclass
class Step:
    outcome: str
    sentence: str
    state: str


class SimAgent:
    """One authenticated console session (the simulation's stand-in for an
    agent / counterparty / principal)."""

    def __init__(self, base_url: str, password: str, name: str) -> None:
        self.name = name
        self.client = httpx.Client(base_url=base_url, follow_redirects=False, timeout=10)
        token = _csrf(self.client.get("/login").text)
        response = self.client.post("/login", data={"password": password, "csrf_token": token})
        if response.status_code != 303:
            msg = f"{name}: login failed ({response.status_code})"
            raise RuntimeError(msg)
        self._csrf = _csrf(self.client.get("/").text)  # regenerated on login

    def _post(self, url: str, data: dict[str, str]) -> Step:
        data = {**data, "csrf_token": self._csrf}
        response = self.client.post(url, data=data)
        if response.status_code != 200:
            msg = f"{self.name}: POST {url} -> {response.status_code}"
            raise RuntimeError(msg)
        return _step(response.text, self.name)

    def propose(self, deal_id: str, action: str, amount_dollars: str | None = None) -> Step:
        data = {"action": action}
        if amount_dollars is not None:
            data["amount_dollars"] = amount_dollars
        return self._post(f"/deals/{deal_id}/propose", data)

    def boundary(self, deal_id: str, event: str) -> Step:
        return self._post(f"/deals/{deal_id}/boundary", {"event": event})

    def grant(self, deal_id: str, approval_id: str) -> None:
        response = self.client.post(
            f"/deals/{deal_id}/approvals/{approval_id}/decision",
            data={"operation": "granted", "csrf_token": self._csrf},
        )
        if response.status_code != 303:
            msg = f"{self.name}: grant -> {response.status_code}"
            raise RuntimeError(msg)

    def revoke(self, deal_id: str) -> None:
        response = self.client.post(f"/deals/{deal_id}/revoke", data={"csrf_token": self._csrf})
        if response.status_code != 303:
            msg = f"{self.name}: revoke -> {response.status_code}"
            raise RuntimeError(msg)

    def first_approval_id(self, deal_id: str) -> str | None:
        html = self.client.get(f"/deals/{deal_id}").text
        match = re.search(r"/approvals/([A-Z0-9]{26})/decision", html)
        return match.group(1) if match else None


def _csrf(page: str) -> str:
    match = _CSRE_RE.search(page)
    if match is None:
        msg = "no csrf token in page"
        raise RuntimeError(msg)
    return match.group(1)


def _step(html: str, name: str) -> Step:
    result = _RESULT_RE.search(html)
    state = _STATE_RE.search(html)
    if result is None or state is None:
        msg = f"{name}: could not parse the rendered decision"
        raise RuntimeError(msg)
    return Step(
        outcome=html_module.unescape(result.group("outcome").strip()),
        sentence=html_module.unescape(result.group("sentence").strip()),
        state=state.group(1).strip(),
    )


def _say(actor: str, step: Step) -> None:
    print(f"  {actor:<10} -> {step.outcome}: {step.sentence}  [deal: {step.state}]")


def main() -> int:
    password = secrets.token_urlsafe(16)
    session_secret = secrets.token_urlsafe(32)
    state = build_state(
        store=InMemoryLedgerStore(),
        password=password,
        session_secret=session_secret,
        seed=False,
    )
    app = create_app(state=state, seed=False)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            print("console did not start in time", file=sys.stderr)
            return 1
        time.sleep(0.01)
    base_url = f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
    print(f"console listening on {base_url}\n")

    try:
        # $1,000 cap so the over-cap proposal escalates
        deal_id = boundary.new_ulid()
        record = boundary.make_signed_record(
            state,
            now=boundary.now_iso(),
            agent_id=boundary.new_ulid(),
            principal_id=boundary.new_ulid(),
            purpose="Simulation mandate: $1,000 cap",
            allowed_actions=[a.value for a in ActionToken],
            spend_cap_currency="USD",
            spend_cap_minor=100_000,
            max_negotiation_rounds=10,
            expires_at="2027-01-01T00:00:00+00:00",
            requires_human_approval_for=["capture_payment"],
        )
        boundary.register_deal(state, deal_id, record, boundary.now_iso())

        provider = SimAgent(base_url, password, "provider")
        customer = SimAgent(base_url, password, "customer")
        principal = SimAgent(base_url, password, "principal")

        print("1. the provider works under its mandate")
        _say("provider", provider.propose(deal_id, "request_quote"))
        _say("customer", customer.boundary(deal_id, "quote_received"))

        print("\n2. over the $1,000 cap: escalation, not authorization")
        _say("provider", provider.propose(deal_id, "accept_agreement", "2,500"))
        approval_id = principal.first_approval_id(deal_id)
        if approval_id is None:
            print("expected an open approval", file=sys.stderr)
            return 1
        principal.grant(deal_id, approval_id)
        print("  principal  -> granted the approval (signed one-time record)")

        print("\n3. the provider misbehaves")
        _say("provider", provider.propose(deal_id, "request_quote"))
        principal.revoke(deal_id)
        print("  principal  -> revoked the mandate (signed revocation)")
        _say("provider", provider.propose(deal_id, "counteroffer", "100"))

        events = state.store.events_for(deal_id)
        report = verify_chain(events, state.signer.public_key)
        print(
            f"\nevent chain: {len(events)} events, verification: "
            f"{'OK' if report.ok else report.first_failure()}"
        )
        last = events[-1].payload
        ok = (
            report.ok
            and last.get("outcome") == "deny"
            and last.get("reason_code") == "record_revoked"
        )
        return 0 if ok else 1
    finally:
        server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
