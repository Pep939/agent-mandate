"""Drive the shadow scenario through the real console + policy + ledger stack.

`run_shadow_pilot` builds a fresh in-memory console, logs in as the operator,
and plays every scripted step over real HTTP (starlette TestClient) against the
live FastAPI app: the boundary assembles the signed claim, the engine decides,
the single writer commits, and the approval lifecycle opens and closes.

Nothing is auto-approved: every NEEDS_APPROVAL is resolved by an explicit
principal grant or deny, and no payment provider is involved. Capture is
authorization + recording only - real money movement is Phase 8.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

from mandate.api import boundary
from mandate.api.app import build_state, create_app
from mandate.api.state import AppState
from mandate.domain.approvals import ApprovalStatus
from mandate.domain.authority import ActionToken
from mandate.ledger.store import InMemoryLedgerStore
from mandate.pilot.scenario import SHADOW_DEALS, DealSpec, Step
from mandate.screen.fixture import FixtureScreen

_CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@dataclass(frozen=True)
class Intervention:
    """A human (principal/operator) authority decision the pilot made on purpose."""

    deal_name: str
    actor: str
    action: str
    detail: str


@dataclass
class PilotRun:
    """Everything the report needs: the ledger, the chain key, and the journal."""

    store: InMemoryLedgerStore
    public_key: Ed25519PublicKey
    deals: tuple[DealSpec, ...]
    deal_ids: dict[str, str]
    interventions: list[Intervention] = field(default_factory=list)


class _Console:
    """A logged-in operator driving the console over HTTP."""

    def __init__(self, client: TestClient, state: AppState, password: str) -> None:
        self.client = client
        self.state = state
        self.csrf = self._login(password)

    def _login(self, password: str) -> str:
        token = self._csrf_token(self.client.get("/login").text)
        r = self.client.post(
            "/login",
            data={"password": password, "csrf_token": token},
            follow_redirects=False,
        )
        if r.status_code != 303:
            msg = f"login failed: {r.status_code}"
            raise RuntimeError(msg)
        return self._csrf_token(self.client.get("/").text)

    @staticmethod
    def _csrf_token(html: str) -> str:
        match = _CSRF_RE.search(html)
        if match is None:
            msg = "no csrf token in page"
            raise RuntimeError(msg)
        return match.group(1)

    def _post(self, url: str, data: dict[str, str]) -> int:
        r = self.client.post(url, data={**data, "csrf_token": self.csrf}, follow_redirects=False)
        return int(r.status_code)

    def propose(
        self,
        deal_id: str,
        action: str,
        amount_dollars: str | None,
        content: str = "",
        declared_fields: tuple[str, ...] = (),
    ) -> None:
        data = {"action": action}
        if amount_dollars is not None:
            data["amount_dollars"] = amount_dollars
        if content:
            data["content"] = content
        if declared_fields:
            data["disclosure_fields"] = ",".join(declared_fields)
        status = self._post(f"/deals/{deal_id}/propose", data)
        if status != 200:
            msg = f"propose {action!r} -> {status}"
            raise RuntimeError(msg)

    def boundary(self, deal_id: str, event: str, content: str = "") -> None:
        data = {"event": event}
        if content:
            data["note"] = content
        status = self._post(f"/deals/{deal_id}/boundary", data)
        if status != 200:
            msg = f"boundary {event!r} -> {status}"
            raise RuntimeError(msg)

    def _pending_approval_id(self, deal_id: str) -> str:
        pending = [
            a for a in self.state.store.approvals_for(deal_id) if a.status is ApprovalStatus.PENDING
        ]
        if len(pending) != 1:
            msg = f"expected exactly 1 pending approval, got {len(pending)}"
            raise RuntimeError(msg)
        return pending[0].approval_id

    def decide(self, deal_id: str, operation: str, deny_reason: str | None) -> None:
        approval_id = self._pending_approval_id(deal_id)
        data = {"operation": operation}
        if deny_reason:
            data["deny_reason"] = deny_reason
        status = self._post(f"/deals/{deal_id}/approvals/{approval_id}/decision", data)
        if status != 303:
            msg = f"decide {operation!r} -> {status}"
            raise RuntimeError(msg)

    def revoke(self, deal_id: str) -> None:
        status = self._post(f"/deals/{deal_id}/revoke", {})
        if status != 303:
            msg = f"revoke -> {status}"
            raise RuntimeError(msg)


def _execute(
    console: _Console,
    deal: DealSpec,
    deal_id: str,
    step: Step,
    interventions: list[Intervention],
) -> None:
    if step.kind == "propose":
        assert step.action is not None
        console.propose(
            deal_id, step.action, step.amount_dollars, step.content, step.declared_fields
        )
    elif step.kind == "boundary":
        assert step.event is not None
        console.boundary(deal_id, step.event, step.content)
        if step.note:
            interventions.append(
                Intervention(deal.name, step.actor, f"boundary:{step.event}", step.note)
            )
    elif step.kind == "grant":
        console.decide(deal_id, "granted", None)
        interventions.append(
            Intervention(
                deal.name, "principal", "grant", step.note or "granted the pending approval"
            )
        )
    elif step.kind == "deny":
        console.decide(deal_id, "denied", step.deny_reason or "Denied by operator")
        interventions.append(
            Intervention(
                deal.name,
                "principal",
                "deny",
                step.note or step.deny_reason or "denied the pending approval",
            )
        )
    elif step.kind == "revoke":
        console.revoke(deal_id)
        interventions.append(
            Intervention(deal.name, "principal", "revoke", step.note or "revoked the mandate")
        )
    else:
        msg = f"unknown step kind {step.kind!r}"
        raise RuntimeError(msg)


def run_shadow_pilot(deals: tuple[DealSpec, ...] = SHADOW_DEALS) -> PilotRun:
    """Mint a mandate per deal, then play every step over HTTP. Returns the run."""
    password = secrets.token_urlsafe(16)
    session_secret = secrets.token_urlsafe(32)
    store = InMemoryLedgerStore()
    # ADR-0016: the pilot runs on the deterministic fixture screen, never a
    # vendor — the run must be reproducible and must not need a network or
    # an API key. Swapping in `TypeSafeScreen` changes only this line.
    state = build_state(
        store=store,
        password=password,
        session_secret=session_secret,
        seed=False,
        screen=FixtureScreen(),
    )
    app = create_app(state=state, seed=False)

    deal_ids: dict[str, str] = {}
    interventions: list[Intervention] = []
    now = boundary.now_iso()

    with TestClient(app, base_url="http://test") as client:
        console = _Console(client, state, password)
        for deal in deals:
            deal_id = boundary.new_ulid()
            record = boundary.make_signed_record(
                state,
                now=now,
                agent_id=boundary.new_ulid(),
                principal_id=boundary.new_ulid(),
                purpose=deal.mandate.purpose,
                allowed_actions=[a.value for a in ActionToken],
                prohibited_actions=list(deal.mandate.prohibited_actions),
                spend_cap_currency="USD",
                spend_cap_minor=deal.mandate.spend_cap_minor,
                max_negotiation_rounds=deal.mandate.max_negotiation_rounds,
                expires_at=deal.mandate.expires_at,
                requires_human_approval_for=list(deal.mandate.requires_human_approval_for),
                disclosure_fields=list(deal.mandate.disclosure_fields),
            )
            boundary.register_deal(state, deal_id, record, now)
            deal_ids[deal.name] = deal_id
            for step in deal.steps:
                _execute(console, deal, deal_id, step, interventions)

    return PilotRun(
        store=store,
        public_key=state.signer.public_key,
        deals=deals,
        deal_ids=deal_ids,
        interventions=interventions,
    )
