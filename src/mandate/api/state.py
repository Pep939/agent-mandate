"""Runtime state for the console boundary (ADR-0011).

Process-lifetime. Holds the ledger store, the runtime-only gateway signer, the
server-side session table, and the operator/session secrets. The secrets live
here so the security functions can use them, but the state object is never
rendered into a template or logged — only derived, safe values reach a response
(invariant 12).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mandate.crypto.signing import GatewaySigner
from mandate.domain.content import ContentClaims
from mandate.ledger.store import LedgerStore
from mandate.screen.protocol import ContentScreen


@dataclass
class Session:
    """One server-side session. `csrf_token` is a per-session synchronizer
    token (regenerated on login); `authenticated` flips on successful login."""

    csrf_token: str
    authenticated: bool = False


@dataclass
class AppState:
    store: LedgerStore
    signer: GatewaySigner
    operator_id: str
    operator_password: str  # runtime-only (invariant 12); never rendered or logged
    session_secret: str  # runtime-only (invariant 12); signs session/CSRF tokens
    sessions: dict[str, Session] = field(default_factory=dict)
    deal_ids: list[str] = field(default_factory=list)  # boundary-side deal registry
    deal_records: dict[str, str] = field(default_factory=dict)  # deal_id -> record_id
    screen: ContentScreen | None = None
    """The content screen (ADR-0016), or None when screening is off. Content
    sent with no screen still holds for a person — never treated as clean."""
    screen_claims: dict[str, ContentClaims] = field(default_factory=dict)
    """approval_id -> the screen's claims for the proposal that opened it, so
    the console can badge the approval queue. Advisory display only: the
    authoritative copy is the signed MESSAGE event in the ledger."""
