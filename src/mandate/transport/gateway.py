"""The wire gateway: the second I/O boundary (ADR-0012).

A separate FastAPI app from the operator console (`mandate.api`). It exposes
one endpoint, `POST /messages`, whose pipeline is verify-first:

    size → JSON shape → envelope model → recipient → sender registered →
    signature → payload shape → idempotency → kind dispatch → answer.

Each failed stage returns a structured 4xx and commits nothing (invariant 14,
ADR-0007 at wire level). A processed message gets a signed `receipt` envelope
in the response body (invariant 15). The peer endpoint has no operator auth —
the message signature is the auth (ADR-0012).
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mandate.application.anti_replay import GateOutcome
from mandate.application.claims import build_claim
from mandate.application.screening import screen_content
from mandate.application.services import process_request
from mandate.crypto.signing import GatewaySigner, b64url_decode, gateway_signer
from mandate.domain.authority import AuthorityRecord
from mandate.domain.deals import Deal, DealEvent, DealState
from mandate.domain.decisions import PolicyDecision
from mandate.domain.input import Actor, ActorKind, Counterparty, PolicyInput, Proposal
from mandate.ledger.store import CommitOutcome, LedgerStore, TransitionRequest
from mandate.screen.config import screen_from_env
from mandate.screen.protocol import ContentScreen
from mandate.transport.dedup import DedupVerdict, StoredAnswer, WireDedup
from mandate.transport.envelope import (
    CounterpartyEventPayload,
    EnvelopeError,
    GatewayIdentity,
    MessageKind,
    ProposalPayload,
    ReceiptOutcome,
    ReceiptPayload,
    WireEnvelope,
    envelope_fingerprint,
    envelope_is_stale,
    load_peer_identity,
    make_envelope,
    parse_payload,
    verify_envelope,
)

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# Verify-first stage 1: reject oversized bodies before any parsing (ADR-0012).
MAX_BODY_BYTES = 64 * 1024

# Log keys whose values must never reach a log line (invariant 12).
_SENSITIVE_KEYS = frozenset(
    {"password", "passwd", "secret", "seed", "private", "token", "authorization"}
)
_REDACTED = "***redacted***"

__all__ = [
    "GatewayState",
    "RedactingJsonFormatter",
    "build_gateway_state",
    "configure_gateway_logging",
    "create_gateway_app",
    "load_chain_signer",
    "load_identity",
    "load_peers",
    "max_age_from_env",
    "new_ulid",
    "now_iso",
    "register_deal",
    "require_env",
]


def new_ulid() -> str:
    """Boundary clock/entropy: a fresh ULID (the pure core never calls this)."""
    rng = random.SystemRandom()
    ts = int(time.time() * 1000)
    out = []
    for _ in range(10):
        out.append(CROCKFORD[ts % 32])
        ts //= 32
    for _ in range(16):
        out.append(CROCKFORD[rng.getrandbits(5)])
    return "".join(out)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def require_env(name: str) -> str:
    """Read a required environment variable; `ValueError` when absent/blank."""
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise ValueError(f"{name} is required")
    return value


def max_age_from_env(raw: str | None) -> int | None:
    """`MANDATE_ENVELOPE_MAX_AGE_SECONDS` → window in seconds, or `None` off.

    `0`/`off`/`none`/`disabled`/blank disables the first-seen freshness window
    (dedup + hostile replay stay active — they do not depend on this).
    """
    if raw is None or raw.strip().lower() in {"", "0", "off", "none", "disabled"}:
        return None
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(
            f"MANDATE_ENVELOPE_MAX_AGE_SECONDS must be an integer (got {raw!r})"
        ) from None
    return value if value > 0 else None


class RedactingJsonFormatter(logging.Formatter):
    """One JSON object per line. Any dict value under a sensitive key name is
    replaced before serialization (invariant 12)."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        data = getattr(record, "log", None)
        if isinstance(data, dict):
            entry.update(self._redact(data))
        return json.dumps(entry, sort_keys=True, default=str)

    def _redact(self, data: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, dict):
                out[key] = self._redact(value)
            elif key.lower() in _SENSITIVE_KEYS:
                out[key] = _REDACTED
            else:
                out[key] = value
        return out


def configure_gateway_logging(level: str = "INFO") -> None:
    """JSON-line structured logging for the gateway process (C1)."""
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingJsonFormatter())
    logging.root.handlers[:] = [handler]
    logging.root.setLevel(level.upper())


def load_identity(path: Path) -> GatewayIdentity:
    """Load this gateway's wire identity from a key file (C1 key custody).

    Same JSON shape as `scripts/dev_keys.py`: `key_id`, `public_key` and
    `private_seed` (base64url, unpadded). The stored public key must match
    the one derived from the seed, or the file is corrupt or tampered with.
    The seed never leaves this call (invariant 12).
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        identity = GatewayIdentity.from_seed(
            payload["key_id"], b64url_decode(payload["private_seed"])
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise EnvelopeError(f"cannot load gateway identity from {path}: {exc}") from exc
    if payload.get("public_key") not in (None, identity.public_key_b64url):
        raise EnvelopeError(f"identity file {path}: stored public key does not match the seed")
    return identity


def load_chain_signer(path: Path) -> GatewaySigner:
    """Load the ledger event-chain key from a key file (C1 key custody).

    Same JSON shape as `load_identity`. Distinct from the wire identity key
    (ADR-0012): the chain key signs events, the identity key signs envelopes.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return gateway_signer(payload["key_id"], b64url_decode(payload["private_seed"]))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise EnvelopeError(f"cannot load chain key from {path}: {exc}") from exc


def load_peers(path: Path) -> dict[str, GatewayIdentity]:
    """Load the pre-shared peer registry (ADR-0012 known-hosts, no PKI).

    JSON object mapping `identity_id` → `{"identity_id", "public_key"}`
    (base64url, unpadded). Peers are verify-only: their seeds are not held.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        entries = list(raw.items())
    except (OSError, ValueError, AttributeError) as exc:
        raise EnvelopeError(f"cannot load peer registry from {path}: {exc}") from exc
    peers: dict[str, GatewayIdentity] = {}
    for identity_id, entry in entries:
        try:
            peer = load_peer_identity(
                str(entry.get("identity_id", identity_id)), str(entry["public_key"])
            )
        except (KeyError, TypeError) as exc:
            raise EnvelopeError(f"peer registry entry {identity_id!r} is malformed: {exc}") from exc
        if peer.identity_id != identity_id:
            raise EnvelopeError(
                f"peer registry entry {identity_id!r} declares a different identity_id"
            )
        peers[identity_id] = peer
    return peers


@dataclass
class GatewayState:
    """Runtime state for the wire boundary (process-lifetime, invariant 12).

    `identity` holds this gateway's wire key; `signer` is the separate ledger
    event-chain key (ADR-0012: identity key != chain key). `peers` are the
    pre-shared counterparty identities we trust. `max_age_seconds` bounds how
    old a first-seen envelope's `issued_at` may be (None disables the
    freshness check).
    """

    identity: GatewayIdentity
    signer: GatewaySigner
    store: LedgerStore
    dedup: WireDedup
    peers: dict[str, GatewayIdentity] = field(default_factory=dict)
    deal_ids: list[str] = field(default_factory=list)
    deal_records: dict[str, str] = field(default_factory=dict)  # deal_id -> record_id
    max_age_seconds: int | None = None
    screen: ContentScreen | None = None
    """The content screen (ADR-0016), or None when screening is off. Content
    that arrives with no screen configured is held for a person, never
    treated as clean."""


def build_gateway_state(
    *,
    identity: GatewayIdentity,
    signer: GatewaySigner,
    store: LedgerStore,
    dedup: WireDedup,
    peers: dict[str, GatewayIdentity] | None = None,
    max_age_seconds: int | None = None,
    screen: ContentScreen | None = None,
) -> GatewayState:
    state = GatewayState(
        identity=identity,
        signer=signer,
        store=store,
        dedup=dedup,
        peers=dict(peers or {}),
        max_age_seconds=max_age_seconds,
        screen=screen if screen is not None else screen_from_env(),
    )
    # Rebuild the deal → mandate registry from the store so a restarted
    # process keeps pre-existing deals actionable (C1).
    links = store.list_deal_links()
    state.deal_ids = list(links)
    state.deal_records = dict(links)
    return state


def register_deal(
    state: GatewayState, deal_id: str, record: AuthorityRecord, created_at: str
) -> None:
    """Register a deal + its mandate in this gateway's ledger (idempotent)."""
    deal = Deal(
        deal_id=deal_id,
        state=DealState.DRAFT,
        negotiated_rounds=0,
        committed_minor=0,
        open_disputes=0,
        open_approvals=0,
    )
    state.store.create_deal(deal, created_at)
    state.store.put_record(record)
    state.store.link_deal_record(deal_id, record.record_id, created_at)
    if deal_id not in state.deal_ids:
        state.deal_ids.append(deal_id)
    state.deal_records[deal_id] = record.record_id


def _error(status: int, error: str) -> tuple[int, dict[str, object]]:
    return status, {"error": error}


def _receipt(
    state: GatewayState,
    env: WireEnvelope,
    *,
    outcome: ReceiptOutcome,
    status: int,
    events: tuple[str, ...] = (),
    reason: str | None = None,
    decision: PolicyDecision | None = None,
) -> WireEnvelope:
    payload = ReceiptPayload(
        responds_to=env.message_id,
        outcome=outcome,
        status=status,
        events=list(events),
        reason=reason,
        decision=decision.model_dump(mode="json") if decision is not None else None,
    )
    return make_envelope(
        kind=MessageKind.RECEIPT,
        payload=payload,
        sender=state.identity,
        recipient_id=env.sender_id,
        message_id=new_ulid(),
        idempotency_key=new_ulid(),
        issued_at=now_iso(),
    )


def _accepted(
    state: GatewayState,
    env: WireEnvelope,
    *,
    events: tuple[str, ...] = (),
    reason: str | None = None,
    decision: PolicyDecision | None = None,
) -> tuple[int, dict[str, object]]:
    receipt = _receipt(
        state,
        env,
        outcome=ReceiptOutcome.ACCEPTED,
        status=200,
        events=events,
        reason=reason,
        decision=decision,
    )
    return 200, {"outcome": "accepted", "receipt": receipt.model_dump(mode="json")}


def _handle_proposal(
    state: GatewayState, env: WireEnvelope, payload: ProposalPayload
) -> tuple[int, dict[str, object]]:
    record_id = state.deal_records.get(payload.deal_id)
    record = state.store.get_record(record_id) if record_id else None
    deal = state.store.get_deal(payload.deal_id)
    if record is None or deal is None:
        return _error(404, f"deal {payload.deal_id} is not known to this gateway")
    # Wire-level audience check: an audience-restricted mandate is only
    # actionable by the registered counterparty (engine step 5 is the backstop).
    if record.counterparty_id is not None and record.counterparty_id != env.sender_id:
        return _error(
            403,
            f"sender {env.sender_id} is not the counterparty {record.counterparty_id} "
            "named by this deal's mandate",
        )
    now = now_iso()
    claim = build_claim(state.store, state.signer, record, now=now)
    # ADR-0016: content off the wire is untrusted text. It is screened here,
    # at the boundary; only its digest and the screen's claims go further.
    screened = screen_content(state.screen, payload.content)
    pi = PolicyInput(
        schema_version="0.1",
        request_id=new_ulid(),
        now=now,
        actor=Actor(kind=ActorKind.AGENT, id=record.agent_id),
        authority=claim,
        counterparty=Counterparty(id=record.counterparty_id),
        deal=deal,
        proposal=Proposal(
            action=payload.action,
            deal_id=payload.deal_id,
            amount_minor=payload.amount_minor,
            currency=record.spend_cap.currency,
            disclosure_fields=list(payload.disclosure_fields),
            idempotency_key=env.idempotency_key,
            content_sha256=screened.digest if screened is not None else None,
        ),
        content=screened.claims if screened is not None else None,
    )
    result = process_request(pi, state.store, state.signer, recorded_at=now)
    if result.verdict.outcome is GateOutcome.IDEMPOTENT_HIT:
        return _accepted(
            state,
            env,
            reason="this exact proposal was already handled; the original decision stands",
            decision=result.decision,
        )
    if result.verdict.outcome is not GateOutcome.PASS:
        return _error(400, f"blocked by the replay gate: {result.verdict.detail}")
    assert result.decision is not None
    return _accepted(state, env, reason=result.decision.explanation, decision=result.decision)


def _handle_counterparty_event(
    state: GatewayState, env: WireEnvelope, payload: CounterpartyEventPayload
) -> tuple[int, dict[str, object]]:
    deal = state.store.get_deal(payload.deal_id)
    if deal is None:
        return _error(404, f"deal {payload.deal_id} is not known to this gateway")
    record_id = state.deal_records.get(payload.deal_id)
    record = state.store.get_record(record_id) if record_id else None
    if (
        record is not None
        and record.counterparty_id is not None
        and (record.counterparty_id != env.sender_id)
    ):
        return _error(
            403,
            f"sender {env.sender_id} is not the counterparty {record.counterparty_id} "
            "named by this deal's mandate",
        )
    try:
        event = DealEvent(payload.event)
    except ValueError:
        return _error(400, f"unknown counterparty event {payload.event!r}")
    now = now_iso()
    screened = screen_content(state.screen, payload.note)
    req = TransitionRequest(
        deal_id=payload.deal_id,
        command_id=env.message_id,  # transition-level dedup backstop (ADR-0009)
        event=event,
        actor_kind=ActorKind.COUNTERPARTY,
        actor_id=env.sender_id,
        authority_record_id=None,
        amount_minor=None,
        occurred_at=env.issued_at,
        recorded_at=now,
        note=payload.note,
        content_sha256=screened.digest if screened is not None else None,
        content=screened.claims if screened is not None else None,
    )
    result = state.store.commit_transition(req, state.signer)
    if result.outcome is CommitOutcome.ALREADY_APPLIED:
        return _accepted(state, env, reason=result.detail)
    if result.outcome is not CommitOutcome.COMMITTED:
        return _error(409, f"counterparty event not applied: {result.detail}")
    return _accepted(state, env, events=tuple(e.event_id for e in result.events))


Handler = Callable[[GatewayState, WireEnvelope, Any], tuple[int, dict[str, object]]]

_HANDLERS: dict[MessageKind, Handler] = {
    MessageKind.PROPOSAL: _handle_proposal,
    MessageKind.COUNTERPARTY_EVENT: _handle_counterparty_event,
}


def _process_message(state: GatewayState, env: WireEnvelope) -> tuple[int, dict[str, object]]:
    """Verify-first pipeline for one validated envelope (ADR-0012).

    Returns the (status, body) pair the HTTP layer responds with. Every early
    return is a 4xx that commits nothing; a processed message ends in a signed
    receipt and a dedup store.
    """
    if env.recipient_id != state.identity.identity_id:
        return 400, {"error": f"message is addressed to {env.recipient_id}, not this gateway"}
    peer = state.peers.get(env.sender_id)
    if peer is None:
        return 400, {"error": f"sender {env.sender_id} is not a registered peer"}
    try:
        verify_envelope(env, peer)
        payload = parse_payload(env)
    except EnvelopeError as exc:
        return 400, {"error": str(exc)}

    fingerprint = envelope_fingerprint(env)
    verdict, stored = state.dedup.lookup(env.sender_id, env.idempotency_key, fingerprint)
    if verdict is DedupVerdict.REDELIVERY:
        assert stored is not None
        return stored.status, stored.body
    if verdict is DedupVerdict.HOSTILE:
        return (
            400,
            {
                "error": "idempotency key reused with different message content; "
                "treated as hostile (ADR-0007)"
            },
        )

    # First-seen messages must be fresh. A true redelivery already returned
    # the stored answer above, so a stale redelivery still gets its original
    # outcome (invariant 14 beats the freshness window).
    if state.max_age_seconds is not None and envelope_is_stale(
        env, now_iso(), state.max_age_seconds
    ):
        return (
            400,
            {
                "error": (
                    f"envelope is stale: issued_at is outside the "
                    f"{state.max_age_seconds}s freshness window"
                )
            },
        )

    if env.kind is MessageKind.RECEIPT:
        # v0.1 is synchronous: receipts arrive in the HTTP response, so an
        # inbound receipt is validated and acknowledged, with no ledger write.
        assert isinstance(payload, ReceiptPayload)
        return 202, {"outcome": "acknowledged", "responds_to": payload.responds_to}

    handler = _HANDLERS[env.kind]
    status, body = handler(state, env, payload)
    state.dedup.store(
        env.sender_id,
        env.idempotency_key,
        fingerprint,
        StoredAnswer(status=status, body=body),
        recorded_at=now_iso(),
    )
    return status, body


async def _read_bounded_body(request: Request) -> bytes | None:
    """Read at most MAX_BODY_BYTES, stopping as soon as the limit is passed.

    `await request.body()` accumulates every chunk before returning, so a size
    check on its result bounds nothing: an unauthenticated sender could stream
    an arbitrarily large body and the process would hold all of it before the
    413 was written. The size stage deliberately runs before signature
    verification, so this path is reachable by anyone who can reach the port.

    Returns the body, or None if it exceeds the limit -- in which case the rest
    of the request is never read.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_BODY_BYTES:
                return None
        except ValueError:
            return None

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def create_gateway_app(state: GatewayState) -> FastAPI:
    app = FastAPI(title="mandate wire gateway")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"ok": "true", "identity_id": state.identity.identity_id}

    @app.post("/messages")
    async def messages(request: Request) -> JSONResponse:
        body = await _read_bounded_body(request)
        if body is None:
            status, content = _error(413, "message body exceeds the wire size limit")
            return JSONResponse(status_code=status, content=content)
        try:
            raw = json.loads(body)
        except Exception:
            status, content = _error(400, "message body is not valid JSON")
            return JSONResponse(status_code=status, content=content)
        try:
            env = WireEnvelope.model_validate(raw)
        except Exception as exc:
            status, content = _error(400, f"not a valid envelope: {exc}")
            return JSONResponse(status_code=status, content=content)
        status, content = _process_message(state, env)
        # Structured, metadata-only (no payload, no key material —
        # invariant 12); the redacting JSON formatter is installed by the
        # process entry point (scripts/run_gateway.py).
        logging.getLogger("mandate.gateway").info(
            "message processed",
            extra={
                "log": {
                    "event": "message",
                    "kind": env.kind.value,
                    "sender_id": env.sender_id,
                    "status": status,
                }
            },
        )
        return JSONResponse(status_code=status, content=content)

    return app
