"""Anti-replay gate: the boundary's seen-request state (ADR-0007).

Order (load-bearing): idempotency first, then request_id, then nonce — a
crash-retried request reuses its request_id and idempotency_key with an
identical proposal and must get the original decision back, not a replay
verdict (invariant 14).

The gate is read-only: writing the seen entries is the store's job, done in
the same transaction as the ledger append (ADR-0008/0009). `process_request`
in `mandate.application.services` is the single entry point (Phase 2's
`guarded_evaluate` is superseded).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from mandate.crypto.canonicalization import canonical_sha256_hex
from mandate.domain.decisions import PolicyDecision
from mandate.domain.input import PolicyInput

__all__ = [
    "GateOutcome",
    "GateVerdict",
    "SeenStore",
    "check_anti_replay",
    "proposal_digest",
]


class GateOutcome(StrEnum):
    PASS = "pass"  # noqa: S105 (verdict name, not a credential)
    REPLAY = "replay"
    IDEMPOTENT_HIT = "idempotent_hit"
    CONFLICT = "conflict"


@dataclass(frozen=True)
class GateVerdict:
    """Gate result. `decision` is set only on IDEMPOTENT_HIT (the stored
    original decision, never re-evaluated)."""

    outcome: GateOutcome
    detail: str
    decision: PolicyDecision | None = None


class SeenStore(Protocol):
    """Read-side of the seen-request state. Both ledger backends implement
    it; writes happen inside the store's commit transactions (ADR-0009)."""

    def nonce_owner(self, nonce: str) -> str | None:
        """record_id that first registered this nonce, or None."""
        ...

    def seen_request(self, request_id: str) -> bool:
        """Whether this request_id has been evaluated before."""
        ...

    def decision_for(self, idempotency_key: str) -> tuple[str, PolicyDecision] | None:
        """(proposal digest, decision) stored for this key, or None."""
        ...


def proposal_digest(pi: PolicyInput) -> str:
    """Canonical SHA-256 of the untrusted proposal (shared canonicalizer)."""
    return canonical_sha256_hex(pi.proposal.model_dump(mode="json"))


def check_anti_replay(pi: PolicyInput, store: SeenStore) -> GateVerdict:
    """Gate verdict for one policy input, per ADR-0007 ordering."""
    record = pi.authority.record
    digest = proposal_digest(pi)

    existing = store.decision_for(pi.proposal.idempotency_key)
    if existing is not None:
        stored_digest, stored_decision = existing
        if stored_digest == digest:
            return GateVerdict(GateOutcome.IDEMPOTENT_HIT, "duplicate_proposal", stored_decision)
        return GateVerdict(GateOutcome.CONFLICT, "idempotency_key_reused_for_different_proposal")

    if store.seen_request(pi.request_id):
        return GateVerdict(GateOutcome.REPLAY, "request_id_reused")

    owner = store.nonce_owner(record.nonce)
    if owner is not None and owner != record.record_id:
        return GateVerdict(GateOutcome.REPLAY, "nonce_reused_by_different_record")

    return GateVerdict(GateOutcome.PASS, "first_seen")
