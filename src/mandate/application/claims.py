"""Build an AuthorityClaim from a stored record (ADR-0011, shared by both
boundaries: the console `api/` and the wire `transport/gateway.py`).

Verify the signature against the gateway public key, check applicable
revocations, and resolve the lifecycle status. The store and signer are
injected (no I/O here of its own); time enters only as `now` (invariant 2).
"""

from __future__ import annotations

from mandate.crypto.signing import GatewaySigner
from mandate.crypto.verification import verify_record, verify_revocation
from mandate.domain.authority import AuthorityClaim, AuthorityRecord
from mandate.domain.lifecycle import resolve_status, revocation_applies
from mandate.ledger.store import LedgerStore

__all__ = ["build_claim"]


def build_claim(
    store: LedgerStore, signer: GatewaySigner, record: AuthorityRecord, *, now: str
) -> AuthorityClaim:
    """Verify `record` and resolve its status at `now` (invariant 3/7).

    A revocation only counts if it is validly signed AND targets + times this
    record. Delegation narrowing is out of scope for v0.1, so the chain is
    empty for a top-level mandate.
    """
    public_key = signer.public_key
    result = verify_record(record, public_key, expected_key_id=signer.key_id)
    revoked = any(
        verify_revocation(r, public_key, expected_key_id=signer.key_id).valid
        and revocation_applies(r, record, now)
        for r in store.list_revocations([record.record_id])
    )
    status = resolve_status(record, now, revoked=revoked)
    return AuthorityClaim(
        record=record,
        signature_valid=result.valid,
        delegation_chain=[],
        status=status,
    )
