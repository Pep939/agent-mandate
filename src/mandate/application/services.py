"""The single writer path: gate → evaluate → transactional commit (ADR-0009).

This is the only way events reach the ledger. Rejected gate verdicts write
nothing; a PASS always appends at least the policy_decision event
(invariant 5); the store rechecks the transition against stored state
(invariant 3) inside the same transaction as the append.
"""

from __future__ import annotations

from dataclasses import dataclass

from mandate.application.anti_replay import (
    GateOutcome,
    GateVerdict,
    check_anti_replay,
    proposal_digest,
)
from mandate.crypto.signing import GatewaySigner
from mandate.domain.decisions import PolicyDecision
from mandate.domain.input import PolicyInput
from mandate.ledger.store import (
    CommitOutcome,
    CommitRequest,
    CommitResult,
    LedgerStore,
)
from mandate.policy.engine import evaluate

__all__ = ["ProcessResult", "process_request"]


@dataclass(frozen=True)
class ProcessResult:
    verdict: GateVerdict
    decision: PolicyDecision | None
    commit: CommitResult | None


def process_request(
    pi: PolicyInput, store: LedgerStore, signer: GatewaySigner, *, recorded_at: str
) -> ProcessResult:
    """Evaluate one proposed action and commit its outcome atomically.

    `recorded_at` is the boundary-supplied commit time (invariant 2: no
    clocks in the domain).
    """
    verdict = check_anti_replay(pi, store)
    if verdict.outcome is GateOutcome.IDEMPOTENT_HIT:
        return ProcessResult(verdict, verdict.decision, None)
    if verdict.outcome is not GateOutcome.PASS:
        return ProcessResult(verdict, None, None)

    decision = evaluate(pi)
    req = CommitRequest(
        deal_id=pi.deal.deal_id,
        request_id=pi.request_id,
        decision=decision,
        actor_kind=pi.actor.kind,
        actor_id=pi.actor.id,
        authority_record_id=pi.authority.record.record_id,
        action=pi.proposal.action,
        amount_minor=pi.proposal.amount_minor,
        occurred_at=pi.now,
        recorded_at=recorded_at,
        idempotency_key=pi.proposal.idempotency_key,
        proposal_digest=proposal_digest(pi),
        record=pi.authority.record,
        content_sha256=pi.proposal.content_sha256 if pi.content is not None else None,
        content=pi.content,
        declared_fields=list(pi.proposal.disclosure_fields),
    )
    commit = store.commit_request(req, signer)
    if commit.outcome is CommitOutcome.ALREADY_APPLIED:
        # The commit's claim-first insert lost the race: a rival committed
        # this same request first, and its rows are visible now. Re-gate —
        # the stored verdict is the answer (invariant 14), never a
        # re-evaluation or a second commit.
        verdict = check_anti_replay(pi, store)
        return ProcessResult(verdict, verdict.decision, None)
    return ProcessResult(verdict, decision, commit)
