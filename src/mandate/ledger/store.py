"""The LedgerStore protocol and the in-memory implementation (ADR-0008).

`commit_request` is the single transactional writer for policy outcomes:
one transaction appends the policy_decision event (always — invariant 5),
the state_transition event and the deal row update (only on an ALLOWed
transition), and the seen-store entries (ADR-0007). `commit_transition` is
the sibling path for boundary/operator events (ADR-0009), idempotent by
`command_id` (invariant 14).

The in-memory store is single-threaded: it validates fully before mutating,
so a commit is all-or-nothing in-process. Real crash atomicity is the
Postgres backend's job (ADR-0008).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from mandate.crypto.signing import GatewaySigner
from mandate.domain.approvals import Approval, ApprovalRecord, ApprovalStatus
from mandate.domain.authority import ActionToken, AuthorityRecord, Revocation, _validate_ulid
from mandate.domain.content import ContentClaims, validate_sha256_hex
from mandate.domain.deals import Deal, DealEvent
from mandate.domain.decisions import PolicyDecision
from mandate.domain.events import GENESIS_HASH, Event
from mandate.domain.input import ActorKind
from mandate.domain.lifecycle import revocation_applies
from mandate.domain.state_machine import transition_for
from mandate.ledger.chain import plan_transition
from mandate.ledger.commit_plans import (
    ApprovalDecision,
    plan_commit_approval,
    plan_commit_request,
    plan_commit_revocation,
    plan_commit_transition,
)
from mandate.ledger.commit_plans import (
    grant_recheck as grant_recheck,
)

__all__ = [
    "ApprovalDecision",
    "ApprovalRequest",
    "CommitOutcome",
    "CommitRequest",
    "CommitResult",
    "InMemoryLedgerStore",
    "LedgerStore",
    "RevocationRequest",
    "TransitionRequest",
    "grant_recheck",
]


class CommitOutcome(StrEnum):
    COMMITTED = "committed"
    ALREADY_APPLIED = "already_applied"
    STALE_STATE = "stale_state"
    DEAL_NOT_FOUND = "deal_not_found"
    APPROVAL_NOT_FOUND = "approval_not_found"
    RECORD_NOT_FOUND = "record_not_found"


@dataclass(frozen=True)
class CommitResult:
    outcome: CommitOutcome
    detail: str
    events: tuple[Event, ...]
    new_deal: Deal | None


class CommitRequest(BaseModel):
    """Everything the store needs to commit one policy outcome (ADR-0009).

    The store reads the *stored* deal as the source of truth — never
    `pi.deal`, the boundary's claim.
    """

    model_config = ConfigDict(frozen=True)

    deal_id: str
    request_id: str
    decision: PolicyDecision
    actor_kind: ActorKind
    actor_id: str
    authority_record_id: str
    action: str
    amount_minor: int | None
    occurred_at: str
    recorded_at: str
    idempotency_key: str
    proposal_digest: str
    record: AuthorityRecord
    content_sha256: str | None = None
    content: ContentClaims | None = None
    declared_fields: list[str] = []
    """ADR-0016: when the proposal carried content, its digest, the screen's
    claims and the agent's declared disclosure fields — the commit appends a
    MESSAGE event ahead of the policy decision so the chain shows what was
    screened before it shows what was decided."""

    _v_deal = field_validator("deal_id")(_validate_ulid)
    _v_record = field_validator("authority_record_id")(_validate_ulid)

    @field_validator("content_sha256")
    @classmethod
    def _v_content(cls, v: str | None) -> str | None:
        if v is not None:
            validate_sha256_hex(v)
        return v

    @model_validator(mode="after")
    def _content_pair(self) -> CommitRequest:
        if (self.content is None) != (self.content_sha256 is None):
            msg = "content and content_sha256 must be set together"
            raise ValueError(msg)
        return self


class TransitionRequest(BaseModel):
    """A boundary/operator transition (ADR-0009): counterparty webhook,
    expiry sweep, dispute resolution outcome. `command_id` dedupes retries."""

    model_config = ConfigDict(frozen=True)

    deal_id: str
    command_id: str
    event: DealEvent
    actor_kind: ActorKind
    actor_id: str
    authority_record_id: str | None
    amount_minor: int | None
    occurred_at: str
    recorded_at: str
    note: str = ""
    content_sha256: str | None = None
    content: ContentClaims | None = None
    """ADR-0016: the screen's claims about ``note`` (inbound counterparty
    text). Advisory on the transition path — the state machine is unchanged;
    the MESSAGE event makes the screen's answer part of the evidence."""

    _v_deal = field_validator("deal_id")(_validate_ulid)
    _v_command = field_validator("command_id")(_validate_ulid)

    @field_validator("authority_record_id")
    @classmethod
    def _v_record_ref(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_ulid(v)
        return v

    @field_validator("content_sha256")
    @classmethod
    def _v_content(cls, v: str | None) -> str | None:
        if v is not None:
            validate_sha256_hex(v)
        return v

    @model_validator(mode="after")
    def _content_pair(self) -> TransitionRequest:
        if (self.content is None) != (self.content_sha256 is None):
            msg = "content and content_sha256 must be set together"
            raise ValueError(msg)
        return self


class ApprovalRequest(BaseModel):
    """A boundary approval decision (ADR-0010). ``command_id`` dedupes retries
    (invariant 14). A grant requires the signed ``approval_record``; a deny
    carries ``deny_reason``."""

    model_config = ConfigDict(frozen=True)

    deal_id: str
    approval_id: str
    command_id: str
    operation: ApprovalDecision
    actor_kind: ActorKind
    actor_id: str
    authority_record_id: str
    action: str
    amount_minor: int | None
    occurred_at: str
    recorded_at: str
    decided_by: str
    approval_record: ApprovalRecord | None = None
    deny_reason: str | None = None

    _v_deal = field_validator("deal_id")(_validate_ulid)
    _v_approval = field_validator("approval_id")(_validate_ulid)
    _v_command = field_validator("command_id")(_validate_ulid)
    _v_record_ref = field_validator("authority_record_id")(_validate_ulid)


class RevocationRequest(BaseModel):
    """A boundary revocation (ADR-0014): the signed ``Revocation`` plus the
    deal whose chain the event lands on. ``command_id`` dedupes retries
    (invariant 14). The event's ``authority_record_id`` is
    ``revocation.record_id``."""

    model_config = ConfigDict(frozen=True)

    deal_id: str
    revocation: Revocation
    command_id: str
    actor_kind: ActorKind
    actor_id: str
    occurred_at: str
    recorded_at: str

    _v_deal = field_validator("deal_id")(_validate_ulid)
    _v_command = field_validator("command_id")(_validate_ulid)


class LedgerStore(Protocol):
    """The persistence contract both backends implement (ADR-0008)."""

    def create_deal(self, deal: Deal, created_at: str) -> None: ...

    def get_deal(self, deal_id: str) -> Deal | None: ...

    def get_deal_created_at(self, deal_id: str) -> str | None: ...

    def link_deal_record(self, deal_id: str, record_id: str, linked_at: str) -> None: ...

    def list_deal_links(self) -> dict[str, str]: ...

    def put_record(self, record: AuthorityRecord) -> None: ...

    def get_record(self, record_id: str) -> AuthorityRecord | None: ...

    def put_revocation(self, revocation: Revocation) -> None: ...

    def list_revocations(self, record_ids: Sequence[str]) -> list[Revocation]: ...

    def nonce_owner(self, nonce: str) -> str | None: ...

    def seen_request(self, request_id: str) -> bool: ...

    def decision_for(self, idempotency_key: str) -> tuple[str, PolicyDecision] | None: ...

    def commit_request(self, req: CommitRequest, signer: GatewaySigner) -> CommitResult: ...

    def commit_transition(self, req: TransitionRequest, signer: GatewaySigner) -> CommitResult: ...

    def commit_approval(self, req: ApprovalRequest, signer: GatewaySigner) -> CommitResult: ...

    def commit_revocation(self, req: RevocationRequest, signer: GatewaySigner) -> CommitResult: ...

    def get_approval(self, approval_id: str) -> Approval | None: ...

    def approvals_for(self, deal_id: str) -> tuple[Approval, ...]: ...

    def events_for(self, deal_id: str) -> tuple[Event, ...]: ...


class InMemoryLedgerStore:
    """Process-lifetime store; carries the correctness burden in CI."""

    def __init__(self) -> None:
        self._deals: dict[str, Deal] = {}
        self._deal_created_at: dict[str, str] = {}
        self._deal_links: dict[str, str] = {}
        self._events: dict[str, list[Event]] = {}
        self._records: dict[str, AuthorityRecord] = {}
        self._revocations: dict[str, Revocation] = {}
        self._approvals: dict[str, Approval] = {}
        self._nonce_owners: dict[str, str] = {}
        self._seen_requests: set[str] = set()
        self._decisions: dict[str, tuple[str, PolicyDecision]] = {}
        self._seen_commands: set[str] = set()

    def create_deal(self, deal: Deal, created_at: str) -> None:
        if deal.deal_id in self._deals:
            msg = f"deal {deal.deal_id} already exists"
            raise ValueError(msg)
        self._deals[deal.deal_id] = deal
        self._deal_created_at[deal.deal_id] = created_at
        self._events[deal.deal_id] = []

    def get_deal(self, deal_id: str) -> Deal | None:
        return self._deals.get(deal_id)

    def get_deal_created_at(self, deal_id: str) -> str | None:
        return self._deal_created_at.get(deal_id)

    def link_deal_record(self, deal_id: str, record_id: str, linked_at: str) -> None:
        existing = self._deal_links.get(deal_id)
        if existing is not None and existing != record_id:
            msg = f"deal {deal_id} is already linked to record {existing}"
            raise ValueError(msg)
        self._deal_links[deal_id] = record_id

    def list_deal_links(self) -> dict[str, str]:
        return dict(self._deal_links)

    def put_record(self, record: AuthorityRecord) -> None:
        # Records are immutable signed objects: upsert by record_id.
        self._records[record.record_id] = record

    def get_record(self, record_id: str) -> AuthorityRecord | None:
        return self._records.get(record_id)

    def put_revocation(self, revocation: Revocation) -> None:
        self._revocations[revocation.revocation_id] = revocation

    def list_revocations(self, record_ids: Sequence[str]) -> list[Revocation]:
        wanted = set(record_ids)
        return [r for r in self._revocations.values() if r.record_id in wanted]

    def nonce_owner(self, nonce: str) -> str | None:
        return self._nonce_owners.get(nonce)

    def seen_request(self, request_id: str) -> bool:
        return request_id in self._seen_requests

    def decision_for(self, idempotency_key: str) -> tuple[str, PolicyDecision] | None:
        return self._decisions.get(idempotency_key)

    def commit_request(self, req: CommitRequest, signer: GatewaySigner) -> CommitResult:
        deal = self._deals.get(req.deal_id)
        if deal is None:
            return CommitResult(CommitOutcome.DEAL_NOT_FOUND, "deal row not found", (), None)
        event, abort = plan_transition(deal, req.action, req.decision.outcome)
        if abort is not None:
            return CommitResult(CommitOutcome.STALE_STATE, abort, (), None)

        chain = self._events[req.deal_id]
        plan = plan_commit_request(
            deal,
            len(chain),
            chain[-1].event_hash if chain else GENESIS_HASH,
            req,
            event,
            signer,
        )
        # Validation is complete: apply all-or-nothing (single-threaded).
        chain.extend(plan.events)
        self._deals[req.deal_id] = plan.new_deal
        if plan.approval is not None:
            self._approvals[plan.approval.approval_id] = plan.approval
        self._records[req.record.record_id] = req.record
        self._nonce_owners[req.record.nonce] = req.record.record_id
        self._seen_requests.add(req.request_id)
        self._decisions[req.idempotency_key] = (req.proposal_digest, req.decision)
        return CommitResult(
            CommitOutcome.COMMITTED,
            f"{len(plan.events)} event(s) appended",
            plan.events,
            plan.new_deal,
        )

    def commit_transition(self, req: TransitionRequest, signer: GatewaySigner) -> CommitResult:
        deal = self._deals.get(req.deal_id)
        if deal is None:
            return CommitResult(CommitOutcome.DEAL_NOT_FOUND, "deal row not found", (), None)
        if req.command_id in self._seen_commands:
            return CommitResult(
                CommitOutcome.ALREADY_APPLIED,
                f"command {req.command_id} already applied",
                (),
                deal,
            )
        target = transition_for(deal.state, req.event)
        if target is None:
            return CommitResult(
                CommitOutcome.STALE_STATE,
                f"stale_state: event {req.event.value!r} is not valid from stored state "
                f"{deal.state.value}",
                (),
                None,
            )

        chain = self._events[req.deal_id]
        plan = plan_commit_transition(
            deal,
            len(chain),
            chain[-1].event_hash if chain else GENESIS_HASH,
            req,
            target,
            signer,
        )
        chain.extend(plan.events)
        self._deals[req.deal_id] = plan.new_deal
        self._seen_commands.add(req.command_id)
        return CommitResult(
            CommitOutcome.COMMITTED,
            f"{len(plan.events)} event(s) appended",
            plan.events,
            plan.new_deal,
        )

    def commit_approval(self, req: ApprovalRequest, signer: GatewaySigner) -> CommitResult:
        """Decide one pending approval (ADR-0010).

        A grant rechecks before it applies a transition (invariant 3, applied
        at decision time, not proposal time): step 2 — the parent authority
        record is still current at the boundary-supplied decision time
        (revocation or expiry forces a logged deny, closing the approval —
        invariant 7); step 3 — the stored deal still permits the original
        transition (a stale transition is likewise a logged deny). An explicit
        operator deny is always honored with the operator's reason.
        """
        deal = self._deals.get(req.deal_id)
        if deal is None:
            return CommitResult(CommitOutcome.DEAL_NOT_FOUND, "deal row not found", (), None)
        approval = self._approvals.get(req.approval_id)
        if approval is None:
            return CommitResult(CommitOutcome.APPROVAL_NOT_FOUND, "approval not found", (), None)
        if approval.status is not ApprovalStatus.PENDING:
            return CommitResult(
                CommitOutcome.ALREADY_APPLIED,
                f"approval {req.approval_id} already {approval.status.value}",
                (),
                deal,
            )
        if req.command_id in self._seen_commands:
            return CommitResult(
                CommitOutcome.ALREADY_APPLIED,
                f"command {req.command_id} already applied",
                (),
                deal,
            )

        chain = self._events[req.deal_id]
        token: ActionToken | None = None
        record: AuthorityRecord | None = None
        revoked = False
        if req.operation is ApprovalDecision.GRANTED:
            try:
                token = ActionToken(req.action)
            except ValueError:
                return CommitResult(
                    CommitOutcome.STALE_STATE,
                    f"stale_state: unknown action {req.action!r}",
                    (),
                    None,
                )
            record = self._records.get(approval.authority_record_id)
            revoked = (
                any(
                    revocation_applies(r, record, req.occurred_at)
                    for r in self.list_revocations([record.record_id])
                )
                if record is not None
                else False
            )
        plan = plan_commit_approval(
            deal,
            approval,
            len(chain),
            chain[-1].event_hash if chain else GENESIS_HASH,
            req,
            record,
            revoked,
            token,
            signer,
        )
        assert plan.approval is not None  # the plan always decides the approval
        chain.extend(plan.events)
        self._deals[req.deal_id] = plan.new_deal
        self._approvals[req.approval_id] = plan.approval
        self._seen_commands.add(req.command_id)
        return CommitResult(
            CommitOutcome.COMMITTED,
            f"{len(plan.events)} event(s) appended",
            plan.events,
            plan.new_deal,
        )

    def commit_revocation(self, req: RevocationRequest, signer: GatewaySigner) -> CommitResult:
        """Record one revocation as a chain event (ADR-0014).

        A revocation is an authority decision, so it lands on the linked
        deal's chain — deleting the side-table row later can no longer
        un-revoke silently (invariants 5 and 7). Retries on the same
        ``command_id`` and a second revocation of an already-revoked record
        are idempotent no-ops (invariant 14).
        """
        deal = self._deals.get(req.deal_id)
        if deal is None:
            return CommitResult(CommitOutcome.DEAL_NOT_FOUND, "deal row not found", (), None)
        if req.command_id in self._seen_commands:
            return CommitResult(
                CommitOutcome.ALREADY_APPLIED,
                f"command {req.command_id} already applied",
                (),
                deal,
            )
        record = self._records.get(req.revocation.record_id)
        if record is None:
            return CommitResult(
                CommitOutcome.RECORD_NOT_FOUND,
                f"authority record {req.revocation.record_id} not found",
                (),
                deal,
            )
        if self.list_revocations([record.record_id]):
            return CommitResult(
                CommitOutcome.ALREADY_APPLIED,
                f"record {record.record_id} already revoked",
                (),
                deal,
            )

        chain = self._events[req.deal_id]
        plan = plan_commit_revocation(
            deal, len(chain), chain[-1].event_hash if chain else GENESIS_HASH, req, signer
        )
        chain.extend(plan.events)
        self._revocations[req.revocation.revocation_id] = req.revocation
        self._seen_commands.add(req.command_id)
        return CommitResult(CommitOutcome.COMMITTED, "1 event appended", plan.events, deal)

    def get_approval(self, approval_id: str) -> Approval | None:
        return self._approvals.get(approval_id)

    def approvals_for(self, deal_id: str) -> tuple[Approval, ...]:
        return tuple(a for a in self._approvals.values() if a.deal_id == deal_id)

    def events_for(self, deal_id: str) -> tuple[Event, ...]:
        return tuple(self._events.get(deal_id, ()))
