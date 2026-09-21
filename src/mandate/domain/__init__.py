"""Pure domain models for the Agent Mandate engine.

No I/O, no network, no clock, no model calls. Time enters as an explicit immutable
input supplied by the application boundary.
"""

from mandate.domain.authority import (
    ActionToken,
    AuthorityClaim,
    AuthorityRecord,
    DelegationLink,
    RecordStatus,
    SignatureBlock,
    SpendCap,
)
from mandate.domain.deals import Deal, DealEvent, DealState
from mandate.domain.decisions import Outcome, PolicyDecision, ReasonCode
from mandate.domain.input import Actor, ActorKind, Counterparty, PolicyInput, Proposal
from mandate.domain.state_machine import (
    ACTION_VALID_STATES,
    NEGOTIATION_ACTIONS,
    TRANSITIONS,
    terminal_states,
    transition_for,
)

__all__ = [
    "ACTION_VALID_STATES",
    "NEGOTIATION_ACTIONS",
    "TRANSITIONS",
    "ActionToken",
    "Actor",
    "ActorKind",
    "AuthorityClaim",
    "AuthorityRecord",
    "Counterparty",
    "Deal",
    "DealEvent",
    "DealState",
    "DelegationLink",
    "Outcome",
    "PolicyDecision",
    "PolicyInput",
    "Proposal",
    "ReasonCode",
    "RecordStatus",
    "SignatureBlock",
    "SpendCap",
    "terminal_states",
    "transition_for",
]
