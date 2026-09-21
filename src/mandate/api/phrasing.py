"""Plain-language phrasing for operator-facing decisions (ADR-0011).

The policy engine emits machine `ReasonCode`s; the console must show a
non-technical operator a sentence a human can act on. Every one of the 25
reason codes maps to a sentence; unknown codes fall back to the code name so a
new code can never render as a blank.
"""

from __future__ import annotations

from mandate.domain.decisions import Outcome, ReasonCode

REASON_SENTENCES: dict[ReasonCode, str] = {
    ReasonCode.OK: "Authorized. The action is within the mandate and the deal moved forward.",
    ReasonCode.UNKNOWN_SCHEMA_VERSION: "This mandate uses a format the console does not understand, so it was not acted on.",
    ReasonCode.MISSING_FIELD: "The request was missing a required piece of information, so it could not be evaluated.",
    ReasonCode.INVALID_SIGNATURE_CLAIM: "The mandate's signature could not be verified, so it carries no authority.",
    ReasonCode.RECORD_REVOKED: "This mandate has been revoked, so it no longer authorizes anything.",
    ReasonCode.RECORD_EXPIRED: "This mandate has expired and no longer authorizes the action.",
    ReasonCode.NOT_YET_VALID: "This mandate is not in force yet, so it cannot authorize the action.",
    ReasonCode.DELEGATION_CHAIN_BROKEN: "A link in this mandate's chain of authority is invalid, so its scope cannot be trusted.",
    ReasonCode.AUDIENCE_MISMATCH: "This mandate was issued for a different counterparty than the one in play.",
    ReasonCode.REPLAY_DETECTED: "This exact request was already handled; the original decision stands.",
    ReasonCode.ACTION_PROHIBITED: "The mandate explicitly forbids this action.",
    ReasonCode.ACTION_NOT_ALLOWED: "The mandate does not allow this action.",
    ReasonCode.UNKNOWN_ACTION: "This is not a recognized action type.",
    ReasonCode.INVALID_TRANSITION: "The deal is not in a state where this action can happen right now.",
    ReasonCode.DISCLOSURE_NOT_ALLOWED: "The mandate does not permit exposing the requested field.",
    ReasonCode.SPEND_CAP_EXCEEDED: "This would take the deal over its spend limit, so a person must approve the extra amount first.",
    ReasonCode.NEGOTIATION_LIMIT_REACHED: "The mandate's limit on negotiation rounds has been reached.",
    ReasonCode.APPROVAL_REQUIRED: "The mandate requires a person to approve this action before it can proceed.",
    ReasonCode.PAYMENT_BLOCKED_BY_DISPUTE: "Payment is blocked because a dispute is still open.",
    ReasonCode.PAYMENT_BLOCKED_BY_OPEN_APPROVAL: "Payment is blocked because an approval is still waiting on a person.",
    ReasonCode.CURRENCY_MISMATCH: "The proposed amount is in a different currency than the mandate's spend limit.",
    ReasonCode.DISCLOSURE_DETECTED: "The content screen found the message would reveal something the mandate does not permit exposing, so it was not sent.",
    ReasonCode.CONTENT_REVIEW_REQUIRED: "The content screen suspects the message reveals something the mandate does not permit; a person must read it before it goes out.",
    ReasonCode.HOSTILE_CONTENT_SUSPECTED: "The content screen suspects the message contains injected instructions or a claim of authority; a person must read it first.",
    ReasonCode.CONTENT_SCREEN_UNAVAILABLE: "The content screen could not check this message, so a person must read it before it goes out.",
}

OUTCOME_LABELS: dict[Outcome, str] = {
    Outcome.ALLOW: "Allowed",
    Outcome.DENY: "Denied",
    Outcome.NEEDS_APPROVAL: "Needs a person's approval",
}


def reason_sentence(reason_code: ReasonCode) -> str:
    """A human sentence for a reason code. Unknown codes show their name
    (never a blank), so a newly added code is visible rather than silent."""
    return REASON_SENTENCES.get(reason_code, f"(unexplained reason: {reason_code.value})")


def outcome_label(outcome: Outcome) -> str:
    return OUTCOME_LABELS.get(outcome, outcome.value)
