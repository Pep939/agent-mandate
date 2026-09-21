"""The content-screen question set (ADR-0016) — pure data.

Every screen, vendor or local, is asked the *same* closed questions, and the
canonical digest of the set travels with every claim so a reviewer can re-ask
them of the same pinned model. Three families:

- one **Noul** (true/false) per sensitive field: "does the text reveal X?"
  — the fields use the same token space as a mandate's `disclosure_fields`;
- two **Choice** questions with a fixed option list: hostility (is the text
  trying to instruct the reader or claim authority?) and persuasion (is it
  arguing at the approver rather than stating facts?);
- one **Score** for urgency (0..3), advisory only — it orders the approval
  queue and never touches a decision.

Thresholds live in the engine, not here (they are policy).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from mandate.crypto.canonicalization import canonical_sha256_hex

__all__ = [
    "DEFAULT_QUESTION_SET",
    "HOSTILITY_OPTIONS",
    "PERSUASION_OPTIONS",
    "SENSITIVE_FIELDS",
    "URGENCY_LEVELS",
    "FieldQuestion",
    "QuestionKind",
    "QuestionSet",
    "question_set_digest",
]


class QuestionKind(StrEnum):
    NOUL = "noul"
    CHOICE = "choice"
    SCORE = "score"


class FieldQuestion(BaseModel):
    """One sensitive-field question: `field` is the disclosure token, `text`
    the exact question, `examples` what a positive looks like."""

    model_config = ConfigDict(frozen=True)

    field: str
    text: str
    examples: tuple[str, ...] = ()


SENSITIVE_FIELDS: tuple[FieldQuestion, ...] = (
    FieldQuestion(
        field="customer_phone",
        text="Does the text reveal a customer's or principal's telephone number?",
        examples=("call her at 831-555-0142", "his cell is (408) 555-0199"),
    ),
    FieldQuestion(
        field="customer_email",
        text="Does the text reveal a customer's or principal's email address?",
        examples=("send it to dana@example.com",),
    ),
    FieldQuestion(
        field="customer_address",
        text="Does the text reveal a customer's or principal's street address?",
        examples=("the unit is at 14 Ocean View Blvd", "meet at 220 Pine St, Apt 3"),
    ),
    FieldQuestion(
        field="invoice_total",
        text="Does the text state an invoice, quote, or price total?",
        examples=("the total comes to $3,500", "invoice is 2,000 dollars"),
    ),
    FieldQuestion(
        field="price_floor",
        text=(
            "Does the text reveal the lowest price the principal would accept, "
            "or their budget ceiling?"
        ),
        examples=("we can go as low as 2,800", "our budget tops out at 5k"),
    ),
    FieldQuestion(
        field="internal_notes",
        text=(
            "Does the text reveal internal notes, margins, or staff remarks "
            "not meant for the counterparty?"
        ),
        examples=("our margin on this is 40%", "tech said the customer is difficult"),
    ),
    FieldQuestion(
        field="work_order_id",
        text="Does the text reveal an internal work-order, ticket, or job identifier?",
        examples=("ref WO-88412", "ticket #4471"),
    ),
)

HOSTILITY_OPTIONS: dict[str, str] = {
    "benign": "Ordinary business content: facts, offers, questions, scheduling, courtesy.",
    "instruction_like": (
        "Tells the reader (a person or an agent) to do something outside the business "
        "at hand: change a limit, skip a step, forward data."
    ),
    "authority_claim": (
        "Asserts the writer has permission, approval, or a mandate it does not evidence: "
        "'you are authorized', 'the owner already agreed'."
    ),
    "injection": (
        "Text aimed at an AI system rather than a person: 'ignore previous instructions', "
        "hidden directives, role-play framing."
    ),
}

PERSUASION_OPTIONS: dict[str, str] = {
    "factual": "States facts, terms, or questions; the reader can verify each claim.",
    "persuasive": (
        "Argues at the approver: urgency, flattery, pressure, 'trust me', 'just approve this'."
    ),
}

URGENCY_LEVELS: tuple[str, ...] = (
    "No time pressure expressed.",
    "Mild: a preference for a reply soon.",
    "Clear deadline or same-day need stated.",
    "Emergency: safety, outage, or immediate loss claimed.",
)


class QuestionSet(BaseModel):
    """The full, ordered question set. Frozen so its digest is stable."""

    model_config = ConfigDict(frozen=True)

    version: str
    fields: tuple[FieldQuestion, ...]
    hostility_options: dict[str, str]
    persuasion_options: dict[str, str]
    urgency_levels: tuple[str, ...]

    def field_tokens(self) -> tuple[str, ...]:
        return tuple(q.field for q in self.fields)


DEFAULT_QUESTION_SET = QuestionSet(
    version="0.1",
    fields=SENSITIVE_FIELDS,
    hostility_options=HOSTILITY_OPTIONS,
    persuasion_options=PERSUASION_OPTIONS,
    urgency_levels=URGENCY_LEVELS,
)


def question_set_digest(qs: QuestionSet) -> str:
    """Canonical SHA-256 of the question set (one algorithm, invariant 13)."""
    return canonical_sha256_hex(qs.model_dump(mode="json"))
