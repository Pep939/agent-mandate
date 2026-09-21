"""The `ContentScreen` interface and the pure result → claims mapping (ADR-0016).

A screen answers the question set for one piece of content and returns a
`ScreenResult` in floats (the vendor's native unit). `claims_from_result`
converts that to the domain's integer `ContentClaims` — basis points, pinned
screener id, question-set digest — and is the only place floats are allowed
to exist on the way in. A failed screen (`ok=False`) becomes
`available=False`, which the engine reads as "a person must look".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Protocol

from mandate.domain.content import BP_SCALE, ContentClaims, DetectedField
from mandate.screen.questions import QuestionSet, question_set_digest

__all__ = [
    "ContentScreen",
    "ScreenResult",
    "claims_from_result",
    "content_digest",
    "to_basis_points",
]


@dataclass(frozen=True)
class ScreenResult:
    """One screen's answers. Probabilities are floats in [0, 1]; `hostility`
    is the probability mass on the non-benign options; `urgency` is the
    level index. `ok=False` + `error` when the screen could not answer."""

    screener: str
    ok: bool
    field_probabilities: dict[str, float] = field(default_factory=dict)
    hostility: float = 0.0
    persuasion: float = 0.0
    urgency: int = 0
    error: str = ""


class ContentScreen(Protocol):
    """Anything that can answer the question set for a piece of text."""

    def screen(self, content: str, questions: QuestionSet) -> ScreenResult: ...


def content_digest(content: str) -> str:
    """SHA-256 over the UTF-8 bytes of the exact content screened."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def to_basis_points(p: float) -> int:
    """Clamp a probability into [0, 1] and round to integer basis points."""
    if p != p:  # NaN
        return 0
    p = min(1.0, max(0.0, p))
    return round(p * BP_SCALE)


def claims_from_result(result: ScreenResult, content: str, questions: QuestionSet) -> ContentClaims:
    """Pure mapping from a screen result to the engine's frozen claim.

    Only fields the question set actually asked about are carried; an answer
    for an unknown token is dropped (the vendor cannot invent a field the
    mandate vocabulary does not know). Zero-probability fields are dropped
    too — `detected` lists what the screen believes is present.
    """
    qs_digest = question_set_digest(questions)
    if not result.ok:
        return ContentClaims(
            screener=result.screener,
            question_set_sha256=qs_digest,
            content_chars=len(content),
            available=False,
        )
    known = set(questions.field_tokens())
    detected = [
        DetectedField(field=token, confidence_bp=to_basis_points(p))
        for token, p in sorted(result.field_probabilities.items())
        if token in known and to_basis_points(p) > 0
    ]
    return ContentClaims(
        screener=result.screener,
        question_set_sha256=qs_digest,
        content_chars=len(content),
        available=True,
        detected=detected,
        hostility_bp=to_basis_points(result.hostility),
        persuasion_bp=to_basis_points(result.persuasion),
        urgency_level=max(0, min(3, int(result.urgency))),
    )
