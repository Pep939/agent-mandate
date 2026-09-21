"""A deterministic keyword screen (ADR-0016): the test double, and the stand-in
the shadow pilot runs on when no vendor is configured.

It is deliberately dumb — regexes and word lists — so that a test can
predict its answer from the text alone. It is NOT a model and makes no
accuracy claim; it exists so the plumbing (claims → engine → chain → console)
is exercised end to end without a network. Swap in `TypeSafeScreen` for a
real screen; the interface and the claims are identical.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mandate.screen.protocol import ScreenResult
from mandate.screen.questions import QuestionSet

__all__ = ["FailingScreen", "FixtureScreen"]

_PHONE = re.compile(r"(?:\(\d{3}\)\s?|\b\d{3}[-.\s])\d{3}[-.\s]\d{4}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_ADDRESS = re.compile(
    r"\b\d{1,5}\s+[A-Z][\w']*(?:\s+[A-Z][\w']*)*\s+"
    r"(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Dr|Drive|Ln|Lane|Way|Ct|Court)\b\.?"
)
_MONEY = re.compile(r"(?:\$\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*\s?(?:dollars|usd)\b)", re.I)
_TOTAL_WORDS = re.compile(r"\b(?:total|invoice|quote[sd]?|price)\b", re.I)
_FLOOR = re.compile(
    r"\b(?:as low as|lowest we|walk[- ]away|budget (?:tops|caps|ceiling)|"
    r"won'?t go (?:below|under)|floor is)\b",
    re.I,
)
_INTERNAL = re.compile(
    r"\b(?:our margin|margin on this|internal note|do not share|between us)\b", re.I
)
_WORK_ORDER = re.compile(r"\b(?:WO-\d+|ticket\s?#\s?\d+|job\s?#\s?\d+|work order \d+)\b", re.I)

_INJECTION = re.compile(
    r"\b(?:ignore (?:all |your |the )?(?:previous |prior )?(?:instructions|mandate|rules)|"
    r"disregard (?:your|the) (?:mandate|policy)|system prompt|you are now)\b",
    re.I,
)
_AUTHORITY = re.compile(
    r"\b(?:you are authorized|you're authorized|(?:the )?owner (?:already )?(?:agreed|approved)|"
    r"has been approved|pre-?approved|i have (?:full )?authority)\b",
    re.I,
)
_INSTRUCTION = re.compile(
    r"\b(?:raise (?:the|your) (?:cap|limit)|skip (?:the )?approval|forward (?:me|us) (?:the|their)|"
    r"send (?:me|us) (?:the|their) (?:address|phone|number|details))\b",
    re.I,
)
_PERSUASION = re.compile(
    r"\b(?:trust me|just approve|please approve|no time to|don'?t (?:over)?think|"
    r"you'?ll regret|last chance|everyone else|be reasonable)\b",
    re.I,
)
_URGENT_3 = re.compile(r"\b(?:emergency|no power|power is out|flooding|fire|danger|unsafe)\b", re.I)
_URGENT_2 = re.compile(r"\b(?:today|by (?:noon|eod|end of day)|deadline|asap|right away)\b", re.I)
_URGENT_1 = re.compile(r"\b(?:soon|when you can|at your earliest)\b", re.I)


@dataclass(frozen=True)
class FixtureScreen:
    """Deterministic keyword screen. `hit`/`miss` are the probabilities it
    reports for a matched / unmatched field, so a test can tune where the
    engine's thresholds land (defaults: a hit is a near-certain 0.96)."""

    screener: str = "fixture:keyword-0.1"
    hit: float = 0.96
    miss: float = 0.0

    def screen(self, content: str, questions: QuestionSet) -> ScreenResult:
        probs: dict[str, float] = {}
        for q in questions.fields:
            probs[q.field] = self.hit if self._matches(q.field, content) else self.miss

        if _INJECTION.search(content):
            hostility = 0.97
        elif _AUTHORITY.search(content):
            hostility = 0.90
        elif _INSTRUCTION.search(content):
            hostility = 0.80
        else:
            hostility = 0.03

        persuasion = 0.88 if _PERSUASION.search(content) else 0.05
        if _URGENT_3.search(content):
            urgency = 3
        elif _URGENT_2.search(content):
            urgency = 2
        elif _URGENT_1.search(content):
            urgency = 1
        else:
            urgency = 0
        return ScreenResult(
            screener=self.screener,
            ok=True,
            field_probabilities=probs,
            hostility=hostility,
            persuasion=persuasion,
            urgency=urgency,
        )

    @staticmethod
    def _matches(field: str, content: str) -> bool:
        if field == "customer_phone":
            return _PHONE.search(content) is not None
        if field == "customer_email":
            return _EMAIL.search(content) is not None
        if field == "customer_address":
            return _ADDRESS.search(content) is not None
        if field == "invoice_total":
            return _MONEY.search(content) is not None and _TOTAL_WORDS.search(content) is not None
        if field == "price_floor":
            return _FLOOR.search(content) is not None
        if field == "internal_notes":
            return _INTERNAL.search(content) is not None
        if field == "work_order_id":
            return _WORK_ORDER.search(content) is not None
        return False


@dataclass(frozen=True)
class FailingScreen:
    """A screen that is always down — for testing the fail-toward-caution
    path (`available=False` → the engine holds for a person)."""

    screener: str = "fixture:down"
    error: str = "screen unavailable"

    def screen(self, content: str, questions: QuestionSet) -> ScreenResult:
        return ScreenResult(screener=self.screener, ok=False, error=self.error)
