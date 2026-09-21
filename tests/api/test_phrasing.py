"""Plain-language phrasing (ADR-0011).

Every machine ReasonCode must map to a human sentence (no blanks), and every
Outcome must have a label. (Untrusted-content escaping is covered by
test_proposal_flow, which drives real pages.)
"""

from __future__ import annotations

from mandate.api import phrasing
from mandate.domain.decisions import ReasonCode


def test_every_reason_code_has_a_human_sentence():
    for code in ReasonCode:
        sentence = phrasing.reason_sentence(code)
        assert sentence, f"no sentence for {code}"
        assert not sentence.startswith("(unexplained"), f"fell through to fallback for {code}"
        assert code.value not in sentence or code is ReasonCode.OK  # not a bare code dump


def test_reason_map_covers_exactly_the_enum():
    assert set(phrasing.REASON_SENTENCES) == set(ReasonCode)


def test_every_outcome_has_a_label():
    from mandate.domain.decisions import Outcome

    assert set(phrasing.OUTCOME_LABELS) == set(Outcome)
    for outcome in Outcome:
        assert phrasing.outcome_label(outcome)


def test_sentence_is_not_a_bare_code_dump():
    """A sentence should explain, not just echo the machine code verbatim."""
    sample = phrasing.reason_sentence(ReasonCode.SPEND_CAP_EXCEEDED)
    assert "spend" in sample.lower()
