"""Screen one piece of content into claims (ADR-0016), shared by both
boundaries: the console `api/` and the wire `transport/gateway.py`.

Like `application.claims`, this module has no I/O of its own — the screen is
injected, exactly as the store is. It exists so there is one definition of
"what the boundary does with text": hash it, ask the screen, convert the
answer to integer claims, and hand the engine the digest plus the claims.
The text itself stops here; it never enters `PolicyInput`, a payload, or an
event (payload doctrine, invariant 11/12).
"""

from __future__ import annotations

from mandate.domain.content import ContentClaims
from mandate.screen.protocol import ContentScreen, ScreenResult, claims_from_result, content_digest
from mandate.screen.questions import DEFAULT_QUESTION_SET, QuestionSet

__all__ = ["ScreenedContent", "screen_content"]


class ScreenedContent:
    """The digest of what was screened and what the screen said. Frozen by
    convention: the boundary builds it once per request and reads it twice
    (into the `PolicyInput`, then into the MESSAGE event)."""

    __slots__ = ("claims", "digest")

    def __init__(self, digest: str, claims: ContentClaims) -> None:
        self.digest = digest
        self.claims = claims

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ScreenedContent(digest={self.digest[:12]}…, screener={self.claims.screener})"


def screen_content(
    screen: ContentScreen | None,
    content: str,
    *,
    questions: QuestionSet = DEFAULT_QUESTION_SET,
) -> ScreenedContent | None:
    """Screen `content`, or return `None` when there is nothing to screen.

    With content but no screen configured the result is an *unavailable*
    claim, not an absent one: the engine must hold for a person rather than
    treat an unscreened message as clean (ADR-0016, fail toward caution).
    """
    if not content:
        return None
    digest = content_digest(content)
    if screen is None:
        result = ScreenResult(screener="none:unconfigured", ok=False, error="no screen configured")
    else:
        result = screen.screen(content, questions)
    return ScreenedContent(digest, claims_from_result(result, content, questions))
