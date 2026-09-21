"""The content screen (ADR-0016).

A typed classifier reads free text and answers closed questions about it;
the boundary turns the answers into a frozen `ContentClaims` for the engine.

Layout:

- `questions`  — the question set (pure data) and its canonical digest
- `protocol`   — the `ContentScreen` interface, `ScreenResult`, and the pure
                 mapping from a result to `ContentClaims`
- `fixture`    — a deterministic keyword screen: the test double and the
                 stand-in the shadow pilot runs on (no vendor, no network)
- `typesafe`   — the TypeSafe "Jev" adapter (I/O; imports the SDK lazily)

Only `typesafe` does I/O. Everything else is pure and scanned by the
banned-imports test like the rest of the core.
"""

from __future__ import annotations

from mandate.screen.protocol import ContentScreen, ScreenResult, claims_from_result
from mandate.screen.questions import DEFAULT_QUESTION_SET, QuestionSet, question_set_digest

__all__ = [
    "DEFAULT_QUESTION_SET",
    "ContentScreen",
    "QuestionSet",
    "ScreenResult",
    "claims_from_result",
    "question_set_digest",
]
