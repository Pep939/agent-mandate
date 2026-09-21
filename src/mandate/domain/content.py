"""Content claims — what a content screen said about a message (ADR-0016).

A content screen is a typed classifier (TypeSafe "Jev" or a local stand-in)
that reads the free text an agent wants to send, or a counterparty sent, and
answers closed questions about it: which sensitive fields the text reveals,
how likely it is hostile (an injected instruction, a claim of authority), how
persuasive it is, how urgent. The screen runs at the boundary; its answers
enter the pure engine as this frozen claim — exactly the way `signature_valid`
does — so the engine stays a pure function (invariant 2).

Two rules govern the model (ADR-0016):

* **Narrowing only.** A claim can move a decision toward `needs_approval` or
  `deny`; it can never produce `allow`. Model output is untrusted (invariant
  11), so a fooled screen is an availability problem, never an authority
  problem.
* **No floats.** Probabilities are integer basis points (0..10000) so canonical
  bytes are identical on every machine (invariant 13) and the domain's
  no-float rule holds.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

__all__ = [
    "BP_SCALE",
    "ContentClaims",
    "DetectedField",
    "validate_basis_points",
    "validate_sha256_hex",
]

BP_SCALE = 10_000
"""One = 10 000 basis points. A probability p becomes `round(p * BP_SCALE)`."""

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def validate_basis_points(v: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        msg = f"basis points must be an int, got {type(v).__name__}"
        raise ValueError(msg)
    if not 0 <= v <= BP_SCALE:
        msg = f"basis points must be within 0..{BP_SCALE}: {v}"
        raise ValueError(msg)
    return v


def validate_sha256_hex(v: str) -> str:
    if not _SHA256_RE.match(v):
        msg = f"not a 64-char lowercase hex sha256: {v!r}"
        raise ValueError(msg)
    return v


class DetectedField(BaseModel):
    """One sensitive field the screen believes the content reveals, with the
    screen's probability in basis points. `field` uses the same token space
    as `AuthorityRecord.disclosure_fields` (invariant 9) so the engine can
    compare detected against declared with plain set membership."""

    model_config = ConfigDict(frozen=True)

    field: str
    confidence_bp: int

    _v_bp = field_validator("confidence_bp")(validate_basis_points)

    @field_validator("field")
    @classmethod
    def _v_field(cls, v: str) -> str:
        if not _FIELD_RE.match(v):
            msg = f"disclosure field token must be snake_case ascii: {v!r}"
            raise ValueError(msg)
        return v


class ContentClaims(BaseModel):
    """The boundary's frozen summary of one content screen (ADR-0016).

    `available=False` means the content existed but the screen could not
    answer (timeout, outage, error). The engine treats that as "a person must
    look" — never as "nothing was found" (fail toward caution).
    """

    model_config = ConfigDict(frozen=True)

    screener: str
    """Pinned screener id, e.g. ``typesafe:jev-1.13.0`` or ``fixture``. Never a
    floating alias: thresholds do not survive a model version bump."""

    question_set_sha256: str
    """Canonical digest of the exact question set asked, so a reviewer can
    re-ask the same questions of the same pinned model."""

    content_chars: int
    available: bool = True
    detected: list[DetectedField] = []
    hostility_bp: int = 0
    persuasion_bp: int = 0
    urgency_level: int = 0

    _v_qs = field_validator("question_set_sha256")(validate_sha256_hex)
    _v_hostility = field_validator("hostility_bp")(validate_basis_points)
    _v_persuasion = field_validator("persuasion_bp")(validate_basis_points)

    @field_validator("content_chars")
    @classmethod
    def _v_chars(cls, v: int) -> int:
        if v < 0:
            msg = f"content_chars must be >= 0: {v}"
            raise ValueError(msg)
        return v

    @field_validator("urgency_level")
    @classmethod
    def _v_urgency(cls, v: int) -> int:
        if not 0 <= v <= 3:
            msg = f"urgency_level must be within 0..3: {v}"
            raise ValueError(msg)
        return v

    @field_validator("screener")
    @classmethod
    def _v_screener(cls, v: str) -> str:
        if not v.strip():
            msg = "screener must name the pinned screener"
            raise ValueError(msg)
        if v.endswith("-latest") or v.endswith(":latest") or "jev-latest" in v:
            msg = f"screener must be a pinned version, not a floating alias: {v!r}"
            raise ValueError(msg)
        return v

    @field_validator("detected")
    @classmethod
    def _v_detected_unique(cls, v: list[DetectedField]) -> list[DetectedField]:
        seen: set[str] = set()
        for d in v:
            if d.field in seen:
                msg = f"detected field listed twice: {d.field!r}"
                raise ValueError(msg)
            seen.add(d.field)
        return v

    def undeclared(self, allowed: list[str]) -> list[DetectedField]:
        """Detected fields that are NOT on the mandate's allow-list, in field
        order (deterministic). Declared-and-allowed fields are the mandate's
        business; only leaks outside the allow-list concern the engine."""
        allow = set(allowed)
        return sorted((d for d in self.detected if d.field not in allow), key=lambda d: d.field)
