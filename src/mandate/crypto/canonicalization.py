"""The single canonical serialization for the whole product (invariant 13).

Record signing, revocation signing and the policy engine's input_digest all
hash bytes produced here: same logical value → same bytes, always.

Rules (specs/authority-envelope.md §Canonical serialization):
- object keys sorted lexicographically, recursively;
- no whitespace; separators "," and ":";
- no floats (money is integer minor units);
- non-finite values rejected (not JSON);
- non-ASCII escaped to pure-ASCII bytes (encoding-stable);
- list order preserved (order is semantic).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mandate.domain.approvals import ApprovalRecord
from mandate.domain.authority import AuthorityRecord, Revocation

__all__ = [
    "approval_signing_payload",
    "canonical_bytes",
    "canonical_sha256_hex",
    "record_signing_payload",
    "revocation_signing_payload",
]


def _reject_non_serializable(value: Any) -> None:
    if isinstance(value, float):
        msg = "canonical serialization forbids floats (money is integer minor units)"
        raise ValueError(msg)
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                msg = f"canonical object keys must be str, got {type(key).__name__}"
                raise TypeError(msg)
            _reject_non_serializable(item)
    elif isinstance(value, list):
        for item in value:
            _reject_non_serializable(item)


def canonical_bytes(value: Any) -> bytes:
    """Serialize a JSON-compatible value to canonical bytes (deterministic)."""
    _reject_non_serializable(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256_hex(value: Any) -> str:
    """SHA-256 hex digest of the canonical bytes of `value`."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def record_signing_payload(record: AuthorityRecord) -> bytes:
    """Canonical bytes of the authority record, excluding `signature`."""
    data = record.model_dump(mode="json")
    data.pop("signature", None)
    return canonical_bytes(data)


def revocation_signing_payload(revocation: Revocation) -> bytes:
    """Canonical bytes of the revocation, excluding `signature`."""
    data = revocation.model_dump(mode="json")
    data.pop("signature", None)
    return canonical_bytes(data)


def approval_signing_payload(record: ApprovalRecord) -> bytes:
    """Canonical bytes of the approval override, excluding `signature`."""
    data = record.model_dump(mode="json")
    data.pop("signature", None)
    return canonical_bytes(data)
