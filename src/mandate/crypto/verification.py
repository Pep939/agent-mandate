"""Verification of signed objects → boundary claims for PolicyInput.

The engine consumes *claims* (signature_valid, status), never raw
signatures (brief §11 correction): verification happens here, at the
boundary, and its verdict is passed into the pure engine as data.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mandate.crypto import signing
from mandate.crypto.canonicalization import (
    approval_signing_payload,
    record_signing_payload,
    revocation_signing_payload,
)
from mandate.domain.approvals import ApprovalRecord
from mandate.domain.authority import AuthorityRecord, Revocation

__all__ = ["VerifyResult", "verify_approval", "verify_record", "verify_revocation"]


@dataclass(frozen=True)
class VerifyResult:
    """Verdict of one signature check. `reason` is 'ok' when valid."""

    valid: bool
    reason: str


def _check(
    payload: bytes,
    algorithm: str,
    key_id: str,
    value: str,
    public_key: Ed25519PublicKey,
    expected_key_id: str | None,
) -> VerifyResult:
    if algorithm != signing.ALGORITHM:
        return VerifyResult(False, "unsupported_algorithm")
    if expected_key_id is not None and key_id != expected_key_id:
        return VerifyResult(False, "key_id_mismatch")
    try:
        signature = signing.b64url_decode(value)
    except ValueError:
        return VerifyResult(False, "signature_malformed")
    try:
        public_key.verify(signature, payload)
    except InvalidSignature:
        return VerifyResult(False, "signature_invalid")
    except Exception:
        return VerifyResult(False, "signature_malformed")
    return VerifyResult(True, "ok")


def verify_record(
    record: AuthorityRecord,
    public_key: Ed25519PublicKey,
    expected_key_id: str | None = None,
) -> VerifyResult:
    """Verify an authority record's signature over its canonical payload."""
    sig = record.signature
    return _check(
        record_signing_payload(record),
        sig.algorithm,
        sig.key_id,
        sig.value,
        public_key,
        expected_key_id,
    )


def verify_revocation(
    revocation: Revocation,
    public_key: Ed25519PublicKey,
    expected_key_id: str | None = None,
) -> VerifyResult:
    """Verify a revocation's signature over its canonical payload."""
    sig = revocation.signature
    return _check(
        revocation_signing_payload(revocation),
        sig.algorithm,
        sig.key_id,
        sig.value,
        public_key,
        expected_key_id,
    )


def verify_approval(
    record: ApprovalRecord,
    public_key: Ed25519PublicKey,
    expected_key_id: str | None = None,
) -> VerifyResult:
    """Verify a one-time approval override's signature (ADR-0010)."""
    sig = record.signature
    return _check(
        approval_signing_payload(record),
        sig.algorithm,
        sig.key_id,
        sig.value,
        public_key,
        expected_key_id,
    )
