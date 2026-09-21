"""Ed25519 signing over canonical payloads (invariant 13, ADR-0005).

Pure: no I/O. Key material is created or loaded here only as in-memory
bytes supplied by the caller; the dev key script and tests are the only
things that ever touch a key (invariant 12).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mandate.crypto.canonicalization import approval_signing_payload
from mandate.domain.approvals import ApprovalRecord
from mandate.domain.authority import SignatureBlock

__all__ = [
    "ALGORITHM",
    "GatewaySigner",
    "b64url_decode",
    "b64url_encode",
    "gateway_signer",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "make_approval_record",
    "private_key_seed",
    "public_key_raw",
    "sign",
]

ALGORITHM = "Ed25519"

_B64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def b64url_encode(raw: bytes) -> str:
    """Base64url, unpadded (RFC 4648 §5), ASCII."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    """Inverse of b64url_encode. Raises ValueError on malformed input."""
    if not value or not set(value) <= _B64URL_ALPHABET:
        msg = f"not a valid base64url string: {value!r}"
        raise ValueError(msg)
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh ephemeral Ed25519 keypair (tests, development)."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_seed(private_key: Ed25519PrivateKey) -> bytes:
    """The 32-byte seed. Treat as a secret; never log or persist to the repo."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        msg = f"Ed25519 seed must be 32 bytes, got {len(seed)}"
        raise ValueError(msg)
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    """The 32-byte raw public key (safe to store and display)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    if len(raw) != 32:
        msg = f"Ed25519 public key must be 32 bytes, got {len(raw)}"
        raise ValueError(msg)
    return Ed25519PublicKey.from_public_bytes(raw)


def sign(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    """Sign canonical payload bytes → base64url Ed25519 signature string.

    Ed25519 is deterministic: same key + same payload → identical signature.
    """
    return b64url_encode(private_key.sign(payload))


@dataclass(frozen=True)
class GatewaySigner:
    """In-memory gateway signing key (ADR-0009: the gateway signs every event).

    Never serialized, logged or persisted to the repo (invariant 12).
    """

    key_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def sign_bytes(self, payload: bytes) -> str:
        return sign(self.private_key, payload)


def gateway_signer(key_id: str, seed: bytes) -> GatewaySigner:
    """Build a signer from a 32-byte seed (caller-supplied; ADR-0005)."""
    private_key = load_private_key(seed)
    return GatewaySigner(
        key_id=key_id, private_key=private_key, public_key=private_key.public_key()
    )


def make_approval_record(
    *,
    approval_record_id: str,
    deal_id: str,
    request_id: str,
    parent_authority_record_id: str,
    action: str,
    amount_minor: int | None,
    currency: str,
    proposal_digest: str,
    issued_at: str,
    signer: GatewaySigner,
) -> ApprovalRecord:
    """Mint + sign a one-time approval override (ADR-0010).

    The signature covers the canonical bytes of the record excluding its
    signature (invariant 13). ``issued_at`` and ``approval_record_id`` are
    caller-supplied — the domain never calls a clock (invariant 2).
    """
    unsigned = {
        "schema_version": "0.1",
        "approval_record_id": approval_record_id,
        "deal_id": deal_id,
        "request_id": request_id,
        "parent_authority_record_id": parent_authority_record_id,
        "action": action,
        "amount_minor": amount_minor,
        "currency": currency,
        "proposal_digest": proposal_digest,
        "issued_at": issued_at,
    }
    provisional = ApprovalRecord(
        **unsigned,
        signature=SignatureBlock(algorithm=ALGORITHM, key_id=signer.key_id, value=""),
    )
    value = sign(signer.private_key, approval_signing_payload(provisional))
    return ApprovalRecord(
        **unsigned,
        signature=SignatureBlock(algorithm=ALGORITHM, key_id=signer.key_id, value=value),
    )
