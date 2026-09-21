"""Unit tests for Ed25519 signing and verification (invariant 13, ADR-0005).

All keys are ephemeral, generated in memory per test — no key material ever
reaches fixtures or source (invariant 12).
"""

from __future__ import annotations

import base64

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mandate.crypto import signing
from mandate.crypto.canonicalization import record_signing_payload, revocation_signing_payload
from mandate.crypto.verification import verify_record, verify_revocation
from mandate.domain.authority import AuthorityRecord, Revocation, SignatureBlock
from tests.support.factories import make_record


def _sign_record(
    record: AuthorityRecord, private_key: Ed25519PrivateKey, key_id: str = "k1"
) -> AuthorityRecord:
    value = signing.sign(private_key, record_signing_payload(record))
    return record.model_copy(
        update={"signature": SignatureBlock(algorithm="Ed25519", key_id=key_id, value=value)}
    )


def _sign_revocation(
    revocation: Revocation, private_key: Ed25519PrivateKey, key_id: str = "k1"
) -> Revocation:
    value = signing.sign(private_key, revocation_signing_payload(revocation))
    return revocation.model_copy(
        update={"signature": SignatureBlock(algorithm="Ed25519", key_id=key_id, value=value)}
    )


class TestKeyHandling:
    def test_seed_and_public_roundtrip(self):
        private_key, public_key = signing.generate_keypair()
        assert len(signing.private_key_seed(private_key)) == 32
        assert len(signing.public_key_raw(public_key)) == 32
        reloaded_private = signing.load_private_key(signing.private_key_seed(private_key))
        reloaded_public = signing.load_public_key(signing.public_key_raw(public_key))
        assert signing.public_key_raw(reloaded_public) == signing.public_key_raw(public_key)
        assert reloaded_private.sign(b"x") == private_key.sign(b"x")

    def test_wrong_seed_length_rejected(self):
        with pytest.raises(ValueError, match="32 bytes"):
            signing.load_private_key(b"short")
        with pytest.raises(ValueError, match="32 bytes"):
            signing.load_public_key(b"short")

    def test_b64url_roundtrip_and_malformed(self):
        raw = bytes(range(64))
        assert signing.b64url_decode(signing.b64url_encode(raw)) == raw
        assert "=" not in signing.b64url_encode(raw)
        for bad in ("", "!!!", "abc=", "abc$def"):
            with pytest.raises(ValueError, match="base64url"):
                signing.b64url_decode(bad)


class TestSignVerify:
    def test_roundtrip(self):
        private_key, public_key = signing.generate_keypair()
        sig = signing.sign(private_key, b"payload")
        assert public_key.verify(signing.b64url_decode(sig), b"payload") is None
        assert len(base64.urlsafe_b64decode(sig + "==")) == 64

    def test_ed25519_is_deterministic(self):
        private_key, _ = signing.generate_keypair()
        assert signing.sign(private_key, b"x") == signing.sign(private_key, b"x")

    def test_wrong_key_fails(self):
        priv_a, _ = signing.generate_keypair()
        _, pub_b = signing.generate_keypair()
        sig = signing.sign(priv_a, b"payload")
        with pytest.raises(InvalidSignature):
            pub_b.verify(signing.b64url_decode(sig), b"payload")

    def test_tampered_payload_fails(self):
        private_key, public_key = signing.generate_keypair()
        sig = signing.b64url_decode(signing.sign(private_key, b"payload"))
        with pytest.raises(InvalidSignature):
            public_key.verify(sig, b"payloaD")


# RFC 8032 §7.1 "Signature Checks" — Ed25519 known-answer vectors. These pin
# our raw Ed25519 primitive to the published standard: a signing implementation
# that is subtly broken (wrong scalar expansion, wrong encoding, a home-grown
# "Ed25519") would sign its own records consistently yet fail to reproduce
# these bytes. All three vectors use the raw sign() primitive, bypassing
# canonicalization, so the check is on the crypto itself (invariant 13).
_RFC8032_VECTORS: tuple[tuple[str, str, bytes, str, str], ...] = (
    # (name, secret_key_hex, message, public_key_hex, signature_hex)
    (
        "TEST 1 (message length 0)",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        b"",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "TEST 2 (message length 1)",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        bytes.fromhex("72"),
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "TEST 3 (message length 2)",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        bytes.fromhex("af82"),
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
)


class TestRFC8032KnownAnswer:
    @pytest.mark.parametrize(
        ("name", "seed_hex", "message", "pub_hex", "sig_hex"),
        _RFC8032_VECTORS,
        ids=[v[0] for v in _RFC8032_VECTORS],
    )
    def test_sign_reproduces_published_bytes(
        self, name: str, seed_hex: str, message: bytes, pub_hex: str, sig_hex: str
    ) -> None:
        seed = bytes.fromhex(seed_hex)
        expected_pub = bytes.fromhex(pub_hex)
        expected_sig = bytes.fromhex(sig_hex)

        private_key = signing.load_private_key(seed)
        # Key derivation matches the standard (seed -> public key).
        assert signing.public_key_raw(private_key.public_key()) == expected_pub
        # sign() reproduces the exact published Ed25519 signature bytes.
        assert signing.b64url_decode(signing.sign(private_key, message)) == expected_sig


class TestRecordVerification:
    def test_valid_record(self):
        private_key, public_key = signing.generate_keypair()
        signed = _sign_record(make_record(), private_key)
        result = verify_record(signed, public_key, expected_key_id="k1")
        assert result.valid
        assert result.reason == "ok"

    def test_tampered_record_fails(self):
        private_key, public_key = signing.generate_keypair()
        signed = _sign_record(make_record(), private_key)
        tampered = signed.model_copy(update={"purpose": "something else entirely"})
        result = verify_record(tampered, public_key)
        assert not result.valid
        assert result.reason == "signature_invalid"

    def test_wrong_key_fails(self):
        priv_a, _ = signing.generate_keypair()
        _, pub_b = signing.generate_keypair()
        signed = _sign_record(make_record(), priv_a)
        result = verify_record(signed, pub_b)
        assert not result.valid
        assert result.reason == "signature_invalid"

    def test_key_id_mismatch(self):
        private_key, public_key = signing.generate_keypair()
        signed = _sign_record(make_record(), private_key, key_id="k1")
        result = verify_record(signed, public_key, expected_key_id="k2")
        assert not result.valid
        assert result.reason == "key_id_mismatch"

    def test_unsupported_algorithm(self):
        private_key, public_key = signing.generate_keypair()
        signed = _sign_record(make_record(), private_key)
        forged = signed.model_copy(
            update={"signature": SignatureBlock(algorithm="RSA", key_id="k1", value="x")}
        )
        result = verify_record(forged, public_key)
        assert not result.valid
        assert result.reason == "unsupported_algorithm"

    def test_malformed_signature_value(self):
        private_key, public_key = signing.generate_keypair()
        signed = _sign_record(make_record(), private_key)
        forged = signed.model_copy(
            update={
                "signature": SignatureBlock(algorithm="Ed25519", key_id="k1", value="not-b64!!!")
            }
        )
        result = verify_record(forged, public_key)
        assert not result.valid
        assert result.reason == "signature_malformed"

    def test_signature_cannot_transfer_between_records(self):
        """A valid signature on record A fails on a different record B, even
        signed by the same key (different payload → different signature)."""
        private_key, public_key = signing.generate_keypair()
        signed_a = _sign_record(make_record(), private_key)
        record_b = make_record()
        forged_b = record_b.model_copy(update={"signature": signed_a.signature})
        result = verify_record(forged_b, public_key)
        assert not result.valid
        assert result.reason == "signature_invalid"


class TestRevocationVerification:
    def _revocation(self, record: AuthorityRecord) -> Revocation:
        return Revocation(
            schema_version="0.1",
            revocation_id="0" * 22 + "0001",
            record_id=record.record_id,
            revoked_at="2026-01-15T00:00:00Z",
            signature=SignatureBlock(algorithm="Ed25519", key_id="k1", value="placeholder"),
        )

    def test_valid_revocation(self):
        record = make_record()
        private_key, public_key = signing.generate_keypair()
        signed = _sign_revocation(self._revocation(record), private_key)
        result = verify_revocation(signed, public_key, expected_key_id="k1")
        assert result.valid
        assert result.reason == "ok"

    def test_tampered_revocation_fails(self):
        record = make_record()
        private_key, public_key = signing.generate_keypair()
        signed = _sign_revocation(self._revocation(record), private_key)
        tampered = signed.model_copy(update={"record_id": "0" * 25 + "1"})
        result = verify_revocation(tampered, public_key)
        assert not result.valid
        assert result.reason == "signature_invalid"
