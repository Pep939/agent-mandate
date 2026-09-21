"""Unit tests for the signed wire envelope (ADR-0012, invariants 1, 13, 14).

All identities are ephemeral, generated in memory per test — no key material
ever reaches fixtures or source (invariant 12).
"""

from __future__ import annotations

import pytest

from mandate.crypto.signing import generate_keypair, public_key_raw
from mandate.transport.envelope import (
    CounterpartyEventPayload,
    EnvelopeError,
    GatewayIdentity,
    MessageKind,
    ProposalPayload,
    ReceiptOutcome,
    ReceiptPayload,
    WireEnvelope,
    envelope_fingerprint,
    envelope_is_stale,
    envelope_signing_payload,
    load_peer_identity,
    make_envelope,
    parse_payload,
    verify_envelope,
    verify_receipt,
)
from tests.support.factories import new_ulid

NOW = "2026-09-03T12:00:00Z"


def _identity() -> GatewayIdentity:
    private_key, public_key = generate_keypair()
    return GatewayIdentity(identity_id=new_ulid(), public_key=public_key, private_key=private_key)


def _peer(identity: GatewayIdentity) -> GatewayIdentity:
    """The receiver's view of `identity`: public key only (pre-shared)."""
    return GatewayIdentity(identity_id=identity.identity_id, public_key=identity.public_key)


def _proposal() -> ProposalPayload:
    return ProposalPayload(
        action="accept_agreement",
        deal_id=new_ulid(),
        amount_minor=250_000,
        currency="USD",
        idempotency_key=new_ulid(),
    )


def _make(
    sender: GatewayIdentity | None = None,
    payload: object | None = None,
    message_id: str | None = None,
    idempotency_key: str | None = None,
    recipient_id: str | None = None,
) -> WireEnvelope:
    return make_envelope(
        kind=MessageKind.PROPOSAL,
        payload=payload if payload is not None else _proposal(),
        sender=sender if sender is not None else _identity(),
        recipient_id=recipient_id if recipient_id is not None else new_ulid(),
        message_id=message_id if message_id is not None else new_ulid(),
        idempotency_key=idempotency_key if idempotency_key is not None else new_ulid(),
        issued_at=NOW,
    )


def _receipt(
    sender: GatewayIdentity | None = None,
    *,
    responds_to: str | None = None,
    outcome: ReceiptOutcome = ReceiptOutcome.ACCEPTED,
    status: int = 200,
    recipient_id: str | None = None,
    issued_at: str = NOW,
) -> WireEnvelope:
    return make_envelope(
        kind=MessageKind.RECEIPT,
        payload=ReceiptPayload(
            responds_to=responds_to if responds_to is not None else new_ulid(),
            outcome=outcome,
            status=status,
        ),
        sender=sender if sender is not None else _identity(),
        recipient_id=recipient_id if recipient_id is not None else new_ulid(),
        message_id=new_ulid(),
        idempotency_key=new_ulid(),
        issued_at=issued_at,
    )


class TestCanonicalForm:
    def test_key_order_invariance(self):
        a = _proposal()
        b = ProposalPayload(
            idempotency_key=a.idempotency_key,
            currency=a.currency,
            amount_minor=a.amount_minor,
            deal_id=a.deal_id,
            action=a.action,
        )
        assert a == b
        sender = _identity()
        fixed = {
            "message_id": new_ulid(),
            "idempotency_key": new_ulid(),
            "recipient_id": new_ulid(),
        }
        assert envelope_signing_payload(_make(sender, a, **fixed)) == envelope_signing_payload(
            _make(sender, b, **fixed)
        )

    def test_bytes_are_stable_ascii_and_exclude_signature(self):
        env = _make()
        payload = envelope_signing_payload(env)
        assert payload == envelope_signing_payload(env)
        payload.decode("ascii")
        assert b'"signature"' not in payload

    def test_float_amount_rejected(self):
        with pytest.raises(ValueError, match="float"):
            ProposalPayload(
                action="accept_agreement",
                deal_id=new_ulid(),
                amount_minor=1.5,  # type: ignore[arg-type]
                currency="USD",
                idempotency_key=new_ulid(),
            )


class TestSignVerify:
    def test_roundtrip(self):
        sender = _identity()
        verify_envelope(_make(sender), _peer(sender))

    def test_deterministic_signature(self):
        sender = _identity()
        env = _make(sender)
        again = make_envelope(
            kind=MessageKind.PROPOSAL,
            payload=parse_payload(env),
            sender=sender,
            recipient_id=env.recipient_id,
            message_id=env.message_id,
            idempotency_key=env.idempotency_key,
            issued_at=env.issued_at,
        )
        assert again.signature.value == env.signature.value

    def test_tampered_payload_fails(self):
        sender = _identity()
        env = _make(sender)
        tampered = env.model_copy(update={"payload": {**env.payload, "amount_minor": 1}})
        with pytest.raises(EnvelopeError, match="signature"):
            verify_envelope(tampered, _peer(sender))

    def test_tampered_recipient_fails(self):
        sender = _identity()
        env = _make(sender)
        tampered = env.model_copy(update={"recipient_id": new_ulid()})
        with pytest.raises(EnvelopeError, match="signature"):
            verify_envelope(tampered, _peer(sender))

    def test_unknown_sender_fails(self):
        """A message from a gateway we have not registered: rejected."""
        registered = _identity()
        stranger = _identity()
        env = _make(stranger)
        with pytest.raises(EnvelopeError, match="does not match registered peer"):
            verify_envelope(env, _peer(registered))

    def test_forged_sender_identity_fails(self):
        """Signed by A but claiming to be B, presented to a gateway trusting B."""
        a = _identity()
        b = _identity()
        env = _make(a)
        forged = env.model_copy(update={"sender_id": b.identity_id})
        with pytest.raises(EnvelopeError, match="identity key"):
            verify_envelope(forged, _peer(b))

    def test_algorithm_spoof_rejected(self):
        sender = _identity()
        env = _make(sender)
        for spoof in ("ed25519", "RSA", "Ed25519v2"):
            bad = env.model_copy(
                update={"signature": env.signature.model_copy(update={"algorithm": spoof})}
            )
            with pytest.raises(EnvelopeError, match="algorithm spoof"):
                verify_envelope(bad, _peer(sender))

    def test_key_id_mismatch_rejected(self):
        sender = _identity()
        env = _make(sender)
        bad = env.model_copy(
            update={"signature": env.signature.model_copy(update={"key_id": new_ulid()})}
        )
        with pytest.raises(EnvelopeError, match="identity key"):
            verify_envelope(bad, _peer(sender))

    def test_cross_message_non_transfer(self):
        """A signature valid on one envelope is invalid on any other."""
        sender = _identity()
        env_a = _make(sender)
        env_b = _make(sender)
        assert env_a.signature.value != env_b.signature.value
        swapped = env_b.model_copy(update={"signature": env_a.signature})
        with pytest.raises(EnvelopeError, match="signature"):
            verify_envelope(swapped, _peer(sender))

    def test_malformed_signature_value_rejected(self):
        sender = _identity()
        env = _make(sender)
        bad = env.model_copy(
            update={"signature": env.signature.model_copy(update={"value": "!!!"})}
        )
        with pytest.raises(EnvelopeError, match="base64url"):
            verify_envelope(bad, _peer(sender))

    def test_verify_only_identity_cannot_sign(self):
        sender = _identity()
        with pytest.raises(EnvelopeError, match="verify-only"):
            _make(_peer(sender))


class TestFreshness:
    def test_fresh_envelope_within_window(self):
        env = _make()
        assert not envelope_is_stale(env, NOW, 300)

    def test_envelope_older_than_window_is_stale(self):
        env = _make()
        assert envelope_is_stale(env, "2026-09-03T12:05:01Z", 300)

    def test_exactly_at_window_is_not_stale(self):
        env = _make()
        assert not envelope_is_stale(env, "2026-09-03T12:05:00Z", 300)

    def test_future_skew_beyond_window_is_stale(self):
        env = _make()
        assert envelope_is_stale(env, "2026-09-03T11:50:00Z", 300)
        # Small forward skew stays inside the window.
        assert not envelope_is_stale(env, "2026-09-03T11:59:00Z", 300)

    def test_window_is_configurable(self):
        env = _make()
        assert not envelope_is_stale(env, "2026-09-03T12:05:01Z", 400)
        assert envelope_is_stale(env, "2026-09-03T12:05:01Z", 300)


class TestModelValidation:
    def _bare(self, **overrides: object) -> WireEnvelope:
        fields: dict[str, object] = {
            "schema_version": "0.1",
            "message_id": new_ulid(),
            "idempotency_key": new_ulid(),
            "sender_id": new_ulid(),
            "recipient_id": new_ulid(),
            "kind": "proposal",
            "payload": {},
            "issued_at": NOW,
            "signature": {"algorithm": "Ed25519", "key_id": new_ulid(), "value": "v"},
        }
        fields.update(overrides)
        return WireEnvelope.model_validate(fields)

    def test_schema_version_pinned(self):
        with pytest.raises(ValueError, match="schema_version"):
            self._bare(schema_version="0.2")

    def test_bad_ulid_rejected(self):
        with pytest.raises(ValueError, match="ULID"):
            self._bare(message_id="!" * 26)

    def test_bad_timestamp_rejected(self):
        with pytest.raises(ValueError, match="RFC3339"):
            self._bare(issued_at="yesterday")

    def test_payload_parsed_per_kind(self):
        parsed = parse_payload(_make())
        assert isinstance(parsed, ProposalPayload)
        assert parsed.action == "accept_agreement"

    def test_payload_shape_errors_are_envelope_errors(self):
        env = _make()
        missing = env.model_copy(update={"payload": {"action": "accept_agreement"}})
        with pytest.raises(EnvelopeError, match="not a valid proposal payload"):
            parse_payload(missing)
        float_amount = env.model_copy(update={"payload": {**env.payload, "amount_minor": 1.5}})
        with pytest.raises(EnvelopeError, match="not a valid proposal payload"):
            parse_payload(float_amount)

    def test_counterparty_and_receipt_payloads(self):
        cp = CounterpartyEventPayload(deal_id=new_ulid(), event="quote_received")
        rcpt = ReceiptPayload(
            responds_to=new_ulid(), outcome=ReceiptOutcome.REJECTED, status=400, reason="x"
        )
        assert cp.event == "quote_received"
        assert rcpt.outcome is ReceiptOutcome.REJECTED


class TestFingerprintAndPeers:
    def test_fingerprint_stable_and_sensitive(self):
        sender = _identity()
        env = _make(sender)
        assert envelope_fingerprint(env) == envelope_fingerprint(env)
        changed = env.model_copy(update={"payload": {**env.payload, "action": "cancel_deal"}})
        assert envelope_fingerprint(changed) != envelope_fingerprint(env)
        other = _make(sender)
        re_sig = changed.model_copy(update={"signature": other.signature})
        assert envelope_fingerprint(re_sig) != envelope_fingerprint(changed)

    def test_load_peer_identity(self):
        sender = _identity()
        peer = load_peer_identity(sender.identity_id, sender.public_key_b64url)
        assert peer.private_key is None
        assert public_key_raw(peer.public_key) == public_key_raw(sender.public_key)
        with pytest.raises(EnvelopeError, match="base64url"):
            load_peer_identity(new_ulid(), "!!!")
        with pytest.raises(EnvelopeError, match="32-byte"):
            load_peer_identity(new_ulid(), "aGVsbG8")


class TestVerifyReceipt:
    """The counterparty-side receipt-verify path (Phase 6 threat row)."""

    def test_genuine_receipt_verifies(self):
        authority = _identity()
        sent_message_id = new_ulid()
        receipt = _receipt(authority, responds_to=sent_message_id)
        payload = verify_receipt(receipt, _peer(authority), expected_responds_to=sent_message_id)
        assert payload.outcome is ReceiptOutcome.ACCEPTED
        assert payload.responds_to == sent_message_id

    def test_tampered_payload_fails(self):
        authority = _identity()
        sent_message_id = new_ulid()
        receipt = _receipt(authority, responds_to=sent_message_id)
        # Flip the outcome after signing: accepted -> rejected.
        tampered_payload = {**receipt.payload, "outcome": "rejected"}
        tampered = receipt.model_copy(update={"payload": tampered_payload})
        with pytest.raises(EnvelopeError, match="signature"):
            verify_receipt(tampered, _peer(authority), expected_responds_to=sent_message_id)

    def test_unregistered_sender_fails(self):
        authority = _identity()
        stranger = _identity()
        receipt = _receipt(stranger, responds_to=new_ulid())
        with pytest.raises(EnvelopeError, match="does not match registered peer"):
            verify_receipt(
                receipt, _peer(authority), expected_responds_to=receipt.payload["responds_to"]
            )

    def test_forged_sender_identity_fails(self):
        """A stranger signs but claims the authority's id — the key_id betrays it."""
        authority = _identity()
        attacker = _identity()
        receipt = _receipt(attacker, responds_to=new_ulid())
        forged = receipt.model_copy(update={"sender_id": authority.identity_id})
        with pytest.raises(EnvelopeError, match="identity key"):
            verify_receipt(
                forged, _peer(authority), expected_responds_to=receipt.payload["responds_to"]
            )

    def test_replayed_receipt_for_other_message_rejected(self):
        """A genuine receipt for a different message is a replay, not an answer."""
        authority = _identity()
        receipt = _receipt(authority, responds_to=new_ulid())
        with pytest.raises(EnvelopeError, match="not an answer to this message"):
            verify_receipt(receipt, _peer(authority), expected_responds_to=new_ulid())

    def test_non_receipt_kind_rejected(self):
        sender = _identity()
        proposal = _make(sender)
        with pytest.raises(EnvelopeError, match="is not a receipt"):
            verify_receipt(proposal, _peer(sender), expected_responds_to=proposal.message_id)

    def test_stale_receipt_rejected(self):
        authority = _identity()
        sent_message_id = new_ulid()
        receipt = _receipt(authority, responds_to=sent_message_id, issued_at=NOW)
        payload = verify_receipt(
            receipt,
            _peer(authority),
            expected_responds_to=sent_message_id,
            now="2026-09-03T12:04:00Z",
            max_age_seconds=300,
        )
        assert payload.outcome is ReceiptOutcome.ACCEPTED
        with pytest.raises(EnvelopeError, match="stale"):
            verify_receipt(
                receipt,
                _peer(authority),
                expected_responds_to=sent_message_id,
                now="2026-09-03T12:05:01Z",
                max_age_seconds=300,
            )

    def test_max_age_without_now_is_rejected(self):
        """Fail-closed: a freshness window cannot be silently skipped."""
        authority = _identity()
        sent_message_id = new_ulid()
        receipt = _receipt(authority, responds_to=sent_message_id)
        with pytest.raises(EnvelopeError, match="without now"):
            verify_receipt(
                receipt,
                _peer(authority),
                expected_responds_to=sent_message_id,
                max_age_seconds=300,
            )
