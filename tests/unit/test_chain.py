"""Unit tests for the event-chain helpers (ADR-0009)."""

from __future__ import annotations

from mandate.crypto.signing import b64url_decode
from mandate.domain.deals import DealState
from mandate.domain.decisions import Outcome
from mandate.domain.events import GENESIS_HASH, EventType, event_signing_bytes
from mandate.domain.input import ActorKind
from mandate.ledger.chain import (
    build_event,
    make_event_id,
    plan_transition,
    verify_chain,
)
from tests.support.factories import NOW, make_deal, make_signer, new_ulid


def _chain_signer_pair():
    return make_signer(), make_signer()


def _build(deal_id: str, seq: int, prev: str, signer, **overrides):
    payload = overrides.pop("payload", {"n": seq})
    return build_event(
        event_id=new_ulid(),
        deal_id=deal_id,
        sequence_number=seq,
        event_type=EventType.POLICY_DECISION,
        actor_kind=ActorKind.AGENT,
        actor_id=new_ulid(),
        authority_record_id=None,
        previous_event_hash=prev,
        payload=payload,
        occurred_at=NOW,
        recorded_at=NOW,
        signer=signer,
        **overrides,
    )


class TestMakeEventId:
    def test_is_26_char_crockford(self):
        eid = make_event_id(NOW)
        assert len(eid) == 26
        allowed = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        assert set(eid.upper()) <= allowed

    def test_unique_per_call(self):
        assert make_event_id(NOW) != make_event_id(NOW)

    def test_ordering_follows_timestamp(self):
        early = make_event_id("2026-01-01T00:00:00Z")
        late = make_event_id("2026-06-01T00:00:00Z")
        assert early < late


class TestBuildAndVerify:
    def test_single_event_chain_verifies(self):
        signer = make_signer()
        event = _build(new_ulid(), 0, GENESIS_HASH, signer)
        report = verify_chain([event], signer.public_key)
        assert report.ok
        assert report.first_failure() is None

    def test_multi_event_chain_verifies(self):
        signer = make_signer()
        deal_id = new_ulid()
        e0 = _build(deal_id, 0, GENESIS_HASH, signer)
        e1 = _build(deal_id, 1, e0.event_hash, signer)
        e2 = _build(deal_id, 2, e1.event_hash, signer)
        assert verify_chain([e0, e1, e2], signer.public_key).ok

    def test_wrong_key_fails(self):
        signer = make_signer()
        other = make_signer()
        event = _build(new_ulid(), 0, GENESIS_HASH, signer)
        report = verify_chain([event], other.public_key)
        assert not report.ok
        assert report.first_failure().name.endswith("_signature")

    def test_event_hash_is_deterministic(self):
        # Ed25519 signatures are intentionally non-deterministic (RFC 8032
        # nonce blinding), so the chain's determinism rests on event_hash:
        # the same logical event must always produce the same hash, and any
        # produced signature must verify over those bytes.
        signer = make_signer()
        common = {
            "event_id": new_ulid(),
            "deal_id": new_ulid(),
            "sequence_number": 0,
            "event_type": EventType.POLICY_DECISION,
            "actor_kind": ActorKind.AGENT,
            "actor_id": new_ulid(),
            "authority_record_id": None,
            "previous_event_hash": GENESIS_HASH,
            "payload": {"x": 1},
            "occurred_at": NOW,
            "recorded_at": NOW,
        }
        a = build_event(**common, signer=signer)
        b = build_event(**common, signer=signer)
        assert a.event_hash == b.event_hash
        for event in (a, b):
            signer.public_key.verify(
                b64url_decode(event.signature.value), event_signing_bytes(event)
            )


class TestVerifyDetectsTampering:
    def _tampered(self, original, **updates):
        return original.model_copy(update=updates)

    def test_edited_payload_detected(self):
        signer = make_signer()
        e0 = _build(new_ulid(), 0, GENESIS_HASH, signer, payload={"amount": 100})
        e1 = _build(new_ulid(), 1, e0.event_hash, signer, payload={"amount": 200})
        evil = self._tampered(e1, payload={"amount": 999999})
        report = verify_chain([e0, evil], signer.public_key)
        assert not report.ok
        assert report.first_failure().name.endswith("_payload_hash")

    def test_edited_event_hash_detected(self):
        signer = make_signer()
        e0 = _build(new_ulid(), 0, GENESIS_HASH, signer)
        evil = self._tampered(e0, event_hash="ab" * 32)
        assert not verify_chain([evil], signer.public_key).ok

    def test_reorder_detected(self):
        signer = make_signer()
        deal_id = new_ulid()
        e0 = _build(deal_id, 0, GENESIS_HASH, signer)
        e1 = _build(deal_id, 1, e0.event_hash, signer)
        # swap sequence + prev so the list is out of order
        bad1 = self._tampered(e1, sequence_number=0, previous_event_hash=GENESIS_HASH)
        bad0 = self._tampered(e0, sequence_number=1, previous_event_hash=e1.event_hash)
        report = verify_chain([bad1, bad0], signer.public_key)
        assert not report.ok

    def test_sequence_gap_detected(self):
        signer = make_signer()
        deal_id = new_ulid()
        e0 = _build(deal_id, 0, GENESIS_HASH, signer)
        e2 = _build(deal_id, 2, e0.event_hash, signer)  # skipped 1
        report = verify_chain([e0, e2], signer.public_key)
        assert not report.ok
        assert report.first_failure().name.endswith("_sequence")


class TestPlanTransition:
    def test_non_allow_is_decision_only(self):
        deal = make_deal(state=DealState.DRAFT)
        assert plan_transition(deal, "request_quote", Outcome.DENY) == (None, None)

    def test_allow_with_valid_state_yields_event(self):
        from mandate.domain.deals import DealEvent

        deal = make_deal(state=DealState.DRAFT)
        event, abort = plan_transition(deal, "request_quote", Outcome.ALLOW)
        assert abort is None
        assert event is DealEvent.QUOTE_REQUESTED

    def test_allow_with_stale_state_aborts(self):
        deal = make_deal(state=DealState.CAPTURED)
        event, abort = plan_transition(deal, "request_quote", Outcome.ALLOW)
        assert event is None
        assert abort is not None and abort.startswith("stale_state")

    def test_allow_unknown_action_aborts(self):
        deal = make_deal(state=DealState.DRAFT)
        event, abort = plan_transition(deal, "nonsense", Outcome.ALLOW)
        assert event is None
        assert abort is not None

    def test_resolve_dispute_is_decision_only(self):

        deal = make_deal(state=DealState.DISPUTED)
        event, abort = plan_transition(deal, "resolve_dispute", Outcome.ALLOW)
        assert abort is None
        assert event is None
