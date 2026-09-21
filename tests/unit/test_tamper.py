"""Tamper-resistance suites (founder-locked, brief §13, ADR-0008/0009).

Suite A — a rogue agent cannot write: the only writer is process_request,
malicious proposals are logged as DENY without state change, and no
state-transition exists without a traceable policy decision.

Suite B — database tampering is detected: the hash chain + per-event
signatures detect edit, delete, reorder, duplicate, truncate and forged
append.

Suite C — evidence-bundle tampering is detected: a valid bundle passes
independent verification; any mutation fails with a named check.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from mandate.application.services import process_request
from mandate.crypto.canonicalization import canonical_sha256_hex
from mandate.domain.deals import DealState
from mandate.domain.events import EventType
from mandate.domain.input import ActorKind
from mandate.ledger.chain import verify_chain
from mandate.ledger.evidence import BundleSummary, build_bundle, verify_bundle
from mandate.ledger.store import InMemoryLedgerStore
from tests.support.factories import (
    NOW,
    PAST,
    make_deal,
    make_input,
    make_proposal,
    make_signer,
    new_ulid,
)

RECORDED = "2026-01-15T12:00:01Z"


def _flow():
    """Build a small two-event deal: request_quote ALLOW (decision event +
    transition event). Returns (store, deal, signer, events)."""
    store = InMemoryLedgerStore()
    deal = make_deal(state=DealState.DRAFT)
    store.create_deal(deal, PAST)
    signer = make_signer()
    pi = make_input(deal=deal, proposal=make_proposal(deal_id=deal.deal_id, action="request_quote"))
    process_request(pi, store, signer, recorded_at=RECORDED)
    return store, deal, signer, store.events_for(deal.deal_id)


class TestSuiteA_RogueAgentCannotWrite:
    def test_only_writer_is_process_request(self):
        # the store exposes no free-text append; events come only from
        # commit_request / commit_transition, both of which are driven by a
        # PolicyDecision or an explicit DealEvent.
        store = InMemoryLedgerStore()
        deal = make_deal()
        store.create_deal(deal, PAST)
        assert store.events_for(deal.deal_id) == ()

    def test_malicious_agent_is_denied_and_no_state_change(self):
        store = InMemoryLedgerStore()
        deal = make_deal(state=DealState.DRAFT)
        store.create_deal(deal, PAST)
        signer = make_signer()
        # an agent tries an action its mandate prohibits
        from mandate.domain.authority import ActionToken

        pi = make_input(
            deal=deal,
            record=make_input().authority.record.model_copy(
                update={"prohibited_actions": [ActionToken.REQUEST_QUOTE]}
            ),
            proposal=make_proposal(deal_id=deal.deal_id, action="request_quote"),
        )
        result = process_request(pi, store, signer, recorded_at=RECORDED)
        assert result.decision is not None
        assert result.decision.outcome.value == "deny"
        events = store.events_for(deal.deal_id)
        assert len(events) == 1
        assert events[0].event_type is EventType.POLICY_DECISION
        assert events[0].payload["outcome"] == "deny"
        # no state transition happened
        assert store.get_deal(deal.deal_id) == deal

    def test_every_transition_has_traceable_decision(self):
        store, deal, _, _ = _flow()
        events = store.events_for(deal.deal_id)
        decisions = {
            e.payload["request_id"] for e in events if e.event_type is EventType.POLICY_DECISION
        }
        transitions = [e for e in events if e.event_type is EventType.STATE_TRANSITION]
        for t in transitions:
            # an action-driven transition carries the same request_id
            assert t.payload.get("request_id") in decisions or ("command_id" in t.payload), (
                "state transition with no traceable decision/command"
            )


class TestSuiteB_DbTamperDetected:
    def test_edit_detected(self):
        _, _, signer, events = _flow()
        original = events[0]  # an ALLOW decision
        tampered = original.model_copy(update={"payload": {**original.payload, "outcome": "deny"}})
        bad = [tampered if e.event_id == original.event_id else e for e in events]
        report = verify_chain(bad, signer.public_key)
        assert not report.ok

    def test_delete_detected(self):
        _, _, signer, events = _flow()
        # drop the first event; the chain now starts mid-stream
        if len(events) > 1:
            report = verify_chain(events[1:], signer.public_key)
            assert not report.ok  # first event no longer links to GENESIS

    def test_reorder_detected(self):
        _, _, signer, events = _flow()
        if len(events) >= 2:
            swapped = [events[1], events[0]]
            report = verify_chain(swapped, signer.public_key)
            assert not report.ok

    def test_duplicate_detected(self):
        _, _, signer, events = _flow()
        dup = [*events, events[-1]]
        report = verify_chain(dup, signer.public_key)
        assert not report.ok  # sequence number collision at the tail

    def test_truncate_detected_via_bundle(self):
        # a raw truncated chain still self-verifies (hash chain is
        # self-consistent); detection requires the external witness, which is
        # the evidence bundle summary. See test suite C.
        store, deal, signer, events = _flow()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=store.get_deal(deal.deal_id),  # type: ignore[arg-type]
            deal_created_at=PAST,
            events=events,
            records=[make_input().authority.record],
            revocations=[],
            signer=signer,
        )
        truncated = bundle.model_copy(update={"events": events[:1]})
        report = verify_bundle(truncated)
        assert not report.ok

    def test_forged_append_detected(self):
        _, deal, signer, events = _flow()
        # an attacker appends an event chained to the head but signed by a
        # different key
        from mandate.ledger.chain import build_event

        forger = make_signer()
        forged = build_event(
            event_id=new_ulid(),
            deal_id=deal.deal_id,
            sequence_number=len(events),
            event_type=EventType.POLICY_DECISION,
            actor_kind=ActorKind.AGENT,
            actor_id=new_ulid(),
            authority_record_id=None,
            previous_event_hash=events[-1].event_hash,
            payload={"forged": True},
            occurred_at=NOW,
            recorded_at=RECORDED,
            signer=forger,
        )
        report = verify_chain([*events, forged], signer.public_key)
        assert not report.ok
        assert report.first_failure().name.endswith("_signature")

    @given(st.integers(min_value=0, max_value=3))
    @settings(max_examples=20, deadline=None)
    def test_property_random_mutation_detected(self, which):
        _, _, signer, events = _flow()
        if not events:
            return
        target = events[which % len(events)]
        # flip one hash field
        mutated = target.model_copy(
            update={"event_hash": "f" * 64 if which % 2 else "0" * 63 + "1"}
        )
        bad = [mutated if e.event_id == target.event_id else e for e in events]
        assert not verify_chain(bad, signer.public_key).ok


class TestSuiteC_EvidenceBundleTamper:
    def _bundle(self):
        store, deal, signer, events = _flow()
        current = store.get_deal(deal.deal_id)
        assert current is not None
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=events,
            records=[make_input().authority.record],
            revocations=[],
            signer=signer,
        )
        return bundle, signer

    def test_valid_bundle_passes(self):
        bundle, _ = self._bundle()
        report = verify_bundle(bundle)
        assert report.ok
        assert report.first_failure() is None

    def test_byte_flip_in_event_payload_fails(self):
        bundle, _ = self._bundle()
        ev = bundle.events[0]  # an ALLOW decision
        bad = ev.model_copy(update={"payload": {**ev.payload, "outcome": "deny"}})
        tampered = bundle.model_copy(
            update={"events": [bad if e.event_id == ev.event_id else e for e in bundle.events]}
        )
        report = verify_bundle(tampered)
        assert not report.ok

    def test_swap_revocation_fails(self):
        bundle, _ = self._bundle()
        # swap in a revocation for a different record
        from mandate.domain.authority import Revocation, SignatureBlock

        other = Revocation(
            schema_version="0.1",
            revocation_id=new_ulid(),
            record_id=new_ulid(),
            revoked_at=NOW,
            signature=SignatureBlock(algorithm="ed25519", key_id="k", value="v"),
        )
        tampered = bundle.model_copy(update={"revocations": [other]})
        report = verify_bundle(tampered)
        assert not report.ok
        assert any(c.name == "revocations_sha256" and not c.ok for c in report.checks)

    def test_swapped_record_fails(self):
        bundle, _ = self._bundle()
        swapped = bundle.model_copy(update={"authority_records": [make_input().authority.record]})
        report = verify_bundle(swapped)
        assert not report.ok
        assert any(c.name == "records_sha256" and not c.ok for c in report.checks)

    def test_reexported_truncation_detected_by_summary_signature(self):
        # A2 #7: a DB-access attacker truncates the tail and re-exports. The
        # re-export recomputes the summary hashes, so every hash-based check
        # passes on the forged bundle — only the summary signature (ADR-0015,
        # unproducible without the gateway's chain key) fails.
        store, deal, signer, events = _flow()
        current = store.get_deal(deal.deal_id)
        assert current is not None
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=events,
            records=[make_input().authority.record],
            revocations=[],
            signer=signer,
        )
        truncated = events[:1]
        v = bundle.verification
        reexported_summary = BundleSummary(
            chain_head_event_hash=truncated[-1].event_hash,
            event_count=len(truncated),
            chain_sha256=canonical_sha256_hex([e.model_dump(mode="json") for e in truncated]),
            records_sha256=v.records_sha256,
            revocations_sha256=v.revocations_sha256,
        )
        reexported = bundle.model_copy(
            update={"events": truncated, "verification": reexported_summary}
        )
        report = verify_bundle(reexported)
        assert not report.ok
        assert {c.name for c in report.checks if not c.ok} == {"summary_signature"}
