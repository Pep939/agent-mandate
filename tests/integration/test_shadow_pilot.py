"""Phase-7 shadow pilot: invariants over a realistic, human-gated scenario.

The pilot drives six synthetic field-service deals through the live console +
policy + ledger + approval stack over HTTP. These tests assert the terminal
states, that every event chain independently re-verifies, the two load-bearing
invariants (no autonomous commitment, no money without a human-gated capture),
that specific overreaches are denied for the right reason, and that the
evidence digest is reproducible across runs.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from mandate.pilot.report import DealReport, build_report
from mandate.pilot.run import PilotRun, run_shadow_pilot
from mandate.pilot.scenario import SHADOW_DEALS


@pytest.fixture(scope="module")
def run() -> Iterator[PilotRun]:
    yield run_shadow_pilot()


@pytest.fixture(scope="module")
def report(run: PilotRun):
    return build_report(run)


def _deal(report: object, index: int) -> DealReport:
    deals = report.deals  # type: ignore[attr-defined]
    assert deals[index].name == SHADOW_DEALS[index].name
    return deals[index]


def test_every_deal_reaches_its_expected_terminal_state(report: object) -> None:
    for i, spec in enumerate(SHADOW_DEALS):
        d = _deal(report, i)
        assert d.final_state == spec.expected_terminal_state, (d.name, d.final_state)


def test_every_event_chain_independently_verifies(report: object) -> None:
    assert report.all_chains_ok  # type: ignore[attr-defined]
    for d in report.deals:  # type: ignore[attr-defined]
        assert d.chain_ok, d.chain_detail


def test_no_autonomous_commitment_on_approval_gated_actions(report: object) -> None:
    assert report.no_autonomous_commit  # type: ignore[attr-defined]
    for d in report.deals:  # type: ignore[attr-defined]
        assert d.autonomous_commit_violations == []


def test_no_money_moved_without_a_human_gated_capture(report: object) -> None:
    assert report.no_money_moved  # type: ignore[attr-defined]
    for d in report.deals:  # type: ignore[attr-defined]
        if d.final_state == "CAPTURED":
            assert ("granted", "capture_payment") in d.approval_ops


def test_report_overall_verdict_passes(report: object) -> None:
    assert report.ok  # type: ignore[attr-defined]


def test_overcap_escalation_is_needs_approval_then_resolved(report: object) -> None:
    approved = _deal(report, 1)
    assert (
        "accept_agreement",
        "needs_approval",
        "spend_cap_exceeded",
        250_000,
    ) in approved.decisions
    assert ("granted", "accept_agreement") in approved.approval_ops
    assert approved.final_state == "AGREED"

    declined = _deal(report, 2)
    assert (
        "accept_agreement",
        "needs_approval",
        "spend_cap_exceeded",
        500_000,
    ) in declined.decisions
    assert ("denied", "accept_agreement") in declined.approval_ops
    assert declined.final_state == "QUOTE_RECEIVED"


def test_scope_change_pushing_past_cap_is_escalated(report: object) -> None:
    d = _deal(report, 3)
    assert ("approve_change_order", "needs_approval", "spend_cap_exceeded", 300_000) in d.decisions
    assert d.final_state == "IN_PROGRESS"


def test_dispute_gates_payment_until_resolved(report: object) -> None:
    d = _deal(report, 4)
    # A payment attempt while the deal is DISPUTED is denied (not a valid
    # transition); after the dispute is resolved the same payment is allowed.
    assert ("initiate_payment", "deny", "invalid_transition", 200_000) in d.decisions
    assert ("initiate_payment", "allow", "ok", 200_000) in d.decisions
    assert ("capture_payment", "needs_approval", "approval_required", 200_000) in d.decisions
    assert d.final_state == "CAPTURED"


def test_content_screen_stops_a_leak_and_passes_a_clean_message(report: object) -> None:
    """The content deal (ADR-0016) end to end through the real stack.

    The agent's first message is clean and goes out; a message that reveals
    the principal's price floor is denied before it is sent; the same
    commercial point, said without the leak, is allowed."""
    d = _deal(report, 5)
    assert ("counteroffer", "deny", "disclosure_detected", 280_000) in d.decisions
    assert ("counteroffer", "allow", "ok", 320_000) in d.decisions
    assert d.final_state == "AGREED"

    outbound = [m for m in d.messages if m.direction == "outbound"]
    leaked = [m for m in outbound if {f for f, _ in m.detected} - set(m.declared)]
    assert leaked, "expected one message the screen found an undeclared field in"
    assert {f for f, _ in leaked[0].detected} >= {"price_floor"}
    assert d.content_violations == []


def test_inbound_injection_is_recorded_not_obeyed(report: object) -> None:
    """A counterparty note carrying 'ignore previous instructions' still
    applies its transition — the state machine is unchanged — but the
    screen's verdict is now signed into the evidence chain."""
    d = _deal(report, 5)
    inbound = [m for m in d.messages if m.direction == "inbound"]
    assert any(m.hostility_bp >= 7_000 for m in inbound)
    assert ("quote_received", "QUOTE_REQUESTED", "QUOTE_RECEIVED") in d.transitions


def test_no_message_went_out_with_an_undeclared_disclosure(report: object) -> None:
    assert report.no_unscreened_disclosure  # type: ignore[attr-defined]
    for d in report.deals:  # type: ignore[attr-defined]
        assert d.content_violations == []


def test_every_screened_message_names_its_pinned_screener(report: object) -> None:
    """A verdict is only re-checkable if the chain says which screener, at
    which version, produced it (ADR-0016)."""
    seen = 0
    for d in report.deals:  # type: ignore[attr-defined]
        for m in d.messages:
            assert m.screener == "fixture:keyword-0.1"
            seen += 1
    assert seen == report.screened_messages  # type: ignore[attr-defined]
    assert seen > 0


def test_misbehaving_agent_overreaches_are_denied(report: object) -> None:
    d = _deal(report, 6)
    assert ("start_work", "deny", "invalid_transition", None) in d.decisions
    assert ("cancel_deal", "deny", "action_prohibited", None) in d.decisions
    assert ("counteroffer", "deny", "record_revoked", 10_000) in d.decisions
    # Nothing the agent did advanced the deal past the first quote request.
    assert d.final_state == "QUOTE_REQUESTED"


def test_human_interventions_are_recorded(report: object) -> None:
    actions = {iv.action for iv in report.interventions}  # type: ignore[attr-defined]
    assert {"grant", "deny", "revoke", "boundary:quote_received"} <= actions


def test_evidence_digest_is_reproducible_across_runs() -> None:
    first = build_report(run_shadow_pilot()).digest
    second = build_report(run_shadow_pilot()).digest
    assert first == second
    assert len(first) == 64
