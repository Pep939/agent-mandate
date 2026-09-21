"""Build the Phase-7 shadow-pilot evidence report.

Reads the ledger produced by `run_shadow_pilot` and, per deal, independently
re-verifies the whole event chain (`verify_chain`) and reconstructs the decision
narrative. It then checks the two load-bearing invariants:

  * no autonomous commitment - a state change on an approval-gated action
    (a NEEDS_APPROVAL decision) happened only after an explicit principal grant
    for the same request; and
  * no money moved - every deal that reached CAPTURED did so through the
    human-gated `capture_payment` grant (no payment provider is integrated;
    capture is authorization + recording only, real money is Phase 8).

The report carries a reproducible digest over the *normalized* decision
sequence (actions, outcomes, reasons, amounts, state transitions, approval
operations). Run-specific ULIDs and timestamps are deliberately excluded, so
re-running the same scenario yields the same digest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from mandate.crypto.canonicalization import canonical_sha256_hex
from mandate.domain.events import Event, EventType
from mandate.ledger.chain import verify_chain
from mandate.pilot.run import Intervention, PilotRun


@dataclass(frozen=True)
class ScreenedMessage:
    """One MESSAGE event as the report reads it (ADR-0016)."""

    direction: str
    screener: str
    available: bool
    detected: list[tuple[str, int]]
    hostility_bp: int
    declared: list[str]


@dataclass(frozen=True)
class DealReport:
    name: str
    deal_id: str
    final_state: str
    expected_state: str
    event_count: int
    chain_ok: bool
    chain_detail: str
    decisions: list[tuple[str, str, str, int | None]]
    transitions: list[tuple[str, str, str]]
    approval_ops: list[tuple[str, str]]
    autonomous_commit_violations: list[str]
    messages: list[ScreenedMessage]
    content_violations: list[str]


@dataclass
class PilotReport:
    deals: list[DealReport]
    total_events: int
    all_chains_ok: bool
    no_autonomous_commit: bool
    no_money_moved: bool
    captured_deals: list[str]
    interventions: list[Intervention]
    digest: str
    screened_messages: int = 0
    no_unscreened_disclosure: bool = True

    @property
    def ok(self) -> bool:
        return (
            self.all_chains_ok
            and self.no_autonomous_commit
            and self.no_money_moved
            and self.no_unscreened_disclosure
            and all(d.final_state == d.expected_state for d in self.deals)
        )


def _decisions(events: tuple[Event, ...]) -> list[tuple[str, str, str, int | None]]:
    out: list[tuple[str, str, str, int | None]] = []
    for e in events:
        if e.event_type is EventType.POLICY_DECISION:
            p = e.payload
            amount = cast("int | None", p.get("amount_minor"))
            out.append(
                (
                    str(p["action"]),
                    str(p["outcome"]),
                    str(p["reason_code"]),
                    amount,
                )
            )
    return out


def _transitions(events: tuple[Event, ...]) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for e in events:
        if e.event_type is EventType.STATE_TRANSITION:
            p = e.payload
            out.append((str(p["event"]), str(p["from_state"]), str(p["to_state"])))
    return out


def _approval_ops(events: tuple[Event, ...]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for e in events:
        if e.event_type is EventType.APPROVAL:
            p = e.payload
            out.append((str(p["operation"]), str(p["action"])))
    return out


def find_autonomous_commit_violations(events: tuple[Event, ...]) -> list[str]:
    """A state change on an approval-gated action that lacked a preceding grant.

    A STATE_TRANSITION that carries a request_id originating from a
    NEEDS_APPROVAL decision is only legitimate if an APPROVAL(granted) for the
    same request_id exists. Boundary transitions carry a command_id (no
    request_id) and are operator/counterparty actions, not agent commitments.
    """
    outcomes: dict[str, str] = {}
    granted: set[str] = set()
    for e in events:
        if e.event_type is EventType.POLICY_DECISION:
            outcomes[str(e.payload["request_id"])] = str(e.payload["outcome"])
        elif e.event_type is EventType.APPROVAL and e.payload.get("operation") == "granted":
            granted.add(str(e.payload["request_id"]))

    violations: list[str] = []
    for e in events:
        if e.event_type is not EventType.STATE_TRANSITION:
            continue
        p = e.payload
        rid_obj = p.get("request_id")
        if rid_obj is None:
            continue
        rid = str(rid_obj)
        if outcomes.get(rid) == "needs_approval" and rid not in granted:
            violations.append(
                f"state change on approval-gated action {str(p.get('action'))!r} "
                f"({p['event']!s}) with no preceding principal grant"
            )
    return violations


def _messages(events: tuple[Event, ...]) -> list[ScreenedMessage]:
    out: list[ScreenedMessage] = []
    for e in events:
        if e.event_type is not EventType.MESSAGE:
            continue
        payload = e.payload
        screen = cast("dict[str, object]", payload.get("screen") or {})
        detected = cast("list[dict[str, object]]", screen.get("detected") or [])
        out.append(
            ScreenedMessage(
                direction=str(payload.get("direction")),
                screener=str(screen.get("screener")),
                available=bool(screen.get("available", True)),
                detected=[
                    (str(d.get("field")), int(cast("int", d.get("confidence_bp"))))
                    for d in detected
                ],
                hostility_bp=int(cast("int", screen.get("hostility_bp", 0))),
                declared=[
                    str(f) for f in cast("list[object]", payload.get("declared_fields") or [])
                ],
            )
        )
    return out


def find_content_violations(events: tuple[Event, ...]) -> list[str]:
    """A message that went out although the screen found an undeclared leak.

    ADR-0016's promise in ledger terms: whenever an outbound MESSAGE event
    reports a detected field the agent did not declare, the decision that
    followed it must not be an ALLOW. If one is, the screen was consulted and
    then ignored — the exact failure the narrowing rule exists to prevent.
    """
    violations: list[str] = []
    pending: ScreenedMessage | None = None
    for e in events:
        if e.event_type is EventType.MESSAGE:
            messages = _messages((e,))
            pending = messages[0] if messages and messages[0].direction == "outbound" else None
            continue
        if e.event_type is EventType.POLICY_DECISION and pending is not None:
            undeclared = [f for f, _bp in pending.detected if f not in pending.declared]
            if undeclared and str(e.payload.get("outcome")) == "allow":
                violations.append(
                    f"message revealing {', '.join(sorted(undeclared))} was allowed out "
                    f"on action {str(e.payload.get('action'))!r}"
                )
            pending = None
    return violations


def _no_money_moved(deals: list[DealReport]) -> bool:
    """Every CAPTURED deal must have a granted capture_payment approval."""
    for d in deals:
        if d.final_state == "CAPTURED" and ("granted", "capture_payment") not in d.approval_ops:
            return False
    return True


def _digest(deals: list[DealReport]) -> str:
    normalized = [
        {
            "name": d.name,
            "final_state": d.final_state,
            "decisions": [list(x) for x in d.decisions],
            "transitions": [list(x) for x in d.transitions],
            "approval_ops": [list(x) for x in d.approval_ops],
        }
        for d in deals
    ]
    return canonical_sha256_hex(normalized)


def build_report(run: PilotRun) -> PilotReport:
    deals: list[DealReport] = []
    for spec in run.deals:
        deal_id = run.deal_ids[spec.name]
        events = run.store.events_for(deal_id)
        chain = verify_chain(events, run.public_key)
        deal = run.store.get_deal(deal_id)
        final_state = deal.state.value if deal is not None else "?"
        failures = find_autonomous_commit_violations(events)
        failure = chain.first_failure()
        deals.append(
            DealReport(
                name=spec.name,
                deal_id=deal_id,
                final_state=final_state,
                expected_state=spec.expected_terminal_state,
                event_count=len(events),
                chain_ok=chain.ok,
                chain_detail="" if failure is None else failure.detail,
                decisions=_decisions(events),
                transitions=_transitions(events),
                approval_ops=_approval_ops(events),
                autonomous_commit_violations=failures,
                messages=_messages(events),
                content_violations=find_content_violations(events),
            )
        )

    return PilotReport(
        deals=deals,
        total_events=sum(d.event_count for d in deals),
        all_chains_ok=all(d.chain_ok for d in deals),
        no_autonomous_commit=all(not d.autonomous_commit_violations for d in deals),
        no_money_moved=_no_money_moved(deals),
        captured_deals=[d.name for d in deals if d.final_state == "CAPTURED"],
        interventions=list(run.interventions),
        digest=_digest(deals),
        screened_messages=sum(len(d.messages) for d in deals),
        no_unscreened_disclosure=all(not d.content_violations for d in deals),
    )


def _fmt_money(minor: int | None) -> str:
    if minor is None:
        return "-"
    sign = "-" if minor < 0 else ""
    minor = abs(minor)
    return f"{sign}${minor // 100}.{minor % 100:02d}"


def _yes_no(flag: bool) -> str:
    return "yes" if flag else "NO"


def _message_lines(messages: list[ScreenedMessage]) -> list[str]:
    """The per-deal content-screen block (ADR-0016). Reads the signed MESSAGE
    events, never the text — which the ledger does not hold."""
    if not messages:
        return []
    lines = ["- Content screened:"]
    for m in messages:
        if not m.available:
            lines.append(
                f"  - {m.direction}: screen unavailable ({m.screener}) - held for a person"
            )
            continue
        found = ", ".join(f"{field} {bp // 100}%" for field, bp in m.detected) or "nothing"
        declared = ", ".join(m.declared) or "nothing"
        lines.append(
            f"  - {m.direction}: detected {found} | declared {declared} "
            f"| instruction-like {m.hostility_bp // 100}%"
        )
    return lines


def _deal_lines(index: int, d: DealReport, interventions: list[Intervention]) -> list[str]:
    """One deal's section: outcome, chain verdict, decisions, human calls,
    what the content screen saw, and any violation of the two invariants."""
    match = "ok" if d.final_state == d.expected_state else f"EXPECTED {d.expected_state}"
    lines = [
        f"## {index}. {d.name}",
        f"- Final state: **{d.final_state}** ({match})",
        f"- Event chain: {'verified' if d.chain_ok else 'FAILED: ' + d.chain_detail}",
        "- Decisions:",
    ]
    for action, outcome, reason, amount in d.decisions:
        amt = f" {_fmt_money(amount)}" if amount is not None else ""
        lines.append(f"  - {action}{amt} -> {outcome} ({reason})")
    if d.approval_ops:
        lines.append("- Human approvals:")
        lines.extend(f"  - {action}: {operation}" for operation, action in d.approval_ops)
    deal_interventions = [iv for iv in interventions if iv.deal_name == d.name]
    if deal_interventions:
        lines.append("- Interventions:")
        lines.extend(f"  - [{iv.actor}] {iv.action}: {iv.detail}" for iv in deal_interventions)
    lines.extend(_message_lines(d.messages))
    if d.autonomous_commit_violations:
        lines.append("- AUTONOMOUS-COMMIT VIOLATIONS:")
        lines.extend(f"  - {v}" for v in d.autonomous_commit_violations)
    if d.content_violations:
        lines.append("- CONTENT-SCREEN VIOLATIONS:")
        lines.extend(f"  - {v}" for v in d.content_violations)
    lines.append("")
    return lines


def render_markdown(report: PilotReport) -> str:
    lines: list[str] = []
    lines.append("# Agent Mandate - Phase 7 shadow pilot")
    lines.append("")
    lines.append(f"**Verdict: {'PASS' if report.ok else 'FAIL'}**")
    lines.append("")
    lines.append(f"- Deals: {len(report.deals)}  |  Ledger events: {report.total_events}")
    lines.append(f"- Every event chain independently verified: {_yes_no(report.all_chains_ok)}")
    lines.append(
        f"- No autonomous commitment on approval-gated actions: "
        f"{_yes_no(report.no_autonomous_commit)}"
    )
    lines.append(
        f"- No money moved (capture human-gated, no provider): {_yes_no(report.no_money_moved)}"
    )
    lines.append(
        f"- Messages screened before sending: {report.screened_messages}  |  "
        f"none went out with an undeclared disclosure: "
        f"{_yes_no(report.no_unscreened_disclosure)}"
    )
    lines.append(f"- Reproducible digest: `{report.digest[:16]}...`")
    lines.append("")

    for i, d in enumerate(report.deals, start=1):
        lines.extend(_deal_lines(i, d, report.interventions))

    lines.append("## Reproducible digest")
    lines.append(f"```{report.digest}```")
    lines.append("")
    return "\n".join(lines)
