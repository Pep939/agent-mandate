"""Authority lifecycle: status resolution, revocation, delegation chains.

Pure logic over models already verified at the boundary. Time enters only as
the explicit `now` input, never read from a clock (invariant 2, A8).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from mandate.domain.authority import AuthorityRecord, RecordStatus, Revocation

__all__ = [
    "delegation_violations",
    "resolve_status",
    "revocation_applies",
    "scope_violations",
]


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def resolve_status(record: AuthorityRecord, now: str, revoked: bool = False) -> RecordStatus:
    """Resolve the current status of a record (boundary-supplied `now`).

    A recorded `status=revoked` sticks; `revoked=True` carries a verified
    signed Revocation; otherwise the record expires when `now` is strictly
    past `expires_at` (boundary convention: `now == expires_at` is still
    valid, matching Phase 1).
    """
    if revoked or record.status is RecordStatus.REVOKED:
        return RecordStatus.REVOKED
    if _parse(now) > _parse(record.expires_at):
        return RecordStatus.EXPIRED
    return RecordStatus.ACTIVE


def revocation_applies(revocation: Revocation, record: AuthorityRecord, now: str) -> bool:
    """Whether a revocation fact binds a record as of `now`.

    Signature validity is checked separately (crypto.verification); this is
    the pure target/timing logic: the record ids match and `revoked_at` has
    arrived.
    """
    if revocation.record_id != record.record_id:
        return False
    return _parse(revocation.revoked_at) <= _parse(now)


def scope_violations(child: AuthorityRecord, parent: AuthorityRecord) -> list[str]:  # noqa: C901
    """Per-field narrowing checks (ADR-0006).

    Returns named violations; an empty list means the child is a valid
    narrowing of the parent.
    """
    violations: list[str] = []
    if not set(child.allowed_actions) <= set(parent.allowed_actions):
        violations.append("allowed_actions_not_subset")
    if not set(parent.prohibited_actions) <= set(child.prohibited_actions):
        violations.append("prohibited_actions_not_superset")
    if child.spend_cap.currency != parent.spend_cap.currency:
        violations.append("spend_cap_currency_mismatch")
    elif child.spend_cap.amount_minor > parent.spend_cap.amount_minor:
        violations.append("spend_cap_exceeds_parent")
    if child.max_negotiation_rounds > parent.max_negotiation_rounds:
        violations.append("max_negotiation_rounds_exceed_parent")
    if not set(child.disclosure_fields) <= set(parent.disclosure_fields):
        violations.append("disclosure_fields_not_subset")
    if not set(parent.requires_human_approval_for) <= set(child.requires_human_approval_for):
        violations.append("approval_gates_not_superset")
    if _parse(child.not_before) < _parse(parent.not_before):
        violations.append("not_before_earlier_than_parent")
    if _parse(child.expires_at) > _parse(parent.expires_at):
        violations.append("expires_after_parent")
    if parent.counterparty_id is not None and child.counterparty_id != parent.counterparty_id:
        violations.append("counterparty_mismatch_with_parent")
    return violations


def delegation_violations(
    record: AuthorityRecord,
    records: Mapping[str, AuthorityRecord],
    now: str | None = None,
) -> list[str]:
    """Walk the parent chain upward from `record` and report violations.

    Checks, per hop: the parent resolves, the chain stays acyclic, and the
    child is a valid narrowing of the parent (ADR-0006). When `now` is given,
    ancestors that are recorded-revoked or expired are reported too
    (revoking a parent invalidates descendants, invariant 7).

    `records` maps record_id → record for every ancestor. An empty return
    means the chain is valid and fully resolvable.
    """
    violations: list[str] = []
    seen: set[str] = {record.record_id}
    cursor: AuthorityRecord | None = record
    while cursor is not None and cursor.parent_record_id is not None:
        parent_id = cursor.parent_record_id
        if parent_id in seen:
            violations.append(f"cycle_at:{parent_id}")
            break
        parent = records.get(parent_id)
        if parent is None:
            violations.append(f"unresolvable_parent:{parent_id}")
            break
        for violation in scope_violations(cursor, parent):
            violations.append(f"{parent_id}:{violation}")
        if now is not None and resolve_status(parent, now) is not RecordStatus.ACTIVE:
            violations.append(f"ancestor_{resolve_status(parent, now).value}:{parent_id}")
        seen.add(parent_id)
        cursor = parent
    return violations
