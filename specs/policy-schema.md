# Spec: Policy Engine Schema (v0.1)

Status: FINAL for v0.1 (2026-08-31). Ambiguities P1–P3 resolved per
`docs/decisions/ADR-0004-v01-spec-defaults.md`.

The policy engine is a **pure function**:

```text
PolicyDecision = evaluate(PolicyInput)
```

No I/O, no model calls, no clock calls, no network (invariant 2). Time, verified authority
claims, and delegation-chain claims enter as immutable inputs supplied by the
application boundary (brief §11 correction). Same input ⇒ same decision, always.

## Action vocabulary (closed set)

The authority record's `allowed_actions` / `prohibited_actions` /
`requires_human_approval_for` fields reference only these tokens. Free-text actions
are rejected at record-validation time — a closed set is what makes the engine
deterministic and the mandate human-readable.

```text
request_quote
counteroffer
accept_agreement
start_work
propose_change
approve_change_order
claim_completion
accept_completion
open_dispute
initiate_payment
capture_payment
cancel_deal
resolve_dispute
```

RESOLVED (ADR-0004 P1): Is this vocabulary sufficient for the service-transaction wedge, or do
industry-specific actions (e.g. `reschedule`, `send_reminder`) belong in v0.1?
Proposed default: this set only; extension via a versioned vocabulary table (schema
`0.2`) rather than free text.

## PolicyInput (immutable)

```yaml
schema_version: "0.1"
request_id: "ULID, anti-replay"
now: "RFC3339 trusted timestamp supplied by the boundary"
actor:
  kind: "principal|agent|system|counterparty"
  id: "ULID"
authority:
  record: "parsed authority record (brief §10)"
  signature_valid: bool        # verified by boundary, passed in as a claim
  delegation_chain:            # each link pre-verified by boundary
    - parent_record_id: "ULID"
      scope_narrowing_valid: bool
  status: "active|revoked|expired"  # current status at `now`, resolved by boundary
counterparty:
  id: "ULID or null"           # audience check against record.counterparty_id
deal:
  deal_id: "ULID"
  state: "DealState"
  negotiated_rounds: int
  committed_minor: int         # cumulative money already committed incl. approved changes
  open_disputes: int
  open_approvals: int
proposal:
  action: "action vocabulary token"
  deal_id: "ULID"
  amount_minor: "int or null"  # additional money requested NOW (not cumulative)
  currency: "ISO-4217"
  disclosure_fields: []        # field tokens the action DECLARES it would expose
  idempotency_key: "ULID"
  content_sha256: "sha256 of the text this action would send, or null"
content: "ContentClaims or null"  # ADR-0016; what the boundary's screen said
```

`content` is present only when the proposal carried text. Like
`signature_valid`, it is a claim computed at the boundary and passed in
immutably — the engine performs no I/O to obtain it. It may only narrow a
decision (ADR-0016); see `specs/content-screen.md`.

## PolicyDecision (output)

Per brief §11:

```yaml
outcome: "allow|deny|needs_approval"
reason_code: "machine_stable_reason"
explanation: "human-readable explanation"
matched_rule: "rule identifier"
authority_record_id: "record ID"
evaluated_at: "trusted `now` from input"
input_digest: "hash of canonical PolicyInput"
```

`reason_code` values (initial set): `ok`, `unknown_schema_version`, `missing_field`,
`invalid_signature_claim`, `record_revoked`, `record_expired`, `not_yet_valid`,
`delegation_chain_broken`, `audience_mismatch`, `replay_detected`, `action_prohibited`,
`action_not_allowed`, `invalid_transition`, `disclosure_not_allowed`,
`spend_cap_exceeded`, `negotiation_limit_reached`, `approval_required`,
`payment_blocked_by_dispute`, `payment_blocked_by_open_approval`, `unknown_action`,
plus the four content-screen codes (ADR-0016): `disclosure_detected`,
`content_review_required`, `hostile_content_suspected`,
`content_screen_unavailable`. None of the four can accompany an `allow`.

Of these, `missing_field` (rejected at `PolicyInput` construction) and
`replay_detected` (the boundary's seen-request store, ADR-0007) are **boundary-owned**:
`evaluate()` never emits them. They live in the shared enum so the boundary and the
engine speak one vocabulary.

## Evaluation order

Exactly as brief §11:

1. Validate `schema_version` and required fields.
2. Verify signature claim and canonical payload digest.
3. Check `not_before`, `expires_at`, and current status (revocation).
4. Validate delegation chain and parent scope.
5. Validate audience/counterparty and anti-replay (`nonce`, `request_id`).
6. Apply explicit `prohibited_actions`.
7. Require `proposal.action` ∈ `allowed_actions`.
8. Validate current deal state permits the action (transition table,
   `specs/state-machine.md`).
9. Validate `disclosure_fields` ⊆ `record.disclosure_fields` (allow-list, invariant 9).
9b. **Content screen — deny (ADR-0016).** If the screen detected a field that
    is not on `record.disclosure_fields` with confidence ≥ `CONTENT_DENY_BP`
    (9000 bp) → `deny` / `disclosure_detected`. Step 9 checks what the agent
    *declared*; step 9b checks what the text *contains*. Placed before the
    spend cap so a leaking message is stopped, not sent to ask about money.
10. Compute cumulative financial exposure:
    `record.spend_cap.amount_minor >= deal.committed_minor + proposal.amount_minor`
    (taxes/fees per open question — AMBIGUITY P3). The currency check happens **here,
    before the comparison**: `proposal.currency` must equal `record.spend_cap.currency`,
    because a cross-currency total is not comparable (engine order pinned by
    `test_step10_currency_checked_before_cap`).
11. Check limits: `deal.negotiated_rounds < record.max_negotiation_rounds` for
    negotiation actions.
12. If action ∈ `requires_human_approval_for` (or state rules require it) and no
    recorded approval covers this `idempotency_key` → `needs_approval`.
12b. **Content screen — hold (ADR-0016).** `needs_approval` when the screen
    was unavailable (`content_screen_unavailable`), when an undeclared field
    reaches `CONTENT_HOLD_BP` (7000 bp, `content_review_required`), or when
    hostility reaches it (`hostile_content_suspected`). Persuasion and
    urgency are advisory and never change an outcome.
13. Allow only if all prior checks passed.

**Precedence (invariant 6):** an earlier step that denies always wins; a later step
can never upgrade a deny to allow. `prohibited_actions` (step 6) beats
`allowed_actions` (step 7) unconditionally. Default outcome is DENY.

**Narrowing (invariant 16):** steps 9b and 12b may only move an outcome
toward `deny`. Removing the `content` field from any input can never turn an
`allow` into a deny or hold, and adding it can never do the reverse —
property-tested over arbitrary inputs.

## Money rules

- Integer minor units only. No floats anywhere in the domain.
- Exposure is cumulative across the whole deal, including approved change orders
  (invariant 8). `proposal.amount_minor` is the *increment*; the engine adds it to
  `deal.committed_minor` before comparing to the cap.
- RESOLVED (ADR-0004 P2, matches A2). Over-cap behavior:
  outcome `needs_approval`, not `deny` — a human may approve a one-time override,
  recorded as its own signed authority record.
- RESOLVED (ADR-0004 P3): Taxes/tips/fees/refunds in cumulative exposure:
  v0.1 counts the agreed total price only; itemized tax/fee handling arrives with the
  payment phase (Phase 8) — document in ADR.

## Approval semantics

- `needs_approval` is a first-class outcome: the application layer presents it to the
  human; the engine never assumes approval.
- **The engine is not re-run on approval** (ADR-0010). `PolicyInput` carries no
  recorded-approval field, so `evaluate()` cannot — and does not — factor an approval in.
  `approve → allow` is a boundary/ledger concern: granting applies the original action's
  state transition directly (`commit_approval`), bound to the exact proposal by
  `proposal_digest` + `action` + `amount_minor`. It does not re-enter the anti-replay
  gate or re-evaluate — the original request already consumed its
  `request_id`/`nonce`/`idempotency_key`.
- An approval for a different amount, action, or counterparty does not apply — it is a
  different proposal and must be re-proposed.
- Approvals are single-use: consumed exactly once, when the transition commits.

## Anti-replay

- `nonce` in the authority record + `request_id` + `idempotency_key` per proposal.
- The pure engine checks *shape* (fields present, ids well-formed); the boundary
  (Phase 3+) owns the seen-request store. The engine treats a replay claim from the
  boundary as input (`replay_detected` is available as a reason code when the
  boundary pre-checks fail).

## Determinism requirement

`evaluate` must be pure: given identical `PolicyInput` bytes it returns identical
`PolicyDecision` bytes. This is a property test (see `docs/test-plan.md`), not a hope.

The `input_digest` is a determinism aid, not a published value: no v0.1 consumer pins
specific digest bytes. When the engine moved to the shared canonicalizer (ADR-0005:
`ensure_ascii` + validated inputs) the digest bytes changed; only that the digest is
stable for identical input is required.
