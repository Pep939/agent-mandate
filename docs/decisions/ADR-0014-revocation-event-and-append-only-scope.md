# ADR-0014: Schema 0.2 — revocation as a chain event; append-only scope on all governed tables

Status: accepted (2026-09-04, maintainer approval). Amended the same day on the
implementation pass — decision 2 (the `approvals` exclusion) and two
vocabulary alignments; the amendment is recorded in the amendment section below.

## Context

ADR-0009 fixed the event vocabulary at six types
(`POLICY_DECISION`, `STATE_TRANSITION`, `APPROVAL`, `MESSAGE`, `ARTIFACT`,
`PAYMENT`) and said extension "is a schema `0.2` change, never ad hoc." This
ADR is that change. It is driven by two findings from the 2026-09-04 external
audit, both verified against the tree by the working session before this ADR
was drafted:

1. **Revocation is invisible to the chain.** `put_revocation` writes a plain
   row to the `revocations` table; the decision to revoke — an authority
   change that takes effect immediately (invariant 7) — produces no event.
   Invariant 5 ("every allow, deny and approval-required decision is logged")
   does not hold for the revoke decision, and the chain alone cannot
   reconstruct that a mandate died. Deleting the row silently un-revokes:
   `build_claim` resolves status via `list_revocations`
   (`application/claims.py`), so a DB-level actor with write access restores
   authority by deleting a row, and the hash chain never notices.
2. **The append-only guarantee covers one table.** The BEFORE
   UPDATE OR DELETE trigger (`adapters/postgres/db.py`) exists only on
   `events`. `revocations`, `authority_records`, `approvals`, `seen_nonces`,
   `seen_requests`, `idempotency`, `seen_commands` and `message_dedup` are all
   freely mutable, and nothing stops TRUNCATE (row triggers do not fire on
   TRUNCATE). ADR-0008 promises a least-privilege role ("INSERT/SELECT on
   `events`, never UPDATE/DELETE") but no migration creates the role or its
   grants.

An adjacent question this ADR also settles, because C1 forces the choice:
**key custody** — the ADR-0005 deferral that has now passed its "Phase 4+"
horizon.

## Decisions

### 1. The event vocabulary grows to seven: `REVOCATION`

`EventType` gains `REVOCATION = "revocation"`. The event payload is the signed
`Revocation` record itself (already a signed domain object:
`revocation_id`, `record_id`, `revoked_at`, `signature`) — so
`verify_revocation` is unchanged, and the chain gains an event whose payload
verifies against the gateway key like any other signed fact.

- `actor_kind`: `PRINCIPAL` — the operator revoking through the console acts
  as the principal (the domain actor vocabulary has no `HUMAN`; this mirrors
  the approval-decision path, ADR-0010).
- `authority_record_id`: the revoked record.
- **Which chain:** the deal linked to the revoked record via the
  `deal_authority` mapping introduced by the C1 persistence work. v0.1 is one
  deal per top-level record, so the mapping is 1:1; the event lands on that
  deal's chain.
- The `revocations` table row stays (it is the lookup index behind
  `list_revocations`); the event is the evidence, the row is the index. Both
  are written atomically in the commit transaction, in both backends,
  mirroring `commit_approval`.
- Why an event and not just a better-protected row: the core claim is that
  every decision is *independently reconstructable from the chain*. A
  side-table row, however trigger-protected, is not part of the tamper-evident
  structure — truncating it is not provable, and a chain exported without it
  is a clean history.

### 2. The append-only trigger covers all governed tables

BEFORE UPDATE OR DELETE row triggers on: `events`, `revocations`,
`authority_records`, `seen_nonces`, `seen_requests`, `idempotency`,
`seen_commands`, `message_dedup`. Plus BEFORE TRUNCATE statement triggers on
the same eight.

`deals` and `approvals` are deliberately excluded: their rows are
current-state projections. `deals.state`, `negotiated_rounds`,
`committed_minor` and the counters change on every transition; an `approvals`
row is rewritten when the operator decides it (`pending` →
`granted`/`denied`, `decided_by`, `decided_at`, `command_id`). Both histories
live in `events` — a decision rides an `APPROVAL` event carrying the signed
`ApprovalRecord` — and the chain is what is tamper-evident; the rows are
indexes.

Amendment (2026-09-04, implementation pass): the draft named `approvals` as a
ninth triggered table, but `commit_approval` updates that row by design in
both backends — the trigger as drafted would have broken the approval flow.
The `deals` exclusion logic, applied consistently, covers it.

Addendum (2026-09-05, C1): the `deal_links` table (the persisted
deal → mandate registry that makes gateway restarts safe) joins the
governed set as the **ninth** triggered table — it is an evidence index
whose only writes are new links and whose history must never be
rewritten, so it gets the same BEFORE UPDATE/DELETE + TRUNCATE guards.
`deals` and `approvals` stay excluded as projections. Migration 0005
creates the table and its triggers; migration 0004 keeps its
revision-pinned eight-table subset so fresh upgrades do not reference
`deal_links` before 0005; `roles.sql` grants `mandate_app`
INSERT/SELECT/REFERENCES on it (no UPDATE).

### 3. The least-privilege role becomes DDL, not a docstring

`migrations/sql/roles.sql` — an ops script run by a deployer with elevated
privileges, deliberately outside the Alembic chain — creates `mandate_app`
with INSERT/SELECT/REFERENCES on all ten tables, UPDATE on exactly the two
projection tables (`deals`, `approvals` — the only rows the app rewrites),
and no DELETE/TRUNCATE/DDL. A Postgres-gated test connects as `mandate_app`
and asserts it cannot UPDATE `events` or DELETE from `revocations`, while
UPDATE on `deals` and `approvals` succeeds.

### 4. Key custody for v0.1: persisted gateway key, principal key deferred

Closes the ADR-0005 deferral. v0.1 runs one persisted keypair per gateway
(seed from env or `.dev/keys/`, stable `key_id`) that signs mandates,
revocations and events after an authenticated operator's console action.
"A human mandate" in v0.1 means: minted and revoked only through the
authenticated operator's console, signed by that operator's gateway. A
separate human-held principal key (gateway as delegate) is explicitly
deferred to the standards-adapter phase, where the external credential format
(A2A OBO credential) defines the key model. Rationale: the operator is the
only human in the v0.1 loop, and a two-key ceremony before a counterparty
exists buys ceremony, not a new actor.

## Consequences

- Event sequences for any deal that experiences a revocation grow by one
  event. Verified on the implementation pass: no existing test, race suite or
  Phase 7 pilot flow revokes, so no pinned count or digest changed.
- `verify_chain` mechanics are unchanged (the event type is data in the
  chain); evidence bundles now carry `REVOCATION` events, so a revoked
  mandate is visible in an offline bundle.
- The wire gateway is unchanged in v0.1: revocation is a console path. A
  revocation envelope kind is deferred — the envelope schema is 0.1 with
  three kinds, and a fourth kind is its own decision.
- `EventType` is now a seven-type vocabulary. The policy engine does not
  consume event types and is unaffected.
- Out of scope: the principal key (deferred, above), revocation over the
  wire, and any multi-key / HSM custody (ADR-0005's production horizon,
  unchanged).
