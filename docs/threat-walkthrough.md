# Threat Walkthrough — Can a Bad Agent Manipulate Mandate?

Status: living document (2026-09-03). Sits alongside `docs/threat-model.md`
(that one names the threats; this one walks the *mechanisms* a malicious agent
would use and the specific walls that stop each, and audits whether the
foundation actually holds).

**How to read the labels.** Every claim below is marked one of:
- **Verified** — pinned by a test in this repo, cited with a file.
- **Reasoned** — follows from the design, but not yet pinned by a test.
- **Deferred** — a known, scheduled test in a later phase.
- **Gap** — not yet addressed; named so it is a decision, not a silence.

Safety is the number-one property of this product. This document's job is to
keep the difference between "we believe it's safe" and "we have shown it's
safe" visible at a glance, so the maintainer can see exactly how much of the
former is backed by the latter.

---

## 1. The core asymmetry

A malicious agent can **propose** anything. It cannot **authorize, alter,
replay, or hide** anything. That asymmetry is the entire design. It holds for
one structural reason:

> **In v0.1 the LLM is not in the authorization path.** The agent's output is
> an *input* to a deterministic, pure function. It never talks to a person who
> might be convinced; it talks to a warden with no opinions that reads exactly
> one thing the agent cannot forge: a signature over canonical bytes, for which
> the agent does not hold the key.

LLM output, counterparty messages, Agent Cards, webhook payloads, and imported
documents are all **untrusted data** (invariant 1, invariant 11). Data can
trigger evaluation; it cannot grant authority.

**Where the content screen sits in this (ADR-0016).** A typed classifier now
reads message text and hands the engine an opinion about it. That does not
weaken the asymmetry, because the opinion is wired one-way: it can move a
decision toward *hold* or *deny* and never toward *allow* (invariant 16,
property-tested). So the screen is a second untrusted party whose worst case
is a false alarm. A wrong, miscalibrated or prompt-injected screen costs
availability — someone reviews a message that was fine — and can never hand
an agent authority. The warden still has no opinions; it just gained a smoke
detector.

## 2. Attack → wall → proof

| A bad agent tries… | The wall | Status |
|---|---|---|
| Persuade / prompt-inject its way to approval | Engine never reads proposal notes as authority; only signed records carry it; no model call or I/O in `domain`/`policy` (banned-imports AST scan). A content screen may score the text, but its claims can only hold or deny — never permit (invariant 16) | Verified — `test_banned_imports.py`, `test_content_monotonicity.py`, invariants 1 and 16 |
| Propose over the spend cap | Cumulative spend check → DENY or human NEEDS_APPROVAL, never a silent commit | Verified — `test_adversarial.py:35` (incl. the **split-into-small-increments** bypass), invariant 8 |
| Bypass the cap by many small approved change orders | Cumulative exposure counts the whole deal; the 10th increment crosses into NEEDS_APPROVAL | Verified — `test_adversarial.py:35-62` |
| Duplicate / retry a winning proposal to double-commit | Idempotency: returns the *original* decision, never re-evaluates; one atomic commit per transaction | Verified — ADR-0007, `test_anti_replay.py`, `test_ledger_store.py` |
| Replay a proposal that was valid yesterday | Nonce binds to one record + the transition is re-checked against *stored* state and aborts if the deal has moved | Verified — ADR-0007 + invariant 3, `test_ledger_store.py` (stale-state abort) |
| Edit the mandate to raise its own cap | Canonical bytes + Ed25519 signature; one changed byte fails verification | Verified — `test_signing.py:98`, `test_canonicalization.py` (golden vector) |
| Move a valid signature from record A to record B to fake authority | Signature covers the exact canonical payload; cross-record transfer fails | Verified — `test_signing.py:143` |
| Widen scope via a delegation child | Per-field narrowing only; a child can only shrink; a revoked/expired ancestor voids all descendants, rechecked every evaluation | Verified — ADR-0006, `test_lifecycle.py` |
| Act outside the time window | `now` is boundary-supplied; the domain never calls a clock, so time can't be faked from inside | Verified — ADR-0004 A8, invariant 2 |
| Propose in an impossible state | 360-pair exhaustive transition table; 322 invalid pairs each pinned to deny; terminal states admit nothing | Verified — `test_transitions.py:86-130` |
| Move money while a dispute or required approval is open | Engine step 8 → DENY, both conditions | Verified — `test_adversarial.py:90-109`, invariant 10 |
| Disclose a field outside the allow-list | Engine step → DENY, explicit allow-list match | Verified — `test_adversarial.py:27`, invariant 9 |
| Edit / delete / reorder / truncate / forge-append the ledger to hide what it did | Three layers: DB role can't, a DB trigger refuses UPDATE/DELETE, and the hash chain + per-event signature make any change *provable* | Verified — tamper suites A/B/C, `test_tamper.py`; `test_postgres.py` (trigger) |
| Forge a webhook / counterparty message into a state change | Invariant 11 (data, not authority) + `commit_transition` re-check + `seen_commands` idempotency; still cannot sign | Verified — ADR-0009, `test_ledger_store.py` |
 | Deny-by-default under any single break | 14 named single-axis breaks each pinned to DENY; deny-by-default + never-raises over arbitrary well-typed input | Verified — `test_properties.py:273`, `:220` |
 | **Forge a wire envelope** — send a proposal signed as a peer it is not (Phase 6) | Identity key ≠ chain key (ADR-0012); sender must be in the peer registry; an unknown `sender_id` is rejected **before** policy runs, commits nothing | Verified — `test_gateway_abuse.py::test_unregistered_sender_is_rejected_and_commits_nothing` |
 | **Tamper the payload** of a signed envelope in transit (Phase 6) | The signature covers the exact canonical envelope bytes; one changed byte fails verification before dispatch | Verified — `test_envelope.py`, `test_gateway_abuse.py::test_tampered_payload_fails_signature` |
 | **Replay a stale envelope** over the wire (Phase 6) | Wire `idempotency_key` → the dedup store returns the *stored answer* for a byte-identical redelivery; no re-evaluation, no duplicate commit (invariant 14) | Verified — `test_two_gateways.py::test_replayed_message_is_idempotent_no_duplicate` |
 | **Reuse an idempotency key for different content** to overwrite a prior answer (ADR-0007 wire-level, Phase 6) | The dedup verdict is keyed on `sender + key + fingerprint`; a matching key with a *different* fingerprint is `HOSTILE` and rejected — the stored answer is never replaced | Verified — `test_gateway_abuse.py::test_idempotency_key_reused_for_different_content_is_hostile` |
  | **Forge a receipt** back to the agent to fake an allow/deny (Phase 6) | The counterparty verifies every receipt with `verify_receipt` before reading the outcome: signature against the registered authority identity, `responds_to` bound to *its own* message id (a genuine receipt for a different message is a replay, not an answer), and a fail-closed freshness window | Verified — `verify_receipt` (`src/mandate/transport/envelope.py`), used by `scripts/two_gateways.py`; forged, tampered, replayed and stale receipts each rejected over real HTTP — `tests/adversarial/test_receipt_tampering.py`; unit-pinned — `tests/unit/test_envelope.py::TestVerifyReceipt` |

## 3. The four honest residuals

These are the real limits. Naming them now, not at first incident:

1. **It can try to convince *you*.** The one lever a bad agent still has is a
   persuasive note that makes the *human* grant. Guardrails: the approval
   question is worded by **code, not the agent** (fixed `reason_code` →
   sentence map); its text renders **inert** (never HTML); the approval is
   bound to the **exact** amount and action. Since ADR-0016 the operator also
   gets a second, code-generated opinion beside the agent's prose: the content
   screen scores how instruction-like and how persuasive the text is, the
   badge sits next to the approval question, the queue sorts by urgency, and
   the verdict is signed into the chain — so a grant made against a flagged
   message is visible afterwards. But a human who reads a good note and
   knowingly clicks yes is beyond software — **the human is the last line, by
   design.** That is the product, not a defect.
2. **A fully compromised *operator* machine is a different threat.** If the
   operator box is owned, the attacker holds the key and signs as the
   principal. The system then **detects** (the chain proves what was signed)
   but cannot **prevent**. That is identity theft, not agent misbehavior — a
   key-custody problem (HSM / production custody, Phase 4+).
3. **It can flood.** Spamming proposals fills the ledger with *denials* —
   logged and reconstructable, committing and spending nothing. A nuisance, not
   a break. Rate limiting is a known **Deferred** item (ADR-0011), not a hole.
4. **True parallel races — tested (Phase 5).** Revoking *while* granting:
   `commit_approval` now rechecks the parent record's current status and the
   deal's transition inside its commit transaction (shared `grant_recheck`,
   both backends), and a failed recheck logs a forced deny. The dedicated
   test (`tests/adversarial/test_concurrent_race.py`) fires grant and revoke
   simultaneously over real HTTP; both landing orders occur across runs and
   exactly one consistent outcome persists, with the chain verifying. Note:
   this walkthrough's earlier claim that the recheck was already covered was
   wrong — the recheck was missing until the Phase 5 conformance fix, which is
   why the race had to exist before it was trusted.

## 4. Foundation audit — what is actually pinned

The safety case rests on the test suite. As of 2026-09-03, by direct read:

**Pinned (Verified):**
- State machine vs spec: `test_transitions.py:86-130` (360-pair exhaustive).
- Six Hypothesis safety properties + 14 single-break deny mutations:
  `test_properties.py:111-283`.
- Nine adversarial fixtures: `tests/adversarial/test_adversarial.py`.
- Two-agent end-to-end + misbehavior over real HTTP (Phase 5): 18 tests in
  `tests/adversarial/` — lifecycle to capture, all 13 misbehavior denials,
  payment blocked by open approval/dispute, and the grant-vs-revoke race under
  real parallelism (both landing orders, chain always verifies).
- Canonicalization: determinism, key-order invariance, structure preservation,
  engine-digest agreement: `test_crypto_properties.py`.
- Crypto sign/verify: roundtrip, tamper, wrong-key, algorithm-spoof,
  key_id-mismatch, malformed, **cross-record non-transfer**: `test_signing.py`.
- Ledger tamper suites A/B/C: `test_tamper.py`; Postgres append-only guards —
  all eight governed tables, UPDATE/DELETE and TRUNCATE (incl. the
  FK-closure truncate of `authority_records`):
  `test_postgres.py::TestAppendOnlyGovernedTables`; revocation as a signed
  chain event, idempotent and rechecked by `commit_approval` (a grant after
  revocation lands as a forced deny): `test_postgres.py::TestCommitRevocation`,
  `test_ledger_store.py::TestCommitRevocation`; least-privilege `mandate_app`
  role matrix (SELECT/INSERT/REFERENCES everywhere, UPDATE only on the two
  projections, no DELETE/TRUNCATE/DDL): `test_postgres.py::TestMandateAppRole`.
- Transport (Phase 6, ADR-0012): signed-envelope sign/verify/tamper/non-transfer
  + unknown peer (`tests/unit/test_envelope.py`, 35 — including the
  counterparty-side `verify_receipt` path, `TestVerifyReceipt`); two-
  memoryless-gateways end-to-end over real HTTP with wire-idempotency
  redelivery and independent `verify_chain` per ledger
  (`tests/integration/test_two_gateways.py`, 7) — including replay returning
  the stored answer
  (`test_two_gateways.py::test_replayed_message_is_idempotent_no_duplicate`)
  and receipts being signed envelopes
  (`test_two_gateways.py::test_receipt_is_a_signed_envelope`); the adversarial
  transport suite — forged sender, tampered payload, idempotency-key reuse for
  different content, unregistered attacker, and further envelope-shape attacks
  — none commit anything (`tests/adversarial/test_gateway_abuse.py`, 10); and
  the counterparty-side receipt-forgery suite — a forged, tampered, replayed
  (a genuine receipt for a different message), or stale receipt is rejected
  before its outcome is read
  (`tests/adversarial/test_receipt_tampering.py`, 5), exercised in production
  by `scripts/two_gateways.py`, which runs `verify_receipt` on every receipt
  before reading the decision.

**G1 (closed 2026-09-03) — master "never over-authorizes" property.** Every
earlier property was a *single-axis* negative test (break one thing → never
allow) plus monotonicity; none pinned the **conjunction**: over the full
Hypothesis input space, that `evaluate() == ALLOW` *only when* an
independently-written oracle says the proposal is fully authorized. A 13-step
sequential engine's real risk is a **step-interaction** bug that no single-axis
test touches. `tests/property/test_soundness.py` now pins it: `oracle_allows`
re-derives all 13 gates straight from the PolicyInput, without calling
`evaluate()` or reusing the engine's sequencing, and three Hypothesis properties
tie the engine to it — **soundness** (engine ALLOW ⟹ oracle-authorizes; the
safety claim, over the full arbitrary `policy_inputs()` space), **completeness**
(oracle-authorizes ⟹ engine ALLOW; never over-denies), and a **non-vacuity
baseline** proving the constructed allowing inputs are allowed by both.

> Honest ceiling: a differential oracle is a *second, independent code path* —
> far stronger than per-axis tests, but written by the same team it may share a
> blind spot. It is **much stronger evidence**, not a **formal proof**. A formal
> method or an externally peer-reviewed oracle is the next rung up. The maintainer
> reviewed `oracle_allows` gate-by-gate against this spec (2026-09-03) and
> signed it off; the oracle is now the reference the differential pins the
> engine to.

**G2 (closed 2026-09-03) — RFC 8032 known-answer test.** `signing.sign` is now
pinned to the published Ed25519 standard: `tests/unit/test_signing.py::
TestRFC8032KnownAnswer` reproduces the exact RFC 8032 §7.1 signature bytes for
TEST 1–3 (message lengths 0, 1, 2) and checks seed→public-key derivation,
bypassing canonicalization so the check lands on the raw crypto. Vectors taken
from the RFC at test-writing time, not from memory. A subtly broken or
home-grown "Ed25519" that signs its own records consistently would fail these
bytes; ours reproduce them exactly.

## 5. Status ledger

| Area | Status |
|---|---|
| Proposal can't grant authority | Verified |
| Over-cap / split-increment can't commit silently | Verified |
| Replay / duplicate can't double-commit | Verified |
| Mandate can't be edited or signature-moved | Verified |
| Delegation can't widen; revocation cascades | Verified |
| Time window can't be faked from inside | Verified |
| Impossible state can't transition | Verified |
| Payment blocked by dispute / open approval | Verified |
| Disclosure outside allow-list denied | Verified |
| Ledger can't be quietly rewritten (detection) | Verified |
| Engine never over-authorizes over full input space | **Verified (G1)** — `test_soundness.py` differential property; oracle signed off 2026-09-03 |
| Signing is byte-conformant to RFC 8032 | **Verified (G2)** — `test_signing.py` TestRFC8032KnownAnswer, RFC 8032 §7.1 |
 | Parallel approve/revocate races | **Verified (Phase 5)** — `test_concurrent_race.py`, real parallel HTTP, both landing orders, chain verifies |
  | Wire envelope can't be forged / tampered / replayed (transport) | **Verified (Phase 6)** — `test_envelope.py`, `test_two_gateways.py`, `test_gateway_abuse.py`, `test_receipt_tampering.py`; identity-key auth, canonical-bytes signature, wire-idempotency + ADR-0007 fingerprint, counterparty-side `verify_receipt` on receipts |
 | Flooding / rate limiting | Deferred (ADR-0011) |
| Compromised operator key | Out of scope (key custody, Phase 4+) |
| Human social engineering | Human is the last line (by design) |

## 6. Next action

Both foundation gaps are closed: G2 (RFC 8032 KAT) and G1 (differential
soundness; `oracle_allows` reviewed gate-by-gate against this spec and signed
off by the maintainer, 2026-09-03). The safety case now differential-tests the
whole authorization conjunction against an independently reviewed second spec.

Phase 6 (transport, ADR-0012) closed the last transport threat in the v0.1
model: a gateway cannot be forged, tampered, replayed, or idempotency-poisoned,
and the counterparty verifies every receipt with `verify_receipt` before
trusting its outcome — pinned by `test_envelope.py`, `test_two_gateways.py`,
`test_gateway_abuse.py` and `test_receipt_tampering.py`. The core asymmetry
now holds end-to-end *across the wire*, not only within one process.

Next: brief §16 Phase 7+ (pilot, payments, standards adapters). Present the
breakdown first and wait for go (phase-gate rule).
