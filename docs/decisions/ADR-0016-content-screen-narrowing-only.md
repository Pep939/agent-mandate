# ADR-0016: The content screen — a classifier may only narrow

Status: accepted (2026-09-21). Supersedes nothing; extends the evaluation
order defined in `specs/policy-schema.md`.

## Context

Two facts about this repo sat next to each other until now.

**One: nothing in the system reads the meaning of anything.** A proposal is
six structured fields. `AuthorityRecord.purpose` is signed and never
evaluated. A counterparty `note` is signed into a chain event and never
parsed. `disclosure_fields` — the mechanism invariant 9 rests on — is a list
of tokens the **agent declares about itself**, checked by set membership
against the mandate's allow-list. Nobody checks the text.

**Two: the threat model says so, in writing.** Gap G1:

> the field allow-list gates *structured* disclosure, but a determined LLM
> could encode an allowed field's value into free text. v0.1 mitigation is
> the allow-list + untrusted-input handling; a content-scanning/redaction
> control is a candidate for Phase 4. Not marked solved.

And residual #1 in `docs/threat-walkthrough.md`: an agent's last lever is a
persuasive note that makes the *human* grant. The guardrails there are that
the approval question is code-worded and the text renders inert — but the
operator still reads the agent's prose with no second opinion.

Closing G1 needs something that reads text. Everything in this repo says a
model must not be in the authorization path (invariants 1, 2, 11; an AST test
enforces the second). Those two requirements are only compatible under a
restriction, and this ADR is that restriction.

The trigger was a specific class of model. A **typed classifier** — TypeSafe
AI's "Jev" is the current example — is not a language model: it takes text
and a closed question set and returns labels and probability distributions.
No generation, no tools, no conversation. Its output is *numbers*, which a
pure function can read, an integer canonicalizer can serialize, and a hash
chain can sign. That is the property that makes this possible at all — and it
is a property of the *shape* of the model, not of any vendor. The interface,
not the vendor, is what this repository depends on (decision 7 below).

## Decisions

### 1. Claims enter the engine exactly the way `signature_valid` does

The screen runs at the boundary (`api/`, `transport/gateway.py`). Its answers
become a frozen `ContentClaims` on `PolicyInput`. `evaluate()` reads that
field and performs no I/O; invariant 2 is untouched and the banned-imports
AST scan still passes over `domain/`, `policy/`, `application/`, `ledger/`
and the pure part of `screen/`.

### 2. Narrowing only — the rule this ADR exists for

Rank the outcomes: `allow` (0) → `needs_approval` (1) → `deny` (2). For any
input and any claims a screen could return:

```
rank(evaluate(input + claims)) >= rank(evaluate(input))
```

A claim may push a decision **down** the ladder and never up. Nothing the
screen says can produce an `allow` that the mandate did not already produce.

This is not a preference. Model output is untrusted (invariant 11) and the
vendor states plainly that the text it reads is not treated as hostile — so
it is injectable. Under narrowing-only, a screen that is wrong,
miscalibrated or prompt-injected can cause a false hold or a false deny.
It can never grant authority. **A fooled screen costs availability, never
authority**, which keeps the threat-walkthrough asymmetry intact with a model
in the loop.

Enforced by a Hypothesis property over arbitrary inputs × arbitrary claims
(`tests/property/test_content_monotonicity.py`), not by convention.

### 3. Two engine steps, both after the authority checks

- **Step 9b (deny), `disclosure_detected`** — the screen reports a sensitive
  field that is *not* on the mandate's allow-list, at or above
  `CONTENT_DENY_BP` (9000 bp). This is what closes G1: the allow-list stops
  being a self-declaration and becomes a checked one.
- **Step 12b (hold)** — `content_review_required` (an undeclared field at or
  above `CONTENT_HOLD_BP`, 7000 bp), `hostile_content_suspected` (hostility
  at or above the same), or `content_screen_unavailable`.

Placement is deliberate. Both run after steps 1–8, so an expired mandate, a
prohibited action or an invalid transition is still answered by the
cryptographic and tabular checks — the screen never runs a deal past an
authority failure. Step 9b precedes the spend cap, so a leaking message is
stopped rather than sent to ask about money.

Thresholds are policy and live in the engine, pinned per screener version.
Changing one is a new ADR, never a silent edit.

### 4. Fail toward caution

`available=False` — outage, timeout, no screen configured — is
`needs_approval`, never `allow` and never `deny`. An unscreened message is
not a clean message; a vendor outage must not free the agent, and must not
kill the deal either. The vendor has no SLA and a measured outage two days
before this was written, so this path is load-bearing, not theoretical.

### 5. Integers, not floats; pinned screener; question digest

Probabilities are **integer basis points** (0–10000). The domain has no
floats (money is minor units), canonical bytes must be identical on every
machine (invariant 13), and Ed25519 signs integers reproducibly. The single
float-to-integer conversion lives in `screen/protocol.py`.

Every claim carries a **pinned screener id** (`typesafe:jev-1.13.0`) — a
floating alias is rejected at construction, because thresholds do not survive
a model version bump — and the **canonical digest of the question set**, so a
dispute reviewer can re-ask the same questions of the same model.

### 6. Content is modelled as a digest plus a MESSAGE event

`EventType.MESSAGE` existed as a name with no constructor. It is now real:
the payload carries `content_sha256`, the full screen answer, and (outbound)
what the agent declared — **never the text**, per the payload doctrine
("structured, non-sensitive data and digests — never raw counterparty text,
LLM output or secrets"). The event is appended *ahead of* the decision it
informed, so the chain reads: here is what was screened, here is what was
decided.

`Proposal.content_sha256` binds the screened bytes to the proposal, so the
anti-replay digest covers them: the same action with different text is a
different proposal (ADR-0007).

### 7. The interface is the asset, not the vendor

`ContentScreen` is a protocol. `FixtureScreen` (deterministic keyword
matching) serves the tests, the demos and the shadow pilot with no network.
`TypeSafeScreen` is the vendor adapter, an optional extra, and the **only**
file permitted to import the SDK — enforced by an AST test over every source
file. `MANDATE_CONTENT_SCREEN` selects the backend and is **off by default**.

This matters commercially as well as architecturally: the vendor is
cloud-only with no self-host option, which contradicts an on-prem
deployment. A local classifier speaking the same interface is one more
branch in `screen/config.py`.

### 8. The console gets a second opinion, not a new authority

The approval queue shows the screen's badge — what it detected, how
instruction-like the text is, how urgent — and sorts by urgency. The
approval *question* is still worded by code from the reason code, never by
the agent. This addresses threat-walkthrough residual #1 by giving the human
a code-generated opinion beside the agent's prose, and by putting a record
in the ledger that the opinion existed. The human is still the last line.

## Consequences

- **G1 moves from open to mitigated**, with the honest qualifier that
  mitigation is only as good as the screen's calibration — which is why the
  control is narrowing-only and why the distribution, not just the verdict,
  is signed into the chain.
- **The README line "no LLM in the decision path" was imprecise and is
  reworded** to "no model can widen authority". A classifier *is* in the
  path once it can force a hold. Saying so is the honest version.
- A new invariant (16) states the narrowing rule where the other fifteen
  live.
- The shadow pilot gains a deal where the agent writes to the customer;
  the report gains a content-screen section and a third pass/fail invariant:
  no message with an undeclared disclosure was ever allowed out.
- Cost is negligible (fractions of a cent per message at vendor pricing) and
  latency is ~130 ms p50, so screening every message is affordable; but the
  screen is off by default and no deployment is obliged to enable it.
- **Not addressed:** counterparty identity (G2), insider prevention (G3),
  and the calibration of any particular screener. The repo takes no position
  on whether a given vendor is accurate; it takes a position on what an
  inaccurate one can do, which is: hold things up, and nothing worse.
