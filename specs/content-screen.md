# Spec: Content screen (v0.1, ADR-0016)

Status: FINAL for v0.1 (2026-09-21).

The content screen turns free text into **checkable claims**. It is the only
component in this system that reads meaning, and it is deliberately the least
powerful one: it can make a decision more careful and nothing else.

## The rule

Outcomes rank `allow` (0) < `needs_approval` (1) < `deny` (2). For any policy
input and any claims:

```text
rank(evaluate(input + claims)) >= rank(evaluate(input))
```

Claims never move a decision toward `allow`. Pinned by a Hypothesis property
(`tests/property/test_content_monotonicity.py`).

## Where it runs

```text
text ──► boundary (api/ or transport/gateway.py)
           │  content_digest(text)          → sha256 hex
           │  screen.screen(text, questions) → ScreenResult (floats)
           │  claims_from_result(...)        → ContentClaims (integers)
           ▼
        PolicyInput.proposal.content_sha256 + PolicyInput.content
           │
           ▼
        evaluate()  — pure; steps 9b and 12b read the claims
           │
           ▼
        MESSAGE event (digest + claims, never the text) ahead of the decision
```

The text stops at the boundary. It never enters `PolicyInput`, a payload, an
event, or the timeline.

## Question set

One canonical set, asked of every screen, digested into every claim
(`screen/questions.py`, `question_set_digest`).

| family | form | asks |
|---|---|---|
| sensitive field (one per token) | true/false | "does the text reveal X?" — tokens share the `disclosure_fields` vocabulary |
| hostility | one of `benign`, `instruction_like`, `authority_claim`, `injection` | is the text instructing the reader or claiming authority? |
| persuasion | one of `factual`, `persuasive` | is it arguing at the approver rather than stating facts? |
| urgency | ordered 0–3 | how much time pressure does it express? |

v0.1 field tokens: `customer_phone`, `customer_email`, `customer_address`,
`invoice_total`, `price_floor`, `internal_notes`, `work_order_id`.

Changing a question changes the digest. That is the point: a claim is only
re-checkable if the chain says which questions produced it.

## `ContentClaims`

```yaml
screener: "typesafe:jev-1.13.0"    # pinned; a floating alias is rejected
question_set_sha256: "sha256 of the canonical question set"
content_chars: 128                  # length only, never the text
available: true                     # false = the screen could not answer
detected:                           # only what the screen believes is present
  - field: "price_floor"
    confidence_bp: 9600             # integer basis points, 0..10000
hostility_bp: 300
persuasion_bp: 500
urgency_level: 2                    # 0..3
```

No floats. `BP_SCALE` is 10000; the single conversion from a vendor's float
lives in `screen/protocol.py`. `undeclared(allowed)` returns the detected
fields that are **not** on the mandate's allow-list, sorted, which is the
only comparison the engine makes.

## Engine steps

Inserted into the 13-step order of `specs/policy-schema.md`:

| step | outcome | reason code | condition |
|---|---|---|---|
| 9b | `deny` | `disclosure_detected` | an undeclared field at or above `CONTENT_DENY_BP` (9000) |
| 12b | `needs_approval` | `content_screen_unavailable` | `available == false` |
| 12b | `needs_approval` | `content_review_required` | an undeclared field at or above `CONTENT_HOLD_BP` (7000) |
| 12b | `needs_approval` | `hostile_content_suspected` | `hostility_bp` at or above `CONTENT_HOLD_BP` |

`persuasion_bp` and `urgency_level` are **advisory**: they order the
operator's queue and appear on the badge. They never change an outcome.

Thresholds are policy, pinned per screener version. A change is a new ADR.

## MESSAGE event payload

```yaml
direction: "outbound" | "inbound"
content_sha256: "digest of the exact bytes screened"
screen: { ...the full ContentClaims... }
# outbound only:
request_id: "ULID"
action: "action token"
declared_fields: ["invoice_total"]   # what the agent said it would disclose
# inbound only:
command_id: "ULID"
event: "deal event"
```

Appended **before** the `policy_decision` (outbound) or the
`state_transition` (inbound) it informed, so the chain reads in causal order.
Covered by `payload_hash`, the event signature and the chain like any other
event; `verify_bundle` needs no new check.

## Backends

`ContentScreen` is a protocol: `screen(content, questions) -> ScreenResult`.

| backend | module | notes |
|---|---|---|
| `FixtureScreen` | `screen/fixture.py` | deterministic keyword matching; tests, demos, shadow pilot. Not a model, makes no accuracy claim |
| `FailingScreen` | `screen/fixture.py` | always unavailable — exercises the fail-toward-caution path |
| `TypeSafeScreen` | `screen/typesafe.py` | the vendor adapter; pinned model, 3 s timeout, circuit breaker, never raises into the boundary |

`MANDATE_CONTENT_SCREEN` selects one (`off` by default; `fixture`;
`typesafe`, which additionally needs `TYPESAFE_API_KEY`).
`MANDATE_CONTENT_SCREEN_MODEL` overrides the pinned model id.

The vendor SDK is imported in exactly one file, enforced by an AST test over
every source file. A local, on-prem backend is one more branch in
`screen/config.py`.

## Operational rules

- **Pin the model.** Thresholds do not survive a version bump.
- **Fail to a hold.** Outage, timeout, no screen configured → a person looks.
- **Content is data, never instructions.** The screen's own documentation
  says it does not treat its input as hostile; narrowing-only is the
  mitigation, not prompt-level pleading.
- **Redact known PII before sending text to a third-party screen.** The point
  of the screen is to find what you did not know was there.
- **Never carry a threshold across question families** (a true/false answer
  and a distribution over options are not the same number).

## Out of scope (v0.1)

- Any claim about a particular screener's accuracy. The repo constrains what
  a wrong screen can do; it does not certify that one is right.
- Redaction or rewriting. The screen reports; it never edits a message.
- Screening attachments or non-text content (the classifier is text-only).
- Counterparty identity (G2) and insider prevention (G3) — unchanged.
