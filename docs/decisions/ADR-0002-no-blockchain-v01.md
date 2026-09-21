# ADR-0002: No blockchain in v0.1

Status: accepted (2026-08-31)

## Context

The brief (§5) lists real on-chain advantages (portable identity, public
verification, stablecoin settlement) but also real risks (AML/sanctions,
money-transmission obligations, key compromise, onboarding friction, public
metadata leakage, product distraction). The core claim — scoped, revocable,
auditable authority — does not require any of the on-chain features.

## Decision

**No blockchain in v0.1.** The mandate engine is fully functional offline:
Ed25519 signatures (local keys), a local append-only ledger, and evidence-bundle
export provide the trust and audit properties. On-chain identity, delegation,
anchoring and settlement are deferred to Phase 9 and added only as
**adapters**, never as a dependency of the domain or policy layers.

## Consequences

- Faster, cheaper, legally quieter start; no wallet, gas, or compliance surface
  to get wrong before the product is validated.
- Canonical serialization and signature formats are designed now so that later
  on-chain anchoring can reference the same hashes (invariant 13).
- If/when crypto is added: private contents never go on-chain, autonomous
  payments stay opt-in and policy-bound, human approval stays above thresholds,
  and compliance becomes a subsystem (brief §5).

## Addendum (2026-09-03): when an on-chain anchor would be reconsidered

Maintainer question: does the ledger need something "like the Bitcoin network" —
i.e., unfundable, unalterable by design? Resolution: **no, not for the current
threat model, and the trigger for reopening this question is now pinned
below.**

The technical distinction that settles it:

- **Bitcoin's immutability is immutability by cost.** PoW does not make
  history rewriting logically impossible; it makes it cost more energy than the
  whole network has. The guarantee is economic, and it exists to give strangers
  who trust no common party a shared canonical history.
- **The Mandate ledger's guarantee is tamper-evidence by verification.** The
  hash chain + Ed25519 signatures let any holder of an evidence bundle prove a
  rewrite happened — offline, deterministic, trusting only their own key. It
  does not *prevent* an operator from truncating their own database; it
  prevents them from getting away with it, because the counterparty's copy of
  the signed events will not verify against the new history (tamper suites
  A/B/C pin this: edit, delete, reorder, duplicate, truncate, forged append).

For a two-party deal where both gateways hold verification keys, signatures
dominate PoW: strictly stronger (full offline proof vs. probabilistic economic
one) and simpler. Building consensus machinery to solve a problem signatures
already solve is out of scope, now and for v0.1.

**The one gap signatures do not cover** — and the only trigger for
reconsideration: a gateway **misrepresenting deal history to a third party who
holds no copy of the signed events or bundle** (e.g., a public dispute forum,
a regulator/auditor demand for proof-of-existence, or a Phase 7 pilot
requirement that a counterparty's principal verify history without receiving a
bundle).

If that trigger fires, the prescribed mechanism is a **Merkle-root anchor**:
hash the ledger chain's root and write it to a public chain (OP_RETURN or
equivalent) as a risk-reviewed Phase 9 adapter, per brief §5 constraints —
private contract contents, personal data, prompts and agent memory never
on-chain; complete authority records stay local or encrypted. An anchor proves
"this history existed at block N"; it is not a product blockchain, and no PoW
of our own is ever built.

**Not triggers** (do not reopen this ADR for): wanting Bitcoin-like branding or
finality aesthetics; identity portability (separate track, Phase 9 ERC-8004);
settlement (Phase 8, counsel-gated).
