# Security Policy

## Status of this project

**Agent Mandate is v0.1 research-grade software. Do not deploy it as-is to
protect anything real.** It is published so the design can be examined and
argued with, not because it is production-hardened. The limits below are
deliberate and documented, not undiscovered.

If you are evaluating it for real use, read `docs/threat-model.md` and
`docs/threat-walkthrough.md` first. Between them they name every control, its
enforcement point, and the three gaps that are *not* solved.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting: the **Security** tab of this
repository → **Report a vulnerability**. That creates a private advisory
visible only to the maintainer.

What to include, if you have it: the invariant or control you believe is
broken, the smallest reproduction you can manage (a failing test against this
repo is ideal), and what an attacker gains.

What to expect: an acknowledgement within roughly a week, and an honest
answer about whether it is a bug, a documented limitation, or a design
decision we should revisit. This is a one-maintainer project — there is no
bounty and no service-level commitment, and the maintainer would rather say
that plainly than imply otherwise.

## Scope

**In scope** — anything that breaks one of the fifteen-plus invariants in
`CLAUDE.md`. The ones most worth attacking:

- **Authority.** A proposal that is authorized without a valid, current,
  in-scope mandate. A revoked or expired record that still grants something.
  A delegation chain that widens rather than narrows.
- **Evidence.** A tampered ledger that still verifies: an edited, deleted,
  reordered or truncated event chain that `verify_ledger` reports as clean.
  A forged evidence bundle that passes `verify_bundle`. **One instance of this
  is already known and open (issue #1, found 2026-09-21):** `verify_bundle`
  takes the public key from inside the bundle under test, so a bundle signed
  with an attacker's own keypair verifies clean. Please do not re-report that
  one; a *different* forgery, or a truncation that survives once the key is
  supplied out of band, is still very much in scope.
- **Replay and idempotency.** Any path where one request produces two
  commitments, or a retry produces a different answer than the original.
- **Disclosure.** A field leaving the system that the mandate's allow-list
  does not permit.
- **The content screen (ADR-0016).** Most valuable target: **any input for
  which a classifier's claims make the engine _more_ permissive.** The whole
  safety argument is that claims can only narrow. If you can produce a case
  where adding claims turns a deny or a hold into an allow, that is a real
  finding and we want it.
- **Secrets.** A signing key, session secret or operator password reaching a
  log, an event payload, a template, a test fixture or the repository.

**Out of scope** — these are known and documented, so please do not report
them as vulnerabilities. Arguments that one of them is *worse than we think*
are welcome; a report that merely restates one is not a finding.

- The operator console has no TLS and no multi-user model. It binds to
  `127.0.0.1` only, by decision (ADR-0011).
- The wire transport has no TLS, no PKI and no payload encryption. Peers are
  pre-shared Ed25519 identities; the signature is the authentication
  (ADR-0012). An on-path host can read message structure.
- A fully compromised operator machine defeats the system. It holds the keys.
  The ledger **detects** tampering; it does not **prevent** an insider
  (gap G3).
- Counterparty identity is not verified. A counterparty is an opaque
  identifier and no trust follows from it (gap G2).
- Free-text exfiltration is **mitigated, not closed** (gap G1). The content
  screen compares what it detects against the mandate's allow-list, but it is
  only as good as the classifier's calibration, on which this project makes
  no claim. An encoding the screen misses is a known class of miss — though a
  *cheap, general* evasion is interesting and worth reporting.
- Key custody is v0.1: a persisted keypair per gateway. Hardware security
  modules and rotation are deferred.
- There are no real payments anywhere in the system.

## Dependencies

Runtime dependencies are pinned in `uv.lock`. The optional content-screen
extra pulls in a third-party SDK that talks to an external service; it is
**off by default**, and the only file permitted to import it is
`src/mandate/screen/typesafe.py`, enforced by a test. If you enable it,
message text leaves your machine — that is the point of the feature, and it
is your decision to make.
