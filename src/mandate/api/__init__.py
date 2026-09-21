"""The operator-facing HTTP boundary (Phase 4 step 3, ADR-0011).

This is the only layer that does I/O. Everything it calls (domain, policy,
ledger, crypto, application) stays pure (invariant 2); this layer assembles the
boundary claims, supplies the trusted clock, and renders server-side templates.
"""
