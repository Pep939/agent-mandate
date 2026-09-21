"""Application boundary: the anti-replay gate (ADR-0007).

The gate runs before evaluate() and after any persistence (Phase 3). The
policy engine stays pure; this module owns the seen-request state.
"""
