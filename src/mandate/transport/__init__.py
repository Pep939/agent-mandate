"""Separate-machine transport (ADR-0012): the wire envelope layer.

`envelope.py` is pure (no I/O, invariant 2): the signed message model, its
canonical form, and sign/verify. `dedup.py` holds the idempotency store,
`gateway.py` the HTTP app (the boundary, like `api/`).
"""
