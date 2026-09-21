"""Pure cryptography: canonical serialization, Ed25519 signing, verification.

No I/O anywhere in this package (invariant 2). Key material is passed as
bytes by the caller; it never appears in fixtures, logs, events or source
(invariant 12, ADR-0005).
"""
