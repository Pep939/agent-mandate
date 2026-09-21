"""Database adapters (ADR-0008).

Deliberately outside the no-I/O import scan: the ledger core
(`mandate.ledger`) is DB-agnostic, and this package is the only place a
driver is imported.
"""
