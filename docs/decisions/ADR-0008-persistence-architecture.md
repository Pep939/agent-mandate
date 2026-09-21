# ADR-0008: Persistence architecture — DB-agnostic core, dual backends, gated integration tests

Status: accepted (2026-09-01, maintainer approval of the Phase 3 breakdown)

## Context

Phase 3 (brief §16) requires PostgreSQL schema and migrations, append-only
event recording, hash-chain verification, transactional state updates, and
evidence bundle export. ADR-0007 requires the anti-replay `SeenStore` to become
durable and persist **atomically with the ledger append**. The machine has no
local Postgres (Docker is available); CI must stay green with zero
infrastructure (`uv run pytest` today needs nothing).

## Decisions

- **Layering.** `src/mandate/ledger/` is DB-agnostic and pure: event hashing,
  chain verification, sequence/append-only semantics, and a `LedgerStore`
  **protocol**. No DB driver import anywhere in `ledger/`, `domain/`,
  `policy/`, `crypto/` or `application/` — enforced by the banned-imports
  AST scan, which gains `ledger/`.
- **Two backends implement the protocol:**
  - `InMemoryLedgerStore` (`ledger/store.py`) carries the entire
    *correctness* burden and is always tested in CI. Single-threaded
    validate-then-apply gives all-or-nothing commits in-process.
  - `PostgresLedgerStore` (`src/mandate/adapters/postgres/`) is the
    production path with real transactional atomicity. Deliberately excluded
    from the no-I/O scan.
- **Stack:** SQLAlchemy 2.0 **Core** (explicit `Table`/`Column`, no ORM
  magic) + **Alembic** migrations + **psycopg 3**. The brief names Alembic;
  Alembic is built on SQLAlchemy. Raw psycopg with hand-rolled migrations was
  considered and rejected (schema/code drift risk).
- **Testing strategy:** Postgres integration tests are gated on the
  `MANDATE_TEST_DB_URL` environment variable and skip when unset. Local run:
  `docker run -d --name mandate-pg -e POSTGRES_DB=mandate -e POSTGRES_USER=mandate -e POSTGRES_PASSWORD=dev -p 5432:5432 postgres:16`
  then `MANDATE_TEST_DB_URL=postgresql+psycopg://mandate:dev@localhost:5432/mandate uv run pytest tests/integration`.
- **Append-only enforcement is defense-in-depth** (threat model #14/#15):
  1. least-privilege — the app role gets INSERT/SELECT on `events`, never
     UPDATE/DELETE;
  2. a `BEFORE UPDATE OR DELETE` trigger on `events` that raises, so even an
     over-privileged role cannot modify history;
  3. detection — the hash chain + per-event signatures make any modification
     provable via `verify_chain` / `verify_bundle` (detection, not
     prevention, for a fully compromised operator — threat model #14).
- **Seen-store tables live in the same database** as the ledger and are
  written in the same transaction as the event append (ADR-0007): a crash or
  failure between gate and ledger cannot double-process a request.

## Consequences

- CI stays zero-infrastructure; Postgres is a swappable adapter.
- The in-memory backend simulates (does not provide) crash atomicity; only the
  Postgres backend proves real transactional rollback (gated test B9).
- New dependencies: `sqlalchemy>=2.0`, `alembic>=1.13`, `psycopg[binary]>=3.1`.
