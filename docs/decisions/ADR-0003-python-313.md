# ADR-0003: Python 3.13 (deviation from brief)

Status: accepted (2026-08-31)

## Context

Brief §7 specifies Python 3.12. The maintainer's standing engineering rule (global
CLAUDE.md) is **3.13-only** for all new code, Dockerfiles, requirements and CI —
3.13 has been the default stack since 2026-07. The two sources conflict.

## Decision

Use **Python 3.13** (`requires-python = ">=3.13"`, `.python-version` pinned via
uv). The standing rule is the more recent and repeatedly reaffirmed instruction
and applies to all projects; the brief's 3.12 line is treated as a draft artifact.

## Consequences

- Nothing in the v0.1 stack (FastAPI, Pydantic v2, SQLAlchemy, Alembic, PyNaCl,
  Ruff, mypy, Hypothesis) requires 3.12 specifically; all support 3.13.
- If a future dependency ever fails on 3.13, that is a dependency problem to
  solve, not a reason to downgrade the interpreter.
