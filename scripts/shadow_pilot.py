"""Run the Phase-7 shadow pilot and print the evidence report.

Drives a realistic, synthetic field-service day through the live console +
policy + ledger + approval stack over HTTP (in-process TestClient), with a
human (the operator/principal) resolving every approval and no payment provider
(no money movement - that is Phase 8). It then independently verifies every
event chain and checks the invariants:

  * no autonomous commitment on an approval-gated action,
  * no money moved (every capture is human-gated),
  * every event chain re-verifies clean.

Usage:
  uv run scripts/shadow_pilot.py

Exit codes: 0 = the invariants hold, 1 = an invariant failed.
"""

from __future__ import annotations

import sys

from mandate.pilot.report import build_report, render_markdown
from mandate.pilot.run import run_shadow_pilot


def main() -> int:
    run = run_shadow_pilot()
    report = build_report(run)
    print(render_markdown(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
