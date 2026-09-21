"""Generate development console secrets into .dev/ (gitignored, 0600).

Development convenience only (ADR-0011). Mirrors scripts/dev_keys.py for the
operator password and session secret. The raw values are written to 0600 files
and never printed to the terminal or committed (invariant 12); an export
snippet is shown so you can source them into the environment.

Usage: uv run scripts/dev_secrets.py
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

DEV_DIR = Path(".dev")
OPERATOR_FILE = DEV_DIR / "operator_password"
SESSION_FILE = DEV_DIR / "session_secret"


def _write(path: Path, value: str) -> None:
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o600)


def main() -> int:
    DEV_DIR.mkdir(parents=True, exist_ok=True)
    operator_password = secrets.token_urlsafe(12)
    session_secret = secrets.token_urlsafe(32)
    _write(OPERATOR_FILE, operator_password)
    _write(SESSION_FILE, session_secret)
    print(f"wrote {OPERATOR_FILE} (gitignored, 0600)")
    print(f"wrote {SESSION_FILE} (gitignored, 0600)")
    print("\nsource these into the environment before starting the console:")
    print(f'  export MANDATE_OPERATOR_PASSWORD="$(cat {OPERATOR_FILE})"')
    print(f'  export MANDATE_SESSION_SECRET="$(cat {SESSION_FILE})"')
    print("\nthen run: uv run python -m mandate.api.app")
    print("to log in, read the password with: cat " + str(OPERATOR_FILE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
