"""Generate a development Ed25519 keypair into .dev/keys/ (gitignored).

Development convenience only (ADR-0005). Never use dev keys in production;
production key custody is a Phase 4+ concern (brief §16).

Usage: uv run scripts/dev_keys.py
"""

from __future__ import annotations

import base64
import json
import random
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid(rng: random.Random) -> str:
    ts = int(time.time() * 1000)
    chars = []
    for _ in range(10):
        chars.append(CROCKFORD[ts % 32])
        ts //= 32
    for _ in range(16):
        chars.append(CROCKFORD[rng.getrandbits(5)])
    return "".join(chars)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def main() -> int:
    key_dir = Path(".dev/keys")
    key_dir.mkdir(parents=True, exist_ok=True)
    rng = random.SystemRandom()
    key = Ed25519PrivateKey.generate()
    key_id = new_ulid(rng)
    payload = {
        "key_id": key_id,
        "algorithm": "Ed25519",
        "created_at": datetime.now(UTC).isoformat(),
        "public_key": _b64url(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
        "private_seed": _b64url(
            key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ),
    }
    path = key_dir / f"{key_id}.ed25519.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    print(f"dev key written to {path} (gitignored; development only)")
    print(f"key_id: {key_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
