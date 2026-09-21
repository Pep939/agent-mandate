"""Generate development wire-gateway keys into .dev/keys/gateway/ (gitignored).

Writes the two separate key files a gateway process needs (ADR-0012: the
wire identity key signs envelopes, the chain key signs ledger events — they
must be distinct), plus an empty peer-registry file. Same JSON shape as
scripts/dev_keys.py. Development convenience only: dev keys are for loopback
and the two-machine demo, never for a deployment others rely on.

Usage: uv run scripts/dev_gateway_keys.py
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


def _key_file(key_dir: Path, role: str, rng: random.Random) -> tuple[Path, str, str]:
    key = Ed25519PrivateKey.generate()
    key_id = new_ulid(rng)
    payload = {
        "role": role,
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
    return path, key_id, payload["public_key"]


def main() -> int:
    key_dir = Path(".dev/keys/gateway")
    key_dir.mkdir(parents=True, exist_ok=True)
    rng = random.SystemRandom()

    identity_path, identity_id, identity_pub = _key_file(key_dir, "identity", rng)
    chain_path, chain_id, _chain_pub = _key_file(key_dir, "chain", rng)

    peers_path = key_dir / "peers.json"
    peers_path.write_text("{}\n", encoding="utf-8")
    peers_path.chmod(0o600)

    print(f"identity key : {identity_path} (key_id {identity_id})")
    print(f"chain key    : {chain_path} (key_id {chain_id})")
    print(f"peer registry: {peers_path} (empty — fill before running)")
    print()
    print("Add this gateway to the OTHER machine's peer registry:")
    print(json.dumps({identity_id: {"identity_id": identity_id, "public_key": identity_pub}}))
    print()
    print("Run with:")
    print(f"  MANDATE_IDENTITY_FILE={identity_path}")
    print(f"  MANDATE_CHAIN_KEY_FILE={chain_path}")
    print(f"  MANDATE_PEERS_FILE={peers_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
