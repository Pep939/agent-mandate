"""Independently verify an exported evidence bundle.

Recomputes every payload hash, event hash, Ed25519 signature, sequence
number, chain link and summary hash (specs/evidence-bundle.md). No database
access, no store: the bundle is the only input.

Usage:
  uv run scripts/verify_ledger.py <bundle.json> [checksums.sha256]

Exit codes: 0 = verified, 1 = verification failed, 2 = usage/read error.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from mandate.ledger.evidence import EvidenceBundle, verify_bundle


def _verify_checksums(bundle_path: Path, checksums_text: str) -> list[str]:
    problems: list[str] = []
    entries: dict[str, str] = {}
    for line in checksums_text.splitlines():
        parts = line.split("  ")
        if len(parts) == 2:
            entries[Path(parts[1]).name] = parts[0]
    expected = entries.get(bundle_path.name)
    if expected is None:
        problems.append(f"no checksum entry for {bundle_path.name}")
        return problems
    actual = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    if expected != actual:
        problems.append(
            f"{bundle_path.name}: sha256 mismatch (file {actual[:16]}… vs "
            f"expected {expected[:16]}…)"
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="path to bundle.json")
    parser.add_argument(
        "checksums", nargs="?", default=None, help="optional path to checksums.sha256"
    )
    args = parser.parse_args()

    bundle_path = Path(args.bundle)
    try:
        raw = bundle_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {bundle_path}: {exc}", file=sys.stderr)
        return 2
    try:
        bundle = EvidenceBundle.model_validate_json(raw)
    except Exception as exc:
        print(f"error: {bundle_path} is not a valid evidence bundle: {exc}", file=sys.stderr)
        return 2

    problems: list[str] = []
    if args.checksums is not None:
        problems.extend(_verify_checksums(bundle_path, Path(args.checksums).read_text()))

    report = verify_bundle(bundle)
    failed = [c for c in report.checks if not c.ok]
    for check in failed:
        print(f"FAIL {check.name}: {check.detail}", file=sys.stderr)
    for problem in problems:
        print(f"FAIL checksums: {problem}", file=sys.stderr)

    verdict = report.ok and not problems
    print(
        f"{bundle_path.name}: {'VERIFIED' if verdict else 'FAILED'} "
        f"({len(report.checks) - len(failed)}/{len(report.checks)} checks passed, "
        f"deal {bundle.deal.deal_id}, final state {bundle.deal.state})"
    )
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
