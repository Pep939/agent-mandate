"""Export an evidence bundle for a deal from a Postgres ledger.

Usage:
  uv run scripts/export_evidence.py \
    --db-url postgresql+psycopg://user:pass@localhost/mandate \
    --deal-id <ULID> \
    --chain-key <path to the gateway chain-signer key file> \
    --out <directory> \
    [--now <RFC3339>]

The chain-signer key file is the one the gateway uses to sign events
(`scripts/dev_gateway_keys.py` shape). Schema 0.2 (ADR-0015): the bundle's
summary is signed with that key, so a re-exporter without it cannot truncate
the tail and ship a clean bundle.

Writes bundle.json, timeline.md and checksums.sha256 into --out, then runs
the in-process verification procedure and prints the result (exit 1 if the
exported bundle does not verify).
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from mandate.adapters.postgres.store import PostgresLedgerStore
from mandate.ledger.evidence import (
    build_bundle,
    bundle_json,
    render_checksums,
    render_timeline,
    verify_bundle,
)
from mandate.transport.gateway import load_chain_signer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-url", required=True)
    parser.add_argument("--deal-id", required=True)
    parser.add_argument(
        "--chain-key",
        required=True,
        type=Path,
        help="gateway chain-signer key file (dev_gateway_keys.py shape); signs the summary",
    )
    parser.add_argument("--out", required=True)
    parser.add_argument("--now", default=None, help="RFC3339 export timestamp")
    args = parser.parse_args()

    signer = load_chain_signer(args.chain_key)

    store = PostgresLedgerStore(args.db_url)
    try:
        deal = store.get_deal(args.deal_id)
        if deal is None:
            print(f"error: deal {args.deal_id} not found", file=sys.stderr)
            return 2
        created_at = store.get_deal_created_at(args.deal_id)
        if created_at is None:
            print(f"error: no created_at for deal {args.deal_id}", file=sys.stderr)
            return 2
        events = store.events_for(args.deal_id)
        record_ids = sorted(
            {e.authority_record_id for e in events if e.authority_record_id is not None}
        )
        records = []
        for record_id in record_ids:
            record = store.get_record(record_id)
            if record is None:
                print(
                    f"warning: authority record {record_id} missing from store; "
                    "bundle will not bind it",
                    file=sys.stderr,
                )
                continue
            records.append(record)
        revocations = store.list_revocations(record_ids)

        bundle = build_bundle(
            exported_at=args.now or datetime.now(UTC).isoformat(),
            deal=deal,
            deal_created_at=created_at,
            events=events,
            records=records,
            revocations=revocations,
            signer=signer,
        )
    finally:
        store.close()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "bundle.json").write_text(bundle_json(bundle), encoding="utf-8")
    (out / "timeline.md").write_text(render_timeline(bundle), encoding="utf-8")
    (out / "checksums.sha256").write_text(render_checksums(bundle), encoding="utf-8")

    report = verify_bundle(bundle)
    failed = [c for c in report.checks if not c.ok]
    for check in failed:
        print(f"FAIL {check.name}: {check.detail}", file=sys.stderr)
    print(f"events: {len(events)} | records: {len(records)} | revocations: {len(revocations)}")
    print(
        f"verification: {'ok' if report.ok else 'FAILED'} "
        f"({len(report.checks) - len(failed)}/{len(report.checks)} checks passed)"
    )
    print(f"bundle written to {out}/ (bundle.json, timeline.md, checksums.sha256)")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
