"""Evidence bundle build and verify (specs/evidence-bundle.md, ADR-0015).

Pure: no file I/O. Scripts own file access. `verify_bundle` is the
independent verifier — it recomputes every hash and signature and binds the
records/revocations sections with summary hashes, so any swap is detected.
Schema 0.2 adds the signed summary (`summary_signature`): the head hash and
event count are anchored by the gateway's chain signer, so a re-exporter who
truncates the tail and recomputes the summary cannot produce a clean bundle
(audit A2 #7).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict

from mandate.crypto.canonicalization import canonical_bytes, canonical_sha256_hex
from mandate.crypto.signing import (
    ALGORITHM,
    GatewaySigner,
    b64url_decode,
    b64url_encode,
    load_public_key,
    public_key_raw,
)
from mandate.domain.authority import AuthorityRecord, Revocation, SignatureBlock
from mandate.domain.deals import Deal
from mandate.domain.events import GENESIS_HASH, Event, EventType, event_signing_bytes

__all__ = [
    "SCHEMA_VERSION",
    "BundleCheck",
    "BundleDeal",
    "BundleSummary",
    "EvidenceBundle",
    "GatewayPublicKeyRef",
    "VerifyReport",
    "build_bundle",
    "bundle_json",
    "public_key_ref",
    "render_checksums",
    "render_timeline",
    "summary_signing_bytes",
    "verify_bundle",
]

SCHEMA_VERSION = "0.2"


class GatewayPublicKeyRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    algorithm: str
    key_id: str
    key_b64url: str


class BundleSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    chain_head_event_hash: str
    event_count: int
    chain_sha256: str
    records_sha256: str
    revocations_sha256: str


class BundleDeal(BaseModel):
    model_config = ConfigDict(frozen=True)

    deal_id: str
    state: str
    negotiated_rounds: int
    committed_minor: int
    open_disputes: int
    open_approvals: int
    created_at: str


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str
    exported_at: str
    deal: BundleDeal
    events: list[Event]
    authority_records: list[AuthorityRecord]
    revocations: list[Revocation]
    gateway_public_key: GatewayPublicKeyRef
    verification: BundleSummary
    summary_signature: SignatureBlock


@dataclass(frozen=True)
class BundleCheck:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    checks: tuple[BundleCheck, ...]

    def first_failure(self) -> BundleCheck | None:
        for check in self.checks:
            if not check.ok:
                return check
        return None


def public_key_ref(signer: GatewaySigner) -> GatewayPublicKeyRef:
    """The bundle's gateway key reference from an in-memory signer."""
    return GatewayPublicKeyRef(
        algorithm=ALGORITHM,
        key_id=signer.key_id,
        key_b64url=b64url_encode(public_key_raw(signer.public_key)),
    )


def summary_signing_bytes(
    *,
    deal_id: str,
    key_id: str,
    summary: BundleSummary,
) -> bytes:
    """The canonical payload the gateway signs to anchor the summary (ADR-0015).

    Binds the head hash, event count, and section hashes to the deal and the
    signing key. A re-exporter who truncates the tail and recomputes the
    summary cannot reproduce a valid signature without the chain key.
    """
    return canonical_bytes(
        {
            "kind": "mandate.evidence-summary",
            "schema_version": SCHEMA_VERSION,
            "deal_id": deal_id,
            "key_id": key_id,
            "verification": summary.model_dump(mode="json"),
        }
    )


def build_bundle(
    *,
    exported_at: str,
    deal: Deal,
    deal_created_at: str,
    events: Sequence[Event],
    records: Sequence[AuthorityRecord],
    revocations: Sequence[Revocation],
    signer: GatewaySigner,
) -> EvidenceBundle:
    evs = list(events)
    recs = list(records)
    revs = list(revocations)
    summary = BundleSummary(
        chain_head_event_hash=evs[-1].event_hash if evs else GENESIS_HASH,
        event_count=len(evs),
        chain_sha256=canonical_sha256_hex([e.model_dump(mode="json") for e in evs]),
        records_sha256=canonical_sha256_hex([r.model_dump(mode="json") for r in recs]),
        revocations_sha256=canonical_sha256_hex([r.model_dump(mode="json") for r in revs]),
    )
    public_key = public_key_ref(signer)
    value = signer.sign_bytes(
        summary_signing_bytes(deal_id=deal.deal_id, key_id=signer.key_id, summary=summary)
    )
    return EvidenceBundle(
        schema_version=SCHEMA_VERSION,
        exported_at=exported_at,
        deal=BundleDeal(**deal.model_dump(), created_at=deal_created_at),
        events=evs,
        authority_records=recs,
        revocations=revs,
        gateway_public_key=public_key,
        verification=summary,
        summary_signature=SignatureBlock(algorithm=ALGORITHM, key_id=signer.key_id, value=value),
    )


def bundle_json(bundle: EvidenceBundle) -> str:
    """Canonical bytes of the whole bundle (one algorithm, invariant 13)."""
    return canonical_bytes(bundle.model_dump(mode="json")).decode("ascii")


def _message_detail(payload: dict[str, object]) -> str:
    """One line for a MESSAGE event (ADR-0016): what was screened, by which
    pinned screener, and what it found. The content itself is never in the
    payload — only its digest — so nothing untrusted reaches the timeline."""
    screen = cast("dict[str, object] | None", payload.get("screen")) or {}
    digest = str(payload.get("content_sha256"))[:13]
    screener = screen.get("screener")
    if not screen.get("available", True):
        return f"content={digest}… screen={screener} UNAVAILABLE (held for a person)"
    detected = cast("list[dict[str, object]] | None", screen.get("detected")) or []
    found = ", ".join(f"{d.get('field')}@{d.get('confidence_bp')}bp" for d in detected) or "none"
    return (
        f"content={digest}… {payload.get('direction')} screen={screener} "
        f"detected=[{found}] hostility={screen.get('hostility_bp')}bp"
    )


def render_timeline(bundle: EvidenceBundle) -> str:
    lines = [
        f"# Mandate evidence timeline — deal {bundle.deal.deal_id}",
        "",
        f"Exported: {bundle.exported_at} (schema {bundle.schema_version})",
        f"Final state: {bundle.deal.state} | events: {bundle.verification.event_count}",
        f"Summary signed by: {bundle.summary_signature.key_id} (ADR-0015)",
        "",
        "| seq | occurred_at | type | actor | detail | event_hash |",
        "|---|---|---|---|---|---|",
    ]
    for event in bundle.events:
        if event.event_type is EventType.POLICY_DECISION:
            detail = (
                f"request={str(event.payload.get('request_id'))[:13]}… "
                f"outcome={event.payload.get('outcome')} "
                f"reason={event.payload.get('reason_code')}"
            )
        elif event.event_type is EventType.REVOCATION:
            rev = cast("dict[str, object] | None", event.payload.get("revocation")) or {}
            detail = f"record={str(rev.get('record_id'))[:13]}… revoked_at={rev.get('revoked_at')}"
        elif event.event_type is EventType.MESSAGE:
            detail = _message_detail(event.payload)
        else:
            detail = (
                f"event={event.payload.get('event')} "
                f"{event.payload.get('from_state')}→{event.payload.get('to_state')}"
            )
        lines.append(
            f"| {event.sequence_number} | {event.occurred_at} | {event.event_type.value} "
            f"| {event.actor_kind.value}/{event.actor_id} | {detail} "
            f"| {event.event_hash[:16]}… |"
        )
    return "\n".join(lines) + "\n"


def render_checksums(bundle: EvidenceBundle) -> str:
    bjson = bundle_json(bundle).encode("ascii")
    timeline = render_timeline(bundle).encode("utf-8")
    return (
        f"{hashlib.sha256(bjson).hexdigest()}  bundle.json\n"
        f"{hashlib.sha256(timeline).hexdigest()}  timeline.md\n"
    )


def _verify_event(
    index: int,
    event: Event,
    previous: str,
    public_key: Ed25519PublicKey,
) -> tuple[list[BundleCheck], bool]:
    """Checks for one event. Returns the checks and whether all passed."""
    checks: list[BundleCheck] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append(BundleCheck(name, ok, detail or ("ok" if ok else "FAILED")))

    try:
        payload_ok = event.payload_hash == canonical_sha256_hex(event.payload)
    except (ValueError, TypeError) as exc:
        add(f"event_{index}_payload_hash", False, str(exc))
    else:
        add(f"event_{index}_payload_hash", payload_ok, "payload_hash does not match payload")

    form_bytes = event_signing_bytes(event)
    add(
        f"event_{index}_event_hash",
        event.event_hash == hashlib.sha256(form_bytes).hexdigest(),
        "event_hash does not match the canonical event form",
    )

    if event.signature.algorithm != ALGORITHM:
        add(
            f"event_{index}_signature", False, f"unexpected algorithm {event.signature.algorithm!r}"
        )
    else:
        try:
            public_key.verify(b64url_decode(event.signature.value), form_bytes)
            add(f"event_{index}_signature", True)
        except Exception as exc:
            add(f"event_{index}_signature", False, f"signature failed: {type(exc).__name__}")

    add(
        f"event_{index}_sequence",
        event.sequence_number == index,
        f"sequence {event.sequence_number}, expected {index}",
    )
    add(
        f"event_{index}_chain_link",
        event.previous_event_hash == previous,
        "previous_event_hash breaks the chain",
    )

    return checks, all(c.ok for c in checks)


def _verify_summary_signature(
    bundle: EvidenceBundle, public_key: Ed25519PublicKey
) -> list[BundleCheck]:
    """Checks for the signed summary (ADR-0015) — the head-hash anchor.

    The re-exporter can recompute every summary hash, but not the signature:
    it was made with the gateway's chain key over the original summary.
    """
    expected = summary_signing_bytes(
        deal_id=bundle.deal.deal_id,
        key_id=bundle.gateway_public_key.key_id,
        summary=bundle.verification,
    )
    if bundle.summary_signature.algorithm != ALGORITHM:
        return [
            BundleCheck(
                "summary_signature",
                False,
                f"unexpected algorithm {bundle.summary_signature.algorithm!r}",
            )
        ]
    if bundle.summary_signature.key_id != bundle.gateway_public_key.key_id:
        return [
            BundleCheck(
                "summary_signature",
                False,
                "signature key_id does not match gateway_public_key.key_id",
            )
        ]
    try:
        public_key.verify(b64url_decode(bundle.summary_signature.value), expected)
    except Exception as exc:
        return [
            BundleCheck(
                "summary_signature", False, f"summary signature failed: {type(exc).__name__}"
            )
        ]
    return [BundleCheck("summary_signature", True, "ok")]


def verify_bundle(bundle: EvidenceBundle, *, expected_key: Ed25519PublicKey | str) -> VerifyReport:
    """The normative verification procedure (specs/evidence-bundle.md).

    `expected_key` is the signer's public key as the verifier already knows it —
    an `Ed25519PublicKey`, or its base64url raw form. It is **required and has no
    default**, because the key must come from outside the artifact under test.
    Reading it out of `bundle.gateway_public_key` would only prove the bundle is
    internally consistent: anyone can generate a keypair, sign a fabricated chain
    with it, and embed the matching public key (issue #1). The bundle's own claim
    is still checked, but every signature is verified against `expected_key`.
    """
    checks: list[BundleCheck] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append(BundleCheck(name, ok, detail or ("ok" if ok else "FAILED")))

    add("schema_version", bundle.schema_version == SCHEMA_VERSION, f"got {bundle.schema_version!r}")

    public_key: Ed25519PublicKey | None
    if isinstance(expected_key, Ed25519PublicKey):
        public_key = expected_key
    else:
        try:
            public_key = load_public_key(b64url_decode(expected_key))
        except ValueError as exc:
            public_key = None
            add("expected_public_key", False, f"supplied key is unusable: {exc}")

    if public_key is not None:
        expected_b64url = b64url_encode(public_key_raw(public_key))
        add(
            "gateway_public_key",
            bundle.gateway_public_key.key_b64url == expected_b64url,
            "the bundle names a different signing key than the one supplied; "
            "every signature below is checked against the supplied key",
        )
    if public_key is not None:
        previous = GENESIS_HASH
        for index, event in enumerate(bundle.events):
            event_checks, all_ok = _verify_event(index, event, previous, public_key)
            checks.extend(event_checks)
            if all_ok:
                previous = event.event_hash

    add(
        "event_count",
        bundle.verification.event_count == len(bundle.events),
        f"summary {bundle.verification.event_count} != {len(bundle.events)}",
    )
    add(
        "chain_sha256",
        bundle.verification.chain_sha256
        == canonical_sha256_hex([e.model_dump(mode="json") for e in bundle.events]),
        "summary does not bind the event list",
    )
    add(
        "records_sha256",
        bundle.verification.records_sha256
        == canonical_sha256_hex([r.model_dump(mode="json") for r in bundle.authority_records]),
        "summary does not bind the authority records",
    )
    add(
        "revocations_sha256",
        bundle.verification.revocations_sha256
        == canonical_sha256_hex([r.model_dump(mode="json") for r in bundle.revocations]),
        "summary does not bind the revocations",
    )
    head = bundle.events[-1].event_hash if bundle.events else GENESIS_HASH
    add(
        "chain_head_event_hash",
        bundle.verification.chain_head_event_hash == head,
        "summary head does not match the final event",
    )

    if public_key is not None:
        checks.extend(_verify_summary_signature(bundle, public_key))

    last_transition = next(
        (e for e in reversed(bundle.events) if e.event_type is EventType.STATE_TRANSITION), None
    )
    if last_transition is None:
        add("deal_state_divergent", True, "no transitions recorded")
    else:
        add(
            "deal_state_divergent",
            last_transition.payload.get("to_state") == bundle.deal.state,
            "final transition target != deal state",
        )

    return VerifyReport(ok=all(c.ok for c in checks), checks=tuple(checks))
