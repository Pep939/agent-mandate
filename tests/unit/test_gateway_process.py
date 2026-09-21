"""C1 gateway process helpers: key custody loaders, env parsing, redacting
JSON logging. All deterministic file/env in → object out; no network."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mandate.crypto.signing import b64url_decode, generate_keypair
from mandate.transport.envelope import EnvelopeError, GatewayIdentity
from mandate.transport.gateway import (
    RedactingJsonFormatter,
    configure_gateway_logging,
    load_chain_signer,
    load_identity,
    load_peers,
    max_age_from_env,
    require_env,
)
from tests.support.factories import new_ulid, write_key_file

_ENCODING = serialization.Encoding.Raw
_PUBLIC = serialization.PublicFormat.Raw
_PRIVATE = serialization.PrivateFormat.Raw
_NO_ENCRYPTION = serialization.NoEncryption()


def _seed(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=_ENCODING, format=_PRIVATE, encryption_algorithm=_NO_ENCRYPTION
    )


@pytest.fixture
def identity_key():
    private_key, public_key = generate_keypair()
    return private_key, public_key


class TestLoadIdentity:
    def test_round_trip(self, tmp_path: Path, identity_key) -> None:
        private_key, _public_key = identity_key
        key_id = new_ulid()
        path = write_key_file(tmp_path, key_id, private_key)
        identity = load_identity(path)
        assert identity.identity_id == key_id
        assert identity.private_key is not None
        assert identity.public_key_b64url

    def test_stored_public_key_must_match_seed(self, tmp_path: Path, identity_key) -> None:
        private_key, _public_key = identity_key
        path = write_key_file(tmp_path, new_ulid(), private_key)
        payload = json.loads(path.read_text(encoding="utf-8"))
        # 32-byte b64url, deliberately the wrong key
        payload["public_key"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(EnvelopeError, match="does not match"):
            load_identity(path)

    def test_missing_seed(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.json"
        path.write_text('{"key_id": "x", "public_key": "abc"}\n', encoding="utf-8")
        with pytest.raises(EnvelopeError, match="cannot load"):
            load_identity(path)

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(EnvelopeError, match="cannot load"):
            load_identity(tmp_path / "nope.json")

    def test_corrupt_json(self, tmp_path: Path) -> None:
        path = tmp_path / "corrupt.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(EnvelopeError, match="cannot load"):
            load_identity(path)


class TestLoadChainSigner:
    def test_round_trip_signs_and_verifies(self, tmp_path: Path) -> None:
        private_key, public_key = generate_keypair()
        key_id = new_ulid()
        path = write_key_file(tmp_path, key_id, private_key)
        signer = load_chain_signer(path)
        assert signer.key_id == key_id
        value = signer.sign_bytes(b"event-payload")
        public_key.verify(b64url_decode(value), b"event-payload")  # raises on mismatch

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(EnvelopeError, match="cannot load"):
            load_chain_signer(tmp_path / "nope.json")


class TestLoadPeers:
    def test_round_trip(self, tmp_path: Path) -> None:
        peer = GatewayIdentity.from_seed(new_ulid(), _seed(generate_keypair()[0]))
        entry = {"identity_id": peer.identity_id, "public_key": peer.public_key_b64url}
        path = tmp_path / "peers.json"
        path.write_text(json.dumps({peer.identity_id: entry}), encoding="utf-8")
        peers = load_peers(path)
        assert set(peers) == {peer.identity_id}
        assert peers[peer.identity_id].public_key == peer.public_key
        assert peers[peer.identity_id].private_key is None  # verify-only

    def test_empty_registry(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        path.write_text("{}\n", encoding="utf-8")
        assert load_peers(path) == {}

    def test_entry_declaring_different_id(self, tmp_path: Path) -> None:
        peer = GatewayIdentity.from_seed(new_ulid(), _seed(generate_keypair()[0]))
        entry = {"identity_id": peer.identity_id, "public_key": peer.public_key_b64url}
        path = tmp_path / "peers.json"
        path.write_text(json.dumps({"someone-else": entry}), encoding="utf-8")
        with pytest.raises(EnvelopeError, match="different identity_id"):
            load_peers(path)

    def test_malformed_entry(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        path.write_text(json.dumps({"peer-a": {"identity_id": "peer-a"}}), encoding="utf-8")
        with pytest.raises(EnvelopeError, match="malformed"):
            load_peers(path)

    def test_not_an_object(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        path.write_text("[1, 2, 3]\n", encoding="utf-8")
        with pytest.raises(EnvelopeError, match="cannot load"):
            load_peers(path)


class TestMaxAgeFromEnv:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("300", 300),
            ("60", 60),
            ("  90  ", 90),
            ("0", None),
            ("off", None),
            ("OFF", None),
            ("none", None),
            ("disabled", None),
            ("", None),
            (None, None),
            ("-5", None),
        ],
    )
    def test_values(self, raw: str | None, expected: int | None) -> None:
        assert max_age_from_env(raw) == expected

    def test_non_integer_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be an integer"):
            max_age_from_env("abc")


class TestRequireEnv:
    def test_reads_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MANDATE_TEST_VAR", "  x  ")
        assert require_env("MANDATE_TEST_VAR") == "  x  "

    def test_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MANDATE_TEST_VAR", raising=False)
        with pytest.raises(ValueError, match="is required"):
            require_env("MANDATE_TEST_VAR")

    def test_blank(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MANDATE_TEST_VAR", "   ")
        with pytest.raises(ValueError, match="is required"):
            require_env("MANDATE_TEST_VAR")


class TestRedactingJsonFormatter:
    @staticmethod
    def _format(payload: dict) -> dict:
        formatter = RedactingJsonFormatter()
        record = logging.LogRecord(
            name="mandate.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="message processed",
            args=None,
            exc_info=None,
        )
        record.log = payload  # the structured payload rides under `log`
        return json.loads(formatter.format(record))

    def test_sensitive_keys_redacted(self) -> None:
        entry = self._format(
            {"event": "message", "seed": "topsecret", "PASSWORD": "hunter2", "token": "t-123"}
        )
        assert entry["seed"] == "***redacted***"
        assert entry["PASSWORD"] == "***redacted***"
        assert entry["token"] == "***redacted***"
        assert entry["event"] == "message"  # non-sensitive values survive

    def test_nested_dict_redacted(self) -> None:
        entry = self._format(
            {
                "event": "start",
                "config": {"db": "x", "secret": "s3cret", "nested": {"private": "p"}},
            }
        )
        assert entry["config"]["db"] == "x"
        assert entry["config"]["secret"] == "***redacted***"
        assert entry["config"]["nested"]["private"] == "***redacted***"

    def test_no_structured_payload(self) -> None:
        record = logging.LogRecord("m", logging.INFO, __file__, 1, "plain", None, None)
        entry = json.loads(RedactingJsonFormatter().format(record))
        assert entry["msg"] == "plain"
        assert "level" in entry and "ts" in entry

    def test_configure_gateway_logging(self, capsys: pytest.CaptureFixture[str]) -> None:
        configure_gateway_logging("INFO")
        try:
            logger = logging.getLogger("mandate.test")
            logger.info("hello", extra={"log": {"event": "x", "seed": "s"}})
            out = capsys.readouterr().err
            line = json.loads(out.strip().splitlines()[-1])
            assert line["msg"] == "hello"
            assert line["event"] == "x"
            assert line["seed"] == "***redacted***"
        finally:
            logging.root.handlers[:] = []
            logging.root.setLevel(logging.WARNING)
