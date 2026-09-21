"""AST scan enforcing the no-I/O invariant at the import level.

Exit criterion (docs/test-plan.md): no import in src/mandate/domain or
src/mandate/policy touches socket, subprocess, os.environ secrets, a
database driver, or a clock. Time enters only as the explicit `now` input.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "mandate"

BANNED_MODULES = frozenset(
    {
        # networking
        "socket",
        "http",
        "urllib",
        "requests",
        "httpx",
        "aiohttp",
        "smtplib",
        "ftplib",
        "telnetlib",
        "ssl",
        # process / execution
        "subprocess",
        "multiprocessing",
        "asyncio",
        "sched",
        # secrets / environment
        "os",
        # database drivers
        "sqlite3",
        "psycopg",
        "psycopg2",
        "pymysql",
        "aiomysql",
        "mysql",
        "sqlalchemy",
        "pymongo",
        "redis",
        # clock
        "time",
    }
)

BANNED_DATETIME_CALLS = frozenset({"now", "utcnow", "fromtimestamp", "timestamp"})


def _modules() -> list[Path]:
    # transport/ is the pure part of the wire layer (envelope, dedup);
    # transport/gateway.py is the I/O boundary (like api/) and is excluded.
    # screen/ is pure (questions, protocol, fixture) except the vendor adapter
    # screen/typesafe.py and screen/config.py (reads env) — the third I/O
    # boundary (ADR-0016).
    transport = [p for p in (SRC / "transport").rglob("*.py") if p.name != "gateway.py"]
    screen = [
        p for p in (SRC / "screen").rglob("*.py") if p.name not in ("typesafe.py", "config.py")
    ]
    return sorted(
        list((SRC / "domain").rglob("*.py"))
        + list((SRC / "policy").rglob("*.py"))
        + list((SRC / "crypto").rglob("*.py"))
        + list((SRC / "application").rglob("*.py"))
        + list((SRC / "ledger").rglob("*.py"))
        + transport
        + screen
    )


def _all_src_modules() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_scan_is_not_vacuous():
    names = {p.name for p in _modules()}
    assert "engine.py" in names
    assert "state_machine.py" in names
    assert "authority.py" in names
    assert "canonicalization.py" in names
    assert "signing.py" in names
    assert "anti_replay.py" in names
    assert "chain.py" in names
    assert "evidence.py" in names
    assert "envelope.py" in names
    assert "dedup.py" in names
    assert "content.py" in names
    assert "fixture.py" in names
    assert "typesafe.py" not in names, "the vendor adapter is an I/O boundary, not a pure module"


def test_api_is_the_only_io_boundary():
    """The boundary packages exist and are the only layers allowed to do I/O.

    Invariant 2: domain/policy/ledger/crypto/application stay I/O-free; the
    operator-facing `mandate.api` (console) and `mandate.transport.gateway`
    (wire, ADR-0012) are where I/O lives. This asserts the boundaries are
    present so their exclusion from the pure scan is meaningful, not
    accidental.
    """
    api_dir = SRC / "api"
    assert api_dir.is_dir(), "the mandate.api boundary package is missing"
    assert any(api_dir.rglob("app.py")), "mandate.api has no app factory"
    assert (SRC / "transport" / "gateway.py").is_file(), (
        "the mandate.transport.gateway wire boundary is missing"
    )
    scanned = _modules()
    assert not any(p.parent.name == "api" for p in scanned), (
        "api/ must not be scanned as a pure layer"
    )
    assert not any(p.name == "gateway.py" and p.parent.name == "transport" for p in scanned), (
        "transport/gateway.py must not be scanned as a pure layer"
    )


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(SRC)))
def test_no_banned_module_imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    bad = sorted(imported & BANNED_MODULES)
    assert not bad, f"{path.name} imports banned module(s): {bad}"


_IO_BOUNDARY_PREFIXES = (
    "mandate.api",
    "mandate.transport.gateway",
    "mandate.screen.typesafe",
    "mandate.screen.config",
)

_VENDOR_SDK = "typesafe_sdk"
_VENDOR_ADAPTER = SRC / "screen" / "typesafe.py"


@pytest.mark.parametrize("path", _all_src_modules(), ids=lambda p: str(p.relative_to(SRC)))
def test_vendor_sdk_only_in_its_adapter(path: Path):
    """ADR-0016: the classifier vendor's SDK is imported in exactly one file,
    `screen/typesafe.py`, so swapping vendors (or going local for an on-prem
    build) touches one module and the pure core never learns a vendor name."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports_sdk = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            alias.name.split(".")[0] == _VENDOR_SDK for alias in node.names
        ):
            imports_sdk = True
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".")[0] == _VENDOR_SDK
        ):
            imports_sdk = True
    if path == _VENDOR_ADAPTER:
        assert imports_sdk, "the adapter must be the module that imports the SDK"
    else:
        assert not imports_sdk, f"{path.relative_to(SRC)} imports {_VENDOR_SDK}"


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(SRC)))
def test_pure_layer_never_imports_the_io_boundary(path: Path):
    """domain/policy/ledger/crypto/application must not import an I/O boundary.

    The boundary (mandate.api console, mandate.transport.gateway wire) depends
    inward on these layers, never the reverse (invariant 2); a reverse edge
    would let I/O leak into the pure core.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith(_IO_BOUNDARY_PREFIXES)
        ):
            msg = f"{path.name} imports the I/O boundary: {node.module}"
            raise AssertionError(msg)
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(_IO_BOUNDARY_PREFIXES):
                    msg = f"{path.name} imports the I/O boundary: {alias.name}"
                    raise AssertionError(msg)


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(SRC)))
def test_no_wall_clock_calls(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain: list[str] = []
        func = node.func
        while isinstance(func, ast.Attribute):
            chain.append(func.attr)
            func = func.value
        if not isinstance(func, ast.Name):
            continue
        chain.append(func.id)
        chain.reverse()
        if len(chain) < 2:
            continue
        if chain[0] == "datetime" and chain[-1] in BANNED_DATETIME_CALLS:
            violations.append(".".join(chain))
        if chain[0] == "time":
            violations.append(".".join(chain))
    assert not violations, f"{path.name} calls wall-clock API(s): {violations}"
