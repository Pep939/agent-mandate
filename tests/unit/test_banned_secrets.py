"""Banned-secret scan (invariant 12, ADR-0011).

No literal secret material may live in source control. Three rules:

1. src/ must not give a secret-named module variable or function parameter a
   committed *literal* default (the "default password in code" bug). Secrets are
   env-supplied or generated at the boundary, never a source literal.
2. src/ must not hold real key material (PEM, non-uniform 64-hex, or a long
   high-entropy base64url token) as a direct value.
3. tests/ must not contain a private key (PEM). RFC 8032 hex test vectors are
   public standard material and are allowed.

String constants that are *call arguments* (e.g. a filename, ``getattr``'s attr
name, ``frozenset``'s alphabet) are deliberately ignored — a committed secret is
a direct value, never an argument to a call.
"""

from __future__ import annotations

import ast
import math
import re
from collections.abc import Iterator
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "mandate"
TESTS = Path(__file__).resolve().parents[2] / "tests"

_SECRET_NAME_RE = re.compile(r"(password|passwd|secret|seed|private|token)", re.IGNORECASE)
_PEM_RE = re.compile(r"-----BEGIN")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_\-+/=]+$")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


def _py_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _is_call_argument(node: ast.AST, parent: dict[ast.AST, ast.AST]) -> bool:
    cur = node
    for _ in range(2):
        p = parent.get(cur)
        if p is None or isinstance(p, (ast.Assign, ast.AnnAssign)):
            return False
        if isinstance(p, ast.Call):
            return True
        cur = p
    return False


def _direct_strings(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """(lineno, value) for every str constant that is a direct value, not a
    call argument."""
    parent = _parent_map(tree)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and not _is_call_argument(node, parent)
        ):
            yield node.lineno, node.value


def _is_base64_token(s: str) -> bool:
    if len(s) < 40 or any(ch.isspace() for ch in s) or not _B64URL_RE.match(s):
        return False
    return _entropy(s) > 4.7


def _looks_like_real_key(s: str) -> bool:
    if _PEM_RE.search(s):
        return True
    if _HEX64_RE.match(s) and len(set(s)) > 1:  # not the all-zero GENESIS_HASH
        return True
    return _is_base64_token(s)


def _is_env_name(s: str) -> bool:
    return re.fullmatch(r"[A-Z_]+", s) is not None


def _check_param_defaults(func: ast.FunctionDef, path: Path) -> list[str]:
    """Flag def f(..., password="literal") — a committed default secret."""
    args = list(func.args.args) + list(func.args.kwonlyargs)
    defaults = [None] * (len(args) - len(func.args.defaults)) + list(func.args.defaults)
    out: list[str] = []
    for arg, default in zip(args, defaults, strict=False):
        if (
            isinstance(default, ast.Constant)
            and isinstance(default.value, str)
            and default.value
            and _SECRET_NAME_RE.search(arg.arg)
        ):
            out.append(f"{path.name}:{func.lineno} {arg.arg}={default.value[:8]!r}")
    return out


def test_src_has_no_committed_default_secrets():
    offenders: list[str] = []
    for path in _py_files(SRC):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            # module / class level: NAME = "literal"
            if (
                isinstance(node, (ast.Assign, ast.AnnAssign))
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                if isinstance(node, ast.Assign):
                    targets = [t.id for t in node.targets]
                else:
                    targets = [node.target.id]
                if (
                    node.value.value
                    and not _is_env_name(node.value.value)
                    and any(_SECRET_NAME_RE.search(t) for t in targets)
                ):
                    offenders.append(
                        f"{path.name}:{node.lineno} {targets}={node.value.value[:8]!r}"
                    )
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                offenders.extend(_check_param_defaults(node, path))
    assert not offenders, "committed default secret(s) in src/: " + ", ".join(offenders)


def test_no_real_key_material_in_src():
    """A shipped secret (PEM, hex digest, long token) must not live in src/."""
    offenders: list[str] = []
    for path in _py_files(SRC):
        for lineno, s in _direct_strings(ast.parse(path.read_text(encoding="utf-8"))):
            if _looks_like_real_key(s):
                offenders.append(f"{path.name}:{lineno} {s[:16]!r}...")
    assert not offenders, "possible real key material in src/: " + ", ".join(offenders)


def test_no_private_key_material_in_tests():
    offenders: list[str] = []
    for path in _py_files(TESTS):
        for lineno, s in _direct_strings(ast.parse(path.read_text(encoding="utf-8"))):
            if _PEM_RE.search(s):
                offenders.append(f"{path.name}:{lineno} {s[:16]!r}...")
    assert not offenders, "private key material in tests/: " + ", ".join(offenders)


def test_scan_is_not_vacuous():
    # the detector must actually see secret-shaped strings
    crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # len 32, excluded by length
    token = "K7xPq2mN9rLw4vTz8bYc6dFhJgS3aEUiQw7zB4tXRdY0"  # len 44, high-entropy
    assert _looks_like_real_key("-----BEGIN PRIVATE KEY-----")
    assert _looks_like_real_key("a1" * 32)  # non-uniform 64-hex
    assert _looks_like_real_key(token)
    assert not _looks_like_real_key("0" * 64)  # GENESIS_HASH convention
    assert not _looks_like_real_key("op-test-password")
    assert not _looks_like_real_key(crockford)  # Crockford alphabet
    assert not _looks_like_real_key("Ed25519")
