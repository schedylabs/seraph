"""
Source scanner — detects obfuscated payload execution in installed .py files.

Uses AST analysis instead of regex to avoid false positives from comments,
docstrings, and test code. Flags only structural patterns that indicate
active payload execution: exec/eval wrapping decode or decompress calls,
and dynamic __import__ invocations used to evade static analysis.
"""

import ast
from collections.abc import Iterator
from pathlib import Path

from schedy_seraph.base import Finding, Scanner, ScanResult
from schedy_seraph.scanners._common import iter_site_packages


# Attribute names and function names associated with payload decoding
_DECODE_METHODS: frozenset[str] = frozenset({
    "b64decode", "urlsafe_b64decode", "b32decode", "b85decode",
    "fromhex", "decompress", "decode",
})


def _has_decode_call(node: ast.expr) -> bool:
    """Return True if the expression tree contains a decode/decompress call."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if isinstance(func, ast.Attribute) and func.attr in _DECODE_METHODS:
            return True
        if isinstance(func, ast.Name) and func.id in _DECODE_METHODS:
            return True
    return False


def _check_node(node: ast.AST, py_file: Path) -> Finding | None:
    if not isinstance(node, ast.Call):
        return None

    func = node.func

    # exec(...) or eval(...) wrapping an encoded/compressed payload
    if isinstance(func, ast.Name) and func.id in ("exec", "eval"):
        for arg in node.args:
            if _has_decode_call(arg):
                return Finding(
                    scanner="source",
                    file=py_file,
                    line_number=node.lineno,
                    line=ast.unparse(node)[:120],
                    matched_pattern=f"{func.id}_encoded_payload",
                    severity="critical",
                )

    # __import__("...") — dynamic import used to evade static analysis
    if isinstance(func, ast.Name) and func.id == "__import__":
        return Finding(
            scanner="source",
            file=py_file,
            line_number=node.lineno,
            line=ast.unparse(node)[:120],
            matched_pattern="dynamic_import",
            severity="high",
        )

    return None


class SourceScanner(Scanner):
    __slots__ = ()

    name = "source"
    description = "Detects obfuscated payload execution in installed .py files via AST analysis"

    def run(self) -> ScanResult:
        result = ScanResult(scanner=self.name)
        for site_dir in iter_site_packages():
            for py_file in site_dir.rglob("*.py"):
                # Skip test directories shipped inside packages
                if any(p in {"tests", "test"} for p in py_file.parts):
                    continue
                if py_file.name.startswith("test_") or py_file.name.endswith("_test.py"):
                    continue
                result.scanned.append(py_file)
                result.findings.extend(self._scan_file(py_file))
        return result

    def _scan_file(self, py_file: Path) -> Iterator[Finding]:
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            return

        for node in ast.walk(tree):
            finding = _check_node(node, py_file)
            if finding:
                yield finding
