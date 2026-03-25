"""
PYC file scanner — detects injected or suspicious .pyc files.

Two vectors covered:
1. Orphaned .pyc — bytecode in __pycache__ with no corresponding .py source
   (Python will import and execute it regardless).
2. Suspicious constants — Base64 blobs, URLs, or encoded payloads embedded
   in the code object's constant pool.
"""

import marshal
import re
import types
from collections.abc import Iterator
from pathlib import Path

from seraph.base import Finding, Scanner, ScanResult
from seraph.scanners._common import iter_site_packages


# Matches Base64 payloads with valid padding — requires trailing = or ==
# to avoid false positives on random alphanumeric strings (UUIDs, license keys, etc.)
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)")

# Common exfiltration / C2 indicators in string constants
_SUSPICIOUS_CONST = re.compile(
    r"https?://|socket\.|subprocess|os\.system|os\.popen|eval\(|exec\(|__import__"
)


def _iter_constants(code: types.CodeType) -> Iterator[object]:
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from _iter_constants(const)
        else:
            yield const


class PycScanner(Scanner):
    __slots__ = ()

    name = "pyc"
    description = "Detects orphaned .pyc files and suspicious bytecode constants"

    def run(self) -> ScanResult:
        result = ScanResult(scanner=self.name)
        for site_dir in iter_site_packages():
            for pyc_file in site_dir.rglob("__pycache__/*.pyc"):
                result.scanned.append(pyc_file)
                result.findings.extend(self._scan_file(pyc_file))
        return result

    def _scan_file(self, pyc_file: Path) -> Iterator[Finding]:
        yield from self._check_orphan(pyc_file)

        code = self._load_code(pyc_file)
        if code is None:
            return

        yield from self._check_constants(pyc_file, code)

    def _check_orphan(self, pyc_file: Path) -> Iterator[Finding]:
        # __pycache__/module.cpython-311.pyc → ../module.py
        stem = pyc_file.stem.split(".")[0]
        source = pyc_file.parent.parent / f"{stem}.py"
        if source.exists():
            return
        # Compiled-only packages (Cython, etc.) ship no .py files at all — skip
        if not any(pyc_file.parent.parent.glob("*.py")):
            return
        yield Finding(
                scanner=self.name,
                file=pyc_file,
                line_number=0,
                line="",
                matched_pattern="orphaned_pyc",
                severity="high",
            )

    def _load_code(self, pyc_file: Path) -> types.CodeType | None:
        try:
            data = pyc_file.read_bytes()
        except OSError:
            return None

        # .pyc layout: 16 bytes header (magic + flags + timestamp/hash + size)
        # marshal payload starts at byte 16
        try:
            code = marshal.loads(data[16:])
        except Exception:
            return None

        return code if isinstance(code, types.CodeType) else None

    def _check_constants(self, pyc_file: Path, code: types.CodeType) -> Iterator[Finding]:
        for const in _iter_constants(code):
            # Skip non-strings, short strings, and multiline strings (docstrings, help text)
            if not isinstance(const, str) or len(const) < 10 or "\n" in const:
                continue
            for pattern, regex in (
                ("suspicious_constant", _SUSPICIOUS_CONST),
                ("base64_blob", _BASE64),
            ):
                if regex.search(const):
                    yield Finding(
                        scanner=self.name,
                        file=pyc_file,
                        line_number=0,
                        line=const[:120],
                        matched_pattern=pattern,
                        severity="medium",
                    )
                    break
