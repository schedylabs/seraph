"""
Integrity scanner — verifies installed package files against dist-info RECORD hashes.

pip writes a RECORD file (sha256 per file) at install time.
Any post-install tampering — injected payloads, patched sources — breaks the hash.
No network calls. Works for any package, any version.
"""

import base64
import csv
import hashlib
from collections.abc import Iterator
from importlib.metadata import Distribution
from pathlib import Path

from schedy_seraph.base import Finding, Scanner, ScanResult


class IntegrityScanner(Scanner):
    __slots__ = ()

    name = "integrity"
    description = "Detects post-install file tampering via dist-info RECORD hash verification"

    def run(self) -> ScanResult:
        result = ScanResult(scanner=self.name)
        for dist in Distribution.discover():
            result.findings.extend(self._check_dist(dist, result.scanned))
        return result

    def _check_dist(self, dist: Distribution, scanned: list[Path]) -> Iterator[Finding]:
        record = dist.read_text("RECORD")
        if record is None:
            return

        for row in csv.reader(record.splitlines()):
            if len(row) < 2 or not row[1].startswith("sha256:"):
                continue

            path_str, hash_str, *_ = row
            file = Path(dist.locate_file(path_str))
            scanned.append(file)

            try:
                actual = hashlib.sha256(file.read_bytes()).digest()
            except OSError:
                continue

            try:
                s = hash_str[7:]
                expected = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
            except Exception:
                continue
            if actual != expected:
                yield Finding(
                    scanner=self.name,
                    file=file,
                    line_number=0,
                    line=hash_str,
                    matched_pattern="hash_mismatch",
                    severity="critical",
                )
