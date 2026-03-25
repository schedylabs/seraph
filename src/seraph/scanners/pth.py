"""
PTH file scanner — detects executable code in .pth files.

Legitimate .pth files contain only directory paths.
Lines with executable patterns indicate a supply chain compromise.
"""

import re
from collections.abc import Iterator
from pathlib import Path

from seraph.base import Finding, Scanner, ScanResult
from seraph.scanners._common import iter_site_packages


_PATTERN = re.compile(
    r"import |exec\(|__import__|os\.system|os\.popen|subprocess|socket\.|urllib|requests|base64|eval\(|compile\(|open\("
)


class PthScanner(Scanner):
    __slots__ = ()

    name = "pth"
    description = "Detects executable code in .pth files (supply chain persistence vector)"

    def run(self) -> ScanResult:
        result = ScanResult(scanner=self.name)
        for site_dir in iter_site_packages():
            for pth_file in site_dir.glob("*.pth"):
                result.scanned.append(pth_file)
                result.findings.extend(self._scan_file(pth_file))
        return result

    def _scan_file(self, pth_file: Path) -> Iterator[Finding]:
        try:
            lines = pth_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = _PATTERN.search(stripped)
            if m:
                yield Finding(
                    scanner=self.name,
                    file=pth_file,
                    line_number=i,
                    line=stripped,
                    matched_pattern=m.group(0),
                )
