"""
Persistence scanner — detects known backdoor artifacts on the filesystem.

Covers artifacts dropped by the LiteLLM 1.82.7/1.82.8 payload:
sysmon backdoor, systemd persistence service, and exfiltration remnants.
"""

from collections.abc import Iterator
from pathlib import Path

from seraph.base import Finding, Scanner, ScanResult


def _artifacts() -> tuple[Path, ...]:
    home = Path.home()
    paths = [
        home / ".config/sysmon/sysmon.py",
        home / ".config/systemd/user/sysmon.service",
        Path("/tmp/tpcp.tar.gz"),
        Path("/tmp/session.key"),
        Path("/tmp/payload.enc"),
        Path("/tmp/session.key.enc"),
    ]
    # Add /root paths only when not already covered by home
    if home != Path("/root"):
        paths.append(Path("/root/.config/sysmon/sysmon.py"))
    return tuple(paths)


_ARTIFACTS: tuple[Path, ...] = _artifacts()


class PersistenceScanner(Scanner):
    __slots__ = ()

    name = "persistence"
    description = "Detects known backdoor artifacts (sysmon, systemd service, exfil remnants)"

    def run(self) -> ScanResult:
        result = ScanResult(scanner=self.name)
        result.scanned.extend(_ARTIFACTS)
        result.findings.extend(self._check())
        return result

    def _check(self) -> Iterator[Finding]:
        for path in _ARTIFACTS:
            try:
                exists = path.exists()
            except PermissionError:
                continue
            if exists:
                yield Finding(
                    scanner=self.name,
                    file=path,
                    line_number=0,
                    line="",
                    matched_pattern=path.name,
                    severity="critical",
                )
