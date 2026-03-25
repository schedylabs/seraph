"""
Base types and Scanner protocol for Seraph.

All scanners must implement the Scanner protocol.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass(slots=True, frozen=True)
class Finding:
    scanner: str
    file: Path
    line_number: int
    line: str
    matched_pattern: str
    severity: str = "high"

    def __str__(self) -> str:
        return (
            f"[{self.scanner}] {self.file}:{self.line_number} "
            f"— pattern '{self.matched_pattern}' (severity: {self.severity})"
        )


@dataclass(slots=True)
class ScanResult:
    scanner: str
    scanned: list[Path] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.findings


@runtime_checkable
class Scanner(Protocol):
    """Protocol that all Seraph scanners must implement."""

    #: Short identifier used in findings and CLI output (e.g. "pth")
    name: str

    #: One-line description shown in --help
    description: str

    def run(self) -> ScanResult:
        """Execute the scan and return a result."""
        ...
