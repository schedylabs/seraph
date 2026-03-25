"""
Shared utilities for Seraph scanners.
"""

import site
from collections.abc import Iterator
from pathlib import Path


def iter_site_packages() -> Iterator[Path]:
    """Yield existing site-packages directories (system + user)."""
    for d in (*site.getsitepackages(), site.getusersitepackages()):
        p = Path(d)
        if p.exists():
            yield p
