# Seraph

> Guardian of the supply chain.

Seraph is a Python supply chain security scanner. It detects attack vectors at the package level — before or after compromise — with no external dependencies and no network calls.

Python packages are a common supply chain attack surface. Known vectors include stolen publish tokens used to release malicious versions, payloads injected directly into package source files, persistence via `.pth` files executed automatically on interpreter startup, orphaned `.pyc` bytecode with no corresponding source, and backdoors installed post-execution with systemd persistence. Seraph detects these vectors at the package level.

## What it detects

| Scanner | Detects |
|---|---|
| `pth` | Executable code in `.pth` files (the 1.82.8 vector) |
| `pyc` | Orphaned `.pyc` files and suspicious bytecode constants |
| `source` | Obfuscated payload execution in `.py` files via AST analysis |
| `integrity` | Post-install file tampering via `dist-info` RECORD hash verification |
| `persistence` | Known backdoor artifacts on the filesystem |

## Installation

```bash
pip install seraph
```

## Usage

```bash
# Run all scanners
seraph scan

# CI mode — exits with code 1 if findings are detected
seraph scan --ci
```

## How it works

**PTH scanner** reads every `.pth` file in `site-packages` and flags lines containing executable patterns (`import`, `exec(`, `base64`, etc.). Legitimate `.pth` files contain only directory paths.

**PYC scanner** flags `.pyc` files with no corresponding `.py` source (injected bytecode) and walks the bytecode constant pool looking for Base64 blobs and exfiltration indicators.

**Integrity scanner** reads the `RECORD` file that pip writes at install time — which contains a SHA-256 hash of every installed file — and recomputes each hash. Any mismatch means the file was modified after installation.

**Source scanner** parses `.py` files in `site-packages` with Python's `ast` module and flags `exec`/`eval` calls wrapping decode or decompress operations — the pattern used to execute obfuscated payloads. AST analysis avoids false positives from comments and docstrings.

**Persistence scanner** checks for filesystem artifacts known to be dropped by the LiteLLM payload: the `sysmon` backdoor, systemd persistence service, and exfiltration remnants in `/tmp`.

## Design

- Zero dependencies — stdlib only
- No network calls
- Extensible: implement the `Scanner` protocol and register in `cli.py`

```python
from seraph.base import Scanner, ScanResult

class MyScanner(Scanner):
    name = "my-scanner"
    description = "..."

    def run(self) -> ScanResult: ...
```

## License

MIT
