import py_compile
import sys
import tempfile
import unittest
from pathlib import Path

from schedy_seraph.scanners.pyc import PycScanner


def _make_pyc(tmp: Path, source: str, name: str = "mod") -> Path:
    py = tmp / f"{name}.py"
    py.write_text(source)
    cache = tmp / "__pycache__"
    cache.mkdir(exist_ok=True)
    pyc = cache / f"{name}.{sys.implementation.cache_tag}.pyc"
    py_compile.compile(str(py), cfile=str(pyc), doraise=True)
    return pyc


def _make_orphan(tmp: Path, source: str, name: str = "orphan") -> Path:
    pyc = _make_pyc(tmp, source, name)
    (tmp / f"{name}.py").unlink()
    # Keep another .py in the dir so the compiled-only heuristic doesn't skip
    (tmp / "__init__.py").write_text("")
    return pyc


def _scan(pyc: Path):
    return list(PycScanner()._scan_file(pyc))


class TestPycScanner(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_clean_file_no_findings(self):
        pyc = _make_pyc(self.tmp, "x = 1 + 1\n")
        self.assertEqual(_scan(pyc), [])

    def test_orphan_detected(self):
        pyc = _make_orphan(self.tmp, "x = 1\n")
        patterns = [f.matched_pattern for f in _scan(pyc)]
        self.assertIn("orphaned_pyc", patterns)

    def test_orphan_severity_high(self):
        pyc = _make_orphan(self.tmp, "x = 1\n")
        findings = [f for f in _scan(pyc) if f.matched_pattern == "orphaned_pyc"]
        self.assertEqual(findings[0].severity, "high")

    def test_suspicious_url_constant(self):
        pyc = _make_pyc(self.tmp, 'URL = "http://evil.com/exfil"\n')
        patterns = [f.matched_pattern for f in _scan(pyc)]
        self.assertIn("suspicious_constant", patterns)

    def test_base64_constant_detected(self):
        payload = "A" * 40 + "Ag=="
        pyc = _make_pyc(self.tmp, f'DATA = "{payload}"\n')
        patterns = [f.matched_pattern for f in _scan(pyc)]
        self.assertIn("base64_blob", patterns)

    def test_multiline_string_not_detected(self):
        pyc = _make_pyc(self.tmp, '"""Docs.\nhttp://example.com\n"""\nx = 1\n')
        findings = [f for f in _scan(pyc) if f.matched_pattern == "suspicious_constant"]
        self.assertEqual(findings, [])

    def test_corrupted_pyc_no_crash(self):
        cache = self.tmp / "__pycache__"
        cache.mkdir()
        pyc = cache / "bad.cpython-311.pyc"
        pyc.write_bytes(b"\x00" * 4)
        findings = _scan(pyc)
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
