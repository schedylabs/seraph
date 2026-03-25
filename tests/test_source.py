import tempfile
import unittest
from pathlib import Path

from seraph.scanners.source import SourceScanner


def _scan(tmp: Path, source: str):
    py = tmp / "pkg" / "mod.py"
    py.parent.mkdir(parents=True, exist_ok=True)
    py.write_text(source)
    return list(SourceScanner()._scan_file(py))


class TestSourceScanner(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_clean_code_no_findings(self):
        self.assertEqual(_scan(self.tmp, "x = 1 + 1\n"), [])

    def test_exec_b64decode_detected(self):
        findings = _scan(self.tmp, "exec(base64.b64decode('cGF5bG9hZA=='))\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].matched_pattern, "exec_encoded_payload")
        self.assertEqual(findings[0].severity, "critical")

    def test_eval_b64decode_detected(self):
        findings = _scan(self.tmp, "eval(base64.b64decode(data))\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].matched_pattern, "eval_encoded_payload")

    def test_exec_decompress_detected(self):
        findings = _scan(self.tmp, "exec(zlib.decompress(data))\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].matched_pattern, "exec_encoded_payload")

    def test_exec_fromhex_detected(self):
        findings = _scan(self.tmp, "exec(bytes.fromhex('deadbeef'))\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].matched_pattern, "exec_encoded_payload")

    def test_dynamic_import_detected(self):
        findings = _scan(self.tmp, '__import__("os").system("id")\n')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].matched_pattern, "dynamic_import")
        self.assertEqual(findings[0].severity, "high")

    def test_comment_not_detected(self):
        findings = _scan(self.tmp, "# exec(base64.b64decode('x'))\nx = 1\n")
        self.assertEqual(findings, [])

    def test_line_number_correct(self):
        findings = _scan(self.tmp, "x = 1\nexec(base64.b64decode(data))\n")
        self.assertEqual(findings[0].line_number, 2)

    def test_syntax_error_no_crash(self):
        findings = _scan(self.tmp, "def broken(\n")
        self.assertEqual(findings, [])

    def test_nested_decode_detected(self):
        findings = _scan(self.tmp, "exec(zlib.decompress(base64.b64decode(payload)))\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].matched_pattern, "exec_encoded_payload")


if __name__ == "__main__":
    unittest.main()
