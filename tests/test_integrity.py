import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from schedy_seraph.scanners.integrity import IntegrityScanner


def _dist(record: str, tmp: Path):
    dist = MagicMock()
    dist.read_text.return_value = record
    dist.locate_file.side_effect = lambda p: tmp / p
    return dist


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


class TestIntegrityScanner(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_clean_file_no_findings(self):
        f = self.tmp / "mod.py"
        f.write_text("x = 1\n")
        record = f"mod.py,sha256:{_b64(f.read_bytes())},{f.stat().st_size}\n"
        findings = list(IntegrityScanner()._check_dist(_dist(record, self.tmp), []))
        self.assertEqual(findings, [])

    def test_tampered_file_detected(self):
        f = self.tmp / "mod.py"
        original = b"x = 1\n"
        f.write_bytes(original)
        record = f"mod.py,sha256:{_b64(original)},{len(original)}\n"
        f.write_text("x = 1\nimport os; os.system('id')\n")
        findings = list(IntegrityScanner()._check_dist(_dist(record, self.tmp), []))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].matched_pattern, "hash_mismatch")
        self.assertEqual(findings[0].severity, "critical")

    def test_missing_record_skipped(self):
        dist = MagicMock()
        dist.read_text.return_value = None
        findings = list(IntegrityScanner()._check_dist(dist, []))
        self.assertEqual(findings, [])

    def test_row_without_hash_skipped(self):
        f = self.tmp / "mod.py"
        f.write_text("x = 1\n")
        record = "mod.py,,6\n"
        findings = list(IntegrityScanner()._check_dist(_dist(record, self.tmp), []))
        self.assertEqual(findings, [])

    def test_malformed_base64_no_crash(self):
        f = self.tmp / "mod.py"
        f.write_text("x = 1\n")
        record = "mod.py,sha256:!!!notbase64!!!,6\n"
        findings = list(IntegrityScanner()._check_dist(_dist(record, self.tmp), []))
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
