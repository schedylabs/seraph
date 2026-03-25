import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import seraph.scanners.persistence as mod
from seraph.scanners.persistence import PersistenceScanner, _ARTIFACTS


class TestPersistenceScanner(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_no_artifacts_clean(self):
        with patch.object(Path, "exists", return_value=False):
            result = PersistenceScanner().run()
        self.assertTrue(result.is_clean)

    def test_artifact_detected(self):
        artifact = self.tmp / "sysmon.py"
        artifact.write_text("backdoor")
        original = mod._ARTIFACTS
        try:
            mod._ARTIFACTS = (artifact,)
            findings = list(PersistenceScanner()._check())
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "critical")
            self.assertEqual(findings[0].matched_pattern, artifact.name)
        finally:
            mod._ARTIFACTS = original

    def test_scanned_list_length(self):
        result = PersistenceScanner().run()
        self.assertEqual(len(result.scanned), len(_ARTIFACTS))


if __name__ == "__main__":
    unittest.main()
