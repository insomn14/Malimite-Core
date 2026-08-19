import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from web.app import scanner


class LegacyScanPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scan_root = Path(self.tmp.name) / "malimite-scans"
        self.scan_id = "5ab1d2ef-a53c-4553-8223-690c4f240ddb"
        self.scan_dir = self.scan_root / self.scan_id
        self.scan_dir.mkdir(parents=True)
        self.sqlite = self.scan_dir / "51521775-a173-4eca-af6a-d8c18f7adebf.sqlite"
        self.sqlite.write_text("")
        (self.scan_dir / "upload.ipa").write_bytes(b"ipa")
        self._scan_dir_patch = patch.object(scanner.settings, "scan_dir", self.scan_root)
        self._scan_dir_patch.start()

    def tearDown(self):
        self._scan_dir_patch.stop()
        self.tmp.cleanup()

    def test_rewrites_mailmite_db_and_ipa_paths(self):
        stale = {
            "bundleExecutable": "Captain Nohook",
            "dbPath": f"/tmp/mailmite-scans/{self.scan_id}/{self.sqlite.name}",
            "ipaPath": f"/tmp/mailmite-scans/{self.scan_id}/upload.ipa",
        }
        (self.scan_dir / "scan.json").write_text(json.dumps(stale))

        data = scanner._read_scan_json(self.scan_id)

        self.assertEqual(Path(data["dbPath"]).resolve(), self.sqlite.resolve())
        self.assertTrue(Path(data["dbPath"]).exists())
        self.assertTrue(Path(data["ipaPath"]).exists())
        persisted = json.loads((self.scan_dir / "scan.json").read_text())
        self.assertTrue(Path(persisted["dbPath"]).exists())
        self.assertNotIn("/tmp/mailmite-scans/", persisted["dbPath"])

    def test_discovers_sqlite_when_dbpath_missing(self):
        (self.scan_dir / "scan.json").write_text(json.dumps({
            "bundleExecutable": "App",
            "dbPath": "/tmp/mailmite-scans/missing/nope.sqlite",
        }))

        data = scanner._read_scan_json(self.scan_id)

        self.assertTrue(Path(data["dbPath"]).exists())
        self.assertEqual(Path(data["dbPath"]).name, self.sqlite.name)

    def test_rejects_path_outside_scan_dir(self):
        outside = Path(self.tmp.name) / "secret.sqlite"
        outside.write_text("nope")
        mapped = scanner._remap_legacy_path(str(outside), self.scan_dir)
        self.assertIsNone(mapped)
