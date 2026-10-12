import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from web.app import main, scanner
from web.app.models import ScanMeta


class StoredFileNameTests(unittest.IsolatedAsyncioTestCase):
    """The CLI decides what to do from the extension, so the upload must keep it."""

    async def test_extension_is_preserved_for_every_accepted_format(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner, "_run", AsyncMock()):
            for filename, stored in [("Bank.xapk", "upload.xapk"), ("BANK.XAPK", "upload.xapk"), ("a.apk", "upload.apk"),
                                     ("A.APK", "upload.apk"), ("b.ipa", "upload.ipa")]:
                meta = await scanner.create_scan(b"PK\x03\x04", filename, False, "none", "summarize", "")
                self.assertTrue((Path(d) / meta.scan_id / stored).exists(), f"{filename} -> {stored}")


class UploadRouteTests(unittest.TestCase):
    def setUp(self):
        self.meta = ScanMeta(scan_id="s", filename="x", state="queued", created_at="t")
        self.create = AsyncMock(return_value=self.meta)
        self.patches = [patch.object(scanner, "create_scan", self.create), patch.object(main.settings, "api_key", "")]
        for p in self.patches:
            p.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def post(self, name, data=b"PK\x03\x04data"):
        return self.client.post("/api/v1/scans", files={"file": (name, data)}, data={"llm_provider": "none"})

    def test_xapk_is_accepted_like_apk_and_ipa(self):
        for name in ("bank.xapk", "BANK.XAPK", "a.apk", "b.ipa"):
            self.create.reset_mock()
            r = self.post(name)
            self.assertEqual(r.status_code, 202, name)
            self.assertEqual(self.create.await_args.args[1], name)

    def test_other_formats_are_refused_with_a_message_that_names_xapk(self):
        for name in ("a.zip", "a.xapk.exe", "xapk", "a.aab"):
            r = self.post(name)
            self.assertEqual(r.status_code, 400, name)
            self.assertIn(".xapk", r.json()["detail"])
        self.create.assert_not_awaited()

    def test_empty_xapk_is_refused(self):
        self.assertEqual(self.post("a.xapk", b"").status_code, 400)

    def test_the_ui_offers_and_checks_the_same_formats(self):
        html = (Path(main.__file__).parent.parent / "index.html").read_text()
        self.assertIn('accept=".ipa,.apk,.xapk"', html)
        self.assertIn("n.endsWith('.xapk')", html)
        self.assertEqual(main._ACCEPTED_EXTENSIONS, (".ipa", ".apk", ".xapk"))


if __name__ == "__main__":
    unittest.main()
