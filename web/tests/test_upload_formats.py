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

    # scanner.create_scan(data, filename, llm_enabled, llm_provider, llm_mode, llm_model,
    #   llm_api_key, assessment_enabled, ios_light, decompiler, ci_pipeline_url, ci_commit_sha,
    #   ci_triggered_by) — decompiler is index 9. Pinned by name here (not args[-1]) so adding a
    # new trailing positional parameter (e.g. the ci_* fields) doesn't silently break this.
    DECOMPILER_ARG_INDEX = 9

    def test_decompiler_defaults_to_jadx_and_accepts_asc(self):
        for value in ("jadx", "asc"):
            self.create.reset_mock()
            r = self.client.post("/api/v1/scans", files={"file": ("a.apk", b"PK\x03\x04data")},
                                 data={"llm_provider": "none", "decompiler": value})
            self.assertEqual(r.status_code, 202, value)
            self.assertEqual(self.create.await_args.args[self.DECOMPILER_ARG_INDEX], value)
        # omitted entirely -> jadx default
        self.create.reset_mock()
        r = self.client.post("/api/v1/scans", files={"file": ("a.apk", b"PK\x03\x04data")},
                             data={"llm_provider": "none"})
        self.assertEqual(r.status_code, 202)
        self.assertEqual(self.create.await_args.args[self.DECOMPILER_ARG_INDEX], "jadx")

    def test_decompiler_rejects_unknown_values(self):
        r = self.client.post("/api/v1/scans", files={"file": ("a.apk", b"PK\x03\x04data")},
                             data={"llm_provider": "none", "decompiler": "ghidra"})
        self.assertEqual(r.status_code, 422)
        self.create.assert_not_awaited()

    def test_the_ui_offers_and_checks_the_same_formats(self):
        html = (Path(main.__file__).parent.parent / "index.html").read_text()
        self.assertIn('accept=".ipa,.apk,.xapk"', html)
        self.assertIn("n.endsWith('.xapk')", html)
        self.assertEqual(main._ACCEPTED_EXTENSIONS, (".ipa", ".apk", ".xapk"))

    # scanner.create_scan's trailing three positional args, in order.
    CI_ARG_INDICES = (10, 11, 12)  # ci_pipeline_url, ci_commit_sha, ci_triggered_by

    def test_ci_metadata_is_passed_through_when_supplied(self):
        r = self.client.post("/api/v1/scans", files={"file": ("a.apk", b"PK\x03\x04data")},
                             data={"llm_provider": "none",
                                   "ci_pipeline_url": "https://bitbucket.org/org/repo/pipelines/results/42",
                                   "ci_commit_sha": "abc1234",
                                   "ci_triggered_by": "malimite-ci/0.1"})
        self.assertEqual(r.status_code, 202)
        got = [self.create.await_args.args[i] for i in self.CI_ARG_INDICES]
        self.assertEqual(got, ["https://bitbucket.org/org/repo/pipelines/results/42",
                               "abc1234", "malimite-ci/0.1"])

    def test_ci_metadata_defaults_to_none_when_omitted(self):
        r = self.client.post("/api/v1/scans", files={"file": ("a.apk", b"PK\x03\x04data")},
                             data={"llm_provider": "none"})
        self.assertEqual(r.status_code, 202)
        got = [self.create.await_args.args[i] for i in self.CI_ARG_INDICES]
        self.assertEqual(got, [None, None, None])


class CiMetadataPersistenceTests(unittest.IsolatedAsyncioTestCase):
    """scanner.create_scan() itself: blank strings normalize to None, non-blank survive, and
    scan_mode omission (pre-existing meta.json files from before this feature) reads back as
    None via Pydantic defaults rather than raising."""

    async def test_blank_ci_fields_normalize_to_none(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner, "_run", AsyncMock()):
            meta = await scanner.create_scan(
                b"PK\x03\x04", "a.apk", False, "none", "summarize", "",
                ci_pipeline_url="   ", ci_commit_sha="", ci_triggered_by=None)
        self.assertIsNone(meta.ci_pipeline_url)
        self.assertIsNone(meta.ci_commit_sha)
        self.assertIsNone(meta.ci_triggered_by)

    async def test_non_blank_ci_fields_survive_to_meta_json(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner, "_run", AsyncMock()):
            meta = await scanner.create_scan(
                b"PK\x03\x04", "a.apk", False, "none", "summarize", "",
                ci_pipeline_url="https://ci.example/build/1", ci_commit_sha="deadbeef",
                ci_triggered_by="jenkins")
            detail = scanner.get_scan_detail(meta.scan_id)
        self.assertEqual(detail.ci_pipeline_url, "https://ci.example/build/1")
        self.assertEqual(detail.ci_commit_sha, "deadbeef")
        self.assertEqual(detail.ci_triggered_by, "jenkins")

    async def test_scan_with_no_ci_metadata_at_all_still_has_none_fields(self):
        """Manual upload (the common case) never sets these — a scan created without them
        must read back as None, not raise or omit the keys."""
        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner, "_run", AsyncMock()):
            meta = await scanner.create_scan(b"PK\x03\x04", "a.apk", False, "none", "summarize", "")
            detail = scanner.get_scan_detail(meta.scan_id)
        self.assertIsNone(detail.ci_pipeline_url)
        self.assertIsNone(detail.ci_commit_sha)
        self.assertIsNone(detail.ci_triggered_by)


if __name__ == "__main__":
    unittest.main()
