"""The empty_result flag: a scan that finished but stored nothing must not read as "clean"."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from web.app import main
from web.app.models import ScanDetail


def _detail(**kw):
    base = dict(scan_id="s1", filename="a.apk", state="done", created_at="2026-01-01T00:00:00+00:00",
                db_path="/tmp/x.sqlite", bundle_executable="a")
    base.update(kw)
    return ScanDetail(**base)


def _counts(classes=0, functions=0, strings=0, entry=0):
    return {"class_count": classes, "function_count": functions, "string_count": strings,
            "entry_point_count": entry, "llm_finding_count": 0}


class EmptyResultTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)

    def _get(self, detail, counts):
        with patch.object(main.settings, "api_key", ""), \
             patch.object(main.scanner, "get_scan_detail", return_value=detail), \
             patch.object(main.Path, "exists", return_value=True), \
             patch.object(main.db, "get_counts", AsyncMock(return_value=counts)), \
             patch.object(main.db, "get_vulnerability_counts", AsyncMock(return_value={"total": 0})):
            return self.client.get("/api/v1/scans/s1")

    def test_zero_everything_marks_the_scan_empty(self):
        r = self._get(_detail(), _counts())
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["empty_result"])

    def test_any_stored_class_means_not_empty(self):
        r = self._get(_detail(), _counts(classes=6))
        self.assertFalse(r.json()["empty_result"])

    def test_strings_alone_are_enough(self):
        r = self._get(_detail(), _counts(strings=12))
        self.assertFalse(r.json()["empty_result"])

    def test_entry_points_alone_are_enough(self):
        r = self._get(_detail(), _counts(entry=3))
        self.assertFalse(r.json()["empty_result"])

    def test_running_scan_is_never_flagged(self):
        r = self._get(_detail(state="running"), _counts())
        self.assertFalse(r.json()["empty_result"])

    def test_failed_scan_is_not_double_labelled(self):
        r = self._get(_detail(state="error"), _counts())
        self.assertFalse(r.json()["empty_result"])

    def test_missing_database_stays_unknown(self):
        detail = _detail()
        with patch.object(main.settings, "api_key", ""), \
             patch.object(main.scanner, "get_scan_detail", return_value=detail), \
             patch.object(main.Path, "exists", return_value=False), \
             patch.object(main.db, "get_counts", AsyncMock()) as counts:
            r = self.client.get("/api/v1/scans/s1")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["empty_result"], "no DB read means no verdict")
        counts.assert_not_awaited()

    def test_count_query_failure_stays_unknown(self):
        with patch.object(main.settings, "api_key", ""), \
             patch.object(main.scanner, "get_scan_detail", return_value=_detail()), \
             patch.object(main.Path, "exists", return_value=True), \
             patch.object(main.db, "get_counts", AsyncMock(side_effect=RuntimeError("db gone"))):
            r = self.client.get("/api/v1/scans/s1")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["empty_result"])

    def test_default_is_false_so_old_callers_keep_working(self):
        self.assertFalse(ScanDetail(scan_id="s", filename="f", state="done", created_at="x").empty_result)


if __name__ == "__main__":
    unittest.main()
