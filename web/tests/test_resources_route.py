import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from web.app import main

SCHEMA = "CREATE TABLE ResourceStrings(id INTEGER PRIMARY KEY, resourceId TEXT, value TEXT, type TEXT);"


class ResourcesRouteTests(unittest.TestCase):
    """GET /resources: the original flat response is unchanged for callers that don't ask for a
    page (e.g. the raw API link on the Downloads tab); passing `page` switches to the paginated
    shape the Resources tab's pagination (and the Vulnerabilities tab's "View in Resources" link,
    which searches by the exact evidence text) depends on."""

    def setUp(self):
        h = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        h.close()
        self.path = h.name
        c = sqlite3.connect(self.path)
        c.executescript(SCHEMA)
        rows = [("AllowBackup", "AllowBackup=true", "manifest"),
               ("Debuggable", "Debuggable=false", "manifest")]
        rows += [("Permission", f"Permission=android.permission.P{i}", "manifest-permission") for i in range(15)]
        c.executemany("INSERT INTO ResourceStrings(resourceId,value,type) VALUES (?,?,?)", rows)
        c.commit()
        c.close()
        self.patches = [patch.object(main, "_require_db", return_value=(self.path, "app")),
                        patch.object(main.settings, "api_key", "")]
        for p in self.patches:
            p.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        Path(self.path).unlink(missing_ok=True)

    def test_without_page_returns_the_original_flat_list(self):
        r = self.client.get("/api/v1/scans/s1/resources")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 17)

    def test_paginated_response_shape_and_math(self):
        r = self.client.get("/api/v1/scans/s1/resources", params={"page": 1, "size": 10})
        d = r.json()
        self.assertEqual(d["total"], 17)
        self.assertEqual(d["page"], 1)
        self.assertEqual(d["pages"], 2)
        self.assertEqual(len(d["items"]), 10)
        self.assertIn("manifest-permission", d["type_counts"])
        self.assertEqual(d["type_counts"]["manifest-permission"], 15)

    def test_second_page_has_the_remainder(self):
        r = self.client.get("/api/v1/scans/s1/resources", params={"page": 2, "size": 10})
        self.assertEqual(len(r.json()["items"]), 7)

    def test_search_finds_the_exact_evidence_value(self):
        # This is exactly what the Vulnerabilities tab's "View in Resources" link does: search by
        # the finding's `evidence` text, which VulnerabilityScanner sets to the matched
        # ResourceStrings.value verbatim for short values.
        r = self.client.get("/api/v1/scans/s1/resources",
                            params={"page": 1, "size": 10, "q": "AllowBackup=true"})
        d = r.json()
        self.assertEqual(d["total"], 1)
        self.assertEqual(d["items"][0]["value"], "AllowBackup=true")

    def test_type_filter(self):
        r = self.client.get("/api/v1/scans/s1/resources",
                            params={"page": 1, "size": 50, "type": "manifest"})
        d = r.json()
        self.assertEqual(d["total"], 2)
        self.assertTrue(all(it["type"] == "manifest" for it in d["items"]))


if __name__ == "__main__":
    unittest.main()