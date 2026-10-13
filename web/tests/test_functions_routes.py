import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from web.app import main, scanner
from web.app.agent import ondemand
from web.app.models import ScanDetail

SCHEMA = """
CREATE TABLE Classes(ClassName TEXT, Functions TEXT, ExecutableName TEXT);
CREATE TABLE Functions(FunctionName TEXT, ParentClass TEXT, DecompilationCode TEXT,
                       ExecutableName TEXT, Origin TEXT DEFAULT 'GHIDRA');
"""


class FunctionsRoutesTests(unittest.TestCase):
    """The three read-only routes backing the Functions tab's tree + viewer. Real SQLite data
    (not mocked), since these routes just pass through to db.py's existing query functions."""

    def setUp(self):
        h = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        h.close()
        self.path = h.name
        c = sqlite3.connect(self.path)
        c.executescript(SCHEMA)
        c.executemany("INSERT INTO Classes VALUES (?,?,?)", [
            ("com.a.Crypto", '["<class>","enc"]', "app"),
            ("com.other.X", '["<class>"]', "other")])
        c.executemany("INSERT INTO Functions VALUES (?,?,?,?,?)", [
            ("<class>", "com.a.Crypto", "class Crypto { Cipher.getInstance(\"DES\"); }", "app", "JADX"),
            ("enc", "com.a.Crypto", "void enc() { DES }", "app", "JADX"),
            ("<class>", "com.other.X", "DES elsewhere", "other", "JADX")])
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

    def test_classes_lists_names_and_method_counts(self):
        r = self.client.get("/api/v1/scans/s1/classes")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [{"class": "com.a.Crypto", "methods": 2}])

    def test_classes_substring_filter(self):
        r = self.client.get("/api/v1/scans/s1/classes", params={"query": "nomatch"})
        self.assertEqual(r.json(), [])

    def test_classes_returns_more_than_the_agent_tools_200row_cap(self):
        # Regression: db.list_classes clamps `limit` to a `cap` (default 200, sized for the chat
        # agent). The Functions tab tree needs every class at once — found via a real Krom scan
        # (30k+ classes) silently truncating to 200 before this route raised its cap.
        c = sqlite3.connect(self.path)
        c.executemany("INSERT INTO Classes VALUES (?,?,?)",
                      [(f"com.many.C{i:04d}", "[]", "app") for i in range(250)])
        c.commit()
        c.close()
        r = self.client.get("/api/v1/scans/s1/classes")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()), 251)  # 250 new + the one from setUp

    def test_source_whole_class(self):
        r = self.client.get("/api/v1/scans/s1/source", params={"class_name": "com.a.Crypto"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["function"], "<class>")
        self.assertIn("DES", body[0]["code"])

    def test_source_one_function(self):
        r = self.client.get("/api/v1/scans/s1/source",
                            params={"class_name": "com.a.Crypto", "function_name": "enc"})
        self.assertEqual(r.json()[0]["function"], "enc")

    def test_source_unknown_class_returns_empty_list(self):
        r = self.client.get("/api/v1/scans/s1/source", params={"class_name": "nope.Nothing"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [])

    def test_code_search_matches_decompiled_code(self):
        r = self.client.get("/api/v1/scans/s1/code-search", params={"q": "DES"})
        self.assertEqual(r.status_code, 200)
        classes = {row["class"] for row in r.json()}
        self.assertEqual(classes, {"com.a.Crypto"})  # scoped to ExecutableName 'app', not 'other'

    def test_routes_404_when_scan_not_found(self):
        with patch.object(main, "_require_db", side_effect=main.HTTPException(status_code=404, detail="x")):
            self.assertEqual(self.client.get("/api/v1/scans/missing/classes").status_code, 404)
            self.assertEqual(self.client.get("/api/v1/scans/missing/source",
                                             params={"class_name": "a"}).status_code, 404)
            self.assertEqual(self.client.get("/api/v1/scans/missing/code-search",
                                             params={"q": "a"}).status_code, 404)

    def test_vendor_static_files_are_served(self):
        r = self.client.get("/vendor/hljs/highlight.min.js")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"hljs", r.content[:200])


def _fake_cmd(code):
    """Same trick as test_agent_ondemand.py: stand in for the real `java -cp cli.jar ...` argv so
    the actual subprocess/semaphore/timeout machinery in ondemand.decompile runs for real, just
    against a tiny Python script instead of a real decompiler."""
    return lambda *a, **k: [sys.executable, "-c", code]


class DecompileRouteTests(unittest.TestCase):
    """POST /decompile: Android-only asc/jadx on-demand decompile, sharing ondemand.decompile's
    real subprocess path (mocked at the argv level, not the route level) and the chat.sqlite cache."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        detail = ScanDetail(scan_id="s1", filename="a.apk", state="done", created_at="t",
                            llm_provider="none", platform="ANDROID")
        self.patches = [
            patch.object(main, "_require_db", return_value=("/nope", "app")),
            patch.object(scanner, "get_scan_detail", return_value=detail),
            patch.object(scanner, "_scan_dir", return_value=Path(self.tmp.name)),
            patch.object(main.settings, "api_key", ""),
        ]
        for p in self.patches:
            p.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_decompiles_and_then_serves_from_cache(self):
        with patch.object(ondemand, "_cmd", _fake_cmd("print('{\"ok\": true, \"code\": \"class X {}\"}')")):
            r1 = self.client.post("/api/v1/scans/s1/decompile", json={"tool": "jadx", "target": "com.a.X"})
        self.assertEqual(r1.status_code, 200)
        body = r1.json()
        self.assertEqual(body, {"tool": "jadx", "target": "com.a.X", "code": "class X {}", "cached": False})

        # Second call must not need ondemand at all: patch _cmd to blow up if it's ever invoked.
        def boom(*a, **k):
            raise AssertionError("ondemand.decompile should not run again for a cached target")
        with patch.object(ondemand, "_cmd", boom):
            r2 = self.client.post("/api/v1/scans/s1/decompile", json={"tool": "jadx", "target": "com.a.X"})
        self.assertEqual(r2.status_code, 200)
        self.assertTrue(r2.json()["cached"])

    def test_ghidra_tool_rejected(self):
        r = self.client.post("/api/v1/scans/s1/decompile", json={"tool": "ghidra", "target": "0x1000"})
        self.assertEqual(r.status_code, 422)

    def test_ios_platform_rejected(self):
        with patch.object(scanner, "get_scan_detail",
                          return_value=ScanDetail(scan_id="s1", filename="a.ipa", state="done",
                                                  created_at="t", llm_provider="none", platform="IOS")):
            r = self.client.post("/api/v1/scans/s1/decompile", json={"tool": "jadx", "target": "com.a.X"})
        self.assertEqual(r.status_code, 422)

    def test_invalid_class_name_rejected_before_touching_a_subprocess(self):
        def boom(*a, **k):
            raise AssertionError("invalid input must be rejected before any subprocess is spawned")
        with patch.object(ondemand, "_cmd", boom):
            r = self.client.post("/api/v1/scans/s1/decompile", json={"tool": "jadx", "target": "; rm -rf /"})
        self.assertEqual(r.status_code, 422)

    def test_decompile_failure_becomes_502(self):
        with patch.object(ondemand, "_cmd", _fake_cmd("import sys; print('boom', file=sys.stderr); sys.exit(1)")):
            r = self.client.post("/api/v1/scans/s1/decompile", json={"tool": "asc", "target": "com.a.Y"})
        self.assertEqual(r.status_code, 502)


if __name__ == "__main__":
    unittest.main()
