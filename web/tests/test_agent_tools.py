import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from web.app import db
from web.app.agent import tools
from web.app.agent.tools import Ctx

SCHEMA = """
CREATE TABLE Classes(ClassName TEXT, Functions TEXT, ExecutableName TEXT);
CREATE TABLE Functions(FunctionName TEXT, ParentClass TEXT, DecompilationCode TEXT,
                       ExecutableName TEXT, Origin TEXT DEFAULT 'GHIDRA');
CREATE TABLE MachoStrings(address TEXT, value TEXT, segment TEXT, label TEXT, ExecutableName TEXT);
CREATE TABLE EntryPoints(FunctionName TEXT, ClassName TEXT, ExecutableName TEXT);
CREATE TABLE LlmFindings(id INTEGER PRIMARY KEY, ExecutableName TEXT);
CREATE TABLE FunctionReferences(sourceFunction TEXT, sourceClass TEXT, targetFunction TEXT,
                                targetClass TEXT, lineNumber INTEGER, ExecutableName TEXT);
CREATE TABLE ResourceStrings(id INTEGER PRIMARY KEY, resourceId TEXT, value TEXT, type TEXT);
CREATE TABLE Vulnerabilities(id INTEGER PRIMARY KEY, RuleId TEXT, Title TEXT, Category TEXT, Severity TEXT,
  CvssScore REAL, Cwe TEXT, Description TEXT, AffectedType TEXT, AffectedName TEXT, Evidence TEXT,
  EvidenceLocation TEXT, PocSteps TEXT, Remediation TEXT, ReferenceUrl TEXT, ExecutableName TEXT);
"""


class ToolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        h = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        h.close()
        self.path = h.name
        c = sqlite3.connect(self.path)
        c.executescript(SCHEMA)
        c.executemany("INSERT INTO Classes VALUES (?,?,?)", [
            ("com.a.Crypto", '["<class>","enc"]', "app"), ("com.a.Net", '["<class>"]', "app"),
            ("com.other.X", '["<class>"]', "other")])
        c.executemany("INSERT INTO Functions VALUES (?,?,?,?,?)", [
            ("<class>", "com.a.Crypto", "class Crypto { Cipher.getInstance(\"DES\"); }", "app", "JADX"),
            ("enc", "com.a.Crypto", "void enc() { DES }", "app", "JADX"),
            ("<class>", "com.a.Net", "class Net { }" + "x" * 50, "app", "JADX"),
            ("<class>", "com.other.X", "DES elsewhere", "other", "JADX")])
        c.execute("INSERT INTO MachoStrings VALUES ('1','http://evil.test/%a_b','__JADX','Net','app')")
        c.executemany("INSERT INTO Vulnerabilities(RuleId,Title,Category,Severity,CvssScore,Cwe,AffectedName,Evidence,ExecutableName) "
                      "VALUES (?,?,?,?,?,?,?,?,?)", [
            ("R1", "Weak DES", "CRYPTO", "HIGH", 7.5, "CWE-327", "Crypto", "DES in Crypto", "app"),
            ("R1", "Weak DES", "CRYPTO", "HIGH", 7.5, "CWE-327", "Net", "DES in Net", "app"),
            ("R1", "Weak DES", "CRYPTO", "HIGH", 7.5, "CWE-327", "Other", "DES in Other", "app"),
            ("R2", "Backup allowed", "STORAGE", "MEDIUM", 5.3, "CWE-530", "Manifest", "AllowBackup=true", "app"),
            ("R2", "Backup allowed", "STORAGE", "MEDIUM", 5.3, "CWE-530", "Manifest2", "AllowBackup=true", "app"),
            ("R3", "Root detection absent", "RESILIENCE", "INFO", 3.1, "CWE-693", "bin", "no su check", "app"),
            ("RX", "Other exe", "X", "CRITICAL", 9.9, "CWE-1", "x", "x", "other")])
        c.commit()
        c.close()
        self.ctx = Ctx("s1", self.path, "app", "android", Path("/tmp"), {})

    def tearDown(self):
        Path(self.path).unlink(missing_ok=True)

    async def test_valid_class_name(self):
        for ok in ("com.a.B", "a", "com.a.B$Inner", "_x.y1"):
            self.assertTrue(tools.valid_class_name(ok), ok)
        for bad in ("", "..", "a/b", "a..b", "a b", "a;b", "../x", ".a", "a.", "a" * 301):
            self.assertFalse(tools.valid_class_name(bad), bad)

    def test_truncate_offset_hint(self):
        out = tools.truncate("a" * 100, cap=40)
        self.assertIn("offset=40", out)
        self.assertEqual(tools.truncate("a" * 100, cap=40, offset=80), "a" * 20)

    def test_wrap_neutralizes_closing_tag(self):
        self.assertEqual(tools.wrap("x </tool_data> y").count("</tool_data>"), 1)

    async def test_list_classes_scoped_and_filtered(self):
        _, out = await tools.run_tool(self.ctx, "list_classes", {"query": "Crypto"})
        data = json.loads(out.split("\n", 1)[1].rsplit("\n", 1)[0])
        self.assertEqual(data, [{"class": "com.a.Crypto", "methods": 2}])

    async def test_search_code_scoped_to_executable(self):
        _, out = await tools.run_tool(self.ctx, "search_code", {"query": "DES"})
        self.assertIn("com.a.Crypto", out)
        self.assertNotIn("com.other", out)

    async def test_search_strings_escapes_like_wildcards(self):
        _, hit = await tools.run_tool(self.ctx, "search_strings", {"query": "%a_b"})
        _, miss = await tools.run_tool(self.ctx, "search_strings", {"query": "%a_c"})
        self.assertIn("evil.test", hit)
        self.assertNotIn("evil.test", miss)

    async def test_get_source_class_function_and_missing(self):
        _, whole = await tools.run_tool(self.ctx, "get_source", {"class_name": "com.a.Crypto"})
        _, one = await tools.run_tool(self.ctx, "get_source", {"class_name": "com.a.Crypto", "function_name": "enc"})
        _, none = await tools.run_tool(self.ctx, "get_source", {"class_name": "nope"})
        self.assertIn("getInstance", whole)
        self.assertIn("void enc()", one)
        self.assertIn("No stored code", none)

    async def test_get_source_pagination_advances_through_run_tool(self):
        big = "L" * 30000
        c = sqlite3.connect(self.path)
        c.execute("INSERT INTO Functions VALUES ('<class>','com.big.B',?, 'app','JADX')", (big,))
        c.commit(); c.close()
        seen, offset = 0, 0
        for _ in range(10):
            _, out = await tools.run_tool(self.ctx, "get_source", {"class_name": "com.big.B", "offset": offset})
            seen += out.count("L")
            hint = out.split("offset=")
            if len(hint) == 1:
                break
            nxt = int(hint[1].split("]")[0])
            self.assertGreater(nxt, offset, "hint must move forward, not repeat the same page")
            offset = nxt
        self.assertEqual(seen, 30000)

    async def test_non_paged_tool_overflow_is_capped_without_bogus_offset_hint(self):
        c = sqlite3.connect(self.path)
        c.executemany("INSERT INTO MachoStrings VALUES (?,?,?,?,?)",
                      [(str(i), "needle " + "z" * 300, "s", "l", "app") for i in range(100)])
        c.commit(); c.close()
        _, out = await tools.run_tool(self.ctx, "search_strings", {"query": "needle", "limit": 100})
        self.assertIn("narrow the query", out)
        self.assertNotIn("offset=", out)

    async def test_vulnerabilities_read_never_alters_scan_db(self):
        def cols():
            c = sqlite3.connect(self.path)
            try:
                return c.execute("PRAGMA table_info(Vulnerabilities)").fetchall()
            finally:
                c.close()
        before = cols()
        await tools.run_tool(self.ctx, "get_vulnerabilities", {})
        await tools.run_tool(self.ctx, "scan_overview", {})
        after = cols()
        self.assertEqual(before, after, "assistant must not add triage columns to the scan DB")

    async def test_ro_open_handles_odd_paths(self):
        d = Path(tempfile.mkdtemp()) / "we ird#dir%20?x"
        d.mkdir()
        p = d / "s c#a%n?.sqlite"
        c = sqlite3.connect(p); c.execute("CREATE TABLE T(a)"); c.commit(); c.close()
        async with db._ro(str(p)) as conn:
            async with conn.execute("SELECT count(*) FROM T") as cur:
                self.assertEqual((await cur.fetchone())[0], 0)

    async def test_get_references_reports_missing_call_graph(self):
        _, out = await tools.run_tool(self.ctx, "get_references", {"function": "enc", "direction": "callers"})
        self.assertIn("No call graph", out)

    async def test_overview_and_vulns(self):
        _, ov = await tools.run_tool(self.ctx, "scan_overview", {})
        self.assertIn('"call_graph_available": false', ov)
        self.assertIn('"HIGH": 1', ov)
        self.assertIn('"unique_issues": 3', ov)   # same as the Vulnerabilities tab: grouped per rule_id ...
        self.assertIn('"occurrences": 6', ov)     # ... with the raw row count reported separately
        self.assertNotIn("CRITICAL", ov)          # other executable's finding must not leak in
        _, v = await tools.run_tool(self.ctx, "get_vulnerabilities", {"severity": "high"})
        self.assertIn("Weak DES", v)

    async def test_vulnerabilities_are_grouped_like_the_ui(self):
        _, out = await tools.run_tool(self.ctx, "get_vulnerabilities", {})
        data = json.loads(out.split("\n", 1)[1].rsplit("\n", 1)[0])
        self.assertEqual(data["unique_issues"], 3)
        by = {i["rule_id"]: i for i in data["issues"]}
        self.assertEqual((by["R1"]["hits"], by["R1"]["severity"], by["R1"]["cvss"]), (3, "HIGH", 7.5))
        self.assertEqual(by["R2"]["hits"], 2)
        self.assertEqual([i["rule_id"] for i in data["issues"]], ["R1", "R2", "R3"])  # severity order
        _, one = await tools.run_tool(self.ctx, "get_vulnerabilities", {"rule_id": "R1"})
        d1 = json.loads(one.split("\n", 1)[1].rsplit("\n", 1)[0])
        self.assertEqual(len(d1["issues"][0]["evidence"]), 3)  # rule_id => every occurrence listed

    def test_group_issues_respects_triage_overrides_and_suppression(self):
        row = lambda **k: {"rule_id": "A", "title": "t", "category": "c", "severity": "MEDIUM", "cvss": 5.0,  # noqa: E731
                           "cwe": None, "affected_name": "n", "evidence": "e", "status": "open",
                           "override_severity": None, "override_cvss": None, **k}
        g = db.group_issues([row(override_severity="LOW", override_cvss=2.0), row(status="open")])
        self.assertEqual((g[0]["severity"], g[0]["hits"]), ("MEDIUM", 2))  # most severe active occurrence represents the issue
        g = db.group_issues([row(status="false_positive"), row(rule_id="B", severity="HIGH")])
        self.assertEqual([x["rule_id"] for x in g], ["B", "A"])  # suppressed issues sort last
        g = db.group_issues([row(override_severity="LOW", override_cvss=2.0)])
        self.assertEqual((g[0]["severity"], g[0]["cvss"]), ("LOW", 2.0))

    async def test_errors_become_text_not_exceptions(self):
        ok, out = await tools.run_tool(self.ctx, "search_code", {})
        self.assertFalse(ok)
        self.assertIn("missing required argument", out)
        ok, out = await tools.run_tool(self.ctx, "rm_rf", {})
        self.assertFalse(ok)

    async def test_scan_db_is_opened_read_only(self):
        with self.assertRaises(Exception):
            async with db._ro(self.path) as c:
                await c.execute("DELETE FROM Functions")
                await c.commit()




class AssessmentAndManifestToolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        h = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        h.close()
        self.path = h.name
        self.c = sqlite3.connect(self.path)
        self.c.executescript(SCHEMA)

    def tearDown(self):
        self.c.close()
        Path(self.path).unlink(missing_ok=True)

    def ctx(self, platform="android", meta=None):
        self.c.commit()
        return Ctx("s", self.path, "app", platform, Path("/tmp"), meta or {})

    def add_assessments(self, rows):
        self.c.execute("""CREATE TABLE Assessments(id INTEGER PRIMARY KEY, ControlId TEXT, Title TEXT, Category TEXT,
                          Status TEXT, Confidence TEXT, Evidence TEXT, Detail TEXT, Platform TEXT, CreatedAt INTEGER,
                          ExecutableName TEXT)""")
        self.c.executemany("INSERT INTO Assessments(ControlId,Title,Category,Status,Confidence,Evidence,Detail,ExecutableName) "
                           "VALUES (?,?,?,?,?,?,?,'app')", rows)

    @staticmethod
    def body(out):
        return json.loads(out.split("\n", 1)[1].rsplit("\n", 1)[0])

    # ── get_assessments ───────────────────────────────────────────────────────

    async def test_assessments_are_ordered_filtered_and_counted(self):
        self.add_assessments([
            ("ASSESS-A", "Anti-debug", "DETECTION", "ABSENT", "MEDIUM", "No matching signals", ""),
            ("ASSESS-B", "PIE", "HARDENING", "PRESENT", "HIGH", "MH_PIE=1", ""),
            ("ASSESS-C", "Jailbreak", "DETECTION", "UNKNOWN", "LOW", "x" * 500, "signal=jb"),
        ])
        ok, out = await tools.run_tool(self.ctx("ios"), "get_assessments", {})
        d = self.body(out)
        self.assertTrue(ok)
        self.assertEqual(d["counts_all_controls"], {"ABSENT": 1, "PRESENT": 1, "UNKNOWN": 1})
        self.assertEqual([c["status"] for c in d["controls"]], ["PRESENT", "ABSENT", "UNKNOWN"])
        self.assertEqual(len(d["controls"][2]["evidence"]), 300, "evidence is capped")
        self.assertEqual(d["controls"][2]["detail"], "signal=jb")
        self.assertTrue(any("UNKNOWN" in n for n in d["notes"]), "the model is told UNKNOWN is not 'absent'")
        d = self.body((await tools.run_tool(self.ctx(), "get_assessments", {"status": "unknown"}))[1])
        self.assertEqual([c["id"] for c in d["controls"]], ["ASSESS-C"])
        self.assertEqual(sum(d["counts_all_controls"].values()), 3, "counts describe the whole inventory, not the filter")
        d = self.body((await tools.run_tool(self.ctx(), "get_assessments", {"category": "hardening"}))[1])
        self.assertEqual([c["id"] for c in d["controls"]], ["ASSESS-B"])

    async def test_vm_obfuscation_note_warns_against_calling_hidden_checks_absent(self):
        self.add_assessments([("ASSESS-VM-OBFUSCATION", "Bytecode VM", "OBFUSCATION", "PRESENT", "MEDIUM", "43 fns", "")])
        d = self.body((await tools.run_tool(self.ctx("ios"), "get_assessments", {}))[1])
        self.assertTrue(any("bytecode interpreter" in n for n in d["notes"]))

    async def test_scan_without_assessment_says_so_instead_of_returning_an_empty_inventory(self):
        ok, out = await tools.run_tool(self.ctx(), "get_assessments", {})   # no Assessments table at all
        self.assertTrue(ok)
        self.assertIn("no Security Assessment", out)
        self.assertIn("Do not conclude", out)

    async def test_assessments_never_touch_the_scan_db(self):
        self.add_assessments([("A", "t", "c", "ABSENT", "LOW", "e", "")])
        before = self.c.execute("PRAGMA schema_version").fetchone()
        self.c.commit()
        await tools.run_tool(self.ctx(), "get_assessments", {})
        self.assertEqual(before, self.c.execute("PRAGMA schema_version").fetchone())

    # ── get_manifest ──────────────────────────────────────────────────────────

    def add_android(self):
        rows = [("PackageName", "PackageName=com.x.app", "manifest"), ("Debuggable", "Debuggable=false", "manifest"),
                ("AllowBackup", "AllowBackup=true", "manifest"),
                ("Permission", "Permission=android.permission.CAMERA", "manifest-permission"),
                ("Permission", "Permission=android.permission.READ_CONTACTS", "manifest-permission")]
        rows += [("Component", f"activity com.x.A{i} exported={'true' if i == 3 else 'false'}", "manifest-component") for i in range(40)]
        rows += [("DeepLink", "DeepLink scheme=https host=x.example path=/a component=com.x.A3", "manifest-deeplink")]
        self.c.executemany("INSERT INTO ResourceStrings(resourceId,value,type) VALUES (?,?,?)", rows)
        self.c.execute("INSERT INTO EntryPoints VALUES ('activity:com.x.A3','com.x.A3','app')")

    async def test_android_overview_lists_sections_metadata_and_entry_points_without_paths(self):
        self.add_android()
        meta = {"platform": "ANDROID", "versionName": "1.2", "minSdk": 24, "dbPath": "/var/malimite/secret.sqlite",
                "packagePath": "/var/malimite/upload.apk", "isSwift": False, "bundleTeamId": None}
        ok, out = await tools.run_tool(self.ctx("android", meta), "get_manifest", {})
        d = self.body(out)
        self.assertEqual(d["metadata"], {"platform": "ANDROID", "versionName": "1.2", "minSdk": 24, "isSwift": False})
        self.assertNotIn("/var/malimite", out, "server paths must not reach the model")
        self.assertIn("AllowBackup=true", d["config"])
        self.assertEqual(d["sections"]["permissions"]["rows"], 2)
        self.assertEqual(d["sections"]["components"]["rows"], 40)
        self.assertEqual(d["entry_points"], ["activity:com.x.A3"], "not 'com.x.A3.activity:com.x.A3'")

    async def test_section_rows_are_readable_and_paged(self):
        self.add_android()
        d = self.body((await tools.run_tool(self.ctx(), "get_manifest", {"section": "components", "limit": 15}))[1])
        self.assertEqual((d["total_matching"], len(d["rows"]), d["next_offset"]), (40, 15, 15))
        self.assertTrue(d["rows"][0].startswith("activity com.x.A0 exported="), "the constant 'Component' label is dropped")
        last = self.body((await tools.run_tool(self.ctx(), "get_manifest",
                                               {"section": "components", "limit": 15, "offset": 30}))[1])
        self.assertEqual((len(last["rows"]), "next_offset" in last), (10, False))

    async def test_query_filters_and_escapes_like_wildcards(self):
        self.add_android()
        d = self.body((await tools.run_tool(self.ctx(), "get_manifest", {"section": "components", "query": "exported=true"}))[1])
        self.assertEqual(d["rows"], ["activity com.x.A3 exported=true"])
        d = self.body((await tools.run_tool(self.ctx(), "get_manifest", {"section": "permissions", "query": "%"}))[1])
        self.assertEqual(d["total_matching"], 0, "'%' is a literal, not a wildcard")

    async def test_unknown_section_lists_the_valid_ones_for_that_platform(self):
        ok, out = await tools.run_tool(self.ctx("android"), "get_manifest", {"section": "entitlements"})
        self.assertIn("unknown section 'entitlements'", out)
        self.assertIn("permissions", out)
        self.assertNotIn("info_plist", out)

    async def test_ios_sections_use_ios_data_and_shorten_plist_paths(self):
        self.c.executemany("INSERT INTO ResourceStrings(resourceId,value,type) VALUES (?,?,?)", [
            ("/tmp/x/Payload/App.app/Info.plist", "<key>UIMainStoryboardFile</key>", "plist"),
            ("/tmp/x/Payload/App.app/embedded.mobileprovision", "<key>get-task-allow</key>", "mobileprovision"),
            ("MachOSecurityFlags", "MH_PIE=1", "macho-flags")])
        ov = self.body((await tools.run_tool(self.ctx("ios", {"platform": "IOS", "bundleTeamId": "T1"}), "get_manifest", {}))[1])
        self.assertEqual(set(ov["sections"]), {"info_plist", "entitlements", "macho_flags", "nibs"})
        self.assertEqual(ov["metadata"]["bundleTeamId"], "T1")
        d = self.body((await tools.run_tool(self.ctx("ios"), "get_manifest", {"section": "info_plist"}))[1])
        self.assertEqual(d["rows"], ["App.app/Info.plist: <key>UIMainStoryboardFile</key>"])
        d = self.body((await tools.run_tool(self.ctx("ios"), "get_manifest", {"section": "entitlements", "query": "get-task-allow"}))[1])
        self.assertEqual(d["total_matching"], 1)
        d = self.body((await tools.run_tool(self.ctx("ios"), "get_manifest", {"section": "macho_flags"}))[1])
        self.assertEqual(d["rows"], ["MachOSecurityFlags=MH_PIE=1"])

    async def test_ios_entry_points_keep_class_and_selector(self):
        self.c.execute("INSERT INTO EntryPoints VALUES ('application:didFinishLaunchingWithOptions:','AppDelegate','app')")
        d = self.body((await tools.run_tool(self.ctx("ios"), "get_manifest", {}))[1])
        self.assertEqual(d["entry_points"], ["AppDelegate.application:didFinishLaunchingWithOptions:"])

    def test_system_prompt_sends_control_and_config_questions_to_the_new_tools(self):
        from web.app.agent import loop
        self.assertIn("get_assessments", loop.SYSTEM)
        self.assertIn("get_manifest", loop.SYSTEM)
        self.assertIn("UNKNOWN as unknown", loop.SYSTEM)

    def test_both_tools_are_registered_with_valid_schemas(self):
        names = {t["name"] for t in tools.TOOLS}
        self.assertTrue({"get_assessments", "get_manifest"} <= names)
        for t in tools.TOOLS:
            self.assertEqual(t["schema"]["type"], "object", t["name"])
        self.assertIn("UNKNOWN", next(t for t in tools.TOOLS if t["name"] == "get_assessments")["description"])


if __name__ == "__main__":
    unittest.main()
