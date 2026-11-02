package io.malimite.core;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Since HtmlReporter.TEMPLATE_VERSION 5+, the report is a bilingual VA template (see
 * core/src/main/resources/report-template/) rendered client-side from one injected JSON blob —
 * so most assertions here parse that JSON back out of the generated HTML and check it directly,
 * rather than grepping for HTML fragments the template's own JS may phrase differently over time.
 * A handful of tests still check the raw HTML file for things the JSON contract itself can't
 * express (the file exists, the stale-detection meta tag, which platform template was picked).
 */
class HtmlReporterTest {

    private static final Pattern DATA_BLOCK = Pattern.compile(
            "<script id=\"report-data\" type=\"application/json\">\\n(.*?)\\n</script>", Pattern.DOTALL);

    /** Parses the JSON this class's own buildReportJson() would have produced, round-tripped
     * through the actual generated HTML file — exercises the real injection path end to end. */
    private static JSONObject renderedData(AnalysisReport r, Path tmp) throws Exception {
        String html = Files.readString(HtmlReporter.generate(r, tmp));
        Matcher m = DATA_BLOCK.matcher(html);
        assertTrue(m.find(), "report-data script block must be present in the generated HTML");
        // The injector escapes "</" to "<\/" so a literal "</script>" in finding text can't break
        // the block early — undo that before parsing, same as the template's own JS does.
        String json = m.group(1).replace("<\\/", "</");
        return new JSONObject(json);
    }

    private static AnalysisReport sampleReport() {
        return new AnalysisReport(
                "test-scan-id",
                "TestApp",
                "com.example.test",
                true, false,
                List.of("ARM64"),
                5000L,
                2, 8, 3,
                Map.of("AppDelegate", List.of("applicationDidFinishLaunching:", "application:didFinishLaunchingWithOptions:")),
                List.of(new AnalysisReport.StringEntry("0x1000", "https://api.example.com/v1", "__TEXT", "url")),
                List.of("AppDelegate.application:didFinishLaunchingWithOptions:"),
                "TEAM123",
                "Dev Profile",
                "2026-06-30",
                List.of(),
                List.of(new AnalysisReport.VulnerabilityRecord(
                        1L,
                        "MSTG-STORAGE-1", "Hardcoded API key", "STORAGE",
                        "CRITICAL", 9.1, "CWE-798",
                        "A hardcoded credential was found in the binary",
                        "STRING", "0x1234", "api_key=abcdef", "0x1234 (__TEXT)",
                        "1. extract strings\n2. find key",
                        "Use Keychain",
                        "https://example.com/mstg",
                        "open", null, null, null,
                        null, null, null, null, "none", null, null)),
                "/tmp/test.sqlite",
                "IOS"
        );
    }

    @Test void writesHtmlFile(@TempDir Path tmp) throws Exception {
        Path html = HtmlReporter.generate(sampleReport(), tmp);
        assertTrue(Files.exists(html));
        String content = Files.readString(html);
        assertTrue(content.startsWith("<!doctype html>"));
    }

    /** Regression test for a real bug: injecting the serialized JSON into the template via
     * {@code String.replace(CharSequence, CharSequence)} wrapped in {@code Matcher.quoteReplacement()}
     * silently doubled every backslash already present in the JSON (quoteReplacement is only
     * meaningful for replaceAll/replaceFirst's regex-replacement syntax, not plain replace()).
     * A Mach-O string containing a literal double-quote — e.g. the real string value
     * {@code "/usr/lib/dyld"}, quotes included — gets escaped once to {@code \"} by JSONObject;
     * the bug then escaped that backslash again, corrupting the embedded JSON
     * ({@code \"} → {@code \\"}) so the browser's own {@code JSON.parse} threw a SyntaxError on
     * every report containing such a string. See generate()'s injection comment for the fix. */
    @Test void stringValueContainingLiteralQuotesSurvivesTheRoundTrip(@TempDir Path tmp) throws Exception {
        var report = new AnalysisReport(
                "quote-test", "TestApp", "com.example.test", true, false,
                List.of("ARM64"), 1000L, 1, 1, 1,
                Map.of(), List.of(new AnalysisReport.StringEntry(
                        "0x1000", "\"/usr/lib/dyld\"", "__TEXT", null)),
                List.of(), null, null, null,
                List.of(), List.of(), "/tmp/test.sqlite", "IOS");

        JSONObject data = renderedData(report, tmp);
        String value = data.getJSONArray("strings_sample").getJSONObject(0).getString("value");
        assertEquals("\"/usr/lib/dyld\"", value, "embedded quotes must round-trip exactly, not gain extra backslashes");
    }

    /** Same regression, with a backslash-and-quote combination (common in escaped paths found in
     * real binaries) to make sure the fix isn't narrowly specific to a bare leading/trailing quote. */
    @Test void stringValueContainingBackslashQuoteCombinationSurvivesTheRoundTrip(@TempDir Path tmp) throws Exception {
        // Runtime value: path="C:\Program Files\App"  (one backslash per separator).
        String withBackslashes = "path=\"C:\\Program Files\\App\"";
        var report = new AnalysisReport(
                "backslash-test", "TestApp", "com.example.test", true, false,
                List.of("ARM64"), 1000L, 1, 1, 1,
                Map.of(), List.of(new AnalysisReport.StringEntry(
                        "0x1000", withBackslashes, "__TEXT", null)),
                List.of(), null, null, null,
                List.of(), List.of(), "/tmp/test.sqlite", "IOS");

        JSONObject data = renderedData(report, tmp);
        String value = data.getJSONArray("strings_sample").getJSONObject(0).getString("value");
        assertEquals(withBackslashes, value);
    }

    @Test void embedsCurrentTemplateVersionNearTheTopOfTheFile(@TempDir Path tmp) throws Exception {
        String content = Files.readString(HtmlReporter.generate(sampleReport(), tmp));
        String meta = "<meta name=\"malimite-report-template\" content=\"" + HtmlReporter.TEMPLATE_VERSION + "\">";
        assertTrue(content.contains(meta), "report must embed TEMPLATE_VERSION for stale-detection");
        // web/app/main.py's _html_template_stale() only reads the first 4096 bytes — this is the
        // other half of that contract, locked in here so a template edit can't silently push the
        // meta tag out of that window again (see HtmlReporter.generate()'s injection comment).
        int idx = content.indexOf(meta);
        assertTrue(idx >= 0 && idx < 4096,
                "template-version meta tag must stay within the first 4096 bytes, was at " + idx);
    }

    @Test void picksAndroidTemplateForAndroidPlatform(@TempDir Path tmp) throws Exception {
        var report = new AnalysisReport(
                "android-test", "com.example.app", "com.example.app", false, false,
                List.of(), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), null, null, null,
                List.of(), List.of(), "/tmp/test.sqlite", "ANDROID");
        String html = Files.readString(HtmlReporter.generate(report, tmp));
        assertTrue(html.contains("ANDROID / APK"), "Android template's own header comment should be present");
    }

    @Test void picksIosTemplateForIosPlatform(@TempDir Path tmp) throws Exception {
        String html = Files.readString(HtmlReporter.generate(sampleReport(), tmp));
        assertFalse(html.contains("ANDROID / APK"), "iOS platform must not render the Android template");
    }

    @Test void rendersAssessmentControls(@TempDir Path tmp) throws Exception {
        var assess = new AnalysisReport.AssessmentRecord(
                1L, "ASSESS-FLAG-SECURE", "FLAG_SECURE", "UI_PRIVACY",
                "PRESENT", "HIGH", "addFlags(FLAG_SECURE)", "signal=ui", "ANDROID");
        var report = new AnalysisReport(
                "assess-test", "App", "com.example", false, false,
                List.of("arm64-v8a"), 100L, 1, 1, 0,
                Map.of(), List.of(), List.of(), null, null, null,
                List.of(), List.of(), "/tmp/t.sqlite", "ANDROID", List.of(assess));

        JSONArray controls = renderedData(report, tmp).getJSONArray("controls");
        assertEquals(1, controls.length());
        JSONObject c = controls.getJSONObject(0);
        assertEquals("ASSESS-FLAG-SECURE", c.getString("rule"));
        assertEquals("FLAG_SECURE", c.getString("name"));
        assertEquals("UI_PRIVACY", c.getString("group"));
        assertEquals("PRESENT", c.getString("status"));
        assertEquals("HIGH", c.getString("confidence"));
    }

    @Test void containsBundleId(@TempDir Path tmp) throws Exception {
        JSONObject data = renderedData(sampleReport(), tmp);
        assertEquals("com.example.test", data.getJSONObject("app").getString("bundle_id"));
    }

    @Test void containsEntryPoint(@TempDir Path tmp) throws Exception {
        JSONObject data = renderedData(sampleReport(), tmp);
        JSONArray eps = data.getJSONObject("code_surface").getJSONArray("entry_points");
        assertEquals(1, eps.length());
        assertEquals("AppDelegate.application:didFinishLaunchingWithOptions:", eps.getString(0));
    }

    @Test void containsTeamId(@TempDir Path tmp) throws Exception {
        JSONObject data = renderedData(sampleReport(), tmp);
        assertEquals("TEAM123", data.getJSONObject("app").getString("team_id"));
    }

    @Test void rendersFindingCoreFields(@TempDir Path tmp) throws Exception {
        JSONArray findings = renderedData(sampleReport(), tmp).getJSONArray("findings");
        assertEquals(1, findings.length());
        JSONObject f = findings.getJSONObject(0);
        assertEquals("MSTG-STORAGE-1", f.getString("rule"));
        assertEquals("Hardcoded API key", f.getString("title"));
        assertEquals(9.1, f.getDouble("cvss"), 0.001);
        assertEquals("CWE-798", f.getString("cwe"));
        assertEquals("api_key=abcdef", f.getString("evidence"));
        assertEquals("Use Keychain", f.getString("remediation"));
        assertEquals("MASTG", f.getString("source"));
        assertEquals("MASVS-STORAGE", f.getString("masvs"));
        assertEquals("OPEN", f.getString("status"));
        // "1. extract strings\n2. find key" → two PoC steps, numbering stripped (template owns
        // its own step numbering in the rendered <ol>).
        JSONArray poc = f.getJSONArray("poc");
        assertEquals(2, poc.length());
        assertEquals("extract strings", poc.getString(0));
        assertEquals("find key", poc.getString(1));
    }

    @Test void falsePositiveExcludedFromFindingsJson(@TempDir Path tmp) throws Exception {
        var fpFinding = new AnalysisReport.VulnerabilityRecord(
                2L, "MSTG-RESILIENCE-1", "No jailbreak detection", "RESILIENCE",
                "MEDIUM", 5.3, "CWE-693", "...", "BINARY", "TestApp",
                "...", "Whole binary", "1. step", "Fix this",
                "https://example.com",
                "false_positive", null, null, "Reviewer says: not applicable to enterprise app",
                null, null, null, null, "none", null, null);

        var report = new AnalysisReport(
                "fp-test-id", "TestApp", "com.example.test", true, false,
                List.of("ARM64"), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), "TEAM", "Profile", "2026-12-31",
                List.of(),
                List.of(fpFinding),
                "/tmp/test.sqlite", "IOS");

        JSONObject data = renderedData(report, tmp);
        assertEquals(0, data.getJSONArray("findings").length(),
                "false-positive findings must not appear in the exported report at all");
        assertEquals(0, data.getJSONObject("summary").getInt("occurrences"));
    }

    @Test void overrideSeverityUsedAsEffectiveSeverity(@TempDir Path tmp) throws Exception {
        var overridden = new AnalysisReport.VulnerabilityRecord(
                3L, "MSTG-STORAGE-1", "Hardcoded API key", "STORAGE",
                "CRITICAL", 9.1, "CWE-798", "Test", "STRING", "0x1234",
                "key=abcdef", "0x1234", "steps", "remediation",
                "https://example.com",
                "open", "LOW", 3.0, "Server-side key, not exploitable client-side",
                null, null, null, null, "none", null, null);

        var report = new AnalysisReport(
                "ov-test", "TestApp", "com.example.test", true, false,
                List.of("ARM64"), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), "TEAM", "Profile", "2026-12-31",
                List.of(), List.of(overridden), "/tmp/test.sqlite", "IOS");

        JSONObject f = renderedData(report, tmp).getJSONArray("findings").getJSONObject(0);
        assertEquals("LOW", f.getString("severity"), "effective (overridden) severity must be exported, not the original CRITICAL");
        assertEquals(3.0, f.getDouble("cvss"), 0.001, "effective (overridden) CVSS must be exported");
    }

    @Test void riskPostureUsesEffectiveSeverityWhenDowngradedToInfo(@TempDir Path tmp) throws Exception {
        var downgraded = new AnalysisReport.VulnerabilityRecord(
                4L, "MSTG-NETWORK-2", "ATS disabled via NSAllowsArbitraryLoads", "NETWORK",
                "CRITICAL", 9.1, "CWE-295", "ATS disabled", "RESOURCE", "Info.plist",
                "NSAllowsArbitraryLoads=true", "Info.plist", "steps", "remediation",
                "https://example.com",
                "accepted_risk", "INFO", 0.0, "Accepted for lab app",
                null, null, null, null, "none", null, null);

        var report = new AnalysisReport(
                "info-test", "FreshCart", "com.example.freshcart", true, false,
                List.of("ARM64"), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), "TEAM", "Profile", "2026-12-31",
                List.of(), List.of(downgraded), "/tmp/test.sqlite", "IOS");

        JSONObject data = renderedData(report, tmp);
        assertEquals(1, data.getJSONArray("findings").length(),
                "accepted_risk findings still count (only false_positive/fixed are excluded)");
        JSONObject f = data.getJSONArray("findings").getJSONObject(0);
        assertEquals("INFO", f.getString("severity"));
        assertEquals("ACCEPTED", f.getString("status"));
    }

    @Test void aiFixOverridesUsedAsEffectiveTextFields(@TempDir Path tmp) throws Exception {
        var fixed = new AnalysisReport.VulnerabilityRecord(
                5L, "MSTG-STORAGE-1", "Hardcoded API key", "STORAGE",
                "CRITICAL", 9.1, "CWE-798",
                "Original terse description", "STRING", "0x1234",
                "original evidence snippet", "0x1234",
                "original poc", "original remediation",
                "https://example.com/mstg",
                "open", null, null, null,
                "AI-rewritten description with full context",
                "AI-rewritten evidence excerpt",
                "1. AI step one\n2. AI step two",
                "AI-rewritten remediation guidance",
                "applied", "deepseek", "deepseek-flash");

        var report = new AnalysisReport(
                "aifix-test", "TestApp", "com.example.test", true, false,
                List.of("ARM64"), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), "TEAM", "Profile", "2026-12-31",
                List.of(), List.of(fixed), "/tmp/test.sqlite", "IOS");

        JSONObject f = renderedData(report, tmp).getJSONArray("findings").getJSONObject(0);
        assertEquals("AI-rewritten description with full context", f.getString("description"));
        assertEquals("AI-rewritten evidence excerpt", f.getString("evidence"));
        assertEquals("AI-rewritten remediation guidance", f.getString("remediation"));
        JSONArray poc = f.getJSONArray("poc");
        assertEquals("AI step one", poc.getString(0));
        assertEquals("AI step two", poc.getString(1));
        // The original text must not leak through anywhere once an AI Fix override is applied.
        String flat = f.toString();
        assertFalse(flat.contains("Original terse description"));
        assertFalse(flat.contains("original evidence snippet"));
        assertFalse(flat.contains("original poc"));
        assertFalse(flat.contains("original remediation"));
    }

    @Test void androidReportShowsPlatformNotObjectiveC(@TempDir Path tmp) throws Exception {
        var report = new AnalysisReport(
                "android-test", "com.example.app", "com.example.app", false, false,
                List.of(), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), null, null, null,
                List.of(), List.of(), "/tmp/test.sqlite", "ANDROID");

        JSONObject app = renderedData(report, tmp).getJSONObject("app");
        assertEquals("Android", app.getString("platform"));
        assertEquals("Java/Kotlin (DEX)", app.getString("language"));
    }

    @Test void androidManifestFieldsExportedWhenPresent(@TempDir Path tmp) throws Exception {
        var manifest = new AnalysisReport.AndroidManifestInfo(
                false, true, true, "res/xml/network_security_config.xml",
                List.of("android.permission.INTERNET", "android.permission.CAMERA"),
                List.of(new AnalysisReport.AndroidManifestInfo.Component(
                        "activity", "com.example.MainActivity", true, null)));
        var report = new AnalysisReport(
                "android-manifest-test", "com.example.app", "com.example.app", false, false,
                List.of(), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), null, null, null,
                List.of(), List.of(), "/tmp/test.sqlite", "ANDROID", List.of(), manifest);

        JSONObject data = renderedData(report, tmp);
        assertTrue(data.has("manifest"), "manifest section must be present when AndroidManifestInfo is populated");
        JSONObject m = data.getJSONObject("manifest");
        assertFalse(m.getBoolean("debuggable"));
        assertTrue(m.getBoolean("allow_backup"));
        assertTrue(m.getBoolean("uses_cleartext_traffic"));
        assertEquals("res/xml/network_security_config.xml", m.getString("network_security_config"));
        assertEquals(2, m.getJSONArray("permissions").length());
        JSONObject comp = m.getJSONArray("components").getJSONObject(0);
        assertEquals("activity", comp.getString("type"));
        assertEquals("com.example.MainActivity", comp.getString("name"));
        assertTrue(comp.getBoolean("exported"));
        assertFalse(comp.has("permission"), "null permission must be omitted, not sent as an empty string");
    }

    @Test void manifestSectionAbsentForIos(@TempDir Path tmp) throws Exception {
        JSONObject data = renderedData(sampleReport(), tmp);
        assertFalse(data.has("manifest"), "iOS reports must not carry an Android manifest section");
    }

    @Test void groupsDuplicateRuleIdIntoOneFindingWithUniqueAssets(@TempDir Path tmp) throws Exception {
        var a1 = finding(10L, "MASTG-TEST-0339", "SQL Injection in Content Providers", "CODE",
                "HIGH", 8.1, "FUNCTION", "DBHelper", "com.example.DBHelper.DBHelper");
        var a2 = finding(11L, "MASTG-TEST-0339", "SQL Injection in Content Providers", "CODE",
                "HIGH", 8.1, "FUNCTION", "onCreate", "com.example.DBHelper.onCreate");
        var a3 = finding(12L, "MASTG-TEST-0339", "SQL Injection in Content Providers", "CODE",
                "HIGH", 8.1, "FUNCTION", "addUser", "com.example.DBHelper.addUser");
        // identical asset row should be deduped
        var aDup = finding(13L, "MASTG-TEST-0339", "SQL Injection in Content Providers", "CODE",
                "HIGH", 8.1, "FUNCTION", "onCreate", "com.example.DBHelper.onCreate");
        var other = finding(20L, "MASTG-TEST-0364", "Exported And Unprotected Activities", "PLATFORM",
                "HIGH", 7.5, "RESOURCE", "Component", "Component");

        var report = new AnalysisReport(
                "group-test", "TestApp", "com.example.test", false, false,
                List.of(), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), null, null, null,
                List.of(), List.of(a1, a2, a3, aDup, other), "/tmp/test.sqlite", "ANDROID");

        JSONArray findings = renderedData(report, tmp).getJSONArray("findings");
        assertEquals(2, findings.length(), "two unique issues (0339 + 0364), not five raw rows");

        JSONObject grouped = findings.getJSONObject(0).getString("rule").equals("MASTG-TEST-0339")
                ? findings.getJSONObject(0) : findings.getJSONObject(1);
        assertEquals(3, grouped.getJSONArray("affected").length(), "3 unique assets, dup collapsed");

        var names = new java.util.HashSet<String>();
        for (int i = 0; i < grouped.getJSONArray("affected").length(); i++) {
            names.add(grouped.getJSONArray("affected").getJSONObject(i).getString("name"));
        }
        assertEquals(java.util.Set.of("DBHelper", "onCreate", "addUser"), names);

        int occurrences = renderedData(report, tmp).getJSONObject("summary").getInt("occurrences");
        assertEquals(5, occurrences, "summary occurrences counts raw rows, not deduped assets");
    }

    @Test void groupFindingsByRuleDedupesAssetsAndPicksOpenRepresentative() {
        var open = finding(2L, "RULE-1", "Title", "CODE", "MEDIUM", 5.0,
                "FUNCTION", "foo", "pkg.foo");
        var fp = new AnalysisReport.VulnerabilityRecord(
                1L, "RULE-1", "Title", "CODE", "HIGH", 8.0, "CWE-1", "d",
                "FUNCTION", "foo", "ev", "pkg.foo", "poc", "fix", "https://x",
                "false_positive", null, null, null,
                null, null, null, null, "none", null, null);
        var otherAsset = finding(3L, "RULE-1", "Title", "CODE", "LOW", 2.0,
                "FUNCTION", "bar", "pkg.bar");

        var groups = HtmlReporter.groupFindingsByRule(List.of(fp, open, otherAsset));
        assertEquals(1, groups.size());
        assertEquals(2L, groups.get(0).representative().id(),
                "prefer open status over false_positive");
        assertEquals(2, groups.get(0).assets().size(),
                "identical foo/pkg.foo assets from fp+open should dedupe");
        assertEquals(3, groups.get(0).occurrenceCount());
    }

    private static AnalysisReport.VulnerabilityRecord finding(
            long id, String ruleId, String title, String category,
            String severity, double cvss, String type, String name, String location) {
        return new AnalysisReport.VulnerabilityRecord(
                id, ruleId, title, category, severity, cvss, "CWE-89",
                "desc", type, name, "evidence", location,
                "1. step", "remediation", "https://example.com",
                "open", null, null, null,
                null, null, null, null, "none", null, null);
    }
}
