package io.mailmite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class HtmlReporterTest {

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
                        "open", null, null, null)),
                "/tmp/test.sqlite",
                "IOS"
        );
    }

    @Test void writesHtmlFile(@TempDir Path tmp) throws Exception {
        Path html = HtmlReporter.generate(sampleReport(), tmp);
        assertTrue(Files.exists(html));
        String content = Files.readString(html);
        assertTrue(content.startsWith("<!DOCTYPE html>"));
    }

    @Test void embedsCurrentTemplateVersion(@TempDir Path tmp) throws Exception {
        String content = Files.readString(HtmlReporter.generate(sampleReport(), tmp));
        assertTrue(content.contains(
                "<meta name=\"mailmite-report-template\" content=\""
                        + HtmlReporter.TEMPLATE_VERSION + "\">"),
                "report must embed TEMPLATE_VERSION for stale-detection");
        assertTrue(content.contains("affected-list") || content.contains("Affected ("),
                "grouped affected-assets layout expected");
    }

    @Test void rendersAssessmentSection(@TempDir Path tmp) throws Exception {
        var assess = new AnalysisReport.AssessmentRecord(
                1L, "ASSESS-FLAG-SECURE", "FLAG_SECURE", "UI_PRIVACY",
                "PRESENT", "HIGH", "addFlags(FLAG_SECURE)", "signal=ui", "ANDROID");
        var report = new AnalysisReport(
                "assess-test", "App", "com.example", false, false,
                List.of("arm64-v8a"), 100L, 1, 1, 0,
                Map.of(), List.of(), List.of(), null, null, null,
                List.of(), List.of(), "/tmp/t.sqlite", "ANDROID", List.of(assess));
        String html = Files.readString(HtmlReporter.generate(report, tmp));
        assertTrue(html.contains("Security Controls Assessment"));
        assertTrue(html.contains("ASSESS-FLAG-SECURE"));
        assertTrue(html.contains("badge-present") || html.contains("PRESENT"));
        assertEquals("4", HtmlReporter.TEMPLATE_VERSION);
    }

    @Test void omitsRawLlmFindingsSection(@TempDir Path tmp) throws Exception {
        var llmFinding = new AnalysisReport.LlmFinding(
                "didFinishLaunching", "AppDelegate", "deep",
                "CRITICAL: hardcoded credential in binary");
        var report = new AnalysisReport(
                "llm-raw-test", "TestApp", "com.example.test", true, false,
                List.of("ARM64"), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), "TEAM", "Profile", "2026-12-31",
                List.of(llmFinding),
                List.of(),
                "/tmp/test.sqlite", "IOS");

        String html = Files.readString(HtmlReporter.generate(report, tmp));
        assertFalse(html.contains("Raw LLM Findings"),
                "Raw LLM Findings section must not appear in the HTML report");
        assertFalse(html.contains("vulnerabilities above are already distilled"),
                "raw-LLM distillation note must not appear");
    }

    @Test void containsBundleId(@TempDir Path tmp) throws Exception {
        String content = Files.readString(HtmlReporter.generate(sampleReport(), tmp));
        assertTrue(content.contains("com.example.test"));
    }

    @Test void containsEntryPoint(@TempDir Path tmp) throws Exception {
        String content = Files.readString(HtmlReporter.generate(sampleReport(), tmp));
        assertTrue(content.contains("didFinishLaunchingWithOptions"));
    }

    @Test void containsTeamId(@TempDir Path tmp) throws Exception {
        String content = Files.readString(HtmlReporter.generate(sampleReport(), tmp));
        assertTrue(content.contains("TEAM123"));
    }

    @Test void rendersVulnerabilitiesAsFirstClassSection(@TempDir Path tmp) throws Exception {
        String content = Files.readString(HtmlReporter.generate(sampleReport(), tmp));
        assertTrue(content.contains("MSTG-STORAGE-1"),    "rule ID should appear");
        assertTrue(content.contains("Hardcoded API key"), "title should appear");
        assertTrue(content.contains("CVSS 9.1"),          "CVSS score should appear");
        assertTrue(content.contains("CWE-798"),           "CWE should appear");
        assertTrue(content.contains("api_key=abcdef"),    "evidence should appear");
        assertTrue(content.contains("Use Keychain"),      "remediation should appear");
    }

    @Test void falsePositiveExcludedFromActiveSectionButShownAsSuppressed(@TempDir Path tmp) throws Exception {
        var fpFinding = new AnalysisReport.VulnerabilityRecord(
                2L, "MSTG-RESILIENCE-1", "No jailbreak detection", "RESILIENCE",
                "MEDIUM", 5.3, "CWE-693", "...", "BINARY", "TestApp",
                "...", "Whole binary", "1. step", "Fix this",
                "https://example.com",
                "false_positive", null, null, "Reviewer says: not applicable to enterprise app");

        var report = new AnalysisReport(
                "fp-test-id", "TestApp", "com.example.test", true, false,
                List.of("ARM64"), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), "TEAM", "Profile", "2026-12-31",
                List.of(),
                List.of(fpFinding),
                "/tmp/test.sqlite", "IOS");

        String html = Files.readString(HtmlReporter.generate(report, tmp));

        // The card MUST NOT appear in the main vulnerability list
        // (because that section iterates only active findings)
        // — verify by checking the Risk Posture total
        assertTrue(html.contains("0 findings detected") || html.contains("No vulnerabilities detected"),
                "false-positive should not contribute to active findings count");

        // It MUST appear in the Suppressed Findings section instead
        assertTrue(html.contains("Suppressed Findings"),
                "suppressed section should be rendered");
        assertTrue(html.contains("False Positive"),
                "false positive label should appear in suppressed list");
        assertTrue(html.contains("Reviewer says: not applicable"),
                "reviewer note should appear");
    }

    @Test void overrideSeverityShownInsteadOfOriginal(@TempDir Path tmp) throws Exception {
        var overridden = new AnalysisReport.VulnerabilityRecord(
                3L, "MSTG-STORAGE-1", "Hardcoded API key", "STORAGE",
                "CRITICAL", 9.1, "CWE-798", "Test", "STRING", "0x1234",
                "key=abcdef", "0x1234", "steps", "remediation",
                "https://example.com",
                "open", "LOW", 3.0, "Server-side key, not exploitable client-side");

        var report = new AnalysisReport(
                "ov-test", "TestApp", "com.example.test", true, false,
                List.of("ARM64"), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), "TEAM", "Profile", "2026-12-31",
                List.of(), List.of(overridden), "/tmp/test.sqlite", "IOS");

        String html = Files.readString(HtmlReporter.generate(report, tmp));

        // Effective severity (LOW) used in the card badge, not CRITICAL
        // The override-note hint should be rendered
        assertTrue(html.contains("Severity overridden"),
                "should signal the override to readers");
        assertTrue(html.contains("Server-side key"),
                "override note should appear");
        assertTrue(html.contains("CVSS 3.0"),
                "effective CVSS (override) should be used");
        // Risk Posture dashboard must use effective severity, not original
        assertFalse(html.contains("sev-critical'><div class='v'>1</div>"),
                "CRITICAL tile must not count overridden finding");
        assertTrue(html.contains("sev-low'><div class='v'>1</div>"),
                "LOW tile should reflect effective severity");
    }

    @Test void riskPostureUsesEffectiveSeverityWhenDowngradedToInfo(@TempDir Path tmp) throws Exception {
        var downgraded = new AnalysisReport.VulnerabilityRecord(
                4L, "MSTG-NETWORK-2", "ATS disabled via NSAllowsArbitraryLoads", "NETWORK",
                "CRITICAL", 9.1, "CWE-295", "ATS disabled", "RESOURCE", "Info.plist",
                "NSAllowsArbitraryLoads=true", "Info.plist", "steps", "remediation",
                "https://example.com",
                "accepted_risk", "INFO", 0.0, "Accepted for lab app");

        var report = new AnalysisReport(
                "info-test", "FreshCart", "com.example.freshcart", true, false,
                List.of("ARM64"), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), "TEAM", "Profile", "2026-12-31",
                List.of(), List.of(downgraded), "/tmp/test.sqlite", "IOS");

        String html = Files.readString(HtmlReporter.generate(report, tmp));

        assertFalse(html.contains("sev-critical'><div class='v'>1</div>"),
                "downgraded CRITICAL→INFO must not appear in Risk Posture");
        assertTrue(html.contains("1 finding"), "accepted_risk finding still counts in total");
        assertTrue(html.contains("sev-info'><div class='v'>1</div>"),
                "INFO tile should reflect effective severity");
        assertTrue(html.contains("badge-info'>INFO</span>"),
                "vuln card should show INFO badge");
    }

    @Test void androidReportShowsPlatformNotObjectiveC(@TempDir Path tmp) throws Exception {
        var report = new AnalysisReport(
                "android-test", "com.example.app", "com.example.app", false, false,
                List.of(), 1000L, 1, 1, 0,
                Map.of(), List.of(), List.of(), null, null, null,
                List.of(), List.of(), "/tmp/test.sqlite", "ANDROID");

        String html = Files.readString(HtmlReporter.generate(report, tmp));
        assertTrue(html.contains("Android"), "platform should be Android");
        assertTrue(html.contains("Java/Kotlin (DEX)"), "language should be DEX stack");
        assertFalse(html.contains("Objective-C"), "must not mislabel Android as Objective-C");
    }

    @Test void vulnerabilitiesAppearBeforeStringsSection(@TempDir Path tmp) throws Exception {
        String content = Files.readString(HtmlReporter.generate(sampleReport(), tmp));
        int vulnIdx    = content.indexOf("MSTG-STORAGE-1");
        int stringsIdx = content.indexOf("String Sample");
        assertTrue(vulnIdx > 0, "vuln section must be present");
        assertTrue(stringsIdx > vulnIdx,
                "Vulnerabilities must be rendered before the optional strings sample");
    }

    @Test void groupsDuplicateRuleIdIntoOneCardWithUniqueAssets(@TempDir Path tmp) throws Exception {
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

        String html = Files.readString(HtmlReporter.generate(report, tmp));

        // Two unique issues (0339 + 0364), not five raw rows
        assertEquals(2, countOccurrences(html, "class='vuln "),
                "one card per unique rule_id");
        assertEquals(1, countOccurrences(html, "MASTG-TEST-0339"),
                "MASTG-TEST-0339 should appear once as a grouped card");
        assertEquals(1, countOccurrences(html, "MASTG-TEST-0364"));
        assertTrue(html.contains("Affected (3 unique)"),
                "affected section should report unique asset count");
        assertTrue(html.contains("3 locations"),
                "multi-asset card should show location count badge");
        assertTrue(html.contains("DBHelper"));
        assertTrue(html.contains("onCreate"));
        assertTrue(html.contains("addUser"));
        // Risk posture counts unique issues, not raw duplicates
        assertTrue(html.contains("2 findings detected"),
                "summary total must count unique grouped issues");
        assertTrue(html.contains("sev-high'><div class='v'>2</div>"),
                "HIGH tile should count 2 unique issues, not 5 rows");
        assertTrue(html.contains("unique open/active issues"),
                "should note that summary uses unique-issue counting");
    }

    @Test void groupFindingsByRuleDedupesAssetsAndPicksOpenRepresentative() {
        var open = finding(2L, "RULE-1", "Title", "CODE", "MEDIUM", 5.0,
                "FUNCTION", "foo", "pkg.foo");
        var fp = new AnalysisReport.VulnerabilityRecord(
                1L, "RULE-1", "Title", "CODE", "HIGH", 8.0, "CWE-1", "d",
                "FUNCTION", "foo", "ev", "pkg.foo", "poc", "fix", "https://x",
                "false_positive", null, null, null);
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
                "open", null, null, null);
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0, from = 0;
        while ((from = haystack.indexOf(needle, from)) >= 0) {
            count++;
            from += needle.length();
        }
        return count;
    }
}
