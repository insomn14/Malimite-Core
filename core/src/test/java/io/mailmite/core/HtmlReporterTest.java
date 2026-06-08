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
                "/tmp/test.sqlite"
        );
    }

    @Test void writesHtmlFile(@TempDir Path tmp) throws Exception {
        Path html = HtmlReporter.generate(sampleReport(), tmp);
        assertTrue(Files.exists(html));
        String content = Files.readString(html);
        assertTrue(content.startsWith("<!DOCTYPE html>"));
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
                "/tmp/test.sqlite");

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
                List.of(), List.of(overridden), "/tmp/test.sqlite");

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
                List.of(), List.of(downgraded), "/tmp/test.sqlite");

        String html = Files.readString(HtmlReporter.generate(report, tmp));

        assertFalse(html.contains("sev-critical'><div class='v'>1</div>"),
                "downgraded CRITICAL→INFO must not appear in Risk Posture");
        assertTrue(html.contains("1 finding"), "accepted_risk finding still counts in total");
        assertTrue(html.contains("badge-info'>INFO</span>"),
                "vuln card should show INFO badge");
    }

    @Test void vulnerabilitiesAppearBeforeStringsSection(@TempDir Path tmp) throws Exception {
        String content = Files.readString(HtmlReporter.generate(sampleReport(), tmp));
        int vulnIdx    = content.indexOf("MSTG-STORAGE-1");
        int stringsIdx = content.indexOf("String Sample");
        assertTrue(vulnIdx > 0, "vuln section must be present");
        assertTrue(stringsIdx > vulnIdx,
                "Vulnerabilities must be rendered before the optional strings sample");
    }
}
