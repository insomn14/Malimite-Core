package io.malimite.core;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class SarifExporterTest {

    private static AnalysisReport sampleReport() {
        return new AnalysisReport(
                "test-scan-id",
                "TestApp",
                "com.example.test",
                true, false,
                List.of("ARM64"),
                1234L,
                3, 10, 5,
                Map.of("ViewController", List.of("viewDidLoad", "buttonTapped")),
                List.of(
                        new AnalysisReport.StringEntry("0x1000", "api_key=supersecret", "__TEXT", "str1"),
                        new AnalysisReport.StringEntry("0x1010", "Hello", "__TEXT", "str2")
                ),
                List.of("Global.main"),
                "ABCDE12345",
                "MyProfile",
                "2026-12-31",
                List.of(new AnalysisReport.LlmFinding(
                        "buttonTapped", "ViewController", "FIND_VULNS",
                        "HIGH: SQL injection risk in user input handling")),
                List.of(),
                "/tmp/test.sqlite",
                "IOS"
        );
    }

    @Test void writesSarifFile(@TempDir Path tmp) throws Exception {
        Path sarif = SarifExporter.export(sampleReport(), tmp);
        assertTrue(Files.exists(sarif));
        String content = Files.readString(sarif);
        assertTrue(content.contains("\"version\": \"2.1.0\""));
        assertTrue(content.contains("Malimite"));
    }

    @Test void containsEntryPointResult(@TempDir Path tmp) throws Exception {
        Path sarif = SarifExporter.export(sampleReport(), tmp);
        String content = Files.readString(sarif);
        assertTrue(content.contains("MALIMITE001"));
        assertTrue(content.contains("Global.main"));
    }

    @Test void flagsSuspiciousString(@TempDir Path tmp) throws Exception {
        Path sarif = SarifExporter.export(sampleReport(), tmp);
        String content = Files.readString(sarif);
        assertTrue(content.contains("MALIMITE002"));
        assertTrue(content.contains("api_key"));
    }

    @Test void includesLlmVulnFinding(@TempDir Path tmp) throws Exception {
        Path sarif = SarifExporter.export(sampleReport(), tmp);
        String content = Files.readString(sarif);
        assertTrue(content.contains("MALIMITE003"));
        assertTrue(content.contains("SQL injection"));
    }

    private static AnalysisReport.VulnerabilityRecord finding(
            long id, String ruleId, String title, String severity, String status) {
        return new AnalysisReport.VulnerabilityRecord(
                id, ruleId, title, "STORAGE", severity, 0, "CWE-89",
                "desc", "STRING", "0x1234", "evidence", "0x1234",
                "1. step", "remediation", "https://example.com",
                status, null, null, null,
                null, null, null, null, "none", null, null);
    }

    private static AnalysisReport reportWithVulnerabilities(List<AnalysisReport.VulnerabilityRecord> vulns) {
        AnalysisReport base = sampleReport();
        return new AnalysisReport(
                base.scanId(), base.bundleExecutable(), base.bundleIdentifier(),
                base.isSwift(), base.isUniversal(), base.architectures(), base.durationMs(),
                base.classCount(), base.functionCount(), base.stringCount(),
                base.classes(), base.strings(), base.entryPoints(),
                base.bundleTeamId(), base.provisioningProfile(), base.provisioningExpiry(),
                List.of(), vulns, base.dbPath(), base.platform());
    }

    /** Every entry in the SARIF run's "results" array whose "ruleId" is MALIMITE004 — i.e. actual
     * rule-scanner findings, never confused with the static MALIMITE004 entry that always exists
     * in the "rules" (tool driver) section regardless of whether any finding used it. */
    private static List<JSONObject> malimite004Results(Path sarif) throws Exception {
        JSONObject root = new JSONObject(Files.readString(sarif));
        JSONArray results = root.getJSONArray("runs").getJSONObject(0).getJSONArray("results");
        List<JSONObject> out = new ArrayList<>();
        for (int i = 0; i < results.length(); i++) {
            JSONObject r = results.getJSONObject(i);
            if ("MALIMITE004".equals(r.optString("ruleId", null))) out.add(r);
        }
        return out;
    }

    // Regression for the bug found while scanning `dvba_v1.1.0.apk`: VulnerabilityScanner's
    // MASTG/MSTG rule-catalog findings (the primary signal for most scans — LLM enrichment is
    // optional) were never written to findings.sarif at all, so a CI SARIF gate (e.g. GitHub Code
    // Scanning) could never see them regardless of severity.
    @Test void includesRuleScannerFindingEvenWithoutLlm(@TempDir Path tmp) throws Exception {
        var high = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "open");
        Path sarif = SarifExporter.export(reportWithVulnerabilities(List.of(high)), tmp);
        List<JSONObject> results = malimite004Results(sarif);
        assertEquals(1, results.size());
        String message = results.get(0).getJSONObject("message").getString("text");
        assertTrue(message.contains("MASTG-TEST-0223"));
        assertTrue(message.contains("Stack Canaries Not Enabled"));
    }

    @Test void ruleScannerHighSeverityMapsToErrorLevel(@TempDir Path tmp) throws Exception {
        var high = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "open");
        Path sarif = SarifExporter.export(reportWithVulnerabilities(List.of(high)), tmp);
        assertEquals("error", malimite004Results(sarif).get(0).getString("level"));
    }

    @Test void ruleScannerCriticalSeverityAlsoMapsToErrorLevel(@TempDir Path tmp) throws Exception {
        var critical = finding(1, "MASTG-TEST-9999", "Hardcoded Secret", "CRITICAL", "open");
        Path sarif = SarifExporter.export(reportWithVulnerabilities(List.of(critical)), tmp);
        assertEquals("error", malimite004Results(sarif).get(0).getString("level"));
    }

    @Test void ruleScannerMediumSeverityMapsToWarningLevel(@TempDir Path tmp) throws Exception {
        var medium = finding(1, "MASTG-TEST-0262", "Backup Config", "MEDIUM", "open");
        Path sarif = SarifExporter.export(reportWithVulnerabilities(List.of(medium)), tmp);
        assertEquals("warning", malimite004Results(sarif).get(0).getString("level"));
    }

    @Test void ruleScannerLowSeverityMapsToNoteLevel(@TempDir Path tmp) throws Exception {
        var low = finding(1, "MASTG-TEST-0300", "Info Level Finding", "LOW", "open");
        Path sarif = SarifExporter.export(reportWithVulnerabilities(List.of(low)), tmp);
        assertEquals("note", malimite004Results(sarif).get(0).getString("level"));
    }

    @Test void falsePositiveRuleScannerFindingIsExcludedFromSarif(@TempDir Path tmp) throws Exception {
        var fp = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "false_positive");
        Path sarif = SarifExporter.export(reportWithVulnerabilities(List.of(fp)), tmp);
        assertTrue(malimite004Results(sarif).isEmpty());
    }

    @Test void fixedRuleScannerFindingIsExcludedFromSarif(@TempDir Path tmp) throws Exception {
        var fixed = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "fixed");
        Path sarif = SarifExporter.export(reportWithVulnerabilities(List.of(fixed)), tmp);
        assertTrue(malimite004Results(sarif).isEmpty());
    }

    @Test void acceptedRiskRuleScannerFindingIsStillExportedToSarif(@TempDir Path tmp) throws Exception {
        // accepted_risk is reviewed but not suppressed (see VulnerabilityRecord.isSuppressed()) —
        // it still exports, matching HtmlReporter's own "active findings" filter.
        var accepted = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "accepted_risk");
        Path sarif = SarifExporter.export(reportWithVulnerabilities(List.of(accepted)), tmp);
        assertEquals(1, malimite004Results(sarif).size());
    }

    @Test void multipleRuleScannerFindingsAllExportIndependently(@TempDir Path tmp) throws Exception {
        var high = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "open");
        var medium = finding(2, "MASTG-TEST-0262", "Backup Config", "MEDIUM", "open");
        var fp = finding(3, "MASTG-TEST-9000", "Not Real", "HIGH", "false_positive");
        Path sarif = SarifExporter.export(reportWithVulnerabilities(List.of(high, medium, fp)), tmp);
        assertEquals(2, malimite004Results(sarif).size(), "fp must be excluded, high+medium must remain");
    }
}
