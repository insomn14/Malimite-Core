package io.malimite.cli;

import io.malimite.core.AnalysisReport;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Main.computeExitCode() — the --fail-on gate CI/CD pipelines rely on.
 *
 * Regression context: computeExitCode() originally only looked at report.llmFindings(), so
 * --fail-on silently never tripped on a scan run without --llm (the common case) even with
 * CRITICAL/HIGH findings from VulnerabilityScanner's MASTG/MSTG rule catalog present. Reproduced
 * directly against a real scan (dvba_v1.1.0.apk, no --llm): VulnerabilityScanner found 51
 * findings including 7 HIGH, yet `--fail-on HIGH` exited 0.
 */
class MainTest {

    private static AnalysisReport.VulnerabilityRecord finding(
            long id, String ruleId, String title, String severity, String status) {
        return new AnalysisReport.VulnerabilityRecord(
                id, ruleId, title, "RESILIENCE", severity, 0, "CWE-693",
                "desc", "FUNCTION", "fn", "evidence", "fn",
                "1. step", "remediation", "https://example.com",
                status, null, null, null,
                null, null, null, null, "none", null, null);
    }

    private static AnalysisReport.VulnerabilityRecord finding(
            long id, String ruleId, String title, String severity, String status, String overrideSeverity) {
        return new AnalysisReport.VulnerabilityRecord(
                id, ruleId, title, "RESILIENCE", severity, 0, "CWE-693",
                "desc", "FUNCTION", "fn", "evidence", "fn",
                "1. step", "remediation", "https://example.com",
                status, overrideSeverity, null, null,
                null, null, null, null, "none", null, null);
    }

    private static AnalysisReport reportWith(List<AnalysisReport.VulnerabilityRecord> vulns,
                                             List<AnalysisReport.LlmFinding> llmFindings) {
        return new AnalysisReport(
                "scan-id", "App", "com.example", false, false, List.of(), 0L,
                0, 0, 0, Map.of(), List.of(), List.of(),
                null, null, null,
                llmFindings, vulns, "/tmp/test.sqlite", "ANDROID");
    }

    @Test void failOnNoneAlwaysExitsZero() {
        var high = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "open");
        assertEquals(0, Main.computeExitCode(reportWith(List.of(high), List.of()), "NONE"));
    }

    // This is the exact bug found scanning dvba_v1.1.0.apk: 7 HIGH rule-scanner findings, no LLM
    // enrichment, --fail-on HIGH incorrectly exited 0 before this fix.
    @Test void failOnHighTripsOnRuleScannerFindingEvenWithoutLlm() {
        var high = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "open");
        assertEquals(1, Main.computeExitCode(reportWith(List.of(high), List.of()), "HIGH"));
    }

    @Test void failOnHighDoesNotTripOnMediumOnlyRuleScannerFindings() {
        var medium = finding(1, "MASTG-TEST-0262", "Backup Config", "MEDIUM", "open");
        assertEquals(0, Main.computeExitCode(reportWith(List.of(medium), List.of()), "HIGH"));
    }

    @Test void failOnMediumTripsOnMediumRuleScannerFinding() {
        var medium = finding(1, "MASTG-TEST-0262", "Backup Config", "MEDIUM", "open");
        assertEquals(1, Main.computeExitCode(reportWith(List.of(medium), List.of()), "MEDIUM"));
    }

    @Test void failOnLowTripsOnAnyRuleScannerFinding() {
        var info = finding(1, "MASTG-TEST-9999", "Info only", "INFO", "open");
        assertEquals(1, Main.computeExitCode(reportWith(List.of(info), List.of()), "LOW"));
    }

    @Test void criticalSeverityCountsAsHighForFailOnHigh() {
        var critical = finding(1, "MASTG-TEST-9999", "Hardcoded Secret", "CRITICAL", "open");
        assertEquals(1, Main.computeExitCode(reportWith(List.of(critical), List.of()), "HIGH"));
    }

    @Test void falsePositiveRuleScannerFindingDoesNotTripFailOn() {
        var fp = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "false_positive");
        assertEquals(0, Main.computeExitCode(reportWith(List.of(fp), List.of()), "HIGH"));
    }

    @Test void fixedRuleScannerFindingDoesNotTripFailOn() {
        var fixed = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "fixed");
        assertEquals(0, Main.computeExitCode(reportWith(List.of(fixed), List.of()), "HIGH"));
    }

    @Test void acceptedRiskRuleScannerFindingStillTripsFailOn() {
        // accepted_risk is not suppressed (see VulnerabilityRecord.isSuppressed()) — it's still
        // an active finding, just a reviewed one, so it still exports to SARIF and still gates CI.
        var accepted = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "accepted_risk");
        assertEquals(1, Main.computeExitCode(reportWith(List.of(accepted), List.of()), "HIGH"));
    }

    @Test void overrideSeverityIsHonoredOverOriginalSeverity() {
        // a reviewer downgraded a HIGH finding to LOW via triage — --fail-on HIGH must not trip.
        var downgraded = finding(1, "MASTG-TEST-0223", "Stack Canaries Not Enabled", "HIGH", "open", "LOW");
        assertEquals(0, Main.computeExitCode(reportWith(List.of(downgraded), List.of()), "HIGH"));
    }

    @Test void overrideSeverityCanAlsoEscalateExitCode() {
        // a reviewer escalated a MEDIUM finding to HIGH via triage — --fail-on HIGH must trip.
        var escalated = finding(1, "MASTG-TEST-0262", "Backup Config", "MEDIUM", "open", "HIGH");
        assertEquals(1, Main.computeExitCode(reportWith(List.of(escalated), List.of()), "HIGH"));
    }

    @Test void llmFindingAloneStillTripsFailOn() {
        var llmHigh = new AnalysisReport.LlmFinding("fn", "Cls", "FIND_VULNS", "HIGH: SQL injection");
        assertEquals(1, Main.computeExitCode(reportWith(List.of(), List.of(llmHigh)), "HIGH"));
    }

    @Test void bothSourcesCombineCorrectly() {
        var ruleMedium = finding(1, "MASTG-TEST-0262", "Backup Config", "MEDIUM", "open");
        var llmHigh = new AnalysisReport.LlmFinding("fn", "Cls", "FIND_VULNS", "HIGH: SQL injection");
        assertEquals(1, Main.computeExitCode(reportWith(List.of(ruleMedium), List.of(llmHigh)), "HIGH"));
    }

    @Test void noFindingsAtAllExitsZeroEvenWithStrictestPolicy() {
        assertEquals(0, Main.computeExitCode(reportWith(List.of(), List.of()), "LOW"));
    }

    @Test void nullVulnerabilitiesListDoesNotThrow() {
        var report = new AnalysisReport(
                "scan-id", "App", "com.example", false, false, List.of(), 0L,
                0, 0, 0, Map.of(), List.of(), List.of(),
                null, null, null,
                null, null, "/tmp/test.sqlite", "ANDROID");
        assertEquals(0, Main.computeExitCode(report, "HIGH"));
    }
}
