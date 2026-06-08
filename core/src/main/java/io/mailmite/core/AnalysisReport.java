package io.mailmite.core;

import java.util.List;
import java.util.Map;

/**
 * Complete result of a Mailmite IPA analysis scan.
 *
 * <p>Serialized to JSON by the Worker and stored in Redis at
 * {@code mailmite:result:{scanId}}.  The {@code dbPath} field points to the
 * SQLite file on the shared reports volume for deeper queries (decompiled code,
 * cross-references).
 */
public record AnalysisReport(
        String scanId,
        String bundleExecutable,
        String bundleIdentifier,
        boolean isSwift,
        boolean isUniversal,
        List<String> architectures,
        long durationMs,

        // counts
        int classCount,
        int functionCount,
        int stringCount,

        // structured data
        Map<String, List<String>> classes,   // className → [functionName, ...]
        List<StringEntry> strings,            // first 500 extracted Mach-O strings
        List<String> entryPoints,             // detected entry-point functions (Phase 3)

        // signing info from embedded.mobileprovision (may be null)
        String bundleTeamId,
        String provisioningProfile,
        String provisioningExpiry,

        // LLM enrichment findings (empty when LLM disabled)
        List<LlmFinding> llmFindings,

        // MSTG-derived + LLM-learned security findings (Phase 6)
        List<VulnerabilityRecord> vulnerabilities,

        // pointer to SQLite on the reports volume for /functions queries
        String dbPath
) {

    /** A single extracted Mach-O string. */
    public record StringEntry(String address, String value, String segment, String label) {}

    /** A single LLM enrichment result for one function. */
    public record LlmFinding(String functionName, String className, String mode, String finding) {}

    /** A single security finding (MSTG rule or LLM-discovered). */
    public record VulnerabilityRecord(
            long id,
            String ruleId,
            String title,
            String category,
            String severity,
            double cvssScore,
            String cwe,
            String description,
            String affectedType,
            String affectedName,
            String evidence,
            String evidenceLocation,
            String pocSteps,
            String remediation,
            String referenceUrl,
            // triage fields
            String status,              // open | false_positive | accepted_risk | fixed
            String overrideSeverity,    // nullable
            Double overrideCvssScore,   // nullable
            String overrideNote         // nullable
    ) {
        /** Severity after triage override. */
        public String effectiveSeverity() {
            return overrideSeverity != null && !overrideSeverity.isBlank() ? overrideSeverity : severity;
        }
        /** CVSS after triage override. */
        public double effectiveCvssScore() {
            return overrideCvssScore != null ? overrideCvssScore : cvssScore;
        }
        public boolean isFalsePositive() {
            return "false_positive".equalsIgnoreCase(status);
        }
        public boolean isSuppressed() {
            // false_positive and fixed are both excluded from exports
            return isFalsePositive() || "fixed".equalsIgnoreCase(status);
        }
    }

    /** Lightweight summary — returned by {@code GET /api/v1/scans/{id}/summary}. */
    public record ScanSummary(
            String scanId,
            String bundleExecutable,
            String bundleIdentifier,
            boolean isSwift,
            boolean isUniversal,
            List<String> architectures,
            long durationMs,
            int classCount,
            int functionCount,
            int stringCount,
            List<String> entryPoints,
            String bundleTeamId,
            String provisioningExpiry
    ) {}

    /** A single function returned by the {@code /functions} endpoint. */
    public record FunctionDetail(
            String functionName,
            String className,
            String decompiledCode
    ) {}

    /** A page of functions from {@code GET /api/v1/scans/{id}/functions}. */
    public record FunctionPage(
            String className,
            int page,
            int size,
            int total,
            List<FunctionDetail> items
    ) {}

    public ScanSummary toSummary() {
        return new ScanSummary(scanId, bundleExecutable, bundleIdentifier,
                isSwift, isUniversal, architectures, durationMs,
                classCount, functionCount, stringCount,
                entryPoints, bundleTeamId, provisioningExpiry);
    }
}
