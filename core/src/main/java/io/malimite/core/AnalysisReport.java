package io.malimite.core;

import java.util.List;
import java.util.Map;

/**
 * Complete result of a Malimite IPA analysis scan.
 *
 * <p>Serialized to JSON by the Worker and stored in Redis at
 * {@code malimite:result:{scanId}}.  The {@code dbPath} field points to the
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
        String dbPath,

        /** IOS or ANDROID (null on legacy reports). */
        String platform,

        /** Security-controls inventory (empty when Assessment disabled). */
        List<AssessmentRecord> assessments,

        /** Android manifest facts for the VA report's Manifest section (null on iOS or legacy reports). */
        AndroidManifestInfo androidManifest
) {
    /** Backward-compatible ctor for tests that omit assessments and the Android manifest. */
    public AnalysisReport(
            String scanId, String bundleExecutable, String bundleIdentifier,
            boolean isSwift, boolean isUniversal, List<String> architectures, long durationMs,
            int classCount, int functionCount, int stringCount,
            Map<String, List<String>> classes, List<StringEntry> strings, List<String> entryPoints,
            String bundleTeamId, String provisioningProfile, String provisioningExpiry,
            List<LlmFinding> llmFindings, List<VulnerabilityRecord> vulnerabilities,
            String dbPath, String platform) {
        this(scanId, bundleExecutable, bundleIdentifier, isSwift, isUniversal, architectures,
                durationMs, classCount, functionCount, stringCount, classes, strings, entryPoints,
                bundleTeamId, provisioningProfile, provisioningExpiry, llmFindings, vulnerabilities,
                dbPath, platform, List.of(), null);
    }

    /** Backward-compatible ctor for tests that omit the Android manifest. */
    public AnalysisReport(
            String scanId, String bundleExecutable, String bundleIdentifier,
            boolean isSwift, boolean isUniversal, List<String> architectures, long durationMs,
            int classCount, int functionCount, int stringCount,
            Map<String, List<String>> classes, List<StringEntry> strings, List<String> entryPoints,
            String bundleTeamId, String provisioningProfile, String provisioningExpiry,
            List<LlmFinding> llmFindings, List<VulnerabilityRecord> vulnerabilities,
            String dbPath, String platform, List<AssessmentRecord> assessments) {
        this(scanId, bundleExecutable, bundleIdentifier, isSwift, isUniversal, architectures,
                durationMs, classCount, functionCount, stringCount, classes, strings, entryPoints,
                bundleTeamId, provisioningProfile, provisioningExpiry, llmFindings, vulnerabilities,
                dbPath, platform, assessments, null);
    }

    /** A single extracted Mach-O string. */
    public record StringEntry(String address, String value, String segment, String label) {}

    /** A single LLM enrichment result for one function. */
    public record LlmFinding(String functionName, String className, String mode, String finding) {}

    /** Android manifest facts surfaced in the VA report's Manifest section. All fields except
     * {@code permissions}/{@code components} may be {@code null} when AndroidManifestParser could
     * not determine them (e.g. no {@code uses-sdk cleartextTraffic} attribute present). */
    public record AndroidManifestInfo(
            Boolean debuggable,
            Boolean allowBackup,
            Boolean usesCleartextTraffic,
            String networkSecurityConfig,
            List<String> permissions,
            List<Component> components
    ) {
        /** One manifest-declared activity/service/receiver/provider. */
        public record Component(String type, String name, boolean exported, String permission) {}
    }

    /** One security-control assessment row. */
    public record AssessmentRecord(
            long id,
            String controlId,
            String title,
            String category,
            String status,
            String confidence,
            String evidence,
            String detail,
            String platform
    ) {}

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
            String overrideNote,        // nullable
            // AI Fix fields — LLM-rewritten report text, stored as reversible overrides;
            // never replace description/evidence/pocSteps/remediation above.
            String overrideDescription, // nullable
            String overrideEvidence,    // nullable
            String overridePocSteps,    // nullable
            String overrideRemediation, // nullable
            String aiFixStatus,         // none | applied | reverted
            String aiFixProvider,       // nullable
            String aiFixModel           // nullable
    ) {
        /** Severity after triage/AI-fix override. */
        public String effectiveSeverity() {
            return overrideSeverity != null && !overrideSeverity.isBlank() ? overrideSeverity : severity;
        }
        /** CVSS after triage/AI-fix override. */
        public double effectiveCvssScore() {
            return overrideCvssScore != null ? overrideCvssScore : cvssScore;
        }
        /** Description after AI Fix override, falling back to the original. */
        public String effectiveDescription() {
            return notBlank(overrideDescription) ? overrideDescription : description;
        }
        /** Evidence after AI Fix override, falling back to the original. */
        public String effectiveEvidence() {
            return notBlank(overrideEvidence) ? overrideEvidence : evidence;
        }
        /** Proof-of-concept steps after AI Fix override, falling back to the original. */
        public String effectivePocSteps() {
            return notBlank(overridePocSteps) ? overridePocSteps : pocSteps;
        }
        /** Remediation guidance after AI Fix override, falling back to the original. */
        public String effectiveRemediation() {
            return notBlank(overrideRemediation) ? overrideRemediation : remediation;
        }
        /** True if an AI Fix is currently applied (not reverted) to this finding. */
        public boolean isAiFixed() {
            return "applied".equalsIgnoreCase(aiFixStatus);
        }
        private static boolean notBlank(String s) {
            return s != null && !s.isBlank();
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
            String provisioningExpiry,
            String platform
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
                entryPoints, bundleTeamId, provisioningExpiry, platform);
    }
}
