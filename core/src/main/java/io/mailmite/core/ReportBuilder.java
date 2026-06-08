package io.mailmite.core;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Assembles an {@link AnalysisReport} by reading from a {@link SqliteStore}.
 * Called by the Worker after Ghidra analysis completes.
 */
public final class ReportBuilder {

    /** Max strings included in the report payload stored in Redis. */
    private static final int STRING_SAMPLE_LIMIT = 500;
    private static final Gson GSON = new Gson();

    private ReportBuilder() {}

    /**
     * Convenience factory: reads {@code scan.json} from {@code reportDir},
     * opens the SQLite file, and builds the full report.
     * Used by both Worker and CLI.
     */
    public static AnalysisReport buildFromDir(Path reportDir, long durationMs) throws Exception {
        String json = Files.readString(reportDir.resolve("scan.json"));
        JsonObject meta = GSON.fromJson(json, JsonObject.class);

        String scanId    = meta.get("scanId").getAsString();
        String execName  = meta.get("bundleExecutable").getAsString();
        String bundleId  = meta.get("bundleIdentifier").getAsString();
        boolean isSwift  = meta.get("isSwift").getAsBoolean();
        boolean isUniv   = meta.get("isUniversal").getAsBoolean();
        String dbPath    = meta.get("dbPath").getAsString();

        List<String> archs = new ArrayList<>();
        JsonArray archArr = meta.getAsJsonArray("architectures");
        if (archArr != null) archArr.forEach(e -> archs.add(e.getAsString()));

        String teamId     = optStr(meta, "bundleTeamId");
        String profName   = optStr(meta, "provisioningProfile");
        String profExpiry = optStr(meta, "provisioningExpiry");

        try (SqliteStore store = new SqliteStore(dbPath)) {
            return build(store, scanId, execName, bundleId, isSwift, isUniv,
                    archs, durationMs, dbPath, teamId, profName, profExpiry);
        }
    }

    public static AnalysisReport build(
            SqliteStore store,
            String scanId,
            String bundleExecutable,
            String bundleIdentifier,
            boolean isSwift,
            boolean isUniversal,
            List<String> architectures,
            long durationMs,
            String dbPath,
            String bundleTeamId,
            String provisioningProfile,
            String provisioningExpiry) {

        Map<String, List<String>> classes = store.getClassesAndFunctions(bundleExecutable);
        int fnCount  = store.getFunctionCount(bundleExecutable);
        int strCount = store.getStringCount(bundleExecutable);

        List<AnalysisReport.StringEntry> strings =
                store.getMachoStrings(bundleExecutable, STRING_SAMPLE_LIMIT)
                        .stream()
                        .map(m -> new AnalysisReport.StringEntry(
                                m.get("address"), m.get("value"),
                                m.get("segment"), m.get("label")))
                        .toList();

        List<String> entryPoints = store.getEntryPoints(bundleExecutable);

        List<AnalysisReport.LlmFinding> llmFindings =
                store.getLlmFindings(bundleExecutable)
                        .stream()
                        .map(m -> new AnalysisReport.LlmFinding(
                                m.get("functionName"), m.get("className"),
                                m.get("mode"), m.get("finding")))
                        .toList();

        List<AnalysisReport.VulnerabilityRecord> vulnerabilities =
                store.getVulnerabilities(bundleExecutable)
                        .stream()
                        .map(m -> new AnalysisReport.VulnerabilityRecord(
                                m.get("id") instanceof Number idn ? idn.longValue() : 0L,
                                (String) m.get("rule_id"),
                                (String) m.get("title"),
                                (String) m.get("category"),
                                (String) m.get("severity"),
                                m.get("cvss_score") instanceof Number n ? n.doubleValue() : 0.0,
                                (String) m.get("cwe"),
                                (String) m.get("description"),
                                (String) m.get("affected_type"),
                                (String) m.get("affected_name"),
                                (String) m.get("evidence"),
                                (String) m.get("evidence_location"),
                                (String) m.get("poc_steps"),
                                (String) m.get("remediation"),
                                (String) m.get("reference_url"),
                                (String) m.get("status"),
                                (String) m.get("override_severity"),
                                m.get("override_cvss_score") instanceof Number ocn ? ocn.doubleValue() : null,
                                (String) m.get("override_note")))
                        .toList();

        return new AnalysisReport(
                scanId, bundleExecutable, bundleIdentifier,
                isSwift, isUniversal, architectures, durationMs,
                classes.size(), fnCount, strCount,
                classes, strings, entryPoints,
                bundleTeamId, provisioningProfile, provisioningExpiry,
                llmFindings, vulnerabilities, dbPath
        );
    }

    private static String optStr(JsonObject o, String key) {
        var el = o.get(key);
        return (el == null || el.isJsonNull()) ? null : el.getAsString();
    }
}
