package io.malimite.core;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Serialises an {@link AnalysisReport} to SARIF 2.1.0.
 * Output file is written to {@code outputDir/findings.sarif}.
 *
 * Rules:
 *   MALIMITE001 — Entry point detected           (note)
 *   MALIMITE002 — Suspicious hardcoded string    (warning)
 *   MALIMITE003 — LLM vulnerability finding      (error/warning/note based on severity tag)
 */
public final class SarifExporter {

    private static final String SCHEMA =
            "https://json.schemastore.org/sarif-2.1.0.json";

    // Patterns that flag suspicious strings
    private static final List<Pattern> SUSPICIOUS = List.of(
            Pattern.compile("(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)"),
            Pattern.compile("https?://[^\\s\"]{20,}"),
            Pattern.compile("[A-Za-z0-9+/]{40,}={0,2}")  // base64-ish blob
    );

    private SarifExporter() {}

    /** Writes SARIF to {@code outputDir/findings.sarif} and returns the path. */
    public static Path export(AnalysisReport report, Path outputDir) throws IOException {
        JsonObject sarif = new JsonObject();
        sarif.addProperty("$schema", SCHEMA);
        sarif.addProperty("version", "2.1.0");

        JsonArray runs = new JsonArray();
        JsonObject run = new JsonObject();

        // tool
        JsonObject tool = new JsonObject();
        JsonObject driver = new JsonObject();
        driver.addProperty("name", "Malimite");
        driver.addProperty("version", "0.1.0");
        driver.addProperty("informationUri", "https://github.com/malimite/malimite-core");
        driver.add("rules", buildRules());
        tool.add("driver", driver);
        run.add("tool", tool);

        // results
        JsonArray results = new JsonArray();
        addEntryPointResults(results, report);
        addSuspiciousStringResults(results, report);
        addLlmVulnResults(results, report);
        run.add("results", results);

        runs.add(run);
        sarif.add("runs", runs);

        Path out = outputDir.resolve("findings.sarif");
        Files.writeString(out,
                new GsonBuilder().setPrettyPrinting().create().toJson(sarif));
        return out;
    }

    // ── rules ─────────────────────────────────────────────────────────────────

    private static JsonArray buildRules() {
        JsonArray rules = new JsonArray();
        rules.add(rule("MALIMITE001", "EntryPoint",
                "Entry point function detected in the application binary.", "note"));
        rules.add(rule("MALIMITE002", "SuspiciousString",
                "A potentially sensitive hardcoded string was found in the binary.", "warning"));
        rules.add(rule("MALIMITE003", "LlmVulnerability",
                "LLM analysis identified a potential security vulnerability.", "error"));
        return rules;
    }

    private static JsonObject rule(String id, String name, String description, String level) {
        JsonObject r = new JsonObject();
        r.addProperty("id", id);
        r.addProperty("name", name);
        JsonObject msg = new JsonObject();
        msg.addProperty("text", description);
        r.add("shortDescription", msg);
        JsonObject dflt = new JsonObject();
        dflt.addProperty("level", level);
        r.add("defaultConfiguration", dflt);
        return r;
    }

    // ── result builders ───────────────────────────────────────────────────────

    private static void addEntryPointResults(JsonArray results, AnalysisReport report) {
        for (String ep : report.entryPoints())
            results.add(result("MALIMITE001", "note",
                    "Entry point: " + ep, null, null));
    }

    private static void addSuspiciousStringResults(JsonArray results, AnalysisReport report) {
        for (AnalysisReport.StringEntry s : report.strings()) {
            if (s.value() == null) continue;
            for (Pattern p : SUSPICIOUS) {
                if (p.matcher(s.value()).find()) {
                    results.add(result("MALIMITE002", "warning",
                            "Suspicious string at " + s.address() + " [" + s.segment() + "]: "
                            + truncate(s.value(), 120), null, null));
                    break;
                }
            }
        }
    }

    private static void addLlmVulnResults(JsonArray results, AnalysisReport report) {
        if (report.llmFindings() == null) return;
        for (AnalysisReport.LlmFinding f : report.llmFindings()) {
            if (!"FIND_VULNS".equals(f.mode()) || "NONE".equalsIgnoreCase(f.finding().trim())) continue;
            String level = detectSeverityLevel(f.finding());
            results.add(result("MALIMITE003", level,
                    f.className() + "." + f.functionName() + ": " + truncate(f.finding(), 300),
                    f.className(), f.functionName()));
        }
    }

    private static JsonObject result(String ruleId, String level, String message,
                                      String className, String functionName) {
        JsonObject r = new JsonObject();
        r.addProperty("ruleId", ruleId);
        r.addProperty("level", level);
        JsonObject msg = new JsonObject();
        msg.addProperty("text", message);
        r.add("message", msg);
        if (className != null) {
            JsonArray locs = new JsonArray();
            JsonObject loc = new JsonObject();
            JsonObject pl = new JsonObject();
            JsonObject af = new JsonObject();
            JsonObject uri = new JsonObject();
            uri.addProperty("uri", className.replace('.', '/') + ".m");
            af.add("uri", uri);
            pl.add("artifactLocation", af);
            loc.add("physicalLocation", pl);
            JsonObject logLoc = new JsonObject();
            logLoc.addProperty("fullyQualifiedName", className + "." + functionName);
            loc.add("logicalLocations", new JsonArray());
            locs.add(loc);
            r.add("locations", locs);
        }
        return r;
    }

    // ── util ──────────────────────────────────────────────────────────────────

    private static String detectSeverityLevel(String finding) {
        String upper = finding.toUpperCase();
        if (upper.contains("HIGH"))   return "error";
        if (upper.contains("MEDIUM")) return "warning";
        return "note";
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
