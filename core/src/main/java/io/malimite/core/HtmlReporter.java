package io.malimite.core;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generates a self-contained, bilingual (Indonesian/English) Vulnerability Assessment report
 * from an {@link AnalysisReport}. Output file: {@code outputDir/report.html}
 *
 * <p>This class does not build HTML directly. Instead it serializes the scan into the JSON
 * data contract documented at the top of the bundled templates
 * ({@code core/src/main/resources/report-template/va-report-ios.html} and
 * {@code va-report-android.html}) and injects it into the matching platform template — the
 * template's own client-side JavaScript renders the whole report from that JSON (cover,
 * executive summary, risk rating scale, findings, MASVS mapping, code surface appendix,
 * approval sheet). Picking a template this way means layout/wording changes to the report live
 * entirely in the two HTML files, not scattered across Java string-building code.
 *
 * <p>Findings are grouped by {@code rule_id} (same issue, many assets) to match the web UI's
 * Vulnerabilities tab: one finding per unique issue with every affected asset listed under it.
 * Only active findings (not {@code false_positive}/{@code fixed}) are included, matching the
 * template's own {@code status} values; AI Fix / triage overrides are already resolved via
 * {@link AnalysisReport.VulnerabilityRecord}'s {@code effectiveX()} accessors before this class
 * ever sees them, so the exported report always reflects the latest reviewer decision.
 */
public final class HtmlReporter {

    /**
     * Bump when the report's data contract or chosen template changes in a way that requires
     * regenerating on-disk {@code report.html} files. Embedded as
     * {@code <meta name="malimite-report-template" content="…">} so the web service can detect
     * stale reports and re-render via {@link ReportRenderer}. Keep in sync with
     * {@code web/app/main.py}'s {@code _HTML_REPORT_TEMPLATE_VERSION}.
     */
    public static final String TEMPLATE_VERSION = "9";

    private static final String IOS_TEMPLATE_RESOURCE = "/report-template/va-report-ios.html";
    private static final String ANDROID_TEMPLATE_RESOURCE = "/report-template/va-report-android.html";
    private static final String DATA_MARKER = "__MALIMITE_REPORT_DATA_JSON__";
    // Injected right after <meta charset>, not before </head>: the templates carry a long
    // data-contract comment before <head> that pushes </head> well past the byte window
    // web/app/main.py's _html_template_stale() reads — <meta charset> stays close to byte 0
    // regardless of how long that comment grows.
    private static final String TEMPLATE_META_MARKER = "<meta charset=\"utf-8\">";

    private HtmlReporter() {}

    public static Path generate(AnalysisReport r, Path outputDir) throws IOException {
        boolean android = "ANDROID".equalsIgnoreCase(r.platform());
        String template = loadTemplate(android ? ANDROID_TEMPLATE_RESOURCE : IOS_TEMPLATE_RESOURCE);

        String json = buildReportJson(r).toString(2);
        // The data lives inside <script type="application/json">...</script>, read via
        // .textContent by the template's own JS — a literal "</script>" in evidence/description
        // text would otherwise truncate that block early. See both templates' top-of-file comment.
        String escapedJson = json.replace("</", "<\\/");

        // String.replace(CharSequence, CharSequence) does a literal replace, not a regex one — the
        // replacement text is used as-is. (Matcher.quoteReplacement() does NOT belong here: that's
        // only for replaceAll/replaceFirst's regex-replacement syntax, and using it on this method
        // would double every backslash already in escapedJson — e.g. a Mach-O string value
        // containing a literal '"' character, already escaped once to \" by JSONObject, would come
        // out as \\" instead, corrupting the JSON. Confirmed by a real scan's "/usr/lib/dyld"
        // string, whose embedded quotes made exactly this happen before this fix.)
        String html = template.replace(DATA_MARKER, escapedJson);
        // Embed the template-version marker the web service checks for staleness (ReportRenderer
        // callers compare this against TEMPLATE_VERSION) — the bundled templates don't carry it
        // themselves since they're meant to be usable standalone, outside Malimite too.
        int metaIdx = html.indexOf(TEMPLATE_META_MARKER);
        if (metaIdx < 0) {
            throw new IOException("Report template is missing the expected " + TEMPLATE_META_MARKER + " tag");
        }
        int insertAt = metaIdx + TEMPLATE_META_MARKER.length();
        html = html.substring(0, insertAt)
                + "\n<meta name=\"malimite-report-template\" content=\"" + TEMPLATE_VERSION + "\">"
                + html.substring(insertAt);

        Path out = outputDir.resolve("report.html");
        Files.writeString(out, html, StandardCharsets.UTF_8);
        return out;
    }

    private static String loadTemplate(String resource) throws IOException {
        try (InputStream in = HtmlReporter.class.getResourceAsStream(resource)) {
            if (in == null) throw new IOException("Report template resource not found: " + resource);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // ── JSON data contract ──────────────────────────────────────────────────

    static JSONObject buildReportJson(AnalysisReport r) {
        JSONObject root = new JSONObject();
        root.put("meta", buildMeta(r));
        root.put("app", "ANDROID".equalsIgnoreCase(r.platform()) ? buildAppAndroid(r) : buildAppIos(r));
        if (r.androidManifest() != null) root.put("manifest", buildManifest(r.androidManifest()));
        root.put("summary", buildSummary(r));
        root.put("controls", buildControls(r));
        root.put("findings", buildFindings(r));
        root.put("code_surface", buildCodeSurface(r));
        if (r.strings() != null && !r.strings().isEmpty()) {
            root.put("strings_sample", buildStringsSample(r));
            root.put("strings_total", r.stringCount());
        }
        return root;
    }

    private static JSONObject buildMeta(AnalysisReport r) {
        JSONObject m = new JSONObject();
        m.put("report_title", bi(
                "Laporan Vulnerability Assessment Aplikasi Mobile",
                "Mobile Application Vulnerability Assessment Report"));
        // Malimite has no administrative-metadata input (client name, document numbering,
        // sign-off names) — these render as "—" placeholders in the template and are meant to be
        // filled in by the reviewer after export, same as the template's own authoring workflow.
        m.put("generated", LocalDate.now().toString());
        m.put("scan_id", r.scanId());
        m.put("duration_ms", r.durationMs());
        m.put("tool_version", "Malimite");
        m.put("prepared_by", new JSONArray(List.of("Malimite automated scan")));
        JSONObject history = new JSONObject();
        history.put("version", "1.0");
        history.put("date", LocalDate.now().toString());
        history.put("author", "Malimite");
        history.put("change", "Generated from scan");
        m.put("history", new JSONArray(List.of(history)));
        return m;
    }

    private static JSONObject buildAppIos(AnalysisReport r) {
        JSONObject a = new JSONObject();
        a.put("bundle_id", r.bundleIdentifier());
        a.put("executable", r.bundleExecutable());
        a.put("platform", "iOS");
        a.put("language", r.isSwift() ? "Swift" : "Objective-C");
        a.put("universal", r.isUniversal() ? "Yes" : "No");
        a.put("team_id", r.bundleTeamId());
        a.put("profile", r.provisioningProfile());
        a.put("profile_expires", r.provisioningExpiry());
        a.put("classes", r.classCount());
        a.put("functions", r.functionCount());
        a.put("strings", r.stringCount());
        return a;
    }

    private static JSONObject buildAppAndroid(AnalysisReport r) {
        JSONObject a = new JSONObject();
        a.put("platform", "Android");
        a.put("package_name", r.bundleIdentifier());
        a.put("executable", r.bundleExecutable());
        a.put("language", "Java/Kotlin (DEX)");
        a.put("universal", r.isUniversal() ? "Yes" : "No");
        a.put("classes", r.classCount());
        a.put("functions", r.functionCount());
        a.put("strings", r.stringCount());
        // version_name/code, min/target SDK, signing/cert/APK hashes aren't threaded through
        // AnalysisReport yet (minSdk/targetSdk/versionName/versionCode live only in scan.json's
        // Android-only meta today, not in this platform-neutral record) — the template hides
        // null/absent fields automatically, so these are simply omitted rather than guessed at.
        return a;
    }

    private static JSONObject buildManifest(AnalysisReport.AndroidManifestInfo manifest) {
        JSONObject m = new JSONObject();
        m.put("debuggable", manifest.debuggable());
        m.put("allow_backup", manifest.allowBackup());
        m.put("uses_cleartext_traffic", manifest.usesCleartextTraffic());
        m.put("network_security_config", manifest.networkSecurityConfig());
        m.put("permissions", new JSONArray(manifest.permissions() == null ? List.of() : manifest.permissions()));
        JSONArray components = new JSONArray();
        if (manifest.components() != null) {
            for (var c : manifest.components()) {
                JSONObject co = new JSONObject();
                co.put("type", c.type());
                co.put("name", c.name());
                co.put("exported", c.exported());
                co.put("permission", c.permission());
                components.put(co);
            }
        }
        m.put("components", components);
        return m;
    }

    private static JSONObject buildSummary(AnalysisReport r) {
        JSONObject s = new JSONObject();
        int occurrences = 0;
        for (var g : groupActiveFindings(r)) occurrences += g.occurrenceCount();
        s.put("occurrences", occurrences);
        return s;
    }

    private static JSONArray buildControls(AnalysisReport r) {
        JSONArray out = new JSONArray();
        if (r.assessments() == null) return out;
        for (var a : r.assessments()) {
            JSONObject c = new JSONObject();
            c.put("group", a.category());
            c.put("name", a.title());
            c.put("status", a.status() == null ? "UNKNOWN" : a.status().toUpperCase(Locale.ROOT));
            c.put("detail", a.detail());
            if (notBlank(a.evidence())) c.put("evidence", a.evidence());
            c.put("rule", a.controlId());
            c.put("confidence", a.confidence());
            out.put(c);
        }
        return out;
    }

    private static JSONArray buildFindings(AnalysisReport r) {
        JSONArray out = new JSONArray();
        for (var g : groupActiveFindings(r)) {
            var v = g.representative();
            JSONObject f = new JSONObject();
            f.put("id", "MAL-" + v.id());
            f.put("severity", v.effectiveSeverity() == null ? "INFO" : v.effectiveSeverity().toUpperCase(Locale.ROOT));
            f.put("cvss", v.effectiveCvssScore());
            f.put("title", v.title());
            f.put("rule", v.ruleId());
            // AI_ASSISTANT: added through the web UI's "AI Assistant" chat (propose_finding —
            // see web/app/agent/tools.py and db.insert_vulnerability_manual()'s synthesized
            // "AI-<8 hex chars>" RuleId), confirmed by a human reviewer before being written —
            // distinct from LLM, which is this scanner's own LLM-ASSISTED SCAN MODE heuristic
            // output (RuleId prefix "LLM-"), generated and written automatically with no
            // per-finding human confirmation step.
            f.put("source", v.ruleId() != null && v.ruleId().startsWith("AI-") ? "AI_ASSISTANT"
                    : v.ruleId() != null && v.ruleId().startsWith("LLM-") ? "LLM" : "MASTG");
            f.put("category", v.category());
            f.put("cwe", v.cwe());
            String masvs = masvsCategory(v.category());
            if (masvs != null) f.put("masvs", masvs);
            if (notBlank(v.effectiveDescription())) f.put("description", v.effectiveDescription());
            f.put("affected", buildAffected(g.assets()));
            if (notBlank(v.effectiveEvidence())) f.put("evidence", v.effectiveEvidence());
            if (notBlank(v.effectivePocSteps())) f.put("poc", splitSteps(v.effectivePocSteps()));
            if (notBlank(v.effectiveRemediation())) {
                f.put("remediation", v.effectiveRemediation());   // kept for any older template/consumer
                JSONArray remSteps = splitSteps(v.effectiveRemediation());
                // Same "only when it actually found more than one real step" rule as poc above —
                // most rule-engine remediation text is one recommendation sentence, not steps.
                if (remSteps.length() > 1) f.put("remediation_steps", remSteps);
            }
            if (notBlank(v.referenceUrl())) f.put("reference", v.referenceUrl());
            if (notBlank(v.overrideNote())) f.put("reviewer_note", v.overrideNote());
            f.put("status", templateStatus(v.status()));
            out.put(f);
        }
        return out;
    }

    private static JSONArray buildAffected(List<AnalysisReport.VulnerabilityRecord> assets) {
        JSONArray out = new JSONArray();
        for (var a : assets) {
            JSONObject o = new JSONObject();
            o.put("name", notBlank(a.affectedName()) ? a.affectedName() : "—");
            o.put("type", notBlank(a.affectedType()) ? a.affectedType() : "ASSET");
            if (notBlank(a.evidenceLocation())) o.put("location", a.evidenceLocation());
            out.put(o);
        }
        return out;
    }

    /** Splits PoC steps text (one reproduction step per line) into the template's {@code poc[]}
     * array; falls back to a single-element array when the text has no newlines. */
    // Matches "N) " / "N. " right after a step boundary (start of string, or preceded by
    // whitespace) — used only as a FALLBACK splitter below, so it never fires on an ordinary
    // sentence that happens to contain a number mid-text (e.g. "CVSS 7.2. Also...").
    private static final Pattern INLINE_STEP_MARKER = Pattern.compile("(?:^|(?<=\\s))(\\d+)[.)]\\s+");

    private static JSONArray splitSteps(String pocSteps) {
        JSONArray byLine = new JSONArray();
        for (String line : pocSteps.split("\\r?\\n")) {
            String trimmed = line.replaceFirst("^\\s*\\d+[.)]\\s*", "").trim();
            if (!trimmed.isEmpty()) byLine.put(trimmed);
        }
        if (byLine.length() > 1) return byLine;   // newlines alone already produced real steps
        // Single line (or no newlines at all) — an LLM-authored PoC (see propose_finding in
        // web/app/agent/tools.py) commonly writes every step as one inline-numbered paragraph
        // ("1) Hook X. 2) Open Y. 3) Observe Z.") with no newline at all, which the loop above
        // can't split. Re-split on inline numbering markers instead; only replace the
        // newline-only result when this actually finds more than one step, so a single genuine
        // sentence that merely contains a number is never chopped apart. Matches against the
        // ORIGINAL text, not byLine's single entry — that one already had its own leading
        // "N) "/"N. " marker stripped by the per-line replaceFirst() above, which would
        // silently drop the very first inline marker from the count below.
        String whole = pocSteps.trim();
        Matcher m = INLINE_STEP_MARKER.matcher(whole);
        List<Integer> markerEnds = new ArrayList<>();
        List<Integer> markerStarts = new ArrayList<>();
        while (m.find()) { markerStarts.add(m.start()); markerEnds.add(m.end()); }
        if (markerStarts.size() > 1) {
            JSONArray inline = new JSONArray();
            for (int i = 0; i < markerStarts.size(); i++) {
                int from = markerEnds.get(i);
                int to = i + 1 < markerStarts.size() ? markerStarts.get(i + 1) : whole.length();
                String step = whole.substring(from, to).trim();
                if (!step.isEmpty()) inline.put(step);
            }
            if (inline.length() > 1) return inline;
        }
        if (byLine.length() > 0) return byLine;
        JSONArray fallback = new JSONArray();
        fallback.put(pocSteps.trim());
        return fallback;
    }

    /** Malimite's internal triage status → the template's {@code OPEN|IN_PROGRESS|FIXED|ACCEPTED|FALSE_POSITIVE}. */
    private static String templateStatus(String status) {
        if (status == null) return "OPEN";
        return switch (status.toLowerCase(Locale.ROOT)) {
            case "accepted_risk" -> "ACCEPTED";
            case "fixed" -> "FIXED";
            case "false_positive" -> "FALSE_POSITIVE";
            default -> "OPEN";
        };
    }

    /** Malimite's STORAGE/CRYPTO/NETWORK/PLATFORM/AUTH/CODE/RESILIENCE categories are already the
     * MASVS control-group names without the "MASVS-" prefix (see VulnerabilityCatalog's rule
     * definitions) — findings don't carry a separate structured MASVS field, so this derives the
     * template's optional {@code masvs} tag from the category Malimite already assigns. */
    private static String masvsCategory(String category) {
        if (category == null || category.isBlank()) return null;
        String c = category.trim().toUpperCase(Locale.ROOT);
        return switch (c) {
            case "STORAGE", "CRYPTO", "NETWORK", "PLATFORM", "AUTH", "CODE", "RESILIENCE" -> "MASVS-" + c;
            default -> null;
        };
    }

    private static JSONObject buildCodeSurface(AnalysisReport r) {
        JSONObject cs = new JSONObject();
        cs.put("entry_points", new JSONArray(r.entryPoints() == null ? List.of() : r.entryPoints()));
        JSONArray classes = new JSONArray();
        if (r.classes() != null) {
            r.classes().entrySet().stream()
                    .sorted((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()))
                    .limit(MAX_CLASSES_DISPLAY)
                    .forEach(e -> {
                        JSONObject c = new JSONObject();
                        c.put("name", e.getKey());
                        c.put("fn", e.getValue().size());
                        classes.put(c);
                    });
        }
        cs.put("classes", classes);
        return cs;
    }

    private static final int MAX_CLASSES_DISPLAY = 25;
    private static final int MAX_STRINGS_DISPLAY = 30;

    private static JSONArray buildStringsSample(AnalysisReport r) {
        JSONArray out = new JSONArray();
        int shown = 0;
        for (var s : r.strings()) {
            if (shown++ >= MAX_STRINGS_DISPLAY) break;
            JSONObject o = new JSONObject();
            o.put("address", s.address());
            o.put("segment", s.segment());
            o.put("value", s.value());
            out.put(o);
        }
        return out;
    }

    // ── grouping (unchanged from the previous HTML-building implementation —
    //    same "one card per unique rule_id" semantics as the web UI's Vulnerabilities tab) ──────

    /** Returns only the findings that should appear in the exported report (excludes false_positive & fixed). */
    private static List<AnalysisReport.VulnerabilityRecord> activeVulns(AnalysisReport r) {
        if (r.vulnerabilities() == null) return List.of();
        return r.vulnerabilities().stream().filter(v -> !v.isSuppressed()).toList();
    }

    /** Group active findings by rule_id (UI parity). */
    private static List<VulnGroup> groupActiveFindings(AnalysisReport r) {
        return groupFindingsByRule(activeVulns(r));
    }

    /**
     * Groups raw vulnerability rows by {@code rule_id} (fallback: per-row id),
     * picks a representative (prefer open/active triage, then higher severity,
     * then lower id), and deduplicates affected assets.
     */
    static List<VulnGroup> groupFindingsByRule(List<AnalysisReport.VulnerabilityRecord> findings) {
        if (findings == null || findings.isEmpty()) return List.of();
        java.util.Map<String, List<AnalysisReport.VulnerabilityRecord>> byRule = new java.util.LinkedHashMap<>();
        for (var f : findings) {
            String key = (f.ruleId() != null && !f.ruleId().isBlank())
                    ? f.ruleId()
                    : "__id_" + f.id();
            byRule.computeIfAbsent(key, k -> new ArrayList<>()).add(f);
        }
        List<VulnGroup> groups = new ArrayList<>();
        for (var occurrences : byRule.values()) {
            groups.add(new VulnGroup(
                    pickRepresentative(occurrences),
                    uniqueAffectedAssets(occurrences),
                    occurrences.size()));
        }
        // sort: effective severity (CRITICAL → LOW) then effective CVSS desc, then rule id —
        // matches the previous HTML report's finding order.
        groups.sort((a, b) -> {
            var va = a.representative();
            var vb = b.representative();
            int sa = sevRank(va.effectiveSeverity());
            int sb = sevRank(vb.effectiveSeverity());
            if (sa != sb) return Integer.compare(sa, sb);
            int cvss = Double.compare(vb.effectiveCvssScore(), va.effectiveCvssScore());
            if (cvss != 0) return cvss;
            return String.valueOf(va.ruleId()).compareTo(String.valueOf(vb.ruleId()));
        });
        return groups;
    }

    private static int sevRank(String s) {
        if (s == null) return 5;
        return switch (s.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 0;
            case "HIGH"     -> 1;
            case "MEDIUM"   -> 2;
            case "LOW"      -> 3;
            case "INFO"     -> 4;
            default          -> 5;
        };
    }

    private static AnalysisReport.VulnerabilityRecord pickRepresentative(
            List<AnalysisReport.VulnerabilityRecord> occurrences) {
        AnalysisReport.VulnerabilityRecord best = occurrences.get(0);
        for (int i = 1; i < occurrences.size(); i++) {
            var f = occurrences.get(i);
            int stA = statusPref(f.status());
            int stB = statusPref(best.status());
            int sevA = sevStrength(f.effectiveSeverity());
            int sevB = sevStrength(best.effectiveSeverity());
            if (stA < stB || (stA == stB && (sevA > sevB || (sevA == sevB && f.id() < best.id())))) {
                best = f;
            }
        }
        return best;
    }

    private static int statusPref(String status) {
        if (status == null) return 0;
        return switch (status.toLowerCase(Locale.ROOT)) {
            case "open" -> 0;
            case "accepted_risk" -> 1;
            case "fixed" -> 2;
            case "false_positive" -> 3;
            default -> 9;
        };
    }

    /** Higher = more severe (for representative selection). */
    private static int sevStrength(String s) {
        if (s == null) return 0;
        return switch (s.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 5;
            case "HIGH" -> 4;
            case "MEDIUM" -> 3;
            case "LOW" -> 2;
            case "INFO" -> 1;
            default -> 0;
        };
    }

    static List<AnalysisReport.VulnerabilityRecord> uniqueAffectedAssets(
            List<AnalysisReport.VulnerabilityRecord> occurrences) {
        java.util.Set<String> seen = new java.util.HashSet<>();
        List<AnalysisReport.VulnerabilityRecord> out = new ArrayList<>();
        for (var f : occurrences) {
            String key = assetDedupeKey(f);
            if (!seen.add(key)) continue;
            out.add(f);
        }
        return out;
    }

    private static String assetDedupeKey(AnalysisReport.VulnerabilityRecord f) {
        return trimLower(f.affectedType()) + '\0'
                + trimLower(f.affectedName()) + '\0'
                + trimLower(f.evidenceLocation());
    }

    private static String trimLower(String s) {
        return s == null ? "" : s.trim().toLowerCase(Locale.ROOT);
    }

    /** One unique issue with its deduplicated affected assets. */
    record VulnGroup(
            AnalysisReport.VulnerabilityRecord representative,
            List<AnalysisReport.VulnerabilityRecord> assets,
            int occurrenceCount
    ) {}

    // ── utils ─────────────────────────────────────────────────────────────────

    private static boolean notBlank(String s) { return s != null && !s.isBlank(); }

    /** Builds the template's {@code {"id":"…","en":"…"}} bilingual-string shape. */
    private static JSONObject bi(String id, String en) {
        JSONObject o = new JSONObject();
        o.put("id", id);
        o.put("en", en);
        return o;
    }
}
